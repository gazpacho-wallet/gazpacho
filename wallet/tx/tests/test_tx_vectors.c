/* Official vectors: BIP 341 key-path spending (one transaction, seven
 * signed inputs, intermediate values) and the three BIP 86 leaf keys.
 * The tweak with a script tree is computed here with libsecp256k1, because
 * the libraries only do the no-script tweak. */
#include <secp256k1_schnorrsig.h>

#include "tx_test.h"
#include "tx_vectors_data.h"

#define N_UTXOS (sizeof BIP341_UTXOS / sizeof BIP341_UTXOS[0])
#define N_INPUTS (sizeof BIP341_INPUTS / sizeof BIP341_INPUTS[0])
#define N_LEAVES (sizeof BIP86_LEAVES / sizeof BIP86_LEAVES[0])

static int vectors = 0;

static void check_hex(const uint8_t *got, size_t len, const char *want_hex) {
    uint8_t want[512];
    size_t n = unhex(want_hex, want, sizeof want);
    CHECK(n == len && memcmp(got, want, len) == 0);
    vectors++;
}

static void round_trip(const char *hex, gzt_tx *tx) {
    static uint8_t raw[GZT_MAX_TX_BYTES], back[GZT_MAX_TX_BYTES];
    size_t n = unhex(hex, raw, sizeof raw), m = 0;
    CHECK(gzt_tx_parse(raw, n, tx) == GZT_OK);
    CHECK(gzt_tx_serialize(tx, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_OK);
    CHECK(m == n && memcmp(raw, back, n) == 0);
    vectors++;
}

static void bip341(const secp256k1_context *ctx) {
    static gzt_tx tx, signed_tx;
    gzt_spent_output spent[N_UTXOS];
    gzt_sighash_parts parts;
    uint8_t txid1[32], txid2[32];

    round_trip(BIP341_UNSIGNED, &tx);
    round_trip(BIP341_SIGNED, &signed_tx);
    /* input 2 spends a P2PKH output, so the signed form has a scriptSig and
       another txid; with it removed the txids agree */
    CHECK(signed_tx.in[2].script_sig_len == 107);
    signed_tx.in[2].script_sig_len = 0;
    CHECK(gzt_tx_txid(&tx, txid1) == GZT_OK && gzt_tx_txid(&signed_tx, txid2) == GZT_OK);
    CHECK(memcmp(txid1, txid2, 32) == 0);
    CHECK(tx.n_in == N_UTXOS);

    memset(spent, 0, sizeof spent);
    for (size_t i = 0; i < N_UTXOS; i++) {
        spent[i].amount = BIP341_UTXOS[i].amount;
        spent[i].script_len = (uint16_t)unhex(BIP341_UTXOS[i].script, spent[i].script,
                                              GZT_MAX_SCRIPT);
    }
    CHECK(gzt_sighash_parts_compute(&tx, spent, &parts) == GZT_OK);
    const uint8_t *got[5] = {parts.prevouts, parts.amounts, parts.scripts, parts.sequences,
                             parts.outputs};
    for (int k = 0; k < 5; k++) check_hex(got[k], 32, BIP341_PARTS[k]);

    for (size_t v = 0; v < N_INPUTS; v++) {
        uint8_t priv[32], root[32], buf[64], tweak[32], tpriv[32], xo[32], msg[GZT_SIGMSG_MAX];
        uint8_t hash[32], sig[65], zero[32] = {0};
        size_t mlen;
        secp256k1_keypair kp;
        secp256k1_xonly_pubkey xpub;
        uint32_t idx = BIP341_INPUTS[v].index;
        uint8_t ht = BIP341_INPUTS[v].hash_type;

        unhex(BIP341_INPUTS[v].priv, priv, 32);
        CHECK(secp256k1_keypair_create(ctx, &kp, priv));
        CHECK(secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &kp));
        CHECK(secp256k1_xonly_pubkey_serialize(ctx, xo, &xpub));
        check_hex(xo, 32, BIP341_INPUTS[v].internal_pub);

        size_t blen = 32;
        memcpy(buf, xo, 32);
        if (BIP341_INPUTS[v].merkle_root[0]) {
            unhex(BIP341_INPUTS[v].merkle_root, root, 32);
            memcpy(buf + 32, root, 32);
            blen = 64;
        }
        CHECK(secp256k1_tagged_sha256(ctx, tweak, (const uint8_t *)"TapTweak", 8, buf, blen));
        check_hex(tweak, 32, BIP341_INPUTS[v].tweak);
        CHECK(secp256k1_keypair_xonly_tweak_add(ctx, &kp, tweak));
        CHECK(secp256k1_keypair_sec(ctx, tpriv, &kp));
        check_hex(tpriv, 32, BIP341_INPUTS[v].tweaked_priv);
        if (!BIP341_INPUTS[v].merkle_root[0]) {
            /* The key library's no-script tweak gives the same key. */
            secp256k1_keypair kp2;
            uint8_t out2[32], tpriv2[32];
            CHECK(gzw_taproot_tweak_seckey(ctx, priv, &kp2, out2));
            CHECK(secp256k1_keypair_sec(ctx, tpriv2, &kp2) && memcmp(tpriv, tpriv2, 32) == 0);
        }

        CHECK(gzt_sigmsg(&tx, spent, idx, ht, msg, &mlen) == GZT_OK);
        /* the vector file gives the epoch byte 00 in front of BIP 341's SigMsg */
        uint8_t em[1 + GZT_SIGMSG_MAX] = {0};
        memcpy(em + 1, msg, mlen);
        check_hex(em, 1 + mlen, BIP341_INPUTS[v].sigmsg);
        CHECK(gzt_sighash_keypath(&tx, spent, idx, ht, hash) == GZT_OK);
        check_hex(hash, 32, BIP341_INPUTS[v].sighash);

        /* The published signatures were made with zero auxiliary randomness. */
        CHECK(secp256k1_schnorrsig_sign32(ctx, sig, hash, &kp, zero));
        sig[64] = ht;
        check_hex(sig, ht ? 65 : 64, BIP341_INPUTS[v].witness);
        CHECK(signed_tx.in[idx].witness_count == 1);
        check_hex(signed_tx.in[idx].witness[0].data, signed_tx.in[idx].witness[0].len,
                  BIP341_INPUTS[v].witness);

        if (ht == GZT_SIGHASH_DEFAULT) {
            /* The library's signer gives the published witness. */
            static gzt_tx work;
            work = tx;
            CHECK(gzt_sign_keypath(ctx, &work, spent, idx, &kp, zero) == GZT_OK);
            check_hex(work.in[idx].witness[0].data, work.in[idx].witness[0].len,
                      BIP341_INPUTS[v].witness);
        }
    }
}

static void bip86(const secp256k1_context *ctx) {
    for (size_t v = 0; v < N_LEAVES; v++) {
        gzw_xprv x;
        secp256k1_keypair kp, other;
        secp256k1_xonly_pubkey xpub, want;
        uint8_t out[32], internal[32], spk[34], hash[32], aux[32] = {7};
        int mainnet = 0;
        static gzt_tx tx;
        gzt_spent_output spent;

        CHECK(gzw_xprv_from_string(ctx, BIP86_LEAVES[v].xprv, &x, &mainnet) && mainnet == 1);
        CHECK(secp256k1_keypair_create(ctx, &kp, x.key));
        CHECK(secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &kp));
        CHECK(secp256k1_xonly_pubkey_serialize(ctx, internal, &xpub));
        check_hex(internal, 32, BIP86_LEAVES[v].internal_key);
        CHECK(gzw_taproot_tweak_seckey(ctx, x.key, &kp, out));
        check_hex(out, 32, BIP86_LEAVES[v].output_key);
        CHECK(gzw_p2tr_script_pubkey(out, spk));
        check_hex(spk, 34, BIP86_LEAVES[v].script);

        /* Spend it: one input, one output paying the same script. */
        memset(&tx, 0, sizeof tx);
        memset(&spent, 0, sizeof spent);
        tx.version = 2;
        tx.n_in = tx.n_out = 1;
        tx.in[0].prev_txid[0] = (uint8_t)(v + 1);
        tx.in[0].sequence = 0xfffffffeu;
        tx.out[0].value = 50000;
        tx.out[0].script_len = 34;
        memcpy(tx.out[0].script, spk, 34);
        spent.amount = 60000;
        spent.script_len = (uint16_t)unhex(BIP86_LEAVES[v].script, spent.script, 34);
        CHECK(gzt_sign_keypath(ctx, &tx, &spent, 0, &kp, aux) == GZT_OK);
        CHECK(tx.in[0].witness_count == 1 && tx.in[0].witness[0].len == 64);
        CHECK(gzt_sighash_keypath(&tx, &spent, 0, GZT_SIGHASH_DEFAULT, hash) == GZT_OK);
        unhex(BIP86_LEAVES[v].output_key, out, 32);
        CHECK(secp256k1_xonly_pubkey_parse(ctx, &want, out));
        CHECK(secp256k1_schnorrsig_verify(ctx, tx.in[0].witness[0].data, hash, 32, &want));
        vectors++;

        /* Another leaf's key must not sign for this script. */
        gzw_xprv y;
        CHECK(gzw_xprv_from_string(ctx, BIP86_LEAVES[(v + 1) % N_LEAVES].xprv, &y, NULL));
        CHECK(gzw_taproot_tweak_seckey(ctx, y.key, &other, NULL));
        CHECK(gzt_sign_keypath(ctx, &tx, &spent, 0, &other, aux) == GZT_ERR_KEY);
        gzw_wipe(&x, sizeof x);
        gzw_wipe(&y, sizeof y);
    }
}

int main(void) {
    secp256k1_context *ctx = test_ctx();
    bip341(ctx);
    bip86(ctx);
    printf("official vector values compared: %d (BIP 341: 2 transactions, 5 hashes, %zu inputs; "
           "BIP 86: %zu leaves)\n", vectors, N_INPUTS, N_LEAVES);
    secp256k1_context_destroy(ctx);
    return test_done("test_tx_vectors");
}
