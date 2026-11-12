/* Verify-after-sign: the signer is replaced at link time
 * (-Wl,--wrap=secp256k1_schnorrsig_sign32) by one that can damage the
 * signature or fail, and the library must refuse to hand either out. */
#include "tx_test.h"

int __real_secp256k1_schnorrsig_sign32(const secp256k1_context *ctx, unsigned char *sig64,
                                       const unsigned char *msg32,
                                       const secp256k1_keypair *keypair,
                                       const unsigned char *aux_rand32);
int __wrap_secp256k1_schnorrsig_sign32(const secp256k1_context *ctx, unsigned char *sig64,
                                       const unsigned char *msg32,
                                       const secp256k1_keypair *keypair,
                                       const unsigned char *aux_rand32);

static int fault = 0, calls = 0; /* 0 none, 1 flip a bit, 2 report failure */
int __wrap_secp256k1_schnorrsig_sign32(const secp256k1_context *ctx, unsigned char *sig64,
                                       const unsigned char *msg32,
                                       const secp256k1_keypair *keypair,
                                       const unsigned char *aux_rand32) {
    calls++;
    int r = __real_secp256k1_schnorrsig_sign32(ctx, sig64, msg32, keypair, aux_rand32);
    if (fault == 1) sig64[17] ^= 0x04;
    return fault == 2 ? 0 : r;
}

int main(void) {
    secp256k1_context *ctx = test_ctx();
    static gzt_tx tx;
    static gzt_funding f;
    gzt_spent_output spent;
    secp256k1_keypair kp;
    gzw_xprv master;
    gzw_bip86_output o;
    uint8_t key[32] = {9}, out[32], aux[32] = {0}, factory[34] = {0x51, 0x20, 0xfa};

    memset(&tx, 0, sizeof tx);
    memset(&spent, 0, sizeof spent);
    tx.version = 2;
    tx.n_in = tx.n_out = 1;
    tx.out[0].script_len = 34;
    CHECK(gzw_taproot_tweak_seckey(ctx, key, &kp, out));
    spent.amount = 5000;
    spent.script_len = 34;
    CHECK(gzw_p2tr_script_pubkey(out, spent.script));

    for (fault = 0; fault <= 2; fault++) {
        int before = calls;
        tx.in[0].witness_count = 0;
        gzt_err e = gzt_sign_keypath(ctx, &tx, &spent, 0, &kp, aux);
        CHECK(calls == before + 1); /* the fault was really applied */
        CHECK(e == (fault ? GZT_ERR_SIGN : GZT_OK));
        CHECK(tx.in[0].witness_count == (fault ? 0 : 1));
    }

    /* the funding builder passes the refusal on and keeps nothing */
    gzt_coin coin;
    memset(&coin, 0, sizeof coin);
    CHECK(public_master(ctx, &master));
    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 0, 0, &o, NULL));
    memcpy(coin.script, o.script_pubkey, 34);
    coin.amount = 100000;
    gzt_funding_request req = {GZT_NET_SIGNET, 0, factory, 34, 50000, 1, {{100}, {1000}}, NULL, 0};
    for (fault = 0; fault <= 2; fault++) {
        int before = calls;
        gzt_err e = gzt_funding_build(ctx, &master, &req, &coin, 1, aux, &f);
        CHECK(calls == before + 1);
        CHECK(e == (fault ? GZT_ERR_SIGN : GZT_OK));
        if (fault) {
            const uint8_t *p = (const uint8_t *)&f;
            int zero = 1;
            for (size_t i = 0; i < sizeof f; i++) zero &= p[i] == 0;
            CHECK(zero);
        }
    }
    /* release signs again: a damaged or failed signature there gives nothing */
    static uint8_t rel_out[1000];
    fault = 0;
    CHECK(gzt_funding_build(ctx, &master, &req, &coin, 1, aux, &f) == GZT_OK);
    for (fault = 1; fault <= 2; fault++) {
        int before = calls;
        size_t len = 7;
        memset(rel_out, 0xaa, sizeof rel_out);
        gzt_err e = gzt_funding_release(ctx, &master, &f, f.info.txid, aux, rel_out,
                                        sizeof rel_out, &len);
        CHECK(calls == before + 1);
        CHECK(e == GZT_ERR_SIGN && len == 0);
        int zero = 1;
        for (size_t i = 0; i < sizeof rel_out; i++) zero &= rel_out[i] == 0;
        CHECK(zero);
    }
    gzt_funding_wipe(&f);
    gzw_wipe(&master, sizeof master);
    secp256k1_context_destroy(ctx);
    return test_done("test_tx_faults");
}
