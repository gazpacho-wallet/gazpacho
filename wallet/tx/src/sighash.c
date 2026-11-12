/* BIP 341 signature hash for key-path spends, and BIP 86 key-path signing.
 * See docs/notes/wallet-tx.md sections 1.3 and 1.4. */

#include <secp256k1_schnorrsig.h>

#include "internal.h"

static int spent_ok(const gzt_tx *tx, const gzt_spent_output *spent) {
    if (!tx || !spent || tx->n_in == 0 || tx->n_in > GZT_MAX_INPUTS) return 0;
    if (tx->n_out == 0 || tx->n_out > GZT_MAX_OUTPUTS) return 0;
    for (uint32_t i = 0; i < tx->n_in; i++)
        if (spent[i].script_len > GZT_MAX_SCRIPT || spent[i].amount > GZT_MAX_MONEY) return 0;
    for (uint32_t i = 0; i < tx->n_out; i++)
        if (tx->out[i].script_len > GZT_MAX_SCRIPT) return 0;
    return 1;
}

static void put_output(gzt_w *w, const gzt_txout *o) {
    gzt_put_le(w, o->value, 8);
    gzt_put_cs(w, o->script_len);
    gzt_put(w, o->script, o->script_len);
}

gzt_err gzt_sighash_parts_compute(const gzt_tx *tx, const gzt_spent_output *spent,
                                  gzt_sighash_parts *out) {
    uint8_t buf[GZT_MAX_INPUTS * (GZT_MAX_SCRIPT + 3)];
    if (!out || !spent_ok(tx, spent)) return GZT_ERR_ARG;
    gzt_w w = {buf, sizeof buf, 0, 0};
    for (uint32_t i = 0; i < tx->n_in; i++) {
        gzt_put(&w, tx->in[i].prev_txid, 32);
        gzt_put_le(&w, tx->in[i].prev_vout, 4);
    }
    gzt_sha256(buf, w.len, out->prevouts);
    w.len = 0;
    for (uint32_t i = 0; i < tx->n_in; i++) gzt_put_le(&w, spent[i].amount, 8);
    gzt_sha256(buf, w.len, out->amounts);
    w.len = 0;
    for (uint32_t i = 0; i < tx->n_in; i++) {
        gzt_put_cs(&w, spent[i].script_len);
        gzt_put(&w, spent[i].script, spent[i].script_len);
    }
    gzt_sha256(buf, w.len, out->scripts);
    w.len = 0;
    for (uint32_t i = 0; i < tx->n_in; i++) gzt_put_le(&w, tx->in[i].sequence, 4);
    gzt_sha256(buf, w.len, out->sequences);
    w.len = 0;
    for (uint32_t i = 0; i < tx->n_out; i++) put_output(&w, &tx->out[i]);
    gzt_sha256(buf, w.len, out->outputs);
    return w.over ? GZT_ERR_INTERNAL : GZT_OK;
}

gzt_err gzt_sigmsg(const gzt_tx *tx, const gzt_spent_output *spent, uint32_t in_index,
                   uint8_t hash_type, uint8_t out[GZT_SIGMSG_MAX], size_t *len_out) {
    gzt_sighash_parts parts;
    if (!out || !len_out || !spent_ok(tx, spent) || in_index >= tx->n_in) return GZT_ERR_ARG;
    *len_out = 0;
    uint8_t base = hash_type & 0x7f;
    int anyone = (hash_type & GZT_SIGHASH_ANYONECANPAY) != 0;
    if (hash_type != GZT_SIGHASH_DEFAULT && (base < GZT_SIGHASH_ALL || base > GZT_SIGHASH_SINGLE))
        return GZT_ERR_ARG;
    if (base == GZT_SIGHASH_SINGLE && in_index >= tx->n_out) return GZT_ERR_ARG;
    gzt_err e = gzt_sighash_parts_compute(tx, spent, &parts);
    if (e) return e;

    gzt_w w = {out, GZT_SIGMSG_MAX, 0, 0};
    gzt_put_u8(&w, hash_type);
    gzt_put_le(&w, tx->version, 4);
    gzt_put_le(&w, tx->locktime, 4);
    if (!anyone) {
        gzt_put(&w, parts.prevouts, 32);
        gzt_put(&w, parts.amounts, 32);
        gzt_put(&w, parts.scripts, 32);
        gzt_put(&w, parts.sequences, 32);
    }
    if (base != GZT_SIGHASH_NONE && base != GZT_SIGHASH_SINGLE) gzt_put(&w, parts.outputs, 32);
    gzt_put_u8(&w, 0x00); /* spend_type: key path, no annex */
    if (anyone) {
        const gzt_txin *in = &tx->in[in_index];
        gzt_put(&w, in->prev_txid, 32);
        gzt_put_le(&w, in->prev_vout, 4);
        gzt_put_le(&w, spent[in_index].amount, 8);
        gzt_put_cs(&w, spent[in_index].script_len);
        gzt_put(&w, spent[in_index].script, spent[in_index].script_len);
        gzt_put_le(&w, in->sequence, 4);
    } else {
        gzt_put_le(&w, in_index, 4);
    }
    if (base == GZT_SIGHASH_SINGLE) {
        uint8_t one[GZT_MAX_SCRIPT + 11], h[32];
        gzt_w ow = {one, sizeof one, 0, 0};
        put_output(&ow, &tx->out[in_index]);
        if (ow.over) return GZT_ERR_INTERNAL;
        gzt_sha256(one, ow.len, h);
        gzt_put(&w, h, 32);
    }
    if (w.over) return GZT_ERR_INTERNAL;
    *len_out = w.len;
    return GZT_OK;
}

gzt_err gzt_sighash_keypath(const gzt_tx *tx, const gzt_spent_output *spent,
                            uint32_t in_index, uint8_t hash_type, uint8_t out[32]) {
    uint8_t msg[1 + GZT_SIGMSG_MAX] = {0};
    size_t len;
    if (!out) return GZT_ERR_ARG;
    msg[0] = 0x00; /* epoch */
    gzt_err e = gzt_sigmsg(tx, spent, in_index, hash_type, msg + 1, &len);
    if (e) return e;
    gzt_tagged_hash("TapSighash", msg, 1 + len, out);
    return GZT_OK;
}

gzt_err gzt_sign_keypath(const secp256k1_context *ctx, gzt_tx *tx,
                         const gzt_spent_output *spent, uint32_t in_index,
                         const secp256k1_keypair *keypair, const uint8_t aux32[32]) {
    uint8_t hash[32], sig[64], key[32];
    secp256k1_xonly_pubkey xpub, want;
    if (!ctx || !keypair || !aux32 || !spent_ok(tx, spent) || in_index >= tx->n_in)
        return GZT_ERR_ARG;
    const gzt_spent_output *s = &spent[in_index];
    if (s->script_len != 34 || s->script[0] != 0x51 || s->script[1] != 0x20) return GZT_ERR_KEY;
    if (!secp256k1_xonly_pubkey_parse(ctx, &want, s->script + 2)) return GZT_ERR_KEY;
    if (!secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, keypair) ||
        !secp256k1_xonly_pubkey_serialize(ctx, key, &xpub))
        return GZT_ERR_KEY;
    if (memcmp(key, s->script + 2, 32) != 0) return GZT_ERR_KEY;
    gzt_err e = gzt_sighash_keypath(tx, spent, in_index, GZT_SIGHASH_DEFAULT, hash);
    if (e) return e;
    if (!secp256k1_schnorrsig_sign32(ctx, sig, hash, keypair, aux32)) return GZT_ERR_SIGN;
    if (!secp256k1_schnorrsig_verify(ctx, sig, hash, 32, &want)) {
        gzw_wipe(sig, sizeof sig);
        return GZT_ERR_SIGN;
    }
    gzt_txin *in = &tx->in[in_index];
    memset(in->witness, 0, sizeof in->witness);
    in->witness_count = 1;
    in->witness[0].len = 64;
    memcpy(in->witness[0].data, sig, 64);
    return GZT_OK;
}
