/* Coin selection and the factory funding.  See docs/notes/wallet-tx.md
 * sections 1.7 and 1.8. */

#include "internal.h"

#define P2TR_LEN 34
#define P2TR_DUST 330
/* The funding engine names it GZ_FUND_CHANGE_DUST (core/funding/funding.h). */
_Static_assert(P2TR_DUST == 330, "GZ_FUND_CHANGE_DUST in core/funding/include/gazpacho/funding.h");

/* Order: amount descending, then txid bytes, then vout. */
static int coin_before(const gzt_coin *a, const gzt_coin *b) {
    if (a->amount != b->amount) return a->amount > b->amount;
    int c = memcmp(a->txid, b->txid, 32);
    if (c) return c < 0;
    return a->vout < b->vout;
}

/* must: the index of a coin that is always selected, and first (input 0);
   -1 for none. */
static gzt_err select_coins(const gzt_coin *coins, size_t n_coins, const uint8_t *dest,
                            size_t dest_len, uint64_t amount, gzt_fee_policy fee, long must,
                            int need_change, gzt_selection *out) {
    uint32_t order[GZT_MAX_INPUTS];
    if (!out) return GZT_ERR_ARG;
    memset(out, 0, sizeof *out);
    if (!coins || !dest || n_coins == 0) return GZT_ERR_ARG;
    if (fee.rate.sat_per_kvb == 0 || fee.ceiling.sat_per_kvb > GZT_FEERATE_MAX_SAT_PER_KVB)
        return GZT_ERR_ARG;
    if (fee.rate.sat_per_kvb > fee.ceiling.sat_per_kvb) return GZT_ERR_FEE_CEILING;
    if (!gzt_is_witness_program(dest, dest_len)) return GZT_ERR_SCRIPT;
    if (dest_len < 5) return GZT_ERR_SCRIPT; /* one input, no change: under 65 bytes */
    if (amount > GZT_MAX_MONEY) return GZT_ERR_ARG;
    if (amount < gzt_dust_limit(dest, dest_len)) return GZT_ERR_DUST;
    if (n_coins > GZT_MAX_COINS) return GZT_ERR_LIMIT;

    uint64_t all = 0;
    for (size_t i = 0; i < n_coins; i++) {
        if (coins[i].amount > GZT_MAX_MONEY) return GZT_ERR_ARG;
        all += coins[i].amount;
        if (all > GZT_MAX_MONEY) return GZT_ERR_ARG;
        for (size_t j = 0; j < i; j++)
            if (coins[j].vout == coins[i].vout && memcmp(coins[j].txid, coins[i].txid, 32) == 0)
                return GZT_ERR_ARG;
    }

    /* The best GZT_MAX_INPUTS coins in order, by insertion. */
    size_t n_order = 0;
    if (must >= (long)n_coins) return GZT_ERR_ARG;
    for (size_t i = 0; i < n_coins; i++) {
        if ((long)i == must) continue;
        size_t pos = n_order;
        while (pos > 0 && coin_before(&coins[i], &coins[order[pos - 1]])) pos--;
        if (pos >= GZT_MAX_INPUTS) continue;
        size_t last = n_order < GZT_MAX_INPUTS ? n_order : GZT_MAX_INPUTS - 1;
        for (size_t k = last; k > pos; k--) order[k] = order[k - 1];
        order[pos] = (uint32_t)i;
        if (n_order < GZT_MAX_INPUTS) n_order++;
    }

    if (must >= 0) {
        /* The coin that must be spent goes first, ahead of the order. */
        size_t keep = n_order < GZT_MAX_INPUTS ? n_order : GZT_MAX_INPUTS - 1;
        for (size_t k = keep; k > 0; k--) order[k] = order[k - 1];
        order[0] = (uint32_t)must;
        n_order = keep + 1;
    }
    size_t lens_nc[1] = {dest_len}, lens_c[2] = {dest_len, P2TR_LEN};
    uint64_t total = 0;
    int overpaid = 0;
    for (size_t k = 1; k <= n_order; k++) {
        total += coins[order[k - 1]].amount;
        uint64_t vs_nc = gzt_keypath_vsize(k, lens_nc, 1);
        uint64_t vs_c = gzt_keypath_vsize(k, lens_c, 2);
        uint64_t fee_nc = gzt_fee_for_vsize(fee.rate, vs_nc);
        uint64_t fee_c = gzt_fee_for_vsize(fee.rate, vs_c);
        if (total < amount + fee_nc) continue;
        if (total >= amount + fee_c + P2TR_DUST) {
            out->has_change = 1;
            out->change = total - amount - fee_c;
            out->fee = fee_c;
            out->vsize = vs_c;
        } else {
            if (need_change) continue;   /* H16: the funding keeps change for a child */
            uint64_t paid = total - amount;
            if (paid > gzt_fee_for_vsize(fee.ceiling, vs_nc)) {
                overpaid = 1;
                continue;
            }
            out->fee = paid;
            out->vsize = vs_nc;
        }
        out->n_selected = (uint32_t)k;
        memcpy(out->selected, order, k * sizeof order[0]);
        out->total_in = total;
        return GZT_OK;
    }
    if (overpaid) return GZT_ERR_FEE_CEILING;
    if (must >= 0) return GZT_ERR_FUNDS;
    /* The coins would pay, but only with more inputs than allowed. */
    if (n_coins > GZT_MAX_INPUTS &&
        all >= amount + gzt_fee_for_vsize(fee.rate, gzt_keypath_vsize(GZT_MAX_INPUTS, lens_nc, 1)))
        return GZT_ERR_LIMIT;
    return GZT_ERR_FUNDS;
}

gzt_err gzt_select_coins(const gzt_coin *coins, size_t n_coins, const uint8_t *dest,
                         size_t dest_len, uint64_t amount, gzt_fee_policy fee,
                         gzt_selection *out) {
    return select_coins(coins, n_coins, dest, dest_len, amount, fee, -1, 0, out);
}

void gzt_funding_wipe(gzt_funding *f) {
    if (f) gzw_wipe(f, sizeof *f);
}

/* Sign every input of work (an unsigned copy of f->priv_tx) with the keys
   recorded in f, verifying each signature.  Input i gets the auxiliary
   randomness SHA-256(aux32 || i as 4 bytes little-endian). */
static gzt_err sign_all(const secp256k1_context *ctx, const gzw_xprv *master,
                        const gzt_funding *f, const uint8_t aux32[32], gzt_tx *work) {
    gzw_network knet;
    if (gzt_network_to_keys(f->priv_net, &knet)) return GZT_ERR_ARG;
    for (uint32_t i = 0; i < work->n_in; i++) {
        secp256k1_keypair kp;
        uint8_t aux_in[36], aux[32];
        if (!gzw_bip86_tweaked_keypair(ctx, master, knet, f->priv_account, f->priv_key_change[i],
                                       f->priv_key_index[i], &kp, NULL, NULL))
            return GZT_ERR_KEY;
        memcpy(aux_in, aux32, 32);
        for (int b = 0; b < 4; b++) aux_in[32 + b] = (uint8_t)(i >> (8 * b));
        gzt_sha256(aux_in, sizeof aux_in, aux);
        gzt_err e = gzt_sign_keypath(ctx, work, f->priv_spent, i, &kp, aux);
        gzw_wipe(&kp, sizeof kp);
        gzw_wipe(aux, sizeof aux);
        gzw_wipe(aux_in, sizeof aux_in);
        if (e) return e;
    }
    return GZT_OK;
}

static gzt_err build(const secp256k1_context *ctx, const gzw_xprv *master,
                     const gzt_funding_request *req, const gzt_coin *coins, size_t n_coins,
                     const uint8_t aux32[32], gzt_funding *f) {
    gzt_selection *sel = &f->info.selection;
    gzw_bip86_output change, out;
    gzw_network knet;
    gzt_err e;

    if (!ctx || !master || !req || !coins || !aux32 || !req->funding_script) return GZT_ERR_ARG;
    if (req->n_used_change_indexes && !req->used_change_indexes) return GZT_ERR_ARG;
    if (gzt_network_to_keys(req->net, &knet)) return GZT_ERR_ARG;
    if (master->depth != 0 || req->change_index >= GZW_HARDENED || req->account >= GZW_HARDENED)
        return GZT_ERR_ARG;
    /* A factory output is P2TR, OP_1 <32 bytes>; nothing else is funded. */
    const uint8_t *fs = req->funding_script;
    if (req->funding_script_len != P2TR_LEN || fs[0] != 0x51 || fs[1] != 0x20)
        return GZT_ERR_SCRIPT;
    for (size_t i = 0; i < n_coins; i++)
        if (coins[i].change == 1 && coins[i].index == req->change_index) return GZT_ERR_ARG;
    for (size_t i = 0; i < req->n_used_change_indexes; i++)
        if (req->used_change_indexes[i] == req->change_index) return GZT_ERR_ARG;
    if (!gzw_bip86_output_from_master(ctx, master, knet, req->account, 1, req->change_index,
                                      &change, NULL))
        return GZT_ERR_KEY;
    if (memcmp(fs, change.script_pubkey, P2TR_LEN) == 0) return GZT_ERR_ARG;
    long must = -1;
    if (req->must_spend) {
        /* H11: the coin of the previous attempt's input, offered among the coins. */
        for (size_t i = 0; i < n_coins; i++)
            if (coins[i].vout == req->must_vout && memcmp(coins[i].txid, req->must_txid, 32) == 0) must = (long)i;
        if (must < 0) return GZT_ERR_ARG;
    }
    e = select_coins(coins, n_coins, fs, P2TR_LEN, req->amount, req->fee, must, req->require_change, sel);
    if (e) return e;

    f->priv_net = req->net;
    f->priv_account = req->account;
    gzt_tx *tx = &f->priv_tx;
    tx->version = 2;
    tx->locktime = 0;
    tx->n_in = sel->n_selected;
    for (uint32_t i = 0; i < tx->n_in; i++) {
        const gzt_coin *c = &coins[sel->selected[i]];
        /* The coin's script must be the script of the key at its path. */
        if (!gzw_bip86_output_from_master(ctx, master, knet, req->account, c->change, c->index,
                                          &out, NULL) ||
            memcmp(out.script_pubkey, c->script, P2TR_LEN) != 0)
            return GZT_ERR_KEY;
        memcpy(tx->in[i].prev_txid, c->txid, 32);
        tx->in[i].prev_vout = c->vout;
        tx->in[i].sequence = 0xfffffffeu;
        f->priv_spent[i].amount = c->amount;
        f->priv_spent[i].script_len = P2TR_LEN;
        memcpy(f->priv_spent[i].script, c->script, P2TR_LEN);
        f->priv_key_change[i] = c->change;
        f->priv_key_index[i] = c->index;
    }
    tx->n_out = sel->has_change ? 2 : 1;
    tx->out[0].value = req->amount;
    tx->out[0].script_len = P2TR_LEN;
    memcpy(tx->out[0].script, fs, P2TR_LEN);
    if (sel->has_change) {
        tx->out[1].value = sel->change;
        tx->out[1].script_len = P2TR_LEN;
        memcpy(tx->out[1].script, change.script_pubkey, P2TR_LEN);
    }
    if (gzt_tx_txid(tx, f->info.txid)) return GZT_ERR_INTERNAL;

    /* Sign a copy, to prove the funding can be signed and to measure it,
       then throw the signatures away. */
    gzt_tx work = *tx;
    uint64_t weight, vsize;
    e = sign_all(ctx, master, f, aux32, &work);
    if (!e) e = gzt_tx_weight(&work, &weight, &vsize);
    gzw_wipe(&work, sizeof work);
    if (e) return e;
    if (vsize != sel->vsize) return GZT_ERR_INTERNAL;
    if (sel->fee > gzt_fee_for_vsize(req->fee.ceiling, vsize)) return GZT_ERR_INTERNAL;

    f->info.vout = 0;
    f->info.amount = req->amount;
    f->info.fee = sel->fee;
    f->info.vsize = vsize;
    f->info.has_change = sel->has_change;
    f->info.change = sel->change;
    f->info.change_index = req->change_index;
    f->priv_state = 1;
    return GZT_OK;
}

gzt_err gzt_funding_can_plan(const gzt_coin *coins, size_t n_coins, uint64_t amount,
                             gzt_fee_policy fee, gzt_selection *out) {
    /* the factory's script is OP_1 <32 bytes>: only its length counts here */
    static const uint8_t p2tr[P2TR_LEN] = {0x51, 0x20};
    if (!out) return GZT_ERR_ARG;
    memset(out, 0, sizeof *out);
    if (coins && n_coins == 0) return GZT_ERR_FUNDS; /* no coins: short, not an argument error */
    return select_coins(coins, n_coins, p2tr, P2TR_LEN, amount, fee, -1, 1, out);
}

gzt_err gzt_funding_build(const secp256k1_context *ctx, const gzw_xprv *master,
                          const gzt_funding_request *req, const gzt_coin *coins,
                          size_t n_coins, const uint8_t aux32[32], gzt_funding *out) {
    if (!out) return GZT_ERR_ARG;
    gzt_funding_wipe(out);
    gzt_err e = build(ctx, master, req, coins, n_coins, aux32, out);
    if (e) gzt_funding_wipe(out);
    return e;
}

/* The held funding still describes what was built: within the caps, no
   witness, its txid is the one asked for and the one recorded, and its
   amounts agree with info.  The txid does not cover the spent amounts and
   scripts; an edit of those gives signatures the network refuses (or none:
   the key check in gzt_sign_keypath), never another txid. */
static gzt_err held_ok(const gzt_funding *f, const uint8_t expect_txid[32]) {
    const gzt_tx *tx = &f->priv_tx;
    uint8_t txid[32];
    if (f->priv_state != 1 || !gzt_tx_in_caps(tx) || gzt_tx_has_witness(tx)) return GZT_ERR_STATE;
    if (gzt_tx_txid(tx, txid)) return GZT_ERR_STATE;
    int same = gzw_ct_equal(txid, expect_txid, 32) & gzw_ct_equal(txid, f->info.txid, 32);
    if (!same) return GZT_ERR_STATE;
    if (tx->n_out != (f->info.has_change ? 2u : 1u) || tx->out[0].value != f->info.amount)
        return GZT_ERR_STATE;
    uint64_t in = 0, outs = 0;
    for (uint32_t i = 0; i < tx->n_in; i++) {
        if (f->priv_spent[i].amount > GZT_MAX_MONEY) return GZT_ERR_STATE;
        in += f->priv_spent[i].amount;
    }
    for (uint32_t i = 0; i < tx->n_out; i++) {
        if (tx->out[i].value > GZT_MAX_MONEY) return GZT_ERR_STATE;
        outs += tx->out[i].value;
    }
    if (f->info.fee > GZT_MAX_MONEY || in != outs + f->info.fee) return GZT_ERR_STATE;
    return GZT_OK;
}

gzt_err gzt_funding_release(const secp256k1_context *ctx, const gzw_xprv *master,
                            const gzt_funding *f, const uint8_t expect_txid[32],
                            const uint8_t aux32[32], uint8_t *out, size_t cap,
                            size_t *len_out) {
    uint8_t buf[GZT_MAX_TX_BYTES];
    size_t len = 0;
    if (!out || !len_out) return GZT_ERR_ARG;
    *len_out = 0;
    gzt_err e = GZT_ERR_ARG;
    if (ctx && master && f && expect_txid && aux32 && master->depth == 0) {
        e = held_ok(f, expect_txid);
        if (!e) {
            gzt_tx work = f->priv_tx;
            uint64_t weight, vsize;
            e = sign_all(ctx, master, f, aux32, &work);
            if (!e) e = gzt_tx_weight(&work, &weight, &vsize);
            if (!e && vsize != f->info.vsize) e = GZT_ERR_INTERNAL;
            if (!e) e = gzt_tx_serialize(&work, GZT_SER_WITNESS, buf, sizeof buf, &len);
            if (!e && len > cap) e = GZT_ERR_BUFFER;
            if (!e) memcpy(out, buf, len);
            gzw_wipe(&work, sizeof work);
            gzw_wipe(buf, len);
        }
    }
    if (e) {
        gzw_wipe(out, cap);
        return e;
    }
    *len_out = len;
    return GZT_OK;
}

/* ---- the funding engine's accessors (composite-node.md 14.1, step P4.5) -- */

gzt_err gzt_funding_unsigned(const gzt_funding *f, uint8_t *out, size_t cap, size_t *len_out) {
    if (!out || !len_out) return GZT_ERR_ARG;
    *len_out = 0;
    if (!f) return GZT_ERR_ARG;
    gzt_err e = held_ok(f, f->info.txid);
    if (e) return e;
    return gzt_tx_serialize(&f->priv_tx, GZT_SER_NO_WITNESS, out, cap, len_out);
}

gzt_err gzt_funding_prevout(const gzt_funding *f, uint32_t i, uint64_t *amount, uint8_t *script,
                            size_t cap, size_t *len_out) {
    if (!amount || !script || !len_out) return GZT_ERR_ARG;
    *amount = 0;
    *len_out = 0;
    if (!f) return GZT_ERR_ARG;
    gzt_err e = held_ok(f, f->info.txid);
    if (e) return e;
    if (i >= f->priv_tx.n_in) return GZT_ERR_ARG;
    if (f->priv_spent[i].script_len > cap) return GZT_ERR_BUFFER;
    memcpy(script, f->priv_spent[i].script, f->priv_spent[i].script_len);
    *amount = f->priv_spent[i].amount;
    *len_out = f->priv_spent[i].script_len;
    return GZT_OK;
}

gzt_err gzt_funding_spend_back(const secp256k1_context *ctx, const gzw_xprv *master,
                               const gzt_funding *f, uint32_t i, const uint8_t *dest,
                               size_t dest_len, uint64_t fee, const uint8_t aux32[32],
                               uint8_t *out, size_t cap, size_t *len_out) {
    uint8_t buf[GZT_MAX_TX_BYTES];
    size_t len = 0;
    gzt_tx *work = NULL;
    gzt_tx tx;
    gzt_err e = GZT_ERR_ARG;
    memset(&tx, 0, sizeof tx);
    if (!out || !len_out) return GZT_ERR_ARG;
    *len_out = 0;
    if (ctx && master && f && dest && aux32 && master->depth == 0) {
        e = held_ok(f, f->info.txid);
        if (!e && i >= f->priv_tx.n_in) e = GZT_ERR_ARG;
        if (!e && (!gzt_is_witness_program(dest, dest_len) || dest_len < 5 || dest_len > GZT_MAX_SCRIPT))
            e = GZT_ERR_SCRIPT;
        /* Never back to the factory: the spend-back pays nothing to it. */
        if (!e && dest_len == f->priv_tx.out[0].script_len &&
            memcmp(dest, f->priv_tx.out[0].script, dest_len) == 0)
            e = GZT_ERR_SCRIPT;
        if (!e && (fee > f->priv_spent[i].amount ||
                   f->priv_spent[i].amount - fee < gzt_dust_limit(dest, dest_len)))
            e = GZT_ERR_DUST;
        if (!e) {
            gzw_network knet;
            secp256k1_keypair kp;
            uint8_t aux_in[36], aux[32];
            work = &tx;
            work->version = 2;
            work->locktime = 0;
            work->n_in = 1;
            memcpy(work->in[0].prev_txid, f->priv_tx.in[i].prev_txid, 32);
            work->in[0].prev_vout = f->priv_tx.in[i].prev_vout;
            work->in[0].sequence = 0xfffffffdu;
            work->n_out = 1;
            work->out[0].value = f->priv_spent[i].amount - fee;
            work->out[0].script_len = (uint16_t)dest_len;
            memcpy(work->out[0].script, dest, dest_len);
            if (gzt_network_to_keys(f->priv_net, &knet)) e = GZT_ERR_ARG;
            if (!e && !gzw_bip86_tweaked_keypair(ctx, master, knet, f->priv_account, f->priv_key_change[i],
                                                 f->priv_key_index[i], &kp, NULL, NULL))
                e = GZT_ERR_KEY;
            if (!e) {
                memcpy(aux_in, aux32, 32);
                memcpy(aux_in + 32, "back", 4);
                gzt_sha256(aux_in, sizeof aux_in, aux);
                e = gzt_sign_keypath(ctx, work, &f->priv_spent[i], 0, &kp, aux);
                gzw_wipe(&kp, sizeof kp);
                gzw_wipe(aux, sizeof aux);
                gzw_wipe(aux_in, sizeof aux_in);
            }
            if (!e) e = gzt_tx_serialize(work, GZT_SER_WITNESS, buf, sizeof buf, &len);
            if (!e && len > cap) e = GZT_ERR_BUFFER;
            if (!e) memcpy(out, buf, len);
            gzw_wipe(&tx, sizeof tx);
            gzw_wipe(buf, sizeof buf);
        }
    }
    if (e) {
        if (cap) gzw_wipe(out, cap);
        return e;
    }
    *len_out = len;
    return GZT_OK;
}
