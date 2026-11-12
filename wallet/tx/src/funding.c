/* Coin selection and the factory funding.  See docs/notes/wallet-tx.md
 * sections 1.7 and 1.8. */

#include "internal.h"

#define P2TR_LEN 34
#define P2TR_DUST 330

/* Order: amount descending, then txid bytes, then vout. */
static int coin_before(const gzt_coin *a, const gzt_coin *b) {
    if (a->amount != b->amount) return a->amount > b->amount;
    int c = memcmp(a->txid, b->txid, 32);
    if (c) return c < 0;
    return a->vout < b->vout;
}

gzt_err gzt_select_coins(const gzt_coin *coins, size_t n_coins, const uint8_t *dest,
                         size_t dest_len, uint64_t amount, gzt_fee_policy fee,
                         gzt_selection *out) {
    uint32_t order[GZT_MAX_INPUTS];
    if (!out) return GZT_ERR_ARG;
    memset(out, 0, sizeof *out);
    if (!coins || !dest || n_coins == 0) return GZT_ERR_ARG;
    if (fee.rate.sat_per_kvb == 0 || fee.ceiling.sat_per_kvb > GZT_FEERATE_MAX_SAT_PER_KVB)
        return GZT_ERR_ARG;
    if (fee.rate.sat_per_kvb > fee.ceiling.sat_per_kvb) return GZT_ERR_FEE_CEILING;
    if (!gzt_is_witness_program(dest, dest_len)) return GZT_ERR_SCRIPT;
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
    for (size_t i = 0; i < n_coins; i++) {
        size_t pos = n_order;
        while (pos > 0 && coin_before(&coins[i], &coins[order[pos - 1]])) pos--;
        if (pos >= GZT_MAX_INPUTS) continue;
        size_t last = n_order < GZT_MAX_INPUTS ? n_order : GZT_MAX_INPUTS - 1;
        for (size_t k = last; k > pos; k--) order[k] = order[k - 1];
        order[pos] = (uint32_t)i;
        if (n_order < GZT_MAX_INPUTS) n_order++;
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
    return overpaid ? GZT_ERR_FEE_CEILING : GZT_ERR_FUNDS;
}

void gzt_funding_wipe(gzt_funding *f) {
    if (f) gzw_wipe(f, sizeof *f);
}

static gzt_err build(const secp256k1_context *ctx, const gzw_xprv *master,
                     const gzt_funding_request *req, const gzt_coin *coins, size_t n_coins,
                     const uint8_t aux32[32], gzt_funding *f) {
    gzt_spent_output spent[GZT_MAX_INPUTS];
    gzt_selection *sel = &f->info.selection;
    gzw_bip86_output change, out;
    gzw_network knet;
    gzt_err e;

    if (!ctx || !master || !req || !coins || !aux32 || !req->funding_script) return GZT_ERR_ARG;
    if (gzt_network_to_keys(req->net, &knet)) return GZT_ERR_ARG;
    if (master->depth != 0 || req->change_index >= GZW_HARDENED) return GZT_ERR_ARG;
    for (size_t i = 0; i < n_coins; i++)
        if (coins[i].change == 1 && coins[i].index == req->change_index) return GZT_ERR_ARG;
    if (!gzw_bip86_output_from_master(ctx, master, knet, req->account, 1, req->change_index,
                                      &change, NULL))
        return GZT_ERR_KEY;
    if (req->funding_script_len == P2TR_LEN &&
        memcmp(req->funding_script, change.script_pubkey, P2TR_LEN) == 0)
        return GZT_ERR_ARG;
    e = gzt_select_coins(coins, n_coins, req->funding_script, req->funding_script_len,
                         req->amount, req->fee, sel);
    if (e) return e;

    gzt_tx *tx = &f->priv_tx;
    tx->version = 2;
    tx->locktime = 0;
    tx->n_in = sel->n_selected;
    for (uint32_t i = 0; i < tx->n_in; i++) {
        const gzt_coin *c = &coins[sel->selected[i]];
        memcpy(tx->in[i].prev_txid, c->txid, 32);
        tx->in[i].prev_vout = c->vout;
        tx->in[i].sequence = 0xfffffffeu;
        memset(&spent[i], 0, sizeof spent[i]);
        spent[i].amount = c->amount;
        spent[i].script_len = P2TR_LEN;
        memcpy(spent[i].script, c->script, P2TR_LEN);
    }
    tx->n_out = sel->has_change ? 2 : 1;
    tx->out[0].value = req->amount;
    tx->out[0].script_len = (uint16_t)req->funding_script_len;
    memcpy(tx->out[0].script, req->funding_script, req->funding_script_len);
    if (sel->has_change) {
        tx->out[1].value = sel->change;
        tx->out[1].script_len = P2TR_LEN;
        memcpy(tx->out[1].script, change.script_pubkey, P2TR_LEN);
    }
    if ((e = gzt_tx_txid(tx, f->info.txid))) return GZT_ERR_INTERNAL;

    /* Sign each input on a copy, keep only the signatures. */
    gzt_tx work = *tx;
    for (uint32_t i = 0; i < tx->n_in; i++) {
        const gzt_coin *c = &coins[sel->selected[i]];
        secp256k1_keypair kp;
        uint8_t aux_in[36], aux[32];
        if (!gzw_bip86_tweaked_keypair(ctx, master, knet, req->account, c->change, c->index, &kp,
                                       &out, NULL)) {
            gzw_wipe(&work, sizeof work);
            return GZT_ERR_KEY;
        }
        if (memcmp(out.script_pubkey, c->script, P2TR_LEN) != 0) {
            gzw_wipe(&kp, sizeof kp);
            gzw_wipe(&work, sizeof work);
            return GZT_ERR_KEY;
        }
        memcpy(aux_in, aux32, 32);
        for (int b = 0; b < 4; b++) aux_in[32 + b] = (uint8_t)(i >> (8 * b));
        gzt_sha256(aux_in, sizeof aux_in, aux);
        e = gzt_sign_keypath(ctx, &work, spent, i, &kp, aux);
        gzw_wipe(&kp, sizeof kp);
        gzw_wipe(aux, sizeof aux);
        gzw_wipe(aux_in, sizeof aux_in);
        if (e) {
            gzw_wipe(&work, sizeof work);
            return e;
        }
        memcpy(f->priv_sigs[i], work.in[i].witness[0].data, 64);
    }

    /* The signed size must be the size the fee was computed for. */
    uint64_t weight, vsize;
    uint8_t txid2[32];
    e = gzt_tx_weight(&work, &weight, &vsize);
    if (!e) e = gzt_tx_txid(&work, txid2);
    gzw_wipe(&work, sizeof work);
    if (e || vsize != sel->vsize || memcmp(txid2, f->info.txid, 32) != 0) return GZT_ERR_INTERNAL;
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

gzt_err gzt_funding_build(const secp256k1_context *ctx, const gzw_xprv *master,
                          const gzt_funding_request *req, const gzt_coin *coins,
                          size_t n_coins, const uint8_t aux32[32], gzt_funding *out) {
    if (!out) return GZT_ERR_ARG;
    gzt_funding_wipe(out);
    gzt_err e = build(ctx, master, req, coins, n_coins, aux32, out);
    if (e) gzt_funding_wipe(out);
    return e;
}

gzt_err gzt_funding_release(gzt_funding *f, const uint8_t expect_txid[32], uint8_t *out,
                            size_t cap, size_t *len_out) {
    if (!f || !expect_txid || !out || !len_out) return GZT_ERR_ARG;
    *len_out = 0;
    if (f->priv_state != 1) return GZT_ERR_STATE;
    if (!gzw_ct_equal(expect_txid, f->info.txid, 32)) return GZT_ERR_STATE;
    gzt_tx signed_tx = f->priv_tx;
    for (uint32_t i = 0; i < signed_tx.n_in; i++) {
        signed_tx.in[i].witness_count = 1;
        signed_tx.in[i].witness[0].len = 64;
        memcpy(signed_tx.in[i].witness[0].data, f->priv_sigs[i], 64);
    }
    gzt_err e = gzt_tx_serialize(&signed_tx, GZT_SER_WITNESS, out, cap, len_out);
    gzw_wipe(&signed_tx, sizeof signed_tx);
    return e;
}
