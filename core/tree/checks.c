/* The creation checks: spec/safety-rule.md C1 to C11 for a member and H1 for
 * the host, with signing-round.md 4.1's table and messages.md 7.2's member
 * checks. The order is tree.h's (gz_tree_member_check). */
#include "gazpacho/tree.h"
#include "internal.h"

#include <string.h>

uint16_t gz_tree_reason(gz_chk_t c)
{
    switch (c) {
    case GZ_CHK_OK: return GZ_REASON_NONE;
    case GZ_CHK_BINDING: return GZ_REASON_INVALID;
    case GZ_CHK_C7_NOT_MY_KEY: return GZ_REASON_NOT_MY_KEY;
    case GZ_CHK_C10_BUSY: return GZ_REASON_BUSY;
    case GZ_CHK_C7_OTHER_TREE: return GZ_REASON_OTHER_TREE;
    case GZ_CHK_C8A_PURPOSE: case GZ_CHK_C8A_VERSION: case GZ_CHK_C8A_DIGEST: case GZ_CHK_C8A_READY_OUTER:
    case GZ_CHK_C8_PLACEMENT: case GZ_CHK_C8_ANCHORS: case GZ_CHK_C8_K: case GZ_CHK_C8_LAYER_STEP:
    case GZ_CHK_C8_LAYER_STATES: case GZ_CHK_C8_HASHES: case GZ_CHK_C8_DISTRIBUTION: case GZ_CHK_C8_DEADLINES:
    case GZ_CHK_C8_MEMBERS_TERMS: case GZ_CHK_C8_MEMBERS_OWN: case GZ_CHK_C8_NO_SHAPE: case GZ_CHK_C8_SHAPE:
    case GZ_CHK_C8_FIXED_LEVELS: case GZ_CHK_C8_FEE_RULE: case GZ_CHK_C8_FEE_CEILING:
    case GZ_CHK_C8_FUNDING_RULE: case GZ_CHK_C8_LSTOCK_DELAY: case GZ_CHK_C8_END_ZERO:
    case GZ_CHK_C8_END_WINDOW: case GZ_CHK_C8_END_LOCKTIME: case GZ_CHK_C8_EXIT_TIME: case GZ_CHK_C8_UNDERFUNDED: case GZ_CHK_C8_DUST:
    case GZ_CHK_C8_IMPORT_MINIMUM: case GZ_CHK_C8_LEAF_KIND: case GZ_CHK_C8_OWN_LEAF:
    case GZ_CHK_C8_CHANNEL_TERMS: case GZ_CHK_C8_CHANNEL_OWN: case GZ_CHK_C6_TIERS:
        return GZ_REASON_CONDITIONS;
    case GZ_CHK_C1_PARTICIPANTS: case GZ_CHK_C1_DUPLICATE_KEY: case GZ_CHK_C1_BAD_KEY: case GZ_CHK_C1_HOST_KEY:
    case GZ_CHK_C1_FUNDING_TX: case GZ_CHK_C1_FUNDING_TXID: case GZ_CHK_C1_FUNDING_VOUT:
    case GZ_CHK_C1_FUNDING_AMOUNT: case GZ_CHK_C1_FUNDING_SCRIPT_LEN: case GZ_CHK_C1_FUNDING_SCRIPT:
    case GZ_CHK_C1_NOT_AGGREGATE: case GZ_CHK_C1_IMPORT_DIFFERS: case GZ_CHK_C1_IMPORT_FAILED:
    case GZ_CHK_C5_UNKNOWN_PATH: case GZ_CHK_CRYPTO: case GZ_CHK_ARGUMENT:
        return GZ_REASON_UNSAFE;
    }
    return GZ_REASON_UNSAFE;
}

/* Names, NUL-separated, in enum order (generated from tree.h; test_tree_checks
 * checks every one). A table of pointers would need relocations, which the
 * isolation check reads as writable data in a sanitizer build. */
static const char CHK_NAMES[] =
    "ok\0"
    "c8a_purpose\0"
    "c8a_version\0"
    "c8a_digest\0"
    "c8a_ready_outer\0"
    "c1_participants\0"
    "c1_duplicate_key\0"
    "c1_bad_key\0"
    "c1_host_key\0"
    "c1_funding_tx\0"
    "c1_funding_txid\0"
    "c1_funding_vout\0"
    "c1_funding_amount\0"
    "c1_funding_script_len\0"
    "c1_funding_script\0"
    "c1_not_aggregate\0"
    "c1_import_differs\0"
    "c1_import_failed\0"
    "binding\0"
    "c7_not_my_key\0"
    "c10_busy\0"
    "c7_other_tree\0"
    "c8_placement\0"
    "c8_anchors\0"
    "c8_k\0"
    "c8_layer_step\0"
    "c8_layer_states\0"
    "c8_hashes\0"
    "c8_distribution\0"
    "c8_deadlines\0"
    "c8_members_terms\0"
    "c8_members_own\0"
    "c8_no_shape\0"
    "c8_shape\0"
    "c8_fixed_levels\0"
    "c8_fee_rule\0"
    "c8_fee_ceiling\0"
    "c8_funding_rule\0"
    "c8_lstock_delay\0"
    "c8_end_zero\0"
    "c8_end_window\0"
    "c8_end_locktime\0"
    "c8_exit_time\0"
    "c8_underfunded\0"
    "c8_dust\0"
    "c8_import_minimum\0"
    "c8_leaf_kind\0"
    "c8_own_leaf\0"
    "c8_channel_terms\0"
    "c8_channel_own\0"
    "c6_tiers\0"
    "c5_unknown_path\0"
    "crypto\0"
    "argument\0"
    ;

const char *gz_chk_name(gz_chk_t c)
{
    const char *p = CHK_NAMES;
    int i;
    if ((int)c < (int)GZ_CHK_OK || (int)c > (int)GZ_CHK_ARGUMENT) return "unknown";
    for (i = 0; i < (int)c; i++) {
        while (*p) p++;
        p++;
    }
    return p;
}

static int fail(gz_tree_verdict_t *v, gz_chk_t c, int32_t at)
{
    v->check = c;
    v->reason = gz_tree_reason(c);
    v->at = at;
    return 0;
}

static int same_outpoint(const gz_tree_outpoint_t *a, const uint8_t txid[32], uint32_t vout)
{
    return a->vout == vout && tr_eq(a->txid, txid, 32);
}

int gz_tree_c10_busy(const gz_tree_outpoint_t *f, const gz_tree_outpoint_t *u, size_t n)
{
    size_t i;
    if (!f || (n && !u)) return 1;
    for (i = 0; i < n; i++)
        if (same_outpoint(&u[i], f->txid, f->vout)) return 1;
    return 0;
}

/* C1, messages.md 7.2 record 20: count, valid keys, all 2n keys distinct, the
 * host's contribution key is its long-term key (signing-round.md 2). */
static int check_participants(const gz_tree_member_in_t *in, const gz_tree_proposal_t *p, gz_tree_verdict_t *v)
{
    size_t np = p->n_participants, i, j;
    const gz_tree_participant_t *ps = p->participants;
    if (!ps || np < 2 || np > GZ_TREE_MAX_MEMBERS + 1) return fail(v, GZ_CHK_C1_PARTICIPANTS, -1);
    for (i = 0; i < np; i++)
        if (!in->crypto->point_valid(in->crypto->ctx, ps[i].factory_key)
            || !in->crypto->point_valid(in->crypto->ctx, ps[i].contribution_key))
            return fail(v, GZ_CHK_C1_BAD_KEY, (int32_t)i);
    /* Distinct as x coordinates: P and -P are one BIP 340 key (review A, S1). */
    for (i = 0; i < np; i++) {
        if (tr_eq(ps[i].factory_key + 1, ps[i].contribution_key + 1, 32)) return fail(v, GZ_CHK_C1_DUPLICATE_KEY, (int32_t)i);
        for (j = i + 1; j < np; j++)
            if (tr_eq(ps[i].factory_key + 1, ps[j].factory_key + 1, 32)
                || tr_eq(ps[i].contribution_key + 1, ps[j].contribution_key + 1, 32)
                || tr_eq(ps[i].factory_key + 1, ps[j].contribution_key + 1, 32)
                || tr_eq(ps[i].contribution_key + 1, ps[j].factory_key + 1, 32))
                return fail(v, GZ_CHK_C1_DUPLICATE_KEY, (int32_t)j);
    }
    if (!tr_eq(ps[0].contribution_key, in->outer->host_key, 33)) return fail(v, GZ_CHK_C1_HOST_KEY, 0);
    return 1;
}

/* messages.md 6.3: binding = TH("gazpacho/bind", scope || factory key || contribution key),
 * signed by both keys. */
static int check_bindings(const gz_tree_member_in_t *in, const gz_tree_proposal_t *p, gz_tree_verdict_t *v)
{
    size_t i;
    for (i = 0; i < p->n_participants; i++) {
        const gz_tree_participant_t *q = &p->participants[i];
        uint8_t h[32];
        tr_sha256_t s;
        tr_tagged_init(&s, "gazpacho/bind");
        tr_sha256_write(&s, in->outer_digest, 32);
        tr_sha256_write(&s, q->factory_key, 33);
        tr_sha256_write(&s, q->contribution_key, 33);
        tr_sha256_done(&s, h);
        if (!in->crypto->verify(in->crypto->ctx, h, q->factory_key, q->bind_by_factory)
            || !in->crypto->verify(in->crypto->ctx, h, q->contribution_key, q->bind_by_contribution))
            return fail(v, GZ_CHK_BINDING, (int32_t)i);
    }
    return 1;
}

/* C1: the funding transaction fixes the outpoint, its amount and script; the
 * script is the BIP 86 key of the aggregate of every participant in order. */
static int check_funding(const gz_tree_member_in_t *in, const gz_tree_proposal_t *p, uint8_t (*keys)[33],
                         gz_tree_verdict_t *v)
{
    gz_tx_info_t info;
    uint8_t txid[32], internal[32], out_key[32];
    uint64_t amount;
    const uint8_t *script;
    size_t script_len, i;
    if (!p->funding_tx || !gz_tx_parse(p->funding_tx, p->funding_tx_len, &info)) return fail(v, GZ_CHK_C1_FUNDING_TX, -1);
    gz_tx_txid(p->funding_tx, p->funding_tx_len, txid);
    if (!tr_eq(txid, p->funding_txid, 32)) return fail(v, GZ_CHK_C1_FUNDING_TXID, -1);
    if (p->funding_vout >= info.n_out) return fail(v, GZ_CHK_C1_FUNDING_VOUT, -1);
    if (!gz_tx_output(p->funding_tx, p->funding_tx_len, &info, p->funding_vout, &amount, &script, &script_len))
        return fail(v, GZ_CHK_C1_FUNDING_TX, -1);
    if (amount != p->funding_amount) return fail(v, GZ_CHK_C1_FUNDING_AMOUNT, -1);
    if (p->funding_script_len != 34) return fail(v, GZ_CHK_C1_FUNDING_SCRIPT_LEN, -1);
    if (script_len != 34 || !tr_eq(script, p->funding_script, 34)) return fail(v, GZ_CHK_C1_FUNDING_SCRIPT, -1);
    for (i = 1; i < p->n_participants; i++) memcpy(keys[i - 1], p->participants[i].factory_key, 33);
    if (!in->crypto->agg_tweak(in->crypto->ctx, p->participants[0].factory_key, (const uint8_t(*)[33])keys,
                               p->n_participants - 1, NULL, internal, out_key))
        return fail(v, GZ_CHK_CRYPTO, -1);
    if (p->funding_script[0] != 0x51 || p->funding_script[1] != 0x20 || !tr_eq(p->funding_script + 2, out_key, 32))
        return fail(v, GZ_CHK_C1_NOT_AGGREGATE, -1);
    return 1;
}

/* C1's comparison with the import, and C8's leaf-kind row on the import's own
 * labels (is_ps_leaf and the signer count). */
static int check_import(const gz_tree_member_in_t *in, const gz_tree_build_in_t *bi, const gz_tree_t *t,
                        gz_tree_verdict_t *v)
{
    const gz_tree_import_t *im = in->import_out;
    uint32_t i, leaves = 0;
    if (!in->import_build(in->import_ctx, bi, in->import_out)) return fail(v, GZ_CHK_C1_IMPORT_FAILED, -1);
    if (im->n_nodes != t->n_nodes) return fail(v, GZ_CHK_C1_IMPORT_DIFFERS, -1);
    for (i = 0; i < t->n_nodes; i++) {
        const gz_tree_node_t *n = &t->node[i];
        if (im->node[i].tx_len != n->tx_len || !tr_eq(im->node[i].tx, n->tx, n->tx_len)
            || im->node[i].parent != n->parent || im->node[i].parent_vout != n->parent_vout
            || im->node[i].kind != n->kind || im->node[i].n_signers != 1 + n->count)
            return fail(v, GZ_CHK_C1_IMPORT_DIFFERS, (int32_t)i);
    }
    for (i = 0; i < t->n_nodes; i++) {
        int leaf = t->node[i].kind == GZ_NODE_LEAF_STATE;
        if (im->node[i].is_ps_leaf != leaf || (leaf && im->node[i].n_signers != 2))
            return fail(v, GZ_CHK_C8_LEAF_KIND, (int32_t)i);
        leaves += (uint32_t)leaf;
    }
    if (leaves != t->n_members) return fail(v, GZ_CHK_C8_LEAF_KIND, -1);
    return 1;
}

/* C5 on the member's path: every output of every transaction on it is one the
 * module recognises (tree.h GZ_OUT_*), each spent output carries exactly the
 * timeout exit.md 4.1 says, and the channel output copies the leaf
 * transaction's script, so the commitment's competing claim is H_leaf. */
static int check_path(const gz_tree_t *t, uint32_t member, uint32_t E, gz_tree_verdict_t *v)
{
    uint16_t path[GZ_TREE_MAX_DEPTH + 2];
    size_t n = 0, i, o;
    int idx = t->leaf_state[member];
    uint32_t d = t->node[idx].depth;
    while (idx >= 0 && n < GZ_TREE_MAX_DEPTH + 2) {
        path[n++] = (uint16_t)idx;
        idx = t->node[idx].parent;
    }
    if (idx >= 0 || n != d + 2) return fail(v, GZ_CHK_C5_UNKNOWN_PATH, (int32_t)member);
    for (i = 0; i < n; i++) {
        const gz_tree_node_t *nd = &t->node[path[n - 1 - i]];
        int none;
        int64_t want = gz_exit_path_timeout(E, d, (uint32_t)i, &none);
        if (none ? nd->cltv != 0 : (want <= 0 ? nd->cltv != 0 : (int64_t)nd->cltv != want))
            return fail(v, GZ_CHK_C5_UNKNOWN_PATH, (int32_t)member);
        if (nd->has_merkle != (nd->cltv > 0)) return fail(v, GZ_CHK_C5_UNKNOWN_PATH, (int32_t)member);
        for (o = 0; o < nd->n_out; o++) {
            uint8_t k = nd->out_kind[o];
            if (k == GZ_OUT_ANCHOR) {
                if (nd->out_amount[o] != GZ_TREE_ANCHOR_SAT || nd->out_script_len[o] != 4)
                    return fail(v, GZ_CHK_C5_UNKNOWN_PATH, (int32_t)member);
            } else if (k == GZ_OUT_CHANNEL) {
                if (!tr_eq(nd->out_script[o], nd->spent_script, 34))
                    return fail(v, GZ_CHK_C5_UNKNOWN_PATH, (int32_t)member);
            } else if (k != GZ_OUT_CHILD && k != GZ_OUT_STATE && k != GZ_OUT_LSTOCK) {
                return fail(v, GZ_CHK_C5_UNKNOWN_PATH, (int32_t)member);
            }
        }
    }
    return 1;
}

void gz_tree_member_check(const gz_tree_member_in_t *in, const gz_tree_proposal_t *p, gz_tree_t *t,
                          gz_tree_verdict_t *v)
{
    const gz_terms_outer_t *o;
    const gz_tree_conditions_t *cond;
    gz_tree_params_t prm;
    gz_tree_build_in_t bi;
    gz_tree_b_err_t be;
    gz_tree_outpoint_t fo;
    uint8_t keys[GZ_TREE_MAX_MEMBERS][33];
    uint32_t n, own = 0, i, found = 0, leaves_of_mine = 0;
    int64_t expect, E;
    if (!v) return;
    memset(v, 0, sizeof *v);
    v->at = -1;
    if (!in || !p || !t || !in->outer || !in->outer_digest || !in->frozen || !in->frozen_digest
        || !in->ready_outer_digest || !in->ready_current_digest || !in->cond || !in->crypto
        || !in->crypto->point_valid || !in->crypto->verify || !in->crypto->agg_tweak
        || !in->import_build || !in->import_out
        || (in->n_exposures && !in->exposures) || (in->n_unresolved && !in->unresolved)) {
        fail(v, GZ_CHK_ARGUMENT, -1);
        return;
    }
    o = in->outer;
    cond = in->cond;

    /* C8a: the frozen terms, as named in the member's own ready. */
    if (p->purpose != 1) { fail(v, GZ_CHK_C8A_PURPOSE, -1); return; }
    if (p->terms_version != in->frozen->version || in->ready_version != in->frozen->version) {
        fail(v, GZ_CHK_C8A_VERSION, -1);
        return;
    }
    if (!tr_eq(p->terms_digest, in->frozen_digest, 32) || !tr_eq(in->ready_current_digest, in->frozen_digest, 32)) {
        fail(v, GZ_CHK_C8A_DIGEST, -1);
        return;
    }
    if (!tr_eq(in->ready_outer_digest, in->outer_digest, 32) || !tr_eq(in->frozen->outer_digest, in->outer_digest, 32)) {
        fail(v, GZ_CHK_C8A_READY_OUTER, -1);
        return;
    }

    /* C1: participants; then the bindings. */
    if (!check_participants(in, p, v) || !check_bindings(in, p, v)) return;
    n = (uint32_t)p->n_participants - 1;

    /* C7, fresh funding output: the member's current factory and contribution
     * keys for this lobby, together, as a member (never as the host). */
    if (in->own_factory_key && in->own_contribution_key)
        for (i = 1; i < p->n_participants; i++)
            if (tr_eq(p->participants[i].factory_key, in->own_factory_key, 33)
                && tr_eq(p->participants[i].contribution_key, in->own_contribution_key, 33)) {
                found++;
                own = i - 1;
            }
    if (found != 1) { fail(v, GZ_CHK_C7_NOT_MY_KEY, -1); return; }

    /* C10. */
    memcpy(fo.txid, p->funding_txid, 32);
    fo.vout = p->funding_vout;
    if (gz_tree_c10_busy(&fo, in->unresolved, in->n_unresolved)) { fail(v, GZ_CHK_C10_BUSY, -1); return; }

    /* C8: fields signing-round.md 4.1 fixes for 1.0.0 and Slice 1. */
    if (p->placement != 0) { fail(v, GZ_CHK_C8_PLACEMENT, -1); return; }
    if (p->tree_anchors != 1) { fail(v, GZ_CHK_C8_ANCHORS, -1); return; }
    if (p->k != 1) { fail(v, GZ_CHK_C8_K, -1); return; }
    if (p->layer_step != GZ_TREE_SLICE1_STEP) { fail(v, GZ_CHK_C8_LAYER_STEP, -1); return; }
    if (p->layer_states != GZ_TREE_SLICE1_STATES) { fail(v, GZ_CHK_C8_LAYER_STATES, -1); return; }
    if (p->n_lstock_hashes != 0) { fail(v, GZ_CHK_C8_HASHES, -1); return; }
    if (p->has_distribution) { fail(v, GZ_CHK_C8_DISTRIBUTION, -1); return; }
    if (p->nonces_due_ms > o->step_timeout_ms || p->sigs_due_ms > o->step_timeout_ms) {
        fail(v, GZ_CHK_C8_DEADLINES, -1);
        return;
    }
    /* C8: the member count, the terms' then the member's own. */
    if (n < o->minimum || n > o->target) { fail(v, GZ_CHK_C8_MEMBERS_TERMS, (int32_t)n); return; }
    if (n < cond->min_members || n > cond->max_members) { fail(v, GZ_CHK_C8_MEMBERS_OWN, (int32_t)n); return; }
    /* C8: the spare-liquidity delay. 0 would silently become the import's
     * default (factory_set_l_stock_csv), and a CSV above 65,535 blocks is not
     * a block count under BIP 68. */
    if (p->lstock_delay == 0 || p->lstock_delay > 0xffff || p->lstock_delay < cond->min_lstock_delay
        || p->lstock_delay > cond->max_lstock_delay) {
        fail(v, GZ_CHK_C8_LSTOCK_DELAY, -1);
        return;
    }
    /* C8: shape, fixed levels, fee and funding, all derived from the terms. */
    switch (gz_tree_params(o, n, &prm)) {
    case GZ_TREE_P_OK: break;
    case GZ_TREE_P_COUNT: fail(v, GZ_CHK_C8_MEMBERS_TERMS, (int32_t)n); return;
    case GZ_TREE_P_NO_SHAPE: fail(v, GZ_CHK_C8_NO_SHAPE, (int32_t)n); return;
    case GZ_TREE_P_SPLIT: fail(v, GZ_CHK_C8_SHAPE, (int32_t)n); return;
    case GZ_TREE_P_OVERFLOW: fail(v, GZ_CHK_C8_FUNDING_RULE, -1); return;
    }
    if (p->fixed_levels != prm.D) { fail(v, GZ_CHK_C8_FIXED_LEVELS, -1); return; }
    if (p->fee_per_tx != prm.fee_per_tx) { fail(v, GZ_CHK_C8_FEE_RULE, -1); return; }
    if (p->fee_per_tx > cond->max_fee_per_tx_sat) { fail(v, GZ_CHK_C8_FEE_CEILING, -1); return; }
    if (p->funding_amount != prm.funding_amount) { fail(v, GZ_CHK_C8_FUNDING_RULE, -1); return; }
    /* C8: the end height, then the exit-time check for the member's own leaf. */
    E = p->end_height;
    if (E == 0) { fail(v, GZ_CHK_C8_END_ZERO, -1); return; }
    expect = (int64_t)in->tip + o->lifetime_blocks + o->winddown_blocks;
    if (E > expect + cond->end_window || E < expect - cond->end_window) { fail(v, GZ_CHK_C8_END_WINDOW, -1); return; }
    /* Lock times from 500,000,000 are Unix times, already past (review A, S2). */
    if (E >= 500000000) { fail(v, GZ_CHK_C8_END_LOCKTIME, -1); return; }
    if (!gz_exit_signing_check(E, prm.depth[own], (int64_t)in->tip + cond->funding_deadline_blocks, &cond->exit)) {
        fail(v, GZ_CHK_C8_EXIT_TIME, (int32_t)own);
        return;
    }

    /* C1: the funding transaction and its script. */
    if (!check_funding(in, p, keys, v)) return;

    /* C1: rebuilt here, from the rules, then compared with the import. */
    bi.levels = prm.levels;
    bi.n_levels = prm.n_levels;
    bi.fixed_levels = p->fixed_levels;
    bi.n_members = n;
    bi.host_key = p->participants[0].factory_key;
    bi.member_keys = (const uint8_t(*)[33])keys;
    bi.end_height = p->end_height;
    bi.fee_per_tx = p->fee_per_tx;
    bi.lstock_csv = p->lstock_delay;
    memcpy(bi.funding_txid, p->funding_txid, 32);
    bi.funding_vout = p->funding_vout;
    bi.funding_amount = p->funding_amount;
    memcpy(bi.funding_script, p->funding_script, 34);
    be = gz_tree_build(&bi, in->crypto, t);
    switch (be) {
    case GZ_TREE_B_OK: break;
    case GZ_TREE_B_SPLIT: fail(v, GZ_CHK_C8_SHAPE, -1); return;
    case GZ_TREE_B_FIXED_LEVELS: fail(v, GZ_CHK_C8_FIXED_LEVELS, -1); return;
    case GZ_TREE_B_UNDERFUNDED: fail(v, GZ_CHK_C8_UNDERFUNDED, -1); return;
    case GZ_TREE_B_DUST: fail(v, GZ_CHK_C8_DUST, -1); return;
    case GZ_TREE_B_IMPORT_MINIMUM: fail(v, GZ_CHK_C8_IMPORT_MINIMUM, -1); return;
    case GZ_TREE_B_CRYPTO: fail(v, GZ_CHK_CRYPTO, -1); return;
    case GZ_TREE_B_ARGUMENT: fail(v, GZ_CHK_ARGUMENT, -1); return;
    }
    if (!check_import(in, &bi, t, v)) return;

    /* C2 and C8: the member's own leaf, found from its own key. */
    for (i = 0; i < n; i++) {
        const gz_tree_node_t *s = &t->node[t->leaf_state[i]];
        if (tr_eq(p->participants[1 + s->first].factory_key, in->own_factory_key, 33)) leaves_of_mine++;
    }
    if (leaves_of_mine != 1 || t->node[t->leaf_state[own]].first != own) { fail(v, GZ_CHK_C8_OWN_LEAF, (int32_t)own); return; }
    /* C8: every channel at least channel_sat, the member's own at least its own minimum. */
    for (i = 0; i < n; i++)
        if (t->node[t->leaf_state[i]].out_amount[0] < o->channel_sat) { fail(v, GZ_CHK_C8_CHANNEL_TERMS, (int32_t)i); return; }
    if (t->node[t->leaf_state[own]].out_amount[0] < cond->min_own_channel_sat) {
        fail(v, GZ_CHK_C8_CHANNEL_OWN, (int32_t)own);
        return;
    }
    /* C5. */
    if (!check_path(t, own, p->end_height, v)) return;
    /* C6: one tier, every tree transaction in it. */
    if (p->n_tiers != 1 || p->tier_sizes[0] != t->n_nodes) { fail(v, GZ_CHK_C6_TIERS, -1); return; }
    /* C7: one tree per funding output. */
    gz_tree_digest(t, o->chain, p->funding_txid, p->funding_vout, p->funding_amount, p->participants,
                   p->n_participants, v->tree_digest);
    for (i = 0; i < in->n_exposures; i++)
        if (same_outpoint(&in->exposures[i].funding, p->funding_txid, p->funding_vout)
            && !tr_eq(in->exposures[i].tree_digest, v->tree_digest, 32)) {
            fail(v, GZ_CHK_C7_OTHER_TREE, (int32_t)i);
            return;
        }
    v->own_member = own;
    v->own_depth = prm.depth[own];
    v->leave_by = gz_exit_leave_by(E, prm.depth[own], (uint32_t)prm.depth[own] + 3, &cond->exit);
    v->check = GZ_CHK_OK;
    v->reason = GZ_REASON_NONE;
}

int gz_tree_c4d_dead(const uint8_t *funding_tx, size_t len, const uint8_t spent[36], const uint8_t spender_txid[32])
{
    gz_tx_info_t info;
    uint8_t txid[32];
    size_t i;
    if (!funding_tx || !spent || !spender_txid || !gz_tx_parse(funding_tx, len, &info)) return 0;
    gz_tx_txid(funding_tx, len, txid);
    if (tr_eq(txid, spender_txid, 32)) return 0;
    for (i = 0; i < info.n_in; i++) {
        const uint8_t *op;
        if (gz_tx_input(funding_tx, len, &info, i, &op, NULL, NULL) && tr_eq(op, spent, 36)) return 1;
    }
    return 0;
}

gz_c11_t gz_tree_c11(const gz_tree_c11_in_t *in)
{
    int64_t deadline, leave_by;
    if (!in || !in->cond || !in->funding_script) return GZ_C11_WAIT;
    deadline = (int64_t)in->ack_tip + in->cond->funding_deadline_blocks;
    if (in->seen && (in->seen_amount != in->funding_amount || in->seen_script_len != 34 || !in->seen_script
                     || !tr_eq(in->seen_script, in->funding_script, 34)))
        return GZ_C11_MISMATCH;
    if (!in->seen || in->confirmations < in->cond->exit.B)
        return (int64_t)in->tip > deadline ? GZ_C11_ABANDONED : GZ_C11_WAIT;
    leave_by = gz_exit_leave_by(in->end_height, in->own_depth, (uint32_t)in->own_depth + 3, &in->cond->exit);
    /* On time: the signing-time check, with the deadline that really applies
     * (the ack's tip + the funding deadline; review A, R1). A member that ran
     * gz_tree_may_ack never gets here with it failing; a caller that did not
     * still never sees a factory live after its leave_by. */
    if ((int64_t)in->buried_at <= deadline)
        return gz_exit_signing_check(in->end_height, in->own_depth, deadline, &in->cond->exit) ? GZ_C11_LIVE
                                                                                                 : GZ_C11_ABANDONED;
    /* Buried late: live only with the whole signed tree held and the time
     * check passing again now (one block of being live left before leave_by). */
    if (in->holds_whole_tree && leave_by >= (int64_t)in->tip + 1) return GZ_C11_LIVE;
    return GZ_C11_ABANDONED;
}

int gz_tree_may_ack(uint32_t end_height, uint8_t own_depth, uint32_t ack_tip, const gz_tree_conditions_t *cond)
{
    if (!cond) return 0;
    return gz_exit_signing_check(end_height, own_depth, (int64_t)ack_tip + cond->funding_deadline_blocks, &cond->exit);
}

/* BIP 141: a witness program is a version byte (OP_0, OP_1..OP_16) and one
 * push of 2 to 40 bytes; version 0 only 20 or 32. */
static int witness_program(const uint8_t *s, size_t n)
{
    if (!s || n < 4 || n > 42) return 0;
    if (s[0] != 0x00 && (s[0] < 0x51 || s[0] > 0x60)) return 0;
    if (s[1] != n - 2) return 0;
    if (s[0] == 0x00 && n - 2 != 20 && n - 2 != 32) return 0;
    return 1;
}

gz_h1_t gz_tree_h1(const gz_tree_h1_in_t *in, size_t *at)
{
    gz_tx_info_t info;
    size_t i, dummy;
    if (!at) at = &dummy;
    *at = 0;
    if (!in || (in->n_members && !in->acked) || (in->n_nodes && !in->signed_ok) || !in->proposed_tx || !in->to_sign_tx)
        return GZ_H1_ARGUMENT;
    if (in->n_members == 0 || in->n_nodes == 0) return GZ_H1_EMPTY;
    for (i = 0; i < in->n_members; i++)
        if (!in->acked[i]) { *at = i; return GZ_H1_ACK_MISSING; }
    for (i = 0; i < in->n_nodes; i++)
        if (!in->signed_ok[i]) { *at = i; return GZ_H1_UNSIGNED; }
    if (in->proposed_len != in->to_sign_len || !tr_eq(in->proposed_tx, in->to_sign_tx, in->to_sign_len))
        return GZ_H1_TX_DIFFERS;
    if (!gz_tx_parse(in->proposed_tx, in->proposed_len, &info)) return GZ_H1_TX_INVALID;
    if (!in->prev_scripts || !in->prev_script_lens) return GZ_H1_ARGUMENT;
    if (in->n_prev != info.n_in) return GZ_H1_PREV_COUNT;
    for (i = 0; i < info.n_in; i++) {
        size_t script_len;
        if (!gz_tx_input(in->proposed_tx, in->proposed_len, &info, i, NULL, &script_len, NULL)) return GZ_H1_TX_INVALID;
        if (script_len != 0 || !witness_program(in->prev_scripts[i], in->prev_script_lens[i])) {
            *at = i;
            return GZ_H1_NOT_SEGWIT;
        }
    }
    return GZ_H1_OK;
}
