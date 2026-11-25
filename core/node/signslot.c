/* The signing engine in the composite (docs/notes/composite-node.md P4.3):
 * core/signing's engine behind the composite's engine interface (area Round,
 * 0x0002), with the hooks the composite fills.
 *
 *   KEYS (2.5, 12.2). The key hook finds a scope's (epoch, index) in its slot,
 *   or, for a lobby that has ended, in the table of keyed scopes the node part
 *   keeps (np.keyed). The contribution key is the slot's (a member) or the
 *   host's long-term key; the factory key is the pair's second. Under AT_JOIN
 *   a member's factory key exists only while its lobby's gate is open: it is
 *   derived when the person readies with the passphrase, bound to the values
 *   digest the person readied for, and wiped when the gate closes. The hook
 *   gives it only for a round whose frozen terms digest is that digest.
 *
 *   THE BUILDER (9.2, 13). A member checks a proposal only against what its
 *   lobby accepted (gz_lobby_member_accepted): a check it did not answer, a
 *   withdrawn, unchosen or spent one is ignored, unanswered. Then the
 *   safe-to-sign checks (gz_tree_member_check, with the imported builder the
 *   program plugs in) against the lobby's stored terms and the member's own
 *   limits. The host builds the round it proposes from the lobby's terms
 *   (gz_tree_params, gz_tree_build), the same rules its members check. A
 *   round saved at a start is rebuilt from the proposal and the lobby's terms
 *   alone (no time or tip checks).
 *
 *   OUTCOMES (9.3, rule 2). The engine reports right after its own save; the
 *   outcome reaches the slot's lobby at once, inside the same call, so that
 *   the lobby's save joins the engine's batch by adjacency. When the lobby is
 *   the one calling (a refused begin, a member that left), the outcome waits
 *   in a small queue and is given in a bracket of its own as soon as that
 *   call has returned (gz_sg_drain): no engine is entered from its own hook
 *   (U1).
 *
 *   THE FUNDING PLAN (P4.6). The host's funding transaction is the funding
 *   engine's plan of the attempt (fundslot.c, 9.2 step 1), through the
 *   program's wallet port. Only a test-build node with no wallet port keeps
 *   the old stand-in: one made-up input named by the scope, the check and
 *   the attempt, never broadcast.
 *
 * THE ENGINE RULE. Nothing here returns an error for what a peer, the key
 * port, the person or the chain can cause: a builder refusal is a refusal, a
 * key the port does not give is no key, an outcome for a lobby that has ended
 * is counted and dropped. */
#include "internal.h"
#include <string.h>

/* ---- small helpers -------------------------------------------------------- */

static int sg_same(const void *a, const void *b, size_t n) { return memcmp(a, b, n) == 0; }

static void sg_wipe(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

static const gz_tree_crypto_t *sg_crypto(const gz_node_t *c) { return (const gz_tree_crypto_t *)c->cfg.tree_crypto; }

static void put_hex4(char *p, size_t cap, size_t *at, const uint8_t *b)
{
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 4 && *at + 2 < cap; i++) {
        p[(*at)++] = H[b[i] >> 4];
        p[(*at)++] = H[b[i] & 15];
    }
    p[*at] = 0;
}

static void put_txt(char *p, size_t cap, size_t *at, const char *s)
{
    while (*s && *at + 1 < cap) p[(*at)++] = *s++;
    p[*at] = 0;
}

static void put_num(char *p, size_t cap, size_t *at, uint64_t v)
{
    char d[24];
    int n = 0;
    do {
        d[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n > 0 && *at + 1 < cap) p[(*at)++] = d[--n];
    p[*at] = 0;
}

/* A log line: "<what> scope=<4 bytes> check=<4 bytes> <k>=<v> [<k2>=<v2>]". */
static gz_status_t sg_line(gz_node_t *c, gz_action_list_t *out, const char *what, const uint8_t *scope,
                           const uint8_t *check, const char *k, uint64_t v, const char *k2, uint64_t v2)
{
    char t[160];
    size_t at = 0;
    t[0] = 0;
    put_txt(t, sizeof t, &at, what);
    put_txt(t, sizeof t, &at, " scope=");
    put_hex4(t, sizeof t, &at, scope);
    if (check) {
        put_txt(t, sizeof t, &at, " check=");
        put_hex4(t, sizeof t, &at, check);
    }
    if (k) {
        put_txt(t, sizeof t, &at, k);
        put_num(t, sizeof t, &at, v);
    }
    if (k2) {
        put_txt(t, sizeof t, &at, k2);
        put_num(t, sizeof t, &at, v2);
    }
    return np_log(c, out, t);
}

/* The slot whose lobby has this scope, Open, or -1. */
static int sg_slot(const gz_node_t *c, const uint8_t scope[32])
{
    int i = gz_route_slot_by_scope(c, scope);
    return i >= 0 && c->slots[i].kind == SLOT_KIND_LOBBY && c->slots[i].state == SLOT_OPEN ? i : -1;
}

/* ---- keyed scopes (ended lobbies whose rounds may still need their keys) -- */

void gz_sg_keyed_add(gz_node_t *c, const slot_t *s)
{
    np_keyed_t *k = NULL;
    for (int i = 0; i < NP_MAX_ENDED; i++) {
        np_keyed_t *e = &c->np.keyed[i];
        if (e->used && sg_same(e->scope, s->scope, 32)) { k = e; break; }
        if (!e->used) { if (!k || k->used) k = e; continue; }
        if (!k || (k->used && e->seq < k->seq)) k = e;
    }
    memset(k, 0, sizeof *k);
    k->used = 1;
    k->seq = ++c->np.keyed_seq;
    k->host = s->host;
    memcpy(k->scope, s->scope, 32);
    k->epoch = s->key_epoch;
    k->index = s->key_index;
}

/* The scope's keys: (host, epoch, index), and its slot if Open (-1 if not). 0 if the node knows none. */
static int sg_scope_keys(const gz_node_t *c, const uint8_t scope[32], int *host, uint32_t *epoch, uint32_t *index, int *slot)
{
    int i = sg_slot(c, scope);
    *slot = i;
    if (i >= 0) {
        *host = c->slots[i].host; *epoch = c->slots[i].key_epoch; *index = c->slots[i].key_index;
        return 1;
    }
    for (int k = 0; k < NP_MAX_ENDED; k++) {
        const np_keyed_t *e = &c->np.keyed[k];
        if (!e->used || !sg_same(e->scope, scope, 32)) continue;
        *host = e->host; *epoch = e->epoch; *index = e->index;
        return 1;
    }
    return 0;
}

/* ---- the engine's hooks ------------------------------------------------------- */

int gz_sg_keys(void *ctx, const uint8_t scope[32], const uint8_t *terms_digest, secp256k1_keypair *f,
               secp256k1_keypair *kc)
{
    gz_node_t *c = ctx;
    const secp256k1_context *secp = c->cfg.secp;
    uint8_t sec[32];
    uint32_t epoch, index;
    int host, slot, ok = 1;
    if (!sg_scope_keys(c, scope, &host, &epoch, &index, &slot)) return 0;
    if (host != (c->cfg.host != 0)) return 0;
    if (kc) {
        /* the host's long-term key, or the member's contribution key of the lobby */
        int got = host ? (c->cfg.keys.host_secret && c->cfg.keys.host_secret(c->cfg.keys.ctx, sec) == 1)
                       : (c->cfg.keys.secret && c->cfg.keys.secret(c->cfg.keys.ctx, epoch, index, sec) == 1);
        ok = got && secp256k1_keypair_create(secp, kc, sec);
        sg_wipe(sec, sizeof sec);
    }
    if (ok && f) {
        if (!host && c->cfg.member_signing == GZ_MEMBER_SIGNING_AT_JOIN) {
            /* AT_JOIN: only the scoped secret the person's ready made, and only for its digest. */
            const slot_t *s = slot >= 0 ? &c->slots[slot] : NULL;
            ok = s && s->gate_have && terms_digest && sg_same(terms_digest, s->gate_digest, 32) &&     /* RULE-NODE:AT_JOIN_SCOPED */
                 secp256k1_keypair_create(secp, f, s->gate_secret);
        } else {
            ok = c->cfg.keys.secret && c->cfg.keys.secret(c->cfg.keys.ctx, epoch, index + 1, sec) == 1 &&
                 secp256k1_keypair_create(secp, f, sec);
            sg_wipe(sec, sizeof sec);
        }
    }
    return ok;
}

static int sg_guard(void *ctx, gz_record_t *rec)
{
    gz_node_t *c = ctx;
    rec->type = GZ_RECORD_GUARD;
    rec->bytes.data = c->sg_guard;
    rec->bytes.len = np_guard_for_round(c, c->sg_guard);
    return rec->bytes.len != 0;
}

/* Slice 1's conditions for the exit-time checks (safety-rule.md 12). */
static void sg_exit_conditions(gz_tree_conditions_t *cond)
{
    memset(cond, 0, sizeof *cond);
    cond->exit = gz_exit_signet();
    cond->funding_deadline_blocks = 36;
    cond->end_window = 6;
}

/* The member's ack-time check (gz_tree_may_ack) at its tip: 1 to ack, 0 not to, -1 not yet. The leaf's
 * depth is the round's own: from its lobby's terms and the member's place in the round, never something a
 * builder left in the slot, which a start does not restore and a second attempt overwrites (review B of
 * PR 52, M1). No tip yet (after a start, before the chain reports): not yet, so that the host's next
 * round_complete is judged (L4). */
int gz_sg_may_ack(void *ctx, const gz_sign_round_t *r, uint32_t *ack_tip)
{
    gz_node_t *c = ctx;
    gz_tree_conditions_t cond;
    gz_tree_params_t prm;
    int i = sg_slot(c, r->def.outer_digest);
    sg_exit_conditions(&cond);
    *ack_tip = c->tip;
    if (i < 0) return 0;                    /* no lobby: no ack (Abandoned at its deadline) */
    if (!c->tip) return -1;                 /* RULE-NODE:ACK_WAITS_FOR_TIP */
    const slot_t *s = &c->slots[i];
    if (s->host || !s->lobby.m.have_terms || r->me < 1 || r->me >= r->def.n_participants ||
        gz_tree_params(&s->lobby.m.terms, (uint32_t)r->def.n_participants - 1, &prm) != GZ_TREE_P_OK)
        return 0;
    return gz_tree_may_ack(r->def.end_height, prm.depth[r->me - 1], c->tip, &cond);   /* RULE-NODE:ACK_OWN_DEPTH */
}

/* A member's leaf depth in round r, worked out as gz_sg_may_ack does: the round's own, from its lobby's
 * terms and the member's place, never a slot's leftover (review B of PR 52, M1). 1 with *depth set, or 0
 * when it cannot be had. For the funding engine's member side (P4.6, F12). */
int gz_sg_own_depth(const gz_node_t *c, const gz_sign_round_t *r, uint8_t *depth)
{
    gz_tree_params_t prm;
    int i = r ? sg_slot(c, r->def.outer_digest) : -1;
    if (i < 0) return 0;
    const slot_t *s = &c->slots[i];
    if (s->host || !s->lobby.m.have_terms || r->me < 1 || r->me >= r->def.n_participants ||
        gz_tree_params(&s->lobby.m.terms, (uint32_t)r->def.n_participants - 1, &prm) != GZ_TREE_P_OK)
        return 0;
    *depth = prm.depth[r->me - 1];
    return 1;
}

/* Give an outcome to slot i's lobby, inside the current call. */
static gz_status_t sg_deliver(gz_node_t *c, int i, int kind, const uint8_t *check, const uint8_t *blamed, size_t n_blamed,
                              gz_action_list_t *out)
{
    slot_t *s = &c->slots[i];
    gz_status_t st;
    if (s->host) {
        int o = kind == GZ_SIGN_OUTCOME_FUNDING ? GZ_LOBBY_ROUND_FUNDING
              : kind == GZ_SIGN_OUTCOME_FAILED  ? GZ_LOBBY_ROUND_FAILED : GZ_LOBBY_ROUND_RETRY;
        st = gz_lobby_host_round_result(&s->lobby.h, o, o == GZ_LOBBY_ROUND_RETRY ? blamed : NULL,
                                        o == GZ_LOBBY_ROUND_RETRY ? n_blamed : 0, out);
    } else {
        if (kind == GZ_SIGN_OUTCOME_FAILED) return GZ_OK;   /* a member waits for the host's cancel */
        st = gz_lobby_member_round_result(&s->lobby.m, kind == GZ_SIGN_OUTCOME_FUNDING ? GZ_LOBBY_ROUND_FUNDING
                                                                                         : GZ_LOBBY_ROUND_RETRY,
                                          check, out);
    }
    if (st != GZ_OK) return st;
    return sg_line(c, out, "sign-outcome", s->scope, check, " outcome=", (uint64_t)kind, " blamed=", n_blamed);
}

static int sg_queue(gz_node_t *c, const gz_sign_outcome_t *o)
{
    sg_queued_t *q;
    if (c->n_sq == SG_MAX_QUEUED) return 0;
    q = &c->sq[c->n_sq++];
    memset(q, 0, sizeof *q);
    q->kind = (int)o->kind;
    memcpy(q->scope, o->scope, 32);
    memcpy(q->check, o->check_id, 32);
    q->attempt = o->attempt;
    for (size_t k = 0; k < o->n_blamed && k < GZ_SIGN_MAX_PARTICIPANTS; k++) memcpy(q->blamed + 33 * k, o->blamed[k], 33);
    q->n_blamed = o->n_blamed < GZ_SIGN_MAX_PARTICIPANTS ? o->n_blamed : GZ_SIGN_MAX_PARTICIPANTS;
    return 1;
}

static gz_status_t sg_outcome(void *ctx, const gz_sign_outcome_t *o, gz_action_list_t *out)
{
    gz_node_t *c = ctx;
    int i = sg_slot(c, o->scope), eng;
    size_t start = out->count, used = out->used;
    gz_status_t st;
    if (i < 0) { c->sg_lost++; return GZ_OK; }   /* the lobby has ended: nothing to tell it */
    eng = ENG_SLOT0 + i;
    if (c->busy[eng] || c->sg_defer) return sg_queue(c, o) ? GZ_OK : gz_c_bug(c, ENG_SIGN);
    for (size_t k = 0; k < o->n_blamed && k < GZ_SIGN_MAX_PARTICIPANTS; k++) memcpy(c->sg_blamed + 33 * k, o->blamed[k], 33);
    int kind = (int)o->kind;
    /* H1 before the lobby saves Funding (14.2); a failed H1 gives the lobby Failed. */
    if (c->cfg.host && c->fund_on && kind == GZ_SIGN_OUTCOME_FUNDING) {
        int h1 = gz_fd_h1(c, o);
        if (h1 != 0) {
            kind = GZ_SIGN_OUTCOME_FAILED;
            if ((st = sg_line(c, out, "fund-h1-refused", o->scope, o->check_id, " verdict=", (uint64_t)h1, NULL, 0)) != GZ_OK)
                return st;
        }
    }
    if (c->cfg.host && kind != GZ_SIGN_OUTCOME_FUNDING && o->released) c->fd_released[i] = 1;   /* H11 */
    c->busy[eng] = 1;
    st = sg_deliver(c, i, kind, o->check_id, c->sg_blamed, o->n_blamed, out);
    c->busy[eng] = 0;
    if (st != GZ_OK) {
        if (!c->err_area) c->err_area = gz_c_area(c, eng);
        return st;
    }
    /* What the lobby appended is its own (its seats, its timers, its generation). */
    for (size_t k = start; k < out->count; k++) {
        if (k - c->base >= GZ_NODE_LIST_ACTIONS) return gz_c_bug(c, eng);
        if (c->owner[k - c->base] < 0) c->owner[k - c->base] = (int8_t)eng;
    }
    c->nested_bytes += out->used - used;
    c->sg_touched |= 1u << i;
    /* Funding, after the lobby's save and in the same bracket: the host applies H1's verdict (AUTO signs,
     * saves, broadcasts); a member starts to watch the funding from its ack (P4.6). */
    if (c->fund_on && o->kind == GZ_SIGN_OUTCOME_FUNDING)
        return c->cfg.host ? gz_fd_apply(c, o->scope, out) : gz_fd_member_acked(c, o, out);
    return GZ_OK;
}

/* After a call of the signing engine: each lobby an outcome reached takes its after-step (its gates, its
 * line, its end), as after any step of its own. */
gz_status_t gz_sg_after(gz_node_t *c, gz_action_list_t *out)
{
    gz_status_t st = GZ_OK;
    for (int i = 0; i < GZ_NODE_MAX_SLOTS && st == GZ_OK; i++)
        if (c->sg_touched >> i & 1u) st = gz_ls_after(c, i, out);
    c->sg_touched = 0;
    return st;
}

/* The queued outcomes, each in a bracket of its own. */
static gz_status_t sg_deliver_queued(gz_node_t *c, int eng, gz_action_list_t *out)
{
    const sg_queued_t *q = &c->sq[c->sq_cur];
    return sg_deliver(c, eng - ENG_SLOT0, q->kind, q->check, q->blamed, q->n_blamed, out);
}

gz_status_t gz_sg_drain(gz_node_t *c, gz_action_list_t *out)
{
    gz_status_t st = GZ_OK;
    for (size_t k = 0; k < c->n_sq && st == GZ_OK; k++) {
        int i = sg_slot(c, c->sq[k].scope);
        if (i < 0) { c->sg_lost++; continue; }
        c->sq_cur = k;
        st = gz_c_slot_bracket(c, ENG_SLOT0 + i, sg_deliver_queued, out);
    }
    c->n_sq = 0;
    return st;
}

/* ---- the builder (9.2, 13) ------------------------------------------------------ */

/* The tree a proposal names, from the lobby's terms and the rules (the same
 * inputs gz_tree_member_check rebuilds from). 0 if the rules do not give one. */
static int sg_tree(gz_node_t *c, const gz_terms_outer_t *o, const gz_tree_proposal_t *p, gz_tree_t *t)
{
    gz_tree_params_t prm;
    gz_tree_build_in_t bi;
    uint32_t n;
    if (!sg_crypto(c) || p->n_participants < 2 || p->n_participants > GZ_SIGN_MAX_PARTICIPANTS) return 0;
    n = (uint32_t)p->n_participants - 1;
    if (gz_tree_params(o, n, &prm) != GZ_TREE_P_OK) return 0;
    for (uint32_t i = 0; i < n; i++) memcpy(c->sg_keys[i], p->participants[i + 1].factory_key, 33);
    memset(&bi, 0, sizeof bi);
    bi.levels = prm.levels;
    bi.n_levels = prm.n_levels;
    bi.fixed_levels = p->fixed_levels;
    bi.n_members = n;
    bi.host_key = p->participants[0].factory_key;
    bi.member_keys = (const uint8_t(*)[33])c->sg_keys;
    bi.end_height = p->end_height;
    bi.tree_feerate = p->tree_feerate;
    bi.lstock_csv = p->lstock_delay;
    memcpy(bi.funding_txid, p->funding_txid, 32);
    bi.funding_vout = p->funding_vout;
    bi.funding_amount = p->funding_amount;
    memcpy(bi.funding_script, p->funding_script, 34);
    return gz_tree_build(&bi, sg_crypto(c), t) == GZ_TREE_B_OK;
}

/* The items to sign, one per tree transaction (tree_import.h): index i, tier 0, key path; the merkle
 * root if any; signers participant 0, then participants 1 + first .. first + count; what it spends. */
static int sg_def(const gz_terms_outer_t *o, const uint8_t scope[32], const gz_tree_t *t, gz_sign_def_t *d)
{
    if (t->n_nodes < 1 || t->n_nodes > GZ_SIGN_MAX_ITEMS) return 0;
    memcpy(d->chain, o->chain, 32);
    memcpy(d->host_key, o->host_key, 33);
    memcpy(d->outer_digest, scope, 32);
    d->n_tiers = 1;
    d->n_items = t->n_nodes;
    for (uint16_t i = 0; i < t->n_nodes; i++) {
        const gz_tree_node_t *nd = &t->node[i];
        gz_sign_item_t *it = &d->items[i];
        if (1u + nd->count > GZ_SIGN_MAX_SIGNERS || nd->tx_len > GZ_SIGN_MAX_TX) return 0;
        it->tier = 0;
        it->mode = GZ_SIGN_MODE_KEYPATH;
        it->has_merkle_root = nd->has_merkle ? 1 : 0;
        if (nd->has_merkle) memcpy(it->merkle_root, nd->merkle, 32);
        it->n_signers = (uint8_t)(1u + nd->count);
        it->signers[0] = 0;
        for (uint16_t k = 0; k < nd->count; k++) it->signers[1 + k] = (uint8_t)(1u + nd->first + k);
        it->spent_amount = nd->spent_amount;
        memcpy(it->spent_script, nd->spent_script, 34);
        it->tx_len = nd->tx_len;
        memcpy(it->tx, nd->tx, nd->tx_len);
    }
    return 1;
}

/* A member's conditions for the safe-to-sign checks, from its lobby's limits (terms.md 9). */
static void sg_conditions(const gz_lobby_handoff_t *h, gz_tree_conditions_t *cond)
{
    sg_exit_conditions(cond);
    cond->min_own_channel_sat = h->limits ? h->limits->min_channel_sat : 0;
    cond->max_tree_feerate = h->limits ? h->limits->max_tree_feerate : 0;
    /* Slice 1: the spare-liquidity delay is the import's default on both sides. */
    cond->min_lstock_delay = cond->max_lstock_delay = GZ_TREE_LSTOCK_DEFAULT;
    cond->min_members = h->min_members;
    cond->max_members = GZ_TREE_MAX_MEMBERS;
}

/* The program's imported builder, called through its own type. */
static int sg_import(void *ctx, const gz_tree_build_in_t *in, gz_tree_import_t *out)
{
    gz_node_t *c = ctx;
    return c->cfg.tree_import(c->cfg.tree_import_ctx, in, out);
}

static uint16_t sg_build(void *ctx, const gz_sign_build_in_t *in, gz_sign_def_t *out)
{
    gz_node_t *c = ctx;
    const gz_tree_proposal_t *p = &in->msg->p;
    const uint8_t *scope = in->scope ? in->scope : c->sg_begin_scope;
    int i = sg_slot(c, scope);
    if (i < 0) return in->replay || c->cfg.host ? 1 : GZ_SIGN_BUILD_IGNORE;   /* no lobby for it: a member ignores it */
    slot_t *s = &c->slots[i];
    if (s->host != (c->cfg.host != 0)) return 1;
    if (s->host || in->replay) {
        const gz_terms_outer_t *o = s->host ? &s->lobby.h.terms : &s->lobby.m.terms;
        if (!s->host && !s->lobby.m.have_terms) return 1;
        if (!sg_tree(c, o, p, c->sg_tree) || !sg_def(o, scope, c->sg_tree, out)) return 1;
        return 0;
    }
    /* A member: only what its lobby accepted (13), then the safe-to-sign checks. */
    gz_lobby_handoff_t h;
    gz_tree_member_in_t mi;
    gz_tree_conditions_t cond;
    gz_tree_verdict_t v;
    if (!gz_lobby_member_accepted(&s->lobby.m, in->msg->check_id, in->msg->attempt, &h)) return GZ_SIGN_BUILD_IGNORE;   /* RULE-NODE:ACCEPTED_ONLY */
    if (!sg_crypto(c) || !c->cfg.tree_import) return 9;
    sg_conditions(&h, &cond);
    memset(&mi, 0, sizeof mi);
    mi.outer = h.terms;
    mi.outer_digest = h.scope;
    mi.frozen = h.values;
    mi.frozen_digest = h.current_digest;
    mi.outer_rec = h.outer; mi.outer_rec_len = h.outer_len; mi.outer_sig = h.outer_sig;
    mi.frozen_rec = h.current; mi.frozen_rec_len = h.current_len; mi.frozen_sig = h.current_sig;
    mi.host_pinned_key = h.pinned_key;
    mi.policy = gz_lobby_policy();
    mi.ready_outer_digest = h.scope;
    mi.ready_version = h.version;
    mi.ready_current_digest = h.current_digest;
    mi.own_factory_key = in->own_factory_key;
    mi.own_contribution_key = in->own_contribution_key;
    mi.cond = &cond;
    mi.tip = c->tip;
    mi.exposures = in->exposures; mi.n_exposures = in->n_exposures;
    mi.unresolved = in->unresolved; mi.n_unresolved = in->n_unresolved;
    mi.import_build = sg_import;
    mi.import_ctx = c;
    mi.import_out = c->sg_imp;
    mi.crypto = sg_crypto(c);
    gz_tree_member_check(&mi, p, c->sg_tree, &v);
    if (v.check != GZ_CHK_OK) {
        /* Refused: the engine answers round_abort with the reason. The person is told which rule. */
        c->sg_refused++;
        c->sg_refused_check = (uint32_t)v.check;
        if (c->sg_out && c->sg_line_st == GZ_OK)
            c->sg_line_st = sg_line(c, c->sg_out, "sign-refused", scope, in->msg->check_id, " rule=", (uint64_t)v.check,
                                    " reason=", v.reason ? v.reason : 1);
        return v.reason ? v.reason : 1;
    }
    return sg_def(h.terms, scope, c->sg_tree, out) ? 0 : 1;
}

/* ---- the lobby's side of the hand-off (lobby_handoff.h) ------------------------- */

/* A call into the signing engine from inside a lobby's step: never while the engine's own call runs
 * (U1); what it appends is its own; an outcome it reports waits for the lobby to return. */
static gz_status_t sg_enter(gz_node_t *c, int what, const void *arg, const uint8_t *scope, const uint8_t *key,
                            gz_action_list_t *out)
{
    size_t start = out->count, used = out->used;
    gz_status_t st;
    if (c->busy[ENG_SIGN]) return gz_c_bug(c, ENG_SIGN);
    c->busy[ENG_SIGN] = 1;
    c->sg_defer = 1;
    c->sg_out = out; c->sg_line_st = GZ_OK;
    switch (what) {
    case 0: st = gz_sign_begin(c->sign, (const gz_sign_begin_t *)arg, out); break;
    case 1: st = gz_sign_cancel(c->sign, scope, out); break;
    default: st = gz_sign_member_left(c->sign, scope, key, out); break;
    }
    if (st == GZ_OK) st = c->sg_line_st;
    c->sg_out = NULL;
    c->sg_defer = 0;
    c->busy[ENG_SIGN] = 0;
    if (st != GZ_OK) {
        if (!c->err_area) c->err_area = gz_c_area(c, ENG_SIGN);
        return st;
    }
    for (size_t k = start; k < out->count; k++) {
        if (k - c->base >= GZ_NODE_LIST_ACTIONS) return gz_c_bug(c, ENG_SIGN);
        if (c->owner[k - c->base] < 0) c->owner[k - c->base] = (int8_t)ENG_SIGN;
    }
    c->nested_bytes += out->used - used;
    return GZ_OK;
}

#ifdef GZ_TEST_KINDS
/* The test funding plan (a host node without a wallet port, in tests only): one made-up input named by the scope, check and attempt, and one
 * output of `amount` to `script`. Returns its length. */
static size_t sg_test_funding(const uint8_t scope[32], const uint8_t check[32], uint32_t attempt, uint64_t amount,
                              const uint8_t script[34], uint8_t *out)
{
    gz_sign_sha256_t s;
    uint8_t prev[32], a[4];
    size_t n = 0;
    gz_put_u32(a, attempt);
    gz_sign_tagged_init(&s, "gazpacho/test-funding");
    gz_sign_sha256_write(&s, scope, 32);
    gz_sign_sha256_write(&s, check, 32);
    gz_sign_sha256_write(&s, a, 4);
    gz_sign_sha256_done(&s, prev);
    out[n++] = 2; out[n++] = 0; out[n++] = 0; out[n++] = 0;   /* version */
    out[n++] = 1;                                               /* one input */
    memcpy(out + n, prev, 32); n += 32;
    memset(out + n, 0, 4); n += 4;                              /* its vout */
    out[n++] = 0;                                               /* no script */
    memset(out + n, 0xff, 4); n += 4;                           /* sequence */
    out[n++] = 1;                                               /* one output */
    for (int b = 0; b < 8; b++) out[n++] = (uint8_t)(amount >> (8 * b));
    out[n++] = 34; memcpy(out + n, script, 34); n += 34;
    memset(out + n, 0, 4); n += 4;                              /* lock time */
    return n;
}
#endif

/* The host's largest step for a tree (internal.h, SG_MAX_STEP_BYTES): the nonce sets of a tier to every
 * member at once, each member's message holding, for each of its items, every signer's nonce and its
 * signature (130 bytes a signer), with the message's own overhead; the saves of the step are well below
 * the margin left. A round whose step could pass the bound is not begun. */
_Static_assert(sizeof ((gz_node_t *)0)->sg_ftx == GZ_SIGN_MAX_FUNDING_TX, "the node holds any funding the engine takes");

int gz_sg_set_funding(gz_node_t *c, gz_tree_proposal_t *p, const uint8_t *tx, size_t len, const uint8_t txid[32],
                      uint32_t vout)
{
    if (!tx || len == 0 || len > sizeof c->sg_ftx) return 0;
    memcpy(c->sg_ftx, tx, len);
    p->funding_tx = c->sg_ftx;
    p->funding_tx_len = len;
    memcpy(p->funding_txid, txid, 32);
    p->funding_vout = vout;
    return 1;
}

static size_t sg_step_bytes(const gz_tree_t *t, uint32_t n_members)
{
    size_t total = 0;
    for (uint32_t j = 0; j < n_members; j++) {
        size_t m = 256;
        for (uint16_t i = 0; i < t->n_nodes; i++)
            if (j >= t->node[i].first && j < (uint32_t)t->node[i].first + t->node[i].count)
                m += 6u + (1u + t->node[i].count) * 130u;
        total += m + 64u;
    }
    return total;
}

/* A begin the host cannot propose: the outcome Failed, after the lobby's call (8.1). */
static gz_status_t sg_refuse_begin(gz_node_t *c, const gz_lobby_handoff_t *h, const char *why, gz_action_list_t *out)
{
    gz_sign_outcome_t o;
    memset(&o, 0, sizeof o);
    o.kind = GZ_SIGN_OUTCOME_FAILED; o.scope = h->scope; o.check_id = h->check_id; o.attempt = (uint16_t)h->attempt;
    if (!sg_queue(c, &o)) return gz_c_bug(c, ENG_SIGN);
    return sg_line(c, out, why, h->scope, h->check_id, NULL, 0, NULL, 0);
}

static gz_status_t sg_begin(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out)
{
    slot_t *s = ctx;
    gz_node_t *c = s->node;
    const gz_terms_outer_t *o = h->terms;
    gz_tree_proposal_t *p = &c->sg_prop;
    gz_tree_params_t prm;
    gz_sign_begin_t b;
    uint8_t internal[32], outk[32];
    size_t n;
    /* A member's round begins with the host's proposal; its hand-off is the accepted record (9.2). */
    if (!c->cfg.host || !s->host || h->role != 1) return GZ_OK;
    if (!h->participants || h->n_participants < 2 || h->n_participants > GZ_SIGN_MAX_PARTICIPANTS || !o)
        return sg_refuse_begin(c, h, "sign-begin-refused-participants", out);
    n = (size_t)h->n_participants - 1;
    if (gz_tree_params(o, (uint32_t)n, &prm) != GZ_TREE_P_OK) return sg_refuse_begin(c, h, "sign-begin-refused-terms", out);
    if (!c->tip) return sg_refuse_begin(c, h, "sign-begin-refused-no-tip", out);
    for (size_t k = 0; k < h->n_participants; k++) {
        gz_tree_participant_t *q = &c->sg_parts[k];
        memcpy(q->factory_key, h->participants[k].factory_key, 33);
        memcpy(q->contribution_key, h->participants[k].contribution_key, 33);
        memcpy(q->bind_by_factory, h->participants[k].bind_by_factory, 64);
        memcpy(q->bind_by_contribution, h->participants[k].bind_by_contribution, 64);
        if (k) memcpy(c->sg_keys[k - 1], h->participants[k].factory_key, 33);
    }
    memset(p, 0, sizeof *p);
    p->funding_script[0] = 0x51; p->funding_script[1] = 0x20;
    if (!sg_crypto(c) || !sg_crypto(c)->agg_tweak(sg_crypto(c)->ctx, c->sg_parts[0].factory_key, (const uint8_t(*)[33])c->sg_keys, n,
                                                 NULL, internal, outk))
        return sg_refuse_begin(c, h, "sign-begin-refused-keys", out);
    memcpy(p->funding_script + 2, outk, 32);
    p->purpose = 1;
    p->terms_version = h->version;
    memcpy(p->terms_digest, h->current_digest, 32);
    p->funding_amount = prm.funding_amount;
    p->funding_script_len = 34;
    if (c->fund_on) {
        /* The attempt's plan, first in the bracket (9.2 step 1): H11's `released` from the last
         * attempt's outcome. */
        gz_fund_plan_in_t pi;
        gz_fund_plan_out_t po;
        gz_status_t fst;
        int si = sg_slot(c, h->scope);
        memset(&pi, 0, sizeof pi);
        memcpy(pi.scope, h->scope, 32);
        memcpy(pi.check, h->check_id, 32);
        pi.attempt = (uint16_t)h->attempt;
        pi.amount = prm.funding_amount;
        memcpy(pi.script, p->funding_script, 34);
        pi.released = si >= 0 && c->fd_released[si];
        if ((fst = gz_fd_plan(c, &pi, out, &po)) != GZ_OK) return fst;
        if (!po.ok || !gz_sg_set_funding(c, p, po.tx, po.tx_len, po.funding.txid, po.funding.vout))
            return sg_refuse_begin(c, h, "sign-begin-refused-funding", out);
        if (si >= 0) c->fd_released[si] = 0;
    } else {
#ifdef GZ_TEST_KINDS
        /* A test-build host with no wallet port: the stand-in plan. */
        uint8_t ftx[128], txid[32];
        size_t flen = sg_test_funding(h->scope, h->check_id, h->attempt, prm.funding_amount, p->funding_script, ftx);
        gz_tx_txid(ftx, flen, txid);
        if (!gz_sg_set_funding(c, p, ftx, flen, txid, 0)) return sg_refuse_begin(c, h, "sign-begin-refused-funding", out);
#else
        return sg_refuse_begin(c, h, "sign-begin-refused-no-wallet", out);
#endif
    }
    p->participants = c->sg_parts;
    p->n_participants = h->n_participants;
    p->n_tiers = 1;
    p->end_height = c->tip + o->lifetime_blocks + o->winddown_blocks;
    p->tree_anchors = 1;
    p->tree_feerate = prm.tree_feerate;
    p->lstock_delay = GZ_TREE_LSTOCK_DEFAULT;
    p->fixed_levels = prm.D;
    p->k = 1;
    p->layer_step = GZ_TREE_SLICE1_STEP;
    p->layer_states = GZ_TREE_SLICE1_STATES;
    /* Each step deadline the terms' step timeout (C8 bounds both by it on the member). */
    p->nonces_due_ms = o->step_timeout_ms;
    p->sigs_due_ms = o->step_timeout_ms;
    if (!sg_tree(c, o, p, c->sg_tree)) return sg_refuse_begin(c, h, "sign-begin-refused-tree", out);
    p->tier_sizes[0] = c->sg_tree->n_nodes;
    if (sg_step_bytes(c->sg_tree, (uint32_t)n) > SG_MAX_STEP_BYTES - 128u * 1024u)
        return sg_refuse_begin(c, h, "sign-begin-refused-size", out);
    memset(&b, 0, sizeof b);
    b.p = p;
    b.scope = h->scope;
    b.check_id = h->check_id;
    b.has_attempt = 1;
    b.attempt = (uint16_t)h->attempt;
    b.budget_end_ms = h->budget_end_ms;
    memcpy(c->sg_begin_scope, h->scope, 32);
    gz_status_t st = sg_line(c, out, "sign-begin", h->scope, h->check_id, " members=", n, " resume=", (uint64_t)h->resume);
    if (st != GZ_OK) return st;
    return sg_enter(c, 0, &b, NULL, NULL, out);
}

static gz_status_t sg_cancel(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out)
{
    slot_t *s = ctx;
    (void)reason;
    return sg_enter(s->node, 1, NULL, scope, NULL, out);
}

static gz_status_t sg_left(void *ctx, const uint8_t scope[32], const uint8_t ckey[33], gz_action_list_t *out)
{
    slot_t *s = ctx;
    return sg_enter(s->node, 2, NULL, scope, ckey, out);
}

void gz_sg_signing(slot_t *s, gz_lobby_signing_t *sg)
{
    memset(sg, 0, sizeof *sg);
    sg->begin = sg_begin;
    sg->cancel = sg_cancel;
    sg->member_left = sg_left;
    sg->ctx = s;
}

/* ---- the engine interface ---------------------------------------------------------- */

static gz_status_t sg_ops_load(void *e, const gz_record_t *rec, gz_batch_id_t at)
{
    return gz_sign_load(((gz_node_t *)e)->sign, rec, at);
}

/* Each call of the engine with the list its builder's notices go to. */
static gz_status_t sg_ops_resume(void *e, gz_action_list_t *out, int *more)
{
    gz_node_t *c = e;
    c->sg_out = out; c->sg_line_st = GZ_OK;
    gz_status_t st = gz_sign_resume(c->sign, out, more);
    c->sg_out = NULL;
    return st == GZ_OK ? c->sg_line_st : st;
}

static gz_status_t sg_ops_handle(void *e, const gz_event_t *ev, gz_action_list_t *out)
{
    gz_node_t *c = e;
    c->sg_out = out; c->sg_line_st = GZ_OK;
    gz_status_t st = gz_sign_handle(c->sign, ev, out);
    c->sg_out = NULL;
    return st == GZ_OK ? c->sg_line_st : st;
}

static const gz_engine_ops_t SG_OPS = {
    GZ_AREA_ROUND, sg_ops_load, sg_ops_resume, sg_ops_handle, SG_MAX_STEP_ACTIONS, SG_MAX_STEP_BYTES, 1,
};

const gz_engine_ops_t *gz_sg_ops(void)
{
    return &SG_OPS;
}

/* At a start, after the engine's resume: no Closing survives a start, so a kept host round is kept
 * only while its scope's lobby is Open (review A of PR 52, L3). */
static int sg_scope_open(void *ctx, const uint8_t scope[32])
{
    return sg_slot((const gz_node_t *)ctx, scope) >= 0;
}

void gz_sg_started(gz_node_t *c)
{
    if (c->sign_on) gz_sign_forget_kept_unless(c->sign, sg_scope_open, c);
}

/* The engine, at the node's init: only with a secp256k1 context (node.h). */
gz_status_t gz_sg_init(gz_node_t *c)
{
    gz_sign_config_t sc;
    uint64_t tick = c->cfg.sign_tick_ms ? c->cfg.sign_tick_ms : SG_TICK_MS;
    c->sign_on = 0;
    c->sign = NULL; c->sg_tree = NULL; c->sg_imp = NULL;
    if (!c->cfg.secp || !c->cfg.sign_mem || c->cfg.sign_mem_size < sizeof(sg_mem_t)) return GZ_OK;
    c->sign = &((sg_mem_t *)c->cfg.sign_mem)->sign;
    c->sg_tree = &((sg_mem_t *)c->cfg.sign_mem)->tree;
    c->sg_imp = &((sg_mem_t *)c->cfg.sign_mem)->imp;
    memset(&sc, 0, sizeof sc);
    sc.host = c->cfg.host;
    sc.ctx = c->cfg.secp;
    sc.build = sg_build;
    sc.retry = NULL;   /* every new attempt is the lobby's decision (9.2) */
    sc.build_ctx = c;
    sc.tick_ms = tick;
    sc.resend_ticks = (uint32_t)(SG_RESEND_MS / tick ? SG_RESEND_MS / tick : 1);
    sc.deadline_ticks = (uint32_t)(SG_STEP_MS / tick ? SG_STEP_MS / tick : 1);
    sc.status_ticks = sc.resend_ticks;
    sc.unfinished_ticks = (uint32_t)(SG_UNFINISHED_MS / tick ? SG_UNFINISHED_MS / tick : 1);
    {
        gz_tree_conditions_t fc;
        sg_exit_conditions(&fc);
        sc.funding_deadline_blocks = fc.funding_deadline_blocks;   /* C11, the deadline may_ack judged the ack at */
    }
    sc.keys = gz_sg_keys;
    sc.may_ack = gz_sg_may_ack;
    sc.guard = sg_guard;
    sc.outcome = sg_outcome;
    sc.hook_ctx = c;
    if (gz_sign_init(c->sign, &sc, &c->ports, c->incarnation) != GZ_OK) return GZ_ERR_ARGUMENT;
    c->sign_on = 1;
    return GZ_OK;
}
