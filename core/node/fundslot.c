/* The funding engine in the composite (docs/notes/composite-node.md 9 and 14;
 * docs/notes/funding.md 7): core/funding's engine behind the composite's
 * engine interface (area 0x0003, node-wide, both roles), and its hand-offs.
 * Written on integration-slice1 (P4.6), for #56 to fold in.
 *
 *   HOST, the attempt (9.2 step 1). The signing slot's begin asks for the
 *   attempt's plan first (gz_fd_plan); the proposal carries the plan's
 *   unsigned bytes and outpoint. `released` is the previous attempt's, from
 *   its signing outcome (H11).
 *
 *   HOST, the Funding outcome (14.2). Before the lobby saves Funding, H1
 *   (gz_fd_h1); a failed H1 gives the lobby Failed instead. After the lobby's
 *   save, gz_fund_host_apply in the same bracket: AUTO signs, saves and
 *   broadcasts; CONFIRM waits for the person.
 *
 *   MEMBER, the Complete outcome: gz_fund_member_acked, with what the round
 *   holds (the funding transaction from the proposal's record 18).
 *
 *   THE REPORT HOOK: Live gives the lobby Active (both roles) and, on a
 *   member, gz_sign_resolve live; Dead and abandoned resolve the member's
 *   round; the lobby has no Failed with cancel reason 4 yet (integration.md
 *   W13), so the lobby is told nothing for them.
 *
 * Every call into another engine from here is nested as in signslot.c: the
 * callee's actions are its own, and no engine is entered from its own hook. */
#include "internal.h"
#include <string.h>

static gz_status_t fd_line(gz_node_t *c, gz_action_list_t *out, const char *what, const uint8_t *scope,
                           const char *k1, uint64_t v1)
{
    char line[160];
    size_t at = 0;
    static const char H[] = "0123456789abcdef";
    (void)c;
    for (const char *p = what; *p && at < 60; p++) line[at++] = *p;
    if (scope) {
        const char *s = " scope=";
        for (const char *p = s; *p; p++) line[at++] = *p;
        for (int i = 0; i < 4; i++) { line[at++] = H[scope[i] >> 4]; line[at++] = H[scope[i] & 15]; }
    }
    if (k1) {
        char num[24];
        int n = 0;
        for (const char *p = k1; *p && at < 120; p++) line[at++] = *p;
        do num[n++] = (char)('0' + v1 % 10); while ((v1 /= 10) && n < 20);
        while (n) line[at++] = num[--n];
    }
    line[at] = 0;
    return np_log(c, out, line);
}

/* A call into an engine other than the one running: busy, owner of what it appends, nested bytes. */
static gz_status_t fd_nested(gz_node_t *c, int eng, gz_status_t (*fn)(gz_node_t *, void *, gz_action_list_t *), void *arg,
                             gz_action_list_t *out)
{
    size_t start = out->count, used = out->used;
    gz_status_t st;
    if (c->busy[eng]) return gz_c_bug(c, eng);
    c->busy[eng] = 1;
    st = fn(c, arg, out);
    c->busy[eng] = 0;
    if (st != GZ_OK) {
        if (!c->err_area) c->err_area = gz_c_area(c, eng);
        return st;
    }
    for (size_t k = start; k < out->count; k++) {
        if (k - c->base >= GZ_NODE_LIST_ACTIONS) return gz_c_bug(c, eng);
        if (c->owner[k - c->base] < 0) c->owner[k - c->base] = (int8_t)eng;
    }
    c->nested_bytes += out->used - used;
    if (eng >= ENG_SLOT0 && eng < ENG_N) c->sg_touched |= 1u << (eng - ENG_SLOT0);
    return GZ_OK;
}

/* ---- the host's plan (9.2 step 1) ----------------------------------------- */

typedef struct {
    const gz_fund_plan_in_t *in;
    gz_fund_plan_out_t *res;
} fd_plan_arg_t;

static gz_status_t fd_plan_call(gz_node_t *c, void *a, gz_action_list_t *out)
{
    fd_plan_arg_t *p = a;
    return gz_fund_host_plan(c->fund, p->in, out, p->res);
}

gz_status_t gz_fd_plan(gz_node_t *c, const gz_fund_plan_in_t *in, gz_action_list_t *out, gz_fund_plan_out_t *res)
{
    fd_plan_arg_t a = {in, res};
    memset(res, 0, sizeof *res);
    if (!c->fund_on) return GZ_OK;   /* res->ok 0: the begin is refused */
    return fd_nested(c, ENG_FUNDING, fd_plan_call, &a, out);
}

/* ---- the round the signing engine holds for an outcome -------------------- */

const gz_sign_round_t *gz_fd_round(const gz_node_t *c, const uint8_t *round_id, const uint8_t scope[32])
{
    if (!c->sign_on) return NULL;
    for (size_t i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) {
        const gz_sign_round_t *r = &c->sign->rounds[i];
        if (r->state == GZ_SIGN_ROUND_FREE) continue;
        if (round_id ? memcmp(r->id, round_id, 32) == 0 : memcmp(r->def.outer_digest, scope, 32) == 0) return r;
    }
    return NULL;
}

/* Record 18 (the funding transaction, without witnesses) of the round's saved proposal. */
static int fd_proposed_tx(gz_node_t *c, const gz_sign_round_t *r, gz_bytes_t *tx)
{
    uint16_t kind = 0;
    const uint8_t *scope = NULL, *recs = NULL;
    size_t n = 0;
    /* The saved round_propose: its envelope, else its records alone. */
    if (gz_rmsg_open(r->proposal, r->proposal_len, &kind, &scope, &recs, &n) != 0 ||
        gz_rmsg_propose_decode(recs, n, &c->fd_prop) != 0) {
        if (gz_rmsg_propose_decode(r->proposal, r->proposal_len, &c->fd_prop) != 0) return 0;
    }
    tx->data = c->fd_prop.p.funding_tx;
    tx->len = c->fd_prop.p.funding_tx_len;
    return tx->data && tx->len > 0;
}

/* ---- the host's Funding outcome (14.2) --------------------------------------- */

/* H1 before the lobby's save: 0 (GZ_H1_OK) or the failing check. */
int gz_fd_h1(gz_node_t *c, const gz_sign_outcome_t *o)
{
    const gz_sign_round_t *r = gz_fd_round(c, o->round_id, o->scope);
    gz_fund_h1_in_t in;
    gz_bytes_t tx;
    uint8_t acked[GZ_SIGN_MAX_PARTICIPANTS], ok[GZ_SIGN_MAX_ITEMS];
    if (!c->fund_on) return GZ_FUND_H1_NO_PLAN;
    if (!r || !fd_proposed_tx(c, r, &tx) || r->def.n_participants < 2) return GZ_FUND_H1_NO_PLAN;
    memset(&in, 0, sizeof in);
    memcpy(in.scope, o->scope, 32);
    in.n_members = (size_t)r->def.n_participants - 1;
    for (size_t j = 0; j < in.n_members; j++) acked[j] = (uint8_t)((r->acked >> (j + 1)) & 1u);
    in.acked = acked;
    in.n_nodes = r->def.n_items;
    for (size_t i = 0; i < in.n_nodes; i++) ok[i] = r->have_final[i] ? 1 : 0;
    in.signed_ok = ok;
    in.proposed_tx = tx.data;
    in.proposed_len = tx.len;
    return gz_fund_host_h1(c->fund, &in);
}

static gz_status_t fd_apply_call(gz_node_t *c, void *a, gz_action_list_t *out)
{
    return gz_fund_host_apply(c->fund, (const uint8_t *)a, out);
}

/* After the lobby's save, in the same bracket. */
gz_status_t gz_fd_apply(gz_node_t *c, const uint8_t scope[32], gz_action_list_t *out)
{
    if (!c->fund_on) return GZ_OK;
    return fd_nested(c, ENG_FUNDING, fd_apply_call, (void *)scope, out);
}

/* ---- the member's Complete outcome --------------------------------------------- */

static gz_status_t fd_acked_call(gz_node_t *c, void *a, gz_action_list_t *out)
{
    return gz_fund_member_acked(c->fund, (const gz_fund_acked_in_t *)a, out);
}

gz_status_t gz_fd_member_acked(gz_node_t *c, const gz_sign_outcome_t *o, gz_action_list_t *out)
{
    const gz_sign_round_t *r = gz_fd_round(c, o->round_id, o->scope);
    gz_fund_acked_in_t in;
    gz_bytes_t tx;
    uint16_t have = 0;
    if (!c->fund_on) return GZ_OK;
    if (!r || !fd_proposed_tx(c, r, &tx)) return fd_line(c, out, "fund-acked-no-round", o->scope, NULL, 0);
    uint8_t depth = 0;
    if (!gz_sg_own_depth(c, r, &depth))      /* the round's own depth (review B of PR 52, M1): fail closed */
        return fd_line(c, out, "fund-acked-no-depth", o->scope, NULL, 0);
    memset(&in, 0, sizeof in);
    memcpy(in.scope, o->scope, 32);
    in.funding_tx = tx.data;
    in.funding_tx_len = tx.len;
    memcpy(in.funding.txid, r->def.funding_txid, 32);
    in.funding.vout = r->def.funding_vout;
    in.amount = r->def.funding_amount;
    memcpy(in.script, r->def.funding_script, 34);
    in.ack_tip = r->ack_tip;
    in.end_height = r->def.end_height;
    in.own_depth = depth;
    for (uint16_t i = 0; i < r->def.n_items; i++) have += r->have_final[i] ? 1 : 0;
    in.whole_tree = have == r->def.n_items;
    in.exit = gz_exit_signet();
    in.deadline_blocks = 36;   /* Slice 1 (terms.md; safety-rule.md 12) */
    return fd_nested(c, ENG_FUNDING, fd_acked_call, &in, out);
}

/* ---- the report hook ------------------------------------------------------------- */

typedef struct {
    int slot;
    const uint8_t *round_id;
    uint8_t end;
    int lobby;   /* give the lobby Active */
} fd_report_arg_t;

static gz_status_t fd_resolve_call(gz_node_t *c, void *a, gz_action_list_t *out)
{
    fd_report_arg_t *p = a;
    return gz_sign_resolve(c->sign, p->round_id, p->end, out);
}

static gz_status_t fd_lobby_call(gz_node_t *c, void *a, gz_action_list_t *out)
{
    fd_report_arg_t *p = a;
    slot_t *s = &c->slots[p->slot];
    if (s->host) return gz_lobby_host_round_result(&s->lobby.h, GZ_LOBBY_ROUND_ACTIVE, NULL, 0, out);
    return gz_lobby_member_round_result(&s->lobby.m, GZ_LOBBY_ROUND_ACTIVE, NULL, out);
}

static gz_status_t fd_report(void *ctx, const gz_fund_report_t *rep, gz_action_list_t *out)
{
    gz_node_t *c = ctx;
    fd_report_arg_t a;
    gz_status_t st;
    const gz_sign_round_t *r = c->cfg.host ? NULL : gz_fd_round(c, NULL, rep->scope);
    memset(&a, 0, sizeof a);
    a.slot = -1;
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++)
        if (c->slots[i].state == SLOT_OPEN && c->slots[i].kind == SLOT_KIND_LOBBY &&
            memcmp(c->slots[i].scope, rep->scope, 32) == 0)
            a.slot = i;
    st = fd_line(c, out, "fund-report", rep->scope, " kind=", (uint64_t)rep->kind);
    if (st != GZ_OK) return st;
    /* The member's round: resolved by its own chain view (C11, C4(d)). */
    if (r && c->sign_on && (rep->kind == GZ_FUND_R_LIVE || rep->kind == GZ_FUND_R_DEAD ||
                            rep->kind == GZ_FUND_R_ABANDONED || rep->kind == GZ_FUND_R_FUNDED_LATE)) {
        a.round_id = r->id;
        a.end = rep->kind == GZ_FUND_R_DEAD ? GZ_SIGN_END_DEAD
              : rep->kind == GZ_FUND_R_ABANDONED ? GZ_SIGN_END_ABANDONED : GZ_SIGN_END_LIVE;
        if ((st = fd_nested(c, ENG_SIGN, fd_resolve_call, &a, out)) != GZ_OK) return st;
    }
    if (rep->kind == GZ_FUND_R_LIVE && a.slot >= 0)
        return fd_nested(c, ENG_SLOT0 + a.slot, fd_lobby_call, &a, out);
    return GZ_OK;
}

/* ---- the engine interface ------------------------------------------------------- */

static gz_status_t fd_ops_load(void *e, const gz_record_t *rec, gz_batch_id_t at)
{
    return gz_fund_load(((gz_node_t *)e)->fund, rec, at);
}

static gz_status_t fd_ops_resume(void *e, gz_action_list_t *out, int *more)
{
    return gz_fund_resume(((gz_node_t *)e)->fund, out, more);
}

static gz_status_t fd_ops_handle(void *e, const gz_event_t *ev, gz_action_list_t *out)
{
    return gz_fund_handle(((gz_node_t *)e)->fund, ev, out);
}

static const gz_engine_ops_t FD_OPS = {
    GZ_AREA_FUNDING, fd_ops_load, fd_ops_resume, fd_ops_handle, GZ_FUND_MAX_STEP_ACTIONS, GZ_FUND_MAX_STEP_BYTES,
    GZ_FUND_MAX_TIMERS,
};

const gz_engine_ops_t *gz_fd_ops(void)
{
    return &FD_OPS;
}

/* The engine, at the node's init: with the signing engine only (a node that never signs funds nothing). */
gz_status_t gz_fd_init(gz_node_t *c)
{
    gz_fund_config_t fc;
    c->fund_on = 0;
    /* A host funds only with a wallet port (the program's); without one, a test build keeps the
     * stand-in plan of signslot.c and a release build begins no round. */
    if (!c->sign_on || !c->cfg.sign_mem || (c->cfg.host && !c->cfg.wallet)) return GZ_OK;
    c->fund = &((sg_mem_t *)c->cfg.sign_mem)->fund;
    gz_fund_config_default(&fc, c->cfg.host);
    fc.mode = c->cfg.host_funding;
    if (c->cfg.host && c->cfg.wallet) fc.wallet = *(const gz_wallet_port_t *)c->cfg.wallet;
    if (c->cfg.funding_burial) fc.burial = c->cfg.funding_burial;
    fc.hooks.ctx = c;
    fc.hooks.report = fd_report;
    if (gz_fund_init(c->fund, &fc, &c->ports) != GZ_OK) return GZ_ERR_ARGUMENT;
    c->fund_on = 1;
    return GZ_OK;
}
