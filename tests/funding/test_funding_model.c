/* A property test of the funding engine: random runs of hand-offs, chain
 * facts, broadcast results, commands and restarts, for host and member,
 * checked against invariants and against a restart from the journal.
 *   test_funding_model N [SEED]
 *
 * Invariants, after every step:
 *  I1  no step returns an error;
 *  I2  every step is within the declared worst step, saves before outward;
 *  I3  a funding is broadcast only after H1 passed and (CONFIRM) the person
 *      confirmed; every funding broadcast is the signed plan;
 *  I4  a spend-back is broadcast only at or after its factory's deadline, and
 *      pays at least the minimum it claims;
 *  I5  each factory ends at most once: LIVE, DEAD, ABANDONED and FUNDED_LATE
 *      reports follow the allowed orders (ABANDONED then LIVE, FUNDED_LATE or
 *      DEAD; nothing after LIVE or DEAD);
 *  I6  the held watches never pass the budget, and every release matches a set;
 *  I7  a restart from the journal gives the same scope states and the same
 *      factory states. */
#include "fund_test.h"

static uint64_t s = 0x2545F4914F6CDD1DULL;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }

#define NSCOPE 5

typedef struct {
    int ended, live, dead, abandoned;
    int confirmed_cmd;
} model_t;

static uint8_t scopes[NSCOPE][32];
static uint32_t chain_tip;   /* the chain's height: a restarted engine knows no tip until NEW_TIP */

static void check_reports(ft_t *t, size_t from, model_t *m)
{
    for (size_t i = from; i < t->h.n; i++) {
        const gz_fund_report_t *r = &t->h.r[i];
        int k = -1;
        for (int j = 0; j < NSCOPE; j++)
            if (memcmp(scopes[j], r->scope, 32) == 0) k = j;
        CHECK(k >= 0);
        if (k < 0) continue;
        CHECK(!m[k].live && !m[k].dead);   /* I5: nothing after LIVE or DEAD */
        if (r->kind == GZ_FUND_R_LIVE || r->kind == GZ_FUND_R_FUNDED_LATE) m[k].live = 1;
        if (r->kind == GZ_FUND_R_DEAD) m[k].dead = 1;
        if (r->kind == GZ_FUND_R_ABANDONED) {
            CHECK(!m[k].abandoned);
            m[k].abandoned = 1;
        }
        if (r->kind == GZ_FUND_R_DEAD || r->kind == GZ_FUND_R_ABANDONED) CHECK(r->cancel_reason == 4);
    }
}

/* I3 and I4 on one step's broadcasts. */
static void check_broadcasts(ft_t *t)
{
    for (size_t i = 0; i < t->out.count; i++) {
        const gz_action_t *a = &t->out.slots[i];
        uint8_t strip[GZ_FUND_MAX_SIGNED], txid[32];
        size_t n;
        int known = 0;
        if (a->kind != GZ_ACTION_BROADCAST) continue;
        CHECK(gz_fund_tx_strip(a->u.broadcast.tx.data, a->u.broadcast.tx.len, strip, sizeof strip, &n));
        gz_tx_txid(strip, n, txid);
        for (size_t k = 0; k < GZ_FUND_MAX_FACTORIES; k++) {
            const gz_fund_factory_t *x = &t->f.fac[k];
            if (!x->used) continue;
            if (memcmp(txid, x->funding.txid, 32) == 0) {
                known = 1;
                CHECK(x->signed_len == a->u.broadcast.tx.len &&
                      memcmp(x->signed_tx, a->u.broadcast.tx.data, x->signed_len) == 0);
                CHECK(x->state == GZ_FUND_ST_BROADCAST);
            }
            if (x->sb_len && memcmp(txid, x->sb_txid, 32) == 0) {
                known = 1;
                CHECK(x->state == GZ_FUND_ST_ABANDONED);
                /* I4 by the chain's height, and by the engine's own tip
                 * whenever it knows one (after a restart a refusal can
                 * raise an abandoned factory's spend-back first). */
                CHECK(chain_tip >= x->deadline);
                if (t->f.tip_known) CHECK(t->f.tip >= x->deadline);
                CHECK(x->sb_fee >= gz_fund_fee(x->feerate, 100));
            }
        }
        CHECK(known);
    }
}

static int same_state(ft_t *a, ft_t *b)
{
    for (int j = 0; j < NSCOPE; j++)
        if (gz_fund_scope_state(&a->f, scopes[j], NULL) != gz_fund_scope_state(&b->f, scopes[j], NULL)) return 0;
    for (size_t k = 0; k < GZ_FUND_MAX_FACTORIES; k++) {
        const gz_fund_factory_t *x = &a->f.fac[k];
        const gz_fund_factory_t *y = NULL;
        if (!x->used) continue;
        for (size_t i = 0; i < GZ_FUND_MAX_FACTORIES; i++)
            if (b->f.fac[i].used && memcmp(b->f.fac[i].funding.txid, x->funding.txid, 32) == 0) y = &b->f.fac[i];
        if (!y || y->state != x->state || y->deadline != x->deadline || y->sb_len != x->sb_len) return 0;
    }
    return 1;
}

static void step(ft_t *t, const gz_event_t *e, model_t *m)
{
    size_t from = t->h.n;
    CHECK(ft_ev(t, e) == GZ_OK);                     /* I1, I2 via ft_after */
    CHECK(ft_saves_first(t));
    check_broadcasts(t);
    check_reports(t, from, m);
    CHECK(t->f.n_watches <= GZ_FUND_MAX_WATCHES);   /* I6 */
}

/* H-1 (review B of PR 56): just after a start, the node was down across a
 * factory's deadline while its funding was buried in time. The first tip
 * comes before the watches' reports. Oracle: nothing reports Abandoned
 * before the reports; then a host's factory is Live, never Abandoned. */
static void late_reports(ft_t *t, model_t *m, uint32_t *tip, int host)
{
    gz_fund_factory_t *x = NULL;
    gz_event_t e;
    uint8_t id[32], ins[GZ_FUND_WATCH_INPUTS][36];
    uint32_t dl, h, depth, conf;
    size_t n_ins;
    int j = -1;
    for (size_t k = 0; k < GZ_FUND_MAX_FACTORIES && !x; k++) {
        gz_fund_factory_t *y = &t->f.fac[k];
        if (y->used && y->state == (host ? GZ_FUND_ST_BROADCAST : GZ_FUND_ST_ACKED) && !y->deadline_pending &&
            y->deadline > *tip + 1)
            x = y;
    }
    if (!x) return;
    for (int s = 0; s < NSCOPE; s++)
        if (memcmp(scopes[s], x->scope, 32) == 0) j = s;
    if (j < 0 || m[j].abandoned || m[j].live || m[j].dead) return;
    memcpy(id, x->funding.txid, 32);
    n_ins = x->n_in < GZ_FUND_WATCH_INPUTS ? x->n_in : GZ_FUND_WATCH_INPUTS;
    if (host) n_ins = 1;
    memcpy(ins, x->ins, sizeof ins);
    dl = x->deadline;
    depth = host || x->exit.B == 0 ? 3 : x->exit.B;
    h = dl + 1 - depth;   /* buried exactly at the deadline */
    *tip = dl + 5 + (uint32_t)(rnd() % 10);
    chain_tip = *tip;
    e = ev_tip(*tip);
    step(t, &e, m);
    for (int i = 0; i < 40; i++) {   /* one change per tick: room for every factory */
        e = ev_tick();
        step(t, &e, m);
    }
    CHECK(!m[j].abandoned);   /* no decision before the facts */
    conf = *tip - h + 1;
    e = ev_conf(id, conf, h);
    step(t, &e, m);
    for (size_t k = 0; k < n_ins; k++) {
        e = ev_spent(ins[k], id, conf);
        step(t, &e, m);
    }
    for (int i = 0; i < 40; i++) {   /* one change per tick: room for every factory */
        e = ev_tick();
        step(t, &e, m);
    }
    if (host) CHECK(m[j].live && !m[j].abandoned);
}

/* The chain view answers every watch set at the start (WATCH_SYNCED). */
static void sync_all(ft_t *t, model_t *m)
{
    for (size_t k = 0; k < GZ_FUND_MAX_FACTORIES; k++) {
        gz_fund_factory_t *x = &t->f.fac[k];
        uint8_t id[32], ins[GZ_FUND_WATCH_INPUTS][36];
        size_t n;
        gz_event_t e;
        if (!x->used || !x->resyncing) continue;
        memcpy(id, x->funding.txid, 32);
        memcpy(ins, x->ins, sizeof ins);
        n = t->cfg.host ? 1 : (x->n_in < GZ_FUND_WATCH_INPUTS ? x->n_in : GZ_FUND_WATCH_INPUTS);
        e = ev_synced_tx(id);
        step(t, &e, m);
        for (size_t i = 0; i < n; i++) {
            e = ev_synced_op(ins[i]);
            step(t, &e, m);
        }
    }
}

static ft_t *run_host(ft_t *t, model_t *m, uint32_t *tip, int steps)
{
    for (int i = 0; i < steps; i++) {
        int j = (int)(rnd() % NSCOPE), r = (int)(rnd() % 100);
        gz_event_t e;
        gz_fund_factory_t *x = NULL;
        for (size_t k = 0; k < GZ_FUND_MAX_FACTORIES; k++)
            if (t->f.fac[k].used && memcmp(t->f.fac[k].scope, scopes[j], 32) == 0) x = &t->f.fac[k];
        if (r < 15 && !m[j].ended && !x) {
            gz_fund_plan_in_t in;
            gz_fund_plan_out_t res;
            gz_fund_h1_in_t h;
            uint8_t acked[2] = { 1, 1 }, sig[1] = { 1 }, prop[GZ_FUND_MAX_TX];
            memset(&in, 0, sizeof in);
            memcpy(in.scope, scopes[j], 32);
            in.amount = 500000 + rnd() % 1000;
            ft_script(in.script, 0x77);
            t->w.fail_plan = rnd() % 10 == 0;
            t->w.fail_sign = rnd() % 10 == 0;
            ft_reset(t);
            CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &res) == GZ_OK);
            ft_after(t);
            t->w.fail_plan = 0;
            if (!res.ok) continue;
            memcpy(prop, res.tx, res.tx_len);
            if (rnd() % 10 == 0) prop[res.tx_len - 6] ^= 1;   /* the proposal differs: H1 fails */
            memset(&h, 0, sizeof h);
            memcpy(h.scope, scopes[j], 32);
            h.n_members = 2; h.acked = acked; h.n_nodes = 1; h.signed_ok = sig;
            h.proposed_tx = prop; h.proposed_len = res.tx_len;
            int v = gz_fund_host_h1(&t->f, &h);
            t->w.fail_sign = 0;
            ft_reset(t);
            CHECK(gz_fund_host_apply(&t->f, scopes[j], &t->out) == GZ_OK);
            ft_after(t);
            check_broadcasts(t);
            if (v != GZ_H1_OK) {
                CHECK(ft_count(t, GZ_ACTION_BROADCAST) == 0);
                m[j].ended = 1;
            } else if (t->cfg.mode == GZ_HOST_FUNDING_CONFIRM) {
                CHECK(ft_count(t, GZ_ACTION_BROADCAST) == 0);
            }
            if (v == GZ_H1_OK) m[j].ended = 1;   /* one factory per scope in this model */
        } else if (r < 30) {
            *tip += (uint32_t)(rnd() % 6);
            chain_tip = *tip;
            e = ev_tip(*tip);
            step(t, &e, m);
        } else if (r < 45 && x) {
            e = ev_conf(x->funding.txid, (uint32_t)(rnd() % 5), *tip);
            step(t, &e, m);
        } else if (r < 55 && x) {
            uint8_t other[32];
            memset(other, (int)(rnd() & 0xff), 32);
            e = ev_spent(x->in0, rnd() % 2 ? x->funding.txid : (x->sb_len && rnd() % 2 ? x->sb_txid : other),
                         (uint32_t)(rnd() % 5));
            step(t, &e, m);
        } else if (r < 62 && x && x->sb_len) {
            e = ev_bres(x->sb_txid, (gz_broadcast_outcome_t)(1 + rnd() % 3));
            step(t, &e, m);
        } else if (r < 68 && x) {
            uint8_t buf[256];
            size_t at = 0;
            uint8_t c[2];
            gz_put_u16(c, GZ_CMD_FUNDING_CONFIRM);
            gz_rec_put(buf, 256, &at, 0, (const uint8_t *)"q", 1);
            gz_rec_put(buf, 256, &at, 8, c, 2);
            gz_rec_put(buf, 256, &at, 12, scopes[j], 32);
            memset(&e, 0, sizeof e);
            e.kind = GZ_EVENT_USER_COMMAND;
            e.u.user.bytes.data = buf;
            e.u.user.bytes.len = at;
            t->w.fail_sign = rnd() % 5 == 0;
            step(t, &e, m);
            t->w.fail_sign = 0;
        } else if (r < 70) {
            ft_t *u = ft_restart(t);
            CHECK(same_state(t, u));                 /* I7 */
            free(t);
            t = u;
            if (rnd() % 2) late_reports(t, m, tip, 1);
            if (rnd() % 4) sync_all(t, m);
        } else {
            e = ev_tick();
            step(t, &e, m);
        }
    }
    return t;
}

static ft_t *run_member(ft_t *t, model_t *m, uint32_t *tip, int steps)
{
    static uint8_t txs[NSCOPE][400];
    for (int i = 0; i < steps; i++) {
        int j = (int)(rnd() % NSCOPE), r = (int)(rnd() % 100);
        gz_event_t e;
        gz_fund_factory_t *x = NULL;
        for (size_t k = 0; k < GZ_FUND_MAX_FACTORIES; k++)
            if (t->f.fac[k].used && memcmp(t->f.fac[k].scope, scopes[j], 32) == 0) x = &t->f.fac[k];
        if (r < 12 && !m[j].ended) {
            gz_fund_acked_in_t a;
            ft_in_t ins[2];
            uint64_t amts[1] = { 802811 };
            uint8_t scr[1][34];
            size_t len;
            memset(&a, 0, sizeof a);
            memcpy(a.scope, scopes[j], 32);
            ft_op(ins[0].op, (uint8_t)(0x20 + j), 0);
            ft_op(ins[1].op, (uint8_t)(0x40 + rnd() % 2), 1);   /* sometimes shared */
            ft_script(scr[0], 0x77);
            len = ft_tx(txs[j], ins, 2, amts, (const uint8_t(*)[34])scr, 1, 0);
            a.funding_tx = txs[j];
            a.funding_tx_len = len;
            gz_tx_txid(txs[j], len, a.funding.txid);
            a.amount = 802811;
            memcpy(a.script, scr[0], 34);
            a.ack_tip = *tip;
            a.end_height = *tip + 100 + (uint32_t)(rnd() % 200);
            a.own_depth = (uint8_t)(1 + rnd() % 2);
            a.whole_tree = (uint8_t)(rnd() % 2);
            a.exit = gz_exit_signet();
            a.deadline_blocks = 36;
            ft_reset(t);
            CHECK(gz_fund_member_acked(&t->f, &a, &t->out) == GZ_OK);
            ft_after(t);
            CHECK(ft_count(t, GZ_ACTION_BROADCAST) == 0);   /* a member never broadcasts */
            m[j].ended = 1;
        } else if (r < 35) {
            *tip += (uint32_t)(rnd() % 8);
            chain_tip = *tip;
            e = ev_tip(*tip);
            step(t, &e, m);
        } else if (r < 50 && x) {
            e = ev_conf(x->funding.txid, (uint32_t)(rnd() % 5), *tip - (uint32_t)(rnd() % 3));
            step(t, &e, m);
        } else if (r < 60 && x) {
            uint8_t other[32];
            memset(other, (int)(rnd() & 0xff), 32);
            e = ev_spent(x->ins[rnd() % 2], rnd() % 3 ? other : x->funding.txid, (uint32_t)(rnd() % 5));
            step(t, &e, m);
        } else if (r < 63) {
            ft_t *u = ft_restart(t);
            CHECK(same_state(t, u));
            free(t);
            t = u;
            if (rnd() % 2) late_reports(t, m, tip, 0);
            if (rnd() % 4) sync_all(t, m);
        } else {
            e = ev_tick();
            step(t, &e, m);
        }
        CHECK(ft_count(t, GZ_ACTION_BROADCAST) == 0);
    }
    return t;
}

int main(int argc, char **argv)
{
    long runs = argc > 1 ? strtol(argv[1], NULL, 10) : 100;
    if (argc > 2) s ^= strtoull(argv[2], NULL, 10) * 0x9e3779b97f4a7c15ULL;
    for (int j = 0; j < NSCOPE; j++) memset(scopes[j], 0x61 + j, 32);
    for (long r = 0; r < runs && !g_fail; r++) {
        model_t m[NSCOPE];
        uint32_t tip = 1000;
        chain_tip = tip;
        int host = (int)(r % 2);
        ft_t *t = ft_new(host, rnd() % 2 ? GZ_HOST_FUNDING_AUTO : GZ_HOST_FUNDING_CONFIRM);
        gz_event_t e = ev_tip(tip);
        memset(m, 0, sizeof m);
        if (rnd() % 2) CHECK(ft_ev(t, &e) == GZ_OK);   /* sometimes no tip yet */
        t = host ? run_host(t, m, &tip, 300) : run_member(t, m, &tip, 300);
        free(t);
    }
    if (g_fail) {
        fprintf(stderr, "%d failed\n", g_fail);
        return 1;
    }
    printf("funding model: %ld runs passed\n", runs);
    return 0;
}
