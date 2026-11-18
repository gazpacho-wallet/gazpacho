/* Unit tests of the funding engine (core/funding). */
#include "fund_test.h"

static const uint8_t SCOPE_A[32] = { 0xa1 };
static const uint8_t SCOPE_B[32] = { 0xb2 };

static gz_fund_plan_in_t plan_in(const uint8_t scope[32], int released)
{
    gz_fund_plan_in_t in;
    memset(&in, 0, sizeof in);
    memcpy(in.scope, scope, 32);
    memset(in.check, 0x33, 32);
    in.attempt = 1;
    in.amount = 802811;
    ft_script(in.script, 0x77);
    in.released = released;
    return in;
}

/* Plans, runs H1 against the plan itself, applies. Returns the plan. */
static gz_fund_plan_out_t host_fund(ft_t *t, const uint8_t scope[32], int expect_h1)
{
    gz_fund_plan_in_t in = plan_in(scope, 0);
    gz_fund_plan_out_t res;
    gz_fund_h1_in_t h;
    uint8_t acked[3] = { 1, 1, 1 }, sig[5] = { 1, 1, 1, 1, 1 }, prop[GZ_FUND_MAX_TX];
    ft_reset(t);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &res) == GZ_OK);
    ft_after(t);
    CHECK(res.ok);
    if (!res.ok) return res;
    memcpy(prop, res.tx, res.tx_len);
    memset(&h, 0, sizeof h);
    memcpy(h.scope, scope, 32);
    h.n_members = 3; h.acked = acked; h.n_nodes = 5; h.signed_ok = sig;
    h.proposed_tx = prop; h.proposed_len = res.tx_len;
    CHECK(gz_fund_host_h1(&t->f, &h) == expect_h1);
    ft_reset(t);
    CHECK(gz_fund_host_apply(&t->f, scope, &t->out) == GZ_OK);
    ft_after(t);
    CHECK(ft_saves_first(t));
    return res;
}

static void test_fees(void)
{
    CHECK(gz_fund_fee(100, 111) == 12);
    CHECK(gz_fund_fee(100, 110) == 11);
    CHECK(gz_fund_fee(1000, 111) == 111);
    CHECK(gz_fund_fee(0, 111) == 0);
    CHECK(gz_fund_fee(100000001, 1) == UINT64_MAX);
    /* Funding of 154 vB at 0.1 sat/vB pays 16; the spend-back of 111 vB. */
    CHECK(gz_fund_replace_fee(16, 154, 111, 100) == 28);
    CHECK(gz_fund_replace_fee(16, 154, 111, 1000) == 127);
    /* Rule 6 binds when the replaced transaction pays a high rate. */
    CHECK(gz_fund_replace_fee(1000, 100, 111, 100) == 1111);
    CHECK(gz_fund_replace_fee(0, 0, 111, 100) == 12);
    CHECK(gz_fund_replace_fee(UINT64_MAX, 1, 1, 1) == UINT64_MAX);
}

static void test_tx_sizes(void)
{
    ft_in_t in;
    uint64_t amt = 1000, vs;
    uint8_t scr[1][34], tx[300], st[300];
    size_t len, base, n;
    ft_op(in.op, 1, 0);
    ft_script(scr[0], 2);
    len = ft_tx(tx, &in, 1, &amt, (const uint8_t(*)[34])scr, 1, 1);
    CHECK(gz_fund_tx_vsize(tx, len, &vs, &base) && vs == 111 && base == 94 && len == 162);
    CHECK(gz_fund_tx_strip(tx, len, st, sizeof st, &n) && n == 94);
    len = ft_tx(tx, &in, 1, &amt, (const uint8_t(*)[34])scr, 1, 0);
    CHECK(n == len && memcmp(st, tx, n) == 0);
    CHECK(gz_fund_tx_vsize(tx, len, &vs, &base) && vs == 94);
    CHECK(!gz_fund_tx_vsize(tx, len - 1, &vs, &base));
    tx[len - 1] = 0; /* still parses: the lock time's last byte */
    CHECK(gz_fund_tx_vsize(tx, len, &vs, &base));
    CHECK(!gz_fund_tx_vsize(tx, 9, &vs, &base));
    {
        /* Two inputs with witnesses: 674 weight units, 169 vB (rounded up). */
        ft_in_t two[2];
        ft_op(two[0].op, 1, 0);
        ft_op(two[1].op, 1, 1);
        len = ft_tx(tx, two, 2, &amt, (const uint8_t(*)[34])scr, 1, 1);
        CHECK(len == 269 && gz_fund_tx_vsize(tx, len, &vs, &base) && base == 135 && vs == 169);
    }
}

static void test_init(void)
{
    gz_fund_config_t c;
    gz_ports_t p = ft_ports();
    gz_fund_t *f = (gz_fund_t *)calloc(1, sizeof *f);
    ft_hooks_t h;
    gz_fund_config_default(&c, 0);
    CHECK(c.feerate == 100 && c.incremental == 100 && c.incremental_high == 1000 && c.burial == 3 &&
          c.funding_deadline_blocks == 36 && c.mode == GZ_HOST_FUNDING_AUTO);
    CHECK(gz_fund_init(f, &c, &p) == GZ_ERR_ARGUMENT);   /* no hooks */
    c.hooks.ctx = &h; c.hooks.report = fth_report;
    CHECK(gz_fund_init(f, &c, &p) == GZ_OK);
    c.host = 1;
    CHECK(gz_fund_init(f, &c, &p) == GZ_ERR_ARGUMENT);   /* a host needs its wallet */
    c.host = 0; c.burial = 0;
    CHECK(gz_fund_init(f, &c, &p) == GZ_ERR_ARGUMENT);
    c.burial = 3; c.incremental = 2000;
    CHECK(gz_fund_init(f, &c, &p) == GZ_ERR_ARGUMENT);
    c.incremental = 100; c.mode = (gz_host_funding_t)7;
    CHECK(gz_fund_init(f, &c, &p) == GZ_ERR_ARGUMENT);
    free(f);
}

static void test_auto_live(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
    gz_event_t e = ev_tip(100);
    gz_fund_plan_out_t p;
    const gz_action_t *b;
    uint32_t until;
    CHECK(ft_ev(t, &e) == GZ_OK);
    p = host_fund(t, SCOPE_A, 0);
    CHECK(ft_count(t, GZ_ACTION_SAVE) == 1 && ft_count(t, GZ_ACTION_BROADCAST) == 1);
    CHECK(ft_count(t, GZ_ACTION_WATCH_TX) == 1 && ft_count(t, GZ_ACTION_WATCH_OUTPOINT) == 1);
    CHECK(ft_saved_state(t) == GZ_FUND_ST_BROADCAST);
    b = ft_find(t, GZ_ACTION_BROADCAST);
    CHECK(b && b->u.broadcast.tx.len > p.tx_len);
    CHECK(gz_fund_scope_state(&t->f, SCOPE_A, &until) == GZ_FUND_SCOPE_OPEN && until == 100 + 36 + 3);
    CHECK(t->f.n_watches == 2);
    e = ev_conf(p.funding.txid, 2, 101);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK && t->h.n == 0);
    e = ev_conf(p.funding.txid, 3, 101);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK);
    CHECK(ft_saved_state(t) == GZ_FUND_ST_LIVE);
    CHECK(t->h.n == 1 && t->h.r[0].kind == GZ_FUND_R_LIVE && t->h.r[0].host == 1);
    CHECK(memcmp(t->h.r[0].funding.txid, p.funding.txid, 32) == 0);
    CHECK(t->h.unwatched == 2 && t->f.n_watches == 0);
    CHECK(gz_fund_scope_state(&t->f, SCOPE_A, NULL) == GZ_FUND_SCOPE_LIVE);
    CHECK(gz_fund_scope_state(&t->f, SCOPE_B, NULL) == GZ_FUND_SCOPE_NONE);
    {
        ft_t *u = ft_restart(t);
        CHECK(gz_fund_scope_state(&u->f, SCOPE_A, NULL) == GZ_FUND_SCOPE_LIVE);
        CHECK(u->w.held == 0);
        free(u);
    }
    free(t);
}

static void test_plans(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
    gz_fund_plan_in_t in = plan_in(SCOPE_A, 0);
    gz_fund_plan_out_t r1, r2;
    uint8_t first_in0[36], tx1[GZ_FUND_MAX_TX];
    size_t len1;
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r1) == GZ_OK && r1.ok);
    ft_after(t);
    CHECK(ft_count(t, GZ_ACTION_SAVE) == 1);
    memcpy(tx1, r1.tx, r1.tx_len);
    len1 = r1.tx_len;
    memcpy(first_in0, tx1 + 5, 36);
    /* Nothing released: the same plan, nothing saved. */
    ft_reset(t);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && r2.ok);
    CHECK(t->out.count == 0 && r2.tx_len == len1 && memcmp(r2.tx, tx1, len1) == 0 && t->w.planned == 1);
    /* Released (H11): a new plan spending input 0 of the old one. */
    in.released = 1;
    ft_reset(t);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && r2.ok);
    CHECK(t->w.planned == 2 && t->w.released == 1);
    CHECK(memcmp(r2.tx + 5, first_in0, 36) == 0 && memcmp(r2.funding.txid, r1.funding.txid, 32) != 0);
    /* A wallet that does not honour the reused input: refused. */
    t->w.ignore_must = 1;
    ft_reset(t);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && !r2.ok);
    /* The plan whose attempt released is saved again, marked released (M1). */
    CHECK(ft_count(t, GZ_ACTION_NOTIFY) == 1 && ft_count(t, GZ_ACTION_SAVE) == 1);
    t->w.ignore_must = 0;
    /* No coins. */
    t->w.fail_plan = 1;
    ft_reset(t);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && !r2.ok);
    t->w.fail_plan = 0;
    /* The factory's output twice. */
    t->w.extra_output = 1;
    in.released = 0;
    ft_reset(t);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && !r2.ok);
    t->w.extra_output = 0;
    /* A spent output that is not a witness program (H1, early). */
    t->w.legacy_prev = 1;
    ft_reset(t);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && !r2.ok);
    t->w.legacy_prev = 0;
    /* A witness program shorter than two bytes. */
    for (int k = 1; k <= 2; k++) {
        t->w.tiny_prev = k;
        ft_reset(t);
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && !r2.ok);
    }
    t->w.tiny_prev = 0;
    /* The 8,192-byte cap (item 13): 197 inputs fit, 198 do not. */
    t->w.oversize = 197;
    ft_reset(t);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && r2.ok && r2.tx_len <= GZ_FUND_MAX_TX);
    ft_after(t);
    t->w.oversize = 198;
    in.released = 1;
    ft_reset(t);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && !r2.ok);
    t->w.oversize = 0;
    /* A bad factory output. */
    in.script[0] = 0;
    ft_reset(t);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && !r2.ok);
    CHECK(t->f.refused >= 6);
    /* A member has no plans. */
    {
        ft_t *m = ft_new(0, GZ_HOST_FUNDING_AUTO);
        CHECK(gz_fund_host_plan(&m->f, &in, &m->out, &r2) == GZ_ERR_ARGUMENT);
        free(m);
    }
    free(t);
}

static void test_h1(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
    gz_fund_plan_in_t in = plan_in(SCOPE_A, 0);
    gz_fund_plan_out_t r;
    gz_fund_h1_in_t h;
    uint8_t acked[3] = { 1, 0, 1 }, sig[2] = { 1, 1 }, prop[GZ_FUND_MAX_TX];
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r) == GZ_OK && r.ok);
    memcpy(prop, r.tx, r.tx_len);
    memset(&h, 0, sizeof h);
    memcpy(h.scope, SCOPE_A, 32);
    h.n_members = 3; h.acked = acked; h.n_nodes = 2; h.signed_ok = sig;
    h.proposed_tx = prop; h.proposed_len = r.tx_len;
    CHECK(gz_fund_host_h1(&t->f, &h) == GZ_H1_ACK_MISSING);
    acked[1] = 1;
    sig[1] = 0;
    CHECK(gz_fund_host_h1(&t->f, &h) == GZ_H1_UNSIGNED);
    sig[1] = 1;
    prop[r.tx_len - 5] ^= 1;   /* not the plan */
    CHECK(gz_fund_host_h1(&t->f, &h) == GZ_H1_TX_DIFFERS);
    prop[r.tx_len - 5] ^= 1;
    t->w.fail_sign = 1;
    CHECK(gz_fund_host_h1(&t->f, &h) == GZ_FUND_H1_SIGN);
    t->w.fail_sign = 0;
    t->w.bad_signed = 1;
    CHECK(gz_fund_host_h1(&t->f, &h) == GZ_FUND_H1_SIGNED);
    t->w.bad_signed = 0;
    t->w.empty_wit = 1;   /* an input left without a witness */
    CHECK(gz_fund_host_h1(&t->f, &h) == GZ_FUND_H1_SIGNED);
    t->w.empty_wit = 0;
    memcpy(h.scope, SCOPE_B, 32);
    CHECK(gz_fund_host_h1(&t->f, &h) == GZ_FUND_H1_NO_PLAN);
    /* Apply after a failed H1: released, nothing broadcast, the slot's end. */
    ft_reset(t);
    CHECK(gz_fund_host_apply(&t->f, SCOPE_A, &t->out) == GZ_OK);
    ft_after(t);
    CHECK(ft_count(t, GZ_ACTION_BROADCAST) == 0 && ft_saved_state(t) == GZ_FUND_ST_FAILED && t->w.released == 1);
    CHECK(gz_fund_scope_state(&t->f, SCOPE_A, NULL) == GZ_FUND_SCOPE_FAILED);
    /* Apply with no plan: the composite's bug. */
    ft_reset(t);
    CHECK(gz_fund_host_apply(&t->f, SCOPE_B, &t->out) == GZ_ERR_ARGUMENT);
    /* A plan dropped by a lobby that ended. */
    in = plan_in(SCOPE_B, 0);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r) == GZ_OK && r.ok);
    ft_reset(t);
    CHECK(gz_fund_host_drop(&t->f, SCOPE_B, &t->out) == GZ_OK && ft_saved_state(t) == GZ_FUND_ST_FAILED);
    CHECK(t->w.released == 2);
    ft_reset(t);
    CHECK(gz_fund_host_drop(&t->f, SCOPE_B, &t->out) == GZ_OK && t->out.count == 0);
    free(t);
}

static gz_event_t cmd_confirm(const uint8_t scope[32], uint16_t code, uint8_t *buf, int with_scope)
{
    size_t at = 0;
    uint8_t c[2];
    gz_event_t e;
    gz_put_u16(c, code);
    gz_rec_put(buf, 256, &at, GZ_CMD_REC_REQUEST_ID, (const uint8_t *)"r1", 2);
    gz_rec_put(buf, 256, &at, GZ_CMD_REC_COMMAND, c, 2);
    if (with_scope) gz_rec_put(buf, 256, &at, 12, scope, 32);
    memset(&e, 0, sizeof e);
    e.kind = GZ_EVENT_USER_COMMAND;
    e.u.user.bytes.data = buf;
    e.u.user.bytes.len = at;
    return e;
}

static int result_status(const ft_t *t)
{
    const gz_action_t *a = NULL;
    gz_bytes_t v;
    for (size_t i = 0; i < t->out.count; i++)
        if (t->out.slots[i].kind == GZ_ACTION_NOTIFY && t->out.slots[i].u.notify.code == GZ_NOTIFY_COMMAND_RESULT)
            a = &t->out.slots[i];
    if (!a || gz_rec_find(a->u.notify.bytes, GZ_RESULT_REC_STATUS, &v) != 1 || v.len != 2) return -1;
    return gz_get_u16(v.data);
}

static void test_confirm(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_CONFIRM), *u;
    gz_event_t e = ev_tip(200);
    uint8_t buf[256];
    CHECK(ft_ev(t, &e) == GZ_OK);
    host_fund(t, SCOPE_A, 0);
    CHECK(ft_count(t, GZ_ACTION_BROADCAST) == 0 && ft_saved_state(t) == GZ_FUND_ST_AWAITING);
    CHECK(ft_count(t, GZ_ACTION_NOTIFY) == 1 && t->w.signed_n == 0);
    /* The notice survives a restart, and the coins are held again. */
    u = ft_restart(t);
    CHECK(u->w.held == 1);
    free(t);
    t = u;
    e = ev_tip(201);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = cmd_confirm(SCOPE_B, GZ_CMD_FUNDING_CONFIRM, buf, 1);
    CHECK(ft_ev(t, &e) == GZ_OK && result_status(t) == 404);
    e = cmd_confirm(SCOPE_A, GZ_CMD_FUNDING_CONFIRM, buf, 0);
    CHECK(ft_ev(t, &e) == GZ_OK && result_status(t) == 400);
    e = cmd_confirm(SCOPE_A, 0x0399, buf, 1);
    CHECK(ft_ev(t, &e) == GZ_OK && result_status(t) == 404);
    t->w.fail_sign = 1;
    e = cmd_confirm(SCOPE_A, GZ_CMD_FUNDING_CONFIRM, buf, 1);
    CHECK(ft_ev(t, &e) == GZ_OK && result_status(t) == 503 && ft_count(t, GZ_ACTION_BROADCAST) == 0);
    t->w.fail_sign = 0;
    t->w.bad_signed = 1;   /* signed bytes that are not the plan */
    e = cmd_confirm(SCOPE_A, GZ_CMD_FUNDING_CONFIRM, buf, 1);
    CHECK(ft_ev(t, &e) == GZ_OK && result_status(t) == 503 && ft_count(t, GZ_ACTION_BROADCAST) == 0);
    t->w.bad_signed = 0;
    e = cmd_confirm(SCOPE_A, GZ_CMD_FUNDING_CONFIRM, buf, 1);
    CHECK(ft_ev(t, &e) == GZ_OK && result_status(t) == 200);
    CHECK(ft_count(t, GZ_ACTION_BROADCAST) == 1 && ft_saved_state(t) == GZ_FUND_ST_BROADCAST && ft_saves_first(t));
    e = cmd_confirm(SCOPE_A, GZ_CMD_FUNDING_CONFIRM, buf, 1);
    CHECK(ft_ev(t, &e) == GZ_OK && result_status(t) == 409);
    /* A command without a request id is dropped. */
    {
        gz_event_t z;
        memset(&z, 0, sizeof z);
        z.kind = GZ_EVENT_USER_COMMAND;
        CHECK(ft_ev(t, &z) == GZ_OK && t->out.count == 0);
    }
    free(t);
}

/* Runs ticks until nothing is due; returns the number of steps that did something. */
static int drain(ft_t *t)
{
    int n = 0;
    for (int i = 0; i < 40; i++) {
        gz_event_t e = ev_tick();
        CHECK(ft_ev(t, &e) == GZ_OK);
        if (ft_find(t, GZ_ACTION_SET_TIMER) == NULL) break;
        if (t->out.count > 1) n++;
    }
    return n;
}

static void test_confirm_deadline(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_CONFIRM);
    gz_event_t e = ev_tip(300);
    const gz_action_t *b;
    CHECK(ft_ev(t, &e) == GZ_OK);
    host_fund(t, SCOPE_A, 0);
    e = ev_tip(300 + 36);   /* the deadline: the tip at the plan + 36 */
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 0);
    e = ev_tip(300 + 37);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK);
    CHECK(ft_saved_state(t) == GZ_FUND_ST_ABANDONED && ft_saves_first(t));
    CHECK(t->h.n == 1 && t->h.r[0].kind == GZ_FUND_R_ABANDONED && t->h.r[0].cancel_reason == 4);
    b = ft_find(t, GZ_ACTION_BROADCAST);
    /* Never signed: nothing to replace, the ordinary rate (12 sat on 111 vB). */
    CHECK(b && t->w.last_sb_fee == 12);
    free(t);
}

static void test_abandon_replace(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
    gz_event_t e = ev_tip(400);
    gz_fund_plan_out_t p;
    uint8_t in0[36], sb_txid[32];
    gz_fund_factory_t *x;
    uint64_t ffee, fvs;
    CHECK(ft_ev(t, &e) == GZ_OK);
    p = host_fund(t, SCOPE_A, 0);
    memcpy(in0, p.tx + 5, 36);
    x = &t->f.fac[0];
    /* The funding seen in the mempool. */
    e = ev_spent(in0, p.funding.txid, 0);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tip(400 + 39);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK);
    CHECK(ft_saved_state(t) == GZ_FUND_ST_ABANDONED && t->h.n == 1);
    CHECK(gz_fund_tx_vsize(x->signed_tx, x->signed_len, &fvs, NULL));
    ffee = 2u * 600000u - 802811u - (2u * 600000u - 802811u - 200u);
    CHECK(ffee == 200);
    CHECK(t->w.last_sb_fee == gz_fund_replace_fee(200, fvs, 111, 100));
    CHECK(x->sb_escalated == 1);
    memcpy(sb_txid, x->sb_txid, 32);
    /* Refused (a 28.x or 29.0 server): the higher increment, once. */
    e = ev_bres(sb_txid, GZ_BROADCAST_REFUSED);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK);
    CHECK(t->w.last_sb_fee == gz_fund_replace_fee(200, fvs, 111, 1000) && x->sb_escalated == 2);
    CHECK(ft_count(t, GZ_ACTION_BROADCAST) == 1 && ft_saved_state(t) == GZ_FUND_ST_ABANDONED);
    memcpy(sb_txid, x->sb_txid, 32);
    e = ev_bres(sb_txid, GZ_BROADCAST_REFUSED);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK && ft_count(t, GZ_ACTION_BROADCAST) == 0 && x->sb_escalated == 2);
    /* A restart keeps the spend-back and sends it again. */
    {
        ft_t *u = ft_restart(t);
        CHECK(u->f.fac[0].used && u->f.fac[0].sb_len == x->sb_len && u->f.fac[0].sb_escalated == 2);
        CHECK(memcmp(u->f.fac[0].sb_txid, x->sb_txid, 32) == 0);
        free(u);
    }
    /* The spend-back buried: Dead, nothing more reported. */
    e = ev_spent(in0, sb_txid, 3);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK);
    CHECK(ft_saved_state(t) == GZ_FUND_ST_DEAD && t->h.n == 1 && t->f.n_watches == 0);
    CHECK(gz_fund_scope_state(&t->f, SCOPE_A, NULL) == GZ_FUND_SCOPE_DEAD);
    free(t);
}

static void test_abandon_unseen_then_late(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
    gz_event_t e = ev_tip(500);
    gz_fund_plan_out_t p;
    gz_fund_factory_t *x;
    CHECK(ft_ev(t, &e) == GZ_OK);
    p = host_fund(t, SCOPE_A, 0);
    x = &t->f.fac[0];
    e = ev_tip(539);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK);
    CHECK(t->w.last_sb_fee == 12 && x->sb_escalated == 0);   /* never seen: the ordinary rate */
    e = ev_bres(x->sb_txid, GZ_BROADCAST_REFUSED);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK && x->sb_escalated == 1);
    /* The funding buried first: live after all, funded late. */
    e = ev_conf(p.funding.txid, 3, 540);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK);
    CHECK(ft_saved_state(t) == GZ_FUND_ST_LIVE_LATE && t->h.n == 2 && t->h.r[1].kind == GZ_FUND_R_FUNDED_LATE);
    CHECK(gz_fund_scope_state(&t->f, SCOPE_A, NULL) == GZ_FUND_SCOPE_LIVE);
    free(t);
}

static void test_host_dead_and_reorg(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
    gz_event_t e = ev_tip(600);
    gz_fund_plan_out_t p, q;
    uint8_t in0[36], other[32];
    memset(other, 0x99, 32);
    CHECK(ft_ev(t, &e) == GZ_OK);
    p = host_fund(t, SCOPE_A, 0);
    q = host_fund(t, SCOPE_B, 0);
    memcpy(in0, p.tx + 5, 36);
    /* Reorganised away before burial: not live. */
    e = ev_conf(q.funding.txid, 2, 601);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_conf(q.funding.txid, 0, 0);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_conf(q.funding.txid, 1, 603);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 0);
    e = ev_conf(q.funding.txid, 3, 601);   /* buried, then reorganised away before the tick */
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_conf(q.funding.txid, 0, 0);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 0);
    /* Input 0 spent elsewhere, 0 then 3 confirmations. */
    e = ev_spent(in0, other, 0);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 0);
    e = ev_spent(in0, other, 3);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 1 && t->h.r[0].kind == GZ_FUND_R_DEAD && t->h.r[0].cancel_reason == 4);
    CHECK(memcmp(t->h.r[0].scope, SCOPE_A, 32) == 0);
    /* Both due at once: one change per tick. */
    e = ev_conf(q.funding.txid, 3, 603);
    CHECK(ft_ev(t, &e) == GZ_OK);
    CHECK(drain(t) == 1 && t->h.n == 2 && t->h.r[1].kind == GZ_FUND_R_LIVE);
    free(t);
}

/* What the wallet returns is checked: the spend-back spends the chosen
 * input, does not pay the factory and pays exactly the fee asked; a plan has
 * one spent output per input. A fault: nothing broadcast, the factory still
 * Abandoned (or the plan refused). */
static void test_wallet_checked(void)
{
    for (int k = 0; k < 4; k++) {
        ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
        gz_event_t e = ev_tip(900);
        CHECK(ft_ev(t, &e) == GZ_OK);
        host_fund(t, SCOPE_A, 0);
        t->w.sb_other_input = k == 1;
        t->w.sb_to_factory = k == 2;
        t->w.sb_fee_off = k == 3;
        e = ev_tip(900 + 39);
        CHECK(ft_ev(t, &e) == GZ_OK);
        e = ev_tick();
        CHECK(ft_ev(t, &e) == GZ_OK);
        CHECK(ft_saved_state(t) == GZ_FUND_ST_ABANDONED && t->h.n == 1);
        /* k 0, the wallet's own: one spend-back. */
        CHECK(ft_count(t, GZ_ACTION_BROADCAST) == (k == 0 ? 1u : 0u) && (t->f.fac[0].sb_len != 0) == (k == 0));
        free(t);
    }
    {
        ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
        gz_fund_plan_in_t in = plan_in(SCOPE_A, 0);
        gz_fund_plan_out_t r;
        t->w.extra_prev = 1;
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r) == GZ_OK && !r.ok && t->w.released == 1);
        free(t);
    }
    /* No change for H16's child, an output nobody agreed (M2), or the
     * factory's output twice in two outputs: refused. */
    for (int k = 0; k < 3; k++) {
        ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
        gz_fund_plan_in_t in = plan_in(SCOPE_A, 0);
        gz_fund_plan_out_t r;
        t->w.no_change = k == 0;
        t->w.third_output = k == 1;
        t->w.factory_twice = k == 2;
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r) == GZ_OK && !r.ok && t->w.released == 1);
        free(t);
    }
}

/* H11 across a refused plan (review A of PR 56, M1): the released plan is
 * kept, held again and saved marked; every later plan of the scope spends its
 * input 0, with and without a restart, and its outpoint is never reused. */
static void test_must_kept(void)
{
    for (int restart = 0; restart <= 1; restart++) {
        ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
        gz_fund_plan_in_t in = plan_in(SCOPE_A, 0);
        gz_fund_plan_out_t r1, r2, r3;
        uint8_t in0[36], txid1[32];
        gz_event_t e = ev_tip(50);
        int held;
        CHECK(ft_ev(t, &e) == GZ_OK);
        ft_reset(t);
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r1) == GZ_OK && r1.ok);
        ft_after(t);
        memcpy(in0, r1.tx + 5, 36);
        memcpy(txid1, r1.funding.txid, 32);
        /* Released, and the next plan fails: the old plan is adopted again
         * and saved, marked released. */
        in.released = 1;
        t->w.fail_plan = 1;
        held = t->w.held;
        ft_reset(t);
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && !r2.ok);
        ft_after(t);
        CHECK(t->w.held == held + 1 && ft_count(t, GZ_ACTION_SAVE) == 1);
        t->w.fail_plan = 0;
        if (restart) {
            ft_t *u = ft_restart(t);
            free(t);
            t = u;
        }
        /* The next attempt released nothing itself: still a new plan, on
         * input 0 of the released one. */
        in.released = 0;
        ft_reset(t);
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r2) == GZ_OK && r2.ok);
        ft_after(t);
        CHECK(memcmp(r2.funding.txid, txid1, 32) != 0 && memcmp(r2.tx + 5, in0, 36) == 0);
        /* That plan, not released, serves again as it is. */
        ft_reset(t);
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r3) == GZ_OK && r3.ok &&
              memcmp(r3.funding.txid, r2.funding.txid, 32) == 0 && t->out.count == 0);
        free(t);
    }
    {
        /* The coin that must be spent is input 0, not another input (L2). */
        ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
        gz_fund_plan_in_t in = plan_in(SCOPE_A, 0);
        gz_fund_plan_out_t r;
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r) == GZ_OK && r.ok);
        in.released = 1;
        t->w.must_at_1 = 1;
        ft_reset(t);
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &r) == GZ_OK && !r.ok);
        free(t);
    }
    {
        /* The amount changed, nothing released: a new plan, not the old one. */
        ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
        gz_fund_plan_in_t in = plan_in(SCOPE_B, 0);
        gz_fund_plan_out_t a1, a2;
        uint8_t id1[32];
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &a1) == GZ_OK && a1.ok);
        memcpy(id1, a1.funding.txid, 32);
        in.amount += 1;
        ft_reset(t);
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &a2) == GZ_OK && a2.ok);
        CHECK(memcmp(a2.funding.txid, id1, 32) != 0 && t->w.planned == 2);
        free(t);
    }
}

/* The host's deadline is its tip at the plan + 36 (review A of PR 56, M3):
 * a burial by it is Live; a later one is Abandoned, with no spend-back, then
 * funded late. */
static void test_deadline_basis(void)
{
    for (int late = 0; late <= 1; late++) {
        ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
        gz_event_t e = ev_tip(1000);
        gz_fund_plan_in_t in = plan_in(SCOPE_A, 0);
        gz_fund_plan_out_t p;
        gz_fund_h1_in_t h;
        uint8_t acked[3] = { 1, 1, 1 }, sig[5] = { 1, 1, 1, 1, 1 }, prop[GZ_FUND_MAX_TX];
        uint32_t until;
        CHECK(ft_ev(t, &e) == GZ_OK);
        ft_reset(t);
        CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &p) == GZ_OK && p.ok);
        ft_after(t);
        memcpy(prop, p.tx, p.tx_len);
        e = ev_tip(1005);   /* the round takes five blocks */
        CHECK(ft_ev(t, &e) == GZ_OK);
        memset(&h, 0, sizeof h);
        memcpy(h.scope, SCOPE_A, 32);
        h.n_members = 3; h.acked = acked; h.n_nodes = 5; h.signed_ok = sig;
        h.proposed_tx = prop; h.proposed_len = p.tx_len;
        CHECK(gz_fund_host_h1(&t->f, &h) == 0);
        ft_reset(t);
        CHECK(gz_fund_host_apply(&t->f, SCOPE_A, &t->out) == GZ_OK);
        ft_after(t);
        CHECK(t->f.fac[0].deadline == 1036);
        CHECK(gz_fund_scope_state(&t->f, SCOPE_A, &until) == GZ_FUND_SCOPE_OPEN && until == 1039);
        /* Buried at 1036 (on time) or at 1037 (late). */
        e = ev_conf(p.funding.txid, 3, (uint32_t)(1034 + late));
        CHECK(ft_ev(t, &e) == GZ_OK);
        e = ev_tip((uint32_t)(1036 + late));
        CHECK(ft_ev(t, &e) == GZ_OK);
        e = ev_tick();
        CHECK(ft_ev(t, &e) == GZ_OK);
        if (!late) {
            CHECK(ft_saved_state(t) == GZ_FUND_ST_LIVE && t->h.n == 1 && t->h.r[0].kind == GZ_FUND_R_LIVE);
        } else {
            CHECK(ft_saved_state(t) == GZ_FUND_ST_ABANDONED && ft_count(t, GZ_ACTION_BROADCAST) == 0);
            CHECK(t->h.n == 1 && t->h.r[0].kind == GZ_FUND_R_ABANDONED && t->w.sb_n == 0);
            drain(t);
            CHECK(t->h.n == 2 && t->h.r[1].kind == GZ_FUND_R_FUNDED_LATE);
            CHECK(gz_fund_scope_state(&t->f, SCOPE_A, NULL) == GZ_FUND_SCOPE_LIVE);
        }
        free(t);
    }
}

/* A restart between the plan and the outcome keeps the plan's tip as the
 * deadline's basis. */
static void test_deadline_after_restart(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO), *u;
    gz_event_t e = ev_tip(1000);
    gz_fund_plan_in_t in = plan_in(SCOPE_A, 0);
    gz_fund_plan_out_t p;
    gz_fund_h1_in_t h;
    uint8_t acked[3] = { 1, 1, 1 }, sig[5] = { 1, 1, 1, 1, 1 }, prop[GZ_FUND_MAX_TX];
    CHECK(ft_ev(t, &e) == GZ_OK);
    ft_reset(t);
    CHECK(gz_fund_host_plan(&t->f, &in, &t->out, &p) == GZ_OK && p.ok);
    ft_after(t);
    memcpy(prop, p.tx, p.tx_len);
    u = ft_restart(t);
    free(t);
    e = ev_tip(1005);
    CHECK(ft_ev(u, &e) == GZ_OK);
    memset(&h, 0, sizeof h);
    memcpy(h.scope, SCOPE_A, 32);
    h.n_members = 3; h.acked = acked; h.n_nodes = 5; h.signed_ok = sig;
    h.proposed_tx = prop; h.proposed_len = p.tx_len;
    CHECK(gz_fund_host_h1(&u->f, &h) == 0);
    ft_reset(u);
    CHECK(gz_fund_host_apply(&u->f, SCOPE_A, &u->out) == GZ_OK);
    ft_after(u);
    CHECK(u->f.fac[0].used && u->f.fac[0].deadline == 1036);
    free(u);
}

/* No tip known at the plan or at the outcome: the deadline comes from the
 * first tip, is saved and is kept to. */
static void test_deadline_pending(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
    gz_event_t e;
    host_fund(t, SCOPE_A, 0);
    CHECK(t->f.fac[0].deadline_pending == 1);
    e = ev_tip(2000);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK);
    CHECK(ft_saved_state(t) == GZ_FUND_ST_BROADCAST && t->f.fac[0].deadline == 2036 && !t->f.fac[0].deadline_pending);
    drain(t);
    CHECK(t->h.n == 0);
    e = ev_tip(2036);   /* at the deadline, unburied: not yet */
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 0 && t->f.fac[0].state == GZ_FUND_ST_BROADCAST);
    e = ev_tip(2037);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 1 && t->h.r[0].kind == GZ_FUND_R_ABANDONED);
    free(t);
}

/* The spend-back spends input 0, the input members watch, though input 1 is
 * larger; a refusal of another transaction changes nothing; once the
 * spend-back is mined, no new level and nothing sent again (L10). */
static void test_spend_back_settled(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
    gz_event_t e = ev_tip(3000);
    gz_fund_plan_out_t p;
    gz_fund_factory_t *x;
    uint8_t in0[36], other[32];
    int esc;
    memset(other, 0x97, 32);
    t->w.in1_bigger = 1;
    CHECK(ft_ev(t, &e) == GZ_OK);
    p = host_fund(t, SCOPE_A, 0);
    memcpy(in0, p.tx + 5, 36);
    x = &t->f.fac[0];
    e = ev_spent(in0, p.funding.txid, 0);   /* seen in the mempool */
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tip(3037);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tick();
    CHECK(ft_ev(t, &e) == GZ_OK);
    CHECK(ft_saved_state(t) == GZ_FUND_ST_ABANDONED && ft_count(t, GZ_ACTION_BROADCAST) == 1);
    CHECK(x->sb_index == 0 && t->w.last_sb_index == 0 && t->w.sb_n == 1);
    esc = x->sb_escalated;
    e = ev_bres(other, GZ_BROADCAST_REFUSED);   /* another transaction refused */
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(x->sb_escalated == esc && t->w.sb_n == 1);
    /* The spend-back mined, one confirmation: refused when sent again (its
     * input is spent), then a new tip: nothing. */
    e = ev_spent(in0, x->sb_txid, 1);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_bres(x->sb_txid, GZ_BROADCAST_REFUSED);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_tip(3038);
    CHECK(ft_ev(t, &e) == GZ_OK);
    for (int i = 0; i < 5; i++) {
        e = ev_tick();
        CHECK(ft_ev(t, &e) == GZ_OK && ft_count(t, GZ_ACTION_BROADCAST) == 0 && ft_count(t, GZ_ACTION_SAVE) == 0);
    }
    CHECK(x->sb_escalated == esc && t->w.sb_n == 1 && x->used);
    free(t);
}

/* The wallet signs only a plan it holds, by txid (M4): after a restart it
 * must adopt the plan again; one it refuses is never signed. */
static void test_adopt(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_CONFIRM), *u;
    gz_event_t e = ev_tip(4000);
    uint8_t buf[256];
    CHECK(ft_ev(t, &e) == GZ_OK);
    host_fund(t, SCOPE_A, 0);
    t->w.adopt_refuse = 1;
    u = ft_restart(t);
    CHECK(u->w.held == 1);
    e = cmd_confirm(SCOPE_A, GZ_CMD_FUNDING_CONFIRM, buf, 1);
    CHECK(ft_ev(u, &e) == GZ_OK && result_status(u) == 503 && ft_count(u, GZ_ACTION_BROADCAST) == 0);
    free(u);
    t->w.adopt_refuse = 0;
    u = ft_restart(t);
    e = cmd_confirm(SCOPE_A, GZ_CMD_FUNDING_CONFIRM, buf, 1);
    CHECK(ft_ev(u, &e) == GZ_OK && result_status(u) == 200 && ft_count(u, GZ_ACTION_BROADCAST) == 1);
    free(u);
    free(t);
}

static void test_restart_broadcast(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO), *u;
    gz_event_t e = ev_tip(700);
    gz_fund_plan_out_t p;
    CHECK(ft_ev(t, &e) == GZ_OK);
    p = host_fund(t, SCOPE_A, 0);
    u = ft_restart(t);
    CHECK(u->w.held == 1 && u->h.broadcasts == 1);   /* held again, and sent again */
    CHECK(u->f.fac[0].used && u->f.fac[0].state == GZ_FUND_ST_BROADCAST && u->f.fac[0].signed_len == t->f.fac[0].signed_len);
    CHECK(u->f.n_watches == 2);
    /* A plan whose round crashed: held again, not broadcast. */
    {
        gz_fund_plan_in_t in = plan_in(SCOPE_B, 0);
        gz_fund_plan_out_t r;
        ft_t *v;
        CHECK(gz_fund_host_plan(&u->f, &in, &u->out, &r) == GZ_OK && r.ok);
        ft_after(u);
        v = ft_restart(u);
        CHECK(v->w.held == 2 && v->f.n_watches == 2);
        free(v);
    }
    (void)p;
    free(u);
    free(t);
}

static gz_fund_acked_in_t acked_in(ft_t *t, const uint8_t scope[32], uint8_t tag, uint32_t ack_tip, uint8_t (*fund_tx)[400],
                                   size_t *len)
{
    gz_fund_acked_in_t a;
    ft_in_t ins[2];
    uint64_t amts[2] = { 802811, 5000 };
    uint8_t scr[2][34];
    (void)t;
    memset(&a, 0, sizeof a);
    memcpy(a.scope, scope, 32);
    ft_op(ins[0].op, tag, 0);
    ft_op(ins[1].op, (uint8_t)(tag + 1), 1);
    ft_script(scr[0], 0x77);
    ft_script(scr[1], 0xcc);
    *len = ft_tx(*fund_tx, ins, 2, amts, (const uint8_t(*)[34])scr, 2, 0);
    a.funding_tx = *fund_tx;
    a.funding_tx_len = *len;
    gz_tx_txid(*fund_tx, *len, a.funding.txid);
    a.funding.vout = 0;
    a.amount = 802811;
    memcpy(a.script, scr[0], 34);
    a.ack_tip = ack_tip;
    a.end_height = ack_tip + 180;
    a.own_depth = 2;
    a.whole_tree = 1;
    a.exit = gz_exit_signet();
    a.deadline_blocks = 36;
    return a;
}

static void test_member(void)
{
    ft_t *t = ft_new(0, GZ_HOST_FUNDING_AUTO), *u;
    uint8_t tx[400], tx2[400], tx3[400], op[36], other[32];
    size_t len, len2, len3;
    gz_fund_acked_in_t a = acked_in(t, SCOPE_A, 0x40, 1000, &tx, &len);
    gz_fund_acked_in_t b = acked_in(t, SCOPE_B, 0x50, 1000, &tx2, &len2);
    gz_event_t e;
    uint32_t until;
    memset(other, 0x98, 32);
    ft_reset(t);
    CHECK(gz_fund_member_acked(&t->f, &a, &t->out) == GZ_OK);
    ft_after(t);
    CHECK(ft_count(t, GZ_ACTION_SAVE) == 1 && ft_saved_state(t) == GZ_FUND_ST_ACKED);
    CHECK(ft_count(t, GZ_ACTION_WATCH_TX) == 1 && ft_count(t, GZ_ACTION_WATCH_OUTPOINT) == 2 && t->f.n_watches == 3);
    CHECK(gz_fund_scope_state(&t->f, SCOPE_A, &until) == GZ_FUND_SCOPE_OPEN && until == 1000 + 36 + 3);
    /* Given twice (rule 3): nothing. */
    ft_reset(t);
    CHECK(gz_fund_member_acked(&t->f, &a, &t->out) == GZ_OK && t->out.count == 0);
    ft_reset(t);
    CHECK(gz_fund_member_acked(&t->f, &b, &t->out) == GZ_OK);
    ft_after(t);
    /* A: live on time. */
    e = ev_tip(1005);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_conf(a.funding.txid, 3, 1003);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 1 && t->h.r[0].kind == GZ_FUND_R_LIVE && t->h.r[0].host == 0);
    /* B: its own input spent by the funding itself: not dead. */
    memcpy(op, tx2 + 5, 36);
    e = ev_spent(op, b.funding.txid, 3);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 1);
    /* B abandoned at its deadline. */
    e = ev_tip(1037);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 2 && t->h.r[1].kind == GZ_FUND_R_ABANDONED && t->h.r[1].cancel_reason == 4);
    CHECK(gz_fund_scope_state(&t->f, SCOPE_B, NULL) == GZ_FUND_SCOPE_ABANDONED);
    /* The restart: B stays abandoned and watched; A is live. */
    u = ft_restart(t);
    CHECK(gz_fund_scope_state(&u->f, SCOPE_A, NULL) == GZ_FUND_SCOPE_LIVE);
    CHECK(gz_fund_scope_state(&u->f, SCOPE_B, NULL) == GZ_FUND_SCOPE_ABANDONED && u->f.n_watches == 3);
    free(u);
    /* Buried late with the whole tree and the time check passing: live. */
    e = ev_conf(b.funding.txid, 3, 1040);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 3 && t->h.r[2].kind == GZ_FUND_R_LIVE);
    /* C: an input spent elsewhere and buried: dead. */
    {
        gz_fund_acked_in_t c = acked_in(t, SCOPE_A, 0x60, 1040, &tx3, &len3);
        memset(c.scope, 0xc3, 32);
        ft_reset(t);
        CHECK(gz_fund_member_acked(&t->f, &c, &t->out) == GZ_OK);
        ft_after(t);
        memcpy(op, tx3 + 5 + 41, 36);   /* input 1 */
        e = ev_spent(op, other, 2);
        CHECK(ft_ev(t, &e) == GZ_OK);
        drain(t);
        CHECK(t->h.n == 3);
        e = ev_spent(op, other, 3);
        CHECK(ft_ev(t, &e) == GZ_OK);
        drain(t);
        CHECK(t->h.n == 4 && t->h.r[3].kind == GZ_FUND_R_DEAD);
        CHECK(gz_fund_scope_state(&t->f, c.scope, NULL) == GZ_FUND_SCOPE_DEAD);
    }
    CHECK(t->f.n_watches == 0);
    free(t);
}

static void test_member_late_too_late(void)
{
    ft_t *t = ft_new(0, GZ_HOST_FUNDING_AUTO);
    uint8_t tx[400];
    size_t len;
    gz_fund_acked_in_t a = acked_in(t, SCOPE_A, 0x40, 1000, &tx, &len);
    gz_event_t e;
    a.whole_tree = 0;
    ft_reset(t);
    CHECK(gz_fund_member_acked(&t->f, &a, &t->out) == GZ_OK);
    e = ev_tip(1100);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 1 && t->h.r[0].kind == GZ_FUND_R_ABANDONED);
    /* Buried late without the whole tree: stays abandoned (C11). */
    e = ev_conf(a.funding.txid, 3, 1098);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 1);
    free(t);
}

static void test_member_shared_input(void)
{
    /* Two attempts of one lobby share input 0 (H11): one watch for it. */
    ft_t *t = ft_new(0, GZ_HOST_FUNDING_AUTO);
    uint8_t tx[400], tx2[400];
    size_t len, len2;
    gz_fund_acked_in_t a = acked_in(t, SCOPE_A, 0x40, 1000, &tx, &len);
    gz_fund_acked_in_t b = acked_in(t, SCOPE_A, 0x40, 1000, &tx2, &len2);
    gz_event_t e;
    tx2[5 + 41 + 4] = 0x55;   /* a different input 1: another funding */
    gz_tx_txid(tx2, len2, b.funding.txid);
    ft_reset(t);
    CHECK(gz_fund_member_acked(&t->f, &a, &t->out) == GZ_OK);
    ft_reset(t);
    CHECK(gz_fund_member_acked(&t->f, &b, &t->out) == GZ_OK);
    CHECK(t->f.n_watches == 5);
    /* B's funding buried: B live, A dead (its input 0 spent by B). */
    e = ev_tip(1004);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_conf(b.funding.txid, 3, 1002);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_spent(tx + 5, b.funding.txid, 3);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 2 && t->f.n_watches == 0 && t->h.unwatched == 5);
    free(t);
}

static void test_member_table_full(void)
{
    ft_t *t = ft_new(0, GZ_HOST_FUNDING_AUTO);
    uint8_t tx[400];
    size_t len;
    gz_event_t e;
    for (int i = 0; i < 20; i++) {
        gz_fund_acked_in_t a = acked_in(t, SCOPE_A, (uint8_t)(2 * i + 1), 1000, &tx, &len);
        a.scope[1] = (uint8_t)i;
        ft_reset(t);
        CHECK(gz_fund_member_acked(&t->f, &a, &t->out) == GZ_OK);
        ft_after(t);
        CHECK(t->f.n_watches <= GZ_FUND_MAX_WATCHES);
    }
    CHECK(t->f.untracked == 4);
    {
        uint8_t s[32];
        memcpy(s, SCOPE_A, 32);
        s[1] = 19;
        CHECK(gz_fund_scope_state(&t->f, s, NULL) == GZ_FUND_SCOPE_OPEN);
    }
    e = ev_tip(1037);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 20);
    /* A restart reloads them the same way. */
    {
        ft_t *u = ft_restart(t);
        CHECK(u->f.n_watches <= GZ_FUND_MAX_WATCHES);
        free(u);
    }
    free(t);
}

/* A full table: a new creation takes the place of the oldest Abandoned one,
 * whose watches are given back first. */
static void test_member_evict(void)
{
    ft_t *t = ft_new(0, GZ_HOST_FUNDING_AUTO);
    uint8_t tx[400];
    size_t len;
    gz_event_t e;
    for (int i = 0; i < 16; i++) {
        gz_fund_acked_in_t a = acked_in(t, SCOPE_A, (uint8_t)(2 * i + 1), 1000, &tx, &len);
        a.scope[1] = (uint8_t)i;
        ft_reset(t);
        CHECK(gz_fund_member_acked(&t->f, &a, &t->out) == GZ_OK);
        ft_after(t);
    }
    CHECK(t->f.n_watches == GZ_FUND_MAX_WATCHES);
    e = ev_tip(1037);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 16 && t->f.n_watches == GZ_FUND_MAX_WATCHES);   /* all Abandoned, still watched */
    {
        gz_fund_acked_in_t a = acked_in(t, SCOPE_A, 0x61, 1037, &tx, &len);
        a.scope[1] = 99;
        ft_reset(t);
        CHECK(gz_fund_member_acked(&t->f, &a, &t->out) == GZ_OK);
        ft_after(t);
        CHECK(ft_count(t, GZ_ACTION_UNWATCH) == 3 && ft_count(t, GZ_ACTION_WATCH_TX) == 1);
        CHECK(t->f.n_watches == GZ_FUND_MAX_WATCHES && t->f.untracked == 0);
    }
    free(t);
}

/* A member's own burial depth B, not the host's. */
static void test_member_own_depth(void)
{
    ft_t *t = ft_new(0, GZ_HOST_FUNDING_AUTO);
    uint8_t tx[400];
    size_t len;
    gz_fund_acked_in_t a = acked_in(t, SCOPE_A, 0x40, 1000, &tx, &len);
    const gz_action_t *w;
    gz_event_t e;
    a.exit.B = 6;
    ft_reset(t);
    CHECK(gz_fund_member_acked(&t->f, &a, &t->out) == GZ_OK);
    ft_after(t);
    w = ft_find(t, GZ_ACTION_WATCH_TX);
    CHECK(w && w->u.watch_tx.depth == 6);
    e = ev_tip(1010);
    CHECK(ft_ev(t, &e) == GZ_OK);
    e = ev_conf(a.funding.txid, 3, 1004);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 0);   /* three is not six */
    e = ev_conf(a.funding.txid, 6, 1004);
    CHECK(ft_ev(t, &e) == GZ_OK);
    drain(t);
    CHECK(t->h.n == 1 && t->h.r[0].kind == GZ_FUND_R_LIVE);
    free(t);
}

static void test_corrupt(void)
{
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO);
    gz_batch_id_t b = { 1, 1 };
    gz_record_t r;
    uint8_t buf[256];
    size_t at = 0;
    uint8_t scope[32] = { 1 }, id[32] = { 2 }, st = 4, h[4] = { 0 };
    r.type = 0x00030008u;
    r.bytes.data = buf;
    r.bytes.len = 0;
    CHECK(gz_fund_load(&t->f, &r, b) == GZ_ERR_CORRUPT);    /* a type of the area nobody knows */
    gz_rec_put(buf, sizeof buf, &at, 2, scope, 32);
    gz_rec_put(buf, sizeof buf, &at, 4, id, 32);
    gz_rec_put(buf, sizeof buf, &at, 6, &st, 1);
    gz_rec_put(buf, sizeof buf, &at, 8, h, 4);
    gz_rec_put(buf, sizeof buf, &at, 10, h, 4);
    r.type = GZ_FUND_REC_STATUS;
    r.bytes.len = at;
    CHECK(gz_fund_load(&t->f, &r, b) == GZ_ERR_CORRUPT);    /* a status of nothing planned, on a host */
    gz_rec_put(buf, sizeof buf, &at, 40, h, 4);
    r.bytes.len = at;
    CHECK(gz_fund_load(&t->f, &r, b) == GZ_ERR_CORRUPT);    /* an unknown even field */
    r.bytes.len = 10;
    CHECK(gz_fund_load(&t->f, &r, b) == GZ_ERR_CORRUPT);    /* cut short */
    r.type = GZ_FUND_REC_PLAN;
    CHECK(gz_fund_load(&t->f, &r, b) == GZ_ERR_CORRUPT);
    r.type = GZ_FUND_REC_SIGNED;
    CHECK(gz_fund_load(&t->f, &r, b) == GZ_ERR_CORRUPT);
    free(t);
    /* A member: a status for an unknown creation is history only. */
    t = ft_new(0, GZ_HOST_FUNDING_AUTO);
    r.type = GZ_FUND_REC_STATUS;
    at = 0;
    gz_rec_put(buf, sizeof buf, &at, 2, scope, 32);
    gz_rec_put(buf, sizeof buf, &at, 4, id, 32);
    gz_rec_put(buf, sizeof buf, &at, 6, &st, 1);
    gz_rec_put(buf, sizeof buf, &at, 8, h, 4);
    gz_rec_put(buf, sizeof buf, &at, 10, h, 4);
    r.bytes.len = at;
    CHECK(gz_fund_load(&t->f, &r, b) == GZ_OK);
    CHECK(gz_fund_scope_state(&t->f, scope, NULL) == GZ_FUND_SCOPE_LIVE);
    gz_rec_put(buf, sizeof buf, &at, 40, h, 4);
    r.bytes.len = at;
    CHECK(gz_fund_load(&t->f, &r, b) == GZ_ERR_CORRUPT);    /* an unknown even field */
    st = 9;
    at = 0;
    gz_rec_put(buf, sizeof buf, &at, 2, scope, 32);
    gz_rec_put(buf, sizeof buf, &at, 4, id, 32);
    gz_rec_put(buf, sizeof buf, &at, 6, &st, 1);
    gz_rec_put(buf, sizeof buf, &at, 8, h, 4);
    gz_rec_put(buf, sizeof buf, &at, 10, h, 4);
    r.bytes.len = at;
    CHECK(gz_fund_load(&t->f, &r, b) == GZ_ERR_CORRUPT);
    free(t);
}

static void test_journal_replay_steps(void)
{
    /* An illegal order of statuses in a journal is refused: LIVE then
     * BROADCAST for one funding. */
    ft_t *t = ft_new(1, GZ_HOST_FUNDING_AUTO), *u;
    gz_event_t e = ev_tip(800);
    gz_fund_plan_out_t p;
    gz_batch_id_t b = { 1, 1 };
    CHECK(ft_ev(t, &e) == GZ_OK);
    p = host_fund(t, SCOPE_A, 0);
    (void)p;
    u = ft_new(1, GZ_HOST_FUNDING_AUTO);
    /* plan, signed, status broadcast, then the plan again: refused. */
    for (size_t i = 0; i < t->jn; i++) CHECK(gz_fund_load(&u->f, &t->jrec[i], b) == GZ_OK);
    CHECK(gz_fund_load(&u->f, &t->jrec[0], b) == GZ_ERR_CORRUPT);
    CHECK(gz_fund_load(&u->f, &t->jrec[1], b) == GZ_ERR_CORRUPT);
    {
        uint8_t copy[512];
        gz_record_t r2 = t->jrec[2];
        gz_bytes_t v;
        CHECK(r2.type == GZ_FUND_REC_STATUS && r2.bytes.len <= sizeof copy);
        memcpy(copy, r2.bytes.data, r2.bytes.len);
        r2.bytes.data = copy;
        CHECK(gz_rec_find(r2.bytes, 6, &v) == 1 && v.len == 1 && v.data[0] == GZ_FUND_ST_BROADCAST);
        copy[(size_t)(v.data - copy)] = GZ_FUND_ST_AWAITING;
        CHECK(gz_fund_load(&u->f, &r2, b) == GZ_ERR_CORRUPT);
        copy[(size_t)(v.data - copy)] = GZ_FUND_ST_LIVE;     /* the legal next step loads */
        CHECK(gz_fund_load(&u->f, &r2, b) == GZ_OK);
    }
    {
        /* funding_signed whose bytes are not the plan: refused at load. */
        ft_t *v = ft_new(1, GZ_HOST_FUNDING_AUTO);
        static uint8_t copy[GZ_FUND_MAX_SIGNED + 256];
        gz_record_t r2 = t->jrec[1];
        gz_bytes_t w;
        CHECK(r2.type == GZ_FUND_REC_SIGNED && r2.bytes.len <= sizeof copy);
        memcpy(copy, r2.bytes.data, r2.bytes.len);
        r2.bytes.data = copy;
        CHECK(gz_rec_find(r2.bytes, 6, &w) == 1 && w.len > 60);
        copy[(size_t)(w.data - copy) + 50] ^= 1;   /* a byte of an input's outpoint */
        CHECK(gz_fund_load(&v->f, &t->jrec[0], b) == GZ_OK);
        CHECK(gz_fund_load(&v->f, &r2, b) == GZ_ERR_CORRUPT);
        CHECK(gz_fund_load(&v->f, &t->jrec[1], b) == GZ_OK);   /* the real one loads */
        free(v);
    }
    free(u);
    free(t);
}

static void test_ignored_events(void)
{
    ft_t *t = ft_new(0, GZ_HOST_FUNDING_AUTO);
    gz_event_t e;
    memset(&e, 0, sizeof e);
    e.kind = GZ_EVENT_MESSAGE_RECEIVED;   /* factory_funded: counted, never acted on */
    CHECK(ft_ev(t, &e) == GZ_OK && t->out.count == 0 && t->f.dropped == 1);
    e.kind = GZ_EVENT_TIMER_FIRED;
    e.u.timer.timer_id = 77;
    CHECK(ft_ev(t, &e) == GZ_OK && t->out.count == 0 && t->f.dropped == 2);
    e.kind = GZ_EVENT_STORAGE_CONFIRMED;
    CHECK(ft_ev(t, &e) == GZ_OK && t->out.count == 0);
    CHECK(gz_fund_handle(NULL, &e, &t->out) == GZ_ERR_ARGUMENT);
    free(t);
}

int main(void)
{
    test_fees();
    test_tx_sizes();
    test_init();
    test_auto_live();
    test_plans();
    test_h1();
    test_confirm();
    test_confirm_deadline();
    test_abandon_replace();
    test_abandon_unseen_then_late();
    test_host_dead_and_reorg();
    test_wallet_checked();
    test_must_kept();
    test_deadline_basis();
    test_deadline_after_restart();
    test_deadline_pending();
    test_spend_back_settled();
    test_adopt();
    test_restart_broadcast();
    test_member();
    test_member_late_too_late();
    test_member_shared_input();
    test_member_table_full();
    test_member_evict();
    test_member_own_depth();
    test_corrupt();
    test_journal_replay_steps();
    test_ignored_events();
    if (g_fail) {
        fprintf(stderr, "%d failed\n", g_fail);
        return 1;
    }
    printf("funding: all passed\n");
    return 0;
}
