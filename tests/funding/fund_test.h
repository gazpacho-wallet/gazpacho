/* Shared test harness for the funding engine: a fake wallet port, fake
 * hooks, transactions built byte by byte, event makers and an action list
 * that checks the engine's declared worst step. */
#ifndef FUND_TEST_H
#define FUND_TEST_H

#include "gazpacho/funding.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

/* ---- transactions ------------------------------------------------------- */

typedef struct {
    uint8_t op[36];
    uint64_t amount;
} ft_in_t;

static inline size_t ft_put_cs(uint8_t *p, uint64_t v)
{
    if (v < 0xfd) { p[0] = (uint8_t)v; return 1; }
    p[0] = 0xfd; p[1] = (uint8_t)v; p[2] = (uint8_t)(v >> 8); return 3;
}
static inline void ft_le32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static inline void ft_le64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }

/* outs: n_out (amount, 34-byte script) pairs. witness: 0 none, else a
 * 64-byte item per input. */
static inline size_t ft_tx(uint8_t *out, const ft_in_t *ins, size_t n_in, const uint64_t *amts,
                    const uint8_t (*scripts)[34], size_t n_out, int witness)
{
    size_t at = 0;
    ft_le32(out, 2); at = 4;
    if (witness) { out[at++] = 0; out[at++] = 1; }
    at += ft_put_cs(out + at, n_in);
    for (size_t i = 0; i < n_in; i++) {
        memcpy(out + at, ins[i].op, 36); at += 36;
        out[at++] = 0;
        ft_le32(out + at, 0xfffffffeu); at += 4;
    }
    at += ft_put_cs(out + at, n_out);
    for (size_t i = 0; i < n_out; i++) {
        ft_le64(out + at, amts[i]); at += 8;
        out[at++] = 34;
        memcpy(out + at, scripts[i], 34); at += 34;
    }
    if (witness)
        for (size_t i = 0; i < n_in; i++) {
            out[at++] = 1; out[at++] = 64;
            memset(out + at, 0xa5, 64); at += 64;
        }
    ft_le32(out + at, 0); at += 4;
    return at;
}

static inline void ft_script(uint8_t s[34], uint8_t tag) { s[0] = 0x51; s[1] = 0x20; memset(s + 2, tag, 32); }
static inline void ft_op(uint8_t op[36], uint8_t tag, uint32_t vout) { memset(op, tag, 32); ft_le32(op + 32, vout); }

/* ---- the fake wallet ---------------------------------------------------- */

/* A plan the fake wallet holds, by txid (it signs only these). */
#define FT_PLANS 24
typedef struct {
    int used;
    size_t len;
    uint8_t txid[32];
    uint8_t tx[GZ_FUND_MAX_TX];
} ft_plan_t;

typedef struct {
    int fail_plan, fail_sign, fail_sb, ignore_must, bad_signed, extra_output, legacy_prev, n_in;
    uint64_t in_amount;
    uint8_t next_tag;
    int planned, held, released, signed_n, sb_n;
    uint64_t last_sb_fee;
    size_t oversize;          /* plan this many inputs regardless (the 8,192-byte cap) */
    int sb_other_input, sb_to_factory, sb_fee_off, extra_prev, empty_wit, tiny_prev;   /* faults the engine must refuse */
    int no_change, third_output, must_at_1, in1_bigger, adopt_refuse, factory_twice;
    int sb_two_outputs, zero_prev, scriptsig, factory_at_1;   /* more faults the engine must refuse */
    uint32_t last_sb_index;
    unsigned next_plan;
    ft_plan_t plans[FT_PLANS];   /* memory only: a restart forgets them */
} ft_wallet_t;

static inline void ftw_keep(ft_wallet_t *w, const uint8_t *tx, size_t len)
{
    ft_plan_t *p = &w->plans[w->next_plan++ % FT_PLANS];
    if (len > sizeof p->tx) return;
    memcpy(p->tx, tx, len);
    p->len = len;
    gz_tx_txid(tx, len, p->txid);
    p->used = 1;
}

static inline ft_plan_t *ftw_find(ft_wallet_t *w, const uint8_t txid[32])
{
    for (size_t i = 0; i < FT_PLANS; i++)
        if (w->plans[i].used && memcmp(w->plans[i].txid, txid, 32) == 0) return &w->plans[i];
    return NULL;
}

static inline int ftw_plan(void *ctx, uint64_t amount, const uint8_t script[34], uint64_t feerate, const gz_outpoint_t *must,
                    uint8_t *tx, size_t cap, size_t *tx_len, gz_fund_prevout_t *prev, size_t max_prev, size_t *n_prev)
{
    ft_wallet_t *w = (ft_wallet_t *)ctx;
    ft_in_t ins[300];
    uint64_t amts[3];
    uint8_t scr[3][34];
    size_t n = w->oversize ? w->oversize : (size_t)(w->n_in ? w->n_in : 2), nout = 2;
    uint64_t sum = 0;
    (void)feerate;
    if (w->fail_plan || n > 300 || n > max_prev) return 0;
    for (size_t i = 0; i < n; i++) {
        ft_op(ins[i].op, (uint8_t)(0x10 + w->next_tag), (uint32_t)i);
        ins[i].amount = (w->in_amount ? w->in_amount : 600000) + (w->in1_bigger && i == 1 ? 100000 : 0);
        sum += ins[i].amount;
    }
    w->next_tag++;
    if (must && !w->ignore_must) {
        size_t k = w->must_at_1 && n > 1 ? 1 : 0;   /* must_at_1: the coin not at input 0 */
        memcpy(ins[k].op, must->txid, 32);
        ft_le32(ins[k].op + 32, must->vout);
    }
    amts[0] = amount;
    memcpy(scr[0], script, 34);
    amts[1] = sum - amount - 200;
    ft_script(scr[1], 0xcc);   /* the wallet's change */
    if (w->third_output) { amts[1] -= 1000; amts[2] = 1000; ft_script(scr[2], 0xcd); nout = 3; }
    if (w->extra_output) { amts[2] = amount; memcpy(scr[2], script, 34); nout = 3; }
    if (w->no_change) nout = 1;
    if (w->factory_at_1) {   /* the change first, the factory's output second */
        uint64_t a0 = amts[0];
        uint8_t s0[34];
        memcpy(s0, scr[0], 34);
        amts[0] = amts[1];
        memcpy(scr[0], scr[1], 34);
        amts[1] = a0;
        memcpy(scr[1], s0, 34);
    }
    if (w->factory_twice) { amts[1] = amount; memcpy(scr[1], script, 34); }   /* two outputs, both the factory's */
    if (cap < 10 + n * 41 + nout * 43 + 8) return 0;
    *tx_len = ft_tx(tx, ins, n, amts, (const uint8_t(*)[34])scr, nout, 0);
    if (w->scriptsig && *tx_len + 1 <= cap) {   /* input 0 with a one-byte scriptSig */
        size_t at = 5 + 36;
        memmove(tx + at + 2, tx + at + 1, *tx_len - at - 1);
        tx[at] = 1;
        tx[at + 1] = 0x51;
        (*tx_len)++;
    }
    for (size_t i = 0; i < n; i++) {
        prev[i].amount = ins[i].amount;
        prev[i].script_len = 34;
        ft_script(prev[i].script, 0xdd);
        if (w->legacy_prev && i == 1) { prev[i].script_len = 25; prev[i].script[0] = 0x76; }
        if (w->zero_prev && i == 1) prev[i].amount = 0;
        if (w->tiny_prev && i == 1) {   /* OP_1 and a 0- or 1-byte program */
            prev[i].script_len = (uint8_t)(1 + w->tiny_prev);
            prev[i].script[0] = 0x51;
            prev[i].script[1] = (uint8_t)(w->tiny_prev - 1);
        }
    }
    if (w->extra_prev && n < max_prev) {   /* one spent output more than the inputs */
        prev[n] = prev[0];
        n++;
    }
    *n_prev = n;
    w->planned++;
    ftw_keep(w, tx, *tx_len);
    return 1;
}

/* Re-adds witnesses to an unsigned transaction (the shape ft_tx makes). */
static inline size_t ft_sign_bytes(const uint8_t *tx, size_t len, uint8_t *out)
{
    /* version, marker, flag, body without lock time, witnesses, lock time */
    size_t n_in = tx[4], at;
    memcpy(out, tx, 4);
    out[4] = 0; out[5] = 1;
    memcpy(out + 6, tx + 4, len - 8);
    at = 6 + len - 8;
    for (size_t i = 0; i < n_in; i++) { out[at++] = 1; out[at++] = 64; memset(out + at, 0x5a, 64); at += 64; }
    memcpy(out + at, tx + len - 4, 4);
    return at + 4;
}

/* The same, with input 0's witness left empty (no items). */
static inline size_t ft_sign_empty0(const uint8_t *tx, size_t len, uint8_t *out)
{
    size_t n_in = tx[4], at;
    memcpy(out, tx, 4);
    out[4] = 0; out[5] = 1;
    memcpy(out + 6, tx + 4, len - 8);
    at = 6 + len - 8;
    for (size_t i = 0; i < n_in; i++) {
        if (i == 0) { out[at++] = 0; continue; }
        out[at++] = 1; out[at++] = 64; memset(out + at, 0x5a, 64); at += 64;
    }
    memcpy(out + at, tx + len - 4, 4);
    return at + 4;
}

static inline int ftw_sign_plan(void *ctx, const uint8_t txid[32], uint8_t *out, size_t cap, size_t *out_len)
{
    ft_wallet_t *w = (ft_wallet_t *)ctx;
    ft_plan_t *p = ftw_find(w, txid);
    if (w->fail_sign || !p || cap < p->len + 2 + 66 * 200 || p->tx[4] >= 0xfd) return 0;
    *out_len = w->empty_wit ? ft_sign_empty0(p->tx, p->len, out) : ft_sign_bytes(p->tx, p->len, out);
    if (w->bad_signed) out[10] ^= 1;
    w->signed_n++;
    return 1;
}

/* Holds a plan again after a restart, if its outputs are the factory's and
 * this wallet's change (script 0xcc) only. */
static inline int ftw_adopt(void *ctx, const uint8_t *tx, size_t len, const uint8_t script[34], uint64_t amount)
{
    ft_wallet_t *w = (ft_wallet_t *)ctx;
    gz_tx_info_t info;
    uint64_t amt;
    const uint8_t *scr;
    size_t sl;
    w->held++;
    if (w->adopt_refuse || len > GZ_FUND_MAX_TX || !gz_tx_parse(tx, len, &info) || info.n_out != 2) return 0;
    /* Output 0 the factory's, exactly; output 1 this wallet's change. */
    if (!gz_tx_output(tx, len, &info, 0, &amt, &scr, &sl) || sl != 34 || amt != amount || memcmp(scr, script, 34) != 0)
        return 0;
    if (!gz_tx_output(tx, len, &info, 1, &amt, &scr, &sl) || sl != 34 || scr[2] != 0xcc) return 0;
    ftw_keep(w, tx, len);
    return 1;
}

static inline void ftw_release(void *ctx, const uint8_t *tx, size_t len)
{
    ft_wallet_t *w = (ft_wallet_t *)ctx;
    uint8_t id[32];
    ft_plan_t *p;
    w->released++;
    if (len > GZ_FUND_MAX_TX) return;
    gz_tx_txid(tx, len, id);
    if ((p = ftw_find(w, id)) != NULL) p->used = 0;
}

/* The spend-back of a plan this wallet holds, by its txid. */
static inline int ftw_sb(void *ctx, const uint8_t txid[32], uint32_t index, uint64_t fee, uint8_t *out, size_t cap,
                  size_t *out_len)
{
    ft_wallet_t *w = (ft_wallet_t *)ctx;
    ft_plan_t *p = ftw_find(w, txid);
    ft_in_t in;
    uint64_t amt, amts[2];
    uint8_t scr[2][34];
    size_t at = 5 + 41 * (size_t)index;   /* inputs are 41 bytes: 36 + 1 + 4 */
    const uint8_t *tx;
    if (w->fail_sb || !p || cap < 200 || at + 36 > p->len) return 0;
    tx = p->tx;
    w->last_sb_index = index;
    memcpy(in.op, tx + at, 36);
    if (w->sb_other_input) in.op[35] ^= 0x40;            /* another outpoint */
    amt = (w->in_amount ? w->in_amount : 600000) - fee - (w->sb_fee_off ? 1 : 0);
    ft_script(scr[0], w->sb_to_factory ? 0x77 : 0xee);   /* 0x77: the factory's script in these tests */
    if (w->sb_two_outputs) {   /* a second output nobody asked for */
        amts[0] = amt;   /* output 0 as asked; the second output on top */
        amts[1] = 1000;
        memcpy(scr[1], scr[0], 34);
        *out_len = ft_tx(out, &in, 1, amts, (const uint8_t(*)[34])scr, 2, 1);
    } else {
        *out_len = ft_tx(out, &in, 1, &amt, (const uint8_t(*)[34])scr, 1, 1);
    }
    w->sb_n++;
    w->last_sb_fee = fee;
    return 1;
}

/* ---- hooks -------------------------------------------------------------- */

typedef struct {
    gz_fund_report_t r[256];
    size_t n;
    int unwatched;
    int broadcasts;           /* BROADCAST actions seen by ft_after */
    gz_status_t ret;
} ft_hooks_t;

static inline gz_status_t fth_report(void *ctx, const gz_fund_report_t *r, gz_action_list_t *out)
{
    ft_hooks_t *h = (ft_hooks_t *)ctx;
    (void)out;
    if (h->n < 256) h->r[h->n++] = *r;
    return h->ret;
}

static inline void ft_rand(void *ctx, gz_random_purpose_t p, uint8_t *out, size_t len) { (void)ctx; (void)p; memset(out, 7, len); }
static inline uint64_t ft_now(void *ctx) { (void)ctx; return 1000; }

typedef struct {
    gz_fund_t f;
    ft_wallet_t w;
    ft_hooks_t h;
    gz_fund_config_t cfg;
    gz_action_t slots[64];
    uint8_t bytes[GZ_FUND_MAX_STEP_BYTES + 4096];
    gz_action_list_t out;
    int lag;                  /* 0: the chain view answers every tip at once (TIP_SYNCED after each
                                 NEW_TIP); 1: a test sends TIP_SYNCED itself */
    /* every saved record, for a restart */
    uint8_t jbuf[1 << 22];
    size_t jat;
    gz_record_t jrec[4096];
    size_t jn;
} ft_t;

static inline void ft_cfg(ft_t *t, int host, gz_host_funding_t mode)
{
    gz_fund_config_default(&t->cfg, host);
    t->cfg.mode = mode;
    t->cfg.hooks.ctx = &t->h;
    t->cfg.hooks.report = fth_report;
    if (host) {
        t->cfg.wallet.ctx = &t->w;
        t->cfg.wallet.plan = ftw_plan;
        t->cfg.wallet.sign_plan = ftw_sign_plan;
        t->cfg.wallet.adopt = ftw_adopt;
        t->cfg.wallet.release = ftw_release;
        t->cfg.wallet.spend_back = ftw_sb;
    }
}

static inline gz_ports_t ft_ports(void)
{
    gz_ports_t p;
    memset(&p, 0, sizeof p);
    p.random.fill = ft_rand;
    p.clock.now_ms = ft_now;
    p.clock.mono_ms = ft_now;
    return p;
}

static inline ft_t *ft_new(int host, gz_host_funding_t mode)
{
    ft_t *t = (ft_t *)calloc(1, sizeof *t);
    gz_ports_t p = ft_ports();
    if (!t) exit(2);
    ft_cfg(t, host, mode);
    if (gz_fund_init(&t->f, &t->cfg, &p) != GZ_OK) exit(3);
    gz_action_list_init(&t->out, t->slots, 64, t->bytes, sizeof t->bytes);
    return t;
}

/* Keeps every SAVE's records (the journal) and checks the step's bounds. */
static inline void ft_after(ft_t *t)
{
    CHECK(t->out.count <= GZ_FUND_MAX_STEP_ACTIONS);
    CHECK(t->out.used <= GZ_FUND_MAX_STEP_BYTES);
    for (size_t i = 0; i < t->out.count; i++) t->h.unwatched += t->out.slots[i].kind == GZ_ACTION_UNWATCH;
    for (size_t i = 0; i < t->out.count; i++) t->h.broadcasts += t->out.slots[i].kind == GZ_ACTION_BROADCAST;
    for (size_t i = 0; i < t->out.count; i++) {
        const gz_action_t *a = &t->out.slots[i];
        if (a->kind != GZ_ACTION_SAVE) continue;
        for (size_t k = 0; k < a->u.save.n_records; k++) {
            const gz_record_t *r = &a->u.save.records[k];
            if (t->jn == 4096 || t->jat + r->bytes.len > sizeof t->jbuf) exit(4);
            memcpy(t->jbuf + t->jat, r->bytes.data, r->bytes.len);
            t->jrec[t->jn].type = r->type;
            t->jrec[t->jn].bytes.data = t->jbuf + t->jat;
            t->jrec[t->jn].bytes.len = r->bytes.len;
            t->jat += r->bytes.len;
            t->jn++;
        }
    }
}

static inline void ft_reset(ft_t *t) { gz_action_list_reset(&t->out); }

static inline gz_status_t ft_ev(ft_t *t, const gz_event_t *ev)
{
    gz_status_t st;
    ft_reset(t);
    st = gz_fund_handle(&t->f, ev, &t->out);
    if (st == GZ_OK && !t->lag && ev->kind == GZ_EVENT_CHAIN && ev->u.chain.kind == GZ_CHAIN_NEW_TIP) {
        gz_event_t s;
        memset(&s, 0, sizeof s);
        s.kind = GZ_EVENT_CHAIN;
        s.u.chain.kind = GZ_CHAIN_TIP_SYNCED;
        s.u.chain.height = ev->u.chain.height;
        memcpy(s.u.chain.block_hash, ev->u.chain.block_hash, 32);
        st = gz_fund_handle(&t->f, &s, &t->out);
    }
    ft_after(t);
    return st;
}

static inline gz_event_t ev_tip(uint32_t h)
{
    gz_event_t e;
    memset(&e, 0, sizeof e);
    e.kind = GZ_EVENT_CHAIN;
    e.u.chain.kind = GZ_CHAIN_NEW_TIP;
    e.u.chain.height = h;
    return e;
}
static inline gz_event_t ev_tick(void)
{
    gz_event_t e;
    memset(&e, 0, sizeof e);
    e.kind = GZ_EVENT_TIMER_FIRED;
    e.u.timer.timer_id = GZ_FUND_TIMER_TICK;
    return e;
}
static inline gz_event_t ev_conf(const uint8_t txid[32], uint32_t c, uint32_t h)
{
    gz_event_t e;
    memset(&e, 0, sizeof e);
    e.kind = GZ_EVENT_CHAIN;
    e.u.chain.kind = c ? GZ_CHAIN_TX_CONFIRMED : GZ_CHAIN_TX_UNCONFIRMED;
    memcpy(e.u.chain.txid, txid, 32);
    e.u.chain.confirmations = c;
    e.u.chain.height = h;
    return e;
}
static inline gz_event_t ev_spent(const uint8_t op[36], const uint8_t spender[32], uint32_t c)
{
    gz_event_t e;
    memset(&e, 0, sizeof e);
    e.kind = GZ_EVENT_CHAIN;
    e.u.chain.kind = GZ_CHAIN_OUTPOINT_SPENT;
    memcpy(e.u.chain.outpoint.txid, op, 32);
    e.u.chain.outpoint.vout = (uint32_t)op[32] | (uint32_t)op[33] << 8;
    memcpy(e.u.chain.txid, spender, 32);
    e.u.chain.confirmations = c;
    return e;
}
/* The chain view has answered a watch (GZ_CHAIN_WATCH_SYNCED). */
static inline gz_event_t ev_synced_tx(const uint8_t txid[32])
{
    gz_event_t e;
    memset(&e, 0, sizeof e);
    e.kind = GZ_EVENT_CHAIN;
    e.u.chain.kind = GZ_CHAIN_WATCH_SYNCED;
    e.u.chain.is_tx = 1;
    memcpy(e.u.chain.txid, txid, 32);
    return e;
}
static inline gz_event_t ev_synced_op(const uint8_t op[36])
{
    gz_event_t e;
    memset(&e, 0, sizeof e);
    e.kind = GZ_EVENT_CHAIN;
    e.u.chain.kind = GZ_CHAIN_WATCH_SYNCED;
    memcpy(e.u.chain.outpoint.txid, op, 32);
    e.u.chain.outpoint.vout = (uint32_t)op[32] | (uint32_t)op[33] << 8;
    return e;
}
static inline gz_event_t ev_tip_synced(uint32_t h)
{
    gz_event_t e;
    memset(&e, 0, sizeof e);
    e.kind = GZ_EVENT_CHAIN;
    e.u.chain.kind = GZ_CHAIN_TIP_SYNCED;
    e.u.chain.height = h;
    return e;
}
/* The chain view can never answer a watch (GZ_CHAIN_WATCH_FAILED, G-1). */
static inline gz_event_t ev_failed_tx(const uint8_t txid[32])
{
    gz_event_t e = ev_synced_tx(txid);
    e.u.chain.kind = GZ_CHAIN_WATCH_FAILED;
    return e;
}
static inline gz_event_t ev_failed_op(const uint8_t op[36])
{
    gz_event_t e = ev_synced_op(op);
    e.u.chain.kind = GZ_CHAIN_WATCH_FAILED;
    return e;
}
static inline gz_event_t ev_bres(const uint8_t txid[32], gz_broadcast_outcome_t o)
{
    gz_event_t e;
    memset(&e, 0, sizeof e);
    e.kind = GZ_EVENT_CHAIN;
    e.u.chain.kind = GZ_CHAIN_BROADCAST_RESULT;
    memcpy(e.u.chain.txid, txid, 32);
    e.u.chain.outcome = o;
    return e;
}

static inline size_t ft_count(const ft_t *t, gz_action_kind_t k)
{
    size_t n = 0;
    for (size_t i = 0; i < t->out.count; i++) n += t->out.slots[i].kind == k;
    return n;
}
static inline const gz_action_t *ft_find(const ft_t *t, gz_action_kind_t k)
{
    for (size_t i = 0; i < t->out.count; i++)
        if (t->out.slots[i].kind == k) return &t->out.slots[i];
    return NULL;
}
/* The state field of the last funding_status saved in this step, or -1. */
static inline int ft_saved_state(const ft_t *t)
{
    int st = -1;
    for (size_t i = 0; i < t->out.count; i++) {
        const gz_action_t *a = &t->out.slots[i];
        if (a->kind != GZ_ACTION_SAVE) continue;
        for (size_t k = 0; k < a->u.save.n_records; k++) {
            gz_bytes_t v;
            if (a->u.save.records[k].type == GZ_FUND_REC_STATUS && gz_rec_find(a->u.save.records[k].bytes, 6, &v) == 1 &&
                v.len == 1)
                st = v.data[0];
        }
    }
    return st;
}
/* Saves come before every outward action in a step. */
static inline int ft_saves_first(const ft_t *t)
{
    int outward = 0;
    for (size_t i = 0; i < t->out.count; i++) {
        if (gz_action_is_outward(&t->out.slots[i])) outward = 1;
        else if (t->out.slots[i].kind == GZ_ACTION_SAVE && outward) return 0;
    }
    return 1;
}

/* A fresh engine loaded from t's journal, resumed to the end. */
static inline ft_t *ft_restart(ft_t *t)
{
    ft_t *u = ft_new(t->cfg.host, t->cfg.mode);
    gz_batch_id_t b = { 1, 1 };
    int more = 1;
    u->w = t->w;
    u->w.held = 0;
    memset(u->w.plans, 0, sizeof u->w.plans);   /* the wallet's holds are memory only */
    for (size_t i = 0; i < t->jn; i++) {
        gz_status_t st = gz_fund_load(&u->f, &t->jrec[i], b);
        if (st != GZ_OK) {
            gz_bytes_t v;
            int state = gz_rec_find(t->jrec[i].bytes, 6, &v) == 1 && v.len == 1 ? v.data[0] : -1;
            fprintf(stderr, "restart: record %zu of %zu, type %08x, state %d, host %d: %d\n", i, t->jn,
                    (unsigned)t->jrec[i].type, state, t->cfg.host, (int)st);
            for (size_t k = 0; k <= i; k++) {
                gz_bytes_t w, sc;
                int sk = gz_rec_find(t->jrec[k].bytes, 6, &w) == 1 && w.len == 1 ? w.data[0] : -1;
                gz_rec_find(t->jrec[k].bytes, 2, &sc);
                gz_rec_find(t->jrec[k].bytes, 4, &w);
                fprintf(stderr, "  %zu: %08x scope %02x id %02x%02x state %d len %zu\n", k, (unsigned)t->jrec[k].type,
                        sc.len ? sc.data[0] : 0, w.len > 1 ? w.data[0] : 0, w.len > 1 ? w.data[1] : 0, sk,
                        t->jrec[k].bytes.len);
            }
            exit(1);
        }
        CHECK(st == GZ_OK);
    }
    memcpy(u->jbuf, t->jbuf, t->jat);
    for (size_t i = 0; i < t->jn; i++) {
        u->jrec[i] = t->jrec[i];
        u->jrec[i].bytes.data = u->jbuf + (t->jrec[i].bytes.data - t->jbuf);
    }
    u->jat = t->jat;
    u->jn = t->jn;
    u->out.count = 0;
    while (more) {
        ft_reset(u);
        CHECK(gz_fund_resume(&u->f, &u->out, &more) == GZ_OK);
        ft_after(u);
        if (more && u->out.count == 0) break;
    }
    return u;
}

#endif
