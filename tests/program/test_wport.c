/* SPDX-License-Identifier: MIT */
/* The program's wallet port for the funding engine (program/wport.c), on
 * the real wallet code (review of PR 80, N-1): a plan's holds survive a new
 * coin list, coins in the mempool and change not yet buried are not
 * offered, and can_plan answers what plan does, with the same fee policy.
 *
 * THE KEYS HERE ARE TEST KEYS. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <secp256k1.h>

#include "wport.h"

static int failures, checks;
#define CHECK(c)                                                                         \
    do {                                                                                 \
        checks++;                                                                        \
        if (!(c)) {                                                                      \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c);       \
            failures++;                                                                  \
        }                                                                                \
    } while (0)

static int seed_of(void *ctx, uint8_t out64[64])
{
    (void)ctx;
    memset(out64, 0x42, 64);
    return 0;
}

static secp256k1_context *secp;
static uint8_t factory[34];

static void open_b(gzp_wport_t *w, uint32_t burial)
{
    gzp_unlock_t u;
    memset(&u, 0, sizeof u);
    u.seed = seed_of;
    CHECK(gzp_wport_open(w, secp, &u, GZW_NET_SIGNET, burial) == 0);
}

static void open_w(gzp_wport_t *w)
{
    open_b(w, 0);   /* the engine's default B */
}

static gzt_coin coin(gzp_wport_t *w, uint32_t change, uint32_t j, uint64_t amount, uint8_t tag)
{
    gzt_coin c;
    gzw_bip86_output o;
    gzw_reason why;
    memset(&c, 0, sizeof c);
    CHECK(gzw_bip86_output_from_master(secp, &w->master, GZW_NET_SIGNET, 0, change, j, &o, &why) == 1);
    memset(c.txid, tag, 32);
    c.vout = 0;
    c.amount = amount;
    c.change = change;
    c.index = j;
    memcpy(c.script, o.script_pubkey, 34);
    return c;
}

static int plan(gzp_wport_t *w, uint64_t amount, uint8_t *tx, size_t *len)
{
    gz_fund_prevout_t prev[GZ_FUND_MAX_INPUTS];
    size_t n_prev = 0;
    return w->port.plan(w->port.ctx, amount, factory, 100, NULL, tx, GZ_FUND_MAX_TX, len, prev, GZ_FUND_MAX_INPUTS,
                        &n_prev);
}

static int held_by_txid_tag(const gzp_wport_t *w, uint8_t tag)
{
    for (size_t i = 0; i < w->n_coins; i++)
        if (w->coins[i].txid[0] == tag) return w->held[i];
    return -1;
}

static void test_can_plan_before_and_after(void)
{
    gzp_wport_t w;
    gzt_coin cs[2];
    uint32_t hs[2] = {100, 100};
    uint64_t have = 1;
    size_t n = 1;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    open_w(&w);
    /* no coin list yet: cannot tell */
    CHECK(w.port.can_plan(w.port.ctx, 300000, 100, &have, &n) == -1);
    cs[0] = coin(&w, 0, 0, 500000, 0xa1);
    cs[1] = coin(&w, 0, 1, 400000, 0xa2);
    CHECK(gzp_wport_publish(&w, cs, hs, 2, 110) == 0);
    CHECK(w.port.can_plan(w.port.ctx, 300000, 100, &have, &n) == 1);
    CHECK(have == 900000 && n == 2);
    CHECK(w.port.can_plan(w.port.ctx, 900000, 100, &have, &n) == 0);   /* no room for fee and change */
    /* and the plan agrees */
    CHECK(plan(&w, 300000, tx, &len) == 1);
    gzp_wport_close(&w);
}

/* can_plan at the very edge plan finds: the same coins, the same fee policy */
static void test_can_plan_agrees_with_plan(void)
{
    gzp_wport_t w;
    gzt_coin c;
    uint32_t h = 100;
    uint64_t have, lo = 100000, hi = 300000;
    size_t n, len;
    uint8_t tx[GZ_FUND_MAX_TX];
    open_w(&w);
    c = coin(&w, 0, 0, 300000, 0xb1);
    CHECK(gzp_wport_publish(&w, &c, &h, 1, 110) == 0);
    /* the largest amount plan accepts, by bisection, releasing each plan */
    while (lo + 1 < hi) {
        uint64_t mid = (lo + hi) / 2;
        if (plan(&w, mid, tx, &len) == 1) {
            lo = mid;
            w.port.release(w.port.ctx, tx, len);
        } else {
            hi = mid;
        }
    }
    CHECK(w.port.can_plan(w.port.ctx, lo, 100, &have, &n) == 1);
    CHECK(w.port.can_plan(w.port.ctx, lo + 1, 100, &have, &n) == 0);
    CHECK(plan(&w, lo + 1, tx, &len) == 0);
    gzp_wport_close(&w);
}

/* a plan's holds survive a new coin list */
static void test_holds_across_publish(void)
{
    gzp_wport_t w;
    gzt_coin cs[3];
    uint32_t hs[3] = {100, 100, 100};
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    uint64_t have;
    size_t n;
    open_w(&w);
    cs[0] = coin(&w, 0, 0, 500000, 0xc1);
    cs[1] = coin(&w, 0, 1, 400000, 0xc2);
    CHECK(gzp_wport_publish(&w, cs, hs, 2, 110) == 0);
    CHECK(plan(&w, 600000, tx, &len) == 1);          /* takes both */
    CHECK(held_by_txid_tag(&w, 0xc1) > 0 && held_by_txid_tag(&w, 0xc2) > 0);
    /* the scan publishes again, with one coin more */
    cs[2] = coin(&w, 0, 2, 300000, 0xc3);
    CHECK(gzp_wport_publish(&w, cs, hs, 3, 111) == 0);
    CHECK(held_by_txid_tag(&w, 0xc1) > 0 && held_by_txid_tag(&w, 0xc2) > 0);
    CHECK(held_by_txid_tag(&w, 0xc3) == 0);
    /* so only the new coin is offered */
    CHECK(w.port.can_plan(w.port.ctx, 200000, 100, &have, &n) == 1 && have == 300000 && n == 1);
    CHECK(w.port.can_plan(w.port.ctx, 350000, 100, &have, &n) == 0);
    gzp_wport_close(&w);
}

/* coins in the mempool are not offered; change counts only once buried */
static void test_unconfirmed_and_unburied(void)
{
    gzp_wport_t w;
    gzt_coin cs[4];
    uint32_t hs[4];
    uint64_t have;
    size_t n;
    open_w(&w);
    cs[0] = coin(&w, 0, 0, 100000, 0xd1);   hs[0] = 100;   /* confirmed, receive: offered */
    cs[1] = coin(&w, 0, 1, 200000, 0xd2);   hs[1] = 0;     /* in the mempool: not */
    cs[2] = coin(&w, 1, 0, 300000, 0xd3);   hs[2] = 109;   /* change, 2 deep at 110: not */
    cs[3] = coin(&w, 1, 1, 400000, 0xd4);   hs[3] = 108;   /* change, 3 deep at 110: offered */
    CHECK(gzp_wport_publish(&w, cs, hs, 4, 110) == 0);
    CHECK(w.n_coins == 2);
    CHECK(w.port.can_plan(w.port.ctx, 50000, 100, &have, &n) == 1 && have == 500000 && n == 2);
    /* a block later, the 2-deep change is buried too */
    CHECK(gzp_wport_publish(&w, cs, hs, 4, 111) == 0);
    CHECK(w.n_coins == 3);
    gzp_wport_close(&w);
}

/* B as the node is given it: 0 is the engine's default, any other value is used */
static void test_burial_from_config(void)
{
    gzp_wport_t w;
    gz_fund_config_t fc;
    gzt_coin cs[2];
    uint32_t hs[2] = {108, 106};   /* change, 3 and 5 deep at 110 */
    gz_fund_config_default(&fc, 1);
    open_b(&w, 0);
    CHECK(w.burial == fc.burial);
    gzp_wport_close(&w);
    open_b(&w, 5);
    cs[0] = coin(&w, 1, 0, 300000, 0xe1);
    cs[1] = coin(&w, 1, 1, 400000, 0xe2);
    CHECK(gzp_wport_publish(&w, cs, hs, 2, 110) == 0);
    CHECK(w.n_coins == 1 && w.coins[0].txid[0] == 0xe2);   /* 3 deep is not buried at B = 5 */
    gzp_wport_close(&w);
    open_b(&w, 2);
    hs[0] = 109;                                            /* 2 deep: buried at B = 2 */
    CHECK(gzp_wport_publish(&w, cs, hs, 2, 110) == 0);
    CHECK(w.n_coins == 2);
    gzp_wport_close(&w);
}

/* L-1 (review B of PR 83): a hold belongs to the plan, not to the coin list. A
 * list that misses the held coin (one lookup failed), then a list with it again:
 * the coin is still held, and never offered to a second plan. */
static void test_hold_survives_a_gap(void)
{
    gzp_wport_t w;
    gzt_coin cs[2];
    uint32_t hs[2] = {100, 100};
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len, n;
    uint64_t have;
    open_w(&w);
    cs[0] = coin(&w, 0, 0, 500000, 0xf1);
    cs[1] = coin(&w, 0, 1, 400000, 0xf2);
    CHECK(gzp_wport_publish(&w, cs, hs, 1, 110) == 0);         /* f1 only */
    CHECK(plan(&w, 300000, tx, &len) == 1);
    CHECK(held_by_txid_tag(&w, 0xf1) > 0);
    CHECK(gzp_wport_publish(&w, cs + 1, hs, 1, 111) == 0);     /* f2 only: f1 missed */
    CHECK(gzp_wport_publish(&w, cs, hs, 2, 112) == 0);         /* both again */
    CHECK(held_by_txid_tag(&w, 0xf1) > 0);
    CHECK(held_by_txid_tag(&w, 0xf2) == 0);
    CHECK(w.port.can_plan(w.port.ctx, 100000, 100, &have, &n) == 1 && have == 400000 && n == 1);
    /* and a release frees it in whatever list is current */
    w.port.release(w.port.ctx, tx, len);
    CHECK(held_by_txid_tag(&w, 0xf1) == 0);
    gzp_wport_close(&w);
}

/* L-1: a held change coin that a tip moving back drops, and the tip moving forward
 * brings back, is still held. */
static void test_hold_survives_a_reorg(void)
{
    gzp_wport_t w;
    gzt_coin c;
    uint32_t h = 108;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    open_w(&w);
    c = coin(&w, 1, 0, 500000, 0xf3);
    CHECK(gzp_wport_publish(&w, &c, &h, 1, 110) == 0);         /* 3 deep: offered */
    CHECK(plan(&w, 300000, tx, &len) == 1);
    CHECK(gzp_wport_publish(&w, &c, &h, 1, 109) == 0);         /* 2 deep: not listed */
    CHECK(w.n_coins == 0);
    CHECK(gzp_wport_publish(&w, &c, &h, 1, 110) == 0);
    CHECK(held_by_txid_tag(&w, 0xf3) > 0);
    gzp_wport_close(&w);
}

/* A chain view for the scan: outputs by script, a tip that can fail, and a tip
 * that moves once the first output lookup has been made (L-2). */
typedef struct {
    uint8_t script[8][34];
    gz_chain_output out[8];
    int n;
    int tip_fails;          /* this many tip reads fail first */
    int outputs_fails;      /* this many output lookups fail first */
    int tip_calls, outputs_calls, tip_after_outputs;
    uint32_t tip_before, tip_later;
} fake_chain;

static gz_chain_result fk_tip(void *ctx, gz_chain_tip *out)
{
    fake_chain *f = ctx;
    f->tip_calls++;
    if (f->outputs_calls) f->tip_after_outputs = 1;
    if (f->tip_fails > 0) {
        f->tip_fails--;
        return GZ_CHAIN_UNREACHABLE;
    }
    memset(out, 0, sizeof *out);
    out->height = f->outputs_calls ? f->tip_later : f->tip_before;
    return GZ_CHAIN_OK;
}

static gz_chain_result fk_outputs(void *ctx, const uint8_t *script, size_t script_len, gz_chain_output *out,
                                  size_t cap, size_t *count, bool *unconfirmed_differs)
{
    fake_chain *f = ctx;
    (void)unconfirmed_differs;
    f->outputs_calls++;
    *count = 0;
    if (f->outputs_fails > 0) {
        f->outputs_fails--;
        return GZ_CHAIN_UNREACHABLE;
    }
    for (int i = 0; i < f->n && *count < cap; i++)
        if (script_len == 34 && memcmp(f->script[i], script, 34) == 0) out[(*count)++] = f->out[i];
    return GZ_CHAIN_OK;
}

static const gz_chain_ops fk_ops = {.tip = fk_tip, .script_outputs = fk_outputs};

static void fk_add(fake_chain *f, const gzt_coin *c, uint32_t height)
{
    memcpy(f->script[f->n], c->script, 34);
    memset(&f->out[f->n], 0, sizeof f->out[f->n]);
    memcpy(f->out[f->n].txid, c->txid, 32);
    f->out[f->n].vout = c->vout;
    f->out[f->n].value = c->amount;
    f->out[f->n].confirmed = true;
    f->out[f->n].height = height;
    f->n++;
}

/* L-2: the tip is read before the coin heights, so a block found during the
 * scan never makes an unburied change coin look buried. */
static void test_tip_read_first(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzt_coin c;
    open_w(&w);
    w.gap = 3;
    memset(&f, 0, sizeof f);
    f.tip_before = 110;   /* the change coin at 109 is 2 deep: not buried at B = 3 */
    f.tip_later = 120;    /* a tip read after the lookups would call it 12 deep */
    c = coin(&w, 1, 0, 500000, 0xa7);
    fk_add(&f, &c, 109);
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(f.tip_calls == 1 && !f.tip_after_outputs);
    CHECK(w.n_coins == 0);
    gzp_wport_close(&w);
}

/* L-2: a tip that cannot be read is asked again, and the coins are then published. */
static void test_tip_retried(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzt_coin c;
    uint64_t have;
    size_t n;
    open_w(&w);
    w.gap = 2;
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    f.tip_fails = 2;
    c = coin(&w, 0, 0, 500000, 0xa8);
    fk_add(&f, &c, 100);
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_until(&w, &view, 1) == 1);
    CHECK(f.tip_calls == 3);
    CHECK(w.port.can_plan(w.port.ctx, 100000, 100, &have, &n) == 1 && have == 500000);
    gzp_wport_close(&w);
}

/* Review of PR 85: a failed address lookup is asked again, like a failed tip
 * read; a list short of the coins behind that address is never published (it
 * would turn into a funds_short refusal). */
static void test_lookup_retried(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzt_coin c;
    uint64_t have;
    size_t n;
    open_w(&w);
    w.gap = 2;
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    c = coin(&w, 0, 0, 500000, 0xa9);
    fk_add(&f, &c, 100);
    view.ctx = &f;
    view.ops = &fk_ops;
    f.outputs_fails = 1;                                     /* the first lookup, the coin's address */
    CHECK(gzp_wport_scan_view(&w, &view) == 0);              /* incomplete: nothing published */
    CHECK(w.published == 0);
    CHECK(w.port.can_plan(w.port.ctx, 100000, 100, &have, &n) == -1);
    f.outputs_fails = 2;
    CHECK(gzp_wport_scan_until(&w, &view, 1) == 1);          /* asked again until every lookup answered */
    CHECK(f.outputs_fails == 0);
    CHECK(w.n_coins == 1);
    CHECK(w.port.can_plan(w.port.ctx, 100000, 100, &have, &n) == 1 && have == 500000);
    gzp_wport_close(&w);
}

/* Review of PR 85: the stop flag is read by the scan thread without the mutex
 * and written by close under it, so it is an atomic. */
static void test_stop_is_atomic(void)
{
    gzp_wport_t w;
    memset(&w, 0, sizeof w);
    CHECK(_Generic(&w.stop, _Atomic int *: 1, default: 0) == 1);
}

int main(void)
{
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    factory[0] = 0x51;
    factory[1] = 0x20;
    memset(factory + 2, 0xab, 32);
    test_can_plan_before_and_after();
    test_can_plan_agrees_with_plan();
    test_holds_across_publish();
    test_unconfirmed_and_unburied();
    test_burial_from_config();
    test_hold_survives_a_gap();
    test_hold_survives_a_reorg();
    test_tip_read_first();
    test_tip_retried();
    test_lookup_retried();
    test_stop_is_atomic();
    secp256k1_context_destroy(secp);
    printf("program_wport: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
