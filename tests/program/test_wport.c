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
    secp256k1_context_destroy(secp);
    printf("program_wport: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
