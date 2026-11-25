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
    gz_chain_result fail_as; /* how they fail (0: GZ_CHAIN_UNREACHABLE) */
    uint8_t dust_script[34]; /* an address with dust_n outputs of 330 sat, or none */
    size_t dust_n;
    uint8_t bad_script[34];  /* an address always answered bad_as, or none */
    gz_chain_result bad_as;
    size_t max_cap;          /* the largest cap a lookup asked for */
    size_t reject_over;      /* the dust address is refused (400) past this many outputs, as electrs's utxos limit */
    uint8_t dust2_script[34]; /* a second dust address: dust2_n outputs of dust2_value at dust2_height */
    size_t dust2_n;
    uint64_t dust2_value;
    uint32_t dust2_height;
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
        return f->fail_as != GZ_CHAIN_OK ? f->fail_as : GZ_CHAIN_UNREACHABLE;
    }
    if (cap > f->max_cap) f->max_cap = cap;
    if (f->bad_as != GZ_CHAIN_OK && script_len == 34 && memcmp(f->bad_script, script, 34) == 0) return f->bad_as;
    if (f->dust2_n && script_len == 34 && memcmp(f->dust2_script, script, 34) == 0) {
        if (f->dust2_n > cap) return GZ_CHAIN_TOO_LARGE;
        for (size_t i = 0; i < f->dust2_n; i++) {
            memset(&out[i], 0, sizeof out[i]);
            memset(out[i].txid, 0xc7, 32);
            out[i].txid[1] = (uint8_t)(i >> 8);
            out[i].txid[2] = (uint8_t)i;
            out[i].value = f->dust2_value;
            out[i].confirmed = true;
            out[i].height = f->dust2_height;
        }
        *count = f->dust2_n;
        return GZ_CHAIN_OK;
    }
    if (f->dust_n && script_len == 34 && memcmp(f->dust_script, script, 34) == 0) {
        if (f->reject_over && f->dust_n > f->reject_over) return GZ_CHAIN_REJECTED;   /* electrs: 400 */
        if (f->dust_n > cap) return GZ_CHAIN_TOO_LARGE;   /* as the chain port does past its cap */
        for (size_t i = 0; i < f->dust_n; i++) {
            memset(&out[i], 0, sizeof out[i]);
            memset(out[i].txid, 0xd0, 32);
            out[i].txid[1] = (uint8_t)(i >> 8);
            out[i].txid[2] = (uint8_t)i;
            out[i].value = 330;
            out[i].confirmed = true;
            out[i].height = 100;
        }
        *count = f->dust_n;
        return GZ_CHAIN_OK;
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

/* PR 88: an address with no outputs is what a real server answers for an
 * unused address (200 [], which the chain port gives as OK with none): no
 * coins, the list is complete and published at once, never asked again. A
 * fresh wallet's list is empty, and can_plan says no, not "cannot tell". */
static void test_unused_addresses_are_no_coins(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    uint64_t have = 1;
    size_t n = 1;
    open_w(&w);
    w.gap = 3;
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;   /* no outputs at all: a fresh wallet */
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(f.outputs_calls == 6 && f.tip_calls == 1);       /* every address asked once */
    CHECK(w.published == 1 && w.n_coins == 0);
    CHECK(w.port.can_plan(w.port.ctx, 100000, 100, &have, &n) == 0 && have == 0 && n == 0);
    gzp_wport_close(&w);
}

/* PR 88: every real failure of a lookup is asked again, not only an
 * unreachable server: a 5xx or a malformed answer (both GZ_CHAIN_MALFORMED
 * from the chain port), a 404 or a refusal (NOT_FOUND, REJECTED: a real
 * server answers an unused address 200 []), an answer too large. */
static void test_lookup_failures_retried(void)
{
    static const gz_chain_result kinds[] = {GZ_CHAIN_MALFORMED, GZ_CHAIN_NOT_FOUND, GZ_CHAIN_REJECTED,
                                            GZ_CHAIN_UNREACHABLE};
    for (size_t k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
        gzp_wport_t w;
        fake_chain f;
        gz_chain view;
        gzt_coin c;
        open_w(&w);
        w.gap = 1;
        memset(&f, 0, sizeof f);
        f.tip_before = f.tip_later = 110;
        c = coin(&w, 0, 0, 500000, 0xaa);
        fk_add(&f, &c, 100);
        f.outputs_fails = 1;
        f.fail_as = kinds[k];
        view.ctx = &f;
        view.ops = &fk_ops;
        CHECK(gzp_wport_scan_view(&w, &view) == 0 && w.published == 0);
        CHECK(gzp_wport_scan_view(&w, &view) == 1 && w.n_coins == 1);
        gzp_wport_close(&w);
    }
}

static int has(const char *s, const char *part) { return strstr(s, part) != NULL; }

static void dust_view(gzp_wport_t *w, fake_chain *f, gz_chain *view, uint32_t change, uint32_t j, size_t n)
{
    gzt_coin d = coin(w, change, j, 1, 0xd1);
    memset(f, 0, sizeof *f);
    f->tip_before = f->tip_later = 110;
    memcpy(f->dust_script, d.script, 34);
    f->dust_n = n;
    view->ctx = f;
    view->ops = &fk_ops;
}

/* M-1 (review of PR 88): 33 dust outputs sent to one address are more than a
 * first lookup's 32. The address is asked again at a larger cap, and the list
 * is complete: a stranger's dust no longer stops the scan. */
static void test_dust_33(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzp_wport_coins_t c;
    char js[512];
    open_w(&w);
    w.gap = 1;
    dust_view(&w, &f, &view, 0, 0, 33);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.n_coins == 33 && f.max_cap >= 33);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_COMPLETE && c.reason == NULL && c.attempts == 1);
    CHECK(gzp_wport_coins_json(&c, js, sizeof js) > 0 && has(js, "\"state\":\"complete\"") &&
          has(js, "\"reason\":null") && has(js, "\"attempts\":1"));
    CHECK(gzp_wport_coins_attention(&c) == 0);
    gzp_wport_close(&w);
}

/* M-1: an address with more outputs than the chain port gives at all (1024) is
 * left out; the list is published without it, marked incomplete with the
 * address and the reason, and the other coins can still fund. */
static void test_dust_too_many(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzp_wport_coins_t c;
    gzt_coin k;
    char js[512];
    uint64_t have;
    size_t n;
    open_w(&w);
    w.gap = 1;
    dust_view(&w, &f, &view, 0, 0, 1025);
    k = coin(&w, 1, 0, 500000, 0xe7);
    fk_add(&f, &k, 100);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.published == 1 && w.n_coins == 1);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_INCOMPLETE && c.reason && !strcmp(c.reason, "address_too_large") &&
          c.chain == 0 && c.index == 0);
    CHECK(gzp_wport_coins_json(&c, js, sizeof js) > 0 && has(js, "\"state\":\"incomplete\"") &&
          has(js, "\"reason\":\"address_too_large\"") && has(js, "\"chain\":0") && has(js, "\"index\":0"));
    CHECK(gzp_wport_coins_attention(&c) == 1);
    CHECK(w.port.can_plan(w.port.ctx, 100000, 100, &have, &n) == 1 && have == 500000);
    gzp_wport_close(&w);
}

/* M-1: an address the server keeps refusing is asked again, then left out
 * after 3 refusals in a row: published, incomplete, with the reason. */
static void test_refusal_repeated(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzp_wport_coins_t c;
    gzt_coin k, b;
    char js[512];
    open_w(&w);
    w.gap = 1;
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    b = coin(&w, 0, 0, 1, 0xb0);
    memcpy(f.bad_script, b.script, 34);
    f.bad_as = GZ_CHAIN_REJECTED;
    k = coin(&w, 1, 0, 500000, 0xe8);
    fk_add(&f, &k, 100);
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 0 && w.published == 0);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_SCANNING && c.reason && !strcmp(c.reason, "lookup") && c.error &&
          !strcmp(c.error, "rejected") && c.attempts == 1 && gzp_wport_coins_attention(&c) == 0);
    CHECK(gzp_wport_scan_view(&w, &view) == 0 && w.published == 0);
    CHECK(gzp_wport_scan_view(&w, &view) == 1 && w.published == 1 && w.n_coins == 1);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_INCOMPLETE && c.reason && !strcmp(c.reason, "address_refused") &&
          c.chain == 0 && c.index == 0 && c.attempts == 3);
    CHECK(gzp_wport_coins_json(&c, js, sizeof js) > 0 && has(js, "\"reason\":\"address_refused\"") &&
          has(js, "\"error\":\"rejected\"") && has(js, "\"attempts\":3"));
    CHECK(gzp_wport_coins_attention(&c) == 1);
    gzp_wport_close(&w);
}

/* M-1: a server that cannot be reached is asked again for as long as it takes,
 * and nothing is published; after 3 attempts the person is told. */
static void test_unreachable_told(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzp_wport_coins_t c;
    char js[512];
    open_w(&w);
    w.gap = 1;
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    f.outputs_fails = 1000;
    view.ctx = &f;
    view.ops = &fk_ops;
    for (int i = 0; i < 2; i++) CHECK(gzp_wport_scan_view(&w, &view) == 0);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_SCANNING && c.attempts == 2 && gzp_wport_coins_attention(&c) == 0);
    for (int i = 0; i < 3; i++) CHECK(gzp_wport_scan_view(&w, &view) == 0);
    CHECK(w.published == 0);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_SCANNING && c.attempts == 5 && c.error && !strcmp(c.error, "unreachable"));
    CHECK(gzp_wport_coins_attention(&c) == 1);
    CHECK(gzp_wport_coins_json(&c, js, sizeof js) > 0 && has(js, "\"state\":\"scanning\"") &&
          has(js, "\"reason\":\"lookup\"") && has(js, "\"error\":\"unreachable\"") && has(js, "\"attempts\":5"));
    gzp_wport_close(&w);
}

/* M-1: more coins than the list holds (256) is an incomplete list, not a complete one. */
static void test_too_many_coins(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzp_wport_coins_t c;
    open_w(&w);
    w.gap = 1;
    dust_view(&w, &f, &view, 0, 0, GZP_WPORT_COINS + 44);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.n_coins == GZP_WPORT_COINS);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_INCOMPLETE && c.reason && !strcmp(c.reason, "too_many_coins"));
    CHECK(gzp_wport_coins_attention(&c) == 1);
    gzp_wport_close(&w);
}

/* A wallet port that has not scanned yet, and the invented coin of the test build. */
static void test_coins_before_and_invented(void)
{
    gzp_wport_t w;
    gzp_wport_coins_t c;
    char js[512];
    open_w(&w);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_SCANNING && c.reason == NULL && c.attempts == 0 && gzp_wport_coins_attention(&c) == 0);
    CHECK(gzp_wport_coins_json(&c, js, sizeof js) > 0 && !strcmp(js,
          "{\"state\":\"scanning\",\"reason\":null,\"params\":{},\"attempts\":0}"));
    CHECK(gzp_wport_invent(&w) == 0);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_COMPLETE);
    gzp_wport_close(&w);
}

/* M-1: can_plan's -1 is its own error, coins_unknown: not a locked wallet
 * (no_wallet), not too few coins (funds_short). */
static void test_funds_error_codes(void)
{
    CHECK(gzp_wport_funds_error(GZ_FUND_FUNDS_OK) == NULL);
    CHECK(!strcmp(gzp_wport_funds_error(GZ_FUND_FUNDS_SHORT), "funds_short"));
    CHECK(!strcmp(gzp_wport_funds_error(GZ_FUND_FUNDS_UNKNOWN), "coins_unknown"));
    CHECK(!strcmp(gzp_wport_funds_error((gz_fund_funds_t)0), "coins_unknown"));
}

/* M-1: the log says the first failed attempt, then every 10th. */
static void test_log_rate(void)
{
    CHECK(gzp_wport_log_attempt(1) == 1 && gzp_wport_log_attempt(2) == 0 && gzp_wport_log_attempt(9) == 0);
    CHECK(gzp_wport_log_attempt(10) == 1 && gzp_wport_log_attempt(11) == 0 && gzp_wport_log_attempt(20) == 1);
}

/* M-2 (review of PR 88, second round): the reviewer's probe. 300 dust outputs at
 * receive index 0 come before the real coin at index 1; the list keeps the 256
 * largest coins, so the real one is listed and can fund (the wallet spends
 * its 64 largest anyway), and the list says it is incomplete. */
static void test_dust_does_not_push_out_real_coins(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzp_wport_coins_t c;
    gzt_coin k;
    uint64_t have;
    size_t n;
    int listed = 0;
    open_w(&w);
    w.gap = 2;
    dust_view(&w, &f, &view, 0, 0, 300);
    k = coin(&w, 0, 1, 500000, 0xe9);
    fk_add(&f, &k, 100);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.n_coins == GZP_WPORT_COINS);
    for (size_t i = 0; i < w.n_coins; i++)
        if (w.coins[i].txid[0] == 0xe9) listed = 1;
    CHECK(listed);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_INCOMPLETE && c.reason && !strcmp(c.reason, "too_many_coins"));
    CHECK(w.port.can_plan(w.port.ctx, 400000, 100, &have, &n) == 1);
    gzp_wport_close(&w);
}

/* L-2 (second round): on an incomplete list, "not enough" is not known: the
 * coins left out might cover it, so can_plan cannot tell (coins_unknown),
 * and the error carries the list's state. Enough is still enough. */
static void test_incomplete_short_is_unknown(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzt_coin k;
    uint64_t have;
    size_t n;
    open_w(&w);
    w.gap = 1;
    dust_view(&w, &f, &view, 0, 0, 1025);       /* left out: address_too_large */
    k = coin(&w, 1, 0, 500000, 0xea);
    fk_add(&f, &k, 100);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.port.can_plan(w.port.ctx, 100000, 100, &have, &n) == 1);
    CHECK(w.port.can_plan(w.port.ctx, 900000, 100, &have, &n) == -1);
    gzp_wport_close(&w);
}

/* L-2 (second round): Blockstream's electrs answers an address past its
 * utxos limit (--utxos-limit, 500 by default) with HTTP 400, which the chain
 * port gives as REJECTED. That is refused again at every scan: after 3 the
 * address is left out (address_refused), never a retry loop. */
static void test_electrs_utxo_limit(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzp_wport_coins_t c;
    gzt_coin k;
    open_w(&w);
    w.gap = 1;
    dust_view(&w, &f, &view, 0, 0, 600);
    f.reject_over = 500;
    k = coin(&w, 1, 0, 500000, 0xeb);
    fk_add(&f, &k, 100);
    CHECK(gzp_wport_scan_until(&w, &view, 1) == 1);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_INCOMPLETE && c.reason && !strcmp(c.reason, "address_refused") &&
          c.error && !strcmp(c.error, "rejected") && c.attempts == 3);
    CHECK(w.n_coins == 1);
    gzp_wport_close(&w);
}

/* L-3 (third review of PR 88): too_many_coins drops only coins smaller than
 * the 256 kept, so "not enough" is exact there: can_plan answers 0
 * (funds_short), not -1. Only an address left out makes it unknown. */
static void test_too_many_short_is_exact(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzp_wport_coins_t c;
    uint64_t have;
    size_t n;
    open_w(&w);
    w.gap = 1;
    dust_view(&w, &f, &view, 0, 0, GZP_WPORT_COINS + 44);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_INCOMPLETE && c.reason && !strcmp(c.reason, "too_many_coins"));
    CHECK(w.port.can_plan(w.port.ctx, 900000, 100, &have, &n) == 0);
    gzp_wport_close(&w);
}

/* Third review of PR 88 (optional): change not yet buried, and coins above
 * the tip, never make the list, so they are left out before the 256 largest
 * are chosen: 300 larger unburied change outputs do not push out 255 buried
 * receive coins and a real one, and the list is complete. */
static void test_unburied_change_not_ranked(void)
{
    gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzp_wport_coins_t c;
    gzt_coin k, ch;
    open_w(&w);
    w.gap = 2;
    dust_view(&w, &f, &view, 0, 0, GZP_WPORT_COINS - 1);   /* 255 x 330 sat, buried */
    k = coin(&w, 0, 1, 500000, 0xec);
    fk_add(&f, &k, 100);
    ch = coin(&w, 1, 0, 1, 0xed);
    memcpy(f.dust2_script, ch.script, 34);
    f.dust2_n = 300;
    f.dust2_value = 10000;
    f.dust2_height = 109;                                  /* 2 deep at 110: not buried at B = 3 */
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.n_coins == GZP_WPORT_COINS);
    gzp_wport_coins(&w, &c);
    CHECK(c.state == GZP_COINS_COMPLETE);
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
    test_hold_survives_a_gap();
    test_hold_survives_a_reorg();
    test_tip_read_first();
    test_tip_retried();
    test_lookup_retried();
    test_stop_is_atomic();
    test_unused_addresses_are_no_coins();
    test_lookup_failures_retried();
    test_dust_33();
    test_dust_too_many();
    test_refusal_repeated();
    test_unreachable_told();
    test_too_many_coins();
    test_coins_before_and_invented();
    test_funds_error_codes();
    test_log_rate();
    test_dust_does_not_push_out_real_coins();
    test_incomplete_short_is_unknown();
    test_electrs_utxo_limit();
    test_too_many_short_is_exact();
    test_unburied_change_not_ranked();
    secp256k1_context_destroy(secp);
    printf("program_wport: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
