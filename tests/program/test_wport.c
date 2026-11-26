/* SPDX-License-Identifier: MIT */
#define _POSIX_C_SOURCE 200809L   /* clock_gettime */
/* The program's wallet port for the funding engine (program/wport.c), on
 * the real wallet code (review of PR 80, N-1): a plan's holds survive a new
 * coin list, coins in the mempool and change not yet buried are not
 * offered, and can_plan answers what plan does, with the same fee policy.
 *
 * THE KEYS HERE ARE TEST KEYS. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/crypto.h>
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
static int LOCKED;   /* the seed source refuses, as a locked wallet's does */

static int seed_lockable(void *ctx, uint8_t out64[64])
{
    (void)ctx;
    memset(out64, LOCKED ? 0 : 0x42, 64);
    return LOCKED ? -1 : 0;
}
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
    CHECK(gzw_bip86_output_from_xpub(secp, &w->account, GZW_NET_SIGNET, 0, change, j, &o, &why) == 1);
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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

static int has_bytes(const void *hay, size_t n, const unsigned char *needle, size_t k)
{
    for (size_t i = 0; i + k <= n; i++)
        if (memcmp((const uint8_t *)hay + i, needle, k) == 0) return 1;
    return 0;
}

/* The BIP 32 master key is never kept (signer.md 2.1, keys.md 8; the signer-boundary review of
 * #66): the port asks the seed source for each plan, signature and spend-back, and wipes what it
 * derives. Its memory holds neither the master's private key nor its chain code, before or after
 * a plan and its signature. While the source refuses (the wallet locked) nothing is planned or
 * signed; once it answers again, the port plans and signs. */
static void test_master_not_kept(void)
{
    static gzp_wport_t w;
    gzp_unlock_t u;
    gzt_coin c;
    uint32_t h = 100;
    static uint8_t tx[GZ_FUND_MAX_TX], out[GZ_FUND_MAX_TX];
    uint8_t seed[64];
    size_t len = 0, n = 0;
    gzw_xprv m;
    gzw_reason why;
    memset(&u, 0, sizeof u);
    u.seed = seed_lockable;
    LOCKED = 0;
    CHECK(gzp_wport_open(&w, secp, &u, GZW_NET_SIGNET, 0) == 0);
    memset(seed, 0x42, 64);
    CHECK(gzw_bip32_master(secp, seed, 64, &m, &why) == 1);
    CHECK(!has_bytes(&w, sizeof w, m.key, 32) && !has_bytes(&w, sizeof w, m.chain_code, 32));
    c = coin(&w, 0, 0, 500000, 0xe1);
    CHECK(gzp_wport_publish(&w, &c, &h, 1, 110) == 0);
    LOCKED = 1;                                       /* locked: no plan */
    CHECK(plan(&w, 300000, tx, &len) == 0);
    LOCKED = 0;                                       /* unlocked: a plan */
    CHECK(plan(&w, 300000, tx, &len) == 1);
    CHECK(!has_bytes(&w, sizeof w, m.key, 32) && !has_bytes(&w, sizeof w, m.chain_code, 32));
    LOCKED = 1;                                       /* locked: the plan is not signed */
    CHECK(w.port.sign_plan(w.port.ctx, w.plans[0].info.txid, out, sizeof out, &n) == 0);
    LOCKED = 0;                                       /* unlocked: it is */
    CHECK(w.port.sign_plan(w.port.ctx, w.plans[0].info.txid, out, sizeof out, &n) == 1 && n > 0);
    CHECK(!has_bytes(&w, sizeof w, m.key, 32) && !has_bytes(&w, sizeof w, m.chain_code, 32));
    gzw_wipe(&m, sizeof m);
    OPENSSL_cleanse(seed, sizeof seed);
    gzp_wport_close(&w);
}

/* coins in the mempool are not offered; change counts only once buried */
static void test_unconfirmed_and_unburied(void)
{
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    uint8_t spent[48][34];   /* addresses used and spent: in the history, not among the unspent */
    int n_spent;
    uint8_t hist_script[34]; /* its history answered hist_as, hist_left times */
    gz_chain_result hist_as;
    int hist_left;
    int bad_limited, bad_left; /* bad_script answered bad_as only bad_left times */
    int hist_unsupported;    /* every history answered GZ_CHAIN_UNSUPPORTED (no such route) */
    gzp_wport_t *stop_w;     /* stopped once the tip has been read stop_after times */
    int stop_after;
} fake_chain;

static gz_chain_result fk_tip(void *ctx, gz_chain_tip *out)
{
    fake_chain *f = ctx;
    f->tip_calls++;
    if (f->stop_w && f->tip_calls >= f->stop_after) f->stop_w->stop = 1;   /* a test's time limit */
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
    if (f->bad_as != GZ_CHAIN_OK && script_len == 34 && memcmp(f->bad_script, script, 34) == 0) {
        if (!f->bad_limited) return f->bad_as;
        if (f->bad_left > 0) {
            f->bad_left--;
            return f->bad_as;
        }
    }
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

/* Whether an address was ever used: every transaction that paid or spent it. */
static gz_chain_result fk_history(void *ctx, const uint8_t *script, size_t script_len, gz_script_history *out)
{
    fake_chain *f = ctx;
    memset(out, 0, sizeof *out);
    if (script_len != 34) return GZ_CHAIN_INVALID_ARG;
    if (f->hist_unsupported) return GZ_CHAIN_UNSUPPORTED;
    if (f->hist_left > 0 && memcmp(f->hist_script, script, 34) == 0) {
        f->hist_left--;
        return f->hist_as;
    }
    for (int i = 0; i < f->n_spent; i++)
        if (memcmp(f->spent[i], script, 34) == 0) out->confirmed_txs += 2;   /* paid, then spent */
    if (f->dust_n && memcmp(f->dust_script, script, 34) == 0) out->confirmed_txs += f->dust_n;
    if (f->dust2_n && memcmp(f->dust2_script, script, 34) == 0) out->confirmed_txs += f->dust2_n;
    for (int i = 0; i < f->n; i++)
        if (memcmp(f->script[i], script, 34) == 0) {
            if (f->out[i].confirmed) out->confirmed_txs++;
            else out->mempool_txs++;
        }
    return GZ_CHAIN_OK;
}

static const gz_chain_ops fk_ops = {.tip = fk_tip, .script_outputs = fk_outputs, .script_history = fk_history};
/* A server with no history call. */
static const gz_chain_ops fk_ops_nohist = {.tip = fk_tip, .script_outputs = fk_outputs};

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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
    memset(&w, 0, sizeof w);
    CHECK(_Generic(&w.stop, _Atomic int *: 1, default: 0) == 1);
}

/* PR 88: an address with no outputs is what a real server answers for an
 * unused address (200 [], which the chain port gives as OK with none): no
 * coins, the list is complete and published at once, never asked again. A
 * fresh wallet's list is empty, and can_plan says no, not "cannot tell". */
static void test_unused_addresses_are_no_coins(void)
{
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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
    static gzp_wport_t w;
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

/* N-2 (review of PR 90): a plan's change, confirmed, is the wallet's own coin
 * after a restart, and the next plan takes another change index. */
static void test_change_seen_after_restart(void)
{
    static gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzt_coin k, ch, c1;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    uint64_t change_value;
    open_w(&w);
    w.gap = 20;
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    k = coin(&w, 0, 0, 500000, 0xf5);
    fk_add(&f, &k, 100);
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(plan(&w, 300000, tx, &len) == 1);
    CHECK(w.plans[0].info.has_change && w.plans[0].priv_tx.n_out == 2);
    ch = coin(&w, 1, 0, 1, 0);
    CHECK(memcmp(w.plans[0].priv_tx.out[1].script, ch.script, 34) == 0);   /* the lowest unused change index */
    /* the funding confirms: its change is a coin of the wallet's, buried */
    change_value = w.plans[0].priv_tx.out[1].value;
    memset(&ch, 0, sizeof ch);
    memcpy(ch.txid, w.plans[0].info.txid, 32);
    ch.vout = 1;
    ch.amount = change_value;
    memcpy(ch.script, w.plans[0].priv_tx.out[1].script, 34);
    gzp_wport_close(&w);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 120;
    fk_add(&f, &ch, 112);
    /* the program starts again */
    open_w(&w);
    w.gap = 20;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.n_coins == 1 && w.coins[0].change == 1 && w.coins[0].index == 0 && w.coins[0].amount == change_value);
    CHECK(plan(&w, 100000, tx, &len) == 1);
    c1 = coin(&w, 1, 1, 1, 0);
    CHECK(w.plans[0].info.has_change && memcmp(w.plans[0].priv_tx.out[1].script, c1.script, 34) == 0);
    gzp_wport_close(&w);
}

/* N-2: the change chain is read until 20 unused addresses in a row (a gap
 * limit), not a fixed 0 to 19, and next_change goes past the highest used. */
static void test_change_gap_limit(void)
{
    static gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    open_w(&w);
    w.gap = 20;
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    for (uint32_t j = 0; j <= 30; j += 10) {
        gzt_coin c = coin(&w, 1, j, 10000 + j, (uint8_t)(0x80 + j));
        fk_add(&f, &c, 100);
    }
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.n_coins == 4);
    CHECK(w.next_change == 31);
    gzp_wport_close(&w);
}

/* N-2: a change output still in the mempool is not a coin, but its index is
 * used: the next change index goes past it. */
static void test_unconfirmed_change_counts(void)
{
    static gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    gzt_coin c;
    open_w(&w);
    w.gap = 20;
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    c = coin(&w, 1, 5, 40000, 0x95);
    fk_add(&f, &c, 100);
    f.out[f.n - 1].confirmed = false;
    f.out[f.n - 1].height = 0;
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.n_coins == 0);
    CHECK(w.next_change == 6);
    gzp_wport_close(&w);
}

/* A change mark kept in memory, as the sealed file keeps it across restarts. */
typedef struct {
    uint32_t v;
    int fail, saves, wide;
    int wv, cleared;   /* the last save's wide flag; saves with it 0 */
} mark_store;

static int ms_load(void *ctx, uint32_t *mark, int *wide)
{
    *mark = ((mark_store *)ctx)->v;
    *wide = ((mark_store *)ctx)->wide;
    return 0;
}

static int ms_save(void *ctx, uint32_t mark, int wide)
{
    mark_store *s = ctx;
    if (s->fail) return -1;
    s->v = mark;
    s->wv = wide;
    if (!wide) s->cleared++;
    s->saves++;
    return 0;
}

/* The plan in slot 0 signed: from here its change index may be on the chain. */
static int sign0(gzp_wport_t *w)
{
    static uint8_t out[GZ_FUND_MAX_TX];
    size_t n = 0;
    return w->port.sign_plan(w->port.ctx, w->plans[0].info.txid, out, sizeof out, &n);
}

static void open_marked(gzp_wport_t *w, mark_store *ms)
{
    gzp_wport_marks_t m = {ms_load, ms_save, ms};
    open_w(w);
    w->gap = 20;
    CHECK(gzp_wport_set_marks(w, &m) == 0);
}

/* The change of a plan, as the coin it becomes once its funding confirms. */
static gzt_coin change_of(const gzt_funding *p, uint32_t index)
{
    gzt_coin c;
    memset(&c, 0, sizeof c);
    memcpy(c.txid, p->info.txid, 32);
    c.vout = 1;
    c.amount = p->priv_tx.out[1].value;
    c.change = 1;
    c.index = index;
    memcpy(c.script, p->priv_tx.out[1].script, 34);
    return c;
}

/* M-3 (review of PR 91): 20 plans released unfunded take 20 change indexes;
 * the funded one after them takes the 21st. After a restart its change must
 * be listed: the kept mark says how far the change chain was handed out. */
static void test_change_after_released_plans(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    gzt_coin k, ch;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    k = coin(&w, 0, 0, 500000, 0xf6);
    fk_add(&f, &k, 100);
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    for (int i = 0; i < 20; i++) {
        CHECK(plan(&w, 300000, tx, &len) == 1);
        CHECK(sign0(&w) == 1);   /* signed and never funded (a broadcast that failed): the index stays taken */
        w.port.release(w.port.ctx, tx, len);
    }
    CHECK(plan(&w, 300000, tx, &len) == 1);   /* the one that is funded */
    ch = change_of(&w.plans[0], 20);
    CHECK(ms.v == 21);
    gzp_wport_close(&w);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 120;
    fk_add(&f, &ch, 112);
    open_marked(&w, &ms);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.n_coins == 1 && w.coins[0].change == 1 && w.coins[0].amount == ch.amount);
    CHECK(w.next_change == 21);
    gzp_wport_close(&w);
}

/* M-3: 21 fundings in a row, each spending the change of the one before, so
 * every earlier change address is spent and looks unused to the unspent-
 * outputs lookup. After a restart the live change must be listed. */
static void test_chained_change_after_restart(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    gzt_coin cur;
    uint32_t h = 100;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    cur = coin(&w, 0, 0, 2000000, 0xf7);
    for (uint32_t i = 0; i < 21; i++) {
        CHECK(gzp_wport_publish(&w, &cur, &h, 1, 110) == 0);
        CHECK(plan(&w, 20000, tx, &len) == 1);
        cur = change_of(&w.plans[0], i);
        CHECK(sign0(&w) == 1);
        w.port.release(w.port.ctx, tx, len);   /* broadcast and done: the plan is no longer held */
    }
    gzp_wport_close(&w);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 130;
    fk_add(&f, &cur, 120);   /* only the last change is unspent */
    view.ctx = &f;
    view.ops = &fk_ops;
    open_marked(&w, &ms);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.n_coins == 1 && w.coins[0].change == 1 && w.coins[0].index == 20);
    gzp_wport_close(&w);
}

/* M-3: the mark is kept before its index is used: a plan whose mark cannot
 * be saved is refused, and takes no index. */
static void test_mark_saved_before_use(void)
{
    static gzp_wport_t w;
    mark_store ms;
    gzt_coin k;
    uint32_t h = 100;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    k = coin(&w, 0, 0, 500000, 0xf8);
    CHECK(gzp_wport_publish(&w, &k, &h, 1, 110) == 0);
    ms.fail = 1;
    CHECK(plan(&w, 300000, tx, &len) == 0);
    CHECK(w.next_change == 0 && ms.v == 0);
    ms.fail = 0;
    CHECK(plan(&w, 300000, tx, &len) == 1);
    CHECK(ms.v == 1 && ms.saves == 1 && w.next_change == 1);
    gzp_wport_close(&w);
}

/* Follow-up of the review of PR 91: a change index that never left the port
 * (its plan refused inside it) is handed back, so 20 refused plans do not push
 * the next change 20 addresses on; the mark is saved once. A plan released
 * unsigned keeps its index: its address was shown to the lobby's members in
 * the proposal (L-2, review B of PR 93). */
static void test_unsent_index_handed_back(void)
{
    static gzp_wport_t w;
    mark_store ms;
    gzt_coin k;
    uint32_t h = 100;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    k = coin(&w, 0, 0, 500000, 0xe2);
    CHECK(gzp_wport_publish(&w, &k, &h, 1, 110) == 0);
    for (int i = 0; i < 20; i++)
        CHECK(plan(&w, 5000000, tx, &len) == 0);   /* refused: more than the wallet holds */
    CHECK(w.next_change == 0);
    CHECK(plan(&w, 300000, tx, &len) == 1);
    CHECK(w.plans[0].info.change_index == 0);
    CHECK(ms.v == 1 && ms.saves == 1 && w.next_change == 1);
    w.port.release(w.port.ctx, tx, len);   /* never signed, but shown to the lobby */
    CHECK(plan(&w, 300000, tx, &len) == 1);
    CHECK(w.plans[0].info.change_index == 1);
    gzp_wport_close(&w);
}

/* A signed plan's change index is never handed back, released or not. */
static void test_sent_index_kept(void)
{
    static gzp_wport_t w;
    mark_store ms;
    gzt_coin k;
    uint32_t h = 100;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    k = coin(&w, 0, 0, 500000, 0xe3);
    CHECK(gzp_wport_publish(&w, &k, &h, 1, 110) == 0);
    CHECK(plan(&w, 300000, tx, &len) == 1);
    CHECK(sign0(&w) == 1);
    w.port.release(w.port.ctx, tx, len);
    CHECK(plan(&w, 300000, tx, &len) == 1);
    CHECK(w.plans[0].info.change_index == 1);
    gzp_wport_close(&w);
}

/* Follow-up of the review of PR 91: a host's port with no kept mark plans
 * nothing (its change index could be handed out again after a restart). */
static void test_no_marks_refused(void)
{
    static gzp_wport_t w;
    mark_store ms;
    gzp_wport_marks_t m = {ms_load, ms_save, &ms};
    gzt_coin k;
    uint32_t h = 100;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    open_w(&w);
    gzp_wport_require_marks(&w);
    k = coin(&w, 0, 0, 500000, 0xe4);
    CHECK(gzp_wport_publish(&w, &k, &h, 1, 110) == 0);
    CHECK(plan(&w, 300000, tx, &len) == 0);
    CHECK(w.next_change == 0);
    CHECK(gzp_wport_set_marks(&w, &m) == 0);
    CHECK(plan(&w, 300000, tx, &len) == 1);
    CHECK(ms.v == 1);
    gzp_wport_close(&w);
}

/* Follow-up of the review of PR 91, the restore case: with no mark (a restore
 * from the words into a new folder, or the file lost) the change chain is read
 * wide, so change past 20 unused addresses, spent ones between, is still
 * found; the mark is then saved past it, and the next start is not wide. */
static void test_wide_scan_without_mark(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    gzt_coin c;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    c = coin(&w, 1, 300, 40000, 0xe5);
    fk_add(&f, &c, 100);
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.n_coins == 1 && w.coins[0].change == 1 && w.coins[0].index == 300);
    CHECK(ms.v == 301 && w.next_change == 301 && w.wide == 0);
    gzp_wport_close(&w);
}

static int coins_json_has(gzp_wport_t *w, const char *want)
{
    gzp_wport_coins_t c;
    char js[512];
    gzp_wport_coins(w, &c);
    return gzp_wport_coins_json(&c, js, sizeof js) > 0 && has(js, want);
}

/* H-1 (review B of PR 93): a wide read asks each change address's history,
 * spent outputs too. Change 0 to 39 all spent (chained fundings), none left:
 * the next change is 40, and the mark is kept there, the read settled. */
static void test_wide_reads_spent_change(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    for (uint32_t j = 0; j < 40; j++) {
        gzt_coin c = coin(&w, 1, j, 1, 0);
        memcpy(f.spent[f.n_spent++], c.script, 34);
    }
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.next_change == 40);
    CHECK(ms.v == 40 && ms.wv == 0 && w.wide == 0);
    CHECK(coins_json_has(&w, "\"change_mark\":\"kept\""));
    gzp_wport_close(&w);
}

/* H-1: a server that refuses one change address's history, again and again:
 * the address counts as used, but the read is not settled: no mark kept with
 * the wide read cleared, the wide read still pending, and no plan. */
static void test_wide_history_refused(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    gzt_coin k, b;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    for (uint32_t j = 0; j < 10; j++) {
        gzt_coin c = coin(&w, 1, j, 1, 0);
        memcpy(f.spent[f.n_spent++], c.script, 34);
    }
    b = coin(&w, 1, 5, 1, 0);
    memcpy(f.hist_script, b.script, 34);
    f.hist_as = GZ_CHAIN_REJECTED;
    f.hist_left = 1000000;
    k = coin(&w, 0, 0, 500000, 0xe8);
    fk_add(&f, &k, 100);
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 0);   /* refused once, twice: asked again */
    CHECK(gzp_wport_scan_view(&w, &view) == 0);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);   /* three in a row: left out, counted as used */
    CHECK(w.next_change >= 10);
    CHECK(w.wide_reach == 1200);   /* how far the pass read (P97-2) */
    CHECK(ms.cleared == 0 && w.wide == 1);
    CHECK(coins_json_has(&w, "\"change_mark\":\"history_refused\""));   /* the cause, not "reading" (P97-1) */
    CHECK(plan(&w, 100000, tx, &len) == 0);
    gzp_wport_close(&w);
}

/* H-1: the servers disagree about an address's history: nothing is published,
 * the wide read stays pending, and no plan is made even from coins known. */
static void test_wide_history_disagree(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    gzt_coin k, b;
    uint32_t h = 100;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    b = coin(&w, 1, 0, 1, 0);
    memcpy(f.hist_script, b.script, 34);
    f.hist_as = GZ_CHAIN_DISAGREE;
    f.hist_left = 1000000;
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 0);
    CHECK(ms.cleared == 0 && w.wide == 1);
    k = coin(&w, 0, 0, 500000, 0xe9);
    CHECK(gzp_wport_publish(&w, &k, &h, 1, 110) == 0);
    CHECK(plan(&w, 100000, tx, &len) == 0);
    CHECK(w.next_change == 0);
    gzp_wport_close(&w);
}

/* M-3 (review B of PR 93; A's M1): a change address left out (more outputs
 * than the chain port's cap) counts as used. */
static void test_left_out_change_counts_used(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    dust_view(&w, &f, &view, 1, 3, 1025);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.next_change == 4);
    gzp_wport_close(&w);
}

/* A's M1: dust past the cap on the last change address, then a restore: the
 * wide read knows the address was used, so the mark is kept above it. */
static void test_dust_past_cap_after_restore(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    dust_view(&w, &f, &view, 1, 40, 1025);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.next_change == 41);
    CHECK(ms.v == 41 && ms.wv == 0 && w.wide == 0);
    gzp_wport_close(&w);
}

/* M-3: past index 256 too, one refusal is asked again, not left out at once. */
static void test_refusal_past_256_asked_again(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    gzt_coin b;
    memset(&ms, 0, sizeof ms);
    ms.v = 290;   /* change handed out to 289 */
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    b = coin(&w, 1, 300, 1, 0);
    memcpy(f.bad_script, b.script, 34);
    f.bad_as = GZ_CHAIN_NOT_FOUND;
    f.bad_limited = 1;
    f.bad_left = 1;
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 0);
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(coins_json_has(&w, "\"state\":\"complete\""));
    gzp_wport_close(&w);
}

/* M-4 (review B of PR 93): a plan in the journal, adopted after a restart
 * whose change mark was lost, raises the mark past its change index. */
static void test_adopt_raises_mark(void)
{
    static gzp_wport_t a, b;
    mark_store ma, mb;
    gzt_coin k;
    uint32_t h = 100;
    static uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ma, 0, sizeof ma);
    memset(&mb, 0, sizeof mb);
    open_marked(&a, &ma);
    k = coin(&a, 0, 0, 500000, 0xea);
    CHECK(gzp_wport_publish(&a, &k, &h, 1, 110) == 0);
    a.next_change = 50;
    CHECK(plan(&a, 300000, tx, &len) == 1);
    CHECK(a.plans[0].info.change_index == 50);
    gzp_wport_close(&a);
    open_marked(&b, &mb);
    CHECK(b.port.adopt(b.port.ctx, tx, len, factory, 300000) == 0);   /* not this run's plan */
    CHECK(b.next_change == 51 && mb.v == 51);
    gzp_wport_close(&b);
}

/* L2 (review A of PR 93): a scan stopped by a failed key derivation keeps the
 * wide read pending and saves no mark. */
static void test_failed_derivation_keeps_wide(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    w.wnet = (gzw_network)77;   /* no such network: every derivation fails */
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    view.ctx = &f;
    view.ops = &fk_ops;
    (void)gzp_wport_scan_view(&w, &view);
    CHECK(ms.cleared == 0 && w.wide == 1);
    w.wnet = GZW_NET_SIGNET;
    gzp_wport_close(&w);
}

/* M-1 (review B of PR 93): a pending wide read is kept durably at once, and no
 * plan is made until it is done (a plan would write the file as if it were). */
static void test_wide_pending_kept_and_plans_refused(void)
{
    static gzp_wport_t w;
    mark_store ms;
    gzt_coin k;
    uint32_t h = 100;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    CHECK(ms.saves == 1 && ms.wv == 1);
    k = coin(&w, 0, 0, 500000, 0xeb);
    CHECK(gzp_wport_publish(&w, &k, &h, 1, 110) == 0);
    CHECK(plan(&w, 100000, tx, &len) == 0);
    CHECK(w.next_change == 0 && ms.saves == 1 && ms.wv == 1);
    gzp_wport_close(&w);
}

/* M-2 (review B of PR 93; A's M2): a change.gzm that did not open is read as
 * missing (wide), and the person is told in status.coins. */
static void test_not_opened_told(void)
{
    static gzp_wport_t w;
    mark_store ms;
    memset(&ms, 0, sizeof ms);
    ms.wide = 2;
    open_marked(&w, &ms);
    CHECK(w.wide == 1);
    CHECK(coins_json_has(&w, "\"change_mark\":\"not_opened\""));
    gzp_wport_close(&w);
}

/* B2-2 (review B of PR 93): a spend-back is made while a wide read is
 * pending, at an index above what that read can collide with, kept as the
 * mark with the read still pending. (Today only a plan this run made can be
 * spent back, and plans are refused while a read is pending, so the test sets
 * the pending read by hand after the plan.) */
static void test_spend_back_during_pending_read(void)
{
    static gzp_wport_t w;
    mark_store ms;
    gzt_coin k;
    uint32_t h = 100;
    static uint8_t tx[GZ_FUND_MAX_TX], sb[GZ_FUND_MAX_TX];
    size_t len, sbl = 0;
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    k = coin(&w, 0, 0, 500000, 0xec);
    CHECK(gzp_wport_publish(&w, &k, &h, 1, 110) == 0);
    CHECK(plan(&w, 300000, tx, &len) == 1);
    w.wide = 1;
    /* no pass of the read yet: where the chain is used is not known (P97-2);
     * status says so (L-2, review B of PR 101) */
    CHECK(w.port.spend_back(w.port.ctx, w.plans[0].info.txid, 0, 1000, sb, sizeof sb, &sbl) == 0);
    CHECK(coins_json_has(&w, "\"refused\":\"spend_back_before_first_pass\""));
    w.wide_reach = 1350;   /* a pass read the change chain to index 1,349 */
    CHECK(w.port.spend_back(w.port.ctx, w.plans[0].info.txid, 0, 1000, sb, sizeof sb, &sbl) == 1);
    CHECK(ms.v == 1351 && ms.wv == 1 && w.next_change == 1351);
    gzp_wport_close(&w);
}

/* B2-2: a wide read that cannot settle is asked again while it is pending,
 * not only at the next start: three refusals, then answers. */
static void test_pending_read_asked_again(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    gzt_coin b;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    b = coin(&w, 1, 5, 1, 0);
    memcpy(f.hist_script, b.script, 34);
    f.hist_as = GZ_CHAIN_REJECTED;
    f.hist_left = 3;
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_until(&w, &view, 1) == 1);
    CHECK(w.wide == 0 && ms.cleared == 1 && ms.wv == 0);
    gzp_wport_close(&w);
}

/* B2-3 (review B of PR 93): a spend-back in the journal, not in any mempool,
 * the mark lost, then a restore: the spend-back raises the mark, and the next
 * plan does not pay its change address again. */
static void test_journaled_spend_back_raises_mark(void)
{
    static gzp_wport_t a, b;
    mark_store ma, mb;
    fake_chain f;
    gz_chain view;
    gzt_coin k;
    uint32_t h = 100;
    static uint8_t tx[GZ_FUND_MAX_TX], sb[GZ_FUND_MAX_TX], st[GZ_FUND_MAX_TX];
    size_t len, sbl = 0, stl = 0;
    memset(&ma, 0, sizeof ma);
    memset(&mb, 0, sizeof mb);
    open_marked(&a, &ma);
    k = coin(&a, 0, 0, 500000, 0xed);
    CHECK(gzp_wport_publish(&a, &k, &h, 1, 110) == 0);
    CHECK(plan(&a, 300000, tx, &len) == 1);   /* change 0 */
    CHECK(a.port.spend_back(a.port.ctx, a.plans[0].info.txid, 0, 1000, sb, sizeof sb, &sbl) == 1);   /* change 1 */
    CHECK(gz_fund_tx_strip(sb, sbl, st, sizeof st, &stl));
    gzp_wport_close(&a);
    mb.wide = 1;   /* the mark lost: a restore */
    open_marked(&b, &mb);
    CHECK(b.port.note_tx != NULL);
    if (b.port.note_tx) b.port.note_tx(b.port.ctx, st, stl);
    CHECK(b.next_change == 2 && mb.v == 2 && mb.wv == 1);
    memset(&f, 0, sizeof f);   /* nothing on chain: the spend-back was never seen */
    f.tip_before = f.tip_later = 110;
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&b, &view) == 1);
    CHECK(b.wide == 0 && mb.v == 2);
    k = coin(&b, 0, 0, 500000, 0xee);
    CHECK(gzp_wport_publish(&b, &k, &h, 1, 110) == 0);
    CHECK(plan(&b, 300000, tx, &len) == 1);
    CHECK(b.plans[0].info.change_index == 2);   /* not 1, the spend-back's */
    gzp_wport_close(&b);
}

/* B2-1 (review B of PR 93): a history of "never used" for an address that has
 * unspent outputs is a server that lies or lags: the address counts as used,
 * the read is not settled. Change address 3, and receive address 0. */
static void test_history_zero_with_outputs(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    gzt_coin c;
    for (int chain = 1; chain >= 0; chain--) {
        memset(&ms, 0, sizeof ms);
        ms.wide = 1;
        open_marked(&w, &ms);
        memset(&f, 0, sizeof f);
        f.tip_before = f.tip_later = 110;
        c = coin(&w, (uint32_t)chain, chain ? 3 : 0, 40000, 0xf1);
        fk_add(&f, &c, 100);
        memcpy(f.hist_script, c.script, 34);
        f.hist_as = GZ_CHAIN_OK;   /* answered with zero counts */
        f.hist_left = 1000000;
        view.ctx = &f;
        view.ops = &fk_ops;
        CHECK(gzp_wport_scan_view(&w, &view) == 1);
        CHECK(w.wide == 1 && ms.cleared == 0);
        if (chain) CHECK(w.next_change >= 4);
        gzp_wport_close(&w);
    }
}

/* B2-4 (review B of PR 93): while a wide read is pending, can_plan cannot
 * tell (coins_unknown), and status.coins says why; a server with no history
 * call says that, not "reading" for ever (review A, round 2). */
static void test_can_plan_while_pending(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    gzt_coin k;
    uint32_t h = 100;
    uint64_t have;
    size_t n;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    k = coin(&w, 0, 0, 500000, 0xf2);
    CHECK(gzp_wport_publish(&w, &k, &h, 1, 110) == 0);
    CHECK(w.port.can_plan(w.port.ctx, 100000, 100, &have, &n) == -1);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    view.ctx = &f;
    view.ops = &fk_ops_nohist;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.wide == 1 && coins_json_has(&w, "\"change_mark\":\"no_history\""));
    gzp_wport_close(&w);
}

/* B2-5 (review B of PR 93): past index 1,000 a wide read goes 200 past the
 * highest used address, so 20 or more abandoned lobbies in a row do not hide
 * the change after them. Change used at 1,150 only. */
static void test_wide_gap_past_1000(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    gzt_coin c;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    c = coin(&w, 1, 1150, 40000, 0xf3);
    fk_add(&f, &c, 100);
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.next_change == 1151 && ms.v == 1151 && w.wide == 0);
    gzp_wport_close(&w);
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* M1 (review A of PR 97), P97-1 (review B): a wide read that does not settle
 * is asked again later and later: the base doubled each time, capped. */
static void test_retry_backs_off(void)
{
    CHECK(gzp_wport_retry_ms(15000, 0) == 15000);
    CHECK(gzp_wport_retry_ms(15000, 1) == 30000);
    CHECK(gzp_wport_retry_ms(15000, 2) == 60000);
    CHECK(gzp_wport_retry_ms(15000, 5) == 480000);
    CHECK(gzp_wport_retry_ms(15000, 6) == GZP_WPORT_RETRY_CAP_MS);
    CHECK(gzp_wport_retry_ms(15000, 1000) == GZP_WPORT_RETRY_CAP_MS);
}

/* P97-1: a history refused: scan_until backs off between the reads; after
 * GZP_WPORT_UNSETTLED_MAX of them it asks again only slowly (R2-3, review B
 * of PR 97), and settles once the refusals stop. */
static void test_refused_for_good_backs_off_and_stops(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    gzt_coin b;
    long t0, dt;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    b = coin(&w, 1, 5, 1, 0);
    memcpy(f.hist_script, b.script, 34);
    f.hist_as = GZ_CHAIN_REJECTED;
    f.hist_left = GZP_WPORT_UNSETTLED_MAX + 3;   /* refused through the tenth read and one slow one */
    f.stop_w = &w;
    f.stop_after = 40;   /* a time limit */
    view.ctx = &f;
    view.ops = &fk_ops;
    w.slow_retry_ms = 300;
    t0 = now_ms();
    CHECK(gzp_wport_scan_until(&w, &view, 2) == 1);
    dt = now_ms() - t0;
    /* two refusals asked again 2 and 4 ms apart (R2-1), GZP_WPORT_UNSETTLED_MAX
     * reads that did not settle 2, 4, ... 512 ms apart, then slowly (300 ms
     * here, an hour in the program), until the read settles */
    CHECK(f.tip_calls == GZP_WPORT_UNSETTLED_MAX + 4);
    if (dt < 1600) fprintf(stderr, "scan_until took %ld ms, want at least 1600 (the backoff)\n", dt);
    CHECK(dt >= 1600);   /* the waits alone; each read itself takes a while (1,200 addresses) */
    CHECK(w.wide == 0 && ms.cleared == 1);
    CHECK(coins_json_has(&w, "\"change_mark\":\"kept\""));
    gzp_wport_close(&w);
}

/* P97-1: with no history call the read cannot settle: scan_until stops after
 * the first read and says so (no_history), plans still refused. */
static void test_no_history_stops_asking(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    f.stop_w = &w;
    f.stop_after = 6;
    view.ctx = &f;
    view.ops = &fk_ops_nohist;
    CHECK(gzp_wport_scan_until(&w, &view, 1) == 1);
    CHECK(f.tip_calls == 1 && w.wide == 1);
    CHECK(coins_json_has(&w, "\"change_mark\":\"no_history\""));
    gzp_wport_close(&w);
}

/* P97-4 (review B of PR 97): a server without the history route (404) is
 * no_history too, not a lookup failure asked again for ever. */
static void test_history_route_missing(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    f.hist_unsupported = 1;
    f.stop_w = &w;
    f.stop_after = 6;
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_until(&w, &view, 1) == 1);
    CHECK(f.tip_calls == 1 && w.wide == 1);
    CHECK(coins_json_has(&w, "\"change_mark\":\"no_history\""));
    gzp_wport_close(&w);
}

/* P97-1: a failed key derivation cannot settle either: one read, then stop. */
static void test_failed_derivation_stops_asking(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    open_marked(&w, &ms);
    w.wnet = (gzw_network)77;
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    f.stop_w = &w;
    f.stop_after = 6;
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_until(&w, &view, 1) == 1);
    CHECK(f.tip_calls == 1 && w.wide == 1 && ms.cleared == 0);
    CHECK(coins_json_has(&w, "\"change_mark\":\"derivation_failed\""));
    w.wnet = GZW_NET_SIGNET;
    gzp_wport_close(&w);
}

/* P97-5 (review B of PR 97): change handed out near the end of what a scan
 * reads (a journaled index of 4,076 or above) settles the read with a warning,
 * too_many_addresses, rather than leaving it pending for good: the mark is
 * kept, so nothing below it is handed out again. */
static void test_mark_near_the_end_settles(void)
{
    static gzp_wport_t w;
    mark_store ms;
    fake_chain f;
    gz_chain view;
    memset(&ms, 0, sizeof ms);
    ms.wide = 1;
    ms.v = 4080;
    open_marked(&w, &ms);
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    view.ctx = &f;
    view.ops = &fk_ops;
    CHECK(gzp_wport_scan_view(&w, &view) == 1);
    CHECK(w.wide == 0 && ms.cleared == 1 && ms.v == 4080);
    CHECK(coins_json_has(&w, "\"change_mark\":\"too_many_addresses\""));
    gzp_wport_close(&w);
}

/* R2-1 (review B of PR 97): a read that publishes nothing (an unreachable
 * server, a 5xx, a malformed answer) is asked again later and later too. */
static void test_lookup_failures_back_off(void)
{
    static gzp_wport_t w;
    fake_chain f;
    gz_chain view;
    long t0, dt;
    open_w(&w);
    w.gap = 2;
    memset(&f, 0, sizeof f);
    f.tip_before = f.tip_later = 110;
    f.outputs_fails = 1000000;
    f.stop_w = &w;
    f.stop_after = 8;
    view.ctx = &f;
    view.ops = &fk_ops;
    t0 = now_ms();
    CHECK(gzp_wport_scan_until(&w, &view, 2) == -1);   /* stopped by the test's limit */
    dt = now_ms() - t0;
    CHECK(f.tip_calls == 8);
    /* seven waits, 2, 4, ... 128 ms (a flat 2 ms each before) */
    if (dt < 250) fprintf(stderr, "scan_until took %ld ms, want at least 250 (the backoff)\n", dt);
    CHECK(dt >= 250);
    gzp_wport_close(&w);
}

/* R2-2 (review B of PR 97): no change index near the end of what a scan
 * reads is handed out: the plan is refused, and status says why. */
static void test_change_chain_full(void)
{
    static gzp_wport_t w;
    mark_store ms;
    gzt_coin k;
    uint32_t h = 100;
    uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    k = coin(&w, 0, 0, 500000, 0xf5);
    CHECK(gzp_wport_publish(&w, &k, &h, 1, 110) == 0);
    w.next_change = GZP_WPORT_CHANGE_MAX - 20;   /* 20: the gap a scan reads past the mark */
    CHECK(plan(&w, 100000, tx, &len) == 0);
    CHECK(w.next_change == GZP_WPORT_CHANGE_MAX - 20);
    /* beside the change mark's own state, not over it (L3, review A of PR 101) */
    CHECK(coins_json_has(&w, "\"change_mark\":\"kept\"") && coins_json_has(&w, "\"refused\":\"change_chain_full\""));
    gzp_wport_close(&w);
}

/* P97-3 (review B of PR 97): after a restart the engine gives back a plan
 * from its journal with the outputs its inputs spend; the wallet holds it
 * again, so a spend-back (and the signing) can be made for it. */
static void test_spend_back_after_restart_adopted(void)
{
    static gzp_wport_t a, b;
    mark_store ma, mb;
    gzt_coin k;
    uint32_t h = 100;
    static uint8_t tx[GZ_FUND_MAX_TX], sb[GZ_FUND_MAX_TX], sig[GZ_FUND_MAX_TX];
    gz_fund_prevout_t prev[GZ_FUND_MAX_INPUTS];
    size_t len = 0, n_prev = 0, sbl = 0, sl = 0;
    uint8_t txid[32];
    memset(&ma, 0, sizeof ma);
    memset(&mb, 0, sizeof mb);
    open_marked(&a, &ma);
    k = coin(&a, 0, 0, 500000, 0xf6);
    CHECK(gzp_wport_publish(&a, &k, &h, 1, 110) == 0);
    CHECK(a.port.plan(a.port.ctx, 300000, factory, 100, NULL, tx, sizeof tx, &len, prev, GZ_FUND_MAX_INPUTS, &n_prev) ==
          1);
    memcpy(txid, a.plans[0].info.txid, 32);
    gzp_wport_close(&a);
    open_marked(&b, &mb);   /* the restart */
    k = coin(&b, 0, 0, 500000, 0xf6);
    CHECK(gzp_wport_publish(&b, &k, &h, 1, 110) == 0);
    CHECK(b.port.spend_back(b.port.ctx, txid, 0, 1000, sb, sizeof sb, &sbl) == 0);   /* not held yet */
    CHECK(b.port.adopt_plan != NULL);
    if (b.port.adopt_plan) CHECK(b.port.adopt_plan(b.port.ctx, tx, len, prev, n_prev, factory, 300000, 100) == 1);
    CHECK(memcmp(b.plans[0].info.txid, txid, 32) == 0);
    CHECK(b.port.spend_back(b.port.ctx, txid, 0, 1000, sb, sizeof sb, &sbl) == 1);
    CHECK(b.port.sign_plan(b.port.ctx, txid, sig, sizeof sig, &sl) == 1);
    CHECK(held_by_txid_tag(&b, 0xf6) == 1);   /* its coin is held again */
    gzp_wport_close(&b);
}

/* A plan through the port, with the outputs its inputs spend. */
static int plan_prev(gzp_wport_t *w, uint64_t amount, uint8_t *tx, size_t *len, gz_fund_prevout_t *prev, size_t *n_prev)
{
    return w->port.plan(w->port.ctx, amount, factory, 100, NULL, tx, GZ_FUND_MAX_TX, len, prev, GZ_FUND_MAX_INPUTS,
                        n_prev);
}

/* n coins of 500,000 sat on the first n receive addresses, published. */
static void many_coins(gzp_wport_t *w, int n, uint8_t tag)
{
    static gzt_coin cs[32];
    static uint32_t hs[32];
    for (int i = 0; i < n; i++) {
        cs[i] = coin(w, 0, (uint32_t)i, 500000, (uint8_t)(tag + i));
        hs[i] = 100;
    }
    CHECK(gzp_wport_publish(w, cs, hs, (size_t)n, 110) == 0);
}

/* M-1 (review B of PR 101): as many plans as the engine has factories, 16:
 * a ninth funding in one run is planned. */
static void test_nine_fundings_one_run(void)
{
    static gzp_wport_t w;
    mark_store ms;
    static uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    many_coins(&w, 9, 0x90);
    for (int i = 0; i < 9; i++) CHECK(plan(&w, 100000, tx, &len) == 1);
    gzp_wport_close(&w);
}

/* M-1: a finished factory frees its plan's slot and coins (forget), so a run
 * can fund more than 16 factories. */
static void test_forget_frees_slot(void)
{
    static gzp_wport_t w;
    mark_store ms;
    static uint8_t tx[GZ_FUND_MAX_TX];
    size_t len;
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    many_coins(&w, 1, 0xa0);
    CHECK(w.port.forget != NULL);
    for (int i = 0; i < 20; i++) {
        CHECK(plan(&w, 100000, tx, &len) == 1);
        CHECK(held_by_txid_tag(&w, 0xa0) != 0);
        static const uint8_t none[GZ_FUND_MAX_INPUTS];
        if (w.port.forget) w.port.forget(w.port.ctx, tx, len, none, 1);   /* failed: the coin is free again */
        CHECK(held_by_txid_tag(&w, 0xa0) == 0);
    }
    gzp_wport_close(&w);
}

/* M-1: nine plans from the journal are all held again at a resume. */
static void test_nine_adoptions_at_resume(void)
{
    static gzp_wport_t a, b;
    mark_store ma, mb;
    static uint8_t tx[9][GZ_FUND_MAX_TX];
    static gz_fund_prevout_t prev[9][GZ_FUND_MAX_INPUTS];
    size_t len[9], np[9];
    memset(&ma, 0, sizeof ma);
    memset(&mb, 0, sizeof mb);
    open_marked(&a, &ma);
    many_coins(&a, 9, 0xb0);
    for (int i = 0; i < 9; i++) CHECK(plan_prev(&a, 100000, tx[i], &len[i], prev[i], &np[i]) == 1);
    gzp_wport_close(&a);
    open_marked(&b, &mb);
    many_coins(&b, 9, 0xb0);
    for (int i = 0; i < 9; i++)
        CHECK(b.port.adopt_plan && b.port.adopt_plan(b.port.ctx, tx[i], len[i], prev[i], np[i], factory, 100000, 100) == 1);
    gzp_wport_close(&b);
}

/* M1 (review A of PR 101): a funding without change (its change was dust)
 * is held again after a restart and can be spent back from. */
static void test_adopt_without_change(void)
{
    static gzp_wport_t b;
    mark_store mb;
    static gzt_funding f;
    gzt_funding_request r;
    gzt_coin k;
    uint8_t aux[32];
    static uint8_t tx[GZ_FUND_MAX_TX], sb[GZ_FUND_MAX_TX];
    gz_fund_prevout_t prev[1];
    size_t len = 0, sl = 0, sbl = 0;
    memset(&mb, 0, sizeof mb);
    open_marked(&b, &mb);
    k = coin(&b, 0, 0, 500000, 0xc0);
    memset(&r, 0, sizeof r);
    r.net = GZT_NET_SIGNET;
    r.funding_script = factory;
    r.funding_script_len = 34;
    r.amount = 500000 - 100;   /* what is left after the fee is below dust: no change */
    r.change_index = 7;
    r.fee.rate.sat_per_kvb = 100;
    r.fee.ceiling.sat_per_kvb = 1000;   /* the port's own policy: ten times the rate (adopt checks it) */
    memset(aux, 3, 32);
    {
        gzw_xprv m;   /* the test seed's master: the port keeps none */
        uint8_t sd[64];
        memset(sd, 0x42, 64);
        CHECK(gzw_bip32_master(secp, sd, 64, &m, NULL) == 1);
        CHECK(gzt_funding_build(secp, &m, &r, &k, 1, aux, &f) == GZT_OK && !f.info.has_change);
        gzw_wipe(&m, sizeof m);
    }
    CHECK(gzt_funding_unsigned(&f, tx, sizeof tx, &len) == GZT_OK);
    prev[0].amount = k.amount;
    prev[0].script_len = 34;
    memcpy(prev[0].script, k.script, 34);
    CHECK(b.port.adopt_plan && b.port.adopt_plan(b.port.ctx, tx, len, prev, 1, factory, 500000 - 100, 100) == 1);
    CHECK(b.port.spend_back(b.port.ctx, f.info.txid, 0, 1000, sb, sizeof sb, &sbl) == 1);
    (void)sl;
    gzt_funding_wipe(&f);
    gzp_wport_close(&b);
}

/* L-5 (review B of PR 101): the port refuses a plan that is not this
 * wallet's: a foreign input, a P2WSH script with this wallet's key, foreign
 * change, output 0 or its amount not the engine's, and no free slot. */
static void test_adopt_refusals(void)
{
    static gzp_wport_t a, b;
    mark_store ma, mb;
    static uint8_t tx[GZ_FUND_MAX_TX], bad[GZ_FUND_MAX_TX], other[34];
    gz_fund_prevout_t prev[GZ_FUND_MAX_INPUTS], p2[GZ_FUND_MAX_INPUTS];
    size_t len = 0, np = 0;
    gz_tx_info_t info;
    uint64_t amt;
    const uint8_t *scr = NULL;
    size_t sl;
    memset(&ma, 0, sizeof ma);
    memset(&mb, 0, sizeof mb);
    open_marked(&a, &ma);
    many_coins(&a, 1, 0xd0);
    CHECK(plan_prev(&a, 100000, tx, &len, prev, &np) == 1);
    gzp_wport_close(&a);
    open_marked(&b, &mb);
    CHECK(b.port.adopt_plan != NULL);
    if (!b.port.adopt_plan) {
        gzp_wport_close(&b);
        return;
    }
    memcpy(p2, prev, sizeof prev);
    p2[0].script[10] ^= 1;   /* a foreign input */
    CHECK(b.port.adopt_plan(b.port.ctx, tx, len, p2, np, factory, 100000, 100) == 0);
    memcpy(p2, prev, sizeof prev);
    p2[0].script[0] = 0x00;   /* P2WSH, this wallet's key bytes */
    CHECK(b.port.adopt_plan(b.port.ctx, tx, len, p2, np, factory, 100000, 100) == 0);
    memcpy(bad, tx, len);   /* foreign change: output 1's key changed */
    CHECK(gz_tx_parse(bad, len, &info) && gz_tx_output(bad, len, &info, 1, &amt, &scr, &sl) && sl == 34);
    if (scr) bad[(size_t)(scr - bad) + 10] ^= 1;
    CHECK(b.port.adopt_plan(b.port.ctx, bad, len, prev, np, factory, 100000, 100) == 0);
    memcpy(other, factory, 34);
    other[5] ^= 1;
    CHECK(b.port.adopt_plan(b.port.ctx, tx, len, prev, np, other, 100000, 100) == 0);   /* output 0 not the engine's */
    CHECK(b.port.adopt_plan(b.port.ctx, tx, len, prev, np, factory, 100001, 100) == 0);  /* nor its amount */
    {
        static uint8_t t2[GZ_FUND_MAX_TX];
        size_t l2;
        many_coins(&b, (int)GZP_WPORT_PLANS, 0x40);   /* every slot taken */
        for (int i = 0; i < (int)GZP_WPORT_PLANS; i++) CHECK(plan(&b, 100000, t2, &l2) == 1);
        CHECK(b.port.adopt_plan(b.port.ctx, tx, len, prev, np, factory, 100000, 100) == 0);
    }
    gzp_wport_close(&b);
}

/* L-4 (review B of PR 101): with no wide read pending, a scan that published
 * nothing is asked again at most 2 minutes apart, not 10. */
static void test_failed_retry_caps(void)
{
    CHECK(gzp_wport_failed_retry_ms(15000, 1, 0) == 30000);
    CHECK(gzp_wport_failed_retry_ms(15000, 5, 0) == GZP_WPORT_RETRY_CAP_PLAIN_MS);
    CHECK(gzp_wport_failed_retry_ms(15000, 5, 1) == 480000);
    CHECK(gzp_wport_failed_retry_ms(15000, 50, 1) == GZP_WPORT_RETRY_CAP_MS);
}

/* F-1 (review B of PR 101, round 2): a factory gone live spent its plan's
 * coins: forget drops them from the list, so the next plan cannot pick a
 * spent coin (its broadcast would be refused, missing inputs). */
static void test_forget_live_drops_coins(void)
{
    static gzp_wport_t w;
    mark_store ms;
    static uint8_t tx[GZ_FUND_MAX_TX], t2[GZ_FUND_MAX_TX];
    gz_fund_prevout_t prev[GZ_FUND_MAX_INPUTS];
    size_t len = 0, l2 = 0, np = 0;
    uint8_t spent[GZ_FUND_MAX_INPUTS];
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    many_coins(&w, 2, 0xe0);   /* 0xe0 at receive 0, 0xe1 at receive 1 */
    CHECK(plan_prev(&w, 100000, tx, &len, prev, &np) == 1 && np == 1);
    int first = held_by_txid_tag(&w, 0xe0) ? 0xe0 : 0xe1;
    memset(spent, 1, sizeof spent);
    if (w.port.forget) w.port.forget(w.port.ctx, tx, len, spent, np);   /* live */
    CHECK(held_by_txid_tag(&w, (uint8_t)first) == -1);   /* gone from the list */
    CHECK(plan(&w, 100000, t2, &l2) == 1);
    CHECK(held_by_txid_tag(&w, (uint8_t)(first ^ 1)) == 1);   /* the other coin */
    gzp_wport_close(&w);
}

/* F-1: a dead factory: the input spent elsewhere leaves the list, the others
 * are the wallet's again. */
static void test_forget_dead_mix(void)
{
    static gzp_wport_t w;
    mark_store ms;
    static uint8_t tx[GZ_FUND_MAX_TX], t2[GZ_FUND_MAX_TX];
    gz_fund_prevout_t prev[GZ_FUND_MAX_INPUTS];
    size_t len = 0, l2 = 0, np = 0;
    uint8_t spent[GZ_FUND_MAX_INPUTS];
    gzt_tx parsed;
    int a, b;
    memset(&ms, 0, sizeof ms);
    open_marked(&w, &ms);
    many_coins(&w, 2, 0xf0);
    CHECK(plan_prev(&w, 700000, tx, &len, prev, &np) == 1 && np == 2);   /* both coins */
    CHECK(gzt_tx_parse(tx, len, &parsed) == GZT_OK);
    a = parsed.in[0].prev_txid[0];   /* input 0: spent elsewhere */
    b = parsed.in[1].prev_txid[0];
    memset(spent, 0, sizeof spent);
    spent[0] = 1;
    if (w.port.forget) w.port.forget(w.port.ctx, tx, len, spent, np);   /* dead */
    CHECK(held_by_txid_tag(&w, (uint8_t)a) == -1);   /* gone */
    CHECK(held_by_txid_tag(&w, (uint8_t)b) == 0);    /* the wallet's again, free */
    CHECK(plan(&w, 100000, t2, &l2) == 1 && held_by_txid_tag(&w, (uint8_t)b) == 1);
    gzp_wport_close(&w);
}

/* The boundary review of PR 101: a journaled plan changed to pay a dear fee
 * (its change lowered) is not adopted: nothing is held, so nothing is signed. */
static void test_adopt_refuses_dear_fee(void)
{
    static gzp_wport_t a, b;
    mark_store ma, mb;
    static uint8_t tx[GZ_FUND_MAX_TX];
    gz_fund_prevout_t prev[GZ_FUND_MAX_INPUTS];
    size_t len = 0, np = 0;
    gz_tx_info_t info;
    uint64_t amt, v = 0;
    const uint8_t *scr = NULL;
    size_t sl = 0;
    memset(&ma, 0, sizeof ma);
    memset(&mb, 0, sizeof mb);
    open_marked(&a, &ma);
    many_coins(&a, 1, 0xd8);
    CHECK(plan_prev(&a, 100000, tx, &len, prev, &np) == 1);
    gzp_wport_close(&a);
    CHECK(gz_tx_parse(tx, len, &info) && gz_tx_output(tx, len, &info, 1, &amt, &scr, &sl) && sl == 34 && scr);
    if (scr) {   /* output 1's value: the 8 bytes before its script's length */
        uint8_t *p = (uint8_t *)(uintptr_t)(scr - 9);
        for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
        v -= 50000;
        for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
    }
    open_marked(&b, &mb);
    CHECK(b.port.adopt_plan && b.port.adopt_plan(b.port.ctx, tx, len, prev, np, factory, 100000, 100) == 0);
    for (int k = 0; k < (int)GZP_WPORT_PLANS; k++) CHECK(!b.used[k]);
    gzp_wport_close(&b);
}

int main(void)
{
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    factory[0] = 0x51;
    factory[1] = 0x20;
    memset(factory + 2, 0xab, 32);
    test_master_not_kept();
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
    test_change_seen_after_restart();
    test_change_gap_limit();
    test_unconfirmed_change_counts();
    test_change_after_released_plans();
    test_chained_change_after_restart();
    test_mark_saved_before_use();
    test_unsent_index_handed_back();
    test_sent_index_kept();
    test_no_marks_refused();
    test_wide_scan_without_mark();
    test_wide_reads_spent_change();
    test_wide_history_refused();
    test_wide_history_disagree();
    test_left_out_change_counts_used();
    test_dust_past_cap_after_restore();
    test_refusal_past_256_asked_again();
    test_adopt_raises_mark();
    test_failed_derivation_keeps_wide();
    test_wide_pending_kept_and_plans_refused();
    test_not_opened_told();
    test_spend_back_during_pending_read();
    test_pending_read_asked_again();
    test_journaled_spend_back_raises_mark();
    test_history_zero_with_outputs();
    test_can_plan_while_pending();
    test_wide_gap_past_1000();
    test_retry_backs_off();
    test_refused_for_good_backs_off_and_stops();
    test_no_history_stops_asking();
    test_history_route_missing();
    test_failed_derivation_stops_asking();
    test_mark_near_the_end_settles();
    test_lookup_failures_back_off();
    test_change_chain_full();
    test_spend_back_after_restart_adopted();
    test_nine_fundings_one_run();
    test_forget_frees_slot();
    test_nine_adoptions_at_resume();
    test_adopt_without_change();
    test_adopt_refusals();
    test_failed_retry_caps();
    test_forget_live_drops_coins();
    test_forget_dead_mix();
    test_adopt_refuses_dear_fee();
    secp256k1_context_destroy(secp);
    printf("program_wport: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
