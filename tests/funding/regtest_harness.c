/* gz-funding-harness: the funding engine (host) over the real wallet
 * (wallet/tx: gzt_funding_build, _unsigned, _prevout, _release,
 * _spend_back), driven line by line on stdin by tools/regtest-funding.py,
 * which relays its broadcasts and watches to a regtest bitcoind.
 * Regtest only: the key is a fixed test seed.
 *
 * In:  scripts N | coin TXID VOUT AMOUNT INDEX | inc LOW HIGH | plan AMOUNT SCRIPT
 *      | fund | tip H | conf TXID C H | spent TXID VOUT SPENDER C
 *      | bres TXID ok|refused|unreachable | tick | quit
 * Out: script I HEX | plan ok HEX | plan fail | broadcast HEX | watch_tx TXID
 *      | watch_op TXID VOUT | save STATE | report KIND | h1 N | ok
 * Every TXID in the internal byte order (the driver reverses for RPC). */
#include "gazpacho/funding.h"
#include "gazpacho/wallet_tx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static secp256k1_context *ctx;
static gzw_xprv master;
static gzt_coin coins[64];
static size_t n_coins;
static gzt_funding fundings[8];
static size_t n_fundings;
static uint32_t next_change = 1000;

static void hex(const uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", p[i]); }
static int unhex(const char *s, uint8_t *out, size_t cap, size_t *n)
{
    size_t l = strlen(s);
    if (l % 2 || l / 2 > cap) return 0;
    for (size_t i = 0; i < l / 2; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    *n = l / 2;
    return 1;
}

static gzt_funding *by_tx(const uint8_t *tx, size_t len)
{
    uint8_t buf[GZ_FUND_MAX_TX];
    size_t n;
    for (size_t i = 0; i < n_fundings; i++)
        if (gzt_funding_unsigned(&fundings[i], buf, sizeof buf, &n) == GZT_OK && n == len && !memcmp(buf, tx, n))
            return &fundings[i];
    return NULL;
}

static int w_plan(void *c, uint64_t amount, const uint8_t script[34], uint64_t feerate, const gz_outpoint_t *must,
                  uint8_t *tx, size_t cap, size_t *tx_len, gz_fund_prevout_t *prev, size_t max_prev, size_t *n_prev)
{
    gzt_funding_request req;
    uint8_t aux[32];
    gzt_funding *f;
    (void)c;
    if (n_fundings == 8) return 0;
    f = &fundings[n_fundings];
    memset(&req, 0, sizeof req);
    req.net = GZT_NET_REGTEST;
    req.funding_script = script;
    req.funding_script_len = 34;
    req.amount = amount;
    req.change_index = next_change++;
    req.require_change = 1;   /* H16: change for a child */
    if (must) {
        req.must_spend = 1;   /* H11: the previous plan's input 0 */
        memcpy(req.must_txid, must->txid, 32);
        req.must_vout = must->vout;
    }
    req.fee.rate.sat_per_kvb = feerate;
    req.fee.ceiling.sat_per_kvb = feerate * 10;
    memset(aux, 0x11, 32);
    if (gzt_funding_build(ctx, &master, &req, coins, n_coins, aux, f) != GZT_OK) return 0;
    if (gzt_funding_unsigned(f, tx, cap, tx_len) != GZT_OK) return 0;
    if (f->info.selection.n_selected > max_prev) return 0;
    for (uint32_t i = 0; i < f->info.selection.n_selected; i++) {
        size_t l;
        if (gzt_funding_prevout(f, i, &prev[i].amount, prev[i].script, GZ_FUND_MAX_SCRIPT, &l) != GZT_OK) return 0;
        prev[i].script_len = (uint8_t)l;
    }
    *n_prev = f->info.selection.n_selected;
    n_fundings++;
    return 1;
}

/* Signs only a plan this wallet built, found by its txid. */
static int w_sign_plan(void *c, const uint8_t txid[32], uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t buf[GZ_FUND_MAX_TX], id[32], aux[32];
    size_t n;
    (void)c;
    memset(aux, 0x22, 32);
    for (size_t i = 0; i < n_fundings; i++) {
        gzt_funding *f = &fundings[i];
        if (gzt_funding_unsigned(f, buf, sizeof buf, &n) != GZT_OK) continue;
        gz_tx_txid(buf, n, id);
        if (memcmp(id, txid, 32) == 0)
            return gzt_funding_release(ctx, &master, f, f->info.txid, aux, out, cap, out_len) == GZT_OK;
    }
    return 0;
}
/* The harness never restarts: it adopts only a plan it built, with change. */
static int w_adopt(void *c, const uint8_t *tx, size_t len, const uint8_t script[34], uint64_t amount)
{
    gzt_funding *f = by_tx(tx, len);
    (void)c;
    return f && f->info.has_change && f->info.amount == amount &&
           memcmp(f->priv_tx.out[0].script, script, 34) == 0;
}
static void w_release(void *c, const uint8_t *tx, size_t len) { (void)c; (void)tx; (void)len; }
/* The spend-back of a plan this wallet built, found by its txid. */
static int w_sb(void *c, const uint8_t txid[32], uint32_t index, uint64_t fee, uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t buf[GZ_FUND_MAX_TX], id[32], aux[32];
    gzw_bip86_output dest;
    size_t n;
    (void)c;
    memset(aux, 0x33, 32);
    if (!gzw_bip86_output_from_master(ctx, &master, GZW_NET_REGTEST, 0, 1, 2000, &dest, NULL)) return 0;
    for (size_t i = 0; i < n_fundings; i++) {
        gzt_funding *f = &fundings[i];
        if (gzt_funding_unsigned(f, buf, sizeof buf, &n) != GZT_OK) continue;
        gz_tx_txid(buf, n, id);
        if (memcmp(id, txid, 32) == 0)
            return gzt_funding_spend_back(ctx, &master, f, index, dest.script_pubkey, 34, fee, aux, out, cap, out_len) ==
                   GZT_OK;
    }
    return 0;
}

static gz_status_t h_report(void *c, const gz_fund_report_t *r, gz_action_list_t *out)
{
    (void)c; (void)out;
    printf("report %d\n", (int)r->kind);
    return GZ_OK;
}

static void print_actions(const gz_action_list_t *l)
{
    for (size_t i = 0; i < l->count; i++) {
        const gz_action_t *a = &l->slots[i];
        switch (a->kind) {
        case GZ_ACTION_BROADCAST: printf("broadcast "); hex(a->u.broadcast.tx.data, a->u.broadcast.tx.len); printf("\n"); break;
        case GZ_ACTION_WATCH_TX: printf("watch_tx "); hex(a->u.watch_tx.txid, 32); printf("\n"); break;
        case GZ_ACTION_WATCH_OUTPOINT:
            printf("watch_op "); hex(a->u.watch_outpoint.outpoint.txid, 32);
            printf(" %u\n", (unsigned)a->u.watch_outpoint.outpoint.vout);
            break;
        case GZ_ACTION_SAVE:
            for (size_t k = 0; k < a->u.save.n_records; k++) {
                gz_bytes_t v;
                if (a->u.save.records[k].type == GZ_FUND_REC_STATUS && gz_rec_find(a->u.save.records[k].bytes, 6, &v) == 1)
                    printf("save %u\n", v.data[0]);
            }
            break;
        default: break;
        }
    }
}

static uint64_t now(void *c) { (void)c; return 1; }
static void rnd(void *c, gz_random_purpose_t p, uint8_t *o, size_t n) { (void)c; (void)p; memset(o, 1, n); }

int main(void)
{
    static gz_fund_t f;
    static gz_action_t slots[64];
    static uint8_t bytes[GZ_FUND_MAX_STEP_BYTES + 4096];
    static char line[70000];
    static uint8_t buf[GZ_FUND_MAX_SIGNED], plan_tx[GZ_FUND_MAX_TX];
    size_t plan_len = 0;
    uint8_t scope[32], seed[32];
    gz_fund_config_t cfg;
    gz_ports_t ports;
    gz_action_list_t out;
    memset(scope, 0x5c, 32);
    memset(seed, 0x42, 32);   /* a fixed regtest test seed */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!gzw_bip32_master(ctx, seed, 32, &master, NULL)) return 2;
    gz_fund_config_default(&cfg, 1);
    cfg.wallet.plan = w_plan; cfg.wallet.sign_plan = w_sign_plan; cfg.wallet.adopt = w_adopt;
    cfg.wallet.release = w_release; cfg.wallet.spend_back = w_sb;
    cfg.hooks.report = h_report;
    memset(&ports, 0, sizeof ports);
    ports.clock.now_ms = now; ports.clock.mono_ms = now; ports.random.fill = rnd;
    if (gz_fund_init(&f, &cfg, &ports) != GZ_OK) return 2;
    gz_action_list_init(&out, slots, 64, bytes, sizeof bytes);
    setvbuf(stdout, NULL, _IOLBF, 0);
    while (fgets(line, sizeof line, stdin)) {
        char a1[70000], a2[200], a3[200], a4[200];
        gz_event_t e;
        size_t n;
        line[strcspn(line, "\n")] = 0;
        memset(&e, 0, sizeof e);
        gz_action_list_reset(&out);
        a1[0] = a2[0] = a3[0] = a4[0] = 0;
        if (!strncmp(line, "quit", 4)) break;
        if (sscanf(line, "scripts %s", a1) == 1) {
            for (int i = 0; i < atoi(a1); i++) {
                gzw_bip86_output o;
                if (!gzw_bip86_output_from_master(ctx, &master, GZW_NET_REGTEST, 0, 0, (uint32_t)i, &o, NULL)) return 3;
                printf("script %d ", i); hex(o.script_pubkey, 34); printf("\n");
            }
        } else if (sscanf(line, "coin %s %s %s %s", a1, a2, a3, a4) == 4 && n_coins < 64) {
            gzt_coin *c = &coins[n_coins];
            gzw_bip86_output o;
            memset(c, 0, sizeof *c);
            if (!unhex(a1, c->txid, 32, &n) || n != 32) return 3;
            c->vout = (uint32_t)atoi(a2);
            c->amount = strtoull(a3, NULL, 10);
            c->index = (uint32_t)atoi(a4);
            if (!gzw_bip86_output_from_master(ctx, &master, GZW_NET_REGTEST, 0, 0, c->index, &o, NULL)) return 3;
            memcpy(c->script, o.script_pubkey, 34);
            n_coins++;
        } else if (sscanf(line, "inc %s %s", a1, a2) == 2) {
            cfg.incremental = strtoull(a1, NULL, 10);
            cfg.incremental_high = strtoull(a2, NULL, 10);
            f.cfg.incremental = cfg.incremental;
            f.cfg.incremental_high = cfg.incremental_high;
        } else if (sscanf(line, "plan %s %s", a1, a2) == 2 || sscanf(line, "replan %s %s", a1, a2) == 2) {
            gz_fund_plan_in_t in;
            gz_fund_plan_out_t res;
            memset(&in, 0, sizeof in);
            memcpy(in.scope, scope, 32);
            in.amount = strtoull(a1, NULL, 10);
            in.released = line[0] == 'r';   /* H11: a partial signature was released */
            if (!unhex(a2, in.script, 34, &n) || n != 34) return 3;
            if (gz_fund_host_plan(&f, &in, &out, &res) != GZ_OK) return 4;
            if (res.ok) {
                memcpy(plan_tx, res.tx, res.tx_len);
                plan_len = res.tx_len;
                printf("plan ok "); hex(res.tx, res.tx_len); printf("\n");
            } else printf("plan fail\n");
        } else if (!strcmp(line, "fund")) {
            gz_fund_h1_in_t h;
            uint8_t acked[1] = { 1 }, sig[1] = { 1 };
            memset(&h, 0, sizeof h);
            memcpy(h.scope, scope, 32);
            h.n_members = 1; h.acked = acked; h.n_nodes = 1; h.signed_ok = sig;
            h.proposed_tx = plan_tx; h.proposed_len = plan_len;
            printf("h1 %d\n", gz_fund_host_h1(&f, &h));
            if (gz_fund_host_apply(&f, scope, &out) != GZ_OK) return 4;
        } else if (sscanf(line, "tip %s", a1) == 1) {
            e.kind = GZ_EVENT_CHAIN; e.u.chain.kind = GZ_CHAIN_NEW_TIP; e.u.chain.height = (uint32_t)atoi(a1);
            if (gz_fund_handle(&f, &e, &out) != GZ_OK) return 4;
        } else if (sscanf(line, "synced %s", a1) == 1) {
            /* the driver, as the chain view, has told every fact for that tip (B12) */
            e.kind = GZ_EVENT_CHAIN; e.u.chain.kind = GZ_CHAIN_TIP_SYNCED; e.u.chain.height = (uint32_t)atoi(a1);
            if (gz_fund_handle(&f, &e, &out) != GZ_OK) return 4;
        } else if (sscanf(line, "conf %s %s %s", a1, a2, a3) == 3) {
            e.kind = GZ_EVENT_CHAIN;
            e.u.chain.kind = atoi(a2) ? GZ_CHAIN_TX_CONFIRMED : GZ_CHAIN_TX_UNCONFIRMED;
            if (!unhex(a1, e.u.chain.txid, 32, &n)) return 3;
            e.u.chain.confirmations = (uint32_t)atoi(a2); e.u.chain.height = (uint32_t)atoi(a3);
            if (gz_fund_handle(&f, &e, &out) != GZ_OK) return 4;
        } else if (sscanf(line, "spent %s %s %s %s", a1, a2, a3, a4) == 4) {
            e.kind = GZ_EVENT_CHAIN; e.u.chain.kind = GZ_CHAIN_OUTPOINT_SPENT;
            if (!unhex(a1, e.u.chain.outpoint.txid, 32, &n) || !unhex(a3, e.u.chain.txid, 32, &n)) return 3;
            e.u.chain.outpoint.vout = (uint32_t)atoi(a2); e.u.chain.confirmations = (uint32_t)atoi(a4);
            if (gz_fund_handle(&f, &e, &out) != GZ_OK) return 4;
        } else if (sscanf(line, "bres %s %s", a1, a2) == 2) {
            e.kind = GZ_EVENT_CHAIN; e.u.chain.kind = GZ_CHAIN_BROADCAST_RESULT;
            if (!unhex(a1, e.u.chain.txid, 32, &n)) return 3;
            e.u.chain.outcome = !strcmp(a2, "ok") ? GZ_BROADCAST_ACCEPTED
                                : !strcmp(a2, "refused") ? GZ_BROADCAST_REFUSED : GZ_BROADCAST_UNREACHABLE;
            if (gz_fund_handle(&f, &e, &out) != GZ_OK) return 4;
        } else if (!strcmp(line, "tick")) {
            e.kind = GZ_EVENT_TIMER_FIRED; e.u.timer.timer_id = GZ_FUND_TIMER_TICK;
            if (gz_fund_handle(&f, &e, &out) != GZ_OK) return 4;
        } else {
            fprintf(stderr, "bad line: %.40s\n", line);
            return 5;
        }
        print_actions(&out);
        printf("ok\n");
        (void)buf;
    }
    secp256k1_context_destroy(ctx);
    return 0;
}
