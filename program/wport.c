/* The funding engine's wallet port over wallet/tx: see wport.h. */
#include "wport.h"

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "gazpacho/chain.h"
#ifdef GZP_HAVE_CURL
#include "gazpacho/chain_esplora.h"
#include "gazpacho/chain_http.h"
#endif
#include "gzp.h"

static int out_of(gzp_wport_t *w, uint32_t change, uint32_t j, gzw_bip86_output *o)
{
    gzw_reason why;
    return gzw_bip86_output_from_master(w->secp, &w->master, w->wnet, 0, change, j, o, &why) == 1;
}

static gzt_funding *by_tx(gzp_wport_t *w, const uint8_t *tx, size_t len, int *k_out)
{
    uint8_t buf[GZ_FUND_MAX_TX];
    size_t n;
    for (int k = 0; k < GZP_WPORT_PLANS; k++)
        if (w->used[k] && gzt_funding_unsigned(&w->plans[k], buf, sizeof buf, &n) == GZT_OK && n == len &&
            memcmp(buf, tx, n) == 0) {
            if (k_out) *k_out = k;
            return &w->plans[k];
        }
    return NULL;
}

static void unhold(gzp_wport_t *w, int k)
{
    for (size_t i = 0; i < w->n_coins; i++)
        if (w->held[i] == k + 1) w->held[i] = 0;
}

static int w_plan(void *ctx, uint64_t amount, const uint8_t script[34], uint64_t feerate, const gz_outpoint_t *must,
                  uint8_t *tx, size_t cap, size_t *tx_len, gz_fund_prevout_t *prev, size_t max_prev, size_t *n_prev)
{
    gzp_wport_t *w = ctx;
    static gzt_coin offer[GZP_WPORT_COINS];
    size_t map[GZP_WPORT_COINS], n = 0;
    gzt_funding_request req;
    uint8_t aux[32];
    int k;
    if (!w->have_master) return 0;
    for (k = 0; k < GZP_WPORT_PLANS && w->used[k]; k++) {}
    if (k == GZP_WPORT_PLANS) return 0;
    for (size_t i = 0; i < w->n_coins; i++)
        if (!w->held[i]) { map[n] = i; offer[n++] = w->coins[i]; }
    memset(&req, 0, sizeof req);
    req.net = w->net;
    req.account = 0;
    req.funding_script = script;
    req.funding_script_len = 34;
    req.amount = amount;
    req.change_index = w->next_change++;
    req.require_change = 1;              /* H16: change for a child */
    req.fee.rate.sat_per_kvb = feerate;
    req.fee.ceiling.sat_per_kvb = feerate * 10;
    if (must) {                          /* H11: the previous plan's input 0 */
        req.must_spend = 1;
        memcpy(req.must_txid, must->txid, 32);
        req.must_vout = must->vout;
    }
    gzp_os_random(aux, sizeof aux);
    if (gzt_funding_build(w->secp, &w->master, &req, offer, n, aux, &w->plans[k]) != GZT_OK) {
        gzp_log("wallet-plan-refused coins=%zu amount=%llu", n, (unsigned long long)amount);
        return 0;
    }
    if (gzt_funding_unsigned(&w->plans[k], tx, cap, tx_len) != GZT_OK ||
        w->plans[k].info.selection.n_selected > max_prev) {
        gzt_funding_wipe(&w->plans[k]);
        return 0;
    }
    for (uint32_t i = 0; i < w->plans[k].info.selection.n_selected; i++) {
        size_t l;
        if (gzt_funding_prevout(&w->plans[k], i, &prev[i].amount, prev[i].script, GZ_FUND_MAX_SCRIPT, &l) != GZT_OK) {
            gzt_funding_wipe(&w->plans[k]);
            return 0;
        }
        prev[i].script_len = (uint8_t)l;
        w->held[map[w->plans[k].info.selection.selected[i]]] = (uint8_t)(k + 1);
    }
    *n_prev = w->plans[k].info.selection.n_selected;
    w->used[k] = 1;
    gzp_log("wallet-plan inputs=%zu fee=%llu", *n_prev, (unsigned long long)w->plans[k].info.fee);
    return 1;
}

/* Signs only a plan this wallet holds, found by its txid (docs/notes/signer.md). */
static int w_sign_plan(void *ctx, const uint8_t txid[32], uint8_t *out, size_t cap, size_t *out_len)
{
    gzp_wport_t *w = ctx;
    uint8_t aux[32];
    gzp_os_random(aux, sizeof aux);
    for (int k = 0; k < GZP_WPORT_PLANS; k++)
        if (w->used[k] && memcmp(w->plans[k].info.txid, txid, 32) == 0)
            return gzt_funding_release(w->secp, &w->master, &w->plans[k], txid, aux, out, cap, out_len) == GZT_OK;
    return 0;
}

/* Holds again only a plan this run made, with its change (the stand-in of wport.h). */
static int w_adopt(void *ctx, const uint8_t *tx, size_t len, uint32_t vout)
{
    gzp_wport_t *w = ctx;
    gzt_funding *f = by_tx(w, tx, len, NULL);
    return f && f->info.has_change && vout == f->info.vout;
}

static void w_release(void *ctx, const uint8_t *tx, size_t len)
{
    gzp_wport_t *w = ctx;
    int k;
    if (!by_tx(w, tx, len, &k)) return;
    unhold(w, k);
    gzt_funding_wipe(&w->plans[k]);
    w->used[k] = 0;
}

static int w_spend_back(void *ctx, const uint8_t *tx, size_t len, uint32_t index, uint64_t fee, uint8_t *out,
                        size_t cap, size_t *out_len)
{
    gzp_wport_t *w = ctx;
    gzt_funding *f = by_tx(w, tx, len, NULL);
    gzw_bip86_output dest;
    uint8_t aux[32];
    if (!f || !out_of(w, 1, w->next_change++, &dest)) return 0;
    gzp_os_random(aux, sizeof aux);
    return gzt_funding_spend_back(w->secp, &w->master, f, index, dest.script_pubkey, sizeof dest.script_pubkey, fee,
                                  aux, out, cap, out_len) == GZT_OK;
}

int gzp_wport_open(gzp_wport_t *w, const secp256k1_context *secp, const gzp_unlock_t *unlock, gzw_network wnet)
{
    uint8_t seed[64];
    gzw_reason why;
    memset(w, 0, sizeof *w);
    w->secp = secp;
    w->wnet = wnet;
    switch (wnet) {
    case GZW_NET_SIGNET: w->net = GZT_NET_SIGNET; break;
    case GZW_NET_REGTEST: w->net = GZT_NET_REGTEST; break;
    case GZW_NET_TESTNET4: w->net = GZT_NET_TESTNET4; break;
    default: return -1;                  /* never mainnet */
    }
    if (!unlock || !unlock->seed || unlock->seed(unlock->ctx, seed) != 0) return -1;
    w->have_master = gzw_bip32_master(secp, seed, sizeof seed, &w->master, &why) == 1;
    OPENSSL_cleanse(seed, sizeof seed);
    if (!w->have_master) return -1;
    w->next_change = 100;
    w->port.plan = w_plan;
    w->port.sign_plan = w_sign_plan;
    w->port.adopt = w_adopt;
    w->port.release = w_release;
    w->port.spend_back = w_spend_back;
    w->port.ctx = w;
    return 0;
}

int gzp_wport_scan(gzp_wport_t *w, const char *url, uint32_t gap)
{
#ifdef GZP_HAVE_CURL
    static gz_chain_output outs[32];
    gz_http http;
    gz_http_curl_config hc;
    gz_esplora_config cfg;
    gz_chain view;
    uint64_t total = 0;
    int failed = 0;
    if (!w->have_master || !url) return -1;
    memset(&hc, 0, sizeof hc);
    if (!gz_http_curl_create(&http, &hc)) return -1;
    gz_esplora_config_default(&cfg);
    cfg.base_url = url;
    if (gz_esplora_create(&cfg, &http, &view) != GZ_CHAIN_OK) {
        gz_http_curl_destroy(&http);
        return -1;
    }
    for (uint32_t change = 0; change < 2; change++)
        for (uint32_t j = 0; j < gap; j++) {
            gzw_bip86_output o;
            size_t n = 0;
            if (!out_of(w, change, j, &o)) {
                failed = 1;
                break;
            }
            if (gz_chain_script_outputs(&view, o.script_pubkey, sizeof o.script_pubkey, outs, 32, &n, NULL) !=
                GZ_CHAIN_OK) {
                failed = 1;
                continue;
            }
            for (size_t i = 0; i < n && w->n_coins < GZP_WPORT_COINS; i++) {
                gzt_coin *c = &w->coins[w->n_coins];
                if (!outs[i].confirmed) continue;   /* confirmed coins only (review A of PR 56, M5) */
                memcpy(c->txid, outs[i].txid, 32);
                c->vout = outs[i].vout;
                c->amount = outs[i].value;
                c->change = change;
                c->index = j;
                memcpy(c->script, o.script_pubkey, 34);
                total += c->amount;
                w->n_coins++;
                if (change == 1 && j + 100 > w->next_change) w->next_change = j + 100;
            }
        }
    gz_chain_destroy(&view);
    gz_http_curl_destroy(&http);
    gzp_log("wallet-coins count=%zu total_sat=%llu lookups-failed=%d", w->n_coins, (unsigned long long)total, failed);
    return (int)w->n_coins;
#else
    (void)w;
    (void)url;
    (void)gap;
    return -1;
#endif
}

int gzp_wport_invent(gzp_wport_t *w)
{
    gzw_bip86_output o;
    gzt_coin *c;
    if (!w->have_master || w->n_coins || !out_of(w, 0, 0, &o)) return -1;
    c = &w->coins[w->n_coins++];
    SHA256((const unsigned char *)"gazpacho/test-invented-coin", 27, c->txid);
    c->vout = 0;
    c->amount = 1000000000;   /* 10 coins: an invented one, never on any chain */
    c->change = 0;
    c->index = 0;
    memcpy(c->script, o.script_pubkey, 34);
    gzp_log("wallet-coins invented=1 (test build, no chain)");
    return 0;
}

void gzp_wport_close(gzp_wport_t *w)
{
    for (int k = 0; k < GZP_WPORT_PLANS; k++)
        if (w->used[k]) gzt_funding_wipe(&w->plans[k]);
    OPENSSL_cleanse(w, sizeof *w);
}
