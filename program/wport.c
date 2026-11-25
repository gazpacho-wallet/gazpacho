/* The funding engine's wallet port over wallet/tx: see wport.h. */
#define _POSIX_C_SOURCE 200809L   /* nanosleep */
#include "wport.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

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

/* Every listed coin that a live plan spends is held by that plan: the holds
 * come from the plans' inputs, so a list that missed a held coin, or a tip that
 * moved back, never frees it (review B of PR 83, L-1). Under the mutex. */
static void rehold_locked(gzp_wport_t *w)
{
    memset(w->held, 0, sizeof w->held);
    for (int k = 0; k < GZP_WPORT_PLANS; k++) {
        const gzt_tx *t = &w->plans[k].priv_tx;
        if (!w->used[k]) continue;
        for (uint32_t i = 0; i < t->n_in; i++)
            for (size_t j = 0; j < w->n_coins; j++)
                if (w->coins[j].vout == t->in[i].prev_vout && memcmp(w->coins[j].txid, t->in[i].prev_txid, 32) == 0)
                    w->held[j] = (uint8_t)(k + 1);
    }
}

/* The fee policy of every plan: the engine's rate, a ceiling of ten times it. */
static gzt_fee_policy policy(uint64_t feerate)
{
    gzt_fee_policy p;
    p.rate.sat_per_kvb = feerate;
    p.ceiling.sat_per_kvb = feerate * 10;
    return p;
}

static int plan_locked(void *ctx, uint64_t amount, const uint8_t script[34], uint64_t feerate, const gz_outpoint_t *must,
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
    req.fee = policy(feerate);
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
static int w_adopt(void *ctx, const uint8_t *tx, size_t len, const uint8_t script[34], uint64_t amount)
{
    gzp_wport_t *w = ctx;
    gzt_funding *f = by_tx(w, tx, len, NULL);
    return f && f->info.has_change && f->info.vout == 0 && f->info.amount == amount &&
           memcmp(f->priv_tx.out[0].script, script, 34) == 0;
}

static gzt_funding *by_txid(gzp_wport_t *w, const uint8_t txid[32])
{
    for (int k = 0; k < GZP_WPORT_PLANS; k++)
        if (w->used[k] && memcmp(w->plans[k].info.txid, txid, 32) == 0) return &w->plans[k];
    return NULL;
}

static void release_locked(void *ctx, const uint8_t *tx, size_t len)
{
    gzp_wport_t *w = ctx;
    int k;
    if (!by_tx(w, tx, len, &k)) return;
    unhold(w, k);
    gzt_funding_wipe(&w->plans[k]);
    w->used[k] = 0;
}

/* The coins and their holds, under the mutex the scan publishes with. */
static int w_plan(void *ctx, uint64_t amount, const uint8_t script[34], uint64_t feerate, const gz_outpoint_t *must,
                  uint8_t *tx, size_t cap, size_t *tx_len, gz_fund_prevout_t *prev, size_t max_prev, size_t *n_prev)
{
    gzp_wport_t *w = ctx;
    int r;
    pthread_mutex_lock(&w->mu);
    r = plan_locked(ctx, amount, script, feerate, must, tx, cap, tx_len, prev, max_prev, n_prev);
    pthread_mutex_unlock(&w->mu);
    return r;
}

static void w_release(void *ctx, const uint8_t *tx, size_t len)
{
    gzp_wport_t *w = ctx;
    pthread_mutex_lock(&w->mu);
    release_locked(ctx, tx, len);
    pthread_mutex_unlock(&w->mu);
}

static int w_spend_back(void *ctx, const uint8_t txid[32], uint32_t index, uint64_t fee, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    gzp_wport_t *w = ctx;
    gzt_funding *f = by_txid(w, txid);
    gzw_bip86_output dest;
    uint8_t aux[32];
    if (!f || !out_of(w, 1, w->next_change++, &dest)) return 0;
    gzp_os_random(aux, sizeof aux);
    return gzt_funding_spend_back(w->secp, &w->master, f, index, dest.script_pubkey, sizeof dest.script_pubkey, fee,
                                  aux, out, cap, out_len) == GZT_OK;
}

/* The funds check's dry run (funding.h, can_plan): the coins plan would
 * offer, the selection plan makes, with change, under the same policy. */
static int w_can_plan(void *ctx, uint64_t amount, uint64_t feerate, uint64_t *have_sat, size_t *n_coins)
{
    gzp_wport_t *w = ctx;
    static gzt_coin offer[GZP_WPORT_COINS];
    uint64_t top[GZT_MAX_INPUTS];
    size_t n = 0, nt = 0;
    gzt_selection sel;
    gzt_err e;
    int r;
    *have_sat = 0;
    *n_coins = 0;
    pthread_mutex_lock(&w->mu);
    if (!w->have_master || !w->published) {
        pthread_mutex_unlock(&w->mu);
        return -1;   /* no coin list yet: cannot tell */
    }
    for (size_t i = 0; i < w->n_coins; i++)
        if (!w->held[i]) offer[n++] = w->coins[i];
    /* what a plan could use: the largest GZT_MAX_INPUTS coins */
    for (size_t i = 0; i < n; i++) {
        size_t pos = nt;
        while (pos > 0 && offer[i].amount > top[pos - 1]) pos--;
        if (pos >= GZT_MAX_INPUTS) continue;
        if (nt < GZT_MAX_INPUTS) nt++;
        for (size_t k = nt - 1; k > pos; k--) top[k] = top[k - 1];
        top[pos] = offer[i].amount;
    }
    for (size_t k = 0; k < nt; k++) *have_sat += top[k];
    *n_coins = nt;
    e = gzt_funding_can_plan(offer, n, amount, policy(feerate), &sel);
    r = e == GZT_OK ? 1 : (e == GZT_ERR_FUNDS || e == GZT_ERR_LIMIT || e == GZT_ERR_DUST) ? 0 : -1;
    /* the coins left out of an incomplete list might cover what these do not:
     * "not enough" is not known, so the open answers coins_unknown, with the
     * list's state, rather than a funds_short that does not explain itself
     * (L-2, second review of PR 88) */
    if (r == 0 && w->coin_list.state == GZP_COINS_INCOMPLETE) r = -1;
    pthread_mutex_unlock(&w->mu);
    return r;
}

int gzp_wport_publish(gzp_wport_t *w, const gzt_coin *coins, const uint32_t *heights, size_t n, uint32_t tip)
{
    static gzt_coin keep[GZP_WPORT_COINS];
    size_t nk = 0;
    pthread_mutex_lock(&w->mu);
    for (size_t i = 0; i < n && nk < GZP_WPORT_COINS; i++) {
        /* confirmed only (review A of PR 56, M5); change once buried (B deep),
         * which a funding's change is not before it is buried (N-1) */
        if (heights[i] == 0 || heights[i] > tip) continue;
        if (coins[i].change == 1 && tip - heights[i] + 1 < w->burial) continue;
        keep[nk++] = coins[i];
    }
    memcpy(w->coins, keep, nk * sizeof keep[0]);
    w->n_coins = nk;
    rehold_locked(w);   /* every live plan's coins, in the new list (N-1; L-1) */
    w->published = 1;
    pthread_mutex_unlock(&w->mu);
    OPENSSL_cleanse(keep, sizeof keep);
    return 0;
}

int gzp_wport_open(gzp_wport_t *w, const secp256k1_context *secp, const gzp_unlock_t *unlock, gzw_network wnet,
                   uint32_t burial)
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
    pthread_mutex_init(&w->mu, NULL);
    w->next_change = 100;
    w->port.plan = w_plan;
    w->port.sign_plan = w_sign_plan;
    w->port.adopt = w_adopt;
    w->port.release = w_release;
    w->port.spend_back = w_spend_back;
    w->port.can_plan = w_can_plan;
    w->coin_list.chain = w->coin_list.index = -1;
    {
        gz_fund_config_t fc;   /* the engine's default B, as fundslot.c falls back to it */
        gz_fund_config_default(&fc, 1);
        w->burial = burial ? burial : fc.burial;
    }
    w->port.ctx = w;
    return 0;
}

void gzp_wport_coins(gzp_wport_t *w, gzp_wport_coins_t *out)
{
    pthread_mutex_lock(&w->mu);
    *out = w->coin_list;
    pthread_mutex_unlock(&w->mu);
}

int gzp_wport_coins_json(const gzp_wport_coins_t *c, char *buf, size_t cap)
{
    static const char *const STATE[] = {"scanning", "complete", "incomplete"};
    char reason[48], params[160];
    int n;
    if (c->state < 0 || c->state > GZP_COINS_INCOMPLETE) return -1;
    if (c->reason) snprintf(reason, sizeof reason, "\"%s\"", c->reason);
    else snprintf(reason, sizeof reason, "null");
    if (c->chain >= 0 && c->error)
        snprintf(params, sizeof params, "{\"chain\":%d,\"index\":%d,\"error\":\"%s\"}", c->chain, c->index,
                 c->error);
    else if (c->chain >= 0)
        snprintf(params, sizeof params, "{\"chain\":%d,\"index\":%d}", c->chain, c->index);
    else if (c->error)
        snprintf(params, sizeof params, "{\"error\":\"%s\"}", c->error);
    else if (c->reason && !strcmp(c->reason, "too_many_coins"))
        snprintf(params, sizeof params, "{\"kept\":%d}", GZP_WPORT_COINS);
    else
        snprintf(params, sizeof params, "{}");
    n = snprintf(buf, cap, "{\"state\":\"%s\",\"reason\":%s,\"params\":%s,\"attempts\":%u}", STATE[c->state],
                 reason, params, c->attempts);
    return n < 0 || (size_t)n >= cap ? -1 : n;
}

/* After this many attempts without a complete list, status tells the person (11.4). */
#define GZP_WPORT_ATTENTION_AFTER 3

int gzp_wport_coins_attention(const gzp_wport_coins_t *c)
{
    return c->state == GZP_COINS_INCOMPLETE ||
           (c->state == GZP_COINS_SCANNING && c->attempts >= GZP_WPORT_ATTENTION_AFTER);
}

/* can_plan's -1 is not a locked wallet and not too few coins: its own code
 * (review of PR 88, M-1; local-api.md 8.1). */
const char *gzp_wport_funds_error(gz_fund_funds_t r)
{
    return r == GZ_FUND_FUNDS_OK ? NULL : r == GZ_FUND_FUNDS_SHORT ? "funds_short" : "coins_unknown";
}

int gzp_wport_log_attempt(unsigned n)
{
    return n == 1 || n % 10 == 0;
}

static const char *result_name(gz_chain_result r)
{
    switch (r) {
    case GZ_CHAIN_UNREACHABLE: return "unreachable";
    case GZ_CHAIN_MALFORMED: return "malformed";
    case GZ_CHAIN_TOO_LARGE: return "too_large";
    case GZ_CHAIN_REJECTED: return "rejected";
    case GZ_CHAIN_NOT_FOUND: return "not_found";
    default: return "failed";
    }
}

static void set_coins(gzp_wport_t *w, int state, const char *reason, int chain, int index, const char *error)
{
    pthread_mutex_lock(&w->mu);
    w->coin_list.state = state;
    w->coin_list.reason = reason;
    w->coin_list.chain = chain;
    w->coin_list.index = index;
    w->coin_list.error = error;
    pthread_mutex_unlock(&w->mu);
}

/* The most outputs one address is asked for: the chain port's own cap
 * (GZ_ES_MAX_UTXOS, within its 512 KiB answer buffer). A first lookup asks for
 * GZP_WPORT_FIRST_ASK; only an address with more is asked again at this cap. */
#define GZP_WPORT_ADDR_MAX 1024
#define GZP_WPORT_FIRST_ASK 32
/* A refusal repeated this many scans in a row leaves the address out. */
#define GZP_WPORT_REFUSALS 3

int gzp_wport_scan_view(gzp_wport_t *w, const gz_chain *view)
{
    static gz_chain_output outs[GZP_WPORT_ADDR_MAX];
    static gzt_coin found[GZP_WPORT_COINS];
    static uint32_t heights[GZP_WPORT_COINS];
    gz_chain_tip tip;
    uint64_t total = 0;
    size_t nf = 0;
    uint32_t next_change = 100;
    int failed = 0, truncated = 0;
    const char *left_out = NULL, *left_error = NULL;   /* the first address left out, and why */
    int left_chain = -1, left_index = -1;
    unsigned attempt;
    gz_chain_result tr;
    pthread_mutex_lock(&w->mu);
    attempt = ++w->coin_list.attempts;
    pthread_mutex_unlock(&w->mu);
    /* the tip first, then the heights: a block found during the scan cannot make
     * a change coin look deeper than it is (review B of PR 83, L-2) */
    memset(&tip, 0, sizeof tip);
    tr = gz_chain_tip_get(view, &tip);
    if (tr != GZ_CHAIN_OK || tip.height == 0) {
        set_coins(w, GZP_COINS_SCANNING, "tip", -1, -1, tr != GZ_CHAIN_OK ? result_name(tr) : "malformed");
        if (gzp_wport_log_attempt(attempt)) gzp_log("wallet-coins incomplete why=tip attempt=%u", attempt);
        return 0;
    }
    for (uint32_t change = 0; change < 2 && !w->stop; change++)
        for (uint32_t j = 0; j < w->gap && !w->stop; j++) {
            gzw_bip86_output o;
            size_t n = 0;
            if (!out_of(w, change, j, &o)) {
                failed = 1;
                break;
            }
            gz_chain_result r = gz_chain_script_outputs(view, o.script_pubkey, sizeof o.script_pubkey, outs,
                                                        GZP_WPORT_FIRST_ASK, &n, NULL);
            /* more outputs than a first lookup takes (33 dust outputs anyone
             * can send): asked again at the chain port's own cap (review of PR 88, M-1) */
            if (r == GZ_CHAIN_TOO_LARGE)
                r = gz_chain_script_outputs(view, o.script_pubkey, sizeof o.script_pubkey, outs, GZP_WPORT_ADDR_MAX,
                                            &n, NULL);
            uint8_t *refused = j < GZP_WPORT_GAP_MAX ? &w->refusals[change][j] : NULL;
            if (r == GZ_CHAIN_OK) {
                if (refused) *refused = 0;
            } else if (r == GZ_CHAIN_TOO_LARGE ||
                       ((r == GZ_CHAIN_REJECTED || r == GZ_CHAIN_NOT_FOUND) &&
                        (!refused || ++*refused >= GZP_WPORT_REFUSALS))) {
                /* an address that will not be read, too many outputs even at
                 * the cap, or a refusal again and again: left out, and the list
                 * is published marked incomplete, never held back for good (M-1) */
                if (!left_out) {
                    left_out = r == GZ_CHAIN_TOO_LARGE ? "address_too_large" : "address_refused";
                    left_error = result_name(r);
                    left_chain = (int)change;
                    left_index = (int)j;
                }
                gzp_log("wallet-coins left-out chain=%u index=%u error=%s", (unsigned)change, (unsigned)j,
                        result_name(r));
                continue;
            } else {
                /* could not ask (unreachable, a 5xx, a malformed answer), or a
                 * refusal not yet repeated: nothing published, asked again
                 * (review of PR 85) */
                set_coins(w, GZP_COINS_SCANNING, "lookup", (int)change, (int)j, result_name(r));
                if (gzp_wport_log_attempt(attempt))
                    gzp_log("wallet-coins incomplete why=lookup chain=%u index=%u error=%s attempt=%u",
                            (unsigned)change, (unsigned)j, result_name(r), attempt);
                OPENSSL_cleanse(found, sizeof found);
                return w->stop ? -1 : 0;
            }
            for (size_t i = 0; i < n; i++) {
                size_t at = nf;
                if (!outs[i].confirmed) continue;   /* confirmed coins only (review A of PR 56, M5) */
                if (nf == GZP_WPORT_COINS) {
                    /* more coins than the list holds: incomplete, not complete
                     * (M-1), and the list keeps the largest, not the first met,
                     * so dust at an early address cannot push the real coins
                     * out (M-2, second review of PR 88; the wallet spends its
                     * 64 largest anyway) */
                    size_t m = 0;
                    truncated = 1;
                    for (size_t q = 1; q < nf; q++)
                        if (found[q].amount < found[m].amount) m = q;
                    if (outs[i].value <= found[m].amount) continue;
                    total -= found[m].amount;
                    at = m;
                } else {
                    nf++;
                }
                gzt_coin *c = &found[at];
                heights[at] = outs[i].height;
                memcpy(c->txid, outs[i].txid, 32);
                c->vout = outs[i].vout;
                c->amount = outs[i].value;
                c->change = change;
                c->index = j;
                memcpy(c->script, o.script_pubkey, 34);
                total += c->amount;
                if (change == 1 && j + 100 > next_change) next_change = j + 100;
            }
        }
    if (w->stop) {
        OPENSSL_cleanse(found, sizeof found);
        return -1;
    }
    pthread_mutex_lock(&w->mu);
    if (next_change > w->next_change) w->next_change = next_change;
    pthread_mutex_unlock(&w->mu);
    (void)gzp_wport_publish(w, found, heights, nf, tip.height);
    if (left_out)
        set_coins(w, GZP_COINS_INCOMPLETE, left_out, left_chain, left_index, left_error);
    else if (truncated)
        set_coins(w, GZP_COINS_INCOMPLETE, "too_many_coins", -1, -1, NULL);
    else
        set_coins(w, GZP_COINS_COMPLETE, NULL, -1, -1, NULL);
    gzp_log("wallet-coins count=%zu total_sat=%llu lookups-failed=%d%s%s", nf, (unsigned long long)total, failed,
            left_out || truncated ? " incomplete=" : "", left_out ? left_out : truncated ? "too_many_coins" : "");
    OPENSSL_cleanse(found, sizeof found);
    return 1;
}

int gzp_wport_scan_until(gzp_wport_t *w, const gz_chain *view, uint32_t wait_ms)
{
    for (unsigned tries = 1;; tries++) {
        int r = gzp_wport_scan_view(w, view);
        if (r != 0) return r;
        /* no coin list without the tip and every address: every lobby would be
         * refused, so say so and ask again (review B of PR 83, L-2; review of PR 85) */
        if (gzp_wport_log_attempt(tries))
            gzp_log("wallet-coins retry attempt=%u retry_ms=%u (funding waits for the coin list; logged at the "
                    "first and every 10th attempt)", tries, (unsigned)wait_ms);
        for (uint32_t t = 0; t < wait_ms && !w->stop; t += 100) {
            struct timespec ts = {0, (long)(wait_ms - t < 100 ? wait_ms - t : 100) * 1000000L};
            nanosleep(&ts, NULL);
        }
        if (w->stop) return -1;
    }
}

#ifdef GZP_HAVE_CURL
/* The scan, in a thread of its own (it may wait on a slow server; the loop never does). */
static void *scan_thread(void *arg)
{
    gzp_wport_t *w = arg;
    gz_http http;
    gz_http_curl_config hc;
    gz_esplora_config cfg;
    gz_chain view;
    memset(&hc, 0, sizeof hc);
    if (!gz_http_curl_create(&http, &hc)) return NULL;
    gz_esplora_config_default(&cfg);
    cfg.base_url = w->url;
    if (gz_esplora_create(&cfg, &http, &view) != GZ_CHAIN_OK) {
        gz_http_curl_destroy(&http);
        return NULL;
    }
    pthread_mutex_lock(&w->mu);
    w->http_live = &http;
    pthread_mutex_unlock(&w->mu);
    (void)gzp_wport_scan_until(w, &view, GZP_WPORT_TIP_RETRY_MS);
    pthread_mutex_lock(&w->mu);
    w->http_live = NULL;
    pthread_mutex_unlock(&w->mu);
    gz_chain_destroy(&view);
    gz_http_curl_destroy(&http);
    return NULL;
}
#endif

int gzp_wport_scan_start(gzp_wport_t *w, const char *url, uint32_t gap)
{
#ifdef GZP_HAVE_CURL
    if (!w->have_master || !url || w->th_on) return -1;
    w->url = url;
    w->gap = gap;
    w->stop = 0;
    if (pthread_create(&w->th, NULL, scan_thread, w) != 0) return -1;
    w->th_on = 1;
    return 0;
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
    w->published = 1;
    w->coin_list.state = GZP_COINS_COMPLETE;
    gzp_log("wallet-coins invented=1 (test build, no chain)");
    return 0;
}

void gzp_wport_close(gzp_wport_t *w)
{
    if (w->th_on) {
        /* The scan ends at once: no further lookup, the one under way interrupted. */
        pthread_mutex_lock(&w->mu);
        w->stop = 1;
#ifdef GZP_HAVE_CURL
        if (w->http_live) gz_http_curl_interrupt((gz_http *)w->http_live, true);
#endif
        pthread_mutex_unlock(&w->mu);
        pthread_join(w->th, NULL);
        w->th_on = 0;
    }
    if (w->have_master) pthread_mutex_destroy(&w->mu);
    for (int k = 0; k < GZP_WPORT_PLANS; k++)
        if (w->used[k]) gzt_funding_wipe(&w->plans[k]);
    OPENSSL_cleanse(w, sizeof *w);
}
