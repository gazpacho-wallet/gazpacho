/* SPDX-License-Identifier: MIT */
/* The chain adapter. See pchain.h. */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#ifdef GZP_HAVE_CURL
#include "gazpacho/chain_esplora.h"
#include "gazpacho/chain_http.h"
#include "gazpacho/chain_multi.h"
#endif

#include "gazpacho/node.h"
#include "gzp.h"
#include "pchain.h"

#define GZP_PACERS 8
#define GZP_PACE_PUBLIC_MS 2000u   /* a public server: at most one request every two seconds */
static struct {
    char url[GZ_ESPLORA_URL_MAX + 1];
    gz_esplora_pacer pacer;
} PACERS[GZP_PACERS];
static size_t N_PACERS;
static pthread_mutex_t PACERS_MU = PTHREAD_MUTEX_INITIALIZER;

gz_esplora_pacer *gzp_chain_pacer(const char *url, int local)
{
    gz_esplora_pacer *p = NULL;
    if (!url || strlen(url) > GZ_ESPLORA_URL_MAX) return NULL;
    /* the local test chain, or a server on this machine (the only plain-http one the chain port
     * takes): not a public server, nothing to throttle; each client keeps its own pace, as before */
    if (local || strncmp(url, "http://", 7) == 0) return NULL;
    pthread_mutex_lock(&PACERS_MU);
    for (size_t i = 0; i < N_PACERS && !p; i++)
        if (strcmp(PACERS[i].url, url) == 0) p = &PACERS[i].pacer;
    if (!p && N_PACERS < GZP_PACERS &&
        gz_esplora_pacer_init(&PACERS[N_PACERS].pacer, GZP_PACE_PUBLIC_MS)) {
        snprintf(PACERS[N_PACERS].url, sizeof PACERS[N_PACERS].url, "%s", url);
        p = &PACERS[N_PACERS++].pacer;
    }
    pthread_mutex_unlock(&PACERS_MU);
    return p;
}

/* The worker holds every watch the node can ask for at once; else a FULL
 * answer would come back at every start (review of PR 50, M2). */
_Static_assert(GZ_NODE_MAX_WATCHES <= GZP_MAX_WATCHES, "the chain worker holds fewer watches than the node asks for");

enum { REQ_WATCH_TX = 1, REQ_WATCH_OUTPOINT, REQ_BROADCAST, REQ_UNWATCH_TX, REQ_UNWATCH_OUTPOINT };

struct gzp_chain_req {
    int kind;
    uint8_t txid[32];
    uint32_t vout, depth;
    uint64_t id;
    uint8_t *tx; /* REQ_BROADCAST: a copy */
    size_t len;
};

void gzp_chain_none(gzp_chain_t *c, gz_network network)
{
    memset(c, 0, sizeof *c);
    c->network = network;
}

int gzp_chain_fd(const gzp_chain_t *c)
{
    return c->active && c->w ? gz_chainw_fd(c->w) : -1;
}

int gzp_chain_timeout(const gzp_chain_t *c, uint64_t now)
{
    (void)now;
    return c->active && c->n_backlog ? GZP_CHAIN_RETRY_MS : -1;
}

static void req_free(gzp_chain_req_t *r)
{
    free(r->tx);
    r->tx = NULL;
}

static void backlog_clear(gzp_chain_t *c)
{
    size_t i;
    for (i = 0; i < c->n_backlog; i++) req_free(&c->backlog[i]);
    c->n_backlog = 0;
}

/* One request to the worker. GZ_CHAINW_* */
static int ask(gzp_chain_t *c, const gzp_chain_req_t *r)
{
    switch (r->kind) {
    case REQ_WATCH_TX: return gz_chainw_watch_tx(c->w, r->txid, r->depth, 0);
    case REQ_WATCH_OUTPOINT: return gz_chainw_watch_outpoint(c->w, r->txid, r->vout, r->depth, 0);
    case REQ_UNWATCH_TX: return gz_chainw_unwatch_tx(c->w, r->txid);
    case REQ_UNWATCH_OUTPOINT: return gz_chainw_unwatch_outpoint(c->w, r->txid, r->vout);
    default: return gz_chainw_broadcast(c->w, r->id, r->tx, r->len);
    }
}

/* What a refusal means. 1: keep it and ask again; -1: fatal;
 * GZP_CHAIN_STOP: the watch set is full. */
static int refused(gzp_chain_t *c, const gzp_chain_req_t *r, int rc)
{
    if (rc == GZ_CHAINW_BUSY || (rc == GZ_CHAINW_FULL && r->kind == REQ_BROADCAST)) {
        c->refusals++;
        return 1;
    }
    if (rc == GZ_CHAINW_FULL) {
        c->why = "chain-watch-set-full";
        gzp_log("chain-watch-set-full kind=%d watches=%u", r->kind, (unsigned)c->max_watches);
        return GZP_CHAIN_STOP;
    }
    c->why = "chain-request-refused";
    gzp_log("chain-request-refused kind=%d answer=%s", r->kind,
            rc == GZ_CHAINW_FULL ? "full" : rc == GZ_CHAINW_INVALID ? "invalid" : "other");
    return -1;
}

/* Asks again for what was refused, oldest first; stops at the first that is
 * refused again, so the order of requests is kept. */
int gzp_chain_retry(gzp_chain_t *c)
{
    size_t done = 0;
    if (!c->active) return 0;
    while (done < c->n_backlog) {
        int rc = ask(c, &c->backlog[done]);
        if (rc != GZ_CHAINW_OK) {
            int k = refused(c, &c->backlog[done], rc);
            if (k < 0) return k;
            break;
        }
        req_free(&c->backlog[done]);
        done++;
    }
    if (done) {
        memmove(c->backlog, c->backlog + done, (c->n_backlog - done) * sizeof *c->backlog);
        c->n_backlog -= done;
        gzp_log("chain-backlog asked=%zu left=%zu", done, c->n_backlog);
    }
    return 0;
}

/* A request: asked now unless older ones wait (the order is kept), else
 * kept. 0, or -1: fatal. Takes the copy in r->tx. */
static int submit(gzp_chain_t *c, gzp_chain_req_t *r)
{
    int rc = GZ_CHAINW_BUSY;
    if (c->n_backlog == 0) {
        rc = ask(c, r);
        if (rc == GZ_CHAINW_OK) {
            req_free(r);
            return 0;
        }
        int k = refused(c, r, rc);
        if (k < 0) {
            req_free(r);
            return k;
        }
    }
    if (c->n_backlog == c->backlog_cap) {
        c->why = "chain-backlog-full";
        gzp_log("chain-backlog-full held=%zu", c->n_backlog);
        req_free(r);
        return -1;
    }
    c->backlog[c->n_backlog++] = *r;
    gzp_log("chain-busy kind=%d held=%zu", r->kind, c->n_backlog);
    return 0;
}

int gzp_chain_watch_tx(gzp_chain_t *c, const uint8_t txid[32], uint32_t depth)
{
    gzp_chain_req_t r;
    if (!c->active) return 0;
    memset(&r, 0, sizeof r);
    r.kind = REQ_WATCH_TX;
    memcpy(r.txid, txid, 32);
    r.depth = depth;
    return submit(c, &r);
}

int gzp_chain_watch_outpoint(gzp_chain_t *c, const uint8_t txid[32], uint32_t vout, uint32_t depth)
{
    gzp_chain_req_t r;
    if (!c->active) return 0;
    memset(&r, 0, sizeof r);
    r.kind = REQ_WATCH_OUTPOINT;
    memcpy(r.txid, txid, 32);
    r.vout = vout;
    r.depth = depth;
    return submit(c, &r);
}

int gzp_chain_unwatch(gzp_chain_t *c, int is_tx, const uint8_t txid[32], uint32_t vout)
{
    gzp_chain_req_t r;
    if (!c->active) return 0;
    memset(&r, 0, sizeof r);
    r.kind = is_tx ? REQ_UNWATCH_TX : REQ_UNWATCH_OUTPOINT;
    memcpy(r.txid, txid, 32);
    r.vout = vout;
    return submit(c, &r);
}

int gzp_chain_broadcast(gzp_chain_t *c, const uint8_t *tx, size_t len)
{
    gzp_chain_req_t r;
    uint8_t txid[32];
    if (!c->active) {
        gzp_log("broadcast-dropped len=%zu why=no-chain", len);
        return 0;
    }
    if (!gz_network_is_test(c->network)) { /* never reached: options.c refuses mainnet */
        gzp_log("broadcast-refused why=mainnet");
        return 0;
    }
    if (len > GZ_TX_MAX_BYTES || !gz_txid_from_raw(tx, len, txid)) {
        /* The node is told, as advice, that this was not sent. */
        if (c->n_refused == sizeof c->refused_txids / sizeof c->refused_txids[0]) {
            gzp_log("broadcast-refused-full");
            return -1;
        }
        memset(c->refused_txids[c->n_refused++], 0, 32);
        gzp_log("broadcast-refused len=%zu why=not-a-transaction", len);
        return 0;
    }
    memset(&r, 0, sizeof r);
    r.kind = REQ_BROADCAST;
    r.id = ++c->next_id;
    if (!(r.tx = malloc(len))) return -1;
    memcpy(r.tx, tx, len);
    r.len = len;
    {
        char hex[65];
        gz_hash_to_hex(txid, hex);
        gzp_log("broadcast-queued id=%llu txid=%s", (unsigned long long)r.id, hex);
    }
    return submit(c, &r);
}

static void reason_bytes(gzp_chain_t *c, gz_event_t *ev, const char *why)
{
    size_t n = strlen(why);
    if (n > sizeof c->reason - 1) n = sizeof c->reason - 1;
    memcpy(c->reason, why, n);
    c->reason[n] = 0;
    ev->u.chain.reason.data = (const uint8_t *)c->reason;
    ev->u.chain.reason.len = n;
}

int gzp_chain_take(gzp_chain_t *c, gz_event_t *ev)
{
    gz_chainw_event w;
    char hex[65], hex2[65];
    if (!c->active) return 0;
    memset(ev, 0, sizeof *ev);
    ev->kind = GZ_EVENT_CHAIN;
    if (c->n_refused) {
        c->n_refused--;
        ev->u.chain.kind = GZ_CHAIN_BROADCAST_RESULT;
        memcpy(ev->u.chain.txid, c->refused_txids[c->n_refused], 32);
        ev->u.chain.outcome = GZ_BROADCAST_REFUSED;
        reason_bytes(c, ev, "not a transaction");
        gzp_log("chain-broadcast-result txid=%064d outcome=refused reason=%s", 0, c->reason);
        return 1;
    }
    while (gz_chainw_take(c->w, &w)) {
        gz_hash_to_hex(w.txid, hex);
        switch (w.kind) {
        case GZ_CHAINW_TIP:
            if (c->have_tip && w.height == c->tip.height && !memcmp(w.block_hash, c->tip.hash, 32)) continue;
            c->have_tip = 1;
            c->tip.height = w.height;
            memcpy(c->tip.hash, w.block_hash, 32);
            gzp_log("chain-tip height=%u", w.height);
            ev->u.chain.kind = GZ_CHAIN_NEW_TIP;
            ev->u.chain.height = w.height;
            memcpy(ev->u.chain.block_hash, w.block_hash, 32);
            return 1;
        case GZ_CHAINW_TX_CONFIRMED:
            gzp_log("chain-tx-confirmed txid=%s conf=%u height=%u%s", hex, w.confirmations, w.height,
                    w.reorg ? " reorg" : "");
            ev->u.chain.kind = GZ_CHAIN_TX_CONFIRMED;
            memcpy(ev->u.chain.txid, w.txid, 32);
            ev->u.chain.confirmations = w.confirmations;
            ev->u.chain.height = w.height;
            return 1;
        case GZ_CHAINW_TX_UNCONFIRMED:
            gzp_log("chain-tx-unconfirmed txid=%s", hex);
            ev->u.chain.kind = GZ_CHAIN_TX_UNCONFIRMED;
            memcpy(ev->u.chain.txid, w.txid, 32);
            return 1;
        case GZ_CHAINW_OUTPOINT_SPENT:
            gz_hash_to_hex(w.outpoint_txid, hex2);
            gzp_log("chain-spent outpoint=%s:%u by=%s vin=%u conf=%u%s", hex2, w.outpoint_vout, hex, w.vin,
                    w.confirmations, w.replaced ? " replaced" : "");
            ev->u.chain.kind = GZ_CHAIN_OUTPOINT_SPENT;
            memcpy(ev->u.chain.outpoint.txid, w.outpoint_txid, 32);
            ev->u.chain.outpoint.vout = w.outpoint_vout;
            memcpy(ev->u.chain.txid, w.txid, 32);
            ev->u.chain.confirmations = w.confirmations;
            ev->u.chain.height = w.confirmations ? w.height : 0;
            return 1;
        case GZ_CHAINW_BROADCAST:
            gzp_log("chain-broadcast id=%llu outcome=%s final=%d tries=%u", (unsigned long long)w.broadcast.id,
                    gz_chainw_outcome_name(w.broadcast.outcome), w.broadcast.final ? 1 : 0, w.broadcast.attempts);
            if (!w.broadcast.final) continue;
            ev->u.chain.kind = GZ_CHAIN_BROADCAST_RESULT;
            memcpy(ev->u.chain.txid, w.txid, 32);
            switch (w.broadcast.outcome) {
            case GZ_CHAINW_ACCEPTED:
            case GZ_CHAINW_ALREADY_KNOWN: ev->u.chain.outcome = GZ_BROADCAST_ACCEPTED; break;
            case GZ_CHAINW_UNREACHABLE: ev->u.chain.outcome = GZ_BROADCAST_UNREACHABLE; break;
            default:
                ev->u.chain.outcome = GZ_BROADCAST_REFUSED;
                reason_bytes(c, ev, w.broadcast.reason);
                break;
            }
            /* What the node is handed, so a test can read it. */
            gzp_log("chain-broadcast-result txid=%s outcome=%s reason=%s", hex,
                    ev->u.chain.outcome == GZ_BROADCAST_ACCEPTED      ? "accepted"
                    : ev->u.chain.outcome == GZ_BROADCAST_UNREACHABLE ? "unreachable"
                                                                      : "refused",
                    ev->u.chain.outcome == GZ_BROADCAST_REFUSED ? c->reason : "-");
            return 1;
        case GZ_CHAINW_SOURCES:
            gzp_log("chain-sources %s", gz_chain_result_name(w.sources));
            continue;
        case GZ_CHAINW_REORG:
            /* No core event yet (spec/exit.md 3.2 asks for one): logged. */
            gzp_log("chain-reorg from=%u gone=%u", w.height, w.disconnected);
            continue;
        case GZ_CHAINW_TX_MEMPOOL:
            gzp_log("chain-tx-mempool txid=%s", hex);
            continue;
        case GZ_CHAINW_TX_EVICTED:
            gzp_log("chain-tx-evicted txid=%s", hex);
            continue;
        case GZ_CHAINW_TIP_SYNCED:
            gzp_log("chain-tip-synced height=%u", w.height);
            ev->u.chain.kind = GZ_CHAIN_TIP_SYNCED;
            ev->u.chain.height = w.height;
            memcpy(ev->u.chain.block_hash, w.block_hash, 32);
            return 1;
        case GZ_CHAINW_WATCH_PENDING:
            ev->u.chain.kind = GZ_CHAIN_WATCH_PENDING;
            if (w.outpoint_watch) {
                gz_hash_to_hex(w.outpoint_txid, hex2);
                gzp_log("chain-watch-pending outpoint=%s:%u result=%s", hex2, w.outpoint_vout,
                        gz_chain_result_name(w.sources));
                memcpy(ev->u.chain.outpoint.txid, w.outpoint_txid, 32);
                ev->u.chain.outpoint.vout = w.outpoint_vout;
            } else {
                gzp_log("chain-watch-pending tx=%s result=%s", hex, gz_chain_result_name(w.sources));
                ev->u.chain.is_tx = 1;
                memcpy(ev->u.chain.txid, w.txid, 32);
            }
            return 1;
        case GZ_CHAINW_WATCH_FAILED:
            ev->u.chain.kind = GZ_CHAIN_WATCH_FAILED;
            if (w.outpoint_watch) {
                gz_hash_to_hex(w.outpoint_txid, hex2);
                gzp_log("chain-watch-failed outpoint=%s:%u result=%s", hex2, w.outpoint_vout,
                        gz_chain_result_name(w.sources));
                memcpy(ev->u.chain.outpoint.txid, w.outpoint_txid, 32);
                ev->u.chain.outpoint.vout = w.outpoint_vout;
            } else {
                gzp_log("chain-watch-failed tx=%s result=%s", hex, gz_chain_result_name(w.sources));
                ev->u.chain.is_tx = 1;
                memcpy(ev->u.chain.txid, w.txid, 32);
            }
            return 1;
        case GZ_CHAINW_SYNCED:
            ev->u.chain.kind = GZ_CHAIN_WATCH_SYNCED;
            if (w.outpoint_watch) {
                gz_hash_to_hex(w.outpoint_txid, hex2);
                gzp_log("chain-synced outpoint=%s:%u", hex2, w.outpoint_vout);
                memcpy(ev->u.chain.outpoint.txid, w.outpoint_txid, 32);
                ev->u.chain.outpoint.vout = w.outpoint_vout;
            } else {
                gzp_log("chain-synced tx=%s", hex);
                ev->u.chain.is_tx = 1;
                memcpy(ev->u.chain.txid, w.txid, 32);
            }
            return 1;
        case GZ_CHAINW_OUTPOINT_UNSPENT:
            gz_hash_to_hex(w.outpoint_txid, hex2);
            gzp_log("chain-unspent outpoint=%s:%u was=%s", hex2, w.outpoint_vout, hex);
            continue;
        }
    }
    return 0;
}

#ifdef GZP_HAVE_CURL
/* Makes one client: its transport, a backend per server, and the comparing
 * backend with two servers or more. check: ask each server for block 0 and
 * refuse one on another network (done once, for the worker's client; the
 * lookup client is made right after it for the same servers). Returns 0, or
 * a GZP_EXIT_* status after printing why; what was made is freed by
 * client_close. */
static int client_open(gzp_chain_client_t *k, const char *const *urls, const char *const *operators, size_t n,
                       gz_network network, int check)
{
    gz_esplora_config cfg;
    gz_http_curl_config hc;
    gz_chain_result r;
    size_t i;
    memset(&hc, 0, sizeof hc);
    if (!gz_http_curl_create(&k->http, &hc)) {
        fprintf(stderr, "gazpacho: cannot set up HTTPS\n");
        return GZP_EXIT_CHAIN;
    }
    k->have_http = 1;
    for (i = 0; i < n; i++) {
        gz_network seen = GZ_NET_INVALID;
        gz_esplora_config_default(&cfg);
        cfg.base_url = urls[i];
        /* one pace per server for all the program's clients of it (signet run 2) */
        cfg.pacer = gzp_chain_pacer(urls[i], network == GZ_NET_REGTEST);
        if (operators && operators[i]) {
            /* Named by the user: two servers on one machine (or two names
             * of one provider) can be told apart, or put together. */
            if (!gz_operator_name_valid(operators[i])) {
                fprintf(stderr, "gazpacho: --chain-operator %s: lowercase letters, digits, '.' and '-'\n",
                        operators[i]);
                return GZP_EXIT_USAGE;
            }
            cfg.operator_id = operators[i];
        }
        if ((r = gz_esplora_create(&cfg, &k->http, &k->servers[i])) != GZ_CHAIN_OK) {
            fprintf(stderr, "gazpacho: chain server %s refused: %s\n", urls[i], gz_chain_result_name(r));
            return GZP_EXIT_CHAIN;
        }
        k->n_servers = i + 1;
        if (!check) continue;
        r = gz_chain_identify_network(&k->servers[i], &seen);
        if (r == GZ_CHAIN_OK && seen != network) r = GZ_CHAIN_WRONG_NETWORK;
        if (r != GZ_CHAIN_OK) {
            if (r == GZ_CHAIN_WRONG_NETWORK)
                fprintf(stderr, "gazpacho: the chain server %s is on %s, not %s: refused\n", urls[i],
                        seen == GZ_NET_INVALID ? "an unknown network" : gz_network_name(seen),
                        gz_network_name(network));
            else
                fprintf(stderr, "gazpacho: cannot check the chain server %s: %s\n", urls[i], gz_chain_result_name(r));
            return GZP_EXIT_CHAIN;
        }
    }
    k->view = &k->servers[0];
    if (n > 1) {
        gz_multi_config mc;
        gz_multi_config_default(&mc, network);
        mc.now_ms = k->http.now_ms;
        mc.clock_ctx = k->http.ctx;
        if ((r = gz_multi_create(&mc, k->servers, n, &k->multi)) != GZ_CHAIN_OK) {
            fprintf(stderr, "gazpacho: the chain servers cannot be compared (%s): give servers of different "
                            "operators\n", gz_chain_result_name(r));
            return GZP_EXIT_CHAIN;
        }
        k->view = &k->multi;
    }
    return 0;
}
#endif

/* Frees one client: the backends, then the transport they use. */
static void client_close(gzp_chain_client_t *k)
{
    size_t i;
    if (k->multi.ops) gz_chain_destroy(&k->multi);
    for (i = 0; i < k->n_servers; i++)
        if (k->servers[i].ops) gz_chain_destroy(&k->servers[i]);
    k->n_servers = 0;
    k->view = NULL;
#ifdef GZP_HAVE_CURL
    if (k->have_http) gz_http_curl_destroy(&k->http);
    k->have_http = 0;
#endif
}

int gzp_chain_open(gzp_chain_t *c, const char *const *urls, const char *const *operators, size_t n,
                   gz_network network, uint32_t poll_ms, const gzp_chain_limits_t *lim)
{
#ifdef GZP_HAVE_CURL
    gz_chainw_config wc;
    gz_chain_result r;
    char hex[65];
    int rc;
    gzp_chain_none(c, network);
    /* Refuse mainnet whatever the caller asked: the program only ever runs
     * on a test network (options.c refuses --network mainnet already), and
     * the chain worker refuses it again. */
    if (!gz_network_is_test(network)) {
        fprintf(stderr, "gazpacho: refusing a chain view on %s\n", gz_network_name(network));
        return GZP_EXIT_USAGE;
    }
    if (n == 0 || n > GZP_CHAIN_SERVERS) {
        fprintf(stderr, "gazpacho: from one to %d chain servers\n", GZP_CHAIN_SERVERS);
        return GZP_EXIT_USAGE;
    }
    gzp_log("chain lookups-without-blocking=%d", gz_http_curl_async_dns() ? 1 : 0);
    /* Two clients, both made here, on this thread, before the worker starts:
     * the worker's, which only the worker calls once it runs, and the loop's
     * own for its lookups. One client shared by two threads corrupted the
     * heap (docs/notes/integration.md B11). */
    if ((rc = client_open(&c->worker, urls, operators, n, network, 1)) != 0 ||
        (rc = client_open(&c->lookup, urls, operators, n, network, 0)) != 0) {
        gzp_chain_close(c);
        return rc;
    }
    if ((r = gz_chain_tip_get(c->worker.view, &c->tip)) != GZ_CHAIN_OK) {
        fprintf(stderr, "gazpacho: cannot read the chain tip: %s\n", gz_chain_result_name(r));
        gzp_chain_close(c);
        return GZP_EXIT_CHAIN;
    }
    c->have_tip = 1;
    c->backlog_cap = lim && lim->backlog ? lim->backlog : GZP_CHAIN_BACKLOG;
    if (!(c->backlog = calloc(c->backlog_cap, sizeof *c->backlog))) {
        gzp_chain_close(c);
        return GZP_EXIT_FAILED;
    }
    gz_chainw_config_default(&wc, c->worker.view, network);
    wc.tip_poll_ms = poll_ms;
    wc.max_watches = GZP_MAX_WATCHES;
    if (lim && lim->small) {
        wc.max_watches = 16;
        wc.max_requests = 16 + GZ_CHAINW_MAX_BROADCASTS;
    }
    if (lim && lim->watches) {
        wc.max_watches = lim->watches;
        if (wc.max_requests < lim->watches + GZ_CHAINW_MAX_BROADCASTS)
            wc.max_requests = lim->watches + GZ_CHAINW_MAX_BROADCASTS;
    }
    c->max_watches = (uint32_t)wc.max_watches;
    wc.report_synced = true;   /* GZ_CHAIN_WATCH_SYNCED (action.h, WATCHES) */
    wc.interrupt = gz_http_curl_interrupt_hook;
    wc.interrupt_ctx = &c->worker.http;
    if (!(c->w = gz_chainw_new(&wc))) {
        fprintf(stderr, "gazpacho: cannot start the chain worker\n");
        gzp_chain_close(c);
        return GZP_EXIT_FAILED;
    }
    c->active = 1;
    gz_hash_to_hex(c->tip.hash, hex);
    gzp_log("chain network=%s servers=%zu tip=%u hash=%s", gz_network_name(network), n, c->tip.height, hex);
    return 0;
#else
    (void)urls;
    (void)operators;
    (void)n;
    (void)poll_ms;
    (void)lim;
    gzp_chain_none(c, network);
    fprintf(stderr, "gazpacho: built without libcurl: only --no-chain is available\n");
    return GZP_EXIT_USAGE;
#endif
}

int gzp_chain_show_outputs(gzp_chain_t *c, const uint8_t *script, size_t len)
{
    gz_chain_output outs[32];
    size_t n = 0, i;
    uint64_t total = 0;
    gz_chain_result r;
    /* the loop's own client: never the worker's, which the worker is using */
    if (!c->lookup.view) return -1;
    r = gz_chain_script_outputs(c->lookup.view, script, len, outs, 32, &n, NULL);
    if (r != GZ_CHAIN_OK) {
        gzp_log("wallet-outputs-failed why=%s", gz_chain_result_name(r));
        return -1;
    }
    for (i = 0; i < n; i++) total += outs[i].value;
    gzp_log("wallet-outputs count=%zu total_sat=%llu", n, (unsigned long long)total);
    return 0;
}

void gzp_chain_restart(gzp_chain_t *c)
{
    size_t i;
    /* Broadcasts still held are not sent and get no result: the new
     * incarnation sends again what it needs. Written, so a missing result
     * can be explained (review of PR 50, L3). */
    for (i = 0; i < c->n_backlog; i++)
        if (c->backlog[i].kind == REQ_BROADCAST)
            gzp_log("chain-broadcast-dropped id=%llu why=restart", (unsigned long long)c->backlog[i].id);
    backlog_clear(c);
    c->n_refused = 0;
    c->why = NULL;
    if (c->active && c->w) {
        uint64_t g = gz_chainw_reset(c->w);
        gzp_log("chain-restart generation=%llu", (unsigned long long)g);
    }
}

void gzp_chain_close(gzp_chain_t *c)
{
    /* the worker first: it is the only user of its client's backends and transport */
    if (c->w) gz_chainw_free(c->w);
    c->w = NULL;
    if (c->backlog) backlog_clear(c);
    free(c->backlog);
    c->backlog = NULL;
    client_close(&c->worker);
    client_close(&c->lookup);
    c->active = 0;
}
