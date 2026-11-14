/* SPDX-License-Identifier: MIT */
/* The network adapter over ports/net/peers.h. See net.h. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "envelope.h"
#include "frame.h"
#include "gzp.h"
#include "net.h"

uint64_t gzp_peer_id(const uint8_t key[33])
{
    uint8_t d[32];
    unsigned int n = 0;
    uint64_t v = 0;
    int i;
    if (!EVP_Digest(key, 33, d, &n, EVP_sha256(), NULL) || n != 32) abort();
    for (i = 0; i < 8; i++) v = v << 8 | d[i];
    return v;
}

int gzp_net_init(gzp_net_t *n, const secp256k1_context *secp, const uint8_t priv[32], gz_net_random_t random,
                 const uint8_t chain[32], const gzp_net_limits_t *lim, int reconnect_ms,
                 const gzp_net_events_t *ev)
{
    secp256k1_pubkey pk;
    size_t len = 33;
    memset(n, 0, sizeof *n);
    gz_peers_default_config(&n->cfg);
    n->cfg.secp = secp;
    memcpy(n->cfg.static_key, priv, 32);
    n->cfg.random = random;
    memcpy(n->cfg.chain, chain, 32);
    n->cfg.is_member = gz_conn_any_member; /* slice 1's host: transport.md rule 13 */
    n->cfg.handshake_ms = lim->handshake_ms;
    n->cfg.recv_ms = lim->recv_ms;
    n->cfg.send_ms = lim->send_ms;
    n->cfg.ping_ms = lim->ping_ms;
    n->cfg.pong_ms = lim->pong_ms;
    if (lim->max_per_address >= 0) n->cfg.max_per_address = (unsigned)lim->max_per_address;
    if (lim->max_queue) n->cfg.max_queue = lim->max_queue;
    if (n->cfg.max_conns > GZP_MAX_CONNS) n->cfg.max_conns = GZP_MAX_CONNS;
    if (!secp256k1_ec_pubkey_create(secp, &pk, n->cfg.static_key) ||
        !secp256k1_ec_pubkey_serialize(secp, n->pub, &len, &pk, SECP256K1_EC_COMPRESSED))
        return -1;
    n->ev = *ev;
    n->first_backoff_ms = reconnect_ms;
    n->peers = gz_peers_new(&n->cfg);
    return n->peers ? 0 : -1;
}

void gzp_net_set_listen(gzp_net_t *n, const char *host, uint16_t port)
{
    n->want_listen = 1;
    snprintf(n->listen_host, sizeof n->listen_host, "%s", host);
    n->listen_port = port;
}

int gzp_net_open(gzp_net_t *n)
{
    int i;
    if (n->want_listen && !n->listening) {
        /* After a restart the same port again, also when 0 picked it. */
        uint16_t port = n->bound_port ? n->bound_port : n->listen_port, bound = 0;
        gz_peers_err_t e = gz_peers_listen(n->peers, n->listen_host, port, &bound);
        if (e) {
            fprintf(stderr, "gazpacho: cannot listen on %s:%u: %s\n", n->listen_host, (unsigned)port,
                    gz_peers_err_name(e));
            return -1;
        }
        n->bound_port = bound;
        n->listening = 1;
    }
    n->open = 1;
    for (i = 0; i < GZP_MAX_TARGETS; i++) n->targets[i].next_connect_ms = 0;
    return 0;
}

/* ---- connections ---------------------------------------------------------- */

static gzp_conn_t *by_conn(gzp_net_t *n, uint64_t conn)
{
    int i;
    for (i = 0; i < GZP_MAX_CONNS; i++)
        if (n->conns[i].used && n->conns[i].conn == conn) return &n->conns[i];
    return NULL;
}

/* The connection to a key: on both sides at most one live connection per
 * link, and every link's local key is ours. */
static gzp_conn_t *by_key(const gzp_net_t *n, const uint8_t key[33])
{
    int i;
    for (i = 0; i < GZP_MAX_CONNS; i++)
        if (n->conns[i].used && !memcmp(n->conns[i].key, key, 33)) return (gzp_conn_t *)&n->conns[i];
    return NULL;
}

int gzp_net_connected(const gzp_net_t *n, const uint8_t key[33])
{
    return by_key(n, key) != NULL;
}

static void link_of(const gzp_net_t *n, const gzp_conn_t *c, gz_link_t *l)
{
    memcpy(l->local.key, n->pub, 33);
    memcpy(l->remote.key, c->key, 33);
}

int gzp_net_send(gzp_net_t *n, const gz_link_t *link, uint16_t kind, const uint8_t scope[32],
                 const uint8_t *records, size_t len)
{
    gzp_conn_t *c = by_key(n, link->remote.key);
    gz_peers_err_t e;
    unsigned long long pid = (unsigned long long)gzp_peer_id(link->remote.key);
    if (memcmp(link->local.key, n->pub, 33) != 0) {
        n->dropped_unconnected++;
        gzp_log("send-dropped peer=%016llx why=not-our-key", pid);
        return 1;
    }
    if (!c || n->queueing) {
        /* No outbox (contract-v2.md section 1). During a start nothing of a
         * connection has been reported to the node, so nothing is sent on it. */
        n->dropped_unconnected++;
        gzp_log("send-dropped peer=%016llx why=not-connected", pid);
        return 1;
    }
    e = gz_peers_send(n->peers, c->conn, kind, scope, records, len);
    if (e == GZ_PEERS_OK) return 0;
    if (e == GZ_PEERS_ERR_TOO_BIG) return -1;
    /* FULL or ARGS closed the connection (SEND_REFUSED, an event follows);
     * NO_CONN and NOT_READY: it is going or not there. */
    gzp_log("send-refused peer=%016llx why=%s", pid, gz_peers_err_name(e));
    return 1;
}

int gzp_net_connect(gzp_net_t *n, const uint8_t host_key[33], const uint8_t *address, size_t address_len,
                    uint32_t key_epoch, uint32_t key_index)
{
    char buf[80], *colon, *end;
    long port;
    int i, free_i = -1;
    gzp_target_t *t;
    if (address_len == 0 || address_len >= sizeof buf) return -1;
    memcpy(buf, address, address_len);
    buf[address_len] = 0;
    colon = strrchr(buf, ':');
    if (!colon || colon == buf || colon - buf >= 64) return -1;
    *colon = 0;
    port = strtol(colon + 1, &end, 10);
    if (*end || port <= 0 || port > 65535) return -1;
    for (i = 0; i < GZP_MAX_TARGETS; i++) {
        if (n->targets[i].used && !memcmp(n->targets[i].key, host_key, 33)) break;
        if (!n->targets[i].used && free_i < 0) free_i = i;
    }
    if (i == GZP_MAX_TARGETS) {
        if (free_i < 0) return -1;
        i = free_i;
        memset(&n->targets[i], 0, sizeof n->targets[i]);
        n->targets[i].backoff_ms = n->first_backoff_ms;
    }
    t = &n->targets[i];
    /* A second CONNECT with the same host and key replaces the address. */
    t->used = 1;
    memcpy(t->key, host_key, 33);
    snprintf(t->host, sizeof t->host, "%s", buf);
    t->port = (uint16_t)port;
    t->epoch = key_epoch;
    t->index = key_index;
    gzp_log("connect-kept host=%016llx address=%s:%ld", (unsigned long long)gzp_peer_id(host_key), buf, port);
    return 0;
}

void gzp_net_disconnect(gzp_net_t *n, const gz_link_t *link, unsigned why)
{
    gzp_conn_t *c = by_key(n, link->remote.key);
    int i;
    for (i = 0; i < GZP_MAX_TARGETS; i++)
        if (n->targets[i].used && !memcmp(n->targets[i].key, link->remote.key, 33)) {
            n->targets[i].used = 0; /* no longer kept */
            if (c && c->target == i) c->target = -1;
        }
    gzp_log("disconnect peer=%016llx why=%u connected=%d", (unsigned long long)gzp_peer_id(link->remote.key), why,
            c != NULL);
    if (!c) return;
    if (why == 1) gz_peers_refuse(n->peers, c->conn, "refused");
    else gz_peers_close_after_send(n->peers, c->conn);
}

void gzp_net_set_seated(gzp_net_t *n, const uint8_t key[33], int seated)
{
    gz_peers_set_seated_key(n->peers, key, seated);
}

#ifdef GZP_TEST_BUILD
void gzp_net_test_raw(gzp_net_t *n, uint16_t kind, int zero_scope)
{
    uint8_t scope[32], msg[64];
    size_t len = 0;
    int i;
    memset(scope, zero_scope ? 0 : 0x5a, sizeof scope);
    if (gz_env_write(kind, scope, NULL, 0, msg, sizeof msg, &len) != 0) return;
    for (i = 0; i < GZP_MAX_CONNS; i++)
        if (n->conns[i].used) {
            gz_peers_send_raw(n->peers, n->conns[i].conn, msg, len);
            gzp_log("raw-sent kind=%u conn=%llu", (unsigned)kind, (unsigned long long)n->conns[i].conn);
        }
}
#endif

/* ---- events --------------------------------------------------------------- */

static void enqueue(gzp_net_t *n, int type, uint64_t conn, uint16_t kind, const uint8_t *scope,
                    const uint8_t *bytes, size_t len)
{
    gzp_qev_t *e;
    if (n->nq == n->capq) {
        size_t c = n->capq ? n->capq * 2 : 32;
        gzp_qev_t *nq = realloc(n->q, c * sizeof *nq);
        if (!nq) abort(); /* an input must not be lost silently */
        n->q = nq;
        n->capq = c;
    }
    e = &n->q[n->nq++];
    memset(e, 0, sizeof *e);
    e->type = type;
    e->conn = conn;
    e->kind = kind;
    if (scope) memcpy(e->scope, scope, 32);
    e->len = len;
    n->queued_total += len + GZP_QUEUE_OVERHEAD;
    if (len) {
        e->bytes = malloc(len);
        if (!e->bytes) abort();
        memcpy(e->bytes, bytes, len);
    }
}

/* Forget everything queued for `conn` (its connected and its messages).
 * Returns the number of messages forgotten. */
static size_t unqueue_conn(gzp_net_t *n, uint64_t conn)
{
    size_t i, j = 0, msgs = 0;
    for (i = 0; i < n->nq; i++) {
        if (n->q[i].conn == conn) {
            if (n->q[i].type == GZ_PEER_EV_MESSAGE) msgs++;
            n->queued_total -= n->q[i].len + GZP_QUEUE_OVERHEAD;
            free(n->q[i].bytes);
            continue;
        }
        n->q[j++] = n->q[i];
    }
    n->nq = j;
    return msgs;
}

/* A reason as one word for output lines. Valid until the next call. */
static const char *word(const char *s)
{
    static char buf[64];
    size_t i;
    for (i = 0; s[i] && i + 1 < sizeof buf; i++) buf[i] = s[i] == ' ' ? '-' : s[i];
    buf[i] = 0;
    return buf;
}

static void schedule_reconnect(gzp_net_t *n, int ti, uint64_t now)
{
    gzp_target_t *t = &n->targets[ti];
    t->conn = 0;
    t->next_connect_ms = now + (uint64_t)t->backoff_ms;
    t->backoff_ms = t->backoff_ms * 2 > GZP_BACKOFF_MAX_MS ? GZP_BACKOFF_MAX_MS : t->backoff_ms * 2;
}

static int target_of_conn(const gzp_net_t *n, uint64_t conn)
{
    int i;
    for (i = 0; i < GZP_MAX_TARGETS; i++)
        if (n->targets[i].used && n->targets[i].conn == conn) return i;
    return -1;
}

static void report_connected(gzp_net_t *n, const gzp_conn_t *c)
{
    gz_link_t l;
    uint32_t epoch = 0, index = 0;
    if (!n->ev.connected) return;
    link_of(n, c, &l);
    if (c->target >= 0) {
        epoch = n->targets[c->target].epoch;
        index = n->targets[c->target].index;
    }
    n->ev.connected(n->ev.ctx, &l, c->outbound, epoch, index, c->conn);
}

static void handle(gzp_net_t *n, const gz_peer_event_t *ev, uint64_t now)
{
    gzp_conn_t *c = by_conn(n, ev->conn);
    switch (ev->type) {
    case GZ_PEER_EV_CONNECTED: {
        int i;
        if (!c) {
            for (i = 0; i < GZP_MAX_CONNS && n->conns[i].used; i++) {
            }
            if (i == GZP_MAX_CONNS) { /* cannot happen: max_conns is capped to the table */
                gz_peers_close(n->peers, ev->conn);
                return;
            }
            c = &n->conns[i];
        }
        memset(c, 0, sizeof *c);
        c->used = 1;
        c->conn = ev->conn;
        c->outbound = ev->outbound;
        memcpy(c->key, ev->node_id, 33);
        c->peer_id = gzp_peer_id(ev->node_id);
        c->target = ev->outbound ? target_of_conn(n, ev->conn) : -1;
        if (c->target >= 0) n->targets[c->target].backoff_ms = n->first_backoff_ms;
        if (n->queueing) enqueue(n, GZ_PEER_EV_CONNECTED, ev->conn, 0, NULL, NULL, 0);
        else report_connected(n, c);
        break;
    }
    case GZ_PEER_EV_MESSAGE: {
        gz_link_t l;
        if (!c) break;
        if (n->drop_kind && ev->kind == n->drop_kind) {
            gzp_log("test-drop kind=%u peer=%016llx", (unsigned)ev->kind, (unsigned long long)c->peer_id);
            break;
        }
        if (n->queueing) {
            c->queued_bytes += ev->records_len + GZP_QUEUE_OVERHEAD;
            if (c->queued_bytes > GZP_QUEUE_PER_CONN ||
                n->queued_total + ev->records_len + GZP_QUEUE_OVERHEAD > GZP_QUEUE_TOTAL) {
                /* Past the start queue's limit, for this connection or for
                 * the queue as a whole (B5): close it; it was never
                 * reported. gz_peers_close gives no CLOSED event, so a
                 * member's own connection is rescheduled here. */
                int ti = target_of_conn(n, c->conn);
                gzp_log("start-queue closed conn=%llu why=%s peer=%016llx", (unsigned long long)c->conn,
                        c->queued_bytes > GZP_QUEUE_PER_CONN ? "over-1MiB" : "over-total",
                        (unsigned long long)c->peer_id);
                if (ti >= 0) schedule_reconnect(n, ti, now);
                gz_peers_close(n->peers, c->conn);
                unqueue_conn(n, c->conn);
                n->closed_while_starting++;
                memset(c, 0, sizeof *c);
                break;
            }
            enqueue(n, GZ_PEER_EV_MESSAGE, ev->conn, ev->kind, ev->scope, ev->records, ev->records_len);
        } else if (n->ev.message) {
            link_of(n, c, &l);
            n->ev.message(n->ev.ctx, &l, ev->kind, ev->scope, ev->records, ev->records_len);
        }
        break;
    }
    case GZ_PEER_EV_CLOSED: {
        const char *why = word(gz_peer_why_name(ev->why));
        char hex[67];
        int ti = target_of_conn(n, ev->conn);
        gzp_hex(ev->node_id, 33, hex);
        gzp_log("closed conn=%llu why=%s was_connected=%d key=%s mono=%llu", (unsigned long long)ev->conn, why,
                ev->was_connected, ev->have_node_id ? hex : "-", (unsigned long long)gzp_mono_ms());
        if (ti >= 0) schedule_reconnect(n, ti, now);
        if (c) {
            uint64_t id = c->peer_id;
            gz_link_t l;
            link_of(n, c, &l);
            if (n->queueing) {
                size_t k = unqueue_conn(n, ev->conn);
                gzp_log("start-queue dropped conn=%llu why=closed-during-start peer=%016llx messages=%zu",
                        (unsigned long long)ev->conn, (unsigned long long)id, k);
            }
            memset(c, 0, sizeof *c);
            if (!n->queueing && ev->was_connected && n->ev.disconnected) n->ev.disconnected(n->ev.ctx, &l, why);
        }
        break;
    }
    case GZ_PEER_EV_WARNING:
        gzp_log("warning conn=%llu text=%s", (unsigned long long)ev->conn, ev->text);
        break;
    }
}

void gzp_net_queue_begin(gzp_net_t *n)
{
    n->queueing = 1;
}

/* Hand the queue over: per connection still open, its connected, then its
 * messages in order. A connection closed during the start was unqueued when
 * its CLOSED arrived; the slot check below is a second guard only. */
void gzp_net_queue_end(gzp_net_t *n)
{
    size_t i, j;
    gzp_qev_t *q = n->q;
    size_t nq = n->nq;
    n->queueing = 0;
    n->q = NULL;
    n->nq = n->capq = 0;
    n->queued_total = 0;
    for (i = 0; i < nq; i++) {
        gzp_conn_t *c;
        gz_link_t l;
        if (q[i].type != GZ_PEER_EV_CONNECTED) continue;
        c = by_conn(n, q[i].conn);
        if (!c) {
            gzp_log("start-queue dropped conn=%llu why=closed-during-start", (unsigned long long)q[i].conn);
            continue;
        }
        c->queued_bytes = 0;
        report_connected(n, c);
        link_of(n, c, &l);
        /* Every queued message of the connection, in order. */
        for (j = i + 1; j < nq; j++) {
            if (q[j].conn != q[i].conn || q[j].type != GZ_PEER_EV_MESSAGE) continue;
            if (!by_conn(n, q[i].conn)) break; /* closed by a delivery's refusal: the rest go with it */
            if (n->ev.message) n->ev.message(n->ev.ctx, &l, q[j].kind, q[j].scope, q[j].bytes, q[j].len);
        }
    }
    for (i = 0; i < nq; i++) free(q[i].bytes);
    free(q);
}

/* ---- the loop ------------------------------------------------------------- */

size_t gzp_net_max_fds(const gzp_net_t *n)
{
    return gz_peers_max_fds(n->peers);
}

size_t gzp_net_pollfds(gzp_net_t *n, struct pollfd *fds, size_t cap, int *timeout_ms, uint64_t now)
{
    size_t k = gz_peers_pollfds(n->peers, fds, cap, timeout_ms);
    int i;
    if (!n->open) return k;
    for (i = 0; i < GZP_MAX_TARGETS; i++) {
        const gzp_target_t *t = &n->targets[i];
        int d;
        if (!t->used || t->conn) continue;
        d = t->next_connect_ms > now ? (int)(t->next_connect_ms - now) : 0;
        if (*timeout_ms < 0 || d < *timeout_ms) *timeout_ms = d;
    }
    return k;
}

void gzp_net_dispatch(gzp_net_t *n, const struct pollfd *fds, size_t count, uint64_t now)
{
    gz_peer_event_t ev;
    int k, i;
    gz_peers_dispatch(n->peers, fds, count);
    /* Bounded (M1): what is left is taken next turn. */
    for (k = 0; k < GZP_DRAIN_MAX && gz_peers_poll(n->peers, 0, &ev); k++) handle(n, &ev, now);
    if (!n->open) return;
    for (i = 0; i < GZP_MAX_TARGETS; i++) {
        gzp_target_t *t = &n->targets[i];
        uint64_t conn = 0;
        gz_peers_err_t e;
        if (!t->used || t->conn || now < t->next_connect_ms) continue;
        e = gz_peers_connect(n->peers, t->host, t->port, t->key, NULL, &conn);
        if (e) {
            gzp_log("connect-failed why=%s", gz_peers_err_name(e));
            schedule_reconnect(n, i, now);
        } else {
            t->conn = conn;
        }
    }
}

int gzp_net_reset(gzp_net_t *n)
{
    size_t i;
    gz_peers_free(n->peers); /* every connection and the listener, no events */
    for (i = 0; i < n->nq; i++) free(n->q[i].bytes);
    free(n->q);
    n->q = NULL;
    n->nq = n->capq = 0;
    n->queueing = 0;
    memset(n->conns, 0, sizeof n->conns);
    memset(n->targets, 0, sizeof n->targets);
    n->listening = 0;
    n->open = 0;
    n->queued_total = 0;
    n->peers = gz_peers_new(&n->cfg);
    return n->peers ? 0 : -1;
}

void gzp_net_free(gzp_net_t *n)
{
    size_t i;
    if (n->peers) gz_peers_free(n->peers);
    for (i = 0; i < n->nq; i++) free(n->q[i].bytes);
    free(n->q);
    OPENSSL_cleanse(n->cfg.static_key, sizeof n->cfg.static_key);
    memset(n, 0, sizeof *n);
}
