/* SPDX-License-Identifier: MIT */
/* The network adapter over ports/net/peers.h. See net.h. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

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
    if (n->cfg.max_conns > GZP_MAX_CONNS) n->cfg.max_conns = GZP_MAX_CONNS;
    if (!secp256k1_ec_pubkey_create(secp, &pk, n->cfg.static_key) ||
        !secp256k1_ec_pubkey_serialize(secp, n->pub, &len, &pk, SECP256K1_EC_COMPRESSED))
        return -1;
    n->ev = *ev;
    n->first_backoff_ms = n->backoff_ms = reconnect_ms;
    n->peers = gz_peers_new(&n->cfg);
    return n->peers ? 0 : -1;
}

void gzp_net_set_listen(gzp_net_t *n, const char *host, uint16_t port)
{
    n->want_listen = 1;
    snprintf(n->listen_host, sizeof n->listen_host, "%s", host);
    n->listen_port = port;
}

void gzp_net_target(gzp_net_t *n, const char *host, uint16_t port, const uint8_t key[33])
{
    n->has_target = 1;
    snprintf(n->target_host, sizeof n->target_host, "%s", host);
    n->target_port = port;
    memcpy(n->target_key, key, 33);
}

int gzp_net_open(gzp_net_t *n)
{
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
    if (n->has_target) {
        n->target_live = 1;
        n->next_connect_ms = 0;
        n->backoff_ms = n->first_backoff_ms;
    }
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

static gzp_conn_t *by_peer(const gzp_net_t *n, uint64_t peer_id)
{
    int i;
    for (i = 0; i < GZP_MAX_CONNS; i++)
        if (n->conns[i].used && n->conns[i].peer_id == peer_id) return (gzp_conn_t *)&n->conns[i];
    return NULL;
}

int gzp_net_connected(const gzp_net_t *n, uint64_t peer_id)
{
    return by_peer(n, peer_id) != NULL;
}

/* ---- the placeholder carrier ---------------------------------------------- */

/* The bytes of record 1 in a TLV stream, or NULL. */
const uint8_t *gzp_net_record1(const uint8_t *s, size_t len, size_t *out_len)
{
    size_t off = 0;
    while (off < len) {
        uint64_t type, l;
        size_t u1, u2;
        if (gz_bigsize_read(s + off, len - off, &type, &u1) != GZ_FRAME_OK) return NULL;
        if (gz_bigsize_read(s + off + u1, len - off - u1, &l, &u2) != GZ_FRAME_OK) return NULL;
        off += u1 + u2;
        if (l > len - off) return NULL;
        if (type == 1) {
            *out_len = (size_t)l;
            return s + off;
        }
        off += (size_t)l;
    }
    return NULL;
}

int gzp_net_send(gzp_net_t *n, uint64_t peer_id, const uint8_t *bytes, size_t len)
{
    gzp_conn_t *c = by_peer(n, peer_id);
    if (!c || n->queueing) {
        /* No outbox (contract-v2.md section 1). During a start nothing of a
         * connection has been reported to the node, so nothing is sent on it. */
        n->dropped_unconnected++;
        gzp_log("send-dropped peer=%016llx why=not-connected", (unsigned long long)peer_id);
        return 1;
    }
#ifdef GZP_TEST_BUILD
    {
        uint8_t hdr[18], scope[32];
        uint8_t *rec;
        size_t h = 0, rl;
        gz_peers_err_t e;
        h += gz_bigsize_write(1, hdr);
        h += gz_bigsize_write(len, hdr + h);
        rl = h + len;
        rec = malloc(rl ? rl : 1);
        if (!rec) abort();
        memcpy(rec, hdr, h);
        if (len) memcpy(rec + h, bytes, len);
        memset(scope, 0, sizeof scope);
        e = gz_peers_send(n->peers, c->conn, GZP_KIND_TEST, scope, rec, rl);
        free(rec);
        if (e == GZ_PEERS_OK) return 0;
        if (e == GZ_PEERS_ERR_TOO_BIG) return -1;
        /* FULL or ARGS closed the connection (SEND_REFUSED, an event follows);
         * NO_CONN and NOT_READY: it is going or not there. */
        gzp_log("send-refused peer=%016llx why=%s", (unsigned long long)peer_id, gz_peers_err_name(e));
        return 1;
    }
#else
    (void)bytes;
    gzp_log("send-dropped peer=%016llx len=%zu why=no-kind-in-release-build", (unsigned long long)peer_id, len);
    return 1;
#endif
}

/* ---- events --------------------------------------------------------------- */

static void enqueue(gzp_net_t *n, int type, uint64_t conn, const uint8_t *bytes, size_t len, const char *why)
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
    e->type = type;
    e->conn = conn;
    e->why = why;
    e->len = len;
    e->bytes = NULL;
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

/* A reason as one word for output lines: "handshake timed out" becomes
 * "handshake-timed-out". Valid until the next call. */
static const char *word(const char *s)
{
    static char buf[64];
    size_t i;
    for (i = 0; s[i] && i + 1 < sizeof buf; i++) buf[i] = s[i] == ' ' ? '-' : s[i];
    buf[i] = 0;
    return buf;
}

static void schedule_reconnect(gzp_net_t *n, uint64_t now)
{
    n->target_conn = 0;
    n->next_connect_ms = now + (uint64_t)n->backoff_ms;
    n->backoff_ms = n->backoff_ms * 2 > GZP_BACKOFF_MAX_MS ? GZP_BACKOFF_MAX_MS : n->backoff_ms * 2;
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
        if (ev->outbound && ev->conn == n->target_conn) n->backoff_ms = n->first_backoff_ms;
        if (n->queueing) enqueue(n, GZ_PEER_EV_CONNECTED, ev->conn, NULL, 0, NULL);
        else if (n->ev.connected) n->ev.connected(n->ev.ctx, c->peer_id, c->key, c->outbound, c->conn);
        break;
    }
    case GZ_PEER_EV_MESSAGE: {
        const uint8_t *b = NULL;
        size_t bl = 0;
        if (!c) break;
        if (ev->kind == GZP_KIND_TEST) b = gzp_net_record1(ev->records, ev->records_len, &bl);
        if (!b) {
            gzp_log("message-ignored peer=%016llx kind=%u", (unsigned long long)c->peer_id, (unsigned)ev->kind);
            break;
        }
        if (n->queueing) {
            c->queued_bytes += bl + GZP_QUEUE_OVERHEAD;
            if (c->queued_bytes > GZP_QUEUE_PER_CONN ||
                n->queued_total + bl + GZP_QUEUE_OVERHEAD > GZP_QUEUE_TOTAL) {
                /* Past the start queue's limit, for this connection or for
                 * the queue as a whole (B5): close it; it was never
                 * reported. gz_peers_close gives no CLOSED event, so a
                 * member's own connection is rescheduled here. */
                gzp_log("start-queue closed conn=%llu why=%s peer=%016llx", (unsigned long long)c->conn,
                        c->queued_bytes > GZP_QUEUE_PER_CONN ? "over-1MiB" : "over-total",
                        (unsigned long long)c->peer_id);
                if (c->conn == n->target_conn && n->target_live) schedule_reconnect(n, now);
                gz_peers_close(n->peers, c->conn);
                unqueue_conn(n, c->conn);
                n->closed_while_starting++;
                memset(c, 0, sizeof *c);
                break;
            }
            enqueue(n, GZ_PEER_EV_MESSAGE, ev->conn, b, bl, NULL);
        } else if (n->ev.message) {
            n->ev.message(n->ev.ctx, c->peer_id, b, bl);
        }
        break;
    }
    case GZ_PEER_EV_CLOSED: {
        const char *why = word(gz_peer_why_name(ev->why));
        char hex[67];
        gzp_hex(ev->node_id, 33, hex);
        gzp_log("closed conn=%llu why=%s was_connected=%d key=%s", (unsigned long long)ev->conn, why,
                ev->was_connected, ev->have_node_id ? hex : "-");
        if (ev->outbound && ev->conn == n->target_conn && n->target_live) schedule_reconnect(n, now);
        if (c) {
            uint64_t id = c->peer_id;
            if (n->queueing) {
                /* It came and went during the start: never reported, and
                 * what it queued is freed now, not at the end of the start
                 * (review B of PR 27, B5). */
                size_t k = unqueue_conn(n, ev->conn);
                gzp_log("start-queue dropped conn=%llu why=closed-during-start peer=%016llx messages=%zu",
                        (unsigned long long)ev->conn, (unsigned long long)id, k);
            }
            memset(c, 0, sizeof *c);
            if (!n->queueing && ev->was_connected && n->ev.disconnected) n->ev.disconnected(n->ev.ctx, id, why);
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
 * its CLOSED arrived (that is the guard the tests cover: two_process's member
 * 4, queue_overhead's "gone"); the slot check below is a second guard only
 * (connection numbers are never reused, and a closed slot is cleared). */
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
        if (q[i].type != GZ_PEER_EV_CONNECTED) continue;
        c = by_conn(n, q[i].conn);
        if (!c) {
            gzp_log("start-queue dropped conn=%llu why=closed-during-start", (unsigned long long)q[i].conn);
            continue;
        }
        c->queued_bytes = 0;
        if (n->ev.connected) n->ev.connected(n->ev.ctx, c->peer_id, c->key, c->outbound, c->conn);
        /* Every queued message of the connection, in order. A delivery that
         * closes it (a refused send) is reported by the transport later, so
         * these still come before that connection's disconnected. */
        for (j = i + 1; j < nq; j++) {
            if (q[j].conn != q[i].conn || q[j].type != GZ_PEER_EV_MESSAGE) continue;
            if (n->ev.message) n->ev.message(n->ev.ctx, c->peer_id, q[j].bytes, q[j].len);
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
    if (n->has_target && n->target_live && !n->target_conn) {
        int t = n->next_connect_ms > now ? (int)(n->next_connect_ms - now) : 0;
        if (*timeout_ms < 0 || t < *timeout_ms) *timeout_ms = t;
    }
    return k;
}

void gzp_net_dispatch(gzp_net_t *n, const struct pollfd *fds, size_t count, uint64_t now)
{
    gz_peer_event_t ev;
    int k;
    gz_peers_dispatch(n->peers, fds, count);
    /* Bounded (M1): gz_peers_poll(p, 0) does I/O of its own when its queue is
     * empty, so an unbounded drain could last as long as a peer keeps
     * sending. What is left is taken next turn: gz_peers_pollfds then gives
     * a zero timeout. */
    for (k = 0; k < GZP_DRAIN_MAX && gz_peers_poll(n->peers, 0, &ev); k++) handle(n, &ev, now);
    if (n->has_target && n->target_live && !n->target_conn && now >= n->next_connect_ms) {
        uint64_t conn = 0;
        gz_peers_err_t e = gz_peers_connect(n->peers, n->target_host, n->target_port, n->target_key, NULL, &conn);
        if (e) {
            gzp_log("connect-failed why=%s", gz_peers_err_name(e));
            schedule_reconnect(n, now);
        } else {
            n->target_conn = conn;
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
    n->listening = 0;
    n->queued_total = 0;
    n->target_live = 0;
    n->target_conn = 0;
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
