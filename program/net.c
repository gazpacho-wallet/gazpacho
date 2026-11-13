/* SPDX-License-Identifier: MIT */
/* The network adapter over ports/net/conn.h. See net.h. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

int gzp_net_init(gzp_net_t *n, const secp256k1_context *secp, const uint8_t priv[32],
                 gz_random_port_t random, const gz_conn_limits_t *limits, int reconnect_ms,
                 const gzp_net_events_t *ev)
{
    secp256k1_pubkey pk;
    size_t len = 33;
    memset(n, 0, sizeof *n);
    n->listen_fd = -1;
    n->secp = secp;
    memcpy(n->priv, priv, 32);
    if (!secp256k1_ec_pubkey_create(secp, &pk, n->priv) ||
        !secp256k1_ec_pubkey_serialize(secp, n->pub, &len, &pk, SECP256K1_EC_COMPRESSED))
        return -1;
    n->random = random;
    n->limits = *limits;
    n->reconnect_ms = reconnect_ms;
    n->ev = *ev;
    return 0;
}

int gzp_net_listen(gzp_net_t *n, const char *host, uint16_t port)
{
    gz_conn_err_t e = gz_conn_listen(host, port, &n->listen_fd, &n->bound_port);
    if (e) {
        fprintf(stderr, "gazpacho: cannot listen on %s:%u: %s\n", host, (unsigned)port, gz_conn_err_name(e));
        n->listen_fd = -1;
        return -1;
    }
    return 0;
}

void gzp_net_target(gzp_net_t *n, const char *host, uint16_t port, const uint8_t key[33])
{
    n->has_target = 1;
    snprintf(n->target_host, sizeof n->target_host, "%s", host);
    n->target_port = port;
    memcpy(n->target_key, key, 33);
    n->next_connect_ms = 0;
}

static gzp_peer_t *find(gzp_net_t *n, uint64_t peer_id)
{
    int i;
    for (i = 0; i < GZP_MAX_PEERS; i++)
        if (n->peers[i].used && !n->peers[i].closing && n->peers[i].peer_id == peer_id) return &n->peers[i];
    return NULL;
}

int gzp_net_connected(const gzp_net_t *n, uint64_t peer_id)
{
    return find((gzp_net_t *)n, peer_id) != NULL;
}

/* Mark for closing; reported (and freed) by gzp_net_poll_done. */
static void doom(gzp_peer_t *p, const char *why)
{
    if (!p->closing) {
        p->closing = 1;
        p->why = why;
        gz_conn_close(p->conn);
    }
}

static int carrier_send(gzp_peer_t *p, const uint8_t *bytes, size_t len)
{
    uint8_t *msg;
    size_t mlen = 0;
    gz_conn_err_t e;
    if (len + 2 > GZ_MSG_MAX) return -1;
    msg = malloc(len + 2);
    if (!msg) return -1;
    if (gz_msg_write((uint16_t)GZP_CARRIER_TYPE, bytes, len, msg, len + 2, &mlen) != GZ_FRAME_OK) {
        free(msg);
        return -1;
    }
    e = gz_conn_send(p->conn, msg, mlen);
    free(msg);
    if (e) {
        doom(p, gz_conn_err_name(e));
        return -1;
    }
    return 0;
}

static int keep(gzp_net_t *n, uint64_t peer_id, const uint8_t *bytes, size_t len)
{
    gzp_out_t *o;
    if (n->out_bytes + len > GZP_OUTBOX_MAX_BYTES) {
        n->dropped++;
        return -1;
    }
    if (n->n_out == n->cap_out) {
        size_t c = n->cap_out ? n->cap_out * 2 : 32;
        gzp_out_t *no = realloc(n->out, c * sizeof *no);
        if (!no) return -1;
        n->out = no;
        n->cap_out = c;
    }
    o = &n->out[n->n_out];
    o->bytes = malloc(len ? len : 1);
    if (!o->bytes) return -1;
    if (len) memcpy(o->bytes, bytes, len);
    o->len = len;
    o->peer_id = peer_id;
    n->n_out++;
    n->out_bytes += len;
    return 1;
}

int gzp_net_send(gzp_net_t *n, uint64_t peer_id, const uint8_t *bytes, size_t len)
{
    gzp_peer_t *p = find(n, peer_id);
    if (len + 2 > GZ_MSG_MAX) return -1;
    if (p && carrier_send(p, bytes, len) == 0) return 0;
    /* Not connected, or the send failed (the connection is now closing):
     * keep it for the next connection. */
    return keep(n, peer_id, bytes, len);
}

int gzp_net_send_raw_carrier(gzp_net_t *n, uint64_t peer_id, const uint8_t *bytes, size_t len)
{
    gzp_peer_t *p = find(n, peer_id);
    return p ? carrier_send(p, bytes, len) : -1;
}

/* Send what the outbox holds for this peer, oldest first. */
static void flush(gzp_net_t *n, gzp_peer_t *p)
{
    size_t i, j = 0;
    for (i = 0; i < n->n_out; i++) {
        gzp_out_t *o = &n->out[i];
        if (o->peer_id == p->peer_id && !p->closing && carrier_send(p, o->bytes, o->len) == 0) {
            n->out_bytes -= o->len;
            free(o->bytes);
            continue;
        }
        n->out[j++] = *o;
    }
    n->n_out = j;
}

static gzp_peer_t *new_slot(gzp_net_t *n)
{
    int i;
    for (i = 0; i < GZP_MAX_PEERS; i++)
        if (!n->peers[i].used) {
            gzp_peer_t *p = &n->peers[i];
            memset(p, 0, sizeof *p);
            p->conn = calloc(1, sizeof *p->conn); /* 64 KiB buffer each */
            if (!p->conn) return NULL;
            p->used = 1;
            return p;
        }
    return NULL;
}

static void free_slot(gzp_peer_t *p)
{
    gz_conn_close(p->conn);
    free(p->conn);
    memset(p, 0, sizeof *p);
}

/* A connection is up: replace an older one from the same key, then deliver. */
static void up(gzp_net_t *n, gzp_peer_t *p)
{
    int i;
    gz_conn_remote_static(p->conn, p->key);
    p->peer_id = gzp_peer_id(p->key);
    for (i = 0; i < GZP_MAX_PEERS; i++) {
        gzp_peer_t *q = &n->peers[i];
        if (q != p && q->used && !q->closing && q->peer_id == p->peer_id) doom(q, "replaced by a newer connection");
    }
    /* Report the replaced one's loss before the new one's arrival. */
    {
        for (i = 0; i < GZP_MAX_PEERS; i++) {
            gzp_peer_t *q = &n->peers[i];
            if (q->used && q->closing && q != p) {
                uint64_t id = q->peer_id;
                const char *why = q->why;
                free_slot(q);
                if (n->ev.disconnected) n->ev.disconnected(n->ev.ctx, id, why);
            }
        }
    }
    flush(n, p);
    if (n->ev.connected) n->ev.connected(n->ev.ctx, p->peer_id, p->key);
}

/* slice1-attempt: the transport now takes its own random type (noise.h). */
static void net_rand_fill(void *ctx, uint8_t *out, size_t len)
{
    const gz_random_port_t *r = ctx;
    r->fill(r->ctx, GZ_RANDOM_SECRET, out, len);
}
static gz_net_random_t netrnd(gzp_net_t *n)
{
    gz_net_random_t r = {net_rand_fill, &n->random};
    return r;
}

static void do_accept(gzp_net_t *n)
{
    gzp_peer_t *p = new_slot(n);
    gz_conn_limits_t lim = n->limits;
    gz_conn_err_t e;
    if (!p) {
        /* Full: take the connection and drop it, so poll does not spin. */
        int fd = accept(n->listen_fd, NULL, NULL);
        if (fd >= 0) close(fd);
        return;
    }
    lim.accept_ms = 1000; /* poll said one is waiting */
    /* Slice 1's host accepts any member key (transport.md rule 13). The
     * handshake blocks the loop for up to handshake_ms (transport.md,
     * "Limits"; peers.h in PR 23 steps it without blocking). */
    e = gz_conn_accept(p->conn, n->listen_fd, n->secp, n->priv, netrnd(n), &lim, gz_conn_any_member, NULL);
    if (e) {
        gzp_log("accept-failed why=%s", gz_conn_err_name(e));
        free_slot(p);
        return;
    }
    up(n, p);
}

static void do_connect(gzp_net_t *n, uint64_t now)
{
    gzp_peer_t *p;
    gz_conn_err_t e;
    n->next_connect_ms = now + (uint64_t)n->reconnect_ms;
    if (find(n, gzp_peer_id(n->target_key))) return;
    p = new_slot(n);
    if (!p) return;
    /* Blocks for up to handshake_ms. */
    e = gz_conn_connect(p->conn, n->target_host, n->target_port, n->secp, n->priv, n->target_key,
                        netrnd(n), &n->limits);
    if (e) {
        gzp_log("connect-failed why=%s", gz_conn_err_name(e));
        free_slot(p);
        return;
    }
    up(n, p);
}

static void do_recv(gzp_net_t *n, gzp_peer_t *p)
{
    uint8_t *msg = malloc(GZ_MSG_MAX);
    size_t len = 0;
    uint16_t type;
    const uint8_t *rest;
    size_t rest_len;
    gz_conn_err_t e;
    if (!msg) return;
    /* poll said bytes are waiting; a whole message must follow within recv_ms. */
    e = gz_conn_recv(p->conn, msg, GZ_MSG_MAX, &len);
    if (e) {
        doom(p, gz_conn_err_name(e));
    } else if (gz_msg_parse(msg, len, &type, &rest, &rest_len) != GZ_FRAME_OK) {
        doom(p, "malformed message");
    } else if (type == GZP_CARRIER_TYPE) {
        if (n->ev.message) n->ev.message(n->ev.ctx, p->peer_id, rest, rest_len);
    } else if (gz_msg_unknown_action(type) == GZ_MSG_CLOSE) {
        doom(p, "unknown even message");
    } /* else an unknown odd message: ignored (BOLT 1) */
    free(msg);
}

size_t gzp_net_pollfds(gzp_net_t *n, struct pollfd *fds, size_t cap)
{
    size_t k = 0;
    int i;
    if (n->listen_fd >= 0 && k < cap) {
        fds[k].fd = n->listen_fd;
        fds[k].events = POLLIN;
        fds[k].revents = 0;
        k++;
    }
    for (i = 0; i < GZP_MAX_PEERS && k < cap; i++) {
        gzp_peer_t *p = &n->peers[i];
        if (!p->used || p->closing) continue;
        fds[k].fd = p->conn->fd;
        fds[k].events = POLLIN;
        fds[k].revents = 0;
        k++;
    }
    return k;
}

void gzp_net_poll_done(gzp_net_t *n, const struct pollfd *fds, size_t count, uint64_t now)
{
    size_t k;
    int i;
    for (k = 0; k < count; k++) {
        if (!fds[k].revents) continue;
        if (fds[k].fd == n->listen_fd) {
            if (fds[k].revents & POLLIN) do_accept(n);
            continue;
        }
        for (i = 0; i < GZP_MAX_PEERS; i++) {
            gzp_peer_t *p = &n->peers[i];
            if (p->used && !p->closing && p->conn->fd == fds[k].fd) {
                if (fds[k].revents & (POLLIN | POLLHUP | POLLERR)) do_recv(n, p);
                break;
            }
        }
    }
    /* Report losses, including sends that failed inside the executor. */
    for (i = 0; i < GZP_MAX_PEERS; i++) {
        gzp_peer_t *p = &n->peers[i];
        if (p->used && p->closing) {
            uint64_t id = p->peer_id;
            const char *why = p->why;
            free_slot(p);
            if (n->ev.disconnected) n->ev.disconnected(n->ev.ctx, id, why);
        }
    }
    if (n->has_target && now >= n->next_connect_ms) do_connect(n, now);
}

int gzp_net_timeout(const gzp_net_t *n, uint64_t now)
{
    if (!n->has_target || gzp_net_connected(n, gzp_peer_id(n->target_key))) return -1;
    return n->next_connect_ms > now ? (int)(n->next_connect_ms - now) : 0;
}

void gzp_net_drop_all(gzp_net_t *n)
{
    int j;
    for (j = 0; j < GZP_MAX_PEERS; j++)
        if (n->peers[j].used) free_slot(&n->peers[j]);
    n->next_connect_ms = 0;
}

void gzp_net_free(gzp_net_t *n)
{
    size_t i;
    int j;
    for (j = 0; j < GZP_MAX_PEERS; j++)
        if (n->peers[j].used) free_slot(&n->peers[j]);
    for (i = 0; i < n->n_out; i++) free(n->out[i].bytes);
    free(n->out);
    if (n->listen_fd >= 0) close(n->listen_fd);
    OPENSSL_cleanse(n->priv, sizeof n->priv);
    memset(n, 0, sizeof *n);
    n->listen_fd = -1;
}
