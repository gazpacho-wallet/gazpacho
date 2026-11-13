/* SPDX-License-Identifier: MIT */
/* The network adapter: SEND actions out, received messages in, over the
 * merged transport (ports/net/conn.h, one BOLT 8 connection per peer).
 *
 * Peer identifiers. The core names a peer by a uint64_t; the transport by its
 * 33-byte static key. The adapter's peer id is the first 8 bytes, big-endian,
 * of SHA-256 of that key, so it is the same after a restart of either side:
 * the placeholder node stores the peer id with each ping and resends the
 * reply to it after a restart. A connection from a key already connected
 * replaces the older one.
 *
 * Carrier. The node's message bytes travel as the body of one odd custom
 * Lightning message, GZP_CARRIER_TYPE. This is a skeleton carrier: when the
 * lobby transport (PR 23) is merged, node messages travel in the factory
 * envelope (messages.md section 3, type 52791) instead, through
 * ports/net/peers.h.
 *
 * Sends to a peer that is not connected are kept, in order, in a bounded
 * outbox and go out when it connects. They are lost if the program stops: a
 * SEND released by the runner has not necessarily left this machine
 * (docs/notes/program.md, "Mismatches"). */
#ifndef GZP_NET_H
#define GZP_NET_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include <secp256k1.h>

#include "conn.h"

#define GZP_CARRIER_TYPE 32771u
#define GZP_MAX_PEERS 16
#define GZP_OUTBOX_MAX_BYTES (1u << 20)

typedef struct {
    void (*connected)(void *ctx, uint64_t peer_id, const uint8_t key[33]);
    void (*disconnected)(void *ctx, uint64_t peer_id, const char *why);
    void (*message)(void *ctx, uint64_t peer_id, const uint8_t *bytes, size_t len);
    void *ctx;
} gzp_net_events_t;

typedef struct {
    int used, closing;
    gz_conn_t *conn;
    uint64_t peer_id;
    uint8_t key[33];
    const char *why;
} gzp_peer_t;

typedef struct {
    uint64_t peer_id;
    uint8_t *bytes;
    size_t len;
} gzp_out_t;

typedef struct {
    const secp256k1_context *secp;
    uint8_t priv[32];
    uint8_t pub[33];
    gz_random_port_t random;
    gz_conn_limits_t limits;
    gzp_net_events_t ev;
    int listen_fd;
    uint16_t bound_port;
    /* member: the host to keep a connection to */
    int has_target;
    char target_host[64];
    uint16_t target_port;
    uint8_t target_key[33];
    uint64_t next_connect_ms;
    int reconnect_ms;
    gzp_peer_t peers[GZP_MAX_PEERS];
    gzp_out_t *out;
    size_t n_out, cap_out, out_bytes;
    uint64_t dropped;
} gzp_net_t;

uint64_t gzp_peer_id(const uint8_t key[33]);

/* `priv` is copied; the caller wipes its own copy. 0 or -1. */
int gzp_net_init(gzp_net_t *n, const secp256k1_context *secp, const uint8_t priv[32],
                 gz_random_port_t random, const gz_conn_limits_t *limits, int reconnect_ms,
                 const gzp_net_events_t *ev);
/* Host: listen on a numeric address. 0, or -1 with a reason printed. */
int gzp_net_listen(gzp_net_t *n, const char *host, uint16_t port);
/* Member: keep one connection to the host whose key is `key`. */
void gzp_net_target(gzp_net_t *n, const char *host, uint16_t port, const uint8_t key[33]);

/* Called from the executor: send now if connected, else keep in the outbox.
 * Never calls back into the events (it may run inside the runner's executor
 * callback); a failure closes the connection and is reported at the next
 * gzp_net_poll_done. Returns 0 sent, 1 kept, -1 dropped (too big, or the
 * outbox is full). */
int gzp_net_send(gzp_net_t *n, uint64_t peer_id, const uint8_t *bytes, size_t len);
/* Send any Lightning message to a connected peer (tests). 0 or -1. */
int gzp_net_send_raw_carrier(gzp_net_t *n, uint64_t peer_id, const uint8_t *bytes, size_t len);
int gzp_net_connected(const gzp_net_t *n, uint64_t peer_id);

/* The poll loop: add our descriptors (returns how many), then after poll()
 * handle them; events are delivered from gzp_net_poll_done only. */
size_t gzp_net_pollfds(gzp_net_t *n, struct pollfd *fds, size_t cap);
void gzp_net_poll_done(gzp_net_t *n, const struct pollfd *fds, size_t count, uint64_t now_ms);
/* Milliseconds until the adapter next wants to act (a reconnect), or -1. */
int gzp_net_timeout(const gzp_net_t *n, uint64_t now_ms);

/* Close every connection without events (a restart from storage: peers see
 * the loss and send again what was not answered). The outbox is kept. */
void gzp_net_drop_all(gzp_net_t *n);
void gzp_net_free(gzp_net_t *n);

#endif
