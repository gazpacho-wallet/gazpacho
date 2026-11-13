/* SPDX-License-Identifier: MIT */
/* The network adapter: SEND actions out, received messages and connection
 * changes in, over the lobby transport (ports/net/peers.h). The program never
 * uses conn.h (contract-v2.md section 6): every handshake and message is
 * stepped through gz_peers_pollfds / gz_peers_dispatch in the one poll loop.
 *
 * Peer identifiers. Until P4 gives the core links (contract-v2.md section 2)
 * the core still names a peer by a uint64_t: here the first 8 bytes,
 * big-endian, of SHA-256 of the peer's 33-byte static key. The transport
 * keeps one live connection per key (GZ_PEER_WHY_REPLACED).
 *
 * Carrier. Until P4 gives SEND a kind and a scope, the placeholder's bytes
 * travel as record 1 (odd) of the test kind 32767, scope zero, which only the
 * test build's transport knows (GZ_TEST_KINDS). The release build sends
 * nothing for the placeholder and ignores kind 32767 like any unknown odd
 * kind.
 *
 * Losses (contract-v2.md section 1). There is no outbox: a SEND to a peer
 * with no live connection is dropped and counted. Any refusal of a send on a
 * live connection closes it in the transport (GZ_PEER_WHY_SEND_REFUSED), so
 * every loss coincides with a reconnect; a message too big is fatal for the
 * incarnation.
 *
 * Starts (contract-v2.md section 1). While the executor starts a node the
 * adapter queues what the transport reports, per connection, and hands it
 * over when the start is complete: a connection's messages only between its
 * own connected and disconnected, a connection that came and went during the
 * start not at all, at most 1 MiB per connection, counting 64 bytes of
 * overhead per message (past that the connection is closed). */
#ifndef GZP_NET_H
#define GZP_NET_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include <secp256k1.h>

#include "peers.h"

#define GZP_KIND_TEST 32767u
#define GZP_MAX_CONNS 64
#define GZP_QUEUE_PER_CONN (1u << 20)
#define GZP_QUEUE_OVERHEAD 64u     /* counted per queued message, so empty ones count too */
/* Most transport events handled per loop turn (review of PR 27, M1): a peer
 * that keeps sending cannot hold the loop, so the stop pipe, the timers and
 * the chain are seen at least once per GZP_DRAIN_MAX events. */
#define GZP_DRAIN_MAX 4
#define GZP_BACKOFF_MAX_MS 60000

typedef struct {
    void (*connected)(void *ctx, uint64_t peer_id, const uint8_t key[33], int outbound, uint64_t conn);
    void (*disconnected)(void *ctx, uint64_t peer_id, const char *why);
    void (*message)(void *ctx, uint64_t peer_id, const uint8_t *bytes, size_t len);
    void *ctx;
} gzp_net_events_t;

typedef struct {
    int handshake_ms, recv_ms, send_ms, ping_ms, pong_ms;
    int max_per_address; /* -1: the transport's default */
} gzp_net_limits_t;

typedef struct {
    int used, outbound;
    uint64_t conn, peer_id;
    uint8_t key[33];
    size_t queued_bytes;
} gzp_conn_t;

typedef struct {
    int type; /* GZ_PEER_EV_CONNECTED, _MESSAGE, _CLOSED */
    uint64_t conn;
    uint8_t *bytes;
    size_t len;
    const char *why;
} gzp_qev_t;

typedef struct {
    gz_peers_config_t cfg;
    gz_peers_t *peers;
    uint8_t pub[33];
    gzp_net_events_t ev;
    /* host */
    int want_listen, listening;
    char listen_host[64];
    uint16_t listen_port, bound_port;
    /* member: one connection to the pinned host, the stand-in for CONNECT (P4) */
    int has_target, target_live;
    char target_host[64];
    uint16_t target_port;
    uint8_t target_key[33];
    uint64_t target_conn, next_connect_ms;
    int backoff_ms, first_backoff_ms;
    gzp_conn_t conns[GZP_MAX_CONNS];
    /* the start queue */
    int queueing;
    gzp_qev_t *q;
    size_t nq, capq;
    /* counters */
    uint64_t dropped_unconnected, closed_while_starting;
} gzp_net_t;

uint64_t gzp_peer_id(const uint8_t key[33]);

/* `priv` is copied into the transport's configuration and wiped with it.
 * `chain` is init's chain hash (signet or testnet4; the transport refuses the
 * main network). 0, or -1 if the transport refuses the configuration. */
int gzp_net_init(gzp_net_t *n, const secp256k1_context *secp, const uint8_t priv[32], gz_net_random_t random,
                 const uint8_t chain[32], const gzp_net_limits_t *lim, int reconnect_ms,
                 const gzp_net_events_t *ev);
/* Host: where to listen. Nothing is opened until gzp_net_open (after the start). */
void gzp_net_set_listen(gzp_net_t *n, const char *host, uint16_t port);
/* Member: keep one connection to the host whose key is `key`, from gzp_net_open on. */
void gzp_net_target(gzp_net_t *n, const char *host, uint16_t port, const uint8_t key[33]);
/* Open the listener (host) and allow connecting (member). 0, or -1 printed. */
int gzp_net_open(gzp_net_t *n);

/* Queue the transport's reports (a start), then hand them over. */
void gzp_net_queue_begin(gzp_net_t *n);
void gzp_net_queue_end(gzp_net_t *n);

/* From the executor (possibly inside the runner's callback; never calls back
 * into the events): 0 handed to the transport, 1 dropped (not connected, or
 * the connection was closed by the refusal), -1 too big (fatal). */
int gzp_net_send(gzp_net_t *n, uint64_t peer_id, const uint8_t *bytes, size_t len);
int gzp_net_connected(const gzp_net_t *n, uint64_t peer_id);

/* The poll loop. */
size_t gzp_net_max_fds(const gzp_net_t *n);
size_t gzp_net_pollfds(gzp_net_t *n, struct pollfd *fds, size_t cap, int *timeout_ms, uint64_t now_ms);
void gzp_net_dispatch(gzp_net_t *n, const struct pollfd *fds, size_t count, uint64_t now_ms);

/* A restart from storage: close every connection and the listener without
 * events (gz_peers_free), forget the queue, and make a fresh transport;
 * gzp_net_open opens again after the next start. 0 or -1. */
int gzp_net_reset(gzp_net_t *n);
void gzp_net_free(gzp_net_t *n);

#endif
