/* SPDX-License-Identifier: MIT */
/* The network adapter: SEND, CONNECT, DISCONNECT and SET_SEATED out, received
 * messages and connection changes in, over the lobby transport
 * (ports/net/peers.h). The program never uses conn.h (contract-v2.md section
 * 6): every handshake and message is stepped through gz_peers_pollfds /
 * gz_peers_dispatch in the one poll loop.
 *
 * Links (contract-v2.md section 2). The core names a peer by its link: our
 * static key on the connection and the key the handshake proved. Until P8
 * derives per-lobby keys, the transport has one static key (the stand-in
 * transport key), so every link's local key is that key, whatever key epoch
 * and index a CONNECT names. A SEND whose local key is not ours is dropped.
 * Output lines still name a peer by `peer=` and the first 8 bytes of SHA-256
 * of its key, for the tests.
 *
 * Messages (contract-v2.md section 7). SEND and MESSAGE_RECEIVED carry kind,
 * scope and records; the transport adds the protocol tag and type 52791,
 * splits a host's large message and puts parts back together. Kind 32767
 * (test traffic) exists only in the test build's transport (GZ_TEST_KINDS).
 *
 * Connections. A CONNECT keeps a connection to a host while it stands,
 * reconnecting with backoff (the first delay doubling to 60 s); a DISCONNECT
 * of its link stops keeping it. DISCONNECT sends what is queued, then
 * closes (gz_peers_close_after_send), or for `refused` sends a warning and
 * closes (gz_peers_refuse). SET_SEATED marks a member's key
 * (gz_peers_set_seated_key).
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
 * overhead per message (past that the connection is closed). A connection
 * that closes during the start is forgotten at once, with what it queued, and
 * the queue as a whole holds at most 4 MiB. CONNECTs given during the start
 * are kept and acted on once the start is complete. */
#ifndef GZP_NET_H
#define GZP_NET_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include <secp256k1.h>

#include "gazpacho/types.h"
#include "peers.h"

#define GZP_KIND_TEST 32767u
#define GZP_MAX_CONNS 64
#define GZP_MAX_TARGETS 16
#define GZP_QUEUE_PER_CONN (1u << 20)
#define GZP_QUEUE_OVERHEAD 64u     /* counted per queued message, so empty ones count too */
#define GZP_QUEUE_TOTAL (4u << 20) /* the whole start queue, every connection together */
/* Most transport events handled per loop turn (review of PR 27, M1). */
#define GZP_DRAIN_MAX 4
#define GZP_BACKOFF_MAX_MS 60000

typedef struct {
    void (*connected)(void *ctx, const gz_link_t *link, int outbound, uint32_t key_epoch, uint32_t key_index,
                      uint64_t conn);
    void (*disconnected)(void *ctx, const gz_link_t *link, const char *why);
    void (*message)(void *ctx, const gz_link_t *link, uint16_t kind, const uint8_t scope[32],
                    const uint8_t *records, size_t len);
    void *ctx;
} gzp_net_events_t;

typedef struct {
    int handshake_ms, recv_ms, send_ms, ping_ms, pong_ms;
    int max_per_address; /* -1: the transport's default */
    unsigned max_queue;  /* 0: the transport's default */
} gzp_net_limits_t;

typedef struct {
    int used, outbound, target;   /* target: the CONNECT it serves, or -1 */
    uint64_t conn, peer_id;
    uint8_t key[33];
    size_t queued_bytes;
} gzp_conn_t;

typedef struct {
    int used;
    uint8_t key[33];
    char host[80];
    uint16_t port;
    uint32_t epoch, index;
    uint64_t conn, next_connect_ms;
    int backoff_ms;
} gzp_target_t;

typedef struct {
    int type; /* GZ_PEER_EV_CONNECTED, _MESSAGE */
    uint64_t conn;
    uint16_t kind;
    uint8_t scope[32];
    uint8_t *bytes;
    size_t len;
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
    /* member: what CONNECT asked for */
    int open;                       /* gzp_net_open has run: targets may connect */
    gzp_target_t targets[GZP_MAX_TARGETS];
    int first_backoff_ms;
    gzp_conn_t conns[GZP_MAX_CONNS];
    /* the start queue */
    int queueing;
    gzp_qev_t *q;
    size_t nq, capq;
    size_t queued_total; /* bytes plus GZP_QUEUE_OVERHEAD per entry */
    /* tests: a kind dropped on receipt (--test-drop-kind), 0 for none */
    unsigned drop_kind;
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
/* Open the listener (host) and let the CONNECTs connect. 0, or -1 printed. */
int gzp_net_open(gzp_net_t *n);

/* Queue the transport's reports (a start), then hand them over. */
void gzp_net_queue_begin(gzp_net_t *n);
void gzp_net_queue_end(gzp_net_t *n);

/* The actions, from the executor (possibly inside the runner's callback;
 * none calls back into the events).
 * send: 0 handed to the transport, 1 dropped (not connected, a local key not
 * ours, or the connection was closed by the refusal), -1 too big (fatal).
 * connect: 0, or -1 if `address` is not "host:port" or the table is full
 * (an engine bug: fatal). */
int gzp_net_send(gzp_net_t *n, const gz_link_t *link, uint16_t kind, const uint8_t scope[32],
                 const uint8_t *records, size_t len);
int gzp_net_connect(gzp_net_t *n, const uint8_t host_key[33], const uint8_t *address, size_t address_len,
                    uint32_t key_epoch, uint32_t key_index);
void gzp_net_disconnect(gzp_net_t *n, const gz_link_t *link, unsigned why);
void gzp_net_set_seated(gzp_net_t *n, const uint8_t key[33], int seated);
int gzp_net_connected(const gzp_net_t *n, const uint8_t key[33]);

/* The poll loop. */
size_t gzp_net_max_fds(const gzp_net_t *n);
size_t gzp_net_pollfds(gzp_net_t *n, struct pollfd *fds, size_t cap, int *timeout_ms, uint64_t now_ms);
void gzp_net_dispatch(gzp_net_t *n, const struct pollfd *fds, size_t count, uint64_t now_ms);

/* A restart from storage: close every connection and the listener without
 * events (gz_peers_free), forget the queue and every CONNECT, and make a
 * fresh transport; the next start issues its CONNECTs again. 0 or -1. */
int gzp_net_reset(gzp_net_t *n);
void gzp_net_free(gzp_net_t *n);

#ifdef GZP_TEST_BUILD
/* Tests: send a raw factory message of any kind on every live connection
 * (unknown kinds, for the transport's refusals). */
void gzp_net_test_raw(gzp_net_t *n, uint16_t kind, int zero_scope);
#endif

#endif
