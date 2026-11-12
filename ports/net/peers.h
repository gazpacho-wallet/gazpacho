/* Lobby connections: many BOLT 8 connections driven by one poll loop, with
 * BOLT 1's init, ping and pong, Gazpacho's factory envelope, and events.
 *
 * The host listens and accepts; a member connects, giving the host's key as
 * a pin and, for each connection, its own static key (messages.md section 2:
 * a fresh key per new connection, or the seat's key). Every handshake is
 * stepped without blocking, so a silent peer holds only its own slot until
 * the handshake deadline (review of PR 10, F2). Once both sides have sent
 * init, a connection stays open while it answers pings: a ping goes out
 * after ping_ms (15 s) without a message from the peer, and a peer whose pong
 * has not come within pong_ms (30 s) is closed.
 *
 * Everything that happens is reported as an event from gz_peers_poll,
 * failures included: a connection refused, lost, timed out, refused by us or
 * by the peer. Each event names the connection and, once the handshake has
 * proved it, the peer's node id (its static key). Running out of memory
 * aborts the program (a slice 1 choice: an event must never be lost). See spec/transport.md,
 * "Lobby connections". POSIX only; one thread. */
#ifndef GAZPACHO_NET_PEERS_H
#define GAZPACHO_NET_PEERS_H

#include <stddef.h>
#include <stdint.h>
#include "conn.h"
#include "envelope.h"

typedef struct {
    const secp256k1_context *secp;
    uint8_t static_key[32];  /* the listener's key, and the default for connections we make */
    gz_random_port_t random;
    uint8_t chain[32];       /* init's networks: exactly this chain (signet in slice 1) */
    gz_conn_member_fn is_member; /* required for accepted connections (transport.md rule 13) */
    void *member_ctx;
    int handshake_ms;        /* TCP connect, handshake and init, from the start (default 10,000) */
    int ping_ms;             /* send a ping after this long without a message (default 15,000) */
    int pong_ms;             /* close if the pong has not come within this (default 30,000) */
    int recv_ms;             /* one message, header and body, from its first byte (default 30,000) */
    int send_ms;             /* queued bytes must make progress within this (default 10,000) */
    unsigned max_conns;      /* open connections, both kinds (default 64) */
    size_t max_queue;        /* unsent bytes per connection (default 4 MiB) */
    unsigned max_pings;      /* pings accepted per pong_ms window before closing (default 10) */
    unsigned max_handshakes; /* accepted connections still in their handshake or before init; when
                                full, the oldest is evicted (default 16; review of PR 23, F1) */
    unsigned max_per_address; /* accepted connections from one IP address, 0 for no cap (default 4) */
    unsigned max_ignored;    /* ignored messages (unknown odd types and kinds, wrong tags, warnings)
                                per pong_ms window before closing (default 100) */
    unsigned max_warning_events; /* WARNING events per connection; later ones are counted (default 10) */
} gz_peers_config_t;

/* Fills the defaults above; the caller then sets secp, static_key, random,
 * is_member and, if not signet, chain. */
void gz_peers_default_config(gz_peers_config_t *c);

typedef enum {
    GZ_PEER_EV_CONNECTED = 1, /* handshake done and the peer's init accepted: messages may be sent */
    GZ_PEER_EV_MESSAGE,       /* a whole factory message, put back together if it came in parts */
    GZ_PEER_EV_WARNING,       /* the peer sent a BOLT 1 warning; the connection stays */
    GZ_PEER_EV_CLOSED         /* the connection is gone; `why` says how */
} gz_peer_ev_type_t;

typedef enum {
    GZ_PEER_WHY_NONE = 0,
    GZ_PEER_WHY_LOST,              /* the peer closed or reset the connection */
    GZ_PEER_WHY_REFUSED,           /* our connect was refused (nobody listening) */
    GZ_PEER_WHY_TIMEOUT_CONNECT,   /* TCP connect did not finish within handshake_ms */
    GZ_PEER_WHY_TIMEOUT_HANDSHAKE, /* handshake or init not finished within handshake_ms */
    GZ_PEER_WHY_TIMEOUT_PONG,      /* no pong within pong_ms */
    GZ_PEER_WHY_TIMEOUT_MESSAGE,   /* a message started but not finished within recv_ms */
    GZ_PEER_WHY_TIMEOUT_SEND,      /* our queued bytes made no progress within send_ms */
    GZ_PEER_WHY_HANDSHAKE,         /* BOLT 8 refused (wrong pin, bad MAC, ...); see noise_err */
    GZ_PEER_WHY_NOT_MEMBER,        /* our member check refused the peer's key */
    GZ_PEER_WHY_INIT,              /* the peer's init: missing, malformed, wrong chain, required feature */
    GZ_PEER_WHY_PROTOCOL,          /* we refused a message (warning sent); see text */
    GZ_PEER_WHY_PEER_ERROR,        /* the peer sent a BOLT 1 error; see text */
    GZ_PEER_WHY_CRYPTO,            /* a message failed to decrypt */
    GZ_PEER_WHY_SOCKET,            /* another system error; see sys_errno */
    GZ_PEER_WHY_ADDRESS,           /* the address is not numeric */
    GZ_PEER_WHY_LOCAL,             /* we refused it with gz_peers_refuse */
    GZ_PEER_WHY_EVICTED,           /* made way for a newcomer: the oldest handshake when the handshake
                                      budget was full, or the oldest connection without a seat when
                                      max_conns were established */
    GZ_PEER_WHY_FULL               /* max_conns established, every accepted one holding a seat */
} gz_peer_why_t;

typedef struct {
    gz_peer_ev_type_t type;
    uint64_t conn;            /* never reused */
    int outbound;             /* 1: we connected (we are the member); 0: we accepted (the host) */
    int have_node_id;         /* the handshake proved the peer's key (always, for outbound: the pin) */
    uint8_t node_id[33];
    /* GZ_PEER_EV_MESSAGE */
    uint16_t kind;
    uint8_t scope[32];
    const uint8_t *records;   /* valid until the next gz_peers_poll or gz_peers_free */
    size_t records_len;
    /* GZ_PEER_EV_CLOSED */
    gz_peer_why_t why;
    int was_connected;        /* a CONNECTED event was given for this connection */
    int sys_errno;
    gz_noise_err_t noise_err;
    /* GZ_PEER_EV_WARNING, and CLOSED for PROTOCOL, PEER_ERROR and INIT: printable ASCII */
    char text[160];
} gz_peer_event_t;

typedef struct gz_peers gz_peers_t;

typedef enum {
    GZ_PEERS_OK = 0,
    GZ_PEERS_ERR_ARGS,      /* missing configuration, or a bad argument */
    GZ_PEERS_ERR_NO_CONN,   /* no such connection (closed, or never existed) */
    GZ_PEERS_ERR_NOT_READY, /* no CONNECTED event yet: the peer's init has not come */
    GZ_PEERS_ERR_TOO_BIG,   /* over 1 MiB, or over 65,495 bytes from a member (members send no parts) */
    GZ_PEERS_ERR_FULL,      /* the connection's send queue would exceed max_queue */
    GZ_PEERS_ERR_LIMIT,     /* max_conns connections are open */
    GZ_PEERS_ERR_SOCKET,    /* the system refused (listen, socket) */
    GZ_PEERS_ERR_ADDRESS,   /* the address is not numeric */
    GZ_PEERS_ERR_MEMORY
} gz_peers_err_t;

gz_peers_t *gz_peers_new(const gz_peers_config_t *config);
/* Closes every connection without events and frees everything. */
void gz_peers_free(gz_peers_t *p);

/* Listen on a numeric host and port (0 picks one). At most 4 listeners. */
gz_peers_err_t gz_peers_listen(gz_peers_t *p, const char *host, uint16_t port, uint16_t *bound_port);

/* Start a connection to a host whose key is `pin`, with our static key
 * `static_key` (NULL: the configured one). The key is copied into the
 * connection's state and wiped with it; wiping the caller's copy is the
 * caller's job. Returns at once; the outcome is a
 * CONNECTED or CLOSED event for *conn. */
gz_peers_err_t gz_peers_connect(gz_peers_t *p, const char *host, uint16_t port, const uint8_t pin[33],
                                const uint8_t static_key[32], uint64_t *conn);

/* Send a factory message. Records over 65,495 bytes are split into parts
 * (section 5), all queued at once, so one transfer completes before the next
 * begins; only the host splits. */
gz_peers_err_t gz_peers_send(gz_peers_t *p, uint64_t conn, uint16_t kind, const uint8_t scope[32],
                             const uint8_t *records, size_t records_len);

/* Send any Lightning message (type included), for tools and tests. */
gz_peers_err_t gz_peers_send_raw(gz_peers_t *p, uint64_t conn, const uint8_t *msg, size_t len);

/* Refuse: send a warning with `reason` (short ASCII), stop reading, and
 * close once it is sent (or send_ms has passed). A CLOSED event with
 * GZ_PEER_WHY_LOCAL follows. For refusals decided above the envelope. */
gz_peers_err_t gz_peers_refuse(gz_peers_t *p, uint64_t conn, const char *reason);

/* Close at once, dropping anything unsent. No event follows, and events
 * already queued for the connection are dropped. */
gz_peers_err_t gz_peers_close(gz_peers_t *p, uint64_t conn);

/* Mark an accepted connection as holding a seat (the lobby engine does this
 * at join and clears it at leave). When max_conns connections are
 * established, a newcomer evicts the oldest accepted connection without a
 * seat; seated ones are never evicted. */
gz_peers_err_t gz_peers_set_seated(gz_peers_t *p, uint64_t conn, int seated);

/* Wait up to timeout_ms (0: do not wait; negative: without limit) for the
 * next event. 1 if *ev holds one, 0 if the time passed without one. Pings,
 * pongs, parts and timeouts are handled inside. */
int gz_peers_poll(gz_peers_t *p, int timeout_ms, gz_peer_event_t *ev);

/* Counters, for tests and status lines. */
typedef struct {
    uint64_t pings_sent, pongs_received, pings_received, pongs_sent;
    uint64_t evicted_handshakes; /* handshakes evicted when the handshake budget was full */
    uint64_t evicted_unseated;   /* established connections without a seat evicted for a newcomer */
    uint64_t refused_full;       /* newcomers refused: every slot held by a seated member */
    uint64_t refused_address;    /* accepts closed at once: max_per_address reached */
    uint64_t warnings_dropped;   /* warnings received past max_warning_events */
    unsigned open;
    size_t reassembly_bytes;     /* held by incomplete transfers now */
} gz_peers_stats_t;
void gz_peers_stats(const gz_peers_t *p, gz_peers_stats_t *s);
/* For tests: 1 if the buffer that holds each decrypted message is all
 * zero, as it must be between messages. */
int gz_peers_test_plain_clear(const gz_peers_t *p);

const char *gz_peer_why_name(gz_peer_why_t w);
const char *gz_peers_err_name(gz_peers_err_t e);

#endif
