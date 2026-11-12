/* A small POSIX TCP connection driving the BOLT 8 state machine.
 *
 * The host listens and is the responder; the member connects, is the
 * initiator, and gives the host's key as a pin. Sockets are non-blocking,
 * close-on-exec, never raise SIGPIPE, and every wait has a deadline.
 * Addresses must be numeric: no name lookup is done. See spec/transport.md.
 *
 * Slice 1 limit: accept and handshake are one blocking call, so one slow or
 * silent peer holds the host for up to handshake_ms (spec, "Limits"). */
#ifndef GAZPACHO_NET_CONN_H
#define GAZPACHO_NET_CONN_H

#include <stddef.h>
#include <stdint.h>
#include "noise.h"

typedef enum {
    GZ_CONN_OK = 0,
    GZ_CONN_ERR_SOCKET,     /* the system refused (bind, connect, read, write) */
    GZ_CONN_ERR_TIMEOUT,    /* a deadline passed */
    GZ_CONN_ERR_CLOSED,     /* the peer closed the connection, or it is not open */
    GZ_CONN_ERR_HANDSHAKE,  /* the state machine refused an act; see noise_err */
    GZ_CONN_ERR_PIN,        /* the host's key is not the pinned one (a guard; see gz_conn_connect) */
    GZ_CONN_ERR_TOO_BIG,    /* a message over the size cap, either way */
    GZ_CONN_ERR_CRYPTO,     /* the state machine refused a message; see noise_err */
    GZ_CONN_ERR_NOT_MEMBER, /* the host's member check refused the member's key */
    GZ_CONN_ERR_BUSY,       /* accept or connect on a gz_conn_t that is still open */
    GZ_CONN_ERR_ARGS,       /* no member check given to accept */
    GZ_CONN_ERR_ADDRESS     /* the address is not numeric (names are not looked up) */
} gz_conn_err_t;

typedef struct {
    int accept_ms;    /* wait for a connection; 0 or less waits without limit (default 0) */
    int handshake_ms; /* whole handshake, from the connection (default 10,000) */
    int recv_ms;      /* one whole message, header and body, from its first byte awaited (default 30,000) */
    int send_ms;      /* one whole write (default 10,000) */
    size_t max_msg;   /* largest message accepted (default 65,535; more changes nothing) */
} gz_conn_limits_t;

/* A gz_conn_t must start zeroed (static, or memset) and is reusable after
 * gz_conn_close or any error. Accept or connect on an open one is refused
 * with GZ_CONN_ERR_BUSY and leaves it as it was. */
typedef struct {
    int fd;
    uint32_t live;
    gz_noise_t noise;
    gz_conn_limits_t limits;
    gz_noise_err_t noise_err; /* the state machine's reason, after a refusal */
    uint8_t buf[GZ_NOISE_HDR_LEN + GZ_NOISE_MAX_MSG + GZ_NOISE_MAC_LEN];
} gz_conn_t;

/* The host's check of a member's static key, called once the handshake is
 * complete and before any message is read. 1 accepts, 0 refuses. */
typedef int (*gz_conn_member_fn)(const uint8_t key[33], void *ctx);

/* Accepts every key: slice 1's host, which learns members' keys as they
 * join (spec, rule 13). */
int gz_conn_any_member(const uint8_t key[33], void *ctx);

void gz_conn_default_limits(gz_conn_limits_t *l);

/* Listen on a numeric host:port (port 0 picks one; *bound_port gets it). */
gz_conn_err_t gz_conn_listen(const char *host, uint16_t port, int *listen_fd, uint16_t *bound_port);

/* Host side: wait up to limits.accept_ms for one connection, complete the
 * handshake as responder within limits.handshake_ms, then ask is_member
 * (required). The member's key is then in remote_static. */
gz_conn_err_t gz_conn_accept(gz_conn_t *c, int listen_fd, const secp256k1_context *secp,
                             const uint8_t ls_priv[32], gz_random_port_t random,
                             const gz_conn_limits_t *limits, gz_conn_member_fn is_member, void *member_ctx);

/* Member side: connect to a numeric host:port and complete the handshake as
 * initiator against the pinned host key. The handshake fails unless the host
 * holds that key. */
gz_conn_err_t gz_conn_connect(gz_conn_t *c, const char *host, uint16_t port,
                              const secp256k1_context *secp, const uint8_t ls_priv[32],
                              const uint8_t pinned_host[33], gz_random_port_t random,
                              const gz_conn_limits_t *limits);

gz_conn_err_t gz_conn_remote_static(const gz_conn_t *c, uint8_t out[33]);

/* Send one message (type included), at most limits.max_msg bytes. */
gz_conn_err_t gz_conn_send(gz_conn_t *c, const uint8_t *msg, size_t len);

/* Receive one message into out (out_cap at least limits.max_msg is enough). */
gz_conn_err_t gz_conn_recv(gz_conn_t *c, uint8_t *out, size_t out_cap, size_t *len);

/* Close the socket and wipe the keys. Safe to call more than once. Any error
 * from the functions above (other than BUSY and ARGS) leaves the connection
 * closed in the same way. */
void gz_conn_close(gz_conn_t *c);

const char *gz_conn_err_name(gz_conn_err_t e);

#endif
