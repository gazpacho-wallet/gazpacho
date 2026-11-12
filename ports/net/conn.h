/* A small POSIX TCP connection driving the BOLT 8 state machine.
 *
 * The host listens and is the responder; the member connects, is the
 * initiator, and gives the host's key as a pin. Sockets are non-blocking and
 * every wait has a deadline. See spec/transport.md. */
#ifndef GAZPACHO_NET_CONN_H
#define GAZPACHO_NET_CONN_H

#include <stddef.h>
#include <stdint.h>
#include "noise.h"

typedef enum {
    GZ_CONN_OK = 0,
    GZ_CONN_ERR_SOCKET,    /* the system refused (bind, connect, read, write) */
    GZ_CONN_ERR_TIMEOUT,   /* a deadline passed */
    GZ_CONN_ERR_CLOSED,    /* the peer closed the connection */
    GZ_CONN_ERR_HANDSHAKE, /* the state machine refused an act; see noise_err */
    GZ_CONN_ERR_PIN,       /* the host's key is not the pinned one */
    GZ_CONN_ERR_TOO_BIG,   /* a message over the size cap, either way */
    GZ_CONN_ERR_CRYPTO     /* the state machine refused a message; see noise_err */
} gz_conn_err_t;

typedef struct {
    int handshake_ms; /* whole handshake (default 10,000) */
    int recv_ms;      /* one whole message, from its first byte awaited (default 30,000) */
    int send_ms;      /* one whole write (default 10,000) */
    size_t max_msg;   /* largest message accepted, at most 65,535 (default 65,535) */
} gz_conn_limits_t;

typedef struct {
    int fd;
    gz_noise_t noise;
    gz_conn_limits_t limits;
    gz_noise_err_t noise_err; /* the state machine's reason, after a refusal */
    uint8_t buf[GZ_NOISE_HDR_LEN + GZ_NOISE_MAX_MSG + GZ_NOISE_MAC_LEN];
} gz_conn_t;

void gz_conn_default_limits(gz_conn_limits_t *l);

/* Listen on host:port (port 0 picks one; *bound_port gets it). */
gz_conn_err_t gz_conn_listen(const char *host, uint16_t port, int *listen_fd, uint16_t *bound_port);

/* Host side: wait up to limits.handshake_ms for one connection and complete
 * the handshake as responder. The member's key is then in remote_static. */
gz_conn_err_t gz_conn_accept(gz_conn_t *c, int listen_fd, const secp256k1_context *secp,
                             const uint8_t ls_priv[32], gz_random_port_t random,
                             const gz_conn_limits_t *limits);

/* Member side: connect to host:port and complete the handshake as initiator
 * against the pinned host key. Refused unless the host holds that key. */
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
 * from the functions above leaves the connection closed in the same way. */
void gz_conn_close(gz_conn_t *c);

const char *gz_conn_err_name(gz_conn_err_t e);

#endif
