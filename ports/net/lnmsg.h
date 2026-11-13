/* BOLT 1's setup and control messages: init, warning, error, ping, pong.
 *
 * No input or output and no allocation. Every reader checks the length it is
 * given; a known message that is too short is malformed (BOLT 1). See
 * spec/transport.md, "Lobby connections". */
#ifndef GAZPACHO_NET_LNMSG_H
#define GAZPACHO_NET_LNMSG_H

#include <stddef.h>
#include <stdint.h>

#define GZ_LN_WARNING 1
#define GZ_LN_INIT 16
#define GZ_LN_ERROR 17
#define GZ_LN_PING 18
#define GZ_LN_PONG 19

/* A ping asking for this many pong bytes or more is ignored (BOLT 1). */
#define GZ_LN_PONG_IGNORE_FROM 65532

/* Signet's chain hash: its genesis block hash in internal byte order. */
extern const uint8_t GZ_LN_CHAIN_SIGNET[32];
extern const uint8_t GZ_LN_CHAIN_TESTNET4[32];
/* The main network's chain hash: never used, refused by gz_peers_new
 * (SLICES.md rule 3). */
extern const uint8_t GZ_LN_CHAIN_MAINNET[32];

typedef enum {
    GZ_LN_OK = 0,
    GZ_LN_MALFORMED,        /* too short, a length past the end, a bad TLV stream */
    GZ_LN_REQUIRED_FEATURE, /* init: an even feature bit this program does not know */
    GZ_LN_NETWORK           /* init: networks missing, or not exactly our chain */
} gz_ln_err_t;

/* init with no feature bits set (a build without discovery sets none,
 * messages.md section 2) and networks = [chain]. */
int gz_ln_init_write(const uint8_t chain[32], uint8_t *out, size_t out_cap, size_t *out_len);
/* A received init (type included): features must hold no even bit (this
 * program knows no feature), and networks must be exactly [chain]. */
gz_ln_err_t gz_ln_init_check(const uint8_t *msg, size_t len, const uint8_t chain[32]);

/* ping and pong. The ignored bytes are written as zeros. */
int gz_ln_ping_write(uint16_t num_pong_bytes, uint16_t byteslen, uint8_t *out, size_t out_cap, size_t *out_len);
gz_ln_err_t gz_ln_ping_read(const uint8_t *msg, size_t len, uint16_t *num_pong_bytes);
int gz_ln_pong_write(uint16_t byteslen, uint8_t *out, size_t out_cap, size_t *out_len);
gz_ln_err_t gz_ln_pong_read(const uint8_t *msg, size_t len, uint16_t *byteslen);

/* warning (type 1) or error (type 17) with an all-zero channel_id and an
 * ASCII text. */
int gz_ln_alert_write(uint16_t type, const char *text, uint8_t *out, size_t out_cap, size_t *out_len);
/* Reads a warning or an error; copies its text into `text` (cap bytes,
 * NUL-terminated), replacing every byte outside printable ASCII with '?'. */
gz_ln_err_t gz_ln_alert_read(const uint8_t *msg, size_t len, char *text, size_t cap);

#endif
