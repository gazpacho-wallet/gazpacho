/* Basic types shared by every part of the Gazpacho core. */
#ifndef GAZPACHO_TYPES_H
#define GAZPACHO_TYPES_H

#include <stddef.h>
#include <stdint.h>

/* Result of a core call. Anything other than GZ_OK leaves its target unchanged. */
typedef enum {
    GZ_OK = 0,
    GZ_ERR_ARGUMENT,        /* a required argument is missing or malformed */
    GZ_ERR_NO_SPACE,        /* the caller-provided storage is full */
    GZ_ERR_REFUSED,         /* the runner could not accept a list: fatal for the node (runner.h) */
    GZ_ERR_FAILED,          /* the runner has failed and releases nothing further (runner.h) */
    GZ_ERR_REENTRANT,       /* the runner was called from inside its own executor callback */
    GZ_ERR_STALE_BATCH,     /* a confirmation for a batch issued before the last restart: ignored */
    GZ_ERR_UNKNOWN_BATCH,   /* a confirmation for a batch never issued, or already confirmed */
    GZ_ERR_OUT_OF_ORDER,    /* a confirmation that skips an earlier unconfirmed batch */
    GZ_ERR_CORRUPT,         /* storage does not hold the journal the contract describes */
    GZ_WAITING,             /* not an error: nothing can be done until one of the node's
                               batches is confirmed; nothing was appended (node.h) */
    GZ_ERR_BUG              /* the composite node caught one of its engines breaking a rule
                               it checks (a timer id too large, a broadcast from the wrong
                               engine, a bracket or re-entry check in a test build): a bug,
                               fatal for the node (node.h) */
} gz_status_t;

/* Identifier of one save batch. Issued by the runner, never by a node, and
 * never reused: `incarnation` is the number the surrounding program gave the
 * runner when it started (strictly greater at every start, see runner.h) and
 * `sequence` counts that runner's batches from 1. */
typedef struct {
    uint64_t incarnation;
    uint64_t sequence;
} gz_batch_id_t;

/* A read-only byte string. The core never frees `data`; who owns it is stated
 * wherever a gz_bytes_t appears. `data` may be NULL only when `len` is 0. */
typedef struct {
    const uint8_t *data;
    size_t len;
} gz_bytes_t;

/* A node id: a 33-byte compressed secp256k1 public key, the BOLT 8 static
 * key (BOLT 1's node_id). */
#define GZ_NODE_ID_LEN 33
typedef struct { uint8_t key[GZ_NODE_ID_LEN]; } gz_node_id_t;

/* A link: one connection's two static keys, the only name the core has for a
 * peer (contract-v2.md section 2). `local` is our key on it (the host's
 * long-term key on the host side; a per-lobby key on a member's side,
 * messages.md section 2); `remote` is the key the handshake proved. Both are
 * derived from seeds, so a link is the same after either side restarts. At
 * most one connection per link is live. An engine never keeps a link on its
 * own: it derives it from keys it holds (composite-node.md section 3). */
typedef struct { gz_node_id_t local; gz_node_id_t remote; } gz_link_t;

/* A transaction output: the transaction's identifier, in the byte order the
 * chain hashes it (not reversed for display), and the output's index. */
typedef struct {
    uint8_t txid[32];
    uint32_t vout;
} gz_outpoint_t;

#endif
