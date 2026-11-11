/*
 * Gazpacho chain view: the backend-neutral interface.
 *
 * The chain view is a port. The core never calls it. The program around the
 * core turns the core's "watch this script" and "broadcast this transaction"
 * actions into calls on a gz_chain and feeds the results back as events.
 *
 * A gz_chain is a struct of function pointers plus an opaque context. Two
 * implementations exist: the Esplora HTTP backend (chain_esplora.h), which
 * talks to one chain server, and the comparing backend (chain_multi.h), which
 * wraps several and answers only when they agree.
 *
 * Conventions used by every function in this file
 * -----------------------------------------------
 * Byte order. Every 32-byte hash (txid, block hash, Merkle node) is held in
 *   the order the hash function produced it ("internal" order), which is the
 *   order used inside transactions and block headers. The hex strings people
 *   read, and the ones chain servers use, are the reverse. gz_hash_to_hex and
 *   gz_hash_from_hex convert.
 * Ownership. The caller owns every output buffer and struct. Nothing returned
 *   points into the backend. No function allocates memory the caller must
 *   free. Output is only meaningful when the function returns GZ_CHAIN_OK
 *   (gz_chain_broadcast also fills its result struct on failure).
 * Lifetimes. A gz_chain value is a handle that may be copied. The backend
 *   lives until gz_chain_destroy is called once on any copy.
 * Threads. A backend keeps per-instance state (rate limiting, a response
 *   buffer). Use one instance from one thread at a time. There is no global
 *   mutable state.
 * Blocking. Every call may block on the network, bounded by the backend's
 *   timeouts and retry limits.
 * Trust. Everything a chain server returns is treated as hostile input. A
 *   backend returns GZ_CHAIN_OK only after strict validation, but a single
 *   server can still lie by omission or invention. See docs/notes/chain-port.md.
 */
#ifndef GAZPACHO_CHAIN_H
#define GAZPACHO_CHAIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GZ_HASH_LEN 32
#define GZ_HEADER_LEN 80
/* Longest Merkle branch accepted. A block of 4 million weight units cannot
 * hold more than about 2^16 transactions; 32 leaves a wide margin and keeps
 * the position inside 32 bits. */
#define GZ_MERKLE_MAX_DEPTH 32
/* Longest server reason text kept, including the terminating zero. */
#define GZ_REASON_MAX 256
/* Most fee targets kept from one answer. */
#define GZ_FEE_MAX_TARGETS 64
/* Longest scriptPubKey accepted (the consensus script size limit). */
#define GZ_SCRIPT_MAX_LEN 10000
/* Largest amount in satoshi: 21 million bitcoin. */
#define GZ_MAX_MONEY UINT64_C(2100000000000000)
/* Largest block height accepted from a server. */
#define GZ_MAX_HEIGHT UINT32_C(0x7fffffff)

/* Result of every call. The first group are answers; the second group mean
 * no trustworthy answer was obtained. */
typedef enum gz_chain_result {
  GZ_CHAIN_OK = 0,
  /* The server answered and says it does not have this (no block at that
   * height, no such transaction). A "no" from a server, not a failure. */
  GZ_CHAIN_NOT_FOUND = 1,
  /* The server answered and refused the request (a broadcast it rejects, or
   * any other 4xx). The reason text is kept where the call has room for it. */
  GZ_CHAIN_REJECTED = 2,

  /* Could not reach the server: no connection, timeout, or the server kept
   * answering "busy" (429 or 5xx) after the bounded retries. */
  GZ_CHAIN_UNREACHABLE = 10,
  /* The server answered but the answer was not exactly what the interface
   * defines, or was inconsistent with itself. */
  GZ_CHAIN_MALFORMED = 11,
  /* The answer was larger than the size cap or than the caller's buffer. */
  GZ_CHAIN_TOO_LARGE = 12,
  /* The answer was well formed but failed a check against data it must
   * match: a Merkle proof that does not reach the header's root, a header
   * that does not hash to the stated block, proof of work that fails. */
  GZ_CHAIN_BAD_PROOF = 13,

  /* Comparing backend only: servers gave different answers. Treat as not
   * confirmed. gz_multi_last_report holds each server's answer. */
  GZ_CHAIN_DISAGREE = 20,
  /* Comparing backend only: fewer servers gave a usable answer than the
   * quorum requires, so nothing could be compared. Treat as not confirmed. */
  GZ_CHAIN_NO_QUORUM = 21,

  /* The caller passed something invalid. Nothing was sent. */
  GZ_CHAIN_INVALID_ARG = 30,
  /* Out of memory inside the backend. */
  GZ_CHAIN_NO_MEMORY = 31
} gz_chain_result;

/* Short fixed name of a result code, for logs. Never NULL. */
const char *gz_chain_result_name(gz_chain_result r);

typedef enum gz_network {
  GZ_NET_MAINNET = 0,
  GZ_NET_TESTNET3 = 1,
  GZ_NET_TESTNET4 = 2,
  GZ_NET_SIGNET = 3
} gz_network;

/* "mainnet", "testnet", "testnet4", "signet". Never NULL. */
const char *gz_network_name(gz_network n);
/* Parses the names above. Returns false if the name is not one of them. */
bool gz_network_from_name(const char *name, gz_network *out);

/* ---- answers ---------------------------------------------------------- */

typedef struct gz_chain_tip {
  uint32_t height;
  uint8_t hash[GZ_HASH_LEN];
} gz_chain_tip;

typedef enum gz_tx_state {
  GZ_TX_UNKNOWN = 0,  /* the server has no such transaction */
  GZ_TX_MEMPOOL = 1,  /* the server has it, unconfirmed */
  GZ_TX_CONFIRMED = 2 /* in block `block_hash` at height `height` */
} gz_tx_state;

typedef struct gz_tx_status {
  gz_tx_state state;
  /* The fields below are zero unless state is GZ_TX_CONFIRMED. */
  uint32_t height;
  uint8_t block_hash[GZ_HASH_LEN];
  /* tip_height - height + 1, from the tip the same server reported. */
  uint32_t confirmations;
  uint32_t tip_height;
} gz_tx_status;

/* One unspent output paying a script. */
typedef struct gz_chain_output {
  uint8_t txid[GZ_HASH_LEN];
  uint32_t vout;
  uint64_t value; /* satoshi */
  bool confirmed; /* false: in the mempool; height and block_hash are zero */
  uint32_t height;
  uint8_t block_hash[GZ_HASH_LEN];
} gz_chain_output;

typedef struct gz_outspend {
  bool spent;
  /* The fields below are zero unless spent is true. */
  uint8_t spender_txid[GZ_HASH_LEN];
  uint32_t spender_vin; /* index of the spending input */
  bool confirmed;       /* false: the spending transaction is in the mempool */
  uint32_t height;
  uint8_t block_hash[GZ_HASH_LEN];
} gz_outspend;

typedef struct gz_merkle_proof {
  uint32_t block_height;
  uint32_t pos;   /* index of the transaction in the block */
  uint32_t depth; /* number of entries used in `nodes` */
  uint8_t nodes[GZ_MERKLE_MAX_DEPTH][GZ_HASH_LEN];
} gz_merkle_proof;

typedef struct gz_broadcast_result {
  gz_chain_result result;
  /* Valid when result is GZ_CHAIN_OK. Always equals the txid computed from
   * the bytes that were sent. */
  uint8_t txid[GZ_HASH_LEN];
  /* HTTP status of the last answer, or 0 if the server was not reached. */
  long server_status;
  /* The server's own words when it refused, zero-terminated, printable ASCII
   * only (other bytes replaced by '?'), cut at GZ_REASON_MAX - 1. */
  char reason[GZ_REASON_MAX];
} gz_broadcast_result;

typedef struct gz_fee_estimate {
  uint16_t target;      /* confirmation target in blocks */
  uint64_t sat_per_kvb; /* fee rate, satoshi per 1000 virtual bytes, rounded up */
} gz_fee_estimate;

typedef struct gz_fee_estimates {
  size_t count; /* entries used, sorted by target ascending, no duplicates */
  gz_fee_estimate entries[GZ_FEE_MAX_TARGETS];
} gz_fee_estimates;

/* ---- the interface ---------------------------------------------------- */

typedef struct gz_chain_ops {
  gz_chain_result (*tip)(void *ctx, gz_chain_tip *out);
  gz_chain_result (*block_hash)(void *ctx, uint32_t height, uint8_t out[GZ_HASH_LEN]);
  gz_chain_result (*block_header)(void *ctx, uint32_t height, uint8_t out[GZ_HEADER_LEN]);
  gz_chain_result (*tx_status)(void *ctx, const uint8_t txid[GZ_HASH_LEN], gz_tx_status *out);
  gz_chain_result (*script_outputs)(void *ctx, const uint8_t *script, size_t script_len,
                                    gz_chain_output *out, size_t cap, size_t *count);
  gz_chain_result (*outspend)(void *ctx, const uint8_t txid[GZ_HASH_LEN], uint32_t vout,
                              gz_outspend *out);
  gz_chain_result (*raw_tx)(void *ctx, const uint8_t txid[GZ_HASH_LEN], uint8_t *buf, size_t cap,
                            size_t *len);
  gz_chain_result (*merkle_proof)(void *ctx, const uint8_t txid[GZ_HASH_LEN],
                                  gz_merkle_proof *out);
  gz_chain_result (*broadcast)(void *ctx, const uint8_t *raw, size_t len,
                               gz_broadcast_result *out);
  gz_chain_result (*fee_estimates)(void *ctx, gz_fee_estimates *out);
  void (*destroy)(void *ctx);
} gz_chain_ops;

typedef struct gz_chain {
  void *ctx;
  const gz_chain_ops *ops;
} gz_chain;

/*
 * The calls. Each checks its arguments (GZ_CHAIN_INVALID_ARG) and forwards to
 * the backend. `c` and every out pointer must be non-NULL.
 */

/* Height and hash of the best block the server knows. */
gz_chain_result gz_chain_tip_get(const gz_chain *c, gz_chain_tip *out);

/* Hash of the block at `height`. GZ_CHAIN_NOT_FOUND if there is none. */
gz_chain_result gz_chain_block_hash(const gz_chain *c, uint32_t height, uint8_t out[GZ_HASH_LEN]);

/* The 80-byte header of the block at `height`. A backend returns OK only if
 * the header hashes to the block hash the server gave for that height.
 * GZ_CHAIN_NOT_FOUND if there is no block at that height. */
gz_chain_result gz_chain_block_header(const gz_chain *c, uint32_t height,
                                      uint8_t out[GZ_HEADER_LEN]);

/* Whether the server knows the transaction and where it confirmed. An unknown
 * transaction is GZ_CHAIN_OK with state GZ_TX_UNKNOWN. This is the server's
 * claim; gz_chain_confirm_tx checks it against a header and a Merkle proof. */
gz_chain_result gz_chain_tx_status(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN],
                                   gz_tx_status *out);

/* The unspent outputs paying `script` (a scriptPubKey), confirmed and in the
 * mempool, written to out[0..*count), sorted by (txid, vout). `cap` is the
 * room in `out`; if the server reports more, the result is GZ_CHAIN_TOO_LARGE
 * and nothing is returned. An output that has been spent is not listed: ask
 * gz_chain_outspend about an outpoint you already know. */
gz_chain_result gz_chain_script_outputs(const gz_chain *c, const uint8_t *script,
                                        size_t script_len, gz_chain_output *out, size_t cap,
                                        size_t *count);

/* Whether output `vout` of `txid` is spent, and by which input of which
 * transaction. A server answers "not spent" for an output that does not
 * exist, so ask only about outputs known to exist. */
gz_chain_result gz_chain_outspend(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN],
                                  uint32_t vout, gz_outspend *out);

/* The serialized transaction, written to buf[0..*len). OK only if the bytes
 * parse as a transaction whose txid is `txid`, so inputs, outputs and
 * locktime cannot be forged. The txid does not cover witness data: a single
 * server can alter or strip witnesses undetected (the comparing backend
 * compares every byte). GZ_CHAIN_TOO_LARGE if it does not fit in `cap`;
 * GZ_CHAIN_NOT_FOUND if the server does not have it. */
gz_chain_result gz_chain_raw_tx(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN], uint8_t *buf,
                                size_t cap, size_t *len);

/* The Merkle branch for a confirmed transaction. GZ_CHAIN_NOT_FOUND if the
 * server has no confirmed transaction with that id. The proof is not yet
 * checked: pass it to gz_merkle_verify with a header. */
gz_chain_result gz_chain_merkle_proof(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN],
                                      gz_merkle_proof *out);

/* Sends a serialized transaction. `out` is filled whatever the result and
 * out->result equals the return value. GZ_CHAIN_OK means a server accepted it
 * and returned the txid computed from `raw`. GZ_CHAIN_REJECTED carries the
 * server's reason. A transaction that does not parse is GZ_CHAIN_INVALID_ARG
 * and is not sent. */
gz_chain_result gz_chain_broadcast(const gz_chain *c, const uint8_t *raw, size_t len,
                                   gz_broadcast_result *out);

/* Fee rate estimates by confirmation target. Advisory: nothing can check
 * them. */
gz_chain_result gz_chain_fee_estimates(const gz_chain *c, gz_fee_estimates *out);

/* Frees the backend. `c` may be NULL or zeroed. Clears *c. */
void gz_chain_destroy(gz_chain *c);

/* ---- helpers that need no server -------------------------------------- */

/* Writes 64 lowercase hex characters and a terminating zero, in the reversed
 * order people and servers use. */
void gz_hash_to_hex(const uint8_t hash[GZ_HASH_LEN], char out[2 * GZ_HASH_LEN + 1]);
/* Parses exactly 64 lowercase hex characters (reversed order) into internal
 * order. `hex` need not be zero-terminated. */
bool gz_hash_from_hex(const char *hex, size_t len, uint8_t out[GZ_HASH_LEN]);
/* Strict lowercase hex decoding. Returns false on odd length, a non-hex
 * character, or more than `cap` bytes. */
bool gz_hex_decode(const char *hex, size_t len, uint8_t *out, size_t cap, size_t *out_len);

/* SHA-256 applied twice. */
void gz_sha256d(const uint8_t *data, size_t len, uint8_t out[GZ_HASH_LEN]);
/* Esplora's lookup key for a script: SHA-256 of the scriptPubKey, in the
 * order the hash function produced it (not reversed). */
void gz_script_hash(const uint8_t *script, size_t len, uint8_t out[GZ_HASH_LEN]);

/* Parses a serialized transaction (with or without witness data), requiring
 * every length to fit and no bytes left over, and writes its txid. Returns
 * false if it does not parse. */
bool gz_txid_from_raw(const uint8_t *raw, size_t len, uint8_t txid[GZ_HASH_LEN]);

/* ---- block headers (headers.c) ---------------------------------------- */

typedef struct gz_block_header {
  int32_t version;
  uint8_t prev_hash[GZ_HASH_LEN];
  uint8_t merkle_root[GZ_HASH_LEN];
  uint32_t time;
  uint32_t bits;
  uint32_t nonce;
} gz_block_header;

void gz_header_parse(const uint8_t raw[GZ_HEADER_LEN], gz_block_header *out);
void gz_header_hash(const uint8_t raw[GZ_HEADER_LEN], uint8_t out[GZ_HASH_LEN]);
/* True if `next` names `prev` as its predecessor. */
bool gz_header_links(const uint8_t prev[GZ_HEADER_LEN], const uint8_t next[GZ_HEADER_LEN]);

typedef enum gz_pow_result {
  GZ_POW_OK = 0,
  GZ_POW_BAD_BITS = 1,   /* the target field is zero, negative or overflows */
  GZ_POW_TOO_EASY = 2,   /* the target is easier than the network allows */
  GZ_POW_HASH_ABOVE = 3  /* the header's hash does not meet its own target */
} gz_pow_result;

/*
 * Checks a header's proof of work against the target the header itself
 * states, and that this target is no easier than the network's limit.
 *
 * What this does and does not establish, per network:
 *  - mainnet, testnet3, testnet4: the header cost real work at the difficulty
 *    it claims. NOT checked: that the claimed difficulty is the one the
 *    network required at that height (no retargeting rules, no chain of
 *    headers back to a known block, no total-work comparison). Testnet also
 *    allows minimum-difficulty blocks, which are cheap. A caller wanting more
 *    must fetch a run of headers and check gz_header_links along it.
 *  - signet: blocks are authorised by a signature in the coinbase and the
 *    difficulty is nominal. The check still runs (the grinding is real but
 *    trivial) and proves nothing useful. The block signature is NOT verified.
 *    On signet the only defence is comparing servers run by different
 *    operators (chain_multi.h).
 */
gz_pow_result gz_header_check_pow(const uint8_t raw[GZ_HEADER_LEN], gz_network network);

/* Expands the compact target `bits` to a 32-byte big-endian number. Returns
 * false if the encoding is zero, negative or overflows 256 bits. */
bool gz_bits_to_target(uint32_t bits, uint8_t target_be[GZ_HASH_LEN]);

/* ---- Merkle proofs (headers.c) ----------------------------------------- */

/* Folds `txid` up the branch. Returns false if the proof is not well formed
 * (depth above the limit, or pos not below 2^depth). */
bool gz_merkle_root_from_proof(const uint8_t txid[GZ_HASH_LEN], const gz_merkle_proof *proof,
                               uint8_t root[GZ_HASH_LEN]);
/* True only if the branch leads from `txid` to the Merkle root in `header`.
 * This shows the block commits to a 32-byte value at that position. It does
 * not show the value is a transaction: call it only for a txid computed from
 * transaction bytes you hold (gz_txid_from_raw), never for an id a server
 * supplied on its own. */
bool gz_merkle_verify(const uint8_t txid[GZ_HASH_LEN], const gz_merkle_proof *proof,
                      const uint8_t header[GZ_HEADER_LEN]);

/* ---- a checked confirmation (verify.c) --------------------------------- */

typedef struct gz_confirmation {
  gz_tx_status status;
  /* Filled only when status.state is GZ_TX_CONFIRMED. */
  uint8_t header[GZ_HEADER_LEN];
  gz_merkle_proof proof;
} gz_confirmation;

/*
 * Asks `c` for the status of `txid` and, if the server says it is confirmed,
 * checks the claim: fetches the header at that height, requires it to hash to
 * the block hash in the status, checks its proof of work for `network` (see
 * gz_header_check_pow for what that is worth), fetches the Merkle proof and
 * requires it to be for the same height and to lead from `txid` to that
 * header's Merkle root.
 *
 * Returns GZ_CHAIN_OK with the state in out->status (unknown and mempool are
 * passed through unchecked: there is nothing to check). Returns
 * GZ_CHAIN_BAD_PROOF if any check fails. Other codes come from the calls it
 * makes. Used on the comparing backend, every step is also a comparison.
 *
 * A server that controls the header it returns can still fabricate all three
 * pieces on signet; that is what the comparing backend is for.
 */
gz_chain_result gz_chain_confirm_tx(const gz_chain *c, gz_network network,
                                    const uint8_t txid[GZ_HASH_LEN], gz_confirmation *out);

#ifdef __cplusplus
}
#endif

#endif /* GAZPACHO_CHAIN_H */
