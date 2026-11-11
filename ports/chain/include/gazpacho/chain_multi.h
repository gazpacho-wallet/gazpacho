/*
 * The comparing backend: a gz_chain that wraps several gz_chain backends,
 * asks all of them every question, and answers only when they agree.
 *
 * Agreement rules (the full reasoning is in docs/notes/chain-port.md)
 * -------------------------------------------------------------------
 * A server's reply is "usable" when it is GZ_CHAIN_OK or GZ_CHAIN_NOT_FOUND
 * (a clear "no" is an answer). Any other result (unreachable, malformed, too
 * large, bad proof) counts as no reply from that server.
 *
 *  - Fewer usable replies than the quorum (default and minimum 2):
 *    GZ_CHAIN_NO_QUORUM. With two servers, one unreachable means no answer.
 *  - Usable replies that are not all equal: GZ_CHAIN_DISAGREE, even if a
 *    majority agrees. One dissenting server is enough to withhold the answer.
 *  - Otherwise the common answer is returned.
 * When there is no quorum because every server failed in the same way (all
 * unreachable, all too large), that failure code is returned instead of
 * GZ_CHAIN_NO_QUORUM so the caller can tell why.
 *
 * "Equal" per call:
 *  - tip: the reported tips may differ in height by at most tip_slack
 *    (default 1) because a block reaches servers at slightly different
 *    times. The answer is the lowest reported tip, and every server that
 *    reported a higher tip is asked for its block hash at that lower height,
 *    which must match exactly. Same height with different hashes disagrees.
 *  - block_hash, block_header, merkle_proof, outspend: every field identical.
 *  - tx_status: same state; if confirmed, same height and same block hash.
 *    The confirmation count returned is the lowest any server reported.
 *  - script_outputs: the same set of outputs with identical fields,
 *    including mempool entries.
 *  - raw_tx: every byte identical. Each server's bytes must already hash to
 *    the txid, but the txid does not cover witness data, so the full
 *    serializations are compared as well.
 *  - broadcast: sent to every server; GZ_CHAIN_OK if at least one accepts.
 *    Every server's result is in the report.
 *  - fee_estimates: estimates are opinions and never match exactly. At least
 *    a quorum must answer; for each target every answering server lists, the
 *    highest rate is returned. An answer with any rate above
 *    fee_ceiling_sat_per_kvb is discarded as malformed. Never DISAGREE.
 */
#ifndef GAZPACHO_CHAIN_MULTI_H
#define GAZPACHO_CHAIN_MULTI_H

#include "gazpacho/chain.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GZ_MULTI_MAX_SERVERS 8

typedef struct gz_multi_config {
  /* Usable replies needed before anything is returned. At least 2. */
  uint32_t quorum;
  /* Largest tip height difference still treated as the same chain. */
  uint32_t tip_slack;
  /* Most outputs kept per server for script_outputs. */
  size_t max_outputs;
  /* Fee rates above this are treated as a malformed answer. */
  uint64_t fee_ceiling_sat_per_kvb;
} gz_multi_config;

/* quorum 2, tip_slack 1, max_outputs 256, ceiling 2,000,000 sat/kvB. */
void gz_multi_config_default(gz_multi_config *cfg);

typedef enum gz_chain_call {
  GZ_CALL_NONE = 0,
  GZ_CALL_TIP,
  GZ_CALL_BLOCK_HASH,
  GZ_CALL_BLOCK_HEADER,
  GZ_CALL_TX_STATUS,
  GZ_CALL_SCRIPT_OUTPUTS,
  GZ_CALL_OUTSPEND,
  GZ_CALL_RAW_TX,
  GZ_CALL_MERKLE_PROOF,
  GZ_CALL_BROADCAST,
  GZ_CALL_FEE_ESTIMATES
} gz_chain_call;

/* One server's reply to the last call. The union member matching the call is
 * valid when result is GZ_CHAIN_OK (broadcast: always). */
typedef struct gz_multi_answer {
  gz_chain_result result;
  union {
    gz_chain_tip tip;
    uint8_t block_hash[GZ_HASH_LEN];
    uint8_t header[GZ_HEADER_LEN];
    gz_tx_status tx_status;
    struct {
      /* Points into memory owned by the comparing backend; valid until the
       * next call on it or its destruction. */
      const gz_chain_output *items;
      size_t count;
    } outputs;
    gz_outspend outspend;
    struct {
      size_t len;
      uint8_t digest[GZ_HASH_LEN]; /* SHA-256 twice over every byte returned */
    } raw_tx;
    gz_merkle_proof proof;
    gz_broadcast_result broadcast;
    gz_fee_estimates fees;
  } u;
} gz_multi_answer;

typedef struct gz_multi_report {
  gz_chain_call call;
  gz_chain_result verdict; /* what the call returned */
  size_t server_count;
  gz_multi_answer answers[GZ_MULTI_MAX_SERVERS]; /* in the order given at creation */
} gz_multi_report;

/*
 * Creates the comparing backend over servers[0..count). The gz_chain handles
 * are copied; the backends themselves are borrowed and must outlive it (it
 * does not destroy them). count may be 1 to GZ_MULTI_MAX_SERVERS; with fewer
 * servers than the quorum every call returns GZ_CHAIN_NO_QUORUM, and the
 * report still shows what the server said. Use servers run by different
 * operators: two addresses of one operator compare nothing.
 */
gz_chain_result gz_multi_create(const gz_multi_config *cfg, const gz_chain *servers, size_t count,
                                gz_chain *out);

/* Every server's reply to the most recent call on `multi`, owned by the
 * backend and overwritten by the next call. NULL if `multi` is not a
 * comparing backend. */
const gz_multi_report *gz_multi_last_report(const gz_chain *multi);

#ifdef __cplusplus
}
#endif

#endif /* GAZPACHO_CHAIN_MULTI_H */
