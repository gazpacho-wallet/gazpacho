/*
 * The comparing backend: a gz_chain that wraps several gz_chain backends,
 * asks all of them every question, and answers only when they agree.
 *
 * What it does NOT do: it does not make anything true. It reports that
 * servers run by different operators said the same thing. If they are all
 * wrong, lying together, or secretly one operator, it reports their common
 * answer. Fee estimates are never an agreed fact at all (see below).
 *
 * Who counts
 * ----------
 * - A server is used only after its block 0 has been seen to be the genesis
 *   block of the configured network. A server on another chain answers
 *   GZ_CHAIN_WRONG_NETWORK to everything and is never sent a broadcast.
 * - The same server cannot be given twice: creation refuses two handles to
 *   one backend, two backends with the same address, and two backends on the
 *   same host. Hosts are compared in the canonical form of
 *   gz_host_normalise, so "mempool.space." is "mempool.space".
 * - The quorum counts OPERATORS, not servers. Two servers of one operator
 *   (as named by gz_chain_describe) count once.
 *
 * Verdicts
 * --------
 * A server's reply is "usable" when it is GZ_CHAIN_OK or, for calls where a
 * clean "no" is meaningful, GZ_CHAIN_NOT_FOUND. Anything else (unreachable,
 * malformed, too large, wrong network) counts as no reply from that server.
 *
 *  - Usable replies from fewer operators than the quorum (default and
 *    minimum 2): GZ_CHAIN_NO_QUORUM; or, if every server failed in the same
 *    way, that failure code, so the caller can tell why.
 *  - Usable replies that contradict each other about confirmed data:
 *    GZ_CHAIN_DISAGREE, even if a majority agrees. There is no vote.
 *  - The same contradiction is GZ_CHAIN_LAG instead only when it has the
 *    shape of a server being behind, all of:
 *      . the disputed item (a block, a confirmation, a confirmed spend, a
 *        confirmed output) lies at a height ABOVE the tip of every server
 *        that lacks it, and at or below the tip of every server that has it
 *        (for an output that one server no longer lists: that server shows
 *        it spent in a block above the tip of the server that lists it);
 *      . the tips lie on one chain and differ by at most tip_slack, which is
 *        at most GZ_MULTI_LAG_MAX_BLOCKS;
 *      . lag has not been seen continuously for more than
 *        GZ_MULTI_LAG_MAX_MS (by the configured clock). The period ends when
 *        a call sees every server at the same tip.
 *    Anything at or below the lower server's tip that servers disagree
 *    about is GZ_CHAIN_DISAGREE: a server cannot turn a contradiction into
 *    lag by naming the block before the honest server's tip.
 *  - Otherwise GZ_CHAIN_OK (or GZ_CHAIN_NOT_FOUND) with the common answer.
 *
 * Unconfirmed data (mempool contents) differs between honest servers all the
 * time and anyone can put a transaction in one server's mempool. So a
 * difference that is only about unconfirmed things never blocks the answer:
 * the agreed, confirmed part is returned and a flag says the rest differs.
 *
 * Per call:
 *  - tip: the reported tips may differ in height by at most tip_slack
 *    (default 3). The answer is the lowest reported tip, and every server
 *    that reported a higher tip is asked for its block hash at that lower
 *    height, which must match exactly. Same height with different hashes
 *    disagrees. More than tip_slack apart disagrees.
 *  - block_hash, block_header, block_summary, merkle_proof: every field
 *    identical. One server having it and another not: LAG if it has the lag
 *    shape above (the block's height; for a proof, the proof's height),
 *    else DISAGREE.
 *  - tx_status: all confirmed: same height and block hash required; the
 *    claimed confirmation count returned is the lowest (still a claim).
 *    None confirmed: OK; the state is "mempool" or "unknown" if all say so,
 *    else "unknown" with unconfirmed_differs set. Some confirmed and some
 *    not: LAG if it has the lag shape, else DISAGREE.
 *  - outspend: the same pattern. A confirmed spend must be reported
 *    identically by all. No confirmed spend: OK; "not spent", or the
 *    unconfirmed spend if all report the same one, else "not spent" with
 *    unconfirmed_differs set (the report shows who claims what). A confirmed
 *    spend on some servers only: LAG or DISAGREE.
 *  - script_outputs: the confirmed outputs must be identical on all servers,
 *    else LAG or DISAGREE. The answer is those plus the unconfirmed outputs
 *    every server lists; unconfirmed_differs is set when any server's list
 *    is not exactly the answer. A list naming one outpoint twice counts as
 *    a malformed reply.
 *  - raw_tx: every byte identical. Each server's bytes must already hash to
 *    the txid, but the txid does not cover witness data, so the full
 *    serializations are compared as well. A transaction one server has and
 *    another lacks is DISAGREE (it has no height to judge lag by).
 *  - broadcast: sent to every server on the right network; GZ_CHAIN_OK if at
 *    least one accepts (or already has it). Every server's result is in the
 *    report. Accepted is not the same as relayed: follow up with tx_status.
 *  - fee_estimates: opinions, not facts. At least a quorum of operators must
 *    answer the call. The result has an entry for each target any of them
 *    lists. A server ANSWERS FOR a target T with its estimate for the
 *    highest target it lists that is not above T (T itself or a faster
 *    target, so never a lower rate than T needs); a server that lists
 *    nothing at or below T does not answer for T. For each T, only the
 *    servers answering for T count: fewer than a quorum of operators and T
 *    is left out; otherwise the entry is the LOWEST rate they give, cut at
 *    fee_ceiling_sat_per_kvb, so no single server can raise what the user
 *    pays. If for any T the highest of those rates is more than
 *    fee_disagree_factor times the lowest plus
 *    fee_disagree_slack_sat_per_kvb, the call returns GZ_CHAIN_DISAGREE.
 *    So a single server can lower a target's rate only to about
 *    1/fee_disagree_factor of what the others give FOR THAT TARGET, less
 *    the slack: leaving targets out removes it from the targets it left
 *    out, it does not let its other estimates stand in for them. At most
 *    GZ_FEE_MAX_TARGETS targets are kept (the lowest). On test networks
 *    gz_chain_choose_fee_rate ignores estimates altogether.
 */
#ifndef GAZPACHO_CHAIN_MULTI_H
#define GAZPACHO_CHAIN_MULTI_H

#include "gazpacho/chain.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GZ_MULTI_MAX_SERVERS 8

/* The limits on lag (see "Verdicts" above). A difference counts as lag only
 * while the servers' tips are at most GZ_MULTI_LAG_MAX_BLOCKS apart, and
 * only until lag has been seen continuously for GZ_MULTI_LAG_MAX_MS,
 * whichever limit is reached first; beyond either it is GZ_CHAIN_DISAGREE. */
#define GZ_MULTI_LAG_MAX_BLOCKS 3u
#define GZ_MULTI_LAG_MAX_MS (30u * 60u * 1000u)

typedef struct gz_multi_config {
  /* The network every server must be on. Required. */
  gz_network network;
  /* Independent operators that must give a usable reply. At least 2. */
  uint32_t quorum;
  /* Largest tip height difference still treated as one chain (for the tip
   * and for lag). 0..GZ_MULTI_LAG_MAX_BLOCKS; default the maximum. */
  uint32_t tip_slack;
  /* The clock lag is timed by: milliseconds, never going backwards (the
   * transport's now_ms fits). Required. */
  uint64_t (*now_ms)(void *clock_ctx);
  void *clock_ctx;
  /* Most outputs kept per server for script_outputs. 1..4096. */
  size_t max_outputs;
  /* Combined fee estimates are cut at this rate. Supplied by the caller;
   * 1..GZ_FEE_MAX_SAT_PER_KVB. */
  uint64_t fee_ceiling_sat_per_kvb;
  /* See fee_estimates above. Factor 1..100. */
  uint32_t fee_disagree_factor;
  uint64_t fee_disagree_slack_sat_per_kvb;
} gz_multi_config;

/* quorum 2, tip_slack GZ_MULTI_LAG_MAX_BLOCKS, max_outputs 256, fee ceiling
 * 200,000 sat/kvB (200 sat/vB), fee factor 3, fee slack 1000 sat/kvB
 * (1 sat/vB). No clock: the caller must set now_ms. */
void gz_multi_config_default(gz_multi_config *cfg, gz_network network);

typedef enum gz_chain_call {
  GZ_CALL_NONE = 0,
  GZ_CALL_TIP,
  GZ_CALL_BLOCK_HASH,
  GZ_CALL_BLOCK_HEADER,
  GZ_CALL_BLOCK_SUMMARY,
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
    gz_block_summary summary;
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
  /* The verdict is an answer, but the servers differ about unconfirmed data. */
  bool unconfirmed_differs;
  size_t server_count;
  size_t operator_count; /* distinct operators among the servers */
  gz_multi_answer answers[GZ_MULTI_MAX_SERVERS]; /* in the order given at creation */
  /* The operator each server was counted under. */
  char operators[GZ_MULTI_MAX_SERVERS][GZ_OPERATOR_MAX];
} gz_multi_report;

/*
 * Creates the comparing backend over servers[0..count). The gz_chain handles
 * are copied; the backends themselves are borrowed and must outlive it (it
 * does not destroy them). count may be 1 to GZ_MULTI_MAX_SERVERS.
 *
 * Returns GZ_CHAIN_INVALID_ARG, and creates nothing, if any two servers are
 * the same backend, have the same normalised address, or are on the same
 * host, if a server describes itself with a host gz_host_normalise refuses
 * or an operator name not in canonical form, or if the configuration has no
 * clock. Servers that cannot say who they talk to (no describe function) are
 * told apart by handle only and each counts as its own operator; that is for
 * tests and for backends that are not network servers.
 *
 * With fewer operators than the quorum every call returns
 * GZ_CHAIN_NO_QUORUM, and the report still shows what each server said.
 * Creation sends nothing; each server's network is checked on first use.
 */
gz_chain_result gz_multi_create(const gz_multi_config *cfg, const gz_chain *servers, size_t count,
                                gz_chain *out);

/* Every server's reply to the most recent call on `multi`, owned by the
 * backend and overwritten by the next call. NULL if `multi` is not a
 * comparing backend. */
const gz_multi_report *gz_multi_last_report(const gz_chain *multi);

/* Number of distinct operators among the servers; 0 if `multi` is not a
 * comparing backend. Below the quorum, nothing can ever be answered. */
size_t gz_multi_operator_count(const gz_chain *multi);

#ifdef __cplusplus
}
#endif

#endif /* GAZPACHO_CHAIN_MULTI_H */
