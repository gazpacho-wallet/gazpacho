/*
 * The chain worker and the watch loop (plan items P7 and S8).
 *
 * A gz_chain blocks: every call may wait on the network for the backend's
 * time limits and retries. The program's one loop must never wait on the
 * network. So one thread, the chain worker, owns the gz_chain and does all
 * chain I/O. The loop talks to it only through two bounded queues and one
 * descriptor:
 *
 *   loop  --requests-->  worker      set a watch, drop one, release one,
 *                                    broadcast
 *   loop  <--events----  worker      gz_chainw_take, when gz_chainw_fd is
 *                                    readable
 *
 * Nothing the loop calls here ever waits on the network, on the worker, or
 * on a full queue: a call that cannot be queued is refused and says so.
 *
 * What the worker does with a watch, which events it sends and in which
 * order, what a chain server can and cannot make it report, and what it
 * tells a server about the user: docs/notes/chain-port.md, sections 16 to 21.
 *
 * This header includes no core header. The program converts events to the
 * core's GZ_CHAIN_* events (docs/notes/chain-port.md section 22).
 */
#ifndef GAZPACHO_CHAIN_WATCH_H
#define GAZPACHO_CHAIN_WATCH_H

#include "gazpacho/chain.h"
#include "gazpacho/chain_multi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Most watches a worker can be configured to hold. */
#define GZ_CHAINW_WATCHES_LIMIT 1024
/* Most broadcasts waiting for their final result at one time. */
#define GZ_CHAINW_MAX_BROADCASTS 16
/* Longest refusal text kept in an event, including the terminating zero. */
#define GZ_CHAINW_REASON_MAX 128
/* The deepest burial a watch can ask for (the most headers a confirmation
 * check follows). */
#define GZ_CHAINW_MAX_DEPTH GZ_CONFIRM_MAX_DEPTH

/* ---- events ------------------------------------------------------------- */

typedef enum gz_chainw_kind {
  /* The best block changed. `height`, `block_hash`. The first event about
   * the chain in a generation is the tip. A broadcast outcome or a SOURCES
   * event can come before it: a broadcast waits for nothing, and servers can
   * be down from the start. */
  GZ_CHAINW_TIP = 1,
  /* A watched transaction is in the best chain. `txid`, `height`,
   * `block_hash`, `confirmations` (1 or more), `buried` (confirmations have
   * reached the watch's depth), `reorg` (the count is lower than the one
   * reported before). Sent when the transaction is first seen confirmed,
   * then each time the count, cut at the watch's depth, changes. */
  GZ_CHAINW_TX_CONFIRMED = 2,
  /* A confirmation reported earlier was undone: the transaction's block left
   * the best chain. `txid`; `in_mempool` says whether servers still show the
   * transaction unconfirmed. */
  GZ_CHAINW_TX_UNCONFIRMED = 3,
  /* A watched outpoint is spent. `outpoint_txid`, `outpoint_vout`; `txid` is
   * the spending transaction and `vin` its input; `confirmations` is 0 while
   * the spender is unconfirmed, else as for TX_CONFIRMED with `height`,
   * `block_hash` and `buried`. `replaced`: a different spender from the one
   * reported before. `reorg`: the spender reported before was confirmed and
   * is no longer, or its count went down. */
  GZ_CHAINW_OUTPOINT_SPENT = 4,
  /* The outcome of a broadcast: `broadcast`. */
  GZ_CHAINW_BROADCAST = 5,
  /* What the chain servers are worth right now changed: `sources`.
   * GZ_CHAIN_OK: they answer and agree. Anything else: nothing is reported
   * from them until it is GZ_CHAIN_OK again (lag, disagreement, no quorum,
   * unreachable, wrong network, a failed proof, a malformed answer). */
  GZ_CHAINW_SOURCES = 6,
  /* A watched transaction was seen unconfirmed for the first time. `txid`. */
  GZ_CHAINW_TX_MEMPOOL = 7,
  /* A watched transaction reported in the mempool is no longer known to the
   * servers and is not confirmed. `txid`. */
  GZ_CHAINW_TX_EVICTED = 8,
  /* A spend reported earlier is gone and nothing else spends the outpoint:
   * `outpoint_txid`, `outpoint_vout`; `txid` is the spender that left;
   * `reorg` says it had been confirmed. */
  GZ_CHAINW_OUTPOINT_UNSPENT = 9,
  /* Blocks left the best chain. `height` is the lowest height whose block
   * changed, `disconnected` how many blocks were removed. Sent before the
   * new tip and before what the reorganisation did to each watch. */
  GZ_CHAINW_REORG = 10
} gz_chainw_kind;

typedef enum gz_chainw_outcome {
  GZ_CHAINW_ACCEPTED = 1,      /* a server took it */
  GZ_CHAINW_ALREADY_KNOWN = 2, /* a server refused it as one it has, and was seen to have it */
  GZ_CHAINW_REJECTED = 3,      /* a server answered and refused it: `reason` */
  GZ_CHAINW_UNREACHABLE = 4,   /* no server gave a usable answer: `detail` says how */
  /* A package only: no configured server has a package endpoint, so the pair
   * was sent to nobody. Final. A parent that pays too little to relay alone
   * (a tree transaction at a zero or 0.1 sat/vB rate with its fee child)
   * cannot be published through these servers at all. */
  GZ_CHAINW_NO_PACKAGE_RELAY = 5
} gz_chainw_outcome;

typedef struct gz_chainw_broadcast_info {
  uint64_t id; /* the caller's own number for this broadcast */
  gz_chainw_outcome outcome;
  /* True: the worker is done with this broadcast. False (only with
   * GZ_CHAINW_UNREACHABLE): it will be tried again, and another event for
   * the same id follows. */
  bool final;
  uint32_t attempts; /* tries so far, counting this one */
  /* A parent and child sent together to a package endpoint. `txid` in the
   * event is the child's and `outcome` speaks for the pair: accepted only if
   * both are in. The two fields below say it for each transaction. */
  bool package;
  uint8_t parent_txid[GZ_HASH_LEN];
  gz_chainw_outcome parent_outcome;
  gz_chainw_outcome child_outcome;
  /* (ALREADY_KNOWN per transaction when the server lists it as already in
   * its mempool. All of this is advice, as for a single transaction.) */
  /* The chain view's own result code for the last try. */
  gz_chain_result detail;
  long server_status; /* HTTP status of the answer that decided, or 0 */
  /* The first refusing server's own words, printable ASCII, zero-terminated. */
  char reason[GZ_CHAINW_REASON_MAX];
  /* The comparing backend's per-server results, in the order the servers were
   * given to it; server_count is 0 for a single server. For the log only. */
  size_t server_count;
  struct {
    gz_chain_result result;
    bool already_known;
  } servers[GZ_MULTI_MAX_SERVERS];
} gz_chainw_broadcast_info;

typedef struct gz_chainw_event {
  gz_chainw_kind kind;
  uint64_t generation; /* of the gz_chainw_reset this event belongs to */
  /* Every txid is in the byte order the chain hashes it (chain.h). */
  uint8_t txid[GZ_HASH_LEN];
  uint8_t outpoint_txid[GZ_HASH_LEN];
  uint32_t outpoint_vout;
  uint32_t vin;
  uint32_t confirmations;
  uint32_t height;
  uint8_t block_hash[GZ_HASH_LEN];
  uint32_t disconnected;
  bool buried;
  bool reorg;
  bool replaced;
  bool in_mempool;
  gz_chain_result sources;
  gz_chainw_broadcast_info broadcast;
} gz_chainw_event;

/* A fixed short name for an event kind or a broadcast outcome, for logs. */
const char *gz_chainw_kind_name(gz_chainw_kind k);
const char *gz_chainw_outcome_name(gz_chainw_outcome o);

/* ---- the worker --------------------------------------------------------- */

typedef struct gz_chainw gz_chainw;

/* Flag for a watch: the transaction named cannot have been broadcast yet, so
 * no chain server may be asked about it. The watch is kept and nothing is
 * sent to any server that names its txid until gz_chainw_release. This is
 * how a member keeps a factory's funding txid to itself until the host has
 * broadcast it (docs/notes/chain-port.md section 9). */
#define GZ_CHAINW_NOT_BEFORE 1u

typedef struct gz_chainw_config {
  /* Created by the loop thread before gz_chainw_new, used only by the
   * worker, destroyed by the loop thread after gz_chainw_free. The comparing
   * backend over two operators, or one server the user runs. */
  gz_chain *chain;
  /* signet, testnet3 or testnet4. Mainnet is refused. */
  gz_network network;
  /* Time between two looks at the tip and at every unconfirmed watch. */
  uint32_t tip_poll_ms;
  /* Wait after a pass that failed (servers unreachable, disagreeing, lagging),
   * doubled for each failure in a row up to retry_max_ms. */
  uint32_t retry_ms;
  uint32_t retry_max_ms;
  /* Depth of a watch set with depth 0. 1..GZ_CHAINW_MAX_DEPTH. */
  uint32_t burial_depth;
  /* Most watches held. 1..GZ_CHAINW_WATCHES_LIMIT. One more is refused. */
  size_t max_watches;
  /* Requests queued and not yet taken by the worker. One more is refused. */
  size_t max_requests;
  /* Events waiting for the loop. When full the worker waits; it never drops
   * one. At least 2. */
  size_t max_results;
  /* Tries per broadcast while no server can be reached, and the wait before
   * the second try, doubled for each later one up to broadcast_backoff_max_ms. */
  uint32_t broadcast_attempts;
  uint32_t broadcast_backoff_ms;
  uint32_t broadcast_backoff_max_ms;
  /* Block hashes kept below the tip in the normal course, each from a
   * header checked to link to the one before it. At least 4. */
  uint32_t header_window;
  /* Most headers fetched in one pass, forward toward a tip further ahead or
   * down toward an older confirmation; the rest follow in the next passes,
   * so that the checked chain never has a gap. 1..header_window. */
  uint32_t max_catchup;
  /* Most block hashes ever kept, which bounds how far below the tip a
   * confirmation can be linked to the checked chain before it counts:
   * header_window..10,000,000. A confirmation further down is not told, and
   * the sources say GZ_CHAIN_TOO_LARGE. 32 bytes each, held only while a
   * confirmation that deep is being linked. */
  uint32_t max_link;
  /* The clock for every wait above: milliseconds, never going backwards.
   * NULL: the system's monotonic clock. */
  uint64_t (*now_ms)(void *clock_ctx);
  void *clock_ctx;
  /* Optional. Called with true to make the chain's transfer or wait in
   * progress end at once and every later one fail at once, and with false to
   * allow them again. Called from the loop thread and from the worker. With
   * the libcurl transport: gz_http_curl_interrupt_hook (chain_http.h), with
   * the gz_http as its context. Without it, a reset or a
   * shutdown waits for the request in progress, up to the backend's limits. */
  void (*interrupt)(void *interrupt_ctx, bool on);
  void *interrupt_ctx;
} gz_chainw_config;

/* tip_poll 60 s, retry 5 s to 5 min, burial depth 3, 256 watches, 1,024
 * requests, 4,096 events, 6 broadcast tries from 2 s to 60 s, 288 headers,
 * 144 per pass, links down to 52,560 blocks (a year), the monotonic clock,
 * no interrupt. */
void gz_chainw_config_default(gz_chainw_config *cfg, gz_chain *chain, gz_network network);

/* Starts the worker. NULL on a bad configuration (mainnet, no chain, a limit
 * out of range, max_requests below max_watches + GZ_CHAINW_MAX_BROADCASTS)
 * or if the thread, the queues or the descriptor cannot be made. Sends
 * nothing itself: the first pass of the worker does. */
gz_chainw *gz_chainw_new(const gz_chainw_config *cfg);

/* A descriptor that is readable exactly while events wait. Give it to
 * poll(); never read or write it. */
int gz_chainw_fd(const gz_chainw *w);

/*
 * Return values of the calls below. None of them ever blocks, so any of
 * them can refuse, and the refusal is a result the caller must look at: the
 * compiler warns when it is ignored (GZ_CHAINW_MUST_CHECK).
 *
 * GZ_CHAINW_BUSY on a watch, an unwatch or a release must be retried, from
 * a backlog the caller keeps, or treated as fatal for the incarnation (the
 * rule of contract v2). Some requests are made once only: a release refused
 * and forgotten keeps its watches held back for ever, and a watch refused
 * and forgotten never reports. Size max_requests for the worst burst: at
 * least max_watches + GZ_CHAINW_MAX_BROADCASTS (gz_chainw_new refuses less)
 * plus the releases that can come at once.
 */
#if defined(__GNUC__) || defined(__clang__)
#define GZ_CHAINW_MUST_CHECK __attribute__((warn_unused_result))
#else
#define GZ_CHAINW_MUST_CHECK
#endif
#define GZ_CHAINW_OK 0
/* Refused: the worker already holds max_watches watches, or
 * GZ_CHAINW_MAX_BROADCASTS broadcasts are waiting. Nothing was queued. */
#define GZ_CHAINW_FULL 1
/* Refused: max_requests requests are waiting for the worker. Nothing was
 * queued; ask again when the worker has caught up. */
#define GZ_CHAINW_BUSY 2
/* Refused: a NULL argument, a depth above GZ_CHAINW_MAX_DEPTH, something that
 * is not a transaction, or no memory for a copy. */
#define GZ_CHAINW_INVALID 3

/*
 * Watch a transaction to `depth` confirmations (0: the configured burial
 * depth). Events: GZ_CHAINW_TX_MEMPOOL, TX_EVICTED, TX_CONFIRMED,
 * TX_UNCONFIRMED. Setting a watch that is already set replaces its depth and
 * reports the state found again. `flags`: 0 or GZ_CHAINW_NOT_BEFORE.
 */
GZ_CHAINW_MUST_CHECK int gz_chainw_watch_tx(gz_chainw *w, const uint8_t txid[GZ_HASH_LEN], uint32_t depth,
                       unsigned flags);
/*
 * Watch output `vout` of `txid` for a spend, and the spender to `depth`
 * confirmations. Events: GZ_CHAINW_OUTPOINT_SPENT, OUTPOINT_UNSPENT. With
 * GZ_CHAINW_NOT_BEFORE no server is asked about the outpoint until `txid` is
 * released.
 */
GZ_CHAINW_MUST_CHECK int gz_chainw_watch_outpoint(gz_chainw *w, const uint8_t txid[GZ_HASH_LEN], uint32_t vout,
                             uint32_t depth, unsigned flags);
/* Drop a watch. No event follows for it, except those already queued.
 * Dropping a watch that is not set is not an error. */
GZ_CHAINW_MUST_CHECK int gz_chainw_unwatch_tx(gz_chainw *w, const uint8_t txid[GZ_HASH_LEN]);
GZ_CHAINW_MUST_CHECK int gz_chainw_unwatch_outpoint(gz_chainw *w, const uint8_t txid[GZ_HASH_LEN], uint32_t vout);
/* `txid` can have been broadcast: after `delay_ms` more, every watch held
 * back for it (the transaction watch and the watches on its outputs) is
 * looked at like any other. */
GZ_CHAINW_MUST_CHECK int gz_chainw_release(gz_chainw *w, const uint8_t txid[GZ_HASH_LEN], uint32_t delay_ms);

/*
 * Broadcast a transaction (copied). `id` comes back in every
 * GZ_CHAINW_BROADCAST event for it. Exactly one final event follows each
 * accepted call, whatever happens, unless gz_chainw_reset or gz_chainw_free
 * comes first. While no server can be reached the worker tries again with
 * growing waits and says so once (an event that is not final). A refusal is
 * final at once: the worker does not argue with a server.
 */
GZ_CHAINW_MUST_CHECK int gz_chainw_broadcast(gz_chainw *w, uint64_t id, const uint8_t *raw, size_t len);
/* The same for a parent and its child, sent together as one package (the
 * only way a parent below the relay fee gets in). The pair goes to every
 * server that has a package endpoint. If none has one the final event says
 * GZ_CHAINW_NO_PACKAGE_RELAY: the worker never falls back to sending the two
 * one after the other, because a parent that needs its child would be
 * refused and the failure would look like something else. */
GZ_CHAINW_MUST_CHECK int gz_chainw_broadcast_package(gz_chainw *w, uint64_t id, const uint8_t *parent,
                                size_t parent_len, const uint8_t *child, size_t child_len);

/* 1 and *out (an event of the current generation), or 0 when none waits.
 * Makes room for a worker that is waiting to add one. */
int gz_chainw_take(gz_chainw *w, gz_chainw_event *out);

/* Forgets every watch, queued request, waiting broadcast and waiting event,
 * and ends the request in progress (if the configuration has `interrupt`).
 * Events of earlier generations are never delivered. Returns the new
 * generation. The first event about the chain in the next generation is the
 * tip. */
uint64_t gz_chainw_reset(gz_chainw *w);

typedef struct gz_chainw_stats {
  uint64_t generation;
  uint64_t passes;      /* passes over the chain finished (any generation) */
  uint64_t events;      /* events queued */
  uint64_t waits;       /* times the worker waited for room in the event queue */
  /* requests the engine refused although the loop side had accepted them:
   * the two counts of watches and broadcasts never differ, so always 0 */
  uint64_t diverged;
  size_t watches;       /* watches set */
  size_t broadcasts;    /* broadcasts without a final event yet */
  size_t queued_events; /* waiting for gz_chainw_take */
  size_t queued_requests;
} gz_chainw_stats;
void gz_chainw_stats_get(gz_chainw *w, gz_chainw_stats *out);

/* Ends the request in progress (with `interrupt`), stops and joins the
 * worker, and frees everything. Does not destroy the chain. With `interrupt`
 * this returns within about a second; without, within the backend's limits
 * for one request. `w` may be NULL. */
void gz_chainw_free(gz_chainw *w);

#ifdef __cplusplus
}
#endif

#endif /* GAZPACHO_CHAIN_WATCH_H */
