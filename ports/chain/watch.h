/*
 * The watch engine: the part of the chain worker that has no thread.
 * Internal to ports/chain; in a header so that the worker (chainw.c), the
 * unit tests and the fuzz target can call it.
 *
 * It holds the watch set, a chain of checked block headers and the
 * broadcasts in flight. gz_watch_step makes one pass: it asks the gz_chain
 * (blocking) and hands each change to the `emit` callback as a
 * gz_chainw_event. Everything is on the caller's thread; nothing here locks.
 * The rules are in docs/notes/chain-port.md, sections 16 to 21.
 */
#ifndef GAZPACHO_CHAIN_WATCH_INTERNAL_H
#define GAZPACHO_CHAIN_WATCH_INTERNAL_H

#include "gazpacho/chain_watch.h"

typedef struct gz_watch gz_watch;

typedef struct gz_watch_config {
  const gz_chain *chain;
  gz_network network;
  /* As in gz_chainw_config. */
  uint32_t tip_poll_ms, retry_ms, retry_max_ms, burial_depth;
  size_t max_watches;
  uint32_t broadcast_attempts, broadcast_backoff_ms, broadcast_backoff_max_ms;
  uint32_t header_window, max_catchup, max_link;
  uint64_t (*now_ms)(void *clock_ctx); /* required */
  void *clock_ctx;
  /* Optional. Asked between chain calls; true ends the pass at once, with no
   * event for a call that was cut short. */
  bool (*stop)(void *stop_ctx);
  void *stop_ctx;
  /* Optional. Called between chain calls, after the stop test: the worker
   * hands over requests queued meanwhile, so that a broadcast queued during
   * a long pass is sent within it. It may set, drop and release watches and
   * queue broadcasts; it must not call gz_watch_step or gz_watch_clear. */
  void (*between)(void *between_ctx);
  void *between_ctx;
  /* Required. Receives every event, in order. `generation` is left zero. */
  void (*emit)(void *emit_ctx, const gz_chainw_event *ev);
  void *emit_ctx;
} gz_watch_config;

/* True if the limits are in range and the network is a test network. */
bool gz_watch_config_valid(const gz_watch_config *cfg);

/* NULL on an invalid configuration or no memory. Sends nothing. */
gz_watch *gz_watch_new(const gz_watch_config *cfg);
void gz_watch_free(gz_watch *e);

/* GZ_CHAINW_OK, GZ_CHAINW_FULL or GZ_CHAINW_INVALID (chain_watch.h). */
int gz_watch_tx(gz_watch *e, const uint8_t txid[GZ_HASH_LEN], uint32_t depth, unsigned flags);
int gz_watch_outpoint(gz_watch *e, const uint8_t txid[GZ_HASH_LEN], uint32_t vout, uint32_t depth,
                      unsigned flags);
void gz_watch_drop_tx(gz_watch *e, const uint8_t txid[GZ_HASH_LEN]);
void gz_watch_drop_outpoint(gz_watch *e, const uint8_t txid[GZ_HASH_LEN], uint32_t vout);
void gz_watch_release(gz_watch *e, const uint8_t txid[GZ_HASH_LEN], uint32_t delay_ms);

/* Queues a broadcast. `tx` (and `parent`, or NULL for a single transaction)
 * are heap blocks the engine takes over and frees, also when it refuses.
 * GZ_CHAINW_OK, or GZ_CHAINW_FULL with GZ_CHAINW_MAX_BROADCASTS in flight, or
 * GZ_CHAINW_INVALID for something that is not a transaction. */
int gz_watch_broadcast(gz_watch *e, uint64_t id, uint8_t *parent, size_t parent_len, uint8_t *tx,
                       size_t len);

/* Forgets every watch and broadcast (no event for them) and what was told so
 * far, so that the next pass tells the tip again. The checked headers stay. */
void gz_watch_clear(gz_watch *e);

/* One pass. Returns what the servers were worth in it (GZ_CHAIN_OK, or the
 * first failure). */
gz_chain_result gz_watch_step(gz_watch *e);

/* Milliseconds until gz_watch_step has something to do; 0: now. At most one
 * hour. Never 0 twice in a row without a pass in between having done
 * something, so a caller that sleeps this long cannot spin. */
uint32_t gz_watch_wait_ms(gz_watch *e);

size_t gz_watch_count(const gz_watch *e);
size_t gz_watch_broadcasts(const gz_watch *e);
/* The checked tip: false before the first successful pass. */
bool gz_watch_tip(const gz_watch *e, gz_chain_tip *out);

/* The outpoint that input `vin` of a serialized transaction spends. False if
 * the bytes do not hold such an input. `raw` should have passed
 * gz_txid_from_raw; every read is bounds-checked all the same. */
bool gz_watch_tx_input(const uint8_t *raw, size_t len, uint32_t vin, uint8_t txid[GZ_HASH_LEN],
                       uint32_t *vout);

#endif /* GAZPACHO_CHAIN_WATCH_INTERNAL_H */
