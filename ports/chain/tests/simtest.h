/*
 * What the watch tests share: writing an event as one short line of text, in
 * the names of the made-up world (sim.h), so that a test can state the exact
 * sequence it expects:
 *
 *   tip 1005
 *   mempool T                              evicted T
 *   confirmed T n=1 at a5 [buried] [reorg] unconfirmed T [mempool]
 *   spent P:0 by S1 n=0 [replaced] [reorg]
 *   spent P:0 by S2#1 n=1 at b7 [buried] [replaced] [reorg]   (#1: its input 1)
 *   unspent P:0 was S1 [reorg]
 *   reorg from 1004 gone 2
 *   sources servers-disagree
 *   broadcast #7 accepted final tries=1
 *   broadcast #8 rejected final tries=1 package parent=rejected child=rejected
 */
#ifndef GZ_CHAIN_SIMTEST_H
#define GZ_CHAIN_SIMTEST_H

#include <stdio.h>
#include <string.h>

#include "gazpacho/chain_watch.h"

#include "sim.h"

static inline const char *st_tx_name(const sim_world *w, const uint8_t id[GZ_HASH_LEN]) {
  static const char *const names[SIM_NTX] = {"T", "S1", "S2", "K"};
  for (int i = 0; i < SIM_NTX; i++) {
    if (memcmp(w->tx[i].id, id, GZ_HASH_LEN) == 0) return names[i];
  }
  if (memcmp(w->p, id, GZ_HASH_LEN) == 0) return "P";
  if (memcmp(w->q, id, GZ_HASH_LEN) == 0) return "Q";
  return "?";
}

/* "c2", "a5", "b7", "x8" (branch C's own blocks), or "??" for a block that is
 * not the world's block at that height. */
static inline void st_block_name(const sim_world *w, uint32_t height,
                                 const uint8_t id[GZ_HASH_LEN], char out[16]) {
  static const char letters[3] = {'a', 'b', 'x'};
  snprintf(out, 16, "??");
  for (int br = 0; br < 3; br++) {
    const sim_block *b = sim_block_of(w, br, height);
    if (b == NULL || memcmp(b->id, id, GZ_HASH_LEN) != 0) continue;
    bool own = height >= SIM_H0 + SIM_COMMON && (br != SIM_C || height >= SIM_H0 + 7);
    snprintf(out, 16, "%c%u", own ? letters[br] : height < SIM_H0 + SIM_COMMON ? 'c' : 'a',
             height - SIM_H0);
    return;
  }
}

static inline void st_format(const sim_world *w, const gz_chainw_event *ev, char *out, size_t cap) {
  char blk[16];
  size_t n = 0;
  switch (ev->kind) {
    case GZ_CHAINW_TIP: snprintf(out, cap, "tip %u", ev->height); break;
    case GZ_CHAINW_TX_MEMPOOL: snprintf(out, cap, "mempool %s", st_tx_name(w, ev->txid)); break;
    case GZ_CHAINW_TX_EVICTED: snprintf(out, cap, "evicted %s", st_tx_name(w, ev->txid)); break;
    case GZ_CHAINW_TX_CONFIRMED:
      st_block_name(w, ev->height, ev->block_hash, blk);
      snprintf(out, cap, "confirmed %s n=%u at %s%s%s", st_tx_name(w, ev->txid), ev->confirmations,
               blk, ev->buried ? " buried" : "", ev->reorg ? " reorg" : "");
      break;
    case GZ_CHAINW_TX_UNCONFIRMED:
      snprintf(out, cap, "unconfirmed %s%s", st_tx_name(w, ev->txid),
               ev->in_mempool ? " mempool" : "");
      break;
    case GZ_CHAINW_OUTPOINT_SPENT:
      /* a spender that spends with another input than its first says which */
      n = (size_t)snprintf(out, cap, "spent %s:%u by %s", st_tx_name(w, ev->outpoint_txid),
                           ev->outpoint_vout, st_tx_name(w, ev->txid));
      if (ev->vin != 0 && n < cap) n += (size_t)snprintf(out + n, cap - n, "#%u", ev->vin);
      if (n < cap) n += (size_t)snprintf(out + n, cap - n, " n=%u", ev->confirmations);
      if (ev->confirmations > 0 && n < cap) {
        st_block_name(w, ev->height, ev->block_hash, blk);
        n += (size_t)snprintf(out + n, cap - n, " at %s", blk);
      }
      if (n < cap)
        snprintf(out + n, cap - n, "%s%s%s", ev->buried ? " buried" : "",
                 ev->replaced ? " replaced" : "", ev->reorg ? " reorg" : "");
      break;
    case GZ_CHAINW_OUTPOINT_UNSPENT:
      snprintf(out, cap, "unspent %s:%u was %s%s", st_tx_name(w, ev->outpoint_txid),
               ev->outpoint_vout, st_tx_name(w, ev->txid), ev->reorg ? " reorg" : "");
      break;
    case GZ_CHAINW_REORG:
      snprintf(out, cap, "reorg from %u gone %u", ev->height, ev->disconnected);
      break;
    case GZ_CHAINW_SOURCES:
      snprintf(out, cap, "sources %s", gz_chain_result_name(ev->sources));
      break;
    case GZ_CHAINW_BROADCAST:
      n = (size_t)snprintf(out, cap, "broadcast #%llu %s%s tries=%u",
                           (unsigned long long)ev->broadcast.id,
                           gz_chainw_outcome_name(ev->broadcast.outcome),
                           ev->broadcast.final ? " final" : "", ev->broadcast.attempts);
      if (ev->broadcast.package && n < cap)
        snprintf(out + n, cap - n, " package parent=%s child=%s",
                 gz_chainw_outcome_name(ev->broadcast.parent_outcome),
                 gz_chainw_outcome_name(ev->broadcast.child_outcome));
      break;
    case GZ_CHAINW_TIP_SYNCED: snprintf(out, cap, "tip-synced %u", ev->height); break;
    case GZ_CHAINW_WATCH_PENDING:
      if (ev->outpoint_watch)
        snprintf(out, cap, "pending %s:%u", st_tx_name(w, ev->outpoint_txid), ev->outpoint_vout);
      else
        snprintf(out, cap, "pending %s", st_tx_name(w, ev->txid));
      break;
    case GZ_CHAINW_WATCH_FAILED:
      if (ev->outpoint_watch)
        snprintf(out, cap, "failed %s:%u %s", st_tx_name(w, ev->outpoint_txid), ev->outpoint_vout,
                 gz_chain_result_name(ev->sources));
      else
        snprintf(out, cap, "failed %s %s", st_tx_name(w, ev->txid), gz_chain_result_name(ev->sources));
      break;
    case GZ_CHAINW_SYNCED:
      if (ev->outpoint_watch)
        snprintf(out, cap, "synced %s:%u", st_tx_name(w, ev->outpoint_txid), ev->outpoint_vout);
      else
        snprintf(out, cap, "synced %s", st_tx_name(w, ev->txid));
      break;
    default: snprintf(out, cap, "unknown-kind-%d", (int)ev->kind); break;
  }
}

/* The events since the last look, as "a | b | c". */
#define ST_MAX_EVENTS 256
typedef struct st_rec {
  const sim_world *w;
  gz_chainw_event ev[ST_MAX_EVENTS];
  size_t n;
  size_t dropped;
} st_rec;

static inline void st_record(void *ctx, const gz_chainw_event *ev) {
  st_rec *r = ctx;
  if (r->n < ST_MAX_EVENTS) {
    r->ev[r->n++] = *ev;
  } else {
    r->dropped++;
  }
}

static inline void st_join(st_rec *r, char *out, size_t cap) {
  size_t at = 0;
  out[0] = '\0';
  for (size_t i = 0; i < r->n && at + 4 < cap; i++) {
    if (i > 0) at += (size_t)snprintf(out + at, cap - at, " | ");
    st_format(r->w, &r->ev[i], out + at, cap - at);
    at += strlen(out + at);
  }
  r->n = 0;
}

#endif /* GZ_CHAIN_SIMTEST_H */
