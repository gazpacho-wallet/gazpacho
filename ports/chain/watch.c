/*
 * The watch engine. See watch.h, chain_watch.h and docs/notes/chain-port.md
 * sections 16 to 21.
 *
 * Three things are kept:
 *  - a chain of block hashes, each taken from a header that met its proof of
 *    work and named the one before it, without a gap from the first header
 *    checked to the tip. Confirmations are counted along this chain and
 *    nowhere else, so a server cannot add depth by claiming a tip: a tip far
 *    ahead is followed header by header over several passes, and a block
 *    below the hashes held is linked to them header by header before its
 *    depth counts;
 *  - the watches, each with the last state told to the caller, so that an
 *    event is sent only when that state changes;
 *  - the broadcasts that have no final outcome yet.
 */
#include "watch.h"

#include <stdlib.h>
#include <string.h>

#define KIND_TX 1
#define KIND_OUTPOINT 2

#define ST_NONE 0      /* not seen; outpoint: not spent */
#define ST_MEMPOOL 1   /* seen unconfirmed; outpoint: spent by an unconfirmed transaction */
#define ST_CONFIRMED 2 /* in a block of the checked chain */

/* "Not yet": the answer names a block above the checked headers. Not a
 * failure of the servers; the watch is looked at again after a short wait. */
#define R_LATER ((gz_chain_result)1000)
/* The short wait. */
#define SETTLE_MS 1000u
/* The longest wait gz_watch_wait_ms reports. */
#define WAIT_MAX_MS 3600000u

typedef struct watch {
  bool used;
  uint8_t kind;
  uint8_t txid[GZ_HASH_LEN]; /* the watched transaction, or the outpoint's */
  uint32_t vout;
  uint32_t depth;
  /* not before: nothing naming txid is sent while held */
  bool held;
  bool release_set;
  uint64_t release_at;
  bool fresh;   /* set, set again or released: ask now */
  bool recheck; /* a reorganisation may have undone what is recorded: ask now */
  uint8_t state;
  /* the transaction whose confirmation is followed: the watched one, or the
   * outpoint's spender */
  uint8_t subject[GZ_HASH_LEN];
  uint32_t vin;
  uint32_t height;
  uint8_t block[GZ_HASH_LEN];
  /* The block of the confirmation was found on the checked chain, and that
   * chain has only grown since by linked headers, so its count is the
   * distance to the checked tip even once the block is below the hashes
   * held. Cleared by anything that may have undone it. */
  bool linked;
  uint32_t reported; /* confirmations in the last report of this confirmation; 0: none */
  bool replaced;     /* the next spend report names a different spender */
  bool undone;       /* the next spend report follows a confirmed spender that left the chain */
} watch;

typedef struct bjob {
  bool used;
  uint64_t id;
  uint8_t *parent; /* NULL: a single transaction */
  size_t parent_len;
  uint8_t *tx;
  size_t len;
  uint8_t txid[GZ_HASH_LEN];
  uint8_t parent_txid[GZ_HASH_LEN];
  uint32_t attempts;
  uint64_t next_at;
  int last; /* outcome of the last event sent; 0: none */
} bjob;

struct gz_watch {
  gz_watch_config cfg;
  watch *w;
  size_t n_watches;
  bjob jobs[GZ_CHAINW_MAX_BROADCASTS];
  size_t n_jobs;
  /* the checked header chain: hash[i] is the block at height hbase + i. It
   * holds header_window hashes, more while a confirmation further down is
   * being linked to it, never more than max_link. */
  uint8_t (*hash)[GZ_HASH_LEN];
  uint32_t hn, hbase, hcap;
  uint8_t base_prev[GZ_HASH_LEN]; /* what the block at hbase names as its parent */
  uint8_t *incoming;              /* max_catchup headers, before they are accepted */
  bool catching_up;  /* the servers are further ahead than one pass follows */
  bool descending;   /* a confirmation below the hashes held is being linked */
  size_t next_watch; /* where the next pass starts, after one that ended early */
  bool network_ok;
  bool tell_tip;
  bool tip_synced_told; /* GZ_CHAINW_TIP_SYNCED told for the tip last told */
  uint64_t next_sync;  /* when the tip is next due */
  uint64_t hold_until; /* nothing is asked before this, after a failed pass */
  uint32_t failures;   /* failed passes in a row */
  gz_chain_result sources;
  uint8_t *txbuf; /* GZ_TX_MAX_BYTES, made on first use */
  gz_confirmation conf;
};

const char *gz_chainw_kind_name(gz_chainw_kind k) {
  switch (k) {
    case GZ_CHAINW_TIP: return "tip";
    case GZ_CHAINW_TX_CONFIRMED: return "tx-confirmed";
    case GZ_CHAINW_TX_UNCONFIRMED: return "tx-unconfirmed";
    case GZ_CHAINW_OUTPOINT_SPENT: return "outpoint-spent";
    case GZ_CHAINW_BROADCAST: return "broadcast";
    case GZ_CHAINW_SOURCES: return "sources";
    case GZ_CHAINW_TX_MEMPOOL: return "tx-mempool";
    case GZ_CHAINW_TX_EVICTED: return "tx-evicted";
    case GZ_CHAINW_OUTPOINT_UNSPENT: return "outpoint-unspent";
    case GZ_CHAINW_REORG: return "reorg";
    case GZ_CHAINW_SYNCED: return "synced";
    case GZ_CHAINW_TIP_SYNCED: return "tip-synced";
  }
  return "unknown";
}

const char *gz_chainw_outcome_name(gz_chainw_outcome o) {
  switch (o) {
    case GZ_CHAINW_ACCEPTED: return "accepted";
    case GZ_CHAINW_ALREADY_KNOWN: return "already-known";
    case GZ_CHAINW_REJECTED: return "rejected";
    case GZ_CHAINW_UNREACHABLE: return "unreachable";
    case GZ_CHAINW_NO_PACKAGE_RELAY: return "no-package-relay";
  }
  return "unknown";
}

/* ---- small helpers ------------------------------------------------------- */

static bool hash_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, GZ_HASH_LEN) == 0; }
static uint64_t now_ms(const gz_watch *e) { return e->cfg.now_ms(e->cfg.clock_ctx); }
static bool stopped(const gz_watch *e) {
  return e->cfg.stop != NULL && e->cfg.stop(e->cfg.stop_ctx);
}
static void emit(gz_watch *e, const gz_chainw_event *ev) { e->cfg.emit(e->cfg.emit_ctx, ev); }
static uint32_t top_height(const gz_watch *e) { return e->hbase + e->hn - 1; }
static const uint8_t *hash_at(const gz_watch *e, uint32_t height) {
  return e->hash[height - e->hbase];
}

bool gz_watch_config_valid(const gz_watch_config *cfg) {
  if (cfg == NULL || cfg->chain == NULL || cfg->chain->ops == NULL || cfg->now_ms == NULL ||
      cfg->emit == NULL)
    return false;
  /* signet and the testnets only: this engine never runs on mainnet */
  if (!gz_network_is_test(cfg->network)) return false;
  if (cfg->tip_poll_ms == 0 || cfg->retry_ms == 0 || cfg->retry_max_ms < cfg->retry_ms) return false;
  if (cfg->burial_depth == 0 || cfg->burial_depth > GZ_CHAINW_MAX_DEPTH) return false;
  if (cfg->max_watches == 0 || cfg->max_watches > GZ_CHAINW_WATCHES_LIMIT) return false;
  if (cfg->broadcast_attempts == 0 || cfg->broadcast_backoff_ms == 0 ||
      cfg->broadcast_backoff_max_ms < cfg->broadcast_backoff_ms)
    return false;
  if (cfg->header_window < 4 || cfg->header_window > 100000) return false;
  if (cfg->max_catchup == 0 || cfg->max_catchup > cfg->header_window) return false;
  if (cfg->max_link < cfg->header_window || cfg->max_link > 10000000) return false;
  return true;
}

gz_watch *gz_watch_new(const gz_watch_config *cfg) {
  if (!gz_watch_config_valid(cfg)) return NULL;
  gz_watch *e = calloc(1, sizeof *e);
  if (e == NULL) return NULL;
  e->cfg = *cfg;
  e->w = calloc(cfg->max_watches, sizeof *e->w);
  e->hcap = cfg->header_window;
  e->hash = calloc(e->hcap, GZ_HASH_LEN);
  e->incoming = calloc(cfg->max_catchup, GZ_HEADER_LEN);
  if (e->w == NULL || e->hash == NULL || e->incoming == NULL) {
    gz_watch_free(e);
    return NULL;
  }
  e->sources = GZ_CHAIN_OK;
  e->tell_tip = true;
  return e;
}

static void job_free(gz_watch *e, bjob *j) {
  free(j->parent);
  free(j->tx);
  memset(j, 0, sizeof *j);
  e->n_jobs--;
}

void gz_watch_free(gz_watch *e) {
  if (e == NULL) return;
  for (size_t i = 0; i < GZ_CHAINW_MAX_BROADCASTS; i++) {
    if (e->jobs[i].used) job_free(e, &e->jobs[i]);
  }
  free(e->w);
  free(e->hash);
  free(e->incoming);
  free(e->txbuf);
  free(e);
}

size_t gz_watch_count(const gz_watch *e) { return e->n_watches; }
size_t gz_watch_broadcasts(const gz_watch *e) { return e->n_jobs; }

bool gz_watch_tip(const gz_watch *e, gz_chain_tip *out) {
  if (e->hn == 0) return false;
  out->height = top_height(e);
  memcpy(out->hash, hash_at(e, out->height), GZ_HASH_LEN);
  return true;
}

/* ---- the watch set ------------------------------------------------------- */

static watch *find(gz_watch *e, uint8_t kind, const uint8_t txid[GZ_HASH_LEN], uint32_t vout) {
  for (size_t i = 0; i < e->cfg.max_watches; i++) {
    watch *w = &e->w[i];
    if (w->used && w->kind == kind && w->vout == vout && hash_eq(w->txid, txid)) return w;
  }
  return NULL;
}

static int set_watch(gz_watch *e, uint8_t kind, const uint8_t txid[GZ_HASH_LEN], uint32_t vout,
                     uint32_t depth, unsigned flags) {
  if (e == NULL || txid == NULL || depth > GZ_CHAINW_MAX_DEPTH ||
      (flags & ~GZ_CHAINW_NOT_BEFORE) != 0)
    return GZ_CHAINW_INVALID;
  if (depth == 0) depth = e->cfg.burial_depth;
  watch *w = find(e, kind, txid, vout);
  /* once released, always released: the servers have been asked already */
  bool was_released = w != NULL && !w->held;
  if (w == NULL) {
    if (e->n_watches == e->cfg.max_watches) return GZ_CHAINW_FULL;
    for (size_t i = 0; i < e->cfg.max_watches && w == NULL; i++) {
      if (!e->w[i].used) w = &e->w[i];
    }
    e->n_watches++;
  }
  /* set again: start from nothing, so that the state found is told again */
  memset(w, 0, sizeof *w);
  w->used = true;
  w->kind = kind;
  memcpy(w->txid, txid, GZ_HASH_LEN);
  w->vout = vout;
  w->depth = depth;
  w->held = (flags & GZ_CHAINW_NOT_BEFORE) != 0 && !was_released;
  w->fresh = true;
  return GZ_CHAINW_OK;
}

int gz_watch_tx(gz_watch *e, const uint8_t txid[GZ_HASH_LEN], uint32_t depth, unsigned flags) {
  return set_watch(e, KIND_TX, txid, 0, depth, flags);
}

int gz_watch_outpoint(gz_watch *e, const uint8_t txid[GZ_HASH_LEN], uint32_t vout, uint32_t depth,
                      unsigned flags) {
  return set_watch(e, KIND_OUTPOINT, txid, vout, depth, flags);
}

static void drop(gz_watch *e, uint8_t kind, const uint8_t txid[GZ_HASH_LEN], uint32_t vout) {
  watch *w = e != NULL && txid != NULL ? find(e, kind, txid, vout) : NULL;
  if (w == NULL) return;
  memset(w, 0, sizeof *w);
  e->n_watches--;
}

void gz_watch_drop_tx(gz_watch *e, const uint8_t txid[GZ_HASH_LEN]) { drop(e, KIND_TX, txid, 0); }
void gz_watch_drop_outpoint(gz_watch *e, const uint8_t txid[GZ_HASH_LEN], uint32_t vout) {
  drop(e, KIND_OUTPOINT, txid, vout);
}

void gz_watch_release(gz_watch *e, const uint8_t txid[GZ_HASH_LEN], uint32_t delay_ms) {
  if (e == NULL || txid == NULL) return;
  uint64_t at = now_ms(e) + delay_ms;
  for (size_t i = 0; i < e->cfg.max_watches; i++) {
    watch *w = &e->w[i];
    if (!w->used || !w->held || !hash_eq(w->txid, txid)) continue;
    /* an earlier release stands: a later call cannot push it back */
    if (w->release_set && w->release_at <= at) continue;
    w->release_set = true;
    w->release_at = at;
  }
}

void gz_watch_clear(gz_watch *e) {
  if (e == NULL) return;
  memset(e->w, 0, e->cfg.max_watches * sizeof *e->w);
  e->n_watches = 0;
  for (size_t i = 0; i < GZ_CHAINW_MAX_BROADCASTS; i++) {
    if (e->jobs[i].used) job_free(e, &e->jobs[i]);
  }
  e->sources = GZ_CHAIN_OK;
  e->tell_tip = true;
  e->next_sync = 0;
  e->next_watch = 0;
}

/* ---- transactions -------------------------------------------------------- */

static bool rd_varint(const uint8_t *raw, size_t len, size_t *off, uint64_t *out) {
  if (*off >= len) return false;
  uint8_t first = raw[(*off)++];
  unsigned width = first < 0xfd ? 0 : first == 0xfd ? 2 : first == 0xfe ? 4 : 8;
  if (width == 0) {
    *out = first;
    return true;
  }
  if (len - *off < width) return false;
  uint64_t v = 0;
  for (unsigned i = 0; i < width; i++) v |= (uint64_t)raw[*off + i] << (8 * i);
  *off += width;
  *out = v;
  return true;
}

bool gz_watch_tx_input(const uint8_t *raw, size_t len, uint32_t vin, uint8_t txid[GZ_HASH_LEN],
                       uint32_t *vout) {
  size_t off = 4;
  uint64_t n_in = 0;
  if (raw == NULL || txid == NULL || vout == NULL || len < 6) return false;
  /* the witness marker and flag: an input count of zero cannot be a transaction */
  if (raw[4] == 0x00 && raw[5] == 0x01) off = 6;
  if (!rd_varint(raw, len, &off, &n_in) || vin >= n_in) return false;
  for (uint32_t i = 0;; i++) {
    uint64_t script_len = 0;
    if (len - off < 36) return false;
    if (i == vin) {
      memcpy(txid, raw + off, GZ_HASH_LEN);
      *vout = (uint32_t)raw[off + 32] | (uint32_t)raw[off + 33] << 8 |
              (uint32_t)raw[off + 34] << 16 | (uint32_t)raw[off + 35] << 24;
      return true;
    }
    off += 36;
    if (!rd_varint(raw, len, &off, &script_len) || script_len > len - off) return false;
    off += (size_t)script_len;
    if (len - off < 4) return false;
    off += 4;
  }
}

/* ---- the header chain ---------------------------------------------------- */

static void event_init(gz_chainw_event *ev, gz_chainw_kind kind) {
  memset(ev, 0, sizeof *ev);
  ev->kind = kind;
}

static void emit_tip(gz_watch *e) {
  gz_chainw_event ev;
  event_init(&ev, GZ_CHAINW_TIP);
  ev.height = top_height(e);
  memcpy(ev.block_hash, hash_at(e, ev.height), GZ_HASH_LEN);
  e->tell_tip = false;
  e->tip_synced_told = false;
  emit(e, &ev);
}

static void emit_reorg(gz_watch *e, uint32_t first_changed, uint32_t disconnected) {
  gz_chainw_event ev;
  event_init(&ev, GZ_CHAINW_REORG);
  ev.height = first_changed;
  ev.disconnected = disconnected;
  ev.reorg = true;
  emit(e, &ev);
}

/* Every confirmation recorded above `height` (every one: `all`) may have
 * been undone: it is asked about again and placed on the chain again. */
static void recheck_above(gz_watch *e, uint32_t height, bool all) {
  for (size_t i = 0; i < e->cfg.max_watches; i++) {
    watch *w = &e->w[i];
    if (w->used && w->state == ST_CONFIRMED && (all || w->height > height)) {
      w->recheck = true;
      w->linked = false;
    }
  }
}

/* A header the servers say exists, checked for its proof of work. */
static gz_chain_result get_header(gz_watch *e, uint32_t height, uint8_t out[GZ_HEADER_LEN]) {
  gz_chain_result r = gz_chain_block_header(e->cfg.chain, height, out);
  /* a block that was there a moment ago: the chain moved, ask again */
  if (r == GZ_CHAIN_NOT_FOUND) return GZ_CHAIN_LAG;
  if (r != GZ_CHAIN_OK) return r;
  if (gz_header_check_pow(out, e->cfg.network) != GZ_POW_OK) return GZ_CHAIN_BAD_PROOF;
  return GZ_CHAIN_OK;
}

/* Room for `need` hashes; never more than max_link. */
static bool ensure_cap(gz_watch *e, uint32_t need) {
  if (need <= e->hcap) return true;
  if (need > e->cfg.max_link) return false;
  uint32_t cap = e->hcap;
  while (cap < need) cap = cap > e->cfg.max_link / 2 ? e->cfg.max_link : cap * 2;
  void *grown = realloc(e->hash, (size_t)cap * GZ_HASH_LEN);
  if (grown == NULL) return false;
  e->hash = grown;
  e->hcap = cap;
  return true;
}

/* Drops hashes from the bottom until `keep` are left. A confirmation already
 * linked keeps its count when its block is dropped. */
static void trim(gz_watch *e, uint32_t keep) {
  if (keep == 0 || e->hn <= keep) return;
  uint32_t drop = e->hn - keep;
  memcpy(e->base_prev, e->hash[drop - 1], GZ_HASH_LEN);
  memmove(e->hash, e->hash + drop, (size_t)(e->hn - drop) * GZ_HASH_LEN);
  e->hn -= drop;
  e->hbase += drop;
}

static void push_hash(gz_watch *e, const uint8_t hash[GZ_HASH_LEN]) {
  if (e->hn == e->hcap && !ensure_cap(e, e->hn + 1)) trim(e, e->hn - 1);
  memcpy(e->hash[e->hn++], hash, GZ_HASH_LEN);
}

/* Starts the chain at the tip: one header, nothing below it known. Changes
 * nothing unless it succeeds. `gone` blocks from height `from` are told as
 * replaced first. Used for the first tip, and for servers whose chain shares
 * no block with the hashes held: then all of those are told as replaced,
 * since nothing shows which were not, and every confirmation is placed on
 * the new chain again before it counts. */
static gz_chain_result chain_start(gz_watch *e, const gz_chain_tip *tip, uint32_t from,
                                   uint32_t gone) {
  uint8_t hdr[GZ_HEADER_LEN], id[GZ_HASH_LEN];
  gz_chain_result r = get_header(e, tip->height, hdr);
  if (r != GZ_CHAIN_OK) return r;
  gz_header_hash(hdr, id);
  if (!hash_eq(id, tip->hash)) return GZ_CHAIN_LAG; /* a new block in between */
  bool had_chain = e->hn != 0;
  e->hn = 1;
  e->hbase = tip->height;
  memcpy(e->hash[0], id, GZ_HASH_LEN);
  memcpy(e->base_prev, hdr + 4, GZ_HASH_LEN);
  e->catching_up = false;
  e->descending = false;
  if (gone != 0) emit_reorg(e, from, gone);
  if (had_chain) recheck_above(e, 0, true);
  emit_tip(e);
  return GZ_CHAIN_OK;
}

/*
 * Brings the header chain toward the tip of the servers. Every header added
 * names the one before it and meets its proof of work; nothing is changed
 * unless every header fetched checks out. At most max_catchup headers are
 * added in one pass: a tip further ahead is reached over several passes
 * (catching_up), so the chain never has a gap that a claim could fill. A tip
 * below ours on our own chain changes nothing.
 */
static gz_chain_result sync_headers(gz_watch *e) {
  gz_chain_tip tip;
  uint8_t id[GZ_HASH_LEN];
  gz_chain_result r;
  if (!e->network_ok) {
    r = gz_chain_check_network(e->cfg.chain, e->cfg.network);
    if (r != GZ_CHAIN_OK) return r;
    e->network_ok = true;
  }
  r = gz_chain_tip_get(e->cfg.chain, &tip);
  if (r != GZ_CHAIN_OK) return r;
  if (e->hn == 0) return chain_start(e, &tip, 0, 0);

  uint32_t top = top_height(e);
  e->catching_up = false;
  if (tip.height == top && hash_eq(tip.hash, hash_at(e, top))) return GZ_CHAIN_OK;
  /* Servers far behind what has been checked already are not believed: a
   * chain does not get shorter by more than a reorganisation can explain. */
  if (tip.height < top && top - tip.height > GZ_MULTI_LAG_MAX_BLOCKS) return GZ_CHAIN_DISAGREE;
  if (tip.height < e->hbase) {
    /* below the oldest hash held: the parent of that block is our own
     * chain, one block back; anything else replaced every hash held */
    if (tip.height + 1 == e->hbase && hash_eq(tip.hash, e->base_prev)) return GZ_CHAIN_OK;
    return chain_start(e, &tip, e->hbase, e->hn);
  }

  /* the highest block we and the servers have in common */
  uint32_t common = tip.height < top ? tip.height : top;
  if (common == tip.height) {
    memcpy(id, tip.hash, GZ_HASH_LEN);
  } else {
    r = gz_chain_block_hash(e->cfg.chain, common, id);
    if (r != GZ_CHAIN_OK) return r == GZ_CHAIN_NOT_FOUND ? GZ_CHAIN_LAG : r;
  }
  while (!hash_eq(id, hash_at(e, common))) {
    if (stopped(e)) return GZ_CHAIN_OK;
    /* replaced further back than the hashes held: begin again */
    if (common == e->hbase) return chain_start(e, &tip, e->hbase, e->hn);
    common--;
    r = gz_chain_block_hash(e->cfg.chain, common, id);
    if (r != GZ_CHAIN_OK) return r == GZ_CHAIN_NOT_FOUND ? GZ_CHAIN_LAG : r;
  }
  if (common == tip.height) return GZ_CHAIN_OK; /* their tip is a block we already hold */

  /* fetch and check common + 1 .. common + take before believing any of it */
  uint32_t count = tip.height - common;
  uint32_t take = count < e->cfg.max_catchup ? count : e->cfg.max_catchup;
  const uint8_t *prev = hash_at(e, common);
  uint8_t prev_id[GZ_HASH_LEN];
  for (uint32_t i = 0; i < take; i++) {
    uint8_t *hdr = e->incoming + (size_t)i * GZ_HEADER_LEN;
    r = get_header(e, common + 1 + i, hdr);
    if (stopped(e)) return GZ_CHAIN_OK;
    if (r != GZ_CHAIN_OK) return r;
    if (!hash_eq(hdr + 4, prev)) return GZ_CHAIN_BAD_PROOF; /* does not name its parent */
    gz_header_hash(hdr, prev_id);
    prev = prev_id;
  }
  if (take == count && !hash_eq(prev, tip.hash)) return GZ_CHAIN_LAG; /* the tip moved */

  /* accept */
  if (common < top) {
    emit_reorg(e, common + 1, top - common);
    recheck_above(e, common, false);
    e->hn = common - e->hbase + 1;
  }
  for (uint32_t i = 0; i < take; i++) {
    gz_header_hash(e->incoming + (size_t)i * GZ_HEADER_LEN, id);
    push_hash(e, id);
  }
  e->catching_up = take < count;
  emit_tip(e);
  return GZ_CHAIN_OK;
}

/*
 * Is block `block` at `height` on the checked chain? A block below the
 * hashes held is first linked to them: the headers in between are fetched
 * from the top down, each the parent of the one above it, at most
 * max_catchup in one pass (R_LATER until the block is reached). A block more
 * than max_link below the tip is not followed (GZ_CHAIN_TOO_LARGE).
 */
static gz_chain_result place(gz_watch *e, uint32_t height, const uint8_t block[GZ_HASH_LEN]) {
  uint32_t top = top_height(e);
  if (height > top) return R_LATER;
  if (top - height + 1 > e->cfg.max_link) return GZ_CHAIN_TOO_LARGE;
  if (height < e->hbase) {
    uint32_t n = e->hbase - height;
    if (n > e->cfg.max_catchup) n = e->cfg.max_catchup;
    uint8_t (*down)[GZ_HASH_LEN] = (uint8_t (*)[GZ_HASH_LEN])(void *)e->incoming;
    uint8_t expect[GZ_HASH_LEN];
    memcpy(expect, e->base_prev, GZ_HASH_LEN);
    for (uint32_t i = 0; i < n; i++) {
      uint8_t hdr[GZ_HEADER_LEN];
      gz_chain_result r = get_header(e, e->hbase - 1 - i, hdr);
      if (stopped(e)) return R_LATER;
      if (r != GZ_CHAIN_OK) return r;
      gz_header_hash(hdr, down[i]);
      if (!hash_eq(down[i], expect)) return GZ_CHAIN_BAD_PROOF; /* not the parent above */
      memcpy(expect, hdr + 4, GZ_HASH_LEN);
    }
    if (!ensure_cap(e, e->hn + n)) return GZ_CHAIN_NO_MEMORY;
    memmove(e->hash + n, e->hash, (size_t)e->hn * GZ_HASH_LEN);
    for (uint32_t i = 0; i < n; i++) memcpy(e->hash[n - 1 - i], down[i], GZ_HASH_LEN);
    memcpy(e->base_prev, expect, GZ_HASH_LEN);
    e->hbase -= n;
    e->hn += n;
    if (height < e->hbase) {
      e->descending = true;
      return R_LATER;
    }
  }
  if (!hash_eq(hash_at(e, height), block)) return GZ_CHAIN_DISAGREE;
  return GZ_CHAIN_OK;
}

/*
 * A server says `subject` is confirmed in `block` at `height`. Believed only
 * if that block is on the checked chain and gz_chain_confirm_tx proves the
 * transaction is in it (the bytes, the header, the Merkle branch, the
 * coinbase). Its depth is then counted along the checked chain.
 */
static gz_chain_result confirm(gz_watch *e, const uint8_t subject[GZ_HASH_LEN], uint32_t height,
                               const uint8_t block[GZ_HASH_LEN]) {
  gz_chain_result r = place(e, height, block);
  if (r != GZ_CHAIN_OK) return r;
  r = gz_chain_confirm_tx(e->cfg.chain, e->cfg.network, subject, 1, &e->conf);
  if (r != GZ_CHAIN_OK) return r;
  if (e->conf.status.state != GZ_TX_CONFIRMED || e->conf.status.height != height ||
      !hash_eq(e->conf.status.block_hash, block))
    return R_LATER; /* it moved between the two questions */
  return GZ_CHAIN_OK;
}

/* ---- telling ------------------------------------------------------------- */

static uint32_t cut(uint32_t n, uint32_t depth) { return n < depth ? n : depth; }

static void watch_event(const watch *w, gz_chainw_event *ev, gz_chainw_kind kind) {
  event_init(ev, kind);
  if (w->kind == KIND_TX) {
    memcpy(ev->txid, w->txid, GZ_HASH_LEN);
  } else {
    memcpy(ev->outpoint_txid, w->txid, GZ_HASH_LEN);
    ev->outpoint_vout = w->vout;
    memcpy(ev->txid, w->subject, GZ_HASH_LEN);
    ev->vin = w->vin;
  }
}

/* Tells the confirmation count if, cut at the watch depth, it differs from
 * the last one told. The first report of a confirmation gives the real count. */
static void tell_count(gz_watch *e, watch *w, uint32_t n) {
  if (w->reported != 0 && cut(n, w->depth) == cut(w->reported, w->depth)) {
    return;
  }
  gz_chainw_event ev;
  watch_event(w, &ev, w->kind == KIND_TX ? GZ_CHAINW_TX_CONFIRMED : GZ_CHAINW_OUTPOINT_SPENT);
  ev.confirmations = n;
  ev.height = w->height;
  memcpy(ev.block_hash, w->block, GZ_HASH_LEN);
  ev.buried = n >= w->depth;
  ev.reorg = (w->reported != 0 && n < w->reported) || w->undone;
  ev.replaced = w->replaced;
  w->replaced = false;
  w->undone = false;
  w->reported = n;
  emit(e, &ev);
}

/* Linked confirmations only: the distance to the checked tip. */
static uint32_t count_of(const gz_watch *e, const watch *w) {
  return top_height(e) - w->height + 1;
}

static void set_none(watch *w) {
  w->state = ST_NONE;
  w->reported = 0;
  w->linked = false;
  w->replaced = false;
  w->undone = false;
}

static void set_confirmed(watch *w, uint32_t height, const uint8_t block[GZ_HASH_LEN]) {
  w->state = ST_CONFIRMED;
  w->height = height;
  memcpy(w->block, block, GZ_HASH_LEN);
  w->linked = true;
  w->reported = 0;
}

/* A confirmation already recorded, asked about again and still claimed: is
 * its block still on the checked chain? */
static gz_chain_result still_placed(gz_watch *e, watch *w) {
  if (w->linked && w->height < e->hbase) return GZ_CHAIN_OK;
  gz_chain_result r = place(e, w->height, w->block);
  if (r == GZ_CHAIN_OK) w->linked = true;
  return r;
}

/* ---- one watch ----------------------------------------------------------- */

static gz_chain_result poll_tx(gz_watch *e, watch *w, bool ask) {
  gz_chainw_event ev;
  if (!ask) {
    tell_count(e, w, count_of(e, w));
    return GZ_CHAIN_OK;
  }
  gz_tx_status st;
  gz_chain_result r = gz_chain_tx_status(e->cfg.chain, w->txid, &st);
  if (r != GZ_CHAIN_OK) return r;
  if (st.state == GZ_TX_CONFIRMED) {
    bool same = w->state == ST_CONFIRMED && w->height == st.height && hash_eq(w->block, st.block_hash);
    if (same) {
      r = still_placed(e, w);
      if (r != GZ_CHAIN_OK) return r;
    } else {
      r = confirm(e, w->txid, st.height, st.block_hash);
      if (r != GZ_CHAIN_OK) return r;
      if (w->state == ST_CONFIRMED) {
        /* confirmed in another block than the one told: that one is undone */
        watch_event(w, &ev, GZ_CHAINW_TX_UNCONFIRMED);
        ev.reorg = true;
        emit(e, &ev);
      }
      set_confirmed(w, st.height, st.block_hash);
    }
    tell_count(e, w, count_of(e, w));
    return GZ_CHAIN_OK;
  }
  /* The servers do not all say the same about the mempool: some have it. */
  bool some_have_it = st.state == GZ_TX_MEMPOOL || st.unconfirmed_differs;
  if (w->state == ST_CONFIRMED) {
    watch_event(w, &ev, GZ_CHAINW_TX_UNCONFIRMED);
    ev.reorg = true;
    ev.in_mempool = some_have_it;
    set_none(w);
    w->state = some_have_it ? ST_MEMPOOL : ST_NONE;
    emit(e, &ev);
  } else if (st.unconfirmed_differs) {
    /* neither "seen" nor "gone" until the servers agree */
  } else if (st.state == GZ_TX_MEMPOOL && w->state == ST_NONE) {
    w->state = ST_MEMPOOL;
    watch_event(w, &ev, GZ_CHAINW_TX_MEMPOOL);
    emit(e, &ev);
  } else if (st.state == GZ_TX_UNKNOWN && w->state == ST_MEMPOOL) {
    w->state = ST_NONE;
    watch_event(w, &ev, GZ_CHAINW_TX_EVICTED);
    emit(e, &ev);
  }
  return GZ_CHAIN_OK;
}

/* The spender a server names must really spend the outpoint: its bytes are
 * fetched (and hash to its txid) and its input is read. */
static gz_chain_result check_spender(gz_watch *e, const watch *w, const gz_outspend *sp) {
  uint8_t prev[GZ_HASH_LEN];
  uint32_t vout = 0;
  size_t len = 0;
  if (e->txbuf == NULL) {
    e->txbuf = malloc(GZ_TX_MAX_BYTES);
    if (e->txbuf == NULL) return GZ_CHAIN_NO_MEMORY;
  }
  gz_chain_result r = gz_chain_raw_tx(e->cfg.chain, sp->spender_txid, e->txbuf, GZ_TX_MAX_BYTES, &len);
  if (r == GZ_CHAIN_NOT_FOUND) return R_LATER; /* named and already gone */
  if (r != GZ_CHAIN_OK) return r;
  if (!gz_watch_tx_input(e->txbuf, len, sp->spender_vin, prev, &vout) ||
      !hash_eq(prev, w->txid) || vout != w->vout)
    return GZ_CHAIN_BAD_PROOF;
  return GZ_CHAIN_OK;
}

static gz_chain_result poll_outpoint(gz_watch *e, watch *w, bool ask) {
  gz_chainw_event ev;
  if (!ask) {
    tell_count(e, w, count_of(e, w));
    return GZ_CHAIN_OK;
  }
  gz_outspend sp;
  gz_chain_result r = gz_chain_outspend(e->cfg.chain, w->txid, w->vout, &sp);
  if (r != GZ_CHAIN_OK) return r;
  if (!sp.spent) {
    /* servers that differ about an unconfirmed spend settle nothing, unless
     * what was told was a confirmed spend, which is gone either way */
    if (sp.unconfirmed_differs && w->state != ST_CONFIRMED) return GZ_CHAIN_OK;
    if (w->state != ST_NONE) {
      watch_event(w, &ev, GZ_CHAINW_OUTPOINT_UNSPENT);
      ev.reorg = w->state == ST_CONFIRMED;
      set_none(w);
      emit(e, &ev);
    }
    return GZ_CHAIN_OK;
  }
  bool same_spender = w->state != ST_NONE && hash_eq(w->subject, sp.spender_txid);
  if (!same_spender) {
    r = check_spender(e, w, &sp);
    if (r != GZ_CHAIN_OK) return r;
  }
  bool had_spender = w->state != ST_NONE;
  bool was_confirmed = w->state == ST_CONFIRMED;
  if (!sp.confirmed) {
    if (w->state == ST_MEMPOOL && same_spender) return GZ_CHAIN_OK;
    set_none(w);
    w->state = ST_MEMPOOL;
    memcpy(w->subject, sp.spender_txid, GZ_HASH_LEN);
    w->vin = sp.spender_vin;
    watch_event(w, &ev, GZ_CHAINW_OUTPOINT_SPENT);
    ev.replaced = had_spender && !same_spender;
    ev.reorg = was_confirmed;
    emit(e, &ev);
    return GZ_CHAIN_OK;
  }
  bool same = was_confirmed && same_spender && w->height == sp.height && hash_eq(w->block, sp.block_hash);
  if (same) {
    r = still_placed(e, w);
    if (r != GZ_CHAIN_OK) return r;
  } else {
    r = confirm(e, sp.spender_txid, sp.height, sp.block_hash);
    if (r != GZ_CHAIN_OK) return r;
    memcpy(w->subject, sp.spender_txid, GZ_HASH_LEN);
    w->vin = sp.spender_vin;
    set_confirmed(w, sp.height, sp.block_hash);
    w->replaced = had_spender && !same_spender;
    w->undone = was_confirmed;
  }
  tell_count(e, w, count_of(e, w));
  return GZ_CHAIN_OK;
}

/* ---- broadcasts ---------------------------------------------------------- */

int gz_watch_broadcast(gz_watch *e, uint64_t id, uint8_t *parent, size_t parent_len, uint8_t *tx,
                       size_t len) {
  bjob job;
  memset(&job, 0, sizeof job);
  int rc = GZ_CHAINW_OK;
  if (e == NULL || tx == NULL || len > GZ_TX_MAX_BYTES || !gz_txid_from_raw(tx, len, job.txid)) {
    rc = GZ_CHAINW_INVALID;
  } else if (parent != NULL &&
             (parent_len > GZ_TX_MAX_BYTES || !gz_txid_from_raw(parent, parent_len, job.parent_txid))) {
    rc = GZ_CHAINW_INVALID;
  } else if (e->n_jobs == GZ_CHAINW_MAX_BROADCASTS) {
    rc = GZ_CHAINW_FULL;
  }
  if (rc != GZ_CHAINW_OK) {
    free(parent);
    free(tx);
    return rc;
  }
  job.used = true;
  job.id = id;
  job.parent = parent;
  job.parent_len = parent_len;
  job.tx = tx;
  job.len = len;
  job.next_at = 0; /* at the next pass */
  for (size_t i = 0; i < GZ_CHAINW_MAX_BROADCASTS; i++) {
    if (!e->jobs[i].used) {
      e->jobs[i] = job;
      break;
    }
  }
  e->n_jobs++;
  return GZ_CHAINW_OK;
}

static gz_chainw_outcome outcome_of(gz_chain_result r, bool already_known) {
  switch (r) {
    case GZ_CHAIN_OK: return already_known ? GZ_CHAINW_ALREADY_KNOWN : GZ_CHAINW_ACCEPTED;
    case GZ_CHAIN_REJECTED:
    case GZ_CHAIN_INVALID_ARG: return GZ_CHAINW_REJECTED;
    case GZ_CHAIN_UNSUPPORTED: return GZ_CHAINW_NO_PACKAGE_RELAY;
    default: return GZ_CHAINW_UNREACHABLE;
  }
}

static void copy_reason(char out[GZ_CHAINW_REASON_MAX], const char *in) {
  size_t n = strlen(in);
  if (n > GZ_CHAINW_REASON_MAX - 1) n = GZ_CHAINW_REASON_MAX - 1;
  memcpy(out, in, n);
  out[n] = '\0';
}

static void run_job(gz_watch *e, bjob *j, uint64_t now) {
  gz_chainw_event ev;
  gz_chainw_broadcast_info *b = &ev.broadcast;
  gz_chain_result r;
  event_init(&ev, GZ_CHAINW_BROADCAST);
  memcpy(ev.txid, j->txid, GZ_HASH_LEN);
  b->id = j->id;
  if (j->parent == NULL) {
    gz_broadcast_result br;
    r = gz_chain_broadcast(e->cfg.chain, j->tx, j->len, &br);
    b->outcome = outcome_of(r, br.already_known);
    b->server_status = br.server_status;
    copy_reason(b->reason, br.reason);
  } else {
    gz_package_result pr;
    r = gz_chain_broadcast_package(e->cfg.chain, j->parent, j->parent_len, j->tx, j->len, &pr);
    b->package = true;
    memcpy(b->parent_txid, j->parent_txid, GZ_HASH_LEN);
    b->outcome = outcome_of(r, false);
    b->parent_outcome = outcome_of(pr.parent.result, pr.parent.already_known);
    b->child_outcome = outcome_of(pr.child.result, pr.child.already_known);
    b->server_status = pr.server_status;
    const char *why = pr.reason[0] != '\0'          ? pr.reason
                      : pr.parent.reason[0] != '\0' ? pr.parent.reason
                                                    : pr.child.reason;
    if (r == GZ_CHAIN_UNSUPPORTED) why = "no chain server accepts transaction packages";
    copy_reason(b->reason, why);
  }
  if (stopped(e)) return; /* cut short: it is tried again, and told then */
  b->detail = r;
  j->attempts++;
  b->attempts = j->attempts;
  b->final = b->outcome != GZ_CHAINW_UNREACHABLE || j->attempts >= e->cfg.broadcast_attempts;
  const gz_multi_report *rep = gz_multi_last_report(e->cfg.chain);
  if (rep != NULL && rep->call == GZ_CALL_BROADCAST) {
    b->server_count = rep->server_count;
    for (size_t i = 0; i < rep->server_count && i < GZ_MULTI_MAX_SERVERS; i++) {
      b->servers[i].result = rep->answers[i].result;
      b->servers[i].already_known = rep->answers[i].u.broadcast.already_known;
    }
  }
  bool tell = b->final || (int)b->outcome != j->last;
  if (b->final) {
    job_free(e, j);
  } else {
    unsigned shift = j->attempts - 1 > 20 ? 20 : j->attempts - 1;
    uint64_t wait = (uint64_t)e->cfg.broadcast_backoff_ms << shift;
    if (wait > e->cfg.broadcast_backoff_max_ms) wait = e->cfg.broadcast_backoff_max_ms;
    j->next_at = now + wait;
    j->last = (int)b->outcome;
  }
  if (tell) emit(e, &ev);
}

/* ---- a pass -------------------------------------------------------------- */

static uint64_t retry_wait(const gz_watch *e) {
  unsigned shift = e->failures > 20 ? 20 : e->failures;
  uint64_t wait = (uint64_t)e->cfg.retry_ms << shift;
  return wait > e->cfg.retry_max_ms ? e->cfg.retry_max_ms : wait;
}

static void tell_sources(gz_watch *e, gz_chain_result r) {
  if (r == e->sources) return;
  gz_chainw_event ev;
  event_init(&ev, GZ_CHAINW_SOURCES);
  ev.sources = r;
  e->sources = r;
  emit(e, &ev);
}

/* A failure that says the servers cannot be asked now: the rest of a pass
 * would only wait out the same time limits again. */
static bool ends_pass(gz_chain_result r) {
  return r == GZ_CHAIN_UNREACHABLE || r == GZ_CHAIN_NO_QUORUM;
}

/* The hashes below the window are kept while a confirmation is being linked
 * to them, or still has to be linked again after a reorganisation. */
static bool needs_low(const gz_watch *e) {
  if (e->descending) return true;
  for (size_t i = 0; i < e->cfg.max_watches; i++) {
    const watch *w = &e->w[i];
    if (w->used && w->state == ST_CONFIRMED && !w->linked) return true;
  }
  return false;
}

static void between(gz_watch *e) {
  if (e->cfg.between != NULL) e->cfg.between(e->cfg.between_ctx);
}

/* Broadcasts that are due, at any point of a pass: they wait for nothing. */
static void run_due(gz_watch *e) {
  for (size_t i = 0; i < GZ_CHAINW_MAX_BROADCASTS; i++) {
    if (stopped(e)) return;
    uint64_t now = now_ms(e);
    if (e->jobs[i].used && now >= e->jobs[i].next_at) run_job(e, &e->jobs[i], now);
  }
}

gz_chain_result gz_watch_step(gz_watch *e) {
  uint64_t now = now_ms(e);
  gz_chain_result worst = GZ_CHAIN_OK;
  bool synced = false, asked = false, later = false, ended_early = false;

  /* releases that have come due */
  for (size_t i = 0; i < e->cfg.max_watches; i++) {
    watch *w = &e->w[i];
    if (w->used && w->held && w->release_set && now >= w->release_at) {
      w->held = false;
      w->fresh = true;
    }
  }

  /* broadcasts first, and again after every chain call below */
  run_due(e);
  if (stopped(e)) return GZ_CHAIN_OK;

  if (now < e->hold_until) return e->sources;

  if (e->hn == 0 || now >= e->next_sync) {
    gz_chain_result r = sync_headers(e);
    if (stopped(e)) return GZ_CHAIN_OK;
    asked = true;
    if (r == GZ_CHAIN_OK) {
      synced = true;
      e->next_sync = e->catching_up ? now : now + e->cfg.tip_poll_ms;
      if (!needs_low(e)) trim(e, e->cfg.header_window);
    } else {
      worst = r;
    }
    between(e);
    run_due(e);
    if (stopped(e)) return GZ_CHAIN_OK;
  }
  if (worst == GZ_CHAIN_OK && e->hn != 0) {
    if (e->tell_tip) emit_tip(e);
    bool was_descending = e->descending;
    size_t start = e->next_watch < e->cfg.max_watches ? e->next_watch : 0;
    e->descending = false;
    e->next_watch = 0;
    for (size_t k = 0; k < e->cfg.max_watches && !ended_early; k++) {
      size_t i = (start + k) % e->cfg.max_watches;
      watch *w = &e->w[i];
      if (!w->used || w->held) continue;
      /* asked: when new, when a reorganisation touched it, and at every look
       * at the tip while it is not confirmed. A confirmation that stands is
       * only counted, along the headers. */
      bool ask = w->fresh || w->recheck || (synced && w->state != ST_CONFIRMED);
      if (!ask && !(synced && w->state == ST_CONFIRMED && w->linked)) continue;
      bool was_fresh = w->fresh;
      gz_chain_result r = w->kind == KIND_TX ? poll_tx(e, w, ask) : poll_outpoint(e, w, ask);
      if (stopped(e)) return GZ_CHAIN_OK;
      if (ask) asked = true;
      if (r == GZ_CHAIN_OK) {
        if (was_fresh && e->cfg.report_synced) {
          /* its first answer since it was set: what it found was told above */
          gz_chainw_event ev;
          watch_event(w, &ev, GZ_CHAINW_SYNCED);
          ev.outpoint_watch = w->kind != KIND_TX;
          emit(e, &ev);
        }
        w->fresh = false;
        w->recheck = false;
      } else if (r == R_LATER) {
        later = true;
      } else if (worst == GZ_CHAIN_OK) {
        worst = r;
      }
      if (ends_pass(r)) {
        /* the servers cannot be asked: end the pass here, and start the next
         * one with the next watch, so that one watch they cannot answer does
         * not starve the others */
        e->next_watch = (i + 1) % e->cfg.max_watches;
        ended_early = true;
      }
      if (ask) {
        between(e);
        run_due(e);
        if (stopped(e)) return GZ_CHAIN_OK;
      }
    }
    if (ended_early && was_descending) e->descending = true;
    if (e->cfg.report_synced && synced && worst == GZ_CHAIN_OK && !ended_early && !later &&
        !e->tip_synced_told && !e->tell_tip) {
      /* every watch held has had its answer for this tip, told above */
      gz_chainw_event ev;
      event_init(&ev, GZ_CHAINW_TIP_SYNCED);
      ev.height = top_height(e);
      memcpy(ev.block_hash, hash_at(e, ev.height), GZ_HASH_LEN);
      e->tip_synced_told = true;
      emit(e, &ev);
    }
  }
  if (!asked) return e->sources;
  /* waits are counted from the end of the pass, which can be long */
  uint64_t end = now_ms(e);
  if (worst != GZ_CHAIN_OK) {
    /* lag clears by itself: ask again at the first wait, without growing it */
    uint64_t wait = worst == GZ_CHAIN_LAG ? e->cfg.retry_ms : retry_wait(e);
    if (worst != GZ_CHAIN_LAG) e->failures++;
    e->hold_until = end + wait;
    if (e->next_sync > e->hold_until || !synced) e->next_sync = e->hold_until;
  } else {
    e->failures = 0;
    if (later) {
      e->hold_until = end + SETTLE_MS;
      if (e->next_sync > e->hold_until) e->next_sync = e->hold_until;
    }
  }
  tell_sources(e, worst);
  return worst;
}

uint32_t gz_watch_wait_ms(gz_watch *e) {
  uint64_t now = now_ms(e);
  uint64_t at = e->next_sync;
  bool work = e->hn == 0 || e->tell_tip;
  for (size_t i = 0; i < e->cfg.max_watches; i++) {
    const watch *w = &e->w[i];
    if (!w->used) continue;
    if (w->held) {
      if (w->release_set && w->release_at < at) at = w->release_at;
    } else if (w->fresh || w->recheck) {
      work = true;
    }
  }
  if (work) at = 0;
  if (at < e->hold_until) at = e->hold_until;
  for (size_t i = 0; i < GZ_CHAINW_MAX_BROADCASTS; i++) {
    if (e->jobs[i].used && e->jobs[i].next_at < at) at = e->jobs[i].next_at;
  }
  if (at <= now) return 0;
  return at - now > WAIT_MAX_MS ? WAIT_MAX_MS : (uint32_t)(at - now);
}
