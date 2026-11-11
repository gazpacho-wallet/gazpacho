/*
 * The comparing backend. The agreement rules are stated in chain_multi.h and
 * argued in docs/notes/chain-port.md; this file implements exactly those.
 */
#include "gazpacho/chain_multi.h"

#include <stdlib.h>
#include <string.h>

typedef struct multi {
  gz_multi_config cfg;
  size_t n;
  gz_chain servers[GZ_MULTI_MAX_SERVERS];
  gz_chain_output *scratch; /* n * cfg.max_outputs entries */
  gz_multi_report report;
} multi;

static bool usable(gz_chain_result r) { return r == GZ_CHAIN_OK || r == GZ_CHAIN_NOT_FOUND; }

static void begin(multi *m, gz_chain_call call) {
  memset(&m->report, 0, sizeof m->report);
  m->report.call = call;
  m->report.server_count = m->n;
  m->report.verdict = GZ_CHAIN_NO_QUORUM;
}

static gz_chain_result finish(multi *m, gz_chain_result verdict) {
  m->report.verdict = verdict;
  return verdict;
}

/*
 * What to return when too few servers gave a usable reply. If every server
 * failed the same way, say how (all unreachable, all too large); otherwise
 * there is simply no quorum. Neither is an answer.
 */
static gz_chain_result no_quorum(const multi *m) {
  gz_chain_result first = m->report.answers[0].result;
  if (usable(first)) return GZ_CHAIN_NO_QUORUM;
  for (size_t i = 1; i < m->n; i++) {
    if (m->report.answers[i].result != first) return GZ_CHAIN_NO_QUORUM;
  }
  return first;
}

typedef bool (*same_fn)(const gz_multi_answer *a, const gz_multi_answer *b);

/*
 * The general rule: every usable reply must equal every other; at least a
 * quorum of them must exist. On success *which is the index of one server
 * holding the common answer and the result is OK or NOT_FOUND.
 */
static gz_chain_result compare_all(const multi *m, same_fn same, size_t *which) {
  size_t count = 0, first = 0;
  for (size_t i = 0; i < m->n; i++) {
    const gz_multi_answer *a = &m->report.answers[i];
    if (!usable(a->result)) continue;
    if (count == 0) {
      first = i;
    } else {
      const gz_multi_answer *f = &m->report.answers[first];
      if (a->result != f->result) return GZ_CHAIN_DISAGREE;
      if (a->result == GZ_CHAIN_OK && !same(f, a)) return GZ_CHAIN_DISAGREE;
    }
    count++;
  }
  if (count < m->cfg.quorum) return no_quorum(m);
  *which = first;
  return m->report.answers[first].result;
}

static bool hash_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, GZ_HASH_LEN) == 0; }

/* ---- tip ---------------------------------------------------------------- */

static gz_chain_result multi_tip(void *ctx, gz_chain_tip *out) {
  multi *m = ctx;
  gz_multi_answer *a = m->report.answers;
  size_t count = 0, lowest = 0;
  begin(m, GZ_CALL_TIP);
  for (size_t i = 0; i < m->n; i++) {
    a[i].result = gz_chain_tip_get(&m->servers[i], &a[i].u.tip);
    if (a[i].result != GZ_CHAIN_OK) continue;
    if (count == 0 || a[i].u.tip.height < a[lowest].u.tip.height) lowest = i;
    count++;
  }
  if (count < m->cfg.quorum) return finish(m, no_quorum(m));

  const gz_chain_tip *low = &a[lowest].u.tip;
  for (size_t i = 0; i < m->n; i++) {
    if (a[i].result != GZ_CHAIN_OK || i == lowest) continue;
    const gz_chain_tip *t = &a[i].u.tip;
    if (t->height == low->height) {
      if (!hash_eq(t->hash, low->hash)) return finish(m, GZ_CHAIN_DISAGREE);
      continue;
    }
    if (t->height - low->height > m->cfg.tip_slack) return finish(m, GZ_CHAIN_DISAGREE);
    /* This server is ahead by an allowed amount. It must have the lower
     * server's tip in its own chain. */
    uint8_t at_low[GZ_HASH_LEN];
    gz_chain_result r = gz_chain_block_hash(&m->servers[i], low->height, at_low);
    if (r == GZ_CHAIN_OK) {
      if (!hash_eq(at_low, low->hash)) return finish(m, GZ_CHAIN_DISAGREE);
    } else if (r == GZ_CHAIN_NOT_FOUND) {
      return finish(m, GZ_CHAIN_DISAGREE); /* ahead, yet no block at the lower height */
    } else {
      count--; /* could not be compared: counts as no reply */
    }
  }
  if (count < m->cfg.quorum) return finish(m, GZ_CHAIN_NO_QUORUM);
  *out = *low;
  return finish(m, GZ_CHAIN_OK);
}

/* ---- block hash and header ---------------------------------------------- */

static bool same_block_hash(const gz_multi_answer *a, const gz_multi_answer *b) {
  return hash_eq(a->u.block_hash, b->u.block_hash);
}

static gz_chain_result multi_block_hash(void *ctx, uint32_t height, uint8_t out[GZ_HASH_LEN]) {
  multi *m = ctx;
  size_t which = 0;
  begin(m, GZ_CALL_BLOCK_HASH);
  for (size_t i = 0; i < m->n; i++) {
    m->report.answers[i].result =
        gz_chain_block_hash(&m->servers[i], height, m->report.answers[i].u.block_hash);
  }
  gz_chain_result v = compare_all(m, same_block_hash, &which);
  if (v == GZ_CHAIN_OK) memcpy(out, m->report.answers[which].u.block_hash, GZ_HASH_LEN);
  return finish(m, v);
}

static bool same_header(const gz_multi_answer *a, const gz_multi_answer *b) {
  return memcmp(a->u.header, b->u.header, GZ_HEADER_LEN) == 0;
}

static gz_chain_result multi_block_header(void *ctx, uint32_t height, uint8_t out[GZ_HEADER_LEN]) {
  multi *m = ctx;
  size_t which = 0;
  begin(m, GZ_CALL_BLOCK_HEADER);
  for (size_t i = 0; i < m->n; i++) {
    m->report.answers[i].result =
        gz_chain_block_header(&m->servers[i], height, m->report.answers[i].u.header);
  }
  gz_chain_result v = compare_all(m, same_header, &which);
  if (v == GZ_CHAIN_OK) memcpy(out, m->report.answers[which].u.header, GZ_HEADER_LEN);
  return finish(m, v);
}

/* ---- transaction status -------------------------------------------------- */

static bool same_tx_status(const gz_multi_answer *a, const gz_multi_answer *b) {
  const gz_tx_status *x = &a->u.tx_status, *y = &b->u.tx_status;
  if (x->state != y->state) return false;
  if (x->state != GZ_TX_CONFIRMED) return true;
  return x->height == y->height && hash_eq(x->block_hash, y->block_hash);
}

static gz_chain_result multi_tx_status(void *ctx, const uint8_t txid[GZ_HASH_LEN],
                                       gz_tx_status *out) {
  multi *m = ctx;
  size_t which = 0;
  begin(m, GZ_CALL_TX_STATUS);
  for (size_t i = 0; i < m->n; i++) {
    m->report.answers[i].result =
        gz_chain_tx_status(&m->servers[i], txid, &m->report.answers[i].u.tx_status);
  }
  gz_chain_result v = compare_all(m, same_tx_status, &which);
  if (v == GZ_CHAIN_OK) {
    *out = m->report.answers[which].u.tx_status;
    /* count confirmations from the lowest tip any server reported */
    for (size_t i = 0; i < m->n; i++) {
      const gz_multi_answer *a = &m->report.answers[i];
      if (a->result == GZ_CHAIN_OK && a->u.tx_status.confirmations < out->confirmations) {
        out->confirmations = a->u.tx_status.confirmations;
        out->tip_height = a->u.tx_status.tip_height;
      }
    }
  }
  return finish(m, v);
}

/* ---- outputs paying a script --------------------------------------------- */

static bool output_eq(const gz_chain_output *x, const gz_chain_output *y) {
  return hash_eq(x->txid, y->txid) && x->vout == y->vout && x->value == y->value &&
         x->confirmed == y->confirmed && x->height == y->height &&
         hash_eq(x->block_hash, y->block_hash);
}

static int output_cmp(const void *a, const void *b) {
  const gz_chain_output *x = a, *y = b;
  int c = memcmp(x->txid, y->txid, GZ_HASH_LEN);
  if (c != 0) return c;
  if (x->vout != y->vout) return x->vout < y->vout ? -1 : 1;
  return 0;
}

static bool same_outputs(const gz_multi_answer *a, const gz_multi_answer *b) {
  if (a->u.outputs.count != b->u.outputs.count) return false;
  for (size_t i = 0; i < a->u.outputs.count; i++) {
    if (!output_eq(&a->u.outputs.items[i], &b->u.outputs.items[i])) return false;
  }
  return true;
}

static gz_chain_result multi_script_outputs(void *ctx, const uint8_t *script, size_t script_len,
                                            gz_chain_output *out, size_t cap, size_t *count) {
  multi *m = ctx;
  size_t which = 0;
  begin(m, GZ_CALL_SCRIPT_OUTPUTS);
  if (cap > m->cfg.max_outputs) cap = m->cfg.max_outputs;
  for (size_t i = 0; i < m->n; i++) {
    gz_chain_output *mine = m->scratch + i * m->cfg.max_outputs;
    size_t got = 0;
    gz_multi_answer *a = &m->report.answers[i];
    a->result = gz_chain_script_outputs(&m->servers[i], script, script_len, mine, cap, &got);
    if (a->result == GZ_CHAIN_OK && got > cap) a->result = GZ_CHAIN_MALFORMED;
    if (a->result != GZ_CHAIN_OK) got = 0;
    qsort(mine, got, sizeof *mine, output_cmp); /* do not rely on the backend's order */
    a->u.outputs.items = mine;
    a->u.outputs.count = got;
  }
  gz_chain_result v = compare_all(m, same_outputs, &which);
  if (v == GZ_CHAIN_OK) {
    const gz_multi_answer *a = &m->report.answers[which];
    if (a->u.outputs.count > 0) memcpy(out, a->u.outputs.items, a->u.outputs.count * sizeof *out);
    *count = a->u.outputs.count;
  }
  return finish(m, v);
}

/* ---- outspend ------------------------------------------------------------ */

static bool same_outspend(const gz_multi_answer *a, const gz_multi_answer *b) {
  const gz_outspend *x = &a->u.outspend, *y = &b->u.outspend;
  if (x->spent != y->spent) return false;
  if (!x->spent) return true;
  return hash_eq(x->spender_txid, y->spender_txid) && x->spender_vin == y->spender_vin &&
         x->confirmed == y->confirmed && x->height == y->height &&
         hash_eq(x->block_hash, y->block_hash);
}

static gz_chain_result multi_outspend(void *ctx, const uint8_t txid[GZ_HASH_LEN], uint32_t vout,
                                      gz_outspend *out) {
  multi *m = ctx;
  size_t which = 0;
  begin(m, GZ_CALL_OUTSPEND);
  for (size_t i = 0; i < m->n; i++) {
    m->report.answers[i].result =
        gz_chain_outspend(&m->servers[i], txid, vout, &m->report.answers[i].u.outspend);
  }
  gz_chain_result v = compare_all(m, same_outspend, &which);
  if (v == GZ_CHAIN_OK) *out = m->report.answers[which].u.outspend;
  return finish(m, v);
}

/* ---- raw transaction ----------------------------------------------------- */

static bool same_raw_tx(const gz_multi_answer *a, const gz_multi_answer *b) {
  return a->u.raw_tx.len == b->u.raw_tx.len && hash_eq(a->u.raw_tx.digest, b->u.raw_tx.digest);
}

static gz_chain_result multi_raw_tx(void *ctx, const uint8_t txid[GZ_HASH_LEN], uint8_t *buf,
                                    size_t cap, size_t *len) {
  multi *m = ctx;
  size_t which = 0, last_len = 0;
  begin(m, GZ_CALL_RAW_TX);
  /* Each server writes into the caller's buffer in turn; a digest of every
   * byte (witness included, which the txid does not cover) is kept for the
   * comparison. If all agree, whatever is left in the buffer is the answer. */
  for (size_t i = 0; i < m->n; i++) {
    gz_multi_answer *a = &m->report.answers[i];
    uint8_t check[GZ_HASH_LEN];
    size_t got = 0;
    a->result = gz_chain_raw_tx(&m->servers[i], txid, buf, cap, &got);
    if (a->result != GZ_CHAIN_OK) continue;
    if (got > cap || !gz_txid_from_raw(buf, got, check) || !hash_eq(check, txid)) {
      a->result = GZ_CHAIN_MALFORMED;
      continue;
    }
    a->u.raw_tx.len = got;
    gz_sha256d(buf, got, a->u.raw_tx.digest);
    last_len = got;
  }
  gz_chain_result v = compare_all(m, same_raw_tx, &which);
  if (v == GZ_CHAIN_OK) {
    /* A server that failed after the last good one may have left its own
     * bytes in the buffer. Make sure the buffer holds the agreed bytes. */
    const gz_multi_answer *a = &m->report.answers[which];
    uint8_t digest[GZ_HASH_LEN];
    gz_sha256d(buf, last_len <= cap ? last_len : 0, digest);
    if (last_len != a->u.raw_tx.len || !hash_eq(digest, a->u.raw_tx.digest)) {
      size_t got = 0;
      gz_chain_result r = gz_chain_raw_tx(&m->servers[which], txid, buf, cap, &got);
      if (r == GZ_CHAIN_OK && got <= cap) gz_sha256d(buf, got, digest);
      if (r != GZ_CHAIN_OK || got != a->u.raw_tx.len || !hash_eq(digest, a->u.raw_tx.digest))
        v = GZ_CHAIN_NO_QUORUM;
      last_len = got;
    }
  }
  if (v == GZ_CHAIN_OK) {
    *len = last_len;
  } else {
    memset(buf, 0, cap);
  }
  return finish(m, v);
}

/* ---- Merkle proof -------------------------------------------------------- */

static bool same_proof(const gz_multi_answer *a, const gz_multi_answer *b) {
  const gz_merkle_proof *x = &a->u.proof, *y = &b->u.proof;
  if (x->block_height != y->block_height || x->pos != y->pos || x->depth != y->depth) return false;
  if (x->depth > GZ_MERKLE_MAX_DEPTH) return false;
  return memcmp(x->nodes, y->nodes, (size_t)x->depth * GZ_HASH_LEN) == 0;
}

static gz_chain_result multi_merkle_proof(void *ctx, const uint8_t txid[GZ_HASH_LEN],
                                          gz_merkle_proof *out) {
  multi *m = ctx;
  size_t which = 0;
  begin(m, GZ_CALL_MERKLE_PROOF);
  for (size_t i = 0; i < m->n; i++) {
    m->report.answers[i].result =
        gz_chain_merkle_proof(&m->servers[i], txid, &m->report.answers[i].u.proof);
  }
  gz_chain_result v = compare_all(m, same_proof, &which);
  if (v == GZ_CHAIN_OK) *out = m->report.answers[which].u.proof;
  return finish(m, v);
}

/* ---- broadcast ----------------------------------------------------------- */

static gz_chain_result multi_broadcast(void *ctx, const uint8_t *raw, size_t len,
                                       gz_broadcast_result *out) {
  multi *m = ctx;
  uint8_t txid[GZ_HASH_LEN];
  size_t accepted = m->n, refused = m->n;
  begin(m, GZ_CALL_BROADCAST);
  memset(out, 0, sizeof *out);
  if (!gz_txid_from_raw(raw, len, txid)) return finish(m, GZ_CHAIN_INVALID_ARG);
  for (size_t i = 0; i < m->n; i++) {
    gz_multi_answer *a = &m->report.answers[i];
    a->result = gz_chain_broadcast(&m->servers[i], raw, len, &a->u.broadcast);
    if (a->result == GZ_CHAIN_OK && !hash_eq(a->u.broadcast.txid, txid)) {
      a->result = GZ_CHAIN_MALFORMED; /* accepted something else */
      a->u.broadcast.result = GZ_CHAIN_MALFORMED;
    }
    if (a->result == GZ_CHAIN_OK && accepted == m->n) accepted = i;
    if (a->result == GZ_CHAIN_REJECTED && refused == m->n) refused = i;
  }
  /* Accepted by any server is success: one honest relay is enough to reach
   * the network. Whether it then appears is a question for tx_status. */
  if (accepted != m->n) {
    *out = m->report.answers[accepted].u.broadcast;
  } else if (refused != m->n) {
    *out = m->report.answers[refused].u.broadcast;
  } else {
    *out = m->report.answers[0].u.broadcast;
    out->result = m->report.answers[0].result;
  }
  return finish(m, out->result);
}

/* ---- fee estimates ------------------------------------------------------- */

static const gz_fee_estimate *fee_find(const gz_fee_estimates *f, uint16_t target) {
  size_t n = f->count < GZ_FEE_MAX_TARGETS ? f->count : GZ_FEE_MAX_TARGETS;
  for (size_t i = 0; i < n; i++) {
    if (f->entries[i].target == target) return &f->entries[i];
  }
  return NULL;
}

static gz_chain_result multi_fee_estimates(void *ctx, gz_fee_estimates *out) {
  multi *m = ctx;
  gz_multi_answer *a = m->report.answers;
  size_t count = 0, first = 0;
  begin(m, GZ_CALL_FEE_ESTIMATES);
  for (size_t i = 0; i < m->n; i++) {
    a[i].result = gz_chain_fee_estimates(&m->servers[i], &a[i].u.fees);
    if (a[i].result != GZ_CHAIN_OK) continue;
    if (a[i].u.fees.count > GZ_FEE_MAX_TARGETS) a[i].result = GZ_CHAIN_MALFORMED;
    for (size_t k = 0; a[i].result == GZ_CHAIN_OK && k < a[i].u.fees.count; k++) {
      if (a[i].u.fees.entries[k].sat_per_kvb > m->cfg.fee_ceiling_sat_per_kvb)
        a[i].result = GZ_CHAIN_MALFORMED; /* absurd rate: discard the whole answer */
    }
    if (a[i].result != GZ_CHAIN_OK) continue;
    if (count == 0) first = i;
    count++;
  }
  if (count < m->cfg.quorum) return finish(m, no_quorum(m));

  /* For every target all answering servers list, the highest rate. */
  memset(out, 0, sizeof *out);
  const gz_fee_estimates *f = &a[first].u.fees;
  for (size_t k = 0; k < f->count; k++) {
    uint16_t target = f->entries[k].target;
    uint64_t rate = f->entries[k].sat_per_kvb;
    bool everywhere = true;
    for (size_t i = 0; i < m->n && everywhere; i++) {
      if (a[i].result != GZ_CHAIN_OK || i == first) continue;
      const gz_fee_estimate *e = fee_find(&a[i].u.fees, target);
      if (e == NULL) {
        everywhere = false;
      } else if (e->sat_per_kvb > rate) {
        rate = e->sat_per_kvb;
      }
    }
    if (!everywhere) continue;
    out->entries[out->count].target = target;
    out->entries[out->count].sat_per_kvb = rate;
    out->count++;
  }
  return finish(m, GZ_CHAIN_OK);
}

/* ---- creation ------------------------------------------------------------ */

static void multi_destroy(void *ctx) {
  multi *m = ctx;
  if (m == NULL) return;
  free(m->scratch);
  free(m);
}

static const gz_chain_ops multi_ops = {
    multi_tip,      multi_block_hash, multi_block_header, multi_tx_status, multi_script_outputs,
    multi_outspend, multi_raw_tx,     multi_merkle_proof, multi_broadcast, multi_fee_estimates,
    multi_destroy,
};

void gz_multi_config_default(gz_multi_config *cfg) {
  if (cfg == NULL) return;
  memset(cfg, 0, sizeof *cfg);
  cfg->quorum = 2;
  cfg->tip_slack = 1;
  cfg->max_outputs = 256;
  cfg->fee_ceiling_sat_per_kvb = 2000000; /* 2000 sat/vB */
}

gz_chain_result gz_multi_create(const gz_multi_config *cfg, const gz_chain *servers, size_t count,
                                gz_chain *out) {
  if (out != NULL) {
    out->ctx = NULL;
    out->ops = NULL;
  }
  if (cfg == NULL || servers == NULL || out == NULL) return GZ_CHAIN_INVALID_ARG;
  if (count < 1 || count > GZ_MULTI_MAX_SERVERS) return GZ_CHAIN_INVALID_ARG;
  if (cfg->quorum < 2 || cfg->quorum > GZ_MULTI_MAX_SERVERS || cfg->max_outputs == 0 ||
      cfg->max_outputs > 4096 || cfg->tip_slack > 6)
    return GZ_CHAIN_INVALID_ARG;
  for (size_t i = 0; i < count; i++) {
    if (servers[i].ctx == NULL || servers[i].ops == NULL) return GZ_CHAIN_INVALID_ARG;
  }
  multi *m = calloc(1, sizeof *m);
  if (m == NULL) return GZ_CHAIN_NO_MEMORY;
  m->scratch = calloc(count * cfg->max_outputs, sizeof *m->scratch);
  if (m->scratch == NULL) {
    free(m);
    return GZ_CHAIN_NO_MEMORY;
  }
  m->cfg = *cfg;
  m->n = count;
  memcpy(m->servers, servers, count * sizeof *servers);
  out->ctx = m;
  out->ops = &multi_ops;
  return GZ_CHAIN_OK;
}

const gz_multi_report *gz_multi_last_report(const gz_chain *c) {
  if (c == NULL || c->ops != &multi_ops || c->ctx == NULL) return NULL;
  return &((const multi *)c->ctx)->report;
}
