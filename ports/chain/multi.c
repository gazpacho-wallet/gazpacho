/*
 * The comparing backend. The rules are stated in chain_multi.h and argued in
 * docs/notes/chain-port.md; this file implements exactly those.
 */
#include "gazpacho/chain_multi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { NET_UNCHECKED = 0, NET_RIGHT = 1, NET_WRONG = 2 };

typedef struct multi {
  gz_multi_config cfg;
  size_t n;
  gz_chain servers[GZ_MULTI_MAX_SERVERS];
  size_t op[GZ_MULTI_MAX_SERVERS]; /* operator number of each server */
  size_t n_ops;
  char op_name[GZ_MULTI_MAX_SERVERS][GZ_OPERATOR_MAX];
  int net[GZ_MULTI_MAX_SERVERS];
  gz_chain_output *scratch; /* n * cfg.max_outputs entries */
  gz_multi_report report;
  /* the period of lag now running, if any: since when it has been seen */
  bool lag_running;
  uint64_t lag_since_ms;
} multi;

static bool usable(gz_chain_result r) { return r == GZ_CHAIN_OK || r == GZ_CHAIN_NOT_FOUND; }
static bool hash_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, GZ_HASH_LEN) == 0; }

static void begin(multi *m, gz_chain_call call) {
  memset(&m->report, 0, sizeof m->report);
  m->report.call = call;
  m->report.server_count = m->n;
  m->report.operator_count = m->n_ops;
  m->report.verdict = GZ_CHAIN_NO_QUORUM;
  memcpy(m->report.operators, m->op_name, sizeof m->report.operators);
}

static gz_chain_result finish(multi *m, gz_chain_result verdict) {
  m->report.verdict = verdict;
  return verdict;
}

/*
 * A server takes part only once its block 0 is the configured network's
 * genesis block. The check is made on first use and remembered when it gives
 * a definite result. Returns true if server i may be asked; otherwise stores
 * why not in its answer.
 */
static bool ready(multi *m, size_t i) {
  if (m->net[i] == NET_RIGHT) return true;
  if (m->net[i] == NET_UNCHECKED) {
    gz_chain_result r = gz_chain_check_network(&m->servers[i], m->cfg.network);
    if (r == GZ_CHAIN_OK) {
      m->net[i] = NET_RIGHT;
      return true;
    }
    if (r == GZ_CHAIN_WRONG_NETWORK) {
      m->net[i] = NET_WRONG;
    } else {
      m->report.answers[i].result = r; /* could not be asked: try again next call */
      return false;
    }
  }
  m->report.answers[i].result = GZ_CHAIN_WRONG_NETWORK;
  return false;
}

/* Number of distinct operators among the servers marked in `in`. */
static size_t operators_among(const multi *m, const bool *in) {
  bool seen[GZ_MULTI_MAX_SERVERS] = {false};
  size_t count = 0;
  for (size_t i = 0; i < m->n; i++) {
    if (in[i] && !seen[m->op[i]]) {
      seen[m->op[i]] = true;
      count++;
    }
  }
  return count;
}

/*
 * What to return when too few operators gave a usable reply. If every server
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

/* ---- lag ------------------------------------------------------------------
 * A difference is lag only if it has the shape of servers behind one another
 * (chain_multi.h, "Verdicts"), within GZ_MULTI_LAG_MAX_BLOCKS and
 * GZ_MULTI_LAG_MAX_MS. Everything else is disagreement. */

/* Every server was seen at one height: nobody is behind, any lag is over. */
static void lag_over(multi *m) { m->lag_running = false; }

/* Lag of the right shape has been seen now. True while the period it
 * belongs to is not older than GZ_MULTI_LAG_MAX_MS. */
static bool lag_still_allowed(multi *m) {
  uint64_t now = m->cfg.now_ms(m->cfg.clock_ctx);
  if (!m->lag_running) {
    m->lag_running = true;
    m->lag_since_ms = now;
  }
  /* a clock that went backwards gives a huge difference: disagreement */
  return now - m->lag_since_ms <= GZ_MULTI_LAG_MAX_MS;
}

/*
 * Reads the tip of every server marked in `in` into tips[]. True only if
 * they differ, by no more than tip_slack, and lie on one chain (every higher
 * server has the lowest tip at that height). Costs a few requests; called
 * only after a mismatch.
 */
static bool tips_show_lag(multi *m, const bool *in, gz_chain_tip *tips) {
  size_t low = m->n;
  uint32_t high = 0;
  for (size_t i = 0; i < m->n; i++) {
    if (!in[i]) continue;
    if (gz_chain_tip_get(&m->servers[i], &tips[i]) != GZ_CHAIN_OK) return false;
    if (low == m->n || tips[i].height < tips[low].height) low = i;
    if (tips[i].height > high) high = tips[i].height;
  }
  if (low == m->n) return false;
  if (high == tips[low].height) { /* nobody is behind */
    lag_over(m);
    return false;
  }
  if (high - tips[low].height > m->cfg.tip_slack) return false;
  for (size_t i = 0; i < m->n; i++) {
    uint8_t at_low[GZ_HASH_LEN];
    if (!in[i] || i == low) continue;
    if (tips[i].height == tips[low].height) {
      if (!hash_eq(tips[i].hash, tips[low].hash)) return false;
    } else if (gz_chain_block_hash(&m->servers[i], tips[low].height, at_low) != GZ_CHAIN_OK ||
               !hash_eq(at_low, tips[low].hash)) {
      return false;
    }
  }
  return true;
}

/*
 * One disputed item at `height`: the servers marked in `has` hold it, the
 * others marked in `in` do not. Lag only if it lies above the tip of every
 * server lacking it and not above the tip of any server holding it. A
 * height of 0 means the item has none (an unconfirmed transaction): never
 * lag.
 */
static bool lagging(multi *m, const bool *in, const bool *has, uint32_t height) {
  gz_chain_tip tips[GZ_MULTI_MAX_SERVERS];
  if (height == 0 || !tips_show_lag(m, in, tips)) return false;
  for (size_t i = 0; i < m->n; i++) {
    if (!in[i]) continue;
    if (has[i] ? tips[i].height < height : tips[i].height >= height) return false;
  }
  return lag_still_allowed(m);
}

typedef bool (*same_fn)(const gz_multi_answer *a, const gz_multi_answer *b);
/* The height of the item an answer is about; NULL: the height asked for. */
typedef uint32_t (*height_fn)(const gz_multi_answer *a);

/*
 * The general rule for calls whose answer is one confirmed fact: every
 * usable reply must equal every other, and they must come from a quorum of
 * operators. `height` is the height of the item asked about, or 0 if it
 * must be read from the answer with `height_of`. On success *which is the
 * index of one server holding the common answer and the result is OK or
 * NOT_FOUND.
 */
static gz_chain_result compare_all(multi *m, same_fn same, uint32_t height, height_fn height_of,
                                   size_t *which) {
  bool in[GZ_MULTI_MAX_SERVERS] = {false}, has[GZ_MULTI_MAX_SERVERS] = {false};
  size_t first_ok = m->n, first_missing = m->n;
  for (size_t i = 0; i < m->n; i++) {
    const gz_multi_answer *a = &m->report.answers[i];
    if (!usable(a->result)) continue;
    in[i] = true;
    if (a->result == GZ_CHAIN_NOT_FOUND) {
      if (first_missing == m->n) first_missing = i;
      continue;
    }
    has[i] = true;
    if (first_ok == m->n) {
      first_ok = i;
    } else if (!same(&m->report.answers[first_ok], a)) {
      return GZ_CHAIN_DISAGREE; /* two different positive answers */
    }
  }
  if (first_ok != m->n && first_missing != m->n) {
    /* one has it, another does not: a block or transaction still on its way
     * to one of them, or a server hiding it */
    if (height_of != NULL) height = height_of(&m->report.answers[first_ok]);
    return lagging(m, in, has, height) ? GZ_CHAIN_LAG : GZ_CHAIN_DISAGREE;
  }
  if (operators_among(m, in) < m->cfg.quorum) return no_quorum(m);
  *which = first_ok != m->n ? first_ok : first_missing;
  return m->report.answers[*which].result;
}

/* ---- tip ---------------------------------------------------------------- */

static gz_chain_result multi_tip(void *ctx, gz_chain_tip *out) {
  multi *m = ctx;
  gz_multi_answer *a = m->report.answers;
  bool in[GZ_MULTI_MAX_SERVERS] = {false};
  size_t lowest = m->n;
  begin(m, GZ_CALL_TIP);
  for (size_t i = 0; i < m->n; i++) {
    if (!ready(m, i)) continue;
    a[i].result = gz_chain_tip_get(&m->servers[i], &a[i].u.tip);
    if (a[i].result != GZ_CHAIN_OK) continue;
    in[i] = true;
    if (lowest == m->n || a[i].u.tip.height < a[lowest].u.tip.height) lowest = i;
  }
  if (operators_among(m, in) < m->cfg.quorum) return finish(m, no_quorum(m));

  const gz_chain_tip *low = &a[lowest].u.tip;
  bool all_level = true;
  for (size_t i = 0; i < m->n; i++) {
    if (!in[i] || i == lowest) continue;
    const gz_chain_tip *t = &a[i].u.tip;
    if (t->height == low->height) {
      if (!hash_eq(t->hash, low->hash)) return finish(m, GZ_CHAIN_DISAGREE);
      continue;
    }
    all_level = false;
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
      in[i] = false; /* could not be compared: counts as no reply */
    }
  }
  if (operators_among(m, in) < m->cfg.quorum) return finish(m, GZ_CHAIN_NO_QUORUM);
  if (all_level) lag_over(m); /* every server at one tip: nobody is behind */
  *out = *low;
  return finish(m, GZ_CHAIN_OK);
}

/* ---- block hash, header, summary ----------------------------------------- */

static bool same_block_hash(const gz_multi_answer *a, const gz_multi_answer *b) {
  return hash_eq(a->u.block_hash, b->u.block_hash);
}

static gz_chain_result multi_block_hash(void *ctx, uint32_t height, uint8_t out[GZ_HASH_LEN]) {
  multi *m = ctx;
  size_t which = 0;
  begin(m, GZ_CALL_BLOCK_HASH);
  for (size_t i = 0; i < m->n; i++) {
    if (!ready(m, i)) continue;
    m->report.answers[i].result =
        gz_chain_block_hash(&m->servers[i], height, m->report.answers[i].u.block_hash);
  }
  gz_chain_result v = compare_all(m, same_block_hash, height, NULL, &which);
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
    if (!ready(m, i)) continue;
    m->report.answers[i].result =
        gz_chain_block_header(&m->servers[i], height, m->report.answers[i].u.header);
  }
  gz_chain_result v = compare_all(m, same_header, height, NULL, &which);
  if (v == GZ_CHAIN_OK) memcpy(out, m->report.answers[which].u.header, GZ_HEADER_LEN);
  return finish(m, v);
}

static bool same_summary(const gz_multi_answer *a, const gz_multi_answer *b) {
  const gz_block_summary *x = &a->u.summary, *y = &b->u.summary;
  return hash_eq(x->hash, y->hash) && x->tx_count == y->tx_count &&
         hash_eq(x->coinbase_txid, y->coinbase_txid);
}

static gz_chain_result multi_block_summary(void *ctx, uint32_t height, gz_block_summary *out) {
  multi *m = ctx;
  size_t which = 0;
  begin(m, GZ_CALL_BLOCK_SUMMARY);
  for (size_t i = 0; i < m->n; i++) {
    if (!ready(m, i)) continue;
    m->report.answers[i].result =
        gz_chain_block_summary(&m->servers[i], height, &m->report.answers[i].u.summary);
  }
  gz_chain_result v = compare_all(m, same_summary, height, NULL, &which);
  if (v == GZ_CHAIN_OK) *out = m->report.answers[which].u.summary;
  return finish(m, v);
}

/* ---- transaction status -------------------------------------------------- */

static bool same_confirmation(const gz_tx_status *x, const gz_tx_status *y) {
  return x->height == y->height && hash_eq(x->block_hash, y->block_hash);
}

static gz_chain_result multi_tx_status(void *ctx, const uint8_t txid[GZ_HASH_LEN],
                                       gz_tx_status *out) {
  multi *m = ctx;
  gz_multi_answer *a = m->report.answers;
  bool in[GZ_MULTI_MAX_SERVERS] = {false};
  size_t n_ok = 0, n_confirmed = 0, n_mempool = 0, first_confirmed = m->n;
  bool conflict = false;
  begin(m, GZ_CALL_TX_STATUS);
  for (size_t i = 0; i < m->n; i++) {
    if (!ready(m, i)) continue;
    a[i].result = gz_chain_tx_status(&m->servers[i], txid, &a[i].u.tx_status);
    if (a[i].result != GZ_CHAIN_OK) continue;
    in[i] = true;
    n_ok++;
    if (a[i].u.tx_status.state == GZ_TX_CONFIRMED) {
      n_confirmed++;
      if (first_confirmed == m->n) {
        first_confirmed = i;
      } else if (!same_confirmation(&a[first_confirmed].u.tx_status, &a[i].u.tx_status)) {
        conflict = true; /* confirmed in two different places */
      }
    } else if (a[i].u.tx_status.state == GZ_TX_MEMPOOL) {
      n_mempool++;
    }
  }
  if (conflict) return finish(m, GZ_CHAIN_DISAGREE);
  if (operators_among(m, in) < m->cfg.quorum) return finish(m, no_quorum(m));

  if (n_confirmed == 0) {
    /* nothing confirmed anywhere: that much is agreed */
    memset(out, 0, sizeof *out);
    if (n_mempool == n_ok) {
      out->state = GZ_TX_MEMPOOL;
    } else {
      out->state = GZ_TX_UNKNOWN;
      if (n_mempool != 0) {
        out->unconfirmed_differs = true;
        m->report.unconfirmed_differs = true;
      }
    }
    return finish(m, GZ_CHAIN_OK);
  }
  if (n_confirmed != n_ok) {
    /* confirmed on some, not on others: lag only if the block it is in is
     * above the tip of every server that does not have it confirmed */
    bool has[GZ_MULTI_MAX_SERVERS] = {false};
    for (size_t i = 0; i < m->n; i++)
      has[i] = in[i] && a[i].u.tx_status.state == GZ_TX_CONFIRMED;
    uint32_t height = a[first_confirmed].u.tx_status.height;
    return finish(m, lagging(m, in, has, height) ? GZ_CHAIN_LAG : GZ_CHAIN_DISAGREE);
  }
  *out = a[first_confirmed].u.tx_status;
  /* the claimed count from the lowest tip any server reported */
  for (size_t i = 0; i < m->n; i++) {
    if (in[i] && a[i].u.tx_status.claimed_confirmations < out->claimed_confirmations) {
      out->claimed_confirmations = a[i].u.tx_status.claimed_confirmations;
      out->tip_height = a[i].u.tx_status.tip_height;
    }
  }
  return finish(m, GZ_CHAIN_OK);
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

/* True if the confirmed entries of two sorted lists are the same, in full. */
static bool same_confirmed_outputs(const gz_chain_output *x, size_t nx, const gz_chain_output *y,
                                   size_t ny) {
  size_t i = 0, j = 0;
  for (;;) {
    while (i < nx && !x[i].confirmed) i++;
    while (j < ny && !y[j].confirmed) j++;
    if (i == nx || j == ny) return i == nx && j == ny;
    if (!output_eq(&x[i], &y[j])) return false;
    i++;
    j++;
  }
}

static bool list_has(const gz_chain_output *list, size_t n, const gz_chain_output *want) {
  for (size_t i = 0; i < n; i++) {
    if (output_eq(&list[i], want)) return true;
  }
  return false;
}

/* The entry for the same outpoint as `o`, whatever its details, or NULL. */
static const gz_chain_output *list_find_outpoint(const gz_chain_output *list, size_t n,
                                                 const gz_chain_output *o) {
  for (size_t i = 0; i < n; i++) {
    if (output_cmp(&list[i], o) == 0) return &list[i];
  }
  return NULL;
}

/*
 * Lag for output lists: every confirmed output that one server lists and
 * another does not list as confirmed must be explained by the other being
 * behind or ahead. Either it is new (confirmed above the tip of the server
 * lacking it), or it is gone (the server lacking it shows it spent, by a
 * confirmed transaction in a block above the tip of the server listing it).
 * The same outpoint listed confirmed by both with different details is a
 * contradiction, never lag.
 */
static bool outputs_lagging(multi *m, const bool *in) {
  gz_chain_tip tips[GZ_MULTI_MAX_SERVERS];
  const gz_multi_answer *a = m->report.answers;
  if (!tips_show_lag(m, in, tips)) return false;
  for (size_t i = 0; i < m->n; i++) {
    if (!in[i]) continue;
    for (size_t k = 0; k < a[i].u.outputs.count; k++) {
      const gz_chain_output *o = &a[i].u.outputs.items[k];
      if (!o->confirmed) continue;
      for (size_t j = 0; j < m->n; j++) {
        if (!in[j] || j == i) continue;
        const gz_chain_output *p = list_find_outpoint(a[j].u.outputs.items, a[j].u.outputs.count, o);
        if (p != NULL && p->confirmed) {
          if (!output_eq(p, o)) return false;
          continue;
        }
        if (o->height > tips[j].height && o->height <= tips[i].height) continue; /* new */
        gz_outspend sp;
        if (gz_chain_outspend(&m->servers[j], o->txid, o->vout, &sp) != GZ_CHAIN_OK) return false;
        if (sp.spent && sp.confirmed && sp.height > tips[i].height && sp.height <= tips[j].height)
          continue; /* spent in a block the lister has not seen yet */
        return false;
      }
    }
  }
  return lag_still_allowed(m);
}

static gz_chain_result multi_script_outputs(void *ctx, const uint8_t *script, size_t script_len,
                                            gz_chain_output *out, size_t cap, size_t *count,
                                            bool *unconfirmed_differs) {
  multi *m = ctx;
  gz_multi_answer *a = m->report.answers;
  bool in[GZ_MULTI_MAX_SERVERS] = {false};
  size_t first = m->n;
  begin(m, GZ_CALL_SCRIPT_OUTPUTS);
  if (cap > m->cfg.max_outputs) cap = m->cfg.max_outputs;
  for (size_t i = 0; i < m->n; i++) {
    gz_chain_output *mine = m->scratch + i * m->cfg.max_outputs;
    size_t got = 0;
    a[i].u.outputs.items = mine;
    if (!ready(m, i)) continue;
    a[i].result = gz_chain_script_outputs(&m->servers[i], script, script_len, mine, cap, &got, NULL);
    if (a[i].result == GZ_CHAIN_OK && got > cap) a[i].result = GZ_CHAIN_MALFORMED;
    if (a[i].result != GZ_CHAIN_OK) continue;
    qsort(mine, got, sizeof *mine, output_cmp); /* do not rely on the backend's order */
    for (size_t k = 1; k < got && a[i].result == GZ_CHAIN_OK; k++) {
      if (output_cmp(&mine[k - 1], &mine[k]) == 0) a[i].result = GZ_CHAIN_MALFORMED; /* listed twice */
    }
    if (a[i].result != GZ_CHAIN_OK) continue;
    a[i].u.outputs.count = got;
    in[i] = true;
    if (first == m->n) first = i;
  }
  if (operators_among(m, in) < m->cfg.quorum) return finish(m, no_quorum(m));

  /* the confirmed outputs must be the same everywhere */
  for (size_t i = 0; i < m->n; i++) {
    if (!in[i] || i == first) continue;
    if (!same_confirmed_outputs(a[first].u.outputs.items, a[first].u.outputs.count,
                                a[i].u.outputs.items, a[i].u.outputs.count))
      return finish(m, outputs_lagging(m, in) ? GZ_CHAIN_LAG : GZ_CHAIN_DISAGREE);
  }
  /* answer: the confirmed outputs, plus the unconfirmed ones all servers list */
  size_t kept = 0;
  for (size_t k = 0; k < a[first].u.outputs.count; k++) {
    const gz_chain_output *o = &a[first].u.outputs.items[k];
    bool everywhere = true;
    if (!o->confirmed) {
      for (size_t i = 0; i < m->n && everywhere; i++) {
        if (in[i] && i != first && !list_has(a[i].u.outputs.items, a[i].u.outputs.count, o))
          everywhere = false;
      }
    }
    if (everywhere) out[kept++] = *o;
  }
  /* The answer is part of every server's list (the confirmed outputs are
   * the same everywhere; an unconfirmed one is kept only if all list it),
   * and no list names an outpoint twice. So a server's list is exactly the
   * answer if and only if it is as long: anything else differs. */
  bool differs = false;
  for (size_t i = 0; i < m->n; i++) {
    if (in[i] && a[i].u.outputs.count != kept) differs = true;
  }
  *count = kept;
  *unconfirmed_differs = differs;
  m->report.unconfirmed_differs = differs;
  return finish(m, GZ_CHAIN_OK);
}

/* ---- outspend ------------------------------------------------------------ */

static bool same_spender(const gz_outspend *x, const gz_outspend *y) {
  return hash_eq(x->spender_txid, y->spender_txid) && x->spender_vin == y->spender_vin;
}

static bool same_confirmed_spend(const gz_outspend *x, const gz_outspend *y) {
  return same_spender(x, y) && x->height == y->height && hash_eq(x->block_hash, y->block_hash);
}

static gz_chain_result multi_outspend(void *ctx, const uint8_t txid[GZ_HASH_LEN], uint32_t vout,
                                      gz_outspend *out) {
  multi *m = ctx;
  gz_multi_answer *a = m->report.answers;
  bool in[GZ_MULTI_MAX_SERVERS] = {false};
  size_t n_ok = 0, n_confirmed = 0, n_pending = 0;
  size_t first_confirmed = m->n, first_pending = m->n;
  bool pending_same = true, conflict = false;
  begin(m, GZ_CALL_OUTSPEND);
  for (size_t i = 0; i < m->n; i++) {
    if (!ready(m, i)) continue;
    a[i].result = gz_chain_outspend(&m->servers[i], txid, vout, &a[i].u.outspend);
    if (a[i].result != GZ_CHAIN_OK) continue;
    const gz_outspend *o = &a[i].u.outspend;
    in[i] = true;
    n_ok++;
    if (o->spent && o->confirmed) {
      n_confirmed++;
      if (first_confirmed == m->n) {
        first_confirmed = i;
      } else if (!same_confirmed_spend(&a[first_confirmed].u.outspend, o)) {
        conflict = true; /* two different confirmed spends */
      }
    } else if (o->spent) {
      n_pending++;
      if (first_pending == m->n) {
        first_pending = i;
      } else if (!same_spender(&a[first_pending].u.outspend, o)) {
        pending_same = false;
      }
    }
  }
  if (conflict) return finish(m, GZ_CHAIN_DISAGREE);
  if (operators_among(m, in) < m->cfg.quorum) return finish(m, no_quorum(m));

  if (n_confirmed == 0) {
    /* no confirmed spend anywhere: that much is agreed */
    memset(out, 0, sizeof *out);
    if (n_pending == n_ok && pending_same) {
      *out = a[first_pending].u.outspend; /* all see the same unconfirmed spend */
    } else if (n_pending != 0) {
      out->unconfirmed_differs = true;
      m->report.unconfirmed_differs = true;
    }
    return finish(m, GZ_CHAIN_OK);
  }
  if (n_confirmed != n_ok) {
    /* a confirmed spend on some servers only: lag only if it is in a block
     * above the tip of every server that does not report it */
    bool has[GZ_MULTI_MAX_SERVERS] = {false};
    for (size_t i = 0; i < m->n; i++)
      has[i] = in[i] && a[i].u.outspend.spent && a[i].u.outspend.confirmed;
    uint32_t height = a[first_confirmed].u.outspend.height;
    return finish(m, lagging(m, in, has, height) ? GZ_CHAIN_LAG : GZ_CHAIN_DISAGREE);
  }
  *out = a[first_confirmed].u.outspend;
  return finish(m, GZ_CHAIN_OK);
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
   * comparison. */
  for (size_t i = 0; i < m->n; i++) {
    gz_multi_answer *a = &m->report.answers[i];
    uint8_t check[GZ_HASH_LEN];
    size_t got = 0;
    if (!ready(m, i)) continue;
    a->result = gz_chain_raw_tx(&m->servers[i], txid, buf, cap, &got);
    if (a->result != GZ_CHAIN_OK) continue;
    /* do not take the backend's word that the bytes are this transaction */
    if (got > cap || !gz_txid_from_raw(buf, got, check) || !hash_eq(check, txid)) {
      a->result = GZ_CHAIN_MALFORMED;
      continue;
    }
    a->u.raw_tx.len = got;
    gz_sha256d(buf, got, a->u.raw_tx.digest);
    last_len = got;
  }
  /* a transaction has no height to judge lag by: one lacking it disagrees */
  gz_chain_result v = compare_all(m, same_raw_tx, 0, NULL, &which);
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
  if (x->block_height != y->block_height) return false;
  if (x->pos != y->pos) return false;
  if (x->depth != y->depth || x->depth > GZ_MERKLE_MAX_DEPTH) return false;
  return memcmp(x->nodes, y->nodes, (size_t)x->depth * GZ_HASH_LEN) == 0;
}

static uint32_t proof_height(const gz_multi_answer *a) { return a->u.proof.block_height; }

static gz_chain_result multi_merkle_proof(void *ctx, const uint8_t txid[GZ_HASH_LEN],
                                          gz_merkle_proof *out) {
  multi *m = ctx;
  size_t which = 0;
  begin(m, GZ_CALL_MERKLE_PROOF);
  for (size_t i = 0; i < m->n; i++) {
    if (!ready(m, i)) continue;
    m->report.answers[i].result =
        gz_chain_merkle_proof(&m->servers[i], txid, &m->report.answers[i].u.proof);
  }
  gz_chain_result v = compare_all(m, same_proof, 0, proof_height, &which);
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
    /* a server on another chain is never sent the transaction */
    if (!ready(m, i)) {
      a->u.broadcast.result = a->result;
      continue;
    }
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

/* What a server's answer says for `target`: its estimate for the highest
 * target it lists that is not above `target` (the target itself or a
 * faster one), or NULL if it lists none. */
static const gz_fee_estimate *fee_for(const gz_fee_estimates *f, uint16_t target) {
  const gz_fee_estimate *best = NULL;
  for (size_t i = 0; i < f->count; i++) {
    const gz_fee_estimate *e = &f->entries[i];
    if (e->target <= target && (best == NULL || e->target > best->target)) best = e;
  }
  return best;
}

static int target_cmp(const void *a, const void *b) {
  uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
  return x < y ? -1 : x > y;
}

static gz_chain_result multi_fee_estimates(void *ctx, gz_fee_estimates *out) {
  multi *m = ctx;
  gz_multi_answer *a = m->report.answers;
  bool in[GZ_MULTI_MAX_SERVERS] = {false};
  uint16_t targets[GZ_MULTI_MAX_SERVERS * GZ_FEE_MAX_TARGETS];
  size_t n_targets = 0;
  begin(m, GZ_CALL_FEE_ESTIMATES);
  for (size_t i = 0; i < m->n; i++) {
    if (!ready(m, i)) continue;
    a[i].result = gz_chain_fee_estimates(&m->servers[i], &a[i].u.fees);
    if (a[i].result != GZ_CHAIN_OK) continue;
    if (a[i].u.fees.count > GZ_FEE_MAX_TARGETS) a[i].result = GZ_CHAIN_MALFORMED;
    for (size_t k = 0; a[i].result == GZ_CHAIN_OK && k < a[i].u.fees.count; k++) {
      if (a[i].u.fees.entries[k].sat_per_kvb > GZ_FEE_MAX_SAT_PER_KVB)
        a[i].result = GZ_CHAIN_MALFORMED; /* beyond what any backend may report */
    }
    if (a[i].result != GZ_CHAIN_OK) continue;
    in[i] = true;
    for (size_t k = 0; k < a[i].u.fees.count; k++) targets[n_targets++] = a[i].u.fees.entries[k].target;
  }
  if (operators_among(m, in) < m->cfg.quorum) return finish(m, no_quorum(m));

  /* Every target any answering server lists, lowest first. For each, only
   * the servers that answer for it count (fee_for): fewer than a quorum of
   * operators and it is left out; otherwise the lowest rate, cut at the
   * ceiling. Servers too far apart on any target: no combined answer. */
  qsort(targets, n_targets, sizeof targets[0], target_cmp);
  gz_fee_estimates combined;
  memset(&combined, 0, sizeof combined);
  for (size_t t = 0; t < n_targets && combined.count < GZ_FEE_MAX_TARGETS; t++) {
    if (t > 0 && targets[t] == targets[t - 1]) continue;
    bool answered[GZ_MULTI_MAX_SERVERS] = {false};
    uint64_t lowest = UINT64_MAX, highest = 0;
    for (size_t i = 0; i < m->n; i++) {
      const gz_fee_estimate *e = in[i] ? fee_for(&a[i].u.fees, targets[t]) : NULL;
      if (e == NULL) continue;
      answered[i] = true;
      if (e->sat_per_kvb < lowest) lowest = e->sat_per_kvb;
      if (e->sat_per_kvb > highest) highest = e->sat_per_kvb;
    }
    if (operators_among(m, answered) < m->cfg.quorum) continue;
    /* rates are at most 5,000,000 and the factor at most 100: no overflow */
    if (highest > lowest * m->cfg.fee_disagree_factor + m->cfg.fee_disagree_slack_sat_per_kvb)
      return finish(m, GZ_CHAIN_DISAGREE);
    if (lowest > m->cfg.fee_ceiling_sat_per_kvb) lowest = m->cfg.fee_ceiling_sat_per_kvb;
    combined.entries[combined.count].target = targets[t];
    combined.entries[combined.count].sat_per_kvb = lowest;
    combined.count++;
  }
  *out = combined;
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
    .tip = multi_tip,
    .block_hash = multi_block_hash,
    .block_header = multi_block_header,
    .block_summary = multi_block_summary,
    .tx_status = multi_tx_status,
    .script_outputs = multi_script_outputs,
    .outspend = multi_outspend,
    .raw_tx = multi_raw_tx,
    .merkle_proof = multi_merkle_proof,
    .broadcast = multi_broadcast,
    .fee_estimates = multi_fee_estimates,
    .describe = NULL,
    .destroy = multi_destroy,
};

void gz_multi_config_default(gz_multi_config *cfg, gz_network network) {
  if (cfg == NULL) return;
  memset(cfg, 0, sizeof *cfg);
  cfg->network = network;
  cfg->quorum = 2;
  cfg->tip_slack = GZ_MULTI_LAG_MAX_BLOCKS;
  cfg->max_outputs = 256;
  cfg->fee_ceiling_sat_per_kvb = 200000; /* 200 sat/vB */
  cfg->fee_disagree_factor = 3;
  cfg->fee_disagree_slack_sat_per_kvb = 1000; /* 1 sat/vB */
}

gz_chain_result gz_multi_create(const gz_multi_config *cfg, const gz_chain *servers, size_t count,
                                gz_chain *out) {
  gz_chain_info info[GZ_MULTI_MAX_SERVERS];
  bool described[GZ_MULTI_MAX_SERVERS];
  if (out != NULL) {
    out->ctx = NULL;
    out->ops = NULL;
  }
  if (cfg == NULL || servers == NULL || out == NULL) return GZ_CHAIN_INVALID_ARG;
  if (count < 1 || count > GZ_MULTI_MAX_SERVERS) return GZ_CHAIN_INVALID_ARG;
  if (!gz_network_valid(cfg->network)) return GZ_CHAIN_INVALID_ARG;
  if (cfg->quorum < 2 || cfg->quorum > GZ_MULTI_MAX_SERVERS || cfg->max_outputs == 0 ||
      cfg->max_outputs > 4096 || cfg->tip_slack > GZ_MULTI_LAG_MAX_BLOCKS)
    return GZ_CHAIN_INVALID_ARG;
  if (cfg->now_ms == NULL) return GZ_CHAIN_INVALID_ARG; /* lag must be timed */
  if (cfg->fee_ceiling_sat_per_kvb == 0 || cfg->fee_ceiling_sat_per_kvb > GZ_FEE_MAX_SAT_PER_KVB ||
      cfg->fee_disagree_factor < 1 || cfg->fee_disagree_factor > 100 ||
      cfg->fee_disagree_slack_sat_per_kvb > GZ_FEE_MAX_SAT_PER_KVB)
    return GZ_CHAIN_INVALID_ARG;
  for (size_t i = 0; i < count; i++) {
    if (servers[i].ctx == NULL || servers[i].ops == NULL) return GZ_CHAIN_INVALID_ARG;
    described[i] = gz_chain_describe(&servers[i], &info[i]);
    if (described[i]) {
      /* compare hosts in their one canonical form, whatever the backend
       * wrote; accept operator names only in canonical form */
      char host[GZ_HOST_MAX];
      if (info[i].host[0] != '\0') {
        if (!gz_host_normalise(info[i].host, strlen(info[i].host), host)) return GZ_CHAIN_INVALID_ARG;
        memcpy(info[i].host, host, sizeof host);
      }
      if (info[i].operator_id[0] != '\0' && !gz_operator_name_valid(info[i].operator_id))
        return GZ_CHAIN_INVALID_ARG;
    }
    /* the same server must never be compared with itself */
    for (size_t j = 0; j < i; j++) {
      if (servers[j].ctx == servers[i].ctx) return GZ_CHAIN_INVALID_ARG;
      if (!described[i] || !described[j]) continue;
      if (info[i].endpoint[0] != '\0' && strcmp(info[i].endpoint, info[j].endpoint) == 0)
        return GZ_CHAIN_INVALID_ARG;
      if (info[i].host[0] != '\0' && strcmp(info[i].host, info[j].host) == 0)
        return GZ_CHAIN_INVALID_ARG;
    }
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
  /* number the operators: servers naming the same operator share a number */
  for (size_t i = 0; i < count; i++) {
    bool named = described[i] && info[i].operator_id[0] != '\0';
    if (named) {
      snprintf(m->op_name[i], GZ_OPERATOR_MAX, "%s", info[i].operator_id);
    } else {
      snprintf(m->op_name[i], GZ_OPERATOR_MAX, "unnamed-%u", (unsigned)i);
    }
    m->op[i] = m->n_ops;
    for (size_t j = 0; j < i; j++) {
      if (named && strcmp(m->op_name[j], m->op_name[i]) == 0) m->op[i] = m->op[j];
    }
    if (m->op[i] == m->n_ops) m->n_ops++;
  }
  out->ctx = m;
  out->ops = &multi_ops;
  return GZ_CHAIN_OK;
}

const gz_multi_report *gz_multi_last_report(const gz_chain *c) {
  if (c == NULL || c->ops != &multi_ops || c->ctx == NULL) return NULL;
  return &((const multi *)c->ctx)->report;
}

size_t gz_multi_operator_count(const gz_chain *c) {
  if (c == NULL || c->ops != &multi_ops || c->ctx == NULL) return 0;
  return ((const multi *)c->ctx)->n_ops;
}
