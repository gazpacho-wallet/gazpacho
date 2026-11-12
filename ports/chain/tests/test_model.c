/*
 * A randomised model test of the comparing backend.
 *
 * Thousands of random situations are generated: one to four servers, run by
 * one to three operators, each reachable or not, on the right network or
 * not, at one of five tip heights, on the common chain or another, each
 * with its own claim about a transaction, a spend, a block and a fee rate
 * (for one of two targets). The transaction and the spend, where confirmed,
 * are at a height drawn per situation, so a server lacking one may be below
 * it or not. For each situation the expected verdict is worked out by the
 * functions named expect_* below, which are written from the rules as
 * stated in chain_multi.h and docs/notes/chain-port.md, not from multi.c:
 * they look at the whole situation at once, never ask a server anything,
 * and share no code with the backend. The backend, driven through stub
 * servers, must return the same verdict and the same answer every time.
 *
 * The time limit on lag is not reached here (the clock stands still); it is
 * tested in test_multi.c.
 *
 * GZ_MODEL_SEED and GZ_MODEL_ROUNDS in the environment replay or lengthen a
 * run; a failure prints the seed and round.
 */
#include "test.h"

#include "gazpacho/chain_multi.h"

enum { TX_UNSEEN = 0, TX_IN_MEMPOOL, TX_CONFIRMED_A, TX_CONFIRMED_B, TX_KINDS };
enum { SP_NONE = 0, SP_PENDING_X, SP_PENDING_Y, SP_CONFIRMED_X, SP_CONFIRMED_Y, SP_KINDS };

#define LOW_TIP 100u
#define BLOCK_PROBED 101u

typedef struct sim_server {
  bool reachable;
  bool right_network;
  bool other_chain;      /* its blocks are not the common chain's blocks */
  uint32_t tip;          /* 100 to 104 */
  int op;                /* which operator runs it */
  int tx;                /* what it says about the transaction */
  uint32_t tx_height;    /* where it says the transaction confirmed */
  int spend;             /* what it says about the output */
  uint32_t spend_height; /* where it says the spend confirmed */
  uint16_t fee_target;   /* the one target it lists: 6, or 1008 (leaving 6 out) */
  uint64_t fee;          /* its estimate for that target, sat/kvB */
  char host[48];
} sim_server;

static uint64_t zero_clock(void *ctx) {
  (void)ctx;
  return 0;
}

/* ---- the stub servers the backend talks to ---- */

static void fill(uint8_t out[GZ_HASH_LEN], uint8_t tag, uint32_t n) {
  memset(out, tag, GZ_HASH_LEN);
  out[0] = (uint8_t)n;
  out[1] = (uint8_t)(n >> 8);
}

static void block_at(const sim_server *s, uint32_t height, uint8_t out[GZ_HASH_LEN]) {
  fill(out, s->other_chain ? 0xbb : 0xaa, height);
}

static gz_chain_result sim_block_hash(void *ctx, uint32_t height, uint8_t out[GZ_HASH_LEN]) {
  const sim_server *s = ctx;
  if (!s->reachable) return GZ_CHAIN_UNREACHABLE;
  if (height == 0) {
    gz_network_genesis(s->right_network ? GZ_NET_SIGNET : GZ_NET_TESTNET4, out);
    return GZ_CHAIN_OK;
  }
  if (height > s->tip) return GZ_CHAIN_NOT_FOUND;
  block_at(s, height, out);
  return GZ_CHAIN_OK;
}

static gz_chain_result sim_tip(void *ctx, gz_chain_tip *out) {
  const sim_server *s = ctx;
  if (!s->reachable) return GZ_CHAIN_UNREACHABLE;
  out->height = s->tip;
  block_at(s, s->tip, out->hash);
  return GZ_CHAIN_OK;
}

/* The stubs make claims without checking them against their own tip, as a
 * lying backend could. */
static gz_chain_result sim_tx_status(void *ctx, const uint8_t txid[GZ_HASH_LEN],
                                     gz_tx_status *out) {
  const sim_server *s = ctx;
  (void)txid;
  if (!s->reachable) return GZ_CHAIN_UNREACHABLE;
  memset(out, 0, sizeof *out);
  if (s->tx == TX_IN_MEMPOOL) out->state = GZ_TX_MEMPOOL;
  if (s->tx == TX_CONFIRMED_A || s->tx == TX_CONFIRMED_B) {
    out->state = GZ_TX_CONFIRMED;
    out->height = s->tx_height;
    fill(out->block_hash, s->tx == TX_CONFIRMED_A ? 0x0a : 0x0b, s->tx_height);
    out->tip_height = s->tip;
    out->claimed_confirmations = s->tip >= s->tx_height ? s->tip - s->tx_height + 1 : 0;
  }
  return GZ_CHAIN_OK;
}

static gz_chain_result sim_outspend(void *ctx, const uint8_t txid[GZ_HASH_LEN], uint32_t vout,
                                    gz_outspend *out) {
  const sim_server *s = ctx;
  (void)txid;
  (void)vout;
  if (!s->reachable) return GZ_CHAIN_UNREACHABLE;
  memset(out, 0, sizeof *out);
  if (s->spend == SP_NONE) return GZ_CHAIN_OK;
  out->spent = true;
  bool x = s->spend == SP_PENDING_X || s->spend == SP_CONFIRMED_X;
  fill(out->spender_txid, x ? 0x58 : 0x59, 1);
  if (s->spend == SP_CONFIRMED_X || s->spend == SP_CONFIRMED_Y) {
    out->confirmed = true;
    out->height = s->spend_height;
    fill(out->block_hash, 0x0a, s->spend_height);
  }
  return GZ_CHAIN_OK;
}

static gz_chain_result sim_fees(void *ctx, gz_fee_estimates *out) {
  const sim_server *s = ctx;
  if (!s->reachable) return GZ_CHAIN_UNREACHABLE;
  out->count = 1;
  out->entries[0].target = s->fee_target;
  out->entries[0].sat_per_kvb = s->fee;
  return GZ_CHAIN_OK;
}

static bool sim_describe(void *ctx, gz_chain_info *out) {
  const sim_server *s = ctx;
  snprintf(out->host, sizeof out->host, "%s", s->host);
  snprintf(out->endpoint, sizeof out->endpoint, "https://%s/api", s->host);
  snprintf(out->operator_id, sizeof out->operator_id, "operator-%d", s->op);
  return true;
}

static const gz_chain_ops sim_ops = {
    .tip = sim_tip,
    .block_hash = sim_block_hash,
    .tx_status = sim_tx_status,
    .outspend = sim_outspend,
    .fee_estimates = sim_fees,
    .describe = sim_describe,
};

/* ---- the model: the rules, applied to the whole situation ---- */

typedef struct situation {
  size_t n;
  sim_server s[4];
} situation;

static bool counts(const sim_server *s) { return s->reachable && s->right_network; }

static size_t operators_where(const situation *w, bool (*pick)(const sim_server *, const void *),
                              const void *arg) {
  bool seen[8] = {false};
  size_t ops = 0;
  for (size_t i = 0; i < w->n; i++) {
    const sim_server *s = &w->s[i];
    if (counts(s) && (pick == NULL || pick(s, arg)) && !seen[s->op]) {
      seen[s->op] = true;
      ops++;
    }
  }
  return ops;
}

static size_t operators_counting(const situation *w) { return operators_where(w, NULL, NULL); }

/* "Fewer operators than the quorum: no quorum; or, if every server failed in
 * the same way, that failure." */
static gz_chain_result too_few(const situation *w) {
  bool all_down = true, all_wrong = true;
  for (size_t i = 0; i < w->n; i++) {
    if (w->s[i].reachable) all_down = false;
    if (!w->s[i].reachable || w->s[i].right_network) all_wrong = false;
  }
  if (all_down) return GZ_CHAIN_UNREACHABLE;
  if (all_wrong) return GZ_CHAIN_WRONG_NETWORK;
  return GZ_CHAIN_NO_QUORUM;
}

/* "Lag: the disputed item lies above the tip of every server that lacks it
 * and not above the tip of any server that has it; the tips lie on one
 * chain, differ, and are at most GZ_MULTI_LAG_MAX_BLOCKS apart." */
static bool looks_like_lag(const situation *w, bool (*holds)(const sim_server *), uint32_t height) {
  uint32_t lo = UINT32_MAX, hi = 0;
  bool common = false, other = false;
  for (size_t i = 0; i < w->n; i++) {
    const sim_server *s = &w->s[i];
    if (!counts(s)) continue;
    if (s->tip < lo) lo = s->tip;
    if (s->tip > hi) hi = s->tip;
    if (s->other_chain) other = true;
    else common = true;
    if (holds(s) ? s->tip < height : s->tip >= height) return false;
  }
  return hi > lo && hi - lo <= GZ_MULTI_LAG_MAX_BLOCKS && !(common && other);
}

typedef struct expected {
  gz_chain_result verdict;
  int value;    /* the answer, in the test's own terms */
  bool differs; /* unconfirmed data differs */
  size_t fee_count;
  uint16_t fee_target[2];
  uint64_t fee[2];
} expected;

static bool has_tx(const sim_server *s) { return s->tx == TX_CONFIRMED_A || s->tx == TX_CONFIRMED_B; }

static expected expect_tx_status(const situation *w) {
  expected e = {GZ_CHAIN_OK, TX_UNSEEN, false, 0, {0, 0}, {0, 0}};
  size_t n = 0, in_a = 0, in_b = 0, mempool = 0;
  uint32_t h_a = 0, height = 0;
  bool apart = false;
  for (size_t i = 0; i < w->n; i++) {
    const sim_server *s = &w->s[i];
    if (!counts(s)) continue;
    n++;
    if (has_tx(s)) {
      /* "confirmed in two places": another block, or another height */
      if (s->tx == TX_CONFIRMED_A) in_a++;
      if (s->tx == TX_CONFIRMED_B) in_b++;
      if (height == 0) height = s->tx_height;
      else if (s->tx_height != height) apart = true;
      h_a = height;
    }
    if (s->tx == TX_IN_MEMPOOL) mempool++;
  }
  if ((in_a > 0 && in_b > 0) || apart) { e.verdict = GZ_CHAIN_DISAGREE; return e; }
  if (operators_counting(w) < 2) { e.verdict = too_few(w); return e; }
  size_t confirmed = in_a + in_b;
  if (confirmed == 0) {
    if (mempool == n) e.value = TX_IN_MEMPOOL;
    else e.differs = mempool > 0;
    return e;
  }
  if (confirmed == n) { e.value = in_a ? TX_CONFIRMED_A : TX_CONFIRMED_B; return e; }
  e.verdict = looks_like_lag(w, has_tx, h_a) ? GZ_CHAIN_LAG : GZ_CHAIN_DISAGREE;
  return e;
}

static bool has_spend(const sim_server *s) {
  return s->spend == SP_CONFIRMED_X || s->spend == SP_CONFIRMED_Y;
}

static expected expect_outspend(const situation *w) {
  expected e = {GZ_CHAIN_OK, SP_NONE, false, 0, {0, 0}, {0, 0}};
  size_t n = 0, cx = 0, cy = 0, px = 0, py = 0;
  uint32_t height = 0;
  bool apart = false;
  for (size_t i = 0; i < w->n; i++) {
    const sim_server *s = &w->s[i];
    if (!counts(s)) continue;
    n++;
    if (s->spend == SP_CONFIRMED_X) cx++;
    if (s->spend == SP_CONFIRMED_Y) cy++;
    if (s->spend == SP_PENDING_X) px++;
    if (s->spend == SP_PENDING_Y) py++;
    if (has_spend(s)) {
      if (height == 0) height = s->spend_height;
      else if (s->spend_height != height) apart = true;
    }
  }
  if ((cx > 0 && cy > 0) || apart) { e.verdict = GZ_CHAIN_DISAGREE; return e; }
  if (operators_counting(w) < 2) { e.verdict = too_few(w); return e; }
  if (cx + cy == 0) {
    if (px == n) e.value = SP_PENDING_X;
    else if (py == n) e.value = SP_PENDING_Y;
    else e.differs = px + py > 0;
    return e;
  }
  if (cx + cy == n) { e.value = cx ? SP_CONFIRMED_X : SP_CONFIRMED_Y; return e; }
  e.verdict = looks_like_lag(w, has_spend, height) ? GZ_CHAIN_LAG : GZ_CHAIN_DISAGREE;
  return e;
}

static bool has_block_probed(const sim_server *s) { return s->tip >= BLOCK_PROBED; }

/* The block at height 101: a server has it if its tip is that high. */
static expected expect_block_probed(const situation *w) {
  expected e = {GZ_CHAIN_OK, 0, false, 0, {0, 0}, {0, 0}};
  size_t have_common = 0, have_other = 0, missing = 0;
  for (size_t i = 0; i < w->n; i++) {
    if (!counts(&w->s[i])) continue;
    if (!has_block_probed(&w->s[i])) missing++;
    else if (w->s[i].other_chain) have_other++;
    else have_common++;
  }
  if (have_common > 0 && have_other > 0) { e.verdict = GZ_CHAIN_DISAGREE; return e; }
  if (have_common + have_other > 0 && missing > 0) {
    e.verdict = looks_like_lag(w, has_block_probed, BLOCK_PROBED) ? GZ_CHAIN_LAG : GZ_CHAIN_DISAGREE;
    return e;
  }
  if (operators_counting(w) < 2) { e.verdict = too_few(w); return e; }
  if (missing > 0) { e.verdict = GZ_CHAIN_NOT_FOUND; return e; }
  e.value = have_other ? 0xbb : 0xaa;
  return e;
}

/* "A server answers for target T with its estimate for the highest target
 * it lists not above T. For each target listed, among the servers answering
 * for it: fewer than two operators, no entry; highest above factor times
 * lowest plus slack, disagreement; else the lowest, cut at the ceiling."
 * Defaults: ceiling 200000, factor 3, slack 1000. */
static bool answers_for(const sim_server *s, const void *target) {
  return s->fee_target <= *(const uint16_t *)target;
}

static expected expect_fee(const situation *w) {
  expected e = {GZ_CHAIN_OK, 0, false, 0, {0, 0}, {0, 0}};
  if (operators_counting(w) < 2) { e.verdict = too_few(w); return e; }
  static const uint16_t targets[2] = {6, 1008};
  for (size_t t = 0; t < 2; t++) {
    bool listed = false;
    uint64_t lo = UINT64_MAX, hi = 0;
    for (size_t i = 0; i < w->n; i++) {
      const sim_server *s = &w->s[i];
      if (!counts(s)) continue;
      if (s->fee_target == targets[t]) listed = true;
      if (!answers_for(s, &targets[t])) continue;
      if (s->fee < lo) lo = s->fee;
      if (s->fee > hi) hi = s->fee;
    }
    if (!listed || operators_where(w, answers_for, &targets[t]) < 2) continue;
    if (hi > 3 * lo + 1000) {
      e.verdict = GZ_CHAIN_DISAGREE;
      e.fee_count = 0;
      return e;
    }
    e.fee_target[e.fee_count] = targets[t];
    e.fee[e.fee_count] = lo > 200000 ? 200000 : lo;
    e.fee_count++;
  }
  return e;
}

/* ---- the comparison ---- */

static void describe_situation(const situation *w) {
  for (size_t i = 0; i < w->n; i++) {
    const sim_server *s = &w->s[i];
    fprintf(stderr,
            "    server %zu: op %d %s %s %s tip %lu tx %d@%lu spend %d@%lu fee %llu for %u\n", i,
            s->op, s->reachable ? "up" : "DOWN", s->right_network ? "signet" : "WRONGNET",
            s->other_chain ? "otherchain" : "common", (unsigned long)s->tip, s->tx,
            (unsigned long)s->tx_height, s->spend, (unsigned long)s->spend_height,
            (unsigned long long)s->fee, (unsigned)s->fee_target);
  }
}

static int tx_value(const gz_tx_status *st) {
  if (st->state == GZ_TX_MEMPOOL) return TX_IN_MEMPOOL;
  if (st->state == GZ_TX_CONFIRMED) return st->block_hash[2] == 0x0a ? TX_CONFIRMED_A : TX_CONFIRMED_B;
  return TX_UNSEEN;
}

static int spend_value(const gz_outspend *o) {
  if (!o->spent) return SP_NONE;
  bool x = o->spender_txid[2] == 0x58;
  if (o->confirmed) return x ? SP_CONFIRMED_X : SP_CONFIRMED_Y;
  return x ? SP_PENDING_X : SP_PENDING_Y;
}

static void test_random_situations(test_state *T) {
  static const uint64_t rates[] = {0, 100, 900, 1000, 3000, 4000, 4001, 13000, 50000, 250000, 900000};
  uint64_t seed = UINT64_C(0x5EED5EED12345678);
  unsigned long rounds = 20000;
  const char *env;
  if ((env = getenv("GZ_MODEL_SEED")) != NULL && *env) seed = strtoull(env, NULL, 0);
  if ((env = getenv("GZ_MODEL_ROUNDS")) != NULL && *env) rounds = strtoul(env, NULL, 0);
  if (seed == 0) seed = 1;
  printf("model run: seed 0x%llx, %lu situations\n", (unsigned long long)seed, rounds);

  uint64_t rng = seed;
  unsigned long verdicts[32] = {0}, spend_verdicts[32] = {0}, block_verdicts[32] = {0};
  unsigned long fee_verdicts[32] = {0}, fee_partial = 0;
  unsigned long mismatches = 0;
  uint8_t txid[GZ_HASH_LEN] = {1};
  for (unsigned long round = 0; round < rounds && mismatches < 5; round++) {
    situation w;
    memset(&w, 0, sizeof w);
    w.n = 1 + (size_t)(test_rand(&rng) % 4);
    /* most situations are mostly healthy, so the interesting branches
     * (agreement, lag, unconfirmed differences) are reached often */
    bool calm = test_rand(&rng) % 3 != 0;
    int common_tx = (int)(test_rand(&rng) % TX_KINDS);
    int common_spend = (int)(test_rand(&rng) % SP_KINDS);
    uint32_t tx_height = LOW_TIP + (uint32_t)(test_rand(&rng) % 4);
    uint32_t spend_height = LOW_TIP + (uint32_t)(test_rand(&rng) % 4);
    uint64_t common_fee = rates[test_rand(&rng) % (sizeof rates / sizeof rates[0])];
    for (size_t i = 0; i < w.n; i++) {
      sim_server *s = &w.s[i];
      uint64_t r = test_rand(&rng), r2 = test_rand(&rng);
      s->reachable = (r % 10) != 0;
      s->right_network = ((r >> 8) % 12) != 0;
      s->other_chain = ((r >> 16) % 15) == 0;
      s->tip = LOW_TIP + (uint32_t)((r >> 24) % (calm ? 2 : 5)) + (calm ? 1 : 0);
      s->op = (int)((r >> 32) % 3);
      bool own_view = ((r >> 40) % (calm ? 5 : 2)) == 0;
      s->tx = own_view ? (int)((r >> 44) % TX_KINDS) : common_tx;
      s->spend = own_view ? (int)((r >> 48) % SP_KINDS) : common_spend;
      s->fee = own_view ? rates[(r >> 52) % (sizeof rates / sizeof rates[0])] : common_fee;
      /* a server that has not seen the block a transaction or spend is in
       * usually does not claim it; sometimes one claims it anyway */
      s->tx_height = own_view && (r2 % 7) == 0 ? LOW_TIP + (uint32_t)((r2 >> 8) % 4) : tx_height;
      s->spend_height =
          own_view && ((r2 >> 16) % 7) == 0 ? LOW_TIP + (uint32_t)((r2 >> 24) % 4) : spend_height;
      if (has_tx(s) && s->tx_height > s->tip && (r2 >> 32) % 4 != 0) s->tx = TX_IN_MEMPOOL;
      if (has_spend(s) && s->spend_height > s->tip && (r2 >> 34) % 4 != 0) s->spend = SP_PENDING_X;
      s->fee_target = ((r2 >> 40) % 5) == 0 ? 1008 : 6;
      snprintf(s->host, sizeof s->host, "host%zu.op%d.test", i, s->op);
    }
    gz_chain servers[4], multi;
    for (size_t i = 0; i < w.n; i++) {
      servers[i].ctx = &w.s[i];
      servers[i].ops = &sim_ops;
    }
    gz_multi_config mc;
    gz_multi_config_default(&mc, GZ_NET_SIGNET);
    mc.now_ms = zero_clock;
    if (gz_multi_create(&mc, servers, w.n, &multi) != GZ_CHAIN_OK) {
      fprintf(stderr, "  cannot create the comparing backend\n");
      exit(2);
    }
    const gz_multi_report *rep = gz_multi_last_report(&multi);

    gz_tx_status st;
    expected e = expect_tx_status(&w);
    gz_chain_result got = gz_chain_tx_status(&multi, txid, &st);
    bool ok = got == e.verdict;
    if (ok && got == GZ_CHAIN_OK)
      ok = tx_value(&st) == e.value && st.unconfirmed_differs == e.differs &&
           rep->unconfirmed_differs == e.differs;
    if (ok && got != GZ_CHAIN_OK) ok = st.state == GZ_TX_UNKNOWN && !st.unconfirmed_differs;
    if (!ok) {
      mismatches++;
      fprintf(stderr, "  round %lu tx_status: backend %s (value %d), rules say %s (value %d, differs %d)\n",
              round, gz_chain_result_name(got), tx_value(&st), gz_chain_result_name(e.verdict),
              e.value, (int)e.differs);
      describe_situation(&w);
    }
    verdicts[got % 32]++;

    gz_outspend os;
    e = expect_outspend(&w);
    got = gz_chain_outspend(&multi, txid, 0, &os);
    ok = got == e.verdict;
    if (ok && got == GZ_CHAIN_OK)
      ok = spend_value(&os) == e.value && os.unconfirmed_differs == e.differs;
    if (ok && got != GZ_CHAIN_OK) ok = !os.spent && !os.unconfirmed_differs;
    if (!ok) {
      mismatches++;
      fprintf(stderr, "  round %lu outspend: backend %s (value %d), rules say %s (value %d, differs %d)\n",
              round, gz_chain_result_name(got), spend_value(&os), gz_chain_result_name(e.verdict),
              e.value, (int)e.differs);
      describe_situation(&w);
    }
    spend_verdicts[got % 32]++;

    uint8_t h[GZ_HASH_LEN];
    e = expect_block_probed(&w);
    got = gz_chain_block_hash(&multi, BLOCK_PROBED, h);
    ok = got == e.verdict && (got != GZ_CHAIN_OK || h[2] == (uint8_t)e.value);
    if (!ok) {
      mismatches++;
      fprintf(stderr, "  round %lu block_hash: backend %s, rules say %s\n", round,
              gz_chain_result_name(got), gz_chain_result_name(e.verdict));
      describe_situation(&w);
    }
    block_verdicts[got % 32]++;

    gz_fee_estimates f;
    e = expect_fee(&w);
    got = gz_chain_fee_estimates(&multi, &f);
    ok = got == e.verdict && f.count == e.fee_count;
    for (size_t k = 0; ok && k < f.count; k++)
      ok = f.entries[k].target == e.fee_target[k] && f.entries[k].sat_per_kvb == e.fee[k];
    if (!ok) {
      mismatches++;
      fprintf(stderr, "  round %lu fees: backend %s (%zu entries), rules say %s (%zu entries)\n",
              round, gz_chain_result_name(got), f.count, gz_chain_result_name(e.verdict),
              e.fee_count);
      describe_situation(&w);
    }
    fee_verdicts[got % 32]++;
    if (got == GZ_CHAIN_OK && f.count == 1) fee_partial++;
    gz_chain_destroy(&multi);
  }
  CHECK(mismatches == 0);
  if (mismatches != 0) fprintf(stderr, "  replay with GZ_MODEL_SEED=0x%llx\n", (unsigned long long)seed);
  printf("tx_status verdicts seen: ok %lu, disagree %lu, no-quorum %lu, lag %lu, unreachable %lu, "
         "wrong-network %lu\n",
         verdicts[GZ_CHAIN_OK], verdicts[GZ_CHAIN_DISAGREE], verdicts[GZ_CHAIN_NO_QUORUM],
         verdicts[GZ_CHAIN_LAG], verdicts[GZ_CHAIN_UNREACHABLE], verdicts[GZ_CHAIN_WRONG_NETWORK]);
  printf("outspend: ok %lu, disagree %lu, lag %lu; block: ok %lu, not-found %lu, disagree %lu, "
         "lag %lu; fees: ok %lu (one target only %lu), disagree %lu\n",
         spend_verdicts[GZ_CHAIN_OK], spend_verdicts[GZ_CHAIN_DISAGREE], spend_verdicts[GZ_CHAIN_LAG],
         block_verdicts[GZ_CHAIN_OK], block_verdicts[GZ_CHAIN_NOT_FOUND],
         block_verdicts[GZ_CHAIN_DISAGREE], block_verdicts[GZ_CHAIN_LAG], fee_verdicts[GZ_CHAIN_OK],
         fee_partial, fee_verdicts[GZ_CHAIN_DISAGREE]);
  /* the run must actually have reached every kind of verdict */
  CHECK(verdicts[GZ_CHAIN_OK] > rounds / 20);
  CHECK(verdicts[GZ_CHAIN_DISAGREE] > rounds / 100);
  CHECK(verdicts[GZ_CHAIN_NO_QUORUM] > rounds / 100);
  CHECK(verdicts[GZ_CHAIN_LAG] > rounds / 500);
  CHECK(spend_verdicts[GZ_CHAIN_LAG] > rounds / 500);
  CHECK(block_verdicts[GZ_CHAIN_LAG] > rounds / 500);
  CHECK(fee_partial > rounds / 500);
  CHECK(verdicts[GZ_CHAIN_UNREACHABLE] > 0 && verdicts[GZ_CHAIN_WRONG_NETWORK] > 0);
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  RUN(test_random_situations);
  TEST_MAIN_END("test_model");
}
