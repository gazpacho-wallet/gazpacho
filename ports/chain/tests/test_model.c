/*
 * A randomised model test of the comparing backend.
 *
 * Thousands of random situations are generated: one to four servers, run by
 * one to three operators, each reachable or not, on the right network or
 * not, at one of three tip heights, on the common chain or another, each
 * with its own claim about a transaction, a spend, a block and a fee rate.
 * For each situation the expected verdict is worked out by the functions
 * named expect_* below, which are written from the rules as stated in
 * chain_multi.h and docs/notes/chain-port.md, not from multi.c: they look at
 * the whole situation at once, never ask a server anything, and share no
 * code with the backend. The backend, driven through stub servers, must
 * return the same verdict and the same answer every time.
 *
 * GZ_MODEL_SEED and GZ_MODEL_ROUNDS in the environment replay or lengthen a
 * run; a failure prints the seed and round.
 */
#include "test.h"

#include "gazpacho/chain_multi.h"

enum { TX_UNSEEN = 0, TX_IN_MEMPOOL, TX_CONFIRMED_A, TX_CONFIRMED_B, TX_KINDS };
enum { SP_NONE = 0, SP_PENDING_X, SP_PENDING_Y, SP_CONFIRMED_X, SP_CONFIRMED_Y, SP_KINDS };

typedef struct sim_server {
  bool reachable;
  bool right_network;
  bool other_chain; /* its blocks are not the common chain's blocks */
  uint32_t tip;     /* 100, 101 or 102 */
  int op;           /* which operator runs it */
  int tx;           /* what it says about the transaction */
  int spend;        /* what it says about the output */
  uint64_t fee;     /* its estimate for the one target, sat/kvB */
  char host[48];
} sim_server;

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

static gz_chain_result sim_tx_status(void *ctx, const uint8_t txid[GZ_HASH_LEN],
                                     gz_tx_status *out) {
  const sim_server *s = ctx;
  (void)txid;
  if (!s->reachable) return GZ_CHAIN_UNREACHABLE;
  memset(out, 0, sizeof *out);
  if (s->tx == TX_IN_MEMPOOL) out->state = GZ_TX_MEMPOOL;
  if (s->tx == TX_CONFIRMED_A || s->tx == TX_CONFIRMED_B) {
    out->state = GZ_TX_CONFIRMED;
    out->height = 100;
    fill(out->block_hash, s->tx == TX_CONFIRMED_A ? 0x0a : 0x0b, 100);
    out->tip_height = s->tip;
    out->claimed_confirmations = s->tip - 100 + 1;
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
    out->height = 100;
    fill(out->block_hash, 0x0a, 100);
  }
  return GZ_CHAIN_OK;
}

static gz_chain_result sim_fees(void *ctx, gz_fee_estimates *out) {
  const sim_server *s = ctx;
  if (!s->reachable) return GZ_CHAIN_UNREACHABLE;
  out->count = 1;
  out->entries[0].target = 6;
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

static size_t operators_counting(const situation *w) {
  bool seen[8] = {false};
  size_t ops = 0;
  for (size_t i = 0; i < w->n; i++) {
    if (counts(&w->s[i]) && !seen[w->s[i].op]) {
      seen[w->s[i].op] = true;
      ops++;
    }
  }
  return ops;
}

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

/* "Their tips differ by an allowed amount and are on one chain." */
static bool looks_like_lag(const situation *w) {
  uint32_t lo = UINT32_MAX, hi = 0;
  int chains = 0;
  bool common = false, other = false;
  for (size_t i = 0; i < w->n; i++) {
    if (!counts(&w->s[i])) continue;
    if (w->s[i].tip < lo) lo = w->s[i].tip;
    if (w->s[i].tip > hi) hi = w->s[i].tip;
    if (w->s[i].other_chain) other = true; else common = true;
  }
  chains = (common ? 1 : 0) + (other ? 1 : 0);
  return hi > lo && hi - lo <= 1 && chains == 1;
}

typedef struct expected {
  gz_chain_result verdict;
  int value;    /* the answer, in the test's own terms */
  bool differs; /* unconfirmed data differs */
  uint64_t fee;
} expected;

static expected expect_tx_status(const situation *w) {
  expected e = {GZ_CHAIN_OK, TX_UNSEEN, false, 0};
  size_t n = 0, in_a = 0, in_b = 0, mempool = 0;
  for (size_t i = 0; i < w->n; i++) {
    if (!counts(&w->s[i])) continue;
    n++;
    if (w->s[i].tx == TX_CONFIRMED_A) in_a++;
    if (w->s[i].tx == TX_CONFIRMED_B) in_b++;
    if (w->s[i].tx == TX_IN_MEMPOOL) mempool++;
  }
  if (in_a > 0 && in_b > 0) { e.verdict = GZ_CHAIN_DISAGREE; return e; }
  if (operators_counting(w) < 2) { e.verdict = too_few(w); return e; }
  size_t confirmed = in_a + in_b;
  if (confirmed == 0) {
    if (mempool == n) e.value = TX_IN_MEMPOOL;
    else e.differs = mempool > 0;
    return e;
  }
  if (confirmed == n) { e.value = in_a ? TX_CONFIRMED_A : TX_CONFIRMED_B; return e; }
  e.verdict = looks_like_lag(w) ? GZ_CHAIN_LAG : GZ_CHAIN_DISAGREE;
  return e;
}

static expected expect_outspend(const situation *w) {
  expected e = {GZ_CHAIN_OK, SP_NONE, false, 0};
  size_t n = 0, cx = 0, cy = 0, px = 0, py = 0;
  for (size_t i = 0; i < w->n; i++) {
    if (!counts(&w->s[i])) continue;
    n++;
    if (w->s[i].spend == SP_CONFIRMED_X) cx++;
    if (w->s[i].spend == SP_CONFIRMED_Y) cy++;
    if (w->s[i].spend == SP_PENDING_X) px++;
    if (w->s[i].spend == SP_PENDING_Y) py++;
  }
  if (cx > 0 && cy > 0) { e.verdict = GZ_CHAIN_DISAGREE; return e; }
  if (operators_counting(w) < 2) { e.verdict = too_few(w); return e; }
  if (cx + cy == 0) {
    if (px == n) e.value = SP_PENDING_X;
    else if (py == n) e.value = SP_PENDING_Y;
    else e.differs = px + py > 0;
    return e;
  }
  if (cx + cy == n) { e.value = cx ? SP_CONFIRMED_X : SP_CONFIRMED_Y; return e; }
  e.verdict = looks_like_lag(w) ? GZ_CHAIN_LAG : GZ_CHAIN_DISAGREE;
  return e;
}

/* The block at height 101: a server has it if its tip is that high. */
static expected expect_block_101(const situation *w) {
  expected e = {GZ_CHAIN_OK, 0, false, 0};
  size_t have_common = 0, have_other = 0, missing = 0;
  for (size_t i = 0; i < w->n; i++) {
    if (!counts(&w->s[i])) continue;
    if (w->s[i].tip < 101) missing++;
    else if (w->s[i].other_chain) have_other++;
    else have_common++;
  }
  if (have_common > 0 && have_other > 0) { e.verdict = GZ_CHAIN_DISAGREE; return e; }
  if (have_common + have_other > 0 && missing > 0) {
    e.verdict = looks_like_lag(w) ? GZ_CHAIN_LAG : GZ_CHAIN_DISAGREE;
    return e;
  }
  if (operators_counting(w) < 2) { e.verdict = too_few(w); return e; }
  if (missing > 0) { e.verdict = GZ_CHAIN_NOT_FOUND; return e; }
  e.value = have_other ? 0xbb : 0xaa;
  return e;
}

/* "The lowest rate, cut at the ceiling; highest above factor times lowest
 * plus slack: disagreement." Defaults: ceiling 200000, factor 3, slack 1000. */
static expected expect_fee(const situation *w) {
  expected e = {GZ_CHAIN_OK, 0, false, 0};
  uint64_t lo = UINT64_MAX, hi = 0;
  if (operators_counting(w) < 2) { e.verdict = too_few(w); return e; }
  for (size_t i = 0; i < w->n; i++) {
    if (!counts(&w->s[i])) continue;
    if (w->s[i].fee < lo) lo = w->s[i].fee;
    if (w->s[i].fee > hi) hi = w->s[i].fee;
  }
  if (hi > 3 * lo + 1000) { e.verdict = GZ_CHAIN_DISAGREE; return e; }
  e.fee = lo > 200000 ? 200000 : lo;
  return e;
}

/* ---- the comparison ---- */

static void describe_situation(const situation *w) {
  for (size_t i = 0; i < w->n; i++) {
    const sim_server *s = &w->s[i];
    fprintf(stderr, "    server %zu: op %d %s %s %s tip %lu tx %d spend %d fee %llu\n", i, s->op,
            s->reachable ? "up" : "DOWN", s->right_network ? "signet" : "WRONGNET",
            s->other_chain ? "otherchain" : "common", (unsigned long)s->tip, s->tx, s->spend,
            (unsigned long long)s->fee);
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
  unsigned long verdicts[32] = {0};
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
    uint64_t common_fee = rates[test_rand(&rng) % (sizeof rates / sizeof rates[0])];
    for (size_t i = 0; i < w.n; i++) {
      sim_server *s = &w.s[i];
      uint64_t r = test_rand(&rng);
      s->reachable = (r % 10) != 0;
      s->right_network = ((r >> 8) % 12) != 0;
      s->other_chain = ((r >> 16) % 15) == 0;
      s->tip = 100 + (uint32_t)((r >> 24) % (calm ? 2 : 3)) + (calm ? 1 : 0);
      s->op = (int)((r >> 32) % 3);
      bool own_view = ((r >> 40) % (calm ? 5 : 2)) == 0;
      s->tx = own_view ? (int)((r >> 44) % TX_KINDS) : common_tx;
      s->spend = own_view ? (int)((r >> 48) % SP_KINDS) : common_spend;
      s->fee = own_view ? rates[(r >> 52) % (sizeof rates / sizeof rates[0])] : common_fee;
      snprintf(s->host, sizeof s->host, "host%zu.op%d.test", i, s->op);
    }
    gz_chain servers[4], multi;
    for (size_t i = 0; i < w.n; i++) {
      servers[i].ctx = &w.s[i];
      servers[i].ops = &sim_ops;
    }
    gz_multi_config mc;
    gz_multi_config_default(&mc, GZ_NET_SIGNET);
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

    uint8_t h[GZ_HASH_LEN];
    e = expect_block_101(&w);
    got = gz_chain_block_hash(&multi, 101, h);
    ok = got == e.verdict && (got != GZ_CHAIN_OK || h[2] == (uint8_t)e.value);
    if (!ok) {
      mismatches++;
      fprintf(stderr, "  round %lu block_hash: backend %s, rules say %s\n", round,
              gz_chain_result_name(got), gz_chain_result_name(e.verdict));
      describe_situation(&w);
    }

    gz_fee_estimates f;
    e = expect_fee(&w);
    got = gz_chain_fee_estimates(&multi, &f);
    ok = got == e.verdict;
    if (ok && got == GZ_CHAIN_OK) ok = f.count == 1 && f.entries[0].sat_per_kvb == e.fee;
    if (ok && got != GZ_CHAIN_OK) ok = f.count == 0;
    if (!ok) {
      mismatches++;
      fprintf(stderr, "  round %lu fees: backend %s, rules say %s (rate %llu)\n", round,
              gz_chain_result_name(got), gz_chain_result_name(e.verdict), (unsigned long long)e.fee);
      describe_situation(&w);
    }
    gz_chain_destroy(&multi);
  }
  CHECK(mismatches == 0);
  if (mismatches != 0) fprintf(stderr, "  replay with GZ_MODEL_SEED=0x%llx\n", (unsigned long long)seed);
  printf("tx_status verdicts seen: ok %lu, disagree %lu, no-quorum %lu, lag %lu, unreachable %lu, "
         "wrong-network %lu\n",
         verdicts[GZ_CHAIN_OK], verdicts[GZ_CHAIN_DISAGREE], verdicts[GZ_CHAIN_NO_QUORUM],
         verdicts[GZ_CHAIN_LAG], verdicts[GZ_CHAIN_UNREACHABLE], verdicts[GZ_CHAIN_WRONG_NETWORK]);
  /* the run must actually have reached every kind of verdict */
  CHECK(verdicts[GZ_CHAIN_OK] > rounds / 20);
  CHECK(verdicts[GZ_CHAIN_DISAGREE] > rounds / 100);
  CHECK(verdicts[GZ_CHAIN_NO_QUORUM] > rounds / 100);
  CHECK(verdicts[GZ_CHAIN_LAG] > rounds / 200);
  CHECK(verdicts[GZ_CHAIN_UNREACHABLE] > 0 && verdicts[GZ_CHAIN_WRONG_NETWORK] > 0);
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  RUN(test_random_situations);
  TEST_MAIN_END("test_model");
}
