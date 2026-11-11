/*
 * Mutation tests for everything that parses server input: a seeded loop that
 * damages recorded answers and feeds them to each parser. Meant to be run
 * under AddressSanitizer and UBSan, where any out-of-bounds read or undefined
 * operation aborts the test. Inputs are copied into exactly-sized heap blocks
 * with no terminating zero so that reading one byte too far is caught.
 *
 * This is a stand-in for a real coverage-guided fuzzer. When one is attached
 * (libFuzzer or AFL++), the entry points are the same functions called from
 * run_parsers() below, and the files in tests/data/ are the starting corpus.
 *
 * GZ_FUZZ_SEED and GZ_FUZZ_ITERS in the environment override the defaults,
 * so a failure can be replayed and longer runs made.
 */
#include "test.h"

#include "../esplora_parse.h"
#include "../json.h"

typedef struct corpus_item {
  const char *file;
  char *data;
  size_t len;
} corpus_item;

static corpus_item corpus[] = {
    {"tx_a_status.json", NULL, 0},
    {"tx_a_outspend_0.json", NULL, 0},
    {"tx_a_outspend_2.json", NULL, 0},
    {"tx_a_merkle_proof.json", NULL, 0},
    {"utxo_script_a2.json", NULL, 0},
    {"fee_estimates_mempool.json", NULL, 0},
    {"fee_estimates_blockstream.json", NULL, 0},
    {"header_329438.txt", NULL, 0},
    {"block_hash_329438.txt", NULL, 0},
    {"tx_a_hex.txt", NULL, 0},
    {"post_known_mempool.txt", NULL, 0},
};
#define CORPUS_COUNT (sizeof corpus / sizeof corpus[0])

typedef struct fuzz_ctx {
  uint8_t tx_a[GZ_HASH_LEN];
  uint8_t header[GZ_HEADER_LEN];
  gz_merkle_proof real_proof;
  unsigned long accepted[8];
  unsigned long forged; /* damaged proofs that still verified: must stay 0 */
  unsigned long broken; /* invariant violations: must stay 0 */
} fuzz_ctx;

static const char interesting[] = "{}[]\",:0123456789abcdef-+.eE \\\n\ttruefalsenull";

/* Applies one random change. `buf` has room for `cap` bytes. */
static size_t mutate(uint64_t *rng, char *buf, size_t len, size_t cap) {
  uint64_t r = test_rand(rng);
  unsigned kind = (unsigned)(r % 8);
  size_t at = len ? (size_t)((r >> 8) % len) : 0;
  size_t span = 1 + (size_t)((r >> 40) % 16);
  switch (kind) {
    case 0: /* flip a bit */
      if (len) buf[at] = (char)(buf[at] ^ (1 << ((r >> 32) & 7)));
      break;
    case 1: /* put a structurally interesting character */
      if (len) buf[at] = interesting[(r >> 32) % (sizeof interesting - 1)];
      break;
    case 2: /* random byte */
      if (len) buf[at] = (char)(r >> 32);
      break;
    case 3: /* delete a span */
      if (len) {
        if (span > len - at) span = len - at;
        memmove(buf + at, buf + at + span, len - at - span);
        len -= span;
      }
      break;
    case 4: /* duplicate a span */
      if (len) {
        if (span > len - at) span = len - at;
        if (len + span <= cap) {
          memmove(buf + at + span, buf + at, len - at);
          len += span;
        }
      }
      break;
    case 5: /* insert an interesting character */
      if (len + 1 <= cap) {
        memmove(buf + at + 1, buf + at, len - at);
        buf[at] = interesting[(r >> 32) % (sizeof interesting - 1)];
        len++;
      }
      break;
    case 6: /* truncate */
      len = at;
      break;
    default: /* replace a digit run with a huge number */
      if (len > 24 && at + 22 < len) memcpy(buf + at, "99999999999999999999999", 22);
      break;
  }
  return len;
}

static void run_parsers(fuzz_ctx *fz, const char *in, size_t len) {
  gz_json_tok toks[256];
  size_t n = 0;
  if (gz_json_parse(in, len, toks, 256, &n)) {
    fz->accepted[0]++;
    /* token invariants: ranges inside the input, subtree links forward */
    if (n == 0 || n > 256) fz->broken++;
    for (size_t i = 0; i < n && i < 256; i++) {
      if (toks[i].start > toks[i].end || toks[i].end > len) fz->broken++;
      if (toks[i].next <= i || toks[i].next > n) fz->broken++;
    }
  }

  gz_es_status st;
  if (gz_es_parse_status(in, len, &st)) {
    fz->accepted[1]++;
    if (st.height > GZ_MAX_HEIGHT) fz->broken++;
  }

  gz_outspend os;
  if (gz_es_parse_outspend(in, len, &os)) {
    fz->accepted[2]++;
    if (os.height > GZ_MAX_HEIGHT || (!os.spent && os.confirmed)) fz->broken++;
  }

  gz_chain_output outs[4];
  size_t count = 99;
  gz_es_parse_result ur = gz_es_parse_utxos(in, len, outs, 4, &count);
  if (ur == GZ_ES_PARSE_OK) {
    fz->accepted[3]++;
    if (count > 4) fz->broken++;
    for (size_t i = 0; i < count && i < 4; i++) {
      if (outs[i].value > GZ_MAX_MONEY || outs[i].height > GZ_MAX_HEIGHT) fz->broken++;
    }
  } else if (count != 99) {
    fz->broken++; /* wrote the count without succeeding */
  }

  gz_merkle_proof mp;
  if (gz_es_parse_merkle_proof(in, len, &mp)) {
    fz->accepted[4]++;
    if (mp.depth > GZ_MERKLE_MAX_DEPTH) fz->broken++;
    if (mp.depth < 32 && (mp.pos >> mp.depth) != 0) fz->broken++;
    /* a proof that verifies must be the real proof, bit for bit */
    if (gz_merkle_verify(fz->tx_a, &mp, fz->header)) {
      if (mp.pos != fz->real_proof.pos || mp.depth != fz->real_proof.depth ||
          memcmp(mp.nodes, fz->real_proof.nodes, (size_t)mp.depth * GZ_HASH_LEN) != 0)
        fz->forged++;
    }
  }

  gz_fee_estimates fe;
  if (gz_es_parse_fee_estimates(in, len, &fe)) {
    fz->accepted[5]++;
    if (fe.count > GZ_FEE_MAX_TARGETS) fz->broken++;
    for (size_t i = 0; i < fe.count && i < GZ_FEE_MAX_TARGETS; i++) {
      if (fe.entries[i].target < 1 || fe.entries[i].target > GZ_ES_MAX_FEE_TARGET) fz->broken++;
      if (i > 0 && fe.entries[i - 1].target >= fe.entries[i].target) fz->broken++;
    }
  }

  uint32_t height;
  uint8_t hdr[GZ_HEADER_LEN], hash[GZ_HASH_LEN];
  if (gz_es_parse_height(in, len, &height)) {
    fz->accepted[6]++;
    if (height > GZ_MAX_HEIGHT) fz->broken++;
  }
  (void)gz_es_parse_header(in, len, hdr);
  (void)gz_hash_from_hex(in, len, hash);

  /* the transaction parser, on the input as hex and on the raw bytes */
  uint8_t *raw = malloc(len / 2 + 1);
  size_t raw_len = 0;
  if (raw == NULL) exit(2);
  if (gz_hex_decode(in, len, raw, len / 2, &raw_len)) {
    uint8_t *exact = malloc(raw_len ? raw_len : 1);
    if (exact == NULL) exit(2);
    memcpy(exact, raw, raw_len);
    if (gz_txid_from_raw(exact, raw_len, hash)) fz->accepted[7]++;
    free(exact);
  }
  free(raw);
  (void)gz_txid_from_raw((const uint8_t *)in, len, hash);
}

static void test_mutated_answers(test_state *T) {
  uint64_t seed = UINT64_C(0x9E3779B97F4A7C15);
  unsigned long iters = 40000;
  const char *env;
  if ((env = getenv("GZ_FUZZ_SEED")) != NULL && *env) seed = strtoull(env, NULL, 0);
  if ((env = getenv("GZ_FUZZ_ITERS")) != NULL && *env) iters = strtoul(env, NULL, 0);
  if (seed == 0) seed = 1;
  printf("mutation run: seed 0x%llx, %lu iterations per recorded answer, %zu answers\n",
         (unsigned long long)seed, iters, CORPUS_COUNT);

  fuzz_ctx fz;
  memset(&fz, 0, sizeof fz);
  test_hash(TX_A, fz.tx_a);
  size_t len;
  char *hex = test_read_data("header_329438.txt", &len);
  CHECK(gz_es_parse_header(hex, len, fz.header));
  free(hex);
  char *proof = test_read_data("tx_a_merkle_proof.json", &len);
  CHECK(gz_es_parse_merkle_proof(proof, len, &fz.real_proof));
  free(proof);

  for (size_t c = 0; c < CORPUS_COUNT; c++) {
    corpus[c].data = test_read_data(corpus[c].file, &corpus[c].len);
    /* the untouched answer first */
    char *same = malloc(corpus[c].len ? corpus[c].len : 1);
    if (same == NULL) exit(2);
    memcpy(same, corpus[c].data, corpus[c].len);
    run_parsers(&fz, same, corpus[c].len);
    free(same);
  }
  /* every recorded answer is accepted by its own parser when undamaged */
  CHECK(fz.accepted[1] == 1 && fz.accepted[2] == 2 && fz.accepted[3] == 1);
  CHECK(fz.accepted[4] == 1 && fz.accepted[5] == 2 && fz.accepted[7] == 1);

  uint64_t rng = seed;
  for (size_t c = 0; c < CORPUS_COUNT; c++) {
    size_t cap = corpus[c].len + 64;
    char *work = malloc(cap);
    if (work == NULL) exit(2);
    for (unsigned long i = 0; i < iters; i++) {
      memcpy(work, corpus[c].data, corpus[c].len);
      size_t cur = corpus[c].len;
      unsigned changes = 1 + (unsigned)(test_rand(&rng) % 4);
      for (unsigned m = 0; m < changes; m++) cur = mutate(&rng, work, cur, cap);
      char *exact = malloc(cur ? cur : 1);
      if (exact == NULL) exit(2);
      memcpy(exact, work, cur);
      run_parsers(&fz, exact, cur);
      free(exact);
    }
    free(work);
  }
  printf("accepted after damage: json %lu, status %lu, outspend %lu, utxo %lu, proof %lu, "
         "fees %lu, height %lu, tx %lu\n",
         fz.accepted[0], fz.accepted[1], fz.accepted[2], fz.accepted[3], fz.accepted[4],
         fz.accepted[5], fz.accepted[6], fz.accepted[7]);
  CHECK(fz.broken == 0);
  CHECK(fz.forged == 0);
  for (size_t c = 0; c < CORPUS_COUNT; c++) free(corpus[c].data);
}

/* Random bytes with no structure at all, and every short prefix of each
 * recorded answer. */
static void test_garbage_and_prefixes(test_state *T) {
  fuzz_ctx fz;
  uint64_t rng = UINT64_C(0xD1B54A32D192ED03);
  memset(&fz, 0, sizeof fz);
  for (int i = 0; i < 20000; i++) {
    size_t len = (size_t)(test_rand(&rng) % 200);
    char *buf = malloc(len ? len : 1);
    if (buf == NULL) exit(2);
    for (size_t k = 0; k < len; k++) buf[k] = (char)test_rand(&rng);
    run_parsers(&fz, buf, len);
    free(buf);
  }
  for (size_t c = 0; c < CORPUS_COUNT; c++) {
    size_t len;
    char *data = test_read_data(corpus[c].file, &len);
    for (size_t cut = 0; cut < len; cut++) {
      char *buf = malloc(cut ? cut : 1);
      if (buf == NULL) exit(2);
      memcpy(buf, data, cut);
      run_parsers(&fz, buf, cut);
      free(buf);
    }
    free(data);
  }
  CHECK(fz.broken == 0 && fz.forged == 0);
  /* no strict prefix of a JSON answer is itself accepted by its parser */
  CHECK(fz.accepted[1] == 0 && fz.accepted[2] == 0 && fz.accepted[3] == 0);
  CHECK(fz.accepted[4] == 0 && fz.accepted[5] == 0);
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  RUN(test_mutated_answers);
  RUN(test_garbage_and_prefixes);
  TEST_MAIN_END("test_fuzz");
}
