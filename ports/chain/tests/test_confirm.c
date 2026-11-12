/*
 * gz_chain_confirm_tx against a backend that serves a fabricated chain:
 * blocks whose Merkle trees are built here, with headers that meet signet's
 * proof-of-work limit (their nonces were ground once and are listed in
 * fab_nonces.h). A backend can say anything, so these tests show what each
 * step of the check stops on its own, with every other step passing.
 *
 * The attacks need no 64-byte transaction to be fetched: a block may hold a
 * 64-byte transaction X whose bytes are txid(F) followed by 32 more bytes,
 * and a server can then "prove" F one level below X. The coinbase steps
 * (its branch's depth, the branch itself, that it is a coinbase, that it
 * has one input, that no coinbase sits elsewhere) are what catch that. In
 * the trees below, "N(a, b)" is such a node: sha256d(a || b), which is what
 * a 64-byte transaction a||b would hash to.
 *
 *   GZ_FAB_GRIND=1 chain_test_confirm   grinds the nonces again and prints
 *                                       fab_nonces.h (a few minutes)
 */
#include "test.h"

#include "fab_nonces.h"

#define H0 500000u
#define SIGNET_BITS 0x1e0377aeu
#define FAB_MAX_TX 8
#define FAB_MAX_HEADERS (1 + FAB_LONG_CHAIN)

typedef struct fab_tx {
  uint8_t id[GZ_HASH_LEN];
  uint8_t raw[200];
  size_t len;
} fab_tx;

typedef struct fab {
  uint8_t headers[FAB_MAX_HEADERS][GZ_HEADER_LEN]; /* heights H0, H0 + 1, ... */
  uint32_t n_headers;
  gz_block_summary summary;
  fab_tx tx[FAB_MAX_TX];
  size_t n_tx;
  struct {
    uint8_t id[GZ_HASH_LEN];
    gz_merkle_proof p;
  } proof[FAB_MAX_TX];
  size_t n_proof;
  uint8_t confirmed[GZ_HASH_LEN]; /* the one transaction said to be confirmed at H0 */
  /* when asked for this txid's bytes, return those of tx[swap_to] */
  bool swap;
  uint8_t swap_id[GZ_HASH_LEN];
  size_t swap_to;
} fab;

/* ---- the backend ---- */

static void header_id(const fab *f, uint32_t height, uint8_t out[GZ_HASH_LEN]) {
  gz_header_hash(f->headers[height - H0], out);
}

static bool have_height(const fab *f, uint32_t height) {
  return height >= H0 && height - H0 < f->n_headers;
}

static gz_chain_result fab_tip(void *ctx, gz_chain_tip *out) {
  const fab *f = ctx;
  out->height = H0 + f->n_headers - 1;
  header_id(f, out->height, out->hash);
  return GZ_CHAIN_OK;
}

static gz_chain_result fab_block_hash(void *ctx, uint32_t height, uint8_t out[GZ_HASH_LEN]) {
  const fab *f = ctx;
  if (height == 0) return gz_network_genesis(GZ_NET_SIGNET, out) ? GZ_CHAIN_OK : GZ_CHAIN_MALFORMED;
  if (!have_height(f, height)) return GZ_CHAIN_NOT_FOUND;
  header_id(f, height, out);
  return GZ_CHAIN_OK;
}

static gz_chain_result fab_header(void *ctx, uint32_t height, uint8_t out[GZ_HEADER_LEN]) {
  const fab *f = ctx;
  if (!have_height(f, height)) return GZ_CHAIN_NOT_FOUND;
  memcpy(out, f->headers[height - H0], GZ_HEADER_LEN);
  return GZ_CHAIN_OK;
}

static gz_chain_result fab_summary(void *ctx, uint32_t height, gz_block_summary *out) {
  const fab *f = ctx;
  if (height != H0) return GZ_CHAIN_NOT_FOUND;
  *out = f->summary;
  return GZ_CHAIN_OK;
}

static gz_chain_result fab_status(void *ctx, const uint8_t txid[GZ_HASH_LEN], gz_tx_status *out) {
  const fab *f = ctx;
  memset(out, 0, sizeof *out);
  if (memcmp(txid, f->confirmed, GZ_HASH_LEN) != 0) return GZ_CHAIN_OK; /* unknown */
  out->state = GZ_TX_CONFIRMED;
  out->height = H0;
  header_id(f, H0, out->block_hash);
  out->tip_height = H0 + f->n_headers - 1;
  out->claimed_confirmations = f->n_headers;
  return GZ_CHAIN_OK;
}

static gz_chain_result fab_raw(void *ctx, const uint8_t txid[GZ_HASH_LEN], uint8_t *buf, size_t cap,
                               size_t *len) {
  const fab *f = ctx;
  for (size_t i = 0; i < f->n_tx; i++) {
    const fab_tx *t = &f->tx[i];
    if (memcmp(t->id, txid, GZ_HASH_LEN) != 0) continue;
    if (f->swap && memcmp(f->swap_id, txid, GZ_HASH_LEN) == 0) t = &f->tx[f->swap_to];
    if (t->len > cap) return GZ_CHAIN_TOO_LARGE;
    memcpy(buf, t->raw, t->len);
    *len = t->len;
    return GZ_CHAIN_OK;
  }
  return GZ_CHAIN_NOT_FOUND;
}

static gz_chain_result fab_proof(void *ctx, const uint8_t txid[GZ_HASH_LEN], gz_merkle_proof *out) {
  const fab *f = ctx;
  for (size_t i = 0; i < f->n_proof; i++) {
    if (memcmp(f->proof[i].id, txid, GZ_HASH_LEN) == 0) {
      *out = f->proof[i].p;
      return GZ_CHAIN_OK;
    }
  }
  return GZ_CHAIN_NOT_FOUND;
}

static const gz_chain_ops fab_ops = {
    .tip = fab_tip,
    .block_hash = fab_block_hash,
    .block_header = fab_header,
    .block_summary = fab_summary,
    .tx_status = fab_status,
    .raw_tx = fab_raw,
    .merkle_proof = fab_proof,
};

/* ---- building blocks ---- */

static void put32(uint8_t *p, uint32_t v) {
  for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* kind 0: an ordinary transaction; 1: a coinbase; 2: coinbase-like, but a
 * second input after the null one. `tag` makes each one different. */
static const fab_tx *add_tx(fab *f, int kind, uint8_t tag) {
  fab_tx *t = &f->tx[f->n_tx++];
  uint8_t *o = t->raw;
  size_t p = 0;
  put32(o + p, kind == 0 ? 2 : 1);
  p += 4;
  o[p++] = kind == 2 ? 2 : 1; /* inputs */
  if (kind == 0) {
    memset(o + p, tag, 32);
    memset(o + p + 32, 0, 4);
  } else {
    memset(o + p, 0, 32);
    memset(o + p + 32, 0xff, 4); /* the null outpoint */
  }
  p += 36;
  o[p++] = 2;
  o[p++] = 0x01;
  o[p++] = tag; /* input script */
  memset(o + p, 0xff, 4);
  p += 4;
  if (kind == 2) {
    memset(o + p, tag, 32);
    memset(o + p + 32, 1, 4);
    p += 36;
    o[p++] = 0;
    memset(o + p, 0xff, 4);
    p += 4;
  }
  o[p++] = 1; /* outputs */
  memset(o + p, 0, 8);
  o[p] = tag;
  p += 8;
  o[p++] = 1;
  o[p++] = 0x51;
  put32(o + p, 0); /* locktime */
  p += 4;
  t->len = p;
  if (!gz_txid_from_raw(t->raw, t->len, t->id)) {
    fprintf(stderr, "test transaction does not parse\n");
    exit(2);
  }
  return t;
}

static void node(const uint8_t a[GZ_HASH_LEN], const uint8_t b[GZ_HASH_LEN], uint8_t out[GZ_HASH_LEN]) {
  uint8_t pair[64];
  memcpy(pair, a, 32);
  memcpy(pair + 32, b, 32);
  gz_sha256d(pair, 64, out);
}

static void add_proof(fab *f, const uint8_t id[GZ_HASH_LEN], uint32_t pos, uint32_t depth,
                      const uint8_t *nodes[]) {
  gz_merkle_proof *p = &f->proof[f->n_proof].p;
  memcpy(f->proof[f->n_proof].id, id, GZ_HASH_LEN);
  f->n_proof++;
  memset(p, 0, sizeof *p);
  p->block_height = H0;
  p->pos = pos;
  p->depth = depth;
  for (uint32_t i = 0; i < depth; i++) memcpy(p->nodes[i], nodes[i], GZ_HASH_LEN);
}

static void make_header(uint8_t h[GZ_HEADER_LEN], const uint8_t prev[GZ_HASH_LEN],
                        const uint8_t root[GZ_HASH_LEN], uint32_t time, uint32_t nonce) {
  put32(h, 0x20000000u);
  memcpy(h + 4, prev, 32);
  memcpy(h + 36, root, 32);
  put32(h + 68, time);
  put32(h + 72, SIGNET_BITS);
  put32(h + 76, nonce);
}

static bool grinding;
static uint32_t ground[FAB_N_NONCES];

/* The nonce for header number `which` (0..FAB_N_NONCES-1): from the table,
 * or found now when grinding. */
static uint32_t nonce_for(size_t which, uint8_t h[GZ_HEADER_LEN]) {
  if (!grinding) return fab_nonces[which];
  uint32_t n = 0;
  for (;; n++) {
    put32(h + 76, n);
    if (gz_header_check_pow(h, GZ_NET_SIGNET) == GZ_POW_OK) break;
  }
  ground[which] = n;
  return n;
}

/* The block at H0 with Merkle root `root`, then `later` headers on top. */
static void make_chain(test_state *T, fab *f, size_t block, const uint8_t root[GZ_HASH_LEN],
                       uint32_t later) {
  uint8_t prev[GZ_HASH_LEN], later_root[GZ_HASH_LEN];
  memset(prev, 0x11, sizeof prev);
  make_header(f->headers[0], prev, root, 1800000000u + (uint32_t)block, 0);
  put32(f->headers[0] + 76, nonce_for(block, f->headers[0]));
  for (uint32_t k = 1; k <= later; k++) {
    gz_header_hash(f->headers[k - 1], prev);
    memset(later_root, 0x22, sizeof later_root);
    later_root[0] = (uint8_t)k;
    make_header(f->headers[k], prev, later_root, 1800001000u + k, 0);
    put32(f->headers[k] + 76, nonce_for(FAB_BLOCKS + k - 1, f->headers[k]));
  }
  f->n_headers = 1 + later;
  for (uint32_t k = 0; k < f->n_headers; k++) {
    T->checks++;
    if (gz_header_check_pow(f->headers[k], GZ_NET_SIGNET) != GZ_POW_OK) {
      T->failed++;
      fprintf(stderr, "  fabricated header %u of block %zu fails proof of work: "
                      "fab_nonces.h is stale (GZ_FAB_GRIND=1 makes it again)\n",
              (unsigned)k, block);
      break;
    }
  }
  gz_header_hash(f->headers[0], f->summary.hash);
}

static gz_chain chain_of(fab *f) {
  gz_chain c = {f, &fab_ops};
  return c;
}

static gz_chain_result confirm(fab *f, const uint8_t id[GZ_HASH_LEN], uint32_t want,
                               gz_confirmation *out) {
  gz_chain c = chain_of(f);
  memcpy(f->confirmed, id, GZ_HASH_LEN);
  return gz_chain_confirm_tx(&c, GZ_NET_SIGNET, id, want, out);
}

/* ---- block 0: an honest two-transaction block, with a long chain on top ---- */

static void test_honest_block_and_depth_cap(test_state *T) {
  static fab f;
  gz_confirmation conf;
  memset(&f, 0, sizeof f);
  const fab_tx *cb = add_tx(&f, 1, 0x10), *t = add_tx(&f, 0, 0x11), *u = add_tx(&f, 0, 0x12);
  uint8_t root[GZ_HASH_LEN];
  node(cb->id, t->id, root);
  make_chain(T, &f, 0, root, FAB_LONG_CHAIN);
  f.summary.tx_count = 2;
  memcpy(f.summary.coinbase_txid, cb->id, GZ_HASH_LEN);
  add_proof(&f, t->id, 1, 1, (const uint8_t *[]){cb->id});
  add_proof(&f, cb->id, 0, 1, (const uint8_t *[]){t->id});

  CHECK_RESULT(confirm(&f, t->id, 1, &conf), GZ_CHAIN_OK);
  CHECK(conf.checked_confirmations == 1);
  CHECK_RESULT(confirm(&f, cb->id, 6, &conf), GZ_CHAIN_OK);
  CHECK(conf.checked_confirmations == 6);
  /* Review v14: the chain is longer than GZ_CONFIRM_MAX_DEPTH; asking for
   * more is cut to the limit */
  CHECK(f.n_headers > GZ_CONFIRM_MAX_DEPTH + 1);
  CHECK_RESULT(confirm(&f, t->id, 1000000, &conf), GZ_CHAIN_OK);
  CHECK(conf.checked_confirmations == GZ_CONFIRM_MAX_DEPTH);
  /* Review v5: the summary names another block than the status does (all
   * else in order): the depth and the coinbase it gives are not this
   * block's to give */
  f.summary.hash[0] ^= 1;
  CHECK_RESULT(confirm(&f, t->id, 1, &conf), GZ_CHAIN_BAD_PROOF);
  CHECK(conf.checked_confirmations == 0);
  f.summary.hash[0] ^= 1;
  /* Review v2: the backend answers with another transaction's bytes (one
   * not in the block): the id is not that of the bytes */
  f.swap = true;
  memcpy(f.swap_id, t->id, GZ_HASH_LEN);
  f.swap_to = (size_t)(u - f.tx);
  CHECK_RESULT(confirm(&f, t->id, 1, &conf), GZ_CHAIN_BAD_PROOF);
  f.swap = false;
  CHECK_RESULT(confirm(&f, t->id, 1, &conf), GZ_CHAIN_OK);
}

/* ---- block 1: [CB, N(F, R)], F claimed one level below a 64-byte transaction ---- */

static void test_coinbase_depth_pins_the_tree(test_state *T) {
  static fab f;
  gz_confirmation conf;
  memset(&f, 0, sizeof f);
  const fab_tx *cb = add_tx(&f, 1, 0x20), *fx = add_tx(&f, 0, 0x21);
  uint8_t r[GZ_HASH_LEN], n1[GZ_HASH_LEN], root[GZ_HASH_LEN], junk1[GZ_HASH_LEN], junk2[GZ_HASH_LEN];
  memset(r, 0x31, sizeof r);
  node(fx->id, r, n1); /* what a 64-byte transaction txid(F)||R hashes to */
  node(cb->id, n1, root);
  make_chain(T, &f, 1, root, 0);
  memcpy(f.summary.coinbase_txid, cb->id, GZ_HASH_LEN);

  /* control: the block as it is, two leaves; the coinbase confirms */
  f.summary.tx_count = 2;
  add_proof(&f, cb->id, 0, 1, (const uint8_t *[]){n1});
  CHECK_RESULT(confirm(&f, cb->id, 1, &conf), GZ_CHAIN_OK);

  /* The attack: three transactions claimed, so a depth of 2, and F at
   * position 2 below N. F's own branch is right and reaches the root. */
  f.summary.tx_count = 3;
  add_proof(&f, fx->id, 2, 2, (const uint8_t *[]){r, cb->id});
  CHECK(gz_merkle_verify(fx->id, &f.proof[1].p, f.headers[0]));
  /* Review v6: the real coinbase branch has depth 1, not 2 */
  CHECK_RESULT(confirm(&f, fx->id, 1, &conf), GZ_CHAIN_BAD_PROOF);
  /* Review v8: a coinbase branch of depth 2 that does not reach the root */
  memset(junk1, 0x41, sizeof junk1);
  memset(junk2, 0x42, sizeof junk2);
  add_proof(&f, cb->id, 0, 2, (const uint8_t *[]){junk1, junk2});
  f.proof[0] = f.proof[2]; /* the coinbase is now answered with this one */
  CHECK_RESULT(confirm(&f, fx->id, 1, &conf), GZ_CHAIN_BAD_PROOF);
  CHECK(conf.status.state == GZ_TX_UNKNOWN);
}

/* ---- blocks 2, 3, 4: [N(G, R0), N(F, R1)], both leaves 64-byte transactions ---- */

static void two_node_block(test_state *T, fab *f, size_t block, int g_kind, uint8_t g_tag,
                           int f_kind, uint8_t f_tag, const fab_tx **g, const fab_tx **fx) {
  uint8_t r0[GZ_HASH_LEN], r1[GZ_HASH_LEN], n0[GZ_HASH_LEN], n1[GZ_HASH_LEN], root[GZ_HASH_LEN];
  memset(f, 0, sizeof *f);
  *g = add_tx(f, g_kind, g_tag);
  *fx = add_tx(f, f_kind, f_tag);
  memset(r0, 0x30, sizeof r0);
  memset(r1, 0x31, sizeof r1);
  node((*g)->id, r0, n0);
  node((*fx)->id, r1, n1);
  node(n0, n1, root);
  make_chain(T, f, block, root, 0);
  f->summary.tx_count = 4; /* depth 2: G and F one level below the real leaves */
  memcpy(f->summary.coinbase_txid, (*g)->id, GZ_HASH_LEN);
  add_proof(f, (*fx)->id, 2, 2, (const uint8_t *[]){r1, n0});
  add_proof(f, (*g)->id, 0, 2, (const uint8_t *[]){r0, n1});
}

static void test_coinbase_must_be_a_coinbase(test_state *T) {
  static fab f;
  gz_confirmation conf;
  const fab_tx *g, *fx;
  /* Review v7: the "first transaction" is an ordinary one */
  two_node_block(T, &f, 2, 0, 0x22, 0, 0x21, &g, &fx);
  CHECK(!gz_tx_is_coinbase(g->raw, g->len));
  CHECK_RESULT(confirm(&f, fx->id, 1, &conf), GZ_CHAIN_BAD_PROOF);
  /* Review c14: it spends the null outpoint first, but has a second input */
  two_node_block(T, &f, 3, 2, 0x23, 0, 0x21, &g, &fx);
  CHECK(!gz_tx_is_coinbase(g->raw, g->len));
  CHECK_RESULT(confirm(&f, fx->id, 1, &conf), GZ_CHAIN_BAD_PROOF);
}

static void test_no_coinbase_after_the_first(test_state *T) {
  static fab f;
  gz_confirmation conf;
  const fab_tx *g, *fx;
  /* Review v9: G is a coinbase at position 0, and F, also a coinbase, is
   * "proved" at position 2 */
  two_node_block(T, &f, 4, 1, 0x24, 1, 0x25, &g, &fx);
  CHECK(gz_tx_is_coinbase(fx->raw, fx->len));
  CHECK_RESULT(confirm(&f, g->id, 1, &conf), GZ_CHAIN_OK); /* control: the block passes */
  CHECK_RESULT(confirm(&f, fx->id, 1, &conf), GZ_CHAIN_BAD_PROOF);
}

/* ---- block 5: four real leaves, a count of three claimed ---- */

static void test_position_below_the_count(test_state *T) {
  static fab f;
  gz_confirmation conf;
  memset(&f, 0, sizeof f);
  const fab_tx *cb = add_tx(&f, 1, 0x26), *a = add_tx(&f, 0, 0x27), *b = add_tx(&f, 0, 0x28),
               *t = add_tx(&f, 0, 0x29);
  uint8_t ab[GZ_HASH_LEN], bt[GZ_HASH_LEN], root[GZ_HASH_LEN];
  node(cb->id, a->id, ab);
  node(b->id, t->id, bt);
  node(ab, bt, root);
  make_chain(T, &f, 5, root, 0);
  memcpy(f.summary.coinbase_txid, cb->id, GZ_HASH_LEN);
  add_proof(&f, t->id, 3, 2, (const uint8_t *[]){b->id, ab});
  add_proof(&f, cb->id, 0, 2, (const uint8_t *[]){a->id, bt});
  f.summary.tx_count = 4;
  CHECK_RESULT(confirm(&f, t->id, 1, &conf), GZ_CHAIN_OK); /* control */
  /* Review v4: with three claimed, the depth is still 2 and the branch is
   * well formed (its left neighbour differs, so it is not the copied last
   * node), but position 3 is past the end of the block */
  f.summary.tx_count = 3;
  CHECK_RESULT(confirm(&f, t->id, 1, &conf), GZ_CHAIN_BAD_PROOF);
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  const char *g = getenv("GZ_FAB_GRIND");
  grinding = g != NULL && *g != '\0';
  RUN(test_honest_block_and_depth_cap);
  RUN(test_coinbase_depth_pins_the_tree);
  RUN(test_coinbase_must_be_a_coinbase);
  RUN(test_no_coinbase_after_the_first);
  RUN(test_position_below_the_count);
  if (grinding) {
    FILE *out = fopen("fab_nonces.h", "w");
    if (out == NULL) return 2;
    fprintf(out, "/* Nonces of the fabricated headers in test_confirm.c, which meet signet's\n"
                 " * proof-of-work limit. Made by GZ_FAB_GRIND=1 chain_test_confirm. */\n"
                 "#define FAB_BLOCKS %d\n#define FAB_LONG_CHAIN %d\n#define FAB_N_NONCES %d\n"
                 "static const uint32_t fab_nonces[FAB_N_NONCES] = {",
            FAB_BLOCKS, FAB_LONG_CHAIN, FAB_N_NONCES);
    for (size_t i = 0; i < FAB_N_NONCES; i++)
      fprintf(out, "%s%luu,", i % 6 == 0 ? "\n    " : " ", (unsigned long)ground[i]);
    fprintf(out, "\n};\n");
    fclose(out);
    printf("wrote fab_nonces.h\n");
  }
  TEST_MAIN_END("test_confirm");
}
