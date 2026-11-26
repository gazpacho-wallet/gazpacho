/* The made-up chain and its two servers. See sim.h. */
#define _POSIX_C_SOURCE 200809L

#include "sim.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gazpacho/chain_esplora.h"
#include "gazpacho/chain_multi.h"

#include "sim_nonces.h"
#include "../watch.h"

#define SIGNET_BITS 0x1e0377aeu
#define GENESIS_SIGNET "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
#define GENESIS_MAINNET "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
#define BODY_MAX 8192

static void put32(uint8_t *p, uint32_t v) {
  for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

void sim_hex(const uint8_t hash[GZ_HASH_LEN], char out[2 * GZ_HASH_LEN + 1]) {
  gz_hash_to_hex(hash, out);
}

static void plain_hex(const uint8_t *in, size_t len, char *out) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[2 * i] = digits[in[i] >> 4];
    out[2 * i + 1] = digits[in[i] & 15];
  }
  out[2 * len] = '\0';
}

/* ---- the world ----------------------------------------------------------- */

/* Which of the world's transactions t is, if a view gives it another
 * witness; -1 otherwise (a coinbase, or no other witness). */
static int alt_index(const sim_view *v, const sim_tx *t) {
  for (int k = 0; k < SIM_NTX; k++)
    if (t == &v->w->tx[k]) return v->alt_witness[k] ? k : -1;
  return -1;
}

static void finish_tx(sim_tx *t) {
  if (!gz_txid_from_raw(t->raw, t->len, t->id)) {
    fprintf(stderr, "sim: a made-up transaction does not parse\n");
    exit(2);
  }
}

/* One input spending prev:vout, one output; `tag` makes it its own. */
static void make_tx(sim_tx *t, const uint8_t prev[GZ_HASH_LEN], uint32_t vout, uint8_t tag) {
  uint8_t *o = t->raw;
  size_t p = 0;
  put32(o + p, 2);
  p += 4;
  o[p++] = 1;
  memcpy(o + p, prev, GZ_HASH_LEN);
  p += 32;
  put32(o + p, vout);
  p += 4;
  o[p++] = 0;
  memset(o + p, 0xff, 4);
  p += 4;
  o[p++] = 1;
  memset(o + p, 0, 8);
  o[p] = tag;
  p += 8;
  o[p++] = 1;
  o[p++] = 0x51;
  put32(o + p, 0);
  p += 4;
  t->len = p;
  finish_tx(t);
}

/* Two inputs, prev0:vout0 then prev1:vout1, one output. */
static void make_tx2(sim_tx *t, const uint8_t prev0[GZ_HASH_LEN], uint32_t vout0,
                     const uint8_t prev1[GZ_HASH_LEN], uint32_t vout1, uint8_t tag) {
  uint8_t *o = t->raw;
  size_t p = 0;
  put32(o + p, 2);
  p += 4;
  o[p++] = 2;
  for (int k = 0; k < 2; k++) {
    memcpy(o + p, k ? prev1 : prev0, GZ_HASH_LEN);
    p += 32;
    put32(o + p, k ? vout1 : vout0);
    p += 4;
    o[p++] = 0;
    memset(o + p, 0xff, 4);
    p += 4;
  }
  o[p++] = 1;
  memset(o + p, 0, 8);
  o[p] = tag;
  p += 8;
  o[p++] = 1;
  o[p++] = 0x51;
  put32(o + p, 0);
  p += 4;
  t->len = p;
  finish_tx(t);
}

static void make_coinbase(sim_tx *t, int branch, uint32_t height) {
  uint8_t *o = t->raw;
  size_t p = 0;
  put32(o + p, 1);
  p += 4;
  o[p++] = 1;
  memset(o + p, 0, 32);
  memset(o + p + 32, 0xff, 4);
  p += 36;
  o[p++] = 4;
  o[p++] = (uint8_t)branch;
  o[p++] = (uint8_t)(height & 0xff);
  o[p++] = (uint8_t)(height >> 8);
  o[p++] = 0x01;
  memset(o + p, 0xff, 4);
  p += 4;
  o[p++] = 1;
  memset(o + p, 0, 8);
  o[p] = 50;
  p += 8;
  o[p++] = 1;
  o[p++] = 0x51;
  put32(o + p, 0);
  p += 4;
  t->len = p;
  finish_tx(t);
}

static void merkle_root(const sim_world *w, const sim_block *b, uint8_t out[GZ_HASH_LEN]) {
  if (b->tx < 0) {
    memcpy(out, b->coinbase.id, GZ_HASH_LEN);
    return;
  }
  uint8_t pair[64];
  memcpy(pair, b->coinbase.id, 32);
  memcpy(pair + 32, w->tx[b->tx].id, 32);
  gz_sha256d(pair, 64, out);
}

static bool grinding;

static void make_block(sim_world *w, sim_block *b, const sim_block *prev, int branch,
                       uint32_t height, int tx, size_t nonce_index) {
  uint8_t *h = b->header;
  b->height = height;
  b->tx = tx;
  make_coinbase(&b->coinbase, branch, height);
  put32(h, 0x20000000u);
  if (prev != NULL) {
    memcpy(h + 4, prev->id, GZ_HASH_LEN);
  } else {
    memset(h + 4, 0x77, GZ_HASH_LEN); /* the block before the first is not served */
  }
  merkle_root(w, b, h + 36);
  put32(h + 68, 1800000000u + height);
  put32(h + 72, SIGNET_BITS);
  uint32_t nonce = sim_nonces[nonce_index];
  put32(h + 76, nonce);
  if (grinding) {
    for (nonce = 0;; nonce++) {
      put32(h + 76, nonce);
      if (gz_header_check_pow(h, GZ_NET_SIGNET) == GZ_POW_OK) break;
    }
    printf("    %uu,%s", nonce, nonce_index % 4 == 3 ? "\n" : "");
  } else if (gz_header_check_pow(h, GZ_NET_SIGNET) != GZ_POW_OK) {
    fprintf(stderr, "sim: nonce %zu in sim_nonces.h does not fit its header any more; run\n"
                    "  GZ_SIM_GRIND=1 chain_test_watch > ports/chain/tests/sim_nonces.h\n",
            nonce_index);
    exit(2);
  }
  gz_header_hash(h, b->id);
}

void sim_world_init(sim_world *w) {
  uint8_t r[GZ_HASH_LEN];
  memset(w, 0, sizeof *w);
  memset(w->q, 0x11, sizeof w->q);
  memset(r, 0x33, sizeof r);
  memset(w->p, 0x22, sizeof w->p);
  make_tx(&w->tx[SIM_T], w->q, 0, 1);
  make_tx(&w->tx[SIM_S1], w->p, 0, 2);
  make_tx2(&w->tx[SIM_S2], r, 5, w->p, 0, 3);
  make_tx(&w->tx[SIM_K], w->tx[SIM_T].id, 0, 4);

  grinding = getenv("GZ_SIM_GRIND") != NULL;
  if (grinding) {
    printf("/* Nonces of the made-up headers in sim.c, which meet signet's\n"
           " * proof-of-work limit. Made by GZ_SIM_GRIND=1 chain_test_watch. */\n"
           "static const uint32_t sim_nonces[%u] = {\n",
           SIM_BLOCKS);
  }
  size_t k = 0;
  for (uint32_t i = 0; i < SIM_COMMON; i++)
    make_block(w, &w->common[i], i ? &w->common[i - 1] : NULL, 2, SIM_H0 + i, -1, k++);
  for (int br = 0; br < 2; br++) {
    for (uint32_t j = 0; j < SIM_LEN - SIM_COMMON; j++) {
      uint32_t height = SIM_H0 + SIM_COMMON + j;
      int tx = -1;
      if (br == SIM_A && height == SIM_H0 + 5) tx = SIM_T;
      if (br == SIM_A && height == SIM_H0 + 6) tx = SIM_S1;
      if (br == SIM_A && height == SIM_H0 + 7) tx = SIM_K;
      if (br == SIM_B && height == SIM_H0 + 6) tx = SIM_T;
      if (br == SIM_B && height == SIM_H0 + 7) tx = SIM_S2;
      make_block(w, &w->branch[br][j], j ? &w->branch[br][j - 1] : &w->common[SIM_COMMON - 1], br,
                 height, tx, k++);
    }
  }
  for (uint32_t j = 0; j < SIM_C_LEN; j++) {
    make_block(w, &w->c[j], j ? &w->c[j - 1] : &w->branch[SIM_A][2], 3, SIM_H0 + 7 + j,
               j == 0 ? SIM_K : -1, k++);
  }
  /* the same block as a6 with a nonce that does not meet the target */
  w->weak = w->branch[SIM_A][2];
  do {
    w->weak.header[76]++;
  } while (gz_header_check_pow(w->weak.header, GZ_NET_SIGNET) == GZ_POW_OK);
  gz_header_hash(w->weak.header, w->weak.id);
  if (grinding) {
    printf("};\n");
    exit(0);
  }
}

const sim_block *sim_block_of(const sim_world *w, int branch, uint32_t height) {
  if (height < SIM_H0 || height > SIM_TOP) return NULL;
  uint32_t i = height - SIM_H0;
  if (branch == SIM_C) {
    if (height > SIM_C_TOP) return NULL;
    if (i >= 7) return &w->c[i - 7];
    branch = SIM_A;
  }
  return i < SIM_COMMON ? &w->common[i] : &w->branch[branch][i - SIM_COMMON];
}

/* ---- a view -------------------------------------------------------------- */

void sim_view_init(sim_view *v, const sim_world *w, int branch, uint32_t tip) {
  memset(v, 0, sizeof *v);
  v->w = w;
  v->branch = branch;
  v->tip = tip;
}

static uint32_t view_top(const sim_view *v) {
  uint32_t limit = v->branch == SIM_C ? SIM_C_TOP : SIM_TOP;
  return v->tip < limit ? v->tip : limit;
}

static const sim_block *view_block(const sim_view *v, uint32_t height) {
  if (height > view_top(v)) return NULL;
  if (v->weak && height == SIM_H0 + 6 && v->branch == SIM_A) return &v->w->weak;
  if (v->graft_below != 0 && height < v->graft_below && height >= SIM_H0 + SIM_COMMON &&
      v->branch != SIM_C)
    return sim_block_of(v->w, 1 - v->branch, height);
  if (v->graft != 0 && height >= v->graft && v->branch != SIM_C)
    return sim_block_of(v->w, 1 - v->branch, height);
  return sim_block_of(v->w, v->branch, height);
}

/* 2: confirmed (in *blk at *pos); 1: in the mempool; 0: unknown to the view. */
static int find_tx(const sim_view *v, const uint8_t id[GZ_HASH_LEN], const sim_block **blk,
                   const sim_tx **tx, uint32_t *pos) {
  for (uint32_t h = SIM_H0; h <= view_top(v); h++) {
    const sim_block *b = view_block(v, h);
    if (memcmp(b->coinbase.id, id, GZ_HASH_LEN) == 0) {
      *blk = b;
      *tx = &b->coinbase;
      *pos = 0;
      return 2;
    }
    if (b->tx >= 0 && !v->hide[b->tx] && memcmp(v->w->tx[b->tx].id, id, GZ_HASH_LEN) == 0) {
      *blk = b;
      *tx = &v->w->tx[b->tx];
      *pos = 1;
      return 2;
    }
  }
  for (int i = 0; i < SIM_NTX; i++) {
    if (v->mempool[i] && !v->hide[i] && memcmp(v->w->tx[i].id, id, GZ_HASH_LEN) == 0) {
      *tx = &v->w->tx[i];
      return 1;
    }
  }
  return 0;
}

static size_t status_json(const sim_view *v, const sim_block *b, char *out, size_t cap) {
  char hex[65];
  if (b == NULL) return (size_t)snprintf(out, cap, "{\"confirmed\":false}");
  sim_hex(b->id, hex);
  return (size_t)snprintf(out, cap,
                          "{\"confirmed\":true,\"block_height\":%u,\"block_hash\":\"%s\","
                          "\"block_time\":%u}",
                          (unsigned)((int)b->height + v->lie_height), hex, 1800000000u + b->height);
}

static bool world_tx_index(const sim_world *w, const uint8_t id[GZ_HASH_LEN], int *index) {
  for (int i = 0; i < SIM_NTX; i++) {
    if (memcmp(w->tx[i].id, id, GZ_HASH_LEN) == 0) {
      *index = i;
      return true;
    }
  }
  return false;
}

/* Marks a broadcast transaction as in the view's mempool, if it is one of
 * the world's and not already in the view's chain. */
static void into_mempool(sim_view *v, const uint8_t id[GZ_HASH_LEN]) {
  const sim_block *b = NULL;
  const sim_tx *t = NULL;
  uint32_t pos = 0;
  int i = 0;
  if (world_tx_index(v->w, id, &i) && find_tx(v, id, &b, &t, &pos) == 0) v->mempool[i] = true;
}

static size_t package_json(const uint8_t parent[GZ_HASH_LEN], const uint8_t child[GZ_HASH_LEN],
                           bool ok, bool parent_known, char *out, size_t cap) {
  char p[65], c[65], pk[96], ck[96];
  sim_hex(parent, p);
  sim_hex(child, c);
  /* "other-wtxid" is a wtxid; these transactions' own ids stand in for it */
  pk[0] = ck[0] = '\0';
  if (parent_known) {
    snprintf(pk, sizeof pk, "\"other-wtxid\":\"%s\",", p);
    snprintf(ck, sizeof ck, "\"other-wtxid\":\"%s\",", c);
  }
  if (ok)
    return (size_t)snprintf(
        out, cap,
        "{\"package_msg\":\"success\",\"tx-results\":{\"%s\":{\"txid\":\"%s\",\"vsize\":61,%s"
        "\"fees\":{\"base\":0.00000000}},\"%s\":{\"txid\":\"%s\",\"vsize\":61,%s\"fees\":{\"base\":"
        "0.00000100,\"effective-feerate\":0.00000819,\"effective-includes\":[\"%s\",\"%s\"]}}},"
        "\"replaced-transactions\":[]}",
        p, p, pk, c, c, ck, p, c);
  return (size_t)snprintf(
      out, cap,
      "{\"package_msg\":\"transaction failed\",\"tx-results\":{\"%s\":{\"txid\":\"%s\",\"error\":"
      "\"min relay fee not met, 0 < 61\"},\"%s\":{\"txid\":\"%s\",\"error\":"
      "\"bad-txns-inputs-missingorspent\"}},\"replaced-transactions\":[]}",
      p, p, c, c);
}

/* "success", listing the parent only: an answer that contradicts itself. */
static size_t package_lie_json(const uint8_t parent[GZ_HASH_LEN], char *out, size_t cap) {
  char p[65];
  sim_hex(parent, p);
  return (size_t)snprintf(out, cap,
                          "{\"package_msg\":\"success\",\"tx-results\":{\"%s\":{\"txid\":\"%s\","
                          "\"vsize\":61}},\"replaced-transactions\":[]}",
                          p, p);
}

/* The two hex strings of ["..",".."], decoded. */
static bool package_body(const uint8_t *body, size_t len, uint8_t parent[GZ_HASH_LEN],
                         uint8_t child[GZ_HASH_LEN]) {
  uint8_t raw[200];
  size_t n = 0, at = 0;
  for (int k = 0; k < 2; k++) {
    while (at < len && body[at] != '"') at++;
    size_t start = ++at;
    while (at < len && body[at] != '"') at++;
    if (at >= len) return false;
    if (!gz_hex_decode((const char *)body + start, at - start, raw, sizeof raw, &n)) return false;
    if (!gz_txid_from_raw(raw, n, k == 0 ? parent : child)) return false;
    at++;
  }
  return true;
}

static bool honest(sim_view *v, bool post, const char *path, const uint8_t *body, size_t body_len,
                   char *out, size_t cap, long *status, size_t *len, int *failure) {
  char hex[65];
  uint8_t id[GZ_HASH_LEN];
  *status = 200;
  *len = 0;
  if (post) {
    uint8_t raw[200], parent[GZ_HASH_LEN], child[GZ_HASH_LEN];
    size_t n = 0;
    if (strcmp(path, "/tx") == 0) {
      v->posts++;
      if (v->post == SIM_POST_DOWN) {
        *failure = GZ_HTTP_E_CONNECT;
        return false;
      }
      if (!gz_hex_decode((const char *)body, body_len, raw, sizeof raw, &n) ||
          !gz_txid_from_raw(raw, n, id)) {
        *status = 400;
        *len = (size_t)snprintf(out, cap, "sendrawtransaction RPC error: TX decode failed");
        return true;
      }
      if (v->post == SIM_POST_REJECT && v->reject_reason != NULL) {
        *status = 400;
        *len = (size_t)snprintf(out, cap, "%s", v->reject_reason);
        return true;
      }
      if (v->post == SIM_POST_REJECT) {
        *status = 400;
        *len = (size_t)snprintf(out, cap,
                                "sendrawtransaction RPC error: {\"code\":-26,\"message\":"
                                "\"min relay fee not met, 6 < 11\"}");
        return true;
      }
      into_mempool(v, id);
      if (v->post == SIM_POST_KNOWN) {
        *status = 400;
        *len = (size_t)snprintf(out, cap,
                                "sendrawtransaction RPC error: {\"code\":-27,\"message\":"
                                "\"Transaction outputs already in utxo set\"}");
        return true;
      }
      sim_hex(id, hex);
      *len = (size_t)snprintf(out, cap, "%s", hex);
      return true;
    }
    bool first = strcmp(path, "/txs/package") == 0, second = strcmp(path, "/v1/txs/package") == 0;
    if (first || second) {
      v->packages++;
      if (v->package == SIM_PKG_DOWN) {
        *failure = GZ_HTTP_E_CONNECT;
        return false;
      }
      if (first && v->package == SIM_PKG_BUSY_FIRST) {
        *status = 429;
        *len = (size_t)snprintf(out, cap, "Too Many Requests");
        return true;
      }
      bool here = (first && (v->package == SIM_PKG_OK || v->package == SIM_PKG_FAIL ||
                             v->package == SIM_PKG_KNOWN || v->package == SIM_PKG_LIE)) ||
                  (second && (v->package == SIM_PKG_OK_V1 || v->package == SIM_PKG_BUSY_FIRST));
      if (!here) {
        *status = 404;
        *len = (size_t)snprintf(out, cap, "endpoint does not exist \"%s\"", path);
        return true;
      }
      if (!package_body(body, body_len, parent, child)) {
        *status = 400;
        *len = (size_t)snprintf(out, cap, "invalid package");
        return true;
      }
      if (v->package == SIM_PKG_LIE) {
        *len = package_lie_json(parent, out, cap);
        return true;
      }
      if (v->package != SIM_PKG_FAIL) {
        into_mempool(v, parent);
        into_mempool(v, child);
      }
      *len = package_json(parent, child, v->package != SIM_PKG_FAIL, v->package == SIM_PKG_KNOWN,
                          out, cap);
      return true;
    }
    *status = 404;
    return true;
  }
  if (strcmp(path, "/blocks/tip/height") == 0) {
    *len = (size_t)snprintf(out, cap, "%u", v->claim_tip != 0 ? v->claim_tip : view_top(v));
    return true;
  }
  if (strncmp(path, "/block-height/", 14) == 0) {
    char *end = NULL;
    unsigned long h = strtoul(path + 14, &end, 10);
    const sim_block *b = *end == '\0' && h <= 0xffffffffu ? view_block(v, (uint32_t)h) : NULL;
    if (*end == '\0' && h == 0) {
      *len = (size_t)snprintf(out, cap, "%s", v->mainnet ? GENESIS_MAINNET : GENESIS_SIGNET);
    } else if (b != NULL) {
      sim_hex(b->id, hex);
      *len = (size_t)snprintf(out, cap, "%s", hex);
    } else {
      *status = 404;
      *len = (size_t)snprintf(out, cap, "Block not found");
    }
    return true;
  }
  if (strncmp(path, "/block/", 7) == 0 && strlen(path) >= 7 + 64 &&
      gz_hash_from_hex(path + 7, 64, id)) {
    const char *rest = path + 7 + 64;
    const sim_block *b = NULL;
    for (uint32_t h = SIM_H0; h <= view_top(v); h++) {
      const sim_block *c = view_block(v, h);
      if (memcmp(c->id, id, GZ_HASH_LEN) == 0) b = c;
    }
    if (b == NULL) {
      *status = 404;
      *len = (size_t)snprintf(out, cap, "Block not found");
    } else if (strcmp(rest, "/header") == 0) {
      char h160[161];
      plain_hex(b->header, GZ_HEADER_LEN, h160);
      *len = (size_t)snprintf(out, cap, "%s", h160);
    } else if (strcmp(rest, "/txid/0") == 0) {
      sim_hex(b->coinbase.id, hex);
      *len = (size_t)snprintf(out, cap, "%s", hex);
    } else if (rest[0] == '\0') {
      char root[65], prev[65];
      uint8_t r[GZ_HASH_LEN];
      merkle_root(v->w, b, r);
      sim_hex(r, root);
      sim_hex(b->header + 4, prev);
      sim_hex(b->id, hex);
      bool shown = b->tx >= 0 && !v->hide[b->tx];
      *len = (size_t)snprintf(
          out, cap,
          "{\"id\":\"%s\",\"height\":%u,\"version\":536870912,\"timestamp\":%u,\"tx_count\":%d,"
          "\"size\":300,\"weight\":1200,\"merkle_root\":\"%s\",\"previousblockhash\":\"%s\","
          "\"mediantime\":%u,\"nonce\":%u,\"bits\":%u,\"difficulty\":0.0481}",
          hex, b->height, 1800000000u + b->height, shown ? 2 : 1, root, prev,
          1800000000u + b->height - 3,
          (unsigned)b->header[76] | (unsigned)b->header[77] << 8 | (unsigned)b->header[78] << 16 |
              (unsigned)b->header[79] << 24,
          SIGNET_BITS);
    } else {
      *status = 404;
    }
    return true;
  }
  if (strncmp(path, "/tx/", 4) == 0 && strlen(path) >= 4 + 64 && gz_hash_from_hex(path + 4, 64, id)) {
    const char *rest = path + 4 + 64;
    const sim_block *b = NULL;
    const sim_tx *t = NULL;
    uint32_t pos = 0;
    int known = find_tx(v, id, &b, &t, &pos);
    if (strcmp(rest, "/status") == 0) {
      if (v->pin_t && memcmp(id, v->w->tx[SIM_T].id, GZ_HASH_LEN) == 0)
        *len = status_json(v, sim_block_of(v->w, SIM_A, SIM_H0 + 5), out, cap);
      else
        *len = status_json(v, known == 2 ? b : NULL, out, cap);
    } else if (strcmp(rest, "/hex") == 0) {
      if (known == 0) {
        *status = 404;
        *len = (size_t)snprintf(out, cap, "Transaction not found");
      } else if (alt_index(v, t) >= 0 && t->raw[4] == 1) {
        /* the same transaction with a witness: marker and flag after the
         * version, one item for its one input before the lock time */
        uint8_t wit[sizeof t->raw + 8];
        char h[2 * sizeof wit + 1];
        size_t n = 0;
        memcpy(wit, t->raw, 4);
        n = 4;
        wit[n++] = 0;
        wit[n++] = 1;
        memcpy(wit + n, t->raw + 4, t->len - 8);
        n += t->len - 8;
        wit[n++] = 1;
        wit[n++] = 1;
        wit[n++] = 0x77;
        memcpy(wit + n, t->raw + t->len - 4, 4);
        n += 4;
        plain_hex(wit, n, h);
        *len = (size_t)snprintf(out, cap, "%s", h);
      } else {
        char h[2 * sizeof t->raw + 1];
        plain_hex(t->raw, t->len, h);
        *len = (size_t)snprintf(out, cap, "%s", h);
      }
    } else if (strcmp(rest, "/merkle-proof") == 0) {
      if (known != 2) {
        *status = 404;
        *len = (size_t)snprintf(out, cap, "Transaction not found or is unconfirmed");
      } else if (b->tx < 0 || v->hide[b->tx]) {
        *len = (size_t)snprintf(out, cap, "{\"block_height\":%u,\"merkle\":[],\"pos\":0}", b->height);
      } else {
        sim_hex(pos == 0 ? v->w->tx[b->tx].id : b->coinbase.id, hex);
        *len = (size_t)snprintf(out, cap, "{\"block_height\":%u,\"merkle\":[\"%s\"],\"pos\":%u}",
                                b->height, hex, pos);
      }
    } else if (strncmp(rest, "/outspend/", 10) == 0) {
      unsigned long n = strtoul(rest + 10, NULL, 10);
      const sim_tx *spender = NULL;
      const sim_block *sb = NULL;
      uint32_t spender_vin = 0;
      for (int i = 0; i < SIM_NTX && sb == NULL; i++) {
        const sim_tx *c = &v->w->tx[i];
        const sim_block *cb = NULL;
        const sim_tx *ct = NULL;
        uint32_t cpos = 0, vin = 0, cvout = 0;
        uint8_t cprev[GZ_HASH_LEN];
        bool spends = false;
        for (vin = 0; vin < 2 && !spends; vin++) {
          spends = gz_watch_tx_input(c->raw, c->len, vin, cprev, &cvout) &&
                   memcmp(cprev, id, GZ_HASH_LEN) == 0 && cvout == n;
        }
        if (!spends) continue;
        int ck = find_tx(v, c->id, &cb, &ct, &cpos);
        if (ck == 2) {
          spender = c;
          sb = cb;
          spender_vin = vin - 1;
        } else if (ck == 1 && spender == NULL) {
          spender = c;
          spender_vin = vin - 1;
        }
      }
      if (spender == NULL) {
        *len = (size_t)snprintf(out, cap, "{\"spent\":false}");
      } else {
        char st[256];
        status_json(v, sb, st, sizeof st);
        sim_hex(spender->id, hex);
        *len = (size_t)snprintf(out, cap, "{\"spent\":true,\"txid\":\"%s\",\"vin\":%u,\"status\":%s}",
                                hex, spender_vin, st);
      }
    } else {
      *status = 404;
    }
    return true;
  }
  *status = 404;
  *len = (size_t)snprintf(out, cap, "not found");
  return true;
}

bool sim_respond(sim_view *v, bool post, const char *path, const uint8_t *body, size_t body_len,
                 char *out, size_t cap, long *status, size_t *len, int *failure) {
  static char full[BODY_MAX]; /* callers hold the net's lock, or are single-threaded */
  size_t n = 0;
  *failure = GZ_HTTP_OK;
  bool hit = v->fault != SIM_FAULT_NONE && (v->fault_path == NULL || strstr(path, v->fault_path));
  if (hit && v->fault == SIM_FAULT_DOWN) {
    *failure = GZ_HTTP_E_CONNECT;
    return false;
  }
  if (hit && v->fault == SIM_FAULT_TIMEOUT) {
    *failure = GZ_HTTP_E_TIMEOUT;
    return false;
  }
  bool flip_now = v->flip_path != NULL && strstr(path, v->flip_path) != NULL &&
                  ++v->flip_seen == v->flip_after;
  bool answered = honest(v, post, path, body, body_len, full, sizeof full, status, &n, failure);
  if (flip_now) v->branch = v->flip_to;
  if (!answered) return false;
  if (n >= sizeof full) n = sizeof full - 1;
  if (hit) {
    switch (v->fault) {
      case SIM_FAULT_500:
        *status = 500;
        n = (size_t)snprintf(full, sizeof full, "busy");
        break;
      case SIM_FAULT_GARBAGE:
        *status = 200;
        n = v->garbage_len < sizeof full ? v->garbage_len : sizeof full;
        if (n) memcpy(full, v->garbage, n);
        break;
      case SIM_FAULT_TRUNCATE:
        if (n > v->cut) n = v->cut;
        break;
      case SIM_FAULT_HUGE:
        *len = cap + 1000;
        memset(out, '9', cap);
        return true;
      case SIM_FAULT_FLIP:
        if (n > 0) full[v->seed % n] ^= (char)(1 + (v->seed >> 16) % 127);
        break;
      default: break;
    }
  }
  *len = n;
  memcpy(out, full, n < cap ? n : cap);
  return true;
}

static void dump_get(sim_view *v, const char *path, FILE *f) {
  char body[BODY_MAX], hex[2 * BODY_MAX + 1];
  long status = 0;
  size_t len = 0;
  int failure = 0;
  if (!sim_respond(v, false, path, NULL, 0, body, sizeof body, &status, &len, &failure)) return;
  if (len > sizeof body) len = sizeof body;
  plain_hex((const uint8_t *)body, len, hex);
  fprintf(f, "G %s %ld %s\n", path, status, len ? hex : "-");
}

static void dump_tx(sim_view *v, const uint8_t id[GZ_HASH_LEN], FILE *f) {
  char hex[65], path[160];
  static const char *const parts[] = {"status", "hex", "merkle-proof", "outspend/0"};
  sim_hex(id, hex);
  for (size_t i = 0; i < 4; i++) {
    snprintf(path, sizeof path, "/tx/%s/%s", hex, parts[i]);
    dump_get(v, path, f);
  }
}

void sim_dump(sim_view *v, FILE *f) {
  char hex[65], path[160];
  static const char *const posts[] = {"accept", "known", "reject", "down"};
  dump_get(v, "/blocks/tip/height", f);
  dump_get(v, "/block-height/0", f);
  for (uint32_t h = SIM_H0; h <= view_top(v); h++) {
    const sim_block *b = view_block(v, h);
    snprintf(path, sizeof path, "/block-height/%u", h);
    dump_get(v, path, f);
    sim_hex(b->id, hex);
    snprintf(path, sizeof path, "/block/%s", hex);
    dump_get(v, path, f);
    snprintf(path, sizeof path, "/block/%s/header", hex);
    dump_get(v, path, f);
    snprintf(path, sizeof path, "/block/%s/txid/0", hex);
    dump_get(v, path, f);
    dump_tx(v, b->coinbase.id, f);
  }
  for (int i = 0; i < SIM_NTX; i++) dump_tx(v, v->w->tx[i].id, f);
  dump_tx(v, v->w->p, f);
  fprintf(f, "P /tx %s\n", posts[v->post]);
  fprintf(f, "P /txs/package %s\n",
          v->package == SIM_PKG_OK ? "ok" : v->package == SIM_PKG_FAIL ? "fail"
                                        : v->package == SIM_PKG_DOWN ? "down" : "none");
  fprintf(f, "P /v1/txs/package %s\n",
          v->package == SIM_PKG_OK_V1 ? "ok" : v->package == SIM_PKG_DOWN ? "down" : "none");
}

/* ---- the transport ------------------------------------------------------- */

static uint64_t real_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void deadline_in(struct timespec *ts, uint32_t ms) {
  clock_gettime(CLOCK_MONOTONIC, ts);
  ts->tv_sec += (time_t)(ms / 1000u);
  ts->tv_nsec += (long)(ms % 1000u) * 1000000L;
  if (ts->tv_nsec >= 1000000000L) {
    ts->tv_sec += 1;
    ts->tv_nsec -= 1000000000L;
  }
}

void sim_net_init(sim_net *n, bool real_time) {
  pthread_condattr_t attr;
  memset(n, 0, sizeof *n);
  sim_world_init(&n->world);
  sim_view_init(&n->view[0], &n->world, SIM_A, SIM_H0 + 3);
  sim_view_init(&n->view[1], &n->world, SIM_A, SIM_H0 + 3);
  pthread_mutex_init(&n->mu, NULL);
  pthread_condattr_init(&attr);
  pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  pthread_cond_init(&n->cv, &attr);
  pthread_condattr_destroy(&attr);
  n->real_time = real_time;
  n->stall_view = -1;
  n->delay_view = -1;
  n->now = 1000000;
}

void sim_net_free(sim_net *n) {
  pthread_cond_destroy(&n->cv);
  pthread_mutex_destroy(&n->mu);
  free(n->log);
  n->log = NULL;
}

void sim_lock(sim_net *n) { pthread_mutex_lock(&n->mu); }
void sim_unlock(sim_net *n) { pthread_mutex_unlock(&n->mu); }

uint64_t sim_clock(void *net) {
  sim_net *n = net;
  if (n->real_time) return real_ms();
  sim_lock(n);
  uint64_t now = n->now;
  sim_unlock(n);
  return now;
}

static void sim_sleep(void *net, uint32_t ms) {
  sim_net *n = net;
  sim_lock(n);
  if (!n->real_time) {
    n->now += ms;
  } else {
    struct timespec until;
    deadline_in(&until, ms);
    while (!n->interrupted) {
      if (pthread_cond_timedwait(&n->cv, &n->mu, &until) == ETIMEDOUT) break;
    }
  }
  sim_unlock(n);
}

void sim_interrupt(void *net, bool on) {
  sim_net *n = net;
  sim_lock(n);
  n->interrupted = on;
  pthread_cond_broadcast(&n->cv);
  sim_unlock(n);
}

static void log_url(sim_net *n, const char *url) {
  size_t len = strlen(url);
  if (n->log_len + len + 2 > n->log_cap) {
    size_t cap = n->log_cap ? 2 * n->log_cap : 4096;
    while (cap < n->log_len + len + 2) cap *= 2;
    char *grown = realloc(n->log, cap);
    if (grown == NULL) return;
    n->log = grown;
    n->log_cap = cap;
  }
  memcpy(n->log + n->log_len, url, len);
  n->log_len += len;
  n->log[n->log_len++] = '\n';
  n->log[n->log_len] = '\0';
}

bool sim_log_has(sim_net *n, const char *needle) {
  sim_lock(n);
  bool has = n->log != NULL && strstr(n->log, needle) != NULL;
  sim_unlock(n);
  return has;
}

unsigned sim_requests(sim_net *n) {
  sim_lock(n);
  unsigned r = n->requests;
  sim_unlock(n);
  return r;
}

static gz_http_result sim_request(void *net, const gz_http_request *req, uint8_t *buf, size_t cap,
                                  gz_http_response *resp) {
  sim_net *n = net;
  int which = -1;
  const char *path = NULL;
  size_t la = strlen(SIM_BASE_A), lb = strlen(SIM_BASE_B);
  if (strncmp(req->url, SIM_BASE_A, la) == 0) {
    which = 0;
    path = req->url + la;
  } else if (strncmp(req->url, SIM_BASE_B, lb) == 0) {
    which = 1;
    path = req->url + lb;
  }
  resp->status = 0;
  resp->len = 0;
  sim_lock(n);
  n->requests++;
  log_url(n, req->url);
  if (n->interrupted || which < 0) {
    sim_unlock(n);
    return GZ_HTTP_E_FAILED;
  }
  if (n->real_time && n->stall && (n->stall_view < 0 || n->stall_view == which) &&
      (n->stall_path == NULL || strstr(path, n->stall_path) != NULL)) {
    struct timespec until;
    deadline_in(&until, req->timeout_ms);
    n->stalled++;
    while (n->stall && !n->interrupted) {
      if (pthread_cond_timedwait(&n->cv, &n->mu, &until) == ETIMEDOUT) break;
    }
    n->stalled--;
    if (n->interrupted) n->stall_aborts++;
    if (n->interrupted || n->stall) {
      gz_http_result r = n->interrupted ? GZ_HTTP_E_FAILED : GZ_HTTP_E_TIMEOUT;
      sim_unlock(n);
      return r;
    }
  }
  if (n->real_time && n->delay_ms > 0 && (n->delay_view < 0 || n->delay_view == which) &&
      (n->delay_path == NULL || strstr(path, n->delay_path) != NULL)) {
    struct timespec until;
    deadline_in(&until, n->delay_ms);
    while (!n->interrupted) {
      if (pthread_cond_timedwait(&n->cv, &n->mu, &until) == ETIMEDOUT) break;
    }
  }
  long status = 0;
  size_t len = 0;
  int failure = 0;
  bool ok = sim_respond(&n->view[which], req->post, path, req->body, req->body_len, (char *)buf,
                        cap, &status, &len, &failure);
  if (!ok && failure == GZ_HTTP_E_TIMEOUT && !n->real_time) n->now += req->timeout_ms;
  sim_unlock(n);
  if (!ok) return (gz_http_result)failure;
  if (len > cap) return GZ_HTTP_E_TOO_LARGE;
  resp->status = status;
  resp->len = len;
  return GZ_HTTP_OK;
}

gz_http sim_transport(sim_net *n) {
  gz_http h;
  h.ctx = n;
  h.request = sim_request;
  h.now_ms = sim_clock;
  h.sleep_ms = sim_sleep;
  return h;
}

uint32_t sim_request_timeout_ms = 2000;

bool sim_stack_open(sim_stack *s, sim_net *n) {
  static const char *const base[2] = {SIM_BASE_A, SIM_BASE_B};
  static const char *const op[2] = {"op-a", "op-b"};
  memset(s, 0, sizeof *s);
  s->http = sim_transport(n);
  for (int i = 0; i < 2; i++) {
    gz_esplora_config c;
    gz_esplora_config_default(&c);
    c.base_url = base[i];
    c.operator_id = op[i];
    c.timeout_ms = sim_request_timeout_ms;
    c.max_attempts = 1;
    c.backoff_ms = 1;
    c.min_interval_ms = 0;
    if (gz_esplora_create(&c, &s->http, &s->server[i]) != GZ_CHAIN_OK) return false;
  }
  gz_multi_config mc;
  gz_multi_config_default(&mc, GZ_NET_SIGNET);
  mc.now_ms = sim_clock;
  mc.clock_ctx = n;
  return gz_multi_create(&mc, s->server, 2, &s->multi) == GZ_CHAIN_OK;
}

void sim_stack_close(sim_stack *s) {
  gz_chain_destroy(&s->multi);
  gz_chain_destroy(&s->server[0]);
  gz_chain_destroy(&s->server[1]);
}
