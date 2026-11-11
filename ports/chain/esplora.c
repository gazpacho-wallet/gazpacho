/*
 * The Esplora HTTP backend. One instance talks to one chain server.
 *
 * Endpoints used (all verified against mempool.space and blockstream.info on
 * signet, 2026-11-11; examples in docs/notes/chain-port.md):
 *   GET  /blocks/tip/height             text, decimal
 *   GET  /block-height/{height}         text, 64 hex (block hash)
 *   GET  /block/{hash}/header           text, 160 hex
 *   GET  /tx/{txid}/status              JSON
 *   GET  /tx/{txid}/hex                 text, hex
 *   GET  /tx/{txid}/merkle-proof        JSON
 *   GET  /tx/{txid}/outspend/{vout}     JSON
 *   GET  /scripthash/{sha256(script)}/utxo   JSON; the hash is NOT reversed
 *   GET  /fee-estimates                 JSON
 *   POST /tx                            body: hex; answer: text txid
 *
 * Everything a server sends is hostile input: each body has its own size cap,
 * each field is checked, and nothing is allocated in proportion to what the
 * server sends (the response buffer is fixed at creation; the token array for
 * the output list is sized from the caller's capacity).
 */
#include "gazpacho/chain_esplora.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esplora_parse.h"
#include "json.h"

/* ======================================================================== */
/* Parsers                                                                   */
/* ======================================================================== */

bool gz_es_parse_height(const char *s, size_t len, uint32_t *out) {
  uint64_t v;
  if (s == NULL || len > 10 || !gz_parse_u64(s, len, &v) || v > GZ_MAX_HEIGHT) return false;
  *out = (uint32_t)v;
  return true;
}

bool gz_es_parse_header(const char *s, size_t len, uint8_t out[GZ_HEADER_LEN]) {
  uint8_t tmp[GZ_HEADER_LEN];
  if (s == NULL || len != 2 * GZ_HEADER_LEN) return false;
  if (!gz_hex_decode(s, len, tmp, sizeof tmp, NULL)) return false;
  memcpy(out, tmp, GZ_HEADER_LEN);
  return true;
}

static bool tok_hash(const char *s, const gz_json_tok *t, uint8_t out[GZ_HASH_LEN]) {
  if (t->type != GZ_JSON_STRING) return false;
  return gz_hash_from_hex(s + t->start, t->end - t->start, out);
}

static bool tok_u32(const char *s, const gz_json_tok *t, uint32_t max, uint32_t *out) {
  uint64_t v;
  if (!gz_json_u64(s, t, &v) || v > max) return false;
  *out = (uint32_t)v;
  return true;
}

static bool tok_bool(const gz_json_tok *t, bool *out) {
  if (t->type == GZ_JSON_TRUE) {
    *out = true;
    return true;
  }
  if (t->type == GZ_JSON_FALSE) {
    *out = false;
    return true;
  }
  return false;
}

/* Parses the status object at toks[idx]. */
static bool status_object(const char *s, const gz_json_tok *toks, size_t idx, gz_es_status *out) {
  enum { F_CONFIRMED = 1, F_HEIGHT = 2, F_HASH = 4, F_TIME = 8 };
  unsigned seen = 0;
  gz_es_status st;
  uint32_t block_time;
  memset(&st, 0, sizeof st);
  if (toks[idx].type != GZ_JSON_OBJECT) return false;
  size_t i = idx + 1;
  for (uint32_t m = 0; m < toks[idx].size; m++) {
    const gz_json_tok *key = &toks[i], *val = &toks[i + 1];
    if (gz_json_str_eq(s, key, "confirmed")) {
      if (!tok_bool(val, &st.confirmed)) return false;
      seen |= F_CONFIRMED;
    } else if (gz_json_str_eq(s, key, "block_height")) {
      if (!tok_u32(s, val, GZ_MAX_HEIGHT, &st.height)) return false;
      seen |= F_HEIGHT;
    } else if (gz_json_str_eq(s, key, "block_hash")) {
      if (!tok_hash(s, val, st.block_hash)) return false;
      seen |= F_HASH;
    } else if (gz_json_str_eq(s, key, "block_time")) {
      if (!tok_u32(s, val, UINT32_MAX, &block_time)) return false;
      seen |= F_TIME;
    } else {
      return false; /* a field this interface does not define */
    }
    i = val->next;
  }
  if (st.confirmed) {
    if (seen != (F_CONFIRMED | F_HEIGHT | F_HASH | F_TIME)) return false;
  } else {
    if (seen != F_CONFIRMED) return false;
  }
  *out = st;
  return true;
}

bool gz_es_parse_status(const char *s, size_t len, gz_es_status *out) {
  gz_json_tok toks[16];
  size_t n;
  if (s == NULL || out == NULL) return false;
  if (!gz_json_parse(s, len, toks, sizeof toks / sizeof toks[0], &n)) return false;
  return status_object(s, toks, 0, out);
}

bool gz_es_parse_outspend(const char *s, size_t len, gz_outspend *out) {
  enum { F_SPENT = 1, F_TXID = 2, F_VIN = 4, F_STATUS = 8 };
  gz_json_tok toks[32];
  size_t n;
  unsigned seen = 0;
  gz_outspend o;
  gz_es_status st;
  memset(&o, 0, sizeof o);
  memset(&st, 0, sizeof st);
  if (s == NULL || out == NULL) return false;
  if (!gz_json_parse(s, len, toks, sizeof toks / sizeof toks[0], &n)) return false;
  if (toks[0].type != GZ_JSON_OBJECT) return false;
  size_t i = 1;
  for (uint32_t m = 0; m < toks[0].size; m++) {
    const gz_json_tok *key = &toks[i], *val = &toks[i + 1];
    if (gz_json_str_eq(s, key, "spent")) {
      if (!tok_bool(val, &o.spent)) return false;
      seen |= F_SPENT;
    } else if (gz_json_str_eq(s, key, "txid")) {
      if (!tok_hash(s, val, o.spender_txid)) return false;
      seen |= F_TXID;
    } else if (gz_json_str_eq(s, key, "vin")) {
      if (!tok_u32(s, val, UINT32_MAX, &o.spender_vin)) return false;
      seen |= F_VIN;
    } else if (gz_json_str_eq(s, key, "status")) {
      if (!status_object(s, toks, i + 1, &st)) return false;
      seen |= F_STATUS;
    } else {
      return false;
    }
    i = val->next;
  }
  if (o.spent) {
    if (seen != (F_SPENT | F_TXID | F_VIN | F_STATUS)) return false;
    o.confirmed = st.confirmed;
    o.height = st.height;
    memcpy(o.block_hash, st.block_hash, GZ_HASH_LEN);
  } else {
    if (seen != F_SPENT) return false;
  }
  *out = o;
  return true;
}

static int output_cmp(const void *a, const void *b) {
  const gz_chain_output *x = a, *y = b;
  int c = memcmp(x->txid, y->txid, GZ_HASH_LEN);
  if (c != 0) return c;
  if (x->vout != y->vout) return x->vout < y->vout ? -1 : 1;
  return 0;
}

gz_es_parse_result gz_es_parse_utxos(const char *s, size_t len, gz_chain_output *out, size_t cap,
                                     size_t *count) {
  enum { F_TXID = 1, F_VOUT = 2, F_STATUS = 4, F_VALUE = 8 };
  /* A confirmed entry is 17 tokens. Room for three times the caller's
   * capacity lets "more than you asked for" be told apart from garbage for
   * any body that fits the size cap esplora.c applies. */
  if (s == NULL || out == NULL || count == NULL || cap == 0) return GZ_ES_PARSE_MALFORMED;
  if (cap > GZ_ES_MAX_UTXOS) cap = GZ_ES_MAX_UTXOS;
  size_t tok_cap = cap * 3 * 17 + 8;
  gz_json_tok *toks = malloc(tok_cap * sizeof *toks);
  if (toks == NULL) return GZ_ES_PARSE_NO_MEMORY;
  gz_es_parse_result res = GZ_ES_PARSE_MALFORMED;
  size_t n;
  if (!gz_json_parse(s, len, toks, tok_cap, &n)) goto done;
  if (toks[0].type != GZ_JSON_ARRAY) goto done;
  if (toks[0].size > cap) {
    res = GZ_ES_PARSE_TOO_MANY;
    goto done;
  }
  size_t e = 1;
  for (uint32_t k = 0; k < toks[0].size; k++) {
    gz_chain_output o;
    gz_es_status st;
    unsigned seen = 0;
    memset(&o, 0, sizeof o);
    memset(&st, 0, sizeof st);
    if (toks[e].type != GZ_JSON_OBJECT) goto done;
    size_t i = e + 1;
    for (uint32_t m = 0; m < toks[e].size; m++) {
      const gz_json_tok *key = &toks[i], *val = &toks[i + 1];
      if (gz_json_str_eq(s, key, "txid")) {
        if (!tok_hash(s, val, o.txid)) goto done;
        seen |= F_TXID;
      } else if (gz_json_str_eq(s, key, "vout")) {
        if (!tok_u32(s, val, UINT32_MAX, &o.vout)) goto done;
        seen |= F_VOUT;
      } else if (gz_json_str_eq(s, key, "status")) {
        if (!status_object(s, toks, i + 1, &st)) goto done;
        seen |= F_STATUS;
      } else if (gz_json_str_eq(s, key, "value")) {
        if (!gz_json_u64(s, val, &o.value) || o.value > GZ_MAX_MONEY) goto done;
        seen |= F_VALUE;
      } else {
        goto done;
      }
      i = val->next;
    }
    if (seen != (F_TXID | F_VOUT | F_STATUS | F_VALUE)) goto done;
    o.confirmed = st.confirmed;
    o.height = st.height;
    memcpy(o.block_hash, st.block_hash, GZ_HASH_LEN);
    out[k] = o;
    e = toks[e].next;
  }
  size_t total = toks[0].size;
  qsort(out, total, sizeof *out, output_cmp);
  for (size_t k = 1; k < total; k++) {
    if (output_cmp(&out[k - 1], &out[k]) == 0) goto done; /* same outpoint twice */
  }
  *count = total;
  res = GZ_ES_PARSE_OK;
done:
  free(toks);
  return res;
}

bool gz_es_parse_merkle_proof(const char *s, size_t len, gz_merkle_proof *out) {
  enum { F_HEIGHT = 1, F_MERKLE = 2, F_POS = 4 };
  gz_json_tok toks[GZ_MERKLE_MAX_DEPTH + 16];
  size_t n;
  unsigned seen = 0;
  gz_merkle_proof p;
  memset(&p, 0, sizeof p);
  if (s == NULL || out == NULL) return false;
  if (!gz_json_parse(s, len, toks, sizeof toks / sizeof toks[0], &n)) return false;
  if (toks[0].type != GZ_JSON_OBJECT) return false;
  size_t i = 1;
  for (uint32_t m = 0; m < toks[0].size; m++) {
    const gz_json_tok *key = &toks[i], *val = &toks[i + 1];
    if (gz_json_str_eq(s, key, "block_height")) {
      if (!tok_u32(s, val, GZ_MAX_HEIGHT, &p.block_height)) return false;
      seen |= F_HEIGHT;
    } else if (gz_json_str_eq(s, key, "merkle")) {
      if (val->type != GZ_JSON_ARRAY || val->size > GZ_MERKLE_MAX_DEPTH) return false;
      for (uint32_t k = 0; k < val->size; k++) {
        /* elements must be strings, so each is exactly one token */
        if (!tok_hash(s, &toks[i + 2 + k], p.nodes[k])) return false;
      }
      p.depth = val->size;
      seen |= F_MERKLE;
    } else if (gz_json_str_eq(s, key, "pos")) {
      if (!tok_u32(s, val, UINT32_MAX, &p.pos)) return false;
      seen |= F_POS;
    } else {
      return false;
    }
    i = val->next;
  }
  if (seen != (F_HEIGHT | F_MERKLE | F_POS)) return false;
  if (p.depth < 32 && (p.pos >> p.depth) != 0) return false;
  *out = p;
  return true;
}

static int fee_cmp(const void *a, const void *b) {
  const gz_fee_estimate *x = a, *y = b;
  return (x->target > y->target) - (x->target < y->target);
}

bool gz_es_parse_fee_estimates(const char *s, size_t len, gz_fee_estimates *out) {
  gz_json_tok toks[2 * GZ_FEE_MAX_TARGETS + 2];
  size_t n;
  gz_fee_estimates f;
  memset(&f, 0, sizeof f);
  if (s == NULL || out == NULL) return false;
  if (!gz_json_parse(s, len, toks, sizeof toks / sizeof toks[0], &n)) return false;
  if (toks[0].type != GZ_JSON_OBJECT || toks[0].size > GZ_FEE_MAX_TARGETS) return false;
  size_t i = 1;
  for (uint32_t m = 0; m < toks[0].size; m++) {
    const gz_json_tok *key = &toks[i], *val = &toks[i + 1];
    uint64_t target, rate;
    if (!gz_parse_u64(s + key->start, key->end - key->start, &target)) return false;
    if (target < 1 || target > GZ_ES_MAX_FEE_TARGET) return false;
    /* sat/vB with a fraction -> sat per 1000 vB, rounded up */
    if (!gz_json_decimal_scaled(s, val, 3, &rate) || rate > GZ_MAX_MONEY) return false;
    f.entries[m].target = (uint16_t)target;
    f.entries[m].sat_per_kvb = rate;
    i = val->next;
  }
  f.count = toks[0].size;
  qsort(f.entries, f.count, sizeof f.entries[0], fee_cmp);
  for (size_t k = 1; k < f.count; k++) {
    if (f.entries[k - 1].target == f.entries[k].target) return false; /* "1" and "01" cannot both occur, but be sure */
  }
  *out = f;
  return true;
}

/* ======================================================================== */
/* The backend                                                               */
/* ======================================================================== */

#define ES_PATH_MAX 192
#define ES_MAX_BACKOFF_MS 30000u
/* Per-call caps on the response body, in bytes. */
#define ES_CAP_HEIGHT 10
#define ES_CAP_HASH (2 * GZ_HASH_LEN)
#define ES_CAP_HEADER (2 * GZ_HEADER_LEN)
#define ES_CAP_STATUS 256
#define ES_CAP_OUTSPEND 512
#define ES_CAP_PROOF 4096
#define ES_CAP_FEES 8192
#define ES_CAP_BROADCAST 4096
#define ES_UTXO_BYTES_EACH 320
/* Largest transaction gz_chain_broadcast will send. */
#define ES_MAX_BROADCAST_BYTES 400000

typedef struct esplora {
  gz_http http;
  gz_esplora_config cfg;
  char base[GZ_ESPLORA_URL_MAX + 1];
  uint8_t *buf; /* the one response buffer, cfg.max_response_bytes long */
  bool has_last;
  uint64_t last_ms; /* when the previous request started */
} esplora;

static void hex_plain(const uint8_t *in, size_t len, char *out) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[2 * i] = digits[in[i] >> 4];
    out[2 * i + 1] = digits[in[i] & 15];
  }
  out[2 * len] = '\0';
}

/*
 * One request with the rate limit, the retries and the size cap. Returns
 * GZ_CHAIN_OK when an HTTP response was received whose status is not 429 or
 * 5xx (the caller interprets the status), GZ_CHAIN_TOO_LARGE, or
 * GZ_CHAIN_UNREACHABLE. The body is in es->buf[0..*len).
 */
static gz_chain_result es_request(esplora *es, bool post, const char *path, const uint8_t *body,
                                  size_t body_len, size_t cap, long *status, size_t *len) {
  char url[GZ_ESPLORA_URL_MAX + ES_PATH_MAX + 1];
  int w = snprintf(url, sizeof url, "%s%s", es->base, path);
  if (w < 0 || (size_t)w >= sizeof url) return GZ_CHAIN_INVALID_ARG;
  if (cap > es->cfg.max_response_bytes) cap = es->cfg.max_response_bytes;
  *status = 0;
  *len = 0;

  for (uint32_t attempt = 0; attempt < es->cfg.max_attempts; attempt++) {
    if (attempt > 0) {
      uint64_t wait = (uint64_t)es->cfg.backoff_ms << (attempt - 1 > 16 ? 16 : attempt - 1);
      if (wait > ES_MAX_BACKOFF_MS) wait = ES_MAX_BACKOFF_MS;
      es->http.sleep_ms(es->http.ctx, (uint32_t)wait);
    }
    /* keep the request rate polite */
    uint64_t now = es->http.now_ms(es->http.ctx);
    if (es->has_last && now >= es->last_ms && now - es->last_ms < es->cfg.min_interval_ms) {
      es->http.sleep_ms(es->http.ctx, (uint32_t)(es->cfg.min_interval_ms - (now - es->last_ms)));
      now = es->http.now_ms(es->http.ctx);
    }
    es->last_ms = now;
    es->has_last = true;

    gz_http_request req;
    gz_http_response resp;
    memset(&req, 0, sizeof req);
    memset(&resp, 0, sizeof resp);
    req.url = url;
    req.post = post;
    req.body = body;
    req.body_len = body_len;
    req.timeout_ms = es->cfg.timeout_ms;
    gz_http_result hr = es->http.request(es->http.ctx, &req, es->buf, cap, &resp);
    if (hr == GZ_HTTP_OK) {
      if (resp.len > cap) return GZ_CHAIN_TOO_LARGE; /* a transport that broke its promise */
      *status = resp.status;
      *len = resp.len;
      if (resp.status == 429) continue; /* refused before doing anything: safe to repeat */
      if (resp.status >= 500 && resp.status <= 599) {
        if (post) break; /* see below */
        continue;
      }
      return GZ_CHAIN_OK;
    }
    if (hr == GZ_HTTP_E_TOO_LARGE) return GZ_CHAIN_TOO_LARGE;
    /* A broadcast that timed out or drew a 5xx may have been acted on. Sending
     * it again could turn an accepted transaction into an "already known"
     * refusal, so it is not repeated; the caller sees "unreachable". */
    if (post && hr != GZ_HTTP_E_CONNECT) break;
  }
  return GZ_CHAIN_UNREACHABLE;
}

static gz_chain_result es_get(esplora *es, const char *path, size_t cap, long *status,
                              size_t *len) {
  return es_request(es, false, path, NULL, 0, cap, status, len);
}

/* What an HTTP status means when the body has not been looked at yet. */
static gz_chain_result status_meaning(long status) {
  if (status == 200) return GZ_CHAIN_OK;
  if (status == 404) return GZ_CHAIN_NOT_FOUND;
  if (status >= 400 && status <= 499) return GZ_CHAIN_REJECTED;
  return GZ_CHAIN_MALFORMED;
}

static const char *body_of(const esplora *es) { return (const char *)es->buf; }

static gz_chain_result es_tip_height(esplora *es, uint32_t *height) {
  long status;
  size_t len;
  gz_chain_result r = es_get(es, "/blocks/tip/height", ES_CAP_HEIGHT, &status, &len);
  if (r != GZ_CHAIN_OK) return r;
  if (status != 200) return status == 404 ? GZ_CHAIN_MALFORMED : status_meaning(status);
  if (!gz_es_parse_height(body_of(es), len, height)) return GZ_CHAIN_MALFORMED;
  return GZ_CHAIN_OK;
}

static gz_chain_result es_block_hash(void *ctx, uint32_t height, uint8_t out[GZ_HASH_LEN]) {
  esplora *es = ctx;
  char path[ES_PATH_MAX];
  long status;
  size_t len;
  snprintf(path, sizeof path, "/block-height/%lu", (unsigned long)height);
  gz_chain_result r = es_get(es, path, ES_CAP_HASH, &status, &len);
  if (r != GZ_CHAIN_OK) return r;
  if (status != 200) return status_meaning(status);
  if (!gz_hash_from_hex(body_of(es), len, out)) return GZ_CHAIN_MALFORMED;
  return GZ_CHAIN_OK;
}

static gz_chain_result es_tip(void *ctx, gz_chain_tip *out) {
  esplora *es = ctx;
  uint32_t height;
  gz_chain_result r = es_tip_height(es, &height);
  if (r != GZ_CHAIN_OK) return r;
  /* The hash is asked for by height, so the pair is consistent even if a new
   * block arrives between the two requests. */
  r = es_block_hash(es, height, out->hash);
  if (r == GZ_CHAIN_NOT_FOUND) return GZ_CHAIN_MALFORMED; /* its own tip has no block */
  if (r != GZ_CHAIN_OK) return r;
  out->height = height;
  return GZ_CHAIN_OK;
}

static gz_chain_result es_block_header(void *ctx, uint32_t height, uint8_t out[GZ_HEADER_LEN]) {
  esplora *es = ctx;
  uint8_t hash[GZ_HASH_LEN], check[GZ_HASH_LEN], header[GZ_HEADER_LEN];
  char hex[2 * GZ_HASH_LEN + 1], path[ES_PATH_MAX];
  long status;
  size_t len;
  gz_chain_result r = es_block_hash(es, height, hash);
  if (r != GZ_CHAIN_OK) return r;
  gz_hash_to_hex(hash, hex);
  snprintf(path, sizeof path, "/block/%s/header", hex);
  r = es_get(es, path, ES_CAP_HEADER, &status, &len);
  if (r != GZ_CHAIN_OK) return r;
  if (status != 200) return status == 404 ? GZ_CHAIN_MALFORMED : status_meaning(status);
  if (!gz_es_parse_header(body_of(es), len, header)) return GZ_CHAIN_MALFORMED;
  /* the header must be the one the server named for this height */
  gz_header_hash(header, check);
  if (memcmp(check, hash, GZ_HASH_LEN) != 0) return GZ_CHAIN_MALFORMED;
  memcpy(out, header, GZ_HEADER_LEN);
  return GZ_CHAIN_OK;
}

/*
 * Fetches /tx/{txid}/hex into es->buf and decodes it in place. OK only if the
 * bytes are a transaction whose id is `txid`. `cap` limits the decoded size.
 */
static gz_chain_result es_fetch_tx(esplora *es, const uint8_t txid[GZ_HASH_LEN], size_t cap,
                                   size_t *raw_len) {
  char hex[2 * GZ_HASH_LEN + 1], path[ES_PATH_MAX];
  uint8_t check[GZ_HASH_LEN];
  long status;
  size_t len;
  size_t body_cap = cap > es->cfg.max_response_bytes / 2 ? es->cfg.max_response_bytes : cap * 2;
  gz_hash_to_hex(txid, hex);
  snprintf(path, sizeof path, "/tx/%s/hex", hex);
  gz_chain_result r = es_get(es, path, body_cap, &status, &len);
  if (r != GZ_CHAIN_OK) return r;
  if (status != 200) return status_meaning(status);
  /* decoding in place is safe: byte i is written after characters 2i, 2i+1 are read */
  if (!gz_hex_decode(body_of(es), len, es->buf, len / 2, raw_len)) return GZ_CHAIN_MALFORMED;
  if (!gz_txid_from_raw(es->buf, *raw_len, check)) return GZ_CHAIN_MALFORMED;
  if (memcmp(check, txid, GZ_HASH_LEN) != 0) return GZ_CHAIN_MALFORMED;
  return GZ_CHAIN_OK;
}

static gz_chain_result es_tx_status(void *ctx, const uint8_t txid[GZ_HASH_LEN],
                                    gz_tx_status *out) {
  esplora *es = ctx;
  char hex[2 * GZ_HASH_LEN + 1], path[ES_PATH_MAX];
  gz_es_status st;
  long status;
  size_t len;
  gz_hash_to_hex(txid, hex);
  snprintf(path, sizeof path, "/tx/%s/status", hex);
  gz_chain_result r = es_get(es, path, ES_CAP_STATUS, &status, &len);
  if (r != GZ_CHAIN_OK) return r;
  if (status == 404) {
    out->state = GZ_TX_UNKNOWN;
    return GZ_CHAIN_OK;
  }
  if (status != 200) return status_meaning(status);
  if (!gz_es_parse_status(body_of(es), len, &st)) return GZ_CHAIN_MALFORMED;

  if (st.confirmed) {
    uint32_t tip;
    r = es_tip_height(es, &tip);
    if (r != GZ_CHAIN_OK) return r;
    if (tip < st.height) return GZ_CHAIN_MALFORMED; /* confirmed above its own tip */
    out->state = GZ_TX_CONFIRMED;
    out->height = st.height;
    memcpy(out->block_hash, st.block_hash, GZ_HASH_LEN);
    out->tip_height = tip;
    out->confirmations = tip - st.height + 1;
    return GZ_CHAIN_OK;
  }
  /* Esplora answers {"confirmed":false} both for a mempool transaction and
   * for one it has never seen. Asking for the transaction itself tells them
   * apart, and the bytes must hash to the txid. */
  size_t raw_len;
  r = es_fetch_tx(es, txid, es->cfg.max_response_bytes / 2, &raw_len);
  if (r == GZ_CHAIN_NOT_FOUND) {
    out->state = GZ_TX_UNKNOWN;
    return GZ_CHAIN_OK;
  }
  if (r != GZ_CHAIN_OK) return r;
  out->state = GZ_TX_MEMPOOL;
  return GZ_CHAIN_OK;
}

static gz_chain_result es_raw_tx(void *ctx, const uint8_t txid[GZ_HASH_LEN], uint8_t *buf,
                                 size_t cap, size_t *len) {
  esplora *es = ctx;
  size_t raw_len;
  gz_chain_result r = es_fetch_tx(es, txid, cap, &raw_len);
  if (r != GZ_CHAIN_OK) return r;
  if (raw_len > cap) return GZ_CHAIN_TOO_LARGE;
  memcpy(buf, es->buf, raw_len);
  *len = raw_len;
  return GZ_CHAIN_OK;
}

static gz_chain_result es_script_outputs(void *ctx, const uint8_t *script, size_t script_len,
                                         gz_chain_output *out, size_t cap, size_t *count) {
  esplora *es = ctx;
  uint8_t sh[GZ_HASH_LEN];
  char hex[2 * GZ_HASH_LEN + 1], path[ES_PATH_MAX];
  long status;
  size_t len;
  if (cap > GZ_ES_MAX_UTXOS) cap = GZ_ES_MAX_UTXOS;
  gz_script_hash(script, script_len, sh);
  hex_plain(sh, GZ_HASH_LEN, hex); /* not reversed: verified against both servers */
  snprintf(path, sizeof path, "/scripthash/%s/utxo", hex);
  gz_chain_result r = es_get(es, path, cap * ES_UTXO_BYTES_EACH + 16, &status, &len);
  if (r != GZ_CHAIN_OK) return r;
  if (status != 200) return status == 404 ? GZ_CHAIN_MALFORMED : status_meaning(status);
  switch (gz_es_parse_utxos(body_of(es), len, out, cap, count)) {
    case GZ_ES_PARSE_OK: return GZ_CHAIN_OK;
    case GZ_ES_PARSE_TOO_MANY: return GZ_CHAIN_TOO_LARGE;
    case GZ_ES_PARSE_NO_MEMORY: return GZ_CHAIN_NO_MEMORY;
    case GZ_ES_PARSE_MALFORMED: break;
  }
  return GZ_CHAIN_MALFORMED;
}

static gz_chain_result es_outspend(void *ctx, const uint8_t txid[GZ_HASH_LEN], uint32_t vout,
                                   gz_outspend *out) {
  esplora *es = ctx;
  char hex[2 * GZ_HASH_LEN + 1], path[ES_PATH_MAX];
  long status;
  size_t len;
  gz_hash_to_hex(txid, hex);
  snprintf(path, sizeof path, "/tx/%s/outspend/%lu", hex, (unsigned long)vout);
  gz_chain_result r = es_get(es, path, ES_CAP_OUTSPEND, &status, &len);
  if (r != GZ_CHAIN_OK) return r;
  if (status != 200) return status_meaning(status);
  if (!gz_es_parse_outspend(body_of(es), len, out)) return GZ_CHAIN_MALFORMED;
  return GZ_CHAIN_OK;
}

static gz_chain_result es_merkle_proof(void *ctx, const uint8_t txid[GZ_HASH_LEN],
                                       gz_merkle_proof *out) {
  esplora *es = ctx;
  char hex[2 * GZ_HASH_LEN + 1], path[ES_PATH_MAX];
  long status;
  size_t len;
  gz_hash_to_hex(txid, hex);
  snprintf(path, sizeof path, "/tx/%s/merkle-proof", hex);
  gz_chain_result r = es_get(es, path, ES_CAP_PROOF, &status, &len);
  if (r != GZ_CHAIN_OK) return r;
  if (status != 200) return status_meaning(status);
  if (!gz_es_parse_merkle_proof(body_of(es), len, out)) return GZ_CHAIN_MALFORMED;
  return GZ_CHAIN_OK;
}

static gz_chain_result es_broadcast(void *ctx, const uint8_t *raw, size_t raw_len,
                                    gz_broadcast_result *out) {
  esplora *es = ctx;
  uint8_t want[GZ_HASH_LEN], got[GZ_HASH_LEN];
  long status = 0;
  size_t len = 0;
  memset(out, 0, sizeof *out);
  if (raw_len > ES_MAX_BROADCAST_BYTES || !gz_txid_from_raw(raw, raw_len, want)) {
    out->result = GZ_CHAIN_INVALID_ARG;
    return out->result;
  }
  char *hex = malloc(2 * raw_len + 1); /* sized by our own transaction, not by the server */
  if (hex == NULL) {
    out->result = GZ_CHAIN_NO_MEMORY;
    return out->result;
  }
  hex_plain(raw, raw_len, hex);
  gz_chain_result r =
      es_request(es, true, "/tx", (const uint8_t *)hex, 2 * raw_len, ES_CAP_BROADCAST, &status, &len);
  free(hex);
  out->server_status = status;
  if (r != GZ_CHAIN_OK) {
    out->result = r;
    return r;
  }
  if (status == 200) {
    /* accept only the txid of what we sent */
    if (!gz_hash_from_hex(body_of(es), len, got) || memcmp(got, want, GZ_HASH_LEN) != 0) {
      out->result = GZ_CHAIN_MALFORMED;
      return out->result;
    }
    memcpy(out->txid, want, GZ_HASH_LEN);
    out->result = GZ_CHAIN_OK;
    return out->result;
  }
  if (status >= 400 && status <= 499) {
    size_t n = len < GZ_REASON_MAX - 1 ? len : GZ_REASON_MAX - 1;
    for (size_t i = 0; i < n; i++) {
      uint8_t ch = es->buf[i];
      out->reason[i] = (ch >= 0x20 && ch <= 0x7e) ? (char)ch : '?';
    }
    out->reason[n] = '\0';
    out->result = GZ_CHAIN_REJECTED;
    return out->result;
  }
  out->result = GZ_CHAIN_MALFORMED;
  return out->result;
}

static gz_chain_result es_fee_estimates(void *ctx, gz_fee_estimates *out) {
  esplora *es = ctx;
  long status;
  size_t len;
  gz_chain_result r = es_get(es, "/fee-estimates", ES_CAP_FEES, &status, &len);
  if (r != GZ_CHAIN_OK) return r;
  /* mempool.space answers 203 here (it computes the figures itself) */
  if (status != 200 && status != 203)
    return status == 404 ? GZ_CHAIN_MALFORMED : status_meaning(status);
  if (!gz_es_parse_fee_estimates(body_of(es), len, out)) return GZ_CHAIN_MALFORMED;
  return GZ_CHAIN_OK;
}

static void es_destroy(void *ctx) {
  esplora *es = ctx;
  if (es == NULL) return;
  free(es->buf);
  free(es);
}

static const gz_chain_ops es_ops = {
    es_tip,       es_block_hash,   es_block_header, es_tx_status,     es_script_outputs,
    es_outspend,  es_raw_tx,       es_merkle_proof, es_broadcast,     es_fee_estimates,
    es_destroy,
};

void gz_esplora_config_default(gz_esplora_config *cfg) {
  if (cfg == NULL) return;
  memset(cfg, 0, sizeof *cfg);
  cfg->timeout_ms = 15000;
  cfg->max_attempts = 3;
  cfg->backoff_ms = 500;
  cfg->min_interval_ms = 250;
  cfg->max_response_bytes = 512 * 1024;
}

static bool url_ok(const char *url) {
  size_t n = strlen(url);
  size_t scheme;
  if (strncmp(url, "https://", 8) == 0) {
    scheme = 8;
  } else if (strncmp(url, "http://", 7) == 0) {
    scheme = 7;
  } else {
    return false;
  }
  if (n <= scheme || n > GZ_ESPLORA_URL_MAX || url[n - 1] == '/') return false;
  for (size_t i = scheme; i < n; i++) {
    char c = url[i];
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-' || c == '_' || c == '~' || c == ':' || c == '/';
    if (!ok) return false;
  }
  return true;
}

gz_chain_result gz_esplora_create(const gz_esplora_config *cfg, const gz_http *http,
                                  gz_chain *out) {
  if (out != NULL) {
    out->ctx = NULL;
    out->ops = NULL;
  }
  if (cfg == NULL || http == NULL || out == NULL || cfg->base_url == NULL) return GZ_CHAIN_INVALID_ARG;
  if (http->request == NULL || http->now_ms == NULL || http->sleep_ms == NULL)
    return GZ_CHAIN_INVALID_ARG;
  if (!url_ok(cfg->base_url)) return GZ_CHAIN_INVALID_ARG;
  if (cfg->timeout_ms == 0 || cfg->timeout_ms > 120000 || cfg->max_attempts == 0 ||
      cfg->max_attempts > 8 || cfg->backoff_ms > ES_MAX_BACKOFF_MS ||
      cfg->min_interval_ms > 60000 || cfg->max_response_bytes < 4096 ||
      cfg->max_response_bytes > 16u * 1024 * 1024)
    return GZ_CHAIN_INVALID_ARG;
  esplora *es = calloc(1, sizeof *es);
  if (es == NULL) return GZ_CHAIN_NO_MEMORY;
  es->buf = malloc(cfg->max_response_bytes);
  if (es->buf == NULL) {
    free(es);
    return GZ_CHAIN_NO_MEMORY;
  }
  es->http = *http;
  es->cfg = *cfg;
  memcpy(es->base, cfg->base_url, strlen(cfg->base_url) + 1);
  es->cfg.base_url = es->base;
  out->ctx = es;
  out->ops = &es_ops;
  return GZ_CHAIN_OK;
}
