/* Shared test fixtures: recorded data, the fake transport. */
#include "test.h"

#ifndef GZ_TEST_DATA_DIR
#error "GZ_TEST_DATA_DIR must be defined by the build"
#endif

char *test_read_data(const char *name, size_t *len) {
  char path[1024];
  snprintf(path, sizeof path, "%s/%s", GZ_TEST_DATA_DIR, name);
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) {
    fprintf(stderr, "missing test data file %s\n", path);
    exit(2);
  }
  char *buf = malloc(1 << 20);
  if (buf == NULL) exit(2);
  size_t n = fread(buf, 1, (1 << 20) - 1, fp);
  fclose(fp);
  buf[n] = '\0';
  if (len != NULL) *len = n;
  return buf;
}

void test_hash(const char *hex, uint8_t out[GZ_HASH_LEN]) {
  if (!gz_hash_from_hex(hex, strlen(hex), out)) {
    fprintf(stderr, "bad hash constant %s\n", hex);
    exit(2);
  }
}

uint64_t test_rand(uint64_t *state) {
  /* xorshift64*: repeatable, seeded by the caller */
  uint64_t x = *state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *state = x;
  return x * UINT64_C(2685821657736338717);
}

/* ---- fake transport ---- */

void fake_init(fake_http *f) { memset(f, 0, sizeof *f); }

void fake_free(fake_http *f) {
  for (size_t i = 0; i < f->n; i++) free(f->routes[i].body);
  memset(f, 0, sizeof *f);
}

static fake_route *fake_new_route(fake_http *f, bool post, const char *url) {
  if (f->n >= FAKE_MAX_ROUTES || strlen(url) >= FAKE_URL_MAX) {
    fprintf(stderr, "fake transport: too many routes or address too long\n");
    exit(2);
  }
  fake_route *r = &f->routes[f->n++];
  memset(r, 0, sizeof *r);
  r->post = post;
  strcpy(r->url, url);
  return r;
}

void fake_set_bytes(fake_http *f, bool post, const char *url, long status, const void *body,
                    size_t len) {
  fake_route *r = NULL;
  for (size_t i = 0; i < f->n; i++) {
    fake_route *c = &f->routes[i];
    if (c->remaining == -1 && c->post == post && strcmp(c->url, url) == 0) r = c;
  }
  if (r == NULL) {
    r = fake_new_route(f, post, url);
  } else {
    free(r->body);
  }
  r->result = GZ_HTTP_OK;
  r->status = status;
  r->body = malloc(len + 1);
  if (r->body == NULL) exit(2);
  if (len > 0) memcpy(r->body, body, len);
  r->len = len;
  r->remaining = -1;
}

void fake_set(fake_http *f, bool post, const char *url, long status, const char *body) {
  fake_set_bytes(f, post, url, status, body, strlen(body));
}

void fake_set_file(fake_http *f, const char *url, long status, const char *data_file) {
  size_t len;
  char *body = test_read_data(data_file, &len);
  fake_set_bytes(f, false, url, status, body, len);
  free(body);
}

void fake_once(fake_http *f, bool post, const char *url, gz_http_result result, long status,
               const char *body, int times) {
  fake_route *r = fake_new_route(f, post, url);
  size_t len = strlen(body);
  r->result = result;
  r->status = status;
  r->body = malloc(len + 1);
  if (r->body == NULL) exit(2);
  memcpy(r->body, body, len);
  r->len = len;
  r->remaining = times;
}

unsigned fake_hits(const fake_http *f, bool post, const char *url) {
  unsigned hits = 0;
  for (size_t i = 0; i < f->n; i++) {
    if (f->routes[i].post == post && strcmp(f->routes[i].url, url) == 0) hits += f->routes[i].hits;
  }
  return hits;
}

static gz_http_result fake_request(void *ctx, const gz_http_request *req, uint8_t *buf, size_t cap,
                                   gz_http_response *resp) {
  fake_http *f = ctx;
  if (f->requests < FAKE_MAX_SLEEPS) f->starts[f->requests] = f->now_ms;
  f->requests++;
  f->now_ms += 20; /* every request takes a little time */
  snprintf(f->last_url, sizeof f->last_url, "%s", req->url);
  f->last_timeout_ms = req->timeout_ms;
  f->last_cap = cap;
  f->last_body_len = 0;
  if (req->post && req->body != NULL) {
    f->last_body_len = req->body_len < sizeof f->last_body ? req->body_len : sizeof f->last_body;
    memcpy(f->last_body, req->body, f->last_body_len);
  }
  if (f->down) return GZ_HTTP_E_CONNECT;
  fake_route *r = NULL;
  for (int pass = 0; pass < 2 && r == NULL; pass++) {
    for (size_t i = 0; i < f->n && r == NULL; i++) {
      fake_route *c = &f->routes[i];
      bool temporary = c->remaining > 0;
      bool permanent = c->remaining == -1;
      if ((pass == 0 ? temporary : permanent) && c->post == req->post &&
          strcmp(c->url, req->url) == 0)
        r = c;
    }
  }
  if (r == NULL) {
    f->unexpected++;
    fprintf(stderr, "  fake transport: no route for %s %s\n", req->post ? "POST" : "GET", req->url);
    return GZ_HTTP_E_FAILED;
  }
  r->hits++;
  if (r->remaining > 0) r->remaining--;
  if (r->result != GZ_HTTP_OK) return r->result;
  if (r->len > cap) {
    if (f->overrun) { /* a transport that lies about how much it wrote */
      resp->status = r->status;
      resp->len = r->len;
      return GZ_HTTP_OK;
    }
    return GZ_HTTP_E_TOO_LARGE;
  }
  memcpy(buf, r->body, r->len);
  resp->status = r->status;
  resp->len = r->len;
  return GZ_HTTP_OK;
}

uint64_t fake_clock(void *ctx) { return ((fake_http *)ctx)->now_ms; }

static void fake_sleep(void *ctx, uint32_t ms) {
  fake_http *f = ctx;
  if (f->n_sleeps < FAKE_MAX_SLEEPS) f->sleeps[f->n_sleeps] = ms;
  f->n_sleeps++;
  f->now_ms += ms;
}

gz_http fake_transport(fake_http *f) {
  gz_http h = {f, fake_request, fake_clock, fake_sleep};
  return h;
}

void fake_load_honest(fake_http *f, const char *base, bool blockstream) {
  char url[FAKE_URL_MAX];
  static const struct {
    const char *path;
    long status;
    const char *file;
  } files[] = {
      {"/block-height/329437", 200, "block_hash_329437.txt"},
      {"/block-height/329438", 200, "block_hash_329438.txt"},
      {"/block-height/329439", 200, "block_hash_329439.txt"},
      {"/block/" HASH_329437 "/header", 200, "header_329437.txt"},
      {"/block/" HASH_329438 "/header", 200, "header_329438.txt"},
      {"/block/" HASH_329439 "/header", 200, "header_329439.txt"},
      {"/tx/" TX_A "/status", 200, "tx_a_status.json"},
      {"/tx/" TX_A "/hex", 200, "tx_a_hex.txt"},
      {"/tx/" TX_A "/merkle-proof", 200, "tx_a_merkle_proof.json"},
      {"/tx/" TX_A "/outspend/0", 200, "tx_a_outspend_0.json"},
      {"/tx/" TX_A "/outspend/2", 200, "tx_a_outspend_2.json"},
      {"/block/" HASH_329438, 200, "block_329438.json"},
      {"/block/" HASH_329438 "/txid/0", 200, "block_329438_txid_0.txt"},
      {"/block/" HASH_329439, 200, "block_329439.json"},
      {"/block/" HASH_329439 "/txid/0", 200, "block_329439_txid_0.txt"},
      {"/tx/" TX_COINBASE "/status", 200, "tx_a_status.json"},
      {"/tx/" TX_COINBASE "/hex", 200, "tx_coinbase_hex.txt"},
      {"/tx/" TX_COINBASE "/merkle-proof", 200, "tx_coinbase_merkle_proof.json"},
      {"/tx/" TX_COINBASE_39 "/hex", 200, "tx_coinbase_329439_hex.txt"},
      {"/tx/" TX_COINBASE_39 "/merkle-proof", 200, "tx_coinbase_329439_merkle_proof.json"},
      {"/tx/" TX_B "/hex", 200, "tx_b_hex.txt"},
      {"/tx/" TX_B "/status", 200, "tx_b_status.json"},
      {"/tx/" TX_B "/merkle-proof", 200, "tx_b_merkle_proof.json"},
      {"/tx/" TX_SPENDER "/status", 200, "tx_spender_status.json"},
      {"/tx/" TX_SPENDER "/hex", 200, "tx_spender_hex.txt"},
      {"/tx/" TX_SPENDER "/merkle-proof", 200, "tx_spender_merkle_proof.json"},
      {"/scripthash/" SCRIPT_A2_HASH "/utxo", 200, "utxo_script_a2.json"},
  };
  for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
    snprintf(url, sizeof url, "%s%s", base, files[i].path);
    fake_set_file(f, url, files[i].status, files[i].file);
  }
  snprintf(url, sizeof url, "%s/blocks/tip/height", base);
  fake_set(f, false, url, 200, "329439");
  snprintf(url, sizeof url, "%s/block-height/0", base);
  fake_set(f, false, url, 200, GENESIS_SIGNET);
  snprintf(url, sizeof url, "%s/block-height/329440", base);
  fake_set(f, false, url, 404, "Block not found");
  snprintf(url, sizeof url, "%s/fee-estimates", base);
  fake_set_file(f, url, blockstream ? 200 : 203,
                blockstream ? "fee_estimates_blockstream.json" : "fee_estimates_mempool.json");
  /* a transaction no server has */
  snprintf(url, sizeof url, "%s/tx/" TX_NONE "/status", base);
  fake_set(f, false, url, 200, "{\"confirmed\":false}");
  snprintf(url, sizeof url, "%s/tx/" TX_NONE "/hex", base);
  fake_set(f, false, url, 404, "Transaction not found");
  snprintf(url, sizeof url, "%s/tx/" TX_NONE "/merkle-proof", base);
  fake_set(f, false, url, 404, "Transaction not found or is unconfirmed");
  snprintf(url, sizeof url, "%s/tx/" TX_NONE "/outspend/0", base);
  fake_set(f, false, url, 200, "{\"spent\":false}");
}
