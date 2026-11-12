/* Argument-checking front of the gz_chain interface, names, hex, hashing,
 * transaction ids, network identity and the fee rate policy. */
#include "gazpacho/chain.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

const char *gz_chain_result_name(gz_chain_result r) {
  switch (r) {
    case GZ_CHAIN_OK: return "ok";
    case GZ_CHAIN_NOT_FOUND: return "not-found";
    case GZ_CHAIN_REJECTED: return "rejected";
    case GZ_CHAIN_UNREACHABLE: return "unreachable";
    case GZ_CHAIN_MALFORMED: return "malformed";
    case GZ_CHAIN_TOO_LARGE: return "too-large";
    case GZ_CHAIN_BAD_PROOF: return "bad-proof";
    case GZ_CHAIN_WRONG_NETWORK: return "wrong-network";
    case GZ_CHAIN_DISAGREE: return "servers-disagree";
    case GZ_CHAIN_NO_QUORUM: return "no-quorum";
    case GZ_CHAIN_LAG: return "server-lagging";
    case GZ_CHAIN_INVALID_ARG: return "invalid-argument";
    case GZ_CHAIN_NO_MEMORY: return "no-memory";
  }
  return "unknown";
}

/* ---- networks ----------------------------------------------------------- */

const char *gz_network_name(gz_network n) {
  switch (n) {
    case GZ_NET_MAINNET: return "mainnet";
    case GZ_NET_TESTNET3: return "testnet";
    case GZ_NET_TESTNET4: return "testnet4";
    case GZ_NET_SIGNET: return "signet";
    case GZ_NET_INVALID: break;
  }
  return "invalid";
}

bool gz_network_valid(gz_network n) {
  return n == GZ_NET_MAINNET || n == GZ_NET_TESTNET3 || n == GZ_NET_TESTNET4 || n == GZ_NET_SIGNET;
}

bool gz_network_is_test(gz_network n) {
  return n == GZ_NET_TESTNET3 || n == GZ_NET_TESTNET4 || n == GZ_NET_SIGNET;
}

bool gz_network_from_name(const char *name, gz_network *out) {
  static const gz_network all[] = {GZ_NET_MAINNET, GZ_NET_TESTNET3, GZ_NET_TESTNET4, GZ_NET_SIGNET};
  if (name == NULL || out == NULL) return false;
  for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
    if (strcmp(name, gz_network_name(all[i])) == 0) {
      *out = all[i];
      return true;
    }
  }
  return false;
}

bool gz_network_genesis(gz_network n, uint8_t out[GZ_HASH_LEN]) {
  const char *hex = NULL;
  switch (n) {
    case GZ_NET_MAINNET:
      hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
      break;
    case GZ_NET_TESTNET3:
      hex = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
      break;
    case GZ_NET_TESTNET4:
      hex = "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043";
      break;
    case GZ_NET_SIGNET:
      hex = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
      break;
    case GZ_NET_INVALID: break;
  }
  if (hex == NULL || out == NULL) return false;
  return gz_hash_from_hex(hex, 2 * GZ_HASH_LEN, out);
}

/* ---- hex and hashing --------------------------------------------------- */

static int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

bool gz_hex_decode(const char *hex, size_t len, uint8_t *out, size_t cap, size_t *out_len) {
  if (hex == NULL || out == NULL || (len & 1) != 0 || len / 2 > cap) return false;
  for (size_t i = 0; i < len / 2; i++) {
    int hi = hex_val(hex[2 * i]), lo = hex_val(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  if (out_len != NULL) *out_len = len / 2;
  return true;
}

void gz_hash_to_hex(const uint8_t hash[GZ_HASH_LEN], char out[2 * GZ_HASH_LEN + 1]) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < GZ_HASH_LEN; i++) {
    uint8_t b = hash[GZ_HASH_LEN - 1 - i];
    out[2 * i] = digits[b >> 4];
    out[2 * i + 1] = digits[b & 15];
  }
  out[2 * GZ_HASH_LEN] = '\0';
}

bool gz_hash_from_hex(const char *hex, size_t len, uint8_t out[GZ_HASH_LEN]) {
  uint8_t tmp[GZ_HASH_LEN];
  if (len != 2 * GZ_HASH_LEN) return false;
  if (!gz_hex_decode(hex, len, tmp, sizeof tmp, NULL)) return false;
  for (size_t i = 0; i < GZ_HASH_LEN; i++) out[i] = tmp[GZ_HASH_LEN - 1 - i];
  return true;
}

void gz_sha256d(const uint8_t *data, size_t len, uint8_t out[GZ_HASH_LEN]) {
  uint8_t first[SHA256_DIGEST_LENGTH];
  SHA256(data, len, first);
  SHA256(first, sizeof first, out);
}

void gz_script_hash(const uint8_t *script, size_t len, uint8_t out[GZ_HASH_LEN]) {
  SHA256(script, len, out);
}

/* ---- operators ---------------------------------------------------------- */

/* The operator name given to every name of this machine. */
#define LOOPBACK_OPERATOR "this-machine"

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

/* Four decimal numbers 0-255 separated by dots, no leading zeros. */
static bool canonical_ipv4(const char *s, size_t n) {
  size_t i = 0;
  for (int part = 0; part < 4; part++) {
    size_t start = i;
    unsigned v = 0;
    while (i < n && is_digit(s[i]) && i - start < 3) v = v * 10 + (unsigned)(s[i++] - '0');
    size_t digits = i - start;
    if (digits == 0 || v > 255 || (digits > 1 && s[start] == '0')) return false;
    if (part < 3) {
      if (i >= n || s[i] != '.') return false;
      i++;
    }
  }
  return i == n;
}

static bool normalise_into(const char *in, size_t len, char out[GZ_HOST_MAX]) {
  if (in == NULL) return false;
  if (len > 0 && in[len - 1] == '.') len--; /* the DNS root: one trailing dot */
  if (len == 0 || len >= GZ_HOST_MAX) return false;
  if (in[0] == '[') {
    /* the IPv6 loopback address is the only bracketed host accepted */
    if (len != 5 || memcmp(in, "[::1]", 5) != 0) return false;
    memcpy(out, "[::1]", 6);
    return true;
  }
  size_t label = 0, last_label = 0;
  for (size_t i = 0; i < len; i++) {
    char c = in[i];
    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    if (c == '.') {
      /* an empty label, or one that ends with '-' */
      if (label == 0 || out[i - 1] == '-') return false;
      label = 0;
      last_label = i + 1;
    } else if ((c >= 'a' && c <= 'z') || is_digit(c) || c == '-') {
      if (label == 0 && c == '-') return false;
      if (++label > 63) return false;
    } else {
      return false; /* not part of a host name: '@', '%', ':', '/', non-ASCII... */
    }
    out[i] = c;
  }
  if (label == 0 || out[len - 1] == '-') return false;
  out[len] = '\0';
  /* a last label that starts with a digit is read as an address by
   * resolvers: only the canonical dotted IPv4 form is accepted */
  if (is_digit(out[last_label]) && !canonical_ipv4(out, len)) return false;
  return true;
}

bool gz_host_normalise(const char *in, size_t len, char out[GZ_HOST_MAX]) {
  if (out == NULL) return false;
  if (normalise_into(in, len, out)) return true;
  out[0] = '\0'; /* nothing half-written is left behind */
  return false;
}

bool gz_host_is_loopback(const char *host) {
  return host != NULL && (strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0 ||
                          strcmp(host, "[::1]") == 0);
}

bool gz_operator_from_host(const char *host, char out[GZ_OPERATOR_MAX]) {
  char norm[GZ_HOST_MAX];
  if (out == NULL) return false;
  out[0] = '\0';
  if (host == NULL || !gz_host_normalise(host, strlen(host), norm)) return false;
  const char *start = norm;
  if (gz_host_is_loopback(norm)) {
    start = LOOPBACK_OPERATOR; /* one machine is one operator, by any name */
  } else if (!canonical_ipv4(norm, strlen(norm))) {
    /* keep the last two labels; an address is its own operator */
    size_t seen = 0;
    for (size_t i = strlen(norm); i > 0; i--) {
      if (norm[i - 1] == '.' && ++seen == 2) {
        start = norm + i;
        break;
      }
    }
  }
  size_t m = strlen(start);
  if (m >= GZ_OPERATOR_MAX) return false;
  memcpy(out, start, m + 1);
  return true;
}

bool gz_operator_name_valid(const char *id) {
  if (id == NULL) return false;
  size_t n = strlen(id);
  if (n == 0 || n >= GZ_OPERATOR_MAX) return false;
  for (size_t i = 0; i < n; i++) {
    char c = id[i];
    bool edge = i == 0 || i == n - 1;
    if (c == '.' || c == '-') {
      if (edge || (c == '.' && id[i - 1] == '.')) return false;
    } else if (!((c >= 'a' && c <= 'z') || is_digit(c))) {
      return false;
    }
  }
  return true;
}

/* ---- transactions ------------------------------------------------------ */

typedef struct reader {
  const uint8_t *p;
  size_t len;
  size_t pos;
} reader;

static bool rd_skip(reader *r, uint64_t n) {
  if (n > r->len - r->pos) return false;
  r->pos += (size_t)n;
  return true;
}

/* Bitcoin's variable-length integer, canonical encodings only. */
static bool rd_varint(reader *r, uint64_t *out) {
  if (r->pos >= r->len) return false;
  uint8_t first = r->p[r->pos++];
  unsigned extra;
  uint64_t min;
  if (first < 0xfd) {
    *out = first;
    return true;
  } else if (first == 0xfd) {
    extra = 2;
    min = 0xfd;
  } else if (first == 0xfe) {
    extra = 4;
    min = 0x10000;
  } else {
    extra = 8;
    min = UINT64_C(0x100000000);
  }
  if (r->len - r->pos < extra) return false;
  uint64_t v = 0;
  for (unsigned i = 0; i < extra; i++) v |= (uint64_t)r->p[r->pos + i] << (8 * i);
  r->pos += extra;
  if (v < min) return false;
  *out = v;
  return true;
}

bool gz_txid_from_raw(const uint8_t *raw, size_t len, uint8_t txid[GZ_HASH_LEN]) {
  if (raw == NULL || txid == NULL || len < 10) return false;
  reader r = {raw, len, 0};
  uint64_t n_in, n_out, n;
  bool segwit = false;

  if (!rd_skip(&r, 4)) return false; /* version */
  if (len - r.pos >= 2 && raw[r.pos] == 0x00 && raw[r.pos + 1] == 0x01) {
    segwit = true;
    r.pos += 2;
  }
  size_t body_start = r.pos;
  if (!rd_varint(&r, &n_in) || n_in == 0) return false;
  for (uint64_t i = 0; i < n_in; i++) {
    /* outpoint, script, sequence. The loop cannot run longer than the input:
     * every pass consumes at least 41 bytes or fails. */
    if (!rd_skip(&r, 36) || !rd_varint(&r, &n) || !rd_skip(&r, n) || !rd_skip(&r, 4))
      return false;
  }
  if (!rd_varint(&r, &n_out) || n_out == 0) return false;
  for (uint64_t i = 0; i < n_out; i++) {
    if (!rd_skip(&r, 8) || !rd_varint(&r, &n) || !rd_skip(&r, n)) return false;
  }
  size_t body_end = r.pos;
  if (segwit) {
    for (uint64_t i = 0; i < n_in; i++) {
      uint64_t items;
      if (!rd_varint(&r, &items)) return false;
      for (uint64_t j = 0; j < items; j++) {
        if (!rd_varint(&r, &n) || !rd_skip(&r, n)) return false;
      }
    }
  }
  size_t locktime_at = r.pos;
  if (!rd_skip(&r, 4) || r.pos != len) return false;
  /* 64 bytes without witness: cannot be told from a Merkle inner node */
  if (4 + (body_end - body_start) + 4 == 64) return false;

  /* txid = SHA256d(version | inputs and outputs | locktime), witness left out */
  uint8_t first[EVP_MAX_MD_SIZE];
  unsigned int out_len = 0;
  EVP_MD_CTX *md = EVP_MD_CTX_new();
  if (md == NULL) return false;
  bool ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
            EVP_DigestUpdate(md, raw, 4) == 1 &&
            EVP_DigestUpdate(md, raw + body_start, body_end - body_start) == 1 &&
            EVP_DigestUpdate(md, raw + locktime_at, 4) == 1 &&
            EVP_DigestFinal_ex(md, first, &out_len) == 1 && out_len == GZ_HASH_LEN;
  EVP_MD_CTX_free(md);
  if (!ok) return false;
  SHA256(first, GZ_HASH_LEN, txid);
  return true;
}

bool gz_tx_is_coinbase(const uint8_t *raw, size_t len) {
  static const uint8_t null_outpoint[36] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff};
  if (raw == NULL || len < 4 + 1 + 36) return false;
  size_t pos = 4;
  if (len - pos >= 2 && raw[pos] == 0x00 && raw[pos + 1] == 0x01) pos += 2;
  if (len - pos < 1 + 36) return false;
  if (raw[pos] != 0x01) return false; /* exactly one input */
  return memcmp(raw + pos + 1, null_outpoint, sizeof null_outpoint) == 0;
}

/* ---- interface front --------------------------------------------------- */

static bool usable(const gz_chain *c) { return c != NULL && c->ops != NULL && c->ctx != NULL; }

gz_chain_result gz_chain_tip_get(const gz_chain *c, gz_chain_tip *out) {
  if (!usable(c) || out == NULL) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);
  if (c->ops->tip == NULL) return GZ_CHAIN_INVALID_ARG;
  return c->ops->tip(c->ctx, out);
}

gz_chain_result gz_chain_block_hash(const gz_chain *c, uint32_t height, uint8_t out[GZ_HASH_LEN]) {
  if (!usable(c) || out == NULL || height > GZ_MAX_HEIGHT) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, GZ_HASH_LEN);
  if (c->ops->block_hash == NULL) return GZ_CHAIN_INVALID_ARG;
  return c->ops->block_hash(c->ctx, height, out);
}

gz_chain_result gz_chain_block_header(const gz_chain *c, uint32_t height,
                                      uint8_t out[GZ_HEADER_LEN]) {
  if (!usable(c) || out == NULL || height > GZ_MAX_HEIGHT) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, GZ_HEADER_LEN);
  if (c->ops->block_header == NULL) return GZ_CHAIN_INVALID_ARG;
  return c->ops->block_header(c->ctx, height, out);
}

gz_chain_result gz_chain_block_summary(const gz_chain *c, uint32_t height, gz_block_summary *out) {
  if (!usable(c) || out == NULL || height > GZ_MAX_HEIGHT) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);
  if (c->ops->block_summary == NULL) return GZ_CHAIN_INVALID_ARG;
  return c->ops->block_summary(c->ctx, height, out);
}

gz_chain_result gz_chain_tx_status(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN],
                                   gz_tx_status *out) {
  if (!usable(c) || txid == NULL || out == NULL) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);
  if (c->ops->tx_status == NULL) return GZ_CHAIN_INVALID_ARG;
  return c->ops->tx_status(c->ctx, txid, out);
}

gz_chain_result gz_chain_script_outputs(const gz_chain *c, const uint8_t *script,
                                        size_t script_len, gz_chain_output *out, size_t cap,
                                        size_t *count, bool *unconfirmed_differs) {
  bool differs = false;
  if (unconfirmed_differs != NULL) *unconfirmed_differs = false;
  if (!usable(c) || script == NULL || script_len == 0 || script_len > GZ_SCRIPT_MAX_LEN ||
      out == NULL || cap == 0 || count == NULL)
    return GZ_CHAIN_INVALID_ARG;
  *count = 0;
  if (c->ops->script_outputs == NULL) return GZ_CHAIN_INVALID_ARG;
  gz_chain_result r = c->ops->script_outputs(c->ctx, script, script_len, out, cap, count, &differs);
  if (r == GZ_CHAIN_OK && unconfirmed_differs != NULL) *unconfirmed_differs = differs;
  return r;
}

gz_chain_result gz_chain_outspend(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN],
                                  uint32_t vout, gz_outspend *out) {
  if (!usable(c) || txid == NULL || out == NULL) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);
  if (c->ops->outspend == NULL) return GZ_CHAIN_INVALID_ARG;
  return c->ops->outspend(c->ctx, txid, vout, out);
}

gz_chain_result gz_chain_raw_tx(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN], uint8_t *buf,
                                size_t cap, size_t *len) {
  if (!usable(c) || txid == NULL || buf == NULL || cap == 0 || len == NULL)
    return GZ_CHAIN_INVALID_ARG;
  *len = 0;
  if (c->ops->raw_tx == NULL) return GZ_CHAIN_INVALID_ARG;
  return c->ops->raw_tx(c->ctx, txid, buf, cap, len);
}

gz_chain_result gz_chain_merkle_proof(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN],
                                      gz_merkle_proof *out) {
  if (!usable(c) || txid == NULL || out == NULL) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);
  if (c->ops->merkle_proof == NULL) return GZ_CHAIN_INVALID_ARG;
  return c->ops->merkle_proof(c->ctx, txid, out);
}

gz_chain_result gz_chain_broadcast(const gz_chain *c, const uint8_t *raw, size_t len,
                                   gz_broadcast_result *out) {
  uint8_t txid[GZ_HASH_LEN];
  if (out != NULL) {
    memset(out, 0, sizeof *out);
    out->result = GZ_CHAIN_INVALID_ARG;
  }
  if (!usable(c) || raw == NULL || out == NULL) return GZ_CHAIN_INVALID_ARG;
  /* nothing that is not a transaction of sane size reaches a backend */
  if (len > GZ_TX_MAX_BYTES) return GZ_CHAIN_INVALID_ARG;
  if (!gz_txid_from_raw(raw, len, txid)) return GZ_CHAIN_INVALID_ARG;
  if (c->ops->broadcast == NULL) return GZ_CHAIN_INVALID_ARG;
  gz_chain_result r = c->ops->broadcast(c->ctx, raw, len, out);
  out->result = r;
  return r;
}

gz_chain_result gz_chain_fee_estimates(const gz_chain *c, gz_fee_estimates *out) {
  if (!usable(c) || out == NULL) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);
  if (c->ops->fee_estimates == NULL) return GZ_CHAIN_INVALID_ARG;
  return c->ops->fee_estimates(c->ctx, out);
}

bool gz_chain_describe(const gz_chain *c, gz_chain_info *out) {
  if (out == NULL) return false;
  memset(out, 0, sizeof *out);
  if (!usable(c) || c->ops->describe == NULL) return false;
  if (!c->ops->describe(c->ctx, out)) {
    memset(out, 0, sizeof *out);
    return false;
  }
  out->endpoint[GZ_ENDPOINT_MAX - 1] = '\0';
  out->host[GZ_HOST_MAX - 1] = '\0';
  out->operator_id[GZ_OPERATOR_MAX - 1] = '\0';
  return true;
}

void gz_chain_destroy(gz_chain *c) {
  if (c == NULL) return;
  if (c->ops != NULL && c->ctx != NULL && c->ops->destroy != NULL) c->ops->destroy(c->ctx);
  c->ctx = NULL;
  c->ops = NULL;
}

/* ---- network identity ---------------------------------------------------- */

gz_chain_result gz_chain_identify_network(const gz_chain *c, gz_network *out) {
  static const gz_network all[] = {GZ_NET_MAINNET, GZ_NET_TESTNET3, GZ_NET_TESTNET4, GZ_NET_SIGNET};
  uint8_t block0[GZ_HASH_LEN], genesis[GZ_HASH_LEN];
  if (out == NULL) return GZ_CHAIN_INVALID_ARG;
  *out = GZ_NET_INVALID;
  gz_chain_result r = gz_chain_block_hash(c, 0, block0);
  if (r == GZ_CHAIN_NOT_FOUND) return GZ_CHAIN_WRONG_NETWORK; /* a chain with no block 0 */
  if (r != GZ_CHAIN_OK) return r;
  for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
    if (gz_network_genesis(all[i], genesis) && memcmp(block0, genesis, GZ_HASH_LEN) == 0) {
      *out = all[i];
      return GZ_CHAIN_OK;
    }
  }
  return GZ_CHAIN_WRONG_NETWORK;
}

gz_chain_result gz_chain_check_network(const gz_chain *c, gz_network network) {
  gz_network found = GZ_NET_INVALID;
  if (!gz_network_valid(network)) return GZ_CHAIN_INVALID_ARG;
  gz_chain_result r = gz_chain_identify_network(c, &found);
  if (r != GZ_CHAIN_OK) return r;
  return found == network ? GZ_CHAIN_OK : GZ_CHAIN_WRONG_NETWORK;
}

/* ---- fee rate policy ----------------------------------------------------- */

gz_chain_result gz_chain_choose_fee_rate(const gz_chain *c, gz_network network, uint16_t target,
                                         uint64_t ceiling_sat_per_kvb, gz_fee_choice *out) {
  gz_fee_estimates est;
  if (out != NULL) memset(out, 0, sizeof *out);
  if (out == NULL || !gz_network_valid(network) || target == 0 || ceiling_sat_per_kvb == 0)
    return GZ_CHAIN_INVALID_ARG;
  if (gz_network_is_test(network)) {
    /* Estimates on test networks are noise and are not consulted. */
    out->sat_per_kvb = GZ_FEE_TEST_DEFAULT_SAT_PER_KVB;
    out->source = GZ_FEE_FROM_TEST_DEFAULT;
    if (out->sat_per_kvb > ceiling_sat_per_kvb) {
      out->sat_per_kvb = ceiling_sat_per_kvb;
      out->capped = true;
    }
    return GZ_CHAIN_OK;
  }
  gz_chain_result r = gz_chain_fee_estimates(c, &est);
  if (r != GZ_CHAIN_OK) return r;
  if (est.count > GZ_FEE_MAX_TARGETS) return GZ_CHAIN_MALFORMED;
  /* the highest listed target not above `target`: the target asked for or
   * a faster one. A slower one would ask for less than is needed, so if
   * every listed target is above `target` there is no rate. */
  const gz_fee_estimate *pick = NULL;
  for (size_t i = 0; i < est.count; i++) {
    const gz_fee_estimate *e = &est.entries[i];
    if (e->target <= target && (pick == NULL || e->target > pick->target)) pick = e;
  }
  if (pick == NULL) return GZ_CHAIN_NOT_FOUND;
  uint64_t rate = pick->sat_per_kvb;
  if (rate > GZ_FEE_MAX_SAT_PER_KVB) return GZ_CHAIN_MALFORMED;
  out->source = GZ_FEE_FROM_SERVERS;
  if (rate < GZ_FEE_MIN_SAT_PER_KVB) rate = GZ_FEE_MIN_SAT_PER_KVB;
  if (rate > ceiling_sat_per_kvb) {
    rate = ceiling_sat_per_kvb;
    out->capped = true;
  }
  out->sat_per_kvb = rate;
  return GZ_CHAIN_OK;
}
