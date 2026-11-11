/* Argument-checking front of the gz_chain interface, names, hex and hashing. */
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
    case GZ_CHAIN_DISAGREE: return "servers-disagree";
    case GZ_CHAIN_NO_QUORUM: return "no-quorum";
    case GZ_CHAIN_INVALID_ARG: return "invalid-argument";
    case GZ_CHAIN_NO_MEMORY: return "no-memory";
  }
  return "unknown";
}

const char *gz_network_name(gz_network n) {
  switch (n) {
    case GZ_NET_MAINNET: return "mainnet";
    case GZ_NET_TESTNET3: return "testnet";
    case GZ_NET_TESTNET4: return "testnet4";
    case GZ_NET_SIGNET: return "signet";
  }
  return "unknown";
}

bool gz_network_from_name(const char *name, gz_network *out) {
  if (name == NULL || out == NULL) return false;
  for (int n = GZ_NET_MAINNET; n <= GZ_NET_SIGNET; n++) {
    if (strcmp(name, gz_network_name((gz_network)n)) == 0) {
      *out = (gz_network)n;
      return true;
    }
  }
  return false;
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

/* ---- interface front --------------------------------------------------- */

static bool usable(const gz_chain *c) { return c != NULL && c->ops != NULL && c->ctx != NULL; }

gz_chain_result gz_chain_tip_get(const gz_chain *c, gz_chain_tip *out) {
  if (!usable(c) || out == NULL) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);
  return c->ops->tip(c->ctx, out);
}

gz_chain_result gz_chain_block_hash(const gz_chain *c, uint32_t height, uint8_t out[GZ_HASH_LEN]) {
  if (!usable(c) || out == NULL || height > GZ_MAX_HEIGHT) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, GZ_HASH_LEN);
  return c->ops->block_hash(c->ctx, height, out);
}

gz_chain_result gz_chain_block_header(const gz_chain *c, uint32_t height,
                                      uint8_t out[GZ_HEADER_LEN]) {
  if (!usable(c) || out == NULL || height > GZ_MAX_HEIGHT) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, GZ_HEADER_LEN);
  return c->ops->block_header(c->ctx, height, out);
}

gz_chain_result gz_chain_tx_status(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN],
                                   gz_tx_status *out) {
  if (!usable(c) || txid == NULL || out == NULL) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);
  return c->ops->tx_status(c->ctx, txid, out);
}

gz_chain_result gz_chain_script_outputs(const gz_chain *c, const uint8_t *script,
                                        size_t script_len, gz_chain_output *out, size_t cap,
                                        size_t *count) {
  if (!usable(c) || script == NULL || script_len == 0 || script_len > GZ_SCRIPT_MAX_LEN ||
      out == NULL || cap == 0 || count == NULL)
    return GZ_CHAIN_INVALID_ARG;
  *count = 0;
  return c->ops->script_outputs(c->ctx, script, script_len, out, cap, count);
}

gz_chain_result gz_chain_outspend(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN],
                                  uint32_t vout, gz_outspend *out) {
  if (!usable(c) || txid == NULL || out == NULL) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);
  return c->ops->outspend(c->ctx, txid, vout, out);
}

gz_chain_result gz_chain_raw_tx(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN], uint8_t *buf,
                                size_t cap, size_t *len) {
  if (!usable(c) || txid == NULL || buf == NULL || cap == 0 || len == NULL)
    return GZ_CHAIN_INVALID_ARG;
  *len = 0;
  return c->ops->raw_tx(c->ctx, txid, buf, cap, len);
}

gz_chain_result gz_chain_merkle_proof(const gz_chain *c, const uint8_t txid[GZ_HASH_LEN],
                                      gz_merkle_proof *out) {
  if (!usable(c) || txid == NULL || out == NULL) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);
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
  if (!gz_txid_from_raw(raw, len, txid)) return GZ_CHAIN_INVALID_ARG;
  gz_chain_result r = c->ops->broadcast(c->ctx, raw, len, out);
  out->result = r;
  return r;
}

gz_chain_result gz_chain_fee_estimates(const gz_chain *c, gz_fee_estimates *out) {
  if (!usable(c) || out == NULL) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);
  return c->ops->fee_estimates(c->ctx, out);
}

void gz_chain_destroy(gz_chain *c) {
  if (c == NULL) return;
  if (c->ops != NULL && c->ctx != NULL && c->ops->destroy != NULL) c->ops->destroy(c->ctx);
  c->ctx = NULL;
  c->ops = NULL;
}
