/*
 * Block header and Merkle proof checks. Pure functions: no network, no state.
 * What the proof-of-work check is worth on each network is documented at
 * gz_header_check_pow in chain.h.
 */
#include "gazpacho/chain.h"

#include <string.h>

static uint32_t le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void gz_header_parse(const uint8_t raw[GZ_HEADER_LEN], gz_block_header *out) {
  out->version = (int32_t)le32(raw);
  memcpy(out->prev_hash, raw + 4, GZ_HASH_LEN);
  memcpy(out->merkle_root, raw + 36, GZ_HASH_LEN);
  out->time = le32(raw + 68);
  out->bits = le32(raw + 72);
  out->nonce = le32(raw + 76);
}

void gz_header_hash(const uint8_t raw[GZ_HEADER_LEN], uint8_t out[GZ_HASH_LEN]) {
  gz_sha256d(raw, GZ_HEADER_LEN, out);
}

bool gz_header_links(const uint8_t prev[GZ_HEADER_LEN], const uint8_t next[GZ_HEADER_LEN]) {
  uint8_t h[GZ_HASH_LEN];
  gz_header_hash(prev, h);
  return memcmp(h, next + 4, GZ_HASH_LEN) == 0;
}

bool gz_bits_to_target(uint32_t bits, uint8_t target_be[GZ_HASH_LEN]) {
  uint32_t exponent = bits >> 24;
  uint32_t mantissa = bits & 0x007fffff;
  memset(target_be, 0, GZ_HASH_LEN);
  if ((bits & 0x00800000) != 0) return false; /* negative */
  if (mantissa == 0) return false;            /* zero target */
  if (exponent > 34 || (mantissa > 0xff && exponent > 33) || (mantissa > 0xffff && exponent > 32))
    return false; /* does not fit in 256 bits */
  if (exponent <= 3) {
    mantissa >>= 8 * (3 - exponent);
    if (mantissa == 0) return false;
    target_be[29] = (uint8_t)(mantissa >> 16);
    target_be[30] = (uint8_t)(mantissa >> 8);
    target_be[31] = (uint8_t)mantissa;
    return true;
  }
  /* the three mantissa bytes sit so that the lowest is `exponent - 3` bytes
   * above the bottom of the number */
  for (uint32_t i = 0; i < 3; i++) {
    uint32_t byte_from_low = exponent - 3 + i; /* 0 is the least significant */
    uint8_t b = (uint8_t)(mantissa >> (8 * i));
    if (byte_from_low < GZ_HASH_LEN) target_be[GZ_HASH_LEN - 1 - byte_from_low] = b;
  }
  return true;
}

/* The easiest target each network allows, as its compact encoding. */
static uint32_t pow_limit_bits(gz_network network) {
  switch (network) {
    case GZ_NET_SIGNET: return 0x1e0377ae;
    case GZ_NET_MAINNET:
    case GZ_NET_TESTNET3:
    case GZ_NET_TESTNET4: return 0x1d00ffff;
  }
  return 0x1d00ffff;
}

gz_pow_result gz_header_check_pow(const uint8_t raw[GZ_HEADER_LEN], gz_network network) {
  uint8_t target[GZ_HASH_LEN], limit[GZ_HASH_LEN], hash[GZ_HASH_LEN], hash_be[GZ_HASH_LEN];
  if (!gz_bits_to_target(le32(raw + 72), target)) return GZ_POW_BAD_BITS;
  if (!gz_bits_to_target(pow_limit_bits(network), limit)) return GZ_POW_BAD_BITS;
  if (memcmp(target, limit, GZ_HASH_LEN) > 0) return GZ_POW_TOO_EASY;
  gz_header_hash(raw, hash);
  for (size_t i = 0; i < GZ_HASH_LEN; i++) hash_be[i] = hash[GZ_HASH_LEN - 1 - i];
  if (memcmp(hash_be, target, GZ_HASH_LEN) > 0) return GZ_POW_HASH_ABOVE;
  return GZ_POW_OK;
}

bool gz_merkle_root_from_proof(const uint8_t txid[GZ_HASH_LEN], const gz_merkle_proof *proof,
                               uint8_t root[GZ_HASH_LEN]) {
  uint8_t pair[2 * GZ_HASH_LEN];
  uint8_t cur[GZ_HASH_LEN];
  if (txid == NULL || proof == NULL || root == NULL) return false;
  if (proof->depth > GZ_MERKLE_MAX_DEPTH) return false;
  if (proof->depth < 32 && (proof->pos >> proof->depth) != 0) return false;
  memcpy(cur, txid, GZ_HASH_LEN);
  uint32_t pos = proof->pos;
  for (uint32_t i = 0; i < proof->depth; i++) {
    if (pos & 1) {
      memcpy(pair, proof->nodes[i], GZ_HASH_LEN);
      memcpy(pair + GZ_HASH_LEN, cur, GZ_HASH_LEN);
    } else {
      memcpy(pair, cur, GZ_HASH_LEN);
      memcpy(pair + GZ_HASH_LEN, proof->nodes[i], GZ_HASH_LEN);
    }
    gz_sha256d(pair, sizeof pair, cur);
    pos >>= 1;
  }
  memcpy(root, cur, GZ_HASH_LEN);
  return true;
}

bool gz_merkle_verify(const uint8_t txid[GZ_HASH_LEN], const gz_merkle_proof *proof,
                      const uint8_t header[GZ_HEADER_LEN]) {
  uint8_t root[GZ_HASH_LEN];
  if (header == NULL) return false;
  if (!gz_merkle_root_from_proof(txid, proof, root)) return false;
  return memcmp(root, header + 36, GZ_HASH_LEN) == 0;
}
