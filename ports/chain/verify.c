/* gz_chain_confirm_tx: a server's "confirmed" claim checked step by step.
 * Works on any gz_chain, including the comparing one. The steps and what
 * they are worth are documented at the declaration in chain.h. */
#include "gazpacho/chain.h"

#include <stdlib.h>
#include <string.h>

/* A NOT_FOUND for something the server has just vouched for is the server
 * contradicting itself, which is a failed proof, not a clean "no". */
static gz_chain_result must_exist(gz_chain_result r) {
  return r == GZ_CHAIN_NOT_FOUND ? GZ_CHAIN_BAD_PROOF : r;
}

static gz_chain_result check_confirmed(const gz_chain *c, gz_network network,
                                       const uint8_t txid[GZ_HASH_LEN], uint32_t want,
                                       gz_confirmation *out, uint8_t *txbuf) {
  uint8_t hash[GZ_HASH_LEN], check[GZ_HASH_LEN];
  size_t tx_len = 0;
  gz_chain_result r;
  const uint32_t height = out->status.height;

  /* 2. the id belongs to a real transaction */
  r = must_exist(gz_chain_raw_tx(c, txid, txbuf, GZ_TX_MAX_BYTES, &tx_len));
  if (r != GZ_CHAIN_OK) return r;
  if (!gz_txid_from_raw(txbuf, tx_len, check) || memcmp(check, txid, GZ_HASH_LEN) != 0)
    return GZ_CHAIN_BAD_PROOF;
  bool tx_is_coinbase = gz_tx_is_coinbase(txbuf, tx_len);

  /* 3. the header is the block the status names, and cost its stated work */
  r = must_exist(gz_chain_block_header(c, height, out->header));
  if (r != GZ_CHAIN_OK) return r;
  gz_header_hash(out->header, hash);
  if (memcmp(hash, out->status.block_hash, GZ_HASH_LEN) != 0) return GZ_CHAIN_BAD_PROOF;
  if (gz_header_check_pow(out->header, network) != GZ_POW_OK) return GZ_CHAIN_BAD_PROOF;

  /* 4. the branch has the shape of this block and reaches its root */
  r = must_exist(gz_chain_block_summary(c, height, &out->block));
  if (r != GZ_CHAIN_OK) return r;
  if (memcmp(out->block.hash, out->status.block_hash, GZ_HASH_LEN) != 0) return GZ_CHAIN_BAD_PROOF;
  if (out->block.tx_count == 0 || out->block.tx_count > GZ_MAX_BLOCK_TXS) return GZ_CHAIN_BAD_PROOF;
  const uint32_t depth = gz_merkle_depth_for_count(out->block.tx_count);

  r = must_exist(gz_chain_merkle_proof(c, txid, &out->proof));
  if (r != GZ_CHAIN_OK) return r;
  if (out->proof.block_height != height) return GZ_CHAIN_BAD_PROOF;
  if (out->proof.depth != depth) return GZ_CHAIN_BAD_PROOF;
  if (out->proof.pos >= out->block.tx_count) return GZ_CHAIN_BAD_PROOF;
  if (!gz_merkle_verify(txid, &out->proof, out->header)) return GZ_CHAIN_BAD_PROOF;

  /* 5. the coinbase pins the depth: it is a real transaction at position 0,
   * so its branch is exactly as long as the tree is deep */
  if (out->proof.pos == 0) {
    if (memcmp(txid, out->block.coinbase_txid, GZ_HASH_LEN) != 0) return GZ_CHAIN_BAD_PROOF;
    if (!tx_is_coinbase) return GZ_CHAIN_BAD_PROOF;
  } else {
    gz_merkle_proof cb_proof;
    if (tx_is_coinbase) return GZ_CHAIN_BAD_PROOF; /* a coinbase anywhere but first */
    r = must_exist(gz_chain_raw_tx(c, out->block.coinbase_txid, txbuf, GZ_TX_MAX_BYTES, &tx_len));
    if (r != GZ_CHAIN_OK) return r;
    if (!gz_txid_from_raw(txbuf, tx_len, check) ||
        memcmp(check, out->block.coinbase_txid, GZ_HASH_LEN) != 0)
      return GZ_CHAIN_BAD_PROOF;
    if (!gz_tx_is_coinbase(txbuf, tx_len)) return GZ_CHAIN_BAD_PROOF;
    r = must_exist(gz_chain_merkle_proof(c, out->block.coinbase_txid, &cb_proof));
    if (r != GZ_CHAIN_OK) return r;
    if (cb_proof.block_height != height || cb_proof.pos != 0 || cb_proof.depth != depth)
      return GZ_CHAIN_BAD_PROOF;
    if (!gz_merkle_verify(out->block.coinbase_txid, &cb_proof, out->header))
      return GZ_CHAIN_BAD_PROOF;
  }
  out->checked_confirmations = 1;

  /* 6. later headers, each linking to the one before, up to the tip. On the
   * comparing backend that is the agreed (lowest) tip, so a server that has
   * already seen a newer block does not stall the count. */
  if (want < 2) return GZ_CHAIN_OK;
  gz_chain_tip tip;
  r = gz_chain_tip_get(c, &tip);
  if (r != GZ_CHAIN_OK) return r;
  uint8_t prev[GZ_HEADER_LEN], next[GZ_HEADER_LEN];
  memcpy(prev, out->header, GZ_HEADER_LEN);
  for (uint32_t k = 1; k < want; k++) {
    if (height > GZ_MAX_HEIGHT - k || height + k > tip.height) break;
    r = gz_chain_block_header(c, height + k, next);
    if (r == GZ_CHAIN_NOT_FOUND) break; /* the chain is not that long yet */
    if (r != GZ_CHAIN_OK) return r;
    if (!gz_header_links(prev, next)) return GZ_CHAIN_BAD_PROOF;
    if (gz_header_check_pow(next, network) != GZ_POW_OK) return GZ_CHAIN_BAD_PROOF;
    out->checked_confirmations++;
    memcpy(prev, next, GZ_HEADER_LEN);
  }
  return GZ_CHAIN_OK;
}

gz_chain_result gz_chain_confirm_tx(const gz_chain *c, gz_network network,
                                    const uint8_t txid[GZ_HASH_LEN], uint32_t want_confirmations,
                                    gz_confirmation *out) {
  gz_chain_result r;
  if (out != NULL) memset(out, 0, sizeof *out);
  if (c == NULL || txid == NULL || out == NULL || !gz_network_valid(network))
    return GZ_CHAIN_INVALID_ARG;
  if (want_confirmations < 1) want_confirmations = 1;
  if (want_confirmations > GZ_CONFIRM_MAX_DEPTH) want_confirmations = GZ_CONFIRM_MAX_DEPTH;

  /* 1. the right chain */
  r = gz_chain_check_network(c, network);
  if (r != GZ_CHAIN_OK) return r;

  gz_tx_status status;
  r = gz_chain_tx_status(c, txid, &status);
  if (r != GZ_CHAIN_OK) return r;
  out->status = status;
  if (status.state != GZ_TX_CONFIRMED) return GZ_CHAIN_OK;

  /* fixed size: chosen by us, not by anything a server says */
  uint8_t *txbuf = malloc(GZ_TX_MAX_BYTES);
  if (txbuf == NULL) {
    memset(out, 0, sizeof *out);
    return GZ_CHAIN_NO_MEMORY;
  }
  r = check_confirmed(c, network, txid, want_confirmations, out, txbuf);
  free(txbuf);
  if (r != GZ_CHAIN_OK) {
    /* nothing half-checked is handed back as if it were confirmed */
    memset(out, 0, sizeof *out);
  }
  return r;
}
