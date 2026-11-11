/* gz_chain_confirm_tx: a server's "confirmed" claim checked against a header
 * and a Merkle proof. Works on any gz_chain, including the comparing one. */
#include "gazpacho/chain.h"

#include <string.h>

gz_chain_result gz_chain_confirm_tx(const gz_chain *c, gz_network network,
                                    const uint8_t txid[GZ_HASH_LEN], gz_confirmation *out) {
  uint8_t hash[GZ_HASH_LEN];
  gz_chain_result r;
  if (c == NULL || txid == NULL || out == NULL) return GZ_CHAIN_INVALID_ARG;
  memset(out, 0, sizeof *out);

  r = gz_chain_tx_status(c, txid, &out->status);
  if (r != GZ_CHAIN_OK) return r;
  if (out->status.state != GZ_TX_CONFIRMED) return GZ_CHAIN_OK;

  r = gz_chain_block_header(c, out->status.height, out->header);
  if (r == GZ_CHAIN_NOT_FOUND) return GZ_CHAIN_BAD_PROOF; /* confirmed in a block it cannot show */
  if (r != GZ_CHAIN_OK) return r;
  gz_header_hash(out->header, hash);
  if (memcmp(hash, out->status.block_hash, GZ_HASH_LEN) != 0) return GZ_CHAIN_BAD_PROOF;
  if (gz_header_check_pow(out->header, network) != GZ_POW_OK) return GZ_CHAIN_BAD_PROOF;

  r = gz_chain_merkle_proof(c, txid, &out->proof);
  if (r == GZ_CHAIN_NOT_FOUND) return GZ_CHAIN_BAD_PROOF; /* confirmed but no proof offered */
  if (r != GZ_CHAIN_OK) return r;
  if (out->proof.block_height != out->status.height) return GZ_CHAIN_BAD_PROOF;
  if (!gz_merkle_verify(txid, &out->proof, out->header)) return GZ_CHAIN_BAD_PROOF;
  return GZ_CHAIN_OK;
}
