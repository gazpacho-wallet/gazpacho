/* The vectors build's one extra operation (review B of #71, M2). Compiled
 * into gazpacho_signer_vectors only, never into gazpacho_signer: the
 * production sources hold no fixed-aux path to switch on. */
#ifndef GAZPACHO_SIGNER_VECTORS_AUX_H
#define GAZPACHO_SIGNER_VECTORS_AUX_H

#include "gazpacho/signer.h"

/* gz_sg_sign_envelope with BIP 340's all-zero aux_rand, for byte-exact test
 * vectors. Only the host's round_tier_result (72) and round_abort (78), the
 * messages the engine rebuilt before decision K20; anything else is
 * GZ_SG_E_KIND with `sig` zeroed. Every other check is the production one. */
gz_sg_err_t gz_sgv_sign_envelope_fixed(gz_signer_t *sg, gz_sg_key_t key, const uint8_t scope[32], uint16_t kind,
                                       const uint8_t *records, size_t len, uint8_t sig[64]);

#endif
