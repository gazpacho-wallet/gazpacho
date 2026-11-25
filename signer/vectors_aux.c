/* The vectors build's fixed-aux signature (vectors_aux.h). Compiled into
 * gazpacho_signer_vectors only. It runs the production gz_sg_sign_envelope
 * with a random port that writes zeros, so the signed bytes, the checks and
 * the verification are the production code's. */
#include "internal.h"
#include "vectors_aux.h"
#include "gazpacho/round_msg.h"

#include <string.h>

/* Present in this build only. signer_link_guard requires it absent from
 * gazpacho_signer, and signer_never_ship from every program the build makes. */
const char gz_sg_vectors_build_never_ship[] = "gazpacho signer vectors build: never ship";

static void zero_fill(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    (void)ctx;
    (void)purpose;
    memset(out, 0, len);
}

gz_sg_err_t gz_sgv_sign_envelope_fixed(gz_signer_t *sg, gz_sg_key_t key, const uint8_t scope[32], uint16_t kind,
                                       const uint8_t *records, size_t len, uint8_t sig[64])
{
    gz_random_port_t saved;
    gz_sg_err_t e;
    if (sig) memset(sig, 0, 64);
    if (!sg || !sig) return GZ_SG_E_ARG;
    if (sg->cfg.role != GZ_SG_ROLE_HOST || (kind != GZ_KIND_ROUND_TIER_RESULT && kind != GZ_KIND_ROUND_ABORT))
        return GZ_SG_E_KIND;
    saved = sg->cfg.random;
    sg->cfg.random.fill = zero_fill;
    sg->cfg.random.ctx = NULL;
    e = gz_sg_sign_envelope(sg, key, scope, kind, records, len, sig);
    sg->cfg.random = saved;
    return e;
}
