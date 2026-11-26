/* The amount a hosted lobby sets aside (spec/local-api.md 15.2): opening is
 * the host's consent to spend up to it when the start rule is met, and an
 * early start echoes it (`confirm_funding_max_sat`). It is the factory
 * output a start can need: the funding amount R(root) of terms.md 4.2, the
 * largest over every member count a start may have (the minimum to the
 * target). The host's own funding transaction fee is the wallet's, outside
 * it. Pure: the terms alone decide it. */
#include "gazpacho/funding.h"

uint64_t gz_fund_set_aside_sat(const gz_terms_outer_t *t)
{
    gz_tree_params_t p;
    uint64_t most = 0;
    if (!t || t->minimum > t->target) return 0;
    for (uint32_t n = t->minimum; n <= t->target; n++) {
        if (gz_tree_params(t, n, &p) != GZ_TREE_P_OK) return 0;
        if (p.funding_amount > most) most = p.funding_amount;
    }
    return most;
}
