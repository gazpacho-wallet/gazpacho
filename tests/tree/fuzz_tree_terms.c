/* Fuzz target: the terms decoder (terms.md sections 2 to 5).
 *
 * The first byte splits the rest into an outer record and a current record.
 * Properties, each an abort if broken:
 *   - the decoders never read out of bounds (the sanitizers watch);
 *   - CANONICAL: a record that parses re-encodes to exactly its own bytes
 *     (unless it carried unknown odd types, which are not re-encoded), so one
 *     set of terms has one byte string and one digest (section 2);
 *   - an outer record that passes every bound has a usable shape table: for
 *     each n from 3 to the target, terms.md 4.2's parameters exist and the
 *     funding amount does not overflow, or the overflow is reported. */
#include "gazpacho/terms.h"
#include "gazpacho/tree.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    static gz_terms_outer_t o;
    static gz_terms_current_t c;
    static uint8_t buf[GZ_TERMS_OUTER_MAX];
    static const gz_terms_policy_t any = {0}, slice1 = {1};
    const uint8_t *ob, *cb;
    size_t on, cn, m;
    if (n < 1) return 0;
    on = (size_t)d[0] * (n - 1) / 255;
    ob = d + 1;
    cb = d + 1 + on;
    cn = n - 1 - on;

    if (gz_terms_decode_current(cb, cn, NULL, &c) == GZ_TERMS_OK) {
        m = gz_terms_encode_current(&c, buf, sizeof buf);
        if (m != cn || memcmp(buf, cb, cn) != 0) abort();
    }
    if (gz_terms_parse_outer(ob, on, &o) != GZ_TERMS_OK) return 0;
    if (o.n_unknown_odd == 0) {
        m = gz_terms_encode_outer(&o, buf, sizeof buf);
        if (m != on || memcmp(buf, ob, on) != 0) abort();
    }
    (void)gz_terms_check_outer(&o, &slice1);
    if (gz_terms_check_outer(&o, &any) == GZ_TERMS_OK) {
        uint32_t k;
        gz_tree_params_t p;
        for (k = 3; k <= o.target && k <= GZ_TREE_MAX_MEMBERS; k++) {
            gz_tree_p_err_t e = gz_tree_params(&o, k, &p);
            if (e != GZ_TREE_P_OK && e != GZ_TREE_P_OVERFLOW) abort();   /* 4.3 promised a valid split */
            if (e == GZ_TREE_P_OK && (p.D == 0 || p.fee_per_tx == 0 || p.funding_amount == 0)) abort();
        }
        if (gz_terms_decode_current(cb, cn, &o, &c) == GZ_TERMS_OK) {
            gz_terms_limits_t l;
            memset(&l, 0, sizeof l);
            (void)gz_terms_classify(&o, &c, &l);
        }
    }
    return 0;
}
