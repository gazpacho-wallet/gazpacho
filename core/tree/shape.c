/* terms.md section 4: the split rule, D, the fee per transaction and the
 * funding amount, written out from the import's behaviour
 * (src/factory.c:948-1010 split_clients_for_arity, :1694-1720 and :1299-1323
 * amounts). */
#include "gazpacho/tree.h"
#include "internal.h"

#include <string.h>

size_t gz_tree_levels(const gz_shape_entry_t *e, uint8_t levels[GZ_TREE_MAX_LEVELS])
{
    size_t i, n;
    if (!e || e->n_interior > GZ_TERMS_MAX_INTERIOR) return 0;
    n = e->n_interior;
    for (i = 0; i < n; i++) levels[i] = e->interior[i];
    levels[n] = e->leaf_kind;
    return n + 1;
}

const gz_shape_entry_t *gz_tree_shape_for(const gz_terms_outer_t *t, uint32_t n)
{
    size_t i;
    if (!t) return NULL;
    for (i = 0; i < t->n_shapes && i < GZ_TERMS_MAX_SHAPES; i++)
        if (t->shapes[i].max_members >= n) return &t->shapes[i];
    return NULL;
}

uint32_t tr_children(const uint8_t *levels, size_t n_levels, uint32_t m, uint32_t d, uint32_t sizes[16])
{
    uint32_t a = tr_level(levels, n_levels, d), j, rem = m, k = 0;
    if (a == GZ_TERMS_LEAF_PS) {
        if (m < 2) return 0;
        sizes[0] = m / 2;
        sizes[1] = m - m / 2;
        return 2;
    }
    if (a < 4 || a > 15 || m <= a) return 0;
    for (j = 0; j < a && rem > 0; j++) {
        uint32_t c = (rem + (a - j) - 1) / (a - j);
        if (c > rem) c = rem;
        sizes[k++] = c;
        rem -= c;
    }
    return k;
}

int tr_split(const uint8_t *levels, size_t n_levels, uint32_t m, uint32_t d, uint8_t *depths, uint32_t *k,
             uint32_t max_depth)
{
    uint32_t sizes[16], n, i;
    if (d > max_depth || m == 0) return 0;
    if (tr_level(levels, n_levels, d) == GZ_TERMS_LEAF_PS && m == 1) {
        if (depths) depths[*k] = (uint8_t)d;
        (*k)++;
        return 1;
    }
    n = tr_children(levels, n_levels, m, d, sizes);
    if (n == 0) return 0;
    for (i = 0; i < n; i++)
        if (!tr_split(levels, n_levels, sizes[i], d + 1, depths, k, max_depth)) return 0;
    return 1;
}

static int levels_ok(const uint8_t *levels, size_t n_levels)
{
    return levels && n_levels >= 1 && n_levels <= GZ_TREE_MAX_LEVELS;
}

int gz_tree_split(const uint8_t *levels, size_t n_levels, uint32_t n_members, uint8_t *depths)
{
    uint32_t k = 0;
    if (!levels_ok(levels, n_levels) || !depths || n_members == 0) return 0;
    return tr_split(levels, n_levels, n_members, 0, depths, &k, GZ_TREE_MAX_DEPTH) && k == n_members;
}

uint32_t gz_tree_vsize(uint32_t k)
{
    return (4 * (64 + 43 * k) + 2 + 66 + 3) / 4;
}

static int add_ok(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a > UINT64_MAX - b) return 0;
    *out = a + b;
    return 1;
}

static int mul_ok(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a && b > UINT64_MAX / a) return 0;
    *out = a * b;
    return 1;
}

static int requirement(const uint8_t *levels, size_t nl, uint32_t m, uint32_t d, uint64_t channel, uint64_t fee,
                       uint64_t *out)
{
    uint32_t sizes[16], n, i;
    uint64_t best = 0, r, x;
    if (d > GZ_TREE_MAX_DEPTH || m == 0) return 0;
    if (tr_level(levels, nl, d) == GZ_TERMS_LEAF_PS && m == 1) {
        /* R(leaf) = 2 channel + 2 fee + 2 x 240 */
        return mul_ok(channel, 2, &r) && mul_ok(fee, 2, &x) && add_ok(r, x, &r)
            && add_ok(r, 2 * GZ_TREE_ANCHOR_SAT, out);
    }
    n = tr_children(levels, nl, m, d, sizes);
    if (n == 0) return 0;
    for (i = 0; i < n; i++) {
        if (!requirement(levels, nl, sizes[i], d + 1, channel, fee, &r)) return 0;
        if (r > best) best = r;
    }
    /* R(node with k children) = k max R(child) + fee + 240 */
    return mul_ok(best, n, &r) && add_ok(r, fee, &r) && add_ok(r, GZ_TREE_ANCHOR_SAT, out);
}

int gz_tree_requirement(const uint8_t *levels, size_t n_levels, uint32_t n_members, uint64_t channel_sat,
                        uint64_t fee, uint64_t *out)
{
    if (!levels_ok(levels, n_levels) || !out) return 0;
    return requirement(levels, n_levels, n_members, 0, channel_sat, fee, out);
}

static uint32_t max_children(const uint8_t *levels, size_t nl, uint32_t m, uint32_t d)
{
    uint32_t sizes[16], n, i, best;
    if (tr_level(levels, nl, d) == GZ_TERMS_LEAF_PS && m == 1) return 2;   /* the leaf transaction */
    n = tr_children(levels, nl, m, d, sizes);
    best = n;
    for (i = 0; i < n; i++) {
        uint32_t c = max_children(levels, nl, sizes[i], d + 1);
        if (c > best) best = c;
    }
    return best;
}

gz_tree_p_err_t gz_tree_params(const gz_terms_outer_t *t, uint32_t n, gz_tree_params_t *p)
{
    const gz_shape_entry_t *e;
    uint32_t i;
    if (!t || !p) return GZ_TREE_P_COUNT;
    memset(p, 0, sizeof *p);
    if (n < 3 || n > GZ_TREE_MAX_MEMBERS) return GZ_TREE_P_COUNT;
    e = gz_tree_shape_for(t, n);
    if (!e) return GZ_TREE_P_NO_SHAPE;
    p->n_members = n;
    p->n_levels = gz_tree_levels(e, p->levels);
    if (!p->n_levels || !gz_tree_split(p->levels, p->n_levels, n, p->depth)) return GZ_TREE_P_SPLIT;
    for (i = 0; i < n; i++)
        if (p->depth[i] > p->D) p->D = p->depth[i];
    p->max_children = max_children(p->levels, p->n_levels, n, 0);
    p->V = gz_tree_vsize(p->max_children);
    p->fee_per_tx = ((uint64_t)t->tree_feerate * p->V + 999) / 1000;
    if (!gz_tree_requirement(p->levels, p->n_levels, n, t->channel_sat, p->fee_per_tx, &p->funding_amount))
        return GZ_TREE_P_OVERFLOW;
    return GZ_TREE_P_OK;
}

static int path(const uint8_t *levels, size_t nl, uint32_t m, uint32_t d, uint32_t offset, uint32_t member,
                uint8_t *outs, size_t *n)
{
    uint32_t sizes[16], k, i, off = offset;
    if (d >= GZ_TREE_MAX_DEPTH) return 0;   /* keeps outs[] inside GZ_TREE_MAX_DEPTH + 2 */
    if (tr_level(levels, nl, d) == GZ_TERMS_LEAF_PS && m == 1) {
        if (offset != member) return 0;
        outs[(*n)++] = 1;      /* the leaf's kickoff: the leaf transaction's output */
        outs[(*n)++] = 2;      /* the leaf transaction: channel and spare liquidity */
        return 1;
    }
    k = tr_children(levels, nl, m, d, sizes);
    if (k == 0) return 0;
    for (i = 0; i < k; i++) {
        if (member >= off && member < off + sizes[i]) {
            outs[(*n)++] = (uint8_t)k;
            return path(levels, nl, sizes[i], d + 1, off, member, outs, n);
        }
        off += sizes[i];
    }
    return 0;
}

size_t gz_tree_member_path(const uint8_t *levels, size_t n_levels, uint32_t n_members, uint32_t member,
                           uint8_t *depth, uint8_t outs[GZ_TREE_MAX_DEPTH + 2])
{
    size_t n = 0;
    if (!levels_ok(levels, n_levels) || !depth || !outs || member >= n_members) return 0;
    if (!path(levels, n_levels, n_members, 0, 0, member, outs, &n)) return 0;
    *depth = (uint8_t)(n - 2);
    return n;
}
