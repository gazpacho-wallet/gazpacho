/* The lobby's use of core/tree's terms library: its policy, the deciding term
 * of a comparison, the crypto adapter for receipt, and the build parameters
 * of the hand-off. No terms rule is written here: every bound, every
 * comparison and the shape rule are core/tree's. */
#include "lobby_internal.h"
#include <string.h>

const gz_terms_policy_t *gz_lobby_policy(void)
{
    static const gz_terms_policy_t P = {1};
    return &P;
}

/* ------------------------------------------------------------ comparison */

/* The class the limits give when only the field of terms.md type `type` is
 * kept (every other field at its "no limit" value, no adjustable limit but
 * those of `type`). */
static gz_terms_class_t alone(const gz_terms_outer_t *o, const gz_terms_current_t *c,
                              const gz_terms_limits_t *l, uint8_t type)
{
    gz_terms_limits_t one;
    uint8_t j;
    memset(&one, 0, sizeof one);
    switch (type) {
    case GZ_TT_PROFILE: one.profiles = l->profiles; break;
    case GZ_TT_MINIMUM: one.min_members = l->min_members; break;
    case GZ_TT_LIFETIME: one.min_lifetime = l->min_lifetime; one.max_lifetime = l->max_lifetime; break;
    case GZ_TT_CHANNEL: one.min_channel_sat = l->min_channel_sat; break;
    case GZ_TT_FEERATE: one.max_tree_feerate = l->max_tree_feerate; break;
    default:
        for (j = 0; j < l->n_max && j < GZ_TERMS_MAX_ADJ; j++)
            if (l->max[j].type == type) one.max[one.n_max++] = l->max[j];
        break;
    }
    return gz_terms_classify(o, c, &one);
}

int gz_lobby_classify(const gz_terms_outer_t *o, const gz_terms_current_t *c,
                      const gz_lobby_conditions_t *cond, uint8_t *term)
{
    static const uint8_t FIXED[5] = {GZ_TT_PROFILE, GZ_TT_MINIMUM, GZ_TT_LIFETIME, GZ_TT_CHANNEL, GZ_TT_FEERATE};
    gz_terms_class_t all = gz_terms_classify(o, c, &cond->limits);
    uint8_t k;
    *term = 0;
    if (all == GZ_TERMS_FITS) return GZ_FIT_YES;
    if (all == GZ_TERMS_DOES_NOT_FIT)
        for (k = 0; k < 5; k++)
            if (alone(o, c, &cond->limits, FIXED[k]) == GZ_TERMS_DOES_NOT_FIT) { *term = FIXED[k]; return GZ_FIT_NO; }
    for (k = 0; k < o->n_adj && k < GZ_TERMS_MAX_ADJ; k++)   /* the outer record's types, increasing */
        if (alone(o, c, &cond->limits, o->adj[k].type) == all) { *term = o->adj[k].type; break; }
    return all == GZ_TERMS_DOES_NOT_FIT ? GZ_FIT_NO : GZ_FIT_NOW;
}

int gz_lobby_ready_ok(int cls, const gz_lobby_conditions_t *cond)
{
    return cls == GZ_FIT_YES || (cls == GZ_FIT_NOW && cond->current_only);
}

/* --------------------------------------------------------------- receipt */

static int tc_point(void *ctx, const uint8_t pub[33])
{
    const gz_lobby_crypto_t *c = ctx;
    return c->point_ok(c->ctx, pub) == 1;
}

static int tc_verify(void *ctx, const uint8_t msg[32], const uint8_t pub[33], const uint8_t sig[64])
{
    const gz_lobby_crypto_t *c = ctx;
    return c->verify(c->ctx, pub, msg, sig) == 1;
}

void gz_la_tree_crypto(const gz_lobby_crypto_t *c, gz_tree_crypto_t *out)
{
    memset(out, 0, sizeof *out);
    out->ctx = (void *)(uintptr_t)c;
    out->point_valid = tc_point;
    out->verify = tc_verify;
}

int gz_la_decode_terms(const uint8_t *outer, size_t olen, const uint8_t *cur, size_t clen,
                       gz_terms_outer_t *o, uint8_t od[32], gz_terms_current_t *c, uint8_t cd[32])
{
    if (!outer || !cur || gz_terms_decode_outer(outer, olen, gz_lobby_policy(), o) != GZ_TERMS_OK) return 0;
    gz_terms_outer_digest(outer, olen, od);
    if (gz_terms_decode_current(cur, clen, o, c) != GZ_TERMS_OK || memcmp(c->outer_digest, od, 32) != 0) return 0;
    gz_terms_current_digest(cur, clen, cd);
    return 1;
}

/* ---------------------------------------------------------------- shape */

void gz_la_shape(const gz_terms_outer_t *o, uint16_t members, gz_lobby_handoff_t *ho)
{
    gz_tree_params_t p;
    ho->k = 1;
    ho->tree_anchors = 1;
    ho->layer_step = GZ_TREE_SLICE1_STEP;
    ho->layer_states = GZ_TREE_SLICE1_STATES;
    ho->n_levels = 0;                                 /* no shape: the signing engine refuses */
    if (gz_tree_params(o, members, &p) != GZ_TREE_P_OK || p.n_levels > sizeof ho->levels) return;
    memcpy(ho->levels, p.levels, p.n_levels);
    ho->n_levels = (uint8_t)p.n_levels;
    ho->fixed_levels = p.D;
}
