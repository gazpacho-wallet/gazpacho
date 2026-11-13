/* The tree through the imported SuperScalar builder (tree_import.h). */
#include "gazpacho/tree_import.h"

#include "superscalar/factory.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <secp256k1_schnorrsig.h>
#include <stdlib.h>
#include <string.h>

/* ----------------------------------------------------- crypto provider */

static int parse_point(const secp256k1_context *ctx, const uint8_t pub[33], secp256k1_pubkey *pk)
{
    if (pub[0] != 2 && pub[0] != 3) return 0;
    return secp256k1_ec_pubkey_parse(ctx, pk, pub, 33);
}

static int c_point_valid(void *ctx, const uint8_t pub[33])
{
    secp256k1_pubkey pk;
    return parse_point(ctx, pub, &pk);
}

static int c_verify(void *ctx, const uint8_t msg[32], const uint8_t pub[33], const uint8_t sig[64])
{
    secp256k1_pubkey pk;
    secp256k1_xonly_pubkey x;
    if (!parse_point(ctx, pub, &pk) || !secp256k1_xonly_pubkey_from_pubkey(ctx, &x, NULL, &pk)) return 0;
    return secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &x);
}

static int c_agg_tweak(void *ctx, const uint8_t first[33], const uint8_t (*rest)[33], size_t n_rest,
                       const uint8_t *merkle, uint8_t internal[32], uint8_t output[32])
{
    secp256k1_context *c = ctx;
    size_t n = n_rest + 1, i;
    secp256k1_pubkey *pks;
    const secp256k1_pubkey **ptrs;
    secp256k1_xonly_pubkey agg, outx;
    secp256k1_pubkey tweaked;
    uint8_t buf[64], tweak[32];
    int ok = 0;
    if (n_rest > GZ_TREE_MAX_MEMBERS || (n_rest && !rest)) return 0;
    pks = malloc(n * sizeof *pks);
    ptrs = malloc(n * sizeof *ptrs);
    if (!pks || !ptrs) goto done;
    if (!parse_point(c, first, &pks[0])) goto done;
    for (i = 0; i < n_rest; i++)
        if (!parse_point(c, rest[i], &pks[i + 1])) goto done;
    for (i = 0; i < n; i++) ptrs[i] = &pks[i];
    /* KeyAgg in the given order: no key sorting (BIP 327 leaves it to the caller). */
    /* The pinned secp256k1-zkp takes a scratch space first (NULL: none). */
    if (!secp256k1_musig_pubkey_agg(c, NULL, &agg, NULL, ptrs, n)) goto done;
    if (!secp256k1_xonly_pubkey_serialize(c, internal, &agg)) goto done;
    memcpy(buf, internal, 32);
    if (merkle) memcpy(buf + 32, merkle, 32);
    if (!secp256k1_tagged_sha256(c, tweak, (const unsigned char *)"TapTweak", 8, buf, merkle ? 64 : 32)) goto done;
    if (!secp256k1_xonly_pubkey_tweak_add(c, &tweaked, &agg, tweak)) goto done;
    if (!secp256k1_xonly_pubkey_from_pubkey(c, &outx, NULL, &tweaked)) goto done;
    if (!secp256k1_xonly_pubkey_serialize(c, output, &outx)) goto done;
    ok = 1;
done:
    free(pks);
    free((void *)ptrs);
    return ok;
}

void gz_tree_secp_crypto(secp256k1_context *ctx, gz_tree_crypto_t *out)
{
    out->ctx = ctx;
    out->point_valid = c_point_valid;
    out->verify = c_verify;
    out->agg_tweak = c_agg_tweak;
}

/* ------------------------------------------------------------- the build */

gz_tree_i_err_t gz_tree_import_build(secp256k1_context *ctx, const gz_tree_build_in_t *in, gz_tree_import_t *out)
{
    size_t n, i;
    secp256k1_pubkey *pks = NULL;
    factory_t *f = NULL;
    gz_tree_i_err_t err = GZ_TREE_I_ARGUMENT;
    if (!ctx || !in || !out || !in->levels || !in->host_key || !in->member_keys || in->n_levels < 1
        || in->n_levels > GZ_TREE_MAX_LEVELS || in->n_members < 1 || in->n_members > GZ_TREE_MAX_MEMBERS)
        return GZ_TREE_I_ARGUMENT;
    memset(out, 0, sizeof *out);
    n = (size_t)in->n_members + 1;
    pks = calloc(n, sizeof *pks);
    f = calloc(1, sizeof *f);
    if (!pks || !f) { err = GZ_TREE_I_NO_MEMORY; goto done; }
    if (!parse_point(ctx, in->host_key, &pks[0])) goto done;
    for (i = 1; i < n; i++)
        if (!parse_point(ctx, in->member_keys[i - 1], &pks[i])) goto done;

    /* signing-round.md section 13, in this order. */
    factory_init_from_pubkeys(f, ctx, pks, n, GZ_TREE_SLICE1_STEP, GZ_TREE_SLICE1_STATES);
    factory_set_level_arity(f, in->levels, in->n_levels);          /* never empty: n_levels >= 1 */
    factory_set_static_near_root(f, in->fixed_levels);
    factory_set_ps_subfactory_arity(f, 1);
    factory_set_l_stock_csv(f, in->lstock_csv);
    f->placement_mode = PLACEMENT_SEQUENTIAL;
    f->use_tree_anchor = 1;
    f->use_hashlock_poison = 0;
    f->fee = NULL;
    f->fee_per_tx = in->fee_per_tx;
    f->cltv_timeout = in->end_height;
    /* The script is a fixed 34-byte field here; factory_set_funding would
     * silently drop a longer one (signing-round.md 12). */
    factory_set_funding(f, in->funding_txid, in->funding_vout, in->funding_amount, in->funding_script, 34);
    if (!factory_build_tree(f)) { err = GZ_TREE_I_REFUSED; goto done; }

    if (f->n_nodes > GZ_TREE_MAX_NODES) { err = GZ_TREE_I_TOO_BIG; goto done; }
    out->n_nodes = (uint16_t)f->n_nodes;
    for (i = 0; i < f->n_nodes; i++) {
        const factory_node_t *nd = &f->nodes[i];
        size_t k;
        if (nd->unsigned_tx.len > GZ_TREE_MAX_TX || nd->parent_vout > 255) { err = GZ_TREE_I_TOO_BIG; goto done; }
        /* Signers: the host, then members in tree order, consecutive. */
        if (nd->n_signers < 2 || nd->signer_indices[0] != 0) { err = GZ_TREE_I_SIGNERS; goto done; }
        for (k = 2; k < nd->n_signers; k++)
            if (nd->signer_indices[k] != nd->signer_indices[k - 1] + 1) { err = GZ_TREE_I_SIGNERS; goto done; }
        out->node[i].kind = nd->type == NODE_STATE ? GZ_NODE_LEAF_STATE
                          : nd->type == NODE_KICKOFF && nd->is_static_only ? GZ_NODE_FIXED
                          : nd->type == NODE_KICKOFF ? GZ_NODE_LEAF_KICKOFF : 0;
        out->node[i].is_ps_leaf = nd->is_ps_leaf ? 1 : 0;
        out->node[i].n_signers = (uint16_t)nd->n_signers;
        out->node[i].parent = (int16_t)nd->parent_index;
        out->node[i].parent_vout = (uint8_t)nd->parent_vout;
        out->node[i].tx_len = (uint16_t)nd->unsigned_tx.len;
        memcpy(out->node[i].tx, nd->unsigned_tx.data, nd->unsigned_tx.len);
    }
    err = GZ_TREE_I_OK;
done:
    if (err != GZ_TREE_I_OK) out->n_nodes = 0;
    if (f) {
        if (f->nodes) factory_free(f);
        free(f);
    }
    free(pks);
    return err;
}

static int import_cb(void *ctx, const gz_tree_build_in_t *in, gz_tree_import_t *out)
{
    return gz_tree_import_build(ctx, in, out) == GZ_TREE_I_OK;
}

void gz_tree_import_member_check(secp256k1_context *ctx, gz_tree_member_in_t *in, const gz_tree_proposal_t *p,
                                 gz_tree_t *t, gz_tree_import_t *scratch, gz_tree_verdict_t *v)
{
    if (in) {
        in->import_build = import_cb;
        in->import_ctx = ctx;
        in->import_out = scratch;
    }
    gz_tree_member_check(in, p, t, v);
}
