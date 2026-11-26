/* tree_massexit: a large factory tree with the test keys, signed, for the
 * mass-exit run on a real node (docs/SLICE-1.5-PLAN.md, P8 and test R6).
 *
 * Used by tools/regtest-mass-exit.py. Like tree_regtest (the T1 tree, 3 to
 * 16 members), but for any member count the imported builder signs in one
 * process (up to GZ_MASSEXIT_MAX members), with the interior levels given on
 * the command line. THE KEYS ARE TEST KEYS (terms.md section 11); never use
 * them for coins.
 *
 *   tree_massexit params N RATE SHAPE
 *       -> "levels L1,..,3 D d funding R nodes K script HEX rules yes|no"
 *   tree_massexit build N RATE SHAPE TXID VOUT AMOUNT END
 *       -> one line per tree transaction, then one per member:
 *          "node I parent P vout V type T signers S seq Q in X fee F anchor A
 *           txid T outs AMT:SCRIPT,.. tx HEX"
 *          "member M leaf I channel AMT script HEX"
 *
 * SHAPE is the interior widths from the root down, comma separated, each 4
 * to 15 (terms.md 4.1), or "ps" for none; the leaf kind is always 3 (one
 * member per pseudo-Spilman leaf), and every level down to the deepest leaf
 * is fixed (D), as the Slice 1 tree is (signing-round.md 4.1).
 *
 * At up to GZ_TREE_MAX_MEMBERS (256) members the tree is built twice, by the
 * rules (core/tree, from terms whose one shape entry is SHAPE) and by the
 * import signed with every key, and refused unless the two agree byte for
 * byte, as tree_regtest does. Above 256 the rules refuse the member count
 * (gz_tree_params: GZ_TREE_P_COUNT; signing-round.md 12), so only the import
 * builds and signs it; the split, D and R(root) still come from the rules'
 * own arithmetic (gz_tree_split, gz_tree_requirement), and "rules no" says
 * that the byte-for-byte check was not possible.
 *
 * The import's factory_init writes past its timed-layer array from 257
 * members on and factory_set_level_arity repairs it (docs/notes/
 * tree-scale-check.md, finding 2): it is called immediately after, as in
 * tree_regtest and tree_shapes.
 *
 * Exit 0 on success, 1 on a refusal, 2 on bad arguments. */
#include "../tree/tree_test.h"
#include "gazpacho/tree_import.h"
#include "superscalar/factory.h"
#include "superscalar/tx_builder.h"

#include <secp256k1_musig.h>

#define GZ_MASSEXIT_MAX 1000
#define CHANNEL_SAT 100000u         /* T1's channel_sat */
#define LSTOCK_CSV 144u

static int hexbyte(const char *s, uint8_t *out)
{
    unsigned v;
    if (sscanf(s, "%2x", &v) != 1) return 0;
    *out = (uint8_t)v;
    return 1;
}

static void print_hex(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

/* "8,4" -> {8, 4, 3}; "ps" -> {3}. */
static size_t parse_shape(const char *s, uint8_t levels[GZ_TREE_MAX_LEVELS])
{
    size_t n = 0;
    if (strcmp(s, "ps") == 0) { levels[0] = GZ_TERMS_LEAF_PS; return 1; }
    while (*s) {
        char *end;
        unsigned long w = strtoul(s, &end, 10);
        if (end == s || w < 4 || w > 15 || n + 1 >= GZ_TREE_MAX_LEVELS || n >= GZ_TERMS_MAX_INTERIOR) return 0;
        levels[n++] = (uint8_t)w;
        s = end;
        if (*s == ',') s++;
        else if (*s) return 0;
    }
    if (n == 0) return 0;
    levels[n++] = GZ_TERMS_LEAF_PS;
    return n;
}

/* BIP 327 KeyAgg of host then members, no sorting, then the BIP 341 tweak
 * with no script tree: the funding output key. tree_import's agg_tweak does
 * the same up to 256 members; this one has no cap. */
static int funding_key(const secp256k1_pubkey *pks, size_t n, uint8_t out[32])
{
    const secp256k1_pubkey **ptrs = malloc(n * sizeof *ptrs);
    secp256k1_xonly_pubkey agg, outx;
    secp256k1_pubkey tweaked;
    uint8_t internal[32], tweak[32];
    int ok = 0;
    if (!ptrs) return 0;
    for (size_t i = 0; i < n; i++) ptrs[i] = &pks[i];
    if (secp256k1_musig_pubkey_agg(test_ctx(), NULL, &agg, NULL, ptrs, n)
        && secp256k1_xonly_pubkey_serialize(test_ctx(), internal, &agg)
        && secp256k1_tagged_sha256(test_ctx(), tweak, (const unsigned char *)"TapTweak", 8, internal, 32)
        && secp256k1_xonly_pubkey_tweak_add(test_ctx(), &tweaked, &agg, tweak)
        && secp256k1_xonly_pubkey_from_pubkey(test_ctx(), &outx, NULL, &tweaked)
        && secp256k1_xonly_pubkey_serialize(test_ctx(), out, &outx))
        ok = 1;
    free((void *)ptrs);
    return ok;
}

/* The rules' parameters from terms whose one shape entry is the given levels
 * (only up to 256 members: gz_tree_params refuses more). */
static int rules_params(uint32_t n, uint64_t rate, const uint8_t *levels, size_t nl, gz_tree_params_t *p)
{
    gz_terms_outer_t t;
    t1_terms(&t);
    t.n_shapes = 1;
    t.target = (uint16_t)n;
    memset(&t.shapes[0], 0, sizeof t.shapes[0]);
    t.shapes[0].max_members = (uint16_t)(n < 4 ? 4 : n);
    t.shapes[0].n_interior = (uint8_t)(nl - 1);
    for (size_t i = 0; i + 1 < nl; i++) t.shapes[0].interior[i] = levels[i];
    t.shapes[0].leaf_kind = GZ_TERMS_LEAF_PS;
    t.tree_feerate = (uint32_t)rate;
    return gz_tree_params(&t, n, p) == GZ_TREE_P_OK;
}

int main(int argc, char **argv)
{
    static gz_tree_t TREE;
    static uint8_t depths[GZ_MASSEXIT_MAX];
    uint8_t levels[GZ_TREE_MAX_LEVELS], out_key[32], D = 0;
    gz_tree_params_t p;
    size_t nl;
    uint64_t R = 0;
    if (argc < 5) { fprintf(stderr, "usage: see the top of tests/regtest/tree_massexit.c\n"); return 2; }
    uint32_t n = (uint32_t)strtoul(argv[2], NULL, 10);
    uint64_t rate = strtoull(argv[3], NULL, 10);
    nl = parse_shape(argv[4], levels);
    if (n < 3 || n > GZ_MASSEXIT_MAX || rate < 100 || rate > 1000000 || nl == 0) { fprintf(stderr, "bad arguments\n"); return 2; }
    if (!gz_tree_split(levels, nl, n, depths)) { fprintf(stderr, "the shape makes a leaf with more than one member\n"); return 1; }
    for (uint32_t i = 0; i < n; i++)
        if (depths[i] > D) D = depths[i];
    if (!gz_tree_requirement(levels, nl, n, CHANNEL_SAT, rate, &R)) { fprintf(stderr, "no R(root)\n"); return 1; }
    int rules = n <= GZ_TREE_MAX_MEMBERS;
    if (rules) {
        if (!rules_params(n, rate, levels, nl, &p)) { fprintf(stderr, "the rules refuse the terms\n"); return 1; }
        if (p.n_levels != nl || memcmp(p.levels, levels, nl) != 0 || p.D != D || p.funding_amount != R) {
            fprintf(stderr, "the terms' parameters differ from the shape's arithmetic\n");
            return 1;
        }
    }

    /* Keys: participant 0 the host, then members 1..n (terms.md 11). */
    size_t np = (size_t)n + 1;
    secp256k1_keypair *kps = calloc(np, sizeof *kps);
    secp256k1_pubkey *pks = calloc(np, sizeof *pks);
    uint8_t (*mkeys)[33] = calloc(n, sizeof *mkeys);
    uint8_t host[33];
    if (!kps || !pks || !mkeys) return 1;
    for (size_t i = 0; i < np; i++) {
        uint8_t sk[32];
        char label[64];
        if (i == 0) snprintf(label, sizeof label, "host");
        else snprintf(label, sizeof label, "member %zu factory", i);
        test_secret(label, sk);
        if (!secp256k1_keypair_create(test_ctx(), &kps[i], sk) || !secp256k1_keypair_pub(test_ctx(), &pks[i], &kps[i]))
            return 1;
        if (i == 0) test_pub(label, host);
        else test_pub(label, mkeys[i - 1]);
    }
    if (!funding_key(pks, np, out_key)) return 1;
    if (rules) {
        gz_tree_crypto_t cr;
        uint8_t internal[32], q[32];
        gz_tree_secp_crypto(test_ctx(), &cr);
        if (!cr.agg_tweak(cr.ctx, host, (const uint8_t(*)[33])mkeys, n, NULL, internal, q) || memcmp(q, out_key, 32) != 0) {
            fprintf(stderr, "the funding key differs from the rules' provider\n");
            return 1;
        }
    }

    if (strcmp(argv[1], "params") == 0) {
        gz_tree_params_t q;
        memset(&q, 0, sizeof q);
        memcpy(q.levels, levels, nl);
        q.n_levels = nl;
        q.n_members = n;
        printf("levels ");
        for (size_t i = 0; i < nl; i++) printf("%s%u", i ? "," : "", (unsigned)levels[i]);
        printf(" D %u funding %llu nodes %u script 5120", (unsigned)D, (unsigned long long)R, gz_tree_node_count(&q));
        print_hex(out_key, 32);
        printf(" rules %s\n", rules ? "yes" : "no");
        return 0;
    }
    if (strcmp(argv[1], "build") != 0 || argc != 9 || strlen(argv[5]) != 64) { fprintf(stderr, "bad arguments\n"); return 2; }

    gz_tree_build_in_t in;
    memset(&in, 0, sizeof in);
    for (int i = 0; i < 32; i++)                       /* display order -> internal order */
        if (!hexbyte(argv[5] + 2 * (31 - i), &in.funding_txid[i])) return 2;
    in.funding_vout = (uint32_t)strtoul(argv[6], NULL, 10);
    in.funding_amount = strtoull(argv[7], NULL, 10);
    in.end_height = (uint32_t)strtoul(argv[8], NULL, 10);
    in.levels = levels;
    in.n_levels = nl;
    in.fixed_levels = D;
    in.n_members = n;
    in.host_key = host;
    in.member_keys = (const uint8_t(*)[33])mkeys;
    in.tree_feerate = rate;
    in.lstock_csv = LSTOCK_CSV;
    in.funding_script[0] = 0x51; in.funding_script[1] = 0x20;
    memcpy(in.funding_script + 2, out_key, 32);
    if (in.funding_amount != R) { fprintf(stderr, "the amount is not R(root) = %llu\n", (unsigned long long)R); return 1; }
    if (rules) {
        gz_tree_crypto_t cr;
        gz_tree_secp_crypto(test_ctx(), &cr);
        if (gz_tree_build(&in, &cr, &TREE) != GZ_TREE_B_OK) { fprintf(stderr, "the rules refuse the tree\n"); return 1; }
    }

    /* The import, with every secret key, in signing-round.md section 13's order. */
    factory_t *f = calloc(1, sizeof *f);
    if (!f || !factory_init(f, test_ctx(), kps, np, GZ_TREE_SLICE1_STEP, GZ_TREE_SLICE1_STATES)) return 1;
    int ok = factory_set_level_arity(f, in.levels, in.n_levels);
    factory_set_static_near_root(f, in.fixed_levels);
    factory_set_ps_subfactory_arity(f, 1);
    factory_set_l_stock_csv(f, in.lstock_csv);
    ok = ok && factory_set_placement_mode(f, PLACEMENT_SEQUENTIAL);
    f->use_tree_anchor = 1;
    f->use_hashlock_poison = 0;
    f->tree_fee_rate = rate;
    f->build_quiet = 1;
    f->cltv_timeout = in.end_height;
    ok = ok && factory_set_funding(f, in.funding_txid, in.funding_vout, in.funding_amount, in.funding_script, 34)
            && factory_build_tree(f);
    if (!ok) { fprintf(stderr, "the import refuses the tree\n"); return 1; }
    {
        char why[256] = "";
        if (!factory_check_tree_fees(f, why, sizeof why)) { fprintf(stderr, "the import's fee audit refuses: %s\n", why); return 1; }
    }
    if (!factory_sign_all(f) || !factory_verify_all(f)) { fprintf(stderr, "the import does not sign or verify\n"); return 1; }
    if (rules && f->n_nodes != TREE.n_nodes) { fprintf(stderr, "the import has %zu nodes, the rules %u\n", f->n_nodes, TREE.n_nodes); return 1; }
    if ((size_t)f->n_leaf_nodes != n) { fprintf(stderr, "the import has %d leaves for %u members\n", f->n_leaf_nodes, n); return 1; }

    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *nd = &f->nodes[i];
        uint8_t disp[32];
        size_t a = nd->n_outputs - 1;
        if (rules) {
            const gz_tree_node_t *m = &TREE.node[i];
            if (nd->unsigned_tx.len != m->tx_len || memcmp(nd->unsigned_tx.data, m->tx, m->tx_len) != 0) {
                fprintf(stderr, "node %zu: the rules and the import differ\n", i);
                return 1;
            }
        }
        if (nd->n_outputs < 2 || nd->outputs[a].script_pubkey_len != 4
            || memcmp(nd->outputs[a].script_pubkey, "\x51\x02\x4e\x73", 4) != 0 || nd->outputs[a].amount_sats != GZ_TREE_ANCHOR_SAT) {
            fprintf(stderr, "node %zu: the last output is not the 240-sat P2A anchor\n", i);
            return 1;
        }
        for (int j = 0; j < 32; j++) disp[j] = nd->txid[31 - j];
        printf("node %zu parent %d vout %u type %d signers %zu seq %u in %llu fee %llu anchor %zu txid ", i, nd->parent_index,
               nd->parent_vout, (int)nd->type, nd->n_signers, nd->nsequence, (unsigned long long)nd->input_amount,
               (unsigned long long)nd->fee_sats, a);
        print_hex(disp, 32);
        printf(" outs ");
        for (size_t k = 0; k < nd->n_outputs; k++) {
            printf("%s%llu:", k ? "," : "", (unsigned long long)nd->outputs[k].amount_sats);
            print_hex(nd->outputs[k].script_pubkey, nd->outputs[k].script_pubkey_len);
        }
        printf(" tx ");
        print_hex(nd->signed_tx.data, nd->signed_tx.len);
        printf("\n");
    }
    /* Member i's leaf transaction: signed by the host and that member alone,
     * its output 0 the member's channel (at least channel_sat). */
    for (uint32_t i = 0; i < n; i++) {
        size_t leaf = f->leaf_node_indices[i];
        const factory_node_t *nd = &f->nodes[leaf];
        if (leaf >= f->n_nodes || nd->n_signers != 2 || nd->signer_indices[0] != 0 || nd->signer_indices[1] != i + 1) {
            fprintf(stderr, "member %u: leaf %zu is not signed by the host and that member\n", i + 1, leaf);
            return 1;
        }
        if (rules && leaf != TREE.leaf_state[i]) { fprintf(stderr, "member %u: the rules' leaf differs\n", i + 1); return 1; }
        if (nd->outputs[0].amount_sats < CHANNEL_SAT) { fprintf(stderr, "member %u: channel below channel_sat\n", i + 1); return 1; }
        printf("member %u leaf %zu channel %llu script ", i + 1, leaf, (unsigned long long)nd->outputs[0].amount_sats);
        print_hex(nd->outputs[0].script_pubkey, nd->outputs[0].script_pubkey_len);
        printf("\n");
    }
    factory_free(f);
    free(f);
    free(kps);
    free(pks);
    free(mkeys);
    return check_done();
}
