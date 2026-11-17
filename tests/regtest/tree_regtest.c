/* tree_regtest: the T1 tree with the test keys, signed, for a real-node run.
 *
 * Used by tools/regtest-tree.py (spec/exit.md section 6.8): it prints what a
 * regtest Bitcoin Core node is then asked to accept, one tree level per block.
 * THE KEYS ARE TEST KEYS (terms.md section 11); never use them for coins.
 *
 *   tree_regtest params N RATE
 *       -> "levels L1,L2,.. D d funding R script HEX"  (T1's shape for N
 *          members at RATE sat/kvB; HEX is the funding output's script)
 *   tree_regtest build N RATE TXID VOUT AMOUNT END
 *       TXID in display order. Builds the tree twice (the rules, core/tree;
 *       the import, signed with every key by factory_sign_all), refuses
 *       unless the two agree byte for byte and the import's own fee audit
 *       passes, then prints one line per node:
 *         "node I parent P vout V kind K depth D cltv C seq S anchor A txid T tx HEX"
 *       (A: the anchor's output index; HEX: the signed transaction), and
 *       for member 1's leaf one line
 *         "timeout node I locktime L tx HEX"
 *       the host's signed timeout spend of that leaf's channel output, which
 *       a node must refuse before height L and accept from it.
 * Exit 0 on success, 1 on a refusal, 2 on bad arguments. */
#include "../tree/tree_test.h"
#include "gazpacho/tree_import.h"
#include "superscalar/factory.h"
#include "superscalar/tx_builder.h"

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

static int params_for(uint32_t n, uint64_t rate, gz_tree_params_t *p)
{
    gz_terms_outer_t t;
    t1_terms(&t);
    t.n_shapes = 2;
    t.target = 16;
    t.tree_feerate = (uint32_t)rate;
    return gz_tree_params(&t, n, p) == GZ_TREE_P_OK;
}

static void keys_of(uint32_t n, uint8_t host[33], uint8_t members[][33])
{
    char label[64];
    test_pub("host", host);
    for (uint32_t i = 0; i < n; i++) {
        snprintf(label, sizeof label, "member %u factory", i + 1);
        test_pub(label, members[i]);
    }
}

int main(int argc, char **argv)
{
    static uint8_t HOST[33], MEMBERS[GZ_TREE_MAX_MEMBERS][33];
    static gz_tree_t TREE;
    gz_tree_crypto_t cr;
    gz_tree_params_t p;
    gz_tree_build_in_t in;
    uint8_t internal[32], out_key[32];
    if (argc < 4) { fprintf(stderr, "usage: see the top of tests/regtest/tree_regtest.c\n"); return 2; }
    uint32_t n = (uint32_t)strtoul(argv[2], NULL, 10);
    uint64_t rate = strtoull(argv[3], NULL, 10);
    if (n < 3 || n > 16 || rate < 1 || rate > 1000000 || !params_for(n, rate, &p)) { fprintf(stderr, "no T1 tree\n"); return 2; }
    gz_tree_secp_crypto(test_ctx(), &cr);
    keys_of(n, HOST, MEMBERS);
    if (!cr.agg_tweak(cr.ctx, HOST, (const uint8_t(*)[33])MEMBERS, n, NULL, internal, out_key)) return 1;

    if (strcmp(argv[1], "params") == 0) {
        printf("levels ");
        for (size_t i = 0; i < p.n_levels; i++) printf("%s%u", i ? "," : "", (unsigned)p.levels[i]);
        printf(" D %u funding %llu script 5120", (unsigned)p.D, (unsigned long long)p.funding_amount);
        print_hex(out_key, 32);
        printf("\n");
        return 0;
    }
    if (strcmp(argv[1], "build") != 0 || argc != 8 || strlen(argv[4]) != 64) { fprintf(stderr, "bad arguments\n"); return 2; }

    memset(&in, 0, sizeof in);
    for (int i = 0; i < 32; i++)                       /* display order -> internal order */
        if (!hexbyte(argv[4] + 2 * (31 - i), &in.funding_txid[i])) return 2;
    in.funding_vout = (uint32_t)strtoul(argv[5], NULL, 10);
    in.funding_amount = strtoull(argv[6], NULL, 10);
    in.end_height = (uint32_t)strtoul(argv[7], NULL, 10);
    in.levels = p.levels;
    in.n_levels = p.n_levels;
    in.fixed_levels = p.D;
    in.n_members = n;
    in.host_key = HOST;
    in.member_keys = (const uint8_t(*)[33])MEMBERS;
    in.tree_feerate = rate;
    in.lstock_csv = 144;
    in.funding_script[0] = 0x51; in.funding_script[1] = 0x20;
    memcpy(in.funding_script + 2, out_key, 32);
    if (in.funding_amount != p.funding_amount) { fprintf(stderr, "the amount is not R(root) = %llu\n", (unsigned long long)p.funding_amount); return 1; }
    if (gz_tree_build(&in, &cr, &TREE) != GZ_TREE_B_OK) { fprintf(stderr, "the rules refuse the tree\n"); return 1; }

    /* The import, with every secret key, in signing-round.md section 13's order. */
    size_t np = (size_t)n + 1;
    secp256k1_keypair kps[GZ_TREE_MAX_MEMBERS + 1];
    for (size_t i = 0; i < np; i++) {
        uint8_t sk[32];
        char label[64];
        if (i == 0) snprintf(label, sizeof label, "host");
        else snprintf(label, sizeof label, "member %zu factory", i);
        test_secret(label, sk);
        if (!secp256k1_keypair_create(test_ctx(), &kps[i], sk)) return 1;
    }
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
            && factory_build_tree(f) && factory_check_tree_fees(f, NULL, 0) && factory_sign_all(f) && factory_verify_all(f);
    if (!ok || f->n_nodes != TREE.n_nodes) { fprintf(stderr, "the import refuses or differs\n"); return 1; }
    for (uint32_t i = 0; i < TREE.n_nodes; i++) {
        const factory_node_t *nd = &f->nodes[i];
        const gz_tree_node_t *m = &TREE.node[i];
        uint8_t disp[32];
        if (nd->unsigned_tx.len != m->tx_len || memcmp(nd->unsigned_tx.data, m->tx, m->tx_len) != 0) {
            fprintf(stderr, "node %u: the rules and the import differ\n", i);
            return 1;
        }
        for (int j = 0; j < 32; j++) disp[j] = m->txid[31 - j];
        printf("node %u parent %d vout %u kind %u depth %u cltv %u seq %u anchor %u txid ", i, m->parent, m->parent_vout,
               m->kind, m->depth, m->cltv, m->nsequence, (unsigned)m->n_out - 1);
        print_hex(disp, 32);
        printf(" tx ");
        print_hex(nd->signed_tx.data, nd->signed_tx.len);
        printf("\n");
    }
    /* The host's timeout spend of member 1's channel output (the leaf
     * transaction's output 0, whose script is the leaf's own, so its height is
     * H_leaf = E - 10 d). Paid to the funding script, 1,000 sat of fee. */
    {
        uint32_t leaf = TREE.leaf_state[0];
        const factory_node_t *nd = &f->nodes[leaf];
        tx_buf_t out;
        tx_buf_init(&out, 256);
        if (!factory_build_timeout_spend_tx(f, nd->txid, 0, nd->outputs[0].amount_sats, (int)leaf, &kps[0],
                                            in.funding_script, 34, 1000, &out)) {
            fprintf(stderr, "no timeout spend\n");
            return 1;
        }
        printf("timeout node %u locktime %u tx ", leaf, nd->cltv_timeout);
        print_hex(out.data, out.len);
        printf("\n");
        tx_buf_free(&out);
    }
    factory_free(f);
    free(f);
    return check_done();
}

