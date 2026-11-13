/* The tree T1 builds, three ways, byte for byte:
 *   1. gz_tree_build: the rules written out (core/tree/model.c);
 *   2. gz_tree_import_build: the imported builder through the glue;
 *   3. the imported builder called directly here, in signing-round.md
 *      section 13's order, without the glue (an independent caller).
 * Txids for 3, 4, 8 and 16 members are pinned in
 * tests/reference/tree-from-terms-txids.txt. The model's BIP 341 digests are
 * checked against signatures the import itself makes (factory_sign_all), so
 * the digest the signing engine will sign is the one the import's
 * transactions need. Then terms.md test 19, and the import's own refusals
 * (dust, its minimum funding) at their boundaries, in both builders.
 *
 * usage: test_tree_build REFERENCE-FILE [--print] */
#include "tree_test.h"
#include "gazpacho/tree_import.h"
#include "superscalar/factory.h"

#define FUND_LABEL "gazpacho test funding"
#define TIP 290000u
#define END (TIP + 144 + 36)

static gz_tree_crypto_t CR;
static uint8_t HOST[33];
static uint8_t MEMBERS[GZ_TREE_MAX_MEMBERS][33];

static void keys(uint32_t n)
{
    uint32_t i;
    char label[64];
    test_pub("host", HOST);
    for (i = 0; i < n; i++) {
        snprintf(label, sizeof label, "member %u factory", i + 1);
        test_pub(label, MEMBERS[i]);
    }
}

/* T1's inputs for n members: levels, D, fee and funding from terms.md 4.2. */
static void t1_inputs(uint32_t n, gz_tree_params_t *p, gz_tree_build_in_t *in)
{
    gz_terms_outer_t t;
    uint8_t internal[32], out_key[32];
    t1_terms(&t);
    keys(n);
    if (gz_tree_params(&t, n, p) != GZ_TREE_P_OK) abort();
    memset(in, 0, sizeof *in);
    in->levels = p->levels;
    in->n_levels = p->n_levels;
    in->fixed_levels = p->D;
    in->n_members = n;
    in->host_key = HOST;
    in->member_keys = (const uint8_t(*)[33])MEMBERS;
    in->end_height = END;
    in->fee_per_tx = p->fee_per_tx;
    in->lstock_csv = 144;
    tr_sha256((const uint8_t *)FUND_LABEL, strlen(FUND_LABEL), in->funding_txid);
    in->funding_vout = 0;
    in->funding_amount = p->funding_amount;
    if (!CR.agg_tweak(CR.ctx, HOST, (const uint8_t(*)[33])MEMBERS, n, NULL, internal, out_key)) abort();
    in->funding_script[0] = 0x51; in->funding_script[1] = 0x20;
    memcpy(in->funding_script + 2, out_key, 32);
}

/* 3: the import, called here directly (section 13's order). With
 * `sign` = 1 it is built with every secret key and signed by the import. */
static factory_t *raw_import(const gz_tree_build_in_t *in, int sign)
{
    size_t n = in->n_members + 1, i;
    secp256k1_pubkey pks[GZ_TREE_MAX_MEMBERS + 1];
    secp256k1_keypair kps[GZ_TREE_MAX_MEMBERS + 1];
    factory_t *f = calloc(1, sizeof *f);
    if (!f) abort();
    for (i = 0; i < n; i++) {
        uint8_t sk[32];
        char label[64];
        if (i == 0) snprintf(label, sizeof label, "host");
        else snprintf(label, sizeof label, "member %zu factory", i);
        test_secret(label, sk);
        if (!secp256k1_keypair_create(test_ctx(), &kps[i], sk)) abort();
        if (!secp256k1_keypair_pub(test_ctx(), &pks[i], &kps[i])) abort();
    }
    if (sign) {
        if (!factory_init(f, test_ctx(), kps, n, 144, 4)) abort();
    } else {
        factory_init_from_pubkeys(f, test_ctx(), pks, n, 144, 4);
    }
    factory_set_level_arity(f, in->levels, in->n_levels);
    factory_set_static_near_root(f, in->fixed_levels);
    factory_set_ps_subfactory_arity(f, 1);
    factory_set_l_stock_csv(f, in->lstock_csv);
    f->placement_mode = PLACEMENT_SEQUENTIAL;
    f->use_tree_anchor = 1;
    f->use_hashlock_poison = 0;
    f->fee_per_tx = in->fee_per_tx;
    f->cltv_timeout = in->end_height;
    factory_set_funding(f, in->funding_txid, in->funding_vout, in->funding_amount, in->funding_script, 34);
    if (!factory_build_tree(f)) { factory_free(f); free(f); return NULL; }
    return f;
}

static void free_raw(factory_t *f)
{
    if (f) { factory_free(f); free(f); }
}

static int same_as_import(const gz_tree_t *t, const gz_tree_import_t *im)
{
    uint32_t i;
    if (im->n_nodes != t->n_nodes) return 0;
    for (i = 0; i < t->n_nodes; i++)
        if (im->node[i].tx_len != t->node[i].tx_len || memcmp(im->node[i].tx, t->node[i].tx, t->node[i].tx_len) != 0
            || im->node[i].parent != t->node[i].parent || im->node[i].kind != t->node[i].kind
            || im->node[i].n_signers != 1 + t->node[i].count)
            return 0;
    return 1;
}

static int same_as_raw(const gz_tree_t *t, const factory_t *f)
{
    uint32_t i;
    if (!f || f->n_nodes != t->n_nodes) return 0;
    for (i = 0; i < t->n_nodes; i++)
        if (memcmp(f->nodes[i].txid, t->node[i].txid, 32) != 0 || f->nodes[i].is_ps_leaf != (t->node[i].kind == GZ_NODE_LEAF_STATE)
            || f->nodes[i].input_amount != t->node[i].spent_amount
            || memcmp(f->nodes[i].spending_spk, t->node[i].spent_script, 34) != 0)
            return 0;
    return 1;
}

/* The lines of the reference file for n members. */
static size_t lines_for(const gz_tree_t *t, uint32_t n, char out[][128], size_t cap)
{
    size_t k = 0;
    uint32_t i;
    for (i = 0; i < t->n_nodes && k < cap; i++) {
        uint8_t disp[32];
        char hx[65];
        int j;
        for (j = 0; j < 32; j++) disp[j] = t->node[i].txid[31 - j];
        tohex(disp, 32, hx);
        snprintf(out[k++], 128, "n %u node %u kind %u depth %u members %u+%u txid %s", n, i, t->node[i].kind,
                 t->node[i].depth, t->node[i].first, t->node[i].count, hx);
    }
    return k;
}

static gz_tree_t TREE, TREE2;
static gz_tree_import_t IMPORT;
static char REF[2000][128];
static size_t NREF;

static void read_reference(const char *path)
{
    FILE *fp = fopen(path, "r");
    char buf[256];
    NREF = 0;
    if (!fp) { printf("cannot read %s\n", path); CHECK(0); return; }
    while (fgets(buf, sizeof buf, fp) && NREF < 2000) {
        size_t l = strlen(buf);
        while (l && (buf[l - 1] == '\n' || buf[l - 1] == '\r')) buf[--l] = 0;
        if (strncmp(buf, "n ", 2) == 0) snprintf(REF[NREF++], 128, "%.127s", buf);
    }
    fclose(fp);
}

static void pinned(int print)
{
    static const uint32_t SIZES[4] = {3, 4, 8, 16};
    static char got[200][128];
    size_t used = 0, i, k;
    gz_tree_params_t p;
    gz_tree_build_in_t in;
    for (i = 0; i < 4; i++) {
        uint32_t n = SIZES[i];
        factory_t *f;
        t1_inputs(n, &p, &in);
        CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_OK);
        CHECK(gz_tree_import_build(test_ctx(), &in, &IMPORT) == GZ_TREE_I_OK);
        CHECK(same_as_import(&TREE, &IMPORT));
        f = raw_import(&in, 0);
        CHECK(same_as_raw(&TREE, f));
        free_raw(f);
        k = lines_for(&TREE, n, got, 200);
        for (size_t j = 0; j < k; j++) {
            if (print) printf("%s\n", got[j]);
            CHECK(used < NREF && strcmp(got[j], REF[used]) == 0);
            if (used < NREF && strcmp(got[j], REF[used]) != 0) printf("  reference %s\n  built     %s\n", REF[used], got[j]);
            used++;
        }
    }
    CHECK(used == NREF);
}

/* Model and import agree for every n of T1 (terms.md test 17, signing-round
 * test 12), every leaf a one-member pseudo-Spilman leaf, every interior node
 * fixed, every channel at least channel_sat. */
static void every_size(void)
{
    uint32_t n, i, leaves;
    gz_tree_params_t p;
    gz_tree_build_in_t in;
    for (n = 3; n <= 16; n++) {
        t1_inputs(n, &p, &in);
        CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_OK);
        CHECK(gz_tree_import_build(test_ctx(), &in, &IMPORT) == GZ_TREE_I_OK);
        CHECK(same_as_import(&TREE, &IMPORT));
        leaves = 0;
        for (i = 0; i < TREE.n_nodes; i++) {
            const gz_tree_node_t *nd = &TREE.node[i];
            if (nd->kind == GZ_NODE_LEAF_STATE) {
                leaves++;
                CHECK(nd->count == 1 && IMPORT.node[i].is_ps_leaf == 1 && IMPORT.node[i].n_signers == 2);
                CHECK(nd->out_amount[0] >= 100000);
                CHECK(nd->n_out == 3 && nd->out_kind[2] == GZ_OUT_ANCHOR && nd->out_amount[2] == 240);
            } else {
                CHECK(IMPORT.node[i].is_ps_leaf == 0);
                if (nd->kind == GZ_NODE_FIXED) CHECK(nd->nsequence == 0xfffffffeu && nd->depth < p.D);
                else CHECK(nd->nsequence == 0xffffffffu);
            }
            /* Every transaction pays exactly fee_per_tx. */
            {
                uint64_t out = 0;
                size_t o;
                for (o = 0; o < nd->n_out; o++) out += nd->out_amount[o];
                CHECK(nd->spent_amount - out == p.fee_per_tx);
            }
        }
        CHECK(leaves == n);
        /* The largest transaction's signed size is V. */
        {
            uint32_t vmax = 0;
            for (i = 0; i < TREE.n_nodes; i++) {
                uint32_t v = (4 * TREE.node[i].tx_len + 2 + 66 + 3) / 4;
                if (v > vmax) vmax = v;
            }
            CHECK(vmax == p.V);
        }
    }
    /* Test 19: with funding_amount - 1 at 4 members some channel is below channel_sat. */
    t1_inputs(4, &p, &in);
    in.funding_amount -= 1;
    CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_OK);
    {
        uint64_t lo = UINT64_MAX;
        for (i = 0; i < 4; i++) if (TREE.node[TREE.leaf_state[i]].out_amount[0] < lo) lo = TREE.node[TREE.leaf_state[i]].out_amount[0];
        CHECK(lo == 99999);
    }
    /* Three members: member 1's channel is about twice channel_sat (terms.md 4.2). */
    t1_inputs(3, &p, &in);
    CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_OK);
    CHECK(TREE.node[TREE.leaf_state[0]].out_amount[0] == 200385);
    CHECK(TREE.node[TREE.leaf_state[1]].out_amount[0] == 100000);
    CHECK(TREE.node[TREE.leaf_state[2]].out_amount[0] == 100000);
}

/* The digest each node is signed under: the import signs every node
 * (factory_sign_all) and its signature verifies under the model's digest
 * and the model's output key. */
static void sighashes(void)
{
    static const uint32_t SIZES[3] = {3, 5, 16};
    size_t s;
    for (s = 0; s < 3; s++) {
        gz_tree_params_t p;
        gz_tree_build_in_t in;
        factory_t *f;
        uint32_t i;
        t1_inputs(SIZES[s], &p, &in);
        CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_OK);
        f = raw_import(&in, 1);
        CHECK(f != NULL);
        if (!f) continue;
        CHECK(factory_sign_all(f));
        for (i = 0; i < TREE.n_nodes; i++) {
            const tx_buf_t *st = &f->nodes[i].signed_tx;
            secp256k1_xonly_pubkey x;
            CHECK(st->len > 68);
            CHECK(secp256k1_xonly_pubkey_parse(test_ctx(), &x, TREE.node[i].spent_script + 2));
            CHECK(secp256k1_schnorrsig_verify(test_ctx(), st->data + st->len - 4 - 64, TREE.node[i].sighash, 32, &x));
            /* and not under a neighbour's digest */
            if (i) CHECK(!secp256k1_schnorrsig_verify(test_ctx(), st->data + st->len - 4 - 64, TREE.node[i - 1].sighash, 32, &x));
        }
        free_raw(f);
    }
}

/* The rules and the import build the same bytes for these inputs. */
static int agree(const gz_tree_build_in_t *in)
{
    gz_tree_b_err_t b = gz_tree_build(in, &CR, &TREE);
    gz_tree_i_err_t i = gz_tree_import_build(test_ctx(), in, &IMPORT);
    if (b != GZ_TREE_B_OK || i != GZ_TREE_I_OK) {
        printf("  build %d, import %d\n", (int)b, (int)i);
        return 0;
    }
    return same_as_import(&TREE, &IMPORT);
}

/* Inputs that T1 at R(root) never exercises, where a wrong rule would still
 * build: remainders, small and zero end heights (the import's saturating
 * timeouts and small script numbers), one and two members, the
 * spare-liquidity delay 0 (the import's default) and around 16. */
static void corners(void)
{
    gz_tree_params_t p;
    gz_tree_build_in_t in;
    uint32_t n, extra;
    static const uint32_t ENDS[6] = {0, 1, 7, 12, 21, 31};
    static const uint32_t CSVS[6] = {0, 1, 16, 17, 127, 65535};
    size_t k;
    for (n = 3; n <= 16; n++)
        for (extra = 1; extra <= 3; extra++) {
            t1_inputs(n, &p, &in);
            in.funding_amount += extra;
            CHECK(agree(&in));
        }
    for (k = 0; k < 6; k++) {
        t1_inputs(4, &p, &in);
        in.end_height = ENDS[k];
        CHECK(agree(&in));
        t1_inputs(5, &p, &in);
        in.end_height = ENDS[k];
        CHECK(agree(&in));
        t1_inputs(3, &p, &in);
        in.lstock_csv = CSVS[k];
        CHECK(agree(&in));
    }
    for (n = 1; n <= 2; n++) {
        static const uint8_t L3[1] = {3};
        uint8_t internal[32], q[32];
        keys(n);
        memset(&in, 0, sizeof in);
        in.levels = L3; in.n_levels = 1; in.fixed_levels = (uint8_t)(n - 1); in.n_members = n;
        in.host_key = HOST; in.member_keys = (const uint8_t(*)[33])MEMBERS;
        in.end_height = END; in.fee_per_tx = 17; in.lstock_csv = 144;
        CHECK(gz_tree_requirement(L3, 1, n, 100000, 17, &in.funding_amount));
        tr_sha256((const uint8_t *)FUND_LABEL, strlen(FUND_LABEL), in.funding_txid);
        CHECK(CR.agg_tweak(CR.ctx, HOST, (const uint8_t(*)[33])MEMBERS, n, NULL, internal, q));
        in.funding_script[0] = 0x51; in.funding_script[1] = 0x20; memcpy(in.funding_script + 2, q, 32);
        CHECK(agree(&in));
        CHECK(TREE.n_nodes == (n == 1 ? 2 : 5));
    }
}

/* The import's own refusals, at their boundaries, in both builders. */
static void refusals(void)
{
    gz_tree_params_t p;
    gz_tree_build_in_t in;
    static const uint8_t L3[1] = {3};
    uint64_t R;
    factory_t *f;
    /* Dust: channel_sat 546 at 4 members; R builds, R - 1 leaves a 545 channel. */
    t1_inputs(4, &p, &in);
    CHECK(gz_tree_requirement(L3, 1, 4, 546, 17, &R));
    in.funding_amount = R;
    CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_OK);
    CHECK(gz_tree_import_build(test_ctx(), &in, &IMPORT) == GZ_TREE_I_OK && same_as_import(&TREE, &IMPORT));
    in.funding_amount = R - 1;
    CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_DUST);
    CHECK(gz_tree_import_build(test_ctx(), &in, &IMPORT) == GZ_TREE_I_REFUSED);
    /* The import's minimum funding: fee 880 builds at R; fee 881 is refused
     * although R(881) pays every channel 546. */
    in.fee_per_tx = 880;
    CHECK(gz_tree_requirement(L3, 1, 4, 546, 880, &R));
    in.funding_amount = R;
    CHECK(R == 16688);
    in.funding_amount = R - 1;                         /* the import's minimum - 1 (review A, M43) */
    CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_IMPORT_MINIMUM);
    CHECK(gz_tree_import_build(test_ctx(), &in, &IMPORT) == GZ_TREE_I_REFUSED);
    in.funding_amount = R;
    CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_OK);
    CHECK(gz_tree_import_build(test_ctx(), &in, &IMPORT) == GZ_TREE_I_OK && same_as_import(&TREE, &IMPORT));
    in.fee_per_tx = 881;
    CHECK(gz_tree_requirement(L3, 1, 4, 546, 881, &R));
    in.funding_amount = R;
    CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_IMPORT_MINIMUM);
    CHECK(gz_tree_import_build(test_ctx(), &in, &IMPORT) == GZ_TREE_I_REFUSED);
    f = raw_import(&in, 0);
    CHECK(f == NULL);
    free_raw(f);
    /* fixed_levels other than D: the model refuses; the import builds a
     * different tree (state nodes appear) or the same bytes (above D). */
    t1_inputs(4, &p, &in);
    in.fixed_levels = (uint8_t)(p.D - 1);
    CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_FIXED_LEVELS);
    CHECK(gz_tree_import_build(test_ctx(), &in, &IMPORT) == GZ_TREE_I_OK);
    in.fixed_levels = p.D;
    CHECK(gz_tree_build(&in, &CR, &TREE2) == GZ_TREE_B_OK);
    CHECK(!same_as_import(&TREE2, &IMPORT));
    in.fixed_levels = (uint8_t)(p.D + 1);
    CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_FIXED_LEVELS);
    CHECK(gz_tree_import_build(test_ctx(), &in, &IMPORT) == GZ_TREE_I_OK);
    CHECK(same_as_import(&TREE2, &IMPORT));
    /* A multi-member leaf: levels [4] at 4 members. */
    {
        static const uint8_t L4[1] = {4};
        in.levels = L4; in.n_levels = 1; in.fixed_levels = 0;
        CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_SPLIT);
        CHECK(gz_tree_import_build(test_ctx(), &in, &IMPORT) == GZ_TREE_I_OK);   /* the import builds one N-way leaf */
        CHECK(IMPORT.node[1].is_ps_leaf == 0 && IMPORT.node[1].n_signers == 5);
    }
    /* Layer step and states change no byte under fixed levels (signing-round 4.1). */
    t1_inputs(8, &p, &in);
    CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_OK);
    {
        factory_t *g = raw_import(&in, 0);
        CHECK(same_as_raw(&TREE, g));
        free_raw(g);
    }
    /* A larger tree: 256 members, binary, the bound of signing-round.md 12. */
    {
        static uint8_t many[GZ_TREE_MAX_MEMBERS][33];
        uint32_t i;
        uint8_t depths[GZ_TREE_MAX_MEMBERS], D = 0, internal[32], ok[32];
        char label[64];
        for (i = 0; i < GZ_TREE_MAX_MEMBERS; i++) { snprintf(label, sizeof label, "member %u factory", i + 1); test_pub(label, many[i]); }
        CHECK(gz_tree_split(L3, 1, 256, depths));
        for (i = 0; i < 256; i++) if (depths[i] > D) D = depths[i];
        CHECK(D == 8);
        in.levels = L3; in.n_levels = 1; in.fixed_levels = D; in.n_members = 256; in.member_keys = (const uint8_t(*)[33])many;
        CHECK(gz_tree_requirement(L3, 1, 256, 1000, 30, &in.funding_amount));
        in.fee_per_tx = 30;
        CHECK(CR.agg_tweak(CR.ctx, HOST, (const uint8_t(*)[33])many, 256, NULL, internal, ok));
        memcpy(in.funding_script + 2, ok, 32);
        CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_OK);
        CHECK(TREE.n_nodes == 255 + 512);
        CHECK(gz_tree_import_build(test_ctx(), &in, &IMPORT) == GZ_TREE_I_OK && same_as_import(&TREE, &IMPORT));
        in.n_members = 257;
        CHECK(gz_tree_build(&in, &CR, &TREE) == GZ_TREE_B_ARGUMENT);
    }
}

int main(int argc, char **argv)
{
    int print = argc > 2 && strcmp(argv[2], "--print") == 0;
    gz_tree_secp_crypto(test_ctx(), &CR);
    if (argc > 1) read_reference(argv[1]);
    pinned(print);
    every_size();
    sighashes();
    corners();
    refusals();
    return check_done();
}
