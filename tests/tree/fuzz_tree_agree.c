/* Fuzz target (review B of the re-import, M2): the three ways a member meets
 * a tree, on the same fuzzed terms, must agree.
 *
 *   gz_tree_build          the tree from the rules (core/tree/model.c)
 *   gz_tree_import_build   the tree from the imported SuperScalar builder
 *   gz_tree_member_check   the member's checks, which build both again
 *
 * The input picks the member count (3 to 16), the tree fee rate (1 to
 * 1,000,000 sat/kvB), channel_sat, a shape table, the member's position, the
 * end height and an offset of the funding amount from R(root). Terms that a
 * member would refuse on receipt are skipped. Properties, each an abort:
 *   - the two builders both build, with the same bytes, or both refuse;
 *   - with the funding amount R(root), every check passes, and the member's
 *     check never reports that the import differs or failed (C1);
 *   - with another funding amount the member refuses (C8 funding rule).
 * THE KEYS ARE TEST KEYS. */
#include "tree_test.h"
#include "gazpacho/tree_import.h"
#include "../../core/tree/internal.h"

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t len);

#define TIP 290000u
static const gz_terms_policy_t SLICE1 = {1};

static gz_tree_crypto_t CR;
static gz_tree_t TREE, TREE2;
static gz_tree_import_t IMPORT;
static gz_tree_participant_t PARTS[17];
static uint8_t KEYS[16][33];

static void bind_one(const uint8_t od[32], uint32_t i, const char *ff, const char *cf)
{
    uint8_t h[32];
    char a[64], b[64];
    tr_sha256_t t;
    tr_tagged_init(&t, "gazpacho/bind");
    tr_sha256_write(&t, od, 32);
    tr_sha256_write(&t, PARTS[i].factory_key, 33);
    tr_sha256_write(&t, PARTS[i].contribution_key, 33);
    tr_sha256_done(&t, h);
    snprintf(a, sizeof a, ff, i);
    snprintf(b, sizeof b, cf, i);
    test_sign(a, h, PARTS[i].bind_by_factory);
    test_sign(b, h, PARTS[i].bind_by_contribution);
}

static int same_trees(void)
{
    uint32_t i;
    if (IMPORT.n_nodes != TREE.n_nodes) return 0;
    for (i = 0; i < TREE.n_nodes; i++)
        if (IMPORT.node[i].tx_len != TREE.node[i].tx_len || memcmp(IMPORT.node[i].tx, TREE.node[i].tx, TREE.node[i].tx_len) != 0
            || IMPORT.node[i].parent != TREE.node[i].parent || IMPORT.node[i].kind != TREE.node[i].kind)
            return 0;
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t len)
{
    static int ready;
    static gz_terms_outer_t outer;
    static gz_terms_current_t cur;
    static uint8_t ob[GZ_TERMS_OUTER_MAX], cb[GZ_TERMS_CURRENT_MAX], osig[64], csig[64], od[32], cd[32], pinned[33];
    static uint8_t ftx[200], change_script[34];
    gz_tree_params_t prm;
    gz_tree_build_in_t bi;
    gz_tree_proposal_t p;
    gz_tree_conditions_t cond;
    gz_tree_member_in_t in;
    gz_tree_verdict_t v;
    gz_tree_b_err_t be;
    gz_tree_i_err_t ie;
    size_t on, cn, fi = 0;
    uint32_t n, me, i, rate;
    int64_t delta;
    uint8_t internal[32], q[32], prev[32];
    (void)check_done;
    if (!ready) {
        gz_tree_secp_crypto(test_ctx(), &CR);
        ready = 1;
    }
    if (len < 12) return 0;
    n = 3u + d[0] % 14u;
    rate = 1 + (uint32_t)(((uint32_t)d[1] << 16 | (uint32_t)d[2] << 8 | d[3]) % 1000000u);
    me = 1u + d[4] % n;
    delta = (int64_t)(d[5] % 7) - 3;                       /* the funding amount: R(root) - 3 .. R(root) + 3 */

    /* The terms: T1, with the fuzzed rate, channel and shape table. */
    t1_terms(&outer);
    outer.target = 16;
    outer.tree_feerate = rate;
    outer.channel_sat = 546 + ((uint64_t)d[6] << 16 | (uint64_t)d[7] << 8 | d[8]);
    switch (d[9] % 4) {
    case 0: break;                                                                 /* T1: {4: leaf}, {16: 4} */
    case 1: outer.n_shapes = 1; outer.shapes[0].max_members = 16; outer.shapes[0].n_interior = 0; break;   /* binary */
    case 2: outer.shapes[0].max_members = 5; outer.shapes[1].interior[0] = 5; break;                        /* {5: leaf}, {16: 5} */
    default: outer.shapes[1].n_interior = 1; outer.shapes[1].interior[0] = (uint8_t)(4 + d[10] % 12); break;         /* {4: leaf}, {16: w} */
    }
    if (gz_terms_check_outer(&outer, &SLICE1) != GZ_TERMS_OK) return 0;        /* refused on receipt */
    if (gz_tree_params(&outer, n, &prm) != GZ_TREE_P_OK) abort();               /* the receipt check promised it */
    on = gz_terms_encode_outer(&outer, ob, sizeof ob);
    if (!on) abort();
    gz_terms_outer_digest(ob, on, od);
    t1_current(od, 1, 500, 1000, 1000, &cur);
    cn = gz_terms_encode_current(&cur, cb, sizeof cb);
    if (!cn) abort();
    gz_terms_current_digest(cb, cn, cd);
    test_sign("host", od, osig);
    test_sign("host", cd, csig);
    test_pub("host", pinned);

    /* The participants: the host, then n members, each bound to the lobby. */
    {
        char label[64];
        snprintf(label, sizeof label, "host factory");
        test_pub(label, PARTS[0].factory_key);
        test_pub("host", PARTS[0].contribution_key);
        bind_one(od, 0, "host factory", "host");
        for (i = 1; i <= n; i++) {
            snprintf(label, sizeof label, "member %u factory", i);
            test_pub(label, PARTS[i].factory_key);
            snprintf(label, sizeof label, "member %u contribution", i);
            test_pub(label, PARTS[i].contribution_key);
            bind_one(od, i, "member %u factory", "member %u contribution");
            memcpy(KEYS[i - 1], PARTS[i].factory_key, 33);
        }
    }
    if (!CR.agg_tweak(CR.ctx, PARTS[0].factory_key, (const uint8_t(*)[33])KEYS, n, NULL, internal, q)) abort();

    /* The proposal. */
    memset(&p, 0, sizeof p);
    p.purpose = 1;
    p.terms_version = 1;
    memcpy(p.terms_digest, cd, 32);
    p.funding_amount = (uint64_t)((int64_t)prm.funding_amount + delta);
    p.funding_script[0] = 0x51; p.funding_script[1] = 0x20; memcpy(p.funding_script + 2, q, 32);
    p.funding_script_len = 34;
    memset(change_script, 0x42, sizeof change_script);
    change_script[0] = 0x51; change_script[1] = 0x20;
    tr_sha256((const uint8_t *)"gazpacho test funding input", 27, prev);
    tr_le32(ftx, 2); fi = 4;
    ftx[fi++] = 1;
    memcpy(ftx + fi, prev, 32); fi += 32;
    tr_le32(ftx + fi, 0); fi += 4;
    ftx[fi++] = 0;
    tr_le32(ftx + fi, 0xfffffffdu); fi += 4;
    ftx[fi++] = 2;
    tr_le64(ftx + fi, p.funding_amount); fi += 8;
    ftx[fi++] = 34; memcpy(ftx + fi, p.funding_script, 34); fi += 34;
    tr_le64(ftx + fi, 5000); fi += 8;
    ftx[fi++] = 34; memcpy(ftx + fi, change_script, 34); fi += 34;
    tr_le32(ftx + fi, 0); fi += 4;
    tr_sha256d(ftx, fi, p.funding_txid);
    p.funding_tx = ftx;
    p.funding_tx_len = fi;
    p.participants = PARTS;
    p.n_participants = n + 1;
    p.n_tiers = 1;
    p.end_height = TIP + 180 + (uint32_t)(d[11] % 13) - 6;
    p.tree_anchors = 1;
    p.tree_feerate = rate;
    p.lstock_delay = 144;
    p.fixed_levels = prm.D;
    p.k = 1;
    p.layer_step = 144;
    p.layer_states = 4;
    p.nonces_due_ms = 30000;
    p.sigs_due_ms = 30000;

    /* The two builders on exactly these inputs. */
    memset(&bi, 0, sizeof bi);
    bi.levels = prm.levels; bi.n_levels = prm.n_levels; bi.fixed_levels = prm.D; bi.n_members = n;
    bi.host_key = PARTS[0].factory_key; bi.member_keys = (const uint8_t(*)[33])KEYS;
    bi.end_height = p.end_height; bi.tree_feerate = rate; bi.lstock_csv = 144;
    memcpy(bi.funding_txid, p.funding_txid, 32);
    bi.funding_amount = p.funding_amount;
    memcpy(bi.funding_script, p.funding_script, 34);
    be = gz_tree_build(&bi, &CR, &TREE);
    ie = gz_tree_import_build(test_ctx(), &bi, &IMPORT);
    if ((be == GZ_TREE_B_OK) != (ie == GZ_TREE_I_OK)) abort();                 /* one builds, the other refuses */
    if (be == GZ_TREE_B_OK && !same_trees()) abort();                            /* other bytes */
    p.tier_sizes[0] = be == GZ_TREE_B_OK ? TREE.n_nodes : 1;

    /* The member's checks, on the same proposal. */
    memset(&cond, 0, sizeof cond);
    cond.min_own_channel_sat = 546;
    cond.max_tree_feerate = 0;                                                    /* none of its own */
    cond.min_lstock_delay = 1; cond.max_lstock_delay = 1000;
    cond.min_members = 3; cond.max_members = 16;
    cond.exit = gz_exit_signet();
    cond.funding_deadline_blocks = 36;
    cond.end_window = 6;
    memset(&in, 0, sizeof in);
    in.outer = &outer; in.outer_digest = od; in.frozen = &cur; in.frozen_digest = cd;
    in.outer_rec = ob; in.outer_rec_len = on; in.outer_sig = osig;
    in.frozen_rec = cb; in.frozen_rec_len = cn; in.frozen_sig = csig;
    in.host_pinned_key = pinned; in.policy = &SLICE1;
    in.ready_outer_digest = od; in.ready_version = 1; in.ready_current_digest = cd;
    in.own_factory_key = PARTS[me].factory_key; in.own_contribution_key = PARTS[me].contribution_key;
    in.cond = &cond; in.tip = TIP; in.crypto = &CR;
    gz_tree_import_member_check(test_ctx(), &in, &p, &TREE2, &IMPORT, &v);
    if (v.check == GZ_CHK_C1_IMPORT_DIFFERS || v.check == GZ_CHK_C1_IMPORT_FAILED) abort();
    if (delta != 0 && v.check != GZ_CHK_C8_FUNDING_RULE) abort();
    if (delta == 0 && be == GZ_TREE_B_OK && v.check != GZ_CHK_OK && v.check != GZ_CHK_C8_EXIT_TIME) abort();
    if (v.check == GZ_CHK_OK && (be != GZ_TREE_B_OK || TREE2.n_nodes != TREE.n_nodes
                                 || memcmp(TREE2.node[0].tx, TREE.node[0].tx, TREE.node[0].tx_len) != 0))
        abort();
    return 0;
}

