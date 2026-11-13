/* safety-rule.md C1 to C11 and H1, each refused at its exact boundary (one
 * below, at, one above wherever the rule is numeric), with the precise check
 * and the messages.md 7.9 reason. The scenario is a T1 lobby whose proposal
 * passes every check; each test changes one thing. */
#include "tree_test.h"
#include "gazpacho/tree_import.h"
#include "../../core/tree/internal.h"

#define TIP 290000u
static const gz_exit_consts_t SIG = GZ_EXIT_SIGNET_INIT;
static const gz_terms_policy_t SLICE1 = {1};
#define MAXP 300
#define PIN_TREE_DIGEST "04ea434128f5bd849b918d5e8953e347bd5f17fcafe43ff56b90dbdca5afba83"
#define PIN_ROUND_ID "75c3144848bfba3cd74ab25041ddd730e79e0e45bdf7ffcfa6eff082c5d32516"

typedef struct {
    gz_terms_outer_t outer;
    uint8_t od[32];
    gz_terms_current_t cur;
    uint8_t cd[32];
    /* the same terms as stored bytes, signed by the host's key */
    uint8_t ob[GZ_TERMS_OUTER_MAX], cb[GZ_TERMS_CURRENT_MAX], osig[64], csig[64], pinned[33];
    size_t on, cn;
    int fund_second;            /* the funding output is the transaction's output 1 */
    gz_tree_participant_t parts[MAXP];
    uint8_t ftx[200];
    size_t ftx_len;
    uint64_t change;
    uint8_t change_script[34];
    gz_tree_proposal_t p;
    gz_tree_conditions_t cond;
    gz_tree_member_in_t in;
    uint8_t own_f[33], own_c[33];
    gz_tree_params_t prm;
    uint32_t n, me;
} scen_t;

static gz_tree_t TREE;
static gz_tree_import_t IMPORT;
static gz_tree_crypto_t CR;
static scen_t S;

static void key(const char *fmt, uint32_t i, uint8_t out[33])
{
    char label[64];
    snprintf(label, sizeof label, fmt, i);
    test_pub(label, out);
}

static void sign_label(const char *fmt, uint32_t i, const uint8_t msg[32], uint8_t sig[64])
{
    char label[64];
    snprintf(label, sizeof label, fmt, i);
    test_sign(label, msg, sig);
}

static void bind(scen_t *s, uint32_t i, const char *ff, const char *cf)
{
    uint8_t h[32];
    tr_sha256_t t;
    tr_tagged_init(&t, "gazpacho/bind");
    tr_sha256_write(&t, s->od, 32);
    tr_sha256_write(&t, s->parts[i].factory_key, 33);
    tr_sha256_write(&t, s->parts[i].contribution_key, 33);
    tr_sha256_done(&t, h);
    sign_label(ff, i, h, s->parts[i].bind_by_factory);
    sign_label(cf, i, h, s->parts[i].bind_by_contribution);
}

/* The host's funding transaction: one segwit input, the funding output, change. */
static void set_funding(scen_t *s, uint64_t amount_in_tx, const uint8_t script_in_tx[34])
{
    uint8_t *p = s->ftx, prev[32];
    size_t i = 0;
    tr_sha256((const uint8_t *)"gazpacho test funding input", 27, prev);
    tr_le32(p, 2); i = 4;
    p[i++] = 1;
    memcpy(p + i, prev, 32); i += 32;
    tr_le32(p + i, 0); i += 4;
    p[i++] = 0;
    tr_le32(p + i, 0xfffffffdu); i += 4;
    p[i++] = 2;
    if (s->fund_second) { tr_le64(p + i, s->change); i += 8; p[i++] = 34; memcpy(p + i, s->change_script, 34); i += 34; }
    tr_le64(p + i, amount_in_tx); i += 8;
    p[i++] = 34; memcpy(p + i, script_in_tx, 34); i += 34;
    if (!s->fund_second) { tr_le64(p + i, s->change); i += 8; p[i++] = 34; memcpy(p + i, s->change_script, 34); i += 34; }
    tr_le32(p + i, 0); i += 4;
    s->ftx_len = i;
    tr_sha256d(s->ftx, i, s->p.funding_txid);
    s->p.funding_tx = s->ftx;
    s->p.funding_tx_len = i;
}

static void aggregate_script(scen_t *s, uint8_t script[34])
{
    uint8_t keys[GZ_TREE_MAX_MEMBERS][33], internal[32], q[32];
    uint32_t i;
    for (i = 0; i < s->n; i++) memcpy(keys[i], s->parts[i + 1].factory_key, 33);
    if (!CR.agg_tweak(CR.ctx, s->parts[0].factory_key, (const uint8_t(*)[33])keys, s->n, NULL, internal, q)) abort();
    script[0] = 0x51; script[1] = 0x20; memcpy(script + 2, q, 32);
}

/* The stored records from the structs: encoded, digested, signed by the host. */
static void seal_terms(scen_t *s)
{
    s->on = gz_terms_encode_outer(&s->outer, s->ob, sizeof s->ob);
    if (!s->on) abort();
    gz_terms_outer_digest(s->ob, s->on, s->od);
    memcpy(s->cur.outer_digest, s->od, 32);
    s->cn = gz_terms_encode_current(&s->cur, s->cb, sizeof s->cb);
    if (!s->cn) abort();
    gz_terms_current_digest(s->cb, s->cn, s->cd);
    test_sign("host", s->od, s->osig);
    test_sign("host", s->cd, s->csig);
}

/* After a test changed S.outer or S.cur: new records, digests and signatures,
 * the proposal's terms digest and every binding (they name the outer digest). */
static void reseal(void)
{
    uint32_t i;
    seal_terms(&S);
    S.in.outer_rec_len = S.on; S.in.frozen_rec_len = S.cn;   /* a new table can change the length */
    memcpy(S.p.terms_digest, S.cd, 32);
    bind(&S, 0, "host factory", "host");
    for (i = 1; i <= S.n; i++) bind(&S, i, "member %u factory", "member %u contribution");
}

/* A proposal for n members in which this member is member `me` (1-based). */
static void scenario(uint32_t n, uint32_t me)
{
    scen_t *s = &S;
    uint32_t i;
    memset(s, 0, sizeof *s);
    s->n = n; s->me = me;
    t1_terms(&s->outer);
    t1_current(s->od, 1, 500, 1000, 1000, &s->cur);
    seal_terms(s);
    test_pub("host", s->pinned);
    key("host factory", 0, s->parts[0].factory_key);
    test_pub("host", s->parts[0].contribution_key);
    bind(s, 0, "host factory", "host");
    for (i = 1; i <= n; i++) {
        key("member %u factory", i, s->parts[i].factory_key);
        key("member %u contribution", i, s->parts[i].contribution_key);
        bind(s, i, "member %u factory", "member %u contribution");
    }
    memcpy(s->own_f, s->parts[me].factory_key, 33);
    memcpy(s->own_c, s->parts[me].contribution_key, 33);
    if (n >= 3 && n <= 16 && gz_tree_params(&s->outer, n, &s->prm) != GZ_TREE_P_OK) abort();
    s->change = 5000;
    key("change %u", 0, s->change_script);   /* any 34 bytes: a P2TR-like script */
    s->change_script[0] = 0x51; s->change_script[1] = 0x20;
    s->p.purpose = 1;
    s->p.terms_version = 1;
    memcpy(s->p.terms_digest, s->cd, 32);
    s->p.funding_vout = 0;
    s->p.funding_amount = s->prm.funding_amount;
    aggregate_script(s, s->p.funding_script);
    s->p.funding_script_len = 34;
    set_funding(s, s->p.funding_amount, s->p.funding_script);
    s->p.participants = s->parts;
    s->p.n_participants = n + 1;
    s->p.n_tiers = 1;
    s->p.end_height = TIP + 180;
    s->p.tree_anchors = 1;
    s->p.fee_per_tx = s->prm.fee_per_tx;
    s->p.lstock_delay = 144;
    s->p.fixed_levels = s->prm.D;
    s->p.k = 1;
    s->p.layer_step = 144;
    s->p.layer_states = 4;
    s->p.nonces_due_ms = 30000;
    s->p.sigs_due_ms = 30000;
    s->cond.min_own_channel_sat = 100000;
    s->cond.max_fee_per_tx_sat = 1000;
    s->cond.min_lstock_delay = 1;
    s->cond.max_lstock_delay = 1000;
    s->cond.min_members = 3;
    s->cond.max_members = 16;
    s->cond.exit = gz_exit_signet();
    s->cond.funding_deadline_blocks = 36;
    s->cond.end_window = 6;
    s->in.outer = &s->outer;
    s->in.outer_digest = s->od;
    s->in.frozen = &s->cur;
    s->in.frozen_digest = s->cd;
    s->in.outer_rec = s->ob; s->in.outer_rec_len = s->on; s->in.outer_sig = s->osig;
    s->in.frozen_rec = s->cb; s->in.frozen_rec_len = s->cn; s->in.frozen_sig = s->csig;
    s->in.host_pinned_key = s->pinned;
    s->in.policy = &SLICE1;
    s->in.ready_outer_digest = s->od;
    s->in.ready_version = 1;
    s->in.ready_current_digest = s->cd;
    s->in.own_factory_key = s->own_f;
    s->in.own_contribution_key = s->own_c;
    s->in.cond = &s->cond;
    s->in.tip = TIP;
    s->in.crypto = &CR;
    /* the tier: every node of the tree */
    {
        gz_tree_build_in_t bi;
        uint8_t keys[GZ_TREE_MAX_MEMBERS][33];
        memset(&bi, 0, sizeof bi);
        for (i = 0; i < n; i++) memcpy(keys[i], s->parts[i + 1].factory_key, 33);
        bi.levels = s->prm.levels; bi.n_levels = s->prm.n_levels; bi.fixed_levels = s->prm.D; bi.n_members = n;
        bi.host_key = s->parts[0].factory_key; bi.member_keys = (const uint8_t(*)[33])keys;
        bi.end_height = s->p.end_height; bi.fee_per_tx = s->p.fee_per_tx; bi.lstock_csv = 144;
        bi.funding_amount = s->p.funding_amount;
        if (n >= 3 && n <= 16 && gz_tree_build(&bi, &CR, &TREE) == GZ_TREE_B_OK) s->p.tier_sizes[0] = TREE.n_nodes;
    }
}

static gz_tree_verdict_t run(void)
{
    gz_tree_verdict_t v;
    gz_tree_import_member_check(test_ctx(), &S.in, &S.p, &TREE, &IMPORT, &v);
    return v;
}

static int expect_at(gz_chk_t want, uint16_t reason, int line)
{
    gz_tree_verdict_t v = run();
    int ok = v.check == want && v.reason == reason && gz_tree_reason(want) == reason;
    check_count++;
    if (!ok) {
        printf("FAIL line %d: want %s (%u), got %s (%u) at %d\n", line, gz_chk_name(want), reason, gz_chk_name(v.check),
               v.reason, (int)v.at);
        check_failures++;
    }
    return ok;
}
#define EXPECT(c, r) expect_at((c), (r), __LINE__)
#define OK() expect_at(GZ_CHK_OK, GZ_REASON_NONE, __LINE__)

static void refund(void) { set_funding(&S, S.p.funding_amount, S.p.funding_script); }

static void honest(void)
{
    uint32_t n, me;
    for (n = 3; n <= 8; n++)
        for (me = 1; me <= n; me++) {
            gz_tree_verdict_t v;
            scenario(n, me);
            v = run();
            CHECK(v.check == GZ_CHK_OK);
            CHECK(v.own_member == me - 1 && v.own_depth == S.prm.depth[me - 1]);
            CHECK(v.leave_by == gz_exit_leave_by(TIP + 180, v.own_depth, v.own_depth + 3u, &SIG));
        }
}

static void c8a(void)
{
    scenario(4, 2);
    OK();
    S.p.purpose = 0; EXPECT(GZ_CHK_C8A_PURPOSE, 9); S.p.purpose = 2; EXPECT(GZ_CHK_C8A_PURPOSE, 9); S.p.purpose = 1;
    S.p.terms_version = 0; EXPECT(GZ_CHK_C8A_VERSION, 9); S.p.terms_version = 2; EXPECT(GZ_CHK_C8A_VERSION, 9); S.p.terms_version = 1;
    S.in.ready_version = 2; EXPECT(GZ_CHK_C8A_VERSION, 9); S.in.ready_version = 1;
    S.p.terms_digest[31] ^= 1; EXPECT(GZ_CHK_C8A_DIGEST, 9); S.p.terms_digest[31] ^= 1;
    {
        uint8_t other[32];
        memcpy(other, S.cd, 32); other[0] ^= 1;
        S.in.ready_current_digest = other; EXPECT(GZ_CHK_C8A_DIGEST, 9); S.in.ready_current_digest = S.cd;
        memcpy(other, S.od, 32); other[0] ^= 1;
        S.in.ready_outer_digest = other; EXPECT(GZ_CHK_C8A_READY_OUTER, 9); S.in.ready_outer_digest = S.od;
    }
    S.cur.outer_digest[5] ^= 1; EXPECT(GZ_CHK_C8A_READY_OUTER, 9); S.cur.outer_digest[5] ^= 1;
    OK();
}

static void c1_participants(void)
{
    scenario(4, 2);
    S.p.n_participants = 1; EXPECT(GZ_CHK_C1_PARTICIPANTS, 1);
    S.p.n_participants = GZ_TREE_MAX_MEMBERS + 2; EXPECT(GZ_CHK_C1_PARTICIPANTS, 1);
    S.p.n_participants = 5;
    S.parts[3].factory_key[0] = 4; EXPECT(GZ_CHK_C1_BAD_KEY, 1); S.parts[3].factory_key[0] ^= 4 ^ 2;
    if (!CR.point_valid(CR.ctx, S.parts[3].factory_key)) S.parts[3].factory_key[0] = 3;
    scenario(4, 2);
    memset(S.parts[4].contribution_key + 1, 0xff, 32); EXPECT(GZ_CHK_C1_BAD_KEY, 1);
    scenario(4, 2);
    memcpy(S.parts[3].factory_key, S.parts[1].factory_key, 33); EXPECT(GZ_CHK_C1_DUPLICATE_KEY, 1);
    scenario(4, 2);
    memcpy(S.parts[3].contribution_key, S.parts[1].contribution_key, 33); EXPECT(GZ_CHK_C1_DUPLICATE_KEY, 1);
    scenario(4, 2);
    memcpy(S.parts[3].contribution_key, S.parts[1].factory_key, 33); EXPECT(GZ_CHK_C1_DUPLICATE_KEY, 1);
    scenario(4, 2);
    memcpy(S.parts[1].contribution_key, S.parts[1].factory_key, 33); EXPECT(GZ_CHK_C1_DUPLICATE_KEY, 1);
    /* P and -P are one BIP 340 key (review A, S1): another member's key with the other parity. */
    scenario(4, 2);
    memcpy(S.parts[3].factory_key, S.parts[1].factory_key, 33); S.parts[3].factory_key[0] ^= 1;
    CHECK(CR.point_valid(CR.ctx, S.parts[3].factory_key)); EXPECT(GZ_CHK_C1_DUPLICATE_KEY, 1);
    scenario(4, 2);
    memcpy(S.parts[3].contribution_key, S.parts[2].factory_key, 33); S.parts[3].contribution_key[0] ^= 1;
    EXPECT(GZ_CHK_C1_DUPLICATE_KEY, 1);
    scenario(4, 2);
    memcpy(S.parts[2].contribution_key, S.parts[2].factory_key, 33); S.parts[2].contribution_key[0] ^= 1;
    EXPECT(GZ_CHK_C1_DUPLICATE_KEY, 1);
    scenario(4, 2);
    memcpy(S.parts[3].factory_key, S.parts[0].contribution_key, 33); EXPECT(GZ_CHK_C1_DUPLICATE_KEY, 1);
    /* the host's contribution key is its long-term key (signing-round.md 2) */
    scenario(4, 2);
    key("someone %u", 0, S.parts[0].contribution_key); EXPECT(GZ_CHK_C1_HOST_KEY, 1);
    /* bindings (messages.md 6.3): reason 5 */
    scenario(4, 2);
    S.parts[3].bind_by_factory[10] ^= 1; EXPECT(GZ_CHK_BINDING, 5);
    scenario(4, 2);
    S.parts[0].bind_by_contribution[63] ^= 1; EXPECT(GZ_CHK_BINDING, 5);
    scenario(4, 2);
    memcpy(S.parts[2].bind_by_factory, S.parts[1].bind_by_factory, 64); EXPECT(GZ_CHK_BINDING, 5);
}

static void c7_c10(void)
{
    gz_tree_outpoint_t u[2];
    gz_tree_exposure_t x[2];
    gz_tree_verdict_t v;
    /* C7 fresh key (reason 12). */
    scenario(4, 2);
    S.in.own_factory_key = NULL; EXPECT(GZ_CHK_C7_NOT_MY_KEY, 12); S.in.own_factory_key = S.own_f;
    S.in.own_contribution_key = NULL; EXPECT(GZ_CHK_C7_NOT_MY_KEY, 12); S.in.own_contribution_key = S.own_c;
    key("member %u contribution", 3, S.own_c); EXPECT(GZ_CHK_C7_NOT_MY_KEY, 12);   /* my factory key, another's contribution */
    key("member %u contribution", 9, S.own_c); EXPECT(GZ_CHK_C7_NOT_MY_KEY, 12);   /* a key from another epoch */
    key("member %u contribution", 2, S.own_c); OK();
    key("host factory", 0, S.own_f); test_pub("host", S.own_c); EXPECT(GZ_CHK_C7_NOT_MY_KEY, 12);   /* never as the host */
    /* C10 (reason 6): the same outpoint is busy; another index of the same transaction is not. */
    scenario(4, 2);
    memcpy(u[0].txid, S.p.funding_txid, 32); u[0].vout = 1;
    S.in.unresolved = u; S.in.n_unresolved = 1; OK();
    u[0].vout = 0; EXPECT(GZ_CHK_C10_BUSY, 6);
    u[1] = u[0]; u[0].txid[0] ^= 1; S.in.n_unresolved = 2; EXPECT(GZ_CHK_C10_BUSY, 6);
    S.in.n_unresolved = 1; OK();
    S.in.n_unresolved = 0;
    /* C7, one tree per funding output (reason 11). */
    v = run();
    CHECK(v.check == GZ_CHK_OK);
    memcpy(x[0].funding.txid, S.p.funding_txid, 32); x[0].funding.vout = 0;
    memcpy(x[0].tree_digest, v.tree_digest, 32);
    S.in.exposures = x; S.in.n_exposures = 1; OK();               /* the same tree: allowed */
    x[0].tree_digest[3] ^= 1; EXPECT(GZ_CHK_C7_OTHER_TREE, 11);   /* another tree on this outpoint */
    x[0].funding.vout = 1; OK();                                   /* another outpoint */
    x[0].funding.vout = 0; x[1] = x[0]; memcpy(x[1].tree_digest, v.tree_digest, 32); x[0].funding.txid[0] ^= 1;
    S.in.n_exposures = 2; OK();
    x[0].funding.txid[0] ^= 1; EXPECT(GZ_CHK_C7_OTHER_TREE, 11);
}

static void c8_fixed(void)
{
    scenario(4, 2);
    S.p.placement = 1; EXPECT(GZ_CHK_C8_PLACEMENT, 9); S.p.placement = 0;
    S.p.tree_anchors = 0; EXPECT(GZ_CHK_C8_ANCHORS, 9); S.p.tree_anchors = 2; EXPECT(GZ_CHK_C8_ANCHORS, 9); S.p.tree_anchors = 1;
    S.p.k = 0; EXPECT(GZ_CHK_C8_K, 9); S.p.k = 2; EXPECT(GZ_CHK_C8_K, 9); S.p.k = 1;
    S.p.layer_step = 143; EXPECT(GZ_CHK_C8_LAYER_STEP, 9); S.p.layer_step = 145; EXPECT(GZ_CHK_C8_LAYER_STEP, 9); S.p.layer_step = 144;
    S.p.layer_states = 3; EXPECT(GZ_CHK_C8_LAYER_STATES, 9); S.p.layer_states = 5; EXPECT(GZ_CHK_C8_LAYER_STATES, 9); S.p.layer_states = 4;
    S.p.n_lstock_hashes = 1; EXPECT(GZ_CHK_C8_HASHES, 9); S.p.n_lstock_hashes = 0;
    S.p.has_distribution = 1; EXPECT(GZ_CHK_C8_DISTRIBUTION, 9); S.p.has_distribution = 0;
    /* messages.md 7.2 records 48 and 50: at most the terms' step timeout (60,000 in T1). */
    S.p.nonces_due_ms = 60000; OK();
    S.p.nonces_due_ms = 60001; EXPECT(GZ_CHK_C8_DEADLINES, 9); S.p.nonces_due_ms = 59999; OK();
    S.p.sigs_due_ms = 60000; OK();
    S.p.sigs_due_ms = 60001; EXPECT(GZ_CHK_C8_DEADLINES, 9); S.p.sigs_due_ms = 30000;
    OK();
}

static void c8_members(void)
{
    /* The terms: minimum 3, target 8. */
    scenario(2, 1); S.p.tier_sizes[0] = 0; EXPECT(GZ_CHK_C8_MEMBERS_TERMS, 9);
    scenario(3, 1); OK();
    scenario(8, 8); OK();
    scenario(9, 1); EXPECT(GZ_CHK_C8_MEMBERS_TERMS, 9);
    /* The member's own range. */
    scenario(3, 1); S.cond.min_members = 4; EXPECT(GZ_CHK_C8_MEMBERS_OWN, 9); S.cond.min_members = 3; OK();
    scenario(8, 1); S.cond.max_members = 7; EXPECT(GZ_CHK_C8_MEMBERS_OWN, 9); S.cond.max_members = 8; OK();
}

static void c8_lstock(void)
{
    scenario(4, 2);
    S.p.lstock_delay = 0; EXPECT(GZ_CHK_C8_LSTOCK_DELAY, 9);
    S.cond.min_lstock_delay = 0; EXPECT(GZ_CHK_C8_LSTOCK_DELAY, 9);   /* 0 even when the member allows it */
    S.cond.min_lstock_delay = 2; S.p.lstock_delay = 1; EXPECT(GZ_CHK_C8_LSTOCK_DELAY, 9);
    S.p.lstock_delay = 2; OK();
    S.p.lstock_delay = 1000; OK();
    S.p.lstock_delay = 1001; EXPECT(GZ_CHK_C8_LSTOCK_DELAY, 9);
    S.cond.max_lstock_delay = 70000;
    S.p.lstock_delay = 65535; OK();
    S.p.lstock_delay = 65536; EXPECT(GZ_CHK_C8_LSTOCK_DELAY, 9);
}

static void c8_shape_fee_funding(void)
{
    gz_tree_verdict_t v;
    scenario(4, 2);
    S.p.fixed_levels = S.prm.D - 1; EXPECT(GZ_CHK_C8_FIXED_LEVELS, 9);
    S.p.fixed_levels = S.prm.D + 1; EXPECT(GZ_CHK_C8_FIXED_LEVELS, 9);
    S.p.fixed_levels = S.prm.D; OK();
    S.p.fee_per_tx = S.prm.fee_per_tx - 1; EXPECT(GZ_CHK_C8_FEE_RULE, 9);
    S.p.fee_per_tx = S.prm.fee_per_tx + 1; EXPECT(GZ_CHK_C8_FEE_RULE, 9);
    S.p.fee_per_tx = S.prm.fee_per_tx;
    S.cond.max_fee_per_tx_sat = S.prm.fee_per_tx - 1; EXPECT(GZ_CHK_C8_FEE_CEILING, 9);
    S.cond.max_fee_per_tx_sat = S.prm.fee_per_tx; OK();
    S.p.funding_amount = S.prm.funding_amount - 1; refund(); EXPECT(GZ_CHK_C8_FUNDING_RULE, 9);
    S.p.funding_amount = S.prm.funding_amount + 1; refund(); EXPECT(GZ_CHK_C8_FUNDING_RULE, 9);
    S.p.funding_amount = S.prm.funding_amount; refund(); OK();
    /* No shape for n, and a shape whose split makes a multi-member leaf:
     * outer rules that would not have decoded are refused by the member's
     * re-check of the terms before anything is built from them (review B,
     * B1), with or without stored bytes that match them. */
    scenario(5, 2);
    S.outer.n_shapes = 1;
    v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_BOUNDS && v.reason == 9 && v.at == GZ_TERMS_E_SHAPE_TARGET);
    reseal();
    v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_BOUNDS && v.at == GZ_TERMS_E_SHAPE_TARGET);
    scenario(3, 2);
    S.outer.n_shapes = 1; S.outer.shapes[0].max_members = 16; S.outer.shapes[0].n_interior = 1;
    S.outer.shapes[0].interior[0] = 4;
    v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_BOUNDS && v.at == GZ_TERMS_E_SHAPE_SPLIT);
    /* The member's own channel: at its minimum, and one above. */
    scenario(3, 1);
    v = run();
    CHECK(v.check == GZ_CHK_OK);
    S.cond.min_own_channel_sat = TREE.node[TREE.leaf_state[0]].out_amount[0];
    CHECK(S.cond.min_own_channel_sat == 200385);
    OK();
    S.cond.min_own_channel_sat++; EXPECT(GZ_CHK_C8_CHANNEL_OWN, 9);
    /* The import's minimum funding, from the terms (a lobby of exactly 4):
     * fee 880 builds, 881 does not. Terms that cannot be funded are refused
     * on receipt (review A, S3), and so by the member's re-check of the
     * terms before the build's own mirror of the import's minimum. */
    scenario(4, 2);
    S.outer.minimum = 4; S.outer.target = 4;
    S.outer.channel_sat = 546; S.cond.min_own_channel_sat = 546; S.cond.max_fee_per_tx_sat = 100000;
    S.outer.tree_feerate = 5269;
    reseal();
    CHECK(gz_tree_params(&S.outer, 4, &S.prm) == GZ_TREE_P_OK && S.prm.fee_per_tx == 880);
    S.p.fee_per_tx = 880; S.p.funding_amount = S.prm.funding_amount; refund();
    OK();
    S.outer.tree_feerate = 5270;
    reseal();
    CHECK(gz_tree_params(&S.outer, 4, &S.prm) == GZ_TREE_P_OK && S.prm.fee_per_tx == 881);
    S.p.fee_per_tx = 881; S.p.funding_amount = S.prm.funding_amount; refund();
    v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_BOUNDS && v.reason == 9 && v.at == GZ_TERMS_E_UNFUNDABLE);
}

static void c8_heights(void)
{
    /* End height: tip + lifetime + wind-down = TIP + 180, within 6. */
    scenario(3, 1);
    S.p.end_height = 0; EXPECT(GZ_CHK_C8_END_ZERO, 9);
    S.p.end_height = TIP + 180 - 7; EXPECT(GZ_CHK_C8_END_WINDOW, 9);
    S.p.end_height = TIP + 180 - 6; OK();
    S.p.end_height = TIP + 180 + 6; OK();
    S.p.end_height = TIP + 180 + 7; EXPECT(GZ_CHK_C8_END_WINDOW, 9);
    S.p.end_height = TIP + 180;
    /* Exit time: member 1 of 3 is at depth 1, leave_by = TIP + 130, so the
     * latest funding deadline is TIP + 126 (exit.md 4.4's signing-time check). */
    S.cond.funding_deadline_blocks = 126; OK();
    S.cond.funding_deadline_blocks = 127; EXPECT(GZ_CHK_C8_EXIT_TIME, 9);
    S.cond.funding_deadline_blocks = 125; OK();
    /* member 2 of 3 is at depth 2: leave_by = TIP + 114, latest deadline TIP + 110. */
    scenario(3, 2);
    S.cond.funding_deadline_blocks = 110; OK();
    S.cond.funding_deadline_blocks = 111; EXPECT(GZ_CHK_C8_EXIT_TIME, 9);
    /* Heights only: E below 500,000,000 (review A, S2). expect = tip + 180. */
    scenario(3, 1);
    S.in.tip = 499999819u; S.p.end_height = 499999999u; OK();
    S.p.end_height = 500000000u; EXPECT(GZ_CHK_C8_END_LOCKTIME, 9);
    S.p.end_height = 500000005u; EXPECT(GZ_CHK_C8_END_LOCKTIME, 9);
    /* The same with a shorter life: E moves with the tip. */
    scenario(3, 2);
    S.outer.lifetime_blocks = 144 - 74; S.outer.winddown_blocks = 36;
    reseal();
    S.p.end_height = TIP + 106;      /* leave_by = TIP + 40 */
    S.cond.funding_deadline_blocks = 36; OK();
    S.p.end_height = TIP + 105;
    EXPECT(GZ_CHK_C8_EXIT_TIME, 9);
}

static void c1_funding(void)
{
    uint8_t other[34];
    scenario(4, 2);
    S.p.funding_tx_len -= 1; EXPECT(GZ_CHK_C1_FUNDING_TX, 1); S.p.funding_tx_len += 1;
    S.p.funding_tx = NULL; EXPECT(GZ_CHK_C1_FUNDING_TX, 1); S.p.funding_tx = S.ftx;
    S.ftx[S.ftx_len] = 0; S.p.funding_tx_len += 1; EXPECT(GZ_CHK_C1_FUNDING_TX, 1); S.p.funding_tx_len -= 1;   /* a byte left over */
    {   /* a count written in three bytes (fd 01 00): not canonical */
        static uint8_t nc[220];
        memcpy(nc, S.ftx, 4); nc[4] = 0xfd; nc[5] = 1; nc[6] = 0; memcpy(nc + 7, S.ftx + 5, S.ftx_len - 5);
        S.p.funding_tx = nc; S.p.funding_tx_len = S.ftx_len + 2; EXPECT(GZ_CHK_C1_FUNDING_TX, 1);
        S.p.funding_tx = S.ftx; S.p.funding_tx_len = S.ftx_len;
    }
    S.p.funding_txid[0] ^= 1; EXPECT(GZ_CHK_C1_FUNDING_TXID, 1); S.p.funding_txid[0] ^= 1;
    S.p.funding_vout = 2; EXPECT(GZ_CHK_C1_FUNDING_VOUT, 1);
    S.p.funding_vout = 1; EXPECT(GZ_CHK_C1_FUNDING_AMOUNT, 1);   /* the change output */
    S.p.funding_vout = 0; OK();
    set_funding(&S, S.p.funding_amount + 1, S.p.funding_script); EXPECT(GZ_CHK_C1_FUNDING_AMOUNT, 1);
    set_funding(&S, S.p.funding_amount - 1, S.p.funding_script); EXPECT(GZ_CHK_C1_FUNDING_AMOUNT, 1);
    refund(); OK();
    S.p.funding_script_len = 33; EXPECT(GZ_CHK_C1_FUNDING_SCRIPT_LEN, 1);
    S.p.funding_script_len = 35; EXPECT(GZ_CHK_C1_FUNDING_SCRIPT_LEN, 1);
    S.p.funding_script_len = 34;
    memcpy(other, S.p.funding_script, 34); other[33] ^= 1;
    set_funding(&S, S.p.funding_amount, other); EXPECT(GZ_CHK_C1_FUNDING_SCRIPT, 1);
    /* The right key under another prefix (review A, M09): a P2WSH 00 20 || Q, and 51 21 || Q. */
    scenario(4, 2);
    S.p.funding_script[0] = 0x00; refund(); EXPECT(GZ_CHK_C1_NOT_AGGREGATE, 1);
    scenario(4, 2);
    S.p.funding_script[1] = 0x21; refund(); EXPECT(GZ_CHK_C1_NOT_AGGREGATE, 1);
    scenario(4, 2);
    memcpy(other, S.p.funding_script, 34); other[33] ^= 1;
    /* Both the proposal and the transaction name a script that is not the aggregate. */
    memcpy(S.p.funding_script, other, 34); refund(); EXPECT(GZ_CHK_C1_NOT_AGGREGATE, 1);
    /* The aggregate in another order is another key. */
    scenario(4, 2);
    {
        gz_tree_participant_t t = S.parts[1];
        S.parts[1] = S.parts[2]; S.parts[2] = t;
        aggregate_script(&S, other);
        S.parts[2] = S.parts[1]; S.parts[1] = t;
        memcpy(S.p.funding_script, other, 34); refund(); EXPECT(GZ_CHK_C1_NOT_AGGREGATE, 1);
    }
    /* The funding output at index 1, through the real import (review B, B7):
     * the glue must hand the index on, or the import's root spends output 0
     * and the comparison refuses every such round. */
    scenario(4, 2);
    S.fund_second = 1; refund();
    S.p.funding_vout = 1; OK();
    S.p.funding_vout = 0; EXPECT(GZ_CHK_C1_FUNDING_AMOUNT, 1);   /* the change output */
    S.p.funding_vout = 2; EXPECT(GZ_CHK_C1_FUNDING_VOUT, 1);
    S.fund_second = 0;
    /* A scriptSig length past the end of the funding transaction (review B,
     * B7): 2^64 - 4, which read without its bound wraps the offset back over
     * the length's own last 4 bytes (read as the sequence) and parses the
     * rest as one output, the funding output. */
    {
        static uint8_t w[200];
        gz_tx_info_t info;
        size_t i;
        scenario(4, 2);
        tr_le32(w, 2); i = 4; w[i++] = 1;
        memcpy(w + i, S.ftx + 5, 36); i += 36;
        w[i++] = 0xff; tr_le64(w + i, 0xfffffffffffffffcull); i += 8;
        w[i++] = 1; tr_le64(w + i, S.p.funding_amount); i += 8;
        w[i++] = 34; memcpy(w + i, S.p.funding_script, 34); i += 34;
        tr_le32(w + i, 0); i += 4;
        CHECK(i == 98 && !gz_tx_parse(w, i, &info));
        tr_sha256d(w, i, S.p.funding_txid);
        S.p.funding_tx = w; S.p.funding_tx_len = i;
        EXPECT(GZ_CHK_C1_FUNDING_TX, 1);
        /* a length one byte past the end, in the shortest form */
        w[41] = 98 - 46 - 4 + 1; memmove(w + 42, w + 50, 48); i = 90;
        CHECK(!gz_tx_parse(w, i, &info));
        w[41] = 98 - 46 - 4 - 8; CHECK(!gz_tx_parse(w, i, &info));   /* and short of it: what follows is not an output list */
    }
}

/* An import that misbehaves on demand, and counts its calls. */
static int tamper, import_calls;
static int tampering_import(void *ctx, const gz_tree_build_in_t *in, gz_tree_import_t *out)
{
    uint32_t i;
    int ok = gz_tree_import_build(ctx, in, out) == GZ_TREE_I_OK;
    import_calls++;
    switch (tamper) {
    case 1: out->node[3].tx[10] ^= 1; break;
    case 2: out->n_nodes--; break;
    case 3: out->node[2].n_signers++; break;
    case 4: out->node[2].parent = 0; break;
    case 5: return 0;
    case 6: for (i = 0; i < out->n_nodes; i++) if (out->node[i].is_ps_leaf) { out->node[i].is_ps_leaf = 0; break; } break;
    case 7: out->node[0].is_ps_leaf = 1; break;
    case 8: out->node[1].parent_vout ^= 1; break;
    case 9: out->node[0].kind = GZ_NODE_LEAF_KICKOFF; break;
    }
    return ok;
}

static gz_tree_verdict_t run_tampered(int how)
{
    gz_tree_verdict_t v;
    tamper = how;
    S.in.import_build = tampering_import;
    S.in.import_ctx = test_ctx();
    S.in.import_out = &IMPORT;
    gz_tree_member_check(&S.in, &S.p, &TREE, &v);
    tamper = 0;
    return v;
}

static void c1_import_leaves_tiers(void)
{
    gz_tree_verdict_t v;
    uint32_t first_leaf = 0;
    scenario(4, 2);
    OK();
    while (!IMPORT.node[first_leaf].is_ps_leaf) first_leaf++;
    v = run_tampered(0); CHECK(v.check == GZ_CHK_OK);
    /* The import's bytes, or what it says about a node, other than the rules': refused. */
    v = run_tampered(1); CHECK(v.check == GZ_CHK_C1_IMPORT_DIFFERS && v.reason == 1 && v.at == 3);
    v = run_tampered(2); CHECK(v.check == GZ_CHK_C1_IMPORT_DIFFERS && v.at == -1);
    v = run_tampered(3); CHECK(v.check == GZ_CHK_C1_IMPORT_DIFFERS && v.at == 2);
    v = run_tampered(4); CHECK(v.check == GZ_CHK_C1_IMPORT_DIFFERS && v.at == 2);
    v = run_tampered(8); CHECK(v.check == GZ_CHK_C1_IMPORT_DIFFERS && v.at == 1);
    v = run_tampered(9); CHECK(v.check == GZ_CHK_C1_IMPORT_DIFFERS && v.at == 0);
    v = run_tampered(5); CHECK(v.check == GZ_CHK_C1_IMPORT_FAILED && v.reason == 1);
    /* C8 leaf kind on the import's own labels. */
    v = run_tampered(6); CHECK(v.check == GZ_CHK_C8_LEAF_KIND && v.reason == 9 && v.at == (int32_t)first_leaf);
    v = run_tampered(7); CHECK(v.check == GZ_CHK_C8_LEAF_KIND && v.at == 0);
    /* The import never runs on a proposal the rules refuse: here a shape
     * whose split puts 3 members under a width of 4, which the pinned import
     * would build reading layers[-1] (signing-round.md 12; upstream #486).
     * The re-check of the terms refuses it first (review B, B1). */
    scenario(3, 2);
    S.outer.n_shapes = 1; S.outer.shapes[0].max_members = 16; S.outer.shapes[0].n_interior = 1;
    S.outer.shapes[0].interior[0] = 4;
    reseal();
    import_calls = 0;
    v = run_tampered(0); CHECK(v.check == GZ_CHK_C8A_TERMS_BOUNDS && v.at == GZ_TERMS_E_SHAPE_SPLIT && import_calls == 0);
    scenario(4, 2);
    S.p.fixed_levels = 1;
    import_calls = 0;
    v = run_tampered(0); CHECK(v.check == GZ_CHK_C8_FIXED_LEVELS && import_calls == 0);
    scenario(4, 2);
    import_calls = 0;
    v = run_tampered(0); CHECK(v.check == GZ_CHK_OK && import_calls == 1);
    /* A missing import is an argument error, not a pass. */
    S.in.import_build = NULL;
    gz_tree_member_check(&S.in, &S.p, &TREE, &v); CHECK(v.check == GZ_CHK_ARGUMENT);
    S.in.import_build = tampering_import; S.in.import_out = NULL;
    gz_tree_member_check(&S.in, &S.p, &TREE, &v); CHECK(v.check == GZ_CHK_ARGUMENT);
    /* C6: one tier holding every tree transaction. */
    scenario(4, 2);
    S.p.n_tiers = 0; EXPECT(GZ_CHK_C6_TIERS, 9);
    S.p.n_tiers = 2; EXPECT(GZ_CHK_C6_TIERS, 9);
    S.p.n_tiers = 1;
    S.p.tier_sizes[0]--; EXPECT(GZ_CHK_C6_TIERS, 9);
    S.p.tier_sizes[0] += 2; EXPECT(GZ_CHK_C6_TIERS, 9);
    S.p.tier_sizes[0]--; OK();
}

/* A provider that fails on demand. */
static int fail_agg_after = -1, fail_valid;
static int f_point_valid(void *ctx, const uint8_t pub[33]) { return !fail_valid && CR.point_valid(ctx, pub); }
static int f_verify(void *ctx, const uint8_t m[32], const uint8_t pub[33], const uint8_t sig[64]) { return CR.verify(ctx, m, pub, sig); }
static int f_agg(void *ctx, const uint8_t first[33], const uint8_t (*rest)[33], size_t n, const uint8_t *merkle, uint8_t in[32], uint8_t out[32])
{
    if (fail_agg_after == 0) return 0;
    if (fail_agg_after > 0) fail_agg_after--;
    return CR.agg_tweak(ctx, first, rest, n, merkle, in, out);
}

static void crypto_and_arguments(void)
{
    gz_tree_crypto_t bad = {0};
    gz_tree_verdict_t v;
    bad.ctx = CR.ctx; bad.point_valid = f_point_valid; bad.verify = f_verify; bad.agg_tweak = f_agg;
    scenario(4, 2);
    S.in.crypto = &bad;
    fail_agg_after = 0; EXPECT(GZ_CHK_CRYPTO, 1);      /* the funding aggregate */
    fail_agg_after = 1; EXPECT(GZ_CHK_CRYPTO, 1);      /* inside the rebuild */
    fail_agg_after = 5; EXPECT(GZ_CHK_CRYPTO, 1);
    fail_agg_after = -1; OK();
    /* A provider that refuses every point refuses the host key of the stored
     * terms first (terms.md 7 step 3, run again by the member check). */
    fail_valid = 1; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_RECORD && v.at == GZ_TERMS_E_HOST_KEY); fail_valid = 0;
    S.in.crypto = NULL; EXPECT(GZ_CHK_ARGUMENT, 1); S.in.crypto = &CR;
    gz_tree_member_check(NULL, &S.p, &TREE, &v); CHECK(v.check == GZ_CHK_ARGUMENT);
    gz_tree_member_check(&S.in, NULL, &TREE, &v); CHECK(v.check == GZ_CHK_ARGUMENT);
    gz_tree_member_check(&S.in, &S.p, NULL, &v); CHECK(v.check == GZ_CHK_ARGUMENT);
    S.in.n_exposures = 1; EXPECT(GZ_CHK_ARGUMENT, 1); S.in.n_exposures = 0;
    S.in.n_unresolved = 1; EXPECT(GZ_CHK_ARGUMENT, 1); S.in.n_unresolved = 0;
    OK();
    /* Every check has a reason and a name. */
    {
        int c;
        for (c = GZ_CHK_OK; c <= GZ_CHK_ARGUMENT; c++) {
            uint16_t r = gz_tree_reason((gz_chk_t)c);
            CHECK(c == GZ_CHK_OK ? r == 0 : (r == 1 || r == 5 || r == 6 || r == 9 || r == 11 || r == 12));
            CHECK(strcmp(gz_chk_name((gz_chk_t)c), "unknown") != 0);
        }
    }
}

/* The identity of a tree (messages.md 7.12) and of a round (7.1). */
static void identities(void)
{
    gz_tree_verdict_t v;
    uint8_t d1[32], d2[32], r1[32], r2[32], hr[32] = {7};
    scenario(4, 2);
    v = run();
    CHECK(v.check == GZ_CHK_OK);
    gz_tree_digest(&TREE, S.outer.chain, S.p.funding_txid, 0, S.p.funding_amount, S.parts, 5, d1);
    CHECK(memcmp(d1, v.tree_digest, 32) == 0);
    gz_tree_round_id(&TREE, S.outer.chain, S.outer.host_key, S.od, S.cd, S.p.funding_txid, 0, S.p.funding_amount, S.parts, 5, hr, r1);
    /* Pinned: the tree digest and round identifier of this 4-member T1
     * proposal (host_random = 07 then zeros). messages.md 7.1 and 7.12 have
     * no vectors yet; these are offered for them. */
    {
        char hx[65];
        tohex(d1, 32, hx); printf("tree digest (T1, 4 members) = %s\n", hx);
        CHECK(eqhex(d1, 32, PIN_TREE_DIGEST));
        tohex(r1, 32, hx); printf("round id    (T1, 4 members) = %s\n", hx);
        CHECK(eqhex(r1, 32, PIN_ROUND_ID));
    }
    hr[0] = 8;
    gz_tree_round_id(&TREE, S.outer.chain, S.outer.host_key, S.od, S.cd, S.p.funding_txid, 0, S.p.funding_amount, S.parts, 5, hr, r2);
    CHECK(memcmp(r1, r2, 32) != 0);                          /* a new attempt, a new identifier */
    /* Contribution keys are in the round identifier but not in the tree digest. */
    key("member %u contribution", 7, S.parts[3].contribution_key);
    gz_tree_digest(&TREE, S.outer.chain, S.p.funding_txid, 0, S.p.funding_amount, S.parts, 5, d2);
    CHECK(memcmp(d1, d2, 32) == 0);
    gz_tree_round_id(&TREE, S.outer.chain, S.outer.host_key, S.od, S.cd, S.p.funding_txid, 0, S.p.funding_amount, S.parts, 5, hr, r1);
    CHECK(memcmp(r1, r2, 32) != 0);
    /* Another member order is another tree. */
    scenario(4, 3);
    {
        gz_tree_participant_t t = S.parts[1];
        S.parts[1] = S.parts[2]; S.parts[2] = t;
        aggregate_script(&S, S.p.funding_script); refund();
        memcpy(S.own_f, S.parts[3].factory_key, 33); memcpy(S.own_c, S.parts[3].contribution_key, 33);
        /* bindings stay valid: they name the lobby and the pair, not the position */
        v = run();
        CHECK(v.check == GZ_CHK_OK);
        CHECK(memcmp(v.tree_digest, d1, 32) != 0);
    }
}

static void c4d_c10_c11_h1(void)
{
    gz_tree_c11_in_t c;
    gz_tree_conditions_t cond;
    uint8_t script[34], other[34], txid[32], op[36];
    uint8_t acked[4] = {1, 1, 1, 1}, signed_ok[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    const uint8_t *prev[1];
    size_t prev_len[1], at;
    gz_tree_h1_in_t h;
    static const uint8_t P2WPKH[22] = {0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    static const uint8_t P2PKH[25] = {0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac};
    uint8_t v0_21[23], p2tr[34], p2a[4] = {0x51, 0x02, 0x4e, 0x73};

    scenario(4, 2);
    /* C4(d): an input of the funding transaction spent by another transaction. */
    memcpy(op, S.ftx + 5, 36);
    tr_sha256d(S.ftx, S.ftx_len, txid);
    {
        uint8_t spender[32] = {9};
        CHECK(gz_tree_c4d_dead(S.ftx, S.ftx_len, op, spender) == 1);
        CHECK(gz_tree_c4d_dead(S.ftx, S.ftx_len, op, txid) == 0);      /* the funding itself */
        op[35] ^= 1;
        CHECK(gz_tree_c4d_dead(S.ftx, S.ftx_len, op, spender) == 0);   /* not one of its inputs */
    }
    {   /* C4(d) with the spent input not the first (review B, B7). */
        static uint8_t t2[200];
        uint8_t spender[32] = {9}, op2[36];
        size_t i;
        memset(op2, 0x42, 32); tr_le32(op2 + 32, 7);
        tr_le32(t2, 2); i = 4; t2[i++] = 2;
        memcpy(t2 + i, S.ftx + 5, 36); i += 36; t2[i++] = 0; tr_le32(t2 + i, 0xfffffffdu); i += 4;
        memcpy(t2 + i, op2, 36); i += 36; t2[i++] = 0; tr_le32(t2 + i, 0xfffffffdu); i += 4;
        t2[i++] = 1; tr_le64(t2 + i, 1000); i += 8; t2[i++] = 34; memcpy(t2 + i, S.p.funding_script, 34); i += 34;
        tr_le32(t2 + i, 0); i += 4;
        CHECK(gz_tree_c4d_dead(t2, i, op2, spender) == 1);
        CHECK(gz_tree_c4d_dead(t2, i, S.ftx + 5, spender) == 1);
        op2[0] ^= 1;
        CHECK(gz_tree_c4d_dead(t2, i, op2, spender) == 0);
    }
    /* C11. */
    memset(&cond, 0, sizeof cond);
    cond.exit = gz_exit_signet();
    cond.funding_deadline_blocks = 36;
    memcpy(script, S.p.funding_script, 34);
    memcpy(other, script, 34); other[20] ^= 1;
    memset(&c, 0, sizeof c);
    c.cond = &cond; c.ack_tip = TIP; c.tip = TIP + 1; c.funding_amount = 802827; c.funding_script = script;
    c.end_height = TIP + 180; c.own_depth = 2; c.holds_whole_tree = 1;
    CHECK(gz_tree_c11(&c) == GZ_C11_WAIT);
    c.tip = TIP + 36; CHECK(gz_tree_c11(&c) == GZ_C11_WAIT);          /* at the deadline: still waiting */
    c.tip = TIP + 37; CHECK(gz_tree_c11(&c) == GZ_C11_ABANDONED);     /* one past it */
    c.seen = 1; c.seen_amount = 802827; c.seen_script = script; c.seen_script_len = 34;
    c.tip = TIP + 30; c.confirmations = 2; CHECK(gz_tree_c11(&c) == GZ_C11_WAIT);   /* B - 1 */
    c.confirmations = 3; c.buried_at = TIP + 30; CHECK(gz_tree_c11(&c) == GZ_C11_LIVE);
    c.buried_at = TIP + 36; c.tip = TIP + 36; CHECK(gz_tree_c11(&c) == GZ_C11_LIVE);          /* buried at the deadline */
    c.seen_amount = 802826; CHECK(gz_tree_c11(&c) == GZ_C11_MISMATCH);
    c.seen_amount = 802828; CHECK(gz_tree_c11(&c) == GZ_C11_MISMATCH);
    c.seen_amount = 802827; c.seen_script = other; CHECK(gz_tree_c11(&c) == GZ_C11_MISMATCH);
    c.seen_script = script; c.seen_script_len = 33; CHECK(gz_tree_c11(&c) == GZ_C11_MISMATCH);
    c.seen_script_len = 34;
    /* On time and live: still live with the tip long past leave_by (TIP + 114);
     * leaving is the exit engine's call from then on (review B, B3). */
    c.buried_at = TIP + 30; c.tip = TIP + 500; CHECK(gz_tree_c11(&c) == GZ_C11_LIVE);
    /* Buried late: live only with the whole tree and leave_by >= buried_at + 1,
     * judged at the burial, not at the tip (review B, B2). leave_by(d = 2) =
     * TIP + 114. Review B's T1 case: buried at TIP + 37, live at TIP + 113
     * and still live at TIP + 114 and later, for the same chain facts. */
    c.buried_at = TIP + 37; c.tip = TIP + 113; CHECK(gz_tree_c11(&c) == GZ_C11_LIVE);
    c.tip = TIP + 114; CHECK(gz_tree_c11(&c) == GZ_C11_LIVE);
    c.tip = TIP + 1000; CHECK(gz_tree_c11(&c) == GZ_C11_LIVE);
    /* The late branch's edge is at the burial: one block of being live left. */
    c.buried_at = TIP + 113; c.tip = TIP + 113; CHECK(gz_tree_c11(&c) == GZ_C11_LIVE);
    c.tip = TIP + 400; CHECK(gz_tree_c11(&c) == GZ_C11_LIVE);
    c.buried_at = TIP + 114; c.tip = TIP + 114; CHECK(gz_tree_c11(&c) == GZ_C11_ABANDONED);
    c.tip = TIP + 400; CHECK(gz_tree_c11(&c) == GZ_C11_ABANDONED);
    c.buried_at = TIP + 37; c.tip = TIP + 113; c.holds_whole_tree = 0; CHECK(gz_tree_c11(&c) == GZ_C11_ABANDONED);
    /* The on-time branch alone (M31): buried at the deadline without the late
     * branch's help is live; one block later it is not. */
    c.holds_whole_tree = 0; c.buried_at = TIP + 36; c.tip = TIP + 36; CHECK(gz_tree_c11(&c) == GZ_C11_LIVE);
    c.buried_at = TIP + 37; c.tip = TIP + 37; CHECK(gz_tree_c11(&c) == GZ_C11_ABANDONED);
    c.holds_whole_tree = 1;
    /* Review A's probe P1 (R1): leave_by(d = 2) = TIP + 114. The ack came at
     * TIP + 100, so the deadline is TIP + 136; funding buried at TIP + 130 is
     * on time, yet leave_by has passed: never live. The same check at the ack
     * (gz_tree_may_ack) refuses to ack. Its boundary: ack at TIP + 74 gives
     * deadline TIP + 110 and 114 >= 110 + 3 + 1. */
    c.ack_tip = TIP + 100; c.buried_at = TIP + 130; c.tip = TIP + 130; CHECK(gz_tree_c11(&c) == GZ_C11_ABANDONED);
    c.ack_tip = TIP + 74; c.buried_at = TIP + 100; c.tip = TIP + 100; CHECK(gz_tree_c11(&c) == GZ_C11_LIVE);
    c.ack_tip = TIP + 75; CHECK(gz_tree_c11(&c) == GZ_C11_ABANDONED);
    CHECK(gz_tree_may_ack(TIP + 180, 2, TIP + 74, &cond) == 1);
    CHECK(gz_tree_may_ack(TIP + 180, 2, TIP + 75, &cond) == 0);
    CHECK(gz_tree_may_ack(TIP + 180, 2, TIP + 100, &cond) == 0);
    CHECK(gz_tree_may_ack(TIP + 180, 1, TIP + 90, &cond) == 1);   /* d = 1: leave_by TIP + 130 */
    CHECK(gz_tree_may_ack(TIP + 180, 1, TIP + 91, &cond) == 0);
    CHECK(gz_tree_may_ack(TIP + 180, 1, TIP + 90, NULL) == 0);
    c.ack_tip = TIP;
    /* Not seen, with a stale confirmation count (M36): never live. */
    c.seen = 0; c.confirmations = 5; c.buried_at = TIP + 10; c.tip = TIP + 20; CHECK(gz_tree_c11(&c) == GZ_C11_WAIT);
    c.tip = TIP + 37; CHECK(gz_tree_c11(&c) == GZ_C11_ABANDONED);
    c.seen = 1;
    /* H1. */
    memset(v0_21, 0, sizeof v0_21); v0_21[1] = 21;
    memcpy(p2tr, script, 34);
    prev[0] = P2WPKH; prev_len[0] = 22;
    memset(&h, 0, sizeof h);
    h.n_members = 4; h.acked = acked; h.n_nodes = 8; h.signed_ok = signed_ok;
    h.proposed_tx = S.ftx; h.proposed_len = S.ftx_len; h.to_sign_tx = S.ftx; h.to_sign_len = S.ftx_len;
    h.prev_scripts = prev; h.prev_script_lens = prev_len; h.n_prev = 1;
    CHECK(gz_tree_h1(&h, &at) == GZ_H1_OK);
    /* Nothing to fund is not "may fund" (review A, R2), and one spent script per input. */
    h.n_members = 0; CHECK(gz_tree_h1(&h, &at) == GZ_H1_EMPTY); h.n_members = 4;
    h.n_nodes = 0; CHECK(gz_tree_h1(&h, &at) == GZ_H1_EMPTY); h.n_nodes = 8;
    h.n_prev = 0; CHECK(gz_tree_h1(&h, &at) == GZ_H1_PREV_COUNT);
    h.n_prev = 2; CHECK(gz_tree_h1(&h, &at) == GZ_H1_PREV_COUNT);
    h.n_prev = 1; CHECK(gz_tree_h1(&h, &at) == GZ_H1_OK);
    acked[3] = 0; CHECK(gz_tree_h1(&h, &at) == GZ_H1_ACK_MISSING && at == 3); acked[3] = 1;
    acked[0] = 0; CHECK(gz_tree_h1(&h, &at) == GZ_H1_ACK_MISSING && at == 0); acked[0] = 1;
    signed_ok[7] = 0; CHECK(gz_tree_h1(&h, &at) == GZ_H1_UNSIGNED && at == 7); signed_ok[7] = 1;
    {
        static uint8_t other_tx[200];
        memcpy(other_tx, S.ftx, S.ftx_len);
        other_tx[S.ftx_len - 5] ^= 1;
        h.to_sign_tx = other_tx; CHECK(gz_tree_h1(&h, &at) == GZ_H1_TX_DIFFERS);
        h.to_sign_len = S.ftx_len - 1; h.to_sign_tx = S.ftx; CHECK(gz_tree_h1(&h, &at) == GZ_H1_TX_DIFFERS);
        h.to_sign_len = S.ftx_len;
        /* a scriptSig makes the txid malleable */
        memcpy(other_tx, S.ftx, S.ftx_len);
        memmove(other_tx + 42, other_tx + 41, S.ftx_len - 41);
        other_tx[41] = 1; other_tx[42] = 0x51;
        h.proposed_tx = other_tx; h.to_sign_tx = other_tx; h.proposed_len = h.to_sign_len = S.ftx_len + 1;
        CHECK(gz_tree_h1(&h, &at) == GZ_H1_NOT_SEGWIT);
        h.proposed_tx = h.to_sign_tx = S.ftx; h.proposed_len = h.to_sign_len = S.ftx_len;
    }
    prev[0] = P2PKH; prev_len[0] = 25; CHECK(gz_tree_h1(&h, &at) == GZ_H1_NOT_SEGWIT && at == 0);
    prev[0] = v0_21; prev_len[0] = 23; CHECK(gz_tree_h1(&h, &at) == GZ_H1_NOT_SEGWIT);
    {
        uint8_t nop[34];
        memcpy(nop, p2tr, 34); nop[0] = 0x61;   /* OP_NOP is no witness version */
        prev[0] = nop; prev_len[0] = 34; CHECK(gz_tree_h1(&h, &at) == GZ_H1_NOT_SEGWIT);
        nop[0] = 0x60; CHECK(gz_tree_h1(&h, &at) == GZ_H1_OK);   /* OP_16: version 16 */
        nop[0] = 0x50; CHECK(gz_tree_h1(&h, &at) == GZ_H1_NOT_SEGWIT);
    }
    {   /* The witness program's one push (review B, B7): a push byte other than
         * the program's length, both ways; programs of 2 to 40 bytes only. */
        uint8_t w[44];
        memset(w, 7, sizeof w);
        prev[0] = w;
        w[0] = 0x00; w[1] = 0x21; prev_len[0] = 22; CHECK(gz_tree_h1(&h, &at) == GZ_H1_NOT_SEGWIT);
        w[1] = 0x14; CHECK(gz_tree_h1(&h, &at) == GZ_H1_OK);
        w[0] = 0x51; w[1] = 0xff; prev_len[0] = 34; CHECK(gz_tree_h1(&h, &at) == GZ_H1_NOT_SEGWIT);
        w[1] = 0x1f; CHECK(gz_tree_h1(&h, &at) == GZ_H1_NOT_SEGWIT);
        w[1] = 0x20; CHECK(gz_tree_h1(&h, &at) == GZ_H1_OK);
        w[1] = 40; prev_len[0] = 42; CHECK(gz_tree_h1(&h, &at) == GZ_H1_OK);
        w[1] = 41; prev_len[0] = 43; CHECK(gz_tree_h1(&h, &at) == GZ_H1_NOT_SEGWIT);
        w[1] = 1; prev_len[0] = 3; CHECK(gz_tree_h1(&h, &at) == GZ_H1_NOT_SEGWIT);
    }
    prev[0] = p2tr; prev_len[0] = 34; CHECK(gz_tree_h1(&h, &at) == GZ_H1_OK);
    prev[0] = p2a; prev_len[0] = 4; CHECK(gz_tree_h1(&h, &at) == GZ_H1_OK);
    h.proposed_tx = h.to_sign_tx = (const uint8_t *)"x"; h.proposed_len = h.to_sign_len = 1;
    CHECK(gz_tree_h1(&h, &at) == GZ_H1_TX_INVALID);
    CHECK(gz_tree_h1(NULL, &at) == GZ_H1_ARGUMENT);
    /* C10 alone. */
    {
        gz_tree_outpoint_t f, u;
        memset(&f, 0, sizeof f); memset(&u, 0, sizeof u);
        CHECK(gz_tree_c10_busy(&f, &u, 1) == 1);
        u.vout = 1; CHECK(gz_tree_c10_busy(&f, &u, 1) == 0);
        CHECK(gz_tree_c10_busy(&f, NULL, 0) == 0);
    }
}

/* Review B, B1: the member check alone refuses terms that were only parsed,
 * never received. Each record is out of bounds in one way, encoded, signed by
 * the host and stored exactly as a member would store it, so only the
 * re-check of the bounds can refuse it; it is refused before any key is
 * parsed or any tree built. Then the stored bytes must give exactly the
 * structs and digests the rest of the check uses. */
static void terms_rechecked(void)
{
    static const struct { int which; gz_terms_err_t want; const char *what; } CASES[] = {
        {0, GZ_TERMS_E_CHAIN, "mainnet chain"},
        {1, GZ_TERMS_E_FEERATE, "tree_feerate 0"},
        {2, GZ_TERMS_E_LIFETIME, "lifetime 0"},
        {3, GZ_TERMS_E_WINDDOWN, "wind-down 60,000"},
        {4, GZ_TERMS_E_STEP_TIMEOUT, "step timeout 2^32 - 1 ms"},
        {5, GZ_TERMS_E_PROFILE, "profile 9, switches 0xff"},
        {6, GZ_TERMS_E_CHANNEL, "channel 10^16 sat"},
        {7, GZ_TERMS_E_RANGE, "a range of [9,000, 10]"},
    };
    gz_tree_verdict_t v;
    size_t k;
    for (k = 0; k < sizeof CASES / sizeof CASES[0]; k++) {
        gz_terms_outer_t parsed;
        scenario(4, 2);
        switch (CASES[k].which) {
        case 0: unhex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000", S.outer.chain, 32); break;
        case 1: S.outer.tree_feerate = 0; break;
        case 2: S.outer.lifetime_blocks = 0; S.outer.winddown_blocks = 180; break;
        case 3: S.outer.winddown_blocks = 60000; break;
        case 4: S.outer.step_timeout_ms = 0xffffffffu; S.outer.signing_budget_ms = 0xffffffffu; break;
        case 5: S.outer.profile = 9; S.outer.switches = 0xff; break;
        case 6: S.outer.channel_sat = 10000000000000000ull; break;
        case 7: S.outer.adj[2].min = 9000; S.outer.adj[2].max = 10; break;
        }
        reseal();
        /* what the member stored is exactly what parsing its bytes gives */
        CHECK(gz_terms_parse_outer(S.ob, S.on, &parsed) == GZ_TERMS_OK && gz_terms_outer_equal(&parsed, &S.outer));
        CHECK(gz_terms_check_outer(&parsed, &SLICE1) == CASES[k].want);
        v = run();
        CHECK(v.check == GZ_CHK_C8A_TERMS_BOUNDS && v.reason == 9 && v.at == (int32_t)CASES[k].want);
        if (v.check != GZ_CHK_C8A_TERMS_BOUNDS || v.at != (int32_t)CASES[k].want)
            printf("  %s: %s at %d\n", CASES[k].what, gz_chk_name(v.check), (int)v.at);
    }
    /* The frozen values (section 5): one out of its range, at its edge; a
     * missing value; a type the outer lacks; types out of order; version 0. */
    scenario(4, 2);
    S.cur.val[2].value = 99; reseal(); v = run();
    CHECK(v.check == GZ_CHK_C8A_FROZEN_VALUES && v.reason == 9 && v.at == GZ_TERMS_E_ADJ_VALUE);
    S.cur.val[2].value = 100; reseal(); OK();
    S.cur.val[2].value = 2500; reseal(); OK();
    S.cur.val[2].value = 2501; reseal(); v = run(); CHECK(v.check == GZ_CHK_C8A_FROZEN_VALUES && v.at == GZ_TERMS_E_ADJ_VALUE);
    scenario(4, 2);
    S.cur.n_values = 2; reseal(); v = run(); CHECK(v.check == GZ_CHK_C8A_FROZEN_VALUES && v.at == GZ_TERMS_E_ADJ_SET);
    scenario(4, 2);
    S.cur.val[1].type = 65; reseal(); v = run(); CHECK(v.check == GZ_CHK_C8A_FROZEN_VALUES && v.at == GZ_TERMS_E_ADJ_SET);
    scenario(4, 2);
    S.cur.val[0] = S.cur.val[1]; S.cur.val[1].type = 64; S.cur.val[1].value = 500;   /* 66 then 64 */
    v = run(); CHECK(v.check == GZ_CHK_C8A_FROZEN_VALUES && v.at == GZ_TERMS_E_ADJ_SET);
    scenario(4, 2);
    S.cur.version = 0; S.p.terms_version = 0; S.in.ready_version = 0; reseal(); v = run();
    CHECK(v.check == GZ_CHK_C8A_FROZEN_VALUES && v.at == GZ_TERMS_E_VERSION);
    scenario(4, 2);
    S.cur.version = 2; S.p.terms_version = 2; S.in.ready_version = 2; reseal(); OK();
    /* other valid terms with a record of another length (an alias): signed */
    scenario(4, 2);
    S.outer.alias_len = 4; memcpy(S.outer.alias, "T1 a", 4); reseal(); OK();
    /* A struct that is not what its stored bytes (and so its digest) decode
     * to: valid terms either way, but not the ones the bindings and the
     * member's ready named. */
    scenario(4, 2);
    S.outer.channel_sat = 100001; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_DIFFER && v.reason == 1);
    scenario(4, 2);
    S.outer.lobby_salt[0] ^= 1; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_DIFFER);
    scenario(4, 2);
    S.outer.n_unknown_odd = 1; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_DIFFER);
    scenario(4, 2);
    S.cur.val[0].value = 501; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_DIFFER);
    scenario(4, 2);
    {   /* stored bytes of another record (another salt), validly signed: not
         * the outer digest the bindings and the member's ready name. */
        static gz_terms_outer_t o2;
        static uint8_t b2[GZ_TERMS_OUTER_MAX];
        uint8_t d2[32], s2[64];
        size_t n2;
        o2 = S.outer; o2.lobby_salt[0] ^= 1;
        n2 = gz_terms_encode_outer(&o2, b2, sizeof b2);
        gz_terms_outer_digest(b2, n2, d2); test_sign("host", d2, s2);
        S.in.outer_rec = b2; S.in.outer_rec_len = n2; S.in.outer_sig = s2;
        v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_RECORD && v.reason == 1 && v.at == GZ_TERMS_E_SCOPE);
        S.in.outer_rec = S.ob; S.in.outer_rec_len = S.on; S.in.outer_sig = S.osig;
        OK();
    }
    /* The stored records themselves: steps 1 to 6 again. */
    scenario(4, 2);
    S.osig[5] ^= 1; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_RECORD && v.at == GZ_TERMS_E_OUTER_SIG); S.osig[5] ^= 1;
    S.csig[5] ^= 1; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_RECORD && v.at == GZ_TERMS_E_CURRENT_SIG); S.csig[5] ^= 1;
    key("someone %u", 1, S.pinned); v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_RECORD && v.at == GZ_TERMS_E_PINNED_KEY);
    test_pub("host", S.pinned); OK();
    S.in.outer_rec_len--; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_RECORD && v.at == GZ_TERMS_E_TRUNCATED); S.in.outer_rec_len++;
    S.ob[S.on - 1] ^= 1; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_RECORD && v.at == GZ_TERMS_E_SCOPE); S.ob[S.on - 1] ^= 1;
    S.cb[S.cn - 1] ^= 1; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_RECORD && v.at == GZ_TERMS_E_CURRENT_SIG); S.cb[S.cn - 1] ^= 1;
    {   /* another frozen record, validly signed, than the digest C8a checked */
        gz_terms_current_t c2 = S.cur;
        uint8_t b2[GZ_TERMS_CURRENT_MAX], d2[32], s2[64];
        size_t n2;
        c2.val[0].value = 501;
        n2 = gz_terms_encode_current(&c2, b2, sizeof b2);
        gz_terms_current_digest(b2, n2, d2); test_sign("host", d2, s2);
        S.in.frozen_rec = b2; S.in.frozen_rec_len = n2; S.in.frozen_sig = s2;
        v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_RECORD && v.at == -1);
        S.in.frozen_rec = S.cb; S.in.frozen_rec_len = S.cn; S.in.frozen_sig = S.csig;
    }
    OK();
    /* Missing records, signatures, key or policy: an argument error. */
    S.in.outer_rec = NULL; EXPECT(GZ_CHK_ARGUMENT, 1); S.in.outer_rec = S.ob;
    S.in.frozen_sig = NULL; EXPECT(GZ_CHK_ARGUMENT, 1); S.in.frozen_sig = S.csig;
    S.in.host_pinned_key = NULL; EXPECT(GZ_CHK_ARGUMENT, 1); S.in.host_pinned_key = S.pinned;
    S.in.policy = NULL; EXPECT(GZ_CHK_ARGUMENT, 1); S.in.policy = &SLICE1;
    OK();
    /* A struct counting past its arrays is refused, not read. */
    scenario(4, 2);
    S.outer.n_adj = 200; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_BOUNDS && v.at == GZ_TERMS_E_RANGE);
    scenario(4, 2);
    S.outer.n_shapes = 251; v = run(); CHECK(v.check == GZ_CHK_C8A_TERMS_BOUNDS && v.at == GZ_TERMS_E_SHAPE_ENCODING);
    scenario(4, 2);
    S.cur.n_values = 200; v = run(); CHECK(v.check == GZ_CHK_C8A_FROZEN_VALUES && v.at == GZ_TERMS_E_ADJ_SET);
}

/* Every check's name, against its enum value (the names are a list in enum order). */
static void names(void)
{
    static const struct { gz_chk_t c; const char *n; } NAMES[] = {
        {GZ_CHK_OK, "ok"},
        {GZ_CHK_C8A_PURPOSE, "c8a_purpose"},
        {GZ_CHK_C8A_VERSION, "c8a_version"},
        {GZ_CHK_C8A_DIGEST, "c8a_digest"},
        {GZ_CHK_C8A_READY_OUTER, "c8a_ready_outer"},
        {GZ_CHK_C8A_TERMS_BOUNDS, "c8a_terms_bounds"},
        {GZ_CHK_C8A_FROZEN_VALUES, "c8a_frozen_values"},
        {GZ_CHK_C8A_TERMS_RECORD, "c8a_terms_record"},
        {GZ_CHK_C8A_TERMS_DIFFER, "c8a_terms_differ"},
        {GZ_CHK_C1_PARTICIPANTS, "c1_participants"},
        {GZ_CHK_C1_DUPLICATE_KEY, "c1_duplicate_key"},
        {GZ_CHK_C1_BAD_KEY, "c1_bad_key"},
        {GZ_CHK_C1_HOST_KEY, "c1_host_key"},
        {GZ_CHK_C1_FUNDING_TX, "c1_funding_tx"},
        {GZ_CHK_C1_FUNDING_TXID, "c1_funding_txid"},
        {GZ_CHK_C1_FUNDING_VOUT, "c1_funding_vout"},
        {GZ_CHK_C1_FUNDING_AMOUNT, "c1_funding_amount"},
        {GZ_CHK_C1_FUNDING_SCRIPT_LEN, "c1_funding_script_len"},
        {GZ_CHK_C1_FUNDING_SCRIPT, "c1_funding_script"},
        {GZ_CHK_C1_NOT_AGGREGATE, "c1_not_aggregate"},
        {GZ_CHK_C1_IMPORT_DIFFERS, "c1_import_differs"},
        {GZ_CHK_C1_IMPORT_FAILED, "c1_import_failed"},
        {GZ_CHK_BINDING, "binding"},
        {GZ_CHK_C7_NOT_MY_KEY, "c7_not_my_key"},
        {GZ_CHK_C10_BUSY, "c10_busy"},
        {GZ_CHK_C7_OTHER_TREE, "c7_other_tree"},
        {GZ_CHK_C8_PLACEMENT, "c8_placement"},
        {GZ_CHK_C8_ANCHORS, "c8_anchors"},
        {GZ_CHK_C8_K, "c8_k"},
        {GZ_CHK_C8_LAYER_STEP, "c8_layer_step"},
        {GZ_CHK_C8_LAYER_STATES, "c8_layer_states"},
        {GZ_CHK_C8_HASHES, "c8_hashes"},
        {GZ_CHK_C8_DISTRIBUTION, "c8_distribution"},
        {GZ_CHK_C8_DEADLINES, "c8_deadlines"},
        {GZ_CHK_C8_MEMBERS_TERMS, "c8_members_terms"},
        {GZ_CHK_C8_MEMBERS_OWN, "c8_members_own"},
        {GZ_CHK_C8_NO_SHAPE, "c8_no_shape"},
        {GZ_CHK_C8_SHAPE, "c8_shape"},
        {GZ_CHK_C8_FIXED_LEVELS, "c8_fixed_levels"},
        {GZ_CHK_C8_FEE_RULE, "c8_fee_rule"},
        {GZ_CHK_C8_FEE_CEILING, "c8_fee_ceiling"},
        {GZ_CHK_C8_FUNDING_RULE, "c8_funding_rule"},
        {GZ_CHK_C8_LSTOCK_DELAY, "c8_lstock_delay"},
        {GZ_CHK_C8_END_ZERO, "c8_end_zero"},
        {GZ_CHK_C8_END_WINDOW, "c8_end_window"},
        {GZ_CHK_C8_END_LOCKTIME, "c8_end_locktime"},
        {GZ_CHK_C8_EXIT_TIME, "c8_exit_time"},
        {GZ_CHK_C8_UNDERFUNDED, "c8_underfunded"},
        {GZ_CHK_C8_DUST, "c8_dust"},
        {GZ_CHK_C8_IMPORT_MINIMUM, "c8_import_minimum"},
        {GZ_CHK_C8_LEAF_KIND, "c8_leaf_kind"},
        {GZ_CHK_C8_OWN_LEAF, "c8_own_leaf"},
        {GZ_CHK_C8_CHANNEL_TERMS, "c8_channel_terms"},
        {GZ_CHK_C8_CHANNEL_OWN, "c8_channel_own"},
        {GZ_CHK_C6_TIERS, "c6_tiers"},
        {GZ_CHK_C5_UNKNOWN_PATH, "c5_unknown_path"},
        {GZ_CHK_CRYPTO, "crypto"},
        {GZ_CHK_ARGUMENT, "argument"},
    };
    size_t i;
    for (i = 0; i < sizeof NAMES / sizeof NAMES[0]; i++) CHECK(strcmp(gz_chk_name(NAMES[i].c), NAMES[i].n) == 0);
}

int main(void)
{
    gz_tree_secp_crypto(test_ctx(), &CR);
    honest();
    c8a();
    terms_rechecked();
    c1_participants();
    c7_c10();
    c8_fixed();
    c8_members();
    c8_lstock();
    c8_shape_fee_funding();
    c8_heights();
    c1_funding();
    c1_import_leaves_tiers();
    crypto_and_arguments();
    identities();
    c4d_c10_c11_h1();
    names();
    return check_done();
}
