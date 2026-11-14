/* Vectors T1 to T7 (terms.md 11) and M1, M2 (messages.md 11), byte for byte,
 * and the encoding tests of messages.md 12 (1 to 11). The terms records are
 * core/tree's (gazpacho/terms.h): their bounds, UTF-8, shape and size tests
 * are in tests/tree; here T1 to T7 are read through it as the lobby reads
 * them, under the lobby's policy, and the lobby's own comparison (the
 * deciding term) is checked. */
#include "../check.h"
#include "lobby_test.h"
#include "../../core/lobby/lobby_internal.h"
#include <stdlib.h>

static uint8_t t1[512], t2[128], t3[128];
static size_t t1n, t2n, t3n;
static gz_terms_outer_t o;
static gz_terms_current_t c;
static uint8_t od[32];

static int hexeq(const uint8_t *b, size_t n, const char *hex)
{
    uint8_t want[70000];
    size_t wn = lt_unhex(hex, want, sizeof want);
    return wn == n && memcmp(b, want, n) == 0;
}

static int outer_ok(const uint8_t *b, size_t n)
{
    static gz_terms_outer_t x;
    return lt_outer(b, n, &x);
}

/* T1 changed by `f`, re-encoded: 1 if the lobby's policy accepts it. */
static int t1_with(void (*f)(gz_terms_outer_t *))
{
    static gz_terms_outer_t x;
    uint8_t buf[4200];
    size_t n;
    x = o;
    f(&x);
    n = gz_terms_encode_outer(&x, buf, sizeof buf);
    return n > 0 && outer_ok(buf, n);
}
static void carry_over(gz_terms_outer_t *x) { x->on_shortfall = 1; }
static void testnet4(gz_terms_outer_t *x)
{
    static const uint8_t g[32] = {
        0x43, 0xf0, 0x8b, 0xda, 0xb0, 0x50, 0xe3, 0x5b, 0x56, 0x7c, 0x86, 0x4b, 0x91, 0xf4, 0x7f, 0x50,
        0xae, 0x72, 0x5a, 0xe2, 0xde, 0x53, 0xbc, 0xfb, 0xba, 0xf2, 0x84, 0xda, 0x00, 0x00, 0x00, 0x00};
    memcpy(x->chain, g, 32);
}
static void profile3(gz_terms_outer_t *x) { x->profile = 3; }
static void switches1(gz_terms_outer_t *x) { x->switches = 1; }
static void unfundable(gz_terms_outer_t *x) { x->channel_sat = 2100000000000000ull; }
static void minimum_257(gz_terms_outer_t *x) { x->target = 300; x->minimum = 257; x->shapes[1].max_members = 300; }
static void nothing(gz_terms_outer_t *x) { (void)x; }

static void test_terms(lt_signer_t *host)
{
    gz_lobby_crypto_t cr = lt_crypto(host);
    uint8_t buf[4200], cd[32], sig[64], tmp[600];
    size_t n;
    gz_terms_current_t c3;
    gz_lobby_conditions_t cond;
    gz_lobby_handoff_t ho;
    uint8_t term;
    int i;
    static gz_terms_outer_t o2;

    t1n = lt_unhex(LT_T1, t1, sizeof t1);
    t2n = lt_unhex(LT_T2, t2, sizeof t2);
    t3n = lt_unhex(LT_T3, t3, sizeof t3);
    CHECK(t1n == 225 && t2n == 70 && t3n == 70);
    CHECK(memcmp(host->key[1].pub, (const uint8_t[]){0x02, 0xb8, 0xdd, 0x73}, 4) == 0);

    /* T1 */
    CHECK(lt_outer(t1, t1n, &o));
    CHECK(o.target == 8 && o.minimum == 3 && o.deadline == 1794441600ull && o.n_shapes == 2);
    CHECK(o.ready_window_ms == 30000 && o.signing_budget_ms == 600000 && o.step_timeout_ms == 60000);
    CHECK(o.channel_sat == 100000 && o.tree_feerate == 100 && o.lifetime_blocks == 144 && o.winddown_blocks == 36);
    CHECK(o.n_adj == 3 && o.adj[0].type == 64 && o.adj[0].max == 2000 && o.adj[2].min == 100);
    n = gz_terms_encode_outer(&o, buf, sizeof buf);
    CHECK(n == t1n && memcmp(buf, t1, n) == 0);
    gz_terms_outer_digest(t1, t1n, od);
    CHECK(hexeq(od, 32, "75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2"));
    CHECK(cr.sign(cr.ctx, GZ_LOBBY_KEY_HOST, od, sig) == 1);
    CHECK(hexeq(sig, 64, "0bb885ba5dbf0f21fda26a90c68d6736f71619b72583d8691581319efafdfeb5"
                         "db7c87c85def6708994c5b78dc93be56fd9dd9f670147f353d74787d922bf54d"));

    /* The lobby's policy is core/tree's Slice 1 column: signet only (testnet4
     * waits for the tree stream, docs/notes/lobby.md), Standard, cancel on
     * shortfall (review A, t02), switches 0, and a tree fundable for every
     * member count (review A, F4). */
    CHECK(t1_with(nothing) && !t1_with(carry_over) && !t1_with(testnet4) && !t1_with(profile3) && !t1_with(switches1));
    CHECK(!t1_with(unfundable) && !t1_with(minimum_257));

    /* T2, T3 */
    CHECK(lt_current(t2, t2n, &o, od, &c));
    CHECK(c.version == 1 && c.n_values == 3 && c.val[0].value == 500 && c.val[1].value == 1000);
    n = gz_terms_encode_current(&c, buf, sizeof buf);
    CHECK(n == t2n && memcmp(buf, t2, n) == 0);
    gz_terms_current_digest(t2, t2n, cd);
    CHECK(hexeq(cd, 32, "d1db6ddfd5a2c12ae197036f285457ae6ceaf468c2a47fb71691dde4b1153942"));
    CHECK(cr.sign(cr.ctx, GZ_LOBBY_KEY_HOST, cd, sig) == 1);
    CHECK(hexeq(sig, 64, "a739c225be7e2842c2e7925c12b8e824751ba1d019e31c9f16342cf78f02633f"
                         "f00d0ef1ff618b18456f472818758017a0e682b211d553d00edf3e2d1b1c140d"));
    CHECK(lt_current(t3, t3n, &o, od, &c3) && c3.version == 2 && c3.val[0].value == 1500);
    gz_terms_current_digest(t3, t3n, cd);
    CHECK(hexeq(cd, 32, "ba3bccb892b8b65321956753d973bfba1bbdcbf2e5c68e28052683a713b2b7be"));
    CHECK(cr.sign(cr.ctx, GZ_LOBBY_KEY_HOST, cd, sig) == 1);
    CHECK(hexeq(sig, 64, "7a692794d41ad38a845e6533b2499b197a3d63d86f196d274a14d4aa33478bf3"
                         "f563f2503def1c0b1bf53e096cd2e7be0f45f10c30066f5a6be5d98ff53fff5b"));
    {   /* the decoder the engines use on their own saved records */
        gz_terms_outer_t *t = &o2;
        gz_terms_current_t cv;
        uint8_t d1[32], d2[32];
        CHECK(gz_la_decode_terms(t1, t1n, t2, t2n, t, d1, &cv, d2) && memcmp(d1, od, 32) == 0);
        CHECK(!gz_la_decode_terms(t1, t1n, t2, t2n - 1, t, d1, &cv, d2));
        memcpy(tmp, t2, t2n); tmp[5] ^= 1;                 /* names another outer digest */
        CHECK(!gz_la_decode_terms(t1, t1n, tmp, t2n, t, d1, &cv, d2));
    }

    /* T4: record 10's length written fd 00 02. */
    n = 0;
    for (i = 0; i < (int)t1n; i++) {
        if (i == 90) { CHECK(t1[90] == 0x0a && t1[91] == 0x02); }
        if (i == 91) { tmp[n++] = 0xfd; tmp[n++] = 0x00; tmp[n++] = 0x02; continue; }
        tmp[n++] = t1[i];
    }
    CHECK(n == t1n + 2 && memcmp(tmp, t1, 92) != 0 && memcmp(tmp, t1, 91) == 0);
    CHECK(!outer_ok(tmp, n));
    gz_terms_outer_digest(tmp, n, cd);
    CHECK(cd[0] == 0xad && cd[1] == 0xb3 && cd[2] == 0xa7 && cd[3] == 0x33 && cd[31] == 0x4d);

    /* T5 */
    n = lt_unhex("022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4"
                 "24f2040400000003400800000000000007d1420800000000000003e844080000"
                 "0000000003e8", tmp, sizeof tmp);
    CHECK(n == 70 && !lt_current(tmp, n, &o, od, &c3));
    tmp[31 + 18] = 0xd0;                                  /* 2,000: inside, accepted */
    CHECK(lt_current(tmp, n, &o, od, &c3));

    /* T6, through core/tree's comparison, with the lobby's deciding term */
    cond = lt_cond_fits();
    LT_ADJ(cond, 0) = 1000;
    CHECK(gz_lobby_classify(&o, &c, &cond, &term) == GZ_FIT_NOW && term == 64);
    CHECK(!gz_lobby_ready_ok(GZ_FIT_NOW, &cond));
    cond.current_only = 1;
    CHECK(gz_lobby_ready_ok(GZ_FIT_NOW, &cond) && gz_lobby_ready_ok(GZ_FIT_YES, &cond) && !gz_lobby_ready_ok(GZ_FIT_NO, &cond));
    lt_current(t3, t3n, &o, od, &c3);
    CHECK(gz_lobby_classify(&o, &c3, &cond, &term) == GZ_FIT_NO && term == 64);
    cond = lt_cond_fits();
    CHECK(gz_lobby_classify(&o, &c3, &cond, &term) == GZ_FIT_YES && term == 0);
    /* The deciding term is the smallest type whose limit alone decides. */
    cond = lt_cond_fits(); cond.limits.profiles = 1u << 3;
    CHECK(gz_lobby_classify(&o, &c, &cond, &term) == GZ_FIT_NO && term == 8);
    cond = lt_cond_fits(); cond.limits.min_members = 4;              /* the terms' minimum is 3 */
    CHECK(gz_lobby_classify(&o, &c, &cond, &term) == GZ_FIT_NO && term == 12);
    cond.limits.min_members = 3;
    CHECK(gz_lobby_classify(&o, &c, &cond, &term) == GZ_FIT_YES);
    cond = lt_cond_fits(); cond.limits.max_lifetime = 143; cond.limits.min_channel_sat = 100001;
    CHECK(gz_lobby_classify(&o, &c, &cond, &term) == GZ_FIT_NO && term == 26);
    cond.limits.max_lifetime = 0;                                      /* 0: no limit (core/tree) */
    CHECK(gz_lobby_classify(&o, &c, &cond, &term) == GZ_FIT_NO && term == 30);
    cond = lt_cond_fits(); cond.limits.max_tree_feerate = 99; LT_ADJ(cond, 2) = 999;
    CHECK(gz_lobby_classify(&o, &c, &cond, &term) == GZ_FIT_NO && term == 32);
    cond = lt_cond_fits(); LT_ADJ(cond, 2) = 999; LT_ADJ(cond, 1) = 999;   /* 1,000 and 1,000: 66 fails first */
    CHECK(gz_lobby_classify(&o, &c, &cond, &term) == GZ_FIT_NO && term == 66);
    cond = lt_cond_fits(); LT_ADJ(cond, 1) = 0;                       /* listed 0 is a real bound */
    CHECK(gz_lobby_classify(&o, &c, &cond, &term) == GZ_FIT_NO && term == 66);
    cond = lt_cond_fits(); cond.limits.n_max = 2;                       /* type 68 unnamed: no limit */
    CHECK(gz_lobby_classify(&o, &c, &cond, &term) == GZ_FIT_YES);
    cond = lt_cond_fits(); LT_ADJ(cond, 2) = 1000; LT_ADJ(cond, 1) = 1000;   /* 68 within now only */
    CHECK(gz_lobby_classify(&o, &c, &cond, &term) == GZ_FIT_NOW && term == 68);

    /* T7: the shape the hand-off carries, from core/tree's parameters */
    for (i = 3; i <= 16; i++) {
        memset(&ho, 0, sizeof ho);
        gz_la_shape(&o, (uint16_t)i, &ho);
        CHECK(ho.k == 1 && ho.tree_anchors == 1 && ho.layer_step == 144 && ho.layer_states == 4);
        if (i <= 4) CHECK(ho.n_levels == 1 && ho.levels[0] == 3 && ho.fixed_levels == 2);
        else CHECK(ho.n_levels == 2 && ho.levels[0] == 4 && ho.levels[1] == 3 && ho.fixed_levels == (i <= 8 ? 2 : 3));
    }
    gz_la_shape(&o, 17, &ho);
    CHECK(ho.n_levels == 0);
    gz_la_shape(&o, 2, &ho);
    CHECK(ho.n_levels == 0);
}

static void test_m1(lt_signer_t *member)
{
    gz_lobby_crypto_t cr = lt_crypto(member);
    gz_lobby_enc_t e;
    gz_lobby_msg_t m;
    uint8_t buf[400], b[32], sig[64], cd[32], h[32];
    size_t n;
    gz_terms_current_digest(t2, t2n, cd);
    gz_lobby_binding(od, member->key[3].pub, member->key[2].pub, b);
    CHECK(hexeq(b, 32, "47cc4207f628d147d528abc4dfab2c393e208dfcfa550789540bddd09259007e"));
    cr.sign(cr.ctx, GZ_LOBBY_KEY_FACTORY, b, sig);
    CHECK(hexeq(sig, 64, "64c9b7016f2484c6d4e162a02e701bc3cad8f7741a2ab2f07a2ad32fac0d0932"
                         "bb7e4286df722cbe5147a72425fe9a58fd4afe37357f843ee6d0eb1aa9946cea"));
    cr.sign(cr.ctx, GZ_LOBBY_KEY_CONTRIBUTION, b, sig);
    CHECK(hexeq(sig, 64, "20e17a88512a7899a72ecfa56bc456a12a71012cc2a1f2b5b77bc2c4143b3eb8"
                         "676168a973998b2fdb71d2d8284b9a9e0adf8f2927815ae965398cf4c8184813"));
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_READY, od);
    gz_lobby_enc_record(&e, 2, od, 32);
    gz_lobby_enc_u32(&e, 4, 1);
    gz_lobby_enc_record(&e, 6, cd, 32);
    n = gz_lobby_enc_sign(&e, &cr, GZ_LOBBY_KEY_CONTRIBUTION);
    CHECK(n == 180);
    CHECK(hexeq(buf, n, "ce37677a6601001675e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2"
                        "022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2"
                        "040400000001"
                        "0620d1db6ddfd5a2c12ae197036f285457ae6ceaf468c2a47fb71691dde4b1153942"
                        "f0407eb07e7116d893db0aa57ca3c88fd1b7c67aeb5a0772923c08a4f10350197cbc"
                        "08c19ce8d566df618ab0df88d9773f5089c63b83d4fc99636a5ba7f433762627"));
    CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK && m.kind == GZ_KIND_READY && m.version == 1);
    CHECK(!m.has_check_id && !m.has_min_members && m.sig == buf + n - 64);
    gz_lobby_msg_hash(buf, &m, h);
    CHECK(hexeq(h, 32, "683a9673360b942f37224c92dfeb58765fc9085e14bae4c6120b46c5be42f8d0"));
    CHECK(lt_verify(NULL, member->key[2].pub, h, m.sig));
}

static void test_m2(void)
{
    static uint8_t body[76800], p0[65200], p1[12000], reasm[GZ_PART_MAX_BODY];
    static gz_part_reasm_t r;
    gz_lobby_msg_t m0, m1;
    uint8_t scope[32], sc[32];
    const uint8_t *out;
    size_t n0, n1, ol, i;
    uint16_t k;
    for (i = 0; i < sizeof body; i++) body[i] = (uint8_t)i;
    memset(scope, 0x11, 32);
    CHECK(gz_part_count(sizeof body) == 2);
    CHECK(gz_part_count(65495) == 0 && gz_part_count(65496) == 2);
    CHECK(gz_part_count(GZ_PART_MAX_BODY) == 17 && gz_part_count(GZ_PART_MAX_BODY + 1) == 0);
    n0 = gz_part_build(68, scope, body, sizeof body, 0, p0, sizeof p0);
    n1 = gz_part_build(68, scope, body, sizeof body, 1, p1, sizeof p1);
    CHECK(n0 == 65096 && n1 == 11896);
    CHECK(gz_lobby_decode(p0, n0, &m0) == GZ_DEC_OK && gz_lobby_decode(p1, n1, &m1) == GZ_DEC_OK);
    CHECK(hexeq(m0.transfer_id, 32, "fcb2c91358d5559e25feace2ed8a1562324ec95032f4c514435b5bd2f152a668"));
    CHECK(m0.count == 2 && m1.index == 1 && m1.data_len == 11800);
    /* reverse order, a duplicate, then completion */
    gz_part_reasm_init(&r, reasm, sizeof reasm);
    CHECK(gz_part_feed(&r, &m1, &k, sc, &out, &ol) == 0);
    CHECK(gz_part_feed(&r, &m1, &k, sc, &out, &ol) == 0);
    CHECK(gz_part_feed(&r, &m0, &k, sc, &out, &ol) == 1);
    CHECK(k == 68 && ol == sizeof body && memcmp(out, body, ol) == 0 && memcmp(sc, scope, 32) == 0);
    /* same index, other data: refused */
    CHECK(gz_part_feed(&r, &m1, &k, sc, &out, &ol) == 0);
    p1[n1 - 1] ^= 1;
    gz_lobby_decode(p1, n1, &m1);
    CHECK(gz_part_feed(&r, &m1, &k, sc, &out, &ol) == -1);
    /* wrong transfer id at completion: refused */
    gz_part_reasm_init(&r, reasm, sizeof reasm);
    CHECK(gz_part_feed(&r, &m1, &k, sc, &out, &ol) == 0);
    CHECK(gz_part_feed(&r, &m0, &k, sc, &out, &ol) == -1);
    /* inconsistent count, index >= count, short middle part, inner kind 2 */
    gz_lobby_decode(p0, n0, &m0);
    p0[40 + 34 + 4 + 6 + 4 + 3] = 3;                    /* count = 3 */
    CHECK(gz_lobby_decode(p0, n0, &m0) == GZ_DEC_REFUSE);
    p0[40 + 34 + 4 + 6 + 4 + 3] = 2;
    p0[40 + 34 + 4 + 6 + 3] = 2;                        /* index = 2 */
    CHECK(gz_lobby_decode(p0, n0, &m0) == GZ_DEC_REFUSE);
    p0[40 + 34 + 4 + 6 + 3] = 0;
    p0[40 + 34 + 3] = 2;                                /* inner kind 2 */
    CHECK(gz_lobby_decode(p0, n0, &m0) == GZ_DEC_REFUSE);
    p0[40 + 34 + 3] = 68;
    CHECK(gz_lobby_decode(p0, n0 - 1, &m0) == GZ_DEC_REFUSE);   /* short data, length past end */
    CHECK(gz_lobby_decode(p0, n0, &m0) == GZ_DEC_OK);
    CHECK(gz_part_build(68, scope, body, 65495, 0, p0, sizeof p0) == 0);   /* fits: never split */
    {   /* rule 4: another transfer replaces the open one; a part of another scope is another transfer */
        static uint8_t body2[76800], q0[65200], q1[12000], small[70000];
        static gz_part_reasm_t r2;
        gz_lobby_msg_t a0, b0, b1;
        uint8_t sc2[32];
        size_t qn0, qn1;
        for (i = 0; i < sizeof body2; i++) body2[i] = (uint8_t)(i * 3);
        n0 = gz_part_build(68, scope, body, sizeof body, 0, p0, sizeof p0);
        qn0 = gz_part_build(68, scope, body2, sizeof body2, 0, q0, sizeof q0);
        qn1 = gz_part_build(68, scope, body2, sizeof body2, 1, q1, sizeof q1);
        gz_lobby_decode(p0, n0, &a0); gz_lobby_decode(q0, qn0, &b0); gz_lobby_decode(q1, qn1, &b1);
        gz_part_reasm_init(&r2, reasm, sizeof reasm);
        CHECK(gz_part_feed(&r2, &a0, &k, sc, &out, &ol) == 0);
        CHECK(gz_part_feed(&r2, &b1, &k, sc, &out, &ol) == 0);       /* A dropped */
        CHECK(gz_part_feed(&r2, &b0, &k, sc, &out, &ol) == 1 && ol == sizeof body2 && memcmp(out, body2, ol) == 0);
        CHECK(gz_part_feed(&r2, &b0, &k, sc, &out, &ol) == 0);       /* a new transfer after completion */
        memset(sc2, 0x22, 32);
        qn1 = gz_part_build(68, sc2, body2, sizeof body2, 1, q1, sizeof q1);
        gz_lobby_decode(q1, qn1, &b1);
        CHECK(gz_part_feed(&r2, &b1, &k, sc, &out, &ol) == 0);       /* another scope: the open one dropped */
        CHECK(gz_part_feed(&r2, &b0, &k, sc, &out, &ol) == 0);       /* so this one starts again, not completes */
        gz_part_reasm_init(&r2, small, sizeof small);
        CHECK(gz_part_feed(&r2, &b0, &k, sc, &out, &ol) == -1);      /* more than the buffer holds */
        b0.kind = GZ_KIND_READY;
        gz_part_reasm_init(&r2, reasm, sizeof reasm);
        CHECK(gz_part_feed(&r2, &b0, &k, sc, &out, &ol) == -1);      /* not a part */
    }
}

/* messages.md test 3 to 8 on M1-shaped messages. */
static void test_envelope(lt_signer_t *member)
{
    gz_lobby_crypto_t cr = lt_crypto(member);
    gz_lobby_enc_t e;
    gz_lobby_msg_t m;
    static uint8_t buf[70000], pad[70000];
    uint8_t x[400];
    size_t n;
    uint8_t cd[32];
    gz_terms_current_digest(t2, t2n, cd);
#define BUILD(extra) do { gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_READY, od); \
    gz_lobby_enc_record(&e, 2, od, 32); gz_lobby_enc_u32(&e, 4, 1); \
    gz_lobby_enc_record(&e, 6, cd, 32); extra; n = gz_lobby_enc_sign(&e, &cr, 2); } while (0)
    BUILD(gz_lobby_enc_record(&e, 9, (const uint8_t *)"x", 1));
    CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK);          /* unknown odd: skipped */
    {
        uint8_t h[32];
        gz_lobby_msg_hash(buf, &m, h);
        CHECK(lt_verify(NULL, member->key[2].pub, h, m.sig));
        buf[n - 64 - 2 - 1] ^= 1;                               /* the odd record changed */
        gz_lobby_decode(buf, n, &m);
        gz_lobby_msg_hash(buf, &m, h);
        CHECK(!lt_verify(NULL, member->key[2].pub, h, m.sig));
    }
    BUILD(gz_lobby_enc_record(&e, 10, (const uint8_t *)"x", 1));
    CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_REFUSE);      /* unknown even */
    BUILD(gz_lobby_enc_u16(&e, 11, 5));
    CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK && m.has_min_members && m.min_members == 5);
    BUILD((void)0);
    memcpy(x, buf, n);
    x[n] = 0xf1; x[n + 1] = 0;                                  /* a record after 240 */
    CHECK(gz_lobby_decode(x, n + 2, &m) == GZ_DEC_REFUSE);
    CHECK(gz_lobby_decode(buf, n - 66, &m) == GZ_DEC_REFUSE);   /* 240 missing */
    memcpy(x, buf, n); x[40 + 34 + 1] = 5;                       /* version one byte long */
    CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_REFUSE);
    memcpy(x, buf, n); x[41] = 0x21;                             /* outer digest 33 */
    CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_REFUSE);
    memcpy(x, buf, n); x[40] = 4; x[74] = 2;                     /* types out of order */
    CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_REFUSE);
    memcpy(x, buf, n); x[45] ^= 1;                               /* outer digest != scope */
    CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_REFUSE);
    {   /* non-minimal BigSize length */
        size_t k = 0;
        memcpy(x, buf, 40); k = 40;
        x[k++] = 2; x[k++] = 0xfd; x[k++] = 0; x[k++] = 32; memcpy(x + k, od, 32); k += 32;
        memcpy(x + k, buf + 74, n - 74); k += n - 74;
        CHECK(gz_lobby_decode(x, k, &m) == GZ_DEC_REFUSE);
    }
    /* kinds and protocol */
    memcpy(x, buf, n); x[7] = 23;  CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_IGNORE);
    memcpy(x, buf, n); x[7] = 36;  CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_REFUSE);
    memcpy(x, buf, n); x[7] = 0;   CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_REFUSE);
    memcpy(x, buf, n); x[7] = 130; CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_IGNORE);
    memcpy(x, buf, n); x[7] = 64;  CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_OTHER);
    memcpy(x, buf, n); x[7] = 81;  CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_OTHER);
    memcpy(x, buf, n); x[5] = 2;   CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_BADTAG);
    memcpy(x, buf, n); x[1] = 0x39; CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_IGNORE);
    memcpy(x, buf, n); memset(x + 8, 0, 32); CHECK(gz_lobby_decode(x, n, &m) == GZ_DEC_REFUSE);
    CHECK(gz_lobby_decode(buf, 39, &m) == GZ_DEC_REFUSE);
    /* exactly 65,535 bytes accepted; the encoder never builds more */
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_HELLO, od);
    gz_lobby_enc_record(&e, 1, pad, 65535 - 40 - 4);
    n = gz_lobby_enc_done(&e);
    CHECK(n == 65535 && gz_lobby_decode(buf, n, &m) == GZ_DEC_OK);
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_HELLO, od);
    gz_lobby_enc_record(&e, 1, pad, 65535 - 40 - 3);
    CHECK(gz_lobby_enc_done(&e) == 0);
    CHECK(gz_lobby_decode(buf, 65536, &m) == GZ_DEC_REFUSE);
}

static void test_bigsize(void)
{
    static const struct { const char *hex; int ok; uint64_t v; } t[] = {
        {"00", 1, 0}, {"fc", 1, 252}, {"fd00fd", 1, 253}, {"fd00fc", 0, 0}, {"fdffff", 1, 65535},
        {"fe00010000", 1, 65536}, {"fe0000ffff", 0, 0}, {"feffffffff", 1, 4294967295ull},
        {"ff0000000100000000", 1, 4294967296ull}, {"ff00000000ffffffff", 0, 0},
        {"ffffffffffffffffff", 1, 0xffffffffffffffffull}, {"fd00", 0, 0}, {"fe000100", 0, 0},
        {"ff00000001000000", 0, 0}, {"", 0, 0},
    };
    size_t i;
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        uint8_t b[16], o2[16];
        size_t n = lt_unhex(t[i].hex, b, sizeof b), at = 0;
        uint64_t v = 7;
        int ok = gz_lw_bigsize(b, n, &at, &v);
        CHECK(ok == t[i].ok);
        if (ok) CHECK(v == t[i].v && at == n && gz_lw_put_bigsize(o2, v) == n && memcmp(o2, b, n) == 0);
        else CHECK(at == 0);
    }
}

/* Every lobby kind, with each optional record present and absent, decodes to
 * the values it was built with (messages.md test 2). */
static void test_kinds(lt_signer_t *member)
{
    gz_lobby_crypto_t cr = lt_crypto(member);
    gz_lobby_enc_t e;
    gz_lobby_msg_t m;
    uint8_t buf[700], a[64], k32[32];
    size_t n;
    int opt;
    memset(a, 0x33, sizeof a);
    memset(k32, 0x44, 32);
    for (opt = 0; opt < 2; opt++) {
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_JOIN, od);
        gz_lobby_enc_record(&e, 2, member->key[3].pub, 33);
        gz_lobby_enc_record(&e, 4, a, 64);
        gz_lobby_enc_record(&e, 6, a, 64);
        if (opt) gz_lobby_enc_record(&e, 7, (const uint8_t *)"Ana", 3);
        n = gz_lobby_enc_done(&e);
        CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK && m.kind == GZ_KIND_JOIN && memcmp(m.factory_key, member->key[3].pub, 33) == 0);
        CHECK(m.bind_by_factory == buf + 40 + 35 + 2 && (opt ? m.display_name_len == 3 && memcmp(m.display_name, "Ana", 3) == 0 : m.display_name == NULL));
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_UNREADY, od);
        if (opt) gz_lobby_enc_u16(&e, 1, 2);
        n = gz_lobby_enc_done(&e);
        CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK && m.has_reason == opt && m.reason == (opt ? 2 : 0));
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_LEAVE, od);
        if (opt) gz_lobby_enc_u16(&e, 1, 3);
        n = gz_lobby_enc_done(&e);
        CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK && m.kind == GZ_KIND_LEAVE && m.has_reason == opt && m.reason == (opt ? 3 : 0));
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_LOBBY_STATUS, od);
        gz_lobby_enc_u8(&e, 2, 3); gz_lobby_enc_u8(&e, 4, 4); gz_lobby_enc_u32(&e, 6, 77);
        gz_lobby_enc_u16(&e, 8, 300); gz_lobby_enc_u16(&e, 10, 299);
        if (opt) gz_lobby_enc_u16(&e, 13, 12);
        n = gz_lobby_enc_done(&e);
        CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK && m.lobby_state == 3 && m.seat_state == 4 && m.version == 77);
        CHECK(m.joined == 300 && m.ready == 299 && m.has_reason == opt && m.reason == (opt ? 12 : 0) && !m.sig);
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_READY, od);
        gz_lobby_enc_record(&e, 2, od, 32); gz_lobby_enc_u32(&e, 4, 9); gz_lobby_enc_record(&e, 6, k32, 32);
        if (opt) { gz_lobby_enc_record(&e, 8, a, 32); gz_lobby_enc_u16(&e, 11, 40); }
        n = gz_lobby_enc_sign(&e, &cr, 2);
        CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK && m.version == 9 && memcmp(m.current_digest, k32, 32) == 0);
        CHECK(m.has_check_id == opt && m.has_min_members == opt && m.min_members == (opt ? 40 : 0) && m.signed_len == n - 2 - 66);
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_READY_CHECK, od);
        gz_lobby_enc_record(&e, 2, a, 32); gz_lobby_enc_u32(&e, 4, 5); gz_lobby_enc_record(&e, 6, k32, 32);
        gz_lobby_enc_u32(&e, 8, 123456);
        if (opt) gz_lobby_enc_record(&e, 9, a, 5);
        n = gz_lobby_enc_sign(&e, &cr, 2);
        CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK && m.version == 5 && m.answer_within_ms == 123456 && memcmp(m.check_id, a, 32) == 0);
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_START, od);
        gz_lobby_enc_record(&e, 2, a, 32); gz_lobby_enc_u8(&e, 4, 2); gz_lobby_enc_u16(&e, 6, 513);
        n = gz_lobby_enc_sign(&e, &cr, 2);
        CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK && m.role == 2 && m.signers == 513 && m.has_check_id);
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_CANCEL, od);
        gz_lobby_enc_u16(&e, 2, 3);
        n = gz_lobby_enc_sign(&e, &cr, 2);
        CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK && m.reason == 3 && m.sig == buf + n - 64);
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_HELLO, opt ? od : (const uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        n = gz_lobby_enc_done(&e);
        CHECK(n == 40 && gz_lobby_decode(buf, n, &m) == GZ_DEC_OK && m.kind == GZ_KIND_HELLO);
    }
    /* the shortest inputs: not ours, a broken tag, too short for an envelope */
    {
        static const struct { const char *hex; int code; } s[] = {
            {"", GZ_DEC_IGNORE}, {"ce", GZ_DEC_IGNORE}, {"ce37", GZ_DEC_BADTAG}, {"ce37677a66", GZ_DEC_BADTAG},
            {"ce37677a6601", GZ_DEC_REFUSE}, {"ce36677a6601", GZ_DEC_IGNORE},
        };
        size_t k;
        for (k = 0; k < sizeof s / sizeof s[0]; k++) {
            uint8_t *h = malloc(8);
            size_t hn = lt_unhex(s[k].hex, h, 8);
            CHECK(gz_lobby_decode(h, hn, &m) == s[k].code);
            free(h);
        }
    }
    /* discovery kinds 128 to 159 are ignored; 160 is an unknown even kind */
    {
        static const struct { uint16_t kind; int code; } d[] = {
            {126, GZ_DEC_REFUSE}, {127, GZ_DEC_IGNORE}, {128, GZ_DEC_IGNORE}, {158, GZ_DEC_IGNORE},
            {159, GZ_DEC_IGNORE}, {160, GZ_DEC_REFUSE}, {82, GZ_DEC_REFUSE}, {83, GZ_DEC_IGNORE}, {62, GZ_DEC_REFUSE},
        };
        size_t k;
        for (k = 0; k < sizeof d / sizeof d[0]; k++) {
            gz_lobby_enc_start(&e, buf, sizeof buf, d[k].kind, od);
            n = gz_lobby_enc_done(&e);
            CHECK(gz_lobby_decode(buf, n, &m) == d[k].code);
        }
    }
    /* a part without its transfer id, or without any one required record */
    {
        static uint8_t body[70000], p0[66000];
        size_t k, pn;
        for (k = 0; k < sizeof body; k++) body[k] = (uint8_t)k;
        pn = gz_part_build(68, od, body, sizeof body, 1, p0, sizeof p0);
        CHECK(gz_lobby_decode(p0, pn, &m) == GZ_DEC_OK);
        memmove(p0 + 40, p0 + 40 + 34, pn - 40 - 34);                /* drop record 2 */
        CHECK(gz_lobby_decode(p0, pn - 34, &m) == GZ_DEC_REFUSE);
    }
    /* the encoder at exactly its buffer's size, and one byte short; a signature it cannot make */
    {
        uint8_t small[200];
        lt_signer_t ns = *member;
        gz_lobby_crypto_t cn = lt_crypto(&ns);
        gz_lobby_enc_start(&e, small, 40, GZ_KIND_HELLO, od);
        CHECK(gz_lobby_enc_done(&e) == 40);
        gz_lobby_enc_start(&e, small, 39, GZ_KIND_HELLO, od);
        CHECK(gz_lobby_enc_done(&e) == 0);
        gz_lobby_enc_start(&e, small, 44, GZ_KIND_UNREADY, od);
        gz_lobby_enc_u16(&e, 1, 2);
        CHECK(gz_lobby_enc_done(&e) == 44);
        gz_lobby_enc_start(&e, small, 43, GZ_KIND_UNREADY, od);
        gz_lobby_enc_u16(&e, 1, 2);
        CHECK(gz_lobby_enc_done(&e) == 0 && gz_lobby_enc_sign(&e, &cr, 2) == 0);   /* nothing signed after an overflow */
        gz_lobby_enc_start(&e, small, 110, GZ_KIND_CANCEL, od);
        gz_lobby_enc_u16(&e, 2, 1);
        CHECK(gz_lobby_enc_sign(&e, &cr, 2) == 110);
        gz_lobby_enc_start(&e, small, 109, GZ_KIND_CANCEL, od);
        gz_lobby_enc_u16(&e, 2, 1);
        CHECK(gz_lobby_enc_sign(&e, &cr, 2) == 0);
        ns.fail_sign = 1;
        gz_lobby_enc_start(&e, small, sizeof small, GZ_KIND_CANCEL, od);
        gz_lobby_enc_u16(&e, 2, 1);
        CHECK(gz_lobby_enc_sign(&e, &cn, 2) == 0);
    }
    /* the BOLT 1 warning, byte for byte */
    {
        uint8_t w[64];
        size_t wn = gz_lobby_warning("abc", w, sizeof w);
        CHECK(wn == 39 && w[0] == 0 && w[1] == 1 && w[34] == 0 && w[35] == 3 && memcmp(w + 36, "abc", 3) == 0);
        for (wn = 2; wn < 34; wn++) CHECK(w[wn] == 0);
        CHECK(gz_lobby_warning("abc", w, 39) == 39 && gz_lobby_warning("abc", w, 38) == 0);
        CHECK(gz_lobby_warning("", w, 36) == 36);
    }
    /* parts: a total one byte past a whole part, and the largest body */
    {
        static uint8_t body[GZ_PART_MAX_BODY], pp[66000];
        size_t pn;
        uint16_t cnt = gz_part_count(130001);
        CHECK(cnt == 3);
        pn = gz_part_build(68, od, body, 130001, 2, pp, sizeof pp);
        CHECK(pn > 0 && gz_lobby_decode(pp, pn, &m) == GZ_DEC_OK && m.count == 3 && m.data_len == 1);
        pn = gz_part_build(68, od, body, GZ_PART_MAX_BODY, 16, pp, sizeof pp);
        CHECK(pn > 0 && gz_lobby_decode(pp, pn, &m) == GZ_DEC_OK && m.count == 17 && m.index == 16);
        CHECK(gz_part_build(68, od, body, GZ_PART_MAX_BODY, 17, pp, sizeof pp) == 0);
        CHECK(gz_part_build(GZ_KIND_PART, od, body, 130001, 0, pp, sizeof pp) == 0);
    }
    /* a scope of zeros only in hello; one nonzero byte anywhere makes a scope */
    {
        uint8_t sc[32];
        size_t k;
        memset(sc, 0, 32);
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_UNREADY, sc);
        n = gz_lobby_enc_done(&e);
        CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_REFUSE);
        for (k = 0; k < 32; k += 31) {
            memset(sc, 0, 32);
            sc[k] = 1;
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_UNREADY, sc);
            n = gz_lobby_enc_done(&e);
            CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_OK);
        }
    }
    /* the display name: 1 to 32 bytes */
    {
        size_t L;
        uint8_t nm[40];
        memset(nm, 'n', sizeof nm);
        for (L = 0; L <= 33; L += (L == 1 ? 31 : 1)) {
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_JOIN, od);
            gz_lobby_enc_record(&e, 2, member->key[3].pub, 33);
            gz_lobby_enc_record(&e, 4, a, 64);
            gz_lobby_enc_record(&e, 6, a, 64);
            gz_lobby_enc_record(&e, 7, nm, L);
            n = gz_lobby_enc_done(&e);
            CHECK((gz_lobby_decode(buf, n, &m) == GZ_DEC_OK) == (L >= 1 && L <= 32));
        }
    }
    /* required records, each missing in turn, from a signed kind */
    {
        int miss;
        for (miss = 0; miss < 3; miss++) {
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_START, od);
            if (miss != 0) gz_lobby_enc_record(&e, 2, a, 32);
            if (miss != 1) gz_lobby_enc_u8(&e, 4, 1);
            if (miss != 2) gz_lobby_enc_u16(&e, 6, 4);
            n = gz_lobby_enc_sign(&e, &cr, 2);
            CHECK(gz_lobby_decode(buf, n, &m) == GZ_DEC_REFUSE);
        }
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    lt_signer_t host, member;
    memset(&host, 0, sizeof host);
    memset(&member, 0, sizeof member);
    lt_key(&host.key[1], "host");
    lt_key(&member.key[2], "member 1 contribution");
    lt_key(&member.key[3], "member 1 factory");
    test_terms(&host);
    test_m1(&member);
    test_m2();
    test_envelope(&member);
    test_bigsize();
    test_kinds(&member);
    return check_done();
}
