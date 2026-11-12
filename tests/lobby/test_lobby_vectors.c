/* Vectors T1 to T7 (terms.md 11) and M1, M2 (messages.md 11), byte for byte,
 * and the encoding tests of terms.md 12 and messages.md 12 (1 to 11). */
#include "../check.h"
#include "lobby_test.h"
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
    return gz_terms_outer_decode(b, n, &x);
}

static void test_terms(lt_signer_t *host)
{
    gz_lobby_crypto_t cr = lt_crypto(host);
    uint8_t buf[4200], cd[32], sig[64], tmp[600];
    size_t n;
    gz_terms_current_t c3;
    gz_lobby_conditions_t cond;
    uint8_t term, lv[8], nl, d;
    int i;
    static gz_terms_outer_t o2;

    t1n = lt_unhex(LT_T1, t1, sizeof t1);
    t2n = lt_unhex(LT_T2, t2, sizeof t2);
    t3n = lt_unhex(LT_T3, t3, sizeof t3);
    CHECK(t1n == 225 && t2n == 70 && t3n == 70);
    CHECK(memcmp(host->key[1].pub, (const uint8_t[]){0x02, 0xb8, 0xdd, 0x73}, 4) == 0);

    /* T1 */
    CHECK(gz_terms_outer_decode(t1, t1n, &o));
    CHECK(gz_terms_slice1_ok(&o));
    CHECK(o.target == 8 && o.minimum == 3 && o.deadline == 1794441600ull && o.n_shapes == 2);
    CHECK(o.ready_window_ms == 30000 && o.signing_budget_ms == 600000 && o.step_timeout_ms == 60000);
    CHECK(o.channel_sat == 100000 && o.tree_feerate == 100 && o.lifetime_blocks == 144 && o.winddown_blocks == 36);
    CHECK(o.n_adj == 3 && o.adj[0].type == 64 && o.adj[0].max == 2000 && o.adj[2].min == 100);
    n = gz_terms_outer_encode(&o, buf, sizeof buf);
    CHECK(n == t1n && memcmp(buf, t1, n) == 0);
    gz_terms_outer_digest(t1, t1n, od);
    CHECK(hexeq(od, 32, "75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2"));
    CHECK(cr.sign(cr.ctx, GZ_LOBBY_KEY_HOST, od, sig) == 1);
    CHECK(hexeq(sig, 64, "0bb885ba5dbf0f21fda26a90c68d6736f71619b72583d8691581319efafdfeb5"
                         "db7c87c85def6708994c5b78dc93be56fd9dd9f670147f353d74787d922bf54d"));

    /* T2, T3 */
    CHECK(gz_terms_current_decode(t2, t2n, &o, od, &c));
    CHECK(c.version == 1 && c.n_adj == 3 && c.adj_value[0] == 500 && c.adj_value[1] == 1000);
    n = gz_terms_current_encode(&c, &o, buf, sizeof buf);
    CHECK(n == t2n && memcmp(buf, t2, n) == 0);
    gz_terms_current_digest(t2, t2n, cd);
    CHECK(hexeq(cd, 32, "d1db6ddfd5a2c12ae197036f285457ae6ceaf468c2a47fb71691dde4b1153942"));
    CHECK(cr.sign(cr.ctx, GZ_LOBBY_KEY_HOST, cd, sig) == 1);
    CHECK(hexeq(sig, 64, "a739c225be7e2842c2e7925c12b8e824751ba1d019e31c9f16342cf78f02633f"
                         "f00d0ef1ff618b18456f472818758017a0e682b211d553d00edf3e2d1b1c140d"));
    CHECK(gz_terms_current_decode(t3, t3n, &o, od, &c3) && c3.version == 2 && c3.adj_value[0] == 1500);
    gz_terms_current_digest(t3, t3n, cd);
    CHECK(hexeq(cd, 32, "ba3bccb892b8b65321956753d973bfba1bbdcbf2e5c68e28052683a713b2b7be"));
    CHECK(cr.sign(cr.ctx, GZ_LOBBY_KEY_HOST, cd, sig) == 1);
    CHECK(hexeq(sig, 64, "7a692794d41ad38a845e6533b2499b197a3d63d86f196d274a14d4aa33478bf3"
                         "f563f2503def1c0b1bf53e096cd2e7be0f45f10c30066f5a6be5d98ff53fff5b"));

    /* T4: record 10's length written fd 00 02. */
    n = 0;
    for (i = 0; i < (int)t1n; i++) {
        if (i == 90) { CHECK(t1[90] == 0x0a && t1[91] == 0x02); }
        if (i == 91) { tmp[n++] = 0xfd; tmp[n++] = 0x00; tmp[n++] = 0x02; continue; }
        tmp[n++] = t1[i];
    }
    CHECK(n == t1n + 2 && memcmp(tmp, t1, 92) != 0 && memcmp(tmp, t1, 91) == 0);
    CHECK(!gz_terms_outer_decode(tmp, n, &o2));
    gz_terms_outer_digest(tmp, n, cd);
    CHECK(cd[0] == 0xad && cd[1] == 0xb3 && cd[2] == 0xa7 && cd[3] == 0x33 && cd[31] == 0x4d);

    /* T5 */
    n = lt_unhex("022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4"
                 "24f2040400000003400800000000000007d1420800000000000003e844080000"
                 "0000000003e8", tmp, sizeof tmp);
    CHECK(n == 70 && !gz_terms_current_decode(tmp, n, &o, od, &c3));
    tmp[31 + 18] = 0xd0;                                  /* 2,000: inside, accepted */
    CHECK(gz_terms_current_decode(tmp, n, &o, od, &c3));

    /* T6 */
    cond = lt_cond_fits();
    cond.adj_max[0] = 1000;
    CHECK(gz_terms_classify(&o, &c, &cond, &term) == GZ_FIT_NOW && term == 64);
    CHECK(!gz_terms_ready_ok(GZ_FIT_NOW, &cond));
    cond.current_only = 1;
    CHECK(gz_terms_ready_ok(GZ_FIT_NOW, &cond));
    gz_terms_current_decode(t3, t3n, &o, od, &c3);
    CHECK(gz_terms_classify(&o, &c3, &cond, &term) == GZ_FIT_NO && term == 64);
    cond = lt_cond_fits();
    CHECK(gz_terms_classify(&o, &c3, &cond, &term) == GZ_FIT_YES && term == 0);

    /* T7 */
    for (i = 3; i <= 16; i++) {
        CHECK(gz_terms_shape_for(&o, (uint16_t)i, lv, &nl, &d));
        if (i <= 4) CHECK(nl == 1 && lv[0] == 3 && d == 2);
        else CHECK(nl == 2 && lv[0] == 4 && lv[1] == 3 && d == (i <= 8 ? 2 : 3));
    }
    CHECK(!gz_terms_shape_for(&o, 17, lv, &nl, &d));
    /* Draft 1's entry 0004 01 04 (level arity [4]) is refused at n = 3. */
    o2 = o;
    o2.n_shapes = 1;
    o2.shapes[0].max_members = 16; o2.shapes[0].n_interior = 0; o2.shapes[0].leaf_kind = 3;
    n = gz_terms_outer_encode(&o2, buf, sizeof buf);
    CHECK(n > 0 && outer_ok(buf, n));
    {   /* hand-write the draft-1 entry, which the encoder's struct cannot hold */
        size_t k;
        uint8_t raw[300];
        size_t at = 0;
        for (k = 0; k < n; ) {
            size_t vl = buf[k + 1];
            if (buf[k] == 24) {
                raw[at++] = 24; raw[at++] = 4;
                raw[at++] = 0; raw[at++] = 16; raw[at++] = 1; raw[at++] = 4;
            } else { memcpy(raw + at, buf + k, 2 + vl); at += 2 + vl; }
            k += 2 + vl;
        }
        CHECK(!outer_ok(raw, at));
    }
}

/* terms.md test 2, 3 and 5: each bound at its edge and one past it. */
static void test_terms_bounds(void)
{
    static gz_terms_outer_t x;
    uint8_t buf[4200], big[1100];
    size_t n;
    struct { int field; uint64_t ok, bad; } e[] = {
        {10, 1000, 1001}, {10, 8, 2}, {12, 3, 2}, {12, 8, 9}, {18, 1000, 999}, {18, 600000, 600001},
        {20, 600000, 59999}, {20, 86400000, 86400001}, {22, 60000, 59999}, {26, 52560, 52561},
        {26, 1, 0}, {28, 52560, 52561}, {30, 546, 545}, {30, 2100000000000000ull, 2100000000000001ull},
        {32, 1, 0}, {32, 1000000, 1000001}, {34, 7, 8}, {8, 4, 5}, {8, 1, 0}, {16, 1, 2},
        {64, 2100000000000000ull, 2100000000000001ull}, {66, 4294967295ull, 4294967296ull},
    };
    size_t i;
    for (i = 0; i < sizeof e / sizeof e[0]; i++) {
        int pass;
        for (pass = 0; pass < 2; pass++) {
            uint64_t v = pass ? e[i].bad : e[i].ok;
            x = o;
            switch (e[i].field) {
            case 8: x.profile = (uint8_t)v; break;
            case 10: x.target = (uint16_t)v; if (x.minimum > x.target) x.minimum = 3; break;
            case 12: x.minimum = (uint16_t)v; break;
            case 16: x.on_shortfall = (uint8_t)v; break;
            case 18: x.ready_window_ms = (uint32_t)v; break;
            case 20: x.signing_budget_ms = (uint32_t)v; break;
            case 22: x.step_timeout_ms = (uint32_t)v; break;
            case 26: x.lifetime_blocks = (uint32_t)v; break;
            case 28: x.winddown_blocks = (uint32_t)v; break;
            case 30: x.channel_sat = v; break;
            case 32: x.tree_feerate = (uint32_t)v; break;
            case 34: x.switches = (uint8_t)v; break;
            case 64: x.adj[0].max = v; break;
            case 66: x.adj[1].max = v; break;
            }
            if (e[i].field == 10 && v > 16) { x.shapes[1].max_members = (uint16_t)(v > 1000 ? 1000 : v); }
            n = gz_terms_outer_encode(&x, buf, sizeof buf);
            CHECK(n > 0);
            if (n > 0 && gz_terms_outer_decode(buf, n, &x) != !pass)
                printf("  bound: field %d value %llu\n", e[i].field, (unsigned long long)v);
            CHECK(n > 0 && outer_ok(buf, n) == !pass);
        }
    }
    /* min > max; shapes not increasing; last below target; 7 interior; width 3 and 16; leaf 2. */
    x = o; x.adj[1].min = 1001; n = gz_terms_outer_encode(&x, buf, sizeof buf); CHECK(!outer_ok(buf, n));
    x = o; x.shapes[1].max_members = 4; n = gz_terms_outer_encode(&x, buf, sizeof buf); CHECK(!outer_ok(buf, n));
    x = o; x.shapes[1].max_members = 7; n = gz_terms_outer_encode(&x, buf, sizeof buf); CHECK(!outer_ok(buf, n));
    x = o; x.shapes[1].max_members = 8; n = gz_terms_outer_encode(&x, buf, sizeof buf); CHECK(outer_ok(buf, n));
    x = o; x.shapes[1].interior[0] = 3; n = gz_terms_outer_encode(&x, buf, sizeof buf); CHECK(!outer_ok(buf, n));
    x = o; x.shapes[1].interior[0] = 15; n = gz_terms_outer_encode(&x, buf, sizeof buf); CHECK(!outer_ok(buf, n));
    x = o; x.n_shapes = 3; x.shapes[2] = x.shapes[1]; x.shapes[2].max_members = 40; x.shapes[2].interior[0] = 15;
    n = gz_terms_outer_encode(&x, buf, sizeof buf); CHECK(outer_ok(buf, n));   /* 15 wide, n 17..40 */
    x = o; x.shapes[1].interior[0] = 16; n = gz_terms_outer_encode(&x, buf, sizeof buf); CHECK(!outer_ok(buf, n));
    x = o; x.shapes[1].leaf_kind = 2; n = gz_terms_outer_encode(&x, buf, sizeof buf); CHECK(!outer_ok(buf, n));
    x = o; x.n_shapes = 3; x.shapes[1].max_members = 19; x.shapes[2] = x.shapes[1];
    x.shapes[2].max_members = 1000; x.shapes[2].n_interior = 2; x.shapes[2].interior[1] = 4;
    n = gz_terms_outer_encode(&x, buf, sizeof buf); CHECK(outer_ok(buf, n));   /* [4,4,3] from 20 */
    x.shapes[1].max_members = 18; n = gz_terms_outer_encode(&x, buf, sizeof buf); CHECK(!outer_ok(buf, n));
    x.shapes[1].n_interior = 7; CHECK(gz_terms_outer_encode(&x, buf, sizeof buf) == 0);
    /* Unknown even types refused, odd skipped (and in the digest). */
    {
        uint8_t r[300];
        uint8_t d1[32], d2[32];
        size_t k = 0;
        memcpy(r, t1, 2 + 32); k = 34;                 /* chain */
        r[k++] = 3; r[k++] = 2; r[k++] = 'h'; r[k++] = 'i';
        memcpy(r + k, t1 + 34, t1n - 34); k += t1n - 34;
        CHECK(outer_ok(r, k));
        gz_terms_outer_digest(r, k, d1); gz_terms_outer_digest(t1, t1n, d2);
        CHECK(memcmp(d1, d2, 32) != 0);
        r[36] = 0xff; CHECK(!outer_ok(r, k));          /* alias, invalid UTF-8 */
        r[36] = 0xc3; r[37] = 0xa9; CHECK(outer_ok(r, k));
        r[36] = 0xc0; r[37] = 0xa9; CHECK(!outer_ok(r, k));   /* overlong */
        r[34] = 5; CHECK(!outer_ok(r, k));             /* 5 before 4: out of order */
        memcpy(r, t1, t1n);                            /* unknown odd 63 before 64: skipped */
        k = t1n - 54;
        CHECK(r[k] == 64);
        r[k] = 63; r[k + 1] = 1; r[k + 2] = 0;
        memcpy(r + k + 3, t1 + t1n - 54, 54);
        CHECK(outer_ok(r, t1n + 3));
        r[k] = 62; CHECK(!outer_ok(r, t1n + 3));       /* unknown even below 64 */
        r[k] = 36; CHECK(!outer_ok(r, t1n + 3));       /* reserved even, invalid in draft 2 */
        memcpy(r, t1, t1n);
        r[t1n] = 70; r[t1n + 1] = 16; memset(r + t1n + 2, 0, 16);   /* even 70: refused */
        CHECK(!outer_ok(r, t1n + 18));
        r[t1n] = 0x81; r[t1n + 1] = 0;                 /* 129 */
        CHECK(!outer_ok(r, t1n + 2));
        r[t1n] = 71;                                   /* odd 71: kept as a range */
        r[t1n + 1] = 16;
        CHECK(outer_ok(r, t1n + 18));
        r[t1n] = 33; CHECK(!outer_ok(r, t1n + 18));    /* order */
        r[t1n] = 68; CHECK(!outer_ok(r, t1n + 18));    /* repeated */
        CHECK(!outer_ok(t1, t1n - 1));                 /* truncated */
    }
    /* Size limits. */
    memset(big, 0, sizeof big);
    CHECK(!gz_terms_current_decode(big, 1025, &o, od, &c));
    {
        static uint8_t huge[4200];
        size_t k = 0;
        gz_terms_current_t cc;
        memcpy(huge, t1, t1n); k = t1n;
        CHECK(!outer_ok(huge, 4097));
        (void)k;
        /* current: missing one type, extra type, version 0, wrong outer digest */
        memcpy(big, t2, t2n);
        CHECK(!gz_terms_current_decode(big, t2n - 10, &o, od, &cc));
        big[t2n] = 70; big[t2n + 1] = 8; memset(big + t2n + 2, 0, 8);
        CHECK(!gz_terms_current_decode(big, t2n + 10, &o, od, &cc));
        memcpy(big, t2, t2n); big[39] = 0;
        CHECK(!gz_terms_current_decode(big, t2n, &o, od, &cc));
        memcpy(big, t2, t2n); big[5] ^= 1;
        CHECK(!gz_terms_current_decode(big, t2n, &o, od, &cc));
        memcpy(big, t2, t2n);
        CHECK(gz_terms_current_decode(big, t2n, &o, od, &cc));
    }
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
    test_terms_bounds();
    test_m1(&member);
    test_m2();
    test_envelope(&member);
    return check_done();
}
