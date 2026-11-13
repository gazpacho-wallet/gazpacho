/* Vectors T1 to T7 (terms.md 11) and M1, M2 (messages.md 11), byte for byte,
 * and the encoding tests of terms.md 12 and messages.md 12 (1 to 11). */
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
    CHECK(gz_terms_slice1_ok(&o, GZ_LOBBY_NET_SIGNET) && !gz_terms_slice1_ok(&o, GZ_LOBBY_NET_TESTNET4));
    CHECK(!gz_terms_slice1_ok(&o, 2) && !gz_terms_genesis(2) && gz_terms_genesis(GZ_LOBBY_NET_TESTNET4)[0] == 0x43);
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
        {22, 600000, 600001}, {28, 1, 0}, {18, 30000, 999}, {20, 60000, 59999},
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
            case 22: x.step_timeout_ms = (uint32_t)v; x.signing_budget_ms = 700000; break;
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
        CHECK(!gz_terms_current_decode(t2 + 34, t2n - 34, &o, od, &cc));        /* no outer digest */
        {   /* values at the bottom of their ranges; an odd adjustable term 127 */
            static gz_terms_outer_t o3;
            uint8_t r3[400], c3[128], d3[32];
            size_t r3n, c3n;
            gz_terms_current_t v;
            gz_terms_current_decode(t2, t2n, &o, od, &v);
            v.adj_value[0] = 0; v.adj_value[2] = 100;
            c3n = gz_terms_current_encode(&v, &o, c3, sizeof c3);
            CHECK(c3n == t2n && gz_terms_current_decode(c3, c3n, &o, od, &cc));
            CHECK(gz_terms_current_encode(&v, &o, c3, t2n) == t2n && gz_terms_current_encode(&v, &o, c3, t2n - 1) == 0);
            v.adj_value[2] = 99;
            c3n = gz_terms_current_encode(&v, &o, c3, sizeof c3);
            CHECK(!gz_terms_current_decode(c3, c3n, &o, od, &cc));
            o3 = o;
            o3.adj[3].type = 127; o3.adj[3].min = 5; o3.adj[3].max = 9; o3.n_adj = 4;
            r3n = gz_terms_outer_encode(&o3, r3, sizeof r3);
            CHECK(gz_terms_outer_decode(r3, r3n, &o3) && o3.n_adj == 4);
            gz_terms_outer_digest(r3, r3n, d3);
            v.adj_value[2] = 100; memcpy(v.outer_digest, d3, 32);
            v.n_adj = 4; v.adj_type[3] = 127; v.adj_value[3] = 9;
            c3n = gz_terms_current_encode(&v, &o3, c3, sizeof c3);
            CHECK(gz_terms_current_decode(c3, c3n, &o3, d3, &cc) && cc.n_adj == 4 && cc.adj_value[3] == 9);
            v.n_adj = 3;                                 /* without it: refused */
            c3n = gz_terms_current_encode(&v, &o3, c3, sizeof c3);
            CHECK(!gz_terms_current_decode(c3, c3n, &o3, d3, &cc));
        }
        memcpy(big, t2, 34); memcpy(big + 34, t2 + 40, t2n - 40);
        CHECK(!gz_terms_current_decode(big, t2n - 6, &o, od, &cc));            /* no version */
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

/* SHA-256 at every length around the padding boundaries, written whole and in
 * pieces; references from Python's hashlib. */
static void test_sha256(void)
{
    gz_lobby_sha256_t acc, s;
    uint8_t d[32], msg[1000];
    size_t L, i, at;
    gz_lobby_sha256_init(&s);
    gz_lobby_sha256_done(&s, d);
    CHECK(hexeq(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    gz_lobby_sha256_init(&s);
    gz_lobby_sha256_write(&s, (const uint8_t *)"abc", 3);
    gz_lobby_sha256_done(&s, d);
    CHECK(hexeq(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    gz_lobby_sha256_init(&acc);
    for (L = 0; L < 200; L++) {
        for (i = 0; i < L; i++) msg[i] = (uint8_t)((i * 7 + L) % 256);
        gz_lobby_sha256_init(&s);
        gz_lobby_sha256_write(&s, msg, L);
        gz_lobby_sha256_done(&s, d);
        gz_lobby_sha256_write(&acc, d, 32);
    }
    gz_lobby_sha256_done(&acc, d);
    CHECK(hexeq(d, 32, "8c7c9ff69da76fc28823a1cb97268672663e628e1ea955868b16db46bab0545d"));
    for (i = 0; i < 1000; i++) msg[i] = (uint8_t)((i * 13 + 5) % 256);
    gz_lobby_sha256_init(&s);
    for (at = 0, L = 1; at < 1000; at += L, L = L % 13 + 1)
        gz_lobby_sha256_write(&s, msg + at, at + L <= 1000 ? L : 1000 - at);
    gz_lobby_sha256_done(&s, d);
    CHECK(hexeq(d, 32, "7994e00959d889b2edd138584884b26ecd04053d86779cb88d89202dea18e599"));
}

/* UTF-8 in the alias (record 3): every edge of well-formedness. */
static void test_utf8(void)
{
    static const struct { const char *hex; int ok; } v[] = {
        {"41", 1}, {"7f", 1}, {"c280", 1}, {"c1bf", 0}, {"c0a9", 0}, {"dfbf", 1}, {"e0a080", 1}, {"e09fbf", 0},
        {"ed9fbf", 1}, {"eda080", 0}, {"edbfbf", 0}, {"ee8080", 1}, {"efbfbf", 1}, {"f0908080", 1},
        {"f08fbfbf", 0}, {"f48fbfbf", 1}, {"f4908080", 0}, {"f5808080", 0}, {"80", 0}, {"bf", 0},
        {"e282", 0}, {"c3", 0}, {"f09080", 0}, {"c341", 0}, {"e241ac", 0}, {"f09041bf", 0}, {"41c3a9", 1},
        {"e282ac41", 1}, {"f09f9880", 1}, {"fe", 0}, {"ff", 0},
    };
    size_t i;
    for (i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint8_t r[300], u[8];
        size_t un = lt_unhex(v[i].hex, u, sizeof u), k = 0;
        memcpy(r, t1, 34); k = 34;
        r[k++] = 3; r[k++] = (uint8_t)un; memcpy(r + k, u, un); k += un;
        memcpy(r + k, t1 + 34, t1n - 34); k += t1n - 34;
        if (outer_ok(r, k) != v[i].ok) printf("  utf8 %s\n", v[i].hex);
        CHECK(outer_ok(r, k) == v[i].ok);
    }
}

/* Shapes: the first entry may cover 3; the split must place every member;
 * the shape for an unchecked table is refused where it breaks. */
static void test_shapes(void)
{
    static gz_terms_outer_t x, y;
    uint8_t buf[600], lv[8], nl, d;
    size_t n;
    uint16_t k;
    x = o;
    x.n_shapes = 3;
    x.shapes[2] = x.shapes[1];
    x.shapes[1] = x.shapes[0];
    x.shapes[0].max_members = 3;
    n = gz_terms_outer_encode(&x, buf, sizeof buf);
    CHECK(gz_terms_outer_decode(buf, n, &y) && y.n_shapes == 3 && y.shapes[0].max_members == 3);
    x.shapes[0].max_members = 2;                       /* below 3 */
    n = gz_terms_outer_encode(&x, buf, sizeof buf);
    CHECK(!gz_terms_outer_decode(buf, n, &y));
    /* T7 with the leaves counted: every n from 3 to 16 gives n leaves (the decoder checks it) */
    for (k = 3; k <= 16; k++) CHECK(gz_terms_shape_for(&o, k, lv, &nl, &d));
    CHECK(!gz_terms_shape_for(&o, 0, lv, &nl, &d) && !gz_terms_shape_for(&o, 1000, lv, &nl, &d));
    /* an unchecked table: draft 1's [4] at 3 members, and [4,4,3] at 17 */
    x = o;
    x.n_shapes = 1; x.shapes[0].max_members = 20; x.shapes[0].n_interior = 1; x.shapes[0].interior[0] = 4;
    CHECK(!gz_terms_shape_for(&x, 3, lv, &nl, &d) && gz_terms_shape_for(&x, 5, lv, &nl, &d) && d == 2);
    x.shapes[0].n_interior = 2; x.shapes[0].interior[1] = 4;
    CHECK(!gz_terms_shape_for(&x, 17, lv, &nl, &d) && !gz_terms_shape_for(&x, 19, lv, &nl, &d));
    CHECK(gz_terms_shape_for(&x, 20, lv, &nl, &d) && nl == 3 && lv[0] == 4 && lv[1] == 4 && lv[2] == 3 && d == 3);
}

/* T1 with a display record (3 alias or 5 description) of `len` bytes 'a'
 * inserted in its place, or with the host key's first byte replaced. */
static int with_display(int type, size_t len)
{
    uint8_t r[700];
    size_t k = 0, at = type == 3 ? 34 : 69;            /* after chain (34) or after host_key (34 + 35) */
    memcpy(r, t1, at); k = at;
    r[k++] = (uint8_t)type;
    if (len < 253) r[k++] = (uint8_t)len;
    else { r[k++] = 0xfd; r[k++] = (uint8_t)(len >> 8); r[k++] = (uint8_t)len; }
    memset(r + k, 'a', len); k += len;
    memcpy(r + k, t1 + at, t1n - at); k += t1n - at;
    if (outer_ok(r, k)) {                               /* accepted: and it is canonical */
        static gz_terms_outer_t d;
        uint8_t again[700];
        gz_terms_outer_decode(r, k, &d);
        if (gz_terms_outer_encode(&d, again, sizeof again) != k || memcmp(again, r, k) != 0) return -1;
        return 1;
    }
    return 0;
}

static void test_display_and_key(void)
{
    uint8_t r[300];
    CHECK(!with_display(3, 0) && with_display(3, 1) == 1 && with_display(3, 32) == 1 && !with_display(3, 33));
    CHECK(!with_display(5, 0) && with_display(5, 1) == 1 && with_display(5, 280) == 1 && !with_display(5, 281));
    memcpy(r, t1, t1n);
    CHECK(r[34] == 4 && r[35] == 33 && r[36] == 2);
    r[36] = 3; CHECK(outer_ok(r, t1n));               /* odd y: a valid prefix (the point itself is the engines' check) */
    r[36] = 4; CHECK(!outer_ok(r, t1n));
    r[36] = 0; CHECK(!outer_ok(r, t1n));
}

/* The outer record's size limit, reached with an unknown odd record. */
static void test_outer_size(void)
{
    static uint8_t r[4200];
    size_t L, k, n;
    for (L = 3866; L <= 3868; L++) {
        k = t1n - 54;                                  /* just before record 64 */
        memcpy(r, t1, k);
        n = k;
        r[n++] = 63; r[n++] = 0xfd; r[n++] = (uint8_t)(L >> 8); r[n++] = (uint8_t)L;
        memset(r + n, 0x55, L); n += L;
        memcpy(r + n, t1 + k, 54); n += 54;
        CHECK(n == 225 + 4 + L);
        CHECK(outer_ok(r, n) == (n <= 4096));
    }
    CHECK(!outer_ok(t1, 0));
}

/* T1 with the shape table (record 24) replaced by raw bytes. */
static size_t with_shape_bytes(const uint8_t *sv, size_t sn, uint8_t *out)
{
    size_t k = 0, at = 0;
    while (k < t1n) {                                  /* every T1 record has a 1-byte type and length */
        size_t vl = t1[k + 1];
        if (t1[k] == 24) {
            out[at++] = 24;
            if (sn < 253) out[at++] = (uint8_t)sn;
            else { out[at++] = 0xfd; out[at++] = (uint8_t)(sn >> 8); out[at++] = (uint8_t)sn; }
            memcpy(out + at, sv, sn); at += sn;
        } else { memcpy(out + at, t1 + k, 2 + vl); at += 2 + vl; }
        k += 2 + vl;
    }
    return at;
}

static size_t with_shapes(const char *hex, uint8_t *out)
{
    uint8_t sv[256];
    return with_shape_bytes(sv, lt_unhex(hex, sv, sizeof sv), out);
}

/* Every fixed-size value of T1 one byte short and one byte long (terms.md
 * test 2), and the longest shape table, 1,000 bytes, and one entry more. */
static void test_record_sizes(void)
{
    static uint8_t r[1400], sv[1004];
    size_t k = 0, n, i;
    int refused = 0, tried = 0;
    while (k < t1n) {
        size_t vl = t1[k + 1];
        int d;
        for (d = -1; d <= 1; d += 2) {
            if (t1[k] == 24) break;                     /* the shape table has its own tests */
            memcpy(r, t1, k + 1);
            r[k + 1] = (uint8_t)(vl + d);
            n = k + 2;
            memcpy(r + n, t1 + k + 2, d < 0 ? vl - 1 : vl); n += d < 0 ? vl - 1 : vl;
            if (d > 0) r[n++] = 0;
            memcpy(r + n, t1 + k + 2 + vl, t1n - k - 2 - vl); n += t1n - k - 2 - vl;
            tried++;
            refused += !outer_ok(r, n);
        }
        k += 2 + vl;
    }
    CHECK(tried == 2 * 19 && refused == tried);
    for (i = 0; i < 250; i++) {                         /* {4, 5, ..., 253}: each [3] */
        sv[4 * i] = 0; sv[4 * i + 1] = (uint8_t)(4 + i); sv[4 * i + 2] = 0; sv[4 * i + 3] = 3;
    }
    n = with_shape_bytes(sv, 1000, r);
    CHECK(outer_ok(r, n));
    {   /* and the longest table encodes back to the same bytes, into a buffer of exactly its size */
        static gz_terms_outer_t d;
        static uint8_t again[1400];
        CHECK(gz_terms_outer_decode(r, n, &d) && d.n_shapes == 250);
        CHECK(gz_terms_outer_encode(&d, again, n) == n && memcmp(again, r, n) == 0);
        CHECK(gz_terms_outer_encode(&d, again, n - 1) == 0);
        d.shapes[0].n_interior = 6;                     /* six interior levels: encodable (the split refuses it) */
        CHECK(gz_terms_outer_encode(&d, again, sizeof again) == 0);   /* 1,006 bytes: more than a table holds */
        d.n_shapes = 2;
        CHECK(gz_terms_outer_encode(&d, again, sizeof again) > 0);
    }
    sv[1000] = 0; sv[1001] = 0xfe; sv[1002] = 0; sv[1003] = 3;
    n = with_shape_bytes(sv, 1004, r);
    CHECK(!outer_ok(r, n));
    /* 1,001 bytes of entries that are each valid: 249 of [3] and one of [4, 3] */
    sv[996] = 0x03; sv[997] = 0xe8; sv[998] = 1; sv[999] = 4; sv[1000] = 3;
    n = with_shape_bytes(sv, 1001, r);
    CHECK(!outer_ok(r, n));
    n = with_shape_bytes(sv + 4, 997, r);                   /* without the first entry: 997 bytes, valid */
    CHECK(outer_ok(r, n));
}

/* Each bound of a shape entry, on the last entry, after entries that would
 * already cover the target: so only that bound can refuse the record. */
static void test_shape_bytes(void)
{
    static const struct { const char *hex; int ok; } v[] = {
        {"000400030010010403", 1},
        {"00040003001001040300140104", 0},             /* the last entry lacks its leaf kind */
        {"0004000300100104030014", 0},                 /* two bytes of an entry */
        {"000400030010010403001401", 0},
        {"00040003001001040300140104 02", 0},          /* leaf kind 2 */
        {"00040003001001040300140104 03", 1},
        {"0004000300100104 03 03e8010403", 1},         /* 1,000 */
        {"0004000300100104 03 03e9010403", 0},         /* 1,001 */
        {"0004000300100104 03 0010010403", 0},         /* not increasing */
        {"0004000300100104 03 0014010303", 0},         /* width 3 */
        {"0004000300100104 03 0014011003", 0},         /* width 16 */
        {"0004000300050204040300100104 03", 0},        /* an entry for 5 alone, [4,4,3]: refused at 5 */
        {"00030003000400030010010403", 1},             /* the first entry may cover 3 */
        {"00020003000400030010010403", 0},             /* but not 2 */
    };
    size_t i;
    for (i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint8_t r[400];
        size_t n = with_shapes(v[i].hex, r);
        if (outer_ok(r, n) != v[i].ok) printf("  shape bytes %s\n", v[i].hex);
        CHECK(outer_ok(r, n) == v[i].ok);
    }
    {   /* width 7 covering 17 to 20: 17 splits as 3,3,3,2,2,2,2 above leaf kind 3: valid */
        uint8_t r[400];
        size_t n = with_shapes("000400030010010403 0014010703", r);
        CHECK(outer_ok(r, n));
        n = with_shapes("000400030010010403 0011010f03", r);   /* width 15 at 17: valid */
        CHECK(outer_ok(r, n));
        n = with_shapes("00040003 000f010f03", r);              /* width 15 at 5 to 15: refused */
        CHECK(!outer_ok(r, n));
    }
}

/* BigSize at every boundary of its forms, minimal or not, whole or cut short. */
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
    test_terms_bounds();
    test_m1(&member);
    test_m2();
    test_envelope(&member);
    test_sha256();
    test_utf8();
    test_shapes();
    test_shape_bytes();
    test_outer_size();
    test_display_and_key();
    test_record_sizes();
    test_bigsize();
    test_kinds(&member);
    return check_done();
}
