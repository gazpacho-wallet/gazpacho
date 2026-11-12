/* terms.md: vectors T1 to T7 and the tests of section 12 (encoding, shape,
 * signatures and identity, versions and freezing, comparison), with every
 * bound refused one past its edge and accepted at it. */
#include "tree_test.h"
#include "gazpacho/tree_import.h"
#include "../../core/tree/internal.h"

static const char *T1_OUTER =
    "0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800"
    "0000042102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e"
    "34733491560610c31b4b333d598e176bb883203548a5e60801020a0200080c02"
    "00030e08000000006af501801001001204000075301404000927c016040000ea"
    "6018090004000300100104031a04000000901c04000000241e08000000000001"
    "86a02004000000642201004010000000000000000000000000000007d0421000"
    "0000000000000000000000000003e84410000000000000006400000000000009"
    "c4";
static const char *T1_DIGEST = "75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2";
static const char *T1_SIG = "0bb885ba5dbf0f21fda26a90c68d6736f71619b72583d8691581319efafdfeb5"
                            "db7c87c85def6708994c5b78dc93be56fd9dd9f670147f353d74787d922bf54d";
static const char *T2_CUR =
    "022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4"
    "24f2040400000001400800000000000001f4420800000000000003e844080000"
    "0000000003e8";
static const char *T2_DIGEST = "d1db6ddfd5a2c12ae197036f285457ae6ceaf468c2a47fb71691dde4b1153942";
static const char *T2_SIG = "a739c225be7e2842c2e7925c12b8e824751ba1d019e31c9f16342cf78f02633f"
                            "f00d0ef1ff618b18456f472818758017a0e682b211d553d00edf3e2d1b1c140d";
static const char *T3_CUR =
    "022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4"
    "24f2040400000002400800000000000005dc420800000000000003e844080000"
    "0000000003e8";
static const char *T3_DIGEST = "ba3bccb892b8b65321956753d973bfba1bbdcbf2e5c68e28052683a713b2b7be";
static const char *T3_SIG = "7a692794d41ad38a845e6533b2499b197a3d63d86f196d274a14d4aa33478bf3"
                            "f563f2503def1c0b1bf53e096cd2e7be0f45f10c30066f5a6be5d98ff53fff5b";
static const char *T5_CUR =
    "022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4"
    "24f2040400000003400800000000000007d1420800000000000003e844080000"
    "0000000003e8";

static const gz_terms_policy_t SLICE1 = {1};
static const gz_terms_policy_t ANY = {0};

/* ---- an independent TLV writer for hostile records ---- */
typedef struct { uint8_t b[5000]; size_t n; } rec_t;
static void bs(rec_t *r, uint64_t x)
{
    if (x < 0xfd) r->b[r->n++] = (uint8_t)x;
    else if (x < 0x10000) { r->b[r->n++] = 0xfd; r->b[r->n++] = (uint8_t)(x >> 8); r->b[r->n++] = (uint8_t)x; }
    else { int i; r->b[r->n++] = 0xfe; for (i = 3; i >= 0; i--) r->b[r->n++] = (uint8_t)(x >> (8 * i)); }
}
static void add(rec_t *r, uint64_t type, const uint8_t *v, size_t len)
{
    bs(r, type); bs(r, len); memcpy(r->b + r->n, v, len); r->n += len;
}

/* Re-encode T1 with one field replaced by an arbitrary value (same type). */
static void t1_with(rec_t *r, uint64_t type, const uint8_t *v, size_t len, uint64_t extra_type,
                    const uint8_t *ev, size_t elen)
{
    uint8_t outer[GZ_TERMS_OUTER_MAX];
    size_t n = unhex(T1_OUTER, outer, sizeof outer), i = 0;
    int extra_done = extra_type == 0;
    r->n = 0;
    while (i < n) {
        uint64_t t = outer[i], l = outer[i + 1];
        if (!extra_done && extra_type < t) { add(r, extra_type, ev, elen); extra_done = 1; }
        if (t == type) add(r, t, v, len);
        else add(r, t, outer + i + 2, (size_t)l);
        i += 2 + (size_t)l;
    }
    if (!extra_done) add(r, extra_type, ev, elen);
}

static gz_terms_err_t dec(const rec_t *r, const gz_terms_policy_t *pol)
{
    static gz_terms_outer_t o;
    return gz_terms_decode_outer(r->b, r->n, pol, &o);
}

static void u16be(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void u32be(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static void u64be(uint8_t *p, uint64_t v) { u32be(p, (uint32_t)(v >> 32)); u32be(p + 4, (uint32_t)v); }

/* One bound: value `bad` refused with `e`, value `good` accepted. */
static void bound_u16(uint64_t type, uint32_t good, uint32_t bad, gz_terms_err_t e)
{
    rec_t r; uint8_t v[2];
    u16be(v, good); t1_with(&r, type, v, 2, 0, NULL, 0); CHECK(dec(&r, &SLICE1) == GZ_TERMS_OK);
    u16be(v, bad); t1_with(&r, type, v, 2, 0, NULL, 0); CHECK(dec(&r, &SLICE1) == e);
}
static void bound_u32(uint64_t type, uint32_t good, uint32_t bad, gz_terms_err_t e)
{
    rec_t r; uint8_t v[4];
    u32be(v, good); t1_with(&r, type, v, 4, 0, NULL, 0); CHECK(dec(&r, &SLICE1) == GZ_TERMS_OK);
    u32be(v, bad); t1_with(&r, type, v, 4, 0, NULL, 0); CHECK(dec(&r, &SLICE1) == e);
    if (dec(&r, &SLICE1) != e) printf("  type %llu value %u gave %s\n", (unsigned long long)type, bad, gz_terms_err_name(dec(&r, &SLICE1)));
}
static void bound_u64(uint64_t type, uint64_t good, uint64_t bad, gz_terms_err_t e)
{
    rec_t r; uint8_t v[8];
    u64be(v, good); t1_with(&r, type, v, 8, 0, NULL, 0); CHECK(dec(&r, &SLICE1) == GZ_TERMS_OK);
    u64be(v, bad); t1_with(&r, type, v, 8, 0, NULL, 0); CHECK(dec(&r, &SLICE1) == e);
}
static void bound_range(uint64_t type, uint64_t lo, uint64_t hi, gz_terms_err_t e)
{
    rec_t r; uint8_t v[16];
    u64be(v, lo); u64be(v + 8, hi); t1_with(&r, type, v, 16, 0, NULL, 0); CHECK(dec(&r, &SLICE1) == e);
}
static gz_terms_err_t shapes(const char *hex)
{
    rec_t r; uint8_t v[1100];
    size_t n = unhex(hex, v, sizeof v);
    t1_with(&r, 24, v, n, 0, NULL, 0);
    return dec(&r, &SLICE1);
}

static void test_sha256(void)
{
    uint8_t h[32], big[1000];
    tr_sha256((const uint8_t *)"", 0, h);
    CHECK(eqhex(h, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    tr_sha256((const uint8_t *)"abc", 3, h);
    CHECK(eqhex(h, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    tr_sha256((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, h);
    CHECK(eqhex(h, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    memset(big, 'a', sizeof big);
    {   /* one million 'a', written in uneven pieces */
        tr_sha256_t s; size_t done = 0, piece = 1;
        tr_sha256_init(&s);
        while (done < 1000000) {
            size_t k = 1000000 - done < piece ? 1000000 - done : piece;
            tr_sha256_write(&s, big, k); done += k; piece = piece % 997 + 1;
        }
        tr_sha256_done(&s, h);
        CHECK(eqhex(h, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    }
}

static void test_vectors(void)
{
    gz_terms_outer_t t, d;
    gz_terms_current_t c, cd;
    uint8_t out[GZ_TERMS_OUTER_MAX], dig[32], sig[64], cur[1024], want[1024];
    size_t n, m;
    char hx[200];

    /* T1: the struct encodes to exactly the published bytes, digest, signature. */
    t1_terms(&t);
    n = gz_terms_encode_outer(&t, out, sizeof out);
    CHECK(n == 225);
    CHECK(eqhex(out, n, T1_OUTER));
    gz_terms_outer_digest(out, n, dig);
    CHECK(eqhex(dig, 32, T1_DIGEST));
    test_sign("host", dig, sig);
    CHECK(eqhex(sig, 64, T1_SIG));
    tohex(t.host_key, 33, hx);
    CHECK(strcmp(hx, "02b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e3473349156") == 0);
    {
        uint8_t k[33];
        test_pub("member 1 factory", k);
        CHECK(eqhex(k, 33, "0223a26c411e719d542783e3bb05fa00a467fb73227d495ab89734fef0ecec3974"));
        test_pub("member 1 contribution", k);
        CHECK(eqhex(k, 33, "024322bd904fa9770421b0b48f08e961d473f3ee9a36a5bc85fa3cac30fa2e15ae"));
    }
    /* ...and the bytes decode to the same struct. */
    CHECK(gz_terms_decode_outer(out, n, &SLICE1, &d) == GZ_TERMS_OK);
    CHECK(memcmp(&d, &t, sizeof t) == 0);

    /* T2 and T3. */
    t1_current(dig, 1, 500, 1000, 1000, &c);
    m = gz_terms_encode_current(&c, cur, sizeof cur);
    CHECK(m == 70 && eqhex(cur, m, T2_CUR));
    gz_terms_current_digest(cur, m, want);
    CHECK(eqhex(want, 32, T2_DIGEST));
    test_sign("host", want, sig);
    CHECK(eqhex(sig, 64, T2_SIG));
    CHECK(gz_terms_decode_current(cur, m, &d, &cd) == GZ_TERMS_OK && memcmp(&cd, &c, sizeof c) == 0);
    t1_current(dig, 2, 1500, 1000, 1000, &c);
    m = gz_terms_encode_current(&c, cur, sizeof cur);
    CHECK(m == 70 && eqhex(cur, m, T3_CUR));
    gz_terms_current_digest(cur, m, want);
    CHECK(eqhex(want, 32, T3_DIGEST));
    test_sign("host", want, sig);
    CHECK(eqhex(sig, 64, T3_SIG));

    /* T4: record 10's length written fd0002 is refused; the bytes differ from offset 91. */
    {
        uint8_t bad[300];
        size_t k = unhex(T1_OUTER, bad, sizeof bad), i, at = 0;
        for (i = 0; i + 3 < k; i++)
            if (bad[i] == 0x0a && bad[i + 1] == 0x02 && bad[i + 2] == 0x00 && bad[i + 3] == 0x08) { at = i; break; }
        CHECK(at == 90);
        memmove(bad + at + 4, bad + at + 2, k - at - 2);
        bad[at + 1] = 0xfd; bad[at + 2] = 0x00; bad[at + 3] = 0x02;
        k += 2;
        CHECK(gz_terms_decode_outer(bad, k, &ANY, &d) == GZ_TERMS_E_NOT_MINIMAL);
        gz_terms_outer_digest(bad, k, want);
        tohex(want, 32, hx);
        CHECK(strncmp(hx, "adb3a733", 8) == 0 && strcmp(hx + 56, "eb352a4d") == 0);
    }
    /* T5: joining fee 2,001 outside 0 to 2,000. */
    CHECK(gz_terms_decode_outer(out, n, &SLICE1, &d) == GZ_TERMS_OK);
    m = unhex(T5_CUR, cur, sizeof cur);
    CHECK(gz_terms_decode_current(cur, m, &d, &cd) == GZ_TERMS_E_ADJ_VALUE);
}

static void test_receive(void)
{
    uint8_t outer[300], cur[100], cur3[100], osig[64], csig[64], csig3[64], od[32], cd[32], pinned[33], scope[32];
    size_t on = unhex(T1_OUTER, outer, sizeof outer), cn = unhex(T2_CUR, cur, sizeof cur), c3 = unhex(T3_CUR, cur3, sizeof cur3);
    gz_terms_outer_t o;
    gz_terms_current_t c;
    gz_tree_crypto_t cr;
    gz_tree_secp_crypto(test_ctx(), &cr);
    unhex(T1_SIG, osig, 64); unhex(T2_SIG, csig, 64); unhex(T3_SIG, csig3, 64);
    unhex(T1_DIGEST, scope, 32);
    test_pub("host", pinned);
    CHECK(gz_terms_receive(outer, on, osig, cur, cn, csig, scope, pinned, &SLICE1, &cr, &o, od, &c, cd) == GZ_TERMS_OK);
    CHECK(eqhex(cd, 32, T2_DIGEST) && c.version == 1);
    CHECK(gz_terms_receive(outer, on, osig, cur3, c3, csig3, scope, pinned, &SLICE1, &cr, &o, od, &c, cd) == GZ_TERMS_OK);
    /* Test 7: another key's signature; a host key that is not the pinned key;
     * a signature over the wrong digest, both ways. */
    {
        uint8_t other[33], s2[64], dig2[32];
        test_pub("member 1 factory", other);
        CHECK(gz_terms_receive(outer, on, osig, cur, cn, csig, scope, other, &SLICE1, &cr, &o, od, &c, cd) == GZ_TERMS_E_PINNED_KEY);
        unhex(T1_DIGEST, dig2, 32);
        test_sign("member 1 factory", dig2, s2);
        CHECK(gz_terms_receive(outer, on, s2, cur, cn, csig, scope, pinned, &SLICE1, &cr, &o, od, &c, cd) == GZ_TERMS_E_OUTER_SIG);
        /* the outer digest signed, presented as the current signature, and the other way round */
        CHECK(gz_terms_receive(outer, on, osig, cur, cn, osig, scope, pinned, &SLICE1, &cr, &o, od, &c, cd) == GZ_TERMS_E_CURRENT_SIG);
        CHECK(gz_terms_receive(outer, on, csig, cur, cn, csig, scope, pinned, &SLICE1, &cr, &o, od, &c, cd) == GZ_TERMS_E_OUTER_SIG);
        /* the outer digest put through the current tag is not the current digest */
        gz_terms_current_digest(outer, on, dig2);
        CHECK(!eqhex(dig2, 32, T1_DIGEST));
    }
    /* Scope mismatch (step 2) and a current record naming another outer digest (step 6). */
    {
        uint8_t sc[32], bad[100], bsig[64], bd[32];
        memcpy(sc, scope, 32); sc[0] ^= 1;
        CHECK(gz_terms_receive(outer, on, osig, cur, cn, csig, sc, pinned, &SLICE1, &cr, &o, od, &c, cd) == GZ_TERMS_E_SCOPE);
        memcpy(bad, cur, cn); bad[2] ^= 1;
        gz_terms_current_digest(bad, cn, bd);
        test_sign("host", bd, bsig);
        CHECK(gz_terms_receive(outer, on, osig, bad, cn, bsig, scope, pinned, &SLICE1, &cr, &o, od, &c, cd) == GZ_TERMS_E_OUTER_DIGEST);
    }
    /* Test 9: a mainnet chain hash is refused by a Slice 1 app; another app may decode it. */
    {
        rec_t r; uint8_t main_chain[32];
        unhex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000", main_chain, 32);
        t1_with(&r, 2, main_chain, 32, 0, NULL, 0);
        CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_CHAIN);
        CHECK(dec(&r, &ANY) == GZ_TERMS_OK);
    }
    /* Test 8: equal rules, another salt: another identifier. */
    {
        rec_t r; uint8_t salt[16] = {1}, d1[32];
        t1_with(&r, 6, salt, 16, 0, NULL, 0);
        gz_terms_outer_digest(r.b, r.n, d1);
        CHECK(!eqhex(d1, 32, T1_DIGEST));
    }
    /* A host key with prefix 02 that is not on the curve: refused at step 3. */
    {
        rec_t r; uint8_t k[33], d1[32], s1[64];
        memset(k, 0xff, 33); k[0] = 2;            /* x >= p: not a point */
        t1_with(&r, 4, k, 33, 0, NULL, 0);
        gz_terms_outer_digest(r.b, r.n, d1);
        test_sign("host", d1, s1);
        CHECK(gz_terms_receive(r.b, r.n, s1, cur, cn, csig, d1, k, &SLICE1, &cr, &o, od, &c, cd) == GZ_TERMS_E_HOST_KEY);
    }
}

static void test_encoding_rules(void)
{
    rec_t r;
    uint8_t outer[300], v[64];
    size_t n = unhex(T1_OUTER, outer, sizeof outer);
    gz_terms_outer_t o;
    gz_terms_current_t c;
    uint8_t dig[32];
    unhex(T1_DIGEST, dig, 32);

    /* Types out of order and repeated. */
    {
        uint8_t b[300];
        memcpy(b, outer, n);
        CHECK(gz_terms_decode_outer(b, n, &SLICE1, &o) == GZ_TERMS_OK);
        /* swap the order of records 2 and 4 */
        r.n = 0;
        add(&r, 4, outer + 36, 33);
        add(&r, 2, outer + 2, 32);
        memcpy(r.b + r.n, outer + 69, n - 69); r.n += n - 69;
        CHECK(dec(&r, &ANY) == GZ_TERMS_E_ORDER);
        r.n = 0;
        add(&r, 2, outer + 2, 32);
        add(&r, 2, outer + 2, 32);
        memcpy(r.b + r.n, outer + 34, n - 34); r.n += n - 34;
        CHECK(dec(&r, &ANY) == GZ_TERMS_E_ORDER);
    }
    /* Each fixed-width value one byte short and one long. */
    {
        static const struct { uint8_t type; uint8_t size; } F[] = {
            {2, 32}, {4, 33}, {6, 16}, {8, 1}, {10, 2}, {12, 2}, {14, 8}, {16, 1}, {18, 4}, {20, 4}, {22, 4},
            {26, 4}, {28, 4}, {30, 8}, {32, 4}, {34, 1}, {64, 16}, {66, 16}, {68, 16}};
        size_t i;
        memset(v, 0, sizeof v);
        for (i = 0; i < sizeof F / sizeof F[0]; i++) {
            t1_with(&r, F[i].type, v, F[i].size - 1u, 0, NULL, 0);
            CHECK(dec(&r, &ANY) == GZ_TERMS_E_LENGTH);
            t1_with(&r, F[i].type, v, F[i].size + 1u, 0, NULL, 0);
            CHECK(dec(&r, &ANY) == GZ_TERMS_E_LENGTH);
        }
    }
    /* A truncated last record; a length past the end. */
    CHECK(gz_terms_decode_outer(outer, n - 1, &SLICE1, &o) == GZ_TERMS_E_TRUNCATED);
    {
        uint8_t b[300];
        memcpy(b, outer, n);
        b[n - 17] = 17;   /* record 68's length 0x10 -> 0x11 */
        CHECK(gz_terms_decode_outer(b, n, &SLICE1, &o) == GZ_TERMS_E_TRUNCATED);
    }
    /* Size limits: an outer record of 4,096 bytes is read; 4,097 is not. The
     * description fills the room (odd types of 1..63 are skipped: use 63). */
    {
        uint8_t pad[4096];
        size_t room;
        memset(pad, 'a', sizeof pad);
        t1_with(&r, 0, NULL, 0, 63, pad, 1);
        room = 4096 - r.n + 1;   /* grow the one-byte value to fill exactly 4,096 */
        t1_with(&r, 0, NULL, 0, 63, pad, room - 2);   /* the length becomes fd xx xx: two more bytes */
        CHECK(r.n == 4096);
        CHECK(dec(&r, &SLICE1) == GZ_TERMS_OK);
        t1_with(&r, 0, NULL, 0, 63, pad, room - 1);
        CHECK(r.n == 4097);
        CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_TOO_LONG);
    }
    {
        rec_t cr;
        uint8_t pad[1100];
        uint8_t d8[8] = {0};
        memset(pad, 0, sizeof pad);
        cr.n = 0;
        add(&cr, 2, dig, 32);
        u32be(v, 1); add(&cr, 4, v, 4);
        add(&cr, 64, d8, 8); add(&cr, 66, d8, 8); u64be(d8, 100); add(&cr, 68, d8, 8);
        CHECK(gz_terms_decode_outer(outer, n, &SLICE1, &o) == GZ_TERMS_OK);
        CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_OK);
        /* pad with an unknown odd adjustable type? Not allowed in the outer;
         * use the size check directly: 1,025 bytes is refused before parsing. */
        memcpy(pad, cr.b, cr.n);
        CHECK(gz_terms_decode_current(pad, 1025, &o, &c) == GZ_TERMS_E_TOO_LONG);
        CHECK(gz_terms_decode_current(pad, 1024, &o, &c) != GZ_TERMS_E_TOO_LONG);
    }
    /* Test 3: unknown even types in 1..63, in 64..127 and from 128: refused.
     * An unknown odd type of 1..63 is skipped, but changes the digest. */
    memset(v, 0, sizeof v);
    t1_with(&r, 0, NULL, 0, 36, v, 1);  CHECK(dec(&r, &ANY) == GZ_TERMS_E_UNKNOWN_EVEN);   /* reserved even 36 */
    t1_with(&r, 0, NULL, 0, 38, v, 1);  CHECK(dec(&r, &ANY) == GZ_TERMS_E_UNKNOWN_EVEN);
    t1_with(&r, 0, NULL, 0, 70, v, 16); CHECK(dec(&r, &ANY) == GZ_TERMS_E_UNKNOWN_EVEN);
    t1_with(&r, 0, NULL, 0, 72, v, 16); CHECK(dec(&r, &ANY) == GZ_TERMS_E_UNKNOWN_EVEN);
    t1_with(&r, 0, NULL, 0, 128, v, 1); CHECK(dec(&r, &ANY) == GZ_TERMS_E_RESERVED_TYPE);
    t1_with(&r, 0, NULL, 0, 129, v, 1); CHECK(dec(&r, &ANY) == GZ_TERMS_E_RESERVED_TYPE);
    t1_with(&r, 0, NULL, 0, 0, v, 0);   CHECK(dec(&r, &ANY) == GZ_TERMS_OK);   /* extra_type 0: nothing added */
    {
        uint8_t d1[32];
        t1_with(&r, 0, NULL, 0, 35, v, 3);
        CHECK(dec(&r, &SLICE1) == GZ_TERMS_OK);
        gz_terms_outer_digest(r.b, r.n, d1);
        CHECK(!eqhex(d1, 32, T1_DIGEST));
        CHECK(gz_terms_decode_outer(r.b, r.n, &SLICE1, &o) == GZ_TERMS_OK && o.n_unknown_odd == 1);
    }
    /* An odd adjustable type 65 is a range; its current record must carry it. */
    {
        uint8_t rg[16];
        u64be(rg, 1); u64be(rg + 8, 5);
        t1_with(&r, 0, NULL, 0, 65, rg, 16);
        CHECK(gz_terms_decode_outer(r.b, r.n, &SLICE1, &o) == GZ_TERMS_OK && o.n_adj == 4);
    }
    /* UTF-8 in the display texts: an overlong form and a surrogate are refused. */
    {
        static const uint8_t overlong[2] = {0xc0, 0xaf}, surrogate[3] = {0xed, 0xa0, 0x80}, ok[4] = {0xf0, 0x9f, 0x8d, 0x85};
        t1_with(&r, 0, NULL, 0, 3, overlong, 2);  CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_UTF8);
        t1_with(&r, 0, NULL, 0, 5, surrogate, 3); CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_UTF8);
        t1_with(&r, 0, NULL, 0, 3, ok, 4);        CHECK(dec(&r, &SLICE1) == GZ_TERMS_OK);
        memset(v, 'x', 33);
        t1_with(&r, 0, NULL, 0, 3, v, 32);        CHECK(dec(&r, &SLICE1) == GZ_TERMS_OK);
        t1_with(&r, 0, NULL, 0, 3, v, 33);        CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_LENGTH);
        t1_with(&r, 0, NULL, 0, 3, v, 0);         CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_LENGTH);
    }
    /* Each required type missing in turn. */
    {
        static const uint8_t REQ[] = {2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 64, 66, 68};
        size_t k;
        for (k = 0; k < sizeof REQ; k++) {
            rec_t m;
            size_t i = 0;
            m.n = 0;
            while (i < n) {
                uint8_t t = outer[i], l = outer[i + 1];
                if (t != REQ[k]) add(&m, t, outer + i + 2, l);
                i += 2 + (size_t)l;
            }
            CHECK(dec(&m, &ANY) == GZ_TERMS_E_MISSING);
        }
    }
    /* BigSize minimality at each width's edge: 0xfc in three bytes, 0xffff
     * in five, 0xffffffff in nine are refused; 0xfd in three is the shortest. */
    {
        static const char *NONMIN[3] = {"fd00fc", "fe0000ffff", "ff00000000ffffffff"};
        size_t k;
        for (k = 0; k < 3; k++) {
            uint8_t tail[16];
            size_t tl = unhex(NONMIN[k], tail, sizeof tail);
            memcpy(r.b, outer, n);
            memcpy(r.b + n, tail, tl);
            r.b[n + tl] = 0;     /* length 0 */
            r.n = n + tl + 1;
            CHECK(dec(&r, &ANY) == GZ_TERMS_E_NOT_MINIMAL);
        }
        memset(v, 'd', 64);
        {
            uint8_t desc[300];
            memset(desc, 'd', sizeof desc);
            t1_with(&r, 0, NULL, 0, 5, desc, 253);   /* length fd00fd: minimal */
            CHECK(dec(&r, &SLICE1) == GZ_TERMS_OK);
            t1_with(&r, 0, NULL, 0, 5, desc, 280);
            CHECK(dec(&r, &SLICE1) == GZ_TERMS_OK);
            t1_with(&r, 0, NULL, 0, 5, desc, 281);
            CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_LENGTH);
            t1_with(&r, 0, NULL, 0, 5, desc, 0);
            CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_LENGTH);
        }
    }
    /* Test 4: a current record missing an adjustable type, or carrying one the outer lacks. */
    {
        rec_t cr;
        uint8_t d8[8] = {0};
        CHECK(gz_terms_decode_outer(outer, n, &SLICE1, &o) == GZ_TERMS_OK);
        cr.n = 0;
        add(&cr, 2, dig, 32); u32be(v, 1); add(&cr, 4, v, 4); add(&cr, 64, d8, 8); add(&cr, 66, d8, 8);
        CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_E_ADJ_SET);
        u64be(d8, 100); add(&cr, 68, d8, 8); add(&cr, 69, d8, 8);
        CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_E_ADJ_SET);
        /* version 0; a type other than 2 and 4 below 64, odd or even */
        cr.n = 0;
        add(&cr, 2, dig, 32); u32be(v, 0); add(&cr, 4, v, 4);
        u64be(d8, 0); add(&cr, 64, d8, 8); add(&cr, 66, d8, 8); u64be(d8, 100); add(&cr, 68, d8, 8);
        CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_E_VERSION);
        cr.n = 0;
        add(&cr, 2, dig, 32); u32be(v, 1); add(&cr, 4, v, 4); add(&cr, 5, v, 1);
        CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_E_TYPE_NOT_ALLOWED);
        cr.n = 0;
        add(&cr, 2, dig, 32); u32be(v, 1); add(&cr, 4, v, 4); add(&cr, 6, v, 1);
        CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_E_UNKNOWN_EVEN);
        cr.n = 0;
        add(&cr, 2, dig, 32);
        CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_E_MISSING);
        /* A value at its range's lower edge, and one below (proportional fee 100..2,500). */
        cr.n = 0;
        add(&cr, 2, dig, 32); u32be(v, 1); add(&cr, 4, v, 4);
        u64be(d8, 0); add(&cr, 64, d8, 8); add(&cr, 66, d8, 8); u64be(d8, 100); add(&cr, 68, d8, 8);
        CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_OK);
        cr.b[cr.n - 1] = 99;
        CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_E_ADJ_VALUE);
        /* The outer digest one byte short and one long. */
        {
            uint8_t d33[33];
            memcpy(d33, dig, 32); d33[32] = 0;
            cr.n = 0; add(&cr, 2, d33, 33); u32be(v, 1); add(&cr, 4, v, 4);
            CHECK(gz_terms_decode_current(cr.b, cr.n, NULL, &c) == GZ_TERMS_E_LENGTH);
            cr.n = 0; add(&cr, 2, d33, 31); u32be(v, 1); add(&cr, 4, v, 4);
            CHECK(gz_terms_decode_current(cr.b, cr.n, NULL, &c) == GZ_TERMS_E_LENGTH);
            cr.n = 0; add(&cr, 2, d33, 32); add(&cr, 4, v, 3);
            CHECK(gz_terms_decode_current(cr.b, cr.n, NULL, &c) == GZ_TERMS_E_LENGTH);
            cr.n = 0; add(&cr, 2, d33, 32); add(&cr, 4, v, 4); add(&cr, 64, d8, 7);
            CHECK(gz_terms_decode_current(cr.b, cr.n, NULL, &c) == GZ_TERMS_E_LENGTH);
        }
        /* In a current record too: an unknown even adjustable type, type 128. */
        cr.n = 0;
        add(&cr, 2, dig, 32); u32be(v, 1); add(&cr, 4, v, 4);
        u64be(d8, 0); add(&cr, 64, d8, 8); add(&cr, 66, d8, 8); u64be(d8, 100); add(&cr, 68, d8, 8);
        {
            size_t base = cr.n;
            add(&cr, 70, d8, 8);
            CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_E_UNKNOWN_EVEN);
            CHECK(gz_terms_decode_current(cr.b, cr.n, NULL, &c) == GZ_TERMS_E_UNKNOWN_EVEN);
            cr.n = base;
            add(&cr, 128, d8, 8);
            CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_E_RESERVED_TYPE);
            cr.n = base;
            add(&cr, 129, d8, 8);
            CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_E_RESERVED_TYPE);
            cr.n = base;
            CHECK(gz_terms_decode_current(cr.b, cr.n, &o, &c) == GZ_TERMS_OK);
        }
    }
}

static void test_bounds(void)
{
    rec_t r;
    uint8_t v[16];
    /* Test 5: every bound at its edge (accepted) and one past it (refused). */
    bound_u16(10, 16, 1001, GZ_TERMS_E_TARGET);     /* the 1,000 edge: test_target_edge */
    bound_u16(10, 3, 2, GZ_TERMS_E_TARGET);
    bound_u16(12, 8, 9, GZ_TERMS_E_MINIMUM);        /* minimum > target */
    bound_u16(12, 3, 2, GZ_TERMS_E_MINIMUM);
    bound_u32(18, 1000, 999, GZ_TERMS_E_READY_WINDOW);
    bound_u32(18, 600000, 600001, GZ_TERMS_E_READY_WINDOW);
    bound_u32(22, 60000, 59999, GZ_TERMS_E_STEP_TIMEOUT);
    bound_u32(20, 60000, 59999, GZ_TERMS_E_SIGNING_BUDGET);   /* budget below the step timeout */
    bound_u32(20, 86400000, 86400001, GZ_TERMS_E_SIGNING_BUDGET);
    bound_u32(26, 1, 0, GZ_TERMS_E_LIFETIME);
    bound_u32(26, 52560, 52561, GZ_TERMS_E_LIFETIME);
    bound_u32(28, 1, 0, GZ_TERMS_E_WINDDOWN);
    bound_u32(28, 52560, 52561, GZ_TERMS_E_WINDDOWN);
    bound_u64(30, 546, 545, GZ_TERMS_E_CHANNEL);
    bound_u64(30, 2100000000000000ull, 2100000000000001ull, GZ_TERMS_E_CHANNEL);
    bound_u32(32, 1, 0, GZ_TERMS_E_FEERATE);
    bound_u32(32, 1000000, 1000001, GZ_TERMS_E_FEERATE);
    /* Step timeout above 600,000 (with the budget raised to keep it valid). */
    {
        uint8_t b[4];
        u32be(b, 600001);
        t1_with(&r, 22, b, 4, 0, NULL, 0);
        CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_STEP_TIMEOUT);
    }
    /* Target 1,000 needs a shape reaching 1,000; with T1's table it is refused
     * for the shape, not the bound. */
    {
        uint8_t b[2];
        u16be(b, 17);
        t1_with(&r, 10, b, 2, 0, NULL, 0);
        CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_SHAPE_TARGET);
        u16be(b, 16);
        t1_with(&r, 10, b, 2, 0, NULL, 0);
        CHECK(dec(&r, &SLICE1) == GZ_TERMS_OK);
    }
    /* Profile 1..4, Slice 1 only 2; shortfall 0..1, Slice 1 only 0; switches. */
    v[0] = 0; t1_with(&r, 8, v, 1, 0, NULL, 0); CHECK(dec(&r, &ANY) == GZ_TERMS_E_PROFILE);
    v[0] = 5; t1_with(&r, 8, v, 1, 0, NULL, 0); CHECK(dec(&r, &ANY) == GZ_TERMS_E_PROFILE);
    v[0] = 4; t1_with(&r, 8, v, 1, 0, NULL, 0); CHECK(dec(&r, &ANY) == GZ_TERMS_OK);
    CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_SLICE1);
    v[0] = 2; v[1] = 0;
    v[0] = 1; t1_with(&r, 16, v, 1, 0, NULL, 0); CHECK(dec(&r, &ANY) == GZ_TERMS_OK);
    CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_SLICE1);
    v[0] = 2; t1_with(&r, 16, v, 1, 0, NULL, 0); CHECK(dec(&r, &ANY) == GZ_TERMS_E_SHORTFALL);
    v[0] = 7; t1_with(&r, 34, v, 1, 0, NULL, 0); CHECK(dec(&r, &ANY) == GZ_TERMS_OK);
    CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_SLICE1);
    v[0] = 8; t1_with(&r, 34, v, 1, 0, NULL, 0); CHECK(dec(&r, &ANY) == GZ_TERMS_E_SWITCHES);
    /* Ranges: min > max; above their ceilings; at them. */
    bound_range(64, 5, 4, GZ_TERMS_E_RANGE);
    bound_range(64, 4, 4, GZ_TERMS_OK);
    bound_range(64, 0, 2100000000000000ull, GZ_TERMS_OK);
    bound_range(64, 0, 2100000000000001ull, GZ_TERMS_E_RANGE);
    bound_range(66, 0, 4294967295ull, GZ_TERMS_OK);
    bound_range(66, 0, 4294967296ull, GZ_TERMS_E_RANGE);
    bound_range(68, 0, 4294967295ull, GZ_TERMS_OK);
    bound_range(68, 0, 4294967296ull, GZ_TERMS_E_RANGE);
    /* A host key prefix other than 2 or 3. */
    {
        uint8_t k[33];
        test_pub("host", k);
        k[0] = 4;
        t1_with(&r, 4, k, 33, 0, NULL, 0);
        CHECK(dec(&r, &SLICE1) == GZ_TERMS_E_HOST_KEY);
    }
}

static void test_shapes(void)
{
    gz_terms_outer_t t;
    gz_tree_params_t p;
    uint8_t depths[16];
    static const uint8_t L4[1] = {4}, L43[2] = {4, 3};
    uint32_t n;
    /* T1's table, and section 4.1's bounds one past each edge. */
    CHECK(shapes("0004000300100104 03") == GZ_TERMS_OK);
    CHECK(shapes("0004000300040104 03") == GZ_TERMS_E_SHAPE_MAX_MEMBERS);   /* not increasing */
    CHECK(shapes("0002000300100104 03") == GZ_TERMS_E_SHAPE_MAX_MEMBERS);   /* 2 < 3 */
    CHECK(shapes("0003000300100104 03") == GZ_TERMS_E_SHAPE_SPLIT);          /* 4 members under width 4 */
    CHECK(shapes("000300030004000300100104 03") == GZ_TERMS_OK);             /* 3 itself as an entry */
    CHECK(shapes("000400030007010403") == GZ_TERMS_E_SHAPE_TARGET);           /* last 7 < target 8 */
    CHECK(shapes("000400030008010403") == GZ_TERMS_OK);                       /* last 8 = target */
    CHECK(shapes("000f000303e8010f03") == GZ_TERMS_OK);                       /* 1,000, width 15 */
    CHECK(shapes("000f000303e9010f03") == GZ_TERMS_E_SHAPE_MAX_MEMBERS);      /* 1,001 */
    CHECK(shapes("0004000300100110 03") == GZ_TERMS_E_SHAPE_WIDTH);           /* width 16 */
    CHECK(shapes("0004000300100103 03") == GZ_TERMS_E_SHAPE_WIDTH);           /* width 3 */
    CHECK(shapes("0004000200100104 03") == GZ_TERMS_E_SHAPE_LEAF_KIND);       /* leaf kind 2 */
    CHECK(shapes("0004000400100104 03") == GZ_TERMS_E_SHAPE_LEAF_KIND);       /* leaf kind 4 */
    CHECK(shapes("03e8060404040404 0403") == GZ_TERMS_E_SHAPE_SPLIT);         /* 6 interior: valid size, bad split */
    CHECK(shapes("03e8070404040404 040403") == GZ_TERMS_E_SHAPE_N_INTERIOR);  /* 7 interior */
    CHECK(shapes("0004000300100104") == GZ_TERMS_E_SHAPE_ENCODING);           /* last entry cut */
    CHECK(shapes("00040003001001040300") == GZ_TERMS_E_SHAPE_ENCODING);       /* a stray byte */
    /* Test 18 and T7: draft 1's {4: width 4} and review 3's [4, 3] at 3 members. */
    CHECK(shapes("0004010403 00100104 03") == GZ_TERMS_E_SHAPE_SPLIT);
    /* Only the last n of an entry fails: {16: leaf only}, {17: widths 4, 4}. */
    CHECK(shapes("00040003 00100003 0011020404 03") == GZ_TERMS_E_SHAPE_SPLIT);
    CHECK(shapes("00040003 00130003 0014020404 03") == GZ_TERMS_OK);       /* 20 = 5 + 5 + 5 + 5 */
    CHECK(!gz_tree_split(L4, 1, 3, depths));
    CHECK(!gz_tree_split(L43, 2, 3, depths));
    /* T7 and test 17: for 3..16 the split gives n one-member leaves, D as stated. */
    t1_terms(&t);
    for (n = 3; n <= 16; n++) {
        uint8_t want_D = n <= 8 ? 2 : 3;
        CHECK(gz_tree_params(&t, n, &p) == GZ_TREE_P_OK);
        CHECK(p.D == want_D);
        CHECK(p.n_levels == (n <= 4 ? 1u : 2u));
        CHECK(p.fee_per_tx == (n <= 4 ? 17u : 26u));
        CHECK(p.V == (n <= 4 ? 167u : 253u));
    }
    /* Test 19: the build-server table. */
    CHECK(gz_tree_params(&t, 3, &p) == GZ_TREE_P_OK && p.funding_amount == 802827);
    CHECK(gz_tree_params(&t, 4, &p) == GZ_TREE_P_OK && p.funding_amount == 802827);
    CHECK(gz_tree_params(&t, 5, &p) == GZ_TREE_P_OK && p.funding_amount == 1605586);
    CHECK(gz_tree_params(&t, 8, &p) == GZ_TREE_P_OK && p.funding_amount == 1605586);
    CHECK(gz_tree_params(&t, 16, &p) == GZ_TREE_P_OK && p.funding_amount == 3211970);
    CHECK(gz_tree_params(&t, 2, &p) == GZ_TREE_P_COUNT);
    CHECK(gz_tree_params(&t, 17, &p) == GZ_TREE_P_NO_SHAPE);
    /* R(root) overflow: in the addition, in the multiplication, and just below. */
    {
        static const uint8_t L3[1] = {3};
        uint64_t R;
        static const uint8_t W16[2] = {16, 3}, W15[2] = {15, 3};
        uint8_t dd[40];
        CHECK(!gz_tree_requirement(L3, 1, 1, 0x8000000000000000ull, 0, &R));     /* 2 x channel */
        CHECK(!gz_tree_requirement(L3, 1, 1, 0, 0x8000000000000000ull, &R));     /* 2 x fee */
        CHECK(!gz_tree_requirement(L3, 1, 1, 0x7fffffffffffffffull, 0, &R));
        /* Widths 16 and 3 are not widths (the anchor would be the 17th output). */
        CHECK(!gz_tree_split(W16, 2, 32, dd) && gz_tree_split(W15, 2, 32, dd));
        CHECK(!gz_tree_requirement(W16, 2, 32, 1000, 1, &R) && gz_tree_requirement(W15, 2, 32, 1000, 1, &R));
        CHECK(gz_tree_requirement(L3, 1, 1, 0x7fffffffffffff00ull, 0, &R) && R == 0xffffffffffffffe0ull);
        CHECK(!gz_tree_requirement(L3, 1, 1, 0x7fffffffffffff00ull, 16, &R));
        CHECK(!gz_tree_requirement(L3, 1, 2, 0x7fffffffffffff00ull, 0, &R));
        CHECK(!gz_tree_requirement(L3, 1, 2, 0x3fffffffffffff00ull, 0xffffffffull, &R));
        CHECK(!gz_tree_requirement(L3, 1, 2, 0x3fffffffffffff00ull, 0, &R));   /* the node's + 240 overflows */
        CHECK(gz_tree_requirement(L3, 1, 2, 0x3ffffffffffffe00ull, 0, &R) && R == 0xfffffffffffffcb0ull);
    }
    /* X2's depths. */
    CHECK(gz_tree_params(&t, 3, &p) == GZ_TREE_P_OK && p.depth[0] == 1 && p.depth[1] == 2 && p.depth[2] == 2);
    CHECK(gz_tree_params(&t, 16, &p) == GZ_TREE_P_OK && p.depth[0] == 3 && p.depth[15] == 3);
}

static void test_versions_and_classes(void)
{
    uint8_t a[32] = {1}, b[32] = {2};
    gz_terms_outer_t t;
    gz_terms_current_t c;
    gz_terms_limits_t l;
    uint8_t dig[32];
    /* Test 10 and 11. */
    CHECK(gz_terms_version_rule(0, 0, a, 0, 1, a) == GZ_TERMS_V_ACCEPT);
    CHECK(gz_terms_version_rule(1, 2, a, 0, 1, b) == GZ_TERMS_V_IGNORE_OLDER);
    CHECK(gz_terms_version_rule(1, 2, a, 0, 2, a) == GZ_TERMS_V_DUPLICATE);
    CHECK(gz_terms_version_rule(1, 2, a, 0, 2, b) == GZ_TERMS_V_EQUIVOCATION);
    CHECK(gz_terms_version_rule(1, 2, a, 0, 3, b) == GZ_TERMS_V_ACCEPT);
    CHECK(gz_terms_version_rule(1, 2, a, 1, 3, b) == GZ_TERMS_V_FROZEN_BREACH);
    CHECK(gz_terms_version_rule(1, 2, a, 1, 2, a) == GZ_TERMS_V_DUPLICATE);
    CHECK(gz_terms_version_rule(1, 2, a, 1, 1, b) == GZ_TERMS_V_FROZEN_BREACH);
    /* T6 and test 14. */
    t1_terms(&t);
    unhex(T1_DIGEST, dig, 32);
    memset(&l, 0, sizeof l);
    l.n_max = 3;
    l.max[0].type = 64; l.max[0].max = 1000;
    l.max[1].type = 66; l.max[1].max = 1000;
    l.max[2].type = 68; l.max[2].max = 2500;
    t1_current(dig, 1, 500, 1000, 1000, &c);
    CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_FITS_ONLY_NOW);
    t1_current(dig, 2, 1500, 1000, 1000, &c);
    CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_DOES_NOT_FIT);
    l.max[0].max = 2000;   /* the whole range: fits, whatever the host moves */
    CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_FITS);
    l.max[0].max = 1999;
    t1_current(dig, 1, 1999, 1000, 1000, &c);
    CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_FITS_ONLY_NOW);
    t1_current(dig, 1, 2000, 1000, 1000, &c);
    CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_DOES_NOT_FIT);
    /* Fixed terms. */
    l.max[0].max = 2000;
    l.min_channel_sat = 100000; CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_FITS);
    l.min_channel_sat = 100001; CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_DOES_NOT_FIT);
    l.min_channel_sat = 0; l.max_tree_feerate = 99; CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_DOES_NOT_FIT);
    l.max_tree_feerate = 100; l.profiles = 1u << 3; CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_DOES_NOT_FIT);
    l.profiles = 1u << 2; l.min_members = 4; CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_DOES_NOT_FIT);
    l.min_members = 3; l.min_lifetime = 145; CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_DOES_NOT_FIT);
    l.min_lifetime = 144; l.max_lifetime = 143; CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_DOES_NOT_FIT);
    l.max_lifetime = 144; CHECK(gz_terms_classify(&t, &c, &l) == GZ_TERMS_FITS);
}

/* Target 1,000 needs a shape table reaching 1,000. */
static void test_target_edge(void)
{
    gz_terms_outer_t t, d;
    uint8_t b[GZ_TERMS_OUTER_MAX];
    size_t n;
    t1_terms(&t);
    t.n_shapes = 1;
    t.shapes[0].max_members = 1000; t.shapes[0].n_interior = 0; t.shapes[0].leaf_kind = 3;
    t.target = 1000;
    n = gz_terms_encode_outer(&t, b, sizeof b);
    CHECK(n > 0 && gz_terms_decode_outer(b, n, &SLICE1, &d) == GZ_TERMS_OK);
    t.target = 1001;
    n = gz_terms_encode_outer(&t, b, sizeof b);
    CHECK(n > 0 && gz_terms_decode_outer(b, n, &SLICE1, &d) == GZ_TERMS_E_TARGET);
    /* The encoder refuses what it cannot write. */
    t.target = 8;
    CHECK(gz_terms_encode_outer(&t, b, 100) == 0);
    t.n_shapes = 0;
    CHECK(gz_terms_encode_outer(&t, b, sizeof b) == 0);
}

int main(void)
{
    test_sha256();
    test_target_edge();
    test_vectors();
    test_receive();
    test_encoding_rules();
    test_bounds();
    test_shapes();
    test_versions_and_classes();
    return check_done();
}
