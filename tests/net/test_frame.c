/* BOLT 1: BigSize vectors (Appendix A), TLV vectors (Appendix B) in the n1
 * and n2 namespaces, message extensions (Appendix C), message framing, the
 * TLV writer, and a randomised comparison with an independent model. */
#include <stdlib.h>
#include <secp256k1.h>
#include "../check.h"
#include "hex.h"
#include "frame.h"

static secp256k1_context *secp;
static uint8_t S[4096];

/* --- the two test namespaces of Appendix B, written from the text -------- */
static int c_tu64(const gz_tlv_record_t *r, void *x) { uint64_t v; (void)x; return gz_tu_read(r->value, r->len, 8, &v) == 0; }
static int c_tu32(const gz_tlv_record_t *r, void *x) { uint64_t v; (void)x; return gz_tu_read(r->value, r->len, 4, &v) == 0; }
static int c_scid(const gz_tlv_record_t *r, void *x) { (void)x; return r->len == 8; }
static int c_u16(const gz_tlv_record_t *r, void *x) { (void)x; return r->len == 2; }
static int c_tlv3(const gz_tlv_record_t *r, void *x)
{
    secp256k1_pubkey pk;
    (void)x;
    return r->len == 49 && (r->value[0] == 2 || r->value[0] == 3) &&
           secp256k1_ec_pubkey_parse(secp, &pk, r->value, 33);
}
static const gz_tlv_known_t N1[] = {{1, c_tu64}, {2, c_scid}, {3, c_tlv3}, {254, c_u16}};
static const gz_tlv_known_t N2[] = {{0, c_tu64}, {11, c_tu32}};

static gz_frame_err_t parse(const char *hex, const gz_tlv_known_t *k, size_t nk, gz_tlv_record_t *rec, size_t *n)
{
    size_t len = unhex(hex, S, sizeof S);
    if (len == (size_t)-1) { printf("bad hex in test: %s\n", hex); return GZ_FRAME_INVALID; }
    return gz_tlv_parse(S, len, k, nk, NULL, rec, 8, n);
}

static int fails(const char *hex, const gz_tlv_known_t *k, size_t nk)
{
    gz_tlv_record_t rec[8];
    size_t n;
    return parse(hex, k, nk, rec, &n) != GZ_FRAME_OK;
}

static void test_bigsize(void)
{
    static const struct { const char *hex; uint64_t v; gz_frame_err_t err; } dec[] = {
        {"00", 0, 0}, {"fc", 252, 0}, {"fd00fd", 253, 0}, {"fdffff", 65535, 0},
        {"fe00010000", 65536, 0}, {"feffffffff", 4294967295ULL, 0},
        {"ff0000000100000000", 4294967296ULL, 0}, {"ffffffffffffffffff", 18446744073709551615ULL, 0},
        {"fd00fc", 0, GZ_FRAME_NONCANONICAL}, {"fe0000ffff", 0, GZ_FRAME_NONCANONICAL},
        {"ff00000000ffffffff", 0, GZ_FRAME_NONCANONICAL},
        {"fd00", 0, GZ_FRAME_TRUNCATED}, {"feffff", 0, GZ_FRAME_TRUNCATED}, {"ffffffffff", 0, GZ_FRAME_TRUNCATED},
        {"", 0, GZ_FRAME_EOF}, {"fd", 0, GZ_FRAME_TRUNCATED}, {"fe", 0, GZ_FRAME_TRUNCATED}, {"ff", 0, GZ_FRAME_TRUNCATED},
    };
    size_t i;
    int vectors = 0;
    for (i = 0; i < sizeof dec / sizeof dec[0]; i++) {
        uint8_t b[16], out[9];
        uint64_t v = 12345;
        size_t len = unhex(dec[i].hex, b, sizeof b), used = 0;
        gz_frame_err_t e = gz_bigsize_read(b, len, &v, &used);
        CHECK(e == dec[i].err);
        if (dec[i].err == 0) {
            CHECK(v == dec[i].v && used == len);
            /* the eight encoding vectors are the eight valid decoding ones */
            CHECK(gz_bigsize_write(dec[i].v, out) == len && memcmp(out, b, len) == 0);
        }
        vectors++;
    }
    CHECK(vectors == 18);
}

static void test_tlv_failures(void)
{
    static const char *any[] = {
        "fd", "fd01", "fd000100", "fd0101", "0ffd", "0ffd26", "0ffd2602", "0ffd000100",
        NULL /* value truncated: built below */,
        "1200", "fd010200", "fe0100000200", "ff010000000000000200",
    };
    static const char *n1[] = {
        "0109ffffffffffffffffff", "010100", "01020001", "0103000100", "010400010000", "01050001000000",
        "0106000100000000", "010700010000000000", "01080001000000000000", "020701010101010101",
        "0209010101010101010101",
        "0321023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb",
        "0329023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001",
        "0330023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb000000000000000100000000000001",
        "0331043da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002",
        "0332023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001000000000000000001",
        "fd00fe00", "fd00fe0101", "fd00fe03010101", "0000",
        /* stream failures */
        "0208000000000000022601012a", "0208000000000000023102080000000000000451", "1f000f012a", "1f001f012a",
    };
    static char truncated[8 + 2 * 512 + 1];
    size_t i;
    memcpy(truncated, "0ffd0201", 8);
    memset(truncated + 8, '0', 2 * 512); /* 512 of the 513 bytes */
    truncated[8 + 2 * 512] = 0;
    any[8] = truncated;
    for (i = 0; i < sizeof any / sizeof any[0]; i++) {
        CHECK(fails(any[i], N1, 4));
        CHECK(fails(any[i], N2, 2));
    }
    for (i = 0; i < sizeof n1 / sizeof n1[0]; i++) CHECK(fails(n1[i], N1, 4));
    CHECK(fails("ffffffffffffffffff000000", N2, 2));
    /* Specific reasons for a few, so a wrong reason is noticed too. */
    {
        gz_tlv_record_t r[8];
        size_t n;
        CHECK(parse("fd000100", N1, 4, r, &n) == GZ_FRAME_NONCANONICAL);
        CHECK(parse("0ffd000100", N1, 4, r, &n) == GZ_FRAME_NONCANONICAL);
        CHECK(parse("1200", N1, 4, r, &n) == GZ_FRAME_UNKNOWN_EVEN);
        CHECK(parse("0000", N1, 4, r, &n) == GZ_FRAME_UNKNOWN_EVEN);
        CHECK(parse("1f000f012a", N1, 4, r, &n) == GZ_FRAME_ORDER);
        CHECK(parse("1f001f012a", N1, 4, r, &n) == GZ_FRAME_ORDER);
        CHECK(parse("0ffd2602", N1, 4, r, &n) == GZ_FRAME_TRUNCATED);
        CHECK(parse("fd0101", N1, 4, r, &n) == GZ_FRAME_TRUNCATED);
        CHECK(parse("010100", N1, 4, r, &n) == GZ_FRAME_INVALID);
        CHECK(n == 0);
    }
}

typedef struct { const char *hex; uint64_t type; } valid_t;
static const valid_t VALID_ANY[] = {
    {"2100", 0x21}, {"fd020100", 0x201}, {"fd00fd00", 0xfd}, {"fd00ff00", 0xff},
    {"fe0200000100", 0x2000001}, {"ff020000000000000100", 0x200000000000001ULL},
};
static const valid_t VALID_N1[] = {
    {"0100", 1}, {"010101", 1}, {"01020100", 1}, {"0103010000", 1}, {"010401000000", 1},
    {"01050100000000", 1}, {"0106010000000000", 1}, {"010701000000000000", 1}, {"01080100000000000000", 1},
    {"02080000000000000226", 2},
    {"0331023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002", 3},
    {"fd00fe020226", 254},
};

static void test_tlv_successes(void)
{
    static const uint64_t amounts[] = {0, 1, 256, 65536, 16777216, 4294967296ULL, 1099511627776ULL,
                                       281474976710656ULL, 72057594037927936ULL};
    gz_tlv_record_t r[8];
    size_t i, n;
    uint64_t v;
    CHECK(parse("", N1, 4, r, &n) == GZ_FRAME_OK && n == 0);
    CHECK(parse("", N2, 2, r, &n) == GZ_FRAME_OK && n == 0);
    for (i = 0; i < sizeof VALID_ANY / sizeof VALID_ANY[0]; i++) {
        CHECK(parse(VALID_ANY[i].hex, N1, 4, r, &n) == GZ_FRAME_OK && n == 0);
        CHECK(parse(VALID_ANY[i].hex, N2, 2, r, &n) == GZ_FRAME_OK && n == 0);
    }
    for (i = 0; i < 9; i++) {
        CHECK(parse(VALID_N1[i].hex, N1, 4, r, &n) == GZ_FRAME_OK && n == 1 && r[0].type == 1);
        CHECK(n == 1 && gz_tu_read(r[0].value, r[0].len, 8, &v) == 0 && v == amounts[i]);
    }
    CHECK(parse(VALID_N1[9].hex, N1, 4, r, &n) == GZ_FRAME_OK && n == 1 && r[0].type == 2);
    CHECK(n == 1 && eqhex(r[0].value, r[0].len, "0000000000000226")); /* scid 0x0x550 */
    CHECK(parse(VALID_N1[10].hex, N1, 4, r, &n) == GZ_FRAME_OK && n == 1 && r[0].type == 3);
    CHECK(n == 1 && eqhex(r[0].value, 33, "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"));
    CHECK(n == 1 && eqhex(r[0].value + 33, 8, "0000000000000001") && eqhex(r[0].value + 41, 8, "0000000000000002"));
    CHECK(parse(VALID_N1[11].hex, N1, 4, r, &n) == GZ_FRAME_OK && n == 1 && r[0].type == 254);
    CHECK(n == 1 && r[0].value[0] == 0x02 && r[0].value[1] == 0x26); /* cltv_delta 550 */
}

/* "Any appending of an invalid stream to a valid stream should trigger a
 * decoding failure. Any appending of a higher-numbered valid stream to a
 * lower-numbered valid stream should not." */
static void test_tlv_appending(void)
{
    static const char *invalid_n1[] = {"fd", "fd01", "fd000100", "fd0101", "0ffd", "0ffd2602", "1200",
                                       "010100", "020701010101010101", "fd00fe00", "0000", "1f000f012a"};
    valid_t all[18];
    size_t i, j, nv = 0, pairs = 0;
    char buf[512];
    for (i = 0; i < 6; i++) all[nv++] = VALID_ANY[i];
    for (i = 0; i < 12; i++) all[nv++] = VALID_N1[i];
    for (i = 0; i < nv; i++)
        for (j = 0; j < sizeof invalid_n1 / sizeof invalid_n1[0]; j++) {
            snprintf(buf, sizeof buf, "%s%s", all[i].hex, invalid_n1[j]);
            CHECK(fails(buf, N1, 4));
        }
    for (i = 0; i < nv; i++)
        for (j = 0; j < nv; j++) {
            snprintf(buf, sizeof buf, "%s%s", all[i].hex, all[j].hex);
            if (all[i].type < all[j].type) { CHECK(!fails(buf, N1, 4)); pairs++; }
            else CHECK(fails(buf, N1, 4));
        }
    CHECK(pairs > 100);
}

/* Appendix C: init = type 16, u16 gflen, gflen bytes, u16 flen, flen bytes, TLVs. */
static int init_ok(const char *hex)
{
    static const gz_tlv_known_t init_known[] = {{1, NULL}, {3, NULL}};
    uint8_t b[64];
    size_t len = unhex(hex, b, sizeof b), rl, p, n;
    const uint8_t *rest;
    uint16_t type;
    gz_tlv_record_t r[4];
    if (gz_msg_parse(b, len, &type, &rest, &rl) || type != 16) return 0;
    if (rl < 2) return 0;
    p = 2 + (size_t)(rest[0] << 8 | rest[1]);
    if (rl < p + 2) return 0;
    p += 2 + (size_t)(rest[p] << 8 | rest[p + 1]);
    if (rl < p) return 0;
    return gz_tlv_parse(rest + p, rl - p, init_known, 2, NULL, r, 4, &n) == GZ_FRAME_OK;
}

static void test_message_extension(void)
{
    CHECK(init_ok("001000000000"));
    CHECK(init_ok("001000000000c9012acb0104"));
    CHECK(!init_ok("00100000000001"));
    CHECK(!init_ok("001000000000ca012a"));
    CHECK(!init_ok("001000000000c90101c90102"));
}

static uint8_t big[65537];

static void test_messages_and_writer(void)
{
    uint8_t out[64], t[8];
    const uint8_t *rest;
    size_t rl, n;
    uint16_t type;
    uint64_t v;
    gz_tlv_writer_t w;
    CHECK(gz_msg_parse(big, 0, &type, &rest, &rl) == GZ_FRAME_TRUNCATED);
    CHECK(gz_msg_parse(big, 1, &type, &rest, &rl) == GZ_FRAME_TRUNCATED);
    CHECK(gz_msg_parse(big, 65536, &type, &rest, &rl) == GZ_FRAME_TOO_BIG);
    big[0] = 0x80; big[1] = 0x01;
    CHECK(gz_msg_parse(big, 65535, &type, &rest, &rl) == GZ_FRAME_OK && type == 32769 && rl == 65533 && rest == big + 2);
    CHECK(gz_msg_parse(big, 2, &type, &rest, &rl) == GZ_FRAME_OK && rl == 0);
    CHECK(gz_msg_write(32769, (const uint8_t *)"ab", 2, out, sizeof out, &n) == GZ_FRAME_OK && eqhex(out, n, "80016162"));
    CHECK(gz_msg_write(1, NULL, 0, out, 1, &n) == GZ_FRAME_TOO_BIG);
    CHECK(gz_msg_write(1, big, 65534, big, sizeof big, &n) == GZ_FRAME_TOO_BIG);
    CHECK(gz_msg_write(1, big, 65533, big, sizeof big, &n) == GZ_FRAME_OK && n == 65535);
    CHECK(gz_msg_unknown_action(32769) == GZ_MSG_IGNORE && gz_msg_unknown_action(32768) == GZ_MSG_CLOSE);
    CHECK(gz_msg_unknown_action(0) == GZ_MSG_CLOSE && gz_msg_unknown_action(1) == GZ_MSG_IGNORE);
    CHECK(gz_msg_unknown_action(65535) == GZ_MSG_IGNORE && gz_msg_unknown_action(65534) == GZ_MSG_CLOSE);

    /* Truncated integers. */
    CHECK(gz_tu_write(0, t) == 0 && gz_tu_write(1, t) == 1 && gz_tu_write(256, t) == 2);
    CHECK(gz_tu_write(UINT64_MAX, t) == 8 && all_zero(t, 0) && t[0] == 0xff && t[7] == 0xff);
    CHECK(gz_tu_write(0x0102030405ULL, t) == 5 && eqhex(t, 5, "0102030405"));
    CHECK(gz_tu_read((const uint8_t *)"\x01\x00\x00\x00\x00", 5, 4, &v) == GZ_FRAME_INVALID);
    CHECK(gz_tu_read((const uint8_t *)"\x01\x00\x00\x00", 4, 4, &v) == GZ_FRAME_OK && v == 0x01000000);
    CHECK(gz_tu_read((const uint8_t *)"\x00\x01", 2, 8, &v) == GZ_FRAME_NONCANONICAL);
    CHECK(gz_tu_read(NULL, 0, 8, &v) == GZ_FRAME_OK && v == 0);

    /* Writer: the n1 vectors in order make their concatenation. */
    gz_tlv_writer_init(&w, out, sizeof out);
    CHECK(gz_tlv_put(&w, 1, (const uint8_t *)"\x01\x00", 2) == GZ_FRAME_OK);
    CHECK(gz_tlv_put(&w, 2, (const uint8_t *)"\x00\x00\x00\x00\x00\x00\x02\x26", 8) == GZ_FRAME_OK);
    CHECK(gz_tlv_put(&w, 254, (const uint8_t *)"\x02\x26", 2) == GZ_FRAME_OK);
    CHECK(gz_tlv_put(&w, 0x21, NULL, 0) == GZ_FRAME_ORDER);
    CHECK(gz_tlv_put(&w, 255, NULL, 0) == GZ_FRAME_ORDER); /* sticky */
    CHECK(eqhex(out, w.len, "0102010002080000000000000226fd00fe020226"));
    gz_tlv_writer_init(&w, out, sizeof out);
    CHECK(gz_tlv_put(&w, 5, NULL, 0) == GZ_FRAME_OK && gz_tlv_put(&w, 5, NULL, 0) == GZ_FRAME_ORDER);
    gz_tlv_writer_init(&w, out, 4);
    CHECK(gz_tlv_put(&w, 1, (const uint8_t *)"ab", 2) == GZ_FRAME_OK && w.len == 4);
    CHECK(gz_tlv_put(&w, 3, NULL, 0) == GZ_FRAME_TOO_BIG && w.len == 4);
    gz_tlv_writer_init(&w, out, 4);
    CHECK(gz_tlv_put(&w, 1, (const uint8_t *)"abc", 3) == GZ_FRAME_TOO_BIG && w.len == 0);
    gz_tlv_writer_init(&w, big, sizeof big);
    CHECK(gz_tlv_put(&w, 0xffffffffffffffffULL, S, 300) == GZ_FRAME_OK && w.len == 9 + 3 + 300);
    CHECK(eqhex(big, 12, "ffffffffffffffffff fd012c"));
    /* More known records than room for them. */
    {
        gz_tlv_record_t r[1];
        size_t len = unhex("01000208000000000000022", S, sizeof S);
        CHECK(len == (size_t)-1); /* odd digit count is refused by the helper */
        len = unhex("010002080000000000000226", S, sizeof S);
        CHECK(gz_tlv_parse(S, len, N1, 4, NULL, r, 1, &n) == GZ_FRAME_TOO_MANY);
    }
}

/* --- randomised comparison with an independent model --------------------
 * The generator builds a stream record by record from the rules of BOLT 1
 * and the n1 namespace, so it knows the right answer: which records the
 * reader must return, in order, or that it must fail. */
static uint64_t rs = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

typedef struct { uint64_t type; uint8_t val[64]; size_t len; } mrec_t;

static int n1_known(uint64_t t) { return t == 1 || t == 2 || t == 3 || t == 254; }

static size_t put_record(uint8_t *s, const mrec_t *m, int noncanonical_len)
{
    size_t p = gz_bigsize_write(m->type, s);
    if (noncanonical_len) { s[p] = 0xfd; s[p + 1] = 0; s[p + 2] = (uint8_t)m->len; p += 3; }
    else p += gz_bigsize_write(m->len, s + p);
    memcpy(s + p, m->val, m->len);
    return p + m->len;
}

/* A valid value for the type: n1's encodings, or random bytes if unknown. */
static void fill_value(mrec_t *x)
{
    static const uint8_t point[33] = {0x02, 0x3d, 0xa0, 0x92, 0xf6, 0x98, 0x0e, 0x58, 0xd2, 0xc0, 0x37, 0x17,
                                      0x31, 0x80, 0xe9, 0xa4, 0x65, 0x47, 0x60, 0x26, 0xee, 0x50, 0xf9, 0x66,
                                      0x95, 0x96, 0x3e, 0x8e, 0xfe, 0x43, 0x6f, 0x54, 0xeb};
    size_t i;
    if (x->type == 1) { x->len = gz_tu_write(rnd() >> (rnd() % 64), x->val); return; }
    x->len = x->type == 2 ? 8 : x->type == 3 ? 49 : x->type == 254 ? 2 : rnd() % 20;
    for (i = 0; i < x->len; i++) x->val[i] = (uint8_t)rnd();
    if (x->type == 3) memcpy(x->val, point, 33);
}

enum { F_NONE, F_NONE2, F_SWAP, F_DUP, F_EVEN, F_NONCANON, F_SIZE, F_CUT, F_COUNT };

static void test_tlv_model(int rounds)
{
    static const uint64_t known[] = {1, 2, 3, 254};
    int round, agree = 0, faulty = 0;
    for (round = 0; round < rounds; round++) {
        mrec_t m[9];
        gz_tlv_record_t r[8];
        size_t nm = 1 + rnd() % 6, i, k, len = 0, n = 0, last_start = 0;
        uint64_t prev = 0;
        int fault = (int)(rnd() % F_COUNT), expect_ok = fault <= F_NONE2, ok, same = 1;
        memset(m, 0, sizeof m);
        for (i = 0; i < nm; i++) {
            uint64_t t = known[rnd() % 4];
            if (rnd() % 2 || (i && t <= prev)) t = (i ? prev + 1 : 0) + rnd() % (rnd() % 4 ? 40 : 100000);
            if (!n1_known(t) && (t & 1) == 0) t++;
            m[i].type = prev = t;
            fill_value(&m[i]);
        }
        if (fault == F_SWAP && nm >= 2) { mrec_t t = m[nm - 1]; m[nm - 1] = m[nm - 2]; m[nm - 2] = t; }
        if (fault == F_DUP || (fault == F_SWAP && nm < 2)) { m[nm] = m[nm - 1]; nm++; }
        if (fault == F_EVEN) {
            uint64_t t = nm >= 2 ? m[nm - 2].type + 1 : 0;
            if (t & 1) t++;
            while (n1_known(t)) t += 2;
            m[nm - 1].type = t;
        }
        if (fault == F_SIZE) {
            uint64_t before = nm >= 2 ? m[nm - 2].type : 0;
            if (nm == 1 || before < 2) { m[nm - 1].type = 2; m[nm - 1].len = rnd() % 2 ? 7 : 9; }
            else if (before < 254) { m[nm - 1].type = 254; m[nm - 1].len = rnd() % 2 ? 1 : 3; }
            else fault = F_NONCANON;
        }
        for (i = 0; i < nm; i++) {
            last_start = len;
            len += put_record(S + len, &m[i], fault == F_NONCANON && i == nm - 1);
        }
        if (fault == F_CUT) len -= 1 + rnd() % (len - last_start - 1);
        ok = gz_tlv_parse(S, len, N1, 4, NULL, r, 8, &n) == GZ_FRAME_OK;
        if (ok && expect_ok) {
            for (i = 0, k = 0; i < nm; i++) {
                if (!n1_known(m[i].type)) continue;
                if (k >= n || r[k].type != m[i].type || r[k].len != m[i].len || memcmp(r[k].value, m[i].val, m[i].len))
                    same = 0;
                k++;
            }
            if (k != n) same = 0;
        }
        if (ok != expect_ok || !same)
            printf("model and reader disagree: round %d fault %d (model %d, reader %d)\n", round, fault, expect_ok, ok);
        else
            agree++;
        faulty += !expect_ok;
    }
    CHECK(agree == rounds);
    CHECK(faulty > rounds / 2); /* the faults were really made */
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 20000;
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    test_bigsize();
    test_tlv_failures();
    test_tlv_successes();
    test_tlv_appending();
    test_message_extension();
    test_messages_and_writer();
    test_tlv_model(rounds);
    secp256k1_context_destroy(secp);
    return check_done();
}
