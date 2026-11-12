/* The factory message envelope (spec/messages.md sections 3 to 5, 10, 11
 * and tests 1 to 14): vectors M0 to M3 byte for byte, the record tables of
 * every kind at every limit (the tables below are written from the
 * specification, not copied from envelope.c), and splitting. */
#include <stdlib.h>
#include <string.h>
#include <secp256k1.h>
#include "../check.h"
#include "hex.h"
#include "envelope.h"
#include "frame.h"

static secp256k1_context *secp;

/* M1, messages.md section 11. */
static const char *M1 =
    "ce37677a6601001675e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2"
    "022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2"
    "040400000001"
    "0620d1db6ddfd5a2c12ae197036f285457ae6ceaf468c2a47fb71691dde4b1153942"
    "f0407eb07e7116d893db0aa57ca3c88fd1b7c67aeb5a0772923c08a4f10350197cbc"
    "08c19ce8d566df618ab0df88d9773f5089c63b83d4fc99636a5ba7f433762627";
static const char *M1_HASH = "683a9673360b942f37224c92dfeb58765fc9085e14bae4c6120b46c5be42f8d0";
static const char *M1_KEY = "024322bd904fa9770421b0b48f08e961d473f3ee9a36a5bc85fa3cac30fa2e15ae";
static const char *M3_HEAD = "80200004" "0020c3a082d0fcb768d76999f4f8ad672f7110fbef6a13a1697686c7073961c842f1" "fd0400ae";
static const char *M0 = "80200002fd020020c3a082d0fcb768d76999f4f8ad672f7110fbef6a13a1697686c7073961c842f1";
static const char *M2_TID = "fcb2c91358d5559e25feace2ed8a1562324ec95032f4c514435b5bd2f152a668";
static const char *T1_DIGEST = "75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2";

static uint8_t SCOPE[32];

/* Writes one part, naming the transfer from the body. */
static int wp(uint16_t inner, const uint8_t *scope, const uint8_t *b, size_t len, unsigned index, uint8_t *out,
              size_t cap, size_t *n)
{
    uint8_t tid[32];
    gz_env_transfer_id(secp, inner, b, len, tid);
    return gz_env_write_part(tid, inner, scope, b, len, index, out, cap, n);
}
static const uint8_t ZERO[32];

static uint8_t big[2 << 20], msg[70000], msg2[70000];

static int hex_eq(const uint8_t *p, size_t n, const char *h)
{
    static uint8_t want[1 << 16];
    size_t wn = unhex(h, want, sizeof want);
    return wn == n && memcmp(p, want, n) == 0;
}

static void test_vectors(void)
{
    uint8_t m1[200], out[400], h[32], key[33];
    size_t n = unhex(M1, m1, sizeof m1), on;
    gz_env_msg_t m;
    gz_env_record_t rec[8];
    int nr;
    CHECK(n == 180);
    /* M1 reads as a ready (kind 22) for lobby T1, at the host. */
    CHECK(gz_env_read(m1, n, GZ_ENV_AT_HOST, &m, NULL) == GZ_ENV_DELIVER);
    CHECK(m.kind == GZ_ENV_KIND_READY && hex_eq(m.scope, 32, T1_DIGEST));
    nr = gz_env_records(m.records, m.records_len, rec, 8);
    CHECK(nr == 4 && rec[0].type == 2 && rec[1].type == 4 && rec[2].type == 6 && rec[3].type == 240);
    CHECK(gz_env_msg_hash(secp, &m, h) && hex_eq(h, 32, M1_HASH));
    unhex(M1_KEY, key, 33);
    CHECK(gz_env_verify(secp, &m, key));
    key[5] ^= 1;
    CHECK(!gz_env_verify(secp, &m, key));
    /* Encoding it again gives the same bytes. */
    CHECK(gz_env_write(m.kind, m.scope, m.records, m.records_len, out, sizeof out, &on) == 0);
    CHECK(on == n && memcmp(out, m1, n) == 0);
    /* M3: M1 through the bLIP-56 adapter, and back. */
    CHECK(gz_env_blip56_wrap(m1, n, out, sizeof out, &on) == 0);
    CHECK(on == 216 && hex_eq(out, 42, M3_HEAD) && memcmp(out + 42, m1 + 6, 174) == 0);
    CHECK(gz_env_blip56_unwrap(out, on, msg, sizeof msg, &n) == 0 && n == 180 && memcmp(msg, m1, 180) == 0);
    /* An adapter message with another protocol id, or without TLV 1024. */
    out[10] ^= 1;
    CHECK(gz_env_blip56_unwrap(out, on, msg, sizeof msg, &n) != 0);
    out[10] ^= 1;
    CHECK(gz_env_blip56_unwrap(out, 38, msg, sizeof msg, &n) != 0);
    /* M0. */
    CHECK(gz_env_blip56_supported(out, sizeof out, &on) == 0 && on == 40 && hex_eq(out, on, M0));
    /* The type is 52791 and the tag 67 7a 66 01. */
    CHECK(GZ_ENV_TYPE == 0xce37 && GZ_ENV_PROTOCOL[0] == 0x67 && GZ_ENV_PROTOCOL[3] == 1);
}

/* M2: a 76,800-byte body of kind 68 in two parts of 65,000 and 11,800 bytes
 * of data, messages of 65,096 and 11,896 bytes. */
static void test_m2(void)
{
    size_t i, n0, n1;
    uint8_t tid[32];
    for (i = 0; i < 76800; i++) big[i] = (uint8_t)i;
    CHECK(gz_env_part_count(76800) == 2);
    CHECK(wp(68, SCOPE, big, 76800, 0, msg, sizeof msg, &n0) == 0 && n0 == 65096);
    CHECK(wp(68, SCOPE, big, 76800, 1, msg2, sizeof msg2, &n1) == 0 && n1 == 11896);
    CHECK(wp(68, SCOPE, big, 76800, 2, msg2, sizeof msg2, &n1) != 0);
    /* Header: type, tag, kind 2, scope; then records 2, 4, 6, 8, 10, 12. */
    CHECK(msg[0] == 0xce && msg[1] == 0x37 && msg[6] == 0 && msg[7] == 2 && memcmp(msg + 8, SCOPE, 32) == 0);
    CHECK(msg[40] == 2 && msg[41] == 32 && hex_eq(msg + 42, 32, M2_TID));
    CHECK(hex_eq(msg + 74, 4, "04020044") && hex_eq(msg + 78, 6, "060400012c00"));
    CHECK(hex_eq(msg + 84, 4, "08020000") && hex_eq(msg + 88, 4, "0a020002") && hex_eq(msg + 92, 4, "0cfdfde8"));
    CHECK(memcmp(msg + 96, big, 65000) == 0);
    CHECK(hex_eq(msg2 + 84, 4, "08020001") && hex_eq(msg2 + 92, 4, "0cfd2e18") && memcmp(msg2 + 96, big + 65000, 11800) == 0);
    /* transfer_id = TH("gazpacho/part", u16 68 || body). */
    memmove(big + 2, big, 76800);
    big[0] = 0;
    big[1] = 68;
    gz_env_tagged_hash(secp, "gazpacho/part", big, 76802, tid);
    CHECK(hex_eq(tid, 32, M2_TID));
}

/* ------------------------------------------- the record tables, from the spec */

typedef struct {
    uint16_t type;
    uint32_t lo, hi;  /* bytes, or entries for a list */
    uint16_t entry;   /* bytes per entry for a list, else 0 */
    int req;
} trec;

typedef struct {
    uint16_t kind;
    int dir;          /* 1 host to member, 2 member to host, 3 either */
    int n;
    trec r[26];
} tkind;

#define F(t, n, q) {t, n, n, 0, q}
#define S F(240, 64, 1)
static const tkind TK[] = {
    {16, 2, 0, {{0}}},
    {18, 1, 4, {{2, 1, 4096, 0, 1}, F(4, 64, 1), {6, 1, 1024, 0, 1}, F(8, 64, 1)}},
    {20, 2, 4, {F(2, 33, 1), F(4, 64, 1), F(6, 64, 1), {7, 1, 32, 0, 0}}},
    {22, 2, 6, {F(2, 32, 1), F(4, 4, 1), F(6, 32, 1), F(8, 32, 0), F(11, 2, 0), S}},
    {24, 2, 1, {F(1, 2, 0)}},
    {26, 2, 1, {F(1, 2, 0)}},
    {28, 1, 6, {F(2, 1, 1), F(4, 1, 1), F(6, 4, 1), F(8, 2, 1), F(10, 2, 1), F(13, 2, 0)}},
    {30, 1, 5, {F(2, 32, 1), F(4, 4, 1), F(6, 32, 1), F(8, 4, 1), S}},
    {32, 1, 4, {F(2, 32, 1), F(4, 1, 1), F(6, 2, 1), S}},
    {34, 1, 2, {F(2, 2, 1), S}},
    {64, 1, 25, {F(2, 32, 1), F(4, 32, 1), F(6, 1, 1), F(7, 2, 0), F(8, 4, 1), F(10, 32, 1), F(12, 36, 1),
                 F(14, 8, 1), F(16, 34, 1), {18, 60, 100000, 0, 1}, {20, 2, 1001, 194, 1}, {22, 1, 8, 4, 1},
                 F(24, 4, 1), F(28, 1, 1), F(30, 8, 1), F(32, 4, 1), {34, 0, 4096, 36, 1}, F(36, 1, 1),
                 F(38, 1, 1), F(40, 2, 1), F(42, 2, 1), F(46, 32, 1), F(48, 4, 1), F(50, 4, 1), S}},
    {66, 2, 3, {F(2, 32, 1), F(4, 1, 1), {6, 1, 256, 134, 1}}},
    {68, 1, 3, {F(2, 32, 1), F(4, 1, 1), {6, 0, 0, 0, 1}}}, /* items: tested on their own below */
    {70, 2, 4, {F(2, 32, 1), F(4, 1, 1), {6, 1, 256, 68, 1}, S}},
    {72, 1, 4, {F(2, 32, 1), F(4, 1, 1), {6, 1, 256, 68, 1}, S}},
    {74, 1, 2, {F(2, 32, 1), S}},
    {76, 2, 3, {F(2, 32, 1), F(4, 32, 1), S}},
    {78, 3, 6, {F(2, 32, 1), F(4, 2, 1), {7, 1, 256, 0, 0}, F(9, 1, 0), {11, 1, 256, 4, 0}, S}},
    {80, 2, 1, {F(2, 32, 1)}},
    {81, 1, 1, {F(2, 32, 1)}},
};

/* One record's value length for a variant. */
static size_t base_len(const trec *r)
{
    if (r->entry) return (size_t)r->entry * r->lo;
    if (r->type == 6 && r->hi == 0) return 136; /* one round_all_nonces item with one signer */
    return r->lo;
}

static uint8_t body[1 << 20];

/* Writes the records of kind k; `skip` leaves one out, `over` gives record
 * `over_ix` the length `over_len`, `all` includes the optional ones, and
 * `extra_type` (if nonzero) adds a record of that type and 3 bytes. */
static size_t build(const tkind *k, int all, int skip, int over_ix, size_t over_len, uint64_t extra_type)
{
    gz_tlv_writer_t w;
    static uint8_t val[200000];
    int i, extra_done = extra_type == 0;
    memset(val, 'A', sizeof val);
    gz_tlv_writer_init(&w, body, sizeof body);
    for (i = 0; i < k->n; i++) {
        const trec *r = &k->r[i];
        size_t len = i == over_ix ? over_len : base_len(r);
        if (!extra_done && extra_type < r->type) {
            gz_tlv_put(&w, extra_type, val, 3);
            extra_done = 1;
        }
        if (i == skip || (!r->req && !all)) continue;
        if (r->type == 6 && r->hi == 0) {
            /* index 0, one signer, nonce and signature */
            memset(val, 0, 6);
            val[5] = 1;
            gz_tlv_put(&w, 6, val, len);
            memset(val, 'A', 6);
            continue;
        }
        gz_tlv_put(&w, r->type, val, len);
    }
    if (!extra_done) gz_tlv_put(&w, extra_type, val, 3);
    CHECK(w.err == GZ_FRAME_OK);
    return w.len;
}

static gz_env_side_t side_of(const tkind *k)
{
    return k->dir == 1 ? GZ_ENV_AT_MEMBER : GZ_ENV_AT_HOST;
}

static void test_tables(void)
{
    size_t ki;
    for (ki = 0; ki < sizeof TK / sizeof TK[0]; ki++) {
        const tkind *k = &TK[ki];
        gz_env_side_t at = side_of(k), wrong = at == GZ_ENV_AT_HOST ? GZ_ENV_AT_MEMBER : GZ_ENV_AT_HOST;
        size_t n;
        int i, failures_before = check_failures;
        int is_signed = k->n && k->r[k->n - 1].type == 240;
        /* Required records only, then everything. */
        n = build(k, 0, -1, -1, 0, 0);
        CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_DELIVER);
        n = build(k, 1, -1, -1, 0, 0);
        CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_DELIVER);
        /* The direction rule, except for round_abort (either way). */
        CHECK(gz_env_check(k->kind, SCOPE, body, n, wrong, NULL) == (k->dir == 3 ? GZ_ENV_DELIVER : GZ_ENV_REFUSE));
        /* An all-zero scope only in hello. */
        CHECK(gz_env_check(k->kind, ZERO, body, n, at, NULL) == (k->kind == 16 ? GZ_ENV_DELIVER : GZ_ENV_REFUSE));
        /* An unknown even record is refused; an unknown odd one skipped. */
        n = build(k, 1, -1, -1, 0, 238);
        CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_REFUSE);
        n = build(k, 1, -1, -1, 0, 239);
        CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_DELIVER);
        /* Nothing after the signature, even odd; an unsigned kind does not
         * know record 240 at all. */
        n = build(k, 1, -1, -1, 0, 241);
        CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == (is_signed ? GZ_ENV_REFUSE : GZ_ENV_DELIVER));
        if (!is_signed) {
            n = build(k, 1, -1, -1, 0, 240);
            CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_REFUSE);
        }
        for (i = 0; i < k->n; i++) {
            const trec *r = &k->r[i];
            /* Each required record missing. */
            if (r->req) {
                n = build(k, 1, i, -1, 0, 0);
                CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_REFUSE);
            }
            if (r->type == 6 && r->hi == 0) continue;
            if (r->entry) {
                /* A list: one byte off a whole entry, the bounds, one past each. */
                n = build(k, 1, -1, i, (size_t)r->entry * r->lo + 1, 0);
                CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_REFUSE);
                n = build(k, 1, -1, i, (size_t)r->entry * r->hi, 0);
                CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_DELIVER);
                n = build(k, 1, -1, i, (size_t)r->entry * (r->hi + 1), 0);
                CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_REFUSE);
                if (r->lo > 0) {
                    n = build(k, 1, -1, i, (size_t)r->entry * (r->lo - 1), 0);
                    CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_REFUSE);
                }
            } else {
                /* A size: one byte short and one long, and the upper bound. */
                n = build(k, 1, -1, i, r->hi, 0);
                CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_DELIVER);
                n = build(k, 1, -1, i, r->hi + 1, 0);
                CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_REFUSE);
                n = build(k, 1, -1, i, r->lo - 1, 0);
                CHECK(gz_env_check(k->kind, SCOPE, body, n, at, NULL) == GZ_ENV_REFUSE);
            }
        }
        if (check_failures != failures_before) printf("  (in kind %u)\n", (unsigned)k->kind);
    }
}

static void test_special_records(void)
{
    gz_tlv_writer_t w;
    uint8_t v[1000];
    size_t n;
    int i;
    /* round_abort's detail: printable ASCII only. */
    memset(v, 'x', sizeof v);
    for (i = 0; i < 3; i++) {
        uint8_t bad = i == 0 ? 0x7f : i == 1 ? 0x1f : 0x80;
        gz_tlv_writer_init(&w, body, sizeof body);
        gz_tlv_put(&w, 2, v, 32);
        gz_tlv_put(&w, 4, v, 2);
        v[3] = bad;
        gz_tlv_put(&w, 7, v, 10);
        v[3] = 'x';
        gz_tlv_put(&w, 240, v, 64);
        CHECK(gz_env_check(78, SCOPE, body, w.len, GZ_ENV_AT_HOST, NULL) == GZ_ENV_REFUSE);
    }
    /* join's display_name: well-formed UTF-8 only. */
    {
        static const char *good[] = {"Ana", "\xc3\xa9t\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x8d\x85"};
        static const char *bad[] = {"\xc0\xaf", "\xe0\x80\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xc3", "\x80",
                                    "\xf5\x80\x80\x80", "\xe2\x82", "\xc3\x41", "\xe2\x82\x41"};
        size_t g;
        for (g = 0; g < 4 + 10; g++) {
            const char *s = g < 4 ? good[g] : bad[g - 4];
            gz_tlv_writer_init(&w, body, sizeof body);
            gz_tlv_put(&w, 2, v, 33);
            gz_tlv_put(&w, 4, v, 64);
            gz_tlv_put(&w, 6, v, 64);
            gz_tlv_put(&w, 7, (const uint8_t *)s, strlen(s));
            CHECK(gz_env_check(20, SCOPE, body, w.len, GZ_ENV_AT_HOST, NULL) == (g < 4 ? GZ_ENV_DELIVER : GZ_ENV_REFUSE));
        }
    }
    /* round_all_nonces items: whole blocks, 1 to 256 items, at least one signer each. */
    {
        static uint8_t items[300 * 136 + 10];
        size_t cases[][3] = {/* items, signers each, extra bytes; then expected */
                             {1, 1, 0}, {256, 1, 0}, {257, 1, 0}, {1, 2, 0}, {2, 3, 0}, {1, 1, 1}, {1, 0, 0}, {0, 0, 0}};
        int expect[] = {1, 1, 0, 1, 1, 0, 0, 0};
        size_t c;
        for (c = 0; c < sizeof cases / sizeof cases[0]; c++) {
            size_t it, at = 0;
            memset(items, 0, sizeof items);
            for (it = 0; it < cases[c][0]; it++) {
                items[at + 5] = (uint8_t)cases[c][1];
                at += 6 + cases[c][1] * 130;
            }
            at += cases[c][2];
            gz_tlv_writer_init(&w, body, sizeof body);
            gz_tlv_put(&w, 2, v, 32);
            gz_tlv_put(&w, 4, v, 1);
            gz_tlv_put(&w, 6, items, at);
            CHECK(gz_env_check(68, SCOPE, body, w.len, GZ_ENV_AT_MEMBER, NULL) ==
                  (expect[c] ? GZ_ENV_DELIVER : GZ_ENV_REFUSE));
        }
        /* A block claiming more signers than the bytes hold. */
        memset(items, 0, 140);
        items[5] = 2;
        gz_tlv_writer_init(&w, body, sizeof body);
        gz_tlv_put(&w, 2, v, 32);
        gz_tlv_put(&w, 4, v, 1);
        gz_tlv_put(&w, 6, items, 136);
        CHECK(gz_env_check(68, SCOPE, body, w.len, GZ_ENV_AT_MEMBER, NULL) == GZ_ENV_REFUSE);
    }
    /* round_propose carrying record 26 (placement, removed) or 44
     * (distribution, not in slice 1): unknown even, refused. */
    {
        const tkind *k = NULL;
        size_t ki;
        for (ki = 0; ki < sizeof TK / sizeof TK[0]; ki++)
            if (TK[ki].kind == 64) k = &TK[ki];
        n = build(k, 1, -1, -1, 0, 26);
        CHECK(gz_env_check(64, SCOPE, body, n, GZ_ENV_AT_MEMBER, NULL) == GZ_ENV_REFUSE);
        n = build(k, 1, -1, -1, 0, 44);
        CHECK(gz_env_check(64, SCOPE, body, n, GZ_ENV_AT_MEMBER, NULL) == GZ_ENV_REFUSE);
        /* The unspecified odd records of 7.6, 7.7 and 7.9 are skipped. */
        n = build(k, 1, -1, -1, 0, 0);
        CHECK(gz_env_check(64, SCOPE, body, n, GZ_ENV_AT_MEMBER, NULL) == GZ_ENV_DELIVER);
    }
}

/* Kinds, tags and the generic record rules through gz_env_read. */
static size_t mk(uint16_t kind, const uint8_t *scope, const char *records_hex, uint8_t *out)
{
    uint8_t rec[2000];
    size_t rn = unhex(records_hex, rec, sizeof rec), n;
    CHECK(rn != (size_t)-1);
    CHECK(gz_env_write(kind, scope, rec, rn, out, 70000, &n) == 0);
    return n;
}

static void test_read(void)
{
    uint8_t m1[200];
    size_t n = unhex(M1, m1, sizeof m1);
    gz_env_msg_t m;
    const char *why;
    /* Kinds (test 7). */
    CHECK(gz_env_read(msg, mk(36, SCOPE, "", msg), GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_REFUSE);
    CHECK(gz_env_read(msg, mk(0, SCOPE, "", msg), GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_REFUSE);
    CHECK(gz_env_read(msg, mk(37, SCOPE, "0201", msg), GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_IGNORE);
    CHECK(gz_env_read(msg, mk(65535, SCOPE, "", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_IGNORE);
    /* Discovery kinds: never refused, whatever they hold (4.1). */
    CHECK(gz_env_read(msg, mk(128, SCOPE, "fd", msg), GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_IGNORE);
    CHECK(gz_env_read(msg, mk(130, ZERO, "0201ff", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_IGNORE);
    CHECK(gz_env_read(msg, mk(159, SCOPE, "", msg), GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_IGNORE);
    CHECK(gz_env_read(msg, mk(158, SCOPE, "", msg), GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_IGNORE);
    CHECK(gz_env_read(msg, mk(128, SCOPE, "", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_IGNORE);
    CHECK(gz_env_read(msg, mk(160, SCOPE, "", msg), GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_REFUSE);
    CHECK(gz_env_read(msg, mk(126, SCOPE, "", msg), GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_REFUSE);
    /* A scope that is zero but for its last byte is a scope. */
    {
        uint8_t last[32] = {0};
        last[31] = 1;
        CHECK(gz_env_read(msg, mk(28, last, "020100040100060400000000080200000a020000", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_DELIVER);
        last[31] = 0;
        last[0] = 1;
        CHECK(gz_env_read(msg, mk(28, last, "020100040100060400000000080200000a020000", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_DELIVER);
    }
    /* hello, with and without a scope; never from the host. */
    CHECK(gz_env_read(msg, mk(16, ZERO, "", msg), GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_DELIVER);
    CHECK(gz_env_read(msg, mk(16, SCOPE, "", msg), GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_DELIVER);
    CHECK(gz_env_read(msg, mk(16, SCOPE, "", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_REFUSE);
    /* M1 at the member: a ready from the host is in the wrong direction. */
    CHECK(gz_env_read(m1, n, GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_REFUSE);
    /* Wrong protocol tag: ignored, with a warning (once: the caller's job). */
    m1[5] = 2;
    CHECK(gz_env_read(m1, n, GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_IGNORE_WARN && why);
    m1[5] = 1;
    m1[2] ^= 0x80;
    CHECK(gz_env_read(m1, n, GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_IGNORE_WARN);
    m1[2] ^= 0x80;
    /* Too short: under the tag, and between the tag and the full header. */
    CHECK(gz_env_read(m1, 5, GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_REFUSE);
    CHECK(gz_env_read(m1, 6, GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_REFUSE);
    CHECK(gz_env_read(m1, 39, GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_REFUSE && why &&
          strcmp(why, "factory message too short") == 0);
    CHECK(gz_env_read(m1, 40, GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_REFUSE); /* ready without records */
    /* Not type 52791 at all. */
    m1[1] ^= 2;
    CHECK(gz_env_read(m1, n, GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_REFUSE);
    m1[1] ^= 2;
    /* Records (test 3): a non-minimal type, a non-minimal length, a repeat,
     * a decrease, a length past the end; an empty stream where records are
     * required. Each on lobby_status at the member. */
    CHECK(gz_env_read(msg, mk(28, SCOPE, "020100040100060400000000080200000a020000", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_DELIVER);
    CHECK(gz_env_read(msg, mk(28, SCOPE, "fd000201000401000604000000000802" "00000a020000", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_REFUSE);
    CHECK(gz_env_read(msg, mk(28, SCOPE, "02fd000100040100060400000000080200000a020000", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_REFUSE);
    CHECK(gz_env_read(msg, mk(28, SCOPE, "02010002010004010006040000000008020000" "0a020000", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_REFUSE);
    CHECK(gz_env_read(msg, mk(28, SCOPE, "040100020100060400000000080200000a020000", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_REFUSE);
    CHECK(gz_env_read(msg, mk(28, SCOPE, "020100040100060400000000080200000a0300 00", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_REFUSE);
    CHECK(gz_env_read(msg, mk(28, SCOPE, "", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_REFUSE);
    /* An unknown odd record one byte longer than what is left: refused for
     * its length, though it would be skipped. */
    CHECK(gz_env_read(msg, mk(28, SCOPE, "020100040100060400000000080200000a0200000b0200", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_REFUSE &&
          why && strcmp(why, "record past the end") == 0);
    /* A record type past 2^16, odd, is skipped like any unknown odd record. */
    CHECK(gz_env_read(msg, mk(28, SCOPE, "020100040100060400000000080200000a020000fe0001000100", msg), GZ_ENV_AT_MEMBER, &m, &why) == GZ_ENV_DELIVER);
    /* A changed odd record before the signature fails the signature (test 4). */
    {
        uint8_t key[33];
        size_t i, k = 0;
        gz_env_msg_t mm;
        unhex(M1_KEY, key, 33);
        /* M1 with odd record 9 (one byte) inserted before 240. */
        for (i = 0; i < n; i++) {
            if (i == 2 + 38 + 34 + 6 + 34) { msg[k++] = 9; msg[k++] = 1; msg[k++] = 0x55; }
            msg[k++] = m1[i];
        }
        CHECK(gz_env_read(msg, k, GZ_ENV_AT_HOST, &mm, &why) == GZ_ENV_DELIVER);
        CHECK(!gz_env_verify(secp, &mm, key));
        CHECK(gz_env_find(NULL, 0, 9) == NULL);
    }
    /* The largest message (test 8): 65,535 bytes are accepted; one more is
     * never built. */
    {
        gz_tlv_writer_t w;
        static uint8_t pad[GZ_ENV_MAX_RECORDS];
        size_t mn;
        memset(pad, 0, sizeof pad);
        gz_tlv_writer_init(&w, body, sizeof body);
        gz_tlv_put(&w, 1, pad, GZ_ENV_MAX_RECORDS - 34 - 4); /* type 1, length fd xxxx: 4 bytes of header */
        gz_tlv_put(&w, 2, pad, 32);
        CHECK(w.len == GZ_ENV_MAX_RECORDS);
        CHECK(gz_env_write(80, SCOPE, body, w.len, msg, sizeof msg, &mn) == 0 && mn == 65535);
        CHECK(gz_env_read(msg, mn, GZ_ENV_AT_HOST, &m, &why) == GZ_ENV_DELIVER);
        CHECK(gz_env_write(80, SCOPE, body, w.len + 1, msg, sizeof msg, &mn) != 0);
        CHECK(gz_env_write(80, SCOPE, body, 10, msg, 49, &mn) != 0);
    }
}

/* ------------------------------------------- splitting */

/* A valid round_all_nonces body of exactly `len` bytes (len at least 200):
 * records 2 and 4, then record 6 with one item of enough signers, padded with
 * odd record 1 in front to the exact length. */
static size_t valid_body(size_t len, uint8_t *out)
{
    gz_tlv_writer_t w;
    static uint8_t items[1100000], pad[800];
    size_t signers = (len - 600) / 130, item_len = 6 + signers * 130, rest;
    uint8_t lenhdr[9];
    memset(items, 0x33, item_len);
    memset(items, 0, 6);
    items[4] = (uint8_t)(signers >> 8);
    items[5] = (uint8_t)signers;
    /* What remains after records 2 (34), 4 (3), 6 (header + items). */
    rest = len - 34 - 3 - (1 + gz_bigsize_write(item_len, lenhdr) + item_len);
    memset(pad, 0, sizeof pad);
    gz_tlv_writer_init(&w, out, len);
    /* rest is 547 bytes or more, so record 1's length takes 3 bytes. */
    gz_tlv_put(&w, 1, pad, rest - 4);
    gz_tlv_put(&w, 2, pad, 32);
    gz_tlv_put(&w, 4, pad, 1);
    gz_tlv_put(&w, 6, items, item_len);
    CHECK(w.err == GZ_FRAME_OK && w.len == len);
    CHECK(gz_env_check(68, SCOPE, out, len, GZ_ENV_AT_MEMBER, NULL) == GZ_ENV_DELIVER);
    return w.len;
}

static uint8_t parts[GZ_ENV_MAX_PARTS][65535];
static size_t part_len[GZ_ENV_MAX_PARTS];

static unsigned split(const uint8_t *b, size_t len)
{
    unsigned c = gz_env_part_count(len), i;
    for (i = 0; i < c; i++)
        CHECK(wp(68, SCOPE, b, len, i, parts[i], sizeof parts[i], &part_len[i]) == 0);
    return c;
}

/* Feeds part i; returns the verdict. */
static gz_env_verdict_t feed(gz_env_reasm_t *r, const uint8_t *m, size_t len, gz_env_msg_t *out)
{
    gz_env_msg_t p;
    gz_env_verdict_t v = gz_env_read(m, len, GZ_ENV_AT_MEMBER, &p, NULL);
    if (v != GZ_ENV_DELIVER) return v;
    CHECK(p.kind == GZ_ENV_KIND_PART);
    return gz_env_reasm_add(r, &p, GZ_ENV_AT_MEMBER, secp, out, NULL);
}

/* A part written by hand, with any fields. */
static size_t hand_part(const uint8_t tid[32], uint16_t inner, uint32_t total, uint16_t index, uint16_t count,
                        const uint8_t *data, size_t dlen, uint8_t *out)
{
    gz_tlv_writer_t w;
    uint8_t k[2] = {(uint8_t)(inner >> 8), (uint8_t)inner}, t[4] = {(uint8_t)(total >> 24), (uint8_t)(total >> 16),
                                                                    (uint8_t)(total >> 8), (uint8_t)total};
    uint8_t ix[2] = {(uint8_t)(index >> 8), (uint8_t)index}, c[2] = {(uint8_t)(count >> 8), (uint8_t)count};
    size_t n;
    static uint8_t rec[65535];
    gz_tlv_writer_init(&w, rec, sizeof rec);
    gz_tlv_put(&w, 2, tid, 32);
    gz_tlv_put(&w, 4, k, 2);
    gz_tlv_put(&w, 6, t, 4);
    gz_tlv_put(&w, 8, ix, 2);
    gz_tlv_put(&w, 10, c, 2);
    gz_tlv_put(&w, 12, data, dlen);
    CHECK(w.err == GZ_FRAME_OK);
    CHECK(gz_env_write(GZ_ENV_KIND_PART, SCOPE, rec, w.len, out, 65535, &n) == 0);
    return n;
}

static uint8_t whole[1 << 20];

/* A part with unknown odd records before, between and after the required
 * ones (review of PR 23, F2): 1, 3, 5 first, 7, 9, 11 between, 13, 15
 * after. */
static size_t odd_part(const uint8_t tid[32], uint16_t inner, uint32_t total, uint16_t index, uint16_t count,
                       const uint8_t *data, size_t dlen, uint8_t *out)
{
    gz_tlv_writer_t w;
    uint8_t k[2] = {(uint8_t)(inner >> 8), (uint8_t)inner}, t[4] = {(uint8_t)(total >> 24), (uint8_t)(total >> 16),
                                                                    (uint8_t)(total >> 8), (uint8_t)total};
    uint8_t ix[2] = {(uint8_t)(index >> 8), (uint8_t)index}, c[2] = {(uint8_t)(count >> 8), (uint8_t)count};
    static const uint8_t junk[40];
    size_t n;
    static uint8_t rec[65535];
    gz_tlv_writer_init(&w, rec, sizeof rec);
    gz_tlv_put(&w, 1, junk, 40);
    gz_tlv_put(&w, 2, tid, 32);
    gz_tlv_put(&w, 3, junk, 40);
    gz_tlv_put(&w, 4, k, 2);
    gz_tlv_put(&w, 5, junk, 40);
    gz_tlv_put(&w, 6, t, 4);
    gz_tlv_put(&w, 7, junk, 40);
    gz_tlv_put(&w, 8, ix, 2);
    gz_tlv_put(&w, 9, junk, 40);
    gz_tlv_put(&w, 10, c, 2);
    gz_tlv_put(&w, 11, junk, 40);
    gz_tlv_put(&w, 12, data, dlen);
    gz_tlv_put(&w, 13, junk, 40);
    gz_tlv_put(&w, 15, junk, 40);
    CHECK(w.err == GZ_FRAME_OK);
    CHECK(gz_env_write(GZ_ENV_KIND_PART, SCOPE, rec, w.len, out, 65535, &n) == 0);
    return n;
}

static void test_split(void)
{
    gz_env_reasm_t r;
    gz_env_msg_t out;
    unsigned c, i;
    size_t len;
    uint8_t tid[32];
    static const size_t sizes[] = {65496, 65999, 130000, 130001, 300000, GZ_ENV_MAX_WHOLE};
    size_t si;
    gz_env_reasm_init(&r);
    /* The thresholds (test 9). */
    CHECK(gz_env_part_count(GZ_ENV_MAX_RECORDS) == 0 && gz_env_part_count(GZ_ENV_MAX_RECORDS + 1) == 2);
    CHECK(gz_env_part_count(130000) == 2 && gz_env_part_count(130001) == 3);
    CHECK(gz_env_part_count(GZ_ENV_MAX_WHOLE) == 17 && gz_env_part_count(GZ_ENV_MAX_WHOLE + 1) == 0);
    CHECK(wp(2, SCOPE, whole, 70000, 0, msg, sizeof msg, &len) != 0);
    CHECK(wp(68, SCOPE, whole, 1000, 0, msg, sizeof msg, &len) != 0);
    CHECK(wp(68, SCOPE, whole, 70000, 0, msg, 100, &len) != 0);
    /* In order, in reverse and in a scrambled order, at several sizes. */
    for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
        int order;
        len = valid_body(sizes[si], whole);
        c = split(whole, len);
        CHECK(c == (len + 64999) / 65000);
        for (order = 0; order < 3; order++) {
            for (i = 0; i < c; i++) {
                unsigned j = order == 0 ? i : order == 1 ? c - 1 - i : (i * 7 + 3) % c;
                gz_env_verdict_t v = feed(&r, parts[j], part_len[j], &out);
                if (i + 1 < c) CHECK(v == GZ_ENV_HELD);
                else CHECK(v == GZ_ENV_DELIVER && out.kind == 68 && out.records_len == len &&
                           memcmp(out.records, whole, len) == 0 && memcmp(out.scope, SCOPE, 32) == 0);
            }
        }
        /* Memory: at most the message, and nothing once reset (test 14). */
        CHECK(r.allocated <= GZ_ENV_MAX_WHOLE);
        gz_env_reasm_reset(&r);
        CHECK(r.buf == NULL && r.allocated == 0);
    }
    /* Hostile parts (tests 10 and 11), on a 3-part message. */
    len = valid_body(140000, whole);
    c = split(whole, len);
    CHECK(c == 3);
    memmove(big + 2, whole, len);
    big[0] = 0;
    big[1] = 68;
    gz_env_tagged_hash(secp, "gazpacho/part", big, len + 2, tid);
    /* Duplicate: ignored. Same index, other data: refused. */
    CHECK(feed(&r, parts[0], part_len[0], &out) == GZ_ENV_HELD);
    CHECK(feed(&r, parts[0], part_len[0], &out) == GZ_ENV_IGNORE);
    memcpy(msg, parts[0], part_len[0]);
    msg[part_len[0] - 1] ^= 1;
    CHECK(feed(&r, msg, part_len[0], &out) == GZ_ENV_REFUSE && r.buf == NULL);
    /* count inconsistent with total_len; count 1; count above 17; index past
     * count; a short middle part; a long last part; a short last part;
     * total_len above 1 MiB; inner_kind 2. */
    CHECK(feed(&r, msg, hand_part(tid, 68, (uint32_t)len, 0, 4, whole, 65000, msg), &out) == GZ_ENV_REFUSE);
    CHECK(feed(&r, msg, hand_part(tid, 68, 60000, 0, 1, whole, 60000, msg), &out) == GZ_ENV_REFUSE);
    CHECK(feed(&r, msg, hand_part(tid, 68, 65001, 0, 1, whole, 65000, msg), &out) == GZ_ENV_REFUSE);
    CHECK(feed(&r, msg, hand_part(tid, 68, 18 * 65000, 0, 18, whole, 65000, msg), &out) == GZ_ENV_REFUSE);
    CHECK(feed(&r, msg, hand_part(tid, 68, (uint32_t)len, 3, 3, whole, 10000, msg), &out) == GZ_ENV_REFUSE);
    CHECK(feed(&r, msg, hand_part(tid, 68, (uint32_t)len, 3, 3, whole, 65000, msg), &out) == GZ_ENV_REFUSE);
    /* A one-part "transfer", even with the right transfer_id for a valid
     * message: refused (count is at least 2). */
    {
        static uint8_t small[65000];
        uint8_t stid[32];
        size_t sl = valid_body(60000, small);
        gz_env_transfer_id(secp, 68, small, sl, stid);
        CHECK(feed(&r, msg, hand_part(stid, 68, (uint32_t)sl, 0, 1, small, sl, msg), &out) == GZ_ENV_REFUSE);
    }
    CHECK(feed(&r, msg, hand_part(tid, 68, (uint32_t)len, 1, 3, whole, 64999, msg), &out) == GZ_ENV_REFUSE);
    CHECK(feed(&r, msg, hand_part(tid, 68, (uint32_t)len, 2, 3, whole, len - 130000 + 1, msg), &out) == GZ_ENV_REFUSE);
    CHECK(feed(&r, msg, hand_part(tid, 68, (uint32_t)len, 2, 3, whole, len - 130000 - 1, msg), &out) == GZ_ENV_REFUSE);
    CHECK(feed(&r, msg, hand_part(tid, 68, GZ_ENV_MAX_WHOLE + 1, 0, 17, whole, 65000, msg), &out) == GZ_ENV_REFUSE);
    CHECK(feed(&r, msg, hand_part(tid, 2, (uint32_t)len, 0, 3, whole, 65000, msg), &out) == GZ_ENV_REFUSE);
    /* The largest total opens a transfer of exactly 1 MiB. */
    CHECK(feed(&r, msg, hand_part(tid, 68, GZ_ENV_MAX_WHOLE, 16, 17, whole, GZ_ENV_MAX_WHOLE - 16 * 65000, msg), &out) == GZ_ENV_HELD);
    CHECK(r.allocated == GZ_ENV_MAX_WHOLE);
    gz_env_reasm_reset(&r);
    /* A part that disagrees with its open transfer: other total, other
     * inner kind, other scope. */
    CHECK(feed(&r, parts[0], part_len[0], &out) == GZ_ENV_HELD);
    CHECK(feed(&r, msg, hand_part(tid, 68, (uint32_t)len + 1, 1, 3, whole, 65000, msg), &out) == GZ_ENV_REFUSE);
    CHECK(feed(&r, parts[0], part_len[0], &out) == GZ_ENV_HELD);
    CHECK(feed(&r, msg, hand_part(tid, 70, (uint32_t)len, 1, 3, whole, 65000, msg), &out) == GZ_ENV_REFUSE);
    CHECK(feed(&r, parts[0], part_len[0], &out) == GZ_ENV_HELD);
    memcpy(msg, parts[1], part_len[1]);
    msg[8] ^= 1; /* the scope */
    CHECK(feed(&r, msg, part_len[1], &out) == GZ_ENV_REFUSE);
    /* A wrong transfer_id at completion. */
    tid[0] ^= 1;
    for (i = 0; i < 3; i++) {
        size_t dl = i < 2 ? 65000 : len - 130000;
        gz_env_verdict_t v = feed(&r, msg, hand_part(tid, 68, (uint32_t)len, (uint16_t)i, 3, whole + i * 65000, dl, msg), &out);
        CHECK(v == (i < 2 ? GZ_ENV_HELD : GZ_ENV_REFUSE));
    }
    tid[0] ^= 1;
    /* The same bytes with the right id complete. */
    for (i = 0; i < 3; i++) {
        size_t dl = i < 2 ? 65000 : len - 130000;
        gz_env_verdict_t v = feed(&r, msg, hand_part(tid, 68, (uint32_t)len, (uint16_t)i, 3, whole + i * 65000, dl, msg), &out);
        CHECK(v == (i < 2 ? GZ_ENV_HELD : GZ_ENV_DELIVER));
    }
    /* A new transfer while one is open drops the old one (test 12). */
    CHECK(feed(&r, parts[0], part_len[0], &out) == GZ_ENV_HELD);
    CHECK(feed(&r, parts[1], part_len[1], &out) == GZ_ENV_HELD);
    {
        static uint8_t other[200000];
        size_t olen = valid_body(131000, other);
        unsigned oc = gz_env_part_count(olen);
        size_t ol[3];
        static uint8_t op[3][65535];
        for (i = 0; i < oc; i++) CHECK(wp(68, SCOPE, other, olen, i, op[i], 65535, &ol[i]) == 0);
        CHECK(feed(&r, op[0], ol[0], &out) == GZ_ENV_HELD);
        /* The old transfer's last part now opens a third transfer. */
        CHECK(feed(&r, parts[2], part_len[2], &out) == GZ_ENV_HELD);
        CHECK(feed(&r, op[1], ol[1], &out) == GZ_ENV_HELD);
        CHECK(feed(&r, op[2], ol[2], &out) == GZ_ENV_HELD);
        CHECK(feed(&r, op[0], ol[0], &out) == GZ_ENV_DELIVER && out.records_len == olen &&
              memcmp(out.records, other, olen) == 0);
    }
    /* After a drop, the whole message sent again is accepted. */
    gz_env_reasm_reset(&r);
    for (i = 0; i < 3; i++) CHECK(feed(&r, parts[i], part_len[i], &out) == (i < 2 ? GZ_ENV_HELD : GZ_ENV_DELIVER));
    /* Unknown odd records anywhere in a part, eight of them (F2). */
    {
        uint8_t otid[32];
        static uint8_t om[65535];
        len = valid_body(140000, whole);
        gz_env_transfer_id(secp, 68, whole, len, otid);
        gz_env_reasm_reset(&r);
        for (i = 0; i < 3; i++) {
            size_t dl = i < 2 ? 65000 : len - 130000;
            size_t on = odd_part(otid, 68, (uint32_t)len, (uint16_t)i, 3, whole + i * 65000, dl, om);
            CHECK(on <= 65535);
            CHECK(feed(&r, om, on, &out) == (i < 2 ? GZ_ENV_HELD : GZ_ENV_DELIVER));
        }
        CHECK(out.records_len == len && memcmp(out.records, whole, len) == 0);
        /* The caller releases a delivered message; a new transfer would too. */
        CHECK(r.buf != NULL);
        gz_env_reasm_reset(&r);
        CHECK(r.buf == NULL && r.allocated == 0);
    }
    /* A completed transfer of an unknown odd kind is released at once. */
    {
        uint8_t otid[32];
        static uint8_t om[65535];
        len = valid_body(140000, whole);
        gz_env_transfer_id(secp, 69, whole, len, otid);
        for (i = 0; i < 3; i++) {
            size_t dl = i < 2 ? 65000 : len - 130000;
            size_t on = odd_part(otid, 69, (uint32_t)len, (uint16_t)i, 3, whole + i * 65000, dl, om);
            CHECK(feed(&r, om, on, &out) == (i < 2 ? GZ_ENV_HELD : GZ_ENV_IGNORE));
        }
        CHECK(r.buf == NULL && r.allocated == 0);
    }
    /* A completed message left unreleased is released by the next part. */
    {
        len = valid_body(140000, whole);
        c = split(whole, len);
        for (i = 0; i < c; i++) CHECK(feed(&r, parts[i], part_len[i], &out) == (i + 1 < c ? GZ_ENV_HELD : GZ_ENV_DELIVER));
        CHECK(r.allocated == len);
        CHECK(feed(&r, parts[0], part_len[0], &out) == GZ_ENV_HELD);
        CHECK(r.allocated == len && r.held == 1);
        gz_env_reasm_reset(&r);
    }
    /* A host refuses parts (members send none in slice 1; test 13). */
    {
        gz_env_msg_t p;
        CHECK(gz_env_read(parts[0], part_len[0], GZ_ENV_AT_HOST, &p, NULL) == GZ_ENV_REFUSE);
    }
    /* A whole message that is valid as parts but not as its kind is refused
     * after reassembly; one of an unknown odd kind is ignored. */
    len = valid_body(140000, whole);
    {
        gz_tlv_writer_t w;
        static uint8_t bad[140000];
        gz_tlv_writer_init(&w, bad, sizeof bad);
        gz_tlv_put(&w, 2, whole, 139990);
        len = w.len;
        for (i = 0; i < 3; i++) CHECK(wp(68, SCOPE, bad, len, i, parts[i], 65535, &part_len[i]) == 0);
        for (i = 0; i < 3; i++) CHECK(feed(&r, parts[i], part_len[i], &out) == (i < 2 ? GZ_ENV_HELD : GZ_ENV_REFUSE));
        for (i = 0; i < 3; i++) CHECK(wp(69, SCOPE, bad, len, i, parts[i], 65535, &part_len[i]) == 0);
        for (i = 0; i < 3; i++) CHECK(feed(&r, parts[i], part_len[i], &out) == (i < 2 ? GZ_ENV_HELD : GZ_ENV_IGNORE));
    }
    gz_env_reasm_reset(&r);
    /* A part given to the reassembler that is not a part. */
    {
        gz_env_msg_t p;
        p.kind = 68;
        p.scope = SCOPE;
        p.records = whole;
        p.records_len = 10;
        CHECK(gz_env_reasm_add(&r, &p, GZ_ENV_AT_MEMBER, secp, &out, NULL) == GZ_ENV_REFUSE);
    }
}

int main(void)
{
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unhex(T1_DIGEST, SCOPE, 32);
    test_vectors();
    test_m2();
    test_tables();
    test_special_records();
    test_read();
    test_split();
    secp256k1_context_destroy(secp);
    return check_done();
}
