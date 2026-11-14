/* The journal's own SHA-256, tested directly (final review of PR 29).
 *
 * journal.c hashes with its own incremental SHA-256, so that a check never
 * allocates (N1). Until now it was tested only through the journal: the J
 * vectors, the Python reader, the fuzz targets. A fault in it would be
 * reported as a journal mismatch. This test includes journal.c, so that its
 * static functions can be called, and holds the digests itself.
 *
 *   1. The NIST vectors (FIPS 180-4's examples): the empty input, "abc", the
 *      448-bit and the 896-bit message, and one million 'a', that one fed
 *      whole and in pieces of 1, 7, 63, 64, 65 and 1,000 bytes.
 *   2. The padding and block boundaries: inputs of 55, 56, 57, 63, 64, 65,
 *      119, 120, 127, 128 and 129 bytes against digests written here, fed
 *      whole, a byte at a time, in every two-part split, and in the
 *      three-part splits whose first cut lies at 1, 54 to 57 or 62 to 65.
 *   3. Every length from 0 to 300, whole and in every two-part split,
 *      against the imported SHA-256 (OpenSSL), which the journal no longer
 *      calls.
 *   4. An update of no bytes changes nothing, with a null pointer too, with
 *      and without bytes buffered (a null pointer must never reach memcpy:
 *      the sanitizer builds would report it).
 *   5. The entry check is the first 16 bytes of SHA-256(salt, offset, frame). */
#include "../../ports/storage/journal.c"

#include "../check.h"
#include "superscalar/sha256.h"

static void from_hex(const char *hex, uint8_t out[32])
{
    for (int i = 0; i < 32; i++) {
        unsigned v = 0;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static int is_digest(const uint8_t got[32], const char *hex)
{
    uint8_t want[32];
    from_hex(hex, want);
    return memcmp(got, want, 32) == 0;
}

/* d[0..len) fed in pieces of `piece` bytes (0: all at once). */
static void in_pieces(const uint8_t *d, size_t len, size_t piece, uint8_t out[32])
{
    sha_t s;
    sha_init(&s);
    if (!piece) piece = len;
    for (size_t at = 0; at < len; at += piece) sha_update(&s, d + at, len - at < piece ? len - at : piece);
    sha_final(&s, out);
}

/* d[0..len) fed as [0, a), [a, b), [b, len). */
static void in_three(const uint8_t *d, size_t len, size_t a, size_t b, uint8_t out[32])
{
    sha_t s;
    sha_init(&s);
    sha_update(&s, d, a);
    sha_update(&s, d + a, b - a);
    sha_update(&s, d + b, len - b);
    sha_final(&s, out);
}

static void fill(uint8_t *d, size_t len, unsigned mul, unsigned add)
{
    for (size_t i = 0; i < len; i++) d[i] = (uint8_t)(i * mul + add);
}

/* --- 1 -------------------------------------------------------------------- */
static void test_nist(void)
{
    static const struct { const char *msg, *digest; } v[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"}};
    uint8_t h[32];
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        size_t len = strlen(v[i].msg);
        sha256_of((const uint8_t *)v[i].msg, len, h);
        CHECK(is_digest(h, v[i].digest));
        in_pieces((const uint8_t *)v[i].msg, len, 1, h);
        CHECK(is_digest(h, v[i].digest));
    }
    CHECK(strlen(v[2].msg) * 8 == 448 && strlen(v[3].msg) * 8 == 896);

    static uint8_t million[1000000];
    static const size_t pieces[] = {0, 1, 7, 63, 64, 65, 1000};
    memset(million, 'a', sizeof million);
    for (size_t i = 0; i < sizeof pieces / sizeof pieces[0]; i++) {
        in_pieces(million, sizeof million, pieces[i], h);
        CHECK(is_digest(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    }
}

/* --- 2 -------------------------------------------------------------------- */
static void test_boundaries(void)
{
    /* Byte i of the input is 7 i + 3 (mod 256). */
    static const struct { size_t len; const char *digest; } v[] = {
        {55, "e7313d333c272e639f790978283f9eb392e843d0f29b7016828bb1daa4aac70b"},
        {56, "4324d65f3c103567f5589c710bc08f8523f929a9272e3af36fc968e52abc6c27"},
        {57, "35df609437dcfea3279283ab79fd554e2bf78f8f7ae2de532d8ee300b09e8f73"},
        {63, "81c80242132f230c3bd41b3e63bbcff16107339549214a99614ff26664625055"},
        {64, "39e3d7b6b5d075d37d053ad89b24b41bef4f3c29760c84447cab3f3be1882241"},
        {65, "aacca6ff74fdbb296d165a45cecfa04e5127bc008770fbbdd48006f2d2fae95e"},
        {119, "9ce7368e4daf32341631b492e80359dc9f594b48453cd0dd5bf0b19279cc177e"},
        {120, "7836b787757e95e58b3ca5aec90b1b004e8deba1e50e9675af9cabf1a13a04b5"},
        {127, "a8d23e75d936f303d248888d9b165ee543f4cbafcad3c9dd2a79bd84faa11d07"},
        {128, "d2742f1f4ac6bb7ca2b239ee18402ba8b3f9f8e652d2a72973c2b9ba11c08cf6"},
        {129, "307f8fc2c1622b92762e818d39a185d4d667ad49a4b07ceae1f4afa008a93ec4"}};
    static const size_t first_cut[] = {1, 54, 55, 56, 57, 62, 63, 64, 65};
    uint8_t d[129], h[32];
    int bad = 0, cases = 0;
    fill(d, sizeof d, 7, 3);
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        size_t len = v[i].len;
        sha256_of(d, len, h);
        bad += !is_digest(h, v[i].digest);
        in_pieces(d, len, 1, h);
        bad += !is_digest(h, v[i].digest);
        cases += 2;
        for (size_t a = 0; a <= len; a++, cases++) {
            in_three(d, len, a, a, h); /* two parts: [0, a) and [a, len) */
            bad += !is_digest(h, v[i].digest);
        }
        for (size_t k = 0; k < sizeof first_cut / sizeof first_cut[0]; k++)
            for (size_t b = first_cut[k]; first_cut[k] <= len && b <= len; b++, cases++) {
                in_three(d, len, first_cut[k], b, h);
                bad += !is_digest(h, v[i].digest);
            }
    }
    printf("  boundaries: %d splits of 11 inputs\n", cases);
    CHECK(bad == 0 && cases > 4000);
}

/* --- 3 -------------------------------------------------------------------- */
static void test_against_imported(void)
{
    uint8_t d[300], h[32], want[32];
    int bad = 0, cases = 0;
    fill(d, sizeof d, 131, 17);
    for (size_t len = 0; len <= sizeof d; len++) {
        sha256(d, len, want);
        sha256_of(d, len, h);
        bad += memcmp(h, want, 32) != 0;
        for (size_t a = 0; a <= len; a++, cases++) {
            in_three(d, len, a, len, h);
            bad += memcmp(h, want, 32) != 0;
        }
    }
    printf("  against the imported SHA-256: %d cases\n", cases);
    CHECK(bad == 0 && cases == 45451);
}

/* --- 4 -------------------------------------------------------------------- */
static void test_no_bytes(void)
{
    static const size_t before[] = {0, 3, 55, 63, 64, 100};
    uint8_t d[100], h[32], want[32];
    fill(d, sizeof d, 5, 1);
    for (size_t i = 0; i < sizeof before / sizeof before[0]; i++) {
        size_t len = before[i];
        sha256(d, len, want);
        sha_t s;
        sha_init(&s);
        sha_update(&s, NULL, 0);
        sha_update(&s, d, len);
        sha_update(&s, NULL, 0); /* with `len` mod 64 bytes buffered */
        sha_update(&s, d, 0);
        sha_final(&s, h);
        CHECK(memcmp(h, want, 32) == 0);
    }
    sha256_of(NULL, 0, h);
    CHECK(is_digest(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

/* --- 5 -------------------------------------------------------------------- */
static void test_entry_check(void)
{
    static const size_t lens[] = {0, 1, 15, 16, 23, 24, 25, 87, 88, 89, 1000};
    static uint8_t buf[GZ_JOURNAL_SALT_LEN + 8 + 1000];
    uint8_t salt[GZ_JOURNAL_SALT_LEN], c[GZ_JOURNAL_CHECK_LEN], want[32];
    int bad = 0;
    fill(salt, sizeof salt, 3, 9);
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        uint64_t offset = 88 + 0x0102030405060708ull * i;
        memcpy(buf, salt, sizeof salt);
        put64(buf + sizeof salt, offset);
        fill(buf + sizeof salt + 8, lens[i], 11, 2);
        sha256(buf, sizeof salt + 8 + lens[i], want);
        gz_journal_entry_check(salt, offset, buf + sizeof salt + 8, lens[i], c);
        bad += memcmp(c, want, sizeof c) != 0;
    }
    /* An empty frame may be given as a null pointer. */
    memcpy(buf, salt, sizeof salt);
    put64(buf + sizeof salt, 88);
    sha256(buf, sizeof salt + 8, want);
    gz_journal_entry_check(salt, 88, NULL, 0, c);
    bad += memcmp(c, want, sizeof c) != 0;
    CHECK(bad == 0);
}

int main(void)
{
    test_nist();
    test_boundaries();
    test_against_imported();
    test_no_bytes();
    test_entry_check();
    return check_done();
}
