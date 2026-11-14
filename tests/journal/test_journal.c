/* The journal's format, vector, open, write and limit tests (spec/journal.md
 * section 12; the numbers in the comments are the spec's test numbers). The
 * crash sweeps are in test_journal_crash.c. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../check.h"
#include "harness.h"

static size_t unhex(const char *s, uint8_t *out)
{
    size_t n = 0;
    for (; *s; s++) {
        if (*s == ' ' || *s == '\n') continue;
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
        s++;
    }
    return n;
}

/* Spec section 11, as printed there (the salt 00 01 .. 1f). */
static const char *J1 = "475a4a4f55524e53 f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000"
                        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                        "598cbcfdcc7c3d3b1a1eab6adac61dac";
static const char *J2 = "00000019 01 0000000000000001 0000000000000000 000001a1b2bb9400"
                        "d0742bb1d178d951a10a23fc4da6e5dd";
static const char *J3 = "00000021 02 0000000000000001 0000000000000001 00000001 7e570001 00000004 70696e67"
                        "ddde3c927fd591a41118a5ec813fcd5a";
static const char *J5 = "00000019 03 0000000000000001 0000000000000000 0000000000000085"
                        "67591b2f763b7489609793e88e380adc";
static const char *J6M = "00000019 03 0000000000000001 0000000000000000 00000000000000e7"
                         "8e9c126043c3bea83a91d7802d2d4c10";

#define HL GZ_JOURNAL_HEADER_LEN        /* 88 */
#define ML GZ_JOURNAL_MARK_LEN          /* 45 */
#define C0 (HL + 2 * ML)                /* after header, J2, J5: 178, where J3 sits */
#define J3L 53u                         /* J3's size */
#define C1 (C0 + J3L)                   /* the second mark: 231 */

static uint8_t clean[512];
static size_t clean_len; /* header, J2, J5, J3, second mark: 276 bytes */

static void build_clean(void)
{
    clean_len = unhex(J1, clean);
    clean_len += unhex(J2, clean + clean_len);
    clean_len += unhex(J5, clean + clean_len);
    clean_len += unhex(J3, clean + clean_len);
    clean_len += unhex(J6M, clean + clean_len);
}

/* An entry with any fields, its check computed over what is given, for
 * file offset `at`. */
static size_t raw_entry(uint8_t *out, uint64_t at, uint32_t length, uint8_t kind, uint64_t inc, uint64_t seq,
                        const uint8_t *payload, size_t plen)
{
    out[0] = (uint8_t)(length >> 24); out[1] = (uint8_t)(length >> 16);
    out[2] = (uint8_t)(length >> 8); out[3] = (uint8_t)length;
    out[4] = kind;
    for (int i = 0; i < 8; i++) {
        out[5 + i] = (uint8_t)(inc >> (56 - 8 * i));
        out[13 + i] = (uint8_t)(seq >> (56 - 8 * i));
    }
    if (plen) memcpy(out + 21, payload, plen);
    gz_journal_entry_check(h_salt, at, out, 21 + plen, out + 21 + plen);
    return 21 + plen + GZ_JOURNAL_CHECK_LEN;
}

/* A sync mark at offset `at` naming `value` (a correct mark names `at`). */
static size_t mark_val(uint8_t *out, uint64_t inc, uint64_t at, uint64_t value)
{
    return gz_journal_encode_small(out, h_salt, at, GZ_JOURNAL_KIND_MARK, inc, value);
}

static size_t mark(uint8_t *out, uint64_t inc, uint64_t at) { return mark_val(out, inc, at, at); }

static size_t small(uint8_t *out, uint64_t at, uint8_t kind, uint64_t inc, uint64_t value)
{
    return gz_journal_encode_small(out, h_salt, at, kind, inc, value);
}

static size_t batch(uint8_t *out, uint64_t at, uint64_t inc, uint64_t seq, uint32_t type, const char *bytes)
{
    gz_record_t r = {type, {(const uint8_t *)bytes, strlen(bytes)}};
    gz_batch_id_t id = {inc, seq};
    return gz_journal_encode_batch(out, h_salt, at, id, &r, 1);
}

static gz_journal_scan_t scan(const uint8_t *d, size_t len)
{
    gz_journal_scan_t s;
    gz_journal_scan(d, len, gz_journal_chain_signet, &s, NULL, NULL);
    return s;
}

/* Open a journal held in `bytes` on a fresh memfs; returns the status, and
 * whether the file was left exactly as it was. */
static gz_journal_status_t open_bytes(const uint8_t *bytes, size_t len, gz_journal_open_info_t *info,
                                      int *untouched, memfs_t *keep)
{
    memfs_t fs;
    memfs_init(&fs);
    memfs_put(&fs, H_JOURNAL, bytes, len);
    gz_journal_t *j = NULL;
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 5, &fs.os, 0, 0, 0, 0, 0, NULL, NULL};
    gz_journal_status_t st = gz_journal_open(&j, &cfg, info);
    size_t now = 0;
    const uint8_t *d = memfs_get(&fs, H_JOURNAL, &now);
    if (untouched) *untouched = now == len && memcmp(d, bytes, len) == 0;
    gz_journal_close(j);
    if (keep) {
        *keep = fs;
        keep->os.ctx = keep; /* the table's context follows the copy */
    }
    else memfs_free(&fs);
    return st;
}

static void test_vectors(void)
{
    uint8_t a[128], b[128];
    /* 1. J1, J2, J3, J5 and the second mark from the encoders. */
    CHECK(gz_journal_encode_header(a, gz_journal_chain_signet, h_salt) == unhex(J1, b) && !memcmp(a, b, HL));
    CHECK(small(a, HL, 1, 1, 1794000000000ull) == unhex(J2, b) && !memcmp(a, b, ML));
    CHECK(batch(a, C0, 1, 1, 0x7e570001, "ping") == unhex(J3, b) && !memcmp(a, b, J3L));
    CHECK(mark(a, 1, HL + ML) == unhex(J5, b) && !memcmp(a, b, ML));
    CHECK(mark(a, 1, C1) == unhex(J6M, b) && !memcmp(a, b, ML));
    /* The same bytes at another offset, or under another salt, differ. */
    uint8_t other[GZ_JOURNAL_SALT_LEN] = {1};
    CHECK(mark(b, 1, C1) == ML && small(a, C1 + 1, GZ_JOURNAL_KIND_MARK, 1, C1) == ML && memcmp(a, b, ML) != 0);
    CHECK(gz_journal_encode_small(a, other, C1, GZ_JOURNAL_KIND_MARK, 1, C1) == ML && memcmp(a, b, ML) != 0);

    /* The writer itself produces header, J2, J5, J3 and the second mark. */
    h_t *h = calloc(1, sizeof *h);
    memfs_init(&h->fs);
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 1794000000000ull, &h->fs.os, 0, 0, 0, 0, 0, NULL, NULL};
    gz_journal_open_info_t info;
    CHECK(gz_journal_open(&h->j, &cfg, &info) == GZ_JOURNAL_OK && info.created && info.incarnation == 1);
    gz_journal_attach(h->j, NULL, NULL, NULL); /* nobody confirms */
    gz_record_t r = {0x7e570001, {(const uint8_t *)"ping", 4}};
    gz_action_t s = {.kind = GZ_ACTION_SAVE};
    s.u.save.batch.incarnation = 1;
    s.u.save.batch.sequence = 1;
    s.u.save.records = &r;
    s.u.save.n_records = 1;
    CHECK(gz_journal_save(h->j, &s) == GZ_JOURNAL_OK);
    CHECK(gz_journal_flush(h->j) == GZ_JOURNAL_OK);
    size_t len;
    const uint8_t *d = memfs_get(&h->fs, H_JOURNAL, &len);
    CHECK(len == clean_len && !memcmp(d, clean, clean_len));
    gz_journal_close(h->j);
    memfs_free(&h->fs);
    free(h);

    /* J4: header, J2, J5, J3 without its last 3 bytes. */
    gz_journal_scan_t sc = scan(clean, C1 - 3);
    CHECK(sc.verdict == GZ_JOURNAL_TORN && sc.valid_end == C0 && sc.highest_incarnation == 1);
    int untouched;
    memfs_t fs;
    CHECK(open_bytes(clean, C1 - 3, &info, &untouched, &fs) == GZ_JOURNAL_OK);
    CHECK(info.incarnation == 2 && info.cut_bytes == J3L - 3);
    d = memfs_get(&fs, H_JOURNAL, &len);
    CHECK(len == C0 + 2 * ML && !memcmp(d, clean, C0));
    memfs_free(&fs);

    /* J6: J3's byte 25 has bit 0 flipped, the second mark follows. */
    uint8_t j6[512];
    memcpy(j6, clean, clean_len);
    j6[C0 + 25] ^= 1;
    sc = scan(j6, clean_len);
    CHECK(sc.verdict == GZ_JOURNAL_REFUSED && sc.status == GZ_JOURNAL_ERR_CORRUPT);
    CHECK(sc.error_at == C0 && sc.mark_at == C1);
    CHECK(open_bytes(j6, clean_len, &info, &untouched, NULL) == GZ_JOURNAL_ERR_CORRUPT && untouched);

    sc = scan(clean, clean_len);
    CHECK(sc.verdict == GZ_JOURNAL_CLEAN && sc.status == GZ_JOURNAL_OK && sc.n_batches == 1 &&
          sc.n_marks == 2 && sc.n_records == 1);
    CHECK(open_bytes(clean, clean_len, &info, NULL, NULL) == GZ_JOURNAL_OK && info.incarnation == 2);
}

static void test_header(void)
{
    uint8_t d[512];
    int untouched;
    /* 2. Wrong magic, wrong check (a salt byte, a check byte), mainnet chain, too short. */
    memcpy(d, clean, clean_len);
    d[0] ^= 1;
    CHECK(open_bytes(d, clean_len, NULL, &untouched, NULL) == GZ_JOURNAL_ERR_HEADER && untouched);
    memcpy(d, clean, clean_len);
    d[45] ^= 0x80;
    CHECK(open_bytes(d, clean_len, NULL, &untouched, NULL) == GZ_JOURNAL_ERR_HEADER && untouched);
    memcpy(d, clean, clean_len);
    d[HL - 1] ^= 0x01;
    CHECK(open_bytes(d, clean_len, NULL, &untouched, NULL) == GZ_JOURNAL_ERR_HEADER && untouched);
    gz_journal_encode_header(d, gz_journal_chain_mainnet, h_salt);
    CHECK(open_bytes(d, HL, NULL, &untouched, NULL) == GZ_JOURNAL_ERR_NETWORK && untouched);
    memcpy(d, clean, clean_len);
    d[20] ^= 1; /* chain changed, check not recomputed */
    CHECK(open_bytes(d, clean_len, NULL, NULL, NULL) == GZ_JOURNAL_ERR_HEADER);
    for (size_t n = 0; n < HL; n++)
        CHECK(open_bytes(clean, n, NULL, &untouched, NULL) == GZ_JOURNAL_ERR_HEADER && untouched);
    /* A header alone is a clean, empty journal. */
    gz_journal_open_info_t info;
    CHECK(open_bytes(clean, HL, &info, NULL, NULL) == GZ_JOURNAL_OK && info.incarnation == 1);
    /* Entries are bound to the salt: the same file under another salt
     * (header check recomputed) keeps no entry, and is torn at once. */
    memcpy(d, clean, clean_len);
    uint8_t salt2[GZ_JOURNAL_SALT_LEN];
    for (int i = 0; i < 32; i++) salt2[i] = (uint8_t)(i + 1);
    gz_journal_encode_header(d, gz_journal_chain_signet, salt2);
    gz_journal_scan_t sc = scan(d, clean_len);
    CHECK(sc.verdict == GZ_JOURNAL_TORN && sc.valid_end == HL && sc.n_incarnations == 0);
}

/* `entry` placed after header, J2, J5: invalid, so torn without a mark after
 * it and corrupt with one. */
static void expect_invalid(const uint8_t *entry, size_t elen, const char *what)
{
    uint8_t d[700];
    memcpy(d, clean, C0);
    memcpy(d + C0, entry, elen);
    gz_journal_scan_t sc = scan(d, C0 + elen);
    int ok1 = sc.verdict == GZ_JOURNAL_TORN && sc.valid_end == C0;
    size_t m = mark(d + C0 + elen, 1, C0 + elen);
    sc = scan(d, C0 + elen + m);
    int ok2 = sc.verdict == GZ_JOURNAL_REFUSED && sc.status == GZ_JOURNAL_ERR_CORRUPT && sc.error_at == C0;
    if (!ok1 || !ok2) printf("  not invalid: %s\n", what);
    CHECK(ok1 && ok2);
}

static void test_fields(void)
{
    uint8_t e[600], p[64] = {0};
    /* 3. Lengths 20, 16, 0 and the maximum + 1 (each with a correct check over what follows). */
    static const uint32_t lens[] = {20, 16, 0, GZ_JOURNAL_ENTRY_MAX + 1};
    for (int i = 0; i < 4; i++) {
        size_t n = raw_entry(e, C0, lens[i], 2, 1, 1, p, 8);
        expect_invalid(e, n, "length");
    }
    /* Incarnation and mark entries whose length is not 25. */
    for (uint32_t len = 21; len <= 30; len++) {
        if (len == 25) continue;
        expect_invalid(e, raw_entry(e, C0, len, 1, 2, 0, p, len - 17), "incarnation length");
        expect_invalid(e, raw_entry(e, C0, len, 3, 1, 0, p, len - 17), "mark length");
    }
    /* Unknown kinds. */
    static const uint8_t kinds[] = {0, 4, 5, 0x7f, 0x80, 0xff};
    for (int i = 0; i < 6; i++) expect_invalid(e, raw_entry(e, C0, 25, kinds[i], 1, 0, p, 8), "kind");
    /* A mark naming another offset, check correct for where it sits. */
    expect_invalid(e, mark_val(e, 1, C0, C0 - 1), "mark offset - 1");
    expect_invalid(e, mark_val(e, 1, C0, C0 + 1), "mark offset + 1");
    expect_invalid(e, mark_val(e, 1, C0, 0), "mark offset 0");
    /* Entries sealed for another offset or another salt (review H1). */
    expect_invalid(e, mark_val(e, 1, C0 + 1, C0), "mark sealed for offset + 1");
    expect_invalid(e, batch(e, C0 - 1, 1, 1, 0x7e570001, "x"), "batch sealed for offset - 1");
    expect_invalid(e, mark_val(e, 1, 0, C0), "mark sealed for offset 0");
    {
        uint8_t zero[GZ_JOURNAL_SALT_LEN] = {0};
        expect_invalid(e, gz_journal_encode_small(e, zero, C0, GZ_JOURNAL_KIND_MARK, 1, C0), "mark, another salt");
    }
    /* A flipped bit in every byte of a batch entry and of a mark entry. */
    size_t n = batch(e, C0, 1, 1, 0x7e570001, "region");
    for (size_t i = 0; i < n; i++)
        for (int bit = 0; bit < 8; bit += 7) {
            uint8_t f[64];
            memcpy(f, e, n);
            f[i] ^= (uint8_t)(1 << bit);
            expect_invalid(f, n, "flipped bit in a batch");
        }
    n = mark(e, 1, C0);
    for (size_t i = 0; i < n; i++) {
        uint8_t f[64];
        memcpy(f, e, n);
        f[i] ^= 1;
        expect_invalid(f, n, "flipped bit in a mark");
    }
    /* 4. Records that under- or overrun the payload. */
    static const char *const bad[] = {
        "00000002 7e570001 00000001 41",          /* two records, one present */
        "00000001 7e570001 00000005 41424344",    /* record longer than the payload */
        "00000001 7e570001 00000001 4142",        /* a byte left over */
        "00000000 00",                            /* no records, a byte left over */
        "000000"};                                /* shorter than the count */
    for (int i = 0; i < 5; i++) {
        uint8_t pl[64];
        size_t pn = unhex(bad[i], pl);
        expect_invalid(e, raw_entry(e, C0, (uint32_t)(17 + pn), 2, 1, 1, pl, pn), "records fill");
    }
    /* The largest allowed entry is valid; one byte more is not. */
    size_t big = GZ_JOURNAL_ENTRY_MAX - 17 - 4 - 8;
    uint8_t *buf = calloc(1, GZ_JOURNAL_ENTRY_MAX + 300);
    gz_record_t r = {0x7e570001, {buf + GZ_JOURNAL_ENTRY_MAX + 200, 0}};
    r.bytes.data = calloc(1, big + 1);
    r.bytes.len = big;
    CHECK(gz_journal_batch_size(&r, 1) == 4 + GZ_JOURNAL_ENTRY_MAX + GZ_JOURNAL_CHECK_LEN);
    memcpy(buf, clean, C0);
    size_t w = gz_journal_encode_batch(buf + C0, h_salt, C0, (gz_batch_id_t){1, 1}, &r, 1);
    gz_journal_scan_t sc = scan(buf, C0 + w);
    CHECK(sc.verdict == GZ_JOURNAL_CLEAN && sc.n_batches == 1);
    r.bytes.len = big + 1;
    CHECK(gz_journal_batch_size(&r, 1) == 0);
    free((void *)r.bytes.data);
    free(buf);
}

static void test_order(void)
{
    uint8_t d[600];
    size_t n;
    int untouched;
    struct { const char *what; size_t len; } c[12];
    uint8_t cases[12][600];
    int k = 0;
#define CASE(w) (c[k].what = (w), n = HL, memcpy(cases[k], clean, HL))
#define ADD(x) (n += (x))
#define END() (c[k].len = n, k++)
    uint8_t *e;
    /* 5. A batch before any incarnation. */
    CASE("batch first"); e = cases[k]; ADD(batch(e + n, n, 1, 1, 0x7e570001, "x")); END();
    CASE("mark first"); e = cases[k]; ADD(mark(e + n, 1, HL)); END();
    CASE("incarnation equal"); e = cases[k];
    ADD(small(e + n, n, 1, 1, 0)); ADD(small(e + n, n, 1, 1, 0)); END();
    CASE("incarnation lower"); e = cases[k];
    ADD(small(e + n, n, 1, 3, 0)); ADD(small(e + n, n, 1, 2, 0)); END();
    CASE("batch under older incarnation"); e = cases[k];
    ADD(small(e + n, n, 1, 1, 0)); ADD(small(e + n, n, 1, 2, 0));
    ADD(batch(e + n, n, 1, 1, 0x7e570001, "x")); END();
    CASE("batch under newer incarnation"); e = cases[k];
    ADD(small(e + n, n, 1, 1, 0)); ADD(batch(e + n, n, 2, 1, 0x7e570001, "x")); END();
    CASE("sequence gap"); e = cases[k];
    ADD(small(e + n, n, 1, 1, 0)); ADD(batch(e + n, n, 1, 1, 0x7e570001, "x"));
    ADD(batch(e + n, n, 1, 3, 0x7e570001, "x")); END();
    CASE("sequence repeated"); e = cases[k];
    ADD(small(e + n, n, 1, 1, 0)); ADD(batch(e + n, n, 1, 1, 0x7e570001, "x"));
    ADD(batch(e + n, n, 1, 1, 0x7e570001, "x")); END();
    CASE("sequence starts at 2"); e = cases[k];
    ADD(small(e + n, n, 1, 1, 0)); ADD(batch(e + n, n, 1, 2, 0x7e570001, "x")); END();
    CASE("sequence 0"); e = cases[k];
    ADD(small(e + n, n, 1, 1, 0)); ADD(batch(e + n, n, 1, 0, 0x7e570001, "x")); END();
    CASE("mark of another incarnation"); e = cases[k];
    ADD(small(e + n, n, 1, 1, 0)); ADD(mark(e + n, 2, n)); END();
    CASE("incarnation 0"); e = cases[k]; ADD(small(e + n, n, 1, 0, 0)); END();
    for (int i = 0; i < k; i++) {
        memcpy(d, cases[i], c[i].len);
        gz_journal_status_t st = open_bytes(d, c[i].len, NULL, &untouched, NULL);
        if (st != GZ_JOURNAL_ERR_ORDER || !untouched) printf("  order case not refused: %s\n", c[i].what);
        CHECK(st == GZ_JOURNAL_ERR_ORDER && untouched);
    }
    /* A new incarnation restarts the sequence at 1. */
    n = HL;
    memcpy(d, clean, HL);
    ADD(small(d + n, n, 1, 1, 0)); ADD(batch(d + n, n, 1, 1, 0x7e570001, "x"));
    ADD(small(d + n, n, 1, 4, 0)); ADD(batch(d + n, n, 4, 1, 0x7e570001, "x"));
    gz_journal_open_info_t info;
    CHECK(open_bytes(d, n, &info, NULL, NULL) == GZ_JOURNAL_OK && info.incarnation == 5);
#undef CASE
#undef ADD
#undef END
}

/* 6, 15, reader. An empty batch; a stale confirmation; batches of this
 * incarnation visible once durable; unknown types (18). */
static void test_write_read(void)
{
    h_t *h = calloc(1, sizeof *h);
    memfs_init(&h->fs);
    CHECK(h_open(h, NULL) == GZ_JOURNAL_OK);
    gz_action_t slots[2];
    uint8_t bytes[256];
    gz_action_list_t list;
    gz_action_list_init(&list, slots, 2, bytes, sizeof bytes);
    gz_action_t save = {.kind = GZ_ACTION_SAVE};
    gz_action_list_add(&list, &save);
    /* A step whose generated batch is empty, so h_verify can check it. */
    h_batch_t eb;
    uint64_t g0 = 0;
    while (h_records(g0, &eb, 0) != 0) g0++;
    gz_action_t send = {.kind = GZ_ACTION_SEND};
    h_send_mark(&send, g0);
    gz_action_list_add(&list, &send);
    h->pending_step[1] = g0;
    h->next_step = g0 + 1;
    CHECK(gz_runner_submit(&h->runner, &list) == GZ_OK);
    CHECK(gz_journal_pending(h->j) == 1 && !h->released[g0]);
    gz_storage_reader_t rd = gz_journal_reader(h->j);
    gz_stored_batch_t sb;
    CHECK(rd.next(rd.ctx, &sb) == 0); /* not durable yet */
    CHECK(gz_journal_flush(h->j) == GZ_JOURNAL_OK);
    CHECK(h->confirmed[g0] && h->released[g0] && gz_journal_pending(h->j) == 0);
    rd.rewind(rd.ctx);
    CHECK(rd.next(rd.ctx, &sb) == 1 && sb.n_records == 0 && sb.id.incarnation == 1 && sb.id.sequence == 1);
    CHECK(rd.next(rd.ctx, &sb) == 0);
    rd.rewind(rd.ctx);
    CHECK(rd.next(rd.ctx, &sb) == 1);
    h_close(h);
    /* Reopen: the empty batch is read back; an old confirmation is stale. */
    CHECK(h_open(h, NULL) == GZ_JOURNAL_OK && h->inc == 2);
    rd = gz_journal_reader(h->j);
    CHECK(rd.incarnation == 2);
    CHECK(rd.next(rd.ctx, &sb) == 1 && sb.n_records == 0 && sb.id.sequence == 1);
    CHECK(h_step(h) == GZ_OK);
    size_t held = gz_runner_held(&h->runner);
    CHECK(gz_runner_confirm(&h->runner, (gz_batch_id_t){1, 1}) == GZ_ERR_STALE_BATCH);
    CHECK(gz_runner_held(&h->runner) == held && !h->released[g0 + 1] && !gz_runner_failed(&h->runner));
    CHECK(gz_journal_flush(h->j) == GZ_JOURNAL_OK && h->released[g0 + 1]);
    CHECK(h_verify(h, 0, 0) == 0);
    h_close(h);
    memfs_free(&h->fs);
    free(h);

    /* 18. Unknown even type: refused. Unknown odd: skipped. 0x00040008 is unused: refused. */
    uint8_t d[600];
    size_t n = C0;
    memcpy(d, clean, C0);
    n += batch(d + n, n, 1, 1, 0x00050002, "even");
    gz_journal_scan_t sc = scan(d, n);
    CHECK(sc.status == GZ_JOURNAL_ERR_UNKNOWN_RECORD && sc.bad_type == 0x00050002 && sc.error_at == C0);
    int untouched;
    CHECK(open_bytes(d, n, NULL, &untouched, NULL) == GZ_JOURNAL_ERR_UNKNOWN_RECORD && untouched);
    n = C0;
    n += batch(d + n, n, 1, 1, 0x00040008, "fresh");
    CHECK(open_bytes(d, n, NULL, NULL, NULL) == GZ_JOURNAL_ERR_UNKNOWN_RECORD);
    n = C0;
    gz_record_t rs[3] = {{0x00050001, {(const uint8_t *)"odd", 3}},
                         {0x00020006, {(const uint8_t *)"exp", 3}},
                         {0x7e570001, {(const uint8_t *)"ping", 4}}};
    n += gz_journal_encode_batch(d + n, h_salt, n, (gz_batch_id_t){1, 1}, rs, 3);
    memfs_t fs;
    CHECK(open_bytes(d, n, NULL, NULL, &fs) == GZ_JOURNAL_OK);
    gz_journal_t *j;
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 5, &fs.os, 0, 0, 0, 0, 0, NULL, NULL};
    CHECK(gz_journal_open(&j, &cfg, NULL) == GZ_JOURNAL_OK);
    rd = gz_journal_reader(j);
    CHECK(rd.next(rd.ctx, &sb) == 1 && sb.n_records == 2 && sb.records[0].type == 0x00020006 &&
          sb.records[1].type == 0x7e570001 && sb.records[1].bytes.len == 4 &&
          !memcmp(sb.records[1].bytes.data, "ping", 4));
    gz_journal_close(j);
    memfs_free(&fs);
    /* An unknown even type in a torn tail is cut with it, not refused. */
    n = C0;
    n += batch(d + n, n, 1, 1, 0x00050002, "even");
    CHECK(scan(d, n - 1).verdict == GZ_JOURNAL_TORN);
    CHECK(gz_journal_type_known(0x00020006) && !gz_journal_type_known(0x00020010) &&
          gz_journal_type_known(0x7e57ffff) && !gz_journal_type_known(0x00040008));
}

/* 7, 8, 9, 10. */
static void test_tails(void)
{
    gz_journal_open_info_t info;
    int untouched;
    memfs_t fs;
    /* 7. Every cut inside the last entry after the last mark (J3, C0..C1-1). */
    for (size_t cut = C0; cut < C1; cut++) {
        int ok = open_bytes(clean, cut, &info, NULL, &fs) == GZ_JOURNAL_OK && info.incarnation == 2 &&
                 info.cut_bytes == cut - C0;
        size_t len;
        const uint8_t *d = memfs_get(&fs, H_JOURNAL, &len);
        ok = ok && len == C0 + 2 * ML && !memcmp(d, clean, C0);
        memfs_free(&fs);
        CHECK(ok);
    }
    /* 8. Zero bytes after the last mark. */
    uint8_t d[800];
    memcpy(d, clean, clean_len);
    for (size_t z = 1; z <= 100; z += 33) {
        memset(d + clean_len, 0, z);
        CHECK(open_bytes(d, clean_len + z, &info, NULL, NULL) == GZ_JOURNAL_OK &&
              info.cut_bytes == z && info.incarnation == 2);
    }
    /* 9. Earlier batch torn, later one intact, no mark: both dropped. */
    size_t n = C0;
    memcpy(d, clean, C0);
    n += batch(d + n, n, 1, 1, 0x7e570001, "first");
    n += batch(d + n, n, 1, 2, 0x7e570001, "second");
    d[C0 + 8] ^= 0x10;
    CHECK(open_bytes(d, n, &info, NULL, &fs) == GZ_JOURNAL_OK && info.cut_bytes == n - C0);
    gz_journal_t *j;
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 5, &fs.os, 0, 0, 0, 0, 0, NULL, NULL};
    CHECK(gz_journal_open(&j, &cfg, NULL) == GZ_JOURNAL_OK);
    gz_storage_reader_t rd = gz_journal_reader(j);
    gz_stored_batch_t sb;
    CHECK(rd.next(rd.ctx, &sb) == 0);
    gz_journal_close(j);
    memfs_free(&fs);
    /* 10. An invalid entry just before the final mark. */
    n = C0;
    n += batch(d + n, n, 1, 1, 0x7e570001, "first");
    size_t at = n;
    n += batch(d + n, n, 1, 2, 0x7e570001, "second");
    n += mark(d + n, 1, n);
    d[at + 30] ^= 4;
    CHECK(open_bytes(d, n, NULL, &untouched, NULL) == GZ_JOURNAL_ERR_CORRUPT && untouched);
    /* A false mark in the torn tail, offset right but check wrong, is not a mark. */
    n = C0;
    n += batch(d + n, n, 1, 1, 0x7e570001, "first");
    d[n - 1] ^= 1;
    size_t m = n;
    n += mark(d + n, 1, m);
    d[n - 1] ^= 1;
    CHECK(open_bytes(d, n, &info, NULL, NULL) == GZ_JOURNAL_OK && info.cut_bytes == n - C0);
}

/* 25. A member journal of about 40 KB; a bit flipped in a confirmed exposure entry. */
static void test_member_journal(void)
{
    h_t *h = calloc(1, sizeof *h);
    memfs_init(&h->fs);
    CHECK(h_open(h, NULL) == GZ_JOURNAL_OK);
    gz_journal_attach(h->j, NULL, NULL, NULL); /* batches handed over directly */
    static uint8_t blob[1200];
    for (size_t i = 0; i < sizeof blob; i++) blob[i] = (uint8_t)(i * 7);
    uint64_t exposure_at = 0;
    for (uint64_t s = 1; s <= 34; s++) {
        gz_record_t r[2] = {{0x00020002, {blob, 40}}, {0x00020006, {blob, sizeof blob}}};
        gz_action_t a = {.kind = GZ_ACTION_SAVE};
        a.u.save.batch.incarnation = h->inc;
        a.u.save.batch.sequence = s;
        a.u.save.records = r;
        a.u.save.n_records = s == 34 ? 1 : 2;
        if (s == 17) exposure_at = gz_journal_size(h->j);
        CHECK(gz_journal_save(h->j, &a) == GZ_JOURNAL_OK);
        if (s < 34) gz_journal_flush(h->j);
    }
    size_t len;
    const uint8_t *cur = memfs_get(&h->fs, H_JOURNAL, &len);
    uint8_t *d = malloc(len);
    memcpy(d, cur, len);
    CHECK(len > 40000 && len < 46000);
    gz_journal_close(h->j);
    d[exposure_at + 21 + 4 + 8 + 40 + 8 + 600] ^= 0x20;
    int untouched;
    CHECK(open_bytes(d, len, NULL, &untouched, NULL) == GZ_JOURNAL_ERR_CORRUPT && untouched);
    d[exposure_at + 21 + 4 + 8 + 40 + 8 + 600] ^= 0x20;
    /* The last batch, after the last mark: a torn tail. */
    d[len - 20] ^= 0x20;
    gz_journal_open_info_t info;
    CHECK(open_bytes(d, len, &info, NULL, NULL) == GZ_JOURNAL_OK && info.cut_bytes == 4 + 17 + 4 + 8 + 40 + GZ_JOURNAL_CHECK_LEN);
    free(d);
    memfs_free(&h->fs);
    free(h);
}

/* 12, 13, 26, 28: failing syncs and writes, a full disk, the guard. */
static int run_failure(int mode, uint64_t fail_point, uint64_t capacity, int guards, int *confirmed_any)
{
    h_t *h = calloc(1, sizeof *h);
    memfs_init(&h->fs);
    h->guards = guards;
    if (h_open(h, NULL) != GZ_JOURNAL_OK) return -1;
    h->fs.points = 0;
    h->fs.fail_at = fail_point;
    h->fs.fail_mode = mode;
    h->fs.capacity = capacity;
    int failed_at = -1;
    for (int s = 0; s < 12 && failed_at < 0; s++) {
        h_step(h);
        if (s % 3 == 2) gz_journal_flush(h->j);
        if (gz_journal_failed(h->j)) failed_at = s;
    }
    gz_journal_flush(h->j);
    int bad = 0;
    if (failed_at >= 0) {
        /* Nothing written after the failure; nothing more confirmed. */
        size_t len_before, len_after;
        memfs_get(&h->fs, H_JOURNAL, &len_before);
        uint8_t conf[H_MAX_STEP];
        memcpy(conf, h->confirmed, sizeof conf);
        h_step(h);
        gz_journal_flush(h->j);
        memfs_get(&h->fs, H_JOURNAL, &len_after);
        bad += len_before != len_after || memcmp(conf, h->confirmed, sizeof conf) != 0;
        bad += !gz_runner_failed(&h->runner);
        bad += gz_journal_save(h->j, &(gz_action_t){.kind = GZ_ACTION_SAVE}) != GZ_JOURNAL_ERR_FAILED;
    }
    *confirmed_any = 0;
    for (uint64_t g = 0; g < h->next_step; g++) *confirmed_any |= h->confirmed[g];
    gz_journal_close(h->j);
    h->fs.capacity = 0;
    memfs_settle(&h->fs, MEMFS_LOSE, 0);
    if (h_open(h, NULL) != GZ_JOURNAL_OK) bad += 100;
    else bad += h_verify(h, 0, 0);
    h_close(h);
    memfs_free(&h->fs);
    free(h);
    return failed_at >= 0 ? bad : -1 - bad;
}

static void test_failures(void)
{
    int any, fails = 0, runs = 0;
    /* Every point of a run of 12 steps, failing as an error, a short write and no space. */
    for (int mode = MEMFS_FAIL_ERROR; mode <= MEMFS_FAIL_NOSPACE; mode++)
        for (uint64_t p = 1; p < 80; p++) {
            int r = run_failure(mode, p, 0, 1, &any);
            if (r == -1) continue; /* past the run's last point */
            runs++;
            if (r != 0) { printf("  failure mode %d at point %llu: %d problems\n", mode, (unsigned long long)p, r); fails++; }
        }
    CHECK(fails == 0 && runs > 100);
    printf("  failure injection: %d runs\n", runs);
    /* A full disk at every capacity from the header up. */
    fails = runs = 0;
    for (uint64_t cap = HL; cap < 1500; cap += 7) {
        int r = run_failure(0, 0, cap, 0, &any);
        if (r == -1) continue;
        runs++;
        if (r != 0) fails++;
    }
    CHECK(fails == 0 && runs > 50);
}

static void test_guard(void)
{
    /* 28. The guard file is written, with its check, before the batch is confirmed. */
    h_t *h = calloc(1, sizeof *h);
    memfs_init(&h->fs);
    h->guards = 1;
    CHECK(h_open(h, NULL) == GZ_JOURNAL_OK);
    for (int s = 0; s < 4; s++) h_step(h);
    CHECK(memfs_get(&h->fs, H_GUARD, &(size_t){0}) == NULL);
    CHECK(gz_journal_flush(h->j) == GZ_JOURNAL_OK && h->confirmed[3]);
    size_t len;
    const uint8_t *g = memfs_get(&h->fs, H_GUARD, &len);
    uint8_t want[80], c[32];
    size_t wn = h_guard_bytes(want, 3);
    sha256(want, wn, c);
    CHECK(g && len == wn + 8 && !memcmp(g, want, wn) && !memcmp(g + wn, c, 8));
    CHECK(memfs_get(&h->fs, H_DIR "/guard.gzg.tmp", &len) == NULL);
    /* A guard record that is not a guard: a storage failure. */
    uint8_t bad[80];
    h_guard_bytes(bad, 9);
    gz_record_t r = {GZ_RECORD_GUARD, {bad, 66}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch.incarnation = h->inc;
    a.u.save.batch.sequence = 5;
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    static const size_t pos[] = {0, 10, 49, 65};
    for (int i = 0; i < 4; i++) {
        h_t *k = calloc(1, sizeof *k);
        memfs_init(&k->fs);
        h_open(k, NULL);
        a.u.save.batch.incarnation = k->inc;
        a.u.save.batch.sequence = 1;
        h_guard_bytes(bad, 9);
        if (i < 3) bad[pos[i]] ^= 1;
        r.bytes.len = i < 3 ? 66 : 65;
        CHECK(gz_journal_save(k->j, &a) == GZ_JOURNAL_ERR_GUARD && gz_runner_failed(&k->runner));
        h_close(k);
        memfs_free(&k->fs);
        free(k);
    }
    h_close(h);
    memfs_free(&h->fs);
    free(h);
}

/* The writer's own checks (spec 3.4: rules 3 and 4 before writing). */
static void test_writer_rules(void)
{
    static const gz_batch_id_t wrong[] = {{1, 1}, {2, 2}, {2, 0}, {3, 1}};
    for (int i = 0; i < 4; i++) {
        h_t *h = calloc(1, sizeof *h);
        memfs_init(&h->fs);
        memfs_put(&h->fs, H_JOURNAL, clean, clean_len); /* next incarnation: 2 */
        CHECK(h_open(h, NULL) == GZ_JOURNAL_OK && h->inc == 2);
        size_t before;
        memfs_get(&h->fs, H_JOURNAL, &before);
        gz_action_t a = {.kind = GZ_ACTION_SAVE};
        a.u.save.batch = wrong[i];
        CHECK(gz_journal_save(h->j, &a) == GZ_JOURNAL_ERR_SEQUENCE && gz_runner_failed(&h->runner));
        size_t after;
        memfs_get(&h->fs, H_JOURNAL, &after);
        CHECK(before == after);
        h_close(h);
        memfs_free(&h->fs);
        free(h);
    }
}

/* 17 and the unsynced bound. */
static void test_limits(void)
{
    h_t *h = calloc(1, sizeof *h);
    memfs_init(&h->fs);
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 1, &h->fs.os, 2000, 3000, 0, 0, 0, NULL, NULL};
    gz_journal_open_info_t info;
    CHECK(gz_journal_open(&h->j, &cfg, &info) == GZ_JOURNAL_OK && !info.soft_full);
    h->inc = 1;
    gz_runner_init(&h->runner, h->slots, 64, h->rbytes, sizeof h->rbytes, 1, h_execute, h);
    gz_journal_attach(h->j, &h->runner, h_on_confirmed, h);
    int soft_seen_at = -1, full_at = -1;
    for (int s = 0; s < 200 && full_at < 0; s++) {
        uint64_t before = gz_journal_size(h->j);
        h_step(h);
        gz_journal_flush(h->j);
        if (soft_seen_at < 0 && gz_journal_soft_full(h->j)) soft_seen_at = s;
        if (gz_journal_failed(h->j)) {
            full_at = s;
            CHECK(gz_journal_size(h->j) == before && before <= 3000);
        }
        CHECK(gz_journal_size(h->j) <= 3000);
    }
    CHECK(soft_seen_at >= 0 && full_at > soft_seen_at);
    gz_journal_close(h->j);
    /* Nothing confirmed is lost; the soft limit is reported at open; a journal
     * with no room for an incarnation is refused. */
    memfs_settle(&h->fs, MEMFS_LOSE, 0);
    /* At the hard limit not even a new incarnation fits: refused as full. */
    CHECK(gz_journal_open(&h->j, &cfg, &info) == GZ_JOURNAL_ERR_FULL && h->j == NULL);
    cfg.hard_limit = 4000; /* space freed */
    CHECK(gz_journal_open(&h->j, &cfg, &info) == GZ_JOURNAL_OK && info.soft_full);
    if (!h->j) return;
    h->inc = info.incarnation;
    gz_runner_init(&h->runner, h->slots, 64, h->rbytes, sizeof h->rbytes, h->inc, h_execute, h);
    CHECK(h_verify(h, 0, 0) == 0);
    gz_journal_close(h->j);
    size_t len;
    memfs_get(&h->fs, H_JOURNAL, &len);
    cfg.hard_limit = len + 73;
    CHECK(gz_journal_open(&h->j, &cfg, &info) == GZ_JOURNAL_ERR_FULL);
    memfs_free(&h->fs);
    free(h);

    /* The unsynced bound: a group past it is synced and marked inside save. */
    h = calloc(1, sizeof *h);
    memfs_init(&h->fs);
    gz_journal_config_t c2 = {H_DIR, gz_journal_chain_signet, 1, &h->fs.os, 0, 0, 300, 0, 0, NULL, NULL};
    CHECK(gz_journal_open(&h->j, &c2, NULL) == GZ_JOURNAL_OK);
    h->inc = 1;
    gz_runner_init(&h->runner, h->slots, 64, h->rbytes, sizeof h->rbytes, 1, h_execute, h);
    gz_journal_attach(h->j, &h->runner, h_on_confirmed, h);
    for (int s = 0; s < 20; s++) h_step(h);
    gz_storage_reader_t rd = gz_journal_reader(h->j);
    gz_stored_batch_t sb;
    int durable = 0;
    while (rd.next(rd.ctx, &sb)) durable++;
    CHECK(durable > 5 && durable < 20 && !h->confirmed[0] && gz_journal_pending(h->j) == 20);
    size_t jl;
    const uint8_t *jd = memfs_get(&h->fs, H_JOURNAL, &jl);
    gz_journal_scan_t sc = scan(jd, jl);
    CHECK(sc.n_marks > 3);
    CHECK(gz_journal_flush(h->j) == GZ_JOURNAL_OK && h->confirmed[19] && h->released[19]);
    CHECK(h_verify(h, 0, 0) == 0);
    h_close(h);
    memfs_free(&h->fs);
    free(h);
}

/* Real files: creation, permissions, reopen, a stale temporary file, the lock (16). */
static void test_posix(void)
{
    char dir[] = "/tmp/gzj-test-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char path[256], tmp[256];
    snprintf(path, sizeof path, "%s/%s", dir, GZ_JOURNAL_FILE);
    snprintf(tmp, sizeof tmp, "%s/%s.tmp", dir, GZ_JOURNAL_FILE);
    FILE *f = fopen(tmp, "w"); /* left by a creation that crashed */
    fputs("junk", f);
    fclose(f);
    gz_journal_t *j, *j2;
    gz_journal_config_t cfg = {dir, gz_journal_chain_signet, 1794000000000ull, NULL, 0, 0, 0, 0, 0, NULL, NULL};
    gz_journal_open_info_t info;
    CHECK(gz_journal_open(&j, &cfg, &info) == GZ_JOURNAL_OK && info.created && info.incarnation == 1);
    gz_journal_attach(j, NULL, NULL, NULL); /* nobody confirms */
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    CHECK(access(tmp, F_OK) != 0);
    gz_record_t r = {0x7e570001, {(const uint8_t *)"ping", 4}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch.incarnation = 1;
    a.u.save.batch.sequence = 1;
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    CHECK(gz_journal_save(j, &a) == GZ_JOURNAL_OK && gz_journal_flush(j) == GZ_JOURNAL_OK);
    /* Locked: a second open in this process and one in another process. */
    CHECK(gz_journal_open(&j2, &cfg, NULL) == GZ_JOURNAL_ERR_LOCKED && j2 == NULL);
    pid_t pid = fork();
    if (pid == 0) _exit(gz_journal_open(&j2, &cfg, NULL) == GZ_JOURNAL_ERR_LOCKED ? 0 : 1);
    int status;
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    gz_journal_close(j);
    f = fopen(path, "rb");
    uint8_t d[400];
    size_t n = fread(d, 1, sizeof d, f);
    fclose(f);
    /* The same entries as J1 to J6 under this file's own random salt. */
    {
        uint8_t want[512];
        const uint8_t *sl = d + 40;
        size_t w = gz_journal_encode_header(want, gz_journal_chain_signet, sl);
        w += gz_journal_encode_small(want + w, sl, w, GZ_JOURNAL_KIND_INCARNATION, 1, 1794000000000ull);
        w += gz_journal_encode_small(want + w, sl, w, GZ_JOURNAL_KIND_MARK, 1, w);
        gz_record_t pr = {0x7e570001, {(const uint8_t *)"ping", 4}};
        w += gz_journal_encode_batch(want + w, sl, w, (gz_batch_id_t){1, 1}, &pr, 1);
        w += gz_journal_encode_small(want + w, sl, w, GZ_JOURNAL_KIND_MARK, 1, w);
        CHECK(n == clean_len && w == n && !memcmp(d, want, n) && memcmp(sl, h_salt, GZ_JOURNAL_SALT_LEN) != 0);
    }
    CHECK(gz_journal_open(&j, &cfg, &info) == GZ_JOURNAL_OK && info.incarnation == 2 && !info.created);
    gz_storage_reader_t rd = gz_journal_reader(j);
    gz_stored_batch_t sb;
    CHECK(rd.next(rd.ctx, &sb) == 1 && sb.n_records == 1 && !memcmp(sb.records[0].bytes.data, "ping", 4));
    gz_journal_close(j);
    /* A torn tail on a real file is cut. */
    f = fopen(path, "ab");
    fputs("torn", f);
    fclose(f);
    CHECK(gz_journal_open(&j, &cfg, &info) == GZ_JOURNAL_OK && info.cut_bytes == 4 && info.incarnation == 3);
    gz_journal_close(j);
    cfg.chain = gz_journal_chain_mainnet;
    CHECK(gz_journal_open(&j, &cfg, NULL) == GZ_JOURNAL_ERR_NETWORK);
    unlink(path);
    snprintf(path, sizeof path, "%s/%s", dir, GZ_JOURNAL_LOCK_FILE);
    CHECK(unlink(path) == 0); /* the folder's lock file, never removed by the journal */
    CHECK(rmdir(dir) == 0);
    CHECK(gz_journal_open(&j, &cfg, NULL) == GZ_JOURNAL_ERR_IO); /* no folder */
    CHECK(gz_journal_open(NULL, &cfg, NULL) == GZ_JOURNAL_ERR_ARGUMENT);
    CHECK(gz_journal_open(&j, NULL, NULL) == GZ_JOURNAL_ERR_ARGUMENT);
}

int main(void)
{
    build_clean();
    test_vectors();
    test_header();
    test_fields();
    test_order();
    test_write_read();
    test_tails();
    test_member_journal();
    test_failures();
    test_guard();
    test_writer_rules();
    test_limits();
    test_posix();
    return check_done();
}
