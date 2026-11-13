/* Boundaries and rarely taken paths of the journal, added after mutation
 * testing showed them unchecked: constants, exact limits, failures inside an
 * open (creating the file, cutting a tail), the reader's re-check of durable
 * bytes, and the writer's argument checks. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../check.h"
#include "harness.h"

static size_t small(uint8_t *out, uint8_t kind, uint64_t inc, uint64_t v)
{
    return gz_journal_encode_small(out, kind, inc, v);
}

static size_t one_batch(uint8_t *out, uint64_t inc, uint64_t seq, uint32_t type, size_t len)
{
    static uint8_t zero[64];
    gz_record_t r = {type, {zero, len}};
    return gz_journal_encode_batch(out, (gz_batch_id_t){inc, seq}, &r, 1);
}

static gz_journal_t *open_on(memfs_t *fs, uint64_t soft, uint64_t hard, uint64_t unsynced,
                             gz_journal_status_t *st, gz_journal_open_info_t *info)
{
    gz_journal_t *j = NULL;
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 3, &fs->os, soft, hard, unsynced, 0, 0, NULL, NULL};
    *st = gz_journal_open(&j, &cfg, info);
    if (j) gz_journal_attach(j, NULL, NULL, NULL); /* nobody confirms */
    return j;
}

static gz_journal_status_t save_n(gz_journal_t *j, uint64_t inc, uint64_t seq, size_t len, uint32_t type)
{
    static uint8_t buf[256];
    gz_record_t r = {type, {buf, len}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch = (gz_batch_id_t){inc, seq};
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    return gz_journal_save(j, &a);
}

static uint64_t marks_in(memfs_t *fs)
{
    size_t len;
    const uint8_t *d = memfs_get(fs, H_JOURNAL, &len);
    gz_journal_scan_t s;
    gz_journal_scan(d, len, gz_journal_chain_signet, &s, NULL, NULL);
    return s.n_marks;
}

static void test_constants(void)
{
    static const uint8_t mainnet[32] = {
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
        0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00};
    CHECK(memcmp(gz_journal_chain_mainnet, mainnet, 32) == 0); /* the genesis block hash */
    static const char *const names[] = {"ok", "argument", "io", "locked", "header", "network",
                                        "corrupt", "order", "unknown_record", "full", "too_large",
                                        "sequence", "guard", "no_memory", "failed", "marker",
                                        "incarnation"};
    for (int s = 0; s <= GZ_JOURNAL_ERR_INCARNATION; s++)
        CHECK(strcmp(gz_journal_status_name((gz_journal_status_t)s), names[s]) == 0);
    CHECK(strcmp(gz_journal_status_name((gz_journal_status_t)(GZ_JOURNAL_ERR_INCARNATION + 1)), "?") == 0);
    /* Every type of spec section 9, and none of its odd neighbours. */
    static const uint32_t known[] = {
        0x00040002, 0x00040004, 0x00040006, 0x0004000a, 0x00010002, 0x00010004, 0x00010006,
        0x00010008, 0x0001000a, 0x0001000c, 0x0001000e, 0x00010010, 0x00010012, 0x00010014,
        0x00010016, 0x00020002, 0x00020004, 0x00020006, 0x00020008, 0x0002000a, 0x0002000c,
        0x0002000e, 0x00030002, 0x00030004, 0x00030006};
    for (size_t i = 0; i < sizeof known / sizeof known[0]; i++)
        CHECK(gz_journal_type_known(known[i]) == 1 && gz_journal_type_known(known[i] + 1) == 0);
    CHECK(gz_journal_type_known(0x00040008) == 0 && gz_journal_type_known(0x00010018) == 0);
    CHECK(gz_journal_type_known(0x7e570000) == 1 && gz_journal_type_known(0x7e56ffff) == 0 &&
          gz_journal_type_known(0x7e580000) == 0);
}

static void test_scan_edges(void)
{
    uint8_t d[600];
    size_t n = gz_journal_encode_header(d, gz_journal_chain_signet);
    gz_journal_scan_t s;
    /* Incarnations above 2^32 (the high word counts). */
    uint64_t big = 0x100000005ull;
    n += small(d + n, 1, big, 0);
    n += one_batch(d + n, big, 1, 0x7e570001, 3);
    n += small(d + n, 3, big, n);
    CHECK(gz_journal_scan(d, n, gz_journal_chain_signet, &s, NULL, NULL) == GZ_JOURNAL_OK &&
          s.verdict == GZ_JOURNAL_CLEAN && s.highest_incarnation == big);
    CHECK(s.n_incarnations == 1 && s.n_batches == 1 && s.n_marks == 1 && s.n_records == 1 &&
          s.file_end == n && s.valid_end == n);
    /* A mark found at V + 1 exactly. */
    size_t v = n;
    d[n++] = 0xee;
    n += small(d + n, 3, big, n);
    CHECK(gz_journal_scan(d, n, gz_journal_chain_signet, &s, NULL, NULL) == GZ_JOURNAL_ERR_CORRUPT &&
          s.error_at == v && s.mark_at == v + 1);
    /* A length of 16 with a correct check over its 20 bytes: invalid. */
    n = v;
    uint8_t *e = d + n;
    memset(e, 0, 28);
    e[3] = 16; e[4] = 2;
    uint8_t h[32];
    sha256(e, 20, h);
    memcpy(e + 20, h, 8);
    CHECK(gz_journal_scan(d, n + 28, gz_journal_chain_signet, &s, NULL, NULL) == GZ_JOURNAL_OK &&
          s.verdict == GZ_JOURNAL_TORN && s.valid_end == v);
    /* The last possible incarnation cannot be followed (and none at or
     * above 2^63 is used: contract-v2 section 8). */
    n = 48;
    n += small(d + n, 1, UINT64_MAX, 0);
    memfs_t fs;
    memfs_init(&fs);
    memfs_put(&fs, H_JOURNAL, d, n);
    gz_journal_status_t st;
    gz_journal_t *j = open_on(&fs, 0, 0, 0, &st, NULL);
    CHECK(st == GZ_JOURNAL_ERR_INCARNATION && j == NULL);
    memfs_free(&fs);
}

/* Exact limits: soft, hard (at open and on save), the unsynced bound. */
static void test_limit_edges(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    /* Fresh journal after open: 48 + 37 + 37 = 122 bytes. */
    memfs_init(&fs);
    gz_journal_t *j = open_on(&fs, 122, 122, 0, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.soft_full && gz_journal_soft_full(j) && gz_journal_size(j) == 122);
    gz_journal_close(j);
    memfs_free(&fs);
    memfs_init(&fs);
    j = open_on(&fs, 123, 121, 0, &st, &info);
    CHECK(st == GZ_JOURNAL_ERR_FULL && j == NULL);
    memfs_free(&fs);
    memfs_init(&fs);
    j = open_on(&fs, 123, 400, 0, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && !info.soft_full && !gz_journal_soft_full(j));
    gz_journal_close(j);
    /* A file larger than the hard limit is refused before it is read, even
     * when cutting its tail would make room; one of exactly the limit is not. */
    size_t len;
    const uint8_t *cur = memfs_get(&fs, H_JOURNAL, &len);
    uint8_t *copy = calloc(1, len + 100);
    memcpy(copy, cur, len);
    for (int z = 74; z <= 100; z += 26) {
        memfs_put(&fs, H_JOURNAL, copy, len + (size_t)z);
        j = open_on(&fs, 0, len + 74, 0, &st, &info);
        CHECK(z == 100 ? st == GZ_JOURNAL_ERR_FULL && j == NULL
                       : st == GZ_JOURNAL_OK && info.cut_bytes == 74);
        gz_journal_close(j);
    }
    free(copy);
    memfs_free(&fs);

    /* A batch fits exactly with its mark; one byte less of room and it does not. */
    for (int room = 0; room < 2; room++) {
        memfs_init(&fs);
        uint64_t batch = 4 + 17 + 4 + 8 + 10 + 8; /* 51 */
        j = open_on(&fs, 0, 122 + batch + 37 - (uint64_t)room, 0, &st, NULL);
        CHECK(st == GZ_JOURNAL_OK);
        gz_journal_status_t s = save_n(j, 1, 1, 10, 0x7e570001);
        CHECK(room ? s == GZ_JOURNAL_ERR_FULL && gz_journal_size(j) == 122
                   : s == GZ_JOURNAL_OK && gz_journal_flush(j) == GZ_JOURNAL_OK);
        gz_journal_close(j);
        memfs_free(&fs);
    }

    /* The unsynced bound: two batches of 51 bytes fill 102 exactly and stay
     * unsynced; a third passes it and makes the first two durable first. */
    memfs_init(&fs);
    j = open_on(&fs, 0, 0, 102, &st, NULL);
    CHECK(save_n(j, 1, 1, 10, 0x7e570001) == GZ_JOURNAL_OK && save_n(j, 1, 2, 10, 0x7e570001) == GZ_JOURNAL_OK);
    CHECK(marks_in(&fs) == 1);
    CHECK(save_n(j, 1, 3, 10, 0x7e570001) == GZ_JOURNAL_OK && marks_in(&fs) == 2);
    gz_storage_reader_t rd = gz_journal_reader(j);
    gz_stored_batch_t sb;
    int k = 0;
    while (rd.next(rd.ctx, &sb)) k++;
    CHECK(k == 2 && gz_journal_pending(j) == 3);
    CHECK(gz_journal_flush(j) == GZ_JOURNAL_OK && marks_in(&fs) == 3 && gz_journal_pending(j) == 0);
    gz_journal_close(j);
    memfs_free(&fs);
    /* With the default bound, saves alone never sync. */
    memfs_init(&fs);
    j = open_on(&fs, 0, 0, 0, &st, NULL);
    for (uint64_t s = 1; s <= 32; s++) CHECK(save_n(j, 1, s, 200, 0x7e570001) == GZ_JOURNAL_OK);
    CHECK(marks_in(&fs) == 1);
    /* A 33rd unconfirmed batch is more than the runner can issue. */
    CHECK(save_n(j, 1, 33, 1, 0x7e570001) == GZ_JOURNAL_ERR_SEQUENCE && gz_journal_failed(j));
    gz_journal_close(j);
    memfs_free(&fs);
}

static void test_save_arguments(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    memfs_init(&fs);
    gz_journal_t *j = open_on(&fs, 0, 0, 0, &st, NULL);
    CHECK(gz_journal_save(NULL, NULL) == GZ_JOURNAL_ERR_ARGUMENT);
    CHECK(gz_journal_save(j, NULL) == GZ_JOURNAL_ERR_ARGUMENT && gz_journal_failed(j));
    gz_journal_close(j);
    j = open_on(&fs, 0, 0, 0, &st, NULL);
    gz_action_t send = {.kind = GZ_ACTION_SEND};
    CHECK(gz_journal_save(j, &send) == GZ_JOURNAL_ERR_ARGUMENT && gz_journal_failed(j));
    gz_journal_close(j);
    j = open_on(&fs, 0, 0, 0, &st, NULL);
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch = (gz_batch_id_t){gz_journal_incarnation(j), 1};
    a.u.save.n_records = 2; /* and no records */
    CHECK(gz_journal_save(j, &a) != GZ_JOURNAL_OK && gz_journal_failed(j));
    gz_journal_close(j);
    j = open_on(&fs, 0, 0, 0, &st, NULL);
    gz_record_t r = {0x7e570001, {NULL, 3}}; /* a length with no bytes */
    a.u.save.batch = (gz_batch_id_t){gz_journal_incarnation(j), 1};
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    CHECK(gz_journal_save(j, &a) == GZ_JOURNAL_ERR_ARGUMENT && gz_journal_failed(j));
    gz_journal_close(j);
    /* A record longer than an entry may be. */
    j = open_on(&fs, 0, 0, 0, &st, NULL);
    static uint8_t one;
    r.bytes.data = &one;
    r.bytes.len = (size_t)GZ_JOURNAL_ENTRY_MAX + 1;
    CHECK(gz_journal_batch_size(&r, 1) == 0);
    a.u.save.batch = (gz_batch_id_t){gz_journal_incarnation(j), 1};
    size_t before;
    memfs_get(&fs, H_JOURNAL, &before);
    CHECK(gz_journal_save(j, &a) == GZ_JOURNAL_ERR_TOO_LARGE && gz_journal_failed(j));
    size_t after;
    memfs_get(&fs, H_JOURNAL, &after);
    CHECK(before == after);
    CHECK(gz_journal_flush(j) == GZ_JOURNAL_ERR_FAILED && gz_journal_flush(NULL) == GZ_JOURNAL_ERR_ARGUMENT);
    gz_journal_close(j);
    gz_journal_close(NULL);
    /* Guards with no epochs and with 256 epochs are guards. */
    static uint8_t g[66 + 255 * 8];
    for (int epochs = 0; epochs <= 256; epochs += 256) {
        j = open_on(&fs, 0, 0, 0, &st, NULL);
        h_guard_bytes(g, 4);
        g[48] = (uint8_t)(epochs >> 8);
        g[49] = (uint8_t)epochs;
        gz_record_t gr = {GZ_RECORD_GUARD, {g, GZ_GUARD_MIN_LEN + 8 * (size_t)epochs}};
        a.u.save.batch = (gz_batch_id_t){gz_journal_incarnation(j), 1};
        a.u.save.records = &gr;
        CHECK(gz_journal_save(j, &a) == GZ_JOURNAL_OK && gz_journal_flush(j) == GZ_JOURNAL_OK);
        size_t glen;
        CHECK(memfs_get(&fs, H_GUARD, &glen) && glen == gr.bytes.len + 8);
        gz_journal_close(j);
    }
    /* Arguments of open. */
    gz_journal_t *jj;
    gz_journal_config_t cfg = {H_DIR, NULL, 3, &fs.os, 0, 0, 0, 0, 0, NULL, NULL};
    CHECK(gz_journal_open(&jj, &cfg, NULL) == GZ_JOURNAL_ERR_ARGUMENT && jj == NULL);
    cfg.chain = gz_journal_chain_signet;
    cfg.dir = NULL;
    CHECK(gz_journal_open(&jj, &cfg, NULL) == GZ_JOURNAL_ERR_ARGUMENT && jj == NULL);
    memfs_free(&fs);
}

/* The runner refuses a confirmation: the journal stops too. */
static void test_runner_refusal(void)
{
    h_t *h = calloc(1, sizeof *h);
    memfs_init(&h->fs);
    CHECK(h_open(h, NULL) == GZ_JOURNAL_OK);
    h_step(h);
    gz_runner_storage_failed(&h->runner);
    CHECK(gz_journal_flush(h->j) == GZ_JOURNAL_ERR_FAILED && gz_journal_failed(h->j) && !h->confirmed[0]);
    CHECK(gz_journal_flush(h->j) == GZ_JOURNAL_ERR_FAILED);
    h_close(h);
    memfs_free(&h->fs);
    free(h);
}

/* Durable bytes changed or lost behind the journal's back: the reader fails
 * the journal and the runner instead of yielding less. */
static void test_reader_recheck(void)
{
    for (int how = 0; how < 3; how++) {
        h_t *h = calloc(1, sizeof *h);
        memfs_init(&h->fs);
        CHECK(h_open(h, NULL) == GZ_JOURNAL_OK);
        gz_journal_attach(h->j, NULL, NULL, NULL);
        CHECK(save_n(h->j, 1, 1, 5, 0x7e570001) == GZ_JOURNAL_OK && gz_journal_flush(h->j) == GZ_JOURNAL_OK);
        gz_journal_attach(h->j, &h->runner, NULL, NULL);
        size_t len;
        const uint8_t *cur = memfs_get(&h->fs, H_JOURNAL, &len);
        uint8_t *d = malloc(len);
        memcpy(d, cur, len);
        if (how == 0) d[130] ^= 1;              /* inside the batch */
        if (how == 1) len = 140;                /* cut inside it */
        if (how == 2) d[126] = 3;               /* now a mark-kind entry */
        memfs_put(&h->fs, H_JOURNAL, d, len);
        gz_storage_reader_t rd = gz_journal_reader(h->j);
        gz_stored_batch_t sb;
        CHECK(rd.next(rd.ctx, &sb) == 0 && gz_journal_failed(h->j) && gz_runner_failed(&h->runner));
        free(d);
        h_close(h);
        memfs_free(&h->fs);
        free(h);
    }
}

static void test_open_points(void)
{
    uint8_t torn[300];
    /* (The same points crashed instead of failed: test_journal_crash.c.) */
    size_t n = gz_journal_encode_header(torn, gz_journal_chain_signet);
    n += small(torn + n, 1, 1, 0);
    n += small(torn + n, 3, 1, n);
    n += one_batch(torn + n, 1, 1, 0x7e570001, 4);
    n += small(torn + n, 3, 1, n);
    n += one_batch(torn + n, 1, 2, 0x7e570001, 4) - 5; /* torn */
    int runs = 0;
    for (int seeded = 0; seeded < 2; seeded++) {
        runs += open_points(seeded ? torn : NULL, n, 0, MEMFS_LOSE);
    }
    printf("  open failure points: %d runs\n", runs);
    CHECK(runs >= 15); /* 10 points creating, 6 cutting */
}

/* Found by the second mutation run: descriptors, index growth past 64
 * batches, reads that return little, a lone batch over the unsynced bound,
 * another valid batch where a durable one was, and a refused open that must
 * leave the file as it was. */
static void test_more(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    memfs_init(&fs);
    gz_journal_t *j = open_on(&fs, 0, 0, 0, &st, NULL);
    CHECK(st == GZ_JOURNAL_OK && memfs_open_fds(&fs) == 2); /* journal and lock */
    static uint8_t g[66];
    h_guard_bytes(g, 1);
    gz_record_t gr = {GZ_RECORD_GUARD, {g, 66}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch = (gz_batch_id_t){1, 1};
    a.u.save.records = &gr;
    a.u.save.n_records = 1;
    CHECK(gz_journal_save(j, &a) == GZ_JOURNAL_OK && gz_journal_flush(j) == GZ_JOURNAL_OK);
    CHECK(memfs_open_fds(&fs) == 2); /* the guard's temporary file is closed */
    for (uint64_t s = 2; s <= 200; s++) {
        CHECK(save_n(j, 1, s, 3, 0x7e570001) == GZ_JOURNAL_OK);
        if (s % 7 == 0 || s == 200) CHECK(gz_journal_flush(j) == GZ_JOURNAL_OK);
    }
    gz_storage_reader_t rd = gz_journal_reader(j);
    gz_stored_batch_t sb;
    uint64_t k = 0;
    while (rd.next(rd.ctx, &sb)) k += sb.id.sequence == k + 1;
    CHECK(k == 200 && !gz_journal_failed(j));
    gz_journal_close(j);
    CHECK(memfs_open_fds(&fs) == 0 && fs.bad_closes == 0);
    /* Reads that return 7 bytes at a time. */
    fs.max_read = 7;
    j = open_on(&fs, 0, 0, 0, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.scan.n_batches == 200 && info.scan.verdict == GZ_JOURNAL_CLEAN);
    rd = gz_journal_reader(j);
    k = 0;
    while (rd.next(rd.ctx, &sb)) k += sb.id.sequence == k + 1 && sb.n_records == 1;
    CHECK(k == 200 && !gz_journal_failed(j));
    gz_journal_close(j);
    fs.max_read = 0;
    /* A refused open leaves the file as it was, and nothing open. */
    size_t before, after;
    memfs_get(&fs, H_JOURNAL, &before);
    j = open_on(&fs, 0, before + 73, 0, &st, NULL);
    memfs_get(&fs, H_JOURNAL, &after);
    CHECK(st == GZ_JOURNAL_ERR_FULL && j == NULL && after == before);
    CHECK(memfs_open_fds(&fs) == 0 && fs.bad_closes == 0);
    memfs_free(&fs);

    /* One batch larger than the unsynced bound, right after an open: there
     * is nothing unsynced to make durable first, so no extra mark. */
    memfs_init(&fs);
    j = open_on(&fs, 0, 0, 40, &st, NULL);
    CHECK(save_n(j, 1, 1, 10, 0x7e570001) == GZ_JOURNAL_OK && marks_in(&fs) == 1);
    CHECK(save_n(j, 1, 2, 10, 0x7e570001) == GZ_JOURNAL_OK && marks_in(&fs) == 2);
    gz_journal_close(j);
    memfs_free(&fs);

    /* Another valid batch, shorter, written over a durable one. */
    memfs_init(&fs);
    j = open_on(&fs, 0, 0, 0, &st, NULL);
    CHECK(save_n(j, 1, 1, 20, 0x7e570001) == GZ_JOURNAL_OK && gz_journal_flush(j) == GZ_JOURNAL_OK);
    size_t len;
    const uint8_t *cur = memfs_get(&fs, H_JOURNAL, &len);
    uint8_t *d = malloc(len);
    memcpy(d, cur, len);
    one_batch(d + 122, 1, 1, 0x7e570001, 2);
    memfs_put(&fs, H_JOURNAL, d, len);
    rd = gz_journal_reader(j);
    CHECK(rd.next(rd.ctx, &sb) == 0 && gz_journal_failed(j));
    free(d);
    gz_journal_close(j);
    memfs_free(&fs);
}

/* A small journal written by the journal itself (three incarnations, marked
 * and unmarked batches), cut at every length and damaged at every byte with
 * two different bit flips. The expected outcome is worked out from the entry
 * map alone: a cut is a torn tail at the entry it falls in (or clean on a
 * boundary); damage to entry k is corruption if a sync mark starts after k,
 * else a torn tail cut at k. Corruption must leave the file untouched; a cut
 * must keep exactly the bytes before k. */
static void test_every_byte(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    memfs_init(&fs);
    for (uint64_t inc = 1; inc <= 3; inc++) {
        gz_journal_t *j = open_on(&fs, 0, 0, 0, &st, NULL);
        for (uint64_t s = 1; s <= 3; s++) {
            CHECK(save_n(j, inc, s, (size_t)(s * 5), 0x00020006) == GZ_JOURNAL_OK);
            if (inc < 3 && s != 2) gz_journal_flush(j);
        }
        gz_journal_close(j); /* the last batches of each run stay unmarked */
    }
    size_t len;
    const uint8_t *cur = memfs_get(&fs, H_JOURNAL, &len);
    uint8_t *orig = malloc(len), *d = malloc(len);
    memcpy(orig, cur, len);
    memfs_free(&fs);
    /* The entry map. */
    uint64_t start[128], last_mark = 0;
    size_t n = 0;
    for (uint64_t p = 48; p < len; n++) {
        start[n] = p;
        if (orig[p + 4] == GZ_JOURNAL_KIND_MARK) last_mark = p;
        p += 12 + ((uint64_t)orig[p] << 24 | (uint64_t)orig[p + 1] << 16 | (uint64_t)orig[p + 2] << 8 | orig[p + 3]);
    }
    start[n] = len;
    int bad = 0, cases = 0;
    for (size_t cut = 0; cut <= len; cut++) {
        gz_journal_open_info_t info;
        memfs_init(&fs);
        memfs_put(&fs, H_JOURNAL, orig, cut);
        gz_journal_t *j = open_on(&fs, 0, 0, 0, &st, &info);
        size_t k = 0; /* the last entry starting at or before the cut */
        while (k < n && start[k + 1] <= cut) k++;
        uint64_t v = k < n && start[k] < cut ? start[k] : cut;
        if (cut < 48) bad += st != GZ_JOURNAL_ERR_HEADER;
        else bad += st != GZ_JOURNAL_OK || info.scan.valid_end != v || info.cut_bytes != cut - v;
        gz_journal_close(j);
        memfs_free(&fs);
        cases++;
    }
    for (size_t i = 0; i < len; i++)
        for (int f = 0; f < 2; f++) {
            memcpy(d, orig, len);
            d[i] ^= f ? 0x80 : 0x01;
            gz_journal_open_info_t info;
            memfs_init(&fs);
            memfs_put(&fs, H_JOURNAL, d, len);
            gz_journal_t *j = open_on(&fs, 0, 0, 0, &st, &info);
            size_t now;
            const uint8_t *after = memfs_get(&fs, H_JOURNAL, &now);
            if (i < 48) {
                bad += st != GZ_JOURNAL_ERR_HEADER || now != len;
            } else {
                size_t k = 0;
                while (start[k + 1] <= i) k++;
                if (last_mark > start[k]) /* a mark starts after the damaged entry */
                    bad += st != GZ_JOURNAL_ERR_CORRUPT || info.scan.error_at != start[k] || now != len ||
                           memcmp(after, d, len) != 0;
                else
                    bad += st != GZ_JOURNAL_OK || info.scan.valid_end != start[k] ||
                           now != start[k] + 74 || memcmp(after, orig, start[k]) != 0;
            }
            gz_journal_close(j);
            memfs_free(&fs);
            cases++;
        }
    printf("  every byte: %zu-byte journal, %zu entries, %d cuts and flips\n", len, n, cases);
    CHECK(bad == 0 && n > 15 && last_mark > 48);
    free(orig);
    free(d);
}

int main(void)
{
    test_every_byte();
    test_more();
    test_constants();
    test_scan_edges();
    test_limit_edges();
    test_save_arguments();
    test_runner_refusal();
    test_reader_recheck();
    test_open_points();
    return check_done();
}
