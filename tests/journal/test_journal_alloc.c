/* The journal under allocation failure (re-confirmation review of PR 29,
 * finding N1). journal.c is built into this test with its malloc, calloc and
 * realloc routed through a hook (journal_alloc_hook.c) that can fail the
 * N-th allocation, every allocation from the N-th on, or every allocation of
 * at least a given size.
 *
 *   1. N1 itself: with every allocation of the size the old check needed
 *      (salt + offset + frame) failing, a save of a 1,000-byte record is ok
 *      and confirmed, and the journal reads back, now and later: the check
 *      allocates nothing. The same on the read side: the open is ok.
 *   2. The check makes no allocation at all, for any entry size.
 *   3. Every allocation of an open, a save, a complete and a read failed in
 *      turn (the N-th alone, and all from the N-th on): a call either
 *      succeeds or fails with no_memory (an open never says corrupt, order,
 *      header or marker; a failed save fails the journal and confirms
 *      nothing), and with memory back the journal opens, every confirmed
 *      batch is there with its bytes, and nothing unconfirmed that is kept
 *      differs from what was saved.
 *   4. The same for an import and a restore mark. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../check.h"
#include "harness.h"

#define H_MARKER H_DIR "/" GZ_JOURNAL_MARKER_FILE
#define H_STAGED H_DIR "/journal.gzj.import"

/* --- the hook --------------------------------------------------------------- */
static unsigned long a_count;      /* allocations asked for since the last reset */
static unsigned long a_fail_at;    /* fail the N-th (1-based); 0: none */
static int a_fail_from;            /* with a_fail_at: fail every one from the N-th on */
static size_t a_fail_size;         /* fail every allocation of exactly this size; 0: none */
static unsigned long a_failed;     /* how many were failed */

static int a_fails(size_t n)
{
    a_count++;
    int f = (a_fail_at && (a_fail_from ? a_count >= a_fail_at : a_count == a_fail_at)) ||
            (a_fail_size && n == a_fail_size);
    a_failed += (unsigned long)f;
    return f;
}

void *gz_test_malloc(size_t n);
void *gz_test_calloc(size_t k, size_t n);
void *gz_test_realloc(void *p, size_t n);
void *gz_test_malloc(size_t n) { return a_fails(n) ? NULL : malloc(n); }
void *gz_test_calloc(size_t k, size_t n) { return a_fails(k * n) ? NULL : calloc(k, n); }
void *gz_test_realloc(void *p, size_t n) { return a_fails(n) ? NULL : realloc(p, n); }

static void a_reset(void) { a_count = a_fail_at = a_fail_size = a_failed = 0; a_fail_from = 0; }

/* --- helpers ---------------------------------------------------------------- */
static gz_journal_t *jopen(memfs_t *fs, gz_journal_status_t *st, gz_journal_open_info_t *info)
{
    gz_journal_t *j = NULL;
    gz_journal_open_info_t scratch;
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 11, &fs->os, 0, 0, 0, 1, 0, NULL, NULL};
    *st = gz_journal_open(&j, &cfg, info ? info : &scratch);
    return j;
}

static uint8_t pat(uint64_t inc, uint64_t seq, size_t k) { return (uint8_t)h_mix(inc * 131 + seq * 7 + k); }

/* Batch (inc, seq): one record of `len` patterned bytes, and with `guard` a
 * guard record of counter inc * 100 + seq. */
static gz_journal_status_t save(gz_journal_t *j, uint64_t seq, size_t len, int guard)
{
    static uint8_t b[4096];
    uint8_t g[66];
    uint64_t inc = gz_journal_incarnation(j);
    for (size_t k = 0; k < len; k++) b[k] = pat(inc, seq, k);
    h_guard_bytes(g, inc * 100 + seq);
    gz_record_t r[2] = {{0x7e570001, {b, len}}, {GZ_RECORD_GUARD, {g, 66}}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch = (gz_batch_id_t){inc, seq};
    a.u.save.records = r;
    a.u.save.n_records = guard ? 2 : 1;
    return gz_journal_save(j, &a);
}

/* Every batch the reader yields has its first record's bytes exactly as
 * saved; returns the count, or -1 on a difference. *has: (inc, seq) seen. */
static int read_all_batches(gz_journal_t *j, uint64_t inc, uint64_t seq, int *has)
{
    gz_storage_reader_t rd = gz_journal_reader(j);
    gz_stored_batch_t sb;
    int n = 0;
    if (has) *has = 0;
    while (rd.next(rd.ctx, &sb)) {
        if (sb.n_records < 1) return -1;
        for (size_t k = 0; k < sb.records[0].bytes.len; k++)
            if (sb.records[0].bytes.data[k] != pat(sb.id.incarnation, sb.id.sequence, k)) return -1;
        if (has && sb.id.incarnation == inc && sb.id.sequence == seq) *has = 1;
        n++;
    }
    return gz_journal_failed(j) ? -1 : n;
}

/* A journal with three incarnations, small and large batches, one guard. */
static void seed(memfs_t *fs)
{
    gz_journal_status_t st;
    gz_batch_id_t id;
    memfs_init(fs);
    for (int i = 0; i < 3; i++) {
        gz_journal_t *j = jopen(fs, &st, NULL);
        save(j, 1, 10, 0);
        save(j, 2, 1000, i == 1);
        save(j, 3, 600, 0);
        while (gz_journal_complete(j, &id)) {}
        gz_journal_close(j);
    }
}

/* --- 1, 2 ------------------------------------------------------------------- */
static void test_n1(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    gz_batch_id_t id;
    int has;
    memfs_init(&fs);
    a_reset();
    gz_journal_t *j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK);
    /* The frame of a 1,000-byte record is 21 + 4 + 8 + 1000 bytes; the old
     * check allocated salt (32) + offset (8) + frame for it. */
    const size_t frame = 21 + 4 + 8 + 1000, old_check = 32 + 8 + frame;
    a_reset();
    a_fail_size = old_check;
    CHECK(save(j, 1, 1000, 0) == GZ_JOURNAL_OK && !gz_journal_failed(j));
    CHECK(gz_journal_complete(j, &id) == 1 && id.sequence == 1);
    CHECK(a_failed == 0); /* nothing of that size is asked for any more */
    /* 2. The save's only allocation is the entry's own buffer. */
    a_reset();
    CHECK(save(j, 2, 3000, 0) == GZ_JOURNAL_OK && a_count == 1);
    CHECK(gz_journal_complete(j, &id) == 1);
    a_reset();
    gz_journal_close(j);
    /* The read side, the same allocations failing: ok, not corrupt. */
    a_fail_size = old_check;
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && read_all_batches(j, 1, 1, &has) == 2 && has && a_failed == 0);
    gz_journal_close(j);
    a_reset();
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && read_all_batches(j, 1, 2, &has) == 2 && has);
    gz_journal_close(j);
    /* The check itself, at sizes around the old stack buffer and far past it. */
    static uint8_t big[70000];
    uint8_t c[GZ_JOURNAL_CHECK_LEN];
    a_reset();
    a_fail_at = 1;
    a_fail_from = 1;
    static const size_t sizes[] = {0, 1, 55, 56, 63, 64, 471, 472, 473, 4096, 70000};
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) gz_journal_entry_check(h_salt, k, big, sizes[k], c);
    CHECK(a_count == 0);
    a_reset();
    memfs_free(&fs);
}

/* --- 3 ---------------------------------------------------------------------- */

/* One life on a seeded journal with allocation `n` failing (alone, or all
 * from it on). Returns 1 if a failure was injected. */
static int one_life(unsigned long n, int from, int *bad)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    gz_batch_id_t id;
    int confirmed[4] = {0, 0, 0, 0};
    uint64_t inc = 0;
    seed(&fs);
    a_reset();
    a_fail_at = n;
    a_fail_from = from;
    gz_journal_t *j = jopen(&fs, &st, &info);
    if (!j) {
        /* A refusal for want of memory is a resource error, never a verdict
         * on the journal. */
        if (st != GZ_JOURNAL_ERR_NO_MEMORY) { (*bad)++; printf("  open at %lu: %s\n", n, gz_journal_status_name(st)); }
        if (memfs_open_fds(&fs) != 0) (*bad)++;
    } else {
        inc = info.incarnation;
        if (read_all_batches(j, 0, 0, NULL) < 0 && !gz_journal_failed(j)) (*bad)++;
        for (uint64_t s = 1; s <= 3; s++) {
            int was_failed = gz_journal_failed(j);
            gz_journal_status_t ss = save(j, s, s == 2 ? 1500 : 40, s == 3);
            if (ss != GZ_JOURNAL_OK) {
                /* A failed save fails the journal, with the reason. */
                if (!gz_journal_failed(j)) (*bad)++;
                if (!was_failed && ss != GZ_JOURNAL_ERR_NO_MEMORY) {
                    (*bad)++;
                    printf("  save at %lu: %s\n", n, gz_journal_status_name(ss));
                }
                break;
            }
            while (gz_journal_complete(j, &id)) {
                if (id.incarnation != inc || id.sequence < 1 || id.sequence > 3) (*bad)++;
                else confirmed[id.sequence] = 1;
            }
        }
        if (gz_journal_failed(j) && gz_journal_complete(j, &id)) (*bad)++;
        gz_journal_close(j);
    }
    int injected = a_failed > 0;
    a_reset();
    /* With memory back: the journal opens, whatever happened. */
    j = jopen(&fs, &st, &info);
    if (st != GZ_JOURNAL_OK) {
        (*bad)++;
        printf("  after a failure at %lu (%s): reopen %s\n", n, from ? "from" : "alone", gz_journal_status_name(st));
    } else {
        int has;
        if (read_all_batches(j, 0, 0, NULL) < 9) (*bad)++; /* the nine seeded batches, bytes intact */
        for (uint64_t s = 1; s <= 3; s++)
            if (confirmed[s]) {
                read_all_batches(j, inc, s, &has);
                if (!has) { (*bad)++; printf("  confirmed (%llu,%llu) lost at %lu\n", (unsigned long long)inc, (unsigned long long)s, n); }
            }
        gz_journal_close(j);
    }
    if (memfs_open_fds(&fs) != 0) (*bad)++;
    memfs_free(&fs);
    return injected;
}

static void test_every_allocation(void)
{
    int bad = 0, runs = 0;
    for (int from = 0; from < 2; from++)
        for (unsigned long n = 1;; n++) {
            int injected = one_life(n, from, &bad);
            if (!injected) break; /* past the last allocation of a life */
            runs++;
        }
    printf("  allocation failures: %d lives, each with one allocation (or all from it on) failing\n", runs);
    CHECK(bad == 0 && runs >= 30);
}

/* --- 4 ---------------------------------------------------------------------- */
static void test_import_allocations(void)
{
    int bad = 0, runs = 0;
    for (int what = 0; what < 2; what++)
        for (unsigned long n = 1;; n++) {
            memfs_t fs;
            gz_journal_status_t st;
            gz_journal_open_info_t info;
            size_t blen, len;
            seed(&fs);
            const uint8_t *d = memfs_get(&fs, H_JOURNAL, &blen);
            uint8_t *backup = malloc(blen);
            memcpy(backup, d, blen);
            memfs_put(&fs, H_STAGED, backup, blen - 700); /* an older, shorter state: torn, as a copy cut short */
            free(backup);
            a_reset();
            a_fail_at = n;
            gz_journal_status_t is = what ? gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0)
                                          : gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0);
            int injected = a_failed > 0;
            a_reset();
            if (injected && is != GZ_JOURNAL_ERR_NO_MEMORY && is != GZ_JOURNAL_OK) {
                bad++;
                printf("  %s at %lu: %s\n", what ? "mark" : "import", n, gz_journal_status_name(is));
            }
            /* Refused for memory: nothing was written. */
            if (is == GZ_JOURNAL_ERR_NO_MEMORY &&
                (memfs_get(&fs, H_MARKER, &len) || (!what && !memfs_get(&fs, H_STAGED, &len))))
                bad++;
            if (memfs_open_fds(&fs) != 0) bad++;
            gz_journal_t *j = jopen(&fs, &st, &info);
            if (st != GZ_JOURNAL_OK || info.restored != (is == GZ_JOURNAL_OK) || info.incarnation != 4) bad++;
            gz_journal_close(j);
            memfs_free(&fs);
            if (!injected) break;
            runs++;
        }
    printf("  import and mark allocation failures: %d runs\n", runs);
    CHECK(bad == 0 && runs >= 8);
}

int main(void)
{
    test_n1();
    test_every_allocation();
    test_import_allocations();
    return check_done();
}
