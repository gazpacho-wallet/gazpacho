/* Regressions for the findings of review A of PR 29 (the journal), each
 * written to fail on the code before its fix:
 *
 *   R1  A failed sync, the way Linux's ext4 and XFS fail one (the bytes stay
 *       readable in the page cache and never reach the disk): the next open,
 *       in the same boot or in the same process (contract-v2 test T6),
 *       reads the disk, so it neither gives the node a batch that was never
 *       durable nor writes a sync mark after one (the reviewer's probes F1,
 *       F1b). And POSIX pread_device returns the file's bytes at any offset.
 *   R2  An import writes the marker before the file: a crash at any point
 *       of it never starts the backup unmarked, never reuses an incarnation
 *       (F3).
 *   R3  The lock is on journal.lock, never replaced: renaming a copy over
 *       journal.gzj does not let a second program in (F4); two first starts
 *       are serialised.
 *   R4  The start counter on every start, handed out before the incarnation
 *       entry is written; a key file with no journal starts as a restore.
 *   R5  The hard limit holds when the unsynced bound adds a mark (F2).
 *   R6  A guard batch kept across a kill reaches guard.gzg (F5).
 *   R7  2^63 refused (F6); a flush with no runner attached refuses and
 *       keeps the batches; a flush from on_confirmed confirms in order; a
 *       file system without hard links. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../check.h"
#include "harness.h"

#define H_MARKER H_DIR "/" GZ_JOURNAL_MARKER_FILE
#define H_LOCK   H_DIR "/" GZ_JOURNAL_LOCK_FILE
#define H_STAGED H_DIR "/journal.gzj.import"

static gz_journal_t *jopen_c(memfs_t *fs, const gz_journal_os_t *os, uint64_t hard, uint64_t unsynced,
                             uint64_t counter, gz_journal_status_t *st, gz_journal_open_info_t *info)
{
    gz_journal_t *j = NULL;
    gz_journal_open_info_t scratch;
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 11, os ? os : &fs->os, 0, hard, unsynced, 1, 0, NULL, NULL};
    cfg.start_counter = counter;
    *st = gz_journal_open(&j, &cfg, info ? info : &scratch);
    return j;
}

static gz_journal_t *jopen(memfs_t *fs, gz_journal_status_t *st, gz_journal_open_info_t *info)
{
    return jopen_c(fs, NULL, 0, 0, 0, st, info);
}

static gz_journal_status_t save(gz_journal_t *j, uint64_t seq, size_t len, uint8_t fill)
{
    static uint8_t b[8192];
    memset(b, fill, len);
    gz_record_t r = {0x7e570001, {b, len}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch = (gz_batch_id_t){gz_journal_incarnation(j), seq};
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    return gz_journal_save(j, &a);
}

static int drain(gz_journal_t *j)
{
    gz_batch_id_t id;
    int n = 0;
    while (gz_journal_complete(j, &id)) n++;
    return n;
}

static int has_batch(gz_journal_t *j, uint64_t inc, uint64_t seq)
{
    gz_storage_reader_t rd = gz_journal_reader(j);
    gz_stored_batch_t b;
    int found = 0;
    while (rd.next(rd.ctx, &b)) found |= b.id.incarnation == inc && b.id.sequence == seq;
    return found;
}

static size_t file_len(memfs_t *fs, const char *path)
{
    size_t len = 0;
    return memfs_get(fs, path, &len) ? len : (size_t)-1;
}

/* --- R1 ------------------------------------------------------------------- */

/* Program A saves (inc, 1) and (inc, 2); point `which` of the flush of
 * (inc, 2) fails: 1 its sync, 3 its mark's sync. A fails and confirms
 * nothing. Program B starts in the same boot (or the same process restarts
 * the node), then the power goes, then C starts. `drops`: the older memfs
 * model, in which the failed bytes vanish from view too. */
static void failed_sync_then_restart(uint64_t which, int drops)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    memfs_init(&fs);
    fs.sync_fail_drops = drops;
    gz_journal_t *a = jopen(&fs, &st, &info);
    uint64_t inc = info.incarnation;
    CHECK(save(a, 1, 100, 1) == GZ_JOURNAL_OK && drain(a) == 1);
    CHECK(save(a, 2, 100, 2) == GZ_JOURNAL_OK);
    fs.points = 0;
    fs.fail_at = which;
    fs.fail_mode = MEMFS_FAIL_ERROR;
    CHECK(drain(a) == 0 && gz_journal_failed(a));
    size_t seen = 0, disk = 0;
    memfs_get(&fs, H_JOURNAL, &seen);
    memfs_disk(&fs, H_JOURNAL, &disk);
    /* Linux: what failed is readable and not durable. */
    CHECK(drops ? seen == disk : seen == disk + (which == 1 ? 141 : GZ_JOURNAL_MARK_LEN));
    gz_journal_close(a);
    fs.fail_at = 0;

    gz_journal_t *b = jopen(&fs, &st, &info);
    int ok = st == GZ_JOURNAL_OK && has_batch(b, inc, 1);
    /* (inc, 2) was durable only if its own sync passed. */
    ok = ok && has_batch(b, inc, 2) == (which == 3);
    ok = ok && info.cut_bytes == (drops ? 0 : which == 1 ? 141 : GZ_JOURNAL_MARK_LEN);
    if (!ok) printf("  failed sync %llu (drops %d): B open %s, cut %llu, kept (%llu,2) %d\n",
                    (unsigned long long)which, drops, gz_journal_status_name(st),
                    (unsigned long long)info.cut_bytes, (unsigned long long)inc, b ? has_batch(b, inc, 2) : -1);
    CHECK(ok);
    gz_journal_close(b);

    memfs_settle(&fs, MEMFS_LOSE, 0); /* the power cut */
    gz_journal_t *c = jopen(&fs, &st, &info);
    ok = st == GZ_JOURNAL_OK && has_batch(c, inc, 1) && has_batch(c, inc, 2) == (which == 3);
    if (!ok) printf("  failed sync %llu (drops %d): after the power cut: %s\n", (unsigned long long)which,
                    drops, gz_journal_status_name(st));
    CHECK(ok);
    gz_journal_close(c);
    CHECK(memfs_open_fds(&fs) == 0);
    memfs_free(&fs);
}

/* The POSIX table's device read returns the file's bytes for any offset and
 * length, short only at the end of the file. Run in /tmp (tmpfs here) and in
 * the working folder (the build tree, a disk file system where O_DIRECT is
 * taken), so both the direct path and the fallback are exercised. */
static void device_read_in(const char *base)
{
    char dir[300];
    snprintf(dir, sizeof dir, "%s/gzj-dev-XXXXXX", base);
    CHECK(mkdtemp(dir) != NULL);
    char path[340];
    snprintf(path, sizeof path, "%s/f", dir);
    static uint8_t want[3 * 4096 + 777], got[sizeof want + 64];
    for (size_t i = 0; i < sizeof want; i++) want[i] = (uint8_t)h_mix(i);
    FILE *f = fopen(path, "wb");
    CHECK(f && fwrite(want, 1, sizeof want, f) == sizeof want);
    if (f) fclose(f);
    const gz_journal_os_t *px = gz_journal_os_posix();
    CHECK(px->pread_device != NULL);
    if (!px->pread_device) return;
    int fd = px->open(px->ctx, path, GZ_JOURNAL_OPEN_RW);
    CHECK(fd >= 0 && px->sync(px->ctx, fd) == 0);
    static const uint64_t offs[] = {0, 1, 4095, 4096, 4097, 5000, 12288, sizeof want - 1};
    int bad = 0;
    for (size_t k = 0; k < sizeof offs / sizeof offs[0]; k++) {
        uint64_t off = offs[k];
        /* To the end and past it: the bytes, then 0. */
        size_t len = sizeof want - (size_t)off, ask = len + 64;
        memset(got, 0, sizeof got);
        uint64_t g = 0;
        for (;;) {
            long r = px->pread_device(px->ctx, fd, got + g, (size_t)(ask - g), off + g);
            if (r < 0) { bad++; break; }
            if (r == 0) break;
            g += (uint64_t)r;
        }
        bad += g != len || memcmp(got, want + off, len) != 0;
        /* A few bytes in the middle, exactly. */
        size_t few = len < 7 ? len : 7;
        memset(got, 0xee, 16);
        bad += px->pread_device(px->ctx, fd, got, few, off) != (long)few || memcmp(got, want + off, few) != 0 ||
               got[few] != 0xee;
    }
    if (bad) printf("  device read in %s: %d problems\n", base, bad);
    CHECK(bad == 0);
    px->close(px->ctx, fd);
    unlink(path);
    rmdir(dir);
}

static void test_posix_device_read(void)
{
    device_read_in("/tmp");
    device_read_in(".");
}

/* --- R2 ------------------------------------------------------------------- */

/* Five starts, a batch each; *backup is the journal after the second. */
static void five_starts(memfs_t *fs, uint8_t **backup, size_t *blen)
{
    gz_journal_status_t st;
    for (int i = 0; i < 5; i++) {
        gz_journal_t *j = jopen(fs, &st, NULL);
        save(j, 1, 10, (uint8_t)i);
        drain(j);
        gz_journal_close(j);
        if (i == 1) {
            const uint8_t *d = memfs_get(fs, H_JOURNAL, blen);
            *backup = malloc(*blen);
            memcpy(*backup, d, *blen);
        }
    }
}

static void test_import(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    uint8_t *backup = NULL;
    size_t blen = 0, len;

    /* The import: marker, then the file; the restored start is above all five. */
    memfs_init(&fs);
    five_starts(&fs, &backup, &blen);
    memfs_put(&fs, H_STAGED, backup, blen);
    CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0) == GZ_JOURNAL_OK);
    const uint8_t *d = memfs_get(&fs, H_JOURNAL, &len);
    CHECK(d && len == blen && memcmp(d, backup, blen) == 0 && !memfs_get(&fs, H_STAGED, &len) &&
          memfs_get(&fs, H_MARKER, &len));
    gz_journal_t *j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.restored && info.incarnation == 6);
    gz_journal_close(j);
    memfs_free(&fs);
    free(backup);

    /* The reviewer's F3 done the old way (the file replaced, the program dies
     * before marking): the start counter keeps the number from repeating. */
    memfs_init(&fs);
    five_starts(&fs, &backup, &blen);
    memfs_put(&fs, H_JOURNAL, backup, blen);
    j = jopen_c(&fs, NULL, 0, 0, 5, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.incarnation == 6);
    gz_journal_close(j);
    memfs_free(&fs);
    free(backup);

    /* A higher floor from the caller wins; a refused backup changes nothing;
     * an open journal refuses the import. */
    memfs_init(&fs);
    five_starts(&fs, &backup, &blen);
    uint8_t *bad = malloc(blen);
    memcpy(bad, backup, blen);
    bad[3] ^= 1;
    memfs_put(&fs, H_STAGED, bad, blen);
    size_t before = file_len(&fs, H_JOURNAL);
    CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0) == GZ_JOURNAL_ERR_HEADER);
    CHECK(file_len(&fs, H_JOURNAL) == before && !memfs_get(&fs, H_MARKER, &len));
    free(bad);
    memfs_put(&fs, H_STAGED, backup, blen);
    j = jopen(&fs, &st, &info);
    CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0) == GZ_JOURNAL_ERR_LOCKED);
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_ERR_LOCKED);
    gz_journal_close(j); /* incarnation 6 used */
    CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 9) == GZ_JOURNAL_OK);
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.restored && info.incarnation == 10);
    gz_journal_close(j);
    CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, NULL, 0) == GZ_JOURNAL_ERR_ARGUMENT);
    CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0) == GZ_JOURNAL_ERR_IO); /* gone */
    memfs_free(&fs);
    free(backup);

    /* No staged file: nothing written. */
    memfs_init(&fs);
    five_starts(&fs, &backup, &blen);
    free(backup);
    CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0) == GZ_JOURNAL_ERR_IO &&
          !memfs_get(&fs, H_MARKER, &len));
    memfs_free(&fs);

    /* A crash at every point of the import, every settle: the next start is
     * either the old journal, not restored, or the backup, restored; either
     * way above every incarnation used. */
    int runs = 0, olds = 0, backups = 0, wrong = 0;
    for (uint64_t p = 1;; p++) {
        int hit = 0;
        for (int mode = 0; mode < 3; mode++) {
            memfs_init(&fs);
            five_starts(&fs, &backup, &blen);
            memfs_put(&fs, H_STAGED, backup, blen);
            free(backup);
            fs.points = 0;
            fs.crash_at = p;
            gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0);
            hit = fs.crashed;
            if (!hit) { memfs_free(&fs); break; }
            memfs_settle(&fs, mode, p);
            j = jopen(&fs, &st, &info);
            int is_backup = info.scan.highest_incarnation == 2;
            int ok = st == GZ_JOURNAL_OK && info.incarnation >= 6 && (is_backup ? info.restored : !info.restored) &&
                     (is_backup || info.scan.highest_incarnation == 5);
            if (!ok) printf("  import crash at %llu mode %d: %s, highest %llu, restored %d, incarnation %llu\n",
                            (unsigned long long)p, mode, gz_journal_status_name(st),
                            (unsigned long long)info.scan.highest_incarnation, info.restored,
                            (unsigned long long)info.incarnation);
            wrong += !ok;
            backups += is_backup;
            olds += !is_backup;
            gz_journal_close(j);
            memfs_free(&fs);
            runs++;
        }
        if (!hit) break;
    }
    printf("  import crash points: %d runs, %d left the old journal, %d the marked backup\n", runs, olds, backups);
    CHECK(wrong == 0 && runs >= 12 && olds > 0 && backups > 0);
}

/* --- R3 ------------------------------------------------------------------- */

static int copy_file(const char *from, const char *to)
{
    FILE *a = fopen(from, "rb"), *b = fopen(to, "wb");
    int ok = a && b;
    char buf[4096];
    size_t n;
    while (ok && (n = fread(buf, 1, sizeof buf, a)) > 0) ok = fwrite(buf, 1, n, b) == n;
    if (a) fclose(a);
    if (b) fclose(b);
    return ok;
}

/* The reviewer's F4 on real files. */
static void test_lock_real(void)
{
    char dir[] = "/tmp/gzj-lock-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char path[256], copy[256], staged[256], lock[256], marker[256];
    snprintf(path, sizeof path, "%s/%s", dir, GZ_JOURNAL_FILE);
    snprintf(copy, sizeof copy, "%s/%s.copy", dir, GZ_JOURNAL_FILE);
    snprintf(staged, sizeof staged, "%s/%s.import", dir, GZ_JOURNAL_FILE);
    snprintf(lock, sizeof lock, "%s/%s", dir, GZ_JOURNAL_LOCK_FILE);
    snprintf(marker, sizeof marker, "%s/%s", dir, GZ_JOURNAL_MARKER_FILE);
    gz_journal_config_t cfg = {dir, gz_journal_chain_signet, 1, NULL, 0, 0, 0, 1, 0, NULL, NULL};
    gz_journal_t *a = NULL, *b = NULL, *c = NULL;
    CHECK(gz_journal_open(&a, &cfg, NULL) == GZ_JOURNAL_OK);
    CHECK(gz_journal_open(&b, &cfg, NULL) == GZ_JOURNAL_ERR_LOCKED && b == NULL);
    CHECK(copy_file(path, copy) && rename(copy, path) == 0);
    CHECK(gz_journal_open(&c, &cfg, NULL) == GZ_JOURNAL_ERR_LOCKED && c == NULL);
    CHECK(copy_file(path, staged));
    CHECK(gz_journal_import(dir, gz_journal_chain_signet, NULL, staged, 0) == GZ_JOURNAL_ERR_LOCKED);
    CHECK(gz_journal_mark_restored(dir, gz_journal_chain_signet, NULL, 0) == GZ_JOURNAL_ERR_LOCKED);
    struct stat sb;
    CHECK(stat(lock, &sb) == 0 && (sb.st_mode & 0777) == 0600);
    gz_journal_close(a);
    CHECK(gz_journal_open(&c, &cfg, NULL) == GZ_JOURNAL_OK);
    gz_journal_close(c);
    CHECK(gz_journal_import(dir, gz_journal_chain_signet, NULL, staged, 0) == GZ_JOURNAL_OK);
    gz_journal_open_info_t info;
    CHECK(gz_journal_open(&c, &cfg, &info) == GZ_JOURNAL_OK && info.restored && info.incarnation == 3);
    /* The lock file removed by hand while C runs: the journal's own lock
     * still keeps a second program out. */
    CHECK(unlink(lock) == 0);
    CHECK(gz_journal_open(&b, &cfg, NULL) == GZ_JOURNAL_ERR_LOCKED && b == NULL);
    gz_journal_close(c);
    unlink(path);
    unlink(lock);
    unlink(marker);
    CHECK(rmdir(dir) == 0);
}

/* Two first starts at once: the second, run from inside the first's
 * creation of the file, finds the folder locked. */
static memfs_t *race_fs;
static int race_done;
static gz_journal_status_t race_st;
static int race_open(void *ctx, const char *path, int how)
{
    if (!race_done && how == GZ_JOURNAL_OPEN_CREATE_EXCL) {
        race_done = 1;
        gz_journal_t *k = NULL;
        gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 2, &race_fs->os, 0, 0, 0, 1, 0, NULL, NULL};
        race_st = gz_journal_open(&k, &cfg, NULL);
        gz_journal_close(k);
    }
    return race_fs->os.open(ctx, path, how);
}

static void test_first_starts(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    memfs_init(&fs);
    race_fs = &fs;
    race_done = 0;
    gz_journal_os_t os = fs.os;
    os.open = race_open;
    gz_journal_t *j = jopen_c(&fs, &os, 0, 0, 0, &st, &info);
    CHECK(race_done && race_st == GZ_JOURNAL_ERR_LOCKED);
    CHECK(st == GZ_JOURNAL_OK && info.created && info.incarnation == 1);
    gz_journal_close(j);
    size_t len;
    const uint8_t *d = memfs_get(&fs, H_JOURNAL, &len);
    gz_journal_scan_t s;
    CHECK(d && gz_journal_scan(d, len, gz_journal_chain_signet, &s, NULL, NULL) == GZ_JOURNAL_OK &&
          s.verdict == GZ_JOURNAL_CLEAN && s.n_incarnations == 1);
    CHECK(!memfs_get(&fs, H_DIR "/" GZ_JOURNAL_FILE ".tmp", &len));
    memfs_free(&fs);
}

/* --- R4 ------------------------------------------------------------------- */

typedef struct {
    memfs_t *fs;
    int calls, fail;
    uint64_t stored, highest_at_call;
} counter_t;

static int write_counter(void *ctx, uint64_t n)
{
    counter_t *c = ctx;
    size_t len;
    const uint8_t *d = memfs_get(c->fs, H_JOURNAL, &len);
    gz_journal_scan_t s;
    gz_journal_scan(d, len, gz_journal_chain_signet, &s, NULL, NULL);
    c->highest_at_call = s.highest_incarnation; /* the entry for n is not written yet */
    c->calls++;
    if (c->fail) return -1;
    c->stored = n;
    return 0;
}

static gz_journal_t *copen(memfs_t *fs, counter_t *c, gz_journal_status_t *st, gz_journal_open_info_t *info)
{
    gz_journal_t *j = NULL;
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 11, &fs->os, 0, 0, 0, 1, 0, NULL, NULL};
    cfg.start_counter = c->stored;
    cfg.write_counter = write_counter;
    cfg.counter_ctx = c;
    *st = gz_journal_open(&j, &cfg, info);
    return j;
}

static void test_counter(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    counter_t c = {&fs, 0, 0, 0, 0};
    memfs_init(&fs);
    gz_journal_t *j = copen(&fs, &c, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.incarnation == 1 && c.calls == 1 && c.stored == 1 && c.highest_at_call == 0);
    gz_journal_close(j);
    /* A counter above the journal wins. */
    c.stored = 7;
    j = copen(&fs, &c, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.incarnation == 8 && c.stored == 8 && c.highest_at_call == 1);
    gz_journal_close(j);
    /* The counter cannot be written: nothing is appended. */
    size_t before = file_len(&fs, H_JOURNAL);
    c.fail = 1;
    j = copen(&fs, &c, &st, &info);
    CHECK(st == GZ_JOURNAL_ERR_IO && j == NULL && file_len(&fs, H_JOURNAL) == before);
    c.fail = 0;
    j = copen(&fs, &c, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.incarnation == 9);
    gz_journal_close(j);
    memfs_free(&fs);

    /* Contract-v2 test T8 on the journal alone: a backup at incarnation 2,
     * three more starts, the backup put back and started as a restore: 6. */
    memfs_init(&fs);
    c.stored = 0;
    c.calls = 0;
    uint8_t *backup = NULL;
    size_t blen = 0;
    for (int i = 0; i < 5; i++) {
        j = copen(&fs, &c, &st, &info);
        save(j, 1, 10, (uint8_t)i);
        drain(j);
        gz_journal_close(j);
        if (i == 1) {
            const uint8_t *d = memfs_get(&fs, H_JOURNAL, &blen);
            backup = malloc(blen);
            memcpy(backup, d, blen);
        }
    }
    CHECK(c.stored == 5);
    memfs_put(&fs, H_JOURNAL, backup, blen);
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_OK);
    j = copen(&fs, &c, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.restored && info.incarnation == 6);
    gz_journal_close(j);
    /* Without the counter (the file missing) the journal alone decides. */
    memfs_put(&fs, H_JOURNAL, backup, blen);
    c.stored = 0;
    j = copen(&fs, &c, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.incarnation == 3);
    gz_journal_close(j);
    free(backup);
    memfs_free(&fs);

    /* A key file with no journal: started as a restore, above the counter. */
    memfs_init(&fs);
    c.stored = 4;
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_OK);
    j = copen(&fs, &c, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.created && info.restored && info.incarnation == 5);
    gz_journal_close(j);
    memfs_free(&fs);
    /* The same with the counter missing (incarnation 1): its answer made
     * durable and the marker's removal failing, the next open recognises
     * the answer from the journal (the marker's base is 0). */
    memfs_init(&fs);
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_OK);
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.restored && info.incarnation == 1 && save(j, 1, 10, 1) == GZ_JOURNAL_OK);
    fs.points = 0;
    fs.fail_at = 4; /* sync, mark, sync, then the marker's unlink */
    fs.fail_mode = MEMFS_FAIL_ERROR;
    CHECK(drain(j) == 0 && gz_journal_failed(j));
    gz_journal_close(j);
    fs.fail_at = 0;
    size_t mlen;
    CHECK(memfs_get(&fs, H_MARKER, &mlen) != NULL);
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && !info.restored && info.incarnation == 2 && !memfs_get(&fs, H_MARKER, &mlen));
    gz_journal_close(j);
    memfs_free(&fs);

    /* 2^63 (contract-v2 section 8; the reviewer's F6). */
    memfs_init(&fs);
    j = jopen(&fs, &st, &info);
    gz_journal_close(j);
    before = file_len(&fs, H_JOURNAL);
    const uint64_t lim = GZ_JOURNAL_INCARNATION_LIMIT;
    j = jopen_c(&fs, NULL, 0, 0, lim, &st, &info);
    CHECK(st == GZ_JOURNAL_ERR_INCARNATION && j == NULL && file_len(&fs, H_JOURNAL) == before);
    j = jopen_c(&fs, NULL, 0, 0, lim - 1, &st, &info);
    CHECK(st == GZ_JOURNAL_ERR_INCARNATION && j == NULL);
    j = jopen_c(&fs, NULL, 0, 0, UINT64_MAX, &st, &info);
    CHECK(st == GZ_JOURNAL_ERR_INCARNATION && j == NULL);
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, lim) == GZ_JOURNAL_OK);
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_ERR_INCARNATION && j == NULL && file_len(&fs, H_JOURNAL) == before);
    fs.os.unlink(fs.os.ctx, H_MARKER);
    j = jopen_c(&fs, NULL, 0, 0, lim - 2, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.incarnation == lim - 1);
    gz_journal_close(j);
    j = jopen(&fs, &st, &info); /* the journal itself is now at the limit */
    CHECK(st == GZ_JOURNAL_ERR_INCARNATION && j == NULL);
    CHECK(strcmp(gz_journal_status_name(GZ_JOURNAL_ERR_INCARNATION), "incarnation") == 0);
    memfs_free(&fs);
}

/* --- R5 ------------------------------------------------------------------- */

static void test_hard_limit(void)
{
    const uint64_t hard = 3000;
    for (int fits = 0; fits < 2; fits++) {
        memfs_t fs;
        gz_journal_status_t st;
        memfs_init(&fs);
        gz_journal_t *j = jopen_c(&fs, NULL, hard, 300, 0, &st, NULL);
        uint64_t start = gz_journal_size(j);
        CHECK(save(j, 1, 100, 1) == GZ_JOURNAL_OK); /* 141 bytes, not synced */
        /* Exactly what a check for the entry and one mark lets in; the
         * unsynced bound then writes a mark before it. */
        uint64_t room = hard - (start + 141) - GZ_JOURNAL_MARK_LEN;
        size_t rec = (size_t)(room - 41 - (fits ? GZ_JOURNAL_MARK_LEN : 0));
        gz_journal_status_t s2 = save(j, 2, rec, 2);
        int n = drain(j);
        uint64_t end = gz_journal_size(j);
        CHECK(fits ? s2 == GZ_JOURNAL_OK && n == 2 && end == hard
                   : s2 == GZ_JOURNAL_ERR_FULL && gz_journal_failed(j) && n == 0 && end == start + 141);
        CHECK(end <= hard && file_len(&fs, H_JOURNAL) <= hard);
        gz_journal_close(j);
        /* Never past the limit: an open with room for its incarnation entry
         * and mark reads it. */
        j = jopen_c(&fs, NULL, hard + 2 * GZ_JOURNAL_MARK_LEN, 0, 0, &st, NULL);
        CHECK(st == GZ_JOURNAL_OK && has_batch(j, 1, 1) && has_batch(j, 1, 2) == fits);
        gz_journal_close(j);
        memfs_free(&fs);
    }
}

/* --- R6 ------------------------------------------------------------------- */

static void put_guard_file(memfs_t *fs, uint64_t counter, int damage)
{
    uint8_t g[74], h[32];
    h_guard_bytes(g, counter);
    sha256(g, 66, h);
    memcpy(g + 66, h, 8);
    if (damage) g[70] ^= 1;
    memfs_put(fs, H_GUARD, g, 74);
}

static uint64_t guard_counter(memfs_t *fs, int *valid)
{
    size_t len;
    const uint8_t *g = memfs_get(fs, H_GUARD, &len);
    *valid = 0;
    if (!g || len != 74) return 0;
    uint8_t h[32];
    sha256(g, 66, h);
    *valid = memcmp(h, g + 66, 8) == 0;
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) c = c << 8 | g[40 + i];
    return c;
}

/* A guard batch appended and never flushed (the program killed; the page
 * cache keeps it), then the next start. `pre`: 0 no guard file, 1 an older
 * one, 2 a newer one, 3 a damaged one; `restored`: the start is a restore. */
static void guard_kept(int pre, int restored)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    memfs_init(&fs);
    gz_journal_t *j = jopen(&fs, &st, &info);
    uint8_t g[66];
    h_guard_bytes(g, 9);
    gz_record_t r = {GZ_RECORD_GUARD, {g, 66}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch = (gz_batch_id_t){info.incarnation, 1};
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    CHECK(gz_journal_save(j, &a) == GZ_JOURNAL_OK);
    gz_journal_close(j); /* killed before the flush */
    if (pre) put_guard_file(&fs, pre == 2 ? 20 : 3, pre == 3);
    size_t before_len = 0;
    const uint8_t *bp = memfs_get(&fs, H_GUARD, &before_len);
    uint8_t before[74] = {0};
    if (bp) memcpy(before, bp, before_len);
    if (restored) CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_OK);
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && has_batch(j, 1, 1) && info.restored == restored);
    int valid;
    uint64_t counter = guard_counter(&fs, &valid);
    size_t len = 0;
    const uint8_t *now = memfs_get(&fs, H_GUARD, &len);
    int unchanged = bp ? now && len == before_len && memcmp(now, before, len) == 0 : now == NULL;
    int replaced = !restored && (pre == 0 || pre == 1);
    int ok = replaced ? valid && counter == 9 : unchanged;
    if (!ok) printf("  kept guard batch, guard file %d, restored %d: counter %llu valid %d unchanged %d\n", pre,
                    restored, (unsigned long long)counter, valid, unchanged);
    CHECK(ok);
    gz_journal_close(j);
    memfs_free(&fs);
}

/* --- R7 ------------------------------------------------------------------- */

static void test_no_runner(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    memfs_init(&fs);
    gz_journal_t *j = NULL;
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 11, &fs.os, 0, 0, 0, 0, 0, NULL, NULL};
    CHECK(gz_journal_open(&j, &cfg, NULL) == GZ_JOURNAL_OK);
    CHECK(save(j, 1, 10, 1) == GZ_JOURNAL_OK);
    size_t before = file_len(&fs, H_JOURNAL);
    st = gz_journal_flush(j);
    CHECK(st == GZ_JOURNAL_ERR_ARGUMENT && !gz_journal_failed(j) && gz_journal_pending(j) == 1 &&
          file_len(&fs, H_JOURNAL) == before);
    gz_journal_attach(j, NULL, NULL, NULL); /* stated: nobody confirms */
    CHECK(gz_journal_flush(j) == GZ_JOURNAL_OK && gz_journal_pending(j) == 0);
    gz_journal_close(j);
    memfs_free(&fs);
}

/* A flush from on_confirmed: the node saves in answer and the program
 * flushes at once. Confirmations must stay in order. */
static h_t *re_h;
static int re_depth;
static gz_batch_id_t re_order[8];
static int re_n;
static void re_confirmed(void *ctx, gz_batch_id_t id)
{
    h_on_confirmed(ctx, id);
    if (re_n < 8) re_order[re_n++] = id;
    if (re_depth++ == 0) {
        h_step(re_h);
        gz_journal_flush(re_h->j);
    }
}

static void test_reentrant_flush(void)
{
    h_t *h = calloc(1, sizeof *h);
    memfs_init(&h->fs);
    re_h = h;
    re_depth = re_n = 0;
    CHECK(h_open(h, NULL) == GZ_JOURNAL_OK);
    gz_journal_attach(h->j, &h->runner, re_confirmed, h);
    h_step(h);
    h_step(h);
    CHECK(gz_journal_flush(h->j) == GZ_JOURNAL_OK);
    int ok = !gz_journal_failed(h->j) && !gz_runner_failed(&h->runner) && re_n == 3 &&
             gz_journal_pending(h->j) == 0;
    for (int i = 0; i < re_n; i++) ok &= re_order[i].sequence == (uint64_t)i + 1;
    for (uint64_t g = 0; g < 3; g++) ok &= h->confirmed[g] && h->released[g];
    if (!ok) printf("  re-entrant flush: %d confirmed, failed %d\n", re_n, gz_journal_failed(h->j));
    CHECK(ok);
    h_close(h);
    memfs_free(&h->fs);
    free(h);
}

static void test_no_links(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    size_t len;
    gz_journal_t *j;
    /* Each errno a link gives without hard links: created by rename. Any
     * other link error (EXDEV here) is a failure. */
    static const int errs[] = {EPERM, ENOTSUP, EOPNOTSUPP, ENOSYS, EMLINK, EXDEV};
    for (size_t k = 0; k < sizeof errs / sizeof errs[0]; k++) {
        memfs_init(&fs);
        fs.no_links = errs[k];
        j = jopen(&fs, &st, &info);
        int ok = errs[k] == EXDEV ? st == GZ_JOURNAL_ERR_IO && j == NULL && !memfs_get(&fs, H_JOURNAL, &len)
                                  : st == GZ_JOURNAL_OK && info.created;
        CHECK(ok && !memfs_get(&fs, H_DIR "/" GZ_JOURNAL_FILE ".tmp", &len) && memfs_open_fds(&fs) == (j ? 2 : 0));
        gz_journal_close(j);
        memfs_free(&fs);
    }
    memfs_init(&fs);
    fs.no_links = EPERM;
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.created && info.incarnation == 1);
    CHECK(save(j, 1, 10, 1) == GZ_JOURNAL_OK && drain(j) == 1);
    gz_journal_close(j);
    CHECK(!memfs_get(&fs, H_DIR "/" GZ_JOURNAL_FILE ".tmp", &len));
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && !info.created && info.incarnation == 2 && has_batch(j, 1, 1));
    gz_journal_close(j);
    memfs_free(&fs);
    /* Any other link error is still a failure. */
    memfs_init(&fs);
    fs.points = 0;
    fs.fail_at = 5; /* lock file, temporary file, its header, its sync, then the link */
    fs.fail_mode = MEMFS_FAIL_ERROR;
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_ERR_IO && j == NULL && memfs_open_fds(&fs) == 0);
    memfs_free(&fs);
}

static void test_failed_sync(void)
{
    failed_sync_then_restart(1, 0);
    failed_sync_then_restart(3, 0);
    failed_sync_then_restart(1, 1);
    failed_sync_then_restart(3, 1);
}

static void test_guard_kept(void)
{
    for (int pre = 0; pre < 4; pre++)
        for (int restored = 0; restored < 2; restored++) guard_kept(pre, restored);
}

/* With an argument, only the part of that name. */
int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        void (*fn)(void);
    } parts[] = {{"failed_sync", test_failed_sync}, {"device_read", test_posix_device_read},
                 {"import", test_import},           {"lock_real", test_lock_real},
                 {"first_starts", test_first_starts}, {"counter", test_counter},
                 {"hard_limit", test_hard_limit},   {"guard_kept", test_guard_kept},
                 {"no_runner", test_no_runner},     {"reentrant_flush", test_reentrant_flush},
                 {"no_links", test_no_links}};
    for (size_t i = 0; i < sizeof parts / sizeof parts[0]; i++)
        if (argc < 2 || strcmp(argv[1], parts[i].name) == 0) parts[i].fn();
    return check_done();
}
