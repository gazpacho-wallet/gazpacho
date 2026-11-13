/* Regressions for review B of PR 29 (the journal), each failing on the code
 * before its fix, and the test gaps its mutation probes found:
 *
 *   B1  journal.lock removed or replaced while a program runs: an import or
 *       a mark is refused (the journal's own lock), in one process on memfs
 *       and in 200 rounds of two real processes (the reviewer's case E).
 *   B2  An import that cannot read the journal it replaces is refused; one
 *       the scan refuses still gives its highest incarnation to the floor
 *       (order and corruption).
 *   B3  An open that finds a journal whose name never became durable (its
 *       creating open failed, or was killed, before the folder sync) makes
 *       it durable before confirming anything.
 *   M28 An unreadable restore.gzr refuses the start.
 *   M5  The O_DIRECT refusal (EINVAL) falls back to an ordinary read.
 *   M24 The reader yields nothing once the journal has failed.
 *   M36 The guard file is settled from the newest kept guard record. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../check.h"
#include "harness.h"

#define H_MARKER H_DIR "/" GZ_JOURNAL_MARKER_FILE
#define H_LOCK   H_DIR "/" GZ_JOURNAL_LOCK_FILE
#define H_STAGED H_DIR "/journal.gzj.import"

static gz_journal_t *jopen_os(const gz_journal_os_t *os, const char *dir, gz_journal_status_t *st,
                              gz_journal_open_info_t *info)
{
    gz_journal_t *j = NULL;
    gz_journal_open_info_t scratch;
    gz_journal_config_t cfg = {dir, gz_journal_chain_signet, 11, os, 0, 0, 0, 1, 0, NULL, NULL};
    *st = gz_journal_open(&j, &cfg, info ? info : &scratch);
    return j;
}

static gz_journal_t *jopen(memfs_t *fs, gz_journal_status_t *st, gz_journal_open_info_t *info)
{
    return jopen_os(&fs->os, H_DIR, st, info);
}

static gz_journal_status_t save(gz_journal_t *j, uint64_t seq, size_t len, uint8_t fill)
{
    uint8_t b[256];
    memset(b, fill, sizeof b);
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

/* `n` starts with a batch each on `fs`; *backup is the journal after the
 * second (highest incarnation 2). */
static void starts(memfs_t *fs, int n, uint8_t **backup, size_t *blen)
{
    gz_journal_status_t st;
    for (int i = 0; i < n; i++) {
        gz_journal_t *j = jopen(fs, &st, NULL);
        save(j, 1, 10, (uint8_t)i);
        drain(j);
        gz_journal_close(j);
        if (i == 1 && backup) {
            const uint8_t *d = memfs_get(fs, H_JOURNAL, blen);
            *backup = malloc(*blen);
            memcpy(*backup, d, *blen);
        }
    }
}

/* --- B1 ------------------------------------------------------------------- */

static void test_lock_memfs(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    uint8_t *backup = NULL;
    size_t blen = 0, len;
    memfs_init(&fs);
    starts(&fs, 3, &backup, &blen);
    memfs_put(&fs, H_STAGED, backup, blen);
    gz_journal_t *j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && save(j, 1, 10, 9) == GZ_JOURNAL_OK && drain(j) == 1);
    for (int how = 0; how < 2; how++) {
        /* Removed (0) or replaced by a new file (1) while j runs. */
        CHECK(fs.os.unlink(fs.os.ctx, H_LOCK) == 0);
        if (how == 1) memfs_put(&fs, H_LOCK, NULL, 0);
        size_t before = file_len(&fs, H_JOURNAL);
        CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0) == GZ_JOURNAL_ERR_LOCKED);
        CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_ERR_LOCKED);
        CHECK(file_len(&fs, H_JOURNAL) == before && !memfs_get(&fs, H_MARKER, &len) &&
              memfs_get(&fs, H_STAGED, &len));
        CHECK(memfs_open_fds(&fs) == 2);
    }
    CHECK(save(j, 2, 10, 9) == GZ_JOURNAL_OK && drain(j) == 1 && !gz_journal_failed(j));
    gz_journal_close(j);
    /* The confirmed batches are all there; with nobody running, the import goes ahead. */
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && has_batch(j, 4, 1) && has_batch(j, 4, 2) && !info.restored);
    gz_journal_close(j);
    CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0) == GZ_JOURNAL_OK);
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.restored && info.incarnation == 6);
    gz_journal_close(j);
    free(backup);
    memfs_free(&fs);
}

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

/* The reviewer's case E, as two real processes: P1 opens, confirms a batch
 * and holds the journal; meanwhile journal.lock is removed (even rounds) or
 * replaced (odd rounds) and P2 tries to import a backup and to mark a
 * restore. Both must be refused, and P1's confirmed batch must survive. */
static void test_lock_rounds(int rounds)
{
    char dir[] = "/tmp/gzj-b1-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char jpath[300], lock[300], staged[300], backup[300], marker[300];
    snprintf(jpath, sizeof jpath, "%s/%s", dir, GZ_JOURNAL_FILE);
    snprintf(lock, sizeof lock, "%s/%s", dir, GZ_JOURNAL_LOCK_FILE);
    snprintf(staged, sizeof staged, "%s/journal.gzj.import", dir);
    snprintf(backup, sizeof backup, "%s/backup", dir);
    snprintf(marker, sizeof marker, "%s/%s", dir, GZ_JOURNAL_MARKER_FILE);
    gz_journal_status_t st;
    gz_journal_t *j = jopen_os(gz_journal_os_posix(), dir, &st, NULL);
    CHECK(st == GZ_JOURNAL_OK && save(j, 1, 10, 1) == GZ_JOURNAL_OK && drain(j) == 1);
    gz_journal_close(j);
    CHECK(copy_file(jpath, backup));
    int refused = 0, lost = 0, broken = 0;
    for (int r = 0; r < rounds; r++) {
        int up[2], down[2];
        if (pipe(up) != 0 || pipe(down) != 0) { broken++; break; }
        pid_t pid = fork();
        if (pid == 0) {
            close(up[0]);
            close(down[1]);
            gz_journal_status_t cs;
            gz_journal_t *cj = jopen_os(gz_journal_os_posix(), dir, &cs, NULL);
            uint64_t inc = 0;
            if (cs == GZ_JOURNAL_OK && save(cj, 1, 10, (uint8_t)r) == GZ_JOURNAL_OK && drain(cj) == 1)
                inc = gz_journal_incarnation(cj);
            if (write(up[1], &inc, sizeof inc) != (ssize_t)sizeof inc) _exit(3);
            char go;
            if (read(down[0], &go, 1) != 1) _exit(4);
            int ok = inc && save(cj, 2, 10, (uint8_t)r) == GZ_JOURNAL_OK && drain(cj) == 1;
            gz_journal_close(cj);
            _exit(ok ? 0 : 5);
        }
        close(up[1]);
        close(down[0]);
        uint64_t inc = 0;
        int got = read(up[0], &inc, sizeof inc) == (ssize_t)sizeof inc && inc;
        unlink(lock);
        if (r & 1) {
            FILE *f = fopen(lock, "w");
            if (f) fclose(f);
        }
        int ok = got && copy_file(backup, staged);
        gz_journal_status_t si = gz_journal_import(dir, gz_journal_chain_signet, NULL, staged, 0);
        gz_journal_status_t sm = gz_journal_mark_restored(dir, gz_journal_chain_signet, NULL, 0);
        refused += ok && si == GZ_JOURNAL_ERR_LOCKED && sm == GZ_JOURNAL_ERR_LOCKED;
        if (write(down[1], "g", 1) != 1) ok = 0;
        int status;
        waitpid(pid, &status, 0);
        ok = ok && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        close(up[0]);
        close(down[1]);
        unlink(staged);
        unlink(marker);
        /* P1's confirmed batches are in the journal. */
        gz_journal_open_info_t info;
        j = jopen_os(gz_journal_os_posix(), dir, &st, &info);
        int kept = st == GZ_JOURNAL_OK && has_batch(j, inc, 1) && has_batch(j, inc, 2) && !info.restored;
        gz_journal_close(j);
        lost += !kept;
        broken += !ok;
        if ((!kept || !ok) && lost + broken <= 3)
            printf("  round %d: import %s, mark %s, child ok %d, batches kept %d\n", r, gz_journal_status_name(si),
                   gz_journal_status_name(sm), ok, kept);
    }
    printf("  lock rounds: %d, both refused in %d, confirmed batches lost in %d\n", rounds, refused, lost);
    CHECK(refused == rounds && lost == 0 && broken == 0);
    unlink(jpath);
    unlink(lock);
    unlink(backup);
    unlink(staged);
    unlink(marker);
    CHECK(rmdir(dir) == 0);
}

/* --- B2 ------------------------------------------------------------------- */

static void test_import_floor(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    uint8_t *backup = NULL;
    size_t blen = 0, len;

    /* The journal it replaces cannot be read (open or pread fails): refused,
     * nothing written, nothing renamed. */
    for (int how = 1; how <= 2; how++) {
        memfs_init(&fs);
        starts(&fs, 5, &backup, &blen);
        memfs_put(&fs, H_STAGED, backup, blen);
        free(backup);
        size_t before = file_len(&fs, H_JOURNAL);
        fs.fail_path = H_JOURNAL;
        fs.fail_path_how = how;
        CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0) == GZ_JOURNAL_ERR_IO);
        CHECK(file_len(&fs, H_JOURNAL) == before);
        CHECK(!memfs_get(&fs, H_MARKER, &len));
        CHECK(memfs_get(&fs, H_STAGED, &len) != NULL);
        CHECK(memfs_open_fds(&fs) == 0);
        fs.fail_path = NULL;
        CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0) == GZ_JOURNAL_OK);
        gz_journal_t *j = jopen(&fs, &st, &info);
        CHECK(st == GZ_JOURNAL_OK && info.restored && info.incarnation == 6);
        gz_journal_close(j);
        memfs_free(&fs);
    }

    /* The journal it replaces is refused by the scan: its highest
     * incarnation still raises the floor. 0: an order violation (a valid
     * batch under incarnation 9 after the end); 1: damage in the first
     * batch, before every later mark (the newest mark names 5). */
    for (int how = 0; how < 2; how++) {
        memfs_init(&fs);
        starts(&fs, 5, &backup, &blen);
        memfs_put(&fs, H_STAGED, backup, blen);
        free(backup);
        size_t jl;
        const uint8_t *d = memfs_get(&fs, H_JOURNAL, &jl);
        uint8_t *bad = malloc(jl + 64);
        memcpy(bad, d, jl);
        uint64_t want;
        gz_journal_status_t want_st;
        if (how == 0) {
            uint8_t z[10] = {0};
            gz_record_t r = {0x7e570001, {z, 10}};
            jl += gz_journal_encode_batch(bad + jl, (gz_batch_id_t){9, 1}, &r, 1);
            want = 9;
            want_st = GZ_JOURNAL_ERR_ORDER;
        } else {
            bad[GZ_JOURNAL_HEADER_LEN + 2 * GZ_JOURNAL_MARK_LEN + 30] ^= 1; /* inside batch (1, 1) */
            want = 5;
            want_st = GZ_JOURNAL_ERR_CORRUPT;
        }
        memfs_put(&fs, H_JOURNAL, bad, jl);
        gz_journal_scan_t sc;
        CHECK(gz_journal_scan(bad, jl, gz_journal_chain_signet, &sc, NULL, NULL) == want_st &&
              sc.highest_incarnation == want);
        free(bad);
        CHECK(gz_journal_import(H_DIR, gz_journal_chain_signet, &fs.os, H_STAGED, 0) == GZ_JOURNAL_OK);
        gz_journal_t *j = jopen(&fs, &st, &info);
        CHECK(st == GZ_JOURNAL_OK && info.restored && info.incarnation == want + 1);
        gz_journal_close(j);
        memfs_free(&fs);
    }
}

/* --- B3 ------------------------------------------------------------------- */

static memfs_t *b3_fs;
static int b3_mode, b3_done; /* 1: the creating open's folder sync fails; 2: the program is killed there */
static int b3_sync_dir(void *ctx, const char *dir)
{
    if (!b3_done) {
        b3_done = 1;
        if (b3_mode == 1) { errno = EIO; return -1; }
        b3_fs->crash_at = b3_fs->points + 1;
    }
    return b3_fs->os.sync_dir(ctx, dir);
}

static void test_name_durable(void)
{
    for (int mode = 1; mode <= 2; mode++) {
        memfs_t fs;
        gz_journal_status_t st;
        gz_journal_open_info_t info;
        size_t len;
        memfs_init(&fs);
        b3_fs = &fs;
        b3_mode = mode;
        b3_done = 0;
        gz_journal_os_t os = fs.os;
        os.sync_dir = b3_sync_dir;
        gz_journal_t *j = jopen_os(&os, H_DIR, &st, &info);
        CHECK(j == NULL && st == GZ_JOURNAL_ERR_IO && b3_done);
        if (mode == 2) memfs_settle(&fs, MEMFS_KEEP, 1); /* killed; the name is not durable */
        CHECK(memfs_get(&fs, H_JOURNAL, &len) != NULL);
        /* The next open finds the journal, confirms a batch... */
        j = jopen(&fs, &st, &info);
        CHECK(st == GZ_JOURNAL_OK && !info.created && info.incarnation == 1);
        CHECK(save(j, 1, 10, 1) == GZ_JOURNAL_OK && drain(j) == 1);
        gz_journal_close(j);
        /* ...and a power cut keeps it. */
        memfs_settle(&fs, MEMFS_LOSE, 2);
        j = jopen(&fs, &st, &info);
        int ok = st == GZ_JOURNAL_OK && !info.created && info.incarnation == 2 && has_batch(j, 1, 1);
        if (!ok) printf("  name durable (mode %d): %s, created %d, incarnation %llu\n", mode,
                        gz_journal_status_name(st), info.created, (unsigned long long)info.incarnation);
        CHECK(ok);
        gz_journal_close(j);
        memfs_free(&fs);
    }
}

/* --- M28 ------------------------------------------------------------------ */

static void test_marker_unreadable(void)
{
    for (int how = 1; how <= 2; how++) {
        memfs_t fs;
        gz_journal_status_t st;
        gz_journal_open_info_t info;
        memfs_init(&fs);
        starts(&fs, 2, NULL, NULL);
        CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_OK);
        size_t before = file_len(&fs, H_JOURNAL);
        fs.fail_path = H_MARKER;
        fs.fail_path_how = how;
        fs.fail_path_errno = how == 1 ? EACCES : EIO;
        gz_journal_t *j = jopen(&fs, &st, &info);
        CHECK(j == NULL && st == GZ_JOURNAL_ERR_IO && file_len(&fs, H_JOURNAL) == before);
        CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_ERR_IO);
        CHECK(memfs_open_fds(&fs) == 0);
        fs.fail_path = NULL;
        j = jopen(&fs, &st, &info);
        CHECK(st == GZ_JOURNAL_OK && info.restored && info.incarnation == 3);
        gz_journal_close(j);
        memfs_free(&fs);
    }
}

/* --- M5 ------------------------------------------------------------------- */

static void test_direct_refused(void)
{
    char dir[] = "/tmp/gzj-m5-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char jpath[300], lock[300], fpath[300];
    snprintf(jpath, sizeof jpath, "%s/%s", dir, GZ_JOURNAL_FILE);
    snprintf(lock, sizeof lock, "%s/%s", dir, GZ_JOURNAL_LOCK_FILE);
    snprintf(fpath, sizeof fpath, "%s/f", dir);
    gz_journal_posix_test_direct_einval(1);
    /* The table's device read alone: the file's bytes at odd offsets. */
    static uint8_t want[2 * 4096 + 333], got[sizeof want];
    for (size_t i = 0; i < sizeof want; i++) want[i] = (uint8_t)h_mix(i + 7);
    FILE *f = fopen(fpath, "wb");
    CHECK(f && fwrite(want, 1, sizeof want, f) == sizeof want);
    if (f) fclose(f);
    const gz_journal_os_t *px = gz_journal_os_posix();
    int fd = px->open(px->ctx, fpath, GZ_JOURNAL_OPEN_READ);
    CHECK(fd >= 0 && px->sync(px->ctx, fd) == 0);
    int bad = 0;
    for (uint64_t off = 0; off < sizeof want; off += 1777) {
        size_t n = sizeof want - (size_t)off;
        long r = px->pread_device(px->ctx, fd, got, n, off);
        bad += r != (long)n || memcmp(got, want + off, n) != 0;
    }
    CHECK(bad == 0);
    px->close(px->ctx, fd);
    /* A whole journal life on it. */
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    gz_journal_t *j = jopen_os(px, dir, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && save(j, 1, 100, 3) == GZ_JOURNAL_OK && drain(j) == 1);
    gz_journal_close(j);
    j = jopen_os(px, dir, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && info.incarnation == 2 && has_batch(j, 1, 1));
    gz_journal_close(j);
    gz_journal_posix_test_direct_einval(0);
    unlink(fpath);
    unlink(jpath);
    unlink(lock);
    CHECK(rmdir(dir) == 0);
}

/* --- M24 ------------------------------------------------------------------ */

static void test_reader_after_failure(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    memfs_init(&fs);
    starts(&fs, 1, NULL, NULL);
    gz_journal_t *j = jopen(&fs, &st, NULL);
    CHECK(save(j, 1, 10, 1) == GZ_JOURNAL_OK && drain(j) == 1);
    gz_storage_reader_t rd = gz_journal_reader(j);
    gz_stored_batch_t b;
    CHECK(rd.next(rd.ctx, &b) == 1);
    gz_action_t bad = {.kind = GZ_ACTION_SAVE};
    bad.u.save.batch = (gz_batch_id_t){gz_journal_incarnation(j), 7}; /* out of sequence: fails */
    CHECK(gz_journal_save(j, &bad) == GZ_JOURNAL_ERR_SEQUENCE && gz_journal_failed(j));
    CHECK(rd.next(rd.ctx, &b) == 0);
    rd.rewind(rd.ctx);
    CHECK(rd.next(rd.ctx, &b) == 0);
    gz_journal_close(j);
    memfs_free(&fs);
}

/* --- M36 ------------------------------------------------------------------ */

static void test_guard_newest(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    memfs_init(&fs);
    gz_journal_t *j = jopen(&fs, &st, &info);
    uint8_t g[66];
    for (uint64_t s = 1; s <= 3; s++) {
        h_guard_bytes(g, s == 2 ? 9 : s == 1 ? 5 : 0);
        gz_record_t r[2] = {{0x7e570001, {g, 4}}, {GZ_RECORD_GUARD, {g, 66}}};
        gz_action_t a = {.kind = GZ_ACTION_SAVE};
        a.u.save.batch = (gz_batch_id_t){info.incarnation, s};
        a.u.save.records = r;
        a.u.save.n_records = s == 3 ? 1 : 2; /* the third batch holds no guard record */
        CHECK(gz_journal_save(j, &a) == GZ_JOURNAL_OK);
    }
    gz_journal_close(j); /* killed before the flush */
    j = jopen(&fs, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && has_batch(j, 1, 3));
    size_t len;
    const uint8_t *gf = memfs_get(&fs, H_GUARD, &len);
    uint64_t c = 0;
    for (int i = 0; gf && i < 8; i++) c = c << 8 | gf[40 + i];
    CHECK(gf && len == 74 && c == 9);
    gz_journal_close(j);
    memfs_free(&fs);
}

int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        void (*fn)(void);
    } parts[] = {{"lock_memfs", test_lock_memfs},        {"import_floor", test_import_floor},
                 {"name_durable", test_name_durable},    {"marker_unreadable", test_marker_unreadable},
                 {"direct_refused", test_direct_refused}, {"reader_after_failure", test_reader_after_failure},
                 {"guard_newest", test_guard_newest}};
    int rounds = argc > 2 ? atoi(argv[2]) : 200;
    for (size_t i = 0; i < sizeof parts / sizeof parts[0]; i++)
        if (argc < 2 || strcmp(argv[1], parts[i].name) == 0) parts[i].fn();
    if (argc < 2 || strcmp(argv[1], "lock_rounds") == 0) test_lock_rounds(rounds);
    return check_done();
}
