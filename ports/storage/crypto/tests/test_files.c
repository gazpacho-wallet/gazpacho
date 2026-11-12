/* The files in a data folder: set-up, unlock through the KDF helper, the start
 * rule's inputs, 6.3 step 0, passphrase change and upgrade, the words,
 * recovery from the words, the attempts file, a scan for secrets (test 12),
 * the helper's failures (test 14) and crashes at every operating-system call
 * of set-up, passphrase change, the mark append and the guard replace (test
 * 10), with a power-loss model: unsynced writes and renames not followed by
 * a folder sync are lost. */
#define _GNU_SOURCE
#include "sc_internal.h"
#include "sc_test.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const gz_sc_kdf_params_t TP = {1, 3, 64, 1};
static const gz_sc_kdf_params_t TP_UP = {1, 4, 128, 1};
static const char PW[] = "the first test passphrase here";
static const char PW2[] = "the second test passphrase here";
static uint8_t ENT[32];

/* ---- a data folder ---- */
static char *mkdir_tmp(void)
{
    static char path[64];
    strcpy(path, "/tmp/gz-sc-files-XXXXXX");
    if (!mkdtemp(path)) {
        perror("mkdtemp");
        exit(1);
    }
    return path;
}

static void rm_dir(const char *d)
{
    DIR *dh = opendir(d);
    if (!dh)
        return;
    struct dirent *e;
    char p[512];
    while ((e = readdir(dh)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
            snprintf(p, sizeof p, "%s/%s", d, e->d_name);
            unlink(p);
        }
    closedir(dh);
    rmdir(d);
}

static int exists(const char *d, const char *name)
{
    char p[512];
    snprintf(p, sizeof p, "%s/%s", d, name);
    return access(p, F_OK) == 0;
}

static void rm_file(const char *d, const char *name)
{
    char p[512];
    snprintf(p, sizeof p, "%s/%s", d, name);
    unlink(p);
}

static int no_marks(void *c, uint64_t i, uint64_t o)
{
    (void)c; (void)i; (void)o;
    return 0;
}
static int mark_1_254(void *c, uint64_t i, uint64_t o)
{
    (void)c;
    return i == 1 && o == 254;
}
static const gz_sc_journal_view_t EMPTY_J = {0, no_marks, NULL, 0};
static const gz_sc_journal_view_t J1 = {1, mark_1_254, NULL, 0};

static gz_sc_store_t store_for(const char *dir, int helper)
{
    gz_sc_store_t s;
    memset(&s, 0, sizeof s);
    s.os = &gz_sc_os_posix;
    s.dir = dir;
    memcpy(s.chain, SIGNET, 32);
    s.kdf = helper ? gz_sc_kdf_helper : gz_sc_test_kdf_inprocess;
    s.kdf_ctx = helper ? (void *)GZ_SC_HELPER : NULL;
    return s;
}

#define PWB(p) (const uint8_t *)(p), strlen(p)

/* ---- the ordinary path, through the helper ---- */
static void flow(void)
{
    char *d = mkdir_tmp();
    gz_sc_store_t s = store_for(d, 1);
    gz_sc_unlocked_t u, u2;
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW), &TP, &u), GZ_SC_MISSING);
    CHECK_ERR(gz_sc_setup(&s, PWB(PW), &TP, ENT, SEED64, &u), GZ_SC_OK);
    CHECK(u.vault && u.kj && u.kh && !u.restore);
    uint8_t fid[16];
    memcpy(fid, u.file_id, 16);
    gz_sc_unlocked_clear(&u);
    const char *names[] = {GZ_SC_FILE_KEYS, GZ_SC_FILE_GUARD, GZ_SC_FILE_MARK, GZ_SC_FILE_JOURNAL};
    for (int i = 0; i < 4; i++) {
        char p[512];
        struct stat st;
        snprintf(p, sizeof p, "%s/%s", d, names[i]);
        CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == 0600);
    }
    CHECK_ERR(gz_sc_setup(&s, PWB(PW), &TP, ENT, SEED64, &u), GZ_SC_EXISTS);
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW), &TP, &u), GZ_SC_OK);
    CHECK(!u.restore && memcmp(u.file_id, fid, 16) == 0 && !u.upgrade_due);
    CHECK(gz_sc_check_start(&s, &u, &EMPTY_J) == GZ_SC_START_OK);
    /* An anchored batch: (1, 254). The journal must hold that mark. */
    CHECK_ERR(gz_sc_anchor(&s, &u, 1, 254), GZ_SC_OK);
    CHECK(gz_sc_check_start(&s, &u, &J1) == GZ_SC_START_OK);
    CHECK(gz_sc_check_start(&s, &u, &EMPTY_J) == GZ_SC_START_BEHIND);
    CHECK_ERR(gz_sc_anchor(&s, &u, 1, 200), GZ_SC_STORAGE_FAILED); /* never backwards */
    {   /* A torn tail (half an entry) is cut before the next append. */
        char mp[512];
        snprintf(mp, sizeof mp, "%s/%s", d, GZ_SC_FILE_MARK);
        FILE *mf = fopen(mp, "ab");
        CHECK(mf && fwrite("torn tail bytes", 1, 15, mf) == 15);
        if (mf)
            fclose(mf);
        CHECK(gz_sc_check_start(&s, &u, &J1) == GZ_SC_START_OK);
        CHECK_ERR(gz_sc_anchor(&s, &u, 1, 254), GZ_SC_OK);
        uint8_t *mm = NULL;
        size_t mml = 0;
        CHECK_ERR(gz_sc_fs_read(&s, GZ_SC_FILE_MARK, 4096, &mm, &mml), GZ_SC_OK);
        CHECK(mml == 57 + 3 * 56);
        free(mm);
    }
    /* A guard newer than the journal's newest guard record: behind. */
    gz_sc_epoch_t ep = {0, 3};
    gz_sc_guard_t g = {2, 1, &ep, 0};
    CHECK_ERR(gz_sc_guard_write(&s, u.vault, &g), GZ_SC_OK);
    gz_sc_journal_view_t j2 = J1;
    CHECK(gz_sc_check_start(&s, &u, &j2) == GZ_SC_START_BEHIND);
    j2.newest_guard_counter = 2;
    CHECK(gz_sc_check_start(&s, &u, &j2) == GZ_SC_START_OK);
    /* Wrong passphrase; then the helper's failures, never "wrong". */
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW2), &TP, &u2), GZ_SC_WRONG_PASSPHRASE);
    CHECK(u2.vault == NULL);
    const char *modes[] = {"crash", "short", "exit1", "garbage"};
    gz_sc_store_t bad = s;
    bad.kdf_ctx = (void *)GZ_SC_BAD_HELPER;
    for (int i = 0; i < 4; i++) {
        setenv("GZ_SC_BAD", modes[i], 1);
        CHECK_ERR(gz_sc_unlock(&bad, PWB(PW), &TP, &u2), GZ_SC_HELPER_FAILED);
    }
    bad.kdf_ctx = (void *)"/nonexistent/gz-helper";
    CHECK_ERR(gz_sc_unlock(&bad, PWB(PW), &TP, &u2), GZ_SC_HELPER_FAILED);
    /* The real helper refuses parameters below its floor itself. */
    unsetenv("GZ_SC_TEST_FLOOR");
    uint8_t salt[16] = {0}, pk[32];
    gz_sc_kdf_params_t real = {1, 3, 65536, 1};
    int locked = -1;
    CHECK_ERR(gz_sc_kdf_helper((void *)GZ_SC_HELPER, PWB(PW), salt, &real, pk, &locked), GZ_SC_OK);
    CHECK(locked == 0 || locked == 1);
    uint8_t pk_in[32];
    CHECK_ERR(gz_sc_test_kdf_inprocess(NULL, PWB(PW), salt, &real, pk_in, NULL), GZ_SC_OK);
    CHECK(memcmp(pk, pk_in, 32) == 0);
    printf("KDF helper at 64 MiB: pages locked = %d\n", locked);
    /* 64 KiB: this process's test floor accepts it, the helper's release floor does not. */
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW), &TP, &u2), GZ_SC_PARAMS_REFUSED);
    setenv("GZ_SC_TEST_FLOOR", "1", 1);

    /* Possibly old: the guard or the mark file missing or damaged. */
    rm_file(d, GZ_SC_FILE_GUARD);
    CHECK(gz_sc_check_start(&s, &u, &J1) == GZ_SC_START_POSSIBLY_OLD);
    CHECK_ERR(gz_sc_guard_write(&s, u.vault, &g), GZ_SC_OK);
    rm_file(d, GZ_SC_FILE_MARK);
    CHECK(gz_sc_check_start(&s, &u, &j2) == GZ_SC_START_POSSIBLY_OLD);
    CHECK_ERR(gz_sc_anchor(&s, &u, 1, 254), GZ_SC_STORAGE_FAILED);
    CHECK_ERR(gz_sc_mark_restart(&s, &u), GZ_SC_OK); /* start as restore */
    CHECK(gz_sc_check_start(&s, &u, &j2) == GZ_SC_START_OK);

    /* Passphrase change: the new one opens, the old one does not; an old
     * copy of the key file still opens with the old passphrase (4.7). */
    uint8_t *old = NULL;
    size_t ol = 0;
    CHECK_ERR(gz_sc_fs_read(&s, GZ_SC_FILE_KEYS, 1000, &old, &ol), GZ_SC_OK);
    CHECK_ERR(gz_sc_rewrap(&s, PWB(PW2), PWB(PW), &TP), GZ_SC_WRONG_PASSPHRASE);
    CHECK_ERR(gz_sc_rewrap(&s, PWB(PW), PWB(PW2), &TP), GZ_SC_OK);
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW), &TP, &u2), GZ_SC_WRONG_PASSPHRASE);
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW2), &TP, &u2), GZ_SC_OK);
    CHECK(memcmp(u2.file_id, fid, 16) == 0);
    gz_sc_unlocked_clear(&u2);
    uint8_t ent[32];
    CHECK_ERR(gz_sc_words(&s, PWB(PW2), ent), GZ_SC_OK);
    CHECK(memcmp(ent, ENT, 32) == 0);
    CHECK_ERR(gz_sc_words(&s, PWB(PW), ent), GZ_SC_WRONG_PASSPHRASE);
    CHECK_ERR(gz_sc_fs_replace(&s, GZ_SC_FILE_KEYS, old, ol), GZ_SC_OK);
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW), &TP, &u2), GZ_SC_OK);
    gz_sc_unlocked_clear(&u2);
    free(old);

    /* Upgrade (4.7): stored below the default; the same passphrase rewraps. */
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW), &TP_UP, &u2), GZ_SC_OK);
    CHECK(u2.upgrade_due);
    gz_sc_unlocked_clear(&u2);
    CHECK_ERR(gz_sc_rewrap(&s, PWB(PW), NULL, 0, &TP_UP), GZ_SC_OK);
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW), &TP_UP, &u2), GZ_SC_OK);
    CHECK(!u2.upgrade_due && u2.info.kdf.t == 4 && u2.info.kdf.m_kib == 128);
    gz_sc_unlocked_clear(&u2);

    /* 9.3: key file lost; the words reopen the journal and a new key file
     * keeps the vault_id and MSK. */
    rm_file(d, GZ_SC_FILE_KEYS);
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW), &TP, &u2), GZ_SC_MISSING);
    uint8_t oseed[64];
    crypto_hash_sha512(oseed, (const uint8_t *)"other", 5);
    CHECK_ERR(gz_sc_recover_keyfile(&s, ENT, oseed, PWB(PW2), &TP), GZ_SC_NOT_THIS_WALLET);
    CHECK(!exists(d, GZ_SC_FILE_KEYS));
    CHECK_ERR(gz_sc_recover_keyfile(&s, ENT, SEED64, PWB(PW2), &TP), GZ_SC_OK);
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW2), &TP, &u2), GZ_SC_OK);
    CHECK(!u2.restore && memcmp(u2.file_id, fid, 16) == 0);
    uint8_t c1[32], v1[16], c2[32], v2[16];
    gz_sc_vault_ids(u.vault, c1, v1);
    gz_sc_vault_ids(u2.vault, c2, v2);
    CHECK(memcmp(v1, v2, 16) == 0 && memcmp(c1, c2, 32) == 0);
    CHECK(gz_sc_check_start(&s, &u2, &j2) == GZ_SC_START_OK);
    gz_sc_unlocked_clear(&u2);

    /* 6.3 step 0 (R2-2): the journal and the guard deleted together. */
    rm_file(d, GZ_SC_FILE_JOURNAL);
    rm_file(d, GZ_SC_FILE_GUARD);
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW2), &TP, &u2), GZ_SC_OK);
    CHECK(u2.restore && memcmp(u2.file_id, fid, 16) != 0 && exists(d, GZ_SC_FILE_JOURNAL));
    uint8_t *m = NULL;
    size_t ml;
    CHECK_ERR(gz_sc_fs_read(&s, GZ_SC_FILE_MARK, 4096, &m, &ml), GZ_SC_OK);
    uint64_t mi = 9, mo = 9;
    CHECK(m && gz_sc_mark_read(u2.kh, m, ml, SIGNET, u2.file_id, &mi, &mo, NULL) == GZ_SC_MARK_OK && mi == 0 &&
          mo == 0);
    free(m);
    gz_sc_unlocked_clear(&u2);
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW2), &TP, &u2), GZ_SC_OK);
    CHECK(!u2.restore);
    gz_sc_unlocked_clear(&u2);

    /* Another network's files are refused before anything is derived. */
    gz_sc_store_t other = s;
    other.chain[0] ^= 1;
    CHECK_ERR(gz_sc_unlock(&other, PWB(PW2), &TP, &u2), GZ_SC_OTHER_NETWORK);
    {   /* Another wallet's journal: refused after the key file opened, and
         * every key is dropped (8.2 step 3). */
        uint8_t *jold = NULL, oh[GZ_SC_JHEADER_LEN], om[32], ov[16] = {0};
        size_t jl = 0;
        gz_sc_fs_read(&s, GZ_SC_FILE_JOURNAL, 4096, &jold, &jl);
        tv("files other msk", om, 32);
        gz_sc_vault_t *vo = NULL;
        gz_sc_vault_new(SIGNET, ov, om, SEED64, &vo);
        gz_sc_header_seal(vo, fid, oh);
        gz_sc_vault_free(vo);
        CHECK_ERR(gz_sc_fs_replace(&s, GZ_SC_FILE_JOURNAL, oh, sizeof oh), GZ_SC_OK);
        CHECK_ERR(gz_sc_unlock(&s, PWB(PW2), &TP, &u2), GZ_SC_NOT_THIS_WALLET);
        CHECK(u2.vault == NULL && u2.kj == NULL && u2.kh == NULL);
        CHECK_ERR(gz_sc_fs_replace(&s, GZ_SC_FILE_JOURNAL, jold, jl), GZ_SC_OK);
        free(jold);
    }

    /* The attempts file. */
    gz_sc_attempts_t a;
    CHECK(gz_sc_attempts_load(&s, 100, &a) == 0 && a.blocked_until_s == 1000);
    a.wrong_in_a_row = 3;
    CHECK_ERR(gz_sc_attempts_store(&s, &a), GZ_SC_OK);
    gz_sc_attempts_t b;
    CHECK(gz_sc_attempts_load(&s, 100, &b) == 1 && b.wrong_in_a_row == 3 && b.counter == a.counter);
    gz_sc_unlocked_clear(&u);
    rm_dir(d);
}

/* ---- test 12: no secret in any file ---- */
static int contains(const uint8_t *hay, size_t hn, const uint8_t *needle, size_t nn)
{
    for (size_t i = 0; i + nn <= hn; i++)
        if (memcmp(hay + i, needle, nn) == 0)
            return 1;
    return 0;
}

static void secrets_scan(void)
{
    char *d = mkdir_tmp();
    gz_sc_store_t s = store_for(d, 0);
    gz_sc_unlocked_t u;
    CHECK_ERR(gz_sc_setup(&s, PWB(PW), &TP, ENT, SEED64, &u), GZ_SC_OK);
    CHECK_ERR(gz_sc_anchor(&s, &u, 1, 254), GZ_SC_OK);
    gz_sc_unlocked_clear(&u);
    CHECK_ERR(gz_sc_rewrap(&s, PWB(PW), PWB(PW2), &TP), GZ_SC_OK);
    uint8_t *kf = NULL, *hdr = NULL;
    size_t kl, hl;
    gz_sc_fs_read(&s, GZ_SC_FILE_KEYS, 1000, &kf, &kl);
    gz_sc_fs_read(&s, GZ_SC_FILE_JOURNAL, 1000, &hdr, &hl);
    uint8_t msk[32], pk[32], pk1[32];
    CHECK_ERR(gz_sc_header_recover(hdr, SIGNET, SEED64, msk), GZ_SC_OK);
    gz_sc_keyfile_info_t info;
    gz_sc_keyfile_parse(kf, kl, SIGNET, &info);
    gz_sc_test_kdf_inprocess(NULL, PWB(PW2), info.salt, &info.kdf, pk, NULL);
    gz_sc_test_kdf_inprocess(NULL, PWB(PW), info.salt, &info.kdf, pk1, NULL);
    struct { const char *what; const uint8_t *p; size_t n; } sec[] = {
        {"passphrase", (const uint8_t *)PW, 12}, {"new passphrase", (const uint8_t *)PW2, 12},
        {"MSK", msk, 16}, {"MSK tail", msk + 16, 16}, {"PK", pk, 16}, {"entropy", ENT, 16},
        {"entropy tail", ENT + 16, 16}, {"seed", SEED64, 16}, {"seed tail", SEED64 + 48, 16},
    };
    DIR *dh = opendir(d);
    struct dirent *e;
    while (dh && (e = readdir(dh))) {
        if (e->d_name[0] == '.')
            continue;
        uint8_t *f = NULL;
        size_t fl = 0;
        gz_sc_fs_read(&s, e->d_name, 1 << 20, &f, &fl);
        for (size_t i = 0; i < sizeof sec / sizeof sec[0]; i++)
            if (contains(f, fl, sec[i].p, sec[i].n)) {
                fprintf(stderr, "%s holds the %s\n", e->d_name, sec[i].what);
                sc_failures++;
            }
        free(f);
    }
    if (dh)
        closedir(dh);
    free(kf);
    free(hdr);
    rm_dir(d);
}

/* ---- test 10: crashes at every call ---- */
#define MAXF 16
typedef struct {
    int calls, crash_at, crashed;
    char dir[256];
    struct {
        int fd, used;
        char path[512];
        off_t synced;
    } fds[MAXF];
    struct {
        char from[512], to[512];
        uint8_t *old;
        size_t old_len;
        int had_old;
    } ren[MAXF];
    int n_ren;
} fault_t;

static off_t size_of(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 ? st.st_size : 0;
}

static void power_loss(fault_t *f)
{
    for (int i = 0; i < MAXF; i++)
        if (f->fds[i].used && size_of(f->fds[i].path) > f->fds[i].synced &&
            truncate(f->fds[i].path, f->fds[i].synced) != 0)
            perror("power loss: truncate");
    for (int i = f->n_ren; i-- > 0;) {
        rename(f->ren[i].to, f->ren[i].from);
        if (f->ren[i].had_old) {
            int fd = open(f->ren[i].to, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd >= 0) {
                if (write(fd, f->ren[i].old, f->ren[i].old_len) < 0)
                    perror("restore");
                close(fd);
            }
        }
    }
}

static int step(fault_t *f)
{
    if (f->crashed) {
        errno = EIO;
        return -1;
    }
    if (++f->calls == f->crash_at) {
        f->crashed = 1;
        power_loss(f);
        errno = EIO;
        return -1;
    }
    return 0;
}

static int f_open(void *c, const char *p, int fl, int m)
{
    fault_t *f = c;
    if (step(f))
        return -1;
    int fd = open(p, fl | O_CLOEXEC, m);
    if (fd >= 0 && (fl & (O_WRONLY | O_RDWR)))
        for (int i = 0; i < MAXF; i++)
            if (!f->fds[i].used) {
                f->fds[i].used = 1;
                f->fds[i].fd = fd;
                snprintf(f->fds[i].path, sizeof f->fds[i].path, "%s", p);
                f->fds[i].synced = size_of(p);
                break;
            }
    return fd;
}
static long f_write(void *c, int fd, const void *p, size_t n)
{
    return step(c) ? -1 : (long)write(fd, p, n);
}
static long f_read(void *c, int fd, void *p, size_t n)
{
    return step(c) ? -1 : (long)read(fd, p, n);
}
static int f_fsync(void *c, int fd)
{
    fault_t *f = c;
    if (step(f))
        return -1;
    int rc = fsync(fd);
    for (int i = 0; i < MAXF; i++)
        if (f->fds[i].used && f->fds[i].fd == fd)
            f->fds[i].synced = size_of(f->fds[i].path);
    char link[64], target[512];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t tl = readlink(link, target, sizeof target - 1);
    if (tl > 0) {
        target[tl] = 0;
        if (strcmp(target, f->dir) == 0) { /* the folder is synced: renames are durable */
            for (int i = 0; i < f->n_ren; i++)
                free(f->ren[i].old);
            f->n_ren = 0;
        }
    }
    return rc;
}
static int f_ftruncate(void *c, int fd, uint64_t l)
{
    return step(c) ? -1 : ftruncate(fd, (off_t)l);
}
static int f_close(void *c, int fd)
{
    fault_t *f = c;
    for (int i = 0; i < MAXF; i++)
        if (f->fds[i].used && f->fds[i].fd == fd) {
            /* An unsynced file stays at risk after close: keep the record by path. */
            f->fds[i].fd = -1;
        }
    if (step(f)) {
        close(fd);
        return -1;
    }
    return close(fd);
}
static int f_rename(void *c, const char *a, const char *b)
{
    fault_t *f = c;
    if (step(f))
        return -1;
    if (f->n_ren < MAXF) {
        int i = f->n_ren++;
        snprintf(f->ren[i].from, sizeof f->ren[i].from, "%s", a);
        snprintf(f->ren[i].to, sizeof f->ren[i].to, "%s", b);
        f->ren[i].old = NULL;
        f->ren[i].had_old = 0;
        int fd = open(b, O_RDONLY);
        if (fd >= 0) {
            off_t n = size_of(b);
            f->ren[i].old = malloc((size_t)n + 1);
            f->ren[i].old_len = (size_t)read(fd, f->ren[i].old, (size_t)n);
            f->ren[i].had_old = 1;
            close(fd);
        }
    }
    int rc = rename(a, b);
    /* The renamed file's synced state follows it. */
    for (int i = 0; i < MAXF; i++)
        if (f->fds[i].used && strcmp(f->fds[i].path, a) == 0)
            snprintf(f->fds[i].path, sizeof f->fds[i].path, "%s", b);
    return rc;
}
static int f_unlink(void *c, const char *p)
{
    return step(c) ? -1 : unlink(p);
}

static void fault_reset(fault_t *f, gz_sc_os_t *os, const char *dir, int crash_at)
{
    for (int i = 0; i < f->n_ren; i++)
        free(f->ren[i].old);
    memset(f, 0, sizeof *f);
    f->crash_at = crash_at;
    snprintf(f->dir, sizeof f->dir, "%s", dir);
    *os = (gz_sc_os_t){f, f_open, f_write, f_read, f_fsync, f_ftruncate, f_close, f_rename, f_unlink};
}

static void crashes(void)
{
    fault_t f;
    memset(&f, 0, sizeof f);
    gz_sc_os_t os;
    int total, n;
    gz_sc_unlocked_t u;

    /* Set-up: after a crash at any call, the wallet either does not exist
     * (set-up again works) or opens with the passphrase, as a restore if the
     * journal is missing; never "wrong" or "damaged". */
    char *d = mkdir_tmp();
    gz_sc_store_t s = store_for(d, 0);
    fault_reset(&f, &os, d, 0);
    s.os = &os;
    CHECK_ERR(gz_sc_setup(&s, PWB(PW), &TP, ENT, SEED64, &u), GZ_SC_OK);
    gz_sc_unlocked_clear(&u);
    total = f.calls;
    rm_dir(d);
    int restores = 0, absent = 0;
    for (n = 1; n <= total; n++) {
        d = mkdir_tmp();
        s = store_for(d, 0);
        fault_reset(&f, &os, d, n);
        s.os = &os;
        /* A crash at the very last call (closing the synced folder) is after
         * everything durable: set-up may report success. */
        if (gz_sc_setup(&s, PWB(PW), &TP, ENT, SEED64, &u) == GZ_SC_OK)
            CHECK(n == total);
        gz_sc_unlocked_clear(&u);
        s.os = &gz_sc_os_posix;
        gz_sc_err_t e = gz_sc_unlock(&s, PWB(PW), &TP, &u);
        if (e == GZ_SC_MISSING) {
            absent++;
            CHECK_ERR(gz_sc_setup(&s, PWB(PW), &TP, ENT, SEED64, &u), GZ_SC_OK);
        } else {
            CHECK_ERR(e, GZ_SC_OK);
            if (e == GZ_SC_OK && u.restore)
                restores++;
            else if (e == GZ_SC_OK)
                CHECK(gz_sc_check_start(&s, &u, &EMPTY_J) == GZ_SC_START_OK);
        }
        gz_sc_unlocked_clear(&u);
        CHECK_ERR(gz_sc_unlock(&s, PWB(PW), &TP, &u), GZ_SC_OK);
        CHECK(gz_sc_check_start(&s, &u, &EMPTY_J) == GZ_SC_START_OK || !exists(d, GZ_SC_FILE_GUARD));
        gz_sc_unlocked_clear(&u);
        rm_dir(d);
    }
    printf("set-up: %d calls, each crashed: %d left no wallet, %d started as a restore\n", total, absent,
           restores);
    CHECK(absent > 0 && restores > 0);

    /* Passphrase change: exactly one of the two passphrases opens. */
    d = mkdir_tmp();
    s = store_for(d, 0);
    CHECK_ERR(gz_sc_setup(&s, PWB(PW), &TP, ENT, SEED64, &u), GZ_SC_OK);
    gz_sc_unlocked_clear(&u);
    uint8_t *orig = NULL;
    size_t olen;
    gz_sc_fs_read(&s, GZ_SC_FILE_KEYS, 1000, &orig, &olen);
    fault_reset(&f, &os, d, 0);
    s.os = &os;
    CHECK_ERR(gz_sc_rewrap(&s, PWB(PW), PWB(PW2), &TP), GZ_SC_OK);
    total = f.calls;
    int old_ok = 0, new_ok = 0;
    for (n = 1; n <= total; n++) {
        s.os = &gz_sc_os_posix;
        CHECK_ERR(gz_sc_fs_replace(&s, GZ_SC_FILE_KEYS, orig, olen), GZ_SC_OK);
        fault_reset(&f, &os, d, n);
        s.os = &os;
        if (gz_sc_rewrap(&s, PWB(PW), PWB(PW2), &TP) == GZ_SC_OK)
            CHECK(n == total);
        s.os = &gz_sc_os_posix;
        gz_sc_err_t a = gz_sc_unlock(&s, PWB(PW), &TP, &u);
        gz_sc_unlocked_clear(&u);
        gz_sc_err_t b = gz_sc_unlock(&s, PWB(PW2), &TP, &u);
        gz_sc_unlocked_clear(&u);
        CHECK((a == GZ_SC_OK) != (b == GZ_SC_OK));
        CHECK(a == GZ_SC_OK || a == GZ_SC_WRONG_PASSPHRASE);
        CHECK(b == GZ_SC_OK || b == GZ_SC_WRONG_PASSPHRASE);
        old_ok += a == GZ_SC_OK;
        new_ok += b == GZ_SC_OK;
    }
    printf("passphrase change: %d calls; after a crash the old opened %d times, the new %d\n", total, old_ok,
           new_ok);
    CHECK(old_ok > 0 && new_ok > 0);
    s.os = &gz_sc_os_posix;
    CHECK_ERR(gz_sc_fs_replace(&s, GZ_SC_FILE_KEYS, orig, olen), GZ_SC_OK);
    free(orig);

    /* The mark append and the guard replace: the file reads as before or after. */
    s.os = &gz_sc_os_posix;
    CHECK_ERR(gz_sc_unlock(&s, PWB(PW), &TP, &u), GZ_SC_OK);
    gz_sc_unlocked_t uu = u;
    uint8_t *m0 = NULL, *g0 = NULL;
    size_t m0l, g0l;
    gz_sc_fs_read(&s, GZ_SC_FILE_MARK, 4096, &m0, &m0l);
    gz_sc_fs_read(&s, GZ_SC_FILE_GUARD, 4096, &g0, &g0l);
    fault_reset(&f, &os, d, 0);
    s.os = &os;
    CHECK_ERR(gz_sc_anchor(&s, &uu, 1, 254), GZ_SC_OK);
    total = f.calls;
    /* A power cut right after a successful append keeps the entry: it was synced. */
    power_loss(&f);
    s.os = &gz_sc_os_posix;
    CHECK(gz_sc_check_start(&s, &uu, &EMPTY_J) == GZ_SC_START_BEHIND);
    for (n = 1; n <= total; n++) {
        s.os = &gz_sc_os_posix;
        gz_sc_fs_replace(&s, GZ_SC_FILE_MARK, m0, m0l);
        fault_reset(&f, &os, d, n);
        s.os = &os;
        if (gz_sc_anchor(&s, &uu, 1, 254) == GZ_SC_OK)
            CHECK(n == total);
        s.os = &gz_sc_os_posix;
        gz_sc_start_t r = gz_sc_check_start(&s, &uu, &J1);
        CHECK(r == GZ_SC_START_OK);
        CHECK_ERR(gz_sc_anchor(&s, &uu, 1, 254), GZ_SC_OK); /* a torn tail is cut first */
        CHECK(gz_sc_check_start(&s, &uu, &J1) == GZ_SC_START_OK);
        CHECK(gz_sc_check_start(&s, &uu, &EMPTY_J) == GZ_SC_START_BEHIND);
    }
    gz_sc_epoch_t ep = {0, 9};
    gz_sc_guard_t g = {5, 1, &ep, 2};
    fault_reset(&f, &os, d, 0);
    s.os = &os;
    CHECK_ERR(gz_sc_guard_write(&s, uu.vault, &g), GZ_SC_OK);
    total = f.calls;
    for (n = 1; n <= total; n++) {
        s.os = &gz_sc_os_posix;
        gz_sc_fs_replace(&s, GZ_SC_FILE_GUARD, g0, g0l);
        fault_reset(&f, &os, d, n);
        s.os = &os;
        if (gz_sc_guard_write(&s, uu.vault, &g) == GZ_SC_OK)
            CHECK(n == total);
        s.os = &gz_sc_os_posix;
        uint8_t *gb = NULL;
        size_t gbl;
        gz_sc_guard_t back;
        CHECK_ERR(gz_sc_fs_read(&s, GZ_SC_FILE_GUARD, 4096, &gb, &gbl), GZ_SC_OK);
        CHECK_ERR(gz_sc_guard_open(uu.vault, gb, gbl, &back), GZ_SC_OK);
        CHECK(back.counter == 0 || back.counter == 5);
        gz_sc_guard_clear(&back);
        free(gb);
    }
    fault_reset(&f, &os, d, 0);
    free(m0);
    free(g0);
    gz_sc_unlocked_clear(&uu);
    rm_dir(d);
}

int main(void)
{
    sc_test_init();
    setenv("GZ_SC_TEST_FLOOR", "1", 1);
    tv("files entropy", ENT, 32);
    flow();
    secrets_scan();
    crashes();
    return sc_test_done("storage files");
}
