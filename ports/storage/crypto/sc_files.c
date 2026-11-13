/* The storage layer's files: atomic replaces, appends, set-up, unlock and the
 * start rule's inputs (spec 6.3, 7, 9, 10, 12.3). POSIX. */
#define _GNU_SOURCE
#include "gz_storage_files.h"
#include "sc_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- the real operating system ---------------------------------------------- */
static int px_open(void *c, const char *p, int f, int m) { (void)c; return open(p, f | O_CLOEXEC, m); }
static long px_write(void *c, int fd, const void *p, size_t n) { (void)c; return (long)write(fd, p, n); }
static long px_read(void *c, int fd, void *p, size_t n) { (void)c; return (long)read(fd, p, n); }
static int px_fsync(void *c, int fd)
{
    (void)c;
#if defined(__APPLE__)
    return fcntl(fd, F_FULLFSYNC);
#else
    return fsync(fd);
#endif
}
static int px_ftruncate(void *c, int fd, uint64_t l) { (void)c; return ftruncate(fd, (off_t)l); }
static int px_close(void *c, int fd) { (void)c; return close(fd); }
static int px_rename(void *c, const char *a, const char *b) { (void)c; return rename(a, b); }
static int px_unlink(void *c, const char *p) { (void)c; return unlink(p); }

const gz_sc_os_t gz_sc_os_posix = {NULL, px_open, px_write, px_read, px_fsync, px_ftruncate,
                                   px_close, px_rename, px_unlink};

#define OS(s) ((s)->os)
#define PATH_CAP 4096

static gz_sc_err_t path_of(const gz_sc_store_t *s, const char *name, const char *suffix, char *out)
{
    int n = snprintf(out, PATH_CAP, "%s/%s%s", s->dir, name, suffix);
    return n < 0 || n >= PATH_CAP ? GZ_SC_ARG : GZ_SC_OK;
}

static int write_all(const gz_sc_store_t *s, int fd, const uint8_t *p, size_t n)
{
    while (n) {
        long w = OS(s)->write(OS(s)->ctx, fd, p, n);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return -1; /* a short write is a failure; no retry after an error */
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static gz_sc_err_t sync_dir(const gz_sc_store_t *s)
{
    int fd = OS(s)->open(OS(s)->ctx, s->dir, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0)
        return GZ_SC_STORAGE_FAILED;
    int rc = OS(s)->fsync(OS(s)->ctx, fd);
    OS(s)->close(OS(s)->ctx, fd);
    return rc == 0 ? GZ_SC_OK : GZ_SC_STORAGE_FAILED;
}

gz_sc_err_t gz_sc_fs_read(const gz_sc_store_t *s, const char *name, size_t max, uint8_t **data, size_t *len)
{
    char p[PATH_CAP];
    *data = NULL;
    *len = 0;
    gz_sc_err_t e = path_of(s, name, "", p);
    if (e != GZ_SC_OK)
        return e;
    int fd = OS(s)->open(OS(s)->ctx, p, O_RDONLY, 0);
    if (fd < 0)
        return errno == ENOENT ? GZ_SC_MISSING : GZ_SC_STORAGE_FAILED;
    size_t cap = 4096, n = 0;
    uint8_t *b = malloc(cap);
    e = b ? GZ_SC_OK : GZ_SC_NOMEM;
    while (e == GZ_SC_OK && n < max) {
        if (n == cap) {
            size_t nc = cap * 2 > max ? max : cap * 2;
            uint8_t *nb = realloc(b, nc);
            if (!nb) {
                e = GZ_SC_NOMEM;
                break;
            }
            b = nb;
            cap = nc;
        }
        long r = OS(s)->read(OS(s)->ctx, fd, b + n, (cap < max ? cap : max) - n);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            e = GZ_SC_STORAGE_FAILED;
        else if (r == 0)
            break;
        else
            n += (size_t)r;
    }
    OS(s)->close(OS(s)->ctx, fd);
    if (e != GZ_SC_OK) {
        free(b);
        return e;
    }
    *data = b;
    *len = n;
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_fs_replace(const gz_sc_store_t *s, const char *name, const uint8_t *data, size_t len)
{
    char tmp[PATH_CAP], dst[PATH_CAP];
    if (path_of(s, name, ".tmp", tmp) != GZ_SC_OK || path_of(s, name, "", dst) != GZ_SC_OK)
        return GZ_SC_ARG;
    /* A temporary file left by a crash is never trusted or reused. */
    if (OS(s)->unlink(OS(s)->ctx, tmp) != 0 && errno != ENOENT)
        return GZ_SC_STORAGE_FAILED;
    int fd = OS(s)->open(OS(s)->ctx, tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return GZ_SC_STORAGE_FAILED;
    int ok = write_all(s, fd, data, len) == 0 && OS(s)->fsync(OS(s)->ctx, fd) == 0;
    if (OS(s)->close(OS(s)->ctx, fd) != 0)
        ok = 0;
    if (!ok || OS(s)->rename(OS(s)->ctx, tmp, dst) != 0)
        return GZ_SC_STORAGE_FAILED;
    /* The rename is the commit point: from here the new file is the one in
     * the folder, so a failed folder sync is not "nothing happened" (review B,
     * L1). Only its durability across a power cut is unconfirmed. */
    return sync_dir(s) == GZ_SC_OK ? GZ_SC_OK : GZ_SC_DONE_WITH_FAULT;
}

gz_sc_err_t gz_sc_fs_append(const gz_sc_store_t *s, const char *name, uint64_t at, const uint8_t *data, size_t len)
{
    char p[PATH_CAP];
    if (path_of(s, name, "", p) != GZ_SC_OK)
        return GZ_SC_ARG;
    int fd = OS(s)->open(OS(s)->ctx, p, O_WRONLY | O_APPEND, 0);
    if (fd < 0)
        return GZ_SC_STORAGE_FAILED;
    int ok = OS(s)->ftruncate(OS(s)->ctx, fd, at) == 0 && write_all(s, fd, data, len) == 0 &&
             OS(s)->fsync(OS(s)->ctx, fd) == 0;
    if (OS(s)->close(OS(s)->ctx, fd) != 0)
        ok = 0;
    return ok ? GZ_SC_OK : GZ_SC_STORAGE_FAILED;
}

/* ---- set-up and unlock --------------------------------------------------------- */
void gz_sc_unlocked_clear(gz_sc_unlocked_t *u)
{
    gz_sc_vault_free(u->vault);
    gz_sc_framekey_free(u->kj);
    gz_sc_framekey_free(u->kh);
    memset(u, 0, sizeof *u);
}

static gz_sc_err_t derive_pk(const gz_sc_store_t *s, const uint8_t *pw, size_t pw_len, const uint8_t salt[16],
                             const gz_sc_kdf_params_t *p, uint8_t **pk, int *locked)
{
    *pk = sodium_malloc(32);
    if (!*pk)
        return GZ_SC_NOMEM;
    int l = 0;
    gz_sc_err_t e = s->kdf(s->kdf_ctx, pw, pw_len, salt, p, *pk, &l);
    if (locked)
        *locked = l;
    if (e != GZ_SC_OK) {
        sodium_free(*pk);
        *pk = NULL;
    }
    return e;
}

/* A new journal (header only) and its mark file: the mark file first (7.4),
 * each by an atomic replace. For a restore (6.3 step 0) the mark file holds
 * the restore marker instead of the set-up entry, and it is written before
 * the journal exists: a crash before the journal's rename leaves no journal
 * (step 0 again), and one after it leaves the marker, so the next start is
 * the same restore (review B, M2). */
static gz_sc_err_t new_journal(const gz_sc_store_t *s, gz_sc_unlocked_t *u, int restore)
{
    gz_sc_err_t e = gz_sc_random(u->file_id, 16);
    if (e != GZ_SC_OK)
        return e;
    uint8_t mk[GZ_SC_MARK_HEADER_LEN + GZ_SC_MARK_ENTRY_LEN], hdr[GZ_SC_JHEADER_LEN];
    if ((e = gz_sc_mark_key(u->vault, u->file_id, &u->kh)) != GZ_SC_OK ||
        (e = (restore ? gz_sc_mark_new_restore : gz_sc_mark_new)(u->kh, s->chain, mk)) != GZ_SC_OK ||
        (e = gz_sc_header_seal(u->vault, u->file_id, hdr)) != GZ_SC_OK)
        return e;
    if ((e = gz_sc_fs_replace(s, GZ_SC_FILE_MARK, mk, sizeof mk)) != GZ_SC_OK ||
        (e = gz_sc_fs_replace(s, GZ_SC_FILE_JOURNAL, hdr, sizeof hdr)) != GZ_SC_OK)
        return e == GZ_SC_DONE_WITH_FAULT ? GZ_SC_STORAGE_FAILED : e; /* an unsynced folder is a failure here */
    return gz_sc_header_open(hdr, u->vault, &u->kj);
}

/* 4.1's form and length rules for a passphrase that will make a key file
 * (review A, M3): the layer enforces them whatever its caller did. */
static gz_sc_err_t new_pass_ok(const uint8_t *pw, size_t len)
{
    return gz_sc_pass_check_form(pw, len) == GZ_SC_PASS_OK ? GZ_SC_OK : GZ_SC_PASS_REFUSED;
}

/* A passphrase that opens an existing key file: never derived from unless it
 * is NFC, so a decomposed spelling cannot make or meet a key (M3). */
static gz_sc_err_t old_pass_ok(const uint8_t *pw, size_t len)
{
    return sc_pass_is_nfc(pw, len) ? GZ_SC_OK : GZ_SC_PASS_REFUSED;
}

/* GZ_SC_OK if dir/name exists, GZ_SC_MISSING if not, else the read error. */
static gz_sc_err_t present(const gz_sc_store_t *s, const char *name)
{
    uint8_t *b = NULL;
    size_t l = 0;
    gz_sc_err_t e = gz_sc_fs_read(s, name, 1, &b, &l);
    free(b);
    return e;
}

/* What set-up may write over (review B, M1): nothing of a wallet. A key file
 * is EXISTS; a journal is JOURNAL_HERE (its recovery wrap opens with the old
 * words, 9.3, which set-up would destroy); a guard or mark file without them
 * is EXISTS too: the guard is the only record of an old wallet's epochs.
 * restore: the restore path, where a guard is kept rather than refused and a
 * stale mark file (no journal) is replaced, as at step 0. */
static gz_sc_err_t folder_free(const gz_sc_store_t *s, int restore)
{
    gz_sc_err_t e = present(s, GZ_SC_FILE_KEYS);
    if (e != GZ_SC_MISSING)
        return e == GZ_SC_OK ? GZ_SC_EXISTS : e;
    if ((e = present(s, GZ_SC_FILE_JOURNAL)) != GZ_SC_MISSING)
        return e == GZ_SC_OK ? GZ_SC_JOURNAL_HERE : e;
    if (restore)
        return GZ_SC_OK;
    const char *const rest[] = {GZ_SC_FILE_GUARD, GZ_SC_FILE_MARK};
    for (size_t i = 0; i < 2; i++)
        if ((e = present(s, rest[i])) != GZ_SC_MISSING)
            return e == GZ_SC_OK ? GZ_SC_EXISTS : e;
    return GZ_SC_OK;
}

/* Set-up and the restore from the words (9.3, first bullet): 7.4's creation
 * order. Once the key file's rename has happened the wallet exists: a later
 * failure is DONE_WITH_FAULT, never a failure (review B, L1), with every key
 * dropped; the next unlock makes what is missing as a restore (6.3 step 0). */
static gz_sc_err_t make_wallet(const gz_sc_store_t *s, const uint8_t *pw_nfc, size_t pw_len,
                               const gz_sc_kdf_params_t *params, const uint8_t entropy[32], const uint8_t seed[64],
                               int restore, gz_sc_unlocked_t *u)
{
    memset(u, 0, sizeof *u);
    gz_sc_err_t e = new_pass_ok(pw_nfc, pw_len);
    if (e != GZ_SC_OK)
        return e;
    if ((e = folder_free(s, restore)) != GZ_SC_OK)
        return e;
    if ((e = gz_sc_params_check(params)) != GZ_SC_OK)
        return e;
    uint8_t *msk = sodium_malloc(32), *pk = NULL;
    uint8_t vault_id[16], salt[16], kf[GZ_SC_KEYFILE_LEN];
    int committed = 0, fault = 0;
    if (!msk)
        return GZ_SC_NOMEM;
    if ((e = gz_sc_random(msk, 32)) != GZ_SC_OK || (e = gz_sc_random(vault_id, 16)) != GZ_SC_OK ||
        (e = gz_sc_random(salt, 16)) != GZ_SC_OK)
        goto done;
    if ((e = derive_pk(s, pw_nfc, pw_len, salt, params, &pk, &u->mem_locked)) != GZ_SC_OK)
        goto done;
    if ((e = gz_sc_keyfile_build(s->chain, vault_id, params, salt, pk, msk, entropy, seed, kf)) != GZ_SC_OK)
        goto done;
    if ((e = gz_sc_vault_new(s->chain, vault_id, msk, seed, &u->vault)) != GZ_SC_OK)
        goto done;
    sc_vault_set_kdf(u->vault, params);
    e = gz_sc_fs_replace(s, GZ_SC_FILE_KEYS, kf, sizeof kf);
    if (e != GZ_SC_OK && e != GZ_SC_DONE_WITH_FAULT)
        goto done;
    committed = 1;
    fault = e != GZ_SC_OK;
    if (!restore) {
        /* A new wallet's guard: counter 0, no epochs. A restore keeps the
         * folder's guard: if it opens under the seed, the restore's first
         * batch carries its counter and epochs on; if it is missing or does
         * not open, that batch replaces it (journal.md 8.3). */
        gz_sc_guard_t g;
        memset(&g, 0, sizeof g);
        uint8_t gbuf[GZ_SC_GUARD_HEAD + 40 + 18];
        size_t gl;
        if ((e = gz_sc_guard_seal(u->vault, &g, gbuf, sizeof gbuf, &gl)) != GZ_SC_OK ||
            (e = gz_sc_fs_replace(s, GZ_SC_FILE_GUARD, gbuf, gl)) != GZ_SC_OK)
            goto done;
    }
    e = new_journal(s, u, restore);
    u->restore = restore;
    /* The same info gz_sc_unlock gives (review A, L8). */
    memcpy(u->info.chain, s->chain, 32);
    memcpy(u->info.vault_id, vault_id, 16);
    u->info.kdf = *params;
    memcpy(u->info.salt, salt, 16);
done:
    gz_sc_sfree(msk);
    gz_sc_sfree(pk);
    sodium_memzero(kf, sizeof kf);
    if (e == GZ_SC_OK && fault)
        e = GZ_SC_DONE_WITH_FAULT;
    if (e != GZ_SC_OK) {
        gz_sc_unlocked_clear(u);
        if (committed)
            e = GZ_SC_DONE_WITH_FAULT;
    }
    return e;
}

gz_sc_err_t gz_sc_setup(const gz_sc_store_t *s, const uint8_t *pw_nfc, size_t pw_len,
                        const gz_sc_kdf_params_t *params, const uint8_t entropy[32], const uint8_t seed[64],
                        gz_sc_unlocked_t *u)
{
    return make_wallet(s, pw_nfc, pw_len, params, entropy, seed, 0, u);
}

gz_sc_err_t gz_sc_setup_restore(const gz_sc_store_t *s, const uint8_t *pw_nfc, size_t pw_len,
                                const gz_sc_kdf_params_t *params, const uint8_t entropy[32],
                                const uint8_t seed[64], gz_sc_unlocked_t *u)
{
    return make_wallet(s, pw_nfc, pw_len, params, entropy, seed, 1, u);
}

/* A temporary file left by a crashed replace is sealed but useless: removed
 * once the key file has opened (review A, L8). Failures are ignored: the next
 * replace of that file removes it too. */
static void drop_stale_tmp(const gz_sc_store_t *s)
{
    static const char *const names[] = {GZ_SC_FILE_KEYS, GZ_SC_FILE_JOURNAL, GZ_SC_FILE_GUARD, GZ_SC_FILE_MARK,
                                        GZ_SC_FILE_ATTEMPTS};
    char p[PATH_CAP];
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (path_of(s, names[i], ".tmp", p) == GZ_SC_OK)
            (void)OS(s)->unlink(OS(s)->ctx, p);
}

gz_sc_err_t gz_sc_unlock(const gz_sc_store_t *s, const uint8_t *pw_nfc, size_t pw_len,
                         const gz_sc_kdf_params_t *def, gz_sc_unlocked_t *u)
{
    memset(u, 0, sizeof *u);
    uint8_t *kf = NULL, *hdr = NULL, *pk = NULL;
    size_t kl = 0, hl = 0;
    gz_sc_err_t e = old_pass_ok(pw_nfc, pw_len);
    if (e != GZ_SC_OK)
        return e;
    if ((e = gz_sc_fs_read(s, GZ_SC_FILE_KEYS, GZ_SC_KEYFILE_LEN + 1, &kf, &kl)) != GZ_SC_OK)
        return e;
    if ((e = gz_sc_keyfile_parse(kf, kl, s->chain, &u->info)) != GZ_SC_OK)
        goto done;
    if ((e = derive_pk(s, pw_nfc, pw_len, u->info.salt, &u->info.kdf, &pk, &u->mem_locked)) != GZ_SC_OK)
        goto done;
    if ((e = gz_sc_keyfile_unlock(kf, pk, &u->vault)) != GZ_SC_OK)
        goto done;
    drop_stale_tmp(s);
    if (def) {
        gz_sc_kdf_params_t want;
        gz_sc_params_for_new_wrap(&u->info.kdf, def, &want);
        u->upgrade_due = want.t > u->info.kdf.t || want.m_kib > u->info.kdf.m_kib;
    }
    e = gz_sc_fs_read(s, GZ_SC_FILE_JOURNAL, GZ_SC_JHEADER_LEN, &hdr, &hl);
    if (e == GZ_SC_MISSING) {
        /* 6.3 step 0 (review R2-2): a key file with no journal starts as a
         * restore, with a new journal and a mark file holding the restore
         * marker (written first, review B, M2); a stale mark file is
         * replaced; the guard file is kept. */
        u->restore = 1;
        e = new_journal(s, u, 1);
        goto done;
    }
    if (e != GZ_SC_OK)
        goto done;
    uint8_t vid[16];
    if ((e = gz_sc_header_clear(hdr, hl, s->chain, vid, u->file_id)) != GZ_SC_OK)
        goto done;
    if ((e = gz_sc_header_open(hdr, u->vault, &u->kj)) != GZ_SC_OK)
        goto done;
    e = gz_sc_mark_key(u->vault, u->file_id, &u->kh);
done:
    free(kf);
    free(hdr);
    gz_sc_sfree(pk);
    if (e != GZ_SC_OK)
        gz_sc_unlocked_clear(u); /* keys dropped on every failure (8.2) */
    return e;
}

static gz_sc_err_t read_mark(const gz_sc_store_t *s, const gz_sc_unlocked_t *u, gz_sc_mark_state_t *st,
                             uint64_t *inc, uint64_t *off, size_t *end)
{
    uint8_t *m = NULL;
    size_t ml = 0;
    gz_sc_err_t e = gz_sc_fs_read(s, GZ_SC_FILE_MARK, (size_t)1 << 30, &m, &ml);
    if (e == GZ_SC_MISSING) {
        *st = GZ_SC_MARK_NOT_A_MARK_FILE;
        return GZ_SC_OK;
    }
    if (e != GZ_SC_OK)
        return e;
    *st = gz_sc_mark_read(u->kh, m, ml, s->chain, u->file_id, inc, off, end);
    free(m);
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_check_start(const gz_sc_store_t *s, const gz_sc_unlocked_t *u, const gz_sc_journal_view_t *j,
                              gz_sc_start_t *start)
{
    gz_sc_mark_state_t ms = GZ_SC_MARK_NOT_A_MARK_FILE;
    uint64_t inc = 0, off = 0;
    size_t end = 0;
    gz_sc_err_t e = read_mark(s, u, &ms, &inc, &off, &end);
    if (e != GZ_SC_OK)
        return e; /* a read error is a storage failure, never "possibly old" (M1) */
    uint8_t *g = NULL;
    size_t gl = 0;
    gz_sc_guard_t guard;
    memset(&guard, 0, sizeof guard);
    gz_sc_err_t gs = gz_sc_fs_read(s, GZ_SC_FILE_GUARD, (size_t)1 << 20, &g, &gl);
    if (gs != GZ_SC_OK && gs != GZ_SC_MISSING)
        return gs;
    if (gs == GZ_SC_OK) {
        gs = gz_sc_guard_open(u->vault, g, gl, &guard);
        free(g);
        if (gs == GZ_SC_NOMEM)
            return gs;
        if (gs != GZ_SC_OK)
            gs = GZ_SC_DAMAGED; /* another format, network or a failed tag */
    }
    *start = gz_sc_start_rule(ms, inc, off, gs, guard.counter, j);
    gz_sc_guard_clear(&guard);
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_anchor(const gz_sc_store_t *s, const gz_sc_unlocked_t *u, uint64_t incarnation,
                         uint64_t mark_offset)
{
    uint8_t *m = NULL;
    size_t ml = 0, end = 0;
    gz_sc_err_t e = gz_sc_fs_read(s, GZ_SC_FILE_MARK, (size_t)1 << 30, &m, &ml);
    if (e != GZ_SC_OK)
        return GZ_SC_STORAGE_FAILED; /* a missing mark file at write time is a storage failure */
    uint64_t i, o;
    gz_sc_mark_state_t st = gz_sc_mark_read(u->kh, m, ml, s->chain, u->file_id, &i, &o, &end);
    uint8_t entry[GZ_SC_MARK_ENTRY_LEN];
    if (st != GZ_SC_MARK_OK || incarnation < i || (incarnation == i && mark_offset < o))
        e = GZ_SC_STORAGE_FAILED;
    else
        e = gz_sc_mark_entry(u->kh, m, (uint64_t)end, incarnation, mark_offset, entry);
    free(m);
    if (e != GZ_SC_OK)
        return e;
    return gz_sc_fs_append(s, GZ_SC_FILE_MARK, (uint64_t)end, entry, sizeof entry);
}

gz_sc_err_t gz_sc_guard_write(const gz_sc_store_t *s, const gz_sc_vault_t *v, const gz_sc_guard_t *g)
{
    size_t cap = GZ_SC_GUARD_HEAD + 40 + gz_sc_guard_contents_len(g), n;
    uint8_t *b = malloc(cap);
    if (!b)
        return GZ_SC_NOMEM;
    gz_sc_err_t e = gz_sc_guard_seal(v, g, b, cap, &n);
    if (e == GZ_SC_OK)
        e = gz_sc_fs_replace(s, GZ_SC_FILE_GUARD, b, n);
    free(b);
    /* A batch is confirmed only after a durable guard (7 step 2). */
    return e == GZ_SC_DONE_WITH_FAULT ? GZ_SC_STORAGE_FAILED : e;
}

gz_sc_err_t gz_sc_mark_restart(const gz_sc_store_t *s, const gz_sc_unlocked_t *u)
{
    /* The restore marker (review B, M2): until the restore's first batch is
     * anchored, every start is that restore, so a crash or a closed window
     * in between does not send the person back to "files behind". */
    uint8_t mk[GZ_SC_MARK_HEADER_LEN + GZ_SC_MARK_ENTRY_LEN];
    gz_sc_err_t e = gz_sc_mark_new_restore(u->kh, s->chain, mk);
    if (e != GZ_SC_OK)
        return e;
    e = gz_sc_fs_replace(s, GZ_SC_FILE_MARK, mk, sizeof mk);
    return e == GZ_SC_DONE_WITH_FAULT ? GZ_SC_STORAGE_FAILED : e;
}

/* ---- passphrase change, words, recovery ------------------------------------------ */
gz_sc_err_t gz_sc_rewrap(const gz_sc_store_t *s, const uint8_t *old_pw, size_t old_len, const uint8_t *new_pw,
                         size_t new_len, const gz_sc_kdf_params_t *def)
{
    uint8_t *kf = NULL, *old_pk = NULL, *new_pk = NULL;
    size_t kl = 0;
    gz_sc_keyfile_info_t info;
    gz_sc_err_t e = old_pass_ok(old_pw, old_len);
    if (e == GZ_SC_OK && new_pw)
        e = new_pass_ok(new_pw, new_len);
    if (e != GZ_SC_OK)
        return e;
    if ((e = gz_sc_fs_read(s, GZ_SC_FILE_KEYS, GZ_SC_KEYFILE_LEN + 1, &kf, &kl)) != GZ_SC_OK)
        return e;
    uint8_t salt[16], out[GZ_SC_KEYFILE_LEN];
    gz_sc_kdf_params_t np;
    if ((e = gz_sc_keyfile_parse(kf, kl, s->chain, &info)) != GZ_SC_OK)
        goto done;
    gz_sc_params_for_new_wrap(&info.kdf, def, &np);
    if ((e = gz_sc_random(salt, sizeof salt)) != GZ_SC_OK)
        goto done;
    if ((e = derive_pk(s, old_pw, old_len, info.salt, &info.kdf, &old_pk, NULL)) != GZ_SC_OK)
        goto done;
    if (!new_pw) {
        new_pw = old_pw;
        new_len = old_len;
    }
    if ((e = derive_pk(s, new_pw, new_len, salt, &np, &new_pk, NULL)) != GZ_SC_OK)
        goto done;
    if ((e = gz_sc_keyfile_rewrap(kf, old_pk, &np, salt, new_pk, out)) != GZ_SC_OK)
        goto done;
    e = gz_sc_fs_replace(s, GZ_SC_FILE_KEYS, out, sizeof out);
done:
    free(kf);
    gz_sc_sfree(old_pk);
    gz_sc_sfree(new_pk);
    return e;
}

gz_sc_err_t gz_sc_words(const gz_sc_store_t *s, const uint8_t *pw_nfc, size_t pw_len, uint8_t entropy[32])
{
    uint8_t *kf = NULL, *pk = NULL;
    size_t kl = 0;
    gz_sc_keyfile_info_t info;
    gz_sc_err_t e = old_pass_ok(pw_nfc, pw_len);
    if (e != GZ_SC_OK)
        return e;
    if ((e = gz_sc_fs_read(s, GZ_SC_FILE_KEYS, GZ_SC_KEYFILE_LEN + 1, &kf, &kl)) != GZ_SC_OK)
        return e;
    if ((e = gz_sc_keyfile_parse(kf, kl, s->chain, &info)) == GZ_SC_OK &&
        (e = derive_pk(s, pw_nfc, pw_len, info.salt, &info.kdf, &pk, NULL)) == GZ_SC_OK)
        e = gz_sc_keyfile_words(kf, pk, entropy);
    free(kf);
    gz_sc_sfree(pk);
    return e;
}

gz_sc_err_t gz_sc_check(const gz_sc_store_t *s, const gz_sc_vault_t *v, const uint8_t *pw_nfc, size_t pw_len)
{
    uint8_t *kf = NULL, *pk = NULL;
    size_t kl = 0;
    gz_sc_keyfile_info_t info;
    gz_sc_err_t e = old_pass_ok(pw_nfc, pw_len);
    if (e != GZ_SC_OK)
        return e;
    if ((e = gz_sc_fs_read(s, GZ_SC_FILE_KEYS, GZ_SC_KEYFILE_LEN + 1, &kf, &kl)) != GZ_SC_OK)
        return e;
    if ((e = gz_sc_keyfile_parse(kf, kl, s->chain, &info)) == GZ_SC_OK &&
        (e = derive_pk(s, pw_nfc, pw_len, info.salt, &info.kdf, &pk, NULL)) == GZ_SC_OK)
        e = gz_sc_keyfile_check(kf, pk, v);
    free(kf);
    gz_sc_sfree(pk);
    return e;
}

gz_sc_err_t gz_sc_recover_keyfile(const gz_sc_store_t *s, const uint8_t entropy[32], const uint8_t seed[64],
                                  const uint8_t *pw_nfc, size_t pw_len, const gz_sc_kdf_params_t *params)
{
    gz_sc_err_t pe = new_pass_ok(pw_nfc, pw_len);
    if (pe != GZ_SC_OK)
        return pe;
    uint8_t *hdr = NULL, *msk = sodium_malloc(32), *pk = NULL;
    size_t hl = 0;
    if (!msk)
        return GZ_SC_NOMEM;
    uint8_t vid[16], fid[16], salt[16], kf[GZ_SC_KEYFILE_LEN];
    gz_sc_err_t e = gz_sc_fs_read(s, GZ_SC_FILE_JOURNAL, GZ_SC_JHEADER_LEN, &hdr, &hl);
    if (e != GZ_SC_OK)
        goto done;
    if ((e = gz_sc_header_clear(hdr, hl, s->chain, vid, fid)) != GZ_SC_OK ||
        (e = gz_sc_header_recover(hdr, s->chain, seed, msk)) != GZ_SC_OK)
        goto done;
    if ((e = gz_sc_params_check(params)) != GZ_SC_OK || (e = gz_sc_random(salt, 16)) != GZ_SC_OK ||
        (e = derive_pk(s, pw_nfc, pw_len, salt, params, &pk, NULL)) != GZ_SC_OK ||
        (e = gz_sc_keyfile_build(s->chain, vid, params, salt, pk, msk, entropy, seed, kf)) != GZ_SC_OK)
        goto done;
    e = gz_sc_fs_replace(s, GZ_SC_FILE_KEYS, kf, sizeof kf);
done:
    free(hdr);
    gz_sc_sfree(msk);
    gz_sc_sfree(pk);
    sodium_memzero(kf, sizeof kf);
    return e;
}

/* ---- attempts.gza ----------------------------------------------------------------- */
int gz_sc_attempts_load(const gz_sc_store_t *s, uint64_t now_s, gz_sc_attempts_t *a)
{
    uint8_t *d = NULL;
    size_t dl = 0;
    gz_sc_err_t e = gz_sc_fs_read(s, GZ_SC_FILE_ATTEMPTS, GZ_SC_ATTEMPTS_LEN + 1, &d, &dl);
    int ok = gz_sc_attempts_decode(s->chain, e == GZ_SC_OK ? d : NULL, dl, now_s, a);
    free(d);
    return ok;
}

gz_sc_err_t gz_sc_attempts_store(const gz_sc_store_t *s, const gz_sc_attempts_t *a)
{
    uint8_t b[GZ_SC_ATTEMPTS_LEN];
    gz_sc_attempts_encode(s->chain, a, b);
    gz_sc_err_t e = gz_sc_fs_replace(s, GZ_SC_FILE_ATTEMPTS, b, sizeof b);
    return e == GZ_SC_DONE_WITH_FAULT ? GZ_SC_STORAGE_FAILED : e;
}
