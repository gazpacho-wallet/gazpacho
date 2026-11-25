/* SPDX-License-Identifier: MIT */
/* program/unlock.h over the storage layer of ports/storage/crypto (S6): the
 * key file keys.gzk, the attempts file attempts.gza (mode 1, storage 12.3),
 * set-up (7.4), the restore from the words (9.3), the unlock (8.2) and the
 * start rule (6.3) at the journal's open. See store_unlock.h. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "gazpacho/wallet_keys.h"

#include "datadir.h"
#include "gzp.h"
#include "store_unlock.h"
#ifdef GZP_TEST_BUILD
#include "gz_storage_crypto_test.h"
#endif

struct gzp_wallet {
    gz_sc_store_t sc;
    char dir[GZP_PATH_MAX];
    char helper[GZP_PATH_MAX];
    uint8_t chain[32];
    gz_sc_kdf_params_t params;   /* for a new key file */
    gz_sc_unlocked_t u;          /* the unlocked keys; u.vault NULL while locked */
    int unlocked;
    gzp_store_t opened;          /* the store finish opened, until taken */
    int have_opened;
    atomic_int deriving;         /* a begin is under way (one derivation at a time, 8.2) */
    int setup_interrupted;       /* this unlock found the set-up marker and no journal (told only) */
    int change_wide;             /* this start is a restore: the change mark may be behind (wport.h) */
#ifdef GZP_TEST_BUILD
    char restore_from[GZP_PATH_MAX];
    int keys_only;
    int seed_fault; /* tests: seed() answers as if storage failed */
#endif
};

/* What begin leaves for finish (job->keys). */
typedef struct {
    int op;
    gz_sc_err_t err;             /* of the derivation */
    gz_sc_unlocked_t u;          /* UNLOCK, START_AS_RESTORE, CHECK: the key file opened */
    gz_sc_prepared_t prep;       /* CREATE, RESTORE: the key file's bytes */
    int have_prep;
} job_keys_t;

static const char *const STATUS_NAMES[] = {"ok", "wrong", "busy", "not_checked", "no_wallet", "exists",
                                           "weak", "bad_words", "files_behind", "storage_failed",
                                           "words_differ"};

const char *gzp_unlock_status_name(int status)
{
    return status >= 0 && (size_t)status < sizeof STATUS_NAMES / sizeof STATUS_NAMES[0] ? STATUS_NAMES[status] : "?";
}

/* ---- the folder ----------------------------------------------------------- */

static int file_exists(const gzp_wallet_t *w, const char *name)
{
    char p[GZP_PATH_MAX + 64];
    struct stat st;
    snprintf(p, sizeof p, "%s/%s", w->dir, name);
    return stat(p, &st) == 0;
}

/* The set-up marker: written before the key file at set-up (not at the
 * restore from the words) and removed once the first incarnation entry is
 * durable, so a key file with no start counter beside it is a set-up that
 * never started (storage 7.4, pending the storage reviewers): finished as a
 * new wallet, never a restore, nothing told. */
#define SETUP_MARKER "setup.gzp"

static int setup_marker_write(gzp_wallet_t *w)
{
    static const uint8_t body[] = "gazpacho set-up not yet started\n";
    char p[GZP_PATH_MAX + 64];
    snprintf(p, sizeof p, "%s/%s.tmp", w->dir, SETUP_MARKER);
    (void)unlink(p); /* a crashed replace's leftover */
    return gz_sc_fs_replace(&w->sc, SETUP_MARKER, body, sizeof body - 1) == GZ_SC_OK ? 0 : -1;
}

/* A regular file only (review A of PR 54, L7: a directory of that name is
 * not the marker). */
static int marker_present(const gzp_wallet_t *w)
{
    char p[GZP_PATH_MAX + 64];
    struct stat st;
    snprintf(p, sizeof p, "%s/%s", w->dir, SETUP_MARKER);
    return lstat(p, &st) == 0 && S_ISREG(st.st_mode);
}

/* Through the storage layer's OS table, so the tests' kill and power-cut
 * points see the removal and its folder sync (review A of PR 54, L1). */
static int setup_marker_clear(gzp_wallet_t *w)
{
    const gz_sc_os_t *os = w->sc.os;
    char p[GZP_PATH_MAX + 64];
    int fd, rc;
    if (!marker_present(w)) return 0;
    snprintf(p, sizeof p, "%s/%s", w->dir, SETUP_MARKER);
    if (os->unlink(os->ctx, p) != 0) return errno == ENOENT ? 0 : -1;
    if ((fd = os->open(os->ctx, w->dir, O_RDONLY | O_DIRECTORY, 0)) < 0) return -1;
    rc = os->fsync(os->ctx, fd);
    os->close(os->ctx, fd);
    return rc;
}

#ifdef GZP_TEST_BUILD
/* The storage layer's calls, each counted by --test-kill-at (store.h). */
static int t_open(void *c, const char *p, int f, int m)
{
    (void)c;
    if (f & (O_WRONLY | O_RDWR | O_CREAT)) gzp_store_test_tick("storage-open-write");
    int existed = gzp_pc_pre(p), fd = gz_sc_os_posix.open(gz_sc_os_posix.ctx, p, f, m);
    gzp_pc_opened(p, fd, existed);
    return fd;
}
static long t_write(void *c, int fd, const void *p, size_t n)
{
    (void)c;
    gzp_store_test_tick("storage-write");
    return gz_sc_os_posix.write(gz_sc_os_posix.ctx, fd, p, n);
}
static long t_read(void *c, int fd, void *p, size_t n) { (void)c; return gz_sc_os_posix.read(gz_sc_os_posix.ctx, fd, p, n); }
static int t_fsync(void *c, int fd)
{
    (void)c;
    gzp_store_test_tick("storage-sync");
    if (gz_sc_os_posix.fsync(gz_sc_os_posix.ctx, fd) != 0) return -1;
    gzp_pc_synced(fd);
    return 0;
}
static int t_ftruncate(void *c, int fd, uint64_t l)
{
    (void)c;
    gzp_store_test_tick("storage-truncate");
    return gz_sc_os_posix.ftruncate(gz_sc_os_posix.ctx, fd, l);
}
static int t_close(void *c, int fd)
{
    (void)c;
    gzp_pc_closed(fd);
    return gz_sc_os_posix.close(gz_sc_os_posix.ctx, fd);
}
static int t_rename(void *c, const char *a, const char *b)
{
    (void)c;
    gzp_store_test_tick("storage-rename");
    gzp_pc_pre(a);
    gzp_pc_pre(b);
    if (gz_sc_os_posix.rename(gz_sc_os_posix.ctx, a, b) != 0) return -1;
    gzp_pc_renamed(a, b);
    return 0;
}
static int t_unlink(void *c, const char *p)
{
    (void)c;
    gzp_store_test_tick("storage-unlink");
    gzp_pc_pre(p);
    if (gz_sc_os_posix.unlink(gz_sc_os_posix.ctx, p) != 0) return -1;
    gzp_pc_unlinked(p);
    return 0;
}
static const gz_sc_os_t TEST_OS = {NULL, t_open, t_write, t_read, t_fsync, t_ftruncate, t_close, t_rename, t_unlink};
#endif

int gzp_wallet_open(gzp_wallet_t **out, const char *dir, const uint8_t chain[32], const char *helper)
{
    char p[GZP_PATH_MAX + 64];
    struct stat st;
    gzp_wallet_t *w;
    *out = NULL;
    if (gz_sc_init() != GZ_SC_OK) {
        fprintf(stderr, "gazpacho: the storage library did not start\n");
        return GZP_EXIT_FAILED;
    }
    if (strlen(dir) >= GZP_PATH_MAX - 32 || strlen(helper) >= GZP_PATH_MAX) return GZP_EXIT_DATA;
    w = calloc(1, sizeof *w);
    if (!w) return GZP_EXIT_FAILED;
    strcpy(w->dir, dir);
    strcpy(w->helper, helper);
    memcpy(w->chain, chain, 32);
#ifdef GZP_TEST_BUILD
    w->sc.os = &TEST_OS;
#else
    w->sc.os = &gz_sc_os_posix;
#endif
    w->sc.dir = w->dir;
    memcpy(w->sc.chain, chain, 32);
    w->sc.kdf = gz_sc_kdf_helper;
    w->sc.kdf_ctx = w->helper;
    w->params = GZ_SC_KDF_KEYFILE_DEFAULT;
    atomic_init(&w->deriving, 0);
    /* The key file closed to others, as the stand-in key files were (a
     * copy of it is an offline guess at the passphrase, storage 3.3). */
    snprintf(p, sizeof p, "%s/%s", dir, GZ_SC_FILE_KEYS);
    if (stat(p, &st) == 0 && (st.st_mode & 077)) {
        fprintf(stderr, "gazpacho: %s must be closed to others (chmod 600)\n", p);
        free(w);
        return GZP_EXIT_DATA;
    }
    *out = w;
    return 0;
}

static void drop_opened(gzp_wallet_t *w)
{
    if (w->have_opened) w->opened.ops->close(w->opened.ctx);
    w->have_opened = 0;
}

void gzp_wallet_lock(gzp_wallet_t *w)
{
    drop_opened(w);
    gz_sc_unlocked_clear(&w->u); /* wipes MSK, the seed copy and every subkey */
    w->unlocked = 0;
}

void gzp_wallet_free(gzp_wallet_t *w)
{
    if (!w) return;
    gzp_wallet_lock(w);
    OPENSSL_cleanse(w, sizeof *w);
    free(w);
}

gzp_wallet_state_t gzp_wallet_state(gzp_wallet_t *w)
{
    if (w->unlocked) return GZP_WALLET_UNLOCKED;
    return file_exists(w, GZ_SC_FILE_KEYS) ? GZP_WALLET_LOCKED : GZP_WALLET_NONE;
}

/* ---- attempts (local-api.md 4.3, storage 12.3) ------------------------------ */

static uint64_t secs(int64_t now_ms) { return now_ms > 0 ? (uint64_t)now_ms / 1000u : 0; }

/* Wrong passphrases in a row before the delay starts doubling (gz_sc_attempts_wait). */
#define FREE_WRONG 5u

static void fill_attempts(gzp_unlock_result_t *r, const gz_sc_attempts_t *a, uint64_t now_s)
{
    uint64_t wait = gz_sc_attempts_wait(a, now_s);
    r->wrong_in_row = a->wrong_in_a_row;
    r->attempts_left = a->wrong_in_a_row >= FREE_WRONG ? 0 : FREE_WRONG - a->wrong_in_a_row;
    r->retry_after_s = wait > UINT32_MAX ? UINT32_MAX : (uint32_t)wait;
}

void gzp_wallet_attempts(gzp_wallet_t *w, int64_t now_ms, gzp_unlock_result_t *out)
{
    gz_sc_attempts_t a;
    uint64_t now_s = secs(now_ms);
    memset(out, 0, sizeof *out);
    if (atomic_load(&w->deriving)) {
        out->status = GZP_UNLOCK_BUSY;
        out->retry_after_s = 1;
        return;
    }
    /* No key file: nothing to guess yet (create and restore make the file,
     * clean). Otherwise a missing or damaged file is the strictest state. */
    if (gzp_wallet_state(w) == GZP_WALLET_NONE) {
        out->status = GZP_UNLOCK_OK;
        return;
    }
    gz_sc_attempts_load(&w->sc, now_s, &a);
    if (gz_sc_attempts_wait(&a, now_s) > 0) {
        out->status = GZP_UNLOCK_BUSY;
        fill_attempts(out, &a, now_s);
        return;
    }
    out->status = GZP_UNLOCK_OK;
}

/* Count one wrong or one right passphrase (finish and discard). 0, or -1 if
 * the file could not be written. */
static int count_attempt(gzp_wallet_t *w, int wrong, int64_t now_ms, gzp_unlock_result_t *r)
{
    gz_sc_attempts_t a;
    uint64_t now_s = secs(now_ms);
    gz_sc_attempts_load(&w->sc, now_s, &a);
    if (wrong) gz_sc_attempts_wrong(&a, now_s);
    else gz_sc_attempts_right(&a, now_s);
    if (r) fill_attempts(r, &a, now_s);
    return gz_sc_attempts_store(&w->sc, &a) == GZ_SC_OK ? 0 : -1;
}

/* ---- results ------------------------------------------------------------------ */

static void set_result(gzp_unlock_result_t *r, int status, const char *reason)
{
    memset(r, 0, sizeof *r);
    r->status = status;
    r->reason = reason;
}

/* A storage-layer error as an unlock result. */
static void map_err(gzp_unlock_result_t *r, gz_sc_err_t e)
{
    switch (e) {
    case GZ_SC_OK: set_result(r, GZP_UNLOCK_OK, NULL); break;
    case GZ_SC_WRONG_PASSPHRASE: set_result(r, GZP_UNLOCK_WRONG, NULL); break;
    case GZ_SC_MISSING: set_result(r, GZP_UNLOCK_NO_WALLET, NULL); break;
    case GZ_SC_EXISTS: set_result(r, GZP_UNLOCK_EXISTS, "wallet_exists"); break;
    case GZ_SC_JOURNAL_HERE: set_result(r, GZP_UNLOCK_EXISTS, "journal_here"); break;
    case GZ_SC_HELPER_FAILED:
    case GZ_SC_NOMEM: set_result(r, GZP_UNLOCK_NOT_CHECKED, NULL); break;
    case GZ_SC_NEEDS_MORE_MEMORY: set_result(r, GZP_UNLOCK_NOT_CHECKED, "needs_more_memory"); break;
    case GZ_SC_PASS_REFUSED: set_result(r, GZP_UNLOCK_WEAK, "not_nfc"); break;
    case GZ_SC_DAMAGED: set_result(r, GZP_UNLOCK_STORAGE_FAILED, "damaged"); break;
    case GZ_SC_NOT_THIS_WALLET: set_result(r, GZP_UNLOCK_STORAGE_FAILED, "not_this_wallet"); break;
    case GZ_SC_OTHER_NETWORK: set_result(r, GZP_UNLOCK_STORAGE_FAILED, "other_network"); break;
    case GZ_SC_NOT_THIS_FORMAT: set_result(r, GZP_UNLOCK_STORAGE_FAILED, "not_a_key_file"); break;
    case GZ_SC_PARAMS_REFUSED: set_result(r, GZP_UNLOCK_STORAGE_FAILED, "params_refused"); break;
    default: set_result(r, GZP_UNLOCK_STORAGE_FAILED, "storage"); break;
    }
}

static const char *weak_reason(gz_sc_pass_rule_t rule)
{
    switch (rule) {
    case GZ_SC_PASS_TOO_SHORT: return "too_short";
    case GZ_SC_PASS_TOO_LONG: return "too_long";
    case GZ_SC_PASS_COMMON: return "common";
    case GZ_SC_PASS_NAME: return "name";
    case GZ_SC_PASS_WORDS: return "words";
    case GZ_SC_PASS_NOT_UTF8: return "not_utf8";
    case GZ_SC_PASS_NOT_NFC: return "not_nfc";
    case GZ_SC_PASS_UNASSIGNED: return "unassigned";
    case GZ_SC_PASS_NUL: return "nul";
    default: return "weak";
    }
}

/* ---- words ------------------------------------------------------------------------ */

/* The 24 words as one phrase (single spaces), into phrase. 0, or -1 if a
 * word is empty, too long or not lowercase ASCII (its 1-based *position). */
static int join_words(const char words[GZP_UNLOCK_WORDS][GZP_UNLOCK_WORD_MAX], char phrase[GZW_PHRASE_MAX],
                      uint32_t *position)
{
    size_t at = 0;
    for (size_t i = 0; i < GZP_UNLOCK_WORDS; i++) {
        size_t n = strnlen(words[i], GZP_UNLOCK_WORD_MAX);
        int ok = n > 0 && n <= 8;
        for (size_t k = 0; ok && k < n; k++) ok = words[i][k] >= 'a' && words[i][k] <= 'z';
        if (!ok) {
            *position = (uint32_t)i + 1;
            return -1;
        }
        if (i) phrase[at++] = ' ';
        memcpy(phrase + at, words[i], n);
        at += n;
    }
    phrase[at] = 0;
    return 0;
}

/* The first word gzw does not know (1-based), or 0. A single known word in
 * every other place keeps the count right and the checksum out of the way:
 * only the word list decides. */
static uint32_t unknown_word(const char words[GZP_UNLOCK_WORDS][GZP_UNLOCK_WORD_MAX])
{
    char phrase[GZW_PHRASE_MAX], one[GZP_UNLOCK_WORDS][GZP_UNLOCK_WORD_MAX];
    uint32_t pos = 0;
    for (size_t i = 0; i < GZP_UNLOCK_WORDS && !pos; i++) {
        for (size_t k = 0; k < GZP_UNLOCK_WORDS; k++) strcpy(one[k], k == i ? "" : "abandon");
        snprintf(one[i], GZP_UNLOCK_WORD_MAX, "%.*s", (int)strnlen(words[i], GZP_UNLOCK_WORD_MAX - 1), words[i]);
        if (join_words(one, phrase, &pos) != 0) break;
        if (gzw_phrase_check(phrase) == GZW_PHRASE_ERR_UNKNOWN_WORD) pos = (uint32_t)i + 1;
    }
    OPENSSL_cleanse(phrase, sizeof phrase);
    OPENSSL_cleanse(one, sizeof one);
    return pos;
}

/* BIP 39's entropy of a checked 24-word phrase: each word's index in the
 * English list, 11 bits each, the first 256 bits. The index is found by
 * asking gzw for the phrase of an entropy with that index in the first
 * word's place: the word list is gzw's own, never copied here. */
static int word_index(const char *word, uint16_t *idx)
{
    static char list[2048][9];
    static int have;
    if (!have) {
        for (unsigned i = 0; i < 2048; i++) {
            unsigned char e[32];
            char ph[GZW_PHRASE_MAX];
            memset(e, 0, sizeof e);
            e[0] = (unsigned char)(i >> 3);
            e[1] = (unsigned char)((i & 7) << 5);
            if (gzw_phrase_from_entropy(e, ph) != 1) return -1;
            size_t n = strcspn(ph, " ");
            if (n > 8) return -1;
            memcpy(list[i], ph, n);
            list[i][n] = 0;
        }
        have = 1;
    }
    for (unsigned i = 0; i < 2048; i++)
        if (!strcmp(list[i], word)) {
            *idx = (uint16_t)i;
            return 0;
        }
    return -1;
}

static int words_entropy(const char words[GZP_UNLOCK_WORDS][GZP_UNLOCK_WORD_MAX], uint8_t entropy[32])
{
    uint8_t bits[33];
    memset(bits, 0, sizeof bits);
    for (size_t i = 0; i < GZP_UNLOCK_WORDS; i++) {
        uint16_t v;
        if (word_index(words[i], &v) != 0) return -1;
        for (unsigned b = 0; b < 11; b++)
            if (v & (1u << (10 - b))) {
                size_t bit = i * 11 + b;
                bits[bit / 8] |= (uint8_t)(0x80u >> (bit % 8));
            }
    }
    memcpy(entropy, bits, 32);
    OPENSSL_cleanse(bits, sizeof bits);
    return 0;
}

/* ---- begin: the derivation thread; writes nothing -------------------------------- */

/* REVEAL and WORDS_CHECK (storage 9.2): the passphrase opens the words'
 * entropy (the helper derives, gz_sc_words); the wallet library makes the
 * 24 words. Reveal: into job->words, the caller's to show once and wipe.
 * Check: words[0..2] against the words at positions[0..2] (1-based), then
 * every copy wiped. Nothing is logged or written here. */
static void reveal_or_check(gzp_wallet_t *w, gzp_unlock_job_t *job)
{
    uint8_t *entropy = gz_sc_salloc(32);
    char *phrase = gz_sc_salloc(GZW_PHRASE_MAX);
    char *mine = gz_sc_salloc(GZP_UNLOCK_WORDS * GZP_UNLOCK_WORD_MAX);
    gz_sc_err_t e;
    if (!entropy || !phrase || !mine) {
        set_result(&job->result, GZP_UNLOCK_NOT_CHECKED, NULL);
        goto out;
    }
    e = gz_sc_words(&w->sc, job->passphrase, job->passphrase_len, entropy);
    if (e != GZ_SC_OK) {
        map_err(&job->result, e);
        goto out;
    }
    if (gzw_phrase_from_entropy(entropy, phrase) != 1) {
        set_result(&job->result, GZP_UNLOCK_STORAGE_FAILED, "words");
        goto out;
    }
    {
        char *save = NULL, *t = strtok_r(phrase, " ", &save);
        for (size_t i = 0; i < GZP_UNLOCK_WORDS; i++, t = strtok_r(NULL, " ", &save))
            snprintf(mine + i * GZP_UNLOCK_WORD_MAX, GZP_UNLOCK_WORD_MAX, "%s", t ? t : "");
    }
    if (job->op == GZP_UNLOCK_OP_REVEAL) {
        memcpy(job->words, mine, GZP_UNLOCK_WORDS * GZP_UNLOCK_WORD_MAX);
        set_result(&job->result, GZP_UNLOCK_OK, NULL);
    } else {
        int same = 1;
        for (int i = 0; i < 3; i++)
            same &= job->positions[i] >= 1 && job->positions[i] <= GZP_UNLOCK_WORDS &&
                    strncmp(job->words[i], mine + (size_t)(job->positions[i] - 1) * GZP_UNLOCK_WORD_MAX,
                            GZP_UNLOCK_WORD_MAX) == 0;
        set_result(&job->result, same ? GZP_UNLOCK_OK : GZP_UNLOCK_WORDS_DIFFER, NULL);
    }
out:
    gz_sc_sfree(entropy);
    gz_sc_sfree(phrase);
    gz_sc_sfree(mine);
}

void gzp_wallet_begin(gzp_wallet_t *w, gzp_unlock_job_t *job)
{
    job_keys_t *k = calloc(1, sizeof *k);
    uint8_t *seed = NULL, *entropy = NULL;
    char *phrase = NULL;
    atomic_store(&w->deriving, 1);
    job->keys = k;
    if (!k) {
        set_result(&job->result, GZP_UNLOCK_NOT_CHECKED, NULL);
        return;
    }
    k->op = job->op;
    set_result(&job->result, GZP_UNLOCK_OK, NULL);
    switch (job->op) {
    case GZP_UNLOCK_OP_UNLOCK:
    case GZP_UNLOCK_OP_START_AS_RESTORE:
    case GZP_UNLOCK_OP_CHECK:
        k->err = gz_sc_unlock_derive(&w->sc, job->passphrase, job->passphrase_len, &w->params, &k->u);
        map_err(&job->result, k->err);
        return;
    case GZP_UNLOCK_OP_REVEAL:
    case GZP_UNLOCK_OP_WORDS_CHECK:
        reveal_or_check(w, job);
        return;
    case GZP_UNLOCK_OP_CREATE:
    case GZP_UNLOCK_OP_RESTORE:
        break;
    default:
        set_result(&job->result, GZP_UNLOCK_NOT_CHECKED, "op");
        return;
    }
    /* Create and restore: the words, the seed, the passphrase's rules, then
     * the key file in memory. */
    seed = gz_sc_salloc(64);
    entropy = gz_sc_salloc(32);
    phrase = gz_sc_salloc(GZW_PHRASE_MAX);
    if (!seed || !entropy || !phrase) {
        set_result(&job->result, GZP_UNLOCK_NOT_CHECKED, NULL);
        goto out;
    }
    if (job->op == GZP_UNLOCK_OP_CREATE) {
        if (gz_sc_random(entropy, 32) != GZ_SC_OK || gzw_phrase_from_entropy(entropy, phrase) != 1) {
            set_result(&job->result, GZP_UNLOCK_STORAGE_FAILED, "random");
            goto out;
        }
        char *save = NULL, *t = strtok_r(phrase, " ", &save);
        for (size_t i = 0; i < GZP_UNLOCK_WORDS; i++, t = strtok_r(NULL, " ", &save))
            snprintf(job->words[i], GZP_UNLOCK_WORD_MAX, "%s", t ? t : "");
        if (gzw_phrase_from_entropy(entropy, phrase) != 1) { /* strtok cut it */
            set_result(&job->result, GZP_UNLOCK_STORAGE_FAILED, "words");
            goto out;
        }
    } else {
        uint32_t pos = 0;
        gzw_phrase_status ps;
        if (join_words(job->words, phrase, &pos) != 0) {
            set_result(&job->result, GZP_UNLOCK_BAD_WORDS, "position");
            job->result.position = pos;
            goto out;
        }
        ps = gzw_phrase_check(phrase);
        if (ps == GZW_PHRASE_ERR_UNKNOWN_WORD) {
            set_result(&job->result, GZP_UNLOCK_BAD_WORDS, "position");
            job->result.position = unknown_word(job->words);
            goto out;
        }
        if (ps != GZW_PHRASE_OK || words_entropy(job->words, entropy) != 0) {
            set_result(&job->result, GZP_UNLOCK_BAD_WORDS, "checksum");
            goto out;
        }
    }
    if (gzw_phrase_to_seed(phrase, "", seed) != 1) {
        set_result(&job->result, GZP_UNLOCK_STORAGE_FAILED, "seed");
        goto out;
    }
    {
        /* 4.1's rules that need the words (the wallet's name: none yet). */
        const char *wl[GZP_UNLOCK_WORDS];
        size_t n = strnlen((const char *)job->passphrase, job->passphrase_len);
        gz_sc_pass_rule_t rule;
        for (size_t i = 0; i < GZP_UNLOCK_WORDS; i++) wl[i] = job->words[i];
        rule = n != job->passphrase_len ? GZ_SC_PASS_NUL
                                        : gz_sc_pass_check(job->passphrase, job->passphrase_len, NULL, wl,
                                                           GZP_UNLOCK_WORDS);
        if (rule != GZ_SC_PASS_OK) {
            set_result(&job->result, GZP_UNLOCK_WEAK, weak_reason(rule));
            if (rule == GZ_SC_PASS_TOO_SHORT) {
                size_t cp = 0;
                for (size_t i = 0; i < job->passphrase_len; i++) cp += (job->passphrase[i] & 0xc0) != 0x80;
                job->result.length = (uint32_t)cp;
                job->result.minimum = GZ_SC_PASS_MIN_CP;
            }
            goto out;
        }
    }
    k->err = gz_sc_setup_prepare(&w->sc, job->passphrase, job->passphrase_len, &w->params, entropy, seed,
                                 job->op == GZP_UNLOCK_OP_RESTORE, &k->prep);
    k->have_prep = k->err == GZ_SC_OK;
    map_err(&job->result, k->err);
out:
    if (job->result.status != GZP_UNLOCK_OK && job->op == GZP_UNLOCK_OP_CREATE)
        OPENSSL_cleanse(job->words, sizeof job->words); /* never shown for a wallet not made */
    gz_sc_sfree(seed);
    gz_sc_sfree(entropy);
    gz_sc_sfree(phrase);
}

/* ---- finish and discard: the loop thread ------------------------------------------ */

static void free_keys(gzp_unlock_job_t *job)
{
    job_keys_t *k = job->keys;
    if (!k) return;
    gz_sc_unlocked_clear(&k->u);
    if (k->have_prep) gz_sc_prepared_clear(&k->prep);
    OPENSSL_cleanse(k, sizeof *k);
    free(k);
    job->keys = NULL;
}

/* Open the journal over the keys now held (store_journal.c) and keep it for
 * the executor. GZP_UNLOCK_OK, FILES_BEHIND or STORAGE_FAILED. */
static int open_storage(gzp_wallet_t *w, gzp_unlock_result_t *r)
{
    char err[200] = "";
    uint64_t inc = 0;
    int rc;
#ifdef GZP_TEST_BUILD
    if (w->restore_from[0]) {
        rc = gzp_journal_store_import(w->dir, w, w->restore_from, err, sizeof err);
        w->restore_from[0] = 0;
        if (rc != 0) {
            fprintf(stderr, "gazpacho: %s\n", err);
            set_result(r, GZP_UNLOCK_STORAGE_FAILED, "import");
            return r->status;
        }
    }
#endif
    if (gzp_journal_store_open(&w->opened, w->dir, w, err, sizeof err) != 0) {
        fprintf(stderr, "gazpacho: cannot open storage: %s\n", err);
        set_result(r, GZP_UNLOCK_STORAGE_FAILED, "journal");
        return r->status;
    }
    rc = w->opened.ops->begin(w->opened.ctx, &inc, err, sizeof err);
    if (rc != 0) {
        int behind = gzp_journal_store_behind(&w->opened);
        w->opened.ops->close(w->opened.ctx);
        if (behind) {
            /* local-api.md's cause: behind, or possibly old (storage 6.3). */
            set_result(r, GZP_UNLOCK_FILES_BEHIND, behind == 1 ? "behind" : "possibly_old");
        } else {
            fprintf(stderr, "gazpacho: cannot start storage: %s\n", err);
            set_result(r, GZP_UNLOCK_STORAGE_FAILED, "journal");
        }
        return r->status;
    }
    /* The first incarnation entry is durable: no longer a set-up that never
     * started. Removed before the node starts, so no key is ever used while
     * the marker could still say so. */
    if (setup_marker_clear(w) != 0) {
        w->opened.ops->close(w->opened.ctx);
        set_result(r, GZP_UNLOCK_STORAGE_FAILED, "setup_marker");
        return r->status;
    }
    w->have_opened = 1;
    return GZP_UNLOCK_OK;
}

void gzp_wallet_finish(gzp_wallet_t *w, gzp_unlock_job_t *job, int64_t now_ms)
{
    job_keys_t *k = job->keys;
    gz_sc_err_t e;
    gzp_unlock_result_t *r = &job->result;
    if (!k) {
        atomic_store(&w->deriving, 0);
        return;
    }
    if (r->status == GZP_UNLOCK_WRONG) {
        if (count_attempt(w, 1, now_ms, r) != 0) set_result(r, GZP_UNLOCK_STORAGE_FAILED, "attempts");
        else r->status = GZP_UNLOCK_WRONG;
        goto out;
    }
    if (r->status == GZP_UNLOCK_WORDS_DIFFER) {
        (void)count_attempt(w, 0, now_ms, NULL);
        goto out;
    }
    if (r->status != GZP_UNLOCK_OK) goto out;
    switch (k->op) {
    case GZP_UNLOCK_OP_CHECK: {
        /* The same wallet's passphrase: the key file it opened holds the
         * storage key in memory (storage 4.6: MSK compared in constant time;
         * the public ids alone can be forged, review B of PR 54, M1). */
        uint8_t c1[32], c2[32], v1[16], v2[16];
        int same = 0;
        if (w->unlocked && w->u.vault && k->u.vault) {
            gz_sc_vault_ids(w->u.vault, c1, v1);
            gz_sc_vault_ids(k->u.vault, c2, v2);
            same = !memcmp(c1, c2, 32) && !memcmp(v1, v2, 16) && gz_sc_vault_same(w->u.vault, k->u.vault);
        }
        if (!same) {
            set_result(r, GZP_UNLOCK_WRONG, NULL);
            if (count_attempt(w, 1, now_ms, r) != 0) set_result(r, GZP_UNLOCK_STORAGE_FAILED, "attempts");
        } else {
            (void)count_attempt(w, 0, now_ms, NULL);
        }
        goto out;
    }
    case GZP_UNLOCK_OP_UNLOCK:
    case GZP_UNLOCK_OP_START_AS_RESTORE:
        if (w->unlocked) gzp_wallet_lock(w);
#ifdef GZP_TEST_BUILD
        if (w->keys_only) { /* read only: the vault, nothing written */
            w->u = k->u;
            memset(&k->u, 0, sizeof k->u);
            w->unlocked = 1;
            goto out;
        }
#endif
        (void)count_attempt(w, 0, now_ms, NULL); /* the passphrase was right, whatever follows */
        w->u = k->u;
        memset(&k->u, 0, sizeof k->u);
        /* The set-up marker changes only what is told, never what is done
         * (review A of PR 54, H1: it is not authenticated). A key file with no
         * journal is 6.3 step 0's restore, with a new epoch, whatever it says;
         * beside it a missing start counter is told as an interrupted set-up. */
        w->setup_interrupted = k->op == GZP_UNLOCK_OP_UNLOCK && marker_present(w) &&
                               !file_exists(w, GZ_SC_FILE_JOURNAL) && !file_exists(w, GZ_SC_FILE_MARK);
        e = gz_sc_unlock_open(&w->sc, &w->u);
        if (e != GZ_SC_OK) {
            map_err(r, e);
            if (r->status == GZP_UNLOCK_OK || r->status == GZP_UNLOCK_WRONG)
                set_result(r, GZP_UNLOCK_STORAGE_FAILED, "journal_header");
            gzp_wallet_lock(w);
            goto out;
        }
        w->change_wide = w->u.restore || k->op == GZP_UNLOCK_OP_START_AS_RESTORE;
        if (k->op == GZP_UNLOCK_OP_START_AS_RESTORE && !w->u.restore) {
            uint64_t floor = 0;
            char err[200] = "";
            (void)gz_sc_counter_read(&w->sc, w->u.vault, &floor);
            if (gzp_journal_store_mark_restored(w->dir, w, floor, err, sizeof err) != 0) {
                fprintf(stderr, "gazpacho: %s\n", err);
                set_result(r, GZP_UNLOCK_STORAGE_FAILED, "restore");
                gzp_wallet_lock(w);
                goto out;
            }
        }
        w->unlocked = 1;
        if (open_storage(w, r) != GZP_UNLOCK_OK) gzp_wallet_lock(w);
        goto out;
    case GZP_UNLOCK_OP_REVEAL:
    case GZP_UNLOCK_OP_WORDS_CHECK:
        /* The passphrase was right (a WRONG went above): counted as such;
         * WORDS_DIFFER is the words' answer, not the passphrase's. */
        (void)count_attempt(w, 0, now_ms, NULL);
        goto out;
    case GZP_UNLOCK_OP_CREATE:
    case GZP_UNLOCK_OP_RESTORE:
        if (w->unlocked) gzp_wallet_lock(w);
        /* The attempts file first, clean: once the key file is in place a
         * missing one would refuse every unlock for 15 minutes (12.3). */
        if (count_attempt(w, 0, now_ms, NULL) != 0) {
            set_result(r, GZP_UNLOCK_STORAGE_FAILED, "attempts");
            goto out;
        }
        /* The set-up marker before the key file; a restore from the words
         * removes any stale one (its interrupted start stays a restore). */
        if ((k->op == GZP_UNLOCK_OP_CREATE ? setup_marker_write(w) : setup_marker_clear(w)) != 0) {
            set_result(r, GZP_UNLOCK_STORAGE_FAILED, "setup_marker");
            goto out;
        }
        e = gz_sc_setup_commit(&w->sc, &k->prep, &w->u);
        k->have_prep = 0;
        /* Refused before the key file (a file appeared meanwhile, L7): no
         * set-up of ours is here, so no marker either. */
        if (k->op == GZP_UNLOCK_OP_CREATE && (e == GZ_SC_EXISTS || e == GZ_SC_JOURNAL_HERE))
            (void)setup_marker_clear(w);
        if (e == GZ_SC_DONE_WITH_FAULT) {
            /* The wallet exists; the next unlock completes it (review B, L1). */
            set_result(r, GZP_UNLOCK_STORAGE_FAILED, "done_with_fault");
            gzp_wallet_lock(w);
            goto out;
        }
        if (e != GZ_SC_OK) {
            map_err(r, e);
            gzp_wallet_lock(w);
            goto out;
        }
        w->unlocked = 1;
        /* A new wallet has handed out no change: its mark, 0, is kept, so
         * only a missing file (lost, or a restore into a new folder) reads
         * the change chain wide. A restore from the words reads it wide. If
         * this write fails the next start reads wide: slower, never blind. */
        w->change_wide = k->op == GZP_UNLOCK_OP_RESTORE || w->u.restore;
        if (k->op == GZP_UNLOCK_OP_CREATE && gzp_wallet_change_mark_write(w, 0) != 0)
            gzp_log("wallet-change-mark-not-kept at set-up (the first start reads the change chain wide)");
        if (open_storage(w, r) != GZP_UNLOCK_OK) gzp_wallet_lock(w);
        goto out;
    default:
        break;
    }
out:
    free_keys(job);
    atomic_store(&w->deriving, 0);
}

void gzp_wallet_discard(gzp_wallet_t *w, gzp_unlock_job_t *job, int64_t now_ms)
{
    if (job->keys && job->result.status == GZP_UNLOCK_WRONG) (void)count_attempt(w, 1, now_ms, &job->result);
    if (job->op == GZP_UNLOCK_OP_CREATE) OPENSSL_cleanse(job->words, sizeof job->words);
    free_keys(job);
    atomic_store(&w->deriving, 0);
}

/* ---- the table -------------------------------------------------------------------- */

static gzp_wallet_state_t t_state(void *c) { return gzp_wallet_state(c); }
static void t_attempts(void *c, int64_t now, gzp_unlock_result_t *o) { gzp_wallet_attempts(c, now, o); }
static void t_begin(void *c, gzp_unlock_job_t *j) { gzp_wallet_begin(c, j); }
static void t_finish(void *c, gzp_unlock_job_t *j, int64_t now) { gzp_wallet_finish(c, j, now); }
static void t_discard(void *c, gzp_unlock_job_t *j, int64_t now) { gzp_wallet_discard(c, j, now); }
static void t_lock(void *c) { gzp_wallet_lock(c); }
static int t_seed(void *c, uint8_t out64[64]) { return gzp_wallet_seed(c, out64); }

gzp_unlock_t gzp_wallet_unlock_api(gzp_wallet_t *w)
{
    gzp_unlock_t t = {t_state, t_attempts, t_begin, t_finish, t_discard, t_lock, t_seed, w};
    return t;
}

/* ---- while unlocked ------------------------------------------------------------- */

int gzp_wallet_take_store(gzp_wallet_t *w, gzp_store_t *out)
{
    if (!w->unlocked || !w->have_opened) return -1;
    *out = w->opened;
    w->have_opened = 0;
    return 0;
}

int gzp_wallet_open_store(gzp_wallet_t *w, gzp_store_t *out, char *err, size_t errlen)
{
    if (!w->unlocked) {
        snprintf(err, errlen, "the wallet is locked");
        return -1;
    }
    return gzp_journal_store_open(out, w->dir, w, err, errlen);
}

int gzp_wallet_setup_interrupted(const gzp_wallet_t *w) { return w && w->setup_interrupted; }

int gzp_wallet_seed(gzp_wallet_t *w, uint8_t seed[64])
{
    if (!w->unlocked) return -1; /* out64 untouched */
#ifdef GZP_TEST_BUILD
    if (w->seed_fault) {
        OPENSSL_cleanse(seed, 64);
        return -2;
    }
#endif
    if (!w->u.vault || gz_sc_vault_seed(w->u.vault, seed) != GZ_SC_OK) {
        OPENSSL_cleanse(seed, 64);
        return -2;
    }
    return 0;
}

int gzp_wallet_transport_key(gzp_wallet_t *w, int (*valid)(const uint8_t key[32], void *ctx), void *ctx,
                             uint8_t out[32])
{
    char label[48];
    if (!w->unlocked || !w->u.vault) return -1;
    for (unsigned i = 0; i < 256; i++) {
        snprintf(label, sizeof label, "transport stand-in %u", i);
        if (gz_sc_vault_derive(w->u.vault, label, out) != GZ_SC_OK) break;
        if (!valid || valid(out, ctx)) return 0;
    }
    OPENSSL_cleanse(out, 32);
    return -1;
}

const gz_sc_store_t *gzp_wallet_sc_store(gzp_wallet_t *w) { return &w->sc; }
gz_sc_unlocked_t *gzp_wallet_sc_unlocked(gzp_wallet_t *w) { return w->unlocked ? &w->u : NULL; }

#ifdef GZP_TEST_BUILD
void gzp_wallet_test_kdf_floor(gzp_wallet_t *w)
{
    /* The storage library's test floor (the vectors' parameters), here and
     * in the helper this process starts (it reads GZP_TEST_KDF_FLOOR). */
    gz_sc_test_set_floor(1, 8);
    setenv("GZP_TEST_KDF_FLOOR", "1", 1);
    w->params.kdf = 1;
    w->params.t = 1;
    w->params.m_kib = 8;
    w->params.p = 1;
}

void gzp_wallet_test_keys_only(gzp_wallet_t *w) { w->keys_only = 1; }
void gzp_wallet_test_seed_fault(gzp_wallet_t *w, int on) { w->seed_fault = on; }

/* gazpacho-test (review B of PR 54, M1): keys.gzk replaced by a key file with
 * this wallet's chain and vault_id over another passphrase, MSK and seed, as
 * anyone who can write the folder can make one. */
int gzp_wallet_test_forge_keyfile(gzp_wallet_t *w, const uint8_t *pw, size_t len)
{
    uint8_t chain[32], vid[16], salt[16], pk[32], msk[32], ent[32], seed[64], kf[GZ_SC_KEYFILE_LEN];
    int ml = 0, rc = -1;
    if (!w->unlocked || !w->u.vault) return -1;
    gz_sc_vault_ids(w->u.vault, chain, vid);
    if (RAND_bytes(salt, 16) == 1 && RAND_bytes(msk, 32) == 1 && RAND_bytes(ent, 32) == 1 &&
        RAND_bytes(seed, 64) == 1 && w->sc.kdf(w->sc.kdf_ctx, pw, len, salt, &w->params, pk, &ml) == GZ_SC_OK &&
        gz_sc_keyfile_build(chain, vid, &w->params, salt, pk, msk, ent, seed, kf) == GZ_SC_OK)
        rc = gz_sc_fs_replace(&w->sc, GZ_SC_FILE_KEYS, kf, sizeof kf) == GZ_SC_OK ? 0 : -1;
    OPENSSL_cleanse(pk, sizeof pk);
    OPENSSL_cleanse(msk, sizeof msk);
    OPENSSL_cleanse(ent, sizeof ent);
    OPENSSL_cleanse(seed, sizeof seed);
    OPENSSL_cleanse(kf, sizeof kf);
    return rc;
}

void gzp_wallet_test_restore_from(gzp_wallet_t *w, const char *backup)
{
    snprintf(w->restore_from, sizeof w->restore_from, "%s", backup);
}
#endif

/* ---- the wallet port's change mark (M-3, review of PR 91) ------------------- */
#define GZP_CHANGE_MARK_FILE "change.gzm"

int gzp_wallet_change_mark_read(gzp_wallet_t *w, uint32_t *mark, int *wide)
{
    const gz_sc_store_t *s = gzp_wallet_sc_store(w);
    gz_sc_unlocked_t *u = gzp_wallet_sc_unlocked(w);
    uint8_t *data = NULL;
    size_t len = 0;
    uint64_t v = 0;
    gz_sc_err_t e;
    *mark = 0;
    *wide = w->change_wide;
    if (!s || !u || !u->vault) return -1;
    e = gz_sc_fs_read(s, GZP_CHANGE_MARK_FILE, GZ_SC_CHANGE_MARK_LEN, &data, &len);
    if (e == GZ_SC_MISSING) {
        *wide = 1;   /* lost, or a folder made by a restore: the mark may be anywhere */
        return 0;
    }
    if (e != GZ_SC_OK) return -1;
    e = gz_sc_change_mark_open(u->vault, data, len, &v);
    free(data);
    if (e != GZ_SC_OK || v > UINT32_MAX) return -1;
    *mark = (uint32_t)v;
    return 0;
}

int gzp_wallet_change_mark_write(gzp_wallet_t *w, uint32_t mark)
{
    const gz_sc_store_t *s = gzp_wallet_sc_store(w);
    gz_sc_unlocked_t *u = gzp_wallet_sc_unlocked(w);
    uint8_t out[GZ_SC_CHANGE_MARK_LEN];
    if (!s || !u || !u->vault || gz_sc_change_mark_seal(u->vault, mark, out) != GZ_SC_OK) return -1;
    /* DONE_WITH_FAULT: the folder sync failed and a power cut may bring the
     * old mark back, so it is not kept, and the index is not handed out */
    return gz_sc_fs_replace(s, GZP_CHANGE_MARK_FILE, out, sizeof out) == GZ_SC_OK ? 0 : -1;
}
