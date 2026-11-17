/* SPDX-License-Identifier: MIT */
/* TEST ONLY: a stand-in for the passphrase layer (unlock.h) until encrypted
 * storage is wired into the program (branch s5-s6-program). Compiled into
 * gazpacho-test only; the release program uses unlock_none.c.
 *
 * It is NOT key protection. It keeps, in the data folder's owner-only file
 * `unlock.standin`, a random salt and SHA-256(salt || passphrase), and
 * compares. The 24 words are those of the wallet's stand-in seed file
 * (`wallet-seed.standin`, as main.c reads it); restore checks the words'
 * checksum and nothing else. Nothing it handles is logged, and every buffer
 * that held the passphrase, the words or the seed is wiped. The attempts
 * limit is the API server's own (attempts.gza, local-api.md 4.3), so
 * `attempts` here always answers OK. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "gazpacho/wallet_keys.h"
#include "gzp.h"
#include "unlock.h"
#include "unlock_impl.h"

#define FILE_NAME "unlock.standin"

typedef struct {
    gzp_datadir_t *dir;
    int unlocked;
} standin_t;

static standin_t g_standin;

typedef struct {
    int have;                 /* the file exists and reads */
    uint8_t salt[16], hash[32];
} record_t;

static int read_record(standin_t *s, record_t *r)
{
    char path[GZP_PATH_MAX];
    uint8_t b[48];
    int fd;
    ssize_t n;
    memset(r, 0, sizeof *r);
    if (gzp_datadir_path(s->dir, FILE_NAME, path) != 0) return -1;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    n = read(fd, b, sizeof b);
    close(fd);
    if (n != (ssize_t)sizeof b) return -1;
    memcpy(r->salt, b, 16);
    memcpy(r->hash, b + 16, 32);
    r->have = 1;
    return 0;
}

static void hash_pass(const uint8_t salt[16], const uint8_t *p, size_t n, uint8_t out[32])
{
    static const char tag[] = "gazpacho unlock stand-in, test only";
    size_t len = sizeof tag - 1 + 16 + n;
    uint8_t *b = malloc(len);
    if (!b) abort();
    memcpy(b, tag, sizeof tag - 1);
    memcpy(b + sizeof tag - 1, salt, 16);
    memcpy(b + sizeof tag - 1 + 16, p, n);
    SHA256(b, len, out);
    OPENSSL_cleanse(b, len);
    free(b);
}

static int write_record(standin_t *s, const uint8_t salt[16], const uint8_t hash[32])
{
    char path[GZP_PATH_MAX], tmp[GZP_PATH_MAX + 8];
    uint8_t b[48];
    int fd, ok;
    if (gzp_datadir_path(s->dir, FILE_NAME, path) != 0) return -1;
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    memcpy(b, salt, 16);
    memcpy(b + 16, hash, 32);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    ok = write(fd, b, sizeof b) == (ssize_t)sizeof b && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    if (!ok || rename(tmp, path) != 0) return -1;
    return gzp_datadir_sync(s->dir);
}

/* The 24 words of the stand-in seed, into job->words. */
static int seed_words(standin_t *s, char words[GZP_UNLOCK_WORDS][GZP_UNLOCK_WORD_MAX])
{
    uint8_t entropy[32];
    char phrase[GZW_PHRASE_MAX], *w, *save = NULL;
    int i = 0;
    if (gzp_datadir_secret(s->dir, "wallet-seed.standin", entropy, NULL, NULL) != 0) return -1;
    if (gzw_phrase_from_entropy(entropy, phrase) != 1) {
        gzw_wipe(entropy, sizeof entropy);
        return -1;
    }
    gzw_wipe(entropy, sizeof entropy);
    for (w = strtok_r(phrase, " ", &save); w && i < GZP_UNLOCK_WORDS; w = strtok_r(NULL, " ", &save), i++)
        snprintf(words[i], GZP_UNLOCK_WORD_MAX, "%s", w);
    gzw_wipe(phrase, sizeof phrase);
    return i == GZP_UNLOCK_WORDS ? 0 : -1;
}

static size_t code_points(const uint8_t *p, size_t n)
{
    size_t i, c = 0;
    for (i = 0; i < n; i++)
        if ((p[i] & 0xc0) != 0x80) c++;
    return c;
}

static gzp_wallet_state_t st_state(void *ctx)
{
    standin_t *s = ctx;
    record_t r;
    if (read_record(s, &r) != 0 || !r.have) return GZP_WALLET_NONE;
    return s->unlocked ? GZP_WALLET_UNLOCKED : GZP_WALLET_LOCKED;
}

static void st_attempts(void *ctx, int64_t now_ms, gzp_unlock_result_t *out)
{
    (void)ctx;
    (void)now_ms;
    memset(out, 0, sizeof *out);
    out->status = GZP_UNLOCK_OK;
}

/* Derivation thread: reads only. */
static void st_begin(void *ctx, gzp_unlock_job_t *job)
{
    standin_t *s = ctx;
    record_t r;
    uint8_t h[32];
    int i, exists;
    memset(&job->result, 0, sizeof job->result);
    exists = read_record(s, &r) == 0 && r.have;
    switch (job->op) {
    case GZP_UNLOCK_OP_CREATE:
    case GZP_UNLOCK_OP_RESTORE:
        if (exists) { job->result.status = GZP_UNLOCK_EXISTS; return; }
        if (code_points(job->passphrase, job->passphrase_len) < 15) {
            job->result.status = GZP_UNLOCK_WEAK;
            job->result.reason = "too_short";
            job->result.length = (uint32_t)code_points(job->passphrase, job->passphrase_len);
            job->result.minimum = 15;
            return;
        }
        if (job->op == GZP_UNLOCK_OP_RESTORE) {
            char phrase[GZW_PHRASE_MAX];
            size_t at = 0;
            phrase[0] = 0;
            for (i = 0; i < GZP_UNLOCK_WORDS; i++)
                at += (size_t)snprintf(phrase + at, sizeof phrase - at, "%s%s", i ? " " : "", job->words[i]);
            if (gzw_phrase_check(phrase) != GZW_PHRASE_OK) {
                job->result.status = GZP_UNLOCK_BAD_WORDS;
                job->result.reason = "checksum";
            }
            gzw_wipe(phrase, sizeof phrase);
            if (job->result.status) return;
        } else if (seed_words(s, job->words) != 0) {
            job->result.status = GZP_UNLOCK_STORAGE_FAILED;
            job->result.reason = "seed";
            return;
        }
        job->result.status = GZP_UNLOCK_OK;
        return;
    default:
        break;
    }
    if (!exists) { job->result.status = GZP_UNLOCK_NO_WALLET; return; }
    hash_pass(r.salt, job->passphrase, job->passphrase_len, h);
    if (CRYPTO_memcmp(h, r.hash, 32) != 0) {
        OPENSSL_cleanse(h, sizeof h);
        job->result.status = GZP_UNLOCK_WRONG;
        return;
    }
    OPENSSL_cleanse(h, sizeof h);
    job->result.status = GZP_UNLOCK_OK;
    if (job->op == GZP_UNLOCK_OP_REVEAL) {
        if (seed_words(s, job->words) != 0) job->result.status = GZP_UNLOCK_STORAGE_FAILED;
    } else if (job->op == GZP_UNLOCK_OP_WORDS_CHECK) {
        char all[GZP_UNLOCK_WORDS][GZP_UNLOCK_WORD_MAX];
        if (seed_words(s, all) != 0) {
            job->result.status = GZP_UNLOCK_STORAGE_FAILED;
        } else {
            for (i = 0; i < 3; i++) {
                int p = job->positions[i];
                if (p < 1 || p > GZP_UNLOCK_WORDS || strcmp(job->words[i], all[p - 1]) != 0)
                    job->result.status = GZP_UNLOCK_WORDS_DIFFER;
            }
        }
        OPENSSL_cleanse(all, sizeof all);
    }
}

/* Loop thread: install. */
static void st_finish(void *ctx, gzp_unlock_job_t *job, int64_t now_ms)
{
    standin_t *s = ctx;
    (void)now_ms;
    if (job->result.status != GZP_UNLOCK_OK) return;
    if (job->op == GZP_UNLOCK_OP_CREATE || job->op == GZP_UNLOCK_OP_RESTORE) {
        uint8_t salt[16], h[32];
        gzp_os_random(salt, sizeof salt);
        hash_pass(salt, job->passphrase, job->passphrase_len, h);
        if (write_record(s, salt, h) != 0) {
            job->result.status = GZP_UNLOCK_STORAGE_FAILED;
            job->result.reason = "write";
        } else {
            s->unlocked = 1;
        }
        OPENSSL_cleanse(h, sizeof h);
        return;
    }
    if (job->op == GZP_UNLOCK_OP_UNLOCK || job->op == GZP_UNLOCK_OP_CHECK) s->unlocked = 1;
}

static void st_discard(void *ctx, gzp_unlock_job_t *job, int64_t now_ms)
{
    (void)ctx;
    (void)now_ms;
    OPENSSL_cleanse(job->words, sizeof job->words);
}

static void st_lock(void *ctx)
{
    standin_t *s = ctx;
    s->unlocked = 0;
}

void gzp_unlock_impl(gzp_unlock_t *u, gzp_datadir_t *dir)
{
    memset(&g_standin, 0, sizeof g_standin);
    g_standin.dir = dir;
    u->state = st_state;
    u->attempts = st_attempts;
    u->begin = st_begin;
    u->finish = st_finish;
    u->discard = st_discard;
    u->lock = st_lock;
    u->ctx = &g_standin;
    gzp_log("unlock stand-in: TEST ONLY, not key protection (unlock.standin)");
}
