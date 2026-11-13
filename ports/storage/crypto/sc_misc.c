/* The attempts file in mode 1 (spec 12.3) and the socket token folder (12.2). */
#define _GNU_SOURCE
#include "sc_internal.h"

#include <errno.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AT_MAGIC "GZTRIES1"
#define STRICT_S 900u

/* ---- attempts.gza ---------------------------------------------------------- */
static uint64_t sat_add(uint64_t a, uint64_t b)
{
    return a > UINT64_MAX - b ? UINT64_MAX : a + b;
}

/* The counter never falls, so it saturates instead of wrapping (L1). */
static void count_up(gz_sc_attempts_t *a)
{
    if (a->counter < UINT64_MAX)
        a->counter++;
}

void gz_sc_attempts_encode(const uint8_t chain[32], const gz_sc_attempts_t *a, uint8_t out[GZ_SC_ATTEMPTS_LEN])
{
    memcpy(out, AT_MAGIC, 8);
    memcpy(out + 8, chain, 32);
    sc_put64(out + 40, a->counter);
    sc_put32(out + 48, a->wrong_in_a_row);
    sc_put64(out + 52, a->last_wrong_s);
    sc_put64(out + 60, a->blocked_until_s);
    out[68] = 1; /* mode 1: Slice 1 has no KB (8.7.3) */
    uint8_t h[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(h, out, 69);
    memcpy(out + 69, h, 16);
}

int gz_sc_attempts_decode(const uint8_t chain[32], const uint8_t *data, size_t len, uint64_t now_s,
                          gz_sc_attempts_t *a)
{
    int ok = 0;
    if (data && len == GZ_SC_ATTEMPTS_LEN && memcmp(data, AT_MAGIC, 8) == 0 && memcmp(data + 8, chain, 32) == 0 &&
        data[68] == 1) {
        uint8_t h[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(h, data, 69);
        ok = sodium_memcmp(h, data + 69, 16) == 0;
    }
    /* A mode 2 file cannot be checked without KB: read as damaged. */
    if (!ok) {
        /* The strictest state: refused for 15 minutes from now. Nothing of a
         * file that failed its check is used, not even its counter (review B,
         * L2): unauthenticated bytes could pin it at its cap, and in mode 2 a
         * file below the store record would then never be caught as older.
         * Mode 1 has no store record, so the counter starts again from 0. */
        a->counter = 0;
        a->wrong_in_a_row = 0;
        a->last_wrong_s = 0;
        a->blocked_until_s = sat_add(now_s, STRICT_S);
        return 0;
    }
    a->counter = sc_get64(data + 40);
    a->wrong_in_a_row = sc_get32(data + 48);
    a->last_wrong_s = sc_get64(data + 52);
    a->blocked_until_s = sc_get64(data + 60);
    /* Mode 1's check is unkeyed, so anyone who can write the folder can write
     * a valid file. That writer is out of 12.3's reach, but capping costs
     * nothing (review A, L1): the strictest state a file can impose is the
     * strictest state itself, 15 minutes from now; no wrong attempt is in the
     * future. */
    if (a->blocked_until_s > sat_add(now_s, STRICT_S))
        a->blocked_until_s = sat_add(now_s, STRICT_S);
    if (a->last_wrong_s > now_s)
        a->last_wrong_s = now_s;
    return 1;
}

uint64_t gz_sc_attempts_wait(const gz_sc_attempts_t *a, uint64_t now_s)
{
    return a->blocked_until_s > now_s ? a->blocked_until_s - now_s : 0;
}

static uint64_t delay_after(uint32_t wrong)
{
    if (wrong <= 5)
        return 1;
    uint32_t k = wrong - 5; /* 2, 4, 8, ... seconds */
    if (k >= 10) /* 2^10 > 900 */
        return STRICT_S;
    return (uint64_t)1 << k;
}

void gz_sc_attempts_wrong(gz_sc_attempts_t *a, uint64_t now_s)
{
    if (a->wrong_in_a_row < UINT32_MAX)
        a->wrong_in_a_row++;
    a->last_wrong_s = now_s;
    a->blocked_until_s = sat_add(now_s, delay_after(a->wrong_in_a_row));
    count_up(a);
}

void gz_sc_attempts_right(gz_sc_attempts_t *a, uint64_t now_s)
{
    a->wrong_in_a_row = 0;
    a->blocked_until_s = sat_add(now_s, 1); /* one attempt a second, right or wrong */
    count_up(a);
}

/* ---- the socket token folder ------------------------------------------------- */
gz_sc_err_t gz_sc_token_dir(const char *data_dir, char *out, size_t cap)
{
    if (!data_dir || data_dir[0] != '/')
        return GZ_SC_ARG;
    uint8_t h[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(h, (const unsigned char *)data_dir, strlen(data_dir));
    char hex[17];
    sodium_bin2hex(hex, sizeof hex, h, 8);
    int n;
#if defined(__APPLE__)
    char tmp[1024];
    size_t tl = confstr(_CS_DARWIN_USER_TEMP_DIR, tmp, sizeof tmp);
    if (tl == 0 || tl > sizeof tmp || tmp[0] != '/')
        return GZ_SC_STORAGE_FAILED;
    n = snprintf(out, cap, "%s%sgazpacho-%s", tmp, tmp[tl - 2] == '/' ? "" : "/", hex);
#else
    const char *run = getenv("XDG_RUNTIME_DIR");
    /* Unset, empty or relative: a process with no login session. */
    if (run && run[0] == '/')
        n = snprintf(out, cap, "%s/gazpacho-%s", run, hex);
    else
        n = snprintf(out, cap, "/tmp/gazpacho-%lu-%s", (unsigned long)getuid(), hex);
#endif
    if (n < 0 || (size_t)n >= cap)
        return GZ_SC_BUFFER;
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_token_dir_make(const char *path)
{
    if (mkdir(path, 0700) == 0) {
        if (chmod(path, 0700) != 0) /* whatever the umask */
            return GZ_SC_STORAGE_FAILED;
    } else if (errno != EEXIST) {
        return GZ_SC_STORAGE_FAILED;
    }
    struct stat st;
    if (lstat(path, &st) != 0)
        return GZ_SC_STORAGE_FAILED;
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 07777) != 0700)
        return GZ_SC_UNSAFE_PATH;
    return GZ_SC_OK;
}
