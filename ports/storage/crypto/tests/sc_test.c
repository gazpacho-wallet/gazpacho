#include "sc_test.h"

#include <sodium.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

int sc_failures;

const uint8_t SIGNET[32] = {0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63,
                            0xaf, 0x32, 0xb2, 0xbb, 0xc9, 0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c,
                            0x42, 0x25, 0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00};
uint8_t SEED64[64];

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

size_t hx(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    int hi = -1;
    for (const char *p = hex; *p; p++) {
        if (*p == ' ' || *p == '\n')
            continue;
        int v = hexval(*p);
        if (v < 0 || (hi < 0 && n == cap)) {
            fprintf(stderr, "bad hex constant\n");
            abort();
        }
        if (hi < 0) {
            hi = v;
        } else {
            out[n++] = (uint8_t)(hi << 4 | v);
            hi = -1;
        }
    }
    if (hi >= 0)
        abort();
    return n;
}

int eq_hex(const char *what, const uint8_t *b, size_t n, const char *hex)
{
    uint8_t *want = malloc(n + 1);
    size_t wn = hx(hex, want, n + 1);
    int ok = wn == n && memcmp(want, b, n) == 0;
    if (!ok) {
        fprintf(stderr, "MISMATCH %s (%zu bytes, expected %zu)\n  got  ", what, n, wn);
        for (size_t i = 0; i < n; i++)
            fprintf(stderr, "%02x", b[i]);
        fprintf(stderr, "\n  want %s\n", hex);
        sc_failures++;
    }
    free(want);
    return ok;
}

void tv(const char *label, uint8_t *out, size_t n)
{
    uint8_t h[32];
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, (const unsigned char *)"gazpacho test ", 14);
    crypto_hash_sha256_update(&st, (const unsigned char *)label, strlen(label));
    crypto_hash_sha256_final(&st, h);
    memcpy(out, h, n);
}

/* ---- the random hook ---- */
#define QMAX 16
static const char *queue[QMAX];
static int q_n, q_i, fixed_on, fail_at, calls;
static uint8_t fixed_r[32];

static int hook(void *ctx, uint8_t *out, size_t n)
{
    (void)ctx;
    calls++;
    if (fail_at && calls >= fail_at)
        return -1;
    if (fixed_on) {
        if (n != 32)
            return getrandom(out, n, 0) == (ssize_t)n ? 0 : -1;
        memcpy(out, fixed_r, 32);
        return 0;
    }
    if (q_i < q_n) {
        if (n != 32) {
            fprintf(stderr, "r queue: a draw of %zu bytes\n", n);
            sc_failures++;
            return -1;
        }
        char label[128];
        snprintf(label, sizeof label, "r: %s", queue[q_i++]);
        tv(label, out, 32);
        return 0;
    }
    return getrandom(out, n, 0) == (ssize_t)n ? 0 : -1;
}

void r_queue(const char *first, ...)
{
    va_list ap;
    q_n = q_i = 0;
    va_start(ap, first);
    for (const char *s = first; s && q_n < QMAX; s = va_arg(ap, const char *))
        queue[q_n++] = s;
    va_end(ap);
    fixed_on = 0;
    gz_sc_test_set_random(hook, NULL);
}

int r_left(void)
{
    return q_n - q_i;
}

void r_fixed(const uint8_t *r32)
{
    fixed_on = r32 != NULL;
    if (r32)
        memcpy(fixed_r, r32, 32);
    gz_sc_test_set_random(hook, NULL);
}

void r_fail_after(int n)
{
    fail_at = n;
    calls = 0;
    gz_sc_test_set_random(hook, NULL);
}

void r_os(void)
{
    q_n = q_i = fixed_on = fail_at = 0;
    gz_sc_test_set_random(NULL, NULL);
}

void sc_test_init(void)
{
    if (gz_sc_init() != GZ_SC_OK) {
        fprintf(stderr, "gz_sc_init failed: libsodium is not %s\n", "1.0.22");
        exit(1);
    }
    gz_sc_test_set_floor(1, 8);
    crypto_hash_sha512(SEED64, (const unsigned char *)"gazpacho test bip39 seed", 24);
}

int sc_test_done(const char *name)
{
    if (sc_failures) {
        fprintf(stderr, "%s: %d failure(s)\n", name, sc_failures);
        return 1;
    }
    printf("%s: all passed\n", name);
    return 0;
}
