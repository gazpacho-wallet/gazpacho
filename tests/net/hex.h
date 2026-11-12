/* Hex helpers for the transport tests. */
#ifndef GAZPACHO_TEST_HEX_H
#define GAZPACHO_TEST_HEX_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Decodes hex (optional 0x, spaces ignored) into out; returns the length, or
 * (size_t)-1 on bad input or overflow. */
static inline size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    int hi = -1;
    if (s[0] == '0' && s[1] == 'x') s += 2;
    for (; *s; s++) {
        int v;
        if (*s == ' ') continue;
        if (*s >= '0' && *s <= '9') v = *s - '0';
        else if (*s >= 'a' && *s <= 'f') v = *s - 'a' + 10;
        else return (size_t)-1;
        if (hi < 0) { hi = v; continue; }
        if (n == cap) return (size_t)-1;
        out[n++] = (uint8_t)(hi << 4 | v);
        hi = -1;
    }
    return hi < 0 ? n : (size_t)-1;
}

/* 1 if p[0..n) equals the hex string exactly (same length, same bytes). */
static inline int eqhex(const uint8_t *p, size_t n, const char *hex)
{
    uint8_t b[256];
    size_t m = unhex(hex, b, sizeof b);
    return m == n && memcmp(p, b, n) == 0;
}

static inline int all_zero(const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    for (i = 0; i < n; i++)
        if (b[i]) return 0;
    return 1;
}

#endif
