/* Shared helpers of the tree library (core/tree). Not a public header.
 *
 * Everything here is pure: no allocation, no I/O, no global state. The
 * library is checked by tools/check-core-isolation.sh like the rest of the
 * core. */
#ifndef GAZPACHO_TREE_INTERNAL_H
#define GAZPACHO_TREE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

/* SHA-256 (FIPS 180-4). Own implementation: the core may call nothing outside
 * itself. Checked against the FIPS vectors in tests/tree/test_tree_hash.c. */
typedef struct {
    uint32_t h[8];
    uint64_t n;          /* bytes written so far */
    uint8_t buf[64];
} tr_sha256_t;

void tr_sha256_init(tr_sha256_t *s);
void tr_sha256_write(tr_sha256_t *s, const uint8_t *data, size_t len);
void tr_sha256_done(tr_sha256_t *s, uint8_t out[32]);
/* BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || ...). `tag` is a
 * NUL-terminated ASCII string. */
void tr_tagged_init(tr_sha256_t *s, const char *tag);
void tr_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void tr_sha256d(const uint8_t *data, size_t len, uint8_t out[32]);

/* Big-endian and little-endian writers and readers. */
static inline void tr_be16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void tr_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static inline void tr_be64(uint8_t *p, uint64_t v) { tr_be32(p, (uint32_t)(v >> 32)); tr_be32(p + 4, (uint32_t)v); }
static inline void tr_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline void tr_le64(uint8_t *p, uint64_t v) { tr_le32(p, (uint32_t)v); tr_le32(p + 4, (uint32_t)(v >> 32)); }
static inline uint32_t tr_rd_be16(const uint8_t *p) { return (uint32_t)p[0] << 8 | p[1]; }
static inline uint32_t tr_rd_be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static inline uint64_t tr_rd_be64(const uint8_t *p) { return (uint64_t)tr_rd_be32(p) << 32 | tr_rd_be32(p + 4); }
static inline uint32_t tr_rd_le32(const uint8_t *p)
{
    return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0];
}
static inline uint64_t tr_rd_le64(const uint8_t *p) { return (uint64_t)tr_rd_le32(p + 4) << 32 | tr_rd_le32(p); }

/* terms.md 4.2's split rule over `levels` (shape.c). Walks the m members of
 * a node at depth d; writes each leaf's depth into depths[*k] (when depths is
 * not NULL) and advances *k. Returns 0 if a node at an interior depth would
 * hold m <= a members, or the walk would pass `max_depth`. */
int tr_split(const uint8_t *levels, size_t n_levels, uint32_t m, uint32_t d, uint8_t *depths,
             uint32_t *k, uint32_t max_depth);
/* The children of a node of m members at depth d: their sizes, in order.
 * Returns how many (0 for a one-member node under entry 3, which is a leaf;
 * 0 also for m <= a at a width a, which is invalid: tr_is_leaf tells them
 * apart). */
uint32_t tr_children(const uint8_t *levels, size_t n_levels, uint32_t m, uint32_t d, uint32_t sizes[16]);
static inline uint32_t tr_level(const uint8_t *levels, size_t n_levels, uint32_t d)
{
    return d < n_levels ? levels[d] : levels[n_levels - 1];
}

/* Comparison of public data (no secret ever passes here). */
static inline int tr_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

#endif
