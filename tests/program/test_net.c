/* SPDX-License-Identifier: MIT */
/* The network adapter's reading of the placeholder's carrier (program/net.c,
 * gzp_net_record1): record 1 of a TLV stream, and nothing past the stream's
 * end when a record's length is malformed (review B of PR 27, B7: B36). Each
 * stream is copied into a heap block of exactly its length, so a read past
 * the end is also an AddressSanitizer report. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"

static int failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

/* record1 of `s` (len bytes): 1 and the record if found, 0 if NULL. */
static int rec1(const uint8_t *s, size_t len, uint8_t *out, size_t *out_len)
{
    uint8_t *b = malloc(len ? len : 1);
    const uint8_t *r;
    size_t rl = 0;
    if (!b) abort();
    if (len) memcpy(b, s, len);
    r = gzp_net_record1(b, len, &rl);
    if (r) {
        CHECK(r >= b && rl <= len && (size_t)(r - b) <= len - rl);
        memcpy(out, r, rl);
        *out_len = rl;
    }
    free(b);
    return r != NULL;
}

int main(void)
{
    uint8_t out[64];
    size_t ol = 0;
    static const uint8_t one[] = {1, 3, 'a', 'b', 'c'};
    static const uint8_t two[] = {3, 2, 'x', 'x', 1, 1, 'y'};
    static const uint8_t empty1[] = {1, 0};
    static const uint8_t none[] = {3, 1, 'z'};
    static const uint8_t long1[] = {1, 5, 'a', 'b', 'c'};       /* says 5, has 3 */
    static const uint8_t long3[] = {3, 10, 'a', 'b', 1, 1, 'y'}; /* an earlier record runs past the end */
    static const uint8_t cut_len[] = {1};                        /* a type with no length */
    static const uint8_t big_len[] = {1, 0xfd, 0x01};            /* a bigsize cut short */

    CHECK(rec1(one, sizeof one, out, &ol) && ol == 3 && !memcmp(out, "abc", 3));
    CHECK(rec1(two, sizeof two, out, &ol) && ol == 1 && out[0] == 'y');
    CHECK(rec1(empty1, sizeof empty1, out, &ol) && ol == 0);
    CHECK(!rec1(none, sizeof none, out, &ol));
    CHECK(!rec1(NULL, 0, out, &ol));
    CHECK(!rec1(long1, sizeof long1, out, &ol));
    CHECK(!rec1(long3, sizeof long3, out, &ol));
    CHECK(!rec1(cut_len, sizeof cut_len, out, &ol));
    CHECK(!rec1(big_len, sizeof big_len, out, &ol));

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("net: all checks passed\n");
    return 0;
}
