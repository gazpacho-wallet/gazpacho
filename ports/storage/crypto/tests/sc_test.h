/* Shared by the storage tests: checks, hex, the spec's test values. */
#ifndef GAZPACHO_SC_TEST_H
#define GAZPACHO_SC_TEST_H

#include "gz_storage_crypto.h"
#include "gz_storage_crypto_test.h"
#include "gz_storage_files.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int sc_failures;
#define CHECK(c)                                                                         \
    do {                                                                                 \
        if (!(c)) {                                                                      \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c);        \
            sc_failures++;                                                               \
        }                                                                                \
    } while (0)
#define CHECK_ERR(got, want)                                                             \
    do {                                                                                 \
        gz_sc_err_t g_ = (got), w_ = (want);                                             \
        if (g_ != w_) {                                                                  \
            fprintf(stderr, "%s:%d: %s gave %s, expected %s\n", __FILE__, __LINE__, #got, \
                    gz_sc_err_text(g_), gz_sc_err_text(w_));                             \
            sc_failures++;                                                               \
        }                                                                                \
    } while (0)

/* Hex to bytes; aborts on a malformed constant. Returns the length. */
size_t hx(const char *hex, uint8_t *out, size_t cap);
/* Compare bytes with a hex constant (whitespace ignored); prints both on a miss. */
int eq_hex(const char *what, const uint8_t *b, size_t n, const char *hex);
/* tv(label) = sha256("gazpacho test " + label)[0:n] (spec 15). */
void tv(const char *label, uint8_t *out, size_t n);
/* Signet's chain hash (internal byte order). */
extern const uint8_t SIGNET[32];
extern uint8_t SEED64[64]; /* sha512("gazpacho test bip39 seed") */
void sc_test_init(void);   /* gz_sc_init, test floor (1, 8), SEED64 */

/* Queue the nonce inputs r = tv("r: " + label) for the next seals, in order.
 * A seal beyond the queue fails the test. NULL ends the list. */
void r_queue(const char *first, ...);
int r_left(void);
/* Fixed r for every seal (hedging test 7); NULL: the queue again. */
void r_fixed(const uint8_t *r32);
/* Make the random source fail from the n-th call (0: never). */
void r_fail_after(int n);
/* Back to the operating system's source. */
void r_os(void);

int sc_test_done(const char *name);

#endif
