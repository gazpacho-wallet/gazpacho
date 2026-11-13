/* The test entry point of the storage layer (spec 4.2, review F24).
 *
 * Only the test library (gazpacho_storage_crypto_test, built with
 * GZ_SC_TEST_ENTRY) has these functions. The release library has none of
 * them: a release program refuses E2's key file (test 29) and never runs
 * Argon2id in its own process. */
#ifndef GAZPACHO_STORAGE_CRYPTO_TEST_H
#define GAZPACHO_STORAGE_CRYPTO_TEST_H

#include <stddef.h>
#include <stdint.h>

#ifndef GZ_SC_TEST_ENTRY
#error "gz_storage_crypto_test.h is for test builds only"
#endif

/* Replace the storage random source: fn fills out[0..n) and returns 0, or
 * returns -1 for a failure. NULL restores the operating system's source. */
void gz_sc_test_set_random(int (*fn)(void *ctx, uint8_t *out, size_t n), void *ctx);
/* Lower the parameter floor (vectors use t >= 1, m >= 8 KiB). (3, 65536)
 * restores the release floor. */
void gz_sc_test_set_floor(uint32_t t_min, uint32_t m_kib_min);
/* Pretend the machine has this much physical memory (0: the real amount). */
void gz_sc_test_set_phys(uint64_t bytes);
/* The KDF helper's deadline in milliseconds instead of the one computed from
 * the parameters (0: that one again). */
void gz_sc_test_set_helper_timeout(int64_t ms);
/* Argon2id in this process: tests only (8.3 forbids it in the program). */
gz_sc_err_t gz_sc_test_kdf_inprocess(void *ctx, const uint8_t *pw, size_t pw_len, const uint8_t salt[16],
                                     const gz_sc_kdf_params_t *params, uint8_t pk[32], int *mem_locked);

#endif
