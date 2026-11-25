/* SPDX-License-Identifier: MIT */
/* wallet/src/bip32.c for the key port's constant-time check (ct_keys): the
 * same code, with its declassify hook set to valgrind's, so that only what is
 * public once computed (a key's validity, a public key) may be branched on.
 * As signer/tests/ctime_bip32.c does for the signer's test (#71). */
#include <valgrind/memcheck.h>
#define GZW_DECLASSIFY(p, n) VALGRIND_MAKE_MEM_DEFINED(p, n)
#include "../../wallet/src/bip32.c"
