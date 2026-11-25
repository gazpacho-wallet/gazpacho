/* wallet/src/bip32.c for the signer's constant-time test: the same code, with
 * its declassify hook set to valgrind's, so that a key's validity, which is
 * public, may be branched on and nothing else (review B of #71, M3). */
#include <valgrind/memcheck.h>
#define GZW_DECLASSIFY(p, n) VALGRIND_MAKE_MEM_DEFINED(p, n)
#include "../../wallet/src/bip32.c"
