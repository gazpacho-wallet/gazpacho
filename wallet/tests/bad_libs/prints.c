/* Negative test for check_no_io.py: a "library" that prints.  With the usual
   hardening flags the compiler turns fprintf into __fprintf_chk, a name a
   deny-list of ordinary function names does not contain. */
#include <stdio.h>

void gzw_bad_prints(const unsigned char *key, int n);
void gzw_bad_prints(const unsigned char *key, int n) {
    for (int i = 0; i < n; i++) fprintf(stderr, "%02x", (unsigned)key[i]);
}
