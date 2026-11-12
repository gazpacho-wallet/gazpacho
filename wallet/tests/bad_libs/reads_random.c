/* Negative test for check_no_io.py: a "library" that reads randomness itself. */
#include <sys/random.h>

int gzw_bad_reads_random(unsigned char *out, unsigned long n);
int gzw_bad_reads_random(unsigned char *out, unsigned long n) {
    return getrandom(out, n, 0) == (long)n;
}
