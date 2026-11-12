/* Negative test for check_no_io.py: a "library" that reads the clock. */
#include <time.h>

long gzw_bad_reads_clock(void);
long gzw_bad_reads_clock(void) {
    struct timespec ts;
    if (!timespec_get(&ts, TIME_UTC)) return 0;
    return (long)ts.tv_sec;
}
