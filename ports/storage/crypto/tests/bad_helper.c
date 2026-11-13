/* A KDF helper that fails (spec 8.4, test 14): GZ_SC_BAD=crash (the
 * default) aborts after reading the request; short answers 3 bytes and exits
 * 0; exit1 answers in full and exits 1; garbage answers status 9; hang never
 * answers; linger answers "ok" in full and then never exits (review A, L3). */
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    const char *mode = getenv("GZ_SC_BAD");
    unsigned char buf[64];
    if (read(0, buf, sizeof buf) < 0)
        return 3;
    if (!mode || strcmp(mode, "crash") == 0) {
        signal(SIGABRT, SIG_DFL);
        abort();
    }
    unsigned char ans[34];
    memset(ans, 0, sizeof ans);
    if (strcmp(mode, "hang") == 0) {
        for (;;)
            pause();
    }
    if (strcmp(mode, "short") == 0)
        return write(0, ans, 3) == 3 ? 0 : 2;
    if (strcmp(mode, "garbage") == 0) {
        ans[0] = 9;
        return write(0, ans, sizeof ans) == (ssize_t)sizeof ans ? 0 : 2;
    }
    if (write(0, ans, sizeof ans) < 0)
        return 2;
    if (strcmp(mode, "linger") == 0) {
        for (;;)
            pause();
    }
    return 1;
}
