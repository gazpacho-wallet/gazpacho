/* SPDX-License-Identifier: MIT */
/* The chain adapter's lookups while its worker runs (docs/notes/integration.md
 * B11): gzp_chain_open starts the worker, which polls the tip every few
 * milliseconds, and this thread, as the loop would, asks for a script's
 * outputs again and again. Built with ThreadSanitizer by
 * tools/pchain-tsan.sh and run against a local Esplora stub by
 * tests/program/pchain_threads.py: any data race between the two threads, on
 * a backend or on the transport, stops it with a report.
 *
 *   test_pchain_threads URL ROUNDS */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gzp.h"
#include "pchain.h"

/* The program's output lines (options.c), here plain. */
void gzp_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    gzp_chain_t c;
    const char *urls[1];
    uint8_t script[34];
    int rounds, i, failed = 0;
    if (argc != 3) {
        fprintf(stderr, "usage: test_pchain_threads URL ROUNDS\n");
        return 2;
    }
    urls[0] = argv[1];
    rounds = atoi(argv[2]);
    if (gzp_chain_open(&c, urls, NULL, 1, GZ_NET_SIGNET, 5, NULL) != 0) {
        fprintf(stderr, "FAIL: the chain did not open\n");
        return 1;
    }
    memset(script, 0x5a, sizeof script);
    script[0] = 0x51; /* a P2TR output script: OP_1 PUSH32 */
    script[1] = 0x20;
    for (i = 0; i < rounds; i++)
        if (gzp_chain_show_outputs(&c, script, sizeof script) != 0) failed++;
    gzp_chain_close(&c);
    if (failed) {
        fprintf(stderr, "FAIL: %d of %d lookups failed\n", failed, rounds);
        return 1;
    }
    printf("lookups=%d\n", rounds);
    return 0;
}
