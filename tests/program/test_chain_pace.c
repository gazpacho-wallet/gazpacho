/* SPDX-License-Identifier: MIT */
/* The program's pace for each chain server (program/pchain.c, gzp_chain_pacer): one pacer per
 * server, whichever client asks for it (the chain worker's, the loop's lookups, the wallet's
 * scan), so that together they keep one pace per server. A public server is asked at most once
 * every two seconds; the local test chain and a server on this machine get none: each client keeps its
 * own pace, as before (signet run 2's preparation:
 * mempool.space answered nothing for minutes after about 33 requests at four a second). */
#include <stdio.h>
#include <string.h>

#include "pchain.h"

static int failures, checks;
#define CHECK(c)                                                                         \
    do {                                                                                 \
        checks++;                                                                        \
        if (!(c)) {                                                                      \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c);       \
            failures++;                                                                  \
        }                                                                                \
    } while (0)

int main(void)
{
    char again[64];
    gz_esplora_pacer *a = gzp_chain_pacer("https://mempool.space/signet/api", 0);
    gz_esplora_pacer *b = gzp_chain_pacer("https://blockstream.info/signet/api", 0);
    gz_esplora_pacer *c = gzp_chain_pacer("http://127.0.0.1:18443", 1);
    snprintf(again, sizeof again, "%s", "https://mempool.space/signet/api");
    CHECK(a != NULL && b != NULL && a != b);
    CHECK(gzp_chain_pacer(again, 0) == a);                 /* the same server: the same pace */
    CHECK(a && a->interval_ms == 2000 && b && b->interval_ms == 2000);
    CHECK(c == NULL);                                       /* the local test chain */
    CHECK(gzp_chain_pacer("http://127.0.0.1:3002", 0) == NULL);   /* a server on this machine, any network */
    CHECK(gzp_chain_pacer(NULL, 0) == NULL);
    printf("program_chain_pace: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
