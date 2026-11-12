/* Plain driver for the fuzz target in fuzz_tx_parse.c, used when the build
 * is not linked with libFuzzer.  usage: fuzz_tx_parse [ROUNDS]
 * ROUNDS is a decimal number from 1 to 100000000 (default 200000); anything
 * else is refused (exit 2), so that a libFuzzer-style argument cannot make
 * it run zero rounds and pass.  It mutates the two official BIP 341
 * transactions with a fixed seed and requires that the mutations reach the
 * accepting paths, not only the refusals. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/wallet_tx.h"
#include "tx_vectors_data.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint64_t s = 0x243f6a8885a308d3u;
static uint64_t rnd(void) {
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    return s;
}

static size_t unhex(const char *h, uint8_t *out) {
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) exit(2);
        out[i] = (uint8_t)v;
    }
    return n;
}

static gzt_tx parsed;
static unsigned long accepted = 0;

static void one(const uint8_t *data, size_t size) {
    if (gzt_tx_parse(data, size, &parsed) == GZT_OK) accepted++;
    LLVMFuzzerTestOneInput(data, size);
}

int main(int argc, char **argv) {
    static uint8_t seeds[2][4096], buf[8192];
    size_t seed_len[2];
    unsigned long rounds = 200000;
    if (argc > 2) {
        fprintf(stderr, "usage: fuzz_tx_parse [ROUNDS]\n");
        return 2;
    }
    if (argc == 2) {
        char *end;
        const char *a = argv[1];
        if (*a < '0' || *a > '9') {
            fprintf(stderr, "fuzz_tx_parse: ROUNDS must be a number, not \"%s\"\n", a);
            return 2;
        }
        rounds = strtoul(a, &end, 10);
        if (*end || rounds == 0 || rounds > 100000000) {
            fprintf(stderr, "fuzz_tx_parse: ROUNDS must be 1 to 100000000, not \"%s\"\n", a);
            return 2;
        }
    }
    seed_len[0] = unhex(BIP341_UNSIGNED, seeds[0]);
    seed_len[1] = unhex(BIP341_SIGNED, seeds[1]);
    for (unsigned long r = 0; r < rounds; r++) {
        int k = (int)(rnd() & 1);
        size_t n = seed_len[k];
        memcpy(buf, seeds[k], n);
        int edits = 1 + (int)(rnd() % 4);
        for (int e = 0; e < edits; e++) {
            size_t at = n ? rnd() % n : 0;
            switch (rnd() % 6) {
            case 0: buf[at] ^= (uint8_t)(1u << (rnd() % 8)); break;           /* flip a bit */
            case 1: buf[at] = (uint8_t)rnd(); break;                          /* new byte */
            case 2: if (n) n = at; break;                                     /* truncate */
            case 3: if (n < sizeof buf - 1) {                                 /* insert */
                        memmove(buf + at + 1, buf + at, n - at); buf[at] = (uint8_t)rnd(); n++;
                    } break;
            case 4: if (n) { memmove(buf + at, buf + at + 1, n - at - 1); n--; } break; /* delete */
            case 5: buf[at] = (uint8_t[]){0x00, 0x01, 0xfd, 0xfe, 0xff}[rnd() % 5]; break;
            }
        }
        one(buf, n);
    }
    /* the seeds themselves must be accepted */
    unsigned long before = accepted;
    one(seeds[0], seed_len[0]);
    one(seeds[1], seed_len[1]);
    printf("fuzz_tx_parse: %lu inputs, %lu accepted by the parser, properties held\n",
           rounds, accepted);
    /* and the mutations must reach the accepting paths, not only the refusals */
    return accepted - before == 2 && accepted > rounds / 100 ? 0 : 1;
}
