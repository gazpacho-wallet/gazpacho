/* Fuzz target for gzt_tx_parse.  Properties checked on every input:
 *   - no crash, no out-of-bounds access (run under the memory-error checkers);
 *   - whatever parses serialises back to the identical bytes;
 *   - the legacy form of what parsed parses again, with the same txid;
 *   - weight is 3 x (size without witness) + (size of the input), counted;
 * Built with -DGZT_LIBFUZZER for libFuzzer (clang -fsanitize=fuzzer).
 * Otherwise a built-in driver mutates the official transactions for the
 * number of rounds given (default 200000) with a fixed seed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/wallet_tx.h"

static gzt_tx tx, tx2;
static uint8_t back[GZT_MAX_TX_BYTES];
static unsigned long accepted = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t n;
    uint8_t id1[32], id2[32];
    uint64_t w, vs;
    if (gzt_tx_parse(data, size, &tx) != GZT_OK) return 0;
    accepted++;
    if (gzt_tx_serialize(&tx, GZT_SER_WITNESS, back, sizeof back, &n) != GZT_OK || n != size ||
        memcmp(back, data, size) != 0)
        abort();
    if (gzt_tx_serialize(&tx, GZT_SER_NO_WITNESS, back, sizeof back, &n) != GZT_OK) abort();
    /* the counted weight equals the weight of the real serialisations */
    if (gzt_tx_weight(&tx, &w, &vs) != GZT_OK || w != 3 * (uint64_t)n + size || vs != (w + 3) / 4)
        abort();
    if (gzt_tx_parse(back, n, &tx2) != GZT_OK) abort();
    if (gzt_tx_txid(&tx, id1) != GZT_OK || gzt_tx_txid(&tx2, id2) != GZT_OK ||
        memcmp(id1, id2, 32) != 0)
        abort();
    return 0;
}

#ifndef GZT_LIBFUZZER
#include <stdint.h>

#include "tx_vectors_data.h"

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

int main(int argc, char **argv) {
    static uint8_t seeds[2][4096], buf[8192];
    size_t seed_len[2];
    unsigned long rounds = argc > 1 ? strtoul(argv[1], NULL, 10) : 200000;
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
        LLVMFuzzerTestOneInput(buf, n);
    }
    /* the seeds themselves must be accepted */
    unsigned long before = accepted;
    LLVMFuzzerTestOneInput(seeds[0], seed_len[0]);
    LLVMFuzzerTestOneInput(seeds[1], seed_len[1]);
    printf("fuzz_tx_parse: %lu inputs, %lu accepted by the parser, properties held\n",
           rounds, accepted);
    /* and the mutations must reach the accepting paths, not only the refusals */
    return accepted - before == 2 && accepted > rounds / 100 ? 0 : 1;
}
#endif
