/* The plain driver of fuzz_lobby (CTest; libFuzzer builds leave it out,
 * docs/notes/ci.md): mutations of valid inputs (bit flips, boundary bytes,
 * BigSize prefixes, insertions, deletions, truncation, splicing), each handed
 * to LLVMFuzzerTestOneInput, which aborts on a failed check.
 *
 * usage: fuzz_lobby ITERATIONS SEED */
#include "../check.h"
#include "rng.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
void lobby_fuzz_corpus(void (*add)(const uint8_t *b, size_t n));
extern unsigned long lobby_fuzz_stats[4];

#define MAXB 6000
typedef struct { uint8_t b[MAXB]; size_t n; } blob_t;
static blob_t corpus[32];
static int n_corpus;
static sim_rng_t R;

static void add(const uint8_t *b, size_t n)
{
    if (n <= MAXB && n_corpus < 32) { memcpy(corpus[n_corpus].b, b, n); corpus[n_corpus++].n = n; }
}

static size_t mutate(const blob_t *in, uint8_t *out)
{
    size_t n = in->n, k, rounds = 1 + sim_rng_below(&R, 4), r;
    memcpy(out, in->b, n);
    for (r = 0; r < rounds; r++) {
        size_t at = n ? (size_t)sim_rng_below(&R, n) : 0, len;
        static const uint8_t edge[] = {0x00, 0x01, 0x02, 0x20, 0x40, 0x7f, 0x80, 0xf0, 0xfc, 0xfd, 0xfe, 0xff};
        switch (sim_rng_below(&R, 8)) {
        case 0: if (n) out[at] ^= (uint8_t)(1u << sim_rng_below(&R, 8)); break;
        case 1: if (n) out[at] = edge[sim_rng_below(&R, sizeof edge)]; break;
        case 2: if (n) out[at] = (uint8_t)sim_rng_below(&R, 256); break;
        case 3: len = 1 + (size_t)sim_rng_below(&R, 8);                    /* insert */
            if (n + len < MAXB) {
                memmove(out + at + len, out + at, n - at);
                for (k = 0; k < len; k++) out[at + k] = (uint8_t)sim_rng_below(&R, 256);
                n += len;
            }
            break;
        case 4: len = 1 + (size_t)sim_rng_below(&R, 16);                   /* delete */
            if (at + len <= n) { memmove(out + at, out + at + len, n - at - len); n -= len; }
            break;
        case 5: n = at; break;                                             /* truncate */
        case 6: {                                                          /* splice */
            const blob_t *o = &corpus[sim_rng_below(&R, (uint64_t)n_corpus)];
            size_t from = o->n ? (size_t)sim_rng_below(&R, o->n) : 0;
            len = o->n - from;
            if (at + len > MAXB) len = MAXB - at;
            memcpy(out + at, o->b + from, len);
            if (at + len > n) n = at + len;
            break;
        }
        default:                                                           /* a BigSize prefix */
            if (n + 2 < MAXB) { memmove(out + at + 2, out + at, n - at); out[at] = 0xfd; out[at + 1] = 0; n += 2; }
            break;
        }
    }
    return n;
}

int main(int argc, char **argv)
{
    unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000, i;
    uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 10) : 1;
    static uint8_t buf[MAXB];
    setvbuf(stdout, NULL, _IONBF, 0);
    sim_rng_init(&R, seed, 9);
    lobby_fuzz_corpus(add);
    printf("fuzz: corpus of %d inputs\n", n_corpus);
    for (i = 0; i < (unsigned long)n_corpus; i++) LLVMFuzzerTestOneInput(corpus[i].b, corpus[i].n);
    for (i = 0; i < iters; i++) {
        size_t n = mutate(&corpus[sim_rng_below(&R, (uint64_t)n_corpus)], buf);
        LLVMFuzzerTestOneInput(buf, n);
    }
    printf("fuzz: %lu inputs; accepted %lu messages, %lu outer, %lu current, %lu reassembled\n",
           iters, lobby_fuzz_stats[0], lobby_fuzz_stats[1], lobby_fuzz_stats[2], lobby_fuzz_stats[3]);
    CHECK(n_corpus == 13);
    CHECK(lobby_fuzz_stats[0] > 0 && lobby_fuzz_stats[1] > 0 && lobby_fuzz_stats[2] > 0);   /* the accepting paths are reached */
    return check_done();
}
