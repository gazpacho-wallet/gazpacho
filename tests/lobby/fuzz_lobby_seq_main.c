/* The plain driver of fuzz_lobby_seq (CTest; libFuzzer builds leave it out,
 * docs/notes/ci.md): random scripts of 3-byte steps, each handed to
 * LLVMFuzzerTestOneInput, which aborts on a failed check.
 *
 * usage: fuzz_lobby_seq ITERATIONS SEED */
#include "../check.h"
#include "rng.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern unsigned long lobby_seq_stats[8];

int main(int argc, char **argv)
{
    unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 10) : 2000, i;
    uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 10) : 1;
    static uint8_t buf[3000];
    sim_rng_t R;
    setvbuf(stdout, NULL, _IONBF, 0);
    sim_rng_init(&R, seed, 11);
    for (i = 0; i < iters; i++) {
        size_t n = 1 + 3 * (size_t)(4 + sim_rng_below(&R, 150)), k = 1, w;
        int style = (int)sim_rng_below(&R, 3);
        for (w = 0; w < n; w++) buf[w] = (uint8_t)sim_rng_below(&R, 256);
        if (style == 0) {
            /* a host whose members mostly join, ready and answer: checks and starts come */
            static const uint8_t ops[] = {5, 5, 5, 8, 8, 9, 6, 7, 1, 0, 3};
            buf[0] = (uint8_t)(2 * sim_rng_below(&R, 4));
            for (w = 0; w < 6 && k + 9 <= n; w++, k += 9) {
                buf[k] = 0; buf[k + 1] = (uint8_t)w;
                buf[k + 3] = 3; buf[k + 4] = (uint8_t)w;
                buf[k + 6] = 5; buf[k + 7] = (uint8_t)w; buf[k + 8] = 3;
            }
            for (; k + 3 <= n; k += 3) {
                buf[k] = ops[sim_rng_below(&R, sizeof ops)];
                buf[k + 1] = (uint8_t)sim_rng_below(&R, 6);
                if (buf[k] == 5) buf[k + 2] = sim_rng_below(&R, 2) ? 11 : 3;     /* the latest values, with the check */
                if (buf[k] == 8) buf[k + 2] = sim_rng_below(&R, 2) ? 0 : 3;      /* the window or the deadline */
                if (buf[k] == 9) buf[k + 2] = (uint8_t)(128 + sim_rng_below(&R, 3));
            }
        } else if (style == 1) {
            /* a member taken through terms, a check and a start, with noise */
            static const uint8_t ops[] = {3, 4, 4, 6, 1, 9, 10, 0, 2, 5, 7};
            buf[0] = 1;
            if (k + 12 <= n) {
                buf[1] = 0; buf[4] = 2; buf[6] = 0; buf[7] = 3; buf[8] = 0; buf[9] = 0; buf[10] = 4; buf[11] = 0; buf[12] = 0;
                k = 13;
            }
            for (; k + 3 <= n; k += 3) {
                buf[k] = ops[sim_rng_below(&R, sizeof ops)];
                buf[k + 1] = (uint8_t)(3 * sim_rng_below(&R, 2));               /* mostly the same check */
                if (buf[k] == 8 && sim_rng_below(&R, 4)) buf[k] = 3;
            }
        }
        LLVMFuzzerTestOneInput(buf, n);
    }
    printf("fuzz_seq: %lu scripts, %lu steps; %lu seats, %lu inputs with a check, %lu starts, %lu begins, "
           "%lu restarts, %lu members ended, %lu lobbies ended\n", iters, lobby_seq_stats[0], lobby_seq_stats[1],
           lobby_seq_stats[2], lobby_seq_stats[3], lobby_seq_stats[4], lobby_seq_stats[5], lobby_seq_stats[6],
           lobby_seq_stats[7]);
    CHECK(lobby_seq_stats[1] > 0 && lobby_seq_stats[2] > 0 && lobby_seq_stats[3] > 0 && lobby_seq_stats[4] > 0 &&
          lobby_seq_stats[5] > 0);
    return check_done();
}
