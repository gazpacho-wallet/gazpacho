/* A plain driver for the fuzz targets where libFuzzer is not available.
 *   fuzz_x N [SEED]   run N generated inputs
 *   fuzz_x FILE...    run each file once (replaying a crash)
 * Inputs are random bytes or bytes from a small alphabet of BigSize prefixes
 * and small numbers, at random lengths up to 600. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);

static uint64_t s = 88172645463325252ULL;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }

int main(int argc, char **argv)
{
    static uint8_t buf[1 << 17];
    static const uint8_t alphabet[] = {0, 1, 2, 3, 4, 5, 8, 0x21, 0xfc, 0xfd, 0xfe, 0xff};
    char *end;
    long iters;
    int i;
    if (argc < 2) return 2;
    iters = strtol(argv[1], &end, 10);
    if (*end) {
        for (i = 1; i < argc; i++) {
            FILE *f = fopen(argv[i], "rb");
            size_t n;
            if (!f) return 2;
            n = fread(buf, 1, sizeof buf, f);
            fclose(f);
            LLVMFuzzerTestOneInput(buf, n);
        }
        return 0;
    }
    if (argc > 2) s ^= strtoull(argv[2], NULL, 10) * 0x9e3779b97f4a7c15ULL;
    for (i = 0; i < iters; i++) {
        size_t n = rnd() % (rnd() % 8 ? 80 : 600), k;
        int small = rnd() % 2;
        for (k = 0; k < n; k++) buf[k] = small ? alphabet[rnd() % sizeof alphabet] : (uint8_t)rnd();
        LLVMFuzzerTestOneInput(buf, n);
    }
    printf("RESULT: PASS (%ld inputs)\n", iters);
    return 0;
}
