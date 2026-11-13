/* The plain driver for the storage fuzz targets (without libFuzzer): N inputs
 * from a fixed-seed generator, half of them mutations of the previous input,
 * so CTest runs every target on every build. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint64_t st = 0x9e3779b97f4a7c15ull;
static uint64_t next(void)
{
    st ^= st << 13;
    st ^= st >> 7;
    st ^= st << 17;
    return st;
}

int main(int argc, char **argv)
{
    long n = argc > 1 ? atol(argv[1]) : 10000;
    static uint8_t buf[2048];
    size_t len = 0;
    for (long i = 0; i < n; i++) {
        if (i % 2 == 0 || len == 0) {
            len = (size_t)(next() % sizeof buf);
            for (size_t j = 0; j < len; j++)
                buf[j] = (uint8_t)next();
        } else {
            buf[next() % len] ^= (uint8_t)(1u << (next() % 8));
        }
        LLVMFuzzerTestOneInput(buf, len);
    }
    printf("%ld inputs: no crash\n", n);
    return 0;
}
