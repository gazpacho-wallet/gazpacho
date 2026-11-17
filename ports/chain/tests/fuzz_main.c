/*
 * A plain driver for the chain port's fuzz targets where libFuzzer is not
 * available (the CTest form of each target).
 *   fuzz_x N [SEED]   run N generated inputs
 *   fuzz_x FILE...    run each file once (replaying a finding)
 * Half the inputs are random bytes; the other half are drawn from the
 * characters chain server answers are made of, so the parsers get past
 * their first check more often.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);

static uint64_t s = 88172645463325252ULL;
static uint64_t rnd(void) {
  s ^= s << 13;
  s ^= s >> 7;
  s ^= s << 17;
  return s;
}

int main(int argc, char **argv) {
  static uint8_t buf[1 << 17];
  static const char alphabet[] = "{}[]\",:0123456789abcdef-+.eE \\n\ttruefalsenulspxidvhgk_";
  char *end;
  if (argc < 2) return 2;
  long iters = strtol(argv[1], &end, 10);
  if (*end) {
    for (int i = 1; i < argc; i++) {
      FILE *f = fopen(argv[i], "rb");
      if (!f) return 2;
      size_t n = fread(buf, 1, sizeof buf, f);
      fclose(f);
      LLVMFuzzerTestOneInput(buf, n);
    }
    return 0;
  }
  if (argc > 2) s ^= strtoull(argv[2], NULL, 10) * 0x9e3779b97f4a7c15ULL;
  for (long i = 0; i < iters; i++) {
    size_t n = rnd() % (rnd() % 8 ? 200 : 2000);
    int text = (int)(rnd() % 2);
    for (size_t k = 0; k < n; k++)
      buf[k] = text && k > 0 ? (uint8_t)alphabet[rnd() % (sizeof alphabet - 1)] : (uint8_t)rnd();
    LLVMFuzzerTestOneInput(buf, n);
  }
  printf("RESULT: PASS (%ld inputs)\n", iters);
  return 0;
}
