/* Runs the official BIP test vectors (wallet/vectors/) and fails if any
   vector fails or any group is empty or smaller than the published count. */
#include <stdio.h>

#include <secp256k1.h>

#include "official_vectors.h"

/* Published counts, so a vector silently dropped by the generator is noticed:
   BIP 39 English 24; BIP 32 chains 6+6+2+3 = 17; BIP 32 invalid keys 16;
   BIP 86 root + account + 3 addresses = 5; BIP 350 Bech32m valid 7, invalid 14;
   BIP 350 segwit valid 8, invalid 15; BIP 341 no-script-tree cases 1 + 1. */
static const int expected_cases[GZW_VECTOR_GROUPS] = {24, 17, 16, 5, 7, 14, 8, 15, 2};

int main(void) {
    gzw_vector_group groups[GZW_VECTOR_GROUPS];
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int all, bad = 0, total = 0;

    if (!ctx) {
        printf("FAIL: no secp256k1 context\n");
        return 1;
    }
    all = gzw_official_vectors_run(ctx, groups);
    secp256k1_context_destroy(ctx);

    for (int g = 0; g < GZW_VECTOR_GROUPS; g++) {
        int ok = groups[g].failed == 0 && groups[g].cases == expected_cases[g];
        printf("%s %2d/%2d (expected %2d)  %s\n", ok ? "pass" : "FAIL",
               groups[g].cases - groups[g].failed, groups[g].cases,
               expected_cases[g], groups[g].name);
        if (!ok) bad++;
        total += groups[g].cases;
    }
    printf("test_wallet_vectors: %d vectors, %d groups failed\n", total, bad);
    return (all && bad == 0) ? 0 : 1;
}
