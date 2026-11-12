/* Shared by the wallet transaction tests. */
#ifndef GAZPACHO_TX_TEST_H
#define GAZPACHO_TX_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/wallet_tx.h"

static int checks = 0, failures = 0;

#define CHECK(cond)                                                     \
    do {                                                                \
        checks++;                                                       \
        if (!(cond)) {                                                  \
            failures++;                                                 \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                               \
    } while (0)

static inline size_t unhex(const char *h, uint8_t *out, size_t cap) {
    size_t n = strlen(h) / 2;
    if (n > cap) {
        printf("FAIL unhex: %zu bytes do not fit in %zu\n", n, cap);
        exit(1);
    }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) exit(1);
        out[i] = (uint8_t)v;
    }
    return n;
}

/* The phrase published in BIP 86.  Public, not a secret. */
static const char PUBLIC_PHRASE[] =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon about";

static inline secp256k1_context *test_ctx(void) {
    return secp256k1_context_create(SECP256K1_CONTEXT_NONE);
}

static inline int public_master(const secp256k1_context *ctx, gzw_xprv *master) {
    uint8_t seed[64];
    if (!gzw_phrase_to_seed(PUBLIC_PHRASE, NULL, seed)) return 0;
    return gzw_bip32_master(ctx, seed, 64, master, NULL);
}

static inline int test_done(const char *name) {
    printf("%s: %d checks, %d failures\n", name, checks, failures);
    return failures ? 1 : 0;
}

#endif
