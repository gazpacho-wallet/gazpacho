/* SPDX-License-Identifier: MIT */
/* Constant-time check of the key port's derivations (keys.md 8), run under
 * valgrind's memcheck: the seed the seed source hands out is marked
 * undefined (secret), so memcheck reports every conditional jump and every
 * memory index that depends on it. What may legitimately depend on a secret
 * is declassified here, at the API, as libsecp256k1's own ctime test does:
 * the success result (BIP 32's validity, public by nature) and the public
 * keys handed out. Anything else memcheck reports is a finding; the CTest
 * wrapper (tests/program/ct_keys.sh) fails on any error that is not in the
 * triaged list it carries. THE KEYS HERE ARE TEST KEYS. */
#include <stdio.h>
#include <string.h>

#include <secp256k1.h>
#include <valgrind/memcheck.h>

#include "keys.h"

static uint8_t SEED[64];

static int seed_fn(void *ctx, uint8_t out[64])
{
    (void)ctx;
    memcpy(out, SEED, 64);
    VALGRIND_MAKE_MEM_UNDEFINED(out, 64); /* secret from here on */
    return 1;
}

int main(void)
{
    secp256k1_context *secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    gzp_seed_source_t src = {seed_fn, NULL};
    gzp_keys_t k;
    uint8_t sec[32], pub[33], scope[32] = {1}, digest[32] = {2}, f[32], c[32];
    int ok = 1, r;
    for (int i = 0; i < 64; i++) SEED[i] = (uint8_t)(i * 13 + 5);
    r = gzp_keys_init(&k, secp, GZW_NET_SIGNET, &src, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&r, sizeof r);
    ok &= r;
    VALGRIND_MAKE_MEM_DEFINED(&k.account, sizeof k.account); /* the account's public key */
    for (uint32_t i = 1; i < 5; i++) {
        r = gzp_keys_lobby(&k, 0, i, sec, pub, NULL);
        VALGRIND_MAKE_MEM_DEFINED(&r, sizeof r);
        ok &= r;
    }
    r = gzp_keys_host(&k, sec, pub, NULL, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&r, sizeof r);
    ok &= r;
    r = gzp_keys_scope_open(&k, scope, digest, 0, 1, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&r, sizeof r);
    ok &= r;
    /* The scoped secrets are copied out without a branch on them. */
    r = gzp_keys_scoped(&k, scope, digest, f, c);
    VALGRIND_MAKE_MEM_DEFINED(&r, sizeof r);
    ok &= r;
    gzp_keys_free(&k);
    secp256k1_context_destroy(secp);
    printf("ct_keys: %s\n", ok ? "ran" : "FAILED");
    return ok ? 0 : 1;
}
