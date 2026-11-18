/* SPDX-License-Identifier: MIT */
/* A randomized run of the key port (program/keys.c; keys.md 10). keys.c parses
 * nothing it is sent: its inputs are numbers from the node and a seed. So this
 * drives the whole interface with random seeds, networks, epochs, indexes
 * (edge values often) and scoped-table operations, under the sanitizers, and
 * checks the invariants after every step:
 *   - deterministic: the same call twice gives the same bytes;
 *   - a secret's public key is the public key handed out;
 *   - the policy: no per-lobby key for another epoch or while frozen, and no
 *     key from an empty seed source;
 *   - the scoped table: at most 8, a lookup only for its digest, nothing
 *     after forget, every unused entry all zero;
 *   - payout scripts are 51 20 <32 bytes> and equal the wallet's own output;
 *   - every failure leaves its outputs zeroed.
 * usage: fuzz_keys ITERATIONS [SEED]. Deterministic for a given SEED. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <secp256k1.h>

#include "keys.h"

static uint64_t rng;
static uint64_t next(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static uint32_t num31(void)
{
    static const uint32_t edge[] = {0, 1, 2, 3, 0x7ffffffeu, 0x7fffffffu, 0x80000000u, 0xffffffffu};
    switch (next() % 4) {
    case 0: return edge[next() % 8];
    case 1: return (uint32_t)(next() % 16);
    default: return (uint32_t)next();
    }
}

static uint8_t SEED[64];
static int have_seed = 1;
static int seed_fn(void *ctx, uint8_t out[64])
{
    (void)ctx;
    if (!have_seed) {
        memset(out, 0, 64);
        return 0;
    }
    memcpy(out, SEED, 64);
    return 1;
}

static int fails;
#define REQUIRE(c)                                                                        \
    do {                                                                                  \
        if (!(c)) {                                                                       \
            fprintf(stderr, "fuzz_keys: invariant failed at %s:%d: %s\n", __FILE__, __LINE__, #c); \
            fails++;                                                                      \
            return;                                                                       \
        }                                                                                 \
    } while (0)

static int zero(const void *p, size_t n)
{
    const uint8_t *b = p;
    while (n--)
        if (*b++) return 0;
    return 1;
}

static const secp256k1_context *secp;

static int pub_of(const uint8_t sec[32], uint8_t pub[33])
{
    secp256k1_pubkey pk;
    size_t len = 33;
    return secp256k1_ec_pubkey_create(secp, &pk, sec) &&
           secp256k1_ec_pubkey_serialize(secp, pub, &len, &pk, SECP256K1_EC_COMPRESSED);
}

static void step(gzp_keys_t *k)
{
    uint8_t sec[32], sec2[32], pub[33], pub2[33], p3[33], spk[34], scope[32], digest[32], f[32], c[32];
    uint32_t e = num31(), i = num31();
    gzp_keys_err_t err;
    int ok, ok2;
    size_t n;
    switch (next() % 9) {
    case 0: /* raw, twice */
        memset(sec, 0xaa, 32);
        ok = gzp_keys_lobby_raw(k, e, i, sec, pub, &err);
        ok2 = gzp_keys_lobby_raw(k, e, i, sec2, pub2, &err);
        REQUIRE(ok == ok2);
        REQUIRE(ok == (have_seed && e < 0x80000000u && i < 0x80000000u));
        if (ok) {
            REQUIRE(!memcmp(sec, sec2, 32) && !memcmp(pub, pub2, 33) && pub_of(sec, p3) && !memcmp(p3, pub, 33));
        } else {
            REQUIRE(zero(sec, 32) && zero(pub, 33));
        }
        break;
    case 1: /* policy */
        if (next() % 2) e = k->epoch;
        ok = gzp_keys_lobby(k, e, i, sec, pub, &err);
        if (e != k->epoch || k->frozen) REQUIRE(!ok && err.why == GZP_KEYS_POLICY && zero(sec, 32) && zero(pub, 33));
        else REQUIRE(ok == gzp_keys_lobby_raw(k, e, i, sec2, pub2, NULL) && (!ok || !memcmp(sec, sec2, 32)));
        break;
    case 2:
        gzp_keys_set_epoch(k, num31() & 0x7fffffffu);
        break;
    case 3:
        gzp_keys_freeze(k, (int)(next() % 3));
        break;
    case 4: /* host */
        ok = gzp_keys_host(k, sec, pub, NULL, &err);
        REQUIRE(ok == have_seed);
        if (ok) REQUIRE(pub_of(sec, p3) && !memcmp(p3, pub, 33));
        else REQUIRE(zero(sec, 32) && zero(pub, 33));
        break;
    case 5: { /* payout script and the wallet's own output */
        gzw_bip86_output o;
        uint32_t j = num31();
        ok = gzp_keys_payout_script(k, j, spk, &err);
        REQUIRE(ok == (j < 0x80000000u));
        if (!ok) {
            REQUIRE(zero(spk, 34));
            break;
        }
        REQUIRE(spk[0] == 0x51 && spk[1] == 0x20);
        ok2 = gzp_keys_wallet_output(k, 0, j, &o, &err);
        REQUIRE(ok2 == have_seed);
        if (ok2) REQUIRE(!memcmp(o.script_pubkey, spk, 34));
        break;
    }
    case 6: /* scoped open and lookups */
        memset(scope, (int)(next() % 12), 32);
        memset(digest, (int)(next() % 3), 32);
        ok = gzp_keys_scope_open(k, scope, digest, next() % 2 ? k->epoch : e, i, &err);
        if (ok) {
            REQUIRE(gzp_keys_scoped(k, scope, digest, f, c));
            REQUIRE(gzp_keys_lobby_raw(k, k->epoch, i, sec, NULL, NULL) && !memcmp(c, sec, 32));
            REQUIRE(gzp_keys_lobby_raw(k, k->epoch, i + 1, sec, NULL, NULL) && !memcmp(f, sec, 32));
            digest[next() % 32] ^= (uint8_t)(1u << (next() % 8));
            REQUIRE(!gzp_keys_scoped(k, scope, digest, f, c) && zero(f, 32) && zero(c, 32));
        }
        break;
    case 7: /* forget */
        memset(scope, (int)(next() % 12), 32);
        if (next() % 8 == 0) gzp_keys_forget_all(k);
        else gzp_keys_forget(k, scope);
        memset(digest, 0, 32);
        REQUIRE(!gzp_keys_scoped(k, scope, digest, f, c));
        break;
    default:
        have_seed = (next() % 6) != 0; /* lock and unlock the seed source */
        break;
    }
    n = gzp_keys_scopes_held(k);
    REQUIRE(n <= GZP_KEYS_MAX_SCOPES);
    for (size_t s = 0; s < GZP_KEYS_MAX_SCOPES; s++)
        if (!k->scopes[s].used) REQUIRE(zero(&k->scopes[s], sizeof k->scopes[s]));
}

int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 2000;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    static const gzw_network nets[] = {GZW_NET_SIGNET, GZW_NET_TESTNET4, GZW_NET_TESTNET, GZW_NET_REGTEST};
    gzp_seed_source_t src = {seed_fn, NULL};
    gzp_keys_t k;
    memset(&k, 0, sizeof k);
    rng = argc > 2 ? strtoull(argv[2], NULL, 0) : 0x9e3779b97f4a7c15ull;
    if (!rng) rng = 1;
    secp = ctx;
    for (long it = 0; it < iters && !fails; it++) {
        if (it % 200 == 0) { /* a new seed and network now and then */
            for (int b = 0; b < 64; b++) SEED[b] = (uint8_t)next();
            have_seed = 1;
            gzp_keys_free(&k);
            if (!gzp_keys_init(&k, ctx, nets[next() % 4], &src, NULL)) {
                fprintf(stderr, "fuzz_keys: set-up failed\n");
                return 1;
            }
        }
        step(&k);
    }
    gzp_keys_free(&k);
    secp256k1_context_destroy(ctx);
    if (fails) return 1;
    printf("fuzz_keys: %ld steps, every invariant held\n", iters);
    return 0;
}
