/* Shared helpers for the lobby tests: the crypto port over libsecp256k1 with
 * the test keys of terms.md section 11, hex, and T1/T2 built in. */
#ifndef GAZPACHO_LOBBY_TEST_H
#define GAZPACHO_LOBBY_TEST_H

#include "gazpacho/lobby.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <string.h>

static secp256k1_context *lt_ctx(void)
{
    static secp256k1_context *c;
    if (!c) c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return c;
}

/* A key: SHA256("gazpacho test key: <label>"), as terms.md section 11. */
typedef struct { secp256k1_keypair kp; uint8_t pub[33]; } lt_key_t;

static inline void lt_key(lt_key_t *k, const char *label)
{
    gz_lobby_sha256_t s;
    uint8_t sec[32];
    secp256k1_pubkey pk;
    size_t n = 33;
    const char *pre = "gazpacho test key: ";
    gz_lobby_sha256_init(&s);
    gz_lobby_sha256_write(&s, (const uint8_t *)pre, strlen(pre));
    gz_lobby_sha256_write(&s, (const uint8_t *)label, strlen(label));
    gz_lobby_sha256_done(&s, sec);
    if (!secp256k1_keypair_create(lt_ctx(), &k->kp, sec)) { printf("bad test key\n"); return; }
    if (!secp256k1_keypair_pub(lt_ctx(), &pk, &k->kp)) return;
    secp256k1_ec_pubkey_serialize(lt_ctx(), k->pub, &n, &pk, SECP256K1_EC_COMPRESSED);
}

/* One party's keys behind the port: host, contribution, factory. */
typedef struct { lt_key_t key[4]; int fail_sign; unsigned long signs, verifies; } lt_signer_t;

static inline int lt_verify(void *ctx, const uint8_t pub[33], const uint8_t msg[32], const uint8_t sig[64])
{
    secp256k1_pubkey pk;
    secp256k1_xonly_pubkey x;
    if (ctx) ((lt_signer_t *)ctx)->verifies++;
    if (!secp256k1_ec_pubkey_parse(lt_ctx(), &pk, pub, 33)) return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(lt_ctx(), &x, NULL, &pk)) return 0;
    return secp256k1_schnorrsig_verify(lt_ctx(), sig, msg, 32, &x);
}

static inline int lt_point_ok(void *ctx, const uint8_t pub[33])
{
    secp256k1_pubkey pk;
    (void)ctx;
    return secp256k1_ec_pubkey_parse(lt_ctx(), &pk, pub, 33);
}

static inline int lt_sign(void *ctx, uint32_t which, const uint8_t msg[32], uint8_t sig[64])
{
    lt_signer_t *s = ctx;
    static const uint8_t aux[32];
    if (which < 1 || which > 3 || s->fail_sign) return 0;
    s->signs++;
    return secp256k1_schnorrsig_sign32(lt_ctx(), sig, msg, &s->key[which].kp, aux);
}

static inline gz_lobby_crypto_t lt_crypto(lt_signer_t *s)
{
    gz_lobby_crypto_t c;
    c.verify = lt_verify;
    c.point_ok = lt_point_ok;
    c.sign = lt_sign;
    c.ctx = s;
    return c;
}

static inline size_t lt_unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = 0;
    unsigned v;
    while (*h) {
        if (*h == ' ' || *h == '\n') { h++; continue; }
        if (n >= cap || sscanf(h, "%2x", &v) != 1) return 0;
        out[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

static const char LT_T1[] =
    "0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800"
    "0000042102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e"
    "34733491560610c31b4b333d598e176bb883203548a5e60801020a0200080c02"
    "00030e08000000006af501801001001204000075301404000927c016040000ea"
    "6018090004000300100104031a04000000901c04000000241e08000000000001"
    "86a02004000000642201004010000000000000000000000000000007d0421000"
    "0000000000000000000000000003e84410000000000000006400000000000009"
    "c4";
static const char LT_T2[] =
    "022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4"
    "24f2040400000001400800000000000001f4420800000000000003e844080000"
    "0000000003e8";
static const char LT_T3[] =
    "022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4"
    "24f2040400000002400800000000000005dc420800000000000003e844080000"
    "0000000003e8";

/* A member's conditions that T1 fits as a whole. */
static inline gz_lobby_conditions_t lt_cond_fits(void)
{
    gz_lobby_conditions_t c;
    memset(&c, 0, sizeof c);
    c.profiles = 1u << 2;
    c.life_min = 1; c.life_max = 52560; c.wind_max = 52560; c.rate_max = 1000000;
    c.chan_min = 100000;
    c.adj_max[0] = 2000; c.adj_max[1] = 1000; c.adj_max[2] = 2500;
    return c;
}

#endif
