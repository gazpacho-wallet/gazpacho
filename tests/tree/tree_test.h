/* Helpers for the tree tests: hex, the test keys of terms.md section 11, the
 * T1 terms, and a secp256k1 context. THE KEYS ARE TEST KEYS. */
#ifndef GAZPACHO_TREE_TEST_H
#define GAZPACHO_TREE_TEST_H

#include "../check.h"
#include "gazpacho/terms.h"
#include "gazpacho/tree.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    while (s[0] && s[1] && n < cap) {
        unsigned v;
        if (s[0] == ' ' || s[0] == '\n') { s++; continue; }
        if (sscanf(s, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

static inline void tohex(const uint8_t *b, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) { out[2 * i] = h[b[i] >> 4]; out[2 * i + 1] = h[b[i] & 15]; }
    out[2 * n] = 0;
}

static inline int eqhex(const uint8_t *b, size_t n, const char *hex)
{
    uint8_t want[4096];
    size_t m = unhex(hex, want, sizeof want);
    return m == n && memcmp(b, want, n) == 0;
}

static inline secp256k1_context *test_ctx(void)
{
    static secp256k1_context *ctx;
    if (!ctx) ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return ctx;
}

/* SHA256("gazpacho test key: <label>") mod n (terms.md section 11). The
 * SHA-256 here is OpenSSL-free: secp256k1's tagged hash cannot give a plain
 * hash, so the tests use the tree library's own SHA-256 (checked against the
 * FIPS vectors in test_tree_terms.c) through a tiny local copy of the call. */
void tr_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
static const uint8_t ORDER_N[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
};
static inline void test_secret(const char *label, uint8_t sk[32])
{
    char buf[128];
    snprintf(buf, sizeof buf, "gazpacho test key: %s", label);
    tr_sha256((const uint8_t *)buf, strlen(buf), sk);
    if (memcmp(sk, ORDER_N, 32) >= 0) {   /* mod n: one subtraction is enough below 2n */
        int i, borrow = 0;
        for (i = 31; i >= 0; i--) {
            int d = sk[i] - ORDER_N[i] - borrow;
            borrow = d < 0;
            sk[i] = (uint8_t)(d + (borrow ? 256 : 0));
        }
    }
}

static inline void test_pub(const char *label, uint8_t pub[33])
{
    uint8_t sk[32];
    secp256k1_pubkey pk;
    size_t len = 33;
    test_secret(label, sk);
    if (!secp256k1_ec_pubkey_create(test_ctx(), &pk, sk)) abort();
    secp256k1_ec_pubkey_serialize(test_ctx(), pub, &len, &pk, SECP256K1_EC_COMPRESSED);
}

/* BIP 340 with 32 zero bytes of auxiliary randomness, as spec-vectors.py. */
static inline void test_sign(const char *label, const uint8_t msg[32], uint8_t sig[64])
{
    uint8_t sk[32], aux[32] = {0};
    secp256k1_keypair kp;
    test_secret(label, sk);
    if (!secp256k1_keypair_create(test_ctx(), &kp, sk)) abort();
    if (!secp256k1_schnorrsig_sign32(test_ctx(), sig, msg, &kp, aux)) abort();
}

/* T1 of terms.md section 11, as a struct. */
static inline void t1_terms(gz_terms_outer_t *t)
{
    static const char *salt = "c31b4b333d598e176bb883203548a5e6";
    memset(t, 0, sizeof *t);
    memcpy(t->chain, gz_terms_signet(), 32);
    test_pub("host", t->host_key);
    unhex(salt, t->lobby_salt, 16);
    t->profile = 2;
    t->target = 8;
    t->minimum = 3;
    t->deadline = 1794441600ull;
    t->on_shortfall = 0;
    t->ready_window_ms = 30000;
    t->signing_budget_ms = 600000;
    t->step_timeout_ms = 60000;
    t->n_shapes = 2;
    t->shapes[0].max_members = 4; t->shapes[0].n_interior = 0; t->shapes[0].leaf_kind = 3;
    t->shapes[1].max_members = 16; t->shapes[1].n_interior = 1; t->shapes[1].interior[0] = 4; t->shapes[1].leaf_kind = 3;
    t->lifetime_blocks = 144;
    t->winddown_blocks = 36;
    t->channel_sat = 100000;
    t->tree_feerate = 100;
    t->switches = 0;
    t->n_adj = 3;
    t->adj[0].type = 64; t->adj[0].min = 0; t->adj[0].max = 2000;
    t->adj[1].type = 66; t->adj[1].min = 0; t->adj[1].max = 1000;
    t->adj[2].type = 68; t->adj[2].min = 100; t->adj[2].max = 2500;
}

static inline void t1_current(const uint8_t outer_digest[32], uint32_t version, uint64_t jf, uint64_t base, uint64_t prop,
                       gz_terms_current_t *c)
{
    memset(c, 0, sizeof *c);
    memcpy(c->outer_digest, outer_digest, 32);
    c->version = version;
    c->n_values = 3;
    c->val[0].type = 64; c->val[0].value = jf;
    c->val[1].type = 66; c->val[1].value = base;
    c->val[2].type = 68; c->val[2].value = prop;
}

#endif
