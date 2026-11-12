/* BIP 32's rare cases, forced.
 *
 * BIP 32 says a derivation is invalid when the left half of the HMAC is not
 * below the group order or the resulting key is zero, which happens about
 * once in 2^127 and so never in an ordinary test.  This program is linked
 * with -Wl,--wrap=HMAC so that the library's HMAC calls come here, where the
 * result can be replaced.  (Method taken from the reviewer's rare.c.)
 */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include "gazpacho/wallet_keys.h"

unsigned char *__real_HMAC(const EVP_MD *md, const void *key, int key_len,
                           const unsigned char *data, size_t data_len,
                           unsigned char *out, unsigned int *out_len);
unsigned char *__wrap_HMAC(const EVP_MD *md, const void *key, int key_len,
                           const unsigned char *data, size_t data_len,
                           unsigned char *out, unsigned int *out_len);

static int force = 0;       /* 0: real HMAC; 1: replace the chosen call */
static int force_after = 0; /* real calls to let through first */
static int force_count = 0; /* calls to replace */
static unsigned char forced_I[64];
static int calls = 0;

unsigned char *__wrap_HMAC(const EVP_MD *md, const void *key, int key_len,
                           const unsigned char *data, size_t data_len,
                           unsigned char *out, unsigned int *out_len) {
    calls++;
    if (force && force_after-- <= 0 && force_count-- > 0) {
        memcpy(out, forced_I, 64);
        if (out_len) *out_len = 64;
        return out;
    }
    return __real_HMAC(md, key, key_len, data, data_len, out, out_len);
}

/* Replace the HMAC result of the call after `after` real ones: left half il,
   right half (the chain code) a fixed pattern. */
static void arm(const unsigned char il[32], int after) {
    memcpy(forced_I, il, 32);
    memset(forced_I + 32, 0x5c, 32);
    force = 1;
    force_after = after;
    force_count = 1;
}

static void disarm(void) { force = 0; }

static const unsigned char ORDER[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

static int checks = 0, failures = 0;
#define CHECK(cond)                                                \
    do {                                                           \
        checks++;                                                  \
        if (!(cond)) {                                             \
            failures++;                                            \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                          \
    } while (0)

static int all_zero(const void *p, size_t len) {
    const unsigned char *b = p;
    unsigned char acc = 0;
    for (size_t i = 0; i < len; i++) acc |= b[i];
    return acc == 0;
}

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned char seed[32], zero[32], ones[32], n_minus_1[32], neg_k[32];
    gzw_xprv m, c;
    gzw_xpub mp, cp, via_priv;
    gzw_bip86_output o, good5, good6;
    secp256k1_keypair kp;
    gzw_reason why;
    int normal_calls;

    if (!ctx) return 1;
    for (int i = 0; i < 32; i++) seed[i] = (unsigned char)(i + 1);
    memset(zero, 0, 32);
    memset(ones, 0xff, 32);
    memcpy(n_minus_1, ORDER, 32);
    n_minus_1[31]--;

    /* The wrapper is really in the library's path. */
    calls = 0;
    CHECK(gzw_bip32_master(ctx, seed, 32, &m, NULL));
    CHECK(calls == 1);

    /* ---- master key: left half 0, n, 2^256-1 are invalid; n-1 is valid ---- */
    arm(zero, 0);
    memset(&m, 0xAA, sizeof(m));
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_master(ctx, seed, 32, &m, &why));
    CHECK(why == GZW_REASON_INVALID_CHILD && all_zero(&m, sizeof(m)));
    arm(ORDER, 0);
    memset(&m, 0xAA, sizeof(m));
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_master(ctx, seed, 32, &m, &why));
    CHECK(why == GZW_REASON_INVALID_CHILD && all_zero(&m, sizeof(m)));
    arm(ones, 0);
    memset(&m, 0xAA, sizeof(m));
    CHECK(!gzw_bip32_master(ctx, seed, 32, &m, &why));
    CHECK(why == GZW_REASON_INVALID_CHILD && all_zero(&m, sizeof(m)));
    arm(n_minus_1, 0);
    CHECK(gzw_bip32_master(ctx, seed, 32, &m, &why));
    CHECK(why == GZW_REASON_OK && memcmp(m.key, n_minus_1, 32) == 0);
    disarm();

    CHECK(gzw_bip32_master(ctx, seed, 32, &m, NULL));
    CHECK(gzw_bip32_neuter(ctx, &m, &mp));
    memcpy(neg_k, m.key, 32);
    CHECK(secp256k1_ec_seckey_negate(ctx, neg_k));

    /* ---- private child, non-hardened and hardened ---- */
    for (int hard = 0; hard < 2; hard++) {
        uint32_t idx = hard ? GZW_HARDENED : 0;

        arm(ORDER, 0); /* left half = n */
        memset(&c, 0xAA, sizeof(c));
        why = GZW_REASON_OK;
        CHECK(!gzw_bip32_child_priv(ctx, &m, idx, &c, &why));
        CHECK(why == GZW_REASON_INVALID_CHILD && all_zero(&c, sizeof(c)));

        arm(ones, 0); /* left half = 2^256 - 1 */
        memset(&c, 0xAA, sizeof(c));
        why = GZW_REASON_OK;
        CHECK(!gzw_bip32_child_priv(ctx, &m, idx, &c, &why));
        CHECK(why == GZW_REASON_INVALID_CHILD && all_zero(&c, sizeof(c)));

        arm(neg_k, 0); /* left half = -k_par: the child key would be zero */
        memset(&c, 0xAA, sizeof(c));
        why = GZW_REASON_OK;
        CHECK(!gzw_bip32_child_priv(ctx, &m, idx, &c, &why));
        CHECK(why == GZW_REASON_INVALID_CHILD && all_zero(&c, sizeof(c)));

        arm(zero, 0); /* left half = 0 is allowed: the child key equals the parent's */
        why = GZW_REASON_INTERNAL;
        CHECK(gzw_bip32_child_priv(ctx, &m, idx, &c, &why));
        CHECK(why == GZW_REASON_OK && memcmp(c.key, m.key, 32) == 0);
        CHECK(c.depth == 1 && c.child_number == idx);
        disarm();

        /* The caller's remedy: the next index works. */
        CHECK(gzw_bip32_child_priv(ctx, &m, idx + 1, &c, &why) && why == GZW_REASON_OK);
    }

    /* ---- public child ---- */
    arm(ORDER, 0);
    memset(&cp, 0xAA, sizeof(cp));
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_child_pub(ctx, &mp, 0, &cp, &why));
    CHECK(why == GZW_REASON_INVALID_CHILD && all_zero(&cp, sizeof(cp)));
    arm(neg_k, 0); /* the point at infinity */
    memset(&cp, 0xAA, sizeof(cp));
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_child_pub(ctx, &mp, 0, &cp, &why));
    CHECK(why == GZW_REASON_INVALID_CHILD && all_zero(&cp, sizeof(cp)));
    arm(zero, 0);
    CHECK(gzw_bip32_child_pub(ctx, &mp, 0, &cp, &why));
    CHECK(why == GZW_REASON_OK && memcmp(cp.pubkey, mp.pubkey, 33) == 0);
    /* Private and public derivation agree in that case too. */
    arm(zero, 0);
    CHECK(gzw_bip32_child_priv(ctx, &m, 7, &c, NULL));
    disarm();
    CHECK(gzw_bip32_neuter(ctx, &c, &via_priv));
    arm(zero, 0);
    CHECK(gzw_bip32_child_pub(ctx, &mp, 7, &cp, NULL));
    disarm();
    CHECK(memcmp(via_priv.pubkey, cp.pubkey, 33) == 0);
    CHECK(memcmp(via_priv.chain_code, cp.chain_code, 32) == 0);
    CHECK(memcmp(via_priv.parent_fingerprint, cp.parent_fingerprint, 4) == 0);

    /* ---- the BIP 86 layer: an invalid step anywhere on the path ---- */
    calls = 0;
    CHECK(gzw_bip86_output_from_master(ctx, &m, GZW_NET_SIGNET, 0, 0, 5, &good5, NULL));
    normal_calls = calls;
    /* 3 account steps + change + index privately, then change + index publicly. */
    CHECK(normal_calls == 7);
    CHECK(gzw_bip86_output_from_master(ctx, &m, GZW_NET_SIGNET, 0, 0, 6, &good6, NULL));
    for (int after = 0; after < normal_calls; after++) {
        arm(ORDER, after);
        memset(&o, 0xAA, sizeof(o));
        why = GZW_REASON_OK;
        CHECK(!gzw_bip86_output_from_master(ctx, &m, GZW_NET_SIGNET, 0, 0, 5, &o, &why));
        CHECK(why == GZW_REASON_INVALID_CHILD);
        CHECK(all_zero(&o, sizeof(o)));
        disarm();
    }
    /* Index 5 invalid (its private step is HMAC call 5): the wallet is told
       so, moves to index 6, and gets the ordinary output for index 6. */
    arm(ORDER, 4);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip86_output_from_master(ctx, &m, GZW_NET_SIGNET, 0, 0, 5, &o, &why));
    CHECK(why == GZW_REASON_INVALID_CHILD);
    disarm();
    CHECK(gzw_bip86_output_from_master(ctx, &m, GZW_NET_SIGNET, 0, 0, 6, &o, &why));
    CHECK(why == GZW_REASON_OK && strcmp(o.address, good6.address) == 0);
    CHECK(strcmp(good5.address, good6.address) != 0);

    /* The signing key pair: nothing is returned for an invalid step. */
    for (int after = 0; after < 12; after++) {
        arm(ORDER, after);
        memset(&kp, 0xAA, sizeof(kp));
        memset(&o, 0xAA, sizeof(o));
        why = GZW_REASON_OK;
        CHECK(!gzw_bip86_tweaked_keypair(ctx, &m, GZW_NET_SIGNET, 0, 0, 5, &kp, &o, &why));
        CHECK(why == GZW_REASON_INVALID_CHILD);
        CHECK(all_zero(&kp, sizeof(kp)) && all_zero(&o, sizeof(o)));
        disarm();
    }
    /* (7 calls for the output and 5 for the private path: 12 in all.) */
    calls = 0;
    CHECK(gzw_bip86_tweaked_keypair(ctx, &m, GZW_NET_SIGNET, 0, 0, 5, &kp, &o, &why));
    CHECK(calls == 12 && why == GZW_REASON_OK);
    CHECK(strcmp(o.address, good5.address) == 0);

    /* The account keys. */
    arm(ORDER, 1);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip86_account_xprv(ctx, &m, GZW_NET_SIGNET, 0, &c, &why));
    CHECK(why == GZW_REASON_INVALID_CHILD && all_zero(&c, sizeof(c)));
    arm(ORDER, 2);
    why = GZW_REASON_OK;
    memset(&cp, 0xAA, sizeof(cp));
    CHECK(!gzw_bip86_account_xpub(ctx, &m, GZW_NET_SIGNET, 0, &cp, &why));
    CHECK(why == GZW_REASON_INVALID_CHILD && all_zero(&cp, sizeof(cp)));
    disarm();

    gzw_wipe(&m, sizeof(m));
    gzw_wipe(&c, sizeof(c));
    gzw_wipe(&kp, sizeof(kp));
    secp256k1_context_destroy(ctx);
    printf("test_wallet_rare: %d checks, %d failed\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
