/* SPDX-License-Identifier: MIT */
/* The key port's rare cases and its wipes (program/keys.c; keys.md 3, 8).
 *
 * Linked with -Wl,--wrap=HMAC,--wrap=gzw_wipe. HMAC: BIP 32's invalid child
 * (about 1 in 2^127) is forced at a chosen call, as wallet/tests/
 * test_wallet_rare.c does, so every level of keys.md 3 is reached: the
 * master and the levels above the epoch (the seed cannot be used), the
 * epoch, the index (that key only), and the host key's k (the next k).
 * gzw_wipe: every wipe keys.c asks for is recorded, so a dropped wipe of
 * the seed copy or of an extended key shows. THE KEYS HERE ARE TEST KEYS. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <secp256k1.h>

#include "keys.h"

unsigned char *__real_HMAC(const EVP_MD *md, const void *key, int key_len, const unsigned char *data, size_t data_len,
                           unsigned char *out, unsigned int *out_len);
unsigned char *__wrap_HMAC(const EVP_MD *md, const void *key, int key_len, const unsigned char *data, size_t data_len,
                           unsigned char *out, unsigned int *out_len);
void __real_gzw_wipe(void *p, size_t len);
void __wrap_gzw_wipe(void *p, size_t len);

static int force_at = 0; /* replace the HMAC result of this call (1-based); 0: none */
static uint32_t force_index = 0; /* or: replace the first call whose BIP 32 index is this one */
static int calls = 0;
static const unsigned char ORDER[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
                                        0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

unsigned char *__wrap_HMAC(const EVP_MD *md, const void *key, int key_len, const unsigned char *data, size_t data_len,
                           unsigned char *out, unsigned int *out_len)
{
    int by_index = force_index && data_len == 37 &&
                   ((uint32_t)data[33] << 24 | (uint32_t)data[34] << 16 | (uint32_t)data[35] << 8 | data[36]) == force_index;
    if (by_index) force_index = 0;
    if (++calls == force_at || by_index) {
        memcpy(out, ORDER, 32); /* left half not below the order: invalid */
        memset(out + 32, 0x5c, 32);
        if (out_len) *out_len = 64;
        return out;
    }
    return __real_HMAC(md, key, key_len, data, data_len, out, out_len);
}

#define MAX_WIPES 256
static struct {
    const void *p;
    size_t len;
} wipes[MAX_WIPES];
static int n_wipes;

void __wrap_gzw_wipe(void *p, size_t len)
{
    if (n_wipes < MAX_WIPES) {
        wipes[n_wipes].p = p;
        wipes[n_wipes].len = len;
        n_wipes++;
    }
    __real_gzw_wipe(p, len);
}

static int wiped(size_t len)
{
    int n = 0;
    for (int i = 0; i < n_wipes; i++) n += wipes[i].len == len;
    return n;
}

static int wiped_at(const void *p, size_t len)
{
    for (int i = 0; i < n_wipes; i++)
        if (wipes[i].p == p && wipes[i].len == len) return 1;
    return 0;
}

static int failures, checks;
#define CHECK(c)                                                                         \
    do {                                                                                 \
        checks++;                                                                        \
        if (!(c)) {                                                                      \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c);       \
            failures++;                                                                  \
        }                                                                                \
    } while (0)

static uint8_t SEED[64];

static int seed_fn(void *ctx, uint8_t out[64])
{
    (void)ctx;
    memcpy(out, SEED, 64);
    return 1;
}

static int all0(const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++)
        if (b[i]) return 0;
    return 1;
}

/* Count the HMAC calls of one operation, so a force can target each. */
static void arm(int at)
{
    calls = 0;
    force_at = at;
}

int main(void)
{
    secp256k1_context *secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    gzp_seed_source_t src = {seed_fn, NULL};
    gzp_keys_t k;
    gzp_keys_err_t e;
    uint8_t sec[32], pub[33], pub1[33], hpub[33], pub_next[33];
    uint32_t kk;
    int lvl, base;
    for (int i = 0; i < 64; i++) SEED[i] = (uint8_t)(0x30 + i);

    /* The calls of a lobby key: master, purpose, net, branch, epoch, index. */
    arm(0);
    CHECK(gzp_keys_init(&k, secp, GZW_NET_SIGNET, &src, &e));
    arm(0);
    CHECK(gzp_keys_lobby_raw(&k, 0, 1, sec, pub1, &e));
    base = calls;
    CHECK(base == 6);
    for (lvl = 0; lvl < 6; lvl++) {
        arm(lvl + 1);
        memset(sec, 0xaa, 32);
        memset(pub, 0xaa, 33);
        CHECK(!gzp_keys_lobby_raw(&k, 0, 1, sec, pub, &e) && all0(sec, 32) && all0(pub, 33));
        if (lvl == 0) CHECK(e.why == GZP_KEYS_UNUSABLE && e.level == 0);
        else CHECK(e.why == GZP_KEYS_INVALID_CHILD && e.level == (unsigned)lvl);
    }
    /* At the index: that key only; the pair's other key is still there. */
    arm(6);
    CHECK(!gzp_keys_lobby_raw(&k, 0, 1, NULL, pub, &e) && e.level == 5);
    CHECK(gzp_keys_lobby_raw(&k, 0, 2, NULL, pub, &e));
    arm(0);

    /* The host key: k = 0 invalid gives k = 1, the key at m/P'/net'/1'/1'. */
    CHECK(gzp_keys_host(&k, NULL, hpub, &kk, &e) && kk == 0);
    arm(5);
    CHECK(gzp_keys_host(&k, sec, pub_next, &kk, &e) && kk == 1 && memcmp(pub_next, hpub, 33) != 0);
    {
        gzw_xprv m, x;
        gzw_reason r;
        uint32_t path[4] = {GZP_KEYS_PURPOSE | GZW_HARDENED, 2 | GZW_HARDENED, 1 | GZW_HARDENED, 1 | GZW_HARDENED};
        gzw_xpub p;
        arm(0);
        CHECK(gzw_bip32_master(secp, SEED, 64, &m, &r) && gzw_bip32_derive_priv(secp, &m, path, 4, &x, &r) &&
              gzw_bip32_neuter(secp, &x, &p) && !memcmp(p.pubkey, pub_next, 33) && !memcmp(x.key, sec, 32));
    }
    /* Above k: no host key at all. */
    for (lvl = 1; lvl <= 4; lvl++) {
        arm(lvl);
        memset(pub, 0xaa, 33);
        CHECK(!gzp_keys_host(&k, NULL, pub, &kk, &e) && all0(pub, 33));
    }
    arm(0);

    /* Set-up: an invalid master, purpose, net or branch on either Gazpacho
     * branch, or on the BIP 86 account, means the seed cannot be used, and
     * nothing is left in the key port. Calls: 1-4 the lobby branch, 5-8 the
     * host branch, 9-12 the host's own lobby branch (2'), 13 the master
     * again, 14-16 m/86'/coin'/0'. */
    for (lvl = 1; lvl <= 16; lvl++) {
        arm(lvl);
        CHECK(!gzp_keys_init(&k, secp, GZW_NET_SIGNET, &src, &e) && e.why == GZP_KEYS_UNUSABLE && all0(&k, sizeof k));
    }
    /* Set-up checks the lobby branch itself: the first hardened 0' it derives
     * is the lobby branch (call 4), and it stops there. */
    arm(0);
    force_index = 0x80000000u;
    CHECK(!gzp_keys_init(&k, secp, GZW_NET_SIGNET, &src, &e) && e.why == GZP_KEYS_UNUSABLE && calls == 4);
    force_index = 0;
    arm(17);
    CHECK(gzp_keys_init(&k, secp, GZW_NET_SIGNET, &src, &e)); /* past set-up's calls: nothing forced */

    /* A scoped pair whose factory key is invalid holds nothing. */
    {
        uint8_t scope[32] = {7}, digest[32] = {8};
        arm(12); /* the second key's index step */
        CHECK(!gzp_keys_scope_open(&k, scope, digest, 0, 1, &e) && gzp_keys_scopes_held(&k) == 0);
    }
    /* A payout index with an invalid child: refused, so the allocator skips it. */
    {
        uint8_t spk[34];
        arm(0);
        CHECK(gzp_keys_payout_script(&k, 0, spk, &e)); /* public derivation: HMAC too */
        base = calls;
        arm(base);
        CHECK(!gzp_keys_payout_script(&k, 0, spk, &e) && e.why == GZP_KEYS_INVALID_CHILD && all0(spk, 34));
    }
    arm(0);

    /* Wipes: every derivation wipes its seed copy (64 bytes) and its
     * extended keys; set-up and a host key too. */
    n_wipes = 0;
    CHECK(gzp_keys_lobby_raw(&k, 0, 1, sec, NULL, &e));
    CHECK(wiped(64) == 1 && wiped(sizeof(gzw_xprv)) >= 1);
    n_wipes = 0;
    CHECK(gzp_keys_host(&k, sec, NULL, NULL, &e));
    CHECK(wiped(64) == 1 && wiped(sizeof(gzw_xprv)) >= 2);
    n_wipes = 0;
    {
        gzw_bip86_output o;
        CHECK(gzp_keys_wallet_output(&k, 0, 0, &o, &e) && wiped(64) == 1 && wiped(sizeof(gzw_xprv)) >= 1);
    }
    n_wipes = 0;
    {
        uint8_t scope[32] = {7}, digest[32] = {8};
        CHECK(gzp_keys_scope_open(&k, scope, digest, 0, 1, &e) && wiped(32) >= 4); /* two outputs zeroed first, two locals after */
        n_wipes = 0;
        gzp_keys_forget(&k, scope);
        CHECK(wiped(sizeof(gzp_keys_scope_t)) == 1);
        n_wipes = 0;
        gzp_keys_forget_all(&k);
        CHECK(wiped_at(k.scopes, sizeof k.scopes));
    }
    n_wipes = 0;
    gzp_keys_free(&k);
    CHECK(wiped_at(&k, sizeof k));
    n_wipes = 0;
    arm(2);
    CHECK(!gzp_keys_init(&k, secp, GZW_NET_SIGNET, &src, &e) && wiped(64) >= 1 && wiped_at(&k, sizeof k));
    arm(0);

    secp256k1_context_destroy(secp);
    if (failures) {
        fprintf(stderr, "keys rare: %d of %d checks failed\n", failures, checks);
        return 1;
    }
    printf("keys rare: all %d checks passed\n", checks);
    return 0;
}
