/* SPDX-License-Identifier: MIT */
/* The key port's keys (program/keys.c; docs/notes/keys.md): every vector of
 * tests/program/keys_vectors.h (from tools/keys_ref.py, cross-checked with
 * embit by tools/keys-vectors.py --embit), the network levels, argument
 * refusals, the epoch policy and the restore freeze, the scoped table, the
 * stand-in seed source, and wiping of what the key port keeps.
 *
 * THE KEYS HERE ARE TEST KEYS. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <secp256k1.h>

#include "keys.h"
#include "keys_standin.h"
#include "keys_vectors.h"

static int failures, checks;
#define CHECK(c)                                                                         \
    do {                                                                                 \
        checks++;                                                                        \
        if (!(c)) {                                                                      \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c);       \
            failures++;                                                                  \
        }                                                                                \
    } while (0)

static void unhex(const char *h, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) abort();
        out[i] = (uint8_t)v;
    }
}

static int hexeq(const uint8_t *b, const char *h, size_t n)
{
    uint8_t x[64];
    if (strlen(h) != 2 * n || n > sizeof x) return 0;
    unhex(h, x, n);
    return memcmp(b, x, n) == 0;
}

static int all(const void *p, int v, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++)
        if (b[i] != (uint8_t)v) return 0;
    return 1;
}

/* A seed source over a fixed seed, which can be emptied (locked). */
typedef struct {
    uint8_t seed[64];
    int have, calls;
} raw_t;

static int raw_seed(void *ctx, uint8_t out[64])
{
    raw_t *r = ctx;
    r->calls++;
    if (!r->have) {
        memset(out, 0, 64);
        return 0;
    }
    memcpy(out, r->seed, 64);
    return 1;
}

static int keys_over(gzp_keys_t *k, raw_t *r, const secp256k1_context *secp, int seed, gzw_network net)
{
    gzp_seed_source_t src = {raw_seed, r};
    memset(r, 0, sizeof *r);
    unhex(KV_SEED[seed], r->seed, 64);
    r->have = 1;
    return gzp_keys_init(k, secp, net, &src, NULL);
}

static void vectors(const secp256k1_context *secp)
{
    gzp_keys_t k;
    raw_t r;
    uint8_t sec[32], pub[33], spk[34];
    gzp_keys_err_t e;
    size_t i;
    for (i = 0; i < sizeof KV_LOBBY / sizeof KV_LOBBY[0]; i++) {
        CHECK(keys_over(&k, &r, secp, KV_LOBBY[i].seed, KV_LOBBY[i].net));
        CHECK(gzp_keys_lobby_raw(&k, KV_LOBBY[i].epoch, KV_LOBBY[i].index, sec, pub, &e) && e.why == GZP_KEYS_OK);
        CHECK(hexeq(sec, KV_LOBBY[i].sec, 32) && hexeq(pub, KV_LOBBY[i].pub, 33));
        /* Under the policy: only with the vector's epoch current. */
        CHECK(gzp_keys_lobby(&k, KV_LOBBY[i].epoch, KV_LOBBY[i].index, NULL, pub, &e) == (KV_LOBBY[i].epoch == 0));
        gzp_keys_set_epoch(&k, KV_LOBBY[i].epoch);
        CHECK(gzp_keys_lobby(&k, KV_LOBBY[i].epoch, KV_LOBBY[i].index, sec, pub, &e) && hexeq(sec, KV_LOBBY[i].sec, 32) &&
              hexeq(pub, KV_LOBBY[i].pub, 33));
        CHECK(gzp_keys_net_fn(&k, KV_LOBBY[i].epoch, KV_LOBBY[i].index, sec, NULL) == 1 && hexeq(sec, KV_LOBBY[i].sec, 32));
        memset(sec, 0xaa, 32);
        memset(pub, 0xaa, 33);
        CHECK(!gzp_keys_lobby(&k, KV_LOBBY[i].epoch ^ 1u, KV_LOBBY[i].index, sec, pub, &e) && e.why == GZP_KEYS_POLICY &&
              all(sec, 0, 32) && all(pub, 0, 33));
        gzp_keys_free(&k);
    }
    for (i = 0; i < sizeof KV_HOST / sizeof KV_HOST[0]; i++) {
        uint32_t kk = 99;
        CHECK(keys_over(&k, &r, secp, KV_HOST[i].seed, KV_HOST[i].net));
        CHECK(gzp_keys_host(&k, sec, pub, &kk, &e) && kk == KV_HOST[i].k && hexeq(sec, KV_HOST[i].sec, 32) &&
              hexeq(pub, KV_HOST[i].pub, 33));
        /* The host key does not follow the epoch, nor the freeze. */
        gzp_keys_set_epoch(&k, 0x1234);
        gzp_keys_freeze(&k, 1);
        CHECK(gzp_keys_host(&k, NULL, pub, NULL, &e) && hexeq(pub, KV_HOST[i].pub, 33));
        gzp_keys_free(&k);
    }
    for (i = 0; i < sizeof KV_WALLET / sizeof KV_WALLET[0]; i++) {
        gzw_bip86_output o;
        CHECK(keys_over(&k, &r, secp, KV_WALLET[i].seed, KV_WALLET[i].net));
        CHECK(gzp_keys_wallet_output(&k, KV_WALLET[i].change, KV_WALLET[i].j, &o, &e) &&
              hexeq(o.script_pubkey, KV_WALLET[i].spk, 34));
        if (KV_WALLET[i].change == 0) {
            int calls = r.calls;
            CHECK(gzp_keys_payout_script(&k, KV_WALLET[i].j, spk, &e) && hexeq(spk, KV_WALLET[i].spk, 34));
            CHECK(r.calls == calls); /* a payout script needs no seed */
        }
        gzp_keys_free(&k);
    }
}

static void networks_and_arguments(const secp256k1_context *secp)
{
    gzp_keys_t k;
    raw_t r;
    gzp_keys_err_t e;
    uint32_t v = 77;
    uint8_t sec[32], pub[33], spk[34], pub2[33];
    gzw_bip86_output o;
    CHECK(!gzp_keys_net_level(GZW_NET_MAINNET, &v) && v == 77);
    CHECK(!gzp_keys_net_level((gzw_network)99, &v) && v == 77);
    CHECK(gzp_keys_net_level(GZW_NET_TESTNET4, &v) && v == 1);
    CHECK(gzp_keys_net_level(GZW_NET_SIGNET, &v) && v == 2);
    CHECK(gzp_keys_net_level(GZW_NET_TESTNET, &v) && v == 3);
    CHECK(gzp_keys_net_level(GZW_NET_REGTEST, &v) && v == 4);
    CHECK(gzp_keys_net_level(GZW_NET_SIGNET, NULL));
    /* Mainnet is never derived: the key port refuses to be made for it. */
    CHECK(!keys_over(&k, &r, secp, 0, GZW_NET_MAINNET) && all(&k, 0, sizeof k));
    {
        gzp_seed_source_t src = {raw_seed, &r};
        CHECK(!gzp_keys_init(&k, secp, GZW_NET_MAINNET, &src, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
        CHECK(!gzp_keys_init(&k, NULL, GZW_NET_SIGNET, &src, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
        CHECK(!gzp_keys_init(&k, secp, GZW_NET_SIGNET, NULL, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
        CHECK(!gzp_keys_init(NULL, secp, GZW_NET_SIGNET, &src, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
        src.seed = NULL;
        CHECK(!gzp_keys_init(&k, secp, GZW_NET_SIGNET, &src, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
        src.seed = raw_seed;
        r.have = 0; /* locked: no seed */
        CHECK(!gzp_keys_init(&k, secp, GZW_NET_SIGNET, &src, &e) && e.why == GZP_KEYS_NO_SEED && all(&k, 0, sizeof k));
    }
    CHECK(keys_over(&k, &r, secp, 0, GZW_NET_SIGNET));
    memset(sec, 0xaa, 32);
    memset(pub, 0xaa, 33);
    CHECK(!gzp_keys_lobby_raw(&k, 0x80000000u, 1, sec, pub, &e) && e.why == GZP_KEYS_BAD_ARGUMENT && all(sec, 0, 32) &&
          all(pub, 0, 33));
    memset(sec, 0xaa, 32);
    CHECK(!gzp_keys_lobby_raw(&k, 0, 0x80000000u, sec, NULL, &e) && e.why == GZP_KEYS_BAD_ARGUMENT && all(sec, 0, 32));
    CHECK(!gzp_keys_lobby_raw(NULL, 0, 1, sec, NULL, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
    CHECK(!gzp_keys_lobby(NULL, 0, 1, sec, NULL, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
    CHECK(!gzp_keys_host(NULL, sec, pub, NULL, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
    memset(spk, 0xaa, 34);
    CHECK(!gzp_keys_payout_script(&k, 0x80000000u, spk, &e) && e.why == GZP_KEYS_BAD_ARGUMENT && all(spk, 0, 34));
    CHECK(!gzp_keys_payout_script(&k, 0, NULL, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
    CHECK(!gzp_keys_payout_script(NULL, 0, spk, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
    CHECK(!gzp_keys_wallet_output(&k, 2, 0, &o, &e) && e.why == GZP_KEYS_BAD_ARGUMENT && all(&o, 0, sizeof o));
    CHECK(!gzp_keys_wallet_output(&k, 0, 0x80000000u, &o, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
    CHECK(!gzp_keys_wallet_output(&k, 0, 0, NULL, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
    /* The highest index and epoch are keys. */
    CHECK(gzp_keys_lobby_raw(&k, 0x7fffffffu, 0x7fffffffu, NULL, pub, &e));
    /* The networks give different keys from one seed (contract-v2.md 13). */
    CHECK(gzp_keys_lobby_raw(&k, 0, 1, NULL, pub, &e));
    gzp_keys_free(&k);
    CHECK(keys_over(&k, &r, secp, 0, GZW_NET_TESTNET4) && gzp_keys_lobby_raw(&k, 0, 1, NULL, pub2, &e) &&
          memcmp(pub, pub2, 33) != 0);
    /* Locked after set-up: nothing more is derived; the payout script still is. */
    r.have = 0;
    memset(sec, 0xaa, 32);
    CHECK(!gzp_keys_lobby_raw(&k, 0, 1, sec, NULL, &e) && e.why == GZP_KEYS_NO_SEED && all(sec, 0, 32));
    CHECK(!gzp_keys_host(&k, sec, NULL, NULL, &e) && e.why == GZP_KEYS_NO_SEED);
    CHECK(!gzp_keys_wallet_output(&k, 0, 0, &o, &e) && e.why == GZP_KEYS_NO_SEED);
    CHECK(gzp_keys_payout_script(&k, 0, spk, &e) && spk[0] == 0x51 && spk[1] == 0x20);
    /* A scoped secret already held survives a lock of the seed; a new one cannot be made. */
    gzp_keys_free(&k);
    CHECK(all(&k, 0, sizeof k));
}

static void policy(const secp256k1_context *secp)
{
    gzp_keys_t k;
    raw_t r;
    gzp_keys_err_t e;
    uint8_t pub[33], sec[32];
    CHECK(keys_over(&k, &r, secp, 1, GZW_NET_SIGNET));
    CHECK(k.epoch == 0 && !k.frozen && gzp_keys_lobby(&k, 0, 1, NULL, pub, &e));
    gzp_keys_freeze(&k, 1); /* a restore start: nothing until the new epoch is saved */
    memset(sec, 0xaa, 32);
    CHECK(!gzp_keys_lobby(&k, 0, 1, sec, pub, &e) && e.why == GZP_KEYS_POLICY && all(sec, 0, 32) && all(pub, 0, 33));
    CHECK(!gzp_keys_net_fn(&k, 0, 1, sec, pub));
    gzp_keys_set_epoch(&k, 0x2a5f3c11u);
    CHECK(!gzp_keys_lobby(&k, 0x2a5f3c11u, 1, NULL, pub, &e));
    gzp_keys_freeze(&k, 0);
    CHECK(gzp_keys_lobby(&k, 0x2a5f3c11u, 1, NULL, pub, &e));
    /* The old epoch is recovery-only: never derived again (R3). */
    CHECK(!gzp_keys_lobby(&k, 0, 1, NULL, pub, &e) && e.why == GZP_KEYS_POLICY);
    gzp_keys_freeze(&k, 7);
    CHECK(k.frozen == 1);
    gzp_keys_free(&k);
}

static void scoped(const secp256k1_context *secp)
{
    gzp_keys_t k;
    raw_t r;
    gzp_keys_err_t e;
    uint8_t scope[32], digest[32], other[32], f[32], c[32], wf[32], wc[32];
    int i;
    CHECK(keys_over(&k, &r, secp, 0, GZW_NET_SIGNET));
    memset(scope, 1, 32);
    memset(digest, 2, 32);
    memset(other, 2, 32);
    other[31] = 3;
    CHECK(gzp_keys_scopes_held(&k) == 0 && !gzp_keys_scoped(&k, scope, digest, f, c));
    CHECK(gzp_keys_scope_open(&k, scope, digest, 0, 1, &e) && gzp_keys_scopes_held(&k) == 1);
    CHECK(gzp_keys_lobby_raw(&k, 0, 1, wc, NULL, &e) && gzp_keys_lobby_raw(&k, 0, 2, wf, NULL, &e));
    CHECK(gzp_keys_scoped(&k, scope, digest, f, c) && !memcmp(f, wf, 32) && !memcmp(c, wc, 32));
    /* Another values digest, by one byte: nothing, and the outputs zeroed. */
    CHECK(!gzp_keys_scoped(&k, scope, other, f, c) && all(f, 0, 32) && all(c, 0, 32));
    other[31] = 2;
    other[0] = 9;
    CHECK(!gzp_keys_scoped(&k, scope, other, f, c));
    CHECK(!gzp_keys_scoped(&k, scope, digest, NULL, c) && !gzp_keys_scoped(&k, scope, digest, f, NULL));
    CHECK(!gzp_keys_scoped(NULL, scope, digest, f, c) && !gzp_keys_scoped(&k, NULL, digest, f, c) &&
          !gzp_keys_scoped(&k, scope, NULL, f, c));
    /* Opening the same scope again replaces it: still one entry, the new pair. */
    CHECK(gzp_keys_scope_open(&k, scope, other, 0, 3, &e) && gzp_keys_scopes_held(&k) == 1);
    CHECK(!gzp_keys_scoped(&k, scope, digest, f, c));
    CHECK(gzp_keys_lobby_raw(&k, 0, 4, wf, NULL, &e) && gzp_keys_scoped(&k, scope, other, f, c) && !memcmp(f, wf, 32));
    /* Policy: no scoped secret under another epoch or while frozen; nothing held then. */
    scope[0] = 2;
    CHECK(!gzp_keys_scope_open(&k, scope, digest, 5, 1, &e) && e.why == GZP_KEYS_POLICY && gzp_keys_scopes_held(&k) == 1);
    gzp_keys_freeze(&k, 1);
    CHECK(!gzp_keys_scope_open(&k, scope, digest, 0, 1, &e) && gzp_keys_scopes_held(&k) == 1);
    gzp_keys_freeze(&k, 0);
    CHECK(!gzp_keys_scope_open(&k, scope, digest, 0, 0x7fffffffu, &e) && e.why == GZP_KEYS_BAD_ARGUMENT);
    CHECK(!gzp_keys_scope_open(NULL, scope, digest, 0, 1, &e) && !gzp_keys_scope_open(&k, NULL, digest, 0, 1, &e) &&
          !gzp_keys_scope_open(&k, scope, NULL, 0, 1, &e));
    /* Scopes that differ in their last byte only are two scopes. */
    {
        uint8_t s2[32];
        memset(s2, 1, 32); /* the scope held above, but for its last byte */
        s2[31] ^= 1;
        CHECK(gzp_keys_scope_open(&k, s2, digest, 0, 1, &e) && gzp_keys_scopes_held(&k) == 2);
        CHECK(!gzp_keys_scoped(&k, s2, other, f, c) && gzp_keys_scoped(&k, s2, digest, f, c));
        CHECK(gzp_keys_lobby_raw(&k, 0, 2, wf, NULL, &e) && !memcmp(f, wf, 32));
        gzp_keys_forget(&k, s2);
        CHECK(gzp_keys_scopes_held(&k) == 1 && !gzp_keys_scoped(&k, s2, digest, f, c));
    }
    /* Opening a held scope again and failing (another epoch) leaves nothing
     * held for it: the old secrets are wiped first. */
    {
        uint8_t s3[32];
        memset(s3, 0x33, 32);
        CHECK(gzp_keys_scope_open(&k, s3, digest, 0, 1, &e) && gzp_keys_scopes_held(&k) == 2);
        CHECK(!gzp_keys_scope_open(&k, s3, digest, 6, 1, &e) && e.why == GZP_KEYS_POLICY);
        CHECK(gzp_keys_scopes_held(&k) == 1 && !gzp_keys_scoped(&k, s3, digest, f, c));
        for (i = 0; i < GZP_KEYS_MAX_SCOPES; i++)
            if (!k.scopes[i].used) CHECK(all(&k.scopes[i], 0, sizeof k.scopes[i]));
    }
    /* Eight at most (GZ_NODE_MAX_SLOTS). */
    for (i = 0; i < 7; i++) {
        scope[0] = (uint8_t)(10 + i);
        CHECK(gzp_keys_scope_open(&k, scope, digest, 0, (uint32_t)(5 + 2 * i), &e));
    }
    CHECK(gzp_keys_scopes_held(&k) == 8);
    scope[0] = 99;
    CHECK(!gzp_keys_scope_open(&k, scope, digest, 0, 1, &e) && e.why == GZP_KEYS_FULL && gzp_keys_scopes_held(&k) == 8);
    /* Forget wipes the entry; another scope's stays. */
    scope[0] = 10;
    gzp_keys_forget(&k, scope);
    CHECK(gzp_keys_scopes_held(&k) == 7 && !gzp_keys_scoped(&k, scope, digest, f, c));
    for (i = 0; i < GZP_KEYS_MAX_SCOPES; i++)
        if (!k.scopes[i].used) CHECK(all(&k.scopes[i], 0, sizeof k.scopes[i]));
    scope[0] = 11;
    CHECK(gzp_keys_scoped(&k, scope, digest, f, c));
    gzp_keys_forget(&k, NULL);
    gzp_keys_forget(NULL, scope);
    scope[0] = 98;
    gzp_keys_forget(&k, scope); /* not held: nothing changes */
    CHECK(gzp_keys_scopes_held(&k) == 7);
    gzp_keys_forget_all(&k);
    CHECK(gzp_keys_scopes_held(&k) == 0 && all(k.scopes, 0, sizeof k.scopes));
    gzp_keys_forget_all(NULL);
    CHECK(gzp_keys_scopes_held(NULL) == 0);
    /* Free wipes the table too. */
    scope[0] = 1;
    CHECK(gzp_keys_scope_open(&k, scope, digest, 0, 1, &e));
    gzp_keys_free(&k);
    CHECK(all(&k, 0, sizeof k));
    gzp_keys_free(NULL);
}

static void standin(const secp256k1_context *secp)
{
    gzp_seed_standin_t s;
    gzp_seed_source_t src;
    gzp_keys_t k;
    uint8_t zero[32] = {0}, seed[64], pub[33];
    CHECK(gzp_seed_standin_from_entropy(&s, zero) == 0 && s.have && hexeq(s.seed, KV_SEED[1], 64));
    src = gzp_seed_standin_source(&s);
    CHECK(src.seed(src.ctx, seed) == 1 && hexeq(seed, KV_SEED[1], 64));
    CHECK(gzp_keys_init(&k, secp, GZW_NET_SIGNET, &src, NULL) && gzp_keys_host(&k, NULL, pub, NULL, NULL));
    gzp_seed_standin_close(&s);
    CHECK(all(&s, 0, sizeof s));
    memset(seed, 0xaa, 64);
    CHECK(src.seed(src.ctx, seed) == 0 && all(seed, 0, 64)); /* closed: no seed, and the output zeroed */
    CHECK(!gzp_keys_host(&k, NULL, pub, NULL, NULL));
    CHECK(src.seed(NULL, seed) == 0);
    gzp_keys_free(&k);
}

/* The passphrase layer's seed() (program/unlock.h): 0 with the seed, -1 not
 * unlocked (out untouched), -2 storage failed (out wiped). */
static int fake_answer;
static int fake_seed(void *ctx, uint8_t out64[64])
{
    (void)ctx;
    if (fake_answer == 0) unhex(KV_SEED[0], out64, 64);
    if (fake_answer == -2) memset(out64, 0, 64);
    if (fake_answer == -1) memset(out64, 0x5a, 64); /* a layer that breaks "untouched": still no seed, still wiped */
    return fake_answer;
}

static void from_unlock(const secp256k1_context *secp)
{
    gzp_unlock_t u;
    gzp_seed_source_t src;
    gzp_keys_t k;
    gzp_keys_err_t e;
    uint8_t out[64], pub[33];
    memset(&u, 0, sizeof u);
    u.seed = fake_seed;
    src = gzp_keys_seed_from_unlock(&u);
    fake_answer = 0;
    CHECK(src.seed(src.ctx, out) == 1 && hexeq(out, KV_SEED[0], 64));
    CHECK(gzp_keys_init(&k, secp, KV_HOST[0].net, &src, &e) && gzp_keys_host(&k, NULL, pub, NULL, &e) &&
          hexeq(pub, KV_HOST[0].pub, 33));
    fake_answer = -1; /* locked */
    memset(out, 0xaa, 64);
    CHECK(src.seed(src.ctx, out) == 0 && all(out, 0, 64));
    CHECK(!gzp_keys_host(&k, NULL, pub, NULL, &e) && e.why == GZP_KEYS_NO_SEED && all(pub, 0, 33));
    fake_answer = -2; /* storage failed */
    CHECK(src.seed(src.ctx, out) == 0 && all(out, 0, 64));
    CHECK(!gzp_keys_lobby_raw(&k, 0, 1, NULL, pub, &e) && e.why == GZP_KEYS_NO_SEED);
    fake_answer = 3; /* anything but 0 */
    CHECK(src.seed(src.ctx, out) == 0 && all(out, 0, 64));
    gzp_keys_free(&k);
    u.seed = NULL;
    CHECK(src.seed(src.ctx, out) == 0);
    src = gzp_keys_seed_from_unlock(NULL);
    CHECK(src.seed(src.ctx, out) == 0 && all(out, 0, 64));
}

int main(void)
{
    secp256k1_context *secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!secp) return 2;
    vectors(secp);
    networks_and_arguments(secp);
    policy(secp);
    scoped(secp);
    standin(secp);
    from_unlock(secp);
    secp256k1_context_destroy(secp);
    if (failures) {
        fprintf(stderr, "keys: %d of %d checks failed\n", failures, checks);
        return 1;
    }
    printf("keys: all %d checks passed\n", checks);
    return 0;
}
