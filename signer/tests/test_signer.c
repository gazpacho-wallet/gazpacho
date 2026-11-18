/* The signer, stage 1 (docs/notes/signer.md; signer/include/gazpacho/signer.h).
 *
 * Vectors come from tools/signer-vectors.py (pure Python, independent of
 * this code), through signer/tests/vectors.txt. Every refusal is checked
 * three ways: its reason, every output zeroed, and the signer's bytes
 * unchanged (signer.md 2.1, "refusal-zeroes").
 *
 * usage: test_signer [VECTORS-FILE] */
#include "gazpacho/signer.h"
#include "gazpacho/round_msg.h"
#include "../../tests/check.h"

#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef GZ_SIGNER_VECTORS
#define GZ_SIGNER_VECTORS "signer/tests/vectors.txt"
#endif

static secp256k1_context *ctx;

/* ---- vectors ---- */

typedef struct { char name[64]; char value[160]; } vec_t;
static vec_t vecs[64];
static int n_vecs;

static void load(const char *path)
{
    char line[256];
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("FAIL cannot open %s\n", path);
        check_failures++;
        return;
    }
    while (fgets(line, sizeof line, f) && n_vecs < 64) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%63s %159s", vecs[n_vecs].name, vecs[n_vecs].value) == 2) n_vecs++;
    }
    fclose(f);
}

static const char *vget(const char *name)
{
    for (int i = 0; i < n_vecs; i++)
        if (strcmp(vecs[i].name, name) == 0) return vecs[i].value;
    printf("FAIL no vector %s\n", name);
    check_failures++;
    return NULL;
}

static int unhex(const char *s, uint8_t *out, size_t n)
{
    if (!s || strlen(s) != 2 * n) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

static void vhex(const char *name, uint8_t *out, size_t n)
{
    memset(out, 0, n);
    CHECK(unhex(vget(name), out, n));
}

/* ---- the world: a seed source and a random port that count their calls ---- */

typedef struct { uint8_t seed[64]; int locked, calls; } seed_t;
static int seed_fn(void *c, uint8_t out[64])
{
    seed_t *s = c;
    s->calls++;
    if (s->locked) return 0;
    memcpy(out, s->seed, 64);
    return 1;
}

typedef struct { int calls, ordinary; uint8_t next; } rnd_t;
static void fill(void *c, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    rnd_t *r = c;
    r->calls++;
    if (purpose == GZ_RANDOM_ORDINARY) r->ordinary++;
    for (size_t i = 0; i < len; i++) out[i] = r->next++;
}

static seed_t g_seed;
static rnd_t g_rnd;

static gz_sg_config_t config(gz_sg_role_t role)
{
    gz_sg_config_t c;
    memset(&c, 0, sizeof c);
    c.secp = ctx;
    c.role = role;
    c.network = GZW_NET_SIGNET;
    c.epoch = 7;
    c.frozen = 0;
    c.seed.seed = seed_fn;
    c.seed.ctx = &g_seed;
    c.random.fill = fill;
    c.random.ctx = &g_rnd;
    return c;
}

static gz_signer_t *make(gz_sg_role_t role, int frozen)
{
    gz_sg_config_t c = config(role);
    gz_signer_t *sg = malloc(gz_signer_size());
    c.frozen = frozen;
    CHECK(sg && gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_OK);
    return sg;
}

static void drop(gz_signer_t *sg)
{
    gz_signer_wipe(sg);
    free(sg);
}

static int all(const void *p, int byte, size_t n)
{
    const uint8_t *q = p;
    for (size_t i = 0; i < n; i++)
        if (q[i] != (uint8_t)byte) return 0;
    return 1;
}

/* A copy of the signer's bytes, to check that a refusal changed nothing. */
static uint8_t *snap(const gz_signer_t *sg)
{
    uint8_t *s = malloc(gz_signer_size());
    memcpy(s, sg, gz_signer_size());
    return s;
}
static int same(const gz_signer_t *sg, uint8_t *s)
{
    int r = memcmp(sg, s, gz_signer_size()) == 0;
    free(s);
    return r;
}

static gz_sg_slot_t slot_of(uint32_t epoch, uint32_t index)
{
    gz_sg_slot_t s;
    vhex("scope", s.scope, 32);
    s.epoch = epoch;
    s.key_index = index;
    return s;
}

static int verify(const uint8_t sig[64], const uint8_t msg[32], const uint8_t pub33[33])
{
    secp256k1_xonly_pubkey pk;
    return secp256k1_xonly_pubkey_parse(ctx, &pk, pub33 + 1) && secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &pk);
}

/* ---- init ---- */

static void test_init(void)
{
    gz_sg_config_t c;
    gz_signer_t *sg = malloc(gz_signer_size());
    uint8_t sig[64], scope[32] = {0};
    g_seed.calls = 0;

    c = config(GZ_SG_ROLE_HOST);
    CHECK(gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_OK);
    CHECK(g_seed.calls == 0);   /* nothing is taken from the seed source yet */
    CHECK(gz_signer_init(sg, gz_signer_size() - 1, &c) == GZ_SG_E_ARG);
    CHECK(gz_signer_init(NULL, gz_signer_size(), &c) == GZ_SG_E_ARG);
    CHECK(gz_signer_init(sg, gz_signer_size(), NULL) == GZ_SG_E_ARG);
    c = config(GZ_SG_ROLE_HOST); c.network = GZW_NET_MAINNET;
    CHECK(gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_E_ARG);
    c = config(GZ_SG_ROLE_HOST); c.network = (gzw_network)99;
    CHECK(gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_E_ARG);
    c = config(GZ_SG_ROLE_HOST); c.role = (gz_sg_role_t)0;
    CHECK(gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_E_ARG);
    c = config(GZ_SG_ROLE_HOST); c.secp = NULL;
    CHECK(gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_E_ARG);
    c = config(GZ_SG_ROLE_HOST); c.seed.seed = NULL;
    CHECK(gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_E_ARG);
    c = config(GZ_SG_ROLE_HOST); c.random.fill = NULL;
    CHECK(gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_E_ARG);
    c = config(GZ_SG_ROLE_HOST); c.epoch = GZ_SG_INDEX_LIMIT;
    CHECK(gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_E_ARG);
    c = config(GZ_SG_ROLE_HOST); c.frozen = 2;
    CHECK(gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_E_ARG);
    /* a refused init leaves memory nothing can use */
    memset(sig, 0xff, 64);
    CHECK(gz_sg_sign_envelope(sg, GZ_SG_KEY_HOST, scope, 72, NULL, 0, 0, sig) == GZ_SG_E_ARG);
    CHECK(all(sig, 0, 64));
    /* every test network is accepted */
    for (int n = GZW_NET_TESTNET; n <= GZW_NET_REGTEST; n++) {
        c = config(GZ_SG_ROLE_MEMBER); c.network = (gzw_network)n;
        CHECK(gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_OK);
    }
    gz_signer_wipe(sg);
    free(sg);
}

/* ---- section 3: the tables ---- */

static int expect_kind(gz_sg_role_t role, unsigned k, int *det)
{
    static const unsigned host[] = {18, 28, 30, 32, 34, 64, 68, 72, 74, 78, 81};
    static const unsigned member[] = {16, 20, 22, 24, 26, 66, 70, 76, 78, 80};
    const unsigned *list = role == GZ_SG_ROLE_HOST ? host : member;
    size_t n = role == GZ_SG_ROLE_HOST ? sizeof host / sizeof host[0] : sizeof member / sizeof member[0];
    *det = role == GZ_SG_ROLE_HOST && (k == 72 || k == 78);
    for (size_t i = 0; i < n; i++)
        if (list[i] == k) return 1;
    *det = 0;
    return 0;
}

static void test_tables(void)
{
    int bad = 0, det, want_det;
    size_t n;
    const gz_sg_purpose_t *p;
    for (unsigned k = 0; k <= 0xffffu; k++) {
        int h = gz_sg_kind_allowed(GZ_SG_ROLE_HOST, GZ_SG_KEY_HOST, (uint16_t)k, &det);
        if (h != expect_kind(GZ_SG_ROLE_HOST, k, &want_det) || det != want_det) bad++;
        int m = gz_sg_kind_allowed(GZ_SG_ROLE_MEMBER, GZ_SG_KEY_CONTRIBUTION, (uint16_t)k, &det);
        if (m != expect_kind(GZ_SG_ROLE_MEMBER, k, &want_det) || det != want_det) bad++;
        /* no other key, and no key of the other role, signs any kind */
        for (int key = 0; key <= 5; key++) {
            if (key != GZ_SG_KEY_HOST && gz_sg_kind_allowed(GZ_SG_ROLE_HOST, (gz_sg_key_t)key, (uint16_t)k, &det)) bad++;
            if (key != GZ_SG_KEY_CONTRIBUTION &&
                gz_sg_kind_allowed(GZ_SG_ROLE_MEMBER, (gz_sg_key_t)key, (uint16_t)k, &det)) bad++;
        }
        if (gz_sg_kind_allowed((gz_sg_role_t)0, GZ_SG_KEY_HOST, (uint16_t)k, NULL)) bad++;
    }
    CHECK(bad == 0);
    CHECK(gz_sg_kind_allowed(GZ_SG_ROLE_HOST, GZ_SG_KEY_HOST, 72, NULL) == 1);   /* NULL is allowed */

    CHECK(gz_sg_may_sign_tag(GZ_SG_ROLE_HOST, GZ_SG_KEY_HOST, "gazpacho/msg"));
    CHECK(gz_sg_may_sign_tag(GZ_SG_ROLE_HOST, GZ_SG_KEY_HOST, "gazpacho/terms/outer"));
    CHECK(gz_sg_may_sign_tag(GZ_SG_ROLE_HOST, GZ_SG_KEY_HOST, "gazpacho/terms/current"));
    CHECK(gz_sg_may_sign_tag(GZ_SG_ROLE_MEMBER, GZ_SG_KEY_CONTRIBUTION, "gazpacho/msg"));
    CHECK(gz_sg_may_sign_tag(GZ_SG_ROLE_MEMBER, GZ_SG_KEY_CONTRIBUTION, "gazpacho/nonce"));
    CHECK(!gz_sg_may_sign_tag(GZ_SG_ROLE_MEMBER, GZ_SG_KEY_CONTRIBUTION, "gazpacho/terms/outer"));
    CHECK(!gz_sg_may_sign_tag(GZ_SG_ROLE_MEMBER, GZ_SG_KEY_HOST, "gazpacho/msg"));
    CHECK(!gz_sg_may_sign_tag(GZ_SG_ROLE_HOST, GZ_SG_KEY_CONTRIBUTION, "gazpacho/msg"));
    CHECK(!gz_sg_may_sign_tag(GZ_SG_ROLE_HOST, GZ_SG_KEY_FACTORY, "gazpacho/msg"));
    CHECK(!gz_sg_may_sign_tag(GZ_SG_ROLE_MEMBER, GZ_SG_KEY_FACTORY, "gazpacho/msg"));
    CHECK(gz_sg_may_sign_tag(GZ_SG_ROLE_MEMBER, GZ_SG_KEY_FACTORY, "gazpacho/bind"));   /* until S6 */
    CHECK(!gz_sg_may_sign_tag(GZ_SG_ROLE_HOST, GZ_SG_KEY_WALLET, "gazpacho/msg"));
    CHECK(!gz_sg_may_sign_tag(GZ_SG_ROLE_HOST, GZ_SG_KEY_HOST, "gazpacho" "/msgx"));
    CHECK(!gz_sg_may_sign_tag(GZ_SG_ROLE_HOST, GZ_SG_KEY_HOST, "gazpacho" "/ms"));
    CHECK(!gz_sg_may_sign_tag(GZ_SG_ROLE_HOST, GZ_SG_KEY_HOST, NULL));

    p = gz_sg_purposes(&n);
    CHECK(n == 5);
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) CHECK(!(p[i].key == p[j].key && p[i].role == p[j].role));
        for (size_t t = 0; p[i].tags[t]; t++) {
            CHECK(strncmp(p[i].tags[t], "gazpacho" "/", 9) == 0);   /* never a TapSighash or BIP 340's own tags */
            CHECK(gz_sg_may_sign_tag(p[i].role, p[i].key, p[i].tags[t]));
        }
        if (p[i].key == GZ_SG_KEY_WALLET) {
            CHECK(strncmp(p[i].path, "m/86'/", 6) == 0 && p[i].branch == 86 && p[i].tags[0] == NULL &&
                  p[i].sighash == GZ_SG_SIGHASH_BIP86_KEYPATH && !p[i].ecdh);
        } else {
            CHECK(strncmp(p[i].path, "m/254315617'/net'/", 18) == 0);
        }
        if (p[i].key == GZ_SG_KEY_FACTORY) CHECK(p[i].sighash == GZ_SG_SIGHASH_TREE_MUSIG && !p[i].ecdh && !p[i].stage1);
        if (p[i].key == GZ_SG_KEY_HOST) CHECK(p[i].branch == 1 && p[i].ecdh && p[i].stage1 && p[i].role == GZ_SG_ROLE_HOST);
        if (p[i].key == GZ_SG_KEY_CONTRIBUTION)
            CHECK(p[i].branch == 0 && p[i].ecdh && p[i].stage1 && p[i].role == GZ_SG_ROLE_MEMBER);
        if (p[i].key == GZ_SG_KEY_FACTORY && p[i].role == GZ_SG_ROLE_HOST) CHECK(p[i].branch == 2);
        if (p[i].key == GZ_SG_KEY_FACTORY && p[i].role == GZ_SG_ROLE_MEMBER) CHECK(p[i].branch == 0);
    }
}

/* ---- keys ---- */

static void test_keys(void)
{
    uint8_t want[33], pub[33], cpub[33], fpub[33];
    gz_signer_t *h = make(GZ_SG_ROLE_HOST, 0), *m = make(GZ_SG_ROLE_MEMBER, 0);
    gz_sg_slot_t s = slot_of(7, 4);
    uint8_t *before;

    /* locked: no key, nothing changed */
    g_seed.locked = 1;
    memset(pub, 0xff, 33);
    before = snap(h);
    CHECK(gz_sg_host_pub(h, pub) == GZ_SG_E_NO_SEED);
    CHECK(all(pub, 0, 33));
    CHECK(same(h, before));
    g_seed.locked = 0;

    g_seed.calls = 0;
    vhex("host_pub", want, 33);
    CHECK(gz_sg_host_pub(h, pub) == GZ_SG_OK && memcmp(pub, want, 33) == 0);
    CHECK(g_seed.calls == 1);
    CHECK(gz_sg_host_pub(h, pub) == GZ_SG_OK && memcmp(pub, want, 33) == 0);
    CHECK(g_seed.calls == 1);   /* held for the signer's life */
    CHECK(gz_sg_host_pub(h, NULL) == GZ_SG_E_ARG);

    memset(pub, 0xff, 33);
    CHECK(gz_sg_host_pub(m, pub) == GZ_SG_E_KIND);
    CHECK(all(pub, 0, 33));

    /* a member's slot: contribution at index 4, factory at 5, branch 0 */
    CHECK(gz_sg_slot_add(m, &s, cpub, fpub) == GZ_SG_OK);
    vhex("member_contribution_pub", want, 33);
    CHECK(memcmp(cpub, want, 33) == 0);
    vhex("member_factory_pub", want, 33);
    CHECK(memcmp(fpub, want, 33) == 0);

    /* a host's slot: its long-term key, and its own factory key on branch 2 */
    CHECK(gz_sg_slot_add(h, &s, cpub, fpub) == GZ_SG_OK);
    vhex("host_pub", want, 33);
    CHECK(memcmp(cpub, want, 33) == 0);
    vhex("host_factory_pub", want, 33);
    CHECK(memcmp(fpub, want, 33) == 0);

    /* factory_pub may be NULL */
    gz_sg_slot_drop(m, s.scope);
    CHECK(gz_sg_slot_add(m, &s, cpub, NULL) == GZ_SG_OK);
    vhex("member_contribution_pub", want, 33);
    CHECK(memcmp(cpub, want, 33) == 0);

    /* a host whose first slot derives its key: the same key */
    drop(h);
    h = make(GZ_SG_ROLE_HOST, 0);
    CHECK(gz_sg_slot_add(h, &s, cpub, fpub) == GZ_SG_OK);
    CHECK(gz_sg_host_pub(h, pub) == GZ_SG_OK && memcmp(pub, cpub, 33) == 0);
    drop(h);
    drop(m);
}

/* ---- slots ---- */

static void slot_refused(gz_signer_t *sg, const gz_sg_slot_t *s, gz_sg_err_t want, int line)
{
    uint8_t cpub[33], fpub[33];
    uint8_t *before = snap(sg);
    memset(cpub, 0xff, 33);
    memset(fpub, 0xff, 33);
    gz_sg_err_t e = gz_sg_slot_add(sg, s, cpub, fpub);
    if (e != want) printf("  slot_add at line %d: %d, wanted %d\n", line, (int)e, (int)want);
    CHECK(e == want);
    CHECK(all(cpub, 0, 33) && all(fpub, 0, 33));
    CHECK(same(sg, before));
}

static void test_slots(gz_sg_role_t role)
{
    gz_signer_t *sg = make(role, 0), *fz = make(role, 1);
    gz_sg_slot_t s = slot_of(7, 4), t;
    uint8_t cpub[33], fpub[33];

    slot_refused(sg, &(gz_sg_slot_t){{0}, 6, 4}, GZ_SG_E_EPOCH, __LINE__);    /* another epoch */
    slot_refused(sg, &(gz_sg_slot_t){{0}, 8, 4}, GZ_SG_E_EPOCH, __LINE__);
    slot_refused(fz, &s, GZ_SG_E_EPOCH, __LINE__);                              /* frozen */
    t = s; t.key_index = 5;
    slot_refused(sg, &t, GZ_SG_E_ARG, __LINE__);                                /* odd */
    t.key_index = GZ_SG_INDEX_LIMIT;
    slot_refused(sg, &t, GZ_SG_E_ARG, __LINE__);                                /* even, too high */
    t.key_index = GZ_SG_INDEX_LIMIT + 2;
    slot_refused(sg, &t, GZ_SG_E_ARG, __LINE__);
    slot_refused(sg, NULL, GZ_SG_E_ARG, __LINE__);
    CHECK(gz_sg_slot_add(sg, &s, NULL, fpub) == GZ_SG_E_ARG);
    g_seed.locked = 1;
    slot_refused(sg, &s, GZ_SG_E_NO_SEED, __LINE__);                            /* locked */
    g_seed.locked = 0;

    /* the highest index whose factory key still fits */
    t = s; t.scope[0] ^= 0x80; t.key_index = GZ_SG_INDEX_LIMIT - 2;
    CHECK(gz_sg_slot_add(sg, &t, cpub, fpub) == GZ_SG_OK);
    gz_sg_slot_drop(sg, t.scope);

    CHECK(gz_sg_slot_add(sg, &s, cpub, fpub) == GZ_SG_OK);
    slot_refused(sg, &s, GZ_SG_E_SLOT, __LINE__);                               /* twice */
    t = s; t.key_index = 10;
    slot_refused(sg, &t, GZ_SG_E_SLOT, __LINE__);                               /* same scope, another index */

    /* the table fills at GZ_SG_MAX_SLOTS */
    for (int i = 1; i < GZ_SG_MAX_SLOTS; i++) {
        t = s; t.scope[31] = (uint8_t)(t.scope[31] + i); t.key_index = (uint32_t)(2 * i + 10);
        CHECK(gz_sg_slot_add(sg, &t, cpub, fpub) == GZ_SG_OK);
    }
    t = s; t.scope[30] ^= 1;
    slot_refused(sg, &t, GZ_SG_E_SLOT, __LINE__);                               /* full */
    /* dropping one makes room; dropping an unknown scope changes nothing */
    {
        uint8_t *before = snap(sg);
        gz_sg_slot_drop(sg, t.scope);
        gz_sg_slot_drop(sg, NULL);
        CHECK(same(sg, before));
    }
    gz_sg_slot_drop(sg, s.scope);
    CHECK(gz_sg_slot_add(sg, &t, cpub, fpub) == GZ_SG_OK);
    drop(sg);
    drop(fz);
}

/* ---- envelopes ---- */

static void env_refused(gz_signer_t *sg, gz_sg_key_t key, const uint8_t *scope, uint16_t kind, const uint8_t *rec,
                        size_t len, int fresh, gz_sg_err_t want, int line)
{
    uint8_t sig[64];
    uint8_t *before = snap(sg);
    int calls = g_rnd.calls;
    memset(sig, 0xff, 64);
    gz_sg_err_t e = gz_sg_sign_envelope(sg, key, scope, kind, rec, len, fresh, sig);
    if (e != want) printf("  sign_envelope at line %d: %d, wanted %d\n", line, (int)e, (int)want);
    CHECK(e == want);
    CHECK(all(sig, 0, 64));
    CHECK(same(sg, before));
    CHECK(g_rnd.calls == calls);   /* a refusal draws nothing */
}

#define ENV_REFUSED(sg, key, scope, kind, rec, len, fresh, want) \
    env_refused(sg, key, scope, kind, rec, len, fresh, want, __LINE__)

/* A stream of one record of type 2 whose whole length is `total` (>= 6). */
static size_t one_record(uint8_t *buf, size_t total)
{
    size_t body;
    memset(buf, 0x5a, total);
    buf[0] = 2;
    if (total - 4 < 0x10000u && total - 4 >= 0xfd) {
        body = total - 4;
        buf[1] = 0xfd; buf[2] = (uint8_t)(body >> 8); buf[3] = (uint8_t)body;
    } else {
        body = total - 6;
        buf[1] = 0xfe; buf[2] = (uint8_t)(body >> 24); buf[3] = (uint8_t)(body >> 16);
        buf[4] = (uint8_t)(body >> 8); buf[5] = (uint8_t)body;
    }
    return total;
}

static void test_envelope(void)
{
    gz_signer_t *h = make(GZ_SG_ROLE_HOST, 0), *m = make(GZ_SG_ROLE_MEMBER, 0);
    gz_sg_slot_t s = slot_of(7, 4);
    uint8_t scope[32], other[32], rec[8], hp[33], mp[33], want_sig[64], want_h[32], hh[32], sig[64], sig2[64];
    uint8_t cpub[33];
    static uint8_t big[GZ_RMSG_MAX_WHOLE];
    int calls;

    vhex("scope", scope, 32);
    vhex("records", rec, 8);
    memcpy(other, scope, 32);
    other[0] ^= 1;
    CHECK(gz_sg_slot_add(h, &s, hp, NULL) == GZ_SG_OK);
    CHECK(gz_sg_slot_add(m, &s, mp, NULL) == GZ_SG_OK);

    /* the hash the signer computes is messages.md 4.3's, from the typed fields */
    vhex("msg_hash_72", want_h, 32);
    gz_rmsg_hash(72, scope, rec, 8, hh);
    CHECK(memcmp(hh, want_h, 32) == 0);

#ifdef GZ_SG_VECTORS
    /* the vectors build: fixed aux_rand for the host's rebuilt kinds, the vectors exactly */
    calls = g_rnd.calls;
    vhex("host_sig_72", want_sig, 64);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, scope, 72, rec, 8, 0, sig) == GZ_SG_OK);
    CHECK(memcmp(sig, want_sig, 64) == 0);
    vhex("host_sig_78_empty", want_sig, 64);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, scope, 78, NULL, 0, 0, sig) == GZ_SG_OK);
    CHECK(memcmp(sig, want_sig, 64) == 0);
    CHECK(g_rnd.calls == calls);   /* nothing drawn */
#else
    /* production: fixed aux_rand never, for any kind, key or role */
    {
        int bad = 0;
        for (unsigned k = 0; k <= 0xffffu; k++) {
            memset(sig, 0xff, 64);
            if (gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, scope, (uint16_t)k, rec, 8, 0, sig) == GZ_SG_OK || !all(sig, 0, 64))
                bad++;
            memset(sig, 0xff, 64);
            if (gz_sg_sign_envelope(m, GZ_SG_KEY_CONTRIBUTION, scope, (uint16_t)k, rec, 8, 0, sig) == GZ_SG_OK ||
                !all(sig, 0, 64))
                bad++;
        }
        CHECK(bad == 0);
    }
    ENV_REFUSED(h, GZ_SG_KEY_HOST, scope, 72, rec, 8, 0, GZ_SG_E_KIND);
    ENV_REFUSED(h, GZ_SG_KEY_HOST, scope, 78, NULL, 0, 0, GZ_SG_E_KIND);
    /* the kinds the vectors sign with fixed aux_rand: here one fresh draw
     * each, a valid signature, never the vector's and never twice the same */
    calls = g_rnd.calls;
    vhex("host_sig_72", want_sig, 64);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, scope, 72, rec, 8, 1, sig) == GZ_SG_OK);
    CHECK(g_rnd.calls == calls + 1);
    CHECK(verify(sig, want_h, hp) && memcmp(sig, want_sig, 64) != 0);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, scope, 72, rec, 8, 1, sig2) == GZ_SG_OK);
    CHECK(verify(sig2, want_h, hp) && memcmp(sig2, sig, 64) != 0 && memcmp(sig2, want_sig, 64) != 0);
    vhex("msg_hash_78_empty", hh, 32);
    vhex("host_sig_78_empty", want_sig, 64);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, scope, 78, NULL, 0, 1, sig) == GZ_SG_OK);
    CHECK(verify(sig, hh, hp) && memcmp(sig, want_sig, 64) != 0);
    CHECK(g_rnd.calls == calls + 3);
#endif

    /* fresh: one ordinary draw of aux_rand, a valid signature, never twice the same */
    calls = g_rnd.calls;
    int ord = g_rnd.ordinary;
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, scope, 18, rec, 8, 1, sig) == GZ_SG_OK);
    CHECK(g_rnd.calls == calls + 1 && g_rnd.ordinary == ord + 1);
    gz_rmsg_hash(18, scope, rec, 8, hh);
    CHECK(verify(sig, hh, hp));
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, scope, 18, rec, 8, 1, sig2) == GZ_SG_OK);
    CHECK(verify(sig2, hh, hp) && memcmp(sig, sig2, 64) != 0);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, scope, 72, rec, 8, 1, sig) == GZ_SG_OK);   /* fresh allowed too */

    /* a member: its contribution key over the vector's hash */
    vhex("msg_hash_22", want_h, 32);
    CHECK(gz_sg_sign_envelope(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, rec, 8, 1, sig) == GZ_SG_OK);
    vhex("member_contribution_pub", cpub, 33);
    CHECK(memcmp(cpub, mp, 33) == 0 && verify(sig, want_h, cpub));
    CHECK(!verify(sig, want_h, hp));

    /* 1. the key matches the role: never the factory or a wallet key */
    ENV_REFUSED(h, GZ_SG_KEY_CONTRIBUTION, scope, 72, rec, 8, 0, GZ_SG_E_KIND);
    ENV_REFUSED(h, GZ_SG_KEY_FACTORY, scope, 72, rec, 8, 0, GZ_SG_E_KIND);
    ENV_REFUSED(h, GZ_SG_KEY_FACTORY, scope, 18, rec, 8, 1, GZ_SG_E_KIND);
    ENV_REFUSED(h, GZ_SG_KEY_WALLET, scope, 18, rec, 8, 1, GZ_SG_E_KIND);
    ENV_REFUSED(h, (gz_sg_key_t)0, scope, 18, rec, 8, 1, GZ_SG_E_KIND);
    ENV_REFUSED(m, GZ_SG_KEY_HOST, scope, 22, rec, 8, 1, GZ_SG_E_KIND);
    ENV_REFUSED(m, GZ_SG_KEY_FACTORY, scope, 22, rec, 8, 1, GZ_SG_E_KIND);
    ENV_REFUSED(m, GZ_SG_KEY_WALLET, scope, 22, rec, 8, 1, GZ_SG_E_KIND);
    /* 2. the kind is in the key's row */
    ENV_REFUSED(h, GZ_SG_KEY_HOST, scope, 22, rec, 8, 1, GZ_SG_E_KIND);    /* a member's kind on the host */
    ENV_REFUSED(h, GZ_SG_KEY_HOST, scope, 66, rec, 8, 1, GZ_SG_E_KIND);
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 18, rec, 8, 1, GZ_SG_E_KIND);   /* the host's on a member */
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 72, rec, 8, 1, GZ_SG_E_KIND);
    ENV_REFUSED(h, GZ_SG_KEY_HOST, scope, 100, rec, 8, 1, GZ_SG_E_KIND);   /* no such kind */
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 32767, rec, 8, 1, GZ_SG_E_KIND);
    /* 3. deterministic only for the host's rebuilt kinds */
    ENV_REFUSED(h, GZ_SG_KEY_HOST, scope, 64, rec, 8, 0, GZ_SG_E_KIND);
    ENV_REFUSED(h, GZ_SG_KEY_HOST, scope, 18, rec, 8, 0, GZ_SG_E_KIND);
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 78, rec, 8, 0, GZ_SG_E_KIND);
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, rec, 8, 0, GZ_SG_E_KIND);
    /* 4. length: one envelope's records, or a reassembled host round message */
    CHECK(gz_sg_sign_envelope(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, big, one_record(big, GZ_RMSG_MAX_RECORDS_ONE), 1,
                              sig) == GZ_SG_OK);
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, big, one_record(big, GZ_RMSG_MAX_RECORDS_ONE + 1), 1, GZ_SG_E_ARG);
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 66, big, one_record(big, GZ_RMSG_MAX_RECORDS_ONE + 1), 1, GZ_SG_E_ARG);
    ENV_REFUSED(h, GZ_SG_KEY_HOST, scope, 18, big, one_record(big, GZ_RMSG_MAX_RECORDS_ONE + 1), 1, GZ_SG_E_ARG);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, scope, 64, big, one_record(big, GZ_RMSG_MAX_RECORDS_ONE + 1), 1,
                              sig) == GZ_SG_OK);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, scope, 64, big, one_record(big, GZ_RMSG_MAX_WHOLE - GZ_RMSG_HEADER),
                              1, sig) == GZ_SG_OK);
    ENV_REFUSED(h, GZ_SG_KEY_HOST, scope, 64, big, one_record(big, GZ_RMSG_MAX_WHOLE - GZ_RMSG_HEADER + 1), 1,
                GZ_SG_E_ARG);
    /* 5. a well-formed stream, without the signature record */
    {
        static const uint8_t sig240[] = {0x02, 0x01, 0xaa, 0xf0, 0x00};
        static const uint8_t only240[] = {0xf0, 0x00};
        static const uint8_t past240[] = {0xf1, 0x00};
        static const uint8_t big_type[] = {0xfd, 0x01, 0x00, 0x00};
        static const uint8_t down[] = {0x05, 0x00, 0x02, 0x00};
        static const uint8_t twice[] = {0x02, 0x00, 0x02, 0x00};
        static const uint8_t wide[] = {0xfd, 0x00, 0x05, 0x00};
        static const uint8_t wide_len[] = {0x02, 0xfd, 0x00, 0x01, 0xaa};
        static const uint8_t past_end[] = {0x02, 0x05, 0xaa};
        static const uint8_t cut[] = {0xfd, 0x01};
        static const uint8_t no_len[] = {0x02};
        static const uint8_t t239[] = {0x02, 0x00, 0xef, 0x01, 0x00};
        static const uint8_t zero_type[] = {0x00, 0x01, 0x07};
        ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, sig240, sizeof sig240, 1, GZ_SG_E_ARG);
        ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, only240, sizeof only240, 1, GZ_SG_E_ARG);
        ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, past240, sizeof past240, 1, GZ_SG_E_ARG);
        ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, big_type, sizeof big_type, 1, GZ_SG_E_ARG);
        ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, down, sizeof down, 1, GZ_SG_E_ARG);
        ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, twice, sizeof twice, 1, GZ_SG_E_ARG);
        ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, wide, sizeof wide, 1, GZ_SG_E_ARG);
        ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, wide_len, sizeof wide_len, 1, GZ_SG_E_ARG);
        ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, past_end, sizeof past_end, 1, GZ_SG_E_ARG);
        ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, cut, sizeof cut, 1, GZ_SG_E_ARG);
        ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, no_len, sizeof no_len, 1, GZ_SG_E_ARG);
        ENV_REFUSED(h, GZ_SG_KEY_HOST, scope, 72, sig240, sizeof sig240, 1, GZ_SG_E_ARG);
        CHECK(gz_sg_sign_envelope(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, t239, sizeof t239, 1, sig) == GZ_SG_OK);
        CHECK(gz_sg_sign_envelope(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, zero_type, sizeof zero_type, 1, sig) == GZ_SG_OK);
        CHECK(gz_sg_sign_envelope(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, rec, 0, 1, sig) == GZ_SG_OK);
    }
    /* 6. a held slot */
    ENV_REFUSED(h, GZ_SG_KEY_HOST, other, 72, rec, 8, 1, GZ_SG_E_SLOT);
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, other, 22, rec, 8, 1, GZ_SG_E_SLOT);
    /* arguments */
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, NULL, 22, rec, 8, 1, GZ_SG_E_ARG);
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, NULL, 8, 1, GZ_SG_E_ARG);
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, rec, 8, 2, GZ_SG_E_ARG);
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, rec, 8, -1, GZ_SG_E_ARG);
    CHECK(gz_sg_sign_envelope(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, rec, 8, 1, NULL) == GZ_SG_E_ARG);
    /* a dropped slot signs nothing more */
    gz_sg_slot_drop(m, scope);
    ENV_REFUSED(m, GZ_SG_KEY_CONTRIBUTION, scope, 22, rec, 8, 1, GZ_SG_E_SLOT);
    drop(h);
    drop(m);
}

/* ---- the operations of S4 refuse, outputs zeroed ---- */

static void test_not_yet(void)
{
    gz_signer_t *sg = make(GZ_SG_ROLE_HOST, 0);
    uint8_t a[64], b[64], c[66], d[32], scope[32] = {0}, txid[32] = {0}, out[200], nonces[2][66];
    size_t len, n_prev;
    gz_sg_round_t handle;
    gz_sg_prevout_t prev[2];
    gzt_funding_info info;
    uint8_t *before = snap(sg);

    memset(a, 0xff, 64); memset(b, 0xff, 64);
    CHECK(gz_sg_gate_open(sg, scope, scope, c) == GZ_SG_E_NOT_YET && all(c, 0, 33));
    CHECK(gz_sg_seat_key(sg, scope, c) == GZ_SG_E_NOT_YET);
    CHECK(gz_sg_sign_terms(sg, out, 10, out, 10, a, b) == GZ_SG_E_NOT_YET && all(a, 0, 64) && all(b, 0, 64));
    memset(a, 0xff, 64);
    CHECK(gz_sg_sign_binding(sg, scope, GZ_SG_KEY_HOST, a) == GZ_SG_E_NOT_YET && all(a, 0, 64));
    handle = 0xffffffffu;
    CHECK(gz_sg_round_open(sg, scope, NULL, scope, scope, &handle) == GZ_SG_E_NOT_YET && handle == 0);
    memset(c, 0xff, 66); memset(a, 0xff, 64);
    CHECK(gz_sg_nonce(sg, 1, 0, c, a) == GZ_SG_E_NOT_YET && all(c, 0, 66) && all(a, 0, 64));
    memset(d, 0xff, 32); memset(nonces, 0, sizeof nonces);
    CHECK(gz_sg_partial(sg, 1, 0, (const uint8_t (*)[66])nonces, 2, d) == GZ_SG_E_NOT_YET && all(d, 0, 32));
    memset(d, 0xff, 32);
    CHECK(gz_sg_ecdh(sg, GZ_SG_KEY_HOST, NULL, c, d) == GZ_SG_E_NOT_YET && all(d, 0, 32));
    memset(out, 0xff, sizeof out); memset(prev, 0xff, sizeof prev); memset(&info, 0xff, sizeof info);
    len = n_prev = 99;
    CHECK(gz_sg_fund_plan(sg, NULL, NULL, 0, &info, out, sizeof out, &len, prev, 2, &n_prev) == GZ_SG_E_NOT_YET);
    CHECK(all(out, 0, sizeof out) && all(prev, 0, sizeof prev) && all(&info, 0, sizeof info) && len == 0 && n_prev == 0);
    memset(out, 0xff, sizeof out); len = 99;
    CHECK(gz_sg_fund_sign(sg, txid, out, sizeof out, &len) == GZ_SG_E_NOT_YET && all(out, 0, sizeof out) && len == 0);
    memset(out, 0xff, sizeof out); len = 99;
    CHECK(gz_sg_fund_spend_back(sg, txid, 0, 100, out, sizeof out, &len) == GZ_SG_E_NOT_YET && all(out, 0, sizeof out) &&
          len == 0);
    CHECK(gz_sg_fund_adopt(sg, out, 10, txid, out, 1000) == GZ_SG_E_NOT_YET);
    gz_sg_gate_close(sg, scope);
    gz_sg_gate_close_all(sg);
    gz_sg_round_close(sg, 1);
    gz_sg_fund_release(sg, txid);
    CHECK(same(sg, before));
    drop(sg);
}

/* ---- wipe ---- */

static void test_wipe(void)
{
    gz_signer_t *h = make(GZ_SG_ROLE_HOST, 0);
    gz_sg_slot_t s = slot_of(7, 4);
    uint8_t pub[33], sig[64];
    CHECK(gz_sg_slot_add(h, &s, pub, NULL) == GZ_SG_OK);
    CHECK(!all(h, 0, gz_signer_size()));
    gz_signer_wipe(h);
    CHECK(all(h, 0, gz_signer_size()));
    memset(sig, 0xff, 64);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, s.scope, 72, NULL, 0, 0, sig) == GZ_SG_E_ARG && all(sig, 0, 64));
    CHECK(gz_sg_host_pub(h, pub) == GZ_SG_E_ARG);
    gz_signer_wipe(NULL);
    free(h);

    /* a dropped slot leaves no key behind: its bytes are zero */
    {
        gz_signer_t *m = make(GZ_SG_ROLE_MEMBER, 0), *fresh = make(GZ_SG_ROLE_MEMBER, 0);
        CHECK(gz_sg_slot_add(m, &s, pub, NULL) == GZ_SG_OK);
        gz_sg_slot_drop(m, s.scope);
        CHECK(memcmp(m, fresh, gz_signer_size()) == 0);
        drop(m);
        drop(fresh);
    }
}

/* ---- the spend-back's fee cap ---- */

static void test_fee_cap(void)
{
    int seen = 0;
    for (int i = 0; i < n_vecs; i++) {
        unsigned long long a, b, c, d, want;
        if (sscanf(vecs[i].name, "fee_cap_%llu_%llu_%llu_%llu", &a, &b, &c, &d) != 4) continue;
        want = strtoull(vecs[i].value, NULL, 10);
        CHECK(gz_sg_spend_back_fee_cap(a, b, c, d) == want);
        seen++;
    }
    CHECK(seen == 6);
    /* review B of #56, M-3: a 16 sat, 154 vB funding; a 111 vB spend-back;
     * the harness's ceiling of 1 sat/vB. Level 0 at 0.1 sat/vB is 12 sat,
     * level 1 is 28, level 2 is 127; "ceiling x vsize" would be 111. */
    uint64_t cap = gz_sg_spend_back_fee_cap(16, 154, 111, 1000);
    CHECK(cap == 127);
    CHECK(12 <= cap && 28 <= cap && 127 <= cap && !(128 <= cap));
    CHECK((1000u * 111u + 999u) / 1000u < 127u);   /* the old cap refused level 2 */
    /* bounds */
    CHECK(gz_sg_spend_back_fee_cap(16, 0, 111, 1000) == UINT64_MAX);
    CHECK(gz_sg_spend_back_fee_cap(16, 154, 0, 1000) == UINT64_MAX);
    CHECK(gz_sg_spend_back_fee_cap(16, 4000001, 111, 1000) == UINT64_MAX);
    CHECK(gz_sg_spend_back_fee_cap(16, 154, 4000001, 1000) == UINT64_MAX);
    CHECK(gz_sg_spend_back_fee_cap(16, 154, 111, 100000001) == UINT64_MAX);
    CHECK(gz_sg_spend_back_fee_cap(UINT64_C(2100000000000001), 154, 111, 1000) == UINT64_MAX);
    CHECK(gz_sg_spend_back_fee_cap(UINT64_C(2100000000000000), 154, 4000000, 1000) == UINT64_MAX);   /* overflow */
    CHECK(gz_sg_spend_back_fee_cap(16, 4000000, 4000000, 100000000) != UINT64_MAX);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    load(argc > 1 ? argv[1] : GZ_SIGNER_VECTORS);
    vhex("seed", g_seed.seed, 64);
    printf("signer: %d vectors\n", n_vecs);
    test_init();
    test_tables();
    test_keys();
    test_slots(GZ_SG_ROLE_MEMBER);
    test_slots(GZ_SG_ROLE_HOST);
    test_envelope();
    test_not_yet();
    test_wipe();
    test_fee_cap();
    secp256k1_context_destroy(ctx);
    return check_done();
}
