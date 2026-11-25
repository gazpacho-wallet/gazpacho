/* The signer, stage 1: state, derivation, slots and message signatures.
 * See gazpacho/signer.h and docs/notes/signer.md. */
#include "internal.h"
#include "gazpacho/round_msg.h"

#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <string.h>

/* A constant-time test marks secrets undefined under valgrind and declares
 * here what is public once computed: a library call's success, which depends
 * only on whether a key is valid, and a signature (as libsecp256k1's own
 * ctime test does). Nothing otherwise. */
#ifndef GZ_SG_DECLASSIFY
#define GZ_SG_DECLASSIFY(p, n) ((void)(p), (void)(n))
#endif

#define H GZW_HARDENED
#define SG_MAGIC 0x67736731u          /* "gsg1" */
#define SG_PURPOSE 254315617u          /* SHA256("gazpacho keys")[0..4] & 0x7fffffff, PR #53 */
#define SG_BRANCH_LOBBY 0u
#define SG_BRANCH_HOST 1u
#define SG_BRANCH_HOST_LOBBY 2u

/* Every signature draws fresh aux_rand from the random port (decision K20).
 * There is no fixed-aux path in this file: the vectors build adds one in its
 * own source, vectors_aux.c (review B of #71, M2). */

size_t gz_signer_size(void) { return sizeof(gz_signer_t); }

static int net_level(gzw_network n, uint32_t *out)
{
    switch (n) {   /* PR #53's network level; mainnet has none */
    case GZW_NET_TESTNET4: *out = 1; return 1;
    case GZW_NET_SIGNET: *out = 2; return 1;
    case GZW_NET_TESTNET: *out = 3; return 1;
    case GZW_NET_REGTEST: *out = 4; return 1;
    default: return 0;
    }
}

static int live(const gz_signer_t *sg) { return sg && sg->magic == SG_MAGIC; }

gz_sg_err_t gz_signer_init(gz_signer_t *sg, size_t size, const gz_sg_config_t *cfg)
{
    uint32_t level = 0;
    if (!sg || size < sizeof *sg) return GZ_SG_E_ARG;
    /* the config is checked first: a refused init leaves `sg` as it was */
    if (!cfg || !cfg->secp || !cfg->seed.seed || !cfg->random.fill ||
        (cfg->role != GZ_SG_ROLE_HOST && cfg->role != GZ_SG_ROLE_MEMBER) || !net_level(cfg->network, &level) ||
        cfg->epoch >= GZ_SG_INDEX_LIMIT || (cfg->frozen != 0 && cfg->frozen != 1) ||
        cfg->max_feerate == 0 || cfg->max_feerate > GZ_SG_FEERATE_HARD_MAX)
        return GZ_SG_E_ARG;
    gzw_wipe(sg, sizeof *sg);
    sg->cfg = *cfg;
    sg->net_level = level;
    sg->magic = SG_MAGIC;
    return GZ_SG_OK;
}

void gz_signer_wipe(gz_signer_t *sg)
{
    if (sg) gzw_wipe(sg, sizeof *sg);
}

/* ---- derivation: nothing but the one result is kept ---- */

/* The master key from the seed source. */
static gz_sg_err_t master(const gz_signer_t *sg, gzw_xprv *m)
{
    uint8_t seed[64];
    gzw_reason r = GZW_REASON_OK;
    int ok;
    memset(seed, 0, sizeof seed);
    ok = sg->cfg.seed.seed(sg->cfg.seed.ctx, seed) == 1;
    if (ok) ok = gzw_bip32_master(sg->cfg.secp, seed, sizeof seed, m, &r) == 1;
    gzw_wipe(seed, sizeof seed);
    if (!ok) {
        gzw_wipe(m, sizeof *m);
        return r == GZW_REASON_OK ? GZ_SG_E_NO_SEED : GZ_SG_E_INTERNAL;
    }
    return GZ_SG_OK;
}

/* m/254315617'/net'/path..., every step hardened; `out` is the only result. */
static gz_sg_err_t walk(const gz_signer_t *sg, const uint32_t *tail, size_t n, gzw_xprv *out)
{
    uint32_t path[5];
    gzw_reason r = GZW_REASON_OK;
    gzw_xprv m;
    gz_sg_err_t e;
    size_t i;
    if (n > 3) return GZ_SG_E_INTERNAL;
    path[0] = SG_PURPOSE | H;
    path[1] = sg->net_level | H;
    for (i = 0; i < n; i++) path[2 + i] = tail[i] | H;
    e = master(sg, &m);
    if (e != GZ_SG_OK) return e;
    if (gzw_bip32_derive_priv(sg->cfg.secp, &m, path, 2 + n, out, &r) != 1) e = GZ_SG_E_INTERNAL;
    gzw_wipe(&m, sizeof m);
    return e;
}

/* The key pair, compressed public key and x-only key of `x`. */
static gz_sg_err_t pair_of(const gz_signer_t *sg, const gzw_xprv *x, secp256k1_keypair *kp, uint8_t pub[33],
                           uint8_t xonly[32])
{
    secp256k1_pubkey p;
    secp256k1_xonly_pubkey xo;
    size_t len = 33;
    int ok = secp256k1_keypair_create(sg->cfg.secp, kp, x->key);
    GZ_SG_DECLASSIFY(&ok, sizeof ok);
    if (ok) ok = secp256k1_keypair_pub(sg->cfg.secp, &p, kp);
    GZ_SG_DECLASSIFY(&p, sizeof p);
    if (ok) ok = secp256k1_ec_pubkey_serialize(sg->cfg.secp, pub, &len, &p, SECP256K1_EC_COMPRESSED) && len == 33;
    if (ok) ok = secp256k1_keypair_xonly_pub(sg->cfg.secp, &xo, NULL, kp);
    GZ_SG_DECLASSIFY(&xo, sizeof xo);
    if (ok && xonly) ok = secp256k1_xonly_pubkey_serialize(sg->cfg.secp, xonly, &xo);
    if (!ok) {
        gzw_wipe(kp, sizeof *kp);
        memset(pub, 0, 33);
        if (xonly) memset(xonly, 0, 32);
        return GZ_SG_E_INTERNAL;
    }
    return GZ_SG_OK;
}

/* The host's long-term key: the first k BIP 32 allows under m/P'/net'/1'. */
static gz_sg_err_t derive_host(const gz_signer_t *sg, secp256k1_keypair *kp, uint8_t pub[33], uint8_t xonly[32])
{
    uint32_t branch = SG_BRANCH_HOST, k;
    gzw_xprv parent, x;
    gzw_reason r = GZW_REASON_OK;
    gz_sg_err_t e = walk(sg, &branch, 1, &parent);
    if (e != GZ_SG_OK) return e;
    e = GZ_SG_E_INTERNAL;
    for (k = 0; k < GZ_SG_INDEX_LIMIT; k++) {
        if (gzw_bip32_child_priv(sg->cfg.secp, &parent, k | H, &x, &r) == 1) {
            e = pair_of(sg, &x, kp, pub, xonly);
            break;
        }
        if (r != GZW_REASON_INVALID_CHILD) break;   /* only BIP 32's rare case moves on to the next k */
    }
    gzw_wipe(&parent, sizeof parent);
    gzw_wipe(&x, sizeof x);
    return e;
}

/* A per-lobby key: m/P'/net'/branch'/epoch'/index'. */
static gz_sg_err_t derive_lobby(const gz_signer_t *sg, uint32_t branch, uint32_t epoch, uint32_t index,
                                secp256k1_keypair *kp, uint8_t pub[33], uint8_t xonly[32])
{
    uint32_t tail[3];
    gzw_xprv x;
    gz_sg_err_t e;
    tail[0] = branch;
    tail[1] = epoch;
    tail[2] = index;
    e = walk(sg, tail, 3, &x);
    if (e == GZ_SG_OK) e = pair_of(sg, &x, kp, pub, xonly);
    gzw_wipe(&x, sizeof x);
    return e;
}

gz_sg_err_t gz_sg_host_pub(gz_signer_t *sg, uint8_t pub[33])
{
    secp256k1_keypair kp;
    uint8_t p[33], xo[32];
    gz_sg_err_t e;
    if (pub) memset(pub, 0, 33);
    if (!live(sg) || !pub) return GZ_SG_E_ARG;
    if (sg->cfg.role != GZ_SG_ROLE_HOST) return GZ_SG_E_KIND;
    if (!sg->have_host) {
        e = derive_host(sg, &kp, p, xo);
        if (e != GZ_SG_OK) {
            gzw_wipe(&kp, sizeof kp);
            return e;
        }
        sg->host_kp = kp;
        memcpy(sg->host_pub, p, 33);
        memcpy(sg->host_xonly, xo, 32);
        sg->have_host = 1;
        gzw_wipe(&kp, sizeof kp);
    }
    memcpy(pub, sg->host_pub, 33);
    return GZ_SG_OK;
}

/* ---- slots ---- */

static sg_slot_t *find(gz_signer_t *sg, const uint8_t scope[32])
{
    size_t i;
    for (i = 0; i < GZ_SG_MAX_SLOTS; i++)   /* a scope is public: memcmp is fine */
        if (sg->slots[i].used && memcmp(sg->slots[i].slot.scope, scope, 32) == 0) return &sg->slots[i];
    return NULL;
}

/* 1 if a held slot of the same epoch already uses a key of `s`'s pair. */
static int pair_taken(const gz_signer_t *sg, const gz_sg_slot_t *s)
{
    size_t i;
    for (i = 0; i < GZ_SG_MAX_SLOTS; i++) {
        const gz_sg_slot_t *o = &sg->slots[i].slot;
        if (!sg->slots[i].used || o->epoch != s->epoch) continue;
        if (sg->cfg.role == GZ_SG_ROLE_HOST) {
            if (o->key_index == s->key_index) return 1;   /* the same factory key, i + 1 */
        } else if (o->key_index <= s->key_index + 1 && s->key_index <= o->key_index + 1) {
            return 1;                                     /* {i, i + 1} and {j, j + 1} meet */
        }
    }
    return 0;
}

gz_sg_err_t gz_sg_slot_add(gz_signer_t *sg, const gz_sg_slot_t *slot, uint8_t contribution_pub[33],
                           uint8_t factory_pub[33])
{
    sg_slot_t t, *free_slot = NULL;
    secp256k1_keypair fkp, hkp;
    uint8_t fxo[32], hp[33], hxo[32];
    int new_host = 0;
    gz_sg_err_t e;
    size_t i;
    if (contribution_pub) memset(contribution_pub, 0, 33);
    if (factory_pub) memset(factory_pub, 0, 33);
    if (!live(sg) || !slot || !contribution_pub) return GZ_SG_E_ARG;
    /* 1. the current epoch, not frozen */
    if (slot->epoch != sg->cfg.epoch || sg->cfg.frozen) return GZ_SG_E_EPOCH;
    /* 2. key_index + 1 below 2^31, so that the factory key fits (any parity) */
    if (slot->key_index >= GZ_SG_INDEX_LIMIT - 1) return GZ_SG_E_ARG;
    /* 3. not held, and no key of the pair is a key of a held slot (review B
     *    of #71, H1): a member's {i, i + 1} may not meet another slot's pair
     *    of the same epoch, or one slot's factory key would be another's
     *    contribution key, or one pair would serve two lobbies. A host's
     *    contribution key is its long-term key; its per-lobby key is the
     *    factory key at i + 1, which no two slots may share. */
    if (find(sg, slot->scope)) return GZ_SG_E_SLOT;
    if (pair_taken(sg, slot)) return GZ_SG_E_SLOT;
    /* 4. room */
    for (i = 0; i < GZ_SG_MAX_SLOTS && !free_slot; i++)
        if (!sg->slots[i].used) free_slot = &sg->slots[i];
    if (!free_slot) return GZ_SG_E_SLOT;

    memset(&t, 0, sizeof t);
    memset(&fkp, 0, sizeof fkp);
    memset(&hkp, 0, sizeof hkp);
    memset(hp, 0, sizeof hp);
    memset(hxo, 0, sizeof hxo);
    t.slot = *slot;
    if (sg->cfg.role == GZ_SG_ROLE_MEMBER) {
        e = derive_lobby(sg, SG_BRANCH_LOBBY, slot->epoch, slot->key_index, &t.contribution_kp,
                         t.contribution_pub, t.contribution_xonly);
        if (e == GZ_SG_OK)
            e = derive_lobby(sg, SG_BRANCH_LOBBY, slot->epoch, slot->key_index + 1, &fkp, t.factory_pub, fxo);
    } else {
        /* The host's contribution key is its long-term key. It is kept only
         * if the whole call succeeds: a refusal leaves the state unchanged. */
        e = GZ_SG_OK;
        if (sg->have_host) {
            memcpy(hp, sg->host_pub, 33);
            memcpy(hxo, sg->host_xonly, 32);
        } else {
            e = derive_host(sg, &hkp, hp, hxo);
            new_host = e == GZ_SG_OK;
        }
        if (e == GZ_SG_OK) {
            memcpy(t.contribution_pub, hp, 33);
            memcpy(t.contribution_xonly, hxo, 32);
            e = derive_lobby(sg, SG_BRANCH_HOST_LOBBY, slot->epoch, slot->key_index + 1, &fkp, t.factory_pub, fxo);
        }
    }
    gzw_wipe(&fkp, sizeof fkp);   /* stage 1 keeps no factory secret */
    if (e != GZ_SG_OK) {
        gzw_wipe(&t, sizeof t);
        gzw_wipe(&hkp, sizeof hkp);
        return e;
    }
    if (new_host) {
        sg->host_kp = hkp;
        memcpy(sg->host_pub, hp, 33);
        memcpy(sg->host_xonly, hxo, 32);
        sg->have_host = 1;
    }
    gzw_wipe(&hkp, sizeof hkp);
    t.used = 1;
    *free_slot = t;
    gzw_wipe(&t, sizeof t);
    memcpy(contribution_pub, free_slot->contribution_pub, 33);
    if (factory_pub) memcpy(factory_pub, free_slot->factory_pub, 33);
    return GZ_SG_OK;
}

void gz_sg_slot_drop(gz_signer_t *sg, const uint8_t scope[32])
{
    sg_slot_t *s;
    if (!live(sg) || !scope) return;
    s = find(sg, scope);
    if (s) gzw_wipe(s, sizeof *s);
}

/* ---- message signatures ---- */

/* BigSize (BOLT 1), minimally encoded. */
static int bigsize(const uint8_t *p, size_t n, size_t *at, uint64_t *v)
{
    uint8_t b;
    size_t w, i;
    uint64_t x = 0;
    if (*at >= n) return 0;
    b = p[*at];
    w = b < 0xfd ? 0 : b == 0xfd ? 2 : b == 0xfe ? 4 : 8;
    if (n - *at - 1 < w) return 0;
    if (w == 0) x = b;
    for (i = 0; i < w; i++) x = x << 8 | p[*at + 1 + i];
    if ((w == 2 && x < 0xfd) || (w == 4 && x <= 0xffffu) || (w == 8 && x <= 0xffffffffu)) return 0;
    *at += 1 + w;
    *v = x;
    return 1;
}

/* A record stream under messages.md 4.2's structure, every type below 240. */
static int records_unsigned(const uint8_t *p, size_t n)
{
    size_t at = 0;
    uint64_t type, len, last = 0;
    int first = 1;
    while (at < n) {
        if (!bigsize(p, n, &at, &type) || !bigsize(p, n, &at, &len)) return 0;
        if ((!first && type <= last) || type >= GZ_RMSG_SIG_TYPE || len > n - at) return 0;
        at += (size_t)len;
        last = type;
        first = 0;
    }
    return 1;
}

/* The host's signed round kinds, which may be reassembled (messages.md 5). */
static int host_round_kind(uint16_t kind)
{
    return kind == GZ_KIND_ROUND_PROPOSE || kind == GZ_KIND_ROUND_TIER_RESULT || kind == GZ_KIND_ROUND_COMPLETE ||
           kind == GZ_KIND_ROUND_ABORT;
}

/* BIP 340 over `msg` with `kp`, verified under `xonly` before it is returned. */
static gz_sg_err_t sign32(const gz_signer_t *sg, const secp256k1_keypair *kp, const uint8_t xonly[32],
                          const uint8_t msg[32], uint8_t sig[64])
{
    uint8_t aux[32];
    secp256k1_xonly_pubkey pk;
    int ok;
    memset(aux, 0, sizeof aux);
    sg->cfg.random.fill(sg->cfg.random.ctx, GZ_RANDOM_SECRET, aux, sizeof aux);
    ok = secp256k1_schnorrsig_sign32(sg->cfg.secp, sig, msg, kp, aux);
    GZ_SG_DECLASSIFY(&ok, sizeof ok);
    GZ_SG_DECLASSIFY(sig, 64);
    gzw_wipe(aux, sizeof aux);
    if (ok) ok = secp256k1_xonly_pubkey_parse(sg->cfg.secp, &pk, xonly);
    if (ok) ok = secp256k1_schnorrsig_verify(sg->cfg.secp, sig, msg, 32, &pk);
    if (!ok) {
        memset(sig, 0, 64);
        return GZ_SG_E_INTERNAL;
    }
    return GZ_SG_OK;
}

gz_sg_err_t gz_sg_sign_envelope(gz_signer_t *sg, gz_sg_key_t key, const uint8_t scope[32], uint16_t kind,
                                const uint8_t *records, size_t len, uint8_t sig[64])
{
    size_t max;
    sg_slot_t *s;
    uint8_t h[32];
    gz_sg_err_t e;
    if (sig) memset(sig, 0, 64);
    if (!live(sg) || !sig || !scope || (!records && len)) return GZ_SG_E_ARG;
    /* 1. the key matches the role; never the factory or a wallet key */
    if (!((sg->cfg.role == GZ_SG_ROLE_HOST && key == GZ_SG_KEY_HOST) ||
          (sg->cfg.role == GZ_SG_ROLE_MEMBER && key == GZ_SG_KEY_CONTRIBUTION)))
        return GZ_SG_E_KIND;
    /* 2. the kind is in the key's row, and the key may sign this tag at all (D3) */
    if (!gz_sg_kind_allowed(sg->cfg.role, key, kind) ||
        !gz_sg_may_sign_tag(sg->cfg.role, key, "gazpacho/msg"))
        return GZ_SG_E_KIND;
    /* 3. length */
    max = sg->cfg.role == GZ_SG_ROLE_HOST && host_round_kind(kind) ? GZ_RMSG_MAX_WHOLE - GZ_RMSG_HEADER
                                                                    : GZ_RMSG_MAX_RECORDS_ONE;
    if (len > max) return GZ_SG_E_ARG;
    /* 4. a well-formed stream without the signature record */
    if (!records_unsigned(records, len)) return GZ_SG_E_ARG;
    /* 5. a held slot */
    s = find(sg, scope);
    if (!s) return GZ_SG_E_SLOT;

    gz_rmsg_hash(kind, scope, records, len, h);
    if (sg->cfg.role == GZ_SG_ROLE_HOST) {
        if (!sg->have_host) return GZ_SG_E_INTERNAL;   /* slot_add derived it */
        e = sign32(sg, &sg->host_kp, sg->host_xonly, h, sig);
    } else {
        e = sign32(sg, &s->contribution_kp, s->contribution_xonly, h, sig);
    }
    return e;
}

/* ---- the fee cap of the spend-back ---- */

static uint64_t fee_at(uint64_t rate, uint64_t vsize) { return (rate * vsize + 999) / 1000; }

uint64_t gz_sg_spend_back_fee_cap(const gz_signer_t *sg, uint64_t plan_fee, uint64_t plan_vsize,
                                  uint64_t spend_back_vsize)
{
    uint64_t at_ceiling, top, floor_fee, ceiling_rate;
    if (!live(sg)) return 0;
    ceiling_rate = sg->cfg.max_feerate;   /* the signer's own, never a caller's (review B of #71, M1) */
    if (ceiling_rate == 0 || plan_vsize == 0 || plan_vsize > 4000000u || spend_back_vsize == 0 || spend_back_vsize > 4000000u ||
        ceiling_rate > GZ_SG_FEERATE_HARD_MAX || plan_fee > UINT64_C(2100000000000000) ||
        plan_fee > UINT64_MAX / spend_back_vsize)
        return 0;   /* fails closed: refuses every fee */
    /* a plan paying more than the ceiling on its own size was never one the
     * signer could build or adopt: refuse, whatever the caller says */
    if (plan_fee > fee_at(ceiling_rate, plan_vsize)) return 0;
    at_ceiling = fee_at(ceiling_rate, spend_back_vsize);
    /* the top of the ladder: level 2, as #56's gz_fund_replace_fee with incremental_high */
    top = plan_fee + fee_at(GZ_SG_INCREMENTAL_HIGH, spend_back_vsize);
    floor_fee = plan_fee * spend_back_vsize / plan_vsize + 1;
    if (top < floor_fee) top = floor_fee;
    return at_ceiling > top ? at_ceiling : top;
}

/* ---- the operations of step S4: refused, outputs zeroed ---- */

static void zero(void *p, size_t n)
{
    if (p) memset(p, 0, n);
}

gz_sg_err_t gz_sg_gate_open(gz_signer_t *sg, const uint8_t scope[32], const uint8_t digest[32],
                            uint8_t factory_pub[33])
{
    (void)sg; (void)scope; (void)digest;
    zero(factory_pub, 33);
    return GZ_SG_E_NOT_YET;
}

void gz_sg_gate_close(gz_signer_t *sg, const uint8_t scope[32]) { (void)sg; (void)scope; }
void gz_sg_gate_close_all(gz_signer_t *sg) { (void)sg; }

gz_sg_err_t gz_sg_seat_key(gz_signer_t *sg, const uint8_t scope[32], const uint8_t seat_key[33])
{
    (void)sg; (void)scope; (void)seat_key;
    return GZ_SG_E_NOT_YET;
}

gz_sg_err_t gz_sg_sign_terms(gz_signer_t *sg, const uint8_t *outer, size_t olen, const uint8_t *current,
                             size_t clen, uint8_t outer_sig[64], uint8_t current_sig[64])
{
    (void)sg; (void)outer; (void)olen; (void)current; (void)clen;
    zero(outer_sig, 64);
    zero(current_sig, 64);
    return GZ_SG_E_NOT_YET;
}

gz_sg_err_t gz_sg_sign_binding(gz_signer_t *sg, const uint8_t scope[32], gz_sg_key_t key, uint8_t sig[64])
{
    (void)sg; (void)scope; (void)key;
    zero(sig, 64);
    return GZ_SG_E_NOT_YET;
}

gz_sg_err_t gz_sg_round_open(gz_signer_t *sg, const uint8_t scope[32], const gz_sign_def_t *def,
                             const uint8_t round_id[32], const uint8_t host_random[32], gz_sg_round_t *handle)
{
    (void)sg; (void)scope; (void)def; (void)round_id; (void)host_random;
    zero(handle, sizeof *handle);
    return GZ_SG_E_NOT_YET;
}

gz_sg_err_t gz_sg_nonce(gz_signer_t *sg, gz_sg_round_t handle, uint16_t item, uint8_t pubnonce[66],
                        uint8_t attest_sig[64])
{
    (void)sg; (void)handle; (void)item;
    zero(pubnonce, 66);
    zero(attest_sig, 64);
    return GZ_SG_E_NOT_YET;
}

gz_sg_err_t gz_sg_partial(gz_signer_t *sg, gz_sg_round_t handle, uint16_t item, const uint8_t (*nonces)[66],
                          uint8_t n, uint8_t psig[32])
{
    (void)sg; (void)handle; (void)item; (void)nonces; (void)n;
    zero(psig, 32);
    return GZ_SG_E_NOT_YET;
}

void gz_sg_round_close(gz_signer_t *sg, gz_sg_round_t handle) { (void)sg; (void)handle; }

gz_sg_err_t gz_sg_ecdh(gz_signer_t *sg, gz_sg_key_t key, const gz_sg_slot_t *slot, const uint8_t point[33],
                       uint8_t shared[32])
{
    (void)sg; (void)key; (void)slot; (void)point;
    zero(shared, 32);
    return GZ_SG_E_NOT_YET;
}

gz_sg_err_t gz_sg_fund_plan(gz_signer_t *sg, const gzt_funding_request *req, const gzt_coin *coins, size_t n,
                            gzt_funding_info *info, uint8_t *unsigned_tx, size_t cap, size_t *len,
                            gz_sg_prevout_t *prev, size_t max_prev, size_t *n_prev)
{
    (void)sg; (void)req; (void)coins; (void)n;
    zero(info, sizeof *info);
    zero(unsigned_tx, cap);
    zero(len, sizeof *len);
    zero(prev, max_prev * sizeof *prev);
    zero(n_prev, sizeof *n_prev);
    return GZ_SG_E_NOT_YET;
}

gz_sg_err_t gz_sg_fund_sign(gz_signer_t *sg, const uint8_t txid[32], uint8_t *out, size_t cap, size_t *len)
{
    (void)sg; (void)txid;
    zero(out, cap);
    zero(len, sizeof *len);
    return GZ_SG_E_NOT_YET;
}

gz_sg_err_t gz_sg_fund_spend_back(gz_signer_t *sg, const uint8_t txid[32], uint32_t input, uint64_t fee,
                                  uint8_t *out, size_t cap, size_t *len)
{
    (void)sg; (void)txid; (void)input; (void)fee;
    zero(out, cap);
    zero(len, sizeof *len);
    return GZ_SG_E_NOT_YET;
}

gz_sg_err_t gz_sg_fund_adopt(gz_signer_t *sg, const uint8_t *unsigned_tx, size_t len, const uint8_t txid[32],
                             const uint8_t funding_script[34], uint64_t amount)
{
    (void)sg; (void)unsigned_tx; (void)len; (void)txid; (void)funding_script; (void)amount;
    return GZ_SG_E_NOT_YET;
}

void gz_sg_fund_release(gz_signer_t *sg, const uint8_t txid[32]) { (void)sg; (void)txid; }
