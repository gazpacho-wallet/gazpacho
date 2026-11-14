/* The signing engine's test world: fixed test trees built with the imported
 * SuperScalar code, simulated nodes running the engine, faulty programs, and
 * invariants judged on the secrets themselves. Faulty behaviour lives here,
 * never in the engine. */
#ifndef GZ_TEST_SIGNING_WORLD_H
#define GZ_TEST_SIGNING_WORLD_H

#include "gazpacho/signing.h"
#include "sim.h"
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define W_MAX_NODES 17         /* host and up to 16 members (T1 at its largest) */
#define W_PARAMS 12
#define W_REC_RESTORED 0x00040006u /* journal.md 9, node area: `restored` */

/* ---- the library context: an illegal argument is counted, never fatal ---- */

static int g_illegal;
static void on_illegal(const char *msg, void *data) { (void)msg; (void)data; g_illegal++; }
static secp256k1_context *g_ctx;
static secp256k1_context *w_ctx(void)
{
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        secp256k1_context_set_illegal_callback(g_ctx, on_illegal, NULL);
    }
    return g_ctx;
}

/* ---- fixed test keys: party g (0 = host) ---- */

static void w_secret(const char *what, uint32_t g, uint8_t out[32])
{
    gz_sign_sha256_t s;
    uint8_t b[4] = {(uint8_t)(g >> 24), (uint8_t)(g >> 16), (uint8_t)(g >> 8), (uint8_t)g};
    gz_sign_tagged_init(&s, what);
    gz_sign_sha256_write(&s, b, 4);
    gz_sign_sha256_done(&s, out);
}

/* ---- the fixed test tree ----
 * params (W_PARAMS bytes): [0] version 2, [1] tiers (1 or 2), [2..5] attempt
 * (BE), [6..9] member mask (BE; bit g = party g takes part, g = 1..16),
 * [10] flags, [11] 0.
 * Every leaf is pseudo-Spilman with one member: by default the binary shape
 * (factory_set_arity PS); with WF_T1 the shape of terms.md T1 (interior
 * width 4 above 4 members, leaf kind 3, every interior level fixed), which
 * at 16 members is 17 participants and 45 items. */
enum { WF_SAME_TREE = 1, WF_DUP_KEY = 2, WF_BAD_MODE = 4, WF_DUP_SIGNER = 8, WF_BAD_SCRIPT = 16, WF_T1 = 32 };

static size_t w_params(uint8_t out[W_PARAMS], uint8_t tiers, uint32_t attempt, uint32_t mask, uint8_t flags)
{
    out[0] = 2; out[1] = tiers;
    out[2] = (uint8_t)(attempt >> 24); out[3] = (uint8_t)(attempt >> 16); out[4] = (uint8_t)(attempt >> 8); out[5] = (uint8_t)attempt;
    out[6] = (uint8_t)(mask >> 24); out[7] = (uint8_t)(mask >> 16); out[8] = (uint8_t)(mask >> 8); out[9] = (uint8_t)mask;
    out[10] = flags; out[11] = 0;
    return W_PARAMS;
}
static uint32_t w_be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

typedef struct {
    uint8_t last_params[GZ_SIGN_MAX_PARAMS];
    size_t last_len;
    int have_last;
    gz_sign_def_t last;
    uint64_t builds;
    void (*mutate)(gz_sign_def_t *d, int which);   /* tests only: damage the built definition */
    int which;
} w_builder_t;

static int w_build_tree(const uint8_t *p, size_t len, gz_sign_def_t *d, factory_t **keep)
{
    secp256k1_context *ctx = w_ctx();
    secp256k1_pubkey pks[W_MAX_NODES];
    uint8_t g_of[W_MAX_NODES];
    size_t n = 0;
    if (len != W_PARAMS || p[0] != 2 || p[1] < 1 || p[1] > 2 || p[11] != 0) return 0;
    uint32_t mask = w_be32(p + 6);
    uint32_t attempt = w_be32(p + 2);
    uint8_t flags = p[10];
    if (mask & ~0x1fffeu) return 0;
    memset(d, 0, sizeof *d);
    for (uint32_t g = 0; g < W_MAX_NODES; g++) {
        if (g && !(mask >> g & 1u)) continue;
        uint8_t sk[32], x[32];
        secp256k1_keypair kp;
        secp256k1_xonly_pubkey xo;
        w_secret("test/factory", (flags & WF_DUP_KEY) && g == 2 ? 1 : g, sk);
        if (!secp256k1_keypair_create(ctx, &kp, sk) || !secp256k1_keypair_pub(ctx, &pks[n], &kp)) return 0;
        size_t l = 33;
        secp256k1_ec_pubkey_serialize(ctx, d->participants[n].factory_key, &l, &pks[n], SECP256K1_EC_COMPRESSED);
        w_secret("test/contribution", g, sk);
        if (!secp256k1_keypair_create(ctx, &kp, sk) || !secp256k1_keypair_xonly_pub(ctx, &xo, NULL, &kp)) return 0;
        secp256k1_xonly_pubkey_serialize(ctx, x, &xo);
        memcpy(d->participants[n].contribution_key, x, 32);
        d->participants[n].peer = g;
        g_of[n++] = (uint8_t)g;
    }
    (void)g_of;
    if (n < 2) return 0;
    d->n_participants = (uint8_t)n; d->n_tiers = p[1]; d->purpose = 1;

    factory_t *f = calloc(1, sizeof *f);
    if (!f) return 0;
    factory_init_from_pubkeys(f, ctx, pks, n, 144, 4);
    if (flags & WF_T1) {
        /* terms.md T7: [3] with D = 2 up to 4 members; [4, 3], D = 2 up to 8; [4, 3], D = 3 up to 16 */
        uint8_t lv[2] = {4, 3};
        size_t members = n - 1;
        if (members <= 4) factory_set_level_arity(f, lv + 1, 1);
        else factory_set_level_arity(f, lv, 2);
        factory_set_static_near_root(f, members <= 8 ? 2 : 3);
        factory_set_ps_subfactory_arity(f, 1);
    } else {
        factory_set_arity(f, FACTORY_ARITY_PS);
    }
    f->placement_mode = PLACEMENT_SEQUENTIAL;
    f->cltv_timeout = 100000;
    f->use_tree_anchor = 1;
    musig_keyagg_t ka;
    uint8_t internal[32], tweak[32], spk[34], txid[32], seed[8];
    secp256k1_pubkey tweaked;
    secp256k1_xonly_pubkey tx_key;
    if (!musig_aggregate_keys(ctx, &ka, pks, n)) { free(f); return 0; }
    secp256k1_xonly_pubkey_serialize(ctx, internal, &ka.agg_pubkey);
    sha256_tagged("TapTweak", internal, 32, tweak);
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked, &ka.cache, tweak) ||
        !secp256k1_xonly_pubkey_from_pubkey(ctx, &tx_key, NULL, &tweaked)) { free(f); return 0; }
    build_p2tr_script_pubkey(spk, &tx_key);
    memcpy(seed, p + 2, 4); seed[4] = p[8]; seed[5] = p[9]; seed[4] ^= p[7]; seed[6] = 0x46; seed[7] = 0x44;
    if (flags & WF_SAME_TREE) memset(seed, 0, 4);       /* every attempt on one funding outpoint */
    sha256_tagged("test/funding", seed, 8, txid);
    (void)attempt;
    factory_set_funding(f, txid, 0, (uint64_t)n * 100000u + 1000000u, spk, 34);
    if (!factory_build_tree(f) || f->n_nodes == 0 || f->n_nodes > GZ_SIGN_MAX_ITEMS) { factory_free(f); free(f); return 0; }
    d->n_items = (uint16_t)f->n_nodes;
    /* Two tiers: children before parents (safety-rule.md C6). The imported tree lists the root first
     * (node 0, which spends the funding output and which every participant signs): it alone is tier
     * 1, signed once every transaction below it is, and the rest is tier 0. Items are in tier order, so
     * with two tiers item i is node i + 1 and the last item is the root; with one, item i is node i. */
    for (size_t i = 0; i < f->n_nodes; i++) {
        int two = p[1] == 2 && f->n_nodes > 1;
        const factory_node_t *nd = &f->nodes[two ? (i + 1) % f->n_nodes : i];
        gz_sign_item_t *it = &d->items[i];
        if (nd->unsigned_tx.len > GZ_SIGN_MAX_TX || nd->n_signers > GZ_SIGN_MAX_SIGNERS) { factory_free(f); free(f); return 0; }
        it->tier = (uint8_t)(two && i == f->n_nodes - 1);
        it->mode = (flags & WF_BAD_MODE) ? 2 : GZ_SIGN_MODE_KEYPATH;
        it->has_merkle_root = (uint8_t)(nd->has_taptree != 0);
        if (nd->has_taptree) memcpy(it->merkle_root, nd->merkle_root, 32);
        it->n_signers = (uint8_t)nd->n_signers;
        for (size_t s = 0; s < nd->n_signers; s++) it->signers[s] = (uint8_t)nd->signer_indices[s];
        if ((flags & WF_DUP_SIGNER) && it->n_signers > 2) it->signers[1] = it->signers[2];
        if (nd->parent_index < 0) {
            it->spent_amount = f->funding_amount_sats;
            memcpy(it->spent_script, f->funding_spk, 34);
        } else {
            const tx_output_t *o = &f->nodes[nd->parent_index].outputs[nd->parent_vout];
            it->spent_amount = o->amount_sats;
            memcpy(it->spent_script, o->script_pubkey, 34);
        }
        if ((flags & WF_BAD_SCRIPT) && i == f->n_nodes - 1) it->spent_script[5] ^= 1;
        if ((flags & WF_DUP_SIGNER) && it->n_signers > 2) {
            /* the script made consistent with the duplicated list, so only the duplicate check can refuse it */
            const secp256k1_pubkey *ptr[GZ_SIGN_MAX_SIGNERS];
            secp256k1_pubkey tw_pk;
            secp256k1_xonly_pubkey agg2, x2;
            secp256k1_musig_keyagg_cache c2;
            uint8_t ser[32], tw[32];
            gz_sign_sha256_t th;
            for (int k = 0; k < it->n_signers; k++) ptr[k] = &pks[it->signers[k]];
            if (!secp256k1_musig_pubkey_agg(ctx, NULL, &agg2, &c2, ptr, it->n_signers) ||
                !secp256k1_xonly_pubkey_serialize(ctx, ser, &agg2)) abort();
            gz_sign_tagged_init(&th, "TapTweak");
            gz_sign_sha256_write(&th, ser, 32);
            if (it->has_merkle_root) gz_sign_sha256_write(&th, it->merkle_root, 32);
            gz_sign_sha256_done(&th, tw);
            if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw_pk, &c2, tw) ||
                !secp256k1_xonly_pubkey_from_pubkey(ctx, &x2, NULL, &tw_pk) ||
                !secp256k1_xonly_pubkey_serialize(ctx, it->spent_script + 2, &x2)) abort();
        }
        it->tx_len = (uint16_t)nd->unsigned_tx.len;
        memcpy(it->tx, nd->unsigned_tx.data, nd->unsigned_tx.len);
    }
    if (keep) *keep = f;
    else { factory_free(f); free(f); }
    return 1;
}

static int w_build(void *ctx, const uint8_t *p, size_t len, gz_sign_def_t *out)
{
    w_builder_t *b = ctx;
    if (b->mutate) {
        if (len > GZ_SIGN_MAX_PARAMS || !w_build_tree(p, len, out, NULL)) return 0;
        b->mutate(out, b->which);
        return 1;
    }
    if (b->have_last && len == b->last_len && memcmp(p, b->last_params, len) == 0) { *out = b->last; return 1; }
    if (len > GZ_SIGN_MAX_PARAMS || !w_build_tree(p, len, out, NULL)) return 0;
    b->builds++;
    memcpy(b->last_params, p, len); b->last_len = len; b->last = *out; b->have_last = 1;
    return 1;
}

/* Next attempt: attempt + 1, without the blamed (participant indexes of the failed round). */
static size_t w_retry(void *ctx, const uint8_t *p, size_t len, uint32_t blamed, uint8_t *out)
{
    (void)ctx;
    if (len != W_PARAMS) return 0;
    uint32_t mask = w_be32(p + 6), next = mask;
    uint32_t idx = 1;
    for (uint32_t g = 1; g < W_MAX_NODES; g++)
        if (mask >> g & 1u) { if (blamed >> idx & 1u) next &= ~((uint32_t)1u << g); idx++; }
    if (!next) return 0;
    uint32_t attempt = w_be32(p + 2) + 1;
    return w_params(out, p[1], attempt, next, p[10]);
}

/* ---- faults a program may have on purpose ---- */
enum {
    WX_NONE = 0,
    WX_BAD_PARTIAL,         /* member: alters one partial signature, re-signs its message */
    WX_ALTER_NONCE,         /* host: alters another signer's nonce in round_all_nonces */
    WX_EQUIVOCATE,          /* member: sends a second, different, validly signed nonce */
    WX_BAD_POINT,           /* member: a nonce that is not a curve point, validly signed */
    WX_BAD_SCALAR,          /* member: a partial signature >= the group order, message re-signed */
    WX_SWAP_NONCE,          /* host: moves a signer's signed nonce to another item */
    WX_REPEAT_ALL,          /* host: every message sent twice */
    WX_PARTIAL_TWICE,       /* member: its partial signatures, then a different set, both signed */
    WX_BAD_RESULT           /* host: a wrong final signature in a tier result, re-signed */
};

typedef struct world world_t;
typedef struct {
    gz_sign_t eng;
    world_t *w;
    uint32_t index;
    const sim_storage_t *storage;
    size_t batch_at;
    gz_record_t recs[8];
} w_node_t;

/* A sent contribution: (sender, round, item, kind) -> its bytes. */
typedef struct { uint32_t node; uint8_t round[32]; uint32_t item; uint8_t kind; uint8_t value[66]; } w_contrib_t;

struct world {
    w_builder_t builder;
    int fault, fault_node;
    w_node_t *nodes[W_MAX_NODES];
    /* secrets seen: value -> identity */
    struct { uint8_t value[132]; uint32_t node; uint64_t inc, serial; } *seen;
    size_t n_seen, cap_seen;
    uint64_t absorbed_inc[W_MAX_NODES], absorbed_serial[W_MAX_NODES];
    w_contrib_t *contrib;
    size_t n_contrib, cap_contrib;
    uint64_t second_contributions, sends_partials, sends_nonces;
    uint8_t first_proposal[256];
    size_t first_proposal_len;
    uint64_t secrets_checked, zero_checks;
    uint64_t fuzz_state, fuzzed;
    uint32_t fuzz_pm;
    uint32_t max_attempts;      /* 0: 16 */
};

static void w_resign(uint8_t *msg, size_t signed_len, uint32_t g)
{
    uint8_t sk[32], d[32], aux[32] = {7};
    secp256k1_keypair kp;
    gz_sign_sha256_t s;
    w_secret("test/contribution", g, sk);
    if (!secp256k1_keypair_create(w_ctx(), &kp, sk)) abort();
    gz_sign_tagged_init(&s, "gazpacho/msg");
    gz_sign_sha256_write(&s, msg, signed_len);
    gz_sign_sha256_done(&s, d);
    secp256k1_schnorrsig_sign32(w_ctx(), msg + signed_len, d, &kp, aux);
}

static void w_sign_nonce(uint8_t *entry, const uint8_t id[32], uint8_t tier, uint32_t g)
{
    uint8_t sk[32], d[32], aux[32] = {9};
    secp256k1_keypair kp;
    gz_sign_sha256_t s;
    w_secret("test/contribution", g, sk);
    if (!secp256k1_keypair_create(w_ctx(), &kp, sk)) abort();
    gz_sign_tagged_init(&s, "gazpacho/nonce");
    gz_sign_sha256_write(&s, id, 32); gz_sign_sha256_write(&s, &tier, 1); gz_sign_sha256_write(&s, entry, 4);
    gz_sign_sha256_write(&s, entry + 4, 66);
    gz_sign_sha256_done(&s, d);
    secp256k1_schnorrsig_sign32(w_ctx(), entry + 70, d, &kp, aux);
}

/* Apply this program's fault to what it is about to hand over. */
static uint64_t w_rand(world_t *w)
{
    w->fuzz_state = w->fuzz_state * 6364136223846793005ull + 1442695040888963407ull;
    return w->fuzz_state >> 33;
}

/* Fuzzing: damage some of what any party sends, in place: flip bytes, cut
 * the end, or change a count. The engine must neither crash nor reach the
 * library with an unparsed value. */
static void w_fuzz(world_t *w, gz_action_list_t *list)
{
    for (size_t k = 0; k < list->count; k++) {
        gz_action_t *a = &list->slots[k];
        if (a->kind != GZ_ACTION_SEND || w_rand(w) % 1000 >= w->fuzz_pm || !a->u.send.bytes.len) continue;
        uint8_t *b = (uint8_t *)(uintptr_t)a->u.send.bytes.data;
        size_t len = a->u.send.bytes.len;
        switch (w_rand(w) % 4) {
        case 0: for (int f = 0; f < 1 + (int)(w_rand(w) % 4); f++) b[w_rand(w) % len] ^= (uint8_t)(1u << (w_rand(w) % 8)); break;
        case 1: a->u.send.bytes.len = (size_t)(w_rand(w) % len); break;
        case 2: if (len > 37) b[35 + w_rand(w) % 3] = (uint8_t)w_rand(w); break;
        default: b[w_rand(w) % len] = (uint8_t)w_rand(w); break;
        }
        w->fuzzed++;
    }
}

static void w_apply_fault(w_node_t *n, gz_action_list_t *list)
{
    world_t *w = n->w;
    if (w->fuzz_pm) w_fuzz(w, list);
    if (w->fault == WX_NONE || (int)n->index != w->fault_node) return;
    size_t count = list->count;
    for (size_t k = 0; k < count; k++) {
        gz_action_t *a = &list->slots[k];
        gz_sign_msg_t m;
        if (a->kind != GZ_ACTION_SEND || !gz_sign_decode(a->u.send.bytes.data, a->u.send.bytes.len, &m)) continue;
        uint8_t *b = (uint8_t *)(uintptr_t)a->u.send.bytes.data;
        if (w->fault == WX_BAD_PARTIAL && m.kind == GZ_SIGN_MSG_PARTIALS && m.n) {
            uint8_t *ps = (uint8_t *)(uintptr_t)m.entry[0] + 4;
            ps[31] ^= 1; ps[0] &= 0x7f;
            w_resign(b, m.signed_len, n->index);
        } else if (w->fault == WX_BAD_SCALAR && m.kind == GZ_SIGN_MSG_PARTIALS && m.n) {
            memset((uint8_t *)(uintptr_t)m.entry[0] + 4, 0xff, 32);
            w_resign(b, m.signed_len, n->index);
        } else if (w->fault == WX_PARTIAL_TWICE && m.kind == GZ_SIGN_MSG_PARTIALS && m.n) {
            /* the honest message, then a second one with a different partial signature */
            uint8_t copy[GZ_SIGN_MAX_MSG];
            size_t len = a->u.send.bytes.len;
            memcpy(copy, b, len);
            copy[(size_t)(m.entry[0] - b) + 4 + 31] ^= 1;
            w_resign(copy, m.signed_len, n->index);
            gz_action_t extra = *a;
            extra.u.send.bytes.data = copy;
            gz_action_list_add(list, &extra);
        } else if (w->fault == WX_BAD_RESULT && m.kind == GZ_SIGN_MSG_RESULT && m.n) {
            ((uint8_t *)(uintptr_t)m.entry[0])[4 + 10] ^= 1;
            w_resign(b, m.signed_len, 0);
        } else if ((w->fault == WX_ALTER_NONCE || w->fault == WX_SWAP_NONCE) && m.kind == GZ_SIGN_MSG_ALL_NONCES && m.n) {
            const gz_sign_round_t *r = gz_sign_latest(&n->eng);
            /* someone else's nonce, neither the host's nor the recipient's */
            for (int k2 = 0; r && k2 < m.n; k2++) {
                uint8_t *e = (uint8_t *)(uintptr_t)m.entry[k2];
                uint32_t i = (uint32_t)e[0] << 24 | (uint32_t)e[1] << 16 | (uint32_t)e[2] << 8 | e[3];
                for (int s = 0; s < e[4]; s++) {
                    uint8_t q = r->def.items[i].signers[s];
                    if (q == 0 || r->def.participants[q].peer == a->u.send.peer_id) continue;
                    if (w->fault == WX_ALTER_NONCE) { e[5 + 130 * s + 40] ^= 1; k2 = m.n; break; }
                    /* move q's signed nonce for item i into another item of q in this message */
                    for (int k3 = k2 + 1; k3 < m.n; k3++) {
                        uint8_t *e3 = (uint8_t *)(uintptr_t)m.entry[k3];
                        uint32_t i3 = (uint32_t)e3[0] << 24 | (uint32_t)e3[1] << 16 | (uint32_t)e3[2] << 8 | e3[3];
                        for (int s3 = 0; s3 < e3[4]; s3++)
                            if (r->def.items[i3].signers[s3] == q) { memcpy(e3 + 5 + 130 * s3, e + 5 + 130 * s, 130); k2 = k3 = m.n; s = e[4]; break; }
                    }
                }
            }
        } else if ((w->fault == WX_EQUIVOCATE || w->fault == WX_BAD_POINT) && m.kind == GZ_SIGN_MSG_NONCES && m.n) {
            uint8_t copy[GZ_SIGN_MAX_MSG];
            size_t len = a->u.send.bytes.len;
            memcpy(copy, b, len);
            uint8_t *e = copy + (m.entry[0] - b);
            if (w->fault == WX_BAD_POINT) { memset(e + 4, 0xff, 66); e[4] = 2; b = NULL; }
            else {
                /* a genuine second nonce for the same item: another public nonce made by the library */
                secp256k1_musig_secnonce sn;
                secp256k1_musig_pubnonce pn;
                uint8_t sid[32], sk[32];
                secp256k1_pubkey pk;
                secp256k1_keypair kp;
                w_secret("test/factory", n->index, sk);
                w_secret("test/equivocation-session", (uint32_t)w->sends_nonces, sid);
                if (!secp256k1_keypair_create(w_ctx(), &kp, sk) || !secp256k1_keypair_pub(w_ctx(), &pk, &kp)) abort();
                secp256k1_musig_nonce_gen(w_ctx(), &sn, &pn, sid, sk, &pk, NULL, NULL, NULL);
                secp256k1_musig_pubnonce_serialize(w_ctx(), e + 4, &pn);
            }
            w_sign_nonce(e, m.round_id, m.tier, n->index);
            gz_action_t extra = {.kind = GZ_ACTION_SEND};
            extra.u.send.peer_id = a->u.send.peer_id;
            extra.u.send.bytes.data = copy; extra.u.send.bytes.len = len;
            if (b == NULL) { memcpy((uint8_t *)(uintptr_t)a->u.send.bytes.data, copy, len); continue; }
            gz_action_list_add(list, &extra);
        } else if (w->fault == WX_REPEAT_ALL) {
            gz_action_t again = *a;
            gz_action_list_add(list, &again);
        }
    }
}

/* ---- the simulated node ---- */

static int w_next(void *ctx, gz_stored_batch_t *batch)
{
    w_node_t *n = ctx;
    if (n->batch_at >= sim_storage_count(n->storage)) return 0;
    size_t len, k = 0;
    const uint8_t *p = sim_storage_batch_bytes(n->storage, n->batch_at, &len), *end = p + len;
    batch->id = sim_storage_batch_id(n->storage, n->batch_at++);
    while (p + 8 <= end && k < 8) {
        uint32_t type = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
        uint32_t l = (uint32_t)p[4] | (uint32_t)p[5] << 8 | (uint32_t)p[6] << 16 | (uint32_t)p[7] << 24;
        n->recs[k].type = type; n->recs[k].bytes.data = p + 8; n->recs[k].bytes.len = l;
        p += 8 + l; k++;
    }
    batch->records = n->recs; batch->n_records = k;
    return 1;
}
static void w_rewind(void *ctx) { ((w_node_t *)ctx)->batch_at = 0; }

static void *w_create(void *ops_ctx, uint32_t index, const gz_ports_t *ports, const sim_storage_t *storage)
{
    world_t *w = ops_ctx;
    w_node_t *n = calloc(1, sizeof *n);
    if (!n) abort();
    gz_sign_config_t c;
    memset(&c, 0, sizeof c);
    c.host = index == 0; c.ctx = w_ctx();
    w_secret("test/factory", index, c.factory_secret);
    w_secret("test/contribution", index, c.contribution_secret);
    c.build = w_build; c.retry = w_retry; c.build_ctx = &w->builder;
    c.tick_ms = 1; c.resend_ticks = 40; c.deadline_ticks = 400; c.max_attempts = w->max_attempts ? w->max_attempts : 16;
    if (gz_sign_init(&n->eng, &c, ports, sim_storage_incarnation(storage)) != GZ_OK) abort();
    n->w = w; n->index = index; n->storage = storage;
    w->nodes[index] = n;
    return n;
}

static void w_destroy(void *ops_ctx, void *node)
{
    world_t *w = ops_ctx;
    w_node_t *n = node;
    if (w->nodes[n->index] == n) w->nodes[n->index] = NULL;
    gz_sign_wipe(&n->eng);
    free(n);
}

static gz_status_t w_start(void *node, gz_action_list_t *out, int *more)
{
    w_node_t *n = node;
    int restored = sim_storage_restored(n->storage);
    gz_storage_reader_t r = {w_next, w_rewind, n, sim_storage_incarnation(n->storage), restored};
    if (restored) {
        /* The node around the engine answers the restore marker first with its
         * restore batch (journal.md 8.2; here a stand-in `restored` record of
         * the node area). The engine reads only its own area and skips it. */
        uint8_t inc[8];
        uint64_t v = sim_storage_incarnation(n->storage);
        for (int b = 0; b < 8; b++) inc[b] = (uint8_t)(v >> (56 - 8 * b));
        gz_record_t rec = {W_REC_RESTORED, {inc, 8}};
        gz_action_t a = {.kind = GZ_ACTION_SAVE};
        a.u.save.records = &rec; a.u.save.n_records = 1;
        gz_status_t s0 = gz_action_list_add(out, &a);
        if (s0 != GZ_OK) return s0;
    }
    gz_status_t st = gz_sign_start(&n->eng, &r, out, more);
    if (st == GZ_OK) w_apply_fault(n, out);
    return st;
}

static gz_status_t w_handle(void *node, const gz_event_t *ev, gz_action_list_t *out)
{
    w_node_t *n = node;
    gz_status_t st;
    if (ev->kind == GZ_EVENT_USER_COMMAND) {
        st = gz_sign_begin(&n->eng, ev->u.user.bytes.data, ev->u.user.bytes.len, out);
        if (st == GZ_ERR_ARGUMENT) st = GZ_OK;      /* refused: nothing to do */
    } else st = gz_sign_handle(&n->eng, ev, out);
    if (st == GZ_OK) w_apply_fault(n, out);
    return st;
}

/* Every live secret nonce of a node as (8-byte little-endian serial, the 132
 * secret-nonce bytes), for the simulator's "secrets never leave" check. Read
 * from the engine's structure here, in the test world: the release library
 * has no call that hands out a secret nonce (review A, F5). */
static size_t w_inspect(const void *node, uint8_t *out, size_t cap)
{
    const gz_sign_t *e = &((const w_node_t *)node)->eng;
    size_t n = 0;
    for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++)
        for (int i = 0; i < GZ_SIGN_MAX_ITEMS; i++) {
            if (!e->rounds[k].secnonce_serial[i]) continue;
            if (cap - n < 140) return 0;
            for (int b = 0; b < 8; b++) out[n + (size_t)b] = (uint8_t)(e->rounds[k].secnonce_serial[i] >> (8 * b));
            memcpy(out + n + 8, e->rounds[k].secnonce[i].data, 132);
            n += 140;
        }
    return n;
}

/* Every contribution that leaves a node: never two different ones under one
 * (round, item) from one sender. */
static void w_observe(void *ops_ctx, uint32_t index, const gz_action_t *a)
{
    world_t *w = ops_ctx;
    gz_sign_msg_t m;
    if (!gz_sign_decode(a->u.send.bytes.data, a->u.send.bytes.len, &m)) return;
    if (m.kind == GZ_SIGN_MSG_PROPOSE && !w->first_proposal_len && a->u.send.bytes.len <= sizeof w->first_proposal) {
        memcpy(w->first_proposal, a->u.send.bytes.data, a->u.send.bytes.len);
        w->first_proposal_len = a->u.send.bytes.len;
    }
    if (m.kind != GZ_SIGN_MSG_NONCES && m.kind != GZ_SIGN_MSG_PARTIALS) return;
    if (m.kind == GZ_SIGN_MSG_NONCES) w->sends_nonces++; else w->sends_partials++;
    for (int k = 0; k < m.n; k++) {
        w_contrib_t c;
        memset(&c, 0, sizeof c);
        c.node = index; c.kind = m.kind; memcpy(c.round, m.round_id, 32);
        c.item = (uint32_t)m.entry[k][0] << 24 | (uint32_t)m.entry[k][1] << 16 | (uint32_t)m.entry[k][2] << 8 | m.entry[k][3];
        memcpy(c.value, m.entry[k] + 4, m.kind == GZ_SIGN_MSG_NONCES ? 66 : 32);
        int found = 0;
        for (size_t i = 0; i < w->n_contrib && !found; i++) {
            w_contrib_t *o = &w->contrib[i];
            if (o->node == c.node && o->kind == c.kind && o->item == c.item && memcmp(o->round, c.round, 32) == 0) {
                found = 1;
                if (memcmp(o->value, c.value, 66) != 0) w->second_contributions++;
            }
        }
        if (found) continue;
        if (w->n_contrib == w->cap_contrib) {
            w->cap_contrib = w->cap_contrib ? 2 * w->cap_contrib : 256;
            w->contrib = realloc(w->contrib, w->cap_contrib * sizeof *w->contrib);
            if (!w->contrib) abort();
        }
        w->contrib[w->n_contrib++] = c;
    }
}

/* Invariant: no secret nonce value is ever held twice, by any node, across
 * crashes and restores; judged on the 132 secret bytes the nodes show. And
 * every round that has stopped needing them holds none: the bytes are zero. */
static int w_secrets_ok(const sim_t *sim, void *ctx, const char **why)
{
    world_t *w = ctx;
    static uint8_t shown[GZ_SIGN_MAX_ROUNDS * GZ_SIGN_MAX_ITEMS * 140];
    for (uint32_t node = 0; node < W_MAX_NODES && w->nodes[node]; node++) {
        uint64_t inc = sim_node_incarnation(sim, node);
        size_t len = sim_node_inspect(sim, node, shown, sizeof shown);
        if (inc != w->absorbed_inc[node]) { w->absorbed_inc[node] = inc; w->absorbed_serial[node] = 0; }
        uint64_t top = w->absorbed_serial[node];
        for (size_t at = 0; at + 140 <= len; at += 140) {
            uint64_t serial = 0;
            for (int b = 0; b < 8; b++) serial |= (uint64_t)shown[at + (size_t)b] << (8 * b);
            if (serial <= w->absorbed_serial[node]) continue;
            if (serial > top) top = serial;
            for (size_t i = 0; i < w->n_seen; i++)
                if (memcmp(w->seen[i].value, shown + at + 8, 132) == 0) { *why = "a secret nonce value was held twice"; return 0; }
            if (w->n_seen == w->cap_seen) {
                w->cap_seen = w->cap_seen ? 2 * w->cap_seen : 256;
                w->seen = realloc(w->seen, w->cap_seen * sizeof *w->seen);
                if (!w->seen) abort();
            }
            memcpy(w->seen[w->n_seen].value, shown + at + 8, 132);
            w->seen[w->n_seen].node = node; w->seen[w->n_seen].inc = inc; w->seen[w->n_seen].serial = serial;
            w->n_seen++; w->secrets_checked++;
        }
        w->absorbed_serial[node] = top;
        const gz_sign_t *e = &w->nodes[node]->eng;
        for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
            const gz_sign_round_t *r = &e->rounds[k];
            for (int i = 0; i < r->def.n_items && r->state != GZ_SIGN_ROUND_FREE; i++) {
                /* a member's secret has signed once its tier is Signed; the host signs last, when it combines */
                int stopped = r->state != GZ_SIGN_ROUND_ACTIVE ||
                              r->tier_state[r->def.items[i].tier] >= (node == 0 ? GZ_SIGN_TIER_DONE : GZ_SIGN_TIER_SIGNED);
                if (!stopped) continue;
                w->zero_checks++;
                for (size_t b = 0; b < 132; b++)
                    if (r->secnonce[i].data[b]) { *why = "a secret nonce outlived its round or tier"; return 0; }
            }
        }
    }
    if (g_illegal) { *why = "the library's illegal-argument callback fired"; return 0; }
    return 1;
}

static inline int w_contrib_ok(const sim_t *sim, void *ctx, const char **why)
{
    (void)sim;
    if (((world_t *)ctx)->second_contributions) { *why = "a party sent two different contributions under one (round, item)"; return 0; }
    return 1;
}

static sim_config_t w_config(world_t *w, uint64_t seed, uint32_t members)
{
    sim_config_t c;
    memset(&c, 0, sizeof c);
    c.seed = seed; c.n_nodes = members + 1;
    c.step_slots = 128; c.step_bytes = 1u << 20; c.runner_slots = 512; c.runner_bytes = 4u << 20;
    c.ops.create = w_create; c.ops.destroy = w_destroy; c.ops.start = w_start; c.ops.handle = w_handle;
    c.ops.inspect = w_inspect; c.ops.observe = w_observe; c.ops.ctx = w;
    return c;
}

static uint32_t w_mask(uint32_t members) { return (((uint32_t)1u << (members + 1)) - 1u) & ~1u; }

#endif
