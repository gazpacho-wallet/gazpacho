/* The signing engine's test world: fixed test trees built with the imported
 * SuperScalar code from round_propose (messages.md 7.2), simulated nodes
 * running the engine, faulty programs, and invariants judged on the secrets
 * themselves. Faulty behaviour lives here, never in the engine. */
#ifndef GZ_TEST_SIGNING_WORLD_H
#define GZ_TEST_SIGNING_WORLD_H

#include "gazpacho/signing.h"
#include "gazpacho/tree.h"
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

static void w_pub33(const char *what, uint32_t g, uint8_t out[33])
{
    uint8_t sk[32];
    secp256k1_keypair kp;
    secp256k1_pubkey pk;
    size_t l = 33;
    w_secret(what, g, sk);
    if (!secp256k1_keypair_create(w_ctx(), &kp, sk) || !secp256k1_keypair_pub(w_ctx(), &pk, &kp) ||
        !secp256k1_ec_pubkey_serialize(w_ctx(), out, &l, &pk, SECP256K1_EC_COMPRESSED)) abort();
}

/* Party g's keys in a key epoch (journal.md 8.2: every per-lobby key is
 * derived from the seed, the epoch and an index; here from g and the epoch),
 * cached: parties 0..W_MAX_NODES-1 in epochs 0..W_EPOCHS-1, and the extra
 * parties 100..131 in epoch 0. The host's long-term key has no epoch. */
#define W_EPOCHS 8
typedef struct { uint8_t f[33], c[33]; int ready; } w_key_t;
static w_key_t g_keys[132], g_epoch_keys[W_MAX_NODES][W_EPOCHS];
static uint32_t w_secret_index(uint32_t g, uint32_t epoch) { return epoch ? g + 1000u * epoch : g; }
static const w_key_t *w_keys_e(uint32_t g, uint32_t epoch)
{
    w_key_t *k = g < W_MAX_NODES && epoch && epoch < W_EPOCHS ? &g_epoch_keys[g][epoch] : &g_keys[g < 132 ? g : 131];
    if (!k->ready) {
        w_pub33("test/factory", w_secret_index(g, epoch), k->f);
        w_pub33("test/contribution", w_secret_index(g, epoch), k->c);
        k->ready = 1;
    }
    return k;
}
static const w_key_t *w_keys(uint32_t g) { return w_keys_e(g, 0); }
/* The party whose contribution key this is, in any epoch, or -1. */
static int w_party_of(const uint8_t ckey[33])
{
    for (uint32_t g = 0; g < 132; g++) {
        if (g >= W_MAX_NODES && g < 100) continue;
        for (uint32_t ep = 0; ep < (g < W_MAX_NODES ? W_EPOCHS : 1u); ep++)
            if (memcmp(w_keys_e(g, ep)->c, ckey, 33) == 0) return (int)g;
    }
    return -1;
}

/* ---- the lobby every test round belongs to ---- */

static void w_tag32(const char *tag, uint8_t out[32]) { w_secret(tag, 0, out); }
static void w_chain(uint8_t out[32]) { w_tag32("test/chain", out); }
static void w_outer(uint8_t out[32]) { w_tag32("test/outer", out); }   /* the scope of every message */
static void w_terms(uint8_t out[32]) { w_tag32("test/terms", out); }

/* ---- test parameters ----
 * The host's user command (W_PARAMS bytes): [0] version 2, [1] tiers (1 or
 * 2), [2..5] attempt (BE), [6..9] member mask (BE; bit g = party g takes
 * part, g = 1..16), [10] flags, [11] 0. The host turns them into a
 * round_propose (w_make_begin); every party's builder rebuilds the tree from
 * the proposal alone. Every leaf is pseudo-Spilman with one member: by
 * default the binary shape (factory_set_arity PS, fixed_levels 0); with
 * WF_T1 the shape of terms.md T1 (interior width 4 above 4 members, leaf
 * kind 3, every interior level fixed: fixed_levels D), which at 16 members is
 * 17 participants and 45 items. */
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
static void w_wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

/* The P2TR output of the BIP 86 tweaked aggregate of `n` factory keys. */
static int w_agg_script(const uint8_t (*keys)[33], size_t n, uint8_t spk[34])
{
    secp256k1_pubkey pks[GZ_SIGN_MAX_PARTICIPANTS], tw;
    const secp256k1_pubkey *ptr[GZ_SIGN_MAX_PARTICIPANTS];
    secp256k1_xonly_pubkey agg, x;
    secp256k1_musig_keyagg_cache c;
    uint8_t ser[32], t[32];
    for (size_t i = 0; i < n; i++) {
        if (!secp256k1_ec_pubkey_parse(w_ctx(), &pks[i], keys[i], 33)) return 0;
        ptr[i] = &pks[i];
    }
    if (!secp256k1_musig_pubkey_agg(w_ctx(), NULL, &agg, &c, ptr, n) || !secp256k1_xonly_pubkey_serialize(w_ctx(), ser, &agg)) return 0;
    sha256_tagged("TapTweak", ser, 32, t);
    if (!secp256k1_musig_pubkey_xonly_tweak_add(w_ctx(), &tw, &c, t) || !secp256k1_xonly_pubkey_from_pubkey(w_ctx(), &x, NULL, &tw)) return 0;
    spk[0] = 0x51; spk[1] = 0x20;
    return secp256k1_xonly_pubkey_serialize(w_ctx(), spk + 2, &x);
}

/* An unsigned funding transaction: one input (a made-up coin named by
 * `seed`), one output of `amount` to `spk`. Returns its length (94). */
static size_t w_funding_tx(const uint8_t seed[8], uint64_t amount, const uint8_t spk[34], uint8_t out[100])
{
    size_t n = 0;
    uint8_t prev[32];
    sha256_tagged("test/funding", seed, 8, prev);
    out[n++] = 2; out[n++] = 0; out[n++] = 0; out[n++] = 0;             /* version */
    out[n++] = 1;                                                        /* one input */
    memcpy(out + n, prev, 32); n += 32;
    memset(out + n, 0, 4); n += 4;                                       /* vout 0 */
    out[n++] = 0;                                                        /* no script */
    memset(out + n, 0xff, 4); n += 4;                                    /* sequence */
    out[n++] = 1;                                                        /* one output */
    for (int b = 0; b < 8; b++) out[n++] = (uint8_t)(amount >> (8 * b));
    out[n++] = 34; memcpy(out + n, spk, 34); n += 34;
    memset(out + n, 0, 4); n += 4;                                       /* lock time */
    return n;
}

/* ---- the tree, from the proposal ---- */

typedef struct {
    size_t n;                                   /* participants, host first */
    const gz_tree_participant_t *parts;
    uint8_t tiers, t1;
    uint8_t funding_txid[32];
    uint32_t funding_vout;
    uint64_t funding_amount;
    uint8_t funding_script[34];
    uint8_t damage;                             /* WF_BAD_MODE, WF_DUP_SIGNER, WF_BAD_SCRIPT */
} w_tree_in_t;

static int w_build_tree(const w_tree_in_t *in, gz_sign_def_t *d, factory_t **keep)
{
    secp256k1_context *ctx = w_ctx();
    secp256k1_pubkey pks[GZ_SIGN_MAX_PARTICIPANTS];
    size_t n = in->n;
    if (n < 2 || n > W_MAX_NODES || in->tiers < 1 || in->tiers > 2) return 0;
    memset(d, 0, sizeof *d);
    for (size_t i = 0; i < n; i++) {
        int g = w_party_of(in->parts[i].contribution_key);
        if (!secp256k1_ec_pubkey_parse(ctx, &pks[i], in->parts[i].factory_key, 33)) return 0;
        d->peer[i] = g >= 0 ? (uint64_t)g : 1000u + i;
    }
    /* The participants as the engine will set them (tests that change the items read them). */
    d->n_participants = (uint8_t)n;
    for (size_t i = 0; i < n; i++) d->participants[i] = in->parts[i];
    w_chain(d->chain); w_outer(d->outer_digest);
    memcpy(d->host_key, w_keys(0)->c, 33);
    d->n_tiers = in->tiers;

    factory_t *f = calloc(1, sizeof *f);
    if (!f) return 0;
    factory_init_from_pubkeys(f, ctx, pks, n, 144, 4);
    if (in->t1) {
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
    factory_set_funding(f, in->funding_txid, in->funding_vout, in->funding_amount, in->funding_script, 34);
    if (!factory_build_tree(f) || f->n_nodes == 0 || f->n_nodes > GZ_SIGN_MAX_ITEMS) { factory_free(f); free(f); return 0; }
    d->n_items = (uint16_t)f->n_nodes;
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *nd = &f->nodes[i];
        gz_sign_item_t *it = &d->items[i];
        if (nd->unsigned_tx.len > GZ_SIGN_MAX_TX || nd->n_signers > GZ_SIGN_MAX_SIGNERS) { factory_free(f); free(f); return 0; }
        it->tier = (uint8_t)(in->tiers == 2 && i >= f->n_nodes / 2);
        it->mode = (in->damage & WF_BAD_MODE) ? 2 : GZ_SIGN_MODE_KEYPATH;
        it->has_merkle_root = (uint8_t)(nd->has_taptree != 0);
        if (nd->has_taptree) memcpy(it->merkle_root, nd->merkle_root, 32);
        it->n_signers = (uint8_t)nd->n_signers;
        for (size_t s = 0; s < nd->n_signers; s++) it->signers[s] = (uint8_t)nd->signer_indices[s];
        if ((in->damage & WF_DUP_SIGNER) && it->n_signers > 2) it->signers[1] = it->signers[2];
        if (nd->parent_index < 0) {
            it->spent_amount = f->funding_amount_sats;
            memcpy(it->spent_script, f->funding_spk, 34);
        } else {
            const tx_output_t *o = &f->nodes[nd->parent_index].outputs[nd->parent_vout];
            it->spent_amount = o->amount_sats;
            memcpy(it->spent_script, o->script_pubkey, 34);
        }
        if ((in->damage & WF_BAD_SCRIPT) && i == f->n_nodes - 1) it->spent_script[5] ^= 1;
        it->tx_len = (uint16_t)nd->unsigned_tx.len;
        memcpy(it->tx, nd->unsigned_tx.data, nd->unsigned_tx.len);
    }
    if (keep) *keep = f;
    else { factory_free(f); free(f); }
    return 1;
}

/* The tree inputs a proposal names. */
static void w_tree_in(const gz_tree_proposal_t *p, uint8_t damage, w_tree_in_t *t)
{
    memset(t, 0, sizeof *t);
    t->n = p->n_participants; t->parts = p->participants;
    t->tiers = p->n_tiers > 2 ? 1 : p->n_tiers;   /* more tiers only in tests that spread the items themselves */
    t->t1 = p->fixed_levels != 0;
    memcpy(t->funding_txid, p->funding_txid, 32);
    t->funding_vout = p->funding_vout; t->funding_amount = p->funding_amount;
    memcpy(t->funding_script, p->funding_script, 34);
    t->damage = damage;
}

/* What the host proposes, from test parameters: kept here so the pointers
 * of gz_sign_begin_t stay valid. */
typedef struct {
    gz_tree_proposal_t p;
    gz_tree_participant_t parts[GZ_SIGN_MAX_PARTICIPANTS];
    uint8_t funding_tx[100];
    uint8_t check_id[32];
    gz_sign_begin_t b;
} w_begin_t;

typedef struct {
    gz_sign_def_t last;
    w_tree_in_t last_in;
    gz_tree_participant_t last_parts[GZ_SIGN_MAX_PARTICIPANTS];
    int have_last;
    uint64_t builds;
    uint8_t damage;                             /* tests only: every builder damages what it builds */
    uint8_t flags;                              /* the flags of the host's latest parameters (for retries) */
    void (*mutate)(gz_sign_def_t *d, int which);   /* tests only: damage the built definition */
    int which;
    void (*mutate_proposal)(gz_tree_proposal_t *p, int which);   /* tests only: damage what the host proposes */
    w_begin_t next;                             /* storage for a retry */
    uint16_t refuse;                            /* tests only: members refuse every proposal with this reason */
    /* The lobby's view of each party's current key epoch: the keys the host
     * proposes (a restored member joins again with its new keys). */
    uint32_t epoch[W_MAX_NODES];
    /* The hooks' side (gz_sign_config_t may_ack, guard, outcome). */
    uint32_t tip;                               /* every member's tip, for may_ack */
    uint64_t may_ack_calls, may_ack_refused, guards;
    uint8_t guard_bytes[8];
    int outcomes[64]; size_t n_outcomes, outcome_blamed[64];
} w_builder_t;

/* may_ack: the signing-time check again at the member's tip (gz_tree_may_ack),
 * with Slice 1's conditions: signet's exit constants, a 36-block funding
 * deadline. The member's depth here is its items less one (the test world's
 * stand-in for the verdict's own_depth). */
static int w_may_ack(void *ctx, const gz_sign_round_t *r, uint32_t *ack_tip)
{
    w_builder_t *b = ctx;
    gz_tree_conditions_t cond;
    int items = 0, ok;
    memset(&cond, 0, sizeof cond);
    cond.exit = gz_exit_signet();
    cond.funding_deadline_blocks = 36;
    for (int i = 0; i < r->def.n_items; i++)
        for (int s = 0; s < r->def.items[i].n_signers; s++) items += r->def.items[i].signers[s] == r->me;
    b->may_ack_calls++;
    *ack_tip = b->tip;
    ok = gz_tree_may_ack(r->def.end_height, (uint8_t)(items > 0 ? items - 1 : 0), b->tip, &cond);
    b->may_ack_refused += !ok;
    return ok;
}

/* guard: a stand-in for the node's guard record (journal.md 8.3): its counter. */
static int w_guard(void *ctx, gz_record_t *rec)
{
    w_builder_t *b = ctx;
    uint64_t c = ++b->guards;
    for (int i = 0; i < 8; i++) b->guard_bytes[i] = (uint8_t)(c >> (56 - 8 * i));
    rec->type = GZ_SIGN_REC_GUARD; rec->bytes.data = b->guard_bytes; rec->bytes.len = 8;
    return 1;
}

/* outcome: kept for the tests (the lobby adapter is tested apart). */
static gz_status_t w_outcome(void *ctx, const gz_sign_outcome_t *o, gz_action_list_t *out)
{
    w_builder_t *b = ctx;
    (void)out;
    if (b->n_outcomes < 64) { b->outcome_blamed[b->n_outcomes] = o->n_blamed; b->outcomes[b->n_outcomes++] = (int)o->kind; }
    return GZ_OK;
}

static void w_hooks(w_builder_t *b, gz_sign_config_t *c)
{
    c->may_ack = w_may_ack; c->guard = w_guard; c->outcome = w_outcome; c->hook_ctx = b;
}

/* Test parameters into a proposal. 0 if they are not valid parameters. */
static int w_make_begin(w_builder_t *b, const uint8_t *p, size_t len, w_begin_t *out)
{
    uint8_t keys[GZ_SIGN_MAX_PARTICIPANTS][33], seed[8], t[32];
    w_tree_in_t tin;
    gz_sign_def_t *d;
    size_t n = 0;
    if (len != W_PARAMS || p[0] != 2 || p[1] < 1 || p[1] > 2 || p[11] != 0) return 0;
    uint32_t mask = w_be32(p + 6), attempt = w_be32(p + 2);
    uint8_t flags = p[10];
    if (mask & ~0x1fffeu) return 0;
    memset(out, 0, sizeof *out);
    for (uint32_t g = 0; g < W_MAX_NODES; g++) {
        uint32_t ep = b && g ? b->epoch[g] : 0;
        if (g && !(mask >> g & 1u)) continue;
        memcpy(out->parts[n].factory_key, w_keys_e((flags & WF_DUP_KEY) && g == 2 ? 1 : g, (flags & WF_DUP_KEY) && g == 2 ? 0 : ep)->f, 33);
        memcpy(out->parts[n].contribution_key, w_keys_e(g, ep)->c, 33);
        memcpy(keys[n], out->parts[n].factory_key, 33);
        n++;
    }
    if (n < 2) return 0;
    gz_tree_proposal_t *q = &out->p;
    q->purpose = 1; q->terms_version = 1;
    w_terms(q->terms_digest);
    q->funding_amount = (uint64_t)n * 100000u + 1000000u;
    if (!w_agg_script((const uint8_t (*)[33])keys, n, q->funding_script)) return 0;
    q->funding_script_len = 34;
    memcpy(seed, p + 2, 4); seed[4] = p[8]; seed[5] = p[9]; seed[4] ^= p[7]; seed[6] = 0x46; seed[7] = 0x44;
    if (flags & WF_SAME_TREE) memset(seed, 0, 4);       /* every attempt on one funding outpoint */
    q->funding_tx_len = w_funding_tx(seed, q->funding_amount, q->funding_script, out->funding_tx);
    q->funding_tx = out->funding_tx;
    gz_sign_txid(out->funding_tx, q->funding_tx_len, q->funding_txid);
    q->funding_vout = 0;
    q->participants = out->parts; q->n_participants = n;
    q->n_tiers = p[1];
    q->end_height = 100000; q->tree_anchors = 1; q->fee_per_tx = 200; q->lstock_delay = 144;
    q->fixed_levels = (flags & WF_T1) ? (n - 1 <= 8 ? 2 : 3) : 0;
    q->k = 1; q->layer_step = 144; q->layer_states = 4;
    q->nonces_due_ms = 30000; q->sigs_due_ms = 30000;
    /* the tier sizes: the host builds the tree once to count */
    w_tree_in(q, 0, &tin);
    d = calloc(1, sizeof *d);
    if (!d || !w_build_tree(&tin, d, NULL)) { free(d); return 0; }
    if (b && b->mutate) {                   /* tests: the tiers of the definition as the builder will damage it */
        b->mutate(d, b->which);
        q->n_tiers = d->n_tiers > 8 ? 8 : d->n_tiers;
    }
    for (int i = 0; i < d->n_items && i < GZ_SIGN_MAX_ITEMS; i++)
        if (d->items[i].tier < 8) q->tier_sizes[d->items[i].tier]++;
    free(d);
    if (b && b->mutate_proposal) b->mutate_proposal(q, b->which);
    w_wr32(t, attempt); memset(t + 4, 0, 28);
    sha256_tagged("test/check", t, 32, out->check_id);
    out->b.p = q; out->b.check_id = out->check_id; out->b.has_attempt = 1; out->b.attempt = (uint16_t)attempt;
    if (b) b->flags = flags;
    return 1;
}

/* The tree test parameters give (for tests that build it themselves). */
static inline int w_build_params(const uint8_t *p, gz_sign_def_t *d, factory_t **keep)
{
    static w_begin_t wb;
    w_tree_in_t t;
    if (!w_make_begin(NULL, p, W_PARAMS, &wb)) return 0;
    w_tree_in(&wb.p, 0, &t);
    return w_build_tree(&t, d, keep);
}

static uint16_t w_build(void *ctx, const gz_sign_build_in_t *in, gz_sign_def_t *out)
{
    w_builder_t *b = ctx;
    const gz_tree_proposal_t *p = &in->msg->p;
    w_tree_in_t t;
    if (b->refuse && in->scope && !in->replay) return b->refuse;   /* a member's checks refuse (not the host's own build) */
    w_tree_in(p, b->damage, &t);
    if (b->mutate) {
        if (!w_build_tree(&t, out, NULL)) return 1;
        b->mutate(out, b->which);
        return 0;
    }
    if (b->have_last && t.n == b->last_in.n && t.tiers == b->last_in.tiers && t.t1 == b->last_in.t1 && t.damage == b->last_in.damage &&
        memcmp(t.funding_txid, b->last_in.funding_txid, 32) == 0 && t.funding_amount == b->last_in.funding_amount &&
        t.funding_vout == b->last_in.funding_vout && memcmp(t.funding_script, b->last_in.funding_script, 34) == 0 &&
        memcmp(t.parts, b->last_parts, t.n * sizeof *t.parts) == 0) { *out = b->last; return 0; }
    if (!w_build_tree(&t, out, NULL)) return 1;
    b->builds++;
    b->last = *out; b->last_in = t;
    memcpy(b->last_parts, t.parts, t.n * sizeof *t.parts);
    b->last_in.parts = b->last_parts;
    b->have_last = 1;
    return 0;
}

/* The test parameters a round was proposed from (attempt from record 7). */
static inline size_t w_params_of(const gz_sign_round_t *r, uint8_t out[W_PARAMS], uint8_t flags)
{
    uint32_t mask = 0;
    uint16_t attempt = 0;
    gz_sign_msg_t m;
    static gz_rmsg_propose_t pr;
    for (int j = 1; j < r->def.n_participants; j++) {
        int g = w_party_of(r->def.participants[j].contribution_key);
        if (g > 0 && g < W_MAX_NODES) mask |= (uint32_t)1u << g;
    }
    if (gz_sign_decode(r->proposal, r->proposal_len, &m) && gz_rmsg_propose_decode(m.records, m.records_len, &pr) == GZ_RMSG_OK)
        attempt = pr.attempt;
    return w_params(out, r->def.n_tiers, attempt, mask, flags);
}

/* Next attempt: attempt + 1, without the blamed (participant indexes of the failed round). */
static int w_retry(void *ctx, const gz_sign_retry_in_t *in, gz_sign_begin_t *next)
{
    w_builder_t *b = ctx;
    uint8_t p[W_PARAMS];
    const gz_sign_round_t *r = in->failed;
    w_params_of(r, p, b->flags);
    uint32_t mask = w_be32(p + 6), next_mask = 0;
    for (int j = 1; j < r->def.n_participants; j++) {
        int g = w_party_of(r->def.participants[j].contribution_key);
        if (g > 0 && g < W_MAX_NODES && !(in->blamed >> j & 1u)) next_mask |= (uint32_t)1u << g;
    }
    (void)mask;
    if (!next_mask) return 0;
    w_params(p, p[1], w_be32(p + 2) + 1, next_mask, b->flags);
    if (!w_make_begin(b, p, W_PARAMS, &b->next)) return 0;
    *next = b->next.b;
    return 1;
}

/* ---- messages, as a program at fault would change them ---- */

/* Sign the records of `msg` (an envelope) as party g would: the signature
 * record 240 is the last 64 bytes. */
static void w_resign(uint8_t *msg, size_t len, uint32_t g)
{
    uint8_t sk[32], d[32], aux[32] = {7};
    secp256k1_keypair kp;
    gz_sign_msg_t m;
    if (!gz_sign_decode(msg, len, &m) || !m.sig) {
        /* not decodable (damaged records, or a proposal, which the view does not
         * read): sign everything before the last record, 240's 66 bytes */
        if (len < GZ_RMSG_HEADER + 66) return;
        gz_rmsg_hash((uint16_t)(msg[4] << 8 | msg[5]), msg + 6, msg + GZ_RMSG_HEADER, len - GZ_RMSG_HEADER - 66, d);
    } else gz_rmsg_hash(m.kind, m.scope, m.records, m.signed_len, d);
    w_secret("test/contribution", g, sk);
    if (!secp256k1_keypair_create(w_ctx(), &kp, sk)) abort();
    secp256k1_schnorrsig_sign32(w_ctx(), msg + len - 64, d, &kp, aux);
}

/* A nonce entry (u32 index, 66 nonce, 64 sig) signed by party g. */
static void w_sign_nonce(uint8_t *entry, const uint8_t id[32], uint8_t tier, uint32_t g)
{
    uint8_t sk[32], d[32], aux[32] = {9};
    secp256k1_keypair kp;
    w_secret("test/contribution", g, sk);
    if (!secp256k1_keypair_create(w_ctx(), &kp, sk)) abort();
    gz_rmsg_nonce_hash(id, tier, w_be32(entry), entry + 4, d);
    secp256k1_schnorrsig_sign32(w_ctx(), entry + 70, d, &kp, aux);
}

/* A message of `kind` in the test lobby's scope with the given records
 * (types increasing; type 240 means "sign as party g"). Returns its length. */
typedef struct { uint64_t type; const void *v; size_t len; } w_rec_t;
static inline size_t w_message(uint8_t *out, size_t cap, uint16_t kind, const w_rec_t *recs, size_t n, int g)
{
    uint8_t scope[32], zero[64] = {0};
    gz_rmsg_wr_t w;
    size_t h;
    w_outer(scope);
    h = gz_rmsg_header(out, cap, kind, scope);
    gz_rmsg_wr_init(&w, out + h, cap - h);
    for (size_t i = 0; i < n; i++) gz_rmsg_put(&w, recs[i].type, recs[i].v, recs[i].len);
    if (g >= 0) gz_rmsg_put(&w, GZ_RMSG_SIG_TYPE, zero, 64);
    if (!gz_rmsg_wr_ok(&w)) return 0;
    if (g >= 0) w_resign(out, h + w.n, (uint32_t)g);
    return h + w.n;
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
typedef struct { uint32_t node; uint8_t round[32]; uint32_t item; uint16_t kind; uint8_t value[66]; } w_contrib_t;

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
    uint8_t first_proposal[GZ_SIGN_MAX_PROPOSAL];
    size_t first_proposal_len;
    uint64_t secrets_checked, zero_checks;
    uint64_t fuzz_state, fuzzed;
    uint32_t fuzz_pm;
    uint32_t max_attempts;      /* 0: 16 */
};

/* Apply this program's fault to what it is about to hand over. */
static uint64_t w_rand(world_t *w)
{
    w->fuzz_state = w->fuzz_state * 6364136223846793005ull + 1442695040888963407ull;
    return w->fuzz_state >> 33;
}

/* Fuzzing: damage some of what any party sends, in place: flip bytes, cut
 * the end, or change a byte of the records' start. The engine must neither
 * crash nor reach the library with an unparsed value. */
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
        case 2: if (len > 41) b[38 + w_rand(w) % 4] = (uint8_t)w_rand(w); break;
        default: b[w_rand(w) % len] = (uint8_t)w_rand(w); break;
        }
        w->fuzzed++;
    }
}

static uint8_t w_copy[GZ_SIGN_MAX_MSG];

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
        size_t len = a->u.send.bytes.len;
        if (w->fault == WX_BAD_PARTIAL && m.kind == GZ_SIGN_MSG_PARTIALS && m.n) {
            uint8_t *ps = (uint8_t *)(uintptr_t)m.entry[0] + 4;
            ps[31] ^= 1; ps[0] &= 0x7f;
            w_resign(b, len, n->index);
        } else if (w->fault == WX_BAD_SCALAR && m.kind == GZ_SIGN_MSG_PARTIALS && m.n) {
            memset((uint8_t *)(uintptr_t)m.entry[0] + 4, 0xff, 32);
            w_resign(b, len, n->index);
        } else if (w->fault == WX_PARTIAL_TWICE && m.kind == GZ_SIGN_MSG_PARTIALS && m.n) {
            /* the honest message, then a second one with a different partial signature */
            memcpy(w_copy, b, len);
            w_copy[(size_t)(m.entry[0] - b) + 4 + 31] ^= 1;
            w_resign(w_copy, len, n->index);
            gz_action_t extra = *a;
            extra.u.send.bytes.data = w_copy;
            gz_action_list_add(list, &extra);
        } else if (w->fault == WX_BAD_RESULT && m.kind == GZ_SIGN_MSG_RESULT && m.n) {
            ((uint8_t *)(uintptr_t)m.entry[0])[4 + 10] ^= 1;
            w_resign(b, len, 0);
        } else if ((w->fault == WX_ALTER_NONCE || w->fault == WX_SWAP_NONCE) && m.kind == GZ_SIGN_MSG_ALL_NONCES && m.n) {
            const gz_sign_round_t *r = gz_sign_latest(&n->eng);
            /* someone else's nonce, neither the host's nor the recipient's */
            for (int k2 = 0; r && k2 < m.n; k2++) {
                uint8_t *e = (uint8_t *)(uintptr_t)m.entry[k2];
                uint32_t i = w_be32(e);
                for (int s = 0; s < e[5]; s++) {
                    uint8_t q = r->def.items[i].signers[s];
                    if (q == 0 || r->def.peer[q] == a->u.send.peer_id) continue;
                    if (w->fault == WX_ALTER_NONCE) { e[6 + 130 * s + 40] ^= 1; k2 = m.n; break; }
                    /* move q's signed nonce for item i into another item of q in this message */
                    for (int k3 = k2 + 1; k3 < m.n; k3++) {
                        uint8_t *e3 = (uint8_t *)(uintptr_t)m.entry[k3];
                        uint32_t i3 = w_be32(e3);
                        for (int s3 = 0; s3 < e3[5]; s3++)
                            if (r->def.items[i3].signers[s3] == q) { memcpy(e3 + 6 + 130 * s3, e + 6 + 130 * s, 130); k2 = k3 = m.n; s = e[5]; break; }
                    }
                }
            }
        } else if ((w->fault == WX_EQUIVOCATE || w->fault == WX_BAD_POINT) && m.kind == GZ_SIGN_MSG_NONCES && m.n) {
            memcpy(w_copy, b, len);
            uint8_t *e = w_copy + (m.entry[0] - b);
            if (w->fault == WX_BAD_POINT) { memset(e + 4, 0xff, 66); e[4] = 2; }
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
            if (w->fault == WX_BAD_POINT) { memcpy(b, w_copy, len); continue; }
            gz_action_t extra = {.kind = GZ_ACTION_SEND};
            extra.u.send.peer_id = a->u.send.peer_id;
            extra.u.send.bytes.data = w_copy; extra.u.send.bytes.len = len;
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

#define W_REC_KEY_EPOCH 0x00040002u   /* journal.md 9, node area: `key_epoch` */

/* The key epoch a node's storage holds (its newest key_epoch record), 0 if none. */
static uint32_t w_stored_epoch(const sim_storage_t *storage)
{
    uint32_t ep = 0;
    for (size_t i = 0; i < sim_storage_count(storage); i++) {
        size_t len;
        const uint8_t *p = sim_storage_batch_bytes(storage, i, &len), *end = p + len;
        while (p + 8 <= end) {
            uint32_t type = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
            uint32_t l = (uint32_t)p[4] | (uint32_t)p[5] << 8 | (uint32_t)p[6] << 16 | (uint32_t)p[7] << 24;
            if (type == W_REC_KEY_EPOCH && l == 4) ep = w_be32(p + 8);
            p += 8 + l;
        }
    }
    return ep;
}

static void w_engine_config(world_t *w, uint32_t index, gz_sign_config_t *c)
{
    uint32_t ep = index ? w->builder.epoch[index] : 0;
    memset(c, 0, sizeof *c);
    c->host = index == 0; c->ctx = w_ctx();
    w_secret("test/factory", w_secret_index(index, ep), c->factory_secret);
    w_secret("test/contribution", w_secret_index(index, ep), c->contribution_secret);
    w_hooks(&w->builder, c);
    c->build = w_build; c->retry = w_retry; c->build_ctx = &w->builder;
    c->tick_ms = 1; c->resend_ticks = 40; c->deadline_ticks = 400; c->status_ticks = 10;
    c->max_attempts = w->max_attempts ? w->max_attempts : 16;
}

static void *w_create(void *ops_ctx, uint32_t index, const gz_ports_t *ports, const sim_storage_t *storage)
{
    world_t *w = ops_ctx;
    w_node_t *n = calloc(1, sizeof *n);
    gz_sign_config_t c;
    if (!n) abort();
    /* journal.md 8.2: a start after a restore takes a new epoch (saved in the
     * restore batch); any other start the stored one. The lobby learns it. */
    if (index) {
        uint32_t ep = w_stored_epoch(storage);
        if (sim_storage_restored(storage)) ep = (w->builder.epoch[index] > ep ? w->builder.epoch[index] : ep) + 1;
        if (ep >= W_EPOCHS) ep = W_EPOCHS - 1;
        w->builder.epoch[index] = ep;
    }
    w_engine_config(w, index, &c);
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
        uint8_t inc[8], ep[4];
        uint64_t v = sim_storage_incarnation(n->storage);
        for (int b = 0; b < 8; b++) inc[b] = (uint8_t)(v >> (56 - 8 * b));
        w_wr32(ep, n->index ? n->w->builder.epoch[n->index] : 0);
        gz_record_t recs[2] = {{W_REC_KEY_EPOCH, {ep, 4}}, {W_REC_RESTORED, {inc, 8}}};
        gz_action_t a = {.kind = GZ_ACTION_SAVE};
        a.u.save.records = recs; a.u.save.n_records = 2;
        gz_status_t s0 = gz_action_list_add(out, &a);
        if (s0 != GZ_OK) return s0;
    }
    gz_status_t st = gz_sign_start(&n->eng, &r, out, more);
    if (st == GZ_OK) w_apply_fault(n, out);
    return st;
}

/* The host's user command: test parameters, turned into a proposal. */
static gz_status_t w_begin_params(gz_sign_t *e, w_builder_t *b, const uint8_t *p, size_t len, gz_action_list_t *out)
{
    static w_begin_t wb;
    if (!w_make_begin(b, p, len, &wb)) return GZ_ERR_ARGUMENT;
    return gz_sign_begin(e, &wb.b, out);
}

static gz_status_t w_handle(void *node, const gz_event_t *ev, gz_action_list_t *out)
{
    w_node_t *n = node;
    gz_status_t st;
    if (ev->kind == GZ_EVENT_USER_COMMAND) {
        st = w_begin_params(&n->eng, &n->w->builder, ev->u.user.bytes.data, ev->u.user.bytes.len, out);
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
        c.item = w_be32(m.entry[k]);
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
    c.step_slots = 128; c.step_bytes = 4u << 20; c.runner_slots = 512; c.runner_bytes = 8u << 20;
    c.ops.create = w_create; c.ops.destroy = w_destroy; c.ops.start = w_start; c.ops.handle = w_handle;
    c.ops.inspect = w_inspect; c.ops.observe = w_observe; c.ops.ctx = w;
    return c;
}

static uint32_t w_mask(uint32_t members) { return (((uint32_t)1u << (members + 1)) - 1u) & ~1u; }

#endif
