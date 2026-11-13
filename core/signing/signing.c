/* The signing round engine. See gazpacho/signing.h and spec/signing-round.md.
 *
 * Lines marked RULE:<name> carry one rule each; tools/signing-rules.py removes
 * them one at a time and checks that a test fails. */
#include "gazpacho/signing.h"
#include <secp256k1_schnorrsig.h>
#include <string.h>

#define TIMER_ID 0x5347u
#define WHOLE_ROUND 0xffu

/* ---- small helpers ---- */

typedef struct { uint8_t *p; size_t n, cap; } wr_t;

static void put(wr_t *w, const void *d, size_t n)
{
    if (w->cap - w->n < n) { w->cap = 0; return; }   /* overflow: poison the writer */
    if (n) memcpy(w->p + w->n, d, n);
    w->n += n;
}
static void put8(wr_t *w, uint8_t v) { put(w, &v, 1); }
static void put16(wr_t *w, uint32_t v) { uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v}; put(w, b, 2); }
static void put32(wr_t *w, uint32_t v)
{
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    put(w, b, 4);
}
static void put64(wr_t *w, uint64_t v) { put32(w, (uint32_t)(v >> 32)); put32(w, (uint32_t)v); }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static void wipe(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

static void tagged(const char *tag, const uint8_t *a, size_t an, const uint8_t *b, size_t bn, uint8_t out[32])
{
    gz_sign_sha256_t s;
    gz_sign_tagged_init(&s, tag);
    gz_sign_sha256_write(&s, a, an);
    if (bn) gz_sign_sha256_write(&s, b, bn);
    gz_sign_sha256_done(&s, out);
}

static int same(const void *a, const void *b, size_t n) { return memcmp(a, b, n) == 0; }

static int pos_of(const gz_sign_item_t *it, uint8_t participant)
{
    for (int s = 0; s < it->n_signers; s++)
        if (it->signers[s] == participant) return s;
    return -1;
}

/* Bit masks over at most 32 positions (participants or an item's signers). */
static uint32_t bit(unsigned s) { return (uint32_t)1u << s; }
static uint32_t mask_n(unsigned n) { return n >= 32 ? 0xffffffffu : bit(n) - 1u; }
static uint32_t all_bits(const gz_sign_item_t *it) { return mask_n(it->n_signers); }
/* Every member of the round (participant 0, the host, excluded). */
static uint32_t members_mask(const gz_sign_round_t *r) { return mask_n(r->def.n_participants) & ~1u; }

/* ---- actions ---- */

typedef struct { gz_action_list_t *out; gz_status_t st; } emit_t;

static void emit_save(emit_t *em, uint32_t type, const uint8_t *bytes, size_t len)
{
    gz_record_t rec = {type, {bytes, len}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &rec;
    a.u.save.n_records = 1;
    if (em->st == GZ_OK) em->st = gz_action_list_add(em->out, &a);
}

static void emit_send(emit_t *em, uint64_t peer, const uint8_t *bytes, size_t len)
{
    gz_action_t a = {.kind = GZ_ACTION_SEND};
    a.u.send.peer_id = peer;
    a.u.send.bytes.data = bytes;
    a.u.send.bytes.len = len;
    if (em->st == GZ_OK) em->st = len ? gz_action_list_add(em->out, &a) : GZ_ERR_NO_SPACE;
}

static void emit_timer(gz_sign_t *e, emit_t *em)
{
    gz_action_t a = {.kind = GZ_ACTION_SET_TIMER};
    a.u.set_timer.timer_id = TIMER_ID;
    a.u.set_timer.delay_ms = e->cfg.tick_ms;
    if (em->st == GZ_OK) em->st = gz_action_list_add(em->out, &a);
}

/* ---- signatures over messages ---- */

static void sign_digest(gz_sign_t *e, const uint8_t digest[32], uint8_t sig[64])
{
    uint8_t aux[32];
    e->ports.random.fill(e->ports.random.ctx, GZ_RANDOM_ORDINARY, aux, 32);
    if (!secp256k1_schnorrsig_sign32(e->cfg.ctx, sig, digest, &e->contribution_kp, aux)) memset(sig, 0, 64);
}

static int verify_digest(const gz_sign_t *e, const uint8_t key[32], const uint8_t digest[32], const uint8_t sig[64])
{
    secp256k1_xonly_pubkey pk;
    return secp256k1_xonly_pubkey_parse(e->cfg.ctx, &pk, key) &&
           secp256k1_schnorrsig_verify(e->cfg.ctx, sig, digest, 32, &pk);
}

/* Sign a message: append TH("gazpacho/msg", bytes so far) signed. */
static void finish_msg(gz_sign_t *e, wr_t *w)
{
    uint8_t d[32], sig[64];
    tagged("gazpacho/msg", w->p, w->n, NULL, 0, d);
    sign_digest(e, d, sig);
    put(w, sig, 64);
}

static int msg_signed_by(const gz_sign_t *e, const gz_sign_msg_t *m, const uint8_t *bytes, const uint8_t key[32])
{
    uint8_t d[32];
    tagged("gazpacho/msg", bytes, m->signed_len, NULL, 0, d);
    return verify_digest(e, key, d, m->sig);
}

static void nonce_digest(const uint8_t id[32], uint8_t tier, uint32_t index, const uint8_t nonce[66], uint8_t out[32])
{
    uint8_t pre[32 + 1 + 4 + 66];
    wr_t w = {pre, 0, sizeof pre};
    put(&w, id, 32); put8(&w, tier); put32(&w, index);   /* RULE:NONCE_SIG_COVERS_ITEM */
    put(&w, nonce, 66);
    tagged("gazpacho/nonce", pre, w.n, NULL, 0, out);
}

static void header(wr_t *w, uint8_t kind, const uint8_t id[32])
{
    put8(w, 'G'); put8(w, 'S'); put8(w, kind); put(w, id, 32);
}

/* ---- the round definition ---- */

/* Check a definition and compute each item's key-aggregation cache (tweaked)
 * and signature digest. Every key is parsed here, before any other call. */
static int check_def(const gz_sign_t *e, const gz_sign_def_t *d, gz_sign_round_t *r)
{
    const secp256k1_context *ctx = e->cfg.ctx;
    secp256k1_pubkey pks[GZ_SIGN_MAX_PARTICIPANTS];
    if (d->n_participants < 2 || d->n_participants > GZ_SIGN_MAX_PARTICIPANTS) return 0;
    if (d->n_tiers < 1 || d->n_tiers > GZ_SIGN_MAX_TIERS || d->n_items < 1 || d->n_items > GZ_SIGN_MAX_ITEMS) return 0;
    for (int i = 0; i < d->n_participants; i++) {
        secp256k1_xonly_pubkey x;
        if (!secp256k1_ec_pubkey_parse(ctx, &pks[i], d->participants[i].factory_key, 33)) return 0;
        if (!secp256k1_xonly_pubkey_parse(ctx, &x, d->participants[i].contribution_key)) return 0;
        for (int j = 0; j < i; j++)                                                   /* RULE:DUPLICATE_KEYS */
            if (same(d->participants[i].factory_key, d->participants[j].factory_key, 33) ||
                same(d->participants[i].contribution_key, d->participants[j].contribution_key, 32) ||
                d->participants[i].peer == d->participants[j].peer) return 0;
    }
    int prev_tier = 0;
    for (int i = 0; i < d->n_items; i++) {
        const gz_sign_item_t *it = &d->items[i];
        const secp256k1_pubkey *ptrs[GZ_SIGN_MAX_SIGNERS];
        secp256k1_xonly_pubkey agg, out_x;
        secp256k1_pubkey out_pk;
        uint8_t ser[32], tweak[32];
        gz_sign_tx_t tx;
        if (it->tier < prev_tier || it->tier > prev_tier + (i > 0) || it->tier >= d->n_tiers) return 0;
        prev_tier = it->tier;
        if (it->mode != GZ_SIGN_MODE_KEYPATH || it->has_merkle_root > 1) return 0;    /* RULE:FIXED_MODE */
        if (it->n_signers < 2 || it->n_signers > GZ_SIGN_MAX_SIGNERS || pos_of(it, 0) < 0) return 0;
        for (int s = 0; s < it->n_signers; s++) {
            if (it->signers[s] >= d->n_participants) return 0;
            for (int t = 0; t < s; t++)
                if (it->signers[t] == it->signers[s]) return 0;                        /* RULE:DUPLICATE_SIGNERS */
            ptrs[s] = &pks[it->signers[s]];
        }
        if (it->tx_len > GZ_SIGN_MAX_TX || !gz_sign_tx_parse(it->tx, it->tx_len, &tx) || tx.witness_item) return 0;
        if (!secp256k1_musig_pubkey_agg(ctx, NULL, &agg, &r->cache[i], ptrs, it->n_signers)) return 0;
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &agg)) return 0;
        tagged("TapTweak", ser, 32, it->merkle_root, it->has_merkle_root ? 32 : 0, tweak);
        if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &out_pk, &r->cache[i], tweak)) return 0;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &out_x, NULL, &out_pk)) return 0;
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &out_x)) return 0;
        if (it->spent_script[0] != 0x51 || it->spent_script[1] != 0x20 || !same(it->spent_script + 2, ser, 32)) return 0;   /* RULE:SCRIPT_MATCH */
        gz_sign_tx_sighash(&tx, it->spent_amount, it->spent_script, r->digest[i]);
    }
    return prev_tier == d->n_tiers - 1;
}

static void round_id(const gz_sign_def_t *d, const uint8_t *params, size_t plen, const uint8_t host_random[32], uint8_t out[32])
{
    gz_sign_sha256_t s;
    uint8_t buf[128], pd[32];
    wr_t w = {buf, 0, sizeof buf};
    gz_sign_tagged_init(&s, "gazpacho/round_id");
    put(&w, "gzsign/0", 8); put8(&w, d->purpose); put8(&w, d->n_tiers); put8(&w, d->n_participants);
    gz_sign_sha256_write(&s, buf, w.n);
    for (int i = 0; i < d->n_participants; i++) {
        gz_sign_sha256_write(&s, d->participants[i].factory_key, 33);
        gz_sign_sha256_write(&s, d->participants[i].contribution_key, 32);
    }
    tagged("gazpacho/params", params, plen, NULL, 0, pd);
    gz_sign_sha256_write(&s, pd, 32);
    for (int i = 0; i < d->n_items; i++) {
        const gz_sign_item_t *it = &d->items[i];
        uint8_t dg[32];
        gz_sign_tx_t tx;
        w.n = 0;
        put32(&w, (uint32_t)i); put8(&w, it->tier); put8(&w, it->mode); put8(&w, it->has_merkle_root);
        put(&w, it->merkle_root, 32); put64(&w, it->spent_amount); put(&w, it->spent_script, 34);
        put8(&w, it->n_signers);
        gz_sign_sha256_write(&s, buf, w.n);
        if (gz_sign_tx_parse(it->tx, it->tx_len, &tx)) gz_sign_sha256_write(&s, tx.outpoint, 36);
        tagged("gazpacho/tx", it->tx, it->tx_len, NULL, 0, dg);   /* the digest commits to all of it */
        gz_sign_sha256_write(&s, dg, 32);
        for (int k = 0; k < it->n_signers; k++) gz_sign_sha256_write(&s, d->participants[it->signers[k]].factory_key, 33);
    }
    gz_sign_sha256_write(&s, host_random, 32);                             /* RULE:S4_FRESH_ID */
    gz_sign_sha256_done(&s, out);
}

/* ---- rounds held in memory ---- */

static gz_sign_round_t *find(gz_sign_t *e, const uint8_t id[32])
{
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++)
        if (e->rounds[i].state != GZ_SIGN_ROUND_FREE && same(e->rounds[i].id, id, 32)) return &e->rounds[i];
    return NULL;
}

static int is_known(const gz_sign_t *e, const uint8_t id[32])
{
    for (size_t i = 0; i < e->n_known; i++)
        if (same(e->known[i], id, 32)) return 1;
    return 0;
}

static void wipe_secrets(gz_sign_round_t *r)
{
    wipe(r->secnonce, sizeof r->secnonce);           /* RULE:WIPE_ON_ABORT */
    memset(r->secnonce_serial, 0, sizeof r->secnonce_serial);
}

/* A slot for a new round: a free one, or the oldest that is not running,
 * whose identifier then moves to the refused list. NULL if none (refuse). */
static gz_sign_round_t *take_slot(gz_sign_t *e, int replaying)
{
    gz_sign_round_t *best = NULL;
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) {
        gz_sign_round_t *r = &e->rounds[i];
        if (r->state == GZ_SIGN_ROUND_FREE) return r;
        if ((replaying || r->state != GZ_SIGN_ROUND_ACTIVE) && (!best || r->seq < best->seq)) best = r;
    }
    if (!best || e->n_known == GZ_SIGN_MAX_KNOWN) return NULL;
    memcpy(e->known[e->n_known++], best->id, 32);
    wipe_secrets(best);
    memset(best, 0, sizeof *best);
    return best;
}

/* Move a checked round from `pending` into a slot. NULL if no slot can be had. */
static gz_sign_round_t *adopt(gz_sign_t *e, int replaying)
{
    gz_sign_round_t *r = take_slot(e, replaying);
    if (r) *r = e->pending;
    memset(&e->pending, 0, sizeof e->pending);
    return r;
}

/* Fill a slot from a proposal; `scratch_def` holds the built definition. */
static int load_round(gz_sign_t *e, gz_sign_round_t *r, const gz_sign_msg_t *m, const uint8_t *bytes, size_t len)
{
    memset(r, 0, sizeof *r);
    r->def = e->scratch_def;
    if (!check_def(e, &r->def, r)) return GZ_SIGN_WHY_INVALID_ROUND;
    round_id(&r->def, m->params, m->params_len, m->host_random, r->id);
    if (!same(r->id, m->round_id, 32)) return GZ_SIGN_WHY_ID_MISMATCH;
    if (!msg_signed_by(e, m, bytes, r->def.participants[0].contribution_key)) return GZ_SIGN_WHY_BAD_HOST_SIG;
    int me = -1;
    uint8_t mine[33];
    size_t mlen = 33;
    if (!secp256k1_ec_pubkey_serialize(e->cfg.ctx, mine, &mlen, &e->factory_pk, SECP256K1_EC_COMPRESSED)) return GZ_SIGN_WHY_INVALID_ROUND;
    for (int i = 0; i < r->def.n_participants; i++)
        if (same(r->def.participants[i].factory_key, mine, 33) &&
            same(r->def.participants[i].contribution_key, e->contribution_x, 32)) me = i;
    if (me < 0 || (me == 0) != (e->cfg.host != 0)) return GZ_SIGN_WHY_INVALID_ROUND;
    r->me = (uint8_t)me;
    r->seq = ++e->next_seq;
    r->proposal_len = (uint16_t)len;
    memcpy(r->proposal, bytes, len);
    r->params_len = (uint16_t)m->params_len;
    memcpy(r->params, m->params, m->params_len);
    r->state = GZ_SIGN_ROUND_ACTIVE;
    return GZ_SIGN_WHY_NONE;
}

/* ---- nonces ---- */

static int make_nonce(gz_sign_t *e, gz_sign_round_t *r, int i)
{
    const gz_sign_item_t *it = &r->def.items[i];
    int s = pos_of(it, r->me);
    uint8_t rnd[32], sid[32], extra[32], pre[48];
    secp256k1_musig_pubnonce pub;
    wr_t w = {pre, 0, sizeof pre};
    if (s < 0 || r->secnonce_serial[i] || (r->have_nonce[i] >> s & 1u)) return 0;   /* RULE:S2_ONE_NONCE */
    e->ports.random.fill(e->ports.random.ctx, GZ_RANDOM_SECRET, rnd, 32);
    uint64_t serial = ++e->next_serial;
    put(&w, rnd, 32); put64(&w, e->incarnation); put64(&w, serial);   /* RULE:INCARNATION_MIX */
    tagged("gazpacho/nonce-session", pre, w.n, NULL, 0, sid);
    w.n = 0;
    put(&w, r->id, 32); put8(&w, it->tier); put32(&w, (uint32_t)i);
    tagged("gazpacho/nonce-extra", pre, w.n, NULL, 0, extra);
    int ok = secp256k1_musig_nonce_gen(e->cfg.ctx, &r->secnonce[i], &pub, sid, e->cfg.factory_secret,
                                       &e->factory_pk, r->digest[i], &r->cache[i], extra) &&
             secp256k1_musig_pubnonce_serialize(e->cfg.ctx, r->nonce[i][s], &pub);
    wipe(rnd, sizeof rnd); wipe(sid, sizeof sid); wipe(pre, sizeof pre);
    if (!ok) { wipe(&r->secnonce[i], sizeof r->secnonce[i]); return 0; }
    uint8_t d[32];
    nonce_digest(r->id, it->tier, (uint32_t)i, r->nonce[i][s], d);
    sign_digest(e, d, r->nonce_sig[i][s]);
    r->have_nonce[i] |= bit((unsigned)s);
    r->secnonce_serial[i] = serial;
    e->counters[GZ_SIGN_COUNT_NONCES_MADE]++;
    return 1;
}

/* Parse every nonce of item i and combine them into its session. */
static int make_session(gz_sign_t *e, gz_sign_round_t *r, int i)
{
    const gz_sign_item_t *it = &r->def.items[i];
    secp256k1_musig_pubnonce pn[GZ_SIGN_MAX_SIGNERS];
    const secp256k1_musig_pubnonce *ptrs[GZ_SIGN_MAX_SIGNERS];
    secp256k1_musig_aggnonce agg;
    if (r->have_nonce[i] != all_bits(it)) return 0;                     /* RULE:NO_UNSET_SLOT */
    for (int s = 0; s < it->n_signers; s++) {
        if (!secp256k1_musig_pubnonce_parse(e->cfg.ctx, &pn[s], r->nonce[i][s])) return 0;
        ptrs[s] = &pn[s];
    }
    if (!secp256k1_musig_nonce_agg(e->cfg.ctx, &agg, ptrs, it->n_signers) ||
        !secp256k1_musig_nonce_process(e->cfg.ctx, &r->session[i], &agg, r->digest[i], &r->cache[i], NULL)) return 0;
    return 1;
}

static void set_digest(const gz_sign_round_t *r, int i, uint8_t out[32])
{
    gz_sign_sha256_t s;
    gz_sign_tagged_init(&s, "gazpacho/nonceset");
    for (int k = 0; k < r->def.items[i].n_signers; k++) gz_sign_sha256_write(&s, r->nonce[i][k], 66);
    gz_sign_sha256_done(&s, out);
}

static int sign_item(gz_sign_t *e, gz_sign_round_t *r, int i, uint8_t out32[32])
{
    secp256k1_musig_partial_sig ps;
    int s = pos_of(&r->def.items[i], r->me);
    if (s < 0 || !r->secnonce_serial[i] || (r->have_psig[i] >> s & 1u)) return 0;     /* RULE:S2_ONE_PARTIAL */
    int ok = make_session(e, r, i) &&
             secp256k1_musig_partial_sign(e->cfg.ctx, &ps, &r->secnonce[i], &e->factory_kp, &r->cache[i], &r->session[i]) &&
             secp256k1_musig_partial_sig_serialize(e->cfg.ctx, out32, &ps);
    wipe(&r->secnonce[i], sizeof r->secnonce[i]);                       /* RULE:WIPE_AFTER_SIGN */
    r->secnonce_serial[i] = 0;
    if (!ok) return 0;
    memcpy(r->psig[i][s], out32, 32);
    r->have_psig[i] |= bit((unsigned)s);
    e->counters[GZ_SIGN_COUNT_PARTIALS_MADE]++;
    return 1;
}

/* ---- building messages ---- */

static size_t build_abort(gz_sign_t *e, const gz_sign_round_t *r, const uint8_t id[32], uint8_t why, uint8_t tier, uint8_t *buf, size_t cap)
{
    wr_t w = {buf, 0, cap};
    uint16_t n = 0;
    header(&w, GZ_SIGN_MSG_ABORT, id); put8(&w, why); put8(&w, tier);
    if (r && tier != WHOLE_ROUND)
        for (int i = 0; i < r->def.n_items; i++) n += r->def.items[i].tier == tier && pos_of(&r->def.items[i], r->me) >= 0;
    put16(&w, n);
    if (r && tier != WHOLE_ROUND)
        for (int i = 0; i < r->def.n_items; i++)
            if (r->def.items[i].tier == tier && pos_of(&r->def.items[i], r->me) >= 0) put32(&w, (uint32_t)i);   /* RULE:PER_ITEM_ANSWER */
    finish_msg(e, &w);
    return w.cap ? w.n : 0;
}

static size_t build_all_nonces(const gz_sign_round_t *r, uint8_t tier, uint8_t member, uint8_t *buf, size_t cap)
{
    wr_t w = {buf, 0, cap};
    uint16_t n = 0;
    header(&w, GZ_SIGN_MSG_ALL_NONCES, r->id); put8(&w, tier);
    for (int i = 0; i < r->def.n_items; i++) n += r->def.items[i].tier == tier && pos_of(&r->def.items[i], member) >= 0;
    put16(&w, n);
    for (int i = 0; i < r->def.n_items; i++) {
        const gz_sign_item_t *it = &r->def.items[i];
        if (it->tier != tier || pos_of(it, member) < 0) continue;
        put32(&w, (uint32_t)i); put8(&w, it->n_signers);
        for (int s = 0; s < it->n_signers; s++) { put(&w, r->nonce[i][s], 66); put(&w, r->nonce_sig[i][s], 64); }
    }
    return w.cap ? w.n : 0;
}

static size_t build_status(const gz_sign_round_t *r, uint8_t *buf)
{
    wr_t w = {buf, 0, 35};
    header(&w, GZ_SIGN_MSG_STATUS, r->id);
    return w.n;
}

/* Record: round_id, tier, then `body`. */
static void save_round_record(emit_t *em, uint32_t type, const uint8_t id[32], uint8_t tier, const uint8_t *body, size_t len)
{
    uint8_t buf[40 + GZ_SIGN_MAX_ITEMS * 68 + 64 + 8];
    wr_t w = {buf, 0, sizeof buf};
    put(&w, id, 32); put8(&w, tier); put(&w, body, len);
    if (!w.cap) { em->st = GZ_ERR_NO_SPACE; return; }
    emit_save(em, type, buf, w.n);
}

/* ---- the member ---- */

/* Nonces for tier t: generate, save (S1), then send. */
static void member_begin_tier(gz_sign_t *e, gz_sign_round_t *r, uint8_t t, emit_t *em)
{
    uint8_t rec[40 + 2 + GZ_SIGN_MAX_ITEMS * 4 + sizeof r->proposal];
    wr_t w = {r->nonces_msg, 0, sizeof r->nonces_msg}, rw = {rec, 0, sizeof rec};
    uint16_t n = 0;
    for (int i = 0; i < r->def.n_items; i++) n += r->def.items[i].tier == t && pos_of(&r->def.items[i], r->me) >= 0;
    if (n == 0) {                       /* nothing of mine in this tier: no contribution, wait for its result */
        r->tier = t; r->tier_state[t] = GZ_SIGN_TIER_SIGNED; r->ticks = 0; r->nonces_len = 0; r->partials_len[t] = 0;
        return;
    }
    header(&w, GZ_SIGN_MSG_NONCES, r->id); put8(&w, t); put16(&w, n);
    put(&rw, r->id, 32); put8(&rw, t); put16(&rw, n);
    for (int i = 0; i < r->def.n_items; i++) {
        int s = pos_of(&r->def.items[i], r->me);
        if (r->def.items[i].tier != t || s < 0) continue;
        if (!make_nonce(e, r, i)) { em->st = GZ_ERR_ARGUMENT; return; }
        put32(&w, (uint32_t)i); put(&w, r->nonce[i][s], 66); put(&w, r->nonce_sig[i][s], 64);
        put32(&rw, (uint32_t)i);
    }
    put(&rw, r->proposal, r->proposal_len);
    if (!w.cap || !rw.cap) { em->st = GZ_ERR_NO_SPACE; return; }
    r->tier = t; r->tier_state[t] = GZ_SIGN_TIER_NONCES; r->ticks = 0;
    r->nonces_len = (uint32_t)w.n;
    emit_save(em, GZ_SIGN_REC_M_STARTED, rec, rw.n);                          /* RULE:S1_SAVE_FIRST */
    emit_send(em, r->def.participants[0].peer, r->nonces_msg, w.n);
}

/* Something went wrong for a member's round: Aborted only while no partial
 * signature was ever sent, otherwise Unfinished. */
static void member_fail(gz_sign_t *e, gz_sign_round_t *r, uint8_t why, emit_t *em)
{
    wipe_secrets(r);
    r->nonces_len = 0;
    r->why = why;
    e->counters[GZ_SIGN_COUNT_REJECTED]++;
    if (r->state != GZ_SIGN_ROUND_ACTIVE) return;
    if (!r->ever_partial) {                                              /* RULE:ABORT_ONLY_BEFORE_PARTIAL */
        r->state = GZ_SIGN_ROUND_ABORTED;
        r->tail_len = (uint32_t)build_abort(e, r, r->id, why, WHOLE_ROUND, r->tail_msg, sizeof r->tail_msg);
        save_round_record(em, GZ_SIGN_REC_M_ABORTED, r->id, 0, r->tail_msg, r->tail_len);
        emit_send(em, r->def.participants[0].peer, r->tail_msg, r->tail_len);
    } else {
        r->state = GZ_SIGN_ROUND_UNFINISHED;
        if (r->tier_state[r->tier] == GZ_SIGN_TIER_NONCES) {
            size_t n = build_abort(e, r, r->id, why, r->tier, e->scratch, sizeof e->scratch);
            emit_send(em, r->def.participants[0].peer, e->scratch, n);
        }
    }
}

static void send_abort_for(gz_sign_t *e, const uint8_t id[32], uint8_t why, uint64_t peer, emit_t *em)
{
    size_t n = build_abort(e, NULL, id, why, WHOLE_ROUND, e->scratch, sizeof e->scratch);
    emit_send(em, peer, e->scratch, n);
}

/* What a member answers when a round it already knows is proposed again. */
static void member_answer_known(gz_sign_t *e, gz_sign_round_t *r, emit_t *em)
{
    uint64_t host = r->def.participants[0].peer;
    e->counters[GZ_SIGN_COUNT_DUPLICATES]++;
    if (r->state == GZ_SIGN_ROUND_ABORTED || r->state == GZ_SIGN_ROUND_COMPLETE) {
        emit_send(em, host, r->tail_msg, r->tail_len);
    } else if (r->tier_state[r->tier] == GZ_SIGN_TIER_NONCES) {
        if (r->nonces_len && r->state == GZ_SIGN_ROUND_ACTIVE) emit_send(em, host, r->nonces_msg, r->nonces_len);   /* RULE:S3_RESEND_SAVED */
        else {
            size_t n = build_abort(e, r, r->id, GZ_SIGN_WHY_RESTARTED, r->tier, e->scratch, sizeof e->scratch);
            emit_send(em, host, e->scratch, n);
        }
    } else if (r->tier_state[r->tier] == GZ_SIGN_TIER_SIGNED && r->partials_len[r->tier]) {
        emit_send(em, host, r->partials_msg[r->tier], r->partials_len[r->tier]);
    }
}

static void member_propose(gz_sign_t *e, uint64_t peer, const gz_sign_msg_t *m, const uint8_t *bytes, size_t len, emit_t *em)
{
    gz_sign_round_t *r = find(e, m->round_id);
    if (r) {                                                             /* RULE:S2_KNOWN_ROUND */
        if (peer == r->def.participants[0].peer) member_answer_known(e, r, em);
        return;
    }
    if (is_known(e, m->round_id)) { send_abort_for(e, m->round_id, GZ_SIGN_WHY_KNOWN_ROUND, peer, em); return; }
    memset(&e->scratch_def, 0, sizeof e->scratch_def);
    if (!e->cfg.build(e->cfg.build_ctx, m->params, m->params_len, &e->scratch_def) ||
        e->scratch_def.participants[0].peer != peer) {
        e->counters[GZ_SIGN_COUNT_REJECTED]++;
        send_abort_for(e, m->round_id, GZ_SIGN_WHY_BUILD, peer, em);
        return;
    }
    uint8_t why = (uint8_t)load_round(e, &e->pending, m, bytes, len);
    if (why != GZ_SIGN_WHY_NONE) {                       /* refused before it can push any round out of memory */
        memset(&e->pending, 0, sizeof e->pending);
        e->counters[GZ_SIGN_COUNT_REJECTED]++;
        send_abort_for(e, m->round_id, why, peer, em);
        return;
    }
    r = adopt(e, 0);
    if (!r) { send_abort_for(e, m->round_id, GZ_SIGN_WHY_BUSY, peer, em); return; }
    /* A valid new proposal from the host supersedes a round still collecting. */
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++)
        if (&e->rounds[i] != r && e->rounds[i].state == GZ_SIGN_ROUND_ACTIVE) member_fail(e, &e->rounds[i], GZ_SIGN_WHY_SUPERSEDED, em);
    member_begin_tier(e, r, 0, em);
}

static void member_all_nonces(gz_sign_t *e, gz_sign_round_t *r, const gz_sign_msg_t *m, const uint8_t *bytes, emit_t *em)
{
    uint8_t t = m->tier, d[32];
    if (t >= r->def.n_tiers) return;
    tagged("gazpacho/allnonces", bytes, m->signed_len, NULL, 0, d);
    if (r->tier_state[t] >= GZ_SIGN_TIER_SIGNED || r->have_all_nonces[t]) {
        /* Same bytes again: answer with the saved bytes. Different: refused, kept as evidence (not encoded). */
        if (r->have_all_nonces[t] && same(d, r->all_nonces_digest[t], 32) && r->tier_state[t] == GZ_SIGN_TIER_SIGNED && r->partials_len[t])
            emit_send(em, r->def.participants[0].peer, r->partials_msg[t], r->partials_len[t]);
        else e->counters[GZ_SIGN_COUNT_REJECTED]++;
        return;
    }
    if (r->state != GZ_SIGN_ROUND_ACTIVE || t != r->tier || r->tier_state[t] != GZ_SIGN_TIER_NONCES || !r->nonces_len) return;
    memcpy(r->all_nonces_digest[t], d, 32);
    r->have_all_nonces[t] = 1;
    /* Every item of mine in this tier exactly once, every signer's nonce, every nonce signed by its owner. */
    uint8_t seen[GZ_SIGN_MAX_ITEMS] = {0};
    for (int k = 0; k < m->n; k++) {
        const uint8_t *p = m->entry[k];
        uint32_t i = be32(p);
        if (i >= r->def.n_items || seen[i]) { member_fail(e, r, GZ_SIGN_WHY_BAD_MESSAGE, em); return; }
        const gz_sign_item_t *it = &r->def.items[i];
        int me = pos_of(it, r->me);
        if (it->tier != t || me < 0 || p[4] != it->n_signers) { member_fail(e, r, GZ_SIGN_WHY_BAD_MESSAGE, em); return; }
        seen[i] = 1;
        for (int s = 0; s < it->n_signers; s++) {
            const uint8_t *nonce = p + 5 + 130 * s, *sig = nonce + 66;
            uint8_t nd[32];
            nonce_digest(r->id, t, i, nonce, nd);
            if (!verify_digest(e, r->def.participants[it->signers[s]].contribution_key, nd, sig)) {   /* RULE:CHECK_NONCE_SIGS */
                member_fail(e, r, GZ_SIGN_WHY_BAD_NONCE, em); return;
            }
            if (s == me && (!same(nonce, r->nonce[i][s], 66))) { member_fail(e, r, GZ_SIGN_WHY_OWN_NONCE_CHANGED, em); return; }
        }
    }
    for (int i = 0; i < r->def.n_items; i++)
        if (r->def.items[i].tier == t && pos_of(&r->def.items[i], r->me) >= 0 && !seen[i]) { member_fail(e, r, GZ_SIGN_WHY_BAD_MESSAGE, em); return; }
    for (int k = 0; k < m->n; k++) {
        const uint8_t *p = m->entry[k];
        uint32_t i = be32(p);
        /* The others' nonce signatures are checked above and not kept: a member never sends them on,
         * and evidence (spec section 9) is not encoded in Slice 1. */
        for (int s = 0; s < r->def.items[i].n_signers; s++) memcpy(r->nonce[i][s], p + 5 + 130 * s, 66);
        r->have_nonce[i] = all_bits(&r->def.items[i]);
    }
    /* Sign, then save the exposure and the bytes in one batch, then send. */
    wr_t w = {r->partials_msg[t], 0, sizeof r->partials_msg[t]};
    header(&w, GZ_SIGN_MSG_PARTIALS, r->id); put8(&w, t); put16(&w, m->n);
    for (int k = 0; k < m->n; k++) {
        uint32_t i = be32(m->entry[k]);
        uint8_t ps[32], sd[32];
        if (!sign_item(e, r, (int)i, ps)) { member_fail(e, r, GZ_SIGN_WHY_BAD_NONCE, em); return; }
        set_digest(r, (int)i, sd);
        put32(&w, i); put(&w, ps, 32); put(&w, sd, 32);
    }
    finish_msg(e, &w);
    if (!w.cap) { em->st = GZ_ERR_NO_SPACE; return; }
    r->partials_len[t] = (uint32_t)w.n;
    r->tier_state[t] = GZ_SIGN_TIER_SIGNED;
    r->ever_partial = 1;
    r->nonces_len = 0;
    r->ticks = 0;
    save_round_record(em, GZ_SIGN_REC_M_SIGNED, r->id, t, r->partials_msg[t], w.n);
    emit_send(em, r->def.participants[0].peer, r->partials_msg[t], w.n);
}

/* Final signatures of tier t, judged from the signed transactions' bytes. */
static int check_result(gz_sign_t *e, gz_sign_round_t *r, const gz_sign_msg_t *m, int store)
{
    uint8_t seen[GZ_SIGN_MAX_ITEMS] = {0}, tx[GZ_SIGN_MAX_TX + 80];
    for (int k = 0; k < m->n; k++) {
        uint32_t i = be32(m->entry[k]);
        if (i >= r->def.n_items || seen[i] || r->def.items[i].tier != m->tier) return 0;
        const gz_sign_item_t *it = &r->def.items[i];
        size_t n = gz_sign_tx_attach(it->tx, it->tx_len, m->entry[k] + 4, tx, sizeof tx);
        if (!n || !gz_sign_tx_verify(e->cfg.ctx, tx, n, it->spent_amount, it->spent_script)) return 0;   /* RULE:VERIFY_FINAL */
        e->counters[GZ_SIGN_COUNT_FINALS_VERIFIED]++;
        seen[i] = 1;
    }
    for (int i = 0; i < r->def.n_items; i++)
        if (r->def.items[i].tier == m->tier && !seen[i]) return 0;
    if (store)
        for (int k = 0; k < m->n; k++) {
            uint32_t i = be32(m->entry[k]);
            memcpy(r->final_sig[i], m->entry[k] + 4, 64);
            r->have_final[i] = 1;
        }
    return 1;
}

static void held_digest(const gz_sign_round_t *r, uint8_t out[32])
{
    gz_sign_sha256_t s;
    gz_sign_tagged_init(&s, "gazpacho/held");
    gz_sign_sha256_write(&s, r->id, 32);
    for (int i = 0; i < r->def.n_items; i++) gz_sign_sha256_write(&s, r->final_sig[i], 64);
    gz_sign_sha256_done(&s, out);
}

static void member_result(gz_sign_t *e, gz_sign_round_t *r, const gz_sign_msg_t *m, const uint8_t *bytes, size_t len, emit_t *em)
{
    uint8_t t = m->tier;
    if (t < r->def.n_tiers && r->tier_state[t] == GZ_SIGN_TIER_DONE && r->tier == t + 1 && r->state == GZ_SIGN_ROUND_ACTIVE &&
        r->tier_state[t + 1] == GZ_SIGN_TIER_NONCES && r->nonces_len) {
        /* the host asks again for the next tier's nonces: the same bytes, this incarnation's (S3) */
        emit_send(em, r->def.participants[0].peer, r->nonces_msg, r->nonces_len);
        return;
    }
    if (t >= r->def.n_tiers || r->tier_state[t] != GZ_SIGN_TIER_SIGNED) return;
    if (r->state != GZ_SIGN_ROUND_ACTIVE && r->state != GZ_SIGN_ROUND_UNFINISHED) return;
    if (!msg_signed_by(e, m, bytes, r->def.participants[0].contribution_key) || !check_result(e, r, m, 1)) {
        e->counters[GZ_SIGN_COUNT_REJECTED]++;
        r->state = GZ_SIGN_ROUND_UNFINISHED;                                  /* RULE:SIGNED_NEVER_ABORTED */
        r->why = GZ_SIGN_WHY_BAD_RESULT;
        return;
    }
    r->state = GZ_SIGN_ROUND_ACTIVE;
    r->tier_state[t] = GZ_SIGN_TIER_DONE;           /* the bytes are saved; a member never sends a result on */
    r->ticks = 0;
    save_round_record(em, GZ_SIGN_REC_M_RESULT, r->id, t, bytes, len);
    if (t + 1 < r->def.n_tiers) member_begin_tier(e, r, (uint8_t)(t + 1), em);
}

static void member_complete(gz_sign_t *e, gz_sign_round_t *r, const gz_sign_msg_t *m, const uint8_t *bytes, emit_t *em)
{
    if (r->state == GZ_SIGN_ROUND_COMPLETE) { emit_send(em, r->def.participants[0].peer, r->tail_msg, r->tail_len); return; }
    for (int t = 0; t < r->def.n_tiers; t++)
        if (r->tier_state[t] != GZ_SIGN_TIER_DONE) return;
    if (r->state != GZ_SIGN_ROUND_ACTIVE || !msg_signed_by(e, m, bytes, r->def.participants[0].contribution_key)) return;
    uint8_t held[32];
    wr_t w = {r->tail_msg, 0, sizeof r->tail_msg};
    held_digest(r, held);
    header(&w, GZ_SIGN_MSG_ACK, r->id); put(&w, held, 32);
    finish_msg(e, &w);
    r->tail_len = (uint32_t)w.n;
    r->state = GZ_SIGN_ROUND_COMPLETE;
    save_round_record(em, GZ_SIGN_REC_M_COMPLETE, r->id, 0, r->tail_msg, w.n);
    emit_send(em, r->def.participants[0].peer, r->tail_msg, w.n);
}

static void member_resend(gz_sign_t *e, gz_sign_round_t *r, emit_t *em)
{
    uint64_t host = r->def.participants[0].peer;
    uint8_t st[35];
    (void)e;
    if (r->state == GZ_SIGN_ROUND_COMPLETE) { emit_send(em, host, r->tail_msg, r->tail_len); return; }
    if (r->state != GZ_SIGN_ROUND_ACTIVE && r->state != GZ_SIGN_ROUND_UNFINISHED) return;
    if (r->tier_state[r->tier] == GZ_SIGN_TIER_SIGNED && r->partials_len[r->tier])
        emit_send(em, host, r->partials_msg[r->tier], r->partials_len[r->tier]);
    if (r->tier_state[r->tier] >= GZ_SIGN_TIER_SIGNED) emit_send(em, host, st, build_status(r, st));
}

static void member_message(gz_sign_t *e, uint64_t peer, const gz_sign_msg_t *m, const uint8_t *bytes, size_t len, emit_t *em)
{
    if (m->kind == GZ_SIGN_MSG_PROPOSE) { member_propose(e, peer, m, bytes, len, em); return; }
    gz_sign_round_t *r = find(e, m->round_id);
    if (!r || peer != r->def.participants[0].peer) return;
    switch (m->kind) {
    case GZ_SIGN_MSG_ALL_NONCES: member_all_nonces(e, r, m, bytes, em); break;
    case GZ_SIGN_MSG_RESULT: member_result(e, r, m, bytes, len, em); break;
    case GZ_SIGN_MSG_COMPLETE: member_complete(e, r, m, bytes, em); break;
    case GZ_SIGN_MSG_ABORT:
        if (msg_signed_by(e, m, bytes, r->def.participants[0].contribution_key) && r->state == GZ_SIGN_ROUND_ACTIVE &&
            r->tier_state[r->tier] == GZ_SIGN_TIER_NONCES)
            member_fail(e, r, GZ_SIGN_WHY_HOST_ABORT, em);    /* after a partial signature: Unfinished, never Aborted */
        break;
    default: break;
    }
}

/* ---- the host ---- */

static void host_begin_tier(gz_sign_t *e, gz_sign_round_t *r, uint8_t t)
{
    r->tier = t; r->tier_state[t] = GZ_SIGN_TIER_NONCES; r->ticks = 0;
    for (int i = 0; i < r->def.n_items; i++)
        if (r->def.items[i].tier == t && !make_nonce(e, r, i)) r->state = GZ_SIGN_ROUND_FAILED;
}

static uint32_t members_missing(const gz_sign_round_t *r, int psigs)
{
    uint32_t miss = 0;
    for (int i = 0; i < r->def.n_items; i++) {
        const gz_sign_item_t *it = &r->def.items[i];
        if (it->tier != r->tier) continue;
        uint32_t have = psigs ? r->have_psig[i] : r->have_nonce[i];
        for (int s = 0; s < it->n_signers; s++)
            if (!(have >> s & 1u) && it->signers[s] != 0) miss |= bit(it->signers[s]);
    }
    return miss;
}

static void host_send_results(gz_sign_t *e, gz_sign_round_t *r, uint8_t member, emit_t *em)
{
    (void)e;
    for (int t = 0; t < r->def.n_tiers; t++)
        if (r->tier_state[t] == GZ_SIGN_TIER_DONE) emit_send(em, r->def.participants[member].peer, r->result_msg[t], r->result_len[t]);
    if (r->tail_len) emit_send(em, r->def.participants[member].peer, r->tail_msg, r->tail_len);
}

static void host_retry(gz_sign_t *e, const gz_sign_round_t *r, emit_t *em);

static void host_fail(gz_sign_t *e, gz_sign_round_t *r, uint32_t blamed, uint8_t why, emit_t *em)
{
    uint8_t rec[40];
    wr_t w = {rec, 0, sizeof rec};
    wipe_secrets(r);
    r->state = GZ_SIGN_ROUND_FAILED; r->blamed = blamed; r->why = why;
    /* A fault the host saw itself, against a refusal or a silence it cannot show anyone. */
    if (why == GZ_SIGN_WHY_DEADLINE || why == GZ_SIGN_WHY_MEMBER_ABORT) e->counters[GZ_SIGN_COUNT_BLAME_SILENT] += blamed != 0;
    else e->counters[GZ_SIGN_COUNT_BLAME_FAULT] += blamed != 0;
    put(&w, r->id, 32); put32(&w, blamed); put8(&w, why);
    emit_save(em, GZ_SIGN_REC_H_FAILED, rec, w.n);
    size_t n = build_abort(e, NULL, r->id, why, WHOLE_ROUND, e->scratch, sizeof e->scratch);
    for (int j = 1; j < r->def.n_participants; j++) emit_send(em, r->def.participants[j].peer, e->scratch, n);
    host_retry(e, r, em);
}

static void host_distribute(gz_sign_t *e, gz_sign_round_t *r, uint8_t member, emit_t *em)
{
    int mine = 0;
    for (int i = 0; i < r->def.n_items; i++) mine |= r->def.items[i].tier == r->tier && pos_of(&r->def.items[i], member) >= 0;
    if (!mine) return;                      /* nothing of its own in this tier: it signs nothing, it is sent nothing */
    size_t n = build_all_nonces(r, r->tier, member, e->scratch, sizeof e->scratch);
    emit_send(em, r->def.participants[member].peer, e->scratch, n);
}

/* Every partial signature of the tier is in and verified: add the host's,
 * combine, check each result from its bytes, save, send. */
static void host_combine(gz_sign_t *e, gz_sign_round_t *r, emit_t *em)
{
    /* The partial signatures and the signed transaction live in the engine's
     * work area, not on the stack: this function is inlined into
     * host_partials, and gcc's AddressSanitizer would guard such large
     * inlined locals with calls the isolation check refuses. */
    uint8_t t = r->tier, *tx = e->work_tx;
    wr_t w = {r->result_msg[t], 0, sizeof r->result_msg[t]};
    uint16_t n = 0;
    secp256k1_musig_partial_sig *ps = e->work_psig;
    const secp256k1_musig_partial_sig *ptrs[GZ_SIGN_MAX_SIGNERS];
    uint8_t mine[32];
    for (int i = 0; i < r->def.n_items; i++) n += r->def.items[i].tier == t;
    header(&w, GZ_SIGN_MSG_RESULT, r->id); put8(&w, t); put16(&w, n);
    for (int i = 0; i < r->def.n_items; i++) {
        const gz_sign_item_t *it = &r->def.items[i];
        if (it->tier != t) continue;
        if (!sign_item(e, r, i, mine) || r->have_psig[i] != all_bits(it)) { host_fail(e, r, 0, GZ_SIGN_WHY_BAD_PARTIAL, em); return; }
        for (int s = 0; s < it->n_signers; s++) {
            if (!secp256k1_musig_partial_sig_parse(e->cfg.ctx, &ps[s], r->psig[i][s])) { host_fail(e, r, 0, GZ_SIGN_WHY_BAD_PARTIAL, em); return; }
            ptrs[s] = &ps[s];
        }
        if (!secp256k1_musig_partial_sig_agg(e->cfg.ctx, r->final_sig[i], &r->session[i], ptrs, it->n_signers)) {
            host_fail(e, r, 0, GZ_SIGN_WHY_BAD_PARTIAL, em); return;
        }
        size_t len = gz_sign_tx_attach(it->tx, it->tx_len, r->final_sig[i], tx, sizeof e->work_tx);
        if (!len || !gz_sign_tx_verify(e->cfg.ctx, tx, len, it->spent_amount, it->spent_script)) {   /* RULE:HOST_VERIFY_FINAL */
            host_fail(e, r, 0, GZ_SIGN_WHY_BAD_RESULT, em); return;
        }
        e->counters[GZ_SIGN_COUNT_FINALS_VERIFIED]++;
        r->have_final[i] = 1;
        put32(&w, (uint32_t)i); put(&w, r->final_sig[i], 64);
    }
    finish_msg(e, &w);
    if (!w.cap) { em->st = GZ_ERR_NO_SPACE; return; }
    r->result_len[t] = (uint32_t)w.n;
    r->tier_state[t] = GZ_SIGN_TIER_DONE;
    save_round_record(em, GZ_SIGN_REC_H_RESULT, r->id, t, r->result_msg[t], w.n);
    if (t + 1 == r->def.n_tiers) {
        wr_t c = {r->tail_msg, 0, sizeof r->tail_msg};
        header(&c, GZ_SIGN_MSG_COMPLETE, r->id);
        finish_msg(e, &c);
        r->tail_len = (uint32_t)c.n;
        save_round_record(em, GZ_SIGN_REC_H_COMPLETE, r->id, 0, r->tail_msg, c.n);
        r->state = GZ_SIGN_ROUND_COMPLETE;
        r->ticks = 0;
    }
    for (int j = 1; j < r->def.n_participants; j++) {
        emit_send(em, r->def.participants[j].peer, r->result_msg[t], w.n);
        if (r->state == GZ_SIGN_ROUND_COMPLETE) emit_send(em, r->def.participants[j].peer, r->tail_msg, r->tail_len);
    }
    if (r->state != GZ_SIGN_ROUND_COMPLETE) host_begin_tier(e, r, (uint8_t)(t + 1));
}

static void host_nonces(gz_sign_t *e, gz_sign_round_t *r, uint8_t j, const gz_sign_msg_t *m, emit_t *em)
{
    if (m->tier != r->tier || r->tier_state[r->tier] != GZ_SIGN_TIER_NONCES) {
        e->counters[GZ_SIGN_COUNT_DUPLICATES]++;
        return;
    }
    for (int k = 0; k < m->n; k++) {
        const uint8_t *p = m->entry[k], *nonce = p + 4, *sig = p + 70;
        uint32_t i = be32(p);
        uint8_t d[32];
        secp256k1_musig_pubnonce pn;
        if (i >= r->def.n_items || r->def.items[i].tier != m->tier || pos_of(&r->def.items[i], j) < 0) {
            host_fail(e, r, bit(j), GZ_SIGN_WHY_BAD_MESSAGE, em); return;
        }
        int s = pos_of(&r->def.items[i], j);
        nonce_digest(r->id, m->tier, i, nonce, d);
        if (!verify_digest(e, r->def.participants[j].contribution_key, d, sig) ||
            !secp256k1_musig_pubnonce_parse(e->cfg.ctx, &pn, nonce)) {                      /* RULE:PARSE_NONCE_FIRST */
            host_fail(e, r, bit(j), GZ_SIGN_WHY_BAD_NONCE, em); return;
        }
        if (r->have_nonce[i] >> s & 1u) {                                                   /* RULE:SLOT_NONCE */
            if (same(r->nonce[i][s], nonce, 66)) { e->counters[GZ_SIGN_COUNT_DUPLICATES]++; continue; }
            host_fail(e, r, bit(j), GZ_SIGN_WHY_EQUIVOCATION, em); return;
        }
        memcpy(r->nonce[i][s], nonce, 66);
        memcpy(r->nonce_sig[i][s], sig, 64);
        r->have_nonce[i] |= bit((unsigned)s);
    }
    if (members_missing(r, 0)) return;
    for (int i = 0; i < r->def.n_items; i++)
        if (r->def.items[i].tier == r->tier && !make_session(e, r, i)) { host_fail(e, r, 0, GZ_SIGN_WHY_BAD_NONCE, em); return; }
    r->tier_state[r->tier] = GZ_SIGN_TIER_SIGNED;
    r->ticks = 0;
    for (uint8_t q = 1; q < r->def.n_participants; q++) host_distribute(e, r, q, em);
}

static void host_partials(gz_sign_t *e, gz_sign_round_t *r, uint8_t j, const gz_sign_msg_t *m, const uint8_t *bytes, emit_t *em)
{
    if (!msg_signed_by(e, m, bytes, r->def.participants[j].contribution_key)) { host_fail(e, r, bit(j), GZ_SIGN_WHY_BAD_MESSAGE, em); return; }
    if (m->tier != r->tier || r->tier_state[r->tier] != GZ_SIGN_TIER_SIGNED) { e->counters[GZ_SIGN_COUNT_DUPLICATES]++; return; }
    secp256k1_pubkey pk;
    uint8_t sd[32];
    secp256k1_musig_partial_sig ps;
    secp256k1_musig_pubnonce pn;
    if (!secp256k1_ec_pubkey_parse(e->cfg.ctx, &pk, r->def.participants[j].factory_key, 33)) return;
    for (int k = 0; k < m->n; k++) {
        const uint8_t *p = m->entry[k];
        uint32_t i = be32(p);
        if (i >= r->def.n_items || r->def.items[i].tier != m->tier || pos_of(&r->def.items[i], j) < 0) {
            host_fail(e, r, bit(j), GZ_SIGN_WHY_BAD_MESSAGE, em); return;
        }
        int s = pos_of(&r->def.items[i], j);
        if (r->have_psig[i] >> s & 1u) {                                                    /* RULE:SLOT_PSIG */
            if (same(r->psig[i][s], p + 4, 32)) { e->counters[GZ_SIGN_COUNT_DUPLICATES]++; continue; }
            host_fail(e, r, bit(j), GZ_SIGN_WHY_EQUIVOCATION, em); return;
        }
        set_digest(r, (int)i, sd);
        if (!same(sd, p + 36, 32) ||
            !secp256k1_musig_partial_sig_parse(e->cfg.ctx, &ps, p + 4) ||                  /* RULE:PARSE_PSIG_FIRST */
            !secp256k1_musig_pubnonce_parse(e->cfg.ctx, &pn, r->nonce[i][s]) ||
            !secp256k1_musig_partial_sig_verify(e->cfg.ctx, &ps, &pn, &pk, &r->cache[i], &r->session[i])) {   /* RULE:VERIFY_PARTIAL */
            host_fail(e, r, bit(j), GZ_SIGN_WHY_BAD_PARTIAL, em); return;
        }
        e->counters[GZ_SIGN_COUNT_PSIGS_VERIFIED]++;
        memcpy(r->psig[i][s], p + 4, 32);
        r->have_psig[i] |= bit((unsigned)s);
    }
    if (!members_missing(r, 1)) host_combine(e, r, em);
}

static void host_message(gz_sign_t *e, uint64_t peer, const gz_sign_msg_t *m, const uint8_t *bytes, emit_t *em)
{
    gz_sign_round_t *r = find(e, m->round_id);
    if (!r) {
        if (m->kind == GZ_SIGN_MSG_STATUS && is_known(e, m->round_id)) send_abort_for(e, m->round_id, GZ_SIGN_WHY_HOST_ABORT, peer, em);
        return;
    }
    uint8_t j = 0;
    for (uint8_t q = 1; q < r->def.n_participants; q++)
        if (r->def.participants[q].peer == peer) j = q;
    if (j == 0) return;
    if (m->kind == GZ_SIGN_MSG_STATUS) {
        if (r->state == GZ_SIGN_ROUND_FAILED) send_abort_for(e, r->id, r->why, peer, em);
        else host_send_results(e, r, j, em);
        return;
    }
    if (m->kind == GZ_SIGN_MSG_ACK) {
        uint8_t held[32], rec[33];
        if ((r->state != GZ_SIGN_ROUND_COMPLETE && r->state != GZ_SIGN_ROUND_DONE) || (r->acked >> j & 1u)) return;
        held_digest(r, held);
        if (!same(held, m->held, 32) || !msg_signed_by(e, m, bytes, r->def.participants[j].contribution_key)) return;
        r->acked |= bit(j);
        memcpy(rec, r->id, 32); rec[32] = j;
        emit_save(em, GZ_SIGN_REC_H_ACK, rec, 33);
        if (r->acked == members_mask(r)) r->state = GZ_SIGN_ROUND_DONE;
        return;
    }
    if (r->state != GZ_SIGN_ROUND_ACTIVE) return;
    if (m->kind == GZ_SIGN_MSG_NONCES) host_nonces(e, r, j, m, em);
    else if (m->kind == GZ_SIGN_MSG_PARTIALS) host_partials(e, r, j, m, bytes, em);
    else if (m->kind == GZ_SIGN_MSG_ABORT && msg_signed_by(e, m, bytes, r->def.participants[j].contribution_key))
        host_fail(e, r, m->reason == GZ_SIGN_WHY_RESTARTED || m->reason == GZ_SIGN_WHY_SUPERSEDED ? 0 : bit(j), GZ_SIGN_WHY_MEMBER_ABORT, em);
}

static gz_status_t host_begin(gz_sign_t *e, const uint8_t *params, size_t len, emit_t *em)
{
    uint8_t host_random[32];
    gz_sign_msg_t m;                    /* function scope: no ASan use-after-scope calls (isolation) */
    if (len > GZ_SIGN_MAX_PARAMS || e->attempts >= e->cfg.max_attempts) return GZ_ERR_ARGUMENT;
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++)
        if (e->rounds[i].state == GZ_SIGN_ROUND_ACTIVE) return GZ_ERR_ARGUMENT;
    memset(&e->scratch_def, 0, sizeof e->scratch_def);
    if (!e->cfg.build(e->cfg.build_ctx, params, len, &e->scratch_def)) return GZ_ERR_ARGUMENT;
    gz_sign_round_t *r = &e->pending;
    /* S4: a new attempt has a new identifier, also after a restore whose generator repeats. */
    uint8_t pre[48];
    wr_t hw = {pre, 0, sizeof pre};
    e->ports.random.fill(e->ports.random.ctx, GZ_RANDOM_ORDINARY, pre, 32);
    hw.n = 32; put64(&hw, e->incarnation); put64(&hw, ++e->next_serial);   /* RULE:HOST_RANDOM_MIX */
    tagged("gazpacho/host-random", pre, hw.n, NULL, 0, host_random);
    memset(r, 0, sizeof *r);
    r->def = e->scratch_def;
    if (!check_def(e, &r->def, r)) { memset(r, 0, sizeof *r); return GZ_ERR_ARGUMENT; }
    round_id(&r->def, params, len, host_random, r->id);
    wr_t w = {e->scratch, 0, sizeof r->proposal};       /* load_round copies it into the slot */
    header(&w, GZ_SIGN_MSG_PROPOSE, r->id); put(&w, host_random, 32); put16(&w, (uint32_t)len); put(&w, params, len);
    finish_msg(e, &w);
    if (!w.cap || !gz_sign_decode(e->scratch, w.n, &m) || load_round(e, r, &m, e->scratch, w.n) != GZ_SIGN_WHY_NONE) {
        memset(r, 0, sizeof *r);
        return GZ_ERR_ARGUMENT;
    }
    if (!(r = adopt(e, 0))) return GZ_ERR_NO_SPACE;
    e->attempts++;
    host_begin_tier(e, r, 0);
    emit_save(em, GZ_SIGN_REC_H_PROPOSED, r->proposal, r->proposal_len);
    for (int j = 1; j < r->def.n_participants; j++) emit_send(em, r->def.participants[j].peer, r->proposal, r->proposal_len);
    return GZ_OK;
}

static void host_retry(gz_sign_t *e, const gz_sign_round_t *r, emit_t *em)
{
    uint8_t next[GZ_SIGN_MAX_PARAMS];
    size_t n = e->cfg.retry ? e->cfg.retry(e->cfg.build_ctx, r->params, r->params_len, r->blamed, next) : 0;
    if (n && n <= GZ_SIGN_MAX_PARAMS && em->st == GZ_OK) (void)host_begin(e, next, n, em);
}

static void host_tick(gz_sign_t *e, gz_sign_round_t *r, emit_t *em)
{
    int resend = e->cfg.resend_ticks && ++r->ticks % e->cfg.resend_ticks == 0;
    if (r->state == GZ_SIGN_ROUND_COMPLETE) {
        /* A member that withholds its ack costs the attempt (spec section 10). */
        if (r->ticks >= e->cfg.deadline_ticks) {
            host_fail(e, r, (members_mask(r) & ~r->acked), GZ_SIGN_WHY_DEADLINE, em);
            return;
        }
        for (uint8_t j = 1; resend && j < r->def.n_participants; j++)
            if (!(r->acked >> j & 1u)) host_send_results(e, r, j, em);
        return;
    }
    if (r->state != GZ_SIGN_ROUND_ACTIVE) return;
    int psigs = r->tier_state[r->tier] == GZ_SIGN_TIER_SIGNED;
    uint32_t miss = members_missing(r, psigs);
    if (r->ticks >= e->cfg.deadline_ticks) { host_fail(e, r, miss, GZ_SIGN_WHY_DEADLINE, em); return; }
    for (uint8_t j = 1; resend && j < r->def.n_participants; j++) {
        if (!(miss >> j & 1u)) continue;
        if (psigs) host_distribute(e, r, j, em);
        else if (r->tier == 0) emit_send(em, r->def.participants[j].peer, r->proposal, r->proposal_len);
        else emit_send(em, r->def.participants[j].peer, r->result_msg[r->tier - 1], r->result_len[r->tier - 1]);
    }
}

/* ---- start ---- */

static gz_sign_round_t *start_round(gz_sign_t *e, const uint8_t *proposal, size_t len, const uint8_t *id)
{
    gz_sign_msg_t m;
    if (find(e, id) || !gz_sign_decode(proposal, len, &m) || m.kind != GZ_SIGN_MSG_PROPOSE) return NULL;
    memset(&e->scratch_def, 0, sizeof e->scratch_def);
    if (!e->cfg.build(e->cfg.build_ctx, m.params, m.params_len, &e->scratch_def)) return NULL;
    if (load_round(e, &e->pending, &m, proposal, len) != GZ_SIGN_WHY_NONE || !same(e->pending.id, id, 32)) {
        memset(&e->pending, 0, sizeof e->pending);
        return NULL;
    }
    return adopt(e, 1);
}

/* One stored record. Returns 0 if it is not one this engine wrote. */
static int replay(gz_sign_t *e, const gz_record_t *rec)
{
    const uint8_t *b = rec->bytes.data;
    size_t len = rec->bytes.len;
    gz_sign_msg_t m;
    if (rec->type == GZ_SIGN_REC_H_PROPOSED) {
        if (!e->cfg.host || !gz_sign_decode(b, len, &m)) return 0;
        e->attempts++;
        return start_round(e, b, len, m.round_id) != NULL;
    }
    if (len < 33) return 0;
    gz_sign_round_t *r = find(e, b);
    uint8_t t = b[32];
    const uint8_t *body = b + 33;
    size_t blen = len - 33;
    if (rec->type == GZ_SIGN_REC_M_STARTED) {
        if (e->cfg.host || len < 35) return 0;
        size_t n = (size_t)b[33] << 8 | b[34];
        if (len < 35 + 4 * n) return 0;
        if (!r && is_known(e, b)) return 1;
        if (!r && !(r = start_round(e, b + 35 + 4 * n, len - 35 - 4 * n, b))) return 0;
        if (t >= r->def.n_tiers) return 0;
        r->tier = t; r->tier_state[t] = GZ_SIGN_TIER_NONCES;
        return 1;
    }
    if (!r) return is_known(e, b);                       /* a round evicted to the refused list */
    switch (rec->type) {
    case GZ_SIGN_REC_M_SIGNED:
        if (t >= r->def.n_tiers || blen > sizeof r->partials_msg[t] || !gz_sign_decode(body, blen, &m) ||
            m.kind != GZ_SIGN_MSG_PARTIALS || m.tier != t || !same(m.round_id, r->id, 32) ||
            !msg_signed_by(e, &m, body, r->def.participants[r->me].contribution_key)) return 0;
        r->tier_state[t] = GZ_SIGN_TIER_SIGNED; r->ever_partial = 1;
        memcpy(r->partials_msg[t], body, blen); r->partials_len[t] = (uint32_t)blen;
        return 1;
    case GZ_SIGN_REC_M_RESULT: case GZ_SIGN_REC_H_RESULT:
        if (t >= r->def.n_tiers || blen > sizeof r->result_msg[t] || !gz_sign_decode(body, blen, &m) ||
            m.kind != GZ_SIGN_MSG_RESULT || m.tier != t || !same(m.round_id, r->id, 32) ||
            !msg_signed_by(e, &m, body, r->def.participants[0].contribution_key) || !check_result(e, r, &m, 1)) return 0;
        r->tier_state[t] = GZ_SIGN_TIER_DONE; r->tier = t;
        memcpy(r->result_msg[t], body, blen); r->result_len[t] = (uint32_t)blen;
        return 1;
    case GZ_SIGN_REC_M_COMPLETE: case GZ_SIGN_REC_M_ABORTED: case GZ_SIGN_REC_H_COMPLETE:
        if (t != 0 || blen > sizeof r->tail_msg || !gz_sign_decode(body, blen, &m) || !same(m.round_id, r->id, 32) ||
            m.kind != (rec->type == GZ_SIGN_REC_M_COMPLETE ? GZ_SIGN_MSG_ACK : rec->type == GZ_SIGN_REC_M_ABORTED ? GZ_SIGN_MSG_ABORT : GZ_SIGN_MSG_COMPLETE) ||
            !msg_signed_by(e, &m, body, r->def.participants[r->me].contribution_key))
            return 0;
        memcpy(r->tail_msg, body, blen); r->tail_len = (uint32_t)blen;
        r->state = rec->type == GZ_SIGN_REC_M_ABORTED ? GZ_SIGN_ROUND_ABORTED : GZ_SIGN_ROUND_COMPLETE;
        return 1;
    case GZ_SIGN_REC_H_ACK:
        if (t >= r->def.n_participants || t == 0) return 0;
        r->acked |= bit(t);
        return 1;
    case GZ_SIGN_REC_H_FAILED:
        if (len != 37) return 0;
        r->state = GZ_SIGN_ROUND_FAILED; r->blamed = be32(b + 32); r->why = b[36];
        return 1;
    default:
        return 0;
    }
}

gz_status_t gz_sign_start(gz_sign_t *e, const gz_storage_reader_t *storage, gz_action_list_t *out, int *more)
{
    if (!e || !storage || !storage->next || !storage->rewind || !out || !more) return GZ_ERR_ARGUMENT;
    size_t count = out->count, used = out->used;
    emit_t em = {out, GZ_OK};
    gz_stored_batch_t batch;
    storage->rewind(storage->ctx);
    while (storage->next(storage->ctx, &batch))
        for (size_t i = 0; i < batch.n_records; i++) {
            /* Only this engine's area: the node's own records (journal.md 9,
             * key_epoch, restored, guard) and other engines' are theirs to read. */
            if ((batch.records[i].type >> 16) != GZ_SIGN_REC_AREA) continue;
            if (!replay(e, &batch.records[i])) return GZ_ERR_CORRUPT;
        }
    /* What is left open: no secret nonce survived, so answer per item (S2). */
    gz_sign_round_t *unfinished = NULL;
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) {
        gz_sign_round_t *r = &e->rounds[i];
        if (r->state == GZ_SIGN_ROUND_FREE) continue;
        if (e->cfg.host) {
            if (r->state == GZ_SIGN_ROUND_ACTIVE) unfinished = r;
            else if (r->state == GZ_SIGN_ROUND_COMPLETE) {
                if (r->acked == members_mask(r)) r->state = GZ_SIGN_ROUND_DONE;
                else for (uint8_t j = 1; j < r->def.n_participants; j++)
                    if (!(r->acked >> j & 1u)) host_send_results(e, r, j, &em);
            }
            continue;
        }
        if (r->state == GZ_SIGN_ROUND_ACTIVE && r->tier_state[r->tier] == GZ_SIGN_TIER_NONCES) member_fail(e, r, GZ_SIGN_WHY_RESTARTED, &em);   /* RULE:RESTART_ANSWERS_ABORT */
        else if (r->state == GZ_SIGN_ROUND_ACTIVE && r->tier_state[r->tier] == GZ_SIGN_TIER_DONE && r->tier + 1 < r->def.n_tiers)
            member_begin_tier(e, r, (uint8_t)(r->tier + 1), &em);
        else member_resend(e, r, &em);
    }
    if (unfinished) host_fail(e, unfinished, 0, GZ_SIGN_WHY_HOST_RESTART, &em);   /* then the next attempt (H13) */
    emit_timer(e, &em);
    if (em.st != GZ_OK) { out->count = count; out->used = used; return em.st; }
    *more = 0;
    return GZ_OK;
}

/* ---- the public calls ---- */

gz_status_t gz_sign_init(gz_sign_t *e, const gz_sign_config_t *cfg, const gz_ports_t *ports, uint64_t incarnation)
{
    if (!e || !cfg || !ports || !cfg->ctx || !cfg->build || !ports->random.fill || !cfg->tick_ms) return GZ_ERR_ARGUMENT;
    memset(e, 0, sizeof *e);
    e->cfg = *cfg;
    e->ports = *ports;
    e->incarnation = incarnation;
    if (!secp256k1_keypair_create(cfg->ctx, &e->factory_kp, cfg->factory_secret) ||
        !secp256k1_keypair_create(cfg->ctx, &e->contribution_kp, cfg->contribution_secret) ||
        !secp256k1_keypair_pub(cfg->ctx, &e->factory_pk, &e->factory_kp)) {
        gz_sign_wipe(e);
        return GZ_ERR_ARGUMENT;
    }
    secp256k1_xonly_pubkey x;
    if (!secp256k1_keypair_xonly_pub(cfg->ctx, &x, NULL, &e->contribution_kp) ||
        !secp256k1_xonly_pubkey_serialize(cfg->ctx, e->contribution_x, &x)) { gz_sign_wipe(e); return GZ_ERR_ARGUMENT; }
    return GZ_OK;
}

gz_status_t gz_sign_handle(gz_sign_t *e, const gz_event_t *ev, gz_action_list_t *out)
{
    if (!e || !ev || !out) return GZ_ERR_ARGUMENT;
    size_t count = out->count, used = out->used;
    emit_t em = {out, GZ_OK};
    gz_sign_msg_t m;
    if (ev->kind == GZ_EVENT_MESSAGE_RECEIVED) {
        const uint8_t *b = ev->u.message.bytes.data;
        size_t len = ev->u.message.bytes.len;
        if (!b || !gz_sign_decode(b, len, &m)) e->counters[GZ_SIGN_COUNT_REJECTED]++;   /* RULE:DECODE_FIRST */
        else if (e->cfg.host) host_message(e, ev->u.message.peer_id, &m, b, &em);
        else member_message(e, ev->u.message.peer_id, &m, b, len, &em);
    } else if (ev->kind == GZ_EVENT_TIMER_FIRED && ev->u.timer.timer_id == TIMER_ID) {
        for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) {
            gz_sign_round_t *r = &e->rounds[i];
            if (r->state == GZ_SIGN_ROUND_FREE) continue;
            if (e->cfg.host) { host_tick(e, r, &em); continue; }
            r->ticks++;
            if (r->state == GZ_SIGN_ROUND_ACTIVE && r->tier_state[r->tier] == GZ_SIGN_TIER_NONCES && r->ticks >= e->cfg.deadline_ticks)
                member_fail(e, r, GZ_SIGN_WHY_DEADLINE, &em);
            else if (e->cfg.resend_ticks && r->ticks % e->cfg.resend_ticks == 0 && r->state != GZ_SIGN_ROUND_COMPLETE)
                member_resend(e, r, &em);
        }
        emit_timer(e, &em);
    } else if (ev->kind == GZ_EVENT_PEER_CONNECTED && !e->cfg.host) {
        for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++)
            if (e->rounds[i].state != GZ_SIGN_ROUND_FREE && e->rounds[i].def.participants[0].peer == ev->u.peer.peer_id)
                member_resend(e, &e->rounds[i], &em);
    }
    if (em.st != GZ_OK) { out->count = count; out->used = used; }
    return em.st;
}

gz_status_t gz_sign_begin(gz_sign_t *e, const uint8_t *params, size_t len, gz_action_list_t *out)
{
    if (!e || !out || (!params && len) || !e->cfg.host) return GZ_ERR_ARGUMENT;
    size_t count = out->count, used = out->used;
    emit_t em = {out, GZ_OK};
    gz_status_t st = host_begin(e, params, len, &em);
    if (st == GZ_OK) st = em.st;
    if (st != GZ_OK) { out->count = count; out->used = used; }
    return st;
}

size_t gz_sign_inspect_secrets(const gz_sign_t *e, uint8_t *out, size_t cap)
{
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

const gz_sign_round_t *gz_sign_latest(const gz_sign_t *e)
{
    const gz_sign_round_t *best = NULL;
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++)
        if (e->rounds[i].state != GZ_SIGN_ROUND_FREE && (!best || e->rounds[i].seq > best->seq)) best = &e->rounds[i];
    return best;
}

void gz_sign_wipe(gz_sign_t *e)
{
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) wipe_secrets(&e->rounds[i]);
    wipe(e->cfg.factory_secret, 32);
    wipe(e->cfg.contribution_secret, 32);
    wipe(&e->factory_kp, sizeof e->factory_kp);
    wipe(&e->contribution_kp, sizeof e->contribution_kp);
}
