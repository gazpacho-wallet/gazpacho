/* The signing round engine. See gazpacho/signing.h, spec/signing-round.md
 * and spec/messages.md section 7.
 *
 * Lines marked RULE:<name> carry one rule each; tools/signing-mutants.py
 * removes them one at a time and checks that a test fails. */
#include "gazpacho/signing.h"
#include <secp256k1_schnorrsig.h>
#include <string.h>

#define TIMER_ID 0x5347u

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
static uint16_t be16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

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

/* Items of participant j in tier t (t < 0: every tier). */
static uint16_t count_items(const gz_sign_round_t *r, uint8_t j, int t)
{
    uint16_t n = 0;
    for (int i = 0; i < r->def.n_items; i++)
        n += (t < 0 || r->def.items[i].tier == t) && pos_of(&r->def.items[i], j) >= 0;
    return n;
}

/* ---- reasons (messages.md 7.9) ---- */

uint16_t gz_sign_reason(uint8_t why, uint16_t built)
{
    switch (why) {
    case GZ_SIGN_WHY_BUILD: return built ? built : 1;
    case GZ_SIGN_WHY_INVALID_ROUND: return 1;
    case GZ_SIGN_WHY_ID_MISMATCH: return 2;
    case GZ_SIGN_WHY_KNOWN_ROUND: case GZ_SIGN_WHY_RESTARTED: return 3;
    case GZ_SIGN_WHY_DEADLINE: case GZ_SIGN_WHY_HOST_RESTART: case GZ_SIGN_WHY_MEMBER_ABORT: return 4;
    case GZ_SIGN_WHY_BAD_HOST_SIG: case GZ_SIGN_WHY_BAD_NONCE: case GZ_SIGN_WHY_OWN_NONCE_CHANGED:
    case GZ_SIGN_WHY_BAD_PARTIAL: case GZ_SIGN_WHY_EQUIVOCATION: case GZ_SIGN_WHY_BAD_RESULT:
    case GZ_SIGN_WHY_BAD_MESSAGE: return 5;
    case GZ_SIGN_WHY_BUSY: case GZ_SIGN_WHY_SUPERSEDED: return 6;
    case GZ_SIGN_WHY_CAPACITY: return 9;
    case GZ_SIGN_WHY_NOT_MY_KEY: return 12;
    default: return 0;
    }
}

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

/* ---- signatures over messages (messages.md 4.3) ---- */

/* BIP 340 by the contribution key. `deterministic`: aux_rand of 32 zero
 * bytes, the standard's own variant without randomness, for host messages
 * the engine rebuilds instead of keeping (a member's tier result, an abort):
 * rebuilt, they are the same bytes. Everything else draws aux_rand. */
static void sign_digest(gz_sign_t *e, const uint8_t digest[32], uint8_t sig[64], int deterministic)
{
    uint8_t aux[32] = {0};
    if (!deterministic) e->ports.random.fill(e->ports.random.ctx, GZ_RANDOM_ORDINARY, aux, 32);
    if (!secp256k1_schnorrsig_sign32(e->cfg.ctx, sig, digest, &e->contribution_kp, aux)) memset(sig, 0, 64);
}

/* A BIP 340 signature under a 33-byte compressed key's x coordinate. */
static int verify33(const gz_sign_t *e, const uint8_t key[33], const uint8_t digest[32], const uint8_t sig[64])
{
    secp256k1_xonly_pubkey pk;
    return (key[0] == 2 || key[0] == 3) && secp256k1_xonly_pubkey_parse(e->cfg.ctx, &pk, key + 1) &&
           secp256k1_schnorrsig_verify(e->cfg.ctx, sig, digest, 32, &pk);
}

static int signed_by(const gz_sign_t *e, const gz_sign_msg_t *m, const uint8_t key[33])
{
    uint8_t d[32];
    if (!m->sig) return 0;
    gz_rmsg_hash(m->kind, m->scope, m->records, m->signed_len, d);
    return verify33(e, key, d, m->sig);
}

/* A message being written: the envelope header, then records. */
typedef struct { uint8_t *buf; size_t cap; uint16_t kind; const uint8_t *scope; gz_rmsg_wr_t w; } msg_t;

static void msg_begin(msg_t *m, uint8_t *buf, size_t cap, uint16_t kind, const uint8_t scope[32])
{
    size_t h = gz_rmsg_header(buf, cap, kind, scope);
    m->buf = buf; m->cap = cap; m->kind = kind; m->scope = scope;
    gz_rmsg_wr_init(&m->w, buf + h, h ? cap - h : 0);
    if (!h) m->w.bad = 1;
}
static size_t msg_end(msg_t *m) { return gz_rmsg_wr_ok(&m->w) ? GZ_RMSG_HEADER + m->w.n : 0; }
static size_t msg_end_signed(gz_sign_t *e, msg_t *m, int deterministic)
{
    uint8_t d[32], sig[64];
    if (!gz_rmsg_wr_ok(&m->w)) return 0;
    gz_rmsg_hash(m->kind, m->scope, m->w.p, m->w.n, d);
    sign_digest(e, d, sig, deterministic);
    gz_rmsg_put(&m->w, GZ_RMSG_SIG_TYPE, sig, 64);
    return msg_end(m);
}

/* ---- the round definition ---- */

/* The spent outpoint of a one-input transaction in 7.1's encoding: txid, then
 * the index big-endian. */
static void spent_of(const gz_sign_tx_t *tx, uint8_t out[36])
{
    memcpy(out, tx->outpoint, 32);
    wr32(out + 32, le32(tx->outpoint + 32));
}

/* Check a definition and compute each item's key-aggregation cache (tweaked),
 * tweak and signature digest, and the tree digest. Every key is parsed here,
 * before any other call. Returns GZ_SIGN_WHY_NONE or why it is refused. */
static uint8_t check_def(gz_sign_t *e, gz_sign_def_t *d, gz_sign_round_t *r)
{
    const secp256k1_context *ctx = e->cfg.ctx;
    secp256k1_pubkey pks[GZ_SIGN_MAX_PARTICIPANTS], cpk;
    const secp256k1_pubkey *ptrs[GZ_SIGN_MAX_SIGNERS];
    secp256k1_xonly_pubkey agg, out_x;
    secp256k1_pubkey out_pk;
    uint8_t ser[32], spent[36], txid[32];
    uint64_t amount;
    const uint8_t *script;
    size_t slen;
    gz_sign_tx_t ptx;
    gz_sign_tx_t tx;
    int me = -1, prev_tier = 0, roots = 0;
    if (d->n_participants < 2 || d->n_participants > GZ_SIGN_MAX_PARTICIPANTS) return GZ_SIGN_WHY_INVALID_ROUND;
    if (d->n_tiers < 1 || d->n_tiers > GZ_SIGN_MAX_TIERS || d->n_items < 1 || d->n_items > GZ_SIGN_MAX_ITEMS) return GZ_SIGN_WHY_INVALID_ROUND;
    if (!same(d->host_key, d->participants[0].contribution_key, 33)) return GZ_SIGN_WHY_INVALID_ROUND;
    for (int i = 0; i < d->n_participants; i++) {
        const gz_tree_participant_t *p = &d->participants[i];
        if (!secp256k1_ec_pubkey_parse(ctx, &pks[i], p->factory_key, 33) ||
            !secp256k1_ec_pubkey_parse(ctx, &cpk, p->contribution_key, 33)) return GZ_SIGN_WHY_INVALID_ROUND;
        if (same(p->factory_key, p->contribution_key, 33)) return GZ_SIGN_WHY_INVALID_ROUND;
        for (int j = 0; j < i; j++)                                                   /* RULE:DUPLICATE_KEYS */
            if (same(p->factory_key, d->participants[j].factory_key, 33) || same(p->factory_key, d->participants[j].contribution_key, 33) ||
                same(p->contribution_key, d->participants[j].factory_key, 33) ||
                same(p->contribution_key, d->participants[j].contribution_key, 33)) return GZ_SIGN_WHY_INVALID_ROUND;
        if (e->cfg.host && i > 0)
            for (int j = 1; j < i; j++)
                if (d->peer[i] == d->peer[j]) return GZ_SIGN_WHY_INVALID_ROUND;
        if (same(p->factory_key, e->factory_key, 33) && same(p->contribution_key, e->contribution_key, 33)) me = i;
    }
    /* S5: this party's current keys, exactly once (duplicates are refused above). */
    if (me < 0 || (me == 0) != (e->cfg.host != 0)) return GZ_SIGN_WHY_NOT_MY_KEY;    /* RULE:S5_CURRENT_KEY */
    r->me = (uint8_t)me;
    for (int i = 0; i < d->n_items; i++) {
        gz_sign_item_t *it = &d->items[i];
        if (it->tier < prev_tier || it->tier > prev_tier + (i > 0) || it->tier >= d->n_tiers) return GZ_SIGN_WHY_INVALID_ROUND;
        prev_tier = it->tier;
        if (it->mode != GZ_SIGN_MODE_KEYPATH || it->has_merkle_root > 1) return GZ_SIGN_WHY_INVALID_ROUND;   /* RULE:FIXED_MODE */
        if (it->n_signers < 2 || it->n_signers > GZ_SIGN_MAX_SIGNERS || it->signers[0] != 0) return GZ_SIGN_WHY_INVALID_ROUND;
        for (int s = 0; s < it->n_signers; s++) {
            if (it->signers[s] >= d->n_participants) return GZ_SIGN_WHY_INVALID_ROUND;
            if (s > 0 && it->signers[s] <= it->signers[s - 1]) return GZ_SIGN_WHY_INVALID_ROUND;   /* RULE:DUPLICATE_SIGNERS */
            ptrs[s] = &pks[it->signers[s]];
        }
        if (it->tx_len > GZ_SIGN_MAX_TX || !gz_sign_tx_parse(it->tx, it->tx_len, &tx) || tx.witness_item) return GZ_SIGN_WHY_INVALID_ROUND;
        if (!secp256k1_musig_pubkey_agg(ctx, NULL, &agg, &r->cache[i], ptrs, it->n_signers)) return GZ_SIGN_WHY_INVALID_ROUND;
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &agg)) return GZ_SIGN_WHY_INVALID_ROUND;
        tagged("TapTweak", ser, 32, it->merkle_root, it->has_merkle_root ? 32 : 0, r->tweak[i]);
        if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &out_pk, &r->cache[i], r->tweak[i])) return GZ_SIGN_WHY_INVALID_ROUND;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &out_x, NULL, &out_pk)) return GZ_SIGN_WHY_INVALID_ROUND;
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &out_x)) return GZ_SIGN_WHY_INVALID_ROUND;
        if (it->spent_script[0] != 0x51 || it->spent_script[1] != 0x20 || !same(it->spent_script + 2, ser, 32)) return GZ_SIGN_WHY_INVALID_ROUND;   /* RULE:SCRIPT_MATCH */
        /* What the item spends exists: the funding output, or an output of
         * another item, with exactly the amount and script the digest names. */
        spent_of(&tx, spent);
        if (same(spent, d->funding_txid, 32) && be32(spent + 32) == d->funding_vout) {
            if (it->spent_amount != d->funding_amount || !same(it->spent_script, d->funding_script, 34)) return GZ_SIGN_WHY_INVALID_ROUND;   /* RULE:FUNDING_MATCH */
            /* C1: the funding output needs every participant (the signers are strictly
             * increasing positions among them, so this many is all of them). */
            if (it->n_signers != d->n_participants) return GZ_SIGN_WHY_INVALID_ROUND;   /* RULE:C1_ROOT_ALL */
            roots++;
        } else {
            int found = 0;
            for (int j = 0; j < d->n_items && !found; j++) {
                if (j == i || !gz_sign_tx_parse(d->items[j].tx, d->items[j].tx_len, &ptx)) continue;
                gz_sign_txid(d->items[j].tx, d->items[j].tx_len, txid);
                if (!same(txid, spent, 32)) continue;
                found = 1;
                if (!gz_sign_tx_output(&ptx, be32(spent + 32), &amount, &script, &slen) ||
                    amount != it->spent_amount || slen != 34 || !same(script, it->spent_script, 34)) return GZ_SIGN_WHY_INVALID_ROUND;
            }
            if (!found) return GZ_SIGN_WHY_INVALID_ROUND;
        }
        gz_sign_tx_sighash(&tx, it->spent_amount, it->spent_script, r->digest[i]);
    }
    if (roots < 1 || prev_tier != d->n_tiers - 1) return GZ_SIGN_WHY_INVALID_ROUND;
    gz_sign_tree_digest(d, (const uint8_t (*)[32])r->digest, (const uint8_t (*)[32])r->tweak, d->tree_digest);
    return GZ_SIGN_WHY_NONE;
}

/* ---- messages.md 7.1 and 7.12 ---- */

static void h8(gz_sign_sha256_t *s, uint32_t v) { uint8_t b = (uint8_t)v; gz_sign_sha256_write(s, &b, 1); }
static void h16(gz_sign_sha256_t *s, uint32_t v) { uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v}; gz_sign_sha256_write(s, b, 2); }
static void h32(gz_sign_sha256_t *s, uint32_t v) { uint8_t b[4]; wr32(b, v); gz_sign_sha256_write(s, b, 4); }
static void h64(gz_sign_sha256_t *s, uint64_t v) { h32(s, (uint32_t)(v >> 32)); h32(s, (uint32_t)v); }

/* n_items, then per item: index, spent, sighash, mode, mode_data, signers. */
static void hash_items(gz_sign_sha256_t *s, const gz_sign_def_t *d, const uint8_t (*digest)[32], const uint8_t (*tweak)[32])
{
    gz_sign_tx_t tx;
    uint8_t spent[36];
    h32(s, d->n_items);
    for (int i = 0; i < d->n_items; i++) {
        const gz_sign_item_t *it = &d->items[i];
        memset(spent, 0, sizeof spent);
        if (gz_sign_tx_parse(it->tx, it->tx_len, &tx)) spent_of(&tx, spent);
        h32(s, (uint32_t)i);
        gz_sign_sha256_write(s, spent, 36);
        gz_sign_sha256_write(s, digest[i], 32);
        h8(s, it->mode);
        gz_sign_sha256_write(s, tweak[i], 32);
        h16(s, it->n_signers);
        for (int k = 0; k < it->n_signers; k++) h16(s, it->signers[k]);
    }
}

/* funding, funding_amount, n_participants, participants (factory keys). */
static void hash_funding(gz_sign_sha256_t *s, const gz_sign_def_t *d)
{
    gz_sign_sha256_write(s, d->funding_txid, 32);
    h32(s, d->funding_vout);
    h64(s, d->funding_amount);
    h16(s, d->n_participants);
    for (int i = 0; i < d->n_participants; i++) gz_sign_sha256_write(s, d->participants[i].factory_key, 33);
}

void gz_sign_round_id(const gz_sign_def_t *d, const uint8_t (*digest)[32], const uint8_t (*tweak)[32],
                      const uint8_t host_random[32], uint8_t out[32])
{
    static const uint8_t protocol[4] = {GZ_RMSG_PROTOCOL_0, GZ_RMSG_PROTOCOL_1, GZ_RMSG_PROTOCOL_2, GZ_RMSG_PROTOCOL_3};
    gz_sign_sha256_t s;
    gz_sign_tagged_init(&s, "gazpacho/round_id");
    gz_sign_sha256_write(&s, protocol, 4);
    gz_sign_sha256_write(&s, d->chain, 32);
    gz_sign_sha256_write(&s, d->host_key, 33);
    gz_sign_sha256_write(&s, d->outer_digest, 32);
    gz_sign_sha256_write(&s, d->terms_digest, 32);
    hash_funding(&s, d);
    for (int i = 0; i < d->n_participants; i++) gz_sign_sha256_write(&s, d->participants[i].contribution_key, 33);
    h8(&s, d->purpose);
    h8(&s, d->n_tiers);
    for (int t = 0; t < d->n_tiers; t++) {
        uint32_t n = 0;
        for (int i = 0; i < d->n_items; i++) n += d->items[i].tier == t;
        h32(&s, n);
    }
    hash_items(&s, d, digest, tweak);
    gz_sign_sha256_write(&s, host_random, 32);                            /* RULE:S4_FRESH_ID */
    gz_sign_sha256_done(&s, out);
}

void gz_sign_tree_digest(const gz_sign_def_t *d, const uint8_t (*digest)[32], const uint8_t (*tweak)[32], uint8_t out[32])
{
    gz_sign_sha256_t s;
    gz_sign_tagged_init(&s, "gazpacho/tree");
    gz_sign_sha256_write(&s, d->chain, 32);
    hash_funding(&s, d);
    hash_items(&s, d, digest, tweak);
    gz_sign_sha256_done(&s, out);
}

/* ---- rounds held in memory ---- */

static gz_sign_round_t *find(gz_sign_t *e, const uint8_t id[32])
{
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++)
        if (e->rounds[i].state != GZ_SIGN_ROUND_FREE && same(e->rounds[i].id, id, 32)) return &e->rounds[i];
    return NULL;
}

/* The refused identifiers: the newest exactly, all of them in the filter. */
static void filter_positions(const gz_sign_t *e, const uint8_t id[32], uint32_t pos[GZ_SIGN_KNOWN_FILTER_K])
{
    uint8_t h[32];
    (void)e;
    tagged("gazpacho/known-filter", id, 32, NULL, 0, h);
    for (int k = 0; k < GZ_SIGN_KNOWN_FILTER_K; k++)
        pos[k] = ((uint32_t)h[3 * k] | (uint32_t)h[3 * k + 1] << 8 | (uint32_t)h[3 * k + 2] << 16) & ((1u << GZ_SIGN_KNOWN_FILTER_BITS) - 1u);
}

static int is_known(const gz_sign_t *e, const uint8_t id[32])
{
    uint32_t pos[GZ_SIGN_KNOWN_FILTER_K];
    size_t n = e->n_known < GZ_SIGN_MAX_KNOWN ? e->n_known : GZ_SIGN_MAX_KNOWN;
    for (size_t i = 0; i < n; i++)
        if (same(e->known[i], id, 32)) return 1;
    filter_positions(e, id, pos);
    for (int k = 0; k < GZ_SIGN_KNOWN_FILTER_K; k++)                         /* RULE:KNOWN_FILTER */
        if (!(e->known_filter[pos[k] >> 3] >> (pos[k] & 7) & 1u)) return 0;
    return 1;
}

static void add_known(gz_sign_t *e, const uint8_t id[32])
{
    uint32_t pos[GZ_SIGN_KNOWN_FILTER_K];
    memcpy(e->known[e->n_known % GZ_SIGN_MAX_KNOWN], id, 32);
    e->n_known++;
    filter_positions(e, id, pos);
    for (int k = 0; k < GZ_SIGN_KNOWN_FILTER_K; k++) e->known_filter[pos[k] >> 3] |= (uint8_t)(1u << (pos[k] & 7));
}

/* A round that is over for this party: nothing more will be sent or asked for it. */
static int settled(const gz_sign_round_t *r)
{
    return r->state == GZ_SIGN_ROUND_ABORTED || r->state == GZ_SIGN_ROUND_FAILED || r->state == GZ_SIGN_ROUND_DONE;
}

static void wipe_secrets(gz_sign_round_t *r)
{
    wipe(r->secnonce, sizeof r->secnonce);           /* RULE:WIPE_ON_ABORT */
    memset(r->secnonce_serial, 0, sizeof r->secnonce_serial);
}

/* A slot for a new round: a free one, or the oldest settled one, or else the
 * oldest that is not running (review A, F3: a Complete or Unfinished round
 * goes last), whose identifier then moves to the refused set. NULL if every
 * slot runs a round (refuse). */
static gz_sign_round_t *take_slot(gz_sign_t *e, int replaying)
{
    gz_sign_round_t *best = NULL;
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) {
        gz_sign_round_t *r = &e->rounds[i];
        if (r->state == GZ_SIGN_ROUND_FREE) return r;
        if (!replaying && r->state == GZ_SIGN_ROUND_ACTIVE) continue;
        if (!best || settled(r) > settled(best) || (settled(r) == settled(best) && r->seq < best->seq)) best = r;   /* RULE:EVICT_SETTLED_FIRST */
    }
    if (!best) return NULL;
    add_known(e, best->id);
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

/* The fields of a definition the engine takes from the proposal itself,
 * whatever the builder wrote there. */
static void def_from_proposal(gz_sign_def_t *d, const gz_tree_proposal_t *p)
{
    d->purpose = p->purpose;
    d->n_participants = (uint8_t)p->n_participants;
    for (size_t i = 0; i < p->n_participants; i++) d->participants[i] = p->participants[i];
    memcpy(d->terms_digest, p->terms_digest, 32);
    memcpy(d->funding_txid, p->funding_txid, 32);
    d->funding_vout = p->funding_vout;
    d->funding_amount = p->funding_amount;
    memcpy(d->funding_script, p->funding_script, 34);
    d->end_height = p->end_height;
}

/* Read a round_propose (the envelope `bytes`, whose view is `m`) into `r`:
 * the host's signature, the proposal's own consistency, the builder, the
 * engine's checks of what it built, and the identifier. `peer` is where it
 * came from (member; 0 when replaying or for the host's own). Returns
 * GZ_SIGN_WHY_NONE, or why it is refused (r->built: the builder's reason). */
static uint8_t load_round(gz_sign_t *e, gz_sign_round_t *r, const gz_sign_msg_t *m, const uint8_t *bytes, size_t len,
                          uint64_t peer, int replay)
{
    gz_rmsg_propose_t *pr = &e->prop;
    gz_sign_def_t *d = &e->scratch_def;
    gz_sign_build_in_t in;
    uint8_t d32[32], id[32], why;
    uint64_t amount;
    const uint8_t *script;
    size_t slen;
    gz_rmsg_err_t err;
    memset(r, 0, sizeof *r);
    err = gz_rmsg_propose_decode(m->records, m->records_len, pr);
    if (err == GZ_RMSG_E_CAPACITY) return GZ_SIGN_WHY_CAPACITY;
    if (err != GZ_RMSG_OK) return GZ_SIGN_WHY_BAD_MESSAGE;
    /* The host's long-term key, participant 0's contribution key, signs it. */
    gz_rmsg_hash(m->kind, m->scope, m->records, pr->signed_len, d32);
    if (!verify33(e, pr->p.participants[0].contribution_key, d32, pr->sig)) return GZ_SIGN_WHY_BAD_HOST_SIG;   /* RULE:HOST_SIG */
    if (len > sizeof r->proposal || pr->p.funding_tx_len > GZ_SIGN_MAX_FUNDING_TX || pr->p.n_participants > GZ_SIGN_MAX_PARTICIPANTS)
        return GZ_SIGN_WHY_CAPACITY;
    if (pr->p.purpose != 1 || pr->p.funding_script_len != 34) return GZ_SIGN_WHY_INVALID_ROUND;   /* creation only (Slice 1) */
    /* The funding transaction names the outpoint, amount and script (C1). */
    gz_sign_txid(pr->p.funding_tx, pr->p.funding_tx_len, d32);
    if (!same(d32, pr->p.funding_txid, 32) ||                                                      /* RULE:FUNDING_TX */
        !gz_sign_tx_find_output(pr->p.funding_tx, pr->p.funding_tx_len, pr->p.funding_vout, &amount, &script, &slen) ||
        amount != pr->p.funding_amount || slen != 34 || !same(script, pr->p.funding_script, 34)) return GZ_SIGN_WHY_INVALID_ROUND;
    memset(d, 0, sizeof *d);
    in.msg = pr; in.scope = m->scope; in.peer = peer; in.replay = replay;
    r->built = e->cfg.build(e->cfg.build_ctx, &in, d);
    if (r->built) return GZ_SIGN_WHY_BUILD;
    def_from_proposal(d, &pr->p);
    if (!same(d->outer_digest, m->scope, 32) || pr->p.n_tiers != d->n_tiers) return GZ_SIGN_WHY_INVALID_ROUND;
    for (int t = 0; t < d->n_tiers; t++) {
        uint32_t n = 0;
        for (int i = 0; i < d->n_items; i++) n += d->items[i].tier == t;
        if (pr->p.tier_sizes[t] != n) return GZ_SIGN_WHY_INVALID_ROUND;
    }
    if (!replay && !e->cfg.host && d->peer[0] != peer) return GZ_SIGN_WHY_INVALID_ROUND;
    r->def = *d;
    why = check_def(e, &r->def, r);
    if (why != GZ_SIGN_WHY_NONE) return why;
    gz_sign_round_id(&r->def, (const uint8_t (*)[32])r->digest, (const uint8_t (*)[32])r->tweak, pr->host_random, id);
    if (!same(id, pr->round_id, 32)) return GZ_SIGN_WHY_ID_MISMATCH;
    memcpy(r->id, id, 32);
    r->seq = ++e->next_seq;
    r->proposal_len = (uint32_t)len;
    memcpy(r->proposal, bytes, len);
    r->state = GZ_SIGN_ROUND_ACTIVE;
    return GZ_SIGN_WHY_NONE;
}

/* ---- nonces ---- */

static int make_nonce(gz_sign_t *e, gz_sign_round_t *r, int i)
{
    const gz_sign_item_t *it = &r->def.items[i];
    int s = pos_of(it, r->me);
    uint8_t rnd[32], sid[32], extra[32], pre[48], d[32];
    secp256k1_musig_pubnonce pub;
    wr_t w = {pre, 0, sizeof pre};
    uint64_t counter;
    int ok;
    if (s < 0 || r->secnonce_serial[i] || (r->have_nonce[i] >> s & 1u)) return 0;   /* RULE:S2_ONE_NONCE */
    e->ports.random.fill(e->ports.random.ctx, GZ_RANDOM_SECRET, rnd, 32);
    counter = e->session_counter++;
    put(&w, rnd, 32); put64(&w, e->incarnation); put64(&w, counter);   /* RULE:INCARNATION_MIX */
    tagged("gazpacho/session-id", pre, w.n, NULL, 0, sid);
    w.n = 0;
    put(&w, r->id, 32); put8(&w, it->tier); put32(&w, (uint32_t)i);
    tagged("gazpacho/nonce-extra", pre, w.n, NULL, 0, extra);
    ok = secp256k1_musig_nonce_gen(e->cfg.ctx, &r->secnonce[i], &pub, sid, e->cfg.factory_secret,
                                   &e->factory_pk, r->digest[i], &r->cache[i], extra) &&
         secp256k1_musig_pubnonce_serialize(e->cfg.ctx, r->nonce[i][s], &pub);
    wipe(rnd, sizeof rnd); wipe(sid, sizeof sid); wipe(pre, sizeof pre);
    if (!ok) { wipe(&r->secnonce[i], sizeof r->secnonce[i]); return 0; }
    gz_rmsg_nonce_hash(r->id, it->tier, (uint32_t)i, r->nonce[i][s], d);   /* RULE:NONCE_SIG_COVERS_ITEM */
    sign_digest(e, d, r->nonce_sig[i][s], 0);
    r->have_nonce[i] |= bit((unsigned)s);
    r->secnonce_serial[i] = ++e->next_serial;
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
    gz_rmsg_nonceset_hash((const uint8_t (*)[66])r->nonce[i], r->def.items[i].n_signers, out);
}

static int sign_item(gz_sign_t *e, gz_sign_round_t *r, int i, uint8_t out32[32])
{
    secp256k1_musig_partial_sig ps;
    int s = pos_of(&r->def.items[i], r->me), ok;
    if (s < 0 || !r->secnonce_serial[i] || (r->have_psig[i] >> s & 1u)) return 0;     /* RULE:S2_ONE_PARTIAL */
    ok = make_session(e, r, i) &&
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

/* held_digest (7.8) over participant j's items, in index order. */
static void held_digest(const gz_sign_round_t *r, uint8_t j, uint8_t out[32])
{
    gz_sign_sha256_t s;
    uint8_t b[4];
    gz_sign_tagged_init(&s, "gazpacho/held");
    for (int i = 0; i < r->def.n_items; i++) {
        if (pos_of(&r->def.items[i], j) < 0) continue;
        wr32(b, (uint32_t)i);
        gz_sign_sha256_write(&s, b, 4);
        gz_sign_sha256_write(&s, r->final_sig[i], 64);
    }
    gz_sign_sha256_done(&s, out);
}

/* ---- building messages ---- */

/* round_abort (7.9). Whole round unless `tier` >= 0 and the round has more
 * than one tier: then the tier and this party's items of it (odd records 9
 * and 11, which Slice 1's one-tier rounds never send). */
static size_t build_abort(gz_sign_t *e, const gz_sign_round_t *r, const uint8_t id[32], const uint8_t scope[32], uint16_t reason,
                          int tier, int deterministic, uint8_t *buf, size_t cap)
{
    msg_t m;
    uint8_t b[2] = {(uint8_t)(reason >> 8), (uint8_t)reason}, t8 = (uint8_t)tier, *q;
    uint16_t n;
    msg_begin(&m, buf, cap, GZ_SIGN_MSG_ABORT, scope);
    gz_rmsg_put(&m.w, 2, id, 32);
    gz_rmsg_put(&m.w, 4, b, 2);
    if (r && tier >= 0 && tier < r->def.n_tiers && r->def.n_tiers > 1) {
        n = count_items(r, r->me, tier);
        gz_rmsg_put(&m.w, 9, &t8, 1);
        if (n && (q = gz_rmsg_reserve(&m.w, 11, 4u * n)) != NULL)
            for (int i = 0; i < r->def.n_items; i++)
                if (r->def.items[i].tier == tier && pos_of(&r->def.items[i], r->me) >= 0) { wr32(q, (uint32_t)i); q += 4; }   /* RULE:PER_ITEM_ANSWER */
    }
    return msg_end_signed(e, &m, deterministic);
}

/* round_all_nonces (7.4) for participant j: its items of the tier. */
static size_t build_all_nonces(const gz_sign_round_t *r, uint8_t tier, uint8_t j, uint8_t *buf, size_t cap)
{
    msg_t m;
    size_t len = 0;
    uint8_t *q;
    for (int i = 0; i < r->def.n_items; i++)
        if (r->def.items[i].tier == tier && pos_of(&r->def.items[i], j) >= 0) len += 6 + 130u * r->def.items[i].n_signers;
    msg_begin(&m, buf, cap, GZ_SIGN_MSG_ALL_NONCES, r->def.outer_digest);
    gz_rmsg_put(&m.w, 2, r->id, 32);
    gz_rmsg_put(&m.w, 4, &tier, 1);
    if (!len || !(q = gz_rmsg_reserve(&m.w, 6, len))) return 0;
    for (int i = 0; i < r->def.n_items; i++) {
        const gz_sign_item_t *it = &r->def.items[i];
        if (it->tier != tier || pos_of(it, j) < 0) continue;
        wr32(q, (uint32_t)i); q[4] = 0; q[5] = it->n_signers; q += 6;
        for (int s = 0; s < it->n_signers; s++) { memcpy(q, r->nonce[i][s], 66); memcpy(q + 66, r->nonce_sig[i][s], 64); q += 130; }
    }
    return msg_end(&m);
}

/* round_tier_result (7.6) for participant j: the finals of its items in the
 * tier, signed deterministically, so the host rebuilds the same bytes. */
static size_t build_result(gz_sign_t *e, const gz_sign_round_t *r, uint8_t tier, uint8_t j, uint8_t *buf, size_t cap)
{
    msg_t m;
    uint16_t n = count_items(r, j, tier);
    uint8_t *q;
    msg_begin(&m, buf, cap, GZ_SIGN_MSG_RESULT, r->def.outer_digest);
    gz_rmsg_put(&m.w, 2, r->id, 32);
    gz_rmsg_put(&m.w, 4, &tier, 1);
    if (!n || !(q = gz_rmsg_reserve(&m.w, 6, 68u * n))) return 0;
    for (int i = 0; i < r->def.n_items; i++)
        if (r->def.items[i].tier == tier && pos_of(&r->def.items[i], j) >= 0) { wr32(q, (uint32_t)i); memcpy(q + 4, r->final_sig[i], 64); q += 68; }
    return msg_end_signed(e, &m, 1);
}

static size_t build_status(const gz_sign_round_t *r, uint8_t *buf, size_t cap)
{
    msg_t m;
    msg_begin(&m, buf, cap, GZ_SIGN_MSG_STATUS, r->def.outer_digest);
    gz_rmsg_put(&m.w, 2, r->id, 32);
    return msg_end(&m);
}

/* Record: round_id, tier, then `body`. */
static void save_round_record(gz_sign_t *e, emit_t *em, uint32_t type, const uint8_t id[32], uint8_t tier, const uint8_t *body, size_t len)
{
    wr_t w = {e->work_records, 0, sizeof e->work_records};
    put(&w, id, 32); put8(&w, tier); put(&w, body, len);
    if (!w.cap) { em->st = GZ_ERR_NO_SPACE; return; }
    emit_save(em, type, e->work_records, w.n);
}

/* ---- the member ---- */

static uint64_t host_peer(const gz_sign_round_t *r) { return r->def.peer[0]; }

/* From tier t on, every tier with nothing of mine is done for me: no
 * contribution and nothing to hold (a result names only the recipient's
 * items, 7.6). Returns the first tier with items of mine, or the last. */
static uint8_t skip_empty_tiers(gz_sign_round_t *r, uint8_t t)
{
    while (t < r->def.n_tiers && !count_items(r, r->me, t)) {
        r->tier_state[t] = GZ_SIGN_TIER_DONE;
        if (t + 1 == r->def.n_tiers) return t;
        t++;
    }
    return t;
}

/* Nonces for tier t: generate, save (S1), then send. */
static void member_begin_tier(gz_sign_t *e, gz_sign_round_t *r, uint8_t t, emit_t *em)
{
    wr_t rw = {e->work_records, 0, sizeof e->work_records};
    msg_t m;
    uint16_t n = count_items(r, r->me, t);
    uint8_t *q;
    size_t len;
    t = skip_empty_tiers(r, t);
    n = count_items(r, r->me, t);
    r->ticks = 0; r->nonces_len = 0;
    if (n == 0) { r->tier = t; return; }   /* the last tier had nothing of mine: wait for round_complete */
    msg_begin(&m, r->nonces_msg, sizeof r->nonces_msg, GZ_SIGN_MSG_NONCES, r->def.outer_digest);
    gz_rmsg_put(&m.w, 2, r->id, 32);
    gz_rmsg_put(&m.w, 4, &t, 1);
    q = gz_rmsg_reserve(&m.w, 6, 134u * n);
    put(&rw, r->id, 32); put8(&rw, t); put16(&rw, n);
    for (int i = 0; q && i < r->def.n_items; i++) {
        int s = pos_of(&r->def.items[i], r->me);
        if (r->def.items[i].tier != t || s < 0) continue;
        if (!make_nonce(e, r, i)) { em->st = GZ_ERR_ARGUMENT; return; }
        wr32(q, (uint32_t)i); memcpy(q + 4, r->nonce[i][s], 66); memcpy(q + 70, r->nonce_sig[i][s], 64); q += 134;
        put32(&rw, (uint32_t)i);
    }
    put(&rw, r->proposal, r->proposal_len);
    len = msg_end(&m);
    if (!len || !rw.cap) { em->st = GZ_ERR_NO_SPACE; return; }
    r->tier = t; r->tier_state[t] = GZ_SIGN_TIER_NONCES; r->ticks = 0;
    r->nonces_len = (uint32_t)len;
    emit_save(em, GZ_SIGN_REC_M_STARTED, e->work_records, rw.n);              /* RULE:S1_SAVE_FIRST */
    emit_send(em, host_peer(r), r->nonces_msg, len);
}

/* Something went wrong for a member's round: Aborted only while no partial
 * signature was ever sent, otherwise Unfinished. */
static void member_fail(gz_sign_t *e, gz_sign_round_t *r, uint8_t why, emit_t *em)
{
    size_t n;
    wipe_secrets(r);
    r->nonces_len = 0;
    r->why = why;
    e->counters[GZ_SIGN_COUNT_REJECTED]++;
    if (r->state != GZ_SIGN_ROUND_ACTIVE) return;
    if (!r->ever_partial) {                                              /* RULE:ABORT_ONLY_BEFORE_PARTIAL */
        r->state = GZ_SIGN_ROUND_ABORTED;
        r->tail_len = (uint32_t)build_abort(e, r, r->id, r->def.outer_digest, gz_sign_reason(why, r->built), -1, 0,
                                            r->tail_msg, sizeof r->tail_msg);
        save_round_record(e, em, GZ_SIGN_REC_M_ABORTED, r->id, 0, r->tail_msg, r->tail_len);
        emit_send(em, host_peer(r), r->tail_msg, r->tail_len);
    } else {
        r->state = GZ_SIGN_ROUND_UNFINISHED;
        if (r->tier_state[r->tier] == GZ_SIGN_TIER_NONCES) {
            n = build_abort(e, r, r->id, r->def.outer_digest, gz_sign_reason(why, r->built), r->tier, 0, e->scratch, sizeof e->scratch);
            emit_send(em, host_peer(r), e->scratch, n);
        }
    }
}

static void send_abort_for(gz_sign_t *e, const uint8_t id[32], const uint8_t scope[32], uint16_t reason, uint64_t peer, emit_t *em)
{
    size_t n = build_abort(e, NULL, id, scope, reason, -1, 0, e->scratch, sizeof e->scratch);
    emit_send(em, peer, e->scratch, n);
}

/* What a member answers when a round it already knows is proposed again
 * (messages.md 7.2's table, keyed on the identifier: S6). */
static void member_answer_known(gz_sign_t *e, gz_sign_round_t *r, emit_t *em)
{
    uint64_t host = host_peer(r);
    size_t n;
    e->counters[GZ_SIGN_COUNT_DUPLICATES]++;
    if (r->state == GZ_SIGN_ROUND_ABORTED || r->state == GZ_SIGN_ROUND_COMPLETE) {
        emit_send(em, host, r->tail_msg, r->tail_len);
    } else if (r->tier_state[r->tier] == GZ_SIGN_TIER_NONCES) {
        if (r->nonces_len && r->state == GZ_SIGN_ROUND_ACTIVE) emit_send(em, host, r->nonces_msg, r->nonces_len);   /* RULE:S3_RESEND_SAVED */
        else {
            n = build_abort(e, r, r->id, r->def.outer_digest, 3, r->tier, 0, e->scratch, sizeof e->scratch);
            emit_send(em, host, e->scratch, n);
        }
    } else if (r->tier_state[r->tier] == GZ_SIGN_TIER_SIGNED && r->partials_len[r->tier]) {
        emit_send(em, host, r->partials_msg[r->tier], r->partials_len[r->tier]);
    }
}

static void member_propose(gz_sign_t *e, uint64_t peer, const gz_sign_msg_t *m, const uint8_t *bytes, size_t len, emit_t *em)
{
    gz_sign_round_t *r = find(e, m->round_id);
    uint8_t why, d[32];
    uint16_t reason;
    if (r) {                                                             /* RULE:S2_KNOWN_ROUND */
        if (peer != host_peer(r) || gz_rmsg_propose_decode(m->records, m->records_len, &e->prop) != GZ_RMSG_OK) return;
        gz_rmsg_hash(m->kind, m->scope, m->records, e->prop.signed_len, d);
        if (!verify33(e, r->def.participants[0].contribution_key, d, e->prop.sig)) { e->counters[GZ_SIGN_COUNT_REJECTED]++; return; }
        /* S6: the saved proposal, whatever these bytes say; other bytes under
         * a valid host signature are evidence of the host signing two. */
        if (len != r->proposal_len || !same(bytes, r->proposal, len)) {
            if (!r->evidence) e->counters[GZ_SIGN_COUNT_EVIDENCE]++;
            r->evidence = 1;
        }
        member_answer_known(e, r, em);
        return;
    }
    if (is_known(e, m->round_id)) { send_abort_for(e, m->round_id, m->scope, 3, peer, em); return; }
    why = load_round(e, &e->pending, m, bytes, len, peer, 0);
    if (why != GZ_SIGN_WHY_NONE) {                       /* refused before it can push any round out of memory */
        reason = gz_sign_reason(why, e->pending.built);
        memset(&e->pending, 0, sizeof e->pending);
        e->counters[GZ_SIGN_COUNT_REJECTED]++;
        /* Not signed by the host it names, or not a proposal at all: nothing to answer. */
        if (why != GZ_SIGN_WHY_BAD_HOST_SIG && why != GZ_SIGN_WHY_BAD_MESSAGE) send_abort_for(e, m->round_id, m->scope, reason, peer, em);
        return;
    }
    r = adopt(e, 0);
    if (!r) { send_abort_for(e, m->round_id, m->scope, gz_sign_reason(GZ_SIGN_WHY_BUSY, 0), peer, em); return; }
    /* A valid new proposal from the host supersedes a round still collecting. */
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++)
        if (&e->rounds[i] != r && e->rounds[i].state == GZ_SIGN_ROUND_ACTIVE) member_fail(e, &e->rounds[i], GZ_SIGN_WHY_SUPERSEDED, em);
    member_begin_tier(e, r, 0, em);
}

static void member_all_nonces(gz_sign_t *e, gz_sign_round_t *r, const gz_sign_msg_t *m, emit_t *em)
{
    uint8_t t = m->tier, d[32], seen[GZ_SIGN_MAX_ITEMS] = {0}, nd[32], ps[32], sd[32], *q;
    msg_t w;
    uint16_t n_mine;
    size_t len;
    if (t >= r->def.n_tiers) return;
    tagged("gazpacho/allnonces", m->records, m->records_len, NULL, 0, d);
    if (r->tier_state[t] >= GZ_SIGN_TIER_SIGNED || r->have_all_nonces[t]) {
        /* Same bytes again: answer with the saved bytes. Different: refused, kept as evidence (not encoded in Slice 1). */
        if (r->have_all_nonces[t] && same(d, r->all_nonces_digest[t], 32) && r->tier_state[t] == GZ_SIGN_TIER_SIGNED && r->partials_len[t])
            emit_send(em, host_peer(r), r->partials_msg[t], r->partials_len[t]);
        else e->counters[GZ_SIGN_COUNT_REJECTED]++;
        return;
    }
    if (r->state != GZ_SIGN_ROUND_ACTIVE || t != r->tier || r->tier_state[t] != GZ_SIGN_TIER_NONCES || !r->nonces_len) return;
    memcpy(r->all_nonces_digest[t], d, 32);
    r->have_all_nonces[t] = 1;
    /* Every item of mine in this tier exactly once, every signer's nonce, every nonce signed by its owner. */
    for (int k = 0; k < m->n; k++) {
        const uint8_t *p = m->entry[k];
        uint32_t i = be32(p);
        if (i >= r->def.n_items || seen[i]) { member_fail(e, r, GZ_SIGN_WHY_BAD_MESSAGE, em); return; }
        const gz_sign_item_t *it = &r->def.items[i];
        int me = pos_of(it, r->me);
        if (it->tier != t || me < 0 || be16(p + 4) != it->n_signers) { member_fail(e, r, GZ_SIGN_WHY_BAD_MESSAGE, em); return; }
        seen[i] = 1;
        for (int s = 0; s < it->n_signers; s++) {
            const uint8_t *nonce = p + 6 + 130 * s, *sig = nonce + 66;
            gz_rmsg_nonce_hash(r->id, t, i, nonce, nd);
            if (!verify33(e, r->def.participants[it->signers[s]].contribution_key, nd, sig)) {   /* RULE:CHECK_NONCE_SIGS */
                member_fail(e, r, GZ_SIGN_WHY_BAD_NONCE, em); return;
            }
            if (s == me && !same(nonce, r->nonce[i][s], 66)) { member_fail(e, r, GZ_SIGN_WHY_OWN_NONCE_CHANGED, em); return; }
        }
    }
    n_mine = count_items(r, r->me, t);
    if (m->n != n_mine) { member_fail(e, r, GZ_SIGN_WHY_BAD_MESSAGE, em); return; }
    for (int k = 0; k < m->n; k++) {
        const uint8_t *p = m->entry[k];
        uint32_t i = be32(p);
        /* The others' nonce signatures are checked above and not kept: a member never sends them on,
         * and evidence (spec section 9) is not encoded in Slice 1. */
        for (int s = 0; s < r->def.items[i].n_signers; s++) memcpy(r->nonce[i][s], p + 6 + 130 * s, 66);
        r->have_nonce[i] = all_bits(&r->def.items[i]);
    }
    /* Sign, then save the bytes, then send. */
    msg_begin(&w, r->partials_msg[t], sizeof r->partials_msg[t], GZ_SIGN_MSG_PARTIALS, r->def.outer_digest);
    gz_rmsg_put(&w.w, 2, r->id, 32);
    gz_rmsg_put(&w.w, 4, &t, 1);
    q = gz_rmsg_reserve(&w.w, 6, 68u * n_mine);
    for (int i = 0; q && i < r->def.n_items; i++) {
        if (r->def.items[i].tier != t || pos_of(&r->def.items[i], r->me) < 0) continue;
        if (!sign_item(e, r, i, ps)) { member_fail(e, r, GZ_SIGN_WHY_BAD_NONCE, em); return; }
        set_digest(r, i, sd);
        wr32(q, (uint32_t)i); memcpy(q + 4, ps, 32); memcpy(q + 36, sd, 32); q += 68;
    }
    len = msg_end_signed(e, &w, 0);
    if (!len) { em->st = GZ_ERR_NO_SPACE; return; }
    r->partials_len[t] = (uint32_t)len;
    r->tier_state[t] = GZ_SIGN_TIER_SIGNED;
    r->ever_partial = 1;
    r->nonces_len = 0;
    r->ticks = 0;
    save_round_record(e, em, GZ_SIGN_REC_M_SIGNED, r->id, t, r->partials_msg[t], len);
    emit_send(em, host_peer(r), r->partials_msg[t], len);
}

/* A member's tier result: exactly its items of the tier, each final
 * signature judged from the signed transaction's bytes. */
static int check_result(gz_sign_t *e, gz_sign_round_t *r, const gz_sign_msg_t *m, int store)
{
    uint8_t seen[GZ_SIGN_MAX_ITEMS] = {0};
    size_t n;
    if (m->tier >= r->def.n_tiers || m->n != count_items(r, r->me, m->tier)) return 0;
    for (int k = 0; k < m->n; k++) {
        uint32_t i = be32(m->entry[k]);
        if (i >= r->def.n_items || seen[i] || r->def.items[i].tier != m->tier || pos_of(&r->def.items[i], r->me) < 0) return 0;
        const gz_sign_item_t *it = &r->def.items[i];
        n = gz_sign_tx_attach(it->tx, it->tx_len, m->entry[k] + 4, e->work_tx, sizeof e->work_tx);
        if (!n || !gz_sign_tx_verify(e->cfg.ctx, e->work_tx, n, it->spent_amount, it->spent_script)) return 0;   /* RULE:VERIFY_FINAL */
        e->counters[GZ_SIGN_COUNT_FINALS_VERIFIED]++;
        seen[i] = 1;
    }
    if (store)
        for (int k = 0; k < m->n; k++) {
            uint32_t i = be32(m->entry[k]);
            memcpy(r->final_sig[i], m->entry[k] + 4, 64);
            r->have_final[i] = 1;
        }
    return 1;
}

static void member_result(gz_sign_t *e, gz_sign_round_t *r, const gz_sign_msg_t *m, const uint8_t *bytes, size_t len, emit_t *em)
{
    uint8_t t = m->tier;
    if (t < r->def.n_tiers && r->tier_state[t] == GZ_SIGN_TIER_DONE && r->tier == t + 1 && r->state == GZ_SIGN_ROUND_ACTIVE &&
        r->tier_state[t + 1] == GZ_SIGN_TIER_NONCES && r->nonces_len) {
        /* the host asks again for the next tier's nonces: the same bytes, this incarnation's (S3) */
        emit_send(em, host_peer(r), r->nonces_msg, r->nonces_len);
        return;
    }
    if (t >= r->def.n_tiers || r->tier_state[t] != GZ_SIGN_TIER_SIGNED) return;
    if (r->state != GZ_SIGN_ROUND_ACTIVE && r->state != GZ_SIGN_ROUND_UNFINISHED) return;
    if (len > sizeof r->result_msg[t] || !signed_by(e, m, r->def.participants[0].contribution_key) || !check_result(e, r, m, 1)) {
        e->counters[GZ_SIGN_COUNT_REJECTED]++;
        r->state = GZ_SIGN_ROUND_UNFINISHED;                                  /* RULE:SIGNED_NEVER_ABORTED */
        r->why = GZ_SIGN_WHY_BAD_RESULT;
        return;
    }
    r->state = GZ_SIGN_ROUND_ACTIVE;
    r->tier_state[t] = GZ_SIGN_TIER_DONE;
    r->ticks = 0;
    memcpy(r->result_msg[t], bytes, len); r->result_len[t] = (uint32_t)len;
    save_round_record(e, em, GZ_SIGN_REC_M_RESULT, r->id, t, bytes, len);
    if (t + 1 < r->def.n_tiers) member_begin_tier(e, r, (uint8_t)(t + 1), em);
}

static void member_complete(gz_sign_t *e, gz_sign_round_t *r, const gz_sign_msg_t *m, const uint8_t *bytes, size_t len, emit_t *em)
{
    uint8_t held[32];
    msg_t w;
    if (r->state == GZ_SIGN_ROUND_COMPLETE) { emit_send(em, host_peer(r), r->tail_msg, r->tail_len); return; }
    for (int t = 0; t < r->def.n_tiers; t++)
        if (r->tier_state[t] != GZ_SIGN_TIER_DONE) return;
    if (r->state != GZ_SIGN_ROUND_ACTIVE || len > sizeof r->complete_msg || !signed_by(e, m, r->def.participants[0].contribution_key)) return;
    memcpy(r->complete_msg, bytes, len); r->complete_len = (uint32_t)len;
    held_digest(r, r->me, held);
    msg_begin(&w, r->tail_msg, sizeof r->tail_msg, GZ_SIGN_MSG_ACK, r->def.outer_digest);
    gz_rmsg_put(&w.w, 2, r->id, 32);
    gz_rmsg_put(&w.w, 4, held, 32);
    r->tail_len = (uint32_t)msg_end_signed(e, &w, 0);
    r->state = GZ_SIGN_ROUND_COMPLETE;
    save_round_record(e, em, GZ_SIGN_REC_M_COMPLETE, r->id, 0, r->tail_msg, r->tail_len);
    emit_send(em, host_peer(r), r->tail_msg, r->tail_len);
}

/* The reconnect step for a round (contract v2 section 3, node rule 6): saved
 * partial signatures if the result is missing, then a status request for an
 * unresolved round. Nothing in the nonce phase (the host's step timer). */
static void member_resend(gz_sign_t *e, gz_sign_round_t *r, emit_t *em)
{
    uint64_t host = host_peer(r);
    size_t n;
    if (r->state != GZ_SIGN_ROUND_ACTIVE && r->state != GZ_SIGN_ROUND_UNFINISHED && r->state != GZ_SIGN_ROUND_COMPLETE) return;
    if (r->state != GZ_SIGN_ROUND_COMPLETE) {
        if (r->tier_state[r->tier] < GZ_SIGN_TIER_SIGNED) return;
        if (r->tier_state[r->tier] == GZ_SIGN_TIER_SIGNED && r->partials_len[r->tier])
            emit_send(em, host, r->partials_msg[r->tier], r->partials_len[r->tier]);
    }
    n = build_status(r, e->scratch, sizeof e->scratch);
    emit_send(em, host, e->scratch, n);
}

static void member_message(gz_sign_t *e, uint64_t peer, const gz_sign_msg_t *m, const uint8_t *bytes, size_t len, emit_t *em)
{
    gz_sign_round_t *r;
    if (m->kind == GZ_SIGN_MSG_PROPOSE) { member_propose(e, peer, m, bytes, len, em); return; }
    if (!m->round_id || m->kind == GZ_SIGN_MSG_FUNDED) return;   /* factory_funded: a hint the member never relies on (7.11) */
    r = find(e, m->round_id);
    if (!r || peer != host_peer(r) || !same(m->scope, r->def.outer_digest, 32)) return;
    switch (m->kind) {
    case GZ_SIGN_MSG_ALL_NONCES: member_all_nonces(e, r, m, em); break;
    case GZ_SIGN_MSG_RESULT: member_result(e, r, m, bytes, len, em); break;
    case GZ_SIGN_MSG_COMPLETE: member_complete(e, r, m, bytes, len, em); break;
    case GZ_SIGN_MSG_ABORT:
        if (signed_by(e, m, r->def.participants[0].contribution_key) && r->state == GZ_SIGN_ROUND_ACTIVE &&
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
    uint32_t miss = 0, have;
    for (int i = 0; i < r->def.n_items; i++) {
        const gz_sign_item_t *it = &r->def.items[i];
        if (it->tier != r->tier) continue;
        have = psigs ? r->have_psig[i] : r->have_nonce[i];
        for (int s = 0; s < it->n_signers; s++)
            if (!(have >> s & 1u) && it->signers[s] != 0) miss |= bit(it->signers[s]);
    }
    return miss;
}

/* Every tier result held for participant j, then round_complete if sent. */
static void host_send_results(gz_sign_t *e, gz_sign_round_t *r, uint8_t j, emit_t *em)
{
    size_t n;
    for (int t = 0; t < r->def.n_tiers; t++) {
        if (r->tier_state[t] != GZ_SIGN_TIER_DONE || !count_items(r, j, t)) continue;
        n = build_result(e, r, (uint8_t)t, j, e->scratch, sizeof e->scratch);
        emit_send(em, r->def.peer[j], e->scratch, n);
    }
    if (r->complete_len) emit_send(em, r->def.peer[j], r->complete_msg, r->complete_len);
}

/* The abort a failed attempt sends participant j: the fault for a blamed
 * member (5), or its removal (7), and a deadline (4) for the others. */
static size_t host_abort_for(gz_sign_t *e, const gz_sign_round_t *r, uint8_t j, uint8_t *buf, size_t cap)
{
    uint16_t reason = gz_sign_reason(r->why, 0);
    if (!(r->blamed >> j & 1u)) reason = 4;
    else if (reason == 4) reason = 7;
    return build_abort(e, NULL, r->id, r->def.outer_digest, reason, -1, 1, buf, cap);
}

static void host_retry(gz_sign_t *e, const gz_sign_round_t *r, int released, emit_t *em);

static void host_fail(gz_sign_t *e, gz_sign_round_t *r, uint32_t blamed, uint8_t why, emit_t *em)
{
    uint8_t rec[40];
    wr_t w = {rec, 0, sizeof rec};
    int released = 0;
    size_t n;
    for (int t = 0; t < r->def.n_tiers; t++) released |= r->tier_state[t] >= GZ_SIGN_TIER_SIGNED;
    if (why == GZ_SIGN_WHY_HOST_RESTART) released = 1;      /* what left before the restart is not known */
    wipe_secrets(r);
    r->state = GZ_SIGN_ROUND_FAILED; r->blamed = blamed; r->why = why;
    /* A fault the host saw itself, against a refusal or a silence it cannot show anyone. */
    if (why == GZ_SIGN_WHY_DEADLINE || why == GZ_SIGN_WHY_MEMBER_ABORT) e->counters[GZ_SIGN_COUNT_BLAME_SILENT] += blamed != 0;
    else e->counters[GZ_SIGN_COUNT_BLAME_FAULT] += blamed != 0;
    put(&w, r->id, 32); put32(&w, blamed); put8(&w, why);
    emit_save(em, GZ_SIGN_REC_H_FAILED, rec, w.n);
    for (uint8_t j = 1; j < r->def.n_participants; j++) {
        n = host_abort_for(e, r, j, e->scratch, sizeof e->scratch);
        emit_send(em, r->def.peer[j], e->scratch, n);
    }
    host_retry(e, r, released, em);
}

static void host_distribute(gz_sign_t *e, gz_sign_round_t *r, uint8_t j, emit_t *em)
{
    size_t n;
    if (!count_items(r, j, r->tier)) return;   /* nothing of its own in this tier: it signs nothing, it is sent nothing */
    n = build_all_nonces(r, r->tier, j, e->scratch, sizeof e->scratch);
    emit_send(em, r->def.peer[j], e->scratch, n);
}

/* Every partial signature of the tier is in and verified: add the host's,
 * combine, check each result from its bytes, save, send. */
static void host_combine(gz_sign_t *e, gz_sign_round_t *r, emit_t *em)
{
    /* The partial signatures and the signed transaction live in the engine's
     * work area, not on the stack: this function is inlined into
     * host_partials, and gcc's AddressSanitizer would guard such large
     * inlined locals with calls the isolation check refuses. */
    uint8_t t = r->tier, *tx = e->work_tx, mine[32];
    secp256k1_musig_partial_sig *ps = e->work_psig;
    const secp256k1_musig_partial_sig *ptrs[GZ_SIGN_MAX_SIGNERS];
    wr_t w = {e->work_records, 0, sizeof e->work_records};
    msg_t c;
    size_t len;
    put(&w, r->id, 32); put8(&w, t);
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
        len = gz_sign_tx_attach(it->tx, it->tx_len, r->final_sig[i], tx, sizeof e->work_tx);
        if (!len || !gz_sign_tx_verify(e->cfg.ctx, tx, len, it->spent_amount, it->spent_script)) {   /* RULE:HOST_VERIFY_FINAL */
            host_fail(e, r, 0, GZ_SIGN_WHY_BAD_RESULT, em); return;
        }
        e->counters[GZ_SIGN_COUNT_FINALS_VERIFIED]++;
        r->have_final[i] = 1;
        put32(&w, (uint32_t)i); put(&w, r->final_sig[i], 64);
    }
    if (!w.cap) { em->st = GZ_ERR_NO_SPACE; return; }
    r->tier_state[t] = GZ_SIGN_TIER_DONE;
    emit_save(em, GZ_SIGN_REC_H_RESULT, e->work_records, w.n);
    if (t + 1 == r->def.n_tiers) {
        msg_begin(&c, r->complete_msg, sizeof r->complete_msg, GZ_SIGN_MSG_COMPLETE, r->def.outer_digest);
        gz_rmsg_put(&c.w, 2, r->id, 32);
        r->complete_len = (uint32_t)msg_end_signed(e, &c, 0);
        save_round_record(e, em, GZ_SIGN_REC_H_COMPLETE, r->id, 0, r->complete_msg, r->complete_len);
        r->state = GZ_SIGN_ROUND_COMPLETE;
        r->ticks = 0;
    }
    for (uint8_t j = 1; j < r->def.n_participants; j++) {
        if (count_items(r, j, t)) {
            len = build_result(e, r, t, j, e->scratch, sizeof e->scratch);
            emit_send(em, r->def.peer[j], e->scratch, len);
        }
        if (r->state == GZ_SIGN_ROUND_COMPLETE) emit_send(em, r->def.peer[j], r->complete_msg, r->complete_len);
    }
    if (r->state != GZ_SIGN_ROUND_COMPLETE) host_begin_tier(e, r, (uint8_t)(t + 1));
}

/* Participant j's entries must name exactly its items of the tier, in
 * increasing index (messages.md 7.3, 7.5). */
static int exact_items(const gz_sign_round_t *r, uint8_t j, const gz_sign_msg_t *m)
{
    int k = 0;
    for (int i = 0; i < r->def.n_items; i++) {
        if (r->def.items[i].tier != m->tier || pos_of(&r->def.items[i], j) < 0) continue;
        if (k >= m->n || be32(m->entry[k]) != (uint32_t)i) return 0;
        k++;
    }
    return k == m->n;
}

static void host_nonces(gz_sign_t *e, gz_sign_round_t *r, uint8_t j, const gz_sign_msg_t *m, emit_t *em)
{
    uint8_t d[32];
    secp256k1_musig_pubnonce pn;
    if (m->tier != r->tier || r->tier_state[r->tier] != GZ_SIGN_TIER_NONCES) {
        e->counters[GZ_SIGN_COUNT_DUPLICATES]++;
        return;
    }
    if (!exact_items(r, j, m)) { host_fail(e, r, bit(j), GZ_SIGN_WHY_BAD_MESSAGE, em); return; }
    for (int k = 0; k < m->n; k++) {
        const uint8_t *p = m->entry[k], *nonce = p + 4, *sig = p + 70;
        uint32_t i = be32(p);
        int s = pos_of(&r->def.items[i], j);
        gz_rmsg_nonce_hash(r->id, m->tier, i, nonce, d);
        if (!verify33(e, r->def.participants[j].contribution_key, d, sig) ||
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

static void host_partials(gz_sign_t *e, gz_sign_round_t *r, uint8_t j, const gz_sign_msg_t *m, emit_t *em)
{
    secp256k1_pubkey pk;
    uint8_t sd[32];
    secp256k1_musig_partial_sig ps;
    secp256k1_musig_pubnonce pn;
    if (!signed_by(e, m, r->def.participants[j].contribution_key)) { host_fail(e, r, bit(j), GZ_SIGN_WHY_BAD_MESSAGE, em); return; }
    if (m->tier != r->tier || r->tier_state[r->tier] != GZ_SIGN_TIER_SIGNED) { e->counters[GZ_SIGN_COUNT_DUPLICATES]++; return; }
    if (!exact_items(r, j, m)) { host_fail(e, r, bit(j), GZ_SIGN_WHY_BAD_MESSAGE, em); return; }
    if (!secp256k1_ec_pubkey_parse(e->cfg.ctx, &pk, r->def.participants[j].factory_key, 33)) return;
    for (int k = 0; k < m->n; k++) {
        const uint8_t *p = m->entry[k];
        uint32_t i = be32(p);
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

/* Whom a member's signed abort blames (review A, F4; spec section 10: a fault
 * costs a seat, not the lobby). Reason 3 (it restarted) is honest once in a
 * lobby: the second is blamed. Reason 6 (another round on its outputs) is
 * honest only while this host holds another round on the same funding
 * outpoint that is not over; otherwise the member is blamed. Any other
 * reason is the member's own refusal: blamed, as before. */
static uint32_t abort_blame(gz_sign_t *e, const gz_sign_round_t *r, uint8_t j, uint16_t reason)
{
    const uint8_t *key = r->def.participants[j].contribution_key;
    if (reason == 3) {
        for (size_t k = 0; k < e->n_restarted; k++)
            if (same(e->restarted[k], key, 33)) return bit(j);                 /* RULE:BLAME_SECOND_RESTART */
        if (e->n_restarted == GZ_SIGN_MAX_PARTICIPANTS) return bit(j);
        memcpy(e->restarted[e->n_restarted++], key, 33);
        return 0;
    }
    if (reason == 6) {
        for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) {
            const gz_sign_round_t *o = &e->rounds[i];
            if (o != r && (o->state == GZ_SIGN_ROUND_ACTIVE || o->state == GZ_SIGN_ROUND_COMPLETE || o->state == GZ_SIGN_ROUND_DONE) &&
                same(o->def.funding_txid, r->def.funding_txid, 32) && o->def.funding_vout == r->def.funding_vout) return 0;
        }
        return bit(j);                                                             /* RULE:BLAME_FALSE_SUPERSEDED */
    }
    return bit(j);
}

static void host_message(gz_sign_t *e, uint64_t peer, const gz_sign_msg_t *m, emit_t *em)
{
    uint8_t j = 0, held[32], rec[33];
    gz_sign_round_t *r;
    size_t n;
    if (!m->round_id || m->kind == GZ_SIGN_MSG_PROPOSE || m->kind == GZ_SIGN_MSG_FUNDED) return;
    r = find(e, m->round_id);
    if (!r) return;                                   /* an unknown identifier is ignored (7.10) */
    for (uint8_t q = 1; q < r->def.n_participants; q++)
        if (r->def.peer[q] == peer) j = q;
    if (j == 0 || !same(m->scope, r->def.outer_digest, 32)) return;
    if (m->kind == GZ_SIGN_MSG_STATUS) {
        /* At most one answer per round and member key in status_ticks (7.10). */
        if (r->status_tick[j] && e->tick + 1 < r->status_tick[j] + e->cfg.status_ticks) { e->counters[GZ_SIGN_COUNT_DUPLICATES]++; return; }
        r->status_tick[j] = e->tick + 1;
        if (r->state == GZ_SIGN_ROUND_FAILED) {
            n = host_abort_for(e, r, j, e->scratch, sizeof e->scratch);
            emit_send(em, peer, e->scratch, n);
        } else host_send_results(e, r, j, em);
        return;
    }
    if (m->kind == GZ_SIGN_MSG_ACK) {
        if ((r->state != GZ_SIGN_ROUND_COMPLETE && r->state != GZ_SIGN_ROUND_DONE) || (r->acked >> j & 1u)) return;
        if (!signed_by(e, m, r->def.participants[j].contribution_key)) return;
        held_digest(r, j, held);
        if (!same(held, m->held, 32)) { host_send_results(e, r, j, em); return; }   /* it holds something else: resend (7.8) */
        r->acked |= bit(j);
        memcpy(rec, r->id, 32); rec[32] = j;
        emit_save(em, GZ_SIGN_REC_H_ACK, rec, 33);
        if (r->acked == members_mask(r)) r->state = GZ_SIGN_ROUND_DONE;
        return;
    }
    if (r->state != GZ_SIGN_ROUND_ACTIVE) return;
    if (m->kind == GZ_SIGN_MSG_NONCES) host_nonces(e, r, j, m, em);
    else if (m->kind == GZ_SIGN_MSG_PARTIALS) host_partials(e, r, j, m, em);
    else if (m->kind == GZ_SIGN_MSG_ABORT && signed_by(e, m, r->def.participants[j].contribution_key))
        host_fail(e, r, abort_blame(e, r, j, m->reason), GZ_SIGN_WHY_MEMBER_ABORT, em);
}

/* The host's proposal: encoded once with a zero identifier and read back as
 * a member reads it, built, the identifier computed, then encoded with it,
 * signed, and read back through load_round like any received proposal. */
static gz_status_t host_begin(gz_sign_t *e, const gz_sign_begin_t *b, emit_t *em)
{
    /* Function scope, not inner blocks: no ASan use-after-scope calls (isolation). */
    uint8_t host_random[32], zero[32] = {0}, pre[48], id[32], d[32], sig[64];
    wr_t hw = {pre, 0, sizeof pre};
    gz_rmsg_propose_in_t in;
    gz_rmsg_wr_t w;
    gz_sign_msg_t m;
    size_t n, h;
    gz_sign_round_t *r = &e->pending;
    gz_sign_build_in_t bin;
    if (!b || !b->p || !b->check_id || e->attempts >= e->cfg.max_attempts) return GZ_ERR_ARGUMENT;
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++)
        if (e->rounds[i].state == GZ_SIGN_ROUND_ACTIVE) return GZ_ERR_ARGUMENT;
    if (b->p->n_lstock_hashes || b->p->has_distribution || b->p->n_participants > GZ_SIGN_MAX_PARTICIPANTS) return GZ_ERR_ARGUMENT;
    /* S4: a new attempt has a new identifier, also after a restore whose generator repeats. */
    e->ports.random.fill(e->ports.random.ctx, GZ_RANDOM_ORDINARY, pre, 32);
    hw.n = 32; put64(&hw, e->incarnation); put64(&hw, e->attempt_counter++);   /* RULE:HOST_RANDOM_MIX */
    tagged("gazpacho/host-random", pre, hw.n, NULL, 0, host_random);
    memset(&in, 0, sizeof in);
    in.round_id = zero; in.check_id = b->check_id; in.host_random = host_random;
    in.has_attempt = b->has_attempt; in.attempt = b->attempt; in.p = b->p;
    /* Encodable at all (sizes, counts, ranges) before anything is built. */
    if (!gz_rmsg_propose_encode(&in, e->work_records, sizeof e->work_records - 67)) return GZ_ERR_ARGUMENT;
    /* The host's builder reads the same fields a member's reads. */
    memset(&e->prop, 0, sizeof e->prop);
    e->prop.p = *b->p;
    e->prop.round_id = zero; e->prop.check_id = b->check_id; e->prop.host_random = host_random;
    memset(&e->scratch_def, 0, sizeof e->scratch_def);
    bin.msg = &e->prop; bin.scope = NULL; bin.peer = 0; bin.replay = 0;
    if (e->cfg.build(e->cfg.build_ctx, &bin, &e->scratch_def)) return GZ_ERR_ARGUMENT;
    memset(r, 0, sizeof *r);
    r->def = e->scratch_def;
    def_from_proposal(&r->def, b->p);
    if (check_def(e, &r->def, r) != GZ_SIGN_WHY_NONE) { memset(r, 0, sizeof *r); return GZ_ERR_ARGUMENT; }
    gz_sign_round_id(&r->def, (const uint8_t (*)[32])r->digest, (const uint8_t (*)[32])r->tweak, host_random, id);
    in.round_id = id;
    h = gz_rmsg_header(e->scratch, sizeof e->scratch, GZ_SIGN_MSG_PROPOSE, r->def.outer_digest);
    n = h ? gz_rmsg_propose_encode(&in, e->scratch + h, GZ_SIGN_MAX_PROPOSAL - h - 67) : 0;
    if (!n) { memset(r, 0, sizeof *r); return GZ_ERR_ARGUMENT; }
    gz_rmsg_hash(GZ_SIGN_MSG_PROPOSE, r->def.outer_digest, e->scratch + h, n, d);
    sign_digest(e, d, sig, 0);
    gz_rmsg_wr_init(&w, e->scratch + h, GZ_SIGN_MAX_PROPOSAL - h);
    w.n = n; w.last = 50;
    gz_rmsg_put(&w, GZ_RMSG_SIG_TYPE, sig, 64);
    if (!gz_rmsg_wr_ok(&w)) { memset(r, 0, sizeof *r); return GZ_ERR_ARGUMENT; }
    /* Read back as a member reads it (load_round copies the bytes into the slot). */
    if (!gz_sign_decode(e->scratch, h + w.n, &m) || load_round(e, r, &m, e->scratch, h + w.n, 0, 0) != GZ_SIGN_WHY_NONE) {
        memset(r, 0, sizeof *r);
        return GZ_ERR_ARGUMENT;
    }
    if (!(r = adopt(e, 0))) return GZ_ERR_NO_SPACE;
    e->attempts++;
    host_begin_tier(e, r, 0);
    emit_save(em, GZ_SIGN_REC_H_PROPOSED, r->proposal, r->proposal_len);
    for (uint8_t j = 1; j < r->def.n_participants; j++) emit_send(em, r->def.peer[j], r->proposal, r->proposal_len);
    return GZ_OK;
}

static void host_retry(gz_sign_t *e, const gz_sign_round_t *r, int released, emit_t *em)
{
    gz_sign_begin_t next;
    gz_sign_retry_in_t in;
    in.failed = r; in.blamed = r->blamed; in.released = released;
    memset(&next, 0, sizeof next);
    if (e->cfg.retry && em->st == GZ_OK && e->cfg.retry(e->cfg.build_ctx, &in, &next)) (void)host_begin(e, &next, em);
}

static void host_tick(gz_sign_t *e, gz_sign_round_t *r, emit_t *em)
{
    int resend = e->cfg.resend_ticks && ++r->ticks % e->cfg.resend_ticks == 0, psigs;
    uint32_t miss;
    size_t n;
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
    psigs = r->tier_state[r->tier] == GZ_SIGN_TIER_SIGNED;
    miss = members_missing(r, psigs);
    if (r->ticks >= e->cfg.deadline_ticks) { host_fail(e, r, miss, GZ_SIGN_WHY_DEADLINE, em); return; }
    /* The step timer (contract v2 section 3): the only repair of the nonce phase. */
    for (uint8_t j = 1; resend && j < r->def.n_participants; j++) {
        if (!(miss >> j & 1u)) continue;
        if (psigs) host_distribute(e, r, j, em);
        else if (r->tier == 0) emit_send(em, r->def.peer[j], r->proposal, r->proposal_len);
        else if (count_items(r, j, r->tier - 1)) {
            n = build_result(e, r, (uint8_t)(r->tier - 1), j, e->scratch, sizeof e->scratch);
            emit_send(em, r->def.peer[j], e->scratch, n);
        }
    }
}

/* ---- start ---- */

/* Drop every round and refused identifier held in memory (a start rebuilds
 * them from storage). The keys, the configuration and the counters that keep
 * session ids and host random values unique in this incarnation stay. */
static void reset_rounds(gz_sign_t *e)
{
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) wipe_secrets(&e->rounds[i]);
    wipe_secrets(&e->pending);
    memset(e->rounds, 0, sizeof e->rounds);
    memset(&e->pending, 0, sizeof e->pending);
    memset(e->known, 0, sizeof e->known);
    memset(e->known_filter, 0, sizeof e->known_filter);
    e->n_known = 0;
    e->attempts = 0;
    e->next_seq = 0;
}

/* After an error the engine's state may be ahead of what was handed out:
 * refuse everything until a start (review A, F1). */
static gz_status_t fail_engine(gz_sign_t *e, gz_status_t st)
{
    e->failed = 1;                                                            /* RULE:FAIL_ON_ERROR */
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) wipe_secrets(&e->rounds[i]);
    wipe_secrets(&e->pending);
    return st;
}

/* A saved proposal read back: rebuilt (the builder in replay mode), checked
 * and given a slot. NULL if it is not one this party can rebuild. */
static gz_sign_round_t *start_round(gz_sign_t *e, const uint8_t *proposal, size_t len, const uint8_t *id)
{
    gz_sign_msg_t m;
    if (find(e, id) || !gz_sign_decode(proposal, len, &m) || m.kind != GZ_SIGN_MSG_PROPOSE) return NULL;
    if (load_round(e, &e->pending, &m, proposal, len, 0, 1) != GZ_SIGN_WHY_NONE || !same(e->pending.id, id, 32)) {
        memset(&e->pending, 0, sizeof e->pending);
        return NULL;
    }
    return adopt(e, 1);
}

/* A saved message of the round: decoded, of `kind`, naming the round, and
 * signed by participant `by`. */
static int saved_msg(const gz_sign_t *e, const gz_sign_round_t *r, const uint8_t *b, size_t len, uint16_t kind, uint8_t by, gz_sign_msg_t *m)
{
    return gz_sign_decode(b, len, m) && m->kind == kind && m->round_id && same(m->round_id, r->id, 32) &&
           same(m->scope, r->def.outer_digest, 32) && signed_by(e, m, r->def.participants[by].contribution_key);
}

/* One stored record. Returns 0 if it is not one this engine wrote. */
static int replay(gz_sign_t *e, const gz_record_t *rec)
{
    const uint8_t *b = rec->bytes.data, *body;
    size_t len = rec->bytes.len, blen, n;
    gz_sign_msg_t m;
    gz_sign_round_t *r;
    uint8_t t;
    if (rec->type == GZ_SIGN_REC_H_PROPOSED) {
        if (!e->cfg.host || !gz_sign_decode(b, len, &m) || m.kind != GZ_SIGN_MSG_PROPOSE) return 0;
        e->attempts++;
        return start_round(e, b, len, m.round_id) != NULL;
    }
    if (len < 33) return 0;
    r = find(e, b);
    t = b[32];
    body = b + 33;
    blen = len - 33;
    if (rec->type == GZ_SIGN_REC_M_STARTED) {
        if (e->cfg.host || len < 35) return 0;
        n = (size_t)b[33] << 8 | b[34];
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
        if (e->cfg.host || t >= r->def.n_tiers || blen > sizeof r->partials_msg[t] ||
            !saved_msg(e, r, body, blen, GZ_SIGN_MSG_PARTIALS, r->me, &m) || m.tier != t) return 0;
        r->tier_state[t] = GZ_SIGN_TIER_SIGNED; r->ever_partial = 1;
        memcpy(r->partials_msg[t], body, blen); r->partials_len[t] = (uint32_t)blen;
        return 1;
    case GZ_SIGN_REC_M_RESULT:
        if (e->cfg.host || t >= r->def.n_tiers || blen > sizeof r->result_msg[t] ||
            !saved_msg(e, r, body, blen, GZ_SIGN_MSG_RESULT, 0, &m) || m.tier != t || !check_result(e, r, &m, 1)) return 0;
        r->tier_state[t] = GZ_SIGN_TIER_DONE; r->tier = t;
        memcpy(r->result_msg[t], body, blen); r->result_len[t] = (uint32_t)blen;
        return 1;
    case GZ_SIGN_REC_H_RESULT: {
        /* The tier's final signatures, every one judged again from its transaction's bytes. */
        uint32_t want = 0;
        if (!e->cfg.host || t >= r->def.n_tiers || blen % 68) return 0;
        for (int i = 0; i < r->def.n_items; i++) want += r->def.items[i].tier == t;
        if (blen / 68 != want) return 0;
        for (size_t k = 0; k < blen / 68; k++) {
            uint32_t i = be32(body + 68 * k);
            if (i >= r->def.n_items || r->def.items[i].tier != t || r->have_final[i]) return 0;
            n = gz_sign_tx_attach(r->def.items[i].tx, r->def.items[i].tx_len, body + 68 * k + 4, e->work_tx, sizeof e->work_tx);
            if (!n || !gz_sign_tx_verify(e->cfg.ctx, e->work_tx, n, r->def.items[i].spent_amount, r->def.items[i].spent_script)) return 0;
            memcpy(r->final_sig[i], body + 68 * k + 4, 64);
            r->have_final[i] = 1;
        }
        r->tier_state[t] = GZ_SIGN_TIER_DONE; r->tier = t;
        return 1;
    }
    case GZ_SIGN_REC_M_COMPLETE: case GZ_SIGN_REC_M_ABORTED:
        if (e->cfg.host || t != 0 || blen > sizeof r->tail_msg ||
            !saved_msg(e, r, body, blen, rec->type == GZ_SIGN_REC_M_COMPLETE ? GZ_SIGN_MSG_ACK : GZ_SIGN_MSG_ABORT, r->me, &m)) return 0;
        memcpy(r->tail_msg, body, blen); r->tail_len = (uint32_t)blen;
        r->state = rec->type == GZ_SIGN_REC_M_ABORTED ? GZ_SIGN_ROUND_ABORTED : GZ_SIGN_ROUND_COMPLETE;
        if (r->state == GZ_SIGN_ROUND_COMPLETE)          /* an ack was made only with every tier done */
            for (int k = 0; k < r->def.n_tiers; k++) r->tier_state[k] = GZ_SIGN_TIER_DONE;
        return 1;
    case GZ_SIGN_REC_H_COMPLETE:
        if (!e->cfg.host || t != 0 || blen > sizeof r->complete_msg || !saved_msg(e, r, body, blen, GZ_SIGN_MSG_COMPLETE, 0, &m)) return 0;
        memcpy(r->complete_msg, body, blen); r->complete_len = (uint32_t)blen;
        r->state = GZ_SIGN_ROUND_COMPLETE;
        return 1;
    case GZ_SIGN_REC_H_ACK:
        if (!e->cfg.host || len != 33 || t >= r->def.n_participants || t == 0) return 0;
        r->acked |= bit(t);
        return 1;
    case GZ_SIGN_REC_H_FAILED:
        if (!e->cfg.host || len != 37) return 0;
        r->state = GZ_SIGN_ROUND_FAILED; r->blamed = be32(b + 32); r->why = b[36];
        return 1;
    default:
        return 0;
    }
}

gz_status_t gz_sign_start(gz_sign_t *e, const gz_storage_reader_t *storage, gz_action_list_t *out, int *more)
{
    size_t count, used;
    emit_t em;
    gz_stored_batch_t batch;
    gz_sign_round_t *unfinished = NULL;
    if (!e || !storage || !storage->next || !storage->rewind || !out || !more) return GZ_ERR_ARGUMENT;
    count = out->count; used = out->used;
    em.out = out; em.st = GZ_OK;
    reset_rounds(e);
    e->failed = 1;                                  /* until this start has succeeded */
    storage->rewind(storage->ctx);
    while (storage->next(storage->ctx, &batch))
        for (size_t i = 0; i < batch.n_records; i++) {
            /* Only this engine's area: the node's own records (journal.md 9,
             * key_epoch, restored, guard) and other engines' are theirs to read. */
            if ((batch.records[i].type >> 16) != GZ_SIGN_REC_AREA) continue;
            if (!replay(e, &batch.records[i])) return GZ_ERR_CORRUPT;
        }
    /* What is left open: no secret nonce survived, so answer per item (S2). */
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) {
        gz_sign_round_t *r = &e->rounds[i];
        if (r->state == GZ_SIGN_ROUND_FREE) continue;
        if (e->cfg.host) {
            if (r->state == GZ_SIGN_ROUND_ACTIVE) unfinished = r;
            else if (r->state == GZ_SIGN_ROUND_COMPLETE && r->acked == members_mask(r)) r->state = GZ_SIGN_ROUND_DONE;
            /* The host pushes nothing at start: members ask (contract v2 section 3). */
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
    e->failed = 0;
    *more = 0;
    return GZ_OK;
}

/* ---- the public calls ---- */

gz_status_t gz_sign_init(gz_sign_t *e, const gz_sign_config_t *cfg, const gz_ports_t *ports, uint64_t incarnation)
{
    secp256k1_pubkey cpk;
    size_t l = 33;
    if (!e || !cfg || !ports || !cfg->ctx || !cfg->build || !ports->random.fill || !cfg->tick_ms) return GZ_ERR_ARGUMENT;
    memset(e, 0, sizeof *e);
    e->cfg = *cfg;
    e->ports = *ports;
    e->incarnation = incarnation;
    size_t l2 = 33;
    if (!secp256k1_keypair_create(cfg->ctx, &e->factory_kp, cfg->factory_secret) ||
        !secp256k1_keypair_create(cfg->ctx, &e->contribution_kp, cfg->contribution_secret) ||
        !secp256k1_keypair_pub(cfg->ctx, &e->factory_pk, &e->factory_kp) ||
        !secp256k1_ec_pubkey_serialize(cfg->ctx, e->factory_key, &l, &e->factory_pk, SECP256K1_EC_COMPRESSED) ||
        !secp256k1_keypair_pub(cfg->ctx, &cpk, &e->contribution_kp) ||
        !secp256k1_ec_pubkey_serialize(cfg->ctx, e->contribution_key, &l2, &cpk, SECP256K1_EC_COMPRESSED)) {
        gz_sign_wipe(e);
        return GZ_ERR_ARGUMENT;
    }
    e->failed = 0;                                  /* fresh: nothing to rebuild yet */
    return GZ_OK;
}

gz_status_t gz_sign_handle(gz_sign_t *e, const gz_event_t *ev, gz_action_list_t *out)
{
    size_t count, used;
    emit_t em;
    gz_sign_msg_t m;
    if (!e || !ev || !out) return GZ_ERR_ARGUMENT;
    if (e->failed) return GZ_ERR_FAILED;
    count = out->count; used = out->used;
    em.out = out; em.st = GZ_OK;
    if (ev->kind == GZ_EVENT_MESSAGE_RECEIVED) {
        const uint8_t *b = ev->u.message.bytes.data;
        size_t len = ev->u.message.bytes.len;
        if (!b || !gz_sign_decode(b, len, &m)) e->counters[GZ_SIGN_COUNT_REJECTED]++;   /* RULE:DECODE_FIRST */
        else if (e->cfg.host) host_message(e, ev->u.message.peer_id, &m, &em);
        else member_message(e, ev->u.message.peer_id, &m, b, len, &em);
    } else if (ev->kind == GZ_EVENT_TIMER_FIRED && ev->u.timer.timer_id == TIMER_ID) {
        e->tick++;
        for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) {
            gz_sign_round_t *r = &e->rounds[i];
            if (r->state == GZ_SIGN_ROUND_FREE) continue;
            if (e->cfg.host) { host_tick(e, r, &em); continue; }
            r->ticks++;
            if (r->state == GZ_SIGN_ROUND_ACTIVE && r->tier_state[r->tier] == GZ_SIGN_TIER_NONCES && r->ticks >= e->cfg.deadline_ticks)
                member_fail(e, r, GZ_SIGN_WHY_DEADLINE, &em);
            else if (e->cfg.resend_ticks && r->ticks % e->cfg.resend_ticks == 0) member_resend(e, r, &em);
        }
        emit_timer(e, &em);
    } else if (ev->kind == GZ_EVENT_PEER_CONNECTED && !e->cfg.host) {
        for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++)
            if (e->rounds[i].state != GZ_SIGN_ROUND_FREE && host_peer(&e->rounds[i]) == ev->u.peer.peer_id)
                member_resend(e, &e->rounds[i], &em);
    }
    if (em.st != GZ_OK) { out->count = count; out->used = used; return fail_engine(e, em.st); }
    return GZ_OK;
}

gz_status_t gz_sign_begin(gz_sign_t *e, const gz_sign_begin_t *b, gz_action_list_t *out)
{
    size_t count, used;
    emit_t em;
    gz_status_t st;
    if (!e || !out || !b || !e->cfg.host) return GZ_ERR_ARGUMENT;
    count = out->count; used = out->used;
    em.out = out; em.st = GZ_OK;
    if (e->failed) return GZ_ERR_FAILED;
    e->n_restarted = 0;                             /* the program's begin: a new lobby (F4) */
    st = host_begin(e, b, &em);
    /* A refusal before anything changed is GZ_ERR_ARGUMENT; an emit failure fails the engine. */
    if (st == GZ_OK && em.st != GZ_OK) { out->count = count; out->used = used; return fail_engine(e, em.st); }
    if (st != GZ_OK) { out->count = count; out->used = used; if (em.st != GZ_OK || st == GZ_ERR_NO_SPACE) return fail_engine(e, st); }
    return st;
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
    wipe_secrets(&e->pending);
    wipe(e->cfg.factory_secret, 32);
    wipe(e->cfg.contribution_secret, 32);
    wipe(&e->factory_kp, sizeof e->factory_kp);
    wipe(&e->contribution_kp, sizeof e->contribution_kp);
}
