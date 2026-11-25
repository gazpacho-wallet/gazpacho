/* White-box tests of the engine's guards that no input through the public
 * calls reaches: the engine's own source is compiled into this test, so a
 * guard can be handed the state it exists for.
 *
 * The rule-removed runs (tools/signing-mutants.py) found five rules whose
 * removal no test through the public interface detects, and each is
 * equivalent there:
 *   S2_ONE_NONCE    make_nonce runs once per item: a tier begins once
 *                   (member_begin_tier from the proposal and from a verified
 *                   result, host_begin_tier once per tier), and a restarted
 *                   round in the nonce phase is failed, never begun again.
 *   S2_ONE_PARTIAL  sign_item runs once per item: a member's only from
 *                   member_all_nonces in the nonce phase (a second nonce set
 *                   finds the tier Signed), the host's from host_combine once
 *                   per tier. The library also refuses a second signature
 *                   (it zeroes the secret nonce when it signs).
 *   NO_UNSET_SLOT   make_session runs only when every slot is filled: the
 *                   host after members_missing is empty and its own nonce is
 *                   made, a member after it filled every slot itself.
 *   HOST_VERIFY_FINAL  every partial signature was verified against the
 *                   session, so by MuSig2's correctness their aggregate is a
 *                   valid signature on the digest and key the item names.
 *   WIPE_AFTER_SIGN the library zeroes the secret nonce whatever the outcome
 *                   once it is called; when make_session fails first, the
 *                   caller fails the round, and wipe_secrets erases every
 *                   secret nonce of it within the same event.
 * Each guard is the line that holds if an earlier one is ever wrong; here
 * each is handed exactly the state it guards against, so removing it fails a
 * check. Step 3's checks of a definition added three more such lines
 * (FUNDING_MATCH, SCRIPT_MATCH, DUPLICATE_SIGNERS): see test_definition_lines. */
#include "../../core/signing/signing.c"
#include "world.h"
#include "../check.h"
#include "harness.h"

/* Index of the first queued message from -> to of `kind`, or -1. */
static long q_find(const harness_t *h, uint32_t from, uint32_t to, uint8_t kind)
{
    for (size_t i = 0; i < h->nq; i++)
        if (h->q[i].from == from && h->q[i].to == to && h_kind_of(h->q[i].b, h->q[i].len) == kind) return (long)i;
    return -1;
}

static gz_sign_round_t *round_of(harness_t *h, uint32_t g)
{
    gz_sign_round_t *best = NULL;
    for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
        gz_sign_round_t *r = &h->p[g].e->rounds[k];
        if (r->state != GZ_SIGN_ROUND_FREE && (!best || r->seq > best->seq)) best = r;
    }
    return best;
}

/* The first item party g signs in tier 0, and its position. */
static int item_of(const gz_sign_round_t *r, uint8_t g, int *pos)
{
    for (int i = 0; i < r->def.n_items; i++) {
        int s = pos_of(&r->def.items[i], g);
        if (r->def.items[i].tier == 0 && s >= 0) { *pos = s; return i; }
    }
    return -1;
}

static int all_zero(const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

static void deliver_until_sent(harness_t *h, uint32_t from, uint8_t kind)
{
    while (h->nq && h_count_kind(h, from, kind) == 0) h_deliver(h, 0, 0);
}

/* S2_ONE_NONCE: a second nonce for an item whose nonce exists is refused,
 * whether the secret is still held or only the slot is filled. */
static void test_one_nonce(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    deliver_until_sent(&h, 1, GZ_SIGN_MSG_NONCES);
    gz_sign_round_t *r = round_of(&h, 1);
    int s, i = r ? item_of(r, 1, &s) : -1;
    CHECK(r && i >= 0 && r->secnonce_serial[i] && (r->have_nonce[i] >> s & 1u));
    if (r && i >= 0) {
        uint8_t nonce[66], sn[132];
        uint64_t made = h.p[1].e->counters[GZ_SIGN_COUNT_NONCES_MADE], serial = r->secnonce_serial[i];
        /* The engine gives its keys back after each step (P4.3); hand them over again, so that the only
         * line left between a second call and a second nonce is this rule's. */
        int took = 0;
        CHECK(hold_keys(h.p[1].e, r, 1, &took) && h.p[1].e->keys_held == KEYS_BOTH);
        memcpy(nonce, r->nonce[i][s], 66); memcpy(sn, r->secnonce[i].data, 132);
        CHECK(make_nonce(h.p[1].e, r, i) == 0);                          /* secret held, slot filled */
        CHECK(memcmp(nonce, r->nonce[i][s], 66) == 0 && memcmp(sn, r->secnonce[i].data, 132) == 0);
        CHECK(r->secnonce_serial[i] == serial && h.p[1].e->counters[GZ_SIGN_COUNT_NONCES_MADE] == made);
        r->secnonce_serial[i] = 0;                                        /* the secret gone, the slot filled */
        CHECK(make_nonce(h.p[1].e, r, i) == 0 && memcmp(nonce, r->nonce[i][s], 66) == 0);
        r->secnonce_serial[i] = serial;
        r->have_nonce[i] &= ~bit((unsigned)s);                           /* the slot empty, the secret held */
        CHECK(make_nonce(h.p[1].e, r, i) == 0 && memcmp(sn, r->secnonce[i].data, 132) == 0);
        r->have_nonce[i] |= bit((unsigned)s);
        CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_NONCES_MADE] == made);
        put_keys(h.p[1].e, took);
    }
    h_free(&h);
}

/* S2_ONE_PARTIAL: no second partial signature for an item: none without a
 * secret nonce, none for a filled slot; the library is never handed a spent
 * secret (its illegal-argument callback would count). */
static void test_one_partial(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    deliver_until_sent(&h, 1, GZ_SIGN_MSG_PARTIALS);
    gz_sign_round_t *r = round_of(&h, 1);
    int s, i = r ? item_of(r, 1, &s) : -1;
    CHECK(r && i >= 0 && (r->have_psig[i] >> s & 1u) && !r->secnonce_serial[i]);
    if (r && i >= 0) {
        uint8_t out[32], psig[32];
        int illegal = g_illegal;
        uint64_t made = h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE];
        int took = 0;
        memcpy(psig, r->psig[i][s], 32);
        /* As in test_one_nonce: the keys held, so that only this rule stands in the way. */
        CHECK(hold_keys(h.p[1].e, r, 1, &took) && h.p[1].e->keys_held == KEYS_BOTH);
        CHECK(sign_item(h.p[1].e, r, i, out) == 0);                      /* no secret nonce */
        r->secnonce_serial[i] = 77;                                       /* a serial, the slot filled */
        CHECK(sign_item(h.p[1].e, r, i, out) == 0);
        CHECK(g_illegal == illegal && memcmp(psig, r->psig[i][s], 32) == 0);
        CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE] == made);
        r->secnonce_serial[i] = 0;
        r->have_psig[i] &= ~bit((unsigned)s);                            /* no secret, the slot empty (review B, L5) */
        CHECK(sign_item(h.p[1].e, r, i, out) == 0 && g_illegal == illegal && memcmp(psig, r->psig[i][s], 32) == 0);
        CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE] == made);
        r->have_psig[i] |= bit((unsigned)s);
        put_keys(h.p[1].e, took);
    }
    h_free(&h);
}

/* NO_UNSET_SLOT: a session is never made from an unset slot, even one whose
 * bytes are a valid nonce (left there, say, by an earlier use). */
static void test_no_unset_slot(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (h.nq && h_newest(&h, 0)->tier_state[0] != GZ_SIGN_TIER_SIGNED) h_deliver(&h, 0, 0);
    gz_sign_round_t *r = round_of(&h, 0);
    int s, i = r ? item_of(r, 2, &s) : -1;
    CHECK(r && i >= 0 && r->have_nonce[i] == all_bits(&r->def.items[i]));
    if (r && i >= 0) {
        int illegal = g_illegal;
        r->have_nonce[i] &= ~bit((unsigned)s);                           /* member 2's slot unset, its bytes valid */
        CHECK(make_session(h.p[0].e, r, i) == 0);
        r->have_nonce[i] |= bit((unsigned)s);
        CHECK(make_session(h.p[0].e, r, i) == 1 && g_illegal == illegal); /* the control */
    }
    h_free(&h);
}

/* HOST_VERIFY_FINAL: a combined signature that does not verify from the
 * transaction's bytes is never sent. Here the item's spent amount differs
 * from the one its session signed (an engine or library defect stands in). */
static void test_host_verify_final(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    /* deliver until only member 3's partial signatures are missing at the host */
    while (h.nq) {
        long k = q_find(&h, 3, 0, GZ_SIGN_MSG_PARTIALS);
        if (k >= 0) break;
        h_deliver(&h, 0, 0);
    }
    long k = q_find(&h, 3, 0, GZ_SIGN_MSG_PARTIALS);
    gz_sign_round_t *r = round_of(&h, 0);
    CHECK(k >= 0 && r && r->tier_state[0] == GZ_SIGN_TIER_SIGNED);
    while (h.nq) {                                                        /* everything else first */
        size_t j = 0;
        while (j < h.nq && h.q[j].from == 3 && h.q[j].to == 0) j++;
        if (j == h.nq) break;
        h_deliver(&h, j, 0);
    }
    if (k >= 0 && r) {
        size_t results = h_count_kind(&h, 0, GZ_SIGN_MSG_RESULT);
        r->def.items[0].spent_amount++;
        h_deliver(&h, (size_t)q_find(&h, 3, 0, GZ_SIGN_MSG_PARTIALS), 0);
        CHECK(r->state == GZ_SIGN_ROUND_FAILED && r->why == GZ_SIGN_WHY_BAD_RESULT);
        CHECK(h_count_kind(&h, 0, GZ_SIGN_MSG_RESULT) == results);
    }
    h_free(&h);
}

/* WIPE_AFTER_SIGN: when signing fails before the library is called (the
 * session cannot be made), the secret nonce is erased there and then. */
static void test_wipe_after_sign(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    deliver_until_sent(&h, 1, GZ_SIGN_MSG_NONCES);
    gz_sign_round_t *r = round_of(&h, 1);
    int s, i = r ? item_of(r, 1, &s) : -1;
    CHECK(r && i >= 0 && r->secnonce_serial[i] && !all_zero(r->secnonce[i].data, 132));
    if (r && i >= 0) {
        uint8_t out[32];
        int illegal = g_illegal;
        /* the member's own slot is its only one filled: make_session refuses */
        CHECK(sign_item(h.p[1].e, r, i, out) == 0);
        CHECK(all_zero(r->secnonce[i].data, sizeof r->secnonce[i]) && r->secnonce_serial[i] == 0 && g_illegal == illegal);
    }
    h_free(&h);
}

/* The P2TR output of item `it`'s signers in the order listed, tweaked as the engine tweaks them. */
static void script_for(const gz_sign_def_t *d, const gz_sign_item_t *it, uint8_t out[34])
{
    secp256k1_pubkey pks[GZ_SIGN_MAX_SIGNERS], tw;
    const secp256k1_pubkey *ptr[GZ_SIGN_MAX_SIGNERS];
    secp256k1_xonly_pubkey agg, x;
    secp256k1_musig_keyagg_cache c;
    uint8_t ser[32], t32[32];
    for (int k = 0; k < it->n_signers; k++) {
        CHECK(secp256k1_ec_pubkey_parse(w_ctx(), &pks[k], d->participants[it->signers[k]].factory_key, 33));
        ptr[k] = &pks[k];
    }
    CHECK(secp256k1_musig_pubkey_agg(w_ctx(), NULL, &agg, &c, ptr, it->n_signers) && secp256k1_xonly_pubkey_serialize(w_ctx(), ser, &agg));
    tagged("TapTweak", ser, 32, it->merkle_root, it->has_merkle_root ? 32 : 0, t32);
    CHECK(secp256k1_musig_pubkey_xonly_tweak_add(w_ctx(), &tw, &c, t32) && secp256k1_xonly_pubkey_from_pubkey(w_ctx(), &x, NULL, &tw));
    out[0] = 0x51; out[1] = 0x20;
    CHECK(secp256k1_xonly_pubkey_serialize(w_ctx(), out + 2, &x));
}

/* Three more of check_def's lines are second lines behind others through any
 * tree whose outputs are consistent (each item spends exactly what its parent
 * or the funding pays): FUNDING_MATCH (the root's amount and script are the
 * funding's), SCRIPT_MATCH (an item's script is its signers' aggregate) and
 * DUPLICATE_SIGNERS (signers strictly increasing). Each is handed a
 * definition that only it refuses. */
static void test_definition_lines(void)
{
    harness_t h;
    static gz_sign_def_t d;
    static gz_sign_round_t scratch;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    gz_sign_round_t *r = round_of(&h, 0);
    gz_sign_t *e = h.p[0].e;
    CHECK(r && r->def.items[0].n_signers == 4);
    if (r && r->def.items[0].n_signers == 4) {
        CHECK(take_keys(e, r->def.outer_digest, r->def.terms_digest, 1));            /* the host's own keys, as at begin */
        d = r->def;
        CHECK(check_def(e, &d, &scratch) == GZ_SIGN_WHY_NONE);                     /* the control */
        /* FUNDING_MATCH: the root spends the funding with another amount (nothing else looks) */
        d = r->def; d.items[0].spent_amount++;
        CHECK(check_def(e, &d, &scratch) == GZ_SIGN_WHY_INVALID_ROUND);
        /* SCRIPT_MATCH: the root's script and the funding's agree, and are not the signers' aggregate */
        d = r->def; d.items[0].spent_script[5] ^= 1; d.funding_script[5] ^= 1;
        CHECK(check_def(e, &d, &scratch) == GZ_SIGN_WHY_INVALID_ROUND);
        /* DUPLICATE_SIGNERS: the root's members out of order, and twice, each with the script and the
         * funding made to match that list: only the order refuses it */
        d = r->def;
        d.items[0].signers[1] = r->def.items[0].signers[2]; d.items[0].signers[2] = r->def.items[0].signers[1];
        script_for(&d, &d.items[0], d.items[0].spent_script); memcpy(d.funding_script, d.items[0].spent_script, 34);
        CHECK(check_def(e, &d, &scratch) == GZ_SIGN_WHY_INVALID_ROUND);
        d = r->def;
        d.items[0].signers[2] = d.items[0].signers[1];
        script_for(&d, &d.items[0], d.items[0].spent_script); memcpy(d.funding_script, d.items[0].spent_script, 34);
        CHECK(check_def(e, &d, &scratch) == GZ_SIGN_WHY_INVALID_ROUND);
        drop_keys(e);
    }
    wipe_secrets(&scratch);
    h_free(&h);
}

/* The masks at their width: 32 participants. */
static void test_masks(void)
{
    gz_sign_item_t it;
    memset(&it, 0, sizeof it);
    CHECK(mask_n(0) == 0 && mask_n(1) == 1 && mask_n(31) == 0x7fffffffu && mask_n(32) == 0xffffffffu);
    CHECK(bit(31) == 0x80000000u);
    it.n_signers = 32;
    CHECK(all_bits(&it) == 0xffffffffu);
}

/* ---- review A ---- */

static size_t count_recs(const harness_t *h, uint32_t g, uint32_t type)
{
    size_t n = 0;
    for (size_t i = 0; i < h->p[g].n_recs; i++) n += h->p[g].recs[i].type == type;
    return n;
}

/* Messages of `kind` that party g sent for round `id`. */
static size_t sent_for(const harness_t *h, uint32_t g, uint8_t kind, const uint8_t id[32])
{
    size_t n = 0;
    for (size_t i = 0; i < h->n_sent; i++) {
        const h_sent_t *s = &h->sent[i];
        if (s->party == g && s->kind == kind && s->len >= GZ_RMSG_HEADER + 34 && !memcmp(s->b + GZ_RMSG_HEADER + 2, id, 32)) n++;
    }
    return n;
}

/* Every round_partial_sigs party g ever sent belongs to a round with an exposure record in its journal (C7). */
static int partials_all_exposed(const harness_t *h, uint32_t g)
{
    for (size_t i = 0; i < h->n_sent; i++) {
        const h_sent_t *s = &h->sent[i];
        int found = 0;
        if (s->party != g || s->kind != GZ_SIGN_MSG_PARTIALS || s->len < GZ_RMSG_HEADER + 34) continue;
        for (size_t k = 0; k < h->p[g].n_recs && !found; k++) {
            const h_rec_t *rec = &h->p[g].recs[k];
            found = rec->type == GZ_SIGN_REC_EXPOSURE && rec->len >= 34 && rec->b[0] == 2 && rec->b[1] == 32 &&
                    !memcmp(rec->b + 2, s->b + GZ_RMSG_HEADER + 2, 32);
        }
        if (!found) return 0;
    }
    return 1;
}

/* F1 (review A's probes nospace-*): a round_all_nonces handled with an action
 * list too short for the exposure batch. The engine is failed: given the
 * same event again with room (retry), or a reconnect, it sends nothing; after
 * a restart no partial signature has left without its exposure record. */
static void test_nospace_exposure(void)
{
    harness_t h;
    static gz_action_t slots[8];
    static uint8_t bytes[256];
    gz_action_list_t small;
    gz_event_t ev;
    uint8_t id[32];
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (h.nq && q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
    long k = q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES);
    gz_sign_round_t *r = round_of(&h, 1);
    CHECK(k >= 0 && r != NULL);
    if (k < 0 || !r) { h_free(&h); return; }
    memcpy(id, r->id, 32);
    gz_action_list_init(&small, slots, 8, bytes, sizeof bytes);
    CHECK(w_msg_event(&h.builder, 0, 1, h.q[k].b, h.q[k].len, &ev));
    CHECK(gz_sign_handle(h.p[1].e, &ev, &small) == GZ_ERR_NO_SPACE && small.count == 0 && small.used == 0);
    CHECK(h.p[1].e->failed && h.p[1].e->n_exposures == 0);
    /* retry: the same event with room */
    CHECK(h_deliver(&h, (size_t)k, 1) == GZ_ERR_FAILED);
    CHECK(sent_for(&h, 1, GZ_SIGN_MSG_PARTIALS, id) == 0 && count_recs(&h, 1, GZ_SIGN_REC_EXPOSURE) == 0);
    /* reconnect */
    CHECK(h_connect(&h, 1, 0) == GZ_ERR_FAILED);
    CHECK(sent_for(&h, 1, GZ_SIGN_MSG_PARTIALS, id) == 0);
    /* restart: built from the journal, which holds no exposure; the round was in the nonce phase */
    CHECK(h_restart(&h, 1) == GZ_OK && !h.p[1].e->failed && h.p[1].e->n_exposures == 0);
    CHECK(h_find(&h, 1, id) && h_find(&h, 1, id)->state == GZ_SIGN_ROUND_ABORTED && !h_find(&h, 1, id)->ever_partial);
    h_deliver(&h, (size_t)k, 0);                                    /* the old all_nonces now: refused */
    CHECK(sent_for(&h, 1, GZ_SIGN_MSG_PARTIALS, id) == 0);
    h_flush(&h, 100000);
    for (uint32_t g = 1; g <= 3; g++) CHECK(partials_all_exposed(&h, g));
    h_free(&h);
}

/* F1: an action list one slot short at every step of a two-tier round, each
 * party in turn. Whatever the step, the engine is failed until a start, and
 * no partial signature ever leaves without its exposure record. */
static void test_short_lists(void)
{
    static gz_action_t slots[1];
    static uint8_t bytes[64];
    size_t steps = 0, failed = 0;
    for (int at = 0; at < 60; at++) {
        harness_t h;
        gz_action_list_t small;
        h_init(&h, 3);
        CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
        for (int s = 0; s < at && h.nq; s++) h_deliver(&h, 0, 0);
        if (h.nq) {
            h_msg_t m = h.q[0];
            gz_event_t ev;
            if (!w_msg_event(&h.builder, m.from, m.to, m.b, m.len, &ev)) abort();
            gz_action_list_init(&small, slots, 1, bytes, sizeof bytes);
            gz_status_t st = gz_sign_handle(h.p[m.to].e, &ev, &small);
            steps++;
            if (st != GZ_OK) {
                failed++;
                CHECK(small.count == 0 && small.used == 0 && h.p[m.to].e->failed);
                CHECK(h_deliver(&h, 0, 1) == GZ_ERR_FAILED);          /* again, with room: still refused */
                CHECK(h_restart(&h, m.to) == GZ_OK);
            }
        }
        h_flush(&h, 100000);
        h_ticks(&h, 40);
        for (uint32_t g = 1; g <= 3; g++) CHECK(partials_all_exposed(&h, g));
        h_free(&h);
    }
    printf("  short lists: %zu steps, %zu refused for room\n", steps, failed);
    CHECK(failed > 10);
}

/* F3 (review A's probe evict-unresolved): a Complete round pushed out of memory
 * by later rounds is still unresolved for C10, across a restart, and still
 * reachable by gz_sign_resolve. */
static void test_evicted_unresolved(void)
{
    harness_t h;
    gz_action_list_t list;
    uint8_t a[32], c[32];
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    h_flush(&h, 100000);
    const gz_sign_round_t *ra = h_newest(&h, 1);
    CHECK(ra && ra->state == GZ_SIGN_ROUND_COMPLETE);
    if (!ra) { h_free(&h); return; }
    memcpy(a, ra->id, 32);
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++) { CHECK(h_begin(&h, 1, 3, 0) == GZ_OK); h_flush(&h, 100000); }
    CHECK(h_find(&h, 1, a) == NULL && evicted(h.p[1].e, a) && evicted(h.p[1].e, a)->state == GZ_SIGN_ROUND_COMPLETE);
    CHECK(unresolved(h.p[1].e) == GZ_SIGN_MAX_ROUNDS + 1);
    for (int pass = 0; pass < 2; pass++) {                          /* before and after a restart */
        CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);           /* the same tree on A's outpoint: C10 refuses */
        memcpy(c, h_newest(&h, 0)->id, 32);
        h_flush(&h, 100000);
        CHECK(sent_for(&h, 1, GZ_SIGN_MSG_PARTIALS, c) == 0);
        if (pass == 0) CHECK(h_restart(&h, 1) == GZ_OK && evicted(h.p[1].e, a) && evicted(h.p[1].e, a)->state == GZ_SIGN_ROUND_COMPLETE);
    }
    /* resolve reaches it, and the outcome is kept across a restart */
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    CHECK(gz_sign_resolve(h.p[1].e, a, GZ_SIGN_END_LIVE, &list) == GZ_OK && list.count == 1);
    h_apply(&h, 1, &list);
    CHECK(evicted(h.p[1].e, a)->state == GZ_SIGN_ROUND_LIVE);
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    CHECK(gz_sign_resolve(h.p[1].e, a, GZ_SIGN_END_DEAD, &list) == GZ_OK && list.count == 0);   /* Live is final: a counted no-op (8.1) */
    CHECK(evicted(h.p[1].e, a)->state == GZ_SIGN_ROUND_LIVE);
    CHECK(h_restart(&h, 1) == GZ_OK && evicted(h.p[1].e, a) && evicted(h.p[1].e, a)->state == GZ_SIGN_ROUND_LIVE);
    h_free(&h);
    /* the control: without the eviction the second round on the outpoint is refused the same way */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    h_flush(&h, 100000);
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    memcpy(c, h_newest(&h, 0)->id, 32);
    h_flush(&h, 100000);
    CHECK(sent_for(&h, 1, GZ_SIGN_MSG_PARTIALS, c) == 0);
    h_free(&h);
}

/* F2: when the C7 set has no room (here: a start found more records than
 * fit), every new round is refused with reason 9 before any nonce, never
 * signed with an exposure dropped. */
static void test_exposure_room(void)
{
    harness_t h;
    uint8_t z[32] = {1};
    h_init(&h, 3);
    gz_sign_t *e1 = h.p[1].e;
    size_t n0 = e1->n_exposures;
    e1->n_exposures = GZ_SIGN_MAX_EXPOSURES;                        /* as if full */
    CHECK(add_exposure(e1, z, 0, z, z) == 0 && e1->exposures_lost);  /* not dropped silently */
    e1->n_exposures = n0;
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    long k = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(k >= 0);
    size_t nonces = h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES), sent = h.n_sent;
    if (k >= 0) h_deliver(&h, (size_t)k, 0);
    gz_sign_msg_t m;
    CHECK(h.n_sent == sent + 1 && gz_sign_decode(h.sent[sent].b, h.sent[sent].len, &m) && m.kind == GZ_SIGN_MSG_ABORT && m.reason == 9);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == nonces && h.p[1].e->n_exposures == 0);
    h_free(&h);
    /* and when the room goes between the proposal and the nonce set: no partial signature */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (h.nq && q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
    k = q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES);
    CHECK(k >= 0);
    h.p[1].e->exposures_lost = 1;
    if (k >= 0) h_deliver(&h, (size_t)k, 0);
    gz_sign_round_t *r = round_of(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_ABORTED && r->why == GZ_SIGN_WHY_CAPACITY && !r->ever_partial);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == 0 && h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE] == 0);
    h_free(&h);
}

/* Review A, N10 (the secret nonce wiped after a failed nonce_gen) stays
 * equivalent against the pinned library: secp256k1_musig_nonce_gen zeroes
 * the secret nonce on entry and invalidates it on failure, and serialising
 * the public nonce it has just made cannot fail. The engine's wipe is the
 * line that holds if either ever changes. */

/* Review A, N09: the nonce's secret inputs (the session randomness, the
 * session id and its preimage) are wiped once the nonce is made, in every
 * party, whatever round it made them for. */
static void test_nonce_inputs_wiped(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
    for (int step = 0; h.nq && step < 100000; step++) {
        h_deliver(&h, 0, 0);
        for (uint32_t g = 0; g < h.n; g++) {
            const gz_sign_t *e = h.p[g].e;
            CHECK(all_zero(e->work_rnd, sizeof e->work_rnd) && all_zero(e->work_sid, sizeof e->work_sid) &&
                  all_zero(e->work_pre, sizeof e->work_pre));
        }
    }
    CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_NONCES_MADE] > 0);
    h_free(&h);
}

/* Review A, A06: a round_all_nonces entry that names an item of another tier
 * (one the member signs, with as many signers) is refused as a bad message,
 * before any nonce signature is looked at. */
static void test_all_nonces_other_tier(void)
{
    harness_t h;
    static uint8_t b[GZ_SIGN_MAX_MSG];
    gz_sign_msg_t m;
    h_init(&h, 3);
    CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
    while (h.nq && q_find(&h, 0, 2, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
    long k = q_find(&h, 0, 2, GZ_SIGN_MSG_ALL_NONCES);
    gz_sign_round_t *r = round_of(&h, 2);          /* member 2: items as wide in both tiers */
    CHECK(k >= 0 && r != NULL);
    if (k < 0 || !r) { h_free(&h); return; }
    size_t len = h.q[k].len;
    memcpy(b, h.q[k].b, len);
    CHECK(gz_sign_decode(b, len, &m) && m.n >= 1 && m.tier == 0);
    uint8_t *e0 = NULL;
    uint32_t x = 0xffffffffu;
    for (int q = 0; q < m.n && x == 0xffffffffu; q++) {                /* an entry, and a tier-1 item of the member's as wide */
        e0 = (uint8_t *)(uintptr_t)m.entry[q];
        for (uint32_t i = 0; i < r->def.n_items && x == 0xffffffffu; i++)
            if (r->def.items[i].tier == 1 && pos_of(&r->def.items[i], r->me) >= 0 && r->def.items[i].n_signers == r->def.items[be32(e0)].n_signers) x = i;
    }
    CHECK(x != 0xffffffffu);
    if (x == 0xffffffffu) { h_free(&h); return; }
    wr32(e0, x);
    w_resign(b, len, 0);
    h_drop_msg(&h, (size_t)k);
    h_inject(&h, 0, 2, b, len);
    CHECK(r->state == GZ_SIGN_ROUND_ABORTED && r->why == GZ_SIGN_WHY_BAD_MESSAGE);
    CHECK(h.p[2].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE] == 0);
    h_free(&h);
}

/* RULE:DECODE_FIRST: a message is decoded whole before anything reads it. A
 * round_all_nonces with one byte after its signature does not decode (240
 * is last, messages.md 4.2), even though every record before it would: the
 * member counts it refused and signs nothing. */
static void test_decode_first(void)
{
    harness_t h;
    static uint8_t b[GZ_SIGN_MAX_MSG + 1];
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (h.nq && q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
    long k = q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES);
    CHECK(k >= 0);
    if (k < 0) { h_free(&h); return; }
    size_t len = h.q[k].len;
    memcpy(b, h.q[k].b, len);
    b[len] = 0;
    uint64_t rejected = h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED];
    size_t sent = h.n_sent;
    h_inject(&h, 0, 1, b, len + 1);
    CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == rejected + 1 && h.n_sent == sent);
    CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE] == 0);
    h_deliver(&h, (size_t)k, 0);                                    /* the bytes as sent: signed */
    CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE] > 0);
    h_free(&h);
}

/* ---- review B ---- */

static size_t live_secrets(const gz_sign_t *e)
{
    size_t n = 0;
    for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++)
        for (int i = 0; i < GZ_SIGN_MAX_ITEMS; i++) n += e->rounds[k].secnonce_serial[i] != 0 || !all_zero(&e->rounds[k].secnonce[i], sizeof e->rounds[k].secnonce[i]);
    for (int i = 0; i < GZ_SIGN_MAX_ITEMS; i++) n += e->pending.secnonce_serial[i] != 0 || !all_zero(&e->pending.secnonce[i], sizeof e->pending.secnonce[i]);
    return n;
}

/* B1 (the reviewer's probe P13): a member pads its round_ack with an unknown
 * odd record under its own signature. Up to the size its record's field
 * takes, the ack is taken, saved, and read back by the next start. One byte
 * longer, and at 374 and 3,176 bytes, it is counted and dropped: nothing is
 * saved, the call succeeds, the engine is not failed, the next start
 * succeeds, and the member's plain ack still completes the round. */
static void test_padded_ack(void)
{
    static const size_t pads[] = {0, 59, 60, 200, 3000};
    static uint8_t ack[GZ_SIGN_MAX_SMALL_MSG], big[4096];
    for (size_t pi = 0; pi < sizeof pads / sizeof pads[0]; pi++) {
        harness_t h;
        size_t alen = 0, len;
        h_init(&h, 1);
        CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
        while (h.nq) {
            if (h.q[0].from == 1 && h_kind_of(h.q[0].b, h.q[0].len) == GZ_SIGN_MSG_ACK) {
                if (!alen && h.q[0].len <= sizeof ack) { alen = h.q[0].len; memcpy(ack, h.q[0].b, alen); }
                h_drop_msg(&h, 0);
                continue;
            }
            h_deliver(&h, 0, 0);
        }
        CHECK(alen == 172);
        if (!alen) { h_free(&h); continue; }
        len = w_pad(ack, alen, pads[pi], 1, big);
        gz_sign_msg_t m;
        CHECK(gz_sign_decode(big, len, &m) && m.kind == GZ_SIGN_MSG_ACK);          /* a valid message of the codec */
        int fits = len <= GZ_SIGN_MAX_SMALL_MSG;
        CHECK(fits == (pi < 2) && (pi != 1 || len == GZ_SIGN_MAX_SMALL_MSG) && (pi != 2 || len == GZ_SIGN_MAX_SMALL_MSG + 1) &&
              (pi != 3 || len == 374) && (pi != 4 || len == 3176));
        size_t recs = h.p[0].n_recs;
        uint64_t rejected = h.p[0].e->counters[GZ_SIGN_COUNT_REJECTED];
        CHECK(h_inject(&h, 1, 0, big, len) == GZ_OK && !h.p[0].e->failed);
        const gz_sign_round_t *r = h_newest(&h, 0);
        CHECK(r != NULL);
        if (!r) { h_free(&h); continue; }
        if (fits) {
            CHECK(r->acked == 2u && r->state == GZ_SIGN_ROUND_DONE && h.p[0].n_recs == recs + 1);
            CHECK(h.p[0].recs[recs].type == GZ_SIGN_REC_ACK_RECEIVED && h.p[0].recs[recs].len <= GZ_SIGN_REC_ACK_MAX);
        } else {
            CHECK(r->acked == 0 && r->state == GZ_SIGN_ROUND_COMPLETE && h.p[0].n_recs == recs);
            CHECK(h.p[0].e->counters[GZ_SIGN_COUNT_REJECTED] == rejected + 1);
        }
        CHECK(h_restart(&h, 0) == GZ_OK && !h.p[0].e->failed);                     /* a saved record is always loadable */
        r = h_newest(&h, 0);
        CHECK(r && r->state == (fits ? GZ_SIGN_ROUND_DONE : GZ_SIGN_ROUND_COMPLETE));
        if (!fits) {
            CHECK(h_inject(&h, 1, 0, ack, alen) == GZ_OK);
            CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE && h_restart(&h, 0) == GZ_OK && h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
        }
        CHECK(h.errors == 0);
        h_free(&h);
    }
}

/* B2 (probe P1): a proposal padded by the host up to the engine's limit is
 * taken, saved and read back by the next start; one byte past the limit it
 * is refused with reason 9 before anything is made or saved. Never an error. */
static void test_padded_proposal(void)
{
    static const int less[] = {0, 1, 20, 38, 39, 600, -1};
    static uint8_t b[GZ_SIGN_MAX_PROPOSAL + 16];
    for (size_t di = 0; di < sizeof less / sizeof less[0]; di++) {
        harness_t h;
        h_init(&h, 1);
        CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
        long qi = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
        CHECK(qi >= 0);
        if (qi < 0) { h_free(&h); continue; }
        size_t want = (size_t)((int)GZ_SIGN_MAX_PROPOSAL - less[di]);
        size_t len = w_pad(h.q[qi].b, h.q[qi].len, want - h.q[qi].len - 4, 0, b);
        CHECK(len == want);
        h_drop_msg(&h, (size_t)qi);
        size_t recs = h.p[1].n_recs, sent = h.n_sent;
        CHECK(h_inject(&h, 0, 1, b, len) == GZ_OK && !h.p[1].e->failed);
        if (less[di] >= 0) {
            const gz_sign_round_t *r = h_newest(&h, 1);
            CHECK(r && r->state == GZ_SIGN_ROUND_ACTIVE && r->proposal_len == len && h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == 1);
            CHECK(h.p[1].n_recs > recs && h.p[1].recs[recs].type == GZ_SIGN_REC_ROUND_PROPOSAL && h.p[1].recs[recs].len <= GZ_SIGN_REC_PROPOSAL_MAX);
            if (less[di] == 0) CHECK(h.p[1].recs[recs].len == GZ_SIGN_REC_PROPOSAL_MAX);
            h_flush(&h, 100000);                                                    /* and the round completes with it */
            CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE && h_newest(&h, 1)->state == GZ_SIGN_ROUND_COMPLETE);
            CHECK(h_restart(&h, 1) == GZ_OK && h_newest(&h, 1) && h_newest(&h, 1)->state == GZ_SIGN_ROUND_COMPLETE && h_newest(&h, 1)->proposal_len == len);
        } else {
            gz_sign_msg_t m;
            CHECK(h.n_sent == sent + 1 && gz_sign_decode(h.sent[sent].b, h.sent[sent].len, &m) && m.kind == GZ_SIGN_MSG_ABORT && m.reason == 9);
            CHECK(h_newest(&h, 1) == NULL && h.p[1].n_recs == recs && h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == 0);
            CHECK(h_restart(&h, 1) == GZ_OK);
        }
        CHECK(h.errors == 0);
        h_free(&h);
    }
}

static int fields_ok(const gz_rmsg_wr_t *w, const gz_rmsg_field_t *table, size_t n)
{
    gz_rmsg_got_t g[8];
    return gz_rmsg_wr_ok(w) && gz_rmsg_fields(w->p, w->n, table, n, g, NULL) == GZ_RMSG_OK;
}

/* B1, B2, B12: every record the engine saves, written by its own writer at
 * the largest size its contents can have (64 items of the party in one tier,
 * a funding transaction, a proposal and every kept message at their limits),
 * fits the work area it is written in and is accepted by the reader's table
 * of the start. One byte more does not fit the writer, so the bound is the
 * record's and not some slack. */
static void test_record_bounds(void)
{
    harness_t h;
    static gz_sign_round_t r;
    static uint8_t funding[GZ_SIGN_MAX_FUNDING_TX + 1], msg[GZ_SIGN_MAX_SMALL_MSG + 1];
    gz_rmsg_wr_t w;
    gz_action_list_t list;
    h_init(&h, 1);
    CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
    h_flush(&h, 100000);
    for (uint32_t g = 0; g < 2; g++) {
        gz_sign_t *e = h.p[g].e;
        const gz_sign_round_t *r0 = h_newest(&h, g);
        emit_t em;
        CHECK(r0 && sizeof e->work_records == GZ_SIGN_WORK_RECORDS && sizeof e->work_rec2 == GZ_SIGN_WORK_REC2);
        if (!r0) break;
        r = *r0;
        for (int i = r.def.n_items; i < GZ_SIGN_MAX_ITEMS; i++) r.def.items[i] = r.def.items[i % r0->def.n_items];
        r.def.n_items = GZ_SIGN_MAX_ITEMS; r.def.n_tiers = 1;
        CHECK(count_items(&r, r.me, 0) == GZ_SIGN_MAX_ITEMS);
        r.proposal_len = GZ_SIGN_MAX_PROPOSAL; r.proposal_saved = 0;
        r.partials_len[0] = r.result_len[0] = GZ_SIGN_MAX_LIST68_MSG;
        r.complete_len = r.tail_len = GZ_SIGN_MAX_SMALL_MSG;
        /* round_started, and round_proposal in its batch */
        started_record(e, &r, 0, &w, e->work_rec2, sizeof e->work_rec2);
        CHECK(fields_ok(&w, T_STARTED, NFIELDS(T_STARTED)) && w.n == GZ_SIGN_REC_STARTED_MAX);
        gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
        em.out = &list; em.st = GZ_OK; em.e = e;
        save_started(e, &r, 0, &em);
        CHECK(em.st == GZ_OK && list.count == 1 && list.slots[0].u.save.n_records >= 2);
        if (em.st == GZ_OK && list.count == 1) {
            const gz_record_t *rec = list.slots[0].u.save.records;
            gz_rmsg_got_t got[8];
            CHECK(rec[0].type == GZ_SIGN_REC_ROUND_PROPOSAL && rec[0].bytes.len == GZ_SIGN_REC_PROPOSAL_MAX &&
                  gz_rmsg_fields(rec[0].bytes.data, rec[0].bytes.len, T_PROPOSAL, NFIELDS(T_PROPOSAL), got, NULL) == GZ_RMSG_OK);
            CHECK(rec[1].type == GZ_SIGN_REC_ROUND_STARTED && rec[1].bytes.len == GZ_SIGN_REC_STARTED_MAX);
        }
        /* exposure (a member's) */
        CHECK(exposure_record(e, &r, 0, funding, GZ_SIGN_MAX_FUNDING_TX, &w));
        CHECK(fields_ok(&w, T_EXPOSURE, NFIELDS(T_EXPOSURE)) && w.n == GZ_SIGN_REC_EXPOSURE_MAX);
        CHECK(exposure_record(e, &r, 0, funding, GZ_SIGN_MAX_FUNDING_TX + 1, &w) && !gz_rmsg_wr_ok(&w));   /* one byte more: no room */
        /* round_signed: a member's carries its result, the host's every item */
        gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
        em.out = &list; em.st = GZ_OK; em.e = e;
        save_signed(e, &r, 0, &em);
        CHECK(em.st == GZ_OK && list.count == 1);
        if (em.st == GZ_OK && list.count == 1) {
            const gz_record_t *rec = list.slots[0].u.save.records;
            gz_rmsg_got_t got[8];
            CHECK(rec[0].bytes.len == GZ_SIGN_REC_SIGNED_MAX - (g == 0 ? GZ_SIGN_FIELD(GZ_SIGN_MAX_LIST68_MSG) : 0) &&
                  gz_rmsg_fields(rec[0].bytes.data, rec[0].bytes.len, T_SIGNED, NFIELDS(T_SIGNED), got, NULL) == GZ_RMSG_OK);
        }
        /* round_completed: a member's in the large area, the host's in the small one */
        if (g) completed_record(&r, 1, &w, e->work_records, sizeof e->work_records);
        else completed_record(&r, 0, &w, e->work_rec2, sizeof e->work_rec2);
        CHECK(fields_ok(&w, T_COMPLETED, NFIELDS(T_COMPLETED)));
        CHECK(w.n == (g ? GZ_SIGN_REC_COMPLETED_MAX : GZ_SIGN_FIELD(32u) + GZ_SIGN_FIELD(GZ_SIGN_MAX_SMALL_MSG)));
        /* ack_received (the host's) */
        ack_record(&r, 1, msg, GZ_SIGN_MAX_SMALL_MSG, &w, e->work_rec2, sizeof e->work_rec2);
        CHECK(fields_ok(&w, T_ACK, NFIELDS(T_ACK)) && w.n == GZ_SIGN_REC_ACK_MAX);
        ack_record(&r, 1, msg, GZ_SIGN_MAX_SMALL_MSG + 1, &w, e->work_rec2, sizeof e->work_rec2);
        CHECK(!fields_ok(&w, T_ACK, NFIELDS(T_ACK)));                               /* the reader's bound is the writer's */
        /* round_ended: a member's Aborted with its abort; the host's with whom it blames */
        gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
        em.out = &list; em.st = GZ_OK; em.e = e;
        save_ended_of(e, r.id, 0xffffffffu, 1, msg, GZ_SIGN_MAX_SMALL_MSG, GZ_SIGN_END_ABORTED, 9, &em);
        CHECK(em.st == GZ_OK && list.count == 1);
        if (em.st == GZ_OK && list.count == 1) {
            const gz_record_t *rec = list.slots[0].u.save.records;
            gz_rmsg_got_t got[8];
            CHECK(rec[0].bytes.len == GZ_SIGN_REC_ENDED_MAX - (g ? GZ_SIGN_FIELD(4u) : 0) &&
                  gz_rmsg_fields(rec[0].bytes.data, rec[0].bytes.len, T_ENDED, NFIELDS(T_ENDED), got, NULL) == GZ_RMSG_OK);
        }
    }
    h_free(&h);
}

/* B1's property: after any sequence of events the engine accepted, a start
 * over the journal it wrote succeeds. Here every message in flight is padded
 * by its sender with an unknown odd record of some size (signed again where
 * the message is signed), through whole rounds of one and two tiers; then
 * every party starts again. No call fails, whatever is refused. */
static void test_restart_after_padding(void)
{
    static const size_t pads[] = {0, 1, 40, 59, 60, 61, 300, 3000, 9000, 15000};
    static uint8_t b[GZ_SIGN_MAX_MSG + 16384];
    size_t rounds_done = 0, refused = 0;
    for (size_t pi = 0; pi < sizeof pads / sizeof pads[0]; pi++)
        for (uint8_t tiers = 1; tiers <= 2; tiers++)
            for (int who = 0; who < 3; who++) {             /* the host's messages, the members', or all */
                harness_t h;
                h_init(&h, 3);
                CHECK(h_begin(&h, tiers, 3, 0) == GZ_OK);
                for (int step = 0; step < 4000 && h.nq; step++) {
                    h_msg_t m = h.q[0];
                    uint8_t kind = h_kind_of(m.b, m.len);
                    int is_signed = kind != GZ_SIGN_MSG_NONCES && kind != GZ_SIGN_MSG_ALL_NONCES && kind != GZ_SIGN_MSG_STATUS;
                    if ((who == 0 && m.from != 0) || (who == 1 && m.from == 0) || m.len + pads[pi] + 8 > sizeof b) { h_deliver(&h, 0, 0); continue; }
                    size_t len = w_pad(m.b, m.len, pads[pi], is_signed ? (int)m.from : -1, b);
                    uint32_t from = m.from, to = m.to;
                    h_drop_msg(&h, 0);
                    CHECK(h_inject(&h, from, to, b, len) == GZ_OK);
                }
                h_ticks(&h, 30);                                /* deadlines, resends (unpadded), retries */
                rounds_done += h_newest(&h, 0) && h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE;
                for (uint32_t g = 0; g < h.n; g++) {
                    refused += h.p[g].e->counters[GZ_SIGN_COUNT_REJECTED];
                    CHECK(!h.p[g].e->failed);
                    CHECK(h_restart(&h, g) == GZ_OK && !h.p[g].e->failed);
                }
                h_ticks(&h, 30);
                for (uint32_t g = 0; g < h.n; g++) CHECK(h_restart(&h, g) == GZ_OK);
                CHECK(h.errors == 0);
                for (uint32_t g = 1; g < h.n; g++) CHECK(partials_all_exposed(&h, g));
                h_free(&h);
            }
    printf("  padded rounds: %zu done, %zu refusals counted\n", rounds_done, refused);
    CHECK(rounds_done > 0 && refused > 0);
}

/* Drop every queued message to `to` of kind k1 or k2, deliver the rest. */
static void flush_without(harness_t *h, uint32_t to, uint8_t k1, uint8_t k2)
{
    for (size_t guard = 0; h->nq && guard < 200000; guard++) {
        uint8_t k = h_kind_of(h->q[0].b, h->q[0].len);
        if (h->q[0].to == to && (k == k1 || k == k2)) h_drop_msg(h, 0);
        else h_deliver(h, 0, 0);
    }
}

/* B5 (probe P4): five rounds of a member, each with its partial signatures
 * sent and its result withheld. The first leaves memory Unfinished. With and
 * without a restart of the member it is still Unfinished, counted by C10,
 * reachable by gz_sign_resolve, and C10 lets go of its outpoint when it is
 * resolved; the unfinished deadline ends the others, also the one that has
 * left memory in the second run. */
#define UN (GZ_SIGN_MAX_ROUNDS + 1)   /* one round more than the engine holds in full */
static void test_unfinished_across_restart(void)
{
    for (int restart = 0; restart < 2; restart++)
        for (int by_deadline = 0; by_deadline < 2; by_deadline++) {
            harness_t h;
            uint8_t id1[32], id5[32];
            gz_action_list_t list;
            h_init(&h, 1);
            for (int k = 0; k < UN; k++) {
                CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
                flush_without(&h, 1, GZ_SIGN_MSG_RESULT, GZ_SIGN_MSG_COMPLETE);
                const gz_sign_round_t *r = h_newest(&h, 1);
                CHECK(r && r->state == GZ_SIGN_ROUND_ACTIVE && r->ever_partial);
                if (r && k == 0) memcpy(id1, r->id, 32);
                if (r && k == UN - 1) memcpy(id5, r->id, 32);
                if (k < UN - 1) h_host_settle(&h);     /* the host's Complete round ends, so the host has room */
            }
            gz_sign_t *e = h.p[1].e;
            CHECK(!find(e, id1) && evicted(e, id1) && evicted(e, id1)->state == GZ_SIGN_ROUND_UNFINISHED);
            CHECK(unresolved(e) == UN && e->n_exposures == UN);
            if (restart) {
                CHECK(h_restart(&h, 1) == GZ_OK);
                e = h.p[1].e;
                /* its true state again: Unfinished, not Active; and the same rounds in memory as before */
                CHECK(!find(e, id1) && evicted(e, id1) && evicted(e, id1)->state == GZ_SIGN_ROUND_UNFINISHED);
                CHECK(unresolved(e) == UN && e->n_exposures == UN);
                CHECK(find(e, id5) && find(e, id5)->state == GZ_SIGN_ROUND_ACTIVE && find(e, id5)->ever_partial);
                for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++)
                    CHECK(e->rounds[k].state == (same(e->rounds[k].id, id5, 32) ? GZ_SIGN_ROUND_ACTIVE : GZ_SIGN_ROUND_UNFINISHED));
            }
            e->cfg.unfinished_ticks = 5;
            if (!by_deadline) {
                size_t recs = h.p[1].n_recs;
                gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
                CHECK(gz_sign_resolve(e, id1, GZ_SIGN_END_ABANDONED, &list) == GZ_OK && list.count == 1);
                h_apply(&h, 1, &list);
                CHECK(h.p[1].n_recs == recs + 1 && evicted(e, id1)->state == GZ_SIGN_ROUND_ABANDONED && unresolved(e) == UN - 1);   /* C10 lets go */
            }
            for (int i = 0; i < 80; i++) h_tick(&h, 1);
            CHECK(unresolved(e) == 0 && evicted(e, id1) && evicted(e, id1)->state == GZ_SIGN_ROUND_ABANDONED);
            CHECK(count_recs(&h, 1, GZ_SIGN_REC_ROUND_ENDED) == UN);               /* one each, no more */
            CHECK(h_restart(&h, 1) == GZ_OK && unresolved(h.p[1].e) == 0);
            CHECK(evicted(h.p[1].e, id1) && evicted(h.p[1].e, id1)->state == GZ_SIGN_ROUND_ABANDONED);
            /* Abandoned moves on to Dead, also for the round that left memory: then its record leaves C7 (B8) */
            gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
            CHECK(gz_sign_resolve(h.p[1].e, id1, GZ_SIGN_END_DEAD, &list) == GZ_OK && h.p[1].e->n_exposures == UN - 1);
            h_apply(&h, 1, &list);
            CHECK(h_restart(&h, 1) == GZ_OK && h.p[1].e->n_exposures == UN - 1 && !evicted(h.p[1].e, id1) && h.errors == 0);
            h_free(&h);
        }
}

/* B10 (probe P10): at a start, a round whose identifier the filter of refused
 * identifiers happens to answer "known" for (a false positive: here its ten
 * positions are set by hand, with nothing in the exact list) is taken up all
 * the same, with its exposure and its place in C10. */
static void test_replay_filter_hit(void)
{
    for (int hit = 0; hit < 2; hit++) {
        harness_t h;
        uint8_t id[32];
        gz_stored_batch_t batch;
        int ok = 1;
        h_init(&h, 1);
        CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
        flush_without(&h, 1, GZ_SIGN_MSG_RESULT, GZ_SIGN_MSG_COMPLETE);
        const gz_sign_round_t *r = h_newest(&h, 1);
        CHECK(r && r->ever_partial);
        if (!r) { h_free(&h); continue; }
        memcpy(id, r->id, 32);
        gz_sign_t *e = h.p[1].e;
        h_party_t *p = &h.p[1];
        reset_rounds(e);
        if (hit) {
            uint32_t pos[GZ_SIGN_KNOWN_FILTER_K];
            filter_positions(e, id, pos);
            for (int k = 0; k < GZ_SIGN_KNOWN_FILTER_K; k++) e->known_filter[pos[k] >> 3] |= (uint8_t)(1u << (pos[k] & 7));
            CHECK(is_known(e, id) && !known_exactly(e, id));
        }
        h_rewind(p);
        while (h_next(p, &batch)) {
            const uint8_t *prop = NULL;
            size_t plen = 0;
            for (size_t i = 0; i < batch.n_records; i++)
                if ((batch.records[i].type >> 16) == GZ_SIGN_REC_AREA && !replay(e, &batch.records[i], &prop, &plen)) ok = 0;
        }
        CHECK(ok && find(e, id) && find(e, id)->ever_partial && e->n_exposures == 1 && unresolved(e) == 1);
        /* an identifier held exactly is still not taken up twice */
        h_rewind(p);
        add_known(e, id);
        size_t held = 0;
        memset(e->rounds, 0, sizeof e->rounds);
        while (h_next(p, &batch)) {
            const uint8_t *prop = NULL;
            size_t plen = 0;
            for (size_t i = 0; i < batch.n_records; i++)
                if ((batch.records[i].type >> 16) == GZ_SIGN_REC_AREA && !replay(e, &batch.records[i], &prop, &plen)) ok = 0;
        }
        for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) held += e->rounds[k].state != GZ_SIGN_ROUND_FREE;
        CHECK(ok && held == 0);
        /* its partial signatures are out all the same: the round is Unfinished, counted by C10 and reachable */
        CHECK(evicted(e, id) && evicted(e, id)->state == GZ_SIGN_ROUND_UNFINISHED && unresolved(e) == 1);
        CHECK(h_restart(&h, 1) == GZ_OK);
        h_free(&h);
    }
}

static int has_rec(const h_party_t *p, uint32_t type)
{
    for (size_t i = 0; i < p->n_recs; i++) if (p->recs[i].type == type) return 1;
    return 0;
}

/* B11 (probe P8) and mutant N17: a member's journal that ends between the
 * round_signed of tier 0 and the round_started of tier 1 (a crash between
 * the two batches). A start begins tier 1: new nonces, saved, then sent.
 * When that start's actions do not fit, it fails, the engine is failed, and
 * no secret nonce is left in memory. */
static void test_start_begins_next_tier(void)
{
    for (int room = 0; room < 2; room++) {
        harness_t h;
        static gz_action_t slots[1];
        static uint8_t bytes[64];
        gz_action_list_t list;
        int more = 1;
        h_init(&h, 1);
        CHECK(h_begin(&h, 2, 1, 0) == GZ_OK);
        h_party_t *p = &h.p[1];
        while (h.nq && !has_rec(p, GZ_SIGN_REC_ROUND_SIGNED)) h_deliver(&h, 0, 0);
        size_t cut = p->n_recs;
        for (size_t i = 0; i < p->n_recs && cut == p->n_recs; i++)
            if (p->recs[i].type == GZ_SIGN_REC_ROUND_SIGNED)
                for (size_t j = i + 1; j < p->n_recs; j++) if (p->recs[j].type == GZ_SIGN_REC_ROUND_STARTED) { cut = j; break; }
        CHECK(cut < p->n_recs);
        for (size_t i = cut; i < p->n_recs; i++) free(p->recs[i].b);
        p->n_recs = cut;
        while (h.nq) h_drop_msg(&h, 0);
        size_t nonces = h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES);
        uint64_t made;
        gz_sign_wipe(p->e);
        h_build(&h, 1);
        made = p->e->counters[GZ_SIGN_COUNT_NONCES_MADE];
        if (room) {
            CHECK(h_start(&h, 1) == GZ_OK);
            const gz_sign_round_t *r = h_newest(&h, 1);
            CHECK(r && r->state == GZ_SIGN_ROUND_ACTIVE && r->tier == 1 && r->tier_state[0] == GZ_SIGN_TIER_DONE && r->tier_state[1] == GZ_SIGN_TIER_NONCES);
            CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == nonces + 1 && p->e->counters[GZ_SIGN_COUNT_NONCES_MADE] > made);
            CHECK(p->n_recs > cut && p->recs[cut].type == GZ_SIGN_REC_ROUND_STARTED);
            h_flush(&h, 100000);                                    /* and the round completes */
            CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE && h_newest(&h, 1)->state == GZ_SIGN_ROUND_COMPLETE);
        } else {
            gz_storage_reader_t rd = {h_next, h_rewind, p, p->incarnation, 0, {NULL, 0}};
            gz_action_list_init(&list, slots, 1, bytes, sizeof bytes);
            CHECK(gz_sign_start(p->e, &rd, &list, &more) == GZ_ERR_NO_SPACE && list.count == 0 && p->e->failed);
            CHECK(p->e->counters[GZ_SIGN_COUNT_NONCES_MADE] > made);              /* it did make them */
            CHECK(live_secrets(p->e) == 0);
            CHECK(h_start(&h, 1) == GZ_OK && !p->e->failed);                        /* and a start with room recovers */
        }
        h_free(&h);
    }
}

/* Mutant N16: an engine that fails wipes every secret nonce it holds (here a
 * member's proposal whose answer does not fit: the nonces were made). */
static void test_failed_engine_holds_no_secret(void)
{
    harness_t h;
    static gz_action_t slots[1];
    static uint8_t bytes[64];
    gz_action_list_t small;
    gz_event_t ev;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    CHECK(live_secrets(h.p[0].e) > 0);                                              /* the host's own, made at begin */
    long k = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(k >= 0);
    if (k >= 0) {
        uint64_t made = h.p[1].e->counters[GZ_SIGN_COUNT_NONCES_MADE];
        CHECK(w_msg_event(&h.builder, 0, 1, h.q[k].b, h.q[k].len, &ev));
        gz_action_list_init(&small, slots, 1, bytes, sizeof bytes);
        CHECK(gz_sign_handle(h.p[1].e, &ev, &small) == GZ_ERR_NO_SPACE && h.p[1].e->failed);
        CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_NONCES_MADE] > made && live_secrets(h.p[1].e) == 0);
    }
    /* the host: a timer step whose actions do not fit (a resend) */
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_TIMER_FIRED; ev.u.timer.timer_id = TIMER_ID;
    gz_action_list_init(&small, slots, 0, bytes, 0);
    CHECK(gz_sign_handle(h.p[0].e, &ev, &small) != GZ_OK && h.p[0].e->failed && live_secrets(h.p[0].e) == 0);
    h_free(&h);
}

/* Mutants F23 and F26: gz_sign_resolve is refused while the engine is failed,
 * and a resolve whose record does not fit fails the engine and changes
 * nothing; a start recovers. */
static void test_resolve_errors(void)
{
    harness_t h;
    static gz_action_t slots[1];
    static uint8_t bytes[8];
    gz_action_list_t list;
    uint8_t id[32];
    h_init(&h, 1);
    CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
    h_flush(&h, 100000);
    const gz_sign_round_t *r = h_newest(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_COMPLETE);
    if (!r) { h_free(&h); return; }
    memcpy(id, r->id, 32);
    gz_action_list_init(&list, slots, 1, bytes, sizeof bytes);                     /* no room for round_ended */
    CHECK(gz_sign_resolve(h.p[1].e, id, GZ_SIGN_END_LIVE, &list) == GZ_ERR_NO_SPACE && list.count == 0 && list.used == 0);
    CHECK(h.p[1].e->failed && h_newest(&h, 1)->state == GZ_SIGN_ROUND_COMPLETE);
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    CHECK(gz_sign_resolve(h.p[1].e, id, GZ_SIGN_END_LIVE, &list) == GZ_ERR_FAILED && list.count == 0);
    CHECK(h_newest(&h, 1)->state == GZ_SIGN_ROUND_COMPLETE);
    CHECK(h_restart(&h, 1) == GZ_OK && h_newest(&h, 1)->state == GZ_SIGN_ROUND_COMPLETE);
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    CHECK(gz_sign_resolve(h.p[1].e, id, GZ_SIGN_END_LIVE, &list) == GZ_OK && list.count == 1 && h_newest(&h, 1)->state == GZ_SIGN_ROUND_LIVE);
    h_free(&h);
}

/* Mutant K34: while a member waits for the result of a round it sent partial
 * signatures for (Active, in memory), C10 counts that round: a second round
 * with the same tree on its outpoint is refused with reason 6. */
static void test_c10_active_with_partials(void)
{
    harness_t h;
    uint8_t c[32];
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    flush_without(&h, 1, GZ_SIGN_MSG_RESULT, GZ_SIGN_MSG_COMPLETE);
    const gz_sign_round_t *r = h_newest(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_ACTIVE && r->ever_partial && unresolved(h.p[1].e) == 1);
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    memcpy(c, h_newest(&h, 0)->id, 32);
    long k = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(k >= 0);
    if (k >= 0) {
        size_t sent = h.n_sent;
        gz_sign_msg_t m;
        h_deliver(&h, (size_t)k, 0);
        CHECK(h.n_sent == sent + 1 && gz_sign_decode(h.sent[sent].b, h.sent[sent].len, &m) && m.kind == GZ_SIGN_MSG_ABORT && m.reason == 6);
        CHECK(!find(h.p[1].e, c) && sent_for(&h, 1, GZ_SIGN_MSG_NONCES, c) == 0);
        CHECK(r->state == GZ_SIGN_ROUND_ACTIVE);                                    /* and the waiting round is not given up for it */
    }
    h_free(&h);
}

/* B8: the C7 set at its limit refuses new rounds (reason 9) only until a
 * creation is resolved Dead (C4(d)): its record leaves the set, in memory and
 * at the next start, and the member signs again. Live and Abandoned records
 * stay: one tree per funding output, as long as the output can exist. */
static void test_exposures_recover(void)
{
    harness_t h;
    gz_action_list_t list;
    uint8_t ids[3][32], fill[32] = {0};
    h_init(&h, 1);
    for (int k = 0; k < 3; k++) {
        CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
        h_flush(&h, 100000);
        CHECK(h_newest(&h, 1)->state == GZ_SIGN_ROUND_COMPLETE);
        memcpy(ids[k], h_newest(&h, 1)->id, 32);
    }
    gz_sign_t *e = h.p[1].e;
    CHECK(e->n_exposures == 3);
    /* the set filled to its limit with records of rounds that left memory Unfinished */
    for (size_t i = e->n_exposures; i < GZ_SIGN_MAX_EXPOSURES; i++) {
        fill[0] = (uint8_t)i; fill[1] = (uint8_t)(i >> 8); fill[2] = 0xee;
        CHECK(add_exposure(e, fill, 7, fill, fill));
        e->exposed[i].state = GZ_SIGN_ROUND_UNFINISHED;
    }
    CHECK(e->n_exposures == GZ_SIGN_MAX_EXPOSURES && !e->exposures_lost);
    CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);                                          /* full: refused, reason 9 */
    {
        size_t sent = h.n_sent;
        gz_sign_msg_t m;
        h_flush(&h, 1);
        CHECK(h.n_sent == sent + 1 && gz_sign_decode(h.sent[sent].b, h.sent[sent].len, &m) && m.kind == GZ_SIGN_MSG_ABORT && m.reason == 9);
        h_flush(&h, 100000);
    }
    /* Live and Abandoned do not make room */
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    CHECK(gz_sign_resolve(e, ids[0], GZ_SIGN_END_LIVE, &list) == GZ_OK);
    h_apply(&h, 1, &list);
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    CHECK(gz_sign_resolve(e, ids[1], GZ_SIGN_END_ABANDONED, &list) == GZ_OK);
    h_apply(&h, 1, &list);
    CHECK(e->n_exposures == GZ_SIGN_MAX_EXPOSURES);
    /* Dead does: of a round in memory (ids[2]) and of one that left it (the first filler) */
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    CHECK(gz_sign_resolve(e, ids[2], GZ_SIGN_END_DEAD, &list) == GZ_OK);
    h_apply(&h, 1, &list);
    CHECK(e->n_exposures == GZ_SIGN_MAX_EXPOSURES - 1 && !exposed_of(e, ids[2]) && exposed_of(e, ids[0]) && exposed_of(e, ids[1]));
    fill[0] = 3; fill[1] = 0; fill[2] = 0xee;
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    CHECK(gz_sign_resolve(e, fill, GZ_SIGN_END_DEAD, &list) == GZ_OK && e->n_exposures == GZ_SIGN_MAX_EXPOSURES - 2 && !exposed_of(e, fill));
    for (size_t i = 0; i < e->n_exposures; i++)                                     /* the set stays whole: no hole, no entry twice */
        CHECK(!all_zero(e->exposed[i].round_id, 32) && exposed_of(e, e->exposed[i].round_id) == &e->exposed[i]);
    CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);                                          /* room again: signed */
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE && h_newest(&h, 1)->state == GZ_SIGN_ROUND_COMPLETE);
    CHECK(e->n_exposures == GZ_SIGN_MAX_EXPOSURES - 1);
    /* a start reads the same from the journal: the Dead round's record is not in the set, the others are */
    CHECK(h_restart(&h, 1) == GZ_OK);
    e = h.p[1].e;
    CHECK(e->n_exposures == 3 && !exposed_of(e, ids[2]) && exposed_of(e, ids[0]) && exposed_of(e, ids[1]) && !e->exposures_lost);
    /* the Dead outpoint is free for C7 (it can never exist); the Live one still holds its one tree */
    h_free(&h);
}

/* Review B's confirmation, N2 (probe C6): round A's result is withheld, round
 * B is proposed (A is Unfinished, superseded), then A's result arrives and A
 * runs again. A crash before round_complete: the start must bring A back
 * running, as it was, so that it acks and completes when the host answers.
 * With and without the restart. */
static void test_revived_round_across_restart(void)
{
    for (int restart = 0; restart < 2; restart++) {
        harness_t h;
        uint8_t a_id[32];
        gz_sign_round_t *a;
        h_init(&h, 1);
        CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
        flush_without(&h, 1, GZ_SIGN_MSG_RESULT, GZ_SIGN_MSG_COMPLETE);
        CHECK(h_newest(&h, 1) != NULL);
        if (!h_newest(&h, 1)) { h_free(&h); continue; }
        memcpy(a_id, h_newest(&h, 1)->id, 32);
        CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
        flush_without(&h, 1, GZ_SIGN_MSG_RESULT, GZ_SIGN_MSG_COMPLETE);
        a = find(h.p[1].e, a_id);
        CHECK(a && a->state == GZ_SIGN_ROUND_UNFINISHED && a->why == GZ_SIGN_WHY_SUPERSEDED);
        h_connect(&h, 1, 0);                                 /* the member asks again */
        for (size_t guard = 0; h.nq && guard < 10000; guard++) {      /* of the host's answers only A's result arrives */
            const h_msg_t *m = &h.q[0];
            if (m->to == 1 && !(h_kind_of(m->b, m->len) == GZ_SIGN_MSG_RESULT && same(m->b + GZ_RMSG_HEADER + 2, a_id, 32))) h_drop_msg(&h, 0);
            else h_deliver(&h, 0, 0);
        }
        a = find(h.p[1].e, a_id);
        CHECK(a && a->state == GZ_SIGN_ROUND_ACTIVE && a->tier_state[0] == GZ_SIGN_TIER_DONE);
        if (restart) {
            CHECK(h_restart(&h, 1) == GZ_OK);
            a = find(h.p[1].e, a_id);
            CHECK(a && a->state == GZ_SIGN_ROUND_ACTIVE && a->tier_state[0] == GZ_SIGN_TIER_DONE && a->ever_partial);
        }
        while (h.nq) h_drop_msg(&h, 0);
        h_tick(&h, 0);                                       /* a tick later the host answers a request again */
        while (h.nq) h_drop_msg(&h, 0);
        h_connect(&h, 1, 0);
        h_flush(&h, 10000);
        a = find(h.p[1].e, a_id);
        CHECK(a && a->state == GZ_SIGN_ROUND_COMPLETE && sent_for(&h, 1, GZ_SIGN_MSG_ACK, a_id) == 1);
        CHECK(h_find(&h, 0, a_id) && h_find(&h, 0, a_id)->state == GZ_SIGN_ROUND_DONE && h.errors == 0);
        h_free(&h);
    }
}

/* Audit e2e H1, signing-round.md 6 step 5: before its partial signatures a member checks C7 again. An
 * exposure for another tree on the round's outpoint, recorded after the proposal was taken (here set
 * straight into the engine's exposure list, as a start reads one back from the journal), refuses the
 * round with reason 11, and no partial signature leaves. With the proposal-time check in place no honest
 * journal reaches this state; the recheck is what the spec asks for, and this test holds it. */
static void test_c7_at_signing(void)
{
    harness_t h;
    uint8_t other[32], fid[32];
    gz_sign_msg_t m;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (h.nq && q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
    long k = q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES);
    gz_sign_round_t *r = (gz_sign_round_t *)gz_sign_latest(h.p[1].e);
    CHECK(k >= 0 && r && r->state == GZ_SIGN_ROUND_ACTIVE && !r->ever_partial);
    if (k < 0 || !r) { h_free(&h); return; }
    memcpy(other, r->def.tree_digest, 32);
    other[0] ^= 1;
    memset(fid, 0x5a, 32);
    CHECK(add_exposure(h.p[1].e, r->def.funding_txid, r->def.funding_vout, other, fid));
    size_t partials = h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS), aborts = h_count_kind(&h, 1, GZ_SIGN_MSG_ABORT);
    h_deliver(&h, (size_t)k, 0);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == partials);
    const h_sent_t *a = h_sent_kind(&h, 1, GZ_SIGN_MSG_ABORT, aborts);
    CHECK(a && gz_sign_decode(a->b, a->len, &m) && m.reason == gz_sign_reason(GZ_SIGN_WHY_OTHER_TREE, 0));
    CHECK(r->state != GZ_SIGN_ROUND_ACTIVE && !r->ever_partial);
    h_free(&h);
}

/* MEMBER_REPORTS_FUNDING, MEMBER_REPORTS, REPORT_ONCE: a member's lobby hears of each round once:
 * Funding (released) when its ack is saved; Retry (nothing released) when the round ends for it before
 * any partial signature; and never a second time for the same round. */
static void test_member_outcomes(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    h_flush(&h, 100000);
    for (uint32_t g = 1; g <= 3; g++)
        CHECK(h.builder.m_n_outcomes[g] == 1 && h.builder.m_outcomes[g][0] == GZ_SIGN_OUTCOME_FUNDING &&
              h.builder.m_released[g][0] == 1);
    gz_sign_round_t *r = round_of(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_COMPLETE && r->reported);
    if (r) {
        gz_action_list_t list;
        emit_t em;
        gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
        em.out = &list; em.st = GZ_OK; em.e = h.p[1].e;
        report(h.p[1].e, GZ_SIGN_OUTCOME_RETRY, r, 0, &em);          /* reported already: nothing more */
        CHECK(em.st == GZ_OK && h.builder.m_n_outcomes[1] == 1 && list.count == 0);
    }
    h_free(&h);

    /* member 1's nonce sets never come (what is sent to it is lost): its round ends at its deadline */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    deliver_until_sent(&h, 1, GZ_SIGN_MSG_NONCES);
    CHECK(h.builder.m_n_outcomes[1] == 0);
    h.drop_to |= 1u << 1;
    h_ticks(&h, 40);
    r = round_of(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_ABORTED && !r->ever_partial);
    CHECK(h.builder.m_n_outcomes[1] == 1 && h.builder.m_outcomes[1][0] == GZ_SIGN_OUTCOME_RETRY && h.builder.m_released[1][0] == 0);
    h_free(&h);
}

/* IGNORE_UNACCEPTED: a proposal for a check the member's lobby did not accept (its builder answers
 * GZ_SIGN_BUILD_IGNORE) is ignored: counted, no answer at all (no abort a hostile host could collect,
 * 13, A8), no round, and the keys taken for it given back. */
static void test_ignore_unaccepted(void)
{
    harness_t h;
    h_init(&h, 1);
    CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
    h.builder.refuse = GZ_SIGN_BUILD_IGNORE;          /* the member's builder, from here on */
    long k = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(k >= 0);
    if (k >= 0) {
        gz_sign_t *e = h.p[1].e;
        uint64_t ign = e->counters[GZ_SIGN_COUNT_IGNORED], rej = e->counters[GZ_SIGN_COUNT_REJECTED];
        size_t sent = h.n_sent;
        h_deliver(&h, (size_t)k, 0);
        CHECK(e->counters[GZ_SIGN_COUNT_IGNORED] == ign + 1 && e->counters[GZ_SIGN_COUNT_REJECTED] == rej);
        CHECK(h.n_sent == sent && h_newest(&h, 1) == NULL && e->keys_held == KEYS_NONE);
    }
    h.builder.refuse = 0;
    h_free(&h);
}

/* A signed round message without record `type`, signed again by party g (one-byte record types, lengths
 * as w_pad writes them). Returns the new length, 0 if the message does not parse that way. */
static size_t strip_record(const uint8_t *in, size_t len, uint8_t type, uint32_t g, uint8_t *out)
{
    size_t at = GZ_RMSG_HEADER, n = GZ_RMSG_HEADER;
    memcpy(out, in, GZ_RMSG_HEADER);
    while (at < len) {
        size_t start = at, rl;
        uint8_t t = in[at++];
        if (t >= 253 || at >= len) return 0;
        if (in[at] < 253) rl = in[at++];
        else if (in[at] == 0xfd && at + 2 < len) { rl = (size_t)in[at + 1] << 8 | in[at + 2]; at += 3; }
        else return 0;
        if (at + rl > len) return 0;
        at += rl;
        if (t != type) { memcpy(out + n, in + start, at - start); n += at - start; }
    }
    w_resign(out, n, g);
    return n;
}

/* ATTEMPT_REQUIRED: a proposal without record 7 (the attempt), signed by its host, is refused as an
 * invalid round (messages.md 7.2): no round, no nonces. */
static void test_attempt_required(void)
{
    harness_t h;
    static uint8_t b[GZ_SIGN_MAX_PROPOSAL];
    h_init(&h, 1);
    CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
    long k = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(k >= 0);
    if (k >= 0) {
        size_t len = strip_record(h.q[k].b, h.q[k].len, 7, 0, b), sent;
        gz_sign_msg_t m;
        CHECK(len > 0 && len < h.q[k].len);
        h_drop_msg(&h, (size_t)k);
        sent = h.n_sent;
        CHECK(h_inject(&h, 0, 1, b, len) == GZ_OK && !h.p[1].e->failed);
        CHECK(h.n_sent == sent + 1 && gz_sign_decode(h.sent[sent].b, h.sent[sent].len, &m) && m.kind == GZ_SIGN_MSG_ABORT &&
              m.reason == gz_sign_reason(GZ_SIGN_WHY_INVALID_ROUND, 0));
        CHECK(h_newest(&h, 1) == NULL && h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == 0);
    }
    h_free(&h);
}

/* KEYS_STILL_ROUNDS: keys taken again for a round must still be the round's own. Member 1's key hook
 * gives another factory key once its nonces have left (the contribution key, and so its links, stay);
 * when the nonce sets arrive it signs nothing with it: the round fails NOT_MY_KEY and no key stays held. */
static void keys_still_rounds(int contribution)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    deliver_until_sent(&h, 1, GZ_SIGN_MSG_NONCES);
    gz_sign_round_t *r = round_of(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_ACTIVE && h.p[1].e->keys_held == KEYS_NONE);
    while (h.nq && q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
    long k = q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES);
    CHECK(k >= 0);
    /* member 1's hook now gives another factory key, or another contribution key */
    if (contribution) h.builder.other_contribution = 1u << 1;
    else h.builder.other_factory = 1u << 1;
    if (k >= 0 && r) {
        uint64_t made = h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE];
        h_deliver(&h, (size_t)k, 0);
        CHECK(r->state == GZ_SIGN_ROUND_ABORTED && r->why == GZ_SIGN_WHY_NOT_MY_KEY);
        CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE] == made && h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == 0);
        CHECK(h.p[1].e->keys_held == KEYS_NONE);
    }
    if (r && r->why != GZ_SIGN_WHY_NOT_MY_KEY) printf("  keys_still_rounds: round state %d, why %d\n", (int)r->state, (int)r->why);
    h.builder.other_factory = h.builder.other_contribution = 0;
    h_free(&h);
}

static void test_keys_still_rounds(void)
{
    keys_still_rounds(0);   /* the factory key */
    keys_still_rounds(1);   /* the contribution key */
}

/* SUPERSEDE_OWN_CHECK: a proposal supersedes only an older attempt of its own check in its own lobby;
 * the same attempt, a later one, another check or another lobby runs on. */
static void test_older_attempt(void)
{
    harness_t h;
    static gz_sign_round_t a, b;
    h_init(&h, 1);
    CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
    h_flush(&h, 100000);
    const gz_sign_round_t *r0 = h_newest(&h, 1);
    CHECK(r0 != NULL);
    if (r0) {
        a = *r0; b = *r0;
        b.id[0] ^= 1;
        a.attempt = 2; b.attempt = 3;
        CHECK(older_attempt(&a, &b) == 1 && older_attempt(&b, &a) == 0);
        b.attempt = 2;
        CHECK(older_attempt(&a, &b) == 0 && older_attempt(&b, &a) == 0);
        b.attempt = 3; b.check_id[0] ^= 1;
        CHECK(older_attempt(&a, &b) == 0);
        b.check_id[0] ^= 1; b.def.outer_digest[0] ^= 1;
        CHECK(older_attempt(&a, &b) == 0);
    }
    h_free(&h);
}

/* EXPOSURE_PER_ROUND: two rounds of one tree on one outpoint each have their exposure entry (each is
 * resolved on its own); a round's own exposure again is the same entry. */
static void test_exposure_per_round(void)
{
    harness_t h;
    uint8_t txid[32], dig[32], a[32], b[32];
    h_init(&h, 1);
    gz_sign_t *e = h.p[1].e;
    memset(txid, 0x11, 32); memset(dig, 0x22, 32); memset(a, 0xa1, 32); memset(b, 0xb2, 32);
    size_t n0 = e->n_exposures;
    CHECK(add_exposure(e, txid, 3, dig, a) && e->n_exposures == n0 + 1);
    CHECK(add_exposure(e, txid, 3, dig, a) && e->n_exposures == n0 + 1);
    CHECK(add_exposure(e, txid, 3, dig, b) && e->n_exposures == n0 + 2);
    CHECK(!memcmp(e->exposed[n0].round_id, a, 32) && !memcmp(e->exposed[n0 + 1].round_id, b, 32));
    h_free(&h);
}

/* EXCUSE_ONLY_RELEASED: a member's reason-6 abort (another round of the outpoint) is excused only if a
 * round on that outpoint may have released partial signatures; one that never did excuses nothing. */
static void test_excuse_only_released(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    deliver_until_sent(&h, 1, GZ_SIGN_MSG_NONCES);
    gz_sign_t *e = h.p[0].e;
    gz_sign_round_t *r = round_of(&h, 0);
    int fs = -1;
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS && r && fs < 0; i++) if (e->rounds[i].state == GZ_SIGN_ROUND_FREE) fs = i;
    CHECK(r && fs >= 0);
    if (r && fs >= 0) {
        gz_sign_round_t *o = &e->rounds[fs];
        for (int k = 0; k < GZ_SIGN_MAX_KEPT; k++) CHECK(!e->kept[k].used);
        *o = *r;
        o->id[0] ^= 1; o->why = 0;
        for (int t = 0; t < o->def.n_tiers; t++) o->tier_state[t] = GZ_SIGN_TIER_NONCES;
        CHECK(abort_blame(e, r, 1, 6) == bit(1));
        o->tier_state[0] = GZ_SIGN_TIER_SIGNED;
        CHECK(abort_blame(e, r, 1, 6) == 0);
        memset(o, 0, sizeof *o);
    }
    h_free(&h);
}

/* EARLY_NONCES: nonces for a later tier are early (kept) only from a member with no item in any tier from
 * the one under way up to theirs. A round of three tiers: the first item alone in tier 0, the items
 * without member 3 in tier 1, the rest in tier 2; tier 1 under way. */
/* ACK_WAITS_FOR_TIP (review B of PR 52, L4): a may_ack with nothing to judge from yet answers -1: the
 * member neither acks nor refuses (no Retry, the round still Active), and once it can judge, the host's
 * next round_complete is acked and the round completes. */
static void test_ack_waits_for_tip(void)
{
    harness_t h;
    h_init(&h, 1);
    h.builder.ack_wait = 1u << 1;
    CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
    h_flush(&h, 100000);
    const gz_sign_round_t *r = h_newest(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_ACTIVE && !r->ack_refused && r->why == 0);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_ACK) == 0 && h.builder.m_n_outcomes[1] == 0 && h.builder.may_ack_calls >= 1);
    h.builder.ack_wait = 0;
    h_ticks(&h, 8);                                                 /* the host's round_complete again */
    r = h_newest(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_COMPLETE && h_count_kind(&h, 1, GZ_SIGN_MSG_ACK) >= 1);
    CHECK(h_newest(&h, 0) && h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
    CHECK(h.builder.m_n_outcomes[1] == 1 && h.builder.m_outcomes[1][0] == GZ_SIGN_OUTCOME_FUNDING);
    h_free(&h);
}

static void test_early_nonces(void)
{
    harness_t h;
    static gz_sign_round_t r;
    h_init(&h, 3);
    CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
    deliver_until_sent(&h, 1, GZ_SIGN_MSG_NONCES);
    const gz_sign_round_t *r0 = round_of(&h, 0);
    CHECK(r0 != NULL);
    if (r0) {
        uint8_t other = 0;
        r = *r0;
        r.def.n_tiers = 3;
        for (int i = 0; i < r.def.n_items; i++) r.def.items[i].tier = (uint8_t)(i == 0 ? 0 : pos_of(&r.def.items[i], 3) < 0 ? 1 : 2);
        r.tier = 1; r.tier_state[0] = GZ_SIGN_TIER_SIGNED; r.tier_state[1] = GZ_SIGN_TIER_NONCES;
        CHECK(count_items(&r, 3, 1) == 0 && count_items(&r, 3, 2) > 0);
        for (uint8_t j = 1; j <= 3 && !other; j++) if (count_items(&r, j, 1) > 0) other = j;
        CHECK(other != 0);
        CHECK(early_nonces(&r, 3, 2) == 1);
        CHECK(early_nonces(&r, 3, 1) == 0);
        if (other) CHECK(early_nonces(&r, other, 2) == 0);
        r.tier_state[1] = GZ_SIGN_TIER_NONE;
        CHECK(early_nonces(&r, 3, 2) == 0);
    }
    h_free(&h);
}

/* PARTIALS_OUT_HELD, PARTIALS_OUT_FAIL_CLOSED (Slice 1 blocker C1): the partials-out fact. A round of the
 * scope that sent a partial signature, while Active, Unfinished or Complete; not once resolved, not before
 * any was sent, not for another scope. An exposure whose round left memory unresolved: every scope (its
 * scope is not kept); resolved: none. */
static void test_partials_out(void)
{
    harness_t h;
    static const uint8_t open_states[] = {GZ_SIGN_ROUND_ACTIVE, GZ_SIGN_ROUND_UNFINISHED, GZ_SIGN_ROUND_COMPLETE};
    static const uint8_t ended[] = {GZ_SIGN_ROUND_LIVE, GZ_SIGN_ROUND_DEAD, GZ_SIGN_ROUND_ABANDONED};
    uint8_t scope[32], other[32];
    h_init(&h, 1);
    gz_sign_t *e = h.p[1].e;
    gz_sign_round_t *r = &e->rounds[GZ_SIGN_MAX_ROUNDS - 1];
    memset(scope, 0x31, 32); memset(other, 0x32, 32);
    CHECK(gz_sign_partials_out(e, scope) == 0 && gz_sign_partials_out(NULL, scope) == 0 && gz_sign_partials_out(e, NULL) == 0);
    memset(r, 0, sizeof *r);
    memcpy(r->def.outer_digest, scope, 32);
    for (size_t k = 0; k < sizeof open_states; k++) {
        r->state = open_states[k];
        r->ever_partial = 1;
        CHECK(gz_sign_partials_out(e, scope) == GZ_SIGN_OUT_THIS && gz_sign_partials_out(e, other) == GZ_SIGN_OUT_NONE);
        r->ever_partial = 0;
        CHECK(gz_sign_partials_out(e, scope) == GZ_SIGN_OUT_NONE);
    }
    r->ever_partial = 1;
    for (size_t k = 0; k < sizeof ended; k++) { r->state = ended[k]; CHECK(gz_sign_partials_out(e, scope) == 0); }
    memset(r, 0, sizeof *r);
    size_t n0 = e->n_exposures;
    CHECK(n0 < GZ_SIGN_MAX_EXPOSURES);
    if (n0 < GZ_SIGN_MAX_EXPOSURES) {
        memset(&e->exposed[n0], 0, sizeof e->exposed[n0]);
        e->n_exposures = n0 + 1;
        e->exposed[n0].state = GZ_SIGN_ROUND_FREE;                   /* held in a slot: the round's own test */
        CHECK(gz_sign_partials_out(e, scope) == GZ_SIGN_OUT_NONE);
        for (size_t k = 0; k < sizeof open_states; k++) {
            if (open_states[k] == GZ_SIGN_ROUND_ACTIVE) continue;     /* a round leaving memory Active is Unfinished */
            e->exposed[n0].state = open_states[k];
            /* its lobby not known: fail closed, for every lobby, with its own answer */
            e->exposed[n0].has_scope = 0;
            CHECK(gz_sign_partials_out(e, scope) == GZ_SIGN_OUT_UNKNOWN && gz_sign_partials_out(e, other) == GZ_SIGN_OUT_UNKNOWN);
            /* its lobby known (the saved scope): that lobby only */
            e->exposed[n0].has_scope = 1;
            memcpy(e->exposed[n0].scope, scope, 32);
            CHECK(gz_sign_partials_out(e, scope) == GZ_SIGN_OUT_THIS && gz_sign_partials_out(e, other) == GZ_SIGN_OUT_NONE);
        }
        for (size_t k = 0; k < sizeof ended; k++) {
            e->exposed[n0].state = ended[k];
            e->exposed[n0].has_scope = 0;
            CHECK(gz_sign_partials_out(e, scope) == GZ_SIGN_OUT_NONE);
        }
        memset(&e->exposed[n0], 0, sizeof e->exposed[n0]);
        e->n_exposures = n0;
    }
    h_free(&h);
}

/* The fail-closed case of gz_sign_partials_out clears: an exposure whose round left memory Unfinished is
 * Abandoned at the unfinished deadline (RULE:EVICTED_ABANDONED, saved as round_ended), and then counts
 * for no lobby. (One that left memory Complete is cleared only by gz_sign_resolve, from the funding
 * engine's Live or Dead: P4.6.) */
static void test_partials_out_clears(void)
{
    harness_t h;
    uint8_t scope[32];
    h_init(&h, 1);
    gz_sign_t *e = h.p[1].e;
    memset(scope, 0x33, 32);
    e->cfg.unfinished_ticks = 3;
    size_t n0 = e->n_exposures;
    CHECK(n0 < GZ_SIGN_MAX_EXPOSURES);
    if (n0 < GZ_SIGN_MAX_EXPOSURES) {
        memset(&e->exposures[n0], 0, sizeof e->exposures[n0]);
        memset(&e->exposed[n0], 0, sizeof e->exposed[n0]);
        e->exposed[n0].round_id[0] = 0xc3;
        e->exposed[n0].state = GZ_SIGN_ROUND_UNFINISHED;
        e->exposed[n0].has_scope = 1;
        memcpy(e->exposed[n0].scope, scope, 32);
        e->n_exposures = n0 + 1;
        size_t recs = h.p[1].n_recs;
        CHECK(gz_sign_partials_out(e, scope) == 1);
        h_tick(&h, 1);
        h_tick(&h, 1);
        CHECK(gz_sign_partials_out(e, scope) == 1);                 /* before the deadline: still out */
        h_tick(&h, 1);
        CHECK(e->exposed[n0].state == GZ_SIGN_ROUND_ABANDONED && gz_sign_partials_out(e, scope) == 0);
        CHECK(h.p[1].n_recs > recs && h.p[1].recs[h.p[1].n_recs - 1].type == GZ_SIGN_REC_ROUND_ENDED);   /* saved */
    }
    h_free(&h);
}

/* Review A of PR 81, M1: the unfinished deadline counts from the time the exposure record was saved, on the
 * keep clock, so a start does not begin it again. Member 1's partial signatures are out, its round goes
 * Unfinished at the step deadline, and the member restarts 50 minutes later: the round is still out then, and
 * Abandoned (the lobby leavable) at 60 minutes, not 110. */
static void test_unfinished_deadline_across_restart(void)
{
    harness_t h;
    const uint64_t t0 = 1700000000000ull, minute = 60000ull;
    uint8_t scope[32];
    g_h_now = t0;
    h_init(&h, 3);
    h.unfinished_ticks = 3600000;                                  /* an hour of 1 ms ticks */
    for (uint32_t g = 0; g < h.n; g++) h.p[g].e->cfg.unfinished_ticks = h.unfinished_ticks;
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    deliver_until_sent(&h, 1, GZ_SIGN_MSG_PARTIALS);
    gz_sign_round_t *r = round_of(&h, 1);
    CHECK(r && r->ever_partial);
    if (!r) { h_free(&h); g_h_now = 0; return; }
    memcpy(scope, r->def.outer_digest, 32);
    h.drop_to |= 1u << 1;                                            /* the results never reach it */
    for (uint32_t k = 0; k <= h.deadline_ticks + 2; k++) h_tick(&h, 1);
    r = round_of(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_UNFINISHED && gz_sign_partials_out(h.p[1].e, scope) == GZ_SIGN_OUT_THIS);
    g_h_now = t0 + 50 * minute;
    CHECK(h_restart(&h, 1) == GZ_OK);
    h_tick(&h, 1);
    CHECK(gz_sign_partials_out(h.p[1].e, scope) == GZ_SIGN_OUT_THIS);     /* 50 minutes: still out */
    g_h_now = t0 + 60 * minute + 1000;
    for (uint32_t k = 0; k <= h.deadline_ticks + 2; k++) h_tick(&h, 1);   /* (Active again at the start: its step first) */
    r = round_of(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_ABANDONED && gz_sign_partials_out(h.p[1].e, scope) == GZ_SIGN_OUT_NONE);
    CHECK(h.errors == 0);
    h_free(&h);
    g_h_now = 0;
}

/* Review A of PR 81: a round this start does not hold (here its builder no longer rebuilds it, as for an
 * earlier epoch's) whose ack was saved comes back Complete, not Unfinished: the host may fund it, so it is
 * never Abandoned at the unfinished deadline and its lobby stays unleavable. */
static void test_unheld_complete_stays_complete(void)
{
    harness_t h;
    uint8_t id[32], scope[32];
    h_init(&h, 1);
    h.builder.tip = 1000;
    CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
    h_flush(&h, 100000);
    const gz_sign_round_t *r = h_newest(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_COMPLETE);
    if (!r) { h_free(&h); return; }
    memcpy(id, r->id, 32); memcpy(scope, r->def.outer_digest, 32);
    h.unfinished_ticks = 3;
    h.builder.refuse_replay = 1;
    CHECK(h_restart(&h, 1) == GZ_OK);
    gz_sign_t *e = h.p[1].e;
    gz_sign_exposed_t *x = evicted(e, id);
    CHECK(h_find(&h, 1, id) == NULL && x != NULL);
    if (x) {
        CHECK(x->state == GZ_SIGN_ROUND_COMPLETE && x->ack_tip == 1000 && x->has_scope && !memcmp(x->scope, scope, 32));
        for (int k = 0; k < 6; k++) h_tick(&h, 1);
        CHECK(x->state == GZ_SIGN_ROUND_COMPLETE && gz_sign_partials_out(e, scope) == GZ_SIGN_OUT_THIS);
    }
    h.builder.refuse_replay = 0;
    h_free(&h);
}

static void tip_to(harness_t *h, uint32_t g, uint32_t height)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_CHAIN;
    ev.u.chain.kind = GZ_CHAIN_NEW_TIP;
    ev.u.chain.height = height;
    h_event(h, g, &ev);
}

/* Through the real flow (review B of PR 81, B-4; review A, S1): a member acks a round, and GZ_SIGN_MAX_ROUNDS
 * newer rounds push it out of memory Complete. Its exposure entry knows its lobby: that lobby's leave is
 * refused, another lobby's is not. Then C11's funding deadline (B-1): a host that never funds keeps it until
 * a tip reaches the ack tip plus funding_deadline_blocks, no longer; every Complete round, held or not, is
 * Abandoned and saved so, and after a restart the lobby can be left. */
static void test_partials_out_real_flow(void)
{
    harness_t h;
    uint8_t first[32], scope[32], other[32];
    memset(other, 0x7d, 32);
    h_init(&h, 1);
    h.builder.tip = 1000;
    gz_sign_t *e = h.p[1].e;
    e->cfg.funding_deadline_blocks = 36;
    CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
    h_flush(&h, 100000);
    const gz_sign_round_t *r = h_newest(&h, 1);
    CHECK(r && r->state == GZ_SIGN_ROUND_COMPLETE);
    if (!r) { h_free(&h); return; }
    memcpy(first, r->id, 32); memcpy(scope, r->def.outer_digest, 32);
    for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
        CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
        h_flush(&h, 100000);
    }
    gz_sign_exposed_t *x = evicted(e, first);
    CHECK(h_find(&h, 1, first) == NULL && x != NULL);
    if (x) CHECK(x->state == GZ_SIGN_ROUND_COMPLETE && x->has_scope && !memcmp(x->scope, scope, 32) && x->ack_tip == 1000);
    CHECK(gz_sign_partials_out(e, scope) == GZ_SIGN_OUT_THIS && gz_sign_partials_out(e, other) == GZ_SIGN_OUT_NONE);
    tip_to(&h, 1, 1035);                                             /* before the deadline */
    CHECK(gz_sign_partials_out(e, scope) == GZ_SIGN_OUT_THIS && (!x || x->state == GZ_SIGN_ROUND_COMPLETE));
    for (int k = 0; k < 4; k++) tip_to(&h, 1, 1036 + (uint32_t)k);    /* at it: a few each step */
    if (x) CHECK(x->state == GZ_SIGN_ROUND_ABANDONED);
    CHECK(gz_sign_partials_out(e, scope) == GZ_SIGN_OUT_NONE);
    CHECK(h_restart(&h, 1) == GZ_OK);                                /* saved: it stays so */
    e = h.p[1].e;
    CHECK(gz_sign_partials_out(e, scope) == GZ_SIGN_OUT_NONE);
    CHECK(h.errors == 0);
    h_free(&h);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_masks();
    test_one_nonce();
    test_one_partial();
    test_no_unset_slot();
    test_host_verify_final();
    test_wipe_after_sign();
    test_definition_lines();
    test_nospace_exposure();
    test_short_lists();
    test_evicted_unresolved();
    test_exposure_room();
    test_padded_ack();
    test_padded_proposal();
    test_record_bounds();
    test_restart_after_padding();
    test_unfinished_across_restart();
    test_replay_filter_hit();
    test_start_begins_next_tier();
    test_failed_engine_holds_no_secret();
    test_resolve_errors();
    test_c10_active_with_partials();
    test_exposures_recover();
    test_nonce_inputs_wiped();
    test_all_nonces_other_tier();
    test_decode_first();
    test_revived_round_across_restart();
    test_c7_at_signing();
    test_member_outcomes();
    test_ignore_unaccepted();
    test_attempt_required();
    test_keys_still_rounds();
    test_older_attempt();
    test_exposure_per_round();
    test_excuse_only_released();
    test_early_nonces();
    test_ack_waits_for_tip();
    test_partials_out();
    test_partials_out_clears();
    test_unfinished_deadline_across_restart();
    test_unheld_complete_stays_complete();
    test_partials_out_real_flow();
    printf("  illegal-argument callbacks: %d\n", g_illegal);
    CHECK(g_illegal == 0);
    if (g_ctx) secp256k1_context_destroy(g_ctx);
    return check_done();
}
