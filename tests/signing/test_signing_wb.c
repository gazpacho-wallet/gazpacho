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
        memcpy(psig, r->psig[i][s], 32);
        CHECK(sign_item(h.p[1].e, r, i, out) == 0);                      /* no secret nonce */
        r->secnonce_serial[i] = 77;                                       /* a serial, the slot filled */
        CHECK(sign_item(h.p[1].e, r, i, out) == 0);
        CHECK(g_illegal == illegal && memcmp(psig, r->psig[i][s], 32) == 0);
        CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE] == made);
        r->secnonce_serial[i] = 0;
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
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_MESSAGE_RECEIVED; ev.u.message.peer_id = 0;
    ev.u.message.bytes.data = h.q[k].b; ev.u.message.bytes.len = h.q[k].len;
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
            memset(&ev, 0, sizeof ev);
            ev.kind = GZ_EVENT_MESSAGE_RECEIVED; ev.u.message.peer_id = m.from;
            ev.u.message.bytes.data = m.b; ev.u.message.bytes.len = m.len;
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
    CHECK(gz_sign_resolve(h.p[1].e, a, GZ_SIGN_END_DEAD, &list) == GZ_ERR_ARGUMENT);   /* Live is final */
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
    static uint8_t funding[GZ_SIGN_MAX_FUNDING_TX + 1], msg[GZ_SIGN_MAX_SMALL_MSG];
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
        em.out = &list; em.st = GZ_OK;
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
        em.out = &list; em.st = GZ_OK;
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
        em.out = &list; em.st = GZ_OK;
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
static void test_unfinished_across_restart(void)
{
    for (int restart = 0; restart < 2; restart++)
        for (int by_deadline = 0; by_deadline < 2; by_deadline++) {
            harness_t h;
            uint8_t id1[32], id5[32];
            gz_action_list_t list;
            h_init(&h, 1);
            for (int k = 0; k < 5; k++) {
                CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
                flush_without(&h, 1, GZ_SIGN_MSG_RESULT, GZ_SIGN_MSG_COMPLETE);
                const gz_sign_round_t *r = h_newest(&h, 1);
                CHECK(r && r->state == GZ_SIGN_ROUND_ACTIVE && r->ever_partial);
                if (r && k == 0) memcpy(id1, r->id, 32);
                if (r && k == 4) memcpy(id5, r->id, 32);
            }
            gz_sign_t *e = h.p[1].e;
            CHECK(!find(e, id1) && evicted(e, id1) && evicted(e, id1)->state == GZ_SIGN_ROUND_UNFINISHED);
            CHECK(unresolved(e) == 5 && e->n_exposures == 5);
            if (restart) {
                CHECK(h_restart(&h, 1) == GZ_OK);
                e = h.p[1].e;
                /* its true state again: Unfinished, not Active; and the same rounds in memory as before */
                CHECK(!find(e, id1) && evicted(e, id1) && evicted(e, id1)->state == GZ_SIGN_ROUND_UNFINISHED);
                CHECK(unresolved(e) == 5 && e->n_exposures == 5);
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
                CHECK(h.p[1].n_recs == recs + 1 && evicted(e, id1)->state == GZ_SIGN_ROUND_ABANDONED && unresolved(e) == 4);   /* C10 lets go */
            }
            for (int i = 0; i < 80; i++) h_tick(&h, 1);
            CHECK(unresolved(e) == 0 && evicted(e, id1) && evicted(e, id1)->state == GZ_SIGN_ROUND_ABANDONED);
            CHECK(count_recs(&h, 1, GZ_SIGN_REC_ROUND_ENDED) == 5);                /* one each, no more */
            CHECK(h_restart(&h, 1) == GZ_OK && unresolved(h.p[1].e) == 0);
            CHECK(evicted(h.p[1].e, id1) && evicted(h.p[1].e, id1)->state == GZ_SIGN_ROUND_ABANDONED);
            /* Abandoned moves on to Dead, also for the round that left memory: then its record leaves C7 (B8) */
            gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
            CHECK(gz_sign_resolve(h.p[1].e, id1, GZ_SIGN_END_DEAD, &list) == GZ_OK && h.p[1].e->n_exposures == 4);
            h_apply(&h, 1, &list);
            CHECK(h_restart(&h, 1) == GZ_OK && h.p[1].e->n_exposures == 4 && !evicted(h.p[1].e, id1) && h.errors == 0);
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
            gz_storage_reader_t rd = {h_next, h_rewind, p, p->incarnation, 0};
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
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_MESSAGE_RECEIVED; ev.u.message.peer_id = 0;
        ev.u.message.bytes.data = h.q[k].b; ev.u.message.bytes.len = h.q[k].len;
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
    printf("  illegal-argument callbacks: %d\n", g_illegal);
    CHECK(g_illegal == 0);
    if (g_ctx) secp256k1_context_destroy(g_ctx);
    return check_done();
}
