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
    printf("  illegal-argument callbacks: %d\n", g_illegal);
    CHECK(g_illegal == 0);
    if (g_ctx) secp256k1_context_destroy(g_ctx);
    return check_done();
}
