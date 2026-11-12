/* Scripted scenarios on the direct harness: each asserts the exact messages,
 * abort reasons, states and counters it should produce, and pins the whole
 * transcript (every action and every party's state after every event) to a
 * digest. Included by test_signing.c. */
#ifndef GZ_TEST_SIGNING_SCENARIOS_H
#define GZ_TEST_SIGNING_SCENARIOS_H

#include "harness.h"

static uint32_t be32p(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

/* Items of party j in tier t of a round, in index order. */
static int items_of(const gz_sign_round_t *r, uint32_t j, int t, uint32_t *out)
{
    int n = 0;
    for (int i = 0; i < r->def.n_items; i++) {
        if (t >= 0 && r->def.items[i].tier != t) continue;
        for (int s = 0; s < r->def.items[i].n_signers; s++)
            if (r->def.items[i].signers[s] == j) { if (out) out[n] = (uint32_t)i; n++; }
    }
    return n;
}

/* Index of the first queued message from -> to of `kind`, or -1. */
static long q_find(const harness_t *h, uint32_t from, uint32_t to, uint8_t kind)
{
    for (size_t i = 0; i < h->nq; i++)
        if (h->q[i].from == from && h->q[i].to == to && h->q[i].len > 2 && h->q[i].b[2] == kind) return (long)i;
    return -1;
}

/* Deliver in order until party `from` has sent `count` messages of `kind`. */
static void flush_until(harness_t *h, uint32_t from, uint8_t kind, size_t count)
{
    while (h->nq && h_count_kind(h, from, kind) < count) h_deliver(h, 0, 0);
}

/* An abort as `from` (participant index = party here) would sign it. */
static size_t make_abort(uint8_t *out, const uint8_t id[32], uint8_t reason, uint8_t tier, uint32_t from)
{
    size_t n = 0;
    out[n++] = 'G'; out[n++] = 'S'; out[n++] = GZ_MSG_ABORT;
    memcpy(out + n, id, 32); n += 32;
    out[n++] = reason; out[n++] = tier; out[n++] = 0; out[n++] = 0;
    w_resign(out, n, from);
    return n + 64;
}

static size_t make_status(uint8_t *out, const uint8_t id[32])
{
    out[0] = 'G'; out[1] = 'S'; out[2] = GZ_MSG_STATUS;
    memcpy(out + 3, id, 32);
    return 35;
}

/* An abort that went out: its reason, tier and items. */
static int check_abort(const h_sent_t *s, uint8_t reason, uint8_t tier, int n, const uint32_t *items)
{
    gz_sign_msg_t m;
    if (!s || !gz_sign_decode(s->b, s->len, &m) || m.kind != GZ_MSG_ABORT) return 0;
    if (m.reason != reason || m.tier != tier || m.n != n) return 0;
    for (int k = 0; k < n; k++) if (be32p(m.entry[k]) != items[k]) return 0;
    return 1;
}

/* What a party holds of each round, in a form that must survive a restart. */
typedef struct { uint8_t id[32]; uint8_t state, ts0, ts1; uint16_t acked; uint8_t finals[GZ_SIGN_MAX_ITEMS][64]; uint32_t tail; } held_t;
static size_t held_view(const harness_t *h, uint32_t g, held_t *out)
{
    size_t n = 0;
    for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
        const gz_sign_round_t *r = &h->p[g].e->rounds[k];
        if (r->state == GZ_ROUND_FREE) continue;
        memset(&out[n], 0, sizeof out[n]);
        memcpy(out[n].id, r->id, 32);
        out[n].state = r->state; out[n].ts0 = r->tier_state[0]; out[n].ts1 = r->tier_state[1]; out[n].acked = r->acked;
        memcpy(out[n].finals, r->final_sig, sizeof out[n].finals);
        out[n].tail = r->tail_len;
        n++;
    }
    return n;
}
static int same_held(const held_t *a, size_t na, const held_t *b, size_t nb)
{
    if (na != nb) return 0;
    for (size_t i = 0; i < na; i++) {
        size_t j = 0;
        while (j < nb && memcmp(a[i].id, b[j].id, 32) != 0) j++;
        if (j == nb || memcmp(&a[i], &b[j], sizeof a[i]) != 0) return 0;
    }
    return 1;
}

/* Restart every party; what each holds must not change. */
static void check_restart_keeps(harness_t *h)
{
    static held_t before[GZ_SIGN_MAX_ROUNDS], after[GZ_SIGN_MAX_ROUNDS];
    for (uint32_t g = 0; g < h->n; g++) {
        size_t nb = held_view(h, g, before);
        size_t known = h->p[g].e->n_known;
        CHECK(h_restart(h, g) == GZ_OK);
        size_t na = held_view(h, g, after);
        CHECK(same_held(before, nb, after, na));
        CHECK(h->p[g].e->n_known == known);
    }
}

static void honest_counts(harness_t *h, uint8_t tiers)
{
    const gz_sign_round_t *r = h_newest(h, 0);
    int items = r->def.n_items, psigs = 0;
    for (int i = 0; i < items; i++) psigs += r->def.items[i].n_signers - 1;
    CHECK(r->state == GZ_ROUND_DONE && r->acked == (uint16_t)(((1u << h->n) - 1u) & ~1u));
    const uint64_t *c = h->p[0].e->counters;
    CHECK(c[GZ_SIGN_COUNT_NONCES_MADE] == (uint64_t)items && c[GZ_SIGN_COUNT_PARTIALS_MADE] == (uint64_t)items);
    CHECK(c[GZ_SIGN_COUNT_PSIGS_VERIFIED] == (uint64_t)psigs && c[GZ_SIGN_COUNT_FINALS_VERIFIED] == (uint64_t)items);
    CHECK(c[GZ_SIGN_COUNT_REJECTED] == 0 && c[GZ_SIGN_COUNT_BLAME_FAULT] == 0 && c[GZ_SIGN_COUNT_BLAME_SILENT] == 0);
    for (uint32_t j = 1; j < h->n; j++) {
        const gz_sign_round_t *m = h_find(h, j, r->id);
        const uint64_t *mc = h->p[j].e->counters;
        int mine = items_of(r, j, -1, NULL);
        CHECK(m && m->state == GZ_ROUND_COMPLETE && memcmp(m->final_sig, r->final_sig, sizeof r->final_sig) == 0);
        CHECK(mc[GZ_SIGN_COUNT_NONCES_MADE] == (uint64_t)mine && mc[GZ_SIGN_COUNT_PARTIALS_MADE] == (uint64_t)mine);
        CHECK(mc[GZ_SIGN_COUNT_FINALS_VERIFIED] == (uint64_t)items && mc[GZ_SIGN_COUNT_REJECTED] == 0 && mc[GZ_SIGN_COUNT_DUPLICATES] == 0);
        /* Each message, exactly: one nonce message per tier with items, one partial message, one ack. */
        int tiers_with = 0;
        for (int t = 0; t < tiers; t++) tiers_with += items_of(r, j, t, NULL) > 0;
        CHECK(h_count_kind(h, j, GZ_MSG_NONCES) == (size_t)tiers_with && h_count_kind(h, j, GZ_MSG_PARTIALS) == (size_t)tiers_with);
        CHECK(h_count_kind(h, j, GZ_MSG_ACK) == 1 && h_count_kind(h, j, GZ_MSG_ABORT) == 0 && h_count_kind(h, j, GZ_MSG_STATUS) == 0);
        size_t nth = 0;
        for (int t = 0; t < tiers; t++) {
            uint32_t list[GZ_SIGN_MAX_ITEMS];
            int n = items_of(r, j, t, list);
            if (!n) continue;
            const h_sent_t *ns = h_sent_kind(h, j, GZ_MSG_NONCES, nth), *ps = h_sent_kind(h, j, GZ_MSG_PARTIALS, nth);
            nth++;
            gz_sign_msg_t mn, mp;
            CHECK(ns && ns->len == 38 + (size_t)n * 134 && gz_sign_decode(ns->b, ns->len, &mn) && mn.tier == t && mn.n == n);
            CHECK(ps && ps->len == 38 + (size_t)n * 68 + 64 && gz_sign_decode(ps->b, ps->len, &mp) && mp.tier == t && mp.n == n);
            for (int k = 0; ns && ps && k < n; k++) {
                CHECK(be32p(mn.entry[k]) == list[k] && be32p(mp.entry[k]) == list[k]);
                /* the nonce sent is the one the host holds for that signer, and the set digest is over the host's set */
                int s = 0;
                while (r->def.items[list[k]].signers[s] != j) s++;
                CHECK(memcmp(mn.entry[k] + 4, r->nonce[list[k]][s], 66) == 0);
                gz_sha256_t sd;
                uint8_t d[32];
                gz_tagged_init(&sd, "gazpacho/nonceset");
                for (int q = 0; q < r->def.items[list[k]].n_signers; q++) gz_sha256_write(&sd, r->nonce[list[k]][q], 66);
                gz_sha256_done(&sd, d);
                CHECK(memcmp(mp.entry[k] + 36, d, 32) == 0 && memcmp(mp.entry[k] + 4, r->psig[list[k]][s], 32) == 0);
            }
        }
        /* the ack names what the member holds: TH(held, id || every final signature) */
        const h_sent_t *ack = h_sent_kind(h, j, GZ_MSG_ACK, 0);
        gz_sha256_t hs;
        uint8_t d[32];
        gz_tagged_init(&hs, "gazpacho/held");
        gz_sha256_write(&hs, r->id, 32);
        for (int i = 0; i < items; i++) gz_sha256_write(&hs, r->final_sig[i], 64);
        gz_sha256_done(&hs, d);
        CHECK(ack && ack->len == 35 + 32 + 64 && memcmp(ack->b + 35, d, 32) == 0);
        /* the member's journal, in order */
        static const uint32_t one[] = {GZ_REC_M_STARTED, GZ_REC_M_SIGNED, GZ_REC_M_RESULT, GZ_REC_M_COMPLETE};
        if (tiers == 1) {
            CHECK(h->p[j].n_recs == 4);
            for (int k = 0; k < 4 && h->p[j].n_recs == 4; k++) CHECK(h->p[j].recs[k].type == one[k]);
        }
    }
    /* the host: one proposal, one nonce set and one result per member per tier, one complete each */
    CHECK(h_count_kind(h, 0, GZ_MSG_PROPOSE) == h->n - 1 && h_count_kind(h, 0, GZ_MSG_COMPLETE) == h->n - 1);
    size_t sets = 0;                     /* a nonce set only to members with items in the tier */
    for (int t = 0; t < tiers; t++)
        for (uint32_t j = 1; j < h->n; j++) sets += items_of(r, j, t, NULL) > 0;
    CHECK(h_count_kind(h, 0, GZ_MSG_ALL_NONCES) == sets && h_count_kind(h, 0, GZ_MSG_RESULT) == (size_t)(h->n - 1) * tiers);
    CHECK(h->p[0].n_recs == (size_t)(1 + tiers + 1 + (h->n - 1)));
    const h_sent_t *res = h_sent_kind(h, 0, GZ_MSG_RESULT, 0);
    gz_sign_msg_t mr;
    int tier0 = 0;
    for (int i = 0; i < items; i++) tier0 += r->def.items[i].tier == 0;
    CHECK(res && gz_sign_decode(res->b, res->len, &mr) && mr.n == tier0 && res->len == 38 + (size_t)tier0 * 68 + 64);
}

/* ---- the scenarios; each returns its transcript digest ---- */

static uint64_t sc_honest(int tiers)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, (uint8_t)tiers, 3, 0) == GZ_OK);
    h_flush(&h, 100000);
    honest_counts(&h, (uint8_t)tiers);
    CHECK(h.errors == 0);
    check_restart_keeps(&h);
    h_ticks(&h, 4);            /* after a restart nothing is owed: members resend acks to a host that ignores them */
    CHECK(h_newest(&h, 0)->state == GZ_ROUND_DONE);
    uint64_t d = h_digest(&h);
    h_free(&h);
    return d;
}

/* Every message delivered twice; then everything in reverse order. */
static uint64_t sc_duplicates(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
    while (h.nq) { h_deliver(&h, 0, 1); h_deliver(&h, 0, 0); }
    const gz_sign_round_t *r = h_newest(&h, 0);
    CHECK(r->state == GZ_ROUND_DONE && h.p[0].e->counters[GZ_SIGN_COUNT_REJECTED] == 0);
    CHECK(h.p[0].e->counters[GZ_SIGN_COUNT_DUPLICATES] > 0 && h.p[0].e->counters[GZ_SIGN_COUNT_BLAME_FAULT] == 0);
    for (uint32_t j = 1; j <= 3; j++) {
        CHECK(h_find(&h, j, r->id)->state == GZ_ROUND_COMPLETE);
        CHECK(h.p[j].e->counters[GZ_SIGN_COUNT_DUPLICATES] == 1);      /* the proposal, answered from what was saved */
        /* every resend is the same bytes */
        const h_sent_t *n0 = h_sent_kind(&h, j, GZ_MSG_NONCES, 0), *n1 = h_sent_kind(&h, j, GZ_MSG_NONCES, 1);
        CHECK(n0 && n1 && n0->len == n1->len && memcmp(n0->b, n1->b, n0->len) == 0);
        const h_sent_t *p0 = h_sent_kind(&h, j, GZ_MSG_PARTIALS, 0), *p1 = h_sent_kind(&h, j, GZ_MSG_PARTIALS, 1);
        CHECK(p0 && p1 && p0->len == p1->len && memcmp(p0->b, p1->b, p0->len) == 0);
        const h_sent_t *a0 = h_sent_kind(&h, j, GZ_MSG_ACK, 0), *a1 = h_sent_kind(&h, j, GZ_MSG_ACK, 1);
        CHECK(a0 && a1 && a0->len == a1->len && memcmp(a0->b, a1->b, a0->len) == 0);
    }
    /* acks counted once each */
    size_t acks = 0;
    for (size_t i = 0; i < h.p[0].n_recs; i++) acks += h.p[0].recs[i].type == GZ_REC_H_ACK;
    CHECK(acks == 3);
    uint64_t d = h_digest(&h);
    h_free(&h);

    h_init(&h, 4);
    CHECK(h_begin(&h, 1, 4, 0) == GZ_OK);
    while (h.nq) h_deliver(&h, h.nq - 1, 0);
    h_ticks(&h, 4);                                /* a complete that came before its result was ignored: resent */
    CHECK(h_newest(&h, 0)->state == GZ_ROUND_DONE);
    d ^= h_digest(&h);
    h_free(&h);
    return d;
}

/* A member restarts after its nonces left and before the nonce set came. */
static uint64_t sc_member_restart_nonces(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    flush_until(&h, 3, GZ_MSG_NONCES, 1);
    CHECK(h_restart(&h, 2) == GZ_OK);
    const gz_sign_round_t *r1 = h_oldest(&h, 2);
    CHECK(r1 && r1->state == GZ_ROUND_ABORTED && r1->why == GZ_WHY_RESTARTED && !r1->ever_partial);
    for (int i = 0; r1 && i < r1->def.n_items; i++) CHECK(r1->secnonce_serial[i] == 0);
    CHECK(check_abort(h_sent_kind(&h, 2, GZ_MSG_ABORT, 0), GZ_WHY_RESTARTED, 0xff, 0, NULL));
    CHECK(h.p[2].recs[h.p[2].n_recs - 1].type == GZ_REC_M_ABORTED);
    uint8_t id1[32];
    memcpy(id1, r1->id, 32);
    /* the proposal again: the same abort, never a second nonce */
    const h_sent_t *prop = h_sent_kind(&h, 0, GZ_MSG_PROPOSE, 0);
    h_inject(&h, 0, 2, prop->b, prop->len);
    CHECK(h_count_kind(&h, 2, GZ_MSG_NONCES) == 1 && h_count_kind(&h, 2, GZ_MSG_ABORT) == 2);
    const h_sent_t *a0 = h_sent_kind(&h, 2, GZ_MSG_ABORT, 0), *a1 = h_sent_kind(&h, 2, GZ_MSG_ABORT, 1);
    CHECK(a0->len == a1->len && memcmp(a0->b, a1->b, a0->len) == 0);
    h_flush(&h, 100000);
    h_ticks(&h, 2);
    const gz_sign_round_t *hr = h_find(&h, 0, id1);
    CHECK(hr && hr->state == GZ_ROUND_FAILED && hr->why == GZ_WHY_MEMBER_ABORT && hr->blamed == 0);
    CHECK(h.p[0].e->attempts == 2 && h_newest(&h, 0)->state == GZ_ROUND_DONE);
    CHECK(h_count_kind(&h, 2, GZ_MSG_PARTIALS) == 1);                 /* only in the second attempt */
    for (uint32_t j = 1; j <= 3; j += 2) {                             /* the others signed attempt 1, then were superseded */
        const gz_sign_round_t *m = h_find(&h, j, id1);
        CHECK(m && m->state == GZ_ROUND_UNFINISHED && m->why == GZ_WHY_SUPERSEDED && m->ever_partial);
    }
    uint64_t d = h_digest(&h);
    h_free(&h);
    return d;
}

/* A member restarts after its partial signatures left: it resends the saved bytes and asks. */
static uint64_t sc_member_restart_signed(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    flush_until(&h, 1, GZ_MSG_PARTIALS, 1);
    CHECK(h_restart(&h, 1) == GZ_OK);
    CHECK(h_count_kind(&h, 1, GZ_MSG_PARTIALS) == 2 && h_count_kind(&h, 1, GZ_MSG_STATUS) == 1);
    const h_sent_t *p0 = h_sent_kind(&h, 1, GZ_MSG_PARTIALS, 0), *p1 = h_sent_kind(&h, 1, GZ_MSG_PARTIALS, 1);
    CHECK(p0->len == p1->len && memcmp(p0->b, p1->b, p0->len) == 0);
    const gz_sign_round_t *m = h_newest(&h, 1);
    CHECK(m->state == GZ_ROUND_ACTIVE && m->tier_state[0] == GZ_TIER_SIGNED && m->ever_partial);
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 0)->state == GZ_ROUND_DONE && h.p[0].e->attempts == 1);
    CHECK(h.p[0].e->counters[GZ_SIGN_COUNT_DUPLICATES] > 0);
    uint64_t d = h_digest(&h);
    h_free(&h);
    return d;
}

/* Two tiers: a member Unfinished in tier 1 answers per item. */
static uint64_t sc_tier_abort(void)
{
    harness_t h;
    h_init(&h, 4);
    CHECK(h_begin(&h, 2, 4, 0) == GZ_OK);
    const gz_sign_round_t *r = h_newest(&h, 0);
    uint32_t j = 1;                     /* a member with items in tier 1, not as many as in tier 0 */
    while (j <= 4 && (items_of(r, j, 1, NULL) == 0 || items_of(r, j, 1, NULL) == items_of(r, j, 0, NULL))) j++;
    CHECK(j <= 4);
    flush_until(&h, j, GZ_MSG_NONCES, 2);
    uint32_t list[GZ_SIGN_MAX_ITEMS];
    int n = items_of(r, j, 1, list);
    uint8_t ab[200];
    size_t len = make_abort(ab, r->id, GZ_WHY_DEADLINE, 0xff, 0);
    h_inject(&h, 0, j, ab, len);
    const gz_sign_round_t *m = h_newest(&h, j);
    CHECK(m->state == GZ_ROUND_UNFINISHED && m->why == GZ_WHY_HOST_ABORT && m->tier == 1);
    CHECK(check_abort(h_sent_kind(&h, j, GZ_MSG_ABORT, 0), GZ_WHY_HOST_ABORT, 1, n, list));
    for (int i = 0; i < m->def.n_items; i++) CHECK(m->secnonce_serial[i] == 0);
    /* an abort that is not the host's changes nothing */
    uint32_t k = j == 1 ? 2 : 1;
    harness_t h2;
    h_init(&h2, 4);
    CHECK(h_begin(&h2, 2, 4, 0) == GZ_OK);
    flush_until(&h2, j, GZ_MSG_NONCES, 2);
    len = make_abort(ab, h_newest(&h2, 0)->id, GZ_WHY_DEADLINE, 0xff, k);
    h_inject(&h2, 0, j, ab, len);
    CHECK(h_newest(&h2, j)->state == GZ_ROUND_ACTIVE);
    h_inject(&h2, k, j, ab, len);
    CHECK(h_newest(&h2, j)->state == GZ_ROUND_ACTIVE);
    /* restart there: per item again, then the replayed proposal gets the same answer */
    CHECK(h_restart(&h2, j) == GZ_OK);
    m = h_newest(&h2, j);
    CHECK(m->state == GZ_ROUND_UNFINISHED && m->why == GZ_WHY_RESTARTED);
    CHECK(check_abort(h_sent_kind(&h2, j, GZ_MSG_ABORT, 0), GZ_WHY_RESTARTED, 1, n, list));
    const h_sent_t *prop = h_sent_kind(&h2, 0, GZ_MSG_PROPOSE, 0);
    h_inject(&h2, 0, j, prop->b, prop->len);
    CHECK(check_abort(h_sent_kind(&h2, j, GZ_MSG_ABORT, 1), GZ_WHY_RESTARTED, 1, n, list));
    CHECK(h_count_kind(&h2, j, GZ_MSG_NONCES) == 2);
    uint64_t d = h_digest(&h) ^ h_digest(&h2);
    h_free(&h); h_free(&h2);
    return d;
}

/* The host restarts while collecting, then after complete with no acks yet. */
static uint64_t sc_host_restarts(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    uint8_t id1[32];
    memcpy(id1, h_newest(&h, 0)->id, 32);
    flush_until(&h, 3, GZ_MSG_NONCES, 1);
    CHECK(h_restart(&h, 0) == GZ_OK);
    const gz_sign_round_t *r = h_find(&h, 0, id1);
    CHECK(r && r->state == GZ_ROUND_FAILED && r->why == GZ_WHY_HOST_RESTART && r->blamed == 0);
    CHECK(h.p[0].e->attempts == 2 && memcmp(h_newest(&h, 0)->id, id1, 32) != 0);
    CHECK(h.p[0].recs[h.p[0].n_recs - 1].type == GZ_REC_H_PROPOSED);
    h_flush(&h, 100000);
    for (uint32_t j = 1; j <= 3; j++) {
        const gz_sign_round_t *m = h_find(&h, j, id1);
        CHECK(m && m->state == GZ_ROUND_ABORTED && (m->why == GZ_WHY_HOST_ABORT || m->why == GZ_WHY_SUPERSEDED));
    }
    CHECK(h_newest(&h, 0)->state == GZ_ROUND_DONE);
    /* a status request about the failed attempt: its abort and reason */
    uint8_t st[35];
    size_t before = h_count_kind(&h, 0, GZ_MSG_ABORT);
    h_inject(&h, 1, 0, st, make_status(st, id1));
    CHECK(h_count_kind(&h, 0, GZ_MSG_ABORT) == before + 1);
    CHECK(check_abort(&h.sent[h.n_sent - 1], GZ_WHY_HOST_RESTART, 0xff, 0, NULL) && h.sent[h.n_sent - 1].peer == 1);
    /* about an identifier nobody knows: nothing */
    uint8_t other[32] = {1};
    size_t sent = h.n_sent;
    h_inject(&h, 1, 0, st, make_status(st, other));
    CHECK(h.n_sent == sent);
    uint64_t d = h_digest(&h);
    h_free(&h);

    /* After complete, before any ack: the restarted host sends every result and complete again. */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    flush_until(&h, 0, GZ_MSG_COMPLETE, 3);
    size_t results = h_count_kind(&h, 0, GZ_MSG_RESULT);
    CHECK(h_restart(&h, 0) == GZ_OK);
    CHECK(h_newest(&h, 0)->state == GZ_ROUND_COMPLETE && h.p[0].e->attempts == 1);
    CHECK(h_count_kind(&h, 0, GZ_MSG_RESULT) == results + 3 && h_count_kind(&h, 0, GZ_MSG_COMPLETE) == 6);
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 0)->state == GZ_ROUND_DONE && h_newest(&h, 0)->acked == 0xe);
    check_restart_keeps(&h);
    CHECK(h_newest(&h, 0)->state == GZ_ROUND_DONE);
    /* a status request now: every result and the complete, to that member only */
    sent = h.n_sent;
    uint8_t st2[35];
    h_inject(&h, 2, 0, st2, make_status(st2, h_newest(&h, 0)->id));
    CHECK(h.n_sent == sent + 2 && h.sent[sent].kind == GZ_MSG_RESULT && h.sent[sent + 1].kind == GZ_MSG_COMPLETE && h.sent[sent].peer == 2);
    d ^= h_digest(&h);
    h_free(&h);
    return d;
}

/* Silence: a member that never hears, a withheld ack, a host that never hears. */
static uint64_t sc_timers(void)
{
    harness_t h;
    h_init(&h, 3);
    h.drop_to = 1u << 3;
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    uint8_t id1[32];
    memcpy(id1, h_newest(&h, 0)->id, 32);
    h_flush(&h, 100000);
    for (int t = 0; t < 11; t++) h_ticks(&h, 1);
    CHECK(h_find(&h, 0, id1)->state == GZ_ROUND_ACTIVE);             /* one tick before the deadline */
    h_ticks(&h, 1);
    const gz_sign_round_t *r = h_find(&h, 0, id1);
    CHECK(r->state == GZ_ROUND_FAILED && r->why == GZ_WHY_DEADLINE && r->blamed == 1u << 3);
    CHECK(h.p[0].e->counters[GZ_SIGN_COUNT_BLAME_SILENT] == 1 && h.p[0].e->counters[GZ_SIGN_COUNT_BLAME_FAULT] == 0);
    size_t to3 = 0;
    for (size_t i = 0; i < h.n_sent; i++) to3 += h.sent[i].party == 0 && h.sent[i].peer == 3 && h.sent[i].kind == GZ_MSG_PROPOSE;
    CHECK(to3 == 1 + 12 / 3 - 1);                                     /* resent every third tick until the deadline */
    h_ticks(&h, 3);
    const gz_sign_round_t *r2 = h_newest(&h, 0);
    CHECK(r2->state == GZ_ROUND_DONE && r2->def.n_participants == 3 && h.p[0].e->attempts == 2);
    uint64_t d = h_digest(&h);
    h_free(&h);

    /* every ack lost: the host resends results, then gives the attempt up blaming all; no further attempt */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (h.nq && h_newest(&h, 0)->state != GZ_ROUND_COMPLETE) h_deliver(&h, 0, 0);
    h.drop_to = 1u;
    h_flush(&h, 100000);
    for (int t = 0; t < 12; t++) h_ticks(&h, 1);
    r = h_newest(&h, 0);
    CHECK(r->state == GZ_ROUND_FAILED && r->why == GZ_WHY_DEADLINE && r->blamed == 0xe && h.p[0].e->attempts == 1);
    CHECK(h_count_kind(&h, 0, GZ_MSG_RESULT) == 3 + 3 * 3);           /* first, then at ticks 3, 6 and 9 */
    for (uint32_t j = 1; j <= 3; j++) CHECK(h_newest(&h, j)->state == GZ_ROUND_COMPLETE);
    CHECK(h_count_kind(&h, 1, GZ_MSG_ACK) == 1 + 3);                 /* the ack again for each result set */
    d ^= h_digest(&h);
    h_free(&h);

    /* the host never hears: members give up at their deadline, Aborted, with the reason */
    h_init(&h, 3);
    h.drop_to = 1u;
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    h_flush(&h, 100000);
    for (int t = 0; t < 12; t++) h_ticks(&h, 1);
    for (uint32_t j = 1; j <= 3; j++) {
        const gz_sign_round_t *m = h_newest(&h, j);
        CHECK(m->state == GZ_ROUND_ABORTED && m->why == GZ_WHY_DEADLINE && m->tail_len > 0);
        CHECK(check_abort(h_sent_kind(&h, j, GZ_MSG_ABORT, 0), GZ_WHY_DEADLINE, 0xff, 0, NULL));
        CHECK(h.p[j].e->counters[GZ_SIGN_COUNT_REJECTED] == 1);
    }
    d ^= h_digest(&h);
    h_free(&h);

    /* a member waiting for a result resends its partial signatures and asks, every third tick; never Aborted */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    flush_until(&h, 1, GZ_MSG_PARTIALS, 1);
    h.drop_to = 1u << 1;
    h_flush(&h, 100000);
    for (int t = 0; t < 20; t++) h_tick(&h, 1);
    CHECK(h_newest(&h, 1)->state == GZ_ROUND_ACTIVE && h_newest(&h, 1)->tier_state[0] == GZ_TIER_SIGNED);
    CHECK(h_count_kind(&h, 1, GZ_MSG_PARTIALS) == 1 + 6 && h_count_kind(&h, 1, GZ_MSG_STATUS) == 6);
    d ^= h_digest(&h);
    h_free(&h);
    return d;
}

/* Forge a copy of queued message `i` and let `edit` change it. */
typedef void (*edit_fn)(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r);

static gz_status_t deliver_edited(harness_t *h, long i, edit_fn edit, int signer)
{
    static uint8_t b[GZ_SIGN_MAX_MSG];
    gz_sign_msg_t m;
    if (i < 0) return GZ_ERR_ARGUMENT;
    size_t len = h->q[i].len;
    uint32_t from = h->q[i].from, to = h->q[i].to;
    memcpy(b, h->q[i].b, len);
    h_drop_msg(h, (size_t)i);
    if (!gz_sign_decode(b, len, &m)) return GZ_ERR_ARGUMENT;
    edit(b, &len, &m, h_newest(h, 0));
    if (signer >= 0 && gz_sign_decode(b, len, &m) && m.sig) w_resign(b, m.signed_len, (uint32_t)signer);
    return h_inject(h, from, to, b, len);
}

static void ed_psig(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r) { (void)b; (void)len; (void)r; ((uint8_t *)(uintptr_t)m->entry[0])[4 + 31] ^= 1; ((uint8_t *)(uintptr_t)m->entry[0])[4] &= 0x7f; }
static void ed_setdigest(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r) { (void)b; (void)len; (void)r; ((uint8_t *)(uintptr_t)m->entry[0])[36] ^= 1; }
static void ed_index(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r)
{
    (void)b; (void)len;
    uint8_t *e = (uint8_t *)(uintptr_t)m->entry[0];
    for (uint32_t i = 0; i < r->def.n_items; i++) {        /* an item this signer does not sign */
        int has = 0;
        for (int s = 0; s < r->def.items[i].n_signers; s++) has |= r->def.items[i].signers[s] == 2;
        if (!has) { e[0] = (uint8_t)(i >> 24); e[1] = (uint8_t)(i >> 16); e[2] = (uint8_t)(i >> 8); e[3] = (uint8_t)i; return; }
    }
}
static void ed_tier(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r) { (void)len; (void)r; b[m->entry[0] - b - 3] = 1; }
static void ed_breaksig(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r) { (void)m; (void)r; b[*len - 1] ^= 1; }

/* The host's checks of what members send: who is blamed, and why. */
static uint64_t sc_host_faults(void)
{
    static const struct { uint8_t kind; edit_fn edit; int resign; uint8_t why; uint8_t blame; } cases[] = {
        {GZ_MSG_PARTIALS, ed_psig, 1, GZ_WHY_BAD_PARTIAL, 1},
        {GZ_MSG_PARTIALS, ed_setdigest, 1, GZ_WHY_BAD_PARTIAL, 1},
        {GZ_MSG_PARTIALS, ed_index, 1, GZ_WHY_BAD_MESSAGE, 1},
        {GZ_MSG_PARTIALS, ed_breaksig, 0, GZ_WHY_BAD_MESSAGE, 1},
        {GZ_MSG_PARTIALS, ed_tier, 1, GZ_WHY_NONE, 0},                  /* another tier: a duplicate, ignored */
        {GZ_MSG_NONCES, ed_index, 0, GZ_WHY_BAD_MESSAGE, 1},
        {GZ_MSG_NONCES, ed_breaksig, 0, GZ_WHY_BAD_NONCE, 1},            /* the last entry's nonce signature */
    };
    uint64_t d = 0;
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        uint8_t id[32];
        memcpy(id, h_newest(&h, 0)->id, 32);
        while (q_find(&h, 2, 0, cases[c].kind) < 0) h_deliver(&h, 0, 0);
        deliver_edited(&h, q_find(&h, 2, 0, cases[c].kind), cases[c].edit, cases[c].resign ? 2 : -1);
        const gz_sign_round_t *r = h_find(&h, 0, id);
        if (cases[c].blame) {
            if (!(r->state == GZ_ROUND_FAILED && r->why == cases[c].why && r->blamed == 1u << 2))
                printf("  host fault %zu: state %u why %u blamed %x\n", c, r->state, r->why, r->blamed);
            CHECK(r->state == GZ_ROUND_FAILED && r->why == cases[c].why && r->blamed == 1u << 2);
            CHECK(h.p[0].e->counters[GZ_SIGN_COUNT_BLAME_FAULT] == 1);
            for (uint32_t j = 1; j <= 3; j++) CHECK(h_count_kind(&h, 0, GZ_MSG_ABORT) == 3);
            CHECK(check_abort(h_sent_kind(&h, 0, GZ_MSG_ABORT, 0), cases[c].why, 0xff, 0, NULL));
            size_t i = h.p[0].n_recs;
            while (i && h.p[0].recs[i - 1].type != GZ_REC_H_FAILED) i--;
            CHECK(i && h.p[0].recs[i - 1].len == 37 && h.p[0].recs[i - 1].b[36] == cases[c].why && be32p(h.p[0].recs[i - 1].b + 32) == 1u << 2);
            h_flush(&h, 100000);
            h_ticks(&h, 2);
            CHECK(h_newest(&h, 0)->state == GZ_ROUND_DONE && h_newest(&h, 0)->def.n_participants == 3);
        } else {
            CHECK(r->state == GZ_ROUND_ACTIVE && h.p[0].e->counters[GZ_SIGN_COUNT_DUPLICATES] == 1);
        }
        d ^= h_digest(&h) + c;
        h_free(&h);
    }
    /* nonces from someone who is not in the round, and a second honest copy: no effect */
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (q_find(&h, 2, 0, GZ_MSG_NONCES) < 0) h_deliver(&h, 0, 0);
    long i = q_find(&h, 2, 0, GZ_MSG_NONCES);
    h_inject(&h, 7, 0, h.q[i].b, h.q[i].len);
    h_inject(&h, 2, 0, h.q[i].b, h.q[i].len);
    CHECK(h.p[0].e->counters[GZ_SIGN_COUNT_DUPLICATES] == 0);
    h_deliver(&h, (size_t)i, 0);
    CHECK(h_newest(&h, 0)->state == GZ_ROUND_ACTIVE && h.p[0].e->counters[GZ_SIGN_COUNT_DUPLICATES] == (uint64_t)items_of(h_newest(&h, 0), 2, 0, NULL));
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 0)->state == GZ_ROUND_DONE);
    /* an ack naming the wrong held set, then a second ack: neither changes anything */
    gz_sign_round_t *r = (gz_sign_round_t *)h_newest(&h, 0);
    const h_sent_t *ack = h_sent_kind(&h, 1, GZ_MSG_ACK, 0);
    static uint8_t bad[200];
    memcpy(bad, ack->b, ack->len);
    bad[40] ^= 1;
    w_resign(bad, 67, 1);
    r->acked &= (uint16_t)~2u; r->state = GZ_ROUND_COMPLETE;           /* pretend member 1's ack has not come */
    size_t recs = h.p[0].n_recs;
    h_inject(&h, 1, 0, bad, ack->len);
    CHECK(!(r->acked & 2u) && h.p[0].n_recs == recs);
    h_inject(&h, 1, 0, ack->b, ack->len);
    CHECK(r->acked == 0xe && r->state == GZ_ROUND_DONE && h.p[0].n_recs == recs + 1);
    h_inject(&h, 1, 0, ack->b, ack->len);
    CHECK(h.p[0].n_recs == recs + 1);
    d ^= h_digest(&h);
    h_free(&h);
    return d;
}

static void ea_own(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r)
{   /* the recipient's own nonce changed, and re-signed by it: still not its nonce */
    (void)b; (void)len;
    uint8_t *e = (uint8_t *)(uintptr_t)m->entry[0];
    uint32_t i = be32p(e);
    for (int s = 0; s < e[4]; s++)
        if (r->def.items[i].signers[s] == 1) {
            uint8_t *nonce = e + 5 + 130 * s;
            secp256k1_musig_secnonce sn;
            secp256k1_musig_pubnonce pn;
            uint8_t sid[32] = {3}, sk[32];
            secp256k1_pubkey pk;
            secp256k1_keypair kp;
            w_secret("test/factory", 1, sk);
            if (!secp256k1_keypair_create(w_ctx(), &kp, sk) || !secp256k1_keypair_pub(w_ctx(), &pk, &kp) ||
                !secp256k1_musig_nonce_gen(w_ctx(), &sn, &pn, sid, sk, &pk, NULL, NULL, NULL) ||
                !secp256k1_musig_pubnonce_serialize(w_ctx(), nonce, &pn)) abort();
            uint8_t entry[134];
            memcpy(entry, e, 4); memcpy(entry + 4, nonce, 66);
            w_sign_nonce(entry, m->round_id, m->tier, 1);
            memcpy(nonce + 66, entry + 70, 64);
        }
}
static void ea_other(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r)
{   (void)b; (void)len; (void)r; ((uint8_t *)(uintptr_t)m->entry[0])[5 + 40] ^= 1; }   /* the host's nonce, unsigned by it now */
static void ea_drop(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r)
{   /* the last entry left out */
    (void)r;
    size_t cut = (size_t)(b + *len - m->entry[m->n - 1]);
    *len -= cut;
    b[36] = (uint8_t)((m->n - 1) >> 8); b[37] = (uint8_t)(m->n - 1);
}
static void ea_twice(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r)
{   /* the first entry twice, in place of the second */
    (void)r; (void)len;
    size_t a = (size_t)(m->entry[1] - m->entry[0]);
    if ((size_t)(m->entry[1] - b) + a <= *len && m->entry[0][4] == m->entry[1][4])
        memcpy((uint8_t *)(uintptr_t)m->entry[1], m->entry[0], a);
    else memcpy((uint8_t *)(uintptr_t)m->entry[1], m->entry[0], 4);
}
static void ea_count(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r)
{   (void)b; (void)len; (void)r; ((uint8_t *)(uintptr_t)m->entry[0])[4]--; }
static void ea_foreign(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r)
{   /* the first entry renamed to an item the recipient does not sign */
    (void)b; (void)len;
    uint8_t *e = (uint8_t *)(uintptr_t)m->entry[0];
    for (uint32_t i = 0; i < r->def.n_items; i++) {
        int has = 0;
        for (int s = 0; s < r->def.items[i].n_signers; s++) has |= r->def.items[i].signers[s] == 1;
        if (!has) { e[0] = (uint8_t)(i >> 24); e[1] = (uint8_t)(i >> 16); e[2] = (uint8_t)(i >> 8); e[3] = (uint8_t)i; return; }
    }
}

/* The member's checks of a nonce set and of results. */
static uint64_t sc_member_faults(void)
{
    static const struct { edit_fn edit; uint8_t why; } cases[] = {
        {ea_own, GZ_WHY_OWN_NONCE_CHANGED}, {ea_other, GZ_WHY_BAD_NONCE}, {ea_drop, GZ_WHY_BAD_MESSAGE},
        {ea_twice, GZ_WHY_BAD_MESSAGE}, {ea_foreign, GZ_WHY_BAD_MESSAGE}};
    uint64_t d = 0;
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        while (q_find(&h, 0, 1, GZ_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
        deliver_edited(&h, q_find(&h, 0, 1, GZ_MSG_ALL_NONCES), cases[c].edit, 0);
        const gz_sign_round_t *m = h_newest(&h, 1);
        if (!(m->state == GZ_ROUND_ABORTED && m->why == cases[c].why)) printf("  member fault %zu: state %u why %u\n", c, m->state, m->why);
        CHECK(m->state == GZ_ROUND_ABORTED && m->why == cases[c].why && h_count_kind(&h, 1, GZ_MSG_PARTIALS) == 0);
        CHECK(check_abort(h_sent_kind(&h, 1, GZ_MSG_ABORT, 0), cases[c].why, 0xff, 0, NULL));
        CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 1 && h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE] == 0);
        for (int i = 0; i < m->def.n_items; i++) CHECK(m->secnonce_serial[i] == 0);
        h_flush(&h, 100000);
        h_ticks(&h, 2);
        CHECK(h_newest(&h, 0)->state == GZ_ROUND_DONE && h.p[0].e->attempts == 2);
        d ^= h_digest(&h) + c;
        h_free(&h);
    }
    /* a nonce set whose count does not match its length: not a message, no state changes */
    {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        while (q_find(&h, 0, 1, GZ_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
        deliver_edited(&h, q_find(&h, 0, 1, GZ_MSG_ALL_NONCES), ea_count, -1);
        CHECK(h_newest(&h, 1)->state == GZ_ROUND_ACTIVE && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 1);
        CHECK(h_count_kind(&h, 1, GZ_MSG_PARTIALS) == 0 && h_count_kind(&h, 1, GZ_MSG_ABORT) == 0);
        d ^= h_digest(&h);
        h_free(&h);
    }
    /* a second, different nonce set after signing: refused, nothing sent; the same one again: the saved bytes */
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (q_find(&h, 0, 1, GZ_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
    long i = q_find(&h, 0, 1, GZ_MSG_ALL_NONCES);
    static uint8_t copy[GZ_SIGN_MAX_MSG];
    size_t len = h.q[i].len;
    memcpy(copy, h.q[i].b, len);
    h_deliver(&h, (size_t)i, 0);
    CHECK(h_count_kind(&h, 1, GZ_MSG_PARTIALS) == 1);
    h_inject(&h, 0, 1, copy, len);
    CHECK(h_count_kind(&h, 1, GZ_MSG_PARTIALS) == 2 && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 0);
    copy[len - 1] ^= 1;
    h_inject(&h, 0, 1, copy, len);
    CHECK(h_count_kind(&h, 1, GZ_MSG_PARTIALS) == 2 && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 1);
    copy[len - 1] ^= 1;
    h_inject(&h, 2, 1, copy, len);                                     /* not from the host */
    CHECK(h_count_kind(&h, 1, GZ_MSG_PARTIALS) == 2);
    /* a wrong result, then one not signed by the host: Unfinished; then the right one completes it */
    while (q_find(&h, 0, 1, GZ_MSG_RESULT) < 0) h_deliver(&h, 0, 0);
    i = q_find(&h, 0, 1, GZ_MSG_RESULT);
    static uint8_t good[GZ_SIGN_MAX_MSG];
    size_t glen = h.q[i].len;
    memcpy(good, h.q[i].b, glen);
    h_drop_msg(&h, (size_t)i);
    memcpy(copy, good, glen);
    copy[38 + 4 + 10] ^= 1;
    w_resign(copy, glen - 64, 0);
    h_inject(&h, 0, 1, copy, glen);
    const gz_sign_round_t *m = h_newest(&h, 1);
    CHECK(m->state == GZ_ROUND_UNFINISHED && m->why == GZ_WHY_BAD_RESULT && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 2);
    memcpy(copy, good, glen);
    w_resign(copy, glen - 64, 2);
    h_inject(&h, 0, 1, copy, glen);
    CHECK(m->state == GZ_ROUND_UNFINISHED && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 3);
    /* complete before the result: ignored */
    long ci = q_find(&h, 0, 1, GZ_MSG_COMPLETE);
    CHECK(ci >= 0);
    h_inject(&h, 0, 1, h.q[ci].b, h.q[ci].len);
    CHECK(m->state == GZ_ROUND_UNFINISHED && h_count_kind(&h, 1, GZ_MSG_ACK) == 0);
    h_inject(&h, 0, 1, good, glen);
    CHECK(m->state == GZ_ROUND_ACTIVE && m->tier_state[0] == GZ_TIER_DONE);
    /* a complete that is not signed by the host: ignored */
    memcpy(copy, h.q[ci].b, h.q[ci].len);
    copy[h.q[ci].len - 1] ^= 1;
    h_inject(&h, 0, 1, copy, h.q[ci].len);
    CHECK(m->state == GZ_ROUND_ACTIVE && h_count_kind(&h, 1, GZ_MSG_ACK) == 0);
    h_flush(&h, 100000);
    CHECK(m->state == GZ_ROUND_COMPLETE && h_newest(&h, 0)->state == GZ_ROUND_DONE);
    /* a host abort now changes nothing */
    uint8_t ab[200];
    h_inject(&h, 0, 1, ab, make_abort(ab, m->id, GZ_WHY_DEADLINE, 0xff, 0));
    CHECK(m->state == GZ_ROUND_COMPLETE);
    d ^= h_digest(&h);
    h_free(&h);
    return d;
}

/* Proposals: replayed, from the wrong peer, refused, and rounds pushed out of memory. */
static uint64_t sc_proposals(void)
{
    harness_t h;
    h_init(&h, 3);
    uint8_t ids[6][32];
    for (int k = 0; k < 6; k++) {
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        memcpy(ids[k], h_newest(&h, 0)->id, 32);
        h_flush(&h, 100000);
        CHECK(h_newest(&h, 0)->state == GZ_ROUND_DONE);
    }
    CHECK(h.p[0].e->n_known == 2 && memcmp(h.p[0].e->known[0], ids[0], 32) == 0 && memcmp(h.p[0].e->known[1], ids[1], 32) == 0);
    for (uint32_t j = 1; j <= 3; j++) {
        CHECK(h.p[j].e->n_known == 2 && memcmp(h.p[j].e->known[0], ids[0], 32) == 0);
        CHECK(h_find(&h, j, ids[0]) == NULL && h_find(&h, j, ids[5]) != NULL);
    }
    /* the oldest proposal again: refused as known, never signed */
    const h_sent_t *p0 = h_sent_kind(&h, 0, GZ_MSG_PROPOSE, 0);
    size_t n_nonces = h_count_kind(&h, 1, GZ_MSG_NONCES);
    h_inject(&h, 0, 1, p0->b, p0->len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], GZ_WHY_KNOWN_ROUND, 0xff, 0, NULL) && h_count_kind(&h, 1, GZ_MSG_NONCES) == n_nonces);
    /* a newer one again: answered with the saved ack */
    const h_sent_t *p5 = h_sent_kind(&h, 0, GZ_MSG_PROPOSE, 15);
    h_inject(&h, 0, 1, p5->b, p5->len);
    CHECK(h.sent[h.n_sent - 1].kind == GZ_MSG_ACK && h.p[1].e->counters[GZ_SIGN_COUNT_DUPLICATES] == 1);
    /* the same proposal from another member: nothing */
    size_t sent = h.n_sent;
    h_inject(&h, 2, 1, p5->b, p5->len);
    CHECK(h.n_sent == sent);
    /* a status request about a round the host has pushed out: aborted */
    uint8_t st[35];
    h_inject(&h, 1, 0, st, make_status(st, ids[0]));
    CHECK(check_abort(&h.sent[h.n_sent - 1], GZ_WHY_HOST_ABORT, 0xff, 0, NULL));
    /* restarts keep the refused list and every round held */
    check_restart_keeps(&h);
    h_inject(&h, 0, 1, p0->b, p0->len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], GZ_WHY_KNOWN_ROUND, 0xff, 0, NULL));
    /* a proposal whose host is not the sender, and one the builder refuses: aborted with the reason, to the sender */
    static uint8_t bad[300];
    memcpy(bad, p5->b, p5->len);
    h_inject(&h, 2, 1, bad, p5->len);
    bad[3] ^= 1;                                   /* another identifier, same parameters, host is party 0 */
    h_inject(&h, 2, 1, bad, p5->len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], GZ_WHY_BUILD, 0xff, 0, NULL) && h.sent[h.n_sent - 1].peer == 2);
    h_inject(&h, 0, 1, bad, p5->len);              /* from the host, the identifier does not match */
    CHECK(check_abort(&h.sent[h.n_sent - 1], GZ_WHY_ID_MISMATCH, 0xff, 0, NULL));
    memcpy(bad, p5->b, p5->len);
    bad[3] ^= 1;
    bad[3 + 32 + 32 + 2] = 9;                      /* parameters the builder refuses */
    h_inject(&h, 0, 1, bad, p5->len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], GZ_WHY_BUILD, 0xff, 0, NULL));
    memcpy(bad, p5->b, p5->len);
    bad[p5->len - 1] ^= 1;                         /* the host's signature */
    h_inject(&h, 0, 1, bad, p5->len);
    CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_DUPLICATES] == 1);         /* a known identifier: the saved answer (counters restarted) */
    CHECK(h.p[1].e->n_known == 2);
    /* the refused list full: a new round cannot be held. Refused as busy, nothing signed */
    gz_sign_t *e1 = h.p[1].e;
    while (e1->n_known < GZ_SIGN_MAX_KNOWN) {
        memset(e1->known[e1->n_known], 0xee, 32);
        e1->known[e1->n_known][0] = (uint8_t)e1->n_known; e1->known[e1->n_known][1] = (uint8_t)(e1->n_known >> 8);
        e1->n_known++;
    }
    n_nonces = h_count_kind(&h, 1, GZ_MSG_NONCES);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    long pi = q_find(&h, 0, 1, GZ_MSG_PROPOSE);
    CHECK(pi >= 0);
    h_deliver(&h, (size_t)pi, 0);
    CHECK(check_abort(&h.sent[h.n_sent - 1], GZ_WHY_BUSY, 0xff, 0, NULL) && h_count_kind(&h, 1, GZ_MSG_NONCES) == n_nonces);
    CHECK(e1->n_known == GZ_SIGN_MAX_KNOWN && h_find(&h, 1, h_newest(&h, 0)->id) == NULL);
    uint64_t d = h_digest(&h);
    h_free(&h);

    /* a fresh round's proposal with a broken host signature, and one naming a member not in it */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    const h_sent_t *p = h_sent_kind(&h, 0, GZ_MSG_PROPOSE, 0);
    memcpy(bad, p->b, p->len);
    bad[p->len - 1] ^= 1;
    harness_t h2;
    h_init(&h2, 3);
    h_inject(&h2, 0, 1, bad, p->len);
    CHECK(check_abort(&h2.sent[h2.n_sent - 1], GZ_WHY_BAD_HOST_SIG, 0xff, 0, NULL) && h_newest(&h2, 1) == NULL);
    CHECK(h2.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 1);
    h_free(&h);
    uint8_t q[9];
    gz_action_list_t list;
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    w_params(q, 1, 1, w_mask(2), 0);               /* members 1 and 2 only */
    CHECK(gz_sign_begin(h2.p[0].e, q, 9, &list) == GZ_OK);
    h_apply(&h2, 0, &list);
    p = h_sent_kind(&h2, 0, GZ_MSG_PROPOSE, 0);
    h_inject(&h2, 0, 3, p->b, p->len);
    CHECK(check_abort(&h2.sent[h2.n_sent - 1], GZ_WHY_INVALID_ROUND, 0xff, 0, NULL) && h_newest(&h2, 3) == NULL);
    /* the host cannot begin while a round runs, or past its attempts */
    CHECK(gz_sign_begin(h2.p[0].e, q, 9, &list) == GZ_ERR_ARGUMENT);
    CHECK(gz_sign_begin(h2.p[1].e, q, 9, &list) == GZ_ERR_ARGUMENT);
    d ^= h_digest(&h2);
    h_free(&h2);
    return d;
}

/* The journal: a clean one starts; each kind of damage is refused as corrupt. */
static uint64_t sc_journal(void)
{
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 0)->state == GZ_ROUND_DONE);
    for (uint32_t g = 0; g <= 1; g++) {
        h_party_t *p = &h.p[g];
        for (size_t k = 0; k < p->n_recs; k++) {
            for (int how = 0; how < 5; how++) {
                h_rec_t keep = p->recs[k];
                uint8_t *b = malloc(keep.len + 64);
                memcpy(b, keep.b, keep.len);
                p->recs[k].b = b;
                switch (how) {
                case 0: p->recs[k].len = keep.len - 1; break;                 /* cut */
                case 1: b[0] ^= 1; break;                                     /* another round */
                case 2: p->recs[k].type ^= 0x100; break;                      /* unknown type */
                case 3: b[32] = 7; break;                                     /* another tier, or participant */
                default: b[keep.len - 1] ^= 1; break;                         /* a signature */
                }
                gz_sign_t *saved = p->e;
                uint64_t fill = p->fill, inc = p->incarnation;
                p->e = calloc(1, sizeof *p->e);
                h_build(&h, g);
                p->fill = fill; p->incarnation = inc;
                gz_action_list_t list;
                int more = 1;
                gz_storage_reader_t rd = {h_next, h_rewind, p, 1};
                gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
                gz_status_t st = gz_sign_start(p->e, &rd, &list, &more);
                /* every damage is refused, except in the two records that carry no signature */
                int must = keep.type != GZ_REC_H_FAILED && !(how == 4 && keep.type == GZ_REC_H_ACK);
                if (must && st != GZ_ERR_CORRUPT) printf("  journal: party %u record %zu (type %x) damage %d accepted\n", g, k, keep.type, how);
                if (must) CHECK(st == GZ_ERR_CORRUPT);
                CHECK(st == GZ_OK || st == GZ_ERR_CORRUPT);
                gz_sign_wipe(p->e); free(p->e);
                p->e = saved;
                free(b);
                p->recs[k] = keep;
            }
        }
    }
    check_restart_keeps(&h);
    uint64_t d = h_digest(&h);
    h_free(&h);
    return d;
}

#define N_SCENARIOS 12
static const char *const SC_NAMES[N_SCENARIOS] = {
    "honest-1", "honest-2", "duplicates", "member-restart-nonces", "member-restart-signed", "tier-abort",
    "host-restarts", "timers", "host-faults", "member-faults", "proposals", "journal"};

static uint64_t run_scenario(int k)
{
    switch (k) {
    case 0: return sc_honest(1);
    case 1: return sc_honest(2);
    case 2: return sc_duplicates();
    case 3: return sc_member_restart_nonces();
    case 4: return sc_member_restart_signed();
    case 5: return sc_tier_abort();
    case 6: return sc_host_restarts();
    case 7: return sc_timers();
    case 8: return sc_host_faults();
    case 9: return sc_member_faults();
    case 10: return sc_proposals();
    default: return sc_journal();
    }
}

#endif
