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
        if (h->q[i].from == from && h->q[i].to == to && h_kind_of(h->q[i].b, h->q[i].len) == kind) return (long)i;
    return -1;
}

/* Deliver in order until party `from` has sent `count` messages of `kind`. */
static void flush_until(harness_t *h, uint32_t from, uint8_t kind, size_t count)
{
    while (h->nq && h_count_kind(h, from, kind) < count) h_deliver(h, 0, 0);
}

/* A field of a journal record (journal.md 9; the code table in signing.h), or NULL. */
static const uint8_t *rec_field(const h_rec_t *rec, uint64_t type, size_t *len)
{
    size_t at = 0;
    while (at + 2 <= rec->len) {
        uint64_t t = rec->b[at], l;
        if (t >= 0xfd) return NULL;                       /* the engine's field numbers are all one byte */
        at++;
        l = rec->b[at];
        if (l == 0xfd) { l = (uint64_t)rec->b[at + 1] << 8 | rec->b[at + 2]; at += 3; }
        else if (l == 0xfe) { l = (uint64_t)rec->b[at + 1] << 24 | (uint64_t)rec->b[at + 2] << 16 | (uint64_t)rec->b[at + 3] << 8 | rec->b[at + 4]; at += 5; }
        else at++;
        if (l > rec->len - at) return NULL;
        if (t == type) { if (len) *len = (size_t)l; return rec->b + at; }
        at += (size_t)l;
    }
    return NULL;
}

/* The messages.md 7.9 reason for an engine's `why`. */
#define R(why) gz_sign_reason((uint8_t)(why), 0)
#define WHOLE (-1)

/* A whole-round abort as `from` (participant index = party here) would sign it. */
static size_t make_abort(uint8_t *out, const uint8_t id[32], uint16_t reason, uint32_t from)
{
    uint8_t r2[2] = {(uint8_t)(reason >> 8), (uint8_t)reason};
    w_rec_t recs[2] = {{2, id, 32}, {4, r2, 2}};
    return w_message(out, 512, GZ_SIGN_MSG_ABORT, recs, 2, (int)from);
}

static size_t make_status(uint8_t *out, const uint8_t id[32])
{
    w_rec_t recs[1] = {{2, id, 32}};
    return w_message(out, 128, GZ_SIGN_MSG_STATUS, recs, 1, -1);
}

/* An abort that went out: its reason, its tier (WHOLE: none) and items. */
static int check_abort(const h_sent_t *s, uint16_t reason, int tier, int n, const uint32_t *items)
{
    gz_sign_msg_t m;
    if (!s || !gz_sign_decode(s->b, s->len, &m) || m.kind != GZ_SIGN_MSG_ABORT) return 0;
    if (m.reason != reason || m.n != n || (tier == WHOLE ? m.has_tier != 0 : !m.has_tier || m.tier != tier)) return 0;
    for (int k = 0; k < n; k++) if (be32p(m.entry[k]) != items[k]) return 0;
    return 1;
}

/* The n-th message of `kind` party `from` sent to `to`, or NULL. */
static const h_sent_t *h_sent_to(const harness_t *h, uint32_t from, uint32_t to, uint8_t kind, size_t nth)
{
    for (size_t i = 0; i < h->n_sent; i++)
        if (h->sent[i].party == from && h->sent[i].peer == to && h->sent[i].kind == kind && nth-- == 0) return &h->sent[i];
    return NULL;
}

/* A record's length: BigSize type (one byte here) and length, then the value. */
static size_t rl(size_t v) { return 1 + (v < 0xfd ? 1 : v <= 0xffff ? 3 : 5) + v; }

/* A list message (nonces, all_nonces, partials, result) written again with
 * other entries: records 2 and 4 as they were, record 6 the given blocks,
 * and a signature record (to be re-signed) if the message had one. */
static size_t rebuild_list(uint8_t *b, size_t cap, const gz_sign_msg_t *m, const uint8_t *const *blocks, const size_t *sizes, size_t n)
{
    static uint8_t value[GZ_SIGN_MAX_MSG], copy_id[32];
    size_t v = 0;
    uint8_t tier = m->tier, zero[64] = {0};
    int sig = m->sig != NULL;
    uint16_t kind = m->kind;
    memcpy(copy_id, m->round_id, 32);
    for (size_t i = 0; i < n; i++) { memmove(value + v, blocks[i], sizes[i]); v += sizes[i]; }
    w_rec_t recs[4] = {{2, copy_id, 32}, {4, &tier, 1}, {6, value, v}, {240, zero, 64}};
    return w_message(b, cap, kind, recs, sig ? 4 : 3, -1);
}
/* The size of entry k of a list message. */
static size_t entry_size(const uint8_t *b, size_t len, const gz_sign_msg_t *m, int k)
{
    const uint8_t *end = k + 1 < m->n ? m->entry[k + 1] : NULL;
    if (end) return (size_t)(end - m->entry[k]);
    if (m->kind == GZ_SIGN_MSG_ALL_NONCES) return 6 + 130u * (size_t)(m->entry[k][4] << 8 | m->entry[k][5]);
    if (m->kind == GZ_SIGN_MSG_NONCES) return 134;
    (void)b; (void)len;
    return 68;
}

/* What a party holds of each round, in a form that must survive a restart. */
typedef struct { uint8_t id[32]; uint8_t state, ts0, ts1; uint32_t acked; uint8_t finals[GZ_SIGN_MAX_ITEMS][64]; uint32_t tail; } held_t;
static size_t held_view(const harness_t *h, uint32_t g, held_t *out)
{
    size_t n = 0;
    for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
        const gz_sign_round_t *r = &h->p[g].e->rounds[k];
        if (r->state == GZ_SIGN_ROUND_FREE) continue;
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

static const uint8_t g_zero64[64];
static int items_of_has(const gz_sign_round_t *r, uint32_t j, int i)
{
    for (int s = 0; s < r->def.items[i].n_signers; s++) if (r->def.items[i].signers[s] == j) return 1;
    return 0;
}

static void honest_counts(harness_t *h, uint8_t tiers)
{
    const gz_sign_round_t *r = h_newest(h, 0);
    int items = r->def.n_items, psigs = 0;
    for (int i = 0; i < items; i++) psigs += r->def.items[i].n_signers - 1;
    CHECK(r->state == GZ_SIGN_ROUND_DONE && r->acked == ((h->n >= 32 ? 0xffffffffu : ((uint32_t)1u << h->n) - 1u) & ~1u));
    const uint64_t *c = h->p[0].e->counters;
    CHECK(c[GZ_SIGN_COUNT_NONCES_MADE] == (uint64_t)items && c[GZ_SIGN_COUNT_PARTIALS_MADE] == (uint64_t)items);
    CHECK(c[GZ_SIGN_COUNT_PSIGS_VERIFIED] == (uint64_t)psigs && c[GZ_SIGN_COUNT_FINALS_VERIFIED] == (uint64_t)items);
    CHECK(c[GZ_SIGN_COUNT_REJECTED] == 0 && c[GZ_SIGN_COUNT_BLAME_FAULT] == 0 && c[GZ_SIGN_COUNT_BLAME_SILENT] == 0);
    for (uint32_t j = 1; j < h->n; j++) {
        const gz_sign_round_t *m = h_find(h, j, r->id);
        const uint64_t *mc = h->p[j].e->counters;
        int mine = items_of(r, j, -1, NULL);
        CHECK(m && m->state == GZ_SIGN_ROUND_COMPLETE);
        for (int i = 0; m && i < items; i++)        /* a member holds the finals of its own items, and only those */
            CHECK(memcmp(m->final_sig[i], items_of_has(r, j, i) ? r->final_sig[i] : (const uint8_t *)g_zero64, 64) == 0);
        CHECK(mc[GZ_SIGN_COUNT_NONCES_MADE] == (uint64_t)mine && mc[GZ_SIGN_COUNT_PARTIALS_MADE] == (uint64_t)mine);
        CHECK(mc[GZ_SIGN_COUNT_FINALS_VERIFIED] == (uint64_t)mine && mc[GZ_SIGN_COUNT_REJECTED] == 0 && mc[GZ_SIGN_COUNT_DUPLICATES] == 0);
        /* Each message, exactly: one nonce message per tier with items, one partial message, one ack. */
        int tiers_with = 0;
        for (int t = 0; t < tiers; t++) tiers_with += items_of(r, j, t, NULL) > 0;
        CHECK(h_count_kind(h, j, GZ_SIGN_MSG_NONCES) == (size_t)tiers_with && h_count_kind(h, j, GZ_SIGN_MSG_PARTIALS) == (size_t)tiers_with);
        CHECK(h_count_kind(h, j, GZ_SIGN_MSG_ACK) == 1 && h_count_kind(h, j, GZ_SIGN_MSG_ABORT) == 0 && h_count_kind(h, j, GZ_SIGN_MSG_STATUS) == 0);
        size_t nth = 0;
        for (int t = 0; t < tiers; t++) {
            uint32_t list[GZ_SIGN_MAX_ITEMS];
            int n = items_of(r, j, t, list);
            if (!n) continue;
            const h_sent_t *ns = h_sent_kind(h, j, GZ_SIGN_MSG_NONCES, nth), *ps = h_sent_kind(h, j, GZ_SIGN_MSG_PARTIALS, nth);
            nth++;
            gz_sign_msg_t mn, mp;
            CHECK(ns && ns->len == GZ_RMSG_HEADER + rl(32) + rl(1) + rl((size_t)n * 134) && gz_sign_decode(ns->b, ns->len, &mn) && mn.tier == t && mn.n == n);
            CHECK(ps && ps->len == GZ_RMSG_HEADER + rl(32) + rl(1) + rl((size_t)n * 68) + rl(64) && gz_sign_decode(ps->b, ps->len, &mp) && mp.tier == t && mp.n == n);
            for (int k = 0; ns && ps && k < n; k++) {
                CHECK(be32p(mn.entry[k]) == list[k] && be32p(mp.entry[k]) == list[k]);
                /* the nonce sent is the one the host holds for that signer, and the set digest is over the host's set */
                int s = 0;
                while (r->def.items[list[k]].signers[s] != j) s++;
                CHECK(memcmp(mn.entry[k] + 4, r->nonce[list[k]][s], 66) == 0);
                gz_sign_sha256_t sd;
                uint8_t d[32];
                gz_sign_tagged_init(&sd, "gazpacho/nonceset");
                for (int q = 0; q < r->def.items[list[k]].n_signers; q++) gz_sign_sha256_write(&sd, r->nonce[list[k]][q], 66);
                gz_sign_sha256_done(&sd, d);
                CHECK(memcmp(mp.entry[k] + 36, d, 32) == 0 && memcmp(mp.entry[k] + 4, r->psig[list[k]][s], 32) == 0);
            }
        }
        /* the ack names what the member holds: TH(held, its items' u32 index || final signature) (7.8) */
        const h_sent_t *ack = h_sent_kind(h, j, GZ_SIGN_MSG_ACK, 0);
        uint32_t idx[GZ_SIGN_MAX_ITEMS];
        static uint8_t fin[GZ_SIGN_MAX_ITEMS][64];
        uint8_t d[32];
        gz_sign_msg_t ma;
        int nm = items_of(r, j, -1, idx);
        for (int k = 0; k < nm; k++) memcpy(fin[k], r->final_sig[idx[k]], 64);
        gz_rmsg_held_hash(idx, (const uint8_t (*)[64])fin, (size_t)nm, d);
        CHECK(ack && ack->len == GZ_RMSG_HEADER + rl(32) + rl(32) + rl(64) && gz_sign_decode(ack->b, ack->len, &ma) && memcmp(ma.held, d, 32) == 0);
        /* the member's journal, in order, batch by batch (journal.md 9) */
        static const uint32_t one[] = {GZ_SIGN_REC_ROUND_PROPOSAL, GZ_SIGN_REC_ROUND_STARTED, GZ_SIGN_REC_GUARD, GZ_SIGN_REC_EXPOSURE,
                                       GZ_SIGN_REC_ROUND_SIGNED, GZ_SIGN_REC_ROUND_COMPLETED, GZ_SIGN_REC_FUNDING_STATUS};
        static const uint64_t batch[] = {1, 1, 1, 2, 3, 4, 4};
        if (tiers == 1) {
            CHECK(h->p[j].n_recs == 7);
            for (int k = 0; k < 7 && h->p[j].n_recs == 7; k++)
                CHECK(h->p[j].recs[k].type == one[k] && h->p[j].recs[k].batch == batch[k]);
            /* the exposure record: the funding transaction, the tree digest, the items, the partial signatures */
            size_t fl, il, pl;
            const h_rec_t *xr = h->p[j].n_recs == 7 ? &h->p[j].recs[3] : NULL;
            const uint8_t *ftx = xr ? rec_field(xr, 8, &fl) : NULL, *dig = xr ? rec_field(xr, 10, NULL) : NULL;
            const uint8_t *its = xr ? rec_field(xr, 12, &il) : NULL, *pms = xr ? rec_field(xr, 14, &pl) : NULL;
            const h_sent_t *ps0 = h_sent_kind(h, j, GZ_SIGN_MSG_PARTIALS, 0);
            CHECK(ftx && fl == 94 && dig && memcmp(dig, r->def.tree_digest, 32) == 0 && its && il == 72u * (size_t)mine);
            CHECK(pms && ps0 && pl == ps0->len && memcmp(pms, ps0->b, pl) == 0);
        }
    }
    /* the host: one proposal, one nonce set and one result per member per tier, one complete each */
    CHECK(h_count_kind(h, 0, GZ_SIGN_MSG_PROPOSE) == h->n - 1 && h_count_kind(h, 0, GZ_SIGN_MSG_COMPLETE) == h->n - 1);
    size_t sets = 0;                     /* a nonce set only to members with items in the tier */
    for (int t = 0; t < tiers; t++)
        for (uint32_t j = 1; j < h->n; j++) sets += items_of(r, j, t, NULL) > 0;
    CHECK(h_count_kind(h, 0, GZ_SIGN_MSG_ALL_NONCES) == sets && h_count_kind(h, 0, GZ_SIGN_MSG_RESULT) == sets);
    /* proposal, started and guard; started and guard for each later tier; signed per tier; completed; acks */
    CHECK(h->p[0].n_recs == (size_t)(3 + 2 * (tiers - 1) + tiers + 1 + (h->n - 1)));
    const h_sent_t *res = h_sent_to(h, 0, 1, GZ_SIGN_MSG_RESULT, 0);    /* member 1's: its own items of tier 0 */
    gz_sign_msg_t mr;
    int tier0 = items_of(r, 1, 0, NULL);
    CHECK(res && gz_sign_decode(res->b, res->len, &mr) && mr.n == tier0 && res->len == GZ_RMSG_HEADER + rl(32) + rl(1) + rl((size_t)tier0 * 68) + rl(64));
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
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
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
    CHECK(r->state == GZ_SIGN_ROUND_DONE && h.p[0].e->counters[GZ_SIGN_COUNT_REJECTED] == 0);
    CHECK(h.p[0].e->counters[GZ_SIGN_COUNT_DUPLICATES] > 0 && h.p[0].e->counters[GZ_SIGN_COUNT_BLAME_FAULT] == 0);
    for (uint32_t j = 1; j <= 3; j++) {
        CHECK(h_find(&h, j, r->id)->state == GZ_SIGN_ROUND_COMPLETE);
        CHECK(h.p[j].e->counters[GZ_SIGN_COUNT_DUPLICATES] == 1);      /* the proposal, answered from what was saved */
        /* every resend is the same bytes */
        const h_sent_t *n0 = h_sent_kind(&h, j, GZ_SIGN_MSG_NONCES, 0), *n1 = h_sent_kind(&h, j, GZ_SIGN_MSG_NONCES, 1);
        CHECK(n0 && n1 && n0->len == n1->len && memcmp(n0->b, n1->b, n0->len) == 0);
        const h_sent_t *p0 = h_sent_kind(&h, j, GZ_SIGN_MSG_PARTIALS, 0), *p1 = h_sent_kind(&h, j, GZ_SIGN_MSG_PARTIALS, 1);
        CHECK(p0 && p1 && p0->len == p1->len && memcmp(p0->b, p1->b, p0->len) == 0);
        const h_sent_t *a0 = h_sent_kind(&h, j, GZ_SIGN_MSG_ACK, 0), *a1 = h_sent_kind(&h, j, GZ_SIGN_MSG_ACK, 1);
        CHECK(a0 && a1 && a0->len == a1->len && memcmp(a0->b, a1->b, a0->len) == 0);
    }
    /* acks counted once each */
    size_t acks = 0;
    for (size_t i = 0; i < h.p[0].n_recs; i++) acks += h.p[0].recs[i].type == GZ_SIGN_REC_ACK_RECEIVED;
    CHECK(acks == 3);
    uint64_t d = h_digest(&h);
    h_free(&h);

    h_init(&h, 4);
    CHECK(h_begin(&h, 1, 4, 0) == GZ_OK);
    while (h.nq) h_deliver(&h, h.nq - 1, 0);
    h_ticks(&h, 4);                                /* a complete that came before its result was ignored: resent */
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
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
    flush_until(&h, 3, GZ_SIGN_MSG_NONCES, 1);
    CHECK(h_restart(&h, 2) == GZ_OK);
    const gz_sign_round_t *r1 = h_oldest(&h, 2);
    CHECK(r1 && r1->state == GZ_SIGN_ROUND_ABORTED && r1->why == GZ_SIGN_WHY_RESTARTED && !r1->ever_partial);
    for (int i = 0; r1 && i < r1->def.n_items; i++) CHECK(r1->secnonce_serial[i] == 0);
    CHECK(check_abort(h_sent_kind(&h, 2, GZ_SIGN_MSG_ABORT, 0), R(GZ_SIGN_WHY_RESTARTED), WHOLE, 0, NULL));
    CHECK(h.p[2].recs[h.p[2].n_recs - 1].type == GZ_SIGN_REC_ROUND_ENDED && rec_field(&h.p[2].recs[h.p[2].n_recs - 1], 4, NULL)[0] == GZ_SIGN_END_ABORTED);
    uint8_t id1[32];
    memcpy(id1, r1->id, 32);
    /* the proposal again: the same abort, never a second nonce */
    const h_sent_t *prop = h_sent_kind(&h, 0, GZ_SIGN_MSG_PROPOSE, 0);
    h_inject(&h, 0, 2, prop->b, prop->len);
    CHECK(h_count_kind(&h, 2, GZ_SIGN_MSG_NONCES) == 1 && h_count_kind(&h, 2, GZ_SIGN_MSG_ABORT) == 2);
    const h_sent_t *a0 = h_sent_kind(&h, 2, GZ_SIGN_MSG_ABORT, 0), *a1 = h_sent_kind(&h, 2, GZ_SIGN_MSG_ABORT, 1);
    CHECK(a0->len == a1->len && memcmp(a0->b, a1->b, a0->len) == 0);
    h_flush(&h, 100000);
    h_ticks(&h, 2);
    const gz_sign_round_t *hr = h_find(&h, 0, id1);
    CHECK(hr && hr->state == GZ_SIGN_ROUND_FAILED && hr->why == GZ_SIGN_WHY_MEMBER_ABORT && hr->blamed == 0);
    CHECK(h.p[0].e->attempts == 2 && h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
    CHECK(h_count_kind(&h, 2, GZ_SIGN_MSG_PARTIALS) == 1);                 /* only in the second attempt */
    for (uint32_t j = 1; j <= 3; j += 2) {                             /* the others signed attempt 1, then were superseded */
        const gz_sign_round_t *m = h_find(&h, j, id1);
        CHECK(m && m->state == GZ_SIGN_ROUND_UNFINISHED && m->why == GZ_SIGN_WHY_SUPERSEDED && m->ever_partial);
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
    flush_until(&h, 1, GZ_SIGN_MSG_PARTIALS, 1);
    CHECK(h_restart(&h, 1) == GZ_OK);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == 2 && h_count_kind(&h, 1, GZ_SIGN_MSG_STATUS) == 1);
    const h_sent_t *p0 = h_sent_kind(&h, 1, GZ_SIGN_MSG_PARTIALS, 0), *p1 = h_sent_kind(&h, 1, GZ_SIGN_MSG_PARTIALS, 1);
    CHECK(p0->len == p1->len && memcmp(p0->b, p1->b, p0->len) == 0);
    const gz_sign_round_t *m = h_newest(&h, 1);
    CHECK(m->state == GZ_SIGN_ROUND_ACTIVE && m->tier_state[0] == GZ_SIGN_TIER_SIGNED && m->ever_partial);
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE && h.p[0].e->attempts == 1);
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
    flush_until(&h, j, GZ_SIGN_MSG_NONCES, 2);
    uint32_t list[GZ_SIGN_MAX_ITEMS];
    int n = items_of(r, j, 1, list);
    uint8_t ab[512];
    size_t len = make_abort(ab, r->id, 4, 0);
    h_inject(&h, 0, j, ab, len);
    const gz_sign_round_t *m = h_newest(&h, j);
    CHECK(m->state == GZ_SIGN_ROUND_UNFINISHED && m->why == GZ_SIGN_WHY_HOST_ABORT && m->tier == 1);
    CHECK(check_abort(h_sent_kind(&h, j, GZ_SIGN_MSG_ABORT, 0), R(GZ_SIGN_WHY_HOST_ABORT), 1, n, list));
    for (int i = 0; i < m->def.n_items; i++) CHECK(m->secnonce_serial[i] == 0);
    /* an abort that is not the host's changes nothing */
    uint32_t k = j == 1 ? 2 : 1;
    harness_t h2;
    h_init(&h2, 4);
    CHECK(h_begin(&h2, 2, 4, 0) == GZ_OK);
    flush_until(&h2, j, GZ_SIGN_MSG_NONCES, 2);
    len = make_abort(ab, h_newest(&h2, 0)->id, 4, k);
    h_inject(&h2, 0, j, ab, len);
    CHECK(h_newest(&h2, j)->state == GZ_SIGN_ROUND_ACTIVE);
    h_inject(&h2, k, j, ab, len);
    CHECK(h_newest(&h2, j)->state == GZ_SIGN_ROUND_ACTIVE);
    /* restart there: per item again, then the replayed proposal gets the same answer */
    CHECK(h_restart(&h2, j) == GZ_OK);
    m = h_newest(&h2, j);
    CHECK(m->state == GZ_SIGN_ROUND_UNFINISHED && m->why == GZ_SIGN_WHY_RESTARTED);
    CHECK(check_abort(h_sent_kind(&h2, j, GZ_SIGN_MSG_ABORT, 0), R(GZ_SIGN_WHY_RESTARTED), 1, n, list));
    const h_sent_t *prop = h_sent_kind(&h2, 0, GZ_SIGN_MSG_PROPOSE, 0);
    h_inject(&h2, 0, j, prop->b, prop->len);
    CHECK(check_abort(h_sent_kind(&h2, j, GZ_SIGN_MSG_ABORT, 1), R(GZ_SIGN_WHY_RESTARTED), 1, n, list));
    CHECK(h_count_kind(&h2, j, GZ_SIGN_MSG_NONCES) == 2);
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
    flush_until(&h, 3, GZ_SIGN_MSG_NONCES, 1);
    CHECK(h_restart(&h, 0) == GZ_OK);
    const gz_sign_round_t *r = h_find(&h, 0, id1);
    CHECK(r && r->state == GZ_SIGN_ROUND_FAILED && r->why == GZ_SIGN_WHY_HOST_RESTART && r->blamed == 0);
    CHECK(h.p[0].e->attempts == 2 && memcmp(h_newest(&h, 0)->id, id1, 32) != 0);
    CHECK(h.p[0].recs[h.p[0].n_recs - 1].type == GZ_SIGN_REC_GUARD && h.p[0].recs[h.p[0].n_recs - 2].type == GZ_SIGN_REC_ROUND_STARTED &&
          h.p[0].recs[h.p[0].n_recs - 3].type == GZ_SIGN_REC_ROUND_PROPOSAL);
    h_flush(&h, 100000);
    for (uint32_t j = 1; j <= 3; j++) {
        const gz_sign_round_t *m = h_find(&h, j, id1);
        CHECK(m && m->state == GZ_SIGN_ROUND_ABORTED && (m->why == GZ_SIGN_WHY_HOST_ABORT || m->why == GZ_SIGN_WHY_SUPERSEDED));
    }
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
    /* a status request about the failed attempt: its abort and reason */
    uint8_t st[128];
    size_t before = h_count_kind(&h, 0, GZ_SIGN_MSG_ABORT);
    h_inject(&h, 1, 0, st, make_status(st, id1));
    CHECK(h_count_kind(&h, 0, GZ_SIGN_MSG_ABORT) == before + 1);
    CHECK(check_abort(&h.sent[h.n_sent - 1], R(GZ_SIGN_WHY_HOST_RESTART), WHOLE, 0, NULL) && h.sent[h.n_sent - 1].peer == 1);
    /* about an identifier nobody knows: nothing */
    uint8_t other[32] = {1};
    size_t sent = h.n_sent;
    h_inject(&h, 1, 0, st, make_status(st, other));
    CHECK(h.n_sent == sent);
    uint64_t d = h_digest(&h);
    h_free(&h);

    /* After complete, before any ack: the restarted host pushes nothing (contract v2 section 3: members ask). */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    flush_until(&h, 0, GZ_SIGN_MSG_COMPLETE, 3);
    size_t results = h_count_kind(&h, 0, GZ_SIGN_MSG_RESULT);
    CHECK(h_restart(&h, 0) == GZ_OK);
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_COMPLETE && h.p[0].e->attempts == 1);
    CHECK(h_count_kind(&h, 0, GZ_SIGN_MSG_RESULT) == results && h_count_kind(&h, 0, GZ_SIGN_MSG_COMPLETE) == 3);
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE && h_newest(&h, 0)->acked == 0xe);
    check_restart_keeps(&h);
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
    /* a status request now: every result and the complete, to that member only */
    sent = h.n_sent;
    uint8_t st2[128];
    h_inject(&h, 2, 0, st2, make_status(st2, h_newest(&h, 0)->id));
    CHECK(h.n_sent == sent + 2 && h.sent[sent].kind == GZ_SIGN_MSG_RESULT && h.sent[sent + 1].kind == GZ_SIGN_MSG_COMPLETE && h.sent[sent].peer == 2);
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
    CHECK(h_find(&h, 0, id1)->state == GZ_SIGN_ROUND_ACTIVE);             /* one tick before the deadline */
    h_ticks(&h, 1);
    const gz_sign_round_t *r = h_find(&h, 0, id1);
    CHECK(r->state == GZ_SIGN_ROUND_FAILED && r->why == GZ_SIGN_WHY_DEADLINE && r->blamed == 1u << 3);
    CHECK(h.p[0].e->counters[GZ_SIGN_COUNT_BLAME_SILENT] == 1 && h.p[0].e->counters[GZ_SIGN_COUNT_BLAME_FAULT] == 0);
    size_t to3 = 0;
    for (size_t i = 0; i < h.n_sent; i++) to3 += h.sent[i].party == 0 && h.sent[i].peer == 3 && h.sent[i].kind == GZ_SIGN_MSG_PROPOSE;
    CHECK(to3 == 1 + 12 / 3 - 1);                                     /* resent every third tick until the deadline */
    h_ticks(&h, 3);
    const gz_sign_round_t *r2 = h_newest(&h, 0);
    CHECK(r2->state == GZ_SIGN_ROUND_DONE && r2->def.n_participants == 3 && h.p[0].e->attempts == 2);
    uint64_t d = h_digest(&h);
    h_free(&h);

    /* every ack lost: the host resends results, then gives the attempt up blaming all; no further attempt */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (h.nq && h_newest(&h, 0)->state != GZ_SIGN_ROUND_COMPLETE) h_deliver(&h, 0, 0);
    h.drop_to = 1u;
    h_flush(&h, 100000);
    for (int t = 0; t < 12; t++) h_ticks(&h, 1);
    r = h_newest(&h, 0);
    CHECK(r->state == GZ_SIGN_ROUND_FAILED && r->why == GZ_SIGN_WHY_DEADLINE && r->blamed == 0xe && h.p[0].e->attempts == 1);
    CHECK(h_count_kind(&h, 0, GZ_SIGN_MSG_RESULT) == 3 + 3 * 3);           /* first, then at ticks 3, 6 and 9 */
    for (uint32_t j = 1; j <= 3; j++) CHECK(h_newest(&h, j)->state == GZ_SIGN_ROUND_COMPLETE);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_ACK) == 1 + 3);                 /* the ack again for each result set */
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
        CHECK(m->state == GZ_SIGN_ROUND_ABORTED && m->why == GZ_SIGN_WHY_DEADLINE && m->tail_len > 0);
        CHECK(check_abort(h_sent_kind(&h, j, GZ_SIGN_MSG_ABORT, 0), R(GZ_SIGN_WHY_DEADLINE), WHOLE, 0, NULL));
        CHECK(h.p[j].e->counters[GZ_SIGN_COUNT_REJECTED] == 1);
    }
    d ^= h_digest(&h);
    h_free(&h);

    /* a member waiting for a result resends its partial signatures and asks, every third tick; Unfinished
     * after the step timeout (spec section 6, step 8), never Aborted */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    flush_until(&h, 1, GZ_SIGN_MSG_PARTIALS, 1);
    h.drop_to = 1u << 1;
    h_flush(&h, 100000);
    for (int t = 0; t < 20; t++) h_tick(&h, 1);
    CHECK(h_newest(&h, 1)->state == GZ_SIGN_ROUND_UNFINISHED && h_newest(&h, 1)->why == GZ_SIGN_WHY_DEADLINE &&
          h_newest(&h, 1)->tier_state[0] == GZ_SIGN_TIER_SIGNED);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == 1 + 6 && h_count_kind(&h, 1, GZ_SIGN_MSG_STATUS) == 6);
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
    if (signer >= 0 && gz_sign_decode(b, len, &m) && m.sig) w_resign(b, len, (uint32_t)signer);
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
static void ed_tier(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r) { (void)len; (void)r; (void)m; b[GZ_RMSG_HEADER + 36] = 1; }   /* record 4's value */
static void ed_breaksig(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r) { (void)m; (void)r; b[*len - 1] ^= 1; }

/* The host's checks of what members send: who is blamed, and why. */
static uint64_t sc_host_faults(void)
{
    static const struct { uint8_t kind; edit_fn edit; int resign; uint8_t why; uint8_t blame; } cases[] = {
        {GZ_SIGN_MSG_PARTIALS, ed_psig, 1, GZ_SIGN_WHY_BAD_PARTIAL, 1},
        {GZ_SIGN_MSG_PARTIALS, ed_setdigest, 1, GZ_SIGN_WHY_BAD_PARTIAL, 1},
        {GZ_SIGN_MSG_PARTIALS, ed_index, 1, GZ_SIGN_WHY_BAD_MESSAGE, 1},
        {GZ_SIGN_MSG_PARTIALS, ed_breaksig, 0, GZ_SIGN_WHY_BAD_MESSAGE, 1},
        {GZ_SIGN_MSG_PARTIALS, ed_tier, 1, GZ_SIGN_WHY_NONE, 0},                  /* another tier: a duplicate, ignored */
        {GZ_SIGN_MSG_NONCES, ed_index, 0, GZ_SIGN_WHY_BAD_MESSAGE, 1},
        {GZ_SIGN_MSG_NONCES, ed_breaksig, 0, GZ_SIGN_WHY_BAD_NONCE, 1},            /* the last entry's nonce signature */
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
            if (!(r->state == GZ_SIGN_ROUND_FAILED && r->why == cases[c].why && r->blamed == 1u << 2))
                printf("  host fault %zu: state %u why %u blamed %x\n", c, r->state, r->why, r->blamed);
            CHECK(r->state == GZ_SIGN_ROUND_FAILED && r->why == cases[c].why && r->blamed == 1u << 2);
            CHECK(h.p[0].e->counters[GZ_SIGN_COUNT_BLAME_FAULT] == 1);
            for (uint32_t j = 1; j <= 3; j++) CHECK(h_count_kind(&h, 0, GZ_SIGN_MSG_ABORT) == 3);
            CHECK(check_abort(h_sent_to(&h, 0, 2, GZ_SIGN_MSG_ABORT, 0), R(cases[c].why), WHOLE, 0, NULL));   /* the blamed member: the fault */
            CHECK(check_abort(h_sent_to(&h, 0, 1, GZ_SIGN_MSG_ABORT, 0), 4, WHOLE, 0, NULL));                  /* the others: the attempt ended */
            size_t i = h.p[0].n_recs;
            while (i && h.p[0].recs[i - 1].type != GZ_SIGN_REC_ROUND_ENDED) i--;
            const uint8_t *oc = i ? rec_field(&h.p[0].recs[i - 1], 4, NULL) : NULL, *bl = i ? rec_field(&h.p[0].recs[i - 1], 8, NULL) : NULL;
            const uint8_t *wy = i ? rec_field(&h.p[0].recs[i - 1], 10, NULL) : NULL, *rs = i ? rec_field(&h.p[0].recs[i - 1], 6, NULL) : NULL;
            CHECK(oc && oc[0] == GZ_SIGN_END_FAILED && wy && wy[0] == cases[c].why && bl && be32p(bl) == 1u << 2 &&
                  rs && (rs[0] << 8 | rs[1]) == R(cases[c].why));
            h_flush(&h, 100000);
            h_ticks(&h, 2);
            CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE && h_newest(&h, 0)->def.n_participants == 3);
        } else {
            CHECK(r->state == GZ_SIGN_ROUND_ACTIVE && h.p[0].e->counters[GZ_SIGN_COUNT_DUPLICATES] == 1);
        }
        d ^= h_digest(&h) + c;
        h_free(&h);
    }
    /* nonces from someone who is not in the round, and a second honest copy: no effect */
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (q_find(&h, 2, 0, GZ_SIGN_MSG_NONCES) < 0) h_deliver(&h, 0, 0);
    long i = q_find(&h, 2, 0, GZ_SIGN_MSG_NONCES);
    h_inject(&h, 7, 0, h.q[i].b, h.q[i].len);
    h_inject(&h, 2, 0, h.q[i].b, h.q[i].len);
    CHECK(h.p[0].e->counters[GZ_SIGN_COUNT_DUPLICATES] == 0);
    h_deliver(&h, (size_t)i, 0);
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_ACTIVE && h.p[0].e->counters[GZ_SIGN_COUNT_DUPLICATES] == (uint64_t)items_of(h_newest(&h, 0), 2, 0, NULL));
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
    /* an ack naming the wrong held set, then a second ack: neither changes anything */
    gz_sign_round_t *r = (gz_sign_round_t *)h_newest(&h, 0);
    const h_sent_t *ack = h_sent_kind(&h, 1, GZ_SIGN_MSG_ACK, 0);
    static uint8_t bad[512];
    memcpy(bad, ack->b, ack->len);
    bad[GZ_RMSG_HEADER + 36] ^= 1;                                /* the held digest (record 4) */
    w_resign(bad, ack->len, 1);
    r->acked &= ~2u; r->state = GZ_SIGN_ROUND_COMPLETE;           /* pretend member 1's ack has not come */
    size_t recs = h.p[0].n_recs;
    h_inject(&h, 1, 0, bad, ack->len);
    CHECK(!(r->acked & 2u) && h.p[0].n_recs == recs);
    h_inject(&h, 1, 0, ack->b, ack->len);
    CHECK(r->acked == 0xe && r->state == GZ_SIGN_ROUND_DONE && h.p[0].n_recs == recs + 1);
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
    for (int s = 0; s < e[5]; s++)
        if (r->def.items[i].signers[s] == 1) {
            uint8_t *nonce = e + 6 + 130 * s;
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
{   (void)b; (void)len; (void)r; ((uint8_t *)(uintptr_t)m->entry[0])[6 + 40] ^= 1; }   /* the host's nonce, unsigned by it now */
static void ea_drop(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r)
{   /* the last entry left out */
    const uint8_t *blocks[GZ_RMSG_MAX_ENTRIES];
    size_t sizes[GZ_RMSG_MAX_ENTRIES];
    static uint8_t copy[GZ_SIGN_MAX_MSG];
    (void)r;
    memcpy(copy, b, *len);
    for (int k = 0; k + 1 < m->n; k++) { blocks[k] = copy + (m->entry[k] - b); sizes[k] = entry_size(b, *len, m, k); }
    *len = rebuild_list(b, GZ_SIGN_MAX_MSG, m, blocks, sizes, (size_t)m->n - 1);
}
static void ea_twice(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r)
{   /* the first entry twice, in place of the second */
    (void)r; (void)len;
    size_t a = (size_t)(m->entry[1] - m->entry[0]);
    if ((size_t)(m->entry[1] - b) + a <= *len && m->entry[0][5] == m->entry[1][5])
        memcpy((uint8_t *)(uintptr_t)m->entry[1], m->entry[0], a);
    else memcpy((uint8_t *)(uintptr_t)m->entry[1], m->entry[0], 4);
}
static void ea_count(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r)
{   (void)b; (void)len; (void)r; ((uint8_t *)(uintptr_t)m->entry[0])[5]--; }
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
        {ea_own, GZ_SIGN_WHY_OWN_NONCE_CHANGED}, {ea_other, GZ_SIGN_WHY_BAD_NONCE}, {ea_drop, GZ_SIGN_WHY_BAD_MESSAGE},
        {ea_twice, GZ_SIGN_WHY_BAD_MESSAGE}, {ea_foreign, GZ_SIGN_WHY_BAD_MESSAGE}};
    uint64_t d = 0;
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        while (q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
        deliver_edited(&h, q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES), cases[c].edit, 0);
        const gz_sign_round_t *m = h_newest(&h, 1);
        if (!(m->state == GZ_SIGN_ROUND_ABORTED && m->why == cases[c].why)) printf("  member fault %zu: state %u why %u\n", c, m->state, m->why);
        CHECK(m->state == GZ_SIGN_ROUND_ABORTED && m->why == cases[c].why && h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == 0);
        CHECK(check_abort(h_sent_kind(&h, 1, GZ_SIGN_MSG_ABORT, 0), R(cases[c].why), WHOLE, 0, NULL));
        CHECK(h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 1 && h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE] == 0);
        for (int i = 0; i < m->def.n_items; i++) CHECK(m->secnonce_serial[i] == 0);
        h_flush(&h, 100000);
        h_ticks(&h, 2);
        CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE && h.p[0].e->attempts == 2);
        d ^= h_digest(&h) + c;
        h_free(&h);
    }
    /* a nonce set whose count does not match its length: not a message, no state changes */
    {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        while (q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
        deliver_edited(&h, q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES), ea_count, -1);
        CHECK(h_newest(&h, 1)->state == GZ_SIGN_ROUND_ACTIVE && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 1);
        CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == 0 && h_count_kind(&h, 1, GZ_SIGN_MSG_ABORT) == 0);
        d ^= h_digest(&h);
        h_free(&h);
    }
    /* a second, different nonce set after signing: refused, nothing sent; the same one again: the saved bytes */
    harness_t h;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
    long i = q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES);
    static uint8_t copy[GZ_SIGN_MAX_MSG];
    size_t len = h.q[i].len;
    memcpy(copy, h.q[i].b, len);
    h_deliver(&h, (size_t)i, 0);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == 1);
    h_inject(&h, 0, 1, copy, len);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == 2 && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 0);
    copy[len - 1] ^= 1;
    h_inject(&h, 0, 1, copy, len);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == 2 && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 1);
    copy[len - 1] ^= 1;
    h_inject(&h, 2, 1, copy, len);                                     /* not from the host */
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == 2);
    /* a wrong result, then one not signed by the host: Unfinished; then the right one completes it */
    while (q_find(&h, 0, 1, GZ_SIGN_MSG_RESULT) < 0) h_deliver(&h, 0, 0);
    i = q_find(&h, 0, 1, GZ_SIGN_MSG_RESULT);
    static uint8_t good[GZ_SIGN_MAX_MSG];
    size_t glen = h.q[i].len;
    memcpy(good, h.q[i].b, glen);
    h_drop_msg(&h, (size_t)i);
    memcpy(copy, good, glen);
    {
        gz_sign_msg_t mm;
        CHECK(gz_sign_decode(copy, glen, &mm));
        copy[(size_t)(mm.entry[0] - copy) + 4 + 10] ^= 1;        /* a final signature */
    }
    w_resign(copy, glen, 0);
    h_inject(&h, 0, 1, copy, glen);
    const gz_sign_round_t *m = h_newest(&h, 1);
    CHECK(m->state == GZ_SIGN_ROUND_UNFINISHED && m->why == GZ_SIGN_WHY_BAD_RESULT && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 2);
    memcpy(copy, good, glen);
    w_resign(copy, glen, 2);
    h_inject(&h, 0, 1, copy, glen);
    CHECK(m->state == GZ_SIGN_ROUND_UNFINISHED && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 3);
    /* complete before the result: ignored */
    long ci = q_find(&h, 0, 1, GZ_SIGN_MSG_COMPLETE);
    CHECK(ci >= 0);
    h_inject(&h, 0, 1, h.q[ci].b, h.q[ci].len);
    CHECK(m->state == GZ_SIGN_ROUND_UNFINISHED && h_count_kind(&h, 1, GZ_SIGN_MSG_ACK) == 0);
    h_inject(&h, 0, 1, good, glen);
    CHECK(m->state == GZ_SIGN_ROUND_ACTIVE && m->tier_state[0] == GZ_SIGN_TIER_DONE);
    /* a complete that is not signed by the host: ignored */
    memcpy(copy, h.q[ci].b, h.q[ci].len);
    copy[h.q[ci].len - 1] ^= 1;
    h_inject(&h, 0, 1, copy, h.q[ci].len);
    CHECK(m->state == GZ_SIGN_ROUND_ACTIVE && h_count_kind(&h, 1, GZ_SIGN_MSG_ACK) == 0);
    h_flush(&h, 100000);
    CHECK(m->state == GZ_SIGN_ROUND_COMPLETE && h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
    /* a host abort now changes nothing */
    uint8_t ab[512];
    h_inject(&h, 0, 1, ab, make_abort(ab, m->id, 4, 0));
    CHECK(m->state == GZ_SIGN_ROUND_COMPLETE);
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
        CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
    }
    CHECK(h.p[0].e->n_known == 2 && memcmp(h.p[0].e->known[0], ids[0], 32) == 0 && memcmp(h.p[0].e->known[1], ids[1], 32) == 0);
    for (uint32_t j = 1; j <= 3; j++) {
        CHECK(h.p[j].e->n_known == 2 && memcmp(h.p[j].e->known[0], ids[0], 32) == 0);
        CHECK(h_find(&h, j, ids[0]) == NULL && h_find(&h, j, ids[5]) != NULL);
    }
    /* the oldest proposal again: refused as known, never signed */
    const h_sent_t *p0 = h_sent_kind(&h, 0, GZ_SIGN_MSG_PROPOSE, 0);
    size_t n_nonces = h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES);
    h_inject(&h, 0, 1, p0->b, p0->len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], R(GZ_SIGN_WHY_KNOWN_ROUND), WHOLE, 0, NULL) && h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == n_nonces);
    /* a newer one again: answered with the saved ack */
    const h_sent_t *p5 = h_sent_kind(&h, 0, GZ_SIGN_MSG_PROPOSE, 15);
    h_inject(&h, 0, 1, p5->b, p5->len);
    CHECK(h.sent[h.n_sent - 1].kind == GZ_SIGN_MSG_ACK && h.p[1].e->counters[GZ_SIGN_COUNT_DUPLICATES] == 1);
    /* the same proposal from another member: nothing */
    size_t sent = h.n_sent;
    h_inject(&h, 2, 1, p5->b, p5->len);
    CHECK(h.n_sent == sent);
    /* a status request about a round the host has pushed out of memory: ignored, as for any unknown identifier (7.10) */
    uint8_t st[128];
    sent = h.n_sent;
    h_inject(&h, 1, 0, st, make_status(st, ids[0]));
    CHECK(h.n_sent == sent);
    /* restarts keep the refused list and every round held */
    check_restart_keeps(&h);
    h_inject(&h, 0, 1, p0->b, p0->len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], R(GZ_SIGN_WHY_KNOWN_ROUND), WHOLE, 0, NULL));
    /* a validly signed proposal from a peer that is not its host, one whose identifier is not the
     * member's own computation, and one the member's checks refuse: aborted with the reason, to the sender */
    static uint8_t bad[GZ_SIGN_MAX_PROPOSAL];
    memcpy(bad, p5->b, p5->len);
    h_inject(&h, 2, 1, bad, p5->len);
    bad[GZ_RMSG_HEADER + 2] ^= 1;                  /* another identifier, re-signed by the host */
    w_resign(bad, p5->len, 0);
    h_inject(&h, 2, 1, bad, p5->len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], R(GZ_SIGN_WHY_INVALID_ROUND), WHOLE, 0, NULL) && h.sent[h.n_sent - 1].peer == 2);
    h_inject(&h, 0, 1, bad, p5->len);              /* from the host, the identifier does not match */
    CHECK(check_abort(&h.sent[h.n_sent - 1], R(GZ_SIGN_WHY_ID_MISMATCH), WHOLE, 0, NULL));
    h.builder.refuse = 9;                          /* the member's checks refuse (C8) */
    bad[GZ_RMSG_HEADER + 3] ^= 1;
    w_resign(bad, p5->len, 0);
    h_inject(&h, 0, 1, bad, p5->len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], 9, WHOLE, 0, NULL));
    h.builder.refuse = 0;
    sent = h.n_sent;
    bad[GZ_RMSG_HEADER + 3] ^= 1;
    bad[p5->len - 1] ^= 1;                         /* not signed by the host it names: nothing to answer */
    h_inject(&h, 0, 1, bad, p5->len);
    CHECK(h.n_sent == sent);
    memcpy(bad, p5->b, p5->len);
    bad[p5->len - 1] ^= 1;                         /* the host's signature, on a known identifier */
    sent = h.n_sent;
    uint64_t rejected = h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED];
    h_inject(&h, 0, 1, bad, p5->len);
    /* checked before the identifier is looked up (messages.md 7.2's order): nothing answered */
    CHECK(h.n_sent == sent && h.p[1].e->counters[GZ_SIGN_COUNT_DUPLICATES] == 0 && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == rejected + 1);
    CHECK(h.p[1].e->n_known == 2);
    /* many refused identifiers (review A, F2): the exact list keeps only the newest, the filter
     * keeps all, so an identifier pushed out of the list is still refused, and a new round is
     * still held. Here the list is overwritten as if hundreds more had come after. */
    gz_sign_t *e1 = h.p[1].e;
    for (size_t k = 0; k < GZ_SIGN_MAX_KNOWN; k++) {
        memset(e1->known[k], 0xee, 32);
        e1->known[k][0] = (uint8_t)k;
    }
    e1->n_known = 3 * GZ_SIGN_MAX_KNOWN + 7;
    n_nonces = h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES);
    h_inject(&h, 0, 1, p0->b, p0->len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], R(GZ_SIGN_WHY_KNOWN_ROUND), WHOLE, 0, NULL) && h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == n_nonces);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    long pi = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(pi >= 0);
    h_deliver(&h, (size_t)pi, 0);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == n_nonces + 1 && h_find(&h, 1, h_newest(&h, 0)->id) != NULL);
    CHECK(e1->n_known == 3 * GZ_SIGN_MAX_KNOWN + 8 && memcmp(e1->known[7], ids[2], 32) == 0);
    uint64_t d = h_digest(&h);
    h_free(&h);

    /* a fresh round's proposal with a broken host signature, and one naming a member not in it */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    const h_sent_t *p = h_sent_kind(&h, 0, GZ_SIGN_MSG_PROPOSE, 0);
    memcpy(bad, p->b, p->len);
    bad[p->len - 1] ^= 1;
    harness_t h2;
    h_init(&h2, 3);
    sent = h2.n_sent;
    h_inject(&h2, 0, 1, bad, p->len);
    CHECK(h2.n_sent == sent && h_newest(&h2, 1) == NULL);
    CHECK(h2.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 1);
    h_free(&h);
    uint8_t q[W_PARAMS];
    gz_action_list_t list;
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    w_params(q, 1, 1, w_mask(2), 0);               /* members 1 and 2 only */
    CHECK(w_begin_params(h2.p[0].e, &h2.builder, q, W_PARAMS, &list) == GZ_OK);
    h_apply(&h2, 0, &list);
    p = h_sent_kind(&h2, 0, GZ_SIGN_MSG_PROPOSE, 0);
    h_inject(&h2, 0, 3, p->b, p->len);
    /* S5: the list lacks this member's current keys: reason 12, nothing held */
    CHECK(check_abort(&h2.sent[h2.n_sent - 1], 12, WHOLE, 0, NULL) && h_newest(&h2, 3) == NULL);
    /* the host cannot begin while a round runs; a member cannot begin at all */
    CHECK(w_begin_params(h2.p[0].e, &h2.builder, q, W_PARAMS, &list) == GZ_ERR_ARGUMENT);
    CHECK(w_begin_params(h2.p[1].e, &h2.builder, q, W_PARAMS, &list) == GZ_ERR_ARGUMENT);
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
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
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
                gz_storage_reader_t rd = {h_next, h_rewind, p, 1, 0};
                gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
                gz_status_t st = gz_sign_start(p->e, &rd, &list, &more);
                /* every damage is refused, except in the two records that carry no signature */
                /* Every damage is refused, except where the bytes carry no signature and nothing to
                 * check them against: funding_status and the guard (not the engine's to read); and in the last byte, a
                 * round_started's own key (read as a key of an earlier epoch: refused, never resumed), a
                 * host's round_ended (its why, for display) and a member's round_completed (its ack tip). */
                int must = keep.type != GZ_SIGN_REC_FUNDING_STATUS && keep.type != GZ_SIGN_REC_GUARD &&
                           !(how == 4 && (keep.type == GZ_SIGN_REC_ROUND_STARTED || (g == 0 && keep.type == GZ_SIGN_REC_ROUND_ENDED) ||
                                          (g != 0 && keep.type == GZ_SIGN_REC_ROUND_COMPLETED)));
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

/* Every item's signers in reverse order (the host last), each spent script made to match:
 * a member then signs at position 0 of some items. */
static void reverse_signers(gz_sign_def_t *d, int which)
{
    (void)which;
    for (int i = 0; i < d->n_items; i++) {
        gz_sign_item_t *it = &d->items[i];
        secp256k1_pubkey pks[GZ_SIGN_MAX_SIGNERS], tw_pk;
        const secp256k1_pubkey *ptr[GZ_SIGN_MAX_SIGNERS];
        secp256k1_xonly_pubkey agg, x;
        secp256k1_musig_keyagg_cache c;
        uint8_t ser[32], tw[32];
        gz_sign_sha256_t th;
        for (int a = 0, b = it->n_signers - 1; a < b; a++, b--) { uint8_t t = it->signers[a]; it->signers[a] = it->signers[b]; it->signers[b] = t; }
        for (int k = 0; k < it->n_signers; k++) {
            if (!secp256k1_ec_pubkey_parse(w_ctx(), &pks[k], d->participants[it->signers[k]].factory_key, 33)) abort();
            ptr[k] = &pks[k];
        }
        if (!secp256k1_musig_pubkey_agg(w_ctx(), NULL, &agg, &c, ptr, it->n_signers) || !secp256k1_xonly_pubkey_serialize(w_ctx(), ser, &agg)) abort();
        gz_sign_tagged_init(&th, "TapTweak");
        gz_sign_sha256_write(&th, ser, 32);
        if (it->has_merkle_root) gz_sign_sha256_write(&th, it->merkle_root, 32);
        gz_sign_sha256_done(&th, tw);
        if (!secp256k1_musig_pubkey_xonly_tweak_add(w_ctx(), &tw_pk, &c, tw) || !secp256k1_xonly_pubkey_from_pubkey(w_ctx(), &x, NULL, &tw_pk) ||
            !secp256k1_xonly_pubkey_serialize(w_ctx(), it->spent_script + 2, &x)) abort();
    }
}

static void ea_extra(uint8_t *b, size_t *len, const gz_sign_msg_t *m, const gz_sign_round_t *r)
{   /* entry 0 once more at the end, the count raised */
    (void)r;
    size_t a = (size_t)((m->n > 1 ? m->entry[1] : b + *len) - m->entry[0]);
    const uint8_t *blocks[GZ_RMSG_MAX_ENTRIES];
    size_t sizes[GZ_RMSG_MAX_ENTRIES];
    static uint8_t copy[GZ_SIGN_MAX_MSG];
    memcpy(copy, b, *len);
    for (int k = 0; k < m->n; k++) { blocks[k] = copy + (m->entry[k] - b); sizes[k] = entry_size(b, *len, m, k); }
    blocks[m->n] = copy + (m->entry[0] - b); sizes[m->n] = a;
    *len = rebuild_list(b, GZ_SIGN_MAX_MSG, m, blocks, sizes, (size_t)m->n + 1);
}

/* A result edited: the second entry made a copy of the first; or the last left out; or one from another tier. */
static size_t edit_result(uint8_t *out, const uint8_t *in, size_t len, int how, const gz_sign_round_t *r)
{
    gz_sign_msg_t m;
    memcpy(out, in, len);
    if (!gz_sign_decode(out, len, &m) || m.n < 2) return 0;
    uint8_t *e0 = (uint8_t *)(uintptr_t)m.entry[0], *e1 = (uint8_t *)(uintptr_t)m.entry[1];
    if (how == 0) memcpy(e1, e0, 68);
    else if (how == 1) {
        const uint8_t *blocks[GZ_RMSG_MAX_ENTRIES];
        size_t sizes[GZ_RMSG_MAX_ENTRIES];
        static uint8_t copy[GZ_SIGN_MAX_MSG];
        memcpy(copy, out, len);
        for (int k = 0; k + 1 < m.n; k++) { blocks[k] = copy + (m.entry[k] - out); sizes[k] = 68; }
        len = rebuild_list(out, GZ_SIGN_MAX_MSG, &m, blocks, sizes, (size_t)m.n - 1);
    } else {
        for (uint32_t i = 0; i < r->def.n_items; i++)
            if (r->def.items[i].tier != m.tier) { e0[0] = (uint8_t)(i >> 24); e0[1] = (uint8_t)(i >> 16); e0[2] = (uint8_t)(i >> 8); e0[3] = (uint8_t)i; break; }
    }
    w_resign(out, len, 0);
    return len;
}

static uint64_t sc_edges(void)
{
    uint64_t d = 0;
    /* A. Signers out of increasing order (messages.md 7.1: positions increasing, the host first),
     * every spent script made to match: refused before anything is proposed. */
    {
        harness_t h;
        h_init(&h, 4);
        h.builder.mutate = reverse_signers;
        CHECK(h_begin(&h, 2, 4, 0) == GZ_ERR_ARGUMENT && h.n_sent == 0 && h_newest(&h, 0) == NULL);
        d ^= h_digest(&h);
        h_free(&h);
    }
    /* B. After a restart in Signed, the same nonce set again: refused (no saved answer for it), nothing sent */
    {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        while (q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
        long i = q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES);
        static uint8_t set[GZ_SIGN_MAX_MSG];
        size_t len = h.q[i].len;
        memcpy(set, h.q[i].b, len);
        h_deliver(&h, (size_t)i, 0);
        CHECK(h_restart(&h, 1) == GZ_OK);
        size_t parts = h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS);
        h_inject(&h, 0, 1, set, len);
        CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == parts && h.p[1].e->counters[GZ_SIGN_COUNT_REJECTED] == 1);
        /* F. the proposal again while Signed: the saved partial signatures */
        const h_sent_t *prop = h_sent_kind(&h, 0, GZ_SIGN_MSG_PROPOSE, 0);
        h_inject(&h, 0, 1, prop->b, prop->len);
        CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == parts + 1 && h.sent[h.n_sent - 1].kind == GZ_SIGN_MSG_PARTIALS);
        /* and once the result is in, before complete: nothing at all */
        while (q_find(&h, 0, 1, GZ_SIGN_MSG_RESULT) < 0) h_deliver(&h, 0, 0);
        h_deliver(&h, (size_t)q_find(&h, 0, 1, GZ_SIGN_MSG_RESULT), 0);
        CHECK(h_newest(&h, 1)->tier_state[0] == GZ_SIGN_TIER_DONE && h_newest(&h, 1)->state == GZ_SIGN_ROUND_ACTIVE);
        size_t sent = h.n_sent;
        h_inject(&h, 0, 1, prop->b, prop->len);
        CHECK(h.n_sent == sent);
        h_flush(&h, 100000);
        CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
        d ^= h_digest(&h);
        h_free(&h);
    }
    /* C. A nonce set with one entry twice (the count raised): refused as malformed */
    {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        while (q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
        deliver_edited(&h, q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES), ea_extra, -1);
        const gz_sign_round_t *m = h_newest(&h, 1);
        CHECK(m->state == GZ_SIGN_ROUND_ABORTED && m->why == GZ_SIGN_WHY_BAD_MESSAGE && h.p[1].e->counters[GZ_SIGN_COUNT_PARTIALS_MADE] == 0);
        d ^= h_digest(&h);
        h_free(&h);
    }
    /* D. Results with an entry twice, one left out, or one from another tier: Unfinished, nothing saved */
    for (int how = 0; how < 3; how++) {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
        while (q_find(&h, 0, 1, GZ_SIGN_MSG_RESULT) < 0) h_deliver(&h, 0, 0);
        long i = q_find(&h, 0, 1, GZ_SIGN_MSG_RESULT);
        static uint8_t bad[GZ_SIGN_MAX_MSG];
        size_t len = edit_result(bad, h.q[i].b, h.q[i].len, how, h_newest(&h, 0));
        CHECK(len > 0);
        h_drop_msg(&h, (size_t)i);
        size_t recs = h.p[1].n_recs;
        h_inject(&h, 0, 1, bad, len);
        const gz_sign_round_t *m = h_newest(&h, 1);
        if (!(m->state == GZ_SIGN_ROUND_UNFINISHED && m->why == GZ_SIGN_WHY_BAD_RESULT)) printf("  result edit %d: state %u why %u\n", how, m->state, m->why);
        CHECK(m->state == GZ_SIGN_ROUND_UNFINISHED && m->why == GZ_SIGN_WHY_BAD_RESULT && h.p[1].n_recs == recs);
        d ^= h_digest(&h) + (uint64_t)how;
        h_free(&h);
    }
    /* E. Ticks before progress do not count after it: the deadline and the resends count from the last step. */
    {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
        flush_until(&h, 1, GZ_SIGN_MSG_NONCES, 1);
        h_tick(&h, 1); h_tick(&h, 1);                      /* member 1: two ticks while it waits for the nonce set */
        while (q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES) < 0) h_deliver(&h, 0, 0);
        h_deliver(&h, (size_t)q_find(&h, 0, 1, GZ_SIGN_MSG_ALL_NONCES), 0);
        h.drop_to = 1u << 1;                               /* it hears nothing more */
        size_t p0 = h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS);
        h_tick(&h, 1);
        CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == p0);   /* one tick since it signed: no resend yet */
        h_tick(&h, 1); h_tick(&h, 1);
        CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == p0 + 1);
        d ^= h_digest(&h);
        h_free(&h);

        /* the next tier's nonce deadline counts from the result */
        h_init(&h, 3);
        CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
        const gz_sign_round_t *r = h_newest(&h, 0);
        uint32_t j = 1;
        while (j <= 3 && items_of(r, j, 1, NULL) == 0) j++;
        CHECK(j <= 3);
        while (q_find(&h, 0, j, GZ_SIGN_MSG_RESULT) < 0) {
            if (!h.nq) break;
            h_deliver(&h, 0, 0);
        }
        for (int t = 0; t < 5; t++) h_tick(&h, j);         /* ticks while waiting for the result */
        h.drop_to = 1u;
        h_deliver(&h, (size_t)q_find(&h, 0, j, GZ_SIGN_MSG_RESULT), 0);
        CHECK(h_newest(&h, j)->tier == 1 && h_newest(&h, j)->tier_state[1] == GZ_SIGN_TIER_NONCES);
        for (int t = 0; t < 11; t++) h_tick(&h, j);
        CHECK(h_newest(&h, j)->state == GZ_SIGN_ROUND_ACTIVE);
        h_tick(&h, j);
        CHECK(h_newest(&h, j)->state == GZ_SIGN_ROUND_UNFINISHED && h_newest(&h, j)->why == GZ_SIGN_WHY_DEADLINE);
        d ^= h_digest(&h);
        h_free(&h);

        /* a member's resends after a result count from that result. (With children before parents, C6,
         * the last tier holds the root, which every member signs: no member is without an item there.) */
        for (int tiers = 1; tiers <= 1; tiers++) {
            h_init(&h, 3);
            CHECK(h_begin(&h, (uint8_t)tiers, 3, 0) == GZ_OK);
            r = h_newest(&h, 0);
            j = 1;
            CHECK(items_of(r, j, tiers - 1, NULL) > 0);
            flush_until(&h, j, GZ_SIGN_MSG_PARTIALS, 1);
            h_tick(&h, j); h_tick(&h, j);                  /* two ticks after signing */
            while (q_find(&h, 0, j, GZ_SIGN_MSG_RESULT) < 0 && h.nq) h_deliver(&h, 0, 0);
            h.drop_to = 1u << j;
            for (size_t k = 0; k < h.nq; k++) if (h.q[k].to == 0) { h_drop_msg(&h, k); k--; }
            h.drop_to = 1u;
            h_deliver(&h, (size_t)q_find(&h, 0, j, GZ_SIGN_MSG_RESULT), 0);
            CHECK(h_newest(&h, j)->tier_state[tiers - 1] >= GZ_SIGN_TIER_SIGNED);
            size_t st0 = h_count_kind(&h, j, GZ_SIGN_MSG_STATUS);
            h_tick(&h, j);
            CHECK(h_count_kind(&h, j, GZ_SIGN_MSG_STATUS) == st0);
            h_tick(&h, j); h_tick(&h, j);
            CHECK(h_count_kind(&h, j, GZ_SIGN_MSG_STATUS) == st0 + 1);
            d ^= h_digest(&h);
            h_free(&h);
        }

        /* the host's deadlines count from each step: the nonce set, the next tier */
        for (int tiers = 1; tiers <= 2; tiers++) {
            h_init(&h, 3);
            CHECK(h_begin(&h, (uint8_t)tiers, 3, 0) == GZ_OK);
            if (tiers == 1) {
                for (int t = 0; t < 5; t++) h_tick(&h, 0);         /* five host ticks while it collects nonces */
                while (h.nq && h_count_kind(&h, 0, GZ_SIGN_MSG_ALL_NONCES) == 0) h_deliver(&h, 0, 0);
            } else {
                while (h.nq && h_count_kind(&h, 0, GZ_SIGN_MSG_ALL_NONCES) == 0) h_deliver(&h, 0, 0);
                for (int t = 0; t < 5; t++) h_tick(&h, 0);         /* five host ticks while it collects partial signatures */
                while (h.nq && h_newest(&h, 0)->tier == 0) h_deliver(&h, 0, 0);
            }
            h.drop_to = 1u;
            for (size_t k = 0; k < h.nq; k++) if (h.q[k].to == 0) { h_drop_msg(&h, k); k--; }
            uint8_t rid[32];
            memcpy(rid, h_newest(&h, 0)->id, 32);
            for (int t = 0; t < 11; t++) h_tick(&h, 0);
            CHECK(h_find(&h, 0, rid)->state == GZ_SIGN_ROUND_ACTIVE && h.p[0].e->attempts == 1);
            h_tick(&h, 0);
            CHECK(h_find(&h, 0, rid)->state == GZ_SIGN_ROUND_FAILED && h_find(&h, 0, rid)->why == GZ_SIGN_WHY_DEADLINE);
            d ^= h_digest(&h);
            h_free(&h);
        }

        /* the host's ack deadline counts from the complete */
        h_init(&h, 3);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        while (h.nq && q_find(&h, 1, 0, GZ_SIGN_MSG_PARTIALS) < 0) h_deliver(&h, 0, 0);
        for (int t = 0; t < 2; t++) h_tick(&h, 0);         /* two host ticks while it collects */
        while (h.nq && h_newest(&h, 0)->state != GZ_SIGN_ROUND_COMPLETE) h_deliver(&h, 0, 0);
        h.drop_to = 1u;
        h_flush(&h, 100000);
        for (int t = 0; t < 11; t++) h_tick(&h, 0);
        CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_COMPLETE);
        h_tick(&h, 0);
        CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_FAILED && h_newest(&h, 0)->why == GZ_SIGN_WHY_DEADLINE);
        d ^= h_digest(&h);
        h_free(&h);
    }
    return d;
}

/* ---- contract v2 section 3: the reconnect table, row by row ---- */

static size_t sent_since(const harness_t *h, size_t from, uint32_t party, uint8_t kind)
{
    size_t n = 0;
    for (size_t i = from; i < h->n_sent; i++) n += h->sent[i].party == party && (kind == 0 || h->sent[i].kind == kind);
    return n;
}
/* Drop every queued message from `from` to `to` of `kind` (0: any). */
static size_t drop_queued(harness_t *h, uint32_t from, uint32_t to, uint8_t kind)
{
    size_t n = 0;
    for (size_t k = 0; k < h->nq; k++)
        if (h->q[k].from == from && h->q[k].to == to && (kind == 0 || h_kind_of(h->q[k].b, h->q[k].len) == kind)) { h_drop_msg(h, k); k--; n++; }
    return n;
}

static uint64_t sc_reconnect(void)
{
    uint64_t d = 0;
    /* Row "member": partial signatures sent and lost with the connection, the result missing.
     * At PEER_CONNECTED the member resends its saved partial signatures, then asks for the status. */
    {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        flush_until(&h, 1, GZ_SIGN_MSG_PARTIALS, 1);
        CHECK(drop_queued(&h, 1, 0, GZ_SIGN_MSG_PARTIALS) == 1);       /* lost with the connection */
        size_t at = h.n_sent;
        CHECK(h_connect(&h, 1, 0) == GZ_OK);
        CHECK(h.n_sent == at + 2 && h.sent[at].kind == GZ_SIGN_MSG_PARTIALS && h.sent[at + 1].kind == GZ_SIGN_MSG_STATUS);
        const h_sent_t *p0 = h_sent_kind(&h, 1, GZ_SIGN_MSG_PARTIALS, 0);
        CHECK(p0 && h.sent[at].len == p0->len && memcmp(h.sent[at].b, p0->b, p0->len) == 0);   /* the saved bytes (S3) */
        h_flush(&h, 100000);
        CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE && h.p[0].e->attempts == 1);
        d ^= h_digest(&h);
        h_free(&h);
    }
    /* Row "either, in the nonce phase": nothing at PEER_CONNECTED, on either side; the host's
     * step timer alone repairs it: a lost round_nonces by resending the saved round_propose, which
     * the member answers with its saved nonces; a lost round_all_nonces by resending it. */
    {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        flush_until(&h, 2, GZ_SIGN_MSG_NONCES, 1);
        CHECK(drop_queued(&h, 2, 0, GZ_SIGN_MSG_NONCES) == 1);
        size_t at = h.n_sent;
        CHECK(h_connect(&h, 2, 0) == GZ_OK && h_connect(&h, 0, 2) == GZ_OK);
        CHECK(h.n_sent == at);                                         /* nobody pushes anything at connect */
        h_flush(&h, 100000);
        CHECK(h_newest(&h, 0)->tier_state[0] == GZ_SIGN_TIER_NONCES);
        for (int t = 0; t < 3; t++) h_tick(&h, 0);                     /* the step timer, every resend_ticks */
        CHECK(sent_since(&h, at, 0, GZ_SIGN_MSG_PROPOSE) == 1 && h.sent[h.n_sent - 1].peer == 2);
        h_deliver(&h, (size_t)q_find(&h, 0, 2, GZ_SIGN_MSG_PROPOSE), 0);
        const h_sent_t *n0 = h_sent_kind(&h, 2, GZ_SIGN_MSG_NONCES, 0), *n1 = h_sent_kind(&h, 2, GZ_SIGN_MSG_NONCES, 1);
        CHECK(n0 && n1 && n0->len == n1->len && memcmp(n0->b, n1->b, n0->len) == 0);   /* never new nonces */
        /* now the nonce set to member 3 is lost */
        while (q_find(&h, 0, 3, GZ_SIGN_MSG_ALL_NONCES) < 0 && h.nq) h_deliver(&h, 0, 0);
        CHECK(drop_queued(&h, 0, 3, GZ_SIGN_MSG_ALL_NONCES) == 1);
        h_flush(&h, 100000);
        CHECK(h_newest(&h, 0)->tier_state[0] == GZ_SIGN_TIER_SIGNED);
        at = h.n_sent;
        for (int t = 0; t < 3; t++) h_tick(&h, 0);
        CHECK(sent_since(&h, at, 0, GZ_SIGN_MSG_ALL_NONCES) == 1 && h.sent[h.n_sent - 1].peer == 3);
        h_flush(&h, 100000);
        CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE && h.p[0].e->attempts == 1);
        d ^= h_digest(&h);
        h_free(&h);
    }
    /* Row "member", Complete and not yet live: the ack lost; at PEER_CONNECTED the member asks for
     * the status, the host answers with the saved results and round_complete, the member resends its
     * saved ack. The host answers one status request per round and member key in status_ticks. */
    {
        harness_t h;
        h_init(&h, 3);
        h.status_ticks = 10;
        for (uint32_t g = 0; g < h.n; g++) h.p[g].e->cfg.status_ticks = 10;
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        flush_until(&h, 3, GZ_SIGN_MSG_ACK, 1);
        CHECK(drop_queued(&h, 3, 0, GZ_SIGN_MSG_ACK) == 1);
        h_flush(&h, 100000);
        CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_COMPLETE && h_newest(&h, 3)->state == GZ_SIGN_ROUND_COMPLETE);
        size_t at = h.n_sent;
        CHECK(h_connect(&h, 3, 0) == GZ_OK);
        CHECK(h.n_sent == at + 1 && h.sent[at].kind == GZ_SIGN_MSG_STATUS);
        CHECK(h_connect(&h, 3, 0) == GZ_OK);                           /* a second connection at once */
        h_flush(&h, 100000);
        /* one answer: the result and the complete, once; the ack again, the same bytes */
        CHECK(sent_since(&h, at, 0, GZ_SIGN_MSG_RESULT) == 1 && sent_since(&h, at, 0, GZ_SIGN_MSG_COMPLETE) == 1);
        CHECK(h.p[0].e->counters[GZ_SIGN_COUNT_DUPLICATES] >= 1);
        const h_sent_t *a0 = h_sent_kind(&h, 3, GZ_SIGN_MSG_ACK, 0), *a1 = h_sent_kind(&h, 3, GZ_SIGN_MSG_ACK, 1);
        CHECK(a0 && a1 && a0->len == a1->len && memcmp(a0->b, a1->b, a0->len) == 0);
        CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
        /* after status_ticks, answered again */
        for (int t = 0; t < 10; t++) h_tick(&h, 0);
        h_flush(&h, 100000);
        at = h.n_sent;
        CHECK(h_connect(&h, 3, 0) == GZ_OK);
        h_flush(&h, 100000);
        CHECK(sent_since(&h, at, 0, GZ_SIGN_MSG_RESULT) == 1);
        d ^= h_digest(&h);
        h_free(&h);
    }
    /* Row "member", after a restart while the host still collects partial signatures (F26):
     * the restarted member resends them and the round completes; a restart in the nonce phase
     * answers the replayed proposal with reason 3 only (S2). */
    {
        harness_t h;
        h_init(&h, 3);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        flush_until(&h, 2, GZ_SIGN_MSG_PARTIALS, 1);
        CHECK(drop_queued(&h, 2, 0, GZ_SIGN_MSG_PARTIALS) == 1);
        CHECK(h_restart(&h, 2) == GZ_OK);
        CHECK(h_count_kind(&h, 2, GZ_SIGN_MSG_PARTIALS) == 2);
        h_flush(&h, 100000);
        CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE && h.p[0].e->attempts == 1);
        d ^= h_digest(&h);
        h_free(&h);
    }
    return d;
}

/* ---- the journal's records, the hooks and the round's end ---- */

static const h_rec_t *last_rec(const harness_t *h, uint32_t g, uint32_t type)
{
    for (size_t i = h->p[g].n_recs; i-- > 0;)
        if (h->p[g].recs[i].type == type) return &h->p[g].recs[i];
    return NULL;
}

static uint64_t sc_records(void)
{
    uint64_t d = 0;
    /* The guard is in the batch of every round_started (journal.md 8.3); may_ack runs before the
     * ack, and its tip is saved with it (round_completed, funding_status) and read back; FUNDING
     * is reported once, when every ack is in. */
    {
        harness_t h;
        h_init(&h, 3);
        h.builder.tip = 1234;
        CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
        h_flush(&h, 100000);
        CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
        for (uint32_t g = 0; g < h.n; g++)
            for (size_t i = 0; i < h.p[g].n_recs; i++) {
                if (h.p[g].recs[i].type != GZ_SIGN_REC_ROUND_STARTED) continue;
                int guarded = 0;
                for (size_t k = 0; k < h.p[g].n_recs; k++)
                    guarded |= h.p[g].recs[k].batch == h.p[g].recs[i].batch && h.p[g].recs[k].type == GZ_SIGN_REC_GUARD;
                CHECK(guarded);
            }
        CHECK(h.builder.may_ack_calls == 3 && h.builder.may_ack_refused == 0);
        for (uint32_t j = 1; j <= 3; j++) {
            const h_rec_t *c = last_rec(&h, j, GZ_SIGN_REC_ROUND_COMPLETED), *f = last_rec(&h, j, GZ_SIGN_REC_FUNDING_STATUS);
            const uint8_t *tip = c ? rec_field(c, 8, NULL) : NULL, *ft = f ? rec_field(f, 6, NULL) : NULL;
            CHECK(tip && be32p(tip) == 1234 && ft && be32p(ft) == 1234 && c->batch == f->batch);
            CHECK(f && memcmp(rec_field(f, 2, NULL), h_newest(&h, j)->def.funding_txid, 32) == 0);
        }
        CHECK(h.builder.n_outcomes == 1 && h.builder.outcomes[0] == GZ_SIGN_OUTCOME_FUNDING);
        check_restart_keeps(&h);
        for (uint32_t j = 1; j <= 3; j++) CHECK(h_newest(&h, j)->ack_tip == 1234);   /* read back, never the new tip */
        /* resolved Live: saved; the member stops asking */
        static gz_action_t s[8];
        static uint8_t sb[4096];
        gz_action_list_t l;
        gz_action_list_init(&l, s, 8, sb, sizeof sb);
        CHECK(gz_sign_resolve(h.p[1].e, h_newest(&h, 1)->id, GZ_SIGN_END_LIVE, &l) == GZ_OK && l.count == 1);
        h_apply(&h, 1, &l);
        CHECK(h_newest(&h, 1)->state == GZ_SIGN_ROUND_LIVE);
        gz_action_list_init(&l, s, 8, sb, sizeof sb);
        CHECK(gz_sign_resolve(h.p[1].e, h_newest(&h, 1)->id, GZ_SIGN_END_DEAD, &l) == GZ_ERR_ARGUMENT);   /* Live is final */
        size_t st = h_count_kind(&h, 1, GZ_SIGN_MSG_STATUS);
        for (int t = 0; t < 6; t++) h_tick(&h, 1);
        CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_STATUS) == st);
        CHECK(h_restart(&h, 1) == GZ_OK && h_newest(&h, 1)->state == GZ_SIGN_ROUND_LIVE);
        d ^= h_digest(&h);
        h_free(&h);
    }
    /* may_ack refuses (the tip too late for the exit time): no ack, no funding; Unfinished, then
     * Abandoned at the unfinished deadline, saved as round_ended. */
    {
        harness_t h;
        h_init(&h, 3);
        h.unfinished_ticks = 6;
        for (uint32_t g = 0; g < h.n; g++) h.p[g].e->cfg.unfinished_ticks = 6;
        h.builder.tip = 99990;
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        h_flush(&h, 100000);
        CHECK(h.builder.may_ack_refused == 3 && h_count_kind(&h, 1, GZ_SIGN_MSG_ACK) == 0);
        const gz_sign_round_t *m = h_newest(&h, 1);
        CHECK(m->state == GZ_SIGN_ROUND_UNFINISHED && m->why == GZ_SIGN_WHY_ACK_REFUSED && h_newest(&h, 0)->state == GZ_SIGN_ROUND_COMPLETE);
        for (int t = 0; t < 6; t++) h_tick(&h, 1);
        CHECK(h_newest(&h, 1)->state == GZ_SIGN_ROUND_ABANDONED);
        const h_rec_t *e = last_rec(&h, 1, GZ_SIGN_REC_ROUND_ENDED);
        CHECK(e && rec_field(e, 4, NULL)[0] == GZ_SIGN_END_ABANDONED);
        CHECK(h_restart(&h, 1) == GZ_OK && h_newest(&h, 1)->state == GZ_SIGN_ROUND_ABANDONED);
        d ^= h_digest(&h);
        h_free(&h);
    }
    /* No retry hook: a failed attempt is reported RETRY with the blamed members' keys; the last
     * attempt FAILED. */
    {
        harness_t h;
        h_init(&h, 3);
        h.max_attempts = 2;
        for (uint32_t g = 0; g < h.n; g++) h.p[g].e->cfg.max_attempts = 2;
        h.p[0].e->cfg.retry = NULL;
        h.drop_to = 1u << 3;                                            /* member 3 hears nothing */
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        h_flush(&h, 100000);
        h_ticks(&h, 12);
        CHECK(h.builder.n_outcomes == 1 && h.builder.outcomes[0] == GZ_SIGN_OUTCOME_RETRY && h.builder.outcome_blamed[0] == 1);
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        h_flush(&h, 100000);
        h_ticks(&h, 12);
        CHECK(h.builder.n_outcomes == 2 && h.builder.outcomes[1] == GZ_SIGN_OUTCOME_FAILED);
        d ^= h_digest(&h);
        h_free(&h);
    }
    return d;
}

/* ---- C7 and C10 (safety-rule.md): one tree per funding outpoint, one round per output ---- */

/* Another tree on the same funding output: the last leaf's version changed (nobody spends it). */
static void other_tree(gz_sign_def_t *dd, int which)
{
    (void)which;
    dd->items[dd->n_items - 1].tx[0] ^= 1;
}

/* Every member's unresolved rounds, past their step timeout, resolved Abandoned. */
static void resolve_all(harness_t *h)
{
    static gz_action_t s[8];
    static uint8_t sb[4096];
    gz_action_list_t l;
    for (uint32_t j = 1; j < h->n; j++)
        for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
            const gz_sign_round_t *r = &h->p[j].e->rounds[k];
            if (r->state != GZ_SIGN_ROUND_UNFINISHED && r->state != GZ_SIGN_ROUND_COMPLETE) continue;
            gz_action_list_init(&l, s, 8, sb, sizeof sb);
            CHECK(gz_sign_resolve(h->p[j].e, r->id, GZ_SIGN_END_ABANDONED, &l) == GZ_OK);
            h_apply(h, j, &l);
        }
}

static uint64_t sc_exposure(void)
{
    harness_t h;
    gz_action_list_t l;
    static gz_action_t s[8];
    static uint8_t sb[4096];
    h_init(&h, 3);
    h.p[0].e->cfg.retry = NULL;
    /* Round A on one outpoint (WF_SAME_TREE): member 1 releases its partial signatures (its
     * exposure record), then member 2 hears nothing more. */
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    uint8_t ida[32];
    memcpy(ida, h_newest(&h, 0)->id, 32);
    flush_until(&h, 1, GZ_SIGN_MSG_PARTIALS, 1);
    CHECK(h.p[1].e->n_exposures == 1 && memcmp(h.p[1].e->exposures[0].tree_digest, h_find(&h, 1, ida)->def.tree_digest, 32) == 0);
    h.drop_to = 1u << 2;
    h_flush(&h, 100000);
    h_ticks(&h, 12);
    h.drop_to = 0;
    CHECK(h_find(&h, 0, ida)->state == GZ_SIGN_ROUND_FAILED);
    /* C10: a new round on the same outpoint while member 1's round on it is unresolved: reason 6 */
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    long pi = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(pi >= 0);
    h_deliver(&h, (size_t)pi, 0);
    CHECK(check_abort(&h.sent[h.n_sent - 1], 6, WHOLE, 0, NULL) && h.sent[h.n_sent - 1].party == 1);
    h_flush(&h, 100000);
    h_ticks(&h, 12);
    /* the members resolve what is open on it (Abandoned): their exposure records stay */
    /* member 2's result was lost, so the host's ack deadline failed the attempt: member 1 holds it Complete */
    CHECK(h_find(&h, 1, ida)->state == GZ_SIGN_ROUND_COMPLETE);
    resolve_all(&h);
    CHECK(h_find(&h, 1, ida)->state == GZ_SIGN_ROUND_ABANDONED && h.p[1].e->n_exposures == 1);
    gz_action_list_init(&l, s, 8, sb, sizeof sb);
    CHECK(gz_sign_resolve(h.p[1].e, ida, GZ_SIGN_END_ABANDONED, &l) == GZ_ERR_ARGUMENT);   /* already Abandoned */
    /* C7: another tree on that outpoint: reason 11 from member 1; the others accept it */
    h.builder.mutate = other_tree;
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    pi = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(pi >= 0);
    h_deliver(&h, (size_t)pi, 0);
    CHECK(check_abort(&h.sent[h.n_sent - 1], 11, WHOLE, 0, NULL) && h.sent[h.n_sent - 1].party == 1);
    h_flush(&h, 100000);
    h_ticks(&h, 12);
    /* the same tree as A on it: accepted, and the round completes */
    resolve_all(&h);
    h.builder.mutate = NULL;
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
    CHECK(memcmp(h_newest(&h, 0)->def.tree_digest, h.p[1].e->exposures[0].tree_digest, 32) == 0);
    /* the exposure records survive a restart, also of rounds pushed out of memory */
    size_t ne = h.p[1].e->n_exposures;
    CHECK(h_restart(&h, 1) == GZ_OK && h.p[1].e->n_exposures == ne);
    uint64_t d = h_digest(&h);
    h_free(&h);
    return d;
}

#define N_SCENARIOS 16
static const char *const SC_NAMES[N_SCENARIOS] = {
    "honest-1", "honest-2", "duplicates", "member-restart-nonces", "member-restart-signed", "tier-abort",
    "host-restarts", "timers", "host-faults", "member-faults", "proposals", "journal", "edges",
    "reconnect", "records", "exposure"};

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
    case 11: return sc_journal();
    case 12: return sc_edges();
    case 13: return sc_reconnect();
    case 14: return sc_records();
    default: return sc_exposure();
    }
}

#endif
