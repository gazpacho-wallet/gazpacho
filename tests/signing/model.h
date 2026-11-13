/* An independent model of the contribution rules, written from
 * spec/signing-round.md (sections 3 and 7), not from the engine, and compared
 * with the engine on random event sequences (ENGINEERING-CHECKLIST item 9).
 *
 * The model sees only what a party does (its saves and sends, in order) and
 * keeps its own record of facts. It checks:
 *   S1  a party's nonces for (round, tier) leave only after a save naming that
 *       round, tier and those items;
 *   S2  never two different nonces, or two different partial signatures, for
 *       one (party, round, item); after a restart no nonce is made again for
 *       an item whose nonce had left;
 *   S3  partial signatures that leave are exactly the bytes saved for that
 *       (round, tier), saved before they left;
 *   S4  one identifier, one proposal: the host never sends two different
 *       proposals under one identifier, and never reuses an identifier for a
 *       new attempt;
 *   and the state rules of section 7, predicted from what the party did:
 *       a member that sent a partial signature in a round is never Aborted in
 *       it; a member that sent a whole-round abort for a round it holds is
 *       Aborted in it; a member that sent an ack is Complete; a host round is
 *       Done exactly when an ack from every member it proposed to was saved.
 * S5 (restore epochs) and S6 (contribution keys inside the identifier) are not
 * modelled here: S5 is checked by the proposals scenario and test_definitions, S6 by
 * test_definitions. */
#ifndef GZ_TEST_SIGNING_MODEL_H
#define GZ_TEST_SIGNING_MODEL_H

#include "harness.h"

enum { MF_STARTED = 1, MF_NONCE, MF_PSIG, MF_SAVED_PARTIALS, MF_SENT_PARTIALS, MF_ABORTED, MF_ACKED, MF_PROPOSAL, MF_PROPOSED_TO, MF_ACK_SAVED };

typedef struct {
    uint8_t kind;
    uint32_t party, item;           /* item: index; or tier; or peer, by kind */
    uint8_t id[32];
    uint64_t incarnation;
    size_t len;
    uint8_t *val;
} mfact_t;

typedef struct {
    mfact_t *f; size_t n, cap;
    uint64_t violations, checks;
    const char *why;
} model_t;

static mfact_t *m_find(model_t *m, uint8_t kind, uint32_t party, const uint8_t id[32], uint32_t item)
{
    for (size_t i = 0; i < m->n; i++)
        if (m->f[i].kind == kind && m->f[i].party == party && m->f[i].item == item && memcmp(m->f[i].id, id, 32) == 0) return &m->f[i];
    return NULL;
}

static mfact_t *m_add(model_t *m, uint8_t kind, uint32_t party, const uint8_t id[32], uint32_t item, const uint8_t *val, size_t len, uint64_t inc)
{
    if (m->n == m->cap) {
        m->cap = m->cap ? 2 * m->cap : 256;
        m->f = realloc(m->f, m->cap * sizeof *m->f);
        if (!m->f) abort();
    }
    mfact_t *f = &m->f[m->n++];
    f->kind = kind; f->party = party; f->item = item; f->incarnation = inc; f->len = len;
    memcpy(f->id, id, 32);
    f->val = malloc(len ? len : 1);
    if (!f->val) abort();
    if (len) memcpy(f->val, val, len);
    return f;
}

static void m_violate(model_t *m, const char *why) { m->violations++; if (!m->why) m->why = why; }

static void model_watch(harness_t *h, uint32_t g, const gz_action_t *a)
{
    model_t *m = h->watch_ctx;
    uint64_t inc = h->p[g].incarnation;
    if (a->kind == GZ_ACTION_SAVE) {
        for (size_t k = 0; k < a->u.save.n_records; k++) {
            const gz_record_t *r = &a->u.save.records[k];
            const uint8_t *b = r->bytes.data;
            size_t len = r->bytes.len;
            if (r->type == GZ_SIGN_REC_M_STARTED && len >= 35) {
                size_t n = (size_t)b[33] << 8 | b[34];
                for (size_t i = 0; i < n && 35 + 4 * i + 4 <= len; i++)
                    if (!m_find(m, MF_STARTED, g, b, b[32] << 16 | be32p(b + 35 + 4 * i)))
                        m_add(m, MF_STARTED, g, b, (uint32_t)b[32] << 16 | be32p(b + 35 + 4 * i), NULL, 0, inc);
            } else if (r->type == GZ_SIGN_REC_M_SIGNED && len > 33) {
                if (!m_find(m, MF_SAVED_PARTIALS, g, b, b[32])) m_add(m, MF_SAVED_PARTIALS, g, b, b[32], b + 33, len - 33, inc);
            } else if (r->type == GZ_SIGN_REC_H_ACK && len == 33) {
                if (!m_find(m, MF_ACK_SAVED, g, b, b[32])) m_add(m, MF_ACK_SAVED, g, b, b[32], NULL, 0, inc);
            }
        }
        return;
    }
    if (a->kind != GZ_ACTION_SEND) return;
    gz_sign_msg_t msg;
    const uint8_t *b = a->u.send.bytes.data;
    size_t len = a->u.send.bytes.len;
    if (!gz_sign_decode(b, len, &msg)) return;
    m->checks++;
    switch (msg.kind) {
    case GZ_SIGN_MSG_PROPOSE: {
        mfact_t *f = m_find(m, MF_PROPOSAL, g, msg.round_id, 0);
        if (!f) m_add(m, MF_PROPOSAL, g, msg.round_id, 0, b, len, inc);
        else if (f->len != len || memcmp(f->val, b, len) != 0) m_violate(m, "S4: two different proposals under one identifier");
        if (!m_find(m, MF_PROPOSED_TO, g, msg.round_id, (uint32_t)a->u.send.peer_id))
            m_add(m, MF_PROPOSED_TO, g, msg.round_id, (uint32_t)a->u.send.peer_id, NULL, 0, inc);
        break;
    }
    case GZ_SIGN_MSG_NONCES:
        for (int k = 0; k < msg.n; k++) {
            uint32_t item = be32p(msg.entry[k]);
            if (!m_find(m, MF_STARTED, g, msg.round_id, (uint32_t)msg.tier << 16 | item)) m_violate(m, "S1: nonces left before their save");
            mfact_t *f = m_find(m, MF_NONCE, g, msg.round_id, item);
            if (!f) m_add(m, MF_NONCE, g, msg.round_id, item, msg.entry[k] + 4, 66, inc);
            else if (memcmp(f->val, msg.entry[k] + 4, 66) != 0) m_violate(m, "S2: a second nonce for one (round, item)");
            else if (f->incarnation != inc) m_violate(m, "S2: a nonce sent again after a restart");
        }
        break;
    case GZ_SIGN_MSG_PARTIALS: {
        mfact_t *s = m_find(m, MF_SAVED_PARTIALS, g, msg.round_id, msg.tier);
        if (!s || s->len != len || memcmp(s->val, b, len) != 0) m_violate(m, "S3: partial signatures not the saved bytes");
        for (int k = 0; k < msg.n; k++) {
            uint32_t item = be32p(msg.entry[k]);
            mfact_t *f = m_find(m, MF_PSIG, g, msg.round_id, item);
            if (!f) m_add(m, MF_PSIG, g, msg.round_id, item, msg.entry[k] + 4, 32, inc);
            else if (memcmp(f->val, msg.entry[k] + 4, 32) != 0) m_violate(m, "S2: a second partial signature for one (round, item)");
        }
        if (!m_find(m, MF_SENT_PARTIALS, g, msg.round_id, 0)) m_add(m, MF_SENT_PARTIALS, g, msg.round_id, 0, NULL, 0, inc);
        break;
    }
    case GZ_SIGN_MSG_ABORT:
        if (g != 0 && !msg.has_tier && h_find(h, g, msg.round_id)) {
            if (m_find(m, MF_SENT_PARTIALS, g, msg.round_id, 0)) m_violate(m, "section 7: a whole-round abort after a partial signature");
            if (!m_find(m, MF_ABORTED, g, msg.round_id, 0)) m_add(m, MF_ABORTED, g, msg.round_id, 0, NULL, 0, inc);
        }
        break;
    case GZ_SIGN_MSG_ACK:
        if (!m_find(m, MF_ACKED, g, msg.round_id, 0)) m_add(m, MF_ACKED, g, msg.round_id, 0, NULL, 0, inc);
        break;
    default: break;
    }
}

/* The states the model predicts, against the engines'. */
static void model_states(model_t *m, const harness_t *h)
{
    for (uint32_t g = 0; g < h->n; g++)
        for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
            const gz_sign_round_t *r = &h->p[g].e->rounds[k];
            if (r->state == GZ_SIGN_ROUND_FREE) continue;
            m->checks++;
            if (g == 0) {
                /* acks are saved by participant index, proposals sent by peer: compare how many */
                size_t peers = 0, acks = 0;
                for (size_t i = 0; i < m->n; i++) {
                    const mfact_t *f = &m->f[i];
                    if (f->party != 0 || memcmp(f->id, r->id, 32) != 0) continue;
                    peers += f->kind == MF_PROPOSED_TO;
                    acks += f->kind == MF_ACK_SAVED;
                }
                int all = m_find(m, MF_PROPOSAL, 0, r->id, 0) != NULL && peers > 0 && acks == peers;
                if ((r->state == GZ_SIGN_ROUND_DONE) != (all && r->state != GZ_SIGN_ROUND_FAILED)) m_violate(m, "section 7: host Done without every ack, or every ack and not Done");
                continue;
            }
            int partial = m_find(m, MF_SENT_PARTIALS, g, r->id, 0) != NULL;
            if (partial && r->state == GZ_SIGN_ROUND_ABORTED) m_violate(m, "section 7: Aborted after a partial signature");
            if (m_find(m, MF_ABORTED, g, r->id, 0) && r->state != GZ_SIGN_ROUND_ABORTED) m_violate(m, "section 7: a whole-round abort sent and the round not Aborted");
            if (m_find(m, MF_ACKED, g, r->id, 0) && r->state != GZ_SIGN_ROUND_COMPLETE) m_violate(m, "section 7: an ack sent and the round not Complete");
            if (r->state != GZ_SIGN_ROUND_ACTIVE)
                for (int i = 0; i < r->def.n_items; i++)
                    if (r->secnonce_serial[i]) m_violate(m, "section 8: a secret nonce kept after the round stopped");
        }
}

static void model_free(model_t *m)
{
    for (size_t i = 0; i < m->n; i++) free(m->f[i].val);
    free(m->f);
}

static uint64_t g_mlcg;
static uint32_t mr(uint32_t bound)
{
    g_mlcg = g_mlcg * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)(g_mlcg >> 33) % bound;
}

typedef struct { uint64_t runs, events, restarts, replays, dups, drops, done, exhausted, violations, checks; } model_stats_t;

/* One random sequence. Returns 1 if the model and the engines agreed throughout. */
static int model_run(uint64_t seed, model_stats_t *st)
{
    harness_t h;
    model_t m;
    memset(&m, 0, sizeof m);
    g_mlcg = seed * 0x9e3779b97f4a7c15ull + 1;
    uint32_t members = 3 + mr(2);
    uint8_t tiers = (uint8_t)(1 + mr(2));
    h_init(&h, members);
    h.max_attempts = 40;
    for (uint32_t g = 0; g < h.n; g++) h.p[g].e->cfg.max_attempts = 40;
    h.watch = model_watch; h.watch_ctx = &m;
    CHECK(h_begin(&h, tiers, members, 0) == GZ_OK);
    for (int step = 0; step < 250; step++) {
        uint32_t c = mr(100);
        if (c < 60 && h.nq) {
            size_t i = mr((uint32_t)h.nq);
            uint32_t f = mr(100);
            if (f < 8) { h_drop_msg(&h, i); st->drops++; }
            else { h_deliver(&h, i, f < 18); st->dups += f < 18; }
        } else if (c < 80) {
            h_tick(&h, mr(h.n));
        } else if (c < 85) {
            h_restart(&h, mr(h.n));
            st->restarts++;
        } else if (c < 89 && h.n_sent) {
            const h_sent_t *s = &h.sent[mr((uint32_t)h.n_sent)];
            if (s->kind == GZ_SIGN_MSG_PROPOSE || s->kind == GZ_SIGN_MSG_ALL_NONCES || s->kind == GZ_SIGN_MSG_RESULT) {
                h_inject(&h, s->party, s->peer, s->b, s->len);           /* an old message, again */
                st->replays++;
            }
        } else if (c < 92) {
            const gz_sign_round_t *r = h_newest(&h, 0);
            if (!r || r->state != GZ_SIGN_ROUND_ACTIVE) h_begin(&h, tiers, members, 0);
        }
        model_states(&m, &h);
    }
    /* quiet: no faults; everything settles */
    for (int t = 0; t < 80; t++) {
        h_ticks(&h, 1);
        const gz_sign_round_t *r = h_newest(&h, 0);
        if (r && r->state != GZ_SIGN_ROUND_ACTIVE && r->state != GZ_SIGN_ROUND_COMPLETE && r->state != GZ_SIGN_ROUND_DONE) h_begin(&h, tiers, members, 0);
        model_states(&m, &h);
        if (r && r->state == GZ_SIGN_ROUND_DONE) break;
    }
    const gz_sign_round_t *r = h_newest(&h, 0);
    int done = r && r->state == GZ_SIGN_ROUND_DONE;
    if (done) {
        for (int j = 1; j < r->def.n_participants; j++) {
            const gz_sign_round_t *mr2 = h_find(&h, (uint32_t)r->def.peer[j], r->id);
            CHECK(mr2 && mr2->state == GZ_SIGN_ROUND_COMPLETE);
            for (int i = 0; mr2 && i < r->def.n_items; i++)      /* the finals of its own items, as the host holds them */
                for (int s = 0; s < r->def.items[i].n_signers; s++)
                    if (r->def.items[i].signers[s] == j) CHECK(memcmp(mr2->final_sig[i], r->final_sig[i], 64) == 0);
        }
    } else st->exhausted += h.p[0].e->attempts >= 40;
    st->done += (uint64_t)done;
    st->runs++; st->events += h.events; st->violations += m.violations; st->checks += m.checks;
    if (m.violations) printf("  model run %llu: %s\n", (unsigned long long)seed, m.why);
    int ok = m.violations == 0 && (done || h.p[0].e->attempts >= 40);
    if (!ok && !m.violations) printf("  model run %llu: no round completed (attempts %u)\n", (unsigned long long)seed, h.p[0].e->attempts);
    model_free(&m);
    h_free(&h);
    return ok;
}

#endif
