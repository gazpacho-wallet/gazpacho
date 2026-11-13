/* A small, fully deterministic harness that drives the engines directly,
 * without the simulator: one host and its members, a journal per party that
 * keeps every save at once, a message queue the test delivers by hand, ticks
 * and restarts on demand. Every action and, after every event, every party's
 * state go into a transcript digest, so a test can pin the exact messages,
 * reasons, state transitions and counters of a whole scenario. */
#ifndef GZ_TEST_SIGNING_HARNESS_H
#define GZ_TEST_SIGNING_HARNESS_H

#include "world.h"

#define H_MAX 9

typedef struct { uint32_t type; size_t len; uint8_t *b; uint64_t batch; } h_rec_t;
typedef struct { uint32_t from, to; size_t len; uint8_t *b; } h_msg_t;

/* What one party did, as an action: for tests that look at one kind. */
typedef struct { uint32_t party, peer; uint8_t kind; size_t len; uint8_t *b; } h_sent_t;   /* kind: the envelope's (all round kinds are below 256) */

/* The kind of an envelope, or 0. */
static uint8_t h_kind_of(const uint8_t *b, size_t len) { return len >= GZ_RMSG_HEADER && b[4] == 0 ? b[5] : 0; }

typedef struct {
    gz_sign_t *e;
    uint64_t incarnation, fill;
    h_rec_t *recs; size_t n_recs, cap_recs, reader_at;
    gz_record_t rd[8];
    uint64_t batches;
} h_party_t;

typedef struct harness {
    uint32_t n;                 /* parties: host 0, members 1..n-1 */
    h_party_t p[H_MAX];
    w_builder_t builder;
    h_msg_t *q; size_t nq, capq;
    h_sent_t *sent; size_t n_sent, cap_sent;
    gz_sign_sha256_t tr;             /* the transcript */
    uint64_t events, errors;
    uint32_t drop_to;           /* bit g: messages to party g are lost */
    uint32_t resend_ticks, deadline_ticks, max_attempts, status_ticks, begun, unfinished_ticks;
    /* for the model check (test_signing.c): called with every action a party carries out */
    void (*watch)(struct harness *h, uint32_t party, const gz_action_t *a);
    void *watch_ctx;
} harness_t;

static void h_fill(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    h_party_t *p = ctx;
    (void)purpose;
    for (size_t i = 0; i < len; i++) {
        p->fill = p->fill * 6364136223846793005ull + 1442695040888963407ull;
        out[i] = (uint8_t)(p->fill >> 56);
    }
}
static uint64_t h_now(void *ctx) { (void)ctx; return 0; }

static int h_next(void *ctx, gz_stored_batch_t *b)
{
    h_party_t *p = ctx;
    size_t k = 0;
    if (p->reader_at >= p->n_recs) return 0;
    uint64_t batch = p->recs[p->reader_at].batch;
    b->id.incarnation = 1; b->id.sequence = batch;
    while (p->reader_at < p->n_recs && p->recs[p->reader_at].batch == batch && k < 8) {   /* one saved batch */
        h_rec_t *r = &p->recs[p->reader_at++];
        p->rd[k].type = r->type; p->rd[k].bytes.data = r->b; p->rd[k].bytes.len = r->len; k++;
    }
    b->records = p->rd; b->n_records = k;
    return 1;
}
static void h_rewind(void *ctx) { ((h_party_t *)ctx)->reader_at = 0; }

static void h_fold(harness_t *h, const void *d, size_t n) { gz_sign_sha256_write(&h->tr, d, n); }
static void h_fold64(harness_t *h, uint64_t v)
{
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
    h_fold(h, b, 8);
}

/* Every party's state, into the transcript. */
static void h_snapshot(harness_t *h)
{
    for (uint32_t g = 0; g < h->n; g++) {
        const gz_sign_t *e = h->p[g].e;
        if (!e) continue;
        h_fold64(h, e->attempts); h_fold64(h, e->n_known);
        for (int c = 0; c < 9; c++) h_fold64(h, e->counters[c]);
        for (size_t k = 0; k < e->n_known; k++) h_fold(h, e->known[k], 4);
        for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
            const gz_sign_round_t *r = &e->rounds[k];
            if (r->state == GZ_SIGN_ROUND_FREE) { h_fold64(h, 0); continue; }
            uint8_t s[8] = {r->state, r->tier, r->ever_partial, r->me, r->why, r->tier_state[0], r->tier_state[1], (uint8_t)r->acked};
            h_fold(h, s, 8); h_fold(h, r->id, 4); h_fold64(h, r->blamed); h_fold64(h, r->seq); h_fold64(h, r->acked);
            h_fold64(h, r->nonces_len); h_fold64(h, r->tail_len);
            for (int i = 0; i < r->def.n_items; i++) {
                h_fold64(h, (uint64_t)r->have_nonce[i] | (uint64_t)r->have_psig[i] << 32);
                h_fold64(h, (uint64_t)r->have_final[i] | (uint64_t)(r->secnonce_serial[i] != 0) << 8);
            }
        }
    }
}

static void h_apply(harness_t *h, uint32_t g, const gz_action_list_t *list)
{
    for (size_t k = 0; k < list->count; k++) {
        const gz_action_t *a = &list->slots[k];
        if (h->watch) h->watch(h, g, a);
        h_fold64(h, (uint64_t)g << 8 | a->kind);
        if (a->kind == GZ_ACTION_SAVE) {
            h->p[g].batches++;
            for (size_t r = 0; r < a->u.save.n_records; r++) {
                h_party_t *p = &h->p[g];
                if (p->n_recs == p->cap_recs) {
                    p->cap_recs = p->cap_recs ? 2 * p->cap_recs : 64;
                    p->recs = realloc(p->recs, p->cap_recs * sizeof *p->recs);
                    if (!p->recs) abort();
                }
                h_rec_t *rec = &p->recs[p->n_recs++];
                rec->type = a->u.save.records[r].type; rec->len = a->u.save.records[r].bytes.len; rec->batch = h->p[g].batches;
                rec->b = malloc(rec->len ? rec->len : 1);
                if (!rec->b) abort();
                memcpy(rec->b, a->u.save.records[r].bytes.data, rec->len);
                h_fold64(h, rec->type); h_fold(h, rec->b, rec->len);
            }
        } else if (a->kind == GZ_ACTION_SEND) {
            h_fold64(h, a->u.send.peer_id); h_fold(h, a->u.send.bytes.data, a->u.send.bytes.len);
            if (h->n_sent == h->cap_sent) {
                h->cap_sent = h->cap_sent ? 2 * h->cap_sent : 256;
                h->sent = realloc(h->sent, h->cap_sent * sizeof *h->sent);
                if (!h->sent) abort();
            }
            h_sent_t *s = &h->sent[h->n_sent++];
            s->party = g; s->peer = (uint32_t)a->u.send.peer_id; s->len = a->u.send.bytes.len;
            s->kind = h_kind_of(a->u.send.bytes.data, s->len);
            s->b = malloc(s->len ? s->len : 1);
            if (!s->b) abort();
            memcpy(s->b, a->u.send.bytes.data, s->len);
            if (a->u.send.peer_id < h->n && !(h->drop_to >> a->u.send.peer_id & 1u)) {
                if (h->nq == h->capq) {
                    h->capq = h->capq ? 2 * h->capq : 256;
                    h->q = realloc(h->q, h->capq * sizeof *h->q);
                    if (!h->q) abort();
                }
                h_msg_t *m = &h->q[h->nq++];
                m->from = g; m->to = (uint32_t)a->u.send.peer_id; m->len = s->len;
                m->b = malloc(m->len ? m->len : 1);
                if (!m->b) abort();
                memcpy(m->b, s->b, m->len);
            }
        } else if (a->kind == GZ_ACTION_SET_TIMER) {
            h_fold64(h, a->u.set_timer.timer_id); h_fold64(h, a->u.set_timer.delay_ms);
        }
    }
}

static gz_action_t h_slots[512];
static uint8_t h_bytes[1u << 23];

static gz_status_t h_event(harness_t *h, uint32_t g, const gz_event_t *ev)
{
    gz_action_list_t list;
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    gz_status_t st = gz_sign_handle(h->p[g].e, ev, &list);
    h->events++;
    h_fold64(h, 0xe7e7u); h_fold64(h, (uint64_t)g << 8 | ev->kind); h_fold64(h, (uint64_t)st);
    if (st == GZ_OK) h_apply(h, g, &list); else h->errors++;
    h_snapshot(h);
    return st;
}

static void h_build(harness_t *h, uint32_t g)
{
    h_party_t *p = &h->p[g];
    gz_sign_config_t c;
    gz_ports_t ports = {{h_fill, p}, {h_now, NULL}};
    memset(&c, 0, sizeof c);
    c.host = g == 0; c.ctx = w_ctx();
    w_secret("test/factory", g, c.factory_secret);
    w_secret("test/contribution", g, c.contribution_secret);
    c.build = w_build; c.retry = w_retry; c.build_ctx = &h->builder;
    w_hooks(&h->builder, &c);
    c.tick_ms = 1; c.resend_ticks = h->resend_ticks; c.deadline_ticks = h->deadline_ticks; c.max_attempts = h->max_attempts;
    c.status_ticks = h->status_ticks; c.unfinished_ticks = h->unfinished_ticks;
    p->incarnation++;
    p->fill = 0x9e3779b97f4a7c15ull * (g + 1) ^ p->incarnation << 40;
    if (!p->e) p->e = malloc(sizeof *p->e);
    if (!p->e || gz_sign_init(p->e, &c, &ports, p->incarnation) != GZ_OK) abort();
}

static gz_status_t h_start(harness_t *h, uint32_t g)
{
    gz_action_list_t list;
    int more = 1;
    gz_storage_reader_t r = {h_next, h_rewind, &h->p[g], h->p[g].incarnation, 0};
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    gz_status_t st = gz_sign_start(h->p[g].e, &r, &list, &more);
    h_fold64(h, 0x5747u); h_fold64(h, g); h_fold64(h, (uint64_t)st);
    if (st == GZ_OK) h_apply(h, g, &list); else h->errors++;
    h_snapshot(h);
    return st;
}

static void h_init(harness_t *h, uint32_t members)
{
    memset(h, 0, sizeof *h);
    h->n = members + 1;
    h->resend_ticks = 3; h->deadline_ticks = 12; h->max_attempts = 8; h->status_ticks = 0;
    gz_sign_tagged_init(&h->tr, "test/transcript");
    for (uint32_t g = 0; g < h->n; g++) { h_build(h, g); h_start(h, g); }
}

/* A crash: memory gone, the journal kept; build again and start. */
static gz_status_t h_restart(harness_t *h, uint32_t g)
{
    gz_sign_wipe(h->p[g].e);
    h_build(h, g);
    return h_start(h, g);
}

static void h_free(harness_t *h)
{
    for (uint32_t g = 0; g < h->n; g++) {
        for (size_t i = 0; i < h->p[g].n_recs; i++) free(h->p[g].recs[i].b);
        free(h->p[g].recs);
        if (h->p[g].e) gz_sign_wipe(h->p[g].e);
        free(h->p[g].e);
    }
    for (size_t i = 0; i < h->nq; i++) free(h->q[i].b);
    for (size_t i = 0; i < h->n_sent; i++) free(h->sent[i].b);
    free(h->q); free(h->sent);
}

static void h_drop_msg(harness_t *h, size_t i)
{
    free(h->q[i].b);
    memmove(h->q + i, h->q + i + 1, (h->nq - i - 1) * sizeof *h->q);
    h->nq--;
}

/* Deliver queued message i (and keep a copy if `keep`). */
static gz_status_t h_deliver(harness_t *h, size_t i, int keep)
{
    h_msg_t m = h->q[i];
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_MESSAGE_RECEIVED; ev.u.message.peer_id = m.from;
    ev.u.message.bytes.data = m.b; ev.u.message.bytes.len = m.len;
    if (!keep) memmove(h->q + i, h->q + i + 1, (h->nq-- - i - 1) * sizeof *h->q);
    gz_status_t st = h_event(h, m.to, &ev);
    if (!keep) free(m.b);
    return st;
}

/* Inject a message as if `from` had sent it. */
static gz_status_t h_inject(harness_t *h, uint32_t from, uint32_t to, const uint8_t *b, size_t len)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_MESSAGE_RECEIVED; ev.u.message.peer_id = from;
    ev.u.message.bytes.data = b; ev.u.message.bytes.len = len;
    return h_event(h, to, &ev);
}

/* A connection to `peer` is up at party g (contract v2 section 3: the reconnect step). */
static gz_status_t h_connect(harness_t *h, uint32_t g, uint32_t peer)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_PEER_CONNECTED; ev.u.peer.peer_id = peer;
    return h_event(h, g, &ev);
}

static void h_tick(harness_t *h, uint32_t g)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_TIMER_FIRED; ev.u.timer.timer_id = 0x5347u;
    h_event(h, g, &ev);
}

/* Deliver in order until nothing is queued (or `max` deliveries). */
static void h_flush(harness_t *h, size_t max)
{
    while (h->nq && max--) h_deliver(h, 0, 0);
}

/* Tick every party `n` times, flushing between ticks. */
static void h_ticks(harness_t *h, int n)
{
    for (int i = 0; i < n; i++) {
        for (uint32_t g = 0; g < h->n; g++) h_tick(h, g);
        h_flush(h, 100000);
    }
}

static gz_status_t h_begin(harness_t *h, uint8_t tiers, uint32_t members, uint8_t flags)
{
    uint8_t p[W_PARAMS];
    gz_action_list_t list;
    /* every round the test begins is another attempt, on its own funding outpoint (H11) */
    w_params(p, tiers, ++h->begun, w_mask(members), flags);
    gz_action_list_init(&list, h_slots, 512, h_bytes, sizeof h_bytes);
    gz_status_t st = w_begin_params(h->p[0].e, &h->builder, p, W_PARAMS, &list);
    h_fold64(h, 0xb9u); h_fold64(h, (uint64_t)st);
    if (st == GZ_OK) h_apply(h, 0, &list);
    h_snapshot(h);
    return st;
}

static uint64_t h_digest(harness_t *h)
{
    gz_sign_sha256_t copy = h->tr;
    uint8_t d[32];
    uint64_t v = 0;
    gz_sign_sha256_done(&copy, d);
    for (int i = 0; i < 8; i++) v = v << 8 | d[i];
    return v;
}

static const gz_sign_round_t *h_newest(const harness_t *h, uint32_t g) { return gz_sign_latest(h->p[g].e); }

static const gz_sign_round_t *h_find(const harness_t *h, uint32_t g, const uint8_t id[32])
{
    for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++)
        if (h->p[g].e->rounds[k].state != GZ_SIGN_ROUND_FREE && memcmp(h->p[g].e->rounds[k].id, id, 32) == 0) return &h->p[g].e->rounds[k];
    return NULL;
}

/* The oldest round party g holds (by when it took it up). */
static const gz_sign_round_t *h_oldest(const harness_t *h, uint32_t g)
{
    const gz_sign_round_t *best = NULL;
    for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
        const gz_sign_round_t *r = &h->p[g].e->rounds[k];
        if (r->state != GZ_SIGN_ROUND_FREE && (!best || r->seq < best->seq)) best = r;
    }
    return best;
}

/* The n-th message of `kind` party `from` sent (from 0), or NULL. */
static const h_sent_t *h_sent_kind(const harness_t *h, uint32_t from, uint8_t kind, size_t nth)
{
    for (size_t i = 0; i < h->n_sent; i++)
        if (h->sent[i].party == from && h->sent[i].kind == kind && nth-- == 0) return &h->sent[i];
    return NULL;
}
static size_t h_count_kind(const harness_t *h, uint32_t from, uint8_t kind)
{
    size_t n = 0;
    for (size_t i = 0; i < h->n_sent; i++) n += h->sent[i].party == from && h->sent[i].kind == kind;
    return n;
}

#endif
