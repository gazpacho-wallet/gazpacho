/* A small world for the lobby tests: one host and up to 8 members, each a
 * whole program around its engine (the real runner, a journal that survives a
 * crash, timers), and a network between them with drops, duplicates,
 * reordering and broken connections. Deterministic for a seed (sim/rng.h). */
#ifndef GAZPACHO_LOBBY_WORLD_H
#define GAZPACHO_LOBBY_WORLD_H

#include "lobby_test.h"
#include "gazpacho/runner.h"
#include "rng.h"
#include <stdlib.h>

#define W_MAX 9                      /* node 0 is the host */
#define W_HOST_PEER 1u
#define W_PEER(i) (1000u + (uint64_t)(i))
#define W_T0 1794441000000ull        /* 10 minutes before T1's deadline */

typedef struct { uint32_t type; uint8_t *b; size_t n; uint64_t batch; } w_rec_t;
typedef struct { int to, from; uint64_t at; uint8_t *b; size_t n; uint32_t conn; } w_msg_t;
typedef struct { uint64_t id, at; } w_timer_t;
typedef struct {
    int role; uint8_t check[32], digest[32]; uint16_t signers, n_participants;
    uint8_t participants[GZ_LOBBY_MAX_SEATS + 1][33], factory[GZ_LOBBY_MAX_SEATS + 1][33];
    int bindings_ok, records_ok, terms_ok;     /* checked by the stub itself */
    int sigs_ok, limits_ok;                    /* the host's signatures under the pinned key; member limits */
    uint8_t levels[8], n_levels, fixed_levels, k, anchors;
    uint16_t layer_step, layer_states, min_members;
    uint32_t version;
    size_t start_len;
} w_handoff_t;

typedef struct world world_t;
typedef struct {
    world_t *w; int idx, alive;
    lt_signer_t keys;
    gz_lobby_host_t *host; gz_lobby_member_t *mem;
    gz_lobby_conditions_t cond;
    gz_runner_t runner; gz_runner_slot_t slots[512]; uint8_t *rbytes;
    uint64_t incarnation, unconfirmed[64]; size_t n_unconf;
    w_rec_t *recs; size_t n_recs, cap_recs;    /* the journal, durable and pending */
    w_timer_t timers[8]; int n_timers;
    sim_rng_t rng;
    w_handoff_t handoffs[16]; int n_handoffs;
    int n_resumes, n_repeats;                  /* begin again for a check it holds: resumed, or not */
    int n_left;                                /* member_left calls (host) */
    int n_cancels; uint16_t cancel_reason; uint8_t cancel_scope[32];
    uint32_t notes[64]; uint8_t note_a[64], note_b[64]; int n_notes;
    int close_requested;
    int dead;                                  /* never restarts */
} w_node_t;

struct world {
    int n;                                     /* members */
    w_node_t node[W_MAX];
    uint64_t now;
    w_msg_t *msgs; size_t n_msgs, cap_msgs;
    int link_up[W_MAX]; uint32_t conn_no[W_MAX]; int cut_req[W_MAX];
    sim_rng_t rng;
    uint32_t drop_pm, dup_pm, reorder_pm, crash_pm, cut_pm;
    int faults_on;                             /* set by w_step */
    unsigned long drops, dups, reorders, crashes, cuts, sent, delivered, failures;
    uint8_t outer[512], current[128]; size_t outer_len, current_len;
    uint16_t standbys;
    /* the wire log, for invariants */
    void (*on_wire)(world_t *w, int from, int to, const uint8_t *b, size_t n);
};

static uint64_t w_clock(void *ctx) { return ((world_t *)ctx)->now; }
static inline void w_random(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    (void)purpose;
    sim_rng_fill(&((w_node_t *)ctx)->rng, out, len);
}

static inline gz_status_t w_begin(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out)
{
    w_node_t *d = ctx;
    w_handoff_t *x;
    uint16_t i;
    int k;
    (void)out;
    /* The signing engine's begin is idempotent per check_id (lobby_handoff.h). */
    for (k = 0; k < d->n_handoffs; k++)
        if (memcmp(d->handoffs[k].check, h->check_id, 32) == 0) {
            if (h->resume) d->n_resumes++; else d->n_repeats++;
            return GZ_OK;
        }
    if (h->resume) d->n_resumes++;
    if (d->n_handoffs >= 16) return GZ_OK;
    x = &d->handoffs[d->n_handoffs++];
    memset(x, 0, sizeof *x);
    x->role = h->role;
    memcpy(x->check, h->check_id, 32);
    memcpy(x->digest, h->current_digest, 32);
    x->signers = h->signers;
    x->n_participants = h->n_participants;
    x->bindings_ok = 1;
    for (i = 0; i < h->n_participants && i <= GZ_LOBBY_MAX_SEATS; i++) {
        /* the stub checks each binding itself, as the signing engine will */
        const gz_lobby_participant_t *p = &h->participants[i];
        uint8_t b[32];
        gz_lobby_binding(h->scope, p->factory_key, p->contribution_key, b);
        if (!lt_verify(NULL, p->factory_key, b, p->bind_by_factory) || !lt_verify(NULL, p->contribution_key, b, p->bind_by_contribution))
            x->bindings_ok = 0;
        memcpy(x->participants[i], p->contribution_key, 33);
        memcpy(x->factory[i], p->factory_key, 33);
    }
    {   /* the records handed over are the frozen ones, and name each other */
        uint8_t od[32], cd[32];
        gz_terms_outer_t o;
        gz_terms_current_t c;
        gz_terms_outer_digest(h->outer, h->outer_len, od);
        gz_terms_current_digest(h->current, h->current_len, cd);
        x->records_ok = memcmp(od, h->scope, 32) == 0 && memcmp(cd, h->current_digest, 32) == 0 &&
                        lt_outer(h->outer, h->outer_len, &o) &&
                        lt_current(h->current, h->current_len, &o, od, &c) && c.version == h->version &&
                        h->values && gz_terms_current_equal(h->values, &c);
        x->terms_ok = h->terms && gz_terms_outer_equal(h->terms, &o) && h->pinned_key &&
                      memcmp(h->terms->host_key, h->pinned_key, 33) == 0;
        x->sigs_ok = h->outer_sig && h->current_sig && h->pinned_key &&
                     lt_verify(NULL, h->pinned_key, od, h->outer_sig) && lt_verify(NULL, h->pinned_key, cd, h->current_sig);
        x->limits_ok = h->participants ? h->limits == NULL : h->limits != NULL && h->limits->n_max == 3;
    }
    memcpy(x->levels, h->levels, 8);
    x->n_levels = h->n_levels; x->fixed_levels = h->fixed_levels; x->k = h->k; x->anchors = h->tree_anchors;
    x->layer_step = h->layer_step; x->layer_states = h->layer_states; x->min_members = h->min_members;
    x->version = h->version; x->start_len = h->start_len;
    return GZ_OK;
}

static inline gz_status_t w_left(void *ctx, const uint8_t scope[32], const uint8_t ckey[33], gz_action_list_t *out)
{
    (void)scope; (void)ckey; (void)out;
    ((w_node_t *)ctx)->n_left++;
    return GZ_OK;
}

static inline gz_status_t w_cancel(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out)
{
    w_node_t *d = ctx;
    (void)out;
    d->n_cancels++;
    d->cancel_reason = reason;
    memcpy(d->cancel_scope, scope, 32);
    return GZ_OK;
}

/* The build parameters for n members of T1 (terms.md T7) and the fixed ones. */
static inline int w_params_ok(const w_handoff_t *x, int members)
{
    int lv_ok = members <= 4 ? x->n_levels == 1 && x->levels[0] == 3 && x->fixed_levels == 2
                             : x->n_levels == 2 && x->levels[0] == 4 && x->levels[1] == 3 &&
                                   x->fixed_levels == (members <= 8 ? 2 : 3);
    return lv_ok && x->k == 1 && x->anchors == 1 && x->layer_step == 144 && x->layer_states == 4 &&
           x->records_ok && x->terms_ok && x->bindings_ok && x->sigs_ok && x->limits_ok && x->version >= 1;
}

static inline void w_send(world_t *w, int from, int to, const uint8_t *b, size_t n)
{
    w_msg_t *m;
    int copies = 1, k;
    w->sent++;
    if (w->on_wire) w->on_wire(w, from, to, b, n);
    /* a lost message means a broken connection: BOLT 8 loses nothing while one lasts */
    if (sim_rng_chance(&w->rng, w->faults_on ? w->drop_pm : 0)) { w->drops++; w->cut_req[from ? from : to] = 1; return; }
    if (sim_rng_chance(&w->rng, w->faults_on ? w->dup_pm : 0)) { w->dups++; copies = 2; }
    for (k = 0; k < copies; k++) {
        if (w->n_msgs == w->cap_msgs) {
            w->cap_msgs = w->cap_msgs ? 2 * w->cap_msgs : 256;
            w->msgs = realloc(w->msgs, w->cap_msgs * sizeof *w->msgs);
        }
        m = &w->msgs[w->n_msgs++];
        m->to = to; m->from = from;
        m->at = w->now + 10 + (sim_rng_chance(&w->rng, w->faults_on ? w->reorder_pm : 0) ? (w->reorders++, sim_rng_below(&w->rng, 400)) : 0);
        m->b = malloc(n); memcpy(m->b, b, n); m->n = n;
        m->conn = w->conn_no[from ? from : to];
    }
}

static inline void w_execute(void *ctx, const gz_action_t *a)
{
    w_node_t *d = ctx;
    world_t *w = d->w;
    size_t i;
    int k;
    switch (a->kind) {
    case GZ_ACTION_SAVE:
        for (i = 0; i < a->u.save.n_records; i++) {
            w_rec_t *r;
            if (d->n_recs == d->cap_recs) {
                d->cap_recs = d->cap_recs ? 2 * d->cap_recs : 64;
                d->recs = realloc(d->recs, d->cap_recs * sizeof *d->recs);
            }
            r = &d->recs[d->n_recs++];
            r->type = a->u.save.records[i].type;
            r->n = a->u.save.records[i].bytes.len;
            r->b = malloc(r->n ? r->n : 1);
            if (r->n) memcpy(r->b, a->u.save.records[i].bytes.data, r->n);
            r->batch = a->u.save.batch.sequence | (d->incarnation << 32);
        }
        d->unconfirmed[d->n_unconf++] = a->u.save.batch.sequence;
        break;
    case GZ_ACTION_SEND: {
        int to = d->idx == 0 ? (int)(a->u.send.peer_id - 1000) : 0;
        if (to < 0 || to > w->n || !w->link_up[d->idx ? d->idx : to]) break;
        w_send(w, d->idx, to, a->u.send.bytes.data, a->u.send.bytes.len);
        break;
    }
    case GZ_ACTION_SET_TIMER:
        for (k = 0; k < d->n_timers && d->timers[k].id != a->u.set_timer.timer_id; k++) {}
        if (k == d->n_timers) d->n_timers++;
        d->timers[k].id = a->u.set_timer.timer_id;
        d->timers[k].at = w->now + a->u.set_timer.delay_ms;
        break;
    case GZ_ACTION_NOTIFY:
        if (a->u.notify.code == GZ_NOTE_CLOSE) {
            uint64_t peer = 0;
            for (i = 0; i < 8 && i < a->u.notify.bytes.len; i++) peer = peer << 8 | a->u.notify.bytes.data[i];
            if (d->idx == 0 && peer >= 1001 && peer <= 1000 + (uint64_t)w->n) w->cut_req[peer - 1000] = 1;
            else d->close_requested = 1;
            break;
        }
        if (d->n_notes < 64) {
            d->notes[d->n_notes] = a->u.notify.code;
            d->note_a[d->n_notes] = a->u.notify.bytes.len > 0 ? a->u.notify.bytes.data[0] : 0;
            d->note_b[d->n_notes] = a->u.notify.bytes.len > 1 ? a->u.notify.bytes.data[1] : 0;
            d->n_notes++;
        }
        break;
    default: break;
    }
}

static inline void w_submit(w_node_t *d, gz_action_list_t *l)
{
    if (gz_runner_submit(&d->runner, l) != GZ_OK) { d->w->failures++; printf("runner refused\n"); }
}

/* Confirm every batch the node's storage holds (storage is fast here). */
static inline void w_confirm(w_node_t *d)
{
    size_t i;
    for (i = 0; i < d->n_unconf; i++) {
        gz_batch_id_t b;
        b.incarnation = d->incarnation;
        b.sequence = d->unconfirmed[i];
        if (gz_runner_confirm(&d->runner, b) != GZ_OK) { d->w->failures++; printf("confirm failed\n"); }
    }
    d->n_unconf = 0;
}

static gz_action_t w_slots[512];
static uint8_t w_bytes[1 << 20];

/* Run one input through the node and carry its actions out. */
static inline void w_input(w_node_t *d, const gz_lobby_input_t *in)
{
    gz_action_list_t l;
    gz_status_t st;
    if (!d->alive) return;
    gz_action_list_init(&l, w_slots, 512, w_bytes, sizeof w_bytes);
    st = d->host ? gz_lobby_host_handle(d->host, in, &l) : gz_lobby_member_handle(d->mem, in, &l);
    if (st != GZ_OK) { d->w->failures++; printf("node %d: handle failed %d (input %d)\n", d->idx, st, in->kind); }
    w_submit(d, &l);
}

static inline gz_ports_t w_ports(w_node_t *d)
{
    gz_ports_t p;
    p.random.fill = w_random; p.random.ctx = d;
    p.clock.now_ms = w_clock; p.clock.ctx = d->w;
    return p;
}

/* Build (or rebuild after a crash) a node's program from its journal. */
static inline void w_boot(w_node_t *d)
{
    world_t *w = d->w;
    gz_ports_t p = w_ports(d);
    gz_lobby_crypto_t cr = lt_crypto(&d->keys);
    gz_lobby_signing_t sg;
    gz_action_list_t l;
    size_t i;
    sg.begin = w_begin; sg.cancel = w_cancel; sg.member_left = w_left; sg.ctx = d;
    d->incarnation++;
    gz_runner_init(&d->runner, d->slots, 512, d->rbytes, 1 << 20, d->incarnation, w_execute, d);
    d->n_unconf = 0;
    d->n_timers = 0;
    d->alive = 1;
    gz_action_list_init(&l, w_slots, 512, w_bytes, sizeof w_bytes);
    if (d->idx == 0) {
        gz_lobby_host_config_t cfg;
        memset(&cfg, 0, sizeof cfg);
        memcpy(cfg.factory_key, d->keys.key[3].pub, 33);
        cfg.standbys = w->standbys;
        cfg.listed = 1;
        gz_lobby_host_init(d->host, &p, &cr, &sg, &cfg);
        if (d->n_recs == 0) {
            if (gz_lobby_host_open(d->host, w->outer, w->outer_len, w->current, w->current_len, &l) != GZ_OK)
                { w->failures++; printf("open failed\n"); }
        } else {
            for (i = 0; i < d->n_recs; i++) {
                gz_record_t r;
                r.type = d->recs[i].type; r.bytes.data = d->recs[i].b; r.bytes.len = d->recs[i].n;
                if (gz_lobby_host_restore(d->host, &r) != GZ_OK) { w->failures++; printf("host restore failed\n"); }
            }
            if (gz_lobby_host_resume(d->host, &l) != GZ_OK) { w->failures++; printf("host resume failed\n"); }
        }
    } else {
        uint8_t scope[32];
        gz_terms_outer_digest(w->outer, w->outer_len, scope);
        gz_lobby_member_init(d->mem, &p, &cr, &sg, &d->cond, scope, w->node[0].keys.key[1].pub,
                             d->keys.key[2].pub, d->keys.key[3].pub, 1);
        for (i = 0; i < d->n_recs; i++) {
            gz_record_t r;
            r.type = d->recs[i].type; r.bytes.data = d->recs[i].b; r.bytes.len = d->recs[i].n;
            if (gz_lobby_member_restore(d->mem, &r) != GZ_OK) { w->failures++; printf("member restore failed\n"); }
        }
        if (gz_lobby_member_resume(d->mem, &l) != GZ_OK) { w->failures++; printf("member resume failed\n"); }
    }
    w_submit(d, &l);
}

static inline void w_init(world_t *w, int n_members, uint64_t seed, const gz_lobby_conditions_t *cond)
{
    int i;
    char label[64];
    memset(w, 0, sizeof *w);
    w->n = n_members;
    w->now = W_T0;
    sim_rng_init(&w->rng, seed, 0);
    w->outer_len = lt_unhex(LT_T1, w->outer, sizeof w->outer);
    w->current_len = lt_unhex(LT_T2, w->current, sizeof w->current);
    for (i = 0; i <= n_members; i++) {
        w_node_t *d = &w->node[i];
        d->w = w; d->idx = i;
        sim_rng_init(&d->rng, seed, 100 + (uint64_t)i);
        d->rbytes = malloc(1 << 20);
        if (i == 0) {
            lt_key(&d->keys.key[1], "host");
            lt_key(&d->keys.key[3], "host factory");
            d->host = calloc(1, sizeof *d->host);
        } else {
            snprintf(label, sizeof label, "member %d contribution", i);
            lt_key(&d->keys.key[2], label);
            snprintf(label, sizeof label, "member %d factory", i);
            lt_key(&d->keys.key[3], label);
            d->mem = calloc(1, sizeof *d->mem);
            d->cond = cond ? *cond : lt_cond_fits();
        }
    }
}

static inline void w_start(world_t *w)
{
    int i;
    for (i = 0; i <= w->n; i++) w_boot(&w->node[i]);
}

/* Bring member i's connection up (both sides alive) or down. */
static inline void w_link(world_t *w, int i, int up)
{
    gz_lobby_input_t in;
    size_t k;
    if (w->link_up[i] == up) return;
    if (up && (!w->node[0].alive || !w->node[i].alive)) return;
    w->link_up[i] = up;
    w->conn_no[i]++;
    for (k = 0; k < w->n_msgs; k++)                 /* a connection's messages die with it */
        if ((w->msgs[k].to == i || w->msgs[k].from == i) && w->msgs[k].conn != w->conn_no[i]) w->msgs[k].at = 0;
    memset(&in, 0, sizeof in);
    in.kind = up ? GZ_LIN_CONNECTED : GZ_LIN_DISCONNECTED;
    in.peer_id = W_PEER(i);
    in.peer_key = w->node[i].keys.key[2].pub;
    w_input(&w->node[0], &in);
    in.peer_id = W_HOST_PEER;
    in.peer_key = w->node[0].keys.key[1].pub;
    w_input(&w->node[i], &in);
}

static inline void w_crash(world_t *w, int i)
{
    w_node_t *d = &w->node[i];
    size_t keep = d->n_recs, k;
    int j;
    if (!d->alive) return;
    w->crashes++;
    if (d->n_unconf) {                               /* a prefix of the unconfirmed batches survives */
        uint64_t first = d->unconfirmed[0] | (d->incarnation << 32), cut;
        cut = first + sim_rng_below(&w->rng, d->n_unconf + 1);
        for (k = 0; k < d->n_recs; k++)
            if (d->recs[k].batch >= cut && (d->recs[k].batch >> 32) == d->incarnation) { keep = k; break; }
        for (k = keep; k < d->n_recs; k++) free(d->recs[k].b);
        d->n_recs = keep;
    }
    if (i == 0) { for (j = 1; j <= w->n; j++) w_link(w, j, 0); }
    else w_link(w, i, 0);
    d->alive = 0;
}

/* One step of 50 ms: faults, storage, messages, timers. */
static inline void w_step(world_t *w, int faults)
{
    size_t k;
    int i, j;
    w->now += 50;
    w->faults_on = faults;
    for (i = 0; i <= w->n; i++) {
        w_node_t *d = &w->node[i];
        if (faults && d->alive && sim_rng_chance(&w->rng, w->crash_pm)) w_crash(w, i);
        else if (!d->alive && !d->dead && sim_rng_chance(&w->rng, 100)) w_boot(d);
        if (d->alive) w_confirm(d);
        if (i > 0) {
            if (faults && w->link_up[i] && sim_rng_chance(&w->rng, w->cut_pm)) { w->cuts++; w_link(w, i, 0); }
            else if (!w->link_up[i] && sim_rng_chance(&w->rng, 200)) w_link(w, i, 1);
            if (w->node[i].close_requested || w->cut_req[i]) {
                w->node[i].close_requested = 0; w->cut_req[i] = 0; w_link(w, i, 0);
            }
        }
    }
    for (k = 0; k < w->n_msgs; k++) {                 /* in sending order: BOLT 8 keeps order */
        w_msg_t m = w->msgs[k];
        gz_lobby_input_t in;
        int link = m.to ? m.to : m.from;
        if (m.at == 0 || m.at > w->now) continue;
        memmove(&w->msgs[k], &w->msgs[k + 1], (w->n_msgs - k - 1) * sizeof *w->msgs);
        w->n_msgs--;
        k--;
        if (m.conn == w->conn_no[link] && w->link_up[link] && w->node[m.to].alive) {
            memset(&in, 0, sizeof in);
            in.kind = GZ_LIN_MESSAGE;
            in.peer_id = m.to ? W_HOST_PEER : W_PEER(m.from);
            in.bytes = m.b; in.len = m.n;
            w->delivered++;
            w_input(&w->node[m.to], &in);
        }
        free(m.b);
    }
    for (k = 0; k < w->n_msgs; k++)
        if (w->msgs[k].at == 0) {
            free(w->msgs[k].b);
            memmove(&w->msgs[k], &w->msgs[k + 1], (w->n_msgs - k - 1) * sizeof *w->msgs);
            w->n_msgs--;
            k--;
        }
    for (i = 0; i <= w->n; i++) {
        w_node_t *d = &w->node[i];
        for (j = 0; j < d->n_timers; j++)
            if (d->alive && d->timers[j].at <= w->now) {
                gz_lobby_input_t in;
                memset(&in, 0, sizeof in);
                in.kind = GZ_LIN_TIMER;
                in.timer_id = d->timers[j].id;
                d->timers[j] = d->timers[--d->n_timers];
                j--;
                w_input(d, &in);
            }
    }
}

static inline void w_run(world_t *w, int steps, int faults)
{
    int i;
    for (i = 0; i < steps; i++) w_step(w, faults);
}

static inline void w_free(world_t *w)
{
    int i;
    size_t k;
    for (i = 0; i <= w->n; i++) {
        for (k = 0; k < w->node[i].n_recs; k++) free(w->node[i].recs[k].b);
        free(w->node[i].recs); free(w->node[i].rbytes); free(w->node[i].host); free(w->node[i].mem);
    }
    for (k = 0; k < w->n_msgs; k++) free(w->msgs[k].b);
    free(w->msgs);
}

/* Counting helpers. */
static inline int w_count_recs(const w_node_t *d, uint32_t type)
{
    size_t k;
    int c = 0;
    for (k = 0; k < d->n_recs; k++) c += d->recs[k].type == type;
    return c;
}

static inline int w_has_note(const w_node_t *d, uint32_t code, int a, int b)
{
    int k;
    for (k = 0; k < d->n_notes; k++)
        if (d->notes[k] == code && (a < 0 || d->note_a[k] == a) && (b < 0 || d->note_b[k] == b)) return 1;
    return 0;
}

#endif
