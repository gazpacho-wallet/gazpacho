/* A small harness for the composite node's unit tests: an in-memory journal,
 * ports, and a program that carries out each list at once (saves durable at
 * once, confirmations given back in order). Every action carried out is
 * logged; NOTIFY log lines and command results are kept as text. */
#ifndef GZ_NODE_TEST_H
#define GZ_NODE_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../check.h"
#include "gazpacho/command.h"
#include "gazpacho/envelope.h"
#include "gazpacho/node.h"
#include "gazpacho/test_engine.h"

#define H_MAX_BATCHES 4096
#define H_MAX_LOG 8192

typedef struct {
    gz_batch_id_t id;
    size_t n;
    gz_record_t *recs;
} h_batch_t;

typedef struct {
    gz_action_t a;             /* payload pointers not kept */
    uint16_t kind;
    uint64_t timer;
    char text[160];
    uint8_t key[33];           /* SEND: remote; DISCONNECT: remote; SET_SEATED: member */
    uint16_t why;
    size_t n_records;          /* SAVE */
    uint32_t types[8];
} h_log_t;

typedef struct {
    gz_node_t *n;
    gz_node_config_t cfg;
    int host;
    uint64_t incarnation, seq, clock, rnd;
    h_batch_t *batches;
    size_t n_batches, read_at;
    gz_batch_id_t pending[256];
    size_t n_pending;
    gz_action_t *slots;
    uint8_t *bytes;
    gz_action_list_t list;
    h_log_t *log;
    size_t n_log;
    int restored;
    gz_status_t last;
    int confirm_auto;          /* give confirmations back at once (default 1) */
} h_t;

static inline void h_key(uint8_t tag, uint32_t i, uint8_t out[33])
{
    memset(out, 0, 33);
    out[0] = 0x02;
    out[1] = tag;
    gz_put_u32(out + 2, i);
}

static inline int h_pub(void *ctx, uint32_t epoch, uint32_t index, uint8_t pub33[33])
{
    (void)ctx;
    (void)epoch;
    h_key('K', index, pub33);
    return 1;
}

static inline int h_host_pub(void *ctx, uint8_t pub33[33])
{
    h_t *h = ctx;
    if (!h->host) return 0;
    h_key('H', 0, pub33);
    return 1;
}

static inline void h_fill(void *ctx, gz_random_purpose_t p, uint8_t *out, size_t len)
{
    h_t *h = ctx;
    (void)p;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(++h->rnd * 131u);
}

static inline uint64_t h_now(void *ctx)
{
    return ((h_t *)ctx)->clock;
}

static inline int h_next(void *ctx, gz_stored_batch_t *b)
{
    h_t *h = ctx;
    if (h->read_at >= h->n_batches) return 0;
    b->id = h->batches[h->read_at].id;
    b->records = h->batches[h->read_at].recs;
    b->n_records = h->batches[h->read_at].n;
    h->read_at++;
    return 1;
}

static inline void h_rewind(void *ctx)
{
    ((h_t *)ctx)->read_at = 0;
}

static inline void h_new_node(h_t *h)
{
    gz_ports_t ports;
    memset(&ports, 0, sizeof ports);
    ports.random.fill = h_fill;
    ports.random.ctx = h;
    ports.clock.now_ms = h_now;
    ports.clock.ctx = h;
    h->incarnation++;
    h->seq = 0;
    h->n_pending = 0;
    if (!h->n) h->n = malloc(gz_node_size());
    CHECK(gz_node_init(h->n, &ports, &h->cfg, h->incarnation) == GZ_OK);
}

static inline void h_init(h_t *h, int host, uint32_t engines)
{
    memset(h, 0, sizeof *h);
    h->host = host;
    h->clock = 1000000;
    h->confirm_auto = 1;
    h->cfg.host = host;
    memset(h->cfg.chain, 0xc4, sizeof h->cfg.chain);
    h->cfg.keys.pub = h_pub;
    h->cfg.keys.host_pub = h_host_pub;
    h->cfg.keys.ctx = h;
    h->cfg.test_engines = engines;
    h->batches = calloc(H_MAX_BATCHES, sizeof *h->batches);
    h->log = calloc(H_MAX_LOG, sizeof *h->log);
    h->slots = calloc(GZ_NODE_LIST_ACTIONS, sizeof *h->slots);
    h->bytes = malloc(GZ_NODE_LIST_BYTES);
    gz_action_list_init(&h->list, h->slots, GZ_NODE_LIST_ACTIONS, h->bytes, GZ_NODE_LIST_BYTES);
    h_new_node(h);
}

static inline void h_free(h_t *h)
{
    for (size_t i = 0; i < h->n_batches; i++) {
        for (size_t k = 0; k < h->batches[i].n; k++) free((void *)h->batches[i].recs[k].bytes.data);
        free(h->batches[i].recs);
    }
    free(h->batches);
    free(h->log);
    free(h->slots);
    free(h->bytes);
    free(h->n);
}

static inline void h_text(gz_bytes_t b, uint64_t type, char *out, size_t cap)
{
    gz_bytes_t v;
    out[0] = 0;
    if (gz_rec_find(b, type, &v) != 1) return;
    size_t n = v.len < cap - 1 ? v.len : cap - 1;
    memcpy(out, v.data, n);
    out[n] = 0;
}

/* Carry out one list: saves are durable at once. */
static inline void h_execute(h_t *h, const gz_action_list_t *l)
{
    for (size_t i = 0; i < l->count; i++) {
        const gz_action_t *a = &l->slots[i];
        h_log_t *g = h->n_log < H_MAX_LOG ? &h->log[h->n_log++] : NULL;
        if (g) {
            memset(g, 0, sizeof *g);
            g->a = *a;
        }
        switch (a->kind) {
        case GZ_ACTION_SAVE: {
            if (h->n_batches == H_MAX_BATCHES || h->n_pending == 256) abort(); /* a harness limit */
            h_batch_t *b = &h->batches[h->n_batches++];
            b->id.incarnation = h->incarnation;
            b->id.sequence = ++h->seq;
            b->n = a->u.save.n_records;
            b->recs = calloc(b->n ? b->n : 1, sizeof *b->recs);
            for (size_t k = 0; k < b->n; k++) {
                uint8_t *c = malloc(a->u.save.records[k].bytes.len + 1);
                if (a->u.save.records[k].bytes.len) memcpy(c, a->u.save.records[k].bytes.data, a->u.save.records[k].bytes.len);
                b->recs[k].type = a->u.save.records[k].type;
                b->recs[k].bytes.data = c;
                b->recs[k].bytes.len = a->u.save.records[k].bytes.len;
                if (g && k < 8) g->types[k] = a->u.save.records[k].type;
            }
            if (g) g->n_records = b->n;
            h->pending[h->n_pending++] = b->id;
            break;
        }
        case GZ_ACTION_SEND:
            if (g) {
                g->kind = a->u.send.kind;
                memcpy(g->key, a->u.send.link.remote.key, 33);
            }
            break;
        case GZ_ACTION_DISCONNECT:
            if (g) {
                memcpy(g->key, a->u.disconnect.link.remote.key, 33);
                g->why = a->u.disconnect.why;
            }
            break;
        case GZ_ACTION_SET_SEATED:
            if (g) memcpy(g->key, a->u.set_seated.member.key, 33);
            break;
        case GZ_ACTION_SET_TIMER:
            if (g) g->timer = a->u.set_timer.timer_id;
            break;
        case GZ_ACTION_CANCEL_TIMER:
            if (g) g->timer = a->u.cancel_timer.timer_id;
            break;
        case GZ_ACTION_NOTIFY:
            if (!g) break;
            if (a->u.notify.code == GZ_NOTIFY_LOG) h_text(a->u.notify.bytes, 0, g->text, sizeof g->text);
            else if (a->u.notify.code == GZ_NOTIFY_COMMAND_RESULT) {
                gz_bytes_t v;
                char err[64];
                unsigned st = 0;
                if (gz_rec_find(a->u.notify.bytes, 2, &v) == 1 && v.len == 2) st = gz_get_u16(v.data);
                h_text(a->u.notify.bytes, 4, err, sizeof err);
                snprintf(g->text, sizeof g->text, "result %u %s", st, err);
            } else if ((a->u.notify.code >> 16) == 1) {
                gz_bytes_t v;
                unsigned long long ver = 0;
                if (gz_rec_find(a->u.notify.bytes, 4, &v) == 1 && v.len == 8) ver = gz_get_u64(v.data);
                snprintf(g->text, sizeof g->text, "view %llu", ver);
            }
            break;
        default:
            break;
        }
    }
}

static inline gz_status_t h_handle_raw(h_t *h, const gz_event_t *ev);

static inline void h_confirm_all(h_t *h)
{
    while (h->confirm_auto && h->n_pending) {
        gz_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_STORAGE_CONFIRMED;
        ev.u.storage.batch = h->pending[0];
        memmove(h->pending, h->pending + 1, (--h->n_pending) * sizeof h->pending[0]);
        if (h_handle_raw(h, &ev) != GZ_OK) return;
    }
}

static inline gz_status_t h_handle_raw(h_t *h, const gz_event_t *ev)
{
    gz_action_list_reset(&h->list);
    h->last = gz_node_handle(h->n, ev, &h->list);
    if (h->last == GZ_OK) h_execute(h, &h->list);
    return h->last;
}

static inline gz_status_t h_event(h_t *h, const gz_event_t *ev)
{
    gz_status_t st = h_handle_raw(h, ev);
    if (st == GZ_OK) h_confirm_all(h);
    return st;
}

/* The whole stepped start. */
static inline gz_status_t h_start(h_t *h)
{
    gz_storage_reader_t rd;
    int more = 1, steps = 0;
    memset(&rd, 0, sizeof rd);
    rd.next = h_next;
    rd.rewind = h_rewind;
    rd.ctx = h;
    rd.incarnation = h->incarnation;
    rd.restored = h->restored;
    while (more && steps++ < 1000) {
        gz_action_list_reset(&h->list);
        gz_status_t st = gz_node_start(h->n, &rd, &h->list, &more);
        if (st == GZ_WAITING) {
            if (!h->n_pending) return st;
            h_confirm_all(h);
            continue;
        }
        if (st != GZ_OK) return st;
        h_execute(h, &h->list);
        h_confirm_all(h);
    }
    return GZ_OK;
}

/* A restart from storage: a new node, a new incarnation. */
static inline gz_status_t h_restart(h_t *h)
{
    h_new_node(h);
    return h_start(h);
}

/* ---- events ---- */

static inline gz_link_t h_link(const uint8_t local[33], const uint8_t remote[33])
{
    gz_link_t l;
    memcpy(l.local.key, local, 33);
    memcpy(l.remote.key, remote, 33);
    return l;
}

/* The host's link to member key m ('M', i). */
static inline gz_link_t h_host_link(uint32_t member)
{
    uint8_t a[33], b[33];
    h_key('H', 0, a);
    h_key('M', member, b);
    return h_link(a, b);
}

static inline gz_status_t h_peer(h_t *h, const gz_link_t *l, int up, int outbound)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = up ? GZ_EVENT_PEER_CONNECTED : GZ_EVENT_PEER_DISCONNECTED;
    ev.u.peer.link = *l;
    ev.u.peer.outbound = outbound;
    return h_event(h, &ev);
}

static inline gz_status_t h_msg(h_t *h, const gz_link_t *l, uint16_t kind, const uint8_t scope[32], const uint8_t *rec,
                         size_t len)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_MESSAGE_RECEIVED;
    ev.u.message.link = *l;
    ev.u.message.kind = kind;
    if (scope) memcpy(ev.u.message.scope, scope, 32);
    ev.u.message.records.data = rec;
    ev.u.message.records.len = len;
    return h_event(h, &ev);
}

/* A test message: record 1 tag and body, record 3 the area. */
static inline gz_status_t h_test_msg(h_t *h, const gz_link_t *l, const char tag[4], const uint8_t *body, size_t blen,
                              uint16_t area)
{
    uint8_t r[200], rec[200], a[2];
    size_t at = 0;
    memcpy(r, tag, 4);
    if (blen) memcpy(r + 4, body, blen);
    gz_put_u16(a, area);
    gz_rec_put(rec, sizeof rec, &at, 1, r, 4 + blen);
    gz_rec_put(rec, sizeof rec, &at, 3, a, 2);
    return h_msg(h, l, GZ_TE_KIND, NULL, rec, at);
}

/* A command: code, then records from 10 given as (type, bytes, len) triples. */
typedef struct {
    uint64_t type;
    const void *v;
    size_t len;
} h_arg_t;

static inline gz_status_t h_cmd(h_t *h, uint16_t code, const h_arg_t *args, size_t n)
{
    uint8_t buf[80000], c2[2];
    size_t at = 0;
    gz_event_t ev;
    gz_put_u16(c2, code);
    gz_rec_put(buf, sizeof buf, &at, 0, (const uint8_t *)"req-1", 5);
    gz_rec_put(buf, sizeof buf, &at, 8, c2, 2);
    for (size_t i = 0; i < n; i++) gz_rec_put(buf, sizeof buf, &at, args[i].type, args[i].v, args[i].len);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_USER_COMMAND;
    ev.u.user.bytes.data = buf;
    ev.u.user.bytes.len = at;
    return h_event(h, &ev);
}

static inline gz_status_t h_timer(h_t *h, uint64_t id)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_TIMER_FIRED;
    ev.u.timer.timer_id = id;
    return h_event(h, &ev);
}

/* ---- the log ---- */

static inline size_t h_mark(const h_t *h)
{
    return h->n_log;
}

static inline size_t h_count(const h_t *h, size_t from, gz_action_kind_t kind)
{
    size_t n = 0;
    for (size_t i = from; i < h->n_log; i++)
        if (h->log[i].a.kind == kind) n++;
    return n;
}

static inline int h_said(const h_t *h, size_t from, const char *text)
{
    for (size_t i = from; i < h->n_log; i++)
        if (h->log[i].a.kind == GZ_ACTION_NOTIFY && strstr(h->log[i].text, text)) return 1;
    return 0;
}

static inline size_t h_records_of(const h_t *h, uint32_t type)
{
    size_t n = 0;
    for (size_t i = 0; i < h->n_batches; i++)
        for (size_t k = 0; k < h->batches[i].n; k++)
            if (h->batches[i].recs[k].type == type) n++;
    return n;
}

/* The last timer id set in the log since `from`, or 0. */
static inline uint64_t h_last_timer(const h_t *h, size_t from)
{
    uint64_t t = 0;
    for (size_t i = from; i < h->n_log; i++)
        if (h->log[i].a.kind == GZ_ACTION_SET_TIMER) t = h->log[i].timer;
    return t;
}

/* No node error anywhere: every test asserts it (composite-node.md 15). */
#define CHECK_NO_NODE_ERROR(h) CHECK(gz_node_error_area((h)->n) == 0 && gz_node_error_status((h)->n) == GZ_OK)

#endif
