/* Test nodes shared by the simulator tests.
 *
 * The "multi" node does more per step than the placeholder ping node: three
 * save batches in one list with a notify, a watch, a broadcast, a timer and
 * two sends between and after them, and a start that re-broadcasts and
 * resends from what storage holds. It exists so the simulator exercises the
 * runner with several batches unconfirmed at once and with every kind of
 * action.
 *
 * Also here: programs that are FAULTY ON PURPOSE, which the harness must
 * catch. They live in the tests, never in the library. */
#ifndef GAZPACHO_TEST_SIM_NODES_H
#define GAZPACHO_TEST_SIM_NODES_H

#include "sim.h"
#include <stdlib.h>
#include <string.h>

#define MULTI_RECORD_DECISION 0xd1u     /* a transaction the node decided to broadcast */
#define MULTI_RECORD_MESSAGE  0xa1u     /* 8-byte little-endian peer, then a message to send */
#define MULTI_RECORD_NOTE     0xc1u
#define MULTI_MAX             64        /* largest input the multi node acts on */

typedef struct {
    uint8_t decision[MULTI_MAX + 2]; size_t decision_len;   /* newest stored decision, if any */
    uint8_t message[MULTI_MAX + 9]; size_t message_len;     /* newest stored message record, if any */
} multi_node_t;

static inline uint32_t multi_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* Remember the newest decision and the newest message found in storage. */
static inline void *multi_create(void *ctx, uint32_t index, const gz_ports_t *ports, const sim_storage_t *storage)
{
    (void)index; (void)ports;
    multi_node_t *m = calloc(1, sizeof *m);
    if (!m) abort();
    if (ctx) (*(int *)ctx)++;           /* tests may count how often each simulator builds a node */
    for (size_t i = 0; i < sim_storage_count(storage); i++) {
        size_t len = 0;
        const uint8_t *p = sim_storage_batch_bytes(storage, i, &len), *end = p + len;
        for (; p < end; p += 8 + multi_u32(p + 4)) {
            uint32_t type = multi_u32(p), n = multi_u32(p + 4);
            if (type == MULTI_RECORD_DECISION && n <= sizeof m->decision) { memcpy(m->decision, p + 8, n); m->decision_len = n; }
            if (type == MULTI_RECORD_MESSAGE && n <= sizeof m->message) { memcpy(m->message, p + 8, n); m->message_len = n; }
        }
    }
    return m;
}

static inline void multi_destroy(void *ctx, void *node) { (void)ctx; free(node); }

static inline gz_status_t multi_add(gz_action_list_t *out, gz_action_kind_t kind, uint64_t number, const uint8_t *bytes, size_t len)
{
    gz_action_t a = {.kind = kind};
    gz_bytes_t b = {bytes, len};
    switch (kind) {
    case GZ_ACTION_SEND:      a.u.send.peer_id = number; a.u.send.bytes = b; break;
    case GZ_ACTION_BROADCAST: a.u.broadcast.tx = b; break;
    case GZ_ACTION_WATCH:     a.u.watch.script = b; break;
    case GZ_ACTION_NOTIFY:    a.u.notify.code = (uint32_t)number; a.u.notify.bytes = b; break;
    default:                  a.u.set_timer.timer_id = number; a.u.set_timer.delay_ms = len; break;
    }
    return gz_action_list_add(out, &a);
}

static inline gz_status_t multi_save(gz_action_list_t *out, uint32_t type, const uint8_t *bytes, size_t len)
{
    gz_record_t r = {type, {bytes, len}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    return gz_action_list_add(out, &a);
}

static inline uint64_t multi_peer(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* At start: watch and timer again, broadcast the newest stored decision
 * again, send the newest stored message again. */
static inline gz_status_t multi_start(void *node, gz_action_list_t *out)
{
    multi_node_t *m = node;
    gz_status_t st = multi_add(out, GZ_ACTION_WATCH, 0, (const uint8_t *)"multi", 5);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_SET_TIMER, 5, NULL, 3);
    if (st == GZ_OK && m->decision_len) st = multi_add(out, GZ_ACTION_BROADCAST, 0, m->decision, m->decision_len);
    if (st == GZ_OK && m->message_len >= 8)
        st = multi_add(out, GZ_ACTION_SEND, multi_peer(m->message), m->message + 8, m->message_len - 8);
    return st;
}

/* For a message or a user command carrying bytes b:
 *   save{decision: tx}  save{message}  notify  watch  broadcast tx  timer
 *   send "M"+b  save{note}  send "C"+b */
static inline gz_status_t multi_handle(void *node, const gz_event_t *ev, gz_action_list_t *out)
{
    (void)node;
    gz_bytes_t b;
    uint64_t peer;
    if (ev->kind == GZ_EVENT_MESSAGE_RECEIVED) { b = ev->u.message.bytes; peer = ev->u.message.peer_id; }
    else if (ev->kind == GZ_EVENT_USER_COMMAND) { b = ev->u.user.bytes; peer = SIM_WORLD_PEER; }
    else return GZ_OK;
    if (b.len == 0 || b.len > MULTI_MAX) return GZ_OK;

    uint8_t tx[MULTI_MAX + 2] = {0, 'T'}, record[MULTI_MAX + 9], text[MULTI_MAX + 1] = {'M'};
    memcpy(tx + 2, b.data, b.len);                      /* a transaction spending nothing watched */
    for (int i = 0; i < 8; i++) record[i] = (uint8_t)(peer >> (8 * i));
    record[8] = 'M';
    memcpy(record + 9, b.data, b.len);
    memcpy(text + 1, b.data, b.len);

    gz_status_t st = multi_save(out, MULTI_RECORD_DECISION, tx, b.len + 2);
    if (st == GZ_OK) st = multi_save(out, MULTI_RECORD_MESSAGE, record, b.len + 9);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_NOTIFY, 1, b.data, b.len);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_WATCH, 0, b.data, b.len);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_BROADCAST, 0, tx, b.len + 2);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_SET_TIMER, 5, NULL, 3);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_SEND, peer, text, b.len + 1);
    if (st == GZ_OK) st = multi_save(out, MULTI_RECORD_NOTE, b.data, b.len);
    text[0] = 'C';
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_SEND, peer, text, b.len + 1);
    return st;
}

static inline sim_node_ops_t multi_ops(void)
{
    sim_node_ops_t ops = {multi_create, multi_destroy, multi_start, multi_handle, NULL, NULL, NULL};
    return ops;
}

/* FAULTY ON PURPOSE: a program that carries out every action at once instead
 * of going through the runner. */
static inline gz_status_t eager_release(void *ctx, sim_t *sim, uint32_t index, const gz_action_list_t *list)
{
    (void)ctx;
    for (size_t i = 0; i < list->count; i++) sim_execute(sim, index, &list->slots[i]);
    return GZ_OK;
}

#endif
