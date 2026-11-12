#include "gazpacho/node.h"
#include <string.h>

static const uint8_t PING_PREFIX[GZ_PING_PREFIX_LEN] = {'G', 'Z', 'P', 'I'};
static const uint8_t PONG_PREFIX[GZ_PING_PREFIX_LEN] = {'G', 'Z', 'P', 'O'};

gz_status_t gz_node_init(gz_node_t *node, const gz_ports_t *ports)
{
    if (!node || !ports || !ports->random.fill || !ports->clock.now_ms) return GZ_ERR_ARGUMENT;
    node->ports = *ports;
    node->next_serial = 1;
    node->start_done_to = 0;
    node->start_recording = 0;
    node->awaiting_head = node->n_awaiting = 0;
    return GZ_OK;
}

static int is_ping(gz_bytes_t message)
{
    return message.len >= GZ_PING_PREFIX_LEN &&
           message.len <= GZ_PING_PREFIX_LEN + GZ_PING_MAX_PAYLOAD &&
           memcmp(message.data, PING_PREFIX, GZ_PING_PREFIX_LEN) == 0;
}

static void put_u64(uint8_t out[8], uint64_t v)
{
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (8 * (7 - i)));
}

static uint64_t get_u64(const uint8_t in[8])
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = v << 8 | in[i];
    return v;
}

/* Note that one more of the node's save batches awaits confirmation. */
static void await(gz_node_t *node, uint64_t serial)
{
    node->awaiting[(node->awaiting_head + node->n_awaiting++) % GZ_NODE_MAX_AWAITING] = serial;
}

/* Append a save of one record to the list. */
static gz_status_t add_record(gz_action_list_t *out, uint32_t type, const uint8_t *bytes, size_t len)
{
    gz_record_t record = {type, {bytes, len}};
    gz_action_t save = {.kind = GZ_ACTION_SAVE};
    save.u.save.records = &record;
    save.u.save.n_records = 1;
    return gz_action_list_add(out, &save);
}

/* Append "save a record of this ping" to the list. */
static gz_status_t add_ping_record(gz_node_t *node, uint64_t peer_id, gz_bytes_t payload,
                                   gz_action_list_t *out)
{
    uint8_t body[GZ_PING_RECORD_HEADER + GZ_PING_MAX_PAYLOAD];
    put_u64(body, node->ports.clock.now_ms(node->ports.clock.ctx));
    put_u64(body + 8, peer_id);
    put_u64(body + 16, node->next_serial);
    if (payload.len) memcpy(body + GZ_PING_RECORD_HEADER, payload.data, payload.len);
    return add_record(out, GZ_RECORD_TEST_PING, body, GZ_PING_RECORD_HEADER + payload.len);
}

/* Append "send the reply to this ping" to the list. */
static gz_status_t add_pong(uint64_t peer_id, gz_bytes_t payload, gz_action_list_t *out)
{
    uint8_t reply[GZ_PING_PREFIX_LEN + GZ_PING_MAX_PAYLOAD];
    memcpy(reply, PONG_PREFIX, GZ_PING_PREFIX_LEN);
    if (payload.len) memcpy(reply + GZ_PING_PREFIX_LEN, payload.data, payload.len);

    gz_action_t send = {.kind = GZ_ACTION_SEND};
    send.u.send.peer_id = peer_id;
    send.u.send.bytes.data = reply;
    send.u.send.bytes.len = GZ_PING_PREFIX_LEN + payload.len;
    return gz_action_list_add(out, &send);
}

/* Save first, then reply. On failure the list is put back as it was. */
static gz_status_t answer_ping(gz_node_t *node, uint64_t peer_id, gz_bytes_t message,
                               gz_action_list_t *out)
{
    gz_bytes_t payload = {message.data + GZ_PING_PREFIX_LEN, message.len - GZ_PING_PREFIX_LEN};
    size_t count_before = out->count, used_before = out->used;
    if (node->n_awaiting == GZ_NODE_MAX_AWAITING) return GZ_ERR_NO_SPACE;
    gz_status_t st = add_ping_record(node, peer_id, payload, out);
    if (st == GZ_OK) st = add_pong(peer_id, payload, out);
    if (st != GZ_OK) {
        out->count = count_before;
        out->used = used_before;
        return st;
    }
    await(node, node->next_serial++);
    return GZ_OK;
}

/* The oldest of the node's batches is stored. If it recorded a ping, the
 * runner has now released the reply: save a record saying so. */
static gz_status_t batch_confirmed(gz_node_t *node, gz_action_list_t *out)
{
    uint8_t body[8];
    if (node->n_awaiting == 0) return GZ_OK;
    uint64_t serial = node->awaiting[node->awaiting_head];
    if (serial != 0) {
        put_u64(body, serial);
        gz_status_t st = add_record(out, GZ_RECORD_TEST_PING_SENT, body, sizeof body);
        if (st != GZ_OK) return st;
    }
    node->awaiting_head = (node->awaiting_head + 1) % GZ_NODE_MAX_AWAITING;
    node->n_awaiting--;
    if (serial != 0) await(node, 0);
    return GZ_OK;
}

static int is_ping_record(const gz_record_t *record)
{
    return record->type == GZ_RECORD_TEST_PING && record->bytes.len >= GZ_PING_RECORD_HEADER &&
           record->bytes.len <= GZ_PING_RECORD_HEADER + GZ_PING_MAX_PAYLOAD;
}

/* The replies one start step is considering: the serials of the next few
 * stored pings, and for each whether storage says its reply was sent. */
typedef struct {
    uint64_t serial[GZ_NODE_START_CHUNK];
    int sent[GZ_NODE_START_CHUNK];
    size_t n;
    int more_beyond;        /* storage holds pings after these */
} chunk_t;

/* Walk storage once, calling `visit` for every record. */
static gz_status_t for_each_record(const gz_storage_reader_t *storage,
                                   gz_status_t (*visit)(const gz_record_t *, gz_node_t *, chunk_t *, gz_action_list_t *),
                                   gz_node_t *node, chunk_t *chunk, gz_action_list_t *out)
{
    gz_stored_batch_t batch;
    storage->rewind(storage->ctx);
    while (storage->next(storage->ctx, &batch)) {
        for (size_t i = 0; i < batch.n_records; i++) {
            gz_status_t st = visit(&batch.records[i], node, chunk, out);
            if (st != GZ_OK) return st;
        }
    }
    return GZ_OK;
}

/* First walk: pick the next stored pings the start has not dealt with yet. */
static gz_status_t pick(const gz_record_t *record, gz_node_t *node, chunk_t *chunk, gz_action_list_t *out)
{
    (void)out;
    if (!is_ping_record(record)) return GZ_OK;
    uint64_t serial = get_u64(record->bytes.data + 16);
    if (serial >= node->next_serial) node->next_serial = serial + 1;
    if (serial <= node->start_done_to) return GZ_OK;
    if (chunk->n < GZ_NODE_START_CHUNK) chunk->serial[chunk->n++] = serial;
    else chunk->more_beyond = 1;
    return GZ_OK;
}

/* Second walk: note which of the picked pings storage records as sent. */
static gz_status_t mark_sent(const gz_record_t *record, gz_node_t *node, chunk_t *chunk, gz_action_list_t *out)
{
    (void)node; (void)out;
    if (record->type != GZ_RECORD_TEST_PING_SENT) return GZ_OK;
    for (size_t at = 0; at + 8 <= record->bytes.len; at += 8)
        for (size_t k = 0; k < chunk->n; k++)
            if (chunk->serial[k] == get_u64(record->bytes.data + at)) chunk->sent[k] = 1;
    return GZ_OK;
}

/* Third walk: resend the reply to each picked ping not recorded as sent. */
static gz_status_t resend(const gz_record_t *record, gz_node_t *node, chunk_t *chunk, gz_action_list_t *out)
{
    (void)node;
    if (!is_ping_record(record)) return GZ_OK;
    const uint8_t *body = record->bytes.data;
    for (size_t k = 0; k < chunk->n; k++) {
        if (chunk->serial[k] != get_u64(body + 16) || chunk->sent[k]) continue;
        gz_bytes_t payload = {body + GZ_PING_RECORD_HEADER, record->bytes.len - GZ_PING_RECORD_HEADER};
        return add_pong(get_u64(body + 8), payload, out);
    }
    return GZ_OK;
}

/* Append one "sent" record naming every picked ping that was just resent.
 * Returns how many that was through `*n_resent`. */
static gz_status_t record_resent(gz_node_t *node, const chunk_t *chunk, gz_action_list_t *out, size_t *n_resent)
{
    uint8_t serials[8 * GZ_NODE_START_CHUNK];
    size_t n = 0;
    for (size_t k = 0; k < chunk->n; k++)
        if (!chunk->sent[k]) put_u64(serials + 8 * n++, chunk->serial[k]);
    *n_resent = n;
    if (n == 0) return GZ_OK;
    if (node->n_awaiting == GZ_NODE_MAX_AWAITING) return GZ_ERR_NO_SPACE;
    gz_status_t st = add_record(out, GZ_RECORD_TEST_PING_SENT, serials, 8 * n);
    if (st == GZ_OK) await(node, 0);
    return st;
}

/* Look at the next chunk of stored pings the current pass has not dealt
 * with, and note which of them storage records as sent. */
static gz_status_t next_chunk(gz_node_t *node, const gz_storage_reader_t *storage, chunk_t *chunk)
{
    *chunk = (chunk_t){{0}, {0}, 0, 0};
    gz_status_t st = for_each_record(storage, pick, node, chunk, NULL);
    if (st == GZ_OK && chunk->n > 0) st = for_each_record(storage, mark_sent, node, chunk, NULL);
    return st;
}

/* One step of the start. Two passes over the stored pings, a chunk at a
 * time: first resend every reply not recorded as sent, then save the records
 * that say so. The saves come last, in steps of their own, so that no resent
 * reply has to wait for one of them to be confirmed. */
static gz_status_t start_step(gz_node_t *node, const gz_storage_reader_t *storage,
                              gz_action_list_t *out, int *more)
{
    for (;;) {
        chunk_t chunk;
        size_t n_done = 0;
        gz_status_t st = next_chunk(node, storage, &chunk);
        if (st == GZ_OK && !node->start_recording) {
            size_t before = out->count;
            st = for_each_record(storage, resend, node, &chunk, out);
            n_done = out->count - before;
        } else if (st == GZ_OK) {
            st = record_resent(node, &chunk, out, &n_done);
        }
        if (st != GZ_OK) return st;
        if (chunk.n > 0) node->start_done_to = chunk.serial[chunk.n - 1];
        if (!chunk.more_beyond && !node->start_recording) {     /* every reply resent: now the records */
            node->start_recording = 1;
            node->start_done_to = 0;
            chunk.more_beyond = 1;
        }
        *more = chunk.more_beyond;
        if (n_done > 0 || !chunk.more_beyond) return GZ_OK;
    }
}

gz_status_t gz_node_start(gz_node_t *node, const gz_storage_reader_t *storage,
                          gz_action_list_t *actions_out, int *more)
{
    if (!node || !storage || !storage->next || !storage->rewind || !actions_out || !more) return GZ_ERR_ARGUMENT;
    size_t count_before = actions_out->count, used_before = actions_out->used;
    uint64_t done_before = node->start_done_to;
    int recording_before = node->start_recording, more_out = 0;
    gz_status_t st = start_step(node, storage, actions_out, &more_out);
    if (st != GZ_OK) {
        actions_out->count = count_before;
        actions_out->used = used_before;
        node->start_done_to = done_before;
        node->start_recording = recording_before;
        return st;
    }
    *more = more_out;
    return GZ_OK;
}

gz_status_t gz_node_handle(gz_node_t *node, const gz_event_t *event,
                           gz_action_list_t *actions_out)
{
    if (!node || !event || !actions_out) return GZ_ERR_ARGUMENT;
    if (event->kind == GZ_EVENT_MESSAGE_RECEIVED && is_ping(event->u.message.bytes))
        return answer_ping(node, event->u.message.peer_id, event->u.message.bytes, actions_out);
    if (event->kind == GZ_EVENT_STORAGE_CONFIRMED)
        return batch_confirmed(node, actions_out);
    return GZ_OK;
}
