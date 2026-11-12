#include "gazpacho/node.h"
#include <string.h>

static const uint8_t PING_PREFIX[GZ_PING_PREFIX_LEN] = {'G', 'Z', 'P', 'I'};
static const uint8_t PONG_PREFIX[GZ_PING_PREFIX_LEN] = {'G', 'Z', 'P', 'O'};

gz_status_t gz_node_init(gz_node_t *node, const gz_ports_t *ports)
{
    if (!node || !ports || !ports->random.fill || !ports->clock.now_ms) return GZ_ERR_ARGUMENT;
    node->ports = *ports;
    node->next_serial = 1;
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

/* 1 if some stored "sent" record names this serial. */
static int recorded_as_sent(const gz_record_t *stored, size_t n_stored, uint64_t serial)
{
    for (size_t i = 0; i < n_stored; i++) {
        if (stored[i].type != GZ_RECORD_TEST_PING_SENT) continue;
        for (size_t at = 0; at + 8 <= stored[i].bytes.len; at += 8)
            if (get_u64(stored[i].bytes.data + at) == serial) return 1;
    }
    return 0;
}

/* Resend, oldest first, every stored reply not recorded as sent, and append
 * one save recording them as sent. */
static gz_status_t resend_unsent(gz_node_t *node, const gz_record_t *stored, size_t n_stored,
                                 gz_action_list_t *out)
{
    uint8_t serials[8 * GZ_NODE_MAX_AWAITING];
    size_t n = 0;
    for (size_t i = 0; i < n_stored; i++) {
        if (!is_ping_record(&stored[i])) continue;
        const uint8_t *body = stored[i].bytes.data;
        uint64_t serial = get_u64(body + 16);
        if (serial >= node->next_serial) node->next_serial = serial + 1;
        if (recorded_as_sent(stored, n_stored, serial)) continue;
        if (n == GZ_NODE_MAX_AWAITING) return GZ_ERR_NO_SPACE;
        gz_bytes_t payload = {body + GZ_PING_RECORD_HEADER, stored[i].bytes.len - GZ_PING_RECORD_HEADER};
        gz_status_t st = add_pong(get_u64(body + 8), payload, out);
        if (st != GZ_OK) return st;
        put_u64(serials + 8 * n++, serial);
    }
    if (n == 0) return GZ_OK;
    gz_status_t st = add_record(out, GZ_RECORD_TEST_PING_SENT, serials, 8 * n);
    if (st == GZ_OK) await(node, 0);
    return st;
}

gz_status_t gz_node_start(gz_node_t *node, const gz_record_t *stored, size_t n_stored,
                          gz_action_list_t *actions_out)
{
    if (!node || !actions_out || (n_stored && !stored)) return GZ_ERR_ARGUMENT;
    size_t count_before = actions_out->count, used_before = actions_out->used;
    gz_status_t st = resend_unsent(node, stored, n_stored, actions_out);
    if (st != GZ_OK) {
        actions_out->count = count_before;
        actions_out->used = used_before;
    }
    return st;
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
