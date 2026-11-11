#include "gazpacho/node.h"
#include <string.h>

static const uint8_t PING_PREFIX[GZ_PING_PREFIX_LEN] = {'G', 'Z', 'P', 'I'};
static const uint8_t PONG_PREFIX[GZ_PING_PREFIX_LEN] = {'G', 'Z', 'P', 'O'};

gz_status_t gz_node_init(gz_node_t *node, const gz_ports_t *ports)
{
    if (!node || !ports || !ports->random.fill || !ports->clock.now_ms) return GZ_ERR_ARGUMENT;
    node->ports = *ports;
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

/* Append "save a record of this ping" to the list. */
static gz_status_t add_ping_record(gz_node_t *node, uint64_t peer_id, gz_bytes_t payload,
                                   gz_action_list_t *out)
{
    uint8_t body[GZ_PING_RECORD_HEADER + GZ_PING_MAX_PAYLOAD];
    put_u64(body, node->ports.clock.now_ms(node->ports.clock.ctx));
    put_u64(body + 8, peer_id);
    if (payload.len) memcpy(body + GZ_PING_RECORD_HEADER, payload.data, payload.len);

    gz_record_t record = {GZ_RECORD_TEST_PING, {body, GZ_PING_RECORD_HEADER + payload.len}};
    gz_action_t save = {.kind = GZ_ACTION_SAVE};
    save.u.save.records = &record;
    save.u.save.n_records = 1;
    return gz_action_list_add(out, &save);
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
    gz_status_t st = add_ping_record(node, peer_id, payload, out);
    if (st == GZ_OK) st = add_pong(peer_id, payload, out);
    if (st != GZ_OK) {
        out->count = count_before;
        out->used = used_before;
    }
    return st;
}

static int is_ping_record(const gz_record_t *record)
{
    return record->type == GZ_RECORD_TEST_PING && record->bytes.len >= GZ_PING_RECORD_HEADER &&
           record->bytes.len <= GZ_PING_RECORD_HEADER + GZ_PING_MAX_PAYLOAD;
}

gz_status_t gz_node_start(gz_node_t *node, const gz_record_t *stored, size_t n_stored,
                          gz_action_list_t *actions_out)
{
    if (!node || !actions_out || (n_stored && !stored)) return GZ_ERR_ARGUMENT;
    for (size_t i = n_stored; i-- > 0;) {
        if (!is_ping_record(&stored[i])) continue;
        const uint8_t *body = stored[i].bytes.data;
        gz_bytes_t payload = {body + GZ_PING_RECORD_HEADER, stored[i].bytes.len - GZ_PING_RECORD_HEADER};
        return add_pong(get_u64(body + 8), payload, actions_out);
    }
    return GZ_OK;
}

gz_status_t gz_node_handle(gz_node_t *node, const gz_event_t *event,
                           gz_action_list_t *actions_out)
{
    if (!node || !event || !actions_out) return GZ_ERR_ARGUMENT;
    if (event->kind == GZ_EVENT_MESSAGE_RECEIVED && is_ping(event->u.message.bytes))
        return answer_ping(node, event->u.message.peer_id, event->u.message.bytes, actions_out);
    return GZ_OK;
}
