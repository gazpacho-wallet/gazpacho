#include "gazpacho/node.h"
#include <string.h>

#define STAMP_LEN 8

static const uint8_t PING_PREFIX[GZ_PING_PREFIX_LEN] = {'G', 'Z', 'P', 'I'};
static const uint8_t PONG_PREFIX[GZ_PING_PREFIX_LEN] = {'G', 'Z', 'P', 'O'};

gz_status_t gz_node_init(gz_node_t *node, const gz_ports_t *ports, uint64_t first_batch_id)
{
    if (!node || !ports || !ports->random.fill || !ports->clock.now_ms) return GZ_ERR_ARGUMENT;
    node->ports = *ports;
    node->next_batch_id = first_batch_id;
    return GZ_OK;
}

static int is_ping(gz_bytes_t message)
{
    return message.len >= GZ_PING_PREFIX_LEN &&
           message.len <= GZ_PING_PREFIX_LEN + GZ_PING_MAX_PAYLOAD &&
           memcmp(message.data, PING_PREFIX, GZ_PING_PREFIX_LEN) == 0;
}

/* Append "save a record of this ping" to the list. */
static gz_status_t add_ping_record(gz_node_t *node, gz_bytes_t payload, gz_action_list_t *out)
{
    uint8_t body[STAMP_LEN + GZ_PING_MAX_PAYLOAD];
    uint64_t now = node->ports.clock.now_ms(node->ports.clock.ctx);
    for (int i = 0; i < STAMP_LEN; i++)
        body[i] = (uint8_t)(now >> (8 * (STAMP_LEN - 1 - i)));
    if (payload.len) memcpy(body + STAMP_LEN, payload.data, payload.len);

    gz_record_t record = {GZ_RECORD_TEST_PING, {body, STAMP_LEN + payload.len}};
    gz_action_t save = {.kind = GZ_ACTION_SAVE};
    save.u.save.batch_id = node->next_batch_id;
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
    gz_status_t st = add_ping_record(node, payload, out);
    if (st == GZ_OK) st = add_pong(peer_id, payload, out);
    if (st != GZ_OK) {
        out->count = count_before;
        out->used = used_before;
        return st;
    }
    node->next_batch_id++;
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
