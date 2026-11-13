/* The signing engine behind the node's two calls: see gazpacho/signing_node.h. */
#include "gazpacho/signing_node.h"

#define SIGN_TIMER_ID 0x5347u     /* the engine's one timer (signing.c) */

int gz_sign_node_wants(const gz_event_t *ev)
{
    if (!ev) return 0;
    switch (ev->kind) {
    case GZ_EVENT_MESSAGE_RECEIVED: {
        /* the envelope: protocol (4), kind (u16), scope (32), records */
        const uint8_t *b = ev->u.message.bytes.data;
        size_t len = ev->u.message.bytes.len;
        uint16_t kind;
        if (!b || len < GZ_RMSG_HEADER || b[0] != GZ_RMSG_PROTOCOL_0 || b[1] != GZ_RMSG_PROTOCOL_1 ||
            b[2] != GZ_RMSG_PROTOCOL_2 || b[3] != GZ_RMSG_PROTOCOL_3) return 0;
        kind = (uint16_t)((uint16_t)b[4] << 8 | b[5]);
        return kind >= GZ_KIND_ROUND_PROPOSE && kind <= GZ_KIND_FACTORY_FUNDED;
    }
    case GZ_EVENT_TIMER_FIRED: return ev->u.timer.timer_id == SIGN_TIMER_ID;
    case GZ_EVENT_PEER_CONNECTED: return 1;
    default: return 0;
    }
}

gz_status_t gz_sign_node_init(gz_sign_node_t *n, gz_sign_t *engine, const gz_sign_config_t *cfg, const gz_ports_t *ports,
                              uint64_t incarnation)
{
    if (!n || !engine) return GZ_ERR_ARGUMENT;
    n->engine = engine;
    n->started = 0;
    return gz_sign_init(engine, cfg, ports, incarnation);
}

gz_status_t gz_sign_node_start(gz_sign_node_t *n, const gz_storage_reader_t *storage, gz_action_list_t *out, int *more)
{
    gz_status_t st;
    if (!n || !n->engine || !storage || !out || !more) return GZ_ERR_ARGUMENT;
    /* node rule 5: after a restore, the node's restore batch is the start's first action */
    if (storage->restored && (out->count == 0 || out->slots[0].kind != GZ_ACTION_SAVE)) return GZ_ERR_ARGUMENT;
    st = gz_sign_start(n->engine, storage, out, more);
    if (st == GZ_OK) n->started = 1;
    return st;
}

gz_status_t gz_sign_node_handle(gz_sign_node_t *n, const gz_event_t *ev, gz_action_list_t *out)
{
    if (!n || !n->engine || !ev || !out || !n->started) return GZ_ERR_ARGUMENT;
    if (!gz_sign_node_wants(ev)) return GZ_OK;
    return gz_sign_handle(n->engine, ev, out);
}
