/* The node: the object that receives every event and returns the actions.
 *
 * This is the frame only. It holds no engine yet and knows no protocol. It
 * answers one placeholder message, a ping, so that the path from event to
 * saved record to sent reply, and the path from stored record to resent reply
 * after a restart, are exercised end to end by the tests and the simulator.
 * The ping is not part of any Gazpacho protocol and will be removed when the
 * first engine arrives. */
#ifndef GAZPACHO_NODE_H
#define GAZPACHO_NODE_H

#include "gazpacho/action.h"
#include "gazpacho/event.h"
#include "gazpacho/ports.h"

/* Placeholder ping: a received message of GZ_PING_PREFIX_LEN prefix bytes
 * "GZPI" followed by 0..GZ_PING_MAX_PAYLOAD payload bytes. The reply is "GZPO"
 * followed by the same payload. */
#define GZ_PING_PREFIX_LEN  4
#define GZ_PING_MAX_PAYLOAD 64

/* Type tag of the record saved for each answered ping: an 8-byte big-endian
 * clock stamp, the 8-byte big-endian identifier of the peer that sent the
 * ping, then the ping's payload. */
#define GZ_RECORD_TEST_PING   0x7e570001u
#define GZ_PING_RECORD_HEADER 16

/* Caller-allocated; treat the fields as private. Holds no pointers of its own
 * besides the ports' context pointers, so it needs no destroy call. */
typedef struct {
    gz_ports_t ports;
} gz_node_t;

/* Prepare a node. `ports` is copied.
 * Returns GZ_ERR_ARGUMENT if an argument or a port function is NULL. */
gz_status_t gz_node_init(gz_node_t *node, const gz_ports_t *ports);

/* Start, or start again after a stop or a crash. Called once after
 * gz_node_init and before any event. `stored[0..n_stored)` are the records
 * found in storage, oldest first; they are only read during the call. The
 * actions appended to `actions_out` go through the runner like those of any
 * other step. This is where a node re-arms its timers, registers its watches
 * again and sends again what it had saved but may not have sent.
 *
 * For now: if storage holds a ping record, the reply to the newest one is
 * sent again, because the node cannot know whether it left before the stop.
 * The peer may therefore see a reply twice; it never misses one that was
 * saved.
 *
 * Returns GZ_OK; GZ_ERR_ARGUMENT if `node` or `actions_out` is NULL, or
 * `stored` is NULL with a count; GZ_ERR_NO_SPACE if the actions do not fit.
 * On any error `actions_out` is exactly as it was. */
gz_status_t gz_node_start(gz_node_t *node, const gz_record_t *stored, size_t n_stored,
                          gz_action_list_t *actions_out);

/* Handle one event. Appends the resulting actions, in the order they must be
 * carried out, to `actions_out`, which the caller has initialised and normally
 * emptied. The event and everything it points to are only read during the
 * call (see event.h).
 *
 * For now: a ping message produces a save of one GZ_RECORD_TEST_PING record
 * followed by a send of the reply to the peer that sent the ping. Every other
 * event produces no actions.
 *
 * Returns GZ_OK; GZ_ERR_ARGUMENT if an argument is NULL; GZ_ERR_NO_SPACE if
 * the actions do not fit. On any error `actions_out` is exactly as it was. */
gz_status_t gz_node_handle(gz_node_t *node, const gz_event_t *event,
                           gz_action_list_t *actions_out);

#endif
