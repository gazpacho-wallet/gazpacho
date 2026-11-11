/* The node: the object that receives every event and returns the actions.
 *
 * This is the frame only. It holds no engine yet and knows no protocol. It
 * answers one placeholder message, a ping, so that the path from event to
 * saved record to sent reply is exercised end to end by the tests and the
 * simulator. The ping is not part of any Gazpacho protocol and will be
 * removed when the first engine arrives. */
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
 * clock stamp followed by the ping's payload. */
#define GZ_RECORD_TEST_PING 0x7e570001u

/* Caller-allocated; treat the fields as private. Holds no pointers of its own
 * besides the ports' context pointers, so it needs no destroy call. */
typedef struct {
    gz_ports_t ports;
    uint64_t next_batch_id;
} gz_node_t;

/* Prepare a node. `ports` is copied. `first_batch_id` is the identifier the
 * node gives its first save batch; later batches count up from it. A program
 * restarting from storage passes one more than the highest batch it finds
 * there, so identifiers are never reused for stored batches.
 * Returns GZ_ERR_ARGUMENT if an argument or a port function is NULL. */
gz_status_t gz_node_init(gz_node_t *node, const gz_ports_t *ports, uint64_t first_batch_id);

/* Handle one event. Appends the resulting actions, in the order they must be
 * carried out, to `actions_out`, which the caller has initialised and normally
 * emptied. The event and everything it points to are only read during the
 * call (see event.h).
 *
 * For now: a ping message produces a save of one GZ_RECORD_TEST_PING record
 * followed by a send of the reply to the same peer. Every other event
 * produces no actions.
 *
 * Returns GZ_OK; GZ_ERR_ARGUMENT if an argument is NULL; GZ_ERR_NO_SPACE if
 * the actions do not fit. On any error `actions_out` and the node are exactly
 * as they were. */
gz_status_t gz_node_handle(gz_node_t *node, const gz_event_t *event,
                           gz_action_list_t *actions_out);

#endif
