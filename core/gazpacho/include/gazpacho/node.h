/* The node: the object that receives every event and returns the actions.
 *
 * This is the frame only. It holds no engine yet and knows no protocol. It
 * answers one placeholder message, a ping, so that the path from event to
 * saved record to sent reply, and the path from stored record to resent reply
 * after a restart, are exercised end to end by the tests and the simulator.
 * The ping is not part of any Gazpacho protocol and will be removed when the
 * first engine arrives.
 *
 * WHAT EVERY ENGINE'S START STEP MUST DO
 *
 *   A node can stop at any moment: after a record is durable and before the
 *   message it justified has left, or after the message left and before
 *   anything says so. When it starts again it knows only what storage holds.
 *   So, at start, an engine must:
 *
 *   1. Send again, from the stored bytes, everything it has no stored proof
 *      was acknowledged. Not "rebuild and send": the bytes that were saved.
 *   2. Therefore accept that every message it sends may arrive twice, and may
 *      arrive after newer traffic. Every engine message must be safe to
 *      receive twice and out of order with what came later. A message for
 *      which that cannot be made true must not be designed.
 *   3. Store, as records, the acknowledgements that matter. Anything not in
 *      storage is not known after a restart, and will be sent again.
 *   4. Set its timers and register its watches again: the program around the
 *      core forgets them when it stops.
 *
 * WHAT THE PLACEHOLDER GUARANTEES
 *
 *   At least once. If the record of a ping is durable, the reply to it leaves
 *   the node at least once, provided the node goes on running or is started
 *   again. The peer may see a reply twice, or more often: the node cannot
 *   tell a reply that left just before a crash from one that did not, so
 *   after a restart it sends again every reply it has no stored record of
 *   having sent. It is NOT exactly once, and a ping whose record never became
 *   durable gets no reply at all.
 *
 *   How: each ping is saved with a serial number. When that batch is
 *   confirmed the runner has released the reply, and the node saves a "sent"
 *   record naming the serial. At start the node resends, oldest first, the
 *   reply to every stored ping with no stored "sent" record, and then saves
 *   "sent" records for them. */
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

/* Record saved for each ping: an 8-byte big-endian clock stamp, the 8-byte
 * big-endian identifier of the peer that sent it, an 8-byte big-endian serial
 * number (counting from 1, increasing through storage), then the ping's
 * payload. */
#define GZ_RECORD_TEST_PING   0x7e570001u
#define GZ_PING_RECORD_HEADER 24

/* Record saved once replies are known to have been released: one or more
 * 8-byte big-endian serial numbers. */
#define GZ_RECORD_TEST_PING_SENT 0x7e570002u

/* Most save batches the node may have awaiting confirmation. */
#define GZ_NODE_MAX_AWAITING 64

/* Most replies one call of gz_node_start resends. */
#define GZ_NODE_START_CHUNK 8

/* Caller-allocated; treat the fields as private. Holds no pointers of its own
 * besides the ports' context pointers, so it needs no destroy call. */
typedef struct {
    gz_ports_t ports;
    uint64_t next_serial;
    uint64_t start_done_to;     /* the current pass of the start has dealt with every stored ping up to this serial */
    int start_recording;        /* the start has resent everything and is now saving the "sent" records */
    /* The node's save batches not yet confirmed, oldest first: the serial of
     * the ping each one recorded, or 0 for a batch of "sent" records. */
    uint64_t awaiting[GZ_NODE_MAX_AWAITING];
    size_t awaiting_head, n_awaiting;
} gz_node_t;

/* Prepare a node. `ports` is copied.
 * Returns GZ_ERR_ARGUMENT if an argument or a port function is NULL. */
gz_status_t gz_node_init(gz_node_t *node, const gz_ports_t *ports);

/* Start, or start again after a stop or a crash. What a start has to do can
 * exceed one action list, so it is done in steps:
 *
 *     do {
 *         empty the list;
 *         gz_node_start(node, storage, list, &more);   // must return GZ_OK
 *         give the list to the runner;                  // must be accepted
 *     } while (more);
 *
 * No event may be given to the node before a call has set `*more` to 0. A
 * start that returns an error, or whose list the runner refuses, is fatal:
 * the node must not be used, and the program must not carry on as if it had
 * started.
 *
 * `storage` reads back what storage holds (ports.h). It is used only during
 * the call, and may be walked more than once.
 *
 * For now: each call resends, oldest first, up to GZ_NODE_START_CHUNK replies
 * to stored pings that have no stored "sent" record. Once all have been
 * resent, each further call saves one "sent" record covering up to that many
 * of them. The saves come last, in steps of their own, so that no resent
 * reply waits for one of them to be confirmed. See "what the placeholder
 * guarantees".
 *
 * Returns GZ_OK; GZ_ERR_ARGUMENT if an argument or a reader function is NULL;
 * GZ_ERR_NO_SPACE if the actions do not fit or GZ_NODE_MAX_AWAITING batches
 * already await confirmation. On any error `actions_out` is exactly as it
 * was. */
gz_status_t gz_node_start(gz_node_t *node, const gz_storage_reader_t *storage,
                          gz_action_list_t *actions_out, int *more);

/* Handle one event. Appends the resulting actions, in the order they must be
 * carried out, to `actions_out`, which the caller has initialised and normally
 * emptied. The event and everything it points to are only read during the
 * call (see event.h).
 *
 * For now: a ping message produces a save of one GZ_RECORD_TEST_PING record
 * followed by a send of the reply to the peer that sent the ping. The
 * confirmation of that batch produces a save of a GZ_RECORD_TEST_PING_SENT
 * record. Every other event produces no actions.
 *
 * Returns GZ_OK; GZ_ERR_ARGUMENT if an argument is NULL; GZ_ERR_NO_SPACE if
 * the actions do not fit or GZ_NODE_MAX_AWAITING batches already await
 * confirmation. On any error `actions_out` and the node are exactly as they
 * were. */
gz_status_t gz_node_handle(gz_node_t *node, const gz_event_t *event,
                           gz_action_list_t *actions_out);

#endif
