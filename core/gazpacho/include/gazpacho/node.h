/* The node: the object that receives every event and returns the actions.
 *
 * The node is the composite of docs/notes/composite-node.md: one interface,
 * gz_node_start and gz_node_handle, in front of the engines. This header is
 * the contract; the library core/node (gazpacho_node) implements it. The
 * engines are named by their journal area (Lobby 0x0001, Round 0x0002,
 * Funding 0x0003, Node 0x0004, Local API 0x000d, Test 0x7e57 and 0x7e58);
 * the same number tags an engine's records, timers and commands. In this
 * step (P4.1) the only engine is the test engine, the old placeholder ping,
 * built only into test builds (gazpacho_node_test); the release library has
 * the node part alone.
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
 *      (With rule 6, most of it is sent again when the peer asks.)
 *   2. Therefore accept that every message it sends may arrive twice, and may
 *      arrive after newer traffic. Every engine message must be safe to
 *      receive twice and out of order with what came later. A message for
 *      which that cannot be made true must not be designed.
 *   3. Store, as records, the acknowledgements that matter. Anything not in
 *      storage is not known after a restart, and will be sent again. An
 *      acknowledgement is a message from the peer, saved when it arrives.
 *      That the runner released a send, or that storage confirmed the batch
 *      it followed, says only that the program has the message: the program
 *      drops a send to a peer that is not connected, and a stop loses
 *      whatever it had not written to a socket. The program never lets a
 *      connection outlive a lost message (contract-v2.md section 1), so every
 *      loss is followed by a PEER_DISCONNECTED and, when the peer is back, a
 *      PEER_CONNECTED. No engine may save "sent" for anything it must
 *      deliver.
 *   4. Set its timers and register its watches again: the program around the
 *      core forgets them when it stops. Likewise CONNECT for every link it
 *      needs and SET_SEATED for every seat, after applying a saved pause.
 *   5. With the restore marker (ports.h), save the restore batch (key_epoch,
 *      restored, guard) first, alone, before anything else. The node part
 *      does this for every engine.
 *   6. At GZ_EVENT_PEER_CONNECTED for a link, carry out the protocol's
 *      reconnect step for that link (messages.md section 6: the member asks
 *      with `hello`, resends its saved partial signatures and asks for the
 *      round's status; the host answers and pushes nothing). Keep the
 *      protocol's rate limits per link, not per connection. Resend a stored
 *      state message only when the peer's answer shows it lacks that state.
 *   7. Emit, at start, a NOTIFY for every view object it has
 *      (contract-v2.md section 11): the program forgets the view when it
 *      stops.
 *   8. Put a view NOTIFY after the save of the state it shows, in the same
 *      list, and a command's outcome after the save of its `request_id`
 *      record, where there is one.
 *
 *   ADDRESSING. An engine addresses what it resends after a restart to a
 *   link it derives from keys it has stored: a member to (its seat's key,
 *   the host's key), a host to (its key, the seat's contribution key). Never
 *   to a connection, and never to a key it has not stored.
 *
 * THE ENGINE RULE (composite-node.md section 8.1)
 *
 *   An engine returns an error only for a bug, or for exhausted fixed memory
 *   that its own caps should have prevented. A condition that a peer, the
 *   chain, the wallet port, the key port or a user command can cause is
 *   never an error. It returns GZ_OK with one of: a refusal (DISCONNECT
 *   `refused`, or a refusing message such as `round_abort`); an outcome; a
 *   counted drop; a notice (a view object, an attention item, a command
 *   result). The composite holds every engine to it, and to the rules it can
 *   check (timer ids below 2^32, BROADCAST from the funding engine only, the
 *   bracket and re-entry checks of test builds): a breach is GZ_ERR_BUG.
 *
 * ERRORS (composite-node.md section 8.2)
 *
 *   On any error other than GZ_WAITING, the node must not be used again; the
 *   program starts a new one from storage. The list is as it was before the
 *   call: nothing of the failed step is submitted. The node is not: it
 *   poisons itself, and every later call returns GZ_ERR_FAILED.
 *   gz_node_error_area names the engine whose step failed. Two errors leave
 *   the node usable, because they are found before anything is touched:
 *   GZ_ERR_ARGUMENT for a NULL argument, and GZ_ERR_NO_SPACE for a list with
 *   less free room than GZ_NODE_LIST_ACTIONS actions and GZ_NODE_LIST_BYTES
 *   bytes.
 *
 * SIZING (composite-node.md section 8.3)
 *
 *   Each engine declares its worst step, in actions and bytes, and changes
 *   the state of at most one slot or one round per event. One node call
 *   appends at most the sum over the engines one event can reach, with the
 *   composite's own actions and the room a bracket's merge needs: the two
 *   constants below, held to that sum by a static assertion in core/node. A
 *   test build also checks every engine step against its declaration. The
 *   program gives lists of this size and sizes its runner to hold one. */
#ifndef GAZPACHO_NODE_H
#define GAZPACHO_NODE_H

#include "gazpacho/action.h"
#include "gazpacho/event.h"
#include "gazpacho/ports.h"

/* The list one node call may fill, at most (see SIZING). */
#define GZ_NODE_LIST_ACTIONS 192
#define GZ_NODE_LIST_BYTES   (256u * 1024u)

/* Timers the node may have set at once: the program's table holds this many.
 * core/node keeps the engines' budgets within it by a static assertion. */
#define GZ_NODE_MAX_TIMERS 64

/* Lobbies at once per wallet, each in its own slot (owner decision), and
 * ended lobbies whose rounds are still held (composite-node.md 2.4). */
#define GZ_NODE_MAX_SLOTS 8
#define GZ_NODE_MAX_TOMBSTONES 64

/* Journal areas: an engine's records, timers and commands are tagged with it. */
#define GZ_AREA_LOBBY     0x0001u
#define GZ_AREA_ROUND     0x0002u
#define GZ_AREA_FUNDING   0x0003u
#define GZ_AREA_NODE      0x0004u
#define GZ_AREA_API       0x000du
#define GZ_AREA_TEST      0x7e57u
#define GZ_AREA_TEST2     0x7e58u
#define GZ_AREA_TEST_SLOT 0x7e59u   /* test builds: the stand-in for a slot's lobby */
#define GZ_AREA_RESERVED  0xffffu   /* never an engine: the program's own test timers */

/* The node part's records (journal.md section 9, Node area). Fields are TLV
 * streams; the numbers here are P4.1's, to be registered with the code
 * tables (journal.md open point 3) by P4.2:
 *   key_epoch  2: epoch (u32)
 *   restored   2: clock (u64), 4: the incarnation of the newest batch the
 *              restored journal holds (u64)
 *   guard      2: counter (u64), 4: per epoch, epoch and highest index
 *              (u32, u32), 6: rounds started (u64) */
#define GZ_RECORD_KEY_EPOCH 0x00040002u
#define GZ_RECORD_KEY_INDEX 0x00040004u
#define GZ_RECORD_RESTORED  0x00040006u
#define GZ_RECORD_GUARD     0x0004000au

typedef enum { GZ_HOST_FUNDING_AUTO = 0, GZ_HOST_FUNDING_CONFIRM } gz_host_funding_t;
typedef enum {
    GZ_MEMBER_SIGNING_AT_JOIN = 0,   /* the default (owner): unlock once at join */
    GZ_MEMBER_SIGNING_AUTO,
    GZ_MEMBER_SIGNING_WHEN_UNLOCKED
} gz_member_signing_t;

typedef struct {
    int host;                          /* 1: host, 0: member; fixed per data folder */
    uint8_t chain[32];                 /* the chain's genesis hash, as storage names it: it
                                          opens every guard record (journal.md 8.3) */
    const void *secp;                  /* a secp256k1_context with a non-aborting illegal
                                          callback; unused until the signing engine (P4.3) */
    gz_key_port_t keys;                /* per-lobby keys and the host key */
    gz_host_funding_t host_funding;    /* composite-node.md 12.1; AUTO by default */
    gz_member_signing_t member_signing;/* composite-node.md 12.2; AT_JOIN by default */
    uint32_t test_engines;             /* test builds only: 0, 1 or 2 test engines */
} gz_node_config_t;

/* Opaque, caller-allocated: gz_node_size() bytes, aligned for any object
 * (malloc, or a static max_align_t array). Holds no pointers of its own
 * besides the ports' and the key port's context pointers, so it needs no
 * destroy call. */
typedef struct gz_node gz_node_t;
size_t gz_node_size(void);

/* Prepare a node. `ports` and `cfg` are copied. `incarnation` is the one its
 * runner was given (runner.h).
 * Returns GZ_ERR_ARGUMENT if an argument or a port function is NULL, or a
 * test-engine count other than 0 to 2 (0 in a release build). */
gz_status_t gz_node_init(gz_node_t *node, const gz_ports_t *ports, const gz_node_config_t *cfg,
                         uint64_t incarnation);

/* Start, or start again after a stop or a crash. What a start has to do can
 * exceed one action list, so it is done in steps:
 *
 *     do {
 *         empty the list;
 *         st = gz_node_start(node, storage, list, &more);
 *         if (st == GZ_WAITING) {                       // nothing appended
 *             wait for storage to confirm a batch, and give the node that
 *             confirmation (GZ_EVENT_STORAGE_CONFIRMED, through gz_node_handle);
 *             continue;
 *         }
 *         if (st != GZ_OK) stop: the start failed;
 *         give the list to the runner;                  // must be accepted
 *     } while (more);
 *
 * The start has two phases (composite-node.md section 10). The first call
 * takes the fence and walks storage once, giving each record, in journal
 * order, to the engines that read its area (no actions). Then each call
 * resumes engines in a fixed order (the restore batch, the node part, the
 * test engines, the view) until one of them appends something: a call
 * either appends actions and returns GZ_OK with `*more` set, or appends
 * nothing and returns GZ_WAITING, or appends nothing and returns GZ_OK with
 * `*more` 0 when the start is complete.
 *
 * While a node starts, the only events it may be given are the storage
 * confirmations its runner accepts, between steps. Every other event waits
 * until a call has set `*more` to 0. A start that returns an error other than
 * GZ_WAITING, or whose list the runner refuses, is fatal.
 *
 * Storage may change between steps only by gaining the batches the node's own
 * runner hands over. Whatever an earlier program left pending is settled,
 * durable or gone for good, before the first call (the fence, ports.h). The
 * first call remembers the last batch of an earlier incarnation; a call that
 * finds a later one returns GZ_ERR_CORRUPT.
 *
 * `storage` reads back what storage holds (ports.h). It is used only during
 * the call, and may be walked more than once.
 *
 * When `storage->restored` is 1, the first actions of the start are the node
 * part's restore batch (key_epoch, restored, guard), alone in its list, so
 * the runner issues it as sequence 1 and holds everything outward behind its
 * confirmation.
 *
 * Returns GZ_OK; GZ_WAITING as above; GZ_ERR_ARGUMENT if an argument or a
 * reader function is NULL; GZ_ERR_CORRUPT if storage is not a journal
 * (identifiers not strictly increasing, or one from an incarnation later than
 * `storage->incarnation`), broke the fence, or holds a record of an area no
 * engine reads; GZ_ERR_FAILED once the node is poisoned. */
gz_status_t gz_node_start(gz_node_t *node, const gz_storage_reader_t *storage,
                          gz_action_list_t *actions_out, int *more);

/* Handle one event. Appends the resulting actions, in the order they must be
 * carried out, to `actions_out`, which the caller has initialised and normally
 * emptied. The event and everything it points to are only read during the
 * call (see event.h). Returns GZ_OK, or an error as ERRORS above says. */
gz_status_t gz_node_handle(gz_node_t *node, const gz_event_t *event,
                           gz_action_list_t *actions_out);

/* After an error: the area of the engine whose step failed (GZ_AREA_NODE for
 * the composite itself), and the status it returned; 0 and GZ_OK before any
 * error. For the program's `node-error engine=0x0002 status=...` line. */
uint16_t gz_node_error_area(const gz_node_t *node);
gz_status_t gz_node_error_status(const gz_node_t *node);

#endif
