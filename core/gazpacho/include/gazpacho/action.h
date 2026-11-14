/* Actions: everything the core can ask the outside world to do, and the list
 * that carries them out of one step.
 *
 * The core returns actions in the order they must be carried out. The runner
 * (runner.h) enforces that nothing is sent before the saves ahead of it are
 * stored.
 *
 * Order matters in one more way. Actions other than saves are carried out in
 * the order listed, and a send, broadcast, notify or connect waits until
 * every save listed before it is stored. So A TIMER THAT TIMES OUT A SEND
 * MUST COME AFTER THAT SEND IN THE LIST. Placed after, the timer is set only
 * when the message has actually left. Placed before, it would be set at once
 * while the message still waits for storage, and could fire before the
 * message was ever sent.
 *
 * Memory. An action list uses a caller-provided arena: the caller hands over an
 * array of action slots and a block of bytes, and the list copies every
 * action's payload into that block. This was chosen over an allocator port
 * because it makes the bound visible and fixed before the step runs, needs no
 * free calls (one reset empties the list), cannot leak, and keeps the core free
 * of callbacks into the caller's memory management. A step that needs more
 * than the caller provided fails with GZ_ERR_NO_SPACE and changes nothing.
 *
 * Ownership. The caller owns the slots and the byte block and frees them, if
 * they were allocated at all, after it has finished with the list. Every
 * pointer inside an action in a list points into that list's byte block and is
 * valid until gz_action_list_reset or the end of the block's lifetime. Nobody
 * frees an individual action. */
#ifndef GAZPACHO_ACTION_H
#define GAZPACHO_ACTION_H

#include "gazpacho/types.h"

typedef enum {
    GZ_ACTION_SAVE = 1,     /* store a batch of records atomically */
    GZ_ACTION_SEND,         /* send a factory message on a link */
    GZ_ACTION_BROADCAST,    /* broadcast a transaction */
    GZ_ACTION_WATCH_SCRIPT, /* retired in contract v2: refused */
    GZ_ACTION_SET_TIMER,    /* fire a timer event after a delay */
    GZ_ACTION_CANCEL_TIMER, /* forget a timer */
    GZ_ACTION_NOTIFY,       /* tell the user something */
    GZ_ACTION_WATCH_TX,     /* report a transaction's confirmations, and its leaving the chain */
    GZ_ACTION_WATCH_OUTPOINT, /* report when an outpoint is spent, and by which transaction */
    GZ_ACTION_CONNECT,      /* keep a connection to a host, with one of our keys */
    GZ_ACTION_DISCONNECT,   /* flush, close a link and stop keeping it */
    GZ_ACTION_SET_SEATED    /* host: a member's key holds a seat, or no longer does */
} gz_action_kind_t;

/* WATCHES. A watch asks the chain view to report, through GZ_EVENT_CHAIN
 * events (event.h), until the node's program stops. Watches are not kept
 * across a restart: at start a node sets again every watch it still needs.
 * Setting a watch that is already set (the same txid or outpoint) replaces
 * its depth and reports the current state again. A watch is not outward: it
 * changes nothing anyone else sees, so it does not wait for earlier saves.
 * Broadcasting a transaction does not watch it.
 *
 * A watch cannot be dropped, and setting it again changes only its depth:
 * there is no "unwatch". An engine must ignore reports it no longer needs,
 * and must not treat a report as meaning the watch is still wanted.
 *
 * Every txid here and in event.h is in the byte order the chain hashes it,
 * as gz_outpoint_t says (types.h): not reversed for display. Servers that
 * speak display order (Esplora's API, for one) are converted by the
 * program, never by the core.
 *
 *   WATCH_TX        GZ_CHAIN_TX_CONFIRMED events for transaction `txid`: when
 *                   the watch is set, if the transaction is already in the
 *                   best chain, with its current count (which may exceed
 *                   `depth`); then at each block that brings its count to a
 *                   value from 1 to `depth`. A GZ_CHAIN_TX_UNCONFIRMED event
 *                   when a transaction already reported confirmed leaves the
 *                   best chain in a reorganisation, however deep it was;
 *                   counting starts again when it is confirmed again.
 *   WATCH_OUTPOINT  GZ_CHAIN_OUTPOINT_SPENT events for `outpoint`, each naming
 *                   the spending transaction and its confirmations, 0 while
 *                   it is unconfirmed: when the watch is set, if the outpoint
 *                   is already spent; when a spender is first seen, in the
 *                   mempool or in a block; at each block that brings the
 *                   spender's count to a value from 1 to `depth`; and, with 0
 *                   confirmations, when a spender already reported confirmed
 *                   leaves the best chain. The output's script is not needed.
 *                   If another transaction replaces the spender (a conflict
 *                   that wins in the mempool or in a reorganisation), the
 *                   next event names the new one: an engine compares txids.
 *                   A spender that vanishes with no replacement is not
 *                   reported: no event for it is defined yet.
 *                   So a report with 0 confirmations means either "first
 *                   seen in the mempool" or "a confirmed spender left the
 *                   chain", and a spend seen only in the mempool may vanish
 *                   unreported: an engine must never treat a 0-confirmation
 *                   spend as final (safety-rule.md C4(d) and the Dead state).
 *   WATCH_SCRIPT    retired in contract v2 (section 10): the number stays
 *                   reserved, and gz_action_list_add and the runner refuse it.
 *
 * `depth` is at least 1 for both: the number of confirmations the node waits
 * for (the burial depth, for a funding transaction).
 *
 * CONNECTIONS. A CONNECT stands until a DISCONNECT for its link or the end of
 * the node's program; the program reconnects with the same key while it
 * stands. Connections and seats are not kept across a restart: at start a
 * node applies a saved pause, then issues CONNECT for every link it needs and
 * SET_SEATED for every seat. CONNECT is outward because the handshake shows
 * our key: the save of the key's index pair (messages.md section 2) must come
 * before it in the list, and the runner holds the handshake until that save
 * is confirmed. DISCONNECT is not outward but ordered: what is queued on the
 * link is sent first, so a DISCONNECT listed after a final SEND never loses
 * it. */

/* Why a DISCONNECT closes a link (composite-node.md section 6). It chooses
 * between the transport's warning and a quiet close, and names the cause in
 * the log. */
#define GZ_DISCONNECT_DONE       0  /* stop keeping a connection: the slot is free */
#define GZ_DISCONNECT_REFUSED    1  /* refuse a peer: a BOLT 1 warning, then close */
#define GZ_DISCONNECT_IDLE       2  /* close an idle or unseated connection */
#define GZ_DISCONNECT_HOST_FAULT 3  /* the host broke the protocol */

/* Largest records of one SEND (messages.md section 5: 1 MiB, host to member;
 * the transport splits what is over 65,495 bytes). */
#define GZ_SEND_MAX_RECORDS 1048576u
/* Longest CONNECT address: "host:port", numeric. */
#define GZ_CONNECT_MAX_ADDRESS 64u

/* One stored record: an opaque byte string with a type tag. */
typedef struct {
    uint32_t type;
    gz_bytes_t bytes;
} gz_record_t;

typedef struct {
    gz_action_kind_t kind;
    union {
        /* SAVE: all records are stored or none. `batch` is not chosen by the
         * node: whatever it holds when the list is submitted is ignored, and
         * the runner writes the identifier it issues before the executor sees
         * the action. The same identifier comes back in the
         * GZ_EVENT_STORAGE_CONFIRMED event once the batch is safely stored.
         * A batch with no records is still a batch: it is stored, confirmed
         * and waited for like any other. */
        struct { gz_batch_id_t batch; const gz_record_t *records; size_t n_records; } save;
        /* SEND: one factory message (messages.md sections 3 to 5). `records`
         * is the TLV stream; the program adds the protocol tag, and the
         * transport splits it when it is over 65,495 bytes (host to member
         * only; a member message over 65,495 bytes is fatal for the
         * incarnation, contract-v2.md section 1). */
        struct { gz_link_t link; uint16_t kind; uint8_t scope[32]; gz_bytes_t records; } send;
        /* BROADCAST: outward. Its outcome comes back as a
         * GZ_CHAIN_BROADCAST_RESULT event, which is advice (event.h).
         * Broadcasting a transaction does not watch it. */
        struct { gz_bytes_t tx; } broadcast;
        struct { uint8_t txid[32]; uint32_t depth; } watch_tx;      /* WATCH_TX; txid in hashing order */
        struct { gz_outpoint_t outpoint; uint32_t depth; } watch_outpoint; /* WATCH_OUTPOINT */
        /* SET_TIMER: setting an identifier that is already set replaces it. */
        struct { uint64_t timer_id; uint64_t delay_ms; } set_timer;
        struct { uint64_t timer_id; } cancel_timer;                /* CANCEL_TIMER */
        /* NOTIFY: outward. `bytes` is a TLV stream framed by `code`
         * (command.h; contract-v2.md section 11): a view object, a command's
         * outcome, or a log line. A view object follows, in its list, the
         * save of the state it shows (node.h rule 8). */
        struct { uint32_t code; gz_bytes_t bytes; } notify;
        /* CONNECT: outward. `address` is "host:port", numeric (transport.md:
         * no name lookup), at most 64 bytes. Our key is the per-lobby key
         * (key_epoch, key_index) of contract-v2.md section 13; the program
         * reconnects with that same key while the action stands. */
        struct { gz_node_id_t host; gz_bytes_t address; uint32_t key_epoch; uint32_t key_index; } connect;
        /* DISCONNECT: what is queued on the link is sent, then it is closed;
         * a PEER_DISCONNECTED follows. `why` is a GZ_DISCONNECT_* value. */
        struct { gz_link_t link; uint16_t why; } disconnect;
        /* SET_SEATED: a property of the member's key, kept by the transport
         * across its connections; set again at every start. 0 or 1. */
        struct { gz_node_id_t member; int seated; } set_seated;
    } u;
} gz_action_t;

/* An ordered list of actions in caller-provided storage. Treat the fields as
 * read-only: `slots[0..count)` are the actions, in order. */
typedef struct {
    gz_action_t *slots;
    size_t n_slots;
    size_t count;
    uint8_t *bytes;
    size_t n_bytes;
    size_t used;
} gz_action_list_t;

/* Make `list` an empty list over `slots[0..n_slots)` and `bytes[0..n_bytes)`.
 * Both stay owned by the caller and must outlive the list's use. */
void gz_action_list_init(gz_action_list_t *list, gz_action_t *slots, size_t n_slots,
                         uint8_t *bytes, size_t n_bytes);

/* Empty the list. Every pointer previously handed out by it becomes invalid. */
void gz_action_list_reset(gz_action_list_t *list);

/* Append a deep copy of `action`: its records and byte strings are copied into
 * the list's byte block, so `action` and everything it points to may be
 * discarded as soon as this returns.
 * Returns GZ_OK; GZ_ERR_ARGUMENT for an unknown or retired kind
 * (WATCH_SCRIPT), a byte string with a length but no data, a transaction or
 * outpoint watch of depth 0, a SEND of kind 0 or 2 or with records over
 * GZ_SEND_MAX_RECORDS, a CONNECT with an empty address or one over
 * GZ_CONNECT_MAX_ADDRESS, a DISCONNECT whose `why` is not a GZ_DISCONNECT_*
 * value, or a SET_SEATED whose `seated` is not 0 or 1; GZ_ERR_NO_SPACE if a
 * slot or the bytes do not fit. On any error the list is exactly as it was. */
gz_status_t gz_action_list_add(gz_action_list_t *list, const gz_action_t *action);

/* Merge every SAVE among slots[from..to) into one SAVE at the position of
 * the first of them, keeping the records in their order; the other actions
 * keep their order (composite-node.md section 7.4: moving a save earlier only
 * makes the sends after it wait longer). With fewer than two saves nothing
 * changes. The merged record array is placed in the list's byte block, which
 * needs at most GZ_ACTION_MERGE_BYTES(total records) free. Returns GZ_OK;
 * GZ_ERR_ARGUMENT if the range is not within the list; GZ_ERR_NO_SPACE if the
 * merged array does not fit. On any error the list is exactly as it was. */
gz_status_t gz_action_list_merge_saves(gz_action_list_t *list, size_t from, size_t to);

/* The most bytes gz_action_list_merge_saves needs for `n` records in all. */
#define GZ_ACTION_MERGE_BYTES(n) ((size_t)(n) * sizeof(gz_record_t) + _Alignof(gz_record_t))

/* 1 if the action is visible outside this party once carried out and so must
 * wait for earlier saves: send, broadcast, notify, connect. 0 otherwise. */
int gz_action_is_outward(const gz_action_t *action);

#endif
