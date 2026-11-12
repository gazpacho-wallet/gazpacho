/* Actions: everything the core can ask the outside world to do, and the list
 * that carries them out of one step.
 *
 * The core returns actions in the order they must be carried out. The runner
 * (runner.h) enforces that nothing is sent before the saves ahead of it are
 * stored.
 *
 * Order matters in one more way. Actions other than saves are carried out in
 * the order listed, and a send, broadcast or notify waits until every save
 * listed before it is stored. So A TIMER THAT TIMES OUT A SEND MUST COME AFTER
 * THAT SEND IN THE LIST. Placed after, the timer is set only when the message
 * has actually left. Placed before, it would be set at once while the message
 * still waits for storage, and could fire before the message was ever sent.
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
    GZ_ACTION_SEND,         /* send a message to a peer */
    GZ_ACTION_BROADCAST,    /* broadcast a transaction */
    GZ_ACTION_WATCH,        /* report when an output paying this script is spent */
    GZ_ACTION_SET_TIMER,    /* fire a timer event after a delay */
    GZ_ACTION_CANCEL_TIMER, /* forget a timer */
    GZ_ACTION_NOTIFY        /* tell the user something */
} gz_action_kind_t;

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
        struct { uint64_t peer_id; gz_bytes_t bytes; } send;       /* SEND */
        struct { gz_bytes_t tx; } broadcast;                       /* BROADCAST */
        struct { gz_bytes_t script; } watch;                       /* WATCH */
        /* SET_TIMER: setting an identifier that is already set replaces it. */
        struct { uint64_t timer_id; uint64_t delay_ms; } set_timer;
        struct { uint64_t timer_id; } cancel_timer;                /* CANCEL_TIMER */
        struct { uint32_t code; gz_bytes_t bytes; } notify;        /* NOTIFY */
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
 * Returns GZ_OK; GZ_ERR_ARGUMENT for an unknown kind or a byte string with a
 * length but no data; GZ_ERR_NO_SPACE if a slot or the bytes do not fit. On
 * any error the list is exactly as it was. */
gz_status_t gz_action_list_add(gz_action_list_t *list, const gz_action_t *action);

/* 1 if the action is visible outside this party once carried out and so must
 * wait for earlier saves: send, broadcast, notify. 0 otherwise. */
int gz_action_is_outward(const gz_action_t *action);

#endif
