/* The runner: the one place that enforces "save before send".
 *
 * A step of the core returns an ordered list of actions. The program around
 * the core gives every such list to its runner, and the runner hands actions
 * to an executor callback, which is the only thing that touches storage, the
 * network, the chain or the user.
 *
 * THE RULE
 *
 *   1. A save is handed to the executor at once, when its list is submitted,
 *      in submission order. Saves never wait for anything.
 *   2. An outward action (send, broadcast, notify) is released only when every
 *      save submitted before it has been confirmed as stored.
 *   3. Actions other than saves are released in the order submitted. A watch
 *      or timer does not wait for confirmations itself, but never overtakes
 *      an action ahead of it (see the timer convention in action.h).
 *
 *   Example: [save A, send X, save B, send Y]. A and B go to storage at once.
 *   X is released when A is confirmed; Y when B is.
 *
 * STORAGE IS A JOURNAL
 *
 *   The executor must make batches durable in the order it receives them, and
 *   confirmations must arrive in that order. gz_runner_confirm for any batch
 *   but the oldest unconfirmed one is an error and changes nothing.
 *
 * BATCH IDENTIFIERS
 *
 *   The runner issues them: (incarnation, sequence), sequence counting from 1.
 *   The node does not choose them. They are never reused, provided the
 *   surrounding program does its duty:
 *
 *     THE INCARNATION PASSED TO gz_runner_init MUST BE STRICTLY GREATER THAN
 *     ANY PASSED BEFORE FOR THIS NODE'S STORAGE, AND MUST ITSELF BE DURABLE
 *     BEFORE THE RUNNER IS USED (for example a counter in the journal's
 *     header, incremented and synced at every start).
 *
 *   A confirmation carrying an older incarnation belongs to a batch issued
 *   before a restart. It is reported as GZ_ERR_STALE_BATCH and never releases
 *   anything.
 *
 * WHEN A LIST CANNOT BE ACCEPTED
 *
 *   gz_runner_submit refuses a list whole (GZ_ERR_REFUSED) if its saves would
 *   take the number of unconfirmed batches above GZ_RUNNER_MAX_UNCONFIRMED, or
 *   if its other actions do not fit in the free part of the queue. THIS IS
 *   FATAL FOR THE NODE. The node's in-memory state has already advanced past
 *   the step whose actions were refused, so carrying on would act on decisions
 *   that were never saved. The program must stop the node and start it again
 *   from storage (gz_node_start). To make that hard to ignore the runner
 *   enters the failed state.
 *
 * WHEN STORAGE FAILS
 *
 *   The program calls gz_runner_storage_failed. The runner enters the failed
 *   state.
 *
 * THE FAILED STATE
 *
 *   Nothing is ever released again. Every later submit or confirm returns
 *   GZ_ERR_FAILED. The only way on is a new runner with a new incarnation.
 *
 * A CRASH
 *
 *   The runner keeps nothing durable. If the program stops, the runner and
 *   every action it still held are gone. That is safe because a held action
 *   was never given to the executor. A batch that was handed to storage may
 *   or may not have become durable; the restarted node finds out from storage.
 *
 * AN EMPTY LIST succeeds and releases nothing. A SAVE WITH NO RECORDS is a
 * batch like any other.
 *
 * WHAT THE PROGRAM AROUND THE RUNNER MUST DO
 *
 *   - Store batches in the order received; call gz_runner_confirm only once a
 *     batch is safely stored, and in that order.
 *   - Give the node its GZ_EVENT_STORAGE_CONFIRMED event only for a
 *     confirmation the runner accepted (GZ_OK).
 *   - Not call the runner from inside the executor callback. Such a call
 *     returns GZ_ERR_REENTRANT and does nothing.
 *
 * Memory: saves are passed straight through and are never queued. Other
 * actions are copied into the slots and bytes the caller provides at init, so
 * a submitted list may be reset as soon as gz_runner_submit returns. Space is
 * reused as actions are released: a list is refused only if what is held at
 * that moment plus the list exceeds the storage, wherever in the storage the
 * held actions happen to sit. */
#ifndef GAZPACHO_RUNNER_H
#define GAZPACHO_RUNNER_H

#include "gazpacho/action.h"

/* Most save batches that may be awaiting confirmation at once. */
#define GZ_RUNNER_MAX_UNCONFIRMED 32

/* Carries out one action. `action` and everything it points to are valid only
 * for the duration of the call. For a save, `action->u.save.batch` is the
 * identifier the runner issued. */
typedef void (*gz_execute_fn)(void *ctx, const gz_action_t *action);

/* One queued action. Caller-allocated as an array; contents private. */
typedef struct {
    gz_action_t action;
    uint64_t needs;       /* sequence of the last save submitted before it */
    size_t bytes_off;     /* where its payload starts in the runner's bytes */
} gz_runner_slot_t;

/* Caller-allocated; treat the fields as private and use the functions below. */
typedef struct {
    gz_runner_slot_t *slots;    /* ring of held actions */
    size_t n_slots, head, count;
    uint8_t *bytes;             /* payloads of held actions, oldest first */
    size_t n_bytes, bytes_head, bytes_tail;
    uint64_t incarnation;
    uint64_t issued;            /* sequence of the newest batch handed to storage */
    uint64_t confirmed;         /* sequence of the newest batch confirmed */
    int failed;
    int busy;                   /* inside submit or confirm: guards re-entry */
    gz_execute_fn execute;
    void *ctx;
} gz_runner_t;

/* Prepare an empty runner that queues into `slots[0..n_slots)` and
 * `bytes[0..n_bytes)` (owned by the caller, valid for the runner's life),
 * issues batch identifiers under `incarnation` (see the duty above) and
 * releases actions to `execute(ctx, ...)`.
 * Returns GZ_OK, or GZ_ERR_ARGUMENT if `runner` or `execute` is NULL. */
gz_status_t gz_runner_init(gz_runner_t *runner, gz_runner_slot_t *slots, size_t n_slots,
                           uint8_t *bytes, size_t n_bytes, uint64_t incarnation,
                           gz_execute_fn execute, void *ctx);

/* Take every action of `list`, in order: saves go to the executor at once,
 * other actions are queued and released as the rule allows. The list is
 * copied where needed and may be reset afterwards.
 * Returns:
 *   GZ_OK             accepted;
 *   GZ_ERR_ARGUMENT   `runner` or `list` is NULL; nothing happened;
 *   GZ_ERR_REENTRANT  called from inside the executor; nothing happened;
 *   GZ_ERR_FAILED     the runner had already failed; nothing happened;
 *   GZ_ERR_REFUSED    the list does not fit (see above). Nothing from it was
 *                     executed or queued, the runner is now failed, and the
 *                     node must be restarted from storage. */
gz_status_t gz_runner_submit(gz_runner_t *runner, const gz_action_list_t *list);

/* Record that `batch` is safely stored, and release whatever the rule now
 * allows.
 * Returns:
 *   GZ_OK                 accepted;
 *   GZ_ERR_ARGUMENT       `runner` is NULL;
 *   GZ_ERR_REENTRANT      called from inside the executor;
 *   GZ_ERR_FAILED         the runner has failed;
 *   GZ_ERR_STALE_BATCH    `batch` has an older incarnation: ignored;
 *   GZ_ERR_UNKNOWN_BATCH  `batch` was never issued by this runner, or is
 *                         already confirmed;
 *   GZ_ERR_OUT_OF_ORDER   `batch` is unconfirmed but not the oldest.
 * On anything but GZ_OK nothing is released and nothing changes. */
gz_status_t gz_runner_confirm(gz_runner_t *runner, gz_batch_id_t batch);

/* Record that storage has failed. The runner enters the failed state.
 * Returns GZ_OK, GZ_ERR_ARGUMENT for NULL, or GZ_ERR_REENTRANT. */
gz_status_t gz_runner_storage_failed(gz_runner_t *runner);

/* 1 if the runner is in the failed state. */
int gz_runner_failed(const gz_runner_t *runner);

/* Number of submitted actions not yet released to the executor. May be called
 * from inside the executor: the action being executed is no longer counted. */
size_t gz_runner_held(const gz_runner_t *runner);

/* Number of save batches handed to the executor and not yet confirmed. */
size_t gz_runner_unconfirmed(const gz_runner_t *runner);

#endif
