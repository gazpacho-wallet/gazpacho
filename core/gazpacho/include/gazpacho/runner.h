/* The runner: the one place that enforces "save before send".
 *
 * A step of the core returns an ordered list of actions. The program around
 * the core gives every such list to its runner, and the runner hands actions
 * to an executor callback, which is the only thing that touches storage, the
 * network, the chain or the user.
 *
 * THE RULE
 *
 *   1. Actions are released to the executor strictly in the order they were
 *      submitted, across lists.
 *   2. A save action is released as soon as it reaches the front. From that
 *      moment its batch is "unconfirmed" until gz_runner_confirm is called
 *      with its identifier.
 *   3. An outward action (send, broadcast, notify) is not released while any
 *      batch is unconfirmed. Because of rule 1, everything behind it waits too.
 *   4. Watch and timer actions do not wait for confirmations themselves, but
 *      never overtake an action ahead of them.
 *
 * So when an outward action reaches the executor, every save submitted before
 * it has been confirmed as stored.
 *
 * SEVERAL SAVES IN ONE LIST
 *
 *   [save A, send X, save B, send Y]: A is released; X waits for A. B is
 *   behind X, so B is not even handed to storage until A is confirmed. Then X
 *   and B are released and Y waits for B.
 *
 *   [save A, save B, send X]: A and B are both released at once (at most
 *   GZ_RUNNER_MAX_UNCONFIRMED batches may be unconfirmed together; a further
 *   save waits at the front until one is confirmed). X waits for both.
 *   Confirmations may arrive in either order.
 *
 * AN EMPTY LIST
 *
 *   Submitting a list with no actions succeeds and releases nothing.
 *
 * A CRASH
 *
 *   The runner keeps nothing durable. If the program stops, the runner and
 *   every action it still held are gone. That is safe because a held action
 *   was never given to the executor: nothing after an unconfirmed save has
 *   left. A new runner starts empty. A confirmation that arrives for a batch
 *   released by a previous runner is reported as GZ_ERR_UNKNOWN_BATCH and
 *   releases nothing. What to send again is decided by the node from what it
 *   finds in storage, not by the runner.
 *
 * WHAT THE EXECUTOR MUST DO
 *
 *   Store save batches in the order received, and report a batch (by calling
 *   gz_runner_confirm) only once it is safely stored. It must not call back
 *   into the runner from inside the callback: confirm from the caller's loop.
 *
 * Memory: the runner queues copies of submitted actions in storage the caller
 * provides at init, so a submitted list may be reset as soon as
 * gz_runner_submit returns. The queue's storage is reclaimed whenever the
 * queue drains completely. While actions are held it only grows, and a list
 * that does not fit is refused whole with GZ_ERR_NO_SPACE. */
#ifndef GAZPACHO_RUNNER_H
#define GAZPACHO_RUNNER_H

#include "gazpacho/action.h"

/* Most save batches that may be awaiting confirmation at once. */
#define GZ_RUNNER_MAX_UNCONFIRMED 8

/* Carries out one action. `action` and everything it points to are valid only
 * for the duration of the call. */
typedef void (*gz_execute_fn)(void *ctx, const gz_action_t *action);

/* Caller-allocated; treat the fields as private. */
typedef struct {
    gz_action_list_t queue;   /* copies of submitted actions, in order */
    size_t head;              /* queue.slots[0..head) have been released */
    uint64_t unconfirmed[GZ_RUNNER_MAX_UNCONFIRMED];
    size_t n_unconfirmed;
    gz_execute_fn execute;
    void *ctx;
} gz_runner_t;

/* Prepare an empty runner that queues into `slots[0..n_slots)` and
 * `bytes[0..n_bytes)` (owned by the caller, valid for the runner's life) and
 * releases actions to `execute(ctx, ...)`.
 * Returns GZ_ERR_ARGUMENT if `runner` or `execute` is NULL. */
gz_status_t gz_runner_init(gz_runner_t *runner, gz_action_t *slots, size_t n_slots,
                           uint8_t *bytes, size_t n_bytes,
                           gz_execute_fn execute, void *ctx);

/* Queue every action of `list`, in order, and release whatever the rule
 * allows. The list is copied and may be reset afterwards.
 * Returns GZ_OK; GZ_ERR_NO_SPACE if the list does not fit in the queue;
 * GZ_ERR_DUPLICATE_BATCH if a save in the list uses the identifier of a batch
 * that is unconfirmed, still queued, or earlier in the same list. On any
 * error nothing from the list is queued or released. */
gz_status_t gz_runner_submit(gz_runner_t *runner, const gz_action_list_t *list);

/* Record that batch `batch_id` is safely stored, and release whatever the rule
 * now allows.
 * Returns GZ_ERR_UNKNOWN_BATCH, and releases nothing, if no released save with
 * that identifier is awaiting confirmation. */
gz_status_t gz_runner_confirm(gz_runner_t *runner, uint64_t batch_id);

/* Number of submitted actions not yet released to the executor. */
size_t gz_runner_held(const gz_runner_t *runner);

/* Number of released save batches not yet confirmed. */
size_t gz_runner_unconfirmed(const gz_runner_t *runner);

#endif
