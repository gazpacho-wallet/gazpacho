#include "gazpacho/runner.h"

gz_status_t gz_runner_init(gz_runner_t *runner, gz_action_t *slots, size_t n_slots,
                           uint8_t *bytes, size_t n_bytes,
                           gz_execute_fn execute, void *ctx)
{
    if (!runner || !execute) return GZ_ERR_ARGUMENT;
    gz_action_list_init(&runner->queue, slots, n_slots, bytes, n_bytes);
    runner->head = 0;
    runner->n_unconfirmed = 0;
    runner->execute = execute;
    runner->ctx = ctx;
    return GZ_OK;
}

/* 1 if the action at the front of the queue may be released now. */
static int may_release(const gz_runner_t *runner, const gz_action_t *action)
{
    if (gz_action_is_outward(action)) return runner->n_unconfirmed == 0;
    if (action->kind == GZ_ACTION_SAVE) return runner->n_unconfirmed < GZ_RUNNER_MAX_UNCONFIRMED;
    return 1;
}

/* Release from the front of the queue for as long as the rule allows. */
static void release_ready(gz_runner_t *runner)
{
    while (runner->head < runner->queue.count) {
        const gz_action_t *action = &runner->queue.slots[runner->head];
        if (!may_release(runner, action)) return;
        if (action->kind == GZ_ACTION_SAVE)
            runner->unconfirmed[runner->n_unconfirmed++] = action->u.save.batch_id;
        runner->head++;
        runner->execute(runner->ctx, action);
    }
    gz_action_list_reset(&runner->queue);   /* drained: reclaim the queue's storage */
    runner->head = 0;
}

/* 1 if `batch_id` is unconfirmed or belongs to a save still in the queue. */
static int batch_in_play(const gz_runner_t *runner, uint64_t batch_id)
{
    for (size_t i = 0; i < runner->n_unconfirmed; i++)
        if (runner->unconfirmed[i] == batch_id) return 1;
    for (size_t i = runner->head; i < runner->queue.count; i++) {
        const gz_action_t *queued = &runner->queue.slots[i];
        if (queued->kind == GZ_ACTION_SAVE && queued->u.save.batch_id == batch_id) return 1;
    }
    return 0;
}

gz_status_t gz_runner_submit(gz_runner_t *runner, const gz_action_list_t *list)
{
    if (!runner || !list) return GZ_ERR_ARGUMENT;
    size_t count_before = runner->queue.count, used_before = runner->queue.used;
    gz_status_t st = GZ_OK;
    for (size_t i = 0; i < list->count && st == GZ_OK; i++) {
        const gz_action_t *action = &list->slots[i];
        /* Appended saves are in the queue already, so this also catches a
         * repeat within the list itself. */
        if (action->kind == GZ_ACTION_SAVE && batch_in_play(runner, action->u.save.batch_id))
            st = GZ_ERR_DUPLICATE_BATCH;
        else
            st = gz_action_list_add(&runner->queue, action);
    }
    if (st != GZ_OK) {
        runner->queue.count = count_before;
        runner->queue.used = used_before;
        return st;
    }
    release_ready(runner);
    return GZ_OK;
}

gz_status_t gz_runner_confirm(gz_runner_t *runner, uint64_t batch_id)
{
    if (!runner) return GZ_ERR_ARGUMENT;
    size_t i = 0;
    while (i < runner->n_unconfirmed && runner->unconfirmed[i] != batch_id) i++;
    if (i == runner->n_unconfirmed) return GZ_ERR_UNKNOWN_BATCH;
    for (; i + 1 < runner->n_unconfirmed; i++)
        runner->unconfirmed[i] = runner->unconfirmed[i + 1];
    runner->n_unconfirmed--;
    release_ready(runner);
    return GZ_OK;
}

size_t gz_runner_held(const gz_runner_t *runner)
{
    return runner->queue.count - runner->head;
}

size_t gz_runner_unconfirmed(const gz_runner_t *runner)
{
    return runner->n_unconfirmed;
}
