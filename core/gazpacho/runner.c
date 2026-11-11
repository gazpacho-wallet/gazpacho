#include "gazpacho/runner.h"
#include <string.h>

gz_status_t gz_runner_init(gz_runner_t *runner, gz_runner_slot_t *slots, size_t n_slots,
                           uint8_t *bytes, size_t n_bytes, uint64_t incarnation,
                           gz_execute_fn execute, void *ctx)
{
    if (!runner || !execute) return GZ_ERR_ARGUMENT;
    runner->slots = slots;
    runner->n_slots = n_slots;
    runner->head = runner->count = 0;
    runner->bytes = bytes;
    runner->n_bytes = n_bytes;
    runner->bytes_head = runner->bytes_tail = 0;
    runner->incarnation = incarnation;
    runner->issued = runner->confirmed = 0;
    runner->failed = runner->busy = 0;
    runner->execute = execute;
    runner->ctx = ctx;
    return GZ_OK;
}

/* The one byte string a queued action carries, or NULL for the timer kinds. */
static gz_bytes_t *payload_of(gz_action_t *action)
{
    switch (action->kind) {
    case GZ_ACTION_SEND:      return &action->u.send.bytes;
    case GZ_ACTION_BROADCAST: return &action->u.broadcast.tx;
    case GZ_ACTION_WATCH:     return &action->u.watch.script;
    case GZ_ACTION_NOTIFY:    return &action->u.notify.bytes;
    default:                  return NULL;
    }
}

static size_t payload_len(const gz_action_t *action)
{
    gz_action_t copy = *action;
    const gz_bytes_t *p = payload_of(&copy);
    return p ? p->len : 0;
}

static gz_runner_slot_t *slot_at(gz_runner_t *runner, size_t i)
{
    return &runner->slots[(runner->head + i) % runner->n_slots];
}

/* Slide the held payloads down to the start of the byte block, so the space
 * freed by released actions can be used again. */
static void compact(gz_runner_t *runner)
{
    size_t shift = runner->bytes_head;
    if (shift == 0) return;
    memmove(runner->bytes, runner->bytes + shift, runner->bytes_tail - shift);
    for (size_t i = 0; i < runner->count; i++) {
        gz_runner_slot_t *slot = slot_at(runner, i);
        gz_bytes_t *p = payload_of(&slot->action);
        slot->bytes_off -= shift;
        if (p && p->len) p->data = runner->bytes + slot->bytes_off;
    }
    runner->bytes_tail -= shift;
    runner->bytes_head = 0;
}

/* Copy a non-save action to the back of the queue. The caller has checked
 * that a slot and the bytes are free. */
static void enqueue(gz_runner_t *runner, const gz_action_t *action)
{
    size_t len = payload_len(action);
    if (runner->n_bytes - runner->bytes_tail < len) compact(runner);
    gz_runner_slot_t *slot = slot_at(runner, runner->count);
    slot->action = *action;
    slot->needs = runner->issued;
    slot->bytes_off = runner->bytes_tail;
    gz_bytes_t *p = payload_of(&slot->action);
    if (p && len) {
        memcpy(runner->bytes + runner->bytes_tail, p->data, len);
        p->data = runner->bytes + runner->bytes_tail;
    } else if (p) {
        p->data = NULL;
    }
    runner->bytes_tail += len;
    runner->count++;
}

/* Release from the front of the queue for as long as the rule allows. */
static void release_ready(gz_runner_t *runner)
{
    while (runner->count > 0) {
        gz_runner_slot_t *slot = slot_at(runner, 0);
        if (gz_action_is_outward(&slot->action) && slot->needs > runner->confirmed) return;
        /* Take it out of the queue first, so the executor sees a consistent
         * runner. Its bytes stay in place until something else is queued,
         * which cannot happen during the call. */
        runner->head = (runner->head + 1) % runner->n_slots;
        runner->count--;
        if (runner->count > 0) runner->bytes_head = slot_at(runner, 0)->bytes_off;
        else runner->bytes_head = runner->bytes_tail = 0;
        runner->execute(runner->ctx, &slot->action);
    }
}

/* 1 if the whole list can be accepted now. */
static int fits(const gz_runner_t *runner, const gz_action_list_t *list)
{
    size_t saves = 0, others = 0, bytes = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (list->slots[i].kind == GZ_ACTION_SAVE) { saves++; continue; }
        others++;
        bytes += payload_len(&list->slots[i]);
    }
    return saves <= GZ_RUNNER_MAX_UNCONFIRMED - (runner->issued - runner->confirmed) &&
           others <= runner->n_slots - runner->count &&
           bytes <= runner->n_bytes - (runner->bytes_tail - runner->bytes_head);
}

/* Hand a save to the executor under the next batch identifier. */
static void release_save(gz_runner_t *runner, const gz_action_t *action)
{
    gz_action_t save = *action;
    save.u.save.batch.incarnation = runner->incarnation;
    save.u.save.batch.sequence = ++runner->issued;
    runner->execute(runner->ctx, &save);
}

gz_status_t gz_runner_submit(gz_runner_t *runner, const gz_action_list_t *list)
{
    if (!runner || !list) return GZ_ERR_ARGUMENT;
    if (runner->busy) return GZ_ERR_REENTRANT;
    if (runner->failed) return GZ_ERR_FAILED;
    if (!fits(runner, list)) {
        runner->failed = 1;
        return GZ_ERR_REFUSED;
    }
    runner->busy = 1;
    for (size_t i = 0; i < list->count; i++) {
        if (list->slots[i].kind == GZ_ACTION_SAVE) {
            release_save(runner, &list->slots[i]);
        } else {
            enqueue(runner, &list->slots[i]);
            release_ready(runner);
        }
    }
    runner->busy = 0;
    return GZ_OK;
}

gz_status_t gz_runner_confirm(gz_runner_t *runner, gz_batch_id_t batch)
{
    if (!runner) return GZ_ERR_ARGUMENT;
    if (runner->busy) return GZ_ERR_REENTRANT;
    if (runner->failed) return GZ_ERR_FAILED;
    if (batch.incarnation < runner->incarnation) return GZ_ERR_STALE_BATCH;
    if (batch.incarnation > runner->incarnation || batch.sequence == 0 ||
        batch.sequence > runner->issued || batch.sequence <= runner->confirmed)
        return GZ_ERR_UNKNOWN_BATCH;
    if (batch.sequence != runner->confirmed + 1) return GZ_ERR_OUT_OF_ORDER;
    runner->confirmed++;
    runner->busy = 1;
    release_ready(runner);
    runner->busy = 0;
    return GZ_OK;
}

gz_status_t gz_runner_storage_failed(gz_runner_t *runner)
{
    if (!runner) return GZ_ERR_ARGUMENT;
    if (runner->busy) return GZ_ERR_REENTRANT;
    runner->failed = 1;
    return GZ_OK;
}

int gz_runner_failed(const gz_runner_t *runner) { return runner->failed; }
size_t gz_runner_held(const gz_runner_t *runner) { return runner->count; }
size_t gz_runner_unconfirmed(const gz_runner_t *runner) { return (size_t)(runner->issued - runner->confirmed); }
