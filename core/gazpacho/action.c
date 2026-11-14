#include "gazpacho/action.h"
#include <string.h>

void gz_action_list_init(gz_action_list_t *list, gz_action_t *slots, size_t n_slots,
                         uint8_t *bytes, size_t n_bytes)
{
    list->slots = slots;
    list->n_slots = n_slots;
    list->bytes = bytes;
    list->n_bytes = n_bytes;
    gz_action_list_reset(list);
}

void gz_action_list_reset(gz_action_list_t *list)
{
    list->count = 0;
    list->used = 0;
}

int gz_action_is_outward(const gz_action_t *action)
{
    return action->kind == GZ_ACTION_SEND || action->kind == GZ_ACTION_BROADCAST ||
           action->kind == GZ_ACTION_NOTIFY || action->kind == GZ_ACTION_CONNECT;
}

/* Reserve `len` bytes aligned to `align` (a power of two) in the list's block.
 * Returns NULL if they do not fit. */
static uint8_t *reserve(gz_action_list_t *list, size_t len, size_t align)
{
    uintptr_t base = (uintptr_t)list->bytes;
    size_t start = (size_t)((((base + list->used) + (align - 1)) & ~(uintptr_t)(align - 1)) - base);
    if (start > list->n_bytes || len > list->n_bytes - start) return NULL;
    list->used = start + len;
    return list->bytes + start;
}

/* Copy a byte string into the list's block and point `dst` at the copy. */
static gz_status_t copy_bytes(gz_action_list_t *list, gz_bytes_t *dst, gz_bytes_t src)
{
    dst->data = NULL;
    dst->len = 0;
    if (src.len == 0) return GZ_OK;
    if (!src.data) return GZ_ERR_ARGUMENT;
    uint8_t *copy = reserve(list, src.len, 1);
    if (!copy) return GZ_ERR_NO_SPACE;
    memcpy(copy, src.data, src.len);
    dst->data = copy;
    dst->len = src.len;
    return GZ_OK;
}

/* Copy a save action's record array and every record's bytes. */
static gz_status_t copy_save(gz_action_list_t *list, gz_action_t *dst, const gz_action_t *src)
{
    size_t n = src->u.save.n_records;
    dst->u.save.records = NULL;
    if (n == 0) return GZ_OK;
    if (!src->u.save.records) return GZ_ERR_ARGUMENT;
    if (n > list->n_bytes / sizeof(gz_record_t)) return GZ_ERR_NO_SPACE;
    gz_record_t *records = (gz_record_t *)(void *)reserve(list, n * sizeof(gz_record_t),
                                                          _Alignof(gz_record_t));
    if (!records) return GZ_ERR_NO_SPACE;
    for (size_t i = 0; i < n; i++) {
        records[i].type = src->u.save.records[i].type;
        gz_status_t st = copy_bytes(list, &records[i].bytes, src->u.save.records[i].bytes);
        if (st != GZ_OK) return st;
    }
    dst->u.save.records = records;
    return GZ_OK;
}

static gz_status_t copy_send(gz_action_list_t *list, gz_action_t *dst, const gz_action_t *src)
{
    uint16_t kind = src->u.send.kind;
    if (kind == 0 || kind == 2 || src->u.send.records.len > GZ_SEND_MAX_RECORDS) return GZ_ERR_ARGUMENT;
    return copy_bytes(list, &dst->u.send.records, src->u.send.records);
}

static gz_status_t copy_connect(gz_action_list_t *list, gz_action_t *dst, const gz_action_t *src)
{
    size_t n = src->u.connect.address.len;
    if (n == 0 || n > GZ_CONNECT_MAX_ADDRESS) return GZ_ERR_ARGUMENT;
    return copy_bytes(list, &dst->u.connect.address, src->u.connect.address);
}

/* Copy whatever the action points to; fields held by value were copied already. */
static gz_status_t copy_payload(gz_action_list_t *list, gz_action_t *dst, const gz_action_t *src)
{
    switch (src->kind) {
    case GZ_ACTION_SAVE:         return copy_save(list, dst, src);
    case GZ_ACTION_SEND:         return copy_send(list, dst, src);
    case GZ_ACTION_BROADCAST:    return copy_bytes(list, &dst->u.broadcast.tx, src->u.broadcast.tx);
    case GZ_ACTION_WATCH_SCRIPT: return GZ_ERR_ARGUMENT; /* retired (contract v2, section 10) */
    case GZ_ACTION_WATCH_TX:     return src->u.watch_tx.depth ? GZ_OK : GZ_ERR_ARGUMENT;
    case GZ_ACTION_WATCH_OUTPOINT: return src->u.watch_outpoint.depth ? GZ_OK : GZ_ERR_ARGUMENT;
    case GZ_ACTION_NOTIFY:       return copy_bytes(list, &dst->u.notify.bytes, src->u.notify.bytes);
    case GZ_ACTION_CONNECT:      return copy_connect(list, dst, src);
    case GZ_ACTION_DISCONNECT:   return src->u.disconnect.why <= GZ_DISCONNECT_HOST_FAULT ? GZ_OK : GZ_ERR_ARGUMENT;
    case GZ_ACTION_SET_SEATED:   return src->u.set_seated.seated == 0 || src->u.set_seated.seated == 1
                                        ? GZ_OK : GZ_ERR_ARGUMENT;
    case GZ_ACTION_SET_TIMER:
    case GZ_ACTION_CANCEL_TIMER: return GZ_OK;
    }
    return GZ_ERR_ARGUMENT;
}

gz_status_t gz_action_list_add(gz_action_list_t *list, const gz_action_t *action)
{
    if (!list || !action) return GZ_ERR_ARGUMENT;
    if (list->count >= list->n_slots) return GZ_ERR_NO_SPACE;
    size_t used_before = list->used;
    gz_action_t *dst = &list->slots[list->count];
    *dst = *action;
    gz_status_t st = copy_payload(list, dst, action);
    if (st != GZ_OK) {
        list->used = used_before;
        return st;
    }
    list->count++;
    return GZ_OK;
}

gz_status_t gz_action_list_merge_saves(gz_action_list_t *list, size_t from, size_t to)
{
    size_t first = to, n_saves = 0, n_records = 0, i, k, at;
    if (!list || from > to || to > list->count) return GZ_ERR_ARGUMENT;
    for (i = from; i < to; i++) {
        if (list->slots[i].kind != GZ_ACTION_SAVE) continue;
        if (n_saves++ == 0) first = i;
        n_records += list->slots[i].u.save.n_records;
    }
    if (n_saves < 2) return GZ_OK;
    gz_record_t *merged = NULL;
    if (n_records > 0) {
        if (n_records > list->n_bytes / sizeof(gz_record_t)) return GZ_ERR_NO_SPACE;
        merged = (gz_record_t *)(void *)reserve(list, n_records * sizeof(gz_record_t), _Alignof(gz_record_t));
        if (!merged) return GZ_ERR_NO_SPACE; /* reserve changed nothing */
    }
    /* Gather the records in order, then drop every save after the first. The
     * records' bytes stay where they are in the block. */
    k = 0;
    for (i = first; i < to; i++) {
        const gz_action_t *a = &list->slots[i];
        if (a->kind != GZ_ACTION_SAVE) continue;
        for (size_t r = 0; r < a->u.save.n_records; r++) merged[k++] = a->u.save.records[r];
    }
    list->slots[first].u.save.records = merged;
    list->slots[first].u.save.n_records = n_records;
    at = first + 1;
    for (i = first + 1; i < list->count; i++) {
        if (i < to && list->slots[i].kind == GZ_ACTION_SAVE) continue;
        list->slots[at++] = list->slots[i];
    }
    list->count = at;
    return GZ_OK;
}
