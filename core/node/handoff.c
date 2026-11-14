/* Engine calls, brackets and merges, confirmations (composite-node.md 7.4,
 * 7.5 and 9.6).
 *
 * EVERY ENGINE CALL goes through call() below. It refuses to enter an engine
 * whose own call is still running (U1: no engine is entered from its own
 * hook), claims the actions the engine appended (so the composite knows each
 * action's engine), and in test builds holds the engine to its declared worst
 * step.
 *
 * A BRACKET is one top-level engine call made by the composite, with every
 * hand-off it makes through a hook and every hand-off deferred until the
 * engine it targets has returned. When the bracket closes, postprocess():
 *   - rewrites the timer ids of each engine (timers.c) and refuses an id at
 *     or above 2^32 (GZ_ERR_BUG);
 *   - refuses a BROADCAST from any engine but funding (GZ_ERR_BUG);
 *   - keeps the watch registry and drops repeated watches (watches.c);
 *   - notes the seats a slot's engine marks (SET_SEATED);
 *   - with a hand-off: in test builds, checks that no outward action sat
 *     between two of the bracket's saves (an engine that sends before it
 *     saves, which the merge would hide), then merges every SAVE of the
 *     bracket into one at the first one's position; without a hand-off,
 *     merges adjacent saves only;
 *   - queues, per SAVE returned, the mask of engines whose records it holds,
 *     so each confirmation reaches exactly them.
 * Why moving a save earlier is safe: a send waits for every save before it;
 * moving a later save ahead of a send only makes that send wait longer, and
 * no save depends on a send having been released (contract v2 forbids saving
 * "sent"). Timers, watches, DISCONNECT and SET_SEATED after the merged save
 * are only delayed. */
#include "internal.h"
#include <string.h>

enum { OP_HANDLE, OP_RESUME, OP_TAKE };

uint16_t gz_c_area(const gz_node_t *c, int eng)
{
    (void)c;
    if (eng == ENG_NODE) return (uint16_t)GZ_AREA_NODE;
#ifdef GZ_TEST_KINDS
    if (eng == ENG_TEST0 || eng == ENG_TEST1) return c->test[eng - ENG_TEST0].area;
    if (eng >= ENG_SLOT0 && eng < ENG_N) return (uint16_t)GZ_AREA_TEST_SLOT;
#endif
    return (uint16_t)GZ_AREA_NODE;
}

/* Note a bug in engine `eng`: the area is reported (gz_node_error_area). */
gz_status_t gz_c_bug(gz_node_t *c, int eng)
{
    if (!c->err_area) c->err_area = gz_c_area(c, eng);
    return GZ_ERR_BUG;
}

static const gz_engine_ops_t *ops_of(const gz_node_t *c, int eng, void **inst)
{
    (void)c;
    (void)eng;
    *inst = NULL;
#ifdef GZ_TEST_KINDS
    if (eng == ENG_TEST0 || eng == ENG_TEST1) {
        *inst = (void *)&((gz_node_t *)c)->test[eng - ENG_TEST0];
        return gz_te_ops();
    }
    if (eng >= ENG_SLOT0 && eng < ENG_N) {
        *inst = (void *)&((gz_node_t *)c)->slots[eng - ENG_SLOT0].ts;
        return gz_ts_ops();
    }
#endif
    return NULL;
}

/* The engine index of an area among the node-wide engines, or -1. */
static int eng_of_area(const gz_node_t *c, uint16_t area)
{
    (void)c;
    (void)area;
#ifdef GZ_TEST_KINDS
    for (int i = 0; i < c->n_test; i++)
        if (c->test[i].area == area) return ENG_TEST0 + i;
#endif
    return -1;
}

/* One engine call. */
static gz_status_t call(gz_node_t *c, int eng, int op, const gz_event_t *ev, uint64_t tag,
                        gz_action_list_t *out, int *more)
{
    void *inst;
    const gz_engine_ops_t *ops = ops_of(c, eng, &inst);
    size_t start = out->count, used0 = out->used, outer_nested = c->nested_bytes;
    gz_status_t st;
    if (!ops) return gz_c_bug(c, ENG_NODE);
    if (c->busy[eng]) return gz_c_bug(c, eng); /* U1: entered while its own call runs */
    c->busy[eng] = 1;
    c->nested_bytes = 0;
    switch (op) {
    case OP_HANDLE: st = ops->handle(inst, ev, out); break;
    case OP_RESUME: st = ops->resume(inst, out, more); break;
#ifdef GZ_TEST_KINDS
    case OP_TAKE: st = (eng == ENG_TEST0 || eng == ENG_TEST1) ? te_take_handoff(inst, tag, out) : GZ_ERR_BUG; break;
#endif
    default: st = GZ_ERR_BUG; break;
    }
    (void)tag;
    c->busy[eng] = 0;
    if (st != GZ_OK && st != GZ_WAITING) {
        if (!c->err_area) c->err_area = gz_c_area(c, eng);
        return st;
    }
    /* Claim what it appended that a nested call has not claimed. */
    size_t own = 0;
    for (size_t i = start; i < out->count; i++) {
        size_t k = i - c->base;
        if (k >= GZ_NODE_LIST_ACTIONS) return gz_c_bug(c, eng); /* past the sized list */
        if (c->owner[k] < 0) {
            c->owner[k] = (int8_t)eng;
            own++;
        }
    }
    size_t delta = out->used - used0, own_bytes = delta - c->nested_bytes;
    c->nested_bytes = outer_nested + delta;
#if GZ_NODE_CHECKS
    /* 8.3: every step within the engine's declared worst step. */
    if (own > ops->max_step_actions || own_bytes > ops->max_step_bytes) return gz_c_bug(c, eng);
#else
    (void)own;
    (void)own_bytes;
#endif
    return st;
}

/* Run the hand-offs deferred until their target returned (U1), still inside
 * the bracket. Each may defer more; the queue is small and fixed. */
static gz_status_t run_deferred(gz_node_t *c, gz_action_list_t *out)
{
    while (c->n_deferred > 0) {
        deferred_t d = c->deferred[0];
        memmove(&c->deferred[0], &c->deferred[1], (size_t)(c->n_deferred - 1) * sizeof c->deferred[0]);
        c->n_deferred--;
        gz_status_t st = call(c, d.to, OP_TAKE, NULL, d.tag, out, NULL);
        if (st != GZ_OK) return st;
    }
    return GZ_OK;
}

static gz_status_t bracket_end(gz_node_t *c, gz_action_list_t *out)
{
    gz_status_t st = run_deferred(c, out);
    if (st == GZ_OK) st = gz_c_postprocess(c, c->bracket_from, c->bracket_handoff, out);
    c->bracket_on = 0;
    return st;
}

gz_status_t gz_c_call(gz_node_t *c, int eng, const gz_event_t *ev, gz_action_list_t *out)
{
    return call(c, eng, OP_HANDLE, ev, 0, out, NULL);
}

/* A top-level call of engine `eng`: one bracket. */
gz_status_t gz_c_bracket(gz_node_t *c, int eng, const gz_event_t *ev, gz_action_list_t *out)
{
    if (c->bracket_on) return gz_c_bug(c, ENG_NODE);
    c->bracket_on = 1;
    c->bracket_handoff = 0;
    c->bracket_top = eng;
    c->bracket_from = out->count;
    c->n_deferred = 0;
    gz_status_t st = call(c, eng, OP_HANDLE, ev, 0, out, NULL);
    if (st != GZ_OK) {
        c->bracket_on = 0;
        return st;
    }
    return bracket_end(c, out);
}

/* An engine's resume step, in a bracket of its own. */
gz_status_t gz_c_resume(gz_node_t *c, int eng, gz_action_list_t *out, int *more);
gz_status_t gz_c_resume(gz_node_t *c, int eng, gz_action_list_t *out, int *more)
{
    if (c->bracket_on) return gz_c_bug(c, ENG_NODE);
    c->bracket_on = 1;
    c->bracket_handoff = 0;
    c->bracket_top = eng;
    c->bracket_from = out->count;
    c->n_deferred = 0;
    gz_status_t st = call(c, eng, OP_RESUME, NULL, 0, out, more);
    if (st != GZ_OK) {
        c->bracket_on = 0;
        return st;
    }
    return bracket_end(c, out);
}

/* The node part's own actions: a bracket whose engine is the node part. Its
 * actions are claimed by postprocess (unclaimed actions go to the bracket's
 * top engine). */
gz_status_t gz_c_node_bracket_begin(gz_node_t *c, gz_action_list_t *out)
{
    if (c->bracket_on) return gz_c_bug(c, ENG_NODE);
    c->bracket_on = 1;
    c->bracket_handoff = 0;
    c->bracket_top = ENG_NODE;
    c->bracket_from = out->count;
    c->n_deferred = 0;
    return GZ_OK;
}

gz_status_t gz_c_node_bracket_end(gz_node_t *c, gz_action_list_t *out)
{
    return bracket_end(c, out);
}

/* A slot engine's call made by the node part inside the node part's bracket
 * (opening a slot, a seat): its actions are its own, with its generation. */
gz_status_t gz_c_slot_inline(gz_node_t *c, int eng, gz_status_t (*fn)(gz_node_t *, int, gz_action_list_t *),
                             gz_action_list_t *out);
gz_status_t gz_c_slot_inline(gz_node_t *c, int eng, gz_status_t (*fn)(gz_node_t *, int, gz_action_list_t *),
                             gz_action_list_t *out)
{
    size_t start = out->count;
    if (c->busy[eng]) return gz_c_bug(c, eng);
    c->busy[eng] = 1;
    gz_status_t st = fn(c, eng, out);
    c->busy[eng] = 0;
    if (st != GZ_OK) {
        if (!c->err_area) c->err_area = gz_c_area(c, eng);
        return st;
    }
    for (size_t i = start; i < out->count; i++) {
        size_t k = i - c->base;
        if (k >= GZ_NODE_LIST_ACTIONS) return gz_c_bug(c, eng);
        if (c->owner[k] < 0) c->owner[k] = (int8_t)eng;
    }
    return GZ_OK;
}

/* The hooks given to an engine for a hand-off (9.1: engines never call each
 * other). Inside a bracket only. */
static gz_status_t handoff(gz_node_t *c, uint16_t from, uint16_t to, uint64_t tag, gz_action_list_t *out,
                           int may_defer)
{
    int target = eng_of_area(c, to), source = eng_of_area(c, from);
    if (target < 0 || source < 0 || !c->bracket_on) return gz_c_bug(c, source < 0 ? ENG_NODE : source);
    c->bracket_handoff = 1;
    if (may_defer && c->busy[target]) {
        if (c->n_deferred == MAX_DEFERRED) return gz_c_bug(c, source);
        c->deferred[c->n_deferred].from = source;
        c->deferred[c->n_deferred].to = target;
        c->deferred[c->n_deferred].tag = tag;
        c->n_deferred++;
        return GZ_OK;
    }
    return call(c, target, OP_TAKE, NULL, tag, out, NULL);
}

gz_status_t gz_c_handoff(void *ctx, uint16_t from, uint16_t to, uint64_t tag, gz_action_list_t *out)
{
    return handoff(ctx, from, to, tag, out, 1);
}

gz_status_t gz_c_handoff_now(void *ctx, uint16_t from, uint16_t to, uint64_t tag, gz_action_list_t *out)
{
    return handoff(ctx, from, to, tag, out, 0);
}

/* ---- after a bracket ---------------------------------------------------- */

static void drop_action(gz_node_t *c, gz_action_list_t *out, size_t i)
{
    size_t k = i - c->base;
    memmove(&out->slots[i], &out->slots[i + 1], (out->count - i - 1) * sizeof out->slots[0]);
    memmove(&c->owner[k], &c->owner[k + 1], (out->count - i - 1) * sizeof c->owner[0]);
    out->count--;
    c->owner[out->count - c->base] = -1;
}

static uint16_t gen_of(const gz_node_t *c, int eng)
{
    if (eng >= ENG_SLOT0 && eng < ENG_N) return c->slots[eng - ENG_SLOT0].gen;
    return 0;
}

static gz_status_t push_mask(gz_node_t *c, uint16_t mask)
{
    if (c->cq_n == CQ_MAX) return gz_c_bug(c, ENG_NODE); /* the runner holds at most 32 */
    c->cq[(c->cq_head + c->cq_n++) % CQ_MAX] = mask;
    return GZ_OK;
}

static int seat_note(slot_t *s, const gz_node_id_t *member, int seated)
{
    size_t i;
    for (i = 0; i < s->n_seated; i++)
        if (np_same_key(&s->seated[i], member)) break;
    if (seated) {
        if (i < s->n_seated) return 1;
        if (s->n_seated == SLOT_MAX_SEATS) return 0;
        s->seated[s->n_seated++] = *member;
        return 1;
    }
    if (i < s->n_seated) s->seated[i] = s->seated[--s->n_seated];
    return 1;
}

gz_status_t gz_c_postprocess(gz_node_t *c, size_t from, int merge_all, gz_action_list_t *out)
{
    size_t i;
    gz_status_t st;
    for (i = from; i < out->count; i++) {
        size_t k = i - c->base;
        if (k >= GZ_NODE_LIST_ACTIONS) return gz_c_bug(c, ENG_NODE);
        if (c->owner[k] < 0) c->owner[k] = (int8_t)c->bracket_top;
    }
    for (i = from; i < out->count;) {
        gz_action_t *a = &out->slots[i];
        int eng = c->owner[i - c->base];
        if (a->kind == GZ_ACTION_SET_TIMER || a->kind == GZ_ACTION_CANCEL_TIMER) {
            uint64_t *id = a->kind == GZ_ACTION_SET_TIMER ? &a->u.set_timer.timer_id : &a->u.cancel_timer.timer_id;
            if (*id > TIMER_ID_MAX) {
                /* Only the composite's own cancels of a freed slot come packed. */
                if (eng != ENG_NODE) return gz_c_bug(c, eng);
            } else {
                *id = gz_timer_pack(gz_c_area(c, eng), gen_of(c, eng), (uint32_t)*id);
                if (eng >= ENG_SLOT0 && !gz_timer_track(&c->slots[eng - ENG_SLOT0], *id,
                                                         a->kind == GZ_ACTION_SET_TIMER))
                    return gz_c_bug(c, eng); /* over its timer budget (7.1) */
            }
        } else if (a->kind == GZ_ACTION_BROADCAST) {
            if (gz_c_area(c, eng) != GZ_AREA_FUNDING) return gz_c_bug(c, eng); /* 14.2, A11 */
        } else if (a->kind == GZ_ACTION_WATCH_TX || a->kind == GZ_ACTION_WATCH_OUTPOINT) {
            int keep = gz_watch_note(c, a, eng);
            if (keep < 0) return gz_c_bug(c, eng);
            if (!keep) {
                drop_action(c, out, i);
                continue;
            }
        } else if (a->kind == GZ_ACTION_SET_SEATED && eng >= ENG_SLOT0) {
            if (!seat_note(&c->slots[eng - ENG_SLOT0], &a->u.set_seated.member, a->u.set_seated.seated))
                return gz_c_bug(c, eng);
        }
        i++;
    }
    if (merge_all) {
        size_t first = out->count, last = 0, n = 0;
        uint16_t mask = 0;
        for (i = from; i < out->count; i++) {
            if (out->slots[i].kind != GZ_ACTION_SAVE) continue;
            if (n++ == 0) first = i;
            last = i;
            mask |= (uint16_t)(1u << c->owner[i - c->base]);
        }
#if GZ_NODE_CHECKS
        /* 7.4: no outward action between two saves of one bracket. */
        for (i = first + 1; n > 1 && i < last; i++)
            if (gz_action_is_outward(&out->slots[i])) return gz_c_bug(c, c->owner[i - c->base]);
#endif
        if (n > 1) {
            size_t before = out->count;
            st = gz_action_list_merge_saves(out, from, out->count);
            if (st != GZ_OK) return st == GZ_ERR_NO_SPACE ? gz_c_bug(c, ENG_NODE) : st;
            /* The merged save sits at `first`. The owners of this bracket's
             * range are not read again; the freed tail is unclaimed. */
            for (i = out->count; i < before; i++) c->owner[i - c->base] = -1;
        }
        if (n > 0 && (st = push_mask(c, mask)) != GZ_OK) return st;
        (void)first;
        (void)last;
        return GZ_OK;
    }
    for (i = from; i < out->count; i++) {
        if (out->slots[i].kind != GZ_ACTION_SAVE) continue;
        size_t j = i;
        uint16_t mask = 0;
        while (j < out->count && out->slots[j].kind == GZ_ACTION_SAVE) {
            mask |= (uint16_t)(1u << c->owner[j - c->base]);
            j++;
        }
        if (j - i > 1) {
            st = gz_action_list_merge_saves(out, i, j);
            if (st != GZ_OK) return st == GZ_ERR_NO_SPACE ? gz_c_bug(c, ENG_NODE) : st;
            /* Keep the owner array in step with the list for the actions after. */
            size_t gone = j - i - 1, k;
            memmove(&c->owner[i + 1 - c->base], &c->owner[j - c->base],
                    (out->count + gone - j) * sizeof c->owner[0]);
            for (k = out->count; k < out->count + gone; k++) c->owner[k - c->base] = -1;
        }
        if ((st = push_mask(c, mask)) != GZ_OK) return st;
    }
    return GZ_OK;
}

/* ---- confirmations (7.5) ------------------------------------------------ */

void gz_c_confirmed(gz_node_t *c, gz_action_list_t *out, gz_status_t *result)
{
    gz_event_t ev;
    uint16_t mask;
    *result = GZ_OK;
    if (c->cq_n == 0) {
        *result = np_drop(c, DROP_CONFIRM, 0, out);
        return;
    }
    mask = c->cq[c->cq_head];
    c->cq_head = (c->cq_head + 1) % CQ_MAX;
    c->cq_n--;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_STORAGE_CONFIRMED;
    for (int e = ENG_TEST0; e < ENG_N; e++) {
        void *inst;
        if (!(mask & (1u << e)) || !ops_of(c, e, &inst)) continue;
        /* During the start, held for an engine not yet resumed (R4). */
        if (!c->resumed[e]) {
            c->held[e]++;
            continue;
        }
        *result = gz_c_bracket(c, e, &ev, out);
        if (*result != GZ_OK) return;
    }
}

/* Give an engine the confirmations held for it during the start. */
gz_status_t gz_c_release_held(gz_node_t *c, int eng, gz_action_list_t *out);
gz_status_t gz_c_release_held(gz_node_t *c, int eng, gz_action_list_t *out)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_STORAGE_CONFIRMED;
    while (c->held[eng] > 0) {
        c->held[eng]--;
        gz_status_t st = gz_c_bracket(c, eng, &ev, out);
        if (st != GZ_OK) return st;
    }
    return GZ_OK;
}
