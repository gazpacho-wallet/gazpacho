/* Timer ids (composite-node.md section 7.1).
 *
 * An engine sets timers with its own ids, each below 2^32. After each engine
 * call the composite rewrites them: the engine's area in the top 16 bits, the
 * slot's generation in the next 16 (0 for node-wide engines), the engine's id
 * in the low 32. On TIMER_FIRED it decodes the id and gives the low 32 bits
 * to that engine and slot; an id whose generation is not in use is dropped.
 * When a slot is freed the composite cancels every id it rewrote for that
 * slot and has not seen fire or cancelled, so a later lobby never gets an
 * earlier lobby's timer, even within one incarnation. Area 0xffff is never an
 * engine's: the program's test timers live there.
 *
 * The program's table holds GZ_NODE_MAX_TIMERS timers. The budget: the lobby
 * 6 per slot, the node part 2, signing 1, funding 1, the local API 2, each
 * test engine 4. Raising GZ_NODE_MAX_SLOTS costs 6 timers a slot. */
#include "internal.h"

#define BUDGET_SIGNING 1
#define BUDGET_FUNDING 1
#define BUDGET_API     2
_Static_assert(TS_MAX_TIMERS == 6, "a slot's engine has the lobby's six timers");
_Static_assert(GZ_NODE_MAX_SLOTS * TS_MAX_TIMERS + NP_MAX_TIMERS + BUDGET_SIGNING + BUDGET_FUNDING +
                       BUDGET_API + 2 * TE_MAX_TIMERS <= GZ_NODE_MAX_TIMERS,
               "the engines' timers must fit the program's table (7.1, R8)");
_Static_assert(SLOT_MAX_TIMERS >= TS_MAX_TIMERS, "a slot tracks every timer its engine may set");

uint64_t gz_timer_pack(uint16_t area, uint16_t gen, uint32_t id)
{
    return (uint64_t)area << 48 | (uint64_t)gen << 32 | id;
}

void gz_timer_unpack(uint64_t packed, uint16_t *area, uint16_t *gen, uint32_t *id)
{
    *area = (uint16_t)(packed >> 48);
    *gen = (uint16_t)(packed >> 32);
    *id = (uint32_t)packed;
}

/* Note a slot timer set (set = 1) or cancelled or fired (set = 0). 0 if a set
 * would pass the slot's table: the engine broke its budget. */
int gz_timer_track(slot_t *s, uint64_t packed, int set)
{
    size_t i;
    for (i = 0; i < s->n_timers; i++)
        if (s->timers[i] == packed) break;
    if (set) {
        if (i < s->n_timers) return 1; /* setting a set timer replaces it */
        if (s->n_timers == SLOT_MAX_TIMERS) return 0;
        s->timers[s->n_timers++] = packed;
        return 1;
    }
    if (i < s->n_timers) s->timers[i] = s->timers[--s->n_timers];
    return 1;
}

/* Append a CANCEL_TIMER for every timer of the slot still set. */
gz_status_t gz_timer_cancel_slot(slot_t *s, gz_action_list_t *out)
{
    while (s->n_timers > 0) {
        gz_action_t a = {.kind = GZ_ACTION_CANCEL_TIMER};
        a.u.cancel_timer.timer_id = s->timers[s->n_timers - 1];
        gz_status_t st = gz_action_list_add(out, &a);
        if (st != GZ_OK) return st;
        s->n_timers--;
    }
    return GZ_OK;
}

/* Which engine a fired timer is for, and its own id. 0 if none: an area no
 * engine has, or a generation not in use. */
int gz_timer_route(const gz_node_t *c, uint64_t packed, int *eng, uint32_t *id)
{
    uint16_t area, gen;
    gz_timer_unpack(packed, &area, &gen, id);
    if (area == GZ_AREA_RESERVED) return 0;
    if (gen == 0) {
        if (area == GZ_AREA_NODE) {
            *eng = ENG_NODE;
            return 1;
        }
#ifdef GZ_TEST_KINDS
        for (int i = 0; i < c->n_test; i++)
            if (c->test[i].area == area) {
                *eng = ENG_TEST0 + i;
                return 1;
            }
#endif
        return 0;
    }
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) {
        const slot_t *s = &c->slots[i];
        if (s->state != SLOT_OPEN || s->gen != gen || gz_c_area(c, ENG_SLOT0 + i) != area) continue;
        *eng = ENG_SLOT0 + i;
        return 1;
    }
    return 0;
}
