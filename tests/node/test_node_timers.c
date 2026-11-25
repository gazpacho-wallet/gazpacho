/* Timer ids (composite-node.md 7.1): packing with area and slot generation,
 * a freed slot's timers cancelled, a stale generation dropped, generations
 * never reused while in use, and an id at or above 2^32 refused (a bug). */
#include "node_test.h"
#include "internal.h"

static void scope_of(uint8_t s[32], uint8_t b)
{
    memset(s, b, 32);
}

static void open_slot(h_t *h, uint8_t b, uint32_t timer_ms)
{
    uint8_t s[32], role = 1, ms[4];
    scope_of(s, b);
    gz_put_u32(ms, timer_ms);
    h_arg_t a[3] = {{12, s, 32}, {14, &role, 1}, {20, ms, 4}};
    h_cmd(h, GZ_TE_CMD_SLOT_OPEN, a, 3);
}

static void close_slot(h_t *h, uint8_t b)
{
    uint8_t s[32];
    scope_of(s, b);
    h_arg_t a[1] = {{12, s, 32}};
    h_cmd(h, GZ_TE_CMD_SLOT_CLOSE, a, 1);
}

static void test_pack(void)
{
    uint16_t area, gen;
    uint32_t id;
    uint64_t p = gz_timer_pack(0x0001, 0x00ab, 0x4c000001u);
    CHECK(p == UINT64_C(0x000100ab4c000001));
    gz_timer_unpack(p, &area, &gen, &id);
    CHECK(area == 1 && gen == 0xab && id == 0x4c000001u);
    gz_timer_unpack(gz_timer_pack(0xffff, 0xffff, 0xffffffffu), &area, &gen, &id);
    CHECK(area == 0xffff && gen == 0xffff && id == 0xffffffffu);
}

/* Test 5: a slot's timer, the slot closed and another opened: the first
 * timer never fires into the second. */
static void test_generations(void)
{
    h_t h;
    h_init(&h, 1, 1);
    h_start(&h);
    size_t m = h_mark(&h);
    open_slot(&h, 1, 10000);
    uint64_t t1 = h_last_timer(&h, m);
    CHECK(t1 == ((uint64_t)GZ_AREA_TEST_SLOT << 48 | (uint64_t)1 << 32 | 0x4c000001u));
    m = h_mark(&h);
    close_slot(&h, 1);
    CHECK(h_count(&h, m, GZ_ACTION_CANCEL_TIMER) == 1 && h.log[m].timer == t1);
    m = h_mark(&h);
    open_slot(&h, 1, 10000); /* the same scope again: a new generation */
    uint64_t t2 = h_last_timer(&h, m);
    CHECK(t2 != t1 && (uint16_t)(t2 >> 32) == 2);
    /* The old id, had the program fired it anyway: dropped, not given to the new slot. */
    m = h_mark(&h);
    CHECK(h_timer(&h, t1) == GZ_OK);
    CHECK(h_said(&h, m, "drop why=timer") && !h_said(&h, m, "slot-timer"));
    m = h_mark(&h);
    h_timer(&h, t2);
    CHECK(h_said(&h, m, "slot-timer gen=2 id=1275068417"));
    /* Fired: no longer outstanding, so closing cancels nothing. */
    m = h_mark(&h);
    close_slot(&h, 1);
    CHECK(h_count(&h, m, GZ_ACTION_CANCEL_TIMER) == 0);
    /* Unknown areas, the reserved area, a generation never used: dropped. */
    m = h_mark(&h);
    h_timer(&h, gz_timer_pack(0x0005, 0, 1));
    h_timer(&h, gz_timer_pack(0xffff, 0, 1));
    h_timer(&h, gz_timer_pack(GZ_AREA_TEST_SLOT, 77, 1));
    h_timer(&h, gz_timer_pack(GZ_AREA_TEST, 3, 1));
    CHECK(h.n->np.drops[DROP_TIMER] == 5);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* Generation reuse: a serial whose low 16 bits are in use, or 0, is skipped. */
static void test_generation_reuse(void)
{
    h_t h;
    h_init(&h, 1, 1);
    h_start(&h);
    open_slot(&h, 1, 1000); /* serial 1, generation 1, kept open */
    h.n->slot_serial = 0xffff; /* the next serials: 0x10000 (gen 0), 0x10001 (gen 1, in use), 0x10002 */
    size_t m = h_mark(&h);
    open_slot(&h, 2, 1000);
    uint64_t t = h_last_timer(&h, m);
    CHECK((uint16_t)(t >> 32) == 2);
    CHECK(h.n->slot_serial == 0x10002);
    /* Each slot's timer fires into its own slot. */
    m = h_mark(&h);
    h_timer(&h, t);
    CHECK(h_said(&h, m, "slot-timer gen=2"));
    m = h_mark(&h);
    h_timer(&h, gz_timer_pack(GZ_AREA_TEST_SLOT, 1, 0x4c000001u));
    CHECK(h_said(&h, m, "slot-timer gen=1"));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* An engine's id at or above 2^32 is a bug: fatal, the list rolled back. */
static void test_big_id(void)
{
    h_t h;
    h_init(&h, 1, 1);
    h_start(&h);
    CHECK(h_cmd(&h, GZ_TE_CMD_BIG_TIMER, NULL, 0) == GZ_ERR_BUG);
    CHECK(h.list.count == 0 && gz_node_error_area(h.n) == GZ_AREA_TEST);
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_TIMER_FIRED;
    CHECK(gz_node_handle(h.n, &ev, &h.list) == GZ_ERR_FAILED);
    h_free(&h);
}

/* A slot's engine tracked within its budget; the node part's timers carry area 4. */
static void test_tracking(void)
{
    slot_t s;
    memset(&s, 0, sizeof s);
    for (uint32_t i = 0; i < SLOT_MAX_TIMERS; i++) CHECK(gz_timer_track(&s, gz_timer_pack(1, 1, i), 1));
    CHECK(gz_timer_track(&s, gz_timer_pack(1, 1, 0), 1)); /* set again: replaces */
    CHECK(!gz_timer_track(&s, gz_timer_pack(1, 1, 99), 1)); /* over the table */
    CHECK(gz_timer_track(&s, gz_timer_pack(1, 1, 3), 0) && s.n_timers == SLOT_MAX_TIMERS - 1);
    gz_action_t slots[16];
    uint8_t bytes[64];
    gz_action_list_t l;
    gz_action_list_init(&l, slots, 16, bytes, sizeof bytes);
    CHECK(gz_timer_cancel_slot(&s, &l) == GZ_OK && l.count == SLOT_MAX_TIMERS - 1 && s.n_timers == 0);
}

/* T-P42-6: every engine is held to its own budget of timers, not only a
 * slot's engine to the table's size: the node part to NP_MAX_TIMERS, a test
 * engine to TE_MAX_TIMERS, the signing engine to its one tick (P4.3), a lobby
 * to the lobby's six, the stand-in to its own. Setting a set timer replaces it; a fired or cancelled one frees its
 * place. */
static void test_budgets(void)
{
    static gz_node_t c;
    struct { int eng; size_t max; } e[] = {
        {ENG_NODE, NP_MAX_TIMERS}, {ENG_TEST0, TE_MAX_TIMERS}, {ENG_TEST1, TE_MAX_TIMERS},
        {ENG_SLOT0, LS_MAX_TIMERS}, {ENG_SLOT0 + 1, TS_MAX_TIMERS}};
    memset(&c, 0, sizeof c);
    c.slots[0].kind = SLOT_KIND_LOBBY;
    c.slots[1].kind = SLOT_KIND_STANDIN;
    for (size_t k = 0; k < sizeof e / sizeof e[0]; k++) {
        CHECK(gz_timer_budget(&c, e[k].eng) == e[k].max);
        for (uint32_t i = 0; i < e[k].max; i++) CHECK(gz_timer_note(&c, e[k].eng, gz_timer_pack(7, 1, i), 1));
        CHECK(gz_timer_note(&c, e[k].eng, gz_timer_pack(7, 1, 0), 1));       /* set again: replaces */
        CHECK(!gz_timer_note(&c, e[k].eng, gz_timer_pack(7, 1, 99), 1));     /* one more: over its budget */
        CHECK(gz_timer_note(&c, e[k].eng, gz_timer_pack(7, 1, 1), 0));       /* one fires */
        CHECK(gz_timer_note(&c, e[k].eng, gz_timer_pack(7, 1, 99), 1));      /* and its place is free */
        CHECK(!gz_timer_note(&c, e[k].eng, gz_timer_pack(7, 1, 98), 1));
    }
    CHECK(LS_MAX_TIMERS == 6 && NP_MAX_TIMERS == 4 && TE_MAX_TIMERS == 4); /* the node part: idle, continue, sign, discovery */
    /* The signing engine: its one tick timer (P4.3). */
    CHECK(gz_timer_budget(&c, ENG_SIGN) == 1);
    CHECK(gz_timer_note(&c, ENG_SIGN, gz_timer_pack(7, 1, 0), 1));
    CHECK(gz_timer_note(&c, ENG_SIGN, gz_timer_pack(7, 1, 0), 1));         /* set again: replaces */
    CHECK(!gz_timer_note(&c, ENG_SIGN, gz_timer_pack(7, 1, 99), 1));       /* a second: over its budget */
    CHECK(gz_timer_note(&c, ENG_SIGN, gz_timer_pack(7, 1, 0), 0));         /* it fires */
    CHECK(gz_timer_note(&c, ENG_SIGN, gz_timer_pack(7, 1, 99), 1));        /* and its place is free */
}

int main(void)
{
    test_budgets();
    test_pack();
    test_generations();
    test_generation_reuse();
    test_big_id();
    test_tracking();
    return check_done();
}
