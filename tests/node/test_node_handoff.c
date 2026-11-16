/* Hand-off brackets (composite-node.md 7.4, 7.5, 9.6): every save of a
 * bracket merged into one batch at the first save's position; the test-build
 * checks for an outward action between two saves and for re-entry; deferral
 * of a hand-off to an engine still running; confirmations per merged batch;
 * a BROADCAST from an engine other than funding refused. */
#include "node_test.h"
#include "internal.h"

static gz_record_t rec(uint32_t type, const char *s)
{
    gz_record_t r = {type, {(const uint8_t *)s, strlen(s)}};
    return r;
}

static void add_save(gz_action_list_t *l, const gz_record_t *r, size_t n)
{
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = r;
    a.u.save.n_records = n;
    CHECK(gz_action_list_add(l, &a) == GZ_OK);
}

static void add_kind(gz_action_list_t *l, gz_action_kind_t k)
{
    gz_action_t a;
    memset(&a, 0, sizeof a);
    a.kind = k;
    if (k == GZ_ACTION_SEND) a.u.send.kind = 16;
    CHECK(gz_action_list_add(l, &a) == GZ_OK);
}

/* The primitive, gz_action_list_merge_saves. */
static void test_merge_primitive(void)
{
    gz_action_t slots[16];
    uint8_t bytes[2048];
    gz_action_list_t l;
    gz_record_t a = rec(1, "a"), b[2] = {rec(2, "bb"), rec(3, "ccc")}, d = rec(4, "d");
    gz_action_list_init(&l, slots, 16, bytes, sizeof bytes);
    add_kind(&l, GZ_ACTION_SET_TIMER);
    add_save(&l, &a, 1);
    add_kind(&l, GZ_ACTION_SEND);
    add_save(&l, b, 2);
    add_kind(&l, GZ_ACTION_SET_TIMER);
    add_save(&l, &d, 1);
    add_kind(&l, GZ_ACTION_NOTIFY);
    CHECK(gz_action_list_merge_saves(&l, 0, 99) == GZ_ERR_ARGUMENT);
    CHECK(gz_action_list_merge_saves(&l, 3, 2) == GZ_ERR_ARGUMENT);
    size_t used1 = l.used;
    CHECK(gz_action_list_merge_saves(&l, 0, 2) == GZ_OK && l.count == 7 && l.used == used1); /* one save: nothing */
    CHECK(gz_action_list_merge_saves(&l, 0, l.count) == GZ_OK);
    CHECK(l.count == 5);
    CHECK(l.slots[0].kind == GZ_ACTION_SET_TIMER && l.slots[1].kind == GZ_ACTION_SAVE &&
          l.slots[2].kind == GZ_ACTION_SEND && l.slots[3].kind == GZ_ACTION_SET_TIMER &&
          l.slots[4].kind == GZ_ACTION_NOTIFY);
    CHECK(l.slots[1].u.save.n_records == 4);
    for (uint32_t i = 0; i < 4; i++) CHECK(l.slots[1].u.save.records[i].type == i + 1);
    CHECK(!memcmp(l.slots[1].u.save.records[2].bytes.data, "ccc", 3));
    /* Too little room for the merged array: nothing changes. */
    gz_action_list_init(&l, slots, 16, bytes, 200);
    add_save(&l, &a, 1);
    add_save(&l, b, 2);
    size_t used = l.used, count = l.count;
    l.n_bytes = l.used + sizeof(gz_record_t); /* room for one record of the three */
    CHECK(gz_action_list_merge_saves(&l, 0, l.count) == GZ_ERR_NO_SPACE);
    CHECK(l.used == used && l.count == count && l.slots[1].kind == GZ_ACTION_SAVE);
    CHECK(l.slots[0].u.save.n_records == 1 && l.slots[1].u.save.n_records == 2);
    l.n_bytes = 200;
    CHECK(gz_action_list_merge_saves(&l, 0, l.count) == GZ_OK && l.count == 1 && l.slots[0].u.save.n_records == 3);
    /* A save past the range stays where it is, a batch of its own. */
    gz_action_list_init(&l, slots, 16, bytes, sizeof bytes);
    add_save(&l, &a, 1);
    add_save(&l, b, 2);
    add_kind(&l, GZ_ACTION_SEND);
    add_save(&l, &d, 1);
    CHECK(gz_action_list_merge_saves(&l, 0, 2) == GZ_OK && l.count == 3);
    CHECK(l.slots[0].kind == GZ_ACTION_SAVE && l.slots[0].u.save.n_records == 3);
    CHECK(l.slots[1].kind == GZ_ACTION_SEND && l.slots[2].kind == GZ_ACTION_SAVE);
    CHECK(l.slots[2].u.save.n_records == 1 && l.slots[2].u.save.records[0].type == 4);
    /* Empty saves merge into one empty save. */
    gz_action_list_init(&l, slots, 16, bytes, sizeof bytes);
    add_save(&l, NULL, 0);
    add_save(&l, NULL, 0);
    CHECK(gz_action_list_merge_saves(&l, 0, 2) == GZ_OK && l.count == 1 && l.slots[0].u.save.n_records == 0);
}

static void handoff(h_t *h, int between, gz_status_t want)
{
    uint8_t to[2], bw = (uint8_t)between;
    gz_put_u16(to, GZ_AREA_TEST2);
    h_arg_t a[2] = {{12, to, 2}, {14, &bw, 1}};
    CHECK(h_cmd(h, GZ_TE_CMD_HANDOFF, a, 2) == want);
}

/* Test 2: engine A saves, sets a timer, hands off to B, which saves: one batch. */
static void test_bracket(void)
{
    h_t h;
    h_init(&h, 1, 2);
    h_start(&h);
    uint64_t ba = h.n->test[0].batches, bb = h.n->test[1].batches;
    size_t m = h_mark(&h), batches = h.n_batches;
    handoff(&h, 0, GZ_OK);
    CHECK(h.n_batches == batches + 1);
    CHECK(h.log[m].a.kind == GZ_ACTION_SAVE && h.log[m].n_records == 2);
    CHECK(h.log[m].types[0] == 0x7e570006u && h.log[m].types[1] == 0x7e580007u);
    CHECK(h.log[m + 1].a.kind == GZ_ACTION_SET_TIMER); /* the timer after the merged save */
    CHECK(h_said(&h, m, "test-handoff taken area=0x7e58") && h_said(&h, m, "result 200"));
    /* The confirmation of the merged batch reached both engines, once. */
    CHECK(h.n->test[0].batches == ba + 1 && h.n->test[1].batches == bb + 1);
    /* After a restart both records are there, or (had the batch not become
     * durable) neither: it is one batch. */
    CHECK(h_restart(&h) == GZ_OK);
    CHECK(h_records_of(&h, 0x7e570006u) == 1 && h_records_of(&h, 0x7e580007u) == 1);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* The variant where A sends between its saves trips the test-build check. */
static void test_adjacency_check(void)
{
    h_t h;
    h_init(&h, 1, 2);
    h_start(&h);
    size_t batches = h.n_batches;
    handoff(&h, 1, GZ_ERR_BUG);
    CHECK(h.list.count == 0 && h.n_batches == batches);
    CHECK(gz_node_error_area(h.n) == GZ_AREA_TEST && gz_node_error_status(h.n) == GZ_ERR_BUG);
    h_free(&h);
}

/* U1: a hand-off to an engine whose call is still running is deferred until
 * it returns, inside the same bracket; without deferral, the re-entry check. */
static void test_reentry(void)
{
    h_t h;
    h_init(&h, 1, 1);
    h_start(&h);
    size_t m = h_mark(&h);
    CHECK(h_cmd(&h, GZ_TE_CMD_SELF_HANDOFF, NULL, 0) == GZ_OK);
    CHECK(h.log[m].a.kind == GZ_ACTION_SAVE && h.log[m].n_records == 2);
    CHECK(h.log[m].types[0] == 0x7e570006u && h.log[m].types[1] == 0x7e570007u);
    CHECK_NO_NODE_ERROR(&h);
    CHECK(h_cmd(&h, GZ_TE_CMD_SELF_HANDOFF_NOW, NULL, 0) == GZ_ERR_BUG);
    CHECK(h.list.count == 0 && gz_node_error_area(h.n) == GZ_AREA_TEST);
    h_free(&h);
}

/* A hand-off outside a bracket, or to an engine that is not there, is a bug. */
static void test_bad_handoffs(void)
{
    h_t h;
    gz_action_t slots[8];
    uint8_t bytes[256];
    gz_action_list_t l;
    gz_action_list_init(&l, slots, 8, bytes, sizeof bytes);
    h_init(&h, 1, 1);
    h_start(&h);
    CHECK(gz_c_handoff(h.n, GZ_AREA_TEST, GZ_AREA_TEST, 1, &l) == GZ_ERR_BUG);   /* no bracket */
    CHECK(gz_c_handoff(h.n, GZ_AREA_TEST, GZ_AREA_FUNDING, 1, &l) == GZ_ERR_BUG); /* no such engine */
    h_free(&h);
    h_init(&h, 1, 1);
    h_start(&h);
    uint8_t to[2];
    gz_put_u16(to, GZ_AREA_TEST2); /* one engine: B is not there */
    h_arg_t a[1] = {{12, to, 2}};
    CHECK(h_cmd(&h, GZ_TE_CMD_HANDOFF, a, 1) == GZ_ERR_BUG && h.list.count == 0);
    CHECK(gz_node_error_area(h.n) == GZ_AREA_TEST); /* the bug is the engine's that asked */
    h_free(&h);
}

/* 14.2, A11: only the funding engine may broadcast. */
static void test_broadcast_owner(void)
{
    h_t h;
    h_init(&h, 1, 1);
    h_start(&h);
    CHECK(h_cmd(&h, GZ_TE_CMD_BROADCAST, NULL, 0) == GZ_ERR_BUG);
    CHECK(h.list.count == 0 && gz_node_error_area(h.n) == GZ_AREA_TEST);
    h_free(&h);
}

static void confirm_one(h_t *h)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_STORAGE_CONFIRMED;
    ev.u.storage.batch = h->pending[0];
    memmove(h->pending, h->pending + 1, (--h->n_pending) * sizeof h->pending[0]);
    CHECK(h_handle_raw(h, &ev) == GZ_OK);
}

/* Confirmations per merged batch, in order: a node part save (the restore
 * batch) is nobody else's; a ping's is its engine's. */
static void test_confirm_queue(void)
{
    h_t h;
    gz_link_t l = h_host_link(1);
    h_init(&h, 1, 2);
    h.confirm_auto = 0;
    h.restored = 1;
    h_start(&h); /* the restore batch waits unconfirmed */
    CHECK(h.n_pending == 1);
    h_test_msg(&h, &l, "GZPI", (const uint8_t *)"p", 1, GZ_AREA_TEST2);
    CHECK(h.n_pending == 2 && h.n->cq_n == 2);
    /* The oldest first: the restore batch's confirmation is not the ping's. */
    confirm_one(&h);
    CHECK(h.n->test[0].batches == 0 && h.n->test[1].batches == 0 && h.n->cq_n == 1);
    h.confirm_auto = 1;
    h_confirm_all(&h);
    CHECK(h.n->test[0].batches == 0 && h.n->test[1].batches == 1);
    /* A confirmation with nothing awaiting is counted, never an error. */
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_STORAGE_CONFIRMED;
    size_t m = h_mark(&h);
    CHECK(h_event(&h, &ev) == GZ_OK && h_said(&h, m, "drop why=confirm"));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* R4: during the start, a confirmation for an engine not yet resumed is held
 * and given after its resume. */
static void test_held_confirmations(void)
{
    h_t h;
    h_init(&h, 1, 1);
    h_start(&h);
    h.n->started = 0; /* as if still starting */
    h.n->resumed[ENG_TEST0] = 0;
    h.n->cq[(h.n->cq_head + h.n->cq_n++) % CQ_MAX] = (uint16_t)(1u << ENG_TEST0);
    uint64_t before = h.n->test[0].batches;
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_STORAGE_CONFIRMED;
    CHECK(h_handle_raw(&h, &ev) == GZ_OK);
    CHECK(h.n->held[ENG_TEST0] == 1 && h.n->test[0].batches == before);
    gz_action_list_reset(&h.list);
    h.n->base = 0;
    memset(h.n->owner, -1, sizeof h.n->owner);
    CHECK(gz_c_release_held(h.n, ENG_TEST0, &h.list) == GZ_OK);
    CHECK(h.n->held[ENG_TEST0] == 0 && h.n->test[0].batches == before + 1);
    h_free(&h);
}

/* 8.3: a step past the engine's declared worst step is a bug (test builds). */
static void test_step_bound(void)
{
    h_t h;
    uint8_t n[4];
    h_arg_t a[1] = {{12, n, 4}};
    h_init(&h, 1, 1);
    h_start(&h);
    gz_put_u32(n, TE_MAX_STEP_ACTIONS);
    size_t m = h_mark(&h);
    CHECK(h_cmd(&h, GZ_TE_CMD_FLOOD, a, 1) == GZ_OK && h_count(&h, m, GZ_ACTION_NOTIFY) == TE_MAX_STEP_ACTIONS);
    CHECK_NO_NODE_ERROR(&h);
    gz_put_u32(n, TE_MAX_STEP_ACTIONS + 1);
    CHECK(h_cmd(&h, GZ_TE_CMD_FLOOD, a, 1) == GZ_ERR_BUG && h.list.count == 0);
    CHECK(gz_node_error_area(h.n) == GZ_AREA_TEST && gz_node_error_status(h.n) == GZ_ERR_BUG);
    h_free(&h);
}

/* Without a hand-off: adjacent saves of one bracket are one batch; saves with
 * something between them stay two batches, in order, and are no bug. */
static void test_saves_without_handoff(void)
{
    h_t h;
    uint8_t bw = 0;
    h_arg_t a[1] = {{12, &bw, 1}};
    h_init(&h, 1, 1);
    h_start(&h);
    size_t m = h_mark(&h), batches = h.n_batches;
    uint64_t confirmed = h.n->test[0].batches;
    CHECK(h_cmd(&h, GZ_TE_CMD_TWO_SAVES, a, 1) == GZ_OK);
    CHECK(h_count(&h, m, GZ_ACTION_SAVE) == 1 && h.n_batches == batches + 1);
    CHECK(h.log[m].a.kind == GZ_ACTION_SAVE && h.log[m].n_records == 2);
    CHECK(h.log[m].types[0] == 0x7e570006u && h.log[m].types[1] == 0x7e570007u);
    CHECK(h.n->test[0].batches == confirmed + 1 && h.n->cq_n == 0);
    bw = 1;
    m = h_mark(&h);
    CHECK(h_cmd(&h, GZ_TE_CMD_TWO_SAVES, a, 1) == GZ_OK);
    CHECK(h_count(&h, m, GZ_ACTION_SAVE) == 2 && h.n_batches == batches + 3);
    CHECK(h.log[m].a.kind == GZ_ACTION_SAVE && h.log[m].n_records == 1 && h.log[m].types[0] == 0x7e570006u);
    CHECK(h_said(&h, m, "test-two-saves between") && h.log[m + 1].a.kind == GZ_ACTION_NOTIFY);
    CHECK(h.log[m + 2].a.kind == GZ_ACTION_SAVE && h.log[m + 2].types[0] == 0x7e570007u);
    CHECK(h.n->test[0].batches == confirmed + 3 && h.n->cq_n == 0);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* A bracket inside a bracket cannot happen (9.6: a call begins with no
 * bracket open, and none opens another); the frame refuses it all the same. */
static void test_nested_bracket(void)
{
    h_t h;
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_STORAGE_CONFIRMED;
    h_init(&h, 1, 1);
    h_start(&h);
    gz_action_list_reset(&h.list);
    h.n->base = 0;
    memset(h.n->owner, -1, sizeof h.n->owner);
    uint64_t before = h.n->test[0].batches;
    h.n->bracket_on = 1;
    CHECK(gz_c_bracket(h.n, ENG_TEST0, &ev, &h.list) == GZ_ERR_BUG);
    CHECK(h.n->test[0].batches == before && h.list.count == 0);
    h.n->bracket_on = 0;
    CHECK(gz_c_bracket(h.n, ENG_TEST0, &ev, &h.list) == GZ_OK && h.n->test[0].batches == before + 1);
    h_free(&h);
}

/* A list that already holds actions when the call begins: the composite
 * touches only what the call appends. */
static void test_list_not_empty(void)
{
    h_t h;
    uint8_t buf[64], c2[2], ms[4];
    size_t at = 0;
    gz_event_t ev;
    gz_action_t t = {.kind = GZ_ACTION_SET_TIMER};
    h_init(&h, 1, 1);
    h_start(&h);
    gz_put_u16(c2, GZ_TE_CMD_TIMER);
    gz_put_u32(ms, 10);
    gz_rec_put(buf, sizeof buf, &at, 0, (const uint8_t *)"req-1", 5);
    gz_rec_put(buf, sizeof buf, &at, 8, c2, 2);
    gz_rec_put(buf, sizeof buf, &at, 12, ms, 4);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_USER_COMMAND;
    ev.u.user.bytes.data = buf;
    ev.u.user.bytes.len = at;
    /* The harness list is exactly the node's size: this one has room to spare. */
    gz_action_t *slots = calloc(GZ_NODE_LIST_ACTIONS + 4, sizeof *slots);
    uint8_t *bytes = malloc(GZ_NODE_LIST_BYTES + 1024);
    gz_action_list_t l;
    if (!slots || !bytes) abort();
    gz_action_list_init(&l, slots, GZ_NODE_LIST_ACTIONS + 4, bytes, GZ_NODE_LIST_BYTES + 1024);
    t.u.set_timer.timer_id = 77;
    t.u.set_timer.delay_ms = 5;
    CHECK(gz_action_list_add(&l, &t) == GZ_OK);
    CHECK(gz_node_handle(h.n, &ev, &l) == GZ_OK && l.count == 3);
    CHECK(l.slots[0].kind == GZ_ACTION_SET_TIMER && l.slots[0].u.set_timer.timer_id == 77);
    CHECK(l.slots[1].kind == GZ_ACTION_SET_TIMER &&
          l.slots[1].u.set_timer.timer_id == ((uint64_t)GZ_AREA_TEST << 48 | 1));
    free(slots);
    free(bytes);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

int main(void)
{
    test_merge_primitive();
    test_bracket();
    test_adjacency_check();
    test_reentry();
    test_bad_handoffs();
    test_broadcast_owner();
    test_confirm_queue();
    test_held_confirmations();
    test_step_bound();
    test_saves_without_handoff();
    test_nested_bracket();
    test_list_not_empty();
    return check_done();
}
