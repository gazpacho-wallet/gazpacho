/* The composite node with the test engine: the start and its checks of
 * storage (journal order, the fence, the restore batch alone), pings and the
 * pull model, views, two engines, the watch registry, commands, the address
 * rule and CONNECT, the engine rule at the test engine's tables, the guard
 * record and the epochs, poisoning after an error (composite-node.md 8.2,
 * 10; journal.md 8.3). */
#include "node_test.h"
#include "internal.h"

static const uint8_t ZERO[32];

static gz_link_t member_side(void)
{
    uint8_t a[33], b[33];
    h_key('K', 2, a); /* the member's key (key port) */
    h_key('H', 0, b);
    return h_link(a, b);
}

static void test_fresh_start(void)
{
    h_t h;
    h_init(&h, 1, 1);
    CHECK(h_start(&h) == GZ_OK);
    /* The start saves nothing but a restore batch (contract v2): epoch 0 is implied. */
    CHECK(h_records_of(&h, GZ_RECORD_KEY_EPOCH) == 0 && h.n_batches == 0);
    CHECK(h.log[0].a.kind == GZ_ACTION_NOTIFY);
    CHECK(h_said(&h, 0, "view 0"));
    /* A second start saves nothing either, and emits the view again (rule 7). */
    size_t m = h_mark(&h);
    CHECK(h_restart(&h) == GZ_OK);
    CHECK(h_records_of(&h, GZ_RECORD_KEY_EPOCH) == 0);
    CHECK(h_count(&h, m, GZ_ACTION_SAVE) == 0 && h_said(&h, m, "view 0"));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

static void test_ping_pull(void)
{
    h_t h;
    gz_link_t l = h_host_link(7);
    uint8_t serial[8];
    h_init(&h, 1, 1);
    h_start(&h);
    size_t m = h_mark(&h);
    CHECK(h_test_msg(&h, &l, "GZPI", (const uint8_t *)"a/0", 3, GZ_AREA_TEST) == GZ_OK);
    /* Save first, then the reply, then the view after its save (rule 8). */
    CHECK(h.log[m].a.kind == GZ_ACTION_SAVE && h.log[m].types[0] == 0x7e570001u);
    CHECK(h.log[m + 1].a.kind == GZ_ACTION_SEND && h.log[m + 1].kind == GZ_TE_KIND);
    CHECK(h_said(&h, m, "view 1"));
    CHECK(h_records_of(&h, 0x7e570001u) == 1);
    /* The reply is not acknowledged: a hello gets it again, at most once a second. */
    m = h_mark(&h);
    h_test_msg(&h, &l, "GZPH", NULL, 0, GZ_AREA_TEST);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1);
    m = h_mark(&h);
    h_test_msg(&h, &l, "GZPH", NULL, 0, GZ_AREA_TEST);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0);
    h.clock += 1000;
    /* The acknowledgement is saved; then a hello gets nothing. */
    gz_put_u64(serial, (uint64_t)1 << 32 | 1); /* the first incarnation's first serial */
    CHECK(h_test_msg(&h, &l, "GZPA", serial, 8, GZ_AREA_TEST) == GZ_OK);
    CHECK(h_records_of(&h, 0x7e570004u) == 1);
    h_test_msg(&h, &l, "GZPA", serial, 8, GZ_AREA_TEST); /* a repeat: nothing saved */
    CHECK(h_records_of(&h, 0x7e570004u) == 1);
    m = h_mark(&h);
    h_test_msg(&h, &l, "GZPH", NULL, 0, GZ_AREA_TEST);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0);
    /* Another ping, then a restart: the start sends nothing; the hello does. */
    h_test_msg(&h, &l, "GZPI", (const uint8_t *)"a/1", 3, GZ_AREA_TEST);
    m = h_mark(&h);
    CHECK(h_restart(&h) == GZ_OK);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0 && h_said(&h, m, "view 2"));
    h_peer(&h, &l, 1, 0);
    h.clock += 2000;
    m = h_mark(&h);
    h_test_msg(&h, &l, "GZPH", NULL, 0, GZ_AREA_TEST);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1);
    /* Another link never gets that reply. */
    gz_link_t other = h_host_link(8);
    h_peer(&h, &other, 1, 0);
    m = h_mark(&h);
    h_test_msg(&h, &other, "GZPH", NULL, 0, GZ_AREA_TEST);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* A member answers a reply with its acknowledgement, and asks with a hello
 * on a connection it made (rule 6). */
static void test_member_side(void)
{
    h_t h;
    gz_link_t l = member_side();
    uint8_t body[8 + 3];
    h_init(&h, 0, 1);
    h_start(&h);
    size_t m = h_mark(&h);
    h_peer(&h, &l, 1, 1);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1);
    m = h_mark(&h);
    h_peer(&h, &l, 1, 0); /* accepted: no hello */
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0);
    gz_put_u64(body, 5);
    memcpy(body + 8, "x/0", 3);
    m = h_mark(&h);
    h_test_msg(&h, &l, "GZPO", body, sizeof body, GZ_AREA_TEST);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1 && h_count(&h, m, GZ_ACTION_SAVE) == 0);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

static void test_restore_batch(void)
{
    h_t h;
    h_init(&h, 1, 1);
    h_start(&h);
    size_t m = h_mark(&h);
    h.restored = 1;
    CHECK(h_restart(&h) == GZ_OK);
    /* First and alone in its list: key_epoch, restored, guard (rule 5). */
    CHECK(h.log[m].a.kind == GZ_ACTION_SAVE && h.log[m].n_records == 3);
    CHECK(h.log[m].types[0] == GZ_RECORD_KEY_EPOCH && h.log[m].types[1] == GZ_RECORD_RESTORED &&
          h.log[m].types[2] == GZ_RECORD_GUARD);
    CHECK(h.log[m + 1].a.kind == GZ_ACTION_NOTIFY); /* the view, in the next step's list */
    CHECK(h_records_of(&h, GZ_RECORD_KEY_EPOCH) == 1);
    /* The epoch is not 0. */
    const h_batch_t *b = &h.batches[h.n_batches - 1];
    gz_bytes_t v;
    CHECK(gz_rec_find(b->recs[0].bytes, 2, &v) == 1 && v.len == 4 && gz_get_u32(v.data) != 0);
    uint32_t epoch1 = gz_get_u32(v.data);
    /* The guard record as storage reads it (journal.md 8.3): the magic, the
     * chain, counter 1, two epochs (installation's 0, then the new one), no
     * round started. */
    const uint8_t *g = b->recs[2].bytes.data;
    CHECK(b->recs[2].bytes.len == 58 + 16 && !memcmp(g, "GZGUARD1", 8) && !memcmp(g + 8, h.cfg.chain, 32));
    CHECK(gz_get_u64(g + 40) == 1 && gz_get_u16(g + 48) == 2);
    CHECK(gz_get_u32(g + 50) == 0 && gz_get_u32(g + 54) == 0 && gz_get_u32(g + 58) == epoch1);
    CHECK(gz_get_u32(g + 62) == 0 && gz_get_u64(g + 66) == 0);
    /* A second restore: a third epoch after the first two, counter 2. */
    CHECK(h_restart(&h) == GZ_OK);
    b = &h.batches[h.n_batches - 1];
    g = b->recs[2].bytes.data;
    CHECK(b->n == 3 && b->recs[2].type == GZ_RECORD_GUARD && b->recs[2].bytes.len == 58 + 24);
    CHECK(gz_get_u64(g + 40) == 2 && gz_get_u16(g + 48) == 3 && gz_get_u32(g + 50) == 0);
    CHECK(gz_get_u32(g + 58) == epoch1 && gz_get_u32(g + 66) != epoch1 && gz_get_u32(g + 66) != 0);
    CHECK(gz_rec_find(b->recs[0].bytes, 2, &v) == 1 && gz_get_u32(v.data) == gz_get_u32(g + 66));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* 8.2: an error rolls the list back, names the engine and poisons the node. */
static void test_poison(void)
{
    h_t h;
    gz_link_t l = h_host_link(3);
    uint8_t after[4];
    h_init(&h, 1, 2);
    h_start(&h);
    gz_put_u32(after, 1);
    uint8_t area[2];
    gz_put_u16(area, GZ_AREA_TEST2);
    h_arg_t a[2] = {{10, area, 2}, {12, after, 4}};
    CHECK(h_cmd(&h, GZ_TE_CMD_FAIL, a, 2) == GZ_OK);
    size_t batches = h.n_batches;
    gz_action_list_reset(&h.list);
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_PEER_CONNECTED;
    ev.u.peer.link = l;
    /* Engine A runs first and appends nothing; engine B saves and fails. */
    gz_status_t st = gz_node_handle(h.n, &ev, &h.list);
    CHECK(st == GZ_ERR_NO_SPACE);
    CHECK(h.list.count == 0 && h.list.used == 0);
    CHECK(gz_node_error_area(h.n) == GZ_AREA_TEST2 && gz_node_error_status(h.n) == GZ_ERR_NO_SPACE);
    CHECK(h.n_batches == batches);
    /* Every later call is refused. */
    CHECK(gz_node_handle(h.n, &ev, &h.list) == GZ_ERR_FAILED);
    gz_storage_reader_t rd = {h_next, h_rewind, &h, h.incarnation, 0, {NULL, 0}};
    int more = 0;
    CHECK(gz_node_start(h.n, &rd, &h.list, &more) == GZ_ERR_FAILED);
    /* A new node from storage starts, with nothing of the failed step. */
    CHECK(h_restart(&h) == GZ_OK);
    CHECK(h_records_of(&h, 0x7e580006u) == 0);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* Arguments the caller gets wrong leave the node usable. */
static void test_caller_errors(void)
{
    h_t h;
    gz_event_t ev;
    gz_action_t small_slots[4];
    uint8_t small_bytes[64];
    gz_action_list_t small;
    h_init(&h, 1, 1);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_TIMER_FIRED;
    /* While it starts only confirmations are taken. */
    CHECK(gz_node_handle(h.n, &ev, &h.list) == GZ_ERR_ARGUMENT);
    h_start(&h);
    CHECK(gz_node_handle(NULL, &ev, &h.list) == GZ_ERR_ARGUMENT);
    gz_action_list_init(&small, small_slots, 4, small_bytes, sizeof small_bytes);
    CHECK(gz_node_handle(h.n, &ev, &small) == GZ_ERR_NO_SPACE);
    CHECK(h_event(&h, &ev) == GZ_OK);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* A record of an area no engine reads stops the start. */
static void test_unknown_area(void)
{
    h_t h;
    h_init(&h, 1, 1);
    h_start(&h);
    h_batch_t *b = &h.batches[h.n_batches++];
    b->id.incarnation = h.incarnation;
    b->id.sequence = ++h.seq;
    b->n = 1;
    b->recs = calloc(1, sizeof *b->recs);
    b->recs[0].type = 0x7e580001u; /* engine B's, with one engine */
    b->recs[0].bytes.data = malloc(1);
    CHECK(h_restart(&h) == GZ_ERR_CORRUPT);
    h_free(&h);
}

/* Two test engines: own records, own timers with the same id (test 1). */
static void test_two_engines(void)
{
    h_t h;
    gz_link_t l = h_host_link(4);
    uint8_t ms[4], a2[2];
    h_init(&h, 1, 2);
    h_start(&h);
    h_test_msg(&h, &l, "GZPI", (const uint8_t *)"a", 1, GZ_AREA_TEST);
    h_test_msg(&h, &l, "GZPI", (const uint8_t *)"b", 1, GZ_AREA_TEST2);
    CHECK(h_records_of(&h, 0x7e570001u) == 1 && h_records_of(&h, 0x7e580001u) == 1);
    gz_put_u32(ms, 100);
    size_t m = h_mark(&h);
    h_arg_t a[1] = {{12, ms, 4}};
    h_cmd(&h, GZ_TE_CMD_TIMER, a, 1);
    uint64_t ta = h_last_timer(&h, m);
    gz_put_u16(a2, GZ_AREA_TEST2);
    m = h_mark(&h);
    h_arg_t b[2] = {{10, a2, 2}, {12, ms, 4}};
    h_cmd(&h, GZ_TE_CMD_TIMER, b, 2);
    uint64_t tb = h_last_timer(&h, m);
    CHECK(ta == ((uint64_t)GZ_AREA_TEST << 48 | 1) && tb == ((uint64_t)GZ_AREA_TEST2 << 48 | 1));
    m = h_mark(&h);
    h_timer(&h, tb);
    CHECK(h_said(&h, m, "test-timer area=0x7e58 id=1") && !h_said(&h, m, "area=0x7e57"));
    m = h_mark(&h);
    h_timer(&h, ta);
    CHECK(h_said(&h, m, "test-timer area=0x7e57 id=1") && !h_said(&h, m, "area=0x7e58"));
    /* The view of each engine. */
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* 7.2: one watch for both engines, the larger depth issued again; reports to both (test 6). */
static void test_watch_registry(void)
{
    h_t h;
    uint8_t txid[32], d1[4], d3[4], a2[2];
    memset(txid, 0xab, sizeof txid);
    gz_put_u32(d1, 1);
    gz_put_u32(d3, 3);
    gz_put_u16(a2, GZ_AREA_TEST2);
    h_init(&h, 1, 2);
    h_start(&h);
    size_t m = h_mark(&h);
    h_arg_t a[2] = {{12, txid, 32}, {14, d1, 4}};
    h_cmd(&h, GZ_TE_CMD_WATCH, a, 2);
    h_arg_t b[3] = {{10, a2, 2}, {12, txid, 32}, {14, d3, 4}};
    h_cmd(&h, GZ_TE_CMD_WATCH, b, 3);
    CHECK(h_count(&h, m, GZ_ACTION_WATCH_TX) == 2);
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_WATCH, a, 2); /* a repeat at a smaller depth: nothing */
    h_cmd(&h, GZ_TE_CMD_WATCH, b, 3); /* the same depth: nothing */
    CHECK(h_count(&h, m, GZ_ACTION_WATCH_TX) == 0);
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_CHAIN;
    ev.u.chain.kind = GZ_CHAIN_TX_CONFIRMED;
    memcpy(ev.u.chain.txid, txid, 32);
    ev.u.chain.confirmations = 2;
    m = h_mark(&h);
    h_event(&h, &ev);
    CHECK(h_said(&h, m, "test-chain area=0x7e57") && h_said(&h, m, "test-chain area=0x7e58"));
    /* A report for a txid nobody watches reaches nobody. */
    ev.u.chain.txid[0] ^= 1;
    m = h_mark(&h);
    h_event(&h, &ev);
    CHECK(!h_said(&h, m, "test-chain"));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

static void test_commands(void)
{
    h_t h;
    gz_event_t ev;
    h_init(&h, 1, 1);
    h_start(&h);
    size_t m = h_mark(&h);
    h_cmd(&h, 0x0177, NULL, 0); /* the lobby's range: no lobby yet */
    CHECK(h_said(&h, m, "result 404 unknown_command"));
    m = h_mark(&h);
    h_cmd(&h, 0x7e70, NULL, 0); /* an unknown test command */
    CHECK(h_said(&h, m, "result 404 unknown_command"));
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_USER_COMMAND; /* no code at all, and malformed bytes */
    ev.u.user.bytes.data = (const uint8_t *)"\xff\xff";
    ev.u.user.bytes.len = 2;
    m = h_mark(&h);
    CHECK(h_event(&h, &ev) == GZ_OK && h_said(&h, m, "result 404"));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* The member's --connect: saved with its index pair, then CONNECT; again at every start. */
static void test_connect(void)
{
    h_t h;
    uint8_t key[33];
    h_key('H', 0, key);
    h_init(&h, 0, 1);
    h_start(&h);
    size_t m = h_mark(&h);
    h_arg_t a[2] = {{12, key, 33}, {14, "127.0.0.1:9", 11}};
    h_cmd(&h, GZ_TE_CMD_CONNECT, a, 2);
    CHECK(h.log[m].a.kind == GZ_ACTION_SAVE && h.log[m + 1].a.kind == GZ_ACTION_CONNECT);
    h_cmd(&h, GZ_TE_CMD_CONNECT, a, 2); /* the same host: nothing new */
    CHECK(h_records_of(&h, 0x7e570005u) == 1);
    m = h_mark(&h);
    h_restart(&h);
    CHECK(h_count(&h, m, GZ_ACTION_CONNECT) == 1 && h_count(&h, m, GZ_ACTION_SAVE) == 0);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* ---- the start's checks of storage (composite-node.md 10; ports.h) -------- */

/* One step of a start, the list kept for the test to read. */
static gz_status_t start_step(h_t *h, int *more)
{
    gz_storage_reader_t rd = {h_next, h_rewind, h, h->incarnation, h->restored, {h->guard, h->guard_len}};
    gz_action_list_reset(&h->list);
    return gz_node_start(h->n, &rd, &h->list, more);
}

/* Storage that is not a journal is refused: identifiers that do not strictly
 * increase, a sequence of 0, a batch of an incarnation later than the one
 * starting. Storage written by the very incarnation starting is taken. */
static void test_storage_that_is_not_a_journal(void)
{
    static const struct {
        uint64_t inc[3], seq[3];
        gz_status_t want;
    } cases[] = {
        {{1, 1, 2}, {1, 2, 1}, GZ_OK},          /* a journal */
        {{1, 1, 3}, {1, 2, 1}, GZ_OK},          /* its last batch written by the incarnation starting (3) */
        {{1, 1, 1}, {1, 1, 2}, GZ_ERR_CORRUPT}, /* the same identifier twice */
        {{1, 1, 1}, {2, 1, 3}, GZ_ERR_CORRUPT}, /* a sequence going back */
        {{2, 1, 2}, {1, 1, 2}, GZ_ERR_CORRUPT}, /* an incarnation going back */
        {{1, 2, 2}, {1, 0, 1}, GZ_ERR_CORRUPT}, /* sequence 0 */
        {{1, 2, 4}, {1, 1, 1}, GZ_ERR_CORRUPT}, /* a batch of an incarnation later than the one starting */
        {{1, 2, 9}, {1, 1, 1}, GZ_ERR_CORRUPT},
    };
    for (size_t k = 0; k < sizeof cases / sizeof cases[0]; k++) {
        h_t h;
        int more = 1;
        h_init(&h, 1, 1);
        h.incarnation = 2; /* the node below starts under incarnation 3 */
        for (int i = 0; i < 3; i++) h_add_batch(&h, cases[k].inc[i], cases[k].seq[i], GZ_RECORD_RESTORED, NULL, 0);
        h_new_node(&h);
        CHECK(h.incarnation == 3);
        gz_status_t st = start_step(&h, &more);
        CHECK(st == cases[k].want);
        if (cases[k].want != GZ_OK) {
            /* Nothing appended, the node says why and is not used again. */
            CHECK(h.list.count == 0 && gz_node_error_status(h.n) == GZ_ERR_CORRUPT);
            CHECK(start_step(&h, &more) == GZ_ERR_FAILED);
        }
        h_free(&h);
    }
}

static void add_earlier_batch_once(void *ctx)
{
    h_t *h = ctx;
    /* At the second rewind of the first call: between the walk that takes
     * the fence and the walk that loads. */
    if (h->rewinds == 2) h_add_batch(h, 1, 3, GZ_RECORD_RESTORED, NULL, 0);
}

/* THE FENCE (ports.h): storage may gain only the starting node's own batches
 * after the first call began. A batch of an earlier incarnation that appears
 * after the fence was taken is refused, in the first call and in every later
 * step; one of the starting incarnation is taken. */
static void test_the_fence(void)
{
    h_t h;
    int more = 1;
    /* In the first call, between its two walks. */
    h_init(&h, 1, 1);
    h_add_batch(&h, 1, 1, GZ_RECORD_RESTORED, NULL, 0);
    h_add_batch(&h, 1, 2, GZ_RECORD_RESTORED, NULL, 0);
    h_new_node(&h); /* incarnation 2 */
    h.on_rewind = add_earlier_batch_once;
    h.rewinds = 0;
    CHECK(start_step(&h, &more) == GZ_ERR_CORRUPT && h.list.count == 0);
    CHECK(h.rewinds == 2 && h.n_batches == 3);
    h_free(&h);
    /* The same storage, whole before the first call: a journal. */
    h_init(&h, 1, 1);
    h_add_batch(&h, 1, 1, GZ_RECORD_RESTORED, NULL, 0);
    h_add_batch(&h, 1, 2, GZ_RECORD_RESTORED, NULL, 0);
    h_add_batch(&h, 1, 3, GZ_RECORD_RESTORED, NULL, 0);
    h_new_node(&h);
    CHECK(h_start(&h) == GZ_OK);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
    /* At a later step: a restored start is two steps (the restore batch,
     * then the view). Between them the dead program's batch lands. */
    h_init(&h, 1, 1);
    h_add_batch(&h, 1, 1, GZ_RECORD_RESTORED, NULL, 0);
    h_new_node(&h);
    h.restored = 1;
    more = 0;
    CHECK(start_step(&h, &more) == GZ_OK && more == 1 && h.list.count == 1);
    h_execute(&h, &h.list); /* the restore batch: 2.1, the node's own, is durable */
    h_confirm_all(&h);
    h_add_batch(&h, 1, 2, GZ_RECORD_RESTORED, NULL, 0); /* after the fence (1.1) */
    CHECK(start_step(&h, &more) == GZ_ERR_CORRUPT && h.list.count == 0);
    CHECK(gz_node_error_status(h.n) == GZ_ERR_CORRUPT);
    h_free(&h);
    /* The same without the late batch: the start completes; its own batch
     * between the steps is no breach. */
    h_init(&h, 1, 1);
    h_add_batch(&h, 1, 1, GZ_RECORD_RESTORED, NULL, 0);
    h_new_node(&h);
    h.restored = 1;
    CHECK(start_step(&h, &more) == GZ_OK && more == 1);
    h_execute(&h, &h.list);
    h_confirm_all(&h);
    CHECK(start_step(&h, &more) == GZ_OK && h.list.count == 1 && h.list.slots[0].kind == GZ_ACTION_NOTIFY);
    h_execute(&h, &h.list);
    CHECK(start_step(&h, &more) == GZ_OK && h.list.count == 1 && h.list.slots[0].kind == GZ_ACTION_NOTIFY &&
          h.list.slots[0].u.notify.code == GZ_NOTIFY_VIEW(GZ_VIEW_STATUS)); /* the status object (rule 7, P6a) */
    h_execute(&h, &h.list);
    CHECK(start_step(&h, &more) == GZ_OK && more == 0 && h.list.count == 0);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* Node rule 5: the restore batch is ALONE in its list, one SAVE and nothing
 * beside it, so the runner issues it as sequence 1 and everything else waits
 * for the next step. And the `restored` record names the incarnation of the
 * newest batch the restored journal holds, whatever area its records are of
 * (review A, F3): here every batch is a test engine's. */
static void test_restore_batch_alone(void)
{
    h_t h;
    gz_link_t l = h_host_link(7);
    gz_bytes_t v;
    int more = 0;
    h_init(&h, 1, 1);
    h_start(&h);
    h_test_msg(&h, &l, "GZPI", (const uint8_t *)"a", 1, GZ_AREA_TEST); /* incarnation 1 */
    h_restart(&h);
    h_test_msg(&h, &l, "GZPI", (const uint8_t *)"b", 1, GZ_AREA_TEST); /* incarnation 2 */
    h_restart(&h);
    h_test_msg(&h, &l, "GZPI", (const uint8_t *)"c", 1, GZ_AREA_TEST); /* incarnation 3 */
    CHECK(h.incarnation == 3 && h_records_of(&h, 0x7e570001u) == 3 && h_records_of(&h, GZ_RECORD_GUARD) == 0);
    h_new_node(&h);
    h.restored = 1;
    CHECK(start_step(&h, &more) == GZ_OK && more == 1);
    CHECK(h.list.count == 1 && h.list.slots[0].kind == GZ_ACTION_SAVE && h.list.slots[0].u.save.n_records == 3);
    const gz_record_t *r = h.list.slots[0].u.save.records;
    CHECK(r[0].type == GZ_RECORD_KEY_EPOCH && r[1].type == GZ_RECORD_RESTORED && r[2].type == GZ_RECORD_GUARD);
    CHECK(gz_rec_find(r[1].bytes, 4, &v) == 1 && v.len == 8 && gz_get_u64(v.data) == 3);
    CHECK(gz_rec_find(r[1].bytes, 2, &v) == 1 && v.len == 8 && gz_get_u64(v.data) == h.clock);
    h_execute(&h, &h.list);
    h_confirm_all(&h);
    /* The next step: the view, not in the restore batch's list. */
    CHECK(start_step(&h, &more) == GZ_OK && h.list.count == 1 && h.list.slots[0].kind == GZ_ACTION_NOTIFY);
    h_execute(&h, &h.list);
    CHECK(start_step(&h, &more) == GZ_OK && h.list.count == 1 && h.list.slots[0].kind == GZ_ACTION_NOTIFY &&
          h.list.slots[0].u.notify.code == GZ_NOTIFY_VIEW(GZ_VIEW_STATUS)); /* the status object (rule 7, P6a) */
    h_execute(&h, &h.list);
    CHECK(start_step(&h, &more) == GZ_OK && more == 0);
    /* An empty journal restored: the newest batch's incarnation is 0. */
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
    h_init(&h, 1, 1);
    h.restored = 1;
    CHECK(start_step(&h, &more) == GZ_OK && h.list.count == 1);
    r = h.list.slots[0].u.save.records;
    CHECK(gz_rec_find(r[1].bytes, 4, &v) == 1 && v.len == 8 && gz_get_u64(v.data) == 0);
    h_free(&h);
}

/* ---- the address rule, and CONNECT (review A F1, review B 3) -------------- */

static int addr_ok(const char *s)
{
    gz_bytes_t b = {(const uint8_t *)s, strlen(s)};
    return gz_connect_address_ok(b);
}

static void test_address_rule(void)
{
    static const char *good[] = {"127.0.0.1:1", "127.0.0.1:65535", "192.0.2.7:9735", "192.0.2.4:80", "[::1]:9735",
                                 "[2001:db8::1]:1", "[::ffff:198.51.100.1]:65535", "1:1",
                                 "203.0.113.255:65535"};
    static const char *bad[] = {"not-an-address", "no-port-here", "127.0.0.1", "127.0.0.1:", ":9735", "127.0.0.1:0",
                                "127.0.0.1:65536", "127.0.0.1:99999", "127.0.0.1:123456", "127.0.0.1:01",
                                "127.0.0.1:-1", "127.0.0.1:+1", "127.0.0.1:1 ", " 127.0.0.1:1", "127.0.0.1:1x",
                                "host:1", "example.com:9735", "127.0.0.1.:1", ".127.0.0.1:1", "::1:9735",
                                "[::1]", "[::1]:", "[::1:9735", "[]:1", "[:]:1", "[::g]:1", "[::1]x:1",
                                "127.0.0.1:1\n", "127.0.0.1:9735:1x", "1,2:1"};
    char longest[80];
    gz_bytes_t none = {NULL, 0}, zero_len = {(const uint8_t *)"127.0.0.1:1", 0};
    for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) CHECK(addr_ok(good[i]));
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) CHECK(!addr_ok(bad[i]));
    CHECK(!gz_connect_address_ok(none) && !gz_connect_address_ok(zero_len));
    /* 64 bytes at most. */
    memset(longest, '1', sizeof longest);
    memcpy(longest + 62, ":7", 3);
    CHECK(strlen(longest) == 64 && addr_ok(longest));
    memset(longest, '1', sizeof longest);
    memcpy(longest + 63, ":7", 3);
    CHECK(strlen(longest) == 65 && !addr_ok(longest));
    /* The list refuses what the rule refuses: an engine that skipped the
     * rule gets an error at its own step, before anything is carried out. */
    gz_action_t slot[2];
    uint8_t bytes[256];
    gz_action_list_t list;
    gz_action_t a = {.kind = GZ_ACTION_CONNECT};
    gz_action_list_init(&list, slot, 2, bytes, sizeof bytes);
    a.u.connect.address.data = (const uint8_t *)"not-an-address";
    a.u.connect.address.len = 14;
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT && list.count == 0 && list.used == 0);
    a.u.connect.address.data = (const uint8_t *)"127.0.0.1:9";
    a.u.connect.address.len = 11;
    CHECK(gz_action_list_add(&list, &a) == GZ_OK && list.count == 1);
}

/* A bad CONNECT target is refused when the command is taken: an answer to the
 * person, nothing saved, no CONNECT, no node error, and the next start is as
 * any other. */
static void test_connect_bad_address(void)
{
    static const char *bad[] = {"not-an-address", "no-port-here", "127.0.0.1", "127.0.0.1:0", "host.example:9735"};
    h_t h;
    uint8_t key[33];
    h_key('H', 0, key);
    h_init(&h, 0, 1);
    h_start(&h);
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        size_t m = h_mark(&h);
        h_arg_t a[2] = {{12, key, 33}, {14, bad[i], strlen(bad[i])}};
        CHECK(h_cmd(&h, GZ_TE_CMD_CONNECT, a, 2) == GZ_OK);
        CHECK(h_said(&h, m, "result 400 bad_address"));
        CHECK(h_count(&h, m, GZ_ACTION_SAVE) == 0 && h_count(&h, m, GZ_ACTION_CONNECT) == 0);
    }
    CHECK(h.n_batches == 0);
    size_t m = h_mark(&h);
    CHECK(h_restart(&h) == GZ_OK && h_count(&h, m, GZ_ACTION_CONNECT) == 0);
    /* A good target after the bad ones is saved and kept as before. */
    h_arg_t ok[2] = {{12, key, 33}, {14, "127.0.0.1:9", 11}};
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_CONNECT, ok, 2);
    CHECK(h_said(&h, m, "result 200") && h_count(&h, m, GZ_ACTION_CONNECT) == 1);
    /* The same host at a bad address: refused, and the good one stands. */
    h_arg_t repl[2] = {{12, key, 33}, {14, "nowhere", 7}};
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_CONNECT, repl, 2);
    CHECK(h_said(&h, m, "result 400 bad_address") && h_records_of(&h, 0x7e570005u) == 1);
    m = h_mark(&h);
    CHECK(h_restart(&h) == GZ_OK && h_count(&h, m, GZ_ACTION_CONNECT) == 1);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* A bad target that storage already holds (saved before the rule was checked
 * at the command) must not stop a start, this one or any later one: it is
 * passed over with a notice, and the good targets beside it are connected. */
static void test_saved_bad_target_does_not_stop_a_start(void)
{
    static const char *bad[] = {"not-an-address", "127.0.0.1"};
    h_t h;
    uint8_t rec[41 + 64], key[33];
    h_init(&h, 0, 1);
    h_start(&h);
    for (uint32_t i = 0; i < 2; i++) {
        h_key('H', 1 + i, key);
        memcpy(rec, key, 33);
        gz_put_u32(rec + 33, 0);
        gz_put_u32(rec + 37, 2 * (i + 1));
        memcpy(rec + 41, bad[i], strlen(bad[i]));
        h_add_batch(&h, 1, ++h.seq, 0x7e570005u, rec, 41 + strlen(bad[i]));
    }
    h_key('H', 3, key);
    memcpy(rec, key, 33);
    gz_put_u32(rec + 37, 6);
    memcpy(rec + 41, "127.0.0.1:9", 11);
    h_add_batch(&h, 1, ++h.seq, 0x7e570005u, rec, 41 + 11);
    for (int round = 0; round < 3; round++) {
        size_t m = h_mark(&h);
        CHECK(h_restart(&h) == GZ_OK);
        CHECK(h_count(&h, m, GZ_ACTION_CONNECT) == 1 && h_count(&h, m, GZ_ACTION_SAVE) == 0);
        CHECK(h_said(&h, m, "test-connect-skipped area=0x7e57 why=bad-address count=2"));
        CHECK(h_said(&h, m, "view 0"));
        CHECK_NO_NODE_ERROR(&h);
    }
    /* The node goes on working. */
    gz_link_t l;
    uint8_t mine[33];
    h_key('K', 6, mine);
    l = h_link(mine, key);
    size_t m = h_mark(&h);
    CHECK(h_peer(&h, &l, 1, 1) == GZ_OK && h_count(&h, m, GZ_ACTION_SEND) == 1);
    h_free(&h);
}

/* ---- the engine rule at the test engine's own tables (review B 5, 7) ------ */

/* A peer's unacknowledged pings past the table are counted drops, never an
 * error, and one key cannot fill the table for the others: a link holds at
 * most a quarter of it. */
static void test_ping_table(void)
{
    h_t h;
    uint8_t body[4];
    h_init(&h, 1, 1);
    h_start(&h);
    h.confirm_auto = 1;
    gz_link_t greedy = h_host_link(1), honest = h_host_link(2);
    h_peer(&h, &greedy, 1, 0);
    h_peer(&h, &honest, 1, 0);
    /* 600 pings from one key, none acknowledged: 128 saved, the rest dropped. */
    for (uint32_t i = 0; i < 600; i++) {
        gz_put_u32(body, i);
        size_t m = h_mark(&h);
        CHECK(h_test_msg(&h, &greedy, "GZPI", body, 4, GZ_AREA_TEST) == GZ_OK);
        if (i < TE_MAX_PENDING_LINK) CHECK(h_count(&h, m, GZ_ACTION_SAVE) == 1 && h_count(&h, m, GZ_ACTION_SEND) == 1);
        else CHECK(h_count(&h, m, GZ_ACTION_SAVE) == 0 && h_count(&h, m, GZ_ACTION_SEND) == 0 &&
                   h_said(&h, m, "test-ping-dropped area=0x7e57"));
    }
    CHECK(h_records_of(&h, 0x7e570001u) == TE_MAX_PENDING_LINK);
    /* The honest member is served as if the other were not there. */
    for (uint32_t i = 0; i < 5; i++) {
        size_t m = h_mark(&h);
        h_test_msg(&h, &honest, "GZPI", body, 4, GZ_AREA_TEST);
        CHECK(h_count(&h, m, GZ_ACTION_SAVE) == 1 && h_count(&h, m, GZ_ACTION_SEND) == 1);
    }
    /* Also after a restart: the journal holds the greedy key's 128 for good. */
    CHECK(h_restart(&h) == GZ_OK);
    h_peer(&h, &honest, 1, 0);
    size_t m = h_mark(&h);
    h_test_msg(&h, &honest, "GZPI", body, 4, GZ_AREA_TEST);
    CHECK(h_count(&h, m, GZ_ACTION_SAVE) == 1 && h_count(&h, m, GZ_ACTION_SEND) == 1);
    /* The whole table: four keys fill it (the honest one has 6 already); the
     * 513th unacknowledged ping, from a fifth key, is a counted drop. */
    for (uint32_t k = 3; k <= 4; k++) {
        gz_link_t l = h_host_link(k);
        h_peer(&h, &l, 1, 0);
        for (uint32_t i = 0; i < TE_MAX_PENDING_LINK; i++) CHECK(h_test_msg(&h, &l, "GZPI", body, 4, GZ_AREA_TEST) == GZ_OK);
    }
    for (uint32_t i = 6; i < TE_MAX_PENDING_LINK; i++) h_test_msg(&h, &honest, "GZPI", body, 4, GZ_AREA_TEST);
    CHECK(h_records_of(&h, 0x7e570001u) == TE_MAX_PENDING && TE_MAX_PENDING == 4 * TE_MAX_PENDING_LINK);
    gz_link_t fifth = h_host_link(6);
    h_peer(&h, &fifth, 1, 0);
    m = h_mark(&h);
    CHECK(h_test_msg(&h, &fifth, "GZPI", body, 4, GZ_AREA_TEST) == GZ_OK);
    CHECK(h_count(&h, m, GZ_ACTION_SAVE) == 0 && h_said(&h, m, "test-ping-dropped"));
    CHECK(h_records_of(&h, 0x7e570001u) == TE_MAX_PENDING);
    /* A full journal of pings loads again, and the node is as before. */
    CHECK(h_restart(&h) == GZ_OK);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* An acknowledgement counts only on the link its reply was sent on: serials
 * can be guessed (the incarnation and a count), and another key must not be
 * able to stop a reply from being sent again. */
static void test_ack_from_another_link(void)
{
    h_t h;
    gz_link_t a = h_host_link(1), b = h_host_link(2);
    uint8_t serial[8];
    h_init(&h, 1, 1);
    h_start(&h);
    h_test_msg(&h, &a, "GZPI", (const uint8_t *)"p", 1, GZ_AREA_TEST);
    gz_put_u64(serial, (uint64_t)1 << 32 | 1);
    size_t m = h_mark(&h);
    CHECK(h_test_msg(&h, &b, "GZPA", serial, 8, GZ_AREA_TEST) == GZ_OK);
    CHECK(h_count(&h, m, GZ_ACTION_SAVE) == 0 && h_records_of(&h, 0x7e570004u) == 0);
    /* The reply is still owed to a: its hello gets it again. */
    m = h_mark(&h);
    h_test_msg(&h, &a, "GZPH", NULL, 0, GZ_AREA_TEST);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1);
    /* From a itself the acknowledgement is saved. */
    CHECK(h_test_msg(&h, &a, "GZPA", serial, 8, GZ_AREA_TEST) == GZ_OK && h_records_of(&h, 0x7e570004u) == 1);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* A hello inside the engine's one answer a second is not dropped: it is
 * answered, once, when the second is over (the pinger asks only once per
 * connection). A link that goes away meanwhile is not answered. */
static void test_hello_inside_the_second_is_deferred(void)
{
    h_t h;
    gz_link_t l = h_host_link(7);
    const uint64_t t4 = (uint64_t)GZ_AREA_TEST << 48 | 4;
    h_init(&h, 1, 1);
    h_start(&h);
    h_test_msg(&h, &l, "GZPI", (const uint8_t *)"a", 1, GZ_AREA_TEST);
    size_t m = h_mark(&h);
    h_test_msg(&h, &l, "GZPH", NULL, 0, GZ_AREA_TEST);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1);
    h.clock += 300;
    m = h_mark(&h);
    h_test_msg(&h, &l, "GZPH", NULL, 0, GZ_AREA_TEST);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0 && h_count(&h, m, GZ_ACTION_SET_TIMER) == 1);
    CHECK(h.log[m].a.kind == GZ_ACTION_SET_TIMER && h.log[m].timer == t4 && h.log[m].a.u.set_timer.delay_ms == 700);
    m = h_mark(&h);
    h_test_msg(&h, &l, "GZPH", NULL, 0, GZ_AREA_TEST); /* a third: one deferred answer is enough */
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0 && h_count(&h, m, GZ_ACTION_SET_TIMER) == 0);
    h.clock += 700;
    m = h_mark(&h);
    CHECK(h_timer(&h, t4) == GZ_OK && h_count(&h, m, GZ_ACTION_SEND) == 1);
    m = h_mark(&h);
    h_timer(&h, t4); /* once */
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0);
    /* Deferred again, and the link goes: nothing is sent to it. */
    h.clock += 100;
    h_test_msg(&h, &l, "GZPH", NULL, 0, GZ_AREA_TEST);
    h_peer(&h, &l, 0, 0);
    h.clock += 1000;
    m = h_mark(&h);
    h_timer(&h, t4);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* The reserved kind 0xffff (action.h): an engine that sends it broke a rule
 * the composite checks; the person's `send` command is refused. */
static void test_reserved_kind(void)
{
    h_t h;
    uint8_t key[33], kind[2], scope[32] = {0};
    h_key('M', 1, key);
    gz_put_u16(kind, GZ_SEND_KIND_RESERVED);
    h_init(&h, 1, 1);
    h_start(&h);
    h_arg_t a[4] = {{12, key, 33}, {14, kind, 2}, {16, scope, 32}, {18, "", 0}};
    size_t m = h_mark(&h);
    CHECK(h_cmd(&h, GZ_TE_CMD_SEND, a, 4) == GZ_OK);
    CHECK(h_said(&h, m, "result 400 bad_request") && h_count(&h, m, GZ_ACTION_SEND) == 0);
    gz_put_u16(kind, 28);
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_SEND, a, 4);
    CHECK(h_said(&h, m, "result 200") && h_count(&h, m, GZ_ACTION_SEND) == 1);
    /* An engine that puts it in its list: a bug, the list rolled back. */
    CHECK(h_cmd(&h, GZ_TE_CMD_SEND_RESERVED, NULL, 0) == GZ_ERR_BUG);
    CHECK(h.list.count == 0 && gz_node_error_area(h.n) == GZ_AREA_TEST);
    h_free(&h);
}

/* ---- chain reports -------------------------------------------------------- */

/* A new tip reaches every test engine; a transaction and an outpoint with
 * the same txid are two watches, and so are two outpoints of one
 * transaction. */
static void test_chain_routing(void)
{
    h_t h;
    uint8_t txid[32], d[4], v0[4], v1[4], a2[2];
    gz_event_t ev;
    memset(txid, 0x5c, sizeof txid);
    gz_put_u32(d, 1);
    gz_put_u32(v0, 0);
    gz_put_u32(v1, 1);
    gz_put_u16(a2, GZ_AREA_TEST2);
    h_init(&h, 1, 2);
    h_start(&h);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_CHAIN;
    ev.u.chain.kind = GZ_CHAIN_NEW_TIP;
    ev.u.chain.height = 77;
    size_t m = h_mark(&h);
    CHECK(h_event(&h, &ev) == GZ_OK);
    CHECK(h_said(&h, m, "test-chain area=0x7e57") && h_said(&h, m, "test-chain area=0x7e58"));
    /* Engine A watches the transaction; engine B the outpoint (txid, 0). */
    h_arg_t wa[2] = {{12, txid, 32}, {14, d, 4}};
    h_arg_t wb[4] = {{10, a2, 2}, {12, txid, 32}, {14, v0, 4}, {16, d, 4}};
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_WATCH, wa, 2);
    h_cmd(&h, GZ_TE_CMD_WATCH_OUTPOINT, wb, 4);
    CHECK(h_count(&h, m, GZ_ACTION_WATCH_TX) == 1 && h_count(&h, m, GZ_ACTION_WATCH_OUTPOINT) == 1);
    ev.u.chain.kind = GZ_CHAIN_TX_CONFIRMED;
    memcpy(ev.u.chain.txid, txid, 32);
    m = h_mark(&h);
    h_event(&h, &ev);
    CHECK(h_said(&h, m, "test-chain area=0x7e57") && !h_said(&h, m, "area=0x7e58"));
    ev.u.chain.kind = GZ_CHAIN_OUTPOINT_SPENT;
    memcpy(ev.u.chain.outpoint.txid, txid, 32);
    ev.u.chain.outpoint.vout = 0;
    m = h_mark(&h);
    h_event(&h, &ev);
    CHECK(h_said(&h, m, "test-chain area=0x7e58") && !h_said(&h, m, "area=0x7e57"));
    /* Output 1 of the same transaction is another watch: nobody asked. */
    ev.u.chain.outpoint.vout = 1;
    m = h_mark(&h);
    h_event(&h, &ev);
    CHECK(!h_said(&h, m, "test-chain"));
    h_arg_t wb1[4] = {{10, a2, 2}, {12, txid, 32}, {14, v1, 4}, {16, d, 4}};
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_WATCH_OUTPOINT, wb1, 4);
    CHECK(h_count(&h, m, GZ_ACTION_WATCH_OUTPOINT) == 1); /* issued: not a repeat of output 0 */
    m = h_mark(&h);
    h_event(&h, &ev);
    CHECK(h_said(&h, m, "test-chain area=0x7e58"));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* ---- the guard record and the epochs (journal.md 8.3; review A F7, B 4) --- */

/* The restore epoch's mix, undone: the 8 bytes that make the node draw
 * `epoch` under `incarnation` (nodepart.c: 31 bits of the SplitMix64
 * finaliser of the draw XOR the incarnation times an odd constant). */
static uint64_t unshift(uint64_t y, int s)
{
    uint64_t x = y;
    for (int i = 0; i < 64 / s + 1; i++) x = y ^ (x >> s);
    return x;
}

static uint64_t inverse(uint64_t c)
{
    uint64_t x = c;
    for (int i = 0; i < 6; i++) x *= 2 - c * x;
    return x;
}

static uint64_t draw_for_epoch(uint32_t epoch, uint64_t incarnation)
{
    uint64_t x = unshift((uint64_t)epoch << 33 | 12345, 31);
    x = unshift(x * inverse(0x94D049BB133111EBull), 27);
    x = unshift(x * inverse(0xBF58476D1CE4E5B9ull), 30);
    return x ^ (incarnation * 0x9E3779B97F4A7C15ull);
}

/* The guard record of the newest batch that has one. */
static const uint8_t *last_guard(const h_t *h, size_t *len)
{
    for (size_t i = h->n_batches; i-- > 0;)
        for (size_t k = 0; k < h->batches[i].n; k++)
            if (h->batches[i].recs[k].type == GZ_RECORD_GUARD) {
                *len = h->batches[i].recs[k].bytes.len;
                return h->batches[i].recs[k].bytes.data;
            }
    static const uint8_t none[64];
    *len = 0;
    return none; /* no guard record: a counter of 0 and no epochs */
}

static uint32_t guard_epoch(const uint8_t *g, size_t i)
{
    return gz_get_u32(g + 50 + 8 * i);
}

static int guard_has(const uint8_t *g, uint32_t epoch)
{
    for (size_t i = 0; i < gz_get_u16(g + 48); i++)
        if (guard_epoch(g, i) == epoch) return 1;
    return 0;
}

/* A drawn epoch is never 0 and never one the node knows: it draws again. */
static void test_restore_epoch_redraw(void)
{
    h_t h;
    size_t len;
    h_init(&h, 1, 1);
    h_start(&h);
    h.restored = 1;
    /* The port gives the bytes that make epoch 0 under incarnation 2. */
    h.force_draw = draw_for_epoch(0, 2);
    h.force_n = 1;
    uint64_t draws = h.draws;
    CHECK(h_restart(&h) == GZ_OK && h.incarnation == 2);
    const uint8_t *g = last_guard(&h, &len);
    CHECK(len == 58 + 16 && gz_get_u16(g + 48) == 2 && guard_epoch(g, 0) == 0 && guard_epoch(g, 1) != 0);
    CHECK(h.draws == draws + 2); /* the first draw was refused, the second taken */
    uint32_t first = guard_epoch(g, 1);
    /* The port repeats the epoch the node is in: drawn again. */
    h.force_draw = draw_for_epoch(first, 3);
    h.force_n = 1;
    draws = h.draws;
    CHECK(h_restart(&h) == GZ_OK && h.incarnation == 3);
    g = last_guard(&h, &len);
    CHECK(gz_get_u16(g + 48) == 3 && guard_epoch(g, 1) == first && guard_epoch(g, 2) != first && guard_epoch(g, 2) != 0);
    CHECK(h.draws == draws + 2);
    /* A port stuck on one value cannot hold the start: the count mixed into
     * each further draw moves it on. */
    h.force_draw = draw_for_epoch(first, 4);
    h.force_n = 1000;
    draws = h.draws;
    CHECK(h_restart(&h) == GZ_OK);
    CHECK(h.draws == draws + 2); /* the same bytes again, and a new epoch all the same */
    g = last_guard(&h, &len);
    CHECK(gz_get_u16(g + 48) == 4 && guard_epoch(g, 3) != first && guard_epoch(g, 3) != 0 &&
          guard_epoch(g, 3) != guard_epoch(g, 2));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* The guard holds the newest 16 epochs: the current one and the 15 before
 * it. Past that the oldest is forgotten, one per restore, and every start
 * goes on succeeding (review A probe P8, 21 restores). */
static void test_guard_forgets_the_oldest_epoch(void)
{
    h_t h;
    uint32_t epochs[32];
    size_t len;
    h_init(&h, 1, 1);
    h_start(&h);
    h.restored = 1;
    epochs[0] = 0;
    for (int r = 1; r <= 21; r++) {
        CHECK(h_restart(&h) == GZ_OK);
        const uint8_t *g = last_guard(&h, &len);
        size_t n = gz_get_u16(g + 48), want = r + 1 > 16 ? 16 : (size_t)r + 1;
        CHECK(n == want && len == 58 + 8 * n && gz_get_u64(g + 40) == (uint64_t)r);
        epochs[r] = guard_epoch(g, n - 1);
        CHECK(epochs[r] != 0);
        /* Exactly the newest `n`, oldest first. */
        for (size_t i = 0; i < n; i++) CHECK(guard_epoch(g, i) == epochs[(size_t)r + 1 - n + i]);
        for (int k = 0; k < r; k++) CHECK(epochs[k] != epochs[r]);
    }
    /* A plain restart reads the list back from the journal: the next restore
     * goes on from it. */
    h.restored = 0;
    CHECK(h_restart(&h) == GZ_OK);
    h.restored = 1;
    CHECK(h_restart(&h) == GZ_OK);
    const uint8_t *g = last_guard(&h, &len);
    CHECK(gz_get_u16(g + 48) == 16 && gz_get_u64(g + 40) == 22 && guard_epoch(g, 14) == epochs[21]);
    CHECK(guard_epoch(g, 0) == epochs[7]);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

static size_t make_guard(uint8_t *out, const uint8_t chain[32], uint64_t counter, const uint32_t (*epochs)[2], size_t n,
                         uint64_t rounds)
{
    memcpy(out, "GZGUARD1", 8);
    memcpy(out + 8, chain, 32);
    gz_put_u64(out + 40, counter);
    gz_put_u16(out + 48, (uint16_t)n);
    for (size_t i = 0; i < n; i++) {
        gz_put_u32(out + 50 + 8 * i, epochs[i][0]);
        gz_put_u32(out + 54 + 8 * i, epochs[i][1]);
    }
    gz_put_u64(out + 50 + 8 * n, rounds);
    return 58 + 8 * n;
}

/* A restore of a stale backup must not write over a newer guard file with
 * the backup's shorter list and lower counter (journal.md 8.3; review A F7,
 * review B 4). The node is given the file with the restore marker and its
 * guard record holds the union, a counter above both, and the larger count
 * of rounds started; a later start reads that back. */
static void test_guard_file_is_not_overwritten_with_less(void)
{
    h_t h;
    uint8_t file[58 + 8 * 40];
    size_t len;
    /* The device since the backup: three more epochs, keys used under two of
     * them, seven rounds started; the guard file's counter is 22. */
    static const uint32_t later[4][2] = {{0, 3}, {0x1111, 0}, {0x2222, 8}, {0x3333, 4}};
    h_init(&h, 1, 1);
    h_start(&h); /* the backup: a journal with no guard record, epoch 0 */
    h.guard_len = make_guard(file, h.cfg.chain, 22, later, 4, 7);
    h.guard = file;
    h.restored = 1;
    CHECK(h_restart(&h) == GZ_OK);
    const uint8_t *g = last_guard(&h, &len);
    CHECK(len && gz_get_u64(g + 40) == 23);               /* above the file's 22 and the backup's 0 */
    CHECK(gz_get_u16(g + 48) == 5 && len == 58 + 40);
    for (size_t i = 0; i < 4; i++)                        /* every epoch of the file, in its order, with its index */
        CHECK(guard_epoch(g, i) == later[i][0] && gz_get_u32(g + 54 + 8 * i) == later[i][1]);
    uint32_t fresh = guard_epoch(g, 4);
    CHECK(fresh != 0 && fresh != 0x1111 && fresh != 0x2222 && fresh != 0x3333 && gz_get_u32(g + 54 + 32) == 0);
    CHECK(gz_get_u64(g + 50 + 40) == 7);                  /* the rounds started are not forgotten */
    /* A plain restart, then another restore with the guard file as the node
     * last wrote it: nothing of the union is lost. */
    uint8_t written[58 + 8 * 40];
    memcpy(written, g, len);
    h.guard = written;
    h.guard_len = len;
    h.restored = 0;
    CHECK(h_restart(&h) == GZ_OK);
    h.restored = 1;
    CHECK(h_restart(&h) == GZ_OK);
    g = last_guard(&h, &len);
    CHECK(gz_get_u64(g + 40) == 24 && gz_get_u16(g + 48) == 6 && guard_epoch(g, 4) == fresh);
    for (size_t i = 0; i < 4; i++) CHECK(guard_epoch(g, i) == later[i][0] && gz_get_u32(g + 54 + 8 * i) == later[i][1]);
    CHECK(gz_get_u64(g + 50 + 48) == 7);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);

    /* The other way round: the file is OLDER than the journal (a guard file
     * put back from an export). The journal's list keeps its order; what
     * only the file has is older still. */
    static const uint32_t stale[2][2] = {{0x9999, 5}, {0, 9}};
    h_init(&h, 1, 1);
    h_start(&h);
    h.restored = 1;
    h_restart(&h);
    h_restart(&h); /* the journal: epochs 0, e1, e2; counter 2 */
    g = last_guard(&h, &len);
    uint32_t e1 = guard_epoch(g, 1), e2 = guard_epoch(g, 2);
    h.guard_len = make_guard(file, h.cfg.chain, 1, stale, 2, 0);
    h.guard = file;
    CHECK(h_restart(&h) == GZ_OK);
    g = last_guard(&h, &len);
    CHECK(gz_get_u64(g + 40) == 3 && gz_get_u16(g + 48) == 5);
    CHECK(guard_epoch(g, 0) == 0x9999 && guard_epoch(g, 1) == 0 && guard_epoch(g, 2) == e1 && guard_epoch(g, 3) == e2);
    CHECK(gz_get_u32(g + 54) == 5 && gz_get_u32(g + 54 + 8) == 9); /* epoch 0's higher index, from the file */
    h_free(&h);

    /* A file for another chain, or one that is not a guard, is as none. */
    h_init(&h, 1, 1);
    h_start(&h);
    uint8_t other[32];
    memset(other, 0x11, sizeof other);
    h.guard_len = make_guard(file, other, 22, later, 4, 7);
    h.guard = file;
    h.restored = 1;
    CHECK(h_restart(&h) == GZ_OK);
    g = last_guard(&h, &len);
    CHECK(gz_get_u64(g + 40) == 1 && gz_get_u16(g + 48) == 2 && !guard_has(g, 0x2222));
    h.guard_len = make_guard(file, h.cfg.chain, 22, later, 4, 7) - 1; /* cut short */
    CHECK(h_restart(&h) == GZ_OK);
    g = last_guard(&h, &len);
    CHECK(gz_get_u64(g + 40) == 2 && gz_get_u16(g + 48) == 3 && !guard_has(g, 0x2222));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);

    /* A file with more epochs than the node holds: the newest stay. */
    static uint32_t many[30][2];
    for (uint32_t i = 0; i < 30; i++) {
        many[i][0] = i == 0 ? 0 : 0x5000 + i;
        many[i][1] = i;
    }
    h_init(&h, 1, 1);
    h_start(&h);
    h.guard_len = make_guard(file, h.cfg.chain, 40, (const uint32_t (*)[2])many, 30, 3);
    h.guard = file;
    h.restored = 1;
    CHECK(h_restart(&h) == GZ_OK);
    g = last_guard(&h, &len);
    CHECK(gz_get_u64(g + 40) == 41 && gz_get_u16(g + 48) == 16);
    for (size_t i = 0; i < 15; i++) CHECK(guard_epoch(g, i) == 0x5000 + 15 + i && gz_get_u32(g + 54 + 8 * i) == 15 + i);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

int main(void)
{
    (void)ZERO;
    test_fresh_start();
    test_ping_pull();
    test_member_side();
    test_restore_batch();
    test_poison();
    test_caller_errors();
    test_unknown_area();
    test_two_engines();
    test_watch_registry();
    test_commands();
    test_connect();
    test_storage_that_is_not_a_journal();
    test_the_fence();
    test_restore_batch_alone();
    test_address_rule();
    test_connect_bad_address();
    test_saved_bad_target_does_not_stop_a_start();
    test_ping_table();
    test_ack_from_another_link();
    test_hello_inside_the_second_is_deferred();
    test_chain_routing();
    test_restore_epoch_redraw();
    test_guard_forgets_the_oldest_epoch();
    test_guard_file_is_not_overwritten_with_less();
    test_reserved_kind();
    return check_done();
}
