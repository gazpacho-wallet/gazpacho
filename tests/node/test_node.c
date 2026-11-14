/* The composite node with the test engine: the start, pings and the pull
 * model, the restore batch, views, two engines, the watch registry,
 * commands, poisoning after an error (composite-node.md 8.2, 10). */
#include "node_test.h"

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
    gz_storage_reader_t rd = {h_next, h_rewind, &h, h.incarnation, 0};
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
    return check_done();
}
