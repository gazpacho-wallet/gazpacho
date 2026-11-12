/* Tests for the node frame (core/gazpacho/node.c) and, at the end, the whole
 * path: event -> node -> action list -> runner -> executor, and the same after
 * a restart from stored records. */
#include "gazpacho/node.h"
#include "gazpacho/runner.h"
#include "../check.h"
#include <string.h>

static uint64_t g_now = 0x0102030405060708ull;
static int g_random_calls;

static void fill(void *ctx, uint32_t purpose, uint8_t *out, size_t len) { (void)ctx; (void)purpose; g_random_calls++; memset(out, 0x42, len); }
static uint64_t now_ms(void *ctx) { (void)ctx; return g_now; }

static const gz_ports_t PORTS = {{fill, NULL}, {now_ms, NULL}};

static gz_action_t slots[80];
static uint8_t bytes[4096];
static gz_action_list_t out;

static gz_event_t message_event(uint64_t peer, const uint8_t *data, size_t len)
{
    gz_event_t ev = {.kind = GZ_EVENT_MESSAGE_RECEIVED};
    ev.u.message.peer_id = peer;
    ev.u.message.bytes = (gz_bytes_t){data, len};
    return ev;
}

static const gz_event_t CONFIRMED = {.kind = GZ_EVENT_STORAGE_CONFIRMED};

static uint64_t be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = v << 8 | p[i];
    return v;
}

static void test_arguments(void)
{
    gz_node_t node;
    gz_ports_t no_clock = PORTS, no_random = PORTS;
    no_clock.clock.now_ms = NULL;
    no_random.random.fill = NULL;
    CHECK(gz_node_init(NULL, &PORTS) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_init(&node, NULL) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_init(&node, &no_clock) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_init(&node, &no_random) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    gz_event_t ev = message_event(1, NULL, 0);
    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_handle(NULL, &ev, &out) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_handle(&node, NULL, &out) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_handle(&node, &ev, NULL) == GZ_ERR_ARGUMENT);
    CHECK(out.count == 0);
}

static void test_ping_is_saved_then_answered(void)
{
    gz_node_t node;
    const uint8_t ping[7] = {'G', 'Z', 'P', 'I', 0xaa, 0xbb, 0xcc};
    gz_event_t ev = message_event(0x1f2e3d4c5b6a7988ull, ping, sizeof ping);
    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(out.count == 2);

    const gz_action_t *save = &out.slots[0], *send = &out.slots[1];
    CHECK(save->kind == GZ_ACTION_SAVE && save->u.save.n_records == 1);
    const gz_record_t *r = &save->u.save.records[0];
    CHECK(r->type == GZ_RECORD_TEST_PING && r->bytes.len == GZ_PING_RECORD_HEADER + 3);
    CHECK(be64(r->bytes.data) == 0x0102030405060708ull);            /* the clock port's time */
    CHECK(be64(r->bytes.data + 8) == 0x1f2e3d4c5b6a7988ull);        /* who to answer */
    CHECK(be64(r->bytes.data + 16) == 1);                           /* the first serial */
    CHECK(memcmp(r->bytes.data + 24, ping + 4, 3) == 0);

    const uint8_t pong[7] = {'G', 'Z', 'P', 'O', 0xaa, 0xbb, 0xcc};
    CHECK(send->kind == GZ_ACTION_SEND && send->u.send.peer_id == 0x1f2e3d4c5b6a7988ull);   /* the right peer */
    CHECK(send->u.send.bytes.len == 7 && memcmp(send->u.send.bytes.data, pong, 7) == 0);

    gz_action_list_reset(&out);                                     /* serials count up */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(be64(out.slots[0].u.save.records[0].bytes.data + 16) == 2);
}

/* When the batch recording a ping is confirmed, the runner has released the
 * reply, and the node records that. */
static void test_confirmation_records_the_reply_as_sent(void)
{
    gz_node_t node;
    const uint8_t ping[5] = {'G', 'Z', 'P', 'I', 1};
    gz_event_t ev = message_event(3, ping, sizeof ping);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_handle(&node, &CONFIRMED, &out) == GZ_OK && out.count == 0);  /* nothing awaited: nothing to do */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK && out.count == 4);

    gz_action_list_reset(&out);
    CHECK(gz_node_handle(&node, &CONFIRMED, &out) == GZ_OK && out.count == 1);  /* the first ping's batch */
    const gz_record_t *r = &out.slots[0].u.save.records[0];
    CHECK(out.slots[0].kind == GZ_ACTION_SAVE && r->type == GZ_RECORD_TEST_PING_SENT);
    CHECK(r->bytes.len == 8 && be64(r->bytes.data) == 1);

    gz_action_list_reset(&out);
    CHECK(gz_node_handle(&node, &CONFIRMED, &out) == GZ_OK && out.count == 1);  /* the second ping's batch */
    CHECK(be64(out.slots[0].u.save.records[0].bytes.data) == 2);

    gz_action_list_reset(&out);                                                 /* the two "sent" batches */
    CHECK(gz_node_handle(&node, &CONFIRMED, &out) == GZ_OK && out.count == 0);
    CHECK(gz_node_handle(&node, &CONFIRMED, &out) == GZ_OK && out.count == 0);
    CHECK(node.n_awaiting == 0);

    /* No room for the "sent" record: nothing changes, and the same confirmation can be handled again. */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    gz_action_list_init(&out, slots, 0, bytes, sizeof bytes);
    CHECK(gz_node_handle(&node, &CONFIRMED, &out) == GZ_ERR_NO_SPACE && node.n_awaiting == 1);
    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_handle(&node, &CONFIRMED, &out) == GZ_OK && out.count == 1 && node.n_awaiting == 1);
}

static void test_limit_on_batches_awaiting_confirmation(void)
{
    gz_node_t node;
    const uint8_t ping[5] = {'G', 'Z', 'P', 'I', 1};
    gz_event_t ev = message_event(3, ping, sizeof ping);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    for (int i = 0; i < GZ_NODE_MAX_AWAITING; i++) {
        gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
        CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    }
    gz_action_list_reset(&out);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_ERR_NO_SPACE && out.count == 0);
    CHECK(gz_node_handle(&node, &CONFIRMED, &out) == GZ_OK && out.count == 1);  /* one confirmed: its "sent" batch takes the place */
    gz_action_list_reset(&out);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_ERR_NO_SPACE);
}

static void test_ping_sizes(void)
{
    gz_node_t node;
    uint8_t ping[GZ_PING_PREFIX_LEN + GZ_PING_MAX_PAYLOAD + 1] = {'G', 'Z', 'P', 'I'};
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);

    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    gz_event_t ev = message_event(1, ping, GZ_PING_PREFIX_LEN);     /* no payload */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK && out.count == 2);
    CHECK(out.slots[0].u.save.records[0].bytes.len == GZ_PING_RECORD_HEADER && out.slots[1].u.send.bytes.len == 4);

    gz_action_list_reset(&out);
    ev = message_event(1, ping, GZ_PING_PREFIX_LEN + GZ_PING_MAX_PAYLOAD);   /* the largest */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK && out.count == 2);
    CHECK(out.slots[1].u.send.bytes.len == GZ_PING_PREFIX_LEN + GZ_PING_MAX_PAYLOAD);

    gz_action_list_reset(&out);
    ev = message_event(1, ping, sizeof ping);                       /* one byte too long: ignored */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK && out.count == 0);
}

static void test_everything_else_does_nothing(void)
{
    gz_node_t node;
    const uint8_t other[5] = {'G', 'Z', 'P', 'O', 1};
    const uint8_t brief[3] = {'G', 'Z', 'P'};
    gz_event_t events[8];
    size_t n = 0;
    events[n++] = message_event(1, other, sizeof other);
    events[n++] = message_event(1, brief, sizeof brief);
    events[n++] = message_event(1, NULL, 0);
    events[n] = (gz_event_t){.kind = GZ_EVENT_TIMER_FIRED}; events[n++].u.timer.timer_id = 4;
    events[n] = (gz_event_t){.kind = GZ_EVENT_CHAIN}; events[n++].u.chain.kind = GZ_CHAIN_NEW_TIP;
    events[n] = (gz_event_t){.kind = GZ_EVENT_USER_COMMAND}; events[n++].u.user.bytes = (gz_bytes_t){other, 5};
    events[n] = (gz_event_t){.kind = GZ_EVENT_PEER_CONNECTED}; events[n++].u.peer.peer_id = 3;
    events[n] = (gz_event_t){.kind = GZ_EVENT_PEER_DISCONNECTED}; events[n++].u.peer.peer_id = 3;

    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    for (size_t i = 0; i < n; i++)
        CHECK(gz_node_handle(&node, &events[i], &out) == GZ_OK && out.count == 0);
}

static void test_no_space_changes_nothing(void)
{
    gz_node_t node;
    const uint8_t ping[6] = {'G', 'Z', 'P', 'I', 1, 2};
    gz_event_t ev = message_event(1, ping, sizeof ping);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);

    gz_action_list_init(&out, slots, 1, bytes, sizeof bytes);       /* room for the save only */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_ERR_NO_SPACE);
    CHECK(out.count == 0 && out.used == 0 && node.n_awaiting == 0);

    gz_action_list_init(&out, slots, 8, bytes, 52);                 /* bytes run out at the reply */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_ERR_NO_SPACE);
    CHECK(out.count == 0 && out.used == 0 && node.n_awaiting == 0);

    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK && out.count == 2);
    CHECK(be64(out.slots[0].u.save.records[0].bytes.data + 16) == 1);   /* the serial was not used up */
}

/* ---- starting from stored records ---- */

/* A storage reader over an array of records, one record to a batch. */
typedef struct { const gz_record_t *records; size_t n, at, walks; } array_reader_t;

static int array_next(void *ctx, gz_stored_batch_t *batch)
{
    array_reader_t *r = ctx;
    if (r->at >= r->n) return 0;
    batch->id = (gz_batch_id_t){1, r->at + 1};
    batch->records = &r->records[r->at++];
    batch->n_records = 1;
    return 1;
}

static void array_rewind(void *ctx)
{
    array_reader_t *r = ctx;
    r->at = 0;
    r->walks++;
}

static array_reader_t g_array;

static gz_storage_reader_t reader_over(const gz_record_t *records, size_t n)
{
    g_array = (array_reader_t){records, n, 0, 0};
    return (gz_storage_reader_t){array_next, array_rewind, &g_array, 2};
}

/* Run a whole start, every step's actions appended to `out`. Returns the
 * number of steps it took, or 0 if a step failed. */
static size_t start_fully(gz_node_t *node, const gz_storage_reader_t *reader)
{
    int more = 1;
    size_t steps = 0;
    while (more) {
        if (gz_node_start(node, reader, &out, &more) != GZ_OK) return 0;
        steps++;
    }
    return steps;
}

static uint8_t g_bodies[200][32];

static gz_record_t ping_record(size_t slot, uint64_t peer, uint64_t serial, uint8_t payload)
{
    uint8_t *body = g_bodies[slot];
    memset(body, 0, 32);
    for (int i = 0; i < 8; i++) body[8 + i] = (uint8_t)(peer >> (8 * (7 - i)));
    for (int i = 0; i < 8; i++) body[16 + i] = (uint8_t)(serial >> (8 * (7 - i)));
    body[GZ_PING_RECORD_HEADER] = payload;
    return (gz_record_t){GZ_RECORD_TEST_PING, {body, GZ_PING_RECORD_HEADER + 1}};
}

static gz_record_t sent_record(size_t slot, uint64_t serial_a, uint64_t serial_b)
{
    uint8_t *body = g_bodies[slot];
    for (int i = 0; i < 8; i++) body[i] = (uint8_t)(serial_a >> (8 * (7 - i)));
    for (int i = 0; i < 8; i++) body[8 + i] = (uint8_t)(serial_b >> (8 * (7 - i)));
    return (gz_record_t){GZ_RECORD_TEST_PING_SENT, {body, serial_b ? 16 : 8}};
}

static int is_pong(const gz_action_t *a, uint64_t peer, uint8_t payload)
{
    const uint8_t pong[5] = {'G', 'Z', 'P', 'O', payload};
    return a->kind == GZ_ACTION_SEND && a->u.send.peer_id == peer && a->u.send.bytes.len == 5 &&
           memcmp(a->u.send.bytes.data, pong, 5) == 0;
}

static void test_start_arguments(void)
{
    gz_node_t node;
    int more = 7;
    gz_storage_reader_t reader = reader_over(NULL, 0), no_next = reader, no_rewind = reader;
    no_next.next = NULL;
    no_rewind.rewind = NULL;
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_start(NULL, &reader, &out, &more) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_start(&node, NULL, &out, &more) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_start(&node, &no_next, &out, &more) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_start(&node, &no_rewind, &out, &more) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_start(&node, &reader, NULL, &more) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_start(&node, &reader, &out, NULL) == GZ_ERR_ARGUMENT);
    CHECK(out.count == 0 && more == 7);
    CHECK(gz_node_start(&node, &reader, &out, &more) == GZ_OK && out.count == 0 && more == 0);   /* empty storage */
}

static void test_start_resends_every_reply_not_recorded_as_sent(void)
{
    gz_node_t node;
    uint8_t other[4] = {1, 2, 3, 4}, runt[4] = {0};
    gz_record_t stored[9];
    stored[0] = ping_record(0, 11, 1, 0x61);
    stored[1] = ping_record(1, 22, 2, 0x62);
    stored[2] = sent_record(2, 2, 0);                               /* the second was sent */
    stored[3] = ping_record(3, 33, 3, 0x63);
    stored[4] = (gz_record_t){0x1234, {other, 4}};                  /* a record of some other kind */
    stored[5] = (gz_record_t){GZ_RECORD_TEST_PING, {runt, 4}};      /* too short to be a ping record */
    stored[6] = ping_record(6, 44, 4, 0x64);
    stored[7] = ping_record(7, 55, 5, 0x65);
    stored[8] = sent_record(8, 9, 4);                               /* one record may name several */

    gz_storage_reader_t reader = reader_over(stored + 4, 2);
    gz_action_list_init(&out, slots, 80, bytes, sizeof bytes);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    CHECK(start_fully(&node, &reader) == 1 && out.count == 0);      /* nothing of ours in storage */
    reader = reader_over(stored + 1, 2);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    CHECK(start_fully(&node, &reader) == 1 && out.count == 0);      /* everything stored was sent */

    /* Pings 1, 3 and 5 have no "sent" record: resent oldest first, then one record for the three. */
    reader = reader_over(stored, 9);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    CHECK(start_fully(&node, &reader) == 2 && out.count == 4);     /* one step resends, one records */
    CHECK(is_pong(&out.slots[0], 11, 0x61) && is_pong(&out.slots[1], 33, 0x63) && is_pong(&out.slots[2], 55, 0x65));
    const gz_record_t *r = &out.slots[3].u.save.records[0];
    CHECK(out.slots[3].kind == GZ_ACTION_SAVE && r->type == GZ_RECORD_TEST_PING_SENT && r->bytes.len == 24);
    CHECK(be64(r->bytes.data) == 1 && be64(r->bytes.data + 8) == 3 && be64(r->bytes.data + 16) == 5);
    CHECK(node.n_awaiting == 1);                                    /* that save will be confirmed like any other */

    /* New pings continue the serials past everything stored. */
    const uint8_t ping[5] = {'G', 'Z', 'P', 'I', 7};
    gz_event_t ev = message_event(1, ping, sizeof ping);
    gz_action_list_reset(&out);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(be64(out.slots[0].u.save.records[0].bytes.data + 16) == 6);

    /* No room for a step's actions: nothing is appended, and the same step can be asked for again. */
    int more = 0;
    reader = reader_over(stored, 9);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    gz_action_list_init(&out, slots, 2, bytes, sizeof bytes);
    CHECK(gz_node_start(&node, &reader, &out, &more) == GZ_ERR_NO_SPACE && out.count == 0 && out.used == 0 && more == 0);
    gz_action_list_init(&out, slots, 80, bytes, sizeof bytes);
    CHECK(gz_node_start(&node, &reader, &out, &more) == GZ_OK && out.count == 3 && more == 1);
    CHECK(gz_node_start(&node, &reader, &out, &more) == GZ_OK && out.count == 4 && more == 0);
}

/* More to resend than one step takes: the start comes in steps, each a list
 * of at most GZ_NODE_START_CHUNK replies or one record, replies first, and
 * says when it is done. Fifty stored pings, every third one already recorded
 * as sent. */
static void test_start_comes_in_steps(void)
{
    static gz_record_t stored[70];
    gz_node_t node;
    size_t n = 0, unsent = 0, sends = 0, saves = 0, steps = 0, recorded = 0;
    uint64_t last_serial = 0;
    int more = 1, in_order = 1, sizes_ok = 1;
    for (uint64_t serial = 1; serial <= 50; serial++) {
        stored[n] = ping_record(n, 100 + serial, serial, (uint8_t)serial); n++;
        if (serial % 3 == 0) { stored[n] = sent_record(n, serial, 0); n++; }
        else unsent++;
    }
    gz_storage_reader_t reader = reader_over(stored, n);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    while (more) {
        gz_action_list_init(&out, slots, 80, bytes, sizeof bytes);
        if (gz_node_start(&node, &reader, &out, &more) != GZ_OK) break;
        steps++;
        sizes_ok &= out.count >= 1 && out.count <= GZ_NODE_START_CHUNK;
        sizes_ok &= out.slots[0].kind != GZ_ACTION_SAVE || out.count == 1;   /* a record has a step to itself */
        for (size_t i = 0; i < out.count; i++) {
            const gz_action_t *a = &out.slots[i];
            if (a->kind == GZ_ACTION_SEND) {
                uint64_t serial = a->u.send.peer_id - 100;
                in_order &= saves == 0;                                      /* every reply before the first record */
                in_order &= serial > last_serial && serial % 3 != 0 && is_pong(a, 100 + serial, (uint8_t)serial);
                last_serial = serial;
                sends++;
            } else {
                saves++;
                recorded += a->u.save.records[0].bytes.len / 8;
            }
        }
    }
    CHECK(more == 0 && saves >= 5 && steps == 2 * saves);
    CHECK(sends == unsent && recorded == unsent && in_order && sizes_ok);
    CHECK(node.n_awaiting == saves && node.next_serial == 51);
    CHECK(g_array.walks >= 2 * steps);                              /* it walked storage, it was not handed an array */
}

/* A node tracks at most GZ_NODE_MAX_AWAITING of its own batches. A start that
 * would need more stops with an error, which is fatal for that start. */
static void test_start_stops_at_the_limit_of_batches_awaiting(void)
{
    enum { N = GZ_NODE_MAX_AWAITING * GZ_NODE_START_CHUNK + 8 };
    static gz_record_t stored[N];
    static uint8_t bodies[N][GZ_PING_RECORD_HEADER];
    gz_node_t node;
    size_t steps = 0;
    int more = 1;
    gz_status_t st = GZ_OK;
    for (size_t i = 0; i < N; i++) {                                /* more unsent pings than the node can track */
        memset(bodies[i], 0, GZ_PING_RECORD_HEADER);
        for (int k = 0; k < 8; k++) bodies[i][16 + k] = (uint8_t)((uint64_t)(i + 1) >> (8 * (7 - k)));
        stored[i] = (gz_record_t){GZ_RECORD_TEST_PING, {bodies[i], GZ_PING_RECORD_HEADER}};
    }
    gz_storage_reader_t reader = reader_over(stored, N);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    while (more && st == GZ_OK) {
        gz_action_list_init(&out, slots, 80, bytes, sizeof bytes);
        st = gz_node_start(&node, &reader, &out, &more);
        steps += st == GZ_OK;
    }
    CHECK(st == GZ_ERR_NO_SPACE && steps == N / GZ_NODE_START_CHUNK + GZ_NODE_MAX_AWAITING && out.count == 0);
}

/* ---- end to end ---- */

typedef struct { gz_action_kind_t kind; uint64_t peer; gz_batch_id_t batch; uint32_t type; uint8_t record[96]; size_t record_len; } seen_t;
static seen_t g_seen[16];
static size_t g_seen_n;

static void see(void *ctx, const gz_action_t *a)
{
    (void)ctx;
    seen_t s = {a->kind, 0, {0, 0}, 0, {0}, 0};
    if (a->kind == GZ_ACTION_SEND) s.peer = a->u.send.peer_id;
    if (a->kind == GZ_ACTION_SAVE) {
        s.batch = a->u.save.batch;
        s.type = a->u.save.records[0].type;
        s.record_len = a->u.save.records[0].bytes.len;
        memcpy(s.record, a->u.save.records[0].bytes.data, s.record_len);
    }
    if (g_seen_n < 16) g_seen[g_seen_n++] = s;
}

static void test_event_to_executor_and_again_after_a_restart(void)
{
    static gz_runner_slot_t r_slots[8];
    static uint8_t r_bytes[512];
    gz_node_t node;
    gz_runner_t runner;
    const uint8_t ping[5] = {'G', 'Z', 'P', 'I', 9};
    gz_event_t ev = message_event(2, ping, sizeof ping);
    gz_storage_reader_t reader = reader_over(NULL, 0);

    g_seen_n = 0;
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    CHECK(gz_runner_init(&runner, r_slots, 8, r_bytes, sizeof r_bytes, 1, see, NULL) == GZ_OK);
    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(start_fully(&node, &reader) == 1);
    CHECK(gz_runner_submit(&runner, &out) == GZ_OK && g_seen_n == 0);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(gz_runner_submit(&runner, &out) == GZ_OK);
    CHECK(g_seen_n == 1 && g_seen[0].kind == GZ_ACTION_SAVE);       /* the reply waits */
    CHECK(g_seen[0].batch.incarnation == 1 && g_seen[0].batch.sequence == 1);

    /* The program stops here: the batch is stored, the reply never left. A new
     * program starts from what storage holds. */
    gz_record_t stored[2] = {{GZ_RECORD_TEST_PING, {g_seen[0].record, g_seen[0].record_len}}, {0, {NULL, 0}}};
    reader = reader_over(stored, 1);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    CHECK(gz_runner_init(&runner, r_slots, 8, r_bytes, sizeof r_bytes, 2, see, NULL) == GZ_OK);
    gz_action_list_reset(&out);
    CHECK(start_fully(&node, &reader) == 2);
    CHECK(gz_runner_submit(&runner, &out) == GZ_OK);
    CHECK(g_seen_n == 3 && g_seen[1].kind == GZ_ACTION_SEND && g_seen[1].peer == 2);    /* sent again, to the same peer */
    CHECK(g_seen[2].kind == GZ_ACTION_SAVE && g_seen[2].type == GZ_RECORD_TEST_PING_SENT);   /* and recorded as sent */

    /* Stop again once that record is stored: this time nothing is resent. */
    stored[1] = (gz_record_t){GZ_RECORD_TEST_PING_SENT, {g_seen[2].record, g_seen[2].record_len}};
    reader = reader_over(stored, 2);
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    CHECK(gz_runner_init(&runner, r_slots, 8, r_bytes, sizeof r_bytes, 3, see, NULL) == GZ_OK);
    gz_action_list_reset(&out);
    CHECK(start_fully(&node, &reader) == 1 && out.count == 0);

    /* And the ordinary path on the new program: saved, confirmed, answered, recorded. */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(gz_runner_submit(&runner, &out) == GZ_OK && g_seen_n == 4);
    CHECK(g_seen[3].batch.incarnation == 3 && g_seen[3].batch.sequence == 1);
    CHECK(be64(g_seen[3].record + 16) == 2);                        /* the serial continues from storage */
    gz_event_t stored_event = {.kind = GZ_EVENT_STORAGE_CONFIRMED};
    stored_event.u.storage.batch = g_seen[3].batch;
    CHECK(gz_runner_confirm(&runner, stored_event.u.storage.batch) == GZ_OK);
    CHECK(g_seen_n == 5 && g_seen[4].kind == GZ_ACTION_SEND && g_seen[4].peer == 2);
    gz_action_list_reset(&out);
    CHECK(gz_node_handle(&node, &stored_event, &out) == GZ_OK && out.count == 1);
    CHECK(gz_runner_submit(&runner, &out) == GZ_OK);
    CHECK(g_seen_n == 6 && g_seen[5].type == GZ_RECORD_TEST_PING_SENT && be64(g_seen[5].record) == 2);
}

int main(void)
{
    test_arguments();
    test_ping_is_saved_then_answered();
    test_confirmation_records_the_reply_as_sent();
    test_limit_on_batches_awaiting_confirmation();
    test_ping_sizes();
    test_everything_else_does_nothing();
    test_no_space_changes_nothing();
    test_start_arguments();
    test_start_resends_every_reply_not_recorded_as_sent();
    test_start_comes_in_steps();
    test_start_stops_at_the_limit_of_batches_awaiting();
    test_event_to_executor_and_again_after_a_restart();
    CHECK(g_random_calls == 0);     /* nothing in the frame draws randomness yet */
    return check_done();
}
