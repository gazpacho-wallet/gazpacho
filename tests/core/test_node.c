/* Tests for the node frame (core/gazpacho/node.c) and, at the end, the whole
 * path: event -> node -> action list -> runner -> executor, and the same after
 * a restart from stored records. */
#include "gazpacho/node.h"
#include "gazpacho/runner.h"
#include "../check.h"
#include <string.h>

static uint64_t g_now = 0x0102030405060708ull;
static int g_random_calls;

static void fill(void *ctx, uint8_t *out, size_t len) { (void)ctx; g_random_calls++; memset(out, 0x42, len); }
static uint64_t now_ms(void *ctx) { (void)ctx; return g_now; }

static const gz_ports_t PORTS = {{fill, NULL}, {now_ms, NULL}};

static gz_action_t slots[8];
static uint8_t bytes[512];
static gz_action_list_t out;

static gz_event_t message_event(uint64_t peer, const uint8_t *data, size_t len)
{
    gz_event_t ev = {.kind = GZ_EVENT_MESSAGE_RECEIVED};
    ev.u.message.peer_id = peer;
    ev.u.message.bytes = (gz_bytes_t){data, len};
    return ev;
}

static void test_arguments(void)
{
    gz_node_t node;
    gz_ports_t no_clock = PORTS, no_random = PORTS;
    gz_record_t record = {0, {NULL, 0}};
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
    CHECK(gz_node_start(NULL, &record, 1, &out) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_start(&node, &record, 1, NULL) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_start(&node, NULL, 1, &out) == GZ_ERR_ARGUMENT);
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
    const uint8_t stamp[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t peer[8] = {0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88};
    CHECK(r->type == GZ_RECORD_TEST_PING && r->bytes.len == GZ_PING_RECORD_HEADER + 3);
    CHECK(memcmp(r->bytes.data, stamp, 8) == 0);                    /* the clock port's time */
    CHECK(memcmp(r->bytes.data + 8, peer, 8) == 0);                 /* who to answer */
    CHECK(memcmp(r->bytes.data + 16, ping + 4, 3) == 0);

    const uint8_t pong[7] = {'G', 'Z', 'P', 'O', 0xaa, 0xbb, 0xcc};
    CHECK(send->kind == GZ_ACTION_SEND && send->u.send.peer_id == 0x1f2e3d4c5b6a7988ull);   /* the right peer */
    CHECK(send->u.send.bytes.len == 7 && memcmp(send->u.send.bytes.data, pong, 7) == 0);
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
    events[n] = (gz_event_t){.kind = GZ_EVENT_STORAGE_CONFIRMED}; events[n++].u.storage.batch.sequence = 9;

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
    CHECK(out.count == 0 && out.used == 0);

    gz_action_list_init(&out, slots, 8, bytes, 44);                 /* bytes run out at the reply */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_ERR_NO_SPACE);
    CHECK(out.count == 0 && out.used == 0);

    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK && out.count == 2);
}

/* ---- starting from stored records ---- */

static size_t ping_record(uint8_t *body, uint64_t peer, uint8_t payload)
{
    memset(body, 0, GZ_PING_RECORD_HEADER);
    for (int i = 0; i < 8; i++) body[8 + i] = (uint8_t)(peer >> (8 * (7 - i)));
    body[GZ_PING_RECORD_HEADER] = payload;
    return GZ_PING_RECORD_HEADER + 1;
}

static void test_start_resends_the_newest_saved_reply(void)
{
    gz_node_t node;
    uint8_t first[32], second[32], other[4] = {1, 2, 3, 4}, runt[4] = {0};
    gz_record_t stored[4];
    stored[0] = (gz_record_t){GZ_RECORD_TEST_PING, {first, ping_record(first, 11, 0x61)}};
    stored[1] = (gz_record_t){GZ_RECORD_TEST_PING, {second, ping_record(second, 22, 0x62)}};
    stored[2] = (gz_record_t){0x1234, {other, 4}};                  /* a record of some other kind */
    stored[3] = (gz_record_t){GZ_RECORD_TEST_PING, {runt, 4}};      /* too short to be a ping record */
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);

    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_start(&node, NULL, 0, &out) == GZ_OK && out.count == 0);      /* empty storage: nothing to do */
    CHECK(gz_node_start(&node, stored + 2, 2, &out) == GZ_OK && out.count == 0);

    CHECK(gz_node_start(&node, stored, 4, &out) == GZ_OK && out.count == 1);
    const uint8_t pong[5] = {'G', 'Z', 'P', 'O', 0x62};
    CHECK(out.slots[0].kind == GZ_ACTION_SEND && out.slots[0].u.send.peer_id == 22);
    CHECK(out.slots[0].u.send.bytes.len == 5 && memcmp(out.slots[0].u.send.bytes.data, pong, 5) == 0);

    gz_action_list_init(&out, slots, 0, bytes, sizeof bytes);       /* no room: nothing changes */
    CHECK(gz_node_start(&node, stored, 4, &out) == GZ_ERR_NO_SPACE && out.count == 0 && out.used == 0);
}

/* ---- end to end ---- */

typedef struct { gz_action_kind_t kind; uint64_t peer; gz_batch_id_t batch; uint8_t record[96]; size_t record_len; } seen_t;
static seen_t g_seen[8];
static size_t g_seen_n;

static void see(void *ctx, const gz_action_t *a)
{
    (void)ctx;
    seen_t s = {a->kind, 0, {0, 0}, {0}, 0};
    if (a->kind == GZ_ACTION_SEND) s.peer = a->u.send.peer_id;
    if (a->kind == GZ_ACTION_SAVE) {
        s.batch = a->u.save.batch;
        s.record_len = a->u.save.records[0].bytes.len;
        memcpy(s.record, a->u.save.records[0].bytes.data, s.record_len);
    }
    if (g_seen_n < 8) g_seen[g_seen_n++] = s;
}

static void test_event_to_executor_and_again_after_a_restart(void)
{
    static gz_runner_slot_t r_slots[8];
    static uint8_t r_bytes[512];
    gz_node_t node;
    gz_runner_t runner;
    const uint8_t ping[5] = {'G', 'Z', 'P', 'I', 9};
    gz_event_t ev = message_event(2, ping, sizeof ping);

    g_seen_n = 0;
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    CHECK(gz_runner_init(&runner, r_slots, 8, r_bytes, sizeof r_bytes, 1, see, NULL) == GZ_OK);
    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_start(&node, NULL, 0, &out) == GZ_OK);
    CHECK(gz_runner_submit(&runner, &out) == GZ_OK && g_seen_n == 0);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(gz_runner_submit(&runner, &out) == GZ_OK);
    CHECK(g_seen_n == 1 && g_seen[0].kind == GZ_ACTION_SAVE);       /* the reply waits */
    CHECK(g_seen[0].batch.incarnation == 1 && g_seen[0].batch.sequence == 1);

    /* The program stops here: the batch is stored, the reply never left. A new
     * program starts from what storage holds. */
    gz_record_t stored = {GZ_RECORD_TEST_PING, {g_seen[0].record, g_seen[0].record_len}};
    CHECK(gz_node_init(&node, &PORTS) == GZ_OK);
    CHECK(gz_runner_init(&runner, r_slots, 8, r_bytes, sizeof r_bytes, 2, see, NULL) == GZ_OK);
    gz_action_list_reset(&out);
    CHECK(gz_node_start(&node, &stored, 1, &out) == GZ_OK);
    CHECK(gz_runner_submit(&runner, &out) == GZ_OK);
    CHECK(g_seen_n == 2 && g_seen[1].kind == GZ_ACTION_SEND && g_seen[1].peer == 2);    /* sent again, to the same peer */

    /* And the ordinary path on the new program: saved, confirmed, answered. */
    gz_action_list_reset(&out);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(gz_runner_submit(&runner, &out) == GZ_OK && g_seen_n == 3);
    CHECK(g_seen[2].batch.incarnation == 2 && g_seen[2].batch.sequence == 1);
    gz_event_t stored_event = {.kind = GZ_EVENT_STORAGE_CONFIRMED};
    stored_event.u.storage.batch = g_seen[2].batch;
    CHECK(gz_runner_confirm(&runner, stored_event.u.storage.batch) == GZ_OK);
    gz_action_list_reset(&out);
    CHECK(gz_node_handle(&node, &stored_event, &out) == GZ_OK && out.count == 0);
    CHECK(g_seen_n == 4 && g_seen[3].kind == GZ_ACTION_SEND && g_seen[3].peer == 2);
}

int main(void)
{
    test_arguments();
    test_ping_is_saved_then_answered();
    test_ping_sizes();
    test_everything_else_does_nothing();
    test_no_space_changes_nothing();
    test_start_resends_the_newest_saved_reply();
    test_event_to_executor_and_again_after_a_restart();
    CHECK(g_random_calls == 0);     /* nothing in the frame draws randomness yet */
    return check_done();
}
