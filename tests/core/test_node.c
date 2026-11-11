/* Tests for the node frame (core/gazpacho/node.c) and, at the end, the whole
 * path: event -> node -> action list -> runner -> executor. */
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

static void test_init_arguments(void)
{
    gz_node_t node;
    gz_ports_t no_clock = PORTS, no_random = PORTS;
    no_clock.clock.now_ms = NULL;
    no_random.random.fill = NULL;
    CHECK(gz_node_init(NULL, &PORTS, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_init(&node, NULL, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_init(&node, &no_clock, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_init(&node, &no_random, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_init(&node, &PORTS, 1) == GZ_OK);
    gz_event_t ev = message_event(1, NULL, 0);
    CHECK(gz_node_handle(NULL, &ev, &out) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_handle(&node, NULL, &out) == GZ_ERR_ARGUMENT);
    CHECK(gz_node_handle(&node, &ev, NULL) == GZ_ERR_ARGUMENT);
}

static void test_ping_is_saved_then_answered(void)
{
    gz_node_t node;
    const uint8_t ping[7] = {'G', 'Z', 'P', 'I', 0xaa, 0xbb, 0xcc};
    gz_event_t ev = message_event(31, ping, sizeof ping);
    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_init(&node, &PORTS, 500) == GZ_OK);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(out.count == 2);

    const gz_action_t *save = &out.slots[0], *send = &out.slots[1];
    CHECK(save->kind == GZ_ACTION_SAVE && save->u.save.batch_id == 500 && save->u.save.n_records == 1);
    const gz_record_t *r = &save->u.save.records[0];
    const uint8_t stamp[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(r->type == GZ_RECORD_TEST_PING && r->bytes.len == 11);
    CHECK(memcmp(r->bytes.data, stamp, 8) == 0);                    /* the clock port's time */
    CHECK(memcmp(r->bytes.data + 8, ping + 4, 3) == 0);

    const uint8_t pong[7] = {'G', 'Z', 'P', 'O', 0xaa, 0xbb, 0xcc};
    CHECK(send->kind == GZ_ACTION_SEND && send->u.send.peer_id == 31);
    CHECK(send->u.send.bytes.len == 7 && memcmp(send->u.send.bytes.data, pong, 7) == 0);

    gz_action_list_reset(&out);                                     /* batch numbers count up */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(out.slots[0].u.save.batch_id == 501);
}

static void test_ping_sizes(void)
{
    gz_node_t node;
    uint8_t ping[GZ_PING_PREFIX_LEN + GZ_PING_MAX_PAYLOAD + 1] = {'G', 'Z', 'P', 'I'};
    CHECK(gz_node_init(&node, &PORTS, 1) == GZ_OK);

    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    gz_event_t ev = message_event(1, ping, GZ_PING_PREFIX_LEN);     /* no payload */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK && out.count == 2);
    CHECK(out.slots[0].u.save.records[0].bytes.len == 8 && out.slots[1].u.send.bytes.len == 4);

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
    events[n] = (gz_event_t){.kind = GZ_EVENT_STORAGE_CONFIRMED}; events[n++].u.storage.batch_id = 9;

    CHECK(gz_node_init(&node, &PORTS, 1) == GZ_OK);
    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    for (size_t i = 0; i < n; i++)
        CHECK(gz_node_handle(&node, &events[i], &out) == GZ_OK && out.count == 0);
    CHECK(node.next_batch_id == 1);
}

static void test_no_space_changes_nothing(void)
{
    gz_node_t node;
    const uint8_t ping[6] = {'G', 'Z', 'P', 'I', 1, 2};
    gz_event_t ev = message_event(1, ping, sizeof ping);
    CHECK(gz_node_init(&node, &PORTS, 70) == GZ_OK);

    gz_action_list_init(&out, slots, 1, bytes, sizeof bytes);       /* room for the save only */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_ERR_NO_SPACE);
    CHECK(out.count == 0 && out.used == 0 && node.next_batch_id == 70);

    gz_action_list_init(&out, slots, 8, bytes, 36);                 /* bytes run out at the reply */
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_ERR_NO_SPACE);
    CHECK(out.count == 0 && out.used == 0 && node.next_batch_id == 70);

    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(out.slots[0].u.save.batch_id == 70);                      /* the number was not used up */
}

/* ---- end to end ---- */

static gz_action_kind_t g_seen[8];
static size_t g_seen_n;
static void see(void *ctx, const gz_action_t *a) { (void)ctx; if (g_seen_n < 8) g_seen[g_seen_n++] = a->kind; }

static void test_event_to_executor(void)
{
    static gz_action_t r_slots[8];
    static uint8_t r_bytes[512];
    gz_node_t node;
    gz_runner_t runner;
    const uint8_t ping[5] = {'G', 'Z', 'P', 'I', 9};
    gz_event_t ev = message_event(2, ping, sizeof ping);

    g_seen_n = 0;
    CHECK(gz_node_init(&node, &PORTS, 1) == GZ_OK);
    CHECK(gz_runner_init(&runner, r_slots, 8, r_bytes, sizeof r_bytes, see, NULL) == GZ_OK);
    gz_action_list_init(&out, slots, 8, bytes, sizeof bytes);
    CHECK(gz_node_handle(&node, &ev, &out) == GZ_OK);
    CHECK(gz_runner_submit(&runner, &out) == GZ_OK);
    CHECK(g_seen_n == 1 && g_seen[0] == GZ_ACTION_SAVE);            /* the reply waits */

    gz_event_t stored = {.kind = GZ_EVENT_STORAGE_CONFIRMED};
    stored.u.storage.batch_id = 1;
    CHECK(gz_runner_confirm(&runner, stored.u.storage.batch_id) == GZ_OK);
    gz_action_list_reset(&out);
    CHECK(gz_node_handle(&node, &stored, &out) == GZ_OK && out.count == 0);
    CHECK(g_seen_n == 2 && g_seen[1] == GZ_ACTION_SEND);
}

int main(void)
{
    test_init_arguments();
    test_ping_is_saved_then_answered();
    test_ping_sizes();
    test_everything_else_does_nothing();
    test_no_space_changes_nothing();
    test_event_to_executor();
    CHECK(g_random_calls == 0);     /* nothing in the frame draws randomness yet */
    return check_done();
}
