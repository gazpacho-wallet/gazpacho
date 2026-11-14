/* List sizing (composite-node.md 8.3): the static assertion, the room check
 * before a call, and the worst steps of the test engine within its declared
 * bounds (the composite's test-build check, which would return GZ_ERR_BUG),
 * the rest of a large answer going out one chunk per continuation timer. */
#include "node_test.h"
#include "internal.h"

/* The same sum composite.c asserts, so that a change to an engine's worst
 * step that breaks it fails here by name too. */
_Static_assert(NP_MAX_STEP_ACTIONS + GZ_NODE_N_TEST * TE_MAX_STEP_ACTIONS + NP_MAX_LISTED * TS_MAX_STEP_ACTIONS +
                       SLOT_MAX_TIMERS <= GZ_NODE_LIST_ACTIONS,
               "the list's actions");
_Static_assert(NP_MAX_STEP_BYTES + GZ_NODE_N_TEST * TE_MAX_STEP_BYTES + NP_MAX_LISTED * TS_MAX_STEP_BYTES +
                       GZ_ACTION_MERGE_BYTES(GZ_NODE_LIST_ACTIONS) <= GZ_NODE_LIST_BYTES,
               "the list's bytes");
_Static_assert(TE_MAX_SEND + 1024 <= TE_MAX_STEP_BYTES, "a test SEND fits one step");
_Static_assert(TE_CHUNK_BYTES + 4096 <= TE_MAX_STEP_BYTES, "a resend chunk fits one step");

static void test_room(void)
{
    h_t h;
    gz_event_t ev;
    gz_action_list_t l;
    h_init(&h, 1, 1);
    h_start(&h);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_TIMER_FIRED;
    gz_action_list_init(&l, h.slots, GZ_NODE_LIST_ACTIONS - 1, h.bytes, GZ_NODE_LIST_BYTES);
    CHECK(gz_node_handle(h.n, &ev, &l) == GZ_ERR_NO_SPACE);
    gz_action_list_init(&l, h.slots, GZ_NODE_LIST_ACTIONS, h.bytes, GZ_NODE_LIST_BYTES - 1);
    CHECK(gz_node_handle(h.n, &ev, &l) == GZ_ERR_NO_SPACE);
    /* A list already holding actions has less room. */
    gz_action_list_init(&l, h.slots, GZ_NODE_LIST_ACTIONS, h.bytes, GZ_NODE_LIST_BYTES);
    gz_action_t t = {.kind = GZ_ACTION_SET_TIMER};
    CHECK(gz_action_list_add(&l, &t) == GZ_OK);
    CHECK(gz_node_handle(h.n, &ev, &l) == GZ_ERR_NO_SPACE);
    /* None of that poisons the node: exactly the declared room works. */
    gz_action_list_init(&l, h.slots, GZ_NODE_LIST_ACTIONS, h.bytes, GZ_NODE_LIST_BYTES);
    CHECK(gz_node_handle(h.n, &ev, &l) == GZ_OK);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* The largest steps: 60,000-byte replies, 40 of them answered on one hello. */
static void test_worst_steps(void)
{
    h_t h;
    gz_link_t l = h_host_link(9);
    uint8_t pad[4], payload[64];
    h_init(&h, 1, 2);
    h_start(&h);
    gz_put_u32(pad, 60000);
    h_arg_t a[1] = {{12, pad, 4}};
    CHECK(h_cmd(&h, GZ_TE_CMD_BIG_REPLY, a, 1) == GZ_OK);
    memset(payload, 'p', sizeof payload);
    for (int i = 0; i < 40; i++) CHECK(h_test_msg(&h, &l, "GZPI", payload, 64, GZ_AREA_TEST) == GZ_OK);
    CHECK(h.list.used <= GZ_NODE_LIST_BYTES);
    size_t m = h_mark(&h);
    CHECK(h_test_msg(&h, &l, "GZPH", NULL, 0, GZ_AREA_TEST) == GZ_OK);
    size_t sent = h_count(&h, m, GZ_ACTION_SEND);
    CHECK(sent >= 1 && sent < 40);
    uint64_t cont = h_last_timer(&h, m);
    CHECK(cont == ((uint64_t)GZ_AREA_TEST << 48 | 2));
    for (int k = 0; k < 100 && cont; k++) {
        size_t mm = h_mark(&h);
        CHECK(h_timer(&h, cont) == GZ_OK);
        sent += h_count(&h, mm, GZ_ACTION_SEND);
        cont = h_last_timer(&h, mm);
    }
    CHECK(sent == 40);
    /* A test SEND of the largest records the engine takes. */
    static uint8_t big[TE_MAX_SEND], fill[TE_MAX_SEND];
    size_t at = 0;
    uint8_t rk[33], kind[2], scope[32];
    gz_rec_put(big, sizeof big, &at, 1, fill, TE_MAX_SEND - 10);
    h_key('M', 9, rk);
    gz_put_u16(kind, GZ_MSG_KIND_LOBBY_STATUS);
    memset(scope, 3, sizeof scope);
    h_arg_t s[4] = {{12, rk, 33}, {14, kind, 2}, {16, scope, 32}, {18, big, at}};
    m = h_mark(&h);
    CHECK(h_cmd(&h, GZ_TE_CMD_SEND, s, 4) == GZ_OK && h_count(&h, m, GZ_ACTION_SEND) == 1);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

int main(void)
{
    test_room();
    test_worst_steps();
    return check_done();
}
