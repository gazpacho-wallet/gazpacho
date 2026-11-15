/* The node part's connections on the host (composite-node.md section 3): the
 * one rule for connections without a seat (at most 16, the oldest silent one
 * pushed out first, each closed after 60 s without a message, on the
 * monotonic clock), seats, what happens when a slot closes, the per-link
 * hello limits, and messages on a link the node part does not hold as
 * connected. No case may cause a node error. */
#include "node_test.h"
#include "internal.h"

#define IDLE_TIMER ((uint64_t)GZ_AREA_NODE << 48 | NP_TIMER_IDLE)

static void scope_of(uint8_t s[32], uint8_t b)
{
    memset(s, b, 32);
}

static void open_host_slot(h_t *h, uint8_t b, int listed)
{
    uint8_t s[32], role = 1, l = (uint8_t)listed;
    scope_of(s, b);
    h_arg_t a[3] = {{12, s, 32}, {14, &role, 1}, {22, &l, 1}};
    h_cmd(h, GZ_TE_CMD_SLOT_OPEN, a, 3);
}

static void close_slot(h_t *h, uint8_t b)
{
    uint8_t s[32];
    scope_of(s, b);
    h_arg_t a[1] = {{12, s, 32}};
    h_cmd(h, GZ_TE_CMD_SLOT_CLOSE, a, 1);
}

static void seat(h_t *h, uint8_t scope, uint32_t member, int seated)
{
    uint8_t s[32], mk[33], v = (uint8_t)seated;
    scope_of(s, scope);
    h_key('M', member, mk);
    h_arg_t a[3] = {{12, s, 32}, {14, mk, 33}, {16, &v, 1}};
    h_cmd(h, GZ_TE_CMD_SLOT_SEAT, a, 3);
}

static uint32_t n_unseated(const h_t *h)
{
    uint32_t n = 0;
    for (int i = 0; i < NP_MAX_CONNS; i++) {
        const np_conn_t *k = &h->n->np.conns[i];
        if (k->used && k->connected && !k->closing && !k->seated) n++;
    }
    return n;
}

/* The member key of the i-th DISCONNECT since `from` (0-based), or 0xffffffff. */
static uint32_t closed_member(const h_t *h, size_t from, size_t i, uint16_t *why)
{
    for (size_t k = from; k < h->n_log; k++) {
        if (h->log[k].a.kind != GZ_ACTION_DISCONNECT) continue;
        if (i-- == 0) {
            if (why) *why = h->log[k].why;
            return gz_get_u32(h->log[k].key + 2);
        }
    }
    return 0xffffffffu;
}

static int closed(const h_t *h, size_t from, uint32_t member)
{
    for (size_t i = 0;; i++) {
        uint32_t m = closed_member(h, from, i, NULL);
        if (m == 0xffffffffu) return 0;
        if (m == member) return 1;
    }
}

/* The delay of the last idle timer set since `from`, or -1 if none was. */
static int64_t idle_set(const h_t *h, size_t from)
{
    int64_t d = -1;
    for (size_t i = from; i < h->n_log; i++)
        if (h->log[i].a.kind == GZ_ACTION_SET_TIMER && h->log[i].timer == IDLE_TIMER)
            d = (int64_t)h->log[i].a.u.set_timer.delay_ms;
    return d;
}

/* Who is pushed out: the oldest SILENT one first; one that has spoken goes
 * only when no silent one is left, the oldest of those first; never the
 * newcomer, and never a seated one. */
static void test_push_out_order(void)
{
    h_t h;
    uint16_t why = 0;
    h_init(&h, 1, 1);
    h_start(&h);
    open_host_slot(&h, 4, 0);
    seat(&h, 4, 100, 1);
    gz_link_t seated = h_host_link(100);
    h_peer(&h, &seated, 1, 0); /* older than all, silent, and seated */
    /* Members 0 to 15 connect 10 ms apart. Member 3 speaks before member 4
     * connects, so it is OLDER by its last message than every later one, and
     * yet not silent; member 9 speaks last of all. */
    for (uint32_t i = 0; i < 16; i++) {
        gz_link_t l = h_host_link(i);
        h.clock += 10;
        h_peer(&h, &l, 1, 0);
        if (i == 3) {
            h.clock += 5;
            h_msg(&h, &l, 128, NULL, NULL, 0); /* a discovery kind: dropped, but it spoke */
        }
    }
    gz_link_t l9 = h_host_link(9);
    h.clock += 10;
    h_msg(&h, &l9, 128, NULL, NULL, 0);
    CHECK(n_unseated(&h) == 16);
    h.clock += NP_SILENT_GRACE_MS; /* those that said nothing have had their time: they are silent */
    /* Fourteen newcomers, one push-out each: the silent ones in the order
     * they connected, 0 1 2 4 5 6 7 8 10 ... and never 3 or 9 while a silent
     * one is left. */
    static const uint32_t expect[14] = {0, 1, 2, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15};
    for (uint32_t i = 0; i < 14; i++) {
        gz_link_t l = h_host_link(200 + i);
        size_t m = h_mark(&h);
        h.clock += 10;
        CHECK(h_peer(&h, &l, 1, 0) == GZ_OK);
        CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1);
        CHECK(closed_member(&h, m, 0, &why) == expect[i] && why == GZ_DISCONNECT_IDLE);
        CHECK(n_unseated(&h) == 16);
        /* The newcomers speak at once, so each stays behind the silent ones. */
        h_msg(&h, &l, 128, NULL, NULL, 0);
    }
    /* No silent one is left (3, 9 and the fourteen newcomers have all
     * spoken): the oldest by its last message goes, which is 3, then 9. */
    for (uint32_t i = 0; i < 2; i++) {
        gz_link_t l = h_host_link(300 + i);
        size_t m = h_mark(&h);
        h.clock += 10;
        h_peer(&h, &l, 1, 0);
        CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed_member(&h, m, 0, NULL) == (i == 0 ? 3u : 9u));
        h_msg(&h, &l, 128, NULL, NULL, 0);
    }
    /* A silent newcomer is not its own victim: the next push-out takes it
     * only when a later one arrives. */
    gz_link_t quiet = h_host_link(400), next = h_host_link(401);
    size_t m = h_mark(&h);
    h_peer(&h, &quiet, 1, 0);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed_member(&h, m, 0, NULL) != 400);
    m = h_mark(&h);
    h.clock += NP_SILENT_GRACE_MS;
    h_peer(&h, &next, 1, 0);
    CHECK(closed_member(&h, m, 0, NULL) == 400);
    /* The seated one, the oldest and silent throughout, was never touched. */
    CHECK(!closed(&h, 0, 100));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* The idle rule on the monotonic clock: 60 s without a message, not 30 and
 * not 59.999; a message refreshes it; the timer is set again while anyone is
 * left; a wall clock stepped back a day changes nothing. */
static void test_idle_clock(void)
{
    h_t h;
    gz_link_t a = h_host_link(1), b = h_host_link(2), c = h_host_link(3);
    h_init(&h, 1, 1);
    h.clock += 200000000; /* room to step the wall clock back a day */
    h_start(&h);
    size_t m = h_mark(&h);
    h_peer(&h, &a, 1, 0);
    CHECK(idle_set(&h, m) == NP_IDLE_MS); /* armed at the first unseated connection */
    h.clock += 20000;
    m = h_mark(&h);
    h_peer(&h, &b, 1, 0);
    CHECK(idle_set(&h, m) == -1); /* the earlier deadline stands */
    /* Fired early, at 30 s: nobody is closed and the timer is set again for
     * what is left of a's 60 s. */
    h.clock += 10000;
    m = h_mark(&h);
    CHECK(h_timer(&h, IDLE_TIMER) == GZ_OK);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 0 && idle_set(&h, m) == 30000);
    /* At 59.999 s: still nobody, and 1 ms to go. */
    h.clock += 29999;
    m = h_mark(&h);
    h_timer(&h, IDLE_TIMER);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 0 && idle_set(&h, m) == 1);
    /* b speaks at 59.999 s of a's life (39.999 s of its own). */
    h_msg(&h, &b, 128, NULL, NULL, 0);
    /* At 60 s: a goes, b stays, and the timer is set again for b: 60 s from
     * its message, less the millisecond that has passed. */
    h.clock += 1;
    m = h_mark(&h);
    h_timer(&h, IDLE_TIMER);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed(&h, m, 1) && !closed(&h, m, 2));
    CHECK(h.log[m].why == GZ_DISCONNECT_IDLE);
    CHECK(idle_set(&h, m) == NP_IDLE_MS - 1);
    /* Without its message b would have gone 20 s after a: at that moment it
     * is still there. */
    h.clock += 20000;
    m = h_mark(&h);
    h_timer(&h, IDLE_TIMER);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 0 && idle_set(&h, m) == NP_IDLE_MS - 20001);
    /* The wall clock is stepped back a day. The monotonic clock goes on: b is
     * closed when its 60 s are over, and the timer is not set for a day. */
    h_clock_back(&h, 86400000);
    h_peer(&h, &c, 1, 0);
    h.clock += NP_IDLE_MS - 20001;
    m = h_mark(&h);
    h_timer(&h, IDLE_TIMER);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed(&h, m, 2));
    CHECK(idle_set(&h, m) == 20001); /* c's turn, 60 s after it connected */
    h.clock += 20001;
    m = h_mark(&h);
    h_timer(&h, IDLE_TIMER);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed(&h, m, 3));
    CHECK(idle_set(&h, m) == -1 && n_unseated(&h) == 0); /* nobody left: not set again */
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* A connection a message bound to a slot, whose key holds no seat, is under
 * the same rule (review A F9, review B 7): it counts among the 16, is pushed
 * out, and is closed when idle; its slot's lobby then hears of the end when
 * the program reports it. A seated member is never refused for them. */
static void test_bound_without_a_seat(void)
{
    h_t h;
    uint8_t s[32];
    scope_of(s, 4);
    h_init(&h, 1, 1);
    h_start(&h);
    open_host_slot(&h, 4, 0);
    /* Twenty keys each say one hello for the open scope: each is bound, and
     * at most 16 of them are held. */
    for (uint32_t i = 0; i < 20; i++) {
        gz_link_t l = h_host_link(i);
        size_t m = h_mark(&h);
        h.clock += 10;
        h_peer(&h, &l, 1, 0);
        if (i >= 16) CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed_member(&h, m, 0, NULL) == i - 16);
        m = h_mark(&h);
        h_msg(&h, &l, GZ_MSG_KIND_HELLO, s, NULL, 0);
        CHECK(h_said(&h, m, "slot-peer gen=1 up=1") && h_said(&h, m, "slot-msg gen=1 kind=16"));
    }
    CHECK(n_unseated(&h) == 16);
    /* A pushed-out bound connection: its slot hears of the end at its
     * PEER_DISCONNECTED, once. */
    gz_link_t l0 = h_host_link(0);
    size_t m = h_mark(&h);
    h_peer(&h, &l0, 0, 0);
    CHECK(h_said(&h, m, "slot-peer gen=1 up=0"));
    m = h_mark(&h);
    h_peer(&h, &l0, 0, 0);
    CHECK(!h_said(&h, m, "slot-peer"));
    /* A member with a seat connects: bound at once, nobody refused or pushed out. */
    seat(&h, 4, 100, 1);
    gz_link_t member = h_host_link(100);
    m = h_mark(&h);
    CHECK(h_peer(&h, &member, 1, 0) == GZ_OK);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 0 && h_said(&h, m, "slot-peer gen=1 up=1"));
    /* A minute of silence: the sixteen bound ones go, the member stays. */
    h.clock += NP_IDLE_MS;
    m = h_mark(&h);
    h_timer(&h, IDLE_TIMER);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 16 && !closed(&h, m, 100) && n_unseated(&h) == 0);
    for (size_t i = m; i < h.n_log; i++)
        if (h.log[i].a.kind == GZ_ACTION_DISCONNECT) CHECK(h.log[i].why == GZ_DISCONNECT_IDLE);
    /* Ten more minutes: the member is never closed as idle. */
    h.clock += 600000;
    m = h_mark(&h);
    h_timer(&h, IDLE_TIMER);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 0);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* Seats (SET_SEATED, noted by the composite): a connection of the key is
 * seated and bound at once; a seat given up puts it back under the rule. */
static void test_seats(void)
{
    h_t h;
    gz_link_t a = h_host_link(1);
    h_init(&h, 1, 1);
    h_start(&h);
    open_host_slot(&h, 4, 0);
    h_peer(&h, &a, 1, 0);
    CHECK(n_unseated(&h) == 1);
    size_t m = h_mark(&h);
    seat(&h, 4, 1, 1);
    CHECK(h_count(&h, m, GZ_ACTION_SET_SEATED) == 1 && n_unseated(&h) == 0);
    /* Bound: its end is the slot's to hear; seated: a minute of silence is nothing. */
    h.clock += 2 * NP_IDLE_MS;
    m = h_mark(&h);
    h_timer(&h, IDLE_TIMER);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 0);
    m = h_mark(&h);
    h_peer(&h, &a, 0, 0);
    CHECK(h_said(&h, m, "slot-peer gen=1 up=0"));
    h_peer(&h, &a, 1, 0);
    CHECK(n_unseated(&h) == 0);
    /* The seat is given up: the connection is unseated from now, the idle
     * timer is set for it, and 60 s later it is closed. */
    m = h_mark(&h);
    seat(&h, 4, 1, 0);
    CHECK(h_count(&h, m, GZ_ACTION_SET_SEATED) == 1 && n_unseated(&h) == 1);
    CHECK(idle_set(&h, m) == NP_IDLE_MS);
    h.clock += NP_IDLE_MS;
    m = h_mark(&h);
    h_timer(&h, IDLE_TIMER);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed(&h, m, 1));
    /* Seventeen seats given up at once in turn: the cap holds after each. */
    for (uint32_t i = 10; i < 27; i++) {
        gz_link_t l = h_host_link(i);
        seat(&h, 4, i, 1);
        h.clock += 10;
        h_peer(&h, &l, 1, 0);
    }
    CHECK(n_unseated(&h) == 0);
    m = h_mark(&h);
    for (uint32_t i = 10; i < 27; i++) seat(&h, 4, i, 0);
    CHECK(n_unseated(&h) == 16 && h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed(&h, m, 10));
    /* The 33rd seat of a slot is a refusal to the person, never an error. */
    for (uint32_t i = 1000; i < 1000 + SLOT_MAX_SEATS; i++) seat(&h, 4, i, 1);
    m = h_mark(&h);
    seat(&h, 4, 5000, 1);
    CHECK(h_said(&h, m, "result 409 too_many_seats") && h_count(&h, m, GZ_ACTION_SET_SEATED) == 0);
    m = h_mark(&h);
    seat(&h, 4, 1000, 1); /* one that is seated already: it stands */
    CHECK(h_said(&h, m, "result 200"));
    m = h_mark(&h);
    seat(&h, 4, 1000, 0); /* a seat given up makes room */
    seat(&h, 4, 5000, 1);
    CHECK(!h_said(&h, m, "result 409"));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* A slot closes (review B 2): its connections are unbound and unseated, and
 * the cap holds AT ONCE: the excess is closed in that step, the silent first,
 * the oldest of them first. A member seated in another slot is never one of
 * them. What is left can bind to another slot, and goes when idle. */
static void test_slot_close_keeps_the_cap(void)
{
    h_t h;
    uint8_t s5[32];
    scope_of(s5, 5);
    h_init(&h, 1, 1);
    h_start(&h);
    open_host_slot(&h, 4, 0);
    open_host_slot(&h, 5, 0);
    /* Thirty members seated in slot 4 and five in slot 5, all connected.
     * Members 20 to 29 of slot 4 have spoken. */
    for (uint32_t i = 0; i < 30; i++) {
        gz_link_t l = h_host_link(i);
        seat(&h, 4, i, 1);
        h.clock += 10;
        h_peer(&h, &l, 1, 0);
        if (i >= 20) h_msg(&h, &l, 128, NULL, NULL, 0);
    }
    for (uint32_t i = 50; i < 55; i++) {
        gz_link_t l = h_host_link(i);
        seat(&h, 5, i, 1);
        h_peer(&h, &l, 1, 0);
    }
    CHECK(n_unseated(&h) == 0);
    size_t m = h_mark(&h);
    close_slot(&h, 4);
    CHECK(h_said(&h, m, "result 200"));
    /* 30 are unseated now, 16 may stay: 14 go in this very step, the silent
     * ones (0 to 19) before any that spoke, the oldest first. */
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 14 && n_unseated(&h) == 16);
    for (uint32_t i = 0; i < 14; i++) {
        uint16_t why = 99;
        CHECK(closed_member(&h, m, i, &why) == i && why == GZ_DISCONNECT_IDLE);
    }
    for (uint32_t i = 50; i < 55; i++) CHECK(!closed(&h, m, i));
    CHECK(idle_set(&h, m) == NP_IDLE_MS);
    /* One of those left is unbound: its message for slot 5's scope binds it there. */
    gz_link_t l25 = h_host_link(25);
    m = h_mark(&h);
    h_msg(&h, &l25, GZ_MSG_KIND_HELLO, s5, NULL, 0);
    CHECK(h_said(&h, m, "slot-peer gen=2 up=1") && h_said(&h, m, "slot-msg gen=2 kind=16"));
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 0);
    /* Its end is slot 5's to hear, not the closed slot's. */
    m = h_mark(&h);
    h_peer(&h, &l25, 0, 0);
    CHECK(h_said(&h, m, "slot-peer gen=2 up=0") && !h_said(&h, m, "gen=1"));
    /* One the close pushed out: its end is nobody's (its slot is gone). */
    gz_link_t l0 = h_host_link(0);
    m = h_mark(&h);
    h_peer(&h, &l0, 0, 0);
    CHECK(!h_said(&h, m, "slot-peer"));
    /* A connection bound to slot 5 by its message, and seated through a
     * third slot: when that slot closes its seat is gone, though its binding
     * to slot 5 stands, and it is under the rule again. */
    open_host_slot(&h, 6, 0);
    gz_link_t l60 = h_host_link(60);
    h_peer(&h, &l60, 1, 0);
    h_msg(&h, &l60, GZ_MSG_KIND_HELLO, s5, NULL, 0);
    seat(&h, 6, 60, 1);
    CHECK(n_unseated(&h) == 15);
    close_slot(&h, 6);
    CHECK(n_unseated(&h) == 16);
    m = h_mark(&h);
    h_msg(&h, &l60, 20, s5, NULL, 0);
    CHECK(h_said(&h, m, "slot-msg gen=2 kind=20"));
    /* A minute later the other fifteen go; slot 5's members stay. */
    h.clock += NP_IDLE_MS;
    m = h_mark(&h);
    h_timer(&h, IDLE_TIMER);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 16 && n_unseated(&h) == 0 && closed(&h, m, 60));
    for (uint32_t i = 50; i < 55; i++) CHECK(!closed(&h, m, i));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* A member's slot closes: its connection to the host is no longer kept. */
static void test_member_slot_close(void)
{
    h_t h;
    uint8_t s[32], role = 0, hk[33];
    scope_of(s, 5);
    h_key('H', 0, hk);
    h_init(&h, 0, 1);
    h_start(&h);
    h_arg_t a[4] = {{12, s, 32}, {14, &role, 1}, {16, hk, 33}, {18, "127.0.0.1:1", 11}};
    h_cmd(&h, GZ_TE_CMD_SLOT_OPEN, a, 4);
    size_t m = h_mark(&h);
    close_slot(&h, 5);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1);
    for (size_t i = m; i < h.n_log; i++)
        if (h.log[i].a.kind == GZ_ACTION_DISCONNECT)
            CHECK(h.log[i].why == GZ_DISCONNECT_DONE && !memcmp(h.log[i].key, hk, 33));
    /* A bad address is refused before anything is kept: no slot, no CONNECT. */
    static const char *bad[] = {"not-an-address", "127.0.0.1", "127.0.0.1:0", "host:1"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        h_arg_t b[4] = {{12, s, 32}, {14, &role, 1}, {16, hk, 33}, {18, bad[i], strlen(bad[i])}};
        m = h_mark(&h);
        h_cmd(&h, GZ_TE_CMD_SLOT_OPEN, b, 4);
        CHECK(h_said(&h, m, "result 400 bad_address") && h_count(&h, m, GZ_ACTION_CONNECT) == 0);
        CHECK(!h_said(&h, m, "slot-open") && gz_route_slot_by_scope(h.n, s) < 0);
    }
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* A full table: every entry holds a connection that stays (64 members with
 * seats). One more is refused, never an error, and none of the 64 is lost. */
static void test_table_full(void)
{
    h_t h;
    uint8_t s[2][32];
    uint16_t why = 0;
    scope_of(s[0], 4);
    scope_of(s[1], 5);
    h_init(&h, 1, 1);
    h_start(&h);
    open_host_slot(&h, 4, 0);
    open_host_slot(&h, 5, 0);
    for (uint32_t i = 0; i < NP_MAX_CONNS; i++) {
        gz_link_t l = h_host_link(i);
        seat(&h, (uint8_t)(4 + i / SLOT_MAX_SEATS), i, 1);
        h.clock += 10;
        CHECK(h_peer(&h, &l, 1, 0) == GZ_OK);
    }
    gz_link_t extra = h_host_link(999);
    size_t m = h_mark(&h);
    CHECK(h_peer(&h, &extra, 1, 0) == GZ_OK);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed_member(&h, m, 0, &why) == 999);
    CHECK(why == GZ_DISCONNECT_REFUSED);
    /* It holds no entry: what it sends is dropped. */
    h.auto_connect = 0;
    m = h_mark(&h);
    h_msg(&h, &extra, GZ_MSG_KIND_HELLO, s[0], NULL, 0);
    CHECK(h_said(&h, m, "drop why=unconnected") && !h_said(&h, m, "slot-"));
    /* Every one of the 64 is still there and bound to its slot. */
    for (uint32_t i = 0; i < NP_MAX_CONNS; i++) {
        gz_link_t l = h_host_link(i);
        m = h_mark(&h);
        h_msg(&h, &l, 20, s[i / SLOT_MAX_SEATS], NULL, 0);
        CHECK(h_said(&h, m, i < SLOT_MAX_SEATS ? "slot-msg gen=1 kind=20" : "slot-msg gen=2 kind=20"));
    }
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* A link the node part does not hold as connected (review A F5, review B 1):
 * one never reported, one it pushed out, one it refused. Whatever it sends is
 * dropped and counted: nothing is bound, no engine hears of it, no hello is
 * answered, nothing is saved. */
static void test_unconnected_links(void)
{
    h_t h;
    gz_link_t ghost = h_host_link(7);
    uint8_t s[32], unknown[32], zero[32] = {0};
    scope_of(s, 4);
    scope_of(unknown, 0x66);
    h_init(&h, 1, 1);
    h_start(&h);
    open_host_slot(&h, 4, 1);
    h.auto_connect = 0;
    size_t m = h_mark(&h);
    uint64_t before = h.n->np.drops[DROP_UNCONNECTED];
    for (int i = 0; i < 5; i++) CHECK(h_msg(&h, &ghost, 20, s, NULL, 0) == GZ_OK);
    for (int i = 0; i < 30; i++) CHECK(h_msg(&h, &ghost, GZ_MSG_KIND_HELLO, unknown, NULL, 0) == GZ_OK);
    for (int i = 0; i < 30; i++) CHECK(h_msg(&h, &ghost, GZ_MSG_KIND_HELLO, zero, NULL, 0) == GZ_OK);
    CHECK(h_msg(&h, &ghost, 64, s, NULL, 0) == GZ_OK);
    CHECK(h_test_msg(&h, &ghost, "GZPI", (const uint8_t *)"x", 1, GZ_AREA_TEST) == GZ_OK);
    CHECK(h_test_msg(&h, &ghost, "GZPH", NULL, 0, GZ_AREA_TEST) == GZ_OK);
    CHECK(h.n->np.drops[DROP_UNCONNECTED] == before + 68);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0 && h_count(&h, m, GZ_ACTION_SAVE) == 0);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 0);
    CHECK(!h_said(&h, m, "slot-peer") && !h_said(&h, m, "slot-msg") && h_said(&h, m, "drop why=unconnected kind=20"));
    CHECK(h_records_of(&h, 0x7e570001u) == 0);
    /* Its PEER_DISCONNECTED, if one comes, reaches no slot. */
    m = h_mark(&h);
    h_peer(&h, &ghost, 0, 0);
    CHECK(!h_said(&h, m, "slot-peer"));
    /* Connected, it is taken: bound by its first message. */
    h_peer(&h, &ghost, 1, 0);
    m = h_mark(&h);
    h_msg(&h, &ghost, 20, s, NULL, 0);
    CHECK(h_said(&h, m, "slot-peer gen=1 up=1") && h_said(&h, m, "slot-msg gen=1 kind=20"));
    /* Refused (it names another scope): from then on it is dropped, though
     * the program has not yet reported it gone. */
    m = h_mark(&h);
    h_msg(&h, &ghost, 20, unknown, NULL, 0);
    CHECK(h_said(&h, m, "drop why=rebind") && h_count(&h, m, GZ_ACTION_DISCONNECT) == 1);
    m = h_mark(&h);
    for (int i = 0; i < 5; i++) h_msg(&h, &ghost, 20, s, NULL, 0);
    for (int i = 0; i < 5; i++) h_msg(&h, &ghost, GZ_MSG_KIND_HELLO, zero, NULL, 0);
    CHECK(!h_said(&h, m, "slot-msg") && h_count(&h, m, GZ_ACTION_DISCONNECT) == 0);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0);
    /* Its end is still its slot's to hear, once. */
    m = h_mark(&h);
    h_peer(&h, &ghost, 0, 0);
    CHECK(h_said(&h, m, "slot-peer gen=1 up=0"));
    /* Pushed out: the same. */
    for (uint32_t i = 20; i < 37; i++) {
        gz_link_t l = h_host_link(i);
        h.clock += 10;
        h_peer(&h, &l, 1, 0);
    }
    gz_link_t pushed = h_host_link(20);
    m = h_mark(&h);
    for (int i = 0; i < 25; i++) h_msg(&h, &pushed, GZ_MSG_KIND_HELLO, unknown, NULL, 0);
    h_msg(&h, &pushed, 20, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0 && h_count(&h, m, GZ_ACTION_DISCONNECT) == 0);
    CHECK(!h_said(&h, m, "slot-") && !h_said(&h, m, "hello-limit"));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* The state byte of a lobby_status (record 2), or -1. */
static int status_state(const h_t *h)
{
    gz_bytes_t v;
    /* The log keeps no payload: read it from the list of the last call. */
    for (size_t i = 0; i < h->list.count; i++)
        if (h->list.slots[i].kind == GZ_ACTION_SEND && h->list.slots[i].u.send.kind == GZ_MSG_KIND_LOBBY_STATUS)
            return gz_rec_find(h->list.slots[i].u.send.records, 2, &v) == 1 && v.len == 1 ? v.data[0] : -1;
    return -1;
}

/* The per-link hello limits (messages.md 6.1): one answer a second, to the
 * millisecond; the connection closed at the twentieth ignored hello in ten
 * minutes, not the twenty-first, and not for twenty spread over more; the
 * listing with at most four offers; an unknown scope answered with state 0
 * under the scope asked. */
static void test_hello_limits_exact(void)
{
    h_t h;
    gz_link_t a = h_host_link(1), b = h_host_link(2), c = h_host_link(3), d = h_host_link(4);
    uint8_t s[32], zero[32] = {0};
    uint16_t why = 0;
    scope_of(s, 0x33);
    h_init(&h, 1, 1);
    h.clock += 200000000; /* room to step the wall clock back an hour */
    h_start(&h);
    h_peer(&h, &a, 1, 0);
    size_t m = h_mark(&h);
    h_msg(&h, &a, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1 && h.log[m].kind == GZ_MSG_KIND_LOBBY_STATUS);
    CHECK(status_state(&h) == 0);
    CHECK(!memcmp(h.list.slots[0].u.send.scope, s, 32)); /* under the scope it asked for */
    CHECK(!memcmp(h.log[m].key, a.remote.key, 33));
    /* 999 ms later: ignored. 1000 ms: answered. */
    h.clock += 999;
    m = h_mark(&h);
    h_msg(&h, &a, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0 && h_said(&h, m, "drop why=hello-limit"));
    h.clock += 1;
    m = h_mark(&h);
    h_msg(&h, &a, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1);
    /* Nineteen ignored (one above, eighteen here): no close. The twentieth closes. */
    m = h_mark(&h);
    for (int i = 0; i < 18; i++) h_msg(&h, &a, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 0 && h_count(&h, m, GZ_ACTION_SEND) == 0);
    m = h_mark(&h);
    h_msg(&h, &a, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed_member(&h, m, 0, &why) == 1);
    CHECK(why == GZ_DISCONNECT_REFUSED);
    /* Ten ignored, then 9 min 59 s, then ten more: twenty within the ten
     * minutes, closed at the twentieth. */
    h_peer(&h, &b, 1, 0);
    h_msg(&h, &b, GZ_MSG_KIND_HELLO, s, NULL, 0); /* answered */
    for (int i = 0; i < 10; i++) h_msg(&h, &b, GZ_MSG_KIND_HELLO, s, NULL, 0);
    h.clock += 599000;
    h_msg(&h, &b, GZ_MSG_KIND_HELLO, s, NULL, 0); /* answered: a second has passed */
    m = h_mark(&h);
    for (int i = 0; i < 9; i++) h_msg(&h, &b, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 0);
    h_msg(&h, &b, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1);
    /* Nineteen ignored, then ten minutes, then nineteen more: never closed,
     * the count starts again with the window. */
    h_peer(&h, &c, 1, 0);
    h_msg(&h, &c, GZ_MSG_KIND_HELLO, s, NULL, 0);
    m = h_mark(&h);
    for (int i = 0; i < 19; i++) h_msg(&h, &c, GZ_MSG_KIND_HELLO, s, NULL, 0);
    h.clock += 600000;
    h_msg(&h, &c, GZ_MSG_KIND_HELLO, s, NULL, 0); /* answered */
    for (int i = 0; i < 18; i++) h_msg(&h, &c, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 0);
    /* The limits are on the monotonic clock: a wall clock stepped back an
     * hour neither opens the limit nor holds it shut. */
    h_clock_back(&h, 3600000);
    m = h_mark(&h);
    h_msg(&h, &c, GZ_MSG_KIND_HELLO, s, NULL, 0); /* the nineteenth ignored of this window */
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0 && h_count(&h, m, GZ_ACTION_DISCONNECT) == 0);
    h.clock += 1000;
    m = h_mark(&h);
    h_msg(&h, &c, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1);
    /* The listing: five listed slots, four offers, under the same limit. */
    for (uint8_t i = 0; i < 5; i++) open_host_slot(&h, (uint8_t)(0x40 + i), 1);
    h_peer(&h, &d, 1, 0);
    m = h_mark(&h);
    h_msg(&h, &d, GZ_MSG_KIND_HELLO, zero, NULL, 0);
    size_t offers = 0;
    for (size_t i = m; i < h.n_log; i++)
        if (h.log[i].a.kind == GZ_ACTION_NOTIFY && strstr(h.log[i].text, "slot-msg") && strstr(h.log[i].text, "kind=16"))
            offers++;
    CHECK(offers == NP_MAX_LISTED && NP_MAX_LISTED == 4);
    m = h_mark(&h);
    uint64_t limited = h.n->np.drops[DROP_HELLO_LIMIT];
    h_msg(&h, &d, GZ_MSG_KIND_HELLO, zero, NULL, 0);
    CHECK(!h_said(&h, m, "slot-msg") && h.n->np.drops[DROP_HELLO_LIMIT] == limited + 1);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* F8: a slot's engine gets the confirmations of its own saves, and reports of
 * its own watches; when the slot closes, its bits leave the queued batches
 * and the watch registry, so the next slot at that index inherits neither. */
static void test_slot_confirmations_and_watches(void)
{
    h_t h;
    uint8_t s1[32], s2[32], txid[32], d[4];
    gz_event_t ev;
    scope_of(s1, 1);
    scope_of(s2, 2);
    memset(txid, 0x77, sizeof txid);
    gz_put_u32(d, 2);
    h_init(&h, 1, 1);
    h_start(&h);
    open_host_slot(&h, 1, 0);
    h_arg_t sv[1] = {{12, s1, 32}};
    size_t m = h_mark(&h);
    CHECK(h_cmd(&h, GZ_TE_CMD_SLOT_SAVE, sv, 1) == GZ_OK);
    CHECK(h_count(&h, m, GZ_ACTION_SAVE) == 1 && h_said(&h, m, "slot-saved gen=1"));
    CHECK(h_said(&h, m, "slot-confirmed gen=1")); /* its confirmation reaches it */
    /* A hundred more: the queue of masks wraps (it holds 96), and each save
     * is confirmed to the slot exactly once. */
    m = h_mark(&h);
    for (int i = 0; i < 100; i++) h_cmd(&h, GZ_TE_CMD_SLOT_SAVE, sv, 1);
    size_t confirmed = 0;
    for (size_t i = m; i < h.n_log; i++)
        if (h.log[i].a.kind == GZ_ACTION_NOTIFY && strstr(h.log[i].text, "slot-confirmed gen=1")) confirmed++;
    CHECK(confirmed == 100);
    /* The watch: asked once, reported to the slot. */
    h_arg_t w[3] = {{12, s1, 32}, {14, txid, 32}, {16, d, 4}};
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_SLOT_WATCH, w, 3);
    CHECK(h_count(&h, m, GZ_ACTION_WATCH_TX) == 1 && h_said(&h, m, "result 200"));
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_CHAIN;
    ev.u.chain.kind = GZ_CHAIN_TX_CONFIRMED;
    memcpy(ev.u.chain.txid, txid, 32);
    ev.u.chain.confirmations = 1;
    m = h_mark(&h);
    h_event(&h, &ev);
    CHECK(h_said(&h, m, "slot-chain gen=1 conf=1"));
    /* A save whose confirmation is still on its way when the slot closes,
     * and another slot opens at the same index. */
    h.confirm_auto = 0;
    h_cmd(&h, GZ_TE_CMD_SLOT_SAVE, sv, 1);
    CHECK(h.n_pending == 1);
    close_slot(&h, 1);
    open_host_slot(&h, 2, 0);
    CHECK(gz_route_slot_by_scope(h.n, s2) == 0); /* the same index, generation 2 */
    h.confirm_auto = 1;
    m = h_mark(&h);
    h_confirm_all(&h);
    CHECK(h.n_pending == 0 && !h_said(&h, m, "slot-confirmed")); /* nobody's now */
    /* A report for the closed slot's watch reaches nobody. */
    m = h_mark(&h);
    CHECK(h_event(&h, &ev) == GZ_OK);
    CHECK(!h_said(&h, m, "slot-chain"));
    /* The new slot's own saves and watches work as the first one's did. */
    h_arg_t sv2[1] = {{12, s2, 32}};
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_SLOT_SAVE, sv2, 1);
    CHECK(h_said(&h, m, "slot-confirmed gen=2"));
    h_arg_t w2[3] = {{12, s2, 32}, {14, txid, 32}, {16, d, 4}};
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_SLOT_WATCH, w2, 3);
    CHECK(h_count(&h, m, GZ_ACTION_WATCH_TX) == 1); /* forgotten with the old slot: asked for anew */
    m = h_mark(&h);
    h_event(&h, &ev);
    CHECK(h_said(&h, m, "slot-chain gen=2 conf=1") && !h_said(&h, m, "gen=1"));
    /* A restart with the stand-in's records in the journal: they are passed by. */
    CHECK(h_restart(&h) == GZ_OK);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* F2: no watch command can become a node error. Every engine has a budget
 * of distinct watches and refuses the next one itself; the budgets fill the
 * registry exactly and no further; a closed slot's watches are forgotten. */
static void test_watch_budgets(void)
{
    h_t h;
    uint8_t txid[32], d[4], vout[4], a2[2];
    size_t m;
    gz_put_u32(d, 1);
    gz_put_u32(vout, 0);
    gz_put_u16(a2, GZ_AREA_TEST2);
    h_init(&h, 1, 2);
    h_start(&h);
    /* 80 watch commands with different txids to one engine: 16 taken. */
    m = h_mark(&h);
    for (int i = 0; i < 80; i++) {
        memset(txid, 1 + i, sizeof txid);
        h_arg_t a[2] = {{12, txid, 32}, {14, d, 4}};
        CHECK(h_cmd(&h, GZ_TE_CMD_WATCH, a, 2) == GZ_OK);
        CHECK(h_said(&h, h.n_log - 1, i < TE_MAX_WATCHES ? "result 200" : "result 409 too_many_watches"));
    }
    CHECK(h_count(&h, m, GZ_ACTION_WATCH_TX) == TE_MAX_WATCHES);
    /* One it already has: it stands, and a larger depth is still issued. */
    memset(txid, 1, sizeof txid);
    gz_put_u32(d, 6);
    h_arg_t again[2] = {{12, txid, 32}, {14, d, 4}};
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_WATCH, again, 2);
    CHECK(h_said(&h, m, "result 200") && h_count(&h, m, GZ_ACTION_WATCH_TX) == 1);
    gz_put_u32(d, 1);
    /* The second engine has its own sixteen, outpoints among them. */
    m = h_mark(&h);
    for (int i = 0; i < 20; i++) {
        memset(txid, 1 + i, sizeof txid);
        h_arg_t a[4] = {{10, a2, 2}, {12, txid, 32}, {14, vout, 4}, {16, d, 4}};
        h_cmd(&h, GZ_TE_CMD_WATCH_OUTPOINT, a, 4);
        CHECK(h_said(&h, h.n_log - 1, i < TE_MAX_WATCHES ? "result 200" : "result 409 too_many_watches"));
    }
    CHECK(h_count(&h, m, GZ_ACTION_WATCH_OUTPOINT) == TE_MAX_WATCHES);
    /* Every slot: four each, the fifth refused. */
    for (uint8_t sl = 0; sl < GZ_NODE_MAX_SLOTS; sl++) {
        uint8_t s[32];
        scope_of(s, (uint8_t)(0x80 + sl));
        open_host_slot(&h, (uint8_t)(0x80 + sl), 0);
        for (int i = 0; i < TS_MAX_WATCHES + 2; i++) {
            memset(txid, 0xa0 + sl, sizeof txid);
            txid[0] = (uint8_t)i;
            h_arg_t a[3] = {{12, s, 32}, {14, txid, 32}, {16, d, 4}};
            CHECK(h_cmd(&h, GZ_TE_CMD_SLOT_WATCH, a, 3) == GZ_OK);
            CHECK(h_said(&h, h.n_log - 1, i < TS_MAX_WATCHES ? "result 200" : "result 409 too_many_watches"));
        }
    }
    /* The registry holds exactly what the budgets allow: 64, all in use. */
    size_t used = 0;
    for (int i = 0; i < MAX_WATCHES; i++) used += h.n->watches[i].used ? 1 : 0;
    CHECK(used == MAX_WATCHES && used == 2 * TE_MAX_WATCHES + GZ_NODE_MAX_SLOTS * TS_MAX_WATCHES);
    /* A slot closes: its four are free, and the slot opened in its place can
     * watch four of its own. */
    close_slot(&h, 0x80);
    used = 0;
    for (int i = 0; i < MAX_WATCHES; i++) used += h.n->watches[i].used ? 1 : 0;
    CHECK(used == MAX_WATCHES - TS_MAX_WATCHES);
    open_host_slot(&h, 0x90, 0);
    for (int i = 0; i < TS_MAX_WATCHES + 1; i++) {
        uint8_t s[32];
        scope_of(s, 0x90);
        memset(txid, 0xee, sizeof txid);
        txid[0] = (uint8_t)i;
        h_arg_t a[3] = {{12, s, 32}, {14, txid, 32}, {16, d, 4}};
        h_cmd(&h, GZ_TE_CMD_SLOT_WATCH, a, 3);
        CHECK(h_said(&h, h.n_log - 1, i < TS_MAX_WATCHES ? "result 200" : "result 409 too_many_watches"));
    }
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* A slot's timer fired after the slot closed, as if the program had not
 * carried out its cancel: dropped and counted, never given to the engine. */
static void test_timer_of_a_closed_slot(void)
{
    h_t h;
    uint8_t s[32], role = 1, ms[4];
    scope_of(s, 9);
    gz_put_u32(ms, 10000);
    h_init(&h, 1, 1);
    h_start(&h);
    h_arg_t a[3] = {{12, s, 32}, {14, &role, 1}, {20, ms, 4}};
    size_t m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_SLOT_OPEN, a, 3);
    uint64_t t = h_last_timer(&h, m);
    CHECK((t >> 48) == GZ_AREA_TEST_SLOT && ((t >> 32) & 0xffff) == 1);
    close_slot(&h, 9);
    uint64_t dropped = h.n->np.drops[DROP_TIMER];
    m = h_mark(&h);
    CHECK(h_timer(&h, t) == GZ_OK);
    CHECK(!h_said(&h, m, "slot-timer") && h.n->np.drops[DROP_TIMER] == dropped + 1);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* T-P42-7: chatter does not hold a place without a seat for ever, and a
 * newcomer is not "silent" before it has had two seconds to speak.
 * T-P42-8: the drop notices are rate-limited, the counts exact. */
static void test_age_grace_and_notices(void)
{
    h_t h;
    h_init(&h, 1, 1);
    h_start(&h);
    /* One connection without a seat that says something every 50 s: never
     * idle, and closed ten minutes after it came up, not before. */
    gz_link_t chat = h_host_link(1);
    size_t m = h_mark(&h);
    h_peer(&h, &chat, 1, 0);
    for (int i = 1; i <= 12; i++) {
        h.clock += 50000;
        h_timer(&h, IDLE_TIMER);
        CHECK(closed(&h, m, 1) == (i == 12));
        if (i < 12) h_msg(&h, &chat, 128, NULL, NULL, 0);
    }
    CHECK(n_unseated(&h) == 0);
    /* Sixteen that keep talking, then an honest one, silent so far, and a
     * millisecond later one more: the honest one is not pushed out for
     * having had no time to speak; the one quiet longest among the talkers
     * goes. */
    for (uint32_t i = 0; i < 16; i++) {
        gz_link_t l = h_host_link(100 + i);
        h.clock += 10;
        h_msg(&h, &l, 128, NULL, NULL, 0);
    }
    gz_link_t honest = h_host_link(200), late = h_host_link(201), later = h_host_link(202);
    h.clock += 10;
    m = h_mark(&h);
    h_peer(&h, &honest, 1, 0);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed_member(&h, m, 0, NULL) == 100);
    h.clock += 1;
    m = h_mark(&h);
    h_peer(&h, &late, 1, 0);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed_member(&h, m, 0, NULL) == 101 && !closed(&h, m, 200));
    /* Two seconds on, still silent, they are the first to go: the older first. */
    h.clock += NP_SILENT_GRACE_MS;
    m = h_mark(&h);
    h_peer(&h, &later, 1, 0);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && closed_member(&h, m, 0, NULL) == 200);
    /* Two hundred dropped messages: 64 notices, then one at the 128th; the
     * count is 200. */
    gz_link_t f = h_host_link(102);
    uint64_t before = h.n->np.drops[DROP_FUNDED];
    size_t lines = 0;
    m = h_mark(&h);
    for (int i = 0; i < 200; i++) h_msg(&h, &f, 81, NULL, NULL, 0);
    for (size_t i = m; i < h.n_log; i++)
        if (h.log[i].a.kind == GZ_ACTION_NOTIFY && strstr(h.log[i].text, "drop why=factory-funded")) lines++;
    CHECK(h.n->np.drops[DROP_FUNDED] == before + 200 && before == 0 && lines == NP_DROP_NOTICES + 1);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

int main(void)
{
    test_age_grace_and_notices();
    test_push_out_order();
    test_idle_clock();
    test_bound_without_a_seat();
    test_seats();
    test_slot_close_keeps_the_cap();
    test_member_slot_close();
    test_table_full();
    test_unconnected_links();
    test_hello_limits_exact();
    test_slot_confirmations_and_watches();
    test_watch_budgets();
    test_timer_of_a_closed_slot();
    return check_done();
}
