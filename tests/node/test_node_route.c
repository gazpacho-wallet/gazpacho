/* Routing: by kind, then scope, then link (composite-node.md sections 3 to 5,
 * layer 1 of section 13), connection binding on the host, the unbound caps
 * and the per-link hello limits. No case may cause a node error. */
#include "node_test.h"
#include "internal.h"

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

static void open_member_slot(h_t *h, uint8_t b)
{
    uint8_t s[32], role = 0, hk[33];
    scope_of(s, b);
    h_key('H', 0, hk);
    h_arg_t a[4] = {{12, s, 32}, {14, &role, 1}, {16, hk, 33}, {18, "127.0.0.1:1", 11}};
    h_cmd(h, GZ_TE_CMD_SLOT_OPEN, a, 4);
}

static void test_family(void)
{
    CHECK(gz_route_family(16, 1) == FAM_LOBBY && gz_route_family(63, 1) == FAM_LOBBY);
    CHECK(gz_route_family(36, 1) == FAM_LOBBY);
    CHECK(gz_route_family(64, 1) == FAM_ROUND && gz_route_family(80, 1) == FAM_ROUND);
    CHECK(gz_route_family(81, 1) == FAM_FUNDED);
    CHECK(gz_route_family(15, 1) == FAM_NONE && gz_route_family(82, 1) == FAM_NONE);
    CHECK(gz_route_family(127, 1) == FAM_NONE && gz_route_family(160, 1) == FAM_NONE);
    CHECK(gz_route_family(128, 1) == FAM_DISCOVERY && gz_route_family(159, 1) == FAM_DISCOVERY);
    CHECK(gz_route_family(32767, 1) == FAM_TEST && gz_route_family(32767, 0) == FAM_NONE);
    CHECK(gz_route_family(0, 1) == FAM_NONE && gz_route_family(65535, 1) == FAM_NONE);
}

/* Kinds no engine takes: dropped and counted, never a disconnect. */
static void test_drops_by_kind(void)
{
    h_t h;
    gz_link_t l = h_host_link(1);
    uint8_t s[32];
    scope_of(s, 9);
    h_init(&h, 1, 1);
    h_start(&h);
    h_peer(&h, &l, 1, 0);
    uint16_t kinds[] = {128, 140, 159, 81, 99, 1001, 3};
    for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        size_t m = h_mark(&h);
        CHECK(h_msg(&h, &l, kinds[i], s, NULL, 0) == GZ_OK);
        CHECK(h_said(&h, m, "drop why=") && h_count(&h, m, GZ_ACTION_DISCONNECT) == 0);
    }
    CHECK(h.n->np.drops[DROP_DISCOVERY] == 3 && h.n->np.drops[DROP_FUNDED] == 1 && h.n->np.drops[DROP_KIND] == 3);
    /* A test message naming an engine that is not there: dropped. */
    size_t m = h_mark(&h);
    h_test_msg(&h, &l, "GZPI", (const uint8_t *)"x", 1, GZ_AREA_TEST2);
    CHECK(h_said(&h, m, "drop why=kind") && h_records_of(&h, 0x7e570001u) == 0);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* Test 4, member side: a scope-valid lobby kind for a scope with no slot,
 * from the member's host: dropped and counted (A15). */
static void test_member_gates(void)
{
    h_t h;
    gz_link_t l;
    uint8_t s[32], other[32], k1[33], k2[33];
    h_init(&h, 0, 1);
    h_start(&h);
    h_key('K', 2, k1);
    h_key('H', 0, k2);
    l = h_link(k1, k2);
    scope_of(s, 5);
    size_t m = h_mark(&h);
    h_msg(&h, &l, GZ_MSG_KIND_LOBBY_STATUS, s, NULL, 0);
    CHECK(h_said(&h, m, "drop why=no-slot kind=28") && h_count(&h, m, GZ_ACTION_DISCONNECT) == 0);
    /* With the slot open, from its link: to the slot's engine. */
    m = h_mark(&h);
    open_member_slot(&h, 5);
    CHECK(h_count(&h, m, GZ_ACTION_CONNECT) == 1 && h_said(&h, m, "slot-open gen=1"));
    m = h_mark(&h);
    h_msg(&h, &l, GZ_MSG_KIND_LOBBY_STATUS, s, NULL, 0);
    CHECK(h_said(&h, m, "slot-msg gen=1 kind=28"));
    /* Another scope: dropped. Scope zero: dropped. */
    scope_of(other, 6);
    m = h_mark(&h);
    h_msg(&h, &l, 30, other, NULL, 0);
    h_msg(&h, &l, 28, (const uint8_t[32]){0}, NULL, 0);
    CHECK(h_said(&h, m, "no-slot") && h_said(&h, m, "scope-zero") && !h_said(&h, m, "slot-msg"));
    /* The right scope from another link: dropped and the connection refused. */
    gz_link_t bad = l;
    bad.remote.key[5] ^= 1;
    m = h_mark(&h);
    h_msg(&h, &bad, 28, s, NULL, 0);
    CHECK(h_said(&h, m, "drop why=link") && h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && !h_said(&h, m, "slot-msg"));
    CHECK(h.log[h.n_log - 1].a.kind == GZ_ACTION_DISCONNECT && h.log[h.n_log - 1].why == GZ_DISCONNECT_REFUSED);
    /* Round kinds: no round under the scope, dropped; with the check
     * answered, to the signing engine (none before P4.3: counted). */
    m = h_mark(&h);
    h_msg(&h, &l, 64, s, NULL, 0);
    CHECK(h_said(&h, m, "drop why=no-slot kind=64"));
    h_arg_t r[1] = {{12, s, 32}};
    h_cmd(&h, GZ_TE_CMD_SLOT_ROUND, r, 1);
    m = h_mark(&h);
    h_msg(&h, &l, 66, s, NULL, 0);
    CHECK(h_said(&h, m, "drop why=no-engine kind=66"));
    m = h_mark(&h);
    h_msg(&h, &bad, 66, s, NULL, 0);
    CHECK(h_said(&h, m, "drop why=link") && h_count(&h, m, GZ_ACTION_DISCONNECT) == 1);
    /* Peer events reach the slot of the link. */
    m = h_mark(&h);
    h_peer(&h, &l, 1, 1);
    CHECK(h_said(&h, m, "slot-peer gen=1 up=1"));
    m = h_mark(&h);
    h_peer(&h, &bad, 1, 1);
    CHECK(!h_said(&h, m, "slot-peer"));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* Section 3: binding on the host. */
static void test_host_binding(void)
{
    h_t h;
    gz_link_t a = h_host_link(1), b = h_host_link(2);
    uint8_t s1[32], s2[32];
    scope_of(s1, 1);
    scope_of(s2, 2);
    h_init(&h, 1, 1);
    h_start(&h);
    open_host_slot(&h, 1, 1);
    open_host_slot(&h, 2, 0);
    h_peer(&h, &a, 1, 0);
    CHECK(h.n->np.n_unbound == 1);
    /* The first message with a nonzero scope binds it: connected, then the message. */
    size_t m = h_mark(&h);
    h_msg(&h, &a, GZ_MSG_KIND_HELLO, s1, NULL, 0);
    CHECK(h_said(&h, m, "slot-peer gen=1 up=1") && h_said(&h, m, "slot-msg gen=1 kind=16"));
    CHECK(h.n->np.n_unbound == 0);
    /* Another nonzero scope on a bound link: refused. */
    m = h_mark(&h);
    h_msg(&h, &a, 20, s2, NULL, 0);
    CHECK(h_said(&h, m, "drop why=rebind") && h_count(&h, m, GZ_ACTION_DISCONNECT) == 1 && !h_said(&h, m, "gen=2"));
    /* A seated key is bound at once on connecting. */
    uint8_t mk[33];
    h_key('M', 2, mk);
    h_arg_t st[2] = {{12, s2, 32}, {14, mk, 33}};
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_SLOT_SEAT, st, 2);
    CHECK(h_count(&h, m, GZ_ACTION_SET_SEATED) == 1);
    m = h_mark(&h);
    h_peer(&h, &b, 1, 0);
    CHECK(h_said(&h, m, "slot-peer gen=2 up=1") && h.n->np.n_unbound == 0);
    m = h_mark(&h);
    h_peer(&h, &b, 0, 0);
    CHECK(h_said(&h, m, "slot-peer gen=2 up=0"));
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* Test 4, host side: an unknown scope's hello gets lobby state 0; 30 in a
 * second get one answer; 20 ignored close the connection (A16). Scope-zero
 * hello: the listing, by listed slots only. */
static void test_hello_limits(void)
{
    h_t h;
    gz_link_t a = h_host_link(1), b = h_host_link(2);
    uint8_t s[32];
    scope_of(s, 0x33);
    h_init(&h, 1, 1);
    h_start(&h);
    h_peer(&h, &a, 1, 0);
    size_t m = h_mark(&h);
    for (int i = 0; i < 30; i++) CHECK(h_msg(&h, &a, GZ_MSG_KIND_HELLO, s, NULL, 0) == GZ_OK);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1);
    for (size_t i = m; i < h.n_log; i++)
        if (h.log[i].a.kind == GZ_ACTION_SEND) CHECK(h.log[i].kind == GZ_MSG_KIND_LOBBY_STATUS);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) >= 1);
    /* The limit is the link's, not the connection's: reconnecting resets nothing. */
    h_peer(&h, &a, 0, 0);
    h_peer(&h, &a, 1, 0);
    m = h_mark(&h);
    h_msg(&h, &a, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0);
    h.clock += 1000;
    m = h_mark(&h);
    h_msg(&h, &a, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1);
    /* Listing: no listed lobby, nothing; a listed one answers. */
    h_peer(&h, &b, 1, 0);
    m = h_mark(&h);
    h_msg(&h, &b, GZ_MSG_KIND_HELLO, (const uint8_t[32]){0}, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 0 && !h_said(&h, m, "slot-msg"));
    open_host_slot(&h, 7, 0);
    open_host_slot(&h, 8, 1);
    h.clock += 1000;
    m = h_mark(&h);
    h_msg(&h, &b, GZ_MSG_KIND_HELLO, (const uint8_t[32]){0}, NULL, 0);
    CHECK(h_said(&h, m, "slot-msg gen=2 kind=16") && !h_said(&h, m, "gen=1 kind"));
    /* A non-hello lobby kind for an unknown scope: dropped, no answer. */
    m = h_mark(&h);
    h_msg(&h, &b, 20, s, NULL, 0);
    CHECK(h_said(&h, m, "drop why=no-slot") && h_count(&h, m, GZ_ACTION_SEND) == 0);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* B7 moved up: at most 16 unbound; the oldest silent one is pushed out;
 * after 60 s without a message, closed. A seated one is never pushed out. */
static void test_unbound_caps(void)
{
    h_t h;
    uint8_t s[32];
    scope_of(s, 4);
    h_init(&h, 1, 1);
    h_start(&h);
    open_host_slot(&h, 4, 0);
    uint8_t mk[33];
    h_key('M', 100, mk);
    h_arg_t st[2] = {{12, s, 32}, {14, mk, 33}};
    h_cmd(&h, GZ_TE_CMD_SLOT_SEAT, st, 2);
    gz_link_t seated = h_host_link(100);
    h_peer(&h, &seated, 1, 0);
    for (uint32_t i = 1; i <= 16; i++) {
        gz_link_t l = h_host_link(i);
        h.clock += 10;
        h_peer(&h, &l, 1, 0);
        if (i != 1) h_test_msg(&h, &l, "GZPX", NULL, 0, GZ_AREA_TEST); /* all but 1 speak */
    }
    CHECK(h.n->np.n_unbound == 16);
    gz_link_t l17 = h_host_link(17);
    size_t m = h_mark(&h);
    h_peer(&h, &l17, 1, 0);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 1);
    uint8_t k1[33];
    h_key('M', 1, k1);
    CHECK(!memcmp(h.log[m].key, k1, 33) && h.log[m].why == GZ_DISCONNECT_IDLE); /* the silent one */
    CHECK(h.n->np.n_unbound == 16);
    /* The idle timer: everything unbound for 60 s goes; the seated one stays. */
    uint64_t t = 0;
    for (size_t i = 0; i < h.n_log; i++)
        if (h.log[i].a.kind == GZ_ACTION_SET_TIMER && (h.log[i].timer >> 48) == GZ_AREA_NODE) t = h.log[i].timer;
    CHECK(t == ((uint64_t)GZ_AREA_NODE << 48 | NP_TIMER_IDLE));
    h.clock += 61000;
    m = h_mark(&h);
    h_timer(&h, t);
    CHECK(h_count(&h, m, GZ_ACTION_DISCONNECT) == 16);
    for (size_t i = m; i < h.n_log; i++)
        if (h.log[i].a.kind == GZ_ACTION_DISCONNECT) CHECK(memcmp(h.log[i].key, mk, 33) != 0);
    CHECK(h.n->np.n_unbound == 0);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* More connections than the table holds: refused, never an error. */
static void test_conn_table_full(void)
{
    h_t h;
    uint8_t s[32];
    scope_of(s, 4);
    h_init(&h, 1, 1);
    h_start(&h);
    open_host_slot(&h, 4, 0);
    for (uint32_t i = 0; i < NP_MAX_CONNS + 5; i++) {
        uint8_t mk[33];
        h_key('M', 1000 + i, mk);
        h_arg_t st[2] = {{12, s, 32}, {14, mk, 33}};
        if (i < SLOT_MAX_SEATS) h_cmd(&h, GZ_TE_CMD_SLOT_SEAT, st, 2);
        gz_link_t l = h_host_link(1000 + i);
        CHECK(h_peer(&h, &l, 1, 0) == GZ_OK);
    }
    CHECK(h.n->np.n_unbound <= NP_MAX_UNBOUND);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* Slots: the ninth is a refused command; a closed scope is unknown again. */
static void test_slot_limits(void)
{
    h_t h;
    h_init(&h, 1, 1);
    h_start(&h);
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) open_host_slot(&h, (uint8_t)(10 + i), 0);
    size_t m = h_mark(&h);
    open_host_slot(&h, 99, 0);
    CHECK(h_said(&h, m, "result 409 too_many_lobbies"));
    m = h_mark(&h);
    open_host_slot(&h, 10, 0);
    CHECK(h_said(&h, m, "result 409 lobby_exists"));
    uint8_t s[32];
    scope_of(s, 10);
    h_arg_t c[1] = {{12, s, 32}};
    h_cmd(&h, GZ_TE_CMD_SLOT_CLOSE, c, 1);
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_SLOT_CLOSE, c, 1);
    CHECK(h_said(&h, m, "result 404 no_such_lobby"));
    gz_link_t l = h_host_link(1);
    h_peer(&h, &l, 1, 0);
    m = h_mark(&h);
    h_msg(&h, &l, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1 && h.log[h.n_log - 1].kind == GZ_MSG_KIND_LOBBY_STATUS);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

/* The decisions themselves, as functions of the composite's state. */
static void test_decisions(void)
{
    h_t h;
    gz_link_t a = h_host_link(1), b;
    gz_node_id_t k1, k2;
    uint8_t s[32], zero[32] = {0}, first[32] = {1}, last[32] = {0}, rec[32];
    gz_bytes_t none = {NULL, 0}, records;
    size_t at = 0;
    rt_t r;
    last[31] = 1;
    scope_of(s, 1);
    /* Keys and links: every byte of both keys counts. */
    h_key('M', 1, k1.key);
    k2 = k1;
    k2.key[32] ^= 1;
    CHECK(np_same_key(&k1, &k1) && !np_same_key(&k1, &k2));
    k2 = k1;
    k2.key[0] ^= 1;
    CHECK(!np_same_key(&k1, &k2));
    b = a;
    b.local.key[7] ^= 1;
    CHECK(np_same_link(&a, &a) && !np_same_link(&a, &b));
    b = a;
    b.remote.key[32] ^= 1;
    CHECK(!np_same_link(&a, &b));

    h_init(&h, 1, 1);
    h_start(&h);
    open_host_slot(&h, 1, 1);
    /* Scope zero on the host: a hello is the listing's, any other lobby kind
     * is dropped; a round kind is dropped as scope zero. */
    r = gz_route_message(h.n, -1, &a, GZ_MSG_KIND_HELLO, zero, none);
    CHECK(r.kind == RT_LISTING);
    r = gz_route_message(h.n, -1, &a, 20, zero, none);
    CHECK(r.kind == RT_DROP && r.drop == DROP_SCOPE_ZERO);
    r = gz_route_message(h.n, -1, &a, 64, zero, none);
    CHECK(r.kind == RT_DROP && r.drop == DROP_SCOPE_ZERO);
    r = gz_route_message(h.n, -1, &a, 64, last, none);
    CHECK(r.kind == RT_DROP && r.drop == DROP_NO_SLOT);
    /* A scope with one byte set, the first or the last, is not scope zero. */
    r = gz_route_message(h.n, -1, &a, GZ_MSG_KIND_HELLO, first, none);
    CHECK(r.kind == RT_UNKNOWN_HELLO);
    r = gz_route_message(h.n, -1, &a, GZ_MSG_KIND_HELLO, last, none);
    CHECK(r.kind == RT_UNKNOWN_HELLO);
    r = gz_route_message(h.n, -1, &a, GZ_MSG_KIND_HELLO, s, none);
    CHECK(r.kind == RT_BIND && r.slot == gz_route_slot_by_scope(h.n, s));
    /* Seats: every seat of an Open host slot, and of no other. */
    h_key('M', 2, k2.key);
    h_arg_t st1[2] = {{12, s, 32}, {14, k1.key, 33}}, st2[2] = {{12, s, 32}, {14, k2.key, 33}};
    h_cmd(&h, GZ_TE_CMD_SLOT_SEAT, st1, 2);
    h_cmd(&h, GZ_TE_CMD_SLOT_SEAT, st2, 2);
    int slot = gz_route_slot_by_scope(h.n, s);
    CHECK(slot >= 0 && gz_route_slot_seated(h.n, &k1) == slot && gz_route_slot_seated(h.n, &k2) == slot);
    h.n->slots[slot].state = SLOT_CLOSING;
    CHECK(gz_route_slot_seated(h.n, &k1) == -1 && gz_route_slot_by_scope(h.n, s) == -1);
    h.n->slots[slot].state = SLOT_OPEN;
    /* The test family: record 3 is exactly a u16; records that do not parse
     * reach no engine. */
    gz_rec_put(rec, sizeof rec, &at, 1, (const uint8_t *)"GZPIx", 5);
    records.data = rec;
    records.len = at;
    r = gz_route_message(h.n, -1, &a, GZ_MSG_KIND_TEST, zero, records);
    CHECK(r.kind == RT_TEST && r.eng == ENG_TEST0);
    gz_rec_put(rec, sizeof rec, &at, 3, (const uint8_t *)"\x7e\x57\x00", 3);
    records.len = at;
    r = gz_route_message(h.n, -1, &a, GZ_MSG_KIND_TEST, zero, records);
    CHECK(r.kind == RT_DROP && r.drop == DROP_KIND);
    records.len = 1; /* a type and no length */
    r = gz_route_message(h.n, -1, &a, GZ_MSG_KIND_TEST, zero, records);
    CHECK(r.kind == RT_DROP && r.drop == DROP_KIND);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
}

int main(void)
{
    test_family();
    test_decisions();
    test_drops_by_kind();
    test_member_gates();
    test_host_binding();
    test_hello_limits();
    test_unbound_caps();
    test_conn_table_full();
    test_slot_limits();
    return check_done();
}
