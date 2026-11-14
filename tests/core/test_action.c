/* Tests for the action list container (core/gazpacho/action.c). */
#include "gazpacho/action.h"
#include "../check.h"
#include <string.h>

static gz_action_t slots[4];
static uint8_t bytes[256];
static gz_action_list_t list;

static gz_action_t send_action(uint64_t peer, const uint8_t *data, size_t len)
{
    gz_action_t a = {.kind = GZ_ACTION_SEND};
    a.u.send.link.remote.key[1] = (uint8_t)peer;
    a.u.send.kind = 32767;
    a.u.send.records = (gz_bytes_t){data, len};
    return a;
}

static void test_init_and_reset(void)
{
    uint8_t msg[3] = {1, 2, 3};
    gz_action_t a = send_action(7, msg, 3);
    gz_action_list_init(&list, slots, 4, bytes, sizeof bytes);
    CHECK(list.count == 0 && list.used == 0);
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    CHECK(list.count == 1 && list.used == 3);
    gz_action_list_reset(&list);
    CHECK(list.count == 0 && list.used == 0);
}

static void test_deep_copy_of_every_kind(void)
{
    uint8_t src[4] = {9, 8, 7, 6};
    gz_action_t a;
    gz_action_list_init(&list, slots, 4, bytes, sizeof bytes);

    a = send_action(42, src, 4);
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    a = (gz_action_t){.kind = GZ_ACTION_BROADCAST};
    a.u.broadcast.tx = (gz_bytes_t){src, 3};
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    a = (gz_action_t){.kind = GZ_ACTION_CONNECT};
    a.u.connect.address = (gz_bytes_t){src, 2};
    a.u.connect.key_index = 77;
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    a = (gz_action_t){.kind = GZ_ACTION_NOTIFY};
    a.u.notify.code = 5;
    a.u.notify.bytes = (gz_bytes_t){src, 1};
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);

    memset(src, 0, sizeof src);     /* the list must not depend on the source any more */
    CHECK(list.count == 4);
    CHECK(list.slots[0].kind == GZ_ACTION_SEND && list.slots[0].u.send.link.remote.key[1] == 42 &&
          list.slots[0].u.send.kind == 32767);
    CHECK(list.slots[0].u.send.records.len == 4 && list.slots[0].u.send.records.data[0] == 9 &&
          list.slots[0].u.send.records.data[3] == 6);
    CHECK(list.slots[0].u.send.records.data != src);
    CHECK(list.slots[1].u.broadcast.tx.len == 3 && list.slots[1].u.broadcast.tx.data[2] == 7);
    CHECK(list.slots[2].u.connect.address.len == 2 && list.slots[2].u.connect.address.data[1] == 8 &&
          list.slots[2].u.connect.address.data != src && list.slots[2].u.connect.key_index == 77);
    CHECK(list.slots[3].u.notify.code == 5 && list.slots[3].u.notify.bytes.len == 1 &&
          list.slots[3].u.notify.bytes.data[0] == 9);
}

/* The chain watches hold everything by value: no bytes are used, the values
 * are kept, and a depth of 0 is refused without changing the list. */
static void test_chain_watches(void)
{
    gz_action_t a = {.kind = GZ_ACTION_WATCH_TX};
    for (int i = 0; i < 32; i++) a.u.watch_tx.txid[i] = (uint8_t)(i + 1);
    a.u.watch_tx.depth = 6;
    gz_action_list_init(&list, slots, 4, bytes, sizeof bytes);
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    a.u.watch_tx.depth = 0;
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);
    gz_action_t o = {.kind = GZ_ACTION_WATCH_OUTPOINT};
    o.u.watch_outpoint.outpoint.txid[31] = 0xee;
    o.u.watch_outpoint.outpoint.vout = 70000;
    o.u.watch_outpoint.depth = 1;
    CHECK(gz_action_list_add(&list, &o) == GZ_OK);
    o.u.watch_outpoint.depth = 0;
    CHECK(gz_action_list_add(&list, &o) == GZ_ERR_ARGUMENT);
    CHECK(list.count == 2 && list.used == 0);
    CHECK(list.slots[0].u.watch_tx.depth == 6 && list.slots[0].u.watch_tx.txid[0] == 1 &&
          list.slots[0].u.watch_tx.txid[31] == 32);
    CHECK(list.slots[1].u.watch_outpoint.outpoint.vout == 70000 &&
          list.slots[1].u.watch_outpoint.outpoint.txid[31] == 0xee && list.slots[1].u.watch_outpoint.depth == 1);
    gz_action_t unknown = {.kind = (gz_action_kind_t)(GZ_ACTION_WATCH_OUTPOINT + 1)};
    CHECK(gz_action_list_add(&list, &unknown) == GZ_ERR_ARGUMENT);
    CHECK(list.count == 2);
}

static void test_timers_use_no_bytes(void)
{
    gz_action_t a = {.kind = GZ_ACTION_SET_TIMER};
    a.u.set_timer.timer_id = 11;
    a.u.set_timer.delay_ms = 3000;
    gz_action_list_init(&list, slots, 4, bytes, sizeof bytes);
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    a = (gz_action_t){.kind = GZ_ACTION_CANCEL_TIMER};
    a.u.cancel_timer.timer_id = 11;
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    CHECK(list.used == 0);
    CHECK(list.slots[0].u.set_timer.timer_id == 11 && list.slots[0].u.set_timer.delay_ms == 3000);
    CHECK(list.slots[1].kind == GZ_ACTION_CANCEL_TIMER && list.slots[1].u.cancel_timer.timer_id == 11);
}

static void test_save_copies_records(void)
{
    uint8_t one[5] = {1, 1, 1, 1, 1}, two[2] = {2, 2};
    gz_record_t records[3] = {{100, {one, 5}}, {200, {two, 2}}, {300, {NULL, 0}}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch.sequence = 77;
    a.u.save.records = records;
    a.u.save.n_records = 3;
    /* Start the byte block at an odd address so the record array must be aligned. */
    gz_action_list_init(&list, slots, 4, bytes + 1, sizeof bytes - 1);
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    memset(one, 0, sizeof one); memset(two, 0, sizeof two); memset(records, 0, sizeof records);

    const gz_action_t *got = &list.slots[0];
    CHECK(got->kind == GZ_ACTION_SAVE && got->u.save.batch.sequence == 77 && got->u.save.n_records == 3);
    CHECK((uintptr_t)got->u.save.records % _Alignof(gz_record_t) == 0);
    CHECK(got->u.save.records[0].type == 100 && got->u.save.records[0].bytes.len == 5 &&
          got->u.save.records[0].bytes.data[4] == 1);
    CHECK(got->u.save.records[1].type == 200 && got->u.save.records[1].bytes.len == 2 &&
          got->u.save.records[1].bytes.data[1] == 2);
    CHECK(got->u.save.records[2].type == 300 && got->u.save.records[2].bytes.len == 0 &&
          got->u.save.records[2].bytes.data == NULL);

    a.u.save.n_records = 0;         /* an empty batch is allowed */
    a.u.save.records = NULL;
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    CHECK(list.slots[1].u.save.n_records == 0 && list.slots[1].u.save.records == NULL);

    a.u.save.records = records;     /* a stray pointer with a zero count is not kept */
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    CHECK(list.slots[2].u.save.n_records == 0 && list.slots[2].u.save.records == NULL);
}

static void test_full_list_is_left_unchanged(void)
{
    uint8_t big[200];
    memset(big, 0x55, sizeof big);
    gz_action_t a = send_action(1, big, 200);
    gz_action_list_init(&list, slots, 2, bytes, sizeof bytes);
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    size_t used = list.used;

    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_NO_SPACE);       /* bytes do not fit */
    CHECK(list.count == 1 && list.used == used);

    gz_record_t records[2] = {{1, {big, 30}}, {2, {big, 30}}};     /* fails part-way through */
    gz_action_t save = {.kind = GZ_ACTION_SAVE};
    save.u.save.records = records;
    save.u.save.n_records = 2;
    CHECK(gz_action_list_add(&list, &save) == GZ_ERR_NO_SPACE);
    CHECK(list.count == 1 && list.used == used);

    save.u.save.n_records = (size_t)-1 / 2;                         /* absurd count */
    CHECK(gz_action_list_add(&list, &save) == GZ_ERR_NO_SPACE);
    CHECK(list.count == 1 && list.used == used);

    /* A count chosen so that count * sizeof(gz_record_t) wraps round to a
     * few bytes. Without the guard on the count the array would seem to fit
     * and records would be written over the block before the bytes ran out.
     * The block must come back untouched. */
    gz_record_t many[16];
    int untouched = 1;
    for (int i = 0; i < 16; i++) many[i] = (gz_record_t){(uint32_t)i, {big, 30}};
    memset(bytes, 0xaa, sizeof bytes);
    gz_action_list_init(&list, slots, 2, bytes, sizeof bytes);
    save.u.save.records = many;
    save.u.save.n_records = (size_t)-1 / sizeof(gz_record_t) + 1;
    CHECK(save.u.save.n_records * sizeof(gz_record_t) < sizeof(gz_record_t));
    CHECK(gz_action_list_add(&list, &save) == GZ_ERR_NO_SPACE);
    for (size_t i = 0; i < sizeof bytes; i++) untouched &= bytes[i] == 0xaa;
    CHECK(untouched && list.count == 0 && list.used == 0);
    gz_action_list_init(&list, slots, 2, bytes, sizeof bytes);
    a = send_action(1, big, 200);
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);

    a = send_action(2, big, 1);
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_NO_SPACE);       /* no slot left */
    CHECK(list.count == 2);
}

static void test_bad_arguments(void)
{
    gz_action_t a = send_action(1, NULL, 5);        /* a length with no data */
    gz_action_list_init(&list, slots, 4, bytes, sizeof bytes);
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);
    a = (gz_action_t){.kind = (gz_action_kind_t)99};
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);
    a = (gz_action_t){.kind = GZ_ACTION_SAVE};
    a.u.save.n_records = 1;                         /* a count with no records */
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);
    CHECK(gz_action_list_add(NULL, &a) == GZ_ERR_ARGUMENT);
    CHECK(gz_action_list_add(&list, NULL) == GZ_ERR_ARGUMENT);
    CHECK(list.count == 0 && list.used == 0);

    a = send_action(1, NULL, 0);                    /* an empty message is fine */
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    CHECK(list.slots[0].u.send.records.data == NULL && list.slots[0].u.send.records.len == 0);
}

static void test_which_actions_are_outward(void)
{
    static const struct { gz_action_kind_t kind; int outward; } cases[] = {
        {GZ_ACTION_SAVE, 0}, {GZ_ACTION_SEND, 1}, {GZ_ACTION_BROADCAST, 1}, {GZ_ACTION_WATCH_SCRIPT, 0},
        {GZ_ACTION_CONNECT, 1}, {GZ_ACTION_DISCONNECT, 0}, {GZ_ACTION_SET_SEATED, 0},
        {GZ_ACTION_SET_TIMER, 0}, {GZ_ACTION_CANCEL_TIMER, 0}, {GZ_ACTION_NOTIFY, 1},
        {GZ_ACTION_WATCH_TX, 0}, {GZ_ACTION_WATCH_OUTPOINT, 0},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        gz_action_t a = {.kind = cases[i].kind};
        CHECK(gz_action_is_outward(&a) == cases[i].outward);
    }
}

/* Contract v2: what gz_action_list_add refuses, each leaving the list as it was. */
static void test_contract_v2_refusals(void)
{
    uint8_t b[70] = {1};
    gz_action_t a;
    gz_action_list_init(&list, slots, 4, bytes, sizeof bytes);
    a = (gz_action_t){.kind = GZ_ACTION_WATCH_SCRIPT};
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);       /* retired */
    a = send_action(1, b, 1);
    a.u.send.kind = 0;
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);
    a.u.send.kind = 2;                                               /* part: the transport's own */
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);
    a.u.send.kind = 16;
    a.u.send.records.len = GZ_SEND_MAX_RECORDS + 1;
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);
    a = (gz_action_t){.kind = GZ_ACTION_CONNECT};
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);       /* no address */
    a.u.connect.address = (gz_bytes_t){b, 65};
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);
    a = (gz_action_t){.kind = GZ_ACTION_DISCONNECT};
    a.u.disconnect.why = 4;
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);
    a = (gz_action_t){.kind = GZ_ACTION_SET_SEATED};
    a.u.set_seated.seated = 2;
    CHECK(gz_action_list_add(&list, &a) == GZ_ERR_ARGUMENT);
    CHECK(list.count == 0 && list.used == 0);
    a.u.set_seated.seated = 1;
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    a = (gz_action_t){.kind = GZ_ACTION_DISCONNECT};
    a.u.disconnect.why = GZ_DISCONNECT_HOST_FAULT;
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    a = (gz_action_t){.kind = GZ_ACTION_CONNECT};
    a.u.connect.address = (gz_bytes_t){b, 64};
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    CHECK(list.count == 3 && list.used == 64);
}

int main(void)
{
    test_contract_v2_refusals();
    test_init_and_reset();
    test_deep_copy_of_every_kind();
    test_chain_watches();
    test_timers_use_no_bytes();
    test_save_copies_records();
    test_full_list_is_left_unchanged();
    test_bad_arguments();
    test_which_actions_are_outward();
    return check_done();
}
