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
    a.u.send.peer_id = peer;
    a.u.send.bytes = (gz_bytes_t){data, len};
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
    a = (gz_action_t){.kind = GZ_ACTION_WATCH};
    a.u.watch.script = (gz_bytes_t){src, 2};
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    a = (gz_action_t){.kind = GZ_ACTION_NOTIFY};
    a.u.notify.code = 5;
    a.u.notify.bytes = (gz_bytes_t){src, 1};
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);

    memset(src, 0, sizeof src);     /* the list must not depend on the source any more */
    CHECK(list.count == 4);
    CHECK(list.slots[0].kind == GZ_ACTION_SEND && list.slots[0].u.send.peer_id == 42);
    CHECK(list.slots[0].u.send.bytes.len == 4 && list.slots[0].u.send.bytes.data[0] == 9 &&
          list.slots[0].u.send.bytes.data[3] == 6);
    CHECK(list.slots[0].u.send.bytes.data != src);
    CHECK(list.slots[1].u.broadcast.tx.len == 3 && list.slots[1].u.broadcast.tx.data[2] == 7);
    CHECK(list.slots[2].u.watch.script.len == 2 && list.slots[2].u.watch.script.data[1] == 8);
    CHECK(list.slots[3].u.notify.code == 5 && list.slots[3].u.notify.bytes.len == 1 &&
          list.slots[3].u.notify.bytes.data[0] == 9);
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
    a.u.save.batch_id = 77;
    a.u.save.records = records;
    a.u.save.n_records = 3;
    /* Start the byte block at an odd address so the record array must be aligned. */
    gz_action_list_init(&list, slots, 4, bytes + 1, sizeof bytes - 1);
    CHECK(gz_action_list_add(&list, &a) == GZ_OK);
    memset(one, 0, sizeof one); memset(two, 0, sizeof two); memset(records, 0, sizeof records);

    const gz_action_t *got = &list.slots[0];
    CHECK(got->kind == GZ_ACTION_SAVE && got->u.save.batch_id == 77 && got->u.save.n_records == 3);
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

    save.u.save.n_records = (size_t)-1 / 2;                         /* absurd count: no overflow */
    CHECK(gz_action_list_add(&list, &save) == GZ_ERR_NO_SPACE);
    CHECK(list.count == 1 && list.used == used);

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
    CHECK(list.slots[0].u.send.bytes.data == NULL && list.slots[0].u.send.bytes.len == 0);
}

static void test_which_actions_are_outward(void)
{
    static const struct { gz_action_kind_t kind; int outward; } cases[] = {
        {GZ_ACTION_SAVE, 0}, {GZ_ACTION_SEND, 1}, {GZ_ACTION_BROADCAST, 1}, {GZ_ACTION_WATCH, 0},
        {GZ_ACTION_SET_TIMER, 0}, {GZ_ACTION_CANCEL_TIMER, 0}, {GZ_ACTION_NOTIFY, 1},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        gz_action_t a = {.kind = cases[i].kind};
        CHECK(gz_action_is_outward(&a) == cases[i].outward);
    }
}

int main(void)
{
    test_init_and_reset();
    test_deep_copy_of_every_kind();
    test_timers_use_no_bytes();
    test_save_copies_records();
    test_full_list_is_left_unchanged();
    test_bad_arguments();
    test_which_actions_are_outward();
    return check_done();
}
