/* Tests for the runner (core/gazpacho/runner.c): "save before send".
 *
 * Every scenario is driven through a small interface so the same scenario can
 * be run against the real runner and against two deliberately wrong runners
 * that live only in this file. An independent checker reads the log of what
 * reached the executor and what was confirmed, and decides whether the rule
 * was kept. The wrong runners must be caught by it; the real one never. */
#include "gazpacho/runner.h"
#include "../check.h"
#include <string.h>

/* ---- log of what the outside world saw ---- */

typedef struct { int is_confirm; gz_action_kind_t kind; uint64_t id; int bytes_ok; } entry_t;

#define LOG_MAX 65536
static entry_t g_log[LOG_MAX];
static size_t g_log_n;

static void id_bytes(uint64_t id, uint8_t out[8])
{
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(id >> (8 * i));
}

static int bytes_match(gz_bytes_t b, uint64_t id)
{
    uint8_t want[8];
    id_bytes(id, want);
    return b.len == 8 && memcmp(b.data, want, 8) == 0;
}

/* Every test action carries one identifier, repeated in its payload. */
static uint64_t action_id(const gz_action_t *a, int *bytes_ok)
{
    *bytes_ok = 1;
    switch (a->kind) {
    case GZ_ACTION_SAVE:
        *bytes_ok = a->u.save.n_records == 1 && bytes_match(a->u.save.records[0].bytes, a->u.save.batch_id);
        return a->u.save.batch_id;
    case GZ_ACTION_SEND:
        *bytes_ok = bytes_match(a->u.send.bytes, a->u.send.peer_id);
        return a->u.send.peer_id;
    case GZ_ACTION_NOTIFY:       return a->u.notify.code;
    case GZ_ACTION_SET_TIMER:    return a->u.set_timer.timer_id;
    case GZ_ACTION_CANCEL_TIMER: return a->u.cancel_timer.timer_id;
    case GZ_ACTION_BROADCAST:    return a->u.broadcast.tx.len;
    case GZ_ACTION_WATCH:        return a->u.watch.script.len;
    }
    return 0;
}

static void record_execute(void *ctx, const gz_action_t *a)
{
    (void)ctx;
    entry_t e = {0, a->kind, 0, 0};
    e.id = action_id(a, &e.bytes_ok);
    if (g_log_n < LOG_MAX) g_log[g_log_n++] = e;
}

static void record_confirm(uint64_t id)
{
    entry_t e = {1, GZ_ACTION_SAVE, id, 1};
    if (g_log_n < LOG_MAX) g_log[g_log_n++] = e;
}

/* The independent checker. Returns 1 if, anywhere in the log, an outward
 * action reached the executor while a save that reached it earlier had not
 * been confirmed. It knows nothing about how the runner works. */
static int log_breaks_rule(void)
{
    static uint64_t open[LOG_MAX];
    size_t n_open = 0;
    for (size_t i = 0; i < g_log_n; i++) {
        const entry_t *e = &g_log[i];
        if (e->is_confirm) {
            for (size_t k = 0; k < n_open; k++)
                if (open[k] == e->id) { open[k] = open[--n_open]; break; }
        } else if (e->kind == GZ_ACTION_SAVE) {
            open[n_open++] = e->id;
        } else if ((e->kind == GZ_ACTION_SEND || e->kind == GZ_ACTION_BROADCAST ||
                    e->kind == GZ_ACTION_NOTIFY) && n_open > 0) {
            return 1;
        }
    }
    return 0;
}

/* 1 if the executor saw exactly these actions, in this order (confirmations skipped). */
static int released_are(const uint64_t *ids, size_t n)
{
    size_t k = 0;
    for (size_t i = 0; i < g_log_n; i++) {
        if (g_log[i].is_confirm) continue;
        if (k >= n || g_log[i].id != ids[k] || !g_log[i].bytes_ok) return 0;
        k++;
    }
    return k == n;
}

#define RELEASED(...) released_are((const uint64_t[]){__VA_ARGS__}, sizeof((const uint64_t[]){__VA_ARGS__}) / sizeof(uint64_t))

/* ---- building lists ---- */

static gz_action_t l_slots[32];
static uint8_t l_bytes[2048];
static gz_action_list_t l;

static void list_begin(void) { gz_action_list_init(&l, l_slots, 32, l_bytes, sizeof l_bytes); }

static void add_save(uint64_t batch)
{
    uint8_t b[8];
    id_bytes(batch, b);
    gz_record_t r = {1, {b, 8}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch_id = batch;
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    CHECK(gz_action_list_add(&l, &a) == GZ_OK);
}

static void add_send(uint64_t id)
{
    uint8_t b[8];
    id_bytes(id, b);
    gz_action_t a = {.kind = GZ_ACTION_SEND};
    a.u.send.peer_id = id;
    a.u.send.bytes = (gz_bytes_t){b, 8};
    CHECK(gz_action_list_add(&l, &a) == GZ_OK);
}

static void add_notify(uint32_t id)
{
    gz_action_t a = {.kind = GZ_ACTION_NOTIFY};
    a.u.notify.code = id;
    CHECK(gz_action_list_add(&l, &a) == GZ_OK);
}

static void add_broadcast(size_t id)
{
    static const uint8_t tx[64] = {0};
    gz_action_t a = {.kind = GZ_ACTION_BROADCAST};
    a.u.broadcast.tx = (gz_bytes_t){tx, id};
    CHECK(gz_action_list_add(&l, &a) == GZ_OK);
}

static void add_watch(size_t id)
{
    static const uint8_t script[64] = {0};
    gz_action_t a = {.kind = GZ_ACTION_WATCH};
    a.u.watch.script = (gz_bytes_t){script, id};
    CHECK(gz_action_list_add(&l, &a) == GZ_OK);
}

static void add_timer(uint64_t id)
{
    gz_action_t a = {.kind = GZ_ACTION_SET_TIMER};
    a.u.set_timer.timer_id = id;
    CHECK(gz_action_list_add(&l, &a) == GZ_OK);
}

/* ---- the thing under test, behind one interface ---- */

typedef struct driver {
    gz_status_t (*submit)(struct driver *d, const gz_action_list_t *list);
    gz_status_t (*confirm)(struct driver *d, uint64_t batch);
    gz_runner_t runner;
    gz_action_t slots[64];
    uint8_t bytes[4096];
} driver_t;

static gz_status_t real_submit(driver_t *d, const gz_action_list_t *list) { return gz_runner_submit(&d->runner, list); }

static gz_status_t real_confirm(driver_t *d, uint64_t batch)
{
    record_confirm(batch);          /* logged first: what it releases comes after it */
    gz_status_t st = gz_runner_confirm(&d->runner, batch);
    if (st != GZ_OK) g_log_n--;     /* refused: it confirmed nothing and released nothing */
    return st;
}

/* WRONG ON PURPOSE (1): carries out every action the moment it is submitted. */
static gz_status_t eager_submit(driver_t *d, const gz_action_list_t *list)
{
    for (size_t i = 0; i < list->count; i++) record_execute(d, &list->slots[i]);
    return GZ_OK;
}

static gz_status_t eager_confirm(driver_t *d, uint64_t batch) { (void)d; record_confirm(batch); return GZ_OK; }

/* WRONG ON PURPOSE (2): treats one confirmation as confirming every batch. */
static gz_status_t sloppy_confirm(driver_t *d, uint64_t batch)
{
    record_confirm(batch);
    while (d->runner.n_unconfirmed > 0)
        (void)gz_runner_confirm(&d->runner, d->runner.unconfirmed[0]);
    return GZ_OK;
}

static void driver_init(driver_t *d, int variant)
{
    g_log_n = 0;
    CHECK(gz_runner_init(&d->runner, d->slots, 64, d->bytes, sizeof d->bytes, record_execute, d) == GZ_OK);
    d->submit = variant == 1 ? eager_submit : real_submit;
    d->confirm = variant == 1 ? eager_confirm : variant == 2 ? sloppy_confirm : real_confirm;
}

static driver_t g_driver;

/* ---- scenarios (each returns with the log filled) ---- */

static void scenario_save_then_send(driver_t *d)
{
    list_begin(); add_save(100); add_send(1);
    d->submit(d, &l);
    d->confirm(d, 100);
}

static void scenario_two_saves_then_send(driver_t *d)
{
    list_begin(); add_save(100); add_save(101); add_send(1);
    d->submit(d, &l);
    d->confirm(d, 101);     /* out of order, and only one of the two so far */
    list_begin(); add_notify(2);
    d->submit(d, &l);
    d->confirm(d, 100);
}

/* A small generator, so the random scenario is the same on every machine. */
static uint64_t g_lcg;
static uint32_t next_random(uint32_t bound)
{
    g_lcg = g_lcg * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)(g_lcg >> 33) % bound;
}

/* Many random lists with confirmations arriving at random moments and in
 * random order. Returns the number of actions submitted and accepted. */
/* The batches that reached the executor and have no confirmation yet, read
 * from the log as the storage would know them. Returns how many. */
static size_t open_saves(uint64_t *out)
{
    size_t n = 0;
    for (size_t i = 0; i < g_log_n; i++) {
        if (!g_log[i].is_confirm && g_log[i].kind == GZ_ACTION_SAVE) out[n++] = g_log[i].id;
        if (!g_log[i].is_confirm) continue;
        for (size_t k = 0; k < n; k++)
            if (out[k] == g_log[i].id) { out[k] = out[--n]; break; }
    }
    return n;
}

static size_t scenario_random(driver_t *d, uint64_t seed, int confirm_everything_at_end)
{
    static uint64_t pending[LOG_MAX];
    size_t n_pending = 0, accepted = 0;
    uint64_t next_batch = 1000, next_id = 1;
    g_lcg = seed;
    for (int round = 0; round < 300; round++) {
        list_begin();
        uint32_t n = next_random(5);
        uint64_t first_batch = next_batch;
        for (uint32_t i = 0; i < n; i++) {
            switch (next_random(6)) {
            case 0: case 1: add_save(next_batch++); break;
            case 2: add_send(next_id++); break;
            case 3: add_notify((uint32_t)next_id++); break;
            case 4: add_broadcast(next_random(60)); break;
            default: add_timer(next_id++); break;
            }
        }
        if (d->submit(d, &l) == GZ_OK) accepted += l.count;
        else next_batch = first_batch;      /* refused whole: those batches do not exist */
        n_pending = open_saves(pending);
        while (n_pending && next_random(3) != 0) {
            size_t k = next_random((uint32_t)n_pending);
            d->confirm(d, pending[k]);
            pending[k] = pending[--n_pending];
        }
    }
    while (confirm_everything_at_end && (n_pending = open_saves(pending)) > 0)
        if (d->confirm(d, pending[0]) != GZ_OK) break;     /* a runner that lost track: stop, the checks will say so */
    return accepted;
}

/* ---- tests of the real runner ---- */

static void test_init_arguments(void)
{
    gz_runner_t r;
    CHECK(gz_runner_init(NULL, NULL, 0, NULL, 0, record_execute, NULL) == GZ_ERR_ARGUMENT);
    CHECK(gz_runner_init(&r, NULL, 0, NULL, 0, NULL, NULL) == GZ_ERR_ARGUMENT);
    CHECK(gz_runner_submit(NULL, &l) == GZ_ERR_ARGUMENT);
    CHECK(gz_runner_confirm(NULL, 1) == GZ_ERR_ARGUMENT);
}

static void test_empty_list(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin();
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(g_log_n == 0 && gz_runner_held(&d->runner) == 0 && gz_runner_unconfirmed(&d->runner) == 0);
}

static void test_no_save_means_no_waiting(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_send(1); add_watch(2); add_timer(3); add_broadcast(4); add_notify(5);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(1, 2, 3, 4, 5));
    CHECK(gz_runner_held(&d->runner) == 0);
}

static void test_send_waits_for_its_save(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_send(1);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100));
    CHECK(gz_runner_held(&d->runner) == 1 && gz_runner_unconfirmed(&d->runner) == 1);
    CHECK(d->confirm(d, 100) == GZ_OK);
    CHECK(RELEASED(100, 1));
    CHECK(gz_runner_held(&d->runner) == 0 && gz_runner_unconfirmed(&d->runner) == 0);
    CHECK(!log_breaks_rule());
}

static void test_broadcast_and_notify_wait_too(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_broadcast(7);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100));
    CHECK(d->confirm(d, 100) == GZ_OK);
    list_begin(); add_save(101); add_notify(8);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100, 7, 101));
    CHECK(d->confirm(d, 101) == GZ_OK);
    CHECK(RELEASED(100, 7, 101, 8));
    CHECK(!log_breaks_rule());
}

static void test_saves_interleaved_with_sends(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_send(1); add_save(101); add_send(2);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100));                           /* B is behind X: not even stored yet */
    CHECK(d->confirm(d, 101) == GZ_ERR_UNKNOWN_BATCH);
    CHECK(RELEASED(100));
    CHECK(d->confirm(d, 100) == GZ_OK);
    CHECK(RELEASED(100, 1, 101));
    CHECK(d->confirm(d, 101) == GZ_OK);
    CHECK(RELEASED(100, 1, 101, 2));
    CHECK(!log_breaks_rule());
}

static void test_adjacent_saves_any_confirmation_order(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_save(101); add_send(1);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100, 101));
    CHECK(d->confirm(d, 101) == GZ_OK);
    CHECK(RELEASED(100, 101));                      /* 100 is still unconfirmed */
    CHECK(d->confirm(d, 100) == GZ_OK);
    CHECK(RELEASED(100, 101, 1));
    CHECK(!log_breaks_rule());
}

static void test_order_is_kept_behind_a_waiting_action(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_watch(9); add_timer(10); add_send(1); add_watch(11); add_timer(12);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100, 9, 10));                    /* watch and timer pass; nothing overtakes the send */
    CHECK(gz_runner_held(&d->runner) == 3);
    CHECK(d->confirm(d, 100) == GZ_OK);
    CHECK(RELEASED(100, 9, 10, 1, 11, 12));
}

static void test_the_rule_spans_lists(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100);
    CHECK(d->submit(d, &l) == GZ_OK);
    list_begin(); add_send(1);                      /* a later step's send still waits */
    CHECK(d->submit(d, &l) == GZ_OK);
    list_begin(); add_timer(2);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100));
    CHECK(d->confirm(d, 100) == GZ_OK);
    CHECK(RELEASED(100, 1, 2));
    CHECK(!log_breaks_rule());
}

static void test_unknown_and_repeated_confirmations(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    CHECK(d->confirm(d, 5) == GZ_ERR_UNKNOWN_BATCH);
    list_begin(); add_save(100); add_send(1);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(d->confirm(d, 999) == GZ_ERR_UNKNOWN_BATCH);
    CHECK(RELEASED(100));
    CHECK(d->confirm(d, 100) == GZ_OK);
    CHECK(d->confirm(d, 100) == GZ_ERR_UNKNOWN_BATCH);
    CHECK(RELEASED(100, 1));
}

static void test_duplicate_batch_is_refused_whole(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_send(1); add_save(100); add_save(100);        /* twice in one list */
    CHECK(d->submit(d, &l) == GZ_ERR_DUPLICATE_BATCH);
    CHECK(g_log_n == 0 && gz_runner_held(&d->runner) == 0);

    list_begin(); add_save(100); add_send(1); add_save(101);
    CHECK(d->submit(d, &l) == GZ_OK);
    list_begin(); add_timer(3); add_save(100);                      /* 100 is unconfirmed */
    CHECK(d->submit(d, &l) == GZ_ERR_DUPLICATE_BATCH);
    list_begin(); add_timer(3); add_save(101);                      /* 101 is still queued */
    CHECK(d->submit(d, &l) == GZ_ERR_DUPLICATE_BATCH);
    CHECK(RELEASED(100) && gz_runner_held(&d->runner) == 2);
    CHECK(d->confirm(d, 100) == GZ_OK);
    CHECK(d->confirm(d, 101) == GZ_OK);
    list_begin(); add_save(100);                                    /* confirmed long ago: free again */
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100, 1, 101, 100));
}

static void test_full_queue_refuses_whole_list(void)
{
    static gz_action_t slots[4];
    static uint8_t bytes[256];
    gz_runner_t r;
    g_log_n = 0;
    CHECK(gz_runner_init(&r, slots, 4, bytes, sizeof bytes, record_execute, NULL) == GZ_OK);
    list_begin(); add_save(100); add_send(1); add_send(2);
    CHECK(gz_runner_submit(&r, &l) == GZ_OK);
    list_begin(); add_send(3); add_send(4);                         /* only one slot is left */
    CHECK(gz_runner_submit(&r, &l) == GZ_ERR_NO_SPACE);
    CHECK(gz_runner_held(&r) == 2);
    CHECK(gz_runner_confirm(&r, 100) == GZ_OK);
    CHECK(RELEASED(100, 1, 2));                                     /* 3 and 4 never existed */
    CHECK(gz_runner_submit(&r, &l) == GZ_OK);                       /* drained: there is room again */
    CHECK(RELEASED(100, 1, 2, 3, 4));
}

static void test_queue_storage_is_reclaimed(void)
{
    static gz_action_t slots[4];
    static uint8_t bytes[128];
    gz_runner_t r;
    g_log_n = 0;
    CHECK(gz_runner_init(&r, slots, 4, bytes, sizeof bytes, record_execute, NULL) == GZ_OK);
    int ok = 1;
    for (uint64_t i = 0; i < 5000; i++) {
        list_begin(); add_save(1000 + i); add_send(i);
        ok &= gz_runner_submit(&r, &l) == GZ_OK;
        ok &= gz_runner_confirm(&r, 1000 + i) == GZ_OK;
    }
    CHECK(ok);
    CHECK(g_log_n == 10000 && gz_runner_held(&r) == 0);
}

static void test_limit_on_unconfirmed_batches(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin();
    for (uint64_t i = 0; i <= GZ_RUNNER_MAX_UNCONFIRMED; i++) add_save(100 + i);
    add_send(1);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(gz_runner_unconfirmed(&d->runner) == GZ_RUNNER_MAX_UNCONFIRMED);
    CHECK(gz_runner_held(&d->runner) == 2);                         /* the ninth save and the send */
    CHECK(d->confirm(d, 100 + GZ_RUNNER_MAX_UNCONFIRMED) == GZ_ERR_UNKNOWN_BATCH);
    CHECK(d->confirm(d, 103) == GZ_OK);
    CHECK(gz_runner_held(&d->runner) == 1);                         /* the ninth save went out */
    for (uint64_t i = 0; i <= GZ_RUNNER_MAX_UNCONFIRMED; i++)
        if (i != 3) CHECK(d->confirm(d, 100 + i) == GZ_OK);
    CHECK(gz_runner_held(&d->runner) == 0 && g_log[g_log_n - 1].kind == GZ_ACTION_SEND);
    CHECK(!log_breaks_rule());
}

static void test_submitted_list_may_be_reused_at_once(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_send(1);
    CHECK(d->submit(d, &l) == GZ_OK);
    memset(l_bytes, 0xee, sizeof l_bytes);          /* the runner must hold its own copy */
    memset(l_slots, 0xee, sizeof l_slots);
    CHECK(d->confirm(d, 100) == GZ_OK);
    CHECK(RELEASED(100, 1));                        /* RELEASED also checks the payload bytes */
}

/* A crash: the program stops between the save and its confirmation. The
 * runner is thrown away with what it held, and a new one is built. */
static void test_crash_before_confirmation(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_send(1); add_notify(2); add_broadcast(3);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100));

    memset(&d->runner, 0xdd, sizeof d->runner);     /* the old runner is gone */
    memset(d->slots, 0xdd, sizeof d->slots);
    memset(d->bytes, 0xdd, sizeof d->bytes);
    CHECK(gz_runner_init(&d->runner, d->slots, 64, d->bytes, sizeof d->bytes, record_execute, d) == GZ_OK);

    CHECK(gz_runner_held(&d->runner) == 0 && gz_runner_unconfirmed(&d->runner) == 0);
    CHECK(d->confirm(d, 100) == GZ_ERR_UNKNOWN_BATCH);     /* the late confirmation unlocks nothing */
    list_begin(); add_timer(9);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100, 9));                        /* 1, 2 and 3 never left, and never will */
    CHECK(!log_breaks_rule());
}

static void test_random_schedules(void)
{
    driver_t *d = &g_driver;
    size_t outward = 0;
    for (uint64_t seed = 1; seed <= 200; seed++) {
        driver_init(d, 0);
        size_t accepted = scenario_random(d, seed, 1);
        size_t released = 0;
        int payloads_ok = 1;
        for (size_t i = 0; i < g_log_n; i++) {
            if (g_log[i].is_confirm) continue;
            released++;
            payloads_ok &= g_log[i].bytes_ok;
            outward += g_log[i].kind == GZ_ACTION_SEND || g_log[i].kind == GZ_ACTION_NOTIFY;
        }
        CHECK(!log_breaks_rule());
        CHECK(released == accepted);                /* everything accepted left once all was confirmed */
        CHECK(payloads_ok);
        CHECK(gz_runner_held(&d->runner) == 0 && gz_runner_unconfirmed(&d->runner) == 0);

        driver_init(d, 0);
        scenario_random(d, seed, 0);                /* and with confirmations still outstanding */
        CHECK(!log_breaks_rule());
    }
    CHECK(outward > 1000);                          /* the schedules really did send things */
}

/* ---- the checker must catch a runner that breaks the rule ---- */

static void test_wrong_runners_are_caught(void)
{
    driver_t *d = &g_driver;

    driver_init(d, 0); scenario_save_then_send(d);
    CHECK(!log_breaks_rule());
    driver_init(d, 1); scenario_save_then_send(d);          /* eager: sends before the confirmation */
    CHECK(log_breaks_rule());

    driver_init(d, 0); scenario_two_saves_then_send(d);
    CHECK(!log_breaks_rule());
    driver_init(d, 2); scenario_two_saves_then_send(d);     /* sloppy: one confirmation unlocks all */
    CHECK(log_breaks_rule());

    int eager_caught = 0, sloppy_caught = 0;
    for (uint64_t seed = 1; seed <= 50; seed++) {
        driver_init(d, 1); scenario_random(d, seed, 0); eager_caught += log_breaks_rule();
        driver_init(d, 2); scenario_random(d, seed, 0); sloppy_caught += log_breaks_rule();
    }
    CHECK(eager_caught == 50);
    CHECK(sloppy_caught == 50);
}

int main(void)
{
    test_init_arguments();
    test_empty_list();
    test_no_save_means_no_waiting();
    test_send_waits_for_its_save();
    test_broadcast_and_notify_wait_too();
    test_saves_interleaved_with_sends();
    test_adjacent_saves_any_confirmation_order();
    test_order_is_kept_behind_a_waiting_action();
    test_the_rule_spans_lists();
    test_unknown_and_repeated_confirmations();
    test_duplicate_batch_is_refused_whole();
    test_full_queue_refuses_whole_list();
    test_queue_storage_is_reclaimed();
    test_limit_on_unconfirmed_batches();
    test_submitted_list_may_be_reused_at_once();
    test_crash_before_confirmation();
    test_random_schedules();
    test_wrong_runners_are_caught();
    return check_done();
}
