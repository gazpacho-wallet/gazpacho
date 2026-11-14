/* Tests for the runner (core/gazpacho/runner.c): "save before send".
 *
 * Scenarios are driven through a small interface so the same scenario can be
 * run against the real runner and against two deliberately wrong runners that
 * live only in this file. Two independent judges read the log of what reached
 * the executor: a checker that knows only the rule, and a model that computes,
 * from the history of submissions and confirmations alone, the exact order in
 * which everything must have been released. The wrong runners must be caught;
 * the real one never.
 *
 * The tests use only the runner's documented functions. */
#include "gazpacho/runner.h"
#include "../check.h"
#include <stdlib.h>
#include <string.h>

#define INCARNATION 7

/* ---- log of what the outside world saw ---- */

/* Three kinds of entry: an action offered to the runner (written by the test
 * when it submits a list), an action that reached the executor, and a
 * confirmation. */
typedef struct { int is_confirm, is_offer; gz_action_kind_t kind; uint64_t id; uint64_t seq; } entry_t;

#define LOG_MAX 65536
static entry_t g_log[LOG_MAX];
static size_t g_log_n;
static int g_payloads_ok, g_incarnations_ok;

static void id_bytes(uint64_t id, uint8_t out[8])
{
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(id >> (8 * i));
}

static uint64_t bytes_id(gz_bytes_t b)
{
    uint64_t id = 0;
    if (b.len != 8) { g_payloads_ok = 0; return 0; }
    for (int i = 0; i < 8; i++) id |= (uint64_t)b.data[i] << (8 * i);
    return id;
}

/* Every test action carries one identifier: in its payload, or in the timer
 * identifier. A save with no records has identifier 0. */
static uint64_t action_id(const gz_action_t *a)
{
    switch (a->kind) {
    case GZ_ACTION_SAVE:         return a->u.save.n_records ? bytes_id(a->u.save.records[0].bytes) : 0;
    case GZ_ACTION_SEND:         if (bytes_id((gz_bytes_t){a->u.send.link.remote.key, 8}) != bytes_id(a->u.send.records))
                                     g_payloads_ok = 0;
                                 return bytes_id(a->u.send.records);
    case GZ_ACTION_BROADCAST:    return bytes_id(a->u.broadcast.tx);
    case GZ_ACTION_WATCH_SCRIPT: return 0; /* retired: never released */
    case GZ_ACTION_CONNECT:      return bytes_id(a->u.connect.address);
    case GZ_ACTION_DISCONNECT:   return bytes_id((gz_bytes_t){a->u.disconnect.link.remote.key, 8});
    case GZ_ACTION_SET_SEATED:   return bytes_id((gz_bytes_t){a->u.set_seated.member.key, 8});
    case GZ_ACTION_WATCH_TX:     return bytes_id((gz_bytes_t){a->u.watch_tx.txid, 8});
    case GZ_ACTION_WATCH_OUTPOINT: return bytes_id((gz_bytes_t){a->u.watch_outpoint.outpoint.txid, 8});
    case GZ_ACTION_NOTIFY:       if (a->u.notify.code != (uint32_t)bytes_id(a->u.notify.bytes)) g_payloads_ok = 0;
                                 return bytes_id(a->u.notify.bytes);
    case GZ_ACTION_SET_TIMER:    return a->u.set_timer.timer_id;
    case GZ_ACTION_CANCEL_TIMER: return a->u.cancel_timer.timer_id;
    }
    return 0;
}

/* Something for the executor to do in the middle of a release, or NULL. */
static void (*g_inside_executor)(void);

static void record_execute(void *ctx, const gz_action_t *a)
{
    (void)ctx;
    entry_t e = {0, 0, a->kind, action_id(a), 0};
    if (a->kind == GZ_ACTION_SAVE) {
        e.seq = a->u.save.batch.sequence;
        if (a->u.save.batch.incarnation != INCARNATION) g_incarnations_ok = 0;
    }
    if (g_log_n < LOG_MAX) g_log[g_log_n++] = e;
    if (g_inside_executor) g_inside_executor();
}

static void record_confirm(uint64_t seq)
{
    entry_t e = {1, 0, GZ_ACTION_SAVE, 0, seq};
    if (g_log_n < LOG_MAX) g_log[g_log_n++] = e;
}

static int is_outward_kind(gz_action_kind_t k)
{
    return k == GZ_ACTION_SEND || k == GZ_ACTION_BROADCAST || k == GZ_ACTION_NOTIFY;
}

/* Write down every action of a list as offered, in order. */
static void record_offers(const gz_action_list_t *list)
{
    for (size_t i = 0; i < list->count && g_log_n < LOG_MAX; i++) {
        entry_t e = {0, 1, list->slots[i].kind, action_id(&list->slots[i]), 0};
        g_log[g_log_n++] = e;
    }
}

/* Judge 1. Returns 1 if, anywhere in the log, an outward action reached the
 * executor before every save offered ahead of it had been confirmed. It knows
 * the rule and nothing about how the runner works. Outward actions are told
 * apart by their identifiers, which the tests keep unique. */
static int log_breaks_rule(void)
{
    static uint64_t need_id[LOG_MAX], need_saves[LOG_MAX];
    size_t n_needs = 0;
    uint64_t saves_offered = 0, confirms = 0;
    for (size_t i = 0; i < g_log_n; i++) {
        const entry_t *e = &g_log[i];
        if (e->is_confirm) { confirms++; continue; }
        if (e->is_offer) {
            if (e->kind == GZ_ACTION_SAVE) saves_offered++;
            else if (is_outward_kind(e->kind)) { need_id[n_needs] = e->id; need_saves[n_needs++] = saves_offered; }
            continue;
        }
        if (!is_outward_kind(e->kind)) continue;
        size_t k = 0;
        while (k < n_needs && need_id[k] != e->id) k++;
        if (k == n_needs || confirms < need_saves[k]) return 1;     /* never offered, or released too early */
    }
    return 0;
}

/* 1 if the executor saw exactly these actions, in this order (confirmations skipped). */
static int released_are(const uint64_t *ids, size_t n)
{
    size_t k = 0;
    for (size_t i = 0; i < g_log_n; i++) {
        if (g_log[i].is_confirm || g_log[i].is_offer) continue;
        if (k >= n || g_log[i].id != ids[k]) return 0;
        k++;
    }
    return k == n && g_payloads_ok && g_incarnations_ok;
}

#define RELEASED(...) released_are((const uint64_t[]){__VA_ARGS__}, sizeof((const uint64_t[]){__VA_ARGS__}) / sizeof(uint64_t))

/* Batch sequence of the first save that reached the executor, or 0. */
static uint64_t first_save_sequence(void)
{
    for (size_t i = 0; i < g_log_n; i++)
        if (!g_log[i].is_confirm && !g_log[i].is_offer && g_log[i].kind == GZ_ACTION_SAVE) return g_log[i].seq;
    return 0;
}

static size_t released_count(void)
{
    size_t n = 0;
    for (size_t i = 0; i < g_log_n; i++) n += !g_log[i].is_confirm && !g_log[i].is_offer;
    return n;
}

/* ---- building lists ---- */

static gz_action_t l_slots[80];
static uint8_t l_bytes[4096];
static gz_action_list_t l;

static void list_begin(void) { gz_action_list_init(&l, l_slots, 80, l_bytes, sizeof l_bytes); }

static void add_save(uint64_t id)
{
    uint8_t b[8];
    id_bytes(id, b);
    gz_record_t r = {1, {b, 8}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch.sequence = 999999;       /* whatever the node leaves here must be ignored */
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    CHECK(gz_action_list_add(&l, &a) == GZ_OK);
}

static void add_empty_save(void)
{
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    CHECK(gz_action_list_add(&l, &a) == GZ_OK);
}

static void add_kind(gz_action_kind_t kind, uint64_t id)
{
    uint8_t b[8];
    gz_action_t a = {.kind = kind};
    id_bytes(id, b);
    switch (kind) {
    case GZ_ACTION_SEND:      memcpy(a.u.send.link.remote.key, b, 8); a.u.send.kind = 16; a.u.send.records = (gz_bytes_t){b, 8}; break;
    case GZ_ACTION_BROADCAST: a.u.broadcast.tx = (gz_bytes_t){b, 8}; break;
    case GZ_ACTION_DISCONNECT: memcpy(a.u.disconnect.link.remote.key, b, 8); break;
    case GZ_ACTION_WATCH_TX:  memcpy(a.u.watch_tx.txid, b, 8); a.u.watch_tx.depth = 1; break;
    case GZ_ACTION_WATCH_OUTPOINT: memcpy(a.u.watch_outpoint.outpoint.txid, b, 8); a.u.watch_outpoint.depth = 1; break;
    case GZ_ACTION_NOTIFY:    a.u.notify.code = (uint32_t)id; a.u.notify.bytes = (gz_bytes_t){b, 8}; break;
    case GZ_ACTION_SET_TIMER: a.u.set_timer.timer_id = id; break;
    default:                  a.u.cancel_timer.timer_id = id; break;
    }
    CHECK(gz_action_list_add(&l, &a) == GZ_OK);
}

static void add_send(uint64_t id)      { add_kind(GZ_ACTION_SEND, id); }
static void add_notify(uint64_t id)    { add_kind(GZ_ACTION_NOTIFY, id); }
static void add_broadcast(uint64_t id) { add_kind(GZ_ACTION_BROADCAST, id); }
/* A non-outward action that carries the identifier (once WATCH_SCRIPT, retired). */
static void add_watch(uint64_t id)     { add_kind(GZ_ACTION_DISCONNECT, id); }
static void add_watch_tx(uint64_t id)  { add_kind(GZ_ACTION_WATCH_TX, id); }
static void add_watch_outpoint(uint64_t id) { add_kind(GZ_ACTION_WATCH_OUTPOINT, id); }
static void add_timer(uint64_t id)     { add_kind(GZ_ACTION_SET_TIMER, id); }

static gz_batch_id_t batch(uint64_t incarnation, uint64_t sequence)
{
    gz_batch_id_t b = {incarnation, sequence};
    return b;
}

/* ---- the thing under test, behind one interface ---- */

typedef struct driver {
    gz_status_t (*submit)(struct driver *d, const gz_action_list_t *list);
    gz_status_t (*confirm)(struct driver *d, uint64_t seq);
    gz_runner_t runner;
    gz_runner_slot_t slots[64];
    uint8_t bytes[4096];
    uint64_t eager_issued;
} driver_t;

/* Submit a list to a runner, writing its actions down as offered first. */
static gz_status_t submit_logged(gz_runner_t *runner, const gz_action_list_t *list)
{
    size_t before = g_log_n;
    record_offers(list);
    gz_status_t st = gz_runner_submit(runner, list);
    if (st != GZ_OK) g_log_n = before;      /* refused: nothing of it was taken or executed */
    return st;
}

static gz_status_t real_submit(driver_t *d, const gz_action_list_t *list) { return submit_logged(&d->runner, list); }

/* Confirm a batch to a runner, writing the confirmation down first: what it
 * releases comes after it in the log. */
static gz_status_t confirm_logged(gz_runner_t *runner, uint64_t seq)
{
    record_confirm(seq);
    gz_status_t st = gz_runner_confirm(runner, batch(INCARNATION, seq));
    if (st != GZ_OK) g_log_n--;     /* refused: it confirmed nothing and released nothing */
    return st;
}

static gz_status_t real_confirm(driver_t *d, uint64_t seq) { return confirm_logged(&d->runner, seq); }

/* WRONG ON PURPOSE (1): carries out every action the moment it is submitted. */
static gz_status_t eager_submit(driver_t *d, const gz_action_list_t *list)
{
    record_offers(list);
    for (size_t i = 0; i < list->count; i++) {
        gz_action_t a = list->slots[i];
        if (a.kind == GZ_ACTION_SAVE) a.u.save.batch = batch(INCARNATION, ++d->eager_issued);
        record_execute(d, &a);
    }
    return GZ_OK;
}

static gz_status_t eager_confirm(driver_t *d, uint64_t seq) { (void)d; record_confirm(seq); return GZ_OK; }

/* WRONG ON PURPOSE (2): treats one confirmation as confirming every batch
 * handed to storage so far. */
static gz_status_t sloppy_confirm(driver_t *d, uint64_t seq)
{
    record_confirm(seq);
    while (gz_runner_unconfirmed(&d->runner) > 0) {
        seq = 0;
        for (size_t i = 0; i < g_log_n; i++)        /* the newest batch the executor has seen... */
            if (!g_log[i].is_confirm && !g_log[i].is_offer && g_log[i].kind == GZ_ACTION_SAVE) seq = g_log[i].seq;
        seq -= gz_runner_unconfirmed(&d->runner) - 1;   /* ...back to the oldest unconfirmed one */
        if (gz_runner_confirm(&d->runner, batch(INCARNATION, seq)) != GZ_OK) break;
    }
    return GZ_OK;
}

static void log_reset(void)
{
    g_log_n = 0;
    g_payloads_ok = g_incarnations_ok = 1;
    g_inside_executor = NULL;
}

static void driver_init(driver_t *d, int variant)
{
    log_reset();
    d->eager_issued = 0;
    CHECK(gz_runner_init(&d->runner, d->slots, 64, d->bytes, sizeof d->bytes, INCARNATION, record_execute, d) == GZ_OK);
    d->submit = variant == 1 ? eager_submit : real_submit;
    d->confirm = variant == 1 ? eager_confirm : variant == 2 ? sloppy_confirm : real_confirm;
}

static driver_t g_driver;

/* ---- Judge 2: the model ----
 *
 * It records the history (which lists were submitted, when each confirmation
 * came) and afterwards works out when every action must have been released:
 *   - a save: at its place in its own submission;
 *   - any other action: no earlier than its own place in its own submission;
 *     if outward, no earlier than the confirmation of the last save submitted
 *     before it; and no earlier than the action before it that is not a save.
 * Sorting by those moments gives the one permitted order of the log. */

typedef struct { gz_action_kind_t kind; uint64_t id; uint64_t when; uint64_t needs; } model_action_t;

#define MODEL_MAX 8192
static model_action_t m_actions[MODEL_MAX];
static size_t m_n;
static uint64_t m_confirm_when[MODEL_MAX];      /* by batch sequence */
static uint64_t m_saves, m_confirms, m_op;

#define NOT_YET UINT64_MAX

static void model_reset(void) { m_n = 0; m_saves = m_confirms = m_op = 0; }

static void model_submit(const gz_action_list_t *list)
{
    m_op++;
    for (size_t i = 0; i < list->count; i++) {
        model_action_t a = {list->slots[i].kind, action_id(&list->slots[i]), m_op * 1000 + i, 0};
        if (a.kind == GZ_ACTION_SAVE) m_confirm_when[++m_saves] = NOT_YET;
        a.needs = m_saves;
        m_actions[m_n++] = a;
    }
}

static void model_confirm(void)
{
    m_op++;
    m_confirm_when[++m_confirms] = m_op * 1000;
}

/* 1 if the log holds exactly what the model says, in the model's order. */
static int log_matches_model(void)
{
    static struct { uint64_t when, id; gz_action_kind_t kind; } want[MODEL_MAX];
    size_t n = 0;
    uint64_t previous = 0;
    for (size_t i = 0; i < m_n; i++) {
        uint64_t when = m_actions[i].when;
        if (m_actions[i].kind != GZ_ACTION_SAVE) {
            if (is_outward_kind(m_actions[i].kind) && m_actions[i].needs > 0) {
                uint64_t stored = m_confirm_when[m_actions[i].needs];
                if (stored > when) when = stored;
            }
            if (previous > when) when = previous;
            previous = when;
        }
        if (when == NOT_YET) continue;
        size_t at = n++;                        /* insert in order of `when`; ties keep submission order */
        while (at > 0 && want[at - 1].when > when) { want[at] = want[at - 1]; at--; }
        want[at].when = when; want[at].id = m_actions[i].id; want[at].kind = m_actions[i].kind;
    }
    size_t k = 0;
    for (size_t i = 0; i < g_log_n; i++) {
        if (g_log[i].is_confirm || g_log[i].is_offer) continue;
        if (k >= n || g_log[i].id != want[k].id || g_log[i].kind != want[k].kind) return 0;
        k++;
    }
    return k == n;
}

/* ---- scenarios ---- */

static void scenario_save_then_send(driver_t *d)
{
    list_begin(); add_save(100); add_send(1);
    d->submit(d, &l);
    d->confirm(d, 1);
}

static void scenario_two_saves_then_send(driver_t *d)
{
    list_begin(); add_save(100); add_save(101); add_send(1);
    d->submit(d, &l);
    d->confirm(d, 1);       /* only the first of the two */
    list_begin(); add_notify(2);
    d->submit(d, &l);
    d->confirm(d, 2);
}

/* A small generator, so the random scenario is the same on every machine. */
static uint64_t g_lcg;
static uint32_t next_random(uint32_t bound)
{
    g_lcg = g_lcg * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)(g_lcg >> 33) % bound;
}

/* Many random lists, with confirmations arriving in order at random moments.
 * The model is told the same history. Returns the number of lists refused. */
static size_t scenario_random(driver_t *d, uint64_t seed, int confirm_everything_at_end)
{
    uint64_t next_id = 1, saves = 0, confirmed = 0;
    size_t refused = 0;
    g_lcg = seed;
    model_reset();
    for (int round = 0; round < 300; round++) {
        uint64_t saves_in_list = 0;
        list_begin();
        for (uint32_t n = next_random(6); n > 0; n--) {
            switch (next_random(10)) {
            case 0: case 1: add_save(next_id++); saves_in_list++; break;
            case 2: add_empty_save(); saves_in_list++; break;
            case 3: add_send(next_id++); break;
            case 4: add_notify(next_id++); break;
            case 5: add_broadcast(next_id++); break;
            case 6: add_watch(next_id++); break;
            case 7: add_watch_tx(next_id++); break;
            case 8: add_watch_outpoint(next_id++); break;
            default: add_timer(next_id++); break;
            }
        }
        if (d->submit(d, &l) != GZ_OK) { refused++; break; }    /* fatal for a real node: stop here */
        model_submit(&l);
        saves += saves_in_list;
        while (confirmed < saves && next_random(3) != 0) {
            if (d->confirm(d, ++confirmed) != GZ_OK) return refused + 1000;
            model_confirm();
        }
    }
    while (confirm_everything_at_end && confirmed < saves) {
        if (d->confirm(d, ++confirmed) != GZ_OK) return refused + 1000;
        model_confirm();
    }
    return refused;
}

/* ---- tests of the real runner ---- */

static void test_arguments(void)
{
    gz_runner_t r;
    list_begin();
    CHECK(gz_runner_init(NULL, NULL, 0, NULL, 0, 1, record_execute, NULL) == GZ_ERR_ARGUMENT);
    CHECK(gz_runner_init(&r, NULL, 0, NULL, 0, 1, NULL, NULL) == GZ_ERR_ARGUMENT);
    CHECK(gz_runner_init(&r, NULL, 0, NULL, 0, 1, record_execute, NULL) == GZ_OK);
    CHECK(gz_runner_submit(NULL, &l) == GZ_ERR_ARGUMENT);
    CHECK(gz_runner_submit(&r, NULL) == GZ_ERR_ARGUMENT);
    CHECK(gz_runner_confirm(NULL, batch(1, 1)) == GZ_ERR_ARGUMENT);
    CHECK(gz_runner_storage_failed(NULL) == GZ_ERR_ARGUMENT);
    CHECK(!gz_runner_failed(&r));               /* argument errors are not fatal */
    CHECK(gz_runner_submit(&r, &l) == GZ_OK);
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
    CHECK(first_save_sequence() == 1);              /* the runner's identifier, not the node's 999999 */
    CHECK(gz_runner_held(&d->runner) == 1 && gz_runner_unconfirmed(&d->runner) == 1);
    CHECK(d->confirm(d, 1) == GZ_OK);
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
    CHECK(d->confirm(d, 1) == GZ_OK);
    list_begin(); add_save(101); add_notify(8);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100, 7, 101));
    CHECK(d->confirm(d, 2) == GZ_OK);
    CHECK(RELEASED(100, 7, 101, 8));
    CHECK(!log_breaks_rule());
}

static void test_saves_never_wait(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_send(1); add_save(101); add_send(2);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100, 101));                      /* B goes to storage although X is still held */
    CHECK(first_save_sequence() == 1);
    CHECK(gz_runner_held(&d->runner) == 2 && gz_runner_unconfirmed(&d->runner) == 2);
    CHECK(d->confirm(d, 1) == GZ_OK);
    CHECK(RELEASED(100, 101, 1));                   /* X needed A only; Y still needs B */
    CHECK(d->confirm(d, 2) == GZ_OK);
    CHECK(RELEASED(100, 101, 1, 2));
    CHECK(!log_breaks_rule());
}

static void test_send_waits_for_every_earlier_save(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_save(101); add_send(1);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(d->confirm(d, 1) == GZ_OK);
    CHECK(RELEASED(100, 101));                      /* 101 is still unconfirmed */
    CHECK(d->confirm(d, 2) == GZ_OK);
    CHECK(RELEASED(100, 101, 1));
    CHECK(!log_breaks_rule());
}

static void test_empty_batch_is_a_batch(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_empty_save(); add_send(1);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(0));                             /* the empty save went to storage; the send waits */
    CHECK(first_save_sequence() == 1);
    CHECK(gz_runner_unconfirmed(&d->runner) == 1 && gz_runner_held(&d->runner) == 1);
    CHECK(d->confirm(d, 1) == GZ_OK);
    CHECK(RELEASED(0, 1));
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
    CHECK(d->confirm(d, 1) == GZ_OK);
    CHECK(RELEASED(100, 9, 10, 1, 11, 12));
}

/* The convention in action.h: a timer that times out a send goes after it. */
static void test_timer_placed_after_its_send_waits_with_it(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_send(1); add_timer(50);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100));                           /* the timer is not set while the send waits */
    CHECK(d->confirm(d, 1) == GZ_OK);
    CHECK(RELEASED(100, 1, 50));

    driver_init(d, 0);
    list_begin(); add_save(100); add_timer(50); add_send(1);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100, 50));                       /* placed before, it is set at once: the wrong way */
}

static void test_the_rule_spans_lists(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100);
    CHECK(d->submit(d, &l) == GZ_OK);
    list_begin(); add_send(1);                      /* a later step's send still waits */
    CHECK(d->submit(d, &l) == GZ_OK);
    list_begin(); add_timer(2); add_save(101);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100, 101));
    CHECK(d->confirm(d, 1) == GZ_OK);
    CHECK(RELEASED(100, 101, 1, 2));
    CHECK(!log_breaks_rule());
}

/* Storage is a journal: confirmations come in order, once each. Anything else
 * means storage can no longer be trusted, and the runner fails for good. */
static void test_confirmation_out_of_order_is_fatal(void)
{
    static const struct { uint64_t incarnation, sequence; gz_status_t want; } wrong[] = {
        {INCARNATION, 2, GZ_ERR_OUT_OF_ORDER},      /* the second before the first */
        {INCARNATION, 3, GZ_ERR_OUT_OF_ORDER},
        {INCARNATION, 4, GZ_ERR_UNKNOWN_BATCH},     /* never issued */
        {INCARNATION, 0, GZ_ERR_UNKNOWN_BATCH},
        {INCARNATION + 1, 1, GZ_ERR_UNKNOWN_BATCH}, /* an incarnation that does not exist yet */
    };
    driver_t *d = &g_driver;
    for (size_t k = 0; k < sizeof wrong / sizeof wrong[0]; k++) {
        driver_init(d, 0);
        list_begin(); add_save(100); add_save(101); add_save(102); add_send(1); add_watch(2);
        CHECK(d->submit(d, &l) == GZ_OK && !gz_runner_failed(&d->runner));
        CHECK(gz_runner_confirm(&d->runner, batch(wrong[k].incarnation, wrong[k].sequence)) == wrong[k].want);
        CHECK(gz_runner_failed(&d->runner));
        CHECK(d->confirm(d, 1) == GZ_ERR_FAILED);               /* even the right one is refused now */
        list_begin(); add_timer(9);
        CHECK(d->submit(d, &l) == GZ_ERR_FAILED);
        CHECK(RELEASED(100, 101, 102) && gz_runner_held(&d->runner) == 2);   /* the send and what is behind it never leave */
    }

    driver_init(d, 0);                                          /* a duplicate */
    list_begin(); add_save(100); add_save(101); add_send(1);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(d->confirm(d, 1) == GZ_OK);
    CHECK(d->confirm(d, 1) == GZ_ERR_UNKNOWN_BATCH && gz_runner_failed(&d->runner));
    CHECK(d->confirm(d, 2) == GZ_ERR_FAILED && RELEASED(100, 101));

    driver_init(d, 0);                                          /* before anything was issued */
    CHECK(d->confirm(d, 1) == GZ_ERR_UNKNOWN_BATCH && gz_runner_failed(&d->runner));

    driver_init(d, 0);                                          /* in order: nothing fails */
    list_begin(); add_save(100); add_save(101); add_save(102); add_send(1);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(d->confirm(d, 1) == GZ_OK && d->confirm(d, 2) == GZ_OK && RELEASED(100, 101, 102));
    CHECK(d->confirm(d, 3) == GZ_OK && RELEASED(100, 101, 102, 1) && !gz_runner_failed(&d->runner));
}

/* A crash: the program stops between the save and its confirmation. The
 * runner is thrown away with what it held, and a new one is built under the
 * next incarnation. The old batch's confirmation then arrives. */
static void test_crash_and_stale_confirmation(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_send(1); add_notify(2); add_broadcast(3);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(RELEASED(100));

    memset(&d->runner, 0xdd, sizeof d->runner);     /* the old runner is gone */
    memset(d->slots, 0xdd, sizeof d->slots);
    memset(d->bytes, 0xdd, sizeof d->bytes);
    CHECK(gz_runner_init(&d->runner, d->slots, 64, d->bytes, sizeof d->bytes, INCARNATION + 1, record_execute, d) == GZ_OK);
    CHECK(gz_runner_held(&d->runner) == 0 && gz_runner_unconfirmed(&d->runner) == 0);

    /* The new runner saves and holds a send of its own, under sequence 1 again. */
    list_begin(); add_save(200); add_send(9);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(gz_runner_confirm(&d->runner, batch(INCARNATION, 1)) == GZ_ERR_STALE_BATCH);
    CHECK(gz_runner_confirm(&d->runner, batch(0, 1)) == GZ_ERR_STALE_BATCH);
    CHECK(gz_runner_confirm(&d->runner, batch(INCARNATION, 99)) == GZ_ERR_STALE_BATCH);
    CHECK(!gz_runner_failed(&d->runner));           /* stale is ignored, not fatal */
    CHECK(released_count() == 2 && gz_runner_held(&d->runner) == 1);    /* and unlocked nothing */
    CHECK(gz_runner_confirm(&d->runner, batch(INCARNATION + 1, 1)) == GZ_OK);
    CHECK(released_count() == 3 && g_log[g_log_n - 1].id == 9 && !g_log[g_log_n - 1].is_offer);   /* 1, 2 and 3 never left */
}

/* What the incarnation duty is for, shown by breaking it. A program starts
 * twice under the same number. The confirmation of a batch the first start
 * saved arrives during the second, which holds a send behind a batch of its
 * own that is NOT stored. The runner cannot tell the two batches apart, and
 * the send leaves. The runner cannot detect this; only the program around it
 * can prevent it (runner.h). */
static void test_repeated_incarnation_is_not_detected(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_send(1);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(gz_runner_init(&d->runner, d->slots, 64, d->bytes, sizeof d->bytes, INCARNATION, record_execute, d) == GZ_OK);
    list_begin(); add_save(200); add_send(9);
    CHECK(d->submit(d, &l) == GZ_OK && gz_runner_held(&d->runner) == 1);
    CHECK(gz_runner_confirm(&d->runner, batch(INCARNATION, 1)) == GZ_OK);       /* the first start's batch */
    CHECK(gz_runner_held(&d->runner) == 0 && g_log[g_log_n - 1].id == 9);       /* released the second start's send */
}

static void test_refusal_is_whole_and_fatal(void)
{
    static gz_runner_slot_t slots[4];
    static uint8_t bytes[64];
    gz_runner_t r;

    /* Too many actions for the free slots. */
    log_reset();
    CHECK(gz_runner_init(&r, slots, 4, bytes, sizeof bytes, INCARNATION, record_execute, NULL) == GZ_OK);
    list_begin(); add_save(100); add_send(1); add_send(2);
    CHECK(gz_runner_submit(&r, &l) == GZ_OK);
    list_begin(); add_save(101); add_send(3); add_send(4); add_send(5);
    CHECK(gz_runner_submit(&r, &l) == GZ_ERR_REFUSED);
    CHECK(RELEASED(100));                           /* not even its save went out */
    CHECK(gz_runner_failed(&r) && gz_runner_held(&r) == 2);
    list_begin();
    CHECK(gz_runner_submit(&r, &l) == GZ_ERR_FAILED);
    CHECK(gz_runner_confirm(&r, batch(INCARNATION, 1)) == GZ_ERR_FAILED);
    CHECK(RELEASED(100));                           /* and what it held never leaves */

    /* Too many bytes. */
    log_reset();
    CHECK(gz_runner_init(&r, slots, 4, bytes, 20, INCARNATION, record_execute, NULL) == GZ_OK);
    list_begin(); add_save(100); add_send(1); add_send(2); add_send(3);
    CHECK(gz_runner_submit(&r, &l) == GZ_ERR_REFUSED);
    CHECK(g_log_n == 0 && gz_runner_failed(&r));

    /* Too many bytes once what is already held is counted: 16 of 20 are in
     * use, so 8 more do not fit although 8 alone would. */
    log_reset();
    CHECK(gz_runner_init(&r, slots, 4, bytes, 20, INCARNATION, record_execute, NULL) == GZ_OK);
    list_begin(); add_save(100); add_send(1); add_send(2);
    CHECK(gz_runner_submit(&r, &l) == GZ_OK && gz_runner_held(&r) == 2);
    list_begin(); add_send(3);
    CHECK(gz_runner_submit(&r, &l) == GZ_ERR_REFUSED);
    CHECK(RELEASED(100) && gz_runner_failed(&r) && gz_runner_held(&r) == 2);

    /* More unconfirmed batches than the bound. */
    log_reset();
    CHECK(gz_runner_init(&r, slots, 4, bytes, sizeof bytes, INCARNATION, record_execute, NULL) == GZ_OK);
    list_begin();
    for (uint64_t i = 0; i < GZ_RUNNER_MAX_UNCONFIRMED; i++) add_save(100 + i);
    CHECK(gz_runner_submit(&r, &l) == GZ_OK);       /* exactly the bound is fine */
    CHECK(gz_runner_unconfirmed(&r) == GZ_RUNNER_MAX_UNCONFIRMED);
    list_begin(); add_save(999);
    CHECK(gz_runner_submit(&r, &l) == GZ_ERR_REFUSED);
    CHECK(released_count() == GZ_RUNNER_MAX_UNCONFIRMED && gz_runner_failed(&r));

    log_reset();
    CHECK(gz_runner_init(&r, slots, 4, bytes, sizeof bytes, INCARNATION, record_execute, NULL) == GZ_OK);
    list_begin();
    for (uint64_t i = 0; i < GZ_RUNNER_MAX_UNCONFIRMED; i++) add_save(100 + i);
    CHECK(gz_runner_submit(&r, &l) == GZ_OK);
    CHECK(gz_runner_confirm(&r, batch(INCARNATION, 1)) == GZ_OK);
    list_begin(); add_save(999);
    CHECK(gz_runner_submit(&r, &l) == GZ_OK);       /* one was confirmed, so one more fits */
}

static void test_storage_failure_stops_everything(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_send(1); add_watch(2);
    CHECK(d->submit(d, &l) == GZ_OK);
    CHECK(!gz_runner_failed(&d->runner));
    CHECK(gz_runner_storage_failed(&d->runner) == GZ_OK);
    CHECK(gz_runner_failed(&d->runner));
    CHECK(d->confirm(d, 1) == GZ_ERR_FAILED);       /* even a confirmation releases nothing now */
    list_begin(); add_timer(3);
    CHECK(d->submit(d, &l) == GZ_ERR_FAILED);
    CHECK(RELEASED(100) && gz_runner_held(&d->runner) == 2);
}

/* The executor must not submit or confirm. If it does, it gets an error and
 * nothing changes. */
static gz_runner_t *g_reentry_runner;
static gz_status_t g_reentry_status[2];
static size_t g_held_inside[8], g_held_inside_n;

static void try_reentry(void)
{
    gz_action_t slot;
    gz_action_list_t inner;
    gz_action_list_init(&inner, &slot, 1, NULL, 0);
    gz_action_t timer = {.kind = GZ_ACTION_SET_TIMER};
    gz_action_list_add(&inner, &timer);
    g_reentry_status[0] = gz_runner_submit(g_reentry_runner, &inner);
    g_reentry_status[1] = gz_runner_confirm(g_reentry_runner, batch(INCARNATION, 1));
    if (g_held_inside_n < 8) g_held_inside[g_held_inside_n++] = gz_runner_held(g_reentry_runner);
}

static void test_reentry_is_refused(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    g_reentry_runner = &d->runner;
    g_held_inside_n = 0;
    g_inside_executor = try_reentry;

    list_begin(); add_save(100); add_send(1); add_send(2);
    CHECK(d->submit(d, &l) == GZ_OK);               /* the executor ran once, for the save */
    CHECK(g_reentry_status[0] == GZ_ERR_REENTRANT && g_reentry_status[1] == GZ_ERR_REENTRANT);
    CHECK(g_held_inside_n == 1 && g_held_inside[0] == 0);
    CHECK(!gz_runner_failed(&d->runner) && gz_runner_unconfirmed(&d->runner) == 1);

    memset(g_reentry_status, 0, sizeof g_reentry_status);
    CHECK(d->confirm(d, 1) == GZ_OK);               /* the executor runs for each send */
    CHECK(g_reentry_status[0] == GZ_ERR_REENTRANT && g_reentry_status[1] == GZ_ERR_REENTRANT);
    /* Seen from inside the executor, the action being carried out has already
     * left the queue: one held during the first send, none during the second. */
    CHECK(g_held_inside_n == 3 && g_held_inside[1] == 1 && g_held_inside[2] == 0);
    CHECK(RELEASED(100, 1, 2) && !gz_runner_failed(&d->runner));
    g_inside_executor = NULL;
    list_begin(); add_timer(3);
    CHECK(d->submit(d, &l) == GZ_OK);               /* and the runner still works afterwards */
}

/* A storage layer that writes synchronously learns of a failure inside the
 * executor, and reports it from there. Nothing more of the list, or of the
 * confirmation's releases, is handed over. */
static uint64_t g_fail_at_id;
static void fail_storage_at(void)
{
    if (g_log[g_log_n - 1].id == g_fail_at_id) (void)gz_runner_storage_failed(g_reentry_runner);
}

static void test_storage_failure_from_inside_the_executor(void)
{
    driver_t *d = &g_driver;

    driver_init(d, 0);                              /* while a list is being carried out */
    g_reentry_runner = &d->runner;
    g_inside_executor = fail_storage_at;
    g_fail_at_id = 101;
    list_begin(); add_watch(5); add_save(100); add_save(101); add_timer(6); add_save(102);
    CHECK(gz_runner_submit(&d->runner, &l) == GZ_ERR_FAILED);
    CHECK(RELEASED(5, 100, 101) && gz_runner_failed(&d->runner));   /* the timer and the third save never reach it */

    driver_init(d, 0);                              /* while a confirmation is releasing */
    g_reentry_runner = &d->runner;
    list_begin(); add_save(100); add_send(1); add_send(2); add_watch(3);
    CHECK(d->submit(d, &l) == GZ_OK);
    g_inside_executor = fail_storage_at;
    g_fail_at_id = 1;
    CHECK(gz_runner_confirm(&d->runner, batch(INCARNATION, 1)) == GZ_ERR_FAILED);
    CHECK(RELEASED(100, 1) && gz_runner_held(&d->runner) == 2);     /* the second send and the watch never leave */
    g_inside_executor = NULL;
    CHECK(gz_runner_confirm(&d->runner, batch(INCARNATION, 1)) == GZ_ERR_FAILED);
}

/* An executor that only counts, for lists whose payloads are not the usual
 * eight bytes. */
static size_t g_counted, g_counted_bytes;
static const uint8_t *g_last_data;
static void count_execute(void *ctx, const gz_action_t *a)
{
    (void)ctx;
    g_counted++;
    if (a->kind == GZ_ACTION_SEND) { g_counted_bytes += a->u.send.records.len; g_last_data = a->u.send.records.data; }
}

static gz_action_t plain_send(const uint8_t *data, size_t len)
{
    gz_action_t a = {.kind = GZ_ACTION_SEND};
    a.u.send.kind = 16;
    a.u.send.records = (gz_bytes_t){data, len};
    return a;
}

/* What can go straight to the executor needs no room in the queue. */
static void test_only_what_must_be_held_needs_room(void)
{
    static gz_runner_slot_t slots[64];
    static uint8_t bytes[100];
    static uint8_t payload[60];
    gz_runner_t r;

    g_counted = 0;                                  /* 65 timers through 64 slots, nothing held */
    CHECK(gz_runner_init(&r, slots, 64, bytes, sizeof bytes, INCARNATION, count_execute, NULL) == GZ_OK);
    list_begin();
    for (uint64_t i = 0; i < 65; i++) add_timer(i);
    CHECK(gz_runner_submit(&r, &l) == GZ_OK && g_counted == 65 && gz_runner_held(&r) == 0);

    g_counted = g_counted_bytes = 0;                /* two 60-byte sends through 100 bytes, nothing unconfirmed */
    CHECK(gz_runner_init(&r, slots, 64, bytes, sizeof bytes, INCARNATION, count_execute, NULL) == GZ_OK);
    gz_action_t big = plain_send(payload, sizeof payload);
    list_begin();
    CHECK(gz_action_list_add(&l, &big) == GZ_OK && gz_action_list_add(&l, &big) == GZ_OK);
    CHECK(gz_runner_submit(&r, &l) == GZ_OK && g_counted == 2 && g_counted_bytes == 120);

    g_counted = 0;                                  /* even a runner with no queue at all passes them through */
    CHECK(gz_runner_init(&r, NULL, 0, NULL, 0, INCARNATION, count_execute, NULL) == GZ_OK);
    CHECK(gz_runner_submit(&r, &l) == GZ_OK && g_counted == 2);
    list_begin(); add_save(1); add_send(2);         /* but this send would have to be held */
    CHECK(gz_runner_submit(&r, &l) == GZ_ERR_REFUSED && g_counted == 2);

    g_counted = 0;                                  /* behind a held send, every one of 64 timers needs a slot */
    CHECK(gz_runner_init(&r, slots, 64, bytes, sizeof bytes, INCARNATION, count_execute, NULL) == GZ_OK);
    list_begin(); add_save(1); add_send(2);
    for (uint64_t i = 0; i < 63; i++) add_timer(i);
    CHECK(gz_runner_submit(&r, &l) == GZ_OK && g_counted == 1 && gz_runner_held(&r) == 64);
    CHECK(gz_runner_init(&r, slots, 64, bytes, sizeof bytes, INCARNATION, count_execute, NULL) == GZ_OK);
    add_timer(99);
    CHECK(gz_runner_submit(&r, &l) == GZ_ERR_REFUSED && gz_runner_failed(&r));
}

/* The byte bound, to the byte: 16 of 24 held, so 8 more fit and 9 do not. */
static void test_byte_bound_is_exact(void)
{
    static gz_runner_slot_t slots[8];
    static uint8_t bytes[24];
    static const uint8_t nine[9] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    for (size_t extra = 8; extra <= 9; extra++) {
        gz_runner_t r;
        gz_action_t more = plain_send(nine, extra);
        g_counted = g_counted_bytes = 0;
        CHECK(gz_runner_init(&r, slots, 8, bytes, sizeof bytes, INCARNATION, count_execute, NULL) == GZ_OK);
        list_begin(); add_save(1); add_send(2); add_send(3);
        CHECK(gz_runner_submit(&r, &l) == GZ_OK && gz_runner_held(&r) == 2);
        list_begin();
        CHECK(gz_action_list_add(&l, &more) == GZ_OK);
        CHECK(gz_runner_submit(&r, &l) == (extra == 8 ? GZ_OK : GZ_ERR_REFUSED));
        if (extra == 8) {
            CHECK(gz_runner_confirm(&r, batch(INCARNATION, 1)) == GZ_OK);
            CHECK(g_counted == 4 && g_counted_bytes == 24);     /* all three sends arrived whole */
        }
    }
}

/* A held action with an empty payload does not keep the pointer it came with. */
static void test_empty_payload_is_not_a_pointer_into_the_list(void)
{
    static gz_runner_slot_t slots[4];
    static uint8_t bytes[16];
    static const uint8_t stray[4] = {9, 9, 9, 9};
    gz_action_t raw[2] = {{.kind = GZ_ACTION_SAVE}, plain_send(stray, 0)};      /* not built by gz_action_list_add */
    gz_action_list_t list = {raw, 2, 2, NULL, 0, 0};
    gz_runner_t r;
    g_counted = 0;
    g_last_data = stray;
    CHECK(gz_runner_init(&r, slots, 4, bytes, sizeof bytes, INCARNATION, count_execute, NULL) == GZ_OK);
    CHECK(gz_runner_submit(&r, &list) == GZ_OK && gz_runner_held(&r) == 1);
    CHECK(gz_runner_confirm(&r, batch(INCARNATION, 1)) == GZ_OK && g_counted == 2);
    CHECK(g_last_data == NULL);
}

static void test_unknown_kinds_are_refused(void)
{
    driver_t *d = &g_driver;
    gz_action_t raw[3] = {{.kind = GZ_ACTION_SAVE}, {.kind = (gz_action_kind_t)99}, {.kind = GZ_ACTION_SET_TIMER}};
    gz_action_list_t list = {raw, 3, 3, NULL, 0, 0};
    driver_init(d, 0);
    CHECK(gz_runner_submit(&d->runner, &list) == GZ_ERR_ARGUMENT);
    CHECK(g_log_n == 0 && !gz_runner_failed(&d->runner) && gz_runner_unconfirmed(&d->runner) == 0);
    raw[1].kind = (gz_action_kind_t)0;
    CHECK(gz_runner_submit(&d->runner, &list) == GZ_ERR_ARGUMENT && g_log_n == 0);
    raw[1].kind = GZ_ACTION_WATCH_SCRIPT;          /* retired in contract v2: refused like an unknown kind */
    CHECK(gz_runner_submit(&d->runner, &list) == GZ_ERR_ARGUMENT && g_log_n == 0);
    raw[1].kind = GZ_ACTION_CANCEL_TIMER;
    CHECK(gz_runner_submit(&d->runner, &list) == GZ_OK && g_log_n == 3);
}

/* A queue that never drains must still reuse the room released actions leave. */
static void test_queue_room_is_reused_without_draining(void)
{
    static gz_runner_slot_t slots[4];
    static uint8_t bytes[40];           /* room for five 8-byte payloads */
    gz_runner_t r;
    int ok = 1;
    log_reset();
    CHECK(gz_runner_init(&r, slots, 4, bytes, sizeof bytes, INCARNATION, record_execute, NULL) == GZ_OK);
    /* Identifiers whose every byte varies, so a payload moved one byte short would show. */
#define ROOM_ID(i) ((((uint64_t)(i) * 37 % 251 + 1) << 56) | (((uint64_t)(i) * 101 % 239 + 1) << 48) | (uint64_t)(i))
    list_begin(); add_save(1000); add_send(ROOM_ID(0));
    CHECK(submit_logged(&r, &l) == GZ_OK);
    for (uint64_t i = 1; i <= 5000; i++) {          /* always one send held when the next list arrives */
        list_begin(); add_save(1000 + i); add_send(ROOM_ID(i)); add_watch(ROOM_ID(i) ^ 0x5a5a5a5a00000000ull);
        ok &= submit_logged(&r, &l) == GZ_OK;
        ok &= gz_runner_held(&r) == (i == 1 ? 3 : 4);    /* every slot in use from the second round on */
        ok &= confirm_logged(&r, i) == GZ_OK;
        ok &= gz_runner_held(&r) == 2;              /* this round's send and watch wait for the next confirmation */
    }
    CHECK(ok && !gz_runner_failed(&r));
    CHECK(g_payloads_ok);                           /* payloads survived being moved */
    CHECK(released_count() == 5001 + 5000 + 4999); /* every save; sends 1..5000; watches up to the last but one */
    CHECK(!log_breaks_rule());
}

/* Steady load well below capacity, storage taking one or two ticks. A runner
 * that only reclaims its queue when it is completely empty refuses lists here
 * although it never holds more than a third of its slots. */
static uint64_t g_load_due[8], g_load_tick, g_load_last_due;
static size_t g_load_head, g_load_tail;
static uint32_t g_load_max_delay;

static void load_execute(void *ctx, const gz_action_t *a)
{
    (void)ctx;
    if (a->kind != GZ_ACTION_SAVE) return;
    uint64_t due = g_load_tick + 1 + next_random(g_load_max_delay);
    if (due < g_load_last_due) due = g_load_last_due;      /* a journal: in order */
    g_load_last_due = due;
    g_load_due[g_load_tail++ % 8] = due;
}

static void test_steady_load_is_never_refused(void)
{
    static gz_runner_slot_t slots[64];
    static uint8_t bytes[16384];
    gz_runner_t r;
    uint64_t offered = 0, refused = 0, confirmed = 0;
    size_t max_held = 0;
    g_lcg = 12345; g_load_head = g_load_tail = 0; g_load_last_due = 0; g_load_max_delay = 2;
    CHECK(gz_runner_init(&r, slots, 64, bytes, sizeof bytes, INCARNATION, load_execute, NULL) == GZ_OK);
    for (g_load_tick = 1; g_load_tick <= 400000 && !refused; g_load_tick++) {
        while (g_load_head < g_load_tail && g_load_due[g_load_head % 8] <= g_load_tick) {
            g_load_head++;
            if (gz_runner_confirm(&r, batch(INCARNATION, ++confirmed)) != GZ_OK) refused++;
        }
        if (gz_runner_held(&r) > max_held) max_held = gz_runner_held(&r);
        if (next_random(1000) >= 500) continue;     /* a new list on half the ticks */
        list_begin(); add_save(1); add_send(2);
        offered++;
        if (gz_runner_submit(&r, &l) != GZ_OK) refused++;
    }
    CHECK(offered > 190000);
    CHECK(refused == 0);
    CHECK(max_held > 0 && max_held < 32);
}

static void test_submitted_list_may_be_reused_at_once(void)
{
    driver_t *d = &g_driver;
    driver_init(d, 0);
    list_begin(); add_save(100); add_send(1); add_broadcast(2); add_notify(3); add_watch(4);
    CHECK(d->submit(d, &l) == GZ_OK);
    memset(l_bytes, 0xee, sizeof l_bytes);          /* the runner must hold its own copies */
    memset(l_slots, 0xee, sizeof l_slots);
    CHECK(d->confirm(d, 1) == GZ_OK);
    CHECK(RELEASED(100, 1, 2, 3, 4));               /* RELEASED also checks the payload bytes */
}

static void test_random_schedules_match_the_model(void)
{
    driver_t *d = &g_driver;
    size_t outward = 0, refused = 0;
    for (uint64_t seed = 1; seed <= 300; seed++) {
        for (int confirm_all = 0; confirm_all <= 1; confirm_all++) {
            driver_init(d, 0);
            size_t r = scenario_random(d, seed, confirm_all);
            refused += r;
            CHECK(r < 1000);                        /* no in-order confirmation was ever rejected */
            CHECK(!log_breaks_rule());
            CHECK(log_matches_model());             /* exactly the permitted actions, in the permitted order */
            CHECK(g_payloads_ok && g_incarnations_ok);
            if (confirm_all && r == 0) CHECK(gz_runner_held(&d->runner) == 0 && gz_runner_unconfirmed(&d->runner) == 0);
        }
        for (size_t i = 0; i < g_log_n; i++)
            outward += !g_log[i].is_confirm && !g_log[i].is_offer && is_outward_kind(g_log[i].kind);
    }
    CHECK(outward > 10000);                         /* the schedules really did send things */
    CHECK(refused < 300);                           /* and most ran to the end */
}

/* ---- the judges must catch a runner that breaks the rule ---- */

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

    int eager_caught = 0, eager_off_model = 0, sloppy_caught = 0, sloppy_off_model = 0;
    for (uint64_t seed = 1; seed <= 50; seed++) {
        driver_init(d, 1); scenario_random(d, seed, 0);
        eager_caught += log_breaks_rule(); eager_off_model += !log_matches_model();
        driver_init(d, 2); scenario_random(d, seed, 0);
        sloppy_caught += log_breaks_rule(); sloppy_off_model += !log_matches_model();
    }
    CHECK(eager_caught == 50 && eager_off_model == 50);
    CHECK(sloppy_caught == 50 && sloppy_off_model == 50);
}

/* Compaction exactly at the edge of the byte block. In a 23-byte block, an
 * 8-byte and a 2-byte payload are held; the first is released, freeing 8
 * bytes at the front and leaving 13 free at the back; a 14-byte payload
 * arrives. Unless the held payload is moved down first, the new one runs one
 * byte past the block. The block is an allocation of its own, so the memory
 * checkers see an overrun, and in the second round it is followed by a guard
 * byte that a build without them checks. */
static uint8_t g_edge_seen[3][16];
static size_t g_edge_len[3], g_edge_n;
static void edge_execute(void *ctx, const gz_action_t *a)
{
    (void)ctx;
    const gz_bytes_t *b = a->kind == GZ_ACTION_SEND ? &a->u.send.records : NULL;
    if (!b || g_edge_n >= 3) return;
    memcpy(g_edge_seen[g_edge_n], b->data, b->len);
    g_edge_len[g_edge_n++] = b->len;
}

static void test_compaction_at_the_edge_of_the_block(void)
{
    enum { BLOCK = 23 };
    static gz_runner_slot_t slots[4];
    static const uint8_t eight[8] = {8, 8, 8, 8, 8, 8, 8, 8}, two[2] = {2, 2};
    static const uint8_t fourteen[14] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    for (int guarded = 0; guarded <= 1; guarded++) {
        uint8_t *block = malloc(BLOCK + (size_t)guarded);
        gz_runner_t r;
        if (!block) { CHECK(0); return; }
        if (guarded) block[BLOCK] = 0xa5;
        g_edge_n = 0;
        CHECK(gz_runner_init(&r, slots, 4, block, BLOCK, INCARNATION, edge_execute, NULL) == GZ_OK);
        gz_action_t first = plain_send(eight, 8), second = plain_send(two, 2), watch = plain_send(fourteen, sizeof fourteen);
        list_begin(); add_save(100);
        CHECK(gz_action_list_add(&l, &first) == GZ_OK);
        add_save(101);
        CHECK(gz_action_list_add(&l, &second) == GZ_OK);
        CHECK(gz_runner_submit(&r, &l) == GZ_OK && gz_runner_held(&r) == 2);
        CHECK(gz_runner_confirm(&r, batch(INCARNATION, 1)) == GZ_OK && gz_runner_held(&r) == 1);
        list_begin();
        CHECK(gz_action_list_add(&l, &watch) == GZ_OK);
        CHECK(gz_runner_submit(&r, &l) == GZ_OK && gz_runner_held(&r) == 2);
        if (guarded) CHECK(block[BLOCK] == 0xa5);
        CHECK(gz_runner_confirm(&r, batch(INCARNATION, 2)) == GZ_OK && gz_runner_held(&r) == 0);
        CHECK(g_edge_n == 3 && g_edge_len[0] == 8 && g_edge_len[1] == 2 && g_edge_len[2] == 14);
        CHECK(memcmp(g_edge_seen[1], two, 2) == 0 && memcmp(g_edge_seen[2], fourteen, 14) == 0);
        free(block);
    }
}

/* A failed runner answers every submit with GZ_ERR_FAILED, even a list it
 * could not have taken anyway. */
static void test_a_failed_runner_refuses_everything_the_same_way(void)
{
    static gz_runner_slot_t slots[1];
    gz_runner_t r;
    log_reset();
    CHECK(gz_runner_init(&r, slots, 1, NULL, 0, INCARNATION, record_execute, NULL) == GZ_OK);
    CHECK(gz_runner_storage_failed(&r) == GZ_OK);
    list_begin(); add_save(1); add_send(2); add_send(3);            /* would not fit */
    CHECK(gz_runner_submit(&r, &l) == GZ_ERR_FAILED && g_log_n == 0);
    list_begin();
    CHECK(gz_runner_submit(&r, &l) == GZ_ERR_FAILED);
}

int main(void)
{
    test_arguments();
    test_empty_list();
    test_no_save_means_no_waiting();
    test_send_waits_for_its_save();
    test_broadcast_and_notify_wait_too();
    test_saves_never_wait();
    test_send_waits_for_every_earlier_save();
    test_empty_batch_is_a_batch();
    test_order_is_kept_behind_a_waiting_action();
    test_timer_placed_after_its_send_waits_with_it();
    test_the_rule_spans_lists();
    test_confirmation_out_of_order_is_fatal();
    test_crash_and_stale_confirmation();
    test_repeated_incarnation_is_not_detected();
    test_refusal_is_whole_and_fatal();
    test_storage_failure_stops_everything();
    test_reentry_is_refused();
    test_storage_failure_from_inside_the_executor();
    test_only_what_must_be_held_needs_room();
    test_byte_bound_is_exact();
    test_empty_payload_is_not_a_pointer_into_the_list();
    test_unknown_kinds_are_refused();
    test_compaction_at_the_edge_of_the_block();
    test_a_failed_runner_refuses_everything_the_same_way();
    test_queue_room_is_reused_without_draining();
    test_steady_load_is_never_refused();
    test_submitted_list_may_be_reused_at_once();
    test_random_schedules_match_the_model();
    test_wrong_runners_are_caught();
    return check_done();
}
