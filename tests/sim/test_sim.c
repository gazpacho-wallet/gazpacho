/* Tests for the simulator skeleton (sim/sim.c): determinism, each network
 * fault, crash and rebuild, the pretend chain and timers, and the two
 * invariants, each shown to catch a deliberately faulty node defined here. */
#include "sim.h"
#include "gazpacho/node.h"
#include "../check.h"
#include <stdlib.h>
#include <string.h>

static sim_config_t quiet_config(uint64_t seed, uint32_t n_nodes)
{
    sim_config_t c;
    memset(&c, 0, sizeof c);
    c.seed = seed;
    c.n_nodes = n_nodes;
    c.confirm_depth = 3;
    return c;
}

/* A configuration with every kind of fault switched on. */
static sim_config_t busy_config(uint64_t seed)
{
    sim_config_t c = quiet_config(seed, 4);
    c.drop_pm = 100; c.duplicate_pm = 100; c.delay_pm = 200; c.max_delay_steps = 6; c.reorder_pm = 200;
    c.save_delay_pm = 400; c.max_save_delay_steps = 4; c.save_never_pm = 5;
    c.crash_pm = 20; c.ping_pm = 400; c.block_pm = 50;
    return c;
}

static void world_ping(sim_t *sim, uint64_t to, uint8_t tag)
{
    const uint8_t ping[5] = {'G', 'Z', 'P', 'I', tag};
    sim_send_message(sim, SIM_WORLD_PEER, to, ping, sizeof ping);
}

static int trace_has(const sim_t *sim, const char *text)
{
    return strstr(sim_trace(sim, NULL), text) != NULL;
}

/* ---- the plain path ---- */

static void test_ping_is_stored_then_answered(void)
{
    sim_config_t c = quiet_config(1, 2);
    sim_t *sim = sim_create(&c);
    world_ping(sim, 0, 0x5a);
    CHECK(sim_run(sim, 1) == 1);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    CHECK(sim_storage_count(st) == 1 && sim_storage_batch_id(st, 0) == 1 && sim_storage_has(st, 1));
    CHECK(sim_stats(sim)->world_replies == 0);          /* the reply is still in flight */
    CHECK(sim_run(sim, 1) == 1);
    CHECK(sim_stats(sim)->world_replies == 1);

    size_t len = 0;
    const uint8_t *b = sim_storage_batch_bytes(st, 0, &len);
    const uint8_t want[17] = {0x01, 0x00, 0x57, 0x7e,  9, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 1,  0x5a};
    CHECK(len == sizeof want && memcmp(b, want, len) == 0);   /* type, length, clock stamp = step 1, payload */
    CHECK(sim_storage_count(sim_node_storage(sim, 1)) == 0);
    CHECK(!sim_failed(sim) && sim_step_count(sim) == 2);
    sim_destroy(sim);
    CHECK(sim_create(NULL) == NULL);
    c.n_nodes = 0;
    CHECK(sim_create(&c) == NULL);
}

/* ---- determinism ---- */

static void test_same_seed_same_trace(void)
{
    sim_config_t c = busy_config(2024);
    sim_t *a = sim_create(&c), *b = sim_create(&c);
    size_t la = 0, lb = 0;
    CHECK(sim_run(a, 2000) == 2000 && sim_run(b, 2000) == 2000);
    const char *ta = sim_trace(a, &la), *tb = sim_trace(b, &lb);
    CHECK(la > 10000);                                  /* a run with real content */
    CHECK(la == lb && memcmp(ta, tb, la) == 0);         /* byte for byte */
    CHECK(sim_trace_hash(a) == sim_trace_hash(b));
    CHECK(memcmp(sim_stats(a), sim_stats(b), sizeof(sim_stats_t)) == 0);
    const sim_stats_t *s = sim_stats(a);
    CHECK(s->messages_dropped && s->messages_duplicated && s->messages_delayed && s->deliveries_reordered);
    CHECK(s->crashes && s->saves_lost && s->blocks && s->world_replies && s->saves_durable);

    c.seed = 2025;
    sim_t *d = sim_create(&c);
    CHECK(sim_run(d, 2000) == 2000);
    CHECK(sim_trace_hash(d) != sim_trace_hash(a));      /* a different seed is a different run */
    sim_destroy(a); sim_destroy(b); sim_destroy(d);
}

static void test_same_seed_invariant_holds(void)
{
    sim_config_t c = busy_config(77);
    c.check_same_seed = 1;
    sim_t *sim = sim_create(&c);
    CHECK(sim_run(sim, 1500) == 1500);
    world_ping(sim, 1, 1);                              /* hand-driven occurrences are mirrored too */
    sim_crash_node(sim, 2);
    sim_mine_block(sim);
    CHECK(sim_run(sim, 100) == 100 && !sim_failed(sim));
    sim_destroy(sim);
}

/* FAULTY ON PURPOSE: a node whose behaviour depends on something outside the
 * seed (a counter shared by every node in the process). */
static uint32_t g_outside_counter;
static void *leaky_create(void *ctx, uint32_t index, const gz_ports_t *ports, const sim_storage_t *storage)
{
    (void)ctx; (void)index; (void)ports; (void)storage;
    return malloc(1);
}
static void leaky_destroy(void *ctx, void *node) { (void)ctx; free(node); }
static gz_status_t leaky_handle(void *node, const gz_event_t *ev, gz_action_list_t *out)
{
    (void)node;
    if (ev->kind != GZ_EVENT_MESSAGE_RECEIVED) return GZ_OK;
    gz_action_t a = {.kind = GZ_ACTION_NOTIFY};
    a.u.notify.code = g_outside_counter++;
    return gz_action_list_add(out, &a);
}

static void test_same_seed_invariant_catches_a_leak(void)
{
    sim_config_t c = quiet_config(5, 2);
    c.check_same_seed = 1;
    c.ops = (sim_node_ops_t){leaky_create, leaky_destroy, leaky_handle, NULL, NULL};
    sim_t *sim = sim_create(&c);
    world_ping(sim, 0, 1);
    CHECK(sim_run(sim, 10) == 0);                       /* fails at the first step */
    CHECK(sim_failed(sim) && sim_failure_step(sim) == 1);
    CHECK(strstr(sim_failure_reason(sim), "same seed") != NULL);
    CHECK(sim_step(sim) == 0 && sim_step_count(sim) == 1);   /* a failed run does nothing further */
    sim_destroy(sim);
}

/* ---- network faults, one at a time ---- */

static void test_drop(void)
{
    sim_config_t c = quiet_config(3, 2);
    c.drop_pm = 1000;
    sim_t *sim = sim_create(&c);
    for (uint8_t i = 0; i < 5; i++) world_ping(sim, 0, i);
    CHECK(sim_run(sim, 30) == 30);
    const sim_stats_t *s = sim_stats(sim);
    CHECK(s->messages_sent == 5 && s->messages_dropped == 5 && s->messages_delivered == 0);
    CHECK(sim_storage_count(sim_node_storage(sim, 0)) == 0);
    sim_destroy(sim);
}

static void test_duplicate(void)
{
    sim_config_t c = quiet_config(3, 2);
    c.duplicate_pm = 1000;
    sim_t *sim = sim_create(&c);
    world_ping(sim, 0, 9);
    CHECK(sim_run(sim, 30) == 30);
    const sim_stats_t *s = sim_stats(sim);
    CHECK(s->messages_sent == 3 && s->messages_duplicated == 3);    /* the ping and its two replies */
    CHECK(sim_storage_count(sim_node_storage(sim, 0)) == 2);        /* the node saw the ping twice */
    CHECK(s->world_replies == 4 && s->messages_delivered == 6);
    sim_destroy(sim);
}

static void test_delay(void)
{
    sim_config_t c = quiet_config(3, 2);
    sim_t *prompt = sim_create(&c);
    world_ping(prompt, 0, 9);
    CHECK(sim_run(prompt, 1) == 1 && sim_stats(prompt)->messages_delivered == 1);
    sim_destroy(prompt);

    c.delay_pm = 1000; c.max_delay_steps = 5;
    sim_t *sim = sim_create(&c);
    world_ping(sim, 0, 9);
    CHECK(sim_run(sim, 1) == 1);
    CHECK(sim_stats(sim)->messages_delivered == 0 && sim_stats(sim)->messages_delayed == 1);
    CHECK(sim_run(sim, 5) == 5);                        /* at most 1 + 5 steps after sending */
    CHECK(sim_stats(sim)->messages_delivered == 1);
    sim_destroy(sim);
}

static void test_reorder(void)
{
    sim_config_t c = quiet_config(3, 2);
    sim_t *fifo = sim_create(&c);
    for (uint8_t i = 0; i < 4; i++) world_ping(fifo, 0, i);
    CHECK(sim_run(fifo, 1) == 1);
    CHECK(trace_has(fifo, "1 deliver seq=0 ") && sim_stats(fifo)->deliveries_reordered == 0);
    sim_destroy(fifo);

    c.reorder_pm = 1000;
    sim_t *sim = sim_create(&c);
    for (uint8_t i = 0; i < 4; i++) world_ping(sim, 0, i);
    CHECK(sim_run(sim, 1) == 1);
    CHECK(!trace_has(sim, "1 deliver seq=0 ") && trace_has(sim, "1 deliver seq="));
    CHECK(sim_stats(sim)->deliveries_reordered == 1);
    CHECK(sim_run(sim, 30) == 30);
    CHECK(sim_storage_count(sim_node_storage(sim, 0)) == 4);        /* all four still arrive */
    sim_destroy(sim);
}

/* ---- crash and rebuild ---- */

static void test_crash_between_save_and_confirmation(void)
{
    sim_config_t c = quiet_config(8, 2);
    c.save_delay_pm = 1000; c.max_save_delay_steps = 5;
    sim_t *sim = sim_create(&c);
    world_ping(sim, 0, 1);
    CHECK(sim_run(sim, 1) == 1);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    CHECK(sim_storage_pending(st) == 1 && sim_storage_count(st) == 0);   /* saved, not yet stored */
    sim_crash_node(sim, 0);
    CHECK(sim_stats(sim)->crashes == 1 && sim_stats(sim)->saves_lost == 1);
    CHECK(trace_has(sim, "crash node=0 lost-saves=1 held-actions=1"));
    CHECK(sim_run(sim, 40) == 40);
    CHECK(sim_storage_count(st) == 0 && sim_storage_pending(st) == 0);
    CHECK(sim_stats(sim)->world_replies == 0 && sim_stats(sim)->messages_sent == 1);  /* the reply never left */

    world_ping(sim, 0, 2);                              /* the rebuilt node works */
    CHECK(sim_run(sim, 40) == 40);
    CHECK(sim_storage_count(st) == 1 && sim_storage_batch_id(st, 0) == 1);
    CHECK(sim_stats(sim)->world_replies == 1 && !sim_failed(sim));
    sim_destroy(sim);
}

static void test_storage_survives_a_crash(void)
{
    sim_config_t c = quiet_config(8, 2);
    sim_t *sim = sim_create(&c);
    world_ping(sim, 0, 1);
    world_ping(sim, 0, 2);
    CHECK(sim_run(sim, 10) == 10);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    CHECK(sim_storage_count(st) == 2);
    world_ping(sim, 0, 3);                              /* in flight across the crash */
    sim_crash_node(sim, 0);
    CHECK(sim_storage_count(st) == 2 && sim_storage_has(st, 1) && sim_storage_has(st, 2));
    CHECK(sim_run(sim, 10) == 10);
    CHECK(sim_storage_count(st) == 3 && sim_storage_batch_id(st, 2) == 3);   /* numbering continues */
    CHECK(sim_stats(sim)->world_replies == 3);
    sim_crash_node(sim, 7);                             /* no such node: ignored */
    CHECK(sim_stats(sim)->crashes == 1);
    sim_destroy(sim);
}

static void test_storage_that_never_completes(void)
{
    sim_config_t c = quiet_config(8, 1);
    c.save_never_pm = 1000;
    sim_t *sim = sim_create(&c);
    for (int i = 0; i < 100; i++) { world_ping(sim, 0, (uint8_t)i); sim_step(sim); }
    CHECK(sim_run(sim, 200) == 200 && !sim_failed(sim));
    CHECK(sim_stats(sim)->world_replies == 0 && sim_stats(sim)->saves_durable == 0);
    CHECK(sim_stats(sim)->lists_refused > 0);           /* the runner filled up and said so */
    CHECK(trace_has(sim, "due=never"));
    sim_destroy(sim);
}

/* ---- "nothing is sent before it is saved" ---- */

/* FAULTY ON PURPOSE: a program that carries out every action at once instead
 * of going through the runner. */
static gz_status_t eager_release(void *ctx, sim_t *sim, uint32_t index, const gz_action_list_t *list)
{
    (void)ctx;
    for (size_t i = 0; i < list->count; i++) sim_execute(sim, index, &list->slots[i]);
    return GZ_OK;
}

/* FAULTY ON PURPOSE: a program that carries out actions last first. */
static gz_status_t backwards_release(void *ctx, sim_t *sim, uint32_t index, const gz_action_list_t *list)
{
    (void)ctx;
    for (size_t i = list->count; i-- > 0;) sim_execute(sim, index, &list->slots[i]);
    return GZ_OK;
}

static void test_save_before_send_catches_a_faulty_node(void)
{
    for (int delayed = 0; delayed <= 1; delayed++) {
        sim_config_t c = quiet_config(11, 3);
        c.save_delay_pm = delayed ? 1000 : 0;           /* even with instant storage it is a violation */
        c.max_save_delay_steps = 3;

        sim_t *good = sim_create(&c);                   /* the same run with the real runner passes */
        world_ping(good, 1, 4);
        CHECK(sim_run(good, 20) == 20 && !sim_failed(good) && sim_stats(good)->world_replies == 1);
        sim_destroy(good);

        c.ops.release = eager_release;
        sim_t *bad = sim_create(&c);
        world_ping(bad, 1, 4);
        CHECK(sim_run(bad, 20) == 0);
        CHECK(sim_failed(bad) && sim_failure_step(bad) == 1);
        CHECK(strstr(sim_failure_reason(bad), "nothing is sent before it is saved") != NULL);
        CHECK(trace_has(bad, "FAILED"));

        sim_t *replay = sim_create(&c);                 /* replay from (seed, step) */
        world_ping(replay, 1, 4);
        sim_run(replay, sim_failure_step(bad));
        size_t la = 0, lb = 0;
        const char *ta = sim_trace(bad, &la), *tb = sim_trace(replay, &lb);
        CHECK(sim_failed(replay) && la == lb && memcmp(ta, tb, la) == 0);
        sim_destroy(bad); sim_destroy(replay);
    }

    sim_config_t c = quiet_config(11, 3);
    c.ops.release = backwards_release;
    sim_t *bad = sim_create(&c);
    world_ping(bad, 1, 4);
    CHECK(sim_run(bad, 20) == 0 && sim_failed(bad));
    sim_destroy(bad);
}

static void test_faulty_node_is_caught_under_load(void)
{
    int caught = 0;
    for (uint64_t seed = 1; seed <= 50; seed++) {
        sim_config_t c = busy_config(seed);
        c.ops.release = eager_release;
        sim_t *bad = sim_create(&c);
        sim_run(bad, 400);
        caught += sim_failed(bad);
        sim_destroy(bad);
    }
    CHECK(caught == 50);
}

/* ---- pretend chain, timers and the invariant hook, seen by a probe node ---- */

typedef struct {
    uint32_t tips, last_tip, spent, confirmed, last_confirmations, timers, stored, messages;
    uint8_t spent_txid[32], confirmed_txid[32];
} probe_t;
static probe_t g_probe[4];

static void *probe_create(void *ctx, uint32_t index, const gz_ports_t *ports, const sim_storage_t *storage)
{
    (void)ctx; (void)ports; (void)storage;
    return &g_probe[index];
}
static void probe_destroy(void *ctx, void *node) { (void)ctx; (void)node; }

/* User commands: 'B' tx.. broadcast; 'W' script.. watch; 'T' id delay: set a
 * timer; 'C' id: cancel it; 'N' code: notify; 'S' id: save batch id then notify. */
static gz_status_t probe_command(gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_action_t a = {0};
    gz_bytes_t rest = {cmd.data + 1, cmd.len - 1};
    switch (cmd.data[0]) {
    case 'B': a.kind = GZ_ACTION_BROADCAST; a.u.broadcast.tx = rest; break;
    case 'W': a.kind = GZ_ACTION_WATCH; a.u.watch.script = rest; break;
    case 'T': a.kind = GZ_ACTION_SET_TIMER; a.u.set_timer.timer_id = cmd.data[1]; a.u.set_timer.delay_ms = cmd.data[2]; break;
    case 'C': a.kind = GZ_ACTION_CANCEL_TIMER; a.u.cancel_timer.timer_id = cmd.data[1]; break;
    case 'N': a.kind = GZ_ACTION_NOTIFY; a.u.notify.code = cmd.data[1]; break;
    case 'S': {
        gz_record_t r = {7, rest};
        a.kind = GZ_ACTION_SAVE; a.u.save.batch_id = cmd.data[1]; a.u.save.records = &r; a.u.save.n_records = 1;
        gz_status_t st = gz_action_list_add(out, &a);
        if (st != GZ_OK) return st;
        a = (gz_action_t){.kind = GZ_ACTION_NOTIFY};
        a.u.notify.code = cmd.data[1];
        break;
    }
    default: return GZ_ERR_ARGUMENT;
    }
    return gz_action_list_add(out, &a);
}

static gz_status_t probe_handle(void *node, const gz_event_t *ev, gz_action_list_t *out)
{
    probe_t *p = node;
    switch (ev->kind) {
    case GZ_EVENT_USER_COMMAND:      return probe_command(ev->u.user.bytes, out);
    case GZ_EVENT_TIMER_FIRED:       p->timers++; break;
    case GZ_EVENT_STORAGE_CONFIRMED: p->stored++; break;
    case GZ_EVENT_MESSAGE_RECEIVED:  p->messages++; break;
    case GZ_EVENT_CHAIN:
        if (ev->u.chain.kind == GZ_CHAIN_NEW_TIP) { p->tips++; p->last_tip = ev->u.chain.height; }
        if (ev->u.chain.kind == GZ_CHAIN_SCRIPT_SPENT) { p->spent++; memcpy(p->spent_txid, ev->u.chain.txid, 32); }
        if (ev->u.chain.kind == GZ_CHAIN_TX_CONFIRMED) {
            p->confirmed++; p->last_confirmations = ev->u.chain.confirmations;
            memcpy(p->confirmed_txid, ev->u.chain.txid, 32);
        }
        break;
    }
    return GZ_OK;
}

static sim_t *probe_sim(uint32_t n_nodes)
{
    sim_config_t c = quiet_config(21, n_nodes);
    c.ops = (sim_node_ops_t){probe_create, probe_destroy, probe_handle, NULL, NULL};
    memset(g_probe, 0, sizeof g_probe);
    return sim_create(&c);
}

static void test_chain_events(void)
{
    sim_t *sim = probe_sim(3);
    const uint8_t watch[4] = {'W', 0xaa, 0xbb, 0xcc};
    const uint8_t spend[7] = {'B', 3, 0xaa, 0xbb, 0xcc, 1, 2};      /* a tx spending script aa bb cc */
    const uint8_t other[4] = {'B', 0, 5, 5};                        /* a tx spending nothing watched */
    sim_user_command(sim, 0, watch, sizeof watch);
    sim_user_command(sim, 1, spend, sizeof spend);
    sim_user_command(sim, 1, spend, sizeof spend);                  /* broadcasting twice is one tx */
    sim_user_command(sim, 2, other, sizeof other);
    CHECK(trace_has(sim, "already-known"));
    CHECK(g_probe[0].spent == 0 && sim_chain_height(sim) == 0);

    sim_mine_block(sim);
    CHECK(sim_chain_height(sim) == 1 && sim_stats(sim)->blocks == 1);
    for (int n = 0; n < 3; n++) CHECK(g_probe[n].tips == 1 && g_probe[n].last_tip == 1);
    CHECK(g_probe[0].spent == 1 && g_probe[1].spent == 0 && g_probe[2].spent == 0);
    CHECK(g_probe[1].confirmed == 1 && g_probe[1].last_confirmations == 1);
    CHECK(g_probe[2].confirmed == 1 && g_probe[0].confirmed == 0);
    CHECK(memcmp(g_probe[0].spent_txid, g_probe[1].confirmed_txid, 32) == 0);   /* the same transaction */
    CHECK(memcmp(g_probe[1].confirmed_txid, g_probe[2].confirmed_txid, 32) != 0);

    sim_mine_block(sim); sim_mine_block(sim); sim_mine_block(sim); sim_mine_block(sim);
    CHECK(g_probe[1].confirmed == 3 && g_probe[1].last_confirmations == 3);     /* reported to confirm_depth */
    CHECK(g_probe[0].spent == 1 && g_probe[0].tips == 5 && g_probe[0].last_tip == 5);
    CHECK(!sim_failed(sim));
    sim_destroy(sim);

    sim_config_t c = quiet_config(4, 2);                /* blocks also come from the schedule */
    c.block_pm = 1000;
    sim = sim_create(&c);
    CHECK(sim_run(sim, 7) == 7 && sim_chain_height(sim) == 7);
    sim_destroy(sim);
}

static void test_timers(void)
{
    sim_t *sim = probe_sim(2);
    const uint8_t set_a[3] = {'T', 1, 3}, set_b[3] = {'T', 2, 5}, reset_b[3] = {'T', 2, 8}, cancel_a[2] = {'C', 1};
    sim_user_command(sim, 0, set_a, 3);
    sim_user_command(sim, 0, set_b, 3);
    CHECK(sim_run(sim, 2) == 2 && g_probe[0].timers == 0);
    CHECK(sim_run(sim, 1) == 1 && g_probe[0].timers == 1);          /* timer 1 fires at step 3 */
    sim_user_command(sim, 0, reset_b, 3);                           /* setting again replaces: now due at 11 */
    sim_user_command(sim, 0, set_a, 3);
    sim_user_command(sim, 0, cancel_a, 2);
    CHECK(sim_run(sim, 7) == 7 && g_probe[0].timers == 1);
    CHECK(sim_run(sim, 1) == 1 && g_probe[0].timers == 2);
    CHECK(sim_run(sim, 20) == 20 && g_probe[0].timers == 2 && g_probe[1].timers == 0);

    sim_user_command(sim, 0, set_a, 3);                             /* a crash forgets timers */
    sim_crash_node(sim, 0);
    CHECK(sim_run(sim, 10) == 10 && g_probe[0].timers == 2);
    sim_destroy(sim);
}

static void test_probe_save_notify_and_errors(void)
{
    sim_t *sim = probe_sim(2);
    const uint8_t save[3] = {'S', 9, 1}, bad[1] = {'?'}, note[2] = {'N', 4};
    const uint8_t hello[2] = {1, 2};
    sim_user_command(sim, 0, save, 3);
    CHECK(g_probe[0].stored == 1 && sim_storage_has(sim_node_storage(sim, 0), 9));
    CHECK(trace_has(sim, "notify node=0 code=9"));
    sim_user_command(sim, 0, save, 3);                              /* same batch again: stored twice here, */
    CHECK(sim_storage_count(sim_node_storage(sim, 0)) == 2);        /* the confirmed batch number is free */
    sim_user_command(sim, 1, bad, 1);
    CHECK(sim_stats(sim)->handle_errors == 1);
    sim_user_command(sim, 1, note, 2);
    CHECK(trace_has(sim, "notify node=1 code=4"));
    sim_send_message(sim, 0, 1, hello, 2);
    sim_send_message(sim, 0, 5, hello, 2);                          /* no such peer: delivered nowhere */
    CHECK(sim_run(sim, 5) == 5 && g_probe[1].messages == 1 && sim_stats(sim)->messages_delivered == 1);
    CHECK(!sim_failed(sim));
    sim_destroy(sim);
}

static int fails_at_five(const sim_t *sim, void *ctx, const char **why)
{
    (*(int *)ctx)++;
    if (sim_step_count(sim) < 5) return 1;
    *why = "test invariant";
    return 0;
}

static void test_invariant_hook(void)
{
    sim_config_t c = quiet_config(1, 2);
    sim_t *sim = sim_create(&c);
    int calls = 0;
    CHECK(sim_add_invariant(sim, fails_at_five, &calls) == 1);
    CHECK(sim_add_invariant(sim, NULL, NULL) == 0);
    CHECK(sim_run(sim, 100) == 4);
    CHECK(calls == 5 && sim_failed(sim) && sim_failure_step(sim) == 5);
    CHECK(strcmp(sim_failure_reason(sim), "test invariant") == 0);
    sim_crash_node(sim, 0); sim_mine_block(sim); world_ping(sim, 0, 1);      /* ignored after a failure */
    CHECK(sim_stats(sim)->crashes == 0 && sim_chain_height(sim) == 0 && sim_stats(sim)->messages_sent == 0);
    sim_destroy(sim);

    sim = sim_create(&c);
    for (int i = 0; i < 8; i++) CHECK(sim_add_invariant(sim, fails_at_five, &calls) == 1);
    CHECK(sim_add_invariant(sim, fails_at_five, &calls) == 0);      /* at most 8 */
    CHECK(strcmp(sim_failure_reason(sim), "") == 0);
    sim_destroy(sim);
    sim_destroy(NULL);
}

int main(void)
{
    test_ping_is_stored_then_answered();
    test_same_seed_same_trace();
    test_same_seed_invariant_holds();
    test_same_seed_invariant_catches_a_leak();
    test_drop();
    test_duplicate();
    test_delay();
    test_reorder();
    test_crash_between_save_and_confirmation();
    test_storage_survives_a_crash();
    test_storage_that_never_completes();
    test_save_before_send_catches_a_faulty_node();
    test_faulty_node_is_caught_under_load();
    test_chain_events();
    test_timers();
    test_probe_save_notify_and_errors();
    test_invariant_hook();
    return check_done();
}
