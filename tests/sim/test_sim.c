/* Tests for the simulator (sim/sim.c): determinism, each network fault, crash
 * and rebuild at step boundaries and inside a release, storage that is slow,
 * confirmed late, failing or never finishing, the pretend chain and timers,
 * and each invariant shown to catch a deliberately faulty program defined
 * here or in sim_nodes.h. */
#include "sim_nodes.h"
#include "gazpacho/node.h"
#include "gazpacho/runner.h"
#include "../check.h"

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
    c.save_delay_pm = 400; c.max_save_delay_steps = 4; c.save_never_pm = 5; c.save_fail_pm = 5;
    c.confirm_delay_pm = 300; c.max_confirm_delay_steps = 3;
    c.crash_pm = 20; c.crash_in_release_pm = 10; c.ping_pm = 400; c.block_pm = 50;
    c.allow_refusals = 1;
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

static size_t trace_count(const sim_t *sim, const char *text)
{
    size_t n = 0;
    for (const char *p = sim_trace(sim, NULL); (p = strstr(p, text)) != NULL; p += strlen(text)) n++;
    return n;
}

static int same_batch(gz_batch_id_t id, uint64_t incarnation, uint64_t sequence)
{
    return id.incarnation == incarnation && id.sequence == sequence;
}

/* ---- the plain path ---- */

static void test_ping_is_stored_then_answered(void)
{
    sim_config_t c = quiet_config(1, 2);
    sim_t *sim = sim_create(&c);
    world_ping(sim, 0, 0x5a);
    CHECK(sim_run(sim, 1) == 1);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    /* Two batches: the ping, and (once that was confirmed and the reply released) the record that it was sent. */
    CHECK(sim_storage_count(st) == 2 && same_batch(sim_storage_batch_id(st, 0), 1, 1) && same_batch(sim_storage_batch_id(st, 1), 1, 2));
    CHECK(sim_storage_pending(st) == 0 && sim_storage_unconfirmed(st) == 0);
    CHECK(sim_stats(sim)->world_replies == 0);          /* the reply is still in flight */
    CHECK(sim_run(sim, 1) == 1);
    CHECK(sim_stats(sim)->world_replies == 1 && sim_stats(sim)->confirmations == 2);

    size_t len = 0;
    const uint8_t *b = sim_storage_batch_bytes(st, 0, &len);
    const uint8_t want[33] = {0x01, 0x00, 0x57, 0x7e,  25, 0, 0, 0,          /* type, length */
                              0, 0, 0, 0, 0, 0, 0, 1,                         /* clock stamp: step 1 */
                              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* the peer: the world */
                              0, 0, 0, 0, 0, 0, 0, 1,                         /* serial 1 */
                              0x5a};
    CHECK(len == sizeof want && memcmp(b, want, len) == 0);
    const uint8_t sent[16] = {0x02, 0x00, 0x57, 0x7e,  8, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 1};   /* "sent": serial 1 */
    b = sim_storage_batch_bytes(st, 1, &len);
    CHECK(len == sizeof sent && memcmp(b, sent, len) == 0);
    CHECK(saved_replies_not_sent(sim, 2) == 0);
    CHECK(sim_storage_count(sim_node_storage(sim, 1)) == 0);
    CHECK(!sim_failed(sim) && sim_step_count(sim) == 2 && sim_node_incarnation(sim, 0) == 1);
    sim_destroy(sim);
    CHECK(sim_create(NULL) == NULL);
    c.n_nodes = 0;
    CHECK(sim_create(&c) == NULL);
}

/* The sender a node is told about is the real one, and the reply goes there. */
static void test_reply_goes_to_the_sender(void)
{
    sim_config_t c = quiet_config(1, 3);
    sim_t *sim = sim_create(&c);
    const uint8_t ping[5] = {'G', 'Z', 'P', 'I', 7};
    sim_send_message(sim, 2, 0, ping, sizeof ping);     /* node 2's address to node 0 */
    CHECK(sim_run(sim, 3) == 3);
    CHECK(trace_has(sim, " 0->2 len=5"));               /* node 0 answered node 2 */
    CHECK(!trace_has(sim, " 0->-1 ") && !trace_has(sim, " 0->1 "));
    CHECK(sim_stats(sim)->world_replies == 0 && sim_stats(sim)->messages_delivered == 2);
    sim_destroy(sim);
}

/* ---- determinism ---- */

static void test_same_seed_same_trace(void)
{
    for (int multi = 0; multi <= 1; multi++) {
        sim_config_t c = busy_config(2024);
        if (multi) c.ops = multi_ops();
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
        CHECK(s->crashes && s->crashes_in_release && s->saves_lost && s->blocks && s->saves_durable);
        CHECK(s->stale_confirmations && s->storage_failures && s->confirmations && s->handle_errors == 0);
        if (!multi) CHECK(s->world_replies > 0);

        c.seed = 2025;
        sim_t *d = sim_create(&c);
        CHECK(sim_run(d, 2000) == 2000);
        CHECK(sim_trace_hash(d) != sim_trace_hash(a));      /* a different seed is a different run */
        sim_destroy(a); sim_destroy(b); sim_destroy(d);
    }
}

static void test_same_seed_invariant_holds(void)
{
    sim_config_t c = busy_config(77);
    int built = 0, built_twin = 0;
    c.check_same_seed = 1;
    c.ops = multi_ops();
    c.ops.ctx = &built;                                 /* the two simulators get separate contexts */
    c.ops.twin_ctx = &built_twin;
    sim_t *sim = sim_create(&c);
    CHECK(built >= 4 && built_twin == built);            /* four nodes each, plus any crash at start */
    CHECK(sim_run(sim, 1500) == 1500);
    world_ping(sim, 1, 1);                              /* hand-driven occurrences are mirrored too */
    sim_crash_node(sim, 2);
    sim_crash_after_releases(sim, 1, 2);
    sim_fail_storage(sim, 3);
    sim_user_command(sim, 0, (const uint8_t *)"hello", 5);
    sim_mine_block(sim);
    CHECK(sim_run(sim, 100) == 100 && !sim_failed(sim));
    CHECK(built == built_twin && built > 20);           /* the same crashes happened in both */
    sim_destroy(sim);
}

/* FAULTY ON PURPOSE: nodes whose behaviour depends on something outside the
 * seed: a counter shared by the whole process. The first shows it in what it
 * tells the user, the second only in the bytes it saves. */
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
    return multi_add(out, GZ_ACTION_NOTIFY, g_outside_counter++, NULL, 0);
}
static gz_status_t leaky_record_handle(void *node, const gz_event_t *ev, gz_action_list_t *out)
{
    (void)node;
    if (ev->kind != GZ_EVENT_MESSAGE_RECEIVED) return GZ_OK;
    uint8_t v = (uint8_t)g_outside_counter++;
    gz_status_t st = multi_save(out, 7, &v, 1);
    return st == GZ_OK ? multi_add(out, GZ_ACTION_SEND, SIM_WORLD_PEER, (const uint8_t *)"reply", 5) : st;
}

static void test_same_seed_invariant_catches_a_leak(void)
{
    gz_status_t (*handlers[2])(void *, const gz_event_t *, gz_action_list_t *) = {leaky_handle, leaky_record_handle};
    for (int k = 0; k < 2; k++) {
        sim_config_t c = quiet_config(5, 2);
        c.check_same_seed = 1;
        c.ops = (sim_node_ops_t){.create = leaky_create, .destroy = leaky_destroy, .handle = handlers[k]};
        sim_t *sim = sim_create(&c);
        world_ping(sim, 0, 1);
        CHECK(sim_run(sim, 10) == 0);                       /* fails at the first step */
        CHECK(sim_failed(sim) && sim_failure_step(sim) == 1);
        CHECK(strstr(sim_failure_reason(sim), "same seed") != NULL);
        CHECK(sim_step(sim) == 0 && sim_step_count(sim) == 1);   /* a failed run does nothing further */
        sim_destroy(sim);
    }
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
    CHECK(sim_storage_count(sim_node_storage(sim, 0)) == 4);        /* the node saw the ping twice: two pings, two sent records */
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
    CHECK(sim_stats(sim)->messages_delivered >= 1 && sim_storage_count(sim_node_storage(sim, 0)) == 2);
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
    CHECK(sim_storage_count(sim_node_storage(sim, 0)) == 8);        /* all four still arrive */
    sim_destroy(sim);
}

/* ---- crash and rebuild ---- */

static void test_crash_while_a_save_is_pending(void)
{
    sim_config_t c = quiet_config(8, 2);
    c.save_delay_pm = 1000; c.max_save_delay_steps = 5;
    sim_t *sim = sim_create(&c);
    world_ping(sim, 0, 1);
    CHECK(sim_run(sim, 1) == 1);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    CHECK(sim_storage_pending(st) == 1 && sim_storage_count(st) == 0);   /* handed over, not yet durable */
    sim_crash_node(sim, 0);
    CHECK(sim_stats(sim)->crashes == 1 && sim_stats(sim)->saves_lost == 1);
    CHECK(trace_has(sim, "crash node=0 pending-saves=1 held-actions=1"));
    CHECK(sim_node_incarnation(sim, 0) == 2 && sim_node_incarnation(sim, 1) == 1);
    CHECK(sim_run(sim, 40) == 40);
    CHECK(sim_storage_count(st) == 0 && sim_storage_pending(st) == 0);
    CHECK(sim_stats(sim)->world_replies == 0 && sim_stats(sim)->messages_sent == 1);  /* the reply never left */

    world_ping(sim, 0, 2);                              /* the rebuilt node works, under new identifiers */
    CHECK(sim_run(sim, 40) == 40);
    CHECK(sim_storage_count(st) == 2 && same_batch(sim_storage_batch_id(st, 0), 2, 1));
    CHECK(sim_stats(sim)->world_replies == 1 && !sim_failed(sim));
    sim_destroy(sim);
}

/* The batch is durable, its confirmation has not been delivered, and the node
 * crashes. The rebuilt node finds the record and sends the reply that never
 * left. The old confirmation then arrives and must unlock nothing. */
static void test_crash_between_durable_and_confirmed(void)
{
    sim_config_t c = quiet_config(8, 2);
    c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 5;
    sim_t *sim = sim_create(&c);
    world_ping(sim, 0, 0x33);
    CHECK(sim_run(sim, 1) == 1);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    CHECK(sim_storage_count(st) == 1 && sim_storage_pending(st) == 0 && sim_storage_unconfirmed(st) == 1);
    CHECK(sim_stats(sim)->messages_sent == 1);          /* only the ping: the reply is held */

    sim_crash_node(sim, 0);
    CHECK(sim_stats(sim)->saves_lost == 0 && same_batch(sim_storage_batch_id(st, 0), 1, 1));   /* durable: not lost */
    CHECK(sim_stats(sim)->messages_sent == 2);          /* the start resent the saved reply */
    CHECK(sim_storage_count(st) == 2 && same_batch(sim_storage_batch_id(st, 1), 2, 1));       /* and recorded that */
    world_ping(sim, 0, 0x44);                           /* the new runner has a batch of its own in play */
    CHECK(sim_run(sim, 14) == 14);                      /* when the old batch's confirmation arrives */
    CHECK(sim_stats(sim)->stale_confirmations == 1 && sim_stats(sim)->confirmations >= 2);   /* the new incarnation's own batches */
    CHECK(trace_has(sim, "confirmation-ignored node=0 batch=1.1"));
    CHECK(sim_stats(sim)->world_replies == 2 && !sim_failed(sim));
    sim_destroy(sim);
}

/* Two pings are saved and the node crashes before either batch is confirmed.
 * Both replies must still leave: "saved, so eventually sent". */
static void test_every_saved_reply_is_sent_after_a_crash(void)
{
    size_t both_durable = 0;
    for (uint64_t seed = 1; seed <= 100; seed++) {
        sim_config_t c = quiet_config(seed, 1);
        c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 6;
        sim_t *sim = sim_create(&c);
        world_ping(sim, 0, 1);
        world_ping(sim, 0, 2);
        CHECK(sim_run(sim, 2) == 2);
        const sim_storage_t *st = sim_node_storage(sim, 0);
        if (sim_storage_count(st) == 2 && sim_storage_unconfirmed(st) == 2) {
            both_durable++;
            CHECK(saved_replies_not_sent(sim, 1) == 2);     /* both durable, and neither reply has left yet */
        }
        sim_crash_node(sim, 0);
        sim_quiesce(sim);
        CHECK(sim_run(sim, 40) == 40 && !sim_failed(sim));
        CHECK(saved_replies_not_sent(sim, 1) == 0);
        sim_destroy(sim);
    }
    CHECK(both_durable >= 50);                          /* the case in question really was produced */
}

static uint64_t stamp_of(const sim_storage_t *st, size_t i)
{
    const uint8_t *b = sim_storage_batch_bytes(st, i, NULL);
    uint64_t v = 0;
    for (int k = 0; k < 8; k++) v = v << 8 | b[8 + k];
    return v;
}

static void test_storage_survives_a_crash(void)
{
    sim_config_t c = quiet_config(8, 2);
    sim_t *sim = sim_create(&c);
    for (uint8_t i = 1; i <= 4; i++) world_ping(sim, 0, i);
    CHECK(sim_run(sim, 10) == 10);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    CHECK(sim_storage_count(st) == 8 && sim_stats(sim)->world_replies == 4);   /* four pings, four "sent" */
    world_ping(sim, 0, 5);                              /* in flight across the crash */
    sim_crash_node(sim, 0);
    CHECK(sim_storage_count(st) == 8);
    for (size_t i = 0; i < 8; i++) CHECK(same_batch(sim_storage_batch_id(st, i), 1, i + 1));
    CHECK(sim_stats(sim)->messages_sent == 9);          /* every reply is recorded as sent: the start resends none */
    CHECK(sim_run(sim, 10) == 10);
    CHECK(sim_storage_count(st) == 10 && same_batch(sim_storage_batch_id(st, 8), 2, 1));
    CHECK(stamp_of(st, 0) == 1 && stamp_of(st, 8) == 11);   /* the clock carries on across the crash */
    CHECK(sim_stats(sim)->world_replies == 5 && saved_replies_not_sent(sim, 2) == 0);
    sim_crash_node(sim, 7);                             /* no such node: ignored */
    CHECK(sim_stats(sim)->crashes == 1 && !sim_failed(sim));
    sim_destroy(sim);
}

static void test_storage_that_never_completes(void)
{
    for (int allow = 0; allow <= 1; allow++) {
        sim_config_t c = quiet_config(8, 1);
        c.save_never_pm = 1000;
        c.allow_refusals = allow;
        sim_t *sim = sim_create(&c);
        for (int i = 0; i < 100 && !sim_failed(sim); i++) { world_ping(sim, 0, (uint8_t)i); sim_step(sim); }
        const sim_stats_t *s = sim_stats(sim);
        CHECK(s->world_replies == 0 && s->saves_durable == 0);
        CHECK(s->lists_refused > 0 && trace_has(sim, "durable-at=-1"));   /* the runner filled up and said so */
        if (allow) {
            CHECK(!sim_failed(sim) && s->crashes == s->lists_refused);  /* each refusal restarted the node */
            CHECK(sim_node_incarnation(sim, 0) == 1 + s->crashes);
        } else {
            CHECK(sim_failed(sim) && strstr(sim_failure_reason(sim), "refused") != NULL);
        }
        sim_destroy(sim);
    }
}

static void test_storage_failure(void)
{
    sim_config_t c = quiet_config(8, 2);
    c.save_delay_pm = 1000; c.max_save_delay_steps = 5;
    sim_t *sim = sim_create(&c);
    world_ping(sim, 0, 1);
    CHECK(sim_run(sim, 1) == 1);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    CHECK(sim_storage_pending(st) == 1);
    sim_fail_storage(sim, 0);
    const sim_stats_t *s = sim_stats(sim);
    CHECK(s->storage_failures == 1 && s->saves_lost == 1 && s->crashes == 1);
    CHECK(sim_node_incarnation(sim, 0) == 2 && sim_storage_pending(st) == 0);
    CHECK(sim_run(sim, 20) == 20);
    CHECK(sim_storage_count(st) == 0 && s->world_replies == 0);     /* what waited for that save never left */
    world_ping(sim, 0, 2);
    CHECK(sim_run(sim, 20) == 20 && s->world_replies == 1 && !sim_failed(sim));
    sim_destroy(sim);

    c = quiet_config(8, 2);                             /* and from the schedule: every save fails */
    c.save_fail_pm = 1000;
    sim = sim_create(&c);
    for (uint8_t i = 0; i < 5; i++) world_ping(sim, 0, i);
    CHECK(sim_run(sim, 30) == 30 && !sim_failed(sim));
    s = sim_stats(sim);
    CHECK(s->storage_failures == 5 && s->saves_durable == 0 && s->world_replies == 0 && s->crashes == 5);
    sim_destroy(sim);
}

/* ---- the multi node: several batches unconfirmed, every kind of action ---- */

static void test_multi_node_plain_run(void)
{
    sim_config_t c = quiet_config(9, 2);
    c.ops = multi_ops();
    c.save_delay_pm = 1000; c.max_save_delay_steps = 3;
    c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 3;
    sim_t *sim = sim_create(&c);
    sim_user_command(sim, 0, (const uint8_t *)"abc", 3);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    CHECK(sim_storage_pending(st) == 3);                /* all three batches went to storage at once */
    CHECK(!trace_has(sim, "notify node=0") && !trace_has(sim, "broadcast node=0") && sim_stats(sim)->messages_sent == 0);
    CHECK(sim_run(sim, 20) == 20 && !sim_failed(sim));
    CHECK(sim_storage_count(st) == 3 && sim_stats(sim)->confirmations == 3);
    CHECK(trace_count(sim, "notify node=0 code=1") == 1 && trace_count(sim, "broadcast node=0") == 1);
    CHECK(sim_stats(sim)->world_replies == 2);          /* "Mabc" and "Cabc" */
    /* In the order the node listed them: notify, watch, broadcast, timer, send, send. */
    const char *t = sim_trace(sim, NULL);
    const char *notify = strstr(t, "notify node=0"), *watch = strstr(notify, "watch node=0 len=3"),
               *broadcast = strstr(t, "broadcast node=0"), *timer = strstr(broadcast, "set-timer node=0"),
               *first = strstr(t, "queue seq=0"), *second = strstr(t, "queue seq=1");
    CHECK(notify && watch && broadcast && timer && first && second);
    CHECK(notify < watch && watch < broadcast && broadcast < timer && timer < first && first < second);
    sim_destroy(sim);
}

/* A crash before each of the nine actions one command makes the runner hand
 * over, and after the last. Three are saves, released by the submit; the
 * second confirmation releases five (notify, watch, broadcast, timer, send);
 * the third releases the last send. */
static void test_crash_inside_a_release(void)
{
    for (uint32_t k = 0; k <= 9; k++) {
        sim_config_t c = quiet_config(9, 2);
        c.ops = multi_ops();
        c.check_same_seed = 1;
        sim_t *sim = sim_create(&c);
        sim_crash_after_releases(sim, 0, k);
        sim_user_command(sim, 0, (const uint8_t *)"abc", 3);
        CHECK(sim_run(sim, 10) == 10 && !sim_failed(sim));
        const sim_stats_t *s = sim_stats(sim);
        const sim_storage_t *st = sim_node_storage(sim, 0);
        CHECK(s->crashes_in_release == (k < 9) && s->crashes == (k < 9));
        CHECK(sim_node_incarnation(sim, 0) == (k < 9 ? 2u : 1u));
        if (k < 3) {
            /* Crashed while handing over the saves: those already handed over were
             * still pending and are lost; nothing else was ever carried out. */
            CHECK(sim_storage_count(st) == 0 && s->saves_lost == k);
            CHECK(!trace_has(sim, "notify node=0") && !trace_has(sim, "broadcast node=0") && s->messages_sent == 0);
        } else {
            /* All three batches are durable. Whatever had not left before the
             * crash is made good by the restart: the decision is broadcast and
             * the message sent, once or (if they had already left) twice. */
            CHECK(sim_storage_count(st) == 3 && s->saves_lost == 0);
            CHECK(trace_count(sim, "notify node=0 code=1") == (k >= 4));
            CHECK(trace_count(sim, "broadcast node=0") == 1 + (size_t)(k >= 6 && k < 9));
            CHECK(trace_count(sim, "already-known") == (size_t)(k >= 6 && k < 9));
            /* "Mabc" before the crash from k = 8, "Cabc" only with no crash, and the restart's resend. */
            CHECK(s->messages_sent == (uint64_t)(k >= 8) + (k >= 9) + (k < 9));
        }
        sim_destroy(sim);
    }
}

/* A saved decision to broadcast survives a crash that comes before the
 * broadcast: the restart broadcasts it, and it confirms. */
static void test_saved_decision_is_broadcast_after_a_crash(void)
{
    sim_config_t c = quiet_config(9, 2);
    c.ops = multi_ops();
    c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 6;
    sim_t *sim = sim_create(&c);
    sim_user_command(sim, 0, (const uint8_t *)"pay", 3);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    CHECK(sim_storage_count(st) == 3 && sim_storage_unconfirmed(st) == 3);
    CHECK(!trace_has(sim, "broadcast node=0") && sim_stats(sim)->messages_sent == 0);   /* nothing has left */
    sim_crash_node(sim, 0);
    CHECK(trace_count(sim, "broadcast node=0 len=5") == 1 && sim_stats(sim)->messages_sent == 1);
    sim_mine_block(sim);
    CHECK(trace_has(sim, "chain confirmed node=0 confirmations=1"));
    CHECK(sim_run(sim, 20) == 20 && !sim_failed(sim));
    CHECK(sim_stats(sim)->stale_confirmations == 3 && sim_stats(sim)->confirmations == 0);
    CHECK(trace_count(sim, "broadcast node=0") == 1);   /* the stale confirmations released nothing */
    sim_destroy(sim);
}

/* ---- "nothing is sent before it is saved" ---- */

/* FAULTY ON PURPOSE: a program that carries out actions last first. */
static gz_status_t backwards_release(void *ctx, sim_t *sim, uint32_t index, const gz_action_list_t *list)
{
    (void)ctx;
    for (size_t i = list->count; i-- > 0;) sim_execute(sim, index, &list->slots[i]);
    return GZ_OK;
}

static void test_save_before_send_catches_a_faulty_program(void)
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
}

/* ---- a probe node, to see the pretend chain, timers, ports and errors ---- */

typedef struct {
    uint32_t tips, last_tip, spent, confirmed, unconfirmed, last_confirmations, timers, stored, messages, chain_left;
    uint32_t connected, disconnected;
    uint64_t last_sender, last_peer, last_clock;
    uint8_t spent_txid[32], confirmed_txid[32];
    int notify_on_timer, notify_on_tip;     /* make those events produce an action, so a crash can interrupt it */
    const gz_ports_t *ports;
} probe_t;
static probe_t g_probe[4];

static void *probe_create(void *ctx, uint32_t index, const gz_ports_t *ports, const sim_storage_t *storage)
{
    (void)ctx; (void)storage;
    g_probe[index].ports = ports;
    return &g_probe[index];
}
static void probe_destroy(void *ctx, void *node) { (void)ctx; (void)node; }

/* User commands: 'B' tx.. broadcast; 'W' script.. watch; 'T' id delay: set a
 * timer; 'C' id: cancel it; 'N' code: notify; 'O': two notifies; 'S' x: save
 * then notify x; 'D' x: two saves; 'R': save eight bytes from the random
 * port; 'E': a save, and another at each confirmation, 100,000 times. */
static gz_status_t probe_command(probe_t *p, gz_bytes_t cmd, gz_action_list_t *out)
{
    uint8_t drawn[8];
    const uint8_t *rest = cmd.data + 1;
    size_t rest_len = cmd.len - 1;
    gz_status_t st;
    switch (cmd.data[0]) {
    case 'B': return multi_add(out, GZ_ACTION_BROADCAST, 0, rest, rest_len);
    case 'W': return multi_add(out, GZ_ACTION_WATCH, 0, rest_len ? rest : NULL, rest_len);
    case 'T': return multi_add(out, GZ_ACTION_SET_TIMER, cmd.data[1], NULL, cmd.data[2]);
    case 'C': {
        gz_action_t a = {.kind = GZ_ACTION_CANCEL_TIMER};
        a.u.cancel_timer.timer_id = cmd.data[1];
        return gz_action_list_add(out, &a);
    }
    case 'N': return multi_add(out, GZ_ACTION_NOTIFY, cmd.data[1], NULL, 0);
    case 'O':
        st = multi_add(out, GZ_ACTION_NOTIFY, 1, NULL, 0);
        return st == GZ_OK ? multi_add(out, GZ_ACTION_NOTIFY, 2, NULL, 0) : st;
    case 'S':
        st = multi_save(out, 7, rest, rest_len);
        return st == GZ_OK ? multi_add(out, GZ_ACTION_NOTIFY, cmd.data[1], NULL, 0) : st;
    case 'D':
        st = multi_save(out, 7, (const uint8_t *)"first", 5);
        return st == GZ_OK ? multi_save(out, 7, (const uint8_t *)"second", 6) : st;
    case 'R':
        p->ports->random.fill(p->ports->random.ctx, GZ_RANDOM_OTHER, drawn, sizeof drawn);
        return multi_save(out, 8, drawn, sizeof drawn);
    case 'K':   /* a "secret" taken straight from the random port, saved and used */
        p->ports->random.fill(p->ports->random.ctx, GZ_RANDOM_SECRET, drawn, sizeof drawn);
        st = multi_save(out, 8, drawn, sizeof drawn);
        return st == GZ_OK ? multi_add(out, GZ_ACTION_NOTIFY, 77, drawn, sizeof drawn) : st;
    case 'U':   /* two timers due together */
        st = multi_add(out, GZ_ACTION_SET_TIMER, 1, NULL, 1);
        return st == GZ_OK ? multi_add(out, GZ_ACTION_SET_TIMER, 2, NULL, 1) : st;
    case 'L':
        p->last_clock = p->ports->clock.now_ms(p->ports->clock.ctx);
        return GZ_OK;
    case 'E':
        p->chain_left = 100000;
        return multi_save(out, 9, rest, rest_len);
    default: return GZ_ERR_ARGUMENT;
    }
}

static gz_status_t probe_handle(void *node, const gz_event_t *ev, gz_action_list_t *out)
{
    probe_t *p = node;
    switch (ev->kind) {
    case GZ_EVENT_USER_COMMAND:      return probe_command(p, ev->u.user.bytes, out);
    case GZ_EVENT_TIMER_FIRED:
        p->timers++;
        if (p->notify_on_timer) return multi_add(out, GZ_ACTION_NOTIFY, (uint32_t)ev->u.timer.timer_id, NULL, 0);
        break;
    case GZ_EVENT_PEER_CONNECTED:    p->connected++; p->last_peer = ev->u.peer.peer_id; break;
    case GZ_EVENT_PEER_DISCONNECTED: p->disconnected++; p->last_peer = ev->u.peer.peer_id; break;
    case GZ_EVENT_STORAGE_CONFIRMED:
        p->stored++;
        if (p->chain_left && p->chain_left--) return multi_save(out, 9, NULL, 0);
        break;
    case GZ_EVENT_MESSAGE_RECEIVED:  p->messages++; p->last_sender = ev->u.message.peer_id; break;
    case GZ_EVENT_CHAIN:
        if (ev->u.chain.kind == GZ_CHAIN_NEW_TIP) {
            p->tips++; p->last_tip = ev->u.chain.height;
            if (p->notify_on_tip) return multi_add(out, GZ_ACTION_NOTIFY, 500, NULL, 0);
        }
        if (ev->u.chain.kind == GZ_CHAIN_TX_UNCONFIRMED) p->unconfirmed++;
        if (ev->u.chain.kind == GZ_CHAIN_SCRIPT_SPENT) { p->spent++; memcpy(p->spent_txid, ev->u.chain.txid, 32); }
        if (ev->u.chain.kind == GZ_CHAIN_TX_CONFIRMED) {
            p->confirmed++; p->last_confirmations = ev->u.chain.confirmations;
            memcpy(p->confirmed_txid, ev->u.chain.txid, 32);
        }
        break;
    }
    return GZ_OK;
}

static sim_config_t probe_config(uint32_t n_nodes)
{
    sim_config_t c = quiet_config(21, n_nodes);
    c.ops = (sim_node_ops_t){.create = probe_create, .destroy = probe_destroy, .handle = probe_handle};
    memset(g_probe, 0, sizeof g_probe);
    return c;
}

static sim_t *probe_sim(uint32_t n_nodes)
{
    sim_config_t c = probe_config(n_nodes);
    return sim_create(&c);
}

/* Saves are told apart by their place in the node's own sequence, so a
 * faulty program cannot hide behind identifiers: here the first batch is
 * durable and the second is not, and both carry the same (zero) identifier. */
static void test_observer_counts_saves_by_position(void)
{
    sim_config_t c = quiet_config(11, 1);
    c.ops = multi_ops();
    c.ops.release = eager_release;
    c.save_delay_pm = 1000; c.max_save_delay_steps = 3;
    sim_t *sim = sim_create(&c);
    CHECK(!sim_failed(sim));                            /* the start list has no saves: nothing wrong yet */
    sim_user_command(sim, 0, (const uint8_t *)"abc", 3);
    CHECK(sim_failed(sim) && strstr(sim_failure_reason(sim), "nothing is sent before it is saved") != NULL);
    sim_destroy(sim);

    /* One save alone, long since durable; then a save and a notify from an
     * eager program while the second save is still pending. */
    c = probe_config(1);
    c.ops.release = eager_release;
    c.save_delay_pm = 1000; c.max_save_delay_steps = 3;
    sim = sim_create(&c);
    sim_user_command(sim, 0, (const uint8_t *)"R", 1);
    CHECK(sim_run(sim, 10) == 10 && sim_storage_count(sim_node_storage(sim, 0)) == 1 && !sim_failed(sim));
    sim_user_command(sim, 0, (const uint8_t *)"Sx", 2);
    CHECK(sim_storage_pending(sim_node_storage(sim, 0)) == 1);
    CHECK(sim_failed(sim) && strstr(sim_failure_reason(sim), "nothing is sent before it is saved") != NULL);
    sim_destroy(sim);
}

static void test_observer_checks_the_order_of_what_leaves(void)
{
    sim_config_t c = probe_config(1);
    sim_t *good = sim_create(&c);
    sim_user_command(good, 0, (const uint8_t *)"O", 1);
    CHECK(!sim_failed(good) && trace_count(good, "notify node=0") == 2);
    sim_destroy(good);

    c.ops.release = backwards_release;                  /* no saves involved: only the order is wrong */
    sim_t *bad = sim_create(&c);
    sim_user_command(bad, 0, (const uint8_t *)"O", 1);
    CHECK(sim_failed(bad) && strstr(sim_failure_reason(bad), "out of the order") != NULL);
    sim_destroy(bad);

    sim_t *swapped = sim_create(&c);                    /* two saves handed to storage in the wrong order */
    sim_user_command(swapped, 0, (const uint8_t *)"D", 1);
    CHECK(sim_failed(swapped) && strstr(sim_failure_reason(swapped), "not the next one the node emitted") != NULL);
    sim_destroy(swapped);
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

static void test_a_crash_forgets_watches_and_timers(void)
{
    sim_t *sim = probe_sim(2);
    const uint8_t watch[3] = {'W', 0x11, 0x22}, spend[5] = {'B', 2, 0x11, 0x22, 9}, set[3] = {'T', 1, 3};
    sim_user_command(sim, 0, watch, sizeof watch);
    sim_user_command(sim, 0, set, sizeof set);
    sim_crash_node(sim, 0);
    sim_user_command(sim, 1, spend, sizeof spend);
    sim_mine_block(sim);
    CHECK(sim_run(sim, 10) == 10);
    CHECK(g_probe[0].spent == 0 && g_probe[0].timers == 0);     /* the rebuilt node asked for neither */
    CHECK(g_probe[0].tips == 1 && !sim_failed(sim));
    sim_user_command(sim, 0, (const uint8_t *)"W", 1);          /* an empty script is a script too */
    sim_user_command(sim, 0, (const uint8_t *)"W", 1);
    sim_mine_block(sim);
    CHECK(!sim_failed(sim));
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
    sim_destroy(sim);
}

/* The random port after a crash: a fresh stream, the same in every run of the
 * seed, and never one an earlier incarnation used. */
static void test_random_port_across_a_crash(void)
{
    uint8_t drawn[2][6][8];
    for (int run = 0; run < 2; run++) {
        sim_t *sim = probe_sim(2);
        const sim_storage_t *st = sim_node_storage(sim, 0);
        for (int i = 0; i < 6; i++) {
            if (i == 2 || i == 4) sim_crash_node(sim, 0);
            sim_user_command(sim, 0, (const uint8_t *)"R", 1);
        }
        CHECK(sim_storage_count(st) == 6 && sim_node_incarnation(sim, 0) == 3 && !sim_failed(sim));
        for (size_t i = 0; i < 6; i++) memcpy(drawn[run][i], sim_storage_batch_bytes(st, i, NULL) + 8, 8);
        sim_user_command(sim, 1, (const uint8_t *)"R", 1);          /* another node has its own stream */
        CHECK(memcmp(sim_storage_batch_bytes(sim_node_storage(sim, 1), 0, NULL) + 8, drawn[run][0], 8) != 0);
        sim_destroy(sim);
    }
    CHECK(memcmp(drawn[0], drawn[1], sizeof drawn[0]) == 0);        /* same seed, same bytes */
    for (int i = 0; i < 6; i++)
        for (int k = i + 1; k < 6; k++)
            CHECK(memcmp(drawn[0][i], drawn[0][k], 8) != 0);        /* nothing repeats across crashes */
}

static void test_probe_save_notify_and_errors(void)
{
    sim_t *sim = probe_sim(2);
    const uint8_t save[3] = {'S', 9, 1}, bad[1] = {'?'}, note[2] = {'N', 4};
    const uint8_t hello[2] = {1, 2};
    sim_user_command(sim, 0, save, 3);
    CHECK(g_probe[0].stored == 1 && sim_storage_count(sim_node_storage(sim, 0)) == 1);
    CHECK(trace_has(sim, "notify node=0 code=9"));
    sim_user_command(sim, 1, bad, 1);
    CHECK(sim_stats(sim)->handle_errors == 1);
    sim_user_command(sim, 1, note, 2);
    CHECK(trace_has(sim, "notify node=1 code=4"));
    sim_send_message(sim, 0, 1, hello, 2);
    sim_send_message(sim, 0, 5, hello, 2);                          /* no such peer: delivered nowhere */
    CHECK(sim_run(sim, 5) == 5 && g_probe[1].messages == 1 && sim_stats(sim)->messages_delivered == 1);
    CHECK(g_probe[1].last_sender == 0);                             /* told who really sent it */
    CHECK(!sim_failed(sim));
    sim_destroy(sim);
}

/* One event leading to another, a hundred thousand deep: handled in a loop,
 * not by calling ever deeper. */
static void test_long_chains_of_events(void)
{
    sim_t *sim = probe_sim(1);
    sim_user_command(sim, 0, (const uint8_t *)"E", 1);
    CHECK(sim_storage_count(sim_node_storage(sim, 0)) == 100001 && g_probe[0].stored == 100001);
    CHECK(!sim_failed(sim));
    sim_destroy(sim);
}

/* ---- start in steps, and starts that fail ---- */

/* Twenty saved replies are unsent when the node crashes: more than one start
 * step resends. The start comes in steps and every reply leaves. */
static void test_start_in_steps_through_the_runner(void)
{
    sim_config_t c = quiet_config(31, 1);
    c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 1000;
    sim_t *sim = sim_create(&c);
    for (uint8_t i = 0; i < 20; i++) world_ping(sim, 0, i);
    CHECK(sim_run(sim, 20) == 20);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    size_t unsent = saved_replies_not_sent(sim, 1);
    CHECK(sim_storage_count(st) >= 20 && unsent >= 15);     /* nearly all still wait for a far-off confirmation */
    uint64_t sent_before = sim_stats(sim)->node_sends;
    sim_crash_node(sim, 0);
    CHECK(!sim_failed(sim) && sim_stats(sim)->node_sends - sent_before == unsent);
    CHECK(saved_replies_not_sent(sim, 1) == 0);
    CHECK(sim_storage_count(st) + sim_storage_pending(st) >= 20 + (unsent + 7) / 8);   /* one "sent" record per step */
    sim_destroy(sim);
}

static int g_start_calls;
static gz_status_t failing_start(void *node, gz_action_list_t *out, int *more)
{
    (void)node; (void)out;
    *more = 0;
    return ++g_start_calls >= 3 ? GZ_ERR_NO_SPACE : GZ_OK;     /* the first node starts; a later start fails */
}
static gz_status_t refusing_release(void *ctx, sim_t *sim, uint32_t index, const gz_action_list_t *list)
{
    (void)ctx; (void)sim; (void)index; (void)list;
    return GZ_ERR_REFUSED;
}
static gz_status_t endless_start(void *node, gz_action_list_t *out, int *more)
{
    (void)node; (void)out;
    *more = 1;
    return GZ_OK;
}
/* A start that returns an error, or never finishes, fails the run: the
 * simulator does not log it and carry on with a node that never started. */
static void test_a_failed_start_is_fatal(void)
{
    sim_config_t c = quiet_config(31, 1);
    c.ops = (sim_node_ops_t){.create = probe_create, .destroy = probe_destroy, .start = failing_start, .handle = probe_handle};
    g_start_calls = 0;
    sim_t *sim = sim_create(&c);
    CHECK(!sim_failed(sim));
    sim_crash_node(sim, 0);
    CHECK(!sim_failed(sim));
    sim_crash_node(sim, 0);                                 /* this start returns an error */
    CHECK(sim_failed(sim) && strstr(sim_failure_reason(sim), "failed to start") != NULL);
    CHECK(sim_stats(sim)->handle_errors == 1 && trace_has(sim, "start-error node=0"));
    sim_destroy(sim);

    c.ops.start = endless_start;
    sim = sim_create(&c);
    CHECK(sim_failed(sim) && strstr(sim_failure_reason(sim), "failed to start") != NULL);
    sim_destroy(sim);

    c = quiet_config(31, 1);                                /* a start list its program refuses */
    c.ops = multi_ops();
    c.ops.release = refusing_release;
    c.allow_refusals = 1;                                   /* allowed for ordinary lists, never for a start */
    sim = sim_create(&c);
    CHECK(sim_failed(sim) && strstr(sim_failure_reason(sim), "start actions were refused") != NULL);
    sim_destroy(sim);
}

/* ---- restore from an older backup, and what invariants can see ---- */

static void test_restore_from_an_older_backup(void)
{
    sim_config_t c = quiet_config(41, 2);
    sim_t *sim = sim_create(&c);
    for (uint8_t i = 1; i <= 3; i++) world_ping(sim, 0, i);
    CHECK(sim_run(sim, 10) == 10);
    const sim_storage_t *st = sim_node_storage(sim, 0);
    CHECK(sim_storage_count(st) == 6 && sim_stats(sim)->node_sends == 3);

    sim_restore_backup(sim, 0, 3);                          /* back to: ping 1, its "sent" record, ping 2 */
    CHECK(sim_stats(sim)->restores == 1 && sim_node_incarnation(sim, 0) == 2);
    CHECK(sim_stats(sim)->node_sends == 4);                 /* ping 2 has no "sent" record any more: resent */
    CHECK(sim_storage_count(st) == 4);                      /* the three kept, and the new "sent" record */
    CHECK(same_batch(sim_storage_batch_id(st, 3), 2, 1));   /* and recorded under the new incarnation */
    world_ping(sim, 0, 9);
    CHECK(sim_run(sim, 10) == 10 && !sim_failed(sim));
    CHECK(sim_stats(sim)->stale_confirmations == 0);        /* nothing from before the restore arrived */
    uint8_t shown[16] = {0};
    CHECK(sim_node_inspect(sim, 0, shown, sizeof shown) == 16 && shown[0] == 4);   /* serials went on from the backup: 3 was used again */
    sim_restore_backup(sim, 0, 999);                        /* more than there is: everything is kept */
    CHECK(sim_storage_count(st) == 6 && !sim_failed(sim));
    sim_restore_backup(sim, 0, 0);
    CHECK(sim_storage_count(st) == 0 && !sim_failed(sim) && sim_node_incarnation(sim, 0) == 4);
    sim_destroy(sim);

    /* After a crash the old batches' confirmations still arrive, and are stale. After a
     * restore none may arrive at all: storage is opened afresh. */
    for (int restored = 0; restored <= 1; restored++) {
        c = quiet_config(41, 1);
        c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 5;
        sim = sim_create(&c);
        world_ping(sim, 0, 1);
        world_ping(sim, 0, 2);
        CHECK(sim_run(sim, 2) == 2);
        size_t unconfirmed = sim_storage_unconfirmed(sim_node_storage(sim, 0));
        if (restored) sim_restore_backup(sim, 0, 99); else sim_crash_node(sim, 0);
        sim_quiesce(sim);
        CHECK(sim_run(sim, 30) == 30 && !sim_failed(sim) && unconfirmed >= 1);
        CHECK(sim_stats(sim)->stale_confirmations == (restored ? 0 : unconfirmed));
        sim_destroy(sim);
    }

    c = busy_config(41);                                    /* and from the schedule */
    c.restore_pm = 30;
    c.check_same_seed = 1;
    sim = sim_create(&c);
    CHECK(sim_run(sim, 1500) == 1500 && sim_stats(sim)->restores > 10);
    sim_destroy(sim);
}

/* A program whose release hook goes on after storage failed inside the
 * executor is caught; the default runner stops (tested above). */
static void test_a_program_that_goes_on_after_a_storage_failure(void)
{
    sim_config_t c = probe_config(1);
    c.ops.release = eager_release;
    c.save_fail_inline_pm = 1000;
    sim_t *sim = sim_create(&c);
    sim_user_command(sim, 0, (const uint8_t *)"Sx", 2);     /* a save, which fails, then a notify */
    CHECK(sim_failed(sim) && strstr(sim_failure_reason(sim), "after its program's storage had failed") != NULL);
    CHECK(sim_stats(sim)->inline_storage_failures == 1);
    sim_destroy(sim);
}

/* ---- one-time secrets: judged on the secrets used, not on the draws ---- */

/* Run a multi node, made to use its secrets in `mode`, through two commands,
 * a restore to just after the first, and two more commands. Returns 1 if the
 * invariant over the secrets used failed. */
static int run_secrets(secret_mode_t mode, int repeats, size_t *judged)
{
    sim_config_t c = quiet_config(61, 1);
    secret_watch_t w;
    memset(&w, 0, sizeof w);
    w.n_nodes = 1;
    c.ops = multi_ops();
    c.restore_repeats_random = repeats;
    g_secret_mode = mode;
    sim_t *sim = sim_create(&c);
    CHECK(sim_add_invariant(sim, no_secret_used_twice, &w) == 1);
    sim_user_command(sim, 0, (const uint8_t *)"a", 1);
    sim_run(sim, 5);
    size_t keep = sim_storage_count(sim_node_storage(sim, 0));
    sim_user_command(sim, 0, (const uint8_t *)"b", 1);
    sim_run(sim, 5);
    sim_restore_backup(sim, 0, keep);
    sim_user_command(sim, 0, (const uint8_t *)"c", 1);
    sim_run(sim, 5);
    sim_user_command(sim, 0, (const uint8_t *)"d", 1);
    sim_run(sim, 5);
    int failed = sim_failed(sim);
    if (failed) CHECK(strcmp(sim_failure_reason(sim), "a one-time secret was used twice") == 0);
    *judged = w.checked;
    sim_destroy(sim);
    secret_watch_free(&w);
    g_secret_mode = SECRET_CORRECT;
    return failed;
}

static void test_secrets_are_judged_on_what_was_used(void)
{
    size_t judged = 0;
    /* The correct node mixes in its incarnation: passes, even when the port repeats. */
    CHECK(!run_secrets(SECRET_CORRECT, 1, &judged) && judged == 4);
    CHECK(!run_secrets(SECRET_CORRECT, 0, &judged) && judged == 4);
    /* A node taking its secret from the port alone is caught when the port repeats,
     * whatever tag it gave its draws. */
    CHECK(run_secrets(SECRET_NAIVE, 1, &judged));
    CHECK(run_secrets(SECRET_NAIVE_UNTAGGED, 1, &judged));
    CHECK(!run_secrets(SECRET_NAIVE, 0, &judged));         /* harmless while the port never repeats */
    /* A node deriving its secret from a counter in the journal is caught after a
     * restore, with no help from the port at all. */
    CHECK(run_secrets(SECRET_JOURNAL_COUNTER, 0, &judged));
}

/* The secrets an incarnation used just before it crashed are judged too: the
 * invariant looks at the node before it is destroyed. */
static void test_secrets_of_a_crashing_node_are_judged(void)
{
    sim_config_t c = quiet_config(62, 1);
    secret_watch_t w;
    memset(&w, 0, sizeof w);
    w.n_nodes = 1;
    c.ops = multi_ops();
    sim_t *sim = sim_create(&c);
    CHECK(sim_add_invariant(sim, no_secret_used_twice, &w) == 1);
    sim_crash_after_releases(sim, 0, 0);                    /* dies handing over the first action of its answer */
    sim_user_command(sim, 0, (const uint8_t *)"a", 1);
    CHECK(!sim_failed(sim) && sim_node_incarnation(sim, 0) == 2 && w.checked == 1);
    sim_destroy(sim);
    secret_watch_free(&w);
}

/* After a restore with the repeating fault, the random port gives the stream
 * of the incarnation that wrote the newest batch the backup kept; after a
 * restore to nothing, that of the first incarnation. Both scheduled and
 * hand-driven restores do it. */
static void test_which_stream_a_restore_repeats(void)
{
    sim_config_t c = probe_config(1);
    c.restore_repeats_random = 1;
    sim_t *sim = sim_create(&c);
    sim_user_command(sim, 0, (const uint8_t *)"R", 1);      /* incarnation 1: draw, saved */
    sim_crash_node(sim, 0);
    sim_user_command(sim, 0, (const uint8_t *)"R", 1);      /* incarnation 2: draw, saved */
    sim_crash_node(sim, 0);                                 /* incarnation 3 */
    CHECK(sim_storage_count(sim_node_storage(sim, 0)) == 2);
    sim_restore_backup(sim, 0, 2);                          /* the newest kept was written by incarnation 2 */
    sim_user_command(sim, 0, (const uint8_t *)"R", 1);
    size_t n = sim_node_draw_count(sim, 0);
    CHECK(n == 3 && memcmp(sim_node_draw(sim, 0, 2)->bytes, sim_node_draw(sim, 0, 1)->bytes, 8) == 0);
    CHECK(memcmp(sim_node_draw(sim, 0, 2)->bytes, sim_node_draw(sim, 0, 0)->bytes, 8) != 0);
    sim_restore_backup(sim, 0, 0);                          /* nothing kept: the first stream */
    sim_user_command(sim, 0, (const uint8_t *)"R", 1);
    CHECK(sim_node_draw_count(sim, 0) == 4 && memcmp(sim_node_draw(sim, 0, 3)->bytes, sim_node_draw(sim, 0, 0)->bytes, 8) == 0);
    CHECK(sim_stats(sim)->restores_repeating == 2 && !sim_failed(sim));
    sim_destroy(sim);

    /* Scheduled restores repeat the stream too: a naive node is caught by them. */
    sim_config_t d = busy_config(63);
    secret_watch_t w;
    memset(&w, 0, sizeof w);
    w.n_nodes = 4;
    d.ops = multi_ops();
    d.restore_pm = 100; d.restore_repeats_random = 1;
    d.crash_pm = d.crash_in_release_pm = 0;
    g_secret_mode = SECRET_NAIVE;
    sim = sim_create(&d);
    CHECK(sim_add_invariant(sim, no_secret_used_twice, &w) == 1);
    sim_run(sim, 2000);
    CHECK(sim_failed(sim) && strcmp(sim_failure_reason(sim), "a one-time secret was used twice") == 0);
    CHECK(sim_stats(sim)->restores_repeating > 0);
    sim_destroy(sim);
    secret_watch_free(&w);
    g_secret_mode = SECRET_CORRECT;
}

/* ---- a start that waits, and what happens to events meanwhile ---- */

/* A test node whose start waits: it asks for one save, then waits until that
 * save is confirmed, three times over, sending a notify after each. */
typedef struct { int saves, confirmed, handled_messages, handled_commands; uint64_t steps_of[16]; uint64_t incarnation; } waiter_t;
static waiter_t g_waiter;
static void *waiter_create(void *ctx, uint32_t index, const gz_ports_t *ports, const sim_storage_t *storage)
{
    (void)ctx; (void)index; (void)ports;
    g_waiter.saves = g_waiter.confirmed = 0;
    g_waiter.incarnation = sim_storage_incarnation(storage);
    return &g_waiter;
}
static gz_status_t waiter_start(void *node, gz_action_list_t *out, int *more)
{
    waiter_t *w = node;
    if (w->incarnation < 16) w->steps_of[w->incarnation]++;
    if (w->saves > w->confirmed) return GZ_WAITING;
    *more = w->saves < 3;
    if (!*more) return GZ_OK;
    w->saves++;
    gz_status_t st = multi_save(out, 7, (const uint8_t *)"w", 1);
    return st == GZ_OK ? multi_add(out, GZ_ACTION_NOTIFY, (uint64_t)w->saves, NULL, 0) : st;
}
static gz_status_t waiter_handle(void *node, const gz_event_t *ev, gz_action_list_t *out)
{
    waiter_t *w = node;
    (void)out;
    if (ev->kind == GZ_EVENT_STORAGE_CONFIRMED) w->confirmed++;
    if (ev->kind == GZ_EVENT_MESSAGE_RECEIVED) w->handled_messages++;
    if (ev->kind == GZ_EVENT_USER_COMMAND) w->handled_commands++;
    return GZ_OK;
}

static sim_config_t waiter_config(void)
{
    sim_config_t c = quiet_config(71, 1);
    c.ops = (sim_node_ops_t){.create = waiter_create, .destroy = probe_destroy, .start = waiter_start, .handle = waiter_handle};
    c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 3;
    memset(&g_waiter, 0, sizeof g_waiter);
    return c;
}

static void test_a_start_that_waits_for_confirmations(void)
{
    sim_config_t c = waiter_config();
    const uint8_t hello[2] = {1, 2};
    sim_t *sim = sim_create(&c);
    CHECK(sim_node_starting(sim, 0) && g_waiter.saves == 1);
    sim_send_message(sim, SIM_WORLD_PEER, 0, hello, 2);
    sim_user_command(sim, 0, (const uint8_t *)"x", 1);
    CHECK(g_waiter.handled_commands == 0);                  /* held back while the start waits */
    CHECK(sim_run(sim, 30) == 30 && !sim_failed(sim));
    CHECK(!sim_node_starting(sim, 0) && g_waiter.saves == 3 && g_waiter.confirmed == 3);
    CHECK(g_waiter.handled_messages == 1 && g_waiter.handled_commands == 1);   /* handed on afterwards, in order */
    CHECK(trace_count(sim, "notify node=0") == 3 && trace_has(sim, "start-waiting node=0"));
    sim_destroy(sim);
}

/* While a start waits, a message and a command arrive and the node crashes.
 * The message reaches the rebuilt node once its own start finishes; the
 * command does not, and the user interface is told it was not done. */
static void test_events_held_back_across_a_crash(void)
{
    sim_config_t c = waiter_config();
    const uint8_t hello[2] = {1, 2};
    sim_t *sim = sim_create(&c);
    CHECK(sim_run(sim, 2) == 2);                            /* the message is delivered while the start waits */
    sim_send_message(sim, SIM_WORLD_PEER, 0, hello, 2);
    CHECK(sim_run(sim, 1) == 1);
    sim_user_command(sim, 0, (const uint8_t *)"x", 1);
    CHECK(sim_node_starting(sim, 0) && g_waiter.handled_messages == 0 && g_waiter.handled_commands == 0);
    sim_crash_node(sim, 0);
    CHECK(sim_run(sim, 40) == 40 && !sim_failed(sim) && !sim_node_starting(sim, 0));
    CHECK(g_waiter.handled_messages == 1 && g_waiter.handled_commands == 0);
    CHECK(sim_stats(sim)->commands_not_done == 1 && trace_has(sim, "ui node=0 command-not-done: the app restarted"));
    sim_destroy(sim);
}

/* A node that dies inside a start step is not asked for another step: it is
 * rebuilt, and the new incarnation starts from the beginning. */
static void test_a_start_stops_when_the_node_dies(void)
{
    sim_config_t c = waiter_config();
    c.confirm_delay_pm = 0;
    c.crash_in_release_pm = 1000;                           /* the first program dies at its first action */
    sim_t *sim = sim_create(&c);
    CHECK(!sim_failed(sim) && sim_node_incarnation(sim, 0) == 2 && !sim_node_starting(sim, 0));
    CHECK(g_waiter.steps_of[1] == 1 && g_waiter.steps_of[2] > 3);  /* the dead one was asked for no second step */
    sim_destroy(sim);
}

/* An armed crash belongs to the program it was armed for: if that program
 * crashes some other way first, its successor does not inherit it. */
static void test_an_armed_crash_does_not_outlive_its_program(void)
{
    sim_config_t c = probe_config(1);
    sim_t *sim = sim_create(&c);
    sim_crash_after_releases(sim, 0, 5);
    sim_crash_node(sim, 0);
    for (int i = 0; i < 10; i++) sim_user_command(sim, 0, (const uint8_t *)"N\x01", 2);
    CHECK(!sim_failed(sim) && sim_node_incarnation(sim, 0) == 2 && sim_stats(sim)->crashes_in_release == 0);
    sim_destroy(sim);
}

/* ---- storage that completes a dead program's batch during the next start ---- */

/* Ping A is durable and its confirmation is far off. Ping B is handed to
 * storage and the program dies before B is durable. B completes while the new
 * program starts, after the start has resent A. B's reply must still leave. */
static void test_a_batch_that_completes_late_is_resent(void)
{
    for (int late = 0; late <= 1; late++) {
        sim_config_t c = quiet_config(73, 1);
        c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 1000;
        c.save_delay_pm = 1000; c.max_save_delay_steps = 5;
        c.late_save_pm = late ? 1000 : 0;
        sim_t *sim = sim_create(&c);
        const sim_storage_t *st = sim_node_storage(sim, 0);
        world_ping(sim, 0, 0xa);
        CHECK(sim_run(sim, 7) == 7 && sim_storage_count(st) == 1 && sim_storage_unconfirmed(st) == 1);
        world_ping(sim, 0, 0xb);
        CHECK(sim_run(sim, 1) == 1 && sim_storage_pending(st) == 1);
        sim_crash_node(sim, 0);                             /* B was handed over and is not durable */
        CHECK(!sim_failed(sim) && sim_node_incarnation(sim, 0) == 2);
        CHECK(sim_stats(sim)->late_landings == (uint64_t)late);
        CHECK(trace_has(sim, "late-landing node=0 batch=1.2 at=1") == late);
        sim_quiesce(sim);
        CHECK(sim_run(sim, 1100) == 1100 && !sim_failed(sim));
        CHECK(saved_replies_not_sent(sim, 1) == 0);
        CHECK(sim_stats(sim)->node_sends == 1 + (uint64_t)late);       /* A resent, and B if it completed */
        sim_destroy(sim);
    }

    sim_config_t c = busy_config(75);                       /* and from the schedule */
    c.late_save_pm = 500;
    c.check_same_seed = 1;
    sim_t *sim = sim_create(&c);
    CHECK(sim_run(sim, 2000) == 2000 && sim_stats(sim)->late_landings > 0);
    sim_destroy(sim);
}

/* A batch the dead program left can complete late only until the new
 * program's storage takes its first batch: after that it is gone, so no
 * reply the start resends for it waits behind the start's own saves (found
 * by profile 7 at 20,000 seeds, where such a reply sat behind a save fated
 * never to complete). */
static void test_late_batches_stop_at_the_first_new_save(void)
{
    size_t settled = 0, landed = 0;
    for (uint64_t seed = 1; seed <= 60; seed++) {
        sim_config_t c = quiet_config(seed, 1);
        c.save_delay_pm = 1000; c.max_save_delay_steps = 6;
        c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 1000;
        c.late_save_pm = 300;
        sim_t *sim = sim_create(&c);
        for (uint8_t i = 1; i <= 6; i++) world_ping(sim, 0, i);
        sim_run(sim, 8);                                    /* durable, not confirmed: no "sent" records */
        for (uint8_t i = 7; i <= 12; i++) world_ping(sim, 0, i);
        sim_run(sim, 1);                                    /* these are still pending */
        sim_crash_node(sim, 0);
        const char *trace = sim_trace(sim, NULL);
        const char *first_save = strstr(trace, "save node=0 batch=2.");
        CHECK(first_save != NULL);
        if (first_save) CHECK(strstr(first_save, "late-landing node=0") == NULL);
        settled += trace_has(sim, "orphans-settled node=0");
        landed += sim_stats(sim)->late_landings > 0;
        sim_quiesce(sim);
        CHECK(sim_run(sim, 200) == 200 && !sim_failed(sim));
        CHECK(saved_replies_not_sent(sim, 1) == 0);
        sim_destroy(sim);
    }
    CHECK(settled > 0 && landed > 0);                       /* both happened in some runs */
}

/* ---- storage that fails inside the executor ---- */

static void test_storage_failure_inside_the_executor(void)
{
    sim_config_t c = quiet_config(77, 1);
    c.ops = multi_ops();
    c.save_fail_inline_pm = 1000;
    sim_t *sim = sim_create(&c);
    sim_user_command(sim, 0, (const uint8_t *)"a", 1);      /* the first save fails as it is handed over */
    CHECK(!sim_failed(sim) && sim_stats(sim)->inline_storage_failures >= 1);
    CHECK(sim_node_incarnation(sim, 0) == 2 && sim_storage_count(sim_node_storage(sim, 0)) == 0);
    CHECK(!trace_has(sim, "notify node=0 code=1") && sim_stats(sim)->messages_sent == 0);
    sim_destroy(sim);

    c = busy_config(79);                                    /* and from the schedule, with every check on */
    c.ops = multi_ops();
    c.save_fail_inline_pm = 30;
    c.check_same_seed = 1;
    sim = sim_create(&c);
    CHECK(sim_run(sim, 1500) == 1500 && sim_stats(sim)->inline_storage_failures > 10);
    sim_destroy(sim);
}

static int awaiting_is_bounded(const sim_t *sim, void *ctx, const char **why)
{
    uint8_t shown[16];
    (*(int *)ctx)++;
    if (sim_node_inspect(sim, 0, shown, sizeof shown) != 16) { *why = "the node shows nothing"; return 0; }
    if (shown[8] > 3) { *why = "more than three batches awaiting confirmation"; return 0; }
    return 1;
}

/* An invariant can read a node's own state through its inspection hook. */
static void test_invariants_can_look_inside_a_node(void)
{
    sim_config_t c = quiet_config(43, 1);
    c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 1000;       /* confirmations far off: batches pile up */
    sim_t *sim = sim_create(&c);
    int calls = 0;
    uint8_t shown[16], small[8];
    CHECK(sim_add_invariant(sim, awaiting_is_bounded, &calls) == 1);
    CHECK(sim_node_inspect(sim, 0, shown, sizeof shown) == 16 && shown[0] == 1 && shown[8] == 0);
    CHECK(sim_node_inspect(sim, 0, small, sizeof small) == 0);
    for (uint8_t i = 0; i < 6; i++) world_ping(sim, 0, i);
    uint64_t done = sim_run(sim, 10);
    CHECK(sim_failed(sim) && done < 10 && calls > 0);
    CHECK(strcmp(sim_failure_reason(sim), "more than three batches awaiting confirmation") == 0);
    sim_destroy(sim);

    sim = probe_sim(1);                                     /* a node with no hook shows nothing */
    CHECK(sim_node_inspect(sim, 0, shown, sizeof shown) == 0);
    sim_destroy(sim);
}

/* ---- links, reorganisations, transactions that never confirm, clock jumps ---- */

static void test_links(void)
{
    sim_t *sim = probe_sim(3);
    const uint8_t hello[2] = {1, 2};
    for (int n = 0; n < 3; n++) CHECK(g_probe[n].connected == 3 && g_probe[n].disconnected == 0);   /* two nodes and the world */

    sim_set_link(sim, 0, 1, 0);
    CHECK(g_probe[0].disconnected == 1 && g_probe[0].last_peer == 1 && g_probe[1].disconnected == 1 && g_probe[1].last_peer == 0);
    CHECK(g_probe[2].disconnected == 0 && sim_stats(sim)->link_changes == 1);
    sim_set_link(sim, 1, 0, 0);                             /* already down: nothing happens */
    CHECK(sim_stats(sim)->link_changes == 1 && g_probe[0].disconnected == 1);
    sim_send_message(sim, 0, 1, hello, 2);
    sim_send_message(sim, 0, 2, hello, 2);
    CHECK(sim_run(sim, 5) == 5);
    CHECK(g_probe[1].messages == 0 && g_probe[2].messages == 1 && sim_stats(sim)->messages_lost_to_links == 1);

    sim_set_link(sim, 0, 1, 1);
    CHECK(g_probe[0].connected == 4 && g_probe[1].connected == 4);
    sim_send_message(sim, 0, 1, hello, 2);
    CHECK(sim_run(sim, 5) == 5 && g_probe[1].messages == 1);

    sim_set_link(sim, 2, SIM_WORLD_PEER, 0);                /* the world is a peer too */
    CHECK(g_probe[2].disconnected == 1 && g_probe[2].last_peer == SIM_WORLD_PEER);
    sim_send_message(sim, SIM_WORLD_PEER, 2, hello, 2);
    CHECK(sim_run(sim, 5) == 5 && g_probe[2].messages == 1 && sim_stats(sim)->messages_lost_to_links == 2);

    /* A rebuilt node is told which links are up; its peers see the connection drop and return. */
    sim_crash_node(sim, 0);
    CHECK(g_probe[0].connected == 4 + 3);
    CHECK(g_probe[1].disconnected == 2 && g_probe[1].connected == 5 && g_probe[2].disconnected == 2 && g_probe[2].connected == 4);
    CHECK(!sim_failed(sim));
    sim_destroy(sim);

    sim_config_t c = busy_config(47);                       /* and from the schedule */
    c.link_flap_pm = 100;
    c.check_same_seed = 1;
    sim = sim_create(&c);
    CHECK(sim_run(sim, 1000) == 1000);
    CHECK(sim_stats(sim)->link_changes > 30 && sim_stats(sim)->messages_lost_to_links > 0);
    sim_destroy(sim);
}

static void test_reorganisation_and_never_confirming(void)
{
    sim_t *sim = probe_sim(2);
    const uint8_t tx[4] = {'B', 0, 7, 7};
    sim_user_command(sim, 0, tx, sizeof tx);
    sim_mine_block(sim);
    sim_mine_block(sim);
    CHECK(g_probe[0].confirmed == 2 && g_probe[0].last_confirmations == 2 && sim_chain_height(sim) == 2);

    sim_reorg(sim, 2);                                      /* both blocks gone: the transaction is unconfirmed again */
    CHECK(sim_chain_height(sim) == 0 && sim_stats(sim)->reorgs == 1);
    CHECK(g_probe[0].unconfirmed == 1 && g_probe[1].unconfirmed == 0);
    CHECK(g_probe[0].last_tip == 0 && g_probe[1].last_tip == 0 && g_probe[1].tips == 3);
    sim_mine_block(sim);                                    /* it is still in the mempool, and confirms again */
    CHECK(g_probe[0].confirmed == 3 && g_probe[0].last_confirmations == 1);
    sim_reorg(sim, 0);
    sim_reorg(sim, 99);                                     /* deeper than the chain: back to nothing */
    CHECK(sim_chain_height(sim) == 0 && sim_stats(sim)->reorgs == 2 && g_probe[0].unconfirmed == 2 && !sim_failed(sim));
    sim_destroy(sim);

    sim_config_t c = probe_config(2);
    c.tx_never_pm = 1000;
    sim = sim_create(&c);
    sim_user_command(sim, 0, tx, sizeof tx);
    for (int i = 0; i < 5; i++) sim_mine_block(sim);
    CHECK(g_probe[0].confirmed == 0 && g_probe[0].tips == 5 && sim_stats(sim)->txs_never == 1);
    CHECK(trace_has(sim, "never-confirms"));
    sim_destroy(sim);

    c = busy_config(49);                                    /* and from the schedule */
    c.ops = multi_ops();
    c.reorg_pm = 30; c.max_reorg_depth = 3; c.tx_never_pm = 200;
    c.check_same_seed = 1;
    sim = sim_create(&c);
    CHECK(sim_run(sim, 1500) == 1500 && sim_stats(sim)->reorgs > 5 && sim_stats(sim)->txs_never > 5);
    CHECK(trace_has(sim, "chain unconfirmed node="));
    sim_destroy(sim);
}

static void test_clock_jumps(void)
{
    sim_t *sim = probe_sim(1);
    const uint8_t set[3] = {'T', 1, 5};
    CHECK(sim_run(sim, 10) == 10);
    sim_user_command(sim, 0, (const uint8_t *)"L", 1);
    CHECK(g_probe[0].last_clock == 10);
    sim_jump_clock(sim, 1000);
    sim_user_command(sim, 0, (const uint8_t *)"L", 1);
    CHECK(g_probe[0].last_clock == 1010 && sim_stats(sim)->clock_jumps == 1);
    sim_user_command(sim, 0, set, 3);                       /* a timer counts steps, whatever the clock says */
    sim_jump_clock(sim, -1005);
    sim_user_command(sim, 0, (const uint8_t *)"L", 1);
    CHECK(g_probe[0].last_clock == 5);                      /* backwards */
    sim_jump_clock(sim, -500);
    sim_user_command(sim, 0, (const uint8_t *)"L", 1);
    CHECK(g_probe[0].last_clock == 0);                      /* never below zero */
    CHECK(sim_run(sim, 4) == 4 && g_probe[0].timers == 0);
    CHECK(sim_run(sim, 1) == 1 && g_probe[0].timers == 1);
    sim_destroy(sim);

    sim_config_t c = busy_config(51);                       /* and from the schedule */
    c.clock_jump_pm = 100; c.max_clock_jump = 50;
    c.check_same_seed = 1;
    sim = sim_create(&c);
    CHECK(sim_run(sim, 1000) == 1000 && sim_stats(sim)->clock_jumps > 50);
    sim_destroy(sim);
}

/* ---- what a rebuilt node may be given from before its crash ---- */

/* Two timers are due together. The node crashes carrying out its answer to
 * the first. The second was set by the dead program and must not fire into
 * the new one. */
static void test_a_dead_programs_timer_does_not_fire_into_its_successor(void)
{
    sim_t *sim = probe_sim(1);
    g_probe[0].notify_on_timer = 1;
    sim_user_command(sim, 0, (const uint8_t *)"U", 1);
    sim_crash_after_releases(sim, 0, 0);
    CHECK(sim_run(sim, 3) == 3 && !sim_failed(sim));
    CHECK(sim_node_incarnation(sim, 0) == 2 && g_probe[0].timers == 1);     /* only the first was handled */
    CHECK(trace_count(sim, "notify node=0") == 0 && sim_stats(sim)->events_not_delivered >= 1);
    CHECK(trace_has(sim, "not-delivered node=0 event=2 from-incarnation=1"));
    sim_destroy(sim);
}

/* A block brings node 0 two events: a new tip and the spend of a script it
 * watches. It crashes carrying out its answer to the first. The second
 * happened on chain whatever became of the program, so the rebuilt node gets it. */
static void test_a_chain_event_outlives_a_crash(void)
{
    sim_t *sim = probe_sim(2);
    const uint8_t watch[3] = {'W', 0x11, 0x22}, spend[5] = {'B', 2, 0x11, 0x22, 9};
    g_probe[0].notify_on_tip = 1;
    sim_user_command(sim, 0, watch, sizeof watch);
    sim_user_command(sim, 1, spend, sizeof spend);
    sim_crash_after_releases(sim, 0, 0);
    sim_mine_block(sim);
    CHECK(!sim_failed(sim) && sim_node_incarnation(sim, 0) == 2);
    CHECK(g_probe[0].tips == 1 && g_probe[0].spent == 1);
    sim_destroy(sim);
}

/* ---- the harness's own checks, each shown to catch what it is for ---- */

static void test_damaged_storage_is_caught(void)
{
    for (int drop = 0; drop <= 1; drop++) {
        sim_config_t c = quiet_config(53, 2);
        sim_t *sim = sim_create(&c);
        world_ping(sim, 0, 1);
        world_ping(sim, 1, 2);
        CHECK(sim_run(sim, 6) == 6 && !sim_failed(sim) && sim_storage_count(sim_node_storage(sim, 1)) == 2);
        sim_damage_storage(sim, 1, drop);
        CHECK(sim_failed(sim));
        CHECK(strstr(sim_failure_reason(sim), drop ? "lost or gained a durable batch" : "altered a durable batch") != NULL);
        sim_destroy(sim);
    }
}

/* FAULTY ON PURPOSE: a program with a runner of its own that it starts under
 * the same incarnation every time, breaking the duty in runner.h. A
 * confirmation from before a crash then looks current to it. */
typedef struct { gz_runner_t runner; gz_runner_slot_t slots[8]; uint8_t bytes[256]; sim_t *sim; uint32_t index; } own_runner_t;
static own_runner_t g_own[2];
static int g_own_keeps_the_duty;

static void own_execute(void *ctx, const gz_action_t *a)
{
    own_runner_t *o = ctx;
    sim_execute(o->sim, o->index, a);
}

static void *own_create(void *ctx, uint32_t index, const gz_ports_t *ports, const sim_storage_t *storage)
{
    (void)ctx; (void)ports;
    own_runner_t *o = &g_own[index];
    uint64_t incarnation = g_own_keeps_the_duty ? sim_storage_incarnation(storage) : 7;
    if (gz_runner_init(&o->runner, o->slots, 8, o->bytes, sizeof o->bytes, incarnation, own_execute, o) != GZ_OK) abort();
    return o;
}

static gz_status_t own_handle(void *node, const gz_event_t *ev, gz_action_list_t *out)
{
    (void)node;
    if (ev->kind != GZ_EVENT_USER_COMMAND) return GZ_OK;
    gz_status_t st = multi_save(out, 7, ev->u.user.bytes.data, ev->u.user.bytes.len);
    return st == GZ_OK ? multi_add(out, GZ_ACTION_NOTIFY, 9, NULL, 0) : st;
}

static gz_status_t own_release(void *ctx, sim_t *sim, uint32_t index, const gz_action_list_t *list)
{
    (void)ctx;
    g_own[index].sim = sim;
    g_own[index].index = index;
    return gz_runner_submit(&g_own[index].runner, list);
}

static gz_status_t own_confirm(void *ctx, sim_t *sim, uint32_t index, gz_batch_id_t batch)
{
    (void)ctx; (void)sim;
    return gz_runner_confirm(&g_own[index].runner, batch);
}

static void test_a_stale_confirmation_must_be_reported_stale(void)
{
    for (int keeps = 1; keeps >= 0; keeps--) {
        sim_config_t c = quiet_config(55, 1);
        c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 3;
        c.ops = (sim_node_ops_t){.create = own_create, .destroy = probe_destroy, .handle = own_handle,
                                 .release = own_release, .confirm = own_confirm};
        g_own_keeps_the_duty = keeps;
        sim_t *sim = sim_create(&c);
        sim_user_command(sim, 0, (const uint8_t *)"a", 1);      /* durable, unconfirmed; its notify is held */
        sim_crash_node(sim, 0);
        sim_user_command(sim, 0, (const uint8_t *)"b", 1);      /* the new program's own batch, same sequence */
        sim_run(sim, 10);
        if (keeps) {
            CHECK(!sim_failed(sim) && sim_stats(sim)->stale_confirmations == 1 && trace_count(sim, "notify node=0") == 1);
        } else {
            CHECK(sim_failed(sim) && strstr(sim_failure_reason(sim), "not reported as stale") != NULL);
        }
        sim_destroy(sim);
    }
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
    sim_fail_storage(sim, 0); sim_crash_after_releases(sim, 0, 0); sim_user_command(sim, 0, (const uint8_t *)"x", 1);
    CHECK(sim_stats(sim)->crashes == 0 && sim_chain_height(sim) == 0 && sim_stats(sim)->messages_sent == 0);
    CHECK(sim_stats(sim)->storage_failures == 0 && !trace_has(sim, "arm-crash") && !trace_has(sim, "user node"));
    sim_destroy(sim);

    sim = sim_create(&c);
    for (int i = 0; i < 8; i++) CHECK(sim_add_invariant(sim, fails_at_five, &calls) == 1);
    CHECK(sim_add_invariant(sim, fails_at_five, &calls) == 0);      /* at most 8 */
    CHECK(strcmp(sim_failure_reason(sim), "") == 0);
    sim_destroy(sim);
    sim_destroy(NULL);
}

/* ---- faulty programs under load ---- */

static void test_faulty_programs_are_caught_under_load(void)
{
    int eager_caught = 0, eager_multi_caught = 0;
    for (uint64_t seed = 1; seed <= 50; seed++) {
        sim_config_t c = busy_config(seed);
        c.ops.release = eager_release;
        sim_t *bad = sim_create(&c);
        sim_run(bad, 400);
        eager_caught += sim_failed(bad);
        sim_destroy(bad);

        c = busy_config(seed);
        c.ops = multi_ops();
        c.ops.release = eager_release;
        bad = sim_create(&c);
        sim_run(bad, 400);
        eager_multi_caught += sim_failed(bad);
        sim_destroy(bad);
    }
    CHECK(eager_caught == 50 && eager_multi_caught == 50);
}

int main(void)
{
    test_ping_is_stored_then_answered();
    test_reply_goes_to_the_sender();
    test_same_seed_same_trace();
    test_same_seed_invariant_holds();
    test_same_seed_invariant_catches_a_leak();
    test_drop();
    test_duplicate();
    test_delay();
    test_reorder();
    test_crash_while_a_save_is_pending();
    test_crash_between_durable_and_confirmed();
    test_every_saved_reply_is_sent_after_a_crash();
    test_storage_survives_a_crash();
    test_storage_that_never_completes();
    test_storage_failure();
    test_multi_node_plain_run();
    test_crash_inside_a_release();
    test_saved_decision_is_broadcast_after_a_crash();
    test_save_before_send_catches_a_faulty_program();
    test_observer_counts_saves_by_position();
    test_observer_checks_the_order_of_what_leaves();
    test_chain_events();
    test_a_crash_forgets_watches_and_timers();
    test_timers();
    test_random_port_across_a_crash();
    test_probe_save_notify_and_errors();
    test_long_chains_of_events();
    test_start_in_steps_through_the_runner();
    test_a_failed_start_is_fatal();
    test_restore_from_an_older_backup();
    test_secrets_are_judged_on_what_was_used();
    test_secrets_of_a_crashing_node_are_judged();
    test_which_stream_a_restore_repeats();
    test_a_start_that_waits_for_confirmations();
    test_events_held_back_across_a_crash();
    test_a_start_stops_when_the_node_dies();
    test_an_armed_crash_does_not_outlive_its_program();
    test_a_batch_that_completes_late_is_resent();
    test_late_batches_stop_at_the_first_new_save();
    test_storage_failure_inside_the_executor();
    test_a_program_that_goes_on_after_a_storage_failure();
    test_invariants_can_look_inside_a_node();
    test_links();
    test_reorganisation_and_never_confirming();
    test_clock_jumps();
    test_a_dead_programs_timer_does_not_fire_into_its_successor();
    test_a_chain_event_outlives_a_crash();
    test_damaged_storage_is_caught();
    test_a_stale_confirmation_must_be_reported_stale();
    test_invariant_hook();
    test_faulty_programs_are_caught_under_load();
    return check_done();
}
