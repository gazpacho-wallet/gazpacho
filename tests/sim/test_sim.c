/* Tests for the simulator (sim/sim.c): determinism, each network fault, crash
 * and rebuild at step boundaries and inside a release, storage that is slow,
 * confirmed late, failing or never finishing, the pretend chain and timers,
 * and each invariant shown to catch a deliberately faulty program defined
 * here or in sim_nodes.h. */
#include "sim_nodes.h"
#include "gazpacho/node.h"
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
        c.ops = (sim_node_ops_t){leaky_create, leaky_destroy, NULL, handlers[k], NULL, NULL, NULL};
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
    CHECK(trace_has(sim, "crash node=0 lost-saves=1 held-actions=1"));
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
    uint32_t tips, last_tip, spent, confirmed, last_confirmations, timers, stored, messages, chain_left;
    uint64_t last_sender;
    uint8_t spent_txid[32], confirmed_txid[32];
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
        p->ports->random.fill(p->ports->random.ctx, drawn, sizeof drawn);
        return multi_save(out, 8, drawn, sizeof drawn);
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
    case GZ_EVENT_TIMER_FIRED:       p->timers++; break;
    case GZ_EVENT_STORAGE_CONFIRMED:
        p->stored++;
        if (p->chain_left && p->chain_left--) return multi_save(out, 9, NULL, 0);
        break;
    case GZ_EVENT_MESSAGE_RECEIVED:  p->messages++; p->last_sender = ev->u.message.peer_id; break;
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

static sim_config_t probe_config(uint32_t n_nodes)
{
    sim_config_t c = quiet_config(21, n_nodes);
    c.ops = (sim_node_ops_t){probe_create, probe_destroy, NULL, probe_handle, NULL, NULL, NULL};
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
    test_invariant_hook();
    test_faulty_programs_are_caught_under_load();
    return check_done();
}
