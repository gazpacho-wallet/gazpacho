/* Many seeds through the simulator.
 *
 * For each seed: a run with every invariant on, including "same seed, same
 * run" in lockstep, must not fail; every tenth seed is run a second time on
 * its own and the two traces compared byte for byte; and the same seed with a
 * deliberately faulty program (sim_nodes.h) must be caught by "nothing is
 * sent before it is saved" whenever that program saved anything. Runs of the
 * placeholder ping node then get a quiet tail, after which every reply that
 * was saved must have left its node ("saved, so eventually sent").
 *
 * Odd seeds use the placeholder ping node, even seeds the multi node.
 *
 * usage: test_sim_seeds [SEEDS [STEPS [FIRST_SEED [PROFILE]]]]   (default 1000 400 1 0)
 *
 * Profiles:
 *   0  every fault at a moderate rate, 2 to 6 nodes
 *   1  no faults at all, a ping every step
 *   2  every message duplicated, delayed and reordered, storage slow, a crash,
 *      a ping and a block every step
 *   3  every kind of fault at once, most of them most of the time
 *   4  one node, a ping every step, storage always slow
 *   5  one node, crash half the steps, duplicates and reordering
 *   6  64 nodes, delays of length zero, confirmation depth zero
 *   7  a different random configuration for every seed
 *   8  one node, instant storage, a crash every step
 *   9  crashes inside releases and storage that fails, both often
 *
 * A profile that is meant to produce a kind of activity must produce it: the
 * test fails if a count it expects (saves, sends by nodes, crashes, stale
 * confirmations, storage failures) is zero. */
#include "sim_nodes.h"
#include "../check.h"

static uint64_t g_lcg;
static uint32_t pick(uint32_t bound)
{
    g_lcg = g_lcg * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)(g_lcg >> 33) % bound;
}
static uint32_t any_pm(void) { uint32_t k = pick(4); return k == 0 ? 0 : k == 1 ? 1000 : pick(1001); }

static sim_config_t config_for(int profile, uint64_t seed)
{
    sim_config_t c;
    memset(&c, 0, sizeof c);
    c.seed = seed; c.n_nodes = 3; c.confirm_depth = 3; c.allow_refusals = 1;
    if (seed % 2 == 0) c.ops = multi_ops();
    switch (profile) {
    case 0:
        c.n_nodes = 2 + (uint32_t)(seed % 5);
        c.drop_pm = 100; c.duplicate_pm = 100; c.delay_pm = 200; c.max_delay_steps = 6; c.reorder_pm = 200;
        c.save_delay_pm = 400; c.max_save_delay_steps = 4; c.save_never_pm = 5; c.save_fail_pm = 5;
        c.confirm_delay_pm = 300; c.max_confirm_delay_steps = 3;
        c.crash_pm = 20; c.crash_in_release_pm = 10; c.ping_pm = 400; c.block_pm = 50;
        c.restore_pm = 5; c.link_flap_pm = 20; c.reorg_pm = 10; c.max_reorg_depth = 3; c.tx_never_pm = 100;
        c.clock_jump_pm = 20; c.max_clock_jump = 30;
        c.restore_repeats_random = 1; c.late_save_pm = 100; c.save_fail_inline_pm = 3;
        break;
    case 1: c.ping_pm = 1000; break;
    case 2: c.duplicate_pm = 1000; c.delay_pm = 1000; c.max_delay_steps = 50; c.reorder_pm = 1000;
            c.save_delay_pm = 1000; c.max_save_delay_steps = 20; c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 20;
            c.crash_pm = 1000; c.ping_pm = 1000; c.block_pm = 1000; break;
    case 3: c.drop_pm = 300; c.duplicate_pm = c.delay_pm = c.reorder_pm = 900; c.max_delay_steps = 9;
            c.save_delay_pm = c.confirm_delay_pm = 900; c.max_save_delay_steps = 9; c.max_confirm_delay_steps = 9;
            c.save_never_pm = 20; c.save_fail_pm = 100; c.crash_pm = 300; c.crash_in_release_pm = 200;
            c.restore_pm = 50; c.link_flap_pm = 100; c.ping_pm = 1000; c.block_pm = 900;
            c.reorg_pm = 100; c.max_reorg_depth = 4; c.tx_never_pm = 300; c.clock_jump_pm = 300; c.max_clock_jump = 100;
            break;
    case 4: c.n_nodes = 1; c.save_delay_pm = 1000; c.max_save_delay_steps = 4; c.ping_pm = 1000; break;
    case 5: c.n_nodes = 1; c.crash_pm = 500; c.save_delay_pm = 1000; c.max_save_delay_steps = 1;
            c.duplicate_pm = 500; c.reorder_pm = 500; c.ping_pm = 1000; break;
    case 6: c.n_nodes = 64; c.delay_pm = 1000; c.max_delay_steps = 0; c.save_delay_pm = 1000; c.max_save_delay_steps = 0;
            c.confirm_delay_pm = 1000; c.max_confirm_delay_steps = 0; c.confirm_depth = 0;
            c.ping_pm = 1000; c.block_pm = 1000; c.crash_pm = 300; c.reorder_pm = 1000; c.duplicate_pm = 1000; break;
    case 7:
        g_lcg = seed * 0x9E3779B97F4A7C15ull + 12345;
        c.n_nodes = 1 + pick(9);
        c.drop_pm = any_pm() / 2; c.duplicate_pm = any_pm(); c.delay_pm = any_pm(); c.max_delay_steps = pick(30);
        c.reorder_pm = any_pm(); c.save_delay_pm = any_pm(); c.max_save_delay_steps = pick(12);
        c.save_never_pm = pick(3) ? 0 : pick(30); c.save_fail_pm = pick(3) ? 0 : pick(200);
        c.confirm_delay_pm = any_pm(); c.max_confirm_delay_steps = pick(12);
        c.crash_pm = pick(3) ? pick(100) : any_pm(); c.crash_in_release_pm = pick(3) ? pick(100) : any_pm();
        c.ping_pm = 200 + pick(801); c.block_pm = any_pm(); c.confirm_depth = pick(5);
        c.restore_pm = pick(3) ? 0 : pick(100); c.restore_repeats_random = (int)pick(2);
        c.link_flap_pm = pick(3) ? 0 : pick(300); c.reorg_pm = pick(3) ? 0 : pick(300); c.max_reorg_depth = pick(6);
        c.tx_never_pm = any_pm(); c.clock_jump_pm = pick(3) ? 0 : any_pm(); c.max_clock_jump = pick(1000);
        c.late_save_pm = pick(3) ? 0 : any_pm(); c.save_fail_inline_pm = pick(3) ? 0 : pick(50);
        break;
    case 8: c.n_nodes = 1; c.crash_pm = 1000; c.ping_pm = 1000; break;
    default: c.crash_in_release_pm = 300; c.save_fail_pm = 200; c.save_delay_pm = 500; c.max_save_delay_steps = 3;
             c.confirm_delay_pm = 500; c.max_confirm_delay_steps = 3; c.ping_pm = 1000; c.duplicate_pm = 300; break;
    }
    return c;
}

/* What each profile is meant to produce. */
enum { SAVES = 1, SENDS = 2, CRASHES = 4, STALE = 8, FAILURES = 16, SECRETS = 32 };
static const int EXPECTED[10] = {
    SAVES | SENDS | CRASHES | STALE | FAILURES | SECRETS,     /* 0 */
    SAVES | SENDS | SECRETS,                        /* 1 */
    SAVES | SENDS | CRASHES | STALE,                /* 2 */
    SAVES | SENDS | CRASHES | STALE | FAILURES,     /* 3 */
    SAVES | SENDS,                                  /* 4 */
    SAVES | SENDS | CRASHES,                        /* 5 */
    SAVES | SENDS | CRASHES | STALE,                /* 6 */
    SAVES | SENDS | CRASHES | STALE | FAILURES | SECRETS,     /* 7 */
    SAVES | SENDS | CRASHES,                        /* 8 */
    SAVES | SENDS | CRASHES | STALE | FAILURES,     /* 9 */
};

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv)
{
    uint64_t seeds = argc > 1 ? strtoull(argv[1], NULL, 10) : 1000;
    uint64_t steps = argc > 2 ? strtoull(argv[2], NULL, 10) : 400;
    uint64_t first = argc > 3 ? strtoull(argv[3], NULL, 10) : 1;
    int profile = argc > 4 ? atoi(argv[4]) : 0;
    uint64_t *hashes = calloc(seeds ? seeds : 1, sizeof *hashes);
    uint64_t failed = 0, replays = 0, replay_mismatch = 0, faulty_saved = 0, faulty_caught = 0, faulty_wrongly = 0, distinct = 0;
    uint64_t tail_runs = 0, never_sent = 0, secret_draw_total = 0, secrets_judged = 0;
    sim_stats_t t;
    memset(&t, 0, sizeof t);
    if (!hashes) return 2;

    for (uint64_t i = 0; i < seeds; i++) {
        sim_config_t c = config_for(profile, first + i);
        c.check_same_seed = 1;
        sim_t *sim = sim_create(&c);
        secret_watch_t watch;
        memset(&watch, 0, sizeof watch);
        watch.n_nodes = c.n_nodes;
        if (c.ops.create && !sim_add_invariant(sim, no_secret_used_twice, &watch)) return 2;
        sim_run(sim, steps);
        if (sim_failed(sim)) {
            if (failed++ < 5)
                printf("seed %llu FAILED at step %llu: %s\n", (unsigned long long)c.seed,
                       (unsigned long long)sim_failure_step(sim), sim_failure_reason(sim));
        }
        hashes[i] = sim_trace_hash(sim);
        const sim_stats_t *s = sim_stats(sim);
        t.node_sends += s->node_sends; t.restores += s->restores; t.link_changes += s->link_changes;
        t.messages_lost_to_links += s->messages_lost_to_links; t.events_not_delivered += s->events_not_delivered;
        t.reorgs += s->reorgs; t.txs_never += s->txs_never; t.clock_jumps += s->clock_jumps;
        t.restores_repeating += s->restores_repeating; t.late_landings += s->late_landings;
        t.inline_storage_failures += s->inline_storage_failures; t.commands_not_done += s->commands_not_done;
        secret_draw_total += secret_draws(sim, c.n_nodes); secrets_judged += watch.checked;
        t.messages_sent += s->messages_sent; t.messages_dropped += s->messages_dropped;
        t.messages_duplicated += s->messages_duplicated; t.messages_delayed += s->messages_delayed;
        t.messages_delivered += s->messages_delivered; t.deliveries_reordered += s->deliveries_reordered;
        t.world_replies += s->world_replies; t.saves_durable += s->saves_durable; t.saves_lost += s->saves_lost;
        t.confirmations += s->confirmations; t.stale_confirmations += s->stale_confirmations;
        t.storage_failures += s->storage_failures; t.crashes += s->crashes; t.crashes_in_release += s->crashes_in_release;
        t.blocks += s->blocks; t.lists_refused += s->lists_refused; t.handle_errors += s->handle_errors;

        if (i % 10 == 0) {
            c.check_same_seed = 0;
            sim_t *again = sim_create(&c);
            size_t la = 0, lb = 0;
            sim_run(again, steps);
            const char *ta = sim_trace(sim, &la), *tb = sim_trace(again, &lb);
            replays++;
            if (la != lb || memcmp(ta, tb, la) != 0) replay_mismatch++;
            sim_destroy(again);
        }
        if (!c.ops.create && !sim_failed(sim)) {        /* the ping node: a quiet tail, then the check */
            sim_quiesce(sim);
            sim_run(sim, 120);
            tail_runs++;
            never_sent += saved_replies_not_sent(sim, c.n_nodes);
            failed += (uint64_t)sim_failed(sim);
        }
        sim_destroy(sim);
        secret_watch_free(&watch);

        c = config_for(profile, first + i);
        c.ops.release = eager_release;
        sim_t *bad = sim_create(&c);
        sim_run(bad, steps);
        uint64_t saved = sim_stats(bad)->saves_durable + sim_stats(bad)->saves_lost;
        for (uint32_t n = 0; n < c.n_nodes; n++) saved += sim_storage_pending(sim_node_storage(bad, n));
        faulty_saved += saved > 0;
        faulty_caught += saved > 0 && sim_failed(bad);
        faulty_wrongly += saved == 0 && sim_failed(bad);
        sim_destroy(bad);
    }

    qsort(hashes, seeds, sizeof *hashes, cmp_u64);
    for (uint64_t i = 0; i < seeds; i++) distinct += i == 0 || hashes[i] != hashes[i - 1];
    free(hashes);

#define N(x) ((unsigned long long)(x))
    printf("profile %d: seeds %llu (from %llu), %llu steps each\n", profile, N(seeds), N(first), N(steps));
    printf("  runs that failed an invariant: %llu\n", N(failed));
    printf("  distinct traces: %llu\n", N(distinct));
    printf("  separate re-runs compared byte for byte: %llu, differing: %llu\n", N(replays), N(replay_mismatch));
    printf("  faulty-program runs caught: %llu of the %llu in which it saved anything (and %llu flagged without a save)\n",
           N(faulty_caught), N(faulty_saved), N(faulty_wrongly));
    printf("  saved replies never sent after a quiet tail: %llu (over %llu ping-node runs)\n", N(never_sent), N(tail_runs));
    printf("  totals: sent %llu, dropped %llu, duplicated %llu, delayed %llu, delivered %llu, reordered %llu,\n"
           "          replies to the world %llu, saves stored %llu, saves lost %llu, confirmations %llu, stale %llu,\n"
           "          storage failures %llu, crashes %llu (inside a release %llu), blocks %llu, lists refused %llu,\n"
           "          handle errors %llu\n",
           N(t.messages_sent), N(t.messages_dropped), N(t.messages_duplicated), N(t.messages_delayed),
           N(t.messages_delivered), N(t.deliveries_reordered), N(t.world_replies), N(t.saves_durable), N(t.saves_lost),
           N(t.confirmations), N(t.stale_confirmations), N(t.storage_failures), N(t.crashes), N(t.crashes_in_release),
           N(t.blocks), N(t.lists_refused), N(t.handle_errors));

    printf("  activity: saves stored %llu, sends by nodes %llu, crashes %llu, stale confirmations %llu, storage failures %llu,\n"
           "            restores %llu, link changes %llu (messages lost to links %llu), events not delivered to a rebuilt node %llu,\n"
           "            reorganisations %llu, transactions that never confirm %llu, clock jumps %llu\n",
           N(t.saves_durable), N(t.node_sends), N(t.crashes), N(t.stale_confirmations), N(t.storage_failures),
           N(t.restores), N(t.link_changes), N(t.messages_lost_to_links), N(t.events_not_delivered),
           N(t.reorgs), N(t.txs_never), N(t.clock_jumps));
    printf("            secret draws %llu, secrets judged %llu, restores after which the port repeats %llu,\n"
           "            late completions %llu, storage failures inside the executor %llu, commands not done %llu\n",
           N(secret_draw_total), N(secrets_judged), N(t.restores_repeating), N(t.late_landings),
           N(t.inline_storage_failures), N(t.commands_not_done));
    int expected = profile >= 0 && profile < 10 ? EXPECTED[profile] : 0;
    CHECK(!(expected & SAVES) || t.saves_durable > 0);
    CHECK(!(expected & SENDS) || t.node_sends > 0);
    CHECK(!(expected & CRASHES) || t.crashes > 0);
    CHECK(!(expected & STALE) || t.stale_confirmations > 0);
    CHECK(!(expected & FAILURES) || t.storage_failures > 0);
    CHECK(!(expected & SECRETS) || (secret_draw_total > 0 && secrets_judged > 0));
    if (profile == 0) CHECK(t.restores_repeating > 0 && t.late_landings > 0 && t.inline_storage_failures > 0);
    CHECK(failed == 0);
    CHECK(never_sent == 0);
    CHECK(replay_mismatch == 0);
    CHECK(faulty_caught == faulty_saved && faulty_wrongly == 0);
    CHECK(t.handle_errors == 0);
    if (profile == 0) {
        CHECK(distinct == seeds);
        CHECK(faulty_saved == seeds);
        CHECK(t.messages_dropped && t.messages_duplicated && t.messages_delayed && t.deliveries_reordered &&
              t.crashes && t.crashes_in_release && t.saves_lost && t.world_replies && t.stale_confirmations &&
              t.storage_failures && t.confirmations && t.restores && t.link_changes && t.messages_lost_to_links &&
              t.events_not_delivered && t.reorgs && t.txs_never && t.clock_jumps);
    }
    return check_done();
}
