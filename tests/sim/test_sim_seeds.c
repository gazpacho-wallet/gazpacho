/* Many seeds through the simulator with every fault switched on.
 *
 * For each seed: a run with both invariants on must not fail; every tenth
 * seed is run a second time on its own and the two traces compared byte for
 * byte; and the same seed with a deliberately faulty node (defined here) must
 * be caught by "nothing is sent before it is saved".
 *
 * usage: test_sim_seeds [SEEDS [STEPS [FIRST_SEED]]]   (default 1000 400 1) */
#include "sim.h"
#include "../check.h"
#include <stdlib.h>
#include <string.h>

static sim_config_t config_for(uint64_t seed)
{
    sim_config_t c;
    memset(&c, 0, sizeof c);
    c.seed = seed;
    c.n_nodes = 2 + (uint32_t)(seed % 5);
    c.drop_pm = 100; c.duplicate_pm = 100; c.delay_pm = 200; c.max_delay_steps = 6; c.reorder_pm = 200;
    c.save_delay_pm = 400; c.max_save_delay_steps = 4; c.save_never_pm = 5;
    c.crash_pm = 20; c.ping_pm = 400; c.block_pm = 50;
    c.confirm_depth = 3;
    return c;
}

/* FAULTY ON PURPOSE: carries out every action at once, without the runner. */
static gz_status_t eager_release(void *ctx, sim_t *sim, uint32_t index, const gz_action_list_t *list)
{
    (void)ctx;
    for (size_t i = 0; i < list->count; i++) sim_execute(sim, index, &list->slots[i]);
    return GZ_OK;
}

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
    uint64_t *hashes = calloc(seeds ? seeds : 1, sizeof *hashes);
    uint64_t failed = 0, replays = 0, replay_mismatch = 0, faulty_caught = 0, distinct = 0;
    sim_stats_t total;
    memset(&total, 0, sizeof total);
    if (!hashes) return 2;

    for (uint64_t i = 0; i < seeds; i++) {
        sim_config_t c = config_for(first + i);
        c.check_same_seed = 1;
        sim_t *sim = sim_create(&c);
        sim_run(sim, steps);
        if (sim_failed(sim)) {
            failed++;
            printf("seed %llu FAILED at step %llu: %s\n", (unsigned long long)c.seed,
                   (unsigned long long)sim_failure_step(sim), sim_failure_reason(sim));
        }
        hashes[i] = sim_trace_hash(sim);
        const sim_stats_t *s = sim_stats(sim);
        total.messages_sent += s->messages_sent; total.messages_dropped += s->messages_dropped;
        total.messages_duplicated += s->messages_duplicated; total.messages_delayed += s->messages_delayed;
        total.messages_delivered += s->messages_delivered; total.deliveries_reordered += s->deliveries_reordered;
        total.world_replies += s->world_replies; total.saves_durable += s->saves_durable;
        total.saves_lost += s->saves_lost; total.crashes += s->crashes; total.blocks += s->blocks;
        total.lists_refused += s->lists_refused; total.handle_errors += s->handle_errors;

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
        sim_destroy(sim);

        c = config_for(first + i);
        c.ops.release = eager_release;
        sim_t *bad = sim_create(&c);
        sim_run(bad, steps);
        faulty_caught += (uint64_t)sim_failed(bad);
        sim_destroy(bad);
    }

    qsort(hashes, seeds, sizeof *hashes, cmp_u64);
    for (uint64_t i = 0; i < seeds; i++) distinct += i == 0 || hashes[i] != hashes[i - 1];
    free(hashes);

    printf("seeds %llu (from %llu), %llu steps each\n", (unsigned long long)seeds,
           (unsigned long long)first, (unsigned long long)steps);
    printf("  runs that failed an invariant: %llu\n", (unsigned long long)failed);
    printf("  distinct traces: %llu\n", (unsigned long long)distinct);
    printf("  separate re-runs compared byte for byte: %llu, differing: %llu\n",
           (unsigned long long)replays, (unsigned long long)replay_mismatch);
    printf("  faulty-node runs caught: %llu of %llu\n", (unsigned long long)faulty_caught, (unsigned long long)seeds);
    printf("  totals: sent %llu, dropped %llu, duplicated %llu, delayed %llu, delivered %llu, reordered %llu,\n"
           "          replies to the world %llu, saves stored %llu, saves lost in crashes %llu, crashes %llu,\n"
           "          blocks %llu, lists refused %llu, handle errors %llu\n",
           (unsigned long long)total.messages_sent, (unsigned long long)total.messages_dropped,
           (unsigned long long)total.messages_duplicated, (unsigned long long)total.messages_delayed,
           (unsigned long long)total.messages_delivered, (unsigned long long)total.deliveries_reordered,
           (unsigned long long)total.world_replies, (unsigned long long)total.saves_durable,
           (unsigned long long)total.saves_lost, (unsigned long long)total.crashes,
           (unsigned long long)total.blocks, (unsigned long long)total.lists_refused,
           (unsigned long long)total.handle_errors);

    CHECK(failed == 0);
    CHECK(distinct == seeds);
    CHECK(replay_mismatch == 0);
    CHECK(faulty_caught == seeds);
    CHECK(total.messages_dropped && total.messages_duplicated && total.messages_delayed &&
          total.deliveries_reordered && total.crashes && total.saves_lost && total.world_replies);
    return check_done();
}
