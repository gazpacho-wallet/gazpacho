/* One fixed configuration must give one known trace.
 *
 * The lockstep check compares two simulators inside one process. This test
 * compares across processes, build configurations and machines: the digest of
 * the trace for a fixed seed is written down here, and every build, with or
 * without the memory checkers, must reproduce it.
 *
 * When the simulator or a node is changed on purpose the digests change. Run
 * the program with any argument to print the new ones, check the change was
 * intended, and update the constants. */
#include "sim_nodes.h"
#include "../check.h"

#define KNOWN_PING_NODE  0x406994eb3e3df8f3ull
#define KNOWN_MULTI_NODE 0x2119f18990b4a27full

static uint64_t run(int multi)
{
    sim_config_t c;
    memset(&c, 0, sizeof c);
    c.seed = 20261111; c.n_nodes = 5; c.allow_refusals = 1;
    c.drop_pm = 100; c.duplicate_pm = 100; c.delay_pm = 200; c.max_delay_steps = 6; c.reorder_pm = 200;
    c.save_delay_pm = 400; c.max_save_delay_steps = 4; c.save_never_pm = 5; c.save_fail_pm = 5;
    c.confirm_delay_pm = 300; c.max_confirm_delay_steps = 3;
    c.crash_pm = 20; c.crash_in_release_pm = 10; c.ping_pm = 400; c.block_pm = 50;
    c.restore_pm = 5; c.link_flap_pm = 20; c.reorg_pm = 10; c.max_reorg_depth = 3; c.tx_never_pm = 100;
    c.clock_jump_pm = 20; c.max_clock_jump = 30;
    if (multi) c.ops = multi_ops();
    sim_t *sim = sim_create(&c);
    CHECK(sim_run(sim, 1000) == 1000);
    uint64_t hash = sim_trace_hash(sim);
    sim_destroy(sim);
    return hash;
}

int main(int argc, char **argv)
{
    (void)argv;
    uint64_t ping = run(0), multi = run(1);
    if (argc > 1) {
        printf("#define KNOWN_PING_NODE  0x%016llxull\n#define KNOWN_MULTI_NODE 0x%016llxull\n",
               (unsigned long long)ping, (unsigned long long)multi);
        return 0;
    }
    CHECK(ping == KNOWN_PING_NODE);
    CHECK(multi == KNOWN_MULTI_NODE);
    return check_done();
}
