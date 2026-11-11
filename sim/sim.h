/* The deterministic simulator: N nodes, a pretend storage per node, a pretend
 * network and a pretend chain, in one process and one thread.
 *
 * Everything that varies in a run is drawn from generators keyed by the seed
 * (rng.h). The simulator reads no clock, no environment and no operating
 * system randomness, so the same configuration gives the same run, byte for
 * byte, on any machine: the trace is text, and every digest in it is computed
 * byte by byte in a fixed order, so neither depends on the machine's byte
 * order. The trace records every scheduling decision and a digest of every
 * record saved and every message, transaction and notification that left a
 * node. A failing run is replayed by running the same configuration again up
 * to the failing step.
 *
 * ONE STEP (sim_step) does, in this order:
 *   1. crash: with probability crash_pm, one node is destroyed and rebuilt
 *      from its storage;
 *   2. stimulus: with probability ping_pm, a ping is put on the network to a
 *      node, from another node's address or from the outside world;
 *   3. storage: pending save batches that are due become durable, and
 *      confirmations that are due are delivered;
 *   4. timers: every timer that is due fires;
 *   5. network: at most one in-flight message that is due is delivered;
 *   6. chain: with probability block_pm, a block is mined;
 *   7. the invariants are checked. If one fails the run stops.
 * Events are handled one at a time from a queue; handling one may add others.
 *
 * A NODE in the simulator is a whole program around a core: its node object,
 * its runner, its timers and its watches. Its storage stands outside it and
 * survives a crash; everything else is rebuilt, and the rebuilt node's start
 * actions go through its new runner like those of any step.
 *
 *   Across a crash: the runner gets a new incarnation, one greater than the
 *   last. The clock carries on (it is the step number). The node's random
 *   port continues from a fresh stream derived from the seed, the node and
 *   the incarnation, so no incarnation ever repeats bytes an earlier one
 *   drew. Timers and watches are forgotten. Messages already in flight to the
 *   node are delivered to the rebuilt one.
 *
 *   A crash can come at a step boundary, or inside a release: between any two
 *   actions that one submit or one confirmation hands to the executor
 *   (crash_in_release_pm, sim_crash_after_releases). The actions before the
 *   crash point were carried out; the rest never are.
 *
 *   A refused action list (GZ_ERR_REFUSED) and a storage failure both stop
 *   the node as the runner's contract requires: it is rebuilt from storage.
 *   A refusal fails the run unless allow_refusals is set.
 *
 * PRETEND STORAGE is a journal. A batch handed to it is "pending" until the
 * step the schedule chose: this step, a later one, or never. Batches become
 * durable in the order received. The confirmation of a durable batch is
 * delivered at once or some steps later (confirm_delay_pm), also in order. So
 * a crash can find a batch:
 *   - pending: it is lost;
 *   - durable but not yet confirmed: it is in storage for the rebuilt node,
 *     and its confirmation still arrives, addressed to the old incarnation.
 *     The new runner must report it stale and release nothing.
 * A batch may also fail (save_fail_pm, sim_fail_storage): it and everything
 * pending behind it are discarded, the runner is told, and the node is
 * rebuilt.
 *
 * PRETEND NETWORK. A sent message may be dropped, duplicated or delayed.
 * Delivery takes the oldest due message, or with probability reorder_pm a
 * random other due message.
 *
 * PRETEND CHAIN. Transactions are opaque bytes; nothing is validated. A
 * broadcast goes to the mempool and into the next block. By convention of
 * this pretend chain only, the first byte of a transaction is a length L and
 * the next L bytes are the script whose output it spends (L may be 0). Each
 * block produces: a new-tip event for every node; a script-spent event for
 * every node watching a script that a transaction in the block spends; and a
 * transaction-confirmed event to the node that broadcast a transaction, at
 * each block from its first confirmation to its confirm_depth-th.
 *
 * Time: the clock port returns the step number, and a timer's delay_ms is
 * counted in steps.
 *
 * INVARIANTS, checked after every step and every hand-driven occurrence:
 *   - Nothing is sent before it is saved. The harness keeps its own account,
 *     apart from the runner: the order in which each node emitted its saves
 *     and outward actions, and how many of that node's saves its storage has
 *     made durable. Saves are identified by their position in that order,
 *     never by identifier. An outward action may leave only if it is the next
 *     one emitted and every save emitted before it is durable.
 *   - Storage keeps what it stored. The harness records the identifier and a
 *     digest of every batch as it becomes durable, and compares storage
 *     against that record: nothing lost, added, reordered or altered.
 *   - A confirmation from before a crash releases nothing.
 *   - Same seed, same run (with check_same_seed).
 *   - Any added with sim_add_invariant. */
#ifndef GAZPACHO_SIM_H
#define GAZPACHO_SIM_H

#include "gazpacho/action.h"
#include "gazpacho/event.h"
#include "gazpacho/ports.h"

/* Peer identifier of the outside world: the source of pings that come from no
 * node and the destination that records replies to them. Nodes are peers
 * 0..n_nodes-1. */
#define SIM_WORLD_PEER UINT64_MAX

typedef struct sim sim_t;
typedef struct sim_storage sim_storage_t;

/* The behaviour of a simulated node. Every function must be a deterministic
 * function of its arguments and the node's own state. A zeroed structure
 * selects the default: a gz_node_t whose actions go through a gz_runner_t. */
typedef struct {
    /* Build a node from what its storage holds. Called at the start and after
     * every crash. Returns the node object, owned by the simulator until
     * `destroy`. `ports` stays valid for the node's life. */
    void *(*create)(void *ops_ctx, uint32_t index, const gz_ports_t *ports,
                    const sim_storage_t *storage);
    /* Free a node object. Called at a crash and at sim_destroy. */
    void (*destroy)(void *ops_ctx, void *node);
    /* The node's start actions, called once after `create`: same contract as
     * gz_node_start. May be NULL for a node with nothing to do at start. */
    gz_status_t (*start)(void *node, gz_action_list_t *actions_out);
    /* One step of the node: same contract as gz_node_handle. */
    gz_status_t (*handle)(void *node, const gz_event_t *event, gz_action_list_t *actions_out);
    /* How the node's program carries out a list of actions. NULL: through the
     * node's gz_runner_t, the correct way. A test supplies its own to model a
     * faulty program; it carries out an action by calling sim_execute. */
    gz_status_t (*release)(void *ops_ctx, sim_t *sim, uint32_t index,
                           const gz_action_list_t *list);
    /* Passed back as `ops_ctx`. With check_same_seed the second simulator is
     * given `twin_ctx` instead, so the two never share state: set it to a
     * separate object prepared the same way. */
    void *ctx;
    void *twin_ctx;
} sim_node_ops_t;

/* Probabilities are per mille (0..1000). */
typedef struct {
    uint64_t seed;
    uint32_t n_nodes;

    uint32_t drop_pm;             /* a sent message is lost */
    uint32_t duplicate_pm;        /* a sent message is delivered twice */
    uint32_t delay_pm;            /* a copy is held back by 1..max_delay_steps extra steps */
    uint32_t max_delay_steps;
    uint32_t reorder_pm;          /* a delivery takes a due message other than the oldest */

    uint32_t save_delay_pm;       /* a save becomes durable 1..max_save_delay_steps steps later */
    uint32_t max_save_delay_steps;
    uint32_t save_never_pm;       /* a save never completes */
    uint32_t save_fail_pm;        /* a save fails when its turn comes */
    uint32_t confirm_delay_pm;    /* a confirmation comes 1..max_confirm_delay_steps after durability */
    uint32_t max_confirm_delay_steps;

    uint32_t crash_pm;            /* per step: one node crashes */
    uint32_t crash_in_release_pm; /* per action handed to an executor: the node crashes just
                                     before it (at most once per node per step) */
    uint32_t ping_pm;             /* per step: one ping is sent to a node */
    uint32_t block_pm;            /* per step: a block is mined */
    uint32_t confirm_depth;       /* confirmations reported per transaction */

    /* 0: a list refused by a node's runner fails the run. 1: it is counted and
     * the node is rebuilt. */
    int allow_refusals;

    /* Run a second simulator with the same configuration in lockstep and check
     * after every step that both traces are identical ("same seed, same run"). */
    int check_same_seed;

    sim_node_ops_t ops;
} sim_config_t;

typedef struct {
    uint64_t messages_sent;       /* handed to the network, before faults */
    uint64_t messages_dropped;
    uint64_t messages_duplicated;
    uint64_t messages_delayed;
    uint64_t messages_delivered;  /* to nodes and to the world */
    uint64_t deliveries_reordered;
    uint64_t world_replies;       /* messages delivered to SIM_WORLD_PEER */
    uint64_t saves_durable;
    uint64_t saves_lost;          /* pending at a crash, or behind a failed batch */
    uint64_t confirmations;       /* accepted by a runner (or delivered to a faulty program) */
    uint64_t stale_confirmations; /* arrived for an incarnation that had crashed */
    uint64_t storage_failures;
    uint64_t crashes;             /* every rebuild, whatever caused it */
    uint64_t crashes_in_release;
    uint64_t blocks;
    uint64_t lists_refused;       /* action lists a node's program did not accept */
    uint64_t handle_errors;       /* events or starts a node answered with an error */
} sim_stats_t;

/* An extra invariant, checked after every step. Returns 1 if it holds, or 0
 * and points `*why` at a static description of the violation. */
typedef int (*sim_invariant_fn)(const sim_t *sim, void *ctx, const char **why);

/* Create a simulator, build its nodes and run their start actions. Returns
 * NULL if n_nodes is 0. The configuration is copied. Free with sim_destroy. */
sim_t *sim_create(const sim_config_t *config);

/* Destroy every node and free everything the simulator owns. */
void sim_destroy(sim_t *sim);

/* Add an invariant to those built in. At most 8. Returns 1 if added. */
int sim_add_invariant(sim_t *sim, sim_invariant_fn check, void *ctx);

/* Run one step. Returns 1 if every invariant held, 0 if the run has failed
 * (now or earlier). A failed simulator does nothing further. */
int sim_step(sim_t *sim);

/* Run up to `steps` steps, stopping at the first failure. Returns the number
 * of steps that completed without failure. */
uint64_t sim_run(sim_t *sim, uint64_t steps);

/* Number of steps taken so far. */
uint64_t sim_step_count(const sim_t *sim);

/* 1 if an invariant has failed. */
int sim_failed(const sim_t *sim);

/* The step at which the run failed, and why ("" if it has not). To replay:
 * same configuration and hand-driven calls, sim_run(sim, sim_failure_step(sim)). */
uint64_t sim_failure_step(const sim_t *sim);
const char *sim_failure_reason(const sim_t *sim);

/* The trace so far: one text line per occurrence, each starting with its step
 * number. Owned by the simulator, valid until the next call that changes it.
 * `*len` receives its length in bytes. */
const char *sim_trace(const sim_t *sim, size_t *len);

/* A 64-bit digest of the trace so far. */
uint64_t sim_trace_hash(const sim_t *sim);

/* Counters for the run so far. */
const sim_stats_t *sim_stats(const sim_t *sim);

/* Current height of the pretend chain. */
uint32_t sim_chain_height(const sim_t *sim);

/* How many times node `index` has been built: 1 until its first crash. This
 * is the incarnation its runner was given. */
uint64_t sim_node_incarnation(const sim_t *sim, uint32_t index);

/* --- Driving a run by hand, for tests. Each is recorded in the trace. --- */

/* Destroy node `index` and rebuild it from its storage, now. */
void sim_crash_node(sim_t *sim, uint32_t index);

/* Arm a crash inside a release: node `index` crashes just before the
 * (`after` + 1)-th action its runner next hands to the executor, counting
 * from this call. `after` = 0 crashes it before the very next action. */
void sim_crash_after_releases(sim_t *sim, uint32_t index, uint32_t after);

/* Make the storage of node `index` fail now. */
void sim_fail_storage(sim_t *sim, uint32_t index);

/* Put a message on the network from peer `from` to peer `to`, subject to the
 * configured faults. */
void sim_send_message(sim_t *sim, uint64_t from, uint64_t to, const uint8_t *bytes, size_t len);

/* Deliver a user-command event to node `index`, now. */
void sim_user_command(sim_t *sim, uint32_t index, const uint8_t *bytes, size_t len);

/* Mine a block now. */
void sim_mine_block(sim_t *sim);

/* Carry out one action for node `index` in the pretend world, exactly as the
 * node's runner would have it carried out. For `release` implementations. */
void sim_execute(sim_t *sim, uint32_t index, const gz_action_t *action);

/* --- A node's storage. --- */

/* The storage of node `index`. */
const sim_storage_t *sim_node_storage(const sim_t *sim, uint32_t index);

/* Number of durable batches, oldest first. */
size_t sim_storage_count(const sim_storage_t *storage);

/* Identifier of durable batch `i`. */
gz_batch_id_t sim_storage_batch_id(const sim_storage_t *storage, size_t i);

/* Durable batch `i` as stored: for each record, a 4-byte little-endian type, a
 * 4-byte little-endian length, then the bytes. `*len` receives the total. */
const uint8_t *sim_storage_batch_bytes(const sim_storage_t *storage, size_t i, size_t *len);

/* Number of batches handed over and not yet durable. */
size_t sim_storage_pending(const sim_storage_t *storage);

/* Number of durable batches whose confirmation has not been delivered yet. */
size_t sim_storage_unconfirmed(const sim_storage_t *storage);

#endif
