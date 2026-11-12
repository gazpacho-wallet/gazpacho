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
 *   1. faults chosen by the schedule: a crash, a restore from an older
 *      backup, a link going down or up, a clock jump;
 *   2. stimulus: with probability ping_pm, a ping is put on the network to a
 *      node, from another node's address or from the outside world;
 *   3. storage: pending save batches that are due become durable, and
 *      confirmations that are due are delivered;
 *   4. timers: every timer that is due fires;
 *   5. network: at most one in-flight message that is due is delivered;
 *   6. chain: with probability reorg_pm the chain is reorganised; with
 *      probability block_pm a block is mined;
 *   7. the invariants are checked. If one fails the run stops.
 * Events are handled one at a time from a queue; handling one may add others.
 *
 * A NODE in the simulator is a whole program around a core: its node object,
 * its runner, its timers and its watches. Its storage stands outside it and
 * survives a crash; everything else is rebuilt, and the rebuilt node's start
 * steps go through its new runner like any other step.
 *
 *   Across a crash: the runner gets a new incarnation, one greater than the
 *   last. Timers and watches are forgotten. The node's random port continues
 *   from a fresh stream derived from the seed, the node and the incarnation,
 *   so no incarnation repeats bytes an earlier one drew (but see "restore").
 *
 *   An event already queued for a node when it crashes reaches the rebuilt
 *   node only if it is of a kind that outlives a program by nature: a message
 *   from a peer, or something that happened on chain. A timer the dead
 *   program set, a confirmation of a batch it saved, a command it was given
 *   and news of its connections are not delivered to its successor. Messages
 *   in flight to the node are delivered to the rebuilt one.
 *
 *   A crash can come at a step boundary, or inside a release: between any two
 *   actions that one submit or one confirmation hands to the executor
 *   (crash_in_release_pm, sim_crash_after_releases). The actions before the
 *   crash point were carried out; the rest never are.
 *
 *   A refused action list (GZ_ERR_REFUSED) and a storage failure both stop
 *   the node as the runner's contract requires: it is rebuilt from storage.
 *   A refusal fails the run unless allow_refusals is set. A node whose start
 *   returns an error, or whose start list is refused, fails the run.
 *
 *   A start may take several steps, and may wait (GZ_WAITING) for one of the
 *   node's batches to be confirmed. While it starts, a node is given only the
 *   storage confirmations its runner accepts; every other event for it is
 *   held back, in order, and handed on once the start has finished.
 *
 *   A user command that does not reach a node because the program stopped
 *   before handling it is not dropped silently: the user interface is told
 *   that it was not done because the app restarted (in the trace, and in
 *   commands_not_done).
 *
 *   Late completion (late_save_pm): a batch the dead program had handed to
 *   storage and that was still pending may complete during the next start,
 *   between two start steps, until the new program hands its storage a
 *   batch. It takes its place in the journal before every batch of the new
 *   incarnation. Whatever is still pending when the new program's first
 *   batch reaches storage, or when the start finishes, is gone for good, as
 *   ports.h requires.
 *
 *   Invariants added with sim_add_invariant are also checked just before a
 *   node is destroyed, so they can see its last state.
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
 * rebuilt. With save_fail_inline_pm storage fails as a save is handed over,
 * and tells the runner from inside the executor; from then on the harness
 * treats any action carried out for that program as a violation.
 *
 * RESTORE FROM AN OLDER BACKUP (restore_pm, sim_restore_backup). A node's
 * storage is rolled back to an earlier durable point: the newer batches are
 * gone, what was pending is lost (it cannot complete into the restored copy),
 * and no confirmation from before the restore arrives afterwards. The
 * node is rebuilt under a new, greater incarnation, as the runner's duty
 * requires. By default its random port then gives a fresh stream, like after
 * any crash. With restore_repeats_random the port instead repeats the stream
 * of the incarnation that wrote the newest batch the backup kept: this is the
 * machine restored from a snapshot, generator state and all. A node that
 * trusts the port alone for a one-time secret will then produce a secret it
 * has produced before, and an invariant over the draw log can catch it.
 *
 * THE RESTORE MARKER (ports.h). After a restore the harness, as the program,
 * gives every start of the node the marker (sim_storage_restored, and the
 * default node's reader) until a batch with sequence 1 of an incarnation
 * started with it is durable: then the restore is answered
 * (restores_answered). A crash before that keeps the marker for the next
 * start. A node with a start hook that is given the marker must make a save
 * its first action (an invariant).
 *
 * PRETEND NETWORK. A sent message may be dropped, duplicated or delayed.
 * Delivery takes the oldest due message, or with probability reorder_pm a
 * random other due message. Every pair of peers (nodes, and each node with
 * the outside world) has a link, up at the start. A link can go down and up
 * (link_flap_pm, sim_set_link): the nodes at its ends are told with peer
 * events, and a message due while its link is down is lost. A node is told
 * of every link that is up when it is built, and its peers are told that the
 * connection dropped and came back when it is rebuilt.
 *
 * PRETEND CHAIN. Transactions are opaque bytes; almost nothing is validated.
 * A broadcast goes to the mempool and into the next block, unless the
 * schedule decides it never confirms (tx_never_pm). By convention of this
 * pretend chain only, the first byte of a transaction is a length L and the
 * next L bytes are the script whose output it spends (L may be 0). If the
 * byte after them is 0xF0, the next byte is a count n and n outpoints follow
 * (32-byte txid, 4-byte vout low byte first): the outpoints it spends
 * (sim_pretend_tx builds one). A transaction's identifier is a digest of its
 * bytes (sim_pretend_txid). A broadcast that spends an outpoint some known
 * transaction already spends is a conflict and is dropped, as a mempool
 * without replacement would. Broadcasting watches nothing.
 *
 * Watches (action.h, WATCHES) are kept per node, forgotten when it is
 * rebuilt, and answered as action.h says: script spends at each block;
 * transaction confirmations up to the watch's depth, and their leaving the
 * chain; outpoint spends, when the spender appears in the mempool or a block
 * and at each confirmation up to the depth. Each block also gives every node
 * a new-tip event. A reorganisation (reorg_pm, sim_reorg) removes the newest
 * blocks: their transactions go back to the mempool, watchers are told as
 * action.h says, and every node gets a new-tip event with the lower height.
 *
 * TIME. The clock port returns the step number plus an offset that the
 * schedule may move forwards or backwards (clock_jump_pm, sim_jump_clock). A
 * timer's delay_ms is counted in steps and is not affected by clock jumps.
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
 *   - A confirmation from before a crash is reported stale by the program's
 *     runner and releases nothing.
 *   - Secrets never leave. No action a node's program carries out (a save's
 *     records, a send, broadcast, notify or watch) holds the bytes of one of
 *     that node's secret-tagged draws of 8 bytes or more, anywhere in it
 *     (ports.h). What is derived from such bytes is not seen by this check.
 *   - A node started with the restore marker saves before it does anything
 *     else.
 *   - Same seed, same run (with check_same_seed).
 *   - Any added with sim_add_invariant. Those can look inside: at each node's
 *     own state through its inspection hook (sim_node_inspect), and at every
 *     draw each node has made from its random port (sim_node_draw). */
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
    /* One step of the node's start, called after `create` and again while it
     * sets `*more`: same contract as gz_node_start. May be NULL for a node
     * with nothing to do at start. An error fails the run. */
    gz_status_t (*start)(void *node, gz_action_list_t *actions_out, int *more);
    /* One step of the node: same contract as gz_node_handle. */
    gz_status_t (*handle)(void *node, const gz_event_t *event, gz_action_list_t *actions_out);
    /* Write a description of the node's state, for invariants, into
     * `out[0..cap)` and return its length. What it contains is the node's
     * own business. May be NULL: the node then shows nothing. */
    size_t (*inspect)(const void *node, uint8_t *out, size_t cap);
    /* How the node's program carries out a list of actions. NULL: through the
     * node's gz_runner_t, the correct way. A test supplies its own to model a
     * faulty program; it carries out an action by calling sim_execute. */
    gz_status_t (*release)(void *ops_ctx, sim_t *sim, uint32_t index,
                           const gz_action_list_t *list);
    /* With `release` set: how that program answers a storage confirmation,
     * returning what its runner returned. NULL: it has no runner to ask, and
     * the harness only keeps confirmations of dead incarnations away from the
     * node. */
    gz_status_t (*confirm)(void *ops_ctx, sim_t *sim, uint32_t index, gz_batch_id_t batch);
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
    uint32_t link_flap_pm;        /* per step: one link changes between up and down */

    uint32_t save_delay_pm;       /* a save becomes durable 1..max_save_delay_steps steps later */
    uint32_t max_save_delay_steps;
    uint32_t save_never_pm;       /* a save never completes */
    uint32_t save_fail_pm;        /* a save fails when its turn comes */
    uint32_t save_fail_inline_pm; /* a save fails as it is handed over, and storage reports it from
                                     inside the executor; a program must then carry out nothing more */
    uint32_t late_save_pm;        /* per start step: a batch the previous program left pending
                                     completes now, late (see "late completion" above) */
    uint32_t confirm_delay_pm;    /* a confirmation comes 1..max_confirm_delay_steps after durability */
    uint32_t max_confirm_delay_steps;

    uint32_t crash_pm;            /* per step: one node crashes */
    uint32_t crash_in_release_pm; /* per action handed to an executor: the node crashes just
                                     before it (at most once per node per step) */
    uint32_t restore_pm;          /* per step: one node's storage is rolled back to a random
                                     earlier durable point and the node rebuilt */
    int restore_repeats_random;   /* 1: after a restore the node's random port repeats (see above) */

    uint32_t ping_pm;             /* per step: one ping is sent to a node */
    uint32_t block_pm;            /* per step: a block is mined */
    uint32_t reorg_pm;            /* per step: the newest 1..max_reorg_depth blocks are removed */
    uint32_t max_reorg_depth;
    uint32_t tx_never_pm;         /* a broadcast transaction never confirms */

    uint32_t clock_jump_pm;       /* per step: the clock jumps 1..max_clock_jump either way */
    uint32_t max_clock_jump;

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
    uint64_t node_sends;          /* of those, sent by a node's program (the rest are stimulus) */
    uint64_t messages_dropped;
    uint64_t messages_duplicated;
    uint64_t messages_delayed;
    uint64_t messages_delivered;  /* to nodes and to the world */
    uint64_t messages_lost_to_links; /* due while their link was down */
    uint64_t deliveries_reordered;
    uint64_t world_replies;       /* messages delivered to SIM_WORLD_PEER */
    uint64_t saves_durable;
    uint64_t saves_lost;          /* pending at a crash, or behind a failed batch */
    uint64_t confirmations;       /* accepted by a runner (or delivered to a faulty program) */
    uint64_t stale_confirmations; /* arrived for an incarnation that had crashed */
    uint64_t storage_failures;
    uint64_t inline_storage_failures; /* of those, reported from inside the executor */
    uint64_t late_landings;       /* batches of a dead program that completed during the next start */
    uint64_t commands_not_done;   /* user commands not delivered because the app restarted */
    uint64_t restores_repeating;  /* restores after which the random port repeats */
    uint64_t crashes;             /* every rebuild, whatever caused it */
    uint64_t crashes_in_release;
    uint64_t restores;
    uint64_t events_not_delivered; /* queued for an incarnation that had crashed, of a kind
                                      that does not outlive it */
    uint64_t link_changes;
    uint64_t blocks;
    uint64_t reorgs;
    uint64_t txs_never;           /* broadcasts fated never to confirm */
    uint64_t txs_conflicting;     /* broadcasts dropped: they spend an outpoint already spent */
    uint64_t chain_reports;       /* chain events answering a watch */
    uint64_t restores_answered;   /* restores whose restore batch became durable */
    uint64_t secret_leaks;        /* actions caught holding a secret-tagged draw */
    uint64_t clock_jumps;
    uint64_t lists_refused;       /* action lists a node's program did not accept */
    uint64_t handle_errors;       /* events or starts a node answered with an error */
} sim_stats_t;

/* One draw a node made from its random port. */
typedef struct {
    gz_random_purpose_t purpose;   /* the tag the node gave (ports.h) */
    uint64_t incarnation;   /* which build of the node drew it */
    size_t len;             /* how many bytes it asked for */
    uint8_t bytes[32];      /* the first min(len, 32) of them */
} sim_draw_t;

/* An extra invariant, checked after every step. Returns 1 if it holds, or 0
 * and points `*why` at a static description of the violation. */
typedef int (*sim_invariant_fn)(const sim_t *sim, void *ctx, const char **why);

/* Create a simulator, build its nodes and run their start steps. Returns NULL
 * if n_nodes is 0. The configuration is copied. Free with sim_destroy. */
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

/* 1 while node `index` has not finished its start. */
int sim_node_starting(const sim_t *sim, uint32_t index);

/* --- Looking inside, for invariants and tests. --- */

/* What node `index` shows of its own state: its inspection hook's output,
 * copied into `out[0..cap)`. Returns the length, 0 if the node has no hook. */
size_t sim_node_inspect(const sim_t *sim, uint32_t index, uint8_t *out, size_t cap);

/* Number of draws node `index` has made from its random port, over all its
 * incarnations, and the `i`-th of them (oldest first). */
size_t sim_node_draw_count(const sim_t *sim, uint32_t index);
const sim_draw_t *sim_node_draw(const sim_t *sim, uint32_t index, size_t i);

/* --- Driving a run by hand, for tests. Each is recorded in the trace. --- */

/* Destroy node `index` and rebuild it from its storage, now. */
void sim_crash_node(sim_t *sim, uint32_t index);

/* Arm a crash inside a release: node `index` crashes just before the
 * (`after` + 1)-th action its runner next hands to the executor, counting
 * from this call. `after` = 0 crashes it before the very next action. */
void sim_crash_after_releases(sim_t *sim, uint32_t index, uint32_t after);

/* Make the storage of node `index` fail now. */
void sim_fail_storage(sim_t *sim, uint32_t index);

/* Roll the storage of node `index` back to its oldest `keep` durable batches
 * and rebuild the node: a restore from an older backup. */
void sim_restore_backup(sim_t *sim, uint32_t index, size_t keep);

/* FOR TESTS OF THE HARNESS ITSELF: damage the storage of node `index` behind
 * the harness's back, which the "storage keeps what it stored" invariant must
 * then catch. `drop` 0 alters one byte of the newest durable batch that has
 * any; `drop` 1 removes the newest durable batch. */
void sim_damage_storage(sim_t *sim, uint32_t index, int drop);

/* Take the link between two peers down (`up` 0) or bring it up. Peers are
 * node indexes or SIM_WORLD_PEER. */
void sim_set_link(sim_t *sim, uint64_t a, uint64_t b, int up);

/* Put a transaction on the pretend chain from outside every node (the world
 * broadcasts it). */
void sim_broadcast(sim_t *sim, const uint8_t *tx, size_t len);

/* The pretend chain's identifier of transaction `tx`. */
void sim_pretend_txid(const uint8_t *tx, size_t len, uint8_t txid[32]);

/* Build in `out[0..cap)` a pretend transaction spending the `n` outpoints
 * given (at most 255) and no watched script, followed by `tag` (any bytes,
 * to make it distinct). Returns its length, 0 if it does not fit. */
size_t sim_pretend_tx(uint8_t *out, size_t cap, const gz_outpoint_t *inputs, size_t n,
                      const uint8_t *tag, size_t tag_len);

/* Remove the newest `depth` blocks from the chain. */
void sim_reorg(sim_t *sim, uint32_t depth);

/* Move the clock by `delta` (either sign). It never goes below 0. */
void sim_jump_clock(sim_t *sim, int64_t delta);

/* From now on: no scheduled crashes, restores, link changes, clock jumps,
 * pings, blocks or reorganisations, no dropped or duplicated messages, and no
 * save that fails or never completes. Messages in flight are discarded, so
 * nothing new reaches a node from before. Delays stay, and what storage
 * already holds or has pending is unchanged (a save already fated never to
 * complete still never does). Running some steps after this gives a run a
 * quiet tail, in which everything that can settle does. */
void sim_quiesce(sim_t *sim);

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

/* The incarnation of the node now reading this storage: what a storage reader
 * built over it reports (ports.h). */
uint64_t sim_storage_incarnation(const sim_storage_t *storage);

/* The restore marker a reader built over this storage gives (ports.h). */
int sim_storage_restored(const sim_storage_t *storage);

#endif
