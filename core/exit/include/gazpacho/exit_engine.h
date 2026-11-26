/* The exit engine, tree half (spec/exit.md 6.8; Slice 1.5 plan item P3).
 * Journal areas 0x0007 (Exit) and 0x0008 (Watch). One instance per factory.
 *
 * MEMBER. From the held, signed tree it publishes the member's own path,
 * root kickoff to leaf transaction, one level per block (TRUC, exit.md 4.2):
 * a step is sent only once its parent is confirmed, a step already confirmed
 * (by a sibling, or before a restart) is never sent, and each step goes with
 * its keyless anchor-only child (exit.md 5.2), rebroadcast every block until
 * confirmed (5.4). U-1 and U-2 of exit.md 7.3; signet tests S2 and S3.
 *
 * HOST (INTERIM, exit.md 3.2). It publishes the root kickoff, then sweeps by
 * the host-only timeouts every untouched subtree whose timeout has passed,
 * every confirmed leaf's channel output from H_leaf and its spare liquidity
 * after its delay, never an output with an owed member below (H15). The
 * sweep itself is built and signed outside the core, through the sweep port.
 * E-5, H-2, H-3; signet tests S1 and S4.
 *
 * It watches by outpoint only, decides on the absence of a fact only on a
 * synced view (action.h, SYNCED), classifies every confirmed spend of a
 * watched output (exit.md 8: S1, S2, S3, S8, S9a, S9b) and saves before it
 * sends (runner.h).
 *
 * THE ENGINE RULE. Nothing the chain or the sweep port does is an error: an
 * error means a bug or a corrupt journal.
 *
 * Pure core: strict C11, freestanding, no allocation, no I/O, no writable
 * data of its own; the state is the caller's gz_xe_t (large: allocate it). */
#ifndef GAZPACHO_EXIT_ENGINE_H
#define GAZPACHO_EXIT_ENGINE_H

#include "gazpacho/action.h"
#include "gazpacho/event.h"
#include "gazpacho/tree.h"

/* ---- limits ------------------------------------------------------------ */

#define GZ_XE_MAX_NODES    GZ_TREE_MAX_NODES          /* the host keeps every tree transaction */
#define GZ_XE_MAX_STEPS    (GZ_TREE_MAX_DEPTH + 2)    /* d fixed kickoffs, the leaf kickoff, the leaf */
/* A signed tree transaction: the unsigned one, the segwit marker and flag,
 * and a witness of one 64-byte item. */
#define GZ_XE_MAX_SIGNED   (GZ_TREE_MAX_TX + 2u + 1u + 1u + 64u)
#define GZ_XE_CHILD_LEN    65u                         /* the anchor-only child (exit.md 5.2) */
#define GZ_XE_MAX_SWEEP    8192u                       /* a signed sweep */
#define GZ_XE_MAX_SWEEP_IN 32u                         /* inputs of one sweep: about 6 KB signed */
#define GZ_XE_MAX_SWEEPS   16u                         /* sweeps remembered (in flight or settled) */
#define GZ_XE_FUNDING      0xffffu                     /* parent index: the funding output */
#define GZ_XE_NODE_ENC     74u                         /* bytes of one transaction in exit_plan */
/* The most bytes one call can add to an action list (the plan record of a
 * 256-member tree, with the started record), and the most actions: a save,
 * two broadcasts per step, every watch, a notice. */
#define GZ_XE_MAX_STEP_BYTES   (160u * 1024u)
#define GZ_XE_MAX_STEP_ACTIONS (4u * GZ_XE_MAX_NODES + 4u * GZ_XE_MAX_STEPS + 16u)

/* ---- records (exit.md 6.8; journal.md 9.1) ----------------------------- */

#define GZ_XE_REC_PLAN    0x00070002u
#define GZ_XE_REC_STARTED 0x00070004u
#define GZ_XE_REC_STEP    0x00070006u
#define GZ_XE_REC_ENDED   0x0007000cu
#define GZ_XE_REC_SWEEP   0x00070010u
#define GZ_XE_REC_SEEN    0x00080002u

/* Step states: local-api.md 16.3's list, counted from `pending` = 1. */
#define GZ_XE_ST_PENDING   1
#define GZ_XE_ST_WAITING   2
#define GZ_XE_ST_DUE       3
#define GZ_XE_ST_SENT      4
#define GZ_XE_ST_CONFIRMED 5
#define GZ_XE_ST_BURIED    6

/* exit_started reasons (exit.md 6.1). */
#define GZ_XE_WHY_USER         1
#define GZ_XE_WHY_DEADLINE     2
#define GZ_XE_WHY_HOST_RECOVER 3

/* ended_how. */
#define GZ_XE_END_TREE_PATH_DONE   1
#define GZ_XE_END_HOST_TIMEOUT     2
#define GZ_XE_END_UNEXPLAINED      3
#define GZ_XE_END_HOST_RECOVERED   4

/* spend_seen classes (exit.md 8). */
#define GZ_XE_S1   1
#define GZ_XE_S2   2
#define GZ_XE_S3   3
#define GZ_XE_S8   8
#define GZ_XE_S9A  9
#define GZ_XE_S9B  10

/* ---- the plan ----------------------------------------------------------- */

/* One tree transaction as the engine keeps it. */
typedef struct {
    uint8_t txid[32];          /* internal order */
    uint16_t parent;           /* plan index; GZ_XE_FUNDING for the root kickoff */
    uint8_t parent_vout, kind, depth, n_out;   /* kind: GZ_NODE_*; n_out with the anchor */
    uint16_t first, count;     /* members below it */
    uint32_t cltv;             /* host-only timeout on its input; 0 none */
    uint64_t in_amount;
    uint64_t chan_amount, spare_amount;        /* leaf transactions only */
    uint32_t spare_csv;
} gz_xe_node_t;

typedef struct {
    uint16_t node;             /* plan index */
    uint16_t len;
    uint8_t tx[GZ_XE_MAX_SIGNED];              /* signed */
    /* Derived, never saved: the anchor-only child. */
    uint8_t child[GZ_XE_CHILD_LEN];
    uint8_t child_txid[32];
} gz_xe_step_t;

typedef struct {
    int host;
    uint8_t scope[32];
    gz_outpoint_t funding;
    uint32_t end_height;       /* E */
    uint32_t member;           /* the member's position; 0 for the host */
    gz_exit_consts_t c;
    uint16_t n_nodes, n_steps;
    gz_xe_node_t node[GZ_XE_MAX_NODES];
    gz_xe_step_t step[GZ_XE_MAX_STEPS];
    uint8_t owed[GZ_TREE_MAX_MEMBERS / 8];     /* host: members owed something (H15) */
} gz_xe_plan_t;

/* The held, signed tree (exit.md 6.8, "The plan"). `sigs[i]` is node i's
 * final signature. The program verifies every signature before this call. */
typedef struct {
    uint8_t scope[32];
    const gz_tree_t *tree;
    const uint8_t (*sigs)[64];
    const uint8_t (*member_keys)[33];          /* tree order */
    uint32_t n_members;
    uint32_t end_height;
    gz_exit_consts_t c;
} gz_xe_tree_in_t;

typedef enum {
    GZ_XE_PLAN_OK = 0,
    GZ_XE_PLAN_ARGUMENT,       /* a NULL input, or a tree over the bounds */
    GZ_XE_PLAN_NOT_OURS,       /* not the member's own key, or not its own one-member leaf */
    GZ_XE_PLAN_BAD_TREE        /* the transactions do not chain, or are not TRUC with a P2A last */
} gz_xe_plan_err_t;

/* The member's plan: its own path, root first. */
gz_xe_plan_err_t gz_xe_plan_member(const gz_xe_tree_in_t *in, uint32_t member, const uint8_t own_key[33],
                                   gz_xe_plan_t *out);
/* The host's plan: every tree transaction, the root kickoff its one step.
 * `owed` is a bitmap of members owed something (member i: bit i % 8 of byte
 * i / 8), or NULL for none. */
gz_xe_plan_err_t gz_xe_plan_host(const gz_xe_tree_in_t *in, const uint8_t *owed, gz_xe_plan_t *out);

/* ---- the sweep port (host) ---------------------------------------------- */

#define GZ_XE_OUT_INPUT   1    /* a tree transaction's input: the whole subtree */
#define GZ_XE_OUT_CHANNEL 2    /* a leaf transaction's output 0 */
#define GZ_XE_OUT_SPARE   3    /* a leaf transaction's output 1 */

typedef struct {
    gz_outpoint_t outpoint;
    uint64_t amount;
    uint32_t lock;             /* the host-only timeout height; 0 none */
    uint32_t csv;              /* the relative delay, blocks (the spare); 0 none */
    uint16_t node;             /* the plan index it belongs to */
    uint8_t what;              /* GZ_XE_OUT_* */
} gz_xe_sweep_in_t;

/* Program-supplied, over the host's signer and wallet. `sweep` builds and
 * signs ONE transaction spending exactly in[0..n) in that order through
 * the host-only leaf, input i's sequence in[i].csv when it is not 0, lock
 * time `locktime`, paying the host's wallet. Returns 1 and the signed bytes,
 * or 0 (an outcome: retried at the next tip). */
typedef struct {
    int (*sweep)(void *ctx, const uint8_t scope[32], const gz_xe_sweep_in_t *in, size_t n, uint32_t locktime,
                 uint8_t *tx, size_t cap, size_t *tx_len);
    void *ctx;
} gz_xe_port_t;

/* ---- the engine's state -------------------------------------------------- */

/* What the chain view has said about one watched outpoint. Memory only. */
typedef struct {
    uint8_t watched, synced;
    uint8_t known;             /* a spender was reported */
    uint8_t recorded;          /* spend_seen saved for rec_spender */
    uint8_t spender[32];
    uint32_t conf, height;
    uint8_t rec_spender[32];
} gz_xe_fact_t;

typedef struct {
    int used;
    uint8_t txid[32];
    uint16_t len;
    uint8_t tx[GZ_XE_MAX_SWEEP];
    uint16_t n_in;
    gz_outpoint_t in[GZ_XE_MAX_SWEEP_IN];
    uint32_t last_bcast;
    int bcast_known;
    int settled;               /* every input spent by it and buried */
} gz_xe_sweep_t;

typedef struct {
    uint8_t scope[32];
    gz_xe_port_t port;
    int have_plan, started, ended;
    uint8_t reason, ended_how;
    gz_xe_plan_t plan;
    uint32_t tip;
    int tip_known, tip_synced;
    uint8_t tip_hash[32];
    size_t n_watches, n_unsynced;
    gz_xe_fact_t in[GZ_XE_MAX_NODES];          /* node i's input */
    gz_xe_fact_t chan[GZ_XE_MAX_NODES];        /* leaf transactions: output 0 */
    gz_xe_fact_t spare[GZ_XE_MAX_NODES];       /* and output 1 */
    gz_xe_fact_t anchor[GZ_XE_MAX_STEPS];      /* step i's anchor */
    struct {
        uint8_t state;                         /* journaled: 0, SENT, CONFIRMED or BURIED */
        uint8_t late;                          /* exit_step_late noted this incarnation */
        int bcast_known;
        uint32_t last_bcast;                   /* the tip it was last broadcast at */
    } st[GZ_XE_MAX_STEPS];
    gz_xe_sweep_t sweep[GZ_XE_MAX_SWEEPS];
    size_t sweep_next;                         /* load: the slot an older sweep gives up */
    uint64_t dropped;                          /* counted: reports nobody needs */
    uint64_t port_refused;                     /* counted: sweeps the port failed or got wrong */
    uint8_t scratch[GZ_XE_MAX_STEP_BYTES];     /* the records of one save */
    uint8_t work[GZ_XE_MAX_SWEEP];
} gz_xe_t;

gz_status_t gz_xe_init(gz_xe_t *x, const uint8_t scope[32], const gz_xe_port_t *port);

/* Start the exit (exit.md 6.3 steps 0 to 2, the tree half; the host's
 * recovery). Appends the save of exit_plan and exit_started and the
 * watches. *refused: 0 started; 1 already started or ended
 * (`already_exiting`); 2 the plan is for another factory. */
gz_status_t gz_xe_begin(gz_xe_t *x, const gz_xe_plan_t *plan, uint8_t reason, gz_action_list_t *out,
                        int *refused);

/* The composite's engine interface (core/node/engine.h): load, resume and
 * handle. Load takes the engine's own records for its scope and ignores
 * every other record. */
gz_status_t gz_xe_load(void *e, const gz_record_t *rec, gz_batch_id_t at);
gz_status_t gz_xe_resume(void *e, gz_action_list_t *out, int *more);
gz_status_t gz_xe_handle(void *e, const gz_event_t *ev, gz_action_list_t *out);

/* Read-only views. The step's local-api.md 16.3 state (GZ_XE_ST_*), 0 out
 * of range. Ended: 1 and *how, or 0. */
int gz_xe_step_state(const gz_xe_t *x, size_t i);
int gz_xe_has_ended(const gz_xe_t *x, uint8_t *how);

/* Transaction helpers (exposed for the tests). The anchor-only child of
 * a parent whose anchor is (txid, vout); the transaction without its
 * witness (1, or 0 if it does not parse as one transaction). */
void gz_xe_anchor_child(const uint8_t txid[32], uint32_t vout, uint8_t out[GZ_XE_CHILD_LEN]);
int gz_xe_strip_witness(const uint8_t *tx, size_t len, uint8_t *out, size_t cap, size_t *out_len,
                        int *had_witness);

#endif
