/* The funding engine (docs/notes/composite-node.md 9, 12.1, 14; step P4.5).
 * Journal area 0x0003. One instance per node, node-wide, both roles.
 *
 * HOST. It makes the funding plan of every attempt through the wallet port
 * (14.1), runs H1 before the lobby saves Funding (14.2), signs and
 * broadcasts in AUTO, waits for the person in CONFIRM (12.1), watches the
 * funding to its burial, and abandons a funding not buried by the host's
 * funding deadline with the spend-back at the smallest fee that replaces it
 * (14.3; H16's one exception). It is the only engine that broadcasts.
 *
 * MEMBER. From the ack (the round's Complete outcome) it watches the funding
 * txid to the burial depth and the funding's first inputs, and decides C11
 * (live, abandoned, late live) and C4(d) (dead) from chain facts alone
 * (core/tree's gz_tree_c11 and gz_tree_c4d_dead). `factory_funded` is never
 * acted on.
 *
 * WHAT IT TELLS THE OTHERS. Chain-driven ends come out through one hook,
 * `report`, called from inside the engine's own step after its own save and
 * before its own outward actions, so the composite can bracket the other
 * engines' records with it (composite-node.md 7.4, brackets Live and Dead or
 * abandoned). The hook never re-enters the funding engine.
 *
 * THE ENGINE RULE. Nothing a peer, the chain, the wallet port or a user can
 * do is an error: wallet failures are outcomes (cancel reason 3) with an
 * attention notice, refused commands are command results. An error means a
 * bug or a corrupt journal.
 *
 * Pure core: strict C11, freestanding, no allocation, no I/O, no writable
 * data of its own; the state is the caller's gz_fund_t. */
#ifndef GAZPACHO_FUNDING_H
#define GAZPACHO_FUNDING_H

#include "gazpacho/command.h"
#include "gazpacho/envelope.h"
#include "gazpacho/node.h"
#include "gazpacho/tree.h"

/* ---- limits ------------------------------------------------------------ */

/* The funding transaction without witnesses: what round_propose record 18
 * carries and what the signing engine holds (GZ_SIGN_MAX_FUNDING_TX). A plan
 * the wallet returns larger than this is refused (outcome Failed, reason 3),
 * so the host's own proposal is never refused for its size
 * (notes/p4-3-signing-changes.md, item 13). */
#define GZ_FUND_MAX_TX       8192u
/* Inputs: 197 key-path inputs (41 bytes each without witnesses) and two
 * P2TR outputs fill 8,177 bytes. */
#define GZ_FUND_MAX_INPUTS   197u
/* The signed funding: 8,192 bytes, the segwit marker and every input's
 * witness (a count, a length and a 65-byte signature at most). */
#define GZ_FUND_MAX_SIGNED   (GZ_FUND_MAX_TX + 2u + 67u * GZ_FUND_MAX_INPUTS)
/* The spend-back: one input, one output. */
#define GZ_FUND_MAX_SPEND_BACK 512u
/* A spent output's script: a witness program, 4 to 42 bytes. */
#define GZ_FUND_MAX_SCRIPT   42u

/* Factories followed at once (plans, signed fundings, acked creations). */
#define GZ_FUND_MAX_FACTORIES 16u
/* Ended factories remembered for the slot end conditions (2.4). */
#define GZ_FUND_MAX_ENDED    64u
/* Inputs of the funding a member watches for C4(d): the first ones. The
 * host's spend-back and H11's reused input are always input 0 when it can
 * pay, so a member sees both; a funding input past these spent elsewhere
 * leaves the creation Abandoned rather than Dead, which blocks nothing (C10). */
#define GZ_FUND_WATCH_INPUTS 2u
/* THE WATCH BUDGET (composite-node.md 7.2, task T-P45-1): distinct watches
 * the engine holds at once. A host factory holds 2 (the funding txid and its
 * input 0, which also shows the spend-back), a member factory at most
 * 1 + GZ_FUND_WATCH_INPUTS. The engine keeps its own count and gives back a
 * watch it no longer needs with an UNWATCH action (action.h). */
#define GZ_FUND_MAX_WATCHES  (GZ_FUND_MAX_FACTORIES * (1u + GZ_FUND_WATCH_INPUTS))
_Static_assert(GZ_FUND_MAX_WATCHES <= GZ_NODE_FUNDING_WATCHES, "the funding engine's watches fit its budget in the registry (T-P45-1)");

/* Its one timer (7.1): the tick, low 32 bits of the id. */
#define GZ_FUND_TIMER_TICK   0x46540001u
#define GZ_FUND_MAX_TIMERS   1u

/* Its worst step (8.3): a save, a broadcast, its watches, a notice, the
 * tick; the save holds at most a status with the funding transaction, or
 * the signed funding and its status. */
#define GZ_FUND_MAX_STEP_ACTIONS 12u
#define GZ_FUND_MAX_STEP_BYTES   (2u * GZ_FUND_MAX_SIGNED + 16u * 1024u)

/* ---- records (journal.md 9, Funding area) ------------------------------ */

#define GZ_FUND_REC_PLAN    0x00030002u   /* funding_plan, host */
#define GZ_FUND_REC_SIGNED  0x00030004u   /* funding_signed, host */
#define GZ_FUND_REC_STATUS  0x00030006u   /* funding_status, both */

/* funding_status states. */
#define GZ_FUND_ST_ACKED      1   /* member: acked, waiting for the funding */
#define GZ_FUND_ST_AWAITING   2   /* host, CONFIRM: waiting for the person */
#define GZ_FUND_ST_BROADCAST  3   /* host: signed and broadcast */
#define GZ_FUND_ST_LIVE       4   /* buried (C11 live) */
#define GZ_FUND_ST_ABANDONED  5   /* member: deadline passed; host: abandoned, spend-back made */
#define GZ_FUND_ST_DEAD       6   /* a funding input spent elsewhere and buried (C4(d)) */
#define GZ_FUND_ST_FAILED     7   /* host: the plan released, never funded */
#define GZ_FUND_ST_LIVE_LATE  8   /* host: abandoned, then the funding was buried first */

/* Command (0x03xx): the person confirms a funding in CONFIRM.
 *   12 scope (32). Results 200; 400 bad_request; 404 no_such_funding;
 *   409 refused_now (not awaiting confirmation); 503 wallet_failed. */
#define GZ_CMD_FUNDING_CONFIRM 0x0301u

/* Cancel reasons the lobby sends for the funding engine's ends
 * (messages.md 6.10). */
#define GZ_FUND_CANCEL_SIGNING 3   /* H1 failed, the wallet failed */
#define GZ_FUND_CANCEL_FUNDING 4   /* the funding did not confirm, or is dead */

/* ---- the wallet port (composite-node.md 14.1) -------------------------- */

typedef struct {
    uint64_t amount;
    uint8_t script_len;
    uint8_t script[GZ_FUND_MAX_SCRIPT];
} gz_fund_prevout_t;

/* Program-supplied, over wallet/ (gzt_funding_build, gzt_funding_unsigned,
 * gzt_funding_prevout, gzt_funding_release, gzt_funding_spend_back). Every
 * failure returns 0 and is an outcome, never an error. Byte buffers are the
 * engine's; `cap` is their size.
 *   plan        a new funding paying exactly `amount` to `script` (34 bytes,
 *               OP_1 <32>) at `feerate` sat/kvB, with exactly one other
 *               output, the wallet's own change (H16 bumps a funding only by
 *               a child on it); with `must_spend` set, input 0 spends that
 *               outpoint (H11). The wallet offers only confirmed coins, never
 *               the change of a funding not yet buried. Fills the unsigned
 *               transaction and every input's spent output, in input order.
 *               The wallet holds the plan, and its coins, from then on.
 *   sign_plan   the signed bytes of the plan the wallet holds under `txid`:
 *               never bytes handed in (docs/notes/signer.md). 0 if it holds
 *               no such plan.
 *               The factory's output is output 0 (the engine checks it).
 *   adopt       after a restart (the wallet's holds are in its memory
 *               only): hold again a plan from the engine's journal, only if
 *               the wallet finds it its own: every input one of its coins,
 *               output 0 exactly `amount` to `script` (the factory's), the
 *               other its own change. 0 if refused; such a plan is then
 *               never signed.
 *   release     free the coins of a plan that will never be funded.
 *   spend_back  a transaction spending input `index` of the plan the wallet
 *               holds under `txid` (never bytes handed in) to the wallet's
 *               own script, paying exactly `fee`, signed. The engine never
 *               asks more than the top of its ladder (funding.md 2): the
 *               funding's fee plus `incremental_high` on the spend-back's
 *               size, or the ordinary rate when nothing is replaced. */
typedef struct {
    int (*plan)(void *ctx, uint64_t amount, const uint8_t script[34], uint64_t feerate,
                const gz_outpoint_t *must_spend, uint8_t *tx, size_t cap, size_t *tx_len,
                gz_fund_prevout_t *prev, size_t max_prev, size_t *n_prev);
    int (*sign_plan)(void *ctx, const uint8_t txid[32], uint8_t *out, size_t cap, size_t *out_len);
    int (*adopt)(void *ctx, const uint8_t *tx, size_t tx_len, const uint8_t script[34], uint64_t amount);
    void (*release)(void *ctx, const uint8_t *tx, size_t tx_len);
    int (*spend_back)(void *ctx, const uint8_t txid[32], uint32_t index, uint64_t fee,
                      uint8_t *out, size_t cap, size_t *out_len);
    void *ctx;
} gz_wallet_port_t;

/* ---- what the engine tells the composite ------------------------------- */

typedef enum {
    GZ_FUND_R_LIVE = 1,      /* buried: Active, the slot closed; member: gz_sign_resolve live */
    GZ_FUND_R_DEAD,          /* an input spent elsewhere and buried: Failed reason 4 (if not
                                ended); member: resolve dead */
    GZ_FUND_R_ABANDONED,     /* member: its funding deadline passed: resolve abandoned, Failed
                                reason 4. Host: its deadline passed: Failed reason 4, cancel
                                reason 4 to every seat, the spend-back follows */
    GZ_FUND_R_FUNDED_LATE    /* abandoned, then buried after all: the factory is live; the
                                lobby's history stays Failed, with a "funded late" notice */
} gz_fund_report_kind_t;

typedef struct {
    gz_fund_report_kind_t kind;
    int host;
    uint8_t scope[32];
    gz_outpoint_t funding;   /* the funding outpoint */
    uint16_t cancel_reason;  /* DEAD and ABANDONED: 4 */
    uint32_t height;         /* the tip at the decision */
} gz_fund_report_t;

typedef struct {
    void *ctx;
    /* Called inside a step, after the engine's save and before its outward
     * actions; the composite brackets what the others append. */
    gz_status_t (*report)(void *ctx, const gz_fund_report_t *r, gz_action_list_t *out);
    /* (UNWATCH is an action now: the engine appends it, step P4.5.) */

} gz_fund_hooks_t;

typedef struct {
    int host;
    gz_host_funding_t mode;            /* copied into each plan: AUTO by default (12.1) */
    uint64_t feerate;                  /* sat/kvB of the funding and of an ordinary spend-back:
                                          100, 0.1 sat/vB (owner) */
    /* The replacement increment the spend-back pays on its own size, sat/kvB:
     * 100 on Bitcoin Core 29.1 and later; a refused spend-back is made again
     * once with `incremental_high` (1,000: Core 28.x and 29.0). */
    uint64_t incremental, incremental_high;
    uint32_t burial;                   /* B: 3 in Slice 1 */
    uint32_t funding_deadline_blocks;  /* 36 in Slice 1 (terms.md; safety-rule.md 12) */
    uint32_t tick_ms;                  /* delay of a tick with work still due: 0 */
    gz_wallet_port_t wallet;           /* host only; all NULL on a member */
    gz_fund_hooks_t hooks;
} gz_fund_config_t;

/* The defaults above, for `host`. */
void gz_fund_config_default(gz_fund_config_t *cfg, int host);

/* ---- the engine's state ------------------------------------------------- */

typedef struct {
    int used;
    int state;                          /* GZ_FUND_ST_*, 0: planned, not yet at its outcome */
    uint64_t seq;                       /* age: the order it was opened in */
    uint8_t scope[32], check[32];
    uint16_t attempt;
    int mode;                           /* host: AUTO or CONFIRM, as planned */
    uint64_t feerate;
    gz_outpoint_t funding;              /* txid and the output to the factory */
    uint64_t amount;
    uint8_t script[34];
    uint8_t tx[GZ_FUND_MAX_TX];         /* unsigned */
    size_t tx_len;
    size_t n_in;
    gz_fund_prevout_t prev[GZ_FUND_MAX_INPUTS];   /* host: the spent outputs */
    uint8_t in0[36];                    /* the outpoints of the watched inputs (36 bytes each) */
    uint8_t ins[GZ_FUND_WATCH_INPUTS][36];
    uint8_t signed_tx[GZ_FUND_MAX_SIGNED];
    size_t signed_len;
    int h1_ok;                          /* H1 passed at the outcome (memory: the step between
                                           gz_fund_host_h1 and gz_fund_host_apply) */
    uint32_t deadline;                  /* host: abandon at this tip; member: ack tip + deadline */
    int deadline_pending;               /* host: no tip known yet when it was set */
    uint32_t plan_tip;                  /* host: the tip when the plan was made, the deadline's basis */
    int plan_tip_known;
    int released;                       /* host: a partial signature of this plan's attempt was
                                           released (H11) and no plan spending its input 0 was
                                           accepted yet: never reused, and the next plan spends
                                           its input 0 */
    /* member: C11's inputs */
    uint32_t ack_tip, end_height;
    uint8_t own_depth, whole_tree;
    gz_exit_consts_t exit;
    uint32_t deadline_blocks;
    /* host: the spend-back */
    uint8_t sb[GZ_FUND_MAX_SPEND_BACK];
    size_t sb_len;
    uint8_t sb_txid[32];
    uint64_t sb_fee;
    int sb_escalated;
    uint32_t sb_index;
    /* chain facts (memory: watches report them again at start) */
    uint32_t conf, conf_height;         /* the funding txid's confirmations, its block */
    uint8_t spender[GZ_FUND_WATCH_INPUTS][32];
    uint32_t spender_conf[GZ_FUND_WATCH_INPUTS];
    int spender_known[GZ_FUND_WATCH_INPUTS];
    int seen;                           /* host: the funding was ever seen spending input 0 */
    int due, rebroadcast, escalate;
    int watching;                       /* watches set this incarnation */
    /* After a start (review B of PR 56, H-1): the chain facts are memory only
     * and come back through the watches. Until the chain view has answered
     * every watch of the factory set at this start (GZ_CHAIN_WATCH_SYNCED,
     * event.h), no deadline decision is taken (abandon, a spend-back's level
     * or one not yet made, member Abandoned). No tip count ends it. Rebuilt at
     * every start, never saved. */
    int resyncing;
    unsigned reported;                  /* synced: bit 0 the txid, bit 1 + k watched input k */
    /* Watches the chain view can never answer (GZ_CHAIN_WATCH_FAILED; review B
     * of PR 56, second confirmation, G-1), the same bits. Each is that watch's
     * answer; the factory then fails closed: a member's Abandoned, a host's
     * abandoned with no spend-back. Memory only: the watch fails again after
     * a start. */
    unsigned failed;
} gz_fund_factory_t;

typedef struct {
    uint8_t scope[32];
    uint8_t state;
    uint32_t height;
} gz_fund_ended_t;

typedef struct {
    gz_fund_config_t cfg;
    gz_ports_t ports;
    uint32_t tip;
    int tip_known;
    int tip_synced;                     /* GZ_CHAIN_TIP_SYNCED for `tip` came (integration B12) */
    uint8_t tip_hash[32];               /* the tip block's hash, as NEW_TIP gave it (G-2) */
    uint64_t seq;
    size_t cursor;                      /* round-robin over factories (8.3) */
    size_t resume_at;                   /* the stepped resume: next factory */
    int tick_armed;
    size_t n_watches;                   /* distinct watches held (the budget) */
    gz_fund_factory_t fac[GZ_FUND_MAX_FACTORIES];
    gz_fund_ended_t ended[GZ_FUND_MAX_ENDED];
    size_t n_ended, ended_next;
    /* Member creations past the table: only their deadline is followed, and
     * they are reported Abandoned at it (never live: the safe side). */
    struct { int used; uint8_t scope[32]; gz_outpoint_t funding; uint32_t deadline; } pending[GZ_FUND_MAX_ENDED];
    uint64_t dropped;                   /* counted: events and records nobody needs */
    uint64_t refused;                   /* counted: plans refused (wallet, size, table) */
    uint64_t untracked;                 /* counted: member creations only followed to their deadline */
    gz_action_list_t *cur_out;          /* the list of the call under way (UNWATCH) */
    gz_status_t cur_st;
    uint8_t scratch[2u * GZ_FUND_MAX_SIGNED + 32u * 1024u]; /* the records of one save */
    uint8_t work[GZ_FUND_MAX_SIGNED];   /* a signed transaction being checked */
    gz_fund_factory_t tmp;              /* a factory being decoded: off the stack (review B, L-8) */
} gz_fund_t;

gz_status_t gz_fund_init(gz_fund_t *f, const gz_fund_config_t *cfg, const gz_ports_t *ports);

/* The composite's engine interface (core/node/engine.h): load, resume and
 * handle, with these signatures. reads: its own area only (the first
 * funding_status of a member carries what C11 and C4(d) need). */
gz_status_t gz_fund_load(void *e, const gz_record_t *rec, gz_batch_id_t at);
gz_status_t gz_fund_resume(void *e, gz_action_list_t *out, int *more);
gz_status_t gz_fund_handle(void *e, const gz_event_t *ev, gz_action_list_t *out);

/* ---- hand-offs (each called inside a bracket by core/node/handoff.c) --- */

/* Host, lobby to signing: the plan of an attempt (9.2 step 1). With
 * `released` (a partial signature of the scope's previous attempt was
 * released, H11) the new plan spends input 0 of the previous plan; without
 * it, the scope's unfunded plan is used again. Appends funding_plan when a
 * plan is new. On success *ok is 1 and the plan's unsigned bytes and outpoint
 * are returned (pointers into the engine, valid until its next call); on a
 * wallet failure, a plan over the limits or a full table, *ok is 0: outcome
 * Failed, cancel reason 3, with an attention notice appended. */
typedef struct {
    uint8_t scope[32], check[32];
    uint16_t attempt;
    uint64_t amount;
    uint8_t script[34];
    int released;
} gz_fund_plan_in_t;
typedef struct {
    int ok;
    const uint8_t *tx;
    size_t tx_len;
    gz_outpoint_t funding;
} gz_fund_plan_out_t;
gz_status_t gz_fund_host_plan(gz_fund_t *f, const gz_fund_plan_in_t *in, gz_action_list_t *out,
                              gz_fund_plan_out_t *res);

/* Host, the Funding outcome, BEFORE the lobby's save (14.2): H1. Appends
 * nothing. In AUTO it also signs through the wallet and checks the signed
 * transaction, without witnesses, equals the plan. Returns GZ_H1_OK (0) or
 * the failing check (a gz_h1_t, or GZ_FUND_H1_* below). */
#define GZ_FUND_H1_NO_PLAN   100   /* no plan for the scope */
#define GZ_FUND_H1_SIGN      101   /* the wallet did not sign */
#define GZ_FUND_H1_SIGNED    102   /* the signed bytes are not the plan */
#define GZ_FUND_H1_TOO_LATE  103   /* tip + B - 1 past the deadline: a burial by it is no longer
                                      possible; the lobby's outcome Failed with cancel reason 4
                                      (review B of PR 56, N-1) */
typedef struct {
    uint8_t scope[32];
    size_t n_members;
    const uint8_t *acked;
    size_t n_nodes;
    const uint8_t *signed_ok;
    const uint8_t *proposed_tx;        /* round_proposal record 18 */
    size_t proposed_len;
} gz_fund_h1_in_t;
int gz_fund_host_h1(gz_fund_t *f, const gz_fund_h1_in_t *in);

/* Host, after the lobby's save: with H1 passed, AUTO saves funding_signed
 * and a status, broadcasts and watches; CONFIRM saves the status "awaiting
 * confirmation" and notifies. With H1 failed, the plan is released, a status
 * saved and an attention notice appended. */
gz_status_t gz_fund_host_apply(gz_fund_t *f, const uint8_t scope[32], gz_action_list_t *out);

/* Host: the scope's lobby ended without a Funding outcome (Failed,
 * Cancelled): its unfunded plan is released. Nothing if none. */
gz_status_t gz_fund_host_drop(gz_fund_t *f, const uint8_t scope[32], gz_action_list_t *out);

/* Member, the round's Complete outcome (its own ack sent): the first
 * funding_status, in the outcome bracket, and the watches. This record is
 * the anchored-batch write of journal.md (it changes the watch bundle). */
typedef struct {
    uint8_t scope[32];
    const uint8_t *funding_tx;         /* without witnesses */
    size_t funding_tx_len;
    gz_outpoint_t funding;
    uint64_t amount;
    uint8_t script[34];
    uint32_t ack_tip, end_height;
    uint8_t own_depth, whole_tree;
    gz_exit_consts_t exit;
    uint32_t deadline_blocks;
} gz_fund_acked_in_t;
gz_status_t gz_fund_member_acked(gz_fund_t *f, const gz_fund_acked_in_t *in, gz_action_list_t *out);

/* ---- the slot end conditions (composite-node.md 2.4) ------------------- */

typedef enum {
    GZ_FUND_SCOPE_NONE = 0,   /* nothing funded or followed under this scope */
    GZ_FUND_SCOPE_OPEN,       /* still followed: news may come */
    GZ_FUND_SCOPE_LIVE,       /* Live: the slot's Closing ends */
    GZ_FUND_SCOPE_DEAD,       /* Dead: the slot's Closing ends */
    GZ_FUND_SCOPE_ABANDONED,  /* abandoned, still watched for a late burial */
    GZ_FUND_SCOPE_FAILED      /* host: released, never funded */
} gz_fund_scope_t;
/* The newest factory of the scope. `*until`, when not NULL, is the height
 * after which no deadline of it can still pass (its funding deadline plus
 * the burial depth), 0 if none. */
gz_fund_scope_t gz_fund_scope_state(const gz_fund_t *f, const uint8_t scope[32], uint32_t *until);

/* ---- fees (14.3) -------------------------------------------------------- */

/* The smallest fee that replaces a package paying `package_fee` with a
 * transaction of `vsize`: the package's fee plus `incremental` sat/kvB on
 * the new size (Core's rules 3 and 4), and above the package's own rate
 * (`package_fee` over `package_vsize`, rule 6). UINT64_MAX on overflow. */
uint64_t gz_fund_replace_fee(uint64_t package_fee, uint64_t package_vsize, uint64_t vsize,
                             uint64_t incremental);
/* ceil(rate x vsize / 1000), UINT64_MAX on overflow. */
uint64_t gz_fund_fee(uint64_t rate, uint64_t vsize);

/* A transaction's sizes, with or without witnesses: 1 and *vsize (weight
 * over 4, rounded up), *base (bytes without witnesses), or 0 if it does not
 * parse. */
int gz_fund_tx_vsize(const uint8_t *tx, size_t len, uint64_t *vsize, size_t *base);
/* The bytes without witnesses of a transaction, into out (cap): 1, or 0. */
int gz_fund_tx_strip(const uint8_t *tx, size_t len, uint8_t *out, size_t cap, size_t *out_len);

#endif
