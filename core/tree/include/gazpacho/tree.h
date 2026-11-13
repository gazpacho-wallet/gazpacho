/* The factory tree from signed lobby terms, and the creation checks.
 *
 *   spec/terms.md section 4        the split rule, D, the fee per transaction,
 *                                  the funding amount R(root)
 *   spec/signing-round.md 4.1, 13  the builder's inputs and order (advanceless:
 *                                  every interior level fixed, one member per
 *                                  pseudo-Spilman leaf, owner decision 9)
 *   spec/safety-rule.md 3, 10      checks C1 to C11 for a member, H1 for the host
 *   spec/exit.md 4.1 to 4.4        timeouts on a path, leave_by, the signing-time check
 *   spec/messages.md 7.1, 7.9, 7.12  round identifier, refusal reasons, tree digest
 *
 * Pure C11 like the rest of the core: no allocation, no input or output, no
 * global state, and the compiled library passes tools/check-core-isolation.sh.
 * Elliptic-curve work (MuSig2 key aggregation, taproot tweaks, BIP 340
 * verification) goes through gz_tree_crypto_t, supplied by the embedding;
 * core/tree/import provides one on the pinned secp256k1-zkp, together with
 * the build through the imported SuperScalar code that signing-round.md
 * section 13 requires.
 *
 * TWO BUILDS, ONE TREE. The member builds the tree twice: here, from the
 * rules written out in the specifications (gz_tree_build), and through the
 * imported builder (core/tree/import). gz_tree_member_check refuses unless
 * the two agree byte for byte on every transaction, so a defect in either is
 * a refusal, never a signature. */
#ifndef GAZPACHO_TREE_H
#define GAZPACHO_TREE_H

#include "gazpacho/terms.h"

#include <stddef.h>
#include <stdint.h>

/* Bounds. 256 members: signing-round.md section 12 (the import's layer
 * counter is written out of bounds from 257 members on). */
#define GZ_TREE_MAX_MEMBERS   256
#define GZ_TREE_MAX_NODES     800      /* at most 3 per member (binary interior + leaf pair) */
#define GZ_TREE_MAX_OUTPUTS   16       /* 15 children and the anchor */
#define GZ_TREE_MAX_TX        720      /* 64 + 43 x 15 = 709 bytes at most (15 children and the anchor) */
#define GZ_TREE_MAX_DEPTH     32       /* deeper than any valid tree of 256 members */
#define GZ_TREE_MAX_LEVELS    8        /* the import reads at most 8 arity entries */
#define GZ_TREE_ANCHOR_SAT    240      /* ANCHOR_OUTPUT_AMOUNT, channel.h:16 */
#define GZ_TREE_DUST_SAT      546      /* CHANNEL_DUST_LIMIT_SATS, channel.h:14 */
#define GZ_TREE_TIMEOUT_STEP  5        /* TIMEOUT_STEP_BLOCKS, factory.c:1475 */
#define GZ_TREE_LSTOCK_DEFAULT 144     /* L_STOCK_CSV_DEFAULT_BLOCKS, factory.h:50 */
#define GZ_TREE_SLICE1_STEP   144      /* signing-round.md 4.1: layer step, fixed in Slice 1 */
#define GZ_TREE_SLICE1_STATES 4        /* and states per layer */

/* ---------------------------------------------------------------- crypto */

/* Elliptic-curve operations the core cannot do itself. Every function returns
 * 1 on success and 0 on any failure (an invalid key, a failed check). */
typedef struct gz_tree_crypto {
    void *ctx;
    /* 1 if `pub` is a valid compressed point (prefix 2 or 3, on the curve). */
    int (*point_valid)(void *ctx, const uint8_t pub[33]);
    /* BIP 340 verification of `sig` over `msg` under the x coordinate of `pub`. */
    int (*verify)(void *ctx, const uint8_t msg[32], const uint8_t pub[33], const uint8_t sig[64]);
    /* BIP 327 KeyAgg of the keys first, rest[0], ..., rest[n_rest - 1], in that
     * order (no sorting), then the BIP 341 tweak t = TH("TapTweak", P || m)
     * (or TH("TapTweak", P) when merkle is NULL). Writes the untweaked x-only
     * aggregate P and the x-only output key Q = P + tG. */
    int (*agg_tweak)(void *ctx, const uint8_t first[33], const uint8_t (*rest)[33], size_t n_rest,
                     const uint8_t *merkle, uint8_t internal[32], uint8_t output[32]);
} gz_tree_crypto_t;

/* ---------------------------------------------------------- shape rules */

/* The level list `interior || leaf_kind` of a shape entry (terms.md 4.1).
 * Returns its length. */
size_t gz_tree_levels(const gz_shape_entry_t *e, uint8_t levels[GZ_TREE_MAX_LEVELS]);
/* The first entry with max_members >= n, or NULL. */
const gz_shape_entry_t *gz_tree_shape_for(const gz_terms_outer_t *t, uint32_t n_members);

/* terms.md 4.2's split rule. Writes each member's leaf depth (member order)
 * and returns 1; returns 0 if a node at an interior depth would hold m <= a
 * members (a multi-member or non-pseudo-Spilman leaf). */
int gz_tree_split(const uint8_t *levels, size_t n_levels, uint32_t n_members, uint8_t *depths);

/* Signed virtual size of a tree transaction with k P2TR outputs and the
 * anchor (BIP 141): ceil((4 (64 + 43 k) + 2 + 66) / 4). */
uint32_t gz_tree_vsize(uint32_t k);

/* Everything terms.md section 4.2 derives for n members. */
typedef struct {
    uint32_t n_members;
    uint8_t levels[GZ_TREE_MAX_LEVELS];
    size_t n_levels;
    uint8_t D;                  /* fixed_levels: the depth of the deepest leaf */
    uint32_t max_children;      /* of any tree transaction (2 at least: the leaf's state) */
    uint32_t V;                 /* largest signed vsize */
    uint64_t fee_per_tx;        /* ceil(tree_feerate x V / 1000) */
    uint64_t funding_amount;    /* R(root) */
    uint8_t depth[GZ_TREE_MAX_MEMBERS];   /* each member's leaf depth */
} gz_tree_params_t;

typedef enum {
    GZ_TREE_P_OK = 0,
    GZ_TREE_P_COUNT,            /* n below 3 or above GZ_TREE_MAX_MEMBERS */
    GZ_TREE_P_NO_SHAPE,         /* no entry covers n */
    GZ_TREE_P_SPLIT,            /* the entry makes a leaf with more than one member */
    GZ_TREE_P_OVERFLOW          /* R(root) does not fit 64 bits */
} gz_tree_p_err_t;
gz_tree_p_err_t gz_tree_params(const gz_terms_outer_t *t, uint32_t n_members, gz_tree_params_t *p);
/* R(root) for given levels, member count, channel, fee (anchors on). Returns
 * 0 on overflow or an invalid split, else 1. */
int gz_tree_requirement(const uint8_t *levels, size_t n_levels, uint32_t n_members,
                        uint64_t channel_sat, uint64_t fee, uint64_t *out);

/* exit.md 4.2 vector X2: the member's leaf depth and the number of P2TR
 * outputs of each tree transaction on its path, root first (d fixed
 * kickoffs, the leaf's kickoff with 1, the leaf transaction with 2).
 * Returns the number of transactions (d + 2), or 0 for an invalid split. */
size_t gz_tree_member_path(const uint8_t *levels, size_t n_levels, uint32_t n_members, uint32_t member,
                           uint8_t *depth, uint8_t outs[GZ_TREE_MAX_DEPTH + 2]);

/* ---------------------------------------------------- exit arithmetic */

/* exit.md 4.3: the member's constants. Heights are signed 64-bit, so an end
 * height near zero gives negative dates rather than wrapping. */
typedef struct {
    uint32_t A;         /* confirmation allowance per transaction */
    uint32_t B;         /* burial depth */
    uint32_t M;         /* M_safe + M_lag + M_spike */
    uint32_t M_host;    /* M_safe + M_lag */
} gz_exit_consts_t;
/* A 6, B 3, M 14, M_host 8. */
#define GZ_EXIT_SIGNET_INIT { 6, 3, 14, 8 }
gz_exit_consts_t gz_exit_signet(void);

/* exit.md 4.1: the timeout height on the output that the transaction at
 * position i of a member's path spends, for a leaf at depth d. Positions:
 * 0..d-1 the fixed kickoffs (0 = root, which has none: returns 0 and sets
 * *none), d the leaf's kickoff, d+1 the leaf transaction, d+2 the commitment. */
int64_t gz_exit_path_timeout(int64_t E, uint32_t d, uint32_t i, int *none);
int64_t gz_exit_h_leaf(int64_t E, uint32_t d);                     /* E - 10 d */
int64_t gz_exit_last_safe_confirm(int64_t E, uint32_t d, const gz_exit_consts_t *c);
int64_t gz_exit_leave_by(int64_t E, uint32_t d, uint32_t n_missing, const gz_exit_consts_t *c);
int64_t gz_exit_step_due(int64_t E, uint32_t d, uint32_t i, uint32_t n_missing, const gz_exit_consts_t *c);
int64_t gz_exit_host_force_by(int64_t E, uint32_t d, uint32_t n_host, const gz_exit_consts_t *c);
/* exit.md 5.6: unlock_by while no tree step is late, and once one is. */
int64_t gz_exit_unlock_by(int64_t E, uint32_t d, uint32_t n_missing, int tree_late, const gz_exit_consts_t *c);
/* exit.md 4.4, "Signing-time check": 1 if leave_by with all d + 3 steps
 * missing is at least funding_deadline + B + 1. */
int gz_exit_signing_check(int64_t E, uint32_t d, int64_t funding_deadline, const gz_exit_consts_t *c);

/* ------------------------------------------------------------- the tree */

enum { GZ_NODE_FIXED = 1, GZ_NODE_LEAF_KICKOFF = 2, GZ_NODE_LEAF_STATE = 3 };
enum { GZ_OUT_CHILD = 1, GZ_OUT_CHANNEL = 2, GZ_OUT_LSTOCK = 3, GZ_OUT_ANCHOR = 4, GZ_OUT_STATE = 5 };

/* One tree transaction, as gz_tree_build rebuilt it. Node order is the
 * import's (depth first: a fixed kickoff, then its children in order; a leaf
 * as its kickoff then its state), so node i here is f->nodes[i] there. */
typedef struct {
    uint8_t kind;               /* GZ_NODE_* */
    uint8_t depth;              /* split depth; a leaf's two transactions share it */
    int16_t parent;             /* node index, -1 for the root */
    uint8_t parent_vout;
    uint16_t first, count;      /* members [first, first + count) sign, with the host */
    uint32_t cltv;              /* timeout on the output this node spends; 0 = none */
    uint32_t nsequence;
    uint8_t internal[32];       /* untweaked aggregate of the signers */
    uint8_t has_merkle;
    uint8_t merkle[32];         /* the timeout leaf's hash, the only leaf */
    uint8_t tweak[32];          /* TH("TapTweak", internal || merkle) or TH("TapTweak", internal) */
    uint8_t spent_txid[32];     /* internal order */
    uint32_t spent_vout;
    uint64_t spent_amount;
    uint8_t spent_script[34];   /* P2TR of (internal, merkle) */
    uint8_t n_out;
    uint8_t out_kind[GZ_TREE_MAX_OUTPUTS];
    uint64_t out_amount[GZ_TREE_MAX_OUTPUTS];
    uint8_t out_script_len[GZ_TREE_MAX_OUTPUTS];
    uint8_t out_script[GZ_TREE_MAX_OUTPUTS][34];
    uint32_t lstock_csv;        /* leaf state: the spare-liquidity delay in its script */
    uint16_t tx_len;
    uint8_t tx[GZ_TREE_MAX_TX]; /* unsigned, no witness */
    uint8_t txid[32];           /* internal order */
    uint8_t sighash[32];        /* BIP 341 key path, default type, input 0 */
} gz_tree_node_t;

/* Large (about 1.3 MB): allocate it, do not put it on the stack. */
typedef struct {
    uint32_t n_members;
    uint16_t n_nodes;
    uint16_t leaf_state[GZ_TREE_MAX_MEMBERS];   /* node index of member i's leaf transaction */
    uint8_t funding_internal[32];
    gz_tree_node_t node[GZ_TREE_MAX_NODES];
} gz_tree_t;

/* What gz_tree_build needs. Every field is one row of signing-round.md 4.1. */
typedef struct {
    const uint8_t *levels; size_t n_levels;   /* interior || 3 */
    uint8_t fixed_levels;                       /* must be D */
    uint32_t n_members;
    const uint8_t *host_key;                    /* participant 0's factory key, 33 bytes */
    const uint8_t (*member_keys)[33];           /* members in tree order */
    uint32_t end_height;                        /* cltv_timeout */
    uint64_t fee_per_tx;
    uint32_t lstock_csv;                        /* 0 means the import's default, 144 */
    uint8_t funding_txid[32];                   /* internal order */
    uint32_t funding_vout;
    uint64_t funding_amount;
    /* For the imported builder only (factory_set_funding takes the script on
     * trust); gz_tree_build derives it and ignores this field. */
    uint8_t funding_script[34];
} gz_tree_build_in_t;

typedef enum {
    GZ_TREE_B_OK = 0,
    GZ_TREE_B_ARGUMENT,       /* member count or levels out of bounds */
    GZ_TREE_B_SPLIT,          /* a multi-member leaf */
    GZ_TREE_B_FIXED_LEVELS,   /* fixed_levels is not D */
    GZ_TREE_B_UNDERFUNDED,    /* a node's input does not cover its fee and anchor */
    GZ_TREE_B_DUST,           /* a leaf's channel below 546 */
    GZ_TREE_B_IMPORT_MINIMUM, /* below factory_build_tree's minimum funding check */
    GZ_TREE_B_CRYPTO          /* a key the provider refuses */
} gz_tree_b_err_t;
/* Rebuild every transaction from the rules. Mirrors factory.c's
 * build_subtree for this shape exactly, including the import's own refusals
 * (dust, underfunded nodes, its minimum funding), so the two agree also on
 * what is refused. */
gz_tree_b_err_t gz_tree_build(const gz_tree_build_in_t *in, const gz_tree_crypto_t *cr, gz_tree_t *t);

/* Transaction helpers (exposed for the tests). */
/* 1 if `tx` is exactly one transaction without witness; fills the counts and
 * where the outputs start. */
typedef struct {
    uint32_t version, locktime;
    size_t n_in, n_out;
    size_t in_at, out_at;       /* offsets of the first input and first output */
} gz_tx_info_t;
int gz_tx_parse(const uint8_t *tx, size_t len, gz_tx_info_t *info);
/* Output i's amount and script (pointer into tx). 0 if out of range. */
int gz_tx_output(const uint8_t *tx, size_t len, const gz_tx_info_t *info, size_t i,
                 uint64_t *amount, const uint8_t **script, size_t *script_len);
/* Input i's outpoint (36 bytes, txid internal order then the index little
 * endian as in the transaction), script length and sequence. */
int gz_tx_input(const uint8_t *tx, size_t len, const gz_tx_info_t *info, size_t i,
                const uint8_t **outpoint, size_t *script_len, uint32_t *sequence);
void gz_tx_txid(const uint8_t *tx, size_t len, uint8_t txid[32]);
/* BIP 341 signature message hash, key path, SIGHASH_DEFAULT, no annex, for a
 * transaction with one input spending (amount, script). */
int gz_tx_sighash1(const uint8_t *tx, size_t len, uint64_t amount, const uint8_t *script, size_t script_len,
                   uint8_t out[32]);

/* ---------------------------------------- the round's identity (7.1, 7.12) */

typedef struct {
    uint8_t factory_key[33];
    uint8_t contribution_key[33];
    uint8_t bind_by_factory[64];
    uint8_t bind_by_contribution[64];
} gz_tree_participant_t;

/* The tree digest of messages.md 7.12, over the funding outpoint, amount,
 * participants' factory keys and every node as one key-path item. `chain` is
 * the outer terms' chain hash. */
void gz_tree_digest(const gz_tree_t *t, const uint8_t chain[32], const uint8_t funding_txid[32],
                    uint32_t funding_vout, uint64_t funding_amount,
                    const gz_tree_participant_t *participants, size_t n_participants, uint8_t out[32]);
/* The round identifier of messages.md 7.1 for a creation round with one tier
 * holding every node. */
void gz_tree_round_id(const gz_tree_t *t, const uint8_t chain[32], const uint8_t host_key[33],
                      const uint8_t outer_digest[32], const uint8_t terms_digest[32],
                      const uint8_t funding_txid[32], uint32_t funding_vout, uint64_t funding_amount,
                      const gz_tree_participant_t *participants, size_t n_participants,
                      const uint8_t host_random[32], uint8_t out[32]);

/* --------------------------------------------------- the proposal (7.2) */

/* The parameters of round_propose (messages.md 7.2) the tree is rebuilt
 * from, decoded by the signing engine. Pointers are borrowed. */
typedef struct {
    uint8_t purpose;                    /* record 6 */
    uint32_t terms_version;             /* 8 */
    uint8_t terms_digest[32];           /* 10 */
    uint8_t funding_txid[32];           /* 12: outpoint, txid internal order */
    uint32_t funding_vout;
    uint64_t funding_amount;            /* 14 */
    uint8_t funding_script[34];         /* 16 */
    size_t funding_script_len;          /* 34 on the wire; kept for the C1 length check */
    const uint8_t *funding_tx;          /* 18 */
    size_t funding_tx_len;
    const gz_tree_participant_t *participants;   /* 20: host first */
    size_t n_participants;
    uint8_t n_tiers;                    /* 22 */
    uint32_t tier_sizes[8];
    uint32_t end_height;                /* 24 */
    uint8_t tree_anchors;               /* 28 */
    uint64_t fee_per_tx;                /* 30 */
    uint32_t lstock_delay;              /* 32 */
    size_t n_lstock_hashes;             /* 34: Slice 1, none */
    uint8_t fixed_levels;               /* 36 */
    uint8_t k;                          /* 38 */
    uint16_t layer_step, layer_states;  /* 40, 42 */
    uint8_t has_distribution;           /* 44 present */
    uint8_t placement;                  /* not on the wire: what the engine writes (0) */
    uint32_t nonces_due_ms, sigs_due_ms;  /* 48, 50: each at most the terms' step timeout */
} gz_tree_proposal_t;

/* -------------------------------------------- refusals (messages.md 7.9) */

enum {
    GZ_REASON_NONE = 0,
    GZ_REASON_UNSAFE = 1,          /* the safe-to-sign checks failed */
    GZ_REASON_INVALID = 5,         /* an invalid message (here: a binding signature) */
    GZ_REASON_BUSY = 6,            /* another round touches the same output (C10) */
    GZ_REASON_CONDITIONS = 9,      /* the tree does not meet the member's conditions (C8, C8a) */
    GZ_REASON_OTHER_TREE = 11,     /* C7: another tree on this outpoint */
    GZ_REASON_NOT_MY_KEY = 12      /* C7: the list lacks this member's current key */
};

/* Every reason a check can give, one per rule. gz_tree_reason maps each to
 * its messages.md 7.9 code. */
typedef enum {
    GZ_CHK_OK = 0,
    /* C8a, frozen terms (reason 9) */
    GZ_CHK_C8A_PURPOSE, GZ_CHK_C8A_VERSION, GZ_CHK_C8A_DIGEST, GZ_CHK_C8A_READY_OUTER,
    /* The stored terms, re-checked at signing (review B, B1); `at` is the
     * gz_terms_err_t that refused. */
    GZ_CHK_C8A_TERMS_BOUNDS,      /* terms.md 7 steps 4 and 5 on the outer struct (reason 9) */
    GZ_CHK_C8A_FROZEN_VALUES,     /* terms.md 5 on the frozen values (reason 9) */
    GZ_CHK_C8A_TERMS_RECORD,      /* the stored records fail steps 1 to 6, or name other digests (reason 1) */
    GZ_CHK_C8A_TERMS_DIFFER,      /* the structs are not what the stored records decode to (reason 1) */
    /* C1, rebuilt not received (reason 1) */
    GZ_CHK_C1_PARTICIPANTS,       /* count outside 2..GZ_TREE_MAX_MEMBERS + 1 */
    GZ_CHK_C1_DUPLICATE_KEY,      /* a key twice (factory or contribution, across both) */
    GZ_CHK_C1_BAD_KEY,            /* not a valid point */
    GZ_CHK_C1_HOST_KEY,           /* participant 0's contribution key is not the terms' host key */
    GZ_CHK_C1_FUNDING_TX,         /* funding_tx does not parse, or has a witness */
    GZ_CHK_C1_FUNDING_TXID,       /* its txid is not the outpoint's */
    GZ_CHK_C1_FUNDING_VOUT,       /* the outpoint's index is past its outputs */
    GZ_CHK_C1_FUNDING_AMOUNT,     /* proposal amount differs from that output's */
    GZ_CHK_C1_FUNDING_SCRIPT_LEN, /* the script is not exactly 34 bytes */
    GZ_CHK_C1_FUNDING_SCRIPT,     /* proposal script differs from that output's */
    GZ_CHK_C1_NOT_AGGREGATE,      /* the script is not the BIP 86 key of the aggregate */
    GZ_CHK_C1_IMPORT_DIFFERS,     /* the imported builder made other bytes */
    GZ_CHK_C1_IMPORT_FAILED,      /* the imported builder refused a tree the rules accept */
    GZ_CHK_BINDING,               /* a binding signature does not verify (reason 5) */
    /* C7 and C10 */
    GZ_CHK_C7_NOT_MY_KEY,         /* reason 12 */
    GZ_CHK_C10_BUSY,              /* reason 6 */
    GZ_CHK_C7_OTHER_TREE,         /* reason 11 */
    /* C8, the member's conditions and the fixed and derived fields (reason 9) */
    GZ_CHK_C8_PLACEMENT, GZ_CHK_C8_ANCHORS, GZ_CHK_C8_K, GZ_CHK_C8_LAYER_STEP, GZ_CHK_C8_LAYER_STATES,
    GZ_CHK_C8_HASHES, GZ_CHK_C8_DISTRIBUTION,
    GZ_CHK_C8_DEADLINES,          /* nonces_due_ms or sigs_due_ms above the step timeout (messages.md 7.2) */
    GZ_CHK_C8_MEMBERS_TERMS,      /* fewer than the terms' minimum, more than the target */
    GZ_CHK_C8_MEMBERS_OWN,        /* outside the member's own range */
    GZ_CHK_C8_NO_SHAPE,           /* no shape entry covers this many members */
    GZ_CHK_C8_SHAPE,              /* the entry makes a multi-member leaf */
    GZ_CHK_C8_FIXED_LEVELS,       /* not D */
    GZ_CHK_C8_FEE_RULE,           /* fee_per_tx is not the terms' rule */
    GZ_CHK_C8_FEE_CEILING,        /* above the member's ceiling */
    GZ_CHK_C8_FUNDING_RULE,       /* funding_amount is not R(root) */
    GZ_CHK_C8_LSTOCK_DELAY,       /* outside the member's range, or 0, or above 65,535 */
    GZ_CHK_C8_END_ZERO,           /* end height 0: no timeouts at all */
    GZ_CHK_C8_END_WINDOW,         /* not within 6 blocks of tip + lifetime + wind-down */
    GZ_CHK_C8_END_LOCKTIME,       /* 500,000,000 or more: a lock time read as a Unix time */
    GZ_CHK_C8_EXIT_TIME,          /* leave_by is before the funding deadline + B + 1 */
    GZ_CHK_C8_UNDERFUNDED,        /* a node cannot pay its fee and anchor */
    GZ_CHK_C8_DUST,               /* a channel below 546 */
    GZ_CHK_C8_IMPORT_MINIMUM,     /* below the import's minimum funding */
    GZ_CHK_C8_LEAF_KIND,          /* a leaf that is not a one-member pseudo-Spilman leaf */
    GZ_CHK_C8_OWN_LEAF,           /* the member's key is not on exactly one leaf */
    GZ_CHK_C8_CHANNEL_TERMS,      /* some channel below the terms' channel_sat */
    GZ_CHK_C8_CHANNEL_OWN,        /* the member's channel below its own minimum */
    GZ_CHK_C6_TIERS,              /* not one tier holding every tree transaction */
    GZ_CHK_C5_UNKNOWN_PATH,       /* an output on the path with a way to spend it the module does not know (reason 1) */
    GZ_CHK_CRYPTO,                /* the provider failed (reason 1) */
    GZ_CHK_ARGUMENT               /* a NULL input (reason 1) */
} gz_chk_t;

uint16_t gz_tree_reason(gz_chk_t c);
const char *gz_chk_name(gz_chk_t c);

/* --------------------------------------------- the member's checks */

/* A member's conditions for signing (safety-rule.md C8; terms.md 9 holds the
 * lobby-level ones). */
typedef struct {
    uint64_t min_own_channel_sat;       /* its own channel at least this */
    uint64_t max_fee_per_tx_sat;        /* the fee ceiling */
    uint32_t min_lstock_delay, max_lstock_delay;
    uint32_t min_members, max_members;  /* the tree's member count */
    gz_exit_consts_t exit;              /* A, B, M (exit.md 4.3) */
    uint32_t funding_deadline_blocks;   /* 36 in Slice 1 (safety-rule.md 12 value 4) */
    uint32_t end_window;                /* 6 (messages.md 7.2 record 24) */
} gz_tree_conditions_t;

typedef struct { uint8_t txid[32]; uint32_t vout; } gz_tree_outpoint_t;
/* C7: an exposure record (journal.md `exposure`) still in the exposed set. */
typedef struct { gz_tree_outpoint_t funding; uint8_t tree_digest[32]; } gz_tree_exposure_t;

/* The imported builder's result, for the C1 comparison: per node, its
 * unsigned bytes and what the import says about it. Filled by
 * gz_tree_import_build (core/tree/import). */
typedef struct {
    uint16_t n_nodes;
    struct {
        uint8_t kind;              /* GZ_NODE_* as the import labels it */
        uint8_t is_ps_leaf;
        uint16_t n_signers;
        int16_t parent;
        uint8_t parent_vout;
        uint16_t tx_len;
        uint8_t tx[GZ_TREE_MAX_TX];
    } node[GZ_TREE_MAX_NODES];
} gz_tree_import_t;

typedef struct {
    /* The lobby, as the member stored it. */
    const gz_terms_outer_t *outer;
    const uint8_t *outer_digest;          /* 32 */
    const gz_terms_current_t *frozen;     /* the frozen current values */
    const uint8_t *frozen_digest;         /* 32 */
    /* The same lobby as stored bytes: the outer record and the frozen current
     * record exactly as received in terms_offer, the host's two signatures,
     * and the BOLT 8 key the member connected to the host with. The check
     * runs gz_terms_receive on them again (scope = outer_digest) and refuses
     * unless they give exactly `outer`, `frozen` and the two digests above:
     * the bindings and C8a are checked against the digests, the tree is built
     * from the structs, and this ties the two together (review B, B1). */
    const uint8_t *outer_rec; size_t outer_rec_len;
    const uint8_t *outer_sig;             /* 64 */
    const uint8_t *frozen_rec; size_t frozen_rec_len;
    const uint8_t *frozen_sig;            /* 64 */
    const uint8_t *host_pinned_key;       /* 33 */
    /* What the member accepts (terms.md 7 step 4): {1} in Slice 1. The outer
     * struct is re-checked against it and section 3's bounds whatever the
     * caller did before, so a struct that was only parsed is never signed. */
    const gz_terms_policy_t *policy;
    /* The member's own `ready` (C8a). */
    const uint8_t *ready_outer_digest;    /* 32 */
    uint32_t ready_version;
    const uint8_t *ready_current_digest;  /* 32 */
    /* The member's current-epoch keys for this lobby; NULL if it has no seat. */
    const uint8_t *own_factory_key;       /* 33 */
    const uint8_t *own_contribution_key;  /* 33 */
    const gz_tree_conditions_t *cond;
    uint32_t tip;                         /* the member's tip estimate */
    /* C7 and C10 state. */
    const gz_tree_exposure_t *exposures; size_t n_exposures;
    const gz_tree_outpoint_t *unresolved; size_t n_unresolved;
    /* The imported builder (core/tree/import: gz_tree_import_member_check
     * sets these). Called once, only after the rebuild from the rules has
     * succeeded, with exactly the inputs the rebuild used, so the imported
     * code never runs on a proposal the rules refuse: several of its hazards
     * (signing-round.md 12) are undefined behaviour on shapes the rules
     * exclude. Returns 1 and fills `out`, or 0 if the import refused, which is
     * itself a refusal (C1). */
    int (*import_build)(void *ctx, const gz_tree_build_in_t *in, gz_tree_import_t *out);
    void *import_ctx;
    gz_tree_import_t *import_out;         /* its work space (large: heap) */
    const gz_tree_crypto_t *crypto;
} gz_tree_member_in_t;

typedef struct {
    gz_chk_t check;          /* GZ_CHK_OK or the first rule that failed */
    uint16_t reason;         /* gz_tree_reason(check) */
    int32_t at;              /* the node, participant or member it concerns; -1 if none */
    /* On success: */
    uint32_t own_member;     /* the member's position among the members (0-based) */
    uint8_t own_depth;
    int64_t leave_by;        /* all d + 3 steps missing */
    uint8_t tree_digest[32];
} gz_tree_verdict_t;

/* The member's checks on a creation proposal, in this order:
 *   C8a (purpose, frozen version and digest, own ready); the stored terms
 *   again (terms.md 7 steps 4 and 5 on `outer` under `policy`, section 5 on
 *   `frozen`, then steps 1 to 6 on the stored bytes and signatures, which
 *   must decode to exactly `outer`, `frozen` and the two digests); C1 participants
 *   (count, valid keys, every key distinct, the host's contribution key);
 *   bindings; C7 fresh key (reason 12); C10 (reason 6); C8 fixed fields and
 *   the member's ranges; C8 shape, fixed levels, fee and funding rules; C8
 *   end height and the exit-time check; C1 funding transaction and script;
 *   the rebuild (gz_tree_build) and C1's comparison with the import; C8 leaf
 *   kind, own leaf, channels; C5 every output on the path recognised; C6
 *   tiers; C7 tree digest against the exposure records (reason 11).
 * `t` is work space and, on success, the tree the member will sign.
 * Stops at the first failure. C2 is the own-leaf row (found from the
 * member's own key, never from a position in the request); C3 and C4 are
 * degenerate at creation (owed zero; every tree transaction is harmless,
 * C4(a)); C9 has no channel to touch. */
void gz_tree_member_check(const gz_tree_member_in_t *in, const gz_tree_proposal_t *p, gz_tree_t *t,
                          gz_tree_verdict_t *v);

/* C4(d): 1 if `spent` (36 bytes, txid then little-endian index as in a
 * transaction) is an input of `funding_tx` and was spent by a transaction
 * other than the funding transaction itself. The caller says it is buried. */
int gz_tree_c4d_dead(const uint8_t *funding_tx, size_t funding_tx_len, const uint8_t spent[36],
                     const uint8_t spender_txid[32]);

/* C10 alone (also run inside gz_tree_member_check). */
int gz_tree_c10_busy(const gz_tree_outpoint_t *funding, const gz_tree_outpoint_t *unresolved, size_t n);

/* C11: is the factory live? */
typedef struct {
    uint32_t tip;
    /* The member's tip when it sent round_ack: the height journal.md records
     * in funding_status with the ack (round_completed holds the ack back
     * until it is saved). The same value gz_tree_may_ack was given; after a
     * restart the journaled value, never the new tip. */
    uint32_t ack_tip;
    const gz_tree_conditions_t *cond;  /* B, funding deadline, exit constants */
    /* What the chain view shows at the funding outpoint (seen = 0: nothing). */
    int seen;
    uint64_t seen_amount;
    const uint8_t *seen_script; size_t seen_script_len;
    uint32_t confirmations;
    uint32_t buried_at;                /* height at which it reached B confirmations */
    /* The held tree. */
    uint64_t funding_amount;
    const uint8_t *funding_script;     /* 34 */
    int holds_whole_tree;
    uint32_t end_height;               /* the proposal's end height */
    uint8_t own_depth;                 /* verdict.own_depth */
} gz_tree_c11_in_t;
typedef enum {
    GZ_C11_WAIT = 0,       /* not buried yet, deadline not passed */
    GZ_C11_LIVE,           /* the exact output is buried */
    GZ_C11_ABANDONED,      /* not buried by the deadline, or buried late and the time checks fail */
    GZ_C11_MISMATCH        /* the output at the outpoint is not the held tree's: never live */
} gz_c11_t;
/* Buried by the deadline: live only if exit.md 4.4's signing-time check
 * holds with the real deadline (ack tip + funding deadline). Buried later:
 * live only with the whole tree held and leave_by >= buried_at + 1, the
 * time check passing again at the moment of the burial (safety-rule.md C11).
 * Both branches are judged at the burial, so once the output is buried the
 * verdict depends on the chain facts and ack_tip only, never on `tip`.
 *
 * LIVE IS FINAL. signing-round.md 7's state table has no edge from Live to
 * Abandoned: the caller records LIVE in the journal, hands the factory to
 * the exit engine (exit.md), which says when to leave (also when the tip
 * is already past leave_by), and does not call C11 for it again. `tip` only
 * decides WAIT against ABANDONED while the output is not buried. */
gz_c11_t gz_tree_c11(const gz_tree_c11_in_t *in);

/* Run just before sending round_ack (review A, R1): the signing-time check
 * of exit.md 4.4 again, now that the funding deadline's start is known
 * (`ack_tip`, the member's tip as it acks). 1: ack; 0: do not ack (the
 * creation then becomes Abandoned at its unfinished deadline; the host cannot
 * fund without every ack, H1). The check at proposal time used the
 * proposal's tip, which a host that delays round_complete can make stale.
 * `ack_tip` is the height journaled with the ack in funding_status, and
 * gz_tree_c11 must be given the same value: an ack saved and resent after a
 * restart is not judged again at the new tip. `own_depth` is
 * verdict.own_depth, `end_height` the proposal's. */
int gz_tree_may_ack(uint32_t end_height, uint8_t own_depth, uint32_t ack_tip, const gz_tree_conditions_t *cond);

/* ----------------------------------------------------- the host: H1 */

typedef struct {
    size_t n_members;
    const uint8_t *acked;              /* acked[i] = 1: member i's round_ack is held and valid */
    size_t n_nodes;
    const uint8_t *signed_ok;          /* signed_ok[j] = 1: node j is fully signed and verified */
    const uint8_t *proposed_tx; size_t proposed_len;   /* funding_tx as sent in round_propose */
    const uint8_t *to_sign_tx; size_t to_sign_len;     /* what the host is about to sign */
    /* The scripts of the outputs the funding transaction spends, in input order. */
    const uint8_t *const *prev_scripts; const size_t *prev_script_lens;
    size_t n_prev;                     /* how many: must equal the transaction's inputs */
} gz_tree_h1_in_t;
typedef enum {
    GZ_H1_OK = 0,
    GZ_H1_ACK_MISSING,      /* a chosen member's ack is not held */
    GZ_H1_UNSIGNED,         /* a tree transaction is not fully signed and verified */
    GZ_H1_TX_DIFFERS,       /* not exactly the transaction in the proposal */
    GZ_H1_TX_INVALID,       /* the proposed transaction does not parse */
    GZ_H1_NOT_SEGWIT,       /* an input spends a non-witness output, or has a scriptSig */
    GZ_H1_ARGUMENT,
    GZ_H1_EMPTY,            /* no member or no tree transaction: nothing to fund */
    GZ_H1_PREV_COUNT        /* not one spent script per input */
} gz_h1_t;
/* Returns GZ_H1_OK only if the host may sign the funding now; `at` (may be
 * NULL) names the member, node or input that failed. */
gz_h1_t gz_tree_h1(const gz_tree_h1_in_t *in, size_t *at);

#endif
