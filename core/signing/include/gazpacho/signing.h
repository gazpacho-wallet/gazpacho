/* The signing round engine: spec/signing-round.md draft 4, with the messages
 * of spec/messages.md sections 4 and 7 (gazpacho/round_msg.h).
 *
 * One host (participant 0, the coordinator) and its members sign a set of
 * items (one transaction input each) with MuSig2 (BIP 327), tier by tier.
 * The engine is sans-I/O like the node (node.h): events in, actions out,
 * every save listed before the send it justifies, so that the runner's rule
 * (runner.h) gives "save before send".
 *
 * WHAT THIS ENGINE DOES (spec section in brackets)
 *   - The messages of messages.md 7, inside the envelope of section 4. Until
 *     contract v2's P4 gives SEND and MESSAGE_RECEIVED a kind and a scope,
 *     the bytes of a SEND are the whole envelope (protocol, kind, scope,
 *     records) and a received message is read the same way.
 *   - The round identifier of messages.md 7.1 and the tree digest of 7.12,
 *     computed by the engine from the items it holds, which each party built
 *     itself.
 *   - Its own nonce function [8]: secp256k1_musig_nonce_gen with
 *       session_id32 = TH("gazpacho/session-id", 32 bytes from the random
 *                        port tagged secret || incarnation || counter),
 *       msg32 = the item's signature digest, keyagg_cache = the item's
 *       TWEAKED cache, extra_input32 = TH("gazpacho/nonce-extra",
 *       round_id || tier || index). Secret nonces live in this structure
 *       only, are never saved, and are wiped when they have signed, when the
 *       round fails, and by gz_sign_wipe.
 *   - Rules S1 to S6 [3], the member states [7] and the guards [12]: slot
 *     tracking for nonces and partial signatures, strict parsing of every
 *     value from the network before any library call, duplicate keys
 *     refused, one fixed signing mode.
 *   - Verifying each partial signature as it arrives [6.6], combining, and
 *     verifying each final signature from the signed transaction's bytes
 *     with this engine's own BIP 341 signature hash [6.7, 6.8].
 *   - Members address only the host (participant 0); the host addresses each
 *     member by the peer its builder names (contract v2 section 2: a link,
 *     once P4 lands; a peer id until then).
 *
 * WHAT THE EMBEDDING SUPPLIES
 *   - A builder (gz_sign_build_fn) that turns a decoded round_propose into
 *     the items to sign. A member's builder runs the safe-to-sign checks
 *     (gz_tree_member_check) and refuses with their reason; the engine
 *     checks what the builder returns again (keys, signers, scripts, the
 *     funding output, its own current keys).
 *
 * THE CALLER MUST install on `ctx` an illegal-argument callback that does not
 * abort (secp256k1_context_set_illegal_callback). The engine validates every
 * value before it reaches the library, so the callback should never fire;
 * tests count that it never does. */
#ifndef GAZPACHO_SIGNING_H
#define GAZPACHO_SIGNING_H

#include "gazpacho/action.h"
#include "gazpacho/event.h"
#include "gazpacho/ports.h"
#include "gazpacho/round_msg.h"
#include "gazpacho/signing_outcome.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>

/* Limits. Participant and signer sets are uint32_t bit masks, so 32 is the
 * ceiling; Slice 1's T1 at 16 members needs 17 participants and 45 items
 * (docs/notes/slice1-attempt.md, mismatch 7). */
#define GZ_SIGN_MAX_PARTICIPANTS 32
#define GZ_SIGN_MAX_SIGNERS      32
#define GZ_SIGN_MAX_ITEMS        64
#define GZ_SIGN_MAX_TIERS        4
#define GZ_SIGN_MAX_TX           720     /* bytes of one unsigned transaction: core/tree's GZ_TREE_MAX_TX */
#define GZ_SIGN_MAX_FUNDING_TX   8192    /* the funding transaction this engine holds (messages.md allows 100,000) */
#define GZ_SIGN_MAX_ROUNDS       4       /* rounds a party keeps in full */
#define GZ_SIGN_MAX_KNOWN        256     /* round identifiers remembered as refused */
#define GZ_SIGN_MAX_EXPOSURES    256     /* C7 records (funding outpoint, tree digest) held */

/* Message sizes (envelope included). A record's type and length take at
 * most 8 bytes here; 240, the signature, is 67. */
#define GZ_SIGN_REC_OVERHEAD     8
#define GZ_SIGN_MAX_PROPOSAL     (GZ_RMSG_HEADER + 1024 + GZ_SIGN_MAX_FUNDING_TX + 194 * GZ_SIGN_MAX_PARTICIPANTS)
#define GZ_SIGN_MAX_NONCES_MSG   (GZ_RMSG_HEADER + 64 + GZ_SIGN_MAX_ITEMS * 134)
#define GZ_SIGN_MAX_LIST68_MSG   (GZ_RMSG_HEADER + 64 + GZ_SIGN_MAX_ITEMS * 68 + 67)
#define GZ_SIGN_MAX_SMALL_MSG    (GZ_RMSG_HEADER + 128 + 67)
#define GZ_SIGN_MAX_MSG          (GZ_RMSG_HEADER + 64 + GZ_SIGN_MAX_ITEMS * (6 + GZ_SIGN_MAX_SIGNERS * 130))

/* The one signing mode: key path (messages.md 7.1 mode 0), BIP 341 tweak of
 * the ordered aggregate key with the stated merkle root (or none: BIP 86),
 * default hash type, no annex, transactions with exactly one input.
 * Anything else is refused. */
#define GZ_SIGN_MODE_KEYPATH 0u

/* Records the engine saves: spec/journal.md section 9, area Round (0x0002),
 * each a TLV stream under the rules of messages.md 4.2 (gz_rmsg_fields), the
 * field numbers below being this engine's code table. Every saved message is
 * the whole envelope, as sent or received. Start reads the Round area only. */
#define GZ_SIGN_REC_AREA            0x0002u
#define GZ_SIGN_REC_ROUND_STARTED   0x00020002u  /* before a party's nonces of a tier leave (S1), with the guard */
#define GZ_SIGN_REC_ROUND_PROPOSAL  0x00020004u  /* in the batch of the first round_started */
#define GZ_SIGN_REC_EXPOSURE        0x00020006u  /* member: the C7 record and the partial signatures it releases */
#define GZ_SIGN_REC_ROUND_SIGNED    0x00020008u  /* a tier's final signatures */
#define GZ_SIGN_REC_ROUND_COMPLETED 0x0002000au  /* member: complete, ack and its tip; host: complete */
#define GZ_SIGN_REC_ACK_RECEIVED    0x0002000cu  /* host: a member's ack */
#define GZ_SIGN_REC_ROUND_ENDED     0x0002000eu  /* the outcome */
#define GZ_SIGN_REC_FUNDING_STATUS  0x00030006u  /* member: the height at which it acked (with round_completed) */
#define GZ_SIGN_REC_GUARD           0x0004000au  /* the node's guard record (the guard hook) */

/* Field numbers inside the records (all even: a reader that does not know one refuses).
 *   round_started:   2 round_id 32, 4 funding 36 (txid, u32 vout big-endian), 6 purpose u8,
 *                    8 attempt u16, 10 tier u8, 12 items u32 each (1 to 256), 14 own contribution key 33
 *   round_proposal:  2 round_id, 4 the round_propose
 *   exposure:        2 round_id, 4 tier u8, 6 funding 36, 8 funding transaction, 10 tree digest 32,
 *                    12 items of 72 (u32 index, spent 36, sighash 32), 14 the round_partial_sigs
 *   round_signed:    2 round_id, 4 tier u8, 6 finals of 68 (u32 index, 64), 8 member: the round_tier_result
 *   round_completed: 2 round_id, 4 the round_complete, 6 member: the round_ack, 8 member: ack tip u32
 *   ack_received:    2 round_id, 4 the member's contribution key 33, 6 the round_ack
 *   round_ended:     2 round_id, 4 outcome u8 (GZ_SIGN_END_*), 6 reason u16 (messages.md 7.9),
 *                    8 blamed u32 (host: participant bits), 10 why u8, 12 member: the round_abort it sent
 *   funding_status:  2 txid 32, 4 state u8 (0: acked, nothing seen yet), 6 ack height u32
 * The host keeps no per-member round_tier_result bytes: it signs them
 * deterministically (BIP 340 with zero aux_rand) from the finals it saves, so
 * a resend is the same bytes. */
enum { GZ_SIGN_END_ABORTED = 1, GZ_SIGN_END_FAILED, GZ_SIGN_END_ABANDONED, GZ_SIGN_END_DEAD, GZ_SIGN_END_LIVE };

/* Message kinds: messages.md 4.1. */
enum {
    GZ_SIGN_MSG_PROPOSE = GZ_KIND_ROUND_PROPOSE, GZ_SIGN_MSG_NONCES = GZ_KIND_ROUND_NONCES,
    GZ_SIGN_MSG_ALL_NONCES = GZ_KIND_ROUND_ALL_NONCES, GZ_SIGN_MSG_PARTIALS = GZ_KIND_ROUND_PARTIAL_SIGS,
    GZ_SIGN_MSG_RESULT = GZ_KIND_ROUND_TIER_RESULT, GZ_SIGN_MSG_COMPLETE = GZ_KIND_ROUND_COMPLETE,
    GZ_SIGN_MSG_ACK = GZ_KIND_ROUND_ACK, GZ_SIGN_MSG_ABORT = GZ_KIND_ROUND_ABORT,
    GZ_SIGN_MSG_STATUS = GZ_KIND_ROUND_STATUS_REQUEST, GZ_SIGN_MSG_FUNDED = GZ_KIND_FACTORY_FUNDED
};

/* Why a party refused or failed a round (internal; gz_sign_reason maps each
 * to its messages.md 7.9 code). */
enum {
    GZ_SIGN_WHY_NONE = 0, GZ_SIGN_WHY_BUILD, GZ_SIGN_WHY_INVALID_ROUND, GZ_SIGN_WHY_ID_MISMATCH, GZ_SIGN_WHY_BAD_HOST_SIG,
    GZ_SIGN_WHY_KNOWN_ROUND, GZ_SIGN_WHY_BUSY, GZ_SIGN_WHY_BAD_NONCE, GZ_SIGN_WHY_OWN_NONCE_CHANGED, GZ_SIGN_WHY_RESTARTED,
    GZ_SIGN_WHY_DEADLINE, GZ_SIGN_WHY_HOST_ABORT, GZ_SIGN_WHY_BAD_PARTIAL, GZ_SIGN_WHY_EQUIVOCATION, GZ_SIGN_WHY_BAD_RESULT,
    GZ_SIGN_WHY_HOST_RESTART, GZ_SIGN_WHY_MEMBER_ABORT, GZ_SIGN_WHY_BAD_MESSAGE, GZ_SIGN_WHY_SUPERSEDED,
    GZ_SIGN_WHY_NOT_MY_KEY, GZ_SIGN_WHY_CAPACITY, GZ_SIGN_WHY_OTHER_TREE, GZ_SIGN_WHY_ACK_REFUSED
};
/* The messages.md 7.9 reason a party sends for `why` (`built` is the
 * builder's own reason, used for GZ_SIGN_WHY_BUILD). */
uint16_t gz_sign_reason(uint8_t why, uint16_t built);

/* A decoded round message other than round_propose: one view of the per-kind
 * decoders of round_msg.h, with pointers into the bytes. Entry layouts:
 * NONCES (u32 index, 66 nonce, 64 sig); ALL_NONCES (u32 index, u16 k,
 * k x (66, 64)); PARTIALS (u32 index, 32 psig, 32 set digest); RESULT
 * (u32 index, 64 sig); ABORT (u32 index, when it names items). For
 * round_propose only `kind`, `scope`, `records` and `round_id` are set. */
typedef struct {
    uint16_t kind;
    const uint8_t *scope, *records;
    size_t records_len;
    const uint8_t *round_id, *held, *sig;
    uint8_t tier, has_tier;
    uint16_t reason;
    size_t signed_len;              /* record bytes the signature covers (messages.md 4.3) */
    uint16_t n;
    const uint8_t *entry[GZ_RMSG_MAX_ENTRIES];
} gz_sign_msg_t;

/* One item: one transaction input to sign. */
typedef struct {
    uint8_t tier;
    uint8_t mode;                   /* GZ_SIGN_MODE_KEYPATH */
    uint8_t has_merkle_root;
    uint8_t merkle_root[32];
    uint8_t n_signers;              /* 2.. */
    uint8_t signers[GZ_SIGN_MAX_SIGNERS];   /* positions among the participants, strictly increasing; the host (0) first */
    uint64_t spent_amount;
    uint8_t spent_script[34];       /* must be the P2TR output of the tweaked aggregate */
    uint16_t tx_len;
    uint8_t tx[GZ_SIGN_MAX_TX];     /* unsigned, legacy serialisation, one input */
} gz_sign_item_t;

/* A round as one party built it. Items are in index order, tiers ascending
 * (index unique in the round across tiers, spec section 1). */
typedef struct {
    /* Filled by the engine from the proposal before the builder is called;
     * the builder must leave them as they are. */
    uint8_t purpose;
    uint8_t n_participants;
    gz_tree_participant_t participants[GZ_SIGN_MAX_PARTICIPANTS];   /* host first */
    uint8_t terms_digest[32];       /* record 10: the frozen current-values digest */
    uint8_t funding_txid[32];       /* record 12, internal order */
    uint32_t funding_vout;
    uint64_t funding_amount;        /* record 14 */
    uint8_t funding_script[34];     /* record 16 */
    uint32_t end_height;            /* record 24 */
    /* Filled by the builder. */
    uint8_t chain[32];              /* the outer terms' chain hash (7.1) */
    uint8_t host_key[33];           /* the outer terms' host key: must be participant 0's contribution key */
    uint8_t outer_digest[32];       /* the lobby identifier: the scope of every round message */
    uint64_t peer[GZ_SIGN_MAX_PARTICIPANTS];  /* host: where participant j is reached; member: peer[0] the host, the rest 0 */
    uint8_t n_tiers;
    uint16_t n_items;
    gz_sign_item_t items[GZ_SIGN_MAX_ITEMS];
    /* Computed by the engine: messages.md 7.12. */
    uint8_t tree_digest[32];
} gz_sign_def_t;

/* What a builder is given. */
typedef struct {
    const gz_rmsg_propose_t *msg;   /* the decoded round_propose; msg->p is the gz_tree_proposal_t */
    const uint8_t *scope;           /* its envelope's scope (32) */
    uint64_t peer;                  /* member: the peer it came from; host: 0 */
    int replay;                     /* 1: a saved round rebuilt at start: rebuild only, no checks of time or tip */
    /* What a member's checks need from the engine's records (C7, C10:
     * gz_tree_member_check): every exposure record held, and the funding
     * outpoints of its unresolved rounds. */
    const gz_tree_exposure_t *exposures; size_t n_exposures;
    const gz_tree_outpoint_t *unresolved; size_t n_unresolved;
} gz_sign_build_in_t;
/* Build the round from a proposal. Returns 0 and fills `out`, or the
 * messages.md 7.9 reason to refuse with (1, 5, 6, 9, 11 or 12). Must be a
 * deterministic function of the proposal and the lobby when `replay` is 1. */
typedef uint16_t (*gz_sign_build_fn)(void *ctx, const gz_sign_build_in_t *in, gz_sign_def_t *out);

/* What the host proposes. round_id and host_random are the engine's. */
typedef struct {
    const gz_tree_proposal_t *p;    /* every field of messages.md 7.2; participants host first */
    const uint8_t *check_id;        /* 32: the check this attempt follows */
    int has_attempt;
    uint16_t attempt;
} gz_sign_begin_t;

typedef struct gz_sign_round gz_sign_round_t;

/* Host only: the next attempt after a failed one. `blamed` (bit i =
 * participant i of the failed round) are to be left out; `released` is 1 if
 * any partial signature may have left a member, in which case the next
 * attempt must use a new funding outpoint (H11). Returns 1 and fills `next`
 * (its pointers into the callback's own storage, valid until the next call),
 * or 0 for "no further attempt". */
typedef struct { const gz_sign_round_t *failed; uint32_t blamed; int released; } gz_sign_retry_in_t;
typedef int (*gz_sign_retry_fn)(void *ctx, const gz_sign_retry_in_t *in, gz_sign_begin_t *next);

typedef struct {
    int host;                       /* 1: this party is participant 0 */
    const secp256k1_context *ctx;
    uint8_t factory_secret[32];
    uint8_t contribution_secret[32];
    gz_sign_build_fn build;
    gz_sign_retry_fn retry;
    void *build_ctx;
    uint64_t tick_ms;               /* period of the engine's one timer */
    uint32_t resend_ticks;          /* resend what is unanswered every this many ticks */
    uint32_t deadline_ticks;        /* a step not finished after this many ticks fails */
    uint32_t status_ticks;          /* host: at most one status answer per round and member in this many ticks */
    uint32_t max_attempts;          /* host: attempts in all, over restarts */
    uint32_t unfinished_ticks;      /* member: an Unfinished creation round is Abandoned after this many more ticks (0: never) */
    /* Member, before every round_ack it would make (gz_tree_may_ack): 1 to
     * ack, with its tip in *ack_tip (saved with the ack, funding_status);
     * 0 not to ack (the round is then Abandoned at its unfinished deadline).
     * NULL: always ack, tip 0. */
    int (*may_ack)(void *ctx, const gz_sign_round_t *r, uint32_t *ack_tip);
    /* The node's guard record (journal.md 8.3) for the batch of every
     * round_started: 1 and *rec filled (type GZ_SIGN_REC_GUARD, bytes valid
     * until the call returns), or 0 for none. NULL: none (tests). */
    int (*guard)(void *ctx, gz_record_t *rec);
    /* Host: the outcome of a round or an attempt, with the action list it may
     * append to (the lobby's answer). NULL: none. */
    gz_status_t (*outcome)(void *ctx, const gz_sign_outcome_t *o, gz_action_list_t *out);
    void *hook_ctx;                 /* given to may_ack, guard and outcome */
} gz_sign_config_t;

/* Tier and round states (spec section 7). */
enum { GZ_SIGN_TIER_NONE = 0, GZ_SIGN_TIER_NONCES, GZ_SIGN_TIER_SIGNED, GZ_SIGN_TIER_DONE };
enum {
    GZ_SIGN_ROUND_FREE = 0, GZ_SIGN_ROUND_ACTIVE, GZ_SIGN_ROUND_ABORTED, GZ_SIGN_ROUND_UNFINISHED,
    GZ_SIGN_ROUND_COMPLETE, GZ_SIGN_ROUND_FAILED /* host: attempt given up */, GZ_SIGN_ROUND_DONE /* host: every ack */,
    GZ_SIGN_ROUND_ABANDONED, GZ_SIGN_ROUND_DEAD, GZ_SIGN_ROUND_LIVE   /* member: resolved (spec section 7) */
};

struct gz_sign_round {
    uint8_t state, tier, ever_partial, me, why;
    uint16_t built;                 /* the builder's reason, when why is GZ_SIGN_WHY_BUILD */
    uint32_t seq;                   /* order in which this party took the round up */
    uint8_t tier_state[GZ_SIGN_MAX_TIERS];
    uint8_t id[32];
    uint32_t ticks, blamed;
    gz_sign_def_t def;
    uint32_t proposal_len;
    uint8_t proposal[GZ_SIGN_MAX_PROPOSAL];
    secp256k1_musig_keyagg_cache cache[GZ_SIGN_MAX_ITEMS];
    uint8_t digest[GZ_SIGN_MAX_ITEMS][32];   /* each item's signature digest */
    uint8_t tweak[GZ_SIGN_MAX_ITEMS][32];    /* each item's taproot tweak (7.1 mode_data) */
    /* slots: bit s of have_nonce[i] = signer s of item i has a nonce here */
    uint32_t have_nonce[GZ_SIGN_MAX_ITEMS], have_psig[GZ_SIGN_MAX_ITEMS];
    uint8_t nonce[GZ_SIGN_MAX_ITEMS][GZ_SIGN_MAX_SIGNERS][66];
    uint8_t nonce_sig[GZ_SIGN_MAX_ITEMS][GZ_SIGN_MAX_SIGNERS][64];
    uint8_t psig[GZ_SIGN_MAX_ITEMS][GZ_SIGN_MAX_SIGNERS][32];
    secp256k1_musig_session session[GZ_SIGN_MAX_ITEMS];
    uint8_t final_sig[GZ_SIGN_MAX_ITEMS][64];
    uint8_t have_final[GZ_SIGN_MAX_ITEMS];
    /* secret nonces: memory only; serial 0 = none */
    secp256k1_musig_secnonce secnonce[GZ_SIGN_MAX_ITEMS];
    uint64_t secnonce_serial[GZ_SIGN_MAX_ITEMS];
    uint8_t all_nonces_digest[GZ_SIGN_MAX_TIERS][32];
    uint8_t have_all_nonces[GZ_SIGN_MAX_TIERS];
    uint32_t acked;                 /* host: bit j = participant j acked */
    uint64_t status_tick[GZ_SIGN_MAX_PARTICIPANTS];   /* host: the tick a status request was last answered + 1 */
    /* member: its own saved messages and the host's it verified */
    uint32_t partials_len[GZ_SIGN_MAX_TIERS];
    uint8_t partials_msg[GZ_SIGN_MAX_TIERS][GZ_SIGN_MAX_LIST68_MSG];
    uint32_t result_len[GZ_SIGN_MAX_TIERS];
    uint8_t result_msg[GZ_SIGN_MAX_TIERS][GZ_SIGN_MAX_LIST68_MSG];
    uint32_t nonces_len;            /* this incarnation's nonce message, for resending */
    uint8_t nonces_msg[GZ_SIGN_MAX_NONCES_MSG];
    uint32_t complete_len;          /* host: the round_complete it sends; member: the one it verified */
    uint8_t complete_msg[GZ_SIGN_MAX_SMALL_MSG];
    uint32_t tail_len;              /* member: its ack or abort */
    uint8_t tail_msg[GZ_SIGN_MAX_SMALL_MSG];
    uint8_t evidence;               /* a second, different, validly signed proposal under this identifier was seen */
    uint8_t ack_refused;            /* member: may_ack said no */
    uint8_t proposal_saved;         /* round_proposal is in the journal */
    uint16_t attempt;               /* record 7, for round_started */
    uint8_t old_epoch;              /* member: started with a key of an earlier epoch (S5): kept refused, never resumed */
    uint32_t ack_tip;               /* member: its tip when it acked (funding_status) */
};

/* Caller-allocated (it is large: allocate it, do not put it on the stack);
 * treat the fields as private. */
typedef struct {
    gz_sign_config_t cfg;
    gz_ports_t ports;
    uint64_t incarnation;
    uint64_t session_counter;       /* session_id32s made in this incarnation (S4, section 8) */
    uint64_t attempt_counter;       /* host: attempts proposed in this incarnation (S4) */
    uint64_t next_serial;           /* secret nonces made in this incarnation */
    uint64_t tick;                  /* timer ticks in this incarnation */
    secp256k1_keypair factory_kp, contribution_kp;
    secp256k1_pubkey factory_pk;
    uint8_t factory_key[33], contribution_key[33];   /* this party's current keys, compressed */
    uint32_t attempts, next_seq;
    gz_sign_round_t rounds[GZ_SIGN_MAX_ROUNDS];
    uint8_t known[GZ_SIGN_MAX_KNOWN][32];
    size_t n_known;
    uint64_t counters[9];           /* see GZ_SIGN_COUNT_* */
    uint8_t scratch[GZ_SIGN_MAX_MSG];
    gz_sign_def_t scratch_def;
    gz_sign_round_t pending;        /* a round is checked here before it takes a slot */
    gz_rmsg_propose_t prop;         /* the proposal being read */
    /* C7: every exposure record this party holds, of any epoch, never removed. */
    gz_tree_exposure_t exposures[GZ_SIGN_MAX_EXPOSURES];
    size_t n_exposures;
    gz_tree_outpoint_t unresolved[GZ_SIGN_MAX_ROUNDS];
    /* Work areas for large temporaries of functions the compiler inlines:
     * on the stack, gcc's AddressSanitizer would guard them with calls the
     * isolation check refuses. */
    secp256k1_musig_partial_sig work_psig[GZ_SIGN_MAX_SIGNERS];
    uint8_t work_tx[GZ_SIGN_MAX_TX + 80];
    uint8_t work_records[GZ_SIGN_MAX_PROPOSAL];
    uint8_t work_rec2[2048];
    gz_sign_msg_t work_msg;
    uint8_t work_keys[GZ_SIGN_MAX_PARTICIPANTS][33];
} gz_sign_t;

/* What the engine counts, for tests and reports. */
enum {
    GZ_SIGN_COUNT_NONCES_MADE = 0, GZ_SIGN_COUNT_PARTIALS_MADE, GZ_SIGN_COUNT_PSIGS_VERIFIED,
    GZ_SIGN_COUNT_FINALS_VERIFIED, GZ_SIGN_COUNT_BLAME_FAULT, GZ_SIGN_COUNT_BLAME_SILENT,
    GZ_SIGN_COUNT_REJECTED, GZ_SIGN_COUNT_DUPLICATES, GZ_SIGN_COUNT_EVIDENCE
};

/* Prepare an engine. `incarnation` is the runner's (runner.h): it never
 * repeats, also across restores, and is mixed into every session_id32.
 * Returns GZ_ERR_ARGUMENT for a missing argument or a bad secret key. */
gz_status_t gz_sign_init(gz_sign_t *e, const gz_sign_config_t *cfg, const gz_ports_t *ports, uint64_t incarnation);

/* Start or restart from storage, in one step (`*more` is set to 0). Same
 * contract as gz_node_start. A member answers per item (S2): a round whose
 * nonce was sent and whose partial signature was not becomes Aborted (no
 * partial signature ever sent) or Unfinished, and is answered with an abort;
 * saved partial signatures are resent (S3). A host fails an unfinished
 * attempt (spec H13) and begins the next one. */
gz_status_t gz_sign_start(gz_sign_t *e, const gz_storage_reader_t *storage, gz_action_list_t *out, int *more);

/* Handle one event; same contract as gz_node_handle. Messages that do not
 * parse, or that this party should not get, are counted and ignored. */
gz_status_t gz_sign_handle(gz_sign_t *e, const gz_event_t *event, gz_action_list_t *out);

/* Host: begin a round. GZ_ERR_ARGUMENT if not a host, a round is still
 * running, the attempts are spent, or the proposal or the builder refuses. */
gz_status_t gz_sign_begin(gz_sign_t *e, const gz_sign_begin_t *b, gz_action_list_t *out);

/* Member: the round's end as the embedding judged it from the chain
 * (safety-rule.md C11, C4(d)): GZ_SIGN_END_LIVE, _DEAD or _ABANDONED, saved as
 * round_ended. Rounds that are Complete, Unfinished or Abandoned only.
 * GZ_ERR_ARGUMENT otherwise. */
gz_status_t gz_sign_resolve(gz_sign_t *e, const uint8_t round_id[32], uint8_t outcome, gz_action_list_t *out);

/* The exposure records held (C7), for the embedding's checks. */
size_t gz_sign_exposures(const gz_sign_t *e, const gz_tree_exposure_t **out);

/* Write every live secret nonce as (8-byte little-endian serial, the 132
 * secret-nonce bytes) to `out`; returns the length, or 0 if `cap` is short.
 * For the simulator's inspection hook: the property is judged on these. */
size_t gz_sign_inspect_secrets(const gz_sign_t *e, uint8_t *out, size_t cap);

/* The newest round this party holds, or NULL. */
const gz_sign_round_t *gz_sign_latest(const gz_sign_t *e);

/* Erase every secret this engine holds. */
void gz_sign_wipe(gz_sign_t *e);

/* --- Building blocks, exposed for the tests and the fuzzer. --- */

/* SHA-256 and BIP 340 tagged hashes. */
typedef struct { uint32_t h[8]; uint64_t n; uint8_t buf[64]; } gz_sign_sha256_t;
void gz_sign_sha256_init(gz_sign_sha256_t *s);
void gz_sign_sha256_write(gz_sign_sha256_t *s, const uint8_t *data, size_t len);
void gz_sign_sha256_done(gz_sign_sha256_t *s, uint8_t out[32]);
void gz_sign_tagged_init(gz_sign_sha256_t *s, const char *tag);

/* A transaction with one input, legacy or with a witness of one item. */
typedef struct {
    const uint8_t *bytes; size_t len;
    const uint8_t *outpoint;       /* 36 bytes */
    const uint8_t *sequence;       /* 4 bytes */
    size_t outputs_at, outputs_end;
    const uint8_t *witness_item; size_t witness_len;   /* NULL if legacy */
} gz_sign_tx_t;
/* 1 if `bytes` is exactly one such transaction (canonical sizes, nothing left over). */
int gz_sign_tx_parse(const uint8_t *bytes, size_t len, gz_sign_tx_t *tx);
/* BIP 341 key-path signature hash, default type, no annex, input 0. */
void gz_sign_tx_sighash(const gz_sign_tx_t *tx, uint64_t amount, const uint8_t script[34], uint8_t out[32]);
/* The unsigned transaction with a one-item witness `sig64` added. Returns
 * the length, or 0 if it does not parse or `cap` is short. */
size_t gz_sign_tx_attach(const uint8_t *tx, size_t len, const uint8_t sig64[64], uint8_t *out, size_t cap);
/* 1 if `signed_tx` spends (amount, script) with a valid 64-byte key-path
 * signature, judged from its bytes alone. */
int gz_sign_tx_verify(const secp256k1_context *ctx, const uint8_t *signed_tx, size_t len, uint64_t amount, const uint8_t script[34]);
/* Output `vout`: its amount and script (a pointer into the bytes). 0 if none. */
int gz_sign_tx_output(const gz_sign_tx_t *tx, uint32_t vout, uint64_t *amount, const uint8_t **script, size_t *script_len);
/* Output `vout` of any transaction without witness (inputs of any number):
 * 1 and its amount and script, or 0 if the bytes are not exactly one such
 * transaction or it has no such output. */
int gz_sign_tx_find_output(const uint8_t *tx, size_t len, uint32_t vout, uint64_t *amount, const uint8_t **script, size_t *script_len);
/* The txid (internal order) of a transaction without witness. */
void gz_sign_txid(const uint8_t *tx, size_t len, uint8_t out[32]);

/* 1 if `bytes` is one envelope holding a well-formed round message
 * (messages.md 4 and 7), 0 otherwise. */
int gz_sign_decode(const uint8_t *bytes, size_t len, gz_sign_msg_t *m);

/* messages.md 7.1 and 7.12 over a definition whose items carry their
 * signature digests and tweaks (`digest`, `tweak`: n_items x 32). */
void gz_sign_round_id(const gz_sign_def_t *d, const uint8_t (*digest)[32], const uint8_t (*tweak)[32],
                      const uint8_t host_random[32], uint8_t out[32]);
void gz_sign_tree_digest(const gz_sign_def_t *d, const uint8_t (*digest)[32], const uint8_t (*tweak)[32], uint8_t out[32]);

#endif
