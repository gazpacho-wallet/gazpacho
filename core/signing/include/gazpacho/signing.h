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
 *   - The messages of messages.md 7 in contract v2's terms: a SEND and a
 *     received message carry a kind, a scope and the records. Inside, the
 *     engine still builds, checks and saves each message as its whole
 *     envelope (protocol, kind, scope, records: journal.md 9), so saved
 *     bytes and resends stay byte for byte.
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
 *   - LINKS FROM KEYS (composite-node.md section 3), never a table: the host
 *     reaches participant j on (participant 0's contribution key,
 *     participant j's contribution key); a member reaches only the host, on
 *     (its own contribution key in the round, participant 0's contribution
 *     key). A message counts only on the round's own link.
 *   - KEYS PER ROUND (2.5): the engine holds no key. It asks the embedding's
 *     key hook for this party's keypairs under a round's scope each time it
 *     signs, and wipes them when the operation is done. A hook that gives no
 *     key is not an error: a new proposal is ignored, and a running round
 *     answers with what it saved.
 *
 * WHAT THE EMBEDDING SUPPLIES
 *   - A builder (gz_sign_build_fn) that turns a decoded round_propose into
 *     the items to sign. A member's builder runs the safe-to-sign checks
 *     (gz_tree_member_check) against what its lobby accepted and refuses
 *     with their reason, or tells the engine to ignore the proposal; the
 *     engine checks what the builder returns again (keys, signers, scripts,
 *     the funding output, its own current keys).
 *   - The key hook, and the outcome hook through which every outcome of a
 *     round reaches the lobby (both roles), with its check and attempt.
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
/* Rounds a party keeps in full: one Active round per scope (composite-node.md
 * 8.1, H8) for each of the node's 8 lobbies (core/node holds the two
 * constants together with a static assertion). */
#define GZ_SIGN_MAX_ROUNDS       8
/* Host: rounds that left the full slots Complete, Done or Failed, kept
 * compactly (their finals, their complete, who signs what, the outcome) so
 * that a member's status request is still answered (H12) and the reason-6
 * excuse still sees them, until the embedding forgets their scope at its
 * Closing end (gz_sign_forget_scope). Full: the oldest goes. */
#define GZ_SIGN_MAX_KEPT         64
#define GZ_SIGN_MAX_KNOWN        256     /* the newest refused identifiers, kept exactly (a ring) */
/* Every refused identifier, however many: a Bloom filter of 2^20 bits with 10
 * positions per identifier. It has no false negatives, so a refused
 * identifier is never forgotten; a false positive only refuses a new round
 * (abort reason 3). With 10,000 identifiers the chance of one is below
 * 10^-10, with 100,000 about 1%. The positions are public: a host that grinds
 * identifiers to hit one only gets its own round refused. Fixed memory, no
 * cap: the set never makes a start fail (review A, F2). */
#define GZ_SIGN_KNOWN_FILTER_BITS 20
#define GZ_SIGN_KNOWN_FILTER_K    10
/* C7 records (funding outpoint, tree digest) held in memory: one per funding
 * outpoint this party released a partial signature for whose creation is not
 * Dead (safety-rule.md C4(d): a Dead record stays in the journal and is no
 * longer consulted, so it leaves this set when its round is resolved Dead:
 * review B, B8). While the set is full a new outpoint is refused (abort
 * reason 9), never dropped, and signing comes back as entries are resolved
 * Dead; a journal holding more live ones still starts, with every new round
 * refused until a start finds room (review A, F2).
 *
 * One entry per (funding outpoint, tree, round): two attempts of one tree on
 * one outpoint each keep their own state, ticks and resolution (P4.3 item 6).
 * Accepted limit (item 14): 4,096 rounds against one member could fill the
 * set with Abandoned entries; the remedy is outside the engine (the lobby's
 * limits now, a set kept on storage later). */
#define GZ_SIGN_MAX_EXPOSURES    4096
/* The nonce step's deadline is the proposal's nonces_due_ms (messages.md 7.2)
 * for both sides, read from the same signed bytes, so that two configurations
 * cannot drift apart. The host counts it in whole ticks, rounded down, and
 * refuses to begin a round whose nonces_due_ms is under one of its ticks. A
 * member rounds up and then waits a whole step timeout (deadline_ticks) more
 * before it gives up (abort reason 4), counted from when it sent its nonces.
 * A member loses nothing by waiting (nothing is exposed in the nonce step,
 * and the host's own deadline ends the attempt and tells it so), so the
 * margin is made too large for a late host timer, a slow link or a Tor
 * circuit to reach (review B's final check, R1): the host's deadline always
 * comes first, an honest member never gives up before the host does, and a
 * reason 4 that reaches the host while its attempt still runs is not an
 * honest one (N1 and N1b). The terms' step timeout bounds nonces_due_ms on
 * the member (gz_tree_member_check, GZ_CHK_C8_DEADLINES). */

/* Message sizes (envelope included). A record's type and length take at
 * most 8 bytes here; 240, the signature, is 67. */
#define GZ_SIGN_REC_OVERHEAD     8
#define GZ_SIGN_MAX_PROPOSAL     (GZ_RMSG_HEADER + 1024 + GZ_SIGN_MAX_FUNDING_TX + 194 * GZ_SIGN_MAX_PARTICIPANTS)
#define GZ_SIGN_MAX_NONCES_MSG   (GZ_RMSG_HEADER + 64 + GZ_SIGN_MAX_ITEMS * 134)
#define GZ_SIGN_MAX_LIST68_MSG   (GZ_RMSG_HEADER + 64 + GZ_SIGN_MAX_ITEMS * 68 + 67)
#define GZ_SIGN_MAX_SMALL_MSG    (GZ_RMSG_HEADER + 128 + 67)
#define GZ_SIGN_MAX_MSG          (GZ_RMSG_HEADER + 64 + GZ_SIGN_MAX_ITEMS * (6 + GZ_SIGN_MAX_SIGNERS * 130))

/* The largest record of each kind the engine saves (review B, B1, B2, B12):
 * one table for the writer and for the reader at start. A field is its type
 * (below 253: one byte), its BigSize length and its bytes. Everything a
 * record holds is bounded before it is saved: a message from a peer longer
 * than its field is refused or dropped on receipt (the proposal with reason
 * 9, an ack counted and ignored), and the work areas the records are written
 * in are sized from these (static assertions in signing.c), so that no
 * writer overflows and every record saved is one the start accepts. */
#define GZ_SIGN_FIELD(n)             (1u + ((n) < 253u ? 1u : 3u) + (n))
#define GZ_SIGN_REC_STARTED_MAX      (GZ_SIGN_FIELD(32u) + GZ_SIGN_FIELD(36u) + GZ_SIGN_FIELD(1u) + GZ_SIGN_FIELD(2u) + GZ_SIGN_FIELD(1u) +                                       GZ_SIGN_FIELD(4u * GZ_SIGN_MAX_ITEMS) + GZ_SIGN_FIELD(33u))
#define GZ_SIGN_REC_PROPOSAL_MAX     (GZ_SIGN_FIELD(32u) + GZ_SIGN_FIELD(GZ_SIGN_MAX_PROPOSAL))
#define GZ_SIGN_REC_EXPOSURE_MAX     (GZ_SIGN_FIELD(32u) + GZ_SIGN_FIELD(1u) + GZ_SIGN_FIELD(36u) + GZ_SIGN_FIELD(GZ_SIGN_MAX_FUNDING_TX) +                                       GZ_SIGN_FIELD(32u) + GZ_SIGN_FIELD(72u * GZ_SIGN_MAX_ITEMS) + GZ_SIGN_FIELD(GZ_SIGN_MAX_LIST68_MSG) + GZ_SIGN_FIELD(8u))
#define GZ_SIGN_REC_SIGNED_MAX       (GZ_SIGN_FIELD(32u) + GZ_SIGN_FIELD(1u) + GZ_SIGN_FIELD(68u * GZ_SIGN_MAX_ITEMS) + GZ_SIGN_FIELD(GZ_SIGN_MAX_LIST68_MSG))
#define GZ_SIGN_REC_COMPLETED_MAX    (GZ_SIGN_FIELD(32u) + 2u * GZ_SIGN_FIELD(GZ_SIGN_MAX_SMALL_MSG) + GZ_SIGN_FIELD(4u))
#define GZ_SIGN_REC_ACK_MAX          (GZ_SIGN_FIELD(32u) + GZ_SIGN_FIELD(33u) + GZ_SIGN_FIELD(GZ_SIGN_MAX_SMALL_MSG))
#define GZ_SIGN_REC_ENDED_MAX        (GZ_SIGN_FIELD(32u) + GZ_SIGN_FIELD(1u) + GZ_SIGN_FIELD(2u) + GZ_SIGN_FIELD(4u) + GZ_SIGN_FIELD(1u) +                                       GZ_SIGN_FIELD(GZ_SIGN_MAX_SMALL_MSG))
#define GZ_SIGN_REC_FUNDING_MAX      (GZ_SIGN_FIELD(32u) + GZ_SIGN_FIELD(1u) + GZ_SIGN_FIELD(4u))
/* The two work areas: the large records, and the small ones that share a batch with a large one. */
#define GZ_SIGN_WORK_RECORDS         GZ_SIGN_REC_EXPOSURE_MAX
#define GZ_SIGN_WORK_REC2            512u

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
#define GZ_SIGN_REC_GUARD           0x0004000au  /* the node's guard record (the guard hook) */
/* The engine no longer writes funding_status (composite-node.md 7.3): the
 * member's ack tip is field 8 of its round_completed, and the funding engine
 * (P4.5) writes the first funding_status from it. */

/* Field numbers inside the records (all even: a reader that does not know one refuses).
 *   round_started:   2 round_id 32, 4 funding 36 (txid, u32 vout big-endian), 6 purpose u8,
 *                    8 attempt u16, 10 tier u8, 12 items u32 each (1 to 256), 14 own contribution key 33
 *   round_proposal:  2 round_id, 4 the round_propose
 *   exposure:        2 round_id, 4 tier u8, 6 funding 36, 8 funding transaction, 10 tree digest 32,
 *                    12 items of 72 (u32 index, spent 36, sighash 32), 14 saved at u64 (ms, the keep
 *                    clock), 16 the round_partial_sigs (last: the record ends in its signature)
 *   round_signed:    2 round_id, 4 tier u8, 6 finals of 68 (u32 index, 64), 8 member: the round_tier_result
 *   round_completed: 2 round_id, 4 the round_complete, 6 member: the round_ack, 8 member: ack tip u32
 *   ack_received:    2 round_id, 4 the member's contribution key 33, 6 the round_ack
 *   round_ended:     2 round_id, 4 outcome u8 (GZ_SIGN_END_*), 6 reason u16 (messages.md 7.9),
 *                    8 blamed u32 (host: participant bits), 10 why u8, 12 member: the round_abort it sent
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
    GZ_SIGN_WHY_NOT_MY_KEY, GZ_SIGN_WHY_CAPACITY, GZ_SIGN_WHY_OTHER_TREE, GZ_SIGN_WHY_ACK_REFUSED,
    GZ_SIGN_WHY_IGNORE,             /* a proposal the builder said to ignore: never answered */
    GZ_SIGN_WHY_BUDGET,             /* host: the signing budget ended with the round in flight */
    GZ_SIGN_WHY_CANCELLED,          /* host: the lobby was cancelled with the round in flight */
    GZ_SIGN_WHY_MEMBER_LEFT         /* host: a chosen member left while it still owed its part */
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
    uint8_t n_tiers;
    uint16_t n_items;
    gz_sign_item_t items[GZ_SIGN_MAX_ITEMS];
    /* Computed by the engine: messages.md 7.12. */
    uint8_t tree_digest[32];
} gz_sign_def_t;

/* What a builder is given. */
typedef struct {
    const gz_rmsg_propose_t *msg;   /* the decoded round_propose; msg->p is the gz_tree_proposal_t */
    const uint8_t *scope;           /* its envelope's scope (32); the host's own build: NULL */
    const gz_link_t *link;          /* member: the link it came on; host, or a replay: NULL */
    int replay;                     /* 1: a saved round rebuilt at start: rebuild only, no checks of time or tip */
    /* This party's own keys under the scope, as the key hook gave them (a
     * member's for C7's fresh-key row, gz_tree_member_check); a replay: the
     * contribution key saved with the round, and no factory key. */
    const uint8_t *own_factory_key, *own_contribution_key;
    /* What a member's checks need from the engine's records (C7, C10:
     * gz_tree_member_check): every exposure record held, and the funding
     * outpoints of its unresolved rounds. */
    const gz_tree_exposure_t *exposures; size_t n_exposures;
    const gz_tree_outpoint_t *unresolved; size_t n_unresolved;
} gz_sign_build_in_t;
/* Build the round from a proposal. Returns 0 and fills `out`, or the
 * messages.md 7.9 reason to refuse with (1, 5, 6, 9, 11 or 12), or
 * GZ_SIGN_BUILD_IGNORE: a member's proposal for a check its lobby did not
 * accept (composite-node.md 13: not answered, withdrawn, not chosen, spent),
 * which is ignored without an answer, so that a hostile host gets no signed
 * refusal for nothing. Must be a deterministic function of the proposal and
 * the lobby when `replay` is 1. */
typedef uint16_t (*gz_sign_build_fn)(void *ctx, const gz_sign_build_in_t *in, gz_sign_def_t *out);
#define GZ_SIGN_BUILD_IGNORE 0xffffu

/* What the host proposes. round_id and host_random are the engine's. */
typedef struct {
    const gz_tree_proposal_t *p;    /* every field of messages.md 7.2; participants host first */
    const uint8_t *scope;           /* 32: the lobby (the outer digest the builder will name) */
    const uint8_t *check_id;        /* 32: the check this attempt follows */
    int has_attempt;                /* required (messages.md 7.2 record 7) */
    uint16_t attempt;
    /* The Unix ms at which the lobby's signing budget ends (composite-node.md
     * 9.4): from the hand-off on, the engine alone owns the budget; at expiry
     * it fails the attempt and reports Failed. 0: no budget. Memory only: a
     * restarted host fails every attempt in flight anyway (H13). */
    uint64_t budget_end_ms;
} gz_sign_begin_t;

typedef struct gz_sign_round gz_sign_round_t;

/* The round that made an exposure record, and its state when it left memory
 * (GZ_SIGN_ROUND_FREE while it is held): C10 and gz_sign_resolve reach a
 * round through it after the round has left the slots (review A, F3). One
 * per round: two attempts with one tree on one outpoint have two. */
typedef struct {
    uint8_t round_id[32];
    uint8_t state, why;
    uint32_t ticks;                 /* timer ticks since it left memory Unfinished (the unfinished deadline: review B, B5) */
    uint8_t scope[32];              /* its lobby: the scope of the round_partial_sigs it saved (review of PR 81, S1) */
    uint8_t has_scope;              /* 0: not known (fail closed) */
    uint32_t ack_tip;               /* the member's tip when it acked, if it did (its C11 funding deadline counts from it) */
    uint64_t since_ms;              /* the keep clock when its exposure record was saved (the unfinished deadline counts from it) */
} gz_sign_exposed_t;

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
    gz_sign_build_fn build;
    /* Host: the next attempt after a failed one (above). NULL, or a hook that
     * returns 0: no further attempt, the outcome Retry goes to the lobby,
     * which decides what follows (composite-node.md 9.2: the composite's
     * hook is always "no further attempt"). */
    gz_sign_retry_fn retry;
    void *build_ctx;
    uint64_t tick_ms;               /* period of the engine's one timer */
    uint32_t resend_ticks;          /* resend what is unanswered every this many ticks */
    uint32_t deadline_ticks;        /* a step not finished after this many ticks fails (but the nonce step: the proposal's nonces_due_ms) */
    uint32_t status_ticks;          /* host: at most one status answer per round and member in this many ticks */
    uint32_t unfinished_ticks;      /* member: an Unfinished creation round is Abandoned after this many more ticks (0: never),
                                     * or once this many ticks of tick_ms have passed on the keep clock since its exposure
                                     * record was saved, whichever comes first: a start does not begin the count again */
    uint32_t funding_deadline_blocks; /* member: a Complete round is Abandoned once a tip is past its ack tip plus this
                                     * (C11's funding deadline: a host that never funds does not keep it for good); 0: never */
    /* THE KEY HOOK (composite-node.md 2.5): this party's keypairs under
     * `scope`, the lobby the round belongs to. `factory` and `contribution`
     * are filled when not NULL; `terms_digest` (32, the round's frozen terms
     * digest, record 10) names what the factory key is for and may be NULL
     * when only the contribution key is asked for. Returns 1 if every one
     * asked for was filled, else 0: no key (no lobby for the scope, a key of
     * another epoch, or, with AT_JOIN, no scoped secret for that scope and
     * digest). The hook never looks at a gate. The engine wipes the keypairs
     * as soon as the operation is done. */
    int (*keys)(void *ctx, const uint8_t scope[32], const uint8_t *terms_digest, secp256k1_keypair *factory,
                secp256k1_keypair *contribution);
    /* Member, before every round_ack it would make (gz_tree_may_ack): 1 to
     * ack, with its tip in *ack_tip (saved with the ack, in round_completed);
     * 0 not to ack (the round is then Abandoned at its unfinished deadline);
     * -1 not yet (nothing to judge from, such as no tip: the round_complete
     * is ignored and the host's next one asks again). NULL: always ack, tip 0. */
    int (*may_ack)(void *ctx, const gz_sign_round_t *r, uint32_t *ack_tip);
    /* The node's guard record (journal.md 8.3) for the batch of every
     * round_started: 1 and *rec filled (type GZ_SIGN_REC_GUARD, bytes valid
     * until the call returns), or 0 for none. NULL: none (tests). */
    int (*guard)(void *ctx, gz_record_t *rec);
    /* Both roles: the outcome of a round or an attempt, with the action list
     * it may append to (the lobby's answer). It is called right after the
     * engine's own save of that outcome, if it has one, and before anything
     * the engine sends for it, so that the lobby's save joins the engine's
     * batch (rule 2) and nothing outward sits between them. NULL: none. */
    gz_status_t (*outcome)(void *ctx, const gz_sign_outcome_t *o, gz_action_list_t *out);
    void *hook_ctx;                 /* given to keys, may_ack, guard and outcome */
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
    uint32_t excused;               /* host: bit j = participant j's reason 3 was excused in this round (once per scope and key) */
    uint8_t abort_from;             /* host: the participant whose signed abort failed the round (why MEMBER_ABORT) */
    uint16_t abort_reason;          /* and its reason */
    uint32_t nonce_ticks;           /* the nonce step's deadline in this party's ticks, from the proposal's nonces_due_ms; a member's with its margin */
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
    uint32_t ack_tip;               /* member: its tip when it acked (round_completed field 8) */
    uint8_t check_id[32];           /* record 4: the check this attempt follows */
    uint64_t budget_end_ms;         /* host: the signing budget's end (Unix ms; 0 none); memory only */
    uint8_t reported;               /* its outcome has gone to the lobby */
};

/* Host: a round that left the full slots, compactly (GZ_SIGN_MAX_KEPT): what
 * a status request, a resent ack and the reason-6 excuse need of it. */
typedef struct {
    uint8_t used, state, why, released, n_participants, n_tiers, tiers_done;
    uint16_t n_items;
    uint32_t blamed, acked, seq, excused;
    uint64_t answered;              /* the tick (+ 1) of its last status answer */
    uint8_t id[32], scope[32], check_id[32], funding_txid[32];
    uint32_t funding_vout;
    uint16_t attempt;
    uint8_t ckeys[GZ_SIGN_MAX_PARTICIPANTS][33];
    uint8_t item_tier[GZ_SIGN_MAX_ITEMS];
    uint32_t item_signers[GZ_SIGN_MAX_ITEMS];   /* bit j: participant j signs item i */
    uint8_t final_sig[GZ_SIGN_MAX_ITEMS][64];
    uint32_t complete_len;
    uint8_t complete_msg[GZ_SIGN_MAX_SMALL_MSG];
} gz_sign_kept_t;

/* Caller-allocated (it is large: allocate it, do not put it on the stack);
 * treat the fields as private. */
typedef struct {
    gz_sign_config_t cfg;
    gz_ports_t ports;
    uint64_t incarnation;
    /* The keep clock (the unfinished deadline): wall time while it is ahead, else the monotonic clock's
     * progress; never back, and at a start never before the newest time the journal holds. A wall clock set
     * far ahead carries it ahead for good (setting the clock right does not bring it back): an Unfinished
     * round then reaches its unfinished deadline early, and the lobby can be left sooner; nothing more is
     * signed, and a funding buried later still makes the round Live. */
    uint64_t keep_now, keep_mono;
    int keep_mono_set;
    uint64_t session_counter;       /* session_id32s made in this incarnation (S4, section 8) */
    uint64_t attempt_counter;       /* host: attempts proposed in this incarnation (S4) */
    uint64_t next_serial;           /* secret nonces made in this incarnation */
    uint64_t tick;                  /* timer ticks in this incarnation */
    uint32_t next_seq;
    uint32_t attempts;              /* host: attempts begun, or found at a start: a statistic, no limit (the budget is time) */
    uint32_t rr;                   /* the tick's round-robin over the rounds (composite-node.md 8.3, R3) */
    int timer_on;                   /* the tick timer is set: only while the engine holds a round (an idle engine sets none) */
    gz_sign_round_t rounds[GZ_SIGN_MAX_ROUNDS];
    gz_sign_kept_t kept[GZ_SIGN_MAX_KEPT];   /* host: rounds that left the slots, compactly */
    uint8_t known[GZ_SIGN_MAX_KNOWN][32];   /* the newest, at n % GZ_SIGN_MAX_KNOWN */
    size_t n_known;                         /* refused identifiers in all */
    uint8_t known_filter[1u << (GZ_SIGN_KNOWN_FILTER_BITS - 3)];
    /* Set when a call failed after the engine had changed its state (its
     * actions were not handed out): every call is then refused with
     * GZ_ERR_FAILED until gz_sign_start rebuilds the engine from storage
     * (review A, F1; node.h: on any error the node is as it was). */
    int failed;
    uint64_t counters[16];          /* see GZ_SIGN_COUNT_* */
    uint8_t scratch[GZ_SIGN_MAX_MSG];
    gz_sign_def_t scratch_def;
    gz_sign_round_t pending;        /* a round is checked here before it takes a slot */
    gz_rmsg_propose_t prop;         /* the proposal being read */
    /* C7: every exposure record this party holds, of any epoch, but those of Dead creations (C4(d)). */
    gz_tree_exposure_t exposures[GZ_SIGN_MAX_EXPOSURES];
    gz_sign_exposed_t exposed[GZ_SIGN_MAX_EXPOSURES];
    size_t n_exposures;
    int exposures_lost;             /* a start found more than fit: every new round is refused */
    gz_tree_outpoint_t unresolved[GZ_SIGN_MAX_EXPOSURES + GZ_SIGN_MAX_ROUNDS];
    /* Work areas for large temporaries of functions the compiler inlines:
     * on the stack, gcc's AddressSanitizer would guard them with calls the
     * isolation check refuses. */
    secp256k1_musig_partial_sig work_psig[GZ_SIGN_MAX_SIGNERS];
    uint8_t work_tx[GZ_SIGN_MAX_TX + 80];
    uint8_t work_records[GZ_SIGN_WORK_RECORDS];
    uint8_t work_rec2[GZ_SIGN_WORK_REC2];
    gz_sign_msg_t work_msg;
    uint8_t work_keys[GZ_SIGN_MAX_PARTICIPANTS][33];
    /* A nonce's secret inputs while it is made: here rather than on the
     * stack, so that their wiping can be checked (review A, N09). Zero
     * outside make_nonce. */
    uint8_t work_rnd[32], work_sid[32], work_pre[48], work_sk[32];
    /* The keypairs the key hook gave for the operation under way: here, so
     * that their wiping can be checked. Zero outside an operation. */
    secp256k1_keypair work_fkp, work_ckp;
    secp256k1_pubkey work_fpk;
    uint8_t work_fkey[33], work_ckey[33];
    int keys_held;                  /* what the work area holds now (signing.c) */
    int no_key;                     /* the last message could not be signed: it is not sent */
    /* A received message as its whole envelope (header, then the records). */
    uint8_t work_env[GZ_SIGN_MAX_MSG];
    /* The load (gz_sign_load): a round_proposal waits here for the
     * round_started of its batch. */
    uint8_t load_prop[GZ_SIGN_MAX_PROPOSAL];
    size_t load_prop_len;
    int load_have_prop;
    gz_batch_id_t load_batch;
    int resume_at;                  /* gz_sign_resume: the next round to look at */
    uint32_t resume_seq;            /* ... among those the load found (seq up to this) */
} gz_sign_t;

/* What the engine counts, for tests and reports. */
enum {
    GZ_SIGN_COUNT_NONCES_MADE = 0, GZ_SIGN_COUNT_PARTIALS_MADE, GZ_SIGN_COUNT_PSIGS_VERIFIED,
    GZ_SIGN_COUNT_FINALS_VERIFIED, GZ_SIGN_COUNT_BLAME_FAULT, GZ_SIGN_COUNT_BLAME_SILENT,
    GZ_SIGN_COUNT_REJECTED, GZ_SIGN_COUNT_DUPLICATES, GZ_SIGN_COUNT_EVIDENCE,
    GZ_SIGN_COUNT_IGNORED,          /* proposals, begins and resolves ignored (no lobby, no key, a finished check) */
    GZ_SIGN_COUNT_N
};

/* Prepare an engine. `incarnation` is the runner's (runner.h): it never
 * repeats, also across restores, and is mixed into every session_id32.
 * Returns GZ_ERR_ARGUMENT for a missing argument (the key hook among them). */
gz_status_t gz_sign_init(gz_sign_t *e, const gz_sign_config_t *cfg, const gz_ports_t *ports, uint64_t incarnation);

/* THE START, in the composite's two phases (composite-node.md 10).
 *   gz_sign_load_begin  drop every round held in memory (a start rebuilds
 *                       them), so that it also recovers an engine that
 *                       failed; the counters that make session ids and host
 *                       random values unique within the incarnation are kept.
 *   gz_sign_load        one record of the Round area, in journal order, with
 *                       its batch: memory only. GZ_ERR_CORRUPT for a record
 *                       this engine did not write or that does not fit what
 *                       came before it.
 *   gz_sign_resume      the start's actions, one round a call (`*more`), then
 *                       the timer: a member answers per item (S2), so a round
 *                       whose nonce was sent and whose partial signature was
 *                       not becomes Aborted (no partial signature ever sent)
 *                       or Unfinished and is answered with an abort; saved
 *                       partial signatures are resent (S3). A host fails each
 *                       unfinished attempt (spec H13). Each outcome goes
 *                       through the outcome hook.
 * gz_sign_start does all three over a storage reader, in one step (`*more`
 * is set to 0), for embeddings without a composite. */
gz_status_t gz_sign_load_begin(gz_sign_t *e);
gz_status_t gz_sign_load(gz_sign_t *e, const gz_record_t *rec, gz_batch_id_t at);
gz_status_t gz_sign_resume(gz_sign_t *e, gz_action_list_t *out, int *more);
gz_status_t gz_sign_start(gz_sign_t *e, const gz_storage_reader_t *storage, gz_action_list_t *out, int *more);

/* Handle one event; same contract as gz_node_handle. Messages that do not
 * parse, or that this party should not get, are counted and ignored. Any
 * error leaves the action list as it was and the engine failed: this and
 * every later call return GZ_ERR_FAILED until gz_sign_start. */
gz_status_t gz_sign_handle(gz_sign_t *e, const gz_event_t *event, gz_action_list_t *out);

/* Host: begin a round (the lobby's hand-off). Never an error for what the
 * hand-off says (composite-node.md 8.1):
 *   - a (check, attempt) this engine has begun already, running or ended, is
 *     ignored: nothing is appended (rule 3; lobby_handoff.h);
 *   - while a round of the same scope is Active, ignored too (one Active
 *     round per scope, H8);
 *   - refused, with the outcome Failed through the hook and nothing saved:
 *     no attempt number, a proposal that does not encode, a builder that
 *     refuses, a nonces_due_ms under one tick, a budget already spent.
 * GZ_ERR_ARGUMENT only for a missing argument or a member engine. */
gz_status_t gz_sign_begin(gz_sign_t *e, const gz_sign_begin_t *b, gz_action_list_t *out);

/* The lobby ended by a cancel (lobby_handoff.h, composite-node.md 9.2, A9).
 * Host: the scope's Active round fails (round_ended, then the aborts), with
 * no outcome and no further attempt: the lobby is over. Member: the secret
 * nonces of the scope's rounds are erased; their records are kept, and a
 * round with partial signatures out stays unresolved (Unfinished). */
gz_status_t gz_sign_cancel(gz_sign_t *e, const uint8_t scope[32], gz_action_list_t *out);

/* Host: a chosen member left while Signing (composite-node.md 9.2, R7). While
 * it still owes nonces or partial signatures in the scope's Active round, the
 * attempt fails at once with it blamed (outcome Retry); once it has sent all
 * of them, the round goes on. */
gz_status_t gz_sign_member_left(gz_sign_t *e, const uint8_t scope[32], const uint8_t ckey[33], gz_action_list_t *out);

/* Host: the scope's Closing end: its compact rounds are forgotten (H12 is
 * answered while a member can still need it, composite-node.md 2.4). */
void gz_sign_forget_scope(gz_sign_t *e, const uint8_t scope[32]);
/* At a start, after gz_sign_resume: forget the kept host rounds of every scope `keep` says is gone
 * (review A of PR 52, L3: a scope whose Closing ended before the restart is otherwise kept again, and
 * keeps the tick running, for good). */
void gz_sign_forget_kept_unless(gz_sign_t *e, int (*keep)(void *ctx, const uint8_t scope[32]), void *ctx);

/* 1 if this engine holds any round under `scope` (in full or compactly, or
 * an exposure entry's round): round kinds under it route here
 * (composite-node.md section 4). */
int gz_sign_holds_scope(const gz_sign_t *e, const uint8_t scope[32]);

/* Whether a partial signature of this party may be out for a round of lobby
 * `scope` that is not resolved: GZ_SIGN_OUT_THIS for a round of the scope
 * that ever sent one (Active, Unfinished or Complete), in memory or through
 * its exposure entry after it left memory; GZ_SIGN_OUT_UNKNOWN for an
 * unresolved exposure entry whose lobby is not known (fail closed, whatever
 * the scope; not made by this engine, which saves the scope with the
 * record); else GZ_SIGN_OUT_NONE. While it holds, the lobby must not be
 * given up: the round's ack, and the factory, depend on it (Slice 1 blocker
 * C1; local-api.md, leave). Resolved rounds (Live, Dead, Abandoned) do not
 * count. What ends it: the round's resolution; the unfinished deadline for
 * an Unfinished round; the funding deadline for a Complete one. */
#define GZ_SIGN_OUT_NONE    0
#define GZ_SIGN_OUT_THIS    1
#define GZ_SIGN_OUT_UNKNOWN 2
int gz_sign_partials_out(const gz_sign_t *e, const uint8_t scope[32]);

/* Member: the round's end as the embedding judged it from the chain
 * (safety-rule.md C11, C4(d)): GZ_SIGN_END_LIVE, _DEAD or _ABANDONED, saved as
 * round_ended. Rounds that are Complete, Unfinished or Abandoned only; for a
 * round not found or in another state, a counted no-op (composite-node.md
 * 8.1). GZ_ERR_ARGUMENT only for a missing argument, a host engine or an
 * outcome that is none of the three. A round resolved Dead leaves the C7 set:
 * its funding output can never exist (C4(d)). */
gz_status_t gz_sign_resolve(gz_sign_t *e, const uint8_t round_id[32], uint8_t outcome, gz_action_list_t *out);

/* The exposure records held (C7), for the embedding's checks. */
size_t gz_sign_exposures(const gz_sign_t *e, const gz_tree_exposure_t **out);

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
/* Its last step, BIP 341's SigMsg for hash type default, key path, no annex:
 * from the version and lock time (4 bytes each, as serialised), the five
 * hashes in BIP 341's order (prevouts, amounts, scriptPubKeys, sequences,
 * outputs) and the input's index. gz_sign_tx_sighash is this over a
 * one-input transaction; the BIP 341 vectors check it over theirs. */
void gz_sign_taproot_sighash(const uint8_t version[4], const uint8_t locktime[4], const uint8_t hashes[5][32], uint32_t index,
                             uint8_t out[32]);
/* BIP 341's TapTweak of an x-only internal key, with the script tree's
 * merkle root or none (NULL): the tweak every item's output key is made with. */
void gz_sign_taptweak(const uint8_t internal[32], const uint8_t *merkle_root, uint8_t out[32]);
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
