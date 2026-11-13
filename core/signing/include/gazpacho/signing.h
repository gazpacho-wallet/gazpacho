/* The signing round engine: the core of spec/signing-round.md draft 3.
 *
 * One host (participant 0, the coordinator) and its members sign a set of
 * items (one transaction input each) with MuSig2 (BIP 327), tier by tier.
 * The engine is sans-I/O like the node (node.h): events in, actions out,
 * every save listed before the send it justifies, so that the runner's rule
 * (runner.h) gives "save before send".
 *
 * WHAT THIS ENGINE DOES (spec section in brackets)
 *   - Its own nonce function [8]: secp256k1_musig_nonce_gen with
 *       session_id32 = TH("gazpacho/nonce-session", 32 bytes from the random
 *                        port tagged secret || incarnation || counter),
 *       msg32 = the item's signature digest, keyagg_cache = the item's
 *       TWEAKED cache, extra_input32 = TH("gazpacho/nonce-extra",
 *       round_id || tier || index). Secret nonces live in this structure
 *       only, are never saved, and are wiped when they have signed, when the
 *       round fails, and by gz_sign_wipe.
 *   - Rules S1 to S4 [3], the member states [7] and the guards [12]: slot
 *     tracking for nonces and partial signatures, strict parsing of every
 *     value from the network before any library call, duplicate keys
 *     refused, one fixed signing mode.
 *   - Verifying each partial signature as it arrives [6.6], combining, and
 *     verifying each final signature from the signed transaction's bytes
 *     with this engine's own BIP 341 signature hash [6.7, 6.8].
 *
 * WHAT IT DOES NOT DO (left to later work, see the report)
 *   - Build the items from terms and a proposal: the embedding supplies a
 *     builder (gz_sign_build_fn) that turns the proposal's opaque parameters
 *     into a round definition. The safety checks of safety-rule.md, the C7
 *     exposure record's contents, restore epochs (S5), lobby bindings and the
 *     messages.md encoding are not here. The wire format below is this
 *     engine's own and provisional.
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
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>

#define GZ_SIGN_MAX_PARTICIPANTS 16
#define GZ_SIGN_MAX_SIGNERS      16
#define GZ_SIGN_MAX_ITEMS        64
#define GZ_SIGN_MAX_TIERS        4
#define GZ_SIGN_MAX_TX           512     /* bytes of one unsigned transaction */
#define GZ_SIGN_MAX_PARAMS       64      /* bytes of a proposal's parameters */
#define GZ_SIGN_MAX_ROUNDS       4       /* rounds a member keeps in full */
#define GZ_SIGN_MAX_KNOWN        256     /* round identifiers remembered as refused */
#define GZ_SIGN_MAX_MSG          (40 + GZ_SIGN_MAX_ITEMS * (5 + GZ_SIGN_MAX_SIGNERS * 130) + 64)

/* The one signing mode: key path, BIP 341 tweak of the ordered aggregate key
 * with the stated merkle root (or none: BIP 86), default hash type, no annex,
 * transactions with exactly one input. Anything else is refused. */
#define GZ_SIGN_MODE_KEYPATH 1u

/* Records the engine saves (record types of the journal). */
#define GZ_REC_M_STARTED  0x53470001u  /* round_id, tier, n, indices, proposal: before nonces (S1) */
#define GZ_REC_M_SIGNED   0x53470002u  /* round_id, tier, partial-signature message (with S1: the exposure) */
#define GZ_REC_M_RESULT   0x53470003u  /* round_id, tier, verified tier result message */
#define GZ_REC_M_COMPLETE 0x53470004u  /* round_id, ack message */
#define GZ_REC_M_ABORTED  0x53470005u  /* round_id, abort message */
#define GZ_REC_H_PROPOSED 0x53470011u  /* proposal message */
#define GZ_REC_H_RESULT   0x53470012u  /* round_id, tier, result message */
#define GZ_REC_H_COMPLETE 0x53470013u  /* round_id, complete message */
#define GZ_REC_H_ACK      0x53470014u  /* round_id, participant */
#define GZ_REC_H_FAILED   0x53470015u  /* round_id, blamed mask (u32), reason */

/* Message kinds (byte 2 of every message, after the magic "GS"). */
enum {
    GZ_MSG_PROPOSE = 1, GZ_MSG_NONCES, GZ_MSG_ALL_NONCES, GZ_MSG_PARTIALS, GZ_MSG_RESULT,
    GZ_MSG_COMPLETE, GZ_MSG_ACK, GZ_MSG_STATUS, GZ_MSG_ABORT
};

/* Reasons in an abort, and why a host blamed someone. */
enum {
    GZ_WHY_NONE = 0, GZ_WHY_BUILD, GZ_WHY_INVALID_ROUND, GZ_WHY_ID_MISMATCH, GZ_WHY_BAD_HOST_SIG,
    GZ_WHY_KNOWN_ROUND, GZ_WHY_BUSY, GZ_WHY_BAD_NONCE, GZ_WHY_OWN_NONCE_CHANGED, GZ_WHY_RESTARTED,
    GZ_WHY_DEADLINE, GZ_WHY_HOST_ABORT, GZ_WHY_BAD_PARTIAL, GZ_WHY_EQUIVOCATION, GZ_WHY_BAD_RESULT,
    GZ_WHY_HOST_RESTART, GZ_WHY_MEMBER_ABORT, GZ_WHY_BAD_MESSAGE, GZ_WHY_SUPERSEDED
};

typedef struct {
    uint8_t factory_key[33];        /* compressed; signs the items */
    uint8_t contribution_key[32];   /* x-only; signs this participant's round messages */
    uint64_t peer;                  /* where its messages go and come from */
} gz_sign_participant_t;

typedef struct {
    uint8_t tier;
    uint8_t mode;                   /* GZ_SIGN_MODE_KEYPATH */
    uint8_t has_merkle_root;
    uint8_t merkle_root[32];
    uint8_t n_signers;              /* 2.. ; signing order; participant 0 must be one */
    uint8_t signers[GZ_SIGN_MAX_SIGNERS];
    uint64_t spent_amount;
    uint8_t spent_script[34];       /* must be the P2TR output of the tweaked aggregate */
    uint16_t tx_len;
    uint8_t tx[GZ_SIGN_MAX_TX];     /* unsigned, legacy serialisation, one input */
} gz_sign_item_t;

/* A round as one party builds it. Items are in index order, tiers ascending
 * (index unique in the round across tiers, spec section 1). */
typedef struct {
    uint8_t purpose;
    uint8_t n_tiers;
    uint8_t n_participants;
    gz_sign_participant_t participants[GZ_SIGN_MAX_PARTICIPANTS];
    uint16_t n_items;
    gz_sign_item_t items[GZ_SIGN_MAX_ITEMS];
} gz_sign_def_t;

/* Build the round from a proposal's parameters (hostile bytes). Returns 1 and
 * fills `out`, or 0 to refuse. Must be a deterministic function of `params`. */
typedef int (*gz_sign_build_fn)(void *ctx, const uint8_t *params, size_t len, gz_sign_def_t *out);
/* Host only: the parameters of the next attempt after a failed one, without
 * the participants in `blamed` (bit i = participant i of the failed round).
 * Returns the length written to `out` (at most GZ_SIGN_MAX_PARAMS), or 0 for
 * "no further attempt". */
typedef size_t (*gz_sign_retry_fn)(void *ctx, const uint8_t *params, size_t len, uint32_t blamed, uint8_t *out);

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
    uint32_t max_attempts;          /* host: attempts in all, over restarts */
} gz_sign_config_t;

/* Tier and round states (spec section 7). */
enum { GZ_TIER_NONE = 0, GZ_TIER_NONCES, GZ_TIER_SIGNED, GZ_TIER_DONE };
enum {
    GZ_ROUND_FREE = 0, GZ_ROUND_ACTIVE, GZ_ROUND_ABORTED, GZ_ROUND_UNFINISHED,
    GZ_ROUND_COMPLETE, GZ_ROUND_FAILED /* host: attempt given up */, GZ_ROUND_DONE /* host: every ack */
};

typedef struct {
    uint8_t state, tier, ever_partial, me;
    uint32_t seq;                   /* order in which this party took the round up */
    uint8_t tier_state[GZ_SIGN_MAX_TIERS];
    uint8_t id[32];
    uint32_t ticks, blamed;
    uint8_t why;
    gz_sign_def_t def;
    uint16_t proposal_len;
    uint8_t proposal[48 + GZ_SIGN_MAX_PARAMS + 64];
    uint8_t params[GZ_SIGN_MAX_PARAMS];
    uint16_t params_len;
    secp256k1_musig_keyagg_cache cache[GZ_SIGN_MAX_ITEMS];
    uint8_t digest[GZ_SIGN_MAX_ITEMS][32];
    /* slots: bit s of have_nonce[i] = signer s of item i has a nonce here */
    uint16_t have_nonce[GZ_SIGN_MAX_ITEMS], have_psig[GZ_SIGN_MAX_ITEMS];
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
    uint16_t acked;                 /* host: bit j = participant j acked */
    uint32_t partials_len[GZ_SIGN_MAX_TIERS];
    uint8_t partials_msg[GZ_SIGN_MAX_TIERS][40 + GZ_SIGN_MAX_ITEMS * 68 + 64];
    uint32_t result_len[GZ_SIGN_MAX_TIERS];
    uint8_t result_msg[GZ_SIGN_MAX_TIERS][40 + GZ_SIGN_MAX_ITEMS * 68 + 64];
    uint32_t nonces_len;            /* member: this incarnation's nonce message, for resending */
    uint8_t nonces_msg[40 + GZ_SIGN_MAX_ITEMS * 134];
    uint32_t tail_len;              /* member: ack or abort; host: complete */
    uint8_t tail_msg[40 + 64 + 64];
} gz_sign_round_t;

/* Caller-allocated (it is large: allocate it, do not put it on the stack);
 * treat the fields as private. */
typedef struct {
    gz_sign_config_t cfg;
    gz_ports_t ports;
    uint64_t incarnation, next_serial;
    secp256k1_keypair factory_kp, contribution_kp;
    secp256k1_pubkey factory_pk;
    uint8_t contribution_x[32];
    uint32_t attempts, next_seq;
    gz_sign_round_t rounds[GZ_SIGN_MAX_ROUNDS];
    uint8_t known[GZ_SIGN_MAX_KNOWN][32];
    size_t n_known;
    uint64_t counters[8];           /* see GZ_SIGN_COUNT_* */
    uint8_t scratch[GZ_SIGN_MAX_MSG];
    gz_sign_def_t scratch_def;
    gz_sign_round_t pending;        /* a round is checked here before it takes a slot */
} gz_sign_t;

/* What the engine counts, for tests and reports. */
enum {
    GZ_SIGN_COUNT_NONCES_MADE = 0, GZ_SIGN_COUNT_PARTIALS_MADE, GZ_SIGN_COUNT_PSIGS_VERIFIED,
    GZ_SIGN_COUNT_FINALS_VERIFIED, GZ_SIGN_COUNT_BLAME_FAULT, GZ_SIGN_COUNT_BLAME_SILENT,
    GZ_SIGN_COUNT_REJECTED, GZ_SIGN_COUNT_DUPLICATES
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

/* Host: begin a round with these parameters. GZ_ERR_ARGUMENT if not a host,
 * a round is still running, or the builder refuses. */
gz_status_t gz_sign_begin(gz_sign_t *e, const uint8_t *params, size_t len, gz_action_list_t *out);

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
typedef struct { uint32_t h[8]; uint64_t n; uint8_t buf[64]; } gz_sha256_t;
void gz_sha256_init(gz_sha256_t *s);
void gz_sha256_write(gz_sha256_t *s, const uint8_t *data, size_t len);
void gz_sha256_done(gz_sha256_t *s, uint8_t out[32]);
void gz_tagged_init(gz_sha256_t *s, const char *tag);

/* A transaction with one input, legacy or with a witness of one item. */
typedef struct {
    const uint8_t *bytes; size_t len;
    const uint8_t *outpoint;       /* 36 bytes */
    const uint8_t *sequence;       /* 4 bytes */
    size_t outputs_at, outputs_end;
    const uint8_t *witness_item; size_t witness_len;   /* NULL if legacy */
} gz_tx_t;
/* 1 if `bytes` is exactly one such transaction (canonical sizes, nothing left over). */
int gz_tx_parse(const uint8_t *bytes, size_t len, gz_tx_t *tx);
/* BIP 341 key-path signature hash, default type, no annex, input 0. */
void gz_tx_sighash(const gz_tx_t *tx, uint64_t amount, const uint8_t script[34], uint8_t out[32]);
/* The unsigned transaction with a one-item witness `sig64` added. Returns
 * the length, or 0 if it does not parse or `cap` is short. */
size_t gz_tx_attach(const uint8_t *tx, size_t len, const uint8_t sig64[64], uint8_t *out, size_t cap);
/* 1 if `signed_tx` spends (amount, script) with a valid 64-byte key-path
 * signature, judged from its bytes alone. */
int gz_tx_verify(const secp256k1_context *ctx, const uint8_t *signed_tx, size_t len, uint64_t amount, const uint8_t script[34]);

/* A decoded message: pointers into the bytes. Entry layouts per kind:
 * NONCES (u32 index, 66 nonce, 64 sig); ALL_NONCES (u32 index, u8 k, k x (66, 64));
 * PARTIALS (u32 index, 32 psig, 32 set digest); RESULT (u32 index, 64 sig);
 * ABORT (u32 index). */
typedef struct {
    uint8_t kind, tier, reason;
    const uint8_t *round_id, *host_random, *params, *held, *sig;
    size_t params_len, signed_len;
    uint16_t n;
    const uint8_t *entry[GZ_SIGN_MAX_ITEMS];
} gz_sign_msg_t;
/* 1 if `bytes` is one well-formed message (exact length, bounded counts). */
int gz_sign_decode(const uint8_t *bytes, size_t len, gz_sign_msg_t *m);

#endif
