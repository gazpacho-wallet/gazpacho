/* The hand-off between the lobby engine and the signing engine.
 *
 * A header of its own so that both engines can include it: it needs only the
 * core contract (action.h) and the terms library (core/tree's terms.h), not
 * the rest of the lobby. The signing engine (branch signing-wire and its
 * successors) implements gz_lobby_signing_t; the program routes the signing
 * engine's outcome back with gz_lobby_host_round_result and
 * gz_lobby_member_round_result (lobby.h), using the GZ_LOBBY_ROUND_* codes
 * below.
 *
 * The lobby's part (signing-round.md section 6 step 1, messages.md 6.9 and
 * 7.2, terms.md 9 and 10): it gives the signing engine everything the checks
 * at signing need, namely the frozen records with the host's signatures, the
 * pinned key, the check, the member's whole conditions, and the build
 * parameters the terms fix. It does not run those checks: gz_tree_member_check
 * and gz_tree_may_ack belong to the signing engine. */
#ifndef GAZPACHO_LOBBY_HANDOFF_H
#define GAZPACHO_LOBBY_HANDOFF_H

#include "gazpacho/action.h"
#include "gazpacho/terms.h"

typedef struct {
    uint8_t factory_key[33], contribution_key[33];
    uint8_t bind_by_factory[64], bind_by_contribution[64];
} gz_lobby_participant_t;

/* What the lobby gives the signing engine when a round may begin. Pointers
 * are valid only during the call: copy what is kept. */
typedef struct {
    int role;                                  /* 1: chosen to sign (the host is always 1) */
    /* 1: the same start again after a restart (gz_lobby_host_resume,
     * gz_lobby_member_resume). The signing engine treats `begin` as
     * idempotent per check_id: a check it already began, and saved, is
     * resumed from its own records, never begun twice; and a check it has
     * already finished (any outcome) is ignored: `begin` for it does
     * nothing. The lobby saves each outcome it is given (lobby_state, on
     * both sides) and so does not hand a finished check over again after a
     * restart, but a crash can lose that save, so the rule stands.
     * Under one check_id the lobby never names other participants: a chosen
     * seat keeps its keys until the round is resolved. */
    int resume;
    const uint8_t *scope;                      /* = outer digest, 32 */
    const uint8_t *pinned_key;                 /* the host's key the member pinned (33); the host's own */
    const uint8_t *outer, *current;            /* the frozen records */
    size_t outer_len, current_len;
    const uint8_t *outer_sig, *current_sig;    /* the host's signatures over their digests (64 each) */
    const uint8_t *current_digest;             /* frozen, 32 */
    uint32_t version;                          /* frozen */
    const uint8_t *check_id;                   /* the check this start follows, 32 */
    const gz_terms_outer_t *terms;             /* decoded outer rules */
    const gz_terms_current_t *values;          /* decoded frozen values */
    /* Participants, host included, as the start says. Member: the host
     * signed this count in `start`, but the signing engine must take the
     * count from round_propose and refuse a proposal whose count differs
     * (and so do the shape fields below, which are computed from it). */
    uint16_t signers;
    /* Host: every participant, host first, then the chosen seats in order of
     * joining. Member: NULL (they arrive in round_propose). */
    const gz_lobby_participant_t *participants;
    uint16_t n_participants;
    /* Build parameters (messages.md 7.2) fixed or derived from the terms. */
    uint8_t levels[8], n_levels, fixed_levels; /* shape for signers - 1 members; D. n_levels 0: no shape */
    uint8_t k, tree_anchors;                   /* 1, 1 */
    uint16_t layer_step, layer_states;         /* 144, 4 */
    /* Member: its own conditions (terms.md 9 "at signing": the real tree
     * against all of them) and the min_members hint it sent in `ready`.
     * Host: NULL and 0. */
    const gz_terms_limits_t *limits;
    uint16_t min_members;
    const uint8_t *start_bytes; size_t start_len; /* member: the signed start */
} gz_lobby_handoff_t;

/* The signing engine's side. Each function appends its own actions after the
 * lobby's (round_propose comes after every start), must not keep the
 * pointers, and returns GZ_OK or an error; an error fails the lobby's step.
 *
 *   begin        a round may begin (above). Called after the lobby's saves.
 *   cancel       the lobby ended by a `cancel` (messages.md 6.10): on the host
 *                after its cancel is saved and listed for every seat, on the
 *                member after the received cancel is saved. `reason` is the
 *                cancel's (1 deadline below the minimum, 2 host's choice, 3
 *                signing failed). Called for every cancel, also one before
 *                any start: the signing engine ignores a lobby it never began.
 *                The member's engine erases secret nonces and keeps its round
 *                records; a cancel does not undo partial signatures sent.
 *   member_left  host only: a chosen seat sent `leave` while Signing. The seat
 *                stays seated for the transport until the round is resolved
 *                (the member may still have to abort, resend partial
 *                signatures or ask for the round's status, messages.md 6.6 and
 *                7.10); the signing engine decides what the leave means for
 *                the attempt and reports it with round_result.
 * `cancel` and `member_left` may be NULL. */
typedef struct {
    gz_status_t (*begin)(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out);
    gz_status_t (*cancel)(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out);
    gz_status_t (*member_left)(void *ctx, const uint8_t scope[32], const uint8_t ckey[33], gz_action_list_t *out);
    void *ctx;
} gz_lobby_signing_t;

/* The signing engine's outcome, routed back to the lobby by the program.
 *
 * THE SIGNING BUDGET (terms.md 3: one budget for all attempts, from the
 * lobby's first `start`). Once the lobby hands a round to the signing engine,
 * the signing engine alone owns the budget: it reports GZ_LOBBY_ROUND_FAILED
 * when the budget is spent, and the lobby never cancels a round in Signing
 * for it. The lobby's own budget timer covers only the phases before a
 * hand-off (Open and a ready check after a retry), where it ends the lobby
 * with cancel reason 3. A Funding or Active outcome is always accepted, also
 * after the lobby ended by a cancel: a creation the signing engine completed
 * is never refused. The signing engine reports Funding or Active only for the
 * round it was last handed and is still running: after a Retry, or once that
 * round has ended, it has no round to complete and reports neither (the
 * lobby, once a round was ever handed over, cannot tell a late report from a
 * current one).
 *
 * A Retry names its check: the check_id of the hand-off whose round ended
 * (gz_lobby_member_round_result's `check_id`, required). The member acts on
 * it only if that is the check of the start it holds, and then spends that
 * start; a Retry for an older check, reported after the next check's start
 * arrived, is ignored, so the next check proceeds. It withdraws its answer
 * only if that answer is to the spent start's check, so an answer to a later
 * check given before the Retry arrived stands. */
#define GZ_LOBBY_ROUND_FUNDING 1     /* the creation is signed: funding */
#define GZ_LOBBY_ROUND_ACTIVE  2     /* the factory is funded */
#define GZ_LOBBY_ROUND_RETRY   3     /* host: members named failed; the rest go back to Ready.
                                        member: this attempt ended; a later check may choose it */
#define GZ_LOBBY_ROUND_FAILED  4     /* the signing budget is spent (the signing engine's): cancel reason 3 */

#endif
