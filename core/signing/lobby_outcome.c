/* The signing engine's outcome, as the lobby host takes it: the signing
 * engine's config.outcome hook for a host that runs both engines
 * (docs/notes/slice1-attempt.md, mismatch 23: nothing reported the outcome,
 * the program polled gz_sign_latest).
 *
 * Built only with the lobby engine (CMake: when gazpacho_lobby exists), and
 * against PR 30's gazpacho/lobby.h until that merges. It includes no
 * core/tree header: the lobby's own copy of the terms types still clashes
 * with core/tree's (mismatch 2). */
#include "gazpacho/lobby.h"
#include "gazpacho/signing_outcome.h"

gz_status_t gz_sign_lobby_outcome(void *lobby_host, const gz_sign_outcome_t *o, gz_action_list_t *out)
{
    gz_lobby_host_t *h = lobby_host;
    if (!h || !o || !out) return GZ_ERR_ARGUMENT;
    switch (o->kind) {
    case GZ_SIGN_OUTCOME_FUNDING:
        /* every chosen member acked: Funding (safety-rule.md H1) */
        return gz_lobby_host_round_result(h, GZ_ROUND_FUNDING, NULL, 0, out);
    case GZ_SIGN_OUTCOME_RETRY:
        /* the blamed seats must ready again; the rest go back to Ready (messages.md 6.9) */
        if (o->n_blamed && !o->blamed) return GZ_ERR_ARGUMENT;
        return gz_lobby_host_round_result(h, GZ_ROUND_RETRY, o->n_blamed ? &o->blamed[0][0] : NULL, o->n_blamed, out);
    case GZ_SIGN_OUTCOME_FAILED:
        /* the signing budget is spent: cancel reason 3 (messages.md 6.10) */
        return gz_lobby_host_round_result(h, GZ_ROUND_FAILED, NULL, 0, out);
    default:
        return GZ_ERR_ARGUMENT;
    }
}
