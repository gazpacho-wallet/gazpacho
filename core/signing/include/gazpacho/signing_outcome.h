/* What the signing engine tells its embedding about a host's round, in a
 * header of its own: the lobby adapter (core/signing/lobby_outcome.c)
 * includes it beside gazpacho/lobby.h without core/tree's headers, whose
 * terms types the lobby's own copy still repeats (docs/notes/slice1-attempt.md,
 * mismatch 2). */
#ifndef GAZPACHO_SIGNING_OUTCOME_H
#define GAZPACHO_SIGNING_OUTCOME_H

#include "gazpacho/action.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    GZ_SIGN_OUTCOME_FUNDING = 1,    /* every chosen member acked: the host may fund (safety-rule.md H1) */
    GZ_SIGN_OUTCOME_RETRY,          /* an attempt failed and the engine begins none itself: `blamed` are to be left out */
    GZ_SIGN_OUTCOME_FAILED          /* no further attempt: the attempts are spent */
} gz_sign_outcome_kind_t;

typedef struct {
    gz_sign_outcome_kind_t kind;
    const uint8_t *round_id;        /* 32: the attempt it concerns */
    const uint8_t (*blamed)[33];    /* RETRY: the contribution keys of the members blamed */
    size_t n_blamed;
} gz_sign_outcome_t;

/* The lobby host's side (core/signing/lobby_outcome.c, built only with the
 * lobby engine): gz_lobby_host_round_result for the outcome. `lobby_host` is
 * a gz_lobby_host_t. */
gz_status_t gz_sign_lobby_outcome(void *lobby_host, const gz_sign_outcome_t *o, gz_action_list_t *out);

#endif
