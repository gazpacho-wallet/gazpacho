/* What the signing engine tells its embedding about a round, in a header of
 * its own: the composite's hand-off (core/node) includes it beside
 * gazpacho/lobby.h. Both roles report; each outcome names its check and its
 * attempt, so that the lobby applies it only to the attempt it is in
 * (composite-node.md 9.3, U2; lobby_handoff.h: a Retry names its check). */
#ifndef GAZPACHO_SIGNING_OUTCOME_H
#define GAZPACHO_SIGNING_OUTCOME_H

#include "gazpacho/action.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    /* Host: every chosen member acked: the host may fund (safety-rule.md H1).
     * Member: its own ack is saved and goes out (round Complete). */
    GZ_SIGN_OUTCOME_FUNDING = 1,
    /* Host: an attempt failed and the engine begins none itself: `blamed` are
     * to be left out. Member: this attempt ended for it (Aborted, Unfinished,
     * its ack refused); a later check may choose it. */
    GZ_SIGN_OUTCOME_RETRY,
    /* Host: no further attempt can succeed: the builder refused the hand-off
     * (deterministic: the frozen terms will not build), or the signing budget
     * is spent with the round in flight (cancel reason 3). */
    GZ_SIGN_OUTCOME_FAILED
} gz_sign_outcome_kind_t;

typedef struct {
    gz_sign_outcome_kind_t kind;
    const uint8_t *scope;           /* 32: the lobby */
    const uint8_t *check_id;        /* 32: the check of the attempt */
    uint16_t attempt;
    const uint8_t *round_id;        /* 32: the attempt's round; NULL for a begin refused before it had one */
    /* 1 if a partial signature may have left a member in this attempt: the
     * next attempt must spend a new funding outpoint (H11). */
    int released;
    const uint8_t (*blamed)[33];    /* host RETRY: the contribution keys of the members blamed */
    size_t n_blamed;
} gz_sign_outcome_t;

#endif
