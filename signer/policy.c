/* The tables of docs/notes/signer.md section 3: which key may sign what.
 * Pure data and lookups; no key is held here. */
#include "gazpacho/signer.h"
#include "gazpacho/lobby.h"
#include "gazpacho/round_msg.h"

#include <string.h>

/* ---- 3.2 kinds per key ---- */

typedef struct {
    uint16_t kind;
    uint8_t host, member;   /* 1: the host's long-term key / a member's contribution key may sign it */
    uint8_t deterministic;  /* 1: the host may sign it with the all-zero aux_rand (rebuilt messages) */
} kind_row_t;

static const kind_row_t KINDS[] = {
    {GZ_KIND_HELLO, 0, 1, 0},
    {GZ_KIND_TERMS_OFFER, 1, 0, 0},
    {GZ_KIND_JOIN, 0, 1, 0},
    {GZ_KIND_READY, 0, 1, 0},
    {GZ_KIND_UNREADY, 0, 1, 0},
    {GZ_KIND_LEAVE, 0, 1, 0},
    {GZ_KIND_LOBBY_STATUS, 1, 0, 0},
    {GZ_KIND_READY_CHECK, 1, 0, 0},
    {GZ_KIND_START, 1, 0, 0},
    {GZ_KIND_CANCEL, 1, 0, 0},
    {GZ_KIND_ROUND_PROPOSE, 1, 0, 0},
    {GZ_KIND_ROUND_NONCES, 0, 1, 0},
    {GZ_KIND_ROUND_ALL_NONCES, 1, 0, 0},
    {GZ_KIND_ROUND_PARTIAL_SIGS, 0, 1, 0},
    {GZ_KIND_ROUND_TIER_RESULT, 1, 0, 1},
    {GZ_KIND_ROUND_COMPLETE, 1, 0, 0},
    {GZ_KIND_ROUND_ACK, 0, 1, 0},
    {GZ_KIND_ROUND_ABORT, 1, 1, 1},
    {GZ_KIND_ROUND_STATUS_REQUEST, 0, 1, 0},
    {GZ_KIND_FACTORY_FUNDED, 1, 0, 0},
};

int gz_sg_kind_allowed(gz_sg_role_t role, gz_sg_key_t key, uint16_t kind, int *deterministic_ok)
{
    size_t i;
    if (deterministic_ok) *deterministic_ok = 0;
    if (!((role == GZ_SG_ROLE_HOST && key == GZ_SG_KEY_HOST) ||
          (role == GZ_SG_ROLE_MEMBER && key == GZ_SG_KEY_CONTRIBUTION)))
        return 0;
    for (i = 0; i < sizeof KINDS / sizeof KINDS[0]; i++) {
        if (KINDS[i].kind != kind) continue;
        if (!(role == GZ_SG_ROLE_HOST ? KINDS[i].host : KINDS[i].member)) return 0;
        /* Only the host's rebuilt messages may be deterministic. */
        if (deterministic_ok) *deterministic_ok = role == GZ_SG_ROLE_HOST && KINDS[i].deterministic;
        return 1;
    }
    return 0;
}

/* ---- 3.1 keys and what each may sign ---- */

static const char *const HOST_TAGS[] = {
    "gazpacho/msg", "gazpacho/terms/outer", "gazpacho/terms/current", "gazpacho/bind", "gazpacho/nonce",
    /* later, each by its own typed operation */
    "gazpacho/listing", "gazpacho/withdrawal", "gazpacho/index", "gazpacho/anchor", "gazpacho/beacon",
    NULL};
static const char *const CONTRIBUTION_TAGS[] = {"gazpacho/msg", "gazpacho/bind", "gazpacho/nonce", NULL};
/* bind_by_factory, until PR #59's code (step S6) removes it */
static const char *const FACTORY_TAGS[] = {"gazpacho/bind", NULL};
static const char *const NO_TAGS[] = {NULL};

static const gz_sg_purpose_t PURPOSES[] = {
    {GZ_SG_KEY_HOST, GZ_SG_ROLE_HOST, "m/254315617'/net'/1'/k'", 1u, HOST_TAGS, GZ_SG_SIGHASH_NONE, 1, 1},
    {GZ_SG_KEY_FACTORY, GZ_SG_ROLE_HOST, "m/254315617'/net'/2'/epoch'/(i+1)'", 2u, FACTORY_TAGS,
     GZ_SG_SIGHASH_TREE_MUSIG, 0, 0},
    {GZ_SG_KEY_CONTRIBUTION, GZ_SG_ROLE_MEMBER, "m/254315617'/net'/0'/epoch'/i'", 0u, CONTRIBUTION_TAGS,
     GZ_SG_SIGHASH_NONE, 1, 1},
    {GZ_SG_KEY_FACTORY, GZ_SG_ROLE_MEMBER, "m/254315617'/net'/0'/epoch'/(i+1)'", 0u, FACTORY_TAGS,
     GZ_SG_SIGHASH_TREE_MUSIG, 0, 0},
    {GZ_SG_KEY_WALLET, GZ_SG_ROLE_HOST, "m/86'/coin'/0'/{0,1}/j", 86u, NO_TAGS, GZ_SG_SIGHASH_BIP86_KEYPATH, 0, 0},
};

const gz_sg_purpose_t *gz_sg_purposes(size_t *n)
{
    if (n) *n = sizeof PURPOSES / sizeof PURPOSES[0];
    return PURPOSES;
}

int gz_sg_may_sign_tag(gz_sg_role_t role, gz_sg_key_t key, const char *tag)
{
    size_t i, j;
    if (!tag) return 0;
    for (i = 0; i < sizeof PURPOSES / sizeof PURPOSES[0]; i++) {
        if (PURPOSES[i].key != key || PURPOSES[i].role != role) continue;
        for (j = 0; PURPOSES[i].tags[j]; j++)
            if (strcmp(PURPOSES[i].tags[j], tag) == 0) return 1;
        return 0;
    }
    return 0;
}
