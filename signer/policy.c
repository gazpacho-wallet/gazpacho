/* The tables of docs/notes/signer.md section 3: which key may sign what.
 * Pure data and lookups; no key is held here. */
#include "gazpacho/signer.h"
#include "gazpacho/lobby.h"
#include "gazpacho/round_msg.h"

#include <string.h>

/* ---- 3.2 kinds per key ----
 * signer.md 3.2 as amended by its review (M1): a kind is signable only if
 * spec/messages.md gives it a signature, record 240. Every other kind,
 * hello, terms_offer, join, unready, leave, lobby_status, round_nonces,
 * round_all_nonces, round_status_request and factory_funded among them, is
 * refused under every key. The test compares this table with one read from
 * messages.md (tools/signer-vectors.py), never with a copy of it. */

typedef struct {
    uint16_t kind;
    uint8_t host, member;   /* 1: the host's long-term key / a member's contribution key may sign it */
} kind_row_t;

static const kind_row_t KINDS[] = {
    {GZ_KIND_READY, 0, 1},
    {GZ_KIND_READY_CHECK, 1, 0},
    {GZ_KIND_START, 1, 0},
    {GZ_KIND_CANCEL, 1, 0},
    {GZ_KIND_ROUND_PROPOSE, 1, 0},
    {GZ_KIND_ROUND_PARTIAL_SIGS, 0, 1},
    {GZ_KIND_ROUND_TIER_RESULT, 1, 0},
    {GZ_KIND_ROUND_COMPLETE, 1, 0},
    {GZ_KIND_ROUND_ACK, 0, 1},
    {GZ_KIND_ROUND_ABORT, 1, 1},
};

int gz_sg_kind_allowed(gz_sg_role_t role, gz_sg_key_t key, uint16_t kind)
{
    size_t i;
    if (!((role == GZ_SG_ROLE_HOST && key == GZ_SG_KEY_HOST) ||
          (role == GZ_SG_ROLE_MEMBER && key == GZ_SG_KEY_CONTRIBUTION)))
        return 0;
    for (i = 0; i < sizeof KINDS / sizeof KINDS[0]; i++)
        if (KINDS[i].kind == kind) return role == GZ_SG_ROLE_HOST ? KINDS[i].host : KINDS[i].member;
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
