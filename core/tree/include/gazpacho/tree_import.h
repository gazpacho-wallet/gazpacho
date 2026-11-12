/* The tree through the imported SuperScalar builder, and a crypto provider
 * on secp256k1-zkp, for the pure tree library (tree.h).
 *
 * NOT part of the isolated core: the imported code allocates, prints to
 * stderr and reads /dev/urandom elsewhere. This file is the only place the
 * tree library meets it. The order of calls is signing-round.md section 13's:
 *
 *   factory_init_from_pubkeys (layer step 144, 4 states)
 *   factory_set_level_arity(interior || 3)     never factory_set_arity
 *   factory_set_static_near_root(D)
 *   factory_set_ps_subfactory_arity(1)
 *   factory_set_l_stock_csv(delay)
 *   placement_mode = PLACEMENT_SEQUENTIAL, use_tree_anchor = 1,
 *   use_hashlock_poison = 0, fee_per_tx, cltv_timeout; no mirror hashes;
 *   no fee estimator
 *   the funding script checked to be 34 bytes, then factory_set_funding
 *   factory_build_tree
 *   every node read back: kind, is_ps_leaf, signers (host, then a run of
 *   members in order), parent, unsigned bytes.
 *
 * FOR THE SIGNING ENGINE (core/signing, gz_sign_build_fn). A builder callback
 * decodes round_propose (messages.md 7.2) into a gz_tree_proposal_t and calls
 * gz_tree_import_member_check. On GZ_CHK_OK each node i of the tree is one
 * item: index i, tier 0, key path; merkle root node.merkle if node.has_merkle;
 * signers participant 0 then participants 1 + first .. first + count; spent
 * (node.spent_amount, node.spent_script); the unsigned transaction node.tx.
 * Otherwise the engine aborts with verdict.reason (messages.md 7.9). */
#ifndef GAZPACHO_TREE_IMPORT_H
#define GAZPACHO_TREE_IMPORT_H

#include "gazpacho/tree.h"

#include <secp256k1.h>

/* A gz_tree_crypto_t whose functions use `ctx` (which must allow signing
 * and verification, and should carry an illegal-argument callback that does
 * not abort; every input is validated before it reaches the library). */
void gz_tree_secp_crypto(secp256k1_context *ctx, gz_tree_crypto_t *out);

typedef enum {
    GZ_TREE_I_OK = 0,
    GZ_TREE_I_ARGUMENT,     /* a NULL, a count out of bounds, or a key that does not parse */
    GZ_TREE_I_NO_MEMORY,
    GZ_TREE_I_REFUSED,      /* factory_build_tree returned 0 */
    GZ_TREE_I_TOO_BIG,      /* more nodes or bytes than gz_tree_import_t holds */
    GZ_TREE_I_SIGNERS       /* a node's signers are not the host then a run of members */
} gz_tree_i_err_t;

/* Build through the import with exactly the inputs gz_tree_build takes. */
gz_tree_i_err_t gz_tree_import_build(secp256k1_context *ctx, const gz_tree_build_in_t *in, gz_tree_import_t *out);

/* gz_tree_member_check with the imported builder plugged in: `in`'s
 * import_build, import_ctx and import_out are set here (`in` is modified).
 * The import runs only once the rules have accepted the proposal and rebuilt
 * its tree, on exactly the same inputs. `scratch` holds the import's bytes.
 * Both `t` and `scratch` are large: heap. */
void gz_tree_import_member_check(secp256k1_context *ctx, gz_tree_member_in_t *in, const gz_tree_proposal_t *p,
                                 gz_tree_t *t, gz_tree_import_t *scratch, gz_tree_verdict_t *v);

#endif
