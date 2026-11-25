/* The signer: the one library that holds long-term and per-lobby secret keys
 * and makes signatures (docs/notes/signer.md, decisions D1 to D3).
 *
 * Stage 1 (signer.md 9, S1 and the skeleton of S4). This header is the whole
 * interface of section 2 of the note, typed operations only. There is no
 * operation that takes a digest, a sighash type or a free-form message, and
 * there never will be. Implemented in stage 1:
 *
 *   gz_signer_size, gz_signer_init, gz_signer_wipe   the state
 *   gz_sg_host_pub                                    the host's public key
 *   gz_sg_slot_add, gz_sg_slot_drop                   slots
 *   gz_sg_sign_envelope                               message signatures
 *   gz_sg_kind_allowed, gz_sg_purposes,
 *   gz_sg_may_sign_tag                                the tables of section 3
 *   gz_sg_spend_back_fee_cap                          the spend-back's fee cap (2.3)
 *
 * Every other operation is declared with its final shape and refuses with
 * GZ_SG_E_NOT_YET, outputs zeroed, until step S4 moves its code in (it
 * depends on open PRs: #52 for the gate and rounds, #53 for the derivation
 * layer, #56 for the funding wallet, #59 for the binding).
 *
 * Rules every operation keeps:
 *   - It does no I/O and keeps no global or static state: all state is in the
 *     gz_signer_t the caller allocates (gz_signer_size bytes).
 *   - It reads randomness only through the random port, and the seed only
 *     through the seed source, which gives a seed only while storage is
 *     unlocked. Seeds, master keys and intermediate BIP 32 nodes are never
 *     kept: each derivation walks the path, keeps the one key it needs and
 *     wipes the rest (gzw_wipe).
 *   - It returns GZ_SG_OK (0) or a refusal reason. On any refusal every
 *     output buffer is zeroed and the signer's state is unchanged.
 *   - Never mainnet.
 */
#ifndef GAZPACHO_SIGNER_H
#define GAZPACHO_SIGNER_H

#include <stddef.h>
#include <stdint.h>

#include <secp256k1.h>

#include "gazpacho/ports.h"        /* gz_random_port_t */
#include "gazpacho/signing.h"      /* gz_sign_def_t */
#include "gazpacho/wallet_keys.h"  /* gzw_network */
#include "gazpacho/wallet_tx.h"    /* gzt_funding_request, gzt_coin, gzt_funding_info */

#ifdef GZ_SG_VECTORS   /* the test-only build: other names, so nothing else can link it */
#ifndef GZ_SG_VECTORS_BUILD_TARGET
/* A tripwire only: set by gazpacho_signer_vectors' own compile definitions.
 * The real guard is that the production sources hold no fixed-aux path at
 * all (vectors_aux.c is compiled into the vectors build only). */
#error "GZ_SG_VECTORS outside the signer's vectors build (docs/notes/signer.md, K20)"
#endif
#include "gazpacho/signer_vectors_names.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 2.4 refusal reasons ---- */
typedef enum {
    GZ_SG_OK = 0,
    GZ_SG_E_ARG,        /* NULL, a length out of range, a malformed point or record stream */
    GZ_SG_E_NO_SEED,    /* locked: the seed source has no seed */
    GZ_SG_E_EPOCH,      /* another epoch than the current one, or frozen */
    GZ_SG_E_SLOT,       /* unknown slot, slot already held, or slot table full */
    GZ_SG_E_GATE,       /* AT_JOIN gate closed, or opened for another digest */
    GZ_SG_E_SEAT_KEY,   /* derived factory key differs from seat_key (protocol reason 12) */
    GZ_SG_E_KIND,       /* a kind, tag or key outside the key's row (section 3) */
    GZ_SG_E_ROUND,      /* a round check of 2.3 failed */
    GZ_SG_E_NONCE,      /* no secret nonce, already used, or our own nonce missing */
    GZ_SG_E_PLAN,       /* no plan under that txid, or the plan check failed */
    GZ_SG_E_FEE,        /* above the fee cap */
    GZ_SG_E_INTERNAL,   /* a self-check failed */
    GZ_SG_E_NOT_YET = 100   /* stage 1 only: the operation lands in step S4 */
} gz_sg_err_t;

/* ---- 2.1 shape ---- */
typedef struct gz_signer gz_signer_t;   /* opaque; gz_signer_size() bytes of the caller's memory */

typedef enum { GZ_SG_ROLE_HOST = 1, GZ_SG_ROLE_MEMBER = 2 } gz_sg_role_t;

/* The seed source (PR #53's gzp_seed_source_t, the same shape): fills `out`
 * with the 64-byte BIP 39 seed and returns 1, or returns anything else when
 * there is none (storage locked). The signer wipes `out` itself. */
typedef struct {
    int (*seed)(void *ctx, uint8_t out[64]);
    void *ctx;
} gz_sg_seed_source_t;

typedef struct {
    /* Made with secp256k1_context_create(SECP256K1_CONTEXT_NONE) and
     * randomised by the caller; it must outlive the signer. */
    const secp256k1_context *secp;
    gz_sg_role_t role;              /* fixed per data folder */
    gzw_network network;            /* testnet3, testnet4, signet or regtest; never mainnet */
    uint32_t epoch;                 /* the restore epoch (safety rule C12, R3) */
    int frozen;                     /* 1: restore freeze, no per-lobby key is derived */
    gz_sg_seed_source_t seed;
    gz_random_port_t random;        /* aux_rand of every signature: 32 bytes, GZ_RANDOM_SECRET */
    /* The highest fee rate the signer ever pays, sat/kvB: 1 to
     * GZ_SG_FEERATE_HARD_MAX. Set by the program from its own policy, never
     * from a request (review A of #71, M3); fund_plan, fund_adopt and
     * fund_spend_back use it as the ceiling. */
    uint64_t max_feerate;
} gz_sg_config_t;

/* The bound on max_feerate: 5 sat/vB, fifty times the owner's 0.1 sat/vB. */
#define GZ_SG_FEERATE_HARD_MAX 5000u

/* Bytes the caller allocates for one signer. */
size_t gz_signer_size(void);
/* Make a signer in `mem` (`size` >= gz_signer_size(), suitably aligned, as
 * malloc returns, in pages the program locks or marks MADV_DONTDUMP:
 * signer.md 7.3). Takes nothing from the seed source yet. A refused init
 * leaves `mem` as it was. */
gz_sg_err_t gz_signer_init(gz_signer_t *mem, size_t size, const gz_sg_config_t *cfg);
/* Wipe every key and every byte of the signer. It must be made again with
 * gz_signer_init before any other use. */
void gz_signer_wipe(gz_signer_t *sg);

/* ---- 2.2 common inputs ---- */
#define GZ_SG_MAX_SLOTS 32           /* GZP_KEYS_MAX_SLOTS: open and closing slots */
#define GZ_SG_INDEX_LIMIT 0x80000000u

typedef struct {                     /* a slot, as the node part names it */
    uint8_t scope[32];               /* the lobby id: TH("gazpacho/terms/outer", outer) */
    /* key_index is i, the pair's contribution index (core/node's
     * s->key_index), never the journalled i + 1: the contribution key is at i
     * and the factory key at i + 1. */
    uint32_t epoch, key_index;
} gz_sg_slot_t;

typedef enum {                       /* which of the slot's keys, or the host's */
    GZ_SG_KEY_HOST = 1,              /* the host's long-term key (host only) */
    GZ_SG_KEY_CONTRIBUTION,          /* the member's per-lobby key (member only) */
    GZ_SG_KEY_FACTORY,               /* the slot's factory key (both); signs no message */
    GZ_SG_KEY_WALLET                 /* BIP 86 wallet keys: for the tables only; no message operation takes it */
} gz_sg_key_t;

typedef uint32_t gz_sg_round_t;      /* a round handle (2.3, round_open) */

/* ---- 3 the tables ---- */

/* 3.2 (as amended by its review, M1): 1 if `key` of a party with `role` may
 * sign an envelope of `kind`, which is exactly when spec/messages.md gives
 * that kind a signature (record 240) from that sender: the host 30, 32, 34,
 * 64, 72, 74 and 78; a member 22, 70, 76 and 78. 0 for every other
 * combination. */
int gz_sg_kind_allowed(gz_sg_role_t role, gz_sg_key_t key, uint16_t kind);

/* 3.1, one row per key: its derivation, the BIP 340 tags it may sign
 * directly (NULL-terminated), the sighashes it may sign, whether it does
 * ECDH. A design and audit table; it holds no key. */
#define GZ_SG_SIGHASH_NONE 0u
#define GZ_SG_SIGHASH_TREE_MUSIG 1u   /* MuSig2 partials over the signer's own TapSighash, key path, SIGHASH_DEFAULT */
#define GZ_SG_SIGHASH_BIP86_KEYPATH 2u /* BIP 341 key path, SIGHASH_DEFAULT, of a held funding plan and its spend-backs */
typedef struct {
    gz_sg_key_t key;
    gz_sg_role_t role;
    const char *path;                /* as in PR #53's keys.md */
    uint32_t branch;                 /* m/254315617'/net'/branch'/..., or 86 for the wallet */
    const char *const *tags;         /* BIP 340 tags it may sign, NULL-terminated; never a TapSighash */
    unsigned sighash;                /* GZ_SG_SIGHASH_* */
    int ecdh;                        /* 1: BOLT 8 ECDH */
    int stage1;                      /* 1: an operation of stage 1 uses it */
} gz_sg_purpose_t;
const gz_sg_purpose_t *gz_sg_purposes(size_t *n);
/* 1 if `key` of a party with `role` may sign BIP 340 over a hash with `tag`. */
int gz_sg_may_sign_tag(gz_sg_role_t role, gz_sg_key_t key, const char *tag);

/* ---- the host's key ---- */

/* The host's long-term public key, m/254315617'/net'/1'/k' with k the first
 * index BIP 32 allows (0 but in its rare invalid case). Derived on first use
 * and then held for the life of the signer: the transport needs it for every
 * handshake. Host only (GZ_SG_E_KIND on a member). */
gz_sg_err_t gz_sg_host_pub(gz_signer_t *sg, uint8_t pub[33]);

/* ---- 2.3 operations: slots and gates ---- */

/* Register a slot before any operation names it.
 *   1. The epoch is current and not frozen (C12, R3)          GZ_SG_E_EPOCH
 *   2. key_index + 1 is below 2^31: both keys are hardened     GZ_SG_E_ARG
 *      indexes. Any key_index, odd or even: the node part allocates
 *      pairs (1, 2), (3, 4), ... (review A of #71, H2)
 *   3. The slot's scope is not already held                    GZ_SG_E_SLOT
 *   4. The table has room                                      GZ_SG_E_SLOT
 * A member's contribution key is m/254315617'/net'/0'/epoch'/key_index',
 * held while the slot lives; its factory key is at key_index + 1 on the
 * same branch. A host's contribution key is its long-term key, and its own
 * factory key in the lobby is m/254315617'/net'/2'/epoch'/(key_index+1)'.
 * Returns both public keys; `factory_pub` may be NULL. The factory secret is
 * not kept (stage 1 has no gate; S4 keeps it behind gate_open). */
gz_sg_err_t gz_sg_slot_add(gz_signer_t *sg, const gz_sg_slot_t *slot, uint8_t contribution_pub[33],
                           uint8_t factory_pub[33]);
/* Forget a slot and wipe its keys. Unknown scopes are ignored. */
void gz_sg_slot_drop(gz_signer_t *sg, const uint8_t scope[32]);

/* S4 (PR #52, PR #59): the AT_JOIN gate. */
gz_sg_err_t gz_sg_gate_open(gz_signer_t *sg, const uint8_t scope[32], const uint8_t digest[32],
                            uint8_t factory_pub[33]);
void gz_sg_gate_close(gz_signer_t *sg, const uint8_t scope[32]);
void gz_sg_gate_close_all(gz_signer_t *sg);
gz_sg_err_t gz_sg_seat_key(gz_signer_t *sg, const uint8_t scope[32], const uint8_t seat_key[33]);

/* ---- 2.3 operations: messages ---- */

/* Sign an envelope. The signer computes the hash itself:
 *   msg_hash = TH("gazpacho/msg", protocol || kind || scope || records)
 * (messages.md 4.3; the same code as gz_rmsg_hash) and never takes a digest.
 *   1. `key` matches the role: HOST only on a host, CONTRIBUTION only on a
 *      member; never FACTORY (the factory key signs no message) and never
 *      WALLET                                                  GZ_SG_E_KIND
 *   2. `kind` is in the key's row of table 3.2                 GZ_SG_E_KIND
 *   3. `len` is at most one envelope's records (65,495), or for the host's
 *      signed round kinds (64, 72, 74, 78) a reassembled message's
 *      (messages.md 5)                                         GZ_SG_E_ARG
 *   4. `records` is a well-formed record stream (messages.md 4.2: minimal
 *      BigSize, increasing types, no length past the end) of types below
 *      240: no signature record, which is the signer's to append   GZ_SG_E_ARG
 *   5. `scope` is a held slot (a member's lobby, or a lobby this host has
 *      open)                                                   GZ_SG_E_SLOT
 * Every signature draws 32 bytes of aux_rand (GZ_RANDOM_SECRET) from the
 * random port: there is no deterministic mode (decision K20; review B of
 * #71, M2). The signature is verified before it is returned. */
gz_sg_err_t gz_sg_sign_envelope(gz_signer_t *sg, gz_sg_key_t key, const uint8_t scope[32], uint16_t kind,
                                const uint8_t *records, size_t len, uint8_t sig[64]);

/* S4: the terms (host) and the binding. */
gz_sg_err_t gz_sg_sign_terms(gz_signer_t *sg, const uint8_t *outer, size_t olen, const uint8_t *current,
                             size_t clen, uint8_t outer_sig[64], uint8_t current_sig[64]);
gz_sg_err_t gz_sg_sign_binding(gz_signer_t *sg, const uint8_t scope[32], gz_sg_key_t key, uint8_t sig[64]);

/* ---- 2.3 operations: rounds (S4, PR #52) ---- */
gz_sg_err_t gz_sg_round_open(gz_signer_t *sg, const uint8_t scope[32], const gz_sign_def_t *def,
                             const uint8_t round_id[32], const uint8_t host_random[32], gz_sg_round_t *handle);
gz_sg_err_t gz_sg_nonce(gz_signer_t *sg, gz_sg_round_t handle, uint16_t item, uint8_t pubnonce[66],
                        uint8_t attest_sig[64]);
gz_sg_err_t gz_sg_partial(gz_signer_t *sg, gz_sg_round_t handle, uint16_t item, const uint8_t (*nonces)[66],
                          uint8_t n, uint8_t psig[32]);
void gz_sg_round_close(gz_signer_t *sg, gz_sg_round_t handle);

/* ---- 2.3 operations: transport (S4) ---- */
gz_sg_err_t gz_sg_ecdh(gz_signer_t *sg, gz_sg_key_t key, const gz_sg_slot_t *slot, const uint8_t point[33],
                       uint8_t shared[32]);

/* ---- 2.3 operations: the on-chain wallet, host funding (S4/S5, PR #56) ---- */

/* A spent output of a plan, as the funding engine checks it. */
typedef struct {
    uint8_t txid[32];
    uint32_t vout;
    uint64_t amount;
    uint8_t script[34];
} gz_sg_prevout_t;

gz_sg_err_t gz_sg_fund_plan(gz_signer_t *sg, const gzt_funding_request *req, const gzt_coin *coins, size_t n,
                            gzt_funding_info *info, uint8_t *unsigned_tx, size_t cap, size_t *len,
                            gz_sg_prevout_t *prev, size_t max_prev, size_t *n_prev);
gz_sg_err_t gz_sg_fund_sign(gz_signer_t *sg, const uint8_t txid[32], uint8_t *out, size_t cap, size_t *len);
/* The spend-back: `fee` must be at most gz_sg_spend_back_fee_cap() of the
 * held plan, computed from the plan's own fee and size, never the caller's. */
gz_sg_err_t gz_sg_fund_spend_back(gz_signer_t *sg, const uint8_t txid[32], uint32_t input, uint64_t fee,
                                  uint8_t *out, size_t cap, size_t *len);
gz_sg_err_t gz_sg_fund_adopt(gz_signer_t *sg, const uint8_t *unsigned_tx, size_t len, const uint8_t txid[32],
                             const uint8_t funding_script[34], uint64_t amount);
void gz_sg_fund_release(gz_signer_t *sg, const uint8_t txid[32]);

/* The spend-back's fee cap (signer.md 2.3, fund_spend_back check 3; review
 * B of #56, M-3). The engine's ladder is: level 0, the ordinary rate when
 * the funding was never seen; level 1, the smallest fee that replaces the
 * funding with Core 29.1's increment (100 sat/kvB); level 2, the same with
 * Core 28.x and 29.0's increment (1,000 sat/kvB). A cap of "ceiling x vsize"
 * refuses level 2 (127 sat against 111 on the 111 vB spend-back of a 16 sat,
 * 154 vB funding), so the cap is the larger of
 *   - the ceiling rate on the spend-back's size: ceil(ceiling x vsize / 1000);
 *   - the top of the ladder: the plan's fee plus ceil(GZ_SG_INCREMENTAL_HIGH
 *     x vsize / 1000), raised if needed to one satoshi above the plan's own
 *     rate on the spend-back's size (Core's rule 6: plan_fee x vsize /
 *     plan_vsize + 1).
 * `plan_fee` and `plan_vsize` are the held plan's, computed by the signer
 * from the plan it built or adopted (inputs minus outputs; its own size).
 * The ceiling is the signer's own max_feerate, read from `sg`: no caller
 * chooses it (review B of #71, M1). Rates are sat/kvB, sizes vbytes.
 * Fails closed: returns 0, which refuses every fee, when `sg` is not a live
 * signer, for an out-of-range input (a size of 0 or above 4,000,000 vB, a
 * fee above 21 million BTC), and when `plan_fee` is above the ceiling on the
 * plan's own size, ceil(max_feerate x plan_vsize / 1000): such a plan was
 * never one the signer built or adopted, so the cap is bounded by the policy
 * alone. */
#define GZ_SG_INCREMENTAL_HIGH 1000u
uint64_t gz_sg_spend_back_fee_cap(const gz_signer_t *sg, uint64_t plan_fee, uint64_t plan_vsize,
                                  uint64_t spend_back_vsize);

#ifdef __cplusplus
}
#endif

#endif /* GAZPACHO_SIGNER_H */
