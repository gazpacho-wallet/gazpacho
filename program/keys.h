/* SPDX-License-Identifier: MIT */
/* Keys (docs/notes/keys.md, P8): every key the program signs with, derived
 * from the wallet's BIP 39 seed.
 *
 *   m/254315617'/net'/0'/epoch'/index'   per-lobby keys: the contribution
 *                                        (BOLT 8) key at i, the factory key
 *                                        at i + 1 (contract-v2.md 13)
 *   m/254315617'/net'/1'/k'              the host's long-term key, k the
 *                                        first valid of 0, 1, 2, ...
 *   m/86'/coin'/0'/{0,1}/j               the on-chain wallet (BIP 86); a
 *                                        payout script is receive index j
 *
 * What is held. The key port keeps no seed, no master key and no
 * intermediate node: each derivation asks the seed source for the seed,
 * walks the path, keeps the one result it was asked for and wipes the rest
 * before it returns. It keeps the BIP 86 account's PUBLIC key (payout
 * scripts need no secret), the current epoch, and, under AT_JOIN, the
 * scoped table: per open per-lobby gate, that lobby's factory and
 * contribution secrets, bound to (scope, values digest), wiped at forget.
 *
 * Policy (keys.md 3). gzp_keys_lobby derives only under the current epoch
 * (the newest key_epoch record the node has read or saved; 0 before one)
 * and nothing while frozen (a restore start, until the new epoch is saved):
 * safety-rule.md C12 and R3. gzp_keys_lobby_raw has no policy and exists for
 * the vectors and the test-engine single key.
 *
 * Returns. 1 on success, 0 on failure; on failure every output holding key
 * material is zeroed, and *why (may be NULL) says why. Secrets handed out
 * are the caller's to wipe (gzw_wipe). Nothing here logs, prints or stores
 * a secret. Not thread-safe: the loop thread only. */
#ifndef GZP_KEYS_H
#define GZP_KEYS_H

#include <stddef.h>
#include <stdint.h>

#include <secp256k1.h>

#include "gazpacho/wallet_keys.h"
#include "unlock.h"

/* SHA256("gazpacho keys")[0..4] & 0x7fffffff (contract-v2.md 13). */
#define GZP_KEYS_PURPOSE 254315617u
#define GZP_KEYS_BRANCH_LOBBY 0u
#define GZP_KEYS_BRANCH_HOST 1u
#define GZP_KEYS_MAX_SCOPES 8     /* GZ_NODE_MAX_SLOTS */
#define GZP_KEYS_INDEX_LIMIT 0x80000000u

/* Where the seed comes from: the storage layer while it is unlocked, or the
 * stand-in seed file until storage lands (keys.md 9). seed() fills out with
 * the 64-byte BIP 39 seed and returns 1, or returns 0 when there is none
 * (locked); the caller wipes out. */
typedef struct {
    int (*seed)(void *ctx, uint8_t out[64]);
    void *ctx;
} gzp_seed_source_t;

/* The seed source over the passphrase layer (program/unlock.h, seed(): 0
 * with the seed while UNLOCKED, -1 when not unlocked, -2 when storage cannot
 * give it). Anything but 0 is "no seed", with out wiped. `u` must outlive the
 * source. This is the program's seed source once storage lands; until then
 * the stand-in of keys_standin.h stands in for it. */
gzp_seed_source_t gzp_keys_seed_from_unlock(const gzp_unlock_t *unlock);

/* Why a call failed. */
typedef enum {
    GZP_KEYS_OK = 0,
    GZP_KEYS_NO_SEED,        /* the seed source has none (locked) */
    GZP_KEYS_BAD_ARGUMENT,   /* an epoch or index at or above 2^31, a network with no level, NULL */
    GZP_KEYS_POLICY,         /* another epoch than the current one, or frozen (a restore start) */
    GZP_KEYS_INVALID_CHILD,  /* BIP 32's rare case; *level says where (keys.md 3) */
    GZP_KEYS_UNUSABLE,       /* the seed cannot be used with Gazpacho (an invalid level above the epoch) */
    GZP_KEYS_FULL,           /* the scoped table is full */
    GZP_KEYS_INTERNAL
} gzp_keys_why_t;

typedef struct {
    gzp_keys_why_t why;
    unsigned level;          /* GZP_KEYS_INVALID_CHILD: the path step that failed, 0 the master */
} gzp_keys_err_t;

typedef struct {
    int used;
    uint8_t scope[32];
    uint8_t digest[32];
    uint8_t factory[32];         /* SECRET */
    uint8_t contribution[32];    /* SECRET */
} gzp_keys_scope_t;

typedef struct {
    const secp256k1_context *secp;
    gzw_network wnet;
    uint32_t net_level;
    gzp_seed_source_t src;
    gzw_xpub account;            /* m/86'/coin'/0', public */
    uint32_t epoch;              /* the current restore epoch */
    int frozen;                  /* a restore start: no per-lobby key until the new epoch is saved */
    int scoped_only;             /* AT_JOIN: secrets for rounds only from the scoped table */
    gzp_keys_scope_t scopes[GZP_KEYS_MAX_SCOPES];
} gzp_keys_t;

/* The network level below the purpose: testnet4 1, signet 2, testnet3 3,
 * regtest 4. 0 (and nothing in *out) for mainnet and any other value. */
int gzp_keys_net_level(gzw_network net, uint32_t *out);

/* Set up over a seed source, and check the seed can be used: the master,
 * every level above the epoch on both Gazpacho branches, and the BIP 86
 * account. *err: NO_SEED, BAD_ARGUMENT, UNUSABLE or INTERNAL. `secp` must
 * outlive k. The epoch starts at 0, not frozen, the table empty. */
int gzp_keys_init(gzp_keys_t *k, const secp256k1_context *secp, gzw_network net, const gzp_seed_source_t *src,
                  gzp_keys_err_t *err);

/* Wipe everything, the scoped table included. */
void gzp_keys_free(gzp_keys_t *k);

/* The per-lobby key at (epoch, index), no policy. sec or pub may be NULL. */
int gzp_keys_lobby_raw(const gzp_keys_t *k, uint32_t epoch, uint32_t index, uint8_t sec[32], uint8_t pub[33],
                       gzp_keys_err_t *err);

/* The same under the policy: the current epoch only, nothing while frozen. */
int gzp_keys_lobby(const gzp_keys_t *k, uint32_t epoch, uint32_t index, uint8_t sec[32], uint8_t pub[33],
                   gzp_keys_err_t *err);

/* The host's long-term key, k the first valid of 0, 1, 2, ...; *k_out (may
 * be NULL) says which. sec or pub may be NULL. */
int gzp_keys_host(const gzp_keys_t *k, uint8_t sec[32], uint8_t pub[33], uint32_t *k_out, gzp_keys_err_t *err);

/* The payout script of receive index j (exit.md 3.4): 51 20 <BIP 86 output
 * key of m/86'/coin'/0'/0/j>, from the account's public key alone. */
int gzp_keys_payout_script(const gzp_keys_t *k, uint32_t j, uint8_t spk[34], gzp_keys_err_t *err);

/* The wallet output at change/j derived from the seed, privately all the way
 * and publicly below the account (gzw_bip86_output_from_master). change 0
 * or 1. Public. */
int gzp_keys_wallet_output(const gzp_keys_t *k, uint32_t change, uint32_t j, gzw_bip86_output *out,
                           gzp_keys_err_t *err);

/* The current epoch, and the restore freeze (keys.md 3). */
void gzp_keys_set_epoch(gzp_keys_t *k, uint32_t epoch);
void gzp_keys_freeze(gzp_keys_t *k, int frozen);

/* AT_JOIN's scoped secrets (composite-node.md 12.2; keys.md 7). Open: derive
 * the pair (contribution at index, factory at index + 1) under the policy and
 * keep it for (scope, digest); a scope already held is replaced, its old
 * secrets wiped first; FULL when 8 others are held. Lookup: 1 and both
 * secrets only for that scope AND that digest (compared in constant time).
 * Forget: wipe the scope's entry; forget_all: every entry. */
int gzp_keys_scope_open(gzp_keys_t *k, const uint8_t scope[32], const uint8_t digest[32], uint32_t epoch,
                        uint32_t index, gzp_keys_err_t *err);
int gzp_keys_scoped(const gzp_keys_t *k, const uint8_t scope[32], const uint8_t digest[32], uint8_t factory[32],
                    uint8_t contribution[32]);
void gzp_keys_forget(gzp_keys_t *k, const uint8_t scope[32]);
void gzp_keys_forget_all(gzp_keys_t *k);
size_t gzp_keys_scopes_held(const gzp_keys_t *k);

/* For net.c (gzp_net_t.key_fn): gzp_keys_lobby with ctx a gzp_keys_t. */
int gzp_keys_net_fn(void *ctx, uint32_t epoch, uint32_t index, uint8_t sec[32], uint8_t pub[33]);

#endif
