/* SPDX-License-Identifier: MIT */
/* The wallet's encrypted storage, as the program holds it: program/unlock.h
 * (the passphrase layer the local API drives) implemented over the key file,
 * the attempts file and the sealed journal of ports/storage/crypto (S6), and
 * the keys the rest of the program takes from an unlocked wallet.
 *
 * States (storage-encryption.md 8.1): NONE (no key file), LOCKED, UNLOCKED.
 * The program comes up LOCKED (or NONE) after taking the folder lock; only an
 * unlock (or a create or a restore) that finishes opens storage, and only
 * then does the program start the node and connect (program.md 2, "Start
 * order once storage is encrypted").
 *
 * The passphrase reaches this layer only through a gzp_unlock_job_t: from the
 * local API (P5/P6), or in gazpacho-test from --test-passphrase-file. It is
 * never copied but into the derivation (the helper process, storage 8.4),
 * never logged and never on a command line.
 *
 * finish(UNLOCK) opens the journal (gz_journal_open_sealed: the fence, the
 * start rule, the incarnation) and keeps it for the executor's first
 * incarnation (gzp_wallet_take_store). A journal behind its mark file or
 * guard, or possibly old, is FILES_BEHIND: every key is dropped and the
 * wallet stays LOCKED; GZP_UNLOCK_OP_START_AS_RESTORE (below) is storage 6.3
 * step 4's way out, for the API to wire (it is not in unlock.h). */
#ifndef GZP_STORE_UNLOCK_H
#define GZP_STORE_UNLOCK_H

#include <stddef.h>
#include <stdint.h>

#include "gz_storage_files.h"

#include "store.h"
#include "unlock.h"

/* storage-encryption.md 6.3 step 4 and local-api.md start-as-restore: after
 * FILES_BEHIND, with the passphrase again. begin derives as for UNLOCK;
 * finish marks the journal as a restore (restore.gzr, floor the start
 * counter), starts the mark file again with the restore marker at the open,
 * and opens storage: the node starts as a restore under a new epoch. */
#define GZP_UNLOCK_OP_START_AS_RESTORE 100

typedef struct gzp_wallet gzp_wallet_t;

/* `dir` is the data folder (its lock held), `chain` this network's genesis
 * hash (32 bytes, kept by reference), `helper` the path of this program for
 * the KDF helper (`helper --gz-kdf-helper`, storage 8.4). The key file's
 * parameters at set-up are the default (storage 4.2); gazpacho-test may lower
 * them to the floor (gzp_wallet_test_kdf_floor). Refuses (GZP_EXIT_DATA, the
 * reason on stderr) a key file that others can read. */
int gzp_wallet_open(gzp_wallet_t **out, const char *dir, const uint8_t chain[32], const char *helper);
void gzp_wallet_free(gzp_wallet_t *w);

/* The unlock.h table over this wallet. */
gzp_unlock_t gzp_wallet_unlock_api(gzp_wallet_t *w);

/* The calls of the table, directly. */
gzp_wallet_state_t gzp_wallet_state(gzp_wallet_t *w);
void gzp_wallet_attempts(gzp_wallet_t *w, int64_t now_ms, gzp_unlock_result_t *out);
void gzp_wallet_begin(gzp_wallet_t *w, gzp_unlock_job_t *job);
void gzp_wallet_finish(gzp_wallet_t *w, gzp_unlock_job_t *job, int64_t now_ms);
void gzp_wallet_discard(gzp_wallet_t *w, gzp_unlock_job_t *job, int64_t now_ms);
void gzp_wallet_lock(gzp_wallet_t *w);

/* A result's status as a word for output lines ("ok", "wrong", ...). */
const char *gzp_unlock_status_name(int status);

/* --- while UNLOCKED ---------------------------------------------------------- */

/* The store finish opened (begun: its incarnation is durable), moved to the
 * caller; 0, or -1 if there is none (a later incarnation opens its own). */
int gzp_wallet_take_store(gzp_wallet_t *w, gzp_store_t *out);
/* A new store over the unlocked wallet, not begun (gzp_journal_store_open). */
int gzp_wallet_open_store(gzp_wallet_t *w, gzp_store_t *out, char *err, size_t errlen);
/* The 64-byte BIP 39 seed, for the wallet library (the caller wipes it). */
int gzp_wallet_seed(gzp_wallet_t *w, uint8_t seed[64]);
/* The transport's static key (stand-in until P8 derives per-member keys):
 * derived from the seed and this network, so it lives behind the key file
 * and survives a restore from the words. A secp256k1 secret (the caller
 * wipes it). 0, or -1. */
int gzp_wallet_transport_key(gzp_wallet_t *w, int (*valid)(const uint8_t key[32], void *ctx), void *ctx,
                             uint8_t out[32]);

/* For store_journal.c: the storage layer's folder and the unlocked keys
 * (NULL while locked). */
const gz_sc_store_t *gzp_wallet_sc_store(gzp_wallet_t *w);
gz_sc_unlocked_t *gzp_wallet_sc_unlocked(gzp_wallet_t *w);

#ifdef GZP_TEST_BUILD
/* gazpacho-test: set-up at the storage library's test floor (1 pass,
 * 8 KiB, the vectors' parameters) instead of the default, so the tests can
 * start many wallets, also under the slow sanitizers. */
void gzp_wallet_test_kdf_floor(gzp_wallet_t *w);
/* gazpacho-test (--test-restore-from): the next finish that opens storage
 * imports this backup of the journal first, as a restore. */
void gzp_wallet_test_restore_from(gzp_wallet_t *w, const char *backup);
/* gazpacho-test (--test-dump-journal): an unlock that only derives the keys:
 * no attempts file, no journal open, no clean-up; nothing is written. */
void gzp_wallet_test_keys_only(gzp_wallet_t *w);
#endif

#endif
