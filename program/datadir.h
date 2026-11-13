/* SPDX-License-Identifier: MIT */
/* The data folder: one program per folder, and the files the program keeps
 * outside the journal.
 *
 *   lock                   held with flock(LOCK_EX) while the program runs
 *                          (journal.md section 3, "One writer"); holds the pid
 *   identity               "role network", written at first start; a later
 *                          start with another role or network is refused
 *   journal.standin        the journal stand-in (journal_standin.c)
 *   transport.key          STAND-IN: the BOLT 8 static key, 64 hex, mode 0600.
 *                          messages.md section 2 derives a member's key from
 *                          the seed, the restore epoch and a key index; that
 *                          derivation path is still open, and the key file of
 *                          storage-encryption.md (S6) is not built.
 *   wallet-seed.standin    STAND-IN: 32 bytes of entropy, 64 hex, mode 0600,
 *                          from which the wallet's 24 words and keys come.
 *                          Unencrypted, so for test networks only, until S6.
 */
#ifndef GZP_DATADIR_H
#define GZP_DATADIR_H

#include <stdint.h>

#define GZP_PATH_MAX 4096

typedef struct {
    char dir[GZP_PATH_MAX];
    int lock_fd;
} gzp_datadir_t;

/* Create the folder (0700) if missing, refuse it if others can read or
 * write it, take the lock, and check or write the identity. Returns 0, or a
 * GZP_EXIT_* status after printing why to stderr. */
int gzp_datadir_open(gzp_datadir_t *d, const char *dir, const char *role, const char *network);
void gzp_datadir_close(gzp_datadir_t *d);

/* Path of a file in the folder. 0, or -1 if too long. */
int gzp_datadir_path(const gzp_datadir_t *d, const char *name, char out[GZP_PATH_MAX]);

/* fsync the folder itself, so files created in it survive a crash. */
int gzp_datadir_sync(const gzp_datadir_t *d);

/* Read a 32-byte secret kept as 64 hex digits, creating it from the system's
 * random source if the file does not exist. `check` (may be NULL) must accept
 * the bytes; a new value is drawn again until it does. 0, or GZP_EXIT_DATA. */
int gzp_datadir_secret(const gzp_datadir_t *d, const char *name, uint8_t out[32],
                       int (*check)(const uint8_t key[32], void *ctx), void *ctx);

#endif
