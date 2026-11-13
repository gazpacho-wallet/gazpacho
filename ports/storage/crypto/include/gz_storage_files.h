/* The storage layer's files in the data folder (spec 3.1, 6.3, 7, 9.3, 10, 12.3).
 *
 * Every operating-system call goes through a table (gz_sc_os_t) so tests can
 * fail or "crash" at any call, as the journal's fault injection does. Writes
 * follow spec 7: atomic replaces (name.tmp created exclusively, owner-only,
 * synced, renamed, folder synced) and appends (cut a torn tail, append,
 * sync). No retry of a failed write or sync (7 rule 7). */
#ifndef GAZPACHO_STORAGE_FILES_H
#define GAZPACHO_STORAGE_FILES_H

#include "gz_storage_crypto.h"

#include <stddef.h>
#include <stdint.h>

#define GZ_SC_FILE_KEYS "keys.gzk"
#define GZ_SC_FILE_JOURNAL "journal.gzj"
#define GZ_SC_FILE_GUARD "guard.gzg"
#define GZ_SC_FILE_MARK "mark.gzm"
#define GZ_SC_FILE_ATTEMPTS "attempts.gza"

/* The operating-system calls the storage layer makes. Each returns -1 (or a
 * negative count) on failure, like POSIX. */
typedef struct {
    void *ctx;
    int (*open)(void *ctx, const char *path, int flags, int mode);
    long (*write)(void *ctx, int fd, const void *p, size_t n);
    long (*read)(void *ctx, int fd, void *p, size_t n);
    int (*fsync)(void *ctx, int fd); /* F_FULLFSYNC on macOS */
    int (*ftruncate)(void *ctx, int fd, uint64_t len);
    int (*close)(void *ctx, int fd);
    int (*rename)(void *ctx, const char *from, const char *to);
    int (*unlink)(void *ctx, const char *path);
} gz_sc_os_t;

extern const gz_sc_os_t gz_sc_os_posix;

/* One data folder of one network. */
typedef struct {
    const gz_sc_os_t *os;
    const char *dir; /* absolute, no trailing slash */
    uint8_t chain[32];
    gz_sc_kdf_fn kdf; /* gz_sc_kdf_helper in the program */
    void *kdf_ctx;
} gz_sc_store_t;

/* ---- files ------------------------------------------------------------------ */
/* At most max bytes of dir/name into a malloc'd buffer. MISSING if absent. */
gz_sc_err_t gz_sc_fs_read(const gz_sc_store_t *s, const char *name, size_t max, uint8_t **data, size_t *len);
/* GZ_SC_DONE_WITH_FAULT: the rename happened (the new file is the one in the
 * folder) but the folder sync failed, so a power cut may bring the old one
 * back (review B, L1). The guard, mark file, journal and attempts writes of
 * this layer report that as GZ_SC_STORAGE_FAILED (nothing is confirmed on
 * it); the key file writes (set-up, change, recovery) report it as it is. */
gz_sc_err_t gz_sc_fs_replace(const gz_sc_store_t *s, const char *name, const uint8_t *data, size_t len);
/* Cut the file to `at` (a torn tail), write data there, sync. */
gz_sc_err_t gz_sc_fs_append(const gz_sc_store_t *s, const char *name, uint64_t at, const uint8_t *data, size_t len);

/* ---- set-up, unlock, start ----------------------------------------------------- */
typedef struct {
    gz_sc_vault_t *vault;
    gz_sc_framekey_t *kj; /* the journal key KJ for file_id */
    gz_sc_framekey_t *kh; /* the mark file key KH for file_id */
    uint8_t file_id[16];
    int restore;     /* this call made a new journal for a restore (6.3 step 0, or
                      * gz_sc_setup_restore); the start rule's GZ_SC_START_RESTORE
                      * says so on every start until the restore batch is anchored */
    int mem_locked;  /* the KDF helper locked its pages */
    int upgrade_due; /* the key file's parameters are below the default (4.7) */
    gz_sc_keyfile_info_t info;
} gz_sc_unlocked_t;

void gz_sc_unlocked_clear(gz_sc_unlocked_t *u); /* wipes and frees every key */

/* Passphrases (review A, M3). Every function here that takes one refuses it
 * with GZ_SC_PASS_REFUSED, before reading or deriving anything, unless it is
 * valid UTF-8 and byte for byte its own NFC form (gz_sc_pass_nfc gives that
 * form): a decomposed spelling never makes or opens a key. The functions that
 * make a key file from one (gz_sc_setup, gz_sc_setup_restore, gz_sc_rewrap's
 * new passphrase, gz_sc_recover_keyfile) also refuse it outside 4.1's lengths
 * (15 code points to 1,024 bytes) or with an unassigned code point or U+0000
 * (review B, L3); gz_sc_pass_check_form says which rule. The name, words and
 * blocklist rules need the wallet's name and words: the caller must have run
 * gz_sc_pass_check on a new passphrase before calling these. */

/* 7.4's creation order: MSK, vault_id, salt, PK (KDF); keys.gzk; guard.gzg
 * (counter 0, no epochs); file_id; mark.gzm with (0, 0); journal.gzj (header
 * only). entropy and seed come from the wallet library (BIP 39). params: the
 * calibrated default (4.2). u->info is filled as gz_sc_unlock fills it.
 * Writes over nothing of a wallet (review B, M1): EXISTS if a key file, a
 * guard or a mark file is there; JOURNAL_HERE if a journal is (the words
 * reopen it: gz_sc_recover_keyfile). A wallet restored from its words where
 * no journal is left uses gz_sc_setup_restore.
 * GZ_SC_DONE_WITH_FAULT (review B, L1): the key file was renamed into place,
 * so the wallet exists, but a later step failed (or the folder sync did): u
 * is cleared. Answer it by unlocking with the same passphrase, never by
 * offering set-up as if nothing happened: the unlock completes the files as
 * a restore (6.3 step 0), and the words are shown after it; only if a power
 * cut undid the unsynced rename does that unlock find no key file
 * (GZ_SC_MISSING), and set-up is then offered again. */
gz_sc_err_t gz_sc_setup(const gz_sc_store_t *s, const uint8_t *pw_nfc, size_t pw_len,
                        const gz_sc_kdf_params_t *params, const uint8_t entropy[32], const uint8_t seed[64],
                        gz_sc_unlocked_t *u);

/* 9.3's first bullet, "new device, or no journal": the 24 words and a new
 * passphrase give a new MSK, vault_id and key file, then a new journal whose
 * mark file holds the restore marker (u->restore set; the start rule gives
 * GZ_SC_START_RESTORE until the restore's first batch is anchored). A guard
 * file in the folder is kept, never replaced here (review B, M1): if it opens
 * under the seed, the restore's first batch carries its counter and epochs
 * on (journal.md 8.3); if it does not, that batch's guard write replaces it.
 * A stale mark file is replaced. EXISTS if a key file is there,
 * JOURNAL_HERE if a journal is. DONE_WITH_FAULT as for gz_sc_setup. */
gz_sc_err_t gz_sc_setup_restore(const gz_sc_store_t *s, const uint8_t *pw_nfc, size_t pw_len,
                                const gz_sc_kdf_params_t *params, const uint8_t entropy[32],
                                const uint8_t seed[64], gz_sc_unlocked_t *u);

/* 8.2 step 1 and 3's header: the key file (4.5), then the journal header.
 * A key file with no journal (6.3 step 0): a mark file with the restore
 * marker, then a new journal, are written and u->restore is set ("this
 * unlock did step 0"; whether a start is a restore is the start rule's
 * GZ_SC_START_RESTORE, which also covers a step 0 interrupted before its
 * first batch). MISSING: no key file. A storage failure reading the journal
 * header is returned as such. Once the key file has opened, stale name.tmp
 * files of a crashed replace are removed. */
gz_sc_err_t gz_sc_unlock(const gz_sc_store_t *s, const uint8_t *pw_nfc, size_t pw_len,
                         const gz_sc_kdf_params_t *def, gz_sc_unlocked_t *u);

/* 4.6 "check" (8.2) while unlocked: derives in the helper from the key file
 * on disk and compares the MSK it opens with v's in constant time
 * (gz_sc_keyfile_check). GZ_SC_OK, WRONG_PASSPHRASE, NOT_THIS_WALLET, or the
 * helper's and the storage's failures. */
gz_sc_err_t gz_sc_check(const gz_sc_store_t *s, const gz_sc_vault_t *v, const uint8_t *pw_nfc, size_t pw_len);

/* 6.3 steps 1 and 2 after the journal's scan: reads mark.gzm and guard.gzg
 * and gives the rule's outcome in *start. Only a file that does not exist is
 * "missing"; any other failure to read either file (EIO, EMFILE, ...) is
 * GZ_SC_STORAGE_FAILED and out of memory GZ_SC_NOMEM, never "possibly old":
 * 8.2 step 3 answers a storage failure with a retry, not with an offer to
 * start as a restore (review A, M1). *start is set only on GZ_SC_OK.
 * GZ_SC_START_RESTORE (review B, M2): the mark file's newest entry is the
 * restore marker (6.3 steps 0 and 4). The node starts as a restore: its
 * first batch is key_epoch, restored and guard (journal.md 8.2), the guard
 * record's counter above the guard file's if one opens (read it with
 * gz_sc_fs_read and gz_sc_guard_open) and its epochs kept; that batch is
 * anchored (gz_sc_anchor), which ends the marker, and then the guard file is
 * replaced (gz_sc_guard_write), in 7 step 2's order. Until the anchor, every
 * start gives GZ_SC_START_RESTORE again, never "behind" or "possibly old". */
gz_sc_err_t gz_sc_check_start(const gz_sc_store_t *s, const gz_sc_unlocked_t *u, const gz_sc_journal_view_t *j,
                              gz_sc_start_t *start);

/* 7 step 2 / journal.md 4 step 4: append and sync the mark file's entry for
 * an anchored batch (its incarnation and covering sync mark's offset). */
gz_sc_err_t gz_sc_anchor(const gz_sc_store_t *s, const gz_sc_unlocked_t *u, uint64_t incarnation,
                         uint64_t mark_offset);
/* 10.1: replace the guard file (a batch with a guard record). */
gz_sc_err_t gz_sc_guard_write(const gz_sc_store_t *s, const gz_sc_vault_t *v, const gz_sc_guard_t *g);
/* 6.3 step 4, start as a restore: the mark file is started again with the
 * restore marker, so the start rule then gives GZ_SC_START_RESTORE until the
 * restore's first batch is anchored (review B, M2). */
gz_sc_err_t gz_sc_mark_restart(const gz_sc_store_t *s, const gz_sc_unlocked_t *u);

/* 4.7: a new key file under new_pw (NULL: the same passphrase, for the
 * parameter upgrade), parameters max(stored, def), a new salt. The upgrade
 * derives the old PK again (with the unlock's, a third Argon2id where 4.7
 * counts two); it runs once per upgrade, so the cost is accepted.
 * GZ_SC_DONE_WITH_FAULT (review B, L1): the new key file was renamed into
 * place and is the one in force, but the folder sync failed. Answer it as a
 * change that was made ("changed; if the new passphrase is ever refused after
 * a power cut, the old one opens"), never as a failure. Any other error: the
 * old key file is untouched. */
gz_sc_err_t gz_sc_rewrap(const gz_sc_store_t *s, const uint8_t *old_pw, size_t old_len, const uint8_t *new_pw,
                         size_t new_len, const gz_sc_kdf_params_t *def);
/* 9.2: the words' entropy (guarded memory, 32 bytes). */
gz_sc_err_t gz_sc_words(const gz_sc_store_t *s, const uint8_t *pw_nfc, size_t pw_len, uint8_t entropy[32]);
/* 9.3, same device: the seed opens the journal's recovery wrap; a new key
 * file with the same MSK and vault_id under a new passphrase.
 * DONE_WITH_FAULT as for gz_sc_rewrap: the new key file is in place. */
gz_sc_err_t gz_sc_recover_keyfile(const gz_sc_store_t *s, const uint8_t entropy[32], const uint8_t seed[64],
                                  const uint8_t *pw_nfc, size_t pw_len, const gz_sc_kdf_params_t *params);

/* 12.3: attempts.gza (mode 1). load gives the strictest state for a missing
 * or damaged file and returns its decode result. */
int gz_sc_attempts_load(const gz_sc_store_t *s, uint64_t now_s, gz_sc_attempts_t *a);
gz_sc_err_t gz_sc_attempts_store(const gz_sc_store_t *s, const gz_sc_attempts_t *a);

#endif
