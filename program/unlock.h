/* SPDX-License-Identifier: MIT */
/* The program's passphrase layer (P5): what the local API server needs of
 * the wallet's encrypted storage (spec/local-api.md 4.2 to 4.3, 12;
 * spec/storage-encryption.md 8.2), and nothing more.
 *
 * Two sides implement and use it:
 *   - the storage side (branch s5-s6-program) implements gzp_unlock_t over
 *     the key file and the encrypted journal;
 *   - the API backend (program/api_backend.c, P5) calls it for sign-in,
 *     create, restore and lock.
 * Until the storage side lands, program/unlock_standin.c implements it as a
 * TEST-ONLY stand-in, compiled into gazpacho-test only, never into the
 * release program.
 *
 * Threads (contract-v2.md 4). Deriving a key from a passphrase takes about a
 * second, so every call that takes a passphrase is split in two:
 *   begin   on the API server's derivation thread: derives, reads the key
 *           file, writes NOTHING and touches nothing the loop thread uses;
 *           the result and any keys go into the job;
 *   finish  on the loop thread, after begin: installs what begin produced
 *           (writes the key file, the guard and the first journal for
 *           create and restore; opens storage for unlock), then the program
 *           starts the node (program.md 2, "Start order once storage is
 *           encrypted").
 *   discard on the loop thread, instead of finish, when the job is no longer
 *           wanted (a lock or a stop came meanwhile): wipes the job's keys,
 *           installs nothing.
 * state, lock and attempts are loop-thread calls.
 *
 * Secrets. The passphrase and the words are owned by the caller, which wipes
 * them after finish or discard. An implementation copies neither anywhere but
 * its own derivation, never logs them, never puts them on a command line or in
 * an output line, and wipes every buffer that held them or a key derived from
 * them (with a wipe the compiler cannot remove).
 *
 * Attempts (local-api.md 4.3). The count of wrong passphrases in a row and the
 * time until which attempts are refused belong to the implementation (storage
 * keeps them in attempts.gza, 12.3; a missing or damaged file is the strictest
 * state). A wrong passphrase is counted in finish, never in begin, so a
 * discarded job counts as the spec says (the API server's generation rule). */
#ifndef GZP_UNLOCK_H
#define GZP_UNLOCK_H

#include <stddef.h>
#include <stdint.h>

/* What exists, as the API's wallet field needs it (local-api.md 4.5). */
typedef enum {
    GZP_WALLET_NONE = 0,      /* no key file: first run */
    GZP_WALLET_LOCKED,        /* a wallet exists; its storage key is not in memory */
    GZP_WALLET_UNLOCKED       /* the storage key is in memory; the node may run */
} gzp_wallet_state_t;

typedef enum {
    GZP_UNLOCK_OK = 0,
    GZP_UNLOCK_WRONG,         /* wrong passphrase: counted; see attempts_left, retry_after_s */
    GZP_UNLOCK_BUSY,          /* refused before any derivation: the delay has not passed,
                                 or another derivation runs (retry_after_s says when) */
    GZP_UNLOCK_NOT_CHECKED,   /* the derivation failed (out of memory, ...): NOT counted */
    GZP_UNLOCK_NO_WALLET,     /* unlock with no key file */
    GZP_UNLOCK_EXISTS,        /* create or restore over a wallet */
    GZP_UNLOCK_WEAK,          /* create or restore: storage 4.1's rules; reason, length, minimum */
    GZP_UNLOCK_BAD_WORDS,     /* restore: reason "position" (position set) or "checksum" */
    GZP_UNLOCK_FILES_BEHIND,  /* unlock: the files are older than the last saved state (4.7) */
    GZP_UNLOCK_STORAGE_FAILED,/* the key file or the journal cannot be read or written */
    GZP_UNLOCK_WORDS_DIFFER   /* words check: the passphrase was right, the words were not */
} gzp_unlock_status_t;

typedef struct {
    int status;               /* gzp_unlock_status_t */
    uint32_t wrong_in_row;    /* WRONG and BUSY: wrong passphrases in a row so far */
    uint32_t attempts_left;   /* WRONG: attempts before the delay starts doubling (0: it has) */
    uint32_t retry_after_s;   /* WRONG and BUSY: seconds until the next attempt is taken */
    const char *reason;       /* static text, [a-z_], or NULL: WEAK, BAD_WORDS, FILES_BEHIND, STORAGE_FAILED */
    uint32_t length, minimum; /* WEAK too_short: code points given, and required (15) */
    uint32_t position;        /* BAD_WORDS position: 1-based */
} gzp_unlock_result_t;

#define GZP_UNLOCK_WORDS 24
#define GZP_UNLOCK_WORD_MAX 16  /* the longest BIP 39 English word is 8 letters */

/* One derivation in flight. Allocated by the caller, zeroed before begin. */
typedef struct {
    int op;                                   /* GZP_UNLOCK_OP_* */
    const uint8_t *passphrase;                /* UTF-8, NFC, not NUL-terminated; caller's */
    size_t passphrase_len;
    char words[GZP_UNLOCK_WORDS][GZP_UNLOCK_WORD_MAX]; /* restore, words check: in; create, reveal: out */
    int positions[3];                         /* words check: 1-based positions of words[0..2] */
    gzp_unlock_result_t result;               /* set by begin, final after finish */
    void *keys;                               /* the implementation's derived keys, from begin
                                                 to finish or discard; wiped by them */
} gzp_unlock_job_t;

enum {
    GZP_UNLOCK_OP_UNLOCK = 1, /* open the existing wallet */
    GZP_UNLOCK_OP_CHECK,      /* while unlocked: is this the passphrase? (sign-in, fresh sign-in) */
    GZP_UNLOCK_OP_CREATE,     /* set up a new wallet; the 24 new words come out in words */
    GZP_UNLOCK_OP_RESTORE,    /* set up from the 24 words in words */
    GZP_UNLOCK_OP_REVEAL,     /* the 24 words out, for one showing (local-api.md 12.3; storage 9.2) */
    GZP_UNLOCK_OP_WORDS_CHECK /* compare words[0..2] with the words at positions: OK, or WORDS_DIFFER */
};

typedef struct {
    /* Loop thread. */
    gzp_wallet_state_t (*state)(void *ctx);
    /* Loop thread, before begin: may a derivation start now? GZP_UNLOCK_OK, or
     * BUSY with retry_after_s (the attempts delay; nothing is counted). */
    void (*attempts)(void *ctx, int64_t now_ms, gzp_unlock_result_t *out);
    /* Derivation thread. */
    void (*begin)(void *ctx, gzp_unlock_job_t *job);
    /* Loop thread, after begin: install, count, and set job->result for good. */
    void (*finish)(void *ctx, gzp_unlock_job_t *job, int64_t now_ms);
    /* Loop thread, instead of finish: wipe job->keys, install nothing. A WRONG
     * result is still counted. */
    void (*discard)(void *ctx, gzp_unlock_job_t *job, int64_t now_ms);
    /* Loop thread: drop the storage key from memory (local-api.md 4.7). The
     * program stops the node first; after lock, state is LOCKED. */
    void (*lock)(void *ctx);
    /* Loop thread, and only while the state is UNLOCKED: the wallet's 64-byte
     * BIP 39 seed (its 24 words, no BIP 39 passphrase), for the key port (P8).
     *   0   out64 holds the seed;
     *   -1  the wallet is not unlocked: out64 is not touched;
     *   -2  storage could not give it: out64 is wiped.
     * The caller wipes out64 as soon as it is done with it. The call never
     * logs anything: no seed, no word, no length, no file name. */
    int (*seed)(void *ctx, uint8_t out64[64]);
    void *ctx;
} gzp_unlock_t;

#endif
