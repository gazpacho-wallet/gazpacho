/* Storage encryption, Slice 1 subset (spec/storage-encryption.md draft 3).
 *
 * The key file keys.gzk, the passphrase key (Argon2id in a helper process),
 * the sealed journal header and entries (the journal calls gz_sc_header_* and
 * gz_sc_frame_*), the mark file mark.gzm, the guard file guard.gzg, the
 * attempts file attempts.gza in mode 1, passphrase change, the export .gzb
 * (profiles 1 and 2), the start rule (6.3, with step 0) and the socket token
 * folder (12.2). No watcher, no KB, no OS key store (Slice 1, 8.7.3).
 *
 * Outside the I/O-free core: this library may call the operating system and
 * libsodium; gazpacho_core may not (spec 13).
 *
 * Every secret the storage layer holds (passphrase, PK, MSK, subkeys, the
 * seed copy, the words' entropy) lives in sodium_malloc memory and is wiped
 * when freed (spec 8.3). Buffers the caller passes in for such secrets should
 * be from gz_sc_salloc. All integers in files are big-endian. */
#ifndef GAZPACHO_STORAGE_CRYPTO_H
#define GAZPACHO_STORAGE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    GZ_SC_OK = 0,
    GZ_SC_NOT_THIS_FORMAT,   /* wrong length, magic or format: not this kind of file */
    GZ_SC_OTHER_NETWORK,     /* chain differs; found before anything is derived */
    GZ_SC_PARAMS_REFUSED,    /* Argon2id parameters outside 4.2's floor or fixed ceiling */
    GZ_SC_NEEDS_MORE_MEMORY, /* above this device's ceiling: "open it on a larger one" */
    GZ_SC_WRONG_PASSPHRASE,  /* key file: "wrong passphrase or damaged key file" */
    GZ_SC_DAMAGED,           /* an authenticated part failed (seed, chunk, guard, ...) */
    GZ_SC_NOT_THIS_WALLET,   /* journal header: "this journal is not this wallet's" */
    GZ_SC_INVALID,           /* an entry is invalid at this offset (5.5) */
    GZ_SC_TRUNCATED,         /* export: a chunk is missing at the end */
    GZ_SC_TRAILING_DATA,     /* export: data after the final chunk */
    GZ_SC_EMPTY_CHUNK,       /* export: an empty chunk that is not the final one */
    GZ_SC_NEEDS_WORDS,       /* export profile 2 offered a passphrase */
    GZ_SC_HELPER_FAILED,     /* "the passphrase could not be checked": never a wrong passphrase */
    GZ_SC_RANDOM_FAILED,     /* the storage random source failed: a storage failure (7.5) */
    GZ_SC_STORAGE_FAILED,    /* an operating-system call failed */
    GZ_SC_MISSING,           /* the file does not exist */
    GZ_SC_EXISTS,            /* refused: a wallet (key file) already exists */
    GZ_SC_UNSAFE_PATH,       /* token folder: other owner, other permissions or a link */
    GZ_SC_BUFFER,            /* output buffer too small */
    GZ_SC_ARG,               /* a bad argument from the caller */
    GZ_SC_NOMEM,             /* sodium_malloc or malloc failed */
    GZ_SC_LIBRARY,           /* libsodium is not the pinned version or did not start */
    GZ_SC_PASS_REFUSED       /* the passphrase is not valid NFC UTF-8, or (set-up, change,
                              * recovery) breaks 4.1's length rules: gz_sc_pass_check_form
                              * says which */
} gz_sc_err_t;

const char *gz_sc_err_text(gz_sc_err_t e);

/* Sizes (spec 4.5, 5.3, 5.4, 10.2, 11, 12.3). */
#define GZ_SC_KEYFILE_LEN 363
#define GZ_SC_JHEADER_LEN 185
#define GZ_SC_FRAME_HEAD 21          /* length, kind, incarnation, sequence */
#define GZ_SC_FRAME_OVERHEAD 61      /* 21 + nonce 24 + tag 16 */
#define GZ_SC_FRAME_LEN_MIN 61       /* the length field: 57 + payload */
#define GZ_SC_FRAME_LEN_MAX 8388665u /* 8 MiB payload + 57 */
#define GZ_SC_MARK_HEADER_LEN 57
#define GZ_SC_MARK_ENTRY_LEN 56
#define GZ_SC_GUARD_HEAD 41
#define GZ_SC_ATTEMPTS_LEN 85
#define GZ_SC_EXPORT_HEAD 58
#define GZ_SC_EXPORT_SLOT_END 188
#define GZ_SC_EXPORT_PART_MAX 65536
#define GZ_SC_PASS_MAX_BYTES 1024    /* after NFC (4.1) */
#define GZ_SC_PASS_MIN_CP 15
#define GZ_SC_PASS_IN_MAX 4096       /* largest request body field read (8.4) */

/* Library start: sodium_init and the pinned version check. Call first. */
gz_sc_err_t gz_sc_init(void);

/* Guarded memory (sodium_malloc): wiped and unmapped by gz_sc_sfree. */
void *gz_sc_salloc(size_t n);
void gz_sc_sfree(void *p);

/* ---- the storage random source (5.2): returns an error, never aborts ---- */
gz_sc_err_t gz_sc_random(uint8_t *out, size_t n);

/* ---- Argon2id parameters (4.2) ------------------------------------------ */
typedef struct {
    uint8_t kdf;    /* 1 = Argon2id 0x13 */
    uint32_t t;     /* passes */
    uint32_t m_kib; /* memory in KiB */
    uint8_t p;      /* lanes: 1 */
} gz_sc_kdf_params_t;

/* Defaults: the key file (256 MiB, 3 passes), the profile 1 export (1 GiB, 4). */
extern const gz_sc_kdf_params_t GZ_SC_KDF_KEYFILE_DEFAULT;
extern const gz_sc_kdf_params_t GZ_SC_KDF_EXPORT_DEFAULT;

/* One rule for every slot, checked before any derivation: kdf 1, p 1,
 * 3 <= t <= 16, 65,536 <= m <= 4,194,304 KiB (else PARAMS_REFUSED); m x 1024
 * fits size_t and is at most crypto_pwhash_memlimit_max() and half of the
 * physical memory (else NEEDS_MORE_MEMORY). Computed in 64 bits. */
gz_sc_err_t gz_sc_params_check(const gz_sc_kdf_params_t *p);

/* Parameters for a new wrap (4.7): each field the larger of the stored and
 * the default, then clamped to this device's ceiling but never below the
 * stored ones. */
void gz_sc_params_for_new_wrap(const gz_sc_kdf_params_t *stored, const gz_sc_kdf_params_t *def,
                               gz_sc_kdf_params_t *out);

/* ---- the passphrase (4.1) ------------------------------------------------ */
/* NFC, then UTF-8 (utf8proc). in[0..len) is the bytes as received (at most
 * GZ_SC_PASS_IN_MAX). *out is gz_sc_salloc'd; the caller frees it with
 * gz_sc_sfree. Refuses invalid UTF-8 (GZ_SC_ARG). *code_points gets the count. */
gz_sc_err_t gz_sc_pass_nfc(const uint8_t *in, size_t len, uint8_t **out, size_t *out_len,
                           size_t *code_points);

typedef enum {
    GZ_SC_PASS_OK = 0,
    GZ_SC_PASS_TOO_SHORT, /* fewer than 15 code points after NFC */
    GZ_SC_PASS_TOO_LONG,  /* more than 1,024 bytes after NFC */
    GZ_SC_PASS_COMMON,    /* on the bundled blocklist (case-insensitive, whole) */
    GZ_SC_PASS_NAME,      /* "gazpacho" or the wallet's name, with or without digits */
    GZ_SC_PASS_WORDS,     /* three or more of the wallet's own 24 words in order */
    GZ_SC_PASS_NOT_UTF8,
    GZ_SC_PASS_NOT_NFC    /* not byte for byte its own NFC form: normalise first */
} gz_sc_pass_rule_t;

/* 4.1's rules on an NFC passphrase (from gz_sc_pass_nfc). wallet_name may be
 * NULL; words may be NULL (no words yet) or 24 lowercase ASCII words. The
 * blocklist is the bundled one (sc_blocklist.c, spec open point 3). */
gz_sc_pass_rule_t gz_sc_pass_check(const uint8_t *nfc, size_t len, const char *wallet_name,
                                   const char *const *words, size_t n_words);

/* The part of 4.1 the storage layer enforces itself whatever its caller did
 * (review A, M3): valid UTF-8, already NFC, at most 1,024 bytes, at least 15
 * code points. gz_sc_setup, gz_sc_rewrap (the new passphrase) and
 * gz_sc_recover_keyfile refuse anything else with GZ_SC_PASS_REFUSED; this
 * gives the reason. The name, words and blocklist rules need the wallet's
 * name and words, so they stay with the caller (gz_sc_pass_check). */
gz_sc_pass_rule_t gz_sc_pass_check_form(const uint8_t *pw, size_t len);

/* Six words from the EFF large word list (7,776 words, 77.5 bits), drawn from
 * the storage random source, joined by single spaces. *out is gz_sc_salloc'd
 * and NUL-terminated. */
gz_sc_err_t gz_sc_pass_generate(char **out, size_t *out_len);

/* ---- the passphrase key: Argon2id in a helper process (8.3, 8.4) -------- */
/* A KDF: derive PK (32 bytes, into pk, which should be guarded memory) from
 * the NFC passphrase. *mem_locked gets 1 when the helper's pages were locked.
 * The release build has only gz_sc_kdf_helper. */
typedef gz_sc_err_t (*gz_sc_kdf_fn)(void *ctx, const uint8_t *pw, size_t pw_len, const uint8_t salt[16],
                                    const gz_sc_kdf_params_t *params, uint8_t pk[32], int *mem_locked);

/* Starts ctx (a const char * path to the program) as `path --gz-kdf-helper`
 * with a socket on its standard input, sends the request, reads PK and waits
 * for it. A crash, an out-of-memory or a short answer is GZ_SC_HELPER_FAILED.
 * So is a helper that has not answered and exited by a deadline (30 s plus
 * 1 ms per 64 KiB pass, review A, L3): it is killed and reaped. Parameters
 * are checked (again) before the helper is started. A program that sets
 * SIGCHLD to SIG_IGN cannot reap it: every derivation then fails safe, as
 * "could not be checked". */
gz_sc_err_t gz_sc_kdf_helper(void *ctx, const uint8_t *pw, size_t pw_len, const uint8_t salt[16],
                             const gz_sc_kdf_params_t *params, uint8_t pk[32], int *mem_locked);

/* The helper's hidden mode: the program calls this when started with
 * --gz-kdf-helper, with fd its standard input (a socket). Returns the exit
 * status. Turns core dumps and (Linux) dumpability off, locks its pages where
 * allowed, derives, writes status and PK, wipes, returns. */
int gz_sc_helper_main(int fd);

/* ---- the unlocked wallet ------------------------------------------------- */
/* The storage layer's state while unlocked: chain, vault_id, MSK and its copy
 * of the 64-byte BIP 39 seed (guarded, no access between uses). */
typedef struct gz_sc_vault gz_sc_vault_t;

/* From parts already held (set-up, restore). msk and seed are copied. */
gz_sc_err_t gz_sc_vault_new(const uint8_t chain[32], const uint8_t vault_id[16], const uint8_t msk[32],
                            const uint8_t seed[64], gz_sc_vault_t **out);
void gz_sc_vault_free(gz_sc_vault_t *v);
void gz_sc_vault_ids(const gz_sc_vault_t *v, uint8_t chain[32], uint8_t vault_id[16]);
/* 1 if msk equals the vault's MSK (constant time). 4.6's "check" on the
 * public API is gz_sc_check (gz_storage_files.h) or gz_sc_keyfile_check. */
int gz_sc_vault_same_msk(const gz_sc_vault_t *v, const uint8_t msk[32]);
/* Copies the seed out (into guarded memory the caller owns), for the node. */
gz_sc_err_t gz_sc_vault_seed(const gz_sc_vault_t *v, uint8_t seed[64]);

/* ---- the key file keys.gzk (4.5) ----------------------------------------- */
typedef struct {
    uint8_t chain[32];
    uint8_t vault_id[16];
    gz_sc_kdf_params_t kdf;
    uint8_t salt[16];
} gz_sc_keyfile_info_t;

/* Opening steps 1 and 2: length, magic, format, chain, then the parameter
 * rule. Nothing is derived. */
gz_sc_err_t gz_sc_keyfile_parse(const uint8_t *data, size_t len, const uint8_t chain[32],
                                gz_sc_keyfile_info_t *info);
/* Opening steps 4 to 6 with PK from the KDF: the commitment (constant time),
 * the wrap, the seed. WRONG_PASSPHRASE at 4 or 5, DAMAGED at 6. */
gz_sc_err_t gz_sc_keyfile_unlock(const uint8_t data[GZ_SC_KEYFILE_LEN], const uint8_t pk[32],
                                 gz_sc_vault_t **out);
/* 4.6 "check" (8.2) with PK from the KDF: the commitment and the wrap open
 * MSK into guarded memory, which is compared with the vault's in constant
 * time and wiped. GZ_SC_OK: the same wallet's passphrase; WRONG_PASSPHRASE;
 * NOT_THIS_WALLET: the wrap opens but names another MSK or vault. */
gz_sc_err_t gz_sc_keyfile_check(const uint8_t data[GZ_SC_KEYFILE_LEN], const uint8_t pk[32],
                                const gz_sc_vault_t *v);
/* 9.2: the words' entropy under KD, into entropy (guarded memory). */
gz_sc_err_t gz_sc_keyfile_words(const uint8_t data[GZ_SC_KEYFILE_LEN], const uint8_t pk[32],
                                uint8_t entropy[32]);
/* A new key file. params must pass gz_sc_params_check. Draws the nonce
 * inputs from the storage random source. */
gz_sc_err_t gz_sc_keyfile_build(const uint8_t chain[32], const uint8_t vault_id[16],
                                const gz_sc_kdf_params_t *params, const uint8_t salt[16],
                                const uint8_t pk[32], const uint8_t msk[32], const uint8_t entropy[32],
                                const uint8_t seed[64], uint8_t out[GZ_SC_KEYFILE_LEN]);
/* 4.7: passphrase change or parameter upgrade. old_pk must open old; the
 * words and the wrap are re-sealed under new_pk; bytes 259 to 362 are copied. */
gz_sc_err_t gz_sc_keyfile_rewrap(const uint8_t old[GZ_SC_KEYFILE_LEN], const uint8_t old_pk[32],
                                 const gz_sc_kdf_params_t *new_params, const uint8_t new_salt[16],
                                 const uint8_t new_pk[32], uint8_t out[GZ_SC_KEYFILE_LEN]);

/* ---- framed files: the journal and its siblings (5.3, 5.4) --------------- */
/* A sealing key and its nonce key with the file id they are bound to. */
typedef struct gz_sc_framekey gz_sc_framekey_t;
void gz_sc_framekey_free(gz_sc_framekey_t *k);
/* For tests and the later penalty file and log: keys(ikm, label, chain || id). */
gz_sc_err_t gz_sc_framekey_derive(const uint8_t *ikm, size_t ikm_len, const char *label,
                                  const uint8_t chain[32], const uint8_t file_id[16],
                                  gz_sc_framekey_t **out);

/* The journal header, 185 bytes (5.3). */
gz_sc_err_t gz_sc_header_seal(const gz_sc_vault_t *v, const uint8_t file_id[16],
                              uint8_t out[GZ_SC_JHEADER_LEN]);
/* Before unlock: magic, format, chain. Gives the clear vault_id and file_id. */
gz_sc_err_t gz_sc_header_clear(const uint8_t *hdr, size_t len, const uint8_t chain[32],
                               uint8_t vault_id[16], uint8_t file_id[16]);
/* After unlock: the header tag under KJ (and the vault_id); gives KJ. */
gz_sc_err_t gz_sc_header_open(const uint8_t hdr[GZ_SC_JHEADER_LEN], const gz_sc_vault_t *v,
                              gz_sc_framekey_t **kj);
/* 9.3, the words alone: MSK from the recovery wrap under KR (seed), checked
 * against the header tag. msk should be guarded memory. */
gz_sc_err_t gz_sc_header_recover(const uint8_t hdr[GZ_SC_JHEADER_LEN], const uint8_t chain[32],
                                 const uint8_t seed[64], uint8_t msk[32]);

typedef struct {
    uint8_t kind; /* 1 incarnation, 2 batch, 3 sync mark */
    uint64_t incarnation;
    uint64_t sequence;
    size_t entry_len;   /* bytes the entry takes in the file: 4 + length */
    size_t payload_len; /* length - 57 */
} gz_sc_frame_t;

/* Seals one entry to be written at `offset`. Kinds 1 and 3 carry exactly 8
 * payload bytes (a sync mark's must be its own offset); kind 2 at least 4.
 * *out_len = 61 + payload_len. */
gz_sc_err_t gz_sc_frame_seal(const gz_sc_framekey_t *k, uint64_t offset, uint8_t kind, uint64_t incarnation,
                             uint64_t sequence, const uint8_t *payload, size_t payload_len, uint8_t *out,
                             size_t out_cap, size_t *out_len);
/* The entry at `offset` (data points at it, avail bytes remain in the file):
 * GZ_SC_OK and its payload, or GZ_SC_INVALID for every reason of 5.5 (length
 * rules, unknown kind, short file, tag, a sync mark not naming its own offset).
 * payload may be NULL to validate only. */
gz_sc_err_t gz_sc_frame_open(const gz_sc_framekey_t *k, const uint8_t *data, size_t avail, uint64_t offset,
                             gz_sc_frame_t *f, uint8_t *payload, size_t payload_cap);

/* ---- the mark file mark.gzm (10.2) --------------------------------------- */
/* KH for the journal file_id. */
gz_sc_err_t gz_sc_mark_key(const gz_sc_vault_t *v, const uint8_t file_id[16], gz_sc_framekey_t **kh);
/* Header and the set-up entry (0, 0): 113 bytes. */
gz_sc_err_t gz_sc_mark_new(const gz_sc_framekey_t *kh, const uint8_t chain[32],
                           uint8_t out[GZ_SC_MARK_HEADER_LEN + GZ_SC_MARK_ENTRY_LEN]);
/* One entry to append at file offset `at`. header is the file's first 57 bytes. */
gz_sc_err_t gz_sc_mark_entry(const gz_sc_framekey_t *kh, const uint8_t header[GZ_SC_MARK_HEADER_LEN],
                             uint64_t at, uint64_t incarnation, uint64_t mark_offset,
                             uint8_t out[GZ_SC_MARK_ENTRY_LEN]);

typedef enum {
    GZ_SC_MARK_OK = 0,
    GZ_SC_MARK_NOT_A_MARK_FILE, /* short, other magic, format or chain: possibly old */
    GZ_SC_MARK_NO_ENTRY,        /* no valid entry: possibly old */
    GZ_SC_MARK_DAMAGED,         /* an invalid entry before a valid one, a second invalid
                                 * full entry after the newest valid one, or going backwards */
    GZ_SC_MARK_OTHER_JOURNAL    /* names another journal file_id: behind */
} gz_sc_mark_state_t;

/* The newest valid entry. *valid_end: where the next entry is appended. The
 * torn tail cut there first is one invalid full entry or a piece shorter than
 * 56 bytes after the newest valid entry (10.2): one append tears one entry. */
gz_sc_mark_state_t gz_sc_mark_read(const gz_sc_framekey_t *kh, const uint8_t *data, size_t len,
                                   const uint8_t chain[32], const uint8_t file_id[16], uint64_t *incarnation,
                                   uint64_t *mark_offset, size_t *valid_end);

/* ---- the guard file guard.gzg (10.1) ------------------------------------- */
typedef struct {
    uint32_t epoch;
    uint32_t highest_index;
} gz_sc_epoch_t;

typedef struct {
    uint64_t counter;
    uint16_t n_epochs;
    gz_sc_epoch_t *epochs; /* n_epochs entries; gz_sc_guard_open mallocs it */
    uint64_t rounds_started;
} gz_sc_guard_t;

void gz_sc_guard_clear(gz_sc_guard_t *g); /* frees epochs */
size_t gz_sc_guard_contents_len(const gz_sc_guard_t *g); /* 18 + 8 n */
gz_sc_err_t gz_sc_guard_contents(const gz_sc_guard_t *g, uint8_t *out, size_t cap, size_t *out_len);
gz_sc_err_t gz_sc_guard_parse(const uint8_t *c, size_t len, gz_sc_guard_t *g);
/* Sealed under KG, a key from the seed (readable across a restore). */
gz_sc_err_t gz_sc_guard_seal(const gz_sc_vault_t *v, const gz_sc_guard_t *g, uint8_t *out, size_t cap,
                             size_t *out_len);
gz_sc_err_t gz_sc_guard_open(const gz_sc_vault_t *v, const uint8_t *data, size_t len, gz_sc_guard_t *g);

/* ---- the start rule (6.3 steps 1, 2 and 4) ------------------------------- */
/* What the journal tells the rule after its scan and any torn-tail cut. */
typedef struct {
    uint64_t highest_incarnation;
    /* 1 if a valid sync mark of `incarnation` starts at `offset`. */
    int (*has_sync_mark)(void *ctx, uint64_t incarnation, uint64_t offset);
    void *ctx;
    uint64_t newest_guard_counter; /* 0 if the journal holds no guard record */
} gz_sc_journal_view_t;

typedef enum {
    GZ_SC_START_OK = 0,
    GZ_SC_START_POSSIBLY_OLD, /* step 1: a guard or mark file missing or damaged */
    GZ_SC_START_BEHIND        /* step 2: the journal is behind its mark file or guard */
} gz_sc_start_t;

/* guard_state: GZ_SC_OK with guard_counter, or GZ_SC_MISSING / GZ_SC_DAMAGED. */
gz_sc_start_t gz_sc_start_rule(gz_sc_mark_state_t mark, uint64_t mark_inc, uint64_t mark_off,
                               gz_sc_err_t guard_state, uint64_t guard_counter,
                               const gz_sc_journal_view_t *j);

/* ---- the export .gzb (11) ------------------------------------------------ */
typedef struct {
    uint8_t profile; /* 1 the person's, 2 the host's copy */
    uint8_t chain[32];
    uint8_t export_id[16];
    gz_sc_kdf_params_t kdf; /* profile 1 */
    uint8_t salt[16];       /* profile 1 */
} gz_sc_export_info_t;

/* The plaintext body (11): version 1, created_ms, flags (bit 0: the words'
 * entropy follows; profile 1 only), the guard contents, then entries.
 *
 * The words never pass through the caller's buffer (8.3; review A, M2): the
 * caller builds the body without the 32 bytes of entropy (flag bit 0 set by
 * with_words) and hands the entropy, in guarded memory, to
 * gz_sc_export_build, which puts each chunk that carries it together in
 * guarded memory. The sealed body is then GZ_SC_EXPORT_WORDS_LEN longer than
 * the caller's. */
#define GZ_SC_EXPORT_WORDS_LEN 32
/* The caller's body, without the words. */
size_t gz_sc_export_body_len(size_t guard_len, size_t entries_len);
gz_sc_err_t gz_sc_export_body_begin(uint64_t created_ms, int with_words, const uint8_t *guard, size_t guard_len,
                                    uint8_t *out, size_t cap, size_t *used);
/* Appends one entry as kind, incarnation, sequence, u32 len, payload. */
gz_sc_err_t gz_sc_export_body_entry(uint8_t kind, uint64_t inc, uint64_t seq, const uint8_t *payload,
                                    size_t len, uint8_t *out, size_t cap, size_t *used);

typedef struct {
    uint64_t created_ms;
    uint8_t flags;
    const uint8_t *entropy; /* into the body, or NULL */
    const uint8_t *guard;
    size_t guard_len;
    const uint8_t *entries; /* the rest */
    size_t entries_len;
} gz_sc_export_body_t;

/* Strict parse of an opened body (the words, if any, in place): every entry
 * must fit exactly. */
gz_sc_err_t gz_sc_export_body_parse(const uint8_t *b, size_t len, uint8_t profile, gz_sc_export_body_t *out);
/* Walks the entries: returns 1 and advances *pos, 0 at the end, -1 if malformed. */
int gz_sc_export_body_next(const gz_sc_export_body_t *b, size_t *pos, uint8_t *kind, uint64_t *inc,
                           uint64_t *seq, const uint8_t **payload, size_t *len);

/* The file's size for a sealed body of sealed_len bytes (the caller's body
 * length, plus GZ_SC_EXPORT_WORDS_LEN when the words are carried). */
size_t gz_sc_export_size(uint8_t profile, size_t sealed_len, size_t part);
/* Profile 1: kdf, salt and pkx (PKx from the KDF over that slot) are used;
 * profile 2: they must be NULL. body: the caller's body (without the words);
 * entropy: the words' 32 bytes (guarded memory) exactly when the body's flag
 * bit 0 is set, else NULL. part: chunk size, 1 to 65,536. */
gz_sc_err_t gz_sc_export_build(const gz_sc_vault_t *v, uint8_t profile, const uint8_t export_id[16],
                               const gz_sc_kdf_params_t *kdf, const uint8_t *salt, const uint8_t *pkx,
                               const uint8_t *body, size_t body_len, const uint8_t *entropy, size_t part,
                               uint8_t *out, size_t cap, size_t *out_len);
/* Magic, format, chain, profile, and for profile 1 the slot's parameters
 * against the rule, before any derivation. */
gz_sc_err_t gz_sc_export_parse(const uint8_t *data, size_t len, const uint8_t chain[32],
                               gz_sc_export_info_t *info);
/* Opens with the passphrase key pkx (profile 1 only: NEEDS_WORDS for 2) or
 * with the seed (either profile). *body is in guarded memory (it may hold
 * the words' entropy): the caller frees it with gz_sc_sfree, which wipes it.
 * A chunk length below 40 or above 65,576 is DAMAGED; a chunk running past
 * the end of the file TRUNCATED. */
gz_sc_err_t gz_sc_export_open(const uint8_t *data, size_t len, const uint8_t chain[32], const uint8_t *pkx,
                              const uint8_t *seed, uint8_t **body, size_t *body_len);

/* ---- the attempts file attempts.gza, mode 1 (12.3) ----------------------- */
typedef struct {
    uint64_t counter;
    uint32_t wrong_in_a_row;
    uint64_t last_wrong_s;
    uint64_t blocked_until_s;
} gz_sc_attempts_t;

void gz_sc_attempts_encode(const uint8_t chain[32], const gz_sc_attempts_t *a, uint8_t out[GZ_SC_ATTEMPTS_LEN]);
/* 1 if a valid mode 1 file of this chain; otherwise *a is the strictest state
 * (blocked until now + 900 s, the counter kept from a damaged file of the
 * right length) and 0 is returned. data NULL: a missing file. A valid file
 * cannot block for longer than the strictest state, nor date a wrong attempt
 * after now (review A, L1). The counter saturates at 2^64 - 1. */
int gz_sc_attempts_decode(const uint8_t chain[32], const uint8_t *data, size_t len, uint64_t now_s,
                          gz_sc_attempts_t *a);
/* local-api.md 4.3 (D15): one attempt a second; after 5 wrong in a row the
 * delay doubles with each further wrong one, up to 15 minutes. */
uint64_t gz_sc_attempts_wait(const gz_sc_attempts_t *a, uint64_t now_s); /* 0: may try now */
void gz_sc_attempts_wrong(gz_sc_attempts_t *a, uint64_t now_s);
void gz_sc_attempts_right(gz_sc_attempts_t *a, uint64_t now_s);

/* ---- the socket token folder (12.2) -------------------------------------- */
/* gazpacho-<first 16 hex digits of SHA-256(data_dir)> under $XDG_RUNTIME_DIR,
 * or /tmp/gazpacho-<uid>-<hash> where that is unset (Linux); the per-user
 * temporary folder on macOS. data_dir must be absolute. */
gz_sc_err_t gz_sc_token_dir(const char *data_dir, char *out, size_t cap);
/* Creates it 0700, or accepts an existing one only if it is a directory (not
 * a link), owned by this user, with mode 0700. */
gz_sc_err_t gz_sc_token_dir_make(const char *path);

#endif
