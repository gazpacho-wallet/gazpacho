/* The storage journal: how a node's saved batches survive a crash.
 *
 * Specification: spec/journal.md (draft 2). This is the outer layer
 * (DESIGN.md section 3, L4): it uses the operating system, the core does not.
 * Every operating-system call goes through a gz_journal_os_t table, so tests
 * can fail or "crash" at any write or sync; NULL selects the POSIX one.
 *
 * ONE FILE PER NODE, ONE WRITER. `journal.gzj` in the node's data folder,
 * locked exclusively while open (flock). Bytes are only ever appended; the
 * one exception is cutting a torn tail at open, which removes only bytes
 * after the last sync mark (spec section 5).
 *
 * HOW THE PROGRAM USES IT
 *
 *   gz_journal_open        lock, check the header, scan, cut a torn tail or
 *                          refuse corruption, write and sync a new
 *                          incarnation entry and its sync mark. Pass the
 *                          returned incarnation to gz_runner_init.
 *   gz_journal_attach      give it the runner and the function that hands a
 *                          GZ_EVENT_STORAGE_CONFIRMED event to the node.
 *   gz_journal_reader      the gz_storage_reader_t for gz_node_start.
 *   gz_journal_save        from the runner's executor, for each save action:
 *                          append the batch entry (not yet synced).
 *   gz_journal_flush       outside the executor: sync, append a sync mark,
 *                          sync again, replace the guard file if a batch held
 *                          a guard record, then confirm every batch the sync
 *                          covered, oldest first. Only a confirmation the
 *                          runner accepts reaches the node.
 *   gz_journal_close       release the lock and free. Writes nothing.
 *
 * A write, sync, limit or contract failure calls gz_runner_storage_failed (if
 * a runner is attached), and the journal then writes and confirms nothing
 * more. A failed sync is never retried (spec section 4). */
#ifndef GAZPACHO_JOURNAL_H
#define GAZPACHO_JOURNAL_H

#include <stddef.h>
#include <stdint.h>

#include "gazpacho/ports.h"
#include "gazpacho/runner.h"

#define GZ_JOURNAL_HEADER_LEN   48u
#define GZ_JOURNAL_ENTRY_MIN    21u          /* smallest `length` */
#define GZ_JOURNAL_ENTRY_MAX    8388625u     /* 8 MiB payload + 17 */
#define GZ_JOURNAL_MARK_LEN     37u          /* incarnation and mark entries, in the file */
#define GZ_JOURNAL_UNSYNCED_MAX (16ull << 20)
#define GZ_JOURNAL_SOFT_LIMIT   (768ull << 20)
#define GZ_JOURNAL_HARD_LIMIT   (1ull << 30)

#define GZ_JOURNAL_KIND_INCARNATION 1u
#define GZ_JOURNAL_KIND_BATCH       2u
#define GZ_JOURNAL_KIND_MARK        3u

#define GZ_JOURNAL_FILE       "journal.gzj"
#define GZ_JOURNAL_GUARD_FILE "guard.gzg"
#define GZ_RECORD_GUARD       0x0004000au   /* spec section 9 */
#define GZ_GUARD_MIN_LEN      58u           /* guard record with no epochs */

/* The chain hashes of spec section 2.1, internal byte order. */
extern const uint8_t gz_journal_chain_signet[32];
extern const uint8_t gz_journal_chain_mainnet[32];

typedef enum {
    GZ_JOURNAL_OK = 0,
    GZ_JOURNAL_ERR_ARGUMENT,       /* a required argument is missing */
    GZ_JOURNAL_ERR_IO,             /* an operating-system call failed */
    GZ_JOURNAL_ERR_LOCKED,         /* another process holds the journal */
    GZ_JOURNAL_ERR_HEADER,         /* wrong magic or check, or a file shorter than a header */
    GZ_JOURNAL_ERR_NETWORK,        /* the header names another network */
    GZ_JOURNAL_ERR_CORRUPT,        /* an invalid entry lies before a valid sync mark */
    GZ_JOURNAL_ERR_ORDER,          /* a valid entry breaks an order rule (spec 3.4) */
    GZ_JOURNAL_ERR_UNKNOWN_RECORD, /* a stored record has an unknown even type */
    GZ_JOURNAL_ERR_FULL,           /* the hard limit would be passed */
    GZ_JOURNAL_ERR_TOO_LARGE,      /* one batch is larger than an entry may be */
    GZ_JOURNAL_ERR_SEQUENCE,       /* a batch handed over with the wrong identifier */
    GZ_JOURNAL_ERR_GUARD,          /* a guard record that is not a guard (spec 8.3) */
    GZ_JOURNAL_ERR_NO_MEMORY,
    GZ_JOURNAL_ERR_FAILED          /* the journal has failed and does nothing more */
} gz_journal_status_t;

const char *gz_journal_status_name(gz_journal_status_t status);

/* --- Operating-system calls -------------------------------------------------
 * Each returns 0 (or a non-negative count or descriptor) on success and -1 on
 * failure, setting errno. */
#define GZ_JOURNAL_OPEN_READ        1  /* read only; errno ENOENT if missing */
#define GZ_JOURNAL_OPEN_RW          2  /* read and write an existing file */
#define GZ_JOURNAL_OPEN_CREATE_EXCL 3  /* new file, mode 0600; errno EEXIST if present */
#define GZ_JOURNAL_OPEN_CREATE_TRUNC 4 /* create or empty, mode 0600 */

typedef struct {
    int (*open)(void *ctx, const char *path, int how);
    int (*close)(void *ctx, int fd);
    long (*pread)(void *ctx, int fd, void *buf, size_t len, uint64_t off);
    long (*pwrite)(void *ctx, int fd, const void *buf, size_t len, uint64_t off);
    int (*sync)(void *ctx, int fd);                 /* fsync; F_FULLFSYNC on macOS */
    int (*sync_dir)(void *ctx, const char *dir);
    int (*truncate)(void *ctx, int fd, uint64_t len);
    int (*size)(void *ctx, int fd, uint64_t *out);
    int (*lock)(void *ctx, int fd);                 /* exclusive, non-blocking; errno EWOULDBLOCK if held */
    int (*link)(void *ctx, const char *from, const char *to);   /* never replaces; EEXIST */
    int (*rename)(void *ctx, const char *from, const char *to); /* replaces */
    int (*unlink)(void *ctx, const char *path);
    void *ctx;
} gz_journal_os_t;

const gz_journal_os_t *gz_journal_os_posix(void);

/* --- Scanning (read only, also used by tools/gz-journal) --------------------- */

typedef enum {
    GZ_JOURNAL_CLEAN = 0,     /* every byte is a valid entry */
    GZ_JOURNAL_TORN,          /* bytes after the last valid entry, no valid mark among them: cut */
    GZ_JOURNAL_REFUSED        /* see the status */
} gz_journal_verdict_t;

typedef struct {
    gz_journal_verdict_t verdict;
    gz_journal_status_t status;   /* GZ_JOURNAL_OK unless REFUSED */
    uint64_t file_end;            /* E */
    uint64_t valid_end;           /* V: just after the last valid entry the scan accepted */
    uint64_t error_at;            /* REFUSED: offset of the offending entry (CORRUPT, ORDER) */
    uint64_t mark_at;             /* CORRUPT: offset of the valid sync mark found after it */
    uint32_t bad_type;            /* UNKNOWN_RECORD: the type */
    uint64_t highest_incarnation; /* among kept entries; 0 if none */
    uint64_t n_incarnations, n_batches, n_marks, n_records;
} gz_journal_scan_t;

/* One kept batch entry, as the scan finds it. `payload` points into `data`. */
typedef void (*gz_journal_batch_fn)(void *ctx, uint64_t offset, uint32_t entry_len,
                                    gz_batch_id_t id, const uint8_t *payload, size_t payload_len);

/* Scan a whole journal held in memory (spec section 5, steps 2 to 4, and the
 * record-type rule of section 6). Calls `on_batch` (may be NULL) for each
 * valid batch entry before V, in file order; when the verdict is REFUSED the
 * calls made must be ignored. Returns `out->status`. */
gz_journal_status_t gz_journal_scan(const uint8_t *data, size_t len, const uint8_t chain[32],
                                    gz_journal_scan_t *out, gz_journal_batch_fn on_batch,
                                    void *ctx);

/* 1 if a record type is understood by this program, else 0 (spec 6, 9). */
int gz_journal_type_known(uint32_t type);

/* Parse a batch payload (spec 3.2). Returns the record count, or -1 if the
 * records do not fill the payload exactly. With `records` non-NULL, fills up
 * to `cap` of them, pointing into `payload`, skipping unknown odd types;
 * `*kept` (may be NULL) receives how many were kept. */
long gz_journal_parse_batch(const uint8_t *payload, size_t len, gz_record_t *records,
                            size_t cap, size_t *kept);

/* Encoders, used by the writer and the tests. Each writes into `out`
 * (GZ_JOURNAL_HEADER_LEN, GZ_JOURNAL_MARK_LEN, or the batch's size) and
 * returns the number of bytes. */
size_t gz_journal_encode_header(uint8_t out[48], const uint8_t chain[32]);
size_t gz_journal_encode_small(uint8_t out[37], uint8_t kind, uint64_t incarnation,
                               uint64_t value);
/* Size of a batch entry in the file, or 0 if larger than allowed. */
uint64_t gz_journal_batch_size(const gz_record_t *records, size_t n);
size_t gz_journal_encode_batch(uint8_t *out, gz_batch_id_t id, const gz_record_t *records,
                               size_t n);

/* --- The writer ------------------------------------------------------------ */

typedef struct gz_journal gz_journal_t;

typedef struct {
    const char *dir;                /* the node's data folder */
    const uint8_t *chain;           /* 32 bytes: this build's network */
    uint64_t clock_ms;              /* the clock port's time, for the incarnation entry */
    const gz_journal_os_t *os;      /* NULL: POSIX */
    /* 0 selects the specification's value. Tests set smaller ones. */
    uint64_t soft_limit, hard_limit, unsynced_max;
} gz_journal_config_t;

typedef struct {
    gz_journal_scan_t scan;   /* what the open found */
    uint64_t cut_bytes;       /* bytes cut as a torn tail */
    uint64_t incarnation;     /* the new incarnation, on success */
    int created;              /* the file was created by this open */
    int soft_full;            /* at or past the soft limit: tell the user, open no new lobby */
} gz_journal_open_info_t;

/* Open (or create) the journal and start a new incarnation (spec section 5).
 * On anything but GZ_JOURNAL_OK nothing is held open, `*out` is NULL and,
 * for a refusal, the file is untouched. `info` may be NULL. */
gz_journal_status_t gz_journal_open(gz_journal_t **out, const gz_journal_config_t *config,
                                    gz_journal_open_info_t *info);

typedef void (*gz_journal_confirmed_fn)(void *ctx, gz_batch_id_t batch);

/* Attach the runner created with this journal's incarnation, and the function
 * that gives the node a GZ_EVENT_STORAGE_CONFIRMED event (may be NULL). */
void gz_journal_attach(gz_journal_t *journal, gz_runner_t *runner,
                       gz_journal_confirmed_fn on_confirmed, void *ctx);

/* The incarnation this open wrote. */
uint64_t gz_journal_incarnation(const gz_journal_t *journal);

/* Reader over every durable batch, oldest first, including those of this
 * incarnation once they are durable. Records of unknown odd type are skipped.
 * If reading fails, the journal fails (as a storage failure) and `next`
 * returns 0; the runner then releases nothing more. Valid until close. */
gz_storage_reader_t gz_journal_reader(gz_journal_t *journal);

/* Append one save batch (GZ_ACTION_SAVE). Call from the executor, in the
 * order the runner hands saves over. The identifier must be this journal's
 * incarnation and the next sequence. Does not confirm. */
gz_journal_status_t gz_journal_save(gz_journal_t *journal, const gz_action_t *save);

/* Make every appended batch durable and confirm them in order. Call outside
 * the executor. A no-op when nothing awaits confirmation. */
gz_journal_status_t gz_journal_flush(gz_journal_t *journal);

/* Number of batches appended and not yet confirmed. */
size_t gz_journal_pending(const gz_journal_t *journal);

/* 1 once the journal has failed. */
int gz_journal_failed(const gz_journal_t *journal);

/* 1 at or past the soft limit (spec section 7). */
int gz_journal_soft_full(const gz_journal_t *journal);

/* Size of the file as written so far. */
uint64_t gz_journal_size(const gz_journal_t *journal);

/* Release the lock and free. Writes nothing; unconfirmed batches stay as the
 * operating system has them, to be judged at the next open. */
void gz_journal_close(gz_journal_t *journal);

#endif
