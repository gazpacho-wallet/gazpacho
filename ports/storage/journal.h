/* The storage journal: how a node's saved batches survive a crash.
 *
 * Specification: spec/journal.md. The bytes are draft 2's CLEAR FORMAT, a
 * stand-in that will not ship: draft 3 encrypts every entry (see
 * "Encryption" below), and the J vectors are kept for history only. The
 * crash logic is draft 3's. This is the outer layer
 * (DESIGN.md section 3, L4): it uses the operating system, the core does not.
 * Every operating-system call goes through a gz_journal_os_t table, so tests
 * can fail or "crash" at any write or sync; NULL selects the POSIX one.
 *
 * ONE FILE PER NODE, ONE WRITER. `journal.gzj` in the node's data folder.
 * The writer holds an exclusive lock on `journal.lock` in the same folder, a
 * file that is never replaced or removed, so replacing `journal.gzj` (an
 * import, a person's copy) cannot let a second program in; it is taken
 * before the journal is created, imported or marked. Bytes are only ever
 * appended; the one exception is cutting a torn tail at open, which removes
 * only bytes after the last sync mark (spec section 5).
 *
 * HOW THE PROGRAM USES IT
 *
 *   gz_journal_open        lock, sync the file and read it from the storage
 *                          device (not the page cache: spec section 4,
 *                          failures), check the header, scan, cut a torn
 *                          tail or refuse corruption, write the start
 *                          counter (config.write_counter), then write and
 *                          sync a new incarnation entry and its sync mark.
 *                          Pass the returned incarnation to gz_runner_init.
 *   gz_journal_attach      give it the runner and the function that hands a
 *                          GZ_EVENT_STORAGE_CONFIRMED event to the node.
 *   gz_journal_reader      the gz_storage_reader_t for gz_node_start.
 *   gz_journal_save        from the runner's executor, for each save action:
 *                          append the batch entry (not yet synced).
 *   gz_journal_flush       outside the executor: sync, append a sync mark,
 *                          sync again, replace the guard file if a batch held
 *                          a guard record, then confirm every batch the sync
 *                          covered, oldest first. Only a confirmation the
 *                          runner accepts reaches the node. Refused, with
 *                          nothing done, while no runner is attached. A
 *                          flush called from `on_confirmed` is deferred
 *                          until the running one has confirmed its batches.
 *   gz_journal_close       release the lock and free. Writes nothing.
 *
 * OR, for a program that confirms batches itself (program/store.h on the
 * program skeleton: begin, next/rewind, append, complete, restored, close):
 * open with config.pull = 1, attach no runner, append with gz_journal_save,
 * and take durable batches with gz_journal_complete, oldest first, once each,
 * to give to gz_runner_confirm. complete() runs the flush itself when it has
 * nothing to report, so the guard file and the restore marker are dealt with
 * before any identifier is reported.
 *
 * THE FENCE (ports.h). gz_journal_open settles everything an earlier program
 * left: it scans the file as the device holds it, cuts the torn tail or
 * refuses, brings guard.gzg up to the newest kept guard record when an
 * earlier program kept such a batch without writing the file (not on a
 * restored start, whose guard file is the stale-backup evidence of storage
 * 6.3), and makes the new incarnation durable before the reader exists. No earlier program's batch
 * can appear afterwards: the file is locked, and only this incarnation's
 * batches are added to the reader, as they become durable.
 *
 * THE RESTORE MARKER (ports.h). A program imports a backup with
 * gz_journal_import, which writes the marker FIRST and only then renames the
 * backup to journal.gzj, so a crash at any point leaves either the old
 * journal (the marker is then found answered and cleared: the import did
 * not happen) or the backup marked as a restore. A key file with no journal
 * (storage 6.3 step 0) is started as a restore with gz_journal_mark_restored
 * before the first open. From then on every open sets the reader's
 * `restored` until the batch with sequence 1 of an incarnation started after
 * the import is durable (the node's restore batch); the marker file is then
 * removed, before that batch is confirmed. A crash between the two is
 * recognised at the next open from the journal itself.
 *
 * THE INCARNATION. 1 + the largest of the journal's highest, the start
 * counter (config.start_counter: contract-v2 section 8, `starts.gzs`) and,
 * while a restore is unanswered, the marker's floor. It must stay below
 * 2^63, or the open refuses (GZ_JOURNAL_ERR_INCARNATION). The number is
 * handed to config.write_counter, which writes the counter, before the
 * incarnation entry is appended.
 *
 * A write, sync, limit or contract failure calls gz_runner_storage_failed (if
 * a runner is attached), and the journal then writes and confirms nothing
 * more. A failed sync is never retried (spec section 4), and since the page
 * cache may still hold the bytes that failed, every open reads the file from
 * the device after syncing it: an in-process restart after a storage
 * failure takes that path like any other start (there is no other).
 *
 * ENCRYPTION (spec/storage-encryption.md; PR 25's ports/storage/crypto).
 * Every byte of a frame's layout and protection is in the codec section of
 * journal.c (frame_seal, frame_open, frame_mark_candidate, header_seal,
 * header_open), which already receives each frame's file offset. The
 * encrypted format replaces those five with gz_sc_frame_seal/_open and
 * gz_sc_header_seal/_open; the crash logic around them does not change. */
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
#define GZ_JOURNAL_MARKER_FILE "restore.gzr"
#define GZ_JOURNAL_LOCK_FILE  "journal.lock"   /* never replaced or removed */
#define GZ_JOURNAL_INCARNATION_LIMIT (1ull << 63) /* contract-v2 section 8 */
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
    GZ_JOURNAL_ERR_FAILED,         /* the journal has failed and does nothing more */
    GZ_JOURNAL_ERR_MARKER,         /* restore.gzr is damaged or for another network */
    GZ_JOURNAL_ERR_INCARNATION     /* the next incarnation would reach 2^63 */
} gz_journal_status_t;

const char *gz_journal_status_name(gz_journal_status_t status);

/* --- Operating-system calls -------------------------------------------------
 * Each returns 0 (or a non-negative count or descriptor) on success and -1 on
 * failure, setting errno. */
#define GZ_JOURNAL_OPEN_READ        1  /* read only; errno ENOENT if missing */
#define GZ_JOURNAL_OPEN_RW          2  /* read and write an existing file */
#define GZ_JOURNAL_OPEN_CREATE_EXCL 3  /* new file, mode 0600; errno EEXIST if present */
#define GZ_JOURNAL_OPEN_CREATE_TRUNC 4 /* create or empty, mode 0600 */
#define GZ_JOURNAL_OPEN_CREATE      5  /* open, or create empty if missing, mode 0600; never truncates */

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
    int (*link)(void *ctx, const char *from, const char *to);   /* never replaces; EEXIST;
                                                                   EPERM etc. without hard links */
    int (*rename)(void *ctx, const char *from, const char *to); /* replaces */
    int (*unlink)(void *ctx, const char *path);
    /* Read what the storage device holds, not what the page cache holds:
     * called only after a successful sync of `fd`. After a failed writeback,
     * Linux keeps the failed bytes readable in the cache, marked clean, and
     * never writes them (spec section 4). POSIX: drop the file's clean cached
     * pages (posix_fadvise DONTNEED), then read with O_DIRECT where the file
     * system takes it, else an ordinary read; macOS: F_NOCACHE.
     * Limits (review B, B5): where O_DIRECT falls back silently (ext4
     * data=journal, inline-data files, fscrypt without inline encryption,
     * compressed btrfs, ZFS before 2.3) or is refused (tmpfs before Linux
     * 6.6, some FUSE mounts), the fadvise is the only defence, and it keeps
     * pages another process has mapped: nothing may mmap journal.gzj while
     * the wallet runs (gz-journal reads it with stdio). The macOS path is
     * unverified: Apple's fcntl(2) does not say F_NOCACHE bypasses a page
     * already cached. */
    long (*pread_device)(void *ctx, int fd, void *buf, size_t len, uint64_t off);
    void *ctx;
} gz_journal_os_t;

const gz_journal_os_t *gz_journal_os_posix(void);

/* Tests only: with `on` 1, the POSIX table's direct read reports EINVAL as a
 * file system that refuses O_DIRECT does (tmpfs before Linux 6.6, some FUSE
 * mounts), so the fallback runs; 0 restores. Not thread-safe. */
void gz_journal_posix_test_direct_einval(int on);

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
    /* 1: never call a runner; report durable batches through
     * gz_journal_complete instead (the program confirms them). */
    int pull;
    /* The start counter (contract-v2 section 8, `starts.gzs`): the value the
     * program read, 0 if the file is missing or damaged. Applied on every
     * start: the new incarnation is above it. */
    uint64_t start_counter;
    /* Called once per open with the new incarnation, after the scan and
     * before the incarnation entry is appended: write the counter (write
     * `starts.gzs.tmp`, sync, rename, sync the folder). Nonzero: the open
     * fails (GZ_JOURNAL_ERR_IO) and appends nothing. A crash between the two
     * skips a number, which is harmless. May be NULL. */
    int (*write_counter)(void *ctx, uint64_t incarnation);
    void *counter_ctx;
} gz_journal_config_t;

typedef struct {
    gz_journal_scan_t scan;   /* what the open found */
    uint64_t cut_bytes;       /* bytes cut as a torn tail */
    uint64_t incarnation;     /* the new incarnation, on success */
    int created;              /* the file was created by this open */
    int soft_full;            /* at or past the soft limit: tell the user, open no new lobby */
    int restored;             /* the restore marker is set for this start */
} gz_journal_open_info_t;

/* Open (or create) the journal and start a new incarnation (spec section 5).
 * On anything but GZ_JOURNAL_OK nothing is held open and `*out` is NULL. A
 * refusal by the scan (header, network, corrupt, order, unknown record)
 * leaves the file untouched. `info` may be NULL.
 *
 * GZ_JOURNAL_ERR_IO AT THE FIRST START AFTER A WRITEBACK ERROR. If the
 * kernel's writeback of the journal failed and no program saw the error (the
 * program was killed before its flush), Linux reports it to the next
 * descriptor's first fsync: this open's own sync, which then refuses (spec
 * section 5 step 2). Nothing is lost by it, and the next open reads what
 * survived. The program should say "storage error, trying again" and open
 * once more, not that the wallet is damaged; only a second refusal is a
 * failure to report as such (review B, B4).
 *
 * Every open syncs the folder before anything rests on the journal's name
 * (the open that created it may have failed before its own folder sync). */
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
 * the executor. A no-op when nothing awaits confirmation. Without pull mode
 * and with no runner attached, GZ_JOURNAL_ERR_ARGUMENT and nothing is done
 * (the batches stay pending: no confirmation is dropped). Called again from
 * `on_confirmed` (the node saved in answer and the program flushes at
 * once), it returns GZ_JOURNAL_OK at once and the running flush makes the
 * new batches durable and confirms them after its own, so confirmations
 * stay in order. */
gz_journal_status_t gz_journal_flush(gz_journal_t *journal);

/* Pull mode only: the oldest durable batch not yet reported, once each; 1 and
 * `*id`, or 0 when there is none (or the journal has failed). Flushes first
 * when nothing durable is waiting. Outside the executor. */
int gz_journal_complete(gz_journal_t *journal, gz_batch_id_t *id);

/* The restore marker for this start (the reader's `restored`): 1 until the
 * restored node's answer is durable. */
int gz_journal_restored(const gz_journal_t *journal);

/* Import a backup as a restore (ports.h; spec 8.2). Like the open, it locks
 * journal.lock and then journal.gzj itself, so a running program is never
 * replaced even if journal.lock was removed or replaced by hand. A journal
 * to replace that cannot be read (I/O error, no memory, over the hard limit)
 * refuses the import (GZ_JOURNAL_ERR_IO etc., nothing written); one the scan
 * refuses gives the highest incarnation the scan saw (before the damage,
 * the newest valid sync mark after it, or a valid entry breaking the order)
 * to the floor. `staged` is the backup,
 * already copied to a file IN `dir` (the same file system, so the rename is
 * atomic), for example `dir`/journal.gzj.import. Under the lock: syncs and
 * reads the staged file (refusing one the scan refuses), takes the floor as
 * the larger of `floor` and the highest incarnation of the journal it
 * replaces (see above; a journal with an unreadable header gives none, and
 * the caller's floor and the start counter must cover it), writes the
 * restore marker, durably, and only then
 * renames the staged file over journal.gzj and syncs the folder. A crash
 * before the rename leaves the old journal with a marker whose `base` it is
 * already above, so the next open clears the marker as answered: the import
 * did not happen (in the rare case that the old journal holds no batch
 * above `base`, the old journal starts as a restore, which is safe). A crash
 * after it is a marked restore. GZ_JOURNAL_ERR_LOCKED while a program has
 * the journal open. `os` NULL: POSIX. */
gz_journal_status_t gz_journal_import(const char *dir, const uint8_t chain[32],
                                      const gz_journal_os_t *os, const char *staged,
                                      uint64_t floor);

/* Start the files in place as a restore (storage 6.3: files found behind,
 * started as a restore; or step 0, a key file with no journal): set the
 * restore marker, durably, under the lock (journal.lock and journal.gzj, as
 * the import). `floor` is the highest
 * incarnation known to have been used (0 if none or unknown); no start
 * under the marker uses a number at or below it. Reads the journal
 * (refusing one the scan refuses); with no journal yet, the marker's base is
 * 0 and the open that follows creates the journal and starts restored. A
 * second call before the restore is answered keeps the higher floor. Never
 * use it after replacing journal.gzj yourself: gz_journal_import writes the
 * marker before the file. GZ_JOURNAL_ERR_LOCKED while the journal is open.
 * `os` NULL: POSIX. */
gz_journal_status_t gz_journal_mark_restored(const char *dir, const uint8_t chain[32],
                                             const gz_journal_os_t *os, uint64_t floor);

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
