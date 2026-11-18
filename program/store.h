/* SPDX-License-Identifier: MIT */
/* Storage as the executor sees it. Implemented by the real journal
 * (spec/journal.md, stream S5) sealed by storage encryption (stream S6):
 * store_journal.c, the program's store. The plain append-only stand-in
 * (journal_standin.c) stays for the tests that read its files
 * (--test-standin-store, gazpacho-test only); it is NOT the journal of the
 * specification: no encryption, no compaction; its start counter and
 * restore marker are plain files.
 *
 * The contract, from core/gazpacho/include/gazpacho/runner.h and ports.h:
 *   - begin() settles whatever an earlier program left pending (THE FENCE:
 *     each such batch is durable or gone for good), then makes a new
 *     incarnation durable, strictly greater than any used before for this
 *     storage, and only then returns it. The runner is never used before.
 *     The number is 1 + max(the journal's highest, the start counter), and
 *     the counter is written first (contract-v2.md section 8), so a journal
 *     restored alone never reuses a number this device used since its backup.
 *     Either value read at or above 2^63 refuses the start, so 2^63 itself
 *     is used at most once and the start after it refuses (contract-v2.md
 *     section 8, to the letter; review B of PR 27, N3).
 *   - next()/rewind() walk the durable batches oldest first, including those
 *     appended since begin(); what next() returns stays valid until the next
 *     call of next() or rewind().
 *   - append() stores one batch atomically, in the order appended, and is
 *     SYNCHRONOUS: when it returns 0 the batch is durable; complete() then
 *     reports it (oldest first, once each).
 *   - WHEN append() FAILS THE BATCH IS GONE FOR GOOD, never "maybe durable".
 *     A write or a sync that fails is undone before append() returns: the
 *     file is cut back to its length before the append and that cut is
 *     synced. Nothing in this process, nor a begin() after it in the same
 *     process, may read those bytes back (on Linux a failed fsync leaves them
 *     readable in the page cache while they may be lost on power failure:
 *     the "fsyncgate" behaviour; the journal of PR 29 fixes the same thing,
 *     its R1). If the cut cannot be made durable either, the store is
 *     POISONED (poisoned() returns 1): the program must not start again in
 *     process, and the next start must refuse until a person has looked
 *     (the stand-in leaves storage.failed). The executor ends the incarnation
 *     on any failure, restarts from storage only if the store is not
 *     poisoned, and exits otherwise (GZP_EXIT_STORAGE).
 *
 * WHAT AN ASYNCHRONOUS (GROUP-COMMIT) JOURNAL NEEDS. The executor relies on
 * append() being synchronous; a journal that becomes durable later does NOT
 * plug in unchanged (review of PR 27, M2). S5 must add, and the executor then
 * use:
 *   1. pollfds(ctx, fds, cap, &timeout_ms) and dispatch(ctx, fds, n): a
 *      descriptor and a deadline for the loop's one poll(), so a batch that
 *      becomes durable wakes the loop and is confirmed at once, not when some
 *      other event happens to end the poll;
 *   2. in the stepped start, GZ_WAITING is the normal case and must wait on
 *      those descriptors (stepping the network with every input queued, as
 *      the start-delay test hook does), never be fatal; today a GZ_WAITING
 *      with nothing complete is fatal only because a synchronous store can
 *      never complete anything later;
 *   3. back-pressure by waiting on storage's descriptor (and still stepping
 *      the transport's keep-alives), never a busy wait; today the executor
 *      treats unconfirmed batches after a drain as a contract breach, since a
 *      synchronous store cannot have any.
 * And the failure rule above holds per batch: a group that fails to sync
 * leaves every batch in it gone for good. */
#ifndef GZP_STORE_H
#define GZP_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "gazpacho/action.h"

typedef struct {
    gz_batch_id_t id;
    const gz_record_t *records;
    size_t n_records;
} gzp_batch_t;

typedef struct {
    /* 0, or -1 with a reason in err. */
    int (*begin)(void *ctx, uint64_t *incarnation, char *err, size_t errlen);
    /* 1 with *out filled, 0 at the end. */
    int (*next)(void *ctx, gzp_batch_t *out);
    void (*rewind)(void *ctx);
    /* 0: durable. -1: failed, the batch gone for good (above); fatal. */
    int (*append)(void *ctx, gz_batch_id_t id, const gz_record_t *records, size_t n);
    /* The oldest durable batch not yet reported: 1 and *id, or 0. */
    int (*complete)(void *ctx, gz_batch_id_t *id);
    /* The restore marker (ports.h): 1 while a restore of the journal has not
     * been answered by a durable batch 1 of an incarnation begun with it. */
    int (*restored)(void *ctx);
    void (*close)(void *ctx);
    /* THE GUARD FILE (journal.md 8.3; ports.h, the reader's `guard`): the
     * bytes of the newest guard record storage keeps outside the journal, so
     * that a restore of the journal alone does not take it back. 1 with
     * *data and *len (valid until the next append or close), 0 if there is
     * none. May be NULL: no guard file. */
    int (*guard)(void *ctx, const uint8_t **data, size_t *len);
    /* What the executor reports and hands to the node, for either store. */
    int (*poisoned)(void *ctx);                        /* below */
    int (*counter_state)(void *ctx, uint64_t *value);  /* GZP_COUNTER_*, after begin */
    int (*take_restore_answered)(void *ctx);           /* 1 once, below */
    uint64_t (*cut_bytes)(void *ctx);                  /* torn bytes cut by the last begin/open */
    /* Tests (gazpacho-test; NULL in the release program): the k-th append
     * from now fails before writing anything; the next batch holding a test
     * ping record has its sync fail; the k-th batch's sync fails (cut_fail:
     * the undo fails too, where the store has one), crash_after_counter exits
     * between the counter and the incarnation entry. */
    void (*test_fail_at)(void *ctx, unsigned k);
    void (*test_fail_next_ping)(void *ctx);
    void (*test_hooks)(void *ctx, unsigned sync_fail_at, int cut_fail, int crash_after_counter, const char *log_name);
} gzp_store_ops_t;

typedef struct {
    const gzp_store_ops_t *ops;
    void *ctx;
} gzp_store_t;

/* The calls above, safe where a store leaves one NULL. */
int gzp_store_poisoned(const gzp_store_t *s);
int gzp_store_counter_state(const gzp_store_t *s, uint64_t *value);
int gzp_store_take_restore_answered(gzp_store_t *s);
uint64_t gzp_store_cut_bytes(const gzp_store_t *s);

/* THE REAL STORE (store_journal.c): the journal of ports/storage/journal.h
 * (S5) in its sealed format, under the keys of an unlocked wallet
 * (store_unlock.h; S6). journal.gzj, the mark file, the sealed guard file,
 * the sealed start counter starts.gzs (P9) and restore.gzr, in `dir`.
 * begin() is gz_journal_open (pull mode): the fence, the start rule (a
 * journal behind its mark file or guard, or possibly old, refuses with
 * GZP_STORE_BEHIND), the counter written first, the incarnation durable.
 * append() appends and makes durable (sync, mark, sync, the mark file's
 * entry for an anchored batch, the guard file) before it returns: a failed
 * one is a failed journal, which writes nothing more, and the next begin
 * reads what the device holds (journal.md 4), so it is never "poisoned". */
struct gzp_wallet;
int gzp_journal_store_open(gzp_store_t *out, const char *dir, struct gzp_wallet *w, char *err, size_t errlen);
/* The incarnation begin() made durable (0 before begin). */
uint64_t gzp_journal_store_incarnation(const gzp_store_t *s);
/* begin() refused by the start rule: 1 behind, 2 possibly old, else 0. */
int gzp_journal_store_behind(const gzp_store_t *s);
/* Every batch and record of the journal, read only, as output lines
 * (journal-batch, journal-record with the record's bytes in hex in the test
 * build). 0, or -1 with a reason in err. Takes the journal's lock. */
int gzp_journal_dump(const char *dir, struct gzp_wallet *w, char *err, size_t errlen);
/* Import a backup of the journal as a restore (journal.h, gz_journal_import):
 * staged first as journal.gzj.import in dir. Tests (--test-restore-from) and,
 * later, the API's import. */
int gzp_journal_store_import(const char *dir, struct gzp_wallet *w, const char *backup, char *err, size_t errlen);
/* Mark the journal in place as a restore (gz_journal_mark_restored, floor
 * the start counter): storage 6.3 step 4, "start as restore". */
int gzp_journal_store_mark_restored(const char *dir, struct gzp_wallet *w, uint64_t floor, char *err, size_t errlen);

#define GZP_STORE_BEHIND (-2)  /* begin(): the start rule refused (files behind) */

#ifdef GZP_TEST_BUILD
/* --test-kill-at N (gazpacho-test): SIGKILL just before the N-th write, sync,
 * truncate, rename or removal of storage this process makes, the journal's
 * and the storage layer's alike (store_unlock.c wraps the latter). */
void gzp_store_test_kill_at(unsigned n);
void gzp_store_test_tick(const char *what);
/* --test-power-cut-at K (program/store_powercut.c): the kill at K first puts
 * the folder back to what a disk keeps: each file's data as of its last
 * fsync, the folder's names as of its last folder sync. The hooks are called
 * by the storage layer's and the journal's OS tables; no-ops while off. */
void gzp_store_test_power_cut(void);
int gzp_pc_pre(const char *path);
void gzp_pc_opened(const char *path, int fd, int existed);
void gzp_pc_closed(int fd);
void gzp_pc_synced(int fd);
void gzp_pc_dir_synced(const char *dir);
void gzp_pc_renamed(const char *from, const char *to);
void gzp_pc_linked(const char *from, const char *to);
void gzp_pc_unlinked(const char *path);
void gzp_pc_cut(void);
#endif

/* The stand-in: `dir`/journal.standin, created if missing, with the start
 * counter `dir`/starts.standin (written first at set-up), the restore
 * marker `dir`/restore.pending and the guard file `dir`/guard.standin
 * (journal_standin.c). The guard file is outside what a restore replaces:
 * every durable batch that holds a guard record replaces it (write, sync,
 * rename, sync the folder), never with a lower counter, and a restored
 * start is given it, so the node's restore batch keeps what was used since
 * the backup (review of PR 41, confirmation F1). Refuses to open while
 * `dir`/storage.failed exists. Takes no lock: the data folder's lock
 * (datadir.c) is held around it. Reads the whole journal at open. */
int gzp_standin_open(gzp_store_t *out, const char *dir, char *err, size_t errlen);

/* 1 if a failed append could not be undone durably: stop, do not restart. */
int gzp_standin_poisoned(const gzp_store_t *s);

/* What begin() found of the start counter, and the value it wrote. */
#define GZP_COUNTER_FOUND   0
#define GZP_COUNTER_CREATED 1   /* first start of the folder (set-up) */
#define GZP_COUNTER_SETUP_INTERRUPTED 3 /* missing beside the set-up marker, no journal: told in softer
                                          * words, never hidden; the start is still a restore (6.3 step 0) */
#define GZP_COUNTER_MISSING 2   /* missing or unreadable: the journal alone gave the number */
int gzp_standin_counter_state(const gzp_store_t *s, uint64_t *value);

/* 1 once, after batch 1 of an incarnation begun with the restore marker is
 * durable (the marker is then gone). */
int gzp_standin_take_restore_answered(gzp_store_t *s);

/* Output: bytes cut from a torn tail at the last open, and N of the file
 * `dir`/journal.standin.cut-N that keeps them (0: nothing cut). A damaged
 * entry with any valid entry after it is never cut: open refuses instead
 * (review B of PR 27, B1). S5's journal must keep the same rule. */
uint64_t gzp_standin_cut_bytes(const gzp_store_t *s);
unsigned gzp_standin_cut_kept(const gzp_store_t *s);

#ifdef GZP_TEST_BUILD
/* Tests only (gazpacho-test; absent from the release binary). */
/* --test-restore-from: put `backup` in place as `dir`'s journal, as a restore
 * of the journal alone: the file, then the restore marker. */
int gzp_standin_put_restore(const char *dir, const char *backup, char *err, size_t errlen);
/* The k-th append from now fails before writing anything (0: never). */
void gzp_standin_fail_at(gzp_store_t *s, unsigned k);
/* Tests ("sync-fail-ping" on standard input): the next batch that holds a
 * test engine ping record is written and its sync reports failure, as
 * --test-sync-fail-at does for a batch picked by number. */
void gzp_standin_fail_next_ping(gzp_store_t *s);
/* The k-th batch append writes and then has its sync report failure; with
 * cut_fail the cut back fails too (poisoned); crash_after_counter exits
 * between the start counter and the incarnation entry. */
void gzp_standin_test_hooks(gzp_store_t *s, unsigned sync_fail_at, int cut_fail, int crash_after_counter,
                            const char *log_name);
#endif

#endif
