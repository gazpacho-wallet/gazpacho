/* SPDX-License-Identifier: MIT */
/* Storage as the executor sees it: the interface the real journal
 * (spec/journal.md, stream S5) and storage encryption (stream S6) will
 * provide. Today it is implemented by a plain append-only stand-in
 * (journal_standin.c), which is NOT the journal of the specification: no
 * encryption, no key_epoch, no compaction; its start counter and restore
 * marker are plain files.
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
} gzp_store_ops_t;

typedef struct {
    const gzp_store_ops_t *ops;
    void *ctx;
} gzp_store_t;

/* The stand-in: `dir`/journal.standin, created if missing, with the start
 * counter `dir`/starts.standin (written first at set-up) and the restore
 * marker `dir`/restore.pending (journal_standin.c). Refuses to open while
 * `dir`/storage.failed exists. Takes no lock: the data folder's lock
 * (datadir.c) is held around it. Reads the whole journal at open. */
int gzp_standin_open(gzp_store_t *out, const char *dir, char *err, size_t errlen);

/* 1 if a failed append could not be undone durably: stop, do not restart. */
int gzp_standin_poisoned(const gzp_store_t *s);

/* What begin() found of the start counter, and the value it wrote. */
#define GZP_COUNTER_FOUND   0
#define GZP_COUNTER_CREATED 1   /* first start of the folder (set-up) */
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
/* The k-th batch append writes and then has its sync report failure; with
 * cut_fail the cut back fails too (poisoned); crash_after_counter exits
 * between the start counter and the incarnation entry. */
void gzp_standin_test_hooks(gzp_store_t *s, unsigned sync_fail_at, int cut_fail, int crash_after_counter,
                            const char *log_name);
#endif

#endif
