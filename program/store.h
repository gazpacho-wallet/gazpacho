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
 *   - next()/rewind() walk the durable batches oldest first, including those
 *     appended since begin(); what next() returns stays valid until the next
 *     call of next() or rewind().
 *   - append() stores one batch atomically. Batches are stored in the order
 *     appended. complete() reports, oldest first and once each, the batches
 *     that have become durable. The stand-in is synchronous (append writes
 *     and syncs; the batch is complete when append returns 0), but the
 *     executor only relies on complete(), so a journal that commits in groups
 *     plugs in unchanged.
 *   - A failure of append is fatal for the incarnation: nothing more is
 *     appended, and the program starts again from storage. */
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
    /* 0 accepted, -1 failed (fatal). */
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
 * counter `dir`/starts.standin and the restore marker `dir`/restore.pending
 * (journal_standin.c). Takes no lock: the data folder's lock (datadir.c) is
 * held around it. Reads the whole journal at open: the stand-in keeps every
 * record in memory. begin() takes the incarnation from the journal and the
 * start counter (contract-v2.md section 8). */
int gzp_standin_open(gzp_store_t *out, const char *dir, char *err, size_t errlen);

/* What begin() found of the start counter, and the value it wrote. */
#define GZP_COUNTER_FOUND   0
#define GZP_COUNTER_CREATED 1   /* first start of the folder (set-up) */
#define GZP_COUNTER_MISSING 2   /* missing or unreadable: the journal alone gave the number */
int gzp_standin_counter_state(const gzp_store_t *s, uint64_t *value);

/* 1 once, after batch 1 of an incarnation begun with the restore marker is
 * durable (the marker is then gone). */
int gzp_standin_take_restore_answered(gzp_store_t *s);

/* Tests (--test-restore-from): put `backup` in place as `dir`'s journal, as a
 * restore of the journal alone: the restore marker, then the file. */
int gzp_standin_put_restore(const char *dir, const char *backup, char *err, size_t errlen);

/* Tests: make the k-th append from now fail (0: never). */
void gzp_standin_fail_at(gzp_store_t *s, unsigned k);
/* Tests and output: bytes cut from a torn tail at the last open. */
uint64_t gzp_standin_cut_bytes(const gzp_store_t *s);

#endif
