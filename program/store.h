/* SPDX-License-Identifier: MIT */
/* Storage as the executor sees it: the interface the real journal
 * (spec/journal.md, stream S5) and storage encryption (stream S6) will
 * provide. Today it is implemented by a plain append-only stand-in
 * (journal_standin.c), which is NOT the journal of the specification: no
 * encryption, no key_epoch, no restore marker, no compaction.
 *
 * The contract, from core/gazpacho/include/gazpacho/runner.h and ports.h:
 *   - begin() settles whatever an earlier program left pending (THE FENCE:
 *     each such batch is durable or gone for good), then makes a new
 *     incarnation durable, strictly greater than any used before for this
 *     storage, and only then returns it. The runner is never used before.
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
    /* The restore marker (ports.h in the core follow-up): 1 while a restore
     * from a backup has not been answered. The stand-in has no backups: 0. */
    int (*restored)(void *ctx);
    void (*close)(void *ctx);
} gzp_store_ops_t;

typedef struct {
    const gzp_store_ops_t *ops;
    void *ctx;
} gzp_store_t;

/* The stand-in: one file, `path`, created if missing. Takes no lock: the data
 * folder's lock (datadir.c) is held around it. Reads the whole file at open:
 * the stand-in keeps every record in memory. */
int gzp_standin_open(gzp_store_t *out, const char *path, char *err, size_t errlen);

/* Tests: make the k-th append from now fail (0: never). */
void gzp_standin_fail_at(gzp_store_t *s, unsigned k);
/* Tests and output: bytes cut from a torn tail at the last open. */
uint64_t gzp_standin_cut_bytes(const gzp_store_t *s);

#endif
