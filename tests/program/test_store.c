/* SPDX-License-Identifier: MIT */
/* The journal stand-in (program/journal_standin.c) against the storage
 * contract the executor relies on (program/store.h): incarnations strictly
 * increase and are durable at begin; batches come back in order with their
 * records; complete() reports each new batch once, oldest first; a torn tail
 * is cut, corruption refuses to open; appends out of order or under another
 * incarnation fail and fail for good. */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "store.h"

static int failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static char path[512];

static gz_batch_id_t id(uint64_t i, uint64_t s)
{
    gz_batch_id_t b;
    b.incarnation = i;
    b.sequence = s;
    return b;
}

static int open_store(gzp_store_t *s)
{
    char err[200] = "";
    int r = gzp_standin_open(s, path, err, sizeof err);
    if (r) fprintf(stderr, "open: %s\n", err);
    return r;
}

static size_t count_batches(gzp_store_t *s)
{
    gzp_batch_t b;
    size_t n = 0;
    s->ops->rewind(s->ctx);
    while (s->ops->next(s->ctx, &b)) n++;
    return n;
}

static off_t file_size(void)
{
    struct stat st;
    return stat(path, &st) == 0 ? st.st_size : -1;
}

int main(void)
{
    gzp_store_t s;
    gzp_batch_t b;
    gz_batch_id_t got;
    uint64_t inc = 0;
    char err[200];
    gz_record_t recs[2];
    const uint8_t a[] = "first record", c[] = "x";
    off_t size_ok;
    int fd;

    snprintf(path, sizeof path, "/tmp/gzp-test-store-%ld.journal", (long)getpid());
    unlink(path);

    /* A new file: incarnation 1, two batches, reported once each in order. */
    CHECK(open_store(&s) == 0);
    CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0 && inc == 1);
    CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) != 0); /* once per open */
    recs[0].type = 7; recs[0].bytes.data = a; recs[0].bytes.len = sizeof a;
    recs[1].type = 9; recs[1].bytes.data = NULL; recs[1].bytes.len = 0;
    CHECK(s.ops->complete(s.ctx, &got) == 0);
    CHECK(s.ops->append(s.ctx, id(1, 1), recs, 2) == 0);
    CHECK(s.ops->append(s.ctx, id(1, 2), NULL, 0) == 0); /* an empty batch is a batch */
    CHECK(s.ops->complete(s.ctx, &got) == 1 && got.incarnation == 1 && got.sequence == 1);
    CHECK(s.ops->complete(s.ctx, &got) == 1 && got.sequence == 2);
    CHECK(s.ops->complete(s.ctx, &got) == 0);
    CHECK(s.ops->restored(s.ctx) == 0);
    s.ops->close(s.ctx);

    /* Reopen: both batches with their records; the next incarnation is 2; the
     * old batches are not reported as new. */
    CHECK(open_store(&s) == 0);
    CHECK(count_batches(&s) == 2);
    s.ops->rewind(s.ctx);
    CHECK(s.ops->next(s.ctx, &b) == 1 && b.n_records == 2 && b.records[0].type == 7 &&
          b.records[0].bytes.len == sizeof a && !memcmp(b.records[0].bytes.data, a, sizeof a) &&
          b.records[1].type == 9 && b.records[1].bytes.len == 0);
    CHECK(s.ops->next(s.ctx, &b) == 1 && b.n_records == 0 && b.id.sequence == 2);
    CHECK(s.ops->next(s.ctx, &b) == 0);
    CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0 && inc == 2);
    CHECK(s.ops->complete(s.ctx, &got) == 0);
    /* Wrong incarnation, then out of order: refused, and storage is failed. */
    CHECK(s.ops->append(s.ctx, id(1, 3), recs, 1) != 0);
    CHECK(s.ops->append(s.ctx, id(2, 1), recs, 1) != 0); /* failed for good */
    s.ops->close(s.ctx);

    /* A begin that was durable but never used still moves the counter on. */
    CHECK(open_store(&s) == 0);
    CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0 && inc == 3);
    CHECK(s.ops->append(s.ctx, id(3, 2), recs, 1) == 0); /* sequences need only increase */
    CHECK(s.ops->append(s.ctx, id(3, 2), recs, 1) != 0); /* a repeated id */
    s.ops->close(s.ctx);
    size_ok = file_size();

    /* A torn tail: half an entry at the end is cut, the rest kept. */
    fd = open(path, O_WRONLY | O_APPEND);
    CHECK(fd >= 0);
    CHECK(write(fd, "BTCH\0\0\0\x40partial", 15) == 15);
    close(fd);
    CHECK(open_store(&s) == 0);
    CHECK(gzp_standin_cut_bytes(&s) == 15);
    CHECK(file_size() == size_ok);
    CHECK(count_batches(&s) == 3);
    CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0 && inc == 4);
    /* The test hook: the 2nd append from now fails, and so does every later one. */
    gzp_standin_fail_at(&s, 2);
    CHECK(s.ops->append(s.ctx, id(4, 1), recs, 1) == 0);
    CHECK(s.ops->append(s.ctx, id(4, 2), recs, 1) != 0);
    CHECK(s.ops->append(s.ctx, id(4, 3), recs, 1) != 0);
    CHECK(s.ops->complete(s.ctx, &got) == 1 && got.sequence == 1);
    CHECK(s.ops->complete(s.ctx, &got) == 0);
    s.ops->close(s.ctx);

    /* Corruption with data after it: a flipped byte in the first batch. */
    fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    {
        uint8_t byte;
        off_t at = 16 + 8 + 8 + 32 + 8 + 20; /* header, INCN entry, BTCH head, batch head */
        CHECK(pread(fd, &byte, 1, at) == 1);
        byte ^= 1;
        CHECK(pwrite(fd, &byte, 1, at) == 1);
    }
    close(fd);
    err[0] = 0;
    CHECK(gzp_standin_open(&s, path, err, sizeof err) != 0 && strstr(err, "corrupt"));

    /* Not a journal at all. */
    fd = open(path, O_WRONLY | O_TRUNC);
    CHECK(fd >= 0 && write(fd, "something else entirely", 23) == 23);
    close(fd);
    CHECK(gzp_standin_open(&s, path, err, sizeof err) != 0);

    (void)c;
    unlink(path);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("store: all checks passed\n");
    return 0;
}
