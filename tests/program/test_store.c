/* SPDX-License-Identifier: MIT */
/* The journal stand-in (program/journal_standin.c) against the storage
 * contract the executor relies on (program/store.h): incarnations strictly
 * increase and are durable at begin; batches come back in order with their
 * records; complete() reports each new batch once, oldest first; a torn tail
 * is cut, corruption refuses to open; appends out of order or under another
 * incarnation fail and fail for good; the start counter keeps a journal
 * restored alone from reusing an incarnation (contract-v2.md section 8), and
 * the restore marker goes once batch 1 of a restored incarnation is durable. */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "store.h"

static int failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static char dir[512], path[600];

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
    int r = gzp_standin_open(s, dir, err, sizeof err);
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

/* Raw entries, written the way the stand-in writes them (for scan tests). */
static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)(v >> 32)); put32(p + 4, (uint32_t)v); }

static void raw_entry(int fd, uint32_t tag, const uint8_t *body, uint32_t len)
{
    uint8_t head[8], digest[32];
    unsigned int n = 0;
    EVP_MD_CTX *h = EVP_MD_CTX_new();
    put32(head, tag);
    put32(head + 4, len);
    EVP_DigestInit_ex(h, EVP_sha256(), NULL);
    EVP_DigestUpdate(h, head, 8);
    if (len) EVP_DigestUpdate(h, body, len);
    EVP_DigestFinal_ex(h, digest, &n);
    EVP_MD_CTX_free(h);
    if (write(fd, head, 8) != 8 || (len && write(fd, body, len) != (ssize_t)len) || write(fd, digest, 32) != 32)
        abort();
}

static void raw_incn(int fd, uint64_t inc)
{
    uint8_t b[8];
    put64(b, inc);
    raw_entry(fd, 0x494e434eu, b, 8);
}

static void raw_batch(int fd, uint64_t inc, uint64_t seq)
{
    uint8_t b[20];
    put64(b, inc);
    put64(b + 8, seq);
    put32(b + 16, 0);
    raw_entry(fd, 0x42544348u, b, 20);
}

/* A fresh journal file holding only the stand-in's header. */
static int raw_journal(void)
{
    uint8_t hdr[16] = {'G', 'Z', 'J', 'S', 'T', 'A', 'N', 'D', 0, 0, 0, 1, 0, 0, 0, 0};
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write(fd, hdr, 16) != 16) abort();
    return fd;
}

static int opens(void)
{
    gzp_store_t s;
    char err[200];
    if (gzp_standin_open(&s, dir, err, sizeof err) != 0) return 0;
    s.ops->close(s.ctx);
    return 1;
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

    snprintf(dir, sizeof dir, "/tmp/gzp-test-store-%ld", (long)getpid());
    snprintf(path, sizeof path, "%s/journal.standin", dir);
    mkdir(dir, 0700);
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
    CHECK(gzp_standin_cut_bytes(&s) == 15 && gzp_standin_cut_kept(&s) == 1);
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
    CHECK(gzp_standin_open(&s, dir, err, sizeof err) != 0 && strstr(err, "corrupt"));

    /* Not a journal at all. */
    fd = open(path, O_WRONLY | O_TRUNC);
    CHECK(fd >= 0 && write(fd, "something else entirely", 23) == 23);
    close(fd);
    CHECK(gzp_standin_open(&s, dir, err, sizeof err) != 0);

    /* The start counter: a fresh folder; three starts; the journal of the
     * first start put back alone; the next incarnation is above the counter. */
    {
        char backup[700], cpath[700], mpath[700], buf[64];
        uint64_t v = 0;
        unlink(path);
        snprintf(backup, sizeof backup, "%s/backup", dir);
        snprintf(cpath, sizeof cpath, "%s/starts.standin", dir);
        snprintf(mpath, sizeof mpath, "%s/restore.pending", dir);
        unlink(cpath);
        CHECK(open_store(&s) == 0);
        CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0 && inc == 1);
        CHECK(gzp_standin_counter_state(&s, &v) == GZP_COUNTER_CREATED && v == 1);
        CHECK(s.ops->append(s.ctx, id(1, 1), recs, 1) == 0);
        s.ops->close(s.ctx);
        /* the backup: a copy of the journal now */
        {
            FILE *in = fopen(path, "rb"), *out = fopen(backup, "wb");
            char cb[4096];
            size_t n;
            CHECK(in && out);
            while (in && out && (n = fread(cb, 1, sizeof cb, in)) > 0) CHECK(fwrite(cb, 1, n, out) == n);
            if (in) fclose(in);
            if (out) fclose(out);
        }
        CHECK(open_store(&s) == 0);
        CHECK(s.ops->restored(s.ctx) == 0);
        CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0 && inc == 2);
        CHECK(gzp_standin_counter_state(&s, &v) == GZP_COUNTER_FOUND && v == 2);
        s.ops->close(s.ctx);
        CHECK(open_store(&s) == 0);
        CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0 && inc == 3);
        s.ops->close(s.ctx);
        /* restore the journal of incarnation 1: the counter says 3, so 4 */
        CHECK(gzp_standin_put_restore(dir, backup, err, sizeof err) == 0);
        CHECK(open_store(&s) == 0);
        CHECK(s.ops->restored(s.ctx) == 1);
        CHECK(count_batches(&s) == 1);
        CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0 && inc == 4);
        CHECK(s.ops->restored(s.ctx) == 1);
        CHECK(gzp_standin_take_restore_answered(&s) == 0);
        CHECK(s.ops->append(s.ctx, id(4, 1), recs, 1) == 0); /* batch 1: the restore is answered */
        CHECK(s.ops->restored(s.ctx) == 0 && access(mpath, F_OK) != 0);
        CHECK(gzp_standin_take_restore_answered(&s) == 1);
        CHECK(gzp_standin_take_restore_answered(&s) == 0);
        s.ops->close(s.ctx);
        /* without the counter, a restore falls back to the journal alone */
        CHECK(gzp_standin_put_restore(dir, backup, err, sizeof err) == 0);
        unlink(cpath);
        CHECK(open_store(&s) == 0);
        CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0 && inc == 2);
        CHECK(gzp_standin_counter_state(&s, NULL) == GZP_COUNTER_MISSING);
        s.ops->close(s.ctx);
        /* a counter at 2^63 refuses the start; a damaged one counts as missing */
        fd = open(cpath, O_WRONLY | O_TRUNC);
        CHECK(fd >= 0);
        snprintf(buf, sizeof buf, "GZSTART0 9223372036854775808\n");
        CHECK(write(fd, buf, strlen(buf)) == (ssize_t)strlen(buf));
        close(fd);
        CHECK(open_store(&s) == 0);
        err[0] = 0;
        CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) != 0 && strstr(err, "2^63"));
        s.ops->close(s.ctx);
        fd = open(cpath, O_WRONLY | O_TRUNC);
        CHECK(fd >= 0 && write(fd, "GZSTART0 7x\n", 12) == 12);
        close(fd);
        CHECK(open_store(&s) == 0);
        CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0 && inc == 3);
        CHECK(gzp_standin_counter_state(&s, NULL) == GZP_COUNTER_MISSING);
        s.ops->close(s.ctx);
        unlink(backup);
        unlink(cpath);
        unlink(mpath);
        {
            char tmp[720];
            snprintf(tmp, sizeof tmp, "%s.tmp", cpath);
            unlink(tmp);
        }
    }

    /* The scan (review of PR 27, M28, M43b, M44 and L5): a repeated batch
     * id, a repeated INCN, and a batch of an incarnation never begun are
     * corruption; a whole-length last entry with a flipped body byte is a
     * torn tail. */
    fd = raw_journal(); raw_incn(fd, 1); raw_batch(fd, 1, 1); raw_batch(fd, 1, 1); close(fd);
    CHECK(!opens());
    fd = raw_journal(); raw_incn(fd, 1); raw_incn(fd, 1); close(fd);
    CHECK(!opens());
    fd = raw_journal(); raw_incn(fd, 1); raw_incn(fd, 3); raw_batch(fd, 2, 1); close(fd);
    CHECK(!opens());
    fd = raw_journal(); raw_incn(fd, 1); raw_incn(fd, 3); raw_batch(fd, 3, 1); close(fd);
    CHECK(opens()); /* 2 was skipped (a crash between counter and entry): fine */
    fd = raw_journal(); raw_incn(fd, 1); raw_batch(fd, 1, 1); raw_batch(fd, 1, 2); close(fd);
    size_ok = file_size();
    fd = open(path, O_RDWR);
    {
        uint8_t byte;
        off_t at = size_ok - 32 - 1; /* the last body byte of the last entry */
        CHECK(pread(fd, &byte, 1, at) == 1);
        byte ^= 0x40;
        CHECK(pwrite(fd, &byte, 1, at) == 1);
    }
    close(fd);
    CHECK(open_store(&s) == 0);
    CHECK(gzp_standin_cut_bytes(&s) == 8 + 20 + 32 && count_batches(&s) == 1);
    s.ops->close(s.ctx);

    /* B1 of review B: one flipped bit in the length field of an entry in the
     * middle makes it run past the end of the file. That is not a torn tail:
     * valid entries follow it, so open refuses and cuts nothing. Both a length
     * that only overruns the file and one above the largest entry. */
    {
        static const struct { int byte; uint8_t bit; } flips[] = {{1, 0x01}, {0, 0x80}, {2, 0x10}};
        size_t f;
        for (f = 0; f < sizeof flips / sizeof flips[0]; f++) {
            uint8_t byte = 0;
            off_t at = 16 + (8 + 8 + 32) + 4 + flips[f].byte; /* header, INCN entry, then batch (1,1)'s length */
            fd = raw_journal(); raw_incn(fd, 1); raw_batch(fd, 1, 1); raw_batch(fd, 1, 2); raw_batch(fd, 1, 3); close(fd);
            size_ok = file_size();
            fd = open(path, O_RDWR);
            CHECK(fd >= 0 && pread(fd, &byte, 1, at) == 1);
            byte ^= flips[f].bit;
            CHECK(pwrite(fd, &byte, 1, at) == 1);
            close(fd);
            err[0] = 0;
            CHECK(gzp_standin_open(&s, dir, err, sizeof err) != 0 && strstr(err, "corrupt"));
            CHECK(file_size() == size_ok); /* nothing cut */
        }
    }

    /* The cut keeps what it cuts: journal.standin.cut-N, the first unused N. */
    {
        char kp[700];
        struct stat st;
        unsigned n;
        for (n = 1; n < 20; n++) {
            snprintf(kp, sizeof kp, "%s.cut-%u", path, n);
            unlink(kp);
        }
        fd = raw_journal(); raw_incn(fd, 1); raw_batch(fd, 1, 1); close(fd);
        size_ok = file_size();
        /* B77: a tail shorter than an entry's head is torn */
        fd = open(path, O_WRONLY | O_APPEND);
        CHECK(fd >= 0 && write(fd, "BTCH\0", 5) == 5);
        close(fd);
        CHECK(open_store(&s) == 0);
        CHECK(gzp_standin_cut_bytes(&s) == 5 && gzp_standin_cut_kept(&s) == 1 && count_batches(&s) == 1);
        s.ops->close(s.ctx);
        snprintf(kp, sizeof kp, "%s.cut-1", path);
        CHECK(file_size() == size_ok && stat(kp, &st) == 0 && st.st_size == 5);
        /* B80: a last entry whose length is above the largest entry and runs
         * past the end is torn too (a crash while writing its head) */
        fd = open(path, O_WRONLY | O_APPEND);
        CHECK(fd >= 0 && write(fd, "BTCH\x40\0\0\0" "0123456789", 18) == 18);
        close(fd);
        CHECK(open_store(&s) == 0);
        CHECK(gzp_standin_cut_bytes(&s) == 18 && gzp_standin_cut_kept(&s) == 2 && count_batches(&s) == 1);
        s.ops->close(s.ctx);
        snprintf(kp, sizeof kp, "%s.cut-2", path);
        CHECK(file_size() == size_ok && stat(kp, &st) == 0 && st.st_size == 18);
        for (n = 1; n < 20; n++) {
            snprintf(kp, sizeof kp, "%s.cut-%u", path, n);
            unlink(kp);
        }
    }

    /* B25 and B17: a batch with sequence 0, and an incarnation entry of
     * another length, are corruption. */
    fd = raw_journal(); raw_incn(fd, 1); raw_batch(fd, 1, 0); close(fd);
    CHECK(!opens());
    {
        uint8_t nine[9] = {0, 0, 0, 0, 0, 0, 0, 1, 0};
        fd = raw_journal(); raw_entry(fd, 0x494e434eu, nine, 9); close(fd);
        CHECK(!opens());
        fd = raw_journal(); raw_entry(fd, 0x494e434eu, nine, 8); close(fd);
        CHECK(opens()); /* the same with 8 bytes is fine */
    }

    /* H1: a batch whose sync fails is cut back and gone for good, also for a
     * begin in the same process; if the cut fails too, the store is poisoned
     * and storage.failed refuses the next open. */
    {
        char fpath[700];
        snprintf(fpath, sizeof fpath, "%s/storage.failed", dir);
        unlink(path);
        CHECK(open_store(&s) == 0);
        CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0);
        gzp_standin_test_hooks(&s, 2, 0, 0, "test");
        CHECK(s.ops->append(s.ctx, id(inc, 1), recs, 1) == 0);
        size_ok = file_size();
        CHECK(s.ops->append(s.ctx, id(inc, 2), recs, 1) != 0);  /* written, then its sync fails */
        CHECK(file_size() == size_ok && !gzp_standin_poisoned(&s));
        CHECK(s.ops->complete(s.ctx, &got) == 1 && got.sequence == 1);
        CHECK(s.ops->complete(s.ctx, &got) == 0);
        s.ops->close(s.ctx);
        CHECK(open_store(&s) == 0); /* the restart in the same process */
        CHECK(count_batches(&s) == 1 && gzp_standin_cut_bytes(&s) == 0);
        CHECK(s.ops->begin(s.ctx, &inc, err, sizeof err) == 0);
        gzp_standin_test_hooks(&s, 1, 1, 0, "test");
        CHECK(s.ops->append(s.ctx, id(inc, 1), recs, 1) != 0);  /* sync fails, and the cut too */
        CHECK(gzp_standin_poisoned(&s) && access(fpath, F_OK) == 0);
        s.ops->close(s.ctx);
        err[0] = 0;
        CHECK(gzp_standin_open(&s, dir, err, sizeof err) != 0 && strstr(err, "storage.failed"));
        unlink(fpath);
        CHECK(opens());
    }

    (void)c;
    unlink(path);
    {
        char cp[700];
        snprintf(cp, sizeof cp, "%s/starts.standin", dir);
        unlink(cp);
    }
    rmdir(dir);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("store: all checks passed\n");
    return 0;
}
