/* SPDX-License-Identifier: MIT */
/* A plain append-only journal stand-in behind store.h.
 *
 * NOT spec/journal.md. It exists so the program can run end to end before
 * the journal (stream S5) and storage encryption (stream S6) are merged; both
 * will replace it behind the same interface. Nothing here is encrypted.
 *
 * File: a 16-byte header "GZJSTAND", version (4 bytes, big-endian, 1), 4 zero
 * bytes; then entries, each
 *     tag (4) | body length (4) | body | SHA-256 of tag, length and body (32)
 * with every integer big-endian. Tags:
 *     INCN  body = incarnation (8): written and synced at every begin()
 *     BTCH  body = incarnation (8) | sequence (8) | record count (4) |
 *                  per record: type (4) | length (4) | bytes
 *
 * Open (the fence): read every entry. An entry that runs past the end of the
 * file, or whose hash fails while it is the last thing in the file, is a torn
 * tail: the file is cut before it and synced. A bad entry with data after it,
 * an unknown tag, identifiers that do not strictly increase, or a batch of an
 * incarnation never begun, is corruption: open fails and the program does not
 * start. After the cut nothing an earlier program wrote can still complete:
 * that program is gone (the data folder lock says so) and its unsynced bytes
 * are either in the file now or never will be. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "store.h"

#define HDR_LEN 16
#define TAG_INCN 0x494e434eu
#define TAG_BTCH 0x42544348u
#define MAX_BODY (16u << 20)        /* one entry */
#define MAX_TOTAL (256ull << 20)    /* the whole stand-in, held in memory */

typedef struct {
    gz_batch_id_t id;
    size_t first, n;
} sbatch_t;

typedef struct {
    int fd;
    uint64_t file_len;
    uint64_t max_inc;     /* largest incarnation begun */
    uint64_t cur_inc;     /* this program's, after begin() */
    gz_batch_id_t last;   /* the newest batch stored */
    int have_last;
    sbatch_t *b;
    size_t nb, capb;
    gz_record_t *r;
    size_t nr, capr;
    size_t cursor;
    size_t reported;      /* batches already given out by complete() */
    size_t first_new;     /* batches from first_new on were appended by this program */
    int failed;
    unsigned fail_at;     /* tests */
    uint64_t cut;
} standin_t;

static void be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static void be64(uint8_t *p, uint64_t v) { be32(p, (uint32_t)(v >> 32)); be32(p + 4, (uint32_t)v); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) << 32 | rd32(p + 4); }

static int id_after(gz_batch_id_t a, gz_batch_id_t b) /* a > b */
{
    return a.incarnation > b.incarnation || (a.incarnation == b.incarnation && a.sequence > b.sequence);
}

static int set_err(char *err, size_t n, const char *what)
{
    if (err && n) snprintf(err, n, "%s", what);
    return -1;
}

static int write_all(int fd, const uint8_t *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int read_at(int fd, uint64_t off, uint8_t *p, size_t n)
{
    while (n) {
        ssize_t r = pread(fd, p, n, (off_t)off);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r;
        n -= (size_t)r;
        off += (uint64_t)r;
    }
    return 0;
}

/* SHA-256 of an entry's tag and length (8 bytes) and body. 0 on success. */
static int entry_hash(const uint8_t head[8], const uint8_t *body, size_t len, uint8_t out[32])
{
    EVP_MD_CTX *h = EVP_MD_CTX_new();
    unsigned int n = 0;
    int ok = h && EVP_DigestInit_ex(h, EVP_sha256(), NULL) && EVP_DigestUpdate(h, head, 8) &&
             (len == 0 || EVP_DigestUpdate(h, body, len)) && EVP_DigestFinal_ex(h, out, &n) && n == 32;
    EVP_MD_CTX_free(h);
    return ok ? 0 : -1;
}

static int add_batch(standin_t *s, gz_batch_id_t id, const gz_record_t *recs, size_t n)
{
    size_t i;
    if (s->nb == s->capb) {
        size_t c = s->capb ? s->capb * 2 : 64;
        sbatch_t *nbp = realloc(s->b, c * sizeof *nbp);
        if (!nbp) return -1;
        s->b = nbp;
        s->capb = c;
    }
    while (s->nr + n > s->capr) {
        size_t c = s->capr ? s->capr * 2 : 256;
        gz_record_t *nrp = realloc(s->r, c * sizeof *nrp);
        if (!nrp) return -1;
        s->r = nrp;
        s->capr = c;
    }
    for (i = 0; i < n; i++) {
        uint8_t *d = NULL;
        if (recs[i].bytes.len) {
            d = malloc(recs[i].bytes.len);
            if (!d) {
                while (i--) free((void *)s->r[s->nr + i].bytes.data);
                return -1;
            }
            memcpy(d, recs[i].bytes.data, recs[i].bytes.len);
        }
        s->r[s->nr + i].type = recs[i].type;
        s->r[s->nr + i].bytes.data = d;
        s->r[s->nr + i].bytes.len = recs[i].bytes.len;
    }
    s->b[s->nb].id = id;
    s->b[s->nb].first = s->nr;
    s->b[s->nb].n = n;
    s->nb++;
    s->nr += n;
    s->last = id;
    s->have_last = 1;
    return 0;
}

/* Parse a BTCH body into the in-memory list. 0, or -1 if malformed. */
static int parse_batch(standin_t *s, const uint8_t *body, uint32_t len, gz_batch_id_t *id_out)
{
    gz_batch_id_t id;
    uint32_t n, i, off = 20;
    gz_record_t *tmp;
    int rc;
    if (len < 20) return -1;
    id.incarnation = rd64(body);
    id.sequence = rd64(body + 8);
    n = rd32(body + 16);
    if (n > len / 8) return -1;
    tmp = calloc(n ? n : 1, sizeof *tmp);
    if (!tmp) return -1;
    for (i = 0; i < n; i++) {
        uint32_t rl;
        if (len - off < 8) { free(tmp); return -1; }
        tmp[i].type = rd32(body + off);
        rl = rd32(body + off + 4);
        off += 8;
        if (rl > len - off) { free(tmp); return -1; }
        tmp[i].bytes.data = rl ? body + off : NULL;
        tmp[i].bytes.len = rl;
        off += rl;
    }
    if (off != len) { free(tmp); return -1; }
    *id_out = id;
    rc = add_batch(s, id, tmp, n);
    free(tmp);
    return rc;
}

static int scan(standin_t *s, char *err, size_t errlen)
{
    uint8_t hdr[HDR_LEN], head[8], digest[32];
    uint64_t off = HDR_LEN, total = 0;
    struct stat st;
    if (fstat(s->fd, &st) != 0) return set_err(err, errlen, "cannot stat the journal");
    s->file_len = (uint64_t)st.st_size;
    if (s->file_len < HDR_LEN) {
        /* New, or torn before its header was complete: start it again. */
        memcpy(hdr, "GZJSTAND", 8);
        be32(hdr + 8, 1);
        be32(hdr + 12, 0);
        if (ftruncate(s->fd, 0) != 0 || pwrite(s->fd, hdr, HDR_LEN, 0) != HDR_LEN || fsync(s->fd) != 0)
            return set_err(err, errlen, "cannot write the journal header");
        s->file_len = HDR_LEN;
        return 0;
    }
    if (read_at(s->fd, 0, hdr, HDR_LEN) != 0 || memcmp(hdr, "GZJSTAND", 8) || rd32(hdr + 8) != 1)
        return set_err(err, errlen, "not a journal stand-in file (or a newer version)");
    while (off < s->file_len) {
        uint32_t tag, len;
        uint8_t *buf;
        int torn = 0;
        if (s->file_len - off < 8) { torn = 1; goto cut; }
        if (read_at(s->fd, off, head, 8) != 0) return set_err(err, errlen, "cannot read the journal");
        tag = rd32(head);
        len = rd32(head + 4);
        if (len > MAX_BODY) {
            if (s->file_len - off < 8 + (uint64_t)len + 32) { torn = 1; goto cut; }
            return set_err(err, errlen, "journal corrupt: entry too large");
        }
        if (s->file_len - off < 8 + (uint64_t)len + 32) { torn = 1; goto cut; }
        total += len;
        if (total > MAX_TOTAL) return set_err(err, errlen, "journal stand-in too large to hold in memory");
        buf = malloc((size_t)len + 32 + 1);
        if (!buf) return set_err(err, errlen, "out of memory");
        if (read_at(s->fd, off + 8, buf, (size_t)len + 32) != 0) { free(buf); return set_err(err, errlen, "cannot read the journal"); }
        if (entry_hash(head, buf, len, digest) != 0) { free(buf); return set_err(err, errlen, "SHA-256 failed"); }
        if (memcmp(digest, buf + len, 32)) {
            free(buf);
            if (off + 8 + len + 32 == s->file_len) { torn = 1; goto cut; }
            return set_err(err, errlen, "journal corrupt: an entry fails its hash and data follows it");
        }
        if (tag == TAG_INCN) {
            uint64_t inc;
            if (len != 8) { free(buf); return set_err(err, errlen, "journal corrupt: bad incarnation entry"); }
            inc = rd64(buf);
            if (inc <= s->max_inc || (s->have_last && inc <= s->last.incarnation)) {
                free(buf);
                return set_err(err, errlen, "journal corrupt: incarnations do not increase");
            }
            s->max_inc = inc;
        } else if (tag == TAG_BTCH) {
            gz_batch_id_t id, prev = s->last;
            int had = s->have_last;
            if (parse_batch(s, buf, len, &id) != 0) { free(buf); return set_err(err, errlen, "journal corrupt: bad batch entry"); }
            if (id.incarnation == 0 || id.sequence == 0 || id.incarnation > s->max_inc || (had && !id_after(id, prev))) {
                free(buf);
                return set_err(err, errlen, "journal corrupt: batch identifiers do not strictly increase");
            }
        } else {
            free(buf);
            return set_err(err, errlen, "journal corrupt: unknown entry");
        }
        free(buf);
        off += 8 + (uint64_t)len + 32;
        continue;
    cut:
        if (torn) {
            s->cut = s->file_len - off;
            if (ftruncate(s->fd, (off_t)off) != 0 || fsync(s->fd) != 0)
                return set_err(err, errlen, "cannot cut the journal's torn tail");
            s->file_len = off;
        }
        break;
    }
    return 0;
}

static int append_entry(standin_t *s, uint32_t tag, const uint8_t *body, size_t len)
{
    uint8_t head[8], digest[32];
    be32(head, tag);
    be32(head + 4, (uint32_t)len);
    if (entry_hash(head, body, len, digest) != 0) return -1;
    if (lseek(s->fd, (off_t)s->file_len, SEEK_SET) < 0) return -1;
    if (write_all(s->fd, head, 8) || write_all(s->fd, body, len) || write_all(s->fd, digest, 32)) return -1;
    if (fdatasync(s->fd) != 0) return -1;
    s->file_len += 8 + len + 32;
    return 0;
}

static int st_begin(void *ctx, uint64_t *incarnation, char *err, size_t errlen)
{
    standin_t *s = ctx;
    uint8_t body[8];
    uint64_t inc = s->max_inc;
    if (s->cur_inc) return set_err(err, errlen, "begin called twice");
    if (s->have_last && s->last.incarnation > inc) inc = s->last.incarnation;
    if (inc == UINT64_MAX) return set_err(err, errlen, "incarnations exhausted");
    inc++;
    be64(body, inc);
    if (append_entry(s, TAG_INCN, body, 8) != 0) return set_err(err, errlen, "cannot store the new incarnation");
    s->max_inc = s->cur_inc = inc;
    s->first_new = s->reported = s->nb;
    *incarnation = inc;
    return 0;
}

static int st_next(void *ctx, gzp_batch_t *out)
{
    standin_t *s = ctx;
    if (s->cursor >= s->nb) return 0;
    out->id = s->b[s->cursor].id;
    out->records = s->r + s->b[s->cursor].first;
    out->n_records = s->b[s->cursor].n;
    s->cursor++;
    return 1;
}

static void st_rewind(void *ctx)
{
    ((standin_t *)ctx)->cursor = 0;
}

static int st_append(void *ctx, gz_batch_id_t id, const gz_record_t *records, size_t n)
{
    standin_t *s = ctx;
    uint8_t *body, *p;
    size_t len = 20, i;
    int rc;
    if (s->failed || !s->cur_inc || id.incarnation != s->cur_inc || (s->have_last && !id_after(id, s->last)))
        return s->failed = 1, -1;
    if (s->fail_at && --s->fail_at == 0) return s->failed = 1, -1;
    for (i = 0; i < n; i++) {
        if (records[i].bytes.len > MAX_BODY) return s->failed = 1, -1;
        len += 8 + records[i].bytes.len;
        if (len > MAX_BODY) return s->failed = 1, -1;
    }
    body = malloc(len);
    if (!body) return s->failed = 1, -1;
    be64(body, id.incarnation);
    be64(body + 8, id.sequence);
    be32(body + 16, (uint32_t)n);
    p = body + 20;
    for (i = 0; i < n; i++) {
        be32(p, records[i].type);
        be32(p + 4, (uint32_t)records[i].bytes.len);
        if (records[i].bytes.len) memcpy(p + 8, records[i].bytes.data, records[i].bytes.len);
        p += 8 + records[i].bytes.len;
    }
    rc = append_entry(s, TAG_BTCH, body, len);
    free(body);
    if (rc != 0 || add_batch(s, id, records, n) != 0) return s->failed = 1, -1;
    return 0;
}

static int st_complete(void *ctx, gz_batch_id_t *id)
{
    standin_t *s = ctx;
    if (s->reported >= s->nb) return 0;
    *id = s->b[s->reported++].id;
    return 1;
}

static int st_restored(void *ctx)
{
    (void)ctx;
    return 0;
}

static void st_close(void *ctx)
{
    standin_t *s = ctx;
    size_t i;
    if (!s) return;
    for (i = 0; i < s->nr; i++) free((void *)s->r[i].bytes.data);
    free(s->r);
    free(s->b);
    if (s->fd >= 0) close(s->fd);
    free(s);
}

static const gzp_store_ops_t STANDIN_OPS = {
    st_begin, st_next, st_rewind, st_append, st_complete, st_restored, st_close
};

int gzp_standin_open(gzp_store_t *out, const char *path, char *err, size_t errlen)
{
    standin_t *s = calloc(1, sizeof *s);
    if (!s) return set_err(err, errlen, "out of memory");
    s->fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (s->fd < 0) {
        free(s);
        return set_err(err, errlen, "cannot open the journal");
    }
    if (scan(s, err, errlen) != 0) {
        st_close(s);
        return -1;
    }
    out->ops = &STANDIN_OPS;
    out->ctx = s;
    return 0;
}

void gzp_standin_fail_at(gzp_store_t *st, unsigned k)
{
    ((standin_t *)st->ctx)->fail_at = k;
}

uint64_t gzp_standin_cut_bytes(const gzp_store_t *st)
{
    return ((const standin_t *)st->ctx)->cut;
}
