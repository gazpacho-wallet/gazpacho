/* The storage journal. See journal.h and spec/journal.md (draft 2). */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "journal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "superscalar/sha256.h"

const uint8_t gz_journal_chain_signet[32] = {
    0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9,
    0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00};
const uint8_t gz_journal_chain_mainnet[32] = {
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t MAGIC[8] = {'G', 'Z', 'J', 'O', 'U', 'R', 'N', 'L'};
static const uint8_t GUARD_MAGIC[8] = {'G', 'Z', 'G', 'U', 'A', 'R', 'D', '1'};

const char *gz_journal_status_name(gz_journal_status_t s)
{
    static const char *const names[] = {
        "ok", "argument", "io", "locked", "header", "network", "corrupt", "order",
        "unknown_record", "full", "too_large", "sequence", "guard", "no_memory", "failed", "marker"};
    return (unsigned)s < sizeof names / sizeof names[0] ? names[s] : "?";
}

/* --- bytes ---------------------------------------------------------------- */

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p) << 32 | get32(p + 4); }
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)(v >> 32)); put32(p + 4, (uint32_t)v); }

/* --- the entry codec ------------------------------------------------------
 * Everything that knows how the header and an entry are framed and protected
 * is in this section, and nothing outside it reads or writes a frame's own
 * bytes: the scan, the writer and the reader call frame_seal, frame_open,
 * frame_mark_candidate, header_seal and header_open. This is draft 2's format
 * (spec/journal.md 2.1 and 3): a clear payload and an 8-byte truncated
 * SHA-256 check. The encrypted format of spec/storage-encryption.md (5.3,
 * 5.4) is meant to replace this section alone; the crash logic around it
 * (scan, torn tail, sync marks, confirmation order) does not change.
 *
 * `offset` is the file offset at which the frame starts. This format does not
 * use it (a sync mark carries its own offset in its payload, checked outside
 * the codec); the encrypted format binds every entry to it. */

#define FRAME_HEAD 21u    /* length, kind, incarnation, sequence */
#define FRAME_TAIL 8u     /* check */
#define SMALL_PAYLOAD 8u  /* incarnation entry and sync mark */
#define SMALL_LENGTH (FRAME_HEAD - 4 + SMALL_PAYLOAD) /* their `length`: 25 */

static void check8(const uint8_t *data, size_t len, uint8_t out[8])
{
    uint8_t h[32];
    sha256(data, len, h);
    memcpy(out, h, 8);
}
static int check8_ok(const uint8_t *data, size_t len, const uint8_t *check)
{
    uint8_t c[8];
    check8(data, len, c);
    return memcmp(c, check, 8) == 0;
}

/* Where the caller writes the payload before frame_seal. */
static uint8_t *frame_payload(uint8_t *out) { return out + FRAME_HEAD; }

/* Complete the frame whose payload is already at frame_payload(out); returns
 * its size in the file. */
static size_t frame_seal(uint8_t *out, uint8_t kind, uint64_t incarnation, uint64_t sequence,
                         size_t payload_len, uint64_t offset)
{
    (void)offset;
    put32(out, (uint32_t)(FRAME_HEAD - 4 + payload_len));
    out[4] = kind;
    put64(out + 5, incarnation);
    put64(out + 13, sequence);
    check8(out, FRAME_HEAD + payload_len, out + FRAME_HEAD + payload_len);
    return FRAME_HEAD + payload_len + FRAME_TAIL;
}

typedef struct {
    uint8_t kind;
    uint64_t incarnation, sequence, value;
    const uint8_t *payload;
    size_t payload_len;
    uint64_t size;   /* bytes in the file */
} entry_t;

/* 1 if `q[0..avail)`, at file offset `offset`, starts with an intact frame:
 * length in bounds and right for its kind, enough bytes, known kind, check
 * correct. Fills `*e`, the payload pointing into `q`. `e->size` is set as
 * soon as the length is known, even when the frame then proves invalid. */
static int frame_open(const uint8_t *q, uint64_t avail, uint64_t offset, entry_t *e)
{
    (void)offset;
    if (avail < 4) return 0;
    uint32_t length = get32(q);
    if (length < GZ_JOURNAL_ENTRY_MIN || length > GZ_JOURNAL_ENTRY_MAX) return 0;
    if (avail - 4 < (uint64_t)length + FRAME_TAIL) return 0;
    e->size = 4 + (uint64_t)length + FRAME_TAIL;
    e->kind = q[4];
    if (e->kind < GZ_JOURNAL_KIND_INCARNATION || e->kind > GZ_JOURNAL_KIND_MARK) return 0;
    if (e->kind != GZ_JOURNAL_KIND_BATCH && length != SMALL_LENGTH) return 0;
    if (!check8_ok(q, 4 + (size_t)length, q + 4 + length)) return 0;
    e->incarnation = get64(q + 5);
    e->sequence = get64(q + 13);
    e->payload = q + FRAME_HEAD;
    e->payload_len = length - (FRAME_HEAD - 4);
    return 1;
}

/* A cheap test before frame_open when searching for a sync mark: 1 if a
 * mark-sized frame of kind 3 could start at `q`. */
static int frame_mark_candidate(const uint8_t *q, uint64_t avail)
{
    return avail >= GZ_JOURNAL_MARK_LEN && get32(q) == SMALL_LENGTH && q[4] == GZ_JOURNAL_KIND_MARK;
}

static size_t header_seal(uint8_t out[48], const uint8_t chain[32])
{
    memcpy(out, MAGIC, 8);
    memcpy(out + 8, chain, 32);
    check8(out, 40, out + 40);
    return GZ_JOURNAL_HEADER_LEN;
}

/* GZ_JOURNAL_OK, ERR_HEADER (short, magic, check) or ERR_NETWORK. */
static gz_journal_status_t header_open(const uint8_t *d, size_t len, const uint8_t chain[32])
{
    if (len < GZ_JOURNAL_HEADER_LEN || memcmp(d, MAGIC, 8) != 0 || !check8_ok(d, 40, d + 40))
        return GZ_JOURNAL_ERR_HEADER;
    if (memcmp(d + 8, chain, 32) != 0) return GZ_JOURNAL_ERR_NETWORK;
    return GZ_JOURNAL_OK;
}

/* --- encoders, on top of the codec ---------------------------------------- */

static size_t encode_small_at(uint8_t *out, uint8_t kind, uint64_t incarnation, uint64_t value,
                              uint64_t offset)
{
    put64(frame_payload(out), value);
    return frame_seal(out, kind, incarnation, 0, SMALL_PAYLOAD, offset);
}

static size_t encode_batch_at(uint8_t *out, gz_batch_id_t id, const gz_record_t *records, size_t n,
                              uint64_t offset)
{
    uint8_t *pl = frame_payload(out);
    size_t p = 4;
    put32(pl, (uint32_t)n);
    for (size_t i = 0; i < n; i++) {
        put32(pl + p, records[i].type);
        put32(pl + p + 4, (uint32_t)records[i].bytes.len);
        p += 8;
        if (records[i].bytes.len) memcpy(pl + p, records[i].bytes.data, records[i].bytes.len);
        p += records[i].bytes.len;
    }
    return frame_seal(out, GZ_JOURNAL_KIND_BATCH, id.incarnation, id.sequence, p, offset);
}

/* The public encoders do not know where their output will sit in a file (a
 * mark's offset is its value); the encrypted format will need an offset
 * argument here. The writer uses the *_at forms with the real offset. */
size_t gz_journal_encode_header(uint8_t out[48], const uint8_t chain[32])
{
    return header_seal(out, chain);
}

size_t gz_journal_encode_small(uint8_t out[37], uint8_t kind, uint64_t incarnation, uint64_t value)
{
    return encode_small_at(out, kind, incarnation, value, kind == GZ_JOURNAL_KIND_MARK ? value : 0);
}

uint64_t gz_journal_batch_size(const gz_record_t *records, size_t n)
{
    uint64_t payload = 4;
    for (size_t i = 0; i < n; i++) {
        if (records[i].bytes.len > GZ_JOURNAL_ENTRY_MAX) return 0;
        payload += 8 + (uint64_t)records[i].bytes.len;
        if (FRAME_HEAD - 4 + payload > GZ_JOURNAL_ENTRY_MAX) return 0;
    }
    return FRAME_HEAD + payload + FRAME_TAIL;
}

size_t gz_journal_encode_batch(uint8_t *out, gz_batch_id_t id, const gz_record_t *records, size_t n)
{
    return encode_batch_at(out, id, records, n, 0);
}

/* --- reading -------------------------------------------------------------- */

int gz_journal_type_known(uint32_t type)
{
    static const uint32_t known[] = {
        0x00040002, 0x00040004, 0x00040006, 0x0004000a,
        0x00010002, 0x00010004, 0x00010006, 0x00010008, 0x0001000a, 0x0001000c, 0x0001000e,
        0x00010010, 0x00010012, 0x00010014, 0x00010016,
        0x00020002, 0x00020004, 0x00020006, 0x00020008, 0x0002000a, 0x0002000c, 0x0002000e,
        0x00030002, 0x00030004, 0x00030006};
    if ((type >> 16) == 0x7e57) return 1; /* the placeholder's test types (node.h) */
    for (size_t i = 0; i < sizeof known / sizeof known[0]; i++)
        if (known[i] == type) return 1;
    return 0;
}

long gz_journal_parse_batch(const uint8_t *payload, size_t len, gz_record_t *records, size_t cap,
                            size_t *kept)
{
    size_t k = 0;
    if (len < 4) return -1;
    uint32_t n = get32(payload);
    size_t p = 4;
    for (uint32_t i = 0; i < n; i++) {
        if (len - p < 8) return -1;
        uint32_t type = get32(payload + p), rlen = get32(payload + p + 4);
        p += 8;
        if (len - p < rlen) return -1;
        if (records && (gz_journal_type_known(type) || !(type & 1))) {
            if (k < cap) {
                records[k].type = type;
                records[k].bytes.data = rlen ? payload + p : NULL;
                records[k].bytes.len = rlen;
            }
            k++;
        }
        p += rlen;
    }
    if (p != len) return -1;
    if (kept) *kept = k;
    return (long)n;
}

/* 1 if `q[0..avail)` starts with a valid entry, found at file offset `pos`
 * (spec section 5, step 3): an intact frame whose payload is right for its
 * kind. */
static int entry_at(const uint8_t *q, uint64_t avail, uint64_t pos, entry_t *e)
{
    if (!frame_open(q, avail, pos, e)) return 0;
    e->value = e->kind == GZ_JOURNAL_KIND_BATCH ? 0 : get64(e->payload);
    if (e->kind == GZ_JOURNAL_KIND_MARK && e->value != pos) return 0;
    if (e->kind == GZ_JOURNAL_KIND_BATCH &&
        gz_journal_parse_batch(e->payload, e->payload_len, NULL, 0, NULL) < 0)
        return 0;
    return 1;
}

static int mark_at(const uint8_t *d, uint64_t len, uint64_t p)
{
    entry_t e;
    if (!frame_mark_candidate(d + p, len - p)) return 0;
    return entry_at(d + p, len - p, p, &e);
}

static gz_journal_status_t refuse(gz_journal_scan_t *o, gz_journal_status_t s, uint64_t at)
{
    o->verdict = GZ_JOURNAL_REFUSED;
    o->status = s;
    o->error_at = at;
    return s;
}

gz_journal_status_t gz_journal_scan(const uint8_t *d, size_t len, const uint8_t chain[32],
                                    gz_journal_scan_t *o, gz_journal_batch_fn on_batch, void *ctx)
{
    memset(o, 0, sizeof *o);
    o->file_end = len;
    gz_journal_status_t hs = header_open(d, len, chain);
    if (hs != GZ_JOURNAL_OK) return refuse(o, hs, 0);

    uint64_t p = GZ_JOURNAL_HEADER_LEN, inc = 0, seq = 0;
    int bad_type = 0;
    entry_t e;
    while (p < len && entry_at(d + p, len - p, p, &e)) {
        /* Order rules, spec section 3.4. */
        if (e.kind == GZ_JOURNAL_KIND_INCARNATION) {
            if (e.incarnation <= inc || e.sequence != 0) return refuse(o, GZ_JOURNAL_ERR_ORDER, p);
            inc = e.incarnation;
            seq = 0;
            o->n_incarnations++;
        } else {
            if (inc == 0 || e.incarnation != inc) return refuse(o, GZ_JOURNAL_ERR_ORDER, p);
            if (e.kind == GZ_JOURNAL_KIND_MARK) {
                if (e.sequence != 0) return refuse(o, GZ_JOURNAL_ERR_ORDER, p);
                o->n_marks++;
            } else {
                if (e.sequence != seq + 1) return refuse(o, GZ_JOURNAL_ERR_ORDER, p);
                seq = e.sequence;
                o->n_batches++;
                uint32_t n = get32(e.payload);
                size_t q = 4;
                for (uint32_t i = 0; i < n; i++) {
                    uint32_t type = get32(e.payload + q);
                    if (!bad_type && !(type & 1) && !gz_journal_type_known(type)) {
                        bad_type = 1;
                        o->bad_type = type;
                        o->error_at = p;
                    }
                    q += 8 + get32(e.payload + q + 4);
                }
                o->n_records += n;
                if (on_batch) {
                    gz_batch_id_t id = {e.incarnation, e.sequence};
                    on_batch(ctx, p, (uint32_t)e.size, id, e.payload, e.payload_len);
                }
            }
        }
        p += e.size;
    }
    o->valid_end = p;
    o->highest_incarnation = inc;
    if (p < len) {
        for (uint64_t m = p + 1; m + GZ_JOURNAL_MARK_LEN <= len; m++) {
            if (mark_at(d, len, m)) {
                o->mark_at = m;
                return refuse(o, GZ_JOURNAL_ERR_CORRUPT, p);
            }
        }
        o->verdict = GZ_JOURNAL_TORN;
    }
    if (bad_type) {
        uint64_t at = o->error_at;
        return refuse(o, GZ_JOURNAL_ERR_UNKNOWN_RECORD, at);
    }
    return GZ_JOURNAL_OK;
}

/* --- the POSIX table ------------------------------------------------------ */

static int px_open(void *ctx, const char *path, int how)
{
    (void)ctx;
    int flags = how == GZ_JOURNAL_OPEN_READ          ? O_RDONLY
                : how == GZ_JOURNAL_OPEN_RW          ? O_RDWR
                : how == GZ_JOURNAL_OPEN_CREATE_EXCL ? O_RDWR | O_CREAT | O_EXCL
                                                     : O_RDWR | O_CREAT | O_TRUNC;
    int fd = open(path, flags | O_CLOEXEC, 0600);
    if (fd >= 0 && (flags & O_CREAT) && fchmod(fd, 0600) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}
static int px_close(void *ctx, int fd) { (void)ctx; return close(fd); }
static long px_pread(void *ctx, int fd, void *buf, size_t len, uint64_t off)
{
    (void)ctx;
    return (long)pread(fd, buf, len, (off_t)off);
}
static long px_pwrite(void *ctx, int fd, const void *buf, size_t len, uint64_t off)
{
    (void)ctx;
    return (long)pwrite(fd, buf, len, (off_t)off);
}
static int px_sync(void *ctx, int fd)
{
    (void)ctx;
#ifdef F_FULLFSYNC
    return fcntl(fd, F_FULLFSYNC);
#else
    return fsync(fd);
#endif
}
static int px_sync_dir(void *ctx, const char *dir)
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    int r = px_sync(ctx, fd);
    int saved = errno;
    close(fd);
    errno = saved;
    return r;
}
static int px_truncate(void *ctx, int fd, uint64_t len) { (void)ctx; return ftruncate(fd, (off_t)len); }
static int px_size(void *ctx, int fd, uint64_t *out)
{
    struct stat st;
    (void)ctx;
    if (fstat(fd, &st) != 0) return -1;
    *out = (uint64_t)st.st_size;
    return 0;
}
static int px_lock(void *ctx, int fd) { (void)ctx; return flock(fd, LOCK_EX | LOCK_NB); }
static int px_link(void *ctx, const char *a, const char *b) { (void)ctx; return link(a, b); }
static int px_rename(void *ctx, const char *a, const char *b) { (void)ctx; return rename(a, b); }
static int px_unlink(void *ctx, const char *p) { (void)ctx; return unlink(p); }

static const gz_journal_os_t POSIX_OS = {px_open, px_close, px_pread, px_pwrite, px_sync,
                                         px_sync_dir, px_truncate, px_size, px_lock, px_link,
                                         px_rename, px_unlink, NULL};

const gz_journal_os_t *gz_journal_os_posix(void) { return &POSIX_OS; }

/* --- the writer ----------------------------------------------------------- */

typedef struct {
    gz_batch_id_t id;
    uint64_t offset;
    uint32_t size;
} pending_t;

struct gz_journal {
    gz_journal_os_t os;
    char *dir, *path, *tmp_path, *guard_path, *guard_tmp;
    int fd;
    uint8_t chain[32];
    uint64_t soft_limit, hard_limit, unsynced_max;
    uint64_t end;          /* bytes written */
    uint64_t durable_end;  /* bytes covered by the last synced sync mark */
    uint64_t incarnation, last_sequence;
    int failed;
    /* Durable batch entries, oldest first, for the reader. */
    uint64_t *idx_off;
    uint32_t *idx_size;
    size_t n_idx, cap_idx;
    /* Appended, not yet confirmed, oldest first; the first n_durable are durable. */
    pending_t pend[GZ_RUNNER_MAX_UNCONFIRMED];
    size_t n_pend, n_durable;
    /* The newest guard record handed over and not yet written to the guard file. */
    uint8_t *guard;
    size_t guard_len;
    int guard_due;
    gz_runner_t *runner;
    gz_journal_confirmed_fn on_confirmed;
    void *confirmed_ctx;
    /* Pull mode (config.pull): durable batches waiting for gz_journal_complete. */
    int pull;
    gz_batch_id_t comp[GZ_RUNNER_MAX_UNCONFIRMED];
    size_t comp_head, n_comp;
    /* The restore marker: 1 while restore.gzr says a restore is unanswered. */
    int restored;
    char *marker_path;
    /* Reader state. */
    size_t cursor;
    uint8_t *rbuf;
    size_t rbuf_cap;
    gz_record_t *recs;
    size_t recs_cap;
};

static char *join(const char *dir, const char *name)
{
    size_t a = strlen(dir), b = strlen(name);
    char *s = malloc(a + b + 2);
    if (!s) return NULL;
    memcpy(s, dir, a);
    s[a] = '/';
    memcpy(s + a + 1, name, b + 1);
    return s;
}

static void free_journal(gz_journal_t *j)
{
    if (!j) return;
    free(j->dir); free(j->path); free(j->tmp_path); free(j->guard_path); free(j->guard_tmp);
    free(j->marker_path);
    free(j->idx_off); free(j->idx_size); free(j->guard); free(j->rbuf); free(j->recs);
    free(j);
}

static gz_journal_status_t fail(gz_journal_t *j, gz_journal_status_t s)
{
    j->failed = 1;
    if (j->runner) gz_runner_storage_failed(j->runner);
    return s;
}

static int os_write_all(const gz_journal_os_t *os, int fd, const uint8_t *buf, size_t len, uint64_t off)
{
    long r = os->pwrite(os->ctx, fd, buf, len, off);
    return r >= 0 && (size_t)r == len; /* a short write is a failure, never retried */
}

static int write_all(gz_journal_t *j, int fd, const uint8_t *buf, size_t len, uint64_t off)
{
    return os_write_all(&j->os, fd, buf, len, off);
}

/* Replace `path` with a[0..alen) then b[0..blen): write `tmp`, sync it,
 * rename it over `path`, sync the folder. 1 on success. */
static int replace_file(const gz_journal_os_t *os, const char *dir, const char *tmp, const char *path,
                        const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    int fd = os->open(os->ctx, tmp, GZ_JOURNAL_OPEN_CREATE_TRUNC);
    if (fd < 0) return 0;
    int ok = os_write_all(os, fd, a, alen, 0) && os_write_all(os, fd, b, blen, alen) &&
             os->sync(os->ctx, fd) == 0;
    ok = os->close(os->ctx, fd) == 0 && ok;
    ok = ok && os->rename(os->ctx, tmp, path) == 0;
    ok = ok && os->sync_dir(os->ctx, dir) == 0;
    return ok;
}

/* Read a whole file into buf[0..cap). 1 with *len its size, 0 absent, -1 an
 * error. A file larger than `cap` is not read: 1, with *len its size (so a
 * length check refuses it). */
static int read_small(const gz_journal_os_t *os, const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    int fd = os->open(os->ctx, path, GZ_JOURNAL_OPEN_READ);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    uint64_t size;
    int ok = os->size(os->ctx, fd, &size) == 0;
    if (ok && size > cap) {
        os->close(os->ctx, fd);
        *len = size > SIZE_MAX ? SIZE_MAX : (size_t)size;
        return 1;
    }
    for (uint64_t got = 0; ok && got < size;) {
        long r = os->pread(os->ctx, fd, buf + got, (size_t)(size - got), got);
        if (r <= 0) ok = 0;
        else got += (uint64_t)r;
    }
    os->close(os->ctx, fd);
    if (!ok) return -1;
    *len = (size_t)size;
    return 1;
}

/* Read exactly `len` bytes at `off`; a read may return fewer, so loop. 0 on
 * an error or an end of file before `len`. */
static int read_all(gz_journal_t *j, uint8_t *buf, uint64_t len, uint64_t off)
{
    for (uint64_t got = 0; got < len;) {
        long r = j->os.pread(j->os.ctx, j->fd, buf + got, (size_t)(len - got), off + got);
        if (r <= 0) return 0;
        got += (uint64_t)r;
    }
    return 1;
}

static int index_add(gz_journal_t *j, uint64_t off, uint32_t size)
{
    if (j->n_idx == j->cap_idx) {
        size_t cap = j->cap_idx ? 2 * j->cap_idx : 64;
        uint64_t *o = realloc(j->idx_off, cap * sizeof *o);
        if (!o) return 0;
        j->idx_off = o;
        uint32_t *s = realloc(j->idx_size, cap * sizeof *s);
        if (!s) return 0;
        j->idx_size = s;
        j->cap_idx = cap;
    }
    j->idx_off[j->n_idx] = off;
    j->idx_size[j->n_idx] = size;
    j->n_idx++;
    return 1;
}

/* --- the restore marker (ports.h; journal.md 8.2) --------------------------
 * restore.gzr, beside the journal. gz_journal_mark_restored writes it once a
 * backup has been imported as journal.gzj; it is removed once the restored
 * node's answer, the batch with sequence 1 of an incarnation started after
 * the import, is durable, and before that batch is confirmed. Contents:
 *   magic "GZRESTO1" (8), chain (32),
 *   base  (u64): the highest incarnation in the imported journal; any higher
 *                one was started after the import,
 *   floor (u64): the highest incarnation the replaced journal had used, so
 *                that a restored start never repeats one (runner.h),
 *   check (8):   the first 8 bytes of SHA-256 over the 56 bytes before it. */
#define MARKER_LEN 64u
static const uint8_t MARKER_MAGIC[8] = {'G', 'Z', 'R', 'E', 'S', 'T', 'O', '1'};

static void marker_encode(uint8_t out[MARKER_LEN], const uint8_t chain[32], uint64_t base, uint64_t floor)
{
    memcpy(out, MARKER_MAGIC, 8);
    memcpy(out + 8, chain, 32);
    put64(out + 40, base);
    put64(out + 48, floor);
    check8(out, 56, out + 56);
}

static int marker_decode(const uint8_t *d, size_t len, const uint8_t chain[32], uint64_t *base,
                         uint64_t *floor)
{
    if (len != MARKER_LEN || memcmp(d, MARKER_MAGIC, 8) != 0 || memcmp(d + 8, chain, 32) != 0 ||
        !check8_ok(d, 56, d + 56))
        return 0;
    *base = get64(d + 40);
    *floor = get64(d + 48);
    return 1;
}

static int clear_marker(gz_journal_t *j);

typedef struct {
    gz_journal_t *j;
    int oom;
    int marker;          /* a marker was found; `base` is valid */
    uint64_t base;
    int answered;        /* a kept batch has sequence 1 under an incarnation above `base` */
} collect_t;

static void collect(void *ctx, uint64_t off, uint32_t size, gz_batch_id_t id, const uint8_t *payload,
                    size_t len)
{
    collect_t *c = ctx;
    (void)payload; (void)len;
    if (c->marker && id.incarnation > c->base && id.sequence == 1) c->answered = 1;
    if (!index_add(c->j, off, size)) c->oom = 1;
}

/* Sync, append a sync mark, sync again (spec section 4, steps 2 and 3). */
static int make_durable(gz_journal_t *j)
{
    uint8_t mark[GZ_JOURNAL_MARK_LEN];
    if (j->os.sync(j->os.ctx, j->fd) != 0) return 0;
    encode_small_at(mark, GZ_JOURNAL_KIND_MARK, j->incarnation, j->end, j->end);
    if (!write_all(j, j->fd, mark, sizeof mark, j->end)) return 0;
    j->end += sizeof mark;
    if (j->os.sync(j->os.ctx, j->fd) != 0) return 0;
    j->durable_end = j->end;
    return 1;
}

static gz_journal_status_t create_file(gz_journal_t *j)
{
    uint8_t hdr[GZ_JOURNAL_HEADER_LEN];
    int fd = j->os.open(j->os.ctx, j->tmp_path, GZ_JOURNAL_OPEN_CREATE_EXCL);
    if (fd < 0 && errno == EEXIST) { /* left by a creation that crashed */
        if (j->os.unlink(j->os.ctx, j->tmp_path) != 0) return GZ_JOURNAL_ERR_IO;
        fd = j->os.open(j->os.ctx, j->tmp_path, GZ_JOURNAL_OPEN_CREATE_EXCL);
    }
    if (fd < 0) return GZ_JOURNAL_ERR_IO;
    header_seal(hdr, j->chain);
    int ok = write_all(j, fd, hdr, sizeof hdr, 0) && j->os.sync(j->os.ctx, fd) == 0;
    ok = j->os.close(j->os.ctx, fd) == 0 && ok;
    /* link, not rename: it never replaces a journal another process created meanwhile. */
    if (ok && j->os.link(j->os.ctx, j->tmp_path, j->path) != 0 && errno != EEXIST) ok = 0;
    if (j->os.unlink(j->os.ctx, j->tmp_path) != 0) ok = 0;
    if (ok && j->os.sync_dir(j->os.ctx, j->dir) != 0) ok = 0;
    return ok ? GZ_JOURNAL_OK : GZ_JOURNAL_ERR_IO;
}

gz_journal_status_t gz_journal_open(gz_journal_t **out, const gz_journal_config_t *cfg,
                                    gz_journal_open_info_t *info)
{
    gz_journal_open_info_t scratch;
    gz_journal_status_t st = GZ_JOURNAL_OK;
    uint8_t *data = NULL;
    if (!info) info = &scratch;
    memset(info, 0, sizeof *info);
    if (!out) return GZ_JOURNAL_ERR_ARGUMENT;
    *out = NULL;
    if (!cfg || !cfg->dir || !cfg->chain) return GZ_JOURNAL_ERR_ARGUMENT;

    gz_journal_t *j = calloc(1, sizeof *j);
    if (!j) return GZ_JOURNAL_ERR_NO_MEMORY;
    j->fd = -1;
    j->os = cfg->os ? *cfg->os : POSIX_OS;
    memcpy(j->chain, cfg->chain, 32);
    j->soft_limit = cfg->soft_limit ? cfg->soft_limit : GZ_JOURNAL_SOFT_LIMIT;
    j->hard_limit = cfg->hard_limit ? cfg->hard_limit : GZ_JOURNAL_HARD_LIMIT;
    j->unsynced_max = cfg->unsynced_max ? cfg->unsynced_max : GZ_JOURNAL_UNSYNCED_MAX;
    j->dir = join(cfg->dir, "");
    j->path = join(cfg->dir, GZ_JOURNAL_FILE);
    j->tmp_path = join(cfg->dir, GZ_JOURNAL_FILE ".tmp");
    j->guard_path = join(cfg->dir, GZ_JOURNAL_GUARD_FILE);
    j->guard_tmp = join(cfg->dir, GZ_JOURNAL_GUARD_FILE ".tmp");
    j->marker_path = join(cfg->dir, GZ_JOURNAL_MARKER_FILE);
    j->pull = cfg->pull;
    if (!j->dir || !j->path || !j->tmp_path || !j->guard_path || !j->guard_tmp || !j->marker_path) {
        st = GZ_JOURNAL_ERR_NO_MEMORY;
        goto out;
    }
    j->dir[strlen(cfg->dir)] = '\0';

    /* 1. Open or create, and lock. */
    j->fd = j->os.open(j->os.ctx, j->path, GZ_JOURNAL_OPEN_RW);
    if (j->fd < 0 && errno == ENOENT) {
        st = create_file(j);
        if (st != GZ_JOURNAL_OK) goto out;
        info->created = 1;
        j->fd = j->os.open(j->os.ctx, j->path, GZ_JOURNAL_OPEN_RW);
    }
    if (j->fd < 0) { st = GZ_JOURNAL_ERR_IO; goto out; }
    if (j->os.lock(j->os.ctx, j->fd) != 0) {
        st = (errno == EWOULDBLOCK || errno == EAGAIN) ? GZ_JOURNAL_ERR_LOCKED : GZ_JOURNAL_ERR_IO;
        goto out;
    }

    /* 2 to 4. Read, check the header, scan, judge the tail. */
    uint64_t size;
    if (j->os.size(j->os.ctx, j->fd, &size) != 0) { st = GZ_JOURNAL_ERR_IO; goto out; }
    /* The writer never passes the hard limit, so a larger file is not read. */
    if (size > j->hard_limit) { st = GZ_JOURNAL_ERR_FULL; goto out; }
    data = malloc(size ? (size_t)size : 1);
    if (!data) { st = GZ_JOURNAL_ERR_NO_MEMORY; goto out; }
    if (!read_all(j, data, size, 0)) { st = GZ_JOURNAL_ERR_IO; goto out; }
    collect_t c = {j, 0, 0, 0, 0};
    uint64_t floor = 0;
    uint8_t mk[MARKER_LEN + 16]; /* room to see a marker that is too long */
    size_t mk_len = 0;
    int mr = read_small(&j->os, j->marker_path, mk, sizeof mk, &mk_len);
    if (mr < 0) { st = GZ_JOURNAL_ERR_IO; goto out; }
    if (mr > 0) {
        if (!marker_decode(mk, mk_len, j->chain, &c.base, &floor)) { st = GZ_JOURNAL_ERR_MARKER; goto out; }
        c.marker = 1;
    }
    st = gz_journal_scan(data, (size_t)size, j->chain, &info->scan, collect, &c);
    if (st != GZ_JOURNAL_OK) goto out;
    if (c.oom) { st = GZ_JOURNAL_ERR_NO_MEMORY; goto out; }
    if (info->scan.verdict == GZ_JOURNAL_TORN) {
        if (j->os.truncate(j->os.ctx, j->fd, info->scan.valid_end) != 0 ||
            j->os.sync(j->os.ctx, j->fd) != 0) {
            st = GZ_JOURNAL_ERR_IO;
            goto out;
        }
        info->cut_bytes = size - info->scan.valid_end;
    }
    j->end = info->scan.valid_end;

    /* The restore marker: answered if the cut journal holds the answer (a
     * crash came between it becoming durable and the marker's removal). */
    if (c.marker && c.answered && !clear_marker(j)) { st = GZ_JOURNAL_ERR_IO; goto out; }
    j->restored = c.marker && !c.answered;
    uint64_t highest = info->scan.highest_incarnation;
    if (j->restored && floor > highest) highest = floor;

    /* 5. A new incarnation, durable before the runner exists. */
    if (highest == UINT64_MAX || j->end + 2 * GZ_JOURNAL_MARK_LEN > j->hard_limit) {
        st = GZ_JOURNAL_ERR_FULL;
        goto out;
    }
    j->incarnation = highest + 1;
    uint8_t ent[GZ_JOURNAL_MARK_LEN];
    encode_small_at(ent, GZ_JOURNAL_KIND_INCARNATION, j->incarnation, cfg->clock_ms, j->end);
    if (!write_all(j, j->fd, ent, sizeof ent, j->end)) { st = GZ_JOURNAL_ERR_IO; goto out; }
    j->end += sizeof ent;
    if (!make_durable(j)) { st = GZ_JOURNAL_ERR_IO; goto out; }
    info->incarnation = j->incarnation;
    info->soft_full = j->end >= j->soft_limit;
    info->restored = j->restored;

out:
    free(data);
    if (st != GZ_JOURNAL_OK) {
        if (j->fd >= 0) j->os.close(j->os.ctx, j->fd);
        free_journal(j);
        return st;
    }
    *out = j;
    return GZ_JOURNAL_OK;
}

void gz_journal_attach(gz_journal_t *j, gz_runner_t *runner, gz_journal_confirmed_fn fn, void *ctx)
{
    j->runner = runner;
    j->on_confirmed = fn;
    j->confirmed_ctx = ctx;
}

uint64_t gz_journal_incarnation(const gz_journal_t *j) { return j->incarnation; }
size_t gz_journal_pending(const gz_journal_t *j) { return j->n_pend; }
int gz_journal_failed(const gz_journal_t *j) { return j->failed; }
int gz_journal_soft_full(const gz_journal_t *j) { return j->end >= j->soft_limit; }
uint64_t gz_journal_size(const gz_journal_t *j) { return j->end; }

/* A guard record holds the guard file's contents without the check (spec 8.3). */
static int guard_valid(const gz_journal_t *j, const gz_record_t *r)
{
    const uint8_t *b = r->bytes.data;
    size_t len = r->bytes.len;
    if (len < GZ_GUARD_MIN_LEN || memcmp(b, GUARD_MAGIC, 8) != 0 || memcmp(b + 8, j->chain, 32) != 0)
        return 0;
    uint16_t n = (uint16_t)(b[48] << 8 | b[49]);
    return len == GZ_GUARD_MIN_LEN + 8 * (size_t)n;
}

/* Replace the guard file: temporary name, sync, rename, sync the folder. */
static int write_guard(gz_journal_t *j)
{
    uint8_t check[8];
    check8(j->guard, j->guard_len, check);
    return replace_file(&j->os, j->dir, j->guard_tmp, j->guard_path, j->guard, j->guard_len, check, 8);
}

/* The restore is answered: the marker goes, durably. 1 on success. */
static int clear_marker(gz_journal_t *j)
{
    if (j->os.unlink(j->os.ctx, j->marker_path) != 0 && errno != ENOENT) return 0;
    if (j->os.sync_dir(j->os.ctx, j->dir) != 0) return 0;
    j->restored = 0;
    return 1;
}

/* Everything appended is now durable: make it visible to the reader. */
static int mark_pending_durable(gz_journal_t *j)
{
    for (; j->n_durable < j->n_pend; j->n_durable++)
        if (!index_add(j, j->pend[j->n_durable].offset, j->pend[j->n_durable].size)) return 0;
    return 1;
}

gz_journal_status_t gz_journal_save(gz_journal_t *j, const gz_action_t *a)
{
    if (!j || !a || a->kind != GZ_ACTION_SAVE) return j ? fail(j, GZ_JOURNAL_ERR_ARGUMENT) : GZ_JOURNAL_ERR_ARGUMENT;
    if (j->failed) return fail(j, GZ_JOURNAL_ERR_FAILED);
    const gz_record_t *recs = a->u.save.records;
    size_t n = a->u.save.n_records;
    gz_batch_id_t id = a->u.save.batch;
    /* Order rules 3 and 4, checked before writing (spec 3.4). */
    if (id.incarnation != j->incarnation || id.sequence != j->last_sequence + 1 ||
        j->n_pend + j->n_comp >= GZ_RUNNER_MAX_UNCONFIRMED || (n && !recs))
        return fail(j, GZ_JOURNAL_ERR_SEQUENCE);
    uint64_t size = gz_journal_batch_size(recs, n);
    if (size == 0 || n > UINT32_MAX) return fail(j, GZ_JOURNAL_ERR_TOO_LARGE);
    const gz_record_t *guard = NULL;
    for (size_t i = 0; i < n; i++) {
        if (recs[i].bytes.len && !recs[i].bytes.data) return fail(j, GZ_JOURNAL_ERR_ARGUMENT);
        if (recs[i].type == GZ_RECORD_GUARD) {
            if (!guard_valid(j, &recs[i])) return fail(j, GZ_JOURNAL_ERR_GUARD);
            guard = &recs[i];
        }
    }
    /* Room for the entry and the sync mark that must follow it. */
    if (j->end + size + GZ_JOURNAL_MARK_LEN > j->hard_limit) return fail(j, GZ_JOURNAL_ERR_FULL);
    /* Keep what a crash can lose under the bound (spec section 4). */
    if (j->end > j->durable_end && j->end - j->durable_end + size > j->unsynced_max &&
        !(make_durable(j) && mark_pending_durable(j)))
        return fail(j, GZ_JOURNAL_ERR_IO);
    uint8_t *buf = malloc((size_t)size);
    if (!buf) return fail(j, GZ_JOURNAL_ERR_NO_MEMORY);
    if (guard) {
        uint8_t *g = malloc(guard->bytes.len);
        if (!g) { free(buf); return fail(j, GZ_JOURNAL_ERR_NO_MEMORY); }
        memcpy(g, guard->bytes.data, guard->bytes.len);
        free(j->guard);
        j->guard = g;
        j->guard_len = guard->bytes.len;
        j->guard_due = 1;
    }
    encode_batch_at(buf, id, recs, n, j->end);
    int ok = write_all(j, j->fd, buf, (size_t)size, j->end);
    free(buf);
    if (!ok) return fail(j, GZ_JOURNAL_ERR_IO);
    j->pend[j->n_pend].id = id;
    j->pend[j->n_pend].offset = j->end;
    j->pend[j->n_pend].size = (uint32_t)size;
    j->n_pend++;
    j->end += size;
    j->last_sequence = id.sequence;
    return GZ_JOURNAL_OK;
}

gz_journal_status_t gz_journal_flush(gz_journal_t *j)
{
    if (!j) return GZ_JOURNAL_ERR_ARGUMENT;
    if (j->failed) return GZ_JOURNAL_ERR_FAILED;
    if (j->n_pend == 0) return GZ_JOURNAL_OK;
    if (j->end > j->durable_end && !make_durable(j)) return fail(j, GZ_JOURNAL_ERR_IO);
    if (!mark_pending_durable(j)) return fail(j, GZ_JOURNAL_ERR_NO_MEMORY);
    /* The guard file is replaced before any batch is confirmed (spec 8.3). */
    if (j->guard_due) {
        if (!write_guard(j)) return fail(j, GZ_JOURNAL_ERR_IO);
        j->guard_due = 0;
    }
    /* The answer to a restore is durable: the marker goes before the answer
     * is confirmed (ports.h, the restore marker). Sequence 1 is always the
     * first batch of an incarnation, so it is pend[0] when present. */
    if (j->restored && j->pend[0].id.sequence == 1 && !clear_marker(j)) return fail(j, GZ_JOURNAL_ERR_IO);
    /* Confirming can lead to new saves through the node and the runner, so
     * take the list first. */
    pending_t done[GZ_RUNNER_MAX_UNCONFIRMED];
    size_t n = j->n_pend;
    memcpy(done, j->pend, n * sizeof done[0]);
    j->n_pend = j->n_durable = 0;
    if (j->pull) { /* the caller confirms, from gz_journal_complete */
        for (size_t i = 0; i < n; i++)
            j->comp[(j->comp_head + j->n_comp++) % GZ_RUNNER_MAX_UNCONFIRMED] = done[i].id;
        return GZ_JOURNAL_OK;
    }
    for (size_t i = 0; i < n; i++) {
        if (!j->runner) continue;
        if (gz_runner_confirm(j->runner, done[i].id) != GZ_OK) {
            j->failed = 1; /* the runner has already failed or the contract broke */
            return GZ_JOURNAL_ERR_FAILED;
        }
        if (j->on_confirmed) j->on_confirmed(j->confirmed_ctx, done[i].id);
    }
    return GZ_JOURNAL_OK;
}

/* --- the reader ----------------------------------------------------------- */

static int reader_next(void *ctx, gz_stored_batch_t *batch)
{
    gz_journal_t *j = ctx;
    if (j->failed || j->cursor >= j->n_idx) return 0;
    uint64_t off = j->idx_off[j->cursor];
    uint32_t size = j->idx_size[j->cursor];
    if (size > j->rbuf_cap) {
        uint8_t *b = realloc(j->rbuf, size);
        if (!b) { fail(j, GZ_JOURNAL_ERR_NO_MEMORY); return 0; }
        j->rbuf = b;
        j->rbuf_cap = size;
    }
    entry_t e;
    /* Read back and checked again: what was durable must still be there. */
    if (!read_all(j, j->rbuf, size, off) || !entry_at(j->rbuf, size, off, &e) ||
        e.kind != GZ_JOURNAL_KIND_BATCH || e.size != size) {
        fail(j, GZ_JOURNAL_ERR_IO);
        return 0;
    }
    size_t kept = 0;
    long n = gz_journal_parse_batch(e.payload, e.payload_len, NULL, 0, NULL);
    if ((size_t)n > j->recs_cap) {
        gz_record_t *rs = realloc(j->recs, (size_t)n * sizeof *rs);
        if (!rs) { fail(j, GZ_JOURNAL_ERR_NO_MEMORY); return 0; }
        j->recs = rs;
        j->recs_cap = (size_t)n;
    }
    gz_journal_parse_batch(e.payload, e.payload_len, j->recs, j->recs_cap, &kept);
    batch->id.incarnation = e.incarnation;
    batch->id.sequence = e.sequence;
    batch->records = kept ? j->recs : NULL;
    batch->n_records = kept;
    j->cursor++;
    return 1;
}

static void reader_rewind(void *ctx) { ((gz_journal_t *)ctx)->cursor = 0; }

gz_storage_reader_t gz_journal_reader(gz_journal_t *j)
{
    gz_storage_reader_t r;
    r.next = reader_next;
    r.rewind = reader_rewind;
    r.ctx = j;
    r.incarnation = j->incarnation;
    r.restored = j->restored;
    j->cursor = 0;
    return r;
}

int gz_journal_restored(const gz_journal_t *j) { return j->restored; }

int gz_journal_complete(gz_journal_t *j, gz_batch_id_t *id)
{
    if (!j || !id || !j->pull || j->failed) return 0;
    if (j->n_comp == 0 && j->n_pend > 0 && gz_journal_flush(j) != GZ_JOURNAL_OK) return 0;
    if (j->n_comp == 0) return 0;
    *id = j->comp[j->comp_head];
    j->comp_head = (j->comp_head + 1) % GZ_RUNNER_MAX_UNCONFIRMED;
    j->n_comp--;
    return 1;
}

gz_journal_status_t gz_journal_mark_restored(const char *dir, const uint8_t chain[32],
                                             const gz_journal_os_t *os, uint64_t floor)
{
    if (!dir || !chain) return GZ_JOURNAL_ERR_ARGUMENT;
    if (!os) os = &POSIX_OS;
    gz_journal_status_t st = GZ_JOURNAL_ERR_NO_MEMORY;
    char *jpath = join(dir, GZ_JOURNAL_FILE), *mpath = join(dir, GZ_JOURNAL_MARKER_FILE),
         *mtmp = join(dir, GZ_JOURNAL_MARKER_FILE ".tmp");
    uint8_t *data = NULL;
    int fd = -1;
    if (!jpath || !mpath || !mtmp) goto out;
    /* The imported journal's highest incarnation (read only; the open that
     * follows judges the file as usual). */
    st = GZ_JOURNAL_ERR_IO;
    fd = os->open(os->ctx, jpath, GZ_JOURNAL_OPEN_READ);
    uint64_t size;
    if (fd < 0 || os->size(os->ctx, fd, &size) != 0) goto out;
    if (size > GZ_JOURNAL_HARD_LIMIT) { st = GZ_JOURNAL_ERR_FULL; goto out; }
    data = malloc(size ? (size_t)size : 1);
    if (!data) { st = GZ_JOURNAL_ERR_NO_MEMORY; goto out; }
    for (uint64_t got = 0; got < size;) {
        long r = os->pread(os->ctx, fd, data + got, (size_t)(size - got), got);
        if (r <= 0) goto out;
        got += (uint64_t)r;
    }
    gz_journal_scan_t sc;
    st = gz_journal_scan(data, (size_t)size, chain, &sc, NULL, NULL);
    if (st != GZ_JOURNAL_OK) goto out;
    /* A marker already there (a second import before the first was
     * answered) keeps the higher floor. */
    uint8_t mk[MARKER_LEN + 16]; /* room to see a marker that is too long */
    size_t mk_len = 0;
    uint64_t old_base, old_floor;
    int mr = read_small(os, mpath, mk, sizeof mk, &mk_len);
    if (mr < 0) { st = GZ_JOURNAL_ERR_IO; goto out; }
    if (mr > 0) {
        if (!marker_decode(mk, mk_len, chain, &old_base, &old_floor)) { st = GZ_JOURNAL_ERR_MARKER; goto out; }
        if (old_floor > floor) floor = old_floor;
    }
    marker_encode(mk, chain, sc.highest_incarnation, floor);
    st = replace_file(os, dir, mtmp, mpath, mk, 56, mk + 56, 8) ? GZ_JOURNAL_OK : GZ_JOURNAL_ERR_IO;
out:
    if (fd >= 0) os->close(os->ctx, fd);
    free(data); free(jpath); free(mpath); free(mtmp);
    return st;
}

void gz_journal_close(gz_journal_t *j)
{
    if (!j) return;
    if (j->fd >= 0) j->os.close(j->os.ctx, j->fd);
    free_journal(j);
}
