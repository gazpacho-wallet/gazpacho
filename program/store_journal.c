/* SPDX-License-Identifier: MIT */
/* The program's store: the journal of ports/storage/journal.h (S5) in its
 * sealed format (S6), behind program/store.h. See store.h, "THE REAL STORE".
 *
 * The sealed table (gz_journal_seal_t) is built here over the unlocked
 * wallet's keys (store_unlock.h): the journal header and entries (storage 5.3
 * to 5.5), the start rule (6.3), the mark file's anchors (7 step 2, 10.2),
 * the sealed guard file (10.1); the start counter starts.gzs (contract-v2.md
 * section 8, storage 10.3) is read before the open and written by it. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "journal.h"

#include "datadir.h"
#include "gzp.h"
#include "store.h"
#include "store_unlock.h"

/* ---- the calls every store answers ------------------------------------------- */

int gzp_store_poisoned(const gzp_store_t *s) { return s->ops->poisoned ? s->ops->poisoned(s->ctx) : 0; }
int gzp_store_counter_state(const gzp_store_t *s, uint64_t *value)
{
    if (value) *value = 0;
    return s->ops->counter_state ? s->ops->counter_state(s->ctx, value) : GZP_COUNTER_MISSING;
}
int gzp_store_take_restore_answered(gzp_store_t *s)
{
    return s->ops->take_restore_answered ? s->ops->take_restore_answered(s->ctx) : 0;
}
uint64_t gzp_store_cut_bytes(const gzp_store_t *s) { return s->ops->cut_bytes ? s->ops->cut_bytes(s->ctx) : 0; }

/* ---- test hooks (gazpacho-test only) ------------------------------------------ */

#ifdef GZP_TEST_BUILD
/* --test-kill-at N: SIGKILL just before the N-th storage write, sync or
 * rename of this process (the journal's and the storage layer's), so a test
 * can stop the program dead at every one of them. */
static unsigned kill_at;
void gzp_store_test_kill_at(unsigned n) { kill_at = n; }
void gzp_store_test_tick(const char *what)
{
    if (kill_at && --kill_at == 0) {
        printf("test-kill before=%s\n", what);
        fflush(stdout);
        kill(getpid(), SIGKILL);
    }
}
#endif

/* ---- the sealed table ------------------------------------------------------------ */

typedef struct {
    gzp_wallet_t *w;
    const gz_sc_store_t *sc;
    gz_sc_unlocked_t *u;
} seal_ctx_t;

static gz_journal_status_t sl_header_open(void *ctx, const uint8_t *d, size_t len, const uint8_t chain[32])
{
    seal_ctx_t *c = ctx;
    uint8_t vid[16], fid[16], mine_chain[32], mine_vid[16];
    gz_sc_framekey_t *kj = NULL, *kh = NULL;
    gz_sc_err_t e = gz_sc_header_clear(d, len, chain, vid, fid);
    if (e == GZ_SC_OTHER_NETWORK) return GZ_JOURNAL_ERR_NETWORK;
    if (e != GZ_SC_OK) return GZ_JOURNAL_ERR_HEADER;
    gz_sc_vault_ids(c->u->vault, mine_chain, mine_vid);
    if (memcmp(vid, mine_vid, 16) != 0) return GZ_JOURNAL_ERR_NOT_THIS_WALLET;
    e = gz_sc_header_open(d, c->u->vault, &kj);
    if (e == GZ_SC_NOMEM) return GZ_JOURNAL_ERR_NO_MEMORY;
    if (e != GZ_SC_OK) return GZ_JOURNAL_ERR_NOT_THIS_WALLET;
    if (gz_sc_mark_key(c->u->vault, fid, &kh) != GZ_SC_OK) {
        gz_sc_framekey_free(kj);
        return GZ_JOURNAL_ERR_NO_MEMORY;
    }
    /* The frame and mark keys follow the file this header heads (an import
     * scans the backup and the journal it replaces in turn). */
    gz_sc_framekey_free(c->u->kj);
    gz_sc_framekey_free(c->u->kh);
    c->u->kj = kj;
    c->u->kh = kh;
    memcpy(c->u->file_id, fid, 16);
    return GZ_JOURNAL_OK;
}

static int sl_frame_seal(void *ctx, uint64_t offset, uint8_t kind, uint64_t inc, uint64_t seq,
                         const uint8_t *payload, size_t len, uint8_t *out)
{
    seal_ctx_t *c = ctx;
    size_t n = 0;
    if (!c->u->kj) return -1;
    return gz_sc_frame_seal(c->u->kj, offset, kind, inc, seq, payload, len, out, len + GZ_SC_FRAME_OVERHEAD, &n) ==
                   GZ_SC_OK && n == len + GZ_SC_FRAME_OVERHEAD
               ? 0
               : -1;
}

static int sl_frame_open(void *ctx, const uint8_t *q, uint64_t avail, uint64_t offset, gz_journal_frame_t *f,
                         uint8_t *payload, size_t cap)
{
    seal_ctx_t *c = ctx;
    gz_sc_frame_t fr;
    if (!c->u->kj) return 0;
    if (avail > SIZE_MAX) avail = SIZE_MAX;
    if (gz_sc_frame_open(c->u->kj, q, (size_t)avail, offset, &fr, payload, cap) != GZ_SC_OK) return 0;
    f->kind = fr.kind;
    f->incarnation = fr.incarnation;
    f->sequence = fr.sequence;
    f->size = fr.entry_len;
    f->payload_len = fr.payload_len;
    return 1;
}

static int sl_has_mark(void *ctx, uint64_t inc, uint64_t off)
{
    const gz_journal_view_t *v = ctx;
    return v->has_sync_mark(v->ctx, inc, off);
}

static gz_journal_status_t sl_start_rule(void *ctx, const gz_journal_view_t *view, gz_journal_start_t *out)
{
    seal_ctx_t *c = ctx;
    gz_sc_journal_view_t jv;
    gz_sc_start_t st = GZ_SC_START_OK;
    jv.highest_incarnation = view->highest_incarnation;
    jv.has_sync_mark = sl_has_mark;
    jv.ctx = (void *)view;
    jv.newest_guard_counter = view->newest_guard_counter;
    gz_sc_err_t e = gz_sc_check_start(c->sc, c->u, &jv, &st);
    if (e == GZ_SC_NOMEM) return GZ_JOURNAL_ERR_NO_MEMORY;
    if (e != GZ_SC_OK) return GZ_JOURNAL_ERR_IO;
    *out = st == GZ_SC_START_BEHIND        ? GZ_JOURNAL_START_BEHIND
         : st == GZ_SC_START_POSSIBLY_OLD  ? GZ_JOURNAL_START_POSSIBLY_OLD
         : st == GZ_SC_START_RESTORE       ? GZ_JOURNAL_START_RESTORE
                                           : GZ_JOURNAL_START_OK;
    return GZ_JOURNAL_OK;
}

static int sl_mark_restart(void *ctx)
{
    seal_ctx_t *c = ctx;
    return gz_sc_mark_restart(c->sc, c->u) == GZ_SC_OK ? 0 : -1;
}

static int sl_anchor(void *ctx, uint64_t inc, uint64_t off)
{
    seal_ctx_t *c = ctx;
    return gz_sc_anchor(c->sc, c->u, inc, off) == GZ_SC_OK ? 0 : -1;
}

/* A guard record is the guard file's contents behind its own head:
 * "GZGUARD1", the chain, then counter, epochs, rounds_started (journal.md
 * 8.3); the sealed file carries the contents alone (storage 10.1). */
#define REC_HEAD 40u
static const uint8_t REC_MAGIC[8] = {'G', 'Z', 'G', 'U', 'A', 'R', 'D', '1'};

static int sl_guard_write(void *ctx, const uint8_t *rec, size_t len)
{
    seal_ctx_t *c = ctx;
    gz_sc_guard_t g;
    memset(&g, 0, sizeof g);
    if (len < REC_HEAD || gz_sc_guard_parse(rec + REC_HEAD, len - REC_HEAD, &g) != GZ_SC_OK) return -1;
    gz_sc_err_t e = gz_sc_guard_write(c->sc, c->u->vault, &g);
    gz_sc_guard_clear(&g);
    return e == GZ_SC_OK ? 0 : -1;
}

static int sl_guard_read(void *ctx, uint8_t **rec, size_t *len)
{
    seal_ctx_t *c = ctx;
    uint8_t *d = NULL, *out;
    size_t dl = 0, cl, n = 0;
    gz_sc_guard_t g;
    *rec = NULL;
    *len = 0;
    memset(&g, 0, sizeof g);
    gz_sc_err_t e = gz_sc_fs_read(c->sc, GZ_SC_FILE_GUARD, (size_t)1 << 20, &d, &dl);
    if (e == GZ_SC_MISSING) return 0;
    if (e != GZ_SC_OK) return -1;
    e = gz_sc_guard_open(c->u->vault, d, dl, &g);
    free(d);
    if (e == GZ_SC_NOMEM) return -1;
    if (e != GZ_SC_OK) return 0; /* damaged, or another network: gives nothing (journal.md 8.3) */
    cl = gz_sc_guard_contents_len(&g);
    out = malloc(REC_HEAD + cl);
    if (!out || gz_sc_guard_contents(&g, out + REC_HEAD, cl, &n) != GZ_SC_OK || n != cl) {
        free(out);
        gz_sc_guard_clear(&g);
        return -1;
    }
    gz_sc_guard_clear(&g);
    memcpy(out, REC_MAGIC, 8);
    memcpy(out + 8, c->sc->chain, 32);
    *rec = out;
    *len = REC_HEAD + cl;
    return 1;
}

static void seal_table(gz_journal_seal_t *t, seal_ctx_t *c)
{
    memset(t, 0, sizeof *t);
    t->header_len = GZ_SC_JHEADER_LEN;
    t->overhead = GZ_SC_FRAME_OVERHEAD;
    t->mark_size = GZ_SC_FRAME_OVERHEAD + 8;
    t->mark_length = GZ_SC_FRAME_OVERHEAD - 4 + 8;
    t->header_open = sl_header_open;
    t->frame_seal = sl_frame_seal;
    t->frame_open = sl_frame_open;
    t->start_rule = sl_start_rule;
    t->mark_restart = sl_mark_restart;
    t->anchor = sl_anchor;
    t->guard_write = sl_guard_write;
    t->guard_read = sl_guard_read;
    t->ctx = c;
}

static int seal_ctx(seal_ctx_t *c, gzp_wallet_t *w)
{
    c->w = w;
    c->sc = gzp_wallet_sc_store(w);
    c->u = gzp_wallet_sc_unlocked(w);
    return c->u && c->u->vault ? 0 : -1;
}

/* ---- the operating system, with the test hooks ------------------------------------ */

typedef struct {
    int fail_next_sync;     /* tests: the next sync reports failure */
} os_ctx_t;

static const gz_journal_os_t *POSIX;

static int o_open(void *c, const char *p, int how) { (void)c; return POSIX->open(POSIX->ctx, p, how); }
static int o_close(void *c, int fd) { (void)c; return POSIX->close(POSIX->ctx, fd); }
static long o_pread(void *c, int fd, void *b, size_t n, uint64_t off) { (void)c; return POSIX->pread(POSIX->ctx, fd, b, n, off); }
static long o_pwrite(void *c, int fd, const void *b, size_t n, uint64_t off)
{
    (void)c;
#ifdef GZP_TEST_BUILD
    gzp_store_test_tick("journal-write");
#endif
    return POSIX->pwrite(POSIX->ctx, fd, b, n, off);
}
static int o_sync(void *c, int fd)
{
    os_ctx_t *o = c;
#ifdef GZP_TEST_BUILD
    gzp_store_test_tick("journal-sync");
#endif
    if (o->fail_next_sync) {
        o->fail_next_sync = 0;
        /* The write reached the page cache; its sync is reported failed, as
         * a device error would (journal.md 4, failures). */
        errno = EIO;
        return -1;
    }
    return POSIX->sync(POSIX->ctx, fd);
}
static int o_sync_dir(void *c, const char *d)
{
    (void)c;
#ifdef GZP_TEST_BUILD
    gzp_store_test_tick("journal-sync-dir");
#endif
    return POSIX->sync_dir(POSIX->ctx, d);
}
static int o_truncate(void *c, int fd, uint64_t l)
{
    (void)c;
#ifdef GZP_TEST_BUILD
    gzp_store_test_tick("journal-truncate");
#endif
    return POSIX->truncate(POSIX->ctx, fd, l);
}
static int o_size(void *c, int fd, uint64_t *s) { (void)c; return POSIX->size(POSIX->ctx, fd, s); }
static int o_lock(void *c, int fd) { (void)c; return POSIX->lock(POSIX->ctx, fd); }
static int o_link(void *c, const char *a, const char *b) { (void)c; return POSIX->link(POSIX->ctx, a, b); }
static int o_rename(void *c, const char *a, const char *b)
{
    (void)c;
#ifdef GZP_TEST_BUILD
    gzp_store_test_tick("journal-rename");
#endif
    return POSIX->rename(POSIX->ctx, a, b);
}
static int o_unlink(void *c, const char *p)
{
    (void)c;
#ifdef GZP_TEST_BUILD
    gzp_store_test_tick("journal-unlink");
#endif
    return POSIX->unlink(POSIX->ctx, p);
}
static long o_pread_device(void *c, int fd, void *b, size_t n, uint64_t off)
{
    (void)c;
    return POSIX->pread_device(POSIX->ctx, fd, b, n, off);
}
static int o_random(void *c, uint8_t *b, size_t n) { (void)c; return POSIX->random(POSIX->ctx, b, n); }

static void os_table(gz_journal_os_t *t, os_ctx_t *c)
{
    POSIX = gz_journal_os_posix();
    t->open = o_open;
    t->close = o_close;
    t->pread = o_pread;
    t->pwrite = o_pwrite;
    t->sync = o_sync;
    t->sync_dir = o_sync_dir;
    t->truncate = o_truncate;
    t->size = o_size;
    t->lock = o_lock;
    t->link = o_link;
    t->rename = o_rename;
    t->unlink = o_unlink;
    t->pread_device = o_pread_device;
    t->random = o_random;
    t->ctx = c;
}

/* ---- the store ---------------------------------------------------------------- */

typedef struct {
    char dir[GZP_PATH_MAX];
    gzp_wallet_t *w;
    seal_ctx_t sc;
    gz_journal_seal_t seal;
    os_ctx_t osc;
    gz_journal_os_t os;
    gz_journal_t *j;
    gz_journal_open_info_t info;
    gz_storage_reader_t rd;
    int counter_state;
    uint64_t counter_value;
    int behind;
    int restored_at_begin, answered_told;
    /* tests */
    unsigned fail_at, sync_fail_at;
    int fail_next_ping, crash_after_counter;
    const char *log_name;
} jstore_t;

static int set_err(char *err, size_t n, const char *what)
{
    if (err && n) snprintf(err, n, "%s", what);
    return -1;
}

static int write_counter(void *ctx, uint64_t inc)
{
    jstore_t *s = ctx;
    if (gz_sc_counter_write(s->sc.sc, s->sc.u->vault, inc) != GZ_SC_OK) return -1;
    s->counter_value = inc;
#ifdef GZP_TEST_BUILD
    if (s->crash_after_counter) { /* --test-crash-after-counter */
        printf("%s test-crash after-counter incarnation=%llu\n", s->log_name ? s->log_name : "gazpacho",
               (unsigned long long)inc);
        fflush(stdout);
        _exit(70);
    }
#endif
    return 0;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int js_begin(void *ctx, uint64_t *incarnation, char *err, size_t errlen)
{
    jstore_t *s = ctx;
    gz_journal_config_t cfg;
    uint64_t counter = 0;
    gz_sc_err_t ce;
    gz_journal_status_t st;
    if (s->j) return set_err(err, errlen, "begin called twice");
    /* The start counter, read before the open (contract-v2.md section 8). */
    ce = gz_sc_counter_read(s->sc.sc, s->sc.u->vault, &counter);
    if (ce == GZ_SC_OK) {
        s->counter_state = GZP_COUNTER_FOUND;
    } else if (ce == GZ_SC_MISSING) {
        s->counter_state = GZP_COUNTER_MISSING;
        counter = 0;
    } else {
        return set_err(err, errlen, "cannot read the start counter");
    }
    if (counter >= GZ_JOURNAL_INCARNATION_LIMIT) return set_err(err, errlen, "the start counter is at 2^63");
    memset(&cfg, 0, sizeof cfg);
    cfg.dir = s->dir;
    cfg.chain = s->sc.sc->chain;
    cfg.clock_ms = now_ms();
    cfg.os = &s->os;
    cfg.pull = 1;
    cfg.start_counter = counter;
    cfg.write_counter = write_counter;
    cfg.counter_ctx = s;
    st = gz_journal_open_sealed(&s->j, &cfg, &s->seal, &s->info);
    if (st != GZ_JOURNAL_OK) {
        s->j = NULL;
        s->behind = st == GZ_JOURNAL_ERR_BEHIND ? 1 : st == GZ_JOURNAL_ERR_POSSIBLY_OLD ? 2 : 0;
        if (err && errlen) snprintf(err, errlen, "journal: %s", gz_journal_status_name(st));
        return s->behind ? GZP_STORE_BEHIND : -1;
    }
    s->rd = gz_journal_reader(s->j);
    s->restored_at_begin = gz_journal_restored(s->j);
    *incarnation = gz_journal_incarnation(s->j);
    return 0;
}

static int js_next(void *ctx, gzp_batch_t *out)
{
    jstore_t *s = ctx;
    gz_stored_batch_t b;
    if (!s->j || !s->rd.next(s->rd.ctx, &b)) return 0;
    out->id = b.id;
    out->records = b.records;
    out->n_records = b.n_records;
    return 1;
}

static void js_rewind(void *ctx)
{
    jstore_t *s = ctx;
    if (s->j) s->rd.rewind(s->rd.ctx);
}

#define PING_HEADER 82u
static int has_ping(const gz_record_t *r, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if ((r[i].type == 0x7e570001u || r[i].type == 0x7e580001u) && r[i].bytes.len >= PING_HEADER) return 1;
    return 0;
}

static int js_append(void *ctx, gz_batch_id_t id, const gz_record_t *records, size_t n)
{
    jstore_t *s = ctx;
    gz_action_t a;
    if (!s->j || gz_journal_failed(s->j)) return -1;
    if (s->fail_at && --s->fail_at == 0) return -1; /* tests: fails before writing anything */
    if (s->sync_fail_at && --s->sync_fail_at == 0) s->osc.fail_next_sync = 1;
    if (s->fail_next_ping && has_ping(records, n)) {
        s->fail_next_ping = 0;
        s->osc.fail_next_sync = 1;
    }
    memset(&a, 0, sizeof a);
    a.kind = GZ_ACTION_SAVE;
    a.u.save.batch = id;
    a.u.save.records = records;
    a.u.save.n_records = n;
    if (gz_journal_save(s->j, &a) != GZ_JOURNAL_OK) return -1;
    /* Durable before append returns (store.h): sync, mark, sync, anchor,
     * guard. A failure leaves the journal failed: nothing more is written,
     * and the next begin reads what the device holds. */
    if (gz_journal_flush(s->j) != GZ_JOURNAL_OK) return -1;
    return 0;
}

static int js_complete(void *ctx, gz_batch_id_t *id)
{
    jstore_t *s = ctx;
    return s->j ? gz_journal_complete(s->j, id) : 0;
}

static int js_restored(void *ctx)
{
    jstore_t *s = ctx;
    return s->j ? gz_journal_restored(s->j) : 0;
}

static void js_close(void *ctx)
{
    jstore_t *s = ctx;
    if (s->j) gz_journal_close(s->j);
    OPENSSL_cleanse(s, sizeof *s);
    free(s);
}

static int js_poisoned(void *ctx) { (void)ctx; return 0; }
static int js_counter_state(void *ctx, uint64_t *v)
{
    jstore_t *s = ctx;
    if (v) *v = s->counter_value;
    return s->counter_state;
}
static int js_take_answered(void *ctx)
{
    jstore_t *s = ctx;
    if (!s->j || !s->restored_at_begin || s->answered_told || gz_journal_restored(s->j)) return 0;
    s->answered_told = 1;
    return 1;
}
static uint64_t js_cut_bytes(void *ctx) { return ((jstore_t *)ctx)->info.cut_bytes; }
/* On a restored start: the sealed guard file as a guard record (the
 * journal read it at the open, before anything was written). */
static int js_guard(void *ctx, const uint8_t **data, size_t *len)
{
    jstore_t *s = ctx;
    if (!s->j || !s->restored_at_begin || !s->rd.guard.data || !s->rd.guard.len) return 0;
    *data = s->rd.guard.data;
    *len = s->rd.guard.len;
    return 1;
}
#ifdef GZP_TEST_BUILD
static void js_fail_at(void *ctx, unsigned k) { ((jstore_t *)ctx)->fail_at = k; }
static void js_fail_next_ping(void *ctx) { ((jstore_t *)ctx)->fail_next_ping = 1; }
static void js_test_hooks(void *ctx, unsigned sync_fail_at, int cut_fail, int crash_after_counter,
                          const char *log_name)
{
    jstore_t *s = ctx;
    (void)cut_fail; /* the journal has no cut back to fail: a failed sync fails the journal (journal.md 4) */
    s->sync_fail_at = sync_fail_at;
    s->crash_after_counter = crash_after_counter;
    s->log_name = log_name;
}
#endif

static const gzp_store_ops_t JOURNAL_OPS = {
    js_begin, js_next, js_rewind, js_append, js_complete, js_restored, js_close, js_guard,
    js_poisoned, js_counter_state, js_take_answered, js_cut_bytes,
#ifdef GZP_TEST_BUILD
    js_fail_at, js_fail_next_ping, js_test_hooks
#else
    NULL, NULL, NULL
#endif
};

int gzp_journal_store_open(gzp_store_t *out, const char *dir, gzp_wallet_t *w, char *err, size_t errlen)
{
    jstore_t *s;
    if (strlen(dir) >= GZP_PATH_MAX) return set_err(err, errlen, "folder path too long");
    s = calloc(1, sizeof *s);
    if (!s) return set_err(err, errlen, "out of memory");
    strcpy(s->dir, dir);
    s->w = w;
    if (seal_ctx(&s->sc, w) != 0) {
        free(s);
        return set_err(err, errlen, "the wallet is locked");
    }
    seal_table(&s->seal, &s->sc);
    os_table(&s->os, &s->osc);
    s->counter_state = GZP_COUNTER_MISSING;
    out->ops = &JOURNAL_OPS;
    out->ctx = s;
    return 0;
}

uint64_t gzp_journal_store_incarnation(const gzp_store_t *st)
{
    const jstore_t *s = st->ctx;
    return st->ops == &JOURNAL_OPS && s->j ? gz_journal_incarnation(s->j) : 0;
}

int gzp_journal_store_behind(const gzp_store_t *st)
{
    return st->ops == &JOURNAL_OPS && ((const jstore_t *)st->ctx)->behind;
}

/* ---- dump, import, mark ------------------------------------------------------------ */

static int read_file(const char *path, uint8_t **data, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long n;
    *data = NULL;
    *len = 0;
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    *data = malloc(n ? (size_t)n : 1);
    if (!*data || fread(*data, 1, (size_t)n, f) != (size_t)n) {
        free(*data);
        *data = NULL;
        fclose(f);
        return -1;
    }
    fclose(f);
    *len = (size_t)n;
    return 0;
}

int gzp_journal_dump(const char *dir, gzp_wallet_t *w, char *err, size_t errlen)
{
    char path[GZP_PATH_MAX + 64];
    uint8_t *d = NULL, *pl = NULL;
    size_t len = 0, p;
    seal_ctx_t c;
    gz_journal_seal_t t;
    int rc = -1;
    if (seal_ctx(&c, w) != 0) return set_err(err, errlen, "the wallet is locked");
    seal_table(&t, &c);
    snprintf(path, sizeof path, "%s/%s", dir, GZ_JOURNAL_FILE);
    if (read_file(path, &d, &len) != 0) return set_err(err, errlen, "cannot read the journal");
    if (sl_header_open(&c, d, len, c.sc->chain) != GZ_JOURNAL_OK) {
        set_err(err, errlen, "the journal header does not open");
        goto out;
    }
    pl = malloc(len ? len : 1);
    if (!pl) {
        set_err(err, errlen, "out of memory");
        goto out;
    }
    /* Every valid entry in file order, stopping at the first invalid one (a
     * torn tail, which the next start cuts): an independent walk of the
     * sealed frames, not the journal's scan. */
    for (p = GZ_SC_JHEADER_LEN; p < len;) {
        gz_journal_frame_t f;
        if (!sl_frame_open(&c, d + p, len - p, p, &f, pl, len)) break;
        if (f.kind == GZ_JOURNAL_KIND_INCARNATION) {
            printf("journal-incarnation inc=%llu\n", (unsigned long long)f.incarnation);
        } else if (f.kind == GZ_JOURNAL_KIND_BATCH) {
            gz_record_t *recs;
            size_t kept = 0;
            long nr = gz_journal_parse_batch(pl, f.payload_len, NULL, 0, NULL);
            if (nr < 0) break;
            recs = calloc((size_t)nr + 1, sizeof *recs);
            if (!recs) break;
            gz_journal_parse_batch(pl, f.payload_len, recs, (size_t)nr, &kept);
            printf("journal-batch inc=%llu seq=%llu records=%zu\n", (unsigned long long)f.incarnation,
                   (unsigned long long)f.sequence, kept);
            for (size_t i = 0; i < kept; i++) {
                printf("journal-record inc=%llu seq=%llu type=0x%08x len=%zu", (unsigned long long)f.incarnation,
                       (unsigned long long)f.sequence, (unsigned)recs[i].type, recs[i].bytes.len);
#ifdef GZP_TEST_BUILD
                /* Tests read records back (gzp_harness.parse_journal). */
                printf(" hex=");
                for (size_t k = 0; k < recs[i].bytes.len; k++) printf("%02x", recs[i].bytes.data[k]);
#endif
                printf("\n");
            }
            free(recs);
        }
        p += f.size;
    }
    if (p < len) printf("journal-tail bytes=%zu\n", len - p);
    fflush(stdout);
    rc = 0;
out:
    if (pl) OPENSSL_cleanse(pl, len ? len : 1);
    free(pl);
    free(d);
    return rc;
}

static int copy_file(const char *from, const char *to)
{
    uint8_t *d = NULL;
    size_t len = 0;
    int fd, ok;
    if (read_file(from, &d, &len) != 0) return -1;
    fd = open(to, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        free(d);
        return -1;
    }
    ok = write(fd, d, len) == (ssize_t)len && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    free(d);
    return ok ? 0 : -1;
}

int gzp_journal_store_import(const char *dir, gzp_wallet_t *w, const char *backup, char *err, size_t errlen)
{
    char staged[GZP_PATH_MAX + 64];
    seal_ctx_t c;
    gz_journal_seal_t t;
    uint64_t floor = 0;
    gz_journal_status_t st;
    if (seal_ctx(&c, w) != 0) return set_err(err, errlen, "the wallet is locked");
    seal_table(&t, &c);
    snprintf(staged, sizeof staged, "%s/%s.import", dir, GZ_JOURNAL_FILE);
    if (copy_file(backup, staged) != 0) return set_err(err, errlen, "cannot stage the backup");
    (void)gz_sc_counter_read(c.sc, c.u->vault, &floor);
    st = gz_journal_import_sealed(dir, c.sc->chain, NULL, &t, staged, floor);
    if (st != GZ_JOURNAL_OK) {
        unlink(staged);
        if (err && errlen) snprintf(err, errlen, "the import was refused: %s", gz_journal_status_name(st));
        return -1;
    }
    return 0;
}

int gzp_journal_store_mark_restored(const char *dir, gzp_wallet_t *w, uint64_t floor, char *err, size_t errlen)
{
    seal_ctx_t c;
    gz_journal_seal_t t;
    gz_journal_status_t st;
    if (seal_ctx(&c, w) != 0) return set_err(err, errlen, "the wallet is locked");
    seal_table(&t, &c);
    st = gz_journal_mark_restored_sealed(dir, c.sc->chain, NULL, &t, floor);
    if (st != GZ_JOURNAL_OK) {
        if (err && errlen) snprintf(err, errlen, "the restore mark was refused: %s", gz_journal_status_name(st));
        return -1;
    }
    return 0;
}
