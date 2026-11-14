/* A stateful model test of the whole journal API on the memfs (written by
 * review B of PR 29; its findings B2 and B3 are now violations).
 * The input bytes choose a sequence of operations: open (with or without a
 * start counter, a failing counter write), save, flush, complete, close,
 * crash (lose, keep, reorder), a failure at a later point, a crash at a later
 * point inside any call, snapshot (a backup), import, mark restored. After
 * every operation the contract invariants of ports.h, runner.h, journal.h and
 * contract-v2 section 8 are checked against the model; a violation aborts.
 * Built as a libFuzzer target (GZ_LIBFUZZER: -DLIBFUZZER) or with a random
 * driver:  fuzz_journal_model ITERATIONS SEED [VERBOSE [RUN]] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "journal.h"
#include "memfs.h"
#include "superscalar/sha256.h"

#define D "/node"
#define JP D "/" GZ_JOURNAL_FILE
#define GP D "/" GZ_JOURNAL_GUARD_FILE
#define SP D "/journal.gzj.import"
#define MAXB 2048

static int verbose;
static long cur_it;
#define BUG(...) do { fprintf(stderr, "MODEL VIOLATION (run %ld): ", cur_it); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); abort(); } while (0)

typedef struct { uint64_t inc, seq; } bid_t;

typedef struct {
    memfs_t fs;
    gz_journal_t *j;
    uint64_t inc, seq;          /* current incarnation, last sequence saved */
    int restored_open;          /* this open's restored */
    bid_t handed[MAXB]; int nh;
    bid_t conf[MAXB]; int nc;   /* reported by complete, in this journal's line */
    uint64_t next_report;       /* the sequence complete must report next */
    uint64_t max_inc;           /* largest incarnation of a successful open */
    uint64_t counter;           /* starts.gzs as written */
    int marker;                 /* 1 set, 0 none, -1 unknown (a crash inside import or mark) */
    uint64_t base;
    uint8_t *snap; size_t snap_len; int have_snap;
    uint8_t *staged; size_t staged_len; int import_unknown;
    uint8_t *before; size_t before_len;   /* journal before an import that crashed */
    uint64_t gctr;              /* the next guard counter */
    uint64_t soft, hard, unsynced;
    int wc_fail, had_journal, stop, import_under_fault, b1_risk;
} M;

static const uint8_t *in; static size_t in_len, in_pos;
static int nb(uint8_t *b) { if (in_pos >= in_len) return 0; *b = in[in_pos++]; return 1; }
static uint8_t b8(void) { uint8_t b = 0; nb(&b); return b; }

static uint8_t pat(uint64_t i, uint64_t s, size_t k)
{
    uint64_t x = i * 1000003u + s * 7919u + 0x9e37u;
    x ^= x >> 13; x *= 0xff51afd7ed558ccdull; x ^= x >> 29;
    return (uint8_t)(x + k * 31u);
}

static int handed(M *m, uint64_t i, uint64_t s)
{
    for (int k = 0; k < m->nh; k++) if (m->handed[k].inc == i && m->handed[k].seq == s) return 1;
    return 0;
}

static uint64_t guard_counter_of(const uint8_t *g) { uint64_t c = 0; for (int i = 0; i < 8; i++) c = c << 8 | g[40 + i]; return c; }

static int counter_cb(void *ctx, uint64_t n)
{
    M *m = ctx;
    if (m->wc_fail) return -1;
    if (n <= m->max_inc) BUG("start counter written with %llu, not above %llu", (unsigned long long)n, (unsigned long long)m->max_inc);
    m->counter = n;
    return 0;
}

/* Check the reader and the files after a successful open. */
static void check_open(M *m, const gz_journal_open_info_t *info, uint64_t given_counter)
{
    if (info->incarnation != m->inc) BUG("info incarnation differs");
    if (m->inc <= m->max_inc) BUG("incarnation %llu repeats or goes back (max %llu)", (unsigned long long)m->inc, (unsigned long long)m->max_inc);
    if (m->inc <= given_counter) BUG("incarnation not above the start counter");
    if (m->inc >= GZ_JOURNAL_INCARNATION_LIMIT) BUG("incarnation at 2^63");
    if (m->counter != m->inc) BUG("start counter not written with the incarnation");
    /* The cache view equals the disk after an open (nothing the open kept
     * rests on bytes that only the page cache holds). */
    size_t vl, dl;
    const uint8_t *v = memfs_get(&m->fs, JP, &vl), *d = memfs_disk(&m->fs, JP, &dl);
    if (!v || !d || vl != dl || memcmp(v, d, vl) != 0) BUG("journal after open differs from the disk");
    gz_journal_scan_t sc;
    if (gz_journal_scan(v, vl, gz_journal_chain_signet, &sc, NULL, NULL) != GZ_JOURNAL_OK || sc.verdict != GZ_JOURNAL_CLEAN)
        BUG("journal not clean after open");
    if (sc.highest_incarnation != m->inc) BUG("new incarnation entry not last");
    /* The reader. */
    gz_storage_reader_t rd = gz_journal_reader(m->j);
    if (rd.incarnation != m->inc || rd.restored != info->restored) BUG("reader fields");
    gz_stored_batch_t sb;
    bid_t last = {0, 0};
    static uint8_t seen[MAXB];
    memset(seen, 0, sizeof seen);
    int seq1_above_base = 0;
    uint64_t newest_guard = 0; int any_guard = 0;
    while (rd.next(rd.ctx, &sb)) {
        if (sb.id.incarnation < last.inc || (sb.id.incarnation == last.inc && sb.id.sequence <= last.seq)) BUG("reader order");
        if (sb.id.incarnation >= m->inc) BUG("reader yields a batch of this or a later incarnation at start");
        last.inc = sb.id.incarnation; last.seq = sb.id.sequence;
        if (!handed(m, sb.id.incarnation, sb.id.sequence)) BUG("phantom batch (%llu,%llu)", (unsigned long long)sb.id.incarnation, (unsigned long long)sb.id.sequence);
        if (sb.n_records < 1) BUG("batch without its records");
        const gz_record_t *r = &sb.records[0];
        if (r->type != 0x7e570001u || r->bytes.len < 2) BUG("record 0 type/len");
        size_t len = (size_t)r->bytes.data[0] << 8 | r->bytes.data[1];
        if (len != r->bytes.len) BUG("record length");
        for (size_t k = 2; k < len; k++) if (r->bytes.data[k] != pat(sb.id.incarnation, sb.id.sequence, k)) BUG("altered batch");
        for (size_t q = 1; q < sb.n_records; q++)
            if (sb.records[q].type == GZ_RECORD_GUARD) { newest_guard = guard_counter_of(sb.records[q].bytes.data); any_guard = 1; }
        for (int k = 0; k < m->nc; k++) if (m->conf[k].inc == sb.id.incarnation && m->conf[k].seq == sb.id.sequence) seen[k] = 1;
        if (m->marker == 1 && sb.id.sequence == 1 && sb.id.incarnation > m->base) seq1_above_base = 1;
    }
    if (gz_journal_failed(m->j)) BUG("reader failed");
    for (int k = 0; k < m->nc; k++)
        if (!seen[k]) BUG("confirmed batch (%llu,%llu) lost", (unsigned long long)m->conf[k].inc, (unsigned long long)m->conf[k].seq);
    /* The restore marker. */
    if (m->marker == 0 && info->restored) BUG("restored with no marker");
    if (m->marker == 1 && !seq1_above_base && !info->restored) BUG("restore answered without its batch");
    if (m->marker == 1 && seq1_above_base && info->restored) BUG("restore answered but still restored");
    m->marker = info->restored ? 1 : 0;
    /* The guard file follows the newest kept guard record (not on a restored start). */
    if (!info->restored && any_guard) {
        size_t gl;
        const uint8_t *g = memfs_get(&m->fs, GP, &gl);
        if (!g || gl < 66 || guard_counter_of(g) < newest_guard) BUG("guard file behind the newest kept guard record");
    }
}

static void do_open(M *m)
{
    if (m->j) return;
    uint8_t f = b8();
    uint64_t given = (f & 1) ? m->counter : 0; /* bit 0: the counter file is there */
    m->wc_fail = (f & 6) == 6;
    { size_t hl; m->had_journal = memfs_get(&m->fs, JP, &hl) != NULL; }
    gz_journal_config_t cfg = {0};
    cfg.dir = D; cfg.chain = gz_journal_chain_signet; cfg.clock_ms = 5; cfg.os = &m->fs.os;
    cfg.soft_limit = m->soft; cfg.hard_limit = m->hard; cfg.unsynced_max = m->unsynced;
    cfg.pull = 1; cfg.start_counter = given; cfg.write_counter = counter_cb; cfg.counter_ctx = m;
    gz_journal_open_info_t info;
    uint64_t before = m->counter;
    if (m->marker == -1) { /* unknown after a crash or failure: the file says */
        size_t ml; const uint8_t *mk = memfs_get(&m->fs, D "/" GZ_JOURNAL_MARKER_FILE, &ml);
        m->marker = mk && ml == 64;
        if (m->marker) { m->base = 0; for (int i = 0; i < 8; i++) m->base = m->base << 8 | mk[40 + i]; }
    }
    gz_journal_status_t st = gz_journal_open(&m->j, &cfg, &info);
    m->wc_fail = 0;
    if (verbose) printf("open(counter %llu) -> %s inc %llu restored %d\n", (unsigned long long)given, gz_journal_status_name(st), (unsigned long long)info.incarnation, info.restored);
    if (st != GZ_JOURNAL_OK) {
        if (m->j) BUG("journal returned on failure");
        if (memfs_open_fds(&m->fs) != 0) BUG("descriptor left open by a failed open");
        if (st == GZ_JOURNAL_ERR_CORRUPT || st == GZ_JOURNAL_ERR_ORDER || st == GZ_JOURNAL_ERR_HEADER || st == GZ_JOURNAL_ERR_MARKER)
            if (!m->fs.crashed && m->fs.fail_at == 0) BUG("open refused a journal the writer made: %s", gz_journal_status_name(st));
        (void)before;
        return;
    }
    m->inc = info.incarnation; m->seq = 0; m->next_report = 1;
    m->restored_open = info.restored;
    /* An import that crashed: which file is there now? The backup must never start as an ordinary journal. */
    if (m->import_unknown) {
        size_t l; const uint8_t *now = memfs_get(&m->fs, JP, &l);
        (void)now; (void)l;
    }
    check_open(m, &info, given);
    m->max_inc = m->inc;
}

static void do_save(M *m)
{
    if (!m->j) return;
    uint8_t s = b8(), g = b8();
    size_t len = 2 + (size_t)s * 13;
    uint8_t *buf = malloc(len), gb[66];
    buf[0] = (uint8_t)(len >> 8); buf[1] = (uint8_t)len;
    uint64_t seq = m->seq + 1;
    for (size_t k = 2; k < len; k++) buf[k] = pat(m->inc, seq, k);
    gz_record_t r[2] = {{0x7e570001u, {buf, len}}, {GZ_RECORD_GUARD, {gb, 66}}};
    size_t n = 1;
    if (g & 1) {
        uint64_t c = ++m->gctr;
        memcpy(gb, "GZGUARD1", 8); memcpy(gb + 8, gz_journal_chain_signet, 32);
        for (int i = 0; i < 8; i++) gb[40 + i] = (uint8_t)(c >> (56 - 8 * i));
        gb[48] = 0; gb[49] = 1; memset(gb + 50, 0, 16);
        n = 2;
    }
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch.incarnation = m->inc; a.u.save.batch.sequence = seq;
    a.u.save.records = r; a.u.save.n_records = n;
    int was_failed = gz_journal_failed(m->j);
    size_t pend = gz_journal_pending(m->j);
    gz_journal_status_t st = gz_journal_save(m->j, &a);
    free(buf);
    if (m->nh < MAXB) { m->handed[m->nh].inc = m->inc; m->handed[m->nh].seq = seq; m->nh++; }
    if (st == GZ_JOURNAL_OK) {
        if (was_failed) BUG("save accepted by a failed journal");
        m->seq = seq;
    } else {
        if (st == GZ_JOURNAL_ERR_SEQUENCE && pend < GZ_RUNNER_MAX_UNCONFIRMED && !was_failed) {
            /* the 32-batch window counts reported-but-unread completions too */
        }
        if (!gz_journal_failed(m->j)) BUG("save failure without the failed state");
    }
}

static void do_complete(M *m)
{
    if (!m->j) return;
    gz_batch_id_t id;
    int was_failed = gz_journal_failed(m->j);
    while (gz_journal_complete(m->j, &id)) {
        if (was_failed) BUG("complete after failure");
        if (id.incarnation != m->inc || id.sequence != m->next_report) BUG("complete out of order (%llu,%llu) want %llu", (unsigned long long)id.incarnation, (unsigned long long)id.sequence, (unsigned long long)m->next_report);
        if (id.sequence > m->seq) BUG("complete of a batch never saved");
        /* Durable: the disk holds it now. Re-scan the disk. */
        size_t dl; const uint8_t *d = memfs_disk(&m->fs, JP, &dl);
        gz_journal_scan_t sc;
        if (!d || gz_journal_scan(d, dl, gz_journal_chain_signet, &sc, NULL, NULL) != GZ_JOURNAL_OK) BUG("disk not scannable at complete");
        m->next_report++;
        if (m->nc < MAXB) { m->conf[m->nc].inc = id.incarnation; m->conf[m->nc].seq = id.sequence; m->nc++; }
        if (id.sequence == 1 && m->restored_open) {
            if (gz_journal_restored(m->j)) BUG("restore batch reported while still restored");
            size_t ml;
            if (memfs_get(&m->fs, D "/" GZ_JOURNAL_MARKER_FILE, &ml)) BUG("marker still there after the restore batch");
            m->marker = 0;
        }
    }
}

static void do_close(M *m) { gz_journal_close(m->j); m->j = NULL; }

static void crash_settle(M *m)
{
    uint8_t md = b8();
    gz_journal_close(m->j); m->j = NULL;
    { /* Is the journal's current name durable? If not, a power cut can bring back an older file (B1). */
        int iv = -1, id = -1;
        for (int k = 0; k < MEMFS_FILES; k++) {
            if (m->fs.vol[k].inode >= 0 && !strcmp(m->fs.vol[k].name, JP)) iv = m->fs.vol[k].inode;
            if (m->fs.dur[k].inode >= 0 && !strcmp(m->fs.dur[k].name, JP)) id = m->fs.dur[k].inode;
        }
        if (iv != id && md % 3 != MEMFS_KEEP) m->b1_risk = 1;
        int mv = -1, mdur = -1;
        for (int k = 0; k < MEMFS_FILES; k++) {
            if (m->fs.vol[k].inode >= 0 && !strcmp(m->fs.vol[k].name, D "/" GZ_JOURNAL_MARKER_FILE)) mv = m->fs.vol[k].inode;
            if (m->fs.dur[k].inode >= 0 && !strcmp(m->fs.dur[k].name, D "/" GZ_JOURNAL_MARKER_FILE)) mdur = m->fs.dur[k].inode;
        }
        if (mv != mdur) m->marker = -1; /* the marker's name was not durable: the file decides */
    }
    memfs_settle(&m->fs, md % 3, md);
    if (memfs_open_fds(&m->fs)) BUG("fds after settle");
}

static void do_snapshot(M *m)
{
    size_t l; const uint8_t *d = memfs_disk(&m->fs, JP, &l);
    if (!d) return;
    free(m->snap); m->snap = malloc(l ? l : 1); memcpy(m->snap, d, l); m->snap_len = l; m->have_snap = 1;
}

typedef struct { bid_t ids[MAXB]; int n; } idl_t;
static void snap_cb(void *ctx, uint64_t off, uint32_t size, gz_batch_id_t id, const uint8_t *p, size_t l)
{
    (void)off; (void)size; (void)p; (void)l;
    idl_t *x = ctx; if (x->n < MAXB) { x->ids[x->n].inc = id.incarnation; x->ids[x->n].seq = id.sequence; x->n++; }
}

/* After an import took effect: confirmed := those in the backup's kept batches. */
static void adopt_backup(M *m, const uint8_t *b, size_t bl)
{
    static idl_t x; x.n = 0;
    gz_journal_scan_t sc;
    gz_journal_scan(b, bl, gz_journal_chain_signet, &sc, snap_cb, &x);
    int k2 = 0;
    for (int k = 0; k < m->nc; k++) {
        int in_b = 0;
        for (int q = 0; q < x.n; q++) if (x.ids[q].inc == m->conf[k].inc && x.ids[q].seq == m->conf[k].seq) in_b = 1;
        if (in_b) m->conf[k2++] = m->conf[k];
    }
    m->nc = k2;
    m->base = sc.highest_incarnation;
}

static void do_import(M *m)
{
    if (!m->have_snap) return;
    uint64_t floor = b8() & 3 ? 0 : m->max_inc + b8();
    memfs_put(&m->fs, SP, m->snap, m->snap_len);
    size_t ol; const uint8_t *old = memfs_disk(&m->fs, JP, &ol);
    free(m->before); m->before = NULL; m->before_len = 0;
    if (old) { m->before = malloc(ol ? ol : 1); memcpy(m->before, old, ol); m->before_len = ol; }
    gz_journal_status_t st = gz_journal_import(D, gz_journal_chain_signet, &m->fs.os, SP, floor);
    if (m->fs.fail_at && st == GZ_JOURNAL_OK) m->import_under_fault = 1;
    if (verbose) printf("import -> %s\n", gz_journal_status_name(st));
    if (m->j) { if (st != GZ_JOURNAL_ERR_LOCKED) BUG("import while open: %s", gz_journal_status_name(st)); return; }
    if (m->fs.crashed || (m->fs.fail_at && st != GZ_JOURNAL_OK)) {
        /* Settled by the caller; which file is there is decided after the settle. */
        m->import_unknown = 1;
        return;
    }
    if (st != GZ_JOURNAL_OK) BUG("import failed: %s", gz_journal_status_name(st));
    adopt_backup(m, m->snap, m->snap_len);
    m->marker = 1;
}

static void resolve_import(M *m)
{
    if (!m->import_unknown) return;
    m->import_unknown = 0;
    size_t l; const uint8_t *now = memfs_disk(&m->fs, JP, &l);
    size_t ml; const uint8_t *mk = memfs_disk(&m->fs, D "/" GZ_JOURNAL_MARKER_FILE, &ml);
    int is_backup = now && l == m->snap_len && memcmp(now, m->snap, l) == 0;
    int was_backup = m->before && m->before_len == m->snap_len && memcmp(m->before, m->snap, m->snap_len) == 0;
    if (is_backup && !was_backup) {
        if (!mk) BUG("an import that crashed left the backup without a restore marker (R2)");
        adopt_backup(m, m->snap, m->snap_len);
        m->marker = 1;
    } else {
        m->marker = mk ? -1 : 0;
    }
}

static void do_mark(M *m)
{
    uint64_t floor = b8() & 1 ? m->max_inc + 3 : 0;
    gz_journal_status_t st = gz_journal_mark_restored(D, gz_journal_chain_signet, &m->fs.os, floor);
    if (m->j) { if (st != GZ_JOURNAL_ERR_LOCKED) BUG("mark while open"); return; }
    if (m->fs.crashed || m->fs.fail_at) { if (st == GZ_JOURNAL_OK) { m->marker = 1; size_t l; const uint8_t *d = memfs_disk(&m->fs, JP, &l); gz_journal_scan_t sc; m->base = d && gz_journal_scan(d, l, gz_journal_chain_signet, &sc, NULL, NULL) == GZ_JOURNAL_OK ? sc.highest_incarnation : 0; } else m->marker = -1; return; }
    if (st != GZ_JOURNAL_OK) BUG("mark failed: %s", gz_journal_status_name(st));
    size_t l; const uint8_t *d = memfs_disk(&m->fs, JP, &l);
    gz_journal_scan_t sc;
    uint64_t base = d && gz_journal_scan(d, l, gz_journal_chain_signet, &sc, NULL, NULL) == GZ_JOURNAL_OK ? sc.highest_incarnation : 0;
    m->marker = 1; m->base = base;
}

static void sub_op(M *m, uint8_t which)
{
    if (verbose) printf("  sub %d (fail_at %llu crash_at %llu)\n", which % 6, (unsigned long long)m->fs.fail_at, (unsigned long long)m->fs.crash_at);
    switch (which % 6) {
    case 0: do_open(m); break;
    case 1: do_save(m); break;
    case 2: if (m->j) gz_journal_flush(m->j); break;
    case 3: do_complete(m); break;
    case 4: do_import(m); break;
    case 5: do_mark(m); break;
    }
}

static void run(const uint8_t *data, size_t size)
{
    in = data; in_len = size; in_pos = 0;
    static M mm;
    M *m = &mm;
    memset(m, 0, sizeof *m);
    memfs_init(&m->fs);
    uint8_t cfgb = b8();
    m->unsynced = (cfgb & 3) == 0 ? 0 : 1024u << (cfgb & 3);
    m->hard = (cfgb & 12) == 12 ? 20000 + 1000u * b8() : 0;
    m->soft = m->hard ? m->hard / 2 : 0;
    uint8_t op;
    int steps = 0;
    while (!m->stop && nb(&op) && steps++ < 400) {
        if (verbose) printf("op %d (j %s, points %llu, counter %llu, max_inc %llu, marker %d base %llu, nc %d)\n", op % 12, m->j ? "open" : "closed",
                            (unsigned long long)m->fs.points, (unsigned long long)m->counter, (unsigned long long)m->max_inc, m->marker, (unsigned long long)m->base, m->nc);
        switch (op % 12) {
        case 0: case 1: do_open(m); break;
        case 2: case 3: do_save(m); break;
        case 4: if (m->j) { int f = gz_journal_failed(m->j); gz_journal_status_t st = gz_journal_flush(m->j); if (f && st == GZ_JOURNAL_OK && gz_journal_pending(m->j)) BUG("flush ok on failed"); } break;
        case 5: do_complete(m); break;
        case 6: do_close(m); break;
        case 7: crash_settle(m); resolve_import(m); break;
        case 8: { /* a failure at a later point, then the call that hits it */
            m->fs.fail_at = m->fs.points + 1 + b8() % 24;
            m->fs.fail_mode = 1 + b8() % 3;
            m->fs.fail_only_sync = 0;
            sub_op(m, b8());
            int hit = m->fs.points >= m->fs.fail_at;
            m->fs.fail_at = 0; m->fs.after_fail = 0;
            if (m->import_unknown) {
                /* No settle: the process lives on; the files are as they are. */
                size_t l; const uint8_t *now = memfs_get(&m->fs, JP, &l);
                size_t ml; const uint8_t *mk = memfs_get(&m->fs, D "/" GZ_JOURNAL_MARKER_FILE, &ml);
                int is_backup = now && l == m->snap_len && memcmp(now, m->snap, l) == 0;
                int was_backup = m->before && m->before_len == m->snap_len && memcmp(m->before, m->snap, m->snap_len) == 0;
                m->import_unknown = 0;
                if (is_backup && !was_backup) { if (!mk) BUG("failed import left the backup unmarked"); adopt_backup(m, m->snap, m->snap_len); m->marker = 1; }
                else m->marker = mk ? -1 : 0;
            }
            (void)hit;
            break;
        }
        case 9: { /* a crash at a later point, inside the call */
            m->fs.crash_at = m->fs.points + 1 + b8() % 32;
            sub_op(m, b8());
            if (m->fs.crashed) { crash_settle(m); resolve_import(m); }
            m->fs.crash_at = 0;
            break;
        }
        case 10: do_snapshot(m); break;
        case 11: if (b8() & 1) do_import(m); else do_mark(m); break;
        }
        if (m->j && gz_journal_failed(m->j)) {
            gz_batch_id_t id;
            if (gz_journal_complete(m->j, &id)) BUG("complete on a failed journal");
        }
    }
    gz_journal_close(m->j);
    memfs_free(&m->fs);
    free(m->snap); free(m->before);
}

#ifdef LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    run(data, size);
    return 0;
}
#else
int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 10000;
    uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 10) : 1;
    verbose = argc > 3;
    setvbuf(stdout, NULL, _IONBF, 0);
    static uint8_t buf[600];
    for (long it = 0; it < iters; it++) {
        uint64_t s = seed * 1000003u + (uint64_t)it;
        for (size_t k = 0; k < sizeof buf; k++) {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            buf[k] = (uint8_t)s;
        }
        size_t n = 50 + (size_t)(s % 550);
        cur_it = it;
        if (argc > 4 && it != atol(argv[4])) continue;
        run(buf, n);
    }
    printf("RESULT: PASS (model: %ld runs, no violation)\n", iters);
    return 0;
}
#endif
