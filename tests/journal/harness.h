/* Shared by the journal's tests: a journal on the in-memory file system, the
 * real runner in front of it, a deterministic workload, and the check that
 * nothing confirmed or released was lost.
 *
 * The workload's step g submits [save B_g, send X_g]: a batch whose records
 * are a function of g alone, then a send that the runner must hold until B_g
 * is confirmed. Some batches hold a guard record whose counter is g. */
#ifndef GZ_TEST_JOURNAL_HARNESS_H
#define GZ_TEST_JOURNAL_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/runner.h"
#include "journal.h"
#include "memfs.h"
#include "superscalar/sha256.h"

#define H_DIR      "/node"
#define H_JOURNAL  H_DIR "/" GZ_JOURNAL_FILE
#define H_GUARD    H_DIR "/" GZ_JOURNAL_GUARD_FILE
#define H_MAX_STEP 4096

/* The salt of the first file a fresh memfs creates (its "random" source is a
 * counter), and of spec section 11's vectors. */
static const uint8_t h_salt[GZ_JOURNAL_SALT_LEN] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                                     11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                                                     22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

static inline uint64_t h_mix(uint64_t x)
{
    x += 0x9e3779b97f4a7c15ull;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
    return x ^ (x >> 31);
}

/* A guard record's bytes (spec 8.3, without the check), counter `counter`. */
static inline size_t h_guard_bytes(uint8_t *out, uint64_t counter)
{
    memcpy(out, "GZGUARD1", 8);
    memcpy(out + 8, gz_journal_chain_signet, 32);
    for (int i = 0; i < 8; i++) out[40 + i] = (uint8_t)(counter >> (56 - 8 * i));
    out[48] = 0; out[49] = 1;                           /* one epoch */
    memset(out + 50, 0, 8);                             /* epoch 0, highest index 0 */
    out[57] = (uint8_t)counter;
    memset(out + 58, 0, 8);                             /* rounds started */
    out[65] = (uint8_t)(counter >> 1);
    return 66;
}

/* The records of step g, in `buf`; returns the count (0 to 3). */
typedef struct {
    gz_record_t rec[4];
    uint8_t bytes[4][96];
} h_batch_t;

static inline size_t h_records(uint64_t g, h_batch_t *b, int guards)
{
    static const uint32_t types[] = {0x7e570001, 0x00020002, 0x00020006, 0x00010006, 0x7e570002,
                                     0x00030006};
    uint64_t r = h_mix(g * 7919 + 1);
    size_t n = (size_t)(r % 4);
    for (size_t i = 0; i < n; i++) {
        uint64_t q = h_mix(r + i);
        size_t len = (size_t)(q % 41);
        for (size_t k = 0; k < len; k++) b->bytes[i][k] = (uint8_t)h_mix(q + k);
        b->rec[i].type = types[(q >> 8) % 6];
        b->rec[i].bytes.data = len ? b->bytes[i] : NULL;
        b->rec[i].bytes.len = len;
    }
    if (guards && g % 5 == 3) {
        b->rec[n].type = GZ_RECORD_GUARD;
        b->rec[n].bytes.data = b->bytes[n];
        b->rec[n].bytes.len = h_guard_bytes(b->bytes[n], g);
        n++;
    }
    return n;
}

static inline void h_digest_records(const gz_record_t *r, size_t n, uint8_t out[32])
{
    uint8_t buf[4 * (8 + 96)], *p = buf;
    for (size_t i = 0; i < n; i++) {
        p[0] = (uint8_t)(r[i].type >> 24); p[1] = (uint8_t)(r[i].type >> 16);
        p[2] = (uint8_t)(r[i].type >> 8); p[3] = (uint8_t)r[i].type;
        p[4] = p[5] = p[6] = 0; p[7] = (uint8_t)r[i].bytes.len;
        if (r[i].bytes.len) memcpy(p + 8, r[i].bytes.data, r[i].bytes.len);
        p += 8 + r[i].bytes.len;
    }
    sha256(buf, (size_t)(p - buf), out);
}

typedef struct {
    memfs_t fs;
    gz_journal_t *j;
    gz_runner_t runner;
    gz_runner_slot_t slots[64];
    uint8_t rbytes[4096];
    int guards;
    uint64_t next_step;            /* the next g */
    /* Per step g, what happened (survives crashes; it is the test's memory). */
    gz_batch_id_t id[H_MAX_STEP];
    uint64_t end_after[H_MAX_STEP]; /* journal size after B_g was appended */
    uint8_t handed[H_MAX_STEP];     /* B_g given to the journal */
    uint8_t confirmed[H_MAX_STEP];  /* the node was told B_g is stored */
    uint8_t released[H_MAX_STEP];   /* X_g left */
    uint8_t synced[H_MAX_STEP];     /* the first sync covering B_g returned (for "rule removed") */
    uint64_t pending_step[64];      /* steps handed in this run, by sequence */
    uint64_t max_issued_incarnation;
    uint64_t inc;
    const gz_journal_os_t *os;      /* NULL: the memfs above */
    const char *dir;                /* with `os`: the real folder */
} h_t;

/* The guard file's bytes, from the memfs or the real folder. */
static inline const uint8_t *h_guard_file(h_t *h, size_t *len)
{
    static uint8_t buf[256];
    char path[300];
    if (!h->dir) return memfs_get(&h->fs, H_GUARD, len);
    snprintf(path, sizeof path, "%s/%s", h->dir, GZ_JOURNAL_GUARD_FILE);
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    *len = fread(buf, 1, sizeof buf, f);
    fclose(f);
    return buf;
}

static inline void h_on_sync(void *ctx, int inode, size_t durable_len)
{
    h_t *h = ctx;
    (void)inode;
    for (uint64_t g = 0; g < h->next_step; g++)
        if (h->handed[g] && h->id[g].incarnation == h->inc && h->end_after[g] <= durable_len)
            h->synced[g] = 1;
}

static inline void h_execute(void *ctx, const gz_action_t *a)
{
    h_t *h = ctx;
    if (a->kind == GZ_ACTION_SAVE) {
        uint64_t g = h->pending_step[a->u.save.batch.sequence % 64];
        h->id[g] = a->u.save.batch;
        h->handed[g] = 1;
        if (h->id[g].incarnation > h->max_issued_incarnation)
            h->max_issued_incarnation = h->id[g].incarnation;
        if (gz_journal_save(h->j, a) == GZ_JOURNAL_OK) h->end_after[g] = gz_journal_size(h->j);
    } else if (a->kind == GZ_ACTION_SEND) {
        h->released[a->u.send.peer_id] = 1;
    }
}

static inline void h_on_confirmed(void *ctx, gz_batch_id_t id)
{
    h_t *h = ctx;
    for (uint64_t g = 0; g < h->next_step; g++)
        if (h->handed[g] && h->id[g].incarnation == id.incarnation && h->id[g].sequence == id.sequence)
            h->confirmed[g] = 1;
}

/* Open the journal and a runner on it. */
static inline gz_journal_status_t h_open(h_t *h, gz_journal_open_info_t *info)
{
    gz_journal_config_t cfg = {h->dir ? h->dir : H_DIR, gz_journal_chain_signet, 1794000000000ull,
                               h->os ? h->os : &h->fs.os, 0, 0, 0, 0, 0, NULL, NULL};
    h->fs.on_sync = h_on_sync;
    h->fs.on_sync_ctx = h;
    gz_journal_status_t st = gz_journal_open(&h->j, &cfg, info);
    if (st != GZ_JOURNAL_OK) return st;
    h->inc = gz_journal_incarnation(h->j);
    gz_runner_init(&h->runner, h->slots, 64, h->rbytes, sizeof h->rbytes, h->inc, h_execute, h);
    gz_journal_attach(h->j, &h->runner, h_on_confirmed, h);
    return st;
}

/* Submit step g = next_step. */
static inline gz_status_t h_step(h_t *h)
{
    gz_action_t slots[2];
    uint8_t bytes[1024];
    gz_action_list_t list;
    h_batch_t b;
    uint64_t g = h->next_step++;
    gz_action_list_init(&list, slots, 2, bytes, sizeof bytes);
    gz_action_t save = {.kind = GZ_ACTION_SAVE};
    save.u.save.records = b.rec;
    save.u.save.n_records = h_records(g, &b, h->guards);
    gz_action_t send = {.kind = GZ_ACTION_SEND};
    send.u.send.peer_id = g;
    gz_action_list_add(&list, &save);
    gz_action_list_add(&list, &send);
    h->pending_step[(h->runner.issued + 1) % 64] = g;
    return gz_runner_submit(&h->runner, &list);
}

static inline void h_close(h_t *h)
{
    gz_journal_close(h->j);
    h->j = NULL;
}

/* Read the journal back and check: every confirmed or released batch is there
 * with its exact records; batches come in increasing identifier order; the
 * new incarnation is above every incarnation a batch was issued under; the
 * guard file is at least as new as every confirmed guard record. Returns the
 * number of problems, printing each. `oracle` 1 uses the "first sync
 * returned" notion of confirmed (the rule-removed run). */
static inline int h_verify(h_t *h, int oracle, int quiet)
{
    int bad = 0;
    gz_storage_reader_t rd = gz_journal_reader(h->j);
    gz_stored_batch_t sb;
    static uint8_t found[H_MAX_STEP];
    memset(found, 0, sizeof found);
    gz_batch_id_t last = {0, 0};
    while (rd.next(rd.ctx, &sb)) {
        if (sb.id.incarnation < last.incarnation ||
            (sb.id.incarnation == last.incarnation && sb.id.sequence <= last.sequence)) {
            if (!quiet) printf("  batch order broken at (%llu,%llu)\n",
                               (unsigned long long)sb.id.incarnation, (unsigned long long)sb.id.sequence);
            bad++;
        }
        last = sb.id;
        for (uint64_t g = 0; g < h->next_step; g++) {
            if (!h->handed[g] || h->id[g].incarnation != sb.id.incarnation ||
                h->id[g].sequence != sb.id.sequence)
                continue;
            h_batch_t b;
            uint8_t d1[32], d2[32];
            size_t n = h_records(g, &b, h->guards);
            h_digest_records(b.rec, n, d1);
            h_digest_records(sb.records, sb.n_records, d2);
            if (n != sb.n_records || memcmp(d1, d2, 32) != 0) {
                if (!quiet) printf("  batch of step %llu stored with other contents\n", (unsigned long long)g);
                bad++;
            }
            found[g] = 1;
        }
    }
    if (gz_journal_failed(h->j)) { if (!quiet) printf("  reader failed\n"); bad++; }
    uint64_t newest_guard = 0;
    int any_guard = 0;
    for (uint64_t g = 0; g < h->next_step; g++) {
        int must = oracle ? h->synced[g] : (h->confirmed[g] || h->released[g]);
        if (must && !found[g]) {
            if (!quiet) printf("  step %llu was %s but is missing\n", (unsigned long long)g,
                               h->released[g] ? "released" : "confirmed");
            bad++;
        }
        if (h->released[g] && !h->confirmed[g]) {
            if (!quiet) printf("  step %llu released before confirmation\n", (unsigned long long)g);
            bad++;
        }
        if (h->guards && h->confirmed[g] && g % 5 == 3) { newest_guard = g; any_guard = 1; }
    }
    if (h->runner.issued == 0 && h->inc <= h->max_issued_incarnation) {
        if (!quiet) printf("  incarnation %llu repeats one a batch was issued under\n", (unsigned long long)h->inc);
        bad++;
    }
    if (any_guard) {
        size_t len = 0;
        const uint8_t *gf = h_guard_file(h, &len);
        uint8_t c[32];
        if (!gf || len < 66) { if (!quiet) printf("  guard file missing\n"); bad++; }
        else {
            uint64_t counter = 0;
            for (int i = 0; i < 8; i++) counter = counter << 8 | gf[40 + i];
            sha256(gf, len - 8, c);
            if (memcmp(c, gf + len - 8, 8) != 0 || counter < newest_guard) {
                if (!quiet) printf("  guard file older than a confirmed guard record\n");
                bad++;
            }
        }
    }
    return bad;
}

#ifdef CHECK
static inline gz_journal_t *h_open_on(memfs_t *fs, gz_journal_status_t *st, gz_journal_open_info_t *info)
{
    gz_journal_t *j = NULL;
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 3, &fs->os, 0, 0, 0, 0, 0, NULL, NULL};
    *st = gz_journal_open(&j, &cfg, info);
    if (j) gz_journal_attach(j, NULL, NULL, NULL); /* nobody confirms */
    return j;
}

/* One open on `fs`, failed or crashed at point `p`. Returns the journal if
 * the open returned one. */
static inline gz_journal_t *h_open_attempt(memfs_t *fs, int crash, uint64_t p, gz_journal_status_t *st)
{
    if (crash) fs->crash_at = p;
    else { fs->fail_at = p; fs->fail_mode = MEMFS_FAIL_ERROR; }
    return h_open_on(fs, st, NULL);
}

/* Every point of an open that creates the file, or that cuts a torn tail,
 * failed (crash 0) or crashed (crash 1) in turn, then the disk settled as
 * `mode`. The next clean open must succeed, and the file must be a valid
 * journal that still holds what the seed had durable. */
static inline int open_points(const uint8_t *seed, size_t seed_len, int crash, int mode)
{
    int runs = 0;
    for (uint64_t p = 1;; p++) {
        memfs_t fs;
        memfs_init(&fs);
        if (seed) memfs_put(&fs, H_JOURNAL, seed, seed_len);
        gz_journal_status_t st;
        gz_journal_t *j = h_open_attempt(&fs, crash, p, &st);
        int hit = crash ? fs.crashed : fs.points >= p;
        gz_journal_close(j);
        if (!hit) { memfs_free(&fs); return runs; }
        if (!crash) {
            /* A failed open returns an error and leaves no descriptor open. */
            CHECK(st != GZ_JOURNAL_OK && memfs_open_fds(&fs) == 0 && fs.bad_closes == 0);
            /* ... and writes or syncs nothing after the failure (an unlink to clean up may follow). */
            CHECK(fs.after_fail == 0);
        }
        memfs_settle(&fs, mode, p);
        gz_journal_open_info_t info;
        gz_journal_t *k = h_open_on(&fs, &st, &info);
        int ok = st == GZ_JOURNAL_OK && info.incarnation >= 1;
        if (k) {
            size_t len;
            const uint8_t *d = memfs_get(&fs, H_JOURNAL, &len);
            gz_journal_scan_t s;
            ok = ok && gz_journal_scan(d, len, gz_journal_chain_signet, &s, NULL, NULL) == GZ_JOURNAL_OK &&
                 s.verdict == GZ_JOURNAL_CLEAN && s.highest_incarnation == info.incarnation;
            /* The seed's batch (1, 1) was durable before: still there. */
            if (seed) ok = ok && s.n_batches == 1 && info.incarnation >= 2;
        }
        if (!ok) printf("  open %s at point %llu (mode %d): %s\n", crash ? "crash" : "failure",
                        (unsigned long long)p, mode, gz_journal_status_name(st));
        CHECK(ok);
        gz_journal_close(k);
        memfs_free(&fs);
        runs++;
    }
}

#endif

#endif
