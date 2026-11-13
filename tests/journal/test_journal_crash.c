/* Crash and power-loss sweeps (spec/journal.md tests 11, 14, 25 to 27, and
 * the "kill at every point" requirement).
 *
 *   1. The writer is crashed before every write and sync point of a run that
 *      starts from a journal with a torn tail (so the cut and the new
 *      incarnation are inside the run), and the disk is settled as LOSE,
 *      KEEP and three REORDER draws. The next open must succeed, keep every
 *      confirmed and released batch with its exact records, never reuse an
 *      incarnation a batch was issued under, and keep the guard file at
 *      least as new as every confirmed guard record.
 *   2. The same crashes with a bit flipped in the last batch after the last
 *      durable mark: the correct rule loses nothing. RULE REMOVED: counting a
 *      batch as confirmed once its first sync returns, the same sweep must
 *      find a confirmed batch cut. If it does not, the test fails.
 *   3. Real processes on real files: a child is killed (_exit) before each
 *      point, the parent reopens and checks the same properties.
 *   4. The real placeholder node, runner and journal, crashed at every point:
 *      no reply leaves before its ping is durable, and after a clean start
 *      every durable ping has had its reply sent.
 *
 * A crash is modelled by memfs: from the crash point on, every write and
 * sync fails and changes nothing, so the program unwinds and frees normally
 * and this test runs under the leak checkers like the others. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../check.h"
#include "gazpacho/node.h"
#include "harness.h"

#define STEPS 15

/* The starting disk: one run of 6 steps, the last ones unflushed, settled
 * REORDER: a journal with history and a torn tail. */
static void seed_disk(h_t *h)
{
    h->guards = 1;
    h_open(h, NULL);
    for (int s = 0; s < 6; s++) {
        h_step(h);
        if (s == 2) gz_journal_flush(h->j);
    }
    gz_journal_close(h->j);
    memfs_settle(&h->fs, MEMFS_REORDER, 11);
}

/* One run from the seeded disk, crashed before point `crash_at` (0: none).
 * Returns the number of points the run passed. */
static uint64_t crash_run(h_t *h, uint64_t crash_at)
{
    h->j = NULL; /* a copy of the seeding run's, already closed */
    h->fs.points = 0;
    h->fs.crash_at = crash_at;
    if (h_open(h, NULL) == GZ_JOURNAL_OK) {
        for (int s = 0; s < STEPS; s++) {
            h_step(h);
            if (s % 3 != 0) gz_journal_flush(h->j);
        }
        gz_journal_flush(h->j);
        gz_journal_close(h->j);
        h->j = NULL;
    }
    h->fs.crash_at = 0;
    return h->fs.points;
}

/* Offset of the last batch entry after the last sync mark, or 0. */
static uint64_t last_unmarked_batch(const uint8_t *d, size_t len)
{
    uint64_t p = GZ_JOURNAL_HEADER_LEN, last = 0;
    while (p + 21 <= len) {
        uint32_t l = (uint32_t)d[p] << 24 | (uint32_t)d[p + 1] << 16 | (uint32_t)d[p + 2] << 8 | d[p + 3];
        if (p + 12 + l > len) break;
        if (d[p + 4] == GZ_JOURNAL_KIND_MARK) last = 0;
        if (d[p + 4] == GZ_JOURNAL_KIND_BATCH) last = p;
        p += 12 + l;
    }
    return last;
}

static int sweep_points, sweep_runs, sweep_bad, removed_losses, flip_runs, sweep_crashed, sweep_cut;
static int node_resent, sweep_attempts;

static void sweep(void)
{
    static h_t base, h;
    memfs_init(&base.fs);
    seed_disk(&base);
    /* Count the points of an uncrashed run. */
    h = base;
    memfs_copy(&h.fs, &base.fs);
    uint64_t total = crash_run(&h, 0);
    memfs_free(&h.fs);
    sweep_points = (int)total;
    for (uint64_t p = 1; p <= total; p++) {
        for (int v = 0; v < 5; v++) {
            int mode = v < 2 ? v : MEMFS_REORDER;
            for (int flip = 0; flip < 2; flip++) {
                if (flip && mode == MEMFS_KEEP) continue;
                h = base;
                memfs_copy(&h.fs, &base.fs);
                crash_run(&h, p);
                sweep_crashed += h.fs.crashed;
                sweep_attempts++;
                memfs_settle(&h.fs, mode, p * 31 + (uint64_t)v);
                if (flip) {
                    size_t len;
                    const uint8_t *d = memfs_get(&h.fs, H_JOURNAL, &len);
                    uint64_t at = d ? last_unmarked_batch(d, len) : 0;
                    if (!at) { memfs_free(&h.fs); continue; }
                    ((uint8_t *)d)[at + 22] ^= 0x40; /* external damage, unsynced part */
                    flip_runs++;
                }
                gz_journal_open_info_t info;
                gz_journal_status_t st = h_open(&h, &info);
                sweep_runs++;
                if (st != GZ_JOURNAL_OK) {
                    printf("  point %llu mode %d flip %d: open %s\n", (unsigned long long)p, mode, flip,
                           gz_journal_status_name(st));
                    sweep_bad++;
                } else {
                    sweep_cut += info.cut_bytes > 0;
                    int bad = h_verify(&h, 0, 0);
                    if (bad) printf("  point %llu mode %d flip %d: %d problems\n", (unsigned long long)p, mode, flip, bad);
                    sweep_bad += bad;
                    if (flip) removed_losses += h_verify(&h, 1, 1) > 0;
                    /* The node carries on: later batches are kept too. */
                    for (int s = 0; s < 3; s++) h_step(&h);
                    gz_journal_flush(h.j);
                    sweep_bad += h_verify(&h, 0, 0);
                    h_close(&h);
                }
                memfs_free(&h.fs);
            }
        }
    }
    memfs_free(&base.fs);
}

/* --- 3. real processes ---------------------------------------------------- */

typedef struct {
    uint64_t points, kill_at;
} kill_ctx_t;
static kill_ctx_t kctx;
static const gz_journal_os_t *px;

static void kpoint(void) { if (++kctx.points == kctx.kill_at) _exit(0); }
static int k_open(void *c, const char *p, int how)
{
    if (how >= GZ_JOURNAL_OPEN_CREATE_EXCL) kpoint();
    return px->open(c, p, how);
}
static long k_pwrite(void *c, int fd, const void *b, size_t n, uint64_t o) { kpoint(); return px->pwrite(c, fd, b, n, o); }
static int k_sync(void *c, int fd) { kpoint(); return px->sync(c, fd); }
static int k_sync_dir(void *c, const char *d) { kpoint(); return px->sync_dir(c, d); }
static int k_truncate(void *c, int fd, uint64_t n) { kpoint(); return px->truncate(c, fd, n); }
static int k_link(void *c, const char *a, const char *b) { kpoint(); return px->link(c, a, b); }
static int k_rename(void *c, const char *a, const char *b) { kpoint(); return px->rename(c, a, b); }
static int k_unlink(void *c, const char *a) { kpoint(); return px->unlink(c, a); }

static int kill_sweep(void)
{
    px = gz_journal_os_posix();
    gz_journal_os_t kos = *px;
    kos.open = k_open; kos.pwrite = k_pwrite; kos.sync = k_sync; kos.sync_dir = k_sync_dir;
    kos.truncate = k_truncate; kos.link = k_link; kos.rename = k_rename; kos.unlink = k_unlink;
    char dir[] = "/tmp/gzj-kill-XXXXXX";
    if (!mkdtemp(dir)) return -1;
    char path[300], gpath[300];
    snprintf(path, sizeof path, "%s/%s", dir, GZ_JOURNAL_FILE);
    snprintf(gpath, sizeof gpath, "%s/%s", dir, GZ_JOURNAL_GUARD_FILE);
    h_t *h = mmap(NULL, sizeof *h, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    int runs = 0;
    for (uint64_t k = 1;; k++) {
        unlink(path);
        unlink(gpath);
        memset(h, 0, sizeof *h);
        h->guards = 1;
        h->dir = dir;
        pid_t pid = fork();
        if (pid == 0) {
            /* Two incarnations, the second killed at point k. */
            h->os = px;
            if (h_open(h, NULL) != GZ_JOURNAL_OK) _exit(2);
            for (int s = 0; s < 4; s++) { h_step(h); gz_journal_flush(h->j); }
            gz_journal_close(h->j);
            kctx.points = 0;
            kctx.kill_at = k;
            h->os = &kos;
            if (h_open(h, NULL) != GZ_JOURNAL_OK) _exit(2);
            for (int s = 0; s < STEPS; s++) {
                h_step(h);
                if (s % 2) gz_journal_flush(h->j);
            }
            gz_journal_flush(h->j);
            _exit(1); /* not killed: past the last point */
        }
        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) == 2) { runs = -1; break; }
        h->os = px;
        if (h_open(h, NULL) != GZ_JOURNAL_OK || h_verify(h, 0, 0) != 0) {
            printf("  kill at point %llu: lost or refused\n", (unsigned long long)k);
            runs = -1 - runs;
            if (h->j) h_close(h);
            break;
        }
        h_close(h);
        if (WEXITSTATUS(status) == 1) break;
        runs++;
    }
    unlink(path);
    unlink(gpath);
    rmdir(dir);
    munmap(h, sizeof *h);
    return runs;
}

/* --- 4. the real node ----------------------------------------------------- */

#define NODE_PINGS 4096
typedef struct {
    memfs_t fs;
    gz_journal_t *j;
    gz_runner_t runner;
    gz_runner_slot_t slots[64];
    uint8_t rbytes[8192];
    gz_node_t node;
    uint64_t next_ping, clock, rnd;
    uint8_t replied[NODE_PINGS];
    int failed;
} node_h_t;

static void n_fill(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    node_h_t *n = ctx;
    (void)purpose;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)h_mix(n->rnd++);
}
static uint64_t n_now(void *ctx) { return ++((node_h_t *)ctx)->clock; }

static void n_execute(void *ctx, const gz_action_t *a)
{
    node_h_t *n = ctx;
    if (a->kind == GZ_ACTION_SAVE) gz_journal_save(n->j, a);
    if (a->kind == GZ_ACTION_SEND && a->u.send.bytes.len == 12 && !memcmp(a->u.send.bytes.data, "GZPO", 4)) {
        uint64_t id = 0;
        for (int i = 4; i < 12; i++) id = id << 8 | a->u.send.bytes.data[i];
        if (id < NODE_PINGS) n->replied[id] = 1;
    }
}

static void n_submit(node_h_t *n, gz_action_list_t *list)
{
    gz_status_t st = gz_runner_submit(&n->runner, list);
    if (st != GZ_OK) n->failed = 1;
}

static void n_confirmed(void *ctx, gz_batch_id_t id)
{
    node_h_t *n = ctx;
    gz_action_t slots[16];
    uint8_t bytes[2048];
    gz_action_list_t list;
    gz_action_list_init(&list, slots, 16, bytes, sizeof bytes);
    gz_event_t ev = {.kind = GZ_EVENT_STORAGE_CONFIRMED};
    ev.u.storage.batch = id;
    if (gz_node_handle(&n->node, &ev, &list) != GZ_OK) n->failed = 1;
    else n_submit(n, &list);
}

/* Start the node from its journal and give it `pings` pings. Returns 0, or 1
 * if the open was refused. */
static int node_run(node_h_t *n, int pings)
{
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 7, &n->fs.os, 0, 0, 0, 0};
    if (gz_journal_open(&n->j, &cfg, NULL) != GZ_JOURNAL_OK) return 1;
    gz_runner_init(&n->runner, n->slots, 64, n->rbytes, sizeof n->rbytes, gz_journal_incarnation(n->j),
                   n_execute, n);
    gz_journal_attach(n->j, &n->runner, n_confirmed, n);
    gz_ports_t ports = {{n_fill, n}, {n_now, n}};
    gz_node_init(&n->node, &ports);
    gz_storage_reader_t rd = gz_journal_reader(n->j);
    gz_action_t slots[64];
    uint8_t bytes[8192];
    gz_action_list_t list;
    int more = 1, guard = 0;
    while (more && !n->failed && guard++ < 10000) {
        gz_action_list_init(&list, slots, 64, bytes, sizeof bytes);
        gz_status_t st = gz_node_start(&n->node, &rd, &list, &more);
        if (st == GZ_WAITING) { gz_journal_flush(n->j); continue; }
        if (st != GZ_OK) { n->failed = 1; break; }
        n_submit(n, &list);
    }
    gz_journal_flush(n->j);
    for (int i = 0; i < pings && !n->failed && n->next_ping < NODE_PINGS; i++) {
        uint8_t msg[12] = {'G', 'Z', 'P', 'I'};
        uint64_t id = n->next_ping++;
        for (int k = 0; k < 8; k++) msg[4 + k] = (uint8_t)(id >> (56 - 8 * k));
        gz_event_t ev = {.kind = GZ_EVENT_MESSAGE_RECEIVED};
        ev.u.message.peer_id = 7;
        ev.u.message.bytes.data = msg;
        ev.u.message.bytes.len = 12;
        gz_action_list_init(&list, slots, 64, bytes, sizeof bytes);
        if (gz_node_handle(&n->node, &ev, &list) == GZ_OK) n_submit(n, &list);
        if (i % 2) gz_journal_flush(n->j);
    }
    gz_journal_flush(n->j);
    return 0;
}

/* Every ping id durable in the journal: 1 in `out`. */
static void durable_pings(node_h_t *n, uint8_t *out)
{
    gz_storage_reader_t rd = gz_journal_reader(n->j);
    gz_stored_batch_t sb;
    while (rd.next(rd.ctx, &sb))
        for (size_t i = 0; i < sb.n_records; i++)
            if (sb.records[i].type == GZ_RECORD_TEST_PING && sb.records[i].bytes.len == 32) {
                uint64_t id = 0;
                for (int k = 24; k < 32; k++) id = id << 8 | sb.records[i].bytes.data[k];
                if (id < NODE_PINGS) out[id] = 1;
            }
}

/* One run crashed before point `p`; 1 if it crashed. */
static int node_crash_run(node_h_t *n, uint64_t p)
{
    n->j = NULL;
    n->fs.points = 0;
    n->fs.crash_at = p;
    node_run(n, 10);
    return n->fs.crashed;
}

static int node_sweep(int *runs)
{
    static node_h_t n;
    int bad = 0;
    *runs = 0;
    for (uint64_t p = 1;; p++) {
        for (int mode = 0; mode < 3; mode++) {
            memset(&n, 0, sizeof n);
            memfs_init(&n.fs);
            node_run(&n, 6); /* history */
            gz_journal_close(n.j);
            int crashed = node_crash_run(&n, p);
            gz_journal_close(n.j);
            n.j = NULL;
            if (!crashed) { memfs_free(&n.fs); return bad; }
            memfs_settle(&n.fs, mode, p);
            uint8_t sent_before[NODE_PINGS];
            memcpy(sent_before, n.replied, sizeof sent_before);
            n.failed = 0;
            if (node_run(&n, 0) != 0 || n.failed) { bad++; printf("  node: start after crash %llu failed\n", (unsigned long long)p); }
            else {
                static uint8_t dur[NODE_PINGS];
                memset(dur, 0, sizeof dur);
                durable_pings(&n, dur);
                for (int i = 0; i < NODE_PINGS; i++) {
                    if (sent_before[i] && !dur[i]) { bad++; printf("  node: reply %d sent, ping not durable\n", i); }
                    if (dur[i] && !n.replied[i]) { bad++; printf("  node: durable ping %d never answered\n", i); }
                    node_resent += dur[i] && !sent_before[i] && n.replied[i];
                }
            }
            (*runs)++;
            gz_journal_close(n.j);
            memfs_free(&n.fs);
        }
    }
}

/* Every point of an open that creates the file, and of one that cuts a torn
 * tail, crashed under each settle (the failed variant is in test_journal_edges.c). */
static void open_crashes(void)
{
    uint8_t torn[300];
    size_t n = gz_journal_encode_header(torn, gz_journal_chain_signet);
    n += gz_journal_encode_small(torn + n, 1, 1, 0);
    n += gz_journal_encode_small(torn + n, 3, 1, n);
    gz_record_t r = {0x7e570001, {(const uint8_t *)"abcd", 4}};
    n += gz_journal_encode_batch(torn + n, (gz_batch_id_t){1, 1}, &r, 1);
    n += gz_journal_encode_small(torn + n, 3, 1, n);
    n += gz_journal_encode_batch(torn + n, (gz_batch_id_t){1, 2}, &r, 1) - 5;
    int runs = 0;
    for (int seeded = 0; seeded < 2; seeded++)
        for (int mode = 0; mode < 3; mode++) runs += open_points(seeded ? torn : NULL, n, 1, mode);
    printf("  open crash points: %d runs\n", runs);
    CHECK(runs >= 45); /* 10 points creating, 6 cutting, three settles each */
}

int main(void)
{
    open_crashes();
    sweep();
    printf("  writer crash sweep: %d points, %d reopenings, %d with a flipped unsynced batch\n",
           sweep_points, sweep_runs, flip_runs);
    printf("  of those: %d crashed as planned, %d found a torn tail to cut\n", sweep_crashed, sweep_cut);
    CHECK(sweep_points > 60 && sweep_bad == 0 && sweep_cut > 0 && sweep_crashed == sweep_attempts);
    printf("  rule removed (confirm at the first sync): %d crash points lose a 'confirmed' batch\n",
           removed_losses);
    CHECK(removed_losses > 0);
    int k = kill_sweep();
    printf("  process kill sweep: %d kill points\n", k);
    CHECK(k > 40);
    int runs;
    int nb = node_sweep(&runs);
    printf("  node crash sweep: %d runs, %d replies first sent by a restarted node\n", runs, node_resent);
    CHECK(nb == 0 && runs > 100 && node_resent > 0);
    return check_done();
}
