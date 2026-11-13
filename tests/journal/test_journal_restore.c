/* The restore marker and pull mode (ports.h: the restore marker and the
 * fence; program.md section 4: complete()).
 *
 *   1. A marked journal starts restored, start after start, with incarnations
 *      above the floor, until the batch with sequence 1 of a marked start is
 *      durable; then the marker file is gone and later starts are not.
 *   2. Crashed at every point of a marked start that saves its answer, under
 *      each settle: the next start is restored exactly when the answer is not
 *      durable, and never unmarked without it.
 *   3. A damaged marker is refused; marking a refused journal is refused; a
 *      second mark keeps the higher floor.
 *   4. The real placeholder node, started restored: its first batch, sequence
 *      1, is its restore batch, and the marker goes once it is durable.
 *   5. Pull mode: complete() reports every durable batch once, oldest first,
 *      after the guard file is written; the program's own confirmations
 *      release the sends; the file is byte for byte what runner mode writes.
 *   6. The fence: batches of earlier incarnations never appear after the
 *      first read, only this incarnation's as they become durable. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../check.h"
#include "gazpacho/node.h"
#include "harness.h"

#define H_MARKER H_DIR "/" GZ_JOURNAL_MARKER_FILE

static gz_journal_t *jopen(memfs_t *fs, int pull, gz_journal_status_t *st, gz_journal_open_info_t *info)
{
    gz_journal_t *j = NULL;
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 11, &fs->os, 0, 0, 0, pull};
    *st = gz_journal_open(&j, &cfg, info);
    return j;
}

static gz_journal_status_t save1(gz_journal_t *j, uint64_t inc, uint64_t seq, uint32_t type)
{
    static const uint8_t b[4] = {1, 2, 3, 4};
    gz_record_t r = {type, {b, 4}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.batch = (gz_batch_id_t){inc, seq};
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    return gz_journal_save(j, &a);
}

static int has_marker(memfs_t *fs)
{
    size_t len;
    return memfs_get(fs, H_MARKER, &len) != NULL;
}

/* A journal with two incarnations and a batch in each. */
static void history(memfs_t *fs)
{
    gz_journal_status_t st;
    for (int i = 0; i < 2; i++) {
        gz_journal_t *j = jopen(fs, 0, &st, NULL);
        save1(j, gz_journal_incarnation(j), 1, 0x7e570001);
        gz_journal_flush(j);
        gz_journal_close(j);
    }
}

static void test_marker(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    gz_journal_open_info_t info;
    memfs_init(&fs);
    history(&fs);
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 5) == GZ_JOURNAL_OK);
    CHECK(has_marker(&fs));
    /* Two starts that save nothing: still restored, above the floor. */
    for (uint64_t want = 6; want <= 7; want++) {
        gz_journal_t *j = jopen(&fs, 0, &st, &info);
        gz_storage_reader_t rd = gz_journal_reader(j);
        CHECK(st == GZ_JOURNAL_OK && info.restored && rd.restored == 1 && gz_journal_restored(j) &&
              info.incarnation == want);
        gz_journal_close(j);
    }
    /* A start that saves its answer clears the marker. */
    gz_journal_t *j = jopen(&fs, 0, &st, &info);
    CHECK(info.restored && info.incarnation == 8);
    CHECK(save1(j, 8, 1, GZ_RECORD_TEST_RESTORED) == GZ_JOURNAL_OK && gz_journal_restored(j));
    CHECK(gz_journal_flush(j) == GZ_JOURNAL_OK && !gz_journal_restored(j) && !has_marker(&fs));
    gz_storage_reader_t rd = gz_journal_reader(j);
    CHECK(rd.restored == 0);
    gz_journal_close(j);
    j = jopen(&fs, 0, &st, &info);
    CHECK(st == GZ_JOURNAL_OK && !info.restored && info.incarnation == 9);
    gz_journal_close(j);
    /* Without a floor the numbering just goes on. */
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_OK);
    j = jopen(&fs, 0, &st, &info);
    CHECK(info.restored && info.incarnation == 10);
    gz_journal_close(j);
    memfs_free(&fs);

    /* Damaged markers are refused, and the journal is left untouched. */
    for (int how = 0; how < 4; how++) {
        memfs_init(&fs);
        history(&fs);
        CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_OK);
        size_t len, jlen;
        const uint8_t *m = memfs_get(&fs, H_MARKER, &len);
        uint8_t copy[80];
        memcpy(copy, m, len);
        if (how == 0) copy[3] ^= 1;   /* magic */
        if (how == 1) copy[20] ^= 1;  /* chain */
        if (how == 2) copy[45] ^= 1;  /* base, check now wrong */
        memfs_put(&fs, H_MARKER, copy, how == 3 ? len - 1 : len);
        memfs_get(&fs, H_JOURNAL, &jlen);
        j = jopen(&fs, 0, &st, NULL);
        size_t after;
        memfs_get(&fs, H_JOURNAL, &after);
        CHECK(st == GZ_JOURNAL_ERR_MARKER && j == NULL && after == jlen);
        memfs_free(&fs);
    }
    /* Marking: a refused journal, a missing one, and the higher floor kept. */
    memfs_init(&fs);
    history(&fs);
    size_t len;
    const uint8_t *cur = memfs_get(&fs, H_JOURNAL, &len);
    uint8_t *bad = malloc(len);
    memcpy(bad, cur, len);
    bad[0] ^= 1;
    memfs_put(&fs, H_JOURNAL, bad, len);
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_ERR_HEADER &&
          !has_marker(&fs));
    bad[0] ^= 1;
    memfs_put(&fs, H_JOURNAL, bad, len);
    free(bad);
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_mainnet, &fs.os, 0) == GZ_JOURNAL_ERR_NETWORK);
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 9) == GZ_JOURNAL_OK);
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 4) == GZ_JOURNAL_OK);
    j = jopen(&fs, 0, &st, &info);
    CHECK(info.restored && info.incarnation == 10);
    gz_journal_close(j);
    CHECK(gz_journal_mark_restored(NULL, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_ERR_ARGUMENT);
    memfs_free(&fs);
    memfs_init(&fs);
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_ERR_IO);
    memfs_free(&fs);
}

/* 2. Crashes around the answer. */
static void test_marker_crashes(void)
{
    int runs = 0, bad = 0, answered = 0, unanswered = 0;
    for (uint64_t p = 1;; p++) {
        int hit = 0;
        for (int mode = 0; mode < 3; mode++) {
            memfs_t fs;
            gz_journal_status_t st;
            gz_journal_open_info_t info;
            memfs_init(&fs);
            history(&fs);
            gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0);
            fs.points = 0;
            fs.crash_at = p;
            gz_journal_t *j = jopen(&fs, 0, &st, &info);
            if (j) {
                save1(j, info.incarnation, 1, GZ_RECORD_TEST_RESTORED);
                save1(j, info.incarnation, 2, 0x7e570001);
                gz_journal_flush(j);
                gz_journal_close(j);
            }
            hit = fs.crashed;
            if (!hit) { memfs_free(&fs); break; }
            memfs_settle(&fs, mode, p);
            j = jopen(&fs, 0, &st, &info);
            /* Is the answer durable? A batch with sequence 1 above incarnation 2. */
            int durable = 0;
            if (j) {
                gz_storage_reader_t rd = gz_journal_reader(j);
                gz_stored_batch_t sb;
                while (rd.next(rd.ctx, &sb)) durable |= sb.id.incarnation > 2 && sb.id.sequence == 1;
            }
            int ok = st == GZ_JOURNAL_OK && info.restored == !durable && has_marker(&fs) == !durable;
            if (!ok) printf("  marker crash at %llu mode %d: restored %d, answer durable %d\n",
                            (unsigned long long)p, mode, info.restored, durable);
            bad += !ok;
            answered += durable;
            unanswered += !durable;
            gz_journal_close(j);
            memfs_free(&fs);
            runs++;
        }
        if (!hit) break;
    }
    printf("  restore marker crash points: %d runs, %d answered, %d not\n", runs, answered, unanswered);
    CHECK(bad == 0 && runs > 15 && answered > 0 && unanswered > 0);
}

/* 4. The real node. */
typedef struct {
    gz_journal_t *j;
    gz_runner_t runner;
    gz_runner_slot_t slots[64];
    uint8_t rbytes[8192];
    gz_node_t node;
    uint64_t rnd, clock;
    gz_batch_id_t first_id;
    uint32_t first_type;
    int saves;
} nd_t;

static void nd_fill(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    nd_t *n = ctx;
    (void)purpose;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)h_mix(++n->rnd);
}
static uint64_t nd_now(void *ctx) { return ++((nd_t *)ctx)->clock; }
static void nd_exec(void *ctx, const gz_action_t *a)
{
    nd_t *n = ctx;
    if (a->kind != GZ_ACTION_SAVE) return;
    if (n->saves++ == 0) {
        n->first_id = a->u.save.batch;
        n->first_type = a->u.save.n_records ? a->u.save.records[0].type : 0;
    }
    gz_journal_save(n->j, a);
}
static void nd_confirmed(void *ctx, gz_batch_id_t id)
{
    nd_t *n = ctx;
    gz_action_t slots[16];
    uint8_t bytes[2048];
    gz_action_list_t list;
    gz_action_list_init(&list, slots, 16, bytes, sizeof bytes);
    gz_event_t ev = {.kind = GZ_EVENT_STORAGE_CONFIRMED};
    ev.u.storage.batch = id;
    if (gz_node_handle(&n->node, &ev, &list) == GZ_OK) gz_runner_submit(&n->runner, &list);
}

static int nd_start(nd_t *n, memfs_t *fs)
{
    gz_journal_status_t st;
    memset(n, 0, sizeof *n);
    n->j = jopen(fs, 0, &st, NULL);
    if (!n->j) return -1;
    gz_runner_init(&n->runner, n->slots, 64, n->rbytes, sizeof n->rbytes, gz_journal_incarnation(n->j),
                   nd_exec, n);
    gz_journal_attach(n->j, &n->runner, nd_confirmed, n);
    gz_ports_t ports = {{nd_fill, n}, {nd_now, n}};
    gz_node_init(&n->node, &ports);
    gz_storage_reader_t rd = gz_journal_reader(n->j);
    gz_action_t slots[64];
    uint8_t bytes[8192];
    gz_action_list_t list;
    int more = 1, steps = 0;
    while (more && steps++ < 1000) {
        gz_action_list_init(&list, slots, 64, bytes, sizeof bytes);
        gz_status_t s = gz_node_start(&n->node, &rd, &list, &more);
        if (s == GZ_WAITING) { gz_journal_flush(n->j); continue; }
        if (s != GZ_OK || gz_runner_submit(&n->runner, &list) != GZ_OK) return -2;
    }
    gz_journal_flush(n->j);
    return more ? -3 : 0;
}

static void test_node(void)
{
    static nd_t n;
    memfs_t fs;
    memfs_init(&fs);
    CHECK(nd_start(&n, &fs) == 0 && (n.saves == 0 || n.first_type != GZ_RECORD_TEST_RESTORED));
    gz_journal_close(n.j);
    CHECK(gz_journal_mark_restored(H_DIR, gz_journal_chain_signet, &fs.os, 0) == GZ_JOURNAL_OK);
    CHECK(nd_start(&n, &fs) == 0);
    CHECK(n.saves >= 1 && n.first_id.sequence == 1 && n.first_type == GZ_RECORD_TEST_RESTORED);
    CHECK(!gz_journal_restored(n.j) && !has_marker(&fs) && !gz_journal_failed(n.j));
    gz_journal_close(n.j);
    CHECK(nd_start(&n, &fs) == 0 && !gz_journal_restored(n.j) &&
          (n.saves == 0 || n.first_type != GZ_RECORD_TEST_RESTORED));
    gz_journal_close(n.j);
    memfs_free(&fs);
}

/* 5. Pull mode. */
static void run_workload(h_t *h, int pull, int *order_ok, int *guard_ok)
{
    gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 1794000000000ull, &h->fs.os, 0, 0, 0, pull};
    h->fs.on_sync = h_on_sync;
    h->fs.on_sync_ctx = h;
    gz_journal_open(&h->j, &cfg, NULL);
    h->inc = gz_journal_incarnation(h->j);
    gz_runner_init(&h->runner, h->slots, 64, h->rbytes, sizeof h->rbytes, h->inc, h_execute, h);
    if (!pull) gz_journal_attach(h->j, &h->runner, h_on_confirmed, h);
    uint64_t last = 0;
    *order_ok = *guard_ok = 1;
    for (int s = 0; s < 40; s++) {
        h_step(h);
        if (s % 4 != 3) continue;
        if (!pull) { gz_journal_flush(h->j); continue; }
        gz_batch_id_t id;
        while (gz_journal_complete(h->j, &id)) {
            *order_ok &= id.sequence == last + 1;
            last = id.sequence;
            /* A batch with a guard record is reported only after the guard file has it. */
            uint64_t g = h->pending_step[id.sequence % 64];
            if (g % 5 == 3) {
                size_t len;
                const uint8_t *gf = memfs_get(&h->fs, H_GUARD, &len);
                uint64_t counter = 0;
                for (int i = 0; gf && i < 8; i++) counter = counter << 8 | gf[40 + i];
                *guard_ok &= gf && counter >= g;
            }
            *order_ok &= !h->released[g];
            if (gz_runner_confirm(&h->runner, id) == GZ_OK) h_on_confirmed(h, id);
            *order_ok &= h->released[g];
        }
    }
    if (pull) *order_ok &= last == 40;
}

static void test_pull(void)
{
    static h_t a, b;
    int o1, g1, o2, g2;
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    a.guards = b.guards = 1;
    memfs_init(&a.fs);
    memfs_init(&b.fs);
    run_workload(&a, 0, &o1, &g1);
    run_workload(&b, 1, &o2, &g2);
    CHECK(o2 && g2 && !gz_journal_failed(b.j));
    CHECK(h_verify(&b, 0, 0) == 0);
    for (uint64_t g = 0; g < 40; g++) CHECK(b.confirmed[g] && b.released[g]);
    size_t la, lb;
    const uint8_t *da = memfs_get(&a.fs, H_JOURNAL, &la), *db = memfs_get(&b.fs, H_JOURNAL, &lb);
    CHECK(la == lb && memcmp(da, db, la) == 0);
    const uint8_t *ga = memfs_get(&a.fs, H_GUARD, &la), *gb = memfs_get(&b.fs, H_GUARD, &lb);
    CHECK(ga && gb && la == lb && memcmp(ga, gb, la) == 0);
    gz_batch_id_t id;
    CHECK(gz_journal_complete(b.j, &id) == 0);
    /* In runner mode complete() reports nothing. */
    CHECK(gz_journal_complete(a.j, &id) == 0 && gz_journal_complete(NULL, &id) == 0);
    h_close(&a);
    h_close(&b);
    memfs_free(&a.fs);
    memfs_free(&b.fs);

    /* Durable but unreported batches count toward the 32 unconfirmed. */
    memfs_t fs;
    gz_journal_status_t st;
    memfs_init(&fs);
    gz_journal_t *j = jopen(&fs, 1, &st, NULL);
    for (uint64_t s = 1; s <= 31; s++) CHECK(save1(j, 1, s, 0x7e570001) == GZ_JOURNAL_OK);
    CHECK(gz_journal_flush(j) == GZ_JOURNAL_OK); /* 31 durable, none reported */
    CHECK(save1(j, 1, 32, 0x7e570001) == GZ_JOURNAL_OK);
    CHECK(save1(j, 1, 33, 0x7e570001) == GZ_JOURNAL_ERR_SEQUENCE && gz_journal_failed(j));
    CHECK(gz_journal_complete(j, &id) == 0); /* failed: nothing more is reported */
    gz_journal_close(j);
    memfs_free(&fs);
    /* A failing sync inside complete(): nothing is reported. */
    memfs_init(&fs);
    j = jopen(&fs, 1, &st, NULL);
    CHECK(save1(j, 1, 1, 0x7e570001) == GZ_JOURNAL_OK);
    fs.points = 0;
    fs.fail_at = 1;
    fs.fail_mode = MEMFS_FAIL_ERROR;
    CHECK(gz_journal_complete(j, &id) == 0 && gz_journal_failed(j));
    gz_journal_close(j);
    memfs_free(&fs);
}

/* 6. The fence. */
static void test_fence(void)
{
    memfs_t fs;
    gz_journal_status_t st;
    memfs_init(&fs);
    history(&fs); /* incarnations 1 and 2, one batch each */
    gz_journal_t *j = jopen(&fs, 0, &st, NULL);
    gz_storage_reader_t rd = gz_journal_reader(j);
    gz_stored_batch_t sb;
    int earlier = 0, mine = 0;
    while (rd.next(rd.ctx, &sb)) earlier++;
    CHECK(earlier == 2);
    for (uint64_t s = 1; s <= 3; s++) {
        CHECK(save1(j, 3, s, 0x7e570001) == GZ_JOURNAL_OK);
        rd.rewind(rd.ctx);
        int n = 0, ok = 1;
        while (rd.next(rd.ctx, &sb)) { n++; ok &= n <= 2 ? sb.id.incarnation < 3 : sb.id.incarnation == 3; }
        CHECK(ok && n == 2 + mine); /* not durable yet: not seen */
        CHECK(gz_journal_flush(j) == GZ_JOURNAL_OK);
        mine++;
        rd.rewind(rd.ctx);
        n = 0;
        while (rd.next(rd.ctx, &sb)) n++;
        CHECK(n == 2 + mine);
    }
    gz_journal_close(j);
    memfs_free(&fs);
}

int main(void)
{
    test_marker();
    test_marker_crashes();
    test_node();
    test_pull();
    test_fence();
    return check_done();
}
