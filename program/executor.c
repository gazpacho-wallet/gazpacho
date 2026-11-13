/* SPDX-License-Identifier: MIT */
/* The executor loop. See executor.h and docs/notes/program.md.
 *
 * The rules it keeps (core/gazpacho/include/gazpacho/runner.h, node.h,
 * docs/notes/contract-v2.md sections 1, 4 and 8):
 *   - every step's list goes to the runner; only the runner's callback
 *     (execute below) carries out actions, and it never calls the runner or
 *     the node back (the one exception, storage failure, see below);
 *   - a SAVE is appended to storage; its confirmation is taken from storage
 *     (complete()) after the runner call returns, oldest first, once each,
 *     given to gz_runner_confirm, and only if that returns GZ_OK given to the
 *     node as GZ_EVENT_STORAGE_CONFIRMED;
 *   - the incarnation (1 + max(journal, start counter)) is durable before
 *     the runner exists;
 *   - while the node starts, nothing but its storage confirmations reaches
 *     it: peer events are queued per connection in the network adapter, due
 *     timers stay pending, chain results are not taken; the host listens and
 *     the member connects only after the start;
 *   - a refused list, a failed runner, a storage failure, a node error or a
 *     message too big for the transport is fatal: the loop returns
 *     GZP_RUN_RESTART, and main.c closes every connection and starts again
 *     from storage under a new incarnation. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "executor.h"

/* ---- ports -------------------------------------------------------------- */

/* Both purposes read the operating system at the call and keep nothing
 * (ports.h, GZ_RANDOM_SECRET): there is no seeded source in this program. */
static void port_random(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    (void)ctx;
    (void)purpose;
    gzp_os_random(out, len);
}

static uint64_t port_clock(void *ctx)
{
    (void)ctx;
    return gzp_wall_ms();
}

/* ---- helpers ------------------------------------------------------------ */

static const char *status_name(gz_status_t st)
{
    switch (st) {
    case GZ_OK: return "ok";
    case GZ_ERR_ARGUMENT: return "argument";
    case GZ_ERR_NO_SPACE: return "no-space";
    case GZ_ERR_REFUSED: return "refused";
    case GZ_ERR_FAILED: return "failed";
    case GZ_ERR_REENTRANT: return "reentrant";
    case GZ_ERR_STALE_BATCH: return "stale-batch";
    case GZ_ERR_UNKNOWN_BATCH: return "unknown-batch";
    case GZ_ERR_OUT_OF_ORDER: return "out-of-order";
    case GZ_ERR_CORRUPT: return "corrupt";
    case GZ_WAITING: return "waiting";
    }
    return "unknown";
}

static void fail(gzp_exec_t *ex, const char *why)
{
    if (!ex->fatal) {
        ex->fatal = 1;
        ex->fatal_why = why;
        /* issued: the last batch this incarnation handed to storage; nothing
         * of it may be saved after this line (tests check the journal). */
        gzp_log("fatal why=%s incarnation=%llu issued=%llu", why, (unsigned long long)ex->incarnation,
                (unsigned long long)ex->runner.issued);
    }
}

/* A timer of the test build's own (--test-timer-ms), kept in the same table
 * as the node's and fired by the same code, but logged instead of given to
 * the node: it shows that a timer due during a start fires after it, and that
 * a restart's old timers never fire. */
#define GZP_TEST_TIMER_BASE UINT64_C(0xffffffffffff0000) /* | the incarnation's low 16 bits */
#define GZP_IS_TEST_TIMER(id) (((id) & UINT64_C(0xffffffffffff0000)) == GZP_TEST_TIMER_BASE)

#ifdef GZP_TEST_BUILD
static uint64_t be64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v = v << 8 | p[i];
    return v;
}
#endif

/* ---- timers ------------------------------------------------------------- */

static void timer_set(gzp_exec_t *ex, uint64_t id, uint64_t delay_ms)
{
    int i, free_i = -1;
    uint64_t due = gzp_mono_ms() + delay_ms;
    for (i = 0; i < GZP_MAX_TIMERS; i++) {
        if (ex->timers[i].used && ex->timers[i].id == id) {
            ex->timers[i].due_ms = due; /* setting a set timer replaces it */
            return;
        }
        if (!ex->timers[i].used && free_i < 0) free_i = i;
    }
    if (free_i < 0) {
        /* A timer cannot be dropped silently: the node would wait forever. */
        fail(ex, "timer-table-full");
        return;
    }
    ex->timers[free_i].used = 1;
    ex->timers[free_i].id = id;
    ex->timers[free_i].due_ms = due;
}

static void timer_cancel(gzp_exec_t *ex, uint64_t id)
{
    int i;
    for (i = 0; i < GZP_MAX_TIMERS; i++)
        if (ex->timers[i].used && ex->timers[i].id == id) ex->timers[i].used = 0;
}

static int timer_timeout(const gzp_exec_t *ex, uint64_t now)
{
    int i, t = -1;
    for (i = 0; i < GZP_MAX_TIMERS; i++) {
        int d;
        if (!ex->timers[i].used) continue;
        d = ex->timers[i].due_ms > now ? (int)(ex->timers[i].due_ms - now) : 0;
        if (t < 0 || d < t) t = d;
    }
    return t;
}

/* ---- the runner's executor callback ------------------------------------- */

static void log_hex_payload(const char *what, uint64_t peer, const uint8_t *p, size_t n)
{
    char hex[2 * 64 + 1];
    if (n > 64) n = 64;
    gzp_hex(p, n, hex);
    gzp_log("%s peer=%016llx payload=%s", what, (unsigned long long)peer, hex);
}

static void do_save(gzp_exec_t *ex, const gz_action_t *a)
{
    size_t i;
    if (ex->storage_broken) return; /* nothing more may be appended */
    if (ex->store.ops->append(ex->store.ctx, a->u.save.batch, a->u.save.records, a->u.save.n_records) != 0) {
        ex->storage_broken = 1;
        for (i = 0; i < a->u.save.n_records; i++) {
            const gz_record_t *r = &a->u.save.records[i];
            char hex[2 * 64 + 1];
            size_t pl;
            if (r->type != GZ_RECORD_TEST_PING || r->bytes.len < GZ_PING_RECORD_HEADER) continue;
            pl = r->bytes.len - GZ_PING_RECORD_HEADER;
            gzp_hex(r->bytes.data + GZ_PING_RECORD_HEADER, pl > 64 ? 64 : pl, hex);
            gzp_log("save-failed seq=%llu ping-payload=%s", (unsigned long long)a->u.save.batch.sequence, hex);
        }
        /* Allowed from inside the executor: nothing more of this list is
         * handed over (runner.h). */
        gz_runner_storage_failed(&ex->runner);
        return;
    }
    for (i = 0; i < a->u.save.n_records; i++) {
        const gz_record_t *r = &a->u.save.records[i];
        if (r->type == GZ_RECORD_TEST_RESTORED && r->bytes.len == GZ_RESTORED_RECORD_LEN) {
            gzp_log("restore-batch seq=%llu epoch=%02x%02x%02x%02x", (unsigned long long)a->u.save.batch.sequence,
                    r->bytes.data[8], r->bytes.data[9], r->bytes.data[10], r->bytes.data[11]);
            continue;
        }
        if (r->type != GZ_RECORD_TEST_PING || r->bytes.len < GZ_PING_RECORD_HEADER) continue;
        ex->pings_saved++;
#ifdef GZP_TEST_BUILD
        /* Tests: stop dead once the K-th ping record is durable, before its
         * batch is confirmed, so its reply has not left. */
        if (ex->opt->test_crash_at_ping && ex->pings_saved == (uint64_t)ex->opt->test_crash_at_ping) {
            log_hex_payload("test-crash ping-durable", be64(r->bytes.data + 8),
                            r->bytes.data + GZ_PING_RECORD_HEADER, r->bytes.len - GZ_PING_RECORD_HEADER);
            fflush(stdout);
            _exit(GZP_EXIT_TEST);
        }
#endif
    }
    if (gzp_standin_take_restore_answered(&ex->store)) gzp_log("restore answered: the restore marker is gone");
}

static void execute(void *ctx, const gz_action_t *a)
{
    gzp_exec_t *ex = ctx;
    switch (a->kind) {
    case GZ_ACTION_SAVE:
        do_save(ex, a);
        break;
    case GZ_ACTION_SEND: {
        const uint8_t *data = a->u.send.bytes.data;
        size_t len = a->u.send.bytes.len;
        uint8_t *padded = NULL;
        int r;
        if (ex->starting && len >= GZ_PING_PREFIX_LEN) {
            ex->resent++;
            log_hex_payload("start-resend", a->u.send.peer_id, data + GZ_PING_PREFIX_LEN, len - GZ_PING_PREFIX_LEN);
        }
#ifdef GZP_TEST_BUILD
        if (ex->opt->test_oversize_send && (size_t)ex->opt->test_oversize_send > len) {
            /* --test-oversize-send: the same send, padded past the transport's limit. */
            padded = calloc(1, (size_t)ex->opt->test_oversize_send);
            if (!padded) abort();
            if (len) memcpy(padded, data, len);
            data = padded;
            len = (size_t)ex->opt->test_oversize_send;
        }
#endif
        r = gzp_net_send(ex->net, a->u.send.peer_id, data, len);
        free(padded);
        if (r < 0) fail(ex, "message-too-big"); /* an engine bug (contract-v2.md section 1) */
        break;
    }    case GZ_ACTION_BROADCAST:
        gzp_chain_broadcast(ex->chain, a->u.broadcast.tx.data, a->u.broadcast.tx.len);
        break;
    case GZ_ACTION_WATCH_SCRIPT:
        gzp_chain_watch_script(ex->chain, a->u.watch_script.script.data, a->u.watch_script.script.len);
        break;
    case GZ_ACTION_WATCH_TX:
        gzp_log("watch-tx depth=%u (no watch loop yet: P7)", (unsigned)a->u.watch_tx.depth);
        break;
    case GZ_ACTION_WATCH_OUTPOINT:
        gzp_log("watch-outpoint vout=%u depth=%u (no watch loop yet: P7)",
                (unsigned)a->u.watch_outpoint.outpoint.vout, (unsigned)a->u.watch_outpoint.depth);
        break;
    case GZ_ACTION_SET_TIMER:
        timer_set(ex, a->u.set_timer.timer_id, a->u.set_timer.delay_ms);
        break;
    case GZ_ACTION_CANCEL_TIMER:
        timer_cancel(ex, a->u.cancel_timer.timer_id);
        break;
    case GZ_ACTION_NOTIFY:
        ex->notify.emit(ex->notify.ctx, a->u.notify.code, a->u.notify.bytes.data, a->u.notify.bytes.len);
        break;
    default:
        fail(ex, "unknown-action");
        break;
    }
}

/* ---- steps -------------------------------------------------------------- */

static void submit(gzp_exec_t *ex)
{
    gz_status_t st = gz_runner_submit(&ex->runner, &ex->list);
    if (ex->storage_broken) fail(ex, "storage-failed");
    else if (st != GZ_OK) fail(ex, st == GZ_ERR_REFUSED ? "runner-refused-list" : status_name(st));
}

static void deliver(gzp_exec_t *ex, const gz_event_t *ev)
{
    gz_status_t st;
    if (ex->fatal) return; /* nothing reaches a node after its incarnation's fatal error */
    gz_action_list_reset(&ex->list);
    st = gz_node_handle(&ex->node, ev, &ex->list);
    ex->delivered++;
#ifdef GZP_TEST_BUILD
    if (ex->number == 1 && ex->opt->test_node_error_at && ex->delivered == (uint64_t)ex->opt->test_node_error_at) {
        gz_action_list_reset(&ex->list);
        st = GZ_ERR_NO_SPACE; /* as if the node had refused the event */
    }
#endif
    if (st != GZ_OK) {
        /* The node is unchanged, but an event it could not take (a
         * confirmation above all) leaves it out of step with storage. */
        fail(ex, "node-error");
        return;
    }
    submit(ex);
}

/* Confirm the oldest durable batch not yet confirmed. 1 if there was one. */
static int confirm_one(gzp_exec_t *ex)
{
    gz_batch_id_t id;
    gz_status_t st;
    gz_event_t ev;
    if (ex->fatal || !ex->store.ops->complete(ex->store.ctx, &id)) return 0;
    st = gz_runner_confirm(&ex->runner, id);
    if (ex->storage_broken) {
        fail(ex, "storage-failed");
        return 1;
    }
    if (st != GZ_OK) {
        /* Storage reports each batch once, in order, under this incarnation:
         * anything but GZ_OK means the contract is broken somewhere. */
        fail(ex, status_name(st));
        return 1;
    }
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_STORAGE_CONFIRMED;
    ev.u.storage.batch = id;
    deliver(ex, &ev);
    return 1;
}

static void drain(gzp_exec_t *ex)
{
    while (confirm_one(ex)) {
    }
}

/* ---- network events (never during a start: the adapter queues them) ---- */

static void on_connected(void *ctx, uint64_t peer_id, const uint8_t key[33], int outbound, uint64_t conn)
{
    gzp_exec_t *ex = ctx;
    gz_event_t ev;
    char hex[67];
    gzp_hex(key, 33, hex);
    gzp_log("connected peer=%016llx key=%s outbound=%d conn=%llu", (unsigned long long)peer_id, hex, outbound,
            (unsigned long long)conn);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_PEER_CONNECTED;
    ev.u.peer.peer_id = peer_id;
    deliver(ex, &ev);
    drain(ex);
#ifdef GZP_TEST_BUILD
    /* The test traffic's own reconnect step: send again what is unanswered. */
    gzp_testping_connected(ex->tp, ex->net, peer_id);
#endif
}

static void on_disconnected(void *ctx, uint64_t peer_id, const char *why)
{
    gzp_exec_t *ex = ctx;
    gz_event_t ev;
    gzp_log("disconnected peer=%016llx why=%s", (unsigned long long)peer_id, why ? why : "-");
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_PEER_DISCONNECTED;
    ev.u.peer.peer_id = peer_id;
    deliver(ex, &ev);
    drain(ex);
}

static void on_message(void *ctx, uint64_t peer_id, const uint8_t *bytes, size_t len)
{
    gzp_exec_t *ex = ctx;
    gz_event_t ev;
#ifdef GZP_TEST_BUILD
    gzp_testping_message(ex->tp, peer_id, bytes, len);
#endif
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_MESSAGE_RECEIVED;
    ev.u.message.peer_id = peer_id;
    ev.u.message.bytes.data = bytes;
    ev.u.message.bytes.len = len;
    deliver(ex, &ev);
    drain(ex);
}

/* ---- the start ---------------------------------------------------------- */

static int rd_next(void *ctx, gz_stored_batch_t *b)
{
    gzp_exec_t *ex = ctx;
    gzp_batch_t sb;
    if (!ex->store.ops->next(ex->store.ctx, &sb)) return 0;
    b->id = sb.id;
    b->records = sb.records;
    b->n_records = sb.n_records;
    return 1;
}

static void rd_rewind(void *ctx)
{
    gzp_exec_t *ex = ctx;
    ex->store.ops->rewind(ex->store.ctx);
}

/* node.h's stepped start. Between steps, storage confirmations (and only
 * those) are given to the node; GZ_WAITING waits for the next one. */
static void start_node(gzp_exec_t *ex)
{
    gz_storage_reader_t rd;
    int more = 1;
    unsigned steps = 0;
    memset(&rd, 0, sizeof rd);
    rd.next = rd_next;
    rd.rewind = rd_rewind;
    rd.ctx = ex;
    rd.incarnation = ex->incarnation;
    rd.restored = ex->store.ops->restored(ex->store.ctx);
    ex->store.ops->rewind(ex->store.ctx);
    while (more && !ex->fatal) {
        gz_status_t st;
        gz_action_list_reset(&ex->list);
        st = gz_node_start(&ex->node, &rd, &ex->list, &more);
        steps++;
        if (st == GZ_WAITING) {
            more = 1;
            /* A synchronous store has already reported every durable batch
             * (drain below), so waiting with nothing to confirm would wait
             * forever: a contract mismatch. */
            if (!confirm_one(ex)) fail(ex, "start-waits-with-nothing-to-confirm");
            continue;
        }
        if (st != GZ_OK) {
            fail(ex, st == GZ_ERR_CORRUPT ? "start-storage-corrupt" : "start-failed");
            break;
        }
        submit(ex);
        drain(ex);
    }
    if (!ex->fatal) gzp_log("start steps=%u restored=%d", steps, rd.restored);
}

/* ---- the loop ----------------------------------------------------------- */

static int min_timeout(int a, int b)
{
    if (a < 0) return b;
    if (b < 0) return a;
    return a < b ? a : b;
}

/* One poll and what follows it. During a start (until_ms != 0) only the
 * network is stepped, and the adapter queues what it reports; timers, chain
 * results and test traffic wait. Returns GZP_RUN_* or -1 to go on. */
static int turn(gzp_exec_t *ex, struct pollfd *fds, size_t cap, uint64_t until_ms)
{
    uint64_t now = gzp_mono_ms();
    size_t nfds;
    int timeout = -1, t, i;
    uint32_t height;
    if (*ex->stop) return GZP_RUN_STOP;
    if (ex->fatal) return GZP_RUN_RESTART;
    /* Back-pressure. With the synchronous store every batch is confirmed by
     * the drain, so a batch still unconfirmed here is a contract breach (and
     * an asynchronous journal must instead give the loop a descriptor to wait
     * on: store.h, M2 of the review of PR 27). */
    drain(ex);
    if (gz_runner_unconfirmed(&ex->runner) > 0) {
        fail(ex, "unconfirmed-batch-after-drain");
        return GZP_RUN_RESTART;
    }
    fds[0].fd = ex->stop_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    nfds = 1 + gzp_net_pollfds(ex->net, fds + 1, cap - 1, &t, now);
    timeout = min_timeout(timeout, t);
    if (until_ms) {
        timeout = min_timeout(timeout, until_ms > now ? (int)(until_ms - now) : 0);
    } else {
        timeout = min_timeout(timeout, timer_timeout(ex, now));
#ifdef GZP_TEST_BUILD
        timeout = min_timeout(timeout, gzp_testping_timeout(ex->tp, now));
#endif
        timeout = min_timeout(timeout, gzp_chain_timeout(ex->chain, now));
    }
    if (poll(fds, (nfds_t)nfds, timeout) < 0 && errno != EINTR) {
        gzp_log("poll-failed errno=%d", errno);
        return GZP_RUN_RESTART;
    }
    if (fds[0].revents || *ex->stop) return GZP_RUN_STOP;
    now = gzp_mono_ms();
    gzp_net_dispatch(ex->net, fds + 1, nfds - 1, now);
    if (until_ms) return ex->fatal ? GZP_RUN_RESTART : -1;
    /* Due timers, earliest first, each fired once. */
    for (;;) {
        int best = -1;
        gz_event_t ev;
        for (i = 0; i < GZP_MAX_TIMERS; i++)
            if (ex->timers[i].used && ex->timers[i].due_ms <= now &&
                (best < 0 || ex->timers[i].due_ms < ex->timers[best].due_ms))
                best = i;
        if (best < 0 || ex->fatal) break;
        if (GZP_IS_TEST_TIMER(ex->timers[best].id)) {
            /* The incarnation that set it is in its id: an old incarnation's
             * timer firing after a restart shows as such. */
            uint64_t id = ex->timers[best].id;
            ex->timers[best].used = 0;
            gzp_log("test-timer fired incarnation=%llu", (unsigned long long)(id & 0xffffu));
            timer_set(ex, id, (uint64_t)ex->opt->test_timer_ms);
            continue;
        }
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_TIMER_FIRED;
        ev.u.timer.timer_id = ex->timers[best].id;
        ex->timers[best].used = 0;
        deliver(ex, &ev);
        drain(ex);
    }
#ifdef GZP_TEST_BUILD
    gzp_testping_tick(ex->tp, ex->net, now);
#endif
    if (!ex->fatal && gzp_chain_poll(ex->chain, now, &height)) {
        gz_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_CHAIN;
        ev.u.chain.kind = GZ_CHAIN_NEW_TIP;
        ev.u.chain.height = height;
        deliver(ex, &ev);
        drain(ex);
    }
    return ex->fatal ? GZP_RUN_RESTART : -1;
}

/* ---- one incarnation ---------------------------------------------------- */

static const char *counter_name(int s)
{
    return s == GZP_COUNTER_FOUND ? "found" : s == GZP_COUNTER_CREATED ? "created" : "missing";
}

void gzp_exec_close_storage(gzp_exec_t *ex)
{
    if (ex->store_open) ex->store.ops->close(ex->store.ctx);
    ex->store_open = 0;
}

int gzp_exec_incarnation(gzp_exec_t *ex, int number)
{
    char err[200] = "";
    gz_ports_t ports;
    gzp_net_events_t nev;
    struct pollfd *fds;
    size_t cap;
    uint64_t counter = 0;
    int rc = -1, cstate, restored;

    ex->number = number;
    ex->incarnation = 0;
    ex->fatal = 0;
    ex->fatal_why = NULL;
    ex->storage_broken = 0;
    ex->starting = 0;
    ex->resent = 0;
    memset(ex->timers, 0, sizeof ex->timers); /* the old incarnation's timers never fire */
    gzp_chain_forget_watches(ex->chain);      /* the start sets watches again */

    nev.connected = on_connected;
    nev.disconnected = on_disconnected;
    nev.message = on_message;
    nev.ctx = ex;
    ex->net->ev = nev;
    gzp_net_queue_begin(ex->net); /* nothing reaches a starting node */

#ifdef GZP_TEST_BUILD
    if (number == 1 && ex->opt->test_restore_from &&
        gzp_standin_put_restore(ex->dir->dir, ex->opt->test_restore_from, err, sizeof err) != 0) {
        fprintf(stderr, "gazpacho: %s\n", err);
        return GZP_RUN_FAILED;
    }
#endif
    if (gzp_standin_open(&ex->store, ex->dir->dir, err, sizeof err) != 0) {
        fprintf(stderr, "gazpacho: cannot open storage: %s\n", err);
        return GZP_RUN_FAILED;
    }
    ex->store_open = 1;
#ifdef GZP_TEST_BUILD
    if (number == 1 && ex->opt->test_storage_fail_at)
        gzp_standin_fail_at(&ex->store, (unsigned)ex->opt->test_storage_fail_at);
#endif
#ifdef GZP_TEST_BUILD
    gzp_standin_test_hooks(&ex->store, number == 1 ? (unsigned)ex->opt->test_sync_fail_at : 0u,
                           ex->opt->test_cut_fail, number == 1 && ex->opt->test_crash_after_counter,
                           ex->opt->name);
#endif
    if (gzp_standin_cut_bytes(&ex->store))
        gzp_log("journal-cut torn_bytes=%llu kept=journal.standin.cut-%u",
                (unsigned long long)gzp_standin_cut_bytes(&ex->store), gzp_standin_cut_kept(&ex->store));
    restored = ex->store.ops->restored(ex->store.ctx);
    /* The incarnation is durable before the runner exists (runner.h), and
     * above every number this folder has used (the start counter). */
    if (ex->store.ops->begin(ex->store.ctx, &ex->incarnation, err, sizeof err) != 0 ||
        gzp_datadir_sync(ex->dir) != 0) {
        fprintf(stderr, "gazpacho: cannot start storage: %s\n", err);
        gzp_log("start-refused why=storage");
        gzp_exec_close_storage(ex);
        return GZP_RUN_FAILED;
    }
    cstate = gzp_standin_counter_state(&ex->store, &counter);
    gzp_log("start-counter state=%s incarnation=%llu restored=%d", counter_name(cstate),
            (unsigned long long)ex->incarnation, restored);
    if (cstate == GZP_COUNTER_MISSING) {
        if (restored)
            gzp_log("restore counter_found=0: the person is told (the restore rests on the epoch's random draw)");
        else
            gzp_log("start-counter was missing: rewritten from the journal; the person is told once");
    }

    memset(&ports, 0, sizeof ports);
    ports.random.fill = port_random;
    ports.clock.now_ms = port_clock;
    if (gz_node_init(&ex->node, &ports) != GZ_OK ||
        gz_runner_init(&ex->runner, ex->rslots, GZP_RUNNER_SLOTS, ex->rbytes, GZP_RUNNER_BYTES,
                       ex->incarnation, execute, ex) != GZ_OK) {
        gzp_exec_close_storage(ex);
        return GZP_RUN_FAILED;
    }
    gz_action_list_init(&ex->list, ex->lslots, GZP_LIST_SLOTS, ex->lbytes, GZP_LIST_BYTES);

    cap = 1 + gzp_net_max_fds(ex->net);
    fds = calloc(cap, sizeof *fds);
    if (!fds) abort();

    ex->starting = 1;
    ex->delivered = 0;
#ifdef GZP_TEST_BUILD
    /* Set before the start, so that with a held start it comes due during it. */
    if (ex->opt->test_timer_ms)
        timer_set(ex, GZP_TEST_TIMER_BASE | (ex->incarnation & 0xffffu), (uint64_t)ex->opt->test_timer_ms);
    if (ex->opt->test_listen_during_start && gzp_net_open(ex->net) != 0) fail(ex, "listen");
#endif
#ifdef GZP_TEST_BUILD
    /* Tests: hold the start open with the loop running, before the node's
     * start calls, so that what connects meanwhile waits in the queue while
     * the start resends (and those resends must still be dropped). */
    if (!ex->fatal && ex->opt->test_start_delay_ms) {
        uint64_t until = gzp_mono_ms() + (uint64_t)ex->opt->test_start_delay_ms;
        gzp_log("start-delay ms=%d", ex->opt->test_start_delay_ms);
        while (rc < 0 && gzp_mono_ms() < until) rc = turn(ex, fds, cap, until);
    }
#endif
    if (rc < 0) start_node(ex);
    ex->starting = 0;
    if (ex->fatal && gzp_standin_poisoned(&ex->store)) rc = GZP_RUN_RESTART; /* turned into POISONED below */
    if (rc < 0 && !ex->fatal) {
        gzp_log("ready incarnation=%llu resent=%u", (unsigned long long)ex->incarnation, ex->resent);
        /* Only now does the host listen and the member connect. */
        if (gzp_net_open(ex->net) != 0) {
            free(fds);
            gzp_exec_close_storage(ex);
            return GZP_RUN_FAILED;
        }
        if (ex->net->listening) gzp_log("listening address=%s:%u", ex->net->listen_host, (unsigned)ex->net->bound_port);
        /* The node learns the tip at every start (review of PR 27, L4). */
        if (ex->chain->active && ex->chain->have_tip) {
            gz_event_t ev;
            memset(&ev, 0, sizeof ev);
            ev.kind = GZ_EVENT_CHAIN;
            ev.u.chain.kind = GZ_CHAIN_NEW_TIP;
            ev.u.chain.height = ex->chain->tip.height;
            gzp_log("chain-tip told height=%u", ex->chain->tip.height);
            deliver(ex, &ev);
            drain(ex);
        }
        gzp_net_queue_end(ex->net);
    }
    while (rc < 0) rc = turn(ex, fds, cap, 0);
    free(fds);
    if (rc != GZP_RUN_STOP && gzp_standin_poisoned(&ex->store)) {
        gzp_log("storage poisoned: a failed write could not be undone; not restarting (storage.failed)");
        rc = GZP_RUN_POISONED;
    }
    if (rc != GZP_RUN_STOP) gzp_exec_close_storage(ex);
    return rc;
}
