/* SPDX-License-Identifier: MIT */
/* The executor loop. See executor.h and docs/notes/program.md.
 *
 * The rules it keeps (core/gazpacho/include/gazpacho/runner.h, node.h):
 *   - every step's list goes to the runner; only the runner's callback
 *     (execute below) carries out actions, and it never calls the runner or
 *     the node back (the one exception, storage failure, see below);
 *   - a SAVE is appended to storage; its confirmation is taken from storage
 *     (complete()) after the runner call returns, oldest first, once each,
 *     given to gz_runner_confirm, and only if that returns GZ_OK given to the
 *     node as GZ_EVENT_STORAGE_CONFIRMED;
 *   - the incarnation is durable (store begin()) before the runner exists;
 *   - the node is started from storage before it gets any other event, and
 *     before the loop polls the network;
 *   - a refused list, a failed runner, a storage failure or a node error is
 *     fatal: the loop returns GZP_RUN_RESTART and main.c starts again from
 *     storage under a new incarnation. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "executor.h"

/* ---- ports -------------------------------------------------------------- */

#ifdef GZP_CORE_RANDOM_PURPOSE
/* Both purposes read the operating system at the call and keep nothing
 * (ports.h, GZ_RANDOM_SECRET): there is no seeded source in this program. */
static void port_random(void *ctx, gzp_purpose_t purpose, uint8_t *out, size_t len)
{
    (void)ctx;
    (void)purpose;
    gzp_os_random(out, len);
}
#else
static void port_random(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    gzp_os_random(out, len);
}
#endif

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
#ifdef GZP_CORE_STEPPED_START
    case GZ_ERR_CORRUPT: return "corrupt";
    case GZ_WAITING: return "waiting";
#endif
    }
    return "unknown";
}

static void fail(gzp_exec_t *ex, const char *why)
{
    if (!ex->fatal) {
        ex->fatal = 1;
        ex->fatal_why = why;
        gzp_log("fatal why=%s incarnation=%llu", why, (unsigned long long)ex->incarnation);
    }
}

static uint64_t be64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v = v << 8 | p[i];
    return v;
}

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
        if (!ex->timers[i].used) continue;
        {
            int d = ex->timers[i].due_ms > now ? (int)(ex->timers[i].due_ms - now) : 0;
            if (t < 0 || d < t) t = d;
        }
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
    ex->appends++;
    if (ex->store.ops->append(ex->store.ctx, a->u.save.batch, a->u.save.records, a->u.save.n_records) != 0) {
        ex->storage_broken = 1;
#ifdef GZP_CORE_STEPPED_START
        /* The follow-up's runner allows this from inside the executor and then
         * hands over nothing more of the list being carried out. */
        gz_runner_storage_failed(&ex->runner);
#endif
        return;
    }
    /* Tests: stop dead once the K-th ping record is durable, before its batch
     * is confirmed, so its reply has not left. The next start must send it. */
    for (i = 0; i < a->u.save.n_records; i++) {
        const gz_record_t *r = &a->u.save.records[i];
        if (r->type != GZ_RECORD_TEST_PING || r->bytes.len < GZ_PING_RECORD_HEADER) continue;
        ex->pings_saved++;
        if (ex->opt->test_crash_at_ping && ex->pings_saved == (uint64_t)ex->opt->test_crash_at_ping) {
            log_hex_payload("test-crash ping-durable", be64(r->bytes.data + 8),
                            r->bytes.data + GZ_PING_RECORD_HEADER, r->bytes.len - GZ_PING_RECORD_HEADER);
            fflush(stdout);
            _exit(GZP_EXIT_TEST);
        }
    }
}

static void execute(void *ctx, const gz_action_t *a)
{
    gzp_exec_t *ex = ctx;
    switch (a->kind) {
    case GZ_ACTION_SAVE:
        do_save(ex, a);
        break;
    case GZ_ACTION_SEND: {
        int r = gzp_net_send(ex->net, a->u.send.peer_id, a->u.send.bytes.data, a->u.send.bytes.len);
        if (ex->starting) {
            ex->resent++;
            if (a->u.send.bytes.len >= GZ_PING_PREFIX_LEN)
                log_hex_payload("start-resend", a->u.send.peer_id, a->u.send.bytes.data + GZ_PING_PREFIX_LEN,
                                a->u.send.bytes.len - GZ_PING_PREFIX_LEN);
        }
        if (r < 0) gzp_log("send-dropped peer=%016llx len=%zu", (unsigned long long)a->u.send.peer_id,
                           a->u.send.bytes.len);
        break;
    }
    case GZ_ACTION_BROADCAST:
        gzp_chain_broadcast(ex->chain, a->u.broadcast.tx.data, a->u.broadcast.tx.len);
        break;
#ifdef GZP_CORE_WATCH_TX
    case GZ_ACTION_WATCH_SCRIPT:
        gzp_chain_watch_script(ex->chain, a->u.watch_script.script.data, a->u.watch_script.script.len);
        break;
    case GZ_ACTION_WATCH_TX:
        gzp_log("watch-tx depth=%u (no watch loop yet: stream S8)", (unsigned)a->u.watch_tx.depth);
        break;
    case GZ_ACTION_WATCH_OUTPOINT:
        gzp_log("watch-outpoint vout=%u depth=%u (no watch loop yet: stream S8)",
                (unsigned)a->u.watch_outpoint.outpoint.vout, (unsigned)a->u.watch_outpoint.depth);
        break;
#else
    case GZ_ACTION_WATCH:
        gzp_chain_watch_script(ex->chain, a->u.watch.script.data, a->u.watch.script.len);
        break;
#endif
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

/* Give the runner the list a node call filled. */
static void submit(gzp_exec_t *ex)
{
    gz_status_t st = gz_runner_submit(&ex->runner, &ex->list);
    if (ex->storage_broken) {
        gz_runner_storage_failed(&ex->runner); /* on main: only outside the callback */
        fail(ex, "storage-failed");
    } else if (st != GZ_OK) {
        fail(ex, st == GZ_ERR_REFUSED ? "runner-refused-list" : status_name(st));
    }
}

static void deliver(gzp_exec_t *ex, const gz_event_t *ev)
{
    gz_status_t st;
    if (ex->fatal) return;
    gz_action_list_reset(&ex->list);
    st = gz_node_handle(&ex->node, ev, &ex->list);
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
        gz_runner_storage_failed(&ex->runner);
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

/* ---- network events ----------------------------------------------------- */

static void on_connected(void *ctx, uint64_t peer_id, const uint8_t key[33])
{
    gzp_exec_t *ex = ctx;
    char hex[67];
    gzp_hex(key, 33, hex);
    gzp_log("connected peer=%016llx key=%s", (unsigned long long)peer_id, hex);
#ifdef GZP_CORE_PEER_EVENTS
    {
        gz_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_PEER_CONNECTED;
        ev.u.peer.peer_id = peer_id;
        deliver(ex, &ev);
        drain(ex);
    }
#endif
    gzp_testping_connected(ex->tp, ex->net, peer_id);
}

static void on_disconnected(void *ctx, uint64_t peer_id, const char *why)
{
    gzp_exec_t *ex = ctx;
    gzp_log("disconnected peer=%016llx why=%s", (unsigned long long)peer_id, why ? why : "-");
#ifdef GZP_CORE_PEER_EVENTS
    {
        gz_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_PEER_DISCONNECTED;
        ev.u.peer.peer_id = peer_id;
        deliver(ex, &ev);
        drain(ex);
    }
#else
    (void)ex;
#endif
}

static void on_message(void *ctx, uint64_t peer_id, const uint8_t *bytes, size_t len)
{
    gzp_exec_t *ex = ctx;
    gz_event_t ev;
    gzp_testping_message(ex->tp, peer_id, bytes, len);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_MESSAGE_RECEIVED;
    ev.u.message.peer_id = peer_id;
    ev.u.message.bytes.data = bytes;
    ev.u.message.bytes.len = len;
    deliver(ex, &ev);
    drain(ex);
}

/* ---- the start ---------------------------------------------------------- */

#ifdef GZP_CORE_STEPPED_START
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
#ifdef GZP_CORE_READER_RESTORED
    rd.restored = ex->store.ops->restored(ex->store.ctx);
#else
    if (ex->store.ops->restored(ex->store.ctx)) {
        fail(ex, "restored-storage-but-no-restore-marker-in-this-core");
        return;
    }
#endif
    ex->store.ops->rewind(ex->store.ctx);
    while (more && !ex->fatal) {
        gz_status_t st;
        int was = more;
        gz_action_list_reset(&ex->list);
        st = gz_node_start(&ex->node, &rd, &ex->list, &more);
        steps++;
        if (st == GZ_WAITING) {
            more = was;
            /* A synchronous store has already reported every durable batch
             * (drain below), so waiting with nothing to confirm would wait
             * forever: report it as a contract mismatch. */
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
    if (!ex->fatal) gzp_log("start steps=%u", steps);
}
#else
/* main's one-call start: every stored record, oldest first. */
static void start_node(gzp_exec_t *ex)
{
    gzp_batch_t b;
    gz_record_t *all = NULL;
    size_t n = 0, cap = 0, i;
    gz_status_t st;
    ex->store.ops->rewind(ex->store.ctx);
    while (ex->store.ops->next(ex->store.ctx, &b)) {
        if (n + b.n_records > cap) {
            size_t c = cap ? cap * 2 : 256;
            gz_record_t *na;
            while (c < n + b.n_records) c *= 2;
            na = realloc(all, c * sizeof *na);
            if (!na) {
                free(all);
                fail(ex, "out-of-memory");
                return;
            }
            all = na;
            cap = c;
        }
        /* The stand-in keeps every record in memory for as long as it is
         * open, so the pointers stay valid through the call. */
        for (i = 0; i < b.n_records; i++) all[n++] = b.records[i];
    }
    gz_action_list_reset(&ex->list);
    st = gz_node_start(&ex->node, all, n, &ex->list);
    free(all);
    if (st != GZ_OK) {
        fail(ex, st == GZ_ERR_NO_SPACE ? "start-no-space" : "start-failed");
        return;
    }
    submit(ex);
    drain(ex);
}
#endif

/* ---- the loop ----------------------------------------------------------- */

static int min_timeout(int a, int b)
{
    if (a < 0) return b;
    if (b < 0) return a;
    return a < b ? a : b;
}

static int loop(gzp_exec_t *ex)
{
    struct pollfd fds[GZP_MAX_PEERS + 2];
    for (;;) {
        uint64_t now;
        size_t nfds;
        int timeout, i;
        uint32_t height;
        if (*ex->stop) return GZP_RUN_STOP;
        if (ex->fatal) return GZP_RUN_RESTART;
        now = gzp_mono_ms();
        timeout = 200; /* at least this often: notice a stop */
        timeout = min_timeout(timeout, timer_timeout(ex, now));
        timeout = min_timeout(timeout, gzp_net_timeout(ex->net, now));
        timeout = min_timeout(timeout, gzp_testping_timeout(ex->tp, now));
        timeout = min_timeout(timeout, gzp_chain_timeout(ex->chain, now));
        /* Back-pressure: with many batches awaiting storage, take no new
         * outside event (a refusal would be fatal). A synchronous store never
         * gets here; an asynchronous journal would be polled instead. */
        drain(ex);
        if (gz_runner_unconfirmed(&ex->runner) > GZ_RUNNER_MAX_UNCONFIRMED / 2) {
            poll(NULL, 0, 1);
            continue;
        }
        nfds = gzp_net_pollfds(ex->net, fds, sizeof fds / sizeof fds[0]);
        if (poll(fds, (nfds_t)nfds, timeout) < 0 && errno != EINTR) {
            gzp_log("poll-failed errno=%d", errno);
            return GZP_RUN_RESTART;
        }
        now = gzp_mono_ms();
        gzp_net_poll_done(ex->net, fds, nfds, now);
        /* Due timers, earliest first, each fired once. */
        for (;;) {
            int best = -1;
            for (i = 0; i < GZP_MAX_TIMERS; i++)
                if (ex->timers[i].used && ex->timers[i].due_ms <= now &&
                    (best < 0 || ex->timers[i].due_ms < ex->timers[best].due_ms))
                    best = i;
            if (best < 0 || ex->fatal) break;
            {
                gz_event_t ev;
                memset(&ev, 0, sizeof ev);
                ev.kind = GZ_EVENT_TIMER_FIRED;
                ev.u.timer.timer_id = ex->timers[best].id;
                ex->timers[best].used = 0;
                deliver(ex, &ev);
                drain(ex);
            }
        }
        gzp_testping_tick(ex->tp, ex->net, now);
        if (!ex->fatal && gzp_chain_poll(ex->chain, now, &height)) {
            gz_event_t ev;
            memset(&ev, 0, sizeof ev);
            ev.kind = GZ_EVENT_CHAIN;
            ev.u.chain.kind = GZ_CHAIN_NEW_TIP;
            ev.u.chain.height = height;
            deliver(ex, &ev);
            drain(ex);
        }
    }
}

/* ---- one incarnation ---------------------------------------------------- */

int gzp_exec_incarnation(gzp_exec_t *ex, int number)
{
    char path[GZP_PATH_MAX], err[200];
    gz_ports_t ports;
    gzp_net_events_t nev;
    uint64_t cut;
    int rc;

    ex->incarnation = 0;
    ex->fatal = 0;
    ex->fatal_why = NULL;
    ex->storage_broken = 0;
    ex->starting = 0;
    ex->resent = 0;
    memset(ex->timers, 0, sizeof ex->timers);   /* timers and watches do not */
    gzp_chain_forget_watches(ex->chain);        /* outlive an incarnation */

    nev.connected = on_connected;
    nev.disconnected = on_disconnected;
    nev.message = on_message;
    nev.ctx = ex;
    ex->net->ev = nev;

    if (gzp_datadir_path(ex->dir, "journal.standin", path) != 0 ||
        gzp_standin_open(&ex->store, path, err, sizeof err) != 0) {
        fprintf(stderr, "gazpacho: cannot open storage: %s\n", err);
        return GZP_RUN_FAILED;
    }
    if (number == 1 && ex->opt->test_storage_fail_at)
        gzp_standin_fail_at(&ex->store, (unsigned)ex->opt->test_storage_fail_at);
    cut = gzp_standin_cut_bytes(&ex->store);
    if (cut) gzp_log("journal-cut torn_bytes=%llu", (unsigned long long)cut);
    /* The incarnation is durable before the runner exists (runner.h). */
    if (ex->store.ops->begin(ex->store.ctx, &ex->incarnation, err, sizeof err) != 0 ||
        gzp_datadir_sync(ex->dir) != 0) {
        fprintf(stderr, "gazpacho: cannot start storage: %s\n", err);
        ex->store.ops->close(ex->store.ctx);
        return GZP_RUN_FAILED;
    }

    memset(&ports, 0, sizeof ports);
    ports.random.fill = port_random;
    ports.clock.now_ms = port_clock;
    if (gz_node_init(&ex->node, &ports) != GZ_OK ||
        gz_runner_init(&ex->runner, ex->rslots, GZP_RUNNER_SLOTS, ex->rbytes, GZP_RUNNER_BYTES,
                       ex->incarnation, execute, ex) != GZ_OK) {
        ex->store.ops->close(ex->store.ctx);
        return GZP_RUN_FAILED;
    }
    gz_action_list_init(&ex->list, ex->lslots, GZP_LIST_SLOTS, ex->lbytes, GZP_LIST_BYTES);

    ex->starting = 1;
    start_node(ex);
    ex->starting = 0;
    if (ex->fatal) {
        ex->store.ops->close(ex->store.ctx);
        return GZP_RUN_RESTART;
    }
    gzp_log("ready incarnation=%llu resent=%u", (unsigned long long)ex->incarnation, ex->resent);
#ifdef GZP_CORE_PEER_EVENTS
    /* A restart in the same process: connections were dropped (main.c), so
     * there is no live peer to report yet. */
#endif
    rc = loop(ex);
    ex->store.ops->close(ex->store.ctx);
    return rc;
}
