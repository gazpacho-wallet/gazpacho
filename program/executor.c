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

#include <fcntl.h>

#include "gazpacho/command.h"
#include "gazpacho/envelope.h"
#include "executor.h"
#include "store_unlock.h"
#ifdef GZP_TEST_BUILD
#include "gazpacho/test_engine.h"
#endif

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

/* The monotonic clock (ports.h): the intervals the node measures never
 * follow a wall clock that is stepped. */
static uint64_t port_mono(void *ctx)
{
    (void)ctx;
    return gzp_mono_ms();
}

/* The key port (ports.h) over the stand-in transport key, until P8 derives
 * per-lobby keys: every (epoch, index) is the transport's key, and the host
 * key is it too. No secret is handed out before the signing engine needs one. */
static int port_pub(void *ctx, uint32_t epoch, uint32_t index, uint8_t pub33[33])
{
    gzp_exec_t *ex = ctx;
    return gzp_net_key(ex->net, epoch, index, NULL, pub33);
}

/* Signatures for the lobbies (node.h, gz_node_crypto_t), over the same keys. */
static int port_verify(void *ctx, const uint8_t pub[33], const uint8_t msg[32], const uint8_t sig[64])
{
    return gzp_net_verify(((gzp_exec_t *)ctx)->net, pub, msg, sig);
}

static int port_point_ok(void *ctx, const uint8_t pub[33])
{
    return gzp_net_point_ok(((gzp_exec_t *)ctx)->net, pub);
}

static int port_sign(void *ctx, int host, uint32_t epoch, uint32_t index, const uint8_t msg[32], uint8_t sig[64])
{
    gzp_exec_t *ex = ctx;
    if (host) return ex->opt->role == GZP_ROLE_HOST ? gzp_net_sign(ex->net, 0, 0, msg, sig) : 0;
    return gzp_net_sign(ex->net, epoch, index, msg, sig);
}

/* A lobby's signing gate closed (AT_JOIN): its scoped factory secret is
 * wiped. The stand-in keys hold none apart; the line shows the moment. */
static void port_forget(void *ctx, const uint8_t scope[32])
{
    (void)ctx;
    gzp_log("key-forget scope=%02x%02x%02x%02x", scope[0], scope[1], scope[2], scope[3]);
}

static int port_secret(void *ctx, uint32_t epoch, uint32_t index, uint8_t sec32[32])
{
    (void)ctx;
    (void)epoch;
    (void)index;
    (void)sec32;
    return 0;
}

static int port_host_pub(void *ctx, uint8_t pub33[33])
{
    gzp_exec_t *ex = ctx;
    if (ex->opt->role != GZP_ROLE_HOST) return 0;
    memcpy(pub33, ex->net->pub, 33);
    return 1;
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
    case GZ_ERR_BUG: return "bug";
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

/* A fatal error that no restart from storage can fix: the incarnation ends
 * and the program stops (GZP_RUN_LIMIT), instead of restarting into it. */
static void fail_stop(gzp_exec_t *ex, const char *why)
{
    fail(ex, why);
    ex->fatal_stop = 1;
}

/* What the chain adapter answered a request (pchain.h): -1 is fatal for the
 * incarnation; GZP_CHAIN_STOP (the worker holds fewer watches than the node
 * asks for, and the saved watches come back at every start) stops. */
static void chain_answer(gzp_exec_t *ex, int rc, const char *why)
{
    /* The adapter's own reason, when it gave one, belongs to this answer
     * only: it is cleared here, so an older reason is never printed. */
    const char *own = ex->chain->why;
    ex->chain->why = NULL;
    if (rc == GZP_CHAIN_STOP) fail_stop(ex, "chain-watch-set-full");
    else if (rc < 0) fail(ex, own ? own : why);
}

#ifdef GZP_TEST_BUILD
/* A timer of the test build's own (--test-timer-ms), kept in the same table
 * as the node's and fired by the same code, but logged instead of given to
 * the node: it shows that a timer due during a start fires after it, and that
 * a restart's old timers never fire. Test build only (review B of PR 27, B4):
 * in the release build every timer id is the node's. */
#define GZP_TEST_TIMER_BASE UINT64_C(0xffffffffffff0000) /* | the incarnation's low 16 bits */
#define GZP_IS_TEST_TIMER(id) (((id) & UINT64_C(0xffffffffffff0000)) == GZP_TEST_TIMER_BASE)
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

/* Output lines never carry message bytes in the release build (review B of
 * PR 27, B6): from P4 on these would be engine messages. The test build
 * prints the placeholder's payload, which its tests read. */
#ifdef GZP_TEST_BUILD
static void log_hex_payload(const char *what, uint64_t peer, const uint8_t *p, size_t n)
{
    char hex[2 * 64 + 1];
    if (n > 64) n = 64;
    gzp_hex(p, n, hex);
    gzp_log("%s peer=%016llx payload=%s", what, (unsigned long long)peer, hex);
}
#endif

/* A test engine's ping record (test_engine.h): area 0x7e57 or 0x7e58, kind 1,
 * clock 8, link 66 (the remote key at 41), serial 8, payload. */
#define PING_HEADER 82u
static int is_ping_record(const gz_record_t *r)
{
    return (r->type == 0x7e570001u || r->type == 0x7e580001u) && r->bytes.len >= PING_HEADER;
}

static void do_save(gzp_exec_t *ex, const gz_action_t *a)
{
    size_t i;
    int restored = 0;
    if (ex->storage_broken) return; /* nothing more may be appended */
    if (ex->store.ops->append(ex->store.ctx, a->u.save.batch, a->u.save.records, a->u.save.n_records) != 0) {
        ex->storage_broken = 1;
#ifndef GZP_TEST_BUILD
        gzp_log("save-failed seq=%llu records=%zu", (unsigned long long)a->u.save.batch.sequence,
                a->u.save.n_records);
#else
        /* Tests: the line for every failed batch, then one per ping record in it. */
        gzp_log("save-failed seq=%llu records=%zu", (unsigned long long)a->u.save.batch.sequence,
                a->u.save.n_records);
        for (i = 0; i < a->u.save.n_records; i++) {
            const gz_record_t *r = &a->u.save.records[i];
            char hex[2 * 64 + 1];
            size_t pl;
            if (!is_ping_record(r)) continue;
            pl = r->bytes.len - PING_HEADER;
            gzp_hex(r->bytes.data + PING_HEADER, pl > 64 ? 64 : pl, hex);
            gzp_log("save-failed seq=%llu ping-payload=%s", (unsigned long long)a->u.save.batch.sequence, hex);
        }
#endif
        /* Allowed from inside the executor: nothing more of this list is
         * handed over (runner.h). */
        gz_runner_storage_failed(&ex->runner);
        return;
    }
    ex->saves++;
    for (i = 0; i < a->u.save.n_records; i++)
        if (a->u.save.records[i].type == GZ_RECORD_RESTORED) restored = 1;
    for (i = 0; i < a->u.save.n_records; i++) {
        const gz_record_t *r = &a->u.save.records[i];
        if (r->type == GZ_RECORD_KEY_EPOCH) {
            gz_bytes_t v;
            if (gz_rec_find(r->bytes, 2, &v) == 1 && v.len == 4)
                gzp_log("%s seq=%llu epoch=%02x%02x%02x%02x", restored ? "restore-batch" : "key-epoch",
                        (unsigned long long)a->u.save.batch.sequence, v.data[0], v.data[1], v.data[2], v.data[3]);
            continue;
        }
        if (!is_ping_record(r)) continue;
        ex->pings_saved++;
#ifdef GZP_TEST_BUILD
        /* Tests: stop dead once the K-th ping record is durable, before its
         * batch is confirmed, so its reply has not left. */
        if (ex->opt->test_crash_at_ping && ex->pings_saved == (uint64_t)ex->opt->test_crash_at_ping) {
            log_hex_payload("test-crash ping-durable", gzp_peer_id(r->bytes.data + 41), r->bytes.data + PING_HEADER,
                            r->bytes.len - PING_HEADER);
            fflush(stdout);
            _exit(GZP_EXIT_TEST);
        }
#endif
    }
    /* The restore batch's guard record: the chain the node was given opens it
     * (journal.md 8.3). Shown, so a node given no chain is noticed. */
    for (i = 0; restored && i < a->u.save.n_records; i++) {
        const gz_record_t *r = &a->u.save.records[i];
        if (r->type == GZ_RECORD_GUARD && r->bytes.len >= 48) {
            char hex[17];
            gzp_hex(r->bytes.data + 8, 8, hex);
            gzp_log("restore-guard chain=%s counter=%llu", hex, (unsigned long long)gz_get_u64(r->bytes.data + 40));
        }
    }
    if (gzp_store_take_restore_answered(&ex->store)) gzp_log("restore answered: the restore marker is gone");
#ifdef GZP_TEST_BUILD
    /* Tests: stop once the K-th batch is durable, before the rest of its list
     * (its sends, timers, notices) is carried out. */
    if (ex->number == 1 && ex->opt->test_crash_after_save && ex->saves == (uint64_t)ex->opt->test_crash_after_save) {
        gzp_log("test-crash after-save seq=%llu", (unsigned long long)a->u.save.batch.sequence);
        fflush(stdout);
        _exit(GZP_EXIT_TEST);
    }
    /* Tests: the same, at the batch that holds a record of one type: a crash
     * after a save and before its sends, picked by what was saved. */
    if (ex->number == 1 && ex->opt->test_crash_after_record) {
        for (i = 0; i < a->u.save.n_records; i++)
            if (a->u.save.records[i].type == ex->opt->test_crash_after_record) {
                gzp_log("test-crash after-record type=%08x seq=%llu", (unsigned)ex->opt->test_crash_after_record,
                        (unsigned long long)a->u.save.batch.sequence);
                fflush(stdout);
                _exit(GZP_EXIT_TEST);
            }
    }
#endif
}

#ifdef GZP_TEST_BUILD
/* Tests: a NOTIFY as an output line. The core's log notices and command
 * results are ASCII it wrote itself; a view object is shown by kind, id and
 * version only. */
static void show_notify(uint32_t code, gz_bytes_t b)
{
    gz_bytes_t v, w;
    char text[200];
    size_t i, n;
    if (code == GZ_NOTIFY_LOG && gz_rec_find(b, 0, &v) == 1) {
        n = v.len < sizeof text - 1 ? v.len : sizeof text - 1;
        for (i = 0; i < n; i++) text[i] = v.data[i] >= 32 && v.data[i] < 127 ? (char)v.data[i] : '?';
        text[n] = 0;
        gzp_log("node-log %s", text);
    } else if (code == GZ_NOTIFY_COMMAND_RESULT && gz_rec_find(b, GZ_RESULT_REC_STATUS, &v) == 1 && v.len == 2) {
        char id[70] = "-", err[70] = "-";
        if (gz_rec_find(b, GZ_RESULT_REC_REQUEST_ID, &w) == 1 && w.len < sizeof id) {
            for (i = 0; i < w.len; i++) id[i] = w.data[i] > 32 && w.data[i] < 127 ? (char)w.data[i] : '?';
            id[w.len] = 0;
        }
        if (gz_rec_find(b, GZ_RESULT_REC_ERROR, &w) == 1 && w.len < sizeof err) {
            for (i = 0; i < w.len; i++) err[i] = w.data[i] > 32 && w.data[i] < 127 ? (char)w.data[i] : '?';
            err[w.len] = 0;
        }
        gzp_log("command-result id=%s status=%u error=%s", id, (unsigned)gz_get_u16(v.data), err);
    } else if ((code >> 16) == 1 && gz_rec_find(b, GZ_VIEW_REC_ID, &v) == 1 && v.len < 65) {
        char id[70];
        for (i = 0; i < v.len; i++) id[i] = v.data[i] > 32 && v.data[i] < 127 ? (char)v.data[i] : '?';
        id[v.len] = 0;
        unsigned long long ver = gz_rec_find(b, GZ_VIEW_REC_VERSION, &w) == 1 && w.len == 8 ? gz_get_u64(w.data) : 0;
        gzp_log("view kind=%u id=%s version=%llu", (unsigned)(code & 0xffffu), id, ver);
    } else if ((code & 0xffffff00u) == 0x4c00u) {
        /* A lobby's notice (lobby.h, GZ_NOTE_*): its code and first bytes. */
        gzp_log("lobby-note code=0x%04x a=%u b=%u c=%u", (unsigned)code, b.len > 0 ? b.data[0] : 0u,
                b.len > 1 ? b.data[1] : 0u, b.len > 2 ? b.data[2] : 0u);
    }
}
#endif

static void execute(void *ctx, const gz_action_t *a)
{
    gzp_exec_t *ex = ctx;
    switch (a->kind) {
    case GZ_ACTION_SAVE:
        do_save(ex, a);
        break;
    case GZ_ACTION_SEND: {
        const uint8_t *data = a->u.send.records.data;
        size_t len = a->u.send.records.len;
        uint8_t *padded = NULL;
        int r;
        if (ex->starting) {
            /* The start resends nothing since contract v2 (rule 6): counted. */
            ex->resent++;
            gzp_log("start-resend peer=%016llx kind=%u len=%zu",
                    (unsigned long long)gzp_peer_id(a->u.send.link.remote.key), (unsigned)a->u.send.kind, len);
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
        r = gzp_net_send(ex->net, &a->u.send.link, a->u.send.kind, a->u.send.scope, data, len);
        free(padded);
        if (r == -2) fail(ex, "send-reserved-kind"); /* an engine bug (action.h): never on the wire */
        else if (r < 0) fail(ex, "message-too-big"); /* an engine bug (contract-v2.md section 1) */
        break;
    }
    case GZ_ACTION_CONNECT:
        /* A CONNECT the adapter cannot carry out is never fatal: a bad
         * address is an unreachable host, not a bug, and the target is saved
         * and comes again at every start. The adapter reports and counts it
         * ("connect-failed"), and retries what can be retried. */
        (void)gzp_net_connect(ex->net, a->u.connect.host.key, a->u.connect.address.data, a->u.connect.address.len,
                              a->u.connect.key_epoch, a->u.connect.key_index);
        break;
    case GZ_ACTION_DISCONNECT:
        gzp_net_disconnect(ex->net, &a->u.disconnect.link, a->u.disconnect.why);
        break;
    case GZ_ACTION_SET_SEATED:
        gzp_net_set_seated(ex->net, a->u.set_seated.member.key, a->u.set_seated.seated);
        gzp_log("seated key=%016llx seated=%d", (unsigned long long)gzp_peer_id(a->u.set_seated.member.key),
                a->u.set_seated.seated);
        break;
    case GZ_ACTION_BROADCAST:
        chain_answer(ex, gzp_chain_broadcast(ex->chain, a->u.broadcast.tx.data, a->u.broadcast.tx.len),
                     "chain-backlog-full");
        break;
    case GZ_ACTION_WATCH_TX: {
        char hex[65];
        gzp_hex(a->u.watch_tx.txid, 32, hex);
        gzp_log("watch-tx txid=%s depth=%u", hex, (unsigned)a->u.watch_tx.depth);
        /* BUSY is held and asked again (gzp_chain_retry); -1 is a refusal
         * that cannot be retried, or a full backlog: fatal, never ignored. */
        chain_answer(ex, gzp_chain_watch_tx(ex->chain, a->u.watch_tx.txid, a->u.watch_tx.depth),
                     "chain-watch-refused");
        break;
    }
    case GZ_ACTION_WATCH_OUTPOINT: {
        char hex[65];
        gzp_hex(a->u.watch_outpoint.outpoint.txid, 32, hex);
        gzp_log("watch-outpoint txid=%s vout=%u depth=%u", hex,
                (unsigned)a->u.watch_outpoint.outpoint.vout, (unsigned)a->u.watch_outpoint.depth);
        chain_answer(ex, gzp_chain_watch_outpoint(ex->chain, a->u.watch_outpoint.outpoint.txid,
                                                  a->u.watch_outpoint.outpoint.vout, a->u.watch_outpoint.depth),
                     "chain-watch-refused");
        break;
    }
    case GZ_ACTION_SET_TIMER:
        timer_set(ex, a->u.set_timer.timer_id, a->u.set_timer.delay_ms);
        break;
    case GZ_ACTION_CANCEL_TIMER:
        timer_cancel(ex, a->u.cancel_timer.timer_id);
        break;
    case GZ_ACTION_NOTIFY:
        ex->notify.emit(ex->notify.ctx, a->u.notify.code, a->u.notify.bytes.data, a->u.notify.bytes.len);
#ifdef GZP_TEST_BUILD
        show_notify(a->u.notify.code, a->u.notify.bytes);
#endif
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
    st = gz_node_handle(ex->node, ev, &ex->list);
    ex->delivered++;
#ifdef GZP_TEST_BUILD
    if ((ex->number == 1 || ex->opt->test_node_error_always) && ex->opt->test_node_error_at &&
        ex->delivered == (uint64_t)ex->opt->test_node_error_at) {
        gz_action_list_reset(&ex->list);
        st = GZ_ERR_NO_SPACE; /* as if the node had refused the event */
    }
#endif
    if (st != GZ_OK) {
        /* Fatal for the whole node (node.h, ERRORS): the list is as it was,
         * the node is poisoned and never called again; start from storage. */
        gzp_log("node-error engine=0x%04x status=%s", (unsigned)gz_node_error_area(ex->node), status_name(st));
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
    ex->confirms++;
#ifdef GZP_TEST_BUILD
    if (ex->number == 1 && ex->opt->test_crash_before_confirm &&
        ex->confirms == (uint64_t)ex->opt->test_crash_before_confirm) {
        gzp_log("test-crash before-confirm seq=%llu", (unsigned long long)id.sequence);
        fflush(stdout);
        _exit(GZP_EXIT_TEST);
    }
#endif
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

#ifdef GZP_TEST_BUILD
/* Tests: the node's view of who is connected, as the events gave it, so that
 * a message delivered before its connection's connected (or after its
 * disconnected) shows in the output (review B of PR 27, B42). */
static struct {
    uint64_t peer;
    int n;
} seen[2 * GZP_MAX_CONNS];

static int *seen_count(uint64_t peer, int make)
{
    size_t i, free_i = sizeof seen / sizeof seen[0];
    for (i = 0; i < sizeof seen / sizeof seen[0]; i++) {
        if (seen[i].n > 0 && seen[i].peer == peer) return &seen[i].n;
        if (seen[i].n <= 0 && free_i == sizeof seen / sizeof seen[0]) free_i = i;
    }
    if (!make || free_i == sizeof seen / sizeof seen[0]) return NULL;
    seen[free_i].peer = peer;
    seen[free_i].n = 0;
    return &seen[free_i].n;
}
#endif

static void on_connected(void *ctx, const gz_link_t *link, int outbound, uint32_t key_epoch, uint32_t key_index,
                         uint64_t conn)
{
    gzp_exec_t *ex = ctx;
    gz_event_t ev;
    char hex[67];
    uint64_t peer_id = gzp_peer_id(link->remote.key);
    gzp_hex(link->remote.key, 33, hex);
    gzp_log("connected peer=%016llx key=%s outbound=%d conn=%llu", (unsigned long long)peer_id, hex, outbound,
            (unsigned long long)conn);
#ifdef GZP_TEST_BUILD
    {
        int *n = seen_count(peer_id, 1);
        if (n) (*n)++;
    }
#endif
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_PEER_CONNECTED;
    ev.u.peer.link = *link;
    ev.u.peer.outbound = outbound;
    ev.u.peer.key_epoch = key_epoch;
    ev.u.peer.key_index = key_index;
    deliver(ex, &ev);
    drain(ex);
#ifdef GZP_TEST_BUILD
    /* The test traffic's own reconnect step: send again what is unanswered. */
    gzp_testping_connected(ex->tp, ex->net, link->remote.key);
#endif
}

static void on_disconnected(void *ctx, const gz_link_t *link, const char *why)
{
    gzp_exec_t *ex = ctx;
    gz_event_t ev;
    uint64_t peer_id = gzp_peer_id(link->remote.key);
    gzp_log("disconnected peer=%016llx why=%s", (unsigned long long)peer_id, why ? why : "-");
#ifdef GZP_TEST_BUILD
    {
        int *n = seen_count(peer_id, 0);
        if (n) (*n)--;
    }
#endif
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_PEER_DISCONNECTED;
    ev.u.peer.link = *link;
    deliver(ex, &ev);
    drain(ex);
}

static void on_message(void *ctx, const gz_link_t *link, uint16_t kind, const uint8_t scope[32],
                       const uint8_t *records, size_t len)
{
    gzp_exec_t *ex = ctx;
    gz_event_t ev;
#ifdef GZP_TEST_BUILD
    if (!seen_count(gzp_peer_id(link->remote.key), 0))
        gzp_log("test-order message-from-unreported-peer peer=%016llx",
                (unsigned long long)gzp_peer_id(link->remote.key));
    gzp_testping_message(ex->tp, link->remote.key, kind, records, len);
#endif
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_MESSAGE_RECEIVED;
    ev.u.message.link = *link;
    ev.u.message.kind = kind;
    memcpy(ev.u.message.scope, scope, 32);
    ev.u.message.records.data = records;
    ev.u.message.records.len = len;
    deliver(ex, &ev);
    drain(ex);
}

/* ---- user commands ------------------------------------------------------ */

#ifdef GZP_TEST_BUILD

/* A USER_COMMAND: request_id, command code, then the arguments (already a
 * TLV stream of records 10 and up). */
static void deliver_command(gzp_exec_t *ex, uint16_t code, const uint8_t *args, size_t args_len)
{
    uint8_t *buf = malloc(args_len + 64), c2[2];
    char rid[32];
    size_t at = 0;
    gz_event_t ev;
    if (!buf) abort();
    snprintf(rid, sizeof rid, "p-%llu-%llu", (unsigned long long)ex->incarnation,
             (unsigned long long)++ex->next_request);
    gz_put_u16(c2, code);
    if (gz_rec_put(buf, args_len + 64, &at, GZ_CMD_REC_REQUEST_ID, (const uint8_t *)rid, strlen(rid)) != GZ_OK ||
        gz_rec_put(buf, args_len + 64, &at, GZ_CMD_REC_COMMAND, c2, 2) != GZ_OK) {
        free(buf);
        return;
    }
    if (args_len) memcpy(buf + at, args, args_len);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_USER_COMMAND;
    ev.u.user.bytes.data = buf;
    ev.u.user.bytes.len = at + args_len;
    gzp_log("command id=%s code=0x%04x", rid, (unsigned)code);
    deliver(ex, &ev);
    drain(ex);
    free(buf);
}

/* Test commands from standard input (--test-commands), one per line:
 *   cmd CODE [ARGS-HEX]   a USER_COMMAND (CODE hex, ARGS a TLV stream of records 10 and up)
 *   chain-tx TXID-HEX CONF        a GZ_CHAIN_TX_CONFIRMED report
 *   tip HEIGHT                    a GZ_CHAIN_NEW_TIP
 *   chain-broadcast TX-HEX        bytes straight to the chain adapter's broadcast (pchain.c), as a
 *                                 BROADCAST action would; the result comes back as an event
 *   raw-kind KIND [zero]          a raw factory message of KIND on every connection
 *   sync-fail-ping                the next batch that holds a ping record is written and its sync fails
 * During a start a command is answered 503 node_stopped (contract-v2.md 1),
 * and the other lines wait. */
static void test_line(gzp_exec_t *ex, char *line)
{
    char *w = strtok(line, " "), *a1 = strtok(NULL, " "), *a2 = strtok(NULL, " ");
    gz_event_t ev;
    if (!w) return;
    if (!strcmp(w, "cmd") && a1) {
        unsigned long code = strtoul(a1, NULL, 16);
        size_t n = a2 ? strlen(a2) / 2 : 0;
        uint8_t *args = malloc(n + 1);
        if (!args) abort();
        if (ex->starting) {
            gzp_log("command-answer status=503 code=node_stopped reason=rebuilding");
        } else if (code <= 0xffff && (!a2 || gzp_unhex(a2, strlen(a2), args, n))) {
            deliver_command(ex, (uint16_t)code, args, n);
        } else {
            gzp_log("test-command bad line");
        }
        free(args);
        return;
    }
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_CHAIN;
    if (!strcmp(w, "chain-tx") && a1 && a2 && strlen(a1) == 64 && gzp_unhex(a1, 64, ev.u.chain.txid, 32)) {
        ev.u.chain.kind = GZ_CHAIN_TX_CONFIRMED;
        ev.u.chain.confirmations = (uint32_t)strtoul(a2, NULL, 10);
        gzp_log("test-chain-report confirmations=%u", ev.u.chain.confirmations);
        deliver(ex, &ev);
        drain(ex);
    } else if (!strcmp(w, "tip") && a1) {
        ev.u.chain.kind = GZ_CHAIN_NEW_TIP;
        ev.u.chain.height = (uint32_t)strtoul(a1, NULL, 10);
        deliver(ex, &ev);
        drain(ex);
    } else if (!strcmp(w, "chain-broadcast") && a1 && strlen(a1) % 2 == 0) {
        size_t n = strlen(a1) / 2;
        uint8_t *tx = malloc(n + 1);
        if (!tx) abort();
        if (gzp_unhex(a1, strlen(a1), tx, n)) {
            gzp_log("test-chain-broadcast len=%zu", n);
            chain_answer(ex, gzp_chain_broadcast(ex->chain, tx, n), "chain-backlog-full");
        } else {
            gzp_log("test-command bad line");
        }
        free(tx);
    } else if (!strcmp(w, "raw-kind") && a1) {
        gzp_net_test_raw(ex->net, (uint16_t)strtoul(a1, NULL, 10), a2 && !strcmp(a2, "zero"));
    } else if (!strcmp(w, "sync-fail-ping")) {
        if (ex->store.ops->test_fail_next_ping) ex->store.ops->test_fail_next_ping(ex->store.ctx);
        gzp_log("test-sync-fail armed for the next ping record");
    } else {
        gzp_log("test-command bad line");
    }
}

/* Read what standard input has and act on each whole line. During a start
 * only commands are taken (and refused); other lines stay for later. */
static void read_commands(gzp_exec_t *ex)
{
    for (;;) {
        char *nl;
        ssize_t r;
        if (ex->in_len < sizeof ex->in - 1 && !ex->in_eof) {
            r = read(0, ex->in + ex->in_len, sizeof ex->in - 1 - ex->in_len);
            if (r > 0) ex->in_len += (size_t)r;
            else if (r == 0) ex->in_eof = 1;
        }
        ex->in[ex->in_len] = 0;
        nl = memchr(ex->in, '\n', ex->in_len);
        if (!nl) {
            if (ex->in_len == sizeof ex->in - 1) ex->in_len = 0; /* an overlong line: dropped */
            return;
        }
        if (ex->starting && strncmp(ex->in, "cmd ", 4) != 0) return;
        *nl = 0;
        {
            size_t n = (size_t)(nl - ex->in) + 1;
            test_line(ex, ex->in); /* in place: nothing reads the buffer meanwhile */
            memmove(ex->in, ex->in + n, ex->in_len - n);
            ex->in_len -= n;
        }
        if (ex->fatal) return;
    }
}
#endif

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
    rd.guard.data = NULL;
    rd.guard.len = 0;
    if (rd.restored && ex->store.ops->guard &&
        ex->store.ops->guard(ex->store.ctx, &rd.guard.data, &rd.guard.len) == 1)
        gzp_log("restore-guard-file counter=%llu", (unsigned long long)(rd.guard.len >= 48 ? gz_get_u64(rd.guard.data + 40) : 0));
    ex->store.ops->rewind(ex->store.ctx);
    while (more && !ex->fatal) {
        gz_status_t st;
        gz_action_list_reset(&ex->list);
        st = gz_node_start(ex->node, &rd, &ex->list, &more);
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
            gzp_log("node-error engine=0x%04x status=%s", (unsigned)gz_node_error_area(ex->node), status_name(st));
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
    size_t nfds, nnet;
    int timeout = -1, t, i;
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
    /* Standard input, for test commands (test build, --test-commands). */
    fds[1].fd = -1;
    fds[1].events = POLLIN;
    fds[1].revents = 0;
#ifdef GZP_TEST_BUILD
    if (ex->opt->test_commands && !ex->in_eof) fds[1].fd = 0;
#endif
    nnet = gzp_net_pollfds(ex->net, fds + 2, cap - 3, &t, now);
    nfds = 2 + nnet;
    /* The chain worker's wake fd: readable when it has events. Not while
     * waiting for a batch to be stored (until_ms): events wait in its queue. */
    if (!until_ms && gzp_chain_fd(ex->chain) >= 0) {
        fds[nfds].fd = gzp_chain_fd(ex->chain);
        fds[nfds].events = POLLIN;
        fds[nfds].revents = 0;
        nfds++;
    }
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
    gzp_net_dispatch(ex->net, fds + 2, nnet, now);
#ifdef GZP_TEST_BUILD
    if (fds[1].revents && !ex->fatal) read_commands(ex);
#endif
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
#ifdef GZP_TEST_BUILD
        if (GZP_IS_TEST_TIMER(ex->timers[best].id)) {
            /* The incarnation that set it is in its id: an old incarnation's
             * timer firing after a restart shows as such. */
            uint64_t id = ex->timers[best].id;
            ex->timers[best].used = 0;
            gzp_log("test-timer fired incarnation=%llu", (unsigned long long)(id & 0xffffu));
            timer_set(ex, id, (uint64_t)ex->opt->test_timer_ms);
            continue;
        }
#endif
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
    /* Requests the worker answered BUSY: asked again, in order. */
    if (!ex->fatal) chain_answer(ex, gzp_chain_retry(ex->chain), "chain-request-refused");
    /* What the worker found, a bounded number per turn. */
    for (i = 0; i < 64 && !ex->fatal; i++) {
        gz_event_t ev;
        if (!gzp_chain_take(ex->chain, &ev)) break;
        deliver(ex, &ev);
        drain(ex);
    }
    return ex->fatal ? GZP_RUN_RESTART : -1;
}

/* ---- one incarnation ---------------------------------------------------- */

static const char *counter_name(int s)
{
    return s == GZP_COUNTER_FOUND             ? "found"
         : s == GZP_COUNTER_CREATED           ? "created"
         : s == GZP_COUNTER_SETUP_INTERRUPTED ? "setup_interrupted"
                                              : "missing";
}

/* After the start: what the options ask of the node. A member's --connect
 * is the test engine's "connect" command, given after each start (the
 * same target again changes nothing); the test engine saves the target
 * with a key index pair and issues CONNECT again at every start (contract-v2.md section 3). Then the
 * test commands waiting on standard input. */
static void after_start(gzp_exec_t *ex)
{
#ifdef GZP_TEST_BUILD
    uint8_t args[200];
    char addr[80];
    size_t at = 0;
    int a;
    if (ex->opt->have_connect && ex->opt->test_engines > 0) {
        snprintf(addr, sizeof addr, "%s:%u", ex->opt->connect_host, (unsigned)ex->opt->connect_port);
        if (gz_rec_put(args, sizeof args, &at, 12, ex->opt->connect_key, 33) == GZ_OK &&
            gz_rec_put(args, sizeof args, &at, 14, (const uint8_t *)addr, strlen(addr)) == GZ_OK)
            deliver_command(ex, GZ_TE_CMD_CONNECT, args, at);
    }
    for (a = 0; ex->opt->test_big_reply && a < ex->opt->test_engines && !ex->fatal; a++) {
        uint8_t ar[2], v[4];
        at = 0;
        gz_put_u16(ar, (uint16_t)(GZ_AREA_TEST + (unsigned)a));
        gz_put_u32(v, (uint32_t)ex->opt->test_big_reply);
        if (gz_rec_put(args, sizeof args, &at, 10, ar, 2) == GZ_OK && gz_rec_put(args, sizeof args, &at, 12, v, 4) == GZ_OK)
            deliver_command(ex, GZ_TE_CMD_BIG_REPLY, args, at);
    }
    if (ex->opt->test_commands && !ex->fatal) read_commands(ex);
#else
    if (ex->number == 1 && ex->opt->have_connect)
        gzp_log("connect: no engine in this build makes the connection yet (the lobby, P4.2)");
#endif
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
    gz_node_config_t cfg;
    gzp_net_events_t nev;
    struct pollfd *fds;
    size_t cap;
    uint64_t counter = 0;
    int rc = -1, cstate, restored, begun;

    ex->number = number;
    ex->incarnation = 0;
    ex->fatal = 0;
    ex->fatal_stop = 0;
    ex->fatal_why = NULL;
    ex->storage_broken = 0;
    ex->starting = 0;
    ex->resent = 0;
    memset(ex->timers, 0, sizeof ex->timers); /* the old incarnation's timers never fire */
    gzp_chain_restart(ex->chain);             /* the start sets watches again */
#ifdef GZP_TEST_BUILD
    memset(seen, 0, sizeof seen); /* the new node has seen no connection */
#endif

    nev.connected = on_connected;
    nev.disconnected = on_disconnected;
    nev.message = on_message;
    nev.ctx = ex;
    ex->net->ev = nev;
    gzp_net_queue_begin(ex->net); /* nothing reaches a starting node */

    /* Storage (program.md 2, steps 2 and 3): the store the unlock opened
     * for this incarnation, or a new one over the unlocked wallet. The
     * stand-in only for the tests that read its files. */
#ifdef GZP_TEST_BUILD
    if (ex->opt->test_standin_store) {
        if (number == 1 && ex->opt->test_restore_from &&
            gzp_standin_put_restore(ex->dir->dir, ex->opt->test_restore_from, err, sizeof err) != 0) {
            fprintf(stderr, "gazpacho: %s\n", err);
            return GZP_RUN_FAILED;
        }
        if (gzp_standin_open(&ex->store, ex->dir->dir, err, sizeof err) != 0) {
            fprintf(stderr, "gazpacho: cannot open storage: %s\n", err);
            return GZP_RUN_FAILED;
        }
        begun = 0;
    } else
#endif
    if (gzp_wallet_take_store(ex->wallet, &ex->store) == 0) {
        begun = 1; /* the unlock opened it: fence, start rule, incarnation */
    } else if (gzp_wallet_open_store(ex->wallet, &ex->store, err, sizeof err) != 0) {
        fprintf(stderr, "gazpacho: cannot open storage: %s\n", err);
        return GZP_RUN_FAILED;
    } else {
        begun = 0;
    }
    ex->store_open = 1;
#ifdef GZP_TEST_BUILD
    if (number == 1 && ex->opt->test_storage_fail_at && ex->store.ops->test_fail_at)
        ex->store.ops->test_fail_at(ex->store.ctx, (unsigned)ex->opt->test_storage_fail_at);
    if (ex->store.ops->test_hooks)
        ex->store.ops->test_hooks(ex->store.ctx, number == 1 ? (unsigned)ex->opt->test_sync_fail_at : 0u,
                                  ex->opt->test_cut_fail, number == 1 && ex->opt->test_crash_after_counter,
                                  ex->opt->name);
#endif
    /* The incarnation is durable before the runner exists (runner.h), and
     * above every number this folder has used (the start counter). */
    if (!begun) {
        int br = ex->store.ops->begin(ex->store.ctx, &ex->incarnation, err, sizeof err);
        if (br == GZP_STORE_BEHIND) {
            /* Files behind (storage 6.3) found at a restart from storage: the
             * keys stay, the node does not start; a person decides. */
            gzp_log("start-refused why=files-behind");
            gzp_exec_close_storage(ex);
            return GZP_RUN_FAILED;
        }
        if (br != 0) {
            fprintf(stderr, "gazpacho: cannot start storage: %s\n", err);
            gzp_log("start-refused why=storage");
            gzp_exec_close_storage(ex);
            return GZP_RUN_FAILED;
        }
    } else {
        ex->incarnation = gzp_journal_store_incarnation(&ex->store); /* the unlock's open wrote it */
    }
    if (gzp_datadir_sync(ex->dir) != 0) {
        fprintf(stderr, "gazpacho: cannot sync the data folder\n");
        gzp_log("start-refused why=storage");
        gzp_exec_close_storage(ex);
        return GZP_RUN_FAILED;
    }
    if (gzp_store_cut_bytes(&ex->store))
        gzp_log("journal-cut torn_bytes=%llu", (unsigned long long)gzp_store_cut_bytes(&ex->store));
    restored = ex->store.ops->restored(ex->store.ctx);
    cstate = gzp_store_counter_state(&ex->store, &counter);
    gzp_log("start-counter state=%s incarnation=%llu restored=%d", counter_name(cstate),
            (unsigned long long)ex->incarnation, restored);
    /* Beside the set-up marker the words are softer, but the person is still
     * told: the marker is not authenticated, so a planted one could hide a
     * real removal of a used wallet's records. */
    if (cstate == GZP_COUNTER_SETUP_INTERRUPTED)
        gzp_log("start-counter was not found; set-up may have been interrupted: a restore with a new epoch; "
                "the person is told");
    if (cstate == GZP_COUNTER_MISSING) {
        if (restored)
            gzp_log("restore counter_found=0: the person is told (the restore rests on the epoch's random draw)");
        else
            gzp_log("start-counter was missing: rewritten from the journal; the person is told once");
    }

    memset(&ports, 0, sizeof ports);
    ports.random.fill = port_random;
    ports.clock.now_ms = port_clock;
    ports.clock.mono_ms = port_mono;
    memset(&cfg, 0, sizeof cfg);
    cfg.host = ex->opt->role == GZP_ROLE_HOST;
    if (ex->chain_hash) memcpy(cfg.chain, ex->chain_hash, 32);
    cfg.keys.pub = port_pub;
    cfg.keys.secret = port_secret;
    cfg.keys.host_pub = port_host_pub;
    cfg.keys.ctx = ex;
    cfg.host_funding = GZ_HOST_FUNDING_AUTO;
    cfg.member_signing = (gz_member_signing_t)ex->opt->member_signing;
    cfg.crypto.verify = port_verify;
    cfg.crypto.point_ok = port_point_ok;
    cfg.crypto.sign = port_sign;
    cfg.crypto.forget = port_forget;
    cfg.crypto.ctx = ex;
#ifdef GZP_TEST_BUILD
    cfg.test_sign_outcome = (uint32_t)ex->opt->test_sign_outcome;
    cfg.test_sign_delay_ms = (uint32_t)ex->opt->test_sign_delay_ms;
    cfg.test_engines = (uint32_t)ex->opt->test_engines;
#endif
    if (!ex->node && !(ex->node = malloc(gz_node_size()))) abort();
    if (gz_node_init(ex->node, &ports, &cfg, ex->incarnation) != GZ_OK ||
        gz_runner_init(&ex->runner, ex->rslots, GZP_RUNNER_SLOTS, ex->rbytes, GZP_RUNNER_BYTES,
                       ex->incarnation, execute, ex) != GZ_OK) {
        gzp_exec_close_storage(ex);
        return GZP_RUN_FAILED;
    }
    gz_action_list_init(&ex->list, ex->lslots, GZP_LIST_SLOTS, ex->lbytes, GZP_LIST_BYTES);

    cap = 3 + gzp_net_max_fds(ex->net);
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
    if (ex->fatal && gzp_store_poisoned(&ex->store)) rc = GZP_RUN_RESTART; /* turned into POISONED below */
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
        after_start(ex);
    }
    while (rc < 0) rc = turn(ex, fds, cap, 0);
    free(fds);
    if (rc == GZP_RUN_RESTART && ex->fatal_stop && !gzp_store_poisoned(&ex->store)) {
        gzp_log("stopping why=%s: a restart from storage cannot fix it", ex->fatal_why);
        rc = GZP_RUN_LIMIT;
    }
    if (rc != GZP_RUN_STOP && gzp_store_poisoned(&ex->store)) {
        gzp_log("storage poisoned: a failed write could not be undone; not restarting (storage.failed)");
        rc = GZP_RUN_POISONED;
    }
    if (rc != GZP_RUN_STOP) gzp_exec_close_storage(ex);
    return rc;
}
