/* Test nodes shared by the simulator tests.
 *
 * The "multi" node does more per step than the placeholder ping node: three
 * save batches in one list with a notify, watches of a script, of its
 * transaction and of the outpoint that transaction spends, a broadcast, a
 * timer and two sends between and after them, and a start that answers the
 * restore marker, watches, re-broadcasts and resends from what storage
 * holds. It exists so the simulator exercises the runner with several batches
 * unconfirmed at once and with every kind of action.
 *
 * Each message or command also makes the multi node use a one-time secret,
 * which it shows through its inspection hook, so that the invariant
 * "no one-time secret is used twice" (below) has something to judge. How the
 * secret is made is set by g_secret_mode: the correct way, and three wrong
 * ways the invariant must catch.
 *
 * Also here: programs that are FAULTY ON PURPOSE, which the harness must
 * catch. They live in the tests, never in the library. */
#ifndef GAZPACHO_TEST_SIM_NODES_H
#define GAZPACHO_TEST_SIM_NODES_H

#include "sim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MULTI_RECORD_DECISION 0xd1u     /* a transaction the node decided to broadcast */
#define MULTI_RECORD_MESSAGE  0xa1u     /* 8-byte little-endian peer, then a message to send */
#define MULTI_RECORD_NOTE     0xc1u
#define MULTI_RECORD_COUNTER  0xe1u     /* 8-byte little-endian count of secrets used (journal-counter mode) */
#define MULTI_RECORD_RESTORED 0xf1u     /* the restore batch: the 8-byte incarnation it answers */
#define MULTI_MAX             64        /* largest input the multi node acts on */
#define MULTI_TX_MAX          (3 + 36 + 1 + MULTI_MAX)   /* its transaction: one input, 'T', the input */
#define MULTI_DEPTH           2         /* confirmations its watches follow */

static inline uint32_t multi_u32(const uint8_t *p);
static inline uint64_t multi_peer(const uint8_t *p);

/* ---- one-time secrets ---- */

#define SECRET_LEN  16
#define SECRETS_MAX 512                 /* per incarnation */

typedef enum {
    SECRET_CORRECT,          /* random bytes mixed with the incarnation, which never repeats */
    SECRET_NAIVE,            /* random bytes alone, drawn tagged as a secret */
    SECRET_NAIVE_UNTAGGED,   /* random bytes alone, drawn with the "other" tag */
    SECRET_JOURNAL_COUNTER   /* derived from a counter kept in the journal, no randomness */
} secret_mode_t;

static secret_mode_t g_secret_mode = SECRET_CORRECT;
static int g_secret_leaks;              /* 1: the node also sends the raw bytes it drew for a secret (wrong) */

/* What a node using secrets keeps: the secrets this incarnation used, shown
 * through the inspection hook as a 4-byte little-endian count followed by the
 * secrets. */
typedef struct {
    const gz_ports_t *ports;
    uint64_t incarnation, counter;
    uint8_t last_drawn[SECRET_LEN];     /* the port's bytes behind the newest secret */
    uint8_t used[SECRETS_MAX][SECRET_LEN];
    size_t n_used;
} secrets_t;

static inline void secrets_init(secrets_t *k, const gz_ports_t *ports, const sim_storage_t *storage, uint64_t journal_counter)
{
    k->ports = ports;
    k->incarnation = sim_storage_incarnation(storage);
    k->counter = journal_counter;
    k->n_used = 0;
}

/* Make the next one-time secret in the way g_secret_mode says, and keep it. */
static inline void secret_use(secrets_t *k, uint8_t out[SECRET_LEN])
{
    uint8_t drawn[SECRET_LEN] = {0};
    uint64_t n = ++k->counter;
    if (g_secret_mode == SECRET_JOURNAL_COUNTER) {
        uint64_t h = 0xcbf29ce484222325ull;
        for (int i = 0; i < 8; i++) h = (h ^ (uint8_t)(n >> (8 * i))) * 0x100000001b3ull;
        for (int i = 0; i < SECRET_LEN; i++) drawn[i] = (uint8_t)(h >> (8 * (i % 8))) ^ (uint8_t)i;
    } else {
        k->ports->random.fill(k->ports->random.ctx, g_secret_mode == SECRET_NAIVE_UNTAGGED ? GZ_RANDOM_ORDINARY : GZ_RANDOM_SECRET,
                              drawn, sizeof drawn);
    }
    memcpy(k->last_drawn, drawn, SECRET_LEN);
    if (g_secret_mode == SECRET_CORRECT)
        for (int i = 0; i < 8; i++) {
            drawn[i] ^= (uint8_t)(k->incarnation >> (8 * i));
            drawn[8 + i] ^= (uint8_t)(n >> (8 * i));
        }
    memcpy(out, drawn, SECRET_LEN);
    if (k->n_used < SECRETS_MAX) memcpy(k->used[k->n_used++], drawn, SECRET_LEN);
}

static inline size_t secrets_inspect(const secrets_t *k, uint8_t *out, size_t cap)
{
    size_t len = 4 + SECRET_LEN * k->n_used;
    if (cap < len) return 0;
    for (int i = 0; i < 4; i++) out[i] = (uint8_t)(k->n_used >> (8 * i));
    memcpy(out + 4, k->used, SECRET_LEN * k->n_used);
    return len;
}

/* The invariant "no one-time secret is used twice", over the whole run,
 * across crashes and restores: it judges the secrets the nodes actually used,
 * as their inspection hooks show them, not what they drew from the port. */
typedef struct {
    uint32_t n_nodes;
    uint64_t last_incarnation[64];
    size_t absorbed[64];
    uint8_t (*seen)[SECRET_LEN];
    size_t n_seen, cap_seen;
    size_t checked;             /* secrets judged, for tests that must see some */
} secret_watch_t;

static inline int no_secret_used_twice(const sim_t *sim, void *ctx, const char **why)
{
    secret_watch_t *w = ctx;
    static uint8_t shown[4 + SECRET_LEN * SECRETS_MAX];
    for (uint32_t node = 0; node < w->n_nodes && node < 64; node++) {
        size_t len = sim_node_inspect(sim, node, shown, sizeof shown);
        size_t n = len >= 4 ? multi_u32(shown) : 0;
        if (sim_node_incarnation(sim, node) != w->last_incarnation[node]) {
            w->last_incarnation[node] = sim_node_incarnation(sim, node);
            w->absorbed[node] = 0;
        }
        for (size_t i = w->absorbed[node]; i < n; i++) {
            const uint8_t *secret = shown + 4 + SECRET_LEN * i;
            for (size_t k = 0; k < w->n_seen; k++)
                if (memcmp(w->seen[k], secret, SECRET_LEN) == 0) {
                    *why = "a one-time secret was used twice";
                    return 0;
                }
            if (w->n_seen == w->cap_seen) {
                w->cap_seen = w->cap_seen ? 2 * w->cap_seen : 64;
                w->seen = realloc(w->seen, w->cap_seen * SECRET_LEN);
                if (!w->seen) abort();
            }
            memcpy(w->seen[w->n_seen++], secret, SECRET_LEN);
            w->checked++;
        }
        if (n > w->absorbed[node]) w->absorbed[node] = n;
    }
    return 1;
}

static inline void secret_watch_free(secret_watch_t *w) { free(w->seen); memset(w, 0, sizeof *w); }

/* "A node's restore epochs all differ" (safety-rule.md R2), for the
 * composite node: every nonzero key_epoch record (type 0x00040002, TLV 2: the
 * 4-byte big-endian epoch; 0 is the epoch at installation) seen in a node's
 * storage is remembered with its batch's incarnation, since
 * a later restore cuts storage back; two different incarnations of one node
 * with the same epoch fail the run. Free `seen` after the run. */
typedef struct { uint32_t node; uint64_t incarnation; uint32_t epoch; } epoch_seen_t;
typedef struct { uint32_t n_nodes; epoch_seen_t *seen; size_t n, cap; } epoch_watch_t;

static inline uint32_t sn_le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static inline uint64_t sn_be(const uint8_t *p, int n) { uint64_t v = 0; for (int i = 0; i < n; i++) v = v << 8 | p[i]; return v; }

static inline int restore_epochs_differ(const sim_t *sim, void *ctx, const char **why)
{
    epoch_watch_t *w = ctx;
    for (uint32_t node = 0; node < w->n_nodes; node++) {
        const sim_storage_t *st = sim_node_storage(sim, node);
        for (size_t i = 0; i < sim_storage_count(st); i++) {
            size_t len = 0, at = 0;
            const uint8_t *b = sim_storage_batch_bytes(st, i, &len);
            while (at + 8 <= len) {
                uint32_t type = sn_le32(b + at), rlen = sn_le32(b + at + 4);
                if (at + 8 + rlen > len) break;
                if (type == 0x00040002u && rlen == 6 && sn_be(b + at + 10, 4) != 0) {
                    uint64_t inc = sim_storage_batch_id(st, i).incarnation;
                    uint32_t epoch = (uint32_t)sn_be(b + at + 10, 4);
                    int known = 0;
                    for (size_t k = 0; k < w->n; k++) {
                        if (w->seen[k].node != node) continue;
                        if (w->seen[k].incarnation == inc) { known = 1; continue; }
                        if (w->seen[k].epoch == epoch) { *why = "two restores of a node drew the same restore epoch"; return 0; }
                    }
                    if (!known) {
                        if (w->n == w->cap) {
                            w->cap = w->cap ? 2 * w->cap : 16;
                            w->seen = realloc(w->seen, w->cap * sizeof *w->seen);
                            if (!w->seen) abort();
                        }
                        w->seen[w->n++] = (epoch_seen_t){node, inc, epoch};
                    }
                }
                at += 8 + rlen;
            }
        }
    }
    return 1;
}

/* Number of draws all nodes made with the secret tag. */
static inline size_t secret_draws(const sim_t *sim, uint32_t n_nodes)
{
    size_t n = 0;
    for (uint32_t node = 0; node < n_nodes; node++)
        for (size_t i = 0; i < sim_node_draw_count(sim, node); i++)
            n += sim_node_draw(sim, node, i)->purpose == GZ_RANDOM_SECRET;
    return n;
}

typedef struct {
    uint8_t decision[MULTI_TX_MAX]; size_t decision_len;    /* newest stored decision, if any */
    int restored;                                           /* started with the restore marker */
    uint8_t message[MULTI_MAX + 9]; size_t message_len;     /* newest stored message record, if any */
    secrets_t secrets;
} multi_node_t;

static inline uint32_t multi_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* Remember the newest decision and the newest message found in storage, and
 * the newest secret counter. */
static inline void *multi_create(void *ctx, uint32_t index, const gz_ports_t *ports, const sim_storage_t *storage)
{
    (void)index;
    multi_node_t *m = calloc(1, sizeof *m);
    uint64_t counter = 0;
    if (!m) abort();
    if (ctx) (*(int *)ctx)++;           /* tests may count how often each simulator builds a node */
    for (size_t i = 0; i < sim_storage_count(storage); i++) {
        size_t len = 0;
        const uint8_t *p = sim_storage_batch_bytes(storage, i, &len), *end = p + len;
        for (; p < end; p += 8 + multi_u32(p + 4)) {
            uint32_t type = multi_u32(p), n = multi_u32(p + 4);
            if (type == MULTI_RECORD_DECISION && n <= sizeof m->decision) { memcpy(m->decision, p + 8, n); m->decision_len = n; }
            if (type == MULTI_RECORD_MESSAGE && n <= sizeof m->message) { memcpy(m->message, p + 8, n); m->message_len = n; }
            if (type == MULTI_RECORD_COUNTER && n == 8) counter = multi_peer(p + 8);
        }
    }
    secrets_init(&m->secrets, ports, storage, counter);
    m->restored = sim_storage_restored(storage);
    return m;
}

static inline size_t multi_inspect(const void *node, uint8_t *out, size_t cap)
{
    return secrets_inspect(&((const multi_node_t *)node)->secrets, out, cap);
}

static inline void multi_destroy(void *ctx, void *node) { (void)ctx; free(node); }

static inline gz_status_t multi_add(gz_action_list_t *out, gz_action_kind_t kind, uint64_t number, const uint8_t *bytes, size_t len)
{
    gz_action_t a = {.kind = kind};
    gz_bytes_t b = {bytes, len};
    switch (kind) {
    case GZ_ACTION_SEND:      sim_peer_key(number, a.u.send.link.remote.key); a.u.send.kind = 32767; a.u.send.records = b; break;
    case GZ_ACTION_BROADCAST: a.u.broadcast.tx = b; break;
    case GZ_ACTION_WATCH_TX:  sim_pretend_txid(bytes, len, a.u.watch_tx.txid); a.u.watch_tx.depth = (uint32_t)number; break;
    case GZ_ACTION_WATCH_OUTPOINT:      /* the outpoint `bytes` names: 32-byte txid, then vout */
        memcpy(a.u.watch_outpoint.outpoint.txid, bytes, 32);
        a.u.watch_outpoint.outpoint.vout = multi_u32(bytes + 32);
        a.u.watch_outpoint.depth = (uint32_t)number;
        break;
    case GZ_ACTION_NOTIFY:    a.u.notify.code = (uint32_t)number; a.u.notify.bytes = b; break;
    default:                  a.u.set_timer.timer_id = number; a.u.set_timer.delay_ms = len; break;
    }
    return gz_action_list_add(out, &a);
}

static inline gz_status_t multi_save(gz_action_list_t *out, uint32_t type, const uint8_t *bytes, size_t len)
{
    gz_record_t r = {type, {bytes, len}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    return gz_action_list_add(out, &a);
}

static inline uint64_t multi_peer(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* The outpoint a decision's transaction spends, as 36 bytes: 32-byte txid,
 * 4-byte vout low byte first. 0 if `tx` is not one of the multi node's. */
static inline int multi_input(const uint8_t *tx, size_t len, uint8_t out[36])
{
    if (len < 3 + 36 || tx[0] != 0 || tx[1] != 0xF0 || tx[2] != 1) return 0;
    memcpy(out, tx + 3, 36);
    return 1;
}

/* At start: answer the restore marker first, with a save; then watch and
 * timer again, broadcast the newest stored decision again and watch it, send
 * the newest stored message again. */
static inline gz_status_t multi_start(void *node, gz_action_list_t *out, int *more)
{
    multi_node_t *m = node;
    uint8_t record[8], input[36];
    *more = 0;                          /* everything it has to do fits one list */
    gz_status_t st = GZ_OK;
    if (m->restored) {
        for (int i = 0; i < 8; i++) record[i] = (uint8_t)(m->secrets.incarnation >> (8 * i));
        st = multi_save(out, MULTI_RECORD_RESTORED, record, sizeof record);
    }
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_WATCH_TX, 1, (const uint8_t *)"multi", 5);
    if (st == GZ_OK && m->decision_len) st = multi_add(out, GZ_ACTION_WATCH_TX, MULTI_DEPTH, m->decision, m->decision_len);
    if (st == GZ_OK && multi_input(m->decision, m->decision_len, input))
        st = multi_add(out, GZ_ACTION_WATCH_OUTPOINT, MULTI_DEPTH, input, sizeof input);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_SET_TIMER, 5, NULL, 3);
    if (st == GZ_OK && m->decision_len) st = multi_add(out, GZ_ACTION_BROADCAST, 0, m->decision, m->decision_len);
    if (st == GZ_OK && m->message_len >= 8)
        st = multi_add(out, GZ_ACTION_SEND, multi_peer(m->message), m->message + 8, m->message_len - 8);
    return st;
}

/* For a message or a user command carrying bytes b:
 *   save{decision: tx}  save{message}  notify  watch b (as a transaction)  watch tx
 *   watch its input  broadcast tx  timer  send "M"+b  save{note}  send "C"+b
 * and a one-time secret is used (with, in journal-counter mode, a save of the
 * counter first). The transaction spends output 0 of the pretend transaction
 * whose bytes are b, so two commands with the same bytes conflict. */
static inline gz_status_t multi_handle(void *node, const gz_event_t *ev, gz_action_list_t *out)
{
    multi_node_t *m = node;
    uint8_t secret[SECRET_LEN], counter[8];
    gz_bytes_t b;
    uint64_t peer;
    if (ev->kind == GZ_EVENT_MESSAGE_RECEIVED) { b = ev->u.message.records; peer = sim_key_peer(ev->u.message.link.remote.key); }
    else if (ev->kind == GZ_EVENT_USER_COMMAND) { b = ev->u.user.bytes; peer = SIM_WORLD_PEER; }
    else return GZ_OK;
    if (b.len == 0 || b.len > MULTI_MAX) return GZ_OK;

    uint8_t tx[MULTI_TX_MAX], tag[MULTI_MAX + 1] = {'T'}, record[MULTI_MAX + 9], text[MULTI_MAX + 1] = {'M'}, input[36];
    gz_outpoint_t spent = {{0}, 0};
    sim_pretend_txid(b.data, b.len, spent.txid);
    memcpy(tag + 1, b.data, b.len);
    size_t tx_len = sim_pretend_tx(tx, sizeof tx, &spent, 1, tag, b.len + 1);
    memcpy(input, spent.txid, 32);
    memset(input + 32, 0, 4);
    for (int i = 0; i < 8; i++) record[i] = (uint8_t)(peer >> (8 * i));
    record[8] = 'M';
    memcpy(record + 9, b.data, b.len);
    memcpy(text + 1, b.data, b.len);

    gz_status_t st = GZ_OK;
    if (g_secret_mode == SECRET_JOURNAL_COUNTER) {
        for (int i = 0; i < 8; i++) counter[i] = (uint8_t)((m->secrets.counter + 1) >> (8 * i));
        st = multi_save(out, MULTI_RECORD_COUNTER, counter, 8);
    }
    if (st == GZ_OK) st = multi_save(out, MULTI_RECORD_DECISION, tx, tx_len);
    if (st == GZ_OK) st = multi_save(out, MULTI_RECORD_MESSAGE, record, b.len + 9);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_NOTIFY, 1, b.data, b.len);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_WATCH_TX, 1, b.data, b.len);   /* (once a script watch) */
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_WATCH_TX, MULTI_DEPTH, tx, tx_len);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_WATCH_OUTPOINT, MULTI_DEPTH, input, sizeof input);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_BROADCAST, 0, tx, tx_len);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_SET_TIMER, 5, NULL, 3);
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_SEND, peer, text, b.len + 1);
    if (st == GZ_OK) st = multi_save(out, MULTI_RECORD_NOTE, b.data, b.len);
    text[0] = 'C';
    if (st == GZ_OK) st = multi_add(out, GZ_ACTION_SEND, peer, text, b.len + 1);
    if (st == GZ_OK) secret_use(&m->secrets, secret);
    if (st == GZ_OK && g_secret_leaks)
        st = multi_add(out, GZ_ACTION_SEND, peer, m->secrets.last_drawn, SECRET_LEN);
    return st;
}

static inline sim_node_ops_t multi_ops(void)
{
    sim_node_ops_t ops = {.create = multi_create, .destroy = multi_destroy, .start = multi_start, .handle = multi_handle,
                          .inspect = multi_inspect};
    return ops;
}

/* "Saved, so eventually sent, to a peer that comes back", for the default
 * node's test engine (node.h rule 6: replies are pulled by the pinger's
 * hello). To be called at the end of a run with a quiet tail (sim_quiesce,
 * then enough steps for every delay to pass). Returns the number of durable
 * ping records from another node, over all nodes, whose reply has not left
 * its node at least once for each time it was saved. The world never comes
 * back with a hello, so pings from it are not counted. A ping record is the
 * clock (8), the link (local 33, remote 33), the serial (8), the payload; the
 * reply is the envelope of kind 32767 with record 1 "GZPO", serial, payload
 * and record 3 the area. Whether a reply left is read from the trace, which
 * records the sender, the peer, the length and a digest of every message
 * handed to the network, delivered or dropped. */
static inline size_t saved_replies_not_sent(const sim_t *sim, uint32_t n_nodes)
{
    const char *trace = sim_trace(sim, NULL);
    size_t missing = 0;
    for (uint32_t node = 0; node < n_nodes; node++) {
        const sim_storage_t *st = sim_node_storage(sim, node);
        static char seen[1024][80];
        size_t n_seen = 0;
        for (size_t i = 0; i < sim_storage_count(st); i++) {
            size_t len = 0;
            const uint8_t *p = sim_storage_batch_bytes(st, i, &len), *end = p + len;
            for (; p < end; p += 8 + multi_u32(p + 4)) {
                uint32_t n = multi_u32(p + 4);
                if (multi_u32(p) != 0x7e570001u || n < 82 || n > 82 + 64) continue;
                uint64_t peer = sim_key_peer(p + 8 + 41), digest = 0xcbf29ce484222325ull;
                if (peer == SIM_WORLD_PEER) continue;
                uint8_t env[38 + 2 + 4 + 8 + 64 + 4] = {0x67, 0x7a, 0x66, 0x01, 0x7f, 0xff};
                size_t at = 38, plen = n - 82, earlier = 0, left = 0;
                env[at++] = 1;
                env[at++] = (uint8_t)(4 + 8 + plen);
                memcpy(env + at, "GZPO", 4);
                memcpy(env + at + 4, p + 8 + 74, 8);
                memcpy(env + at + 12, p + 8 + 82, plen);
                at += 12 + plen;
                env[at++] = 3;
                env[at++] = 2;
                env[at++] = 0x7e;
                env[at++] = 0x57;
                char needle[80];
                for (size_t k = 0; k < at; k++) digest = (digest ^ env[k]) * 0x100000001b3ull;
                snprintf(needle, sizeof needle, " %u->%lld len=%zu digest=%016llx", node, (long long)peer, at,
                         (unsigned long long)digest);
                for (size_t k = 0; k < n_seen; k++) earlier += strcmp(seen[k], needle) == 0;
                if (n_seen < 1024) strcpy(seen[n_seen++], needle);
                for (const char *t = strstr(trace, needle); t; t = strstr(t + 1, needle)) left++;
                missing += left <= earlier;
            }
        }
    }
    return missing;
}

/* FAULTY ON PURPOSE: a program that carries out every action at once instead
 * of going through the runner. */
static inline gz_status_t eager_release(void *ctx, sim_t *sim, uint32_t index, const gz_action_list_t *list)
{
    (void)ctx;
    for (size_t i = 0; i < list->count; i++) sim_execute(sim, index, &list->slots[i]);
    return GZ_OK;
}

#endif
