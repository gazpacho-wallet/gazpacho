#include "sim.h"
#include "rng.h"
#include "gazpacho/node.h"
#include "gazpacho/runner.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STEP_SLOTS     16      /* actions one node step may return */
#define STEP_BYTES     4096
#define RUNNER_SLOTS   64      /* actions one node's runner may hold */
#define RUNNER_BYTES   16384
#define MAX_INVARIANTS 8
#define NEVER          UINT64_MAX
#define FNV_OFFSET     0xcbf29ce484222325ull
#define FNV_PRIME      0x100000001b3ull

typedef struct { uint8_t *bytes; size_t len; } blob_t;
typedef struct { uint64_t id; blob_t blob; uint64_t due; } batch_t;
typedef struct { uint64_t from, to; blob_t blob; uint64_t due, seq; } message_t;
typedef struct { uint64_t id, due; } node_timer_t;
typedef struct { blob_t blob; uint32_t origin; uint32_t height; } chain_tx_t;   /* height 0: in the mempool */

/* An outward action the harness saw a node emit and has not yet seen leave. */
typedef struct { uint64_t digest; size_t saves_before; } expected_t;

struct sim_storage {
    batch_t *durable; size_t n_durable, cap_durable;
    batch_t *pending; size_t n_pending, cap_pending;
};

/* One simulated node and everything around it. */
typedef struct {
    sim_t *sim;
    uint32_t index;
    void *node;
    gz_ports_t ports;
    sim_rng_t rng;
    gz_runner_t runner;
    gz_action_t runner_slots[RUNNER_SLOTS];
    uint8_t runner_bytes[RUNNER_BYTES];
    struct sim_storage storage;
    node_timer_t *timers; size_t n_timers, cap_timers;
    blob_t *watches; size_t n_watches, cap_watches;
    /* What the harness observed this node emit since it was last built, for
     * the save-before-send check. Kept apart from the runner on purpose. */
    uint64_t *emitted; size_t n_emitted, cap_emitted;
    expected_t *expected; size_t n_expected, head_expected, cap_expected;
} slot_t;

struct sim {
    sim_config_t cfg;
    sim_rng_t rng;
    uint64_t step;
    slot_t *slots;
    message_t *net; size_t n_net, cap_net;
    uint64_t next_seq;
    chain_tx_t *txs; size_t n_txs, cap_txs;
    uint32_t height;
    char *trace; size_t trace_len, trace_cap;
    uint64_t trace_hash;
    sim_stats_t stats;
    struct { sim_invariant_fn check; void *ctx; } invariants[MAX_INVARIANTS];
    size_t n_invariants;
    const char *violation;          /* set when save-before-send is seen broken */
    int failed;
    uint64_t failure_step;
    const char *failure_reason;
    sim_t *twin;                    /* same configuration, run in lockstep */
};

/* ---- small helpers ---- */

static void *grow(void *p, size_t *cap, size_t need, size_t elem)
{
    if (need <= *cap) return p;
    size_t n = *cap ? *cap * 2 : 8;
    while (n < need) n *= 2;
    p = realloc(p, n * elem);
    if (!p) abort();
    *cap = n;
    return p;
}

static blob_t blob_copy(const uint8_t *bytes, size_t len)
{
    blob_t b = {malloc(len ? len : 1), len};
    if (!b.bytes) abort();
    if (len) memcpy(b.bytes, bytes, len);
    return b;
}

static uint64_t fnv(uint64_t h, const void *data, size_t len)
{
    const uint8_t *p = data;
    for (size_t i = 0; i < len; i++) h = (h ^ p[i]) * FNV_PRIME;
    return h;
}

static uint64_t fnv_u64(uint64_t h, uint64_t v) { return fnv(h, &v, sizeof v); }

static uint64_t digest_bytes(const uint8_t *bytes, size_t len) { return fnv(FNV_OFFSET, bytes, len); }

__attribute__((format(printf, 2, 3)))
static void trace(sim_t *sim, const char *fmt, ...)
{
    char line[256];
    va_list ap;
    int n = snprintf(line, sizeof line, "%llu ", (unsigned long long)sim->step);
    va_start(ap, fmt);
    n += vsnprintf(line + n, sizeof line - (size_t)n - 1, fmt, ap);
    va_end(ap);
    if (n > (int)sizeof line - 2) n = (int)sizeof line - 2;
    line[n++] = '\n';
    sim->trace = grow(sim->trace, &sim->trace_cap, sim->trace_len + (size_t)n + 1, 1);
    memcpy(sim->trace + sim->trace_len, line, (size_t)n);
    sim->trace_len += (size_t)n;
    sim->trace[sim->trace_len] = 0;
    sim->trace_hash = fnv(sim->trace_hash, line, (size_t)n);
}

/* ---- the save-before-send observer ---- */

static uint64_t action_digest(const gz_action_t *a)
{
    uint64_t h = fnv_u64(FNV_OFFSET, (uint64_t)a->kind);
    if (a->kind == GZ_ACTION_SEND) {
        h = fnv_u64(h, a->u.send.peer_id);
        h = fnv(h, a->u.send.bytes.data, a->u.send.bytes.len);
    } else if (a->kind == GZ_ACTION_BROADCAST) {
        h = fnv(h, a->u.broadcast.tx.data, a->u.broadcast.tx.len);
    } else if (a->kind == GZ_ACTION_NOTIFY) {
        h = fnv_u64(h, a->u.notify.code);
        h = fnv(h, a->u.notify.bytes.data, a->u.notify.bytes.len);
    }
    return h;
}

/* Record, in order, the saves and outward actions a node step returned. */
static void note_emitted(slot_t *s, const gz_action_list_t *list)
{
    for (size_t i = 0; i < list->count; i++) {
        const gz_action_t *a = &list->slots[i];
        if (a->kind == GZ_ACTION_SAVE) {
            s->emitted = grow(s->emitted, &s->cap_emitted, s->n_emitted + 1, sizeof *s->emitted);
            s->emitted[s->n_emitted++] = a->u.save.batch_id;
        } else if (gz_action_is_outward(a)) {
            s->expected = grow(s->expected, &s->cap_expected, s->n_expected + 1, sizeof *s->expected);
            s->expected[s->n_expected++] = (expected_t){action_digest(a), s->n_emitted};
        }
    }
}

static int all_emitted_durable(const slot_t *s)
{
    for (size_t i = 0; i < s->n_emitted; i++)
        if (!sim_storage_has(&s->storage, s->emitted[i])) return 0;
    return 1;
}

/* An outward action is leaving a node. It must be the next one the node
 * emitted, and every save the node emitted before it must be in storage. */
static void note_left(slot_t *s, const gz_action_t *a)
{
    sim_t *sim = s->sim;
    if (s->head_expected == s->n_expected ||
        s->expected[s->head_expected].digest != action_digest(a)) {
        if (!sim->violation) sim->violation = "an action left a node out of the order it was emitted";
        return;
    }
    expected_t e = s->expected[s->head_expected++];
    for (size_t i = 0; i < e.saves_before; i++)
        if (!sim_storage_has(&s->storage, s->emitted[i]) && !sim->violation)
            sim->violation = "nothing is sent before it is saved: an action left a node "
                             "before a save ahead of it was stored";
    if (s->head_expected == s->n_expected && all_emitted_durable(s))
        s->n_emitted = s->n_expected = s->head_expected = 0;
}

/* ---- pretend storage ---- */

static void deliver(slot_t *s, const gz_event_t *event);

static blob_t encode_records(const gz_action_t *save)
{
    size_t len = 0;
    for (size_t i = 0; i < save->u.save.n_records; i++)
        len += 8 + save->u.save.records[i].bytes.len;
    blob_t b = {malloc(len ? len : 1), len};
    if (!b.bytes) abort();
    uint8_t *p = b.bytes;
    for (size_t i = 0; i < save->u.save.n_records; i++) {
        const gz_record_t *r = &save->u.save.records[i];
        uint32_t head[2] = {r->type, (uint32_t)r->bytes.len};
        for (int k = 0; k < 8; k++) *p++ = (uint8_t)(head[k / 4] >> (8 * (k % 4)));
        if (r->bytes.len) memcpy(p, r->bytes.data, r->bytes.len);
        p += r->bytes.len;
    }
    return b;
}

/* Take a save batch and decide, from the schedule, when it becomes durable. */
static void storage_accept(slot_t *s, const gz_action_t *save)
{
    sim_t *sim = s->sim;
    struct sim_storage *st = &s->storage;
    int never = sim_rng_chance(&sim->rng, sim->cfg.save_never_pm);
    int late = sim_rng_chance(&sim->rng, sim->cfg.save_delay_pm);
    uint64_t extra = 1 + sim_rng_below(&sim->rng, sim->cfg.max_save_delay_steps ? sim->cfg.max_save_delay_steps : 1);
    uint64_t due = never ? NEVER : sim->step + (late ? extra : 0);
    if (st->n_pending && st->pending[st->n_pending - 1].due > due)
        due = st->pending[st->n_pending - 1].due;     /* batches complete in order */
    st->pending = grow(st->pending, &st->cap_pending, st->n_pending + 1, sizeof *st->pending);
    st->pending[st->n_pending++] = (batch_t){save->u.save.batch_id, encode_records(save), due};
    if (due == NEVER)
        trace(sim, "save node=%u batch=%llu records=%zu due=never", s->index,
              (unsigned long long)save->u.save.batch_id, save->u.save.n_records);
    else
        trace(sim, "save node=%u batch=%llu records=%zu due=%llu", s->index,
              (unsigned long long)save->u.save.batch_id, save->u.save.n_records, (unsigned long long)due);
}

/* Make every due pending batch durable, oldest first, and tell the node. */
static void settle_storage(slot_t *s)
{
    sim_t *sim = s->sim;
    struct sim_storage *st = &s->storage;
    while (st->n_pending && st->pending[0].due <= sim->step) {
        batch_t b = st->pending[0];
        memmove(st->pending, st->pending + 1, --st->n_pending * sizeof *st->pending);
        st->durable = grow(st->durable, &st->cap_durable, st->n_durable + 1, sizeof *st->durable);
        st->durable[st->n_durable++] = b;
        sim->stats.saves_durable++;
        trace(sim, "stored node=%u batch=%llu", s->index, (unsigned long long)b.id);
        if (!sim->cfg.ops.release) (void)gz_runner_confirm(&s->runner, b.id);
        gz_event_t ev = {.kind = GZ_EVENT_STORAGE_CONFIRMED};
        ev.u.storage.batch_id = b.id;
        deliver(s, &ev);
    }
}

/* ---- pretend network ---- */

static void network_send(sim_t *sim, uint64_t from, uint64_t to, const uint8_t *bytes, size_t len)
{
    int drop = sim_rng_chance(&sim->rng, sim->cfg.drop_pm);
    int twice = sim_rng_chance(&sim->rng, sim->cfg.duplicate_pm);
    sim->stats.messages_sent++;
    if (drop) {
        sim->stats.messages_dropped++;
        trace(sim, "drop %lld->%lld len=%zu", (long long)from, (long long)to, len);
        return;
    }
    if (twice) sim->stats.messages_duplicated++;
    for (int copy = 0; copy <= twice; copy++) {
        int late = sim_rng_chance(&sim->rng, sim->cfg.delay_pm);
        uint64_t extra = 1 + sim_rng_below(&sim->rng, sim->cfg.max_delay_steps ? sim->cfg.max_delay_steps : 1);
        message_t m = {from, to, blob_copy(bytes, len), sim->step + 1 + (late ? extra : 0), sim->next_seq++};
        if (late) sim->stats.messages_delayed++;
        sim->net = grow(sim->net, &sim->cap_net, sim->n_net + 1, sizeof *sim->net);
        sim->net[sim->n_net++] = m;
        trace(sim, "queue seq=%llu %lld->%lld len=%zu digest=%016llx due=%llu", (unsigned long long)m.seq,
              (long long)from, (long long)to, len, (unsigned long long)digest_bytes(bytes, len),
              (unsigned long long)m.due);
    }
}

/* Index in sim->net of the message to deliver now, or -1 if none is due. */
static long pick_message(sim_t *sim)
{
    long oldest = -1;
    size_t n_due = 0;
    for (size_t i = 0; i < sim->n_net; i++) {
        if (sim->net[i].due > sim->step) continue;
        n_due++;
        if (oldest < 0) oldest = (long)i;      /* the queue is kept in send order */
    }
    if (n_due == 0) return -1;
    int reorder = sim_rng_chance(&sim->rng, sim->cfg.reorder_pm);
    if (!reorder || n_due < 2) return oldest;
    uint64_t skip = 1 + sim_rng_below(&sim->rng, n_due - 1);   /* a due message other than the oldest */
    for (size_t i = (size_t)oldest + 1; i < sim->n_net; i++)
        if (sim->net[i].due <= sim->step && --skip == 0) {
            sim->stats.deliveries_reordered++;
            return (long)i;
        }
    return oldest;
}

static void deliver_one_message(sim_t *sim)
{
    long i = pick_message(sim);
    if (i < 0) return;
    message_t m = sim->net[i];
    memmove(sim->net + i, sim->net + i + 1, (--sim->n_net - (size_t)i) * sizeof *sim->net);
    trace(sim, "deliver seq=%llu %lld->%lld len=%zu", (unsigned long long)m.seq,
          (long long)m.from, (long long)m.to, m.blob.len);
    if (m.to == SIM_WORLD_PEER) {
        sim->stats.messages_delivered++;
        sim->stats.world_replies++;
    } else if (m.to < sim->cfg.n_nodes) {
        sim->stats.messages_delivered++;
        gz_event_t ev = {.kind = GZ_EVENT_MESSAGE_RECEIVED};
        ev.u.message.peer_id = m.from;
        ev.u.message.bytes = (gz_bytes_t){m.blob.bytes, m.blob.len};
        deliver(&sim->slots[m.to], &ev);
    }
    free(m.blob.bytes);
}

/* ---- pretend chain ---- */

static void pretend_txid(const blob_t *tx, uint8_t txid[32])
{
    for (uint64_t part = 0; part < 4; part++) {
        uint64_t h = fnv(fnv_u64(FNV_OFFSET, part), tx->bytes, tx->len);
        for (int k = 0; k < 8; k++) txid[8 * part + (uint64_t)k] = (uint8_t)(h >> (8 * k));
    }
}

/* The script a pretend transaction spends: see the convention in sim.h. */
static gz_bytes_t spent_script(const blob_t *tx)
{
    gz_bytes_t none = {NULL, 0};
    if (tx->len == 0 || tx->bytes[0] == 0 || (size_t)tx->bytes[0] + 1 > tx->len) return none;
    return (gz_bytes_t){tx->bytes + 1, tx->bytes[0]};
}

static void chain_broadcast(sim_t *sim, uint32_t origin, gz_bytes_t tx)
{
    for (size_t i = 0; i < sim->n_txs; i++)
        if (sim->txs[i].blob.len == tx.len && (tx.len == 0 || memcmp(sim->txs[i].blob.bytes, tx.data, tx.len) == 0)) {
            trace(sim, "broadcast node=%u already-known", origin);
            return;
        }
    sim->txs = grow(sim->txs, &sim->cap_txs, sim->n_txs + 1, sizeof *sim->txs);
    sim->txs[sim->n_txs++] = (chain_tx_t){blob_copy(tx.data, tx.len), origin, 0};
    trace(sim, "broadcast node=%u len=%zu digest=%016llx", origin, tx.len,
          (unsigned long long)digest_bytes(tx.data, tx.len));
}

static int watches(const slot_t *s, gz_bytes_t script)
{
    for (size_t i = 0; i < s->n_watches; i++)
        if (s->watches[i].len == script.len && memcmp(s->watches[i].bytes, script.data, script.len) == 0)
            return 1;
    return 0;
}

/* Tell watchers about the scripts spent by the transaction at index `t`. */
static void report_spend(sim_t *sim, size_t t)
{
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) {
        gz_bytes_t script = spent_script(&sim->txs[t].blob);
        if (script.len == 0 || !watches(&sim->slots[n], script)) continue;
        gz_event_t ev = {.kind = GZ_EVENT_CHAIN};
        ev.u.chain.kind = GZ_CHAIN_SCRIPT_SPENT;
        ev.u.chain.script = script;
        ev.u.chain.height = sim->txs[t].height;
        pretend_txid(&sim->txs[t].blob, ev.u.chain.txid);
        trace(sim, "chain spent node=%u height=%u", n, sim->height);
        deliver(&sim->slots[n], &ev);
    }
}

/* Tell the broadcaster of the transaction at index `t` how deep it now is. */
static void report_confirmations(sim_t *sim, size_t t)
{
    uint32_t confirmations = sim->height - sim->txs[t].height + 1;
    uint32_t origin = sim->txs[t].origin;
    if (confirmations > sim->cfg.confirm_depth || origin >= sim->cfg.n_nodes) return;
    gz_event_t ev = {.kind = GZ_EVENT_CHAIN};
    ev.u.chain.kind = GZ_CHAIN_TX_CONFIRMED;
    ev.u.chain.confirmations = confirmations;
    ev.u.chain.height = sim->txs[t].height;
    pretend_txid(&sim->txs[t].blob, ev.u.chain.txid);
    trace(sim, "chain confirmed node=%u confirmations=%u", origin, confirmations);
    deliver(&sim->slots[origin], &ev);
}

static void mine_block(sim_t *sim)
{
    size_t known = sim->n_txs;      /* transactions broadcast during this block wait for the next */
    sim->height++;
    sim->stats.blocks++;
    for (size_t t = 0; t < known; t++)
        if (sim->txs[t].height == 0) sim->txs[t].height = sim->height;
    trace(sim, "block height=%u", sim->height);
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) {
        gz_event_t ev = {.kind = GZ_EVENT_CHAIN};
        ev.u.chain.kind = GZ_CHAIN_NEW_TIP;
        ev.u.chain.height = sim->height;
        deliver(&sim->slots[n], &ev);
    }
    for (size_t t = 0; t < known; t++)
        if (sim->txs[t].height == sim->height) report_spend(sim, t);
    for (size_t t = 0; t < known; t++)
        report_confirmations(sim, t);
}

/* ---- timers and watches ---- */

static void cancel_timer(slot_t *s, uint64_t id)
{
    for (size_t i = 0; i < s->n_timers; i++)
        if (s->timers[i].id == id) {
            memmove(s->timers + i, s->timers + i + 1, (--s->n_timers - i) * sizeof *s->timers);
            return;
        }
}

static void set_timer(slot_t *s, uint64_t id, uint64_t delay)
{
    cancel_timer(s, id);
    s->timers = grow(s->timers, &s->cap_timers, s->n_timers + 1, sizeof *s->timers);
    s->timers[s->n_timers++] = (node_timer_t){id, s->sim->step + (delay ? delay : 1)};
}

static void fire_timers(slot_t *s)
{
    for (size_t i = 0; i < s->n_timers;) {
        if (s->timers[i].due > s->sim->step) { i++; continue; }
        gz_event_t ev = {.kind = GZ_EVENT_TIMER_FIRED};
        ev.u.timer.timer_id = s->timers[i].id;
        trace(s->sim, "timer node=%u id=%llu", s->index, (unsigned long long)ev.u.timer.timer_id);
        cancel_timer(s, ev.u.timer.timer_id);
        deliver(s, &ev);
        i = 0;      /* the node may have changed its timers */
    }
}

static void add_watch(slot_t *s, gz_bytes_t script)
{
    if (watches(s, script)) return;
    s->watches = grow(s->watches, &s->cap_watches, s->n_watches + 1, sizeof *s->watches);
    s->watches[s->n_watches++] = blob_copy(script.data, script.len);
}

/* ---- nodes ---- */

static void runner_execute(void *ctx, const gz_action_t *action)
{
    slot_t *s = ctx;
    sim_execute(s->sim, s->index, action);
}

void sim_execute(sim_t *sim, uint32_t index, const gz_action_t *a)
{
    slot_t *s = &sim->slots[index];
    switch (a->kind) {
    case GZ_ACTION_SAVE:
        storage_accept(s, a);
        break;
    case GZ_ACTION_SEND:
        note_left(s, a);
        network_send(sim, index, a->u.send.peer_id, a->u.send.bytes.data, a->u.send.bytes.len);
        break;
    case GZ_ACTION_BROADCAST:
        note_left(s, a);
        chain_broadcast(sim, index, a->u.broadcast.tx);
        break;
    case GZ_ACTION_NOTIFY:
        note_left(s, a);
        trace(sim, "notify node=%u code=%u len=%zu", index, a->u.notify.code, a->u.notify.bytes.len);
        break;
    case GZ_ACTION_WATCH:
        add_watch(s, a->u.watch.script);
        trace(sim, "watch node=%u len=%zu", index, a->u.watch.script.len);
        break;
    case GZ_ACTION_SET_TIMER:
        set_timer(s, a->u.set_timer.timer_id, a->u.set_timer.delay_ms);
        trace(sim, "set-timer node=%u id=%llu delay=%llu", index,
              (unsigned long long)a->u.set_timer.timer_id, (unsigned long long)a->u.set_timer.delay_ms);
        break;
    case GZ_ACTION_CANCEL_TIMER:
        cancel_timer(s, a->u.cancel_timer.timer_id);
        trace(sim, "cancel-timer node=%u id=%llu", index, (unsigned long long)a->u.cancel_timer.timer_id);
        break;
    }
}

/* Give one event to a node and carry out what it returns. */
static void deliver(slot_t *s, const gz_event_t *event)
{
    sim_t *sim = s->sim;
    gz_action_t slots[STEP_SLOTS];
    uint8_t bytes[STEP_BYTES];
    gz_action_list_t list;
    gz_action_list_init(&list, slots, STEP_SLOTS, bytes, STEP_BYTES);

    if (sim->cfg.ops.handle(s->node, event, &list) != GZ_OK) {
        sim->stats.handle_errors++;
        trace(sim, "handle-error node=%u event=%d", s->index, (int)event->kind);
        return;
    }
    if (list.count) {
        size_t emitted_before = s->n_emitted, expected_before = s->n_expected;
        note_emitted(s, &list);
        gz_status_t st = sim->cfg.ops.release
            ? sim->cfg.ops.release(sim->cfg.ops.ctx, sim, s->index, &list)
            : gz_runner_submit(&s->runner, &list);
        if (st != GZ_OK) {      /* refused whole: none of it was carried out */
            s->n_emitted = emitted_before;
            s->n_expected = expected_before;
            sim->stats.lists_refused++;
            trace(sim, "refused node=%u actions=%zu status=%d", s->index, list.count, (int)st);
        }
    }
    settle_storage(s);
}

static void random_fill(void *ctx, uint8_t *out, size_t len) { sim_rng_fill(&((slot_t *)ctx)->rng, out, len); }
static uint64_t clock_now(void *ctx) { return ((slot_t *)ctx)->sim->step; }

static void build_node(slot_t *s)
{
    (void)gz_runner_init(&s->runner, s->runner_slots, RUNNER_SLOTS, s->runner_bytes, RUNNER_BYTES,
                         runner_execute, s);
    s->node = s->sim->cfg.ops.create(s->sim->cfg.ops.ctx, s->index, &s->ports, &s->storage);
    if (!s->node) abort();
}

static void free_blobs(blob_t *blobs, size_t n)
{
    for (size_t i = 0; i < n; i++) free(blobs[i].bytes);
}

/* Destroy everything of a node except its durable storage, then rebuild it. */
static void crash(slot_t *s)
{
    sim_t *sim = s->sim;
    sim->stats.crashes++;
    sim->stats.saves_lost += s->storage.n_pending;
    trace(sim, "crash node=%u lost-saves=%zu held-actions=%zu", s->index, s->storage.n_pending,
          sim->cfg.ops.release ? (size_t)0 : gz_runner_held(&s->runner));
    sim->cfg.ops.destroy(sim->cfg.ops.ctx, s->node);
    for (size_t i = 0; i < s->storage.n_pending; i++) free(s->storage.pending[i].blob.bytes);
    free_blobs(s->watches, s->n_watches);
    s->storage.n_pending = s->n_timers = s->n_watches = 0;
    s->n_emitted = s->n_expected = s->head_expected = 0;
    build_node(s);
}

/* The default node: a gz_node_t that continues batch numbering from storage. */
static void *default_create(void *ops_ctx, uint32_t index, const gz_ports_t *ports,
                            const sim_storage_t *storage)
{
    (void)ops_ctx; (void)index;
    uint64_t first = 1;
    for (size_t i = 0; i < sim_storage_count(storage); i++)
        if (sim_storage_batch_id(storage, i) >= first) first = sim_storage_batch_id(storage, i) + 1;
    gz_node_t *node = malloc(sizeof *node);
    if (!node || gz_node_init(node, ports, first) != GZ_OK) abort();
    return node;
}

static void default_destroy(void *ops_ctx, void *node) { (void)ops_ctx; free(node); }

static gz_status_t default_handle(void *node, const gz_event_t *event, gz_action_list_t *out)
{
    return gz_node_handle(node, event, out);
}

/* ---- invariants ---- */

static void fail(sim_t *sim, const char *reason)
{
    if (sim->failed) return;
    sim->failed = 1;
    sim->failure_step = sim->step;
    sim->failure_reason = reason;
    trace(sim, "FAILED %s", reason);
}

static void check_invariants(sim_t *sim)
{
    const char *why = "an invariant failed";
    if (sim->violation) fail(sim, sim->violation);
    if (sim->twin) {
        if (sim->twin->violation) fail(sim, sim->twin->violation);
        if (sim->twin->trace_len != sim->trace_len || sim->twin->trace_hash != sim->trace_hash)
            fail(sim, "same seed, same run: two runs of this configuration differ");
    }
    for (size_t i = 0; i < sim->n_invariants && !sim->failed; i++)
        if (!sim->invariants[i].check(sim, sim->invariants[i].ctx, &why)) fail(sim, why);
}

/* ---- the scheduler ---- */

static void maybe_crash(sim_t *sim)
{
    int crash_now = sim_rng_chance(&sim->rng, sim->cfg.crash_pm);
    uint32_t who = (uint32_t)sim_rng_below(&sim->rng, sim->cfg.n_nodes);
    if (crash_now) crash(&sim->slots[who]);
}

static void maybe_ping(sim_t *sim)
{
    uint8_t ping[GZ_PING_PREFIX_LEN + 8] = {'G', 'Z', 'P', 'I'};
    int ping_now = sim_rng_chance(&sim->rng, sim->cfg.ping_pm);
    uint64_t to = sim_rng_below(&sim->rng, sim->cfg.n_nodes);
    uint64_t from = sim_rng_below(&sim->rng, (uint64_t)sim->cfg.n_nodes + 1);
    sim_rng_fill(&sim->rng, ping + GZ_PING_PREFIX_LEN, 8);
    if (!ping_now) return;
    if (from == sim->cfg.n_nodes || from == to) from = SIM_WORLD_PEER;
    network_send(sim, from, to, ping, sizeof ping);
}

static void step_once(sim_t *sim)
{
    sim->step++;
    maybe_crash(sim);
    maybe_ping(sim);
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) settle_storage(&sim->slots[n]);
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) fire_timers(&sim->slots[n]);
    deliver_one_message(sim);
    if (sim_rng_chance(&sim->rng, sim->cfg.block_pm)) mine_block(sim);
}

/* ---- public ---- */

sim_t *sim_create(const sim_config_t *config)
{
    if (!config || config->n_nodes == 0) return NULL;
    sim_t *sim = calloc(1, sizeof *sim);
    if (!sim) abort();
    sim->cfg = *config;
    if (!sim->cfg.ops.create) {
        sim->cfg.ops.create = default_create;
        sim->cfg.ops.destroy = default_destroy;
        sim->cfg.ops.handle = default_handle;
    }
    sim->trace_hash = FNV_OFFSET;
    sim_rng_init(&sim->rng, config->seed, 0);
    sim->slots = calloc(config->n_nodes, sizeof *sim->slots);
    if (!sim->slots) abort();
    for (uint32_t n = 0; n < config->n_nodes; n++) {
        slot_t *s = &sim->slots[n];
        s->sim = sim;
        s->index = n;
        s->ports.random = (gz_random_port_t){random_fill, s};
        s->ports.clock = (gz_clock_port_t){clock_now, s};
        sim_rng_init(&s->rng, config->seed, (uint64_t)n + 1);
        build_node(s);
    }
    if (config->check_same_seed) {
        sim_config_t same = *config;
        same.check_same_seed = 0;
        sim->twin = sim_create(&same);
    }
    return sim;
}

void sim_destroy(sim_t *sim)
{
    if (!sim) return;
    if (sim->twin) sim_destroy(sim->twin);
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) {
        slot_t *s = &sim->slots[n];
        sim->cfg.ops.destroy(sim->cfg.ops.ctx, s->node);
        for (size_t i = 0; i < s->storage.n_pending; i++) free(s->storage.pending[i].blob.bytes);
        for (size_t i = 0; i < s->storage.n_durable; i++) free(s->storage.durable[i].blob.bytes);
        free_blobs(s->watches, s->n_watches);
        free(s->storage.pending); free(s->storage.durable);
        free(s->watches); free(s->timers); free(s->emitted); free(s->expected);
    }
    for (size_t i = 0; i < sim->n_net; i++) free(sim->net[i].blob.bytes);
    for (size_t i = 0; i < sim->n_txs; i++) free(sim->txs[i].blob.bytes);
    free(sim->net); free(sim->txs); free(sim->slots); free(sim->trace);
    free(sim);
}

int sim_add_invariant(sim_t *sim, sim_invariant_fn check, void *ctx)
{
    if (!check || sim->n_invariants == MAX_INVARIANTS) return 0;
    sim->invariants[sim->n_invariants].check = check;
    sim->invariants[sim->n_invariants++].ctx = ctx;
    return 1;
}

int sim_step(sim_t *sim)
{
    if (sim->failed) return 0;
    step_once(sim);
    if (sim->twin) step_once(sim->twin);
    check_invariants(sim);
    return !sim->failed;
}

uint64_t sim_run(sim_t *sim, uint64_t steps)
{
    uint64_t done = 0;
    while (done < steps && sim_step(sim)) done++;
    return done;
}

uint64_t sim_step_count(const sim_t *sim) { return sim->step; }
int sim_failed(const sim_t *sim) { return sim->failed; }
uint64_t sim_failure_step(const sim_t *sim) { return sim->failure_step; }
const char *sim_failure_reason(const sim_t *sim) { return sim->failed ? sim->failure_reason : ""; }
uint64_t sim_trace_hash(const sim_t *sim) { return sim->trace_hash; }
const sim_stats_t *sim_stats(const sim_t *sim) { return &sim->stats; }
uint32_t sim_chain_height(const sim_t *sim) { return sim->height; }

const char *sim_trace(const sim_t *sim, size_t *len)
{
    if (len) *len = sim->trace_len;
    return sim->trace ? sim->trace : "";
}

void sim_crash_node(sim_t *sim, uint32_t index)
{
    if (sim->failed || index >= sim->cfg.n_nodes) return;
    crash(&sim->slots[index]);
    if (sim->twin) crash(&sim->twin->slots[index]);
    check_invariants(sim);
}

void sim_send_message(sim_t *sim, uint64_t from, uint64_t to, const uint8_t *bytes, size_t len)
{
    if (sim->failed) return;
    network_send(sim, from, to, bytes, len);
    if (sim->twin) network_send(sim->twin, from, to, bytes, len);
    check_invariants(sim);
}

static void user_command(sim_t *sim, uint32_t index, const uint8_t *bytes, size_t len)
{
    gz_event_t ev = {.kind = GZ_EVENT_USER_COMMAND};
    ev.u.user.bytes = (gz_bytes_t){bytes, len};
    trace(sim, "user node=%u len=%zu", index, len);
    deliver(&sim->slots[index], &ev);
}

void sim_user_command(sim_t *sim, uint32_t index, const uint8_t *bytes, size_t len)
{
    if (sim->failed || index >= sim->cfg.n_nodes) return;
    user_command(sim, index, bytes, len);
    if (sim->twin) user_command(sim->twin, index, bytes, len);
    check_invariants(sim);
}

void sim_mine_block(sim_t *sim)
{
    if (sim->failed) return;
    mine_block(sim);
    if (sim->twin) mine_block(sim->twin);
    check_invariants(sim);
}

const sim_storage_t *sim_node_storage(const sim_t *sim, uint32_t index) { return &sim->slots[index].storage; }
size_t sim_storage_count(const sim_storage_t *storage) { return storage->n_durable; }
uint64_t sim_storage_batch_id(const sim_storage_t *storage, size_t i) { return storage->durable[i].id; }
size_t sim_storage_pending(const sim_storage_t *storage) { return storage->n_pending; }

const uint8_t *sim_storage_batch_bytes(const sim_storage_t *storage, size_t i, size_t *len)
{
    if (len) *len = storage->durable[i].blob.len;
    return storage->durable[i].blob.bytes;
}

int sim_storage_has(const sim_storage_t *storage, uint64_t batch_id)
{
    for (size_t i = storage->n_durable; i-- > 0;)
        if (storage->durable[i].id == batch_id) return 1;
    return 0;
}
