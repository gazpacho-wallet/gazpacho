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
#define MAX_START_STEPS 100000
#define READER_RECORDS 16      /* records of one batch the default node's reader presents */
#define NEVER          UINT64_MAX
#define NOT_ARMED      UINT64_MAX
#define FNV_OFFSET     0xcbf29ce484222325ull
#define FNV_PRIME      0x100000001b3ull

typedef struct { uint8_t *bytes; size_t len; } blob_t;
typedef struct { uint64_t from, to; blob_t blob; uint64_t due, seq; } message_t;
typedef struct { uint64_t id, due; } node_timer_t;
typedef struct { blob_t blob; uint32_t origin; uint32_t height; int never; uint8_t txid[32]; } chain_tx_t;   /* height 0: in the mempool */
typedef struct { uint8_t txid[32]; uint32_t depth; int reported; } tx_watch_t;          /* reported: told confirmed, still in the chain */
typedef struct { gz_outpoint_t outpoint; uint32_t depth; int seen, in_chain; } op_watch_t;

/* One batch in a node's storage. */
typedef struct {
    gz_batch_id_t id;
    blob_t blob;                /* the records as stored */
    uint64_t digest;            /* of the records as the node handed them over */
    uint64_t node_incarnation;  /* which build of the node saved it */
    uint64_t durable_at;        /* step at which it becomes durable, or NEVER */
    uint64_t confirm_at;        /* step at which its confirmation is delivered */
    int fails;                  /* storage fails when this batch's turn comes */
} batch_t;

struct sim_storage {
    batch_t *durable; size_t n_durable, cap_durable;
    size_t next_confirm;        /* durable[0..next_confirm) have had their confirmation delivered */
    batch_t *pending; size_t n_pending, cap_pending;
    uint64_t reader_incarnation; /* the incarnation of the node being built from this storage */
    int reader_restored;        /* the restore marker that node is given (ports.h) */
};

/* The harness's own record of a batch that became durable. */
typedef struct { gz_batch_id_t id; uint64_t digest; } shadow_t;

/* An outward action the harness saw a node emit and has not yet seen leave. */
typedef struct { uint64_t digest; size_t saves_before; } expected_t;

/* An event waiting to be handled. */
typedef struct { uint32_t node; uint64_t node_incarnation; gz_event_t ev; blob_t blob; } queued_t;

/* One simulated node and everything around it. */
typedef struct {
    sim_t *sim;
    uint32_t index;
    void *node;
    gz_ports_t ports;
    sim_rng_t rng;
    uint64_t incarnation;       /* how many times the node has been built */
    uint64_t repeat_stream;     /* after a restore: the incarnation whose random stream to repeat, or 0 */
    gz_runner_t runner;
    gz_runner_slot_t *runner_slots;   /* sim->runner_slots of them */
    uint8_t *runner_bytes;            /* sim->runner_bytes */
    struct sim_storage storage;
    node_timer_t *timers; size_t n_timers, cap_timers;
    blob_t *watches; size_t n_watches, cap_watches;
    tx_watch_t *tx_watches; size_t n_tx_watches, cap_tx_watches;
    op_watch_t *op_watches; size_t n_op_watches, cap_op_watches;
    sim_draw_t *draws; size_t n_draws, cap_draws;
    /* The difference signature of every 8-byte window of every secret-tagged
     * draw, forwards and backwards: an open-addressing table (0 marks a free
     * place), for the "secrets never leave" check. */
    uint64_t *secret_keys; size_t n_secret_keys, cap_secret_keys;

    int restore_pending;        /* restored, and no restore batch is durable yet */
    uint64_t restore_first_incarnation;   /* the first incarnation started after that restore */
    int started_restored;       /* this incarnation was started with the restore marker */
    int emitted_any;            /* this incarnation has emitted an action */

    int needs_rebuild;          /* crashed, refused or storage failed: rebuild before going on */
    int dying;                  /* crashed inside a release: nothing more is carried out */
    int died_this_step;
    uint64_t crash_countdown;   /* executor calls left before an armed crash, or NOT_ARMED */
    int storage_failed;         /* this incarnation's storage has failed: nothing more may be carried out */

    int starting;               /* the node's start has not finished */
    size_t start_steps;         /* start steps taken by this incarnation */
    queued_t *deferred; size_t n_deferred, cap_deferred;   /* events held back until the start finishes */
    batch_t *orphans; size_t n_orphans, cap_orphans;       /* an earlier program's pending batches */

    /* What the harness observed this node emit since it was last built, for
     * the save-before-send check. Kept apart from the runner on purpose, and
     * counted by position: the k-th save emitted is the k-th to reach storage
     * and the k-th to become durable. */
    uint64_t *emitted_saves; size_t n_emitted_saves, cap_emitted_saves;   /* digests, in order */
    size_t n_saves_stored;      /* how many of them reached storage */
    size_t n_saves_durable;     /* how many of them storage has made durable */
    expected_t *expected; size_t n_expected, head_expected, cap_expected;

    shadow_t *shadow; size_t n_shadow, cap_shadow;
} slot_t;

struct sim {
    sim_config_t cfg;
    void *ops_ctx;
    sim_rng_t rng;
    uint64_t step;
    int64_t clock_offset;
    slot_t *slots;
    uint8_t *link_down;             /* (n_nodes + 1) squared; the last index is the world */
    queued_t *queue; size_t q_head, q_len, cap_queue;
    message_t *net; size_t n_net, cap_net;
    uint64_t next_seq;
    chain_tx_t *txs; size_t n_txs, cap_txs;
    uint32_t height;
    char *trace; size_t trace_len, trace_cap;
    uint64_t trace_hash;
    sim_stats_t stats;
    struct { sim_invariant_fn check; void *ctx; } invariants[MAX_INVARIANTS];
    size_t n_invariants;
    /* Buffer sizes in use (the configuration's, or the defaults), and the
     * buffers for a start step and for an event step. */
    size_t step_slots, step_bytes, runner_slots, runner_bytes;
    gz_action_t *start_slot_buf, *step_slot_buf;
    uint8_t *start_byte_buf, *step_byte_buf;
    const char *violation;          /* set when a built-in invariant is seen broken */
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

static int same_bytes(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len)
{
    return a_len == b_len && (a_len == 0 || memcmp(a, b, a_len) == 0);
}

/* FNV-1a, fed byte by byte in a fixed order: the same on every machine. */
static uint64_t fnv(uint64_t h, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) h = (h ^ data[i]) * FNV_PRIME;
    return h;
}

static uint64_t fnv_number(uint64_t h, uint64_t v, int n_bytes)
{
    for (int i = 0; i < n_bytes; i++) h = (h ^ (uint8_t)(v >> (8 * i))) * FNV_PRIME;
    return h;
}

static uint64_t digest_bytes(const uint8_t *bytes, size_t len) { return fnv(FNV_OFFSET, bytes, len); }

static void violate(sim_t *sim, const char *what)
{
    if (!sim->violation) sim->violation = what;
}

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
    sim->trace_hash = fnv(sim->trace_hash, (const uint8_t *)line, (size_t)n);
}

/* ---- the save-before-send observer ---- */

/* Digest of a save's records, computed from the action itself. It equals the
 * digest of the bytes storage should hold for it (see encode_records). */
static uint64_t records_digest(const gz_action_t *save)
{
    uint64_t h = FNV_OFFSET;
    for (size_t i = 0; i < save->u.save.n_records; i++) {
        const gz_record_t *r = &save->u.save.records[i];
        h = fnv_number(h, r->type, 4);
        h = fnv_number(h, r->bytes.len, 4);
        h = fnv(h, r->bytes.data, r->bytes.len);
    }
    return h;
}

static uint64_t outward_digest(const gz_action_t *a)
{
    uint64_t h = fnv_number(FNV_OFFSET, (uint64_t)a->kind, 4);
    if (a->kind == GZ_ACTION_SEND) {
        h = fnv_number(h, a->u.send.peer_id, 8);
        h = fnv(h, a->u.send.bytes.data, a->u.send.bytes.len);
    } else if (a->kind == GZ_ACTION_BROADCAST) {
        h = fnv(h, a->u.broadcast.tx.data, a->u.broadcast.tx.len);
    } else {
        h = fnv_number(h, a->u.notify.code, 4);
        h = fnv(h, a->u.notify.bytes.data, a->u.notify.bytes.len);
    }
    return h;
}

/* Record, in order, the saves and outward actions a node step returned. */
static void note_emitted(slot_t *s, const gz_action_list_t *list)
{
    for (size_t i = 0; i < list->count; i++) {
        const gz_action_t *a = &list->slots[i];
        if (s->started_restored && !s->emitted_any && a->kind != GZ_ACTION_SAVE)
            violate(s->sim, "a node started with the restore marker did something before saving its restore batch");
        s->emitted_any = 1;
        if (a->kind == GZ_ACTION_SAVE) {
            s->emitted_saves = grow(s->emitted_saves, &s->cap_emitted_saves, s->n_emitted_saves + 1,
                                    sizeof *s->emitted_saves);
            s->emitted_saves[s->n_emitted_saves++] = records_digest(a);
        } else if (gz_action_is_outward(a)) {
            s->expected = grow(s->expected, &s->cap_expected, s->n_expected + 1, sizeof *s->expected);
            s->expected[s->n_expected++] = (expected_t){outward_digest(a), s->n_emitted_saves};
        }
    }
}

/* A save is reaching storage. It must be the next one the node emitted. */
static void note_stored(slot_t *s, const gz_action_t *save)
{
    size_t k = s->n_saves_stored++;
    if (k >= s->n_emitted_saves || s->emitted_saves[k] != records_digest(save))
        violate(s->sim, "a save reached storage that was not the next one the node emitted");
}

/* An outward action is leaving a node. It must be the next one the node
 * emitted, and every save the node emitted before it must be durable. */
static void note_left(slot_t *s, const gz_action_t *a)
{
    if (s->head_expected == s->n_expected ||
        s->expected[s->head_expected].digest != outward_digest(a)) {
        violate(s->sim, "an action left a node out of the order it was emitted");
        return;
    }
    if (s->expected[s->head_expected++].saves_before > s->n_saves_durable)
        violate(s->sim, "nothing is sent before it is saved: an action left a node "
                        "before a save ahead of it was stored");
    if (s->head_expected == s->n_expected && s->n_saves_durable == s->n_emitted_saves)
        s->n_emitted_saves = s->n_saves_stored = s->n_saves_durable = s->n_expected = s->head_expected = 0;
}

/* ---- the event queue ---- */

/* The byte string an event carries, if any. */
static gz_bytes_t *event_bytes(gz_event_t *ev)
{
    switch (ev->kind) {
    case GZ_EVENT_MESSAGE_RECEIVED: return &ev->u.message.bytes;
    case GZ_EVENT_USER_COMMAND:     return &ev->u.user.bytes;
    case GZ_EVENT_CHAIN:            return &ev->u.chain.script;
    default:                        return NULL;
    }
}

/* Queue a copy of an event for a node, as it is built now. */
static void post_as(slot_t *s, const gz_event_t *ev, uint64_t node_incarnation)
{
    sim_t *sim = s->sim;
    queued_t q = {s->index, node_incarnation, *ev, {NULL, 0}};
    gz_bytes_t *bytes = event_bytes(&q.ev);
    if (bytes) {
        q.blob = blob_copy(bytes->data, bytes->len);
        bytes->data = q.blob.bytes;
    }
    sim->queue = grow(sim->queue, &sim->cap_queue, sim->q_len + 1, sizeof *sim->queue);
    sim->queue[sim->q_len++] = q;
}

static void post(slot_t *s, const gz_event_t *ev) { post_as(s, ev, s->incarnation); }

/* ---- pretend storage ---- */

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

static void fail_storage(slot_t *s);

/* Take a save batch and decide, from the schedule, what becomes of it. */
static void storage_accept(slot_t *s, const gz_action_t *save)
{
    sim_t *sim = s->sim;
    struct sim_storage *st = &s->storage;
    const sim_config_t *c = &sim->cfg;
    int never = sim_rng_chance(&sim->rng, c->save_never_pm);
    int late = sim_rng_chance(&sim->rng, c->save_delay_pm);
    uint64_t extra = 1 + sim_rng_below(&sim->rng, c->max_save_delay_steps ? c->max_save_delay_steps : 1);
    int fails = sim_rng_chance(&sim->rng, c->save_fail_pm);
    int confirm_late = sim_rng_chance(&sim->rng, c->confirm_delay_pm);
    uint64_t confirm_extra = 1 + sim_rng_below(&sim->rng, c->max_confirm_delay_steps ? c->max_confirm_delay_steps : 1);

    int fails_inline = sim_rng_chance(&sim->rng, c->save_fail_inline_pm);
    if (fails_inline) {     /* storage that writes as it is called finds out at once, inside the executor */
        sim->stats.inline_storage_failures++;
        trace(sim, "storage-failed-inline node=%u", s->index);
        sim->stats.saves_lost++;
        fail_storage(s);
        return;
    }
    batch_t b = {save->u.save.batch, encode_records(save), records_digest(save), s->incarnation, 0, NEVER, fails};
    b.durable_at = never ? NEVER : sim->step + (late ? extra : 0);
    if (st->n_pending && st->pending[st->n_pending - 1].durable_at > b.durable_at)
        b.durable_at = st->pending[st->n_pending - 1].durable_at;     /* a journal: in order */
    if (b.durable_at != NEVER) b.confirm_at = b.durable_at + (confirm_late ? confirm_extra : 0);
    st->pending = grow(st->pending, &st->cap_pending, st->n_pending + 1, sizeof *st->pending);
    st->pending[st->n_pending++] = b;
    trace(sim, "save node=%u batch=%llu.%llu records=%zu digest=%016llx durable-at=%lld", s->index,
          (unsigned long long)b.id.incarnation, (unsigned long long)b.id.sequence, save->u.save.n_records,
          (unsigned long long)b.digest, (long long)b.durable_at);
}

/* Storage fails: everything pending is discarded, the program is told, and
 * the node has to be restarted. */
static void fail_storage(slot_t *s)
{
    sim_t *sim = s->sim;
    sim->stats.storage_failures++;
    sim->stats.saves_lost += s->storage.n_pending;
    trace(sim, "storage-failed node=%u lost-saves=%zu", s->index, s->storage.n_pending);
    for (size_t i = 0; i < s->storage.n_pending; i++) free(s->storage.pending[i].blob.bytes);
    s->storage.n_pending = 0;
    if (!sim->cfg.ops.release) (void)gz_runner_storage_failed(&s->runner);
    s->storage_failed = 1;
    s->needs_rebuild = 1;
}

/* A batch has become durable: if it is the restore batch of a start made
 * with the restore marker (sequence 1 of such an incarnation), the restore is
 * answered and later starts are given no marker. */
static void note_durable(slot_t *s, gz_batch_id_t id)
{
    if (!s->restore_pending || id.sequence != 1 || id.incarnation < s->restore_first_incarnation) return;
    s->restore_pending = 0;
    s->sim->stats.restores_answered++;
    trace(s->sim, "restore-answered node=%u batch=%llu.1", s->index, (unsigned long long)id.incarnation);
}

/* Make every due pending batch durable, oldest first, and queue every due
 * confirmation. */
static void settle_storage(slot_t *s)
{
    sim_t *sim = s->sim;
    struct sim_storage *st = &s->storage;
    while (st->n_pending && st->pending[0].durable_at <= sim->step) {
        if (st->pending[0].fails) { fail_storage(s); break; }
        batch_t b = st->pending[0];
        memmove(st->pending, st->pending + 1, --st->n_pending * sizeof *st->pending);
        st->durable = grow(st->durable, &st->cap_durable, st->n_durable + 1, sizeof *st->durable);
        st->durable[st->n_durable++] = b;
        s->shadow = grow(s->shadow, &s->cap_shadow, s->n_shadow + 1, sizeof *s->shadow);
        s->shadow[s->n_shadow++] = (shadow_t){b.id, b.digest};
        s->n_saves_durable++;
        sim->stats.saves_durable++;
        trace(sim, "stored node=%u batch=%llu.%llu", s->index,
              (unsigned long long)b.id.incarnation, (unsigned long long)b.id.sequence);
        note_durable(s, b.id);
    }
    while (st->next_confirm < st->n_durable && st->durable[st->next_confirm].confirm_at <= sim->step) {
        const batch_t *b = &st->durable[st->next_confirm++];
        gz_event_t ev = {.kind = GZ_EVENT_STORAGE_CONFIRMED};
        ev.u.storage.batch = b->id;
        post_as(s, &ev, b->node_incarnation);
    }
}

/* What the harness recorded as durable must be exactly what storage holds. */
static void check_storage(slot_t *s)
{
    const struct sim_storage *st = &s->storage;
    if (st->n_durable != s->n_shadow) {
        violate(s->sim, "storage lost or gained a durable batch");
        return;
    }
    for (size_t i = 0; i < st->n_durable; i++) {
        const batch_t *b = &st->durable[i];
        if (b->id.incarnation != s->shadow[i].id.incarnation || b->id.sequence != s->shadow[i].id.sequence ||
            digest_bytes(b->blob.bytes, b->blob.len) != s->shadow[i].digest) {
            violate(s->sim, "storage altered a durable batch");
            return;
        }
    }
}

static void discard_orphans(slot_t *s);

/* A restore from an older backup: storage goes back to its oldest `keep`
 * batches, nothing pending and no confirmation from before can arrive, and
 * the node restarts. */
static void restore(slot_t *s, size_t keep)
{
    sim_t *sim = s->sim;
    struct sim_storage *st = &s->storage;
    if (keep > st->n_durable) keep = st->n_durable;
    sim->stats.restores++;
    trace(sim, "restore node=%u keeps=%zu of=%zu", s->index, keep, st->n_durable);
    if (sim->cfg.restore_repeats_random) {
        s->repeat_stream = keep ? st->durable[keep - 1].node_incarnation : 1;
        sim->stats.restores_repeating++;
    }
    for (size_t i = keep; i < st->n_durable; i++) free(st->durable[i].blob.bytes);
    st->n_durable = s->n_shadow = st->next_confirm = keep;
    /* Storage is opened afresh: nothing the program had handed over can still
     * complete into the restored copy. */
    sim->stats.saves_lost += st->n_pending;
    for (size_t i = 0; i < st->n_pending; i++) free(st->pending[i].blob.bytes);
    st->n_pending = 0;
    s->restore_pending = 1;                 /* the program knows it restored; the node must be told */
    s->restore_first_incarnation = s->incarnation + 1;
    s->needs_rebuild = 1;
}

/* ---- pretend network ---- */

/* Index of a peer in the link table: nodes first, then the world. -1 if there
 * is no such peer. */
static long peer_index(const sim_t *sim, uint64_t peer)
{
    if (peer == SIM_WORLD_PEER) return (long)sim->cfg.n_nodes;
    return peer < sim->cfg.n_nodes ? (long)peer : -1;
}

static uint8_t *link_cell(const sim_t *sim, long a, long b)
{
    return &sim->link_down[(size_t)a * (sim->cfg.n_nodes + 1) + (size_t)b];
}

static int link_is_up(const sim_t *sim, uint64_t a, uint64_t b)
{
    long ia = peer_index(sim, a), ib = peer_index(sim, b);
    return ia < 0 || ib < 0 || !*link_cell(sim, ia, ib);
}

/* Tell a node that its connection to `peer` is up or down. */
static void tell_peer(slot_t *s, uint64_t peer, int up)
{
    gz_event_t ev = {.kind = up ? GZ_EVENT_PEER_CONNECTED : GZ_EVENT_PEER_DISCONNECTED};
    ev.u.peer.peer_id = peer;
    post(s, &ev);
}

static void set_link(sim_t *sim, uint64_t a, uint64_t b, int up)
{
    long ia = peer_index(sim, a), ib = peer_index(sim, b);
    if (ia < 0 || ib < 0 || ia == ib || !*link_cell(sim, ia, ib) == !!up) return;
    *link_cell(sim, ia, ib) = *link_cell(sim, ib, ia) = (uint8_t)!up;
    sim->stats.link_changes++;
    trace(sim, "link %lld-%lld %s", (long long)a, (long long)b, up ? "up" : "down");
    if (a != SIM_WORLD_PEER) tell_peer(&sim->slots[a], b, up);
    if (b != SIM_WORLD_PEER) tell_peer(&sim->slots[b], a, up);
}

static void network_send(sim_t *sim, uint64_t from, uint64_t to, const uint8_t *bytes, size_t len)
{
    int drop = sim_rng_chance(&sim->rng, sim->cfg.drop_pm);
    int twice = sim_rng_chance(&sim->rng, sim->cfg.duplicate_pm);
    uint64_t digest = digest_bytes(bytes, len);
    sim->stats.messages_sent++;
    if (drop) {
        sim->stats.messages_dropped++;
        trace(sim, "drop %lld->%lld len=%zu digest=%016llx", (long long)from, (long long)to, len,
              (unsigned long long)digest);
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
              (long long)from, (long long)to, len, (unsigned long long)digest, (unsigned long long)m.due);
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
    if (!link_is_up(sim, m.from, m.to)) {
        sim->stats.messages_lost_to_links++;
        trace(sim, "lost-to-link seq=%llu %lld->%lld", (unsigned long long)m.seq, (long long)m.from, (long long)m.to);
    } else {
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
            post(&sim->slots[m.to], &ev);
        }
    }
    free(m.blob.bytes);
}

/* ---- pretend chain ---- */

static uint64_t first8(const uint8_t *b);

/* 32 bytes from four digests of the transaction, each written low byte first. */
static void txid_of(const uint8_t *tx, size_t len, uint8_t txid[32])
{
    for (uint64_t part = 0; part < 4; part++) {
        uint64_t h = fnv(fnv_number(FNV_OFFSET, part, 8), tx, len);
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

#define TX_INPUTS_MARK 0xF0u
#define TX_INPUT_LEN   36

/* The outpoints a pretend transaction spends: their number, and through
 * `*first` where the first one starts. */
static size_t tx_inputs(const uint8_t *tx, size_t len, const uint8_t **first)
{
    if (len == 0) return 0;
    size_t at = 1 + (size_t)tx[0];
    if (at + 2 > len || tx[at] != TX_INPUTS_MARK) return 0;
    size_t n = tx[at + 1];
    if (n * TX_INPUT_LEN > len - at - 2) return 0;
    *first = tx + at + 2;
    return n;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int spends(const uint8_t *tx, size_t len, const gz_outpoint_t *op)
{
    const uint8_t *in = NULL;
    size_t n = tx_inputs(tx, len, &in);
    for (size_t i = 0; i < n; i++, in += TX_INPUT_LEN)
        if (memcmp(in, op->txid, 32) == 0 && le32(in + 32) == op->vout) return 1;
    return 0;
}

static long find_tx(const sim_t *sim, const uint8_t txid[32])
{
    for (size_t t = 0; t < sim->n_txs; t++)
        if (memcmp(sim->txs[t].txid, txid, 32) == 0) return (long)t;
    return -1;
}

/* The known transaction spending `op`, or -1. At most one: conflicts are dropped. */
static long find_spender(const sim_t *sim, const gz_outpoint_t *op)
{
    for (size_t t = 0; t < sim->n_txs; t++)
        if (spends(sim->txs[t].blob.bytes, sim->txs[t].blob.len, op)) return (long)t;
    return -1;
}

static uint32_t confirmations_of(const sim_t *sim, size_t t)
{
    return sim->txs[t].height ? sim->height - sim->txs[t].height + 1 : 0;
}

/* An event about the transaction at index `t`, for node `n`. */
static void post_chain(sim_t *sim, uint32_t n, gz_chain_kind_t kind, size_t t, const gz_outpoint_t *op,
                       uint32_t confirmations)
{
    static const char *const names[] = {"?", "spent", "confirmed", "tip", "unconfirmed", "outpoint-spent"};
    gz_event_t ev = {.kind = GZ_EVENT_CHAIN};
    ev.u.chain.kind = kind;
    if (kind == GZ_CHAIN_SCRIPT_SPENT) ev.u.chain.script = spent_script(&sim->txs[t].blob);
    if (op) ev.u.chain.outpoint = *op;
    ev.u.chain.confirmations = confirmations;
    ev.u.chain.height = sim->txs[t].height;
    memcpy(ev.u.chain.txid, sim->txs[t].txid, 32);
    sim->stats.chain_reports++;
    trace(sim, "chain %s node=%u confirmations=%u tx=%016llx", names[kind], n, confirmations,
          (unsigned long long)first8(sim->txs[t].txid));
    post(&sim->slots[n], &ev);
}

static int watches(const slot_t *s, gz_bytes_t script)
{
    for (size_t i = 0; i < s->n_watches; i++)
        if (same_bytes(s->watches[i].bytes, s->watches[i].len, script.data, script.len)) return 1;
    return 0;
}

static tx_watch_t *add_tx_watch(slot_t *s, const uint8_t txid[32], uint32_t depth)
{
    for (size_t i = 0; i < s->n_tx_watches; i++)
        if (memcmp(s->tx_watches[i].txid, txid, 32) == 0) {
            s->tx_watches[i].depth = depth;
            return &s->tx_watches[i];
        }
    s->tx_watches = grow(s->tx_watches, &s->cap_tx_watches, s->n_tx_watches + 1, sizeof *s->tx_watches);
    tx_watch_t *w = &s->tx_watches[s->n_tx_watches++];
    memcpy(w->txid, txid, 32);
    w->depth = depth;
    w->reported = 0;
    return w;
}

static op_watch_t *add_op_watch(slot_t *s, const gz_outpoint_t *op, uint32_t depth)
{
    for (size_t i = 0; i < s->n_op_watches; i++)
        if (memcmp(s->op_watches[i].outpoint.txid, op->txid, 32) == 0 && s->op_watches[i].outpoint.vout == op->vout) {
            s->op_watches[i].depth = depth;
            return &s->op_watches[i];
        }
    s->op_watches = grow(s->op_watches, &s->cap_op_watches, s->n_op_watches + 1, sizeof *s->op_watches);
    op_watch_t *w = &s->op_watches[s->n_op_watches++];
    *w = (op_watch_t){*op, depth, 0, 0};
    return w;
}

/* Answer a transaction watch: when it is set (`at_set`), with the current
 * count if the transaction is in the chain; at a block, with the new count
 * while it is at most the depth. */
static void answer_tx_watch(sim_t *sim, uint32_t n, tx_watch_t *w, int at_set)
{
    long t = find_tx(sim, w->txid);
    if (t < 0) return;
    uint32_t c = confirmations_of(sim, (size_t)t);
    if (c == 0 || (!at_set && c > w->depth)) return;
    w->reported = 1;
    post_chain(sim, n, GZ_CHAIN_TX_CONFIRMED, (size_t)t, NULL, c);
}

/* Answer an outpoint watch: when it is set, if a spender is known; when a
 * spender is first seen; at a block, while its count is from 1 to the depth. */
static void answer_op_watch(sim_t *sim, uint32_t n, op_watch_t *w, int at_set)
{
    long t = find_spender(sim, &w->outpoint);
    if (t < 0) return;
    uint32_t c = confirmations_of(sim, (size_t)t);
    if (w->seen && !at_set && (c == 0 || c > w->depth)) return;
    w->seen = 1;
    w->in_chain = c > 0;
    post_chain(sim, n, GZ_CHAIN_OUTPOINT_SPENT, (size_t)t, &w->outpoint, c);
}

static void chain_broadcast(sim_t *sim, uint32_t origin, gz_bytes_t tx)
{
    uint64_t digest = digest_bytes(tx.data, tx.len);
    for (size_t i = 0; i < sim->n_txs; i++)
        if (same_bytes(sim->txs[i].blob.bytes, sim->txs[i].blob.len, tx.data, tx.len)) {
            trace(sim, "broadcast node=%u digest=%016llx already-known", origin, (unsigned long long)digest);
            return;
        }
    const uint8_t *in = NULL;
    size_t n_in = tx_inputs(tx.data, tx.len, &in);
    for (size_t i = 0; i < n_in; i++) {
        gz_outpoint_t op;
        memcpy(op.txid, in + TX_INPUT_LEN * i, 32);
        op.vout = le32(in + TX_INPUT_LEN * i + 32);
        if (find_spender(sim, &op) >= 0) {
            sim->stats.txs_conflicting++;
            trace(sim, "broadcast node=%u digest=%016llx conflicts", origin, (unsigned long long)digest);
            return;
        }
    }
    int never = sim_rng_chance(&sim->rng, sim->cfg.tx_never_pm);
    sim->txs = grow(sim->txs, &sim->cap_txs, sim->n_txs + 1, sizeof *sim->txs);
    chain_tx_t *t = &sim->txs[sim->n_txs++];
    *t = (chain_tx_t){blob_copy(tx.data, tx.len), origin, 0, never, {0}};
    txid_of(tx.data, tx.len, t->txid);
    sim->stats.txs_never += (uint64_t)never;
    trace(sim, "broadcast node=%u len=%zu digest=%016llx%s", origin, tx.len, (unsigned long long)digest,
          never ? " never-confirms" : "");
    if (n_in)                               /* a new spender, seen in the mempool */
        for (uint32_t n = 0; n < sim->cfg.n_nodes; n++)
            for (size_t w = 0; w < sim->slots[n].n_op_watches; w++)
                if (!sim->slots[n].op_watches[w].seen) answer_op_watch(sim, n, &sim->slots[n].op_watches[w], 0);
}

/* Tell watchers about the script spent by the transaction at index `t`. */
static void report_spend(sim_t *sim, size_t t)
{
    gz_bytes_t script = spent_script(&sim->txs[t].blob);
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) {
        if (script.len == 0 || !watches(&sim->slots[n], script)) continue;
        post_chain(sim, n, GZ_CHAIN_SCRIPT_SPENT, t, NULL, 0);
    }
}

static void post_tip(sim_t *sim)
{
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) {
        gz_event_t ev = {.kind = GZ_EVENT_CHAIN};
        ev.u.chain.kind = GZ_CHAIN_NEW_TIP;
        ev.u.chain.height = sim->height;
        post(&sim->slots[n], &ev);
    }
}

static void mine_block(sim_t *sim)
{
    sim->height++;
    sim->stats.blocks++;
    for (size_t t = 0; t < sim->n_txs; t++)
        if (sim->txs[t].height == 0 && !sim->txs[t].never) sim->txs[t].height = sim->height;
    trace(sim, "block height=%u", sim->height);
    post_tip(sim);
    for (size_t t = 0; t < sim->n_txs; t++)
        if (sim->txs[t].height == sim->height) report_spend(sim, t);
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) {
        slot_t *s = &sim->slots[n];
        for (size_t w = 0; w < s->n_tx_watches; w++) answer_tx_watch(sim, n, &s->tx_watches[w], 0);
        for (size_t w = 0; w < s->n_op_watches; w++) answer_op_watch(sim, n, &s->op_watches[w], 0);
    }
}

/* Remove the newest `depth` blocks: their transactions return to the mempool. */
static void reorg(sim_t *sim, uint32_t depth)
{
    if (depth > sim->height) depth = sim->height;
    if (depth == 0) return;
    uint32_t new_height = sim->height - depth;
    sim->stats.reorgs++;
    trace(sim, "reorg from=%u to=%u", sim->height, new_height);
    for (size_t t = 0; t < sim->n_txs; t++)
        if (sim->txs[t].height > new_height) sim->txs[t].height = 0;
    sim->height = new_height;
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) {
        slot_t *s = &sim->slots[n];
        for (size_t i = 0; i < s->n_tx_watches; i++) {
            tx_watch_t *w = &s->tx_watches[i];
            long t = find_tx(sim, w->txid);
            if (!w->reported || t < 0 || confirmations_of(sim, (size_t)t) > 0) continue;
            w->reported = 0;
            post_chain(sim, n, GZ_CHAIN_TX_UNCONFIRMED, (size_t)t, NULL, 0);
        }
        for (size_t i = 0; i < s->n_op_watches; i++) {
            op_watch_t *w = &s->op_watches[i];
            long t = find_spender(sim, &w->outpoint);
            if (!w->in_chain || t < 0 || confirmations_of(sim, (size_t)t) > 0) continue;
            w->in_chain = 0;
            post_chain(sim, n, GZ_CHAIN_OUTPOINT_SPENT, (size_t)t, &w->outpoint, 0);
        }
    }
    post_tip(sim);
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

/* Queue a timer event for every timer of the node that is due, in the order set. */
static void fire_timers(slot_t *s)
{
    size_t kept = 0;
    for (size_t i = 0; i < s->n_timers; i++) {
        if (s->timers[i].due > s->sim->step) { s->timers[kept++] = s->timers[i]; continue; }
        gz_event_t ev = {.kind = GZ_EVENT_TIMER_FIRED};
        ev.u.timer.timer_id = s->timers[i].id;
        trace(s->sim, "timer node=%u id=%llu", s->index, (unsigned long long)ev.u.timer.timer_id);
        post(s, &ev);
    }
    s->n_timers = kept;
}

static void add_watch(slot_t *s, gz_bytes_t script)
{
    if (watches(s, script)) return;
    s->watches = grow(s->watches, &s->cap_watches, s->n_watches + 1, sizeof *s->watches);
    s->watches[s->n_watches++] = blob_copy(script.data, script.len);
}

/* ---- carrying out actions ---- */

static int action_holds_secret(const slot_t *s, const gz_action_t *a);
static uint64_t first8(const uint8_t *b);
static tx_watch_t *add_tx_watch(slot_t *s, const uint8_t txid[32], uint32_t depth);
static op_watch_t *add_op_watch(slot_t *s, const gz_outpoint_t *op, uint32_t depth);
static void answer_tx_watch(sim_t *sim, uint32_t n, tx_watch_t *w, int at_set);
static void answer_op_watch(sim_t *sim, uint32_t n, op_watch_t *w, int at_set);

void sim_execute(sim_t *sim, uint32_t index, const gz_action_t *a)
{
    slot_t *s = &sim->slots[index];
    if (s->storage_failed) {
        violate(sim, "an action was carried out after its program's storage had failed");
        return;
    }
    if (action_holds_secret(s, a)) {
        sim->stats.secret_leaks++;
        violate(sim, "the bytes of a secret-tagged random draw left the node in an action");
        return;
    }
    switch (a->kind) {
    case GZ_ACTION_SAVE:
        note_stored(s, a);
        storage_accept(s, a);
        break;
    case GZ_ACTION_SEND:
        note_left(s, a);
        sim->stats.node_sends++;
        if (sim->cfg.ops.observe) sim->cfg.ops.observe(sim->ops_ctx, index, a);
        network_send(sim, index, a->u.send.peer_id, a->u.send.bytes.data, a->u.send.bytes.len);
        break;
    case GZ_ACTION_BROADCAST:
        note_left(s, a);
        chain_broadcast(sim, index, a->u.broadcast.tx);
        break;
    case GZ_ACTION_NOTIFY:
        note_left(s, a);
        trace(sim, "notify node=%u code=%u len=%zu digest=%016llx", index, a->u.notify.code, a->u.notify.bytes.len,
              (unsigned long long)digest_bytes(a->u.notify.bytes.data, a->u.notify.bytes.len));
        break;
    case GZ_ACTION_WATCH_SCRIPT:
        add_watch(s, a->u.watch_script.script);
        trace(sim, "watch node=%u len=%zu digest=%016llx", index, a->u.watch_script.script.len,
              (unsigned long long)digest_bytes(a->u.watch_script.script.data, a->u.watch_script.script.len));
        break;
    case GZ_ACTION_WATCH_TX:
        trace(sim, "watch-tx node=%u txid=%016llx depth=%u", index, (unsigned long long)first8(a->u.watch_tx.txid),
              a->u.watch_tx.depth);
        answer_tx_watch(sim, index, add_tx_watch(s, a->u.watch_tx.txid, a->u.watch_tx.depth), 1);
        break;
    case GZ_ACTION_WATCH_OUTPOINT:
        trace(sim, "watch-outpoint node=%u txid=%016llx vout=%u depth=%u", index,
              (unsigned long long)first8(a->u.watch_outpoint.outpoint.txid), a->u.watch_outpoint.outpoint.vout,
              a->u.watch_outpoint.depth);
        answer_op_watch(sim, index, add_op_watch(s, &a->u.watch_outpoint.outpoint, a->u.watch_outpoint.depth), 1);
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

/* 1 if the node crashes now, just before the action its runner is handing over. */
static int crash_point(slot_t *s)
{
    sim_t *sim = s->sim;
    if (s->crash_countdown != NOT_ARMED) {
        if (s->crash_countdown-- > 0) return 0;
        s->crash_countdown = NOT_ARMED;
        return 1;
    }
    if (sim->cfg.crash_in_release_pm == 0 || s->died_this_step) return 0;
    if (!sim_rng_chance(&sim->rng, sim->cfg.crash_in_release_pm)) return 0;
    s->died_this_step = 1;
    return 1;
}

/* The executor given to each node's runner. */
static void runner_execute(void *ctx, const gz_action_t *action)
{
    slot_t *s = ctx;
    if (s->dying) return;       /* the program is already dead: nothing more is carried out */
    if (crash_point(s)) {
        s->dying = 1;
        s->sim->stats.crashes_in_release++;
        trace(s->sim, "crash-in-release node=%u", s->index);
        return;
    }
    sim_execute(s->sim, s->index, action);
}

/* Give a list of actions to the node's program. */
static void release_list(slot_t *s, const gz_action_list_t *list, int is_start)
{
    sim_t *sim = s->sim;
    if (list->count == 0) return;
    note_emitted(s, list);
    gz_status_t st = sim->cfg.ops.release
        ? sim->cfg.ops.release(sim->ops_ctx, sim, s->index, list)
        : gz_runner_submit(&s->runner, list);
    if (st != GZ_OK && s->storage_failed) {            /* storage failed while the list was carried out */
        trace(sim, "list-stopped node=%u: storage failed", s->index);
        s->needs_rebuild = 1;
    } else if (st != GZ_OK) {
        sim->stats.lists_refused++;
        trace(sim, "refused node=%u actions=%zu status=%d", s->index, list->count, (int)st);
        if (is_start) violate(sim, "a node's start actions were refused");
        else if (!sim->cfg.allow_refusals) violate(sim, "a node's program refused an action list");
        else s->needs_rebuild = 1;
    }
    if (s->dying) s->needs_rebuild = 1;
}

/* ---- nodes ---- */

static uint64_t first8(const uint8_t *b)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i);
    return v ? v : 1;                       /* 0 marks a free place in the table */
}

/* ---- "secrets never leave" (sim.h) ----
 *
 * Every 8-byte window of every secret-tagged draw, read forwards and
 * backwards, is indexed by its difference signature: the seven XORs of
 * neighbouring bytes. Two windows have the same signature exactly when one is
 * the other XOR a single repeated byte, so one lookup finds a window copied
 * raw, XORed with any one-byte constant, or byte-reversed, anywhere in an
 * action's bytes. Hex text in an action is decoded and searched the same way,
 * and so are the action's 8-byte integer fields (a timer's identifier, a
 * send's peer). A secret draw shorter than 16 bytes is itself refused: a
 * secret built from short draws could not be told apart from chance. */
static uint64_t window_signature(const uint8_t *w, int reversed)
{
    uint64_t v = 1;                         /* a set top bit: 0 marks a free place in the table */
    for (int i = 1; i < 8; i++) {
        uint8_t a = reversed ? w[7 - i] : w[i], b = reversed ? w[8 - i] : w[i - 1];
        v = v << 8 | (uint8_t)(a ^ b);
    }
    return v;
}

static void secret_table_put(slot_t *s, uint64_t key)
{
    if (2 * (s->n_secret_keys + 1) > s->cap_secret_keys) {
        size_t old_cap = s->cap_secret_keys, cap = old_cap ? 2 * old_cap : 256;
        uint64_t *old_keys = s->secret_keys;
        s->secret_keys = calloc(cap, sizeof *s->secret_keys);
        if (!s->secret_keys) abort();
        s->cap_secret_keys = cap;
        s->n_secret_keys = 0;
        for (size_t i = 0; i < old_cap; i++)
            if (old_keys[i]) secret_table_put(s, old_keys[i]);
        free(old_keys);
    }
    size_t at = (size_t)(key * 0x9E3779B97F4A7C15ull >> 20) & (s->cap_secret_keys - 1);
    while (s->secret_keys[at]) {
        if (s->secret_keys[at] == key) return;
        at = (at + 1) & (s->cap_secret_keys - 1);
    }
    s->secret_keys[at] = key;
    s->n_secret_keys++;
}

static int secret_table_has(const slot_t *s, uint64_t key)
{
    for (size_t at = (size_t)(key * 0x9E3779B97F4A7C15ull >> 20) & (s->cap_secret_keys - 1); s->secret_keys[at];
         at = (at + 1) & (s->cap_secret_keys - 1))
        if (s->secret_keys[at] == key) return 1;
    return 0;
}

/* A secret-tagged draw: refuse it if short, else index all its windows. */
static void note_secret(slot_t *s, const uint8_t *out, size_t len)
{
    if (len < 16) {
        violate(s->sim, "a secret-tagged random draw was shorter than 16 bytes");
        return;
    }
    for (size_t i = 0; i + 8 <= len; i++) {
        secret_table_put(s, window_signature(out + i, 0));
        secret_table_put(s, window_signature(out + i, 1));
    }
}

/* 1 if some 8 contiguous bytes of `data[0..len)` are 8 contiguous bytes of a
 * secret-tagged draw of this node, raw, XORed with one repeated byte, or in
 * reverse order. */
static int holds_secret_raw(const slot_t *s, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i + 8 <= len; i++)
        if (secret_table_has(s, window_signature(data + i, 0))) return 1;
    return 0;
}

static int hex_value(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* The same, also through hex text: every run of 16 or more hex digits is
 * decoded, at both alignments, and searched. */
static int holds_secret(const slot_t *s, const uint8_t *data, size_t len)
{
    if (!data || !s->n_secret_keys) return 0;
    if (holds_secret_raw(s, data, len)) return 1;
    uint8_t decoded[512];
    for (size_t i = 0; i < len;) {
        size_t run = 0;
        while (i + run < len && hex_value(data[i + run]) >= 0) run++;
        for (size_t align = 0; run >= 16 && align < 2; align++) {
            for (size_t from = i + align; from + 16 <= i + run; from += 2 * sizeof decoded - 16) {
                size_t n = 0;
                for (size_t k = from; k + 1 < i + run && n < sizeof decoded; k += 2)
                    decoded[n++] = (uint8_t)(hex_value(data[k]) << 4 | hex_value(data[k + 1]));
                if (holds_secret_raw(s, decoded, n)) return 1;
            }
        }
        i += run ? run : 1;
    }
    return 0;
}

static int holds_secret_u64(const slot_t *s, uint64_t v)
{
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
    return s->n_secret_keys && holds_secret_raw(s, b, 8);
}

static int action_holds_secret(const slot_t *s, const gz_action_t *a)
{
    switch (a->kind) {
    case GZ_ACTION_SAVE:
        for (size_t i = 0; i < a->u.save.n_records; i++)
            if (holds_secret(s, a->u.save.records[i].bytes.data, a->u.save.records[i].bytes.len)) return 1;
        return 0;
    case GZ_ACTION_SEND:           return holds_secret_u64(s, a->u.send.peer_id) ||
                                          holds_secret(s, a->u.send.bytes.data, a->u.send.bytes.len);
    case GZ_ACTION_BROADCAST:      return holds_secret(s, a->u.broadcast.tx.data, a->u.broadcast.tx.len);
    case GZ_ACTION_NOTIFY:         return holds_secret(s, a->u.notify.bytes.data, a->u.notify.bytes.len);
    case GZ_ACTION_WATCH_SCRIPT:   return holds_secret(s, a->u.watch_script.script.data, a->u.watch_script.script.len);
    case GZ_ACTION_WATCH_TX:       return holds_secret(s, a->u.watch_tx.txid, 32);
    case GZ_ACTION_WATCH_OUTPOINT: return holds_secret(s, a->u.watch_outpoint.outpoint.txid, 32);
    case GZ_ACTION_SET_TIMER:      return holds_secret_u64(s, a->u.set_timer.timer_id);
    case GZ_ACTION_CANCEL_TIMER:   return holds_secret_u64(s, a->u.cancel_timer.timer_id);
    }
    return 0;
}

static void random_fill(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    slot_t *s = ctx;
    sim_draw_t draw = {purpose, s->incarnation, len, {0}};
    sim_rng_fill(&s->rng, out, len);
    memcpy(draw.bytes, out, len < sizeof draw.bytes ? len : sizeof draw.bytes);
    s->draws = grow(s->draws, &s->cap_draws, s->n_draws + 1, sizeof *s->draws);
    s->draws[s->n_draws++] = draw;
    if (purpose == GZ_RANDOM_SECRET) note_secret(s, out, len);
}

static uint64_t clock_now(void *ctx)
{
    const sim_t *sim = ((slot_t *)ctx)->sim;
    int64_t now = (int64_t)sim->step + sim->clock_offset;
    return now < 0 ? 0 : (uint64_t)now;
}

/* The extra invariants only. Run just before a node is destroyed, so that they
 * see its last state; the built-in ones are judged after the step. */
static void check_extra_invariants(sim_t *sim);

/* A batch an earlier program handed over completes now, late. It takes its
 * place in the journal before any batch of a later incarnation. */
static void land_orphan(slot_t *s)
{
    sim_t *sim = s->sim;
    struct sim_storage *st = &s->storage;
    batch_t b = s->orphans[0];
    memmove(s->orphans, s->orphans + 1, --s->n_orphans * sizeof *s->orphans);
    /* It lands only before the new program's first start step (the fence,
     * settle_orphans), so it goes last, and the journal stays in order. */
    size_t at = st->n_durable;
    b.durable_at = b.confirm_at = sim->step;
    st->durable = grow(st->durable, &st->cap_durable, st->n_durable + 1, sizeof *st->durable);
    s->shadow = grow(s->shadow, &s->cap_shadow, s->n_shadow + 1, sizeof *s->shadow);
    st->durable[st->n_durable++] = b;
    s->shadow[s->n_shadow++] = (shadow_t){b.id, b.digest};
    if (at < st->next_confirm) abort();                 /* every earlier batch was confirmed or stale: cannot be */
    st->next_confirm = st->n_durable;                   /* its program is dead: no confirmation */
    sim->stats.saves_durable++;
    sim->stats.late_landings++;
    trace(sim, "late-landing node=%u batch=%llu.%llu at=%zu", s->index,
          (unsigned long long)b.id.incarnation, (unsigned long long)b.id.sequence, at);
    note_durable(s, b.id);
}

/* What an earlier program left pending is gone for good. */
static void discard_orphans(slot_t *s)
{
    s->sim->stats.saves_lost += s->n_orphans;
    for (size_t i = 0; i < s->n_orphans; i++) free(s->orphans[i].blob.bytes);
    s->n_orphans = 0;
}

/* The fence (ports.h): before the new program's first start step, storage
 * settles what the earlier one left pending. Batches complete in the order
 * handed over, each with chance late_save_pm; the first that does not is
 * gone, and so is everything after it. */
static void settle_orphans(slot_t *s)
{
    while (s->n_orphans && sim_rng_chance(&s->sim->rng, s->sim->cfg.late_save_pm)) land_orphan(s);
    if (s->n_orphans) trace(s->sim, "orphans-lost node=%u gone=%zu", s->index, s->n_orphans);
    discard_orphans(s);
}

/* The start has finished: the events held back are handed on. */
static void finish_start(slot_t *s)
{
    sim_t *sim = s->sim;
    s->starting = 0;
    trace(sim, "started node=%u steps=%zu held-back=%zu", s->index, s->start_steps, s->n_deferred);
    for (size_t i = 0; i < s->n_deferred; i++) {
        sim->queue = grow(sim->queue, &sim->cap_queue, sim->q_len + 1, sizeof *sim->queue);
        sim->queue[sim->q_len++] = s->deferred[i];
    }
    s->n_deferred = 0;
}

/* Go on with the node's start, one step at a time, each step's actions going
 * through its program before the next is asked for, until it finishes, waits
 * for a confirmation, or the node stops. */
static void continue_start(slot_t *s)
{
    sim_t *sim = s->sim;
    gz_action_list_t list;
    while (s->starting && !s->needs_rebuild && !sim->violation) {
        int more = 1;
        gz_action_list_init(&list, sim->start_slot_buf, sim->step_slots, sim->start_byte_buf, sim->step_bytes);
        gz_status_t st = s->start_steps++ == MAX_START_STEPS ? GZ_ERR_NO_SPACE : sim->cfg.ops.start(s->node, &list, &more);
        if (st == GZ_WAITING) {
            trace(sim, "start-waiting node=%u", s->index);
            return;
        }
        if (st != GZ_OK) {
            sim->stats.handle_errors++;
            trace(sim, "start-error node=%u status=%d", s->index, (int)st);
            violate(sim, "a node failed to start");
            return;
        }
        release_list(s, &list, 1);
        if (!more && !s->needs_rebuild) finish_start(s);
    }
}

/* Build the node from its storage under a new incarnation, start it and tell
 * it which of its links are up (news it gets once its start has finished). */
static void build_node(slot_t *s)
{
    sim_t *sim = s->sim;
    s->incarnation++;
    /* A stream no earlier incarnation of any node has used, unless a restore
     * was set to make the generator repeat. */
    sim_rng_init(&s->rng, sim->cfg.seed,
                 (s->repeat_stream ? s->repeat_stream : s->incarnation) << 32 | ((uint64_t)s->index + 1));
    s->repeat_stream = 0;
    (void)gz_runner_init(&s->runner, s->runner_slots, sim->runner_slots, s->runner_bytes, sim->runner_bytes,
                         s->incarnation, runner_execute, s);
    s->storage.reader_incarnation = s->incarnation;
    settle_orphans(s);                                  /* the fence: before anything reads storage */
    s->storage.reader_restored = s->restore_pending;
    s->started_restored = s->restore_pending && sim->cfg.ops.start != NULL;
    s->emitted_any = 0;
    if (s->restore_pending) trace(sim, "restore-marker node=%u incarnation=%llu", s->index, (unsigned long long)s->incarnation);
    s->node = sim->cfg.ops.create(sim->ops_ctx, s->index, &s->ports, &s->storage);
    if (!s->node) abort();
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++)
        if (n != s->index && link_is_up(sim, s->index, n)) tell_peer(s, n, 1);
    if (link_is_up(sim, s->index, SIM_WORLD_PEER)) tell_peer(s, SIM_WORLD_PEER, 1);
    s->start_steps = 0;
    s->starting = sim->cfg.ops.start != NULL;
    if (s->starting) continue_start(s);
}

static void free_blobs(blob_t *blobs, size_t n)
{
    for (size_t i = 0; i < n; i++) free(blobs[i].bytes);
}

/* A crash: destroy everything of the node except its durable storage, then
 * build it again. Its peers see the connection drop and come back. What the
 * dead program had handed to storage and was still pending is lost, or, with
 * late_save_pm, may still complete before the new program reads storage. */
static void rebuild(slot_t *s)
{
    sim_t *sim = s->sim;
    sim->stats.crashes++;
    trace(sim, "crash node=%u pending-saves=%zu held-actions=%zu", s->index, s->storage.n_pending,
          sim->cfg.ops.release ? (size_t)0 : gz_runner_held(&s->runner));
    check_extra_invariants(sim);
    sim->cfg.ops.destroy(sim->ops_ctx, s->node);
    if (sim->cfg.late_save_pm && s->storage.n_pending > 0) {
        s->orphans = grow(s->orphans, &s->cap_orphans, s->storage.n_pending, sizeof *s->orphans);
        memcpy(s->orphans, s->storage.pending, s->storage.n_pending * sizeof *s->orphans);
        s->n_orphans = s->storage.n_pending;
    } else {
        sim->stats.saves_lost += s->storage.n_pending;
        for (size_t i = 0; i < s->storage.n_pending; i++) free(s->storage.pending[i].blob.bytes);
    }
    free_blobs(s->watches, s->n_watches);
    s->storage.n_pending = s->n_timers = s->n_watches = s->n_tx_watches = s->n_op_watches = 0;
    s->n_emitted_saves = s->n_saves_stored = s->n_saves_durable = s->n_expected = s->head_expected = 0;
    s->needs_rebuild = s->dying = s->storage_failed = 0;
    s->crash_countdown = NOT_ARMED;
    build_node(s);
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) {
        if (n == s->index || !link_is_up(sim, s->index, n)) continue;
        tell_peer(&sim->slots[n], s->index, 0);
        tell_peer(&sim->slots[n], s->index, 1);
    }
}

/* Bring a node up to date: rebuild it if it has stopped, and let its storage
 * make progress. */
static void service(slot_t *s)
{
    while (s->needs_rebuild && !s->sim->violation) rebuild(s);
    settle_storage(s);
    while (s->needs_rebuild && !s->sim->violation) rebuild(s);
}

/* A confirmation has arrived for the node. Returns 1 if the node is to be
 * told about it. */
static int accept_confirmation(slot_t *s, const queued_t *q)
{
    sim_t *sim = s->sim;
    gz_batch_id_t id = q->ev.u.storage.batch;
    int stale = q->node_incarnation != s->incarnation;
    int has_runner = !sim->cfg.ops.release || sim->cfg.ops.confirm;
    gz_status_t st = GZ_OK;
    if (!sim->cfg.ops.release) st = gz_runner_confirm(&s->runner, id);
    else if (sim->cfg.ops.confirm) st = sim->cfg.ops.confirm(sim->ops_ctx, sim, s->index, id);
    if (s->dying) s->needs_rebuild = 1;
    if (has_runner && stale && st != GZ_ERR_STALE_BATCH)
        violate(sim, "a confirmation from before a crash was not reported as stale");
    if (has_runner && !stale && st != GZ_OK)
        violate(sim, "the runner rejected a confirmation that storage delivered in order");
    if (stale || st != GZ_OK) {
        sim->stats.stale_confirmations += (uint64_t)stale;
        trace(sim, "confirmation-ignored node=%u batch=%llu.%llu status=%d", s->index,
              (unsigned long long)id.incarnation, (unsigned long long)id.sequence, (int)st);
        return 0;
    }
    sim->stats.confirmations++;
    trace(sim, "confirmed node=%u batch=%llu.%llu", s->index,
          (unsigned long long)id.incarnation, (unsigned long long)id.sequence);
    return 1;
}

/* 1 if an event queued for a program that has since died may still be given
 * to its successor: only what comes from outside and would have arrived
 * anyway. */
static int outlives_a_crash(gz_event_kind_t kind)
{
    return kind == GZ_EVENT_MESSAGE_RECEIVED || kind == GZ_EVENT_CHAIN;
}

/* Handle one queued event: give it to its node and carry out what comes back.
 * Returns 1 if the event was held back until the node's start finishes (the
 * event, and its bytes, are then kept), 0 if it is done with. */
static int process(sim_t *sim, const queued_t *q)
{
    slot_t *s = &sim->slots[q->node];
    gz_action_list_t list;

    if (q->ev.kind == GZ_EVENT_STORAGE_CONFIRMED) {
        if (!accept_confirmation(s, q)) return 0;
    } else if (s->starting) {
        s->deferred = grow(s->deferred, &s->cap_deferred, s->n_deferred + 1, sizeof *s->deferred);
        s->deferred[s->n_deferred++] = *q;
        return 1;
    } else if (q->node_incarnation != s->incarnation && !outlives_a_crash(q->ev.kind)) {
        sim->stats.events_not_delivered++;
        trace(sim, "not-delivered node=%u event=%d from-incarnation=%llu", s->index, (int)q->ev.kind,
              (unsigned long long)q->node_incarnation);
        if (q->ev.kind == GZ_EVENT_USER_COMMAND) {      /* the user is told, not left wondering */
            sim->stats.commands_not_done++;
            trace(sim, "ui node=%u command-not-done: the app restarted", s->index);
        }
        return 0;
    }
    gz_action_list_init(&list, sim->step_slot_buf, sim->step_slots, sim->step_byte_buf, sim->step_bytes);
    if (sim->cfg.ops.handle(s->node, &q->ev, &list) != GZ_OK) {
        sim->stats.handle_errors++;
        trace(sim, "handle-error node=%u event=%d", s->index, (int)q->ev.kind);
        return 0;
    }
    release_list(s, &list, 0);
    if (q->ev.kind == GZ_EVENT_STORAGE_CONFIRMED && s->starting) continue_start(s);
    return 0;
}

/* Handle queued events until none are left. Handling one may queue more. */
static void drain(sim_t *sim)
{
    while (sim->q_head < sim->q_len) {
        queued_t q = sim->queue[sim->q_head++];
        if (!process(sim, &q)) free(q.blob.bytes);
        service(&sim->slots[q.node]);
    }
    sim->q_head = sim->q_len = 0;
}

/* The default node: a gz_node_t that reads its storage through a reader. */
typedef struct {
    gz_node_t node;
    const sim_storage_t *storage;
    size_t next_batch;
    gz_record_t records[READER_RECORDS];
} default_node_t;

static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void reader_rewind(void *ctx) { ((default_node_t *)ctx)->next_batch = 0; }

/* The next durable batch, its records decoded in place. The placeholder node
 * saves one record per batch; a batch with more than READER_RECORDS would
 * show only its first ones. */
static int reader_next(void *ctx, gz_stored_batch_t *batch)
{
    default_node_t *d = ctx;
    if (d->next_batch >= sim_storage_count(d->storage)) return 0;
    size_t len = 0, n = 0;
    const uint8_t *p = sim_storage_batch_bytes(d->storage, d->next_batch, &len), *end = p + len;
    for (; p < end && n < READER_RECORDS; p += 8 + read_u32(p + 4))
        d->records[n++] = (gz_record_t){read_u32(p), {p + 8, read_u32(p + 4)}};
    batch->id = sim_storage_batch_id(d->storage, d->next_batch++);
    batch->records = d->records;
    batch->n_records = n;
    return 1;
}

static void *default_create(void *ops_ctx, uint32_t index, const gz_ports_t *ports,
                            const sim_storage_t *storage)
{
    (void)ops_ctx; (void)index;
    default_node_t *d = calloc(1, sizeof *d);
    if (!d || gz_node_init(&d->node, ports) != GZ_OK) abort();
    d->storage = storage;
    return d;
}

static void default_destroy(void *ops_ctx, void *node) { (void)ops_ctx; free(node); }

static gz_status_t default_start(void *node, gz_action_list_t *out, int *more)
{
    default_node_t *d = node;
    gz_storage_reader_t reader = {reader_next, reader_rewind, d, sim_storage_incarnation(d->storage),
                                  sim_storage_restored(d->storage)};
    return gz_node_start(&d->node, &reader, out, more);
}

static gz_status_t default_handle(void *node, const gz_event_t *event, gz_action_list_t *out)
{
    return gz_node_handle(&((default_node_t *)node)->node, event, out);
}

/* The placeholder node shows its next serial and how many of its batches
 * await confirmation, each as 8 bytes, low byte first. */
static size_t default_inspect(const void *node, uint8_t *out, size_t cap)
{
    const gz_node_t *n = &((const default_node_t *)node)->node;
    if (cap < 16) return 0;
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(n->next_serial >> (8 * i));
        out[8 + i] = (uint8_t)((uint64_t)n->n_awaiting >> (8 * i));
    }
    return 16;
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

static void check_extra_invariants(sim_t *sim)
{
    const char *why = "an invariant failed";
    for (size_t i = 0; i < sim->n_invariants && !sim->failed; i++)
        if (!sim->invariants[i].check(sim, sim->invariants[i].ctx, &why)) fail(sim, why);
}

static void check_invariants(sim_t *sim)
{
    const char *why = "an invariant failed";
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) check_storage(&sim->slots[n]);
    if (sim->violation) fail(sim, sim->violation);
    /* The twin is judged only by its trace: whatever it does differently from
     * this simulator shows there, and what it does the same is judged here. */
    if (sim->twin && sim->twin->trace_hash != sim->trace_hash)
        fail(sim, "same seed, same run: two runs of this configuration differ");
    for (size_t i = 0; i < sim->n_invariants && !sim->failed; i++)
        if (!sim->invariants[i].check(sim, sim->invariants[i].ctx, &why)) fail(sim, why);
}

/* ---- the scheduler ---- */

static void service_all(sim_t *sim)
{
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) service(&sim->slots[n]);
    drain(sim);
}

static void maybe_crash(sim_t *sim)
{
    int crash_now = sim_rng_chance(&sim->rng, sim->cfg.crash_pm);
    uint32_t who = (uint32_t)sim_rng_below(&sim->rng, sim->cfg.n_nodes);
    if (crash_now) sim->slots[who].needs_rebuild = 1;
}

static void maybe_restore(sim_t *sim)
{
    int restore_now = sim_rng_chance(&sim->rng, sim->cfg.restore_pm);
    slot_t *s = &sim->slots[sim_rng_below(&sim->rng, sim->cfg.n_nodes)];
    uint64_t share = sim_rng_below(&sim->rng, 1001);
    if (restore_now) restore(s, (size_t)(s->storage.n_durable * share / 1000));
}

static void maybe_flap_link(sim_t *sim)
{
    int flap_now = sim_rng_chance(&sim->rng, sim->cfg.link_flap_pm);
    uint64_t a = sim_rng_below(&sim->rng, sim->cfg.n_nodes);
    uint64_t b = sim_rng_below(&sim->rng, (uint64_t)sim->cfg.n_nodes + 1);
    if (!flap_now || a == b) return;
    if (b == sim->cfg.n_nodes) b = SIM_WORLD_PEER;
    set_link(sim, a, b, !link_is_up(sim, a, b));
}

static void jump_clock(sim_t *sim, int64_t delta)
{
    sim->clock_offset += delta;
    sim->stats.clock_jumps++;
    trace(sim, "clock-jump by=%lld", (long long)delta);
}

static void maybe_jump_clock(sim_t *sim)
{
    int jump_now = sim_rng_chance(&sim->rng, sim->cfg.clock_jump_pm);
    int64_t size = 1 + (int64_t)sim_rng_below(&sim->rng, sim->cfg.max_clock_jump ? sim->cfg.max_clock_jump : 1);
    int back = sim_rng_chance(&sim->rng, 500);
    if (jump_now) jump_clock(sim, back ? -size : size);
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

static void maybe_reorg(sim_t *sim)
{
    int reorg_now = sim_rng_chance(&sim->rng, sim->cfg.reorg_pm);
    uint32_t depth = 1 + (uint32_t)sim_rng_below(&sim->rng, sim->cfg.max_reorg_depth ? sim->cfg.max_reorg_depth : 1);
    if (reorg_now) reorg(sim, depth);
}

static void advance(sim_t *sim)
{
    sim->step++;
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) sim->slots[n].died_this_step = 0;
    maybe_crash(sim);
    maybe_restore(sim);
    maybe_flap_link(sim);
    maybe_jump_clock(sim);
    maybe_ping(sim);
    service_all(sim);
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) fire_timers(&sim->slots[n]);
    drain(sim);
    deliver_one_message(sim);
    drain(sim);
    maybe_reorg(sim);
    if (sim_rng_chance(&sim->rng, sim->cfg.block_pm)) mine_block(sim);
    drain(sim);
}

/* ---- public ---- */

static sim_t *create(const sim_config_t *config, int is_twin)
{
    sim_t *sim = calloc(1, sizeof *sim);
    if (!sim) abort();
    sim->cfg = *config;
    sim->ops_ctx = is_twin ? config->ops.twin_ctx : config->ops.ctx;
    if (!sim->cfg.ops.create) {
        sim->cfg.ops.create = default_create;
        sim->cfg.ops.destroy = default_destroy;
        sim->cfg.ops.start = default_start;
        sim->cfg.ops.handle = default_handle;
        sim->cfg.ops.inspect = default_inspect;
    }
    sim->trace_hash = FNV_OFFSET;
    sim_rng_init(&sim->rng, config->seed, 0);
    sim->slots = calloc(config->n_nodes, sizeof *sim->slots);
    sim->link_down = calloc(((size_t)config->n_nodes + 1) * ((size_t)config->n_nodes + 1), 1);
    if (!sim->slots || !sim->link_down) abort();
    sim->step_slots = config->step_slots ? config->step_slots : STEP_SLOTS;
    sim->step_bytes = config->step_bytes ? config->step_bytes : STEP_BYTES;
    sim->runner_slots = config->runner_slots ? config->runner_slots : RUNNER_SLOTS;
    sim->runner_bytes = config->runner_bytes ? config->runner_bytes : RUNNER_BYTES;
    sim->start_slot_buf = calloc(sim->step_slots, sizeof *sim->start_slot_buf);
    sim->step_slot_buf = calloc(sim->step_slots, sizeof *sim->step_slot_buf);
    sim->start_byte_buf = malloc(sim->step_bytes);
    sim->step_byte_buf = malloc(sim->step_bytes);
    if (!sim->start_slot_buf || !sim->step_slot_buf || !sim->start_byte_buf || !sim->step_byte_buf) abort();
    for (uint32_t n = 0; n < config->n_nodes; n++) {
        slot_t *s = &sim->slots[n];
        s->sim = sim;
        s->index = n;
        s->crash_countdown = NOT_ARMED;
        s->ports.random = (gz_random_port_t){random_fill, s};
        s->ports.clock = (gz_clock_port_t){clock_now, s};
        s->runner_slots = calloc(sim->runner_slots, sizeof *s->runner_slots);
        s->runner_bytes = malloc(sim->runner_bytes);
        if (!s->runner_slots || !s->runner_bytes) abort();
    }
    for (uint32_t n = 0; n < config->n_nodes; n++) build_node(&sim->slots[n]);
    service_all(sim);
    return sim;
}

sim_t *sim_create(const sim_config_t *config)
{
    if (!config || config->n_nodes == 0) return NULL;
    sim_t *sim = create(config, 0);
    if (config->check_same_seed) sim->twin = create(config, 1);
    check_invariants(sim);
    return sim;
}

void sim_destroy(sim_t *sim)
{
    if (!sim) return;
    if (sim->twin) sim_destroy(sim->twin);
    for (uint32_t n = 0; n < sim->cfg.n_nodes; n++) {
        slot_t *s = &sim->slots[n];
        sim->cfg.ops.destroy(sim->ops_ctx, s->node);
        for (size_t i = 0; i < s->storage.n_pending; i++) free(s->storage.pending[i].blob.bytes);
        for (size_t i = 0; i < s->storage.n_durable; i++) free(s->storage.durable[i].blob.bytes);
        free_blobs(s->watches, s->n_watches);
        free(s->storage.pending); free(s->storage.durable);
        for (size_t i = 0; i < s->n_deferred; i++) free(s->deferred[i].blob.bytes);
        for (size_t i = 0; i < s->n_orphans; i++) free(s->orphans[i].blob.bytes);
        free(s->deferred); free(s->orphans);
        free(s->tx_watches); free(s->op_watches); free(s->secret_keys);
        free(s->watches); free(s->timers); free(s->draws); free(s->emitted_saves); free(s->expected); free(s->shadow);
        free(s->runner_slots); free(s->runner_bytes);
    }
    free(sim->start_slot_buf); free(sim->step_slot_buf); free(sim->start_byte_buf); free(sim->step_byte_buf);
    for (size_t i = sim->q_head; i < sim->q_len; i++) free(sim->queue[i].blob.bytes);
    for (size_t i = 0; i < sim->n_net; i++) free(sim->net[i].blob.bytes);
    for (size_t i = 0; i < sim->n_txs; i++) free(sim->txs[i].blob.bytes);
    free(sim->queue); free(sim->net); free(sim->txs); free(sim->slots); free(sim->link_down); free(sim->trace);
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
    advance(sim);
    if (sim->twin) advance(sim->twin);
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
uint64_t sim_node_incarnation(const sim_t *sim, uint32_t index) { return sim->slots[index].incarnation; }
int sim_node_starting(const sim_t *sim, uint32_t index) { return sim->slots[index].starting; }
size_t sim_node_draw_count(const sim_t *sim, uint32_t index) { return sim->slots[index].n_draws; }
const sim_draw_t *sim_node_draw(const sim_t *sim, uint32_t index, size_t i) { return &sim->slots[index].draws[i]; }

size_t sim_node_inspect(const sim_t *sim, uint32_t index, uint8_t *out, size_t cap)
{
    return sim->cfg.ops.inspect ? sim->cfg.ops.inspect(sim->slots[index].node, out, cap) : 0;
}

const char *sim_trace(const sim_t *sim, size_t *len)
{
    if (len) *len = sim->trace_len;
    return sim->trace ? sim->trace : "";
}

/* The hand-driven calls: each does the same thing to the simulator and to its
 * lockstep twin, then checks the invariants. */

static void crash_now(sim_t *sim, uint32_t index)
{
    sim->slots[index].needs_rebuild = 1;
    service_all(sim);
}

void sim_crash_node(sim_t *sim, uint32_t index)
{
    if (sim->failed || index >= sim->cfg.n_nodes) return;
    crash_now(sim, index);
    if (sim->twin) crash_now(sim->twin, index);
    check_invariants(sim);
}

static void arm_crash(sim_t *sim, uint32_t index, uint32_t after)
{
    sim->slots[index].crash_countdown = after;
    trace(sim, "arm-crash node=%u after=%u", index, after);
}

void sim_crash_after_releases(sim_t *sim, uint32_t index, uint32_t after)
{
    if (sim->failed || index >= sim->cfg.n_nodes) return;
    arm_crash(sim, index, after);
    if (sim->twin) arm_crash(sim->twin, index, after);
}

static void fail_storage_now(sim_t *sim, uint32_t index)
{
    fail_storage(&sim->slots[index]);
    service_all(sim);
}

void sim_fail_storage(sim_t *sim, uint32_t index)
{
    if (sim->failed || index >= sim->cfg.n_nodes) return;
    fail_storage_now(sim, index);
    if (sim->twin) fail_storage_now(sim->twin, index);
    check_invariants(sim);
}

static void restore_now(sim_t *sim, uint32_t index, size_t keep)
{
    restore(&sim->slots[index], keep);
    service_all(sim);
}

void sim_restore_backup(sim_t *sim, uint32_t index, size_t keep)
{
    if (sim->failed || index >= sim->cfg.n_nodes) return;
    restore_now(sim, index, keep);
    if (sim->twin) restore_now(sim->twin, index, keep);
    check_invariants(sim);
}

static void damage(sim_t *sim, uint32_t index, int drop)
{
    struct sim_storage *st = &sim->slots[index].storage;
    trace(sim, "damage node=%u %s", index, drop ? "drop" : "alter");
    if (drop && st->n_durable) {
        free(st->durable[--st->n_durable].blob.bytes);
        if (st->next_confirm > st->n_durable) st->next_confirm = st->n_durable;
    }
    for (size_t i = st->n_durable; !drop && i-- > 0;)
        if (st->durable[i].blob.len) { st->durable[i].blob.bytes[st->durable[i].blob.len - 1] ^= 1; break; }
}

void sim_damage_storage(sim_t *sim, uint32_t index, int drop)
{
    if (sim->failed || index >= sim->cfg.n_nodes) return;
    damage(sim, index, drop);
    if (sim->twin) damage(sim->twin, index, drop);
    check_invariants(sim);
}

static void set_link_now(sim_t *sim, uint64_t a, uint64_t b, int up)
{
    set_link(sim, a, b, up);
    drain(sim);
}

void sim_set_link(sim_t *sim, uint64_t a, uint64_t b, int up)
{
    if (sim->failed) return;
    set_link_now(sim, a, b, up);
    if (sim->twin) set_link_now(sim->twin, a, b, up);
    check_invariants(sim);
}

static void reorg_now(sim_t *sim, uint32_t depth)
{
    reorg(sim, depth);
    drain(sim);
}

void sim_reorg(sim_t *sim, uint32_t depth)
{
    if (sim->failed) return;
    reorg_now(sim, depth);
    if (sim->twin) reorg_now(sim->twin, depth);
    check_invariants(sim);
}

void sim_jump_clock(sim_t *sim, int64_t delta)
{
    if (sim->failed) return;
    jump_clock(sim, delta);
    if (sim->twin) jump_clock(sim->twin, delta);
}

static void quiesce(sim_t *sim)
{
    sim_config_t *c = &sim->cfg;
    c->drop_pm = c->duplicate_pm = c->link_flap_pm = c->save_never_pm = c->save_fail_pm = c->save_fail_inline_pm = 0;
    c->crash_pm = c->crash_in_release_pm = c->restore_pm = c->ping_pm = 0;
    c->block_pm = c->reorg_pm = c->clock_jump_pm = 0;
    trace(sim, "quiet from here: %zu messages in flight discarded", sim->n_net);
    for (size_t i = 0; i < sim->n_net; i++) free(sim->net[i].blob.bytes);
    sim->n_net = 0;
}

void sim_quiesce(sim_t *sim)
{
    if (sim->failed) return;
    quiesce(sim);
    if (sim->twin) quiesce(sim->twin);
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
    trace(sim, "user node=%u len=%zu digest=%016llx", index, len, (unsigned long long)digest_bytes(bytes, len));
    post(&sim->slots[index], &ev);
    drain(sim);
}

void sim_user_command(sim_t *sim, uint32_t index, const uint8_t *bytes, size_t len)
{
    if (sim->failed || index >= sim->cfg.n_nodes) return;
    user_command(sim, index, bytes, len);
    if (sim->twin) user_command(sim->twin, index, bytes, len);
    check_invariants(sim);
}

void sim_pretend_txid(const uint8_t *tx, size_t len, uint8_t txid[32]) { txid_of(tx, len, txid); }

size_t sim_pretend_tx(uint8_t *out, size_t cap, const gz_outpoint_t *inputs, size_t n,
                      const uint8_t *tag, size_t tag_len)
{
    size_t len = 3 + TX_INPUT_LEN * n + tag_len;
    if (n > 255 || len > cap) return 0;
    out[0] = 0;                             /* no watched script */
    out[1] = TX_INPUTS_MARK;
    out[2] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) {
        memcpy(out + 3 + TX_INPUT_LEN * i, inputs[i].txid, 32);
        for (int k = 0; k < 4; k++) out[3 + TX_INPUT_LEN * i + 32 + (size_t)k] = (uint8_t)(inputs[i].vout >> (8 * k));
    }
    if (tag_len) memcpy(out + 3 + TX_INPUT_LEN * n, tag, tag_len);
    return len;
}

static void broadcast_now(sim_t *sim, const uint8_t *tx, size_t len)
{
    chain_broadcast(sim, UINT32_MAX, (gz_bytes_t){tx, len});    /* the world: no node */
    drain(sim);
}

void sim_broadcast(sim_t *sim, const uint8_t *tx, size_t len)
{
    if (sim->failed) return;
    broadcast_now(sim, tx, len);
    if (sim->twin) broadcast_now(sim->twin, tx, len);
    check_invariants(sim);
}

static void mine_now(sim_t *sim)
{
    mine_block(sim);
    drain(sim);
}

void sim_mine_block(sim_t *sim)
{
    if (sim->failed) return;
    mine_now(sim);
    if (sim->twin) mine_now(sim->twin);
    check_invariants(sim);
}

const sim_storage_t *sim_node_storage(const sim_t *sim, uint32_t index) { return &sim->slots[index].storage; }
size_t sim_storage_count(const sim_storage_t *storage) { return storage->n_durable; }
gz_batch_id_t sim_storage_batch_id(const sim_storage_t *storage, size_t i) { return storage->durable[i].id; }
size_t sim_storage_pending(const sim_storage_t *storage) { return storage->n_pending; }
size_t sim_storage_unconfirmed(const sim_storage_t *storage) { return storage->n_durable - storage->next_confirm; }
uint64_t sim_storage_incarnation(const sim_storage_t *storage) { return storage->reader_incarnation; }
int sim_storage_restored(const sim_storage_t *storage) { return storage->reader_restored; }

const uint8_t *sim_storage_batch_bytes(const sim_storage_t *storage, size_t i, size_t *len)
{
    if (len) *len = storage->durable[i].blob.len;
    return storage->durable[i].blob.bytes;
}
