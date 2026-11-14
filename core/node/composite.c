/* The composite node (docs/notes/composite-node.md): gz_node_init,
 * gz_node_start and gz_node_handle in front of the engines.
 *
 * ERRORS (8.2). The engines share one runner, one guard and one key table,
 * so an error in any engine is fatal for the whole node. The composite rolls
 * the list back to its length before the call, so nothing of that step is
 * submitted, and poisons itself: every later call returns GZ_ERR_FAILED. By
 * the engine rule (node.h) only a bug can get here.
 *
 * SIZING (8.3). Before a call the composite checks that the list has room
 * for GZ_NODE_LIST_ACTIONS actions and GZ_NODE_LIST_BYTES bytes; that is the
 * sum of the worst steps of the engines one event can reach, plus the
 * composite's own actions and a merge's record array (static assertions
 * below), so a list is never too small in the middle of a step. */
#include "internal.h"
#include <string.h>

gz_status_t gz_c_resume(gz_node_t *c, int eng, gz_action_list_t *out, int *more);
gz_status_t gz_c_release_held(gz_node_t *c, int eng, gz_action_list_t *out);

/* The worst list one event fills: the node part, both test engines (a peer
 * event reaches both), one slot's engine (an event reaches at most one
 * slot's lobby, R3), the composite's cancels of a freed slot's timers, and
 * the record array of a bracket's merge. */
#define LIST_ACTIONS_NEEDED (NP_MAX_STEP_ACTIONS + GZ_NODE_N_TEST * TE_MAX_STEP_ACTIONS + \
                             NP_MAX_LISTED * TS_MAX_STEP_ACTIONS + SLOT_MAX_TIMERS)
#define LIST_BYTES_NEEDED (NP_MAX_STEP_BYTES + GZ_NODE_N_TEST * TE_MAX_STEP_BYTES + \
                           NP_MAX_LISTED * TS_MAX_STEP_BYTES + GZ_ACTION_MERGE_BYTES(GZ_NODE_LIST_ACTIONS))
_Static_assert(LIST_ACTIONS_NEEDED <= GZ_NODE_LIST_ACTIONS, "GZ_NODE_LIST_ACTIONS below the engines' worst steps");
_Static_assert(LIST_BYTES_NEEDED <= GZ_NODE_LIST_BYTES, "GZ_NODE_LIST_BYTES below the engines' worst steps");
_Static_assert(ENG_N <= 16, "a confirmation mask has one bit per engine");
_Static_assert(GZ_NODE_LIST_ACTIONS <= 127 * 1024, "owner indices");

size_t gz_node_size(void)
{
    return sizeof(gz_node_t);
}

gz_status_t gz_node_init(gz_node_t *c, const gz_ports_t *ports, const gz_node_config_t *cfg, uint64_t incarnation)
{
    if (!c || !ports || !cfg || !ports->random.fill || !ports->clock.now_ms) return GZ_ERR_ARGUMENT;
    if (cfg->test_engines > GZ_NODE_N_TEST) return GZ_ERR_ARGUMENT;
    memset(c, 0, sizeof *c);
    c->ports = *ports;
    c->cfg = *cfg;
    c->incarnation = incarnation;
    c->n_test = (int)cfg->test_engines;
    c->err_status = GZ_OK;
    for (int i = 0; i < NP_MAX_CONNS; i++) c->np.conns[i].slot = -1;
#ifdef GZ_TEST_KINDS
    te_hooks_t hooks = {c, gz_c_handoff, gz_c_handoff_now};
    for (int i = 0; i < c->n_test; i++) {
        gz_status_t st = te_init(&c->test[i], (uint16_t)(GZ_AREA_TEST + (unsigned)i), cfg->host, ports, &cfg->keys,
                                 &hooks, incarnation);
        if (st != GZ_OK) return st;
    }
#endif
    return GZ_OK;
}

uint16_t gz_node_error_area(const gz_node_t *c)
{
    return c ? c->err_area : 0;
}

gz_status_t gz_node_error_status(const gz_node_t *c)
{
    return c ? c->err_status : GZ_ERR_ARGUMENT;
}

static int room(const gz_action_list_t *out)
{
    return out->n_slots >= out->count && out->n_slots - out->count >= GZ_NODE_LIST_ACTIONS &&
           out->n_bytes >= out->used && out->n_bytes - out->used >= GZ_NODE_LIST_BYTES;
}

/* Begin a call: what rollback needs. */
typedef struct {
    size_t count, used, cq_head, cq_n;
} mark_t;

static mark_t begin(gz_node_t *c, gz_action_list_t *out)
{
    mark_t m = {out->count, out->used, c->cq_head, c->cq_n};
    c->base = out->count;
    memset(c->owner, -1, sizeof c->owner);
    c->bracket_on = 0;
    c->n_deferred = 0;
    c->nested_bytes = 0;
    memset(c->busy, 0, sizeof c->busy);
    return m;
}

/* An error: roll the list back and poison the node (8.2). */
static gz_status_t fail(gz_node_t *c, gz_action_list_t *out, const mark_t *m, gz_status_t st)
{
    out->count = m->count;
    out->used = m->used;
    c->cq_head = m->cq_head;
    c->cq_n = m->cq_n;
    c->poisoned = 1;
    c->err_status = st;
    if (!c->err_area) c->err_area = (uint16_t)GZ_AREA_NODE;
    return st;
}

/* ---- the start ---------------------------------------------------------- */

static int id_after(gz_batch_id_t a, gz_batch_id_t b)
{
    return b.incarnation > a.incarnation || (b.incarnation == a.incarnation && b.sequence > a.sequence);
}

/* Give a record to the engines that read its area (7.3: one writer per
 * type; each engine reads its own area). An area no engine reads stops the
 * start: every Slice 1 type is even. */
static gz_status_t load_record(gz_node_t *c, const gz_record_t *rec, gz_batch_id_t at)
{
    uint16_t area = (uint16_t)(rec->type >> 16);
    if (area == GZ_AREA_NODE) return np_load(c, rec, at);
#ifdef GZ_TEST_KINDS
    for (int i = 0; i < c->n_test; i++)
        if (c->test[i].area == area) return gz_te_ops()->load(&c->test[i], rec, at);
#endif
    return GZ_ERR_CORRUPT;
}

/* Phase 1 (10): the fence, then one walk of storage. */
static gz_status_t load(gz_node_t *c, const gz_storage_reader_t *storage)
{
    gz_stored_batch_t batch;
    gz_batch_id_t previous = {0, 0};
    if (!c->fenced) {
        /* Storage now holds all an earlier program will ever have (ports.h). */
        storage->rewind(storage->ctx);
        while (storage->next(storage->ctx, &batch))
            if (batch.id.incarnation < storage->incarnation) c->fence = batch.id;
        c->fenced = 1;
    }
    storage->rewind(storage->ctx);
    while (storage->next(storage->ctx, &batch)) {
        if (!id_after(previous, batch.id) || batch.id.sequence == 0 || batch.id.incarnation > storage->incarnation)
            return GZ_ERR_CORRUPT;
        if (batch.id.incarnation < storage->incarnation && id_after(c->fence, batch.id)) return GZ_ERR_CORRUPT;
        previous = batch.id;
        for (size_t i = 0; i < batch.n_records; i++) {
            gz_status_t st = load_record(c, &batch.records[i], batch.id);
            if (st != GZ_OK) return st;
        }
    }
    c->loaded = 1;
    c->restored = storage->restored;
    return GZ_OK;
}

/* Phase 2's order (10): the restore batch, the node part, the test engines,
 * then the view (each engine emits its own view objects in its resume). */
enum { R_RESTORE = 0, R_NODE, R_TEST0, R_TEST1, R_DONE };

static gz_status_t resume_step(gz_node_t *c, gz_action_list_t *out, int *finished)
{
    gz_status_t st;
    int more = 0;
    *finished = 0;
    switch (c->resume_at) {
    case R_RESTORE:
        if (c->restored && !c->resume_restore_done) {
            if ((st = gz_c_node_bracket_begin(c, out)) != GZ_OK) return st;
            if ((st = np_restore_batch(c, out)) != GZ_OK) return st;
            if ((st = gz_c_node_bracket_end(c, out)) != GZ_OK) return st;
            c->resume_restore_done = 1;
        }
        c->resume_at = R_NODE;
        return GZ_OK;
    case R_NODE:
        if ((st = gz_c_node_bracket_begin(c, out)) != GZ_OK) return st;
        if ((st = np_resume(c, out)) != GZ_OK) return st;
        if ((st = gz_c_node_bracket_end(c, out)) != GZ_OK) return st;
        c->resumed[ENG_NODE] = 1;
        c->resume_at = R_TEST0;
        return GZ_OK;
    case R_TEST0:
    case R_TEST1: {
        int e = ENG_TEST0 + (c->resume_at - R_TEST0);
        if (e - ENG_TEST0 >= c->n_test) {
            c->resume_at++;
            return GZ_OK;
        }
        st = gz_c_resume(c, e, out, &more);
        if (st != GZ_OK) return st;
        if (!more) {
            c->resumed[e] = 1;
            if ((st = gz_c_release_held(c, e, out)) != GZ_OK) return st;
            c->resume_at++;
        }
        return GZ_OK;
    }
    default:
        *finished = 1;
        return GZ_OK;
    }
}

gz_status_t gz_node_start(gz_node_t *c, const gz_storage_reader_t *storage, gz_action_list_t *out, int *more)
{
    gz_status_t st = GZ_OK;
    int finished = 0;
    if (!c || !storage || !storage->next || !storage->rewind || !out || !more) return GZ_ERR_ARGUMENT;
    if (c->poisoned) return GZ_ERR_FAILED;
    if (!room(out)) return GZ_ERR_NO_SPACE;
    mark_t m = begin(c, out);
    if (c->started) {
        *more = 0;
        return GZ_OK;
    }
    if (!c->loaded) {
        st = load(c, storage);
    } else if (c->fenced) {
        /* A later step: storage may only have gained this incarnation's
         * batches (the fence). */
        gz_stored_batch_t batch;
        storage->rewind(storage->ctx);
        while (st == GZ_OK && storage->next(storage->ctx, &batch))
            if (batch.id.incarnation < storage->incarnation && id_after(c->fence, batch.id)) st = GZ_ERR_CORRUPT;
    }
    /* One engine's resume per call: on until one appends something. */
    while (st == GZ_OK && out->count == m.count && !finished) {
        st = resume_step(c, out, &finished);
        /* The restore batch is alone in its list (node.h rule 5). */
        if (st == GZ_OK && c->resume_at == R_NODE && out->count > m.count) break;
    }
    if (st == GZ_WAITING && out->count == m.count) return GZ_WAITING;
    if (st != GZ_OK) return fail(c, out, &m, st);
    if (finished) c->started = 1;
    *more = !finished;
    return GZ_OK;
}

/* ---- events ------------------------------------------------------------- */

static gz_status_t on_chain(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    gz_status_t st = GZ_OK;
    uint16_t mask;
    switch (ev->u.chain.kind) {
    case GZ_CHAIN_NEW_TIP:
        /* Signing, funding (P4.3, P4.5) and test. Lobbies take no tips. */
        for (int e = ENG_TEST0; e < ENG_TEST0 + c->n_test && st == GZ_OK; e++) st = gz_c_bracket(c, e, ev, out);
        return st;
    case GZ_CHAIN_TX_CONFIRMED:
    case GZ_CHAIN_TX_UNCONFIRMED:
    case GZ_CHAIN_OUTPOINT_SPENT:
        mask = gz_watch_mask(c, &ev->u.chain);
        for (int e = ENG_TEST0; e < ENG_N && st == GZ_OK; e++)
            if (mask & (1u << e)) st = gz_c_bracket(c, e, ev, out);
        return st;
    case GZ_CHAIN_BROADCAST_RESULT: /* the funding engine's (P4.5) */
    case GZ_CHAIN_SCRIPT_SPENT:     /* retired */
        break;
    }
    if ((st = gz_c_node_bracket_begin(c, out)) != GZ_OK) return st;
    if ((st = np_drop(c, DROP_NO_ENGINE, 0, out)) != GZ_OK) return st;
    return gz_c_node_bracket_end(c, out);
}

static gz_status_t on_timer(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    int eng = -1;
    uint32_t id;
    gz_status_t st;
    if (!gz_timer_route(c, ev->u.timer.timer_id, &eng, &id)) {
        if ((st = gz_c_node_bracket_begin(c, out)) != GZ_OK) return st;
        if ((st = np_drop(c, DROP_TIMER, 0, out)) != GZ_OK) return st;
        return gz_c_node_bracket_end(c, out);
    }
    if (eng == ENG_NODE) return np_timer(c, id, out);
    if (eng >= ENG_SLOT0) gz_timer_track(&c->slots[eng - ENG_SLOT0], ev->u.timer.timer_id, 0);
    gz_event_t own = *ev;
    own.u.timer.timer_id = id; /* the engine gets its own id back */
    return gz_c_bracket(c, eng, &own, out);
}

static gz_status_t on_command(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    gz_bytes_t v, cmd = ev->u.user.bytes;
    uint16_t code = 0;
    if (gz_rec_find(cmd, GZ_CMD_REC_COMMAND, &v) == 1 && v.len == 2) code = gz_get_u16(v.data);
    (void)code;
#ifdef GZ_TEST_KINDS
    if (code && GZ_CMD_RANGE(code) == GZ_CMD_RANGE_TEST) {
        if (code >= 0x7e80) return np_command(c, code, cmd, out);
        uint16_t area = (uint16_t)GZ_AREA_TEST;
        if (gz_rec_find(cmd, GZ_CMD_REC_ARGS, &v) == 1 && v.len == 2) area = gz_get_u16(v.data);
        for (int i = 0; i < c->n_test; i++)
            if (c->test[i].area == area) return gz_c_bracket(c, ENG_TEST0 + i, ev, out);
    }
#endif
    /* No engine takes it: unknown_command, never an error. */
    return np_command(c, 0, cmd, out);
}

static gz_status_t dispatch(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    gz_status_t st;
    switch (ev->kind) {
    case GZ_EVENT_MESSAGE_RECEIVED: return np_message(c, ev, out);
    case GZ_EVENT_PEER_CONNECTED:
    case GZ_EVENT_PEER_DISCONNECTED: return np_peer(c, ev, out);
    case GZ_EVENT_TIMER_FIRED: return on_timer(c, ev, out);
    case GZ_EVENT_CHAIN: return on_chain(c, ev, out);
    case GZ_EVENT_USER_COMMAND: return on_command(c, ev, out);
    case GZ_EVENT_STORAGE_CONFIRMED:
        gz_c_confirmed(c, out, &st);
        return st;
    }
    return GZ_OK;
}

gz_status_t gz_node_handle(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    if (!c || !ev || !out) return GZ_ERR_ARGUMENT;
    if (c->poisoned) return GZ_ERR_FAILED;
    if (!room(out)) return GZ_ERR_NO_SPACE;
    /* While it starts, a node takes only its storage confirmations (node.h). */
    if (!c->started && ev->kind != GZ_EVENT_STORAGE_CONFIRMED) return GZ_ERR_ARGUMENT;
    mark_t m = begin(c, out);
    gz_status_t st = dispatch(c, ev, out);
    if (st != GZ_OK) return fail(c, out, &m, st);
    return GZ_OK;
}
