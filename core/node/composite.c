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

/* The worst list one event fills: the node part's worst step, both test
 * engines (a peer event reaches both), every slot's engine (a message reaches
 * one slot's lobby, R3, a listing at most NP_MAX_LISTED, but a chain report
 * reaches every engine in a watch's set, which can be all the slots), the
 * composite's cancels of a freed slot's timers, and the record array of a
 * bracket's merge. */
#define LIST_ACTIONS_NEEDED (NP_MAX_STEP_ACTIONS + GZ_NODE_N_TEST * TE_MAX_STEP_ACTIONS + \
                             GZ_NODE_MAX_SLOTS * TS_MAX_STEP_ACTIONS + SLOT_MAX_TIMERS + LS_MAX_STEP_ACTIONS + \
                             GZ_NODE_MAX_SLOTS * 4 + SG_MAX_STEP_ACTIONS + \
                             GZ_FUND_MAX_STEP_ACTIONS)
/* With the signing engine's worst step: an event reaches it and at most one
 * lobby (a message, a tick, an outcome; or a lobby's start and its begin). */
#define LIST_BYTES_NEEDED (NP_MAX_STEP_BYTES + GZ_NODE_N_TEST * TE_MAX_STEP_BYTES + \
                           GZ_NODE_MAX_SLOTS * TS_MAX_STEP_BYTES + GZ_ACTION_MERGE_BYTES(GZ_NODE_LIST_ACTIONS) + \
                           LS_MAX_STEP_BYTES + GZ_NODE_MAX_SLOTS * 8192u + SG_MAX_STEP_BYTES + \
                           GZ_FUND_MAX_STEP_BYTES)
_Static_assert(NP_MAX_LISTED <= GZ_NODE_MAX_SLOTS, "a listing reaches no more engines than there are slots");
_Static_assert(LIST_ACTIONS_NEEDED <= GZ_NODE_LIST_ACTIONS, "GZ_NODE_LIST_ACTIONS below the engines' worst steps");
_Static_assert(LIST_BYTES_NEEDED <= GZ_NODE_LIST_BYTES, "GZ_NODE_LIST_BYTES below the engines' worst steps");
_Static_assert(ENG_N <= 16, "a confirmation mask has one bit per engine");
_Static_assert(GZ_NODE_LIST_ACTIONS <= 127 * 1024, "owner indices");

size_t gz_node_size(void)
{
    return sizeof(gz_node_t);
}

size_t gz_node_sign_size(void)
{
    return sizeof(sg_mem_t);
}

gz_status_t gz_node_init(gz_node_t *c, const gz_ports_t *ports, const gz_node_config_t *cfg, uint64_t incarnation)
{
    if (!c || !ports || !cfg || !ports->random.fill || !ports->clock.now_ms || !ports->clock.mono_ms)
        return GZ_ERR_ARGUMENT;
    if (cfg->test_engines > GZ_NODE_N_TEST) return GZ_ERR_ARGUMENT;
    memset(c, 0, sizeof *c);
    c->ports = *ports;
    c->cfg = *cfg;
    c->incarnation = incarnation;
    c->n_test = (int)cfg->test_engines;
    c->err_status = GZ_OK;
    c->tip = cfg->tip;
    for (int i = 0; i < NP_MAX_CONNS; i++) c->np.conns[i].slot = -1;
    gz_status_t sst = gz_sg_init(c);   /* the signing engine, with a secp256k1 context */
    if (sst != GZ_OK) return sst;
    if ((sst = gz_fd_init(c)) != GZ_OK) return sst;   /* the funding engine, beside it (P4.6) */
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
    c->n_sq = 0;
    c->sg_touched = 0;
    c->sg_defer = 0;
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
    if (area == GZ_AREA_API) return gz_api_load(c, rec);
    /* A Lobby record goes to the slot its scope names (7.3). */
    if (area == GZ_AREA_LOBBY) return gz_ls_load_record(c, rec);
    /* A Round record to the signing engine, which finds its lobby by scope. */
    if (area == GZ_AREA_ROUND && c->sign_on) return gz_sign_load(c->sign, rec, at);
    if (area == GZ_AREA_FUNDING && c->fund_on) return gz_fund_load(c->fund, rec, at);
#ifdef GZ_TEST_KINDS
    if (area == 0x7e5au) return gz_ss_load(c, rec); /* the signing stand-in's */
#endif
#ifdef GZ_TEST_KINDS
    for (int i = 0; i < c->n_test; i++)
        if (c->test[i].area == area) return gz_te_ops()->load(&c->test[i], rec, at);
    /* The slot stand-in's records: its slots are not kept across a start. */
    if (area == GZ_AREA_TEST_SLOT) return GZ_OK;
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
    if (c->sign_on) gz_sign_load_begin(c->sign);
    while (storage->next(storage->ctx, &batch)) {
        if (!id_after(previous, batch.id) || batch.id.sequence == 0 || batch.id.incarnation > storage->incarnation)
            return GZ_ERR_CORRUPT;
        if (batch.id.incarnation < storage->incarnation && id_after(c->fence, batch.id)) return GZ_ERR_CORRUPT;
        previous = batch.id;
        /* The newest batch storage holds, whatever areas its records are of
         * (the `restored` record names its incarnation). */
        c->np.newest_incarnation = batch.id.incarnation;
        for (size_t i = 0; i < batch.n_records; i++) {
            gz_status_t st = load_record(c, &batch.records[i], batch.id);
            if (st != GZ_OK) return st;
        }
    }
    {
        gz_status_t st = gz_api_loaded(c);
        if (st != GZ_OK) return st;
    }
    c->loaded = 1;
    c->restored = storage->restored;
    if (c->restored) np_guard_file(c, storage->guard);
    return GZ_OK;
}

/* Phase 2's order (10): the restore batch, the node part, the test engines,
 * then the view (each engine emits its own view objects in its resume). */
enum { R_RESTORE = 0, R_NODE, R_SIGN, R_SLOT0, R_SLOT_LAST = R_SLOT0 + GZ_NODE_MAX_SLOTS - 1, R_FUND, R_TEST0, R_TEST1, R_VIEW, R_DONE };

static gz_status_t resume_step(gz_node_t *c, gz_action_list_t *out, int *finished)
{
    gz_status_t st;
    int more = 0;
    *finished = 0;
    /* The lobbies, one slot a call (10, step 6): SET_SEATED for every seat,
     * CONNECT, the timers, the hand-off again for a check still in Signing.
     * A slot loaded at this start takes its confirmations from here on, the
     * ones held for it first (7.5, T-P42-4). */
    if (c->resume_at >= R_SLOT0 && c->resume_at <= R_SLOT_LAST) {
        int i = c->resume_at - R_SLOT0, e = ENG_SLOT0 + i;
        c->resume_at++;
        if (c->slots[i].state == SLOT_LEFT_OUT) return gz_ls_left_out_note(c, i, out);
        if (c->slots[i].state != SLOT_OPEN || c->slots[i].kind != SLOT_KIND_LOBBY) return GZ_OK;
        /* From its resume on, a saved pause acts on it (lobbyslot.c, pause_apply):
         * after its CONNECT, before it can join, ready or sign anything. */
        c->slots[i].awake = 1;
        if ((st = gz_c_resume(c, e, out, &more)) != GZ_OK) return st;
        if (c->slots[i].state != SLOT_OPEN) return GZ_OK; /* its lobby was over: closed in that step */
        c->resumed[e] = 1;
        return gz_c_release_held(c, e, out);
    }
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
        if ((st = gz_api_resume(c, out)) != GZ_OK) return st; /* local ids for slots without one; held lobbies gone */
        if ((st = gz_c_node_bracket_end(c, out)) != GZ_OK) return st;
        c->resumed[ENG_NODE] = 1;
        c->resume_at = R_SIGN;
        return GZ_OK;
    case R_SIGN:
        /* Signing before the lobbies (10): an attempt found unfinished is
         * failed first, so its lobby hands nothing over again; a member
         * answers per item (S2). One round a call. In test builds the
         * stand-in's rounds too. */
#ifdef GZ_TEST_KINDS
        if ((st = gz_ss_resume(c, out, &more)) != GZ_OK) return st;
        if (more) return GZ_OK;
#endif
        if (c->sign_on && !c->resumed[ENG_SIGN]) {
            if ((st = gz_c_resume(c, ENG_SIGN, out, &more)) != GZ_OK) return st;
            if (more) return GZ_OK;
            c->resumed[ENG_SIGN] = 1;
            gz_sg_started(c);
            if ((st = gz_c_release_held(c, ENG_SIGN, out)) != GZ_OK) return st;
        }
        c->resume_at = R_SLOT0;
        return GZ_OK;
    case R_FUND:
        /* Funding after the lobbies (funding.md 7: the start's step 7). */
        if (c->fund_on && !c->resumed[ENG_FUNDING]) {
            if ((st = gz_c_resume(c, ENG_FUNDING, out, &more)) != GZ_OK) return st;
            if (more) return GZ_OK;
            c->resumed[ENG_FUNDING] = 1;
            if ((st = gz_c_release_held(c, ENG_FUNDING, out)) != GZ_OK) return st;
        }
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
    case R_VIEW: {
        /* 9. View (node rule 7): every object, over several calls. */
        int done = 0;
        if ((st = gz_view_start(c, out, &done)) != GZ_OK) return st;
        if (done) c->resume_at++;
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
    /* Outcomes the signing engine reported to a lobby that was calling it (U1). */
    if (st == GZ_OK && c->n_sq) st = gz_sg_drain(c, out);
    if (st == GZ_WAITING && out->count == m.count) return GZ_WAITING;
    /* "Wait" after appending something is no answer a caller can act on: an
     * engine's bug, and the node says so. */
    if (st == GZ_WAITING) st = gz_c_bug(c, ENG_NODE);
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
    case GZ_CHAIN_TIP_SYNCED:   /* to whoever takes tips */
        /* The tip the signing engine's builder and may_ack judge from (the
         * signing engine itself takes no tips); funding (P4.5) and test.
         * Lobbies take no tips. */
        c->tip = ev->u.chain.height;
        for (int e = ENG_TEST0; e < ENG_TEST0 + c->n_test && st == GZ_OK; e++) st = gz_c_bracket(c, e, ev, out);
        if (st == GZ_OK && c->fund_on) st = gz_c_bracket(c, ENG_FUNDING, ev, out);
        /* A member's signing engine: C11's funding deadline of its Complete rounds (review B of PR 81, B-1). */
        if (st == GZ_OK && c->sign_on && !c->cfg.host) st = gz_c_bracket(c, ENG_SIGN, ev, out);   /* RULE-NODE:TIP_TO_SIGNING */
        /* A host lobby whose automatic start waits for funds is asked again (review B of #55, M-1). */
        if (st == GZ_OK && c->cfg.host) st = gz_ls_funds_recheck(c, out);
        return st;
    case GZ_CHAIN_TX_CONFIRMED:
    case GZ_CHAIN_TX_UNCONFIRMED:
    case GZ_CHAIN_OUTPOINT_SPENT:
    case GZ_CHAIN_WATCH_SYNCED:   /* routed by its watch, like a report */
    case GZ_CHAIN_WATCH_FAILED:
    case GZ_CHAIN_WATCH_PENDING:
        mask = gz_watch_mask(c, &ev->u.chain);
        for (int e = ENG_TEST0; e < ENG_N && st == GZ_OK; e++) {
            /* A slot's engine only while its slot is Open (its bit left the
             * registry when it closed: the second guard). */
            if (e >= ENG_SLOT0 && c->slots[e - ENG_SLOT0].state != SLOT_OPEN) continue;
            if (mask & (1u << e)) st = gz_c_bracket(c, e, ev, out);
        }
        return st;
    case GZ_CHAIN_BROADCAST_RESULT: /* the funding engine's (P4.5) */
        if (c->fund_on) return gz_c_bracket(c, ENG_FUNDING, ev, out);
        break;
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
    gz_timer_note(c, eng, ev->u.timer.timer_id, 0); /* fired: no longer set */
    if (eng == ENG_NODE) return np_timer(c, id, out);
    gz_event_t own = *ev;
    own.u.timer.timer_id = id; /* the engine gets its own id back */
    return gz_c_bracket(c, eng, &own, out);
}

static gz_status_t on_command(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    gz_bytes_t v, cmd = ev->u.user.bytes;
    uint16_t code = 0;
    if (gz_rec_find(cmd, GZ_CMD_REC_COMMAND, &v) == 1 && v.len == 2) code = gz_get_u16(v.data);
    /* An API request's id, and the pause, first (api.c); then the API's own. */
    if (code && (GZ_CMD_RANGE(code) == GZ_CMD_RANGE_LOBBY || GZ_CMD_RANGE(code) == GZ_CMD_RANGE_NODE ||
                 GZ_CMD_RANGE(code) == GZ_CMD_RANGE_API)) {
        int done = 0;
        gz_status_t st = gz_api_precheck(c, code, cmd, out, &done);
        if (st != GZ_OK || done) return st;
    }
    if (code && GZ_CMD_RANGE(code) == GZ_CMD_RANGE_API) return gz_api_command(c, code, cmd, out);
    /* The funding engine's (0x03xx: the person's confirm). */
    if (code && (code >> 8) == 0x03u && c->fund_on) return gz_c_bracket(c, ENG_FUNDING, ev, out);
    /* The lobby's commands and the signing gate's (lobbyslot.c). */
    if (code && (GZ_CMD_RANGE(code) == GZ_CMD_RANGE_LOBBY || GZ_CMD_RANGE(code) == GZ_CMD_RANGE_NODE))
        return np_command(c, code, cmd, out);
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
    /* Outcomes the signing engine reported to a lobby that was calling it (U1). */
    if (st == GZ_OK && c->n_sq) st = gz_sg_drain(c, out);
    if (st != GZ_OK) return fail(c, out, &m, st);
    return GZ_OK;
}
