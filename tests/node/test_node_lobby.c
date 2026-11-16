/* The lobby in the composite (composite-node.md, step P4.2): whole nodes, a
 * host and its members, each a composite with real lobbies in its slots and
 * the signing stand-in behind the hand-off, wired to each other in one
 * process. What a node SENDs is delivered to its peer as a message, a
 * CONNECT brings a connection up on both sides, timers fire when the clock
 * reaches them, and every save is durable at once.
 *
 * Every case asserts outcomes: the states the lobbies reach, what storage
 * holds, what a peer is sent. And in every case no call of any node returns
 * an error (the engine rule). */
#include "node_test.h"
#include "../lobby/lobby_test.h"
#include "internal.h"

#define NN 7                    /* node 0 is the host; 1 to 5 members; 6 a scratch node */
#define SCRATCH 6
#define W_NOW0 1794441000000ull /* ten minutes before T1's deadline */
#define ADDR "192.0.2.1:9735"   /* a documentation address: nothing is dialled here */

typedef struct {
    int to;
    gz_link_t link;             /* as the receiver names it */
    uint16_t kind;
    uint8_t scope[32];
    uint8_t *rec;
    size_t len;
} wmsg_t;
typedef struct { uint64_t id, at; } wtimer_t;
typedef struct {
    int used, up, wanted, node;
    gz_link_t mlink;            /* the member's side: (its key, the host's) */
    uint32_t epoch, index;
} wconn_t;
typedef struct { int node; uint16_t kind; uint8_t to[33], scope[32]; uint8_t rec[512]; size_t len; } wsent_t;

static h_t N[NN];
static int IDENT[NN], ALIVE[NN], PUB_FAIL[NN], SIGN_FAIL[NN], FORGETS[NN];
static wmsg_t Q[8192];
static size_t NQ;
static wtimer_t T[NN][64];
static int NT[NN];
static wconn_t C[64];
static wsent_t SENT[4096];
static size_t NSENT;
static uint64_t NOW;
static int ERRORS;
static int UNSEATS[NN];         /* SET_SEATED 0 actions of each node */

/* ---- keys ------------------------------------------------------------------ */

static int node_of(void *ctx) { return (int)((h_t *)ctx - N); }

static void wkey(int ident, uint32_t epoch, uint32_t index, lt_key_t *k)
{
    char l[64];
    snprintf(l, sizeof l, "node %d epoch %u index %u", ident, (unsigned)epoch, (unsigned)index);
    lt_key(k, l);
}

static void whost(lt_key_t *k) { lt_key(k, "node 0 host key"); }

static int w_pub(void *ctx, uint32_t epoch, uint32_t index, uint8_t pub[33])
{
    lt_key_t k;
    int n = node_of(ctx);
    if (PUB_FAIL[n]) return 0;
    wkey(IDENT[n], epoch, index, &k);
    memcpy(pub, k.pub, 33);
    return 1;
}

static int w_host_pub(void *ctx, uint8_t pub[33])
{
    lt_key_t k;
    if (IDENT[node_of(ctx)] != 0) return 0;
    whost(&k);
    memcpy(pub, k.pub, 33);
    return 1;
}

static int w_verify(void *ctx, const uint8_t pub[33], const uint8_t msg[32], const uint8_t sig[64])
{
    (void)ctx;
    return lt_verify(NULL, pub, msg, sig);
}

static int w_point(void *ctx, const uint8_t pub[33]) { return lt_point_ok(ctx, pub); }

static int w_sign(void *ctx, int host, uint32_t epoch, uint32_t index, const uint8_t msg[32], uint8_t sig[64])
{
    static const uint8_t aux[32];
    lt_key_t k;
    int n = node_of(ctx);
    if (SIGN_FAIL[n]) return 0;
    if (host) {
        if (IDENT[n] != 0) return 0;
        whost(&k);
    } else {
        wkey(IDENT[n], epoch, index, &k);
    }
    return secp256k1_schnorrsig_sign32(lt_ctx(), sig, msg, &k.kp, aux);
}

static void w_forget(void *ctx, const uint8_t scope[32])
{
    (void)scope;
    FORGETS[node_of(ctx)]++;
}

/* ---- the world --------------------------------------------------------------- */

static wconn_t *conn_of_member_key(const uint8_t key[33])
{
    for (int i = 0; i < 64; i++)
        if (C[i].used && !memcmp(C[i].mlink.local.key, key, 33)) return &C[i];
    return NULL;
}

static void fail_node(int n, const char *what, gz_status_t st)
{
    ERRORS++;
    printf("node %d: %s returned %d (error area 0x%04x)\n", n, what, (int)st, (unsigned)gz_node_error_area(N[n].n));
}

/* What node `n` did since log entry `from`: its sends go on their way, its
 * CONNECTs and DISCONNECTs change the connections, its timers are kept. The
 * payloads are still in the node's list here. */
static void post(int n, size_t from)
{
    h_t *h = &N[n];
    lt_key_t hk;
    whost(&hk);
    for (size_t i = from; i < h->n_log; i++) {
        const gz_action_t *a = &h->log[i].a;
        if (a->kind == GZ_ACTION_SEND) {
            wconn_t *c = conn_of_member_key(n == 0 ? a->u.send.link.remote.key : a->u.send.link.local.key);
            if (NSENT < 4096 && a->u.send.records.len <= sizeof SENT[0].rec) {
                wsent_t *s = &SENT[NSENT++];
                s->node = n;
                s->kind = a->u.send.kind;
                memcpy(s->to, a->u.send.link.remote.key, 33);
                memcpy(s->scope, a->u.send.scope, 32);
                s->len = a->u.send.records.len;
                if (s->len) memcpy(s->rec, a->u.send.records.data, s->len);
            }
            if (!c || !c->up || NQ == 8192) continue; /* no connection: the program drops it */
            wmsg_t *m = &Q[NQ++];
            m->to = n == 0 ? c->node : 0;
            if (n == 0) m->link = c->mlink;
            else m->link = h_link(hk.pub, c->mlink.local.key);
            m->kind = a->u.send.kind;
            memcpy(m->scope, a->u.send.scope, 32);
            m->len = a->u.send.records.len;
            m->rec = malloc(m->len + 1);
            if (m->len) memcpy(m->rec, a->u.send.records.data, m->len);
        } else if (a->kind == GZ_ACTION_CONNECT) {
            uint8_t pub[33];
            wconn_t *c;
            int k;
            if (!w_pub(h, a->u.connect.key_epoch, a->u.connect.key_index, pub)) continue;
            if (!(c = conn_of_member_key(pub))) {
                for (k = 0; k < 64 && C[k].used; k++) {}
                if (k == 64) continue;
                c = &C[k];
                memset(c, 0, sizeof *c);
                c->used = 1;
                c->node = n;
                c->mlink = h_link(pub, a->u.connect.host.key);
                c->epoch = a->u.connect.key_epoch;
                c->index = a->u.connect.key_index;
            }
            c->wanted = 1;
        } else if (a->kind == GZ_ACTION_DISCONNECT) {
            wconn_t *c = conn_of_member_key(n == 0 ? a->u.disconnect.link.remote.key : a->u.disconnect.link.local.key);
            if (!c) continue;
            if (n != 0) c->wanted = 0; /* the member's CONNECT stands no longer */
            if (c->up) c->up = -1;     /* reported down to both sides at the next turn */
        } else if (a->kind == GZ_ACTION_SET_SEATED) {
            if (!a->u.set_seated.seated) UNSEATS[n]++;
        } else if (a->kind == GZ_ACTION_SET_TIMER) {
            int k;
            for (k = 0; k < NT[n] && T[n][k].id != a->u.set_timer.timer_id; k++) {}
            if (k == NT[n] && NT[n] < 64) NT[n]++;
            if (k < 64) {
                T[n][k].id = a->u.set_timer.timer_id;
                T[n][k].at = NOW + a->u.set_timer.delay_ms;
            }
        } else if (a->kind == GZ_ACTION_CANCEL_TIMER) {
            for (int k = 0; k < NT[n]; k++)
                if (T[n][k].id == a->u.cancel_timer.timer_id) T[n][k--] = T[n][--NT[n]];
        }
    }
}

/* Storage is fast here: every batch is confirmed at once, in order. */
static void confirm(int n)
{
    h_t *h = &N[n];
    while (h->n_pending && ALIVE[n]) {
        gz_event_t ev;
        size_t mark = h->n_log;
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_STORAGE_CONFIRMED;
        ev.u.storage.batch = h->pending[0];
        memmove(h->pending, h->pending + 1, (--h->n_pending) * sizeof h->pending[0]);
        if (h_handle_raw(h, &ev) != GZ_OK) {
            fail_node(n, "a confirmation", h->last);
            return;
        }
        post(n, mark);
    }
}

static gz_status_t w_event(int n, const gz_event_t *ev)
{
    h_t *h = &N[n];
    size_t mark;
    if (!ALIVE[n]) return GZ_OK;
    if (h->n_log > H_MAX_LOG - 2000) h->n_log = 0; /* the log is a window: long runs start it again */
    mark = h->n_log;
    h->clock = NOW;
    if (h_handle_raw(h, ev) != GZ_OK) {
        fail_node(n, "an event", h->last);
        return h->last;
    }
    post(n, mark);
    confirm(n);
    return GZ_OK;
}

static int w_cmd(int n, uint16_t code, const h_arg_t *args, size_t na)
{
    h_t *h = &N[n];
    size_t mark = h->n_log;
    int status = 0;
    h->clock = NOW;
    if (h_cmd(h, code, args, na) != GZ_OK) {
        fail_node(n, "a command", h->last);
        return -1;
    }
    for (size_t i = mark; i < h->n_log; i++)
        if (h->log[i].a.kind == GZ_ACTION_NOTIFY && !strncmp(h->log[i].text, "result ", 7)) status = atoi(h->log[i].text + 7);
    post(n, mark);
    confirm(n);
    return status;
}

static void w_peer(int n, const gz_link_t *l, int up, int outbound, uint32_t epoch, uint32_t index)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = up ? GZ_EVENT_PEER_CONNECTED : GZ_EVENT_PEER_DISCONNECTED;
    ev.u.peer.link = *l;
    ev.u.peer.outbound = outbound;
    ev.u.peer.key_epoch = epoch;
    ev.u.peer.key_index = index;
    w_event(n, &ev);
}

static void w_msg(int n, const gz_link_t *l, uint16_t kind, const uint8_t scope[32], const uint8_t *rec, size_t len)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_MESSAGE_RECEIVED;
    ev.u.message.link = *l;
    ev.u.message.kind = kind;
    memcpy(ev.u.message.scope, scope, 32);
    ev.u.message.records.data = rec;
    ev.u.message.records.len = len;
    w_event(n, &ev);
}

/* One turn: connections, messages in order, timers. */
static void w_turn(void)
{
    lt_key_t hk;
    whost(&hk);
    for (int i = 0; i < 64; i++) {
        wconn_t *c = &C[i];
        gz_link_t hl;
        if (!c->used) continue;
        hl = h_link(hk.pub, c->mlink.local.key);
        if (c->up == -1) {
            c->up = 0;
            for (size_t k = 0; k < NQ; k++) /* a connection's messages die with it */
                if (Q[k].rec && (!memcmp(&Q[k].link, &hl, sizeof hl) || !memcmp(&Q[k].link, &c->mlink, sizeof hl))) {
                    free(Q[k].rec);
                    Q[k].rec = NULL;
                }
            w_peer(0, &hl, 0, 0, 0, 0);
            w_peer(c->node, &c->mlink, 0, 1, c->epoch, c->index);
        }
        if (c->wanted && !c->up && ALIVE[0] && ALIVE[c->node]) {
            c->up = 1;
            w_peer(0, &hl, 1, 0, 0, 0);
            if (c->up == 1) w_peer(c->node, &c->mlink, 1, 1, c->epoch, c->index);
        }
    }
    for (size_t k = 0; k < NQ; k++) {
        wmsg_t m = Q[k];
        wconn_t *c;
        if (!m.rec) continue;
        Q[k].rec = NULL;
        c = conn_of_member_key(m.to == 0 ? m.link.remote.key : m.link.local.key);
        if (c && c->up == 1 && ALIVE[m.to]) w_msg(m.to, &m.link, m.kind, m.scope, m.rec, m.len);
        free(m.rec);
    }
    NQ = 0;
    for (int n = 0; n < NN; n++)
        for (int k = 0; k < NT[n]; k++)
            if (ALIVE[n] && T[n][k].at <= NOW) {
                gz_event_t ev;
                memset(&ev, 0, sizeof ev);
                ev.kind = GZ_EVENT_TIMER_FIRED;
                ev.u.timer.timer_id = T[n][k].id;
                T[n][k--] = T[n][--NT[n]];
                w_event(n, &ev);
            }
}

static void w_run(uint64_t ms, uint64_t step)
{
    for (uint64_t t = 0; t < ms; t += step) {
        NOW += step;
        w_turn();
        w_turn();
    }
}

/* The stepped start of node `n` on its storage. */
static gz_status_t w_start(int n)
{
    h_t *h = &N[n];
    gz_storage_reader_t rd;
    int more = 1, steps = 0;
    memset(&rd, 0, sizeof rd);
    rd.next = h_next;
    rd.rewind = h_rewind;
    rd.ctx = h;
    rd.incarnation = h->incarnation;
    h->clock = NOW;
    ALIVE[n] = 1;
    while (more && steps++ < 1000) {
        size_t mark = h->n_log;
        gz_action_list_reset(&h->list);
        gz_status_t st = gz_node_start(h->n, &rd, &h->list, &more);
        if (st == GZ_WAITING) {
            if (!h->n_pending) return st;
            confirm(n);
            continue;
        }
        if (st != GZ_OK) return st;
        h_execute(h, &h->list);
        post(n, mark);
        confirm(n);
    }
    return more ? GZ_ERR_BUG : GZ_OK;
}

static void w_node(int n, int ident, gz_member_signing_t signing, uint32_t outcome)
{
    h_t *h = &N[n];
    h_init(h, ident == 0, 0);
    IDENT[n] = ident;
    h->confirm_auto = 0;
    h->clock = NOW;
    h->clock_seen = NOW;
    h->cfg.keys.pub = w_pub;
    h->cfg.keys.host_pub = w_host_pub;
    h->cfg.keys.ctx = h;
    h->cfg.crypto.verify = w_verify;
    h->cfg.crypto.point_ok = w_point;
    h->cfg.crypto.sign = w_sign;
    h->cfg.crypto.forget = w_forget;
    h->cfg.crypto.ctx = h;
    h->cfg.member_signing = signing;
    h->cfg.test_sign_outcome = outcome;
    h->cfg.test_sign_delay_ms = 50;
    h_new_node(h);
}

static void w_reset(void)
{
    for (size_t k = 0; k < NQ; k++) free(Q[k].rec);
    NQ = 0;
    NSENT = 0;
    memset(C, 0, sizeof C);
    memset(NT, 0, sizeof NT);
    memset(ALIVE, 0, sizeof ALIVE);
    memset(PUB_FAIL, 0, sizeof PUB_FAIL);
    memset(SIGN_FAIL, 0, sizeof SIGN_FAIL);
    memset(FORGETS, 0, sizeof FORGETS);
    memset(UNSEATS, 0, sizeof UNSEATS);
    NOW = W_NOW0;
}

/* A world of a host and `members` members, each started on empty storage. */
static void w_world(int members, gz_member_signing_t signing, uint32_t outcome)
{
    w_reset();
    for (int n = 0; n <= members; n++) {
        w_node(n, n, signing, outcome);
        CHECK(w_start(n) == GZ_OK);
    }
}

static void w_free(int upto)
{
    for (int n = 0; n <= upto; n++) h_free(&N[n]);
    memset(N, 0, sizeof N);
}

/* A crash and a restart of node `n` on the same storage. */
static gz_status_t w_restart(int n)
{
    for (int i = 0; i < 64; i++) {
        wconn_t *c = &C[i];
        if (!c->used || (n != 0 && c->node != n)) continue;
        if (c->up == 1) {
            lt_key_t hk;
            gz_link_t hl;
            whost(&hk);
            hl = h_link(hk.pub, c->mlink.local.key);
            c->up = 0;
            ALIVE[n] = 0;
            if (n == 0) w_peer(c->node, &c->mlink, 0, 1, c->epoch, c->index);
            else w_peer(0, &hl, 0, 0, 0, 0);
        }
        c->up = 0;
        if (n != 0) c->wanted = 0; /* issued again at its start */
    }
    for (size_t k = 0; k < NQ; k++) {
        free(Q[k].rec);
        Q[k].rec = NULL;
    }
    NQ = 0;
    NT[n] = 0;
    h_new_node(&N[n]);
    return w_start(n);
}

/* ---- terms and commands ---------------------------------------------------------- */

typedef struct {
    uint8_t outer[512], current[128], scope[32];
    size_t on, cn;
} terms_t;

/* T1 with this world's host key, `target` seats and a deadline `plus` seconds
 * after T1's (a different lobby for each `plus`); T2 for it. */
static void make_terms(terms_t *t, uint16_t target, uint16_t minimum, uint32_t plus)
{
    uint8_t t1[512], t2[128], d1[32];
    size_t n1 = lt_unhex(LT_T1, t1, sizeof t1), n2 = lt_unhex(LT_T2, t2, sizeof t2);
    gz_terms_outer_t o;
    gz_terms_current_t c;
    lt_key_t hk;
    whost(&hk);
    CHECK(lt_outer(t1, n1, &o));
    gz_terms_outer_digest(t1, n1, d1);
    CHECK(lt_current(t2, n2, &o, d1, &c));
    memcpy(o.host_key, hk.pub, 33);
    o.target = target;
    o.minimum = minimum;
    o.deadline += plus;
    t->on = gz_terms_encode_outer(&o, t->outer, sizeof t->outer);
    CHECK(t->on > 0);
    gz_terms_outer_digest(t->outer, t->on, t->scope);
    memcpy(c.outer_digest, t->scope, 32);
    t->cn = gz_terms_encode_current(&c, t->current, sizeof t->current);
    CHECK(t->cn > 0);
}

static int host_open(const terms_t *t, int listed)
{
    uint8_t l = (uint8_t)listed;
    h_arg_t a[3] = {{12, t->outer, t->on}, {14, t->current, t->cn}, {16, &l, 1}};
    return w_cmd(0, GZ_CMD_LOBBY_OPEN, a, 3);
}

static int member_join(int n, const terms_t *t)
{
    lt_key_t hk;
    whost(&hk);
    h_arg_t a[3] = {{12, t->scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}};
    return w_cmd(n, GZ_CMD_LOBBY_JOIN, a, 3);
}

static int scope_cmd(int n, uint16_t code, const terms_t *t, int unlock)
{
    uint8_t u = 1;
    h_arg_t a[2] = {{12, t->scope, 32}, {14, &u, 1}};
    return w_cmd(n, code, a, unlock ? 2 : 1);
}

static slot_t *slot(int n, const terms_t *t)
{
    int i = gz_route_slot_by_scope(N[n].n, t->scope);
    return i >= 0 && N[n].n->slots[i].kind == SLOT_KIND_LOBBY ? &N[n].n->slots[i] : NULL;
}

static int host_state(const terms_t *t)
{
    slot_t *s = slot(0, t);
    return s ? s->lobby.h.state : -1;
}

static int host_ready(const terms_t *t)
{
    slot_t *s = slot(0, t);
    int r = 0;
    if (!s) return -1;
    for (uint16_t k = 0; k < s->lobby.h.n_seats; k++)
        r += s->lobby.h.seats[k].state == GZ_SEAT_READY && s->lobby.h.seats[k].ready_version == s->lobby.h.values.version;
    return r;
}

/* The member's round outcome as its lobby saved it (4 Funding), 0 none, -1 no slot. */
static int member_round(int n, const terms_t *t)
{
    slot_t *s = slot(n, t);
    return s ? s->lobby.m.round_state : -1;
}

static int member_ready(int n, const terms_t *t)
{
    slot_t *s = slot(n, t);
    return s ? s->lobby.m.ready : -1;
}

/* Log lines of node `n` since `from` that contain `text`. */
static int said(int n, size_t from, const char *text)
{
    int c = 0;
    for (size_t i = from; i < N[n].n_log; i++)
        if (N[n].log[i].a.kind == GZ_ACTION_NOTIFY && strstr(N[n].log[i].text, text)) c++;
    return c;
}

/* 1 if some stored batch of node `n` holds every one of `types`, in that order. */
static int batch_with(int n, const uint32_t *types, size_t nt)
{
    for (size_t i = 0; i < N[n].n_batches; i++) {
        size_t at = 0;
        for (size_t k = 0; k < N[n].batches[i].n && at < nt; k++)
            if (N[n].batches[i].recs[k].type == types[at]) at++;
        if (at == nt) return 1;
    }
    return 0;
}

static void no_errors(int upto)
{
    CHECK(ERRORS == 0);
    for (int n = 0; n <= upto; n++)
        if (ALIVE[n]) CHECK_NO_NODE_ERROR(&N[n]);
}

/* The last message of `kind` node `n` sent since SENT index `from`, decoded. */
static int last_sent(int n, size_t from, uint16_t kind, const uint8_t *to, gz_lobby_msg_t *m)
{
    int found = 0;
    for (size_t i = from; i < NSENT; i++)
        if (SENT[i].node == n && SENT[i].kind == kind && (!to || !memcmp(SENT[i].to, to, 33)) &&
            gz_lobby_decode(SENT[i].kind, SENT[i].scope, SENT[i].rec, SENT[i].len, m) == GZ_DEC_OK)
            found = 1;
    return found;
}

static int sent_count(int n, size_t from, uint16_t kind)
{
    int c = 0;
    for (size_t i = from; i < NSENT; i++) c += SENT[i].node == n && SENT[i].kind == kind;
    return c;
}

/* ---- 1. two lobbies at once, to Funding; restarts; a crash at every save -------- */

static terms_t TA, TB;

static void two_lobbies(gz_member_signing_t signing, uint32_t outcome)
{
    w_world(4, signing, outcome);
    make_terms(&TA, 3, 3, 0);
    make_terms(&TB, 3, 3, 7);
    CHECK(memcmp(TA.scope, TB.scope, 32) != 0);
    CHECK(host_open(&TA, 1) == 200 && host_open(&TB, 0) == 200);
    /* A: members 1, 2, 3. B: members 1, 2, 4. Members 1 and 2 are in both. */
    CHECK(member_join(1, &TA) == 200 && member_join(2, &TA) == 200 && member_join(3, &TA) == 200);
    CHECK(member_join(1, &TB) == 200 && member_join(2, &TB) == 200 && member_join(4, &TB) == 200);
}

static void test_two_lobbies(void)
{
    static const uint32_t first[] = {GZ_RECORD_KEY_EPOCH, GZ_RECORD_KEY_INDEX, GZ_RECORD_GUARD, GZ_RECORD_SLOT_OPENED,
                                     GZ_REC_LOBBY_OPENED};
    static const uint32_t next[] = {GZ_RECORD_KEY_INDEX, GZ_RECORD_GUARD, GZ_RECORD_SLOT_OPENED, GZ_REC_LOBBY_OPENED};
    static const uint32_t mfirst[] = {GZ_RECORD_KEY_EPOCH, GZ_RECORD_KEY_INDEX, GZ_RECORD_GUARD, GZ_RECORD_SLOT_OPENED};
    size_t batches[5], marks[5];
    two_lobbies(GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    /* The slot's first batch: the key's index and the guard before the key
     * is used, the slot and its lobby together (7.4). Exactly two batches on
     * the host so far, one per lobby. */
    CHECK(N[0].n_batches == 2 && N[0].batches[0].n == 5 && N[0].batches[1].n == 4);
    CHECK(batch_with(0, first, 5) && batch_with(0, next, 4) && batch_with(1, mfirst, 4));
    /* The guard rides with every key_index, its counter one higher each time (journal.md 8.3). */
    CHECK(N[0].batches[0].recs[2].type == GZ_RECORD_GUARD && N[0].batches[1].recs[1].type == GZ_RECORD_GUARD &&
          gz_get_u64(N[0].batches[1].recs[1].bytes.data + 40) == gz_get_u64(N[0].batches[0].recs[2].bytes.data + 40) + 1 &&
          gz_get_u64(N[0].batches[0].recs[2].bytes.data + 40) == 1);
    CHECK(h_records_of(&N[0], GZ_RECORD_KEY_EPOCH) == 1 && h_records_of(&N[1], GZ_RECORD_KEY_EPOCH) == 1);
    /* A member in two lobbies has two keys and two links. */
    /* Each lobby has its own pair: the contribution key at an index, the
     * factory key at the next; the highest index saved is the last one used. */
    CHECK(slot(0, &TA)->key_index == 1 && slot(0, &TB)->key_index == 3 && N[0].n->np.highest_index == 4);
    CHECK(slot(1, &TA)->key_index == 1 && slot(1, &TB)->key_index == 3 && N[1].n->np.highest_index == 4);
    CHECK(slot(1, &TA) && slot(1, &TB) && slot(1, &TA)->key_index != slot(1, &TB)->key_index &&
          memcmp(&slot(1, &TA)->link, &slot(1, &TB)->link, sizeof(gz_link_t)) != 0);
    w_run(3000, 100);
    CHECK(host_ready(&TA) == 3 && host_ready(&TB) == 3);
    CHECK(host_state(&TA) == GZ_LOBBY_READY_CHECK && host_state(&TB) == GZ_LOBBY_READY_CHECK);
    w_run(32000, 500); /* the ready window, the starts, the hand-off, the outcome back */
    CHECK(host_state(&TA) == GZ_LOBBY_FUNDING && host_state(&TB) == GZ_LOBBY_FUNDING);
    CHECK(member_round(1, &TA) == GZ_LOBBY_FUNDING && member_round(2, &TA) == GZ_LOBBY_FUNDING &&
          member_round(3, &TA) == GZ_LOBBY_FUNDING);
    CHECK(member_round(1, &TB) == GZ_LOBBY_FUNDING && member_round(2, &TB) == GZ_LOBBY_FUNDING &&
          member_round(4, &TB) == GZ_LOBBY_FUNDING);
    CHECK(member_round(3, &TB) == -1 && member_round(4, &TA) == -1);
    /* One hand-off per lobby on every node, and its outcome once. */
    CHECK(said(0, 0, "sign-begin scope=") == 2 && said(0, 0, "sign-outcome") == 2);
    CHECK(said(1, 0, "sign-begin scope=") == 2 && said(3, 0, "sign-begin scope=") == 1 && said(4, 0, "sign-outcome") == 1);
    /* The round's end and the lobby's Funding are one batch (rule 2). */
    {
        static const uint32_t out[] = {0x7e5a0004u, GZ_REC_LOBBY_STATE};
        CHECK(batch_with(0, out, 2) && batch_with(1, out, 2) && batch_with(4, out, 2));
    }
    CHECK(h_records_of(&N[0], GZ_RECORD_SLOT_CLOSED) == 0);
    no_errors(4);

    /* Every node restarted: nothing is lost, nothing is saved or handed over twice. */
    for (int n = 0; n <= 4; n++) {
        batches[n] = N[n].n_batches;
        marks[n] = N[n].n_log;
    }
    for (int n = 0; n <= 4; n++) CHECK(w_restart(n) == GZ_OK);
    w_run(5000, 100);
    CHECK(host_state(&TA) == GZ_LOBBY_FUNDING && host_state(&TB) == GZ_LOBBY_FUNDING);
    CHECK(member_round(1, &TA) == GZ_LOBBY_FUNDING && member_round(2, &TB) == GZ_LOBBY_FUNDING &&
          member_round(4, &TB) == GZ_LOBBY_FUNDING);
    for (int n = 0; n <= 4; n++) CHECK(N[n].n_batches == batches[n] && said(n, marks[n], "sign-begin scope=") == 0);
    {   /* a slot loaded at a start takes its confirmations once its lobby has resumed (T-P42-4) */
        int ia = gz_route_slot_by_scope(N[0].n, TA.scope), ib = gz_route_slot_by_scope(N[1].n, TB.scope);
        CHECK(ia >= 0 && N[0].n->resumed[ENG_SLOT0 + ia] == 1 && N[0].n->held[ENG_SLOT0 + ia] == 0);
        CHECK(ib >= 0 && N[1].n->resumed[ENG_SLOT0 + ib] == 1 && N[1].n->held[ENG_SLOT0 + ib] == 0);
    }
    no_errors(4);

    /* A crash at every save point of the host and of a member: the node
     * starts again on what was durable, whatever prefix that is. */
    for (int who = 0; who <= 1; who++)
        for (size_t k = 0; k <= N[who].n_batches; k++) {
            h_t *x = &N[SCRATCH];
            h_batch_t *own;
            w_node(SCRATCH, who, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
            own = x->batches;
            memcpy(own, N[who].batches, k * sizeof *own); /* the records themselves stay the other node's */
            x->n_batches = k;
            x->incarnation = N[who].incarnation + 1;
            h_new_node(x);
            CHECK(w_start(SCRATCH) == GZ_OK);
            CHECK_NO_NODE_ERROR(x);
            ALIVE[SCRATCH] = 0;
            NT[SCRATCH] = 0;
            for (int i = 0; i < 64; i++)
                if (C[i].used && C[i].node == SCRATCH) C[i].used = 0;
            for (size_t i = k; i < x->n_batches; i++) { /* what this start saved is its own */
                for (size_t j = 0; j < x->batches[i].n; j++) free((void *)x->batches[i].recs[j].bytes.data);
                free(x->batches[i].recs);
            }
            x->n_batches = 0;
            h_free(x);
            memset(x, 0, sizeof *x);
        }
    CHECK(ERRORS == 0);
    w_free(4);
}

/* ---- 2. a cancel during a round: one batch; the tombstone; Closing ---------------- */

static void test_cancel_and_tombstone(void)
{
    static const uint32_t end[] = {GZ_REC_LOBBY_ENDED, 0x7e5a0004u, GZ_RECORD_SLOT_CLOSED};
    static const uint32_t mend[] = {GZ_REC_LOBBY_ENDED, 0x7e5a0004u, GZ_RECORD_SLOT_CLOSED};
    gz_lobby_msg_t g;
    lt_key_t hk, m1;
    gz_link_t l1;
    size_t from, lmark;
    uint8_t other[32];
    two_lobbies(GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_run(36000, 500);
    CHECK(host_state(&TA) == GZ_LOBBY_SIGNING && host_state(&TB) == GZ_LOBBY_SIGNING);
    whost(&hk);
    wkey(1, 0, slot(1, &TA)->key_index, &m1);
    l1 = h_link(hk.pub, m1.pub);
    /* The person cancels lobby A during its round. */
    lmark = N[0].n_log;
    uint16_t gen_a = slot(0, &TA)->gen;
    int timers_a = 0, unseats = UNSEATS[0];
    for (int k = 0; k < NT[0]; k++) timers_a += (T[0][k].id >> 48) == GZ_AREA_LOBBY && ((T[0][k].id >> 32) & 0xffff) == gen_a;
    CHECK(scope_cmd(0, GZ_CMD_LOBBY_CANCEL, &TA, 0) == 200);
    /* The closed lobby's timers are cancelled: none of its generation is left set. */
    for (int k = 0; k < NT[0]; k++) CHECK(!((T[0][k].id >> 48) == GZ_AREA_LOBBY && ((T[0][k].id >> 32) & 0xffff) == gen_a));
    CHECK(timers_a >= 0 && UNSEATS[0] == unseats); /* Closing: the round's members keep their seats */
    CHECK(batch_with(0, end, 3)); /* lobby_ended, the round's end, slot_closed: one batch */
    CHECK(slot(0, &TA) == NULL && host_state(&TB) == GZ_LOBBY_SIGNING);
    CHECK(said(0, lmark, "closing=1") == 1 && gz_ls_closing_count(N[0].n) == 1);
    w_run(1000, 100);
    for (int n = 1; n <= 3; n++) CHECK(slot(n, &TA) == NULL && batch_with(n, mend, 3));
    CHECK(slot(1, &TB) != NULL && slot(4, &TB) != NULL); /* the other lobby goes on */
    /* A late hello for the ended lobby: its final state, the reason, then the saved cancel. */
    from = NSENT;
    w_msg(0, &l1, GZ_MSG_KIND_HELLO, TA.scope, NULL, 0);
    CHECK(last_sent(0, from, GZ_KIND_LOBBY_STATUS, m1.pub, &g) && g.lobby_state == GZ_LOBBY_CANCELLED && g.has_reason &&
          g.reason == 2);
    CHECK(last_sent(0, from, GZ_KIND_CANCEL, m1.pub, &g) && g.reason == 2 && lt_verify(NULL, hk.pub, (gz_lobby_msg_hash(&g, other), other), g.sig));
    CHECK(sent_count(0, from, GZ_KIND_LOBBY_STATUS) == 1 && sent_count(0, from, GZ_KIND_CANCEL) == 1);
    /* Anything but a hello for the ended lobby is dropped: no answer. */
    w_run(1500, 100); /* a hello now would be answered (one a second per link) */
    from = NSENT;
    w_msg(0, &l1, GZ_KIND_UNREADY, TA.scope, NULL, 0);
    w_msg(0, &l1, GZ_KIND_LEAVE, TA.scope, NULL, 0);
    CHECK(NSENT == from);
    /* An unknown lobby: state 0 alone. Asked a second later (one answer a second per link). */
    w_run(1500, 100);
    memset(other, 0x33, 32);
    from = NSENT;
    w_msg(0, &l1, GZ_MSG_KIND_HELLO, other, NULL, 0);
    CHECK(last_sent(0, from, GZ_KIND_LOBBY_STATUS, m1.pub, &g) && g.lobby_state == GZ_LOBBY_UNKNOWN && !g.has_reason &&
          sent_count(0, from, GZ_KIND_CANCEL) == 0);
    /* Closing lasts the lobby's signing budget: then the members' CONNECTs
     * end and the host gives up their seats. */
    {
        int up = 0;
        for (int i = 0; i < 64; i++) up += C[i].used && C[i].up == 1;
        CHECK(up == 6);
        w_run(700000, 5000);
        up = 0;
        for (int i = 0; i < 64; i++) up += C[i].used && C[i].up == 1;
        CHECK(up == 3 && gz_ls_closing_count(N[0].n) == 0 && gz_ls_closing_count(N[1].n) == 0);
        CHECK(UNSEATS[0] == unseats + 3); /* Free: the three members' keys hold no seat any more */
    }
    /* The host restarted in Signing, after lobby B's deadline passed during
     * its round: the unfinished attempt is failed at the start (H13), the
     * lobby takes the Retry, and with nobody Ready past its deadline it is
     * cancelled at once, reason 1 (B4). The members were not connected then:
     * they learn it from the tombstone when they reconnect and say hello. */
    {
        static const uint32_t bretry[] = {0x7e5a0004u, GZ_REC_SEAT, GZ_REC_LOBBY_STATE};
        static const uint32_t bend[] = {GZ_REC_LOBBY_ENDED, GZ_RECORD_SLOT_CLOSED};
        lt_key_t m4;
        gz_link_t l4;
        size_t mark = N[0].n_log;
        wkey(4, 0, slot(4, &TB)->key_index, &m4);
        l4 = h_link(hk.pub, m4.pub);
        CHECK(w_restart(0) == GZ_OK);
        /* Two batches, in this order: the round's end with the lobby back to
         * Open (rule 2), then the lobby's end with its slot's. */
        CHECK(slot(0, &TB) == NULL && said(0, mark, "sign-resume-failed") == 1);
        CHECK(batch_with(0, bretry, 3) && batch_with(0, bend, 2));
        CHECK(slot(1, &TB) != NULL && slot(4, &TB) != NULL);
        from = NSENT;
        w_run(3000, 100);
        CHECK(slot(1, &TB) == NULL && slot(2, &TB) == NULL && slot(4, &TB) == NULL);
        CHECK(last_sent(0, from, GZ_KIND_LOBBY_STATUS, m4.pub, &g) && g.lobby_state == GZ_LOBBY_CANCELLED && g.reason == 1);
        CHECK(last_sent(0, from, GZ_KIND_CANCEL, m4.pub, &g) && g.reason == 1);
        /* And the lobby ended before the restart is answered from the index
         * of ended lobbies, loaded from the journal: the same answer. */
        from = NSENT;
        w_msg(0, &l4, GZ_MSG_KIND_HELLO, TA.scope, NULL, 0);
        CHECK(last_sent(0, from, GZ_KIND_LOBBY_STATUS, m4.pub, &g) && g.lobby_state == GZ_LOBBY_CANCELLED && g.reason == 2);
        CHECK(last_sent(0, from, GZ_KIND_CANCEL, m4.pub, &g) && g.reason == 2);
    }
    no_errors(4);
    w_free(4);
}

/* ---- 3. what a person can get wrong never stops the node, or its next start --------- */

static void test_refusals(void)
{
    terms_t t[9], bad;
    lt_key_t hk;
    uint8_t notkey[33], garbage[40];
    size_t nb;
    whost(&hk);
    /* The host: eight lobbies open; a ninth is refused, not an error. */
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    for (int i = 0; i < 9; i++) make_terms(&t[i], 3, 3, 100 + (uint32_t)i);
    CHECK(member_join(0, &t[0]) == 409 && N[0].n_batches == 0 && gz_route_slot_by_scope(N[0].n, t[0].scope) < 0);
    for (int i = 0; i < 8; i++) CHECK(host_open(&t[i], 0) == 200);
    nb = N[0].n_batches;
    CHECK(host_open(&t[8], 0) == 409 && host_open(&t[0], 0) == 409 && N[0].n_batches == nb);
    /* Terms that are not terms: refused, nothing saved, no key index used. */
    bad = t[8];
    bad.outer[5] ^= 0x40;
    CHECK(scope_cmd(0, GZ_CMD_LOBBY_CANCEL, &t[7], 0) == 200); /* room again */
    nb = N[0].n_batches;
    CHECK(host_open(&bad, 0) == 400 && N[0].n_batches == nb);
    bad = t[8];
    bad.cn = 3;
    CHECK(host_open(&bad, 0) == 400 && N[0].n_batches == nb);
    CHECK(host_open(&t[7], 0) == 409 && N[0].n_batches == nb); /* an ended lobby is not opened again, with room for it */
    CHECK(host_open(&t[8], 0) == 200);
    CHECK(w_restart(0) == GZ_OK);
    for (int i = 0; i < 7; i++) CHECK(host_state(&t[i]) == GZ_LOBBY_OPEN);
    CHECK(host_state(&t[8]) == GZ_LOBBY_OPEN && slot(0, &t[7]) == NULL);
    /* A member's command on the host, and the reverse: refused. */
    CHECK(member_join(0, &t[0]) == 409 && scope_cmd(0, GZ_CMD_LOBBY_READY, &t[0], 0) == 404);

    /* The member: a bad address, a host key that is no key, conditions that
     * are no conditions. Refused before anything is kept. */
    {
        h_arg_t a[4] = {{12, t[0].scope, 32}, {14, hk.pub, 33}, {16, "no-port-here", 12}, {18, garbage, 5}};
        memset(notkey, 0xff, 33);
        notkey[0] = 0x02;
        memset(garbage, 7, sizeof garbage);
        CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, a, 3) == 400);
        a[2].v = "[::1]";
        a[2].len = 5;
        CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, a, 3) == 400);
        a[2].v = ADDR;
        a[2].len = sizeof ADDR - 1;
        a[1].v = notkey;
        CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, a, 3) == 400);
        a[1].v = hk.pub;
        CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, a, 4) == 400);
        a[0].len = 31;
        CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, a, 3) == 400);
        CHECK(N[1].n_batches == 0 && gz_route_slot_by_scope(N[1].n, t[0].scope) < 0);
        CHECK(w_restart(1) == GZ_OK && N[1].n_batches == 0);
    }
    /* A key the port will not sign with: the join is not made, nothing breaks. */
    SIGN_FAIL[1] = 1;
    CHECK(member_join(1, &t[0]) == 200);
    w_run(2000, 100);
    CHECK(slot(1, &t[0]) && !slot(1, &t[0])->lobby.m.joined && h_records_of(&N[1], GZ_REC_JOINED) == 0);
    SIGN_FAIL[1] = 0;
    /* A second join for the same lobby, and a ninth lobby: refused. */
    CHECK(member_join(1, &t[0]) == 409);
    for (int i = 1; i < 7; i++) CHECK(member_join(1, &t[i]) == 200);
    CHECK(member_join(1, &t[8]) == 200 && member_join(1, &t[7]) == 409);
    /* A key port that cannot give the slots' keys at a start (an epoch this
     * wallet cannot derive): the node starts, the slots are left out. With
     * the keys back, so are the slots. */
    w_run(2000, 100); /* the joins are made and saved: Lobby records for every slot */
    CHECK(h_records_of(&N[1], GZ_REC_JOINED) >= 7);
    PUB_FAIL[1] = 1;
    CHECK(w_restart(1) == GZ_OK && slot(1, &t[0]) == NULL && N[1].n->np.skipped_slots == 8);
    PUB_FAIL[1] = 0;
    CHECK(w_restart(1) == GZ_OK && slot(1, &t[0]) != NULL && slot(1, &t[8]) != NULL && N[1].n->np.skipped_slots == 0);
    w_run(3000, 100);
    CHECK(slot(1, &t[0])->lobby.m.joined && h_records_of(&N[1], GZ_REC_JOINED) >= 1);
    /* A slot_opened whose address is no address cannot be saved by the node
     * (the join refuses it). Found in storage all the same, it stops no
     * start: the slot is left out. */
    {
        h_t *x = &N[SCRATCH];
        uint8_t rec[200], v[4];
        size_t at = 0;
        w_node(SCRATCH, 5, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
        gz_put_u32(v, 1);
        gz_rec_put(rec, sizeof rec, &at, 2, v, 4);
        gz_rec_put(rec, sizeof rec, &at, 4, t[0].scope, 32);
        v[0] = 0;
        gz_rec_put(rec, sizeof rec, &at, 6, v, 1);
        gz_rec_put(rec, sizeof rec, &at, 8, hk.pub, 33);
        gz_rec_put(rec, sizeof rec, &at, 10, (const uint8_t *)"no-port-here", 12);
        gz_put_u32(v, 0);
        gz_rec_put(rec, sizeof rec, &at, 12, v, 4);
        gz_put_u32(v, 1);
        gz_rec_put(rec, sizeof rec, &at, 14, v, 4);
        v[0] = 1;
        gz_rec_put(rec, sizeof rec, &at, 22, v, 1);
        h_add_batch(x, 1, 1, GZ_RECORD_SLOT_OPENED, rec, at);
        x->incarnation = 1;
        h_new_node(x);
        CHECK(w_start(SCRATCH) == GZ_OK && x->n->np.skipped_slots == 1 && gz_route_slot_by_scope(x->n, t[0].scope) < 0);
        CHECK_NO_NODE_ERROR(x);
        ALIVE[SCRATCH] = 0;
        h_free(x);
        memset(x, 0, sizeof *x);
    }
    /* Unknown commands in the lobby's and the node's ranges. */
    CHECK(w_cmd(1, 0x01ff, NULL, 0) == 404 && w_cmd(1, 0x04ff, NULL, 0) == 404 && w_cmd(0, 0x0109, NULL, 0) == 404);
    /* The test commands for the stand-in's slots do not reach a slot that
     * holds a lobby: it is closed by its lobby alone, with its records. */
    {
        h_arg_t a[1] = {{12, t[0].scope, 32}};
        size_t nb1 = N[1].n_batches;
        CHECK(w_cmd(1, 0x7e81, a, 1) == 404 && w_cmd(0, 0x7e81, a, 1) == 404 && w_cmd(0, 0x7e83, a, 1) == 404);
        CHECK(slot(1, &t[0]) != NULL && slot(0, &t[0]) != NULL && N[1].n_batches == nb1);
    }
    no_errors(1);
    w_free(1);
}

/* The index of ended lobbies keeps the newest 256: the 257th end forgets the
 * oldest, which is then answered as unknown; every later one is answered
 * with its final state. */
static void test_index(void)
{
    static terms_t t[NP_MAX_ENDED + 1];
    gz_lobby_msg_t g;
    lt_key_t hk;
    uint8_t k[33];
    gz_link_t l;
    size_t from;
    whost(&hk);
    w_world(0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    for (int i = 0; i <= NP_MAX_ENDED; i++) {
        make_terms(&t[i], 3, 3, 1000 + (uint32_t)i);
        CHECK(host_open(&t[i], 0) == 200 && scope_cmd(0, GZ_CMD_LOBBY_CANCEL, &t[i], 0) == 200);
    }
    h_key('M', 7, k);
    l = h_link(hk.pub, k);
    w_peer(0, &l, 1, 0, 0, 0);
    from = NSENT;
    w_msg(0, &l, GZ_MSG_KIND_HELLO, t[0].scope, NULL, 0);
    CHECK(last_sent(0, from, GZ_KIND_LOBBY_STATUS, k, &g) && g.lobby_state == GZ_LOBBY_UNKNOWN && sent_count(0, from, GZ_KIND_CANCEL) == 0);
    for (int i = 1; i <= NP_MAX_ENDED; i += 85) {
        w_run(1100, 100);
        from = NSENT;
        w_msg(0, &l, GZ_MSG_KIND_HELLO, t[i].scope, NULL, 0);
        CHECK(last_sent(0, from, GZ_KIND_LOBBY_STATUS, k, &g) && g.lobby_state == GZ_LOBBY_CANCELLED && g.reason == 2);
        CHECK(last_sent(0, from, GZ_KIND_CANCEL, k, &g) && !memcmp(g.scope, t[i].scope, 32));
    }
    /* The same after a restart, from the journal. */
    CHECK(w_restart(0) == GZ_OK);
    w_peer(0, &l, 1, 0, 0, 0);
    from = NSENT;
    w_msg(0, &l, GZ_MSG_KIND_HELLO, t[0].scope, NULL, 0);
    CHECK(last_sent(0, from, GZ_KIND_LOBBY_STATUS, k, &g) && g.lobby_state == GZ_LOBBY_UNKNOWN);
    w_run(1100, 100);
    from = NSENT;
    w_msg(0, &l, GZ_MSG_KIND_HELLO, t[NP_MAX_ENDED].scope, NULL, 0);
    CHECK(last_sent(0, from, GZ_KIND_CANCEL, k, &g) && !memcmp(g.scope, t[NP_MAX_ENDED].scope, 32));
    no_errors(0);
    w_free(0);
}

/* ---- 4. the member signing gate ----------------------------------------------------- */

static void test_gates(void)
{
    terms_t t;
    size_t b;
    /* Member 1: AT_JOIN (the default). Member 2: WHEN_UNLOCKED. Member 3: AUTO. */
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    w_node(1, 1, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_FUNDING);
    w_node(2, 2, GZ_MEMBER_SIGNING_WHEN_UNLOCKED, GZ_TEST_SIGN_FUNDING);
    w_node(3, 3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    for (int n = 0; n <= 3; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 3, 3, 3000);
    CHECK(host_open(&t, 0) == 200);
    for (int n = 1; n <= 3; n++) CHECK(member_join(n, &t) == 200);
    w_run(4000, 100);
    /* Both locked members hold seats and are not counted Ready: no check runs
     * that they would make fail (R5). */
    CHECK(host_ready(&t) == 1 && host_state(&t) == GZ_LOBBY_OPEN && h_records_of(&N[0], GZ_REC_FREEZE) == 0);
    CHECK(slot(1, &t)->lobby.m.joined && member_ready(1, &t) == 0 && member_ready(2, &t) == 0 && member_ready(3, &t) == 1);
    /* "Ready" without the passphrase leaves an AT_JOIN lobby locked; with it, ready. */
    scope_cmd(1, GZ_CMD_LOBBY_READY, &t, 0);
    w_run(1000, 100);
    CHECK(member_ready(1, &t) == 0 && host_ready(&t) == 1);
    CHECK(scope_cmd(1, GZ_CMD_LOBBY_READY, &t, 1) == 200);
    w_run(1000, 100);
    CHECK(member_ready(1, &t) == 1 && host_ready(&t) == 2);
    /* "Lock signing" closes a lobby's own gate too: the member leaves the
     * count, its scoped secret is forgotten; the passphrase opens it again. */
    CHECK(w_cmd(1, GZ_CMD_SIGNING_LOCK, NULL, 0) == 200);
    w_run(1000, 100);
    CHECK(member_ready(1, &t) == 0 && host_ready(&t) == 1 && FORGETS[1] == 1 && !slot(1, &t)->gate_open);
    CHECK(scope_cmd(1, GZ_CMD_LOBBY_READY, &t, 1) == 200);
    w_run(1000, 100);
    CHECK(member_ready(1, &t) == 1 && host_ready(&t) == 2);
    /* A restart closes every gate: the member tells the host "locked" (saved
     * first), and its seat leaves the count until the person readies again.
     * Twenty restarts in ten minutes do not cost the seat (F4). */
    for (int k = 0; k < 20; k++) {
        slot_t *s;
        int in = 0;
        CHECK(w_restart(1) == GZ_OK);
        w_run(3000, 100);
        CHECK(member_ready(1, &t) == 0 && host_ready(&t) == 1); /* locked: out of the count, each time */
        CHECK(scope_cmd(1, GZ_CMD_LOBBY_READY, &t, 1) == 200);
        w_run(27000, 500);
        CHECK(member_ready(1, &t) == 1);
        /* The first locked/ready pair is free; the host may ignore a ready
         * past its limit of changes, but the seat is never lost. */
        if (k == 0) CHECK(host_ready(&t) == 2);
        s = slot(0, &t);
        for (uint16_t j = 0; s && j < s->lobby.h.n_seats; j++)
            in += s->lobby.h.seats[j].state == GZ_SEAT_JOINED || s->lobby.h.seats[j].state == GZ_SEAT_READY;
        CHECK(in == 3);
    }
    /* Ten quiet minutes later a ready counts again. */
    w_run(601000, 2000);
    CHECK(w_restart(1) == GZ_OK);
    w_run(3000, 100);
    CHECK(scope_cmd(1, GZ_CMD_LOBBY_READY, &t, 1) == 200);
    w_run(3000, 100);
    CHECK(member_ready(1, &t) == 1 && host_ready(&t) == 2 && slot(0, &t)->lobby.h.n_seats == 3);
    /* The node-wide gate: unlocked, member 2 readies; the check runs and all three sign. */
    CHECK(host_state(&t) == GZ_LOBBY_OPEN && FORGETS[1] == 1);
    CHECK(w_cmd(2, GZ_CMD_SIGNING_UNLOCK, NULL, 0) == 200);
    w_run(2000, 100);
    CHECK(member_ready(2, &t) == 1 && host_ready(&t) == 3 && host_state(&t) == GZ_LOBBY_READY_CHECK);
    w_run(33000, 500);
    CHECK(host_state(&t) == GZ_LOBBY_FUNDING);
    for (int n = 1; n <= 3; n++) CHECK(member_round(n, &t) == GZ_LOBBY_FUNDING);
    /* The AT_JOIN gate closed when its check's round ended: the scoped secret is gone. */
    CHECK(FORGETS[1] == 2 && !slot(1, &t)->gate_open && FORGETS[2] == 0 && FORGETS[3] == 0);
    /* Locking after the round changes nothing that is saved or sent. */
    b = N[2].n_batches;
    CHECK(w_cmd(2, GZ_CMD_SIGNING_LOCK, NULL, 0) == 200 && N[2].n_batches == b);
    no_errors(3);
    w_free(3);

    /* A host whose minimum is met only with locked members never starts a
     * check, also at its deadline: it cancels for the deadline (reason 1). */
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    for (int n = 1; n <= 3; n++) w_node(n, n, GZ_MEMBER_SIGNING_WHEN_UNLOCKED, GZ_TEST_SIGN_FUNDING);
    for (int n = 0; n <= 3; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 3, 3, 0);
    CHECK(host_open(&t, 0) == 200);
    for (int n = 1; n <= 3; n++) CHECK(member_join(n, &t) == 200);
    w_run(590000, 2000);
    CHECK(host_state(&t) == GZ_LOBBY_OPEN && host_ready(&t) == 0 && h_records_of(&N[0], GZ_REC_FREEZE) == 0);
    w_run(20000, 1000);
    {
        static const uint32_t end[] = {GZ_REC_LOBBY_ENDED, GZ_RECORD_SLOT_CLOSED};
        int up = 0;
        CHECK(slot(0, &t) == NULL && batch_with(0, end, 2) && h_records_of(&N[0], GZ_REC_START_SENT) == 0);
        for (int n = 1; n <= 3; n++) CHECK(slot(n, &t) == NULL && batch_with(n, end, 2));
        /* No round was ever handed over: the slots are Free at once. The
         * host's seats are given up, and the members keep no connection. */
        w_run(2000, 100);
        for (int i = 0; i < 64; i++) up += C[i].used && (C[i].up == 1 || C[i].wanted);
        CHECK(UNSEATS[0] == 3 && up == 0 && gz_ls_closing_count(N[0].n) == 0 && gz_ls_closing_count(N[1].n) == 0);
    }
    no_errors(3);
    w_free(3);
}

/* ---- 5. the engine rule: a hostile peer, the chain and the person, at random --------- */

static uint64_t RNG = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(uint32_t n)
{
    RNG ^= RNG << 13;
    RNG ^= RNG >> 7;
    RNG ^= RNG << 17;
    return n ? (uint32_t)((RNG >> 11) % n) : 0;
}

static void test_hostile(unsigned long events, uint64_t seed)
{
    static const uint16_t kinds[] = {16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 63, 64, 70, 78, 80, 81, 130,
                                     32767, 0, 2, 0xffff, 15, 17};
    static const uint16_t codes[] = {GZ_CMD_LOBBY_OPEN, GZ_CMD_LOBBY_JOIN, GZ_CMD_LOBBY_READY, GZ_CMD_LOBBY_UNREADY,
                                     GZ_CMD_LOBBY_LEAVE, GZ_CMD_LOBBY_SET_VALUES, GZ_CMD_LOBBY_REMOVE,
                                     GZ_CMD_LOBBY_CANCEL, GZ_CMD_SIGNING_UNLOCK, GZ_CMD_SIGNING_LOCK, 0x7e86, 0x0109,
                                     0x0400, 0x7e80, 0x7e81};
    terms_t t[4];
    lt_key_t hk;
    uint8_t rec[600], scope[32];
    unsigned long done = 0;
    RNG = seed * 0x9e3779b97f4a7c15ull + 1;
    whost(&hk);
    two_lobbies(GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_RETRY);
    t[0] = TA;
    t[1] = TB;
    make_terms(&t[2], 3, 3, 50);
    make_terms(&t[3], 3, 3, 51);
    CHECK(host_open(&t[2], 1) == 200 && scope_cmd(0, GZ_CMD_LOBBY_CANCEL, &t[2], 0) == 200); /* an ended lobby */
    w_run(2000, 100);
    while (done < events && ERRORS == 0 && N[0].n_batches < H_MAX_BATCHES - 600 && N[1].n_batches < H_MAX_BATCHES - 600 &&
           N[2].n_batches < H_MAX_BATCHES - 600) {
        int n = (int)rnd(3); /* the host, member 1, member 2 */
        if (done % 400 == 0) { /* a lobby that ended is followed by a new one, which the members are invited to */
            int which = (int)rnd(2);
            if (!slot(0, &t[which])) {
                make_terms(&t[which], 3, 3, 5000 + (uint32_t)done);
                SIGN_FAIL[0] = 0;
                host_open(&t[which], (int)rnd(2));
                for (int m = 1; m <= 4; m++)
                    if (rnd(4)) member_join(m, &t[which]);
            }
        }
        uint32_t what = rnd(100);
        size_t len = rnd(4) ? rnd(300) : rnd(sizeof rec);
        const terms_t *tt = &t[rnd(4)];
        done++;
        for (size_t i = 0; i < len; i++) rec[i] = (uint8_t)rnd(256);
        if (rnd(3) == 0 && NSENT) { /* something a node really sent, as it was or with a byte changed */
            const wsent_t *s = &SENT[rnd((uint32_t)NSENT)];
            len = s->len;
            memcpy(rec, s->rec, len);
            if (len && rnd(2)) rec[rnd((uint32_t)len)] ^= (uint8_t)(1u << rnd(8));
        }
        switch (rnd(5)) {
        case 0: memset(scope, 0, 32); break;
        case 1: for (int i = 0; i < 32; i++) scope[i] = (uint8_t)rnd(256); break;
        default: memcpy(scope, tt->scope, 32); break;
        }
        if (what < 55) { /* a message, on a real link or on any other */
            gz_link_t l;
            wconn_t *c = &C[rnd(8)];
            uint8_t k[33];
            h_key('M', rnd(90), k);
            if (n == 0) l = rnd(3) && c->used ? h_link(hk.pub, c->mlink.local.key) : h_link(hk.pub, k);
            else l = rnd(4) && c->used ? c->mlink : h_link(k, hk.pub);
            if (n == 0 && rnd(8) == 0) w_peer(0, &l, 1, 0, 0, 0);
            w_msg(n, &l, rnd(10) ? kinds[rnd(sizeof kinds / sizeof kinds[0])] : (uint16_t)rnd(65536), scope, rec, len);
        } else if (what < 62) { /* connections come and go */
            gz_link_t l;
            uint8_t k[33];
            h_key('M', rnd(90), k);
            l = n == 0 ? h_link(hk.pub, k) : h_link(k, hk.pub);
            w_peer(n, &l, (int)rnd(2), n != 0, rnd(3), rnd(40));
        } else if (what < 72) { /* timers: set ones early, and ids nobody set */
            gz_event_t ev;
            memset(&ev, 0, sizeof ev);
            ev.kind = GZ_EVENT_TIMER_FIRED;
            if (NT[n] && rnd(3)) ev.u.timer.timer_id = T[n][rnd((uint32_t)NT[n])].id;
            else ev.u.timer.timer_id = ((uint64_t)rnd(6) << 48) | ((uint64_t)rnd(12) << 32) | (0x4c000000u + rnd(8));
            w_event(n, &ev);
        } else if (what < 90) { /* the person, with good and bad arguments */
            h_arg_t a[4];
            size_t na = rnd(5);
            uint16_t code = codes[rnd(sizeof codes / sizeof codes[0])];
            for (size_t i = 0; i < na; i++) {
                a[i].type = 12 + 2 * i;
                a[i].v = i == 0 && rnd(4) ? scope : rec + rnd(64);
                a[i].len = i == 0 && rnd(4) ? 32 : rnd(3) == 0 ? rnd(200) : (size_t[]){1, 2, 8, 33, 16}[rnd(5)];
            }
            if (code == GZ_CMD_LOBBY_JOIN && rnd(2)) { /* a join that could be real */
                a[0].v = scope; a[0].len = 32;
                a[1].type = 14; a[1].v = hk.pub; a[1].len = 33;
                a[2].type = 16; a[2].v = ADDR; a[2].len = sizeof ADDR - 1;
                na = 3;
            }
            if (code == GZ_CMD_LOBBY_OPEN && rnd(2)) {
                a[0].v = t[3].outer; a[0].len = t[3].on;
                a[1].type = 14; a[1].v = t[3].current; a[1].len = t[3].cn;
                na = 2;
            }
            w_cmd(n, code, a, na);
        } else if (what < 94) { /* the chain */
            gz_event_t ev;
            memset(&ev, 0, sizeof ev);
            ev.kind = GZ_EVENT_CHAIN;
            ev.u.chain.kind = (gz_chain_kind_t)(1 + rnd(6));
            ev.u.chain.height = rnd(1000);
            ev.u.chain.confirmations = rnd(8);
            w_event(n, &ev);
        } else if (what < 97) { /* the key port stops signing for a while */
            SIGN_FAIL[n] = (int)rnd(2);
        } else if (what < 99) { /* time passes: seconds, or the rest of an hour */
            w_run(rnd(4) ? 1000 + rnd(30000) : 600000, 1000 + rnd(20000));
        } else { /* a crash and a restart on what was saved */
            SIGN_FAIL[n] = 0;
            gz_status_t rs = w_restart(n);
            if (rs != GZ_OK) {
                ERRORS++;
                printf("a start of node %d failed after %lu events: status %d, error area 0x%04x, %zu batches\n", n, done,
                       (int)rs, (unsigned)gz_node_error_area(N[n].n), N[n].n_batches);
                for (size_t i = 0; i < N[n].n_batches; i++) {
                    printf("  batch %zu (%llu.%llu):", i, (unsigned long long)N[n].batches[i].id.incarnation,
                           (unsigned long long)N[n].batches[i].id.sequence);
                    for (size_t k = 0; k < N[n].batches[i].n; k++)
                        printf(" %08x/%zu", (unsigned)N[n].batches[i].recs[k].type, N[n].batches[i].recs[k].bytes.len);
                    printf("\n");
                }
            }
        }
    }
    printf("  hostile: %lu events, %zu batches on the host, %zu and %zu on the members\n", done, N[0].n_batches,
           N[1].n_batches, N[2].n_batches);
    for (int n = 0; n <= 4; n++) {
        SIGN_FAIL[n] = 0;
        CHECK(w_restart(n) == GZ_OK); /* and whatever was saved starts again */
    }
    no_errors(4);
    w_free(4);
}

int main(int argc, char **argv)
{
    unsigned long events = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000;
    uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 10) : 1;
    setvbuf(stdout, NULL, _IONBF, 0);
    test_two_lobbies();
    test_cancel_and_tombstone();
    test_refusals();
    test_gates();
    test_index();
    test_hostile(events, seed);
    return check_done();
}
