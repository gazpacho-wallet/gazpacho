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
#include "gazpacho/funding.h"
#include <secp256k1.h>

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
    int closer;                 /* up -1: the node whose DISCONNECT is closing it */
    gz_link_t mlink;            /* the member's side: (its key, the host's) */
    uint32_t epoch, index;
} wconn_t;
typedef struct { int node; uint16_t kind; uint8_t to[33], scope[32]; uint8_t rec[512]; size_t len; } wsent_t;

static h_t N[NN];
static int IDENT[NN], ALIVE[NN], PUB_FAIL[NN], SIGN_FAIL[NN], FORGETS[NN];
static uint32_t BAD_INDEX[NN];  /* an index whose key the port cannot give (an invalid child) */
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

/* ---- the view (P6a): the newest object of each (kind, id), as the program
 * keeps it; a restart forgets it, and what the next start emits must be no
 * older than what was released before (contract-v2.md 11). */
typedef struct {
    int used, stale, gone;
    uint16_t kind;
    char id[65];
    uint8_t b[6144];
    size_t len;
    uint64_t version, old;
} wview_t;
#define NV 320
static wview_t VW[NN][NV];
static int VIEW_ERRORS;
/* The last command-result notice of each node, as the program gets it. */
static uint8_t RES[NN][2600];
static size_t RES_LEN[NN];

static void view_keep(int n, uint16_t kind, gz_bytes_t b)
{
    gz_bytes_t v;
    wview_t *w = NULL;
    char id[65];
    uint64_t ver;
    if (gz_rec_find(b, GZ_VIEW_REC_ID, &v) != 1 || v.len < 1 || v.len > 64 || b.len > sizeof VW[0][0].b) {
        VIEW_ERRORS++;
        return;
    }
    memcpy(id, v.data, v.len);
    id[v.len] = 0;
    for (int k = 0; k < NV && !w; k++)
        if (VW[n][k].used && VW[n][k].kind == kind && !strcmp(VW[n][k].id, id)) w = &VW[n][k];
    for (int k = 0; k < NV && !w; k++)
        if (!VW[n][k].used) w = &VW[n][k];
    if (!w || gz_rec_find(b, GZ_VIEW_REC_VERSION, &v) != 1 || v.len != 8) {
        VIEW_ERRORS++;
        return;
    }
    ver = gz_get_u64(v.data);
    if (w->used && ver <= (w->stale ? w->old : w->version)) {
        printf("view %d kind %u %s: version %llu not above %llu\n", n, (unsigned)kind, id, (unsigned long long)ver,
               (unsigned long long)(w->stale ? w->old : w->version));
        VIEW_ERRORS++;
    }
    w->used = 1;
    w->kind = kind;
    memcpy(w->id, id, sizeof id);
    w->stale = 0;
    w->version = ver;
    w->gone = gz_rec_find(b, GZ_VIEW_REC_GONE, &v) == 1;
    memcpy(w->b, b.data, b.len);
    w->len = b.len;
}

static void view_restart(int n)
{
    for (int k = 0; k < NV; k++)
        if (VW[n][k].used) {
            VW[n][k].stale = 1;
            VW[n][k].old = VW[n][k].version;
        }
}

static wview_t *view_of(int n, uint16_t kind, const char *id)
{
    for (int k = 0; k < NV; k++)
        if (VW[n][k].used && !VW[n][k].stale && VW[n][k].kind == kind && !strcmp(VW[n][k].id, id)) return &VW[n][k];
    return NULL;
}

static int vf(const wview_t *w, uint64_t type, gz_bytes_t *v)
{
    gz_bytes_t b;
    if (!w) return 0;
    b.data = w->b;
    b.len = w->len;
    return gz_rec_find(b, type, v) == 1;
}

static int vf8(const wview_t *w, uint64_t type)
{
    gz_bytes_t v;
    return vf(w, type, &v) && v.len >= 1 ? v.data[0] : -1;
}

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
    if (PUB_FAIL[n] || (BAD_INDEX[n] && index == BAD_INDEX[n])) return 0;
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

static int SIGNS[NN];          /* member signatures of each node (w_sign) */
/* The wallet port's dry run of a host's funding (cfg.funds.can_plan), per node: 0 enough,
 * 1 short, 2 cannot tell; W_NO_WALLET: the next w_node has no port at all. */
static int FUNDS[NN], W_NO_WALLET;
static uint64_t FUNDS_ASKED[NN];
static gz_wallet_port_t WWALLET[NN];

static int w_can_plan(void *ctx, uint64_t amount, uint64_t feerate, uint64_t *have_sat, size_t *n_coins);

static int w_sign(void *ctx, int host, uint32_t epoch, uint32_t index, const uint8_t msg[32], uint8_t sig[64])
{
    static const uint8_t aux[32];
    lt_key_t k;
    int n = node_of(ctx);
    if (SIGN_FAIL[n]) return 0;
    if (!host) SIGNS[n]++;
    if (host) {
        if (IDENT[n] != 0) return 0;
        whost(&k);
    } else {
        wkey(IDENT[n], epoch, index, &k);
    }
    return secp256k1_schnorrsig_sign32(lt_ctx(), sig, msg, &k.kp, aux);
}

static int w_can_plan(void *ctx, uint64_t amount, uint64_t feerate, uint64_t *have_sat, size_t *n_coins)
{
    int n = node_of(ctx);
    (void)feerate;
    FUNDS_ASKED[n] = amount;
    if (FUNDS[n] == 2) return -1;
    *n_coins = 1;
    *have_sat = FUNDS[n] == 1 ? amount / 2 : amount + 100000;
    return FUNDS[n] == 1 ? 0 : 1;
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
            if (!c || c->up != 1 || NQ == 8192) continue; /* no connection, or closing: the program drops it */
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
            if (c->up == 1) {          /* reported down to both sides at the next turn */
                c->up = -1;
                c->closer = n;
            }
        } else if (a->kind == GZ_ACTION_NOTIFY && a->u.notify.code == GZ_NOTIFY_COMMAND_RESULT) {
            RES_LEN[n] = a->u.notify.bytes.len <= sizeof RES[0] ? a->u.notify.bytes.len : 0;
            if (RES_LEN[n]) memcpy(RES[n], a->u.notify.bytes.data, RES_LEN[n]);
        } else if (a->kind == GZ_ACTION_NOTIFY && (a->u.notify.code >> 16) == 1) {
            view_keep(n, (uint16_t)(a->u.notify.code & 0xffff), a->u.notify.bytes);
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

static unsigned long DELIVERED[NN];
static void w_msg(int n, const gz_link_t *l, uint16_t kind, const uint8_t scope[32], const uint8_t *rec, size_t len)
{
    gz_event_t ev;
    DELIVERED[n]++;
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
            /* A DISCONNECT is ordered (action.h): what its side queued on the
             * link is sent first, then it is closed; what the other side had
             * queued to it is lost (the program reads nothing more on a closing
             * link, program/net.c), and nothing sent after it goes. */
            for (size_t k = 0; k < NQ; k++)
                if (Q[k].rec && (!memcmp(&Q[k].link, &hl, sizeof hl) || !memcmp(&Q[k].link, &c->mlink, sizeof hl))) {
                    wmsg_t m = Q[k];
                    Q[k].rec = NULL;
                    if ((m.to == 0 ? c->node : 0) == c->closer && ALIVE[m.to])
                        w_msg(m.to, &m.link, m.kind, m.scope, m.rec, m.len);
                    free(m.rec);
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
        /* Closing (a DISCONNECT, up -1): what the closing side queued before it still goes. */
        if (c && (c->up == 1 || (c->up == -1 && (m.to == 0 ? c->node : 0) == c->closer)) && ALIVE[m.to])
            w_msg(m.to, &m.link, m.kind, m.scope, m.rec, m.len);
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
    rd.restored = h->restored;
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

static uint32_t W_TEST_ENGINES; /* test engines in the next w_node (test_index_unique) */

static void w_node(int n, int ident, gz_member_signing_t signing, uint32_t outcome)
{
    h_t *h = &N[n];
    memset(VW[n], 0, sizeof VW[n]); /* a new program: its view starts empty */
    h_init(h, ident == 0, W_TEST_ENGINES);
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
    WWALLET[n].can_plan = w_can_plan;
    WWALLET[n].ctx = h;
    h->cfg.wallet = W_NO_WALLET ? NULL : &WWALLET[n];
    h_new_node(h);
}

/* A node with the signing engine (a secp256k1 context and the engine's memory) and a key port that gives
 * secrets; its hand-offs still go to the stand-in (`outcome`), so only the key hook and the gate are the
 * engine's here. */
static secp256k1_context *TCTX;
static void *TMEM[NN];          /* one engine memory per node, the scratch node included */
static int w_secret(void *ctx, uint32_t epoch, uint32_t index, uint8_t sec[32])
{
    (void)ctx; (void)epoch;
    memset(sec, (int)(index % 200u) + 1, 32);
    return 1;
}

static void w_node_engine(int n, int ident, gz_member_signing_t signing, uint32_t outcome)
{
    h_t *h = &N[n];
    if (!TCTX) TCTX = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!TMEM[n]) TMEM[n] = malloc(gz_node_sign_size());
    h_init(h, ident == 0, 0);
    IDENT[n] = ident;
    h->confirm_auto = 0;
    h->clock = NOW;
    h->clock_seen = NOW;
    h->cfg.keys.pub = w_pub;
    h->cfg.keys.host_pub = w_host_pub;
    h->cfg.keys.secret = w_secret;
    h->cfg.keys.ctx = h;
    h->cfg.crypto.verify = w_verify;
    h->cfg.crypto.point_ok = w_point;
    h->cfg.crypto.sign = w_sign;
    h->cfg.crypto.forget = w_forget;
    h->cfg.crypto.ctx = h;
    h->cfg.member_signing = signing;
    h->cfg.test_sign_outcome = outcome;
    h->cfg.test_sign_delay_ms = 50;
    h->cfg.secp = TCTX;
    h->cfg.sign_mem = TMEM[n];
    h->cfg.sign_mem_size = gz_node_sign_size();
    WWALLET[n].can_plan = w_can_plan;
    WWALLET[n].ctx = h;
    h->cfg.wallet = W_NO_WALLET ? NULL : &WWALLET[n];
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
    memset(BAD_INDEX, 0, sizeof BAD_INDEX);
    memset(SIGN_FAIL, 0, sizeof SIGN_FAIL);
    memset(FORGETS, 0, sizeof FORGETS);
    memset(UNSEATS, 0, sizeof UNSEATS);
    NOW = W_NOW0;
    memset(FUNDS, 0, sizeof FUNDS);
    memset(FUNDS_ASKED, 0, sizeof FUNDS_ASKED);
    W_NO_WALLET = 0;
    memset(VW, 0, sizeof VW);
    VIEW_ERRORS = 0;
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
    view_restart(n);
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
    /* T1's last shape (one width-4 level, then the leaf kind) stops at 16 members: past it the same shape
     * is offered up to the target (terms.md 4: valid for every n, each member's leaf in a binary split) */
    if (o.n_shapes && target > o.shapes[o.n_shapes - 1].max_members) o.shapes[o.n_shapes - 1].max_members = target;
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

static slot_t *slot(int n, const terms_t *t);

/* With `unlock`: the ready given with the passphrase, for the values the
 * member holds (16, the seen_current_digest; review of #79, M1), or the
 * terms' own before it has any. */
static int scope_cmd(int n, uint16_t code, const terms_t *t, int unlock)
{
    uint8_t u = 1, d[32];
    const slot_t *s = slot(n, t);
    if (s && !s->host && s->lobby.m.have_terms)
        memcpy(d, s->lobby.m.frozen ? s->lobby.m.frozen_digest : s->lobby.m.current_digest, 32);
    else
        gz_terms_current_digest(t->current, t->cn, d);
    h_arg_t a[3] = {{12, t->scope, 32}, {14, &u, 1}, {16, d, 32}};
    return w_cmd(n, code, a, unlock ? 3 : 1);
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
    CHECK(ERRORS == 0 && VIEW_ERRORS == 0);
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

/* ---- the host's table ------------------------------------------------------------ */

/* The host's entry for link `l`: 1 live and seated, 0 live and unseated, -1 none or closing. */
static int host_entry(const gz_link_t *l)
{
    for (int i = 0; i < NP_MAX_CONNS; i++) {
        const np_conn_t *k = &N[0].n->np.conns[i];
        if (k->used && k->connected && !memcmp(&k->link, l, sizeof *l)) return k->closing ? -1 : k->seated;
    }
    return -1;
}

/* The seats the host's Open lobbies hold. */
static size_t host_seated(void)
{
    size_t n = 0;
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++)
        if (N[0].n->slots[i].state == SLOT_OPEN && N[0].n->slots[i].host) n += N[0].n->slots[i].n_seated;
    return n;
}

/* A stranger `who` connects to the host; with `hello`, it asks about a lobby nobody has. */
static void stranger(int who, int hello, gz_link_t *l)
{
    lt_key_t hk, sk;
    char name[40];
    uint8_t scope[32];
    whost(&hk);
    snprintf(name, sizeof name, "stranger %d", who);
    lt_key(&sk, name);
    *l = h_link(hk.pub, sk.pub);
    w_peer(0, l, 1, 0, 0, 0);
    memset(scope, 0x40 + (who & 0x3f), 32);
    if (hello) w_msg(0, l, GZ_MSG_KIND_HELLO, scope, NULL, 0);
}

/* An outsider `who` joins lobby `t` on fresh keys of its own: the connection, then the join. */
static void outsider_join(int who, const terms_t *t, gz_link_t *l)
{
    lt_key_t hk, ck;
    char name[48];
    uint8_t buf[400];
    gz_lobby_enc_t e;
    size_t n;
    whost(&hk);
    snprintf(name, sizeof name, "outsider %d contribution", who);
    lt_key(&ck, name);
    *l = h_link(hk.pub, ck.pub);
    /* K1: a join is the envelope alone, no factory key and no binding (the link proves the contribution
     * key; the factory key and its binding come with the first ready) */
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_JOIN, t->scope);
    n = gz_lobby_enc_done(&e);
    CHECK(n == 38);
    w_peer(0, l, 1, 0, 0, 0);
    w_msg(0, l, GZ_KIND_JOIN, t->scope, buf + 38, n - 38);
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
                                     GZ_RECORD_LOCAL_IDS, GZ_REC_LOBBY_OPENED};
    static const uint32_t next[] = {GZ_RECORD_KEY_INDEX, GZ_RECORD_GUARD, GZ_RECORD_SLOT_OPENED, GZ_RECORD_LOCAL_IDS,
                                    GZ_REC_LOBBY_OPENED};
    static const uint32_t mfirst[] = {GZ_RECORD_KEY_EPOCH, GZ_RECORD_KEY_INDEX, GZ_RECORD_GUARD, GZ_RECORD_SLOT_OPENED,
                                      GZ_RECORD_LOCAL_IDS};
    size_t batches[5], marks[5];
    two_lobbies(GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    /* The slot's first batch: the key's index and the guard before the key
     * is used, the slot and its lobby together (7.4). Exactly two batches on
     * the host so far, one per lobby. */
    CHECK(N[0].n_batches == 2 && N[0].batches[0].n == 6 && N[0].batches[1].n == 5);
    CHECK(batch_with(0, first, 6) && batch_with(0, next, 5) && batch_with(1, mfirst, 5));
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
    /* Closing keeps the round's members seated in the node part's table too
     * (review A of PR 44, M2): twenty strangers who each say hello, a few
     * seconds' work far inside the ten-minute limit, push out none of them. */
    {
        gz_link_t sl;
        CHECK(host_entry(&l1) == 1);
        for (int k = 0; k < 20; k++) stranger(k, 1, &sl);
        CHECK(host_entry(&l1) == 1);
        /* Its connection drops and comes back during Closing: still seated. */
        w_peer(0, &l1, 0, 0, 0, 0);
        w_peer(0, &l1, 1, 0, 0, 0);
        for (int k = 20; k < 40; k++) stranger(k, 1, &sl);
        CHECK(host_entry(&l1) == 1);
    }
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
    {   /* room again; the ended lobby leaves no timer of its own set (review B of PR 44, L7) */
        uint16_t g7 = slot(0, &t[7])->gen;
        CHECK(scope_cmd(0, GZ_CMD_LOBBY_CANCEL, &t[7], 0) == 200);
        for (int k = 0; k < NT[0]; k++)
            CHECK(!((T[0][k].id >> 48) == GZ_AREA_LOBBY && ((T[0][k].id >> 32) & 0xffff) == g7));
    }
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
    /* A key the port will not sign with (K1: a join carries no signature, so it is made; the first ready,
     * which the contribution key signs and which carries the binding, is not): nothing breaks. */
    SIGN_FAIL[1] = 1;
    CHECK(member_join(1, &t[0]) == 200);
    w_run(2000, 100);
    CHECK(slot(1, &t[0]) && slot(1, &t[0])->lobby.m.joined && h_records_of(&N[1], GZ_REC_JOINED) == 1);
    CHECK(!slot(1, &t[0])->lobby.m.ready && h_records_of(&N[1], GZ_REC_READY_SENT) == 0 &&
          h_records_of(&N[1], GZ_REC_SEAT_KEY) == 0);
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
    CHECK(w_cmd(1, 0x01ff, NULL, 0) == 404 && w_cmd(1, 0x04ff, NULL, 0) == 404 && w_cmd(0, 0x010b, NULL, 0) == 404);
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

/* An AT_JOIN ready with the passphrase, carrying the values digest the person saw (record 16). */
static int ready_seen(int n, const terms_t *t, const uint8_t digest[32])
{
    uint8_t u = 1;
    h_arg_t a[3] = {{12, t->scope, 32}, {14, &u, 1}, {16, digest, 32}};
    return w_cmd(n, GZ_CMD_LOBBY_READY, a, 3);
}

/* Review A of PR 52, M3 and L5: the key hook under AT_JOIN. The factory key exists only once the person
 * readied with the passphrase, and only for the values digest the ready carried; a ready for other
 * values than the lobby's is refused and opens nothing; a lock closes the gate and the key is gone. The
 * contribution key (no factory asked) is the lobby's in any case. Kills sg-at-join-any-digest and the
 * reviewer's a-atjoin-bypass. */
/* A join ready under AT_JOIN (field 24, bound by 26) with the signing engine: the lobby's
 * factory key is derived at the join, as a ready's is (#52), so the key hook gives it for
 * the digest joined for, and not for another (review of #79's join-secret routing). */
static void test_join_ready_key_hook(void)
{
    terms_t t;
    lt_key_t hk;
    uint8_t d[32], other[32], one = 1;
    secp256k1_keypair f, kc;
    whost(&hk);
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node_engine(1, 1, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_UNFINISHED);
    w_node_engine(2, 2, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_UNFINISHED);
    for (int n = 0; n <= 2; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 4, 4, 3010);
    CHECK(host_open(&t, 0) == 200);
    gz_terms_current_digest(t.current, t.cn, d);
    memcpy(other, d, 32);
    other[0] ^= 1;
    {
        h_arg_t j[5] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}, {24, &one, 1}, {26, d, 32}};
        CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, j, 5) == 200);
        /* no key before the terms are here (L-4): the join holds none */
        CHECK(slot(1, &t) && !memcmp(slot(1, &t)->gate_secret, (const uint8_t[32]){0}, 32));
        /* member 2 joined ready for values the host does not have: no key at all, ever */
        h_arg_t j2[5] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}, {24, &one, 1}, {26, other, 32}};
        CHECK(w_cmd(2, GZ_CMD_LOBBY_JOIN, j2, 5) == 200);
    }
    w_run(4000, 100);
    CHECK(slot(2, &t) && slot(2, &t)->lobby.m.have_terms && !memcmp(slot(2, &t)->gate_secret, (const uint8_t[32]){0}, 32));
    slot_t *s = slot(1, &t);
    CHECK(s && N[1].n->sign_on && s->gate_open && s->gate_have && !memcmp(s->gate_digest, d, 32));
    CHECK(gz_sg_keys(N[1].n, t.scope, d, &f, &kc) == 1);          /* the factory key, for the values joined for */
    CHECK(gz_sg_keys(N[1].n, t.scope, other, &f, &kc) == 0);      /* and for no other */
    /* a lock closes the gate: the secret is wiped, every byte, and the key is gone */
    CHECK(w_cmd(1, GZ_CMD_SIGNING_LOCK, NULL, 0) == 200);
    w_run(1000, 100);
    if (s) {
        uint8_t zero[32] = {0};
        CHECK(!s->gate_have && !memcmp(s->gate_secret, zero, 32));
    }
    CHECK(gz_sg_keys(N[1].n, t.scope, d, &f, &kc) == 0);
    w_free(2);
}

static void test_at_join_key_hook(void)
{
    terms_t t;
    uint8_t d[32], other[32];
    secp256k1_keypair f, kc;
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node_engine(1, 1, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_UNFINISHED);
    w_node(2, 2, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(3, 3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    for (int n = 0; n <= 3; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 4, 4, 3000);
    CHECK(host_open(&t, 0) == 200);
    for (int n = 1; n <= 3; n++) CHECK(member_join(n, &t) == 200);
    w_run(4000, 100);
    gz_terms_current_digest(t.current, t.cn, d);
    memcpy(other, d, 32);
    other[0] ^= 1;
    slot_t *s = slot(1, &t);
    CHECK(s && N[1].n->sign_on && !s->gate_have && member_ready(1, &t) == 0);
    if (!s) { w_free(3); return; }
    /* before any ready: no factory key; the contribution key is there */
    CHECK(gz_sg_keys(N[1].n, t.scope, d, &f, &kc) == 0 && gz_sg_keys(N[1].n, t.scope, NULL, NULL, &kc) == 1);
    /* a ready for values the lobby does not have: refused, the gate untouched (L5) */
    CHECK(ready_seen(1, &t, other) == 409 && !s->gate_have && !s->gate_open);
    /* a passphrase ready without the digest: a bad request (scope_cmd sends one since W12) */
    {
        uint8_t u1 = 1;
        h_arg_t r[2] = {{12, t.scope, 32}, {14, &u1, 1}};
        CHECK(w_cmd(1, GZ_CMD_LOBBY_READY, r, 2) == 400 && !s->gate_have);
    }
    /* the ready for the values shown: the gate opens, bound to them */
    CHECK(ready_seen(1, &t, d) == 200 && s->gate_have && memcmp(s->gate_digest, d, 32) == 0);
    w_run(1000, 100);
    CHECK(member_ready(1, &t) == 1);
    CHECK(gz_sg_keys(N[1].n, t.scope, d, &f, &kc) == 1);
    CHECK(gz_sg_keys(N[1].n, t.scope, other, &f, &kc) == 0);     /* a proposal for other values: no key */
    CHECK(gz_sg_keys(N[1].n, t.scope, NULL, &f, &kc) == 0);      /* none named: none */
    /* another ready, for other values, while the gate is open: refused, and the gate keeps its binding */
    CHECK(ready_seen(1, &t, other) == 409 && s->gate_have && memcmp(s->gate_digest, d, 32) == 0);
    CHECK(gz_sg_keys(N[1].n, t.scope, d, &f, &kc) == 1);
    /* a lock: the gate closes and the key is gone */
    CHECK(w_cmd(1, GZ_CMD_SIGNING_LOCK, NULL, 0) == 200);
    w_run(1000, 100);
    CHECK(!s->gate_have && gz_sg_keys(N[1].n, t.scope, d, &f, &kc) == 0);
    no_errors(3);
    w_free(3);
}

/* Review A of PR 52, M2: with the engine, terms whose target's tree needs more transactions than the
 * engine signs (GZ_SIGN_MAX_ITEMS) do not open; a node without the engine (the stand-in) has no cap.
 * T1's width-4 shape offered up to 24 members: 69 transactions at 24 (1 + 4 x 17), past 64; at 8, 23. */
static void test_tree_cap(void)
{
    terms_t t;
    w_reset();
    w_node_engine(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    CHECK(w_start(0) == GZ_OK);
    make_terms(&t, 24, 3, 3000);
    CHECK(host_open(&t, 0) == 400);
    make_terms(&t, 8, 3, 3000);
    CHECK(host_open(&t, 0) == 200);
    no_errors(0);
    w_free(0);
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    CHECK(w_start(0) == GZ_OK);
    make_terms(&t, 24, 3, 3000);
    CHECK(host_open(&t, 0) == 200);
    no_errors(0);
    w_free(0);
}

/* The setting at run time (open point 46, command 0x0403, P4.3): a locked
 * member set to AUTO readies; set back to WHEN_UNLOCKED it says unready and
 * leaves the count; a value out of range is refused and changes nothing. */
static void test_signing_set(void)
{
    terms_t t;
    uint8_t v;
    h_arg_t a[1] = {{12, &v, 1}};
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(1, 1, GZ_MEMBER_SIGNING_WHEN_UNLOCKED, GZ_TEST_SIGN_UNFINISHED);
    w_node(2, 2, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(3, 3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    for (int n = 0; n <= 3; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 4, 4, 3000);
    CHECK(host_open(&t, 0) == 200);
    for (int n = 1; n <= 3; n++) CHECK(member_join(n, &t) == 200);
    w_run(4000, 100);
    CHECK(member_ready(1, &t) == 0 && host_ready(&t) == 2);
    v = 3;
    CHECK(w_cmd(1, GZ_CMD_SIGNING_SET, a, 1) == 400 && N[1].n->cfg.member_signing == GZ_MEMBER_SIGNING_WHEN_UNLOCKED);
    CHECK(w_cmd(1, GZ_CMD_SIGNING_SET, NULL, 0) == 400);
    w_run(1000, 100);
    CHECK(member_ready(1, &t) == 0 && host_ready(&t) == 2);
    v = GZ_MEMBER_SIGNING_AUTO;
    CHECK(w_cmd(1, GZ_CMD_SIGNING_SET, a, 1) == 200 && N[1].n->cfg.member_signing == GZ_MEMBER_SIGNING_AUTO);
    w_run(1000, 100);
    CHECK(member_ready(1, &t) == 1 && host_ready(&t) == 3);
    v = GZ_MEMBER_SIGNING_WHEN_UNLOCKED;
    CHECK(w_cmd(1, GZ_CMD_SIGNING_SET, a, 1) == 200);
    w_run(1000, 100);
    CHECK(member_ready(1, &t) == 0 && host_ready(&t) == 2);
    CHECK(w_cmd(1, GZ_CMD_SIGNING_UNLOCK, NULL, 0) == 200);
    w_run(1000, 100);
    CHECK(member_ready(1, &t) == 1 && host_ready(&t) == 3);
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
    static const uint16_t codes[] = {GZ_CMD_API_PAUSE, GZ_CMD_API_SET_SIGNING, GZ_CMD_API_SET_CONDITIONS, 0x0d7f, 0x010a,
                                     GZ_CMD_LOBBY_OPEN, GZ_CMD_LOBBY_JOIN, GZ_CMD_LOBBY_READY, GZ_CMD_LOBBY_UNREADY,
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
            memset(a, 0, sizeof a);
            uint16_t code = codes[rnd(sizeof codes / sizeof codes[0])];
            for (size_t i = 0; i < na; i++) {
                a[i].type = 12 + 2 * i;
                /* One draw decides scope or record bytes, so a length never
                 * runs past the 32-byte scope. */
                int use_scope = i == 0 && rnd(4);
                a[i].v = use_scope ? scope : rec + rnd(64);
                a[i].len = use_scope ? 32 : rnd(3) == 0 ? rnd(200) : (size_t[]){1, 2, 8, 33, 16}[rnd(5)];
            }
            if (code == GZ_CMD_LOBBY_JOIN && rnd(2)) { /* a join that could be real */
                a[0].type = 12; a[0].v = scope; a[0].len = 32;
                a[1].type = 14; a[1].v = hk.pub; a[1].len = 33;
                a[2].type = 16; a[2].v = ADDR; a[2].len = sizeof ADDR - 1;
                na = 3;
            }
            if (code == GZ_CMD_LOBBY_OPEN && rnd(2)) {
                a[0].type = 12; a[0].v = t[3].outer; a[0].len = t[3].on;
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

/* ---- 6. seats and the connection table (review A of PR 44, M1) --------------------- */

/* The entries the table keeps for seats beside the unseated places. */
#define NP_CONNS_FOR_SEATS (NP_MAX_CONNS - NP_MAX_UNSEATED)

/* The host offers more seats than its table can hold beside the unseated
 * places. An outsider takes seat after seat on fresh keys: the joins past
 * NP_MAX_SEATED are refused like joins to a full lobby, never a node error,
 * and an honest member that holds a seat still gets an entry when it comes
 * back while strangers crowd the table. */
static void test_seat_capacity(void)
{
    terms_t t[8];
    gz_link_t l, honest, sl;
    gz_lobby_msg_t g;
    lt_key_t hk, m1;
    int who = 0, refused = 0;
    whost(&hk);
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    for (int i = 0; i < 8; i++) {
        make_terms(&t[i], 7, 3, 200 + (uint32_t)i);
        CHECK(host_open(&t[i], 1) == 200);
    }
    CHECK(member_join(1, &t[0]) == 200);
    w_run(2000, 100);
    CHECK(host_seated() == 1 && slot(1, &t[0]) != NULL);
    wkey(1, 0, slot(1, &t[0])->key_index, &m1);
    honest = h_link(hk.pub, m1.pub);
    CHECK(host_entry(&honest) == 1);
    /* 8 lobbies of 7 seats: 56 offered, 48 kept for seats. */
    for (int round = 0; round < 7; round++)
        for (int i = 0; i < 8; i++) {
            size_t before = host_seated(), from = NSENT;
            outsider_join(++who, &t[i], &l);
            if (host_seated() == before) {
                refused++;
                CHECK(last_sent(0, from, GZ_KIND_LOBBY_STATUS, l.remote.key, &g) && g.seat_state == GZ_SEAT_REFUSED);
            }
        }
    CHECK(host_seated() == NP_CONNS_FOR_SEATS && refused == 56 - 47);
    no_errors(1);
    /* The honest member's connection drops; strangers crowd in; it comes back. */
    w_peer(0, &honest, 0, 0, 0, 0);
    for (int k = 0; k < 24; k++) stranger(100 + k, k & 1, &sl);
    w_peer(0, &honest, 1, 0, 0, 0);
    CHECK(host_entry(&honest) == 1);
    no_errors(1);
    w_free(1);
}

/* "Ready" with the passphrase that the lobby refuses leaves the gate as it
 * was: closed, its scoped secret forgotten (review A of PR 44, L3). */
static void test_gate_refused_ready(void)
{
    terms_t t;
    int forgets;
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    w_node(1, 1, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_FUNDING);
    for (int n = 0; n <= 1; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 3, 3, 4000);
    CHECK(host_open(&t, 0) == 200);
    CHECK(member_join(1, &t) == 200 && slot(1, &t) != NULL && !slot(1, &t)->gate_open);
    forgets = FORGETS[1];
    /* Not connected yet, so no terms and no seat to ready: refused. */
    CHECK(scope_cmd(1, GZ_CMD_LOBBY_READY, &t, 1) == 409);
    CHECK(!slot(1, &t)->gate_open && FORGETS[1] == forgets + 1);
    no_errors(1);
    w_free(1);
}

/* ---- 7. a slot left out at a start keeps its place (review B of PR 44, H1) ---------- */

/* The key port cannot give a slot's keys at a start, and gives them again
 * right after it: the slot is a placeholder that keeps its scope and its
 * place, the person is told, and the same lobby joined or opened again, or
 * eight others, is refused. So the next start, with the keys, loads the same
 * journal the same way: P1 (rejoin), P2 (eight others) and P3 (reopen) of
 * the review, each followed by that start. */
static void test_left_out(void)
{
    terms_t t[9];
    size_t mark;
    int ok = 0;
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    for (int i = 0; i < 9; i++) make_terms(&t[i], 3, 3, 600 + (uint32_t)i);
    for (int i = 0; i < 8; i++) CHECK(host_open(&t[i], 0) == 200);
    CHECK(member_join(1, &t[0]) == 200);
    w_run(2000, 100);
    CHECK(slot(1, &t[0]) && slot(1, &t[0])->lobby.m.joined);
    /* P1: the member. */
    PUB_FAIL[1] = 1;
    mark = N[1].n_log;
    CHECK(w_restart(1) == GZ_OK && slot(1, &t[0]) == NULL && N[1].n->np.skipped_slots == 1);
    PUB_FAIL[1] = 0;
    CHECK(said(1, mark, "attention lobby-left-out scope=") == 1);
    {   /* and its attention item, emitted at the start (P6a) */
        char aid[80];
        const char *id = gz_api_local_id(N[1].n, t[0].scope);
        snprintf(aid, sizeof aid, "att_%s", id ? id + 4 : "");
        CHECK(id && vf8(view_of(1, GZ_VIEW_ATTENTION, aid), GZ_VAT_CODE) == GZ_ATT_LOBBY_LEFT_OUT);
    }
    CHECK(member_join(1, &t[0]) == 503 && scope_cmd(1, GZ_CMD_LOBBY_READY, &t[0], 0) == 503);
    CHECK(w_restart(1) == GZ_OK && slot(1, &t[0]) != NULL && N[1].n->np.skipped_slots == 0);
    w_run(3000, 100);
    CHECK(slot(1, &t[0]) && slot(1, &t[0])->lobby.m.joined);
    /* P2: the member again; eight other lobbies: seven places are free. */
    PUB_FAIL[1] = 1;
    CHECK(w_restart(1) == GZ_OK && slot(1, &t[0]) == NULL);
    PUB_FAIL[1] = 0;
    for (int i = 1; i < 9; i++) ok += member_join(1, &t[i]) == 200;
    CHECK(ok == 7);
    CHECK(w_restart(1) == GZ_OK && slot(1, &t[0]) != NULL && N[1].n->np.skipped_slots == 0);
    /* P3: the host. */
    PUB_FAIL[0] = 1;
    mark = N[0].n_log;
    CHECK(w_restart(0) == GZ_OK && host_state(&t[0]) == -1 && N[0].n->np.skipped_slots == 8);
    PUB_FAIL[0] = 0;
    CHECK(said(0, mark, "attention lobby-left-out scope=") == 8);
    CHECK(host_open(&t[0], 0) == 409 && host_open(&t[8], 0) == 409); /* no place: the placeholders hold all eight */
    CHECK(scope_cmd(0, GZ_CMD_LOBBY_CANCEL, &t[1], 0) == 503);
    CHECK(w_restart(0) == GZ_OK && host_state(&t[0]) == GZ_LOBBY_OPEN && N[0].n->np.skipped_slots == 0);
    /* A placeholder whose lobby ended before the start is Free at it. */
    CHECK(scope_cmd(0, GZ_CMD_LOBBY_CANCEL, &t[2], 0) == 200);
    PUB_FAIL[0] = 1;
    CHECK(w_restart(0) == GZ_OK);
    PUB_FAIL[0] = 0;
    CHECK(host_open(&t[8], 0) == 200);
    CHECK(w_restart(0) == GZ_OK && N[0].n->np.skipped_slots == 0 && host_state(&t[8]) == GZ_LOBBY_OPEN &&
          host_state(&t[2]) == -1);
    no_errors(1);
    w_free(1);
}

/* ---- 8. a Node record with a field this program does not know ------------------------ */

/* slot_opened with an even field this program does not know (a newer
 * program requires it), or a key index whose pair would wrap: damage, so the
 * start refuses it. An odd unknown field is skipped (review B of PR 44, L3,
 * L4). A key index above 0xfffffff0, which allocation never reaches, is
 * refused too, as a second defence after the sealed journal: near the top
 * the contribution index would meet the program's reserved indexes and the
 * factory index wrap (cases 4 and 5; 0xfffffff0 itself still loads, case 6). */
static void test_node_record_fields(void)
{
    lt_key_t hk;
    terms_t t;
    whost(&hk);
    w_reset();
    make_terms(&t, 3, 3, 700);
    static const uint32_t index_of[7] = {1, 0xffffffffu, 1, 1, 0xfffffffeu, 0xfffffff1u, 0xfffffff0u};
    for (int k = 0; k < 7; k++) {
        h_t *x = &N[SCRATCH];
        uint8_t rec[300], v[4];
        size_t at = 0;
        gz_status_t st;
        w_node(SCRATCH, 5, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
        gz_put_u32(v, 1);
        gz_rec_put(rec, sizeof rec, &at, 2, v, 4);
        gz_rec_put(rec, sizeof rec, &at, 4, t.scope, 32);
        v[0] = 0;
        gz_rec_put(rec, sizeof rec, &at, 6, v, 1);
        gz_rec_put(rec, sizeof rec, &at, 8, hk.pub, 33);
        gz_rec_put(rec, sizeof rec, &at, 10, (const uint8_t *)ADDR, sizeof ADDR - 1);
        gz_put_u32(v, 0);
        gz_rec_put(rec, sizeof rec, &at, 12, v, 4);
        gz_put_u32(v, index_of[k]);
        gz_rec_put(rec, sizeof rec, &at, 14, v, 4);
        v[0] = 1;
        gz_rec_put(rec, sizeof rec, &at, 22, v, 1);
        if (k == 2) gz_rec_put(rec, sizeof rec, &at, 26, v, 1); /* unknown, even (24 is the conditions' version now) */
        if (k == 4) gz_rec_put(rec, sizeof rec, &at, 24, v, 1); /* the conditions' version, not 4 bytes */
        if (k == 3) gz_rec_put(rec, sizeof rec, &at, 25, v, 1); /* unknown, odd */
        h_add_batch(x, 1, 1, GZ_RECORD_SLOT_OPENED, rec, at);
        x->incarnation = 1;
        h_new_node(x);
        st = w_start(SCRATCH);
        if (k == 1 || k == 2 || k == 4 || k == 5) {
            CHECK(st == GZ_ERR_CORRUPT);   /* the start refuses: no slot is loaded */
        } else {
            CHECK(st == GZ_OK);
            CHECK(gz_route_slot_by_scope(x->n, t.scope) >= 0);
        }
        ALIVE[SCRATCH] = 0;
        NT[SCRATCH] = 0;
        for (int i = 0; i < 64; i++)
            if (C[i].used && C[i].node == SCRATCH) C[i].used = 0;
        h_free(x);
        memset(x, 0, sizeof *x);
    }
    CHECK(ERRORS == 0);
}

/* ---- 9. a timer set in the step that ends a lobby (review B of PR 44, L7) ------------- */

/* A cancel within a second of a seat's last lobby_status: the lobby wants
 * to send the final status a second later and sets a timer in the very step
 * that ends its slot. The slot is Free, and the timer is not set. */
static void test_timer_of_ended_lobby(void)
{
    terms_t t;
    uint16_t g;
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 800);
    CHECK(host_open(&t, 0) == 200 && member_join(1, &t) == 200);
    w_run(400, 100);
    CHECK(slot(0, &t) != NULL && slot(1, &t) && slot(1, &t)->lobby.m.joined);
    g = slot(0, &t)->gen;
    CHECK(scope_cmd(0, GZ_CMD_LOBBY_CANCEL, &t, 0) == 200 && slot(0, &t) == NULL);
    for (int k = 0; k < NT[0]; k++) CHECK(!((T[0][k].id >> 48) == GZ_AREA_LOBBY && ((T[0][k].id >> 32) & 0xffff) == g));
    w_run(3000, 100);
    no_errors(1);
    w_free(1);
}

/* ---- 10. the view and the API engine (P6a) ------------------------------------------ */

static const char *lid(int n, const terms_t *t)
{
    slot_t *s = slot(n, t);
    return s ? s->view.local_id : "";
}

/* An API request, as the API server sends it: an id, a method, a path, a
 * digest (here 32 bytes of `dig`), the command and its arguments. */
static int w_req(int n, uint16_t code, const char *rid, const char *path, uint8_t dig, const h_arg_t *args, size_t na)
{
    static uint8_t buf[8192];
    uint8_t c2[2], d[32];
    size_t at = 0, mark;
    if (N[n].n_log > H_MAX_LOG - 2000) N[n].n_log = 0; /* the log is a window, as in w_event */
    mark = N[n].n_log;
    int status = 0;
    gz_event_t ev;
    memset(d, dig, 32);
    gz_put_u16(c2, code);
    gz_rec_put(buf, sizeof buf, &at, GZ_CMD_REC_REQUEST_ID, (const uint8_t *)rid, strlen(rid));
    gz_rec_put(buf, sizeof buf, &at, GZ_CMD_REC_METHOD, (const uint8_t *)"POST", 4);
    gz_rec_put(buf, sizeof buf, &at, GZ_CMD_REC_PATH, (const uint8_t *)path, strlen(path));
    gz_rec_put(buf, sizeof buf, &at, GZ_CMD_REC_DIGEST, d, 32);
    gz_rec_put(buf, sizeof buf, &at, GZ_CMD_REC_COMMAND, c2, 2);
    for (size_t i = 0; i < na; i++) gz_rec_put(buf, sizeof buf, &at, args[i].type, args[i].v, args[i].len);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_USER_COMMAND;
    ev.u.user.bytes.data = buf;
    ev.u.user.bytes.len = at;
    if (w_event(n, &ev) != GZ_OK) return -1;
    for (size_t i = mark; i < N[n].n_log; i++)
        if (N[n].log[i].a.kind == GZ_ACTION_NOTIFY && !strncmp(N[n].log[i].text, "result ", 7)) status = atoi(N[n].log[i].text + 7);
    return status;
}

/* Kinds 2, 3 and 1: a member's lobby, a hosted lobby, the status; through
 * Funding; then every node restarted, and every object emitted again, no
 * older than before (rule 7). */
static void test_views(void)
{
    wview_t *w;
    gz_bytes_t v;
    two_lobbies(GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    w_run(3000, 100);
    /* Every lobby has a local id, saved in its slot's first batch (7.3, 7.5). */
    CHECK(strncmp(lid(0, &TA), "lob_", 4) == 0 && strlen(lid(0, &TA)) == 20 && strcmp(lid(0, &TA), lid(0, &TB)) != 0);
    CHECK(strncmp(lid(1, &TA), "lob_", 4) == 0 && h_records_of(&N[1], GZ_RECORD_LOCAL_IDS) == 2);
    /* The member's lobby. */
    w = view_of(1, GZ_VIEW_LOBBY, lid(1, &TA));
    CHECK(w && vf(w, GZ_VLB_FINGERPRINT, &v) && v.len == 32 && !memcmp(v.data, TA.scope, 32));
    CHECK(vf(w, GZ_VLB_HOST_KEY, &v) && v.len == 33 && vf(w, GZ_VLB_HOST_ADDRESS, &v) && v.len == sizeof ADDR - 1);
    CHECK(vf8(w, GZ_VLB_SEAT) == GZ_VSEAT_READY && vf(w, GZ_VLB_READY_VERSION, &v) && v.len == 4);
    CHECK(vf(w, GZ_VLB_GATE, &v) && v.len == 10 && v.data[0] == GZ_GATE_NONE && v.data[1] == 1);
    CHECK(vf(w, GZ_VLB_OUTER, &v) && v.len == TA.on && !memcmp(v.data, TA.outer, TA.on));
    CHECK(vf(w, GZ_VLB_FIT, &v) && v.len == 18 && v.data[0] == GZ_VFIT_FITS && v.data[1] == 0);
    CHECK(!vf(w, GZ_VLB_OUTCOME, &v) && !vf(w, GZ_VLB_LOCKED_SINCE, &v) && vf(w, GZ_VLB_SINCE, &v));
    CHECK(vf8(w, GZ_VLB_DOING) == GZ_DOING_READY_CHECK || vf8(w, GZ_VLB_DOING) == GZ_DOING_IN_LOBBY_WAITING);
    /* The hosted lobby: three seats, each Ready, in order of joining. */
    w = view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &TA));
    CHECK(w && vf(w, GZ_VHL_COUNTS, &v) && v.len == 8 && gz_get_u16(v.data) == 3 && gz_get_u16(v.data + 2) == 3 &&
          gz_get_u16(v.data + 4) == 0 && gz_get_u16(v.data + 6) == 0);
    CHECK(vf(w, GZ_VHL_SEATS, &v) && v.len == 3 * GZ_VHL_SEAT_LEN);
    for (int k = 0; k < 3 && v.len == 3 * GZ_VHL_SEAT_LEN; k++) {
        lt_key_t mk;
        wkey(k + 1, 0, slot(k + 1, &TA)->key_index, &mk);
        CHECK(!memcmp(v.data + k * GZ_VHL_SEAT_LEN, mk.pub, 33) && v.data[k * GZ_VHL_SEAT_LEN + 33] == GZ_VSEAT_READY &&
              (v.data[k * GZ_VHL_SEAT_LEN + 34] & GZ_VHL_F_CONNECTED));
    }
    CHECK(vf8(w, GZ_VHL_LISTED) == 1 && vf8(view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &TB)), GZ_VHL_LISTED) == 0);
    /* The status: the role, both lobbies, the signing setting in force. */
    w = view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
    CHECK(w && vf8(w, GZ_VST_ROLE) == 0 && vf(w, GZ_VST_SIGNING, &v) && v.len == 7 && v.data[0] == GZ_MEMBER_SIGNING_AUTO &&
          v.data[1] == 0xff && vf(w, GZ_VST_PAUSE, &v) && v.data[0] == GZ_PAUSE_OFF);
    CHECK(vf(w, GZ_VST_LOBBIES, &v) && v.len == 2 * (12 + 20) && vf(w, GZ_VST_DOING, &v) && v.len == 30);
    CHECK(vf8(view_of(0, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID), GZ_VST_ROLE) == 1);
    /* Funding: the round and the outcome. */
    w_run(32000, 500);
    w = view_of(1, GZ_VIEW_LOBBY, lid(1, &TA));
    CHECK(vf8(w, GZ_VLB_ROUND) == GZ_LOBBY_FUNDING && vf(w, GZ_VLB_OUTCOME, &v) && v.data[0] == GZ_OUTCOME_STARTED &&
          vf8(w, GZ_VLB_DOING) == GZ_DOING_AWAITING_FUNDING);
    w = view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &TB));
    CHECK(vf8(w, GZ_VHL_STAGE) == GZ_LOBBY_FUNDING && vf(w, GZ_VHL_ROUND, &v) && v.len == 9 && v.data[0] == 1);
    no_errors(4);
    /* A crash of every node (kill -9): the program forgets the view; each
     * start emits every object again, newer than before (rule 7). */
    for (int n = 0; n <= 4; n++) CHECK(w_restart(n) == GZ_OK);
    CHECK(view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &TA)) && view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &TB)));
    CHECK(view_of(1, GZ_VIEW_LOBBY, lid(1, &TA)) && view_of(1, GZ_VIEW_LOBBY, lid(1, &TB)) &&
          view_of(4, GZ_VIEW_LOBBY, lid(4, &TB)) && view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID));
    CHECK(vf8(view_of(1, GZ_VIEW_LOBBY, lid(1, &TA)), GZ_VLB_ROUND) == GZ_LOBBY_FUNDING);
    no_errors(4);
    w_free(4);
}

/* A member whose conditions refuse the terms: its lobby's last object says
 * so, with the failing condition and both values (14.1, refused_at_check). */
static void test_view_refusal(void)
{
    terms_t t;
    uint8_t cond[27];
    lt_key_t hk;
    gz_bytes_t v;
    const char *id;
    wview_t *w;
    whost(&hk);
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 900);
    CHECK(host_open(&t, 0) == 200);
    memset(cond, 0, sizeof cond);
    gz_put_u16(cond + 23, 50);   /* the terms' minimum must be at least 50 */
    h_arg_t a[4] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}, {18, cond, sizeof cond}};
    CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, a, 4) == 200);
    id = gz_api_local_id(N[1].n, t.scope);
    CHECK(id != NULL);
    w_run(3000, 100);
    /* It does not join terms its conditions refuse; the object says which term, with both values. */
    w = view_of(1, GZ_VIEW_LOBBY, id ? id : "");
    CHECK(w && vf8(w, GZ_VLB_SEAT) != GZ_VSEAT_JOINED && vf8(w, GZ_VLB_SEAT) != GZ_VSEAT_READY);
    CHECK(vf(w, GZ_VLB_FIT, &v) && v.len == 18 && v.data[0] == GZ_VFIT_DOES_NOT_FIT && v.data[1] == GZ_TT_MINIMUM &&
          gz_get_u64(v.data + 2) == 50 && gz_get_u64(v.data + 10) == 3);
    no_errors(1);
    w_free(1);
}

/* The host's side: a seat that refused (unready reason 1, 15.3), counted and
 * raised as attention; the member's side behind a closed gate: locked, with
 * its attention item, which goes once the person readies with the passphrase. */
static void test_view_seats(void)
{
    terms_t t;
    lt_key_t hk, m1;
    gz_link_t l1;
    gz_bytes_t v;
    wview_t *w;
    char aid[80];
    uint8_t rec[4] = {0x01, 0x02, 0x00, 0x01};
    whost(&hk);
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    w_node(1, 1, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_FUNDING);
    w_node(2, 2, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    for (int n = 0; n <= 2; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 3, 3, 950);
    CHECK(host_open(&t, 0) == 200 && member_join(1, &t) == 200 && member_join(2, &t) == 200);
    w_run(3000, 100);
    /* Member 1 is locked (AT_JOIN, no passphrase yet). */
    w = view_of(1, GZ_VIEW_LOBBY, lid(1, &t));
    CHECK(w && vf8(w, GZ_VLB_SEAT) == GZ_VSEAT_JOINED && vf(w, GZ_VLB_LOCKED_SINCE, &v) && vf(w, GZ_VLB_GATE, &v) &&
          v.data[0] == GZ_GATE_PER_LOBBY && v.data[1] == 0 && vf8(w, GZ_VLB_DOING) == GZ_DOING_IN_LOBBY_NOT_COUNTED);
    snprintf(aid, sizeof aid, "att_%s", lid(1, &t) + 4);
    w = view_of(1, GZ_VIEW_ATTENTION, aid);
    CHECK(w && !w->gone && vf8(w, GZ_VAT_CODE) == GZ_ATT_UNLOCK_TO_TAKE_PART);
    w = view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &t));
    CHECK(w && vf(w, GZ_VHL_COUNTS, &v) && gz_get_u16(v.data) == 2 && gz_get_u16(v.data + 2) == 1);
    /* The passphrase: the gate opens for the readied values; the item goes. */
    CHECK(scope_cmd(1, GZ_CMD_LOBBY_READY, &t, 1) == 200);
    w_run(1000, 100);
    w = view_of(1, GZ_VIEW_LOBBY, lid(1, &t));
    CHECK(w && vf8(w, GZ_VLB_SEAT) == GZ_VSEAT_READY && vf(w, GZ_VLB_GATE, &v) && v.len == 42 && v.data[1] == 1 &&
          !vf(w, GZ_VLB_LOCKED_SINCE, &v));
    w = view_of(1, GZ_VIEW_ATTENTION, aid);
    CHECK(w && w->gone);
    /* Member 2 refuses at Open (unready reason 1): the host shows it. */
    wkey(2, 0, slot(2, &t)->key_index, &m1);
    l1 = h_link(hk.pub, m1.pub);
    w_msg(0, &l1, GZ_KIND_UNREADY, t.scope, rec, sizeof rec);
    w = view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &t));
    CHECK(w && vf(w, GZ_VHL_COUNTS, &v) && gz_get_u16(v.data + 6) == 1 && vf(w, GZ_VHL_SEATS, &v) && v.len == 2 * GZ_VHL_SEAT_LEN);
    CHECK(v.len == 2 * GZ_VHL_SEAT_LEN && v.data[GZ_VHL_SEAT_LEN + 33] == GZ_VSEAT_REFUSED &&
          (v.data[GZ_VHL_SEAT_LEN + 34] & GZ_VHL_F_REFUSED) && gz_get_u16(v.data + GZ_VHL_SEAT_LEN + 35) == 1 &&
          v.data[GZ_VHL_SEAT_LEN + 37] == GZ_STAGE_OPEN);
    snprintf(aid, sizeof aid, "att_%s", lid(0, &t) + 4);
    w = view_of(0, GZ_VIEW_ATTENTION, aid);
    CHECK(w && !w->gone && vf8(w, GZ_VAT_CODE) == GZ_ATT_MEMBER_REFUSED);
    no_errors(2);
    w_free(2);
}

/* Request ids (7.4): saved in the batch of the action's first save, before
 * the result; a replay answers the saved status and does nothing; the same
 * id for another request is refused; a restart keeps them. */
static void test_api_requests(void)
{
    terms_t t;
    size_t nb;
    uint8_t l = 0;
    static const uint32_t with[] = {GZ_RECORD_SLOT_OPENED, GZ_RECORD_REQUEST_ID, GZ_RECORD_LOCAL_IDS};
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 1000);
    h_arg_t a[3] = {{12, t.outer, t.on}, {14, t.current, t.cn}, {16, &l, 1}};
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "Jq4mT9cV2xE7nR0aW5zK", "/api/v1/host/lobbies", 1, a, 3) == 200);
    CHECK(h_records_of(&N[0], GZ_RECORD_REQUEST_ID) == 1 && batch_with(0, with, 3));
    nb = N[0].n_batches;
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "Jq4mT9cV2xE7nR0aW5zK", "/api/v1/host/lobbies", 1, a, 3) == 200 && N[0].n_batches == nb);
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "Jq4mT9cV2xE7nR0aW5zK", "/api/v1/host/lobbies", 2, a, 3) == 409 && N[0].n_batches == nb);
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "short", "/api/v1/host/lobbies", 1, a, 3) == 400 && N[0].n_batches == nb);
    CHECK(w_restart(0) == GZ_OK);
    nb = N[0].n_batches;
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "Jq4mT9cV2xE7nR0aW5zK", "/api/v1/host/lobbies", 1, a, 3) == 200 && N[0].n_batches == nb);
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "Jq4mT9cV2xE7nR0aW5zK", "/api/v1/host/lobbies", 3, a, 3) == 409);
    /* A refused call saves nothing, so it keeps no id: the same id acts later. */
    CHECK(w_req(0, GZ_CMD_LOBBY_CANCEL, "Kq4mT9cV2xE7nR0aW5zK", "/api/v1/host/lobbies/x/cancel", 1, a, 1) == 404 &&
          N[0].n_batches == nb);
    {
        h_arg_t c1[1] = {{12, t.scope, 32}};
        CHECK(w_req(0, GZ_CMD_LOBBY_CANCEL, "Kq4mT9cV2xE7nR0aW5zK", "/api/v1/host/lobbies/x/cancel", 1, c1, 1) == 200 &&
              N[0].n_batches > nb && h_records_of(&N[0], GZ_RECORD_REQUEST_ID) == 2);
    }
    no_errors(1);
    w_free(1);
}

/* Pause (11.3) and the signing setting (14.3). */
static void test_api_pause_and_signing(void)
{
    terms_t t, u, d;
    uint8_t on = 1, off = 0, sv[4], ms = GZ_MEMBER_SIGNING_AT_JOIN;
    gz_bytes_t v;
    wview_t *w;
    const char *did;
    w_world(3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 1100);
    make_terms(&u, 3, 3, 1200);
    make_terms(&d, 3, 3, 0);    /* its deadline is ten minutes away */
    CHECK(host_open(&t, 0) == 200 && host_open(&u, 0) == 200 && host_open(&d, 0) == 200);
    CHECK(member_join(1, &t) == 200);
    w_run(2000, 100);
    CHECK(slot(1, &t) && slot(1, &t)->lobby.m.joined);
    /* The member pauses: saved first, then its lobby is left; joins refused. */
    {
        h_arg_t p1[1] = {{12, &on, 1}};
        CHECK(w_req(1, GZ_CMD_API_PAUSE, "Pq4mT9cV2xE7nR0aW5zK", "/api/v1/pause", 1, p1, 1) == 200);
    }
    w_run(2000, 100);
    CHECK(slot(1, &t) == NULL && h_records_of(&N[1], GZ_RECORD_PAUSE) == 1 && h_records_of(&N[1], GZ_RECORD_REQUEST_ID) == 1);
    CHECK(member_join(1, &u) == 409 && slot(1, &u) == NULL);
    w = view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
    CHECK(vf(w, GZ_VST_PAUSE, &v) && v.data[0] == GZ_PAUSE_ON);
    /* It survives a restart. */
    CHECK(w_restart(1) == GZ_OK && member_join(1, &u) == 409);
    CHECK(vf(view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID), GZ_VST_PAUSE, &v) && v.data[0] == GZ_PAUSE_ON);
    {
        uint8_t pv[4];
        h_arg_t p0[1] = {{12, &off, 1}};
        /* A resume names the pause's version (review of PR 75, M1): without it, 409. */
        CHECK(w_req(1, GZ_CMD_API_PAUSE, "Rq4mT9cV2xE7nR0aW5zJ", "/api/v1/pause", 1, p0, 1) == 409);
        gz_put_u32(pv, N[1].n->api.pause_version);
        h_arg_t p0v[2] = {{12, &off, 1}, {14, pv, 4}};
        CHECK(w_req(1, GZ_CMD_API_PAUSE, "Rq4mT9cV2xE7nR0aW5zK", "/api/v1/pause", 1, p0v, 2) == 200);
    }
    CHECK(member_join(1, &u) == 200);
    /* A paused host runs no ready check, even with its target ready. */
    {
        h_arg_t p1[1] = {{12, &on, 1}};
        CHECK(w_req(0, GZ_CMD_API_PAUSE, "Sq4mT9cV2xE7nR0aW5zK", "/api/v1/pause", 1, p1, 1) == 200);
    }
    CHECK(member_join(2, &u) == 200 && member_join(3, &u) == 200);
    w_run(5000, 100);
    CHECK(host_ready(&u) == 3 && host_state(&u) == GZ_LOBBY_OPEN);
    CHECK(vf8(view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &u)), GZ_VHL_PAUSED) == 1);
    /* Its deadline comes while paused: cancelled, the host's choice (reason 2). */
    did = lid(0, &d);
    {
        char id[GZ_LOCAL_ID_MAX + 1];
        snprintf(id, sizeof id, "%s", did);
        w_run(610000, 5000);
        CHECK(host_state(&d) == -1);
        w = view_of(0, GZ_VIEW_HOST_LOBBY, id);
        CHECK(vf8(w, GZ_VHL_STAGE) == GZ_LOBBY_CANCELLED && vf(w, GZ_VHL_END_REASON, &v) && gz_get_u16(v.data) == 2);
    }
    {
        uint8_t pv[4];
        gz_put_u32(pv, N[0].n->api.pause_version);
        h_arg_t p0[2] = {{12, &off, 1}, {14, pv, 4}};
        CHECK(w_req(0, GZ_CMD_API_PAUSE, "Tq4mT9cV2xE7nR0aW5zK", "/api/v1/pause", 1, p0, 2) == 200);
    }
    w_run(3000, 100);
    CHECK(host_state(&u) >= GZ_LOBBY_READY_CHECK || host_state(&u) == -1);
    /* The signing setting: saved, pending until the next start. */
    gz_put_u32(sv, 0);
    {
        h_arg_t s1[2] = {{12, &ms, 1}, {14, sv, 4}};
        CHECK(w_req(1, GZ_CMD_API_SET_SIGNING, "Uq4mT9cV2xE7nR0aW5zK", "/api/v1/signing", 1, s1, 2) == 200);
        CHECK(w_req(1, GZ_CMD_API_SET_SIGNING, "Vq4mT9cV2xE7nR0aW5zK", "/api/v1/signing", 1, s1, 2) == 409);
    }
    w = view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
    CHECK(vf(w, GZ_VST_SIGNING, &v) && v.data[0] == GZ_MEMBER_SIGNING_AUTO && v.data[1] == GZ_MEMBER_SIGNING_AT_JOIN &&
          gz_get_u32(v.data + 2) == 1 && N[1].n->cfg.member_signing == GZ_MEMBER_SIGNING_AUTO);
    CHECK(w_restart(1) == GZ_OK && N[1].n->cfg.member_signing == GZ_MEMBER_SIGNING_AT_JOIN);
    w = view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
    CHECK(vf(w, GZ_VST_SIGNING, &v) && v.data[0] == GZ_MEMBER_SIGNING_AT_JOIN && v.data[1] == 0xff);
    no_errors(3);
    w_free(3);
}

/* A pair with an invalid child (the key port gives no key at one index):
 * the next pair is used, never the same index twice, for a host and a
 * member, at either key of the pair. */
static void test_key_skip(void)
{
    terms_t t, u;
    uint32_t h0, h1;
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 1300);
    make_terms(&u, 3, 3, 1310);
    h0 = N[0].n->np.highest_index;
    BAD_INDEX[0] = h0 + 1;               /* the contribution key */
    CHECK(host_open(&t, 0) == 200 && slot(0, &t) && slot(0, &t)->key_index == h0 + 3);
    h1 = N[1].n->np.highest_index;
    BAD_INDEX[1] = h1 + 2;               /* the factory key */
    CHECK(member_join(1, &t) == 200 && slot(1, &t) && slot(1, &t)->key_index == h1 + 3);
    w_run(2000, 100);
    CHECK(slot(1, &t)->lobby.m.joined && host_state(&t) == GZ_LOBBY_OPEN);
    /* The skipped indexes are never used later. */
    BAD_INDEX[0] = 0;
    CHECK(host_open(&u, 0) == 200 && slot(0, &u)->key_index > slot(0, &t)->key_index + 1);
    no_errors(1);
    w_free(1);
}

/* A restore draws its new epoch until the key port says the wallet can
 * derive it, before key_epoch is saved (review R2-8): here the first draw
 * is refused. */
static uint32_t EPOCH_SEEN[4];
static int EPOCH_CALLS;
static int w_epoch_ok(void *ctx, uint32_t epoch)
{
    (void)ctx;
    if (EPOCH_CALLS < 4) EPOCH_SEEN[EPOCH_CALLS] = epoch;
    return EPOCH_CALLS++ > 0;
}

static void test_epoch_ok(void)
{
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    N[0].cfg.keys.epoch_ok = w_epoch_ok;
    h_new_node(&N[0]);
    N[0].restored = 1;
    EPOCH_CALLS = 0;
    CHECK(w_start(0) == GZ_OK && h_records_of(&N[0], GZ_RECORD_KEY_EPOCH) == 1);
    CHECK(EPOCH_CALLS == 2 && N[0].n->np.epoch == EPOCH_SEEN[1] && N[0].n->np.epoch != EPOCH_SEEN[0]);
    no_errors(0);
    w_free(0);
}

/* A record of the API's area that this program does not know: even, a newer
 * program's, stops the start; odd is skipped (journal.md 9.1). */
static void test_api_unknown_record(void)
{
    for (int k = 0; k < 2; k++) {
        h_t *x = &N[SCRATCH];
        w_node(SCRATCH, 5, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
        static const uint8_t tlv[3] = {0x02, 0x01, 'x'}; /* a TLV stream: type 2, one byte (L6: no raw control bytes in a literal) */
        h_add_batch(x, 1, 1, k ? 0x000d0041u : 0x000d0040u, tlv, sizeof tlv);
        x->incarnation = 1;
        h_new_node(x);
        CHECK(w_start(SCRATCH) == (k ? GZ_OK : GZ_ERR_CORRUPT));
        ALIVE[SCRATCH] = 0;
        NT[SCRATCH] = 0;
        h_free(x);
        memset(x, 0, sizeof *x);
    }
}

/* ---- review A of PR 55 ------------------------------------------------------------ */

/* A field of node n's last command result, as text. */
static int res_text(int n, uint64_t type, char *out, size_t cap)
{
    gz_bytes_t b = {RES[n], RES_LEN[n]}, v;
    out[0] = 0;
    if (gz_rec_find(b, type, &v) != 1 || v.len >= cap) return 0;
    memcpy(out, v.data, v.len);
    out[v.len] = 0;
    return 1;
}

/* A pause or resume as the interface sends it: with the version it read. */
static int w_pause(int n, int on, const char *rid)
{
    uint8_t v = (uint8_t)on, pv[4];
    gz_put_u32(pv, N[n].n->api.pause_version);
    h_arg_t a[2] = {{12, &v, 1}, {14, pv, 4}};
    return w_req(n, GZ_CMD_API_PAUSE, rid, "/api/v1/pause", 1, a, 2);
}

/* The member's running stand-in round in lobby t, or NULL. */
static ss_round_t *ss_of(int n, const terms_t *t)
{
    for (int k = 0; k < SS_MAX; k++) {
        ss_round_t *r = &N[n].n->ss.r[k];
        if (r->used && !r->ended && !memcmp(r->scope, t->scope, 32)) return r;
    }
    return NULL;
}

/* A host and `members` AUTO members in lobby t (target 3); member 1's
 * stand-in reports `m1` after `delay` ms; the host's never reports, so that
 * no Funding of the host's reaches member 1 before its own outcome. */
static void pause_world(terms_t *t, int members, uint32_t plus, uint32_t m1, uint32_t delay)
{
    w_world(members, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    N[0].n->cfg.test_sign_outcome = GZ_TEST_SIGN_UNFINISHED;
    N[1].n->cfg.test_sign_outcome = m1;
    N[1].n->cfg.test_sign_delay_ms = delay;
    make_terms(t, 3, 3, plus);
    CHECK(host_open(t, 0) == 200);
    for (int n = 1; n <= members; n++) CHECK(member_join(n, t) == 200);
}

/* Until member 1's lobby t has a round in the stand-in (it was chosen and
 * the round was handed over), one turn at a time: T1's ready window is 30 s. */
static int until_round(const terms_t *t)
{
    for (int k = 0; k < 2400 && !ss_of(1, t); k++) {
        NOW += 25;
        w_turn();
    }
    return ss_of(1, t) != NULL;
}

/* Each row of local-api.md 11.3's table (H1, H2). */
static void test_pause_rows(void)
{
    terms_t t, u;
    char p[2048], id[GZ_LOCAL_ID_MAX + 1];
    size_t mark;
    gz_bytes_t v;
    wview_t *w;
    /* Ready, lobby Open (two of three seats): left, reason 2; 200. */
    pause_world(&t, 2, 1400, GZ_TEST_SIGN_FUNDING, 50);
    w_run(2000, 100);
    CHECK(member_ready(1, &t) == 1 && host_state(&t) == GZ_LOBBY_OPEN);
    snprintf(id, sizeof id, "%s", lid(1, &t));
    mark = NSENT;
    CHECK(w_pause(1, 1, "PauseOpenReady0001") == 200 && slot(1, &t) == NULL && sent_count(1, mark, GZ_KIND_LEAVE) == 1);
    snprintf(p, sizeof p, "{\"left_lobbies\":[\"%s\"],\"aborted_lobbies\":[],\"held_lobbies\":[]}", id);
    {
        char q[2048];
        CHECK(res_text(1, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, p));
    }
    CHECK(N[1].n->api.pause == GZ_PAUSE_ON && N[1].n->api.n_held == 0);
    /* While on, a ready is refused as a join is (rv-paused-ready-allowed). */
    {
        terms_t r2;
        make_terms(&r2, 3, 3, 1401);
        CHECK(host_open(&r2, 0) == 200);
        CHECK(member_join(2, &r2) == 200 && scope_cmd(1, GZ_CMD_LOBBY_READY, &r2, 0) == 409);
    }
    no_errors(2);
    w_free(2);

    /* In a ready check, answered, no start yet (RV2): it leaves, 200, held
     * for nothing; the host never starts a round with it. */
    pause_world(&t, 3, 1410, GZ_TEST_SIGN_FUNDING, 50);
    for (int k = 0; k < 400; k++) {
        slot_t *s = slot(1, &t);
        if (s && s->lobby.m.has_answered && !s->lobby.m.start_len) break;
        NOW += 25;
        w_turn();
    }
    CHECK(slot(1, &t) && slot(1, &t)->lobby.m.has_answered && !slot(1, &t)->lobby.m.start_len && slot(1, &t)->round_ok);
    mark = N[1].n_log;
    CHECK(w_pause(1, 1, "PauseAnswered00001") == 200 && slot(1, &t) == NULL && N[1].n->api.pause == GZ_PAUSE_ON);
    w_run(5000, 100);
    CHECK(said(1, mark, "sign-begin") == 0 && slot(1, &t) == NULL && host_state(&t) != GZ_LOBBY_SIGNING);
    no_errors(3);
    w_free(3);

    /* Chosen, the round begun, no partial signature: round_abort, then the
     * leave; 200, the lobby in aborted_lobbies. */
    pause_world(&t, 3, 1420, GZ_TEST_SIGN_FUNDING, 100000);
    CHECK(until_round(&t));
    snprintf(id, sizeof id, "%s", lid(1, &t));
    mark = N[1].n_log;
    {
        size_t ms = NSENT;
        CHECK(w_pause(1, 1, "PauseRoundBegun001") == 200 && slot(1, &t) == NULL && ss_of(1, &t) == NULL);
        CHECK(said(1, mark, "sign-abort") == 1 && sent_count(1, ms, GZ_KIND_LEAVE) == 1);
    }
    snprintf(p, sizeof p, "{\"left_lobbies\":[],\"aborted_lobbies\":[\"%s\"],\"held_lobbies\":[]}", id);
    {
        char q[2048];
        CHECK(res_text(1, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, p));
    }
    no_errors(3);
    w_free(3);

    /* Partial signatures out: held (202, held_for_signing, the lobby named),
     * until its round ends; then the pause is on, saved again. */
    pause_world(&t, 3, 1430, GZ_TEST_SIGN_FUNDING | GZ_TEST_SIGN_PARTIALS, 3000);
    CHECK(until_round(&t));
    snprintf(id, sizeof id, "%s", lid(1, &t));
    CHECK(w_pause(1, 1, "PauseHeldRound0001") == 202 && slot(1, &t) != NULL && ss_of(1, &t) != NULL);
    CHECK(N[1].n->api.pause == GZ_PAUSE_HELD && N[1].n->api.n_held == 1 && h_records_of(&N[1], GZ_RECORD_PAUSE) == 1);
    snprintf(p, sizeof p, "{\"left_lobbies\":[],\"aborted_lobbies\":[],\"held_lobbies\":[\"%s\"]}", id);
    {
        char q[2048];
        CHECK(res_text(1, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, p));
    }
    w = view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
    CHECK(vf(w, GZ_VST_PAUSE, &v) && v.data[0] == GZ_PAUSE_HELD && vf(w, GZ_VST_PAUSE_LOBBIES, &v) &&
          v.len == strlen(id) && !memcmp(v.data, id, v.len));
    CHECK(vf8(view_of(1, GZ_VIEW_LOBBY, id), GZ_VLB_PAUSED) == 1);
    /* Its replay gives the first answer's status, 202, flagged (7.4). */
    {
        char q[64];
        size_t nb = N[1].n_batches;
        CHECK(w_pause(1, 1, "PauseHeldRound0001") == 202 && N[1].n_batches == nb);
        CHECK(res_text(1, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, "{\"replayed\":true}"));
    }
    make_terms(&u, 3, 3, 1431);
    CHECK(host_open(&u, 0) == 200 && member_join(1, &u) == 409);
    w_run(5000, 100);
    CHECK(member_round(1, &t) == GZ_LOBBY_FUNDING && slot(1, &t) != NULL);
    CHECK(N[1].n->api.pause == GZ_PAUSE_ON && N[1].n->api.n_held == 0 && h_records_of(&N[1], GZ_RECORD_PAUSE) == 2);
    w = view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
    CHECK(vf(w, GZ_VST_PAUSE, &v) && v.data[0] == GZ_PAUSE_ON && !vf(w, GZ_VST_PAUSE_LOBBIES, &v));
    CHECK(vf8(view_of(1, GZ_VIEW_LOBBY, id), GZ_VLB_PAUSED) == -1);
    /* A restart keeps it on, from the same moment (rv-pause-since-zero). */
    {
        uint64_t since = N[1].n->api.pause_since;
        CHECK(since != 0 && w_restart(1) == GZ_OK);
        w = view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
        CHECK(vf(w, GZ_VST_PAUSE, &v) && v.len == 13 && v.data[0] == GZ_PAUSE_ON && gz_get_u64(v.data + 1) == since &&
              gz_get_u32(v.data + 9) == N[1].n->api.pause_version && N[1].n->api.pause_version == 1);
        CHECK(slot(1, &t) != NULL && member_round(1, &t) == GZ_LOBBY_FUNDING); /* Awaiting funding: unchanged */
    }
    no_errors(3);
    w_free(3);

    /* Held, and its round ends in a Retry: the lobby is back before Signing,
     * and the pause, now in effect, leaves it. */
    pause_world(&t, 3, 1440, GZ_TEST_SIGN_RETRY | GZ_TEST_SIGN_PARTIALS, 3000);
    CHECK(until_round(&t));
    CHECK(w_pause(1, 1, "PauseHeldRetry0001") == 202);
    w_run(5000, 100);
    CHECK(slot(1, &t) == NULL && N[1].n->api.pause == GZ_PAUSE_ON && N[1].n->api.n_held == 0);
    no_errors(3);
    w_free(3);

    /* Awaiting funding: unchanged, 200, listed nowhere. */
    pause_world(&t, 3, 1450, GZ_TEST_SIGN_FUNDING, 50);
    w_run(40000, 250);
    CHECK(member_round(1, &t) == GZ_LOBBY_FUNDING);
    CHECK(w_pause(1, 1, "PauseFunding000001") == 200 && slot(1, &t) != NULL && N[1].n->api.pause == GZ_PAUSE_ON);
    {
        char q[2048];
        CHECK(res_text(1, GZ_RESULT_REC_PARAMS, q, sizeof q) &&
              !strcmp(q, "{\"left_lobbies\":[],\"aborted_lobbies\":[],\"held_lobbies\":[]}"));
    }
    no_errors(3);
    w_free(3);

    /* A join in flight (RV1): the member has sent nothing the host answered
     * yet; it leaves all the same and never joins. */
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 1460);
    CHECK(host_open(&t, 0) == 200 && member_join(1, &t) == 200 && slot(1, &t) && !slot(1, &t)->lobby.m.joined);
    mark = N[1].n_log;
    CHECK(w_pause(1, 1, "PauseJoining000001") == 200 && slot(1, &t) == NULL);
    w_run(3000, 100);
    CHECK(slot(1, &t) == NULL && said(1, mark, "joined=1") == 0 && host_ready(&t) == 0);
    no_errors(1);
    w_free(1);

    /* A restart whose journal holds `pause on` and a joined, ready lobby with
     * no leave (RV1's second half): the start leaves it, after its CONNECT. */
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 1470);
    CHECK(host_open(&t, 0) == 200 && member_join(1, &t) == 200);
    w_run(2000, 100);
    CHECK(member_ready(1, &t) == 1 && host_ready(&t) == 1);
    {
        uint8_t rec[24];
        size_t at = 0;
        uint8_t on = GZ_PAUSE_ON, since[8], ver[4];
        gz_put_u64(since, NOW);
        gz_put_u32(ver, 1);
        gz_rec_put(rec, sizeof rec, &at, 2, &on, 1);
        gz_rec_put(rec, sizeof rec, &at, 4, since, 8);
        gz_rec_put(rec, sizeof rec, &at, 8, ver, 4);
        h_add_batch(&N[1], N[1].incarnation, ++N[1].seq, GZ_RECORD_PAUSE, rec, at);
    }
    mark = NSENT;
    CHECK(w_restart(1) == GZ_OK);
    w_run(2000, 100);
    CHECK(slot(1, &t) == NULL);
    /* The leave, reason 2, sent to the host once the link was up (a lobby
     * sends only on a live link). The DISCONNECT that follows it in the same
     * list is ordered after it (action.h); this harness drops what is queued
     * on a link it takes down, so the host's side is not checked here. */
    {
        lt_key_t hk;
        gz_lobby_msg_t g;
        whost(&hk);
        CHECK(sent_count(1, mark, GZ_KIND_LEAVE) == 1 && last_sent(1, mark, GZ_KIND_LEAVE, hk.pub, &g) &&
              g.has_reason && g.reason == 2);
    }
    CHECK(N[1].n->api.pause == GZ_PAUSE_ON && member_join(1, &t) == 409);
    no_errors(1);
    w_free(1);
}

/* Request ids are kept by 7.4 without ever blocking the wallet (review A of
 * PR 55, M1 and N1):
 * - the reviewer's RV4, 600 API requests in a row: none is refused, and
 *   the ring keeps the newest of the ids with no object;
 * - a lobby whose share is full refuses only its own next call; a leave, which
 *   protects the member's funds, still goes, and other lobbies are untouched;
 * - a live lobby's id is never dropped, and stays a replay;
 * - the 30 days run on a clock that a wall clock set back cannot stretch. */
static void test_api_request_keep(void)
{
    terms_t t, u, v;
    char rid[40], q[64];
    size_t nb;
    uint8_t l = 0;
    lt_key_t hk;
    whost(&hk);
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 1500);
    make_terms(&u, 3, 3, 1501);
    make_terms(&v, 3, 3, 1502);
    h_arg_t a[3] = {{12, t.outer, t.on}, {14, t.current, t.cn}, {16, &l, 1}};
    char oid[GZ_LOCAL_ID_MAX + 1];
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "OpenKeptLobby00001", "/api/v1/host/lobbies", 1, a, 3) == 200);
    CHECK(host_open(&u, 0) == 200);
    snprintf(oid, sizeof oid, "%s", lid(0, &t));
    /* RV4: 600 requests with a digest, none refused. */
    for (int k = 0; k < 600; k++) {
        snprintf(rid, sizeof rid, "KeepFill%010d", k);
        CHECK(w_pause(0, (k & 1) == 0, rid) == 200);
    }
    CHECK(N[0].n->api.pause == GZ_PAUSE_OFF);
    nb = N[0].n_batches;
    CHECK(w_pause(0, 0, "KeepFill0000000599") == 200 && N[0].n_batches == nb);   /* the newest: a replay */
    CHECK(res_text(0, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, "{\"replayed\":true}"));
    CHECK(gz_api_req_kept(N[0].n, "KeepFill0000000000") == 0);                   /* the ring's oldest went */
    CHECK(gz_api_req_kept(N[0].n, "KeepFill0000000590") == 1 && gz_api_req_kept(N[0].n, "KeepFill0000000568") == 1 &&
          gz_api_req_kept(N[0].n, "KeepFill0000000567") == 0); /* the newest GZ_API_RING (32) of them, no more */
    /* The open of the live lobby is still kept, and a replay. */
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "OpenKeptLobby00001", "/api/v1/host/lobbies", 1, a, 3) == 200 && N[0].n_batches == nb);
    CHECK(res_text(0, GZ_RESULT_REC_OBJECT, q, sizeof q) && !strcmp(q, oid));
    /* The member's share of lobby t: its join and 63 calls that save. */
    {
        h_arg_t j[3] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}};
        h_arg_t s1[1] = {{12, t.scope, 32}};
        CHECK(w_req(1, GZ_CMD_LOBBY_JOIN, "JoinShareLobby0001", "/api/v1/lobbies/join", 1, j, 3) == 200);
        w_run(2000, 100);
        CHECK(member_ready(1, &t) == 1);
        for (int k = 0; k < GZ_API_LOBBY_SHARE - 1; k++) {
            snprintf(rid, sizeof rid, "ShareToggle%07d", k);
            CHECK(w_req(1, (k & 1) == 0 ? GZ_CMD_LOBBY_UNREADY : GZ_CMD_LOBBY_READY, rid, "/api/v1/lobbies/x/ready", 1,
                        s1, 1) == 200);
        }
        CHECK(member_ready(1, &t) == 0);
        nb = N[1].n_batches;
        CHECK(w_req(1, GZ_CMD_LOBBY_READY, "ShareOneTooMany001", "/api/v1/lobbies/x/ready", 1, s1, 1) == 503 &&
              N[1].n_batches == nb && member_ready(1, &t) == 0);
        CHECK(res_text(1, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "node_busy"));
        /* Another lobby's join is not touched; nor is a pause. */
        h_arg_t j2[3] = {{12, u.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}};
        CHECK(w_req(1, GZ_CMD_LOBBY_JOIN, "JoinOtherLobby0001", "/api/v1/lobbies/join", 1, j2, 3) == 200 && slot(1, &u));
        CHECK(w_pause(1, 0, "PauseOffWhileFull1") == 200);
        /* The leave protects the member: it has the reserve. */
        CHECK(w_req(1, GZ_CMD_LOBBY_LEAVE, "LeaveWhileFull0001", "/api/v1/lobbies/x/leave", 1, s1, 1) == 200 &&
              slot(1, &t) == NULL);
    }
    /* A wall clock set back a year does not stretch the 30 days: they run on. */
    {
        h_arg_t o[3] = {{12, v.outer, v.on}, {14, v.current, v.cn}, {16, &l, 1}};
        CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "OpenClockBack00001", "/api/v1/host/lobbies", 1, o, 3) == 200);
        CHECK(scope_cmd(0, GZ_CMD_LOBBY_CANCEL, &v, 0) == 200 && slot(0, &v) == NULL);
        CHECK(gz_api_req_kept(N[0].n, "OpenClockBack00001") == 1);
        NOW -= 365ull * 24 * 3600 * 1000;
        N[0].clock = NOW;
        CHECK(gz_api_req_kept(N[0].n, "OpenClockBack00001") == 1);
        NOW += 29ull * 24 * 3600 * 1000;
        N[0].clock = NOW;
        CHECK(gz_api_req_kept(N[0].n, "OpenClockBack00001") == 1);
        NOW += 2ull * 24 * 3600 * 1000;
        N[0].clock = NOW;
        CHECK(gz_api_req_kept(N[0].n, "OpenClockBack00001") == 2);
        NOW += 365ull * 24 * 3600 * 1000;
    }
    /* 31 days on, the live lobby's open is still kept, and a replay (M2). */
    NOW += 31ull * 24 * 3600 * 1000;
    N[0].clock = NOW;
    CHECK(slot(0, &t) != NULL && gz_api_req_kept(N[0].n, "OpenKeptLobby00001") == 1);
    nb = N[0].n_batches;
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "OpenKeptLobby00001", "/api/v1/host/lobbies", 1, a, 3) == 200 && N[0].n_batches == nb);
    CHECK(res_text(0, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, "{\"replayed\":true}"));
    no_errors(1);
    w_free(1);
}

/* A request_id record as an earlier run saved it: `object` may be "". */
static void add_req_record(int n, const char *rid, const char *object, uint64_t created)
{
    uint8_t r[200], st[2], cr[8], d[32];
    size_t at = 0;
    memset(d, 9, 32);
    gz_put_u16(st, 200);
    gz_put_u64(cr, created);
    gz_rec_put(r, sizeof r, &at, 2, (const uint8_t *)rid, strlen(rid));
    gz_rec_put(r, sizeof r, &at, 4, (const uint8_t *)"POST", 4);
    gz_rec_put(r, sizeof r, &at, 6, (const uint8_t *)"/api/v1/x", 9);
    gz_rec_put(r, sizeof r, &at, 8, d, 32);
    gz_rec_put(r, sizeof r, &at, 10, st, 2);
    if (object[0]) gz_rec_put(r, sizeof r, &at, 12, (const uint8_t *)object, strlen(object));
    gz_rec_put(r, sizeof r, &at, 14, cr, 8);
    h_add_batch(&N[n], N[n].incarnation, ++N[n].seq, GZ_RECORD_REQUEST_ID, r, at);
}

/* The review of PR 75: M1, a stale resume never turns a later pause off, and
 * M2, the guarantees N1 rests on, each tested. */
static void test_api_request_keep_more(void)
{
    terms_t t;
    char rid[40], q[64];
    size_t nb;
    lt_key_t hk;
    whost(&hk);
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    /* M1: pause (A), resume (B), 40 more no-object calls, pause again (C);
     * then B, pushed out of the ring, arrives again: 409, the pause stays on. */
    {
        uint8_t off = 0, pvb[4];
        CHECK(w_pause(1, 1, "StalePauseA0000001") == 200);
        gz_put_u32(pvb, N[1].n->api.pause_version);
        h_arg_t b[2] = {{12, &off, 1}, {14, pvb, 4}};
        CHECK(w_req(1, GZ_CMD_API_PAUSE, "StaleResumeB000001", "/api/v1/pause", 1, b, 2) == 200);
        for (int k = 0; k < 40; k++) {
            snprintf(rid, sizeof rid, "StaleToggle%07d", k);
            CHECK(w_pause(1, (k & 1) == 0, rid) == 200);
        }
        CHECK(w_pause(1, 1, "StalePauseC0000001") == 200 && N[1].n->api.pause == GZ_PAUSE_ON);
        CHECK(gz_api_req_kept(N[1].n, "StaleResumeB000001") == 0);
        nb = N[1].n_batches;
        CHECK(w_req(1, GZ_CMD_API_PAUSE, "StaleResumeB000001", "/api/v1/pause", 1, b, 2) == 409 &&
              N[1].n->api.pause == GZ_PAUSE_ON && N[1].n_batches == nb);
        CHECK(res_text(1, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "changed_elsewhere"));
        CHECK(w_pause(1, 0, "ResumeAgain0000001") == 200 && N[1].n->api.pause == GZ_PAUSE_OFF);
        /* A stale pause on is not refused: it only tightens. */
        uint8_t on = 1, pv0[4];
        gz_put_u32(pv0, 0);
        h_arg_t s[2] = {{12, &on, 1}, {14, pv0, 4}};
        CHECK(w_req(1, GZ_CMD_API_PAUSE, "StalePauseOn000001", "/api/v1/pause", 1, s, 2) == 200 &&
              N[1].n->api.pause == GZ_PAUSE_ON);
        CHECK(w_pause(1, 0, "ResumeAgain0000002") == 200 && N[1].n->api.pause == GZ_PAUSE_OFF);
    }
    /* The ring after a restart: the newest 32 ids with no object come back,
     * no more (p75-ring-not-loaded). */
    {
        for (int k = 0; k < 40; k++) {
            snprintf(rid, sizeof rid, "RingRestart%07d", k);
            CHECK(w_pause(1, (k & 1) == 0, rid) == 200);
        }
        CHECK(w_restart(1) == GZ_OK);
        CHECK(gz_api_req_kept(N[1].n, "RingRestart0000039") == 1 && gz_api_req_kept(N[1].n, "RingRestart0000008") == 1 &&
              gz_api_req_kept(N[1].n, "RingRestart0000007") == 0);
        nb = N[1].n_batches;
        CHECK(w_pause(1, 0, "RingRestart0000039") == 200 && N[1].n_batches == nb);
        CHECK(res_text(1, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, "{\"replayed\":true}"));
    }
    /* The ended-lobby fallback (p75-ended-fallback-off): the table full of ids
     * of lobbies ended within 30 days, a new join and its leave still go. */
    {
        int k = 0, refused = 0;
        for (; k < GZ_API_MAX_REQUESTS / 2 + 1; k++) {
            make_terms(&t, 3, 3, 20000 + (uint32_t)k);
            h_arg_t j[3] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}};
            h_arg_t s1[1] = {{12, t.scope, 32}};
            snprintf(rid, sizeof rid, "FillJoin%010d", k);
            refused += w_req(1, GZ_CMD_LOBBY_JOIN, rid, "/api/v1/lobbies/join", 1, j, 3) != 200;
            snprintf(rid, sizeof rid, "FillLeave%09d", k);
            refused += w_req(1, GZ_CMD_LOBBY_LEAVE, rid, "/api/v1/lobbies/x/leave", 1, s1, 1) != 200;
        }
        CHECK(refused == 0);
        make_terms(&t, 3, 3, 29999);
        h_arg_t j[3] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}};
        h_arg_t s1[1] = {{12, t.scope, 32}};
        CHECK(w_req(1, GZ_CMD_LOBBY_JOIN, "FillJoinTheLast001", "/api/v1/lobbies/join", 1, j, 3) == 200 && slot(1, &t));
        CHECK(w_req(1, GZ_CMD_LOBBY_LEAVE, "FillLeaveTheLast01", "/api/v1/lobbies/x/leave", 1, s1, 1) == 200 &&
              slot(1, &t) == NULL);
    }
    /* The reserve's upper bound (p75-reserve-unbounded): a live lobby with its
     * share and reserve all kept (as an earlier run saved them) refuses its
     * leave too; a lobby is never given more than its place in the table. */
    {
        char id[GZ_LOCAL_ID_MAX + 1];
        make_terms(&t, 3, 3, 30001);
        CHECK(member_join(1, &t) == 200 && slot(1, &t));
        snprintf(id, sizeof id, "%s", lid(1, &t));
        for (int k = 0; k < GZ_API_LOBBY_SHARE + GZ_API_LOBBY_RESERVE; k++) {
            snprintf(rid, sizeof rid, "Bound%013d", k);
            add_req_record(1, rid, id, NOW);
        }
        CHECK(w_restart(1) == GZ_OK && slot(1, &t));
        h_arg_t s1[1] = {{12, t.scope, 32}};
        nb = N[1].n_batches;
        CHECK(w_req(1, GZ_CMD_LOBBY_LEAVE, "BoundLeave00000001", "/api/v1/lobbies/x/leave", 1, s1, 1) == 503 &&
              slot(1, &t) && N[1].n_batches == nb);
    }
    /* A host's cancel protects its set-aside funds: it has the reserve too
     * (review of PR 75, L1); another call of the full lobby is refused. */
    {
        char id[GZ_LOCAL_ID_MAX + 1];
        uint8_t vals[24];
        make_terms(&t, 3, 3, 30002);
        CHECK(host_open(&t, 0) == 200 && slot(0, &t));
        snprintf(id, sizeof id, "%s", lid(0, &t));
        for (int k = 0; k < GZ_API_LOBBY_SHARE; k++) {
            snprintf(rid, sizeof rid, "HostShare%09d", k);
            add_req_record(0, rid, id, NOW);
        }
        CHECK(w_restart(0) == GZ_OK && slot(0, &t));
        gz_put_u64(vals, 600);
        gz_put_u64(vals + 8, 1000);
        gz_put_u64(vals + 16, 1000);
        h_arg_t sv[2] = {{12, t.scope, 32}, {14, vals, 24}};
        h_arg_t s1[1] = {{12, t.scope, 32}};
        CHECK(w_req(0, GZ_CMD_LOBBY_SET_VALUES, "HostShareFull00001", "/api/v1/host/lobbies/x", 1, sv, 2) == 503);
        CHECK(w_req(0, GZ_CMD_LOBBY_CANCEL, "HostCancelFull0001", "/api/v1/host/lobbies/x/cancel", 1, s1, 1) == 200 &&
              slot(0, &t) == NULL);
    }
    /* The keep clock across a restart (p75-keep-load-ignored): the clock set
     * back a year, then a restart; the ids still age on from their making. */
    {
        uint64_t made = NOW;
        add_req_record(1, "KeepAcross00000001", "", made);
        CHECK(w_restart(1) == GZ_OK);
        NOW -= 365ull * 24 * 3600 * 1000;
        N[1].clock = NOW;
        CHECK(w_restart(1) == GZ_OK);
        NOW += 31ull * 24 * 3600 * 1000;
        N[1].clock = NOW;
        CHECK(gz_api_req_kept(N[1].n, "KeepAcross00000001") == 2);
        NOW += 365ull * 24 * 3600 * 1000;
    }
    no_errors(1);
    w_free(1);
}

/* An attention item's id is whole for the longest local id (N2): two lobbies
 * whose 64-character ids share their first 63 get two items. */
static void test_attention_long_ids(void)
{
    terms_t t, u;
    char a1[80], a2[80], x[GZ_LOCAL_ID_MAX + 1];
    w_world(1, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 1510);
    make_terms(&u, 3, 3, 1511);
    CHECK(host_open(&t, 0) == 200 && host_open(&u, 0) == 200 && member_join(1, &t) == 200 && member_join(1, &u) == 200);
    w_run(2000, 100);
    for (int k = 0; k < 2; k++) {
        uint8_t r[120];
        size_t at = 0;
        memcpy(x, "lob_", 4);
        memset(x + 4, 'q', 59);
        x[63] = k ? 'b' : 'a';
        x[64] = 0;
        gz_rec_put(r, sizeof r, &at, 2, (k ? u : t).scope, 32);
        gz_rec_put(r, sizeof r, &at, 4, (const uint8_t *)x, 64);
        h_add_batch(&N[1], N[1].incarnation, ++N[1].seq, GZ_RECORD_LOCAL_IDS, r, at);
    }
    CHECK(w_restart(1) == GZ_OK);
    CHECK(strlen(lid(1, &t)) == 64 && strlen(lid(1, &u)) == 64 && strcmp(lid(1, &t), lid(1, &u)) != 0);
    snprintf(a1, sizeof a1, "att_%s", lid(1, &t) + 4);
    snprintf(a2, sizeof a2, "att_%s", lid(1, &u) + 4);
    CHECK(strlen(a1) == 64 && strcmp(a1, a2) != 0);
    CHECK(vf8(view_of(1, GZ_VIEW_ATTENTION, a1), GZ_VAT_CODE) == GZ_ATT_UNLOCK_TO_TAKE_PART &&
          vf8(view_of(1, GZ_VIEW_ATTENTION, a2), GZ_VAT_CODE) == GZ_ATT_UNLOCK_TO_TAKE_PART);
    no_errors(1);
    w_free(1);
}

/* Replays and reuse in detail (7.4; M2, L1, L3, the review's mutants). */
static void test_api_replay_detail(void)
{
    terms_t t;
    char q[400], id[GZ_LOCAL_ID_MAX + 1], longid[80];
    uint8_t l = 0;
    size_t nb;
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 1600);
    h_arg_t a[3] = {{12, t.outer, t.on}, {14, t.current, t.cn}, {16, &l, 1}};
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "ReplayDetail000001", "/api/v1/host/lobbies", 1, a, 3) == 200);
    snprintf(id, sizeof id, "%s", lid(0, &t));
    /* The first answer names the object it opened, as a replay does (review of #79: the
     * program answers a call with that object; without it the answer was empty). */
    CHECK(id[0] && res_text(0, GZ_RESULT_REC_OBJECT, q, sizeof q) && !strcmp(q, id));
    nb = N[0].n_batches;
    /* Another path, or another method, with the same id and digest: 409, with the first call named. */
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "ReplayDetail000001", "/api/v1/host/lobbiez", 1, a, 3) == 409 && N[0].n_batches == nb);
    CHECK(res_text(0, GZ_RESULT_REC_PARAMS, q, sizeof q) &&
          !strcmp(q, "{\"first\":{\"method\":\"POST\",\"path\":\"/api/v1/host/lobbies\"}}"));
    for (int mi = 0; mi < 2; mi++) { /* another method, and one that is a prefix of the first call's */
        static uint8_t buf[2048];
        uint8_t c2[2], d[32];
        size_t at = 0;
        gz_event_t ev;
        memset(d, 1, 32);
        gz_put_u16(c2, GZ_CMD_LOBBY_OPEN);
        gz_rec_put(buf, sizeof buf, &at, GZ_CMD_REC_REQUEST_ID, (const uint8_t *)"ReplayDetail000001", 18);
        gz_rec_put(buf, sizeof buf, &at, GZ_CMD_REC_METHOD, (const uint8_t *)(mi ? "POS" : "PUT"), 3);
        gz_rec_put(buf, sizeof buf, &at, GZ_CMD_REC_PATH, (const uint8_t *)"/api/v1/host/lobbies", 20);
        gz_rec_put(buf, sizeof buf, &at, GZ_CMD_REC_DIGEST, d, 32);
        gz_rec_put(buf, sizeof buf, &at, GZ_CMD_REC_COMMAND, c2, 2);
        for (int i = 0; i < 3; i++) gz_rec_put(buf, sizeof buf, &at, a[i].type, a[i].v, a[i].len);
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_USER_COMMAND;
        ev.u.user.bytes.data = buf;
        ev.u.user.bytes.len = at;
        CHECK(w_event(0, &ev) == GZ_OK);
        CHECK(res_text(0, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "request_id_reused") && N[0].n_batches == nb);
    }
    /* A path with a quote, and a 65-character id: 400, nothing done. */
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "ReplayDetail000002", "/api/v1/\"x", 1, a, 3) == 400 && N[0].n_batches == nb);
    memset(longid, 'A', 65);
    longid[65] = 0;
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, longid, "/api/v1/host/lobbies", 1, a, 3) == 400 && N[0].n_batches == nb);
    /* After a restart the replay still names the lobby it opened (M2). */
    CHECK(w_restart(0) == GZ_OK);
    nb = N[0].n_batches;
    CHECK(w_req(0, GZ_CMD_LOBBY_OPEN, "ReplayDetail000001", "/api/v1/host/lobbies", 1, a, 3) == 200 && N[0].n_batches == nb);
    CHECK(res_text(0, GZ_RESULT_REC_OBJECT, q, sizeof q) && !strcmp(q, id));
    CHECK(res_text(0, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, "{\"replayed\":true}"));
    /* The ready count follows the values version (rv-host-ready-any-version). */
    CHECK(member_join(1, &t) == 200);
    CHECK(res_text(1, GZ_RESULT_REC_OBJECT, q, sizeof q) && !strcmp(q, lid(1, &t)));   /* a join names its lobby */
    w_run(2000, 100);
    CHECK(host_ready(&t) == 1);
    {
        uint8_t vals[24];
        gz_put_u64(vals, 600);
        gz_put_u64(vals + 8, 1000);
        gz_put_u64(vals + 16, 1000);
        h_arg_t s[2] = {{12, t.scope, 32}, {14, vals, 24}};
        gz_bytes_t v;
        CHECK(w_cmd(0, GZ_CMD_LOBBY_SET_VALUES, s, 2) == 200);
        CHECK(vf(view_of(0, GZ_VIEW_HOST_LOBBY, id), GZ_VHL_COUNTS, &v) && v.len == 8 && gz_get_u16(v.data) == 1 &&
              gz_get_u16(v.data + 2) == 0);
    }
    no_errors(1);
    w_free(1);
}

/* The signing setting's authority in the core (M4), and its value in force
 * for the program after a restart (H3). */
static void test_api_signing_authority(void)
{
    uint8_t sv[4], au = GZ_MEMBER_SIGNING_AUTO, wu = GZ_MEMBER_SIGNING_WHEN_UNLOCKED, bad = 3, aj = GZ_MEMBER_SIGNING_AT_JOIN;
    uint8_t two = 2;
    char q[64];
    size_t nb;
    w_world(1, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_FUNDING);
    gz_put_u32(sv, 0);
    nb = N[1].n_batches;
    {
        h_arg_t s[2] = {{12, &wu, 1}, {14, sv, 4}};
        CHECK(w_req(1, GZ_CMD_API_SET_SIGNING, "SigningWhenUnlock1", "/api/v1/signing", 1, s, 2) == 501);
        CHECK(res_text(1, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "not_in_this_release"));
    }
    {
        h_arg_t s[2] = {{12, &bad, 1}, {14, sv, 4}};
        CHECK(w_req(1, GZ_CMD_API_SET_SIGNING, "SigningBadValue001", "/api/v1/signing", 1, s, 2) == 400);
    }
    {
        h_arg_t p[1] = {{12, &two, 1}};
        CHECK(w_req(1, GZ_CMD_API_PAUSE, "PauseBadValue00001", "/api/v1/pause", 1, p, 1) == 400);
    }
    {
        h_arg_t s[3] = {{12, &au, 1}, {14, sv, 4}, {16, &au, 1}};
        CHECK(w_cmd(1, GZ_CMD_API_SET_SIGNING, s, 3) == 403); /* no digest: not the API's PUT /signing */
        CHECK(w_req(1, GZ_CMD_API_SET_SIGNING, "SigningNoEcho00001", "/api/v1/signing", 1, s, 2) == 409);
        CHECK(res_text(1, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "confirm_mismatch"));
        h_arg_t s2[3] = {{12, &au, 1}, {14, sv, 4}, {16, &aj, 1}};
        CHECK(w_req(1, GZ_CMD_API_SET_SIGNING, "SigningWrongEcho01", "/api/v1/signing", 1, s2, 3) == 409);
    }
    CHECK(N[1].n_batches == nb && h_records_of(&N[1], GZ_RECORD_SIGNING_SETTING) == 0);
    {
        h_arg_t s[3] = {{12, &au, 1}, {14, sv, 4}, {16, &au, 1}};
        CHECK(w_req(1, GZ_CMD_API_SET_SIGNING, "SigningToAuto00001", "/api/v1/signing", 1, s, 3) == 200);
    }
    CHECK(gz_node_member_signing(N[1].n) == GZ_MEMBER_SIGNING_AT_JOIN); /* until the next start */
    CHECK(w_restart(1) == GZ_OK && gz_node_member_signing(N[1].n) == GZ_MEMBER_SIGNING_AUTO);
    /* Narrowing needs no echo, and may come from any command source. */
    gz_put_u32(sv, 1);
    {
        h_arg_t s[2] = {{12, &aj, 1}, {14, sv, 4}};
        CHECK(w_cmd(1, GZ_CMD_API_SET_SIGNING, s, 2) == 200);
    }
    CHECK(w_restart(1) == GZ_OK && gz_node_member_signing(N[1].n) == GZ_MEMBER_SIGNING_AT_JOIN);
    no_errors(1);
    w_free(1);
}

/* One start of the scratch node on one raw record; its status. */
static gz_status_t start_on(uint32_t type, const uint8_t *b, size_t n)
{
    h_t *x = &N[SCRATCH];
    gz_status_t st;
    w_node(SCRATCH, 5, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    h_add_batch(x, 1, 1, type, b, n);
    x->incarnation = 1;
    h_new_node(x);
    st = w_start(SCRATCH);
    return st;
}

static void scratch_free(void)
{
    ALIVE[SCRATCH] = 0;
    NT[SCRATCH] = 0;
    h_free(&N[SCRATCH]);
    memset(&N[SCRATCH], 0, sizeof N[SCRATCH]);
}

/* The API records at load (M3, L3, L4; the review's unknown-field and bound
 * mutants): each refuses an even field it does not know, and what the live
 * path refuses. */
static void test_api_records(void)
{
    uint8_t r[400], scope[32], x8[8], d[32];
    size_t at;
    memset(scope, 7, 32);
    memset(x8, 0, 8);
    memset(d, 3, 32);
    /* pause: 9 held scopes refused, 8 taken; an unknown even field refused; held with none refused */
    for (int n = 8; n <= 9; n++) {
        uint8_t held[9 * 32], st = GZ_PAUSE_HELD;
        for (int k = 0; k < n; k++) memset(held + 32 * k, k + 1, 32);
        at = 0;
        gz_rec_put(r, sizeof r, &at, 2, &st, 1);
        gz_rec_put(r, sizeof r, &at, 4, x8, 8);
        gz_rec_put(r, sizeof r, &at, 6, held, 32 * (size_t)n);
        gz_rec_put(r, sizeof r, &at, 8, x8, 4);
        CHECK(start_on(GZ_RECORD_PAUSE, r, at) == (n == 8 ? GZ_OK : GZ_ERR_CORRUPT));
        if (n == 8) /* none of them holds a slot: released at the start, saved on */
            CHECK(N[SCRATCH].n->api.pause == GZ_PAUSE_ON && N[SCRATCH].n->api.n_held == 0 &&
                  h_records_of(&N[SCRATCH], GZ_RECORD_PAUSE) == 1 + 8);
        scratch_free();
    }
    {
        uint8_t st = GZ_PAUSE_HELD;
        at = 0;
        gz_rec_put(r, sizeof r, &at, 2, &st, 1);
        gz_rec_put(r, sizeof r, &at, 4, x8, 8);
        gz_rec_put(r, sizeof r, &at, 8, x8, 4);
        CHECK(start_on(GZ_RECORD_PAUSE, r, at) == GZ_ERR_CORRUPT);   /* held, with no lobby */
        scratch_free();
        st = GZ_PAUSE_ON;
        at = 0;
        gz_rec_put(r, sizeof r, &at, 2, &st, 1);
        gz_rec_put(r, sizeof r, &at, 4, x8, 8);
        gz_rec_put(r, sizeof r, &at, 8, x8, 4);
        CHECK(start_on(GZ_RECORD_PAUSE, r, at) == GZ_OK);            /* the control: a good record */
        scratch_free();
        at = 0;
        gz_rec_put(r, sizeof r, &at, 2, &st, 1);
        gz_rec_put(r, sizeof r, &at, 4, x8, 8);
        gz_rec_put(r, sizeof r, &at, 8, x8, 4);
        gz_rec_put(r, sizeof r, &at, 10, &st, 1);
        CHECK(start_on(GZ_RECORD_PAUSE, r, at) == GZ_ERR_CORRUPT);   /* an unknown even field */
        scratch_free();
        at = 0;
        gz_rec_put(r, sizeof r, &at, 2, &st, 1);
        gz_rec_put(r, sizeof r, &at, 4, x8, 8);
        CHECK(start_on(GZ_RECORD_PAUSE, r, at) == GZ_ERR_CORRUPT);   /* no version */
        scratch_free();
    }
    /* local_ids: no "lob_", or an unknown even field */
    for (int k = 0; k < 3; k++) {
        at = 0;
        gz_rec_put(r, sizeof r, &at, 2, scope, 32);
        gz_rec_put(r, sizeof r, &at, 4, (const uint8_t *)(k == 1 ? "abc_7k2q" : "lob_7k2q"), 8);
        if (k == 2) gz_rec_put(r, sizeof r, &at, 6, x8, 1);
        CHECK(start_on(GZ_RECORD_LOCAL_IDS, r, at) == (k == 0 ? GZ_OK : GZ_ERR_CORRUPT));
        scratch_free();
    }
    /* local_ids: the same id for two scopes */
    {
        h_t *x = &N[SCRATCH];
        uint8_t r2[80], s2[32];
        size_t a2 = 0;
        memset(s2, 8, 32);
        at = 0;
        gz_rec_put(r, sizeof r, &at, 2, scope, 32);
        gz_rec_put(r, sizeof r, &at, 4, (const uint8_t *)"lob_same", 8);
        gz_rec_put(r2, sizeof r2, &a2, 2, s2, 32);
        gz_rec_put(r2, sizeof r2, &a2, 4, (const uint8_t *)"lob_same", 8);
        w_node(SCRATCH, 5, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
        h_add_batch(x, 1, 1, GZ_RECORD_LOCAL_IDS, r, at);
        h_add_batch(x, 1, 2, GZ_RECORD_LOCAL_IDS, r2, a2);
        x->incarnation = 1;
        h_new_node(x);
        CHECK(w_start(SCRATCH) == GZ_ERR_CORRUPT);
        scratch_free();
    }
    /* signing_setting: an unknown even field; host_funding applied (rv-host-funding-not-applied) */
    for (int k = 0; k < 2; k++) {
        uint8_t ms = GZ_MEMBER_SIGNING_AT_JOIN, hf = GZ_HOST_FUNDING_CONFIRM, ver[4];
        gz_put_u32(ver, 4);
        at = 0;
        gz_rec_put(r, sizeof r, &at, 2, &ms, 1);
        gz_rec_put(r, sizeof r, &at, 4, &hf, 1);
        gz_rec_put(r, sizeof r, &at, 6, ver, 4);
        if (k) gz_rec_put(r, sizeof r, &at, 8, &ms, 1);
        CHECK(start_on(GZ_RECORD_SIGNING_SETTING, r, at) == (k ? GZ_ERR_CORRUPT : GZ_OK));
        if (!k) CHECK(N[SCRATCH].n->cfg.host_funding == GZ_HOST_FUNDING_CONFIRM &&
                      gz_node_member_signing(N[SCRATCH].n) == GZ_MEMBER_SIGNING_AT_JOIN);
        scratch_free();
    }
    /* request_id: unknown even field 16 (M3, RV6.0); a short id, a method with a
     * quote, an object with a space (L3); and a saved error code replayed (L1). */
    for (int k = 0; k < 5; k++) {
        uint8_t s2[2];
        char q[64];
        gz_put_u16(s2, 409);
        at = 0;
        gz_rec_put(r, sizeof r, &at, 2, (const uint8_t *)(k == 1 ? "ShortId" : "SavedErrorReplay01"), k == 1 ? 7 : 18);
        gz_rec_put(r, sizeof r, &at, 4, (const uint8_t *)(k == 2 ? "PO\"ST" : "POST"), k == 2 ? 5 : 4);
        gz_rec_put(r, sizeof r, &at, 6, (const uint8_t *)"/api/v1/host/lobbies", 20);
        gz_rec_put(r, sizeof r, &at, 8, d, 32);
        gz_rec_put(r, sizeof r, &at, 10, s2, 2);
        gz_rec_put(r, sizeof r, &at, 12, (const uint8_t *)(k == 3 ? "lob x" : "lob_x"), 5);
        gz_rec_put(r, sizeof r, &at, 14, x8, 8);
        gz_rec_put(r, sizeof r, &at, 15, (const uint8_t *)"lobby_exists", 12);
        if (k == 4) gz_rec_put(r, sizeof r, &at, 16, x8, 1);
        CHECK(start_on(GZ_RECORD_REQUEST_ID, r, at) == (k == 0 ? GZ_OK : GZ_ERR_CORRUPT));
        if (k == 0) {
            uint8_t l = 0;
            terms_t t;
            make_terms(&t, 3, 3, 1700);
            h_arg_t a[3] = {{12, t.outer, t.on}, {14, t.current, t.cn}, {16, &l, 1}};
            CHECK(w_req(SCRATCH, GZ_CMD_LOBBY_OPEN, "SavedErrorReplay01", "/api/v1/host/lobbies", 3, a, 3) == 409);
            CHECK(res_text(SCRATCH, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "lobby_exists"));
            CHECK(res_text(SCRATCH, GZ_RESULT_REC_OBJECT, q, sizeof q) && !strcmp(q, "lob_x"));
        }
        scratch_free();
    }
}

/* The index of local ids is full of ended lobbies: an open slot's id is never
 * the one that goes (rv-lid-evicts-open), and no attention item or id is made
 * of the fingerprint (M5). */
static void test_api_ids_kept(void)
{
    terms_t t;
    const char *id;
    w_world(1, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 1800);
    CHECK(host_open(&t, 0) == 200 && member_join(1, &t) == 200);
    w_run(2000, 100);
    id = lid(1, &t);
    CHECK(id[0] != 0);
    for (int k = 0; k < API_MAX_IDS + 4; k++) {
        uint8_t r[80], s[32];
        char x[24];
        size_t at = 0;
        memset(s, 0, 32);
        gz_put_u32(s, (uint32_t)k + 1);
        snprintf(x, sizeof x, "lob_e%07d", k);
        gz_rec_put(r, sizeof r, &at, 2, s, 32);
        gz_rec_put(r, sizeof r, &at, 4, (const uint8_t *)x, strlen(x));
        h_add_batch(&N[1], N[1].incarnation, ++N[1].seq, GZ_RECORD_LOCAL_IDS, r, at);
    }
    CHECK(w_restart(1) == GZ_OK);
    CHECK(gz_api_local_id(N[1].n, t.scope) && !strcmp(gz_api_local_id(N[1].n, t.scope), lid(1, &t)));
    /* The member's attention item (its gate is closed): named by the local id only. */
    for (int k = 0; k < NV; k++) {
        const wview_t *w = &VW[1][k];
        gz_bytes_t v;
        if (!w->used || w->kind != GZ_VIEW_ATTENTION) continue;
        CHECK(!strncmp(w->id, "att_", 4) && strlen(w->id) == 20 && !vf(w, 12, &v)); /* "att_" and the 16 hex of the id */
    }
    CHECK(view_of(1, GZ_VIEW_ATTENTION, "att_x") == NULL);
    no_errors(1);
    w_free(1);
}


/* ---- the person's conditions (0x0d03) and the early start (0x0109) ------------ */

static int set_cond(int n, const char *rid, const gz_lobby_conditions_t *cd, uint32_t version, const uint8_t *echo,
                    size_t ne)
{
    static uint8_t b[COND_MAX];
    uint8_t v[4];
    size_t bl = gz_ls_cond_encode(cd, b, sizeof b), na = 2;
    h_arg_t a[3] = {{12, b, bl}, {14, v, 4}, {16, echo, ne}};
    gz_put_u32(v, version);
    if (echo) na = 3;
    return rid ? w_req(n, GZ_CMD_API_SET_CONDITIONS, rid, "/api/v1/conditions", 3, a, na)
               : w_cmd(n, GZ_CMD_API_SET_CONDITIONS, a, na);
}

static int host_refused(const terms_t *t)
{
    slot_t *s = slot(0, t);
    int r = 0;
    if (!s) return -1;
    for (uint16_t k = 0; k < s->lobby.h.n_seats; k++)
        r += s->lobby.h.seats[k].refused == 1 && s->lobby.h.seats[k].refused_stage == GZ_STAGE_OPEN &&
             s->lobby.h.seats[k].state == GZ_SEAT_LEFT;
    return r;
}

/* Member n's link to the host goes down and stays down: its CONNECT is
 * forgotten, as a program whose transport lost it would. */
static void link_down(int n)
{
    lt_key_t hk;
    whost(&hk);
    for (int i = 0; i < 64; i++)
        if (C[i].used && C[i].node == n && C[i].up == 1) {
            gz_link_t hl = h_link(hk.pub, C[i].mlink.local.key);
            for (size_t k = 0; k < NQ; k++) /* lost, not flushed: the link broke */
                if (Q[k].rec && (!memcmp(&Q[k].link, &hl, sizeof hl) || !memcmp(&Q[k].link, &C[i].mlink, sizeof hl))) {
                    free(Q[k].rec);
                    Q[k].rec = NULL;
                }
            C[i].up = -1;
            C[i].closer = -1; /* a break: neither side's messages go */
            C[i].wanted = 0;
        }
    w_turn();
}

/* local-api.md 13.2: PUT /conditions's core. Saved with a version and read
 * back at a start; a lobby the new conditions refuse is left (reason 1, in
 * the batch of the save), seen by the host as a refusal; a loosening needs
 * the fresh sign-in and its exact echo, and changes no lobby's copy; a link
 * that is down is left once it is up again, also across a restart. */
static void test_api_conditions(void)
{
    terms_t t, u;
    gz_lobby_conditions_t none, tight;
    uint8_t ch = GZ_TT_CHANNEL, bad[1] = {9};
    char q[600], p[600], id1[GZ_LOCAL_ID_MAX + 1], id2[GZ_LOCAL_ID_MAX + 1];
    size_t mark;
    gz_lobby_msg_t m;
    gz_bytes_t v;
    wview_t *w;
    const uint32_t one_batch[3] = {GZ_RECORD_CONDITIONS, GZ_REC_LOBBY_ENDED, GZ_RECORD_SLOT_CLOSED};
    memset(&none, 0, sizeof none);
    tight = none;
    tight.limits.min_channel_sat = 200000; /* T1's channel is 100,000 */
    w_world(2, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 4, 3, 1900);
    make_terms(&u, 4, 3, 1901);
    CHECK(host_open(&t, 0) == 200 && host_open(&u, 0) == 200);
    CHECK(member_join(1, &t) == 200 && member_join(2, &t) == 200);
    w_run(2000, 100);
    CHECK(member_ready(1, &t) == 1 && member_ready(2, &t) == 1 && host_state(&t) == GZ_LOBBY_OPEN && host_ready(&t) == 2);
    snprintf(id1, sizeof id1, "%s", lid(1, &t));
    snprintf(id2, sizeof id2, "%s", lid(2, &t));
    /* The form. */
    {
        uint8_t v4[4] = {0, 0, 0, 0};
        h_arg_t a[2] = {{12, bad, 1}, {14, v4, 4}};
        CHECK(w_cmd(1, GZ_CMD_API_SET_CONDITIONS, a, 2) == 400 && w_cmd(1, GZ_CMD_API_SET_CONDITIONS, a + 1, 1) == 400);
    }
    CHECK(h_records_of(&N[1], GZ_RECORD_CONDITIONS) == 0);
    /* A tightening needs no fresh sign-in. Member 1's lobby no longer fits:
     * it leaves, reason 1, in the batch of the save, and says which. */
    mark = NSENT;
    CHECK(set_cond(1, NULL, &tight, 0, NULL, 0) == 200);
    snprintf(p, sizeof p, "{\"version\":1,\"left_lobbies\":[\"%s\"]}", id1);
    CHECK(res_text(1, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, p));
    CHECK(slot(1, &t) == NULL && sent_count(1, mark, GZ_KIND_LEAVE) == 1 &&
          last_sent(1, mark, GZ_KIND_LEAVE, NULL, &m) && m.has_reason && m.reason == 1);
    CHECK(h_records_of(&N[1], GZ_RECORD_CONDITIONS) == 1 && batch_with(1, one_batch, 3));
    w_run(1000, 100);
    CHECK(host_refused(&t) == 1 && host_ready(&t) == 1 && member_ready(2, &t) == 1);
    w = view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &t));
    CHECK(w && vf(w, GZ_VHL_COUNTS, &v) && v.len == 8 && gz_get_u16(v.data + 6) == 1);
    w = view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
    CHECK(w && vf(w, GZ_VST_CONDITIONS, &v) && v.len == 4 + COND_HEAD && gz_get_u32(v.data) == 1 &&
          gz_get_u64(v.data + 4 + 3) == 200000 && !vf(w, GZ_VST_PRESET, &v));
    /* An older version: changed elsewhere, nothing saved. */
    CHECK(set_cond(1, NULL, &tight, 0, NULL, 0) == 409 && res_text(1, GZ_RESULT_REC_ERROR, q, sizeof q) &&
          !strcmp(q, "changed_elsewhere") && h_records_of(&N[1], GZ_RECORD_CONDITIONS) == 1);
    /* A loosening: not as a plain command (403); as an API request only with
     * the exact list of what it loosens (409 with the list, then 200). */
    CHECK(set_cond(1, NULL, &none, 1, NULL, 0) == 403);
    CHECK(set_cond(1, "CondLoosenNoEcho01", &none, 1, NULL, 0) == 409 && res_text(1, GZ_RESULT_REC_ERROR, q, sizeof q) &&
          !strcmp(q, "confirm_mismatch") && res_text(1, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, "{\"loosens\":[30]}"));
    CHECK(set_cond(1, "CondLoosenBadEcho1", &none, 1, bad, 1) == 409 && h_records_of(&N[1], GZ_RECORD_CONDITIONS) == 1);
    CHECK(set_cond(1, "CondLoosenEcho0001", &none, 1, &ch, 1) == 200 && res_text(1, GZ_RESULT_REC_PARAMS, q, sizeof q) &&
          !strcmp(q, "{\"version\":2,\"left_lobbies\":[]}"));
    CHECK(h_records_of(&N[1], GZ_RECORD_CONDITIONS) == 2 && h_records_of(&N[1], GZ_RECORD_REQUEST_ID) == 1);
    /* Nothing loosens with an echo: also a mismatch (a stale preview). */
    CHECK(set_cond(1, "CondTightenEcho001", &tight, 2, &ch, 1) == 409);
    /* A preset is saved with the conditions. */
    {
        static uint8_t b[COND_MAX];
        uint8_t v4[4], pre[] = "everyday", badp[] = "Every";
        size_t bl = gz_ls_cond_encode(&none, b, sizeof b);
        h_arg_t a[3] = {{12, b, bl}, {14, v4, 4}, {18, badp, 5}};
        gz_put_u32(v4, 2);
        CHECK(w_cmd(1, GZ_CMD_API_SET_CONDITIONS, a, 3) == 400);
        a[2].v = pre;
        a[2].len = 8;
        CHECK(w_cmd(1, GZ_CMD_API_SET_CONDITIONS, a, 3) == 200);
        w = view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
        CHECK(w && vf(w, GZ_VST_PRESET, &v) && v.len == 8 && !memcmp(v.data, "everyday", 8) &&
              vf(w, GZ_VST_CONDITIONS, &v) && gz_get_u32(v.data) == 3);
    }
    /* Read back at a start: version, conditions and preset. */
    CHECK(w_restart(1) == GZ_OK);
    CHECK(N[1].n->api.have_cond && N[1].n->api.cond_version == 3 && !strcmp(N[1].n->api.preset, "everyday") &&
          N[1].n->api.cond.limits.min_channel_sat == 0);
    w = view_of(1, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
    CHECK(w && vf(w, GZ_VST_CONDITIONS, &v) && gz_get_u32(v.data) == 3);
    /* A join that names no conditions copies the saved ones (here: none, so
     * the lobby fits and member 1 joins it). */
    CHECK(member_join(1, &u) == 200);
    w_run(2000, 100);
    CHECK(member_ready(1, &u) == 1 && slot(1, &u)->cond.limits.min_channel_sat == 0);

    /* Member 2's link is down when its conditions tighten: its lobby is left
     * only once the leave can reach the host. It is not up again before a
     * restart: the saved conditions do it at the start. */
    link_down(2);
    CHECK(slot(2, &t) && !slot(2, &t)->lobby.m.connected);
    mark = NSENT;
    CHECK(set_cond(2, NULL, &tight, 0, NULL, 0) == 200 && res_text(2, GZ_RESULT_REC_PARAMS, q, sizeof q) &&
          !strcmp(q, "{\"version\":1,\"left_lobbies\":[]}"));
    CHECK(slot(2, &t) && !slot(2, &t)->lobby.m.ended && sent_count(2, mark, GZ_KIND_LEAVE) == 0 &&
          gz_lobby_member_misfits(&slot(2, &t)->lobby.m, &tight));
    CHECK(w_restart(2) == GZ_OK);
    CHECK(N[2].n->api.have_cond && N[2].n->api.cond_version == 1 && N[2].n->api.cond.limits.min_channel_sat == 200000);
    mark = NSENT;
    w_run(3000, 100);
    CHECK(slot(2, &t) == NULL && sent_count(2, mark, GZ_KIND_LEAVE) == 1 &&
          last_sent(2, mark, GZ_KIND_LEAVE, NULL, &m) && m.reason == 1);
    CHECK(host_refused(&t) == 2 && host_ready(&t) == 0);
    /* Its next join copies the saved conditions, which T1 does not fit: it
     * never joins. */
    CHECK(member_join(2, &u) == 200);
    w_run(2000, 100);
    CHECK(slot(2, &u) && slot(2, &u)->cond.limits.min_channel_sat == 200000 && !slot(2, &u)->lobby.m.joined);
    (void)id2;
    no_errors(2);
    w_free(2);
}

/* local-api.md 15.2: POST /host/lobbies/{id}/start's core, the early start;
 * and 13.2's signing_now: no conditions change leaves a lobby whose round
 * is on. */
static void test_api_start(void)
{
    terms_t t;
    uint8_t e8[8];
    uint64_t aside;
    char q[600], p[600], id[GZ_LOCAL_ID_MAX + 1];
    gz_bytes_t v;
    wview_t *w;
    gz_lobby_conditions_t tight, fits;
    const uint32_t freeze_batch[2] = {GZ_REC_FREEZE, GZ_RECORD_REQUEST_ID};
    w_world(3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    make_terms(&t, 4, 3, 2000);
    CHECK(host_open(&t, 0) == 200 && member_join(1, &t) == 200 && member_join(2, &t) == 200);
    w_run(2000, 100);
    CHECK(host_state(&t) == GZ_LOBBY_OPEN && host_ready(&t) == 2);
    aside = gz_fund_set_aside_sat(&slot(0, &t)->lobby.h.terms);
    CHECK(aside == 802811); /* terms.md T7: T1's tree for 3 or 4 members at 100 sat/kvB */
    w = view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &t));
    CHECK(w && vf(w, GZ_VHL_SET_ASIDE, &v) && v.len == 8 && gz_get_u64(v.data) == aside);
    h_arg_t a[2] = {{12, t.scope, 32}, {14, e8, 8}};
    gz_put_u64(e8, aside);
    /* The person's, freshly: never a plain command. */
    CHECK(w_cmd(0, GZ_CMD_LOBBY_START, a, 2) == 403 && w_cmd(0, GZ_CMD_LOBBY_START, a, 1) == 400);
    /* The echo must be the funding engine's set-aside amount. */
    gz_put_u64(e8, aside - 1);
    snprintf(p, sizeof p, "{\"set_aside_sat\":%llu}", (unsigned long long)aside);
    CHECK(w_req(0, GZ_CMD_LOBBY_START, "StartWrongEcho0001", "/api/v1/host/lobbies/x/start", 1, a, 2) == 409 &&
          res_text(0, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "confirm_mismatch") &&
          res_text(0, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, p));
    gz_put_u64(e8, aside + 1);
    CHECK(w_req(0, GZ_CMD_LOBBY_START, "StartWrongEcho0002", "/api/v1/host/lobbies/x/start", 1, a, 2) == 409);
    gz_put_u64(e8, aside);
    /* Two of the minimum's three. */
    CHECK(w_req(0, GZ_CMD_LOBBY_START, "StartBelowMinimum1", "/api/v1/host/lobbies/x/start", 1, a, 2) == 409 &&
          res_text(0, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "below_minimum") &&
          res_text(0, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, "{\"ready\":2,\"minimum\":3}"));
    CHECK(h_records_of(&N[0], GZ_REC_FREEZE) == 0 && h_records_of(&N[0], GZ_RECORD_REQUEST_ID) == 0);
    CHECK(member_join(3, &t) == 200);
    w_run(3000, 100);
    CHECK(host_state(&t) == GZ_LOBBY_OPEN && host_ready(&t) == 3); /* the rule waits: target 4 */
    /* Paused: no ready check, by the rule or by start (11.3). */
    CHECK(w_pause(0, 1, "StartPausedOn00001") == 200);
    CHECK(w_req(0, GZ_CMD_LOBBY_START, "StartWhilePaused01", "/api/v1/host/lobbies/x/start", 1, a, 2) == 409 &&
          res_text(0, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "paused"));
    CHECK(w_pause(0, 0, "StartPausedOff0001") == 200 && host_state(&t) == GZ_LOBBY_OPEN);
    /* Start now: the ready check, its freeze in the batch of the request id. */
    CHECK(w_req(0, GZ_CMD_LOBBY_START, "StartNowAtMinimum1", "/api/v1/host/lobbies/x/start", 1, a, 2) == 202 &&
          res_text(0, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, "{\"stage\":\"ready_check\"}"));
    CHECK(host_state(&t) == GZ_LOBBY_READY_CHECK && h_records_of(&N[0], GZ_REC_FREEZE) == 1 && batch_with(0, freeze_batch, 2));
    /* Its replay does nothing again; a new start is not_open. */
    CHECK(w_req(0, GZ_CMD_LOBBY_START, "StartNowAtMinimum1", "/api/v1/host/lobbies/x/start", 1, a, 2) == 202 &&
          res_text(0, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, "{\"replayed\":true}"));
    CHECK(w_req(0, GZ_CMD_LOBBY_START, "StartNowAgain00001", "/api/v1/host/lobbies/x/start", 1, a, 2) == 409 &&
          res_text(0, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "not_open"));
    for (int k = 0; k < 2400 && !(ss_of(1, &t) && ss_of(2, &t) && ss_of(3, &t)); k++) {
        NOW += 25;
        w_turn();
    }
    CHECK(host_state(&t) == GZ_LOBBY_SIGNING && ss_of(1, &t) && ss_of(2, &t) && ss_of(3, &t));
    /* signing_now: conditions that would leave a lobby whose round is on are
     * refused, with nothing saved; ones it still fits are taken. */
    memset(&tight, 0, sizeof tight);
    tight.limits.min_channel_sat = 200000;
    fits = tight;
    fits.limits.min_channel_sat = 50000;
    snprintf(id, sizeof id, "%s", lid(1, &t));
    snprintf(p, sizeof p, "{\"lobby_ids\":[\"%s\"]}", id);
    CHECK(set_cond(1, NULL, &tight, 0, NULL, 0) == 409 && res_text(1, GZ_RESULT_REC_ERROR, q, sizeof q) &&
          !strcmp(q, "signing_now") && res_text(1, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, p));
    CHECK(h_records_of(&N[1], GZ_RECORD_CONDITIONS) == 0 && slot(1, &t) && !slot(1, &t)->lobby.m.ended);
    CHECK(set_cond(1, NULL, &fits, 0, NULL, 0) == 200 && h_records_of(&N[1], GZ_RECORD_CONDITIONS) == 1);
    w_run(2000, 100);
    CHECK(slot(1, &t) && !slot(1, &t)->lobby.m.ended && ss_of(1, &t));
    no_errors(3);
    w_free(3);
}


/* Review of #77. L1: after a ready check that ended without a start, an
 * early start with the same seats is refused (refused_now) until a seat
 * changes. L2: the set-aside amount the start echoes is the funding at the
 * target, the amount the opening's preview showed, for every target the
 * tests use. */
static void test_api_start_guard(void)
{
    terms_t t;
    uint8_t e8[8], cb[COND_MAX];
    char q[200];
    gz_lobby_conditions_t hint;
    gz_tree_params_t tp;
    gz_terms_outer_t o;
    lt_key_t hk;
    /* L2 */
    for (uint16_t target = 3; target <= 8; target++) {
        terms_t x;
        make_terms(&x, target, 3, 2100 + target);
        CHECK(lt_outer(x.outer, x.on, &o) && gz_tree_params(&o, target, &tp) == GZ_TREE_P_OK &&
              gz_fund_set_aside_sat(&o) == tp.funding_amount);
    }
    /* L1: three members whose ready hint is four, in a lobby of four (minimum three). */
    memset(&hint, 0, sizeof hint);
    hint.min_members = 4;
    size_t cn = gz_ls_cond_encode(&hint, cb, sizeof cb);
    w_world(3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    make_terms(&t, 4, 3, 2200);
    CHECK(host_open(&t, 0) == 200);
    whost(&hk);
    for (int n = 1; n <= 3; n++) {
        h_arg_t j[4] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}, {18, cb, cn}};
        CHECK(w_cmd(n, GZ_CMD_LOBBY_JOIN, j, 4) == 200);
    }
    w_run(3000, 100);
    CHECK(host_state(&t) == GZ_LOBBY_OPEN && host_ready(&t) == 3);
    h_arg_t a[2] = {{12, t.scope, 32}, {14, e8, 8}};
    gz_put_u64(e8, gz_fund_set_aside_sat(&slot(0, &t)->lobby.h.terms));
    CHECK(w_req(0, GZ_CMD_LOBBY_START, "GuardStartFirst001", "/api/v1/host/lobbies/x/start", 1, a, 2) == 202);
    w_run(40000, 100); /* T1's ready window is 30 s: the check ends, no start (each wants four) */
    CHECK(host_state(&t) == GZ_LOBBY_OPEN && host_ready(&t) == 3 && slot(0, &t)->lobby.h.check_failed);
    CHECK(w_req(0, GZ_CMD_LOBBY_START, "GuardStartAgain001", "/api/v1/host/lobbies/x/start", 1, a, 2) == 409 &&
          res_text(0, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "refused_now") &&
          host_state(&t) == GZ_LOBBY_OPEN);
    /* A seat event: member 1 unreadies and readies again. */
    CHECK(scope_cmd(1, GZ_CMD_LOBBY_UNREADY, &t, 0) == 200);
    w_run(500, 100);
    CHECK(scope_cmd(1, GZ_CMD_LOBBY_READY, &t, 0) == 200);
    w_run(1000, 100);
    CHECK(host_ready(&t) == 3);
    CHECK(w_req(0, GZ_CMD_LOBBY_START, "GuardStartAfter001", "/api/v1/host/lobbies/x/start", 1, a, 2) == 202 &&
          host_state(&t) == GZ_LOBBY_READY_CHECK);
    no_errors(3);
    w_free(3);
}

/* Review of #77, L3: with saved conditions, a join that names its own
 * conditions looser than them needs the fresh sign-in and the echo of what
 * it loosens (field 22), as PUT /conditions does; a confirmed one keeps its
 * looser copy until the person's conditions next change. */
static void test_api_join_looser(void)
{
    terms_t t;
    gz_lobby_conditions_t none, tight;
    uint8_t cb[COND_MAX], tb[COND_MAX], ch = GZ_TT_CHANNEL, bad = 9;
    char q[200];
    lt_key_t hk;
    memset(&none, 0, sizeof none);
    tight = none;
    tight.limits.min_channel_sat = 200000;
    size_t cn = gz_ls_cond_encode(&none, cb, sizeof cb), tn = gz_ls_cond_encode(&tight, tb, sizeof tb);
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 4, 3, 2300);
    CHECK(host_open(&t, 0) == 200);
    CHECK(set_cond(1, NULL, &tight, 0, NULL, 0) == 200);
    whost(&hk);
    h_arg_t j[5] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}, {18, cb, cn}, {22, &ch, 1}};
    /* Looser than the saved ones, as a plain command: refused, no slot. */
    CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, j, 4) == 403 && slot(1, &t) == NULL);
    /* As an API request: the echo must be exactly what it loosens. */
    CHECK(w_req(1, GZ_CMD_LOBBY_JOIN, "JoinLooserNoEcho01", "/api/v1/lobbies/x/join", 4, j, 4) == 409 &&
          res_text(1, GZ_RESULT_REC_ERROR, q, sizeof q) && !strcmp(q, "confirm_mismatch") &&
          res_text(1, GZ_RESULT_REC_PARAMS, q, sizeof q) && !strcmp(q, "{\"loosens\":[30]}") && slot(1, &t) == NULL);
    j[4].v = &bad;
    CHECK(w_req(1, GZ_CMD_LOBBY_JOIN, "JoinLooserBadEcho1", "/api/v1/lobbies/x/join", 4, j, 5) == 409 && slot(1, &t) == NULL);
    /* Its own conditions no looser than the saved ones: a plain join. */
    {
        h_arg_t k[4] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}, {18, tb, tn}};
        terms_t u;
        make_terms(&u, 4, 3, 2301);
        CHECK(host_open(&u, 0) == 200);
        k[0].v = u.scope;
        CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, k, 4) == 200 && slot(1, &u) != NULL);
    }
    /* With the echo: it joins under its looser copy and stays, also across a restart. */
    j[4].v = &ch;
    CHECK(w_req(1, GZ_CMD_LOBBY_JOIN, "JoinLooserEcho0001", "/api/v1/lobbies/x/join", 4, j, 5) == 200);
    w_run(2000, 100);
    CHECK(slot(1, &t) && member_ready(1, &t) == 1 && slot(1, &t)->cond.limits.min_channel_sat == 0);
    CHECK(w_restart(1) == GZ_OK);
    w_run(2000, 100);
    CHECK(slot(1, &t) && member_ready(1, &t) == 1);
    /* Confirmation of #77, N2: the same conditions saved anew, and a
     * loosening, tighten nothing: the confirmed looser copy stays. */
    CHECK(set_cond(1, NULL, &tight, 1, NULL, 0) == 200);
    w_run(1000, 100);
    CHECK(slot(1, &t) && member_ready(1, &t) == 1 && !slot(1, &t)->lobby.m.ended);
    {
        gz_lobby_conditions_t looser = tight;
        looser.limits.min_channel_sat = 150000;
        CHECK(set_cond(1, "CondLoosenAfterJn1", &looser, 2, &ch, 1) == 200);
        w_run(1000, 100);
        CHECK(slot(1, &t) && member_ready(1, &t) == 1);
        /* A change that tightens something reaches it: it is left. */
        looser.limits.min_channel_sat = 250000;
        CHECK(set_cond(1, NULL, &looser, 3, NULL, 0) == 200);
        w_run(1000, 100);
        CHECK(slot(1, &t) == NULL && host_refused(&t) == 1);
    }
    no_errors(1);
    w_free(1);
}

/* Review of #77, L5: a DISCONNECT sends what its own side had queued on the
 * link first (action.h); what the other side had queued to it is lost, as
 * the program reads nothing more on a closing link (program/net.c). */
static void test_harness_flush(void)
{
    terms_t t;
    wconn_t *c = NULL;
    lt_key_t hk;
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 4, 3, 2400);
    CHECK(host_open(&t, 0) == 200 && member_join(1, &t) == 200);
    w_run(2000, 100);
    for (int i = 0; i < 64; i++)
        if (C[i].used && C[i].node == 1 && C[i].up == 1) c = &C[i];
    CHECK(c != NULL);
    if (!c) return;
    whost(&hk);
    /* One hello each way, then member 1 closes the link. */
    for (int dir = 0; dir < 2 && NQ < 8190; dir++) {
        wmsg_t *m = &Q[NQ++];
        m->to = dir == 0 ? 0 : 1;
        m->link = dir == 0 ? h_link(hk.pub, c->mlink.local.key) : c->mlink;
        m->kind = GZ_KIND_HELLO;
        memcpy(m->scope, t.scope, 32);
        m->len = 0;
        m->rec = malloc(1);
    }
    c->up = -1;
    c->closer = 1;
    c->wanted = 0; /* and it stays down */
    unsigned long d0 = DELIVERED[0], d1 = DELIVERED[1];
    w_turn();
    CHECK(DELIVERED[0] > d0 && DELIVERED[1] == d1);
    no_errors(1);
    w_free(1);
}


/* Confirmation of #77, N1: a slot's field 24 (the saved conditions' version
 * when it joined) above the loaded conditions' version, or a conditions
 * record whose field 8 (the last tightening) is above its own version, is a
 * corrupt journal; checked once the walk is over, whatever the order. */
static void test_cond_seen_load(void)
{
    lt_key_t hk;
    terms_t t;
    whost(&hk);
    w_reset();
    make_terms(&t, 3, 3, 710);
    for (int k = 0; k < 5; k++) {
        h_t *x = &N[SCRATCH];
        uint8_t rec[300], v[4], cr[64];
        size_t at = 0, cat = 0;
        gz_status_t st;
        w_node(SCRATCH, 5, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
        gz_put_u32(v, 1);
        gz_rec_put(rec, sizeof rec, &at, 2, v, 4);
        gz_rec_put(rec, sizeof rec, &at, 4, t.scope, 32);
        v[0] = 0;
        gz_rec_put(rec, sizeof rec, &at, 6, v, 1);
        gz_rec_put(rec, sizeof rec, &at, 8, hk.pub, 33);
        gz_rec_put(rec, sizeof rec, &at, 10, (const uint8_t *)ADDR, sizeof ADDR - 1);
        gz_put_u32(v, 0);
        gz_rec_put(rec, sizeof rec, &at, 12, v, 4);
        gz_put_u32(v, 1);
        gz_rec_put(rec, sizeof rec, &at, 14, v, 4);
        v[0] = 1;
        gz_rec_put(rec, sizeof rec, &at, 22, v, 1);
        gz_put_u32(v, 5);
        gz_rec_put(rec, sizeof rec, &at, 24, v, 4);      /* joined under conditions version 5 */
        /* k 0: no conditions saved; 1: version 4; 2: version 5; 3: version 5,
         * last tightening 6; 4: version 5, last tightening 5. */
        gz_rec_put(cr, sizeof cr, &cat, 2, v, 0);
        gz_put_u32(v, k == 1 ? 4 : 5);
        gz_rec_put(cr, sizeof cr, &cat, 4, v, 4);
        if (k >= 3) {
            gz_put_u32(v, k == 3 ? 6 : 5);
            gz_rec_put(cr, sizeof cr, &cat, 8, v, 4);
        }
        h_add_batch(x, 1, 1, GZ_RECORD_SLOT_OPENED, rec, at);
        if (k) h_add_batch(x, 1, 2, GZ_RECORD_CONDITIONS, cr, cat);
        x->incarnation = 1;
        h_new_node(x);
        st = w_start(SCRATCH);
        CHECK(k == 2 || k == 4 ? st == GZ_OK : st == GZ_ERR_CORRUPT);
        if (k == 2) {
            int i = gz_route_slot_by_scope(x->n, t.scope);
            CHECK(i >= 0 && x->n->slots[i].cond_seen == 5);
        }
        ALIVE[SCRATCH] = 0;
        NT[SCRATCH] = 0;
        for (int i = 0; i < 64; i++)
            if (C[i].used && C[i].node == SCRATCH) C[i].used = 0;
        h_free(x);
        memset(x, 0, sizeof *x);
    }
    CHECK(ERRORS == 0);
}

/* A member asks a host for its lobbies (W12: LOBBY_QUERY; messages.md 6.1):
 * the listed lobby is seen, checked and shown (kind 2 with no seat, its fit,
 * its signed terms), the unlisted one is not; the query is answered (kind
 * 10); a join of the seen lobby keeps its local id. A host key that is not
 * the host's gets nothing (failed, no_answer); a host that is down,
 * unreachable. The query's key pair is saved before its CONNECT. */
static void test_discovery(void)
{
    terms_t t, u;
    lt_key_t hk;
    char qid[32], lob[GZ_LOCAL_ID_MAX + 1];
    gz_bytes_t v;
    wview_t *w;
    size_t nb;
    whost(&hk);
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 3100);
    make_terms(&u, 3, 3, 3101);
    CHECK(host_open(&t, 1) == 200 && host_open(&u, 0) == 200);
    {
        h_arg_t q[2] = {{12, hk.pub, 33}, {14, ADDR, sizeof ADDR - 1}};
        nb = N[1].n_batches;
        CHECK(w_req(1, GZ_CMD_LOBBY_QUERY, "QueryHostLobbies01", "/api/v1/discovery/query", 1, q, 2) == 202);
        CHECK(N[1].n_batches == nb + 1 && h_records_of(&N[1], GZ_RECORD_KEY_INDEX) >= 1);
        CHECK(res_text(1, GZ_RESULT_REC_OBJECT, qid, sizeof qid) && !strncmp(qid, "q_", 2));
        CHECK(w_req(1, GZ_CMD_LOBBY_QUERY, "QueryHostLobbies02", "/api/v1/discovery/query", 1, q, 2) == 409);
    }
    w = view_of(1, GZ_VIEW_DISCOVERY, qid);
    CHECK(w && vf8(w, GZ_VDQ_STATE) == 1);
    w_run(4000, 100);
    w = view_of(1, GZ_VIEW_DISCOVERY, qid);
    CHECK(w && vf8(w, GZ_VDQ_STATE) == 2 && vf(w, GZ_VDQ_LOBBIES, &v) && v.len == 20 && !vf(w, GZ_VDQ_FAILED, &v));
    lob[0] = 0;
    if (vf(w, GZ_VDQ_LOBBIES, &v) && v.len < sizeof lob) {
        memcpy(lob, v.data, v.len);
        lob[v.len] = 0;
    }
    CHECK(gz_api_local_id(N[1].n, t.scope) && !strcmp(gz_api_local_id(N[1].n, t.scope), lob));
    CHECK(gz_api_local_id(N[1].n, u.scope) == NULL);           /* unlisted: not seen */
    w = view_of(1, GZ_VIEW_LOBBY, lob);
    CHECK(w && vf8(w, GZ_VLB_SEAT) == GZ_VSEAT_NONE && vf(w, GZ_VLB_FINGERPRINT, &v) && !memcmp(v.data, t.scope, 32));
    CHECK(vf(w, GZ_VLB_OUTER, &v) && v.len == t.on && !memcmp(v.data, t.outer, t.on));
    CHECK(vf(w, GZ_VLB_FIT, &v) && v.len == 18 && v.data[0] == GZ_VFIT_FITS && vf(w, GZ_VLB_SEEN, &v));
    CHECK(vf(w, GZ_VLB_HOST_KEY, &v) && !memcmp(v.data, hk.pub, 33));
    /* The link is closed once answered; a join of the seen lobby keeps its id. */
    CHECK(slot(1, &t) == NULL && member_join(1, &t) == 200 && !strcmp(lid(1, &t), lob));
    w_run(2000, 100);
    CHECK(member_ready(1, &t) == 1 && view_of(1, GZ_VIEW_LOBBY, lob) && vf8(view_of(1, GZ_VIEW_LOBBY, lob), GZ_VLB_SEAT) == GZ_VSEAT_READY);
    /* A restart keeps the joined lobby's id (saved with its slot). */
    CHECK(w_restart(1) == GZ_OK && !strcmp(lid(1, &t), lob));
    /* Another host key: the offers do not check out against it; nothing seen. */
    {
        lt_key_t other;
        wkey(5, 0, 900, &other);
        h_arg_t q[2] = {{12, other.pub, 33}, {14, ADDR, sizeof ADDR - 1}};
        CHECK(w_req(1, GZ_CMD_LOBBY_QUERY, "QueryOtherKey00001", "/api/v1/discovery/query", 1, q, 2) == 202);
        CHECK(res_text(1, GZ_RESULT_REC_OBJECT, qid, sizeof qid));
        w_run(12000, 250);
        w = view_of(1, GZ_VIEW_DISCOVERY, qid);
        CHECK(w && vf8(w, GZ_VDQ_STATE) == 3 && !vf(w, GZ_VDQ_LOBBIES, &v) && vf(w, GZ_VDQ_FAILED, &v) && v.len == 9 &&
              !memcmp(v.data, "no_answer", 9));
    }
    /* The host down: unreachable. */
    {
        h_arg_t q[2] = {{12, hk.pub, 33}, {14, ADDR, sizeof ADDR - 1}};
        ALIVE[0] = 0;
        CHECK(w_req(1, GZ_CMD_LOBBY_QUERY, "QueryHostDown00001", "/api/v1/discovery/query", 1, q, 2) == 202);
        CHECK(res_text(1, GZ_RESULT_REC_OBJECT, qid, sizeof qid));
        w_run(12000, 250);
        w = view_of(1, GZ_VIEW_DISCOVERY, qid);
        CHECK(w && vf8(w, GZ_VDQ_STATE) == 3 && vf(w, GZ_VDQ_FAILED, &v) && v.len == 11 && !memcmp(v.data, "unreachable", 11));
        ALIVE[0] = 1;
    }
    /* A host asks nobody: not a member. */
    {
        h_arg_t q[2] = {{12, hk.pub, 33}, {14, ADDR, sizeof ADDR - 1}};
        CHECK(w_req(0, GZ_CMD_LOBBY_QUERY, "QueryFromHost00001", "/api/v1/discovery/query", 1, q, 2) == 409);
    }
    no_errors(1);
    w_free(1);
}

/* Decision K21 (local-api.md 15.3): a seat that refused stays shown as
 * refused while the member, back as a new seat with a new key, readies; the
 * lobby's next attempt (its ready check) ends the showing. */
static void test_refusal_until_next_attempt(void)
{
    terms_t t;
    lt_key_t hk, m3;
    gz_link_t l3;
    gz_bytes_t v;
    wview_t *w;
    uint8_t rec[4] = {0x01, 0x02, 0x00, 0x01}, e8[8];
    whost(&hk);
    w_world(4, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    make_terms(&t, 4, 3, 2100);
    CHECK(host_open(&t, 0) == 200 && member_join(1, &t) == 200 && member_join(2, &t) == 200 && member_join(3, &t) == 200);
    w_run(2000, 100);
    CHECK(host_ready(&t) == 3);
    /* Member 3 refuses at Open (leave reason 1): its seat is refused, never left. */
    wkey(3, 0, slot(3, &t)->key_index, &m3);
    l3 = h_link(hk.pub, m3.pub);
    w_msg(0, &l3, GZ_KIND_LEAVE, t.scope, rec, sizeof rec);
    w = view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &t));
    CHECK(w && vf(w, GZ_VHL_COUNTS, &v) && gz_get_u16(v.data + 6) == 1);
    /* Member 4 comes (as a rejoin does, a new key): ready, and the refused seat is still shown. */
    CHECK(member_join(4, &t) == 200);
    w_run(2000, 100);
    w = view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &t));
    CHECK(host_ready(&t) == 3 && w && vf(w, GZ_VHL_COUNTS, &v) && gz_get_u16(v.data + 6) == 1 && host_state(&t) == GZ_LOBBY_OPEN);
    /* The early start begins the next attempt: the refusal is no longer shown. */
    gz_put_u64(e8, gz_fund_set_aside_sat(&slot(0, &t)->lobby.h.terms));
    h_arg_t a[2] = {{12, t.scope, 32}, {14, e8, 8}};
    CHECK(w_req(0, GZ_CMD_LOBBY_START, "K21StartAttempt001", "/api/v1/host/lobbies/x/start", 1, a, 2) == 202);
    w = view_of(0, GZ_VIEW_HOST_LOBBY, lid(0, &t));
    CHECK(host_state(&t) == GZ_LOBBY_READY_CHECK && w && vf(w, GZ_VHL_COUNTS, &v) && gz_get_u16(v.data + 6) == 0);
    CHECK(vf(w, GZ_VHL_SEATS, &v));
    for (size_t k = 0; k + GZ_VHL_SEAT_LEN <= v.len; k += GZ_VHL_SEAT_LEN)
        CHECK(v.data[k + 33] != GZ_VSEAT_REFUSED && !(v.data[k + 34] & GZ_VHL_F_REFUSED));
    no_errors(4);
    w_free(4);
}

/* AT_JOIN, joined ready with the passphrase (LOBBY_JOIN 24, W12): the gate is
 * open from the join, so the member readies by itself and is counted; without
 * it, the member joins, locked, and is not. */
static void test_join_unlocked(void)
{
    terms_t t;
    lt_key_t hk;
    uint8_t one = 1;
    whost(&hk);
    w_world(2, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_UNFINISHED);
    make_terms(&t, 3, 3, 3200);
    CHECK(host_open(&t, 0) == 200);
    uint8_t d[32];
    gz_terms_current_digest(t.current, t.cn, d);
    h_arg_t j[5] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}, {24, &one, 1}, {26, d, 32}};
    CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, j, 5) == 200 && member_join(2, &t) == 200);
    w_run(3000, 100);
    CHECK(member_ready(1, &t) == 1 && slot(1, &t)->gate_open && host_ready(&t) == 1);
    CHECK(member_ready(2, &t) != 1 && !slot(2, &t)->gate_open);
    no_errors(2);
    w_free(2);
}

/* Review of #79, M1: the gate opened by a join or a ready under AT_JOIN is
 * bound to the values the person reviewed (local-api.md 14.3 rule 2). The
 * host changes its values between the query and the join: the member does
 * not ready under values it never saw, and the person must ready again. */
static void test_gate_bound_to_seen(void)
{
    terms_t t;
    lt_key_t hk;
    uint8_t one = 1, d0[32], d1[32], vals[24];
    gz_bytes_t v;
    wview_t *w;
    slot_t *s;
    whost(&hk);
    w_world(1, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_UNFINISHED);
    make_terms(&t, 3, 3, 3300);
    CHECK(host_open(&t, 0) == 200);
    gz_terms_current_digest(t.current, t.cn, d0);            /* what the person reviewed */
    {
        h_arg_t j[4] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}, {24, &one, 1}};
        CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, j, 4) == 400 && slot(1, &t) == NULL);   /* no digest: refused */
    }
    gz_put_u64(vals, 600);
    gz_put_u64(vals + 8, 1000);
    gz_put_u64(vals + 16, 1000);
    {
        h_arg_t sv[2] = {{12, t.scope, 32}, {14, vals, 24}};
        CHECK(w_cmd(0, GZ_CMD_LOBBY_SET_VALUES, sv, 2) == 200);
    }
    {
        h_arg_t j[5] = {{12, t.scope, 32}, {14, hk.pub, 33}, {16, ADDR, sizeof ADDR - 1}, {24, &one, 1}, {26, d0, 32}};
        CHECK(w_cmd(1, GZ_CMD_LOBBY_JOIN, j, 5) == 200);
    }
    w_run(3000, 100);
    s = slot(1, &t);
    CHECK(s && s->gate_open && s->lobby.m.have_terms && memcmp(s->lobby.m.current_digest, d0, 32) != 0);
    CHECK(member_ready(1, &t) != 1 && host_ready(&t) == 0);  /* not under values the person never saw */
    w = view_of(1, GZ_VIEW_LOBBY, lid(1, &t));
    CHECK(w && vf(w, GZ_VLB_GATE, &v) && v.len == 42 && !memcmp(v.data + 10, d0, 32));   /* opened for d0 */
    if (s) {
        h_arg_t r0[2] = {{12, t.scope, 32}, {14, &one, 1}};
        h_arg_t r1[3] = {{12, t.scope, 32}, {14, &one, 1}, {16, d0, 32}};
        CHECK(w_cmd(1, GZ_CMD_LOBBY_READY, r0, 2) == 400);   /* a ready names what it was for */
        CHECK(w_cmd(1, GZ_CMD_LOBBY_READY, r1, 3) == 409);   /* terms_changed */
        w_run(1000, 100);
        CHECK(member_ready(1, &t) != 1 && host_ready(&t) == 0);
        memcpy(d1, s->lobby.m.current_digest, 32);
        h_arg_t r2[3] = {{12, t.scope, 32}, {14, &one, 1}, {16, d1, 32}};
        CHECK(w_cmd(1, GZ_CMD_LOBBY_READY, r2, 3) == 200);   /* the person readies again, for the new values */
        w_run(2000, 100);
        CHECK(member_ready(1, &t) == 1 && host_ready(&t) == 1);
        w = view_of(1, GZ_VIEW_LOBBY, lid(1, &t));
        CHECK(w && vf(w, GZ_VLB_GATE, &v) && v.len == 42 && !memcmp(v.data + 10, d1, 32));
    }
    no_errors(1);
    w_free(1);
}

/* Review of #79, M3 (local-api.md 7.4): a ready replayed without the
 * passphrase is looked up first and answered from the first answer; a new
 * request without it (28) is refused, keeps no id, and does nothing. */
static void test_ready_replay_without_passphrase(void)
{
    terms_t t;
    uint8_t one = 1, d[32];
    char e[64];
    const char *path = "/api/v1/lobbies/lob_x/ready";
    w_world(1, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_UNFINISHED);
    make_terms(&t, 3, 3, 3400);
    CHECK(host_open(&t, 0) == 200 && member_join(1, &t) == 200);
    w_run(3000, 100);
    CHECK(slot(1, &t) && slot(1, &t)->lobby.m.have_terms && member_ready(1, &t) != 1);
    memset(d, 0, sizeof d);
    if (slot(1, &t)) memcpy(d, slot(1, &t)->lobby.m.current_digest, 32);
    h_arg_t with[3] = {{12, t.scope, 32}, {14, &one, 1}, {16, d, 32}};
    h_arg_t without[3] = {{12, t.scope, 32}, {16, d, 32}, {28, &one, 1}};
    CHECK(w_req(1, GZ_CMD_LOBBY_READY, "ReadyNoPassNew0001", path, 8, without, 3) == 400);
    CHECK(res_text(1, GZ_RESULT_REC_ERROR, e, sizeof e) && !strcmp(e, "missing_field"));
    w_run(1000, 100);
    CHECK(member_ready(1, &t) != 1 && slot(1, &t) && !slot(1, &t)->gate_open);    /* nothing done */
    CHECK(w_req(1, GZ_CMD_LOBBY_READY, "ReadyWithPass00001", path, 7, with, 3) == 200);
    w_run(2000, 100);
    CHECK(member_ready(1, &t) == 1);
    CHECK(w_req(1, GZ_CMD_LOBBY_READY, "ReadyWithPass00001", path, 7, without, 3) == 200);
    CHECK(res_text(1, GZ_RESULT_REC_PARAMS, e, sizeof e) && !strcmp(e, "{\"replayed\":true}"));
    no_errors(1);
    w_free(1);
}

/* Review of #79, M2: a query's seen lobbies live in a table of their own
 * and end at the next query, so repeated queries neither fill the
 * program's view table nor churn the saved ids (an ended lobby's id stays). */
static void test_discovery_repeat(void)
{
    terms_t t, x;
    lt_key_t hk;
    char xid[GZ_LOCAL_ID_MAX + 1], tid[GZ_LOCAL_ID_MAX + 1], rid[40];
    int used = 0, live = 0, now = 0;
    whost(&hk);
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    make_terms(&t, 3, 3, 3500);
    make_terms(&x, 3, 3, 3501);
    CHECK(host_open(&t, 1) == 200 && host_open(&x, 0) == 200 && member_join(1, &x) == 200);
    w_run(2000, 100);
    snprintf(xid, sizeof xid, "%s", lid(1, &x));
    CHECK(xid[0] && scope_cmd(1, GZ_CMD_LOBBY_LEAVE, &x, 0) == 200);
    w_run(5000, 100);
    CHECK(slot(1, &x) == NULL && gz_api_local_id(N[1].n, x.scope) && !strcmp(gz_api_local_id(N[1].n, x.scope), xid));
    for (int k = 0; k < API_MAX_IDS; k++) used += N[1].n->api.ids[k].used;
    tid[0] = 0;
    for (int i = 0; i < 40; i++) {
        h_arg_t q[2] = {{12, hk.pub, 33}, {14, ADDR, sizeof ADDR - 1}};
        const char *id;
        snprintf(rid, sizeof rid, "QueryRepeat%08d", i);
        CHECK(w_req(1, GZ_CMD_LOBBY_QUERY, rid, "/api/v1/discovery/query", (uint8_t)(i + 1), q, 2) == 202);
        w_run(4000, 100);
        id = gz_api_local_id(N[1].n, t.scope);
        CHECK(id != NULL);
        if (id && !tid[0]) snprintf(tid, sizeof tid, "%s", id);
        CHECK(id && !strcmp(id, tid));                           /* seen again: the same id for the run */
    }
    for (int k = 0; k < NV; k++)
        live += VW[1][k].used && !VW[1][k].stale && !VW[1][k].gone && VW[1][k].kind == GZ_VIEW_DISCOVERY;
    CHECK(live == 1);                                            /* only the last query */
    for (int k = 0; k < API_MAX_IDS; k++) now += N[1].n->api.ids[k].used;
    CHECK(now == used);                                          /* the seen lobby is not among the saved ids */
    CHECK(gz_api_local_id(N[1].n, x.scope) && !strcmp(gz_api_local_id(N[1].n, x.scope), xid));
    no_errors(1);
    w_free(1);
}

/* Review of #79: no two links get the same key index (a query's fresh pair
 * must not tie it to the member's other links). A member with a test engine
 * target (the program's --connect, which picks its own index), then queries,
 * a join, a restart, more of each: every pair is apart from every other. */
static uint32_t PAIRS[32];
static int NPAIRS;

static void pair_note(uint32_t first)
{
    if (NPAIRS < 32) PAIRS[NPAIRS++] = first;
}

static void test_index_unique(void)
{
    terms_t t, u;
    lt_key_t hk;
    char rid[40];
    int ok = 1;
    whost(&hk);
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    W_TEST_ENGINES = 1;                                        /* the member has the program's --connect engine */
    w_node(1, 1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    W_TEST_ENGINES = 0;
    for (int n = 0; n <= 1; n++) CHECK(w_start(n) == GZ_OK);
    NPAIRS = 0;
    {
        h_arg_t a[2] = {{12, hk.pub, 33}, {14, ADDR, sizeof ADDR - 1}};
        /* the test engine answers no result notice; its saved target is the check */
        CHECK(w_cmd(1, GZ_TE_CMD_CONNECT, a, 2) >= 0 && N[1].n->n_test == 1 && N[1].n->test[0].n_targets == 1);
        if (N[1].n->test[0].n_targets) pair_note(N[1].n->test[0].targets[0].index);
    }
    make_terms(&t, 3, 3, 3600);
    make_terms(&u, 3, 3, 3601);
    CHECK(host_open(&t, 1) == 200 && host_open(&u, 1) == 200);
    for (int round = 0; round < 2; round++) {
        h_arg_t q[2] = {{12, hk.pub, 33}, {14, ADDR, sizeof ADDR - 1}};
        snprintf(rid, sizeof rid, "QueryIndexUnique%02d", round);
        CHECK(w_req(1, GZ_CMD_LOBBY_QUERY, rid, "/api/v1/discovery/query", (uint8_t)(40 + round), q, 2) == 202);
        pair_note(N[1].n->dq.key_index);
        w_run(4000, 100);
        CHECK(member_join(1, round ? &u : &t) == 200 && slot(1, round ? &u : &t));
        if (slot(1, round ? &u : &t)) pair_note(slot(1, round ? &u : &t)->key_index);
        w_run(2000, 100);
        if (!round) {
            /* The test engine's own view object (test builds only, id "test-...") starts at
             * version 0 at every start; it alone is forgotten here, so the version rule still
             * holds for every other object the member emits across this restart. */
            for (int k = 0; k < NV; k++)
                if (VW[1][k].used && !strncmp(VW[1][k].id, "test-", 5)) memset(&VW[1][k], 0, sizeof VW[1][k]);
            CHECK(w_restart(1) == GZ_OK);                     /* the allocator comes back from the journal */
        }
    }
    CHECK(NPAIRS == 5);
    for (int i = 0; i < NPAIRS; i++)
        for (int j = i + 1; j < NPAIRS; j++)
            if (PAIRS[i] == PAIRS[j] || PAIRS[i] == PAIRS[j] + 1 || PAIRS[i] + 1 == PAIRS[j]) ok = 0;
    if (!ok)
        for (int i = 0; i < NPAIRS; i++) printf("  pair %d: %u\n", i, (unsigned)PAIRS[i]);
    CHECK(ok);
    no_errors(1);
    w_free(1);
}

/* Review of #79 (local-api.md 14.3 rule 1): the per-lobby gate closes when the
 * seat ends, not only when the slot closes. A member that joined ready with the
 * passphrase and then leaves, and one whose tightened conditions make it refuse:
 * each gate is closed at once, its scoped secret wiped, the view says closed,
 * and nothing more is signed for it. */
static void test_gate_closes_with_seat(void)
{
    terms_t t;
    lt_key_t hk;
    gz_bytes_t v;
    wview_t *w;
    int forgets, signs;
    char l1[GZ_LOCAL_ID_MAX + 1], l2[GZ_LOCAL_ID_MAX + 1];
    whost(&hk);
    w_world(2, GZ_MEMBER_SIGNING_AT_JOIN, GZ_TEST_SIGN_UNFINISHED);
    make_terms(&t, 4, 3, 3700);
    CHECK(host_open(&t, 0) == 200 && member_join(1, &t) == 200 && member_join(2, &t) == 200);
    w_run(3000, 100);
    CHECK(scope_cmd(1, GZ_CMD_LOBBY_READY, &t, 1) == 200 && scope_cmd(2, GZ_CMD_LOBBY_READY, &t, 1) == 200);
    w_run(2000, 100);
    CHECK(slot(1, &t) && slot(1, &t)->gate_open && slot(2, &t) && slot(2, &t)->gate_open);
    snprintf(l1, sizeof l1, "%s", lid(1, &t));
    snprintf(l2, sizeof l2, "%s", lid(2, &t));
    /* 1 leaves */
    forgets = FORGETS[1];
    CHECK(scope_cmd(1, GZ_CMD_LOBBY_LEAVE, &t, 0) == 200);
    w_run(500, 100);
    if (slot(1, &t)) CHECK(slot(1, &t)->lobby.m.left && !slot(1, &t)->gate_open && !slot(1, &t)->gate_have);
    /* the lobby object as the program last holds it, whether the slot is still there or not */
    w = view_of(1, GZ_VIEW_LOBBY, l1);
    CHECK(w && (!vf(w, GZ_VLB_GATE, &v) || (v.len == 10 && v.data[1] == 0)));  /* closed, opened for nothing */
    CHECK(FORGETS[1] == forgets + 1);                                          /* the scoped secret wiped */
    /* 2's conditions tighten past the lobby's minimum: it refuses (leaves, reason 1) */
    forgets = FORGETS[2];
    signs = SIGNS[2];
    {
        uint8_t cb[64];
        size_t n = 27;
        memset(cb, 0, sizeof cb);
        gz_put_u16(cb + 1, 4);                      /* min_members, the ready hint */
        gz_put_u16(cb + 23, 4);                     /* limits.min_members */
        h_arg_t a[2] = {{12, cb, n}, {14, (const uint8_t *)"\0\0\0\0", 4}};
        CHECK(w_req(2, GZ_CMD_API_SET_CONDITIONS, "GateClosesRefused01", "/api/v1/conditions", 3, a, 2) == 200);
    }
    w_run(2000, 100);
    if (slot(2, &t))
        CHECK((slot(2, &t)->lobby.m.left || slot(2, &t)->lobby.m.ended) && !slot(2, &t)->gate_open && !slot(2, &t)->gate_have);
    w = view_of(2, GZ_VIEW_LOBBY, l2);
    CHECK(w && (!vf(w, GZ_VLB_GATE, &v) || (v.len == 10 && v.data[1] == 0)));
    CHECK(FORGETS[2] == forgets + 1);
    w_run(20000, 500);
    CHECK(SIGNS[2] == signs + 1 || SIGNS[2] == signs);   /* its leave at most; nothing after */
    signs = SIGNS[2];
    w_run(20000, 500);
    CHECK(SIGNS[2] == signs && SIGNS[1] >= 0);
    no_errors(2);
    w_free(2);
}


/* Review B of PR 52, M1 and L4: the member's ack-time check judges the round's own leaf depth, also after
 * a start, which restores nothing a builder left in the slot; and with no tip it says not yet, never no.
 * Member 1 restarts on its storage; the hook is then asked about a round in its lobby, at the last tip its
 * true depth acks at, one block later (which depth 0 would still ack), and with no tip. */
static void test_may_ack_depth(void)
{
    terms_t t;
    gz_tree_params_t prm;
    gz_tree_conditions_t cond;
    static gz_sign_round_t r;
    uint32_t tip = 0, good = 0, bad = 0;
    uint8_t me = 0;
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node_engine(1, 1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(2, 2, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(3, 3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    for (int n = 0; n <= 3; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 4, 4, 3000);
    CHECK(host_open(&t, 0) == 200);
    for (int n = 1; n <= 3; n++) CHECK(member_join(n, &t) == 200);
    w_run(4000, 100);
    CHECK(w_restart(1) == GZ_OK);
    w_run(2000, 100);
    slot_t *s = slot(1, &t);
    CHECK(s && N[1].n->sign_on && s->lobby.m.have_terms);
    if (!s || gz_tree_params(&s->lobby.m.terms, 3, &prm) != GZ_TREE_P_OK) { CHECK(0); w_free(3); return; }
    for (uint8_t j = 1; j <= 3; j++) if (!me || prm.depth[j - 1] > prm.depth[me - 1]) me = j;
    CHECK(prm.depth[me - 1] >= 1);
    memset(&r, 0, sizeof r);
    memcpy(r.def.outer_digest, t.scope, 32);
    r.def.n_participants = 4;
    r.me = me;
    r.def.end_height = 100000;
    memset(&cond, 0, sizeof cond);
    cond.exit = gz_exit_signet();
    cond.funding_deadline_blocks = 36;
    cond.end_window = 6;
    for (uint32_t x = 1; x < r.def.end_height; x++) {
        if (!gz_tree_may_ack(r.def.end_height, prm.depth[me - 1], x, &cond)) { bad = x; break; }
        good = x;
    }
    CHECK(good && bad == good + 1 && gz_tree_may_ack(r.def.end_height, 0, bad, &cond));
    N[1].n->tip = good;
    CHECK(gz_sg_may_ack(N[1].n, &r, &tip) == 1 && tip == good);
    N[1].n->tip = bad;
    CHECK(gz_sg_may_ack(N[1].n, &r, &tip) == 0);
    N[1].n->tip = 0;
    CHECK(gz_sg_may_ack(N[1].n, &r, &tip) == -1);
    r.def.outer_digest[0] ^= 1;                                     /* no lobby for it: no */
    N[1].n->tip = good;
    CHECK(gz_sg_may_ack(N[1].n, &r, &tip) == 0);
    no_errors(3);
    w_free(3);
}

/* RULE-NODE:ROUTE_HELD (H12, 2.4): a round message for a scope the signing engine still holds (a round
 * in a slot, or one kept compactly) goes to the engine, also where the lobby does not take it: no slot
 * for the scope (a lobby ended), or a member's slot that does not take rounds. One it does not hold is
 * dropped there. The engine's own memory is set by hand, then cleared. */
static void test_route_held(void)
{
    terms_t t;
    uint8_t other[32];
    gz_bytes_t none = {NULL, 0};
    lt_key_t hk;
    gz_link_t l;
    rt_t r;
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node_engine(1, 1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(2, 2, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(3, 3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    for (int n = 0; n <= 3; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 4, 4, 3000);
    CHECK(host_open(&t, 0) == 200);
    for (int n = 1; n <= 3; n++) CHECK(member_join(n, &t) == 200);
    w_run(4000, 100);
    gz_node_t *c = N[1].n;
    slot_t *s = slot(1, &t);
    CHECK(s && c->sign_on && c->sign);
    if (!s || !c->sign) { w_free(3); return; }
    whost(&hk);
    l = h_link(hk.pub, hk.pub);
    memset(other, 0x5c, 32);
    /* no slot for the scope */
    CHECK(gz_route_slot_by_scope(c, other) < 0);
    r = gz_route_message(c, -1, &l, GZ_MSG_KIND_ROUND_FIRST, other, none);
    CHECK(r.kind == RT_DROP && r.drop == DROP_NO_SLOT);
    c->sign->kept[0].used = 1;
    memcpy(c->sign->kept[0].scope, other, 32);
    r = gz_route_message(c, -1, &l, GZ_MSG_KIND_ROUND_FIRST, other, none);
    CHECK(r.kind == RT_SIGNING);
    memset(&c->sign->kept[0], 0, sizeof c->sign->kept[0]);
    c->sign->rounds[0].state = GZ_SIGN_ROUND_DEAD;
    memcpy(c->sign->rounds[0].def.outer_digest, other, 32);
    r = gz_route_message(c, -1, &l, GZ_MSG_KIND_ROUND_FIRST, other, none);
    CHECK(r.kind == RT_SIGNING);
    memset(&c->sign->rounds[0], 0, sizeof c->sign->rounds[0]);
    /* the member's slot, not taking rounds */
    int was = s->round_ok;
    s->round_ok = 0;
    r = gz_route_message(c, -1, &l, GZ_MSG_KIND_ROUND_FIRST, t.scope, none);
    CHECK(r.kind == RT_DROP && r.drop == DROP_NO_SLOT);
    c->sign->kept[0].used = 1;
    memcpy(c->sign->kept[0].scope, t.scope, 32);
    r = gz_route_message(c, -1, &l, GZ_MSG_KIND_ROUND_FIRST, t.scope, none);
    CHECK(r.kind == RT_SIGNING);
    memset(&c->sign->kept[0], 0, sizeof c->sign->kept[0]);
    s->round_ok = was;
    no_errors(3);
    w_free(3);
}

/* Slice 1 blocker C1 (local-api.md, leave: too_late): once a partial signature of the member's has left,
 * the person's leave is refused while that round is not resolved, so that the lobby, and with it the
 * round's ack, is not given up; the slot stays open. The signing engine's memory is set by hand: a round
 * of the lobby with partial signatures out, in each unresolved state; then an exposure whose round left
 * memory unresolved (its lobby is not known: refused for every lobby, fail closed). With none of these
 * the leave goes through. */
static void test_leave_partials_out(void)
{
    terms_t t;
    static const uint8_t held[] = {GZ_SIGN_ROUND_ACTIVE, GZ_SIGN_ROUND_UNFINISHED, GZ_SIGN_ROUND_COMPLETE};
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node_engine(1, 1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(2, 2, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(3, 3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    for (int n = 0; n <= 3; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 4, 4, 3000);
    CHECK(host_open(&t, 0) == 200);
    for (int n = 1; n <= 3; n++) CHECK(member_join(n, &t) == 200);
    w_run(4000, 100);
    gz_node_t *c = N[1].n;
    slot_t *s = slot(1, &t);
    CHECK(s && c->sign_on && c->sign);
    if (!s || !c->sign) { w_free(3); return; }
    gz_sign_round_t *r = &c->sign->rounds[GZ_SIGN_MAX_ROUNDS - 1];
    CHECK(r->state == GZ_SIGN_ROUND_FREE);
    for (size_t k = 0; k < sizeof held; k++) {
        size_t mark = N[1].n_log;
        memset(r, 0, sizeof *r);
        r->state = held[k];
        r->ever_partial = 1;
        r->id[0] = 0xc1;
        memcpy(r->def.outer_digest, t.scope, 32);
        CHECK(scope_cmd(1, GZ_CMD_LOBBY_LEAVE, &t, 0) == 409 && said(1, mark, "too_late"));
        CHECK(slot(1, &t) == s && !s->lobby.m.ended && !s->lobby.m.left);
    }
    memset(r, 0, sizeof *r);
    /* An unready is not gated (review B of PR 81, B-4): with a round of the lobby out, it is not too_late. */
    {
        size_t mark = N[1].n_log;
        memset(r, 0, sizeof *r);
        r->state = GZ_SIGN_ROUND_ACTIVE; r->ever_partial = 1; r->id[0] = 0xc1;
        memcpy(r->def.outer_digest, t.scope, 32);
        (void)scope_cmd(1, GZ_CMD_LOBBY_UNREADY, &t, 0);
        CHECK(said(1, mark, "too_late") == 0);
        memset(r, 0, sizeof *r);
    }
    uint8_t other[32];
    memset(other, 0x6b, 32);
    size_t n0 = c->sign->n_exposures;
    CHECK(n0 + 1 < GZ_SIGN_MAX_EXPOSURES);
    if (n0 + 1 < GZ_SIGN_MAX_EXPOSURES) {
        gz_sign_exposed_t *x = &c->sign->exposed[n0], *y = &c->sign->exposed[n0 + 1];
        size_t mark = N[1].n_log;
        memset(&c->sign->exposures[n0], 0, 2 * sizeof c->sign->exposures[n0]);
        memset(x, 0, 2 * sizeof *x);
        /* an exposure whose round left memory, Unfinished, its lobby not known: refused with its own reason */
        x->round_id[0] = 0xc2;
        x->state = GZ_SIGN_ROUND_UNFINISHED;
        c->sign->n_exposures = n0 + 1;
        CHECK(scope_cmd(1, GZ_CMD_LOBBY_LEAVE, &t, 0) == 409 && said(1, mark, "too_late_unknown_round"));
        CHECK(slot(1, &t) == s && !s->lobby.m.ended);
        /* the same round of this lobby (its exposure saved the scope, now from NOW on the keep clock) */
        mark = N[1].n_log;
        x->has_scope = 1;
        memcpy(x->scope, t.scope, 32);
        x->since_ms = NOW;
        CHECK(scope_cmd(1, GZ_CMD_LOBBY_LEAVE, &t, 0) == 409 && said(1, mark, "too_late") && !said(1, mark, "unknown"));
        /* another lobby's round, left memory Complete, refuses nothing here */
        y->round_id[0] = 0xc4;
        y->state = GZ_SIGN_ROUND_COMPLETE;
        y->has_scope = 1;
        memcpy(y->scope, other, 32);
        c->sign->n_exposures = n0 + 2;
        /* the unfinished deadline: a tick before it, the leave still refused; a tick past it, Abandoned */
        gz_action_list_t l;
        gz_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_TIMER_FIRED;
        ev.u.timer.timer_id = 0x5347u;                                 /* the engine's tick */
        N[1].clock = NOW + 60000;
        gz_action_list_init(&l, N[1].slots, GZ_NODE_LIST_ACTIONS, N[1].bytes, GZ_NODE_LIST_BYTES);
        CHECK(gz_sign_handle(c->sign, &ev, &l) == GZ_OK && x->state == GZ_SIGN_ROUND_UNFINISHED);
        mark = N[1].n_log;
        CHECK(scope_cmd(1, GZ_CMD_LOBBY_LEAVE, &t, 0) == 409 && said(1, mark, "too_late"));
        NOW += SG_UNFINISHED_MS + 60000;
        N[1].clock = NOW;
        gz_action_list_init(&l, N[1].slots, GZ_NODE_LIST_ACTIONS, N[1].bytes, GZ_NODE_LIST_BYTES);
        CHECK(gz_sign_handle(c->sign, &ev, &l) == GZ_OK && x->state == GZ_SIGN_ROUND_ABANDONED);
        /* cleared: the leave goes through, with another lobby's round still out */
        CHECK(scope_cmd(1, GZ_CMD_LOBBY_LEAVE, &t, 0) == 200);
        w_run(1000, 100);
        CHECK(slot(1, &t) == NULL || s->lobby.m.left);
        memset(x, 0, 2 * sizeof *x);
        c->sign->n_exposures = n0;
    }
    no_errors(3);
    w_free(3);
}

/* Review B of PR 81, B-1: a host that takes the member's ack and never funds does not keep the lobby for good.
 * The member's round is Complete (acked at tip 1000); the tips reach the member's signing engine, and once a tip
 * is past the ack tip plus C11's funding deadline (B-6: past, not at) the round is Abandoned and the leave goes
 * through. */
static void test_leave_after_funding_deadline(void)
{
    terms_t t;
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node_engine(1, 1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(2, 2, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(3, 3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    for (int n = 0; n <= 3; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 4, 4, 3000);
    CHECK(host_open(&t, 0) == 200);
    for (int n = 1; n <= 3; n++) CHECK(member_join(n, &t) == 200);
    w_run(4000, 100);
    gz_node_t *c = N[1].n;
    slot_t *s = slot(1, &t);
    CHECK(s && c->sign_on && c->sign && c->sign->cfg.funding_deadline_blocks > 0);
    if (!s || !c->sign) { w_free(3); return; }
    uint32_t dl = c->sign->cfg.funding_deadline_blocks;
    gz_sign_round_t *r = &c->sign->rounds[GZ_SIGN_MAX_ROUNDS - 1];
    memset(r, 0, sizeof *r);
    r->state = GZ_SIGN_ROUND_COMPLETE;
    r->ever_partial = 1;
    r->ack_tip = 1000;
    r->id[0] = 0xc5;
    memcpy(r->def.outer_digest, t.scope, 32);
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_CHAIN;
    ev.u.chain.kind = GZ_CHAIN_NEW_TIP;
    ev.u.chain.height = 1000 + dl - 1;
    CHECK(w_event(1, &ev) == GZ_OK);
    size_t mark = N[1].n_log;
    CHECK(r->state == GZ_SIGN_ROUND_COMPLETE && scope_cmd(1, GZ_CMD_LOBBY_LEAVE, &t, 0) == 409 && said(1, mark, "too_late"));
    ev.u.chain.height = 1000 + dl;                                  /* at the deadline: not yet (C11: past it) */
    CHECK(w_event(1, &ev) == GZ_OK);
    mark = N[1].n_log;
    CHECK(r->state == GZ_SIGN_ROUND_COMPLETE && scope_cmd(1, GZ_CMD_LOBBY_LEAVE, &t, 0) == 409 && said(1, mark, "too_late"));
    ev.u.chain.height = 1000 + dl + 1;
    CHECK(w_event(1, &ev) == GZ_OK);
    CHECK(r->state == GZ_SIGN_ROUND_ABANDONED);
    CHECK(scope_cmd(1, GZ_CMD_LOBBY_LEAVE, &t, 0) == 200);
    w_run(1000, 100);
    CHECK(slot(1, &t) == NULL || s->lobby.m.left);
    memset(r, 0, sizeof *r);
    no_errors(3);
    w_free(3);
}


/* The index ceiling at allocation (review of PR 87, L1): a slot never takes a
 * key index the next start would refuse as damage. Allocation gives
 * highest_index + 1, so it must stop once highest_index reaches
 * GZ_LS_KEY_INDEX_MAX: at 0xfffffff0 the next index would be 0xfffffff1.
 * Both open paths, the host's and the member's; one below, the last index
 * is still given and loads again after a restart. */
static void test_index_ceiling(void)
{
    terms_t t[4];
    w_world(1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    for (int i = 0; i < 4; i++) make_terms(&t[i], 3, 3, 1900 + (uint32_t)i);
    size_t hb = N[0].n_batches, mb = N[1].n_batches;
    N[0].n->np.highest_index = GZ_LS_KEY_INDEX_MAX;
    CHECK(host_open(&t[0], 0) == 503 && slot(0, &t[0]) == NULL && N[0].n_batches == hb);
    N[1].n->np.highest_index = GZ_LS_KEY_INDEX_MAX;
    CHECK(member_join(1, &t[1]) == 503 && slot(1, &t[1]) == NULL && N[1].n_batches == mb);
    N[0].n->np.highest_index = GZ_LS_KEY_INDEX_MAX - 1;
    CHECK(host_open(&t[2], 0) == 200 && slot(0, &t[2]) && slot(0, &t[2])->key_index == GZ_LS_KEY_INDEX_MAX);
    N[1].n->np.highest_index = GZ_LS_KEY_INDEX_MAX - 1;
    CHECK(member_join(1, &t[3]) == 200 && slot(1, &t[3]) && slot(1, &t[3])->key_index == GZ_LS_KEY_INDEX_MAX);
    /* what was given loads again */
    CHECK(w_restart(0) == GZ_OK && slot(0, &t[2]) && slot(0, &t[2])->key_index == GZ_LS_KEY_INDEX_MAX);
    CHECK(w_restart(1) == GZ_OK && slot(1, &t[3]) && slot(1, &t[3])->key_index == GZ_LS_KEY_INDEX_MAX);
    w_free(1);
}
/* Local-api.md 15.2's funds check (#80) at LOBBY_OPEN and the early start: the wallet's dry
 * run is asked; short gives funds_short (with need and have), a port that cannot tell
 * coins_unknown, no port no_wallet; nothing is opened or started on a refusal. The interim
 * rule for several lobbies: one dry run over this lobby's set-aside and the others'
 * (unfunded) set-asides, each other with a fee bound and a change's dust. */
static void test_funds_check(void)
{
    terms_t t, u;
    char e[64], q[200];
    uint64_t one;
    gz_fund_config_t fc;
    w_world(3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    make_terms(&t, 4, 3, 3800);
    make_terms(&u, 4, 3, 3801);
    FUNDS[0] = 1;
    CHECK(host_open(&t, 0) == 409 && slot(0, &t) == NULL);
    CHECK(res_text(0, GZ_RESULT_REC_ERROR, e, sizeof e) && !strcmp(e, "funds_short"));
    CHECK(res_text(0, GZ_RESULT_REC_PARAMS, q, sizeof q) && strstr(q, "\"need_sat\":") && strstr(q, "\"have_sat\":"));
    FUNDS[0] = 2;
    CHECK(host_open(&t, 0) == 409 && slot(0, &t) == NULL);
    CHECK(res_text(0, GZ_RESULT_REC_ERROR, e, sizeof e) && !strcmp(e, "coins_unknown"));
    FUNDS[0] = 0;
    CHECK(host_open(&t, 0) == 200 && slot(0, &t) != NULL);
    one = FUNDS_ASKED[0];
    CHECK(one == gz_fund_set_aside_sat(&slot(0, &t)->lobby.h.terms));      /* one lobby: its own set-aside */
    /* a second lobby: one dry run over both, the first with a fee bound and dust on top */
    CHECK(host_open(&u, 0) == 200 && slot(0, &u) != NULL);
    memset(&fc, 0, sizeof fc);
    fc.feerate = 100;
    CHECK(FUNDS_ASKED[0] == gz_fund_set_aside_sat(&slot(0, &u)->lobby.h.terms) + one +
                            gz_fund_funding_fee_bound(&fc, GZ_FUND_MAX_INPUTS) + GZ_FUND_CHANGE_DUST);
    /* the early start asks again */
    for (int n = 1; n <= 3; n++) CHECK(member_join(n, &t) == 200);
    w_run(3000, 100);
    {
        uint8_t ech[8];
        gz_put_u64(ech, gz_ls_set_aside(slot(0, &t)));
        h_arg_t a[2] = {{12, t.scope, 32}, {14, ech, 8}};
        FUNDS[0] = 1;
        CHECK(w_req(0, GZ_CMD_LOBBY_START, "StartFundsShort001", "/api/v1/host/lobbies/x/start", 1, a, 2) == 409);
        CHECK(res_text(0, GZ_RESULT_REC_ERROR, e, sizeof e) && !strcmp(e, "funds_short"));
        FUNDS[0] = 2;
        CHECK(w_req(0, GZ_CMD_LOBBY_START, "StartFundsUnknown1", "/api/v1/host/lobbies/x/start", 1, a, 2) == 409);
        CHECK(res_text(0, GZ_RESULT_REC_ERROR, e, sizeof e) && !strcmp(e, "coins_unknown"));
        CHECK(host_state(&t) == GZ_LOBBY_OPEN);                            /* nothing started */
    }
    no_errors(3);
    w_free(3);
    /* no wallet port at all: open refused, no_wallet (fail closed; a release build until integration) */
    w_reset();
    W_NO_WALLET = 1;
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    W_NO_WALLET = 0;
    CHECK(w_start(0) == GZ_OK);
    CHECK(host_open(&t, 0) == 409 && slot(0, &t) == NULL);
    CHECK(res_text(0, GZ_RESULT_REC_ERROR, e, sizeof e) && !strcmp(e, "no_wallet"));
    no_errors(0);
    w_free(0);
}

/* The early start with no wallet port: no_wallet, nothing started. */
static void test_funds_no_wallet_start(void)
{
    terms_t t;
    char e[64];
    w_reset();
    for (int n = 0; n <= 3; n++) {
        w_node(n, n, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
        CHECK(w_start(n) == GZ_OK);
    }
    make_terms(&t, 4, 3, 3802);
    CHECK(host_open(&t, 0) == 200);
    for (int n = 1; n <= 3; n++) CHECK(member_join(n, &t) == 200);
    w_run(3000, 100);
    /* the host restarts without a port (the wallet went away): its start is refused */
    N[0].cfg.wallet = NULL;
    CHECK(w_restart(0) == GZ_OK);
    w_run(3000, 100);
    {
        uint8_t ech[8];
        gz_put_u64(ech, gz_ls_set_aside(slot(0, &t)));
        h_arg_t a[2] = {{12, t.scope, 32}, {14, ech, 8}};
        CHECK(w_req(0, GZ_CMD_LOBBY_START, "StartNoWallet00001", "/api/v1/host/lobbies/x/start", 1, a, 2) == 409);
        CHECK(res_text(0, GZ_RESULT_REC_ERROR, e, sizeof e) && !strcmp(e, "no_wallet"));
        CHECK(host_state(&t) == GZ_LOBBY_OPEN);
    }
    no_errors(3);
    w_free(3);
}

/* K1: a ready too large for its buffer is a bug, and the node error that stops the run is its outcome (a
 * restart recovers from the journal): with the test hook shrinking member 1's ready buffer, its first ready
 * fails with the lobby's area, and nothing of that ready was saved or sent. */
static void test_ready_over_limit(void)
{
    terms_t t;
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    w_node(1, 1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    N[1].cfg.test_ready_cap = 200;                              /* the largest K1 ready is 317 */
    h_new_node(&N[1]);
    for (int n = 0; n <= 1; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 4, 3, 3000);
    CHECK(host_open(&t, 0) == 200);
    int before = ERRORS;
    size_t sent = NSENT;
    (void)member_join(1, &t);
    w_run(2000, 100);
    CHECK(ERRORS > before && gz_node_error_area(N[1].n) == GZ_AREA_LOBBY);
    CHECK(h_records_of(&N[1], GZ_REC_READY_SENT) == 0 && h_records_of(&N[1], GZ_REC_SEAT_KEY) == 0);
    int readies = 0;
    for (size_t k = sent; k < NSENT; k++) readies += SENT[k].node == 1 && SENT[k].kind == GZ_KIND_READY;
    CHECK(readies == 0);
    ERRORS = before;                                            /* this one was the test's */
    w_free(1);
}

/* The signing engine runs only with a secp256k1 context (node.h): a node
 * given the engine's memory but no context starts without it, and never
 * reaches the engine with a NULL context (mutant sg-init-without-secp). */
static void test_sign_needs_secp(void)
{
    h_t *x = &N[SCRATCH];
    w_reset();
    w_node_engine(SCRATCH, 5, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    CHECK(w_start(SCRATCH) == GZ_OK && x->n->sign_on && x->n->sign != NULL);   /* the control: with a context */
    x->cfg.secp = NULL;
    h_new_node(x);
    CHECK(w_start(SCRATCH) == GZ_OK && !x->n->sign_on && x->n->sign == NULL);
    ALIVE[SCRATCH] = 0;
    NT[SCRATCH] = 0;
    for (int i = 0; i < 64; i++)
        if (C[i].used && C[i].node == SCRATCH) C[i].used = 0;
    h_free(x);
    memset(x, 0, sizeof *x);
}
/* Review B of #55, M-1: the automatic start (the target reached) asks the host's funds as
 * the early start does. Coins drop after the open: the target is reached, no ready check
 * is sent, the lobby stays Open and host_funds_short is up (11.4, with need and have);
 * the coins come back and the next tip starts it, the item gone. */
static void test_funds_auto_start(void)
{
    terms_t t;
    char aid[GZ_LOCAL_ID_MAX + 8];
    wview_t *w;
    gz_bytes_t v;
    w_world(3, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_UNFINISHED);
    make_terms(&t, 3, 3, 3803);
    CHECK(host_open(&t, 0) == 200 && slot(0, &t));
    if (!slot(0, &t)) { w_free(3); return; }
    snprintf(aid, sizeof aid, "att_%s", lid(0, &t) + 4);
    FUNDS[0] = 1;                                                  /* the coins dropped since the open */
    for (int n = 1; n <= 3; n++) CHECK(member_join(n, &t) == 200);
    w_run(4000, 100);
    CHECK(host_ready(&t) == 3);                                    /* the target is reached */
    CHECK(host_state(&t) == GZ_LOBBY_OPEN && h_records_of(&N[0], GZ_REC_FREEZE) == 0 && slot(0, &t)->funds_blocked);
    w = view_of(0, GZ_VIEW_ATTENTION, aid);
    CHECK(w && !w->gone && vf8(w, GZ_VAT_CODE) == GZ_ATT_HOST_FUNDS_SHORT && vf(w, GZ_VAT_NEED, &v) && v.len == 8 &&
          vf(w, GZ_VAT_HAVE, &v) && v.len == 8);
    FUNDS[0] = 2;                                                  /* nor when the wallet cannot tell */
    {
        gz_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_CHAIN;
        ev.u.chain.kind = GZ_CHAIN_NEW_TIP;
        ev.u.chain.height = 1001;
        CHECK(w_event(0, &ev) == GZ_OK);
        w_run(500, 100);
        CHECK(host_state(&t) == GZ_LOBBY_OPEN && slot(0, &t)->funds_blocked);
        FUNDS[0] = 0;                                              /* the coins are back: the next tip starts it */
        ev.u.chain.height = 1002;
        CHECK(w_event(0, &ev) == GZ_OK);
    }
    w_run(1000, 100);
    CHECK(host_state(&t) == GZ_LOBBY_READY_CHECK && !slot(0, &t)->funds_blocked);
    w = view_of(0, GZ_VIEW_ATTENTION, aid);
    CHECK(w && w->gone);
    no_errors(3);
    w_free(3);
}

/* Review B of PR 95, L-4: the lobby's signing hook cannot sign with the factory key at all, on the
 * member's slot or the host's: the call is refused and the key port is never asked. */
static void test_k1_ls_sign_no_factory(void)
{
    terms_t t;
    uint8_t msg[32], sig[64];
    w_reset();
    w_node(0, 0, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    w_node(1, 1, GZ_MEMBER_SIGNING_AUTO, GZ_TEST_SIGN_FUNDING);
    for (int n = 0; n <= 1; n++) CHECK(w_start(n) == GZ_OK);
    make_terms(&t, 4, 3, 3110);
    CHECK(host_open(&t, 0) == 200 && member_join(1, &t) == 200);
    w_run(3000, 100);
    slot_t *m = slot(1, &t), *h = slot(0, &t);
    CHECK(m && h);
    if (!m || !h) { w_free(1); return; }
    memset(msg, 0x42, sizeof msg);
    int before = SIGNS[1];
    CHECK(m->lobby.m.crypto.sign(m->lobby.m.crypto.ctx, GZ_LOBBY_KEY_FACTORY, msg, sig) == 0 && SIGNS[1] == before);
    CHECK(h->lobby.h.crypto.sign(h->lobby.h.crypto.ctx, GZ_LOBBY_KEY_FACTORY, msg, sig) == 0);
    /* the contribution key still signs (the ready) */
    CHECK(m->lobby.m.crypto.sign(m->lobby.m.crypto.ctx, GZ_LOBBY_KEY_CONTRIBUTION, msg, sig) == 1 && SIGNS[1] == before + 1);
    no_errors(1);
    w_free(1);
}


int main(int argc, char **argv)
{
    unsigned long events = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000;
    uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 10) : 1;
    setvbuf(stdout, NULL, _IONBF, 0);
    test_discovery();
    test_refusal_until_next_attempt();
    test_join_unlocked();
    test_gate_bound_to_seen();
    test_ready_replay_without_passphrase();
    test_discovery_repeat();
    test_index_unique();
    test_gate_closes_with_seat();
    test_funds_check();
    test_funds_no_wallet_start();
    test_funds_auto_start();
    test_two_lobbies();
    test_cancel_and_tombstone();
    test_refusals();
    test_gates();
    test_signing_set();
    test_at_join_key_hook();
    test_join_ready_key_hook();
    test_tree_cap();
    test_may_ack_depth();
    test_route_held();
    test_leave_partials_out();
    test_leave_after_funding_deadline();
    test_index();
    test_key_skip();
    test_epoch_ok();
    test_api_unknown_record();
    test_views();
    test_view_refusal();
    test_view_seats();
    test_api_requests();
    test_api_pause_and_signing();
    test_pause_rows();
    test_api_request_keep();
    test_api_request_keep_more();
    test_attention_long_ids();
    test_api_replay_detail();
    test_api_signing_authority();
    test_api_conditions();
    test_api_start();
    test_api_start_guard();
    test_api_join_looser();
    test_harness_flush();
    test_cond_seen_load();
    test_api_records();
    test_api_ids_kept();
    test_seat_capacity();
    test_left_out();
    test_node_record_fields();
    test_index_ceiling();
    test_sign_needs_secp();
    test_timer_of_ended_lobby();
    test_gate_refused_ready();
    test_hostile(events, seed);
    test_ready_over_limit();
    test_k1_ls_sign_no_factory();
    return check_done();
}
