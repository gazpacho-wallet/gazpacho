/* A slot's lobby (composite-node.md sections 2.4, 2.5, 7.3, 9 and 12): the
 * lobby engine of core/lobby behind the composite's engine interface, its
 * keys and its signing gate, the Node records slot_opened and slot_closed,
 * the index of ended lobbies, the lobby and gate commands, and, in test
 * builds, the stand-in for the signing engine that P4.3 brings.
 *
 * THE BATCHES (7.4). A slot opens in one batch: key_epoch (the first time),
 * key_index, guard, slot_opened, and on the host lobby_opened; a member's
 * CONNECT follows it, so the handshake never shows a key whose index is not
 * saved. A slot closes in the batch that ends its lobby: slot_closed is put
 * into the SAVE that holds lobby_ended (moving a save earlier is always
 * safe, handoff.c).
 *
 * THE ENGINE RULE. Nothing here returns an error for what a person, a peer
 * or the key port can cause: a bad address or host key, bad terms, a ninth
 * lobby, a key the port does not have are refused commands; a slot whose
 * keys the port cannot give at a start is left out, counted, and the start
 * goes on. */
#include "internal.h"
#include <string.h>

/* ---- small text ---------------------------------------------------------- */

static void put_s(char *p, size_t cap, size_t *at, const char *s)
{
    while (*s && *at + 1 < cap) p[(*at)++] = *s++;
    p[*at] = 0;
}

static void put_u(char *p, size_t cap, size_t *at, uint64_t v)
{
    char d[24];
    int n = 0;
    do {
        d[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n > 0 && *at + 1 < cap) p[(*at)++] = d[--n];
    p[*at] = 0;
}

/* The first four bytes, as eight hex digits: enough to tell lobbies apart in
 * a log line, and no more of an identifier than that. */
static void put_h(char *p, size_t cap, size_t *at, const uint8_t *b)
{
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 4 && *at + 2 < cap; i++) {
        p[(*at)++] = H[b[i] >> 4];
        p[(*at)++] = H[b[i] & 15];
    }
    p[*at] = 0;
}

static int arg(gz_bytes_t cmd, uint64_t type, size_t len, gz_bytes_t *v)
{
    return gz_rec_find(cmd, type, v) == 1 && (len == 0 || v->len == len);
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* ---- the lobby's ports ---------------------------------------------------- */

static int ls_verify(void *ctx, const uint8_t pub[33], const uint8_t msg[32], const uint8_t sig[64])
{
    const slot_t *s = ctx;
    const gz_node_crypto_t *k = &s->node->cfg.crypto;
    return k->verify ? k->verify(k->ctx, pub, msg, sig) : 0;
}

static int ls_point_ok(void *ctx, const uint8_t pub[33])
{
    const slot_t *s = ctx;
    const gz_node_crypto_t *k = &s->node->cfg.crypto;
    return k->point_ok ? k->point_ok(k->ctx, pub) : 0;
}

/* The slot's pair: the contribution key at key_index, the factory key at
 * key_index + 1; the host signs with its long-term key and has no
 * contribution key. A key the port will not sign with is 0: the lobby
 * gives a notice and does nothing (lobby.h, ERRORS). */
static int ls_sign(void *ctx, uint32_t which, const uint8_t msg[32], uint8_t sig[64])
{
    const slot_t *s = ctx;
    const gz_node_crypto_t *k = &s->node->cfg.crypto;
    if (!k->sign) return 0;
    if (which == GZ_LOBBY_KEY_HOST) return s->host ? k->sign(k->ctx, 1, 0, 0, msg, sig) : 0;
    if (which == GZ_LOBBY_KEY_CONTRIBUTION) return s->host ? 0 : k->sign(k->ctx, 0, s->key_epoch, s->key_index, msg, sig);
    if (which == GZ_LOBBY_KEY_FACTORY) return k->sign(k->ctx, 0, s->key_epoch, s->key_index + 1, msg, sig);
    return 0;
}

/* The signing gate (12.2): none with AUTO, the node-wide gate with
 * WHEN_UNLOCKED, the slot's own with AT_JOIN. Memory only; closed at a start. */
static int ls_may_answer(void *ctx, const uint8_t scope[32])
{
    const slot_t *s = ctx;
    (void)scope;
    switch (s->node->cfg.member_signing) {
    case GZ_MEMBER_SIGNING_AUTO: return 1;
    case GZ_MEMBER_SIGNING_WHEN_UNLOCKED: return s->node->unlocked;
    default:
        /* AT_JOIN: the gate is open for the values the person readied for. Values that have changed
         * since (before the freeze) are not what the person agreed to: the gate does not answer for
         * them, and the person readies again. Without the signing engine (a test build's stand-in)
         * the gate alone. */
        if (!s->gate_open) return 0;
        if (!s->gate_have) return !s->node->sign_on;
        {
            const gz_lobby_member_t *m = &s->lobby.m;
            const uint8_t *now = m->frozen ? m->frozen_digest : m->current_digest;
            return m->have_terms && memcmp(now, s->gate_digest, 32) == 0;   /* RULE-NODE:GATE_DIGEST */
        }
    }
}

#ifdef GZ_TEST_KINDS
static gz_status_t ss_begin(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out);
static gz_status_t ss_cancel(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out);
static gz_status_t ss_left(void *ctx, const uint8_t scope[32], const uint8_t ckey[33], gz_action_list_t *out);
#endif

/* A member's conditions as a command and slot_opened carry them: current_only
 * (u8), the min_members hint (u16), then the limits: min_channel_sat (u64),
 * max_tree_feerate (u32), min_lifetime (u32), max_lifetime (u32), min_members
 * (u16), profiles (u8), n (u8), n x (type u8, max u64). Empty: no limits. */
#define COND_HEAD 27u
#define COND_MAX (COND_HEAD + 9u * GZ_TERMS_MAX_ADJ)

static int cond_decode(const uint8_t *p, size_t n, gz_lobby_conditions_t *c)
{
    memset(c, 0, sizeof *c);
    if (n == 0) return 1;
    if (n < COND_HEAD || p[0] > 1 || p[26] > GZ_TERMS_MAX_ADJ || n != COND_HEAD + 9u * p[26]) return 0;
    c->current_only = p[0];
    c->min_members = gz_get_u16(p + 1);
    c->limits.min_channel_sat = gz_get_u64(p + 3);
    c->limits.max_tree_feerate = gz_get_u32(p + 11);
    c->limits.min_lifetime = gz_get_u32(p + 15);
    c->limits.max_lifetime = gz_get_u32(p + 19);
    c->limits.min_members = gz_get_u16(p + 23);
    c->limits.profiles = p[25];
    c->limits.n_max = p[26];
    for (uint8_t i = 0; i < c->limits.n_max; i++) {
        c->limits.max[i].type = p[COND_HEAD + 9u * i];
        c->limits.max[i].max = gz_get_u64(p + COND_HEAD + 9u * i + 1);
    }
    return 1;
}

/* The pause holds a host's start rule (local-api.md 11.3; api.c). */
static int ls_paused(void *ctx)
{
    const slot_t *s = ctx;
    return gz_api_paused(s->node);
}

/* The node's connection table holds every seat of its lobbies (review A of
 * PR 44, M1): a key that holds no seat yet takes one only while fewer than
 * NP_MAX_SEATED keys hold seats, Open and Closing together. */
static int ls_seat_room(void *ctx, const uint8_t key[33])
{
    const slot_t *s = ctx;
    gz_node_id_t id;
    memcpy(id.key, key, 33);
    return gz_route_key_seated(s->node, &id) || gz_route_seats_held(s->node) < NP_MAX_SEATED;
}

/* Make the slot's lobby engine from the slot's fields. 0 if the key port or
 * the crypto port cannot serve it: nothing a start may fail on. */
int gz_ls_init(gz_node_t *c, int i)
{
    slot_t *s = &c->slots[i];
    gz_lobby_crypto_t cr;
    gz_lobby_signing_t sg;
    uint8_t ck[33], fk[33];
    s->node = c;
    cr.verify = ls_verify;
    cr.point_ok = ls_point_ok;
    cr.sign = ls_sign;
    cr.ctx = s;
    memset(&sg, 0, sizeof sg);
    /* The signing engine behind the hand-off. In test builds, with a forced
     * outcome (--test-sign-outcome) or no engine, the stand-in instead: the
     * lobby's side of every hand-off with the outcome a test needs. */
    if (c->sign_on) gz_sg_signing(s, &sg);
#ifdef GZ_TEST_KINDS
    if (!c->sign_on || c->cfg.test_sign_outcome) {
        sg.begin = ss_begin;
        sg.cancel = ss_cancel;
        sg.member_left = ss_left;
        sg.ctx = s;
    }
#endif
    if (!c->cfg.keys.pub || !c->cfg.crypto.verify || !c->cfg.crypto.point_ok || !c->cfg.crypto.sign) return 0;
    if (c->cfg.keys.pub(c->cfg.keys.ctx, s->key_epoch, s->key_index, ck) != 1 ||
        c->cfg.keys.pub(c->cfg.keys.ctx, s->key_epoch, s->key_index + 1, fk) != 1)
        return 0;
    if (s->host) {
        gz_lobby_host_config_t hc;
        memset(&hc, 0, sizeof hc);
        memcpy(hc.factory_key, fk, 33);
        hc.standbys = s->standbys;
        hc.max_tree_nodes = c->sign_on ? GZ_SIGN_MAX_ITEMS : 0;   /* the engine signs at most so many (M2) */
        hc.listed = s->listed;
        hc.seat_room = ls_seat_room;
        hc.paused = ls_paused;
        hc.seat_ctx = s;
        return gz_lobby_host_init(&s->lobby.h, &c->ports, &cr, &sg, &hc) == GZ_OK;
    }
    gz_lobby_member_config_t mc;
    gz_lobby_gate_t gate;
    memset(&mc, 0, sizeof mc);
    memcpy(mc.scope, s->scope, 32);
    memcpy(mc.host_key, s->host_key.key, 33);
    memcpy(mc.ckey, ck, 33);
    memcpy(mc.factory_key, fk, 33);
    memcpy(mc.address, s->address, s->address_len);
    mc.address_len = s->address_len;
    mc.key_epoch = s->key_epoch;
    mc.key_index = s->key_index;
    mc.auto_join = s->auto_join;
    mc.max_tree_nodes = c->sign_on ? GZ_SIGN_MAX_ITEMS : 0;
    gate.may_answer = ls_may_answer;
    gate.ctx = s;
    memcpy(s->link.local.key, ck, 33);
    s->link.remote = s->host_key;
    return gz_lobby_member_init(&s->lobby.m, &c->ports, &cr, &sg, &gate, &s->cond, &mc) == GZ_OK;
}

/* ---- the engine interface -------------------------------------------------- */

static gz_status_t ls_load(void *e, const gz_record_t *rec, gz_batch_id_t at)
{
    (void)e;
    (void)rec;
    (void)at;
    return GZ_ERR_BUG; /* never called: the composite routes Lobby records by scope (gz_ls_load_record) */
}

static gz_status_t ls_resume(void *e, gz_action_list_t *out, int *more)
{
    slot_t *s = e;
    *more = 0;
    return s->host ? gz_lobby_host_resume(&s->lobby.h, out) : gz_lobby_member_resume(&s->lobby.m, out);
}

static gz_status_t ls_handle(void *e, const gz_event_t *ev, gz_action_list_t *out)
{
    slot_t *s = e;
    gz_lobby_input_t in;
    memset(&in, 0, sizeof in);
    switch (ev->kind) {
    case GZ_EVENT_MESSAGE_RECEIVED:
        /* The listing: a scope-zero hello, which the node part gives to each
         * listed slot in turn (section 3). */
        if (s->host && ev->u.message.kind == GZ_MSG_KIND_HELLO && all_zero(ev->u.message.scope, 32))
            return gz_lobby_host_listing(&s->lobby.h, &ev->u.message.link, out);
        in.kind = GZ_LIN_MESSAGE;
        in.link = ev->u.message.link;
        in.msg_kind = ev->u.message.kind;
        in.scope = ev->u.message.scope;
        in.records = ev->u.message.records.data;
        in.len = ev->u.message.records.len;
        break;
    case GZ_EVENT_PEER_CONNECTED:
    case GZ_EVENT_PEER_DISCONNECTED:
        in.kind = ev->kind == GZ_EVENT_PEER_CONNECTED ? GZ_LIN_CONNECTED : GZ_LIN_DISCONNECTED;
        in.link = ev->u.peer.link;
        break;
    case GZ_EVENT_TIMER_FIRED:
        in.kind = GZ_LIN_TIMER;
        in.timer_id = ev->u.timer.timer_id;
        break;
    default:
        return GZ_OK; /* lobbies take no chain reports and use no confirmations */
    }
    return s->host ? gz_lobby_host_handle(&s->lobby.h, &in, out) : gz_lobby_member_handle(&s->lobby.m, &in, out);
}

static const gz_engine_ops_t LS_OPS = {
    GZ_AREA_LOBBY, ls_load, ls_resume, ls_handle, LS_MAX_STEP_ACTIONS, LS_MAX_STEP_BYTES, LS_MAX_TIMERS,
};

const gz_engine_ops_t *gz_ls_ops(void)
{
    return &LS_OPS;
}

/* ---- the index of ended lobbies (2.4) --------------------------------------- */

static int ended_find(const gz_node_t *c, const uint8_t scope[32])
{
    for (int i = 0; i < NP_MAX_ENDED; i++)
        if (c->np.ended[i].used && memcmp(c->np.ended[i].scope, scope, 32) == 0) return i;
    return -1;
}

int gz_ls_ended_find(const gz_node_t *c, const uint8_t scope[32])
{
    return ended_find(c, scope);
}

/* An ended lobby's final state, its reason and its saved signed cancel. The
 * newest NP_MAX_ENDED are kept; past that the oldest is forgotten, and a
 * hello for it is answered as for an unknown lobby. */
static void ended_add(gz_node_t *c, const uint8_t scope[32], uint8_t state, uint16_t reason, const uint8_t *cancel,
                      size_t cancel_len)
{
    int i = ended_find(c, scope), oldest = 0;
    if (i < 0) {
        for (i = 0; i < NP_MAX_ENDED; i++) {
            if (!c->np.ended[i].used) break;
            if (c->np.ended[i].seq < c->np.ended[oldest].seq) oldest = i;
        }
        if (i == NP_MAX_ENDED) i = oldest;
    }
    np_ended_t *e = &c->np.ended[i];
    memset(e, 0, sizeof *e);
    e->used = 1;
    e->seq = ++c->np.ended_seq;
    memcpy(e->scope, scope, 32);
    e->state = state;
    e->reason = reason;
    if (cancel && cancel_len && cancel_len <= sizeof e->cancel) {
        memcpy(e->cancel, cancel, cancel_len);
        e->cancel_len = (uint16_t)cancel_len;
    }
}

/* The answer to a late hello for an ended lobby: its final state and reason,
 * then the saved cancel (sections 4 and 11.1). */
gz_status_t gz_ls_ended_answer(const gz_node_t *c, int idx, const gz_link_t *link, gz_action_list_t *out)
{
    const np_ended_t *e = &c->np.ended[idx];
    return gz_lobby_host_ended(link, e->scope, e->state, e->reason, e->cancel, e->cancel_len, out);
}

/* ---- Closing (2.4) ----------------------------------------------------------- */

/* A slot whose lobby is over while a round was handed over under it stays
 * Closing: a member keeps its CONNECT, a host keeps its members' seats, until
 * the end condition. In this step the end condition is the lobby's signing
 * budget on the monotonic clock, or the end of this run (the chain-based
 * conditions, Live, Dead and the deadlines plus the grace, come with the
 * funding engine, P4.5). At the cap the oldest ends early; nothing is refused. */
static gz_status_t closing_end(gz_node_t *c, int k, gz_action_list_t *out)
{
    np_closing_t *e = &c->np.closing[k];
    gz_status_t st = GZ_OK;
    if (e->host) {
        for (size_t j = 0; j < e->n_seated && st == GZ_OK; j++) {
            gz_action_t a = {.kind = GZ_ACTION_SET_SEATED};
            a.u.set_seated.member = e->seated[j];
            a.u.set_seated.seated = 0;
            st = gz_action_list_add(out, &a);
        }
    } else {
        st = np_disconnect(out, &e->link, GZ_DISCONNECT_DONE);
    }
    /* The host's compact rounds of the scope are answered no longer (H12: while a member can need them). */
    if (e->host && c->sign_on) gz_sign_forget_scope(c->sign, e->scope);
    e->used = 0;
    /* The node part's own table: a key no Open lobby holds is unseated from
     * now, and the cap and the idle rule apply to it (M2). */
    if (e->host && st == GZ_OK) {
        for (size_t j = 0; j < e->n_seated; j++) np_seat_changed(c, -1, &e->seated[j], 0);
        st = np_idle_check(c, out);
    }
    return st;
}

static gz_status_t closing_arm(gz_node_t *c, gz_action_list_t *out)
{
    uint64_t due = 0, now = np_mono(c);
    for (int k = 0; k < GZ_NODE_MAX_TOMBSTONES; k++)
        if (c->np.closing[k].used && (!due || c->np.closing[k].until_ms < due)) due = c->np.closing[k].until_ms;
    if (!due || due == c->np.closing_due_ms) return GZ_OK;
    c->np.closing_due_ms = due;
    return np_set_timer(out, NP_TIMER_CONTINUE, due > now ? due - now : 0);
}

/* The closing timer: every Closing slot past its time is Free. */
gz_status_t gz_ls_closing_timer(gz_node_t *c, gz_action_list_t *out)
{
    uint64_t now = np_mono(c);
    gz_status_t st = GZ_OK;
    int done = 0;
    c->np.closing_due_ms = 0;
    for (int k = 0; k < GZ_NODE_MAX_TOMBSTONES && st == GZ_OK && done < 2; k++)
        if (c->np.closing[k].used && c->np.closing[k].until_ms <= now) {
            st = closing_end(c, k, out); /* at most two a step (8.3); the rest at the next turn */
            done++;
        }
    return st == GZ_OK ? closing_arm(c, out) : st;
}

int gz_ls_closing_count(const gz_node_t *c)
{
    int n = 0;
    for (int k = 0; k < GZ_NODE_MAX_TOMBSTONES; k++) n += c->np.closing[k].used;
    return n;
}

static gz_status_t closing_add(gz_node_t *c, const slot_t *s, uint64_t budget_ms, gz_action_list_t *out)
{
    int k, oldest = 0;
    gz_status_t st = GZ_OK;
    for (k = 0; k < GZ_NODE_MAX_TOMBSTONES; k++) {
        if (!c->np.closing[k].used) break;
        if (c->np.closing[k].seq < c->np.closing[oldest].seq) oldest = k;
    }
    if (k == GZ_NODE_MAX_TOMBSTONES) {
        if ((st = closing_end(c, oldest, out)) != GZ_OK) return st;
        k = oldest;
    }
    np_closing_t *e = &c->np.closing[k];
    memset(e, 0, sizeof *e);
    e->used = 1;
    e->seq = ++c->np.ended_seq;
    e->host = s->host;
    memcpy(e->scope, s->scope, 32);
    e->link = s->link;
    e->until_ms = np_mono(c) + (budget_ms ? budget_ms : 1);
    for (size_t j = 0; j < s->n_seated; j++) e->seated[e->n_seated++] = s->seated[j];
    return closing_arm(c, out);
}

/* ---- records ------------------------------------------------------------------ */

#define OPENED_MAX (200u + GZ_LOBBY_MAX_ADDRESS + COND_MAX)

/* slot_opened: 2 serial (u32), 4 scope (32), 6 role (u8: 1 host, 0 member),
 * 8 host key (33) and 10 host address (member), 12 key epoch (u32), 14 key
 * index (u32, the pair's first), 16 listed (u8) and 18 standbys (u16) (host),
 * 20 conditions and 22 auto-join (u8) (member). */
static size_t opened_record(const slot_t *s, const uint8_t *cond, size_t cond_len, uint8_t *buf, size_t cap)
{
    uint8_t v[4];
    size_t at = 0;
    gz_status_t st;
    gz_put_u32(v, s->serial);
    st = gz_rec_put(buf, cap, &at, 2, v, 4);
    if (st == GZ_OK) st = gz_rec_put(buf, cap, &at, 4, s->scope, 32);
    v[0] = s->host ? 1 : 0;
    if (st == GZ_OK) st = gz_rec_put(buf, cap, &at, 6, v, 1);
    if (!s->host) {
        if (st == GZ_OK) st = gz_rec_put(buf, cap, &at, 8, s->host_key.key, 33);
        if (st == GZ_OK) st = gz_rec_put(buf, cap, &at, 10, s->address, s->address_len);
    }
    gz_put_u32(v, s->key_epoch);
    if (st == GZ_OK) st = gz_rec_put(buf, cap, &at, 12, v, 4);
    gz_put_u32(v, s->key_index);
    if (st == GZ_OK) st = gz_rec_put(buf, cap, &at, 14, v, 4);
    if (s->host) {
        v[0] = s->listed ? 1 : 0;
        if (st == GZ_OK) st = gz_rec_put(buf, cap, &at, 16, v, 1);
        gz_put_u16(v, s->standbys);
        if (st == GZ_OK) st = gz_rec_put(buf, cap, &at, 18, v, 2);
    } else {
        if (st == GZ_OK && cond_len) st = gz_rec_put(buf, cap, &at, 20, cond, cond_len);
        v[0] = s->auto_join ? 1 : 0;
        if (st == GZ_OK) st = gz_rec_put(buf, cap, &at, 22, v, 1);
    }
    return st == GZ_OK ? at : 0;
}

static int free_slot(const gz_node_t *c)
{
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++)
        if (c->slots[i].state == SLOT_FREE) return i;
    return -1;
}

static int lobby_slot_by_scope(const gz_node_t *c, const uint8_t scope[32])
{
    int i = gz_route_slot_by_scope(c, scope);
    return i >= 0 && c->slots[i].kind == SLOT_KIND_LOBBY ? i : -1;
}

/* A slot left out at this start, by its scope (H1). */
static int left_out_by_scope(const gz_node_t *c, const uint8_t scope[32])
{
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++)
        if (c->slots[i].state == SLOT_LEFT_OUT && memcmp(c->slots[i].scope, scope, 32) == 0) return i;
    return -1;
}

/* 1 if every even field of a Node record is one of `known` (bit t / 2): a
 * field a newer program requires stops the start, as for the Lobby records
 * (review B of PR 44, L3). The stream is well formed already. */
static int node_rec_known(gz_bytes_t b, uint32_t known)
{
    size_t at = 0;
    while (at < b.len) {
        uint64_t t, l;
        size_t n = gz_bigsize_get(b.data + at, b.len - at, &t);
        if (!n) return 0;
        at += n;
        n = gz_bigsize_get(b.data + at, b.len - at, &l);
        if (!n || l > b.len - at - n) return 0;
        at += n + (size_t)l;
        if (!(t & 1) && (t >= 64 || !(known & (1u << (t / 2))))) return 0;
    }
    return 1;
}

/* A slot_opened record at load: the slot is Open again, with its lobby
 * engine made anew for the Lobby records that follow. */
gz_status_t gz_ls_load_opened(gz_node_t *c, const gz_record_t *rec)
{
    gz_bytes_t serial, scope, role, epoch, index, v;
    int i, bad_address = 0;
    if (rec->bytes.len > OPENED_MAX || !gz_rec_valid(rec->bytes) || !node_rec_known(rec->bytes, 0xffeu) ||
        !arg(rec->bytes, 2, 4, &serial) ||
        !arg(rec->bytes, 4, 32, &scope) || !arg(rec->bytes, 6, 1, &role) || role.data[0] > 1 ||
        !arg(rec->bytes, 12, 4, &epoch) || !arg(rec->bytes, 14, 4, &index) || gz_get_u32(serial.data) == 0 ||
        gz_get_u32(index.data) == 0xffffffffu) /* the pair's second index would wrap (L4) */
        return GZ_ERR_CORRUPT;
    if (gz_get_u32(serial.data) > c->slot_serial) c->slot_serial = gz_get_u32(serial.data);
    if (gz_get_u32(index.data) + 1 > c->np.highest_index && gz_get_u32(epoch.data) == (c->np.have_epoch ? c->np.epoch : 0))
        c->np.highest_index = gz_get_u32(index.data) + 1;
    if (gz_route_slot_by_scope(c, scope.data) >= 0 || left_out_by_scope(c, scope.data) >= 0 ||
        (i = free_slot(c)) < 0)
        return GZ_ERR_CORRUPT;
    slot_t *s = &c->slots[i];
    memset(s, 0, sizeof *s);
    s->kind = SLOT_KIND_LOBBY;
    s->serial = gz_get_u32(serial.data);
    s->gen = (uint16_t)s->serial;
    s->host = role.data[0] == 1;
    memcpy(s->scope, scope.data, 32);
    s->key_epoch = gz_get_u32(epoch.data);
    s->key_index = gz_get_u32(index.data);
    if (s->host) {
        if (!arg(rec->bytes, 16, 1, &v)) return GZ_ERR_CORRUPT;
        s->listed = v.data[0] != 0;
        if (!arg(rec->bytes, 18, 2, &v)) return GZ_ERR_CORRUPT;
        s->standbys = gz_get_u16(v.data);
    } else {
        if (!arg(rec->bytes, 8, 33, &v)) return GZ_ERR_CORRUPT;
        memcpy(s->host_key.key, v.data, 33);
        if (!arg(rec->bytes, 10, 0, &v)) return GZ_ERR_CORRUPT;
        /* An address that is no address is never saved (the join refuses it).
         * Were one found all the same, the slot is left out below: a CONNECT
         * for it could not be issued, and a start must not fail on it. */
        bad_address = !gz_connect_address_ok(v);
        if (!bad_address) {
            memcpy(s->address, v.data, v.len);
            s->address_len = (uint8_t)v.len;
        }
        v.len = 0;
        if (gz_rec_find(rec->bytes, 20, &v) == 1 && v.len > COND_MAX) return GZ_ERR_CORRUPT;
        if (!cond_decode(v.data, v.len, &s->cond)) return GZ_ERR_CORRUPT;
        if (!arg(rec->bytes, 22, 1, &v)) return GZ_ERR_CORRUPT;
        s->auto_join = v.data[0] != 0;
    }
    /* A role other than the data folder's, or a generation of 0: the slot is
     * left out and counted, at every start alike; its records are nobody's. */
    if (bad_address || s->host != (c->cfg.host != 0) || s->gen == 0) {
        memset(s, 0, sizeof *s);
        c->np.skipped_slots++;
        return GZ_OK;
    }
    /* Keys the port cannot give now (a locked seed, a signer away, an epoch
     * this wallet cannot derive): a placeholder that keeps the slot's place
     * and scope. Its Lobby records are nobody's this run; the person is told
     * at its resume step (H1). */
    if (!gz_ls_init(c, i)) {
        memset(&s->lobby, 0, sizeof s->lobby);
        s->state = SLOT_LEFT_OUT;
        c->np.skipped_slots++;
        return GZ_OK;
    }
    s->state = SLOT_OPEN;
    return GZ_OK;
}

/* slot_closed: 2 serial (u32), 4 final state (u8: 0 never joined, 4 Funding,
 * 5 Active, 6 Cancelled, 7 Failed), 6 reason (u16). */
gz_status_t gz_ls_load_closed(gz_node_t *c, const gz_record_t *rec)
{
    gz_bytes_t serial, state, reason;
    if (rec->bytes.len > 32 || !gz_rec_valid(rec->bytes) || !node_rec_known(rec->bytes, 0xeu) ||
        !arg(rec->bytes, 2, 4, &serial) ||
        !arg(rec->bytes, 4, 1, &state) || !arg(rec->bytes, 6, 2, &reason))
        return GZ_ERR_CORRUPT;
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) {
        slot_t *s = &c->slots[i];
        if ((s->state != SLOT_OPEN && s->state != SLOT_LEFT_OUT) || s->kind != SLOT_KIND_LOBBY ||
            s->serial != gz_get_u32(serial.data))
            continue;
        /* The tombstone's contents: the lobby's own end record if it had one. */
        if (s->host)
            ended_add(c, s->scope, state.data[0], gz_get_u16(reason.data), s->end_cancel, s->have_end ? s->end_cancel_len : 0);
        gz_sg_keyed_add(c, s);   /* its rounds may still need its keys across this start (2.5) */
        memset(s, 0, sizeof *s); /* Free: Closing is derived (the signing engine keeps what its rounds need) */
        return GZ_OK;
    }
    return GZ_OK; /* a slot left out at its slot_opened */
}

/* A Lobby record at load, routed by the scope it carries (7.3). */
gz_status_t gz_ls_load_record(gz_node_t *c, const gz_record_t *rec)
{
    uint8_t scope[32], st8;
    uint16_t reason;
    const uint8_t *cancel;
    size_t cancel_len;
    int i;
    if (!gz_lobby_rec_scope(rec, scope)) return GZ_ERR_CORRUPT;
    if ((i = lobby_slot_by_scope(c, scope)) < 0) return GZ_OK; /* a closed lobby's, or a slot left out */
    slot_t *s = &c->slots[i];
    if (rec->type == GZ_REC_LOBBY_ENDED && gz_lobby_rec_ended(rec, scope, &st8, &reason, &cancel, &cancel_len)) {
        s->have_end = 1;
        s->end_cancel_len = cancel_len <= sizeof s->end_cancel ? cancel_len : 0;
        if (s->end_cancel_len) memcpy(s->end_cancel, cancel, s->end_cancel_len);
    }
    return s->host ? gz_lobby_host_restore(&s->lobby.h, rec) : gz_lobby_member_restore(&s->lobby.m, rec);
}

/* The pause changed (api.c): a host applies its start rule again; a
 * member's lobby is dealt with by gz_ls_after (pause_apply). Each slot in a
 * step of its own inside the API's bracket, its view after it. */
static gz_status_t pause_inline(gz_node_t *c, int eng, gz_action_list_t *out)
{
    slot_t *s = &c->slots[eng - ENG_SLOT0];
    return s->host ? gz_lobby_host_pause_changed(&s->lobby.h, out) : GZ_OK;
}

gz_status_t gz_ls_pause_changed(gz_node_t *c, gz_action_list_t *out)
{
    gz_status_t st = GZ_OK;
    for (int i = 0; i < GZ_NODE_MAX_SLOTS && st == GZ_OK; i++) {
        if (c->slots[i].state != SLOT_OPEN || c->slots[i].kind != SLOT_KIND_LOBBY) continue;
        st = gz_c_slot_inline(c, ENG_SLOT0 + i, pause_inline, out);
        if (st == GZ_OK) st = gz_ls_after(c, i, out);
    }
    return st;
}

/* 1 if the member's round in this lobby has partial signatures out (11.3:
 * the pause then holds the lobby). The signing engine's fact; until P4.3
 * there is none in a release build, so the pause holds nothing there. */
int gz_ls_partials_out(const gz_node_t *c, const uint8_t scope[32])
{
#ifdef GZ_TEST_KINDS
    for (int k = 0; k < SS_MAX; k++)
        if (c->ss.r[k].used && !c->ss.r[k].ended && c->ss.r[k].partials && memcmp(c->ss.r[k].scope, scope, 32) == 0)
            return 1;
#else
    (void)c;
    (void)scope;
#endif
    return 0;
}

#ifdef GZ_TEST_KINDS
#define SS_REC_BEGUN 0x7e5a0002u      /* the signing stand-in's records (below) */
#define SS_REC_ENDED 0x7e5a0004u
static gz_status_t ss_save(gz_action_list_t *out, uint32_t type, const ss_round_t *r);
static gz_status_t ss_line(gz_node_t *c, gz_action_list_t *out, const char *what, const uint8_t *scope,
                           const uint8_t *check, const char *k1, uint64_t v1, const char *k2, uint64_t v2);
#endif

/* The member's round in this lobby, begun and with no partial signature
 * sent, is aborted (11.3: round_abort for its items, before the leave). The
 * signing engine's (P4.3), which sends round_abort only where it has items;
 * in test builds the stand-in ends its round. 1 in *aborted if there was one. */
static gz_status_t round_abort(gz_node_t *c, const slot_t *s, gz_action_list_t *out, int *aborted)
{
    gz_status_t st = GZ_OK;
    *aborted = 0;
#ifdef GZ_TEST_KINDS
    for (int k = 0; k < SS_MAX && st == GZ_OK; k++) {
        ss_round_t *r = &c->ss.r[k];
        if (!r->used || r->ended || memcmp(r->scope, s->scope, 32) != 0) continue;
        r->ended = 1;
        *aborted = 1;
        st = ss_save(out, SS_REC_ENDED, r);
        if (st == GZ_OK) st = ss_line(c, out, "sign-abort", r->scope, r->check, " reason=", 2, NULL, 0);
    }
#else
    (void)c;
    (void)s;
    (void)out;
#endif
    return st;
}

static gz_status_t leave_inline(gz_node_t *c, int eng, gz_action_list_t *out)
{
    return gz_lobby_member_leave(&c->slots[eng - ENG_SLOT0].lobby.m, out);
}

/* The pause on a member's lobby (local-api.md 11.3), after each of its
 * steps. A held lobby whose round no longer has partial signatures out (it
 * ended: Funding, a Retry, a failure) leaves the hold, which is saved again.
 * Then, once the slot is awake (resumed at this start, or opened in this
 * run) and, if the host may hold its seat, connected, a lobby with partial signatures out runs
 * on, one Awaiting funding or Live is unchanged, and every other one, joined
 * or still joining, is left (leave reason 2), after a round_abort where its
 * round had begun. A saved pause is so applied at every start, before the
 * lobby can join, ready or sign anything. */
static gz_status_t pause_apply(gz_node_t *c, int i, gz_action_list_t *out)
{
    slot_t *s = &c->slots[i];
    const gz_lobby_member_t *m = &s->lobby.m;
    int out_now, aborted = 0;
    gz_status_t st;
    if (s->host || !gz_api_paused(c)) return GZ_OK;
    out_now = gz_ls_partials_out(c, s->scope);
    if (!out_now && gz_api_held(c, s->scope) >= 0 && (st = gz_api_release(c, s->scope, out)) != GZ_OK) return st;
    if (!s->awake || m->ended || out_now) return GZ_OK;
    /* A seat the host holds, or may hold (the join was made), is left on a
     * connection, so that the leave reaches the host: at a start that is the
     * step its link comes up in. Not connected, it can sign nothing meanwhile. */
    if (!m->connected && (m->joined || m->join_len)) return GZ_OK;
    if (m->lobby_state == GZ_LOBBY_FUNDING || m->lobby_state == GZ_LOBBY_ACTIVE || m->round_state) return GZ_OK;
    if ((st = round_abort(c, s, out, &aborted)) != GZ_OK) return st;
    if ((st = gz_c_slot_inline(c, ENG_SLOT0 + i, leave_inline, out)) != GZ_OK) return st;
    if (aborted) c->api.aborted |= 1u << i;
    else c->api.left |= 1u << i;
    return GZ_OK;
}

/* ---- after a lobby's step ----------------------------------------------------- */

static gz_status_t gate_closed_inline(gz_node_t *c, int eng, gz_action_list_t *out)
{
    return gz_lobby_member_gate_closed(&c->slots[eng - ENG_SLOT0].lobby.m, out);
}

static gz_status_t gate_opened_inline(gz_node_t *c, int eng, gz_action_list_t *out)
{
    return gz_lobby_member_gate_opened(&c->slots[eng - ENG_SLOT0].lobby.m, out);
}

void gz_ls_wipe32(uint8_t *p)
{
    volatile uint8_t *v = p;
    for (size_t i = 0; i < 32; i++) v[i] = 0;
}

static void gate_wipe(slot_t *s)
{
    volatile uint8_t *v = s->gate_secret;
    for (size_t i = 0; i < sizeof s->gate_secret; i++) v[i] = 0;
    s->gate_have = 0;
}

static void gate_close(gz_node_t *c, slot_t *s)
{
    if (!s->gate_open && !s->gate_have) return;
    s->gate_open = 0;
    s->gate_flight = 0;
    gate_wipe(s);                                                             /* RULE-NODE:GATE_WIPES */
    if (c->cfg.crypto.forget) c->cfg.crypto.forget(c->cfg.crypto.ctx, s->scope); /* the scoped secret is wiped */
}

/* What a log line says of a lobby, when it changes:
 *   lobby scope=S role=host state=N joined=J ready=R
 *   lobby scope=S role=member state=N seat=T joined=J ready=R ended=E */
static gz_status_t state_line(gz_node_t *c, slot_t *s, gz_action_list_t *out)
{
    uint32_t now[5] = {0, 0, 0, 0, 0};
    char text[120];
    size_t at = 0;
    if (s->host) {
        const gz_lobby_host_t *h = &s->lobby.h;
        now[0] = (uint32_t)h->state;
        for (uint16_t k = 0; k < h->n_seats; k++) {
            if (h->seats[k].state == GZ_SEAT_JOINED || h->seats[k].state == GZ_SEAT_READY) now[2]++;
            if (h->seats[k].state == GZ_SEAT_READY && h->seats[k].ready_version == h->values.version) now[3]++;
        }
    } else {
        const gz_lobby_member_t *m = &s->lobby.m;
        now[0] = (uint32_t)m->lobby_state;
        now[1] = (uint32_t)m->seat_state;
        now[2] = (uint32_t)m->joined;
        now[3] = (uint32_t)m->ready;
        now[4] = (uint32_t)m->ended;
    }
    if (s->told && memcmp(now, s->last, sizeof now) == 0) return GZ_OK;
    s->told = 1;
    memcpy(s->last, now, sizeof now);
    text[0] = 0;
    put_s(text, sizeof text, &at, "lobby scope=");
    put_h(text, sizeof text, &at, s->scope);
    put_s(text, sizeof text, &at, s->host ? " role=host state=" : " role=member state=");
    put_u(text, sizeof text, &at, now[0]);
    if (!s->host) {
        put_s(text, sizeof text, &at, " seat=");
        put_u(text, sizeof text, &at, now[1]);
    }
    put_s(text, sizeof text, &at, " joined=");
    put_u(text, sizeof text, &at, now[2]);
    put_s(text, sizeof text, &at, " ready=");
    put_u(text, sizeof text, &at, now[3]);
    if (!s->host) {
        put_s(text, sizeof text, &at, " ended=");
        put_u(text, sizeof text, &at, now[4]);
    }
    return np_log(c, out, text);
}

/* Put the SAVE at `last` (the list's last action) into the first SAVE at or
 * after `from` that holds a record of `type`, with every save between: one
 * batch. The owners follow the list. Nothing to do if there is none. */
static gz_status_t merge_into(gz_node_t *c, gz_action_list_t *out, size_t from, uint32_t type)
{
    size_t first = out->count, i, w;
    for (i = from; i + 1 < out->count && first == out->count; i++) {
        if (out->slots[i].kind != GZ_ACTION_SAVE) continue;
        for (size_t k = 0; k < out->slots[i].u.save.n_records; k++)
            if (out->slots[i].u.save.records[k].type == type) first = i;
    }
    if (first == out->count) return GZ_OK;
    /* The owners of what stays: the first save, and everything after it that
     * is not a save. */
    for (i = first + 1, w = first + 1; i < out->count; i++)
        if (out->slots[i].kind != GZ_ACTION_SAVE) c->owner[w++ - c->base] = c->owner[i - c->base];
    size_t before = out->count;
    gz_status_t st = gz_action_list_merge_saves(out, first, out->count);
    if (st != GZ_OK) return st == GZ_ERR_NO_SPACE ? gz_c_bug(c, ENG_NODE) : st;
    for (i = out->count; i < before; i++) c->owner[i - c->base] = -1;
    return GZ_OK;
}

/* The lobby is over: slot_closed in the batch of its end, its timers
 * cancelled, the slot Free or Closing, its end in the index. */
static gz_status_t slot_end(gz_node_t *c, int i, gz_action_list_t *out)
{
    slot_t *s = &c->slots[i];
    uint8_t rec[32], v[4], state;
    uint16_t reason;
    uint64_t budget = 0;
    size_t at = 0, n_seated = s->n_seated;
    char text[96];
    gz_status_t st;
    gz_record_t r;
    /* A lobby held by the pause ends: the hold goes with it, saved in the
     * batch of its end (merge_into below). Its request ids run their 30 days. */
    if ((st = gz_api_release(c, s->scope, out)) != GZ_OK) return st;
    gz_api_slot_ended(c, s->scope);
    if (s->host) {
        const gz_lobby_host_t *h = &s->lobby.h;
        state = (uint8_t)h->state;
        reason = h->end_reason;
        ended_add(c, s->scope, state, reason, h->cancel_msg, h->cancel_len);
        if (h->terms.signing_budget_ms) budget = h->terms.signing_budget_ms;
    } else {
        const gz_lobby_member_t *m = &s->lobby.m;
        /* 0: it never got in. Else the lobby's end as the member knows it;
         * its own leave and its removal count as Cancelled, for it. */
        state = m->never_joined ? 0 : m->lobby_state == GZ_LOBBY_FAILED ? GZ_LOBBY_FAILED : GZ_LOBBY_CANCELLED;
        reason = m->left ? m->leave_reason : 0;
        if (m->have_terms) budget = m->terms.signing_budget_ms;
    }
    gz_put_u32(v, s->serial);
    if (gz_rec_put(rec, sizeof rec, &at, 2, v, 4) != GZ_OK || gz_rec_put(rec, sizeof rec, &at, 4, &state, 1) != GZ_OK)
        return gz_c_bug(c, ENG_NODE);
    gz_put_u16(v, reason);
    if (gz_rec_put(rec, sizeof rec, &at, 6, v, 2) != GZ_OK) return gz_c_bug(c, ENG_NODE);
    r.type = GZ_RECORD_SLOT_CLOSED;
    r.bytes.data = rec;
    r.bytes.len = at;
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
    c->owner[out->count - 1 - c->base] = (int8_t)ENG_NODE;
    if ((st = merge_into(c, out, c->bracket_from, GZ_REC_LOBBY_ENDED)) != GZ_OK) return st;
    text[0] = 0;
    at = 0;
    put_s(text, sizeof text, &at, "slot-closed scope=");
    put_h(text, sizeof text, &at, s->scope);
    put_s(text, sizeof text, &at, " serial=");
    put_u(text, sizeof text, &at, s->serial);
    put_s(text, sizeof text, &at, " state=");
    put_u(text, sizeof text, &at, state);
    put_s(text, sizeof text, &at, " reason=");
    put_u(text, sizeof text, &at, reason);
    put_s(text, sizeof text, &at, s->round_ok ? " closing=1" : " closing=0");
    if ((st = np_log(c, out, text)) != GZ_OK) return st;
    gate_close(c, s);
    gz_sg_keyed_add(c, s);   /* its rounds may still need its keys (2.5) */
#ifdef GZ_TEST_KINDS
    for (int k = 0; k < SS_MAX; k++) /* a round that was running under it is over with it */
        if (c->ss.r[k].used && !c->ss.r[k].ended && memcmp(c->ss.r[k].scope, s->scope, 32) == 0) c->ss.r[k].ended = 1;
#endif
    if (s->round_ok) {
        /* A round was handed over: Closing. The member's CONNECT stands and
         * the host's seats stay, for the round's last news. */
        if ((st = closing_add(c, s, budget, out)) != GZ_OK) return st;
        s->n_seated = 0; /* np_slot_freed gives up no seat: the Closing entry holds them */
    } else if (s->host) {
        /* Free at once: its members' keys hold no seat any more. */
        for (size_t j = 0; j < n_seated; j++) {
            gz_action_t sa = {.kind = GZ_ACTION_SET_SEATED};
            sa.u.set_seated.member = s->seated[j];
            sa.u.set_seated.seated = 0;
            if ((st = gz_action_list_add(out, &sa)) != GZ_OK) return st;
        }
    } else {
        if ((st = np_disconnect(out, &s->link, GZ_DISCONNECT_DONE)) != GZ_OK) return st;
    }
    if ((st = np_slot_freed(c, i, out)) != GZ_OK) return st;
    return gz_view_status(c, 0, out);
}

/* A slot left out at this start: the person is told at its resume step,
 * which lobby and why (H1). */
gz_status_t gz_ls_left_out_note(gz_node_t *c, int i, gz_action_list_t *out)
{
    const slot_t *s = &c->slots[i];
    char text[192];
    size_t at = 0;
    gz_status_t st;
    text[0] = 0;
    put_s(text, sizeof text, &at, "attention lobby-left-out scope=");
    put_h(text, sizeof text, &at, s->scope);
    put_s(text, sizeof text, &at, s->host ? " role=host" : " role=member");
    put_s(text, sizeof text, &at, " why=keys_unavailable");
    if ((st = gz_c_node_bracket_begin(c, out)) != GZ_OK) return st;
    if ((st = np_log(c, out, text)) != GZ_OK) return st;
    return gz_c_node_bracket_end(c, out);
}

static gz_status_t sign_arm(gz_node_t *c, gz_action_list_t *out);

/* After every step of a slot's lobby (a message, a timer, a command, its
 * resume, an outcome): the routing gate for round kinds, the per-lobby
 * signing gate, the lobby's log line, and the slot's end. What is appended
 * here is the node part's. */
gz_status_t gz_ls_after(gz_node_t *c, int i, gz_action_list_t *out)
{
    slot_t *s = &c->slots[i];
    size_t start = out->count;
    gz_status_t st = GZ_OK;
    if (s->state != SLOT_OPEN || s->kind != SLOT_KIND_LOBBY) return GZ_OK;
    st = pause_apply(c, i, out);
    s->round_ok = s->host ? gz_lobby_host_round_ok(&s->lobby.h) : gz_lobby_member_round_ok(&s->lobby.m);
    /* The per-lobby gate (AT_JOIN) closes when the check it was opened for
     * has had its last attempt: the lobby left Signing for Funding, Open or
     * its end, or the member was not chosen (12.2). */
    if (st == GZ_OK && !s->host && s->gate_open) {
        if (gz_lobby_member_check_in_flight(&s->lobby.m)) s->gate_flight = 1;
        else if (s->gate_flight) {
            gate_close(c, s);
            st = gz_c_slot_inline(c, ENG_SLOT0 + i, gate_closed_inline, out);
        }
    }
    if (st == GZ_OK) st = state_line(c, s, out);
    if (st == GZ_OK) st = gz_view_slot(c, i, 0, out); /* its view, after the step's saves (rule 8) */
    if (st == GZ_OK && c->api.status_dirty) {          /* a hold released in this step */
        c->api.status_dirty = 0;
        st = gz_view_status(c, 0, out);
    }
    if (st == GZ_OK && (s->host ? s->lobby.h.state == GZ_LOBBY_CANCELLED || s->lobby.h.state == GZ_LOBBY_FAILED
                                : s->lobby.m.ended))
        st = slot_end(c, i, out);
    if (st == GZ_OK) st = sign_arm(c, out);
    for (size_t j = start; st == GZ_OK && j < out->count; j++) {
        if (j - c->base >= GZ_NODE_LIST_ACTIONS) return gz_c_bug(c, ENG_NODE);
        if (c->owner[j - c->base] < 0) c->owner[j - c->base] = (int8_t)ENG_NODE;
    }
    return st;
}

/* ---- the signing stand-in (test builds) ---------------------------------------- */

#ifdef GZ_TEST_KINDS
/* What stands where the signing engine will (P4.3), behind the hand-off
 * interface of lobby_handoff.h, so that the lobby's side of every hand-off
 * runs for real: begin, the outcome back, cancel, member_left, a finished
 * check ignored (rule 3), an unfinished attempt failed at a start (H13).
 * It signs nothing. Its outcome is the node's `test_sign_outcome`, reported
 * `test_sign_delay_ms` after begin. Its records (area 0x7e5a): 2 a round
 * begun, 4 a round ended; each scope (32), check (32): SS_REC_*, above. */

static ss_round_t *ss_find(gz_node_t *c, const uint8_t scope[32], const uint8_t check[32])
{
    for (int k = 0; k < SS_MAX; k++)
        if (c->ss.r[k].used && memcmp(c->ss.r[k].scope, scope, 32) == 0 && memcmp(c->ss.r[k].check, check, 32) == 0)
            return &c->ss.r[k];
    return NULL;
}

/* A place for a new round: a free one, else the oldest ended one. NULL only
 * if SS_MAX rounds are running, which GZ_NODE_MAX_SLOTS keeps from happening. */
static ss_round_t *ss_place(gz_node_t *c)
{
    ss_round_t *best = NULL;
    for (int k = 0; k < SS_MAX; k++) {
        ss_round_t *r = &c->ss.r[k];
        if (!r->used) return r;
        if (r->ended && (!best || r->seq < best->seq)) best = r;
    }
    return best;
}

static gz_status_t ss_save(gz_action_list_t *out, uint32_t type, const ss_round_t *r)
{
    uint8_t b[64];
    gz_record_t rec = {type, {b, 64}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    memcpy(b, r->scope, 32);
    memcpy(b + 32, r->check, 32);
    a.u.save.records = &rec;
    a.u.save.n_records = 1;
    return gz_action_list_add(out, &a);
}

static gz_status_t ss_line(gz_node_t *c, gz_action_list_t *out, const char *what, const uint8_t *scope,
                           const uint8_t *check, const char *k1, uint64_t v1, const char *k2, uint64_t v2)
{
    char text[140];
    size_t at = 0;
    text[0] = 0;
    put_s(text, sizeof text, &at, what);
    put_s(text, sizeof text, &at, " scope=");
    put_h(text, sizeof text, &at, scope);
    if (check) {
        put_s(text, sizeof text, &at, " check=");
        put_h(text, sizeof text, &at, check);
    }
    if (k1) {
        put_s(text, sizeof text, &at, k1);
        put_u(text, sizeof text, &at, v1);
    }
    if (k2) {
        put_s(text, sizeof text, &at, k2);
        put_u(text, sizeof text, &at, v2);
    }
    return np_log(c, out, text);
}

static gz_status_t ss_begin(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out)
{
    slot_t *s = ctx;
    gz_node_t *c = s->node;
    ss_round_t *r = ss_find(c, h->scope, h->check_id);
    gz_status_t st;
    if (r && r->ended) /* rule 3: a finished check is ignored */
        return ss_line(c, out, "sign-begin-ignored", h->scope, h->check_id, " resume=", (uint64_t)h->resume, NULL, 0);
    if (!r) {
        if (!(r = ss_place(c))) return GZ_ERR_BUG;
        memset(r, 0, sizeof *r);
        r->used = 1;
        r->seq = ++c->ss.seq;
        memcpy(r->scope, h->scope, 32);
        memcpy(r->check, h->check_id, 32);
        if ((st = ss_save(out, SS_REC_BEGUN, r)) != GZ_OK) return st;
    }
    /* "unfinished": the outcome never comes. */
    r->due_ms = (c->cfg.test_sign_outcome & 0xffu) == GZ_TEST_SIGN_UNFINISHED ? 0 : np_mono(c) + c->cfg.test_sign_delay_ms + 1;
    r->partials = (c->cfg.test_sign_outcome & GZ_TEST_SIGN_PARTIALS) != 0;
    c->ss.arm = 1;
    if ((st = ss_line(c, out, "sign-begin", h->scope, h->check_id, " role=", (uint64_t)h->role, " resume=",
                      (uint64_t)h->resume)) != GZ_OK)
        return st;
    return ss_line(c, out, "sign-handoff", h->scope, h->check_id, " signers=", h->signers, " budget-end=",
                   h->budget_end_ms);
}

static gz_status_t ss_cancel(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out)
{
    slot_t *s = ctx;
    gz_node_t *c = s->node;
    gz_status_t st = GZ_OK;
    for (int k = 0; k < SS_MAX && st == GZ_OK; k++) {
        ss_round_t *r = &c->ss.r[k];
        if (!r->used || r->ended || memcmp(r->scope, scope, 32) != 0) continue;
        r->ended = 1; /* a cancel never leaves a round running (A9) */
        st = ss_save(out, SS_REC_ENDED, r);
    }
    return st == GZ_OK ? ss_line(c, out, "sign-cancel", scope, NULL, " reason=", reason, NULL, 0) : st;
}

static gz_status_t ss_left(void *ctx, const uint8_t scope[32], const uint8_t ckey[33], gz_action_list_t *out)
{
    slot_t *s = ctx;
    return ss_line(s->node, out, "sign-member-left", scope, ckey + 1, NULL, 0, NULL, 0);
}

gz_status_t gz_ss_load(gz_node_t *c, const gz_record_t *rec)
{
    const uint8_t *b = rec->bytes.data;
    ss_round_t *r;
    if (rec->bytes.len != 64 || (rec->type != SS_REC_BEGUN && rec->type != SS_REC_ENDED)) return GZ_ERR_CORRUPT;
    r = ss_find(c, b, b + 32);
    if (!r) {
        if (!(r = ss_place(c))) return GZ_OK; /* more than it keeps: the oldest are ended ones */
        memset(r, 0, sizeof *r);
        r->used = 1;
        r->seq = ++c->ss.seq;
        memcpy(r->scope, b, 32);
        memcpy(r->check, b + 32, 32);
    }
    if (rec->type == SS_REC_ENDED) r->ended = 1;
    return GZ_OK;
}

/* Report round c->ss.cur's outcome to its slot's lobby: the stand-in's record
 * first, then the lobby's (one batch, rule 2). */
static gz_status_t deliver_inline(gz_node_t *c, int eng, gz_action_list_t *out)
{
    slot_t *s = &c->slots[eng - ENG_SLOT0];
    ss_round_t *r = &c->ss.r[c->ss.cur];
    int outcome = (int)(c->ss.force ? GZ_TEST_SIGN_RETRY : c->cfg.test_sign_outcome & 0xffu);
    gz_status_t st;
    /* At function scope: gcc's AddressSanitizer guards a large local whose
     * scope ends early with calls the isolation check refuses. */
    uint8_t failed[GZ_LOBBY_MAX_SEATS * 33];
    r->ended = 1;
    /* Its save, then the lobby's at once: adjacent saves are one batch. The
     * line that tells of it comes after both. */
    if ((st = ss_save(out, SS_REC_ENDED, r)) != GZ_OK) return st;
    if (s->host) {
        gz_lobby_host_t *h = &s->lobby.h;
        size_t n = 0;
        if (outcome == GZ_TEST_SIGN_FUNDING) st = gz_lobby_host_round_result(h, GZ_LOBBY_ROUND_FUNDING, NULL, 0, out);
        else if (outcome == GZ_TEST_SIGN_FAILED) st = gz_lobby_host_round_result(h, GZ_LOBBY_ROUND_FAILED, NULL, 0, out);
        else {
            /* Retry: every chosen seat is blamed, so each must ready again. */
            for (uint16_t k = 0; k < h->n_seats; k++)
                if (h->seats[k].chosen) memcpy(failed + 33 * n++, h->seats[k].ckey, 33);
            st = gz_lobby_host_round_result(h, GZ_LOBBY_ROUND_RETRY, failed, n, out);
        }
    } else {
        st = gz_lobby_member_round_result(&s->lobby.m,
                                          outcome == GZ_TEST_SIGN_FUNDING  ? GZ_LOBBY_ROUND_FUNDING
                                          : outcome == GZ_TEST_SIGN_FAILED ? GZ_LOBBY_ROUND_FAILED
                                                                           : GZ_LOBBY_ROUND_RETRY,
                                          r->check, out);
    }
    if (st != GZ_OK) return st;
    return ss_line(c, out, c->ss.force ? "sign-resume-failed" : "sign-outcome", r->scope, r->check, " outcome=",
                   (uint64_t)outcome, NULL, 0);
}

static gz_status_t sign_arm(gz_node_t *c, gz_action_list_t *out)
{
    uint64_t due = 0, now = np_mono(c);
    if (!c->ss.arm) return GZ_OK;
    c->ss.arm = 0;
    for (int k = 0; k < SS_MAX; k++) {
        const ss_round_t *r = &c->ss.r[k];
        if (r->used && !r->ended && r->due_ms && (!due || r->due_ms < due)) due = r->due_ms;
    }
    return due ? np_set_timer(out, NP_TIMER_SIGN, due > now ? due - now : 0) : GZ_OK;
}

/* The stand-in's timer: one round's outcome a step (8.3, R3). */
gz_status_t gz_ss_timer(gz_node_t *c, gz_action_list_t *out)
{
    uint64_t now = np_mono(c);
    gz_status_t st;
    for (int k = 0; k < SS_MAX; k++) {
        ss_round_t *r = &c->ss.r[k];
        int i;
        if (!r->used || r->ended || !r->due_ms || r->due_ms > now) continue;
        if ((i = lobby_slot_by_scope(c, r->scope)) < 0) {
            r->ended = 1;
            continue;
        }
        c->ss.cur = k;
        c->ss.force = 0;
        if ((st = gz_c_slot_bracket(c, ENG_SLOT0 + i, deliver_inline, out)) != GZ_OK) return st;
        break;
    }
    if ((st = gz_c_node_bracket_begin(c, out)) != GZ_OK) return st;
    c->ss.arm = 1;
    if ((st = sign_arm(c, out)) != GZ_OK) {
        c->bracket_on = 0;
        return st;
    }
    return gz_c_node_bracket_end(c, out);
}

/* At a start, before the lobbies resume: every attempt found unfinished is
 * failed (H13 on the host; a member's round found in progress is aborted),
 * one a call. The lobby, loaded and not yet resumed, takes the Retry and so
 * hands nothing over again. */
gz_status_t gz_ss_resume(gz_node_t *c, gz_action_list_t *out, int *more)
{
    *more = 0;
    for (int k = 0; k < SS_MAX; k++) {
        ss_round_t *r = &c->ss.r[k];
        int i;
        if (!r->used || r->ended) continue;
        if ((i = lobby_slot_by_scope(c, r->scope)) < 0) {
            r->ended = 1;
            continue;
        }
        c->ss.cur = k;
        c->ss.force = 1;
        *more = 1;
        gz_status_t st = gz_c_slot_bracket(c, ENG_SLOT0 + i, deliver_inline, out);
        c->ss.force = 0;
        return st;
    }
    return GZ_OK;
}
#else
static gz_status_t sign_arm(gz_node_t *c, gz_action_list_t *out)
{
    (void)c;
    (void)out;
    return GZ_OK;
}
#endif

/* ---- commands (section 5: 0x01xx the lobby, 0x04xx the signing gate) ------------ */

static gz_status_t open_inline(gz_node_t *c, int eng, gz_action_list_t *out)
{
    slot_t *s = &c->slots[eng - ENG_SLOT0];
    if (s->host) {
        /* Checked once already on the same records (gz_ls_command): a refusal
         * now is a bug. */
        gz_status_t st = gz_lobby_host_open(&s->lobby.h, c->lc.a.data, c->lc.a.len, c->lc.b.data, c->lc.b.len, out);
        return st == GZ_ERR_ARGUMENT ? GZ_ERR_BUG : st;
    }
    return gz_lobby_member_connect(&s->lobby.m, out);
}

static gz_status_t command_inline(gz_node_t *c, int eng, gz_action_list_t *out)
{
    slot_t *s = &c->slots[eng - ENG_SLOT0];
    switch (c->lc.code) {
    case GZ_CMD_LOBBY_READY: return gz_lobby_member_ready(&s->lobby.m, out);
    case GZ_CMD_LOBBY_UNREADY: return gz_lobby_member_unready(&s->lobby.m, out);
    case GZ_CMD_LOBBY_LEAVE: return gz_lobby_member_leave(&s->lobby.m, out);
    case GZ_CMD_LOBBY_REMOVE: return gz_lobby_host_remove(&s->lobby.h, c->lc.a.data, out);
    case GZ_CMD_LOBBY_CANCEL: return gz_lobby_host_cancel(&s->lobby.h, 2, out);
    case GZ_CMD_LOBBY_SET_VALUES: {
        uint64_t vals[GZ_TERMS_MAX_ADJ];
        size_t n = c->lc.a.len / 8, mark = out->count, used = out->used;
        for (size_t k = 0; k < n; k++) vals[k] = gz_get_u64(c->lc.a.data + 8 * k);
        gz_status_t st = gz_lobby_host_set_values(&s->lobby.h, vals, (uint8_t)n, out);
        if (st == GZ_ERR_ARGUMENT) { /* values outside the ranges: the person's, a refusal */
            out->count = mark;
            out->used = used;
            c->lc.refused = 1;
            return GZ_OK;
        }
        return st;
    }
    }
    return GZ_ERR_BUG;
}

/* 1 if the lobby answered the command with "refused now" (lobby.h). */
static int was_refused(const gz_action_list_t *out, size_t from)
{
    for (size_t i = from; i < out->count; i++)
        if (out->slots[i].kind == GZ_ACTION_NOTIFY && out->slots[i].u.notify.code == GZ_NOTE_COMMAND_REFUSED) return 1;
    return 0;
}

static int gen_free(const gz_node_t *c, uint16_t gen)
{
    if (gen == 0) return 0;
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++)
        if (c->slots[i].state != SLOT_FREE && c->slots[i].gen == gen) return 0;
    return 1;
}

static gz_status_t opened_line(gz_node_t *c, const slot_t *s, gz_action_list_t *out)
{
    char text[120];
    size_t at = 0;
    text[0] = 0;
    put_s(text, sizeof text, &at, "slot-opened scope=");
    put_h(text, sizeof text, &at, s->scope);
    put_s(text, sizeof text, &at, " serial=");
    put_u(text, sizeof text, &at, s->serial);
    put_s(text, sizeof text, &at, s->host ? " role=host index=" : " role=member index=");
    put_u(text, sizeof text, &at, s->key_index);
    return np_log(c, out, text);
}

/* The slot's first batch and its lobby's first step. The slot's fields are
 * set and its engine made. */
static gz_status_t slot_begin(gz_node_t *c, int i, gz_bytes_t cond, gz_action_list_t *out)
{
    slot_t *s = &c->slots[i];
    uint8_t ob[OPENED_MAX];
    gz_record_t r;
    gz_status_t st;
    do {
        c->slot_serial++;
    } while (!gen_free(c, (uint16_t)c->slot_serial));
    s->serial = c->slot_serial;
    s->gen = (uint16_t)s->serial;
    s->state = SLOT_OPEN;
    s->awake = 1;
    r.type = GZ_RECORD_SLOT_OPENED;
    r.bytes.data = ob;
    r.bytes.len = opened_record(s, cond.data, cond.len, ob, sizeof ob);
    if (!r.bytes.len) return gz_c_bug(c, ENG_NODE);
    if ((st = np_save_pair(c, s->key_index, &r, out)) != GZ_OK) return st;
    if ((st = gz_api_slot_opened(c, i, out)) != GZ_OK) return st; /* its local id, the same batch */
    gz_c_engine_opened(c, ENG_SLOT0 + i);
    if ((st = gz_c_slot_inline(c, ENG_SLOT0 + i, open_inline, out)) != GZ_OK) return st;
    if ((st = opened_line(c, s, out)) != GZ_OK) return st;
    return gz_ls_after(c, i, out);
}

/* The slot's pair: the next one the key port gives. A pair with an invalid
 * child (BIP 32: the port gives no key at that index) is skipped and the next
 * pair tried, never an index already used; a port that gives none of
 * LS_KEY_TRIES pairs has no keys now (503 no_key). */
#define LS_KEY_TRIES 8
static int ls_init_next(gz_node_t *c, int i)
{
    for (uint32_t k = 0; k < LS_KEY_TRIES; k++) {
        uint32_t first = c->np.highest_index + 1 + 2 * k;
        if (first > 0xfffffff0u) return 0;
        c->slots[i].key_index = first;
        if (gz_ls_init(c, i)) return 1;
    }
    return 0;
}

static gz_status_t cmd_open(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t outer, current, v, none = {NULL, 0};
    int i;
    if (!c->cfg.host) return np_command_result(out, cmd, 409, "not_a_host");
    if (!arg(cmd, 12, 0, &outer) || !arg(cmd, 14, 0, &current) || outer.len == 0 || current.len == 0 ||
        outer.len > GZ_TERMS_OUTER_MAX || current.len > GZ_TERMS_CURRENT_MAX)
        return np_command_result(out, cmd, 400, "bad_request");
    if ((i = free_slot(c)) < 0) return np_command_result(out, cmd, 409, "too_many_lobbies"); /* a ninth: refused */
    if (c->np.highest_index > 0xfffffff0u) return np_command_result(out, cmd, 503, "no_key");
    slot_t *s = &c->slots[i];
    memset(s, 0, sizeof *s);
    s->kind = SLOT_KIND_LOBBY;
    s->host = 1;
    s->listed = arg(cmd, 16, 1, &v) && v.data[0] != 0;
    s->standbys = arg(cmd, 18, 2, &v) ? gz_get_u16(v.data) : 0;
    s->key_epoch = c->np.have_epoch ? c->np.epoch : 0;
    if (!ls_init_next(c, i)) {
        memset(s, 0, sizeof *s);
        return np_command_result(out, cmd, 503, "no_key");
    }
    /* The terms are the person's: checked first, with nothing kept, so that a
     * refusal saves no key and opens no slot. */
    size_t mark = out->count, used = out->used;
    gz_status_t st = gz_lobby_host_open(&s->lobby.h, outer.data, outer.len, current.data, current.len, out);
    out->count = mark;
    out->used = used;
    if (st != GZ_OK) {
        memset(s, 0, sizeof *s);
        return st == GZ_ERR_ARGUMENT ? np_command_result(out, cmd, 400, "bad_terms") : st;
    }
    memcpy(s->scope, s->lobby.h.scope, 32);
    if (left_out_by_scope(c, s->scope) >= 0) {   /* its slot waits for its keys (H1) */
        memset(s, 0, sizeof *s);
        return np_command_result(out, cmd, 503, "no_key");
    }
    if (gz_route_slot_by_scope(c, s->scope) >= 0 || ended_find(c, s->scope) >= 0) {
        memset(s, 0, sizeof *s);
        return np_command_result(out, cmd, 409, "lobby_exists");
    }
    if (!gz_ls_init(c, i)) return gz_c_bug(c, ENG_NODE);
    c->lc.a = outer;
    c->lc.b = current;
    if ((st = slot_begin(c, i, none, out)) != GZ_OK) return st;
    return np_command_result(out, cmd, 200, NULL);
}

static gz_status_t cmd_join(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t scope, hk, addr, cond = {NULL, 0}, v;
    gz_lobby_conditions_t cd;
    gz_status_t st;
    int i;
    if (c->cfg.host) return np_command_result(out, cmd, 409, "not_a_member");
    if (!arg(cmd, 12, 32, &scope) || all_zero(scope.data, 32) || !arg(cmd, 14, 33, &hk) || !arg(cmd, 16, 0, &addr))
        return np_command_result(out, cmd, 400, "bad_request");
    /* The invitation's address and key are anyone's words: checked before
     * anything is kept, and refused, so that no saved slot can ever stop a
     * start (the address rule, action.h). */
    if (!gz_connect_address_ok(addr)) return np_command_result(out, cmd, 400, "bad_address");
    if (!c->cfg.crypto.point_ok || c->cfg.crypto.point_ok(c->cfg.crypto.ctx, hk.data) != 1)
        return np_command_result(out, cmd, 400, "bad_host_key");
    if (gz_rec_find(cmd, 18, &cond) == 1 && cond.len > COND_MAX) return np_command_result(out, cmd, 400, "bad_conditions");
    if (!cond_decode(cond.data, cond.len, &cd)) return np_command_result(out, cmd, 400, "bad_conditions");
    if (left_out_by_scope(c, scope.data) >= 0) return np_command_result(out, cmd, 503, "no_key"); /* H1 */
    if (gz_route_slot_by_scope(c, scope.data) >= 0) return np_command_result(out, cmd, 409, "lobby_exists");
    if ((i = free_slot(c)) < 0) return np_command_result(out, cmd, 409, "too_many_lobbies");
    if (c->np.highest_index > 0xfffffff0u) return np_command_result(out, cmd, 503, "no_key");
    slot_t *s = &c->slots[i];
    memset(s, 0, sizeof *s);
    s->kind = SLOT_KIND_LOBBY;
    memcpy(s->scope, scope.data, 32);
    memcpy(s->host_key.key, hk.data, 33);
    memcpy(s->address, addr.data, addr.len);
    s->address_len = (uint8_t)addr.len;
    s->cond = cd;
    s->auto_join = !(arg(cmd, 20, 1, &v) && v.data[0] == 0);
    s->key_epoch = c->np.have_epoch ? c->np.epoch : 0;
    if (!ls_init_next(c, i)) {
        memset(s, 0, sizeof *s);
        return np_command_result(out, cmd, 503, "no_key");
    }
    if ((st = slot_begin(c, i, cond, out)) != GZ_OK) return st;
    return np_command_result(out, cmd, 200, NULL);
}

/* Every member lobby is told the gate changed, in turn. */
static gz_status_t gates_changed(gz_node_t *c, int opened, gz_action_list_t *out)
{
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) {
        slot_t *s = &c->slots[i];
        gz_status_t st;
        if (s->state != SLOT_OPEN || s->kind != SLOT_KIND_LOBBY || s->host) continue;
        if (!opened) gate_close(c, s);
        if ((st = gz_c_slot_inline(c, ENG_SLOT0 + i, opened ? gate_opened_inline : gate_closed_inline, out)) != GZ_OK)
            return st;
        if ((st = gz_ls_after(c, i, out)) != GZ_OK) return st;
    }
    return GZ_OK;
}

gz_status_t gz_ls_command(gz_node_t *c, uint16_t code, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t scope, v;
    gz_status_t st;
    int i, want_host;
    switch (code) {
    case GZ_CMD_SIGNING_UNLOCK:
    case GZ_CMD_SIGNING_LOCK:
        c->unlocked = code == GZ_CMD_SIGNING_UNLOCK;
        if ((st = gates_changed(c, c->unlocked, out)) != GZ_OK) return st;
        return np_command_result(out, cmd, 200, NULL);
    case GZ_CMD_SIGNING_SET:
        /* The setting at run time (local-api.md 14.3, open point 46): every gate closes (the node-wide
         * one locked, each lobby's scoped secret wiped) and a member Ready with no check in flight
         * says unready reason 3, so the host never counts a seat the new setting has not opened. */
        if (!arg(cmd, 12, 1, &v) || v.data[0] > GZ_MEMBER_SIGNING_WHEN_UNLOCKED) return np_command_result(out, cmd, 400, "bad_request");
        c->cfg.member_signing = (gz_member_signing_t)v.data[0];
        c->unlocked = 0;
        if ((st = gates_changed(c, 0, out)) != GZ_OK) return st;   /* RULE-NODE:SET_CLOSES_GATES */
        if (c->cfg.member_signing == GZ_MEMBER_SIGNING_AUTO && (st = gates_changed(c, 1, out)) != GZ_OK) return st;
        return np_command_result(out, cmd, 200, NULL);
#ifdef GZ_TEST_KINDS
    case 0x7e86: /* the stand-in's outcome from now on: 12 outcome (u8), 14 delay (u32, ms) */
        if (!arg(cmd, 12, 1, &v) || v.data[0] < GZ_TEST_SIGN_FUNDING || v.data[0] > GZ_TEST_SIGN_UNFINISHED)
            return np_command_result(out, cmd, 400, "bad_request");
        c->cfg.test_sign_outcome = v.data[0];
        if (arg(cmd, 14, 4, &v)) c->cfg.test_sign_delay_ms = gz_get_u32(v.data);
        return np_command_result(out, cmd, 200, NULL);
    case GZ_CMD_LOBBY_OPEN: return cmd_open(c, cmd, out);
    case GZ_CMD_LOBBY_JOIN: return cmd_join(c, cmd, out);
#else
    case GZ_CMD_LOBBY_OPEN:
    case GZ_CMD_LOBBY_JOIN:
        /* A release node without the signing engine (no secp256k1 context)
         * hosts and joins nothing: a lobby that could start a round nobody
         * signs must not open. Refused, not an error. */
        if (!c->sign_on) return np_command_result(out, cmd, 503, "signing_unavailable");   /* RULE-NODE:NO_ENGINE_NO_LOBBY */
        return code == GZ_CMD_LOBBY_OPEN ? cmd_open(c, cmd, out) : cmd_join(c, cmd, out);
#endif
    case GZ_CMD_LOBBY_READY:
    case GZ_CMD_LOBBY_UNREADY:
    case GZ_CMD_LOBBY_LEAVE: want_host = 0; break;
    case GZ_CMD_LOBBY_SET_VALUES:
    case GZ_CMD_LOBBY_REMOVE:
    case GZ_CMD_LOBBY_CANCEL: want_host = 1; break;
    default: return np_command_result(out, cmd, 404, "unknown_command");
    }
    /* A lobby left out at this start: its keys are not given (H1). */
    if (arg(cmd, 12, 32, &scope) && lobby_slot_by_scope(c, scope.data) < 0 && left_out_by_scope(c, scope.data) >= 0)
        return np_command_result(out, cmd, 503, "no_key");
    if (!arg(cmd, 12, 32, &scope) || (i = lobby_slot_by_scope(c, scope.data)) < 0 || c->slots[i].host != want_host)
        return np_command_result(out, cmd, 404, "no_such_lobby");
    slot_t *s = &c->slots[i];
    c->lc.code = code;
    c->lc.refused = 0;
    c->lc.a.data = NULL;
    c->lc.a.len = 0;
    if (code == GZ_CMD_LOBBY_REMOVE && !arg(cmd, 14, 33, &c->lc.a)) return np_command_result(out, cmd, 400, "bad_request");
    if (code == GZ_CMD_LOBBY_SET_VALUES &&
        (!arg(cmd, 14, 0, &c->lc.a) || c->lc.a.len == 0 || c->lc.a.len % 8 || c->lc.a.len > 8 * GZ_TERMS_MAX_ADJ))
        return np_command_result(out, cmd, 400, "bad_request");
    /* "Ready" given with the passphrase opens that lobby's gate (AT_JOIN): the
     * program has handed the key port the scoped secret before the command. */
    int opened = 0, rebound = 0, had = s->gate_have;
    uint8_t old_secret[32] = {0}, old_digest[32] = {0}, fresh[32];
    if (code == GZ_CMD_LOBBY_READY && c->cfg.member_signing == GZ_MEMBER_SIGNING_AT_JOIN && arg(cmd, 14, 1, &v) &&
        v.data[0] == 1) {
        /* AT_JOIN (12.2): the lobby's factory key is derived now, and only now, and bound to the
         * values digest the person reviewed, which the ready carries (record 16, local-api.md 14.2's
         * seen_current_digest): values that changed since the screen open nothing (review A of PR
         * 52, L5). The key hook gives the key for that digest alone. */
        if (c->sign_on) {
            const gz_lobby_member_t *m = &s->lobby.m;
            gz_bytes_t seen;
            if (!arg(cmd, 16, 32, &seen)) return np_command_result(out, cmd, 400, "bad_request");
            if (!m->have_terms) return np_command_result(out, cmd, 409, "refused_now");
            if (memcmp(seen.data, m->frozen ? m->frozen_digest : m->current_digest, 32) != 0)   /* RULE-NODE:READY_SEEN_DIGEST */
                return np_command_result(out, cmd, 409, "terms_changed");
            if (!c->cfg.keys.secret || c->cfg.keys.secret(c->cfg.keys.ctx, s->key_epoch, s->key_index + 1, fresh) != 1) {
                gz_ls_wipe32(fresh);
                return np_command_result(out, cmd, 503, "no_key");
            }
            memcpy(old_secret, s->gate_secret, 32);
            memcpy(old_digest, s->gate_digest, 32);
            memcpy(s->gate_secret, fresh, 32);
            gz_ls_wipe32(fresh);
            memcpy(s->gate_digest, seen.data, 32);
            s->gate_have = 1;
            rebound = 1;
        }
        opened = !s->gate_open;
        s->gate_open = 1;
        s->gate_flight = 0;
    }
    size_t from = out->count;
    if ((st = gz_c_slot_inline(c, ENG_SLOT0 + i, command_inline, out)) != GZ_OK) { gz_ls_wipe32(old_secret); return st; }
    int refused = c->lc.refused || was_refused(out, from);
    if ((st = gz_ls_after(c, i, out)) != GZ_OK) { gz_ls_wipe32(old_secret); return st; }
    /* A refused ready leaves the gate as it found it: the person's own
     * ready opens it, and there was none (review A of PR 44, L3); a gate that was open keeps the
     * secret and the digest it had (review A of PR 52, L5). */
    if (refused && opened && s->state == SLOT_OPEN) gate_close(c, s);
    else if (refused && rebound && s->state == SLOT_OPEN) {
        memcpy(s->gate_secret, old_secret, 32);
        memcpy(s->gate_digest, old_digest, 32);
        s->gate_have = had;
    }
    gz_ls_wipe32(old_secret);
    return refused ? np_command_result(out, cmd, 409, c->lc.refused ? "bad_values" : "refused_now")
                   : np_command_result(out, cmd, 200, NULL);
}
