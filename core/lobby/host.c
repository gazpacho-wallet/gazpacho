/* The host side of the lobby: messages.md section 6, terms.md 8, LOBBY.md.
 *
 * Records (journal.md section 9), every integer big-endian:
 *   LOBBY_OPENED   u16 len, outer, outer_sig 64, u16 len, current, current_sig 64
 *   TERMS_VERSION  u16 len, current, current_sig 64
 *   SEAT           ckey 33, fkey 33, bind_f 64, bind_c 64, state u8, min_members u16,
 *                  ready_version u32, join_seq u64, u16 len, the seat's latest ready
 *   FREEZE         check_id 32, version u32, digest 32, u16 len, the ready_check
 *   START_SENT     check_id 32, budget u64 (Unix ms the signing budget began),
 *                  u16 n, n x (ckey 33, u16 len, start)
 *   LOBBY_STATE    state u8 (Open after a retry, Funding, Active; Funding or
 *                  Active may follow LOBBY_ENDED: a creation the signing engine
 *                  completed stands)
 *   LOBBY_ENDED    state u8, reason u16, u16 len, cancel */
#include "lobby_internal.h"
#include <string.h>

#define SEAT_REC (33 + 33 + 64 + 64 + 1 + 2 + 4 + 8 + 2 + GZ_LOBBY_MAX_SAVED_MSG)
#define START_HDR 42                  /* check_id, budget, n */

static uint64_t now_ms(const gz_lobby_host_t *h) { return h->ports.clock.now_ms(h->ports.clock.ctx); }

static gz_lobby_conn_t *conn_of(gz_lobby_host_t *h, uint64_t peer)
{
    int i;
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++)
        if (h->conns[i].used && h->conns[i].peer_id == peer) return &h->conns[i];
    return NULL;
}

static gz_lobby_seat_t *seat_of(gz_lobby_host_t *h, const uint8_t key[33])
{
    uint16_t i;
    for (i = 0; i < h->n_seats; i++)
        if (memcmp(h->seats[i].ckey, key, 33) == 0) return &h->seats[i];
    return NULL;
}

static gz_lobby_conn_t *conn_for(gz_lobby_host_t *h, const gz_lobby_seat_t *s)
{
    int i;
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++)
        if (h->conns[i].used && memcmp(h->conns[i].key, s->ckey, 33) == 0) return &h->conns[i];
    return NULL;
}

/* Ready for the latest (or frozen) values. */
static int is_ready(const gz_lobby_host_t *h, const gz_lobby_seat_t *s)
{
    return s->state == GZ_SEAT_READY && s->ready_version == h->values.version;
}

static int is_in(const gz_lobby_seat_t *s) { return s->state == GZ_SEAT_JOINED || s->state == GZ_SEAT_READY; }

/* A chosen seat that left while Signing stays seated for the transport until
 * the round is resolved (review A, S1). */
static int held(const gz_lobby_host_t *h, const gz_lobby_seat_t *s)
{
    return h->state == GZ_LOBBY_SIGNING && s->chosen && !is_in(s);
}

static int seated(const gz_lobby_host_t *h, const gz_lobby_seat_t *s) { return s && (is_in(s) || held(h, s)); }

static int conn_seated(gz_lobby_host_t *h, const gz_lobby_conn_t *c) { return seated(h, seat_of(h, c->key)); }

/* `rule`: count for the start rule only the seats that are ready, connected
 * and whose min_members a start could ever meet (review A, F6). */
static void counts(const gz_lobby_host_t *h, uint16_t *joined, uint16_t *ready, uint32_t *ready_conn)
{
    uint16_t i;
    *joined = *ready = 0;
    *ready_conn = 0;
    for (i = 0; i < h->n_seats; i++) {
        const gz_lobby_seat_t *s = &h->seats[i];
        if (is_in(s)) (*joined)++;
        if (is_ready(h, s)) {
            (*ready)++;
            if (conn_for((gz_lobby_host_t *)h, s) && s->min_members <= h->terms.target) (*ready_conn)++;
        }
    }
}

static uint8_t seat_state_shown(const gz_lobby_host_t *h, const gz_lobby_seat_t *s)
{
    if (!s) return GZ_SEAT_NONE;
    if (h->state >= GZ_LOBBY_SIGNING && s->start_len && is_in(s)) return s->chosen ? GZ_SEAT_CHOSEN : GZ_SEAT_NOT_CHOSEN;
    if (s->state == GZ_SEAT_READY && !is_ready(h, s)) return GZ_SEAT_JOINED;
    return s->state;
}

/* lobby_status for one connection; `seat` -1 shows the seat as it is. */
static size_t build_status(gz_lobby_host_t *h, const gz_lobby_conn_t *c, int seat, int with_reason,
                           uint16_t reason, int lobby_state, uint8_t buf[GZ_LOBBY_STATUS_MAX])
{
    gz_lobby_enc_t e;
    uint16_t joined, ready;
    uint32_t rc;
    const gz_lobby_seat_t *s = seat_of(h, c->key);
    counts(h, &joined, &ready, &rc);
    gz_lobby_enc_start(&e, buf, GZ_LOBBY_STATUS_MAX, GZ_KIND_LOBBY_STATUS, h->scope);
    gz_lobby_enc_u8(&e, 2, (uint8_t)lobby_state);
    gz_lobby_enc_u8(&e, 4, seat >= 0 ? (uint8_t)seat : lobby_state ? seat_state_shown(h, s) : GZ_SEAT_NONE);
    gz_lobby_enc_u32(&e, 6, lobby_state ? h->values.version : 0);
    gz_lobby_enc_u16(&e, 8, lobby_state ? joined : 0);
    gz_lobby_enc_u16(&e, 10, lobby_state ? ready : 0);
    if (with_reason) gz_lobby_enc_u16(&e, 13, reason);
    return gz_lobby_enc_done(&e);
}

static gz_status_t send_status(gz_lobby_host_t *h, gz_lobby_conn_t *c, int seat, int with_reason, uint16_t reason,
                               int lobby_state, gz_action_list_t *out)
{
    c->status_len = build_status(h, c, seat, with_reason, reason, lobby_state, c->status_msg);
    c->status_ms = now_ms(h);
    c->status_pending = 0;
    return gz_la_send(out, c->peer_id, c->status_msg, c->status_len);
}

static int with_reason(const gz_lobby_host_t *h) { return h->state >= GZ_LOBBY_CANCELLED && h->end_reason; }

static gz_status_t status(gz_lobby_host_t *h, gz_lobby_conn_t *c, gz_action_list_t *out)
{
    return send_status(h, c, -1, with_reason(h), h->end_reason, h->state, out);
}

/* lobby_status to every seat whose view changed, at most once a second per
 * seat (messages.md 6.7): a seat that already holds this status gets nothing. */
static gz_status_t broadcast(gz_lobby_host_t *h, gz_action_list_t *out)
{
    int i, wait = 0;
    uint64_t now = now_ms(h);
    uint8_t now_msg[GZ_LOBBY_STATUS_MAX];
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++) {
        gz_lobby_conn_t *c = &h->conns[i];
        gz_lobby_seat_t *s;
        size_t n;
        if (!c->used || !(s = seat_of(h, c->key)) || !(is_in(s) || h->state >= GZ_LOBBY_CANCELLED)) continue;
        n = build_status(h, c, -1, with_reason(h), h->end_reason, h->state, now_msg);
        if (n == c->status_len && memcmp(now_msg, c->status_msg, n) == 0) { c->status_pending = 0; continue; }
        if (now - c->status_ms >= 1000 || now < c->status_ms) TRY(status(h, c, out));
        else { c->status_pending = 1; wait = 1; }
    }
    return wait ? gz_la_timer(out, GZ_LOBBY_TIMER_STATUS, 1000) : GZ_OK;
}

static gz_status_t save_seat(const gz_lobby_seat_t *s, gz_action_list_t *out)
{
    uint8_t r[SEAT_REC];
    size_t n = 0;
    memcpy(r, s->ckey, 33); memcpy(r + 33, s->fkey, 33);
    memcpy(r + 66, s->bind_f, 64); memcpy(r + 130, s->bind_c, 64);
    r[194] = s->state;
    gz_lw_put(r + 195, s->min_members, 2);
    gz_lw_put(r + 197, s->ready_version, 4);
    gz_lw_put(r + 201, s->join_seq, 8);
    n = 209 + gz_la_put_blob(r + 209, s->ready_msg, s->ready_len);
    return gz_la_save1(out, GZ_REC_SEAT, r, n);
}

/* GZ_NOTE_SEATED for a seat's key. */
static gz_status_t seated_note(const gz_lobby_seat_t *s, int on, gz_action_list_t *out)
{
    uint8_t b[34];
    memcpy(b, s->ckey, 33);
    b[33] = (uint8_t)(on ? 1 : 0);
    return gz_la_notify(out, GZ_NOTE_SEATED, b, 34);
}

/* The round is resolved (the lobby leaves Signing): seats held for it are
 * released. Call before the state changes. */
static gz_status_t release_held(gz_lobby_host_t *h, gz_action_list_t *out)
{
    uint16_t i;
    for (i = 0; i < h->n_seats; i++)
        if (held(h, &h->seats[i])) TRY(seated_note(&h->seats[i], 0, out));
    return GZ_OK;
}

/* --------------------------------------------------------- connections */

/* Idle and unseated connections (review A, F7). Every connection must say
 * hello or join within GZ_LOBBY_IDLE_MS; one whose key holds no seat is
 * closed GZ_LOBBY_UNSEATED_MS after it came up. With `close` 0 this only
 * finds the next due time; with 1 it also closes what is due. Returns the
 * delay to the next due time, 0 if nothing is watched. */
static uint64_t idle_scan(gz_lobby_host_t *h, int close, gz_status_t *st, gz_action_list_t *out)
{
    uint64_t now = now_ms(h), next = 0, age, limit;
    int i;
    for (i = 0; i < GZ_LOBBY_MAX_CONNS && *st == GZ_OK; i++) {
        gz_lobby_conn_t *c = &h->conns[i];
        int on = c->used && !c->closed && conn_seated(h, c);
        if (!c->used || c->closed || (on && c->spoke)) continue;
        if (now < c->connected_ms) c->connected_ms = now;         /* the clock went back */
        age = now - c->connected_ms;
        limit = c->spoke ? GZ_LOBBY_UNSEATED_MS : GZ_LOBBY_IDLE_MS;
        if (age >= limit) {
            if (!close) { next = 1; continue; }
            c->closed = 1;                                       /* closed once */
            *st = gz_la_refuse(out, c->peer_id, c->spoke ? "no seat" : "no hello");
            continue;
        }
        if (!next || limit - age < next) next = limit - age;
    }
    return next;
}

static gz_status_t idle_sweep(gz_lobby_host_t *h, gz_action_list_t *out)
{
    gz_status_t st = GZ_OK;
    uint64_t next;
    h->idle_armed = 0;
    next = idle_scan(h, 1, &st, out);
    TRY(st);
    if (!next) return GZ_OK;
    h->idle_armed = 1;
    return gz_la_timer(out, GZ_LOBBY_TIMER_IDLE, next);
}

/* Set the idle timer if something is watched and it is not set. */
static gz_status_t idle_arm(gz_lobby_host_t *h, gz_action_list_t *out)
{
    gz_status_t st = GZ_OK;
    uint64_t next;
    if (h->idle_armed) return GZ_OK;
    next = idle_scan(h, 0, &st, out);
    if (!next) return GZ_OK;
    h->idle_armed = 1;
    return gz_la_timer(out, GZ_LOBBY_TIMER_IDLE, next);
}

/* Drop a connection whose key holds no seat, to make room: one that has said
 * nothing yet first, then the oldest, as the transport does (review B, B7).
 * Never a seated one. 1 if one was dropped. */
static int evict_unseated(gz_lobby_host_t *h, gz_status_t *st, gz_action_list_t *out)
{
    int i, best = -1;
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++) {
        gz_lobby_conn_t *c = &h->conns[i];
        if (!c->used || conn_seated(h, c)) continue;
        if (best < 0 || (!c->spoke && h->conns[best].spoke) ||
            (c->spoke == h->conns[best].spoke && c->seq < h->conns[best].seq))
            best = i;
    }
    if (best < 0) return 0;
    h->conns[best].used = 0;                          /* its later events are ignored */
    *st = gz_la_refuse(out, h->conns[best].peer_id, "busy");
    return 1;
}

/* `*seat_event` is set when the connecting key's seat is Ready: only then may
 * the start rule be applied (decision 8). */
static gz_status_t on_connected(gz_lobby_host_t *h, const gz_lobby_input_t *in, int *seat_event, gz_action_list_t *out)
{
    gz_lobby_seat_t *s;
    gz_status_t st = GZ_OK;
    int i, unseated = 0, used = 0, on;
    if (!in->peer_key || conn_of(h, in->peer_id)) return GZ_ERR_ARGUMENT;   /* contract v2: ids are not reused */
    s = seat_of(h, in->peer_key);
    on = seated(h, s);
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++)
        if (h->conns[i].used) { used++; if (!conn_seated(h, &h->conns[i])) unseated++; }
    /* A key without a seat takes one of GZ_LOBBY_MAX_UNSEATED places; a full
     * table makes room by dropping the oldest unseated connection, never a
     * seated one. */
    if ((!on && unseated >= GZ_LOBBY_MAX_UNSEATED) || used == GZ_LOBBY_MAX_CONNS) {
        if (!evict_unseated(h, &st, out)) return gz_la_refuse(out, in->peer_id, "busy");
        TRY(st);
    }
    for (i = 0; i < GZ_LOBBY_MAX_CONNS && h->conns[i].used; i++) {}
    if (i == GZ_LOBBY_MAX_CONNS) return gz_la_refuse(out, in->peer_id, "busy");
    memset(&h->conns[i], 0, sizeof h->conns[i]);
    h->conns[i].used = 1;
    h->conns[i].peer_id = in->peer_id;
    memcpy(h->conns[i].key, in->peer_key, 33);
    h->conns[i].connected_ms = now_ms(h);
    h->conns[i].seq = ++h->conn_seq;
    TRY(idle_arm(h, out));
    /* Only a seat's reconnect can change the start rule (decision 8): the
     * host pushes nothing on a stranger's connect (contract v2 rule 6). */
    if (!s || !is_ready(h, s)) return GZ_OK;
    h->rule_dirty = 1;
    h->seat_epoch++;
    *seat_event = 1;
    return GZ_OK;
}

/* A saved change of seat state, within the limit of 10 in 10 minutes
 * (messages.md 6). 1 if made, 0 if the limit ignores it. `force` is for the
 * host's own decisions (removal, a failed attempt). */
static int seat_change(gz_lobby_host_t *h, gz_lobby_seat_t *s, uint8_t state, int force, gz_status_t *st,
                       gz_action_list_t *out)
{
    uint64_t now = now_ms(h);
    int was = seated(h, s);
    if (!force && s->n_changes == 10 && now - s->changes[s->changes_at] < 600000 && now >= s->changes[s->changes_at])
        return 0;
    s->changes[s->changes_at] = now;
    s->changes_at = (uint8_t)((s->changes_at + 1) % 10);
    if (s->n_changes < 10) s->n_changes++;
    s->state = state;
    if (state != GZ_SEAT_READY || h->state != GZ_LOBBY_READY_CHECK) s->answered = 0;
    h->rule_dirty = 1;
    h->seat_epoch++;
    *st = save_seat(s, out);
    if (*st == GZ_OK && was != seated(h, s)) *st = seated_note(s, seated(h, s), out);   /* after its save */
    if (*st == GZ_OK && !seated(h, s)) *st = idle_arm(h, out);                        /* now unseated */
    return 1;
}

static gz_status_t send_terms(gz_lobby_host_t *h, uint64_t peer, gz_action_list_t *out)
{
    gz_lobby_enc_t e;
    uint8_t buf[GZ_TERMS_OUTER_MAX + GZ_TERMS_CURRENT_MAX + 256];
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_TERMS_OFFER, h->scope);
    gz_lobby_enc_record(&e, 2, h->outer, h->outer_len);
    gz_lobby_enc_record(&e, 4, h->outer_sig, 64);
    gz_lobby_enc_record(&e, 6, h->current, h->current_len);
    gz_lobby_enc_record(&e, 8, h->current_sig, 64);
    return gz_la_send(out, peer, buf, gz_lobby_enc_done(&e));
}

/* ------------------------------------------------------- start and end */

static gz_status_t end_lobby(gz_lobby_host_t *h, uint16_t reason, gz_action_list_t *out)
{
    gz_lobby_enc_t e;
    uint8_t r[8 + GZ_LOBBY_MAX_SAVED_MSG];
    int i;
    gz_lobby_enc_start(&e, h->cancel_msg, sizeof h->cancel_msg, GZ_KIND_CANCEL, h->scope);
    gz_lobby_enc_u16(&e, 2, reason);
    h->cancel_len = gz_lobby_enc_sign(&e, &h->crypto, GZ_LOBBY_KEY_HOST);
    if (!h->cancel_len) return GZ_ERR_ARGUMENT;
    r[0] = (uint8_t)(reason == 3 ? GZ_LOBBY_FAILED : GZ_LOBBY_CANCELLED);
    gz_lw_put(r + 1, reason, 2);
    TRY(gz_la_save1(out, GZ_REC_LOBBY_ENDED, r, 3 + gz_la_put_blob(r + 3, h->cancel_msg, h->cancel_len)));
    TRY(release_held(h, out));
    h->state = r[0];
    h->end_reason = reason;
    h->check_open = 0;
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++)
        if (h->conns[i].used && seat_of(h, h->conns[i].key))
            TRY(gz_la_send(out, h->conns[i].peer_id, h->cancel_msg, h->cancel_len));
    TRY(broadcast(h, out));
    return h->signing.cancel ? h->signing.cancel(h->signing.ctx, h->scope, reason, out) : GZ_OK;
}

static gz_status_t ready_check(gz_lobby_host_t *h, gz_action_list_t *out)
{
    gz_lobby_enc_t e;
    uint8_t r[72 + GZ_LOBBY_MAX_SAVED_MSG];
    uint16_t i;
    h->ports.random.fill(h->ports.random.ctx, GZ_RANDOM_ORDINARY, h->check_id, 32);
    gz_lobby_enc_start(&e, h->check_msg, sizeof h->check_msg, GZ_KIND_READY_CHECK, h->scope);
    gz_lobby_enc_record(&e, 2, h->check_id, 32);
    gz_lobby_enc_u32(&e, 4, h->values.version);
    gz_lobby_enc_record(&e, 6, h->current_digest, 32);
    gz_lobby_enc_u32(&e, 8, h->terms.ready_window_ms);
    h->check_len = gz_lobby_enc_sign(&e, &h->crypto, GZ_LOBBY_KEY_HOST);
    if (!h->check_len) return GZ_ERR_ARGUMENT;
    if (!h->frozen) {                                 /* terms.md 8: saved before the first check */
        h->frozen = 1;
        memcpy(r, h->check_id, 32);
        gz_lw_put(r + 32, h->values.version, 4);
        memcpy(r + 36, h->current_digest, 32);
        TRY(gz_la_save1(out, GZ_REC_FREEZE, r, 68 + gz_la_put_blob(r + 68, h->check_msg, h->check_len)));
    }
    h->state = GZ_LOBBY_READY_CHECK;
    h->check_open = 1;
    h->rule_dirty = 0;
    h->failed_epoch = h->seat_epoch;                  /* changes from here on allow the next check */
    for (i = 0; i < h->n_seats; i++) {
        gz_lobby_seat_t *s = &h->seats[i];
        gz_lobby_conn_t *c = conn_for(h, s);
        s->answered = 0;
        s->chosen = 0;
        s->start_len = 0;
        if (is_in(s) && c) TRY(gz_la_send(out, c->peer_id, h->check_msg, h->check_len));
    }
    TRY(gz_la_timer(out, GZ_LOBBY_TIMER_WINDOW, h->terms.ready_window_ms));
    return broadcast(h, out);
}

static gz_status_t apply_rule(gz_lobby_host_t *h, int at_deadline, gz_action_list_t *out)
{
    uint16_t j, r;
    uint32_t rc;
    int rule;
    if (h->state != GZ_LOBBY_OPEN || (!h->rule_dirty && !at_deadline)) return GZ_OK;
    /* After a check without a start, the next needs a seat event in between
     * (or the deadline): an unsatisfiable set never loops (review A, F6). */
    if (!at_deadline && h->check_failed && h->seat_epoch == h->failed_epoch) return GZ_OK;
    counts(h, &j, &r, &rc);
    rule = gz_lobby_start_rule(h->terms.target, h->terms.minimum, h->terms.deadline, now_ms(h) / 1000, rc);
    if (rule == GZ_RULE_CHECK) return ready_check(h, out);
    if (rule == GZ_RULE_CANCEL) return end_lobby(h, 1, out);
    return GZ_OK;
}

/* The chosen seats, in order of joining, to the signing engine. */
static gz_status_t handoff(gz_lobby_host_t *h, int resume, gz_action_list_t *out)
{
    gz_lobby_participant_t ps[GZ_LOBBY_MAX_SEATS + 1];
    const gz_lobby_seat_t *order[GZ_LOBBY_MAX_SEATS];
    gz_lobby_handoff_t ho;
    int i, j, k = 0;
    if (!h->signing.begin) return GZ_OK;
    for (i = 0; i < h->n_seats; i++)
        if (h->seats[i].chosen) {
            for (j = k; j > 0 && order[j - 1]->join_seq > h->seats[i].join_seq; j--) order[j] = order[j - 1];
            order[j] = &h->seats[i];
            k++;
        }
    memset(&ho, 0, sizeof ho);
    ps[0] = h->me;
    for (i = 0; i < k; i++) {
        memcpy(ps[i + 1].factory_key, order[i]->fkey, 33);
        memcpy(ps[i + 1].contribution_key, order[i]->ckey, 33);
        memcpy(ps[i + 1].bind_by_factory, order[i]->bind_f, 64);
        memcpy(ps[i + 1].bind_by_contribution, order[i]->bind_c, 64);
    }
    ho.role = 1;
    ho.resume = resume;
    ho.scope = h->scope;
    ho.pinned_key = h->terms.host_key;
    ho.outer = h->outer; ho.outer_len = h->outer_len; ho.outer_sig = h->outer_sig;
    ho.current = h->current; ho.current_len = h->current_len; ho.current_sig = h->current_sig;
    ho.current_digest = h->current_digest;
    ho.version = h->values.version;
    ho.check_id = h->check_id;
    ho.terms = &h->terms;
    ho.values = &h->values;
    ho.signers = (uint16_t)(k + 1);
    ho.participants = ps;
    ho.n_participants = (uint16_t)(k + 1);
    gz_la_shape(&h->terms, (uint16_t)k, &ho);
    if (!ho.n_levels) return GZ_ERR_ARGUMENT;
    return h->signing.begin(h->signing.ctx, &ho, out);
}

static gz_status_t budget_timer(gz_lobby_host_t *h, gz_action_list_t *out)
{
    uint64_t now = now_ms(h), end = h->budget_ms + h->terms.signing_budget_ms;
    return gz_la_timer(out, GZ_LOBBY_TIMER_BUDGET, now < end ? end - now : 0);
}

/* The ready window closed: choose the signers (messages.md 6.9). */
static gz_status_t window_closed(gz_lobby_host_t *h, gz_action_list_t *out)
{
    const gz_lobby_seat_t *order[GZ_LOBBY_MAX_SEATS];
    uint16_t mins[GZ_LOBBY_MAX_SEATS];
    int idx[GZ_LOBBY_MAX_SEATS], n = 0, k, i, j, first;
    uint8_t rec[START_HDR + GZ_LOBBY_MAX_SEATS * (35 + GZ_LOBBY_MAX_SAVED_MSG)];
    gz_lobby_enc_t e;                 /* function scope: no ASan use-after-scope calls (isolation) */
    size_t rn;
    if (h->state != GZ_LOBBY_READY_CHECK) return GZ_OK;
    h->check_open = 0;
    for (i = 0; i < h->n_seats; i++)                 /* answered and still ready, in order of joining */
        if (h->seats[i].answered && is_ready(h, &h->seats[i])) {
            /* A min_members above the target can never be met: such a seat is
             * left out before the cut, so it takes no one's place (review B, B5). */
            if (h->seats[i].min_members > h->terms.target) continue;
            for (j = n; j > 0 && order[j - 1]->join_seq > h->seats[i].join_seq; j--) order[j] = order[j - 1];
            order[j] = &h->seats[i];
            n++;
        }
    for (i = 0; i < n; i++) mins[i] = order[i]->min_members;
    k = gz_lobby_choose(h->terms.target, h->terms.minimum, mins, n, idx);
    if (k < 0) {
        h->state = GZ_LOBBY_OPEN;
        h->check_failed = 1;
        if (now_ms(h) / 1000 >= h->terms.deadline) return end_lobby(h, 1, out);
        /* The rule again at once: a seat event during the check allows a new
         * one; without one the failed-check guard in apply_rule waits for it
         * (decision 8; review A, F6). */
        h->rule_dirty = 1;
        TRY(broadcast(h, out));
        return apply_rule(h, 0, out);
    }
    first = h->budget_ms == 0;
    if (first) h->budget_ms = now_ms(h);              /* terms.md 3: one budget for all attempts */
    memcpy(rec, h->check_id, 32);
    gz_lw_put(rec + 32, h->budget_ms, 8);
    gz_lw_put(rec + 40, (uint64_t)n, 2);
    rn = START_HDR;
    for (i = 0; i < n; i++) {
        gz_lobby_seat_t *s = (gz_lobby_seat_t *)order[i];
        s->chosen = 0;
        for (j = 0; j < k; j++) if (idx[j] == i) s->chosen = 1;
        gz_lobby_enc_start(&e, s->start_msg, sizeof s->start_msg, GZ_KIND_START, h->scope);
        gz_lobby_enc_record(&e, 2, h->check_id, 32);
        gz_lobby_enc_u8(&e, 4, s->chosen ? 1 : 2);
        gz_lobby_enc_u16(&e, 6, (uint16_t)(k + 1));
        s->start_len = gz_lobby_enc_sign(&e, &h->crypto, GZ_LOBBY_KEY_HOST);
        if (!s->start_len) return GZ_ERR_ARGUMENT;
        memcpy(rec + rn, s->ckey, 33);
        rn += 33 + gz_la_put_blob(rec + rn + 33, s->start_msg, s->start_len);
    }
    TRY(gz_la_save1(out, GZ_REC_START_SENT, rec, rn));   /* saved before the first start */
    h->state = GZ_LOBBY_SIGNING;
    h->check_failed = 0;
    if (first) TRY(budget_timer(h, out));
    for (i = 0; i < n; i++) {
        gz_lobby_conn_t *c = conn_for(h, order[i]);
        if (c) TRY(gz_la_send(out, c->peer_id, order[i]->start_msg, order[i]->start_len));
    }
    TRY(broadcast(h, out));
    return handoff(h, 0, out);
}

/* ------------------------------------------------------------ messages */

/* The hello limits of a member key (messages.md 6.1: per link, counted
 * across its connections, so reconnecting does not reset them). The table
 * keeps the 64 most recent keys; a key pushed out starts afresh. */
static gz_lobby_link_t *link_of(gz_lobby_host_t *h, const uint8_t key[33])
{
    int i, best = 0;
    for (i = 0; i < GZ_LOBBY_MAX_LINKS; i++)
        if (h->links[i].used && memcmp(h->links[i].key, key, 33) == 0) return &h->links[i];
    for (i = 0; i < GZ_LOBBY_MAX_LINKS; i++) {
        if (!h->links[i].used) { best = i; break; }
        if (h->links[i].hello_ms < h->links[best].hello_ms) best = i;
    }
    memset(&h->links[best], 0, sizeof h->links[best]);
    h->links[best].used = 1;
    memcpy(h->links[best].key, key, 33);
    return &h->links[best];
}

static gz_status_t on_hello(gz_lobby_host_t *h, gz_lobby_conn_t *c, const gz_lobby_msg_t *m,
                            gz_action_list_t *out)
{
    static const uint8_t zero[32];
    uint64_t now = now_ms(h);
    gz_lobby_seat_t *s;
    gz_lobby_link_t *l = link_of(h, c->key);
    if (l->answered && now - l->hello_ms < 1000 && now >= l->hello_ms) {
        if (l->ignored == 0 || now - l->window_ms >= 600000 || now < l->window_ms) {
            l->window_ms = now;                       /* a new 10-minute window */
            l->ignored = 0;
        }
        if (++l->ignored > 20) return gz_la_refuse(out, c->peer_id, "too many hello");
        return GZ_OK;
    }
    l->answered = 1;
    l->hello_ms = now;
    if (memcmp(m->scope, zero, 32) == 0) {
        if (now / 1000 != h->zero_hello_window) { h->zero_hello_window = now / 1000; h->zero_hello_count = 0; }
        if (h->zero_hello_count >= 4) return GZ_OK;
        h->zero_hello_count++;
        return h->cfg.listed && h->state != GZ_LOBBY_UNKNOWN ? send_terms(h, c->peer_id, out) : GZ_OK;
    }
    if (memcmp(m->scope, h->scope, 32) != 0 || h->state == GZ_LOBBY_UNKNOWN)
        return send_status(h, c, -1, 0, 0, GZ_LOBBY_UNKNOWN, out);
    TRY(send_terms(h, c->peer_id, out));
    TRY(status(h, c, out));
    s = seat_of(h, c->key);
    if (s && h->state == GZ_LOBBY_SIGNING && s->chosen && s->start_len && is_in(s))
        TRY(gz_la_send(out, c->peer_id, s->start_msg, s->start_len));
    if (s && h->cancel_len) TRY(gz_la_send(out, c->peer_id, h->cancel_msg, h->cancel_len));
    return GZ_OK;
}

/* Creations (messages.md 6): a bucket of `target` creations, refilled at one
 * a second, so that a burst of honest joins passes and the average stays one
 * a second (review A, S5). Memory only: a restart starts full. */
static int creation_due(gz_lobby_host_t *h, uint64_t now)
{
    uint64_t cap = (uint64_t)h->terms.target * 1000;
    if (!h->credit_at_ms) h->create_credit_ms = cap;
    else if (now > h->credit_at_ms) h->create_credit_ms += now - h->credit_at_ms;
    if (h->create_credit_ms > cap) h->create_credit_ms = cap;
    h->credit_at_ms = now ? now : 1;
    return h->create_credit_ms >= 1000;
}

static gz_status_t join_refused(gz_lobby_host_t *h, gz_lobby_conn_t *c, int invalid, gz_action_list_t *out)
{
    if (invalid ? ++c->bad_joins >= GZ_LOBBY_BAD_JOINS : ++c->refused_joins >= GZ_LOBBY_REFUSED_JOINS) {
        c->closed = 1;
        return gz_la_refuse(out, c->peer_id, "too many joins");
    }
    return invalid ? send_status(h, c, GZ_SEAT_REFUSED, 1, 5, h->state, out)
                   : send_status(h, c, GZ_SEAT_REFUSED, 0, 0, h->state, out);   /* closed, full, or a limit */
}

static gz_status_t on_join(gz_lobby_host_t *h, gz_lobby_conn_t *c, const gz_lobby_msg_t *m,
                           gz_action_list_t *out)
{
    gz_lobby_seat_t *s = seat_of(h, c->key);
    uint8_t b[32];
    uint16_t i, taken = 0;
    uint64_t now = now_ms(h);
    gz_status_t st = GZ_OK;
    int bad;
    if (s && is_in(s)) {                              /* a duplicate, or another factory key */
        if (memcmp(s->fkey, m->factory_key, 33) == 0) return status(h, c, out);
        return join_refused(h, c, 1, out);
    }
    if (s && s->state == GZ_SEAT_REMOVED) return status(h, c, out);
    /* A seat chosen in the running attempt keeps the keys it was chosen with
     * until the round is resolved, also after its leave: it cannot join again
     * with new keys, so the signing engine is never given other participants
     * under one check (review B, B1). It may join again after the outcome. */
    if (s && h->state == GZ_LOBBY_SIGNING && s->chosen) return join_refused(h, c, 0, out);
    /* The cheap conditions first, before any signature (review A, F8). Open;
     * or, with standby seats, while a check or an attempt runs, so that late
     * arrivals can fill a gap (owner decision 10; LOBBY.md "standbys"). */
    for (i = 0; i < h->n_seats; i++) if (is_in(&h->seats[i])) taken++;
    if ((h->state != GZ_LOBBY_OPEN &&
         !(h->cfg.standbys && (h->state == GZ_LOBBY_READY_CHECK || h->state == GZ_LOBBY_SIGNING))) ||
        taken >= h->terms.target + h->cfg.standbys || c->joins >= 1 || h->created >= 4u * h->terms.target ||
        !creation_due(h, now) || (!s && h->n_seats >= GZ_LOBBY_MAX_SEATS))
        return join_refused(h, c, 0, out);
    gz_lobby_binding(h->scope, m->factory_key, c->key, b);
    bad = !h->crypto.point_ok(h->crypto.ctx, m->factory_key) ||
          memcmp(m->factory_key, h->me.factory_key, 33) == 0 || memcmp(m->factory_key, h->terms.host_key, 33) == 0 ||
          memcmp(c->key, h->me.factory_key, 33) == 0 || memcmp(c->key, h->terms.host_key, 33) == 0 ||
          memcmp(m->factory_key, c->key, 33) == 0;
    for (i = 0; i < h->n_seats && !bad; i++) {
        const gz_lobby_seat_t *o = &h->seats[i];
        if (o != s && is_in(o) && (memcmp(o->fkey, m->factory_key, 33) == 0 || memcmp(o->ckey, m->factory_key, 33) == 0 ||
                                   memcmp(o->fkey, c->key, 33) == 0))
            bad = 1;
    }
    bad = bad || h->crypto.verify(h->crypto.ctx, m->factory_key, b, m->bind_by_factory) != 1 ||
          h->crypto.verify(h->crypto.ctx, c->key, b, m->bind_by_contribution) != 1;
    if (bad) return join_refused(h, c, 1, out);
    if (!s) {
        s = &h->seats[h->n_seats++];
        memset(s, 0, sizeof *s);
        memcpy(s->ckey, c->key, 33);
    }
    memcpy(s->fkey, m->factory_key, 33);
    memcpy(s->bind_f, m->bind_by_factory, 64);
    memcpy(s->bind_c, m->bind_by_contribution, 64);
    s->ready_len = 0;
    s->ready_version = 0;
    s->min_members = 0;
    s->start_len = 0;
    s->chosen = 0;
    s->join_seq = ++h->next_seq;
    c->joins++;
    h->created++;
    h->create_credit_ms -= 1000;
    seat_change(h, s, GZ_SEAT_JOINED, 1, &st, out);
    TRY(st);
    TRY(status(h, c, out));
    return broadcast(h, out);
}

static gz_status_t on_ready(gz_lobby_host_t *h, gz_lobby_conn_t *c, const uint8_t *raw, size_t len,
                            const gz_lobby_msg_t *m, gz_action_list_t *out)
{
    gz_lobby_seat_t *s = seat_of(h, c->key);
    gz_lobby_seat_t before;           /* function scope: no ASan use-after-scope calls (isolation) */
    gz_status_t st = GZ_OK;
    uint16_t mins = m->has_min_members ? m->min_members : 0;
    if (!gz_la_verified(&h->crypto, raw, m, c->key)) return gz_la_refuse(out, c->peer_id, "bad signature");
    if (!s || !is_in(s) || h->state > GZ_LOBBY_SIGNING || (h->state == GZ_LOBBY_SIGNING && s->chosen))
        return status(h, c, out);
    if (m->version == h->values.version && memcmp(m->current_digest, h->current_digest, 32) == 0 &&
        len <= sizeof s->ready_msg) {
        if (!is_ready(h, s) || s->min_members != mins) {
            /* Applied whole or not at all: a change the limit refuses leaves
             * memory as the saved seat (review A, F5). */
            before = *s;
            s->ready_version = h->values.version;
            s->min_members = mins;
            memcpy(s->ready_msg, raw, len);
            s->ready_len = len;
            if (!seat_change(h, s, GZ_SEAT_READY, 0, &st, out)) *s = before;
            TRY(st);
        }
        if (h->check_open && m->has_check_id && memcmp(m->check_id, h->check_id, 32) == 0 && is_ready(h, s) &&
            s->min_members == mins)
            s->answered = 1;
    }   /* an older version: the seat is shown as Joined, nothing is saved */
    TRY(status(h, c, out));
    TRY(broadcast(h, out));
    return apply_rule(h, 0, out);
}

static gz_status_t on_unready_leave(gz_lobby_host_t *h, gz_lobby_conn_t *c, const gz_lobby_msg_t *m,
                                    gz_action_list_t *out)
{
    gz_lobby_seat_t *s = seat_of(h, c->key);
    gz_status_t st = GZ_OK;
    uint8_t want = m->kind == GZ_KIND_LEAVE ? GZ_SEAT_LEFT : GZ_SEAT_JOINED;
    int in_round = h->state == GZ_LOBBY_SIGNING && s && s->chosen;
    if (s && is_in(s) && s->state != want &&
        !(m->kind == GZ_KIND_UNREADY && h->state >= GZ_LOBBY_SIGNING && s->chosen)) {
        /* Never limited: a move that takes the seat out is always applied, and
         * a chosen seat's leave always reaches the signing engine (review B,
         * B6). Only a move into Ready counts against the limit. */
        seat_change(h, s, want, 1, &st, out);
        TRY(st);
        if (in_round && want == GZ_SEAT_LEFT && h->signing.member_left)
            TRY(h->signing.member_left(h->signing.ctx, h->scope, s->ckey, out));
    }
    TRY(status(h, c, out));
    return broadcast(h, out);
}

gz_status_t gz_lobby_host_handle(gz_lobby_host_t *h, const gz_lobby_input_t *in, gz_action_list_t *out)
{
    gz_lobby_conn_t *c;
    gz_lobby_msg_t m;
    int code;
    if (!h || !in || !out) return GZ_ERR_ARGUMENT;
    switch (in->kind) {
    case GZ_LIN_CONNECTED:
        code = 0;
        TRY(on_connected(h, in, &code, out));
        return code ? apply_rule(h, 0, out) : GZ_OK;   /* a stranger's connect starts nothing */
    case GZ_LIN_DISCONNECTED:
        if ((c = conn_of(h, in->peer_id)) != NULL) c->used = 0;
        return GZ_OK;
    case GZ_LIN_TIMER:
        if (in->timer_id == GZ_LOBBY_TIMER_WINDOW) return window_closed(h, out);
        if (in->timer_id == GZ_LOBBY_TIMER_IDLE) return idle_sweep(h, out);
        if (in->timer_id == GZ_LOBBY_TIMER_STATUS) return broadcast(h, out);
        if (in->timer_id == GZ_LOBBY_TIMER_BUDGET && h->budget_ms && h->state >= GZ_LOBBY_OPEN &&
            h->state <= GZ_LOBBY_SIGNING) {
            /* Once a round is handed over, the signing engine alone owns the
             * budget (GZ_LOBBY_ROUND_FAILED): this timer covers the phases
             * before a hand-off and never cancels a round in Signing (review
             * B, B3). A retry sets it again. */
            if (h->state == GZ_LOBBY_SIGNING) return GZ_OK;
            if (now_ms(h) < h->budget_ms + h->terms.signing_budget_ms) return budget_timer(h, out);
            return end_lobby(h, 3, out);              /* terms.md 3: the budget is spent */
        }
        if (in->timer_id == GZ_LOBBY_TIMER_DEADLINE && h->state == GZ_LOBBY_OPEN) {
            uint64_t now = now_ms(h), at = h->terms.deadline * 1000;
            if (now < at) return gz_la_timer(out, GZ_LOBBY_TIMER_DEADLINE, at - now);
            return apply_rule(h, 1, out);
        }
        return GZ_OK;
    case GZ_LIN_MESSAGE:
        break;
    default:
        return GZ_ERR_ARGUMENT;
    }
    if (!(c = conn_of(h, in->peer_id)) || c->closed || !in->bytes) return GZ_OK;
    code = gz_lobby_decode(in->bytes, in->len, &m);
    if (code == GZ_DEC_REFUSE) { c->closed = 1; return gz_la_refuse(out, c->peer_id, "malformed"); }
    if (code == GZ_DEC_BADTAG && !c->warned) {
        uint8_t w[64];
        c->warned = 1;
        return gz_la_send(out, c->peer_id, w, gz_lobby_warning("unknown protocol", w, sizeof w));
    }
    if (code != GZ_DEC_OK) return GZ_OK;
    if (m.kind == GZ_KIND_HELLO || m.kind == GZ_KIND_JOIN) c->spoke = 1;
    switch (m.kind) {
    case GZ_KIND_HELLO: return on_hello(h, c, &m, out);
    case GZ_KIND_JOIN: case GZ_KIND_READY: case GZ_KIND_UNREADY: case GZ_KIND_LEAVE: break;
    default: c->closed = 1; return gz_la_refuse(out, c->peer_id, "wrong direction");
    }
    if (memcmp(m.scope, h->scope, 32) != 0 || h->state == GZ_LOBBY_UNKNOWN) {
        c->closed = 1;
        return gz_la_refuse(out, c->peer_id, "unknown lobby");
    }
    if (m.kind == GZ_KIND_JOIN) return on_join(h, c, &m, out);
    if (m.kind == GZ_KIND_READY) return on_ready(h, c, in->bytes, in->len, &m, out);
    return on_unready_leave(h, c, &m, out);
}

/* ------------------------------------------------------- set up, restore */

gz_status_t gz_lobby_host_init(gz_lobby_host_t *h, const gz_ports_t *ports, const gz_lobby_crypto_t *crypto,
                               const gz_lobby_signing_t *signing, const gz_lobby_host_config_t *cfg)
{
    if (!h || !ports || !crypto || !cfg || !crypto->verify || !crypto->sign || !crypto->point_ok ||
        !ports->random.fill || !ports->clock.now_ms)
        return GZ_ERR_ARGUMENT;
    memset(h, 0, sizeof *h);
    h->ports = *ports;
    h->crypto = *crypto;
    if (signing) h->signing = *signing;
    h->cfg = *cfg;
    return GZ_OK;
}

/* Take the records as the host's own: decode and check them as a member does
 * (core/tree's policy), with a host key that is a point. */
static int adopt(gz_lobby_host_t *h, const uint8_t *outer, size_t olen, const uint8_t *cur, size_t clen)
{
    gz_terms_outer_t t;
    gz_terms_current_t v;
    uint8_t od[32], cd[32];
    if (!outer || !cur || olen > GZ_TERMS_OUTER_MAX || clen > GZ_TERMS_CURRENT_MAX ||
        !gz_la_decode_terms(outer, olen, cur, clen, &t, od, &v, cd) ||
        h->crypto.point_ok(h->crypto.ctx, t.host_key) != 1 || t.target + h->cfg.standbys > GZ_LOBBY_MAX_SEATS)
        return 0;
    if (outer != h->outer) memcpy(h->outer, outer, olen);
    h->outer_len = olen;
    memcpy(h->current, cur, clen);
    h->current_len = clen;
    h->terms = t;
    h->values = v;
    memcpy(h->scope, od, 32);
    memcpy(h->current_digest, cd, 32);
    return 1;
}

static gz_status_t self_bind(gz_lobby_host_t *h)
{
    uint8_t b[32];
    memcpy(h->me.factory_key, h->cfg.factory_key, 33);
    memcpy(h->me.contribution_key, h->terms.host_key, 33);
    gz_lobby_binding(h->scope, h->me.factory_key, h->me.contribution_key, b);
    if (h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_FACTORY, b, h->me.bind_by_factory) != 1 ||
        h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_HOST, b, h->me.bind_by_contribution) != 1)
        return GZ_ERR_ARGUMENT;
    return GZ_OK;
}

static gz_status_t deadline_timer(gz_lobby_host_t *h, gz_action_list_t *out)
{
    uint64_t now = now_ms(h), at = h->terms.deadline * 1000;
    return gz_la_timer(out, GZ_LOBBY_TIMER_DEADLINE, now < at ? at - now : 0);
}

gz_status_t gz_lobby_host_open(gz_lobby_host_t *h, const uint8_t *outer, size_t outer_len,
                               const uint8_t *current, size_t current_len, gz_action_list_t *out)
{
    uint8_t r[GZ_TERMS_OUTER_MAX + GZ_TERMS_CURRENT_MAX + 140];
    size_t n;
    if (!h || !out || h->state != GZ_LOBBY_UNKNOWN || !adopt(h, outer, outer_len, current, current_len))
        return GZ_ERR_ARGUMENT;
    if (h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_HOST, h->scope, h->outer_sig) != 1 ||
        h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_HOST, h->current_digest, h->current_sig) != 1 ||
        h->crypto.verify(h->crypto.ctx, h->terms.host_key, h->scope, h->outer_sig) != 1)
        return GZ_ERR_ARGUMENT;                       /* host_key is not the key the port signs with */
    TRY(self_bind(h));
    n = gz_la_put_blob(r, h->outer, h->outer_len);
    memcpy(r + n, h->outer_sig, 64); n += 64;
    n += gz_la_put_blob(r + n, h->current, h->current_len);
    memcpy(r + n, h->current_sig, 64); n += 64;
    h->state = GZ_LOBBY_OPEN;
    TRY(gz_la_save1(out, GZ_REC_LOBBY_OPENED, r, n));
    return deadline_timer(h, out);
}

gz_status_t gz_lobby_host_restore(gz_lobby_host_t *h, const gz_record_t *rec)
{
    const uint8_t *p, *a, *b;
    size_t len, at = 0, an, bn;
    gz_lobby_seat_t *s;
    gz_lobby_msg_t m;
    uint16_t n, i;
    if (!h || !rec) return GZ_ERR_ARGUMENT;
    p = rec->bytes.data;
    len = rec->bytes.len;
    switch (rec->type) {
    case GZ_REC_LOBBY_OPENED:
        if (!gz_la_get_blob(p, len, &at, &a, &an) || len - at < 64) return GZ_ERR_CORRUPT;
        at += 64;
        if (!gz_la_get_blob(p, len, &at, &b, &bn) || len - at != 64 || !adopt(h, a, an, b, bn)) return GZ_ERR_CORRUPT;
        memcpy(h->outer_sig, a + an, 64);
        memcpy(h->current_sig, p + at, 64);
        h->state = GZ_LOBBY_OPEN;
        return self_bind(h) == GZ_OK ? GZ_OK : GZ_ERR_CORRUPT;
    case GZ_REC_TERMS_VERSION:
        if (!gz_la_get_blob(p, len, &at, &b, &bn) || len - at != 64 || !adopt(h, h->outer, h->outer_len, b, bn))
            return GZ_ERR_CORRUPT;
        memcpy(h->current_sig, p + at, 64);
        return GZ_OK;
    case GZ_REC_SEAT:
        if (len < 211) return GZ_ERR_CORRUPT;
        at = 209;
        if (!gz_la_get_blob(p, len, &at, &a, &an) || at != len || an > GZ_LOBBY_MAX_SAVED_MSG) return GZ_ERR_CORRUPT;
        if (!(s = seat_of(h, p))) {
            if (h->n_seats >= GZ_LOBBY_MAX_SEATS) return GZ_ERR_CORRUPT;
            s = &h->seats[h->n_seats++];
            memset(s, 0, sizeof *s);
            memcpy(s->ckey, p, 33);
            h->created++;
        }
        /* Each creation took the next join_seq, so the largest one restored is
         * the number of seats ever created, rejoins included (messages.md 6). */
        /* The keys of a seat chosen in the running attempt never change (B1). */
        if (h->state == GZ_LOBBY_SIGNING && s->chosen && memcmp(s->fkey, p + 33, 33) != 0) return GZ_ERR_CORRUPT;
        memcpy(s->fkey, p + 33, 33); memcpy(s->bind_f, p + 66, 64); memcpy(s->bind_c, p + 130, 64);
        s->state = p[194];
        s->min_members = (uint16_t)gz_lw_get(p + 195, 2);
        s->ready_version = (uint32_t)gz_lw_get(p + 197, 4);
        s->join_seq = gz_lw_get(p + 201, 8);
        if (s->join_seq > h->next_seq) h->next_seq = s->join_seq;
        if (s->join_seq > h->created) h->created = s->join_seq;
        memcpy(s->ready_msg, a, an);
        s->ready_len = an;
        return GZ_OK;
    case GZ_REC_FREEZE:
        if (!gz_la_freeze_ok(p, len) || gz_lw_get(p + 32, 4) != h->values.version ||
            memcmp(p + 36, h->current_digest, 32) != 0)
            return GZ_ERR_CORRUPT;
        h->frozen = 1;
        return GZ_OK;
    case GZ_REC_START_SENT:
        if (len < START_HDR || (n = (uint16_t)gz_lw_get(p + 40, 2)) == 0) return GZ_ERR_CORRUPT;
        memcpy(h->check_id, p, 32);
        h->budget_ms = gz_lw_get(p + 32, 8);
        at = START_HDR;
        for (i = 0; i < h->n_seats; i++) { h->seats[i].chosen = 0; h->seats[i].start_len = 0; }
        for (i = 0; i < n; i++) {
            if (len - at < 33 || !(s = seat_of(h, p + at))) return GZ_ERR_CORRUPT;
            at += 33;
            if (!gz_la_get_blob(p, len, &at, &a, &an) || an > GZ_LOBBY_MAX_SAVED_MSG ||
                gz_lobby_decode(a, an, &m) != GZ_DEC_OK || m.kind != GZ_KIND_START || memcmp(m.check_id, p, 32) != 0)
                return GZ_ERR_CORRUPT;
            memcpy(s->start_msg, a, an);
            s->start_len = an;
            s->chosen = m.role == 1;
        }
        if (at != len || !h->budget_ms) return GZ_ERR_CORRUPT;
        h->state = GZ_LOBBY_SIGNING;
        return GZ_OK;
    case GZ_REC_LOBBY_STATE:
        if (len != 1 || (p[0] != GZ_LOBBY_OPEN && p[0] != GZ_LOBBY_FUNDING && p[0] != GZ_LOBBY_ACTIVE))
            return GZ_ERR_CORRUPT;
        if (p[0] != GZ_LOBBY_OPEN) { h->end_reason = 0; h->cancel_len = 0; }   /* a creation stands (B3) */
        if (p[0] == GZ_LOBBY_OPEN)
            for (i = 0; i < h->n_seats; i++) { h->seats[i].chosen = 0; h->seats[i].start_len = 0; }
        h->state = p[0];
        return GZ_OK;
    case GZ_REC_LOBBY_ENDED:
        if (len < 5) return GZ_ERR_CORRUPT;
        at = 3;
        if (!gz_la_get_blob(p, len, &at, &a, &an) || at != len || an > GZ_LOBBY_MAX_SAVED_MSG ||
            (p[0] != GZ_LOBBY_CANCELLED && p[0] != GZ_LOBBY_FAILED))
            return GZ_ERR_CORRUPT;
        h->state = p[0];
        h->end_reason = (uint16_t)gz_lw_get(p + 1, 2);
        memcpy(h->cancel_msg, a, an);
        h->cancel_len = an;
        return GZ_OK;
    default:
        return GZ_OK;                                 /* another engine's record */
    }
}

gz_status_t gz_lobby_host_resume(gz_lobby_host_t *h, gz_action_list_t *out)
{
    uint16_t i;
    if (!h || !out) return GZ_ERR_ARGUMENT;
    if (h->state == GZ_LOBBY_READY_CHECK) h->state = GZ_LOBBY_OPEN;  /* never saved: a check is not resumed */
    h->rule_dirty = 1;
    h->idle_armed = 0;                                /* timers do not survive a restart */
    for (i = 0; i < h->n_seats; i++)                  /* seats again, before any member reconnects */
        if (seated(h, &h->seats[i])) TRY(seated_note(&h->seats[i], 1, out));
    if (h->budget_ms && h->state >= GZ_LOBBY_OPEN && h->state <= GZ_LOBBY_SIGNING) TRY(budget_timer(h, out));
    /* The deadline in Signing too: after a retry the lobby is Open again and
     * still ends at its deadline (review B, B4). */
    if (h->state == GZ_LOBBY_OPEN || h->state == GZ_LOBBY_SIGNING) TRY(deadline_timer(h, out));
    if (h->state == GZ_LOBBY_SIGNING) return handoff(h, 1, out);   /* the saved start, again (F3) */
    return GZ_OK;
}

/* ------------------------------------------------------------ commands */

gz_status_t gz_lobby_host_set_values(gz_lobby_host_t *h, const uint64_t *values, uint8_t n,
                                     gz_action_list_t *out)
{
    gz_terms_current_t v;
    uint8_t cur[GZ_TERMS_CURRENT_MAX], r[GZ_TERMS_CURRENT_MAX + 70], sig[64];
    size_t cn, rn;
    uint8_t k;
    int i;
    if (!h || !values || !out || n != h->values.n_values || h->values.version == 0xffffffffu) return GZ_ERR_ARGUMENT;
    if (h->state != GZ_LOBBY_OPEN || h->frozen) return gz_la_cmd_refused(out, GZ_CMD_SET_VALUES, h->state);
    v = h->values;
    v.version++;
    for (k = 0; k < n; k++) v.val[k].value = values[k];
    cn = gz_terms_encode_current(&v, cur, sizeof cur);
    if (!cn || !adopt(h, h->outer, h->outer_len, cur, cn)) return GZ_ERR_ARGUMENT;   /* outside the ranges */
    if (h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_HOST, h->current_digest, sig) != 1) return GZ_ERR_ARGUMENT;
    memcpy(h->current_sig, sig, 64);
    rn = gz_la_put_blob(r, cur, cn);
    memcpy(r + rn, sig, 64);
    TRY(gz_la_save1(out, GZ_REC_TERMS_VERSION, r, rn + 64));  /* never two values under one version */
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++) {
        gz_lobby_seat_t *s;
        if (h->conns[i].used && (s = seat_of(h, h->conns[i].key)) && is_in(s))
            TRY(send_terms(h, h->conns[i].peer_id, out));
    }
    return broadcast(h, out);
}

gz_status_t gz_lobby_host_remove(gz_lobby_host_t *h, const uint8_t ckey[33], gz_action_list_t *out)
{
    gz_lobby_seat_t *s;
    gz_lobby_conn_t *c;
    gz_status_t st = GZ_OK;
    if (!h || !ckey || !out) return GZ_ERR_ARGUMENT;
    if ((h->state != GZ_LOBBY_OPEN && h->state != GZ_LOBBY_READY_CHECK) || !(s = seat_of(h, ckey)) || !is_in(s))
        return gz_la_cmd_refused(out, GZ_CMD_REMOVE, h->state);
    seat_change(h, s, GZ_SEAT_REMOVED, 1, &st, out);
    TRY(st);
    if ((c = conn_for(h, s)) != NULL) TRY(status(h, c, out));
    return broadcast(h, out);
}

gz_status_t gz_lobby_host_cancel(gz_lobby_host_t *h, uint16_t reason, gz_action_list_t *out)
{
    if (!h || !out || reason < 1 || reason > 3) return GZ_ERR_ARGUMENT;
    if (h->state < GZ_LOBBY_OPEN || h->state > GZ_LOBBY_SIGNING) return gz_la_cmd_refused(out, GZ_CMD_CANCEL, h->state);
    return end_lobby(h, reason, out);
}

gz_status_t gz_lobby_host_round_result(gz_lobby_host_t *h, int outcome, const uint8_t *failed, size_t n_failed,
                                       gz_action_list_t *out)
{
    uint8_t st8;
    size_t i;
    gz_status_t st = GZ_OK;
    if (!h || !out || outcome < GZ_LOBBY_ROUND_FUNDING || outcome > GZ_LOBBY_ROUND_FAILED || (n_failed && !failed))
        return GZ_ERR_ARGUMENT;
    if (outcome == GZ_LOBBY_ROUND_FUNDING || outcome == GZ_LOBBY_ROUND_ACTIVE) {
        /* A creation the signing engine completed is always taken, also after
         * the lobby ended by a cancel (review B, B3); it never goes back. */
        if (!h->budget_ms || h->state < GZ_LOBBY_SIGNING || h->state == GZ_LOBBY_ACTIVE ||
            (outcome == GZ_LOBBY_ROUND_FUNDING && h->state == GZ_LOBBY_FUNDING))
            return gz_la_cmd_refused(out, GZ_CMD_ROUND_RESULT, h->state);
        st8 = outcome == GZ_LOBBY_ROUND_FUNDING ? GZ_LOBBY_FUNDING : GZ_LOBBY_ACTIVE;
        TRY(gz_la_save1(out, GZ_REC_LOBBY_STATE, &st8, 1));
        TRY(release_held(h, out));
        h->state = st8;
        h->end_reason = 0;                            /* the creation stands: no cancel is shown or resent */
        h->cancel_len = 0;
        return broadcast(h, out);
    }
    if (h->state != GZ_LOBBY_SIGNING && !(outcome == GZ_LOBBY_ROUND_FAILED && h->state == GZ_LOBBY_FUNDING))
        return gz_la_cmd_refused(out, GZ_CMD_ROUND_RESULT, h->state);
    if (outcome == GZ_LOBBY_ROUND_FAILED) return end_lobby(h, 3, out);
    for (i = 0; i < n_failed; i++) {                  /* no-shows must ready again */
        gz_lobby_seat_t *s = seat_of(h, failed + 33 * i);
        if (s && is_in(s)) {
            seat_change(h, s, GZ_SEAT_JOINED, 1, &st, out);
            TRY(st);
        }
    }
    st8 = GZ_LOBBY_OPEN;
    TRY(gz_la_save1(out, GZ_REC_LOBBY_STATE, &st8, 1));
    TRY(release_held(h, out));
    for (i = 0; i < h->n_seats; i++) { h->seats[i].chosen = 0; h->seats[i].start_len = 0; }
    h->state = GZ_LOBBY_OPEN;
    h->rule_dirty = 1;
    /* Before the next hand-off the budget is the lobby's again (B3), and the
     * deadline still ends the lobby (B4). */
    TRY(budget_timer(h, out));
    if (now_ms(h) / 1000 < h->terms.deadline) TRY(deadline_timer(h, out));
    TRY(broadcast(h, out));
    return apply_rule(h, now_ms(h) / 1000 >= h->terms.deadline, out);
}
