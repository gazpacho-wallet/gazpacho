/* The host side of the lobby: messages.md section 6, terms.md 8, LOBBY.md.
 *
 * Records (journal.md section 9): TLV streams, field 2 the scope in every
 * one (composite-node.md 7.3); integers big-endian; a saved message is an
 * envelope (tag, kind, scope, records):
 *   LOBBY_OPENED   4 outer, 6 outer_sig (64), 8 current, 10 current_sig (64)
 *   TERMS_VERSION  4 current, 6 current_sig (64)
 *   SEAT           4 ckey (33), 6 fkey (33), 8 bind_f (64), 10 bind_c (64),
 *                  12 state (u8), 14 min_members (u16), 16 ready_version (u32),
 *                  18 join_seq (u64), 20 the seat's latest ready (absent: none)
 *   FREEZE         4 check_id (32), 6 version (u32), 8 digest (32), 10 the ready_check
 *   START_SENT     4 check_id (32), 6 budget (u64, Unix ms the signing budget
 *                  began), 8 one or more of (ckey 33, u16 len, start)
 *   LOBBY_STATE    4 state (u8: Open after a retry, Funding, Active; Funding
 *                  or Active may follow LOBBY_ENDED: a creation the signing
 *                  engine completed stands)
 *   LOBBY_ENDED    4 state (u8), 6 reason (u16), 8 the cancel (absent: none) */
#include "lobby_internal.h"
#include <string.h>

static uint64_t now_ms(const gz_lobby_host_t *h) { return h->ports.clock.now_ms(h->ports.clock.ctx); }

static gz_lobby_conn_t *conn_of(gz_lobby_host_t *h, const gz_link_t *link)
{
    int i;
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++)
        if (h->conns[i].used && memcmp(h->conns[i].key, link->remote.key, 33) == 0) return &h->conns[i];
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
    uint16_t joined, ready;
    uint32_t rc;
    const gz_lobby_seat_t *s = seat_of(h, c->key);
    counts(h, &joined, &ready, &rc);
    return gz_la_status(h->scope, (uint8_t)lobby_state,
                        seat >= 0 ? (uint8_t)seat : lobby_state ? seat_state_shown(h, s) : GZ_SEAT_NONE,
                        lobby_state ? h->values.version : 0, lobby_state ? joined : 0, lobby_state ? ready : 0,
                        with_reason, reason, buf);
}

static gz_status_t send_status(gz_lobby_host_t *h, gz_lobby_conn_t *c, int seat, int with_reason, uint16_t reason,
                               int lobby_state, gz_action_list_t *out)
{
    c->status_len = build_status(h, c, seat, with_reason, reason, lobby_state, c->status_msg);
    c->status_ms = now_ms(h);
    c->status_pending = 0;
    return gz_la_send(out, &c->link, c->status_msg, c->status_len);
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

static gz_status_t save_seat(const gz_lobby_host_t *h, const gz_lobby_seat_t *s, gz_action_list_t *out)
{
    uint8_t r[GZ_LOBBY_REC_MAX_SEAT];
    gz_lr_t w;
    gz_lr_start(&w, r, sizeof r, h->scope);
    gz_lr_put(&w, 4, s->ckey, 33);
    gz_lr_put(&w, 6, s->fkey, 33);
    gz_lr_put(&w, 8, s->bind_f, 64);
    gz_lr_put(&w, 10, s->bind_c, 64);
    gz_lr_int(&w, 12, s->state, 1);
    gz_lr_int(&w, 14, s->min_members, 2);
    gz_lr_int(&w, 16, s->ready_version, 4);
    gz_lr_int(&w, 18, s->join_seq, 8);
    if (s->ready_len) gz_lr_put(&w, 20, s->ready_msg, s->ready_len);
    return gz_lr_save(out, GZ_REC_SEAT, &w);
}

/* SET_SEATED for a seat's key. */
static gz_status_t seated_note(const gz_lobby_seat_t *s, int on, gz_action_list_t *out)
{
    return gz_la_seated(out, s->ckey, on);
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

/* A connection the node part bound to this lobby (composite-node.md section
 * 3). Which connections without a seat stay is the node part's rule; the
 * table here has the node part's size, so it is never full. `*seat_event` is
 * set when the connecting key's seat is Ready: only then may the start rule
 * be applied (decision 8). */
static gz_status_t on_connected(gz_lobby_host_t *h, const gz_lobby_input_t *in, int *seat_event, gz_action_list_t *out)
{
    gz_lobby_seat_t *s = seat_of(h, in->link.remote.key);
    gz_lobby_conn_t *c = conn_of(h, &in->link);
    int i;
    if (!c) {                                         /* a key has one connection: a second replaces it */
        for (i = 0; i < GZ_LOBBY_MAX_CONNS && h->conns[i].used; i++) {}
        if (i == GZ_LOBBY_MAX_CONNS) return gz_la_refuse(out, &in->link);
        c = &h->conns[i];
    }
    memset(c, 0, sizeof *c);
    c->used = 1;
    c->link = in->link;
    memcpy(c->key, in->link.remote.key, 33);
    /* Only a seat's reconnect can change the start rule (decision 8): the
     * host pushes nothing on a stranger's connect (contract v2 rule 6). */
    if (!s || !is_ready(h, s)) return GZ_OK;
    h->rule_dirty = 1;
    h->seat_epoch++;
    *seat_event = 1;
    return GZ_OK;
}

/* A saved change of seat state, within the limit of 10 in 10 minutes
 * (messages.md 6). 1 if made, 0 if the limit ignores it. `force` 1 is for
 * the host's own decisions (removal, a failed attempt) and for moves out,
 * which are counted but never limited; `force` 2 is a change that is neither
 * limited nor counted: the "locked" unready and the ready after it
 * (composite-node.md 12.2). */
static int seat_change(gz_lobby_host_t *h, gz_lobby_seat_t *s, uint8_t state, int force, gz_status_t *st,
                       gz_action_list_t *out)
{
    uint64_t now = now_ms(h);
    int was = seated(h, s);
    if (!force && s->n_changes == 10 && now - s->changes[s->changes_at] < 600000 && now >= s->changes[s->changes_at])
        return 0;
    if (force != 2) {
        s->changes[s->changes_at] = now;
        s->changes_at = (uint8_t)((s->changes_at + 1) % 10);
        if (s->n_changes < 10) s->n_changes++;
    }
    s->state = state;
    if (state != GZ_SEAT_READY || h->state != GZ_LOBBY_READY_CHECK) s->answered = 0;
    h->rule_dirty = 1;
    h->seat_epoch++;
    *st = save_seat(h, s, out);
    if (*st == GZ_OK && was != seated(h, s)) *st = seated_note(s, seated(h, s), out);   /* after its save */
    return 1;
}

static gz_status_t send_terms(gz_lobby_host_t *h, const gz_link_t *link, gz_action_list_t *out)
{
    gz_lobby_enc_t e;
    uint8_t buf[GZ_TERMS_OUTER_MAX + GZ_TERMS_CURRENT_MAX + 256];
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_TERMS_OFFER, h->scope);
    gz_lobby_enc_record(&e, 2, h->outer, h->outer_len);
    gz_lobby_enc_record(&e, 4, h->outer_sig, 64);
    gz_lobby_enc_record(&e, 6, h->current, h->current_len);
    gz_lobby_enc_record(&e, 8, h->current_sig, 64);
    return gz_la_send(out, link, buf, gz_lobby_enc_done(&e));
}

/* ------------------------------------------------------- start and end */

static int self_bind(gz_lobby_host_t *h);

/* End the lobby with a signed `cancel`. If the port will not sign, the lobby
 * ends all the same, without one: a deadline or a spent budget does not wait
 * for a key (the engine rule), and every seat still learns the end and its
 * reason from `lobby_status`. */
static gz_status_t end_lobby(gz_lobby_host_t *h, uint16_t reason, gz_action_list_t *out)
{
    gz_lobby_enc_t e;
    uint8_t r[GZ_LOBBY_REC_MAX_ENDED];
    gz_lr_t w;
    int i, state = reason == 3 ? GZ_LOBBY_FAILED : GZ_LOBBY_CANCELLED;
    gz_lobby_enc_start(&e, h->cancel_msg, sizeof h->cancel_msg, GZ_KIND_CANCEL, h->scope);
    gz_lobby_enc_u16(&e, 2, reason);
    h->cancel_len = gz_lobby_enc_sign(&e, &h->crypto, GZ_LOBBY_KEY_HOST);
    gz_lr_start(&w, r, sizeof r, h->scope);
    gz_lr_int(&w, 4, (uint64_t)state, 1);
    gz_lr_int(&w, 6, reason, 2);
    if (h->cancel_len) gz_lr_put(&w, 8, h->cancel_msg, h->cancel_len);
    TRY(gz_lr_save(out, GZ_REC_LOBBY_ENDED, &w));
    if (!h->cancel_len) TRY(gz_la_no_key(out, GZ_LOBBY_KEY_HOST));
    TRY(release_held(h, out));
    h->state = state;
    h->end_reason = reason;
    h->check_open = 0;
    for (i = 0; i < GZ_LOBBY_MAX_CONNS && h->cancel_len; i++)
        if (h->conns[i].used && seat_of(h, h->conns[i].key))
            TRY(gz_la_send(out, &h->conns[i].link, h->cancel_msg, h->cancel_len));
    TRY(broadcast(h, out));
    return h->signing.cancel ? h->signing.cancel(h->signing.ctx, h->scope, reason, out) : GZ_OK;
}

static gz_status_t ready_check(gz_lobby_host_t *h, gz_action_list_t *out)
{
    gz_lobby_enc_t e;
    uint8_t r[GZ_LOBBY_REC_MAX_FREEZE];
    gz_lr_t w;
    uint16_t i;
    h->rule_dirty = 0;
    h->ports.random.fill(h->ports.random.ctx, GZ_RANDOM_ORDINARY, h->check_id, 32);
    gz_lobby_enc_start(&e, h->check_msg, sizeof h->check_msg, GZ_KIND_READY_CHECK, h->scope);
    gz_lobby_enc_record(&e, 2, h->check_id, 32);
    gz_lobby_enc_u32(&e, 4, h->values.version);
    gz_lobby_enc_record(&e, 6, h->current_digest, 32);
    gz_lobby_enc_u32(&e, 8, h->terms.ready_window_ms);
    h->check_len = gz_lobby_enc_sign(&e, &h->crypto, GZ_LOBBY_KEY_HOST);
    /* No key, no check: nothing is frozen, saved or sent. The rule is applied
     * again at the next seat event or at the deadline. */
    if (!h->check_len) return gz_la_no_key(out, GZ_LOBBY_KEY_HOST);
    if (!h->frozen) {                                 /* terms.md 8: saved before the first check */
        h->frozen = 1;
        gz_lr_start(&w, r, sizeof r, h->scope);
        gz_lr_put(&w, 4, h->check_id, 32);
        gz_lr_int(&w, 6, h->values.version, 4);
        gz_lr_put(&w, 8, h->current_digest, 32);
        gz_lr_put(&w, 10, h->check_msg, h->check_len);
        TRY(gz_lr_save(out, GZ_REC_FREEZE, &w));
    }
    h->state = GZ_LOBBY_READY_CHECK;
    h->check_open = 1;
    h->window_no++;
    h->failed_epoch = h->seat_epoch;                  /* changes from here on allow the next check */
    for (i = 0; i < h->n_seats; i++) {
        gz_lobby_seat_t *s = &h->seats[i];
        gz_lobby_conn_t *c = conn_for(h, s);
        s->answered = 0;
        s->chosen = 0;
        s->start_len = 0;
        if (is_in(s) && c) TRY(gz_la_send(out, &c->link, h->check_msg, h->check_len));
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
    /* Without the host's own binding there is no round to hand over: the
     * signing engine fails the unfinished attempt of a restarted host
     * anyway (H13). */
    if (!h->bound && !self_bind(h)) return gz_la_no_key(out, GZ_LOBBY_KEY_FACTORY);
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
    ho.budget_end_ms = h->budget_ms + h->terms.signing_budget_ms;
    ho.attempt = 1;
    gz_la_shape(&h->terms, (uint16_t)k, &ho);
    /* The terms' policy gives a shape for every member count (terms.md 4.3):
     * none here is a bug in core/tree or in adopt(). */
    if (!ho.n_levels) return GZ_ERR_BUG;
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
    int idx[GZ_LOBBY_MAX_SEATS], n = 0, k, i, j, first, signed_ok = 1;
    uint8_t rec[GZ_LOBBY_REC_MAX_START_SENT], list[GZ_LOBBY_MAX_SEATS * GZ_LOBBY_START_ITEM];
    gz_lobby_enc_t e;                 /* function scope: no ASan use-after-scope calls (isolation) */
    gz_lr_t w;
    size_t ln = 0;
    if (h->state != GZ_LOBBY_READY_CHECK) return GZ_OK;
    h->check_open = 0;
    memset(mins, 0, sizeof mins);
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
    if (!h->bound && !self_bind(h)) signed_ok = 0;
    /* Every start is signed before anything is saved or changed: a port that
     * will not sign makes this a check that started nobody (the engine rule). */
    for (i = 0; i < n && k >= 0 && signed_ok; i++) {
        gz_lobby_seat_t *s = (gz_lobby_seat_t *)order[i];
        int chosen = 0;
        for (j = 0; j < k; j++) if (idx[j] == i) chosen = 1;
        gz_lobby_enc_start(&e, s->start_msg, sizeof s->start_msg, GZ_KIND_START, h->scope);
        gz_lobby_enc_record(&e, 2, h->check_id, 32);
        gz_lobby_enc_u8(&e, 4, chosen ? 1 : 2);
        gz_lobby_enc_u16(&e, 6, (uint16_t)(k + 1));
        s->start_len = gz_lobby_enc_sign(&e, &h->crypto, GZ_LOBBY_KEY_HOST);
        if (!s->start_len) signed_ok = 0;
    }
    if (k < 0 || !signed_ok) {
        for (i = 0; i < n; i++) ((gz_lobby_seat_t *)order[i])->start_len = 0;
        h->state = GZ_LOBBY_OPEN;
        h->check_failed = 1;
        if (!signed_ok) TRY(gz_la_no_key(out, GZ_LOBBY_KEY_HOST));
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
    for (i = 0; i < n; i++) {
        gz_lobby_seat_t *s = (gz_lobby_seat_t *)order[i];
        s->chosen = 0;
        for (j = 0; j < k; j++) if (idx[j] == i) s->chosen = 1;
        memcpy(list + ln, s->ckey, 33);
        gz_lw_put(list + ln + 33, s->start_len, 2);
        memcpy(list + ln + 35, s->start_msg, s->start_len);
        ln += 35 + s->start_len;
    }
    gz_lr_start(&w, rec, sizeof rec, h->scope);
    gz_lr_put(&w, 4, h->check_id, 32);
    gz_lr_int(&w, 6, h->budget_ms, 8);
    gz_lr_put(&w, 8, list, ln);
    TRY(gz_lr_save(out, GZ_REC_START_SENT, &w));        /* saved before the first start */
    h->state = GZ_LOBBY_SIGNING;
    h->check_failed = 0;
    h->started = 1;
    /* No budget timer here: from the hand-off on the signing engine alone
     * owns the budget (composite-node.md 9.4); the lobby's timer is armed
     * only with no round in flight (a retry). */
    for (i = 0; i < n; i++) {
        gz_lobby_conn_t *c = conn_for(h, order[i]);
        if (c) TRY(gz_la_send(out, &c->link, order[i]->start_msg, order[i]->start_len));
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
    uint64_t now = now_ms(h);
    gz_lobby_seat_t *s;
    gz_lobby_link_t *l = link_of(h, c->key);
    if (l->answered && now - l->hello_ms < 1000 && now >= l->hello_ms) {
        if (l->ignored == 0 || now - l->window_ms >= 600000 || now < l->window_ms) {
            l->window_ms = now;                       /* a new 10-minute window */
            l->ignored = 0;
        }
        if (++l->ignored > 20) { c->closed = 1; return gz_la_refuse(out, &c->link); }
        return GZ_OK;
    }
    l->answered = 1;
    l->hello_ms = now;
    /* The node part routes by scope, so another scope does not come here; if
     * one does, it is answered as unknown. A scope-zero hello is the listing
     * (gz_lobby_host_listing): here it names no lobby and gets no answer, as
     * a lobby_status with a scope of zeros is no message (messages.md 4). */
    if (memcmp(m->scope, h->scope, 32) != 0 || h->state == GZ_LOBBY_UNKNOWN) {
        uint8_t any = 0;
        int i;
        for (i = 0; i < 32; i++) any |= m->scope[i];
        return any ? gz_lobby_host_unknown(&c->link, m->scope, out) : GZ_OK;
    }
    TRY(send_terms(h, &c->link, out));
    TRY(status(h, c, out));
    s = seat_of(h, c->key);
    if (s && h->state == GZ_LOBBY_SIGNING && s->chosen && s->start_len && is_in(s))
        TRY(gz_la_send(out, &c->link, s->start_msg, s->start_len));
    if (s && h->cancel_len) TRY(gz_la_send(out, &c->link, h->cancel_msg, h->cancel_len));
    return GZ_OK;
}

gz_status_t gz_lobby_host_listing(gz_lobby_host_t *h, const gz_link_t *link, gz_action_list_t *out)
{
    uint64_t now;
    if (!h || !link || !out) return GZ_ERR_ARGUMENT;
    if (!h->cfg.listed || h->state < GZ_LOBBY_OPEN || h->state > GZ_LOBBY_SIGNING) return GZ_OK;
    now = now_ms(h);
    if (now / 1000 != h->zero_hello_window) { h->zero_hello_window = now / 1000; h->zero_hello_count = 0; }
    if (h->zero_hello_count >= 4) return GZ_OK;
    h->zero_hello_count++;
    return send_terms(h, link, out);
}

int gz_lobby_host_round_ok(const gz_lobby_host_t *h) { return h && h->started; }

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
        return gz_la_refuse(out, &c->link);
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
    s->locked = 0;
    s->join_seq = ++h->next_seq;
    c->joins++;
    h->created++;
    h->create_credit_ms -= 1000;
    seat_change(h, s, GZ_SEAT_JOINED, 1, &st, out);
    TRY(st);
    TRY(status(h, c, out));
    return broadcast(h, out);
}

static gz_status_t on_ready(gz_lobby_host_t *h, gz_lobby_conn_t *c, const gz_lobby_msg_t *m, gz_action_list_t *out)
{
    gz_lobby_seat_t *s = seat_of(h, c->key);
    gz_lobby_seat_t before;           /* function scope: no ASan use-after-scope calls (isolation) */
    uint8_t env[GZ_LOBBY_MAX_SAVED_MSG];
    size_t len;
    gz_status_t st = GZ_OK;
    uint16_t mins = m->has_min_members ? m->min_members : 0;
    if (!gz_la_verified(&h->crypto, m, c->key)) { c->closed = 1; return gz_la_refuse(out, &c->link); }
    if (!s || !is_in(s) || h->state > GZ_LOBBY_SIGNING || (h->state == GZ_LOBBY_SIGNING && s->chosen))
        return status(h, c, out);
    len = gz_la_env(m->kind, m->scope, m->records, m->records_len, env, sizeof env);
    if (m->version == h->values.version && memcmp(m->current_digest, h->current_digest, 32) == 0 && len) {
        if (!is_ready(h, s) || s->min_members != mins) {
            /* A seat that said "locked" readies again without the change
             * being counted, once per check window (composite-node.md 12.2,
             * F4): a phone restarted often does not lose its seat. */
            int free_pair = s->locked && s->free_window != h->window_no + 1;
            /* Applied whole or not at all: a change the limit refuses leaves
             * memory as the saved seat (review A, F5). */
            before = *s;
            s->ready_version = h->values.version;
            s->min_members = mins;
            memcpy(s->ready_msg, env, len);
            s->ready_len = len;
            if (!seat_change(h, s, GZ_SEAT_READY, free_pair ? 2 : 0, &st, out)) *s = before;
            else {
                if (free_pair) s->free_window = h->window_no + 1;
                s->locked = 0;
            }
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
    int locked = m->kind == GZ_KIND_UNREADY && m->has_reason && m->reason == 3;
    if (s && is_in(s) && s->state != want &&
        !(m->kind == GZ_KIND_UNREADY && h->state >= GZ_LOBBY_SIGNING && s->chosen)) {
        /* Never limited: a move that takes the seat out is always applied, and
         * a chosen seat's leave always reaches the signing engine (review B,
         * B6). Only a move into Ready counts against the limit. A "locked"
         * unready is not even counted while its window's free pair is unused. */
        seat_change(h, s, want, locked && s->free_window != h->window_no + 1 ? 2 : 1, &st, out);
        TRY(st);
        if (in_round && want == GZ_SEAT_LEFT && h->signing.member_left)
            TRY(h->signing.member_left(h->signing.ctx, h->scope, s->ckey, out));
    }
    if (s && locked) s->locked = 1;
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
        if ((c = conn_of(h, &in->link)) != NULL) c->used = 0;
        return GZ_OK;
    case GZ_LIN_TIMER:
        if (in->timer_id == GZ_LOBBY_TIMER_WINDOW) return window_closed(h, out);
        if (in->timer_id == GZ_LOBBY_TIMER_STATUS) return broadcast(h, out);
        if (in->timer_id == GZ_LOBBY_TIMER_BUDGET && h->budget_ms && h->state >= GZ_LOBBY_OPEN &&
            h->state <= GZ_LOBBY_SIGNING) {
            /* Once a round is handed over, the signing engine alone owns the
             * budget (GZ_LOBBY_ROUND_FAILED): this timer covers the phases
             * with no round in flight and never cancels a round in Signing
             * (review B, B3; composite-node.md 9.4). A retry sets it again. */
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
    if (!(c = conn_of(h, &in->link)) || c->closed || !in->scope) return GZ_OK;
    code = gz_lobby_decode(in->msg_kind, in->scope, in->records, in->len, &m);
    if (code == GZ_DEC_REFUSE) { c->closed = 1; return gz_la_refuse(out, &c->link); }
    if (code != GZ_DEC_OK) return GZ_OK;
    switch (m.kind) {
    case GZ_KIND_HELLO: return on_hello(h, c, &m, out);
    case GZ_KIND_JOIN: case GZ_KIND_READY: case GZ_KIND_UNREADY: case GZ_KIND_LEAVE: break;
    default: c->closed = 1; return gz_la_refuse(out, &c->link);   /* the wrong direction */
    }
    if (memcmp(m.scope, h->scope, 32) != 0 || h->state == GZ_LOBBY_UNKNOWN) {
        c->closed = 1;
        return gz_la_refuse(out, &c->link);
    }
    if (m.kind == GZ_KIND_JOIN) return on_join(h, c, &m, out);
    if (m.kind == GZ_KIND_READY) return on_ready(h, c, &m, out);
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

/* The host's own binding, signed with its two keys. 1 if the port signed. */
static int self_bind(gz_lobby_host_t *h)
{
    uint8_t b[32];
    memcpy(h->me.factory_key, h->cfg.factory_key, 33);
    memcpy(h->me.contribution_key, h->terms.host_key, 33);
    gz_lobby_binding(h->scope, h->me.factory_key, h->me.contribution_key, b);
    h->bound = h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_FACTORY, b, h->me.bind_by_factory) == 1 &&
               h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_HOST, b, h->me.bind_by_contribution) == 1;
    return h->bound;
}

/* Undo adopt() and self_bind(): the engine as gz_lobby_host_init left it. */
static void unadopt(gz_lobby_host_t *h)
{
    h->outer_len = h->current_len = 0;
    memset(&h->terms, 0, sizeof h->terms);
    memset(&h->values, 0, sizeof h->values);
    memset(h->scope, 0, 32);
    memset(h->current_digest, 0, 32);
    memset(&h->me, 0, sizeof h->me);
    h->bound = 0;
    memset(h->outer_sig, 0, 64);
    memset(h->current_sig, 0, 64);
}

static gz_status_t deadline_timer(gz_lobby_host_t *h, gz_action_list_t *out)
{
    uint64_t now = now_ms(h), at = h->terms.deadline * 1000;
    return gz_la_timer(out, GZ_LOBBY_TIMER_DEADLINE, now < at ? at - now : 0);
}

gz_status_t gz_lobby_host_open(gz_lobby_host_t *h, const uint8_t *outer, size_t outer_len,
                               const uint8_t *current, size_t current_len, gz_action_list_t *out)
{
    uint8_t r[GZ_LOBBY_REC_MAX_OPENED];
    gz_lr_t w;
    if (!h || !out || h->state != GZ_LOBBY_UNKNOWN || !adopt(h, outer, outer_len, current, current_len))
        return GZ_ERR_ARGUMENT;
    if (h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_HOST, h->scope, h->outer_sig) != 1 ||
        h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_HOST, h->current_digest, h->current_sig) != 1 ||
        h->crypto.verify(h->crypto.ctx, h->terms.host_key, h->scope, h->outer_sig) != 1 || !self_bind(h)) {
        unadopt(h);                                   /* host_key is not the key the port signs with */
        return GZ_ERR_ARGUMENT;
    }
    gz_lr_start(&w, r, sizeof r, h->scope);
    gz_lr_put(&w, 4, h->outer, h->outer_len);
    gz_lr_put(&w, 6, h->outer_sig, 64);
    gz_lr_put(&w, 8, h->current, h->current_len);
    gz_lr_put(&w, 10, h->current_sig, 64);
    h->state = GZ_LOBBY_OPEN;
    TRY(gz_lr_save(out, GZ_REC_LOBBY_OPENED, &w));
    return deadline_timer(h, out);
}

gz_status_t gz_lobby_host_restore(gz_lobby_host_t *h, const gz_record_t *rec)
{
    const uint8_t *p, *a, *b, *x;
    size_t len, at, an, bn;
    gz_lobby_seat_t *s;
    gz_lobby_msg_t m;
    gz_lf_t f;
    uint16_t i;
    uint8_t od[32];
    if (!h || !rec) return GZ_ERR_ARGUMENT;
    if (!gz_lobby_rec_max(rec->type)) return GZ_OK;   /* another engine's record */
    p = rec->bytes.data;
    len = rec->bytes.len;
    /* Every record names its lobby. The first, lobby_opened, sets the scope
     * (the digest of its outer record); the rest must carry it. */
    if (len > gz_lobby_rec_max(rec->type) ||
        !gz_lf_read(p, len, rec->type == GZ_REC_LOBBY_OPENED || h->state == GZ_LOBBY_UNKNOWN ? NULL : h->scope, &f) ||
        !gz_lf_known(rec->type, &f))
        return GZ_ERR_CORRUPT;
    if (rec->type != GZ_REC_LOBBY_OPENED && h->state == GZ_LOBBY_UNKNOWN) return GZ_ERR_CORRUPT;
    switch (rec->type) {
    case GZ_REC_LOBBY_OPENED:
        if (h->state != GZ_LOBBY_UNKNOWN || !gz_lf_blob(&f, 4, GZ_TERMS_OUTER_MAX, &a, &an) ||
            !gz_lf_blob(&f, 8, GZ_TERMS_CURRENT_MAX, &b, &bn) || !gz_lf_fixed(&f, 6, 64) || !gz_lf_fixed(&f, 10, 64))
            return GZ_ERR_CORRUPT;
        gz_terms_outer_digest(a, an, od);
        if (memcmp(od, f.v[1], 32) != 0 || !adopt(h, a, an, b, bn)) return GZ_ERR_CORRUPT;
        memcpy(h->outer_sig, gz_lf_fixed(&f, 6, 64), 64);
        memcpy(h->current_sig, gz_lf_fixed(&f, 10, 64), 64);
        h->state = GZ_LOBBY_OPEN;
        /* The binding is signed again at every start. A port that will not
         * sign now is not corrupt storage: the host goes on, and signs it
         * when it next needs it (window_closed, handoff). */
        (void)self_bind(h);
        return GZ_OK;
    case GZ_REC_TERMS_VERSION:
        if (!gz_lf_blob(&f, 4, GZ_TERMS_CURRENT_MAX, &b, &bn) || !(x = gz_lf_fixed(&f, 6, 64)) ||
            !adopt(h, h->outer, h->outer_len, b, bn))
            return GZ_ERR_CORRUPT;
        memcpy(h->current_sig, x, 64);
        return GZ_OK;
    case GZ_REC_SEAT:
        if (!(p = gz_lf_fixed(&f, 4, 33)) || !gz_lf_fixed(&f, 6, 33) || !gz_lf_fixed(&f, 8, 64) ||
            !gz_lf_fixed(&f, 10, 64) || !gz_lf_fixed(&f, 12, 1) || !gz_lf_fixed(&f, 14, 2) ||
            !gz_lf_fixed(&f, 16, 4) || !gz_lf_fixed(&f, 18, 8))
            return GZ_ERR_CORRUPT;
        a = NULL;
        an = 0;
        if (f.v[10] && !gz_lf_blob(&f, 20, GZ_LOBBY_MAX_SAVED_MSG, &a, &an)) return GZ_ERR_CORRUPT;
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
        if (h->state == GZ_LOBBY_SIGNING && s->chosen && memcmp(s->fkey, f.v[3], 33) != 0) return GZ_ERR_CORRUPT;
        memcpy(s->fkey, f.v[3], 33); memcpy(s->bind_f, f.v[4], 64); memcpy(s->bind_c, f.v[5], 64);
        s->state = f.v[6][0];
        s->min_members = (uint16_t)gz_lw_get(f.v[7], 2);
        s->ready_version = (uint32_t)gz_lw_get(f.v[8], 4);
        s->join_seq = gz_lw_get(f.v[9], 8);
        if (s->join_seq > h->next_seq) h->next_seq = s->join_seq;
        if (s->join_seq > h->created) h->created = s->join_seq;
        if (an) memcpy(s->ready_msg, a, an);
        s->ready_len = an;
        return GZ_OK;
    case GZ_REC_FREEZE:
        if (!gz_la_freeze_ok(&f) || gz_lw_get(f.v[3], 4) != h->values.version ||
            memcmp(f.v[4], h->current_digest, 32) != 0)
            return GZ_ERR_CORRUPT;
        h->frozen = 1;
        return GZ_OK;
    case GZ_REC_START_SENT:
        if (!(x = gz_lf_fixed(&f, 4, 32)) || !gz_lf_fixed(&f, 6, 8) ||
            !gz_lf_blob(&f, 8, GZ_LOBBY_MAX_SEATS * GZ_LOBBY_START_ITEM, &p, &len) || len == 0)
            return GZ_ERR_CORRUPT;
        memcpy(h->check_id, x, 32);
        h->budget_ms = gz_lw_get(f.v[3], 8);
        for (i = 0; i < h->n_seats; i++) { h->seats[i].chosen = 0; h->seats[i].start_len = 0; }
        for (at = 0; at < len;) {
            if (len - at < 35 || !(s = seat_of(h, p + at))) return GZ_ERR_CORRUPT;
            an = (size_t)gz_lw_get(p + at + 33, 2);
            a = p + at + 35;
            if (an > len - at - 35 || an > GZ_LOBBY_MAX_SAVED_MSG || gz_lobby_decode_env(a, an, &m) != GZ_DEC_OK ||
                m.kind != GZ_KIND_START || memcmp(m.check_id, x, 32) != 0 || memcmp(m.scope, h->scope, 32) != 0)
                return GZ_ERR_CORRUPT;
            memcpy(s->start_msg, a, an);
            s->start_len = an;
            s->chosen = m.role == 1;
            at += 35 + an;
        }
        if (!h->budget_ms) return GZ_ERR_CORRUPT;
        h->state = GZ_LOBBY_SIGNING;
        h->started = 1;
        return GZ_OK;
    case GZ_REC_LOBBY_STATE:
        if (!(x = gz_lf_fixed(&f, 4, 1)) || f.v[3] ||
            (x[0] != GZ_LOBBY_OPEN && x[0] != GZ_LOBBY_FUNDING && x[0] != GZ_LOBBY_ACTIVE))
            return GZ_ERR_CORRUPT;
        if (x[0] != GZ_LOBBY_OPEN) { h->end_reason = 0; h->cancel_len = 0; }   /* a creation stands (B3) */
        if (x[0] == GZ_LOBBY_OPEN)
            for (i = 0; i < h->n_seats; i++) { h->seats[i].chosen = 0; h->seats[i].start_len = 0; }
        h->state = x[0];
        return GZ_OK;
    case GZ_REC_LOBBY_ENDED:
        if (!(x = gz_lf_fixed(&f, 4, 1)) || !gz_lf_fixed(&f, 6, 2) || f.v[5] ||
            (x[0] != GZ_LOBBY_CANCELLED && x[0] != GZ_LOBBY_FAILED))
            return GZ_ERR_CORRUPT;
        a = NULL;
        an = 0;
        if (f.v[4] && !gz_lf_blob(&f, 8, GZ_LOBBY_MAX_SAVED_MSG, &a, &an)) return GZ_ERR_CORRUPT;
        h->state = x[0];
        h->end_reason = (uint16_t)gz_lw_get(f.v[3], 2);
        if (an) memcpy(h->cancel_msg, a, an);
        h->cancel_len = an;
        return GZ_OK;
    default:
        return GZ_ERR_CORRUPT;                        /* a member's record in a host's lobby */
    }
}

gz_status_t gz_lobby_host_resume(gz_lobby_host_t *h, gz_action_list_t *out)
{
    uint16_t i;
    if (!h || !out) return GZ_ERR_ARGUMENT;
    if (h->state == GZ_LOBBY_READY_CHECK) h->state = GZ_LOBBY_OPEN;  /* never saved: a check is not resumed */
    h->rule_dirty = 1;
    for (i = 0; i < h->n_seats; i++)                  /* seats again, before any member reconnects */
        if (seated(h, &h->seats[i])) TRY(seated_note(&h->seats[i], 1, out));
    /* The lobby's budget timer only with no round in flight (9.4): in Signing
     * the budget is the signing engine's, and a restarted host's attempt
     * fails there (H13), which sets this timer through the Retry. */
    if (h->budget_ms && h->state == GZ_LOBBY_OPEN) TRY(budget_timer(h, out));
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
    gz_terms_outer_t t;
    uint8_t cur[GZ_TERMS_CURRENT_MAX], r[GZ_LOBBY_REC_MAX_VERSION], sig[64], od[32], cd[32];
    gz_lr_t w;
    size_t cn;
    uint8_t k;
    int i;
    if (!h || !values || !out) return GZ_ERR_ARGUMENT;
    if (h->state != GZ_LOBBY_OPEN || h->frozen) return gz_la_cmd_refused(out, GZ_CMD_SET_VALUES, h->state);
    if (n != h->values.n_values || h->values.version == 0xffffffffu) return GZ_ERR_ARGUMENT;
    v = h->values;
    v.version++;
    for (k = 0; k < n; k++) v.val[k].value = values[k];
    cn = gz_terms_encode_current(&v, cur, sizeof cur);
    /* Checked and signed before anything changes: values outside the ranges,
     * or a port that will not sign, leave the lobby as it was. */
    if (!cn || !gz_la_decode_terms(h->outer, h->outer_len, cur, cn, &t, od, &v, cd)) return GZ_ERR_ARGUMENT;
    if (h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_HOST, cd, sig) != 1) return gz_la_no_key(out, GZ_LOBBY_KEY_HOST);
    if (!adopt(h, h->outer, h->outer_len, cur, cn)) return GZ_ERR_BUG;
    memcpy(h->current_sig, sig, 64);
    gz_lr_start(&w, r, sizeof r, h->scope);
    gz_lr_put(&w, 4, cur, cn);
    gz_lr_put(&w, 6, sig, 64);
    TRY(gz_lr_save(out, GZ_REC_TERMS_VERSION, &w));       /* never two values under one version */
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++) {
        gz_lobby_seat_t *s;
        if (h->conns[i].used && (s = seat_of(h, h->conns[i].key)) && is_in(s))
            TRY(send_terms(h, &h->conns[i].link, out));
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

static gz_status_t save_state(const gz_lobby_host_t *h, uint8_t state, gz_action_list_t *out)
{
    uint8_t r[GZ_LOBBY_REC_MAX_STATE];
    gz_lr_t w;
    gz_lr_start(&w, r, sizeof r, h->scope);
    gz_lr_int(&w, 4, state, 1);
    return gz_lr_save(out, GZ_REC_LOBBY_STATE, &w);
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
        TRY(save_state(h, st8, out));
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
    TRY(save_state(h, st8, out));
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
