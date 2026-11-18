/* The member side of the lobby: messages.md section 6, terms.md 7 to 9.
 *
 * Records (journal.md section 9): TLV streams, field 2 the scope in every
 * one (composite-node.md 7.3); integers big-endian; a saved message is an
 * envelope (tag, kind, scope, records):
 *   TERMS_RECEIVED 4 outer, 6 outer_sig (64), 8 current, 10 current_sig (64)
 *   JOINED         4 the signed join (the key epoch and index are in the
 *                  node part's slot_opened)
 *   READY_SENT     4 the signed ready; or, for an unready, 6 its reason (u16:
 *                  1 conditions, 2 the user's choice, 3 locked)
 *   FREEZE         4 check_id (32), 6 version (u32), 8 digest (32), 10 the ready_check
 *   HOST_FAULT     4 fault (u8), 6 evidence a, 8 evidence b
 *   START_RECEIVED 4 the signed start
 *   LOBBY_ENDED    4 state (u8; 0: no cancel ended it), 6 reason (u16), 8 the
 *                  cancel (absent: none), 10 how (u8, with state 0 only;
 *                  absent: the member left; GZ_LOBBY_END_*: removed, refused
 *                  as invalid, or the terms refused before any seat)
 *   LOBBY_STATE    4 state (u8): the signing engine's outcome, so that a
 *                  restart never hands a finished check to the signing engine
 *                  again: 1 Open (a retry) with 6 the check_id it named (32):
 *                  that check is spent, its start and the answer to it;
 *                  4 Funding or 5 Active (no field 6) */
#include "lobby_internal.h"
#include <string.h>

static gz_status_t send_hello(gz_lobby_member_t *m, gz_action_list_t *out)
{
    gz_lobby_enc_t e;
    uint8_t buf[48];
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_HELLO, m->scope);
    return gz_la_send(out, &m->link, buf, gz_lobby_enc_done(&e));
}

static gz_status_t send_reason(gz_lobby_member_t *m, uint16_t kind, uint16_t reason, gz_action_list_t *out)
{
    gz_lobby_enc_t e;
    uint8_t buf[48];
    gz_lobby_enc_start(&e, buf, sizeof buf, kind, m->scope);
    gz_lobby_enc_u16(&e, 1, reason);
    return m->connected ? gz_la_send(out, &m->link, buf, gz_lobby_enc_done(&e)) : GZ_OK;
}

static gz_status_t note2(gz_action_list_t *out, uint32_t code, uint8_t a, uint8_t b)
{
    uint8_t n[2];
    n[0] = a; n[1] = b;
    return gz_la_notify(out, code, n, 2);
}

gz_status_t gz_lobby_member_connect(gz_lobby_member_t *m, gz_action_list_t *out)
{
    gz_action_t a;
    if (!m || !out) return GZ_ERR_ARGUMENT;
    memset(&a, 0, sizeof a);
    a.kind = GZ_ACTION_CONNECT;
    memcpy(a.u.connect.host.key, m->host_key, 33);
    a.u.connect.address.data = m->address;
    a.u.connect.address.len = m->address_len;
    a.u.connect.key_epoch = m->key_epoch;
    a.u.connect.key_index = m->key_index;
    return gz_action_list_add(out, &a);
}

/* Refuse the host: DISCONNECT `refused`. A DISCONNECT ends the CONNECT that
 * stood (action.h), so a member that goes on in this lobby asks for the
 * connection again; the program reconnects at its own pace. */
static gz_status_t refuse_host(gz_lobby_member_t *m, gz_action_list_t *out)
{
    TRY(gz_la_refuse(out, &m->link));
    m->connected = 0;
    return m->ended ? GZ_OK : gz_lobby_member_connect(m, out);
}

/* The signing gate (composite-node.md 12.2): 1 if it is closed. */
static int locked(const gz_lobby_member_t *m)
{
    return m->gate.may_answer && m->gate.may_answer(m->gate.ctx, m->scope) != 1;
}

static gz_status_t locked_note(gz_lobby_member_t *m, gz_action_list_t *out)
{
    if (m->locked_told) return GZ_OK;
    m->locked_told = 1;
    return gz_la_notify(out, GZ_NOTE_LOCKED, NULL, 0);
}

/* The class of the latest values (terms.md 9). */
static int class_of(const gz_lobby_member_t *m, uint8_t *term)
{
    return gz_lobby_classify(&m->terms, &m->values, &m->cond, term);
}

/* May be ready by itself (a plain `ready`). After the freeze the values
 * cannot move, so "fits only now" with fitting values is a fit (terms.md 9). */
static int plain_ok(const gz_lobby_member_t *m, int cls)
{
    return m->frozen ? cls != GZ_FIT_NO : gz_lobby_ready_ok(cls, &m->cond);
}

static void terms_record(const gz_lobby_member_t *m, gz_lr_t *w, uint8_t *buf, size_t cap)
{
    gz_lr_start(w, buf, cap, m->scope);
    gz_lr_put(w, 4, m->outer, m->outer_len);
    gz_lr_put(w, 6, m->outer_sig, 64);
    gz_lr_put(w, 8, m->current, m->current_len);
    gz_lr_put(w, 10, m->current_sig, 64);
}

/* Sign and send `ready` for the latest values, saving first the terms it
 * names (if not saved), the freeze (when answering the first check) and the
 * ready itself, in one batch. `check_msg` is the check's envelope. A port
 * that will not sign changes nothing (GZ_NOTE_NO_KEY). */
static gz_status_t send_ready(gz_lobby_member_t *m, const uint8_t *check_id, const uint8_t *check_msg,
                              size_t check_len, gz_action_list_t *out)
{
    uint8_t tr[GZ_LOBBY_REC_MAX_TERMS], fz[GZ_LOBBY_REC_MAX_FREEZE], rs[GZ_LOBBY_REC_MAX_READY_SENT];
    uint8_t msg[GZ_LOBBY_MAX_SAVED_MSG];
    gz_lr_t wt, wf, wr;
    gz_record_t recs[3];
    size_t n = 0, len;
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, msg, sizeof msg, GZ_KIND_READY, m->scope);
    gz_lobby_enc_record(&e, 2, m->scope, 32);
    gz_lobby_enc_u32(&e, 4, m->values.version);
    gz_lobby_enc_record(&e, 6, m->current_digest, 32);
    if (check_id) gz_lobby_enc_record(&e, 8, check_id, 32);
    if (m->cond.min_members) gz_lobby_enc_u16(&e, 11, m->cond.min_members);
    len = gz_lobby_enc_sign(&e, &m->crypto, GZ_LOBBY_KEY_CONTRIBUTION);
    if (!len) return gz_la_no_key(out, GZ_LOBBY_KEY_CONTRIBUTION);
    memcpy(m->ready_msg, msg, len);
    m->ready_len = len;
    if (m->saved_version != m->values.version) {
        terms_record(m, &wt, tr, sizeof tr);
        if (wt.bad) return GZ_ERR_BUG;
        recs[n].type = GZ_REC_TERMS_RECEIVED;
        recs[n].bytes.data = tr;
        recs[n++].bytes.len = gz_lr_done(&wt);
        m->saved_version = m->values.version;
    }
    if (check_msg && !m->frozen) {
        gz_lr_start(&wf, fz, sizeof fz, m->scope);
        gz_lr_put(&wf, 4, check_id, 32);
        gz_lr_int(&wf, 6, m->values.version, 4);
        gz_lr_put(&wf, 8, m->current_digest, 32);
        gz_lr_put(&wf, 10, check_msg, check_len);
        if (wf.bad) return GZ_ERR_BUG;
        recs[n].type = GZ_REC_FREEZE;
        recs[n].bytes.data = fz;
        recs[n++].bytes.len = gz_lr_done(&wf);
        m->frozen = 1;
        m->frozen_version = m->values.version;
        memcpy(m->frozen_digest, m->current_digest, 32);
    }
    gz_lr_start(&wr, rs, sizeof rs, m->scope);
    gz_lr_put(&wr, 4, m->ready_msg, m->ready_len);
    if (wr.bad) return GZ_ERR_BUG;
    recs[n].type = GZ_REC_READY_SENT;
    recs[n].bytes.data = rs;
    recs[n++].bytes.len = gz_lr_done(&wr);
    m->ready = 1;
    m->ready_version = m->values.version;
    m->unready_reason = 0;
    if (check_id) { memcpy(m->answered_check, check_id, 32); m->has_answered = 1; }
    TRY(gz_la_save(out, recs, n));
    if (!m->connected) return GZ_OK;
    /* `sent_here` is about the join alone: a ready sent here says nothing of
     * whether the host still has the seat. A host that lost it (its save
     * failed, it restarted) shows no seat, and the join is sent again. */
    return gz_la_send(out, &m->link, m->ready_msg, m->ready_len);
}

/* Not ready any more. A check it answered is withdrawn: a start for it is kept
 * as evidence and never begun (messages.md 6.5). */
static void withdraw(gz_lobby_member_t *m, uint16_t reason)
{
    m->ready = 0;
    m->ready_len = 0;
    m->unready_reason = reason;
    if (m->has_answered) {
        memcpy(m->withdrawn_check, m->answered_check, 32);
        m->has_withdrawn = 1;
        m->has_answered = 0;
    }
}

static gz_status_t unready(gz_lobby_member_t *m, uint16_t reason, gz_action_list_t *out)
{
    uint8_t r[GZ_LOBBY_REC_MAX_READY_SENT];
    gz_lr_t w;
    withdraw(m, reason);
    gz_lr_start(&w, r, sizeof r, m->scope);
    gz_lr_int(&w, 6, reason, 2);
    TRY(gz_lr_save(out, GZ_REC_READY_SENT, &w));
    return send_reason(m, GZ_KIND_UNREADY, reason, out);
}

/* An answered check that may still lead to a round: it runs to its end, also
 * when the gate closes (composite-node.md 12.2). A role-2 start ends it for
 * this member: it was not chosen, so a closed gate takes its seat out of the
 * count from then on. */
static int check_in_flight(const gz_lobby_member_t *m)
{
    return !m->ended && m->ready && m->has_answered && m->round_state < GZ_LOBBY_FUNDING &&
           !(m->start_len && m->role == 2);
}

int gz_lobby_member_check_in_flight(const gz_lobby_member_t *m) { return m && check_in_flight(m); }

/* The gate is closed: a Ready seat leaves the count ("locked", reason 3). */
static gz_status_t lock_out(gz_lobby_member_t *m, gz_action_list_t *out)
{
    if (m->ended || !m->joined || !m->ready || check_in_flight(m)) return GZ_OK;
    if (m->round_state >= GZ_LOBBY_FUNDING) return GZ_OK;   /* its creation is signed: nothing to withdraw */
    TRY(unready(m, 3, out));
    return locked_note(m, out);
}

/* The lobby is over for this member without a cancel and without its own
 * leave: saved, so that a restart neither joins again nor forgets why. */
static gz_status_t end_self(gz_lobby_member_t *m, int how, uint16_t reason, gz_action_list_t *out)
{
    uint8_t end[GZ_LOBBY_REC_MAX_ENDED], n[3];
    gz_lr_t w;
    gz_lr_start(&w, end, sizeof end, m->scope);
    gz_lr_int(&w, 4, 0, 1);
    gz_lr_int(&w, 6, reason, 2);
    gz_lr_int(&w, 10, (uint64_t)how, 1);
    m->ended = 1;
    m->ready = 0;
    m->end_how = how;
    m->never_joined = how != GZ_LOBBY_END_REMOVED;
    TRY(gz_lr_save(out, GZ_REC_LOBBY_ENDED, &w));
    n[0] = 0;
    gz_lw_put(n + 1, reason, 2);
    return gz_la_notify(out, GZ_NOTE_ENDED, n, 3);
}

/* Leave and keep the evidence (saved once, before `leave`). */
static gz_status_t leave(gz_lobby_member_t *m, uint8_t fault, const uint8_t *a, size_t an, const uint8_t *b,
                         size_t bn, uint16_t reason, gz_action_list_t *out)
{
    uint8_t ev[GZ_LOBBY_REC_MAX_HOST_FAULT], end[GZ_LOBBY_REC_MAX_ENDED];
    gz_lr_t we, wn;
    gz_record_t recs[2];
    size_t n = 0;
    if (fault) {
        if (an > GZ_LOBBY_EVIDENCE_MAX || bn > GZ_LOBBY_EVIDENCE_MAX) return GZ_ERR_BUG;
        gz_lr_start(&we, ev, sizeof ev, m->scope);
        gz_lr_int(&we, 4, fault, 1);
        gz_lr_put(&we, 6, a, an);
        gz_lr_put(&we, 8, b, bn);
        if (we.bad) return GZ_ERR_BUG;
        recs[n].type = GZ_REC_HOST_FAULT; recs[n].bytes.data = ev; recs[n++].bytes.len = gz_lr_done(&we);
    }
    gz_lr_start(&wn, end, sizeof end, m->scope);
    gz_lr_int(&wn, 4, 0, 1);
    gz_lr_int(&wn, 6, reason, 2);
    if (wn.bad) return GZ_ERR_BUG;
    recs[n].type = GZ_REC_LOBBY_ENDED; recs[n].bytes.data = end; recs[n++].bytes.len = gz_lr_done(&wn);
    m->ended = m->left = 1;
    m->leave_reason = reason;
    withdraw(m, m->unready_reason);
    TRY(gz_la_save(out, recs, n));
    TRY(send_reason(m, GZ_KIND_LEAVE, reason, out));
    return fault ? note2(out, GZ_NOTE_HOST_FAULT, fault, 0) : GZ_OK;
}

/* Compare the latest values with the conditions and act (terms.md 9). A
 * member joins a lobby that fits or fits only now: a ready check freezes the
 * values, after which "fits only now" with fitting values is a fit; it is
 * ready by itself only when plain_ok allows and its gate is open. */
static gz_status_t evaluate(gz_lobby_member_t *m, gz_action_list_t *out)
{
    int cls;
    uint8_t term;
    /* Function scope, not the join block: no ASan use-after-scope calls (isolation). */
    uint8_t b[32], tr[GZ_LOBBY_REC_MAX_TERMS], jr[GZ_LOBBY_REC_MAX_JOINED], msg[GZ_LOBBY_MAX_SAVED_MSG];
    uint8_t sf[64], sc[64];
    gz_lr_t wt, wj;
    gz_record_t recs[2];
    gz_lobby_enc_t e;
    size_t len;
    if (!m->have_terms || m->ended) return GZ_OK;
    cls = class_of(m, &term);
    if (cls != GZ_FIT_NO && !m->joined && m->auto_join) {
        gz_lobby_binding(m->scope, m->factory_key, m->ckey, b);
        if (m->crypto.sign(m->crypto.ctx, GZ_LOBBY_KEY_FACTORY, b, sf) != 1)
            return gz_la_no_key(out, GZ_LOBBY_KEY_FACTORY);
        if (m->crypto.sign(m->crypto.ctx, GZ_LOBBY_KEY_CONTRIBUTION, b, sc) != 1)
            return gz_la_no_key(out, GZ_LOBBY_KEY_CONTRIBUTION);
        gz_lobby_enc_start(&e, msg, sizeof msg, GZ_KIND_JOIN, m->scope);
        gz_lobby_enc_record(&e, 2, m->factory_key, 33);
        gz_lobby_enc_record(&e, 4, sf, 64);
        gz_lobby_enc_record(&e, 6, sc, 64);
        len = gz_lobby_enc_done(&e);
        terms_record(m, &wt, tr, sizeof tr);
        gz_lr_start(&wj, jr, sizeof jr, m->scope);
        gz_lr_put(&wj, 4, msg, len);
        if (!len || wt.bad || wj.bad) return GZ_ERR_BUG;
        memcpy(m->join_msg, msg, len);
        m->join_len = len;
        recs[0].type = GZ_REC_TERMS_RECEIVED; recs[0].bytes.data = tr; recs[0].bytes.len = gz_lr_done(&wt);
        recs[1].type = GZ_REC_JOINED; recs[1].bytes.data = jr; recs[1].bytes.len = gz_lr_done(&wj);
        m->saved_version = m->values.version;
        m->joined = 1;
        TRY(gz_la_save(out, recs, 2));
        if (m->connected) { m->sent_here = 1; TRY(gz_la_send(out, &m->link, m->join_msg, m->join_len)); }
    }
    if (plain_ok(m, cls)) {
        m->last_class = 0;                            /* a later refusal is told again */
        /* After the freeze too (messages.md 6.4 accepts a ready for the frozen
         * values at any time): a seat back in Joined counts again. */
        if (m->joined && !m->user_unready && (!m->ready || m->ready_version != m->values.version)) {
            if (locked(m)) {                          /* "unlock to take part" */
                TRY(lock_out(m, out));                /* ready for an older version: out of the count */
                return locked_note(m, out);
            }
            return send_ready(m, NULL, NULL, 0, out);
        }
        return GZ_OK;
    }
    if (m->ready) {                                   /* whatever was told before: unready now */
        m->last_class = cls;
        m->last_term = term;
        TRY(unready(m, 1, out));
        return note2(out, GZ_NOTE_UNREADY, (uint8_t)cls, term);
    }
    if (cls == m->last_class && term == m->last_term) return GZ_OK;   /* told already */
    m->last_class = cls;
    m->last_term = term;
    return note2(out, GZ_NOTE_REFUSED, (uint8_t)cls, term);
}

static gz_status_t on_check(gz_lobby_member_t *m, const uint8_t *env, size_t len, const gz_lobby_msg_t *g,
                            gz_action_list_t *out);

static gz_status_t on_terms(gz_lobby_member_t *m, const gz_lobby_msg_t *g, gz_action_list_t *out)
{
    gz_terms_outer_t t;
    gz_terms_current_t v;
    gz_tree_crypto_t tc;
    gz_lobby_msg_t c;
    uint8_t od[32], cd[32], a[GZ_LOBBY_EVIDENCE_MAX], b[GZ_LOBBY_EVIDENCE_MAX];
    uint8_t pc[GZ_LOBBY_MAX_SAVED_MSG];
    size_t pn;
    gz_terms_version_t rule;
    gz_la_tree_crypto(&m->crypto, &tc);
    /* terms.md 7 steps 1 to 6 under core/tree's policy: the scope, the pinned
     * key, both signatures, the bounds, the current record against the outer. */
    gz_terms_err_t te = gz_terms_receive(g->outer, g->outer_len, g->outer_sig, g->current, g->current_len, g->current_sig,
                                         m->scope, m->host_key, gz_lobby_policy(), &tc, &t, od, &v, cd);
    if (te == GZ_TERMS_OK && m->max_tree_nodes) te = gz_terms_check_tree_size(&t, m->max_tree_nodes);   /* M2 */
    if (te != GZ_TERMS_OK) {
        /* Terms refused before any seat: the member never got in, and the
         * slot is given up (composite-node.md 2.4, slot_closed state 0). */
        if (!m->joined) TRY(end_self(m, GZ_LOBBY_END_BAD_TERMS, 5, out));
        return refuse_host(m, out);
    }
    /* Steps 7 and 8. */
    rule = gz_terms_version_rule(m->have_terms, m->values.version, m->current_digest, m->frozen, v.version, cd);
    /* messages.md 6.2: a version lower than one accepted is ignored, frozen or
     * not (core/tree's rule calls it a breach once frozen; noted for the tree
     * stream in docs/notes/lobby.md). */
    if (rule == GZ_TERMS_V_FROZEN_BREACH && v.version < m->values.version) rule = GZ_TERMS_V_IGNORE_OLDER;
    switch (rule) {
    case GZ_TERMS_V_IGNORE_OLDER: return GZ_OK;
    /* The same terms again: nothing new to take. But a member restored from
     * storage acts on them now: one without a seat joins, and one whose
     * ready never became durable (a crash, a failed save) readies. For a
     * member that is where it should be this does nothing. */
    case GZ_TERMS_V_DUPLICATE: return evaluate(m, out);
    case GZ_TERMS_V_EQUIVOCATION: case GZ_TERMS_V_FROZEN_BREACH:
        memcpy(a, m->current, m->current_len); memcpy(a + m->current_len, m->current_sig, 64);
        memcpy(b, g->current, g->current_len); memcpy(b + g->current_len, g->current_sig, 64);
        return leave(m, v.version == m->values.version ? GZ_FAULT_TWO_VALUES : GZ_FAULT_AFTER_FREEZE,
                     a, m->current_len + 64, b, g->current_len + 64, 3, out);
    default: break;
    }
    if (!m->have_terms) {
        memcpy(m->outer, g->outer, g->outer_len);
        m->outer_len = g->outer_len;
        memcpy(m->outer_sig, g->outer_sig, 64);
        m->terms = t;
        m->have_terms = 1;
    }
    memcpy(m->current, g->current, g->current_len);
    m->current_len = g->current_len;
    memcpy(m->current_sig, g->current_sig, 64);
    m->values = v;
    memcpy(m->current_digest, cd, 32);
    TRY(evaluate(m, out));
    if (m->pending_len && !m->ended) {                /* a check that waited for these terms */
        pn = m->pending_len;
        memcpy(pc, m->pending_check, pn);
        m->pending_len = 0;
        if (gz_lobby_decode_env(pc, pn, &c) == GZ_DEC_OK) return on_check(m, pc, pn, &c, out);
    }
    return GZ_OK;
}

/* `env` is the check's envelope, `len` 0 if it is too large to keep. */
static gz_status_t on_check(gz_lobby_member_t *m, const uint8_t *env, size_t len, const gz_lobby_msg_t *g,
                            gz_action_list_t *out)
{
    uint8_t term, a[40], b[40];
    if (!gz_la_verified(&m->crypto, g, m->host_key)) return refuse_host(m, out);
    if (!m->joined || !m->have_terms) return GZ_OK;
    if (g->answer_within_ms != m->terms.ready_window_ms) return refuse_host(m, out);
    if (m->frozen && (g->version != m->frozen_version || memcmp(g->current_digest, m->frozen_digest, 32) != 0)) {
        memcpy(a, m->frozen_digest, 32); gz_lw_put(a + 32, m->frozen_version, 4);
        memcpy(b, g->current_digest, 32); gz_lw_put(b + 32, g->version, 4);
        return leave(m, GZ_FAULT_AFTER_FREEZE, a, 36, b, 36, 3, out);
    }
    if (g->version != m->values.version || memcmp(g->current_digest, m->current_digest, 32) != 0) {
        if (len) { memcpy(m->pending_check, env, len); m->pending_len = len; }
        return m->connected ? send_hello(m, out) : GZ_OK;   /* fetch terms; never answer unchecked values */
    }
    if (m->has_answered && memcmp(m->answered_check, g->check_id, 32) == 0 && m->ready_len)
        return gz_la_send(out, &m->link, m->ready_msg, m->ready_len);   /* the same saved bytes */
    /* The check is the host's signed freeze: values that fit only now are
     * fixed by answering it (terms.md 9), so any class but "does not fit". */
    if (m->user_unready || class_of(m, &term) == GZ_FIT_NO || !len) return GZ_OK;
    /* A closed gate does not answer: "locked", at once and again at every
     * check, so the host never runs a check that locked seats would make
     * fail (composite-node.md 12.2, R5). An earlier check still in flight
     * keeps its answer; this one gets none. */
    if (locked(m)) {
        if (m->ready && !check_in_flight(m)) return lock_out(m, out);
        if (!m->ready) TRY(unready(m, 3 /* locked */, out)); /* ready_sent, then the unready (review B, L1) */
        return locked_note(m, out);
    }
    return send_ready(m, g->check_id, env, len, out);
}

/* The start the member holds, if it is of `check`: its role, else 0. */
static int start_role_of(const gz_lobby_member_t *m, const uint8_t check[32], uint16_t *signers)
{
    gz_lobby_msg_t g;
    if (!m->start_len || gz_lobby_decode_env(m->start_msg, m->start_len, &g) != GZ_DEC_OK ||
        g.kind != GZ_KIND_START || memcmp(g.check_id, check, 32) != 0)
        return 0;
    if (signers) *signers = g.signers;
    return g.role;
}

int gz_lobby_member_accepted(const gz_lobby_member_t *m, const uint8_t check_id[32], uint32_t attempt,
                             gz_lobby_handoff_t *ho)
{
    uint16_t signers = 0;
    int role;
    if (!m || !check_id || attempt > 1) return 0;     /* a higher attempt: understudies, P4.7 */
    /* The newest check answered, not withdrawn, for the frozen values. */
    if (!m->ready || m->user_unready || m->ended || !m->frozen || !m->has_answered ||
        memcmp(m->answered_check, check_id, 32) != 0 || m->ready_version != m->frozen_version)
        return 0;
    /* Not spent: a Retry clears the answer (spend), Funding and Active are final. */
    if (m->round_state >= GZ_LOBBY_FUNDING) return 0;
    role = start_role_of(m, check_id, &signers);
    if (role == 2) return 0;                          /* not chosen in that attempt */
    if (!ho) return 1;
    memset(ho, 0, sizeof *ho);
    ho->role = 1;
    ho->scope = m->scope;
    ho->pinned_key = m->host_key;
    ho->outer = m->outer; ho->outer_len = m->outer_len; ho->outer_sig = m->outer_sig;
    ho->current = m->current; ho->current_len = m->current_len; ho->current_sig = m->current_sig;
    ho->current_digest = m->frozen_digest;
    ho->version = m->frozen_version;
    ho->check_id = m->answered_check;
    ho->terms = &m->terms;
    ho->values = &m->values;
    ho->limits = &m->cond.limits;
    ho->min_members = m->cond.min_members;
    ho->attempt = 1;
    ho->k = 1;
    ho->tree_anchors = 1;
    if (role == 1) {
        ho->signers = signers;
        ho->start_bytes = m->start_msg; ho->start_len = m->start_len;
        gz_la_shape(&m->terms, (uint16_t)(signers - 1), ho);
    }
    return 1;
}

int gz_lobby_member_round_ok(const gz_lobby_member_t *m) { return m && (m->has_answered || m->start_len != 0); }

/* A Retry names its check and spends it: the start held for it, and the
 * answer to it, so a start or a proposal for it that a host resends is
 * ignored; an answer to a later check, given before the signing engine
 * reported the retry, stands (confirmation review, N1). */
static int holds_check(const gz_lobby_member_t *m, const uint8_t check[32])
{
    return start_role_of(m, check, NULL) != 0 || (m->has_answered && memcmp(m->answered_check, check, 32) == 0);
}

static void spend_start(gz_lobby_member_t *m, const uint8_t check[32])
{
    if (start_role_of(m, check, NULL) != 0) { m->start_len = 0; m->role = 0; }
    if (m->has_answered && memcmp(m->answered_check, check, 32) == 0) m->has_answered = 0;
}

/* The saved start to the signing engine. */
static gz_status_t begin_signing(gz_lobby_member_t *m, const uint8_t check[32], int resume, gz_action_list_t *out)
{
    gz_lobby_handoff_t ho;
    if (!m->signing.begin || !gz_lobby_member_accepted(m, check, 1, &ho) || !ho.start_len) return GZ_OK;
    ho.resume = resume;
    return m->signing.begin(m->signing.ctx, &ho, out);
}

static gz_status_t on_start(gz_lobby_member_t *m, const uint8_t *env, size_t len, const gz_lobby_msg_t *g,
                            gz_action_list_t *out)
{
    uint8_t n[3], r[GZ_LOBBY_REC_MAX_START_RECEIVED];
    gz_lr_t w;
    int answered, withdrawn;
    if (!gz_la_verified(&m->crypto, g, m->host_key) || (g->role != 1 && g->role != 2) || g->signers < 2)
        return refuse_host(m, out);
    answered = m->has_answered && memcmp(g->check_id, m->answered_check, 32) == 0;
    withdrawn = m->has_withdrawn && memcmp(g->check_id, m->withdrawn_check, 32) == 0;
    if ((!answered && !withdrawn) || !len)
        return GZ_OK;                                 /* a check it did not answer: ignore */
    if (start_role_of(m, g->check_id, NULL) != 0) return GZ_OK;   /* duplicate */
    memcpy(m->start_msg, env, len);
    m->start_len = len;
    m->role = g->role;
    gz_lr_start(&w, r, sizeof r, m->scope);
    gz_lr_put(&w, 4, env, len);
    TRY(gz_lr_save(out, GZ_REC_START_RECEIVED, &w));
    n[0] = g->role;
    gz_lw_put(n + 1, g->signers, 2);
    TRY(gz_la_notify(out, GZ_NOTE_STARTED, n, 3));
    /* A start for a check the member withdrew from is evidence only: the user
     * declined, so no round begins (gz_lobby_member_accepted says no, and the
     * signing engine ignores a proposal for it). */
    /* Not chosen: the check is over for this member, and behind a closed gate
     * its seat leaves the count at once ("locked"), so the host's next check
     * never counts a seat that cannot answer (composite-node.md 12.2, R5). */
    if (g->role != 1) return locked(m) ? lock_out(m, out) : GZ_OK;
    return begin_signing(m, g->check_id, 0, out);
}

static gz_status_t on_cancel(gz_lobby_member_t *m, const uint8_t *env, size_t len, const gz_lobby_msg_t *g,
                             gz_action_list_t *out)
{
    uint8_t r[GZ_LOBBY_REC_MAX_ENDED], n[3];
    gz_lr_t w;
    if (!gz_la_verified(&m->crypto, g, m->host_key)) return refuse_host(m, out);
    /* A signed cancel may carry odd records up to the envelope's limit; only
     * one that fits the saved record is taken. */
    if (!len) return GZ_OK;
    m->ended = 1;
    m->ready = 0;
    m->never_joined = !m->joined;
    m->lobby_state = g->reason == 3 ? GZ_LOBBY_FAILED : GZ_LOBBY_CANCELLED;
    gz_lr_start(&w, r, sizeof r, m->scope);
    gz_lr_int(&w, 4, (uint64_t)m->lobby_state, 1);
    gz_lr_int(&w, 6, g->reason, 2);
    gz_lr_put(&w, 8, env, len);
    TRY(gz_lr_save(out, GZ_REC_LOBBY_ENDED, &w));
    /* The signing engine next, before the notice (as on the host). */
    if (m->signing.cancel) TRY(m->signing.cancel(m->signing.ctx, m->scope, g->reason, out));
    n[0] = (uint8_t)m->lobby_state;
    gz_lw_put(n + 1, g->reason, 2);
    return gz_la_notify(out, GZ_NOTE_ENDED, n, 3);
}

/* Send the saved join and ready again (the host lost them, or refused for a limit). */
static gz_status_t resend(gz_lobby_member_t *m, gz_action_list_t *out)
{
    if (!m->connected || !m->joined || m->ended || !m->join_len) return GZ_OK;
    m->sent_here = 1;
    TRY(gz_la_send(out, &m->link, m->join_msg, m->join_len));
    return m->ready && m->ready_len ? gz_la_send(out, &m->link, m->ready_msg, m->ready_len) : GZ_OK;
}

/* lobby_status: the member's own saved state messages (join, ready, unready,
 * leave) are resent only when the status shows another seat state (contract
 * v2's reconnect table), a few times per connection at most. */
static gz_status_t on_status(gz_lobby_member_t *m, const gz_lobby_msg_t *g, gz_action_list_t *out)
{
    int in = g->seat_state == GZ_SEAT_JOINED || g->seat_state == GZ_SEAT_READY;
    if (g->lobby_state != m->lobby_state || g->seat_state != m->seat_state) {
        m->lobby_state = g->lobby_state;
        m->seat_state = g->seat_state;
        TRY(note2(out, GZ_NOTE_SEAT, g->lobby_state, g->seat_state));
    }
    if (m->left) {                                    /* it left: the host must know, nothing more */
        if (!in || m->resends >= 3) return GZ_OK;
        m->resends++;
        return send_reason(m, GZ_KIND_LEAVE, m->leave_reason, out);
    }
    if (m->have_terms && g->version > m->values.version) return send_hello(m, out);
    if (!m->joined) return GZ_OK;
    if (g->seat_state == GZ_SEAT_REMOVED || (g->seat_state == GZ_SEAT_REFUSED && g->has_reason))
        return end_self(m, g->seat_state == GZ_SEAT_REMOVED ? GZ_LOBBY_END_REMOVED : GZ_LOBBY_END_REFUSED,
                        g->has_reason ? g->reason : 0, out);   /* final, and saved */
    if (g->seat_state == GZ_SEAT_REFUSED)            /* full, closed, or a rate limit: try later */
        return m->retries++ < 30 ? gz_la_timer(out, GZ_LOBBY_TIMER_RETRY, 1500) : GZ_OK;
    if (m->resends >= 3) return GZ_OK;
    /* The host shows Ready, but the member is not: its unready was lost. */
    if (g->seat_state == GZ_SEAT_READY && !m->ready &&
        (g->lobby_state == GZ_LOBBY_OPEN || g->lobby_state == GZ_LOBBY_READY_CHECK)) {
        m->resends++;
        return unready(m, m->unready_reason ? m->unready_reason : 2, out); /* saved first (review B, L1) */
    }
    if (g->lobby_state != GZ_LOBBY_OPEN) return GZ_OK;
    /* The host has no seat for us, though we did not just send our join on this
     * connection; or it shows us Joined at the version we are ready for (it lost
     * or never applied our ready). */
    if ((g->seat_state == GZ_SEAT_NONE && m->join_len && !m->sent_here) ||
        (g->seat_state == GZ_SEAT_JOINED && m->ready && m->ready_len && m->ready_version == g->version)) {
        m->resends++;
        return resend(m, out);
    }
    return GZ_OK;
}

gz_status_t gz_lobby_member_handle(gz_lobby_member_t *m, const gz_lobby_input_t *in, gz_action_list_t *out)
{
    gz_lobby_msg_t g;
    uint8_t env[GZ_LOBBY_MAX_SAVED_MSG];
    size_t en = 0;
    int code;
    if (!m || !in || !out) return GZ_ERR_ARGUMENT;
    if (in->kind == GZ_LIN_TIMER) return in->timer_id == GZ_LOBBY_TIMER_RETRY ? resend(m, out) : GZ_OK;
    if (in->kind != GZ_LIN_CONNECTED && in->kind != GZ_LIN_DISCONNECTED && in->kind != GZ_LIN_MESSAGE)
        return GZ_ERR_ARGUMENT;
    /* Only the slot's own link (the composite's gate, checked again here):
     * anything else is not this lobby's. */
    if (memcmp(in->link.local.key, m->ckey, 33) != 0 || memcmp(in->link.remote.key, m->host_key, 33) != 0)
        return GZ_OK;
    if (in->kind == GZ_LIN_CONNECTED) {
        m->connected = 1;
        m->resends = 0;
        m->retries = 0;
        m->sent_here = 0;
        /* A member that left still asks, so that a lost leave is repaired. */
        return m->ended && !m->left ? GZ_OK : send_hello(m, out);
    }
    if (in->kind == GZ_LIN_DISCONNECTED) {
        m->connected = 0;
        return GZ_OK;
    }
    if (!m->connected || !in->scope) return GZ_OK;
    code = gz_lobby_decode(in->msg_kind, in->scope, in->records, in->len, &g);
    if (code == GZ_DEC_REFUSE) return refuse_host(m, out);
    if (code != GZ_DEC_OK) return GZ_OK;
    if (g.kind == GZ_KIND_HELLO || g.kind == GZ_KIND_JOIN || g.kind == GZ_KIND_READY ||
        g.kind == GZ_KIND_UNREADY || g.kind == GZ_KIND_LEAVE)
        return refuse_host(m, out);                   /* the wrong direction */
    if (memcmp(g.scope, m->scope, 32) != 0) return GZ_OK;
    if (m->ended && !(m->left && g.kind == GZ_KIND_LOBBY_STATUS)) return GZ_OK;
    if (g.kind == GZ_KIND_READY_CHECK || g.kind == GZ_KIND_START || g.kind == GZ_KIND_CANCEL)
        en = gz_la_env(g.kind, g.scope, in->records, in->len, env, sizeof env);
    switch (g.kind) {
    case GZ_KIND_TERMS_OFFER: return on_terms(m, &g, out);
    case GZ_KIND_LOBBY_STATUS: return on_status(m, &g, out);
    case GZ_KIND_READY_CHECK: return on_check(m, env, en, &g, out);
    case GZ_KIND_START: return on_start(m, env, en, &g, out);
    default: return on_cancel(m, env, en, &g, out);
    }
}

gz_status_t gz_lobby_member_init(gz_lobby_member_t *m, const gz_ports_t *ports, const gz_lobby_crypto_t *crypto,
                                 const gz_lobby_signing_t *signing, const gz_lobby_gate_t *gate,
                                 const gz_lobby_conditions_t *cond, const gz_lobby_member_config_t *cfg)
{
    if (!m || !ports || !crypto || !cond || !cfg || !crypto->verify || !crypto->sign || !crypto->point_ok ||
        cfg->address_len == 0 || cfg->address_len > GZ_LOBBY_MAX_ADDRESS)
        return GZ_ERR_ARGUMENT;
    memset(m, 0, sizeof *m);
    m->ports = *ports;
    m->crypto = *crypto;
    if (signing) m->signing = *signing;
    if (gate) m->gate = *gate;
    m->cond = *cond;
    memcpy(m->scope, cfg->scope, 32);
    memcpy(m->host_key, cfg->host_key, 33);
    memcpy(m->ckey, cfg->ckey, 33);
    memcpy(m->factory_key, cfg->factory_key, 33);
    memcpy(m->address, cfg->address, cfg->address_len);
    m->address_len = cfg->address_len;
    m->key_epoch = cfg->key_epoch;
    m->key_index = cfg->key_index;
    m->max_tree_nodes = cfg->max_tree_nodes;
    memcpy(m->link.local.key, cfg->ckey, 33);
    memcpy(m->link.remote.key, cfg->host_key, 33);
    m->auto_join = cfg->auto_join;
    return GZ_OK;
}

gz_status_t gz_lobby_member_restore(gz_lobby_member_t *m, const gz_record_t *rec)
{
    const uint8_t *a, *b, *x;
    size_t an, bn;
    gz_lobby_msg_t g;
    gz_lf_t f;
    uint8_t od[32];
    if (!m || !rec) return GZ_ERR_ARGUMENT;
    if (!gz_lobby_rec_max(rec->type)) return GZ_OK;   /* another engine's record */
    if (rec->bytes.len > gz_lobby_rec_max(rec->type) || !gz_lf_read(rec->bytes.data, rec->bytes.len, m->scope, &f) ||
        !gz_lf_known(rec->type, &f))
        return GZ_ERR_CORRUPT;
    switch (rec->type) {
    case GZ_REC_TERMS_RECEIVED:
        if (!gz_lf_blob(&f, 4, GZ_TERMS_OUTER_MAX, &a, &an) || !gz_lf_blob(&f, 8, GZ_TERMS_CURRENT_MAX, &b, &bn) ||
            !gz_lf_fixed(&f, 6, 64) || !gz_lf_fixed(&f, 10, 64))
            return GZ_ERR_CORRUPT;
        memcpy(m->outer, a, an); m->outer_len = an; memcpy(m->outer_sig, f.v[3], 64);
        memcpy(m->current, b, bn); m->current_len = bn; memcpy(m->current_sig, f.v[5], 64);
        if (!gz_la_decode_terms(m->outer, an, m->current, bn, &m->terms, od, &m->values, m->current_digest) ||
            memcmp(od, m->scope, 32) != 0)
            return GZ_ERR_CORRUPT;
        m->have_terms = 1;
        m->saved_version = m->values.version;
        return GZ_OK;
    case GZ_REC_JOINED:
        if (!gz_lf_blob(&f, 4, sizeof m->join_msg, &a, &an) || gz_lobby_decode_env(a, an, &g) != GZ_DEC_OK ||
            g.kind != GZ_KIND_JOIN)
            return GZ_ERR_CORRUPT;
        m->stale_seat = memcmp(g.factory_key, m->factory_key, 33) != 0;
        if (m->stale_seat) return GZ_OK;              /* an older epoch's seat: join again */
        memcpy(m->join_msg, a, an); m->join_len = an;
        m->joined = 1;
        m->left = m->ended = 0;
        return GZ_OK;
    case GZ_REC_READY_SENT:
        if ((x = gz_lf_fixed(&f, 6, 2)) != NULL && !f.v[2]) {
            if (m->stale_seat) return GZ_OK;
            withdraw(m, (uint16_t)gz_lw_get(x, 2));
            m->user_unready = m->unready_reason == 2;
            return GZ_OK;
        }
        if (f.v[3] || !gz_lf_blob(&f, 4, sizeof m->ready_msg, &a, &an) ||
            gz_lobby_decode_env(a, an, &g) != GZ_DEC_OK || g.kind != GZ_KIND_READY)
            return GZ_ERR_CORRUPT;
        if (m->stale_seat) return GZ_OK;
        memcpy(m->ready_msg, a, an); m->ready_len = an;
        m->ready = 1;
        m->user_unready = 0;
        m->unready_reason = 0;
        m->ready_version = g.version;
        if (g.has_check_id) { memcpy(m->answered_check, g.check_id, 32); m->has_answered = 1; }
        return GZ_OK;
    case GZ_REC_FREEZE:
        if (!gz_la_freeze_ok(&f)) return GZ_ERR_CORRUPT;
        m->frozen = 1;
        m->frozen_version = (uint32_t)gz_lw_get(f.v[3], 4);
        memcpy(m->frozen_digest, f.v[4], 32);
        return GZ_OK;
    case GZ_REC_HOST_FAULT:
        if (!gz_lf_fixed(&f, 4, 1) || !gz_lf_blob(&f, 6, GZ_LOBBY_EVIDENCE_MAX, &a, &an) ||
            !gz_lf_blob(&f, 8, GZ_LOBBY_EVIDENCE_MAX, &b, &bn))
            return GZ_ERR_CORRUPT;
        return GZ_OK;                                 /* evidence: kept, not acted on */
    case GZ_REC_START_RECEIVED:
        if (!gz_lf_blob(&f, 4, sizeof m->start_msg, &a, &an) || gz_lobby_decode_env(a, an, &g) != GZ_DEC_OK ||
            g.kind != GZ_KIND_START)
            return GZ_ERR_CORRUPT;
        if (m->stale_seat) return GZ_OK;
        memcpy(m->start_msg, a, an); m->start_len = an; m->role = g.role;
        return GZ_OK;
    case GZ_REC_LOBBY_ENDED:
        if (!(x = gz_lf_fixed(&f, 4, 1)) || !gz_lf_fixed(&f, 6, 2)) return GZ_ERR_CORRUPT;
        if (f.v[4] && !gz_lf_blob(&f, 8, GZ_LOBBY_MAX_SAVED_MSG, &a, &an)) return GZ_ERR_CORRUPT;
        if (f.v[5] && (x[0] != 0 || !gz_lf_fixed(&f, 10, 1) || f.v[5][0] < GZ_LOBBY_END_REMOVED ||
                       f.v[5][0] > GZ_LOBBY_END_BAD_TERMS))
            return GZ_ERR_CORRUPT;
        if (x[0] != 0 && x[0] != GZ_LOBBY_CANCELLED && x[0] != GZ_LOBBY_FAILED) return GZ_ERR_CORRUPT;
        /* The old seat's own end (an older epoch's keys): the member joins
         * again. Terms refused before any seat end the slot whatever the keys. */
        if (m->stale_seat && x[0] == 0 && !(f.v[5] && f.v[5][0] == GZ_LOBBY_END_BAD_TERMS)) return GZ_OK;
        m->ended = 1;
        m->ready = 0;
        if (x[0] != 0) { m->lobby_state = x[0]; m->never_joined = !m->joined; }
        else if (f.v[5]) { m->end_how = f.v[5][0]; m->never_joined = m->end_how != GZ_LOBBY_END_REMOVED; }
        else { m->left = 1; m->leave_reason = (uint16_t)gz_lw_get(f.v[3], 2); m->never_joined = !m->joined; }
        return GZ_OK;
    case GZ_REC_LOBBY_STATE:                          /* the signing outcome (B2) */
        if (!(x = gz_lf_fixed(&f, 4, 1))) return GZ_ERR_CORRUPT;
        if (x[0] == GZ_LOBBY_OPEN ? !gz_lf_fixed(&f, 6, 32)
                                  : (f.v[3] || (x[0] != GZ_LOBBY_FUNDING && x[0] != GZ_LOBBY_ACTIVE)))
            return GZ_ERR_CORRUPT;
        if (m->stale_seat) return GZ_OK;              /* an older epoch's round */
        if (x[0] == GZ_LOBBY_OPEN) {                  /* the same rule as live */
            if (holds_check(m, f.v[3])) spend_start(m, f.v[3]);
        }
        else m->round_state = m->lobby_state = x[0];
        return GZ_OK;
    default:
        return GZ_ERR_CORRUPT;                        /* a host's record in a member's lobby */
    }
}

gz_status_t gz_lobby_member_resume(gz_lobby_member_t *m, gz_action_list_t *out)
{
    if (!m || !out) return GZ_ERR_ARGUMENT;
    m->locked_told = 0;
    TRY(gz_lobby_member_connect(m, out));             /* at every start (action.h, CONNECTIONS) */
    /* Every gate is closed at a start (composite-node.md 12.2): a Ready seat
     * with no check in flight leaves the count until the person readies. */
    if (locked(m)) TRY(lock_out(m, out));
    if (m->ended || !m->start_len || m->role != 1 || !m->has_answered) return GZ_OK;
    return begin_signing(m, m->answered_check, 1, out);
}

gz_status_t gz_lobby_member_round_result(gz_lobby_member_t *m, int outcome, const uint8_t *check_id,
                                         gz_action_list_t *out)
{
    uint8_t r[GZ_LOBBY_REC_MAX_STATE];
    gz_lr_t w;
    if (!m || !out || outcome < GZ_LOBBY_ROUND_FUNDING || outcome > GZ_LOBBY_ROUND_FAILED ||
        (outcome == GZ_LOBBY_ROUND_RETRY && !check_id))
        return GZ_ERR_ARGUMENT;
    gz_lr_start(&w, r, sizeof r, m->scope);
    if (outcome == GZ_LOBBY_ROUND_FUNDING || outcome == GZ_LOBBY_ROUND_ACTIVE) {
        /* Saved, so that a restart never hands this check over again (review
         * B, B2); taken also after a cancel, since a completed creation stands
         * (B3). */
        int st8 = outcome == GZ_LOBBY_ROUND_FUNDING ? GZ_LOBBY_FUNDING : GZ_LOBBY_ACTIVE;
        if (m->round_state == GZ_LOBBY_ACTIVE ||
            (outcome == GZ_LOBBY_ROUND_FUNDING && m->round_state == GZ_LOBBY_FUNDING))
            return gz_la_cmd_refused(out, GZ_CMD_ROUND_RESULT, m->lobby_state);
        gz_lr_int(&w, 4, (uint64_t)st8, 1);
        TRY(gz_lr_save(out, GZ_REC_LOBBY_STATE, &w));
        m->round_state = m->lobby_state = st8;
        return note2(out, GZ_NOTE_SEAT, (uint8_t)m->lobby_state, (uint8_t)m->seat_state);
    }
    if (m->ended || m->round_state >= GZ_LOBBY_FUNDING) return gz_la_cmd_refused(out, GZ_CMD_ROUND_RESULT, m->lobby_state);
    /* A Retry for the check the member holds (its start, or its answer when
     * the proposal came without a start): that check is spent, the next
     * check's start is new. A Retry for another check, an older one whose
     * report came late, is ignored: what is held stands. */
    if (outcome == GZ_LOBBY_ROUND_RETRY && holds_check(m, check_id)) {
        gz_lr_int(&w, 4, GZ_LOBBY_OPEN, 1);
        gz_lr_put(&w, 6, check_id, 32);
        TRY(gz_lr_save(out, GZ_REC_LOBBY_STATE, &w));
        spend_start(m, check_id);
        /* The check is over: with a closed gate the seat leaves the count
         * now, and the person readies again (composite-node.md 12.2). */
        if (locked(m)) TRY(lock_out(m, out));
    }
    return GZ_OK;                                     /* Failed: the host's cancel follows */
}

gz_status_t gz_lobby_member_ready(gz_lobby_member_t *m, gz_action_list_t *out)
{
    if (!m || !out) return GZ_ERR_ARGUMENT;
    if (m->ended || !m->joined || (m->ready && m->ready_version == m->values.version))
        return gz_la_cmd_refused(out, GZ_CMD_READY, m->lobby_state);
    m->user_unready = 0;
    m->last_class = 0;
    m->locked_told = 0;
    return evaluate(m, out);
}

gz_status_t gz_lobby_member_unready(gz_lobby_member_t *m, gz_action_list_t *out)
{
    if (!m || !out) return GZ_ERR_ARGUMENT;
    if (!m->ready || m->ended) return gz_la_cmd_refused(out, GZ_CMD_UNREADY, m->lobby_state);
    m->user_unready = 1;
    return unready(m, 2, out);
}

gz_status_t gz_lobby_member_leave(gz_lobby_member_t *m, gz_action_list_t *out)
{
    if (!m || !out) return GZ_ERR_ARGUMENT;
    if (m->ended) return gz_la_cmd_refused(out, GZ_CMD_LEAVE, m->lobby_state);
    m->never_joined = !m->joined;
    return leave(m, 0, NULL, 0, NULL, 0, 2, out);
}

gz_status_t gz_lobby_member_set_conditions(gz_lobby_member_t *m, const gz_lobby_conditions_t *c,
                                           gz_action_list_t *out)
{
    if (!m || !c || !out) return GZ_ERR_ARGUMENT;
    m->cond = *c;
    m->user_unready = 0;
    m->last_class = 0;
    return evaluate(m, out);
}

gz_status_t gz_lobby_member_gate_opened(gz_lobby_member_t *m, gz_action_list_t *out)
{
    if (!m || !out) return GZ_ERR_ARGUMENT;
    m->locked_told = 0;
    return evaluate(m, out);                          /* readies, unless the user unreadied */
}

gz_status_t gz_lobby_member_gate_closed(gz_lobby_member_t *m, gz_action_list_t *out)
{
    if (!m || !out) return GZ_ERR_ARGUMENT;
    m->locked_told = 0;
    return locked(m) ? lock_out(m, out) : GZ_OK;
}
