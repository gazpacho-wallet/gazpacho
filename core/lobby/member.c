/* The member side of the lobby: messages.md section 6, terms.md 7 to 9.
 *
 * Records (journal.md section 9), every integer big-endian:
 *   TERMS_RECEIVED u16 len, outer, outer_sig 64, u16 len, current, current_sig 64
 *   JOINED         the signed join bytes (the key epoch and index are the program's)
 *   READY_SENT     the signed ready bytes; for an unready one byte, its reason
 *   FREEZE         check_id 32, version u32, digest 32, u16 len, the ready_check
 *   HOST_FAULT     fault u8, u16 len, evidence a, u16 len, evidence b
 *   START_RECEIVED the signed start bytes
 *   LOBBY_ENDED    state u8 (0: the member left), reason u16, u16 len, the cancel
 *   LOBBY_STATE    state u8: the signing engine's outcome (1 Open: a retry, the
 *                  start is spent; 4 Funding; 5 Active), so that a restart never
 *                  hands a finished check to the signing engine again */
#include "lobby_internal.h"
#include <string.h>

static gz_status_t send_hello(gz_lobby_member_t *m, gz_action_list_t *out)
{
    gz_lobby_enc_t e;
    uint8_t buf[48];
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_HELLO, m->scope);
    return gz_la_send(out, m->host_peer, buf, gz_lobby_enc_done(&e));
}

static gz_status_t send_reason(gz_lobby_member_t *m, uint16_t kind, uint16_t reason, gz_action_list_t *out)
{
    gz_lobby_enc_t e;
    uint8_t buf[48];
    gz_lobby_enc_start(&e, buf, sizeof buf, kind, m->scope);
    gz_lobby_enc_u16(&e, 1, reason);
    return m->connected ? gz_la_send(out, m->host_peer, buf, gz_lobby_enc_done(&e)) : GZ_OK;
}

static gz_status_t note2(gz_action_list_t *out, uint32_t code, uint8_t a, uint8_t b)
{
    uint8_t n[2];
    n[0] = a; n[1] = b;
    return gz_la_notify(out, code, n, 2);
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

static size_t terms_record(const gz_lobby_member_t *m, uint8_t *r)
{
    size_t n = gz_la_put_blob(r, m->outer, m->outer_len);
    memcpy(r + n, m->outer_sig, 64); n += 64;
    n += gz_la_put_blob(r + n, m->current, m->current_len);
    memcpy(r + n, m->current_sig, 64);
    return n + 64;
}

/* Sign and send `ready` for the latest values, saving first the terms it
 * names (if not saved), the freeze (when answering the first check) and the
 * ready itself, in one batch. */
static gz_status_t send_ready(gz_lobby_member_t *m, const uint8_t *check_id, const uint8_t *check_msg,
                              size_t check_len, gz_action_list_t *out)
{
    uint8_t tr[GZ_TERMS_OUTER_MAX + GZ_TERMS_CURRENT_MAX + 140], fz[70 + GZ_LOBBY_MAX_SAVED_MSG];
    gz_record_t recs[3];
    size_t n = 0;
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, m->ready_msg, sizeof m->ready_msg, GZ_KIND_READY, m->scope);
    gz_lobby_enc_record(&e, 2, m->scope, 32);
    gz_lobby_enc_u32(&e, 4, m->values.version);
    gz_lobby_enc_record(&e, 6, m->current_digest, 32);
    if (check_id) gz_lobby_enc_record(&e, 8, check_id, 32);
    if (m->cond.min_members) gz_lobby_enc_u16(&e, 11, m->cond.min_members);
    m->ready_len = gz_lobby_enc_sign(&e, &m->crypto, GZ_LOBBY_KEY_CONTRIBUTION);
    if (!m->ready_len) return GZ_ERR_ARGUMENT;
    if (m->saved_version != m->values.version) {
        recs[n].type = GZ_REC_TERMS_RECEIVED;
        recs[n].bytes.data = tr;
        recs[n++].bytes.len = terms_record(m, tr);
        m->saved_version = m->values.version;
    }
    if (check_msg && !m->frozen) {
        memcpy(fz, check_id, 32);
        gz_lw_put(fz + 32, m->values.version, 4);
        memcpy(fz + 36, m->current_digest, 32);
        recs[n].type = GZ_REC_FREEZE;
        recs[n].bytes.data = fz;
        recs[n++].bytes.len = 68 + gz_la_put_blob(fz + 68, check_msg, check_len);
        m->frozen = 1;
        m->frozen_version = m->values.version;
        memcpy(m->frozen_digest, m->current_digest, 32);
    }
    recs[n].type = GZ_REC_READY_SENT;
    recs[n].bytes.data = m->ready_msg;
    recs[n++].bytes.len = m->ready_len;
    m->ready = 1;
    m->ready_version = m->values.version;
    if (check_id) { memcpy(m->answered_check, check_id, 32); m->has_answered = 1; }
    TRY(gz_la_save(out, recs, n));
    if (!m->connected) return GZ_OK;
    m->sent_here = 1;
    return gz_la_send(out, m->host_peer, m->ready_msg, m->ready_len);
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
    uint8_t r = (uint8_t)reason;
    withdraw(m, reason);
    TRY(gz_la_save1(out, GZ_REC_READY_SENT, &r, 1));
    return send_reason(m, GZ_KIND_UNREADY, reason, out);
}

/* Leave and keep the evidence (saved once, before `leave`). */
static gz_status_t leave(gz_lobby_member_t *m, uint8_t fault, const uint8_t *a, size_t an, const uint8_t *b,
                         size_t bn, uint16_t reason, gz_action_list_t *out)
{
    uint8_t ev[2 * (GZ_TERMS_CURRENT_MAX + 70) + 8], end[5] = {0, 0, 0, 0, 0};
    gz_record_t recs[2];
    size_t n = 0, k;
    if (fault) {
        if (an > GZ_TERMS_CURRENT_MAX + 66 || bn > GZ_TERMS_CURRENT_MAX + 66) return GZ_ERR_ARGUMENT;
        ev[0] = fault;
        k = 1 + gz_la_put_blob(ev + 1, a, an);
        k += gz_la_put_blob(ev + k, b, bn);
        recs[n].type = GZ_REC_HOST_FAULT; recs[n].bytes.data = ev; recs[n++].bytes.len = k;
    }
    end[0] = 0;
    gz_lw_put(end + 1, reason, 2);
    gz_lw_put(end + 3, 0, 2);
    recs[n].type = GZ_REC_LOBBY_ENDED; recs[n].bytes.data = end; recs[n++].bytes.len = 5;
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
 * ready by itself only when plain_ok allows. */
static gz_status_t evaluate(gz_lobby_member_t *m, gz_action_list_t *out)
{
    int cls;
    uint8_t term;
    /* Function scope, not the join block: no ASan use-after-scope calls (isolation). */
    uint8_t b[32], tr[GZ_TERMS_OUTER_MAX + GZ_TERMS_CURRENT_MAX + 140];
    uint8_t sf[64], sc[64];
    gz_record_t recs[2];
    gz_lobby_enc_t e;
    if (!m->have_terms || m->ended) return GZ_OK;
    cls = class_of(m, &term);
    if (cls != GZ_FIT_NO && !m->joined && m->auto_join) {
        gz_lobby_binding(m->scope, m->factory_key, m->ckey, b);
        if (m->crypto.sign(m->crypto.ctx, GZ_LOBBY_KEY_FACTORY, b, sf) != 1 ||
            m->crypto.sign(m->crypto.ctx, GZ_LOBBY_KEY_CONTRIBUTION, b, sc) != 1)
            return GZ_ERR_ARGUMENT;
        gz_lobby_enc_start(&e, m->join_msg, sizeof m->join_msg, GZ_KIND_JOIN, m->scope);
        gz_lobby_enc_record(&e, 2, m->factory_key, 33);
        gz_lobby_enc_record(&e, 4, sf, 64);
        gz_lobby_enc_record(&e, 6, sc, 64);
        m->join_len = gz_lobby_enc_done(&e);
        recs[0].type = GZ_REC_TERMS_RECEIVED; recs[0].bytes.data = tr; recs[0].bytes.len = terms_record(m, tr);
        recs[1].type = GZ_REC_JOINED; recs[1].bytes.data = m->join_msg; recs[1].bytes.len = m->join_len;
        m->saved_version = m->values.version;
        m->joined = 1;
        TRY(gz_la_save(out, recs, 2));
        if (m->connected) { m->sent_here = 1; TRY(gz_la_send(out, m->host_peer, m->join_msg, m->join_len)); }
    }
    if (plain_ok(m, cls)) {
        m->last_class = 0;                            /* a later refusal is told again */
        /* After the freeze too (messages.md 6.4 accepts a ready for the frozen
         * values at any time): a seat back in Joined counts again. */
        if (m->joined && !m->user_unready && (!m->ready || m->ready_version != m->values.version))
            return send_ready(m, NULL, NULL, 0, out);
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

static gz_status_t on_check(gz_lobby_member_t *m, const uint8_t *raw, size_t len, const gz_lobby_msg_t *g,
                            gz_action_list_t *out);

static gz_status_t on_terms(gz_lobby_member_t *m, const gz_lobby_msg_t *g, gz_action_list_t *out)
{
    gz_terms_outer_t t;
    gz_terms_current_t v;
    gz_tree_crypto_t tc;
    gz_lobby_msg_t c;
    uint8_t od[32], cd[32], a[GZ_TERMS_CURRENT_MAX + 66], b[GZ_TERMS_CURRENT_MAX + 66];
    uint8_t pc[GZ_LOBBY_MAX_SAVED_MSG];
    size_t pn;
    gz_terms_version_t rule;
    gz_la_tree_crypto(&m->crypto, &tc);
    /* terms.md 7 steps 1 to 6 under core/tree's policy: the scope, the pinned
     * key, both signatures, the bounds, the current record against the outer. */
    if (gz_terms_receive(g->outer, g->outer_len, g->outer_sig, g->current, g->current_len, g->current_sig, m->scope,
                         m->host_key, gz_lobby_policy(), &tc, &t, od, &v, cd) != GZ_TERMS_OK)
        return gz_la_refuse(out, m->host_peer, "bad terms");
    /* Steps 7 and 8. */
    rule = gz_terms_version_rule(m->have_terms, m->values.version, m->current_digest, m->frozen, v.version, cd);
    /* messages.md 6.2: a version lower than one accepted is ignored, frozen or
     * not (core/tree's rule calls it a breach once frozen; noted for the tree
     * stream in docs/notes/lobby.md). */
    if (rule == GZ_TERMS_V_FROZEN_BREACH && v.version < m->values.version) rule = GZ_TERMS_V_IGNORE_OLDER;
    switch (rule) {
    case GZ_TERMS_V_IGNORE_OLDER: return GZ_OK;
    case GZ_TERMS_V_DUPLICATE: return m->joined ? GZ_OK : evaluate(m, out);   /* restored terms without a seat */
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
        if (gz_lobby_decode(pc, pn, &c) == GZ_DEC_OK) return on_check(m, pc, pn, &c, out);
    }
    return GZ_OK;
}

static gz_status_t on_check(gz_lobby_member_t *m, const uint8_t *raw, size_t len, const gz_lobby_msg_t *g,
                            gz_action_list_t *out)
{
    uint8_t term, a[40], b[40];
    if (!gz_la_verified(&m->crypto, raw, g, m->host_key)) return gz_la_refuse(out, m->host_peer, "bad signature");
    if (!m->joined || !m->have_terms) return GZ_OK;
    if (g->answer_within_ms != m->terms.ready_window_ms) return gz_la_refuse(out, m->host_peer, "bad window");
    if (m->frozen && (g->version != m->frozen_version || memcmp(g->current_digest, m->frozen_digest, 32) != 0)) {
        memcpy(a, m->frozen_digest, 32); gz_lw_put(a + 32, m->frozen_version, 4);
        memcpy(b, g->current_digest, 32); gz_lw_put(b + 32, g->version, 4);
        return leave(m, GZ_FAULT_AFTER_FREEZE, a, 36, b, 36, 3, out);
    }
    if (g->version != m->values.version || memcmp(g->current_digest, m->current_digest, 32) != 0) {
        if (len <= sizeof m->pending_check) { memcpy(m->pending_check, raw, len); m->pending_len = len; }
        return m->connected ? send_hello(m, out) : GZ_OK;   /* fetch terms; never answer unchecked values */
    }
    if (m->has_answered && memcmp(m->answered_check, g->check_id, 32) == 0 && m->ready_len)
        return gz_la_send(out, m->host_peer, m->ready_msg, m->ready_len);   /* the same saved bytes */
    /* The check is the host's signed freeze: values that fit only now are
     * fixed by answering it (terms.md 9), so any class but "does not fit". */
    if (m->user_unready || class_of(m, &term) == GZ_FIT_NO || len > GZ_LOBBY_MAX_SAVED_MSG) return GZ_OK;
    return send_ready(m, g->check_id, raw, len, out);
}

int gz_lobby_member_may_sign(const gz_lobby_member_t *m, const uint8_t check_id[32])
{
    return m && check_id && m->ready && !m->user_unready && !m->ended && m->frozen && m->has_answered &&
           memcmp(m->answered_check, check_id, 32) == 0 && m->ready_version == m->frozen_version;
}

/* The saved start to the signing engine. */
static gz_status_t begin_signing(gz_lobby_member_t *m, int resume, gz_action_list_t *out)
{
    gz_lobby_handoff_t ho;
    gz_lobby_msg_t g;
    if (!m->signing.begin) return GZ_OK;
    if (gz_lobby_decode(m->start_msg, m->start_len, &g) != GZ_DEC_OK || g.kind != GZ_KIND_START) return GZ_OK;
    memset(&ho, 0, sizeof ho);
    ho.role = 1;
    ho.resume = resume;
    ho.scope = m->scope;
    ho.pinned_key = m->host_key;
    ho.outer = m->outer; ho.outer_len = m->outer_len; ho.outer_sig = m->outer_sig;
    ho.current = m->current; ho.current_len = m->current_len; ho.current_sig = m->current_sig;
    ho.current_digest = m->frozen_digest;
    ho.version = m->frozen_version;
    ho.check_id = m->answered_check;
    ho.terms = &m->terms;
    ho.values = &m->values;
    ho.signers = g.signers;
    ho.limits = &m->cond.limits;
    ho.min_members = m->cond.min_members;
    ho.start_bytes = m->start_msg; ho.start_len = m->start_len;
    gz_la_shape(&m->terms, (uint16_t)(g.signers - 1), &ho);
    return m->signing.begin(m->signing.ctx, &ho, out);
}

static gz_status_t on_start(gz_lobby_member_t *m, const uint8_t *raw, size_t len, const gz_lobby_msg_t *g,
                            gz_action_list_t *out)
{
    gz_lobby_msg_t old;
    uint8_t n[3];
    int answered, withdrawn;
    if (!gz_la_verified(&m->crypto, raw, g, m->host_key) || (g->role != 1 && g->role != 2) || g->signers < 2)
        return gz_la_refuse(out, m->host_peer, "bad start");
    answered = m->has_answered && memcmp(g->check_id, m->answered_check, 32) == 0;
    withdrawn = m->has_withdrawn && memcmp(g->check_id, m->withdrawn_check, 32) == 0;
    if ((!answered && !withdrawn) || len > sizeof m->start_msg)
        return GZ_OK;                                 /* a check it did not answer: ignore */
    if (m->start_len && gz_lobby_decode(m->start_msg, m->start_len, &old) == GZ_DEC_OK &&
        memcmp(old.check_id, g->check_id, 32) == 0)
        return GZ_OK;                                 /* duplicate */
    memcpy(m->start_msg, raw, len);
    m->start_len = len;
    m->role = g->role;
    TRY(gz_la_save1(out, GZ_REC_START_RECEIVED, raw, len));
    n[0] = g->role;
    gz_lw_put(n + 1, g->signers, 2);
    TRY(gz_la_notify(out, GZ_NOTE_STARTED, n, 3));
    /* A start for a check the member withdrew from is evidence only: the user
     * declined, so no round begins (the signing engine aborts a proposal for
     * it, gz_lobby_member_may_sign). */
    if (g->role != 1 || !gz_lobby_member_may_sign(m, g->check_id)) return GZ_OK;
    return begin_signing(m, 0, out);
}

static gz_status_t on_cancel(gz_lobby_member_t *m, const uint8_t *raw, size_t len, const gz_lobby_msg_t *g,
                             gz_action_list_t *out)
{
    uint8_t r[5 + GZ_LOBBY_MAX_SAVED_MSG], n[3];
    if (!gz_la_verified(&m->crypto, raw, g, m->host_key)) return gz_la_refuse(out, m->host_peer, "bad cancel");
    /* A signed cancel may carry odd records up to the envelope's limit; only
     * what fits the saved record (state, reason, length, bytes) is taken. */
    if (len > sizeof r - 5) return GZ_OK;
    m->ended = 1;
    m->ready = 0;
    m->lobby_state = g->reason == 3 ? GZ_LOBBY_FAILED : GZ_LOBBY_CANCELLED;
    r[0] = (uint8_t)m->lobby_state;
    gz_lw_put(r + 1, g->reason, 2);
    TRY(gz_la_save1(out, GZ_REC_LOBBY_ENDED, r, 3 + gz_la_put_blob(r + 3, raw, len)));
    n[0] = (uint8_t)m->lobby_state;
    gz_lw_put(n + 1, g->reason, 2);
    TRY(gz_la_notify(out, GZ_NOTE_ENDED, n, 3));
    return m->signing.cancel ? m->signing.cancel(m->signing.ctx, m->scope, g->reason, out) : GZ_OK;
}

/* Send the saved join and ready again (the host lost them, or refused for a limit). */
static gz_status_t resend(gz_lobby_member_t *m, gz_action_list_t *out)
{
    if (!m->connected || !m->joined || m->ended || !m->join_len) return GZ_OK;
    m->sent_here = 1;
    TRY(gz_la_send(out, m->host_peer, m->join_msg, m->join_len));
    return m->ready && m->ready_len ? gz_la_send(out, m->host_peer, m->ready_msg, m->ready_len) : GZ_OK;
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
    if (g->seat_state == GZ_SEAT_REMOVED || (g->seat_state == GZ_SEAT_REFUSED && g->has_reason)) {
        m->ready = 0;                                 /* removed, or refused as invalid: final */
        m->ended = 1;
        return GZ_OK;
    }
    if (g->seat_state == GZ_SEAT_REFUSED)            /* full, closed, or a rate limit: try later */
        return m->retries++ < 30 ? gz_la_timer(out, GZ_LOBBY_TIMER_RETRY, 1500) : GZ_OK;
    if (m->resends >= 3) return GZ_OK;
    /* The host shows Ready, but the member is not: its unready was lost. */
    if (g->seat_state == GZ_SEAT_READY && !m->ready &&
        (g->lobby_state == GZ_LOBBY_OPEN || g->lobby_state == GZ_LOBBY_READY_CHECK)) {
        m->resends++;
        return send_reason(m, GZ_KIND_UNREADY, m->unready_reason ? m->unready_reason : 2, out);
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
    int code;
    if (!m || !in || !out) return GZ_ERR_ARGUMENT;
    if (in->kind == GZ_LIN_CONNECTED) {
        if (!in->peer_key || memcmp(in->peer_key, m->host_key, 33) != 0)
            return gz_la_refuse(out, in->peer_id, "not the pinned host");
        m->host_peer = in->peer_id;
        m->connected = 1;
        m->resends = 0;
        m->retries = 0;
        m->sent_here = 0;
        /* A member that left still asks, so that a lost leave is repaired. */
        return m->ended && !m->left ? GZ_OK : send_hello(m, out);
    }
    if (in->kind == GZ_LIN_DISCONNECTED) {
        if (in->peer_id == m->host_peer) m->connected = 0;
        return GZ_OK;
    }
    if (in->kind == GZ_LIN_TIMER) return in->timer_id == GZ_LOBBY_TIMER_RETRY ? resend(m, out) : GZ_OK;
    if (in->kind != GZ_LIN_MESSAGE || !m->connected || in->peer_id != m->host_peer || !in->bytes) return GZ_OK;
    code = gz_lobby_decode(in->bytes, in->len, &g);
    if (code == GZ_DEC_REFUSE) return gz_la_refuse(out, m->host_peer, "malformed");
    if (code != GZ_DEC_OK || g.kind == GZ_KIND_PART) return GZ_OK;
    if (g.kind == GZ_KIND_HELLO || g.kind == GZ_KIND_JOIN || g.kind == GZ_KIND_READY ||
        g.kind == GZ_KIND_UNREADY || g.kind == GZ_KIND_LEAVE)
        return gz_la_refuse(out, m->host_peer, "wrong direction");
    if (memcmp(g.scope, m->scope, 32) != 0) return GZ_OK;
    if (m->ended && !(m->left && g.kind == GZ_KIND_LOBBY_STATUS)) return GZ_OK;
    switch (g.kind) {
    case GZ_KIND_TERMS_OFFER: return on_terms(m, &g, out);
    case GZ_KIND_LOBBY_STATUS: return on_status(m, &g, out);
    case GZ_KIND_READY_CHECK: return on_check(m, in->bytes, in->len, &g, out);
    case GZ_KIND_START: return on_start(m, in->bytes, in->len, &g, out);
    default: return on_cancel(m, in->bytes, in->len, &g, out);
    }
}

gz_status_t gz_lobby_member_init(gz_lobby_member_t *m, const gz_ports_t *ports, const gz_lobby_crypto_t *crypto,
                                 const gz_lobby_signing_t *signing, const gz_lobby_conditions_t *cond,
                                 const uint8_t scope[32], const uint8_t host_key[33], const uint8_t ckey[33],
                                 const uint8_t factory_key[33], int auto_join)
{
    if (!m || !ports || !crypto || !cond || !scope || !host_key || !ckey || !factory_key || !crypto->verify ||
        !crypto->sign || !crypto->point_ok)
        return GZ_ERR_ARGUMENT;
    memset(m, 0, sizeof *m);
    m->ports = *ports;
    m->crypto = *crypto;
    if (signing) m->signing = *signing;
    m->cond = *cond;
    memcpy(m->scope, scope, 32);
    memcpy(m->host_key, host_key, 33);
    memcpy(m->ckey, ckey, 33);
    memcpy(m->factory_key, factory_key, 33);
    m->auto_join = auto_join;
    return GZ_OK;
}

gz_status_t gz_lobby_member_restore(gz_lobby_member_t *m, const gz_record_t *rec)
{
    const uint8_t *p, *a, *b;
    size_t len, at = 0, an, bn;
    gz_lobby_msg_t g;
    uint8_t od[32];
    if (!m || !rec) return GZ_ERR_ARGUMENT;
    p = rec->bytes.data;
    len = rec->bytes.len;
    switch (rec->type) {
    case GZ_REC_TERMS_RECEIVED:
        if (!gz_la_get_blob(p, len, &at, &a, &an) || an > GZ_TERMS_OUTER_MAX || len - at < 64) return GZ_ERR_CORRUPT;
        at += 64;
        if (!gz_la_get_blob(p, len, &at, &b, &bn) || bn > GZ_TERMS_CURRENT_MAX || len - at != 64) return GZ_ERR_CORRUPT;
        memcpy(m->outer, a, an); m->outer_len = an; memcpy(m->outer_sig, a + an, 64);
        memcpy(m->current, b, bn); m->current_len = bn; memcpy(m->current_sig, p + at, 64);
        if (!gz_la_decode_terms(m->outer, an, m->current, bn, &m->terms, od, &m->values, m->current_digest) ||
            memcmp(od, m->scope, 32) != 0)
            return GZ_ERR_CORRUPT;
        m->have_terms = 1;
        m->saved_version = m->values.version;
        return GZ_OK;
    case GZ_REC_JOINED:
        if (len > sizeof m->join_msg || gz_lobby_decode(p, len, &g) != GZ_DEC_OK || g.kind != GZ_KIND_JOIN)
            return GZ_ERR_CORRUPT;
        m->stale_seat = memcmp(g.factory_key, m->factory_key, 33) != 0;
        if (m->stale_seat) return GZ_OK;              /* an older epoch's seat: join again */
        memcpy(m->join_msg, p, len); m->join_len = len;
        m->joined = 1;
        m->left = m->ended = 0;
        return GZ_OK;
    case GZ_REC_READY_SENT:
        if (m->stale_seat) return GZ_OK;
        if (len == 1) { withdraw(m, p[0]); m->user_unready = p[0] == 2; return GZ_OK; }
        if (len > sizeof m->ready_msg || gz_lobby_decode(p, len, &g) != GZ_DEC_OK || g.kind != GZ_KIND_READY)
            return GZ_ERR_CORRUPT;
        memcpy(m->ready_msg, p, len); m->ready_len = len;
        m->ready = 1;
        m->user_unready = 0;
        m->ready_version = g.version;
        if (g.has_check_id) { memcpy(m->answered_check, g.check_id, 32); m->has_answered = 1; }
        return GZ_OK;
    case GZ_REC_FREEZE:
        if (!gz_la_freeze_ok(p, len)) return GZ_ERR_CORRUPT;
        m->frozen = 1;
        m->frozen_version = (uint32_t)gz_lw_get(p + 32, 4);
        memcpy(m->frozen_digest, p + 36, 32);
        return GZ_OK;
    case GZ_REC_START_RECEIVED:
        if (m->stale_seat) return GZ_OK;
        if (len > sizeof m->start_msg || gz_lobby_decode(p, len, &g) != GZ_DEC_OK || g.kind != GZ_KIND_START)
            return GZ_ERR_CORRUPT;
        memcpy(m->start_msg, p, len); m->start_len = len; m->role = g.role;
        return GZ_OK;
    case GZ_REC_LOBBY_ENDED:
        if (m->stale_seat && len >= 1 && p[0] == 0) return GZ_OK;   /* the old seat's own leave */
        at = 3;
        if (len < 5 || !gz_la_get_blob(p, len, &at, &a, &an) || at != len) return GZ_ERR_CORRUPT;
        m->ended = 1;
        m->ready = 0;
        if (p[0] == 0) { m->left = 1; m->leave_reason = (uint16_t)gz_lw_get(p + 1, 2); }
        else m->lobby_state = p[0];
        return GZ_OK;
    case GZ_REC_LOBBY_STATE:                          /* the signing outcome (B2) */
        if (len != 1 || (p[0] != GZ_LOBBY_OPEN && p[0] != GZ_LOBBY_FUNDING && p[0] != GZ_LOBBY_ACTIVE))
            return GZ_ERR_CORRUPT;
        if (m->stale_seat) return GZ_OK;              /* an older epoch's round */
        if (p[0] == GZ_LOBBY_OPEN) { m->start_len = 0; m->role = 0; m->has_answered = 0; }
        else m->round_state = m->lobby_state = p[0];
        return GZ_OK;
    default:
        return GZ_OK;
    }
}

gz_status_t gz_lobby_member_resume(gz_lobby_member_t *m, gz_action_list_t *out)
{
    gz_lobby_msg_t g;
    if (!m || !out) return GZ_ERR_ARGUMENT;
    if (m->ended || !m->start_len || m->role != 1 || m->round_state >= GZ_LOBBY_FUNDING ||
        gz_lobby_decode(m->start_msg, m->start_len, &g) != GZ_DEC_OK || !gz_lobby_member_may_sign(m, g.check_id))
        return GZ_OK;
    return begin_signing(m, 1, out);
}

gz_status_t gz_lobby_member_round_result(gz_lobby_member_t *m, int outcome, gz_action_list_t *out)
{
    uint8_t st8;
    if (!m || !out || outcome < GZ_LOBBY_ROUND_FUNDING || outcome > GZ_LOBBY_ROUND_FAILED) return GZ_ERR_ARGUMENT;
    if (outcome == GZ_LOBBY_ROUND_FUNDING || outcome == GZ_LOBBY_ROUND_ACTIVE) {
        /* Saved, so that a restart never hands this check over again (review
         * B, B2); taken also after a cancel, since a completed creation stands
         * (B3). */
        if (m->round_state == GZ_LOBBY_ACTIVE ||
            (outcome == GZ_LOBBY_ROUND_FUNDING && m->round_state == GZ_LOBBY_FUNDING))
            return gz_la_cmd_refused(out, GZ_CMD_ROUND_RESULT, m->lobby_state);
        st8 = outcome == GZ_LOBBY_ROUND_FUNDING ? GZ_LOBBY_FUNDING : GZ_LOBBY_ACTIVE;
        TRY(gz_la_save1(out, GZ_REC_LOBBY_STATE, &st8, 1));
        m->round_state = m->lobby_state = st8;
        return note2(out, GZ_NOTE_SEAT, (uint8_t)m->lobby_state, (uint8_t)m->seat_state);
    }
    if (m->ended || m->round_state >= GZ_LOBBY_FUNDING) return gz_la_cmd_refused(out, GZ_CMD_ROUND_RESULT, m->lobby_state);
    if (outcome == GZ_LOBBY_ROUND_RETRY && m->start_len) {   /* the start is spent; the next check's is new */
        st8 = GZ_LOBBY_OPEN;
        TRY(gz_la_save1(out, GZ_REC_LOBBY_STATE, &st8, 1));
        m->start_len = 0;
        m->role = 0;
        m->has_answered = 0;                          /* its check is over: a resent start for it is ignored */
    }
    return GZ_OK;                                     /* Failed: the host's cancel follows */
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
