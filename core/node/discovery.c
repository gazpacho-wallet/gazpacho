/* Asking a host for its lobbies (W12; messages.md 6.1, local-api.md 14.2's
 * POST /api/v1/discovery/query). A member's node part, not a slot's engine:
 *
 *   LOBBY_QUERY (12 host key, 14 address) -> a fresh key pair, saved with the
 *   guard before the CONNECT (messages.md 2: a fresh index pair per CONNECT);
 *   on PEER_CONNECTED a scope-zero `hello`; every `terms_offer` on that link
 *   is checked as a member checks one (terms.md 7 steps 1 to 6: the scope,
 *   the pinned host key, both signatures, the bounds) and kept; the query is
 *   answered DQ_QUIET_MS after the last offer, or failed at DQ_LIMIT_MS
 *   (no_answer, or unreachable when the link never came up); then the link
 *   is closed. One query at a time; memory only.
 *
 * What the view shows (view.c): kind 10, the query (id "q_N"): state, the
 * lobbies' local ids, why it failed; kind 2, each lobby seen, with a local id
 * for the run (local-api.md 7.3) that its slot keeps if the person joins it,
 * its outer rules and current values as signed, and its fit against the
 * member's conditions. The next query ends both (gone), apart from a lobby
 * a slot holds by then. */
#include "internal.h"
#include <string.h>
#include "gazpacho/view.h"
#include "gazpacho/terms.h"
#include "gazpacho/tree.h"

static int arg(gz_bytes_t cmd, uint64_t type, size_t len, gz_bytes_t *v)
{
    return gz_rec_find(cmd, type, v) == 1 && (len == 0 || v->len == len);
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t x = 0;
    for (size_t i = 0; i < n; i++) x |= p[i];
    return x == 0;
}

static int dq_point(void *ctx, const uint8_t pub[33])
{
    const gz_node_t *c = ctx;
    return c->cfg.crypto.point_ok && c->cfg.crypto.point_ok(c->cfg.crypto.ctx, pub) == 1;
}

static int dq_verify(void *ctx, const uint8_t msg[32], const uint8_t pub[33], const uint8_t sig[64])
{
    const gz_node_t *c = ctx;
    return c->cfg.crypto.verify && c->cfg.crypto.verify(c->cfg.crypto.ctx, pub, msg, sig) == 1;
}

static gz_status_t dq_timer(gz_action_list_t *out, uint64_t delay)
{
    gz_action_t a = {.kind = GZ_ACTION_SET_TIMER};
    a.u.set_timer.timer_id = NP_TIMER_DISCOVERY;
    a.u.set_timer.delay_ms = delay;
    return gz_action_list_add(out, &a);
}

static gz_status_t dq_result(gz_node_t *c, gz_bytes_t cmd, uint16_t status, const char *error, const char *object,
                             gz_action_list_t *out)
{
    uint8_t buf[200], st2[2];
    size_t at = 0, n = 0;
    gz_bytes_t rid;
    gz_status_t st;
    (void)c;
    if (gz_rec_find(cmd, GZ_CMD_REC_REQUEST_ID, &rid) != 1 || !rid.len || rid.len > GZ_CMD_MAX_REQUEST_ID) {
        rid.data = (const uint8_t *)"-";
        rid.len = 1;
    }
    gz_put_u16(st2, status);
    st = gz_rec_put(buf, sizeof buf, &at, GZ_RESULT_REC_REQUEST_ID, rid.data, rid.len);
    if (st == GZ_OK) st = gz_rec_put(buf, sizeof buf, &at, GZ_RESULT_REC_STATUS, st2, 2);
    if (st == GZ_OK && error) {
        while (error[n]) n++;
        st = gz_rec_put(buf, sizeof buf, &at, GZ_RESULT_REC_ERROR, (const uint8_t *)error, n);
    }
    if (st == GZ_OK && object) {
        for (n = 0; object[n]; n++) {}
        st = gz_rec_put(buf, sizeof buf, &at, GZ_RESULT_REC_OBJECT, (const uint8_t *)object, n);
    }
    if (st != GZ_OK) return st;
    gz_action_t a = {.kind = GZ_ACTION_NOTIFY};
    a.u.notify.code = GZ_NOTIFY_COMMAND_RESULT;
    a.u.notify.bytes.data = buf;
    a.u.notify.bytes.len = at;
    return gz_action_list_add(out, &a);
}

/* The query is over: the link closed, the view told. */
static gz_status_t dq_end(gz_node_t *c, int state, const char *why, gz_action_list_t *out)
{
    dq_t *q = &c->dq;
    gz_status_t st = GZ_OK;
    q->state = state;
    q->why = why;
    q->ended_ms = c->ports.clock.now_ms(c->ports.clock.ctx);
    if (q->link_wanted) {
        q->link_wanted = 0;
        st = np_disconnect(out, &q->link, GZ_DISCONNECT_DONE);
    }
    q->connected = 0;
    if (st == GZ_OK) st = gz_view_query(c, out);
    return st;
}

/* LOBBY_QUERY, inside the node part's bracket (np_command). */
gz_status_t gz_dq_command(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    dq_t *q = &c->dq;
    gz_bytes_t hk, addr;
    gz_status_t st;
    uint32_t first;
    uint8_t pub[33];
    if (c->cfg.host) return dq_result(c, cmd, 409, "not_a_member", NULL, out);
    if (!arg(cmd, 12, 33, &hk) || !arg(cmd, 14, 0, &addr) || addr.len > GZ_LOBBY_MAX_ADDRESS)
        return dq_result(c, cmd, 400, "bad_request", NULL, out);
    if (!gz_connect_address_ok(addr)) return dq_result(c, cmd, 400, "bad_address", NULL, out);
    if (!c->cfg.crypto.point_ok || c->cfg.crypto.point_ok(c->cfg.crypto.ctx, hk.data) != 1)
        return dq_result(c, cmd, 400, "bad_host_key", NULL, out);
    if (q->state == DQ_ASKING) return dq_result(c, cmd, 409, "busy", q->id, out);
    first = c->np.highest_index + 1;
    if (first > 0xfffffff0u || !c->cfg.keys.pub || c->cfg.keys.pub(c->cfg.keys.ctx, c->np.epoch, first, pub) != 1)
        return dq_result(c, cmd, 503, "no_key", NULL, out);
    /* The pair is saved (and never used again) before the CONNECT shows its key. */
    if ((st = np_save_pair(c, first, NULL, out)) != GZ_OK) return st;
    /* The last query and the lobbies it saw end in the view (review of #79,
     * M2): a host giving fresh lobbies at every query cannot fill the
     * program's table. A lobby a slot now holds is the slot's object. A
     * lobby seen again keeps its id (dq.seen) and comes back. */
    for (int k = 0; k < q->n; k++) {
        const uint8_t *scope = q->offers[k].scope;
        const char *id = gz_api_local_id(c, scope);
        if (!id || gz_route_slot_by_scope(c, scope) >= 0 || !gz_api_seen_only(c, scope)) continue;
        if ((st = gz_view_gone(c, GZ_VIEW_LOBBY, id, &q->offers[k].hash, out)) != GZ_OK) return st;
    }
    if (q->state && (st = gz_view_gone(c, GZ_VIEW_DISCOVERY, q->id, &q->hash, out)) != GZ_OK) return st;
    q->hash = 0;
    memset(q->offers, 0, sizeof q->offers);
    q->n = 0;
    q->serial++;
    q->state = DQ_ASKING;
    q->why = NULL;
    q->connected = 0;
    q->link_wanted = 1;
    q->key_epoch = c->np.epoch;
    q->key_index = first;
    memcpy(q->host.key, hk.data, 33);
    memcpy(q->address, addr.data, addr.len);
    q->address_len = (uint8_t)addr.len;
    memcpy(q->link.local.key, pub, 33);
    q->link.remote = q->host;
    q->asked_ms = c->ports.clock.now_ms(c->ports.clock.ctx);
    q->ended_ms = 0;
    q->deadline = c->ports.clock.mono_ms(c->ports.clock.ctx) + DQ_LIMIT_MS;
    {
        size_t k = 0;
        uint32_t s = q->serial;
        char d[12];
        int nd = 0;
        q->id[k++] = 'q';
        q->id[k++] = '_';
        do { d[nd++] = (char)('0' + s % 10); s /= 10; } while (s);
        while (nd) q->id[k++] = d[--nd];
        q->id[k] = 0;
    }
    gz_action_t a = {.kind = GZ_ACTION_CONNECT};
    a.u.connect.host = q->host;
    a.u.connect.address.data = q->address;
    a.u.connect.address.len = q->address_len;
    a.u.connect.key_epoch = q->key_epoch;
    a.u.connect.key_index = q->key_index;
    if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
    if ((st = dq_timer(out, DQ_LIMIT_MS)) != GZ_OK) return st;
    if ((st = gz_view_query(c, out)) != GZ_OK) return st;
    return dq_result(c, cmd, 202, NULL, q->id, out);
}

int gz_dq_link(const gz_node_t *c, const gz_link_t *link)
{
    return !c->cfg.host && c->dq.link_wanted && np_same_link(&c->dq.link, link);
}

/* PEER_CONNECTED or PEER_DISCONNECTED on the query's link. */
gz_status_t gz_dq_peer(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    dq_t *q = &c->dq;
    gz_status_t st = gz_c_node_bracket_begin(c, out);
    if (st != GZ_OK) return st;
    if (ev->kind == GZ_EVENT_PEER_CONNECTED && q->state == DQ_ASKING) {
        gz_action_t a = {.kind = GZ_ACTION_SEND};
        q->connected = 1;
        a.u.send.link = q->link;
        a.u.send.kind = GZ_MSG_KIND_HELLO;
        memset(a.u.send.scope, 0, 32);
        a.u.send.records.data = NULL;
        a.u.send.records.len = 0;
        st = gz_action_list_add(out, &a);
    } else if (ev->kind == GZ_EVENT_PEER_DISCONNECTED) {
        q->connected = 0;
    }
    if (st == GZ_OK) return gz_c_node_bracket_end(c, out);
    c->bracket_on = 0;
    return st;
}

/* A message on the query's link: a terms_offer is checked and kept. */
gz_status_t gz_dq_message(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    dq_t *q = &c->dq;
    gz_lobby_msg_t m;
    gz_terms_outer_t o;
    gz_terms_current_t v;
    gz_tree_crypto_t tc;
    uint8_t od[32], cd[32];
    const uint8_t *scope = ev->u.message.scope;
    gz_status_t st = gz_c_node_bracket_begin(c, out);
    if (st != GZ_OK) return st;
    memset(&tc, 0, sizeof tc);
    tc.ctx = c;
    tc.point_valid = dq_point;
    tc.verify = dq_verify;
    if (q->state != DQ_ASKING || ev->u.message.kind != GZ_KIND_TERMS_OFFER || all_zero(scope, 32) ||
        gz_lobby_decode(ev->u.message.kind, scope, ev->u.message.records.data, ev->u.message.records.len, &m) != GZ_DEC_OK ||
        gz_terms_receive(m.outer, m.outer_len, m.outer_sig, m.current, m.current_len, m.current_sig, scope, q->host.key,
                         gz_lobby_policy(), &tc, &o, od, &v, cd) != GZ_TERMS_OK) {
        c->np.drops[DROP_DISCOVERY]++;
    } else {
        int k;
        for (k = 0; k < q->n && memcmp(q->offers[k].scope, scope, 32) != 0; k++) {}
        if (k == q->n && q->n < DQ_MAX_OFFERS) q->n++;
        if (k < q->n) {
            dq_offer_t *f = &q->offers[k];
            memcpy(f->scope, scope, 32);
            memcpy(f->outer, m.outer, m.outer_len);
            f->outer_len = m.outer_len;
            memcpy(f->outer_sig, m.outer_sig, 64);
            memcpy(f->current, m.current, m.current_len);
            f->current_len = m.current_len;
            memcpy(f->current_sig, m.current_sig, 64);
            f->terms = o;
            f->values = v;
            if (!gz_api_local_id(c, scope)) st = gz_api_seen_id(c, scope);
            if (st == GZ_OK) st = gz_view_seen(c, k, out);
            if (st == GZ_OK) st = dq_timer(out, DQ_QUIET_MS);
            q->quiet = c->ports.clock.mono_ms(c->ports.clock.ctx) + DQ_QUIET_MS;
        }
    }
    if (st == GZ_OK) return gz_c_node_bracket_end(c, out);
    c->bracket_on = 0;
    return st;
}

/* NP_TIMER_DISCOVERY: answered once quiet after an offer; failed at the limit. */
gz_status_t gz_dq_timer(gz_node_t *c, gz_action_list_t *out)
{
    dq_t *q = &c->dq;
    uint64_t now = c->ports.clock.mono_ms(c->ports.clock.ctx);
    gz_status_t st = gz_c_node_bracket_begin(c, out);
    if (st != GZ_OK) return st;
    if (q->state == DQ_ASKING) {
        if (q->n && now >= q->quiet) st = dq_end(c, DQ_ANSWERED, NULL, out);
        else if (now >= q->deadline) st = dq_end(c, DQ_FAILED, q->connected ? "no_answer" : "unreachable", out);
        else st = dq_timer(out, (q->n && q->quiet < q->deadline ? q->quiet : q->deadline) - now);
    }
    if (st == GZ_OK) return gz_c_node_bracket_end(c, out);
    c->bracket_on = 0;
    return st;
}
