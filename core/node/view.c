/* The view objects (step P6a; contract-v2.md section 11; view.h).
 *
 * Each object is built from the engines' state when it may have changed, and
 * emitted only if its bytes differ from the last ones emitted (a 64-bit hash
 * of the fields, the version left out). It is appended after the step that
 * changed it, so it follows that step's saves in the list (node.h rule 8).
 * At every start the whole view is emitted again (rule 7). Building a view
 * reads state and writes nothing but the hash: it can never change what the
 * engines do, and a view that does not fit its buffer is a bug of this file
 * (the sizes are bounded below), never a peer's doing. */
#include "internal.h"
#include <string.h>
#include "gazpacho/view.h"
#include "gazpacho/terms.h"

static uint64_t wall(gz_node_t *c) { return c->ports.clock.now_ms(c->ports.clock.ctx); }

static uint64_t fnv(const uint8_t *b, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 0x100000001b3ull;
    return h ? h : 1;
}

typedef struct { uint8_t *b; size_t cap, at; int bad; } vw_t;

static void put(vw_t *w, uint64_t type, const void *v, size_t n)
{
    if (!w->bad && gz_rec_put(w->b, w->cap, &w->at, type, (const uint8_t *)v, n) != GZ_OK) w->bad = 1;
}

static void put8(vw_t *w, uint64_t type, uint8_t v) { put(w, type, &v, 1); }
static void put16(vw_t *w, uint64_t type, uint16_t v) { uint8_t b[2]; gz_put_u16(b, v); put(w, type, b, 2); }
static void put32(vw_t *w, uint64_t type, uint32_t v) { uint8_t b[4]; gz_put_u32(b, v); put(w, type, b, 4); }
static void put64(vw_t *w, uint64_t type, uint64_t v) { uint8_t b[8]; gz_put_u64(b, v); put(w, type, b, 8); }

static size_t slen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

/* Emit one object: the fields in c->view.body (from type 6), behind its id
 * and a version, if the hash says they changed or `force` is set. */
static gz_status_t emit(gz_node_t *c, uint8_t kind, const char *id, const uint8_t *fields, size_t n, int gone,
                        uint64_t *last, int force, gz_action_list_t *out)
{
    vw_t w = {c->view.head, sizeof c->view.head, 0, 0};
    uint64_t h = gone ? 0x676f6e65ull : fnv(fields, n);
    if (!force && *last == h) return GZ_OK;
    *last = h;
    put(&w, GZ_VIEW_REC_ID, id, slen(id));
    if (gone) put(&w, GZ_VIEW_REC_GONE, NULL, 0);
    put64(&w, GZ_VIEW_REC_VERSION, (c->incarnation << 32) | (++c->view.counter & 0xffffffffu));
    if (w.bad || w.at + n > sizeof c->view.head) return gz_c_bug(c, ENG_NODE);
    if (!gone && n) {
        memmove(c->view.head + w.at, fields, n);
        w.at += n;
    }
    gz_action_t a = {.kind = GZ_ACTION_NOTIFY};
    a.u.notify.code = GZ_NOTIFY_VIEW(kind);
    a.u.notify.bytes.data = c->view.head;
    a.u.notify.bytes.len = w.at;
    return gz_action_list_add(out, &a);
}

/* ---- a member's lobby (kind 2) ---------------------------------------------- */

static int gate_state(const gz_node_t *c, const slot_t *s);

/* Out of the count by its gate (14.3 rule 3): joined, wanting to be ready, its
 * gate closed (or its "locked" unready sent). */
static int member_locked(const gz_node_t *c, const slot_t *s)
{
    const gz_lobby_member_t *m = &s->lobby.m;
    return m->joined && !m->ended && !m->ready && !m->user_unready && (!gate_state(c, s) || m->unready_reason == 3);
}

static uint8_t member_seat(const gz_lobby_member_t *m)
{
    if (m->ended) {
        if (m->end_how == GZ_LOBBY_END_REMOVED) return GZ_VSEAT_REMOVED;
        if (m->end_how == GZ_LOBBY_END_REFUSED) return GZ_VSEAT_REFUSED_BY_HOST;
        if (m->left) return GZ_VSEAT_LEFT;
    }
    if (!m->joined) return m->ended ? GZ_VSEAT_NONE : (m->join_len ? GZ_VSEAT_JOINING : GZ_VSEAT_NONE);
    if (m->seat_state == GZ_SEAT_CHOSEN) return GZ_VSEAT_CHOSEN;
    if (m->seat_state == GZ_SEAT_NOT_CHOSEN) return GZ_VSEAT_NOT_CHOSEN;
    return m->ready ? GZ_VSEAT_READY : GZ_VSEAT_JOINED;
}

static uint8_t member_outcome(const gz_lobby_member_t *m, uint16_t *reason)
{
    *reason = 0;
    if (m->round_state >= GZ_LOBBY_FUNDING) return GZ_OUTCOME_STARTED;
    if (m->end_how == GZ_LOBBY_END_BAD_TERMS) return GZ_OUTCOME_REFUSED_AT_CHECK;
    if (m->end_how == GZ_LOBBY_END_REFUSED) { *reason = m->leave_reason; return GZ_OUTCOME_REFUSED_BY_HOST; }
    if (m->end_how == GZ_LOBBY_END_REMOVED) return GZ_OUTCOME_REMOVED;
    if (m->left) { *reason = m->leave_reason; return GZ_OUTCOME_LEFT; }
    if (m->ended && m->lobby_state == GZ_LOBBY_CANCELLED) return GZ_OUTCOME_CANCELLED;
    if (m->seat_state == GZ_SEAT_NOT_CHOSEN) return GZ_OUTCOME_NOT_CHOSEN;
    return GZ_OUTCOME_NONE;
}

static uint8_t member_doing(const gz_node_t *c, const slot_t *s)
{
    const gz_lobby_member_t *m = &s->lobby.m;
    if (m->ended) return m->lobby_state == GZ_LOBBY_CANCELLED && !m->left ? GZ_DOING_LOBBY_CANCELLED : GZ_DOING_NONE;
    if (m->round_state >= GZ_LOBBY_FUNDING) return GZ_DOING_AWAITING_FUNDING;
    if (!m->joined) return GZ_DOING_JOINING;
    if (c->api.pause != GZ_PAUSE_OFF) return GZ_DOING_PAUSED;
    if (m->lobby_state == GZ_LOBBY_SIGNING && m->seat_state == GZ_SEAT_CHOSEN) return GZ_DOING_SIGNING;
    if (m->lobby_state == GZ_LOBBY_READY_CHECK && m->ready) return GZ_DOING_READY_CHECK;
    if (member_locked(c, s)) return GZ_DOING_IN_LOBBY_NOT_COUNTED;
    return m->ready ? GZ_DOING_IN_LOBBY_WAITING : GZ_DOING_IN_LOBBY_NOT_READY;
}

/* The failing term's two values: the member's limit and the offer (the
 * current value when the term does not fit now, else the range's top). */
static void fit_values(const gz_lobby_member_t *m, uint8_t term, int cls, uint64_t *yours, uint64_t *offered)
{
    const gz_terms_limits_t *l = &m->cond.limits;
    const gz_terms_outer_t *o = &m->terms;
    *yours = *offered = 0;
    switch (term) {
    case 0: return;
    case GZ_TT_PROFILE: *yours = l->profiles; *offered = o->profile; return;
    case GZ_TT_MINIMUM: *yours = l->min_members; *offered = o->minimum; return;
    case GZ_TT_LIFETIME:
        *offered = o->lifetime_blocks;
        *yours = l->min_lifetime && o->lifetime_blocks < l->min_lifetime ? l->min_lifetime : l->max_lifetime;
        return;
    case GZ_TT_CHANNEL: *yours = l->min_channel_sat; *offered = o->channel_sat; return;
    case GZ_TT_FEERATE: *yours = l->max_tree_feerate; *offered = o->tree_feerate; return;
    default: break;
    }
    for (uint8_t j = 0; j < l->n_max && j < GZ_TERMS_MAX_ADJ; j++)
        if (l->max[j].type == term) *yours = l->max[j].max;
    if (cls == GZ_FIT_NO) {
        for (uint8_t j = 0; j < m->values.n_values && j < GZ_TERMS_MAX_ADJ; j++)
            if (m->values.val[j].type == term) *offered = m->values.val[j].value;
    } else {
        for (uint8_t j = 0; j < o->n_adj && j < GZ_TERMS_MAX_ADJ; j++)
            if (o->adj[j].type == term) *offered = o->adj[j].max;
    }
}

static uint8_t gate_kind(const gz_node_t *c)
{
    switch (c->cfg.member_signing) {
    case GZ_MEMBER_SIGNING_AUTO: return GZ_GATE_NONE;
    case GZ_MEMBER_SIGNING_WHEN_UNLOCKED: return GZ_GATE_NODE;
    default: return GZ_GATE_PER_LOBBY;
    }
}

static int gate_state(const gz_node_t *c, const slot_t *s)
{
    switch (gate_kind(c)) {
    case GZ_GATE_NONE: return 1;
    case GZ_GATE_NODE: return c->unlocked != 0;
    default: return s->gate_open != 0;
    }
}

/* Track when the seat's stage, seat, doing, gate or lock last changed
 * (memory only; at a start, the start's time). */
static void since(gz_node_t *c, slot_t *s, uint8_t stage, uint8_t seat, uint8_t doing, int gate, int locked)
{
    uint64_t now = wall(c);
    uint32_t key = (uint32_t)stage | (uint32_t)seat << 8 | (uint32_t)doing << 16;
    if (!s->view.since_ms || s->view.key != key) {
        s->view.key = key;
        s->view.since_ms = now;
    }
    if (!s->view.gate_ms || s->view.gate != gate) {
        s->view.gate = gate;
        s->view.gate_ms = now;
    }
    if (locked && !s->view.locked_ms) s->view.locked_ms = now;
    if (!locked) s->view.locked_ms = 0;
}

static size_t member_view(gz_node_t *c, slot_t *s)
{
    const gz_lobby_member_t *m = &s->lobby.m;
    vw_t w = {c->view.body, sizeof c->view.body, 0, 0};
    uint8_t seat = member_seat(m), doing = member_doing(c, s), g[42];
    int gate = gate_state(c, s), locked = member_locked(c, s);
    uint16_t reason;
    uint8_t outcome = member_outcome(m, &reason);
    uint8_t f[18], z[36], o[3], term = 0;   /* function scope: no ASan use-after-scope calls (isolation) */
    uint64_t yours, offered;
    since(c, s, (uint8_t)m->lobby_state, seat, doing, gate, locked);
    put(&w, GZ_VLB_FINGERPRINT, s->scope, 32);
    put(&w, GZ_VLB_HOST_KEY, s->host_key.key, 33);
    if (s->address_len) put(&w, GZ_VLB_HOST_ADDRESS, s->address, s->address_len);
    put8(&w, GZ_VLB_STAGE, (uint8_t)m->lobby_state);
    put8(&w, GZ_VLB_SEAT, seat);
    if (m->ready) put32(&w, GZ_VLB_READY_VERSION, m->ready_version);
    if (seat != GZ_VSEAT_NONE) {
        size_t n = 10;
        g[0] = gate_kind(c);
        g[1] = (uint8_t)gate;
        gz_put_u64(g + 2, s->view.gate_ms);
        if (g[0] == GZ_GATE_PER_LOBBY && gate && m->ready && m->have_terms && m->ready_version == m->values.version) {
            memcpy(g + 10, m->current_digest, 32);
            n = 42;
        }
        put(&w, GZ_VLB_GATE, g, n);
    }
    if (locked) put64(&w, GZ_VLB_LOCKED_SINCE, s->view.locked_ms);
    if (m->have_terms) {
        int cls = gz_lobby_classify(&m->terms, &m->values, &m->cond, &term);
        put(&w, GZ_VLB_OUTER, m->outer, m->outer_len);
        put(&w, GZ_VLB_OUTER_SIG, m->outer_sig, 64);
        if (m->current_len) {
            put(&w, GZ_VLB_CURRENT, m->current, m->current_len);
            put(&w, GZ_VLB_CURRENT_SIG, m->current_sig, 64);
        }
        if (m->frozen) {
            gz_put_u32(z, m->frozen_version);
            memcpy(z + 4, m->frozen_digest, 32);
            put(&w, GZ_VLB_FROZEN, z, 36);
        }
        fit_values(m, term, cls, &yours, &offered);
        f[0] = cls == GZ_FIT_YES ? GZ_VFIT_FITS : cls == GZ_FIT_NOW ? GZ_VFIT_FITS_NOW_ONLY : GZ_VFIT_DOES_NOT_FIT;
        f[1] = term;
        gz_put_u64(f + 2, yours);
        gz_put_u64(f + 10, offered);
        put(&w, GZ_VLB_FIT, f, 18);
    }
    if (outcome != GZ_OUTCOME_NONE) {
        o[0] = outcome;
        gz_put_u16(o + 1, reason);
        put(&w, GZ_VLB_OUTCOME, o, 3);
    }
    if (m->round_state) put8(&w, GZ_VLB_ROUND, (uint8_t)m->round_state);
    put8(&w, GZ_VLB_DOING, doing);
    put64(&w, GZ_VLB_SINCE, s->view.since_ms);
    if (c->api.pause != GZ_PAUSE_OFF && gz_api_held(c, s->scope) >= 0) put8(&w, GZ_VLB_PAUSED, 1);
    return w.bad ? 0 : w.at;
}

/* ---- a hosted lobby (kind 3) ---------------------------------------------- */

static uint8_t host_doing(const gz_lobby_host_t *h)
{
    switch (h->state) {
    case GZ_LOBBY_OPEN: return GZ_DOING_HOSTING_OPEN;
    case GZ_LOBBY_READY_CHECK: return GZ_DOING_READY_CHECK;
    case GZ_LOBBY_SIGNING: return GZ_DOING_SIGNING;
    case GZ_LOBBY_FUNDING:
    case GZ_LOBBY_ACTIVE: return GZ_DOING_AWAITING_FUNDING;
    case GZ_LOBBY_CANCELLED: return GZ_DOING_LOBBY_CANCELLED;
    default: return GZ_DOING_NONE;
    }
}

static int host_connected(const gz_lobby_host_t *h, const uint8_t key[33])
{
    for (int i = 0; i < GZ_LOBBY_MAX_CONNS; i++)
        if (h->conns[i].used && memcmp(h->conns[i].key, key, 33) == 0) return 1;
    return 0;
}

static size_t host_view(gz_node_t *c, slot_t *s)
{
    const gz_lobby_host_t *h = &s->lobby.h;
    vw_t w = {c->view.body, sizeof c->view.body, 0, 0};
    uint8_t *e = c->view.seats, cn[8], r[9], z[36];
    uint16_t joined = 0, ready = 0, locked = 0, refused = 0;
    size_t n = 0;
    const gz_lobby_seat_t *order[GZ_LOBBY_MAX_SEATS];
    uint8_t doing = host_doing(h);
    since(c, s, (uint8_t)h->state, 0, doing, 1, 0);
    for (int i = 0; i < h->n_seats; i++) {   /* in order of joining */
        int j;
        for (j = (int)n; j > 0 && order[j - 1]->join_seq > h->seats[i].join_seq; j--) order[j] = order[j - 1];
        order[j] = &h->seats[i];
        n++;
    }
    for (size_t k = 0; k < n; k++) {
        const gz_lobby_seat_t *q = order[k];
        uint8_t *p = e + k * GZ_VHL_SEAT_LEN, state = q->state, flags = 0;
        int in = q->state == GZ_SEAT_JOINED || q->state == GZ_SEAT_READY || q->state == GZ_SEAT_CHOSEN ||
                 q->state == GZ_SEAT_NOT_CHOSEN;
        if (in) joined++;
        if (q->state == GZ_SEAT_READY && q->ready_version == h->values.version) ready++;
        if (q->locked) { flags |= GZ_VHL_F_LOCKED; locked++; if (state == GZ_SEAT_JOINED) state = GZ_VSEAT_LOCKED; }
        if (q->refused) { flags |= GZ_VHL_F_REFUSED; refused++; if (state == GZ_SEAT_JOINED || state == GZ_SEAT_LEFT) state = GZ_VSEAT_REFUSED; }
        if (q->chosen) flags |= GZ_VHL_F_CHOSEN;
        if (q->answered) flags |= GZ_VHL_F_ANSWERED;
        if (host_connected(h, q->ckey)) flags |= GZ_VHL_F_CONNECTED;
        memcpy(p, q->ckey, 33);
        p[33] = state;
        p[34] = flags;
        gz_put_u16(p + 35, q->refused);
        p[37] = q->refused_stage;
        gz_put_u64(p + 38, q->join_seq);
        gz_put_u32(p + 46, q->ready_version);
        gz_put_u16(p + 50, q->min_members);
    }
    put(&w, GZ_VHL_FINGERPRINT, s->scope, 32);
    put8(&w, GZ_VHL_STAGE, (uint8_t)h->state);
    put(&w, GZ_VHL_OUTER, h->outer, h->outer_len);
    put(&w, GZ_VHL_OUTER_SIG, h->outer_sig, 64);
    put(&w, GZ_VHL_CURRENT, h->current, h->current_len);
    put(&w, GZ_VHL_CURRENT_SIG, h->current_sig, 64);
    gz_put_u16(cn, joined);
    gz_put_u16(cn + 2, ready);
    gz_put_u16(cn + 4, locked);
    gz_put_u16(cn + 6, refused);
    put(&w, GZ_VHL_COUNTS, cn, 8);
    if (n) put(&w, GZ_VHL_SEATS, e, n * GZ_VHL_SEAT_LEN);
    put8(&w, GZ_VHL_LISTED, (uint8_t)(s->listed != 0));
    put16(&w, GZ_VHL_STANDBYS, s->standbys);
    if (h->state >= GZ_LOBBY_CANCELLED) put16(&w, GZ_VHL_END_REASON, h->end_reason);
    r[0] = (uint8_t)(h->started != 0);
    gz_put_u64(r + 1, h->budget_ms);
    put(&w, GZ_VHL_ROUND, r, 9);
    put8(&w, GZ_VHL_DOING, doing);
    put64(&w, GZ_VHL_SINCE, s->view.since_ms);
    if (c->api.pause != GZ_PAUSE_OFF && h->state == GZ_LOBBY_OPEN) put8(&w, GZ_VHL_PAUSED, 1);
    if (h->frozen) {
        gz_put_u32(z, h->values.version);
        memcpy(z + 4, h->current_digest, 32);
        put(&w, GZ_VHL_FROZEN, z, 36);
    }
    if (gz_ls_set_aside(s)) put64(&w, GZ_VHL_SET_ASIDE, gz_ls_set_aside(s));
    return w.bad ? 0 : w.at;
}

/* ---- attention (kind 7) --------------------------------------------------- */

/* A slot's attention item (at most one at a time): unlock_to_take_part for
 * a member whose seat is locked, member_refused for a host with refused
 * seats (their count), lobby_left_out for a slot left out at this start.
 * Emitted when it appears or changes, gone when it clears; id "att_" + the
 * lobby's local id. It never carries the fingerprint, and no id is made from
 * it (7.3: never in an event; review A of PR 55, M5): every lobby slot has a
 * local id from its open, or from the start that finds it without one
 * (api.c, gz_api_resume), and a slot without one has no item until then. */
static gz_status_t attention(gz_node_t *c, slot_t *s, int force, gz_action_list_t *out)
{
    char id[GZ_LOCAL_ID_MAX + 8];
    vw_t w = {c->view.body, sizeof c->view.body, 0, 0};
    uint64_t last = 0;
    uint8_t code = 0;
    uint16_t count = 0;
    size_t k = 0;
    int ended;
    if (s->kind != SLOT_KIND_LOBBY || (s->state != SLOT_OPEN && s->state != SLOT_LEFT_OUT)) return GZ_OK;
    ended = s->state == SLOT_OPEN && (s->host ? s->lobby.h.state >= GZ_LOBBY_CANCELLED : s->lobby.m.ended);
    if (s->state == SLOT_LEFT_OUT) {
        code = GZ_ATT_LOBBY_LEFT_OUT;
    } else if (ended) {
        code = 0;
    } else if (!s->host) {
        if (member_locked(c, s) && gate_kind(c) != GZ_GATE_NONE) code = GZ_ATT_UNLOCK_TO_TAKE_PART;
    } else {
        for (int q = 0; q < s->lobby.h.n_seats; q++) count += s->lobby.h.seats[q].refused != 0;
        if (count) code = GZ_ATT_MEMBER_REFUSED;
    }
    if (!s->view.local_id[0]) return GZ_OK;
    if (!force && code == s->view.att_code && count == s->view.att_count) return GZ_OK;
    if (!code && !s->view.att_code) return GZ_OK;
    /* "att_" and the local id after its "lob_": at most 64 characters, one
     * item per lobby (review A of PR 55, N2: never cut, so never shared). */
    id[k++] = 'a'; id[k++] = 't'; id[k++] = 't'; id[k++] = '_';
    for (size_t j = memcmp(s->view.local_id, "lob_", 4) == 0 ? 4 : 0; s->view.local_id[j]; j++) id[k++] = s->view.local_id[j];
    id[k] = 0;
    s->view.att_code = code;
    s->view.att_count = count;
    if (code) {
        put8(&w, GZ_VAT_CODE, code);
        put(&w, GZ_VAT_LOBBY, s->view.local_id, slen(s->view.local_id));
        put64(&w, GZ_VAT_SINCE, wall(c));
        if (count) put16(&w, GZ_VAT_COUNT, count);
        if (w.bad) return gz_c_bug(c, ENG_NODE);
    }
    return emit(c, GZ_VIEW_ATTENTION, id, c->view.body, w.at, !code, &last, 1, out);
}

/* ---- status (kind 1) -------------------------------------------------------- */

static uint8_t slot_role(const slot_t *s) { return s->host ? GZ_ROLE_HOSTED : GZ_ROLE_JOINED; }

static size_t status_view(gz_node_t *c)
{
    vw_t w = {c->view.body, sizeof c->view.body, 0, 0};
    uint8_t p[13], sg[7], d[11 + GZ_LOCAL_ID_MAX], *e = c->view.seats;
    /* at the function's scope: a block's array this large makes an ASan build
     * call __asan_(un)poison_stack_memory, outside calls the isolation check refuses */
    uint8_t cv[4 + COND_MAX];
    size_t n = 0, pl = 0;
    int best = -1, left_out = 0;
    uint8_t best_doing = 0;
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) {
        slot_t *s = &c->slots[i];
        if (s->state == SLOT_LEFT_OUT) left_out++;
        if (s->state != SLOT_OPEN || s->kind != SLOT_KIND_LOBBY || !s->view.local_id[0]) continue;
        uint8_t stage = (uint8_t)(s->host ? s->lobby.h.state : s->lobby.m.lobby_state);
        uint8_t doing = s->host ? host_doing(&s->lobby.h) : member_doing(c, s);
        size_t idl = slen(s->view.local_id);
        e[n++] = slot_role(s);
        e[n++] = stage;
        e[n++] = doing;
        gz_put_u64(e + n, s->view.since_ms);
        n += 8;
        e[n++] = (uint8_t)idl;
        memcpy(e + n, s->view.local_id, idl);
        n += idl;
        /* doing: the lobby nearest to needing the person, by its code's rank */
        if (best < 0 || doing > best_doing) { best = i; best_doing = doing; }
    }
    put8(&w, GZ_VST_ROLE, (uint8_t)(c->cfg.host != 0));
    p[0] = (uint8_t)c->api.pause;
    gz_put_u64(p + 1, c->api.pause_since);
    gz_put_u32(p + 9, c->api.pause_version);
    put(&w, GZ_VST_PAUSE, p, 13);
    for (int k = 0; k < c->api.n_held; k++) {
        int i = gz_route_slot_by_scope(c, c->api.held[k]);
        const char *id = i >= 0 ? c->slots[i].view.local_id : gz_api_local_id(c, c->api.held[k]);
        if (!id || !id[0]) continue;
        size_t idl = slen(id);
        if (pl) c->view.list[pl++] = ',';
        memcpy(c->view.list + pl, id, idl);
        pl += idl;
    }
    if (pl) put(&w, GZ_VST_PAUSE_LOBBIES, c->view.list, pl);
    sg[0] = (uint8_t)c->cfg.member_signing;
    sg[1] = c->api.have_signing && c->api.signing_saved != (uint8_t)c->cfg.member_signing ? c->api.signing_saved : 0xff;
    gz_put_u32(sg + 2, c->api.signing_version);
    sg[6] = (uint8_t)c->cfg.host_funding;
    put(&w, GZ_VST_SIGNING, sg, 7);
    put8(&w, GZ_VST_NODE_GATE, (uint8_t)(c->unlocked != 0));
    memset(d, 0, sizeof d);
    if (best >= 0) {
        size_t idl = slen(c->slots[best].view.local_id);
        d[0] = best_doing;
        d[1] = slot_role(&c->slots[best]);
        gz_put_u64(d + 2, c->slots[best].view.since_ms);
        memcpy(d + 10, c->slots[best].view.local_id, idl);
        put(&w, GZ_VST_DOING, d, 10 + idl);
    } else {
        d[0] = c->api.pause != GZ_PAUSE_OFF ? GZ_DOING_PAUSED : GZ_DOING_NONE;
        put(&w, GZ_VST_DOING, d, 10);
    }
    if (n) put(&w, GZ_VST_LOBBIES, e, n);
    if (left_out) put16(&w, GZ_VST_LEFT_OUT, (uint16_t)left_out);
    if (c->api.have_cond) {
        gz_put_u32(cv, c->api.cond_version);
        memcpy(cv + 4, c->api.cond_bytes, c->api.cond_len);
        put(&w, GZ_VST_CONDITIONS, cv, 4 + c->api.cond_len);
        if (c->api.preset[0]) put(&w, GZ_VST_PRESET, c->api.preset, slen(c->api.preset));
    }
    return w.bad ? 0 : w.at;
}

/* ---- the entry points ------------------------------------------------------ */

gz_status_t gz_view_status(gz_node_t *c, int force, gz_action_list_t *out)
{
    size_t n = status_view(c);
    if (!n) return gz_c_bug(c, ENG_NODE);
    return emit(c, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID, c->view.body, n, 0, &c->view.status_hash, force, out);
}

/* After a step of slot i (and at the start): its object, its attention items,
 * and the status. A slot without a local id (none saved: a slot opened by a
 * build without the API engine) has no object. */
static gz_status_t slot_only(gz_node_t *c, int i, int force, gz_action_list_t *out)
{
    slot_t *s = &c->slots[i];
    gz_status_t st = GZ_OK;
    if (s->kind == SLOT_KIND_LOBBY && s->state == SLOT_OPEN && s->view.local_id[0]) {
        size_t n = s->host ? host_view(c, s) : member_view(c, s);
        if (!n) return gz_c_bug(c, ENG_NODE);
        st = emit(c, s->host ? GZ_VIEW_HOST_LOBBY : GZ_VIEW_LOBBY, s->view.local_id, c->view.body, n, 0,
                  &s->view.hash, force, out);
    }
    return st == GZ_OK ? attention(c, s, force, out) : st;
}

gz_status_t gz_view_slot(gz_node_t *c, int i, int force, gz_action_list_t *out)
{
    gz_status_t st = slot_only(c, i, force, out);
    return st == GZ_OK ? gz_view_status(c, 0, out) : st;
}

/* An ended lobby of the index (np.ended), at a start: its final stage and
 * reason under its local id. */
static gz_status_t ended_view(gz_node_t *c, const np_ended_t *e, gz_action_list_t *out)
{
    const char *id = gz_api_local_id(c, e->scope);
    vw_t w = {c->view.body, sizeof c->view.body, 0, 0};
    uint64_t last = 0;
    uint8_t o[3] = {GZ_OUTCOME_CANCELLED, 0, 0};
    if (!id || !id[0]) return GZ_OK;
    if (c->cfg.host) {
        put(&w, GZ_VHL_FINGERPRINT, e->scope, 32);
        put8(&w, GZ_VHL_STAGE, e->state);
        put16(&w, GZ_VHL_END_REASON, e->reason);
        put8(&w, GZ_VHL_DOING, GZ_DOING_NONE);
    } else {
        put(&w, GZ_VLB_FINGERPRINT, e->scope, 32);
        put8(&w, GZ_VLB_STAGE, e->state);
        gz_put_u16(o + 1, e->reason);
        if (e->state == GZ_LOBBY_CANCELLED) put(&w, GZ_VLB_OUTCOME, o, 3);
        put8(&w, GZ_VLB_DOING, GZ_DOING_NONE);
    }
    if (w.bad) return gz_c_bug(c, ENG_NODE);
    return emit(c, c->cfg.host ? GZ_VIEW_HOST_LOBBY : GZ_VIEW_LOBBY, id, c->view.body, w.at, 0, &last, 1, out);
}

/* Rule 7: the whole view at the end of every start, over several calls so
 * that each node bracket stays within its step (8.3): the ended lobbies 64
 * at a time, then one slot a call, then the status. 1 in *done when over. */
gz_status_t gz_view_start(gz_node_t *c, gz_action_list_t *out, int *done)
{
    size_t n_ended = sizeof c->np.ended / sizeof c->np.ended[0], step = c->view.start_step++;
    size_t chunks = (n_ended + 63) / 64;
    gz_status_t st = gz_c_node_bracket_begin(c, out);
    *done = 0;
    if (step < chunks) {
        for (size_t k = step * 64; st == GZ_OK && k < n_ended && k < step * 64 + 64; k++)
            if (c->np.ended[k].used) st = ended_view(c, &c->np.ended[k], out);
    } else if (step < chunks + GZ_NODE_MAX_SLOTS) {
        int i = (int)(step - chunks);
        c->slots[i].view.att_code = 0;
        c->slots[i].view.att_count = 0;
        st = slot_only(c, i, 1, out); /* the status once, at the end */
    } else {
        st = gz_view_status(c, 1, out);
        *done = 1;
        c->view.start_step = 0;
    }
    if (st == GZ_OK) return gz_c_node_bracket_end(c, out);
    c->bracket_on = 0;
    return st;
}
