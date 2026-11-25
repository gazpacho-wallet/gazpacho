/* The local-API engine (area 0x000d; step P6a; spec/local-api.md 7.4, 7.5,
 * 11.3, 14.3; contract-v2.md section 11). It runs inside the node part:
 *
 * - request ids: a command that carries a digest (record 6, the API server's
 *   RFC 8785 digest) is an API request. Its id is checked before the command
 *   runs (a replay answers the saved status, an id bound to another request
 *   answers 409 request_id_reused), and after it, if it saved anything, the
 *   `request_id` record is put right after its first save, so that the two
 *   are one batch, before the command-result notice (rule 8). A command
 *   without a digest (the program's own, a test's) keeps no id. An id is
 *   kept until the object it acted on has ended and 30 days have passed
 *   (7.4); a new request that finds the table full of kept ids answers
 *   503 node_busy and does nothing.
 * - pause: saved before anything it does. A member's lobby whose round has
 *   partial signatures out is held (held_for_signing) until that round ends;
 *   every other member lobby is left, after a round_abort where its round had
 *   begun (lobbyslot.c, gz_ls_pause_apply). A host runs no check while paused
 *   and cancels at the deadline (the host's `paused` port).
 * - the signing setting: saved with a version; in force from the next start.
 *   A widening to `auto` needs an API request and the echo; `when_unlocked`
 *   is 501 in this release (14.3).
 * - the conditions (13.2): saved with a version, in force at once. A change
 *   that loosens anything needs an API request and the exact list of what it
 *   loosens; one that would leave a lobby whose round is on is refused
 *   (signing_now). Every member lobby they fit worse than its own copy is
 *   left, reason 1, in the batch of the save where its link is up, else once
 *   it is (lobbyslot.c, cond_apply), and at every start from the record.
 * - local ids: "lob_" and 16 random hex digits, saved with the slot's first
 *   batch; kept for the ended lobbies of the index. */
#include "internal.h"
#include <string.h>
#include "gazpacho/view.h"

#define API_KEEP_MS (30ull * 24u * 3600u * 1000u) /* 7.4: 30 days after the object ended (proposed) */

static uint64_t wall(gz_node_t *c) { return c->ports.clock.now_ms(c->ports.clock.ctx); }

static size_t slen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static int arg(gz_bytes_t cmd, uint64_t type, size_t len, gz_bytes_t *v)
{
    return gz_rec_find(cmd, type, v) == 1 && (len == 0 || v->len == len);
}

static int id_char(uint8_t ch)
{
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
}

static int id_chars(gz_bytes_t b)
{
    for (size_t k = 0; k < b.len; k++)
        if (!id_char(b.data[k])) return 0;
    return 1;
}

static int printable(gz_bytes_t b)
{
    for (size_t i = 0; i < b.len; i++)
        if (b.data[i] < 0x20 || b.data[i] > 0x7e || b.data[i] == '"' || b.data[i] == '\\') return 0;
    return 1;
}

/* A request's id, method and path as the live path and the load both check
 * them: an id of 16 to 64 id characters, a method and a path within their
 * bounds and printable (they are copied into a 409's params unescaped). */
static int parts_ok(gz_bytes_t rid, gz_bytes_t method, gz_bytes_t path)
{
    return rid.len >= 16 && rid.len <= GZ_CMD_MAX_REQUEST_ID && id_chars(rid) && method.len <= API_MAX_METHOD &&
           path.len <= API_MAX_PATH && printable(method) && printable(path);
}

/* ---- local ids ----------------------------------------------------------- */

static api_lid_t *lid_find(gz_node_t *c, const uint8_t scope[32])
{
    for (int k = 0; k < API_MAX_IDS; k++)
        if (c->api.ids[k].used && memcmp(c->api.ids[k].scope, scope, 32) == 0) return &c->api.ids[k];
    return NULL;
}

static api_lid_t *lid_by_id(gz_node_t *c, const char *id, size_t len)
{
    for (int k = 0; k < API_MAX_IDS; k++)
        if (c->api.ids[k].used && slen(c->api.ids[k].id) == len && memcmp(c->api.ids[k].id, id, len) == 0)
            return &c->api.ids[k];
    return NULL;
}

static int slot_holds(const gz_node_t *c, const uint8_t scope[32])
{
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++)
        if ((c->slots[i].state == SLOT_OPEN || c->slots[i].state == SLOT_LEFT_OUT) &&
            c->slots[i].kind == SLOT_KIND_LOBBY && memcmp(c->slots[i].scope, scope, 32) == 0)
            return 1;
    return 0;
}

/* 1 if a kept request id names this lobby's local id. */
static int lid_named(const gz_node_t *c, const api_lid_t *e)
{
    size_t n = slen(e->id);
    for (int k = 0; k < GZ_API_MAX_REQUESTS; k++)
        if (c->api.reqs[k].used && slen(c->api.reqs[k].object) == n && memcmp(c->api.reqs[k].object, e->id, n) == 0)
            return 1;
    return 0;
}

/* Keep scope -> id; when full, the oldest whose lobby holds no slot goes,
 * one that no kept request id names first (an ended lobby older than the
 * index then has no object). */
static void lid_keep(gz_node_t *c, const uint8_t scope[32], const char *id, size_t len)
{
    api_lid_t *e = lid_find(c, scope);
    if (!e) {
        int best = -1, best_named = 1;
        for (int k = 0; k < API_MAX_IDS && !e; k++)
            if (!c->api.ids[k].used) e = &c->api.ids[k];
        for (int k = 0; k < API_MAX_IDS && !e; k++) {
            if (slot_holds(c, c->api.ids[k].scope)) continue;
            int named = lid_named(c, &c->api.ids[k]);
            if (best < 0 || named < best_named || (named == best_named && c->api.ids[k].seq < c->api.ids[best].seq)) {
                best = k;
                best_named = named;
            }
        }
        if (!e && best >= 0) e = &c->api.ids[best];
        if (!e) return;
    }
    memset(e, 0, sizeof *e);
    e->used = 1;
    e->seq = ++c->api.id_seq;
    memcpy(e->scope, scope, 32);
    memcpy(e->id, id, len < GZ_LOCAL_ID_MAX ? len : GZ_LOCAL_ID_MAX);
}

const char *gz_api_local_id(gz_node_t *c, const uint8_t scope[32])
{
    api_lid_t *e = lid_find(c, scope);
    return e ? e->id : NULL;
}

/* The lobby's slot ended: from now its request ids run their 30 days. */
void gz_api_slot_ended(gz_node_t *c, const uint8_t scope[32])
{
    api_lid_t *e = lid_find(c, scope);
    if (e && !e->ended_ms) e->ended_ms = wall(c);
}

/* A fresh local id for slot i, saved alone in a SAVE appended to `out`:
 * right after its slot_opened at an open (one batch), or at a start for a
 * slot that has none. */
static gz_status_t new_local_id(gz_node_t *c, int i, gz_action_list_t *out)
{
    static const char x[] = "0123456789abcdef";
    slot_t *s = &c->slots[i];
    uint8_t r[8], rec[80];
    char id[24];
    size_t at = 0;
    gz_status_t st;
    for (int tries = 0;; tries++) {
        c->ports.random.fill(c->ports.random.ctx, GZ_RANDOM_ORDINARY, r, sizeof r);
        /* Mixed with the slot serial and the try, so that two slots never share an
         * id even where the random source repeats (a test port). */
        for (int k = 0; k < 4; k++) r[4 + k] ^= (uint8_t)((s->serial + (uint32_t)tries) >> (24 - 8 * k));
        memcpy(id, "lob_", 4);
        for (int k = 0; k < 8; k++) {
            id[4 + 2 * k] = x[r[k] >> 4];
            id[5 + 2 * k] = x[r[k] & 15];
        }
        id[20] = 0;
        if (!lid_by_id(c, id, 20)) break;
        if (tries == 64) return gz_c_bug(c, ENG_NODE); /* a random source that repeats itself */
    }
    memset(s->view.local_id, 0, sizeof s->view.local_id);
    memcpy(s->view.local_id, id, 21);
    lid_keep(c, s->scope, id, 20);
    if ((st = gz_rec_put(rec, sizeof rec, &at, 2, s->scope, 32)) != GZ_OK ||
        (st = gz_rec_put(rec, sizeof rec, &at, 4, (const uint8_t *)id, 20)) != GZ_OK)
        return gz_c_bug(c, ENG_NODE);
    gz_record_t rr = {GZ_RECORD_LOCAL_IDS, {rec, at}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &rr;
    a.u.save.n_records = 1;
    return gz_action_list_add(out, &a);
}

/* A new slot's local id, saved right after its slot_opened (one batch). A
 * lobby seen in a query already has its id for the run (7.3): the slot
 * keeps it, so the id the interface holds names the lobby it joined. */
gz_status_t gz_api_slot_opened(gz_node_t *c, int i, gz_action_list_t *out)
{
    slot_t *s = &c->slots[i];
    api_lid_t *e = lid_find(c, s->scope);
    c->api.opened = i + 1;
    if (e) {
        uint8_t rec[120];
        size_t at = 0, n = slen(e->id);
        memset(s->view.local_id, 0, sizeof s->view.local_id);
        memcpy(s->view.local_id, e->id, n);
        e->ended_ms = 0;
        if (gz_rec_put(rec, sizeof rec, &at, 2, s->scope, 32) != GZ_OK ||
            gz_rec_put(rec, sizeof rec, &at, 4, (const uint8_t *)e->id, n) != GZ_OK)
            return gz_c_bug(c, ENG_NODE);
        gz_record_t rr = {GZ_RECORD_LOCAL_IDS, {rec, at}};
        gz_action_t a = {.kind = GZ_ACTION_SAVE};
        a.u.save.records = &rr;
        a.u.save.n_records = 1;
        return gz_action_list_add(out, &a);
    }
    return new_local_id(c, i, out);
}

/* A lobby seen in a query for a host's lobbies (discovery.c): a local id
 * for the run, kept in memory only (7.3: after a restart it gets a new one
 * when it is seen again). Made like a slot's, mixed with the query serial. */
gz_status_t gz_api_seen_id(gz_node_t *c, const uint8_t scope[32])
{
    static const char x[] = "0123456789abcdef";
    uint8_t r[8];
    char id[24];
    for (int tries = 0;; tries++) {
        c->ports.random.fill(c->ports.random.ctx, GZ_RANDOM_ORDINARY, r, sizeof r);
        for (int k = 0; k < 4; k++) r[4 + k] ^= (uint8_t)((0x80000000u + c->dq.serial * 64u + (uint32_t)tries) >> (24 - 8 * k));
        memcpy(id, "lob_", 4);
        for (int k = 0; k < 8; k++) {
            id[4 + 2 * k] = x[r[k] >> 4];
            id[5 + 2 * k] = x[r[k] & 15];
        }
        id[20] = 0;
        if (!lid_by_id(c, id, 20)) break;
        if (tries == 64) return gz_c_bug(c, ENG_NODE);
    }
    lid_keep(c, scope, id, 20);
    if (lid_find(c, scope)) lid_find(c, scope)->ended_ms = wall(c); /* no slot: its ids age as an ended lobby's */
    return GZ_OK;
}

/* The member's conditions for a lobby it has not joined (a query's fit):
 * the saved conditions (0x000d0008, GZ_CMD_API_SET_CONDITIONS), or none. */
const gz_lobby_conditions_t *gz_api_conditions(const gz_node_t *c)
{
    static const gz_lobby_conditions_t none;
    return c->api.have_cond ? &c->api.cond : &none;
}

/* At a start, in the node part's resume: every lobby slot without a local id
 * (one opened before this engine) is given one and saves it, so that no
 * object or attention item is ever named after the scope (7.3). Each in a
 * save of its own: they are not one action's. And a held lobby that no
 * longer holds a slot (it ended in the step whose save was the last) leaves
 * the hold; the others are seen by their slots (lobbyslot.c, pause_apply). */
gz_status_t gz_api_resume(gz_node_t *c, gz_action_list_t *out)
{
    gz_status_t st;
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) {
        slot_t *s = &c->slots[i];
        if ((s->state != SLOT_OPEN && s->state != SLOT_LEFT_OUT) || s->kind != SLOT_KIND_LOBBY || s->view.local_id[0])
            continue;
        if ((st = new_local_id(c, i, out)) != GZ_OK) return st;
    }
    for (int k = c->api.n_held - 1; k >= 0; k--) {
        int open = 0;
        for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++)
            if (c->slots[i].state == SLOT_OPEN && c->slots[i].kind == SLOT_KIND_LOBBY && !c->slots[i].host &&
                memcmp(c->slots[i].scope, c->api.held[k], 32) == 0)
                open = 1;
        if (!open && (st = gz_api_release(c, c->api.held[k], out)) != GZ_OK) return st;
    }
    return GZ_OK;
}

/* ---- load ----------------------------------------------------------------- */

static int only_fields(gz_bytes_t b, uint32_t known)
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
        if (!(t & 1) && (t >= 32 || !(known & (1u << (t / 2))))) return 0;
    }
    return 1;
}

static api_req_t *req_find(gz_node_t *c, gz_bytes_t rid)
{
    for (int k = 0; k < GZ_API_MAX_REQUESTS; k++) {
        api_req_t *r = &c->api.reqs[k];
        if (r->used && slen(r->rid) == rid.len && memcmp(r->rid, rid.data, rid.len) == 0) return r;
    }
    return NULL;
}

/* 1 if request id r may be dropped (7.4): the object it acted on has ended
 * and 30 days have passed. A request with no object (the pause, the signing
 * setting) ended when it was made; one whose lobby has left the index of
 * local ids ended no later than that. A lobby whose end time is unknown (it
 * ended before this start) counts as ended at this start: an id is kept
 * longer, never dropped early. */
static int req_droppable(gz_node_t *c, const api_req_t *r)
{
    uint64_t end = r->created_ms, now = wall(c);
    if (!r->used) return 1;
    if (r->object[0]) {
        const api_lid_t *e = lid_by_id(c, r->object, slen(r->object));
        if (e) {
            if (slot_holds(c, e->scope) || !e->ended_ms) return 0;
            if (e->ended_ms > end) end = e->ended_ms;
        }
    }
    return now >= end && now - end >= API_KEEP_MS;
}

/* A place for a new request id: a free one, else the oldest that may be
 * dropped; NULL if every kept id must stay (the caller answers 503). */
static api_req_t *req_slot(gz_node_t *c)
{
    api_req_t *best = NULL;
    for (int k = 0; k < GZ_API_MAX_REQUESTS; k++) {
        api_req_t *r = &c->api.reqs[k];
        if (!r->used) return r;
        if ((!best || r->seq < best->seq) && req_droppable(c, r)) best = r;
    }
    return best;
}

static int req_fill(api_req_t *r, gz_bytes_t rid, gz_bytes_t method, gz_bytes_t path, gz_bytes_t digest)
{
    if (!parts_ok(rid, method, path) || digest.len != 32) return 0;
    memset(r, 0, sizeof *r);
    memcpy(r->rid, rid.data, rid.len);
    memcpy(r->method, method.data, method.len);
    r->method_len = (uint8_t)method.len;
    memcpy(r->path, path.data, path.len);
    r->path_len = (uint16_t)path.len;
    memcpy(r->digest, digest.data, 32);
    return 1;
}

/* A preset's id: 1 to 16 of a-z and _ (13.1: cautious, everyday, wide). */
static int preset_ok(gz_bytes_t p)
{
    if (!p.len || p.len > API_MAX_PRESET) return 0;
    for (size_t k = 0; k < p.len; k++)
        if (!((p.data[k] >= 'a' && p.data[k] <= 'z') || p.data[k] == '_')) return 0;
    return 1;
}

/* The local id field of local_ids: "lob_" and 1 to 60 id characters (7.3). */
static int lob_id_ok(gz_bytes_t w)
{
    return w.len >= 5 && w.len <= GZ_LOCAL_ID_MAX && memcmp(w.data, "lob_", 4) == 0 && id_chars(w);
}

gz_status_t gz_api_load(gz_node_t *c, const gz_record_t *rec)
{
    gz_bytes_t b = rec->bytes, v, w, x, y, st, o, e;
    api_req_t tmp, *r;   /* function scope: no ASan use-after-scope calls (isolation) */
    api_lid_t *have;
    if (!gz_rec_valid(b)) return GZ_ERR_CORRUPT;
    switch (rec->type) {
    case GZ_RECORD_PAUSE:
        if (!only_fields(b, 0x0eu) || !arg(b, 2, 1, &v) || v.data[0] > GZ_PAUSE_HELD || !arg(b, 4, 8, &w))
            return GZ_ERR_CORRUPT;
        c->api.pause = v.data[0];
        c->api.pause_since = gz_get_u64(w.data);
        c->api.n_held = 0;
        if (gz_rec_find(b, 6, &x) == 1) {
            if (x.len % 32 || x.len / 32 > GZ_NODE_MAX_SLOTS) return GZ_ERR_CORRUPT;
            for (size_t k = 0; k < x.len / 32; k++) memcpy(c->api.held[c->api.n_held++], x.data + 32 * k, 32);
        }
        /* held_for_signing names its lobbies; off and on name none. */
        if ((c->api.pause == GZ_PAUSE_HELD) != (c->api.n_held > 0)) return GZ_ERR_CORRUPT;
        return GZ_OK;
    case GZ_RECORD_LOCAL_IDS:
        if (!only_fields(b, 0x06u) || !arg(b, 2, 32, &v) || !arg(b, 4, 0, &w) || !lob_id_ok(w)) return GZ_ERR_CORRUPT;
        /* One id, one lobby: an id another scope holds would route a path to
         * the wrong lobby (review A of PR 55, L4). */
        if ((have = lid_by_id(c, (const char *)w.data, w.len)) != NULL && memcmp(have->scope, v.data, 32) != 0)
            return GZ_ERR_CORRUPT;
        lid_keep(c, v.data, (const char *)w.data, w.len);
        for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) {
            slot_t *s = &c->slots[i];
            if ((s->state == SLOT_OPEN || s->state == SLOT_LEFT_OUT) && s->kind == SLOT_KIND_LOBBY &&
                memcmp(s->scope, v.data, 32) == 0) {
                memset(s->view.local_id, 0, sizeof s->view.local_id);
                memcpy(s->view.local_id, w.data, w.len);
            }
        }
        return GZ_OK;
    case GZ_RECORD_REQUEST_ID:
        if (!only_fields(b, 0xfeu) || !arg(b, 2, 0, &v) || !arg(b, 4, 0, &w) || !arg(b, 6, 0, &x) ||
            !arg(b, 8, 32, &y) || !arg(b, 10, 2, &st) || !arg(b, 14, 8, &e) || !req_fill(&tmp, v, w, x, y))
            return GZ_ERR_CORRUPT;
        tmp.status = gz_get_u16(st.data);
        tmp.created_ms = gz_get_u64(e.data);
        if (gz_rec_find(b, 12, &o) == 1) { /* the acted-on lobby's local id (7.4: a replay after a restart) */
            if (!o.len || o.len > GZ_LOCAL_ID_MAX || !id_chars(o)) return GZ_ERR_CORRUPT;
            memcpy(tmp.object, o.data, o.len);
        }
        if (gz_rec_find(b, 15, &o) == 1) { /* the first answer's error code (L1) */
            if (!o.len || o.len > API_MAX_ERROR || !id_chars(o)) return GZ_ERR_CORRUPT;
            memcpy(tmp.error, o.data, o.len);
        }
        tmp.used = 1;
        tmp.seq = ++c->api.req_seq;
        r = req_find(c, v);
        if (!r) r = req_slot(c);
        if (!r) {
            /* More ids than the table: a running node refuses a request it
             * cannot keep, so these are ids it had dropped under the rule;
             * the oldest made goes. */
            r = &c->api.reqs[0];
            for (int k = 1; k < GZ_API_MAX_REQUESTS; k++)
                if (c->api.reqs[k].created_ms < r->created_ms) r = &c->api.reqs[k];
        }
        *r = tmp;
        return GZ_OK;
    case GZ_RECORD_CONDITIONS:
        if (!only_fields(b, 0x1eu) || gz_rec_find(b, 2, &v) != 1 || v.len > COND_MAX || !arg(b, 4, 4, &w))
            return GZ_ERR_CORRUPT;
        if (!gz_ls_cond_decode(v.data, v.len, &c->api.cond)) return GZ_ERR_CORRUPT;
        if (v.len) memcpy(c->api.cond_bytes, v.data, v.len); /* none saved: no bytes, and v.data may be NULL */
        c->api.cond_len = v.len;
        c->api.cond_version = gz_get_u32(w.data);
        /* The last tightening (8): absent in an older record, which counts every
         * save as one; never after the record's own version. */
        c->api.cond_tightened = c->api.cond_version;
        if (gz_rec_find(b, 8, &x) == 1) {
            if (x.len != 4 || gz_get_u32(x.data) > c->api.cond_version) return GZ_ERR_CORRUPT;
            c->api.cond_tightened = gz_get_u32(x.data);
        }
        c->api.preset[0] = 0;
        if (gz_rec_find(b, 6, &x) == 1) {
            if (!preset_ok(x)) return GZ_ERR_CORRUPT;
            memcpy(c->api.preset, x.data, x.len);
            c->api.preset[x.len] = 0;
        }
        c->api.have_cond = 1;
        return GZ_OK;
    case GZ_RECORD_SIGNING_SETTING:
        if (!only_fields(b, 0x0eu) || !arg(b, 2, 1, &v) || v.data[0] > GZ_MEMBER_SIGNING_WHEN_UNLOCKED ||
            !arg(b, 4, 1, &w) || w.data[0] > GZ_HOST_FUNDING_CONFIRM || !arg(b, 6, 4, &x))
            return GZ_ERR_CORRUPT;
        c->api.have_signing = 1;
        c->api.signing_saved = v.data[0];
        c->api.host_funding_saved = w.data[0];
        c->api.signing_version = gz_get_u32(x.data);
        return GZ_OK;
    default:
        return rec->type & 1 ? GZ_OK : GZ_ERR_CORRUPT; /* an even type a newer program wrote */
    }
}

/* After the walk: the saved signing setting is the one in force for this
 * run (local-api.md 14.3: a change takes effect at the next start), and
 * gz_node_member_signing gives it to the program for its key routing. An
 * ended lobby's ids run their 30 days from this start. A member slot that
 * joined under a conditions version the journal does not hold (slot_opened
 * 24 above the conditions record's version, or with none) is corrupt. */
gz_status_t gz_api_loaded(gz_node_t *c)
{
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) {
        const slot_t *s = &c->slots[i];
        if ((s->state == SLOT_OPEN || s->state == SLOT_LEFT_OUT) && s->kind == SLOT_KIND_LOBBY && !s->host &&
            s->cond_seen > (c->api.have_cond ? c->api.cond_version : 0))
            return GZ_ERR_CORRUPT;
    }
    if (c->api.have_signing) {
        c->cfg.member_signing = (gz_member_signing_t)c->api.signing_saved;
        c->cfg.host_funding = (gz_host_funding_t)c->api.host_funding_saved;
    }
    for (int k = 0; k < API_MAX_IDS; k++)
        if (c->api.ids[k].used && !c->api.ids[k].ended_ms && !slot_holds(c, c->api.ids[k].scope))
            c->api.ids[k].ended_ms = wall(c);
    return GZ_OK;
}

int gz_api_held(const gz_node_t *c, const uint8_t scope[32])
{
    for (int k = 0; k < c->api.n_held; k++)
        if (memcmp(c->api.held[k], scope, 32) == 0) return k;
    return -1;
}

int gz_api_paused(const gz_node_t *c) { return c->api.pause != GZ_PAUSE_OFF; }

/* ---- command results ---------------------------------------------------- */

static gz_status_t result(gz_node_t *c, gz_bytes_t cmd, uint16_t status, const char *error, const char *object,
                          const char *params, gz_action_list_t *out)
{
    uint8_t *buf = c->api.res, st2[2];
    size_t at = 0;
    gz_bytes_t rid;
    gz_status_t st;
    if (gz_rec_find(cmd, GZ_CMD_REC_REQUEST_ID, &rid) != 1 || rid.len > GZ_CMD_MAX_REQUEST_ID || !rid.len) {
        rid.data = (const uint8_t *)"-";
        rid.len = 1;
    }
    gz_put_u16(st2, status);
    st = gz_rec_put(buf, sizeof c->api.res, &at, GZ_RESULT_REC_REQUEST_ID, rid.data, rid.len);
    if (st == GZ_OK) st = gz_rec_put(buf, sizeof c->api.res, &at, GZ_RESULT_REC_STATUS, st2, 2);
    if (st == GZ_OK && error && error[0])
        st = gz_rec_put(buf, sizeof c->api.res, &at, GZ_RESULT_REC_ERROR, (const uint8_t *)error, slen(error));
    if (st == GZ_OK && object && object[0])
        st = gz_rec_put(buf, sizeof c->api.res, &at, GZ_RESULT_REC_OBJECT, (const uint8_t *)object, slen(object));
    if (st == GZ_OK && params)
        st = gz_rec_put(buf, sizeof c->api.res, &at, GZ_RESULT_REC_PARAMS, (const uint8_t *)params, slen(params));
    if (st != GZ_OK) return gz_c_bug(c, ENG_NODE);
    gz_action_t a = {.kind = GZ_ACTION_NOTIFY};
    a.u.notify.code = GZ_NOTIFY_COMMAND_RESULT;
    a.u.notify.bytes.data = buf;
    a.u.notify.bytes.len = at;
    return gz_action_list_add(out, &a);
}

/* ---- before a command ----------------------------------------------------- */

/* An API request's parts: 1 if it carries a digest (and so is one), with
 * its id checked; -1 if it carries a digest and its parts are malformed. */
static int request_parts(gz_bytes_t cmd, gz_bytes_t *rid, gz_bytes_t *method, gz_bytes_t *path, gz_bytes_t *digest)
{
    if (gz_rec_find(cmd, GZ_CMD_REC_DIGEST, digest) != 1) return 0;
    if (digest->len != 32 || gz_rec_find(cmd, GZ_CMD_REC_REQUEST_ID, rid) != 1) return -1;
    if (gz_rec_find(cmd, GZ_CMD_REC_METHOD, method) != 1) method->len = 0, method->data = NULL;
    if (gz_rec_find(cmd, GZ_CMD_REC_PATH, path) != 1) path->len = 0, path->data = NULL;
    return parts_ok(*rid, *method, *path) ? 1 : -1;
}

/* The checks every lobby, node and API command passes first: a replayed or
 * reused request id, the pause for a join or a ready, and room for a new
 * id. 1 in *done when the answer is given here, in a bracket of its own. */
gz_status_t gz_api_precheck(gz_node_t *c, uint16_t code, gz_bytes_t cmd, gz_action_list_t *out, int *done)
{
    gz_bytes_t rid, method, path, digest;
    int kind = request_parts(cmd, &rid, &method, &path, &digest);
    gz_status_t st;
    api_req_t *r;
    *done = 0;
    if (kind == 0 && !(gz_api_paused(c) && (code == GZ_CMD_LOBBY_JOIN || code == GZ_CMD_LOBBY_READY))) return GZ_OK;
    if ((st = gz_c_node_bracket_begin(c, out)) != GZ_OK) return st;
    *done = 1;
    if (kind < 0) {
        st = result(c, cmd, 400, "bad_value", NULL, NULL, out);
    } else if (kind == 1 && (r = req_find(c, rid)) != NULL) {
        if (r->method_len == method.len && r->path_len == path.len && memcmp(r->method, method.data, method.len) == 0 &&
            memcmp(r->path, path.data, path.len) == 0 && memcmp(r->digest, digest.data, 32) == 0) {
            /* The first answer's status and error, replayed (7.4); the API
             * server builds the body from the object's current state. */
            st = result(c, cmd, r->status, r->error, r->object, "{\"replayed\":true}", out);
        } else {
            /* The saved method and path are printable without `"` or `\`
             * (parts_ok, also at load), so they need no escaping. */
            char *p = c->api.params;
            size_t k = 0;
            const char *a = "{\"first\":{\"method\":\"", *m = "\",\"path\":\"", *e = "\"}}";
            for (size_t j = 0; a[j]; j++) p[k++] = a[j];
            memcpy(p + k, r->method, r->method_len);
            k += r->method_len;
            for (size_t j = 0; m[j]; j++) p[k++] = m[j];
            memcpy(p + k, r->path, r->path_len);
            k += r->path_len;
            for (size_t j = 0; e[j]; j++) p[k++] = e[j];
            p[k] = 0;
            st = result(c, cmd, 409, "request_id_reused", NULL, p, out);
        }
    } else if (gz_api_paused(c) && (code == GZ_CMD_LOBBY_JOIN || code == GZ_CMD_LOBBY_READY)) {
        st = result(c, cmd, 409, "paused", NULL, NULL, out);   /* local-api.md 11.3 */
    } else if (!req_slot(c)) {
        /* Every kept id must stay (7.4): the request is refused before it
         * acts, so that a retry can never act twice. */
        st = result(c, cmd, 503, "node_busy", NULL, NULL, out);
    } else {
        *done = 0; /* an API request seen for the first time: the command runs */
        return gz_c_node_bracket_end(c, out);
    }
    if (st == GZ_OK) return gz_c_node_bracket_end(c, out);
    c->bracket_on = 0;
    return st;
}

/* ---- after a command ------------------------------------------------------- */

/* Move the action at `from` (the last) to just after `to`. */
static void move_after(gz_node_t *c, gz_action_list_t *out, size_t to)
{
    size_t last = out->count - 1;
    gz_action_t a = out->slots[last];
    int8_t o = c->owner[last - c->base];
    memmove(&out->slots[to + 2], &out->slots[to + 1], (last - to - 1) * sizeof out->slots[0]);
    memmove(&c->owner[to + 2 - c->base], &c->owner[to + 1 - c->base], (last - to - 1) * sizeof c->owner[0]);
    out->slots[to + 1] = a;
    c->owner[to + 1 - c->base] = o;
}

/* Inside the command's bracket, before it ends: if the command saved
 * anything, its request id goes right after the first save (one batch,
 * local-api.md 7.4), with the status and error of the result notice it gave. */
gz_status_t gz_api_after(gz_node_t *c, gz_bytes_t cmd, size_t from, gz_action_list_t *out)
{
    gz_bytes_t rid, method, path, digest, sb, eb = {NULL, 0};
    size_t first = out->count, at = 0, i;
    uint16_t status = 0;
    uint8_t *rec = c->api.rec, v[8];
    const char *object = "";
    gz_status_t st;
    api_req_t *r;
    if (request_parts(cmd, &rid, &method, &path, &digest) != 1) return GZ_OK;
    for (i = from; i < out->count; i++) {
        const gz_action_t *a = &out->slots[i];
        if (a->kind == GZ_ACTION_SAVE && first == out->count) first = i;
        if (a->kind == GZ_ACTION_NOTIFY && a->u.notify.code == GZ_NOTIFY_COMMAND_RESULT &&
            gz_rec_find(a->u.notify.bytes, GZ_RESULT_REC_STATUS, &sb) == 1 && sb.len == 2) {
            status = gz_get_u16(sb.data);
            if (gz_rec_find(a->u.notify.bytes, GZ_RESULT_REC_ERROR, &eb) != 1 || eb.len > API_MAX_ERROR || !id_chars(eb))
                eb.len = 0;
        }
    }
    if (first == out->count || !status) return GZ_OK; /* nothing saved: no id (7.4) */
    /* The object acted on: the lobby the command names, or the one it opened. */
    gz_bytes_t scope;
    if (c->api.opened) object = c->slots[c->api.opened - 1].view.local_id;
    else if (arg(cmd, 12, 32, &scope) && gz_api_local_id(c, scope.data)) object = gz_api_local_id(c, scope.data);
    c->api.opened = 0;
    gz_put_u16(v, status);
    st = gz_rec_put(rec, sizeof c->api.rec, &at, 2, rid.data, rid.len);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof c->api.rec, &at, 4, method.data, method.len);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof c->api.rec, &at, 6, path.data, path.len);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof c->api.rec, &at, 8, digest.data, 32);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof c->api.rec, &at, 10, v, 2);
    if (st == GZ_OK && object[0]) st = gz_rec_put(rec, sizeof c->api.rec, &at, 12, (const uint8_t *)object, slen(object));
    gz_put_u64(v, wall(c));
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof c->api.rec, &at, 14, v, 8);
    if (st == GZ_OK && eb.len) st = gz_rec_put(rec, sizeof c->api.rec, &at, 15, eb.data, eb.len);
    if (st != GZ_OK) return gz_c_bug(c, ENG_NODE);
    gz_record_t rr = {GZ_RECORD_REQUEST_ID, {rec, at}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &rr;
    a.u.save.n_records = 1;
    /* The place, before anything is appended: precheck found one, and the
     * command between took none. */
    if (!(r = req_find(c, rid))) r = req_slot(c);
    if (!r) return gz_c_bug(c, ENG_NODE);
    if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
    c->owner[out->count - 1 - c->base] = (int8_t)ENG_NODE;
    move_after(c, out, first);
    if (!req_fill(r, rid, method, path, digest)) return gz_c_bug(c, ENG_NODE);
    r->used = 1;
    r->status = status;
    r->seq = ++c->api.req_seq;
    r->created_ms = wall(c);
    memcpy(r->object, object, slen(object) < GZ_LOCAL_ID_MAX ? slen(object) : GZ_LOCAL_ID_MAX);
    if (eb.len) memcpy(r->error, eb.data, eb.len);
    return GZ_OK;
}

/* ---- the API's own commands ---------------------------------------------- */

gz_status_t gz_api_save_pause(gz_node_t *c, gz_action_list_t *out)
{
    uint8_t *rec = c->api.rec, v[9];
    size_t at = 0;
    gz_status_t st;
    v[0] = (uint8_t)c->api.pause;
    st = gz_rec_put(rec, sizeof c->api.rec, &at, 2, v, 1);
    gz_put_u64(v, c->api.pause_since);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof c->api.rec, &at, 4, v, 8);
    if (st == GZ_OK && c->api.n_held)
        st = gz_rec_put(rec, sizeof c->api.rec, &at, 6, c->api.held[0], 32 * (size_t)c->api.n_held);
    if (st != GZ_OK) return gz_c_bug(c, ENG_NODE);
    gz_record_t rr = {GZ_RECORD_PAUSE, {rec, at}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &rr;
    a.u.save.n_records = 1;
    return gz_action_list_add(out, &a);
}

/* A held lobby's round ended (lobbyslot.c): its scope leaves `held`, and the
 * pause is saved again, `on` once none is left (11.3: "the pause takes
 * effect when the round reaches ..."). */
gz_status_t gz_api_release(gz_node_t *c, const uint8_t scope[32], gz_action_list_t *out)
{
    int k = gz_api_held(c, scope);
    if (k < 0) return GZ_OK;
    memmove(c->api.held[k], c->api.held[k + 1], (size_t)(c->api.n_held - k - 1) * 32);
    c->api.n_held--;
    if (!c->api.n_held) c->api.pause = GZ_PAUSE_ON;
    c->api.status_dirty = 1;
    return gz_api_save_pause(c, out);
}

/* The answer's lists (11.3): the local ids of the lobbies in `mask` (bit i,
 * slot i), as a JSON array, from the ids the slots had before the pause. */
static size_t id_list(char *p, size_t k, const char *name, unsigned mask, char ids[][GZ_LOCAL_ID_MAX + 1])
{
    int first = 1;
    p[k++] = '"';
    for (size_t j = 0; name[j]; j++) p[k++] = name[j];
    p[k++] = '"';
    p[k++] = ':';
    p[k++] = '[';
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) {
        if (!(mask & (1u << i)) || !ids[i][0]) continue;
        if (!first) p[k++] = ',';
        first = 0;
        p[k++] = '"';
        for (size_t j = 0; ids[i][j]; j++) p[k++] = ids[i][j];
        p[k++] = '"';
    }
    p[k++] = ']';
    return k;
}

static gz_status_t cmd_pause(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t v;
    gz_status_t st;
    unsigned held = 0;
    char *p = c->api.params;
    size_t k = 0;
    if (!arg(cmd, 12, 1, &v) || v.data[0] > 1) return result(c, cmd, 400, "bad_value", NULL, NULL, out);
    if ((v.data[0] == 1) == (c->api.pause != GZ_PAUSE_OFF)) return result(c, cmd, 200, NULL, NULL, NULL, out);
    if (v.data[0] == 0) {
        c->api.pause = GZ_PAUSE_OFF;
        c->api.pause_since = wall(c);
        c->api.n_held = 0;
        if ((st = gz_api_save_pause(c, out)) != GZ_OK) return st;
        if ((st = gz_ls_pause_changed(c, out)) != GZ_OK) return st;
        return result(c, cmd, 200, NULL, NULL, NULL, out);
    }
    /* A member's lobby whose round has partial signatures out holds the
     * pause: the round runs to its end (11.3). The rest are left after the
     * save, with a round_abort where their round had begun. */
    c->api.n_held = 0;
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) {
        slot_t *s = &c->slots[i];
        memcpy(c->api.pids[i], s->view.local_id, sizeof c->api.pids[i]);
        if (s->state == SLOT_OPEN && s->kind == SLOT_KIND_LOBBY && !s->host && !s->lobby.m.ended &&
            gz_ls_partials_out(c, s->scope)) {
            memcpy(c->api.held[c->api.n_held++], s->scope, 32);
            held |= 1u << i;
        }
    }
    c->api.pause = c->api.n_held ? GZ_PAUSE_HELD : GZ_PAUSE_ON;
    c->api.pause_since = wall(c);
    c->api.left = c->api.aborted = 0;
    if ((st = gz_api_save_pause(c, out)) != GZ_OK) return st;
    if ((st = gz_ls_pause_changed(c, out)) != GZ_OK) return st;
    p[k++] = '{';
    k = id_list(p, k, "left_lobbies", c->api.left, c->api.pids);
    p[k++] = ',';
    k = id_list(p, k, "aborted_lobbies", c->api.aborted, c->api.pids);
    p[k++] = ',';
    k = id_list(p, k, "held_lobbies", held, c->api.pids);
    p[k++] = '}';
    p[k] = 0;
    return result(c, cmd, c->api.n_held ? 202 : 200, NULL, NULL, p, out);
}

/* PUT /api/v1/signing's core (14.3). In order: the value (400), the release
 * (when_unlocked: 501 not_in_this_release), the authority of a widening to
 * auto (an API request, 403 fresh_sign_in_needed; the echo in field 16,
 * 409 confirm_mismatch), the version (409 changed_elsewhere). Saved, in force
 * from the next start. */
static gz_status_t cmd_signing(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t v, b, e;
    uint8_t *rec = c->api.rec, x[4];
    size_t at = 0;
    gz_status_t st;
    if (!arg(cmd, 12, 1, &v) || v.data[0] > GZ_MEMBER_SIGNING_WHEN_UNLOCKED || !arg(cmd, 14, 4, &b))
        return result(c, cmd, 400, "bad_value", NULL, NULL, out);
    if (v.data[0] == GZ_MEMBER_SIGNING_WHEN_UNLOCKED)
        return result(c, cmd, 501, "not_in_this_release", NULL, "{\"release\":\"1.0.0\"}", out);
    if (v.data[0] == GZ_MEMBER_SIGNING_AUTO) {
        /* "No other request results in mode A": only the API server's
         * PUT /signing, behind its fresh sign-in, carries a digest. */
        if (gz_rec_find(cmd, GZ_CMD_REC_DIGEST, &e) != 1) return result(c, cmd, 403, "fresh_sign_in_needed", NULL, NULL, out);
        if (!arg(cmd, 16, 1, &e) || e.data[0] != GZ_MEMBER_SIGNING_AUTO)
            return result(c, cmd, 409, "confirm_mismatch", NULL, NULL, out);
    }
    if (gz_get_u32(b.data) != c->api.signing_version) return result(c, cmd, 409, "changed_elsewhere", NULL, NULL, out);
    x[0] = v.data[0];
    st = gz_rec_put(rec, sizeof c->api.rec, &at, 2, x, 1);
    x[0] = (uint8_t)c->cfg.host_funding;
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof c->api.rec, &at, 4, x, 1);
    gz_put_u32(x, c->api.signing_version + 1);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof c->api.rec, &at, 6, x, 4);
    if (st != GZ_OK) return gz_c_bug(c, ENG_NODE);
    gz_record_t rr = {GZ_RECORD_SIGNING_SETTING, {rec, at}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &rr;
    a.u.save.n_records = 1;
    if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
    c->api.have_signing = 1;
    c->api.signing_saved = v.data[0];
    c->api.host_funding_saved = (uint8_t)c->cfg.host_funding;
    c->api.signing_version++;
    /* In force from the next start (14.3, takes_effect "next_start"). */
    return result(c, cmd, 200, NULL, NULL, "{\"takes_effect\":\"next_start\"}", out);
}

/* What `to` loosens against `from` (13.2 `loosens`): the codes of view.h's
 * GZ_COND_L_*, increasing, each once, into `l` (room for 8 + GZ_TERMS_MAX_ADJ).
 * A limit at its "no limit" value (terms.h) is the loosest it can be. */
size_t gz_api_loosens(const gz_lobby_conditions_t *from, const gz_lobby_conditions_t *to, uint8_t *l)
{
    const gz_terms_limits_t *a = &from->limits, *b = &to->limits;
    size_t n = 0;
    uint8_t adj[256];
    if (!from->current_only && to->current_only) l[n++] = GZ_COND_L_COMPARE;
    if (to->min_members < from->min_members) l[n++] = GZ_COND_L_HINT;
    if (a->profiles && (!b->profiles || (b->profiles & (uint8_t)~a->profiles))) l[n++] = GZ_TT_PROFILE;
    if (b->min_members < a->min_members) l[n++] = GZ_TT_MINIMUM;
    if (b->min_lifetime < a->min_lifetime || (a->max_lifetime && (!b->max_lifetime || b->max_lifetime > a->max_lifetime)))
        l[n++] = GZ_TT_LIFETIME;
    if (b->min_channel_sat < a->min_channel_sat) l[n++] = GZ_TT_CHANNEL;
    if (a->max_tree_feerate && (!b->max_tree_feerate || b->max_tree_feerate > a->max_tree_feerate)) l[n++] = GZ_TT_FEERATE;
    /* An adjustable maximum raised, or no longer named (no limit). A type
     * named twice compares as its strictest (gz_terms_classify). */
    memset(adj, 0, sizeof adj);
    for (uint8_t i = 0; i < a->n_max && i < GZ_TERMS_MAX_ADJ; i++) {
        uint64_t am = a->max[i].max, bm = UINT64_MAX;
        int named = 0;
        for (uint8_t j = 0; j < a->n_max && j < GZ_TERMS_MAX_ADJ; j++)
            if (a->max[j].type == a->max[i].type && a->max[j].max < am) am = a->max[j].max;
        for (uint8_t j = 0; j < b->n_max && j < GZ_TERMS_MAX_ADJ; j++)
            if (b->max[j].type == a->max[i].type) {
                named = 1;
                if (b->max[j].max < bm) bm = b->max[j].max;
            }
        if (!named || bm > am) adj[a->max[i].type] = 1;
    }
    for (int t = GZ_TT_FEERATE + 1; t < 256 && n < 8 + GZ_TERMS_MAX_ADJ; t++)
        if (adj[t]) l[n++] = (uint8_t)t;
    return n;
}

/* Text: s, then n as decimal digits. */
static size_t put_text(char *p, size_t k, const char *s)
{
    while (*s) p[k++] = *s++;
    return k;
}

static size_t put_dec(char *p, size_t k, uint64_t v)
{
    char d[24];
    int m = 0;
    do {
        d[m++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (m) p[k++] = d[--m];
    return k;
}

/* PUT /api/v1/conditions's core (13.2). In order: the form (400 bad_value),
 * the authority of a loosening (an API request, 403 fresh_sign_in_needed),
 * the echo (field 16 exactly what the change loosens, nothing when it
 * loosens nothing: 409 confirm_mismatch with params.loosens), the version
 * (409 changed_elsewhere), a lobby it would leave while that lobby's round
 * is on (409 signing_now, params.lobby_ids: nothing is changed, so no slot
 * whose partial signatures may be out is ever dropped). Then saved and in
 * force at once: every member lobby the new conditions fit worse than its
 * own copy is left, reason 1, its saves in the batch of this save (journal.md
 * 9), or, where its link is down, once it is up (lobbyslot.c, cond_apply).
 * A copy is never changed: a loosening applies to the next join only. The
 * answer's params: the new `version` and `left_lobbies`. */
static gz_status_t cmd_conditions(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    static const gz_lobby_conditions_t NONE;
    gz_lobby_conditions_t nc;
    gz_bytes_t v, b, e, d, pr = {NULL, 0};
    uint8_t *rec = c->api.rec, x[4], l[8 + GZ_TERMS_MAX_ADJ];
    size_t at = 0, nl, k = 0, from;
    char *p = c->api.params;
    unsigned blocked;
    uint32_t tightened;
    gz_status_t st;
    if (gz_rec_find(cmd, 12, &v) != 1 || v.len > COND_MAX || !gz_ls_cond_decode(v.data, v.len, &nc) ||
        !arg(cmd, 14, 4, &b) || (gz_rec_find(cmd, 18, &pr) == 1 && !preset_ok(pr)))
        return result(c, cmd, 400, "bad_value", NULL, NULL, out);
    if (gz_rec_find(cmd, 18, &pr) != 1) pr.len = 0;
    nl = gz_api_loosens(c->api.have_cond ? &c->api.cond : &NONE, &nc, l);
    if (nl && gz_rec_find(cmd, GZ_CMD_REC_DIGEST, &d) != 1)
        return result(c, cmd, 403, "fresh_sign_in_needed", NULL, NULL, out);
    if (gz_rec_find(cmd, 16, &e) != 1) e.len = 0;
    if (e.len != nl || (nl && memcmp(e.data, l, nl) != 0)) {
        k = put_text(p, 0, "{\"loosens\":[");
        for (size_t j = 0; j < nl; j++) {
            if (j) p[k++] = ',';
            k = put_dec(p, k, l[j]);
        }
        k = put_text(p, k, "]}");
        p[k] = 0;
        return result(c, cmd, 409, "confirm_mismatch", NULL, p, out);
    }
    if (gz_get_u32(b.data) != c->api.cond_version) return result(c, cmd, 409, "changed_elsewhere", NULL, NULL, out);
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) memcpy(c->api.pids[i], c->slots[i].view.local_id, sizeof c->api.pids[i]);
    if (gz_ls_conditions_blocked(c, &nc, &blocked)) {
        p[k++] = '{';
        k = id_list(p, k, "lobby_ids", blocked, c->api.pids);
        p[k++] = '}';
        p[k] = 0;
        return result(c, cmd, 409, "signing_now", NULL, p, out);
    }
    st = gz_rec_put(rec, sizeof c->api.rec, &at, 2, v.data, v.len);
    gz_put_u32(x, c->api.cond_version + 1);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof c->api.rec, &at, 4, x, 4);
    if (st == GZ_OK && pr.len) st = gz_rec_put(rec, sizeof c->api.rec, &at, 6, pr.data, pr.len);
    /* Whether it tightens anything (what the old conditions loosen against
     * the new): only such a save reaches the lobbies joined before it, so the
     * same conditions saved anew, or a loosening, never leave a lobby joined
     * with confirmed looser conditions (confirmation of #77, N2). */
    tightened = gz_api_loosens(&nc, c->api.have_cond ? &c->api.cond : &NONE, l) ? c->api.cond_version + 1
                                                                                  : c->api.cond_tightened;
    gz_put_u32(x, tightened);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof c->api.rec, &at, 8, x, 4);
    if (st != GZ_OK) return gz_c_bug(c, ENG_NODE);
    gz_record_t rr = {GZ_RECORD_CONDITIONS, {rec, at}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &rr;
    a.u.save.n_records = 1;
    from = out->count;
    if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
    c->owner[out->count - 1 - c->base] = (int8_t)ENG_NODE;
    c->api.have_cond = 1;
    c->api.cond = nc;
    if (v.len) memcpy(c->api.cond_bytes, v.data, v.len);
    c->api.cond_len = v.len;
    c->api.cond_version++;
    c->api.cond_tightened = tightened;
    if (pr.len) memcpy(c->api.preset, pr.data, pr.len);
    c->api.preset[pr.len] = 0;
    c->api.cond_left = 0;
    if ((st = gz_ls_conditions_changed(c, out)) != GZ_OK) return st;
    /* One batch: the conditions and every leave they caused. */
    if ((st = gz_ls_merge_saves(c, out, from)) != GZ_OK) return st;
    k = put_text(p, 0, "{\"version\":");
    k = put_dec(p, k, c->api.cond_version);
    p[k++] = ',';
    k = id_list(p, k, "left_lobbies", c->api.cond_left, c->api.pids);
    p[k++] = '}';
    p[k] = 0;
    return result(c, cmd, 200, NULL, NULL, p, out);
}

gz_status_t gz_api_command(gz_node_t *c, uint16_t code, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_status_t st = gz_c_node_bracket_begin(c, out);
    size_t from = out->count;
    if (st != GZ_OK) return st;
    c->api.opened = 0;
    switch (code) {
    case GZ_CMD_API_PAUSE: st = cmd_pause(c, cmd, out); break;
    case GZ_CMD_API_SET_SIGNING: st = cmd_signing(c, cmd, out); break;
    case GZ_CMD_API_SET_CONDITIONS: st = cmd_conditions(c, cmd, out); break;
    default: st = result(c, cmd, 404, "unknown_command", NULL, NULL, out); break;
    }
    if (st == GZ_OK) st = gz_api_after(c, cmd, from, out);
    if (st == GZ_OK) st = gz_view_status(c, 0, out);
    if (st == GZ_OK) return gz_c_node_bracket_end(c, out);
    c->bracket_on = 0;
    return st;
}

/* The member_signing in force (node.h): the configuration's until the
 * load, the saved setting's after it. */
gz_member_signing_t gz_node_member_signing(const gz_node_t *c)
{
    return c ? c->cfg.member_signing : GZ_MEMBER_SIGNING_AT_JOIN;
}
