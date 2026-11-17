/* The local-API engine (area 0x000d; step P6a; spec/local-api.md 7.4, 7.5,
 * 11.3, 14.3; contract-v2.md section 11). It runs inside the node part:
 *
 * - request ids: a command that carries a digest (record 6, the API server's
 *   RFC 8785 digest) is an API request. Its id is checked before the command
 *   runs (a replay answers the saved status, an id bound to another request
 *   answers 409 request_id_reused), and after it, if it saved anything, the
 *   `request_id` record is put right after its first save, so that the two
 *   are one batch, before the command-result notice (rule 8). A command
 *   without a digest (the program's own, a test's) keeps no id.
 * - pause: saved before anything it does; a member's lobbies are left, except
 *   one whose round was handed over (held_for_signing); a host runs no check
 *   while paused and cancels at the deadline (the host's `paused` port).
 * - the signing setting: saved with a version; in force from the next start.
 * - local ids: "lob_" and 16 random hex digits, saved with the slot's first
 *   batch; kept for the ended lobbies of the index. */
#include "internal.h"
#include <string.h>
#include "gazpacho/view.h"

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

static int printable(gz_bytes_t b)
{
    for (size_t i = 0; i < b.len; i++)
        if (b.data[i] < 0x20 || b.data[i] > 0x7e || b.data[i] == '"' || b.data[i] == '\\') return 0;
    return 1;
}

/* ---- local ids ----------------------------------------------------------- */

static api_lid_t *lid_find(gz_node_t *c, const uint8_t scope[32])
{
    for (int k = 0; k < API_MAX_IDS; k++)
        if (c->api.ids[k].used && memcmp(c->api.ids[k].scope, scope, 32) == 0) return &c->api.ids[k];
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

/* Keep scope -> id; when full, the oldest whose lobby holds no slot goes
 * (an ended lobby older than the index then has no object). */
static void lid_keep(gz_node_t *c, const uint8_t scope[32], const char *id, size_t len)
{
    api_lid_t *e = lid_find(c, scope);
    if (!e) {
        int best = -1;
        for (int k = 0; k < API_MAX_IDS && !e; k++)
            if (!c->api.ids[k].used) e = &c->api.ids[k];
        for (int k = 0; k < API_MAX_IDS && !e; k++)
            if (!slot_holds(c, c->api.ids[k].scope) && (best < 0 || c->api.ids[k].seq < c->api.ids[best].seq)) best = k;
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

/* A new slot's local id, saved right after its slot_opened (one batch). */
gz_status_t gz_api_slot_opened(gz_node_t *c, int i, gz_action_list_t *out)
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
        for (int k = 0; k < 4; k++) r[4 + k] ^= (uint8_t)((c->slot_serial + (uint32_t)tries) >> (24 - 8 * k));
        memcpy(id, "lob_", 4);
        for (int k = 0; k < 8; k++) {
            id[4 + 2 * k] = x[r[k] >> 4];
            id[5 + 2 * k] = x[r[k] & 15];
        }
        id[20] = 0;
        int taken = 0;
        for (int k = 0; k < API_MAX_IDS; k++)
            if (c->api.ids[k].used && memcmp(c->api.ids[k].id, id, 21) == 0) taken = 1;
        if (!taken) break;
        if (tries == 64) return gz_c_bug(c, ENG_NODE); /* a random source that repeats itself */
    }
    memcpy(s->view.local_id, id, 21);
    c->api.opened = i + 1;
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

static api_req_t *req_slot(gz_node_t *c)
{
    api_req_t *best = NULL;
    for (int k = 0; k < GZ_API_MAX_REQUESTS; k++) {
        api_req_t *r = &c->api.reqs[k];
        if (!r->used) return r;
        if (!best || r->seq < best->seq) best = r;
    }
    return best;
}

static int req_fill(api_req_t *r, gz_bytes_t rid, gz_bytes_t method, gz_bytes_t path, gz_bytes_t digest)
{
    if (rid.len < 1 || rid.len > GZ_CMD_MAX_REQUEST_ID || method.len > API_MAX_METHOD || path.len > API_MAX_PATH ||
        digest.len != 32)
        return 0;
    memset(r, 0, sizeof *r);
    memcpy(r->rid, rid.data, rid.len);
    memcpy(r->method, method.data, method.len);
    r->method_len = (uint8_t)method.len;
    memcpy(r->path, path.data, path.len);
    r->path_len = (uint16_t)path.len;
    memcpy(r->digest, digest.data, 32);
    return 1;
}

gz_status_t gz_api_load(gz_node_t *c, const gz_record_t *rec)
{
    gz_bytes_t b = rec->bytes, v, w, x, y, st;
    api_req_t tmp, *r;   /* function scope: no ASan use-after-scope calls (isolation) */
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
        return GZ_OK;
    case GZ_RECORD_LOCAL_IDS:
        if (!only_fields(b, 0x06u) || !arg(b, 2, 32, &v) || !arg(b, 4, 0, &w) || w.len < 5 || w.len > GZ_LOCAL_ID_MAX)
            return GZ_ERR_CORRUPT;
        for (size_t k = 0; k < w.len; k++)
            if (!id_char(w.data[k])) return GZ_ERR_CORRUPT;
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
        if (!only_fields(b, 0x7ffeu) || !arg(b, 2, 0, &v) || !arg(b, 4, 0, &w) || !arg(b, 6, 0, &x) ||
            !arg(b, 8, 32, &y) || !arg(b, 10, 2, &st) || !req_fill(&tmp, v, w, x, y))
            return GZ_ERR_CORRUPT;
        tmp.status = gz_get_u16(st.data);
        tmp.used = 1;
        tmp.seq = ++c->api.req_seq;
        r = req_find(c, v);
        if (!r) r = req_slot(c);
        *r = tmp;
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
 * run (local-api.md 14.3: a change takes effect at the next start). */
void gz_api_loaded(gz_node_t *c)
{
    if (c->api.have_signing) {
        c->cfg.member_signing = (gz_member_signing_t)c->api.signing_saved;
        c->cfg.host_funding = (gz_host_funding_t)c->api.host_funding_saved;
    }
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
    if (st == GZ_OK && error)
        st = gz_rec_put(buf, sizeof c->api.res, &at, GZ_RESULT_REC_ERROR, (const uint8_t *)error, slen(error));
    if (st == GZ_OK && object && object[0])
        st = gz_rec_put(buf, sizeof c->api.res, &at, 6, (const uint8_t *)object, slen(object));
    if (st == GZ_OK && params)
        st = gz_rec_put(buf, sizeof c->api.res, &at, 8, (const uint8_t *)params, slen(params));
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
    if (digest->len != 32 || gz_rec_find(cmd, GZ_CMD_REC_REQUEST_ID, rid) != 1 || rid->len < 16 ||
        rid->len > GZ_CMD_MAX_REQUEST_ID)
        return -1;
    for (size_t k = 0; k < rid->len; k++)
        if (!id_char(rid->data[k])) return -1;
    if (gz_rec_find(cmd, GZ_CMD_REC_METHOD, method) != 1) method->len = 0, method->data = NULL;
    if (gz_rec_find(cmd, GZ_CMD_REC_PATH, path) != 1) path->len = 0, path->data = NULL;
    if (method->len > API_MAX_METHOD || path->len > API_MAX_PATH || !printable(*method) || !printable(*path)) return -1;
    return 1;
}

/* The checks every lobby, node and API command passes first: a replayed or
 * reused request id, and the pause for a join or a ready. 1 in *done when
 * the answer is given here, in a bracket of its own. */
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
            st = result(c, cmd, r->status, r->status >= 400 ? "replayed" : NULL, r->object, "{\"replayed\":true}", out);
        } else {
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
 * local-api.md 7.4), with the status of the result notice it gave. */
gz_status_t gz_api_after(gz_node_t *c, gz_bytes_t cmd, size_t from, gz_action_list_t *out)
{
    gz_bytes_t rid, method, path, digest, sb;
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
            gz_rec_find(a->u.notify.bytes, GZ_RESULT_REC_STATUS, &sb) == 1 && sb.len == 2)
            status = gz_get_u16(sb.data);
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
    if (st != GZ_OK) return gz_c_bug(c, ENG_NODE);
    gz_record_t rr = {GZ_RECORD_REQUEST_ID, {rec, at}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &rr;
    a.u.save.n_records = 1;
    if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
    c->owner[out->count - 1 - c->base] = (int8_t)ENG_NODE;
    move_after(c, out, first);
    if (!(r = req_find(c, rid))) r = req_slot(c);
    if (!req_fill(r, rid, method, path, digest)) return gz_c_bug(c, ENG_NODE);
    r->used = 1;
    r->status = status;
    r->seq = ++c->api.req_seq;
    memcpy(r->object, object, slen(object) < GZ_LOCAL_ID_MAX ? slen(object) : GZ_LOCAL_ID_MAX);
    return GZ_OK;
}

/* ---- the API's own commands ---------------------------------------------- */

static gz_status_t save_pause(gz_node_t *c, gz_action_list_t *out)
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

static gz_status_t cmd_pause(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t v;
    gz_status_t st;
    if (!arg(cmd, 12, 1, &v) || v.data[0] > 1) return result(c, cmd, 400, "bad_value", NULL, NULL, out);
    if ((v.data[0] == 1) == (c->api.pause != GZ_PAUSE_OFF)) return result(c, cmd, 200, NULL, NULL, NULL, out);
    if (v.data[0] == 1) {
        /* A member's lobby whose round was handed over holds the pause: the
         * round runs to its end (11.3). The rest are left after the save. */
        c->api.n_held = 0;
        for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) {
            slot_t *s = &c->slots[i];
            if (s->state == SLOT_OPEN && s->kind == SLOT_KIND_LOBBY && !s->host && s->round_ok && !s->lobby.m.ended)
                memcpy(c->api.held[c->api.n_held++], s->scope, 32);
        }
        c->api.pause = c->api.n_held ? GZ_PAUSE_HELD : GZ_PAUSE_ON;
        c->api.pause_since = wall(c);
        if ((st = save_pause(c, out)) != GZ_OK) return st;
        if ((st = gz_ls_pause_changed(c, out)) != GZ_OK) return st;
        return result(c, cmd, c->api.n_held ? 202 : 200, NULL, NULL, NULL, out);
    }
    c->api.pause = GZ_PAUSE_OFF;
    c->api.pause_since = wall(c);
    c->api.n_held = 0;
    if ((st = save_pause(c, out)) != GZ_OK) return st;
    if ((st = gz_ls_pause_changed(c, out)) != GZ_OK) return st;
    return result(c, cmd, 200, NULL, NULL, NULL, out);
}

static gz_status_t cmd_signing(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t v, b;
    uint8_t *rec = c->api.rec, x[4];
    size_t at = 0;
    gz_status_t st;
    if (!arg(cmd, 12, 1, &v) || v.data[0] > GZ_MEMBER_SIGNING_WHEN_UNLOCKED || !arg(cmd, 14, 4, &b))
        return result(c, cmd, 400, "bad_value", NULL, NULL, out);
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

gz_status_t gz_api_command(gz_node_t *c, uint16_t code, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_status_t st = gz_c_node_bracket_begin(c, out);
    size_t from = out->count;
    if (st != GZ_OK) return st;
    c->api.opened = 0;
    switch (code) {
    case GZ_CMD_API_PAUSE: st = cmd_pause(c, cmd, out); break;
    case GZ_CMD_API_SET_SIGNING: st = cmd_signing(c, cmd, out); break;
    default: st = result(c, cmd, 404, "unknown_command", NULL, NULL, out); break;
    }
    if (st == GZ_OK) st = gz_api_after(c, cmd, from, out);
    if (st == GZ_OK) st = gz_view_status(c, 0, out);
    if (st == GZ_OK) return gz_c_node_bracket_end(c, out);
    c->bracket_on = 0;
    return st;
}
