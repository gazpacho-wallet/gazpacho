/* SPDX-License-Identifier: MIT */
/* The local API's lobby, hosting, discovery, conditions, pause and signing
 * calls (W12): each acting call becomes the core's command (api_backend.h,
 * "acting calls"; docs/notes/view-objects.md section 6), and each read is
 * answered from the core's view objects (kinds 1, 2, 3, 7 and 10). The core
 * owns request ids and replays; this file never answers one from memory. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include "gazpacho/api_json.h"
#include "gazpacho/command.h"
#include "gazpacho/envelope.h"
#include "gazpacho/lobby.h"
#include "gazpacho/node.h"
#include "gazpacho/terms.h"
#include "gazpacho/view.h"
#include "api.h"
#include "api_lobby.h"

/* ---- reading a view object -------------------------------------------------- */

static int field(const gzp_view_obj_t *o, uint64_t type, gz_bytes_t *v)
{
    gz_bytes_t all;
    if (!o) return 0;
    all.data = o->bytes;
    all.len = o->len;
    return gz_rec_find(all, type, v) == 1;
}

static int f8(const gzp_view_obj_t *o, uint64_t type, int dflt)
{
    gz_bytes_t v;
    return field(o, type, &v) && v.len >= 1 ? v.data[0] : dflt;
}

static uint64_t f64(const gzp_view_obj_t *o, uint64_t type)
{
    gz_bytes_t v;
    return field(o, type, &v) && v.len == 8 ? gz_get_u64(v.data) : 0;
}

static void hex(const uint8_t *b, size_t n, char *out)
{
    static const char x[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = x[b[i] >> 4];
        out[2 * i + 1] = x[b[i] & 15];
    }
    out[2 * n] = 0;
}

static int unhex(const char *s, uint8_t *out, size_t n)
{
    if (!s || strlen(s) != 2 * n) return 0;
    for (size_t i = 0; i < n; i++) {
        int v = 0;
        for (int k = 0; k < 2; k++) {
            char c = s[2 * i + k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else return 0;
        }
        out[i] = (uint8_t)v;
    }
    return 1;
}

static const gz_terms_policy_t *policy(void) { return gz_lobby_policy(); }

/* The outer rules and current values an object carries (kinds 2 and 3). */
typedef struct {
    gz_terms_outer_t o;
    gz_terms_current_t c;
    uint8_t od[32], cd[32];
    int ok;
} terms_t;

static void terms_of(const gzp_view_obj_t *obj, uint64_t f_outer, uint64_t f_current, terms_t *t)
{
    gz_bytes_t a, b;
    memset(t, 0, sizeof *t);
    if (!field(obj, f_outer, &a) || !field(obj, f_current, &b)) return;
    if (gz_terms_decode_outer(a.data, a.len, policy(), &t->o) != GZ_TERMS_OK) return;
    gz_terms_outer_digest(a.data, a.len, t->od);
    if (gz_terms_decode_current(b.data, b.len, &t->o, &t->c) != GZ_TERMS_OK) return;
    gz_terms_current_digest(b.data, b.len, t->cd);
    t->ok = 1;
}

static const char *adj_name(uint8_t type)
{
    switch (type) {
    case GZ_TT_JOINING_FEE: return "joining_fee_sat";
    case GZ_TT_FEE_BASE: return "fee_base_msat";
    case GZ_TT_FEE_PROP: return "fee_ppm";
    default: return NULL;
    }
}

static uint64_t current_value(const terms_t *t, uint8_t type)
{
    for (uint8_t i = 0; i < t->c.n_values; i++)
        if (t->c.val[i].type == type) return t->c.val[i].value;
    return 0;
}

/* terms (14.1): fingerprint, host, outer, ranges, current, derived. A
 * draft (15.1) is not signed yet: no fingerprint, signatures not checked. */
static void terms_any(gz_jw *w, const terms_t *t, int draft)
{
    char fp[65], dg[65], hk[67], shortfp[20];
    hex(t->od, 32, fp);
    hex(t->cd, 32, dg);
    hex(t->o.host_key, 33, hk);
    snprintf(shortfp, sizeof shortfp, "%.4s\xe2\x80\xa6%.4s", fp, fp + 60);
    gz_jw_obj(w);
    if (draft) {
        gz_jw_knull(w, "fingerprint");
        gz_jw_knull(w, "fingerprint_short");
    } else {
        gz_jw_kstr(w, "fingerprint", fp);
        gz_jw_kstr(w, "fingerprint_short", shortfp);
    }
    gz_jw_key(w, "host");
    gz_jw_obj(w);
    gz_jw_kstr(w, "key", hk);
    if (t->o.alias_len) {
        char al[40];
        memcpy(al, t->o.alias, t->o.alias_len);
        al[t->o.alias_len] = 0;
        gz_jw_text(w, "alias", al, "host", 64);
    } else {
        gz_jw_knull(w, "alias");
    }
    gz_jw_end_obj(w);
    gz_jw_kbool(w, "signatures_checked", !draft);
    gz_jw_key(w, "outer");
    gz_jw_obj(w);
    gz_jw_kstr(w, "chain", "signet");
    gz_jw_kstr(w, "profile", "standard");
    gz_jw_kint(w, "target", t->o.target);
    gz_jw_kint(w, "minimum", t->o.minimum);
    gz_jw_kint(w, "deadline_at", (int64_t)t->o.deadline);
    gz_jw_kstr(w, "on_shortfall", "cancel");
    gz_jw_kint(w, "ready_window_ms", t->o.ready_window_ms);
    gz_jw_kint(w, "signing_budget_ms", t->o.signing_budget_ms);
    gz_jw_kint(w, "step_timeout_ms", t->o.step_timeout_ms);
    gz_jw_kint(w, "lifetime_blocks", t->o.lifetime_blocks);
    gz_jw_kint(w, "winddown_blocks", t->o.winddown_blocks);
    gz_jw_kint(w, "channel_sat", (int64_t)t->o.channel_sat);
    gz_jw_kint(w, "tree_feerate_sat_per_kvb", t->o.tree_feerate);
    gz_jw_kraw(w, "switches", "{\"names\":false,\"chat\":false,\"rule_requests\":false}");
    if (t->o.description_len) {
        char d[300];
        memcpy(d, t->o.description, t->o.description_len);
        d[t->o.description_len] = 0;
        gz_jw_text(w, "description", d, "host", 1000);
    } else {
        gz_jw_knull(w, "description");
    }
    gz_jw_end_obj(w);
    gz_jw_key(w, "ranges");
    gz_jw_obj(w);
    for (uint8_t i = 0; i < t->o.n_adj; i++) {
        const char *n = adj_name(t->o.adj[i].type);
        if (!n) continue;
        gz_jw_key(w, n);
        gz_jw_obj(w);
        gz_jw_kint(w, "min", (int64_t)t->o.adj[i].min);
        gz_jw_kint(w, "max", (int64_t)t->o.adj[i].max);
        gz_jw_end_obj(w);
    }
    gz_jw_end_obj(w);
    gz_jw_key(w, "current");
    gz_jw_obj(w);
    gz_jw_kint(w, "version", t->c.version);
    gz_jw_kstr(w, "digest", dg);
    gz_jw_key(w, "values");
    gz_jw_obj(w);
    for (uint8_t i = 0; i < t->c.n_values; i++) {
        const char *n = adj_name(t->c.val[i].type);
        if (n) gz_jw_kint(w, n, (int64_t)t->c.val[i].value);
    }
    gz_jw_end_obj(w);
    gz_jw_end_obj(w);
    gz_jw_knull(w, "frozen");
    gz_jw_kraw(w, "reserved", "{\"receiving_room_fee_ppm\":null,\"joining_fee_chain_share\":null,"
                              "\"newcomer_seats_pct\":null,\"invitation_only\":null}");
    gz_jw_end_obj(w);
}

static void terms_json(gz_jw *w, const terms_t *t)
{
    terms_any(w, t, 0);
}

void gzp_api_draft_json(gz_jw *w, const gz_terms_outer_t *o, const gz_terms_current_t *c)
{
    terms_t t;
    uint8_t b[GZ_TERMS_CURRENT_MAX];
    size_t n;
    memset(&t, 0, sizeof t);
    t.o = *o;
    t.c = *c;
    t.ok = 1;
    n = gz_terms_encode_current(c, b, sizeof b);
    if (n) gz_terms_current_digest(b, n, t.cd);
    terms_any(w, &t, 1);
}

static const char *stage_name(int s)
{
    switch (s) {
    case GZ_LOBBY_OPEN: return "open";
    case GZ_LOBBY_READY_CHECK: return "ready_check";
    case GZ_LOBBY_SIGNING: return "signing";
    case GZ_LOBBY_FUNDING: return "funding";
    case GZ_LOBBY_ACTIVE: return "active";
    case GZ_LOBBY_CANCELLED: return "cancelled";
    case GZ_LOBBY_FAILED: return "failed";
    default: return "unknown";
    }
}

static const char *seat_name(int s)
{
    switch (s) {
    case GZ_VSEAT_JOINED: return "joined_not_ready";
    case GZ_VSEAT_READY: return "ready";
    case GZ_VSEAT_CHOSEN: return "chosen";
    case GZ_VSEAT_NOT_CHOSEN: return "not_chosen";
    case GZ_VSEAT_LEFT: return "left";
    case GZ_VSEAT_REMOVED: return "removed";
    case GZ_VSEAT_REFUSED_BY_HOST: return "refused_by_host";
    case GZ_VSEAT_JOINING: return "joining";
    case GZ_VSEAT_LOCKED: return "locked";
    case GZ_VSEAT_REFUSED: return "refused";
    default: return "none";
    }
}

static const char *fit_name(int c)
{
    return c == GZ_VFIT_FITS ? "fits" : c == GZ_VFIT_FITS_NOW_ONLY ? "fits_only_now" : "does_not_fit";
}

static const char *term_name(uint8_t t)
{
    switch (t) {
    case GZ_TT_PROFILE: return "profile";
    case GZ_TT_MINIMUM: return "members";
    case GZ_TT_LIFETIME: return "lifetime_blocks";
    case GZ_TT_CHANNEL: return "channel_sat";
    case GZ_TT_FEERATE: return "tree_feerate_sat_per_kvb";
    default: return adj_name(t);
    }
}

/* fit (13.4), from GZ_VLB_FIT: the class, and the deciding term with both values. */
static void fit_json(gz_jw *w, const gzp_view_obj_t *o, const terms_t *t)
{
    gz_bytes_t v;
    int cls = GZ_VFIT_FITS;
    uint8_t term = 0;
    uint64_t yours = 0, offered = 0;
    if (field(o, GZ_VLB_FIT, &v) && v.len == 18) {
        cls = v.data[0];
        term = v.data[1];
        yours = gz_get_u64(v.data + 2);
        offered = gz_get_u64(v.data + 10);
    }
    gz_jw_obj(w);
    gz_jw_kstr(w, "class", fit_name(cls));
    gz_jw_kstr(w, "compared_with", "whole_range");
    gz_jw_key(w, "rows");
    gz_jw_arr(w);
    if (term && term_name(term)) {
        gz_jw_obj(w);
        gz_jw_kstr(w, "term", term_name(term));
        gz_jw_kint(w, "offered", (int64_t)offered);
        gz_jw_kint(w, "yours", (int64_t)yours);
        gz_jw_kstr(w, "result", cls == GZ_VFIT_FITS_NOW_ONLY ? "fits_now_only" : "fails");
        gz_jw_end_obj(w);
    }
    gz_jw_end_arr(w);
    gz_jw_kint(w, "counted_from", t->ok ? t->o.minimum : 0);
    gz_jw_end_obj(w);
}

static void lobby_name(gz_jw *w, const terms_t *t)
{
    char d[300];
    size_t n = t->ok ? t->o.description_len : 0;
    /* The host's name for the lobby is the first line of its description. */
    if (n) memcpy(d, t->o.description, n);
    d[n] = 0;
    for (size_t i = 0; i < n; i++)
        if (d[i] == '\n') { d[i] = 0; break; }
    gz_jw_text(w, "name", n ? d : "A lobby", "host", 120);
}

/* A member's lobby (14.1), kind 2: a joined one, or one a query saw. `row`:
 * the shorter form of a list. */
void gzp_api_lobby_json(gzp_api_t *a, gz_jw *w, const gzp_view_obj_t *o, int row)
{
    terms_t t;
    gz_bytes_t v;
    char hk[67], fp[65];
    int seat = f8(o, GZ_VLB_SEAT, GZ_VSEAT_NONE), stage = f8(o, GZ_VLB_STAGE, 0);
    (void)a;
    terms_of(o, GZ_VLB_OUTER, GZ_VLB_CURRENT, &t);
    gz_jw_obj(w);
    gz_jw_kstr(w, "id", o->id);
    if (field(o, GZ_VLB_FINGERPRINT, &v) && v.len == 32) {
        hex(v.data, 32, fp);
        gz_jw_kstr(w, "fingerprint", fp);
    }
    lobby_name(w, &t);
    gz_jw_key(w, "host");
    gz_jw_obj(w);
    if (field(o, GZ_VLB_HOST_KEY, &v) && v.len == 33) {
        hex(v.data, 33, hk);
        gz_jw_kstr(w, "key", hk);
    }
    gz_jw_knull(w, "alias");
    if (field(o, GZ_VLB_HOST_ADDRESS, &v) && v.len < 80) {
        char ad[80];
        memcpy(ad, v.data, v.len);
        ad[v.len] = 0;
        gz_jw_kstr(w, "address", ad);
    }
    gz_jw_end_obj(w);
    gz_jw_kstr(w, "source", "direct_query");
    gz_jw_kstr(w, "stage", stage_name(stage));
    if (t.ok && !row) {
        gz_jw_key(w, "terms");
        terms_json(w, &t);
    }
    gz_jw_key(w, "fit");
    fit_json(w, o, &t);
    gz_jw_key(w, "start_rule");
    gz_jw_obj(w);
    gz_jw_kint(w, "target", t.ok ? t.o.target : 0);
    gz_jw_kint(w, "minimum", t.ok ? t.o.minimum : 0);
    gz_jw_kstr(w, "on_shortfall", "cancel");
    gz_jw_end_obj(w);
    /* A member learns the counts from lobby_status (not in P6a's view): none. */
    gz_jw_kraw(w, "counts", "{\"joined\":null,\"ready\":null}");
    gz_jw_key(w, "you");
    gz_jw_obj(w);
    gz_jw_kstr(w, "seat", seat_name(seat));
    gz_jw_kbool(w, "counted", seat == GZ_VSEAT_READY && !field(o, GZ_VLB_LOCKED_SINCE, &v));
    /* you.gate (14.1; 14.3 MUST 4): the gate as the core holds it; null with no seat. */
    if (seat != GZ_VSEAT_NONE && field(o, GZ_VLB_GATE, &v) && (v.len == 10 || v.len == 42)) {
        char dg[65];
        gz_jw_key(w, "gate");
        gz_jw_obj(w);
        gz_jw_kstr(w, "kind", v.data[0] == GZ_GATE_NONE ? "none" : v.data[0] == GZ_GATE_NODE ? "node" : "per_lobby");
        gz_jw_kstr(w, "state", v.data[1] ? "open" : "closed");
        if (v.len == 42) {
            hex(v.data + 10, 32, dg);
            gz_jw_kstr(w, "opened_for_digest", dg);
        } else {
            gz_jw_knull(w, "opened_for_digest");
        }
        gz_jw_kint(w, "since_at", (int64_t)(gz_get_u64(v.data + 2) / 1000));
        gz_jw_end_obj(w);
    } else {
        gz_jw_knull(w, "gate");
    }
    if (field(o, GZ_VLB_OUTCOME, &v) && v.len == 3) gz_jw_kraw(w, "outcome", "{\"code\":\"ended\"}");
    else gz_jw_knull(w, "outcome");
    gz_jw_end_obj(w);
    if (row) {
        gz_jw_kint(w, "channel_sat", t.ok ? (int64_t)t.o.channel_sat : 0);
        gz_jw_kint(w, "joining_fee_sat", t.ok ? (int64_t)current_value(&t, GZ_TT_JOINING_FEE) : 0);
        gz_jw_kint(w, "exit_blocks", t.ok ? (int64_t)t.o.winddown_blocks * 2 : 0);
    } else {
        gz_jw_knull(w, "round");
        gz_jw_knull(w, "funding");
        gz_jw_knull(w, "factory_id");
        gz_jw_knull(w, "terms_change");
    }
    if (a->answer_replayed) gz_jw_kbool(w, "replayed", 1);
    gz_jw_end_obj(w);
}

/* A seat id, local to the host's program: 16 hex of the key's SHA-256. */
static void seat_id(const uint8_t key[33], char out[17])
{
    uint8_t d[32];
    SHA256(key, 33, d);
    hex(d, 8, out);
}

/* A hosted lobby (15.3), kind 3. */
void gzp_api_host_lobby_json(gzp_api_t *a, gz_jw *w, const gzp_view_obj_t *o, int row)
{
    terms_t t;
    gz_bytes_t v, s;
    char fp[65];
    int stage = f8(o, GZ_VHL_STAGE, 0), joined = 0, ready = 0, locked = 0, refused = 0;
    uint64_t aside = f64(o, GZ_VHL_SET_ASIDE);
    (void)a;
    terms_of(o, GZ_VHL_OUTER, GZ_VHL_CURRENT, &t);
    if (field(o, GZ_VHL_COUNTS, &v) && v.len == 8) {
        joined = gz_get_u16(v.data);
        ready = gz_get_u16(v.data + 2);
        locked = gz_get_u16(v.data + 4);
        refused = gz_get_u16(v.data + 6);
    }
    gz_jw_obj(w);
    gz_jw_kstr(w, "id", o->id);
    if (field(o, GZ_VHL_FINGERPRINT, &v) && v.len == 32) {
        hex(v.data, 32, fp);
        gz_jw_kstr(w, "fingerprint", fp);
    }
    lobby_name(w, &t);
    gz_jw_kstr(w, "stage", stage_name(stage));
    if (t.ok) {
        gz_jw_key(w, "terms");
        terms_json(w, &t);
    }
    gz_jw_key(w, "counts");
    gz_jw_obj(w);
    gz_jw_kint(w, "joined", joined);
    gz_jw_kint(w, "ready", ready);
    gz_jw_kint(w, "locked", locked);
    gz_jw_kint(w, "refused", refused);
    gz_jw_end_obj(w);
    {
        int paused = f8(o, GZ_VHL_PAUSED, 0) == 1;
        int can = stage == GZ_LOBBY_OPEN && t.ok && ready >= t.o.minimum && !paused;
        gz_jw_kbool(w, "can_start_now", can);
        gz_jw_key(w, "start_blocked_by");
        gz_jw_arr(w);
        if (stage != GZ_LOBBY_OPEN) gz_jw_str(w, "not_open");
        else if (paused) gz_jw_str(w, "paused");
        else if (!t.ok || ready < t.o.minimum) gz_jw_str(w, "below_minimum");
        gz_jw_end_arr(w);
    }
    gz_jw_key(w, "funding");
    gz_jw_obj(w);
    gz_jw_kint(w, "needed_at_minimum_sat", (int64_t)aside);
    gz_jw_kint(w, "needed_at_target_sat", (int64_t)aside);
    gz_jw_kint(w, "set_aside_sat", (int64_t)aside);
    gz_jw_kint(w, "wallet_free_sat", 0);
    gz_jw_end_obj(w);
    if (!row) {
        gz_jw_key(w, "seats");
        gz_jw_arr(w);
        if (field(o, GZ_VHL_SEATS, &s))
            for (size_t k = 0; k + GZ_VHL_SEAT_LEN <= s.len; k += GZ_VHL_SEAT_LEN) {
                const uint8_t *e = s.data + k;
                char sid[17], nm[32];
                seat_id(e, sid);
                snprintf(nm, sizeof nm, "Seat %.4s", sid);
                gz_jw_obj(w);
                gz_jw_kstr(w, "seat", sid);
                gz_jw_text(w, "name", nm, "you", 64);
                gz_jw_kstr(w, "state", seat_name(e[33]));
                gz_jw_kbool(w, "can_remove", stage == GZ_LOBBY_OPEN && (e[33] == GZ_VSEAT_JOINED || e[33] == GZ_VSEAT_READY ||
                                                                        e[33] == GZ_VSEAT_LOCKED));
                gz_jw_end_obj(w);
            }
        gz_jw_end_arr(w);
        gz_jw_knull(w, "standby");
        gz_jw_knull(w, "round");
        gz_jw_knull(w, "funding_tx");
        gz_jw_knull(w, "factory_id");
    }
    if (a->answer_replayed) gz_jw_kbool(w, "replayed", 1);
    gz_jw_end_obj(w);
}

/* ---- finding objects -------------------------------------------------------- */

const gzp_view_obj_t *gzp_api_find(gzp_api_t *a, uint32_t kind, const char *id)
{
    return id ? gzp_view_find(&a->view, kind, id) : NULL;
}

/* The scope (fingerprint) a lobby's local id names, from its view object. */
int gzp_api_scope_of(gzp_api_t *a, const char *id, int host, uint8_t scope[32], const gzp_view_obj_t **obj)
{
    const gzp_view_obj_t *o = gzp_api_find(a, host ? GZ_VIEW_HOST_LOBBY : GZ_VIEW_LOBBY, id);
    gz_bytes_t v;
    if (obj) *obj = o;
    if (!o || !field(o, host ? GZ_VHL_FINGERPRINT : GZ_VLB_FINGERPRINT, &v) || v.len != 32) return 0;
    memcpy(scope, v.data, 32);
    return 1;
}

int gzp_api_parse_host(const char *s, uint8_t key[33], char *addr, size_t cap)
{
    const char *at = s ? strchr(s, '@') : NULL;
    char k[67];
    if (!at || at - s != 66 || strlen(at + 1) >= cap || !at[1]) return 0;
    memcpy(k, s, 66);
    k[66] = 0;
    if (!unhex(k, key, 33)) return 0;
    strcpy(addr, at + 1);
    return 1;
}

int gzp_api_unhex32(const char *s, uint8_t out[32]) { return unhex(s, out, 32); }
