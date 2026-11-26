/* SPDX-License-Identifier: MIT */
/* The local API's acting calls and reads for lobbies, hosting, discovery,
 * conditions, pause and the signing setting (W12): the command builders of
 * docs/notes/view-objects.md section 6, the answers from the view. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/rand.h>
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

static const char *jstr(const gz_json *b, const char *k)
{
    const gz_json *v = b ? gz_json_get(b, k) : NULL;
    return v && v->type == GZ_JSON_STR ? v->s : NULL;
}

static int64_t jint(const gz_json *b, const char *k, int64_t dflt)
{
    const gz_json *v = b ? gz_json_get(b, k) : NULL;
    return v && v->type == GZ_JSON_INT ? v->i : dflt;
}

static int jbool(const gz_json *b, const char *k, int dflt)
{
    const gz_json *v = b ? gz_json_get(b, k) : NULL;
    return v && v->type == GZ_JSON_BOOL ? (int)v->i : dflt;
}

static int not_found(gz_api_error *err)
{
    gz_api_err_set(err, "not_found", NULL, NULL);
    return 404;
}

/* ---- command arguments --------------------------------------------------------- */

typedef struct {
    uint8_t b[12000];
    size_t at;
    int bad;
} args_t;

static void put(args_t *a, uint64_t type, const void *v, size_t n)
{
    if (gz_rec_put(a->b, sizeof a->b, &a->at, type, (const uint8_t *)v, n) != GZ_OK) a->bad = 1;
}

static void put8(args_t *a, uint64_t type, uint8_t v) { put(a, type, &v, 1); }

static void put32(args_t *a, uint64_t type, uint32_t v)
{
    uint8_t b[4];
    gz_put_u32(b, v);
    put(a, type, b, 4);
}

static void put64(args_t *a, uint64_t type, uint64_t v)
{
    uint8_t b[8];
    gz_put_u64(b, v);
    put(a, type, b, 8);
}

/* A command for a held call. A call the interface sends with no request id
 * (pause, the signing setting, conditions, a query: 11.3, 13.2, 14.3) gets an
 * internal one; `digest` 1 marks it the API's own request (the core then
 * keeps the id and checks the authority a widening needs), with a digest of
 * that id, since no body was digested. */
static int send(gzp_api_t *a, const gz_api_call *c, uint16_t code, const args_t *x, int digest, gz_api_error *err)
{
    gz_api_call k = *c;
    char rid[40];
    uint8_t d[32];
    if (x->bad) {
        gz_api_err_set(err, "bad_value", NULL, NULL);
        return 400;
    }
    if (!k.request_id) {
        uint8_t r[12];
        static const char hx[] = "0123456789abcdef";
        RAND_bytes(r, sizeof r);
        memcpy(rid, "gzp-", 4);
        for (int i = 0; i < 12; i++) {
            rid[4 + 2 * i] = hx[r[i] >> 4];
            rid[5 + 2 * i] = hx[r[i] & 15];
        }
        rid[28] = 0;
        k.request_id = rid;
        k.digest = NULL;
        if (digest) {
            SHA256((const uint8_t *)rid, strlen(rid), d);
            k.digest = d;
        }
    }
    return gzp_api_send_command(a, &k, code, x->b, x->at, err);
}

/* ---- conditions (13; GZ_CMD_API_SET_CONDITIONS) ------------------------------------- */

/* LOBBY_JOIN's encoding of conditions (node.h; lobbyslot.c's COND_HEAD). */
static size_t cond_encode(const gz_lobby_conditions_t *c, uint8_t *b, size_t cap)
{
    size_t n = 27 + 9u * c->limits.n_max;
    if (n > cap) return 0;
    b[0] = c->current_only;
    gz_put_u16(b + 1, c->min_members);
    gz_put_u64(b + 3, c->limits.min_channel_sat);
    gz_put_u32(b + 11, c->limits.max_tree_feerate);
    gz_put_u32(b + 15, c->limits.min_lifetime);
    gz_put_u32(b + 19, c->limits.max_lifetime);
    gz_put_u16(b + 23, c->limits.min_members);
    b[25] = c->limits.profiles;
    b[26] = c->limits.n_max;
    for (uint8_t i = 0; i < c->limits.n_max; i++) {
        b[27 + 9 * i] = c->limits.max[i].type;
        gz_put_u64(b + 28 + 9 * i, c->limits.max[i].max);
    }
    return n;
}

static int cond_decode(const uint8_t *p, size_t n, gz_lobby_conditions_t *c)
{
    memset(c, 0, sizeof *c);
    if (n == 0) return 1;
    if (n < 27 || p[26] > GZ_TERMS_MAX_ADJ || n != 27 + 9u * p[26]) return 0;
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
        c->limits.max[i].type = p[27 + 9 * i];
        c->limits.max[i].max = gz_get_u64(p + 28 + 9 * i);
    }
    return 1;
}

/* The saved conditions and their version, from the status object. */
static uint32_t saved_conditions(gzp_api_t *a, gz_lobby_conditions_t *c, char *preset, size_t cap)
{
    const gzp_view_obj_t *o = gzp_api_find(a, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
    gz_bytes_t all, v;
    memset(c, 0, sizeof *c);
    if (preset) snprintf(preset, cap, "custom");
    if (!o) return 0;
    all.data = o->bytes;
    all.len = o->len;
    if (preset && gz_rec_find(all, GZ_VST_PRESET, &v) == 1 && v.len < cap) {
        memcpy(preset, v.data, v.len);
        preset[v.len] = 0;
    }
    if (gz_rec_find(all, GZ_VST_CONDITIONS, &v) != 1 || v.len < 4) return 0;
    cond_decode(v.data + 4, v.len - 4, c);
    return gz_get_u32(v.data);
}

static uint64_t adj_max(const gz_lobby_conditions_t *c, uint8_t type)
{
    for (uint8_t i = 0; i < c->limits.n_max; i++)
        if (c->limits.max[i].type == type) return c->limits.max[i].max;
    return 0;
}

static const struct { const char *name; uint8_t type; } ADJ[] = {
    {"max_joining_fee_sat", GZ_TT_JOINING_FEE}, {"max_fee_base_msat", GZ_TT_FEE_BASE}, {"max_fee_ppm", GZ_TT_FEE_PROP}};

static void conditions_json(gz_jw *w, const gz_lobby_conditions_t *c)
{
    gz_jw_obj(w);
    gz_jw_kraw(w, "profiles", "[\"standard\"]");
    gz_jw_kint(w, "min_members", c->limits.min_members ? c->limits.min_members : 2);
    gz_jw_kint(w, "min_channel_sat", (int64_t)c->limits.min_channel_sat);
    for (size_t i = 0; i < sizeof ADJ / sizeof ADJ[0]; i++) {
        uint64_t m = adj_max(c, ADJ[i].type);
        if (m) gz_jw_kint(w, ADJ[i].name, (int64_t)m);
        else gz_jw_knull(w, ADJ[i].name);
    }
    gz_jw_kint(w, "min_life_blocks", c->limits.min_lifetime);
    if (c->limits.max_lifetime) gz_jw_kint(w, "max_life_blocks", c->limits.max_lifetime);
    else gz_jw_knull(w, "max_life_blocks");
    gz_jw_knull(w, "max_exit_blocks");       /* not compared by the core in Slice 1 */
    gz_jw_knull(w, "min_confirmations");
    gz_jw_kstr(w, "compare_with", c->current_only ? "current_value" : "whole_range");
    gz_jw_end_obj(w);
}

/* The JSON conditions into the core's; 0 and *field on a bad value. */
static int conditions_from(const gz_json *j, gz_lobby_conditions_t *c, const char **field)
{
    int64_t v;
    memset(c, 0, sizeof *c);
    *field = NULL;
    if (!j || j->type != GZ_JSON_OBJ) { *field = "/conditions"; return 0; }
    v = jint(j, "min_members", 0);
    if (v < 0 || v > 512) { *field = "/conditions/min_members"; return 0; }
    c->limits.min_members = (uint16_t)v;
    c->min_members = (uint16_t)v;     /* the ready hint: the fewest members it signs with */
    v = jint(j, "min_channel_sat", 0);
    if (v < 0) { *field = "/conditions/min_channel_sat"; return 0; }
    c->limits.min_channel_sat = (uint64_t)v;
    v = jint(j, "min_life_blocks", 0);
    if (v < 0 || v > 0xffffffffLL) { *field = "/conditions/min_life_blocks"; return 0; }
    c->limits.min_lifetime = (uint32_t)v;
    v = jint(j, "max_life_blocks", 0);
    if (v < 0 || v > 0xffffffffLL) { *field = "/conditions/max_life_blocks"; return 0; }
    c->limits.max_lifetime = (uint32_t)v;
    for (size_t i = 0; i < sizeof ADJ / sizeof ADJ[0]; i++) {
        v = jint(j, ADJ[i].name, 0);
        if (v < 0) { *field = "/conditions/max_joining_fee_sat"; return 0; }
        if (v > 0) {
            c->limits.max[c->limits.n_max].type = ADJ[i].type;
            c->limits.max[c->limits.n_max++].max = (uint64_t)v;
        }
    }
    {
        const char *cw = jstr(j, "compare_with");
        c->current_only = cw && strcmp(cw, "current_value") == 0;
    }
    return 1;
}

/* What a change loosens, as the core decides it (api.c, loosens): codes, in
 * the core's order; and their names (13.2 `loosens`). */
static size_t loosens(const gz_lobby_conditions_t *from, const gz_lobby_conditions_t *to, uint8_t *l, const char **names)
{
    const gz_terms_limits_t *a = &from->limits, *b = &to->limits;
    size_t n = 0;
    if (!from->current_only && to->current_only) { names[n] = "compare_with"; l[n++] = GZ_COND_L_COMPARE; }
    if (to->min_members < from->min_members) { names[n] = "ready_hint"; l[n++] = GZ_COND_L_HINT; }
    if (a->profiles && (!b->profiles || (b->profiles & (uint8_t)~a->profiles))) { names[n] = "profiles"; l[n++] = GZ_TT_PROFILE; }
    if (b->min_members < a->min_members) { names[n] = "min_members"; l[n++] = GZ_TT_MINIMUM; }
    if (b->min_lifetime < a->min_lifetime || (a->max_lifetime && (!b->max_lifetime || b->max_lifetime > a->max_lifetime))) {
        names[n] = "life_blocks";
        l[n++] = GZ_TT_LIFETIME;
    }
    if (b->min_channel_sat < a->min_channel_sat) { names[n] = "min_channel_sat"; l[n++] = GZ_TT_CHANNEL; }
    if (a->max_tree_feerate && (!b->max_tree_feerate || b->max_tree_feerate > a->max_tree_feerate)) {
        names[n] = "max_tree_feerate";
        l[n++] = GZ_TT_FEERATE;
    }
    for (size_t i = 0; i < sizeof ADJ / sizeof ADJ[0]; i++) {
        uint64_t am = adj_max(from, ADJ[i].type), bm = adj_max(to, ADJ[i].type);
        if (am && (!bm || bm > am)) { names[n] = ADJ[i].name; l[n++] = ADJ[i].type; }
    }
    return n;
}

static void name_list(gz_jw *w, const char *key, const char **names, size_t n)
{
    gz_jw_key(w, key);
    gz_jw_arr(w);
    for (size_t i = 0; i < n; i++) gz_jw_str(w, names[i]);
    gz_jw_end_arr(w);
}

/* The lobbies the view holds that a member could join or is in (kind 2), with
 * their class under `c`. */
static void fit_summary(gzp_api_t *a, gz_jw *w, const gz_lobby_conditions_t *c, int *would_leave_out)
{
    int listed = 0, fit = 0, now = 0;
    (void)would_leave_out;
    for (size_t i = 0; i < a->view.n; i++) {
        const gzp_view_obj_t *o = &a->view.obj[i];
        gz_bytes_t all = {o->bytes, o->len}, x, y;
        gz_terms_outer_t t;
        gz_terms_current_t v;
        uint8_t term;
        if (o->kind != GZ_VIEW_LOBBY || gz_rec_find(all, GZ_VLB_OUTER, &x) != 1 || gz_rec_find(all, GZ_VLB_CURRENT, &y) != 1)
            continue;
        if (gz_terms_decode_outer(x.data, x.len, gz_lobby_policy(), &t) != GZ_TERMS_OK ||
            gz_terms_decode_current(y.data, y.len, &t, &v) != GZ_TERMS_OK)
            continue;
        listed++;
        switch (gz_lobby_classify(&t, &v, c, &term)) {
        case GZ_FIT_YES: fit++; break;
        case GZ_FIT_NOW: now++; break;
        default: break;
        }
    }
    gz_jw_key(w, "fit_summary");
    gz_jw_obj(w);
    gz_jw_kint(w, "listed", listed);
    gz_jw_kint(w, "fit", fit);
    gz_jw_kint(w, "fits_only_now", now);
    gz_jw_knull(w, "excluded_most_by");
    gz_jw_end_obj(w);
}

static int conditions_get(gzp_api_t *a, gz_jw *w)
{
    gz_lobby_conditions_t c;
    char preset[24];
    uint32_t version = saved_conditions(a, &c, preset, sizeof preset);
    gz_jw_obj(w);
    gz_jw_kint(w, "version", version);
    gz_jw_kstr(w, "preset", preset);
    gz_jw_key(w, "conditions");
    conditions_json(w, &c);
    gz_jw_kraw(w, "limits", "{\"min_members\":[2,512]}");
    gz_jw_kraw(w, "presets", "[]");
    fit_summary(a, w, &c, NULL);
    gz_jw_kraw(w, "copied_into", "[]");
    gz_jw_kbool(w, "editable", 1);
    gz_jw_end_obj(w);
    return 200;
}

/* ---- the draft of a lobby (15.1) and the terms it becomes ------------------------------------- */

/* terms.md section 11's T1, the defaults a draft changes. */
static const char T1[] =
    "0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800"
    "0000042102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e"
    "34733491560610c31b4b333d598e176bb883203548a5e60801020a0200080c02"
    "00030e08000000006af501801001001204000075301404000927c016040000ea"
    "6018090004000300100104031a04000000901c04000000241e08000000000001"
    "86a02004000000642201004010000000000000000000000000000007d0421000"
    "0000000000000000000000000003e84410000000000000006400000000000009"
    "c4";

static size_t unhex_all(const char *s, uint8_t *out, size_t cap)
{
    size_t n = strlen(s) / 2;
    if (n > cap) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return n;
}

static int range_of(const gz_json *d, const char *k, uint64_t *mn, uint64_t *now, uint64_t *mx)
{
    const gz_json *r = d ? gz_json_get(d, k) : NULL;
    if (!r || r->type != GZ_JSON_OBJ) return 0;
    *mn = (uint64_t)jint(r, "min", (int64_t)*mn);
    *now = (uint64_t)jint(r, "now", (int64_t)*now);
    *mx = (uint64_t)jint(r, "max", (int64_t)*mx);
    return 1;
}

/* A draft into outer rules and current values, for this host's key. 0 and
 * *why when it cannot be. */
static int draft_terms(gzp_api_t *a, const gz_json *d, gz_terms_outer_t *o, gz_terms_current_t *c, const char **why)
{
    uint8_t t1[512];
    size_t n = unhex_all(T1, t1, sizeof t1);
    const char *name = jstr(d, "name"), *desc = jstr(d, "description");
    char text[300];
    *why = NULL;
    if (!n || gz_terms_parse_outer(t1, n, o) != GZ_TERMS_OK) { *why = "internal"; return 0; }
    if (!a->host_key_set) { *why = "not_a_host"; return 0; }
    memcpy(o->host_key, a->host_key, 33);
    RAND_bytes(o->lobby_salt, sizeof o->lobby_salt);
    o->target = (uint16_t)jint(d, "target", o->target);
    o->minimum = (uint16_t)jint(d, "minimum", o->minimum);
    /* The deadline is the person's, and in the future (local-api.md 15.1's
     * deadline_missing and deadline_past): T1's own is a fixed example date,
     * and a lobby opened with a past deadline ends at once. */
    if (!d || !gz_json_get(d, "deadline_at")) { *why = "deadline_missing"; return 0; }
    o->deadline = (uint64_t)jint(d, "deadline_at", 0);
    if (o->deadline <= (uint64_t)time(NULL)) { *why = "deadline_past"; return 0; }
    o->ready_window_ms = (uint32_t)jint(d, "ready_window_ms", o->ready_window_ms);
    o->signing_budget_ms = (uint32_t)jint(d, "signing_budget_ms", o->signing_budget_ms);
    o->step_timeout_ms = (uint32_t)jint(d, "step_timeout_ms", o->step_timeout_ms);
    o->lifetime_blocks = (uint32_t)jint(d, "lifetime_blocks", o->lifetime_blocks);
    o->winddown_blocks = (uint32_t)jint(d, "winddown_blocks", o->winddown_blocks);
    o->channel_sat = (uint64_t)jint(d, "channel_sat", (int64_t)o->channel_sat);
    o->tree_feerate = (uint32_t)jint(d, "tree_feerate_sat_per_kvb", o->tree_feerate);
    /* The name, then the description, as the host's text (terms.md type 5). */
    snprintf(text, sizeof text, "%s%s%s", name ? name : "", desc && desc[0] ? "\n" : "", desc ? desc : "");
    o->description_len = (uint16_t)strlen(text) < sizeof o->description ? (uint16_t)strlen(text) : (uint16_t)sizeof o->description;
    memcpy(o->description, text, o->description_len);
    memset(c, 0, sizeof *c);
    c->version = 1;
    for (uint8_t i = 0; i < o->n_adj; i++) {
        const char *k = o->adj[i].type == GZ_TT_JOINING_FEE ? "joining_fee_sat"
                      : o->adj[i].type == GZ_TT_FEE_BASE ? "fee_base_msat" : o->adj[i].type == GZ_TT_FEE_PROP ? "fee_ppm" : NULL;
        uint64_t mn = o->adj[i].min, mx = o->adj[i].max, now = o->adj[i].min;
        if (k) range_of(d, k, &mn, &now, &mx);
        o->adj[i].min = mn;
        o->adj[i].max = mx;
        c->val[c->n_values].type = o->adj[i].type;
        c->val[c->n_values++].value = now;
    }
    if (gz_terms_check_outer(o, gz_lobby_policy()) != GZ_TERMS_OK) { *why = "bad_terms"; return 0; }
    return 1;
}

/* The draft's digest (15.1: what the person saw is what is opened): SHA-256
 * of the outer rules with a zero salt, and the current values. */
static void draft_digest(const gz_terms_outer_t *o, const gz_terms_current_t *c, char out[65])
{
    gz_terms_outer_t z = *o;
    uint8_t b[GZ_TERMS_OUTER_MAX + GZ_TERMS_CURRENT_MAX], d[32];
    size_t n;
    gz_terms_current_t cz = *c;
    memset(z.lobby_salt, 0, sizeof z.lobby_salt);
    memset(cz.outer_digest, 0, 32);
    n = gz_terms_encode_outer(&z, b, GZ_TERMS_OUTER_MAX);
    n += gz_terms_encode_current(&cz, b + n, GZ_TERMS_CURRENT_MAX);
    SHA256(b, n, d);
    for (int i = 0; i < 32; i++) snprintf(out + 2 * i, 3, "%02x", d[i]);
}

static int host_preview(gzp_api_t *a, const gz_json *d, gz_jw *w, gz_api_error *err)
{
    gz_terms_outer_t o;
    gz_terms_current_t c;
    const char *why;
    char dg[65];
    if (!draft_terms(a, d, &o, &c, &why)) {
        int deadline = !strcmp(why, "deadline_missing") || !strcmp(why, "deadline_past");
        gz_jw_obj(w);
        gz_jw_knull(w, "draft_digest");
        gz_jw_knull(w, "as_members_see_it");        /* terms that cannot be made have no view */
        gz_jw_key(w, "problems");
        gz_jw_arr(w);
        if (deadline) {                              /* 15.1: a problem of the draft, by field */
            gz_jw_obj(w);
            gz_jw_kstr(w, "field", "/deadline_at");
            gz_jw_kstr(w, "code", why);
            gz_jw_end_obj(w);
        }
        gz_jw_end_arr(w);
        gz_jw_kbool(w, "can_open", 0);
        gz_jw_key(w, "cannot_open_because");
        gz_jw_arr(w);
        gz_jw_str(w, deadline ? "problems" : why);
        gz_jw_end_arr(w);
        gz_jw_end_obj(w);
        (void)err;
        return 200;
    }
    draft_digest(&o, &c, dg);
    gz_jw_obj(w);
    gz_jw_kstr(w, "draft_digest", dg);
    gz_jw_key(w, "as_members_see_it");               /* 15.1 */
    gzp_api_draft_json(w, &o, &c);
    gz_jw_kint(w, "funding_at_minimum_sat", 0);
    gz_jw_kint(w, "funding_at_target_sat", 0);
    gz_jw_kint(w, "chain_fee_estimate_sat", 0);
    gz_jw_kint(w, "wallet_free_sat", 0);
    gz_jw_kraw(w, "covers", "{\"minimum\":true,\"target\":true}");
    gz_jw_kraw(w, "dates", "[]");
    gz_jw_kraw(w, "host_deadlines", "[]");
    gz_jw_kraw(w, "problems", "[]");
    gz_jw_kbool(w, "can_open", 1);
    gz_jw_kraw(w, "cannot_open_because", "[]");
    gz_jw_end_obj(w);
    return 200;
}

/* ---- the calls ------------------------------------------------------------------------ */

static void list_page(gzp_api_t *a, gz_jw *w, uint32_t kind)
{
    gz_jw_obj(w);
    gz_jw_key(w, "items");
    gz_jw_arr(w);
    for (size_t i = 0; i < a->view.n; i++)
        if (a->view.obj[i].kind == kind) {
            if (kind == GZ_VIEW_LOBBY) gzp_api_lobby_json(a, w, &a->view.obj[i], 1);
            else gzp_api_host_lobby_json(a, w, &a->view.obj[i], 1);
        }
    gz_jw_end_arr(w);
    gz_jw_knull(w, "next_cursor");
    gz_jw_end_obj(w);
}

static int query_json(gzp_api_t *a, gz_jw *w, const char *id)
{
    const gzp_view_obj_t *o = gzp_api_find(a, GZ_VIEW_DISCOVERY, id);
    gz_bytes_t all, v;
    int st;
    if (!o) return 0;
    all.data = o->bytes;
    all.len = o->len;
    st = gz_rec_find(all, GZ_VDQ_STATE, &v) == 1 && v.len == 1 ? v.data[0] : 1;
    gz_jw_obj(w);
    gz_jw_kstr(w, "query_id", id);
    gz_jw_kstr(w, "state", st == 2 ? "answered" : st == 3 ? "failed" : "asking");
    gz_jw_key(w, "lobbies");
    gz_jw_arr(w);
    if (gz_rec_find(all, GZ_VDQ_LOBBIES, &v) == 1) {
        size_t s = 0;
        char id2[GZ_LOCAL_ID_MAX + 1];
        for (size_t k = 0; k <= v.len; k++)
            if (k == v.len || v.data[k] == ',') {
                if (k > s && k - s <= GZ_LOCAL_ID_MAX) {
                    memcpy(id2, v.data + s, k - s);
                    id2[k - s] = 0;
                    gz_jw_str(w, id2);
                }
                s = k + 1;
            }
    }
    gz_jw_end_arr(w);
    if (gz_rec_find(all, GZ_VDQ_FAILED, &v) == 1 && v.len < 32) {
        char why[32];
        memcpy(why, v.data, v.len);
        why[v.len] = 0;
        gz_jw_kstr(w, "failed_because", why);
    } else {
        gz_jw_knull(w, "failed_because");
    }
    if (a->answer_replayed) gz_jw_kbool(w, "replayed", 1);
    gz_jw_end_obj(w);
    return 1;
}

/* A held call's answer, once the core's result came (api.c): the object it
 * acted on, as it is now (7.4: a replay answers the current state). */
static void answer(gzp_api_t *a, int call, const char *object, const char *params, gz_jw *w)
{
    const gzp_view_obj_t *o;
    switch (call) {
    case GZ_API_C_DISCOVERY_QUERY:
        if (object && query_json(a, w, object)) return;
        break;
    case GZ_API_C_JOIN:
    case GZ_API_C_READY:
    case GZ_API_C_LEAVE:
        if (object && (o = gzp_api_find(a, GZ_VIEW_LOBBY, object)) != NULL) {
            gzp_api_lobby_json(a, w, o, 0);
            return;
        }
        break;
    case GZ_API_C_HOST_OPEN:
    case GZ_API_C_HOST_START:
    case GZ_API_C_HOST_CANCEL:
    case GZ_API_C_HOST_SEAT_REMOVE:
        if (object && (o = gzp_api_find(a, GZ_VIEW_HOST_LOBBY, object)) != NULL) {
            gzp_api_host_lobby_json(a, w, o, 0);
            return;
        }
        break;
    case GZ_API_C_CONDITIONS_PUT:
        conditions_get(a, w);
        return;
    default:
        break;
    }
    gz_jw_raw(w, params && params[0] == '{' ? params : "{}");
}

/* With "replayed": true added to the object when the core answered from
 * the first answer (7.4; review of #79, L1). */
void gzp_api_answer(gzp_api_t *a, int call, const char *object, const char *params, gz_jw *w)
{
    a->answer_replayed = params && strstr(params, "\"replayed\":true") != NULL;
    answer(a, call, object, params, w);
    a->answer_replayed = 0;
}

/* seen_current_digest: 64 hex when given; required when `need`. */
static int seen_digest(const char *seen, int need, uint8_t out[32], gz_api_error *err)
{
    memset(out, 0, 32);
    if (!seen && need) {
        gz_api_err_set(err, "missing_field", "/seen_current_digest", NULL);
        return 400;
    }
    if (seen && !gzp_api_unhex32(seen, out)) {
        gz_api_err_set(err, "bad_value", "/seen_current_digest", NULL);
        return 400;
    }
    return 0;
}

/* A ready under at_join without the passphrase: with a request id the core
 * looks the id up first and answers a replay (7.4, "MUST look the
 * request_id up before it checks the body"; review of #79, M3), and
 * refuses a new one (field 28); without one, missing_field here. */
static int passphrase_or_replay(const gz_api_call *c, int unlock, gz_api_error *err)
{
    if (!unlock || jstr(c->body, "passphrase") || c->request_id) return 0;
    gz_api_err_set(err, "missing_field", "/passphrase", NULL);
    return 400;
}

int gzp_api_lobby_call(gzp_api_t *a, const gz_api_call *c, gz_jw *w, gz_api_error *err)
{
    const gzp_view_obj_t *o;
    uint8_t scope[32], key[33];
    char addr[80];
    args_t x;
    int st;
    memset(&x, 0, sizeof x);
    switch (c->id) {
    case GZ_API_C_LOBBIES:
        list_page(a, w, GZ_VIEW_LOBBY);
        return 200;
    case GZ_API_C_HOST_LOBBIES:
        list_page(a, w, GZ_VIEW_HOST_LOBBY);
        return 200;
    case GZ_API_C_LOBBY:
        if (!(o = gzp_api_find(a, GZ_VIEW_LOBBY, c->path_id))) return not_found(err);
        gzp_api_lobby_json(a, w, o, 0);
        return 200;
    case GZ_API_C_HOST_LOBBY:
        if (!(o = gzp_api_find(a, GZ_VIEW_HOST_LOBBY, c->path_id))) return not_found(err);
        gzp_api_host_lobby_json(a, w, o, 0);
        return 200;
    case GZ_API_C_DISCOVERY_QUERY_GET:
        return query_json(a, w, c->path_id) ? 200 : not_found(err);
    case GZ_API_C_DISCOVERY_QUERY:
        if (!gzp_api_parse_host(jstr(c->body, "host"), key, addr, sizeof addr)) {
            gz_api_err_set(err, "bad_host_address", "/host", NULL);
            return 400;
        }
        put(&x, 12, key, 33);
        put(&x, 14, addr, strlen(addr));
        return send(a, c, GZ_CMD_LOBBY_QUERY, &x, 0, err);
    case GZ_API_C_JOIN: {
        gz_bytes_t v, all;
        const char *seen = jstr(c->body, "seen_current_digest");
        int ready = jbool(c->body, "ready", 1), at_join = a->member_signing == GZ_MEMBER_SIGNING_AT_JOIN;
        int unlock = at_join && ready;
        uint8_t sd[32];
        if (!gzp_api_scope_of(a, c->path_id, 0, scope, &o)) return not_found(err);
        all.data = o->bytes;
        all.len = o->len;
        /* The gate is opened for exactly the values the person reviewed
         * (14.3 rule 2): required with a ready under at_join, and sent to the
         * core, which binds the gate to it (review of #79, M1). */
        if ((st = seen_digest(seen, unlock, sd, err)) != 0) return st;
        if (gz_rec_find(all, GZ_VLB_CURRENT, &v) == 1 && seen) {
            uint8_t d[32];
            gz_terms_current_digest(v.data, v.len, d);
            if (memcmp(sd, d, 32) != 0) {
                gz_api_err_set(err, "terms_changed", "/seen_current_digest", NULL);
                return 409;
            }
        }
        /* 14.3 rule 2: under at_join a ready join gives the passphrase; kind
         * A checks it before this phase (the server's derivation). */
        if (c->phase == GZ_API_PHASE_CHECK) return 0;
        if ((st = passphrase_or_replay(c, unlock, err)) != 0) return st;
        put(&x, 12, scope, 32);
        if (gz_rec_find(all, GZ_VLB_HOST_KEY, &v) != 1 || v.len != 33) return not_found(err);
        put(&x, 14, v.data, 33);
        if (gz_rec_find(all, GZ_VLB_HOST_ADDRESS, &v) != 1) return not_found(err);
        put(&x, 16, v.data, v.len);
        put8(&x, 20, (uint8_t)(ready ? 1 : 0));
        if (unlock && jstr(c->body, "passphrase")) {
            put8(&x, 24, 1);                     /* the gate open from the join (the passphrase checked) */
            put(&x, 26, sd, 32);                 /* for these values only */
        } else if (unlock) {
            put8(&x, 28, 1);                     /* no passphrase: only a replay is answered (7.4) */
        }
        return send(a, c, GZ_CMD_LOBBY_JOIN, &x, 1, err);
    }
    case GZ_API_C_READY: {
        int ready = jbool(c->body, "ready", 1), at_join = a->member_signing == GZ_MEMBER_SIGNING_AT_JOIN;
        int unlock = at_join && ready;
        uint8_t sd[32];
        if (!gzp_api_scope_of(a, c->path_id, 0, scope, NULL)) return not_found(err);
        if ((st = seen_digest(jstr(c->body, "seen_current_digest"), unlock, sd, err)) != 0) return st;
        if (c->phase == GZ_API_PHASE_CHECK) return 0;
        if ((st = passphrase_or_replay(c, unlock, err)) != 0) return st;
        put(&x, 12, scope, 32);
        if (unlock && jstr(c->body, "passphrase")) {
            put8(&x, 14, 1);
            put(&x, 16, sd, 32);                 /* the gate bound to it (#52's field 16) */
        } else if (unlock) {
            put8(&x, 28, 1);
        }
        return send(a, c, ready ? GZ_CMD_LOBBY_READY : GZ_CMD_LOBBY_UNREADY, &x, 1, err);
    }
    case GZ_API_C_LEAVE:
        if (!gzp_api_scope_of(a, c->path_id, 0, scope, NULL)) return not_found(err);
        put(&x, 12, scope, 32);
        return send(a, c, GZ_CMD_LOBBY_LEAVE, &x, 1, err);
    case GZ_API_C_HOST_PREVIEW:
        return host_preview(a, c->body, w, err);
    case GZ_API_C_HOST_OPEN: {
        gz_terms_outer_t ot;
        gz_terms_current_t ct;
        const gz_json *d = c->body ? gz_json_get(c->body, "draft") : NULL;
        const char *why, *given = jstr(c->body, "draft_digest");
        char dg[65];
        uint8_t ob[GZ_TERMS_OUTER_MAX], cb[GZ_TERMS_CURRENT_MAX];
        size_t on, cn;
        if (!draft_terms(a, d, &ot, &ct, &why)) {
            gz_api_err_set(err, why, "/draft", NULL);
            return 409;
        }
        draft_digest(&ot, &ct, dg);
        if (!given || strcmp(given, dg) != 0) {
            gz_api_err_set(err, "draft_changed", "/draft_digest", NULL);
            return 409;
        }
        if (c->phase == GZ_API_PHASE_CHECK) return 0;
        on = gz_terms_encode_outer(&ot, ob, sizeof ob);
        gz_terms_outer_digest(ob, on, ct.outer_digest);
        cn = gz_terms_encode_current(&ct, cb, sizeof cb);
        if (!on || !cn) {
            gz_api_err_set(err, "bad_terms", "/draft", NULL);
            return 409;
        }
        put(&x, 12, ob, on);
        put(&x, 14, cb, cn);
        put8(&x, 16, (uint8_t)jbool(d, "listed", 1));
        return send(a, c, GZ_CMD_LOBBY_OPEN, &x, 1, err);
    }
    case GZ_API_C_HOST_START:
        if (!gzp_api_scope_of(a, c->path_id, 1, scope, NULL)) return not_found(err);
        put(&x, 12, scope, 32);
        put64(&x, 14, (uint64_t)jint(c->body, "confirm_funding_max_sat", 0));
        return send(a, c, GZ_CMD_LOBBY_START, &x, 1, err);
    case GZ_API_C_HOST_CANCEL:
        if (!gzp_api_scope_of(a, c->path_id, 1, scope, NULL)) return not_found(err);
        put(&x, 12, scope, 32);
        return send(a, c, GZ_CMD_LOBBY_CANCEL, &x, 1, err);
    case GZ_API_C_HOST_SEAT_REMOVE: {
        gz_bytes_t all, v;
        if (!gzp_api_scope_of(a, c->path_id, 1, scope, &o)) return not_found(err);
        all.data = o->bytes;
        all.len = o->len;
        if (!c->path_id2 || gz_rec_find(all, GZ_VHL_SEATS, &v) != 1) return not_found(err);
        for (size_t k = 0; k + GZ_VHL_SEAT_LEN <= v.len; k += GZ_VHL_SEAT_LEN) {
            uint8_t dd[32];
            char sid[17];
            SHA256(v.data + k, 33, dd);
            for (int i = 0; i < 8; i++) snprintf(sid + 2 * i, 3, "%02x", dd[i]);
            if (strcmp(sid, c->path_id2) != 0) continue;
            put(&x, 12, scope, 32);
            put(&x, 14, v.data + k, 33);
            return send(a, c, GZ_CMD_LOBBY_REMOVE, &x, 1, err);
        }
        return not_found(err);
    }
    case GZ_API_C_PAUSE: {
        /* 11.3: no request id; the version, when the client read one. */
        int on = jbool(c->body, "on", 1);
        int64_t ver = jint(c->body, "based_on_version", -1);
        put8(&x, 12, (uint8_t)(on ? 1 : 0));
        if (ver >= 0) put32(&x, 14, (uint32_t)ver);
        return send(a, c, GZ_CMD_API_PAUSE, &x, 0, err);
    }
    case GZ_API_C_SIGNING_PUT: {
        /* 14.3: the server checked the fresh sign-in and the echo; the core
         * checks them again (an API request, field 16). */
        const char *ms = jstr(c->body, "member_signing"), *cf = jstr(c->body, "confirm_member_signing");
        int v = !ms ? -1 : !strcmp(ms, "at_join") ? 0 : !strcmp(ms, "auto") ? 1 : !strcmp(ms, "when_unlocked") ? 2 : -1;
        if (v < 0) {
            gz_api_err_set(err, "bad_value", "/member_signing", NULL);
            return 400;
        }
        put8(&x, 12, (uint8_t)v);
        put32(&x, 14, (uint32_t)jint(c->body, "based_on_version", 0));
        if (cf && !strcmp(cf, "auto")) put8(&x, 16, 1);
        return send(a, c, GZ_CMD_API_SET_SIGNING, &x, 1, err);
    }
    case GZ_API_C_CONDITIONS_GET:
        return conditions_get(a, w);
    case GZ_API_C_CONDITIONS_PREVIEW:
    case GZ_API_C_CONDITIONS_PUT: {
        gz_lobby_conditions_t now, nc;
        const char *bad, *names[16];
        uint8_t l[16], cb[400];
        size_t nl, n;
        char preset[24];
        (void)saved_conditions(a, &now, preset, sizeof preset);
        if (!conditions_from(c->body ? gz_json_get(c->body, "conditions") : NULL, &nc, &bad)) {
            gz_api_err_set(err, "bad_value", bad, NULL);
            return 400;
        }
        nl = loosens(&now, &nc, l, names);
        if (c->id == GZ_API_C_CONDITIONS_PREVIEW) {
            gz_jw_obj(w);
            name_list(w, "loosens", names, nl);
            fit_summary(a, w, &nc, NULL);
            gz_jw_kraw(w, "would_leave", "[]");
            gz_jw_kraw(w, "problems", "[]");
            gz_jw_end_obj(w);
            return 200;
        }
        if (nl && !c->fresh) {                         /* 13.2: a loosening is kind B */
            gz_api_err_set(err, "fresh_sign_in_needed", NULL, NULL);
            return 403;
        }
        {
            /* The echo: exactly what the change loosens, by name. */
            const gz_json *cl = gz_json_get(c->body, "confirm_loosens"), *m;
            size_t k = 0, ok = 1;
            for (m = cl && cl->type == GZ_JSON_ARR ? cl->child : NULL; m; m = m->next, k++)
                if (m->type != GZ_JSON_STR || k >= nl || strcmp(m->s, names[k]) != 0) ok = 0;
            if (!ok || k != nl) {
                gz_jw w2;
                (void)w2;
                gz_api_err_set(err, "confirm_mismatch", "/confirm_loosens", NULL);
                return 409;
            }
        }
        n = cond_encode(&nc, cb, sizeof cb);
        put(&x, 12, cb, n);
        {
            /* No fallback to the current version: a PUT that names none would
             * overwrite another tab's change (7.4; review of #79, L4). */
            int64_t based = jint(c->body, "based_on_version", -1);
            if (based < 0 || based > 0xffffffffll) {
                gz_api_err_set(err, based < 0 && !gz_json_get(c->body, "based_on_version") ? "missing_field" : "bad_value",
                               "/based_on_version", NULL);
                return 400;
            }
            put32(&x, 14, (uint32_t)based);
        }
        if (nl) put(&x, 16, l, nl);
        if (jstr(c->body, "preset") && strlen(jstr(c->body, "preset")) <= 16 && strcmp(jstr(c->body, "preset"), "custom"))
            put(&x, 18, jstr(c->body, "preset"), strlen(jstr(c->body, "preset")));
        return send(a, c, GZ_CMD_API_SET_CONDITIONS, &x, nl > 0, err);
    }
    default:
        return -1;
    }
}
