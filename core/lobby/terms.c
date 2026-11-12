/* The host terms record: terms.md sections 2 to 9. */
#include "gazpacho/lobby.h"
#include "lobby_internal.h"
#include <string.h>

#define SUPPLY 2100000000000000ull

static const uint8_t SIGNET[32] = {
    0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9,
    0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00};

/* Well-formed UTF-8: no overlong forms, no surrogates, nothing above U+10FFFF. */
static int utf8_ok(const uint8_t *p, size_t n)
{
    size_t i = 0;
    while (i < n) {
        uint8_t c = p[i];
        size_t k, need;
        uint32_t cp;
        if (c < 0x80) { i++; continue; }
        if (c >= 0xc2 && c <= 0xdf) { need = 1; cp = c & 0x1f; }
        else if (c >= 0xe0 && c <= 0xef) { need = 2; cp = c & 0x0f; }
        else if (c >= 0xf0 && c <= 0xf4) { need = 3; cp = c & 0x07; }
        else return 0;
        if (n - i - 1 < need) return 0;
        for (k = 1; k <= need; k++) {
            if ((p[i + k] & 0xc0) != 0x80) return 0;
            cp = cp << 6 | (p[i + k] & 0x3f);
        }
        if ((need == 2 && (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))) ||
            (need == 3 && (cp < 0x10000 || cp > 0x10ffff))) return 0;
        i += need + 1;
    }
    return 1;
}

/* The split rule of terms.md 4.2 for a node of m members at depth d.
 * 0 if it meets an interior node with m <= its width. */
static int split(const uint8_t *lv, int nl, uint32_t m, int d, int *deepest)
{
    uint8_t a = lv[d < nl ? d : nl - 1];
    uint32_t r = m, j;
    if (a == 3) {
        if (m == 1) {
            if (d > *deepest) *deepest = d;
            return 1;
        }
        return split(lv, nl, m / 2, d + 1, deepest) && split(lv, nl, m - m / 2, d + 1, deepest);
    }
    if (m <= a) return 0;
    for (j = 0; j < a && r > 0; j++) {
        uint32_t c = (r + (a - j) - 1) / (a - j);
        if (!split(lv, nl, c, d + 1, deepest)) return 0;
        r -= c;
    }
    return 1;
}

static int levels_of(const gz_terms_shape_t *s, uint8_t lv[8])
{
    memcpy(lv, s->interior, s->n_interior);
    lv[s->n_interior] = s->leaf_kind;
    return s->n_interior + 1;
}

int gz_terms_shape_for(const gz_terms_outer_t *o, uint16_t n, uint8_t levels[8], uint8_t *n_levels,
                       uint8_t *depth)
{
    uint16_t i;
    int d = 0, nl;
    for (i = 0; i < o->n_shapes; i++) {
        if (o->shapes[i].max_members < n) continue;
        if (n < 1) return 0;
        nl = levels_of(&o->shapes[i], levels);
        if (!split(levels, nl, n, 0, &d)) return 0;
        *n_levels = (uint8_t)nl;
        *depth = (uint8_t)d;
        return 1;
    }
    return 0;
}

static int shapes_decode(const uint8_t *p, size_t n, gz_terms_outer_t *o)
{
    size_t at = 0;
    uint16_t prev = 2;
    o->n_shapes = 0;
    while (at < n) {
        gz_terms_shape_t *s;
        uint8_t k;
        if (o->n_shapes >= GZ_TERMS_MAX_SHAPES || n - at < 4) return 0;
        s = &o->shapes[o->n_shapes];
        s->max_members = (uint16_t)gz_lw_get(p + at, 2);
        s->n_interior = p[at + 2];
        if (s->max_members <= prev || s->max_members > 1000 || s->n_interior > 6 ||
            n - at - 3 < (size_t)s->n_interior + 1) return 0;
        for (k = 0; k < s->n_interior; k++) {
            s->interior[k] = p[at + 3 + k];
            if (s->interior[k] < 4 || s->interior[k] > 15) return 0;
        }
        s->leaf_kind = p[at + 3 + s->n_interior];
        if (s->leaf_kind != 3) return 0;
        at += 4u + s->n_interior;
        prev = s->max_members;
        o->n_shapes++;
    }
    return o->n_shapes > 0;
}

/* terms.md 4.3: every n each entry covers splits into one-member leaves. */
static int shapes_check(const gz_terms_outer_t *o)
{
    uint16_t i, n, from = 3;
    for (i = 0; i < o->n_shapes; i++) {
        uint8_t lv[8];
        int nl = levels_of(&o->shapes[i], lv), d = 0;
        for (n = from; n <= o->shapes[i].max_members; n++)
            if (!split(lv, nl, n, 0, &d)) return 0;
        from = (uint16_t)(o->shapes[i].max_members + 1);
    }
    return 1;
}

int gz_terms_outer_decode(const uint8_t *rec, size_t len, gz_terms_outer_t *o)
{
    gz_lw_tlv_t t;
    uint64_t have = 0;     /* bit (type / 2) for the required even types 2 to 34 */
    int r;
    if (len < 1 || len > GZ_TERMS_OUTER_MAX) return 0;
    memset(o, 0, sizeof *o);
    memset(&t, 0, sizeof t);
    t.p = rec;
    t.len = len;
    while ((r = gz_lw_tlv_next(&t)) == 1) {
        const uint8_t *v = t.v;
        size_t n = t.vlen;
        uint64_t x = n >= 1 && n <= 8 ? gz_lw_get(v, n) : 0;
        if (t.type >= 128) return 0;
        if (t.type >= 64) {
            gz_terms_range_t *g;
            uint64_t cap = t.type == 64 ? SUPPLY : 0xffffffffull;
            if (t.type % 2 == 0 && t.type != 64 && t.type != 66 && t.type != 68) return 0;
            if (n != 16 || o->n_adj >= GZ_TERMS_MAX_ADJ) return 0;
            g = &o->adj[o->n_adj++];
            g->type = (uint8_t)t.type;
            g->min = gz_lw_get(v, 8);
            g->max = gz_lw_get(v + 8, 8);
            if (g->min > g->max || (t.type % 2 == 0 && g->max > cap)) return 0;
            if (t.type % 2 == 0) have |= (uint64_t)1 << (t.type / 2);
            continue;
        }
        switch (t.type) {
        case 2: if (n != 32) return 0; memcpy(o->chain, v, 32); break;
        case 3: if (n < 1 || n > 32 || !utf8_ok(v, n)) return 0; o->alias = v; o->alias_len = n; break;
        case 4: if (n != 33 || (v[0] != 2 && v[0] != 3)) return 0; memcpy(o->host_key, v, 33); break;
        case 5: if (n < 1 || n > 280 || !utf8_ok(v, n)) return 0;
            o->description = v; o->description_len = n; break;
        case 6: if (n != 16) return 0; memcpy(o->salt, v, 16); break;
        case 8: if (n != 1 || x < 1 || x > 4) return 0; o->profile = (uint8_t)x; break;
        case 10: if (n != 2 || x < 3 || x > 1000) return 0; o->target = (uint16_t)x; break;
        case 12: if (n != 2 || x < 3 || x > o->target) return 0; o->minimum = (uint16_t)x; break;
        case 14: if (n != 8) return 0; o->deadline = x; break;
        case 16: if (n != 1 || x > 1) return 0; o->on_shortfall = (uint8_t)x; break;
        case 18: if (n != 4 || x < 1000 || x > 600000) return 0; o->ready_window_ms = (uint32_t)x; break;
        case 20: if (n != 4 || x > 86400000) return 0; o->signing_budget_ms = (uint32_t)x; break;
        case 22: if (n != 4 || x < 60000 || x > 600000) return 0; o->step_timeout_ms = (uint32_t)x; break;
        case 24: if (n < 4 || n > 1000 || !shapes_decode(v, n, o)) return 0; break;
        case 26: if (n != 4 || x < 1 || x > 52560) return 0; o->lifetime_blocks = (uint32_t)x; break;
        case 28: if (n != 4 || x < 1 || x > 52560) return 0; o->winddown_blocks = (uint32_t)x; break;
        case 30: if (n != 8 || x < 546 || x > SUPPLY) return 0; o->channel_sat = x; break;
        case 32: if (n != 4 || x < 1 || x > 1000000) return 0; o->tree_feerate = (uint32_t)x; break;
        case 34: if (n != 1 || x > 7) return 0; o->switches = (uint8_t)x; break;
        default: if (t.type % 2 == 0) return 0; continue;
        }
        if (t.type % 2 == 0) have |= (uint64_t)1 << (t.type / 2);
    }
    /* Required: every even type 2 to 34 (bits 1 to 17), and 64, 66, 68 (bits 32 to 34). */
    if (r < 0 || have != (0x3fffeull | 0x700000000ull)) return 0;
    if (o->signing_budget_ms < o->step_timeout_ms) return 0;
    if (o->shapes[o->n_shapes - 1].max_members < o->target) return 0;
    return shapes_check(o);
}

int gz_terms_current_decode(const uint8_t *rec, size_t len, const gz_terms_outer_t *outer,
                            const uint8_t outer_digest[32], gz_terms_current_t *c)
{
    gz_lw_tlv_t t;
    int r, have_digest = 0, have_version = 0;
    if (len < 1 || len > GZ_TERMS_CURRENT_MAX) return 0;
    memset(c, 0, sizeof *c);
    memset(&t, 0, sizeof t);
    t.p = rec;
    t.len = len;
    while ((r = gz_lw_tlv_next(&t)) == 1) {
        const gz_terms_range_t *g;
        uint64_t x;
        if (t.type == 2 && t.vlen == 32) {
            if (memcmp(t.v, outer_digest, 32) != 0) return 0;
            memcpy(c->outer_digest, t.v, 32);
            have_digest = 1;
            continue;
        }
        if (t.type == 4 && t.vlen == 4) {
            c->version = (uint32_t)gz_lw_get(t.v, 4);
            if (c->version == 0) return 0;
            have_version = 1;
            continue;
        }
        /* Only adjustable values remain, each the next of the outer's ranges. */
        if (t.type < 64 || t.type > 127 || t.vlen != 8 || c->n_adj >= outer->n_adj) return 0;
        g = &outer->adj[c->n_adj];
        x = gz_lw_get(t.v, 8);
        if (g->type != t.type || x < g->min || x > g->max) return 0;
        c->adj_type[c->n_adj] = g->type;
        c->adj_value[c->n_adj] = x;
        c->n_adj++;
    }
    return r == 0 && have_digest && have_version && c->n_adj == outer->n_adj;
}

int gz_terms_slice1_ok(const gz_terms_outer_t *o)
{
    return memcmp(o->chain, SIGNET, 32) == 0 && o->profile == 2 && o->on_shortfall == 0 &&
           o->switches == 0;
}

void gz_terms_outer_digest(const uint8_t *rec, size_t len, uint8_t out[32])
{
    gz_lobby_tagged("gazpacho/terms/outer", rec, len, out);
}

void gz_terms_current_digest(const uint8_t *rec, size_t len, uint8_t out[32])
{
    gz_lobby_tagged("gazpacho/terms/current", rec, len, out);
}

/* -------------------------------------------------------------- encoders */

typedef struct { uint8_t *p; size_t cap, len; int bad; } wr_t;

static void rec(wr_t *w, uint64_t type, const uint8_t *v, size_t n)
{
    uint8_t h[18];
    size_t hn = gz_lw_put_bigsize(h, type);
    hn += gz_lw_put_bigsize(h + hn, n);
    if (w->bad || w->cap - w->len < hn + n) { w->bad = 1; return; }
    memcpy(w->p + w->len, h, hn);
    if (n) memcpy(w->p + w->len + hn, v, n);
    w->len += hn + n;
}

static void rec_int(wr_t *w, uint64_t type, uint64_t v, size_t n)
{
    uint8_t b[8];
    gz_lw_put(b, v, n);
    rec(w, type, b, n);
}

size_t gz_terms_outer_encode(const gz_terms_outer_t *o, uint8_t *out, size_t cap)
{
    wr_t w;
    uint8_t shapes[1000];
    size_t sn = 0;
    uint16_t i;
    uint8_t k;
    w.p = out; w.cap = cap; w.len = 0; w.bad = 0;
    for (i = 0; i < o->n_shapes && i < GZ_TERMS_MAX_SHAPES; i++) {
        const gz_terms_shape_t *s = &o->shapes[i];
        if (s->n_interior > 6 || sn + 4u + s->n_interior > sizeof shapes) return 0;
        gz_lw_put(shapes + sn, s->max_members, 2);
        shapes[sn + 2] = s->n_interior;
        memcpy(shapes + sn + 3, s->interior, s->n_interior);
        shapes[sn + 3 + s->n_interior] = s->leaf_kind;
        sn += 4u + s->n_interior;
    }
    rec(&w, 2, o->chain, 32);
    if (o->alias) rec(&w, 3, o->alias, o->alias_len);
    rec(&w, 4, o->host_key, 33);
    if (o->description) rec(&w, 5, o->description, o->description_len);
    rec(&w, 6, o->salt, 16);
    rec_int(&w, 8, o->profile, 1);
    rec_int(&w, 10, o->target, 2);
    rec_int(&w, 12, o->minimum, 2);
    rec_int(&w, 14, o->deadline, 8);
    rec_int(&w, 16, o->on_shortfall, 1);
    rec_int(&w, 18, o->ready_window_ms, 4);
    rec_int(&w, 20, o->signing_budget_ms, 4);
    rec_int(&w, 22, o->step_timeout_ms, 4);
    rec(&w, 24, shapes, sn);
    rec_int(&w, 26, o->lifetime_blocks, 4);
    rec_int(&w, 28, o->winddown_blocks, 4);
    rec_int(&w, 30, o->channel_sat, 8);
    rec_int(&w, 32, o->tree_feerate, 4);
    rec_int(&w, 34, o->switches, 1);
    for (k = 0; k < o->n_adj && k < GZ_TERMS_MAX_ADJ; k++) {
        uint8_t b[16];
        gz_lw_put(b, o->adj[k].min, 8);
        gz_lw_put(b + 8, o->adj[k].max, 8);
        rec(&w, o->adj[k].type, b, 16);
    }
    return w.bad ? 0 : w.len;
}

size_t gz_terms_current_encode(const gz_terms_current_t *c, const gz_terms_outer_t *outer,
                               uint8_t *out, size_t cap)
{
    wr_t w;
    uint8_t k;
    (void)outer;
    w.p = out; w.cap = cap; w.len = 0; w.bad = 0;
    rec(&w, 2, c->outer_digest, 32);
    rec_int(&w, 4, c->version, 4);
    for (k = 0; k < c->n_adj && k < GZ_TERMS_MAX_ADJ; k++) rec_int(&w, c->adj_type[k], c->adj_value[k], 8);
    return w.bad ? 0 : w.len;
}

/* ------------------------------------------------------------ comparison */

static int find_adj(const gz_terms_outer_t *o, const gz_terms_current_t *c, uint8_t type,
                    uint64_t *hi, uint64_t *cur)
{
    uint8_t k;
    for (k = 0; k < o->n_adj && k < c->n_adj; k++)
        if (o->adj[k].type == type && c->adj_type[k] == type) {
            *hi = o->adj[k].max;
            *cur = c->adj_value[k];
            return 1;
        }
    return 0;
}

int gz_terms_classify(const gz_terms_outer_t *o, const gz_terms_current_t *c,
                      const gz_lobby_conditions_t *cond, uint8_t *term)
{
    static const uint8_t adj[3] = {64, 66, 68};
    uint8_t no = 0, now = 0;
    int k;
    if (o->profile > 7 || !(cond->profiles & (1u << o->profile))) no = 8;
    else if (o->lifetime_blocks < cond->life_min || o->lifetime_blocks > cond->life_max) no = 26;
    else if (o->winddown_blocks > cond->wind_max) no = 28;
    else if (o->channel_sat < cond->chan_min) no = 30;
    else if (o->tree_feerate > cond->rate_max) no = 32;
    for (k = 0; k < 3; k++) {
        uint64_t hi, cur;
        if (!find_adj(o, c, adj[k], &hi, &cur)) { if (!no) no = adj[k]; continue; }
        if (cur > cond->adj_max[k] && !no) no = adj[k];
        if (hi > cond->adj_max[k] && !now) now = adj[k];
    }
    if (no) { *term = no; return GZ_FIT_NO; }
    if (now) { *term = now; return GZ_FIT_NOW; }
    *term = 0;
    return GZ_FIT_YES;
}

int gz_terms_ready_ok(int cls, const gz_lobby_conditions_t *cond)
{
    return cls == GZ_FIT_YES || (cls == GZ_FIT_NOW && cond->current_only);
}
