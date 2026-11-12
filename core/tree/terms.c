/* The host terms record: spec/terms.md draft 2, sections 2 to 9. */
#include "gazpacho/terms.h"
#include "gazpacho/tree.h"
#include "internal.h"

#include <string.h>

/* f61eee3b...08000000: signet's genesis hash, internal order (section 3). */
static const uint8_t SIGNET[32] = {
    0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9,
    0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00
};

const uint8_t *gz_terms_signet(void) { return SIGNET; }

#define SUPPLY_SAT 2100000000000000ull
#define U32_MAX_ 4294967295ull

/* ------------------------------------------------------------ the reader */

typedef struct {
    const uint8_t *p;
    size_t n, i;
} rd_t;

static gz_terms_err_t bigsize(rd_t *r, uint64_t *v)
{
    uint8_t first;
    size_t need, k;
    if (r->i >= r->n) return GZ_TERMS_E_TRUNCATED;
    first = r->p[r->i++];
    if (first < 0xfd) { *v = first; return GZ_TERMS_OK; }
    need = first == 0xfd ? 2 : first == 0xfe ? 4 : 8;
    if (r->n - r->i < need) return GZ_TERMS_E_TRUNCATED;
    *v = 0;
    for (k = 0; k < need; k++) *v = *v << 8 | r->p[r->i++];
    if ((first == 0xfd && *v < 0xfd) || (first == 0xfe && *v < 0x10000) || (first == 0xff && *v < 0x100000000ull))
        return GZ_TERMS_E_NOT_MINIMAL;
    return GZ_TERMS_OK;
}

/* One record: type, length, value. Enforces strictly increasing types (the
 * caller passes the previous type, or -1 as UINT64_MAX sentinel). */
static gz_terms_err_t record(rd_t *r, int have_last, uint64_t last, uint64_t *type, const uint8_t **v, size_t *len)
{
    uint64_t t, l;
    gz_terms_err_t e;
    if ((e = bigsize(r, &t)) != GZ_TERMS_OK) return e;
    if ((e = bigsize(r, &l)) != GZ_TERMS_OK) return e;
    if (have_last && t <= last) return GZ_TERMS_E_ORDER;
    if (l > r->n - r->i) return GZ_TERMS_E_TRUNCATED;
    *type = t;
    *v = r->p + r->i;
    *len = (size_t)l;
    r->i += (size_t)l;
    return GZ_TERMS_OK;
}

/* RFC 3629 UTF-8: no overlong forms, no surrogates, nothing above U+10FFFF. */
static int utf8_ok(const uint8_t *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        uint32_t cp, min;
        size_t extra, k;
        if (c < 0x80) { i++; continue; }
        if ((c & 0xe0) == 0xc0) { extra = 1; cp = c & 0x1f; min = 0x80; }
        else if ((c & 0xf0) == 0xe0) { extra = 2; cp = c & 0x0f; min = 0x800; }
        else if ((c & 0xf8) == 0xf0) { extra = 3; cp = c & 0x07; min = 0x10000; }
        else return 0;
        if (n - i - 1 < extra) return 0;
        for (k = 1; k <= extra; k++) {
            if ((s[i + k] & 0xc0) != 0x80) return 0;
            cp = cp << 6 | (s[i + k] & 0x3f);
        }
        if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
        i += extra + 1;
    }
    return 1;
}

static int is_adjustable(uint64_t t) { return t >= 64 && t <= 127; }
static int known_adjustable(uint64_t t)
{
    return t == GZ_TT_JOINING_FEE || t == GZ_TT_FEE_BASE || t == GZ_TT_FEE_PROP;
}
static uint64_t adj_ceiling(uint64_t t)
{
    if (t == GZ_TT_JOINING_FEE) return SUPPLY_SAT;
    if (t == GZ_TT_FEE_BASE || t == GZ_TT_FEE_PROP) return U32_MAX_;
    return UINT64_MAX;   /* an odd adjustable type this app does not know: min <= max only */
}

/* ------------------------------------------------------ the outer record */

static gz_terms_err_t parse_shapes(const uint8_t *v, size_t len, gz_terms_outer_t *t)
{
    size_t i = 0;
    t->n_shapes = 0;
    while (i < len) {
        gz_shape_entry_t *e;
        uint8_t ni;
        if (t->n_shapes >= GZ_TERMS_MAX_SHAPES || len - i < 4) return GZ_TERMS_E_SHAPE_ENCODING;
        e = &t->shapes[t->n_shapes];
        e->max_members = (uint16_t)tr_rd_be16(v + i);
        ni = v[i + 2];
        if (ni > GZ_TERMS_MAX_INTERIOR) return GZ_TERMS_E_SHAPE_N_INTERIOR;
        if (len - i < 4 + (size_t)ni) return GZ_TERMS_E_SHAPE_ENCODING;
        e->n_interior = ni;
        memset(e->interior, 0, sizeof e->interior);
        memcpy(e->interior, v + i + 3, ni);
        e->leaf_kind = v[i + 3 + ni];
        i += 4 + (size_t)ni;
        t->n_shapes++;
    }
    return GZ_TERMS_OK;
}

/* Bit i of `seen` for type i (types 0..63). */
#define REQUIRED_OUTER ((1ull << 2) | (1ull << 4) | (1ull << 6) | (1ull << 8) | (1ull << 10) | (1ull << 12) | \
                        (1ull << 14) | (1ull << 16) | (1ull << 18) | (1ull << 20) | (1ull << 22) | (1ull << 24) | \
                        (1ull << 26) | (1ull << 28) | (1ull << 30) | (1ull << 32) | (1ull << 34))

gz_terms_err_t gz_terms_parse_outer(const uint8_t *b, size_t n, gz_terms_outer_t *t)
{
    rd_t r;
    uint64_t type = 0, seen = 0;
    int have = 0, joining = 0, base = 0, prop = 0;
    gz_terms_err_t e;
    if (!b || !t) return GZ_TERMS_E_ARGUMENT;
    memset(t, 0, sizeof *t);
    if (n > GZ_TERMS_OUTER_MAX) return GZ_TERMS_E_TOO_LONG;
    r.p = b; r.n = n; r.i = 0;
    while (r.i < r.n) {
        const uint8_t *v;
        size_t len;
        if ((e = record(&r, have, type, &type, &v, &len)) != GZ_TERMS_OK) return e;
        have = 1;
        if (type >= 128) return GZ_TERMS_E_RESERVED_TYPE;
        if (is_adjustable(type)) {
            gz_terms_range_t *a;
            if (!known_adjustable(type) && type % 2 == 0) return GZ_TERMS_E_UNKNOWN_EVEN;
            if (len != 16) return GZ_TERMS_E_LENGTH;
            if (t->n_adj >= GZ_TERMS_MAX_ADJ) return GZ_TERMS_E_TOO_LONG;   /* unreachable: 35 types at most */
            a = &t->adj[t->n_adj++];
            a->type = (uint8_t)type;
            a->min = tr_rd_be64(v);
            a->max = tr_rd_be64(v + 8);
            if (type == GZ_TT_JOINING_FEE) joining = 1;
            if (type == GZ_TT_FEE_BASE) base = 1;
            if (type == GZ_TT_FEE_PROP) prop = 1;
            continue;
        }
        switch (type) {
#define FIX(sz) if (len != (sz)) return GZ_TERMS_E_LENGTH
        case GZ_TT_CHAIN: FIX(32); memcpy(t->chain, v, 32); break;
        case GZ_TT_ALIAS:
            if (len < 1 || len > 32) return GZ_TERMS_E_LENGTH;
            if (!utf8_ok(v, len)) return GZ_TERMS_E_UTF8;
            t->alias_len = (uint8_t)len; memcpy(t->alias, v, len); break;
        case GZ_TT_HOST_KEY: FIX(33); memcpy(t->host_key, v, 33); break;
        case GZ_TT_DESCRIPTION:
            if (len < 1 || len > 280) return GZ_TERMS_E_LENGTH;
            if (!utf8_ok(v, len)) return GZ_TERMS_E_UTF8;
            t->description_len = (uint16_t)len; memcpy(t->description, v, len); break;
        case GZ_TT_SALT: FIX(16); memcpy(t->lobby_salt, v, 16); break;
        case GZ_TT_PROFILE: FIX(1); t->profile = v[0]; break;
        case GZ_TT_TARGET: FIX(2); t->target = (uint16_t)tr_rd_be16(v); break;
        case GZ_TT_MINIMUM: FIX(2); t->minimum = (uint16_t)tr_rd_be16(v); break;
        case GZ_TT_DEADLINE: FIX(8); t->deadline = tr_rd_be64(v); break;
        case GZ_TT_SHORTFALL: FIX(1); t->on_shortfall = v[0]; break;
        case GZ_TT_READY_WINDOW: FIX(4); t->ready_window_ms = tr_rd_be32(v); break;
        case GZ_TT_SIGNING_BUDGET: FIX(4); t->signing_budget_ms = tr_rd_be32(v); break;
        case GZ_TT_STEP_TIMEOUT: FIX(4); t->step_timeout_ms = tr_rd_be32(v); break;
        case GZ_TT_SHAPES:
            if (len < 4 || len > 1000) return GZ_TERMS_E_LENGTH;
            if ((e = parse_shapes(v, len, t)) != GZ_TERMS_OK) return e;
            break;
        case GZ_TT_LIFETIME: FIX(4); t->lifetime_blocks = tr_rd_be32(v); break;
        case GZ_TT_WINDDOWN: FIX(4); t->winddown_blocks = tr_rd_be32(v); break;
        case GZ_TT_CHANNEL: FIX(8); t->channel_sat = tr_rd_be64(v); break;
        case GZ_TT_FEERATE: FIX(4); t->tree_feerate = tr_rd_be32(v); break;
        case GZ_TT_SWITCHES: FIX(1); t->switches = v[0]; break;
#undef FIX
        default:
            if (type % 2 == 0) return GZ_TERMS_E_UNKNOWN_EVEN;
            t->n_unknown_odd++;     /* rule 4: display only, skipped */
            continue;
        }
        seen |= 1ull << type;
    }
    if ((seen & REQUIRED_OUTER) != REQUIRED_OUTER || !joining || !base || !prop) return GZ_TERMS_E_MISSING;
    return GZ_TERMS_OK;
}

gz_terms_err_t gz_terms_check_shapes(const gz_shape_entry_t *es, size_t n_entries, uint16_t target)
{
    size_t i, k;
    uint32_t prev = 2;
    if (!es || n_entries == 0) return GZ_TERMS_E_SHAPE_ENCODING;
    for (i = 0; i < n_entries; i++) {
        const gz_shape_entry_t *e = &es[i];
        if (e->max_members < 3 || e->max_members > 1000 || e->max_members <= prev) return GZ_TERMS_E_SHAPE_MAX_MEMBERS;
        if (e->n_interior > GZ_TERMS_MAX_INTERIOR) return GZ_TERMS_E_SHAPE_N_INTERIOR;
        for (k = 0; k < e->n_interior; k++)
            if (e->interior[k] < 4 || e->interior[k] > 15) return GZ_TERMS_E_SHAPE_WIDTH;
        if (e->leaf_kind != GZ_TERMS_LEAF_PS) return GZ_TERMS_E_SHAPE_LEAF_KIND;
        prev = e->max_members;
    }
    if (es[n_entries - 1].max_members < target) return GZ_TERMS_E_SHAPE_TARGET;
    /* Section 4.3: every n of every entry's range splits into one-member
     * pseudo-Spilman leaves. */
    prev = 2;
    for (i = 0; i < n_entries; i++) {
        uint8_t levels[GZ_TREE_MAX_LEVELS];
        size_t nl = gz_tree_levels(&es[i], levels);
        uint32_t m;
        for (m = prev + 1; m <= es[i].max_members; m++) {
            uint32_t leaves = 0;
            if (!tr_split(levels, nl, m, 0, NULL, &leaves, GZ_TREE_MAX_DEPTH) || leaves != m)
                return GZ_TERMS_E_SHAPE_SPLIT;
        }
        prev = es[i].max_members;
    }
    return GZ_TERMS_OK;
}

gz_terms_err_t gz_terms_check_outer(const gz_terms_outer_t *t, const gz_terms_policy_t *pol)
{
    size_t i;
    gz_terms_err_t e;
    if (!t || !pol) return GZ_TERMS_E_ARGUMENT;
    /* Section 7 step 4 comes before the bounds of step 5. */
    if (pol->slice1 && !tr_eq(t->chain, SIGNET, 32)) return GZ_TERMS_E_CHAIN;
    if (t->host_key[0] != 2 && t->host_key[0] != 3) return GZ_TERMS_E_HOST_KEY;
    if (t->profile < 1 || t->profile > 4) return GZ_TERMS_E_PROFILE;
    if (t->target < 3 || t->target > 1000) return GZ_TERMS_E_TARGET;
    if (t->minimum < 3 || t->minimum > t->target) return GZ_TERMS_E_MINIMUM;
    if (t->on_shortfall > 1) return GZ_TERMS_E_SHORTFALL;
    if (t->ready_window_ms < 1000 || t->ready_window_ms > 600000) return GZ_TERMS_E_READY_WINDOW;
    if (t->step_timeout_ms < 60000 || t->step_timeout_ms > 600000) return GZ_TERMS_E_STEP_TIMEOUT;
    if (t->signing_budget_ms < t->step_timeout_ms || t->signing_budget_ms > 86400000u) return GZ_TERMS_E_SIGNING_BUDGET;
    if ((e = gz_terms_check_shapes(t->shapes, t->n_shapes, t->target)) != GZ_TERMS_OK) return e;
    if (t->lifetime_blocks < 1 || t->lifetime_blocks > 52560) return GZ_TERMS_E_LIFETIME;
    if (t->winddown_blocks < 1 || t->winddown_blocks > 52560) return GZ_TERMS_E_WINDDOWN;
    if (t->channel_sat < GZ_TREE_DUST_SAT || t->channel_sat > SUPPLY_SAT) return GZ_TERMS_E_CHANNEL;
    if (t->tree_feerate < 1 || t->tree_feerate > 1000000) return GZ_TERMS_E_FEERATE;
    if (t->switches & ~7u) return GZ_TERMS_E_SWITCHES;
    for (i = 0; i < t->n_adj; i++)
        if (t->adj[i].min > t->adj[i].max || t->adj[i].max > adj_ceiling(t->adj[i].type)) return GZ_TERMS_E_RANGE;
    if (pol->slice1 && (t->profile != 2 || t->on_shortfall != 0 || t->switches != 0)) return GZ_TERMS_E_SLICE1;
    return GZ_TERMS_OK;
}

gz_terms_err_t gz_terms_decode_outer(const uint8_t *b, size_t n, const gz_terms_policy_t *pol, gz_terms_outer_t *out)
{
    gz_terms_err_t e = gz_terms_parse_outer(b, n, out);
    if (e != GZ_TERMS_OK) return e;
    return gz_terms_check_outer(out, pol);
}

/* ---------------------------------------------------- the current record */

static const gz_terms_range_t *outer_range(const gz_terms_outer_t *o, uint64_t type)
{
    size_t i;
    for (i = 0; i < o->n_adj; i++)
        if (o->adj[i].type == type) return &o->adj[i];
    return NULL;
}

gz_terms_err_t gz_terms_decode_current(const uint8_t *b, size_t n, const gz_terms_outer_t *outer, gz_terms_current_t *c)
{
    rd_t r;
    uint64_t type = 0;
    int have = 0, got_digest = 0, got_version = 0;
    size_t i;
    gz_terms_err_t e;
    if (!b || !c) return GZ_TERMS_E_ARGUMENT;
    memset(c, 0, sizeof *c);
    if (n > GZ_TERMS_CURRENT_MAX) return GZ_TERMS_E_TOO_LONG;
    r.p = b; r.n = n; r.i = 0;
    while (r.i < r.n) {
        const uint8_t *v;
        size_t len;
        if ((e = record(&r, have, type, &type, &v, &len)) != GZ_TERMS_OK) return e;
        have = 1;
        if (type >= 128) return GZ_TERMS_E_RESERVED_TYPE;
        if (type == GZ_TC_OUTER_DIGEST) {
            if (len != 32) return GZ_TERMS_E_LENGTH;
            memcpy(c->outer_digest, v, 32);
            got_digest = 1;
        } else if (type == GZ_TC_VERSION) {
            if (len != 4) return GZ_TERMS_E_LENGTH;
            c->version = tr_rd_be32(v);
            got_version = 1;
        } else if (is_adjustable(type)) {
            if (!known_adjustable(type) && type % 2 == 0) return GZ_TERMS_E_UNKNOWN_EVEN;
            if (len != 8) return GZ_TERMS_E_LENGTH;
            if (outer && !outer_range(outer, type)) return GZ_TERMS_E_ADJ_SET;
            if (c->n_values >= GZ_TERMS_MAX_ADJ) return GZ_TERMS_E_TOO_LONG;   /* unreachable */
            c->val[c->n_values].type = (uint8_t)type;
            c->val[c->n_values].value = tr_rd_be64(v);
            c->n_values++;
        } else {
            /* Types 1..63 other than 2 and 4 are never in a current record
             * (section 2 rule 5's table), whatever their parity. */
            return type % 2 == 0 ? GZ_TERMS_E_UNKNOWN_EVEN : GZ_TERMS_E_TYPE_NOT_ALLOWED;
        }
    }
    if (!got_digest || !got_version) return GZ_TERMS_E_MISSING;
    if (c->version == 0) return GZ_TERMS_E_VERSION;
    if (!outer) return GZ_TERMS_OK;      /* section 2 only (gz_terms_receive's step 1) */
    if (c->n_values != outer->n_adj) return GZ_TERMS_E_ADJ_SET;
    for (i = 0; i < c->n_values; i++) {
        const gz_terms_range_t *rg = outer_range(outer, c->val[i].type);
        if (c->val[i].value < rg->min || c->val[i].value > rg->max) return GZ_TERMS_E_ADJ_VALUE;
    }
    return GZ_TERMS_OK;
}

/* -------------------------------------------------------------- encoding */

typedef struct {
    uint8_t *p;
    size_t cap, n;
    int bad;
} wr_t;

static void put(wr_t *w, const uint8_t *d, size_t len)
{
    if (w->bad || w->cap - w->n < len) { w->bad = 1; return; }
    memcpy(w->p + w->n, d, len);
    w->n += len;
}

static void put_bigsize(wr_t *w, uint64_t x)
{
    uint8_t b[9];
    if (x < 0xfd) { b[0] = (uint8_t)x; put(w, b, 1); }
    else if (x < 0x10000) { b[0] = 0xfd; tr_be16(b + 1, (uint32_t)x); put(w, b, 3); }
    else if (x < 0x100000000ull) { b[0] = 0xfe; tr_be32(b + 1, (uint32_t)x); put(w, b, 5); }
    else { b[0] = 0xff; tr_be64(b + 1, x); put(w, b, 9); }
}

static void put_rec(wr_t *w, uint64_t type, const uint8_t *v, size_t len)
{
    put_bigsize(w, type);
    put_bigsize(w, len);
    put(w, v, len);
}

static void put_u8(wr_t *w, uint64_t type, uint8_t x) { put_rec(w, type, &x, 1); }
static void put_u16(wr_t *w, uint64_t type, uint32_t x) { uint8_t b[2]; tr_be16(b, x); put_rec(w, type, b, 2); }
static void put_u32(wr_t *w, uint64_t type, uint32_t x) { uint8_t b[4]; tr_be32(b, x); put_rec(w, type, b, 4); }
static void put_u64(wr_t *w, uint64_t type, uint64_t x) { uint8_t b[8]; tr_be64(b, x); put_rec(w, type, b, 8); }

size_t gz_terms_encode_outer(const gz_terms_outer_t *t, uint8_t *out, size_t cap)
{
    wr_t w;
    uint8_t shapes[1000];
    size_t ns = 0, i;
    if (!t || !out) return 0;
    w.p = out; w.cap = cap > GZ_TERMS_OUTER_MAX ? GZ_TERMS_OUTER_MAX : cap; w.n = 0; w.bad = 0;
    if (t->alias_len > 32 || t->description_len > 280 || t->n_shapes == 0 || t->n_shapes > GZ_TERMS_MAX_SHAPES
        || t->n_adj > GZ_TERMS_MAX_ADJ)
        return 0;
    for (i = 0; i < t->n_shapes; i++) {
        const gz_shape_entry_t *e = &t->shapes[i];
        if (e->n_interior > GZ_TERMS_MAX_INTERIOR || ns + 4 + e->n_interior > sizeof shapes) return 0;
        tr_be16(shapes + ns, e->max_members);
        shapes[ns + 2] = e->n_interior;
        memcpy(shapes + ns + 3, e->interior, e->n_interior);
        shapes[ns + 3 + e->n_interior] = e->leaf_kind;
        ns += 4 + (size_t)e->n_interior;
    }
    put_rec(&w, GZ_TT_CHAIN, t->chain, 32);
    if (t->alias_len) put_rec(&w, GZ_TT_ALIAS, t->alias, t->alias_len);
    put_rec(&w, GZ_TT_HOST_KEY, t->host_key, 33);
    if (t->description_len) put_rec(&w, GZ_TT_DESCRIPTION, t->description, t->description_len);
    put_rec(&w, GZ_TT_SALT, t->lobby_salt, 16);
    put_u8(&w, GZ_TT_PROFILE, t->profile);
    put_u16(&w, GZ_TT_TARGET, t->target);
    put_u16(&w, GZ_TT_MINIMUM, t->minimum);
    put_u64(&w, GZ_TT_DEADLINE, t->deadline);
    put_u8(&w, GZ_TT_SHORTFALL, t->on_shortfall);
    put_u32(&w, GZ_TT_READY_WINDOW, t->ready_window_ms);
    put_u32(&w, GZ_TT_SIGNING_BUDGET, t->signing_budget_ms);
    put_u32(&w, GZ_TT_STEP_TIMEOUT, t->step_timeout_ms);
    put_rec(&w, GZ_TT_SHAPES, shapes, ns);
    put_u32(&w, GZ_TT_LIFETIME, t->lifetime_blocks);
    put_u32(&w, GZ_TT_WINDDOWN, t->winddown_blocks);
    put_u64(&w, GZ_TT_CHANNEL, t->channel_sat);
    put_u32(&w, GZ_TT_FEERATE, t->tree_feerate);
    put_u8(&w, GZ_TT_SWITCHES, t->switches);
    for (i = 0; i < t->n_adj; i++) {
        uint8_t b[16];
        if (t->adj[i].type < 64 || t->adj[i].type > 127 || (i && t->adj[i].type <= t->adj[i - 1].type)) return 0;
        tr_be64(b, t->adj[i].min);
        tr_be64(b + 8, t->adj[i].max);
        put_rec(&w, t->adj[i].type, b, 16);
    }
    return w.bad ? 0 : w.n;
}

size_t gz_terms_encode_current(const gz_terms_current_t *c, uint8_t *out, size_t cap)
{
    wr_t w;
    size_t i;
    if (!c || !out || c->n_values > GZ_TERMS_MAX_ADJ) return 0;
    w.p = out; w.cap = cap > GZ_TERMS_CURRENT_MAX ? GZ_TERMS_CURRENT_MAX : cap; w.n = 0; w.bad = 0;
    put_rec(&w, GZ_TC_OUTER_DIGEST, c->outer_digest, 32);
    put_u32(&w, GZ_TC_VERSION, c->version);
    for (i = 0; i < c->n_values; i++) {
        if (c->val[i].type < 64 || c->val[i].type > 127 || (i && c->val[i].type <= c->val[i - 1].type)) return 0;
        put_u64(&w, c->val[i].type, c->val[i].value);
    }
    return w.bad ? 0 : w.n;
}

/* --------------------------------------------------------------- digests */

static void digest(const char *tag, const uint8_t *b, size_t n, uint8_t out[32])
{
    tr_sha256_t s;
    tr_tagged_init(&s, tag);
    tr_sha256_write(&s, b, n);
    tr_sha256_done(&s, out);
}

void gz_terms_outer_digest(const uint8_t *outer, size_t n, uint8_t out[32])
{
    digest("gazpacho/terms/outer", outer, n, out);
}

void gz_terms_current_digest(const uint8_t *current, size_t n, uint8_t out[32])
{
    digest("gazpacho/terms/current", current, n, out);
}

/* --------------------------------------------------------------- receipt */

gz_terms_err_t gz_terms_receive(const uint8_t *outer, size_t outer_len, const uint8_t outer_sig[64],
                                const uint8_t *current, size_t current_len, const uint8_t current_sig[64],
                                const uint8_t scope[32], const uint8_t pinned_key[33],
                                const gz_terms_policy_t *pol, const gz_tree_crypto_t *crypto,
                                gz_terms_outer_t *o, uint8_t od[32], gz_terms_current_t *c, uint8_t cd[32])
{
    gz_terms_err_t e;
    if (!outer || !outer_sig || !current || !current_sig || !scope || !pinned_key || !pol || !crypto
        || !crypto->verify || !crypto->point_valid || !o || !od || !c || !cd)
        return GZ_TERMS_E_ARGUMENT;
    /* Step 1: both records decode under section 2. The current record's own
     * checks against the outer rules wait for step 6. */
    if ((e = gz_terms_parse_outer(outer, outer_len, o)) != GZ_TERMS_OK) return e;
    if ((e = gz_terms_decode_current(current, current_len, NULL, c)) != GZ_TERMS_OK) return e;
    /* Step 2. */
    gz_terms_outer_digest(outer, outer_len, od);
    if (!tr_eq(od, scope, 32)) return GZ_TERMS_E_SCOPE;
    /* Step 3. */
    if (!tr_eq(o->host_key, pinned_key, 33)) return GZ_TERMS_E_PINNED_KEY;
    if (!crypto->point_valid(crypto->ctx, o->host_key)) return GZ_TERMS_E_HOST_KEY;
    gz_terms_current_digest(current, current_len, cd);
    if (!crypto->verify(crypto->ctx, od, o->host_key, outer_sig)) return GZ_TERMS_E_OUTER_SIG;
    if (!crypto->verify(crypto->ctx, cd, o->host_key, current_sig)) return GZ_TERMS_E_CURRENT_SIG;
    /* Steps 4 and 5. */
    if ((e = gz_terms_check_outer(o, pol)) != GZ_TERMS_OK) return e;
    /* Step 6. */
    if ((e = gz_terms_decode_current(current, current_len, o, c)) != GZ_TERMS_OK) return e;
    if (!tr_eq(c->outer_digest, od, 32)) return GZ_TERMS_E_OUTER_DIGEST;
    return GZ_TERMS_OK;
}

gz_terms_version_t gz_terms_version_rule(int have, uint32_t have_version, const uint8_t have_digest[32],
                                         int frozen, uint32_t new_version, const uint8_t new_digest[32])
{
    int same = have && tr_eq(have_digest, new_digest, 32);
    if (frozen) return same ? GZ_TERMS_V_DUPLICATE : GZ_TERMS_V_FROZEN_BREACH;
    if (!have || new_version > have_version) return GZ_TERMS_V_ACCEPT;
    if (new_version == have_version) return same ? GZ_TERMS_V_DUPLICATE : GZ_TERMS_V_EQUIVOCATION;
    return GZ_TERMS_V_IGNORE_OLDER;
}

/* ------------------------------------------------------------ comparison */

gz_terms_class_t gz_terms_classify(const gz_terms_outer_t *o, const gz_terms_current_t *c, const gz_terms_limits_t *l)
{
    gz_terms_class_t cls = GZ_TERMS_FITS;
    size_t i, j;
    if (!o || !c || !l) return GZ_TERMS_DOES_NOT_FIT;
    if (l->min_channel_sat && o->channel_sat < l->min_channel_sat) return GZ_TERMS_DOES_NOT_FIT;
    if (l->max_tree_feerate && o->tree_feerate > l->max_tree_feerate) return GZ_TERMS_DOES_NOT_FIT;
    if (l->min_lifetime && o->lifetime_blocks < l->min_lifetime) return GZ_TERMS_DOES_NOT_FIT;
    if (l->max_lifetime && o->lifetime_blocks > l->max_lifetime) return GZ_TERMS_DOES_NOT_FIT;
    if (l->min_members && o->minimum < l->min_members) return GZ_TERMS_DOES_NOT_FIT;
    if (l->profiles && (o->profile > 7 || !(l->profiles & (1u << o->profile)))) return GZ_TERMS_DOES_NOT_FIT;
    for (i = 0; i < o->n_adj; i++) {
        const gz_terms_range_t *r = &o->adj[i];
        uint64_t value = 0;
        int found = 0;
        for (j = 0; j < c->n_values; j++)
            if (c->val[j].type == r->type) { value = c->val[j].value; found = 1; }
        if (!found) return GZ_TERMS_DOES_NOT_FIT;
        for (j = 0; j < l->n_max && j < GZ_TERMS_MAX_ADJ; j++) {
            if (l->max[j].type != r->type) continue;
            if (value > l->max[j].max) return GZ_TERMS_DOES_NOT_FIT;
            if (r->max > l->max[j].max) cls = GZ_TERMS_FITS_ONLY_NOW;
        }
    }
    return cls;
}

const char *gz_terms_err_name(gz_terms_err_t e)
{
    switch (e) {
    case GZ_TERMS_OK: return "ok";
    case GZ_TERMS_E_TOO_LONG: return "too_long";
    case GZ_TERMS_E_TRUNCATED: return "truncated";
    case GZ_TERMS_E_NOT_MINIMAL: return "not_minimal";
    case GZ_TERMS_E_ORDER: return "order";
    case GZ_TERMS_E_UNKNOWN_EVEN: return "unknown_even";
    case GZ_TERMS_E_RESERVED_TYPE: return "reserved_type";
    case GZ_TERMS_E_TYPE_NOT_ALLOWED: return "type_not_allowed";
    case GZ_TERMS_E_LENGTH: return "length";
    case GZ_TERMS_E_MISSING: return "missing";
    case GZ_TERMS_E_UTF8: return "utf8";
    case GZ_TERMS_E_HOST_KEY: return "host_key";
    case GZ_TERMS_E_PROFILE: return "profile";
    case GZ_TERMS_E_TARGET: return "target";
    case GZ_TERMS_E_MINIMUM: return "minimum";
    case GZ_TERMS_E_SHORTFALL: return "shortfall";
    case GZ_TERMS_E_READY_WINDOW: return "ready_window";
    case GZ_TERMS_E_SIGNING_BUDGET: return "signing_budget";
    case GZ_TERMS_E_STEP_TIMEOUT: return "step_timeout";
    case GZ_TERMS_E_LIFETIME: return "lifetime";
    case GZ_TERMS_E_WINDDOWN: return "winddown";
    case GZ_TERMS_E_CHANNEL: return "channel";
    case GZ_TERMS_E_FEERATE: return "feerate";
    case GZ_TERMS_E_SWITCHES: return "switches";
    case GZ_TERMS_E_RANGE: return "range";
    case GZ_TERMS_E_SHAPE_ENCODING: return "shape_encoding";
    case GZ_TERMS_E_SHAPE_MAX_MEMBERS: return "shape_max_members";
    case GZ_TERMS_E_SHAPE_N_INTERIOR: return "shape_n_interior";
    case GZ_TERMS_E_SHAPE_WIDTH: return "shape_width";
    case GZ_TERMS_E_SHAPE_LEAF_KIND: return "shape_leaf_kind";
    case GZ_TERMS_E_SHAPE_TARGET: return "shape_target";
    case GZ_TERMS_E_SHAPE_SPLIT: return "shape_split";
    case GZ_TERMS_E_CHAIN: return "chain";
    case GZ_TERMS_E_SLICE1: return "slice1";
    case GZ_TERMS_E_VERSION: return "version";
    case GZ_TERMS_E_ADJ_SET: return "adj_set";
    case GZ_TERMS_E_ADJ_VALUE: return "adj_value";
    case GZ_TERMS_E_SCOPE: return "scope";
    case GZ_TERMS_E_PINNED_KEY: return "pinned_key";
    case GZ_TERMS_E_OUTER_SIG: return "outer_sig";
    case GZ_TERMS_E_CURRENT_SIG: return "current_sig";
    case GZ_TERMS_E_OUTER_DIGEST: return "outer_digest";
    case GZ_TERMS_E_ARGUMENT: return "argument";
    }
    return "unknown";
}
