/* SPDX-License-Identifier: MIT */
/* Strict JSON parser, writer and RFC 8785 canonical form (spec/local-api.md
 * 7.1, 7.4, 5.6). See gazpacho/api_json.h. */
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "gazpacho/api_json.h"

/* ---- arena ----------------------------------------------------------------- */
struct gz_json_block {
    gz_json_block *next;
    size_t size, used;
    unsigned char data[];
};

#define BLOCK_MIN 16384u
#define ALIGN 16u

static void *arena_alloc(gz_json_doc *doc, size_t n)
{
    gz_json_block *b = doc->blocks;
    size_t need;
    n = (n + ALIGN - 1) & ~(size_t)(ALIGN - 1);
    if (!b || b->size - b->used < n) {
        size_t size = n > BLOCK_MIN ? n : BLOCK_MIN;
        b = malloc(sizeof *b + size);
        if (!b) return NULL;
        b->next = doc->blocks;
        b->size = size;
        b->used = 0;
        doc->blocks = b;
    }
    need = b->used;
    b->used += n;
    memset(b->data + need, 0, n);
    return b->data + need;
}

void gz_json_free(gz_json_doc *doc)
{
    gz_json_block *b, *next;
    if (!doc) return;
    for (b = doc->blocks; b; b = next) {
        next = b->next;
        OPENSSL_cleanse(b->data, b->size);
        free(b);
    }
    doc->blocks = NULL;
    doc->root = NULL;
}

/* ---- UTF-8 ------------------------------------------------------------------ */
/* Length of the valid UTF-8 sequence at p (RFC 3629, no overlongs, no
 * surrogates, at most U+10FFFF), its code point in *cp; 0 if invalid. */
static size_t utf8_seq(const uint8_t *p, size_t avail, uint32_t *cp)
{
    uint8_t c = p[0];
    if (c < 0x80) { *cp = c; return 1; }
    if (c >= 0xc2 && c <= 0xdf) {
        if (avail < 2 || (p[1] & 0xc0) != 0x80) return 0;
        *cp = ((uint32_t)(c & 0x1f) << 6) | (p[1] & 0x3f);
        return 2;
    }
    if (c >= 0xe0 && c <= 0xef) {
        if (avail < 3 || (p[1] & 0xc0) != 0x80 || (p[2] & 0xc0) != 0x80) return 0;
        if (c == 0xe0 && p[1] < 0xa0) return 0;          /* overlong */
        if (c == 0xed && p[1] >= 0xa0) return 0;         /* surrogate */
        *cp = ((uint32_t)(c & 0x0f) << 12) | ((uint32_t)(p[1] & 0x3f) << 6) | (p[2] & 0x3f);
        return 3;
    }
    if (c >= 0xf0 && c <= 0xf4) {
        if (avail < 4 || (p[1] & 0xc0) != 0x80 || (p[2] & 0xc0) != 0x80 || (p[3] & 0xc0) != 0x80)
            return 0;
        if (c == 0xf0 && p[1] < 0x90) return 0;          /* overlong */
        if (c == 0xf4 && p[1] >= 0x90) return 0;         /* above U+10FFFF */
        *cp = ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(p[1] & 0x3f) << 12) |
              ((uint32_t)(p[2] & 0x3f) << 6) | (p[3] & 0x3f);
        return 4;
    }
    return 0;
}

static size_t utf8_put(uint32_t cp, char *o)
{
    if (cp < 0x80) { o[0] = (char)cp; return 1; }
    if (cp < 0x800) {
        o[0] = (char)(0xc0 | (cp >> 6));
        o[1] = (char)(0x80 | (cp & 0x3f));
        return 2;
    }
    if (cp < 0x10000) {
        o[0] = (char)(0xe0 | (cp >> 12));
        o[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
        o[2] = (char)(0x80 | (cp & 0x3f));
        return 3;
    }
    o[0] = (char)(0xf0 | (cp >> 18));
    o[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
    o[3] = (char)(0x80 | (cp & 0x3f));
    return 4;
}

/* ---- parser ----------------------------------------------------------------- */
typedef struct {
    const uint8_t *p, *end;
    gz_json_doc *doc;
    int oom;
} parser;

static void skip_ws(parser *ps)
{
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
        ps->p++;
}

static int hex4(const uint8_t *p, uint32_t *v)
{
    int i;
    *v = 0;
    for (i = 0; i < 4; i++) {
        uint8_t c = p[i];
        uint32_t d;
        if (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
        else return 0;
        *v = (*v << 4) | d;
    }
    return 1;
}

/* ps->p at the opening quote. Decoded bytes to *out (arena), length *len. */
static int parse_string(parser *ps, const char **out, size_t *len)
{
    const uint8_t *q = ps->p + 1;
    char *buf, *o;
    size_t raw = 0;
    /* find the closing quote, skipping escapes, to size the buffer */
    while (q + raw < ps->end && q[raw] != '"') {
        if (q[raw] == '\\') raw++;
        raw++;
    }
    if (q + raw >= ps->end) return 0;
    buf = arena_alloc(ps->doc, raw + 1);
    if (!buf) { ps->oom = 1; return 0; }
    o = buf;
    while (*q != '"') {
        uint8_t c = *q;
        if (c < 0x20) return 0;                         /* unescaped control character */
        if (c == '\\') {
            uint32_t cp, lo;
            q++;
            switch (*q) {
            case '"': *o++ = '"'; q++; break;
            case '\\': *o++ = '\\'; q++; break;
            case '/': *o++ = '/'; q++; break;
            case 'b': *o++ = '\b'; q++; break;
            case 'f': *o++ = '\f'; q++; break;
            case 'n': *o++ = '\n'; q++; break;
            case 'r': *o++ = '\r'; q++; break;
            case 't': *o++ = '\t'; q++; break;
            case 'u':
                if (ps->end - q < 5 || !hex4(q + 1, &cp)) return 0;
                q += 5;
                if (cp >= 0xdc00 && cp <= 0xdfff) return 0;   /* lone low surrogate */
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    if (ps->end - q < 6 || q[0] != '\\' || q[1] != 'u' || !hex4(q + 2, &lo)) return 0;
                    if (lo < 0xdc00 || lo > 0xdfff) return 0;   /* lone high surrogate */
                    q += 6;
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                }
                o += utf8_put(cp, o);
                break;
            default:
                return 0;
            }
        } else {
            uint32_t cp;
            size_t k = utf8_seq(q, (size_t)(ps->end - q), &cp);
            if (!k) return 0;
            memcpy(o, q, k);
            o += k;
            q += k;
        }
    }
    *o = 0;
    *out = buf;
    *len = (size_t)(o - buf);
    ps->p = q + 1;
    return 1;
}

static int key_cmp(const void *a, const void *b)
{
    const gz_json *x = *(const gz_json *const *)a, *y = *(const gz_json *const *)b;
    size_t n = x->key_len < y->key_len ? x->key_len : y->key_len;
    int c = memcmp(x->key, y->key, n);
    if (c) return c;
    return x->key_len < y->key_len ? -1 : x->key_len > y->key_len;
}

static gz_json *parse_value(parser *ps, int depth);

static int parse_number(parser *ps, gz_json *v)
{
    int neg = 0;
    int64_t val = 0;
    if (*ps->p == '-') { neg = 1; ps->p++; }
    if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9') return 0;
    if (*ps->p == '0') {
        ps->p++;
    } else {
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') {
            val = val * 10 + (*ps->p - '0');
            if (val > GZ_JSON_MAX_INT) return 0;        /* outside +-(2^53 - 1) */
            ps->p++;
        }
    }
    /* fractions and exponents are not integers */
    if (ps->p < ps->end && (*ps->p == '.' || *ps->p == 'e' || *ps->p == 'E')) return 0;
    if (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') return 0;   /* leading zero */
    v->type = GZ_JSON_INT;
    v->i = neg ? -val : val;
    return 1;
}

static int parse_literal(parser *ps, const char *lit, size_t n)
{
    if ((size_t)(ps->end - ps->p) < n || memcmp(ps->p, lit, n) != 0) return 0;
    ps->p += n;
    return 1;
}

static int parse_container(parser *ps, gz_json *v, int depth, int obj)
{
    gz_json *last = NULL;
    char close = obj ? '}' : ']';
    if (depth > GZ_JSON_MAX_DEPTH) return 0;
    v->type = obj ? GZ_JSON_OBJ : GZ_JSON_ARR;
    ps->p++;
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == close) { ps->p++; return 1; }
    for (;;) {
        const char *key = NULL;
        size_t key_len = 0;
        gz_json *child;
        skip_ws(ps);
        if (obj) {
            if (ps->p >= ps->end || *ps->p != '"' || !parse_string(ps, &key, &key_len)) return 0;
            skip_ws(ps);
            if (ps->p >= ps->end || *ps->p != ':') return 0;
            ps->p++;
        }
        child = parse_value(ps, depth);
        if (!child) return 0;
        child->key = key;
        child->key_len = key_len;
        if (last) last->next = child;
        else v->child = child;
        last = child;
        v->len++;
        skip_ws(ps);
        if (ps->p >= ps->end) return 0;
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == close) { ps->p++; break; }
        return 0;
    }
    if (obj && v->len > 1) {                            /* duplicate names: sort and compare */
        gz_json **m = malloc(v->len * sizeof *m), *c;
        size_t i = 0;
        int dup = 0;
        if (!m) { ps->oom = 1; return 0; }
        for (c = v->child; c; c = c->next) m[i++] = c;
        qsort(m, v->len, sizeof *m, key_cmp);
        for (i = 1; i < v->len; i++)
            if (key_cmp(&m[i - 1], &m[i]) == 0) dup = 1;
        free(m);
        if (dup) return 0;
    }
    return 1;
}

static gz_json *parse_value(parser *ps, int depth)
{
    gz_json *v;
    skip_ws(ps);
    if (ps->p >= ps->end) return NULL;
    v = arena_alloc(ps->doc, sizeof *v);
    if (!v) { ps->oom = 1; return NULL; }
    switch (*ps->p) {
    case '{':
        return parse_container(ps, v, depth + 1, 1) ? v : NULL;
    case '[':
        return parse_container(ps, v, depth + 1, 0) ? v : NULL;
    case '"':
        v->type = GZ_JSON_STR;
        return parse_string(ps, &v->s, &v->len) ? v : NULL;
    case 't':
        v->type = GZ_JSON_BOOL; v->i = 1;
        return parse_literal(ps, "true", 4) ? v : NULL;
    case 'f':
        v->type = GZ_JSON_BOOL; v->i = 0;
        return parse_literal(ps, "false", 5) ? v : NULL;
    case 'n':
        v->type = GZ_JSON_NULL;
        return parse_literal(ps, "null", 4) ? v : NULL;
    default:
        return parse_number(ps, v) ? v : NULL;
    }
}

int gz_json_parse(const uint8_t *in, size_t n, gz_json_doc *doc)
{
    parser ps;
    doc->root = NULL;
    doc->blocks = NULL;
    ps.p = in;
    ps.end = in + n;
    ps.doc = doc;
    ps.oom = 0;
    doc->root = parse_value(&ps, 0);
    if (doc->root) {
        skip_ws(&ps);
        if (ps.p != ps.end) doc->root = NULL;           /* trailing bytes */
    }
    if (!doc->root) {
        int oom = ps.oom;
        gz_json_free(doc);
        return oom ? -2 : -1;
    }
    return 0;
}

const gz_json *gz_json_get(const gz_json *obj, const char *key)
{
    const gz_json *c;
    size_t n = strlen(key);
    if (!obj || obj->type != GZ_JSON_OBJ) return NULL;
    for (c = obj->child; c; c = c->next)
        if (c->key_len == n && memcmp(c->key, key, n) == 0) return c;
    return NULL;
}

/* ---- writer ------------------------------------------------------------------ */
void gz_jw_init(gz_jw *w)
{
    memset(w, 0, sizeof *w);
}

void gz_jw_reset(gz_jw *w)
{
    if (w->buf) OPENSSL_cleanse(w->buf, w->cap);
    w->len = 0;
    w->err = 0;
    w->depth = 0;
    w->after_key = 0;
    memset(w->count, 0, sizeof w->count);
}

void gz_jw_free(gz_jw *w)
{
    if (w->buf) {
        OPENSSL_cleanse(w->buf, w->cap);
        free(w->buf);
    }
    memset(w, 0, sizeof *w);
}

static int jw_reserve(gz_jw *w, size_t n)
{
    char *nb;
    size_t cap;
    if (w->err) return 0;
    if (w->cap - w->len > n) return 1;
    cap = w->cap ? w->cap : 256;
    while (cap - w->len <= n) {
        if (cap > ((size_t)1 << 30)) { w->err = 1; return 0; }
        cap *= 2;
    }
    nb = malloc(cap);                                   /* never realloc: the old copy is wiped */
    if (!nb) { w->err = 1; return 0; }
    if (w->buf) {
        memcpy(nb, w->buf, w->len);
        OPENSSL_cleanse(w->buf, w->cap);
        free(w->buf);
    }
    w->buf = nb;
    w->cap = cap;
    return 1;
}

void gz_jw_bytes(gz_jw *w, const char *s, size_t n)
{
    if (!jw_reserve(w, n + 1)) return;
    memcpy(w->buf + w->len, s, n);
    w->len += n;
    w->buf[w->len] = 0;
}

static void put(gz_jw *w, const char *s) { gz_jw_bytes(w, s, strlen(s)); }

static void pre_value(gz_jw *w)
{
    if (w->after_key) { w->after_key = 0; return; }
    if (w->depth > 0) {
        if (w->is_obj[w->depth - 1]) { w->err = 1; return; }   /* a value in an object needs a key */
        if (w->count[w->depth - 1]++) put(w, ",");
    }
}

static void open_c(gz_jw *w, int obj)
{
    pre_value(w);
    if (w->depth >= GZ_JW_MAX_DEPTH) { w->err = 1; return; }
    w->is_obj[w->depth] = (unsigned char)obj;
    w->count[w->depth] = 0;
    w->depth++;
    put(w, obj ? "{" : "[");
}

static void close_c(gz_jw *w, int obj)
{
    if (w->depth == 0 || w->is_obj[w->depth - 1] != obj || w->after_key) { w->err = 1; return; }
    w->depth--;
    put(w, obj ? "}" : "]");
}

void gz_jw_obj(gz_jw *w) { open_c(w, 1); }
void gz_jw_end_obj(gz_jw *w) { close_c(w, 1); }
void gz_jw_arr(gz_jw *w) { open_c(w, 0); }
void gz_jw_end_arr(gz_jw *w) { close_c(w, 0); }

static void esc_str(gz_jw *w, const char *s, size_t n)
{
    static const char hexd[] = "0123456789abcdef";
    const uint8_t *p = (const uint8_t *)s;
    size_t i = 0;
    put(w, "\"");
    while (i < n) {
        uint8_t c = p[i];
        uint32_t cp;
        size_t k;
        char e[7];
        if (c < 0x20 || c == '"' || c == '\\') {
            switch (c) {
            case '\b': put(w, "\\b"); break;
            case '\t': put(w, "\\t"); break;
            case '\n': put(w, "\\n"); break;
            case '\f': put(w, "\\f"); break;
            case '\r': put(w, "\\r"); break;
            case '"': put(w, "\\\""); break;
            case '\\': put(w, "\\\\"); break;
            default:
                e[0] = '\\'; e[1] = 'u'; e[2] = '0'; e[3] = '0';
                e[4] = hexd[c >> 4]; e[5] = hexd[c & 15]; e[6] = 0;
                put(w, e);
            }
            i++;
            continue;
        }
        k = utf8_seq(p + i, n - i, &cp);
        if (!k) {                                       /* not UTF-8: U+FFFD, never the raw byte */
            put(w, "\xef\xbf\xbd");
            i++;
            continue;
        }
        gz_jw_bytes(w, s + i, k);
        i += k;
    }
    put(w, "\"");
}

void gz_jw_key(gz_jw *w, const char *k)
{
    if (w->depth == 0 || !w->is_obj[w->depth - 1] || w->after_key) { w->err = 1; return; }
    if (w->count[w->depth - 1]++) put(w, ",");
    esc_str(w, k, strlen(k));
    put(w, ":");
    w->after_key = 1;
}

void gz_jw_strn(gz_jw *w, const char *s, size_t n) { pre_value(w); esc_str(w, s, n); }
void gz_jw_str(gz_jw *w, const char *s)
{
    if (!s) { gz_jw_null(w); return; }
    gz_jw_strn(w, s, strlen(s));
}

void gz_jw_int(gz_jw *w, int64_t v)
{
    char b[24];
    int i = 23;
    uint64_t u = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
    pre_value(w);
    b[i] = 0;
    do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    if (v < 0) b[--i] = '-';
    put(w, b + i);
}

void gz_jw_bool(gz_jw *w, int v) { pre_value(w); put(w, v ? "true" : "false"); }
void gz_jw_null(gz_jw *w) { pre_value(w); put(w, "null"); }
void gz_jw_raw(gz_jw *w, const char *json)
{
    if (!json) { gz_jw_null(w); return; }
    pre_value(w);
    put(w, json);
}
void gz_jw_kstr(gz_jw *w, const char *k, const char *s) { gz_jw_key(w, k); gz_jw_str(w, s); }
void gz_jw_kint(gz_jw *w, const char *k, int64_t v) { gz_jw_key(w, k); gz_jw_int(w, v); }
void gz_jw_kbool(gz_jw *w, const char *k, int v) { gz_jw_key(w, k); gz_jw_bool(w, v); }
void gz_jw_knull(gz_jw *w, const char *k) { gz_jw_key(w, k); gz_jw_null(w); }
void gz_jw_kraw(gz_jw *w, const char *k, const char *json) { gz_jw_key(w, k); gz_jw_raw(w, json); }

/* Unicode 15.1 general category Cf. */
int gz_json_is_format_char(uint32_t cp)
{
    static const uint32_t r[][2] = {
        {0x00ad, 0x00ad}, {0x0600, 0x0605}, {0x061c, 0x061c}, {0x06dd, 0x06dd}, {0x070f, 0x070f},
        {0x0890, 0x0891}, {0x08e2, 0x08e2}, {0x180e, 0x180e}, {0x200b, 0x200f}, {0x202a, 0x202e},
        {0x2060, 0x2064}, {0x2066, 0x206f}, {0xfeff, 0xfeff}, {0xfff9, 0xfffb}, {0x110bd, 0x110bd},
        {0x110cd, 0x110cd}, {0x13430, 0x1343f}, {0x1bca0, 0x1bca3}, {0x1d173, 0x1d17a},
        {0xe0001, 0xe0001}, {0xe0020, 0xe007f},
    };
    size_t i;
    for (i = 0; i < sizeof r / sizeof r[0]; i++)
        if (cp >= r[i][0] && cp <= r[i][1]) return 1;
    return 0;
}

void gz_jw_text(gz_jw *w, const char *k, const char *text, const char *by, size_t max_bytes)
{
    const uint8_t *p = (const uint8_t *)(text ? text : "");
    size_t n = strlen((const char *)p), i = 0, outn = 0;
    char *clean = malloc(n + 1);
    if (!clean) { w->err = 1; return; }
    while (i < n) {
        uint32_t cp;
        size_t len = utf8_seq(p + i, n - i, &cp);
        if (!len) { i++; continue; }                    /* invalid byte: dropped */
        if ((cp < 0x20 && cp != '\n') || (cp >= 0x7f && cp <= 0x9f) || gz_json_is_format_char(cp)) {
            i += len;
            continue;
        }
        if (outn + len > max_bytes) break;             /* cut on a character boundary */
        memcpy(clean + outn, p + i, len);
        outn += len;
        i += len;
    }
    if (k) gz_jw_key(w, k);
    gz_jw_obj(w);
    gz_jw_key(w, "text");
    gz_jw_strn(w, clean, outn);
    gz_jw_kstr(w, "by", by);
    gz_jw_kbool(w, "checked", 0);
    gz_jw_end_obj(w);
    OPENSSL_cleanse(clean, n + 1);
    free(clean);
}

/* ---- RFC 8785 ------------------------------------------------------------------ */
/* Compare two valid UTF-8 strings by UTF-16 code units (RFC 8785 3.2.3). */
static int u16_next(const uint8_t *s, size_t n, size_t *i, uint16_t *pending, uint16_t *unit)
{
    uint32_t cp;
    size_t k;
    if (*pending) { *unit = *pending; *pending = 0; return 1; }
    if (*i >= n) return 0;
    k = utf8_seq(s + *i, n - *i, &cp);
    if (!k) { cp = s[*i]; k = 1; }                      /* never reached for parsed input */
    *i += k;
    if (cp >= 0x10000) {
        cp -= 0x10000;
        *unit = (uint16_t)(0xd800 + (cp >> 10));
        *pending = (uint16_t)(0xdc00 + (cp & 0x3ff));
    } else {
        *unit = (uint16_t)cp;
    }
    return 1;
}

static int utf16_cmp(const void *a, const void *b)
{
    const gz_json *x = *(const gz_json *const *)a, *y = *(const gz_json *const *)b;
    size_t i = 0, j = 0;
    uint16_t px = 0, py = 0, ux, uy;
    for (;;) {
        int hx = u16_next((const uint8_t *)x->key, x->key_len, &i, &px, &ux);
        int hy = u16_next((const uint8_t *)y->key, y->key_len, &j, &py, &uy);
        if (!hx || !hy) return hx - hy;
        if (ux != uy) return ux < uy ? -1 : 1;
    }
}

static void jcs_val(const gz_json *v, gz_jw *w, int strip)
{
    const gz_json *c;
    switch (v->type) {
    case GZ_JSON_NULL: gz_jw_bytes(w, "null", 4); break;
    case GZ_JSON_BOOL: put(w, v->i ? "true" : "false"); break;
    case GZ_JSON_INT: {
        char b[24];
        int i = 23;
        uint64_t u = v->i < 0 ? (uint64_t)0 - (uint64_t)v->i : (uint64_t)v->i;
        b[i] = 0;
        do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u);
        if (v->i < 0) b[--i] = '-';
        put(w, b + i);
        break;
    }
    case GZ_JSON_STR: esc_str(w, v->s, v->len); break;
    case GZ_JSON_ARR:
        put(w, "[");
        for (c = v->child; c; c = c->next) {
            if (c != v->child) put(w, ",");
            jcs_val(c, w, 0);
        }
        put(w, "]");
        break;
    case GZ_JSON_OBJ: {
        const gz_json **m = v->len ? malloc(v->len * sizeof *m) : NULL;
        size_t n = 0, i;
        int first = 1;
        if (v->len && !m) { w->err = 1; return; }
        for (c = v->child; c; c = c->next) {
            if (strip && c->key_len == 10 && memcmp(c->key, "passphrase", 10) == 0) continue;
            m[n++] = c;
        }
        if (n > 1) qsort(m, n, sizeof *m, utf16_cmp);
        put(w, "{");
        for (i = 0; i < n; i++) {
            if (!first) put(w, ",");
            first = 0;
            esc_str(w, m[i]->key, m[i]->key_len);
            put(w, ":");
            jcs_val(m[i], w, 0);
        }
        put(w, "}");
        free(m);
        break;
    }
    }
}

void gz_json_jcs(const gz_json *v, int strip_passphrase, gz_jw *out)
{
    jcs_val(v, out, strip_passphrase);
}

int gz_json_jcs_digest(const gz_json *v, uint8_t digest[32])
{
    gz_jw w;
    int ok;
    gz_jw_init(&w);
    jcs_val(v, &w, 1);
    ok = !w.err && SHA256((const unsigned char *)(w.buf ? w.buf : ""), w.len, digest) != NULL;
    gz_jw_free(&w);
    return ok ? 0 : -1;
}
