/* SPDX-License-Identifier: MIT */
/* Strict JSON for the local API (spec/local-api.md 7.1, 7.4, 5.6).
 *
 * The parser refuses what the API refuses: duplicate member names, nesting
 * deeper than 16 levels, numbers that are not integers within +-(2^53 - 1),
 * invalid UTF-8, lone surrogates in escapes, a byte order mark, and anything
 * after the top value. Every byte it holds is wiped when the document is freed,
 * because request bodies carry the passphrase and the 24 words.
 *
 * The writer builds answers. gz_jw_text writes the { text, by, checked } object
 * for text written by other people, with control characters (other than
 * newline) and Unicode format characters (category Cf) removed.
 *
 * gz_json_jcs_digest is the request digest of 7.4: SHA-256 of the body in
 * RFC 8785 canonical form with the top-level "passphrase" member removed. */
#ifndef GAZPACHO_API_JSON_H
#define GAZPACHO_API_JSON_H

#include <stddef.h>
#include <stdint.h>

#define GZ_JSON_MAX_DEPTH 16
#define GZ_JSON_MAX_INT 9007199254740991LL /* 2^53 - 1 */

typedef enum {
    GZ_JSON_NULL,
    GZ_JSON_BOOL,
    GZ_JSON_INT,
    GZ_JSON_STR,
    GZ_JSON_ARR,
    GZ_JSON_OBJ
} gz_json_type;

typedef struct gz_json gz_json;
struct gz_json {
    gz_json_type type;
    int64_t i;            /* GZ_JSON_INT value; GZ_JSON_BOOL 0 or 1 */
    const char *s;        /* GZ_JSON_STR: decoded UTF-8, NUL-terminated (may hold NUL) */
    size_t len;           /* GZ_JSON_STR byte length; ARR/OBJ member count */
    const char *key;      /* member name when inside an object */
    size_t key_len;
    gz_json *child;       /* first element or member */
    gz_json *next;        /* next sibling */
};

typedef struct gz_json_block gz_json_block;
typedef struct {
    gz_json *root;
    gz_json_block *blocks;
} gz_json_doc;

/* 0 on success; -1 not valid for this API (bad_json); -2 out of memory. */
int gz_json_parse(const uint8_t *in, size_t n, gz_json_doc *doc);
/* Wipes and frees every byte of the document. Safe on a zeroed doc. */
void gz_json_free(gz_json_doc *doc);
/* The member named key of an object, or NULL. */
const gz_json *gz_json_get(const gz_json *obj, const char *key);

/* RFC 8785 canonical form of v into out (a gz_jw), top-level "passphrase"
 * removed when strip_passphrase is set. */
struct gz_jw;
void gz_json_jcs(const gz_json *v, int strip_passphrase, struct gz_jw *out);
/* SHA-256 of the canonical form, top-level "passphrase" removed. 0 on success. */
int gz_json_jcs_digest(const gz_json *v, uint8_t digest[32]);

/* ---- writer ---------------------------------------------------------------- */
#define GZ_JW_MAX_DEPTH 32
typedef struct gz_jw {
    char *buf;
    size_t len, cap;
    int err;                          /* sticky: out of memory or misuse */
    int depth;
    unsigned short count[GZ_JW_MAX_DEPTH];
    unsigned char is_obj[GZ_JW_MAX_DEPTH];
    int after_key;
} gz_jw;

void gz_jw_init(gz_jw *w);
void gz_jw_reset(gz_jw *w);           /* wipes, keeps the buffer */
void gz_jw_free(gz_jw *w);            /* wipes and frees */
/* Appends raw bytes with no JSON structure (used for the canonical form). */
void gz_jw_bytes(gz_jw *w, const char *s, size_t n);
void gz_jw_obj(gz_jw *w);
void gz_jw_end_obj(gz_jw *w);
void gz_jw_arr(gz_jw *w);
void gz_jw_end_arr(gz_jw *w);
void gz_jw_key(gz_jw *w, const char *k);
void gz_jw_str(gz_jw *w, const char *s);
void gz_jw_strn(gz_jw *w, const char *s, size_t n);
void gz_jw_int(gz_jw *w, int64_t v);
void gz_jw_bool(gz_jw *w, int v);
void gz_jw_null(gz_jw *w);
/* A value already in JSON form (checked by the caller); NULL writes null. */
void gz_jw_raw(gz_jw *w, const char *json);
/* key + value conveniences */
void gz_jw_kstr(gz_jw *w, const char *k, const char *s);   /* NULL writes null */
void gz_jw_kint(gz_jw *w, const char *k, int64_t v);
void gz_jw_kbool(gz_jw *w, const char *k, int v);
void gz_jw_knull(gz_jw *w, const char *k);
void gz_jw_kraw(gz_jw *w, const char *k, const char *json);
/* Text written by another party (5.6): { "text", "by", "checked": false },
 * control characters other than newline and every format character (Cf)
 * removed, cut to at most max_bytes on a character boundary. */
void gz_jw_text(gz_jw *w, const char *k, const char *text, const char *by, size_t max_bytes);

/* Unicode general category Cf (Unicode 15.1). Exposed for tests. */
int gz_json_is_format_char(uint32_t cp);

#endif
