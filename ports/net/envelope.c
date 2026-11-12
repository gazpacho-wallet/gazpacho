/* Gazpacho's factory message envelope. See envelope.h and spec/messages.md. */
#include "envelope.h"

#include <stdlib.h>
#include <string.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include "frame.h"

const uint8_t GZ_ENV_PROTOCOL[4] = {0x67, 0x7a, 0x66, 0x01};

/* SHA256("SuperScalar/1"), messages.md 10.3. */
const uint8_t GZ_ENV_FACTORY_PROTOCOL_ID[32] = {
    0xc3, 0xa0, 0x82, 0xd0, 0xfc, 0xb7, 0x68, 0xd7, 0x69, 0x99, 0xf4, 0xf8, 0xad, 0x67, 0x2f, 0x71,
    0x10, 0xfb, 0xef, 0x6a, 0x13, 0xa1, 0x69, 0x76, 0x86, 0xc7, 0x07, 0x39, 0x61, 0xc8, 0x42, 0xf1};

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* ------------------------------------------------------------ record tables */

enum { CHK_NONE, CHK_ASCII, CHK_UTF8, CHK_NONCE_BLOCKS };

/* A fixed size: min == max, entry 0. A byte range: min..max, entry 0. A
 * list: entry bytes per entry, min..max entries. */
typedef struct {
    uint16_t type;
    uint32_t min, max;
    uint16_t entry;
    uint8_t required, check;
} rule_t;

enum { DIR_H2M = 1, DIR_M2H = 2, DIR_EITHER = 3 };

typedef struct {
    uint16_t kind;
    uint8_t dir;
    const rule_t *rules;
    size_t n;
} kind_t;

#define FIX(t, n, req) {t, n, n, 0, req, CHK_NONE}
#define RANGE(t, lo, hi, req, chk) {t, lo, hi, 0, req, chk}
#define LIST(t, e, lo, hi, req) {t, lo, hi, e, req, CHK_NONE}
#define SIG FIX(240, 64, 1)

/* Section 5. */
static const rule_t R_PART[] = {FIX(2, 32, 1), FIX(4, 2, 1), FIX(6, 4, 1), FIX(8, 2, 1), FIX(10, 2, 1),
                                RANGE(12, 1, GZ_ENV_PART_DATA, 1, CHK_NONE)};
/* Section 6. */
static const rule_t R_TERMS[] = {RANGE(2, 1, 4096, 1, CHK_NONE), FIX(4, 64, 1), RANGE(6, 1, 1024, 1, CHK_NONE),
                                 FIX(8, 64, 1)};
static const rule_t R_JOIN[] = {FIX(2, 33, 1), FIX(4, 64, 1), FIX(6, 64, 1), RANGE(7, 1, 32, 0, CHK_UTF8)};
static const rule_t R_READY[] = {FIX(2, 32, 1), FIX(4, 4, 1), FIX(6, 32, 1), FIX(8, 32, 0), FIX(11, 2, 0), SIG};
static const rule_t R_REASON[] = {FIX(1, 2, 0)};
static const rule_t R_STATUS[] = {FIX(2, 1, 1), FIX(4, 1, 1), FIX(6, 4, 1), FIX(8, 2, 1), FIX(10, 2, 1),
                                  FIX(13, 2, 0)};
static const rule_t R_CHECK[] = {FIX(2, 32, 1), FIX(4, 4, 1), FIX(6, 32, 1), FIX(8, 4, 1), SIG};
static const rule_t R_START[] = {FIX(2, 32, 1), FIX(4, 1, 1), FIX(6, 2, 1), SIG};
static const rule_t R_CANCEL[] = {FIX(2, 2, 1), SIG};
/* Section 7. Odd records whose encoding is still open (all_partials,
 * payouts, penalties, evidence) are not listed: they are skipped as unknown
 * odd records, as 7.6, 7.7 and 7.9 say. Record 44 (distribution) is not
 * listed: a slice 1 member refuses it as an unknown even record. */
static const rule_t R_PROPOSE[] = {
    FIX(2, 32, 1), FIX(4, 32, 1), FIX(6, 1, 1), FIX(7, 2, 0), FIX(8, 4, 1), FIX(10, 32, 1), FIX(12, 36, 1),
    FIX(14, 8, 1), FIX(16, 34, 1), RANGE(18, 60, 100000, 1, CHK_NONE), LIST(20, 194, 2, 1001, 1),
    LIST(22, 4, 1, 8, 1), FIX(24, 4, 1), FIX(28, 1, 1), FIX(30, 8, 1), FIX(32, 4, 1), LIST(34, 36, 0, 4096, 1),
    FIX(36, 1, 1), FIX(38, 1, 1), FIX(40, 2, 1), FIX(42, 2, 1), FIX(46, 32, 1), FIX(48, 4, 1), FIX(50, 4, 1), SIG};
static const rule_t R_NONCES[] = {FIX(2, 32, 1), FIX(4, 1, 1), LIST(6, 134, 1, 256, 1)};
static const rule_t R_ALL_NONCES[] = {FIX(2, 32, 1), FIX(4, 1, 1), {6, 1, 256, 0, 1, CHK_NONCE_BLOCKS}};
static const rule_t R_PARTIALS[] = {FIX(2, 32, 1), FIX(4, 1, 1), LIST(6, 68, 1, 256, 1), SIG};
static const rule_t R_TIER_RESULT[] = {FIX(2, 32, 1), FIX(4, 1, 1), LIST(6, 68, 1, 256, 1), SIG};
static const rule_t R_COMPLETE[] = {FIX(2, 32, 1), SIG};
static const rule_t R_ACK[] = {FIX(2, 32, 1), FIX(4, 32, 1), SIG};
static const rule_t R_ABORT[] = {FIX(2, 32, 1), FIX(4, 2, 1), RANGE(7, 1, 256, 0, CHK_ASCII), FIX(9, 1, 0),
                                 LIST(11, 4, 1, 256, 0), SIG};
static const rule_t R_ROUND_ID[] = {FIX(2, 32, 1)};

#define K(kind, dir, r) {kind, dir, r, sizeof r / sizeof r[0]}
static const kind_t KINDS[] = {
    /* part: "either" in 4.1, but members send no parts in slice 1 (section
     * 5), so a host refuses one as a kind in the wrong direction. */
    K(GZ_ENV_KIND_PART, DIR_H2M, R_PART),
    {GZ_ENV_KIND_HELLO, DIR_M2H, NULL, 0},
    K(GZ_ENV_KIND_TERMS_OFFER, DIR_H2M, R_TERMS),
    K(GZ_ENV_KIND_JOIN, DIR_M2H, R_JOIN),
    K(GZ_ENV_KIND_READY, DIR_M2H, R_READY),
    K(GZ_ENV_KIND_UNREADY, DIR_M2H, R_REASON),
    K(GZ_ENV_KIND_LEAVE, DIR_M2H, R_REASON),
    K(GZ_ENV_KIND_LOBBY_STATUS, DIR_H2M, R_STATUS),
    K(GZ_ENV_KIND_READY_CHECK, DIR_H2M, R_CHECK),
    K(GZ_ENV_KIND_START, DIR_H2M, R_START),
    K(GZ_ENV_KIND_CANCEL, DIR_H2M, R_CANCEL),
    K(GZ_ENV_KIND_ROUND_PROPOSE, DIR_H2M, R_PROPOSE),
    K(GZ_ENV_KIND_ROUND_NONCES, DIR_M2H, R_NONCES),
    K(GZ_ENV_KIND_ROUND_ALL_NONCES, DIR_H2M, R_ALL_NONCES),
    K(GZ_ENV_KIND_ROUND_PARTIAL_SIGS, DIR_M2H, R_PARTIALS),
    K(GZ_ENV_KIND_ROUND_TIER_RESULT, DIR_H2M, R_TIER_RESULT),
    K(GZ_ENV_KIND_ROUND_COMPLETE, DIR_H2M, R_COMPLETE),
    K(GZ_ENV_KIND_ROUND_ACK, DIR_M2H, R_ACK),
    K(GZ_ENV_KIND_ROUND_ABORT, DIR_EITHER, R_ABORT),
    K(GZ_ENV_KIND_ROUND_STATUS_REQUEST, DIR_M2H, R_ROUND_ID),
    K(GZ_ENV_KIND_FACTORY_FUNDED, DIR_H2M, R_ROUND_ID),
};

static const kind_t *find_kind(uint16_t kind)
{
    size_t i;
    for (i = 0; i < sizeof KINDS / sizeof KINDS[0]; i++)
        if (KINDS[i].kind == kind) return &KINDS[i];
    return NULL;
}

static int is_discovery(uint16_t kind) { return kind >= 128 && kind <= 159; }

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* Printable ASCII, for a reason a person may read in a log. */
static int ascii_ok(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (p[i] < 0x20 || p[i] > 0x7e) return 0;
    return 1;
}

/* Well-formed UTF-8 (RFC 3629): no overlong forms, no surrogates, at most
 * U+10FFFF. */
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
        if ((need == 2 && cp < 0x800) || (need == 3 && (cp < 0x10000 || cp > 0x10ffff)) ||
            (cp >= 0xd800 && cp <= 0xdfff))
            return 0;
        i += need + 1;
    }
    return 1;
}

/* round_all_nonces items (7.4): per item index (u32), n_signers (u16), then
 * n_signers times a public nonce (66) and its signature (64). Between 1 and
 * 256 items, each with at least one signer, and nothing left over. */
static int nonce_blocks_ok(const uint8_t *p, size_t n, uint32_t lo, uint32_t hi)
{
    uint32_t items = 0;
    size_t at = 0;
    while (at < n) {
        size_t signers;
        if (n - at < 6) return 0;
        signers = get16(p + at + 4);
        at += 6;
        if (signers == 0 || (n - at) / 130 < signers) return 0;
        at += signers * 130;
        if (++items > hi) return 0;
    }
    return items >= lo;
}

static int value_ok(const rule_t *r, const uint8_t *v, size_t len)
{
    if (r->check == CHK_NONCE_BLOCKS) return nonce_blocks_ok(v, len, r->min, r->max);
    if (r->entry) {
        if (len % r->entry) return 0;
        if (len / r->entry < r->min || len / r->entry > r->max) return 0;
        return 1;
    }
    if (len < r->min || len > r->max) return 0;
    if (r->check == CHK_ASCII) return ascii_ok(v, len);
    if (r->check == CHK_UTF8) return utf8_ok(v, len);
    return 1;
}

/* ------------------------------------------------------------ the stream */

/* Walks a TLV stream with BOLT 1's rules and section 4.2's rule that nothing
 * follows record 240. Calls `each` (if given) for every record; a nonzero
 * return from it stops the walk with that value. Returns 0 if well formed,
 * 1 if not. */
typedef int (*each_fn)(uint64_t type, const uint8_t *v, size_t len, void *ctx);

static int walk(const uint8_t *s, size_t len, each_fn each, void *ctx, const char **why)
{
    size_t at = 0, used;
    uint64_t type, vlen, last = 0;
    int first = 1, seen_sig = 0;
    while (at < len) {
        if (gz_bigsize_read(s + at, len - at, &type, &used) != GZ_FRAME_OK) { *why = "bad record type"; return 1; }
        at += used;
        if (gz_bigsize_read(s + at, len - at, &vlen, &used) != GZ_FRAME_OK) { *why = "bad record length"; return 1; }
        at += used;
        if (vlen > len - at) { *why = "record past the end"; return 1; }
        if (!first && type <= last) { *why = "records out of order"; return 1; }
        if (seen_sig) { *why = "record after the signature"; return 1; }
        if (type == GZ_ENV_SIG_TYPE) seen_sig = 1;
        if (each) {
            int r = each(type, s + at, (size_t)vlen, ctx);
            if (r) return r;
        }
        first = 0;
        last = type;
        at += (size_t)vlen;
    }
    return 0;
}

typedef struct {
    const kind_t *k;
    uint32_t seen; /* bit i: rule i matched */
    const char *why;
} schema_ctx_t;

static int each_schema(uint64_t type, const uint8_t *v, size_t len, void *vctx)
{
    schema_ctx_t *c = vctx;
    size_t i;
    for (i = 0; i < c->k->n; i++) {
        if (c->k->rules[i].type == type) {
            if (!value_ok(&c->k->rules[i], v, len)) { c->why = "record of the wrong size"; return 1; }
            c->seen |= 1u << i;
            return 0;
        }
    }
    if ((type & 1) == 0) { c->why = "unknown even record"; return 1; }
    return 0; /* unknown odd: skipped */
}

gz_env_verdict_t gz_env_check(uint16_t kind, const uint8_t scope[32], const uint8_t *records, size_t len,
                              gz_env_side_t at, const char **reason)
{
    const char *dummy;
    const kind_t *k;
    schema_ctx_t c;
    size_t i;
    if (!reason) reason = &dummy;
    *reason = NULL;
    /* Discovery is never worth a disconnect (4.1); this build has no
     * discovery, so every discovery kind is ignored. */
    if (is_discovery(kind)) return GZ_ENV_IGNORE;
    k = find_kind(kind);
    if (!k) {
        if (kind & 1) return GZ_ENV_IGNORE;
        *reason = "unknown even kind";
        return GZ_ENV_REFUSE;
    }
    if (!(k->dir & (at == GZ_ENV_AT_HOST ? DIR_M2H : DIR_H2M))) {
        *reason = "kind in the wrong direction";
        return GZ_ENV_REFUSE;
    }
    if (kind != GZ_ENV_KIND_HELLO && all_zero(scope, 32)) {
        *reason = "zero scope";
        return GZ_ENV_REFUSE;
    }
    memset(&c, 0, sizeof c);
    c.k = k;
    c.why = NULL;
    if (walk(records, len, each_schema, &c, &c.why)) {
        *reason = c.why ? c.why : "malformed records";
        return GZ_ENV_REFUSE;
    }
    for (i = 0; i < k->n; i++) {
        if (k->rules[i].required && !(c.seen & (1u << i))) {
            *reason = "required record missing";
            return GZ_ENV_REFUSE;
        }
    }
    return GZ_ENV_DELIVER;
}

gz_env_verdict_t gz_env_read(const uint8_t *msg, size_t len, gz_env_side_t at, gz_env_msg_t *out,
                             const char **reason)
{
    const char *dummy;
    const uint8_t *p;
    size_t n;
    gz_env_verdict_t v;
    if (!reason) reason = &dummy;
    *reason = NULL;
    if (len < 2 || get16(msg) != GZ_ENV_TYPE) { *reason = "not a factory message"; return GZ_ENV_REFUSE; }
    p = msg + 2;
    n = len - 2;
    if (n < 4) { *reason = "factory message too short"; return GZ_ENV_REFUSE; }
    if (memcmp(p, GZ_ENV_PROTOCOL, 4) != 0) {
        *reason = "unknown factory protocol";
        return GZ_ENV_IGNORE_WARN;
    }
    if (n < GZ_ENV_HDR_LEN) { *reason = "factory message too short"; return GZ_ENV_REFUSE; }
    out->kind = get16(p + 4);
    out->scope = p + 6;
    out->records = p + GZ_ENV_HDR_LEN;
    out->records_len = n - GZ_ENV_HDR_LEN;
    v = gz_env_check(out->kind, out->scope, out->records, out->records_len, at, reason);
    return v;
}

typedef struct {
    gz_env_record_t *out;
    size_t cap, n;
} collect_ctx_t;

static int each_collect(uint64_t type, const uint8_t *v, size_t len, void *vctx)
{
    collect_ctx_t *c = vctx;
    if (c->n < c->cap) {
        c->out[c->n].type = type;
        c->out[c->n].value = v;
        c->out[c->n].len = len;
    }
    c->n++;
    return 0;
}

int gz_env_records(const uint8_t *records, size_t len, gz_env_record_t *out, size_t cap)
{
    collect_ctx_t c;
    const char *why;
    c.out = out;
    c.cap = cap;
    c.n = 0;
    if (walk(records, len, each_collect, &c, &why)) return -1;
    return (int)(c.n < cap ? c.n : cap);
}

const gz_env_record_t *gz_env_find(const gz_env_record_t *recs, int n, uint64_t type)
{
    int i;
    for (i = 0; i < n; i++)
        if (recs[i].type == type) return &recs[i];
    return NULL;
}

/* ------------------------------------------------------------ writing */

int gz_env_write(uint16_t kind, const uint8_t scope[32], const uint8_t *records, size_t records_len,
                 uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (records_len > GZ_ENV_MAX_RECORDS || out_cap < 2 + GZ_ENV_HDR_LEN + records_len) return 1;
    put16(out, GZ_ENV_TYPE);
    memcpy(out + 2, GZ_ENV_PROTOCOL, 4);
    put16(out + 6, kind);
    memcpy(out + 8, scope, 32);
    if (records_len) memcpy(out + 2 + GZ_ENV_HDR_LEN, records, records_len);
    *out_len = 2 + GZ_ENV_HDR_LEN + records_len;
    return 0;
}

unsigned gz_env_part_count(size_t body_len)
{
    if (body_len <= GZ_ENV_MAX_RECORDS || body_len > GZ_ENV_MAX_WHOLE) return 0;
    return (unsigned)((body_len + GZ_ENV_PART_DATA - 1) / GZ_ENV_PART_DATA);
}

void gz_env_tagged_hash(const secp256k1_context *secp, const char *tag,
                        const uint8_t *bytes, size_t len, uint8_t out[32])
{
    if (!secp256k1_tagged_sha256(secp, out, (const unsigned char *)tag, strlen(tag), bytes, len))
        abort(); /* cannot fail for valid arguments */
}

void gz_env_transfer_id(const secp256k1_context *secp, uint16_t inner_kind, const uint8_t *body, size_t len,
                        uint8_t out[32])
{
    /* TH("gazpacho/part", u16 inner_kind || body). The tagged hash takes one
     * contiguous preimage, so the kind and the body are copied together. */
    uint8_t *buf = malloc(len + 2);
    if (!buf) abort();
    put16(buf, inner_kind);
    if (len) memcpy(buf + 2, body, len);
    gz_env_tagged_hash(secp, "gazpacho/part", buf, len + 2, out);
    free(buf);
}

int gz_env_write_part(const uint8_t tid[32], uint16_t inner_kind, const uint8_t scope[32],
                      const uint8_t *body, size_t body_len, unsigned index,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t k[2], t[4], ix[2], cnt[2];
    gz_tlv_writer_t w;
    unsigned count = gz_env_part_count(body_len);
    size_t off, dlen;
    if (!count || index >= count || inner_kind == GZ_ENV_KIND_PART) return 1;
    if (out_cap < 2 + GZ_ENV_HDR_LEN) return 1;
    off = (size_t)index * GZ_ENV_PART_DATA;
    dlen = body_len - off < GZ_ENV_PART_DATA ? body_len - off : GZ_ENV_PART_DATA;
    put16(k, inner_kind);
    put32(t, (uint32_t)body_len);
    put16(ix, (uint16_t)index);
    put16(cnt, (uint16_t)count);
    /* The records are written in place, after the header. */
    gz_tlv_writer_init(&w, out + 2 + GZ_ENV_HDR_LEN, out_cap - 2 - GZ_ENV_HDR_LEN);
    gz_tlv_put(&w, 2, tid, 32);
    gz_tlv_put(&w, 4, k, 2);
    gz_tlv_put(&w, 6, t, 4);
    gz_tlv_put(&w, 8, ix, 2);
    gz_tlv_put(&w, 10, cnt, 2);
    gz_tlv_put(&w, 12, body + off, dlen);
    if (w.err) return 1;
    put16(out, GZ_ENV_TYPE);
    memcpy(out + 2, GZ_ENV_PROTOCOL, 4);
    put16(out + 6, GZ_ENV_KIND_PART);
    memcpy(out + 8, scope, 32);
    *out_len = 2 + GZ_ENV_HDR_LEN + w.len;
    return 0;
}

/* ------------------------------------------------------------ signatures */

static int each_find_sig(uint64_t type, const uint8_t *v, size_t len, void *vctx)
{
    const uint8_t **sig = vctx;
    if (type == GZ_ENV_SIG_TYPE && len == 64) *sig = v;
    return 0;
}

/* The bytes before record 240: its type is one byte (0xf0), its length one
 * byte (0x40), so the record starts two bytes before its value. */
static const uint8_t *find_sig(const gz_env_msg_t *m)
{
    const uint8_t *sig = NULL;
    const char *why;
    if (walk(m->records, m->records_len, each_find_sig, &sig, &why)) return NULL;
    return sig;
}

int gz_env_msg_hash(const secp256k1_context *secp, const gz_env_msg_t *m, uint8_t out[32])
{
    const uint8_t *sig = find_sig(m);
    size_t before;
    uint8_t *pre;
    if (!sig) return 0;
    before = (size_t)(sig - 2 - m->records);
    pre = malloc(GZ_ENV_HDR_LEN + before);
    if (!pre) return 0;
    memcpy(pre, GZ_ENV_PROTOCOL, 4);
    put16(pre + 4, m->kind);
    memcpy(pre + 6, m->scope, 32);
    if (before) memcpy(pre + GZ_ENV_HDR_LEN, m->records, before);
    gz_env_tagged_hash(secp, "gazpacho/msg", pre, GZ_ENV_HDR_LEN + before, out);
    free(pre);
    return 1;
}

int gz_env_verify(const secp256k1_context *secp, const gz_env_msg_t *m, const uint8_t key[33])
{
    secp256k1_pubkey pk;
    secp256k1_xonly_pubkey xk;
    uint8_t h[32];
    const uint8_t *sig = find_sig(m);
    if (!sig || !gz_env_msg_hash(secp, m, h)) return 0;
    if (!secp256k1_ec_pubkey_parse(secp, &pk, key, 33)) return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(secp, &xk, NULL, &pk)) return 0;
    return secp256k1_schnorrsig_verify(secp, sig, h, 32, &xk);
}

/* ------------------------------------------------------------ reassembly */

void gz_env_reasm_init(gz_env_reasm_t *r)
{
    memset(r, 0, sizeof *r);
}

void gz_env_reasm_reset(gz_env_reasm_t *r)
{
    free(r->buf);
    gz_env_reasm_init(r);
}

static gz_env_verdict_t reasm_refuse(gz_env_reasm_t *r, const char **reason, const char *why)
{
    gz_env_reasm_reset(r);
    *reason = why;
    return GZ_ENV_REFUSE;
}

gz_env_verdict_t gz_env_reasm_add(gz_env_reasm_t *r, const gz_env_msg_t *part, gz_env_side_t at,
                                  const secp256k1_context *secp, gz_env_msg_t *out, const char **reason)
{
    gz_env_record_t rec[8];
    const gz_env_record_t *tid, *data;
    const char *dummy;
    uint16_t inner, index, count;
    uint32_t total;
    size_t off, want;
    int n;
    uint8_t check[32];
    gz_env_verdict_t v;
    if (!reason) reason = &dummy;
    *reason = NULL;
    if (r->buf && r->held == 0) gz_env_reasm_reset(r); /* the last completed message is released */
    if (part->kind != GZ_ENV_KIND_PART) return reasm_refuse(r, reason, "not a part");
    n = gz_env_records(part->records, part->records_len, rec, 8);
    if (n < 6 || !(tid = gz_env_find(rec, n, 2)) || !(data = gz_env_find(rec, n, 12)) ||
        !gz_env_find(rec, n, 4) || !gz_env_find(rec, n, 6) || !gz_env_find(rec, n, 8) || !gz_env_find(rec, n, 10))
        return reasm_refuse(r, reason, "part records missing");
    inner = get16(gz_env_find(rec, n, 4)->value);
    total = get32(gz_env_find(rec, n, 6)->value);
    index = get16(gz_env_find(rec, n, 8)->value);
    count = get16(gz_env_find(rec, n, 10)->value);
    /* Rule 1, and inner_kind 2. */
    if (inner == GZ_ENV_KIND_PART) return reasm_refuse(r, reason, "part inside a part");
    if (total > GZ_ENV_MAX_WHOLE || count < 2 || count > GZ_ENV_MAX_PARTS ||
        count != (total + GZ_ENV_PART_DATA - 1) / GZ_ENV_PART_DATA)
        return reasm_refuse(r, reason, "part count or length out of bounds");
    if (index >= count) return reasm_refuse(r, reason, "part index out of range");
    off = (size_t)index * GZ_ENV_PART_DATA;
    want = index + 1u == count ? total - off : GZ_ENV_PART_DATA;
    if (data->len != want) return reasm_refuse(r, reason, "part data of the wrong length");
    /* Rule 4: another transfer replaces the open one. */
    if (r->buf && memcmp(r->transfer_id, tid->value, 32) != 0) gz_env_reasm_reset(r);
    if (r->buf) {
        /* Same transfer: everything that defines it must agree. */
        if (r->inner_kind != inner || r->total_len != total || r->count != count ||
            memcmp(r->scope, part->scope, 32) != 0)
            return reasm_refuse(r, reason, "part disagrees with its transfer");
        if (r->held & (1u << index)) {
            /* Rule 3. */
            if (memcmp(r->buf + off, data->value, want) == 0) return GZ_ENV_IGNORE;
            return reasm_refuse(r, reason, "part repeated with other data");
        }
    } else {
        /* Rule 2: the first part seen opens the transfer. */
        r->buf = malloc(total);
        if (!r->buf) return reasm_refuse(r, reason, "out of memory");
        r->allocated = total;
        memcpy(r->transfer_id, tid->value, 32);
        memcpy(r->scope, part->scope, 32);
        r->inner_kind = inner;
        r->total_len = total;
        r->count = count;
        r->held = 0;
    }
    memcpy(r->buf + off, data->value, want);
    r->held |= 1u << index;
    if (r->held != (1u << count) - 1u) return GZ_ENV_HELD;
    /* Rule 5. */
    gz_env_transfer_id(secp, inner, r->buf, total, check);
    if (memcmp(check, r->transfer_id, 32) != 0) return reasm_refuse(r, reason, "transfer_id does not match");
    r->held = 0; /* complete: the buffer is kept for `out` until the next call */
    v = gz_env_check(inner, r->scope, r->buf, total, at, reason);
    if (v != GZ_ENV_DELIVER) {
        if (v == GZ_ENV_REFUSE) gz_env_reasm_reset(r);
        return v;
    }
    out->kind = inner;
    out->scope = r->scope;
    out->records = r->buf;
    out->records_len = total;
    return GZ_ENV_DELIVER;
}

/* ------------------------------------------------------------ bLIP-56 */

#define SUB_SUPPORTED 2
#define SUB_PIGGYBACK 4

int gz_env_blip56_supported(uint8_t *out, size_t out_cap, size_t *out_len)
{
    gz_tlv_writer_t w;
    if (out_cap < 4) return 1;
    put16(out, GZ_ENV_BLIP56_TYPE);
    put16(out + 2, SUB_SUPPORTED);
    gz_tlv_writer_init(&w, out + 4, out_cap - 4);
    gz_tlv_put(&w, 512, GZ_ENV_FACTORY_PROTOCOL_ID, 32);
    if (w.err) return 1;
    *out_len = 4 + w.len;
    return 0;
}

int gz_env_blip56_wrap(const uint8_t *native, size_t len, uint8_t *out, size_t out_cap, size_t *out_len)
{
    gz_tlv_writer_t w;
    if (len < 2 + GZ_ENV_HDR_LEN || get16(native) != GZ_ENV_TYPE || memcmp(native + 2, GZ_ENV_PROTOCOL, 4) != 0)
        return 1;
    if (out_cap < 4) return 1;
    put16(out, GZ_ENV_BLIP56_TYPE);
    put16(out + 2, SUB_PIGGYBACK);
    gz_tlv_writer_init(&w, out + 4, out_cap - 4 > 65531 ? 65531 : out_cap - 4);
    gz_tlv_put(&w, 0, GZ_ENV_FACTORY_PROTOCOL_ID, 32);
    gz_tlv_put(&w, 1024, native + 6, len - 6);
    if (w.err) return 1;
    *out_len = 4 + w.len;
    return 0;
}

static int check_id(const gz_tlv_record_t *rec, void *ctx)
{
    (void)ctx;
    return rec->len == 32 && memcmp(rec->value, GZ_ENV_FACTORY_PROTOCOL_ID, 32) == 0;
}

static int check_inner(const gz_tlv_record_t *rec, void *ctx)
{
    (void)ctx;
    return rec->len >= GZ_ENV_HDR_LEN - 4;
}

int gz_env_blip56_unwrap(const uint8_t *msg, size_t len, uint8_t *out, size_t out_cap, size_t *out_len)
{
    static const gz_tlv_known_t known[] = {{0, check_id}, {1024, check_inner}};
    gz_tlv_record_t rec[2];
    size_t n;
    if (len < 4 || get16(msg) != GZ_ENV_BLIP56_TYPE || get16(msg + 2) != SUB_PIGGYBACK) return 1;
    if (gz_tlv_parse(msg + 4, len - 4, known, 2, NULL, rec, 2, &n) || n != 2) return 1;
    if (rec[0].type != 0 || rec[1].type != 1024) return 1;
    if (6 + rec[1].len > out_cap || 6 + rec[1].len > 65535) return 1;
    put16(out, GZ_ENV_TYPE);
    memcpy(out + 2, GZ_ENV_PROTOCOL, 4);
    memcpy(out + 6, rec[1].value, rec[1].len);
    *out_len = 6 + rec[1].len;
    return 0;
}
