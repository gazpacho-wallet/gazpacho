/* The envelope, the records and every lobby message (messages.md 4 to 6).
 * Everything from a peer is hostile input: every length is checked before it
 * is used. Splitting (section 5) is the transport's. */
#include "gazpacho/lobby.h"
#include "lobby_internal.h"
#include <string.h>

static const uint8_t TAG[4] = {0x67, 0x7a, 0x66, 0x01};
#define HDR GZ_LOBBY_ENV_HDR   /* protocol 4, kind 2, scope 32 */

/* BigSize (BOLT 1), minimally encoded. 1 and advances, or 0. */
int gz_lw_bigsize(const uint8_t *p, size_t len, size_t *at, uint64_t *v)
{
    size_t n, i;
    uint64_t x = 0;
    if (*at >= len) return 0;
    switch (p[*at]) {
    case 0xfd: n = 2; break;
    case 0xfe: n = 4; break;
    case 0xff: n = 8; break;
    default: *v = p[*at]; (*at)++; return 1;
    }
    if (len - *at - 1 < n) return 0;
    for (i = 0; i < n; i++) x = x << 8 | p[*at + 1 + i];
    if ((n == 2 && x < 0xfd) || (n == 4 && x < 0x10000) || (n == 8 && x < 0x100000000ull)) return 0;
    *at += 1 + n;
    *v = x;
    return 1;
}

size_t gz_lw_put_bigsize(uint8_t *out, uint64_t v)
{
    size_t n, i;
    if (v < 0xfd) { out[0] = (uint8_t)v; return 1; }
    if (v <= 0xffff) { out[0] = 0xfd; n = 2; }
    else if (v <= 0xffffffffull) { out[0] = 0xfe; n = 4; }
    else { out[0] = 0xff; n = 8; }
    for (i = 0; i < n; i++) out[1 + i] = (uint8_t)(v >> (8 * (n - 1 - i)));
    return 1 + n;
}

uint64_t gz_lw_get(const uint8_t *p, size_t n)
{
    uint64_t x = 0;
    size_t i;
    for (i = 0; i < n; i++) x = x << 8 | p[i];
    return x;
}

void gz_lw_put(uint8_t *p, uint64_t v, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
}

int gz_lw_tlv_next(gz_lw_tlv_t *t)
{
    uint64_t type, len;
    if (t->at == t->len) return 0;
    if (!gz_lw_bigsize(t->p, t->len, &t->at, &type) || !gz_lw_bigsize(t->p, t->len, &t->at, &len) ||
        len > t->len - t->at || (t->started && type <= t->type)) return -1;
    t->started = 1;
    t->type = type;
    t->vlen = (size_t)len;
    t->v = t->p + t->at;
    t->at += (size_t)len;
    return 1;
}

/* One row of a kind's record table. */
typedef struct { uint16_t kind; uint8_t type; uint32_t min, max; uint8_t req; } row_t;
#define FIX(k, t, n, r) {k, t, n, n, r}
static const row_t ROWS[] = {
    {GZ_KIND_TERMS_OFFER, 2, 1, GZ_TERMS_OUTER_MAX, 1}, FIX(GZ_KIND_TERMS_OFFER, 4, 64, 1),
    {GZ_KIND_TERMS_OFFER, 6, 1, GZ_TERMS_CURRENT_MAX, 1}, FIX(GZ_KIND_TERMS_OFFER, 8, 64, 1),
    {GZ_KIND_JOIN, 7, 1, 32, 0},   /* K1: no factory key and no binding in a join */
    FIX(GZ_KIND_READY, 2, 32, 1), FIX(GZ_KIND_READY, 4, 4, 1), FIX(GZ_KIND_READY, 6, 32, 1),
    FIX(GZ_KIND_READY, 8, 32, 0), FIX(GZ_KIND_READY, 11, 2, 0), FIX(GZ_KIND_READY, 12, 33, 1),
    FIX(GZ_KIND_READY, 14, 64, 1), FIX(GZ_KIND_READY, 240, 64, 1),
    FIX(GZ_KIND_UNREADY, 1, 2, 0), FIX(GZ_KIND_LEAVE, 1, 2, 0),
    FIX(GZ_KIND_LOBBY_STATUS, 2, 1, 1), FIX(GZ_KIND_LOBBY_STATUS, 4, 1, 1),
    FIX(GZ_KIND_LOBBY_STATUS, 6, 4, 1), FIX(GZ_KIND_LOBBY_STATUS, 8, 2, 1),
    FIX(GZ_KIND_LOBBY_STATUS, 10, 2, 1), FIX(GZ_KIND_LOBBY_STATUS, 13, 2, 0),
    FIX(GZ_KIND_READY_CHECK, 2, 32, 1), FIX(GZ_KIND_READY_CHECK, 4, 4, 1),
    FIX(GZ_KIND_READY_CHECK, 6, 32, 1), FIX(GZ_KIND_READY_CHECK, 8, 4, 1),
    FIX(GZ_KIND_READY_CHECK, 240, 64, 1),
    FIX(GZ_KIND_START, 2, 32, 1), FIX(GZ_KIND_START, 4, 1, 1), FIX(GZ_KIND_START, 6, 2, 1),
    FIX(GZ_KIND_START, 240, 64, 1),
    FIX(GZ_KIND_CANCEL, 2, 2, 1), FIX(GZ_KIND_CANCEL, 240, 64, 1),
};
#define N_ROWS (sizeof ROWS / sizeof ROWS[0])

static int is_lobby_kind(uint16_t k)
{
    return k >= GZ_KIND_HELLO && k <= GZ_KIND_CANCEL && k % 2 == 0;
}

static int all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* Put one known record's value into `m`. */
static void set_field(gz_lobby_msg_t *m, uint8_t type, const uint8_t *v, size_t n)
{
    switch (m->kind * 256 + type) {
    case GZ_KIND_TERMS_OFFER * 256 + 2: m->outer = v; m->outer_len = n; break;
    case GZ_KIND_TERMS_OFFER * 256 + 4: m->outer_sig = v; break;
    case GZ_KIND_TERMS_OFFER * 256 + 6: m->current = v; m->current_len = n; break;
    case GZ_KIND_TERMS_OFFER * 256 + 8: m->current_sig = v; break;
    case GZ_KIND_JOIN * 256 + 7: m->display_name = v; m->display_name_len = n; break;
    case GZ_KIND_READY * 256 + 2: m->outer_digest = v; break;
    case GZ_KIND_READY * 256 + 4: case GZ_KIND_READY_CHECK * 256 + 4:
    case GZ_KIND_LOBBY_STATUS * 256 + 6: m->version = (uint32_t)gz_lw_get(v, 4); break;
    case GZ_KIND_READY * 256 + 6: case GZ_KIND_READY_CHECK * 256 + 6: m->current_digest = v; break;
    case GZ_KIND_READY * 256 + 8: m->check_id = v; m->has_check_id = 1; break;
    case GZ_KIND_READY * 256 + 11: m->min_members = (uint16_t)gz_lw_get(v, 2); m->has_min_members = 1; break;
    case GZ_KIND_READY * 256 + 12: m->factory_key = v; break;
    case GZ_KIND_READY * 256 + 14: m->bind_by_contribution = v; break;
    case GZ_KIND_UNREADY * 256 + 1: case GZ_KIND_LEAVE * 256 + 1: case GZ_KIND_LOBBY_STATUS * 256 + 13:
        m->reason = (uint16_t)gz_lw_get(v, 2); m->has_reason = 1; break;
    case GZ_KIND_CANCEL * 256 + 2: m->reason = (uint16_t)gz_lw_get(v, 2); break;
    case GZ_KIND_LOBBY_STATUS * 256 + 2: m->lobby_state = v[0]; break;
    case GZ_KIND_LOBBY_STATUS * 256 + 4: m->seat_state = v[0]; break;
    case GZ_KIND_LOBBY_STATUS * 256 + 8: m->joined = (uint16_t)gz_lw_get(v, 2); break;
    case GZ_KIND_LOBBY_STATUS * 256 + 10: m->ready = (uint16_t)gz_lw_get(v, 2); break;
    case GZ_KIND_READY_CHECK * 256 + 2: case GZ_KIND_START * 256 + 2: m->check_id = v; m->has_check_id = 1; break;
    case GZ_KIND_READY_CHECK * 256 + 8: m->answer_within_ms = (uint32_t)gz_lw_get(v, 4); break;
    case GZ_KIND_START * 256 + 4: m->role = v[0]; break;
    case GZ_KIND_START * 256 + 6: m->signers = (uint16_t)gz_lw_get(v, 2); break;
    default: break;
    }
}

int gz_lobby_decode(uint16_t kind, const uint8_t scope[32], const uint8_t *records, size_t len,
                    gz_lobby_msg_t *m)
{
    gz_lw_tlv_t t;
    uint64_t seen = 0;
    size_t i, start;
    int r, last240 = 0;
    if (!scope || (!records && len) || len > GZ_LOBBY_MAX_RECORDS) return GZ_DEC_REFUSE;
    if (kind >= 128 && kind <= 159) return GZ_DEC_IGNORE;
    if (!is_lobby_kind(kind)) {
        if (kind >= 64 && kind <= 81 && (kind % 2 == 0 || kind == 81)) return GZ_DEC_OTHER;
        return kind % 2 ? GZ_DEC_IGNORE : GZ_DEC_REFUSE;
    }
    memset(m, 0, sizeof *m);
    m->kind = kind;
    memcpy(m->scope, scope, 32);
    if (kind != GZ_KIND_HELLO && all_zero(m->scope, 32)) return GZ_DEC_REFUSE;
    m->records = records;
    m->records_len = len;
    m->signed_len = len;
    memset(&t, 0, sizeof t);
    t.p = records;
    t.len = len;
    while (start = t.at, (r = gz_lw_tlv_next(&t)) == 1) {
        int known = 0;
        if (last240) return GZ_DEC_REFUSE;            /* nothing may follow 240 */
        for (i = 0; i < N_ROWS; i++) {
            if (ROWS[i].kind != kind || ROWS[i].type != t.type) continue;
            if (t.vlen < ROWS[i].min || t.vlen > ROWS[i].max) return GZ_DEC_REFUSE;
            set_field(m, ROWS[i].type, t.v, t.vlen);
            seen |= (uint64_t)1 << i;
            known = 1;
            if (t.type == 240) {
                m->sig = t.v;
                m->signed_len = start;
                last240 = 1;
            }
        }
        if (!known && t.type % 2 == 0) return GZ_DEC_REFUSE;
    }
    if (r < 0) return GZ_DEC_REFUSE;
    for (i = 0; i < N_ROWS; i++)
        if (ROWS[i].kind == kind && ROWS[i].req && !(seen & ((uint64_t)1 << i))) return GZ_DEC_REFUSE;
    if (kind == GZ_KIND_READY && memcmp(m->outer_digest, m->scope, 32) != 0) return GZ_DEC_REFUSE;
    return GZ_DEC_OK;
}

int gz_lobby_decode_env(const uint8_t *env, size_t len, gz_lobby_msg_t *m)
{
    if (!env || len < HDR) return GZ_DEC_REFUSE;
    if (memcmp(env, TAG, 4) != 0) return GZ_DEC_BADTAG;
    return gz_lobby_decode((uint16_t)gz_lw_get(env + 4, 2), env + 6, env + HDR, len - HDR, m);
}

void gz_lobby_msg_hash(const gz_lobby_msg_t *m, uint8_t out[32])
{
    tr_sha256_t s;
    uint8_t k[2];
    gz_lw_put(k, m->kind, 2);
    tr_tagged_init(&s, "gazpacho/msg");
    tr_sha256_write(&s, TAG, 4);
    tr_sha256_write(&s, k, 2);
    tr_sha256_write(&s, m->scope, 32);
    if (m->signed_len) tr_sha256_write(&s, m->records, m->signed_len);
    tr_sha256_done(&s, out);
}

/* ------------------------------------------------------------- encoding */

void gz_lobby_enc_start(gz_lobby_enc_t *e, uint8_t *buf, size_t cap, uint16_t kind,
                        const uint8_t scope[32])
{
    e->buf = buf; e->cap = cap; e->len = 0; e->bad = cap < HDR;
    if (e->bad) return;
    memcpy(buf, TAG, 4);
    gz_lw_put(buf + 4, kind, 2);
    memcpy(buf + 6, scope, 32);
    e->len = HDR;
}

void gz_lobby_enc_record(gz_lobby_enc_t *e, uint64_t type, const uint8_t *v, size_t len)
{
    uint8_t h[18];
    size_t hn;
    if (e->bad) return;
    hn = gz_lw_put_bigsize(h, type);
    hn += gz_lw_put_bigsize(h + hn, len);
    if (e->cap - e->len < hn || e->cap - e->len - hn < len || e->len + hn + len > GZ_LOBBY_MAX_ENV) {
        e->bad = 1;
        return;
    }
    memcpy(e->buf + e->len, h, hn);
    if (len) memcpy(e->buf + e->len + hn, v, len);
    e->len += hn + len;
}

void gz_lobby_enc_u8(gz_lobby_enc_t *e, uint64_t type, uint8_t v) { gz_lobby_enc_record(e, type, &v, 1); }
void gz_lobby_enc_u16(gz_lobby_enc_t *e, uint64_t type, uint16_t v)
{
    uint8_t b[2];
    gz_lw_put(b, v, 2);
    gz_lobby_enc_record(e, type, b, 2);
}
void gz_lobby_enc_u32(gz_lobby_enc_t *e, uint64_t type, uint32_t v)
{
    uint8_t b[4];
    gz_lw_put(b, v, 4);
    gz_lobby_enc_record(e, type, b, 4);
}

size_t gz_lobby_enc_sign(gz_lobby_enc_t *e, const gz_lobby_crypto_t *c, uint32_t which)
{
    uint8_t h[32], sig[64];
    if (e->bad) return 0;
    gz_la_tagged("gazpacho/msg", e->buf, e->len, h);
    if (c->sign(c->ctx, which, h, sig) != 1) return 0;
    gz_lobby_enc_record(e, 240, sig, 64);
    return gz_lobby_enc_done(e);
}

size_t gz_lobby_enc_done(gz_lobby_enc_t *e) { return e->bad ? 0 : e->len; }

void gz_lobby_binding(const uint8_t scope[32], const uint8_t fkey[33], const uint8_t ckey[33],
                      uint8_t out[32])
{
    tr_sha256_t s;
    tr_tagged_init(&s, "gazpacho/bind");
    tr_sha256_write(&s, scope, 32);
    tr_sha256_write(&s, fkey, 33);
    tr_sha256_write(&s, ckey, 33);
    tr_sha256_done(&s, out);
}
