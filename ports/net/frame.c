/* BOLT 1 framing and TLV. See frame.h. */
#include "frame.h"

#include <string.h>

gz_frame_err_t gz_bigsize_read(const uint8_t *p, size_t len, uint64_t *val, size_t *used)
{
    size_t n, i;
    uint64_t v = 0, min;
    if (len == 0) return GZ_FRAME_EOF;
    if (p[0] < 0xfd) {
        *val = p[0];
        *used = 1;
        return GZ_FRAME_OK;
    }
    if (p[0] == 0xfd) { n = 2; min = 0xfd; }
    else if (p[0] == 0xfe) { n = 4; min = 0x10000; }
    else { n = 8; min = 0x100000000ULL; }
    if (len < 1 + n) return GZ_FRAME_TRUNCATED;
    for (i = 0; i < n; i++) v = (v << 8) | p[1 + i];
    if (v < min) return GZ_FRAME_NONCANONICAL;
    *val = v;
    *used = 1 + n;
    return GZ_FRAME_OK;
}

size_t gz_bigsize_write(uint64_t v, uint8_t out[9])
{
    size_t n, i;
    if (v < 0xfd) {
        out[0] = (uint8_t)v;
        return 1;
    }
    if (v < 0x10000) { out[0] = 0xfd; n = 2; }
    else if (v < 0x100000000ULL) { out[0] = 0xfe; n = 4; }
    else { out[0] = 0xff; n = 8; }
    for (i = 0; i < n; i++) out[1 + i] = (uint8_t)(v >> (8 * (n - 1 - i)));
    return 1 + n;
}

gz_frame_err_t gz_tu_read(const uint8_t *p, size_t len, size_t max_bytes, uint64_t *val)
{
    uint64_t v = 0;
    size_t i;
    if (len > max_bytes || len > 8) return GZ_FRAME_INVALID;
    if (len > 0 && p[0] == 0) return GZ_FRAME_NONCANONICAL;
    for (i = 0; i < len; i++) v = (v << 8) | p[i];
    *val = v;
    return GZ_FRAME_OK;
}

size_t gz_tu_write(uint64_t v, uint8_t out[8])
{
    size_t n = 0, i;
    uint64_t t;
    for (t = v; t; t >>= 8) n++;
    for (i = 0; i < n; i++) out[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
    return n;
}

gz_frame_err_t gz_msg_parse(const uint8_t *msg, size_t len, uint16_t *type,
                            const uint8_t **rest, size_t *rest_len)
{
    if (len > GZ_MSG_MAX) return GZ_FRAME_TOO_BIG;
    if (len < 2) return GZ_FRAME_TRUNCATED;
    *type = (uint16_t)((msg[0] << 8) | msg[1]);
    *rest = msg + 2;
    *rest_len = len - 2;
    return GZ_FRAME_OK;
}

gz_frame_err_t gz_msg_write(uint16_t type, const uint8_t *rest, size_t rest_len,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (rest_len > GZ_MSG_MAX - 2 || out_cap < rest_len + 2) return GZ_FRAME_TOO_BIG;
    out[0] = (uint8_t)(type >> 8);
    out[1] = (uint8_t)type;
    if (rest_len) memmove(out + 2, rest, rest_len);
    *out_len = rest_len + 2;
    return GZ_FRAME_OK;
}

gz_msg_unknown_t gz_msg_unknown_action(uint16_t type)
{
    return (type & 1) ? GZ_MSG_IGNORE : GZ_MSG_CLOSE;
}

static const gz_tlv_known_t *find_known(const gz_tlv_known_t *k, size_t n, uint64_t type)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (k[i].type == type) return &k[i];
    return NULL;
}

gz_frame_err_t gz_tlv_parse(const uint8_t *s, size_t len,
                            const gz_tlv_known_t *known, size_t n_known, void *ctx,
                            gz_tlv_record_t *out, size_t out_cap, size_t *n_out)
{
    size_t pos = 0, used, count = 0;
    uint64_t type, rlen, last = 0;
    int started = 0;
    gz_frame_err_t e;
    *n_out = 0;
    while (pos < len) {
        const gz_tlv_known_t *k;
        gz_tlv_record_t rec;
        e = gz_bigsize_read(s + pos, len - pos, &type, &used); /* pos < len: never EOF */
        if (e) return e;
        pos += used;
        e = gz_bigsize_read(s + pos, len - pos, &rlen, &used);
        if (e) return e == GZ_FRAME_EOF ? GZ_FRAME_TRUNCATED : e;
        pos += used;
        if (started && type <= last) return GZ_FRAME_ORDER;
        if (rlen > len - pos) return GZ_FRAME_TRUNCATED;
        rec.type = type;
        rec.value = s + pos;
        rec.len = (size_t)rlen;
        k = find_known(known, n_known, type);
        if (k) {
            if (k->check && !k->check(&rec, ctx)) return GZ_FRAME_INVALID;
            if (count == out_cap) return GZ_FRAME_TOO_MANY;
            out[count++] = rec;
        } else if ((type & 1) == 0) {
            return GZ_FRAME_UNKNOWN_EVEN;
        }
        pos += (size_t)rlen;
        last = type;
        started = 1;
    }
    *n_out = count;
    return GZ_FRAME_OK;
}

void gz_tlv_writer_init(gz_tlv_writer_t *w, uint8_t *buf, size_t cap)
{
    memset(w, 0, sizeof *w);
    w->buf = buf;
    w->cap = cap;
}

gz_frame_err_t gz_tlv_put(gz_tlv_writer_t *w, uint64_t type, const uint8_t *value, size_t len)
{
    uint8_t t[9], l[9];
    size_t tn, ln;
    if (w->err) return w->err;
    if (w->started && type <= w->last_type) return w->err = GZ_FRAME_ORDER;
    tn = gz_bigsize_write(type, t);
    ln = gz_bigsize_write((uint64_t)len, l);
    if (w->cap - w->len < tn + ln || w->cap - w->len - tn - ln < len) return w->err = GZ_FRAME_TOO_BIG;
    memcpy(w->buf + w->len, t, tn);
    memcpy(w->buf + w->len + tn, l, ln);
    if (len) memcpy(w->buf + w->len + tn + ln, value, len);
    w->len += tn + ln + len;
    w->last_type = type;
    w->started = 1;
    return GZ_FRAME_OK;
}

const char *gz_frame_err_name(gz_frame_err_t e)
{
    switch (e) {
    case GZ_FRAME_OK: return "ok";
    case GZ_FRAME_EOF: return "end of input";
    case GZ_FRAME_TRUNCATED: return "truncated";
    case GZ_FRAME_NONCANONICAL: return "not minimally encoded";
    case GZ_FRAME_ORDER: return "types not strictly increasing";
    case GZ_FRAME_UNKNOWN_EVEN: return "unknown even type";
    case GZ_FRAME_INVALID: return "invalid value";
    case GZ_FRAME_TOO_BIG: return "too big";
    case GZ_FRAME_TOO_MANY: return "too many records";
    }
    return "unknown";
}
