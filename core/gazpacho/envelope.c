#include "gazpacho/envelope.h"
#include <string.h>

static const uint8_t GZ_ENVELOPE_TAG[GZ_ENVELOPE_TAG_LEN] = {0x67, 0x7a, 0x66, 0x01};

void gz_put_u16(uint8_t out[2], uint16_t v)
{
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)v;
}

void gz_put_u32(uint8_t out[4], uint32_t v)
{
    for (int i = 0; i < 4; i++) out[i] = (uint8_t)(v >> (8 * (3 - i)));
}

void gz_put_u64(uint8_t out[8], uint64_t v)
{
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (8 * (7 - i)));
}

uint16_t gz_get_u16(const uint8_t in[2])
{
    return (uint16_t)((unsigned)in[0] << 8 | in[1]);
}

uint32_t gz_get_u32(const uint8_t in[4])
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v = v << 8 | in[i];
    return v;
}

uint64_t gz_get_u64(const uint8_t in[8])
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = v << 8 | in[i];
    return v;
}

gz_status_t gz_env_join(uint16_t kind, const uint8_t scope[32], gz_bytes_t records,
                        uint8_t *out, size_t cap, size_t *len)
{
    if (!scope || !out || !len || (records.len && !records.data)) return GZ_ERR_ARGUMENT;
    if (cap < GZ_ENVELOPE_HDR_LEN || records.len > cap - GZ_ENVELOPE_HDR_LEN) return GZ_ERR_NO_SPACE;
    memcpy(out, GZ_ENVELOPE_TAG, GZ_ENVELOPE_TAG_LEN);
    gz_put_u16(out + 4, kind);
    memcpy(out + 6, scope, 32);
    if (records.len) memcpy(out + GZ_ENVELOPE_HDR_LEN, records.data, records.len);
    *len = GZ_ENVELOPE_HDR_LEN + records.len;
    return GZ_OK;
}

gz_status_t gz_env_split(gz_bytes_t envelope, uint16_t *kind, uint8_t scope[32], gz_bytes_t *records)
{
    if (!kind || !scope || !records) return GZ_ERR_ARGUMENT;
    if (envelope.len < GZ_ENVELOPE_HDR_LEN || !envelope.data ||
        memcmp(envelope.data, GZ_ENVELOPE_TAG, GZ_ENVELOPE_TAG_LEN) != 0)
        return GZ_ERR_CORRUPT;
    *kind = gz_get_u16(envelope.data + 4);
    memcpy(scope, envelope.data + 6, 32);
    records->data = envelope.len > GZ_ENVELOPE_HDR_LEN ? envelope.data + GZ_ENVELOPE_HDR_LEN : NULL;
    records->len = envelope.len - GZ_ENVELOPE_HDR_LEN;
    return GZ_OK;
}

size_t gz_bigsize_put(uint64_t v, uint8_t out[9])
{
    if (v < 0xfd) {
        out[0] = (uint8_t)v;
        return 1;
    }
    if (v <= 0xffff) {
        out[0] = 0xfd;
        gz_put_u16(out + 1, (uint16_t)v);
        return 3;
    }
    if (v <= 0xffffffffu) {
        out[0] = 0xfe;
        gz_put_u32(out + 1, (uint32_t)v);
        return 5;
    }
    out[0] = 0xff;
    gz_put_u64(out + 1, v);
    return 9;
}

size_t gz_bigsize_get(const uint8_t *in, size_t len, uint64_t *v)
{
    if (len < 1) return 0;
    if (in[0] < 0xfd) {
        *v = in[0];
        return 1;
    }
    if (in[0] == 0xfd) {
        if (len < 3) return 0;
        *v = gz_get_u16(in + 1);
        return *v < 0xfd ? 0 : 3;
    }
    if (in[0] == 0xfe) {
        if (len < 5) return 0;
        *v = gz_get_u32(in + 1);
        return *v <= 0xffff ? 0 : 5;
    }
    if (len < 9) return 0;
    *v = gz_get_u64(in + 1);
    return *v <= 0xffffffffu ? 0 : 9;
}

/* One record at stream[*at]: its type and value; advances *at. 0 if malformed. */
static int next_record(gz_bytes_t s, size_t *at, uint64_t *type, gz_bytes_t *value)
{
    uint64_t len;
    size_t n = gz_bigsize_get(s.data + *at, s.len - *at, type);
    if (!n) return 0;
    *at += n;
    n = gz_bigsize_get(s.data + *at, s.len - *at, &len);
    if (!n) return 0;
    *at += n;
    if (len > s.len - *at) return 0;
    value->data = len ? s.data + *at : NULL;
    value->len = (size_t)len;
    *at += (size_t)len;
    return 1;
}

int gz_rec_valid(gz_bytes_t s)
{
    size_t at = 0;
    uint64_t type, last = 0;
    int first = 1;
    gz_bytes_t v;
    if (s.len && !s.data) return 0;
    while (at < s.len) {
        if (!next_record(s, &at, &type, &v)) return 0;
        if (!first && type <= last) return 0;
        first = 0;
        last = type;
    }
    return 1;
}

int gz_rec_find(gz_bytes_t s, uint64_t want, gz_bytes_t *value)
{
    size_t at = 0;
    uint64_t type, last = 0;
    int first = 1, found = 0;
    gz_bytes_t v;
    if (!value || (s.len && !s.data)) return -1;
    while (at < s.len) {
        if (!next_record(s, &at, &type, &v)) return -1;
        if (!first && type <= last) return -1;
        first = 0;
        last = type;
        if (type == want) {
            *value = v;
            found = 1;
        }
    }
    return found;
}

gz_status_t gz_rec_put(uint8_t *out, size_t cap, size_t *at, uint64_t type, const uint8_t *value, size_t len)
{
    uint8_t t[9], l[9];
    size_t nt, nl;
    if (!out || !at || (len && !value)) return GZ_ERR_ARGUMENT;
    nt = gz_bigsize_put(type, t);
    nl = gz_bigsize_put((uint64_t)len, l);
    if (*at > cap || nt + nl > cap - *at || len > cap - *at - nt - nl) return GZ_ERR_NO_SPACE;
    memcpy(out + *at, t, nt);
    memcpy(out + *at + nt, l, nl);
    if (len) memcpy(out + *at + nt + nl, value, len);
    *at += nt + nl + len;
    return GZ_OK;
}
