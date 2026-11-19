/* libFuzzer target: a journal holding the local-API engine's records and the
 * slots' records, made from the input's bytes (P6a). A start returns GZ_OK or
 * GZ_ERR_CORRUPT and nothing else; a node that started then takes hostile
 * events, its view on, without an error (node.h, the engine rule).
 *
 * Fields reach 320 bytes and raw records 600, past every bound the engine
 * keeps (a path of 192, 8 held scopes of 32, a local id of 64, a request id
 * of 64), and a batch may be one of the boundary records below with fuzzed
 * fill, one byte either side of each bound (review A of PR 55, L7). */
#include "hostile.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static size_t src_len(src_t *s, size_t cap)
{
    size_t v = src_byte(s);
    v = v << 8 | src_byte(s);
    return v % (cap + 1);
}

/* A record at or one past a bound, its bytes filled from the input. */
static size_t boundary(src_t *s, uint32_t *type, uint8_t *rec, size_t cap)
{
    uint8_t v[400], one = 1, two = 2;
    size_t at = 0, n;
    unsigned which = src_byte(s) % 5, over = src_byte(s) & 1;
    uint8_t fill = src_byte(s);
    memset(v, fill, sizeof v);
    switch (which) {
    case 0: /* pause, held for signing, 8 or 9 scopes */
        *type = 0x000d000cu;
        gz_rec_put(rec, cap, &at, 2, &two, 1);
        gz_rec_put(rec, cap, &at, 4, v, 8);
        gz_rec_put(rec, cap, &at, 6, v, 32 * (8 + over));
        break;
    case 1: /* local_ids: an id of 64 or 65 */
        *type = 0x000d000eu;
        memcpy(v + 32, "lob_", 4);
        for (size_t i = 36; i < 32 + 65; i++) v[i] = (uint8_t)('a' + v[i] % 26);
        gz_rec_put(rec, cap, &at, 2, v, 32);
        gz_rec_put(rec, cap, &at, 4, v + 32, 64 + over);
        break;
    default: /* request_id: an id of 64 or 65, a path of 192 or 193, an object of 64 or 65 */
        *type = 0x000d0014u;
        n = which == 2 ? 64 + over : 16;
        for (size_t i = 0; i < 300; i++) v[i] = (uint8_t)('a' + v[i] % 26);
        gz_rec_put(rec, cap, &at, 2, v, n);
        gz_rec_put(rec, cap, &at, 4, v, 4);
        gz_rec_put(rec, cap, &at, 6, v, which == 3 ? 192 + over : 8);
        gz_rec_put(rec, cap, &at, 8, v, 32);
        gz_rec_put(rec, cap, &at, 10, v, 2);
        gz_rec_put(rec, cap, &at, 12, v, which == 4 ? 64 + over : 5);
        gz_rec_put(rec, cap, &at, 14, v, 8);
        gz_rec_put(rec, cap, &at, 15, v, one);
        break;
    }
    return at;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint32_t types[] = {0x000d000cu, 0x000d000eu, 0x000d0014u, 0x000d0024u, 0x000d0040u, 0x000d0041u,
                                     0x0004000cu, 0x0004000eu};
    h_t h;
    src_t s = {data, size, 0, 0x9e3779b97f4a7c15ull};
    gz_status_t st;
    if (size < 2) return check_done() * 0;
    h_init(&h, data[0] & 1, 1);
    s.at = 1;
    for (unsigned b = 0; s.at < s.n && b < 8; b++) {
        uint8_t rec[700], v[320];
        size_t at = 0;
        uint32_t type = types[src_byte(&s) % (sizeof types / sizeof types[0])];
        uint8_t how = src_byte(&s) % 3;
        if (how == 0) {                   /* raw bytes */
            at = src_len(&s, 600);
            for (size_t i = 0; i < at; i++) rec[i] = src_byte(&s);
        } else if (how == 1) {            /* well-formed fields with fuzzed values */
            unsigned nf = src_byte(&s) % 8;
            for (unsigned f = 0, t = 0; f < nf; f++) {
                size_t n = src_len(&s, sizeof v);
                t += 1 + src_byte(&s) % 4;
                for (size_t i = 0; i < n; i++) v[i] = src_byte(&s);
                if (gz_rec_put(rec, sizeof rec, &at, t, v, n) != GZ_OK) break;
            }
        } else {                          /* a boundary record */
            at = boundary(&s, &type, rec, sizeof rec);
        }
        h_add_batch(&h, 1, b + 1, type, rec, at);
    }
    h_new_node(&h);
    st = h_start(&h);
    if (st != GZ_OK && st != GZ_ERR_CORRUPT) abort();
    if (st == GZ_OK)
        for (unsigned e = 0; s.at < s.n && e < 200; e++)
            if (hostile_step(&h, &s) != GZ_OK || gz_node_error_area(h.n) != 0) abort();
    h_free(&h);
    return 0;
}
