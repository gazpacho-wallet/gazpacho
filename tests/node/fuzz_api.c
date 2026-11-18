/* libFuzzer target: a journal holding the local-API engine's records and the
 * slots' records, made from the input's bytes (P6a). A start returns GZ_OK or
 * GZ_ERR_CORRUPT and nothing else; a node that started then takes hostile
 * events, its view on, without an error (node.h, the engine rule). */
#include "hostile.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

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
        uint8_t rec[300], v[64];
        size_t at = 0;
        uint32_t type = types[src_byte(&s) % (sizeof types / sizeof types[0])];
        if (src_byte(&s) & 1) {           /* raw bytes */
            at = src_byte(&s) % 200;
            for (size_t i = 0; i < at; i++) rec[i] = src_byte(&s);
        } else {                          /* well-formed fields with fuzzed values */
            unsigned nf = src_byte(&s) % 8;
            for (unsigned f = 0, t = 0; f < nf; f++) {
                size_t n = src_byte(&s) % sizeof v;
                t += 1 + src_byte(&s) % 4;
                for (size_t i = 0; i < n; i++) v[i] = src_byte(&s);
                if (gz_rec_put(rec, sizeof rec, &at, t, v, n) != GZ_OK) break;
            }
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
