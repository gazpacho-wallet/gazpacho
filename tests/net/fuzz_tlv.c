/* Fuzz target: BigSize, the message reader and the TLV parser.
 *
 * Checks, besides "no crash, no out-of-bounds read":
 * - every BigSize the reader accepts re-encodes to exactly the bytes read;
 * - a stream the parser accepts with no unknown records is rebuilt byte for
 *   byte by the writer from the returned records, and parsing the rebuilt
 *   stream returns the same records. */
#include <stdlib.h>
#include <string.h>
#include "frame.h"

static int tu64_ok(const gz_tlv_record_t *r, void *c) { uint64_t v; (void)c; return gz_tu_read(r->value, r->len, 8, &v) == GZ_FRAME_OK; }
static int len8(const gz_tlv_record_t *r, void *c) { (void)c; return r->len == 8; }

static const gz_tlv_known_t KNOWN[] = {{0, tu64_ok}, {1, tu64_ok}, {2, len8}, {4, NULL}, {5, NULL}, {254, NULL}};
static uint8_t again[70000];

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    gz_tlv_record_t rec[16], rec2[16];
    size_t i, nr, nr2, used;
    uint64_t v;
    uint8_t enc[9];
    const uint8_t *rest;
    uint16_t type;
    gz_tlv_writer_t w;

    for (i = 0; i < n && i < 64; i++)
        if (gz_bigsize_read(d + i, n - i, &v, &used) == GZ_FRAME_OK)
            if (gz_bigsize_write(v, enc) != used || memcmp(enc, d + i, used)) abort();

    if (gz_msg_parse(d, n, &type, &rest, &nr) == GZ_FRAME_OK && (rest != d + 2 || nr != n - 2)) abort();

    if (gz_tlv_parse(d, n, KNOWN, 6, NULL, rec, 16, &nr) != GZ_FRAME_OK) return 0;
    gz_tlv_writer_init(&w, again, sizeof again);
    for (i = 0; i < nr; i++) {
        if (rec[i].value < d || rec[i].value + rec[i].len > d + n) abort();
        if (i && rec[i].type <= rec[i - 1].type) abort();
        if (gz_tlv_put(&w, rec[i].type, rec[i].value, rec[i].len)) abort();
    }
    if (gz_tlv_parse(again, w.len, KNOWN, 6, NULL, rec2, 16, &nr2) != GZ_FRAME_OK || nr2 != nr) abort();
    for (i = 0; i < nr; i++)
        if (rec2[i].type != rec[i].type || rec2[i].len != rec[i].len || memcmp(rec2[i].value, rec[i].value, rec[i].len)) abort();
    /* With no unknown records skipped, the rebuilt stream is the input. */
    if (w.len == n && memcmp(again, d, n)) abort();
    return 0;
}
