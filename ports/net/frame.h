/* BOLT 1 message framing, BigSize, truncated integers and TLV streams.
 *
 * No input or output and no allocation. Every reader takes a pointer and a
 * length and never reads past them. See spec/transport.md, rules 11 and 12. */
#ifndef GAZPACHO_NET_FRAME_H
#define GAZPACHO_NET_FRAME_H

#include <stddef.h>
#include <stdint.h>

#define GZ_MSG_MAX 65535 /* type included */

typedef enum {
    GZ_FRAME_OK = 0,
    GZ_FRAME_EOF,          /* nothing left where a value was expected to start */
    GZ_FRAME_TRUNCATED,    /* a value or record runs past the end */
    GZ_FRAME_NONCANONICAL, /* BigSize or truncated integer not minimally encoded */
    GZ_FRAME_ORDER,        /* TLV types not strictly increasing */
    GZ_FRAME_UNKNOWN_EVEN, /* unknown even TLV type or message type */
    GZ_FRAME_INVALID,      /* a known record's checker refused it */
    GZ_FRAME_TOO_BIG,      /* over 65,535 bytes, or output buffer full */
    GZ_FRAME_TOO_MANY      /* more known records than the output array holds */
} gz_frame_err_t;

/* BigSize. Reads one value from p[0..len); *used gets its size. */
gz_frame_err_t gz_bigsize_read(const uint8_t *p, size_t len, uint64_t *val, size_t *used);
/* Writes the minimal encoding of v; returns its size (1, 3, 5 or 9). */
size_t gz_bigsize_write(uint64_t v, uint8_t out[9]);

/* Truncated unsigned integers (tu16, tu32, tu64): big-endian, no leading zero
 * byte, at most max_bytes long. */
gz_frame_err_t gz_tu_read(const uint8_t *p, size_t len, size_t max_bytes, uint64_t *val);
size_t gz_tu_write(uint64_t v, uint8_t out[8]); /* returns 0 to 8 */

/* A message: 2-byte big-endian type, then the rest. */
gz_frame_err_t gz_msg_parse(const uint8_t *msg, size_t len, uint16_t *type,
                            const uint8_t **rest, size_t *rest_len);
gz_frame_err_t gz_msg_write(uint16_t type, const uint8_t *rest, size_t rest_len,
                            uint8_t *out, size_t out_cap, size_t *out_len);

/* What to do with a message whose type the program does not know. */
typedef enum { GZ_MSG_IGNORE, GZ_MSG_CLOSE } gz_msg_unknown_t;
gz_msg_unknown_t gz_msg_unknown_action(uint16_t type);

/* TLV reader. The caller lists the types it knows, each with an optional
 * checker (NULL accepts any value). Known records are returned in stream
 * order; unknown odd records are skipped; anything else fails the stream. */
typedef struct {
    uint64_t type;
    const uint8_t *value; /* points into the stream */
    size_t len;
} gz_tlv_record_t;

typedef int (*gz_tlv_check_fn)(const gz_tlv_record_t *rec, void *ctx); /* 1 = valid */

typedef struct {
    uint64_t type;
    gz_tlv_check_fn check;
} gz_tlv_known_t;

gz_frame_err_t gz_tlv_parse(const uint8_t *s, size_t len,
                            const gz_tlv_known_t *known, size_t n_known, void *ctx,
                            gz_tlv_record_t *out, size_t out_cap, size_t *n_out);

/* TLV writer into a caller's buffer. Types must strictly increase. The first
 * error sticks: later puts do nothing and return it. */
typedef struct {
    uint8_t *buf;
    size_t cap, len;
    uint64_t last_type;
    int started;
    gz_frame_err_t err;
} gz_tlv_writer_t;

void gz_tlv_writer_init(gz_tlv_writer_t *w, uint8_t *buf, size_t cap);
gz_frame_err_t gz_tlv_put(gz_tlv_writer_t *w, uint64_t type, const uint8_t *value, size_t len);

const char *gz_frame_err_name(gz_frame_err_t e);

#endif
