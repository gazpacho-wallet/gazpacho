/* BOLT 1's setup and control messages. See lnmsg.h. */
#include "lnmsg.h"

#include <string.h>

#include "frame.h"

/* Signet genesis 00000008819873e9...3bee1ef6, byte-reversed. */
const uint8_t GZ_LN_CHAIN_SIGNET[32] = {
    0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9,
    0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00};

/* testnet4 genesis 00000000da84f2ba...0da8bf043, byte-reversed. */
const uint8_t GZ_LN_CHAIN_TESTNET4[32] = {
    0x43, 0xf0, 0x8b, 0xda, 0xb0, 0x50, 0xe3, 0x5b, 0x56, 0x7c, 0x86, 0x4b, 0x91, 0xf4, 0x7f, 0x50,
    0xae, 0x72, 0x5a, 0xe2, 0xde, 0x53, 0xbc, 0xfb, 0xba, 0xf2, 0x84, 0xda, 0x00, 0x00, 0x00, 0x00};

/* mainnet genesis 000000000019d668...b60a8ce26f, byte-reversed. */
const uint8_t GZ_LN_CHAIN_MAINNET[32] = {
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00};

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

int gz_ln_init_write(const uint8_t chain[32], uint8_t *out, size_t out_cap, size_t *out_len)
{
    /* type, gflen 0, flen 0, TLV 1 (networks) of 32 bytes */
    if (out_cap < 2 + 2 + 2 + 2 + 32) return 1;
    put16(out, GZ_LN_INIT);
    put16(out + 2, 0);
    put16(out + 4, 0);
    out[6] = 1;
    out[7] = 32;
    memcpy(out + 8, chain, 32);
    *out_len = 40;
    return 0;
}

/* 1 if any even bit is set in a big-endian feature field. Bit 0 is the
 * least significant bit of the last byte. */
static int has_even_bit(const uint8_t *f, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (f[i] & 0x55) return 1;
    return 0;
}

static int check_networks(const gz_tlv_record_t *r, void *ctx)
{
    (void)ctx;
    return r->len % 32 == 0;
}

gz_ln_err_t gz_ln_init_check(const uint8_t *msg, size_t len, const uint8_t chain[32])
{
    static const gz_tlv_known_t known[] = {{1, check_networks}};
    const uint8_t *g, *f, *tlv;
    size_t gl, fl, at, n;
    gz_tlv_record_t rec[1];
    if (len < 4 || get16(msg) != GZ_LN_INIT) return GZ_LN_MALFORMED;
    gl = get16(msg + 2);
    if (len - 4 < gl + 2) return GZ_LN_MALFORMED;
    g = msg + 4;
    fl = get16(msg + 4 + gl);
    at = 6 + gl;
    if (len - at < fl) return GZ_LN_MALFORMED;
    f = msg + at;
    at += fl;
    /* BOLT 1: the union of both fields; an unknown even bit fails the
     * connection before the rest is parsed. */
    if (has_even_bit(g, gl) || has_even_bit(f, fl)) return GZ_LN_REQUIRED_FEATURE;
    tlv = msg + at;
    /* remote_addr (3) is odd and unused: skipped like any unknown odd record. */
    if (gz_tlv_parse(tlv, len - at, known, 1, NULL, rec, 1, &n) != GZ_FRAME_OK) return GZ_LN_MALFORMED;
    if (n != 1 || rec[0].len != 32 || memcmp(rec[0].value, chain, 32) != 0) return GZ_LN_NETWORK;
    return GZ_LN_OK;
}

int gz_ln_ping_write(uint16_t num_pong_bytes, uint16_t byteslen, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if ((size_t)byteslen + 6 > out_cap || (size_t)byteslen + 6 > GZ_MSG_MAX) return 1;
    put16(out, GZ_LN_PING);
    put16(out + 2, num_pong_bytes);
    put16(out + 4, byteslen);
    memset(out + 6, 0, byteslen);
    *out_len = (size_t)byteslen + 6;
    return 0;
}

gz_ln_err_t gz_ln_ping_read(const uint8_t *msg, size_t len, uint16_t *num_pong_bytes)
{
    if (len < 6 || get16(msg) != GZ_LN_PING) return GZ_LN_MALFORMED;
    if (len - 6 < get16(msg + 4)) return GZ_LN_MALFORMED;
    *num_pong_bytes = get16(msg + 2);
    return GZ_LN_OK;
}

int gz_ln_pong_write(uint16_t byteslen, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if ((size_t)byteslen + 4 > out_cap) return 1;
    put16(out, GZ_LN_PONG);
    put16(out + 2, byteslen);
    memset(out + 4, 0, byteslen);
    *out_len = (size_t)byteslen + 4;
    return 0;
}

gz_ln_err_t gz_ln_pong_read(const uint8_t *msg, size_t len, uint16_t *byteslen)
{
    if (len < 4 || get16(msg) != GZ_LN_PONG) return GZ_LN_MALFORMED;
    if (len - 4 < get16(msg + 2)) return GZ_LN_MALFORMED;
    *byteslen = get16(msg + 2);
    return GZ_LN_OK;
}

int gz_ln_alert_write(uint16_t type, const char *text, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t n = strlen(text);
    if ((type != GZ_LN_WARNING && type != GZ_LN_ERROR) || n > 1024 || out_cap < 36 + n) return 1;
    put16(out, type);
    memset(out + 2, 0, 32);
    put16(out + 34, (uint16_t)n);
    memcpy(out + 36, text, n);
    *out_len = 36 + n;
    return 0;
}

gz_ln_err_t gz_ln_alert_read(const uint8_t *msg, size_t len, char *text, size_t cap)
{
    size_t n, i;
    uint16_t t;
    if (cap) text[0] = 0;
    if (len < 36) return GZ_LN_MALFORMED;
    t = get16(msg);
    if (t != GZ_LN_WARNING && t != GZ_LN_ERROR) return GZ_LN_MALFORMED;
    n = get16(msg + 34);
    if (len - 36 < n) return GZ_LN_MALFORMED;
    if (!cap) return GZ_LN_OK;
    if (n > cap - 1) n = cap - 1;
    for (i = 0; i < n; i++) text[i] = (msg[36 + i] >= 0x20 && msg[36 + i] <= 0x7e) ? (char)msg[36 + i] : '?';
    text[n] = 0;
    return GZ_LN_OK;
}
