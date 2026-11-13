/* Fuzz target for the factory envelope reader, the reassembly of parts and
 * BOLT 1's init, ping, pong and alert readers (messages.md test 1: every
 * decoder is fuzzed).
 *
 * The first byte chooses the mode and the receiving side:
 *   mode 0: a run of whole messages, each a 2-byte length then its payload
 *           after type 52791, read and, if a part, reassembled;
 *   mode 1: parts made from 10-byte descriptions, so that transfers of
 *           65,000-byte parts are reached from short inputs, and complete
 *           with a right or a wrong transfer_id;
 *   mode 2: the rest as one message for each BOLT 1 reader. */
#include <stdlib.h>
#include <string.h>
#include <secp256k1.h>
#include "envelope.h"
#include "lnmsg.h"
#include "frame.h"

static secp256k1_context *secp;
static uint8_t msg[65535], body[200000];
static const uint8_t SCOPE_A[32] = {1}, SCOPE_B[32] = {2};

static void use(const gz_env_msg_t *m)
{
    gz_env_record_t rec[16];
    uint8_t h[32];
    int n = gz_env_records(m->records, m->records_len, rec, 16);
    if (n < 0) abort(); /* a delivered message is well formed */
    (void)gz_env_find(rec, n, 240);
    (void)gz_env_msg_hash(secp, m, h);
}

static void feed(gz_env_reasm_t *r, const uint8_t *wire, size_t len, gz_env_side_t at)
{
    gz_env_msg_t m, whole;
    gz_env_verdict_t v = gz_env_read(wire, len, at, &m, NULL);
    if (v != GZ_ENV_DELIVER) return;
    use(&m);
    if (m.kind != GZ_ENV_KIND_PART) return;
    v = gz_env_reasm_add(r, &m, at, secp, &whole, NULL);
    if (v == GZ_ENV_DELIVER) {
        if (whole.records_len > GZ_ENV_MAX_WHOLE || r->allocated > GZ_ENV_MAX_WHOLE) abort();
        use(&whole);
    }
}

static void mode_messages(gz_env_reasm_t *r, const uint8_t *d, size_t n, gz_env_side_t at)
{
    while (n >= 2) {
        size_t len = (size_t)(d[0] << 8 | d[1]) % (n - 1);
        d += 2;
        n -= 2;
        msg[0] = 0xce;
        msg[1] = 0x37;
        memcpy(msg + 2, d, len);
        feed(r, msg, len + 2, at);
        d += len;
        n -= len;
    }
}

static void mode_parts(gz_env_reasm_t *r, const uint8_t *d, size_t n, gz_env_side_t at)
{
    int parts = 0;
    while (n >= 10 && parts++ < 6) {
        uint16_t inner = (uint16_t)(d[0] % 4 == 0 ? 2 : d[0] % 4 == 1 ? 68 : (d[0] << 8 | d[1]));
        uint32_t total = 65000u + (uint32_t)(d[2] << 8 | d[3]) * 2u; /* 2 to 3 parts */
        uint16_t count = (uint16_t)((total + 64999) / 65000), index;
        size_t off, dlen;
        uint8_t fill = d[6], tid[32], k[2], t[4], ix[2], cn[2], *rec = msg + 40;
        gz_tlv_writer_t w;
        size_t i, out;
        if (d[4] & 1) count = (uint16_t)(d[4] >> 1); /* sometimes inconsistent */
        index = (uint16_t)(d[5] % (count + 2));
        off = (size_t)index * 65000;
        dlen = off < total ? (total - off < 65000 ? total - off : 65000) : 1;
        if (d[7] & 1) dlen += (d[7] >> 1) % 3 - 1; /* one off either way, or not */
        if (dlen == 0 || dlen > 65000) dlen = 1;
        for (i = 0; i < total && i < sizeof body; i++) body[i] = (uint8_t)(fill + i / 65000);
        memset(tid, d[8], 32);
        if (d[9] & 1) {
            gz_env_transfer_id(secp, inner, body, total, tid);
        }
        k[0] = (uint8_t)(inner >> 8);
        k[1] = (uint8_t)inner;
        t[0] = (uint8_t)(total >> 24); t[1] = (uint8_t)(total >> 16); t[2] = (uint8_t)(total >> 8); t[3] = (uint8_t)total;
        ix[0] = (uint8_t)(index >> 8);
        ix[1] = (uint8_t)index;
        cn[0] = (uint8_t)(count >> 8);
        cn[1] = (uint8_t)count;
        gz_tlv_writer_init(&w, rec, sizeof msg - 40);
        gz_tlv_put(&w, 2, tid, 32);
        gz_tlv_put(&w, 4, k, 2);
        gz_tlv_put(&w, 6, t, 4);
        gz_tlv_put(&w, 8, ix, 2);
        gz_tlv_put(&w, 10, cn, 2);
        gz_tlv_put(&w, 12, off < total ? body + off : body, dlen);
        if (!w.err && !gz_env_write(GZ_ENV_KIND_PART, d[9] & 2 ? SCOPE_B : SCOPE_A, rec, w.len, msg, sizeof msg, &out))
            feed(r, msg, out, at);
        d += 10;
        n -= 10;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    gz_env_reasm_t r;
    gz_env_side_t at;
    uint16_t v;
    char text[64];
    if (!secp) secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (n < 1) return 0;
    at = d[0] & 4 ? GZ_ENV_AT_HOST : GZ_ENV_AT_MEMBER;
    gz_env_reasm_init(&r);
    switch (d[0] % 3) {
    case 0:
        mode_messages(&r, d + 1, n - 1, at);
        break;
    case 1:
        mode_parts(&r, d + 1, n - 1, at);
        break;
    default:
        (void)gz_ln_init_check(d + 1, n - 1, GZ_LN_CHAIN_SIGNET);
        (void)gz_ln_ping_read(d + 1, n - 1, &v);
        (void)gz_ln_pong_read(d + 1, n - 1, &v);
        (void)gz_ln_alert_read(d + 1, n - 1, text, sizeof text);
        if (n - 1 <= sizeof msg) {
            size_t out;
            memcpy(msg, d + 1, n - 1);
            (void)gz_env_blip56_unwrap(msg, n - 1, body, sizeof body, &out);
        }
        break;
    }
    gz_env_reasm_reset(&r);
    return 0;
}
