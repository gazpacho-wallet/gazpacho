/* Fuzz target: the decrypting reader. libFuzzer entry point; fuzz_main.c is
 * a plain driver for machines without libFuzzer.
 *
 * First byte even: the rest is a hostile byte stream fed to a ready
 * responder, header then body, as conn.c does.
 * First byte odd: the rest is a message an honest initiator encrypts; two
 * bytes choose a byte to corrupt and how. Uncorrupted must decrypt to the
 * same bytes; corrupted must be refused. Either way the plaintext then goes
 * through the message and TLV readers. */
#include <stdlib.h>
#include <string.h>
#include "noise.h"
#include "frame.h"

static secp256k1_context *secp;
static gz_noise_t ini0, res0;
static uint8_t wire[GZ_NOISE_HDR_LEN + GZ_NOISE_MAX_MSG + GZ_NOISE_MAC_LEN], plain[GZ_NOISE_MAX_MSG];

static void fill(void *ctx, uint8_t *out, size_t len) { memset(out, *(const uint8_t *)ctx, len); }

static void setup(void)
{
    static const uint8_t e1 = 0x12, e2 = 0x22;
    gz_random_port_t r1 = {fill, (void *)&e1}, r2 = {fill, (void *)&e2};
    uint8_t k1[32], k2[32], pub[33], a[66];
    secp256k1_pubkey pk;
    size_t n = 33;
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    memset(k1, 0x11, 32);
    memset(k2, 0x21, 32);
    if (!secp256k1_ec_pubkey_create(secp, &pk, k2) || !secp256k1_ec_pubkey_serialize(secp, pub, &n, &pk, SECP256K1_EC_COMPRESSED) ||
        gz_noise_init_initiator(&ini0, secp, k1, pub, r1) || gz_noise_init_responder(&res0, secp, k2, r2) ||
        gz_noise_act1_write(&ini0, a) || gz_noise_act1_read(&res0, a, 50) || gz_noise_act2_write(&res0, a) ||
        gz_noise_act2_read(&ini0, a, 50) || gz_noise_act3_write(&ini0, a) || gz_noise_act3_read(&res0, a, 66))
        abort();
}

static int odd_ok(const gz_tlv_record_t *r, void *c) { (void)c; return r->len <= 8 && (r->len == 0 || r->value[0]); }

static void read_plain(const uint8_t *p, size_t n)
{
    static const gz_tlv_known_t known[] = {{1, odd_ok}, {2, NULL}, {3, odd_ok}};
    gz_tlv_record_t rec[8];
    const uint8_t *rest;
    size_t rl, nr;
    uint16_t type;
    if (gz_msg_parse(p, n, &type, &rest, &rl) == GZ_FRAME_OK)
        (void)gz_tlv_parse(rest, rl, known, 3, NULL, rec, 8, &nr);
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    gz_noise_t ini, res;
    size_t body, pos = 0, len;
    if (!secp) setup();
    if (n == 0) return 0;
    ini = ini0;
    res = res0;
    if ((d[0] & 1) == 0) {
        d++, n--;
        while (n - pos >= GZ_NOISE_HDR_LEN) {
            if (gz_noise_decrypt_header(&res, d + pos, GZ_NOISE_HDR_LEN, &body)) break;
            pos += GZ_NOISE_HDR_LEN;
            if (n - pos < body + GZ_NOISE_MAC_LEN) break;
            if (gz_noise_decrypt_body(&res, d + pos, body + GZ_NOISE_MAC_LEN, plain, sizeof plain)) break;
            pos += body + GZ_NOISE_MAC_LEN;
            read_plain(plain, body);
        }
    } else if (n >= 3) {
        size_t at = (size_t)(d[1] << 8 | d[2]);
        uint8_t flip = d[0] >> 1; /* 0 means no corruption */
        int ok;
        d += 3, n -= 3;
        if (n > GZ_NOISE_MAX_MSG) n = GZ_NOISE_MAX_MSG;
        if (gz_noise_encrypt(&ini, d, n, wire, sizeof wire, &len)) abort();
        if (flip) wire[at % len] ^= flip;
        ok = gz_noise_decrypt_header(&res, wire, GZ_NOISE_HDR_LEN, &body) == GZ_NOISE_OK && body == n &&
             gz_noise_decrypt_body(&res, wire + GZ_NOISE_HDR_LEN, len - GZ_NOISE_HDR_LEN, plain, sizeof plain) == GZ_NOISE_OK;
        if (ok != !flip) abort();                  /* corruption accepted, or honest message refused */
        if (ok && n && memcmp(plain, d, n)) abort(); /* decrypted to something else */
        if (ok) read_plain(plain, n);
    }
    gz_noise_wipe(&ini);
    gz_noise_wipe(&res);
    return 0;
}
