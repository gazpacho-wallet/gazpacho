/* Wipes of secrets on the stack, and the paths taken when the crypto library
 * fails. Linked with -Wl,--wrap=OPENSSL_cleanse,--wrap=HMAC: every wipe in
 * the transport is recorded (size, in order), and HMAC can be made to fail
 * at a chosen call. Suggested by the PR 10 review (section 6).
 *
 * The expected wipes are read off the rules, not the run: an HKDF wipes its
 * PRK (32), T (33), and both outputs (32, 32); mixing a key wipes the ECDH
 * output (32) after its HKDF; finishing the handshake wipes ck, temp_k, e and
 * our static secret (4 x 32). */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "../check.h"
#include "hex.h"
#include "noise.h"

void __real_OPENSSL_cleanse(void *p, size_t n);
unsigned char *__real_HMAC(const EVP_MD *md, const void *key, int key_len, const unsigned char *d,
                           size_t n, unsigned char *out, unsigned int *out_len);

static size_t wipes[64], n_wipes;
static int hmac_calls, hmac_fail_at = -1;

void __wrap_OPENSSL_cleanse(void *p, size_t n)
{
    if (n_wipes < 64) wipes[n_wipes] = n;
    n_wipes++;
    __real_OPENSSL_cleanse(p, n);
}

unsigned char *__wrap_HMAC(const EVP_MD *md, const void *key, int key_len, const unsigned char *d,
                           size_t n, unsigned char *out, unsigned int *out_len)
{
    if (hmac_calls++ == hmac_fail_at) return NULL;
    return __real_HMAC(md, key, key_len, d, n, out, out_len);
}

static secp256k1_context *secp;
static uint8_t K11[32], K12[32], K21[32], K22[32], RS[33];

static void fill(void *ctx, uint8_t *out, size_t len) { memcpy(out, ctx, len); }

/* The sizes recorded since the last reset equal `want`, in order. */
static int wiped(const size_t *want, size_t n)
{
    size_t i;
    int ok = n_wipes == n;
    for (i = 0; ok && i < n; i++) ok = wipes[i] == want[i];
    if (!ok) {
        printf("wipes:");
        for (i = 0; i < n_wipes && i < 64; i++) printf(" %u", (unsigned)wipes[i]);
        printf("\n");
    }
    n_wipes = 0;
    return ok;
}

static const size_t HKDF[] = {32, 33, 32, 32};
static const size_t MIX[] = {32, 33, 32, 32, 32};
static const size_t ACT3[] = {32, 33, 32, 32, 32, 32, 33, 32, 32, 32, 32, 32, 32};

static void test_handshake_wipes(void)
{
    gz_random_port_t ri = {fill, K12}, rr = {fill, K22};
    gz_noise_t ini, res;
    uint8_t a[66], k1[32], k2[32];
    n_wipes = 0;
    CHECK(gz_noise_hkdf(K11, 32, K12, 32, k1, k2) && wiped(HKDF, 4));
    CHECK(gz_noise_init_initiator(&ini, secp, K11, RS, ri) == GZ_NOISE_OK && wiped(NULL, 0));
    CHECK(gz_noise_init_responder(&res, secp, K21, rr) == GZ_NOISE_OK && wiped(NULL, 0));
    CHECK(gz_noise_act1_write(&ini, a) == GZ_NOISE_OK && wiped(MIX, 5));
    CHECK(gz_noise_act1_read(&res, a, 50) == GZ_NOISE_OK && wiped(MIX, 5));
    CHECK(gz_noise_act2_write(&res, a) == GZ_NOISE_OK && wiped(MIX, 5));
    CHECK(gz_noise_act2_read(&ini, a, 50) == GZ_NOISE_OK && wiped(MIX, 5));
    CHECK(gz_noise_act3_write(&ini, a) == GZ_NOISE_OK && wiped(ACT3, 13));
    CHECK(gz_noise_act3_read(&res, a, 66) == GZ_NOISE_OK && wiped(ACT3, 13));
    /* A message and its successful decryption wipe nothing (nothing secret
     * is left on the stack by either). */
    {
        uint8_t m[64], out[8];
        size_t n, bl;
        CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"hi", 2, m, sizeof m, &n) == GZ_NOISE_OK);
        CHECK(gz_noise_decrypt_header(&res, m, 18, &bl) == GZ_NOISE_OK);
        CHECK(gz_noise_decrypt_body(&res, m + 18, 18, out, sizeof out) == GZ_NOISE_OK && wiped(NULL, 0));
    }
    gz_noise_wipe(&ini);
    gz_noise_wipe(&res);
    n_wipes = 0;
}

static int pair(gz_noise_t *ini, gz_noise_t *res, gz_noise_err_t *err)
{
    gz_random_port_t ri = {fill, K12}, rr = {fill, K22};
    uint8_t a[66];
    if ((*err = gz_noise_init_initiator(ini, secp, K11, RS, ri)) || (*err = gz_noise_init_responder(res, secp, K21, rr)) ||
        (*err = gz_noise_act1_write(ini, a)) || (*err = gz_noise_act1_read(res, a, 50)) ||
        (*err = gz_noise_act2_write(res, a)) || (*err = gz_noise_act2_read(ini, a, 50)) ||
        (*err = gz_noise_act3_write(ini, a)) || (*err = gz_noise_act3_read(res, a, 66)))
        return 0;
    return 1;
}

/* HMAC failing at each of its calls in a handshake: the handshake stops with
 * GZ_NOISE_ERR_CRYPTO and the state that failed is dead and wiped. */
static void test_crypto_failure_in_handshake(void)
{
    int k, total, stopped = 0;
    gz_noise_t ini, res;
    gz_noise_err_t e;
    hmac_calls = 0;
    hmac_fail_at = -1;
    CHECK(pair(&ini, &res, &e));
    total = hmac_calls;
    CHECK(total == 8 * 3); /* eight HKDFs (three mixes and the split, each side), three HMACs each */
    for (k = 0; k < total; k++) {
        hmac_calls = 0;
        hmac_fail_at = k;
        if (!pair(&ini, &res, &e) && e == GZ_NOISE_ERR_CRYPTO &&
            (ini.phase == GZ_NOISE_DEAD ? all_zero(&ini, sizeof ini) : all_zero(&res, sizeof res)))
            stopped++;
    }
    CHECK(stopped == total);
    hmac_fail_at = -1;
}

/* The rotation after a message whose MAC was good fails: the message's
 * plaintext must not be left in the caller's buffer. */
static uint8_t m[40];

static void test_failed_rotation_wipes_body(void)
{
    gz_noise_t ini, res;
    gz_noise_err_t e;
    uint8_t out[8];
    size_t n, bl;
    int i, ok = 0;
    hmac_fail_at = -1;
    CHECK(pair(&ini, &res, &e));
    for (i = 0; i < 499; i++)
        ok += gz_noise_encrypt(&ini, (const uint8_t *)"secret", 6, m, sizeof m, &n) == GZ_NOISE_OK &&
              gz_noise_decrypt_header(&res, m, 18, &bl) == GZ_NOISE_OK &&
              gz_noise_decrypt_body(&res, m + 18, 22, out, sizeof out) == GZ_NOISE_OK;
    CHECK(ok == 499 && res.rn == 998);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"secret", 6, m, sizeof m, &n) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_header(&res, m, 18, &bl) == GZ_NOISE_OK && res.rn == 999);
    memset(out, 0xaa, sizeof out);
    hmac_calls = 0;
    hmac_fail_at = 0; /* the next HMAC: the rotation's */
    CHECK(gz_noise_decrypt_body(&res, m + 18, 22, out, sizeof out) == GZ_NOISE_ERR_CRYPTO);
    CHECK(all_zero(out, 6) && out[6] == 0xaa && all_zero(&res, sizeof res));
    /* Likewise on the sending side: a failed rotation kills the state. */
    hmac_fail_at = -1;
    CHECK(pair(&ini, &res, &e));
    for (i = 0; i < 499; i++) gz_noise_encrypt(&ini, (const uint8_t *)"x", 1, m, sizeof m, &n);
    hmac_calls = 0;
    hmac_fail_at = 0;
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"x", 1, m, sizeof m, &n) == GZ_NOISE_ERR_CRYPTO && all_zero(&ini, sizeof ini));
    hmac_fail_at = -1;
}

int main(void)
{
    secp256k1_pubkey pk;
    size_t n = 33;
    memset(K11, 0x11, 32); memset(K12, 0x12, 32); memset(K21, 0x21, 32); memset(K22, 0x22, 32);
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    CHECK(secp256k1_ec_pubkey_create(secp, &pk, K21) && secp256k1_ec_pubkey_serialize(secp, RS, &n, &pk, SECP256K1_EC_COMPRESSED));
    test_handshake_wipes();
    test_crypto_failure_in_handshake();
    test_failed_rotation_wipes_body();
    secp256k1_context_destroy(secp);
    return check_done();
}
