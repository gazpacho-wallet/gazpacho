/* Wipes of secrets on the stack, and the paths taken when the crypto library
 * fails. Linked with -Wl,--wrap=gz_net_wipe,--wrap=HMAC: every wipe in
 * the transport is recorded (size, in order; through gz_net_wipe, so a
 * static libcrypto's own wipes are not counted), and HMAC can be made to fail
 * at a chosen call. Suggested by the PR 10 review (section 6).
 *
 * The expected wipes are read off the rules, not the run: an HKDF wipes its
 * PRK (32), T (33), and both outputs (32, 32); mixing a key wipes the ECDH
 * output (32) after its HKDF; finishing the handshake wipes ck, temp_k, e and
 * our static secret (4 x 32).
 *
 * Which buffer each wipe clears is checked too (review of PR 10, round 2,
 * N1): the wrapper keeps the first 33 bytes of every wiped buffer, and they
 * are compared with values known in advance. The test keys are BOLT 8's, so
 * every ECDH output, chaining key and temporary key is a published vector;
 * each HKDF's PRK is one HMAC of those, computed here. */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "../check.h"
#include "hex.h"
#include "noise.h"

void __real_gz_net_wipe(void *p, size_t n);
unsigned char *__real_HMAC(const EVP_MD *md, const void *key, int key_len, const unsigned char *d,
                           size_t n, unsigned char *out, unsigned int *out_len);

static size_t wipes[64], n_wipes;
static uint8_t seen[64][33];
static int hmac_calls, hmac_fail_at = -1;

void __wrap_gz_net_wipe(void *p, size_t n)
{
    if (n_wipes < 64) {
        wipes[n_wipes] = n;
        memcpy(seen[n_wipes], p, n < 33 ? n : 33);
    }
    n_wipes++;
    __real_gz_net_wipe(p, n);
}

unsigned char *__wrap_HMAC(const EVP_MD *md, const void *key, int key_len, const unsigned char *d,
                           size_t n, unsigned char *out, unsigned int *out_len)
{
    if (hmac_calls++ == hmac_fail_at) return NULL;
    return __real_HMAC(md, key, key_len, d, n, out, out_len);
}

static secp256k1_context *secp;
static uint8_t K11[32], K12[32], K21[32], K22[32], RS[33];

static void fill(void *ctx, uint32_t purpose, uint8_t *out, size_t len) { (void)purpose; memcpy(out, ctx, len); }

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

/* The wipes of one HKDF starting at seen[at]: PRK, T (o1 || 0x02), o1, o2;
 * then, when ss is given, the ECDH output that was the input. */
static int hkdf_wiped(size_t at, const char *salt_hex, const char *ikm_hex, const char *o1_hex,
                      const char *o2_hex, int with_ss)
{
    uint8_t salt[32], ikm[32], prk[32], t[33], one = 0;
    unsigned int len = 0;
    size_t ikm_len = unhex(ikm_hex, ikm, sizeof ikm);
    int ok;
    unhex(salt_hex, salt, 32);
    ok = __real_HMAC(EVP_sha256(), salt, 32, ikm_len ? ikm : &one, ikm_len, prk, &len) && len == 32;
    unhex(o1_hex, t, 32);
    t[32] = 2;
    ok = ok && n_wipes >= at + 4 + (size_t)with_ss && memcmp(seen[at], prk, 32) == 0 &&
         memcmp(seen[at + 1], t, 33) == 0 && eqhex(seen[at + 2], 32, o1_hex) && eqhex(seen[at + 3], 32, o2_hex);
    if (with_ss) ok = ok && eqhex(seen[at + 4], 32, ikm_hex);
    if (!ok) printf("wrong buffer wiped in the HKDF at wipe %u\n", (unsigned)at);
    return ok;
}

#define CK0 "2640f52eebcd9e882958951c794250eedb28002c05d7dc2ea0f195406042caf1"
#define SS1 "1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3"
#define CK1 "b61ec1191326fa240decc9564369dbb3ae2b34341d1e11ad64ed89f89180582f"
#define TK1 "e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f"
#define SS2 "c06363d6cc549bcb7913dbb9ac1c33fc1158680c89e972000ecd06b36c472e47"
#define CK2 "e89d31033a1b6bf68c07d22e08ea4d7884646c4b60a9528598ccb4ee2c8f56ba"
#define TK2 "908b166535c01a935cf1e130a5fe895ab4e6f3ef8855d87e9b7581c4ab663ddc"
#define SS3 "b36b6d195982c5be874d6d542dc268234379e1ae4ff1709402135b7de5cf0766"
#define CK3 "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01"
#define TK3 "981a46c820fb7a241bc8184ba4bb1f01bcdfafb00dde80098cb8c38db9141520"
#define SK "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"
#define RK "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"

/* Act three: the mix, the split, then ck, temp_k, e and our static secret. */
static int act3_wiped(const char *e_hex, const char *ls_hex)
{
    int ok = hkdf_wiped(0, CK2, SS3, CK3, TK3, 1) && hkdf_wiped(5, CK3, "", SK, RK, 0) &&
             eqhex(seen[9], 32, CK3) && eqhex(seen[10], 32, TK3) && eqhex(seen[11], 32, e_hex) &&
             eqhex(seen[12], 32, ls_hex);
    if (!ok) printf("wrong buffer wiped at the end of the handshake\n");
    return ok;
}

#define E_I "1212121212121212121212121212121212121212121212121212121212121212"
#define LS_I "1111111111111111111111111111111111111111111111111111111111111111"
#define E_R "2222222222222222222222222222222222222222222222222222222222222222"
#define LS_R "2121212121212121212121212121212121212121212121212121212121212121"

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
    CHECK(gz_noise_act1_write(&ini, a) == GZ_NOISE_OK && hkdf_wiped(0, CK0, SS1, CK1, TK1, 1) && wiped(MIX, 5));
    CHECK(gz_noise_act1_read(&res, a, 50) == GZ_NOISE_OK && hkdf_wiped(0, CK0, SS1, CK1, TK1, 1) && wiped(MIX, 5));
    CHECK(gz_noise_act2_write(&res, a) == GZ_NOISE_OK && hkdf_wiped(0, CK1, SS2, CK2, TK2, 1) && wiped(MIX, 5));
    CHECK(gz_noise_act2_read(&ini, a, 50) == GZ_NOISE_OK && hkdf_wiped(0, CK1, SS2, CK2, TK2, 1) && wiped(MIX, 5));
    CHECK(gz_noise_act3_write(&ini, a) == GZ_NOISE_OK && act3_wiped(E_I, LS_I) && wiped(ACT3, 13));
    CHECK(gz_noise_act3_read(&res, a, 66) == GZ_NOISE_OK && act3_wiped(E_R, LS_R) && wiped(ACT3, 13));
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
