/* BOLT 8 state machine. See noise.h and spec/transport.md. */
#include "noise.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <secp256k1_ecdh.h>
#include "wipe.h"

static const char PROTOCOL_NAME[] = "Noise_XK_secp256k1_ChaChaPoly_SHA256";
static const char PROLOGUE[] = "lightning";
#define EPHEMERAL_TRIES 8

static void wipe(void *p, size_t n) { gz_net_wipe(p, n); }

static gz_noise_err_t fail(gz_noise_t *st, gz_noise_err_t e)
{
    gz_noise_wipe(st);
    return e;
}

/* out = SHA-256(a || b) */
static int sha256_2(uint8_t out[32], const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    int ok = 0;
    unsigned int n = 0;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(md, a, alen) == 1 && (blen == 0 || EVP_DigestUpdate(md, b, blen) == 1) &&
        EVP_DigestFinal_ex(md, out, &n) == 1 && n == 32)
        ok = 1;
    EVP_MD_CTX_free(md);
    return ok;
}

static int mix_hash(gz_noise_t *st, const uint8_t *data, size_t len)
{
    uint8_t h[32];
    int ok = sha256_2(h, st->h, 32, data, len);
    memcpy(st->h, h, 32);
    return ok;
}

static int hmac256(uint8_t out[32], const uint8_t *key, size_t klen, const uint8_t *d, size_t dlen)
{
    static const uint8_t empty[1] = {0};
    unsigned int n = 0;
    if (!HMAC(EVP_sha256(), key, (int)klen, dlen ? d : empty, dlen, out, &n)) return 0;
    return n == 32;
}

/* RFC 5869 with empty info and 64 bytes of output, split in two. */
int gz_noise_hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                  uint8_t out1[32], uint8_t out2[32])
{
    uint8_t prk[32], t[33], o1[32], o2[32];
    int ok = hmac256(prk, salt, salt_len, ikm, ikm_len);
    t[0] = 1;
    ok = ok && hmac256(o1, prk, 32, t, 1);
    memcpy(t, o1, 32);
    t[32] = 2;
    ok = ok && hmac256(o2, prk, 32, t, 33);
    if (ok) {
        memcpy(out1, o1, 32);
        memcpy(out2, o2, 32);
    }
    wipe(prk, sizeof prk);
    wipe(t, sizeof t);
    wipe(o1, sizeof o1);
    wipe(o2, sizeof o2);
    return ok;
}

/* ChaCha20-Poly1305 (RFC 8439), nonce = 4 zero bytes || little-endian n.
 * Encrypt: out gets len bytes then the 16-byte tag. Decrypt: `in` holds len
 * bytes then the tag; out gets len bytes, wiped if the tag is wrong. */
static int aead(int enc, const uint8_t key[32], uint64_t n, const uint8_t *ad, size_t adlen,
                const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t nonce[12] = {0}, tag[16], dummy[1];
    int ok = 0, outl = 0, i;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    for (i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(n >> (8 * i));
    if (!c) return 0;
    if (EVP_CipherInit_ex(c, EVP_chacha20_poly1305(), NULL, NULL, NULL, enc) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_CipherInit_ex(c, NULL, NULL, key, nonce, enc) != 1) goto done;
    if (adlen && EVP_CipherUpdate(c, NULL, &outl, ad, (int)adlen) != 1) goto done;
    if (len && EVP_CipherUpdate(c, out, &outl, in, (int)len) != 1) goto done;
    if (!enc) {
        memcpy(tag, in + len, 16);
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1) goto done;
    }
    if (EVP_CipherFinal_ex(c, dummy, &outl) != 1) goto done;
    if (enc && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, out + len) != 1) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(c);
    if (!ok && !enc && len) wipe(out, len);
    return ok;
}

/* Given 33 bytes, libsecp256k1 accepts only the compressed form (02 or 03). */
static int parse_pub(const gz_noise_t *st, secp256k1_pubkey *pk, const uint8_t in[33])
{
    return secp256k1_ec_pubkey_parse(st->secp, pk, in, 33);
}

static int pub_of(const gz_noise_t *st, uint8_t out[33], const uint8_t priv[32])
{
    secp256k1_pubkey pk;
    size_t n = 33;
    if (!secp256k1_ec_seckey_verify(st->secp, priv)) return 0;
    if (!secp256k1_ec_pubkey_create(st->secp, &pk, priv)) return 0;
    return secp256k1_ec_pubkey_serialize(st->secp, out, &n, &pk, SECP256K1_EC_COMPRESSED) && n == 33;
}

/* ss = SHA-256(compressed(priv * pub)): libsecp256k1's default ECDH hash. */
static gz_noise_err_t ecdh(const gz_noise_t *st, uint8_t ss[32], const uint8_t priv[32],
                           const uint8_t pub[33])
{
    secp256k1_pubkey pk;
    if (!parse_pub(st, &pk, pub)) return GZ_NOISE_ERR_PUBKEY;
    if (!secp256k1_ecdh(st->secp, ss, &pk, priv, NULL, NULL)) return GZ_NOISE_ERR_CRYPTO;
    return GZ_NOISE_OK;
}

/* ck, temp_k = HKDF(ck, ss), then ss is wiped. */
static int mix_key(gz_noise_t *st, uint8_t ss[32])
{
    int ok = gz_noise_hkdf(st->ck, 32, ss, 32, st->ck, st->temp_k);
    wipe(ss, 32);
    return ok;
}

static gz_noise_err_t make_ephemeral(gz_noise_t *st)
{
    int i;
    for (i = 0; i < EPHEMERAL_TRIES; i++) {
        st->random.fill(st->random.ctx, st->e_priv, 32);   /* never saved */
        if (pub_of(st, st->e_pub, st->e_priv)) return GZ_NOISE_OK;
    }
    return GZ_NOISE_ERR_RANDOM;
}

static gz_noise_err_t init_common(gz_noise_t *st, const secp256k1_context *secp,
                                  const uint8_t ls_priv[32], gz_net_random_t random)
{
    memset(st, 0, sizeof *st);
    st->secp = secp;
    st->random = random;
    memcpy(st->ls_priv, ls_priv, 32);
    if (!pub_of(st, st->ls_pub, st->ls_priv)) return fail(st, GZ_NOISE_ERR_KEY);
    if (!sha256_2(st->h, (const uint8_t *)PROTOCOL_NAME, strlen(PROTOCOL_NAME), NULL, 0))
        return fail(st, GZ_NOISE_ERR_CRYPTO);
    memcpy(st->ck, st->h, 32);
    if (!mix_hash(st, (const uint8_t *)PROLOGUE, strlen(PROLOGUE))) return fail(st, GZ_NOISE_ERR_CRYPTO);
    return GZ_NOISE_OK;
}

gz_noise_err_t gz_noise_init_initiator(gz_noise_t *st, const secp256k1_context *secp,
                                       const uint8_t ls_priv[32], const uint8_t rs[33],
                                       gz_net_random_t random)
{
    secp256k1_pubkey pk;
    gz_noise_err_t e = init_common(st, secp, ls_priv, random);
    if (e) return e;
    if (!parse_pub(st, &pk, rs)) return fail(st, GZ_NOISE_ERR_PUBKEY);
    memcpy(st->rs, rs, 33);
    if (!mix_hash(st, rs, 33)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    st->phase = GZ_NOISE_I_START;
    return GZ_NOISE_OK;
}

gz_noise_err_t gz_noise_init_responder(gz_noise_t *st, const secp256k1_context *secp,
                                       const uint8_t ls_priv[32], gz_net_random_t random)
{
    gz_noise_err_t e = init_common(st, secp, ls_priv, random);
    if (e) return e;
    if (!mix_hash(st, st->ls_pub, 33)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    st->phase = GZ_NOISE_R_START;
    return GZ_NOISE_OK;
}

/* Acts one and two have the same shape: 0 || e.pub || tag. The writer combines
 * its new ephemeral with `remote` (act one: rs; act two: re); the reader
 * combines the received ephemeral with `priv` (act one: ls; act two: e). */
static gz_noise_err_t act_ephemeral_write(gz_noise_t *st, uint8_t out[50], const uint8_t remote[33])
{
    uint8_t ss[32];
    gz_noise_err_t e = make_ephemeral(st);
    if (e) return fail(st, e);
    if (!mix_hash(st, st->e_pub, 33)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    e = ecdh(st, ss, st->e_priv, remote);
    if (e) return fail(st, e);
    if (!mix_key(st, ss)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    out[0] = 0;
    memcpy(out + 1, st->e_pub, 33);
    if (!aead(1, st->temp_k, 0, st->h, 32, NULL, 0, out + 34)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    if (!mix_hash(st, out + 34, 16)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    return GZ_NOISE_OK;
}

static gz_noise_err_t act_ephemeral_read(gz_noise_t *st, const uint8_t *in, size_t len,
                                         const uint8_t priv[32])
{
    uint8_t ss[32];
    gz_noise_err_t e;
    if (len != 50) return fail(st, GZ_NOISE_ERR_LENGTH);
    if (in[0] != 0) return fail(st, GZ_NOISE_ERR_VERSION);
    memcpy(st->re, in + 1, 33);
    if (!mix_hash(st, st->re, 33)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    e = ecdh(st, ss, priv, st->re); /* refuses an invalid key */
    if (e) return fail(st, e);
    if (!mix_key(st, ss)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    if (!aead(0, st->temp_k, 0, st->h, 32, in + 34, 0, NULL)) return fail(st, GZ_NOISE_ERR_MAC);
    if (!mix_hash(st, in + 34, 16)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    return GZ_NOISE_OK;
}

/* The handshake is over: keep the session keys and our public key, wipe the rest. */
static void finish(gz_noise_t *st)
{
    memcpy(st->sck, st->ck, 32);
    memcpy(st->rck, st->ck, 32);
    wipe(st->ck, 32);
    wipe(st->temp_k, 32);
    wipe(st->e_priv, 32);
    wipe(st->ls_priv, 32);
    st->sn = st->rn = 0;
    st->phase = GZ_NOISE_READY;
}

gz_noise_err_t gz_noise_act1_write(gz_noise_t *st, uint8_t out[GZ_NOISE_ACT1_LEN])
{
    gz_noise_err_t e;
    if (st->phase != GZ_NOISE_I_START) return fail(st, GZ_NOISE_ERR_STATE);
    e = act_ephemeral_write(st, out, st->rs);
    if (!e) st->phase = GZ_NOISE_I_SENT1;
    return e;
}

gz_noise_err_t gz_noise_act1_read(gz_noise_t *st, const uint8_t *in, size_t len)
{
    gz_noise_err_t e;
    if (st->phase != GZ_NOISE_R_START) return fail(st, GZ_NOISE_ERR_STATE);
    e = act_ephemeral_read(st, in, len, st->ls_priv);
    if (!e) st->phase = GZ_NOISE_R_GOT1;
    return e;
}

gz_noise_err_t gz_noise_act2_write(gz_noise_t *st, uint8_t out[GZ_NOISE_ACT2_LEN])
{
    gz_noise_err_t e;
    if (st->phase != GZ_NOISE_R_GOT1) return fail(st, GZ_NOISE_ERR_STATE);
    e = act_ephemeral_write(st, out, st->re);
    if (!e) st->phase = GZ_NOISE_R_SENT2;
    return e;
}

gz_noise_err_t gz_noise_act2_read(gz_noise_t *st, const uint8_t *in, size_t len)
{
    gz_noise_err_t e;
    if (st->phase != GZ_NOISE_I_SENT1) return fail(st, GZ_NOISE_ERR_STATE);
    e = act_ephemeral_read(st, in, len, st->e_priv);
    if (!e) st->phase = GZ_NOISE_I_GOT2;
    return e;
}

gz_noise_err_t gz_noise_act3_write(gz_noise_t *st, uint8_t out[GZ_NOISE_ACT3_LEN])
{
    uint8_t ss[32];
    gz_noise_err_t e;
    if (st->phase != GZ_NOISE_I_GOT2) return fail(st, GZ_NOISE_ERR_STATE);
    out[0] = 0;
    if (!aead(1, st->temp_k, 1, st->h, 32, st->ls_pub, 33, out + 1)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    if (!mix_hash(st, out + 1, 49)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    e = ecdh(st, ss, st->ls_priv, st->re);
    if (e) return fail(st, e);
    if (!mix_key(st, ss)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    if (!aead(1, st->temp_k, 0, st->h, 32, NULL, 0, out + 50)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    if (!gz_noise_hkdf(st->ck, 32, NULL, 0, st->sk, st->rk)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    finish(st);
    return GZ_NOISE_OK;
}

gz_noise_err_t gz_noise_act3_read(gz_noise_t *st, const uint8_t *in, size_t len)
{
    uint8_t ss[32];
    gz_noise_err_t e;
    if (st->phase != GZ_NOISE_R_SENT2) return fail(st, GZ_NOISE_ERR_STATE);
    if (len != 66) return fail(st, GZ_NOISE_ERR_LENGTH);
    if (in[0] != 0) return fail(st, GZ_NOISE_ERR_VERSION);
    if (!aead(0, st->temp_k, 1, st->h, 32, in + 1, 33, st->rs)) return fail(st, GZ_NOISE_ERR_MAC);
    if (!mix_hash(st, in + 1, 49)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    e = ecdh(st, ss, st->e_priv, st->rs); /* refuses an invalid rs */
    if (e) return fail(st, e);
    if (!mix_key(st, ss)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    if (!aead(0, st->temp_k, 0, st->h, 32, in + 50, 0, NULL)) return fail(st, GZ_NOISE_ERR_MAC);
    if (!gz_noise_hkdf(st->ck, 32, NULL, 0, st->rk, st->sk)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    finish(st);
    return GZ_NOISE_OK;
}

gz_noise_err_t gz_noise_remote_static(const gz_noise_t *st, uint8_t out[33])
{
    if (st->phase != GZ_NOISE_READY && st->phase != GZ_NOISE_READY_BODY) return GZ_NOISE_ERR_STATE;
    memcpy(out, st->rs, 33);
    return GZ_NOISE_OK;
}

/* After each use of a key: count it, and rotate at 1000. */
static int step(uint64_t *n, uint8_t ck[32], uint8_t k[32])
{
    if (++*n < GZ_NOISE_ROTATE_AT) return 1;
    *n = 0;
    return gz_noise_hkdf(ck, 32, k, 32, ck, k);
}

static int ready(const gz_noise_t *st)
{
    return st->phase == GZ_NOISE_READY || st->phase == GZ_NOISE_READY_BODY;
}

gz_noise_err_t gz_noise_encrypt(gz_noise_t *st, const uint8_t *msg, size_t len,
                                uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t l[2];
    if (!ready(st)) return fail(st, GZ_NOISE_ERR_STATE);
    if (len > GZ_NOISE_MAX_MSG || out_cap < GZ_NOISE_HDR_LEN + len + GZ_NOISE_MAC_LEN)
        return fail(st, GZ_NOISE_ERR_TOO_BIG);
    l[0] = (uint8_t)(len >> 8);
    l[1] = (uint8_t)len;
    if (!aead(1, st->sk, st->sn, NULL, 0, l, 2, out) || !step(&st->sn, st->sck, st->sk))
        return fail(st, GZ_NOISE_ERR_CRYPTO);
    if (!aead(1, st->sk, st->sn, NULL, 0, msg, len, out + GZ_NOISE_HDR_LEN) ||
        !step(&st->sn, st->sck, st->sk))
        return fail(st, GZ_NOISE_ERR_CRYPTO);
    *out_len = GZ_NOISE_HDR_LEN + len + GZ_NOISE_MAC_LEN;
    return GZ_NOISE_OK;
}

gz_noise_err_t gz_noise_decrypt_header(gz_noise_t *st, const uint8_t *in, size_t len,
                                       size_t *body_len)
{
    uint8_t l[2];
    if (st->phase != GZ_NOISE_READY) return fail(st, GZ_NOISE_ERR_STATE);
    if (len != GZ_NOISE_HDR_LEN) return fail(st, GZ_NOISE_ERR_LENGTH);
    if (!aead(0, st->rk, st->rn, NULL, 0, in, 2, l)) return fail(st, GZ_NOISE_ERR_MAC);
    if (!step(&st->rn, st->rck, st->rk)) return fail(st, GZ_NOISE_ERR_CRYPTO);
    st->body_len = (uint16_t)((l[0] << 8) | l[1]);
    st->phase = GZ_NOISE_READY_BODY;
    *body_len = st->body_len;
    return GZ_NOISE_OK;
}

gz_noise_err_t gz_noise_decrypt_body(gz_noise_t *st, const uint8_t *in, size_t len,
                                     uint8_t *out, size_t out_cap)
{
    if (st->phase != GZ_NOISE_READY_BODY) return fail(st, GZ_NOISE_ERR_STATE);
    if (len != (size_t)st->body_len + GZ_NOISE_MAC_LEN) return fail(st, GZ_NOISE_ERR_LENGTH);
    if (out_cap < st->body_len) return fail(st, GZ_NOISE_ERR_TOO_BIG);
    if (!aead(0, st->rk, st->rn, NULL, 0, in, st->body_len, out)) return fail(st, GZ_NOISE_ERR_MAC);
    if (!step(&st->rn, st->rck, st->rk)) {
        wipe(out, st->body_len);
        return fail(st, GZ_NOISE_ERR_CRYPTO);
    }
    st->phase = GZ_NOISE_READY;
    return GZ_NOISE_OK;
}

void gz_noise_wipe(gz_noise_t *st)
{
    wipe(st, sizeof *st);
    st->phase = GZ_NOISE_DEAD;
}

const char *gz_noise_err_name(gz_noise_err_t e)
{
    switch (e) {
    case GZ_NOISE_OK: return "ok";
    case GZ_NOISE_ERR_STATE: return "out of order or dead";
    case GZ_NOISE_ERR_LENGTH: return "wrong length";
    case GZ_NOISE_ERR_VERSION: return "unknown version";
    case GZ_NOISE_ERR_PUBKEY: return "invalid public key";
    case GZ_NOISE_ERR_MAC: return "authentication failed";
    case GZ_NOISE_ERR_RANDOM: return "no valid ephemeral key";
    case GZ_NOISE_ERR_TOO_BIG: return "message too big";
    case GZ_NOISE_ERR_KEY: return "invalid static key";
    case GZ_NOISE_ERR_CRYPTO: return "crypto library failure";
    }
    return "unknown";
}
