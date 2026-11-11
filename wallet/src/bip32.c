/* Extended keys per BIP 32, on libsecp256k1 and libcrypto.
 *
 * Written here because the imported hd_key.c derives hardened children only:
 * it has no non-hardened step, no public derivation and no extended-key
 * serialisation, all of which BIP 86 needs. */
#include "gazpacho/wallet_keys.h"

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

/* ---- hygiene -------------------------------------------------------------- */

void gzw_wipe(void *p, size_t len) {
    if (p && len) OPENSSL_cleanse(p, len);
}

int gzw_ct_equal(const void *a, const void *b, size_t len) {
    if (len == 0) return 1;
    if (!a || !b) return 0;
    return CRYPTO_memcmp(a, b, len) == 0;
}

/* ---- helpers -------------------------------------------------------------- */

static void put_be32(unsigned char *out, uint32_t v) {
    out[0] = (unsigned char)(v >> 24);
    out[1] = (unsigned char)(v >> 16);
    out[2] = (unsigned char)(v >> 8);
    out[3] = (unsigned char)v;
}

static uint32_t get_be32(const unsigned char *in) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static int hmac_sha512(const unsigned char *key, size_t key_len,
                       const unsigned char *data, size_t data_len,
                       unsigned char out64[64]) {
    unsigned int md_len = 0;
    if (!HMAC(EVP_sha512(), key, (int)key_len, data, data_len, out64, &md_len))
        return 0;
    return md_len == 64;
}

/* First four bytes of RIPEMD160(SHA256(compressed public key)). */
static int key_fingerprint(const unsigned char pubkey33[33], unsigned char out4[4]) {
    unsigned char sha[SHA256_DIGEST_LENGTH];
    unsigned char rmd[EVP_MAX_MD_SIZE];
    unsigned int rmd_len = 0;
    SHA256(pubkey33, 33, sha);
    if (!EVP_Digest(sha, sizeof(sha), rmd, &rmd_len, EVP_ripemd160(), NULL) ||
        rmd_len != 20)
        return 0;
    memcpy(out4, rmd, 4);
    return 1;
}

static int seckey_to_pubkey33(const secp256k1_context *ctx,
                              const unsigned char seckey[32],
                              unsigned char out33[33]) {
    secp256k1_pubkey pub;
    size_t len = 33;
    int ok = secp256k1_ec_pubkey_create(ctx, &pub, seckey) &&
             secp256k1_ec_pubkey_serialize(ctx, out33, &len, &pub,
                                           SECP256K1_EC_COMPRESSED) &&
             len == 33;
    gzw_wipe(&pub, sizeof(pub));
    return ok;
}

/* ---- derivation ----------------------------------------------------------- */

int gzw_bip32_master(const secp256k1_context *ctx,
                     const unsigned char *seed, size_t seed_len,
                     gzw_xprv *out) {
    static const unsigned char hmac_key[12] = {'B', 'i', 't', 'c', 'o', 'i',
                                               'n', ' ', 's', 'e', 'e', 'd'};
    unsigned char I[64];
    int ok = 0;

    if (!out) return 0;
    gzw_wipe(out, sizeof(*out));
    if (!ctx || !seed || seed_len < 16 || seed_len > 64) return 0;

    if (!hmac_sha512(hmac_key, sizeof(hmac_key), seed, seed_len, I)) goto done;
    /* The left half must be a valid private key: not 0 and below the order. */
    if (!secp256k1_ec_seckey_verify(ctx, I)) goto done;

    memcpy(out->key, I, 32);
    memcpy(out->chain_code, I + 32, 32);
    ok = 1;

done:
    gzw_wipe(I, sizeof(I));
    if (!ok) gzw_wipe(out, sizeof(*out));
    return ok;
}

int gzw_bip32_child_priv(const secp256k1_context *ctx, const gzw_xprv *parent,
                         uint32_t index, gzw_xprv *out) {
    unsigned char data[37];
    unsigned char I[64];
    unsigned char parent_pub[33];
    gzw_xprv child;
    int ok = 0;

    if (!out) return 0;
    if (!ctx || !parent) {
        gzw_wipe(out, sizeof(*out));
        return 0;
    }
    memset(&child, 0, sizeof(child));

    if (parent->depth == 255) goto done;
    if (!seckey_to_pubkey33(ctx, parent->key, parent_pub)) goto done;

    if (index & GZW_HARDENED) {
        /* 0x00 || ser256(k_par) || ser32(i) */
        data[0] = 0x00;
        memcpy(data + 1, parent->key, 32);
    } else {
        /* serP(point(k_par)) || ser32(i) */
        memcpy(data, parent_pub, 33);
    }
    put_be32(data + 33, index);

    if (!hmac_sha512(parent->chain_code, 32, data, sizeof(data), I)) goto done;

    /* k_i = parse256(I_L) + k_par (mod n).  The library call fails if I_L is
       not below the order or the sum is zero, the two invalid cases. */
    memcpy(child.key, parent->key, 32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, child.key, I)) goto done;

    memcpy(child.chain_code, I + 32, 32);
    child.depth = (uint8_t)(parent->depth + 1);
    child.child_number = index;
    if (!key_fingerprint(parent_pub, child.parent_fingerprint)) goto done;
    ok = 1;

done:
    gzw_wipe(data, sizeof(data));
    gzw_wipe(I, sizeof(I));
    if (ok)
        *out = child;
    else
        gzw_wipe(out, sizeof(*out));
    gzw_wipe(&child, sizeof(child));
    return ok;
}

int gzw_bip32_child_pub(const secp256k1_context *ctx, const gzw_xpub *parent,
                        uint32_t index, gzw_xpub *out) {
    unsigned char data[37];
    unsigned char I[64];
    secp256k1_pubkey pub;
    gzw_xpub child;
    size_t len = 33;
    int ok = 0;

    if (!out) return 0;
    if (!ctx || !parent) {
        memset(out, 0, sizeof(*out));
        return 0;
    }
    memset(&child, 0, sizeof(child));

    /* A hardened child needs the parent private key. */
    if (index & GZW_HARDENED) goto done;
    if (parent->depth == 255) goto done;
    if (!secp256k1_ec_pubkey_parse(ctx, &pub, parent->pubkey, 33)) goto done;

    memcpy(data, parent->pubkey, 33);
    put_be32(data + 33, index);
    if (!hmac_sha512(parent->chain_code, 32, data, sizeof(data), I)) goto done;

    /* K_i = point(parse256(I_L)) + K_par.  Fails if I_L is not below the
       order or the result is the point at infinity. */
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &pub, I)) goto done;
    if (!secp256k1_ec_pubkey_serialize(ctx, child.pubkey, &len, &pub,
                                       SECP256K1_EC_COMPRESSED) ||
        len != 33)
        goto done;

    memcpy(child.chain_code, I + 32, 32);
    child.depth = (uint8_t)(parent->depth + 1);
    child.child_number = index;
    if (!key_fingerprint(parent->pubkey, child.parent_fingerprint)) goto done;
    ok = 1;

done:
    /* Not private, but the chain code half lets siblings be derived. */
    gzw_wipe(I, sizeof(I));
    if (ok)
        *out = child;
    else
        memset(out, 0, sizeof(*out));
    return ok;
}

int gzw_bip32_neuter(const secp256k1_context *ctx, const gzw_xprv *xprv,
                     gzw_xpub *out) {
    gzw_xpub pub;
    if (!out) return 0;
    if (!ctx || !xprv) {
        memset(out, 0, sizeof(*out));
        return 0;
    }
    memset(&pub, 0, sizeof(pub));
    if (!seckey_to_pubkey33(ctx, xprv->key, pub.pubkey)) {
        memset(out, 0, sizeof(*out));
        return 0;
    }
    pub.depth = xprv->depth;
    memcpy(pub.parent_fingerprint, xprv->parent_fingerprint, 4);
    pub.child_number = xprv->child_number;
    memcpy(pub.chain_code, xprv->chain_code, 32);
    *out = pub;
    return 1;
}

int gzw_bip32_derive_priv(const secp256k1_context *ctx, const gzw_xprv *start,
                          const uint32_t *path, size_t path_len, gzw_xprv *out) {
    gzw_xprv cur;
    int ok = 1;

    if (!out) return 0;
    if (!ctx || !start || (!path && path_len > 0)) {
        gzw_wipe(out, sizeof(*out));
        return 0;
    }
    cur = *start;
    for (size_t i = 0; i < path_len && ok; i++)
        ok = gzw_bip32_child_priv(ctx, &cur, path[i], &cur);
    if (ok)
        *out = cur;
    else
        gzw_wipe(out, sizeof(*out));
    gzw_wipe(&cur, sizeof(cur));
    return ok;
}

int gzw_bip32_derive_pub(const secp256k1_context *ctx, const gzw_xpub *start,
                         const uint32_t *path, size_t path_len, gzw_xpub *out) {
    gzw_xpub cur;
    int ok = 1;

    if (!out) return 0;
    if (!ctx || !start || (!path && path_len > 0)) {
        memset(out, 0, sizeof(*out));
        return 0;
    }
    cur = *start;
    for (size_t i = 0; i < path_len && ok; i++)
        ok = gzw_bip32_child_pub(ctx, &cur, path[i], &cur);
    if (ok)
        *out = cur;
    else
        memset(out, 0, sizeof(*out));
    return ok;
}

/* ---- Base58Check for the 78-byte extended key ----------------------------- */

#define XKEY_RAW 78
#define XKEY_FULL 82 /* with the 4-byte checksum */

static const unsigned char VER_XPRV[4] = {0x04, 0x88, 0xAD, 0xE4};
static const unsigned char VER_XPUB[4] = {0x04, 0x88, 0xB2, 0x1E};
static const unsigned char VER_TPRV[4] = {0x04, 0x35, 0x83, 0x94};
static const unsigned char VER_TPUB[4] = {0x04, 0x35, 0x87, 0xCF};

static const char B58[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static void checksum4(const unsigned char *data, size_t len, unsigned char out4[4]) {
    unsigned char h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
    SHA256(data, len, h1);
    SHA256(h1, sizeof(h1), h2);
    memcpy(out4, h2, 4);
    gzw_wipe(h1, sizeof(h1));
    gzw_wipe(h2, sizeof(h2));
}

/* Encode exactly 82 bytes.  out must hold GZW_XKEY_STR_MAX characters. */
static int base58_encode82(const unsigned char in[XKEY_FULL],
                           char out[GZW_XKEY_STR_MAX]) {
    unsigned char digits[GZW_XKEY_STR_MAX]; /* base-58 digits, little-endian */
    size_t ndigits = 0;
    size_t zeros = 0;
    size_t pos = 0;
    int ok = 0;

    memset(digits, 0, sizeof(digits));
    while (zeros < XKEY_FULL && in[zeros] == 0) zeros++;

    for (size_t i = zeros; i < XKEY_FULL; i++) {
        unsigned carry = in[i];
        for (size_t j = 0; j < ndigits; j++) {
            carry += (unsigned)digits[j] << 8;
            digits[j] = (unsigned char)(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            if (ndigits >= sizeof(digits)) goto done;
            digits[ndigits++] = (unsigned char)(carry % 58);
            carry /= 58;
        }
    }
    if (zeros + ndigits + 1 > GZW_XKEY_STR_MAX) goto done;
    for (size_t i = 0; i < zeros; i++) out[pos++] = '1';
    for (size_t i = 0; i < ndigits; i++) out[pos++] = B58[digits[ndigits - 1 - i]];
    out[pos] = '\0';
    ok = 1;

done:
    gzw_wipe(digits, sizeof(digits));
    if (!ok) gzw_wipe(out, GZW_XKEY_STR_MAX);
    return ok;
}

/* Decode to exactly 82 bytes; any other decoded length fails. */
static int base58_decode82(const char *str, unsigned char out[XKEY_FULL]) {
    unsigned char bytes[XKEY_FULL + 8]; /* little-endian */
    size_t nbytes = 0;
    size_t zeros = 0;
    size_t slen;
    int ok = 0;

    memset(bytes, 0, sizeof(bytes));
    slen = strnlen(str, GZW_XKEY_STR_MAX + 1);
    if (slen == 0 || slen > GZW_XKEY_STR_MAX - 1) goto done;

    while (zeros < slen && str[zeros] == '1') zeros++;
    for (size_t i = zeros; i < slen; i++) {
        const char *p = (str[i] != '\0') ? strchr(B58, str[i]) : NULL;
        unsigned carry;
        if (!p) goto done;
        carry = (unsigned)(p - B58);
        for (size_t j = 0; j < nbytes; j++) {
            carry += (unsigned)bytes[j] * 58;
            bytes[j] = (unsigned char)(carry & 0xff);
            carry >>= 8;
        }
        while (carry > 0) {
            if (nbytes >= sizeof(bytes)) goto done;
            bytes[nbytes++] = (unsigned char)(carry & 0xff);
            carry >>= 8;
        }
    }
    if (zeros + nbytes != XKEY_FULL) goto done;
    memset(out, 0, zeros);
    for (size_t i = 0; i < nbytes; i++) out[zeros + i] = bytes[nbytes - 1 - i];
    ok = 1;

done:
    gzw_wipe(bytes, sizeof(bytes));
    if (!ok) gzw_wipe(out, XKEY_FULL);
    return ok;
}

static int xkey_to_string(const unsigned char version[4], uint8_t depth,
                          const uint8_t fingerprint[4], uint32_t child_number,
                          const unsigned char chain_code[32],
                          const unsigned char keydata33[33],
                          char out[GZW_XKEY_STR_MAX]) {
    unsigned char raw[XKEY_FULL];
    int ok;

    /* The master key has no parent and no index. */
    if (depth == 0 &&
        (child_number != 0 || fingerprint[0] | fingerprint[1] | fingerprint[2] |
                                  fingerprint[3])) {
        gzw_wipe(out, GZW_XKEY_STR_MAX);
        return 0;
    }
    memcpy(raw, version, 4);
    raw[4] = depth;
    memcpy(raw + 5, fingerprint, 4);
    put_be32(raw + 9, child_number);
    memcpy(raw + 13, chain_code, 32);
    memcpy(raw + 45, keydata33, 33);
    checksum4(raw, XKEY_RAW, raw + XKEY_RAW);
    ok = base58_encode82(raw, out);
    gzw_wipe(raw, sizeof(raw));
    return ok;
}

int gzw_xprv_to_string(const gzw_xprv *xprv, int mainnet,
                       char out[GZW_XKEY_STR_MAX]) {
    unsigned char keydata[33];
    int ok;
    if (!out) return 0;
    if (!xprv) {
        gzw_wipe(out, GZW_XKEY_STR_MAX);
        return 0;
    }
    keydata[0] = 0x00;
    memcpy(keydata + 1, xprv->key, 32);
    ok = xkey_to_string(mainnet ? VER_XPRV : VER_TPRV, xprv->depth,
                        xprv->parent_fingerprint, xprv->child_number,
                        xprv->chain_code, keydata, out);
    gzw_wipe(keydata, sizeof(keydata));
    return ok;
}

int gzw_xpub_to_string(const gzw_xpub *xpub, int mainnet,
                       char out[GZW_XKEY_STR_MAX]) {
    if (!out) return 0;
    if (!xpub || (xpub->pubkey[0] != 0x02 && xpub->pubkey[0] != 0x03)) {
        memset(out, 0, GZW_XKEY_STR_MAX);
        return 0;
    }
    return xkey_to_string(mainnet ? VER_XPUB : VER_TPUB,
                          xpub->depth, xpub->parent_fingerprint,
                          xpub->child_number, xpub->chain_code, xpub->pubkey, out);
}

/* Decode, verify the checksum and the rules shared by both key kinds.
   *is_private_out and *mainnet_out are set from the version bytes. */
static int xkey_decode(const char *str, unsigned char raw[XKEY_FULL],
                       int *is_private_out, int *mainnet_out) {
    unsigned char sum[4];

    if (!base58_decode82(str, raw)) return 0;
    checksum4(raw, XKEY_RAW, sum);
    if (!gzw_ct_equal(sum, raw + XKEY_RAW, 4)) return 0;

    if (memcmp(raw, VER_XPRV, 4) == 0) {
        *is_private_out = 1;
        *mainnet_out = 1;
    } else if (memcmp(raw, VER_XPUB, 4) == 0) {
        *is_private_out = 0;
        *mainnet_out = 1;
    } else if (memcmp(raw, VER_TPRV, 4) == 0) {
        *is_private_out = 1;
        *mainnet_out = 0;
    } else if (memcmp(raw, VER_TPUB, 4) == 0) {
        *is_private_out = 0;
        *mainnet_out = 0;
    } else {
        return 0; /* unknown version */
    }

    /* Depth 0 has no parent and no index. */
    if (raw[4] == 0 && (raw[5] | raw[6] | raw[7] | raw[8] | raw[9] | raw[10] |
                        raw[11] | raw[12]) != 0)
        return 0;
    return 1;
}

int gzw_xprv_from_string(const secp256k1_context *ctx, const char *str,
                         gzw_xprv *out, int *mainnet_out) {
    unsigned char raw[XKEY_FULL];
    int is_private = 0, mainnet = 0;
    int ok = 0;

    if (!out) return 0;
    gzw_wipe(out, sizeof(*out));
    if (!ctx || !str) return 0;

    if (!xkey_decode(str, raw, &is_private, &mainnet)) goto done;
    if (!is_private) goto done;
    if (raw[45] != 0x00) goto done;
    if (!secp256k1_ec_seckey_verify(ctx, raw + 46)) goto done;

    out->depth = raw[4];
    memcpy(out->parent_fingerprint, raw + 5, 4);
    out->child_number = get_be32(raw + 9);
    memcpy(out->chain_code, raw + 13, 32);
    memcpy(out->key, raw + 46, 32);
    if (mainnet_out) *mainnet_out = mainnet;
    ok = 1;

done:
    gzw_wipe(raw, sizeof(raw));
    if (!ok) gzw_wipe(out, sizeof(*out));
    return ok;
}

int gzw_xpub_from_string(const secp256k1_context *ctx, const char *str,
                         gzw_xpub *out, int *mainnet_out) {
    unsigned char raw[XKEY_FULL];
    secp256k1_pubkey pub;
    int is_private = 0, mainnet = 0;
    int ok = 0;

    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!ctx || !str) return 0;

    if (!xkey_decode(str, raw, &is_private, &mainnet)) goto done;
    if (is_private) goto done;
    if (raw[45] != 0x02 && raw[45] != 0x03) goto done;
    if (!secp256k1_ec_pubkey_parse(ctx, &pub, raw + 45, 33)) goto done;

    out->depth = raw[4];
    memcpy(out->parent_fingerprint, raw + 5, 4);
    out->child_number = get_be32(raw + 9);
    memcpy(out->chain_code, raw + 13, 32);
    memcpy(out->pubkey, raw + 45, 33);
    if (mainnet_out) *mainnet_out = mainnet;
    ok = 1;

done:
    /* raw may hold a private key if the caller passed one by mistake. */
    gzw_wipe(raw, sizeof(raw));
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

/* ---- path text ------------------------------------------------------------ */

int gzw_path_to_string(const uint32_t *path, size_t path_len,
                       char *out, size_t out_max) {
    size_t pos = 0;

    if (!out || out_max < 2 || (!path && path_len > 0)) return 0;
    out[pos++] = 'm';
    for (size_t i = 0; i < path_len; i++) {
        char digits[10];
        size_t nd = 0;
        uint32_t v = path[i] & ~GZW_HARDENED;
        int hardened = (path[i] & GZW_HARDENED) != 0;
        do {
            digits[nd++] = (char)('0' + v % 10);
            v /= 10;
        } while (v > 0);
        if (pos + 1 + nd + (size_t)hardened + 1 > out_max) {
            out[0] = '\0';
            return 0;
        }
        out[pos++] = '/';
        while (nd > 0) out[pos++] = digits[--nd];
        if (hardened) out[pos++] = '\'';
    }
    out[pos] = '\0';
    return 1;
}
