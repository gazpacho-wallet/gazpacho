/* Runs the official vectors in official_vectors_data.h. */
#include "official_vectors.h"

#include <stdlib.h>
#include <string.h>

#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include "gazpacho/wallet_keys.h"
#include "superscalar/bip39.h"

#include "official_vectors_data.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex into out; returns the byte count or -1. */
static int unhex(const char *hex, unsigned char *out, size_t out_max) {
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > out_max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)(hi * 16 + lo);
    }
    return (int)(n / 2);
}

static int hex_equals(const char *hex, const unsigned char *bytes, size_t len) {
    unsigned char tmp[128];
    int n = unhex(hex, tmp, sizeof(tmp));
    return n >= 0 && (size_t)n == len && memcmp(tmp, bytes, len) == 0;
}

/* Parse "m/0'/1/2'" into indexes; returns the number of steps or -1. */
static int parse_path(const char *path, uint32_t *out, size_t out_max) {
    size_t n = 0;
    const char *p = path;
    if (*p++ != 'm') return -1;
    while (*p) {
        char *end;
        unsigned long v;
        if (*p++ != '/') return -1;
        v = strtoul(p, &end, 10);
        if (end == p || v > 0x7fffffffUL || n >= out_max) return -1;
        p = end;
        out[n] = (uint32_t)v;
        if (*p == '\'') {
            out[n] |= GZW_HARDENED;
            p++;
        }
        n++;
    }
    return (int)n;
}

/* ---- BIP 39 --------------------------------------------------------------- */

static int one_bip39(const secp256k1_context *ctx, const struct gzv_bip39 *v) {
    unsigned char entropy[32], seed[64];
    char phrase[GZW_PHRASE_MAX], imported[256], xprv_str[GZW_XKEY_STR_MAX];
    gzw_xprv master;
    int ent_len = unhex(v->entropy_hex, entropy, sizeof(entropy));

    if (ent_len != 16 && ent_len != 24 && ent_len != 32) return 0;
    /* Our own encoder makes 24-word phrases only. */
    if (ent_len == 32) {
        if (!gzw_phrase_from_entropy(entropy, phrase)) return 0;
        if (strcmp(phrase, v->phrase) != 0) return 0;
    }
    /* The imported encoder, for every length (it is used when decoding). */
    if (!bip39_entropy_to_mnemonic(entropy, (size_t)ent_len, imported,
                                   sizeof(imported)))
        return 0;
    if (strcmp(imported, v->phrase) != 0) return 0;

    if (gzw_phrase_check(v->phrase) != GZW_PHRASE_OK) return 0;
    if (!gzw_phrase_to_seed(v->phrase, "TREZOR", seed)) return 0;
    if (!hex_equals(v->seed_hex, seed, 64)) return 0;

    if (!gzw_bip32_master(ctx, seed, 64, &master, NULL)) return 0;
    if (!gzw_xprv_to_string(&master, GZW_NET_MAINNET, xprv_str)) return 0;
    return strcmp(xprv_str, v->xprv) == 0;
}

/* ---- BIP 32 --------------------------------------------------------------- */

static int one_bip32(const secp256k1_context *ctx, const struct gzv_bip32 *v) {
    unsigned char seed[64];
    uint32_t path[8];
    char str[GZW_XKEY_STR_MAX];
    gzw_xprv master, key, parsed_prv, parent;
    gzw_xpub pub, parsed_pub, parent_pub, child_pub;
    int mainnet = 0;
    int seed_len = unhex(v->seed_hex, seed, sizeof(seed));
    int n = parse_path(v->path, path, COUNT(path));

    if (seed_len < 0 || n < 0) return 0;
    if (!gzw_bip32_master(ctx, seed, (size_t)seed_len, &master, NULL)) return 0;
    if (!gzw_bip32_derive_priv(ctx, &master, path, (size_t)n, &key, NULL)) return 0;

    /* The derived private key and its public key, as text. */
    if (!gzw_xprv_to_string(&key, GZW_NET_MAINNET, str) || strcmp(str, v->xprv) != 0) return 0;
    if (!gzw_bip32_neuter(ctx, &key, &pub)) return 0;
    if (!gzw_xpub_to_string(&pub, GZW_NET_MAINNET, str) || strcmp(str, v->xpub) != 0) return 0;

    /* The published text parses and writes back unchanged. */
    if (!gzw_xprv_from_string(ctx, v->xprv, &parsed_prv, &mainnet) || !mainnet)
        return 0;
    if (!gzw_xprv_to_string(&parsed_prv, GZW_NET_MAINNET, str) || strcmp(str, v->xprv) != 0)
        return 0;
    if (memcmp(parsed_prv.key, key.key, 32) != 0) return 0;
    if (!gzw_xpub_from_string(ctx, v->xpub, &parsed_pub, &mainnet) || !mainnet)
        return 0;
    if (!gzw_xpub_to_string(&parsed_pub, GZW_NET_MAINNET, str) || strcmp(str, v->xpub) != 0)
        return 0;
    /* A private key string is not a public key and the reverse. */
    if (gzw_xpub_from_string(ctx, v->xprv, &parsed_pub, NULL)) return 0;
    if (gzw_xprv_from_string(ctx, v->xpub, &parsed_prv, NULL)) return 0;

    if (n > 0) {
        uint32_t last = path[n - 1];
        if (!gzw_bip32_derive_priv(ctx, &master, path, (size_t)n - 1, &parent, NULL))
            return 0;
        if (!gzw_bip32_neuter(ctx, &parent, &parent_pub)) return 0;
        if (last & GZW_HARDENED) {
            /* No public derivation of a hardened child. */
            if (gzw_bip32_child_pub(ctx, &parent_pub, last, &child_pub, NULL)) return 0;
        } else {
            /* Public derivation reaches the same extended public key. */
            if (!gzw_bip32_child_pub(ctx, &parent_pub, last, &child_pub, NULL)) return 0;
            if (!gzw_xpub_to_string(&child_pub, GZW_NET_MAINNET, str) ||
                strcmp(str, v->xpub) != 0)
                return 0;
        }
    }
    return 1;
}

static int one_bip32_invalid(const secp256k1_context *ctx,
                             const struct gzv_bip32_invalid *v) {
    gzw_xprv prv;
    gzw_xpub pub;
    if (gzw_xprv_from_string(ctx, v->key, &prv, NULL)) return 0;
    if (gzw_xpub_from_string(ctx, v->key, &pub, NULL)) return 0;
    return 1;
}

/* ---- BIP 86 --------------------------------------------------------------- */

static int bip86_master(const secp256k1_context *ctx, gzw_xprv *master) {
    unsigned char seed[64];
    if (!gzw_phrase_to_seed(GZV_BIP86_PHRASE, NULL, seed)) return 0;
    return gzw_bip32_master(ctx, seed, 64, master, NULL);
}

static int bip86_root(const secp256k1_context *ctx) {
    gzw_xprv master;
    gzw_xpub pub;
    char str[GZW_XKEY_STR_MAX];
    if (!bip86_master(ctx, &master)) return 0;
    if (!gzw_xprv_to_string(&master, GZW_NET_MAINNET, str) || strcmp(str, GZV_BIP86_ROOT_XPRV) != 0)
        return 0;
    if (!gzw_bip32_neuter(ctx, &master, &pub)) return 0;
    return gzw_xpub_to_string(&pub, GZW_NET_MAINNET, str) && strcmp(str, GZV_BIP86_ROOT_XPUB) == 0;
}

static int bip86_account(const secp256k1_context *ctx) {
    gzw_xprv master, acct;
    gzw_xpub pub;
    char str[GZW_XKEY_STR_MAX];
    if (!bip86_master(ctx, &master)) return 0;
    if (!gzw_bip86_account_xprv(ctx, &master, GZW_NET_MAINNET, 0, &acct, NULL)) return 0;
    if (!gzw_xprv_to_string(&acct, GZW_NET_MAINNET, str) ||
        strcmp(str, GZV_BIP86_ACCOUNT_XPRV) != 0)
        return 0;
    if (!gzw_bip86_account_xpub(ctx, &master, GZW_NET_MAINNET, 0, &pub, NULL)) return 0;
    return gzw_xpub_to_string(&pub, GZW_NET_MAINNET, str) &&
           strcmp(str, GZV_BIP86_ACCOUNT_XPUB) == 0;
}

static int output_matches(const gzw_bip86_output *o, const struct gzv_bip86 *v,
                          const uint32_t path[5]) {
    return memcmp(o->path, path, 5 * sizeof(uint32_t)) == 0 &&
           hex_equals(v->internal_key, o->internal_key, 32) &&
           hex_equals(v->output_key, o->output_key, 32) &&
           hex_equals(v->script_pubkey, o->script_pubkey, 34) &&
           strcmp(v->address, o->address) == 0;
}

static int one_bip86(const secp256k1_context *ctx, const struct gzv_bip86 *v) {
    gzw_xprv master, leaf;
    gzw_xpub leaf_pub, acct_pub;
    gzw_bip86_output o;
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey kp_pub;
    unsigned char kp_pub32[32];
    uint32_t want[8], path[5];
    char str[GZW_XKEY_STR_MAX];
    int mainnet = 0;

    /* The published path is the one our path function makes. */
    if (parse_path(v->path, want, COUNT(want)) != 5) return 0;
    if (!gzw_bip86_path(GZW_NET_MAINNET, want[2] & ~GZW_HARDENED, want[3], want[4],
                        path))
        return 0;
    if (memcmp(want, path, sizeof(path)) != 0) return 0;

    if (!bip86_master(ctx, &master)) return 0;
    if (!gzw_bip32_derive_priv(ctx, &master, path, 5, &leaf, NULL)) return 0;
    if (!gzw_xprv_to_string(&leaf, GZW_NET_MAINNET, str) || strcmp(str, v->xprv) != 0) return 0;
    if (!gzw_bip32_neuter(ctx, &leaf, &leaf_pub)) return 0;
    if (!gzw_xpub_to_string(&leaf_pub, GZW_NET_MAINNET, str) || strcmp(str, v->xpub) != 0) return 0;

    /* From the master key. */
    if (!gzw_bip86_output_from_master(ctx, &master, GZW_NET_MAINNET, 0, path[3],
                                      path[4], &o, NULL))
        return 0;
    if (!output_matches(&o, v, path)) return 0;

    /* From the published account public key alone. */
    if (!gzw_xpub_from_string(ctx, GZV_BIP86_ACCOUNT_XPUB, &acct_pub, &mainnet) ||
        !mainnet)
        return 0;
    if (!gzw_bip86_output_from_xpub(ctx, &acct_pub, GZW_NET_MAINNET, 0, path[3],
                                    path[4], &o, NULL))
        return 0;
    if (!output_matches(&o, v, path)) return 0;

    /* The signing key pair belongs to the published output key. */
    if (!gzw_bip86_tweaked_keypair(ctx, &master, GZW_NET_MAINNET, 0, path[3],
                                   path[4], &kp, &o, NULL))
        return 0;
    if (!output_matches(&o, v, path)) return 0;
    if (!secp256k1_keypair_xonly_pub(ctx, &kp_pub, NULL, &kp)) return 0;
    if (!secp256k1_xonly_pubkey_serialize(ctx, kp_pub32, &kp_pub)) return 0;
    return hex_equals(v->output_key, kp_pub32, 32);
}

/* ---- BIP 350 -------------------------------------------------------------- */

static void lower_copy(const char *in, char *out, size_t out_max) {
    size_t i = 0;
    for (; in[i] && i + 1 < out_max; i++)
        out[i] = (in[i] >= 'A' && in[i] <= 'Z') ? (char)(in[i] - 'A' + 'a') : in[i];
    out[i] = '\0';
}

static int one_segwit_valid(const struct gzv_segwit *v) {
    char lower[GZW_ADDRESS_MAX], again[GZW_ADDRESS_MAX];
    unsigned char prog[40], spk[42];
    size_t plen = 0;
    int version = -1;
    const char *hrp;

    lower_copy(v->address, lower, sizeof(lower));
    hrp = (lower[0] == 'b') ? "bc" : "tb";
    if (!gzw_segwit_address_decode(hrp, v->address, &version, prog, &plen)) return 0;
    spk[0] = (unsigned char)(version == 0 ? 0x00 : 0x50 + version);
    spk[1] = (unsigned char)plen;
    memcpy(spk + 2, prog, plen);
    if (!hex_equals(v->script_pubkey, spk, plen + 2)) return 0;
    if (!gzw_segwit_address_encode(hrp, version, prog, plen, again)) return 0;
    if (strcmp(again, lower) != 0) return 0;
    /* The other network's prefix is refused. */
    if (gzw_segwit_address_decode(strcmp(hrp, "bc") == 0 ? "tb" : "bc", v->address,
                                  &version, prog, &plen))
        return 0;
    return 1;
}

static int one_segwit_invalid(const struct gzv_reason *v) {
    unsigned char prog[40];
    size_t plen = 0;
    int version = -1;
    if (gzw_segwit_address_decode("bc", v->str, &version, prog, &plen)) return 0;
    if (gzw_segwit_address_decode("tb", v->str, &version, prog, &plen)) return 0;
    return 1;
}

/* ---- BIP 341 -------------------------------------------------------------- */

static int one_bip341_spk(const secp256k1_context *ctx,
                          const struct gzv_bip341_spk *v) {
    unsigned char internal[32], q[32], spk[34];
    char address[GZW_ADDRESS_MAX];
    if (unhex(v->internal_key, internal, 32) != 32) return 0;
    if (!gzw_taproot_output_key(ctx, internal, q, NULL)) return 0;
    if (!hex_equals(v->output_key, q, 32)) return 0;
    gzw_p2tr_script_pubkey(q, spk);
    if (!hex_equals(v->script_pubkey, spk, 34)) return 0;
    if (!gzw_p2tr_address(GZW_NET_MAINNET, q, address)) return 0;
    return strcmp(address, v->address) == 0;
}

static int one_bip341_keypath(const secp256k1_context *ctx,
                              const struct gzv_bip341_keypath *v) {
    static const unsigned char zero_aux[32] = {0};
    unsigned char sk[32], tweaked_sk[32], internal[32], q[32], q_pub[32];
    unsigned char msg[32], sig[64];
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey q_xonly;

    if (unhex(v->internal_privkey, sk, 32) != 32) return 0;
    if (unhex(v->internal_pubkey, internal, 32) != 32) return 0;
    if (unhex(v->sighash, msg, 32) != 32) return 0;
    if (!gzw_taproot_tweak_seckey(ctx, sk, &kp, q)) return 0;
    if (!secp256k1_keypair_sec(ctx, tweaked_sk, &kp)) return 0;
    if (!hex_equals(v->tweaked_privkey, tweaked_sk, 32)) return 0;
    if (!gzw_taproot_output_key(ctx, internal, q_pub, NULL)) return 0;
    if (memcmp(q, q_pub, 32) != 0) return 0;
    /* Sign the published signature hash; the result is the published
       signature and verifies under the output key. */
    if (!secp256k1_schnorrsig_sign32(ctx, sig, msg, &kp, zero_aux)) return 0;
    if (!hex_equals(v->signature, sig, 64)) return 0;
    if (!secp256k1_xonly_pubkey_parse(ctx, &q_xonly, q)) return 0;
    return secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &q_xonly);
}

/* ---- all ------------------------------------------------------------------ */

int gzw_official_vectors_run(const secp256k1_context *ctx,
                             gzw_vector_group groups[GZW_VECTOR_GROUPS]) {
    static const char *const names[GZW_VECTOR_GROUPS] = {
        "BIP 39 phrases, seeds and master keys (python-mnemonic vectors.json, English)",
        "BIP 32 test vectors 1-4 (private and public derivation, key text)",
        "BIP 32 test vector 5 (invalid extended keys refused)",
        "BIP 86 test vectors (root, account, three addresses)",
        "BIP 350 valid Bech32m strings",
        "BIP 350 invalid Bech32m strings refused",
        "BIP 350 valid segwit addresses",
        "BIP 350 invalid segwit addresses refused",
        "BIP 341 wallet vectors with no script tree (output key, key-path signature)",
    };
    int all = 1;

    if (!ctx || !groups) return 0;
    for (int g = 0; g < GZW_VECTOR_GROUPS; g++) {
        groups[g].name = names[g];
        groups[g].cases = 0;
        groups[g].failed = 0;
    }

#define RUN(g, expr)                  \
    do {                              \
        groups[g].cases++;            \
        if (!(expr)) groups[g].failed++; \
    } while (0)

    for (size_t i = 0; i < COUNT(GZV_BIP39); i++)
        RUN(0, one_bip39(ctx, &GZV_BIP39[i]));
    for (size_t i = 0; i < COUNT(GZV_BIP32); i++)
        RUN(1, one_bip32(ctx, &GZV_BIP32[i]));
    for (size_t i = 0; i < COUNT(GZV_BIP32_INVALID); i++)
        RUN(2, one_bip32_invalid(ctx, &GZV_BIP32_INVALID[i]));
    RUN(3, bip86_root(ctx));
    RUN(3, bip86_account(ctx));
    for (size_t i = 0; i < COUNT(GZV_BIP86); i++)
        RUN(3, one_bip86(ctx, &GZV_BIP86[i]));
    for (size_t i = 0; i < COUNT(GZV_BECH32M_VALID); i++)
        RUN(4, gzw_bech32_check(GZV_BECH32M_VALID[i]) == GZW_BECH32_BECH32M);
    for (size_t i = 0; i < COUNT(GZV_BECH32M_INVALID); i++)
        RUN(5, gzw_bech32_check(GZV_BECH32M_INVALID[i].str) != GZW_BECH32_BECH32M);
    for (size_t i = 0; i < COUNT(GZV_SEGWIT_VALID); i++)
        RUN(6, one_segwit_valid(&GZV_SEGWIT_VALID[i]));
    for (size_t i = 0; i < COUNT(GZV_SEGWIT_INVALID); i++)
        RUN(7, one_segwit_invalid(&GZV_SEGWIT_INVALID[i]));
    for (size_t i = 0; i < COUNT(GZV_BIP341_SPK); i++)
        RUN(8, one_bip341_spk(ctx, &GZV_BIP341_SPK[i]));
    for (size_t i = 0; i < COUNT(GZV_BIP341_KEYPATH); i++)
        RUN(8, one_bip341_keypath(ctx, &GZV_BIP341_KEYPATH[i]));
#undef RUN

    for (int g = 0; g < GZW_VECTOR_GROUPS; g++)
        if (groups[g].cases == 0 || groups[g].failed != 0) all = 0;
    return all;
}
