/* Unit tests for gazpacho_wallet_keys.
 *
 * The official BIP vectors are run by test_wallet_vectors and BIP 32's forced
 * rare cases by test_wallet_rare.  This file tests what those do not reach:
 * the test networks, refusals, limits, hygiene, overlapping arguments, reason
 * codes, the key-path signing key, and what the imported hd_key.c does and
 * does not do.
 */
#include <stdio.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include "gazpacho/wallet_keys.h"
#include "superscalar/bip39.h"
#include "superscalar/hd_key.h"
#include "bip39_wordlist.h" /* imported, core/superscalar/src */

static int checks = 0, failures = 0;

#define CHECK(cond)                                                     \
    do {                                                                \
        checks++;                                                       \
        if (!(cond)) {                                                  \
            failures++;                                                 \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                               \
    } while (0)

/* The phrase published in BIP 86.  Not a secret. */
static const char PUBLIC_PHRASE[] =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon about";

/* Reference values for the test networks.  BIP 86 publishes vectors for
 * mainnet only (coin type 0), so these were computed for PUBLIC_PHRASE with a
 * separate implementation: the Python package embit 0.8.0, on 2026-11-11,
 * script.p2tr(root.derive("m/86h/1h/0h/<change>/<index>")).address(network).
 * They are not official vectors.  The same run reproduced the three official
 * BIP 86 mainnet addresses. */
static const char REF_TEST_ACCOUNT_TPUB[] =
    "tpubDDfvzhdVV4unsoKt5aE6dcsNsfeWbTgmLZPi8LQDYU2xixrYemMfWJ3BaVneH3u7DBQePd"
    "TwhpybaKRU95pi6PMUtLPBJLVQRpzEnjfjZzX";
static const struct {
    uint32_t change, index;
    const char *tb_address, *bcrt_address, *script_pubkey_hex;
} REF_TEST[] = {
    {0, 0, "tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj",
     "bcrt1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqjeprhg",
     "51203b82b2b2a9185315da6f80da5f06d0440d8a5e1457fa93387c2d919c86ec8786"},
    {0, 1, "tb1p90h6z3p36n9hrzy7580h5l429uwchyg8uc9sz4jwzhdtuhqdl5eqmpwq6n",
     "bcrt1p90h6z3p36n9hrzy7580h5l429uwchyg8uc9sz4jwzhdtuhqdl5eqkcyx0f",
     "51202befa14431d4cb71889ea1df7a7eaa2f1d8b9107e60b01564e15dabe5c0dfd32"},
    {1, 0, "tb1p6uav7en8k7zsumsqugdmg5j6930zmzy4dg7jcddshsr0fvxlqx7q7p5els",
     "bcrt1p6uav7en8k7zsumsqugdmg5j6930zmzy4dg7jcddshsr0fvxlqx7qnc7l22",
     "5120d73acf6667b7850e6e00e21bb4525a2c5e2d88956a3d2c35b0bc06f4b0df01bc"},
    {0, 7, "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz",
     "bcrt1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5qgzwrkc",
     "51202258f2d4637b2ca3fd27614868b33dee1a242b42582d5474f51730005fa99ce8"},
};

static void to_hex(const unsigned char *in, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[2 * len] = '\0';
}

static int all_zero(const void *p, size_t len) {
    const unsigned char *b = p;
    unsigned char acc = 0;
    for (size_t i = 0; i < len; i++) acc |= b[i];
    return acc == 0;
}

static int public_master(const secp256k1_context *ctx, gzw_xprv *master) {
    unsigned char seed[64];
    return gzw_phrase_to_seed(PUBLIC_PHRASE, NULL, seed) &&
           gzw_bip32_master(ctx, seed, 64, master, NULL);
}

/* ---- hygiene -------------------------------------------------------------- */

static void test_hygiene(void) {
    unsigned char a[40], b[40];
    memset(a, 0xa5, sizeof(a));
    gzw_wipe(a, sizeof(a));
    CHECK(all_zero(a, sizeof(a)));
    gzw_wipe(NULL, 0); /* must not crash */

    memset(a, 7, sizeof(a));
    memset(b, 7, sizeof(b));
    CHECK(gzw_ct_equal(a, b, sizeof(a)) == 1);
    b[39] ^= 1;
    CHECK(gzw_ct_equal(a, b, sizeof(a)) == 0);
    CHECK(gzw_ct_equal(a, b, 39) == 1);
    b[39] ^= 1;
    b[0] ^= 0x80;
    CHECK(gzw_ct_equal(a, b, sizeof(a)) == 0);
    CHECK(gzw_ct_equal(a, NULL, 4) == 0);
    CHECK(gzw_ct_equal(NULL, NULL, 0) == 1);
}

/* ---- phrases -------------------------------------------------------------- */

static void test_phrase(void) {
    unsigned char entropy[32], back[32], seed[64], seed2[64];
    char phrase[GZW_PHRASE_MAX], other[GZW_PHRASE_MAX + 64];
    int words, valid;

    for (size_t i = 0; i < 32; i++) entropy[i] = (unsigned char)(i * 37 + 11);
    CHECK(gzw_phrase_from_entropy(entropy, phrase));
    words = 1;
    for (const char *p = phrase; *p; p++) words += (*p == ' ');
    CHECK(words == 24);
    CHECK(gzw_phrase_check(phrase) == GZW_PHRASE_OK);
    CHECK(bip39_mnemonic_to_entropy(phrase, back, sizeof(back)) == 32);
    CHECK(memcmp(back, entropy, 32) == 0);
    CHECK(strlen(phrase) < GZW_PHRASE_MAX);

    /* Different entropy, different phrase; one bit is enough. */
    entropy[31] ^= 1;
    CHECK(gzw_phrase_from_entropy(entropy, other));
    CHECK(strcmp(phrase, other) != 0);
    entropy[31] ^= 1;

    /* The longest possible phrase fits the documented buffer. */
    memset(entropy, 0, 32);
    CHECK(gzw_phrase_from_entropy(entropy, other));
    CHECK(strlen(other) + 1 <= GZW_PHRASE_MAX);

    CHECK(!gzw_phrase_from_entropy(NULL, other));
    CHECK(other[0] == '\0');

    /* Refusals. */
    CHECK(gzw_phrase_check(NULL) == GZW_PHRASE_ERR_WORD_COUNT);
    CHECK(gzw_phrase_check("") == GZW_PHRASE_ERR_WORD_COUNT);
    CHECK(gzw_phrase_check("abandon abandon abandon") == GZW_PHRASE_ERR_WORD_COUNT);
    CHECK(gzw_phrase_check("abandon abandon abandon abandon abandon abandon abandon "
                           "abandon abandon abandon abandon abandon") ==
          GZW_PHRASE_ERR_CHECKSUM);
    CHECK(gzw_phrase_check("abandon abandon abandon abandon abandon abandon abandon "
                           "abandon abandon abandon abandon gazpacho") ==
          GZW_PHRASE_ERR_UNKNOWN_WORD);
    CHECK(gzw_phrase_check("Abandon abandon abandon abandon abandon abandon abandon "
                           "abandon abandon abandon abandon about") ==
          GZW_PHRASE_ERR_UNKNOWN_WORD);
    CHECK(gzw_phrase_check(PUBLIC_PHRASE) == GZW_PHRASE_OK);
    /* 11 words and 13 words. */
    CHECK(gzw_phrase_check(PUBLIC_PHRASE + 8) == GZW_PHRASE_ERR_WORD_COUNT);
    snprintf(other, sizeof(other), "%s about", PUBLIC_PHRASE);
    CHECK(gzw_phrase_check(other) == GZW_PHRASE_ERR_WORD_COUNT);

    /* A 12-word phrase has 4 checksum bits: of the 2048 possible last words
       exactly 2048/16 = 128 give a valid phrase. */
    valid = 0;
    for (int w = 0; w < 2048; w++) {
        snprintf(other, sizeof(other),
                 "abandon abandon abandon abandon abandon abandon abandon abandon "
                 "abandon abandon abandon %s", bip39_wordlist_en[w]);
        valid += (gzw_phrase_check(other) == GZW_PHRASE_OK);
    }
    CHECK(valid == 128);

    /* Seeds. */
    CHECK(gzw_phrase_to_seed(PUBLIC_PHRASE, NULL, seed));
    CHECK(gzw_phrase_to_seed(PUBLIC_PHRASE, "", seed2));
    CHECK(memcmp(seed, seed2, 64) == 0);
    /* Extra whitespace does not change the seed. */
    snprintf(other, sizeof(other), "  %s\n", PUBLIC_PHRASE);
    CHECK(gzw_phrase_to_seed(other, NULL, seed2));
    CHECK(memcmp(seed, seed2, 64) == 0);
    /* A passphrase does. */
    CHECK(gzw_phrase_to_seed(PUBLIC_PHRASE, "x", seed2));
    CHECK(memcmp(seed, seed2, 64) != 0);
    /* An invalid phrase gives no seed at all. */
    memset(seed2, 0xff, 64);
    CHECK(!gzw_phrase_to_seed("abandon abandon abandon abandon abandon abandon "
                              "abandon abandon abandon abandon abandon abandon",
                              NULL, seed2));
    CHECK(all_zero(seed2, 64));
    CHECK(!gzw_phrase_to_seed(NULL, NULL, seed2));
    /* A passphrase that would need Unicode normalisation is refused. */
    CHECK(!gzw_phrase_to_seed(PUBLIC_PHRASE, "caf\xc3\xa9", seed2));
    CHECK(all_zero(seed2, 64));

    CHECK(strcmp(gzw_phrase_status_text(GZW_PHRASE_OK), "valid") == 0);
    CHECK(gzw_phrase_status_text(GZW_PHRASE_ERR_CHECKSUM) != NULL);
}

/* ---- BIP 32 --------------------------------------------------------------- */

static void test_bip32(const secp256k1_context *ctx) {
    unsigned char seed[64];
    gzw_xprv master, a, b, c;
    gzw_xpub master_pub, pa, pb;
    char s1[GZW_XKEY_STR_MAX], s2[GZW_XKEY_STR_MAX];
    int mainnet = -1;
    uint32_t path[3] = {86u | GZW_HARDENED, 1u | GZW_HARDENED, 0u | GZW_HARDENED};

    for (size_t i = 0; i < 64; i++) seed[i] = (unsigned char)(255 - i);

    /* Seed length limits. */
    CHECK(!gzw_bip32_master(ctx, seed, 15, &master, NULL));
    CHECK(all_zero(&master, sizeof(master)));
    CHECK(!gzw_bip32_master(ctx, seed, 65, &master, NULL));
    CHECK(!gzw_bip32_master(ctx, NULL, 32, &master, NULL));
    CHECK(!gzw_bip32_master(NULL, seed, 32, &master, NULL));
    CHECK(gzw_bip32_master(ctx, seed, 16, &master, NULL));
    CHECK(gzw_bip32_master(ctx, seed, 64, &master, NULL));
    CHECK(master.depth == 0 && master.child_number == 0);
    CHECK(all_zero(master.parent_fingerprint, 4));
    CHECK(gzw_bip32_neuter(ctx, &master, &master_pub));

    /* Hardened and non-hardened children of the same number differ. */
    CHECK(gzw_bip32_child_priv(ctx, &master, 5, &a, NULL));
    CHECK(gzw_bip32_child_priv(ctx, &master, 5u | GZW_HARDENED, &b, NULL));
    CHECK(memcmp(a.key, b.key, 32) != 0);
    CHECK(memcmp(a.chain_code, b.chain_code, 32) != 0);
    CHECK(a.depth == 1 && a.child_number == 5);
    CHECK(b.child_number == (5u | GZW_HARDENED));
    CHECK(memcmp(a.parent_fingerprint, b.parent_fingerprint, 4) == 0);
    CHECK(!all_zero(a.parent_fingerprint, 4));

    /* Public derivation gives the public key of private derivation, for many
       indexes and at two depths. */
    for (uint32_t i = 0; i < 40; i++) {
        uint32_t idx = (i < 38) ? i : (i == 38 ? 0x7fffffffu : 1000000000u);
        CHECK(gzw_bip32_child_priv(ctx, &master, idx, &a, NULL));
        CHECK(gzw_bip32_neuter(ctx, &a, &pa));
        CHECK(gzw_bip32_child_pub(ctx, &master_pub, idx, &pb, NULL));
        CHECK(memcmp(&pa.pubkey, &pb.pubkey, 33) == 0);
        CHECK(memcmp(pa.chain_code, pb.chain_code, 32) == 0);
        CHECK(pa.depth == pb.depth && pa.child_number == pb.child_number);
        CHECK(memcmp(pa.parent_fingerprint, pb.parent_fingerprint, 4) == 0);
        /* one level further */
        CHECK(gzw_bip32_child_priv(ctx, &a, idx ^ 1u, &c, NULL));
        CHECK(gzw_bip32_neuter(ctx, &c, &pa));
        CHECK(gzw_bip32_child_pub(ctx, &pb, idx ^ 1u, &pb, NULL));
        CHECK(gzw_xpub_to_string(&pa, GZW_NET_SIGNET, s1) && gzw_xpub_to_string(&pb, GZW_NET_SIGNET, s2));
        CHECK(strcmp(s1, s2) == 0);
    }

    /* No hardened child from a public key. */
    memset(&pb, 0xff, sizeof(pb));
    CHECK(!gzw_bip32_child_pub(ctx, &master_pub, GZW_HARDENED, &pb, NULL));
    CHECK(all_zero(&pb, sizeof(pb)));
    CHECK(!gzw_bip32_child_pub(ctx, &master_pub, 0xffffffffu, &pb, NULL));
    CHECK(!gzw_bip32_derive_pub(ctx, &master_pub, path, 3, &pb, NULL));
    /* A public key that is not on the curve is refused. */
    pa = master_pub;
    memset(pa.pubkey + 1, 0, 32);
    pa.pubkey[32] = 7; /* x = 7 has no point, as in BIP 32 test vector 5 */
    CHECK(!gzw_bip32_child_pub(ctx, &pa, 0, &pb, NULL));

    /* Depth cannot pass 255. */
    a = master;
    a.depth = 255;
    CHECK(!gzw_bip32_child_priv(ctx, &a, 0, &b, NULL));
    CHECK(all_zero(&b, sizeof(b)));
    CHECK(gzw_bip32_neuter(ctx, &a, &pa));
    CHECK(!gzw_bip32_child_pub(ctx, &pa, 0, &pb, NULL));

    /* An invalid parent key (zero) is refused. */
    a = master;
    memset(a.key, 0, 32);
    CHECK(!gzw_bip32_child_priv(ctx, &a, 0, &b, NULL));
    CHECK(!gzw_bip32_neuter(ctx, &a, &pa));

    /* derive_priv equals the steps one by one, and may write over its input. */
    CHECK(gzw_bip32_child_priv(ctx, &master, path[0], &a, NULL));
    CHECK(gzw_bip32_child_priv(ctx, &a, path[1], &a, NULL));
    CHECK(gzw_bip32_child_priv(ctx, &a, path[2], &a, NULL));
    CHECK(gzw_bip32_derive_priv(ctx, &master, path, 3, &b, NULL));
    CHECK(memcmp(a.key, b.key, 32) == 0 && memcmp(a.chain_code, b.chain_code, 32) == 0);
    CHECK(b.depth == 3 && b.child_number == path[2]);
    CHECK(gzw_bip32_derive_priv(ctx, &master, path, 0, &b, NULL));
    CHECK(memcmp(b.key, master.key, 32) == 0);

    /* Test-network key text. */
    CHECK(gzw_xprv_to_string(&a, GZW_NET_SIGNET, s1));
    CHECK(strncmp(s1, "tprv", 4) == 0 && strlen(s1) == 111);
    CHECK(gzw_xprv_from_string(ctx, s1, &b, &mainnet) && mainnet == 0);
    CHECK(memcmp(a.key, b.key, 32) == 0 && b.depth == 3 &&
          b.child_number == a.child_number);
    CHECK(gzw_xprv_to_string(&a, GZW_NET_MAINNET, s2) && strncmp(s2, "xprv", 4) == 0);
    CHECK(gzw_bip32_neuter(ctx, &a, &pa));
    CHECK(gzw_xpub_to_string(&pa, GZW_NET_SIGNET, s1));
    CHECK(strncmp(s1, "tpub", 4) == 0 && strlen(s1) == 111);
    CHECK(gzw_xpub_from_string(ctx, s1, &pb, &mainnet) && mainnet == 0);
    CHECK(memcmp(pa.pubkey, pb.pubkey, 33) == 0);
    CHECK(gzw_xpub_to_string(&pa, GZW_NET_MAINNET, s2) && strncmp(s2, "xpub", 4) == 0);
    CHECK(gzw_xpub_from_string(ctx, s2, &pb, &mainnet) && mainnet == 1);

    /* Any single wrong character in the key text is refused (checksum). */
    {
        static const char alphabet[] =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        int accepted = 0;
        size_t len = strlen(s1);
        for (size_t i = 0; i < len; i++) {
            char keep = s1[i];
            for (size_t k = 0; k < 58; k += 7) {
                if (alphabet[k] == keep) continue;
                s1[i] = alphabet[k];
                accepted += gzw_xpub_from_string(ctx, s1, &pb, NULL);
            }
            s1[i] = keep;
        }
        CHECK(accepted == 0);
        CHECK(gzw_xpub_from_string(ctx, s1, &pb, NULL));
        s1[len - 1] = '\0'; /* truncated */
        CHECK(!gzw_xpub_from_string(ctx, s1, &pb, NULL));
        CHECK(!gzw_xpub_from_string(ctx, "", &pb, NULL));
        CHECK(!gzw_xpub_from_string(ctx, "tpub0OIl", &pb, NULL));
        CHECK(!gzw_xpub_from_string(ctx, NULL, &pb, NULL));
    }

    /* A master key cannot be written with a parent or an index. */
    b = master;
    b.child_number = 1;
    CHECK(!gzw_xprv_to_string(&b, GZW_NET_SIGNET, s1));
    CHECK(all_zero(s1, sizeof(s1)));

    /* Path text. */
    {
        uint32_t p5[5] = {86u | GZW_HARDENED, 1u | GZW_HARDENED, GZW_HARDENED, 1,
                          0x7fffffffu};
        char text[GZW_PATH_STR_MAX], small[8];
        CHECK(gzw_path_to_string(p5, 5, text, sizeof(text)));
        CHECK(strcmp(text, "m/86'/1'/0'/1/2147483647") == 0);
        CHECK(gzw_path_to_string(p5, 0, text, sizeof(text)) && strcmp(text, "m") == 0);
        CHECK(!gzw_path_to_string(p5, 5, small, sizeof(small)));
    }

    /* What the imported hd_key.c does.  Its master key and its hardened step
       agree with BIP 32; it has no non-hardened step, so it cannot reach a
       BIP 86 address. */
    {
        unsigned char mk[32], mc[32], ck[32], cc[32];
        CHECK(hd_key_from_seed(seed, 64, mk, mc));
        CHECK(memcmp(mk, master.key, 32) == 0 && memcmp(mc, master.chain_code, 32) == 0);
        CHECK(hd_key_derive_child(mk, mc, 86u | HD_HARDENED, ck, cc));
        CHECK(gzw_bip32_child_priv(ctx, &master, 86u | GZW_HARDENED, &b, NULL));
        CHECK(memcmp(ck, b.key, 32) == 0 && memcmp(cc, b.chain_code, 32) == 0);
        CHECK(hd_key_derive_path(seed, 64, "m/86'/1'/0'", ck));
        CHECK(memcmp(ck, a.key, 32) == 0);
        CHECK(!hd_key_derive_child(mk, mc, 0, ck, cc));
        CHECK(!hd_key_derive_path(seed, 64, "m/86'/1'/0'/0/0", ck));
    }

    gzw_wipe(&master, sizeof(master));
    gzw_wipe(&a, sizeof(a));
    gzw_wipe(&b, sizeof(b));
    gzw_wipe(&c, sizeof(c));
}

/* ---- networks and addresses ----------------------------------------------- */

static void test_networks(void) {
    static const struct {
        gzw_network net;
        const char *name, *hrp;
        uint32_t coin;
    } want[] = {
        {GZW_NET_MAINNET, "mainnet", "bc", 0},
        {GZW_NET_TESTNET, "testnet", "tb", 1},
        {GZW_NET_TESTNET4, "testnet4", "tb", 1},
        {GZW_NET_SIGNET, "signet", "tb", 1},
        {GZW_NET_REGTEST, "regtest", "bcrt", 1},
    };
    gzw_network net;
    uint32_t coin = 99, path[5];

    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        CHECK(gzw_network_from_name(want[i].name, &net) && net == want[i].net);
        CHECK(strcmp(gzw_network_name(want[i].net), want[i].name) == 0);
        CHECK(strcmp(gzw_network_hrp(want[i].net), want[i].hrp) == 0);
        CHECK(gzw_network_coin_type(want[i].net, &coin) && coin == want[i].coin);
        CHECK(gzw_bip86_path(want[i].net, 2, 1, 3, path));
        CHECK(path[0] == (86u | GZW_HARDENED));
        CHECK(path[1] == (want[i].coin | GZW_HARDENED));
        CHECK(path[2] == (2u | GZW_HARDENED));
        CHECK(path[3] == 1 && path[4] == 3);
    }
    CHECK(!gzw_network_from_name("Signet", &net));
    CHECK(!gzw_network_from_name("main", &net));
    CHECK(!gzw_network_from_name("", &net));
    CHECK(!gzw_network_from_name(NULL, &net));
    CHECK(gzw_network_name((gzw_network)17) == NULL);
    CHECK(gzw_network_hrp((gzw_network)17) == NULL);
    CHECK(!gzw_network_coin_type((gzw_network)17, &coin));

    /* Path limits. */
    CHECK(!gzw_bip86_path(GZW_NET_SIGNET, 0x80000000u, 0, 0, path));
    CHECK(!gzw_bip86_path(GZW_NET_SIGNET, 0, 2, 0, path));
    CHECK(!gzw_bip86_path(GZW_NET_SIGNET, 0, 0, 0x80000000u, path));
    CHECK(!gzw_bip86_path((gzw_network)17, 0, 0, 0, path));
    CHECK(gzw_bip86_path(GZW_NET_SIGNET, 0x7fffffffu, 1, 0x7fffffffu, path));
}

static void test_addresses(void) {
    static const gzw_network nets[] = {GZW_NET_MAINNET, GZW_NET_TESTNET,
                                       GZW_NET_TESTNET4, GZW_NET_SIGNET,
                                       GZW_NET_REGTEST};
    static const char charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    unsigned char key[32], back[32], prog[40];
    char addr[GZW_ADDRESS_MAX], mut[GZW_ADDRESS_MAX + 2];
    size_t plen;
    int version;

    for (size_t i = 0; i < 32; i++) key[i] = (unsigned char)(0x10 + i * 5);

    for (size_t n = 0; n < 5; n++) {
        const char *hrp = gzw_network_hrp(nets[n]);
        size_t hrp_len = strlen(hrp);
        CHECK(gzw_p2tr_address(nets[n], key, addr));
        /* prefix, separator, and 'p' for witness version 1 */
        CHECK(strncmp(addr, hrp, hrp_len) == 0 && addr[hrp_len] == '1' &&
              addr[hrp_len + 1] == 'p');
        CHECK(strlen(addr) == hrp_len + 1 + 1 + 52 + 6);
        CHECK(gzw_p2tr_address_decode(nets[n], addr, back));
        CHECK(memcmp(back, key, 32) == 0);
        /* Another network's address is refused when the prefix differs. */
        for (size_t m = 0; m < 5; m++) {
            int same_prefix = strcmp(hrp, gzw_network_hrp(nets[m])) == 0;
            CHECK(gzw_p2tr_address_decode(nets[m], addr, back) == same_prefix);
        }
    }
    CHECK(!gzw_p2tr_address((gzw_network)17, key, addr));

    /* Every single wrong character anywhere in an address is refused. */
    {
        int accepted = 0;
        size_t len;
        CHECK(gzw_p2tr_address(GZW_NET_SIGNET, key, addr));
        len = strlen(addr);
        for (size_t i = 0; i < len; i++) {
            for (size_t k = 0; k < 32; k++) {
                memcpy(mut, addr, len + 1);
                if (mut[i] == charset[k]) continue;
                mut[i] = charset[k];
                accepted += gzw_p2tr_address_decode(GZW_NET_SIGNET, mut, back);
            }
        }
        CHECK(accepted == 0);
        /* Two neighbouring characters swapped. */
        for (size_t i = 0; i + 1 < len; i++) {
            memcpy(mut, addr, len + 1);
            if (mut[i] == mut[i + 1]) continue;
            mut[i] = addr[i + 1];
            mut[i + 1] = addr[i];
            accepted += gzw_p2tr_address_decode(GZW_NET_SIGNET, mut, back);
        }
        CHECK(accepted == 0);
        /* Truncated and extended. */
        memcpy(mut, addr, len + 1);
        mut[len - 1] = '\0';
        CHECK(!gzw_p2tr_address_decode(GZW_NET_SIGNET, mut, back));
        memcpy(mut, addr, len);
        mut[len] = 'q';
        mut[len + 1] = '\0';
        CHECK(!gzw_p2tr_address_decode(GZW_NET_SIGNET, mut, back));
        /* All upper case is the same address; mixed case is refused. */
        memcpy(mut, addr, len + 1);
        for (size_t i = 0; i < len; i++)
            if (mut[i] >= 'a' && mut[i] <= 'z') mut[i] = (char)(mut[i] - 32);
        CHECK(gzw_p2tr_address_decode(GZW_NET_SIGNET, mut, back));
        CHECK(memcmp(back, key, 32) == 0);
        mut[0] = 't';
        CHECK(!gzw_p2tr_address_decode(GZW_NET_SIGNET, mut, back));
    }

    /* A valid segwit address that is not taproot is not a taproot address. */
    CHECK(gzw_segwit_address_encode("tb", 0, key, 32, addr));
    CHECK(gzw_segwit_address_decode("tb", addr, &version, prog, &plen));
    CHECK(version == 0 && plen == 32);
    CHECK(!gzw_p2tr_address_decode(GZW_NET_SIGNET, addr, back));
    CHECK(gzw_segwit_address_encode("tb", 1, key, 20, addr));
    CHECK(!gzw_p2tr_address_decode(GZW_NET_SIGNET, addr, back));
    CHECK(gzw_segwit_address_encode("tb", 2, key, 32, addr));
    CHECK(!gzw_p2tr_address_decode(GZW_NET_SIGNET, addr, back));

    /* Encoder refusals. */
    CHECK(!gzw_segwit_address_encode("tb", 17, key, 32, addr));
    CHECK(!gzw_segwit_address_encode("tb", -1, key, 32, addr));
    CHECK(!gzw_segwit_address_encode("tb", 1, key, 1, addr));
    CHECK(!gzw_segwit_address_encode("tb", 1, key, 41, addr));
    CHECK(!gzw_segwit_address_encode("tb", 0, key, 21, addr));
    CHECK(!gzw_segwit_address_encode("", 1, key, 32, addr));
    CHECK(!gzw_segwit_address_encode("TB", 1, key, 32, addr));
    CHECK(!gzw_segwit_address_encode(NULL, 1, key, 32, addr));

    /* scriptPubKey layout. */
    {
        unsigned char spk[34];
        CHECK(gzw_p2tr_script_pubkey(key, spk));
        CHECK(spk[0] == 0x51 && spk[1] == 0x20 && memcmp(spk + 2, key, 32) == 0);
    }
}

/* ---- BIP 86 on the test networks ------------------------------------------ */

static void test_bip86(const secp256k1_context *ctx) {
    static const gzw_network tb_nets[] = {GZW_NET_TESTNET, GZW_NET_TESTNET4,
                                          GZW_NET_SIGNET};
    gzw_xprv master, acct;
    gzw_xpub acct_pub, parsed, wrong;
    gzw_bip86_output o, o2;
    char str[GZW_XKEY_STR_MAX], hex[69], text[GZW_PATH_STR_MAX];
    int mainnet = -1;

    CHECK(public_master(ctx, &master));

    /* Account key on a test network. */
    CHECK(gzw_bip86_account_xpub(ctx, &master, GZW_NET_SIGNET, 0, &acct_pub, NULL));
    CHECK(acct_pub.depth == 3 && acct_pub.child_number == GZW_HARDENED);
    CHECK(gzw_xpub_to_string(&acct_pub, GZW_NET_SIGNET, str));
    CHECK(strcmp(str, REF_TEST_ACCOUNT_TPUB) == 0);
    CHECK(gzw_xpub_from_string(ctx, REF_TEST_ACCOUNT_TPUB, &parsed, &mainnet));
    CHECK(mainnet == 0);

    for (size_t i = 0; i < sizeof(REF_TEST) / sizeof(REF_TEST[0]); i++) {
        uint32_t ch = REF_TEST[i].change, idx = REF_TEST[i].index;
        for (size_t n = 0; n < 3; n++) {
            CHECK(gzw_bip86_output_from_master(ctx, &master, tb_nets[n], 0, ch, idx, &o, NULL));
            CHECK(strcmp(o.address, REF_TEST[i].tb_address) == 0);
            to_hex(o.script_pubkey, 34, hex);
            CHECK(strcmp(hex, REF_TEST[i].script_pubkey_hex) == 0);
            CHECK(o.path[1] == (1u | GZW_HARDENED));
            /* The same from the account public key alone. */
            CHECK(gzw_bip86_output_from_xpub(ctx, &parsed, tb_nets[n], 0, ch, idx, &o2, NULL));
            CHECK(strcmp(o2.address, REF_TEST[i].tb_address) == 0);
            CHECK(memcmp(o.output_key, o2.output_key, 32) == 0);
            CHECK(memcmp(o.internal_key, o2.internal_key, 32) == 0);
        }
        CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_REGTEST, 0, ch, idx, &o, NULL));
        CHECK(strcmp(o.address, REF_TEST[i].bcrt_address) == 0);
        to_hex(o.script_pubkey, 34, hex);
        CHECK(strcmp(hex, REF_TEST[i].script_pubkey_hex) == 0);
        /* Mainnet uses another coin type, so another key altogether. */
        CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_MAINNET, 0, ch, idx, &o2, NULL));
        CHECK(memcmp(o.output_key, o2.output_key, 32) != 0);
        CHECK(strncmp(o2.address, "bc1p", 4) == 0);
    }

    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 0, 0, &o, NULL));
    CHECK(gzw_path_to_string(o.path, 5, text, sizeof(text)));
    CHECK(strcmp(text, "m/86'/1'/0'/0/0") == 0);
    /* The output key is not the internal key: the tweak was applied. */
    CHECK(memcmp(o.output_key, o.internal_key, 32) != 0);
    CHECK(o.script_pubkey[0] == 0x51 && o.script_pubkey[1] == 0x20);
    CHECK(memcmp(o.script_pubkey + 2, o.output_key, 32) == 0);

    /* Account, change and index each select a different output. */
    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 1, 0, 0, &o2, NULL));
    CHECK(strcmp(o.address, o2.address) != 0 && o2.path[2] == (1u | GZW_HARDENED));
    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 1, 0, &o2, NULL));
    CHECK(strcmp(o.address, o2.address) != 0);
    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 0, 1, &o2, NULL));
    CHECK(strcmp(o.address, o2.address) != 0);

    /* Refusals. */
    memset(&o2, 0xff, sizeof(o2));
    CHECK(!gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 2, 0, &o2, NULL));
    CHECK(all_zero(&o2, sizeof(o2)));
    CHECK(!gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0x80000000u, 0, 0, &o2, NULL));
    CHECK(!gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 0, 0x80000000u, &o2, NULL));
    /* Not a master key. */
    CHECK(gzw_bip86_account_xprv(ctx, &master, GZW_NET_SIGNET, 0, &acct, NULL));
    CHECK(!gzw_bip86_output_from_master(ctx, &acct, GZW_NET_SIGNET, 0, 0, 0, &o2, NULL));
    {
        gzw_xprv again;
        CHECK(!gzw_bip86_account_xprv(ctx, &acct, GZW_NET_SIGNET, 0, &again, NULL));
        CHECK(all_zero(&again, sizeof(again)));
    }
    /* Not an account key, or the wrong account. */
    CHECK(gzw_bip32_neuter(ctx, &master, &wrong));
    CHECK(!gzw_bip86_output_from_xpub(ctx, &wrong, GZW_NET_SIGNET, 0, 0, 0, &o2, NULL));
    CHECK(!gzw_bip86_output_from_xpub(ctx, &acct_pub, GZW_NET_SIGNET, 1, 0, 0, &o2, NULL));
    CHECK(all_zero(&o2, sizeof(o2)));

    /* An internal key that is not on the curve has no output key. */
    {
        unsigned char bad[32] = {0}, q[32];
        bad[31] = 7;
        memset(q, 0xff, 32);
        CHECK(!gzw_taproot_output_key(ctx, bad, q, NULL));
        CHECK(all_zero(q, 32));
    }

    gzw_wipe(&master, sizeof(master));
    gzw_wipe(&acct, sizeof(acct));
}

/* ---- key-path signing key ------------------------------------------------- */

static void test_signing(const secp256k1_context *ctx) {
    static const unsigned char tag[] = "gazpacho/test";
    static const unsigned char text[] = "a message to sign with the output key";
    gzw_xprv master, leaf;
    gzw_xpub leaf_pub;
    gzw_bip86_output o;
    secp256k1_keypair kp, untweaked;
    secp256k1_xonly_pubkey q, p;
    unsigned char msg[32], msg2[32], sig[64], sig2[64], aux[32], q_from_addr[32];
    int seen_even = 0, seen_odd = 0;

    CHECK(public_master(ctx, &master));
    CHECK(secp256k1_tagged_sha256(ctx, msg, tag, sizeof(tag) - 1, text, sizeof(text) - 1));
    memcpy(msg2, msg, 32);
    msg2[0] ^= 1;
    memset(aux, 0x42, sizeof(aux));

    for (uint32_t index = 0; index < 16; index++) {
        CHECK(gzw_bip86_tweaked_keypair(ctx, &master, GZW_NET_SIGNET, 0, 0, index, &kp, &o, NULL));

        /* Take the key to verify against from the address itself. */
        CHECK(gzw_p2tr_address_decode(GZW_NET_SIGNET, o.address, q_from_addr));
        CHECK(memcmp(q_from_addr, o.output_key, 32) == 0);
        CHECK(secp256k1_xonly_pubkey_parse(ctx, &q, q_from_addr));

        /* BIP 340 signature with the tweaked pair verifies under the output key. */
        CHECK(secp256k1_schnorrsig_sign32(ctx, sig, msg, &kp, aux));
        CHECK(secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &q));
        /* ...and not for another message, nor under the internal key. */
        CHECK(!secp256k1_schnorrsig_verify(ctx, sig, msg2, 32, &q));
        CHECK(secp256k1_xonly_pubkey_parse(ctx, &p, o.internal_key));
        CHECK(!secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &p));

        /* A signature made with the untweaked key does not spend the output. */
        CHECK(gzw_bip32_derive_priv(ctx, &master, o.path, 5, &leaf, NULL));
        CHECK(secp256k1_keypair_create(ctx, &untweaked, leaf.key));
        CHECK(secp256k1_schnorrsig_sign32(ctx, sig2, msg, &untweaked, aux));
        CHECK(!secp256k1_schnorrsig_verify(ctx, sig2, msg, 32, &q));
        CHECK(secp256k1_schnorrsig_verify(ctx, sig2, msg, 32, &p));

        /* Both parities of the internal key must be exercised: when the
           derived point has odd Y the private key is negated before tweaking. */
        CHECK(gzw_bip32_neuter(ctx, &leaf, &leaf_pub));
        if (leaf_pub.pubkey[0] == 0x02) seen_even = 1;
        if (leaf_pub.pubkey[0] == 0x03) seen_odd = 1;
    }
    CHECK(seen_even && seen_odd);

    /* Change outputs too, and output_out may be NULL. */
    CHECK(gzw_bip86_tweaked_keypair(ctx, &master, GZW_NET_SIGNET, 0, 1, 3, &kp, NULL, NULL));
    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 1, 3, &o, NULL));
    CHECK(secp256k1_xonly_pubkey_parse(ctx, &q, o.output_key));
    CHECK(secp256k1_schnorrsig_sign32(ctx, sig, msg, &kp, aux));
    CHECK(secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &q));

    /* On refusal nothing is left in the outputs. */
    memset(&kp, 0xff, sizeof(kp));
    memset(&o, 0xff, sizeof(o));
    CHECK(!gzw_bip86_tweaked_keypair(ctx, &master, GZW_NET_SIGNET, 0, 2, 0, &kp, &o, NULL));
    CHECK(all_zero(&kp, sizeof(kp)) && all_zero(&o, sizeof(o)));
    memset(&kp, 0xff, sizeof(kp));
    CHECK(!gzw_bip86_tweaked_keypair(ctx, &leaf, GZW_NET_SIGNET, 0, 0, 0, &kp, NULL, NULL));
    CHECK(all_zero(&kp, sizeof(kp)));
    {
        unsigned char zero[32] = {0}, qout[32];
        memset(&kp, 0xff, sizeof(kp));
        CHECK(!gzw_taproot_tweak_seckey(ctx, zero, &kp, qout));
        CHECK(all_zero(&kp, sizeof(kp)));
    }

    gzw_wipe(&master, sizeof(master));
    gzw_wipe(&leaf, sizeof(leaf));
    gzw_wipe(&kp, sizeof(kp));
    gzw_wipe(&untweaked, sizeof(untweaked));
}

/* ---- cases added after the review of pull request 6 ------------------------ */

/* Bech32 checksum arithmetic, repeated here so that the test can build
   strings the library's own encoder refuses to make. */
static uint32_t t_polymod_step(uint32_t c, unsigned v) {
    unsigned c0 = c >> 25;
    c = ((c & 0x1ffffffu) << 5) ^ v;
    if (c0 & 1) c ^= 0x3b6a57b2u;
    if (c0 & 2) c ^= 0x26508e6du;
    if (c0 & 4) c ^= 0x1ea119fau;
    if (c0 & 8) c ^= 0x3d4233ddu;
    if (c0 & 16) c ^= 0x2a1462b3u;
    return c;
}

/* A correctly checksummed Bech32m string: hrp, '1', ndata symbols, checksum. */
static void t_make_bech32m(const char *hrp, size_t ndata, char *out) {
    static const char charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    size_t hrp_len = strlen(hrp), pos = 0;
    uint32_t c = 1;
    for (size_t i = 0; i < hrp_len; i++) c = t_polymod_step(c, (unsigned char)hrp[i] >> 5);
    c = t_polymod_step(c, 0);
    for (size_t i = 0; i < hrp_len; i++) c = t_polymod_step(c, (unsigned char)hrp[i] & 31);
    memcpy(out, hrp, hrp_len);
    pos = hrp_len;
    out[pos++] = '1';
    for (size_t i = 0; i < ndata; i++) {
        unsigned v = (unsigned)((i * 7 + 3) & 31);
        c = t_polymod_step(c, v);
        out[pos++] = charset[v];
    }
    for (int i = 0; i < 6; i++) c = t_polymod_step(c, 0);
    c ^= 0x2bc830a3u;
    for (int i = 0; i < 6; i++) out[pos++] = charset[(c >> (5 * (5 - i))) & 31];
    out[pos] = '\0';
}

static void test_bech32_length(void) {
    char s[256];
    /* Short prefix "a": 2 + ndata + 6 characters in all. */
    t_make_bech32m("a", 82, s);
    CHECK(strlen(s) == 90);
    CHECK(gzw_bech32_check(s) == GZW_BECH32_BECH32M); /* the builder is right */
    t_make_bech32m("a", 83, s);
    CHECK(strlen(s) == 91);
    CHECK(gzw_bech32_check(s) == GZW_BECH32_NONE); /* one character too long */
    t_make_bech32m("a", 120, s);
    CHECK(gzw_bech32_check(s) == GZW_BECH32_NONE);
    t_make_bech32m("tb", 200, s);
    CHECK(gzw_bech32_check(s) == GZW_BECH32_NONE);
    CHECK(gzw_bech32_check(NULL) == GZW_BECH32_NONE);
    CHECK(gzw_bech32_check("") == GZW_BECH32_NONE);
    /* A taproot-shaped address that is too long is not an address either. */
    {
        unsigned char prog[40];
        size_t plen = 0;
        int version = -1;
        t_make_bech32m("tb", 100, s);
        CHECK(!gzw_segwit_address_decode("tb", s, &version, prog, &plen));
    }
}

static void test_parity(const secp256k1_context *ctx) {
    gzw_xprv master;
    int seen[2] = {0, 0};

    CHECK(public_master(ctx, &master));
    for (uint32_t index = 0; index < 24; index++) {
        gzw_bip86_output o;
        secp256k1_keypair kp;
        secp256k1_pubkey full;
        unsigned char q[32], ser[33];
        size_t len = 33;
        int parity = -1;

        CHECK(gzw_bip86_tweaked_keypair(ctx, &master, GZW_NET_SIGNET, 0, 0, index, &kp, &o, NULL));
        CHECK(gzw_taproot_output_key(ctx, o.internal_key, q, &parity));
        CHECK(memcmp(q, o.output_key, 32) == 0);
        /* The full public key of the signing pair says which Y the output
           key has: 02 even, 03 odd. */
        CHECK(secp256k1_keypair_pub(ctx, &full, &kp));
        CHECK(secp256k1_ec_pubkey_serialize(ctx, ser, &len, &full, SECP256K1_EC_COMPRESSED));
        CHECK(parity == (ser[0] == 0x03));
        CHECK(parity == 0 || parity == 1);
        if (parity == 0 || parity == 1) seen[parity] = 1;
        CHECK(gzw_taproot_output_key(ctx, o.internal_key, q, NULL)); /* NULL allowed */
    }
    CHECK(seen[0] && seen[1]);
    gzw_wipe(&master, sizeof(master));
}

static void test_aliasing(const secp256k1_context *ctx) {
    gzw_xprv master, a, b;
    gzw_xpub pa, pb;
    unsigned char key[32], q[32], buf[34], sk[32], q2[32];
    secp256k1_keypair kp;
    uint32_t path[2] = {0, 3};

    CHECK(public_master(ctx, &master));

    /* Account key written over the master key it came from. */
    CHECK(gzw_bip86_account_xprv(ctx, &master, GZW_NET_SIGNET, 0, &a, NULL));
    b = master;
    CHECK(gzw_bip86_account_xprv(ctx, &b, GZW_NET_SIGNET, 0, &b, NULL));
    CHECK(memcmp(a.key, b.key, 32) == 0 && memcmp(a.chain_code, b.chain_code, 32) == 0);
    CHECK(b.depth == 3);
    /* ...and on failure the shared object is zeroed (b is no longer a master). */
    CHECK(!gzw_bip86_account_xprv(ctx, &b, GZW_NET_SIGNET, 0, &b, NULL));
    CHECK(all_zero(&b, sizeof(b)));

    /* Child and path derivation in place. */
    CHECK(gzw_bip32_derive_priv(ctx, &a, path, 2, &b, NULL));
    CHECK(gzw_bip32_derive_priv(ctx, &a, path, 2, &a, NULL));
    CHECK(memcmp(a.key, b.key, 32) == 0 && a.depth == 5);
    CHECK(gzw_bip32_neuter(ctx, &master, &pa));
    CHECK(gzw_bip32_derive_pub(ctx, &pa, path, 2, &pb, NULL));
    CHECK(gzw_bip32_derive_pub(ctx, &pa, path, 2, &pa, NULL));
    CHECK(memcmp(pa.pubkey, pb.pubkey, 33) == 0 && pa.depth == 2);
    /* In place and failing: the input is zeroed. */
    b = master;
    b.depth = 255;
    CHECK(!gzw_bip32_child_priv(ctx, &b, 0, &b, NULL));
    CHECK(all_zero(&b, sizeof(b)));
    CHECK(!gzw_bip32_child_pub(ctx, &pa, GZW_HARDENED, &pa, NULL));
    CHECK(all_zero(&pa, sizeof(pa)));

    /* Output key written over the internal key. */
    CHECK(gzw_bip32_neuter(ctx, &a, &pb));
    memcpy(key, pb.pubkey + 1, 32);
    CHECK(gzw_taproot_output_key(ctx, key, q, NULL));
    CHECK(memcmp(q, key, 32) != 0);
    CHECK(gzw_taproot_output_key(ctx, key, key, NULL));
    CHECK(memcmp(q, key, 32) == 0);

    /* Output key written over the private key it was made from. */
    memcpy(sk, a.key, 32);
    CHECK(gzw_taproot_tweak_seckey(ctx, sk, &kp, q2));
    CHECK(gzw_taproot_tweak_seckey(ctx, sk, &kp, sk));
    CHECK(memcmp(sk, q2, 32) == 0);
    CHECK(memcmp(q, q2, 32) == 0);

    /* scriptPubKey built in the buffer that holds the key. */
    memcpy(buf, q, 32);
    CHECK(gzw_p2tr_script_pubkey(buf, buf));
    CHECK(buf[0] == 0x51 && buf[1] == 0x20 && memcmp(buf + 2, q, 32) == 0);
    memcpy(buf + 2, q, 32);
    CHECK(gzw_p2tr_script_pubkey(buf + 2, buf));
    CHECK(buf[0] == 0x51 && buf[1] == 0x20 && memcmp(buf + 2, q, 32) == 0);

    /* NULL arguments of gzw_p2tr_script_pubkey. */
    memset(buf, 0xff, sizeof(buf));
    CHECK(!gzw_p2tr_script_pubkey(NULL, buf));
    CHECK(all_zero(buf, sizeof(buf)));
    CHECK(!gzw_p2tr_script_pubkey(q, NULL));
    CHECK(!gzw_p2tr_script_pubkey(NULL, NULL));

    gzw_wipe(&master, sizeof(master));
    gzw_wipe(&a, sizeof(a));
    gzw_wipe(&b, sizeof(b));
    gzw_wipe(&kp, sizeof(kp));
    gzw_wipe(sk, sizeof(sk));
}

static void test_reasons(const secp256k1_context *ctx) {
    unsigned char seed[32];
    gzw_xprv master, a, bad;
    gzw_xpub mp, pa, badp;
    gzw_bip86_output o;
    secp256k1_keypair kp;
    gzw_reason why;
    uint32_t hard_path[1] = {GZW_HARDENED};

    for (size_t i = 0; i < 32; i++) seed[i] = (unsigned char)(i + 1);

    why = GZW_REASON_INTERNAL;
    CHECK(gzw_bip32_master(ctx, seed, 32, &master, &why) && why == GZW_REASON_OK);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_master(ctx, seed, 15, &a, &why) && why == GZW_REASON_BAD_ARGUMENT);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_master(ctx, NULL, 32, &a, &why) && why == GZW_REASON_BAD_ARGUMENT);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_master(ctx, seed, 32, NULL, &why) && why == GZW_REASON_BAD_ARGUMENT);
    CHECK(gzw_bip32_neuter(ctx, &master, &mp));

    /* child_priv */
    why = GZW_REASON_INTERNAL;
    CHECK(gzw_bip32_child_priv(ctx, &master, 0, &a, &why) && why == GZW_REASON_OK);
    bad = master;
    bad.depth = 255;
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_child_priv(ctx, &bad, 0, &a, &why) && why == GZW_REASON_BAD_ARGUMENT);
    bad = master;
    memset(bad.key, 0, 32);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_child_priv(ctx, &bad, 0, &a, &why) && why == GZW_REASON_INVALID_KEY);
    memset(bad.key, 0xff, 32); /* not below the group order */
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_child_priv(ctx, &bad, GZW_HARDENED, &a, &why) &&
          why == GZW_REASON_INVALID_KEY);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_child_priv(ctx, NULL, 0, &a, &why) && why == GZW_REASON_BAD_ARGUMENT);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_derive_priv(ctx, &bad, hard_path, 1, &a, &why) &&
          why == GZW_REASON_INVALID_KEY);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_derive_priv(ctx, &master, NULL, 1, &a, &why) &&
          why == GZW_REASON_BAD_ARGUMENT);
    why = GZW_REASON_INTERNAL;
    CHECK(gzw_bip32_derive_priv(ctx, &master, hard_path, 1, &a, &why) && why == GZW_REASON_OK);

    /* child_pub */
    why = GZW_REASON_INTERNAL;
    CHECK(gzw_bip32_child_pub(ctx, &mp, 0, &pa, &why) && why == GZW_REASON_OK);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_child_pub(ctx, &mp, GZW_HARDENED, &pa, &why) &&
          why == GZW_REASON_BAD_ARGUMENT);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_derive_pub(ctx, &mp, hard_path, 1, &pa, &why) &&
          why == GZW_REASON_BAD_ARGUMENT);
    badp = mp;
    memset(badp.pubkey + 1, 0, 32);
    badp.pubkey[32] = 7; /* no point has x = 7 */
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_child_pub(ctx, &badp, 0, &pa, &why) && why == GZW_REASON_INVALID_KEY);
    badp = mp;
    badp.depth = 255;
    why = GZW_REASON_OK;
    CHECK(!gzw_bip32_child_pub(ctx, &badp, 0, &pa, &why) && why == GZW_REASON_BAD_ARGUMENT);

    /* BIP 86 layer */
    why = GZW_REASON_INTERNAL;
    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 0, 0, &o, &why) &&
          why == GZW_REASON_OK);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 2, 0, &o, &why) &&
          why == GZW_REASON_BAD_ARGUMENT);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip86_output_from_master(ctx, &a, GZW_NET_SIGNET, 0, 0, 0, &o, &why) &&
          why == GZW_REASON_BAD_ARGUMENT); /* a is not a master key */
    why = GZW_REASON_OK;
    CHECK(!gzw_bip86_output_from_master(ctx, &master, (gzw_network)17, 0, 0, 0, &o, &why) &&
          why == GZW_REASON_BAD_ARGUMENT);
    bad = master;
    memset(bad.key, 0, 32);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip86_output_from_master(ctx, &bad, GZW_NET_SIGNET, 0, 0, 0, &o, &why) &&
          why == GZW_REASON_INVALID_KEY);
    why = GZW_REASON_INTERNAL;
    CHECK(gzw_bip86_tweaked_keypair(ctx, &master, GZW_NET_SIGNET, 0, 0, 0, &kp, &o, &why) &&
          why == GZW_REASON_OK);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip86_tweaked_keypair(ctx, &master, GZW_NET_SIGNET, 0, 0, GZW_HARDENED, &kp,
                                     &o, &why) &&
          why == GZW_REASON_BAD_ARGUMENT);
    why = GZW_REASON_OK;
    CHECK(!gzw_bip86_account_xpub(ctx, &a, GZW_NET_SIGNET, 0, &pa, &why) &&
          why == GZW_REASON_BAD_ARGUMENT);
    why = GZW_REASON_INTERNAL;
    CHECK(gzw_bip86_account_xpub(ctx, &master, GZW_NET_SIGNET, 0, &pa, &why) &&
          why == GZW_REASON_OK);

    /* The account key rule of gzw_bip86_output_from_xpub: depth 3 exactly,
       and the right account. */
    why = GZW_REASON_INTERNAL;
    CHECK(gzw_bip86_output_from_xpub(ctx, &pa, GZW_NET_SIGNET, 0, 0, 0, &o, &why) &&
          why == GZW_REASON_OK);
    badp = pa;
    badp.depth = 4;
    why = GZW_REASON_OK;
    memset(&o, 0xff, sizeof(o));
    CHECK(!gzw_bip86_output_from_xpub(ctx, &badp, GZW_NET_SIGNET, 0, 0, 0, &o, &why) &&
          why == GZW_REASON_BAD_ARGUMENT);
    CHECK(all_zero(&o, sizeof(o)));
    badp.depth = 2;
    CHECK(!gzw_bip86_output_from_xpub(ctx, &badp, GZW_NET_SIGNET, 0, 0, 0, &o, NULL));
    badp.depth = 0;
    CHECK(!gzw_bip86_output_from_xpub(ctx, &badp, GZW_NET_SIGNET, 0, 0, 0, &o, NULL));
    why = GZW_REASON_OK;
    CHECK(!gzw_bip86_output_from_xpub(ctx, &pa, GZW_NET_SIGNET, 1, 0, 0, &o, &why) &&
          why == GZW_REASON_BAD_ARGUMENT);

    /* Every reason has its own fixed text. */
    {
        static const gzw_reason all[] = {GZW_REASON_OK, GZW_REASON_BAD_ARGUMENT,
                                         GZW_REASON_INVALID_KEY, GZW_REASON_INVALID_CHILD,
                                         GZW_REASON_INTERNAL};
        for (size_t i = 0; i < 5; i++) {
            CHECK(gzw_reason_text(all[i]) != NULL && gzw_reason_text(all[i])[0] != '\0');
            for (size_t j = i + 1; j < 5; j++)
                CHECK(strcmp(gzw_reason_text(all[i]), gzw_reason_text(all[j])) != 0);
        }
        CHECK(gzw_reason_text((gzw_reason)99) != NULL);
    }

    gzw_wipe(&master, sizeof(master));
    gzw_wipe(&a, sizeof(a));
    gzw_wipe(&bad, sizeof(bad));
    gzw_wipe(&kp, sizeof(kp));
}

static void test_key_text(const secp256k1_context *ctx) {
    static const gzw_network nets[] = {GZW_NET_MAINNET, GZW_NET_TESTNET, GZW_NET_TESTNET4,
                                       GZW_NET_SIGNET, GZW_NET_REGTEST};
    gzw_xprv master, back;
    gzw_xpub pub, pback, badp;
    char s[GZW_XKEY_STR_MAX], with_one[GZW_XKEY_STR_MAX + 2];
    int is_mainnet;

    CHECK(public_master(ctx, &master));
    CHECK(gzw_bip32_neuter(ctx, &master, &pub));

    /* The network picks the version bytes; it is not a yes/no flag.
       (GZW_NET_MAINNET is 0: with a flag, passing a network would invert it.) */
    for (size_t i = 0; i < 5; i++) {
        int want_main = (nets[i] == GZW_NET_MAINNET);
        CHECK(gzw_xprv_to_string(&master, nets[i], s));
        CHECK(strncmp(s, want_main ? "xprv" : "tprv", 4) == 0);
        is_mainnet = -1;
        CHECK(gzw_xprv_from_string(ctx, s, &back, &is_mainnet) && is_mainnet == want_main);
        CHECK(gzw_xpub_to_string(&pub, nets[i], s));
        CHECK(strncmp(s, want_main ? "xpub" : "tpub", 4) == 0);
        is_mainnet = -1;
        CHECK(gzw_xpub_from_string(ctx, s, &pback, &is_mainnet) && is_mainnet == want_main);
    }
    memset(s, 0x55, sizeof(s));
    CHECK(!gzw_xprv_to_string(&master, (gzw_network)17, s));
    CHECK(all_zero(s, sizeof(s)));
    memset(s, 0x55, sizeof(s));
    CHECK(!gzw_xpub_to_string(&pub, (gzw_network)17, s));
    CHECK(all_zero(s, sizeof(s)));
    CHECK(!gzw_xpub_to_string(&pub, (gzw_network)-1, s));

    /* A public key whose first byte is not 02 or 03 is not written. */
    {
        static const unsigned char bad_prefix[] = {0x00, 0x01, 0x04, 0x06, 0xff};
        for (size_t i = 0; i < sizeof(bad_prefix); i++) {
            badp = pub;
            badp.pubkey[0] = bad_prefix[i];
            memset(s, 0x55, sizeof(s));
            CHECK(!gzw_xpub_to_string(&badp, GZW_NET_SIGNET, s));
            CHECK(all_zero(s, sizeof(s)));
        }
    }

    /* Extra leading '1' characters stand for extra zero bytes in Base58, so
       the text is no longer an extended key. */
    CHECK(gzw_xpub_to_string(&pub, GZW_NET_SIGNET, s));
    CHECK(gzw_xpub_from_string(ctx, s, &pback, NULL));
    snprintf(with_one, sizeof(with_one), "1%s", s);
    CHECK(!gzw_xpub_from_string(ctx, with_one, &pback, NULL));
    CHECK(gzw_xprv_to_string(&master, GZW_NET_SIGNET, s));
    CHECK(gzw_xprv_from_string(ctx, s, &back, NULL));
    snprintf(with_one, sizeof(with_one), "1%s", s);
    CHECK(!gzw_xprv_from_string(ctx, with_one, &back, NULL));
    CHECK(all_zero(&back, sizeof(back)));

    gzw_wipe(&master, sizeof(master));
    gzw_wipe(&back, sizeof(back));
    gzw_wipe(s, sizeof(s));
    gzw_wipe(with_one, sizeof(with_one));
}

static void test_review_misc(const secp256k1_context *ctx) {
    unsigned char seed[64];
    gzw_xprv master;
    gzw_bip86_output t3, t4, sg;
    gzw_network net = GZW_NET_MAINNET;

    /* Passphrase bytes: 0x7f is the last one accepted, 0x80 the first refused. */
    CHECK(gzw_phrase_to_seed(PUBLIC_PHRASE, "\x7f", seed));
    memset(seed, 0xff, sizeof(seed));
    CHECK(!gzw_phrase_to_seed(PUBLIC_PHRASE, "\x80", seed));
    CHECK(all_zero(seed, sizeof(seed)));
    CHECK(!gzw_phrase_to_seed(PUBLIC_PHRASE, "a\x80", seed));
    CHECK(!gzw_phrase_to_seed(PUBLIC_PHRASE, "\xff", seed));

    /* testnet4 is a network of its own, although today it shares the address
       prefix and the coin type with testnet and signet, so the three give the
       same addresses for the same phrase. */
    CHECK(GZW_NET_TESTNET4 != GZW_NET_TESTNET && GZW_NET_TESTNET4 != GZW_NET_SIGNET);
    CHECK(gzw_network_from_name("testnet4", &net) && net == GZW_NET_TESTNET4);
    CHECK(gzw_network_from_name("testnet", &net) && net == GZW_NET_TESTNET);
    CHECK(strcmp(gzw_network_name(GZW_NET_TESTNET4), "testnet4") == 0);
    CHECK(strcmp(gzw_network_name(GZW_NET_TESTNET), "testnet") == 0);
    CHECK(!gzw_network_from_name("testnet3", &net));
    CHECK(!gzw_network_from_name("testnet-4", &net));
    CHECK(!gzw_network_from_name("testnet44", &net));
    CHECK(!gzw_network_from_name("testnet ", &net));
    CHECK(public_master(ctx, &master));
    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_TESTNET, 0, 0, 2, &t3, NULL));
    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_TESTNET4, 0, 0, 2, &t4, NULL));
    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 0, 2, &sg, NULL));
    CHECK(strcmp(t3.address, t4.address) == 0 && strcmp(t4.address, sg.address) == 0);
    CHECK(memcmp(t3.path, t4.path, sizeof(t3.path)) == 0);
    gzw_wipe(&master, sizeof(master));
}

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) {
        printf("FAIL: no secp256k1 context\n");
        return 1;
    }
    test_hygiene();
    test_phrase();
    test_bip32(ctx);
    test_networks();
    test_addresses();
    test_bip86(ctx);
    test_signing(ctx);
    test_bech32_length();
    test_parity(ctx);
    test_aliasing(ctx);
    test_reasons(ctx);
    test_key_text(ctx);
    test_review_misc(ctx);
    secp256k1_context_destroy(ctx);

    printf("test_wallet_keys: %d checks, %d failed\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
