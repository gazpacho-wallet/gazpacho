/* Section E of tools/spec-vectors.py (spec/storage-encryption.md 15),
 * reproduced byte for byte with libsodium 1.0.22: E0 to E15, and E2r with
 * the argument "e2r". Test 1 of spec 16. */
#include "sc_internal.h"
#include "sc_test.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

static const char PW1[] = "gazpacho test passphrase, never for coins: caf\xc3\xa9";
static const char PW1_NFD[] = "gazpacho test passphrase, never for coins: cafe\xcc\x81";
static const char PW2[] = "gazpacho second test passphrase, never for coins";
static const gz_sc_kdf_params_t TEST_P = {1, 3, 64, 1};

static uint8_t SALT1[16], SALT2[16], VAULT_ID[16], FILE_ID[16], MSK[32], ENTROPY[32];
static uint8_t pk1[32], pk2[32];
static uint8_t kf1[GZ_SC_KEYFILE_LEN], kf2[GZ_SC_KEYFILE_LEN];

static void ctx2(const uint8_t *a, const uint8_t *b, size_t bn, uint8_t *out)
{
    memcpy(out, a, 32);
    memcpy(out + 32, b, bn);
}

static void derive_hex(const char *what, const uint8_t *ikm, size_t n, const char *label, const uint8_t *ctx,
                       size_t cn, const char *hex)
{
    uint8_t k[32];
    CHECK_ERR(sc_derive(ikm, n, label, ctx, cn, k), GZ_SC_OK);
    eq_hex(what, k, 32, hex);
}

static gz_sc_err_t pk_of(const char *pw, const uint8_t salt[16], const gz_sc_kdf_params_t *p, uint8_t pk[32])
{
    uint8_t *nfc;
    size_t n, cp;
    gz_sc_err_t e = gz_sc_pass_nfc((const uint8_t *)pw, strlen(pw), &nfc, &n, &cp);
    if (e != GZ_SC_OK)
        return e;
    e = gz_sc_test_kdf_inprocess(NULL, nfc, n, salt, p, pk, NULL);
    gz_sc_sfree(nfc);
    return e;
}

/* spec 4.5's opening, as the program does it, with the KDF in process. */
static gz_sc_err_t open_kf(const uint8_t *kf, const char *pw, gz_sc_vault_t **v)
{
    gz_sc_keyfile_info_t info;
    gz_sc_err_t e = gz_sc_keyfile_parse(kf, GZ_SC_KEYFILE_LEN, SIGNET, &info);
    if (e != GZ_SC_OK)
        return e;
    uint8_t pk[32];
    if ((e = pk_of(pw, info.salt, &info.kdf, pk)) != GZ_SC_OK)
        return e;
    e = gz_sc_keyfile_unlock(kf, pk, v);
    sodium_memzero(pk, 32);
    return e;
}

static void e0(void)
{
    /* XChaCha 2.2.1 is HChaCha20; A.3.1 is the AEAD. */
    uint8_t k[32], n16[16], out[32];
    for (int i = 0; i < 32; i++)
        k[i] = (uint8_t)i;
    hx("000000090000004a0000000031415927", n16, 16);
    crypto_core_hchacha20(out, n16, k, NULL);
    eq_hex("E0 HChaCha20 2.2.1", out, 32, "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    static const char pt[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
                             "for the future, sunscreen would be it.";
    uint8_t key[32], ad[12], nonce24[24], nonce12[12], ct[sizeof pt - 1 + 16], back[sizeof pt];
    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)(0x80 + i);
    hx("50515253c0c1c2c3c4c5c6c7", ad, 12);
    hx("404142434445464748494a4b4c4d4e4f5051525354555657", nonce24, 24);
    unsigned long long cl, pl;
    crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &cl, (const uint8_t *)pt, sizeof pt - 1, ad, 12, NULL, nonce24, key);
    eq_hex("E0 XChaCha A.3.1 first 16", ct, 16, "bd6d179d3e83d43b9576579493c0e939");
    eq_hex("E0 XChaCha A.3.1 tag", ct + cl - 16, 16, "c0875924c1c7987947deafd8780acf49");
    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(back, &pl, NULL, ct, cl, ad, 12, nonce24, key) == 0 &&
          pl == sizeof pt - 1 && memcmp(back, pt, pl) == 0);
    hx("070000004041424344454647", nonce12, 12);
    crypto_aead_chacha20poly1305_ietf_encrypt(ct, &cl, (const uint8_t *)pt, sizeof pt - 1, ad, 12, NULL, nonce12, key);
    eq_hex("E0 RFC 8439 2.8.2 first 16", ct, 16, "d31a8d34648e60db7b86afbc53ef7ec2");
    eq_hex("E0 RFC 8439 2.8.2 tag", ct + cl - 16, 16, "1ae10b594f09e26a7e902ecbd0600691");
    /* RFC 5869 A.1 through crypto_kdf_hkdf_sha256. */
    uint8_t ikm[22], salt[13], info[10], prk[32], okm[42];
    memset(ikm, 0x0b, sizeof ikm);
    for (int i = 0; i < 13; i++)
        salt[i] = (uint8_t)i;
    for (int i = 0; i < 10; i++)
        info[i] = (uint8_t)(0xf0 + i);
    crypto_kdf_hkdf_sha256_extract(prk, salt, sizeof salt, ikm, sizeof ikm);
    crypto_kdf_hkdf_sha256_expand(okm, sizeof okm, (const char *)info, sizeof info, prk);
    eq_hex("E0 RFC 5869 A.1", okm, 42,
           "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

static void e1(void)
{
    uint8_t *a, *b;
    size_t an, bn, ac, bc;
    CHECK_ERR(gz_sc_pass_nfc((const uint8_t *)PW1, strlen(PW1), &a, &an, &ac), GZ_SC_OK);
    CHECK_ERR(gz_sc_pass_nfc((const uint8_t *)PW1_NFD, strlen(PW1_NFD), &b, &bn, &bc), GZ_SC_OK);
    CHECK(an == bn && memcmp(a, b, an) == 0 && ac == bc);
    eq_hex("E1", a, an,
           "67617a706163686f207465737420706173737068726173652c206e6576657220"
           "666f7220636f696e733a20636166c3a9");
    gz_sc_sfree(a);
    gz_sc_sfree(b);
}

static void e2_e3_e4(void)
{
    tv("kdf salt", SALT1, 16);
    tv("kdf salt 2", SALT2, 16);
    tv("vault id", VAULT_ID, 16);
    tv("journal file id", FILE_ID, 16);
    tv("storage key", MSK, 32);
    tv("words entropy", ENTROPY, 32);
    eq_hex("E2 salt", SALT1, 16, "db6c732c92598e0ec4c658b7addec256");
    CHECK_ERR(pk_of(PW1, SALT1, &TEST_P, pk1), GZ_SC_OK);
    eq_hex("E2 PK", pk1, 32, "bcc9248a9db077e01fbaa2a93f27041e128273dc0336872fe21f9f69c099904c");

    uint8_t ctx[48];
    ctx2(SIGNET, VAULT_ID, 16, ctx);
    derive_hex("E3 commitment key", pk1, 32, "key file commitment", ctx, 48,
               "00dc1f010ed6a82697cda31c3b9f538df68e56967233bebef437caecf58cbb44");
    derive_hex("E3 KW", pk1, 32, "key file wrap", ctx, 48,
               "c5bb964b729d73609b845b8c8620cc14cf9127fd8c15415b726f88727f0acabc");
    derive_hex("E3 KD", pk1, 32, "words", ctx, 48, "24487797d030cb76de0290e7fe5590ebcfcd399f5514158e30623e979906b743");
    derive_hex("E3 KS", MSK, 32, "node seed", ctx, 48,
               "7236c6a1da88ced5cb0de1d17d579e785177081ffe04a80fb3734c5b6288bee1");
    r_queue("key file wrap 1", "key file words 1", "key file seed", NULL);
    CHECK_ERR(gz_sc_keyfile_build(SIGNET, VAULT_ID, &TEST_P, SALT1, pk1, MSK, ENTROPY, SEED64, kf1), GZ_SC_OK);
    CHECK(r_left() == 0);
    r_os();
    eq_hex("E3 key file", kf1, sizeof kf1,
           "475a4b455946494c01f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42"
           "25e97398810800000058e8eff8fffdf8d50e058079eb04146501000000030000"
           "004001db6c732c92598e0ec4c658b7addec256f7ead7e5bfcd58d4590055a6d9"
           "f53000fa10f49bb2d3e546b47c43d7411132c46611fcc062b8f817fd206b6b8d"
           "664d14cb326a638d39a55f6d9725781dfe2ebfda6a10e61ac5ad4e5c89249587"
           "f0b22ee319b1d8722d02b00220f5adf8e344355bf93de8004188451e62b38c7a"
           "eeae8735cd00c056759663ca4f9e4b543981498e14e280f9cbdb3f9828e9a894"
           "de90e7439550bb0901ea3010bbac6feb0fc9571de3fa376d99c2457fb1d33c87"
           "2d91bf5fe219ef90549c9741a9c8ff5a3349af6036691511684a86495d4a227e"
           "5aed0e32ecaffb98c1bfb397f294ee51ea6c5fe6b151809e1e6efd403d50c937"
           "772b94294b517d05166c3977dceea32291a7eefc344ef7d1148b8526d67fbfd3"
           "ff6616110f9ee510357504");
    gz_sc_vault_t *v = NULL;
    CHECK_ERR(open_kf(kf1, PW1, &v), GZ_SC_OK);
    CHECK(v && gz_sc_vault_same_msk(v, MSK));
    uint8_t seed[64];
    if (v) {
        gz_sc_vault_seed(v, seed);
        CHECK(memcmp(seed, SEED64, 64) == 0);
    }
    gz_sc_vault_free(v);
    v = NULL;
    CHECK_ERR(open_kf(kf1, PW1_NFD, &v), GZ_SC_OK);
    gz_sc_vault_free(v);
    uint8_t ent[32];
    CHECK_ERR(gz_sc_keyfile_words(kf1, pk1, ent), GZ_SC_OK);
    CHECK(memcmp(ent, ENTROPY, 32) == 0);

    /* E4: refusals. */
    uint8_t bad[GZ_SC_KEYFILE_LEN];
    v = NULL;
    CHECK_ERR(open_kf(kf1, "gazpacho test passphrase, never for coins: caf\xc3\xa9 ", &v), GZ_SC_WRONG_PASSPHRASE);
    struct { int at; uint8_t x; int set; gz_sc_err_t want; } cases[] = {
        {65, 0x01, 0, GZ_SC_WRONG_PASSPHRASE},  /* m 64 -> 65 KiB */
        {61, 1, 1, GZ_SC_WRONG_PASSPHRASE},     /* t 3 -> 1 */
        {90, 0x01, 0, GZ_SC_WRONG_PASSPHRASE},  /* the commitment */
        {150, 0x01, 0, GZ_SC_WRONG_PASSPHRASE}, /* the wrapped MSK */
        {330, 0x80, 0, GZ_SC_DAMAGED},          /* the seed ciphertext */
        {9, 0x01, 0, GZ_SC_OTHER_NETWORK},      /* chain */
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        memcpy(bad, kf1, sizeof bad);
        if (cases[i].set)
            bad[cases[i].at] = cases[i].x;
        else
            bad[cases[i].at] ^= cases[i].x;
        v = NULL;
        CHECK_ERR(open_kf(bad, PW1, &v), cases[i].want);
        CHECK(v == NULL);
    }
    gz_sc_test_set_floor(3, 65536);
    CHECK_ERR(open_kf(kf1, PW1, &v), GZ_SC_PARAMS_REFUSED);
    gz_sc_test_set_floor(1, 8);
    memcpy(bad, kf1, sizeof bad);
    bad[62] = 0x00; bad[63] = 0x40; bad[64] = 0x00; bad[65] = 0x01; /* 4,194,305 KiB */
    CHECK_ERR(open_kf(bad, PW1, &v), GZ_SC_PARAMS_REFUSED);
}

static void e2r(void)
{
    gz_sc_kdf_params_t real = {1, 3, 262144, 1};
    uint8_t pk[32], salt[16];
    tv("kdf salt", salt, 16);
    CHECK_ERR(pk_of(PW1, salt, &real, pk), GZ_SC_OK);
    eq_hex("E2r PK at 256 MiB", pk, 32, "acfe7a0e9b72c011d3382684f2b9b06a221f61aeb29fe3382299419b6433c945");
}

/* ---- the journal: E5 to E7 ---- */
static uint8_t EJ[469];
static size_t ej_len;
static const size_t OFF_INC = 185, OFF_M1 = 254, OFF_B = 323, OFF_M2 = 400;
static const uint8_t PING[16] = {0, 0, 0, 1, 0x7e, 0x57, 0, 1, 0, 0, 0, 4, 'p', 'i', 'n', 'g'};

/* journal.md 5 steps 3 and 4 over sealed entries (the reference of spec-vectors.py). */
typedef struct {
    int state; /* 0 clean, 1 torn, 2 corrupt */
    size_t v;
    long last_mark;
    int n;
    uint8_t kinds[16];
    uint64_t incs[16];
    size_t offs[16];
} jstate_t;

static jstate_t read_j(const uint8_t *d, size_t len, const gz_sc_framekey_t *kj)
{
    jstate_t s;
    memset(&s, 0, sizeof s);
    s.last_mark = -1;
    size_t pos = GZ_SC_JHEADER_LEN;
    gz_sc_frame_t f;
    while (pos < len && gz_sc_frame_open(kj, d + pos, len - pos, pos, &f, NULL, 0) == GZ_SC_OK) {
        if (f.kind == 3)
            s.last_mark = (long)pos;
        if (s.n < 16) {
            s.kinds[s.n] = f.kind;
            s.incs[s.n] = f.incarnation;
            s.offs[s.n] = pos;
            s.n++;
        }
        pos += f.entry_len;
    }
    s.v = pos;
    if (pos == len)
        return s;
    s.state = 1;
    for (size_t p = pos + 1; p + 69 <= len; p++)
        if (d[p] == 0 && d[p + 1] == 0 && d[p + 2] == 0 && d[p + 3] == 65 && d[p + 4] == 3 &&
            gz_sc_frame_open(kj, d + p, len - p, p, NULL, NULL, 0) == GZ_SC_OK) {
            s.state = 2;
            break;
        }
    return s;
}

static jstate_t *view_state;
static int has_mark(void *ctx, uint64_t inc, uint64_t off)
{
    (void)ctx;
    for (int i = 0; i < view_state->n; i++)
        if (view_state->kinds[i] == 3 && view_state->incs[i] == inc && view_state->offs[i] == off)
            return 1;
    return 0;
}

static gz_sc_start_t start_against(const jstate_t *s, gz_sc_mark_state_t ms, uint64_t inc, uint64_t off)
{
    view_state = (jstate_t *)s;
    uint64_t hi = 0;
    for (int i = 0; i < s->n; i++)
        if (s->incs[i] > hi)
            hi = s->incs[i];
    gz_sc_journal_view_t j = {hi, has_mark, NULL, 0};
    return gz_sc_start_rule(ms, inc, off, GZ_SC_OK, 0, &j);
}

static void e5_to_e9m(void)
{
    gz_sc_vault_t *v = NULL;
    CHECK_ERR(gz_sc_vault_new(SIGNET, VAULT_ID, MSK, SEED64, &v), GZ_SC_OK);
    if (!v)
        return;
    uint8_t ctx[48];
    ctx2(SIGNET, FILE_ID, 16, ctx);
    derive_hex("E5 KJ", MSK, 32, "journal", ctx, 48, "8b6c75058abb5837cc5d7c069066cc9e4c67d523a725033616515e1cd5843875");
    derive_hex("E5 KJ nonce", MSK, 32, "journal nonce", ctx, 48,
               "84d9e143eb661f2650463cecd21818a6fff19f853343840e6f43d9f9b2cd82d8");
    derive_hex("E5 KR", SEED64, 64, "journal recovery", ctx, 48,
               "9de84e620aee3a44f7d2d7b7efe872b26c5b4d5f1da2b987011281af4f8676d3");
    r_queue("journal recovery", "journal header", NULL);
    CHECK_ERR(gz_sc_header_seal(v, FILE_ID, EJ), GZ_SC_OK);
    eq_hex("E5 header", EJ, GZ_SC_JHEADER_LEN,
           "475a4a4f55524e4501f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42"
           "25e97398810800000058e8eff8fffdf8d50e058079eb041465708bd86b189b21"
           "30142ec86d6c5a6f2280fd61ee3f0cf6d54d3f2e063c41fbc0e0118e7f220b5c"
           "00b31289aaebd4d8be3b480fd9e9ed402953e12c9f4d52e01b84cdb6fdd38872"
           "a35ca8084133fe27e796f5d62cfa19c6203a6b9c9eb29cf9d3ecf44c2a596884"
           "a1b83cc8341546dd0c58f9d91c806318e64fd77992dc9f295f");
    gz_sc_framekey_t *kj = NULL;
    CHECK_ERR(gz_sc_header_open(EJ, v, &kj), GZ_SC_OK);
    uint8_t msk[32], bad[GZ_SC_JHEADER_LEN];
    CHECK_ERR(gz_sc_header_recover(EJ, SIGNET, SEED64, msk), GZ_SC_OK);
    CHECK(memcmp(msk, MSK, 32) == 0);
    gz_sc_vault_t *other = NULL;
    uint8_t omsk[32];
    tv("other storage key", omsk, 32);
    gz_sc_vault_new(SIGNET, VAULT_ID, omsk, SEED64, &other);
    gz_sc_framekey_t *tmpk = NULL;
    CHECK_ERR(gz_sc_header_open(EJ, other, &tmpk), GZ_SC_NOT_THIS_WALLET);
    gz_sc_vault_free(other);
    memcpy(bad, EJ, sizeof bad);
    bad[50] ^= 1;
    CHECK_ERR(gz_sc_header_open(bad, v, &tmpk), GZ_SC_NOT_THIS_WALLET);
    CHECK_ERR(gz_sc_header_recover(bad, SIGNET, SEED64, msk), GZ_SC_NOT_THIS_WALLET);
    memcpy(bad, EJ, sizeof bad);
    bad[9] ^= 1;
    CHECK_ERR(gz_sc_header_open(bad, v, &tmpk), GZ_SC_OTHER_NETWORK);
    uint8_t oseed[64];
    crypto_hash_sha512(oseed, (const uint8_t *)"other", 5);
    CHECK_ERR(gz_sc_header_recover(EJ, SIGNET, oseed, msk), GZ_SC_NOT_THIS_WALLET);

    /* E6. */
    size_t n;
    uint8_t pl[8];
    sc_put64(pl, 1794000000000ull);
    r_queue("entry incarnation 1", "entry mark 1", "entry batch 1 1", "entry mark 2", NULL);
    CHECK_ERR(gz_sc_frame_seal(kj, OFF_INC, 1, 1, 0, pl, 8, EJ + OFF_INC, 69, &n), GZ_SC_OK);
    sc_put64(pl, OFF_M1);
    CHECK_ERR(gz_sc_frame_seal(kj, OFF_M1, 3, 1, 0, pl, 8, EJ + OFF_M1, 69, &n), GZ_SC_OK);
    CHECK_ERR(gz_sc_frame_seal(kj, OFF_B, 2, 1, 1, PING, 16, EJ + OFF_B, 77, &n), GZ_SC_OK);
    sc_put64(pl, OFF_M2);
    CHECK_ERR(gz_sc_frame_seal(kj, OFF_M2, 3, 1, 0, pl, 8, EJ + OFF_M2, 69, &n), GZ_SC_OK);
    ej_len = 469;
    eq_hex("E6a", EJ + OFF_INC, 69,
           "000000410100000000000000010000000000000000ab03f2e41c35f3f411e16b"
           "07f966d57e2f68ec35d15d7316cc582439dfbbc976e1610451ea22b64eb75f8b"
           "b46c3e4105");
    eq_hex("E6b", EJ + OFF_M1, 69,
           "00000041030000000000000001000000000000000035e109f27d3e86b2c47d3a"
           "156356e63cee6b2525a9bee46fcb931acd0fdf5dc57d617ddd41909630076b05"
           "d75742fdef");
    eq_hex("E6c", EJ + OFF_B, 77,
           "000000490200000000000000010000000000000001cc1b5f45edee5cad609902"
           "d8213eb3511c2a3b4cfd360342a18ccd41306b4f1e79fafc5ea879888f042682"
           "7012234a3a348376d6706ad8b2");
    eq_hex("E6d", EJ + OFF_M2, 69,
           "00000041030000000000000001000000000000000060b49aa722550072bc2d42"
           "51164193a739dc6c0a06c579fc2ac9a0c3dfc823bcff8bbe05dad0ac917cf6bc"
           "86ef0b070b");
    uint8_t got[16];
    gz_sc_frame_t f;
    CHECK_ERR(gz_sc_frame_open(kj, EJ + OFF_B, 469 - OFF_B, OFF_B, &f, got, sizeof got), GZ_SC_OK);
    CHECK(f.kind == 2 && f.incarnation == 1 && f.sequence == 1 && f.payload_len == 16 &&
          memcmp(got, PING, 16) == 0);

    /* E7. */
    uint8_t t[600];
    jstate_t s = read_j(EJ, 469, kj), good = s;
    CHECK(s.state == 0 && s.last_mark == (long)OFF_M2 && s.n == 4);
    memcpy(t, EJ, 469);
    t[OFF_B + 50] ^= 1; /* E7a */
    s = read_j(t, 469, kj);
    CHECK(s.state == 2 && s.v == OFF_B);
    memcpy(t, EJ, 469);
    t[OFF_B + 10] ^= 1; /* E7b */
    s = read_j(t, 469, kj);
    CHECK(s.state == 2 && s.v == OFF_B);
    memcpy(t, EJ, 469);
    memcpy(t + 469, EJ + OFF_B, 77); /* E7c */
    s = read_j(t, 546, kj);
    CHECK(s.state == 1 && s.v == 469 && s.n == 4);
    gz_sc_framekey_t *okj = NULL; /* E7d */
    uint8_t ofid[16];
    tv("other journal file id", ofid, 16);
    gz_sc_framekey_derive(MSK, 32, "journal", SIGNET, ofid, &okj);
    memcpy(t, EJ, 469);
    CHECK_ERR(gz_sc_frame_seal(okj, OFF_B, 2, 1, 1, PING, 16, t + OFF_B, 77, &n), GZ_SC_OK);
    s = read_j(t, 469, kj);
    CHECK(s.state == 2 && s.v == OFF_B);
    gz_sc_framekey_free(okj);
    memcpy(t, EJ, OFF_B); /* E7e: swapped */
    memcpy(t + OFF_B, EJ + OFF_M2, 69);
    memcpy(t + OFF_B + 69, EJ + OFF_B, 77);
    s = read_j(t, 469, kj);
    CHECK(s.v == OFF_B && s.n == 2);
    s = read_j(EJ, 466, kj); /* E7f */
    CHECK(s.state == 1 && s.v == OFF_M2);
    jstate_t e7g = read_j(EJ, OFF_B, kj); /* E7g */
    CHECK(e7g.state == 0 && e7g.last_mark == (long)OFF_M1);
    memcpy(t, EJ, 469); /* E7h */
    t[OFF_B + 50] ^= 1;
    t[OFF_M2 + 50] ^= 1;
    jstate_t e7h = read_j(t, 469, kj);
    CHECK(e7h.state == 1 && e7h.v == OFF_B);
    /* Every kind and length rule of 5.5. */
    memcpy(t, EJ, 469);
    t[OFF_M1 + 4] = 1; /* a mark claiming kind 1: tag fails */
    CHECK_ERR(gz_sc_frame_open(kj, t + OFF_M1, 469 - OFF_M1, OFF_M1, NULL, NULL, 0), GZ_SC_INVALID);
    t[OFF_M1 + 4] = 4;
    CHECK_ERR(gz_sc_frame_open(kj, t + OFF_M1, 469 - OFF_M1, OFF_M1, NULL, NULL, 0), GZ_SC_INVALID);
    CHECK_ERR(gz_sc_frame_open(kj, EJ + OFF_M1, 68, OFF_M1, NULL, NULL, 0), GZ_SC_INVALID);
    CHECK_ERR(gz_sc_frame_open(kj, EJ + OFF_M1, 469 - OFF_M1, OFF_M2, NULL, NULL, 0), GZ_SC_INVALID);

    /* E8: the passphrase change. */
    uint8_t *n2;
    size_t n2l, cp;
    CHECK_ERR(gz_sc_pass_nfc((const uint8_t *)PW2, strlen(PW2), &n2, &n2l, &cp), GZ_SC_OK);
    CHECK_ERR(gz_sc_test_kdf_inprocess(NULL, n2, n2l, SALT2, &TEST_P, pk2, NULL), GZ_SC_OK);
    gz_sc_sfree(n2);
    r_queue("key file wrap 2", "key file words 2", NULL);
    CHECK_ERR(gz_sc_keyfile_rewrap(kf1, pk1, &TEST_P, SALT2, pk2, kf2), GZ_SC_OK);
    CHECK(r_left() == 0);
    r_os();
    eq_hex("E8 key file", kf2, sizeof kf2,
           "475a4b455946494c01f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42"
           "25e97398810800000058e8eff8fffdf8d50e058079eb04146501000000030000"
           "004001a89b97d1d90598f7626e1c0cb87c4db55ed57ddbd2bc56ee1110980436"
           "5268f355c3502d18e0d62498b731f85101a3aecbf4b26db55d28d945dcfb5b20"
           "94f71e0954824cc49ec3f5391a4c39ea2a6e5ccfc774fe02a9eca0f90f61231d"
           "cb173602e3fbfed1c2465a52d5d0a9aab54c22c59dc5dcf4ee98605dc07ba9c8"
           "f242408d37dcd356d0f6f87d6b7139ef2604a1808114f651f2998654960024ec"
           "620e3e862dfb3cc48885cceba7f07e2825ae41ede922dedc23c5a13c4a7864eb"
           "61313b5fe219ef90549c9741a9c8ff5a3349af6036691511684a86495d4a227e"
           "5aed0e32ecaffb98c1bfb397f294ee51ea6c5fe6b151809e1e6efd403d50c937"
           "772b94294b517d05166c3977dceea32291a7eefc344ef7d1148b8526d67fbfd3"
           "ff6616110f9ee510357504");
    CHECK(memcmp(kf2, kf1, 67) == 0 && memcmp(kf2 + 259, kf1 + 259, 104) == 0);
    gz_sc_vault_t *v2 = NULL;
    CHECK_ERR(open_kf(kf2, PW2, &v2), GZ_SC_OK);
    gz_sc_vault_t *vx = NULL;
    CHECK_ERR(open_kf(kf2, PW1, &vx), GZ_SC_WRONG_PASSPHRASE);
    CHECK(vx == NULL);
    gz_sc_vault_t *v1 = NULL;
    CHECK_ERR(open_kf(kf1, PW1, &v1), GZ_SC_OK); /* the old copy still opens */
    gz_sc_framekey_t *kj2 = NULL;
    if (v2)
        CHECK_ERR(gz_sc_header_open(EJ, v2, &kj2), GZ_SC_OK);
    gz_sc_framekey_free(kj2);
    gz_sc_vault_free(v1);
    gz_sc_vault_free(v2);
    CHECK_ERR(gz_sc_keyfile_rewrap(kf1, pk2, &TEST_P, SALT2, pk2, kf2), GZ_SC_WRONG_PASSPHRASE);

    /* E9: the guard file. */
    derive_hex("E9 KG", SEED64, 64, "guard", SIGNET, 32,
               "339b2585661fdf58c0d401e63d10bb836bb3b272b6b7dbb5f3d9e417fb630deb");
    gz_sc_epoch_t ep = {0, 2};
    gz_sc_guard_t g = {3, 1, &ep, 1}, g2;
    uint8_t gb[200];
    size_t gl;
    r_queue("guard", NULL);
    CHECK_ERR(gz_sc_guard_seal(v, &g, gb, sizeof gb, &gl), GZ_SC_OK);
    eq_hex("E9 guard file", gb, gl,
           "475a47554152444501f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42"
           "25e9739881080000002d6aad687f0bd082c4c2cd1b3a4167d014c3cf315f1336"
           "f55a078212f02ac333bf61590500fc429a7ab0284d05a7a28928e97e5a583beb"
           "ef82ee452f294a02eb3ca1");
    CHECK_ERR(gz_sc_guard_open(v, gb, gl, &g2), GZ_SC_OK);
    CHECK(g2.counter == 3 && g2.n_epochs == 1 && g2.epochs && g2.epochs[0].highest_index == 2 &&
          g2.rounds_started == 1);
    gz_sc_guard_clear(&g2);
    gb[60] ^= 1;
    CHECK_ERR(gz_sc_guard_open(v, gb, gl, &g2), GZ_SC_DAMAGED);

    /* E9m: the mark file. */
    gz_sc_framekey_t *kh = NULL;
    CHECK_ERR(gz_sc_mark_key(v, FILE_ID, &kh), GZ_SC_OK);
    derive_hex("E9m KH", MSK, 32, "high water", ctx, 48,
               "a441f426101ddffd6caa985201008a86604b9ecd195190faf48a8d14d5ceb084");
    derive_hex("E9m KH nonce", MSK, 32, "high water nonce", ctx, 48,
               "e09b6279ec4d4e7234af72cd47d36404150c87886c56fb0eb76613939babb37c");
    uint8_t mk[300];
    r_queue("mark entry 0", "mark entry 1", NULL);
    CHECK_ERR(gz_sc_mark_new(kh, SIGNET, mk), GZ_SC_OK);
    CHECK_ERR(gz_sc_mark_entry(kh, mk, 113, 1, OFF_M2, mk + 113), GZ_SC_OK);
    r_os();
    eq_hex("E9m mark file", mk, 169,
           "475a4d41524b533101f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42"
           "25e973988108000000708bd86b189b2130142ec86d6c5a6f22a0b0698e035f15"
           "52ef62750af1aef9f023a21555914eec8290b456b8a9dd6cb4f6a092cde0f9e0"
           "23299f404da25a83d7a8970adb034bd7cba0f5665ef7a0d6d955f475d83e23f8"
           "f1e6f884492e105492457783c508d39ef1b552c3da94ab3a6b0ecc6483a01edf"
           "5f6d132bb4b15793d0");
    uint64_t mi = 9, mo = 9;
    size_t end = 0;
    CHECK(gz_sc_mark_read(kh, mk, 169, SIGNET, FILE_ID, &mi, &mo, &end) == GZ_SC_MARK_OK && mi == 1 &&
          mo == OFF_M2 && end == 169);
    CHECK(start_against(&e7g, GZ_SC_MARK_OK, mi, mo) == GZ_SC_START_BEHIND);
    CHECK(start_against(&e7h, GZ_SC_MARK_OK, mi, mo) == GZ_SC_START_BEHIND);
    CHECK(start_against(&good, GZ_SC_MARK_OK, mi, mo) == GZ_SC_START_OK);
    memcpy(mk + 169, mk + 57, 23); /* a torn append: ignored */
    CHECK(gz_sc_mark_read(kh, mk, 192, SIGNET, FILE_ID, &mi, &mo, &end) == GZ_SC_MARK_OK && mo == OFF_M2 &&
          end == 169);
    memcpy(t, mk, 169);
    t[60] ^= 1;
    CHECK(gz_sc_mark_read(kh, t, 169, SIGNET, FILE_ID, &mi, &mo, &end) == GZ_SC_MARK_DAMAGED);
    CHECK(gz_sc_mark_read(kh, mk, 57, SIGNET, FILE_ID, &mi, &mo, &end) == GZ_SC_MARK_NO_ENTRY);
    CHECK(gz_sc_mark_read(kh, mk, 169, SIGNET, ofid, &mi, &mo, &end) == GZ_SC_MARK_OTHER_JOURNAL);
    CHECK(gz_sc_mark_read(kh, mk, 113, SIGNET, FILE_ID, &mi, &mo, &end) == GZ_SC_MARK_OK && mi == 0 && mo == 0);
    CHECK(start_against(&e7g, GZ_SC_MARK_OK, 0, 0) == GZ_SC_START_OK); /* the limit of 6.4 */
    /* Going backwards is damage: (1, 400) then (1, 254). */
    r_os();
    CHECK_ERR(gz_sc_mark_entry(kh, mk, 169, 1, OFF_M1, mk + 169), GZ_SC_OK);
    CHECK(gz_sc_mark_read(kh, mk, 225, SIGNET, FILE_ID, &mi, &mo, &end) == GZ_SC_MARK_DAMAGED);
    gz_sc_framekey_free(kh);
    gz_sc_framekey_free(kj);
    gz_sc_vault_free(v);
}

/* ---- E10, E11: exports ---- */
static size_t plain_entries(uint8_t *out)
{
    size_t used = 0, cap = 400;
    uint8_t pl[8];
    sc_put64(pl, 1794000000000ull);
    gz_sc_export_body_entry(1, 1, 0, pl, 8, out, cap, &used);
    sc_put64(pl, OFF_M1);
    gz_sc_export_body_entry(3, 1, 0, pl, 8, out, cap, &used);
    gz_sc_export_body_entry(2, 1, 1, PING, 16, out, cap, &used);
    sc_put64(pl, OFF_M2);
    gz_sc_export_body_entry(3, 1, 0, pl, 8, out, cap, &used);
    return used;
}

static void e10_e11(void)
{
    gz_sc_vault_t *v = NULL;
    gz_sc_vault_new(SIGNET, VAULT_ID, MSK, SEED64, &v);
    uint8_t eid[16], saltx[16], pkx[32], pk2x[32];
    tv("export id", eid, 16);
    tv("export kdf salt", saltx, 16);
    CHECK_ERR(pk_of(PW1, saltx, &TEST_P, pkx), GZ_SC_OK);
    CHECK_ERR(pk_of(PW2, saltx, &TEST_P, pk2x), GZ_SC_OK);
    derive_hex("E10 BK", SEED64, 64, "backup", SIGNET, 32,
               "9a4617d2c2e8fb4163ddbe6b6b1968302c0a65114f261b444605aef8cf4e1b00");
    uint8_t bk[32], ctx[48];
    sc_derive(SEED64, 64, "backup", SIGNET, 32, bk);
    ctx2(SIGNET, eid, 16, ctx);
    derive_hex("E10 EK", bk, 32, "export", ctx, 48, "e172f2dabc7650d0a79495a05dc2736ae37151ef116fcc2f10dd9d590244ac1f");
    uint8_t guard[26] = {0, 0, 0, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t body[400];
    size_t bl = 0;
    CHECK_ERR(gz_sc_export_body_begin(1794000100000ull, 0, guard, 26, body, sizeof body, &bl), GZ_SC_OK);
    bl += plain_entries(body + bl);
    CHECK(bl == 164);
    uint8_t ex1[600], ex2[600], ex1s[800], *out = NULL;
    size_t l1, l2, l1s, ol;
    r_queue("export slot", "export chunk 0", NULL);
    CHECK_ERR(gz_sc_export_build(v, 1, eid, &TEST_P, saltx, pkx, body, bl, NULL, 65536, ex1, sizeof ex1, &l1), GZ_SC_OK);
    eq_hex("E10a profile 1", ex1, l1,
           "475a4241434b55500101f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c"
           "4225e973988108000000eba594bd30df323ee7faf88bd4e4bf81010000000300"
           "00004001bf6e15c75efe8b4c377417b5042a5fe7617bdcfa344c6dbff78df37c"
           "b8729286e4c6b13bca6c3d9e5e18b89868a0725bdc0832ad9b329149adc77115"
           "3e9c19c2998cabcd4b32d1ff5624c047686dd7a97907e0538a5f527c86a8d692"
           "5c02639793500e9e1dcf73893289d355e92f7b15d646770e919acd61000000cc"
           "0a4d70e2d9e029a1d101479598ad1546e05d7afc35ce13c8ee80dd538642affc"
           "d3b9976fc7e2150b499b33cc57ad0e372283c1e3eaca91a9a3d8bf41c8f7342a"
           "bc0be94d358ead9babcc38a2606d7e050b0bc649acd851912ca96a60a8413f39"
           "6f05b8e56d439d2051db5fb8b355e4a0b0ce224ea21d3c177aa548d898255632"
           "0a4fc645e5fe1dba24a255211c33065d427fdb08d40361316bc1368dad7a26d6"
           "052e917f75692eb026d3404761119282b1921240b1077afb6622b147b27ac18b"
           "b55a7e5e69ea6ef12429621d");
    r_queue("export chunk 0", NULL);
    CHECK_ERR(gz_sc_export_build(v, 2, eid, NULL, NULL, NULL, body, bl, NULL, 65536, ex2, sizeof ex2, &l2), GZ_SC_OK);
    eq_hex("E10b profile 2", ex2, l2,
           "475a4241434b55500102f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c"
           "4225e973988108000000eba594bd30df323ee7faf88bd4e4bf81000000cc217f"
           "eaf9f0202e64dafaea7e9ea793c4a06d67ec5b2d03db2c6c4c7224485ce3eeac"
           "b4177ea62f2e1104847be7a4f0837cbee6573d6cb74a2f294a747e0a7afd9411"
           "f1c64d126d21fe61a4e559c5fbcae529ef03765b5626ec04821de92f99203846"
           "4e8f922a565a3cbe241ef44b299061497e02374aa55f3353b8422c0e73b06eea"
           "c72dbc63e903cceccadb6a8610e4ad4ee764c105db40a71d77f4b418eb70d7f1"
           "82cd650a5f04c3601cd150b5c2a0a4e5a6473bd4048f8ad222d0fe0f7aacecb7"
           "1dbc6869aa241407cff5");
    r_os();
#define OPENS(data, len, pk, seed, want)                                                                 \
    do {                                                                                                 \
        CHECK_ERR(gz_sc_export_open(data, len, SIGNET, pk, seed, &out, &ol), want);                      \
        if ((want) == GZ_SC_OK)                                                                          \
            CHECK(ol == bl && memcmp(out, body, bl) == 0);                                               \
        gz_sc_sfree(out); /* guarded memory (M2): sodium_free aborts on anything else */        \
    } while (0)
    OPENS(ex1, l1, pkx, NULL, GZ_SC_OK);
    OPENS(ex1, l1, NULL, SEED64, GZ_SC_OK);
    OPENS(ex2, l2, NULL, SEED64, GZ_SC_OK);
    OPENS(ex2, l2, pkx, NULL, GZ_SC_NEEDS_WORDS);
    OPENS(ex1, l1, pk2x, NULL, GZ_SC_WRONG_PASSPHRASE);
    uint8_t oseed[64];
    crypto_hash_sha512(oseed, (const uint8_t *)"other", 5);
    OPENS(ex1, l1, NULL, oseed, GZ_SC_DAMAGED);
    /* E11. */
    CHECK_ERR(gz_sc_export_build(v, 1, eid, &TEST_P, saltx, pkx, body, bl, NULL, 64, ex1s, sizeof ex1s, &l1s), GZ_SC_OK);
    OPENS(ex1s, l1s, pkx, NULL, GZ_SC_OK);
    size_t c[3] = {188, 188 + 4 + 64 + 40, 188 + 2 * (4 + 64 + 40)};
    OPENS(ex1s, c[2], pkx, NULL, GZ_SC_TRUNCATED);
    uint8_t sw[900];
    memcpy(sw, ex1s, 188);
    memcpy(sw + 188, ex1s + c[1], 108);
    memcpy(sw + 296, ex1s + c[0], 108);
    memcpy(sw + 404, ex1s + c[2], l1s - c[2]);
    OPENS(sw, l1s, pkx, NULL, GZ_SC_DAMAGED);
    memcpy(sw, ex1s, l1s);
    memcpy(sw + l1s, ex1s + c[2], l1s - c[2]);
    OPENS(sw, l1s + (l1s - c[2]), pkx, NULL, GZ_SC_TRAILING_DATA);
    memcpy(sw, ex1, l1);
    sw[64] ^= 1;
    OPENS(sw, l1, pkx, NULL, GZ_SC_WRONG_PASSPHRASE); /* the slot's m changed: PKx differs */
    memcpy(sw, ex1, l1);
    sw[63] = sw[64] = sw[65] = sw[66] = 0xff;
    OPENS(sw, l1, pkx, NULL, GZ_SC_PARAMS_REFUSED);
    memcpy(sw, ex1, l1);
    sw[67] = 4;
    OPENS(sw, l1, pkx, NULL, GZ_SC_PARAMS_REFUSED);
    /* F17: an empty chunk before the last. */
    sc_keypair_t ek;
    sc_keys(bk, 32, "export", ctx, 48, &ek);
    uint8_t ad[188 + 9];
    memcpy(sw, ex1, 188);
    memcpy(ad, ex1, 188);
    sc_put64(ad + 188, 0);
    ad[196] = 0;
    sc_put32(sw + 188, 40);
    sc_seal(&ek, NULL, 0, ad, sizeof ad, sw + 192);
    sc_put64(ad + 188, 1);
    ad[196] = 1;
    sc_put32(sw + 232, (uint32_t)(bl + 40));
    sc_seal(&ek, body, bl, ad, sizeof ad, sw + 236);
    OPENS(sw, 236 + bl + 40, pkx, NULL, GZ_SC_EMPTY_CHUNK);
    sc_keys_free(&ek);
    /* Profile 2 never carries the words; profile 1 only when chosen. */
    uint8_t wbody[400];
    size_t wl = 0;
    CHECK_ERR(gz_sc_export_body_begin(1, 1, guard, 26, wbody, sizeof wbody, &wl), GZ_SC_OK);
    CHECK(wl == gz_sc_export_body_len(26, 0) && wbody[9] == 1); /* the caller's buffer holds no words */
    CHECK_ERR(gz_sc_export_build(v, 2, eid, NULL, NULL, NULL, wbody, wl, ENTROPY, 65536, sw, sizeof sw, &l2),
              GZ_SC_ARG);
    CHECK_ERR(gz_sc_export_build(v, 1, eid, &TEST_P, saltx, pkx, wbody, wl, NULL, 65536, sw, sizeof sw, &l2),
              GZ_SC_ARG); /* flag bit 0 without the entropy */
    CHECK_ERR(gz_sc_export_build(v, 1, eid, &TEST_P, saltx, pkx, body, bl, ENTROPY, 65536, sw, sizeof sw, &l2),
              GZ_SC_ARG); /* the entropy without flag bit 0 */
    /* Every chunk size up to the whole body, so the words straddle chunk
     * boundaries in every way; the opened body has them in place. */
    uint8_t *wx = malloc(4096);
    for (size_t part = 1; wx && part <= wl + GZ_SC_EXPORT_WORDS_LEN + 1; part++) {
        CHECK_ERR(gz_sc_export_build(v, 1, eid, &TEST_P, saltx, pkx, wbody, wl, ENTROPY, part, wx, 4096, &l2),
                  GZ_SC_OK);
        CHECK(l2 == gz_sc_export_size(1, wl + GZ_SC_EXPORT_WORDS_LEN, part));
        CHECK_ERR(gz_sc_export_open(wx, l2, SIGNET, pkx, NULL, &out, &ol), GZ_SC_OK);
        gz_sc_export_body_t pb;
        CHECK(out && gz_sc_export_body_parse(out, ol, 1, &pb) == GZ_SC_OK && pb.entropy &&
              memcmp(pb.entropy, ENTROPY, 32) == 0 && ol == wl + 32 && memcmp(out, wbody, 10) == 0 &&
              memcmp(out + 42, wbody + 10, wl - 10) == 0);
        gz_sc_sfree(out);
        out = NULL;
    }
    free(wx);
    gz_sc_vault_free(v);
}

/* ---- E12 to E15 (the bundle, penalty and keyed attempts files are 1.0.0:
 * reproduced here from the same primitives, so the envelope is confirmed) ---- */
static void e12_to_e15(void)
{
    uint8_t kb[32], bid[16], pfid[16], ctx[48];
    tv("watch bundle key", kb, 32);
    tv("watch bundle id", bid, 16);
    tv("watch penalty file id", pfid, 16);
    ctx2(SIGNET, bid, 16, ctx);
    derive_hex("E12 KWB", kb, 32, "watch bundle", ctx, 48,
               "c269df89095e6a036a8a3d85616dc6855eda09f4ff55aec973f661c91e45dc0f");
    uint8_t bun[200];
    memcpy(bun, "GZWATCH1", 8);
    bun[8] = 1;
    memcpy(bun + 9, SIGNET, 32);
    memcpy(bun + 41, bid, 16);
    sc_put64(bun + 57, 7);
    static const char bc[] = "test contents: see spec/exit.md";
    uint8_t pt[64];
    pt[0] = 2;
    pt[1] = (uint8_t)(sizeof bc - 1);
    memcpy(pt + 2, bc, sizeof bc - 1);
    sc_keypair_t kwb;
    sc_keys(kb, 32, "watch bundle", ctx, 48, &kwb);
    r_queue("watch bundle 7", NULL);
    CHECK_ERR(sc_seal(&kwb, pt, 2 + sizeof bc - 1, bun, 65, bun + 65), GZ_SC_OK);
    r_os();
    eq_hex("E12 bundle", bun, 65 + 40 + 33,
           "475a57415443483101f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42"
           "25e97398810800000001df1fe044bee7cadf9a1c6611b281f300000000000000"
           "07c7417c3c17ecfc3aac1438892d57c6daf1c89dade8f176b805ebc51a60389f"
           "2820bd70a18ebda5c6d43cdc4bbe498f76c296893b02f7d09e2c3ec4b1661c8f"
           "e743dbf0c8298e2a833a");
    uint8_t back[64];
    CHECK(sc_unseal(&kwb, bun + 65, 73, bun, 65, back) == 0);
    bun[64] ^= 1; /* E13: the counter */
    CHECK(sc_unseal(&kwb, bun + 65, 73, bun, 65, back) != 0);
    bun[64] ^= 1;
    sc_keypair_t wrong;
    sc_keys(MSK, 32, "watch bundle", ctx, 48, &wrong);
    CHECK(sc_unseal(&wrong, bun + 65, 73, bun, 65, back) != 0);
    sc_keys_free(&wrong);
    sc_keys_free(&kwb);

    /* E13p: the penalty file, in the journal's framing under KWP. */
    gz_sc_framekey_t *kwp = NULL;
    CHECK_ERR(gz_sc_framekey_derive(kb, 32, "watch penalties", SIGNET, pfid, &kwp), GZ_SC_OK);
    ctx2(SIGNET, pfid, 16, ctx);
    derive_hex("E13p KWP", kb, 32, "watch penalties", ctx, 48,
               "2a0704f005aebae1374f0bf40f3ab6fa5b6367a4c1b89c136931d7b34d9df984");
    uint8_t pf[300];
    memcpy(pf, "GZPENALT", 8);
    pf[8] = 1;
    memcpy(pf + 9, SIGNET, 32);
    memcpy(pf + 41, pfid, 16);
    static const char pc[] = "test penalty: see spec/exit.md";
    uint8_t pe[100];
    size_t p = 0, n;
    pe[p++] = 2;
    pe[p++] = 16;
    memcpy(pe + p, FILE_ID, 16);
    p += 16;
    pe[p++] = 4;
    pe[p++] = 8;
    sc_put64(pe + p, OFF_M2);
    p += 8;
    pe[p++] = 99;
    pe[p++] = (uint8_t)(sizeof pc - 1);
    memcpy(pe + p, pc, sizeof pc - 1);
    p += sizeof pc - 1;
    r_queue("penalty header", "penalty entry 1", "penalty mark 1", NULL);
    CHECK_ERR(sc_seal(&kwp->kp, NULL, 0, pf, 57, pf + 57), GZ_SC_OK);
    CHECK_ERR(gz_sc_frame_seal(kwp, 97, 2, 0, 1, pe, p, pf + 97, 200, &n), GZ_SC_OK);
    uint8_t mo[8];
    sc_put64(mo, 97 + n);
    CHECK_ERR(gz_sc_frame_seal(kwp, 97 + n, 3, 0, 0, mo, 8, pf + 97 + n, 100, &n), GZ_SC_OK);
    r_os();
    eq_hex("E13p penalty file", pf, 287,
           "475a50454e414c5401f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42"
           "25e9739881080000005e47c54f7b19f693f8ab7de34451e04b5050680f86443a"
           "01d95ba5b666c8a71df2a29fcee2a9b42273e99bfb097602c1d2eca818fe0f0e"
           "cf0000007502000000000000000000000000000000015ac465de1821283132ae"
           "dcb26810fa7bc4bdf438cc38a2cb24b75c778400452e5a9cfd9dbf4f43279fea"
           "72163d774a4704be8413e35b50b7d5b2edacc52f69060b29d3801f1fd8d549de"
           "529d36977e5027aa2ba3a77647e6c03b529b0ef02d761a82a8c9000000410300"
           "00000000000000000000000000000071982635f8efedb48796e4ec9e406ade24"
           "46b0d263a5b75ac1b9afc55ad6bbd33dd310debf4a7667c44a8ddaf602f1a2");
    gz_sc_framekey_free(kwp);

    /* E14: the keyed (mode 2) attempts file. Slice 1 writes mode 1 and reads
     * a mode 2 file as the strictest state. */
    uint8_t at[85], ka[32];
    memcpy(at, "GZTRIES1", 8);
    memcpy(at + 8, SIGNET, 32);
    sc_put64(at + 40, 9);
    sc_put32(at + 48, 6);
    sc_put64(at + 52, 1793999990ull);
    sc_put64(at + 60, 1794000030ull);
    at[68] = 2;
    sc_derive(kb, 32, "attempts", SIGNET, 32, ka);
    uint8_t mac[32];
    crypto_auth_hmacsha256(mac, at, 69, ka);
    memcpy(at + 69, mac, 16);
    eq_hex("E14 attempts file", at, 85,
           "475a545249455331f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225"
           "e973988108000000000000000000000900000006000000006aee447600000000"
           "6aee449e02b9767c56a1c173e4d9560cc0e95af2fa");
    gz_sc_attempts_t a;
    CHECK(gz_sc_attempts_decode(SIGNET, at, 85, 1794000000ull, &a) == 0 && a.blocked_until_s == 1794000900ull);

    /* E15: local-api.md 7.4's digest of the canonical bytes (the canonical
     * JSON itself is the local API's, stream S9). */
    uint8_t cj[197], d[32];
    size_t cl = hx("7b225a6564223a302c22636f6e6669726d5f66756e64696e675f736174223a32"
                   "35303030302c226472616674223a7b2261223a7b2261223a6e756c6c2c226222"
                   "3a747275657d2c227a223a5b332c322c315d7d2c226e616d65223a22436166c3"
                   "a920c2bd20f09f9880207461625c7468657265222c226e6f7465223a22756e69"
                   "745c7530303166736570205c22715c22205c5c222c22726571756573745f6964"
                   "223a226531355f746573745f726571756573745f30303031222c22c3a974c3a9"
                   "223a2d377d",
                   cj, sizeof cj);
    CHECK(cl == 197);
    crypto_hash_sha256(d, cj, cl);
    eq_hex("E15 digest", d, 32, "94f90d8308e1d42c8359dfbed31a81712f3406612fb268a10b41a813d0a73afe");
}

int main(int argc, char **argv)
{
    sc_test_init();
    if (argc > 1 && strcmp(argv[1], "e2r") == 0) {
        e2r();
        return sc_test_done("storage vector E2r");
    }
    e0();
    e1();
    e2_e3_e4();
    e5_to_e9m();
    e10_e11();
    e12_to_e15();
    return sc_test_done("storage vectors E0 to E15");
}
