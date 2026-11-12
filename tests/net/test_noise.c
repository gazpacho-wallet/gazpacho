/* BOLT 8: every test vector of Appendix A byte for byte, then hostile and
 * boundary cases (spec/transport.md, "Tests, listed before the code"). */
#include <stdlib.h>
#include "../check.h"
#include "hex.h"
#include "noise.h"

static secp256k1_context *secp;

/* Randomness that hands out a fixed sequence of 32-byte values. */
typedef struct { const uint8_t *keys; size_t n, next; } fixed_rng_t;
static void fixed_fill(void *ctx, uint8_t *out, size_t len)
{
    fixed_rng_t *r = (fixed_rng_t *)ctx;
    size_t i = r->next < r->n ? r->next : r->n - 1;
    memcpy(out, r->keys + 32 * i, len);
    r->next++;
}

static uint8_t K11[32], K12[32], K21[32], K22[32];
static uint8_t RS_PUB[33];
static fixed_rng_t rng_i, rng_r;

#define ACT1 "0x00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"
#define ACT2 "0x0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae"
#define ACT3 "0x00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"
#define SK "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"
#define RK "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"
#define CK_FINAL "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01"

static void new_initiator(gz_noise_t *st)
{
    gz_random_port_t r = {fixed_fill, &rng_i};
    rng_i.keys = K12; rng_i.n = 1; rng_i.next = 0;
    CHECK(gz_noise_init_initiator(st, secp, K11, RS_PUB, r) == GZ_NOISE_OK);
}

static void new_responder(gz_noise_t *st)
{
    gz_random_port_t r = {fixed_fill, &rng_r};
    rng_r.keys = K22; rng_r.n = 1; rng_r.next = 0;
    CHECK(gz_noise_init_responder(st, secp, K21, r) == GZ_NOISE_OK);
}

static size_t in(const char *hex, uint8_t *buf) { return unhex(hex, buf, 128); }

/* A refused state must be dead and fully wiped. */
static void check_dead(gz_noise_t *st)
{
    uint8_t out[128];
    size_t n;
    CHECK(st->phase == GZ_NOISE_DEAD);
    CHECK(all_zero(st, sizeof *st));
    CHECK(gz_noise_act1_write(st, out) == GZ_NOISE_ERR_STATE);
    CHECK(gz_noise_act1_read(st, out, 50) == GZ_NOISE_ERR_STATE);
    CHECK(gz_noise_act2_write(st, out) == GZ_NOISE_ERR_STATE);
    CHECK(gz_noise_act2_read(st, out, 50) == GZ_NOISE_ERR_STATE);
    CHECK(gz_noise_act3_write(st, out) == GZ_NOISE_ERR_STATE);
    CHECK(gz_noise_act3_read(st, out, 66) == GZ_NOISE_ERR_STATE);
    CHECK(gz_noise_encrypt(st, out, 1, out, sizeof out, &n) == GZ_NOISE_ERR_STATE);
    CHECK(gz_noise_decrypt_header(st, out, 18, &n) == GZ_NOISE_ERR_STATE);
    CHECK(gz_noise_decrypt_body(st, out, 16, out, sizeof out) == GZ_NOISE_ERR_STATE);
    CHECK(gz_noise_remote_static(st, out) == GZ_NOISE_ERR_STATE);
}

static void test_initiator_success(gz_noise_t *st)
{
    uint8_t out[66], buf[128];
    new_initiator(st);
    CHECK(gz_noise_act1_write(st, out) == GZ_NOISE_OK);
    CHECK(eqhex(out, 50, ACT1));
    CHECK(eqhex(st->e_pub, 33, "036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7"));
    CHECK(eqhex(st->ls_pub, 33, "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"));
    CHECK(eqhex(st->ck, 32, "b61ec1191326fa240decc9564369dbb3ae2b34341d1e11ad64ed89f89180582f"));
    CHECK(eqhex(st->temp_k, 32, "e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f"));
    CHECK(eqhex(st->h, 32, "9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce"));
    CHECK(gz_noise_act2_read(st, buf, in(ACT2, buf)) == GZ_NOISE_OK);
    CHECK(eqhex(st->re, 33, "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"));
    CHECK(eqhex(st->ck, 32, "e89d31033a1b6bf68c07d22e08ea4d7884646c4b60a9528598ccb4ee2c8f56ba"));
    CHECK(eqhex(st->temp_k, 32, "908b166535c01a935cf1e130a5fe895ab4e6f3ef8855d87e9b7581c4ab663ddc"));
    CHECK(eqhex(st->h, 32, "90578e247e98674e661013da3c5c1ca6a8c8f48c90b485c0dfa1494e23d56d72"));
    CHECK(gz_noise_act3_write(st, out) == GZ_NOISE_OK);
    CHECK(eqhex(out, 66, ACT3));
    CHECK(eqhex(st->h, 32, "5dcb5ea9b4ccc755e0e3456af3990641276e1d5dc9afd82f974d90a47c918660"));
    CHECK(eqhex(st->sk, 32, SK));
    CHECK(eqhex(st->rk, 32, RK));
    CHECK(eqhex(st->sck, 32, CK_FINAL));
    CHECK(eqhex(st->rck, 32, CK_FINAL));
    CHECK(st->sn == 0 && st->rn == 0 && st->phase == GZ_NOISE_READY);
    /* Handshake secrets are gone once it is over. */
    CHECK(all_zero(st->e_priv, 32) && all_zero(st->ls_priv, 32));
    CHECK(all_zero(st->temp_k, 32) && all_zero(st->ck, 32));
    CHECK(gz_noise_remote_static(st, buf) == GZ_NOISE_OK && memcmp(buf, RS_PUB, 33) == 0);
}

static void test_initiator_failures(void)
{
    static const struct { const char *act2; gz_noise_err_t want; } v[] = {
        /* act2 short read */
        {"0x0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730", GZ_NOISE_ERR_LENGTH},
        /* act2 bad version */
        {"0x0102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae", GZ_NOISE_ERR_VERSION},
        /* act2 bad key serialization */
        {"0x0004466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae", GZ_NOISE_ERR_PUBKEY},
        /* act2 bad MAC */
        {"0x0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730af", GZ_NOISE_ERR_MAC},
    };
    size_t i;
    for (i = 0; i < sizeof v / sizeof v[0]; i++) {
        gz_noise_t st;
        uint8_t out[50], buf[128];
        new_initiator(&st);
        CHECK(gz_noise_act1_write(&st, out) == GZ_NOISE_OK && eqhex(out, 50, ACT1));
        CHECK(gz_noise_act2_read(&st, buf, in(v[i].act2, buf)) == v[i].want);
        check_dead(&st);
    }
}

static void test_responder_success(gz_noise_t *st)
{
    uint8_t out[50], buf[128];
    new_responder(st);
    CHECK(gz_noise_act1_read(st, buf, in(ACT1, buf)) == GZ_NOISE_OK);
    CHECK(eqhex(st->re, 33, "036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7"));
    CHECK(eqhex(st->h, 32, "9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce"));
    CHECK(gz_noise_act2_write(st, out) == GZ_NOISE_OK);
    CHECK(eqhex(out, 50, ACT2));
    CHECK(eqhex(st->ck, 32, "e89d31033a1b6bf68c07d22e08ea4d7884646c4b60a9528598ccb4ee2c8f56ba"));
    CHECK(eqhex(st->h, 32, "90578e247e98674e661013da3c5c1ca6a8c8f48c90b485c0dfa1494e23d56d72"));
    CHECK(gz_noise_act3_read(st, buf, in(ACT3, buf)) == GZ_NOISE_OK);
    CHECK(eqhex(st->rs, 33, "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"));
    CHECK(eqhex(st->h, 32, "5dcb5ea9b4ccc755e0e3456af3990641276e1d5dc9afd82f974d90a47c918660"));
    CHECK(eqhex(st->rk, 32, SK));
    CHECK(eqhex(st->sk, 32, RK));
    CHECK(eqhex(st->rck, 32, CK_FINAL) && eqhex(st->sck, 32, CK_FINAL));
    CHECK(all_zero(st->e_priv, 32) && all_zero(st->ls_priv, 32) && all_zero(st->temp_k, 32));
}

static void test_responder_failures(void)
{
    static const struct { const char *act1, *act3; gz_noise_err_t want; } v[] = {
        /* act1 short read, bad version, bad key, bad MAC */
        {"0x00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c", NULL, GZ_NOISE_ERR_LENGTH},
        {"0x01036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a", NULL, GZ_NOISE_ERR_VERSION},
        {"0x00046360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a", NULL, GZ_NOISE_ERR_PUBKEY},
        {"0x00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6b", NULL, GZ_NOISE_ERR_MAC},
        /* act3 bad version */
        {ACT1, "0x01b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba", GZ_NOISE_ERR_VERSION},
        /* act3 short read */
        {ACT1, "0x00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139", GZ_NOISE_ERR_LENGTH},
        /* act3 bad MAC for ciphertext */
        {ACT1, "0x00c9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba", GZ_NOISE_ERR_MAC},
        /* act3 bad rs */
        {ACT1, "0x00bfe3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa2235536ad09a8ee351870c2bb7f78b754a26c6cef79a98d25139c856d7efd252c2ae73c", GZ_NOISE_ERR_PUBKEY},
        /* act3 bad MAC */
        {ACT1, "0x00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139bb", GZ_NOISE_ERR_MAC},
    };
    size_t i;
    for (i = 0; i < sizeof v / sizeof v[0]; i++) {
        gz_noise_t st;
        uint8_t out[50], buf[128];
        new_responder(&st);
        if (!v[i].act3) {
            CHECK(gz_noise_act1_read(&st, buf, in(v[i].act1, buf)) == v[i].want);
        } else {
            CHECK(gz_noise_act1_read(&st, buf, in(v[i].act1, buf)) == GZ_NOISE_OK);
            CHECK(gz_noise_act2_write(&st, out) == GZ_NOISE_OK && eqhex(out, 50, ACT2));
            CHECK(gz_noise_act3_read(&st, buf, in(v[i].act3, buf)) == v[i].want);
        }
        check_dead(&st);
    }
}

static const char *const MSG_OUT[][2] = {
    {"0", "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95"},
    {"1", "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1"},
    {"500", "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8"},
    {"501", "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd"},
    {"1000", "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09"},
    {"1001", "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36"},
};

/* The initiator sends "hello" 1002 times; the responder reads them all. */
static void test_messages(gz_noise_t *ini, gz_noise_t *res)
{
    uint8_t out[64], body[8];
    size_t n, blen;
    int i, j, matched = 0, read_ok = 0;
    for (i = 0; i < 1002; i++) {
        if (i == 499) CHECK(eqhex(ini->sk, 32, SK) && ini->sn == 998);
        CHECK(gz_noise_encrypt(ini, (const uint8_t *)"hello", 5, out, sizeof out, &n) == GZ_NOISE_OK && n == 39);
        for (j = 0; j < 6; j++)
            if (atoi(MSG_OUT[j][0]) == i) matched += eqhex(out, n, MSG_OUT[j][1]);
        if (i == 499) {
            /* the 500th message used nonces 998 and 999: the key rotates now */
            CHECK(ini->sn == 0);
            CHECK(eqhex(ini->sck, 32, "cc2c6e467efc8067720c2d09c139d1f77731893aad1defa14f9bf3c48d3f1d31"));
            CHECK(eqhex(ini->sk, 32, "3fbdc101abd1132ca3a0ae34a669d8d9ba69a587e0bb4ddd59524541cf4813d8"));
        }
        if (i == 999) {
            CHECK(eqhex(ini->sck, 32, "728366ed68565dc17cf6dd97330a859a6a56e87e2beef3bd828a4c4a54d8df06"));
            CHECK(eqhex(ini->sk, 32, "9e0477f9850dca41e42db0e4d154e3a098e5a000d995e421849fcd5df27882bd"));
        }
        if (gz_noise_decrypt_header(res, out, 18, &blen) == GZ_NOISE_OK && blen == 5 &&
            gz_noise_decrypt_body(res, out + 18, n - 18, body, sizeof body) == GZ_NOISE_OK &&
            memcmp(body, "hello", 5) == 0)
            read_ok++;
        if (i == 499) CHECK(eqhex(res->rk, 32, "3fbdc101abd1132ca3a0ae34a669d8d9ba69a587e0bb4ddd59524541cf4813d8"));
    }
    CHECK(matched == 6);
    CHECK(read_ok == 1002);
    /* The other direction is untouched by all that. */
    CHECK(eqhex(ini->rk, 32, RK) && ini->rn == 0 && eqhex(res->sk, 32, RK) && res->sn == 0);
}

static void test_hkdf_vector(void)
{
    uint8_t salt[32], ikm[32], a[32], b[32];
    unhex("2640f52eebcd9e882958951c794250eedb28002c05d7dc2ea0f195406042caf1", salt, 32);
    unhex("1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3", ikm, 32);
    CHECK(gz_noise_hkdf(salt, 32, ikm, 32, a, b));
    CHECK(eqhex(a, 32, "b61ec1191326fa240decc9564369dbb3ae2b34341d1e11ad64ed89f89180582f"));
    CHECK(eqhex(b, 32, "e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f"));
}

/* Two ready states talking to each other. */
static void pair(gz_noise_t *ini, gz_noise_t *res)
{
    uint8_t a[66];
    new_initiator(ini);
    new_responder(res);
    CHECK(gz_noise_act1_write(ini, a) == GZ_NOISE_OK);
    CHECK(gz_noise_act1_read(res, a, 50) == GZ_NOISE_OK);
    CHECK(gz_noise_act2_write(res, a) == GZ_NOISE_OK);
    CHECK(gz_noise_act2_read(ini, a, 50) == GZ_NOISE_OK);
    CHECK(gz_noise_act3_write(ini, a) == GZ_NOISE_OK);
    CHECK(gz_noise_act3_read(res, a, 66) == GZ_NOISE_OK);
}

static uint8_t big[18 + 65536 + 16], bigout[65536];

static void test_hostile(void)
{
    gz_noise_t ini, res;
    uint8_t buf[128], out[66];
    size_t n, blen, len;
    static const size_t bad_lens[] = {0, 49, 51};
    size_t i;

    /* Acts one byte short and one byte long, and empty. */
    for (i = 0; i < 3; i++) {
        new_responder(&res);
        in(ACT1, buf);
        CHECK(gz_noise_act1_read(&res, buf, bad_lens[i]) == GZ_NOISE_ERR_LENGTH);
        check_dead(&res);
        new_initiator(&ini);
        CHECK(gz_noise_act1_write(&ini, out) == GZ_NOISE_OK);
        in(ACT2, buf);
        CHECK(gz_noise_act2_read(&ini, buf, bad_lens[i]) == GZ_NOISE_ERR_LENGTH);
        check_dead(&ini);
    }
    new_responder(&res);
    CHECK(gz_noise_act1_read(&res, buf, in(ACT1, buf)) == GZ_NOISE_OK);
    CHECK(gz_noise_act2_write(&res, out) == GZ_NOISE_OK);
    in(ACT3, buf);
    CHECK(gz_noise_act3_read(&res, buf, 67) == GZ_NOISE_ERR_LENGTH);

    /* Calls out of order. */
    new_initiator(&ini);
    CHECK(gz_noise_act3_write(&ini, out) == GZ_NOISE_ERR_STATE);
    check_dead(&ini);
    new_initiator(&ini);
    CHECK(gz_noise_act1_read(&ini, buf, in(ACT1, buf)) == GZ_NOISE_ERR_STATE);
    new_responder(&res);
    CHECK(gz_noise_act1_write(&res, out) == GZ_NOISE_ERR_STATE);
    new_responder(&res);
    CHECK(gz_noise_encrypt(&res, buf, 1, out, sizeof out, &n) == GZ_NOISE_ERR_STATE);
    new_responder(&res);
    CHECK(gz_noise_remote_static(&res, buf) == GZ_NOISE_ERR_STATE);

    /* Replayed act one from a session that already finished: fine for act one
     * (it carries nothing secret), but a replayed act three fails its MAC
     * because the responder's new ephemeral differs. */
    {
        static const uint8_t other[32] = {0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                                          0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                                          0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33};
        gz_random_port_t r = {fixed_fill, &rng_r};
        CHECK(gz_noise_init_responder(&res, secp, K21, r) == GZ_NOISE_OK);
        rng_r.keys = other; rng_r.n = 1; rng_r.next = 0;
        CHECK(gz_noise_act1_read(&res, buf, in(ACT1, buf)) == GZ_NOISE_OK);
        CHECK(gz_noise_act2_write(&res, out) == GZ_NOISE_OK);
        CHECK(gz_noise_act3_read(&res, buf, in(ACT3, buf)) == GZ_NOISE_ERR_MAC);
        check_dead(&res);
    }

    /* Header with a bad MAC; body with a bad MAC; body of the wrong length. */
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"abc", 3, buf, sizeof buf, &n) == GZ_NOISE_OK);
    buf[17] ^= 1;
    CHECK(gz_noise_decrypt_header(&res, buf, 18, &blen) == GZ_NOISE_ERR_MAC);
    check_dead(&res);
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"abc", 3, buf, sizeof buf, &n) == GZ_NOISE_OK);
    buf[0] ^= 0x80; /* flips the decrypted length: the MAC must catch it */
    CHECK(gz_noise_decrypt_header(&res, buf, 18, &blen) == GZ_NOISE_ERR_MAC);
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"abc", 3, buf, sizeof buf, &n) == GZ_NOISE_OK);
    buf[18] ^= 1;
    CHECK(gz_noise_decrypt_header(&res, buf, 18, &blen) == GZ_NOISE_OK && blen == 3);
    memset(out, 0xaa, sizeof out);
    CHECK(gz_noise_decrypt_body(&res, buf + 18, n - 18, out, sizeof out) == GZ_NOISE_ERR_MAC);
    CHECK(all_zero(out, 3)); /* no unauthenticated bytes left behind */
    check_dead(&res);
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"abc", 3, buf, sizeof buf, &n) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_header(&res, buf, 18, &blen) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_header(&res, buf, 18, &blen) == GZ_NOISE_ERR_STATE);
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"abc", 3, buf, sizeof buf, &n) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_header(&res, buf, 18, &blen) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_body(&res, buf + 18, n - 19, out, sizeof out) == GZ_NOISE_ERR_LENGTH);
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"abc", 3, buf, sizeof buf, &n) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_header(&res, buf, 18, &blen) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_body(&res, buf + 18, n - 17, out, sizeof out) == GZ_NOISE_ERR_LENGTH);
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"abc", 3, buf, sizeof buf, &n) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_header(&res, buf, 18, &blen) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_body(&res, buf + 18, n - 18, out, 2) == GZ_NOISE_ERR_TOO_BIG);
    pair(&ini, &res);
    CHECK(gz_noise_decrypt_body(&res, buf, 19, out, sizeof out) == GZ_NOISE_ERR_STATE);
    pair(&ini, &res);
    CHECK(gz_noise_decrypt_header(&res, buf, 17, &blen) == GZ_NOISE_ERR_LENGTH);
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"abc", 3, buf, sizeof buf, &n) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_header(&res, buf, 19, &blen) == GZ_NOISE_ERR_LENGTH);

    /* Sizes: 65,535 bytes round trip, 65,536 refused, output buffer one short refused. */
    pair(&ini, &res);
    memset(bigout, 0x5a, 65535);
    CHECK(gz_noise_encrypt(&ini, bigout, 65535, big, sizeof big, &len) == GZ_NOISE_OK && len == 65569);
    memset(bigout, 0, 65535);
    CHECK(gz_noise_decrypt_header(&res, big, 18, &blen) == GZ_NOISE_OK && blen == 65535);
    CHECK(gz_noise_decrypt_body(&res, big + 18, 65551, bigout, 65535) == GZ_NOISE_OK);
    CHECK(bigout[0] == 0x5a && bigout[65534] == 0x5a);
    CHECK(gz_noise_encrypt(&ini, bigout, 65536, big, sizeof big, &len) == GZ_NOISE_ERR_TOO_BIG);
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&ini, bigout, 10, big, 18 + 10 + 15, &len) == GZ_NOISE_ERR_TOO_BIG);
    /* An empty message is allowed. */
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&ini, NULL, 0, buf, sizeof buf, &n) == GZ_NOISE_OK && n == 34);
    CHECK(gz_noise_decrypt_header(&res, buf, 18, &blen) == GZ_NOISE_OK && blen == 0);
    CHECK(gz_noise_decrypt_body(&res, buf + 18, 16, out, 0) == GZ_NOISE_OK);

    /* Messages in both directions keep their own nonces. */
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&res, (const uint8_t *)"xy", 2, buf, sizeof buf, &n) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_header(&ini, buf, 18, &blen) == GZ_NOISE_OK && blen == 2);
    CHECK(gz_noise_decrypt_body(&ini, buf + 18, 18, out, sizeof out) == GZ_NOISE_OK && !memcmp(out, "xy", 2));
    CHECK(ini.rn == 2 && ini.sn == 0 && res.sn == 2 && res.rn == 0);
    /* Encrypting while a body is awaited is allowed. */
    CHECK(gz_noise_encrypt(&res, (const uint8_t *)"z", 1, buf, sizeof buf, &n) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_header(&ini, buf, 18, &blen) == GZ_NOISE_OK);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"q", 1, out, sizeof out, &len) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_body(&ini, buf + 18, 17, out, sizeof out) == GZ_NOISE_OK && out[0] == 'z');
    /* Reordered messages fail: the second message read first. */
    pair(&ini, &res);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"1", 1, out, sizeof out, &n) == GZ_NOISE_OK);
    CHECK(gz_noise_encrypt(&ini, (const uint8_t *)"2", 1, buf, sizeof buf, &n) == GZ_NOISE_OK);
    CHECK(gz_noise_decrypt_header(&res, buf, 18, &blen) == GZ_NOISE_ERR_MAC);
}

static void test_keys_and_randomness(void)
{
    gz_noise_t st;
    uint8_t out[50], zeros[33] = {0}, ffs[32], seq[64];
    fixed_rng_t r = {zeros, 1, 0};
    gz_random_port_t port = {fixed_fill, &r};
    memset(ffs, 0xff, sizeof ffs);
    /* Our static key invalid; remote key invalid. */
    CHECK(gz_noise_init_responder(&st, secp, zeros, port) == GZ_NOISE_ERR_KEY);
    check_dead(&st);
    CHECK(gz_noise_init_responder(&st, secp, ffs, port) == GZ_NOISE_ERR_KEY);
    CHECK(gz_noise_init_initiator(&st, secp, K11, zeros, port) == GZ_NOISE_ERR_PUBKEY);
    check_dead(&st);
    {
        uint8_t uncompressed_prefix[33];
        memcpy(uncompressed_prefix, RS_PUB, 33);
        uncompressed_prefix[0] = 4;
        CHECK(gz_noise_init_initiator(&st, secp, K11, uncompressed_prefix, port) == GZ_NOISE_ERR_PUBKEY);
    }
    /* Randomness that never gives a valid key: zero, then above the order. */
    CHECK(gz_noise_init_initiator(&st, secp, K11, RS_PUB, port) == GZ_NOISE_OK);
    CHECK(gz_noise_act1_write(&st, out) == GZ_NOISE_ERR_RANDOM && r.next == 8);
    check_dead(&st);
    r.keys = ffs; r.next = 0;
    CHECK(gz_noise_init_initiator(&st, secp, K11, RS_PUB, port) == GZ_NOISE_OK);
    CHECK(gz_noise_act1_write(&st, out) == GZ_NOISE_ERR_RANDOM);
    /* One bad draw, then the vector's key: the act is the vector's. */
    memcpy(seq, ffs, 32);
    memcpy(seq + 32, K12, 32);
    r.keys = seq; r.n = 2; r.next = 0;
    CHECK(gz_noise_init_initiator(&st, secp, K11, RS_PUB, port) == GZ_NOISE_OK);
    CHECK(gz_noise_act1_write(&st, out) == GZ_NOISE_OK && r.next == 2 && eqhex(out, 50, ACT1));
}

/* A member pinned to the wrong host key: the host refuses act one, so it
 * never answers and the member learns nothing more. */
static void test_wrong_pin(void)
{
    gz_noise_t ini, res;
    uint8_t a[50], wrong[33];
    gz_random_port_t r = {fixed_fill, &rng_i};
    secp256k1_pubkey pk;
    size_t n = 33;
    CHECK(secp256k1_ec_pubkey_create(secp, &pk, K22) &&
          secp256k1_ec_pubkey_serialize(secp, wrong, &n, &pk, SECP256K1_EC_COMPRESSED));
    rng_i.keys = K12; rng_i.n = 1; rng_i.next = 0;
    CHECK(gz_noise_init_initiator(&ini, secp, K11, wrong, r) == GZ_NOISE_OK);
    CHECK(gz_noise_act1_write(&ini, a) == GZ_NOISE_OK);
    new_responder(&res);
    CHECK(gz_noise_act1_read(&res, a, 50) == GZ_NOISE_ERR_MAC);
}

int main(void)
{
    gz_noise_t ini, res;
    secp256k1_pubkey pk;
    size_t n = 33;
    memset(K11, 0x11, 32); memset(K12, 0x12, 32); memset(K21, 0x21, 32); memset(K22, 0x22, 32);
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    CHECK(secp256k1_ec_pubkey_create(secp, &pk, K21) &&
          secp256k1_ec_pubkey_serialize(secp, RS_PUB, &n, &pk, SECP256K1_EC_COMPRESSED));
    CHECK(eqhex(RS_PUB, 33, "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7"));

    test_hkdf_vector();
    test_initiator_success(&ini);
    test_initiator_failures();
    test_responder_success(&res);
    test_responder_failures();
    test_messages(&ini, &res);
    test_hostile();
    test_keys_and_randomness();
    test_wrong_pin();
    gz_noise_wipe(&ini);
    CHECK(all_zero(&ini, sizeof ini));
    secp256k1_context_destroy(secp);
    return check_done();
}
