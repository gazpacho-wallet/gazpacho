/* Spec 16 tests 2 to 5, 7, 14 (messages), 15, and the attempts file, the
 * start rule, the passphrase rules and the token folder. */
#define _GNU_SOURCE
#include "sc_internal.h"
#include "sc_pass.h"
#include "sc_test.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const gz_sc_kdf_params_t TP = {1, 3, 64, 1};
static uint8_t MSK[32], VID[16], SALT[16], ENT[32], FID[16];

static gz_sc_err_t pk_for(const char *pw, const uint8_t *kf, uint8_t pk[32])
{
    gz_sc_keyfile_info_t info;
    gz_sc_err_t e = gz_sc_keyfile_parse(kf, GZ_SC_KEYFILE_LEN, SIGNET, &info);
    if (e != GZ_SC_OK)
        return e;
    return gz_sc_test_kdf_inprocess(NULL, (const uint8_t *)pw, strlen(pw), info.salt, &info.kdf, pk, NULL);
}

static gz_sc_err_t unlock_kf(const uint8_t *kf, const char *pw)
{
    uint8_t pk[32];
    gz_sc_err_t e = pk_for(pw, kf, pk);
    if (e != GZ_SC_OK)
        return e;
    gz_sc_vault_t *v = NULL;
    e = gz_sc_keyfile_unlock(kf, pk, &v);
    gz_sc_vault_free(v);
    return e;
}

static void params(void)
{
    gz_sc_test_set_floor(3, 65536);
    gz_sc_kdf_params_t p = GZ_SC_KDF_KEYFILE_DEFAULT;
    CHECK_ERR(gz_sc_params_check(&p), GZ_SC_OK);
    struct { uint8_t kdf; uint32_t t, m; uint8_t lanes; gz_sc_err_t want; } c[] = {
        {1, 3, 65536, 1, GZ_SC_OK},          {1, 2, 65536, 1, GZ_SC_PARAMS_REFUSED},
        {1, 3, 65535, 1, GZ_SC_PARAMS_REFUSED}, {1, 16, 65536, 1, GZ_SC_OK},
        {1, 17, 65536, 1, GZ_SC_PARAMS_REFUSED}, {1, 3, 4194305, 1, GZ_SC_PARAMS_REFUSED},
        {1, 3, 0xffffffffu, 1, GZ_SC_PARAMS_REFUSED}, {2, 3, 65536, 1, GZ_SC_PARAMS_REFUSED},
        {0, 3, 65536, 1, GZ_SC_PARAMS_REFUSED}, {1, 3, 65536, 4, GZ_SC_PARAMS_REFUSED},
        {1, 3, 65536, 0, GZ_SC_PARAMS_REFUSED}, {1, 0, 65536, 1, GZ_SC_PARAMS_REFUSED},
    };
    for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
        gz_sc_kdf_params_t q = {c[i].kdf, c[i].t, c[i].m, c[i].lanes};
        CHECK_ERR(gz_sc_params_check(&q), c[i].want);
    }
    /* The device ceiling: half of the physical memory. */
    gz_sc_test_set_phys(256ull << 20);
    gz_sc_kdf_params_t q = {1, 3, 131072, 1};
    CHECK_ERR(gz_sc_params_check(&q), GZ_SC_OK); /* exactly half */
    q.m_kib = 131073;
    CHECK_ERR(gz_sc_params_check(&q), GZ_SC_NEEDS_MORE_MEMORY);
    q.m_kib = 4194304; /* 4 GiB: the fixed ceiling passes, the device's does not */
    CHECK_ERR(gz_sc_params_check(&q), GZ_SC_NEEDS_MORE_MEMORY);
    /* A new wrap: max(stored, default), halved to the device, never below stored. */
    gz_sc_kdf_params_t st = {1, 5, 65536, 1}, out;
    gz_sc_params_for_new_wrap(&st, &GZ_SC_KDF_EXPORT_DEFAULT, &out);
    CHECK(out.t == 5 && out.m_kib == 131072);
    gz_sc_test_set_phys(64ull << 30);
    gz_sc_params_for_new_wrap(&st, &GZ_SC_KDF_EXPORT_DEFAULT, &out);
    CHECK(out.t == 5 && out.m_kib == 1048576);
    gz_sc_params_for_new_wrap(&st, &GZ_SC_KDF_KEYFILE_DEFAULT, &out);
    CHECK(out.t == 5 && out.m_kib == 262144);
    gz_sc_kdf_params_t big = {1, 3, 2097152, 1};
    gz_sc_params_for_new_wrap(&big, &GZ_SC_KDF_KEYFILE_DEFAULT, &out);
    CHECK(out.t == 3 && out.m_kib == 2097152);
    /* Never below the stored parameters, even where this device cannot hold
     * them (4.7; review A, L7 e): a 1 GiB key file on a 1 GiB device stays at
     * 1 GiB, and the rewrap is then refused there rather than downgraded. */
    gz_sc_test_set_phys(1ull << 30);
    gz_sc_kdf_params_t gib = {1, 3, 1048576, 1};
    gz_sc_params_for_new_wrap(&gib, &GZ_SC_KDF_KEYFILE_DEFAULT, &out);
    CHECK(out.t == 3 && out.m_kib == 1048576);
    CHECK_ERR(gz_sc_params_check(&out), GZ_SC_NEEDS_MORE_MEMORY);
    gz_sc_params_for_new_wrap(&gib, &GZ_SC_KDF_EXPORT_DEFAULT, &out);
    CHECK(out.t == 4 && out.m_kib == 1048576);
    gz_sc_test_set_phys(0);
    gz_sc_test_set_floor(1, 8);
}

static void keyfile_fields(void)
{
    uint8_t pk[32], kf[GZ_SC_KEYFILE_LEN], bad[GZ_SC_KEYFILE_LEN];
    const char *pw = "a test passphrase of enough length";
    CHECK_ERR(gz_sc_test_kdf_inprocess(NULL, (const uint8_t *)pw, strlen(pw), SALT, &TP, pk, NULL), GZ_SC_OK);
    CHECK_ERR(gz_sc_keyfile_build(SIGNET, VID, &TP, SALT, pk, MSK, ENT, SEED64, kf), GZ_SC_OK);
    CHECK_ERR(unlock_kf(kf, pw), GZ_SC_OK);
    /* Test 2: every byte altered in turn is refused, at unlock or (the words,
     * 187..258) when the words are opened. */
    int fails = 0;
    for (size_t i = 0; i < GZ_SC_KEYFILE_LEN; i++) {
        for (int b = 0; b < 2; b++) {
            memcpy(bad, kf, sizeof bad);
            bad[i] ^= b ? 0x80 : 0x01;
            gz_sc_err_t e = unlock_kf(bad, pw);
            if (i >= 187 && i < 259) {
                uint8_t ent[32];
                if (e != GZ_SC_OK || gz_sc_keyfile_words(bad, pk, ent) != GZ_SC_DAMAGED)
                    fails++;
            } else if (e == GZ_SC_OK) {
                fprintf(stderr, "key file byte %zu flipped still opens\n", i);
                fails++;
            }
        }
    }
    CHECK(fails == 0);
    memcpy(bad, kf, sizeof bad);
    bad[8] = 2; /* another format is refused as such, before the commitment */
    CHECK_ERR(gz_sc_keyfile_parse(bad, GZ_SC_KEYFILE_LEN, SIGNET, NULL), GZ_SC_NOT_THIS_FORMAT);
    bad[8] = 0;
    CHECK_ERR(gz_sc_keyfile_parse(bad, GZ_SC_KEYFILE_LEN, SIGNET, NULL), GZ_SC_NOT_THIS_FORMAT);
    bad[8] = 1;
    bad[0] ^= 1;
    CHECK_ERR(gz_sc_keyfile_parse(bad, GZ_SC_KEYFILE_LEN, SIGNET, NULL), GZ_SC_NOT_THIS_FORMAT);
    /* 4.5 steps 1 and 2 with their stated reason, before any derivation
     * (test 2; review A, L7 f): every byte of kdf, t and p is read. */
    struct { size_t at; uint8_t v; } pb[] = {{57, 2}, {57, 0}, {66, 2}, {66, 0}, {58, 1}, {59, 1}, {60, 1}};
    for (size_t i = 0; i < sizeof pb / sizeof pb[0]; i++) {
        memcpy(bad, kf, sizeof bad);
        bad[pb[i].at] = pb[i].v;
        CHECK_ERR(gz_sc_keyfile_parse(bad, GZ_SC_KEYFILE_LEN, SIGNET, NULL), GZ_SC_PARAMS_REFUSED);
    }
    memcpy(bad, kf, sizeof bad);
    sc_put32(bad + 58, 0x01000003u); /* t's high byte: 16,777,219 passes */
    CHECK_ERR(gz_sc_keyfile_parse(bad, GZ_SC_KEYFILE_LEN, SIGNET, NULL), GZ_SC_PARAMS_REFUSED);
    /* 4.6 "check" (review A, L6): the same wallet's MSK, or another's. */
    {
        gz_sc_vault_t *cv = NULL, *ov = NULL;
        CHECK_ERR(gz_sc_keyfile_unlock(kf, pk, &cv), GZ_SC_OK);
        uint8_t om[32];
        memcpy(om, MSK, 32);
        om[5] ^= 1;
        CHECK_ERR(gz_sc_vault_new(SIGNET, VID, om, SEED64, &ov), GZ_SC_OK);
        if (cv && ov) {
            CHECK_ERR(gz_sc_keyfile_check(kf, pk, cv), GZ_SC_OK);
            CHECK_ERR(gz_sc_keyfile_check(kf, pk, ov), GZ_SC_NOT_THIS_WALLET);
            uint8_t wrong[32];
            memcpy(wrong, pk, 32);
            wrong[0] ^= 1;
            CHECK_ERR(gz_sc_keyfile_check(kf, wrong, cv), GZ_SC_WRONG_PASSPHRASE);
        }
        gz_sc_vault_free(cv);
        gz_sc_vault_free(ov);
    }
    /* "check" (4.6) compares all 32 bytes of MSK. */
    gz_sc_vault_t *vv = NULL;
    CHECK_ERR(gz_sc_keyfile_unlock(kf, pk, &vv), GZ_SC_OK);
    if (vv) {
        uint8_t m2[32];
        memcpy(m2, MSK, 32);
        CHECK(gz_sc_vault_same_msk(vv, m2));
        m2[31] ^= 1;
        CHECK(!gz_sc_vault_same_msk(vv, m2));
        m2[31] ^= 1;
        m2[0] ^= 1;
        CHECK(!gz_sc_vault_same_msk(vv, m2));
        gz_sc_vault_free(vv);
    }
    CHECK_ERR(gz_sc_keyfile_parse(kf, GZ_SC_KEYFILE_LEN - 1, SIGNET, NULL), GZ_SC_NOT_THIS_FORMAT);
    CHECK_ERR(gz_sc_keyfile_parse(kf, GZ_SC_KEYFILE_LEN + 1, SIGNET, NULL), GZ_SC_NOT_THIS_FORMAT);

    /* Test 5, key commitment: a file whose wrap opens under passphrase B but
     * whose commitment names A is refused for B (and for A, whose wrap fails). */
    const char *pwb = "another test passphrase, never used";
    uint8_t pkb[32], kfb[GZ_SC_KEYFILE_LEN];
    gz_sc_test_kdf_inprocess(NULL, (const uint8_t *)pwb, strlen(pwb), SALT, &TP, pkb, NULL);
    CHECK_ERR(gz_sc_keyfile_build(SIGNET, VID, &TP, SALT, pkb, MSK, ENT, SEED64, kfb), GZ_SC_OK);
    memcpy(kfb + 83, kf + 83, 32);
    CHECK_ERR(unlock_kf(kfb, pwb), GZ_SC_WRONG_PASSPHRASE);
    CHECK_ERR(unlock_kf(kfb, pw), GZ_SC_WRONG_PASSPHRASE);
    uint8_t ent[32];
    CHECK_ERR(gz_sc_keyfile_words(kfb, pkb, ent), GZ_SC_WRONG_PASSPHRASE);
    /* Rewrap refuses a wrong old key and leaves out untouched. */
    uint8_t out[GZ_SC_KEYFILE_LEN];
    memset(out, 0xaa, sizeof out);
    CHECK_ERR(gz_sc_keyfile_rewrap(kf, pkb, &TP, SALT, pkb, out), GZ_SC_WRONG_PASSPHRASE);
    CHECK(out[0] == 0xaa && out[362] == 0xaa);
    gz_sc_kdf_params_t below = {1, 3, 4, 1};
    CHECK_ERR(gz_sc_keyfile_rewrap(kf, pk, &below, SALT, pkb, out), GZ_SC_PARAMS_REFUSED);
    CHECK_ERR(gz_sc_keyfile_build(SIGNET, VID, &below, SALT, pk, MSK, ENT, SEED64, out), GZ_SC_PARAMS_REFUSED);
}

static void journal_fields(void)
{
    gz_sc_vault_t *v = NULL;
    gz_sc_vault_new(SIGNET, VID, MSK, SEED64, &v);
    uint8_t h[GZ_SC_JHEADER_LEN], bad[GZ_SC_JHEADER_LEN];
    CHECK_ERR(gz_sc_header_seal(v, FID, h), GZ_SC_OK);
    gz_sc_framekey_t *kj = NULL, *t = NULL;
    CHECK_ERR(gz_sc_header_open(h, v, &kj), GZ_SC_OK);
    int fails = 0;
    for (size_t i = 0; i < sizeof h; i++) {
        memcpy(bad, h, sizeof bad);
        bad[i] ^= 0x01;
        if (gz_sc_header_open(bad, v, &t) == GZ_SC_OK) {
            gz_sc_framekey_free(t);
            fails++;
        }
        uint8_t m[32];
        if (i >= 57 && gz_sc_header_recover(bad, SIGNET, SEED64, m) == GZ_SC_OK)
            fails++;
    }
    CHECK(fails == 0);
    CHECK_ERR(gz_sc_header_clear(h, 184, SIGNET, NULL, NULL), GZ_SC_NOT_THIS_FORMAT);
    /* Entries: every byte, and the argument rules of the writer. */
    uint8_t e[200], b2[200], pl[40], back[40];
    size_t n;
    for (int i = 0; i < 40; i++)
        pl[i] = (uint8_t)i;
    CHECK_ERR(gz_sc_frame_seal(kj, 1000, 2, 7, 9, pl, 40, e, sizeof e, &n), GZ_SC_OK);
    CHECK(n == 101);
    gz_sc_frame_t f;
    CHECK_ERR(gz_sc_frame_open(kj, e, n, 1000, &f, back, sizeof back), GZ_SC_OK);
    CHECK(f.kind == 2 && f.incarnation == 7 && f.sequence == 9 && memcmp(back, pl, 40) == 0);
    CHECK_ERR(gz_sc_frame_open(kj, e, n, 1000, &f, back, 39), GZ_SC_BUFFER);
    fails = 0;
    for (size_t i = 0; i < n; i++) {
        memcpy(b2, e, n);
        b2[i] ^= 0x01;
        if (gz_sc_frame_open(kj, b2, n, 1000, NULL, NULL, 0) == GZ_SC_OK)
            fails++;
    }
    CHECK(fails == 0);
    for (size_t cut = 0; cut < n; cut++)
        CHECK_ERR(gz_sc_frame_open(kj, e, cut, 1000, NULL, NULL, 0), GZ_SC_INVALID);
    CHECK_ERR(gz_sc_frame_open(kj, e, n, 1001, NULL, NULL, 0), GZ_SC_INVALID);
    /* A length above the maximum, or below 61, is invalid before any work. */
    memcpy(b2, e, n);
    sc_put32(b2, GZ_SC_FRAME_LEN_MAX + 1);
    CHECK_ERR(gz_sc_frame_open(kj, b2, (size_t)GZ_SC_FRAME_LEN_MAX + 10, 1000, NULL, NULL, 0), GZ_SC_INVALID);
    sc_put32(b2, 60);
    CHECK_ERR(gz_sc_frame_open(kj, b2, n, 1000, NULL, NULL, 0), GZ_SC_INVALID);
    /* Entries with a valid tag but a length or kind 5.5 forbids: invalid.
     * Built by hand with the journal key, as an attacker holding it could. */
    struct { uint8_t kind; size_t plen; } forged[] = {{2, 0}, {2, 3}, {0, 8}, {4, 8}, {1, 9}, {3, 7}, {0, 4}};
    for (size_t i = 0; i < sizeof forged / sizeof forged[0]; i++) {
        uint8_t fe[200], fad[45];
        size_t pn = forged[i].plen;
        sc_put32(fe, (uint32_t)(57 + pn));
        fe[4] = forged[i].kind;
        sc_put64(fe + 5, 1);
        sc_put64(fe + 13, 0);
        memcpy(fad, FID, 16);
        sc_put64(fad + 16, 1000);
        memcpy(fad + 24, fe, 21);
        memset(pl, 0, 8);
        sc_put64(pl, 1000);
        gz_sc_framekey_t *fk = NULL;
        gz_sc_framekey_derive(MSK, 32, "journal", SIGNET, FID, &fk);
        CHECK_ERR(sc_seal(&fk->kp, pl, pn, fad, sizeof fad, fe + 21), GZ_SC_OK);
        CHECK_ERR(gz_sc_frame_open(fk, fe, 61 + pn, 1000, NULL, NULL, 0), GZ_SC_INVALID);
        gz_sc_framekey_free(fk);
    }
    {   /* A sync mark with a valid tag naming another offset. */
        uint8_t fe[80], fad[45], p8[8];
        sc_put32(fe, 65);
        fe[4] = 3;
        sc_put64(fe + 5, 1);
        sc_put64(fe + 13, 0);
        memcpy(fad, FID, 16);
        sc_put64(fad + 16, 1000);
        memcpy(fad + 24, fe, 21);
        sc_put64(p8, 999);
        gz_sc_framekey_t *fk = NULL;
        gz_sc_framekey_derive(MSK, 32, "journal", SIGNET, FID, &fk);
        CHECK_ERR(sc_seal(&fk->kp, p8, 8, fad, sizeof fad, fe + 21), GZ_SC_OK);
        CHECK_ERR(gz_sc_frame_open(fk, fe, 69, 1000, NULL, NULL, 0), GZ_SC_INVALID);
        gz_sc_framekey_free(fk);
    }
    {   /* A header sealed under the same MSK for another vault_id. */
        uint8_t ovid[16], oh[GZ_SC_JHEADER_LEN];
        memcpy(ovid, VID, 16);
        ovid[0] ^= 1;
        gz_sc_vault_t *ov = NULL;
        gz_sc_vault_new(SIGNET, ovid, MSK, SEED64, &ov);
        CHECK_ERR(gz_sc_header_seal(ov, FID, oh), GZ_SC_OK);
        gz_sc_framekey_t *tk = NULL;
        CHECK_ERR(gz_sc_header_open(oh, v, &tk), GZ_SC_NOT_THIS_WALLET);
        CHECK(tk == NULL);
        gz_sc_vault_free(ov);
    }
    for (int i = 0; i < 40; i++)
        pl[i] = (uint8_t)i;
    uint8_t eight[8];
    sc_put64(eight, 5);
    CHECK_ERR(gz_sc_frame_seal(kj, 6, 3, 1, 0, eight, 8, e, sizeof e, &n), GZ_SC_ARG);
    CHECK_ERR(gz_sc_frame_seal(kj, 5, 3, 1, 0, eight, 8, e, sizeof e, &n), GZ_SC_OK);
    CHECK_ERR(gz_sc_frame_seal(kj, 5, 1, 1, 0, pl, 9, e, sizeof e, &n), GZ_SC_ARG);
    CHECK_ERR(gz_sc_frame_seal(kj, 5, 2, 1, 1, pl, 3, e, sizeof e, &n), GZ_SC_ARG);
    CHECK_ERR(gz_sc_frame_seal(kj, 5, 0, 1, 1, pl, 8, e, sizeof e, &n), GZ_SC_ARG);
    CHECK_ERR(gz_sc_frame_seal(kj, 5, 4, 1, 1, pl, 8, e, sizeof e, &n), GZ_SC_ARG);
    CHECK_ERR(gz_sc_frame_seal(kj, 5, 2, 1, 1, pl, 40, e, 100, &n), GZ_SC_BUFFER);
    /* A sync mark is self-locating: the same bytes at another offset fail. */
    CHECK_ERR(gz_sc_frame_seal(kj, 5, 3, 1, 0, eight, 8, e, sizeof e, &n), GZ_SC_OK);
    CHECK_ERR(gz_sc_frame_open(kj, e, n, 5, &f, NULL, 0), GZ_SC_OK);
    CHECK(f.kind == 3 && f.entry_len == 69);
    {   /* Offsets at and above 2^32 are bound in all 64 bits (review A, L7 c):
         * a journal can pass 4 GiB. */
        const uint64_t hi = (1ull << 32) + 185;
        CHECK_ERR(gz_sc_frame_seal(kj, hi, 2, 1, 1, pl, 40, e, sizeof e, &n), GZ_SC_OK);
        CHECK_ERR(gz_sc_frame_open(kj, e, n, hi, &f, back, sizeof back), GZ_SC_OK);
        CHECK_ERR(gz_sc_frame_open(kj, e, n, 185, NULL, NULL, 0), GZ_SC_INVALID);
        CHECK_ERR(gz_sc_frame_open(kj, e, n, hi + (1ull << 32), NULL, NULL, 0), GZ_SC_INVALID);
        uint8_t hm[8];
        sc_put64(hm, (1ull << 40) + 7);
        CHECK_ERR(gz_sc_frame_seal(kj, (1ull << 40) + 7, 3, 1, 0, hm, 8, e, sizeof e, &n), GZ_SC_OK);
        CHECK_ERR(gz_sc_frame_open(kj, e, n, (1ull << 40) + 7, &f, NULL, 0), GZ_SC_OK);
        CHECK_ERR(gz_sc_frame_open(kj, e, n, 7, NULL, NULL, 0), GZ_SC_INVALID);
    }
    {   /* The writer refuses a payload above 8 MiB, which its reader would
         * call invalid; 8 MiB exactly is sealed and opened (L7 d). */
        size_t max = GZ_SC_FRAME_LEN_MAX - 57;
        uint8_t *big = calloc(1, max + 1), *bo = malloc(max + 61);
        CHECK(big && bo);
        if (big && bo) {
            CHECK_ERR(gz_sc_frame_seal(kj, 185, 2, 1, 1, big, max + 1, bo, max + 61, &n), GZ_SC_ARG);
            CHECK_ERR(gz_sc_frame_seal(kj, 185, 2, 1, 1, big, max, bo, max + 61, &n), GZ_SC_OK);
            CHECK(n == max + 61);
            CHECK_ERR(gz_sc_frame_open(kj, bo, n, 185, &f, NULL, 0), GZ_SC_OK);
            CHECK(f.payload_len == max);
        }
        free(big);
        free(bo);
    }
    {   /* Stated reasons of the clear header checks (test 2; review A's
         * no-effect survivors): the journal header's format. */
        memcpy(bad, h, sizeof bad);
        bad[8] = 2;
        CHECK_ERR(gz_sc_header_clear(bad, sizeof bad, SIGNET, NULL, NULL), GZ_SC_NOT_THIS_FORMAT);
        bad[8] = 1;
        bad[9] ^= 1;
        CHECK_ERR(gz_sc_header_clear(bad, sizeof bad, SIGNET, NULL, NULL), GZ_SC_OTHER_NETWORK);
    }

    /* Test 7, hedging: with r forced to repeat, different entries at one
     * offset get different nonces, identical entries identical bytes. */
    uint8_t r[32] = {7}, a1[200], a2[200], a3[200];
    size_t l1, l2, l3;
    r_fixed(r);
    CHECK_ERR(gz_sc_frame_seal(kj, 500, 2, 1, 1, pl, 40, a1, sizeof a1, &l1), GZ_SC_OK);
    CHECK_ERR(gz_sc_frame_seal(kj, 500, 2, 1, 1, pl, 40, a2, sizeof a2, &l2), GZ_SC_OK);
    pl[0] ^= 1;
    CHECK_ERR(gz_sc_frame_seal(kj, 500, 2, 1, 1, pl, 40, a3, sizeof a3, &l3), GZ_SC_OK);
    CHECK(l1 == l2 && memcmp(a1, a2, l1) == 0);
    CHECK(memcmp(a1 + 21, a3 + 21, 24) != 0);
    CHECK_ERR(gz_sc_frame_seal(kj, 501, 2, 1, 1, pl, 40, a2, sizeof a2, &l2), GZ_SC_OK);
    CHECK(memcmp(a2 + 21, a3 + 21, 24) != 0); /* the offset is an input too */
    CHECK_ERR(gz_sc_frame_seal(kj, 500, 2, 1, 2, pl, 40, a2, sizeof a2, &l2), GZ_SC_OK);
    CHECK(memcmp(a2 + 21, a3 + 21, 24) != 0); /* and the clear head */
    r_os();
    CHECK_ERR(gz_sc_frame_seal(kj, 500, 2, 1, 1, pl, 40, a2, sizeof a2, &l2), GZ_SC_OK);
    CHECK(memcmp(a2 + 21, a3 + 21, 24) != 0); /* a working source: fresh nonces */

    /* Test 15: the random source failing is a storage failure; nothing is written. */
    memset(a1, 0x55, sizeof a1);
    r_fail_after(1);
    CHECK_ERR(gz_sc_frame_seal(kj, 500, 2, 1, 1, pl, 40, a1, sizeof a1, &l1), GZ_SC_RANDOM_FAILED);
    CHECK(a1[0] == 0x55 && a1[30] == 0x55);
    uint8_t kf[GZ_SC_KEYFILE_LEN], pk[32] = {1};
    memset(kf, 0x55, sizeof kf);
    r_fail_after(3); /* the seed's seal */
    CHECK_ERR(gz_sc_keyfile_build(SIGNET, VID, &TP, SALT, pk, MSK, ENT, SEED64, kf), GZ_SC_RANDOM_FAILED);
    CHECK(kf[0] == 0x55 && kf[362] == 0x55);
    char *gen = NULL;
    size_t gl;
    r_fail_after(1);
    CHECK_ERR(gz_sc_pass_generate(&gen, &gl), GZ_SC_RANDOM_FAILED);
    CHECK(gen == NULL);
    r_os();
    gz_sc_framekey_free(kj);

    /* The guard file: every byte, and the contents' strict lengths. */
    gz_sc_epoch_t ep[2] = {{0, 4}, {77, 1}};
    gz_sc_guard_t g = {5, 2, ep, 3}, g2;
    uint8_t gb[200], gbad[200];
    size_t gn;
    CHECK_ERR(gz_sc_guard_seal(v, &g, gb, sizeof gb, &gn), GZ_SC_OK);
    CHECK_ERR(gz_sc_guard_seal(v, &g, gb, gn - 1, &gn), GZ_SC_BUFFER);
    CHECK_ERR(gz_sc_guard_seal(v, &g, gb, sizeof gb, &gn), GZ_SC_OK);
    CHECK_ERR(gz_sc_guard_open(v, gb, gn, &g2), GZ_SC_OK);
    CHECK(g2.n_epochs == 2 && g2.epochs[1].epoch == 77 && g2.counter == 5 && g2.rounds_started == 3);
    gz_sc_guard_clear(&g2);
    fails = 0;
    for (size_t i = 0; i < gn; i++) {
        memcpy(gbad, gb, gn);
        gbad[i] ^= 0x01;
        if (gz_sc_guard_open(v, gbad, gn, &g2) == GZ_SC_OK)
            fails++;
        gz_sc_guard_clear(&g2);
    }
    CHECK(fails == 0);
    uint8_t c[34];
    size_t cl;
    CHECK_ERR(gz_sc_guard_contents(&g, c, sizeof c, &cl), GZ_SC_OK);
    CHECK_ERR(gz_sc_guard_parse(c, cl - 1, &g2), GZ_SC_DAMAGED);
    CHECK_ERR(gz_sc_guard_parse(c, 17, &g2), GZ_SC_DAMAGED);
    c[9] = 3;
    CHECK_ERR(gz_sc_guard_parse(c, cl, &g2), GZ_SC_DAMAGED);
    memcpy(gbad, gb, gn);
    gbad[9] ^= 1; /* another network's guard is said to be one */
    CHECK_ERR(gz_sc_guard_open(v, gbad, gn, &g2), GZ_SC_OTHER_NETWORK);
    gbad[9] ^= 1;
    gbad[0] ^= 1;
    CHECK_ERR(gz_sc_guard_open(v, gbad, gn, &g2), GZ_SC_NOT_THIS_FORMAT);

    /* The mark file (10.2): the clear header's stated reasons, and the torn
     * tail is one entry at most (review A, L2). */
    gz_sc_framekey_t *kh = NULL;
    CHECK_ERR(gz_sc_mark_key(v, FID, &kh), GZ_SC_OK);
    uint8_t mk[57 + 5 * 56], mbad[57 + 5 * 56];
    CHECK_ERR(gz_sc_mark_new(kh, SIGNET, mk), GZ_SC_OK);
    CHECK_ERR(gz_sc_mark_entry(kh, mk, 113, 1, 300, mk + 113), GZ_SC_OK);
    size_t ml = 169, end = 0;
    uint64_t mi = 0, mo = 0;
    CHECK(gz_sc_mark_read(kh, mk, ml, SIGNET, FID, &mi, &mo, &end) == GZ_SC_MARK_OK && mi == 1 && mo == 300 &&
          end == 169);
    memcpy(mbad, mk, ml);
    mbad[3] ^= 1;
    CHECK(gz_sc_mark_read(kh, mbad, ml, SIGNET, FID, &mi, &mo, &end) == GZ_SC_MARK_NOT_A_MARK_FILE);
    memcpy(mbad, mk, ml);
    mbad[20] ^= 1;
    CHECK(gz_sc_mark_read(kh, mbad, ml, SIGNET, FID, &mi, &mo, &end) == GZ_SC_MARK_NOT_A_MARK_FILE);
    memcpy(mbad, mk, ml);
    mbad[8] = 2;
    CHECK(gz_sc_mark_read(kh, mbad, ml, SIGNET, FID, &mi, &mo, &end) == GZ_SC_MARK_NOT_A_MARK_FILE);
    memcpy(mbad, mk, ml);
    mbad[45] ^= 1;
    CHECK(gz_sc_mark_read(kh, mbad, ml, SIGNET, FID, &mi, &mo, &end) == GZ_SC_MARK_OTHER_JOURNAL);
    /* One invalid full entry after the newest valid one: a torn tail, cut at 169. */
    memcpy(mbad, mk, ml);
    memset(mbad + 169, 0x5a, 56);
    CHECK(gz_sc_mark_read(kh, mbad, 225, SIGNET, FID, &mi, &mo, &end) == GZ_SC_MARK_OK && end == 169 && mi == 1);
    CHECK(gz_sc_mark_read(kh, mbad, 225 + 30, SIGNET, FID, &mi, &mo, &end) == GZ_SC_MARK_OK && end == 169);
    /* Two (probe P2) or three: damaged, never cut silently. */
    memset(mbad + 225, 0x5b, 56);
    CHECK(gz_sc_mark_read(kh, mbad, 281, SIGNET, FID, &mi, &mo, &end) == GZ_SC_MARK_DAMAGED);
    memset(mbad + 281, 0x5c, 56);
    CHECK(gz_sc_mark_read(kh, mbad, 337, SIGNET, FID, &mi, &mo, &end) == GZ_SC_MARK_DAMAGED);
    /* No valid entry at all, however many: possibly old, not damaged. */
    memset(mbad + 57, 0x5d, 112);
    CHECK(gz_sc_mark_read(kh, mbad, 337, SIGNET, FID, &mi, &mo, &end) == GZ_SC_MARK_NO_ENTRY);
    gz_sc_framekey_free(kh);
    gz_sc_vault_free(v);
}

static int marks_ok(void *ctx, uint64_t i, uint64_t o)
{
    (void)ctx;
    return i == 2 && o == 700;
}

static int marks_all(void *ctx, uint64_t i, uint64_t o)
{
    (void)ctx; (void)i; (void)o;
    return 1;
}

static void start_rule(void)
{
    /* Each test stands alone: an incarnation above the journal's is behind
     * even if the view claims the mark. */
    gz_sc_journal_view_t ja = {2, marks_all, NULL, 0};
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 3, 700, GZ_SC_OK, 0, &ja) == GZ_SC_START_BEHIND);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 2, 700, GZ_SC_OK, 0, &ja) == GZ_SC_START_OK);
    gz_sc_journal_view_t j = {2, marks_ok, NULL, 4};
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 2, 700, GZ_SC_OK, 4, &j) == GZ_SC_START_OK);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 0, 0, GZ_SC_OK, 0, &j) == GZ_SC_START_OK);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 2, 700, GZ_SC_MISSING, 0, &j) == GZ_SC_START_POSSIBLY_OLD);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 2, 700, GZ_SC_DAMAGED, 0, &j) == GZ_SC_START_POSSIBLY_OLD);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_NOT_A_MARK_FILE, 0, 0, GZ_SC_OK, 0, &j) == GZ_SC_START_POSSIBLY_OLD);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_NO_ENTRY, 0, 0, GZ_SC_OK, 0, &j) == GZ_SC_START_POSSIBLY_OLD);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_DAMAGED, 0, 0, GZ_SC_OK, 0, &j) == GZ_SC_START_POSSIBLY_OLD);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OTHER_JOURNAL, 0, 0, GZ_SC_OK, 0, &j) == GZ_SC_START_BEHIND);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 3, 700, GZ_SC_OK, 0, &j) == GZ_SC_START_BEHIND);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 2, 701, GZ_SC_OK, 0, &j) == GZ_SC_START_BEHIND);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 1, 700, GZ_SC_OK, 0, &j) == GZ_SC_START_BEHIND);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 0, 1, GZ_SC_OK, 0, &j) == GZ_SC_START_BEHIND);
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 2, 700, GZ_SC_OK, 5, &j) == GZ_SC_START_BEHIND);
    j.newest_guard_counter = 0;
    CHECK(gz_sc_start_rule(GZ_SC_MARK_OK, 0, 0, GZ_SC_OK, 1, &j) == GZ_SC_START_BEHIND);
}

static void exports(void)
{
    gz_sc_vault_t *v = NULL;
    gz_sc_vault_new(SIGNET, VID, MSK, SEED64, &v);
    uint8_t body[300], ex[700], bad[700], pkx[32] = {9}, *out;
    size_t bl = 0, xl, ol;
    uint8_t g[18] = {0};
    CHECK_ERR(gz_sc_export_body_begin(5, 0, g, 18, body, sizeof body, &bl), GZ_SC_OK);
    CHECK_ERR(gz_sc_export_body_entry(2, 1, 1, (const uint8_t *)"abcd", 4, body, sizeof body, &bl), GZ_SC_OK);
    CHECK_ERR(gz_sc_export_build(v, 1, FID, &TP, SALT, pkx, body, bl, NULL, 16, ex, sizeof ex, &xl), GZ_SC_OK);
    CHECK(xl == gz_sc_export_size(1, bl, 16));
    int fails = 0;
    for (size_t i = 0; i < xl; i++) {
        memcpy(bad, ex, xl);
        bad[i] ^= 0x01;
        if (gz_sc_export_open(bad, xl, SIGNET, pkx, NULL, &out, &ol) == GZ_SC_OK) {
            gz_sc_sfree(out);
            fails++;
        }
        /* The words do not read the slot, but every chunk's associated data
         * holds the whole prefix, slot included. */
        if (gz_sc_export_open(bad, xl, SIGNET, NULL, SEED64, &out, &ol) == GZ_SC_OK) {
            gz_sc_sfree(out);
            fails++;
        }
    }
    CHECK(fails == 0);
    for (size_t cut = 0; cut < xl; cut++)
        if (gz_sc_export_open(ex, cut, SIGNET, NULL, SEED64, &out, &ol) == GZ_SC_OK) {
            gz_sc_sfree(out);
            fails++;
        }
    CHECK(fails == 0);
    {   /* Key commitment of the slot: a wrap for B under a commitment for A. */
        uint8_t pkb[32] = {10}, exb[700];
        size_t xbl;
        CHECK_ERR(gz_sc_export_build(v, 1, FID, &TP, SALT, pkb, body, bl, NULL, 16, exb, sizeof exb, &xbl), GZ_SC_OK);
        memcpy(exb + 84, ex + 84, 32);
        CHECK_ERR(gz_sc_export_open(exb, xbl, SIGNET, pkb, NULL, &out, &ol), GZ_SC_WRONG_PASSPHRASE);
        CHECK_ERR(gz_sc_export_open(exb, xbl, SIGNET, pkx, NULL, &out, &ol), GZ_SC_WRONG_PASSPHRASE);
    }
    {   /* A chunk length below 40 or above 65,576 is damage, whatever
         * follows (no writer makes one; review A, L8); a chunk running past
         * the end is truncation. */
        uint8_t ex2[700];
        size_t x2l;
        CHECK_ERR(gz_sc_export_build(v, 2, FID, NULL, NULL, NULL, body, bl, NULL, 65536, ex2, sizeof ex2, &x2l),
                  GZ_SC_OK);
        uint8_t keep[4];
        memcpy(keep, ex2 + 58, 4);
        sc_put32(ex2 + 58, 39);
        CHECK_ERR(gz_sc_export_open(ex2, 58 + 4 + 39, SIGNET, NULL, SEED64, &out, &ol), GZ_SC_DAMAGED);
        sc_put32(ex2 + 58, 65577);
        CHECK_ERR(gz_sc_export_open(ex2, x2l, SIGNET, NULL, SEED64, &out, &ol), GZ_SC_DAMAGED);
        memcpy(ex2 + 58, keep, 4);
        CHECK_ERR(gz_sc_export_open(ex2, x2l - 1, SIGNET, NULL, SEED64, &out, &ol), GZ_SC_TRUNCATED);
        CHECK_ERR(gz_sc_export_open(ex2, x2l, SIGNET, NULL, SEED64, &out, &ol), GZ_SC_OK);
        gz_sc_sfree(out);
    }
    CHECK_ERR(gz_sc_export_open(ex, xl, SIGNET, pkx, SEED64, &out, &ol), GZ_SC_ARG);
    CHECK_ERR(gz_sc_export_open(ex, xl, SIGNET, NULL, NULL, &out, &ol), GZ_SC_ARG);
    CHECK_ERR(gz_sc_export_build(v, 1, FID, NULL, SALT, pkx, body, bl, NULL, 16, ex, sizeof ex, &xl), GZ_SC_ARG);
    CHECK_ERR(gz_sc_export_build(v, 2, FID, &TP, NULL, NULL, body, bl, NULL, 16, ex, sizeof ex, &xl), GZ_SC_ARG);
    CHECK_ERR(gz_sc_export_build(v, 3, FID, NULL, NULL, NULL, body, bl, NULL, 16, ex, sizeof ex, &xl), GZ_SC_ARG);
    CHECK_ERR(gz_sc_export_build(v, 2, FID, NULL, NULL, NULL, body, bl, NULL, 0, ex, sizeof ex, &xl), GZ_SC_ARG);
    CHECK_ERR(gz_sc_export_build(v, 2, FID, NULL, NULL, NULL, body, bl, NULL, 65537, ex, sizeof ex, &xl), GZ_SC_ARG);
    CHECK_ERR(gz_sc_export_build(v, 2, FID, NULL, NULL, NULL, body, bl, NULL, 16, ex, 50, &xl), GZ_SC_BUFFER);
    /* Body parsing: unknown flag bits, a short guard, an entry overrunning. */
    gz_sc_export_body_t pb;
    CHECK_ERR(gz_sc_export_body_parse(body, bl, 1, &pb), GZ_SC_OK);
    CHECK(pb.created_ms == 5 && pb.guard_len == 18 && pb.entries_len == 25 && !pb.entropy);
    CHECK_ERR(gz_sc_export_body_parse(body, bl - 1, 1, &pb), GZ_SC_DAMAGED);
    memcpy(bad, body, bl);
    bad[9] = 2;
    CHECK_ERR(gz_sc_export_body_parse(bad, bl, 1, &pb), GZ_SC_DAMAGED);
    bad[9] = 0;
    bad[0] = 2;
    CHECK_ERR(gz_sc_export_body_parse(bad, bl, 1, &pb), GZ_SC_DAMAGED);
    memcpy(bad, body, bl);
    sc_put32(bad + 10, 400);
    CHECK_ERR(gz_sc_export_body_parse(bad, bl, 1, &pb), GZ_SC_DAMAGED);
    CHECK_ERR(gz_sc_export_body_parse(body, 13, 1, &pb), GZ_SC_DAMAGED);
    /* Zero-length body content: one empty final chunk. */
    CHECK_ERR(gz_sc_export_body_begin(5, 0, NULL, 0, body, sizeof body, &bl), GZ_SC_OK);
    CHECK_ERR(gz_sc_export_build(v, 2, FID, NULL, NULL, NULL, body, bl, NULL, 65536, ex, sizeof ex, &xl), GZ_SC_OK);
    CHECK_ERR(gz_sc_export_open(ex, xl, SIGNET, NULL, SEED64, &out, &ol), GZ_SC_OK);
    CHECK(ol == bl);
    gz_sc_sfree(out);
    gz_sc_vault_free(v);
}

static void attempts(void)
{
    gz_sc_attempts_t a = {41, 0, 0, 0}, b;
    uint8_t f[GZ_SC_ATTEMPTS_LEN], bad[GZ_SC_ATTEMPTS_LEN];
    uint64_t now = 1000000;
    for (int i = 1; i <= 15; i++) {
        CHECK(gz_sc_attempts_wait(&a, now) == 0);
        gz_sc_attempts_wrong(&a, now);
        uint64_t d = gz_sc_attempts_wait(&a, now);
        uint64_t want = i <= 5 ? 1 : (i - 5 >= 10 ? 900 : (1ull << (i - 5)));
        if (want > 900)
            want = 900;
        CHECK(d == want);
        now += d;
    }
    CHECK(a.wrong_in_a_row == 15 && a.counter == 56);
    gz_sc_attempts_right(&a, now);
    CHECK(a.wrong_in_a_row == 0 && gz_sc_attempts_wait(&a, now) == 1 && a.counter == 57);
    gz_sc_attempts_encode(SIGNET, &a, f);
    CHECK(gz_sc_attempts_decode(SIGNET, f, sizeof f, now, &b) == 1);
    CHECK(b.counter == a.counter && b.wrong_in_a_row == 0 && b.blocked_until_s == a.blocked_until_s);
    int fails = 0;
    for (size_t i = 0; i < sizeof f; i++) {
        memcpy(bad, f, sizeof f);
        bad[i] ^= 0x01;
        if (gz_sc_attempts_decode(SIGNET, bad, sizeof bad, now, &b) != 0 || b.blocked_until_s != now + 900)
            fails++;
    }
    CHECK(fails == 0);
    CHECK(gz_sc_attempts_decode(SIGNET, NULL, 0, now, &b) == 0 && b.blocked_until_s == now + 900);
    CHECK(gz_sc_attempts_decode(SIGNET, f, sizeof f - 1, now, &b) == 0);
    uint8_t other[32] = {1};
    CHECK(gz_sc_attempts_decode(other, f, sizeof f, now, &b) == 0);
    /* A mode 2 file with a plain checksum (Slice 1 cannot check mode 2). */
    memcpy(bad, f, sizeof f);
    bad[68] = 2;
    uint8_t h[32];
    crypto_hash_sha256(h, bad, 69);
    memcpy(bad + 69, h, 16);
    CHECK(gz_sc_attempts_decode(SIGNET, bad, sizeof bad, now, &b) == 0 && b.blocked_until_s == now + 900);
    /* A damaged file of the right length: the counter carries on (L7 g). */
    gz_sc_attempts_t c41 = {41, 2, now - 5, now + 1};
    gz_sc_attempts_encode(SIGNET, &c41, f);
    memcpy(bad, f, sizeof f);
    bad[80] ^= 1;
    CHECK(gz_sc_attempts_decode(SIGNET, bad, sizeof bad, now, &b) == 0 && b.counter == 41 &&
          b.blocked_until_s == now + 900);
    gz_sc_attempts_wrong(&b, now);
    CHECK(b.counter == 42);
    /* Probe P1: a forged valid file cannot block longer than the strictest
     * state, nor date a wrong attempt in the future (review A, L1). */
    gz_sc_attempts_t forged = {7, 20, UINT64_MAX - 1, UINT64_MAX - 1};
    gz_sc_attempts_encode(SIGNET, &forged, f);
    CHECK(gz_sc_attempts_decode(SIGNET, f, sizeof f, now, &b) == 1 && b.blocked_until_s == now + 900 &&
          b.last_wrong_s == now && gz_sc_attempts_wait(&b, now) == 900);
    forged.blocked_until_s = now + 899;
    gz_sc_attempts_encode(SIGNET, &forged, f);
    CHECK(gz_sc_attempts_decode(SIGNET, f, sizeof f, now, &b) == 1 && b.blocked_until_s == now + 899);
    /* Probe P1b: at 2^64 - 1 the counter stays, it never wraps to 0. */
    gz_sc_attempts_t top = {UINT64_MAX, 0, 0, 0};
    gz_sc_attempts_encode(SIGNET, &top, f);
    memcpy(bad, f, sizeof f);
    bad[70] ^= 1;
    CHECK(gz_sc_attempts_decode(SIGNET, bad, sizeof bad, now, &b) == 0 && b.counter == UINT64_MAX);
    gz_sc_attempts_wrong(&b, now);
    CHECK(b.counter == UINT64_MAX);
    gz_sc_attempts_right(&b, now);
    CHECK(b.counter == UINT64_MAX);
    /* The clock near its end: no wrap of blocked_until either. */
    gz_sc_attempts_t late = {1, 0, 0, 0};
    gz_sc_attempts_wrong(&late, UINT64_MAX - 1);
    CHECK(late.blocked_until_s == UINT64_MAX);
    CHECK(gz_sc_attempts_decode(SIGNET, NULL, 0, UINT64_MAX - 10, &b) == 0 && b.blocked_until_s == UINT64_MAX);
}

/* Two-byte draws: 0xf300 (62,208, to be thrown away), then 0x0001. */
static int biased_source(void *ctx, uint8_t *out, size_t n)
{
    static int k;
    (void)ctx;
    for (size_t i = 0; i + 1 < n; i += 2) {
        out[i] = (k % 2 == 0) ? 0xf3 : 0x00;
        out[i + 1] = (k % 2 == 0) ? 0x00 : 0x01;
        k++;
    }
    return 0;
}

static void passphrases(void)
{
    /* 14 and 15 code points, with a 4-byte character (U+1F600). */
    const char *p14 = "abcdefghijklm\xf0\x9f\x98\x80", *p15 = "abcdefghijklmn\xf0\x9f\x98\x80";
    CHECK(gz_sc_pass_check((const uint8_t *)p14, strlen(p14), NULL, NULL, 0) == GZ_SC_PASS_TOO_SHORT);
    CHECK(gz_sc_pass_check((const uint8_t *)p15, strlen(p15), NULL, NULL, 0) == GZ_SC_PASS_OK);
    char big[1100];
    memset(big, 'q', sizeof big);
    CHECK(gz_sc_pass_check((const uint8_t *)big, 1024, NULL, NULL, 0) == GZ_SC_PASS_OK);
    CHECK(gz_sc_pass_check((const uint8_t *)big, 1025, NULL, NULL, 0) == GZ_SC_PASS_TOO_LONG);
    CHECK(gz_sc_pass_check((const uint8_t *)"\xff\xfe abcdefghijklmnop", 19, NULL, NULL, 0) == GZ_SC_PASS_NOT_UTF8);
    uint8_t *o;
    size_t ol, cp;
    CHECK_ERR(gz_sc_pass_nfc((const uint8_t *)"\xc3\x28", 2, &o, &ol, &cp), GZ_SC_ARG);
    CHECK_ERR(gz_sc_pass_nfc((const uint8_t *)big, GZ_SC_PASS_IN_MAX + 1, &o, &ol, &cp), GZ_SC_ARG);
    /* NFC: e + U+0301 composes; a Hangul jamo sequence composes to one syllable. */
    CHECK_ERR(gz_sc_pass_nfc((const uint8_t *)"\xe1\x84\x80\xe1\x85\xa1", 6, &o, &ol, &cp), GZ_SC_OK);
    CHECK(cp == 1 && ol == 3 && memcmp(o, "\xea\xb0\x80", 3) == 0);
    gz_sc_sfree(o);
    /* The blocklist, compared whole and case-insensitively. */
    const char *const list[] = {"correct horse battery staple"};
    const char *cand = "Correct Horse BATTERY Staple";
    CHECK(sc_pass_check_list((const uint8_t *)cand, strlen(cand), NULL, NULL, 0, list, 1) == GZ_SC_PASS_COMMON);
    CHECK(sc_pass_check_list((const uint8_t *)"correct horse battery staples", 29, NULL, NULL, 0, list, 1) ==
          GZ_SC_PASS_OK);
    /* The bundled list (open point 3): the pinned entries, sorted, each of
     * 15 lowercase ASCII characters or more; matched whole after folding. */
    {
        crypto_hash_sha256_state bst;
        uint8_t bd[32];
        crypto_hash_sha256_init(&bst);
        int sorted = 1, shape = 1;
        for (size_t i = 0; i < GZ_SC_BLOCK_N; i++) {
            const char *w = gz_sc_blocklist[i];
            if (i)
                crypto_hash_sha256_update(&bst, (const uint8_t *)"\n", 1);
            crypto_hash_sha256_update(&bst, (const uint8_t *)w, strlen(w));
            if (i && strcmp(gz_sc_blocklist[i - 1], w) >= 0)
                sorted = 0;
            if (strlen(w) < GZ_SC_PASS_MIN_CP)
                shape = 0;
            for (const char *q = w; *q; q++)
                if ((unsigned char)*q < 0x20 || (unsigned char)*q >= 0x7f || (*q >= 'A' && *q <= 'Z'))
                    shape = 0;
        }
        crypto_hash_sha256_final(&bst, bd);
        eq_hex("blocklist digest", bd, 32, GZ_SC_BLOCK_DIGEST_HEX);
        CHECK(sorted && shape);
        const char *common[] = {"passwordpassword", "PasswordPassword", "QWERTYUIOPASDFG", "1234567890123456"};
        for (size_t i = 0; i < 4; i++)
            CHECK(gz_sc_pass_check((const uint8_t *)common[i], strlen(common[i]), NULL, NULL, 0) ==
                  GZ_SC_PASS_COMMON);
        /* Entries spread over the list are refused, the first and the last
         * included (every entry would take minutes under valgrind). */
        size_t missed = 0;
        for (size_t i = 0;; i += 97) {
            if (i >= GZ_SC_BLOCK_N)
                i = GZ_SC_BLOCK_N - 1;
            if (gz_sc_pass_check((const uint8_t *)gz_sc_blocklist[i], strlen(gz_sc_blocklist[i]), NULL, NULL, 0) !=
                GZ_SC_PASS_COMMON)
                missed++;
            if (i == GZ_SC_BLOCK_N - 1)
                break;
        }
        CHECK(missed == 0);
        const char *fine[] = {"the quick zebra paints violins", "a passphrase nobody has typed yet",
                              "seventeen orange kites over Ghent"};
        for (size_t i = 0; i < 3; i++)
            CHECK(gz_sc_pass_check((const uint8_t *)fine[i], strlen(fine[i]), NULL, NULL, 0) == GZ_SC_PASS_OK);
    }
    /* NFC is the caller's to apply; a decomposed passphrase is refused as
     * such, never derived from (review A, M3). */
    {
        const char *dec = "caf" "e\xcc\x81" " au lait, deux sucres"; /* e + U+0301 */
        const char *pre = "caf" "\xc3\xa9" " au lait, deux sucres";
        CHECK(gz_sc_pass_check_form((const uint8_t *)dec, strlen(dec)) == GZ_SC_PASS_NOT_NFC);
        CHECK(gz_sc_pass_check((const uint8_t *)dec, strlen(dec), NULL, NULL, 0) == GZ_SC_PASS_NOT_NFC);
        CHECK(gz_sc_pass_check_form((const uint8_t *)pre, strlen(pre)) == GZ_SC_PASS_OK);
        CHECK(gz_sc_pass_check_form((const uint8_t *)p14, strlen(p14)) == GZ_SC_PASS_TOO_SHORT);
        CHECK(gz_sc_pass_check_form((const uint8_t *)big, 1025) == GZ_SC_PASS_TOO_LONG);
        CHECK(gz_sc_pass_check_form((const uint8_t *)big, 1024) == GZ_SC_PASS_OK);
        CHECK(gz_sc_pass_check_form((const uint8_t *)"\xc3\x28 abcdefghijklmnopq", 20) == GZ_SC_PASS_NOT_UTF8);
        CHECK(strcmp(gz_sc_err_text(GZ_SC_PASS_REFUSED), "unknown") != 0);
    }
    /* gazpacho or the wallet's name, with or without digits. */
    CHECK(gz_sc_pass_check((const uint8_t *)"GazPacho1234567", 15, NULL, NULL, 0) == GZ_SC_PASS_NAME);
    CHECK(gz_sc_pass_check((const uint8_t *)"1234567gazpacho", 15, NULL, NULL, 0) == GZ_SC_PASS_NAME);
    CHECK(gz_sc_pass_check((const uint8_t *)"gazpacho soup 1234", 18, NULL, NULL, 0) == GZ_SC_PASS_OK);
    CHECK(gz_sc_pass_check((const uint8_t *)"My Wallet 2026 0001", 19, "My Wallet", NULL, 0) == GZ_SC_PASS_NAME);
    CHECK(gz_sc_pass_check((const uint8_t *)"Holiday Fund 2026", 17, "holiday fund", NULL, 0) == GZ_SC_PASS_NAME);
    CHECK(gz_sc_pass_check((const uint8_t *)"Holiday Fund 2026!", 18, "holiday fund", NULL, 0) == GZ_SC_PASS_OK);
    CHECK(gz_sc_pass_check((const uint8_t *)"HolidayFund20261", 16, "holidayfund", NULL, 0) == GZ_SC_PASS_NAME);
    /* Three or more of the wallet's own words, in order. */
    const char *const words[24] = {"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
                                   "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
                                   "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual"};
    const char *w3 = "my Able and ABOUT then absorb!", *w3r = "absorb about able plus padding";
    const char *w2 = "able about and padding forever";
    CHECK(gz_sc_pass_check((const uint8_t *)w3, strlen(w3), NULL, words, 24) == GZ_SC_PASS_WORDS);
    CHECK(gz_sc_pass_check((const uint8_t *)w3r, strlen(w3r), NULL, words, 24) == GZ_SC_PASS_OK);
    CHECK(gz_sc_pass_check((const uint8_t *)w2, strlen(w2), NULL, words, 24) == GZ_SC_PASS_OK);
    CHECK(gz_sc_pass_check((const uint8_t *)w3, strlen(w3), NULL, NULL, 0) == GZ_SC_PASS_OK);
    /* Generated: six list words, single spaces, passing every rule. */
    char *gen = NULL;
    size_t gl = 0;
    CHECK_ERR(gz_sc_pass_generate(&gen, &gl), GZ_SC_OK);
    if (gen) {
        int nw = 1;
        for (size_t i = 0; i < gl; i++)
            nw += gen[i] == ' ';
        CHECK(nw == 6 && strlen(gen) == gl);
        CHECK(gz_sc_pass_check((const uint8_t *)gen, gl, NULL, words, 24) == GZ_SC_PASS_OK);
        char *save = NULL, *tok = strtok_r(gen, " ", &save);
        int found = 0;
        while (tok) {
            for (int i = 0; i < GZ_SC_EFF_WORDS; i++)
                if (strcmp(gz_sc_eff_words[i], tok) == 0) {
                    found++;
                    break;
                }
            tok = strtok_r(NULL, " ", &save);
        }
        CHECK(found == 6);
        gz_sc_sfree(gen);
    }
    /* No modulo bias: a draw of 62,208 or more is thrown away, not reduced. */
    gz_sc_test_set_random(biased_source, NULL);
    gen = NULL;
    CHECK_ERR(gz_sc_pass_generate(&gen, &gl), GZ_SC_OK);
    CHECK(gen && strncmp(gen, "abdomen ", 8) == 0);
    gz_sc_sfree(gen);
    r_os();
    /* The bundled list is the pinned EFF large list. */
    crypto_hash_sha256_state st;
    uint8_t d[32];
    crypto_hash_sha256_init(&st);
    size_t longest = 0;
    for (int i = 0; i < GZ_SC_EFF_WORDS; i++) {
        if (i)
            crypto_hash_sha256_update(&st, (const uint8_t *)"\n", 1);
        crypto_hash_sha256_update(&st, (const uint8_t *)gz_sc_eff_words[i], strlen(gz_sc_eff_words[i]));
        if (strlen(gz_sc_eff_words[i]) > longest)
            longest = strlen(gz_sc_eff_words[i]);
    }
    crypto_hash_sha256_final(&st, d);
    eq_hex("EFF word list digest", d, 32, GZ_SC_EFF_DIGEST_HEX);
    CHECK(longest == GZ_SC_EFF_WORD_MAX);
}

static void token_dir(void)
{
    char p[512], dir[] = "/tmp/gz-sc-token-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    setenv("XDG_RUNTIME_DIR", dir, 1);
    CHECK_ERR(gz_sc_token_dir("/home/a/.local/share/gazpacho", p, sizeof p), GZ_SC_OK);
    uint8_t h[32];
    char hex[17], want[512];
    crypto_hash_sha256(h, (const uint8_t *)"/home/a/.local/share/gazpacho", 29);
    sodium_bin2hex(hex, sizeof hex, h, 8);
    snprintf(want, sizeof want, "%s/gazpacho-%s", dir, hex);
    CHECK(strcmp(p, want) == 0);
    CHECK_ERR(gz_sc_token_dir_make(p), GZ_SC_OK);
    struct stat st;
    CHECK(lstat(p, &st) == 0 && (st.st_mode & 07777) == 0700);
    CHECK_ERR(gz_sc_token_dir_make(p), GZ_SC_OK);
    chmod(p, 0755);
    CHECK_ERR(gz_sc_token_dir_make(p), GZ_SC_UNSAFE_PATH);
    rmdir(p);
    CHECK(symlink(dir, p) == 0);
    CHECK_ERR(gz_sc_token_dir_make(p), GZ_SC_UNSAFE_PATH);
    unlink(p);
    CHECK_ERR(gz_sc_token_dir("relative/path", p, sizeof p), GZ_SC_ARG);
    CHECK_ERR(gz_sc_token_dir("/x", p, 10), GZ_SC_BUFFER);
    setenv("XDG_RUNTIME_DIR", "relative", 1);
    CHECK_ERR(gz_sc_token_dir("/home/a/.local/share/gazpacho", p, sizeof p), GZ_SC_OK);
    snprintf(want, sizeof want, "/tmp/gazpacho-%lu-%s", (unsigned long)getuid(), hex);
    CHECK(strcmp(p, want) == 0);
    unsetenv("XDG_RUNTIME_DIR");
    CHECK_ERR(gz_sc_token_dir("/home/a/.local/share/gazpacho", p, sizeof p), GZ_SC_OK);
    CHECK(strcmp(p, want) == 0);
    rmdir(dir);
}

int main(void)
{
    sc_test_init();
    tv("format storage key", MSK, 32);
    tv("format vault", VID, 16);
    tv("format salt", SALT, 16);
    tv("format entropy", ENT, 32);
    tv("format file id", FID, 16);
    params();
    keyfile_fields();
    journal_fields();
    start_rule();
    exports();
    attempts();
    passphrases();
    token_dir();
    CHECK(strcmp(gz_sc_err_text(GZ_SC_WRONG_PASSPHRASE), "wrong passphrase or damaged key file") == 0);
    CHECK(strcmp(gz_sc_err_text(GZ_SC_HELPER_FAILED), "the passphrase could not be checked") == 0);
    return sc_test_done("storage formats");
}
