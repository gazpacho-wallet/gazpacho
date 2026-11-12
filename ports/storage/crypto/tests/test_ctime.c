/* Constant time where secrets meet branches (libsecp256k1's valgrind ctime
 * method): the passphrase key, MSK, the seed and the words' entropy are
 * marked undefined, then every storage operation that holds them runs. Under
 * memcheck, any branch or memory index that depends on them is an error.
 * Declassified, on purpose: whether a tag or commitment verified (the
 * outcome is public), and plaintexts that are public once opened (entry
 * kinds and offsets, mark points, guard counts, export bodies).
 * Argon2id is not run here: its second half is data-dependent by design
 * (RFC 9106), which is why it runs in the helper process. Run by CTest as
 * `valgrind --error-exitcode=42 sc_test_ctime`; without valgrind it is a
 * plain functional test. */
#include "sc_internal.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <valgrind/memcheck.h>

#define SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))

static int fails;
#define OK(c)                                                         \
    do {                                                              \
        if (!(c)) {                                                   \
            fprintf(stderr, "%s:%d: failed: %s\n", __FILE__, __LINE__, #c); \
            fails++;                                                  \
        }                                                             \
    } while (0)

int main(void)
{
    if (gz_sc_init() != GZ_SC_OK)
        return 1;
    gz_sc_test_set_floor(1, 8);
    const uint8_t chain[32] = {0xf6, 0x1e}, vid[16] = {1}, salt[16] = {2}, fid[16] = {3};
    const gz_sc_kdf_params_t kp = {1, 1, 8, 1};
    uint8_t *pk = gz_sc_salloc(32), *msk = gz_sc_salloc(32), *seed = gz_sc_salloc(64), *ent = gz_sc_salloc(32);
    randombytes_buf(pk, 32);
    randombytes_buf(msk, 32);
    randombytes_buf(seed, 64);
    randombytes_buf(ent, 32);
    SECRET(pk, 32);
    SECRET(msk, 32);
    SECRET(seed, 64);
    SECRET(ent, 32);

    /* The key file: build (three seals, the commitment), unlock, words, rewrap. */
    uint8_t kf[GZ_SC_KEYFILE_LEN], kf2[GZ_SC_KEYFILE_LEN];
    OK(gz_sc_keyfile_build(chain, vid, &kp, salt, pk, msk, ent, seed, kf) == GZ_SC_OK);
    gz_sc_vault_t *v = NULL;
    OK(gz_sc_keyfile_unlock(kf, pk, &v) == GZ_SC_OK);
    uint8_t *e2 = gz_sc_salloc(32);
    OK(gz_sc_keyfile_words(kf, pk, e2) == GZ_SC_OK);
    OK(v && gz_sc_vault_same_msk(v, msk));
    uint8_t *pk2 = gz_sc_salloc(32);
    randombytes_buf(pk2, 32);
    SECRET(pk2, 32);
    OK(gz_sc_keyfile_rewrap(kf, pk, &kp, salt, pk2, kf2) == GZ_SC_OK);
    gz_sc_vault_t *v2 = NULL;
    OK(gz_sc_keyfile_unlock(kf2, pk2, &v2) == GZ_SC_OK);
    gz_sc_vault_free(v2);
    if (!v)
        return 1;

    /* The journal: header, entries, recovery by the seed. */
    uint8_t hdr[GZ_SC_JHEADER_LEN], ent_buf[200], pl[40] = {0}, back[40];
    gz_sc_framekey_t *kj = NULL, *kh = NULL;
    OK(gz_sc_header_seal(v, fid, hdr) == GZ_SC_OK);
    OK(gz_sc_header_open(hdr, v, &kj) == GZ_SC_OK);
    uint8_t *m2 = gz_sc_salloc(32);
    OK(gz_sc_header_recover(hdr, chain, seed, m2) == GZ_SC_OK);
    size_t n;
    memcpy(pl, "secret payload bytes", 20);
    SECRET(pl, sizeof pl);
    OK(kj && gz_sc_frame_seal(kj, 185, 2, 1, 1, pl, sizeof pl, ent_buf, sizeof ent_buf, &n) == GZ_SC_OK);
    gz_sc_frame_t f;
    OK(gz_sc_frame_open(kj, ent_buf, n, 185, &f, back, sizeof back) == GZ_SC_OK);
    uint8_t eight[8] = {0, 0, 0, 0, 0, 0, 0, 0xfa};
    OK(gz_sc_frame_seal(kj, 250, 3, 1, 0, eight, 8, ent_buf, sizeof ent_buf, &n) == GZ_SC_OK);
    OK(gz_sc_frame_open(kj, ent_buf, n, 250, &f, back, sizeof back) == GZ_SC_OK);

    /* The mark file and the guard. */
    uint8_t mk[GZ_SC_MARK_HEADER_LEN + 2 * GZ_SC_MARK_ENTRY_LEN];
    OK(gz_sc_mark_key(v, fid, &kh) == GZ_SC_OK);
    OK(gz_sc_mark_new(kh, chain, mk) == GZ_SC_OK);
    OK(gz_sc_mark_entry(kh, mk, 113, 1, 250, mk + 113) == GZ_SC_OK);
    uint64_t mi, mo;
    size_t end;
    OK(gz_sc_mark_read(kh, mk, sizeof mk, chain, fid, &mi, &mo, &end) == GZ_SC_MARK_OK);
    gz_sc_epoch_t ep = {0, 1};
    gz_sc_guard_t g = {1, 1, &ep, 0}, g2;
    uint8_t gb[200];
    size_t gl;
    OK(gz_sc_guard_seal(v, &g, gb, sizeof gb, &gl) == GZ_SC_OK);
    OK(gz_sc_guard_open(v, gb, gl, &g2) == GZ_SC_OK);
    gz_sc_guard_clear(&g2);

    /* An export, opened by the seed and by the passphrase key. */
    uint8_t body[100], x[600], *ob = NULL;
    size_t bl = 0, xl, ol;
    uint8_t gc[18] = {0};
    OK(gz_sc_export_body_begin(1, ent, gc, 18, body, sizeof body, &bl) == GZ_SC_OK);
    OK(gz_sc_export_build(v, 1, fid, &kp, salt, pk, body, bl, 64, x, sizeof x, &xl) == GZ_SC_OK);
    OK(gz_sc_export_open(x, xl, chain, NULL, seed, &ob, &ol) == GZ_SC_OK);
    free(ob);
    OK(gz_sc_export_open(x, xl, chain, pk, NULL, &ob, &ol) == GZ_SC_OK);
    free(ob);

    gz_sc_framekey_free(kj);
    gz_sc_framekey_free(kh);
    gz_sc_vault_free(v);
    gz_sc_sfree(pk);
    gz_sc_sfree(pk2);
    gz_sc_sfree(msk);
    gz_sc_sfree(m2);
    gz_sc_sfree(seed);
    gz_sc_sfree(ent);
    gz_sc_sfree(e2);
    if (fails) {
        fprintf(stderr, "storage ctime: %d failure(s)\n", fails);
        return 1;
    }
    printf("storage ctime: every operation ran with the secrets undefined\n");
    return 0;
}
