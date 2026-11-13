/* The key file parser and opener (spec 4.5). Raw inputs exercise the parser
 * and the parameter rule; inputs starting with 'K' build a valid file from
 * the fuzzer's bytes and flip one byte, so the code after the tag runs too. */
#include "gz_storage_crypto.h"
#include "gz_storage_crypto_test.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t PK[32] = {1, 2, 3};

static void init(void)
{
    static int done;
    if (!done) {
        if (gz_sc_init() != GZ_SC_OK)
            abort();
        gz_sc_test_set_floor(1, 8);
        done = 1;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    init();
    uint8_t chain[32] = {0};
    if (size >= 41)
        memcpy(chain, data + 9, 32);
    gz_sc_keyfile_info_t info;
    gz_sc_err_t e = gz_sc_keyfile_parse(data, size, chain, &info);
    if (e == GZ_SC_OK && size == GZ_SC_KEYFILE_LEN) {
        gz_sc_vault_t *v = NULL;
        /* PK is not derived here: a random file with this PK must not open. */
        if (gz_sc_keyfile_unlock(data, PK, &v) == GZ_SC_OK)
            abort();
        uint8_t ent[32];
        if (gz_sc_keyfile_words(data, PK, ent) == GZ_SC_OK)
            abort();
    }
    if (size >= 1 + 16 + 16 + 32 + 32 + 64 + 2 && data[0] == 'K') {
        const uint8_t *p = data + 1;
        gz_sc_kdf_params_t kp = {1, 1, 8, 1};
        uint8_t kf[GZ_SC_KEYFILE_LEN];
        if (gz_sc_keyfile_build(chain, p, &kp, p + 16, PK, p + 32, p + 64, p + 96, kf) != GZ_SC_OK)
            abort();
        gz_sc_vault_t *v = NULL;
        if (gz_sc_keyfile_unlock(kf, PK, &v) != GZ_SC_OK || !gz_sc_vault_same_msk(v, p + 32))
            abort();
        gz_sc_vault_free(v);
        size_t at = ((size_t)data[size - 2] << 8 | data[size - 1]) % GZ_SC_KEYFILE_LEN;
        uint8_t x = data[size - 3] ? data[size - 3] : 1;
        kf[at] ^= x;
        v = NULL;
        e = gz_sc_keyfile_unlock(kf, PK, &v);
        /* Only the words (187..258) are not read by an unlock; the head is
         * under the commitment. */
        if (e == GZ_SC_OK && !(at >= 187 && at < 259))
            abort();
        gz_sc_vault_free(v);
    }
    return 0;
}
