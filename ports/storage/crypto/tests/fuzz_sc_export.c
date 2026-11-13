/* Exports (spec 11): the file parser and opener, the body parser, and the
 * attempts file decoder. Inputs starting with 'X' use the rest as a body:
 * when it parses, it is sealed in chunks of a fuzzer-chosen size, opened by
 * the words and by the passphrase key, compared, and opened again damaged. */
#include "gz_storage_crypto.h"
#include "gz_storage_crypto_test.h"

#include <stdlib.h>
#include <string.h>

static gz_sc_vault_t *vault;
static const uint8_t CHAIN[32] = {0xf6, 0x1e};
static const uint8_t SEED[64] = {5};
static const uint8_t PKX[32] = {3};

static void init(void)
{
    if (vault)
        return;
    if (gz_sc_init() != GZ_SC_OK)
        abort();
    gz_sc_test_set_floor(1, 8);
    uint8_t msk[32] = {7}, vid[16] = {1};
    if (gz_sc_vault_new(CHAIN, vid, msk, SEED, &vault) != GZ_SC_OK)
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    init();
    uint8_t *body = NULL;
    size_t bl = 0;
    gz_sc_export_info_t info;
    (void)gz_sc_export_parse(data, size, CHAIN, &info);
    if (gz_sc_export_open(data, size, CHAIN, NULL, SEED, &body, &bl) == GZ_SC_OK)
        abort();
    if (gz_sc_export_open(data, size, CHAIN, PKX, NULL, &body, &bl) == GZ_SC_OK)
        abort();
    for (uint8_t prof = 1; prof <= 2; prof++) {
        gz_sc_export_body_t b;
        if (gz_sc_export_body_parse(data, size, prof, &b) == GZ_SC_OK) {
            size_t pos = 0, n = 0, len;
            uint8_t k;
            uint64_t i, s;
            const uint8_t *p;
            int r;
            while ((r = gz_sc_export_body_next(&b, &pos, &k, &i, &s, &p, &len)) == 1)
                n += 21 + len;
            if (r != 0 || n != b.entries_len || (prof == 2 && b.entropy))
                abort();
        }
    }
    gz_sc_attempts_t a;
    if (gz_sc_attempts_decode(CHAIN, data, size, 1000, &a) == 0 && a.blocked_until_s != 1900)
        abort();

    if (size >= 2 && data[0] == 'X') {
        const uint8_t *bd = data + 2;
        size_t bdl = size - 2, part = 1 + data[1] % 97;
        gz_sc_export_body_t b;
        for (uint8_t prof = 1; prof <= 2; prof++) {
            if (gz_sc_export_body_parse(bd, bdl, prof, &b) != GZ_SC_OK)
                continue;
            size_t cap = gz_sc_export_size(prof, bdl, part), xl;
            uint8_t *x = malloc(cap), *cb = malloc(bdl);
            gz_sc_kdf_params_t kp = {1, 1, 8, 1};
            uint8_t salt[16] = {2};
            /* The builder takes the body without the words and the words apart. */
            size_t cbl = bdl;
            if (cb && b.entropy) {
                memcpy(cb, bd, 10);
                memcpy(cb + 10, bd + 42, bdl - 42);
                cbl = bdl - 32;
            } else if (cb) {
                memcpy(cb, bd, bdl);
            }
            if (!x || !cb ||
                gz_sc_export_build(vault, prof, salt, prof == 1 ? &kp : NULL, prof == 1 ? salt : NULL,
                                   prof == 1 ? PKX : NULL, cb, cbl, b.entropy, part, x, cap, &xl) != GZ_SC_OK ||
                xl != cap)
                abort();
            free(cb);
            if (gz_sc_export_open(x, xl, CHAIN, NULL, SEED, &body, &bl) != GZ_SC_OK || bl != bdl ||
                memcmp(body, bd, bdl) != 0)
                abort();
            gz_sc_sfree(body);
            gz_sc_err_t e = gz_sc_export_open(x, xl, CHAIN, PKX, NULL, &body, &bl);
            if (prof == 1 ? e != GZ_SC_OK : e != GZ_SC_NEEDS_WORDS)
                abort();
            gz_sc_sfree(body);
            x[(size_t)data[1] * 13 % xl] ^= 0x10;
            if (gz_sc_export_open(x, xl, CHAIN, NULL, SEED, &body, &bl) == GZ_SC_OK)
                abort();
            if (xl > 60 && gz_sc_export_open(x, xl - 1 - data[1] % 40, CHAIN, NULL, SEED, &body, &bl) == GZ_SC_OK)
                abort();
            free(x);
        }
    }
    return 0;
}
