/* The start counter starts.gzs (contract-v2.md section 8, storage 10.3). Raw
 * inputs must never open (no forged tag); a sealed counter with one byte
 * flipped (the input picks which and the value) must never open either, and
 * the unharmed one must give its value back. */
#include "gz_storage_crypto.h"
#include "gz_storage_crypto_test.h"
#include "gz_storage_files.h"

#include <stdlib.h>
#include <string.h>

static gz_sc_vault_t *vault;
static const uint8_t CHAIN[32] = {0xf6, 0x1e};

static void init(void)
{
    if (vault)
        return;
    uint8_t msk[32] = {7}, seed[64] = {5}, vid[16] = {1};
    if (gz_sc_init() != GZ_SC_OK || gz_sc_vault_new(CHAIN, vid, msk, seed, &vault) != GZ_SC_OK)
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    init();
    uint64_t v = 0;
    uint8_t f[GZ_SC_STARTS_LEN];
    if (gz_sc_counter_open(vault, data, size, &v) == GZ_SC_OK)
        abort(); /* nothing forged opens */
    if (size >= GZ_SC_STARTS_LEN - 41) { /* the head put in front of the input */
        uint8_t buf[GZ_SC_STARTS_LEN];
        if (gz_sc_counter_seal(vault, 1, f) != GZ_SC_OK)
            abort();
        memcpy(buf, f, 41);
        memcpy(buf + 41, data, GZ_SC_STARTS_LEN - 41);
        if (memcmp(buf, f, sizeof buf) != 0 && gz_sc_counter_open(vault, buf, sizeof buf, &v) == GZ_SC_OK)
            abort();
    }
    if (size >= 10) {
        uint64_t want = 0;
        for (int i = 0; i < 8; i++)
            want = want << 8 | data[i];
        if (gz_sc_counter_seal(vault, want, f) != GZ_SC_OK)
            abort();
        if (gz_sc_counter_open(vault, f, sizeof f, &v) != GZ_SC_OK || v != want)
            abort();
        size_t at = data[8] % GZ_SC_STARTS_LEN;
        f[at] = (uint8_t)(f[at] ^ (1u << (data[9] & 7)));
        if (gz_sc_counter_open(vault, f, sizeof f, &v) == GZ_SC_OK)
            abort(); /* every byte is the magic, the format, the chain or sealed */
    }
    return 0;
}
