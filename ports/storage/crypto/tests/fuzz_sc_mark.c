/* The mark file reader (10.2) and the guard file (10.1). Raw inputs, with the
 * expected header put in front half the time; inputs starting with 'M' build
 * a mark file of the fuzzer's points, damage it, and check the reader's rules. */
#include "gz_storage_crypto.h"
#include "gz_storage_crypto_test.h"

#include <stdlib.h>
#include <string.h>

static gz_sc_framekey_t *kh;
static gz_sc_vault_t *vault;
static const uint8_t CHAIN[32] = {0xf6, 0x1e};
static const uint8_t FID[16] = {4};

static void init(void)
{
    if (kh)
        return;
    if (gz_sc_init() != GZ_SC_OK)
        abort();
    uint8_t msk[32] = {7}, seed[64] = {5}, vid[16] = {1};
    if (gz_sc_vault_new(CHAIN, vid, msk, seed, &vault) != GZ_SC_OK || gz_sc_mark_key(vault, FID, &kh) != GZ_SC_OK)
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    init();
    static uint8_t buf[4200];
    uint64_t inc, off;
    size_t end;
    gz_sc_mark_state_t st = gz_sc_mark_read(kh, data, size, CHAIN, FID, &inc, &off, &end);
    if (st == GZ_SC_MARK_OK)
        abort();
    if (size + 57 <= sizeof buf) {
        uint8_t mk[113];
        gz_sc_mark_new(kh, CHAIN, mk);
        memcpy(buf, mk, 57);
        memcpy(buf + 57, data, size);
        st = gz_sc_mark_read(kh, buf, size + 57, CHAIN, FID, &inc, &off, &end);
        if (st == GZ_SC_MARK_OK || st == GZ_SC_MARK_NOT_A_MARK_FILE || st == GZ_SC_MARK_OTHER_JOURNAL)
            abort();
    }
    gz_sc_guard_t g;
    if (gz_sc_guard_parse(data, size, &g) == GZ_SC_OK) {
        if (gz_sc_guard_contents_len(&g) != size)
            abort();
        uint8_t again[4200];
        size_t al;
        if (gz_sc_guard_contents(&g, again, sizeof again, &al) != GZ_SC_OK || al != size ||
            memcmp(again, data, size) != 0)
            abort();
        uint8_t sealed[4300];
        size_t sl;
        gz_sc_guard_t back;
        if (gz_sc_guard_seal(vault, &g, sealed, sizeof sealed, &sl) != GZ_SC_OK ||
            gz_sc_guard_open(vault, sealed, sl, &back) != GZ_SC_OK || back.counter != g.counter ||
            back.n_epochs != g.n_epochs)
            abort();
        gz_sc_guard_clear(&back);
    }
    gz_sc_guard_clear(&g);
    if (gz_sc_guard_open(vault, data, size, &g) == GZ_SC_OK)
        abort();
    gz_sc_guard_clear(&g);

    /* Structured: points (inc, off) from the input, non-decreasing. */
    if (size >= 3 && data[0] == 'M') {
        size_t n = 1 + data[1] % 8, len = 0;
        uint8_t mk[57 + 56 * 9];
        if (gz_sc_mark_new(kh, CHAIN, mk) != GZ_SC_OK)
            abort();
        len = 113;
        uint64_t i0 = 0, o0 = 0;
        for (size_t k = 0; k < n; k++) {
            uint8_t b = k + 2 < size ? data[k + 2] : 0;
            i0 += b >> 6;
            o0 += b & 63;
            if (gz_sc_mark_entry(kh, mk, len, i0, o0, mk + len) != GZ_SC_OK)
                abort();
            len += 56;
        }
        if (gz_sc_mark_read(kh, mk, len, CHAIN, FID, &inc, &off, &end) != GZ_SC_MARK_OK || inc != i0 ||
            off != o0 || end != len)
            abort();
        /* A torn tail of any length is ignored. */
        size_t cut = len - data[2] % 56;
        st = gz_sc_mark_read(kh, mk, cut, CHAIN, FID, &inc, &off, &end);
        if (st != GZ_SC_MARK_OK || end > cut)
            abort();
        /* Damage to any entry before the last (entries 0 to n-1): damaged. */
        mk[57 + 56 * (data[2] % n) + 30] ^= 1;
        if (gz_sc_mark_read(kh, mk, len, CHAIN, FID, &inc, &off, &end) != GZ_SC_MARK_DAMAGED)
            abort();
    }
    return 0;
}
