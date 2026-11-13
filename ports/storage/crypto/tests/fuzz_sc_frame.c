/* Journal entries and the journal header (spec 5.3 to 5.5). Raw inputs go
 * to gz_sc_frame_open at an offset taken from the input and to the header
 * checks; inputs starting with 'F' are sealed first (kind, offset and payload
 * from the fuzzer), then opened, compared, and opened with one flipped byte. */
#include "gz_storage_crypto.h"
#include "gz_storage_crypto_test.h"

#include <stdlib.h>
#include <string.h>

static gz_sc_framekey_t *kj;
static gz_sc_vault_t *vault;
static const uint8_t CHAIN[32] = {0xf6, 0x1e};

static void init(void)
{
    if (kj)
        return;
    if (gz_sc_init() != GZ_SC_OK)
        abort();
    uint8_t ikm[32] = {7}, fid[16] = {9}, seed[64] = {5};
    if (gz_sc_framekey_derive(ikm, 32, "journal", CHAIN, fid, &kj) != GZ_SC_OK ||
        gz_sc_vault_new(CHAIN, fid, ikm, seed, &vault) != GZ_SC_OK)
        abort();
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = v << 8 | p[i];
    return v;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    init();
    static uint8_t pl[8400], ent[8400];
    gz_sc_frame_t f;
    uint64_t off = size >= 8 ? get64(data) : 0;
    const uint8_t *e = size >= 8 ? data + 8 : data;
    size_t el = size >= 8 ? size - 8 : size;
    if (gz_sc_frame_open(kj, e, el, off, &f, pl, sizeof pl) == GZ_SC_OK)
        abort(); /* a random entry cannot carry a valid tag */
    uint8_t vid[16], fid[16];
    if (gz_sc_header_clear(data, size, CHAIN, vid, fid) == GZ_SC_OK && size >= GZ_SC_JHEADER_LEN) {
        gz_sc_framekey_t *k = NULL;
        if (gz_sc_header_open(data, vault, &k) == GZ_SC_OK)
            abort();
        uint8_t msk[32], seed[64] = {5};
        if (gz_sc_header_recover(data, CHAIN, seed, msk) == GZ_SC_OK)
            abort();
    }
    if (size >= 11 && data[0] == 'F') {
        uint8_t kind = (uint8_t)(1 + data[1] % 3);
        uint64_t at = get64(data + 2) & 0xffffffffu;
        const uint8_t *p = data + 10;
        size_t n = size - 10;
        uint8_t eight[8];
        if (kind != 2) {
            for (int i = 0; i < 8; i++)
                eight[i] = (uint8_t)(kind == 3 ? at >> (56 - 8 * i) : (i < (int)n ? p[i] : 0));
            p = eight;
            n = 8;
        } else if (n < 4) {
            return 0;
        }
        size_t len = 0;
        if (gz_sc_frame_seal(kj, at, kind, 3, 4, p, n, ent, sizeof ent, &len) != GZ_SC_OK)
            abort();
        if (gz_sc_frame_open(kj, ent, len, at, &f, pl, sizeof pl) != GZ_SC_OK || f.kind != kind ||
            f.payload_len != n || memcmp(pl, p, n) != 0 || f.entry_len != len)
            abort();
        ent[(size_t)data[1] * 7 % len] ^= (uint8_t)(1u << (data[1] % 8));
        if (gz_sc_frame_open(kj, ent, len, at, &f, pl, sizeof pl) == GZ_SC_OK)
            abort();
    }
    return 0;
}
