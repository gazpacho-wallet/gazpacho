/* The start counter starts.gzs (contract-v2.md section 8, storage 10.3) and
 * the program's stand-in keys from the seed.
 *
 *   0   magic "GZSTART1"                  8
 *   8   format, 1                         1
 *   9   chain                             32
 *   41  seal(KC, u64 counter, ad = 0..40) 24 + 8 + 16
 *
 * KC = keys(seed, "start counter", chain) (4.4), so a restore from the words,
 * which makes a new key file, still reads it. A file that is short, of
 * another format or network, or fails its tag is treated as missing. */
#include "gz_storage_files.h"
#include "sc_internal.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#define ST_MAGIC "GZSTART1"

static gz_sc_err_t counter_keys(const gz_sc_vault_t *v, sc_keypair_t *kc)
{
    sodium_mprotect_readonly(v->seed);
    gz_sc_err_t e = sc_keys(v->seed, 64, "start counter", v->chain, 32, kc);
    sodium_mprotect_noaccess(v->seed);
    return e;
}

gz_sc_err_t gz_sc_counter_seal(const gz_sc_vault_t *v, uint64_t counter, uint8_t out[GZ_SC_STARTS_LEN])
{
    uint8_t c[8];
    sc_keypair_t kc;
    gz_sc_err_t e = counter_keys(v, &kc);
    if (e != GZ_SC_OK)
        return e;
    memcpy(out, ST_MAGIC, 8);
    out[8] = 1;
    memcpy(out + 9, v->chain, 32);
    sc_put64(c, counter);
    e = sc_seal(&kc, c, 8, out, 41, out + 41);
    sc_keys_free(&kc);
    return e;
}

gz_sc_err_t gz_sc_counter_open(const gz_sc_vault_t *v, const uint8_t *d, size_t len, uint64_t *counter)
{
    uint8_t c[8];
    sc_keypair_t kc;
    if (len != GZ_SC_STARTS_LEN || memcmp(d, ST_MAGIC, 8) != 0 || d[8] != 1)
        return GZ_SC_NOT_THIS_FORMAT;
    if (memcmp(d + 9, v->chain, 32) != 0)
        return GZ_SC_OTHER_NETWORK;
    gz_sc_err_t e = counter_keys(v, &kc);
    if (e != GZ_SC_OK)
        return e;
    int r = sc_unseal(&kc, d + 41, GZ_SC_STARTS_LEN - 41, d, 41, c);
    sc_keys_free(&kc);
    if (r != 0)
        return GZ_SC_DAMAGED;
    *counter = sc_get64(c);
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_counter_read(const gz_sc_store_t *s, const gz_sc_vault_t *v, uint64_t *counter)
{
    uint8_t *d = NULL;
    size_t len = 0;
    *counter = 0;
    gz_sc_err_t e = gz_sc_fs_read(s, GZ_SC_FILE_STARTS, GZ_SC_STARTS_LEN + 1, &d, &len);
    if (e == GZ_SC_MISSING)
        return e;
    if (e != GZ_SC_OK)
        return e == GZ_SC_NOMEM ? e : GZ_SC_STORAGE_FAILED;
    e = gz_sc_counter_open(v, d, len, counter);
    free(d);
    if (e == GZ_SC_NOMEM || e == GZ_SC_LIBRARY)
        return e;
    if (e != GZ_SC_OK) {
        *counter = 0;
        return GZ_SC_MISSING; /* a file that does not open is treated as missing (10.3) */
    }
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_counter_write(const gz_sc_store_t *s, const gz_sc_vault_t *v, uint64_t counter)
{
    uint8_t b[GZ_SC_STARTS_LEN];
    gz_sc_err_t e = gz_sc_counter_seal(v, counter, b);
    if (e == GZ_SC_OK)
        e = gz_sc_fs_replace(s, GZ_SC_FILE_STARTS, b, sizeof b);
    /* The incarnation entry rests on it: an unsynced folder is a failure. */
    return e == GZ_SC_DONE_WITH_FAULT ? GZ_SC_STORAGE_FAILED : e;
}

gz_sc_err_t gz_sc_vault_derive(const gz_sc_vault_t *v, const char *label, uint8_t out[32])
{
    uint8_t kp[32];
    if (!v || !label || !out)
        return GZ_SC_ARG;
    /* KP = derive(seed, "program keys", chain), then derive(KP, label, chain)
     * (4.4): no label gives a storage key such as KG, KC or BK (review B of
     * PR 54, M2). */
    sodium_mprotect_readonly(v->seed);
    gz_sc_err_t e = sc_derive(v->seed, 64, "program keys", v->chain, 32, kp);
    sodium_mprotect_noaccess(v->seed);
    if (e == GZ_SC_OK)
        e = sc_derive(kp, 32, label, v->chain, 32, out);
    sodium_memzero(kp, sizeof kp);
    return e;
}
