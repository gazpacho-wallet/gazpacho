/* The key file keys.gzk (spec 4.5 to 4.7, 9.2). 363 bytes:
 *   0 magic "GZKEYFIL" | 8 format 1 | 9 chain | 41 vault_id | 57 kdf | 58 t
 *   62 m | 66 p | 67 salt | 83 commitment | 115 wrapped MSK (72)
 *   187 words (72) | 259 seed (104)                                          */
#include "sc_internal.h"

#include <sodium.h>
#include <string.h>

#define KF_MAGIC "GZKEYFIL"
#define KF_HEAD 83
#define KF_SEED_AD 57

static void head_ctx(const uint8_t *data, uint8_t ctx[48])
{
    memcpy(ctx, data + 9, 32);       /* chain */
    memcpy(ctx + 32, data + 41, 16); /* vault_id */
}

gz_sc_err_t gz_sc_keyfile_parse(const uint8_t *data, size_t len, const uint8_t chain[32],
                                gz_sc_keyfile_info_t *info)
{
    if (len != GZ_SC_KEYFILE_LEN || memcmp(data, KF_MAGIC, 8) != 0 || data[8] != 1)
        return GZ_SC_NOT_THIS_FORMAT;
    if (memcmp(data + 9, chain, 32) != 0)
        return GZ_SC_OTHER_NETWORK;
    gz_sc_keyfile_info_t in;
    memcpy(in.chain, data + 9, 32);
    memcpy(in.vault_id, data + 41, 16);
    in.kdf.kdf = data[57];
    in.kdf.t = sc_get32(data + 58);
    in.kdf.m_kib = sc_get32(data + 62);
    in.kdf.p = data[66];
    memcpy(in.salt, data + 67, 16);
    gz_sc_err_t e = gz_sc_params_check(&in.kdf);
    if (e != GZ_SC_OK)
        return e;
    if (info)
        *info = in;
    return GZ_SC_OK;
}

static void write_head(uint8_t *out, const uint8_t chain[32], const uint8_t vault_id[16],
                       const gz_sc_kdf_params_t *p, const uint8_t salt[16])
{
    memcpy(out, KF_MAGIC, 8);
    out[8] = 1;
    memcpy(out + 9, chain, 32);
    memcpy(out + 41, vault_id, 16);
    out[57] = p->kdf;
    sc_put32(out + 58, p->t);
    sc_put32(out + 62, p->m_kib);
    out[66] = p->p;
    memcpy(out + 67, salt, 16);
}

/* Commitment, wrap and words over a written head (bytes 0..82). */
static gz_sc_err_t seal_pk_part(uint8_t *out, const uint8_t pk[32], const uint8_t msk[32],
                                const uint8_t entropy[32])
{
    uint8_t ctx[48];
    head_ctx(out, ctx);
    gz_sc_err_t e = sc_commitment(pk, "key file commitment", ctx, sizeof ctx, out, KF_HEAD, out + 83);
    if (e != GZ_SC_OK)
        return e;
    sc_keypair_t kw, kd;
    if ((e = sc_keys(pk, 32, "key file wrap", ctx, sizeof ctx, &kw)) != GZ_SC_OK)
        return e;
    e = sc_seal(&kw, msk, 32, out, KF_HEAD, out + 115);
    sc_keys_free(&kw);
    if (e != GZ_SC_OK)
        return e;
    if ((e = sc_keys(pk, 32, "words", ctx, sizeof ctx, &kd)) != GZ_SC_OK)
        return e;
    e = sc_seal(&kd, entropy, 32, out, KF_HEAD, out + 187);
    sc_keys_free(&kd);
    return e;
}

gz_sc_err_t gz_sc_keyfile_build(const uint8_t chain[32], const uint8_t vault_id[16],
                                const gz_sc_kdf_params_t *params, const uint8_t salt[16],
                                const uint8_t pk[32], const uint8_t msk[32], const uint8_t entropy[32],
                                const uint8_t seed[64], uint8_t out[GZ_SC_KEYFILE_LEN])
{
    gz_sc_err_t e = gz_sc_params_check(params);
    if (e != GZ_SC_OK)
        return e;
    uint8_t tmp[GZ_SC_KEYFILE_LEN];
    write_head(tmp, chain, vault_id, params, salt);
    if ((e = seal_pk_part(tmp, pk, msk, entropy)) != GZ_SC_OK)
        goto done;
    uint8_t ctx[48];
    head_ctx(tmp, ctx);
    sc_keypair_t ks;
    if ((e = sc_keys(msk, 32, "node seed", ctx, sizeof ctx, &ks)) != GZ_SC_OK)
        goto done;
    e = sc_seal(&ks, seed, 64, tmp, KF_SEED_AD, tmp + 259);
    sc_keys_free(&ks);
    if (e == GZ_SC_OK)
        memcpy(out, tmp, sizeof tmp);
done:
    sodium_memzero(tmp, sizeof tmp);
    return e;
}

/* Steps 4 and 5: the commitment, then the wrap. msk: 32 guarded bytes. */
static gz_sc_err_t open_wrap(const uint8_t *data, const uint8_t pk[32], uint8_t *msk)
{
    uint8_t ctx[48];
    head_ctx(data, ctx);
    if (!sc_commitment_ok(pk, "key file commitment", ctx, sizeof ctx, data, KF_HEAD, data + 83))
        return GZ_SC_WRONG_PASSPHRASE;
    sc_keypair_t kw;
    gz_sc_err_t e = sc_keys(pk, 32, "key file wrap", ctx, sizeof ctx, &kw);
    if (e != GZ_SC_OK)
        return e;
    int rc = sc_unseal(&kw, data + 115, 72, data, KF_HEAD, msk);
    sc_keys_free(&kw);
    return rc == 0 ? GZ_SC_OK : GZ_SC_WRONG_PASSPHRASE;
}

gz_sc_err_t gz_sc_keyfile_unlock(const uint8_t data[GZ_SC_KEYFILE_LEN], const uint8_t pk[32],
                                 gz_sc_vault_t **out)
{
    *out = NULL;
    uint8_t *msk = sodium_malloc(32), *seed = sodium_malloc(64);
    gz_sc_err_t e = GZ_SC_NOMEM;
    if (!msk || !seed)
        goto done;
    if ((e = open_wrap(data, pk, msk)) != GZ_SC_OK)
        goto done;
    uint8_t ctx[48];
    head_ctx(data, ctx);
    sc_keypair_t ks;
    if ((e = sc_keys(msk, 32, "node seed", ctx, sizeof ctx, &ks)) != GZ_SC_OK)
        goto done;
    int rc = sc_unseal(&ks, data + 259, 104, data, KF_SEED_AD, seed);
    sc_keys_free(&ks);
    if (rc != 0) {
        e = GZ_SC_DAMAGED;
        goto done;
    }
    e = gz_sc_vault_new(data + 9, data + 41, msk, seed, out);
done:
    gz_sc_sfree(msk);
    gz_sc_sfree(seed);
    return e;
}

gz_sc_err_t gz_sc_keyfile_words(const uint8_t data[GZ_SC_KEYFILE_LEN], const uint8_t pk[32],
                                uint8_t entropy[32])
{
    uint8_t ctx[48];
    head_ctx(data, ctx);
    if (!sc_commitment_ok(pk, "key file commitment", ctx, sizeof ctx, data, KF_HEAD, data + 83))
        return GZ_SC_WRONG_PASSPHRASE;
    sc_keypair_t kd;
    gz_sc_err_t e = sc_keys(pk, 32, "words", ctx, sizeof ctx, &kd);
    if (e != GZ_SC_OK)
        return e;
    int rc = sc_unseal(&kd, data + 187, 72, data, KF_HEAD, entropy);
    sc_keys_free(&kd);
    return rc == 0 ? GZ_SC_OK : GZ_SC_DAMAGED;
}

gz_sc_err_t gz_sc_keyfile_rewrap(const uint8_t old[GZ_SC_KEYFILE_LEN], const uint8_t old_pk[32],
                                 const gz_sc_kdf_params_t *new_params, const uint8_t new_salt[16],
                                 const uint8_t new_pk[32], uint8_t out[GZ_SC_KEYFILE_LEN])
{
    gz_sc_err_t e = gz_sc_params_check(new_params);
    if (e != GZ_SC_OK)
        return e;
    uint8_t *msk = sodium_malloc(32), *entropy = sodium_malloc(32);
    uint8_t tmp[GZ_SC_KEYFILE_LEN];
    e = GZ_SC_NOMEM;
    if (!msk || !entropy)
        goto done;
    /* The old passphrase opens the wrap and the words (4.7). */
    if ((e = open_wrap(old, old_pk, msk)) != GZ_SC_OK)
        goto done;
    if ((e = gz_sc_keyfile_words(old, old_pk, entropy)) != GZ_SC_OK)
        goto done;
    write_head(tmp, old + 9, old + 41, new_params, new_salt);
    if ((e = seal_pk_part(tmp, new_pk, msk, entropy)) != GZ_SC_OK)
        goto done;
    /* The seed's associated data stops before the KDF fields: copied as is. */
    memcpy(tmp + 259, old + 259, 104);
    memcpy(out, tmp, sizeof tmp);
done:
    sodium_memzero(tmp, sizeof tmp);
    gz_sc_sfree(msk);
    gz_sc_sfree(entropy);
    return e;
}
