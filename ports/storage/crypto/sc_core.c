/* Primitives of spec/storage-encryption.md: subkeys (4.4), seal (5.2), the
 * key commitment (4.6), the storage random source (5.2), the parameter rule
 * (4.2), the unlocked vault and framed-file keys. */
#define _GNU_SOURCE
#include "sc_internal.h"

#include <errno.h>
#include <sodium.h>
#include <string.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

#define HKDF_SALT "gazpacho/v1/storage"
#define LABEL_MAX 48
#define CTX_MAX 48

const gz_sc_kdf_params_t GZ_SC_KDF_KEYFILE_DEFAULT = {1, 3, 262144, 1};
const gz_sc_kdf_params_t GZ_SC_KDF_EXPORT_DEFAULT = {1, 4, 1048576, 1};

const char *gz_sc_err_text(gz_sc_err_t e)
{
    switch (e) {
    case GZ_SC_OK: return "ok";
    case GZ_SC_NOT_THIS_FORMAT: return "not a file of this kind";
    case GZ_SC_OTHER_NETWORK: return "a file of another network";
    case GZ_SC_PARAMS_REFUSED: return "parameters refused";
    case GZ_SC_NEEDS_MORE_MEMORY: return "this file needs more memory than this device has; open it on a larger one";
    case GZ_SC_WRONG_PASSPHRASE: return "wrong passphrase or damaged key file";
    case GZ_SC_DAMAGED: return "damaged";
    case GZ_SC_NOT_THIS_WALLET: return "this journal is not this wallet's";
    case GZ_SC_INVALID: return "invalid entry";
    case GZ_SC_TRUNCATED: return "truncated";
    case GZ_SC_TRAILING_DATA: return "data after the final chunk";
    case GZ_SC_EMPTY_CHUNK: return "empty chunk before the end";
    case GZ_SC_NEEDS_WORDS: return "needs the 24 words";
    case GZ_SC_HELPER_FAILED: return "the passphrase could not be checked";
    case GZ_SC_RANDOM_FAILED: return "the random source failed";
    case GZ_SC_STORAGE_FAILED: return "storage failure";
    case GZ_SC_MISSING: return "missing";
    case GZ_SC_EXISTS: return "a wallet already exists";
    case GZ_SC_UNSAFE_PATH: return "unsafe folder";
    case GZ_SC_BUFFER: return "buffer too small";
    case GZ_SC_ARG: return "bad argument";
    case GZ_SC_NOMEM: return "out of memory";
    case GZ_SC_LIBRARY: return "libsodium is not the pinned version";
    case GZ_SC_PASS_REFUSED:
        return "passphrase refused: not normalised, too short, too long, or with a character a passphrase "
               "cannot hold";
    case GZ_SC_JOURNAL_HERE: return "a journal is in this folder: reopen it with the 24 words";
    case GZ_SC_DONE_WITH_FAULT: return "done, but the disk did not confirm every step";
    }
    return "unknown";
}

gz_sc_err_t gz_sc_init(void)
{
    /* The pinned release only (spec 13): checked at build time and at run time. */
    if (strcmp(SODIUM_VERSION_STRING, GZ_SC_SODIUM_PINNED) != 0)
        return GZ_SC_LIBRARY;
    if (sodium_init() < 0)
        return GZ_SC_LIBRARY;
    if (strcmp(sodium_version_string(), GZ_SC_SODIUM_PINNED) != 0)
        return GZ_SC_LIBRARY;
    return GZ_SC_OK;
}

void *gz_sc_salloc(size_t n)
{
    return sodium_malloc(n);
}

void gz_sc_sfree(void *p)
{
    if (p)
        sodium_free(p); /* zeroes before unmapping */
}

/* ---- the storage random source ------------------------------------------ */
#ifdef GZ_SC_TEST_ENTRY
static int (*test_random)(void *, uint8_t *, size_t);
static void *test_random_ctx;
void gz_sc_test_set_random(int (*fn)(void *ctx, uint8_t *out, size_t n), void *ctx)
{
    test_random = fn;
    test_random_ctx = ctx;
}
#endif

gz_sc_err_t gz_sc_random(uint8_t *out, size_t n)
{
#ifdef GZ_SC_TEST_ENTRY
    if (test_random)
        return test_random(test_random_ctx, out, n) == 0 ? GZ_SC_OK : GZ_SC_RANDOM_FAILED;
#endif
    size_t got = 0;
    while (got < n) {
#if defined(__linux__)
        /* Flags 0: blocks until the pool is initialised. */
        ssize_t r = getrandom(out + got, n - got, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return GZ_SC_RANDOM_FAILED;
        }
        got += (size_t)r;
#elif defined(__APPLE__)
        size_t chunk = n - got > 256 ? 256 : n - got;
        if (getentropy(out + got, chunk) != 0)
            return GZ_SC_RANDOM_FAILED;
        got += chunk;
#else
#error "storage random source: Linux and macOS only in Slice 1"
#endif
    }
    return GZ_SC_OK;
}

/* ---- subkeys -------------------------------------------------------------- */
gz_sc_err_t sc_derive(const uint8_t *ikm, size_t ikm_len, const char *label, const uint8_t *ctx,
                      size_t ctx_len, uint8_t out[32])
{
    size_t label_len = strlen(label);
    if (label_len == 0 || label_len > LABEL_MAX || ctx_len > CTX_MAX)
        return GZ_SC_ARG;
    uint8_t info[LABEL_MAX + 1 + CTX_MAX];
    memcpy(info, label, label_len);
    info[label_len] = 0x00;
    if (ctx_len)
        memcpy(info + label_len + 1, ctx, ctx_len);
    uint8_t *prk = sodium_malloc(crypto_kdf_hkdf_sha256_KEYBYTES);
    if (!prk)
        return GZ_SC_NOMEM;
    gz_sc_err_t e = GZ_SC_OK;
    if (crypto_kdf_hkdf_sha256_extract(prk, (const unsigned char *)HKDF_SALT, sizeof HKDF_SALT - 1, ikm, ikm_len) != 0 ||
        crypto_kdf_hkdf_sha256_expand(out, 32, (const char *)info, label_len + 1 + ctx_len, prk) != 0)
        e = GZ_SC_LIBRARY;
    sodium_free(prk);
    return e;
}

gz_sc_err_t sc_keys(const uint8_t *ikm, size_t ikm_len, const char *label, const uint8_t *ctx, size_t ctx_len,
                    sc_keypair_t *kp)
{
    char nlabel[LABEL_MAX + 8];
    size_t label_len = strlen(label);
    kp->mem = NULL;
    if (label_len + sizeof " nonce" > sizeof nlabel)
        return GZ_SC_ARG;
    memcpy(nlabel, label, label_len);
    memcpy(nlabel + label_len, " nonce", sizeof " nonce");
    uint8_t *m = sodium_malloc(64);
    if (!m)
        return GZ_SC_NOMEM;
    gz_sc_err_t e = sc_derive(ikm, ikm_len, label, ctx, ctx_len, m);
    if (e == GZ_SC_OK)
        e = sc_derive(ikm, ikm_len, nlabel, ctx, ctx_len, m + 32);
    if (e != GZ_SC_OK) {
        sodium_free(m);
        return e;
    }
    sodium_mprotect_noaccess(m);
    kp->mem = m;
    return GZ_SC_OK;
}

void sc_keys_free(sc_keypair_t *kp)
{
    if (kp && kp->mem) {
        sodium_mprotect_readwrite(kp->mem);
        sodium_free(kp->mem);
        kp->mem = NULL;
    }
}

gz_sc_err_t sc_seal(const sc_keypair_t *kp, const uint8_t *pt, size_t pt_len, const uint8_t *ad, size_t ad_len,
                    uint8_t *out)
{
    if (ad_len > UINT32_MAX)
        return GZ_SC_ARG;
    uint8_t r[32], len_ad[4];
    gz_sc_err_t e = gz_sc_random(r, sizeof r);
    if (e != GZ_SC_OK)
        return e;
    sc_put32(len_ad, (uint32_t)ad_len);
    uint8_t mac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    sodium_mprotect_readonly(kp->mem);
    crypto_auth_hmacsha256_init(&st, kp->mem + 32, 32);
    crypto_auth_hmacsha256_update(&st, r, sizeof r);
    crypto_auth_hmacsha256_update(&st, len_ad, sizeof len_ad);
    crypto_auth_hmacsha256_update(&st, ad, ad_len);
    crypto_auth_hmacsha256_update(&st, pt, pt_len);
    crypto_auth_hmacsha256_final(&st, mac);
    memcpy(out, mac, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    unsigned long long clen = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(out + 24, &clen, pt, pt_len, ad, ad_len, NULL, out,
                                                        kp->mem);
    sodium_mprotect_noaccess(kp->mem);
    sodium_memzero(&st, sizeof st);
    sodium_memzero(mac, sizeof mac);
    sodium_memzero(r, sizeof r);
    if (rc != 0 || clen != pt_len + 16)
        return GZ_SC_LIBRARY;
    return GZ_SC_OK;
}

int sc_unseal(const sc_keypair_t *kp, const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len,
              uint8_t *pt)
{
    if (in_len < 40)
        return -1;
    unsigned long long plen = 0;
    sodium_mprotect_readonly(kp->mem);
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &plen, NULL, in + 24, in_len - 24, ad, ad_len, in,
                                                        kp->mem);
    sodium_mprotect_noaccess(kp->mem);
    SC_DECLASSIFY(&rc, sizeof rc); /* whether a tag verified is public */
    return rc == 0 ? 0 : -1;
}

gz_sc_err_t sc_commitment(const uint8_t pk[32], const char *label, const uint8_t *ctx, size_t ctx_len,
                          const uint8_t *ad, size_t ad_len, uint8_t out[32])
{
    uint8_t *ck = sodium_malloc(32);
    if (!ck)
        return GZ_SC_NOMEM;
    gz_sc_err_t e = sc_derive(pk, 32, label, ctx, ctx_len, ck);
    if (e == GZ_SC_OK && crypto_auth_hmacsha256(out, ad, ad_len, ck) != 0)
        e = GZ_SC_LIBRARY;
    sodium_free(ck);
    return e;
}

int sc_commitment_ok(const uint8_t pk[32], const char *label, const uint8_t *ctx, size_t ctx_len,
                     const uint8_t *ad, size_t ad_len, const uint8_t stored[32])
{
    uint8_t *c = sodium_malloc(32);
    if (!c)
        return 0;
    int ok = 0;
    if (sc_commitment(pk, label, ctx, ctx_len, ad, ad_len, c) == GZ_SC_OK)
        ok = sodium_memcmp(c, stored, 32) == 0;
    SC_DECLASSIFY(&ok, sizeof ok);
    sodium_free(c);
    return ok;
}

/* ---- the parameter rule ------------------------------------------------------ */
static uint32_t floor_t = 3, floor_m = 65536;
static uint64_t phys_override;

#ifdef GZ_SC_TEST_ENTRY
void gz_sc_test_set_floor(uint32_t t_min, uint32_t m_kib_min)
{
    floor_t = t_min;
    floor_m = m_kib_min;
}
void gz_sc_test_set_phys(uint64_t bytes)
{
    phys_override = bytes;
}
#endif

static uint64_t phys_bytes(void)
{
    if (phys_override)
        return phys_override;
    long pages = sysconf(_SC_PHYS_PAGES), size = sysconf(_SC_PAGESIZE);
    if (pages <= 0 || size <= 0)
        return 0;
    return (uint64_t)pages * (uint64_t)size;
}

gz_sc_err_t gz_sc_params_check(const gz_sc_kdf_params_t *p)
{
    if (p->kdf != 1 || p->p != 1)
        return GZ_SC_PARAMS_REFUSED;
    if (p->t < floor_t || p->t > 16)
        return GZ_SC_PARAMS_REFUSED;
    if (p->m_kib < floor_m || p->m_kib > 4194304u)
        return GZ_SC_PARAMS_REFUSED;
    uint64_t bytes = (uint64_t)p->m_kib * 1024u;
    if (bytes > (uint64_t)SIZE_MAX || bytes > (uint64_t)crypto_pwhash_memlimit_max())
        return GZ_SC_NEEDS_MORE_MEMORY;
    uint64_t phys = phys_bytes();
    /* Unknown physical memory: the other two bounds still hold. */
    if (phys != 0 && bytes > phys / 2)
        return GZ_SC_NEEDS_MORE_MEMORY;
    return GZ_SC_OK;
}

void gz_sc_params_for_new_wrap(const gz_sc_kdf_params_t *stored, const gz_sc_kdf_params_t *def,
                               gz_sc_kdf_params_t *out)
{
    *out = *def;
    if (stored) {
        if (stored->t > out->t)
            out->t = stored->t;
        if (stored->m_kib > out->m_kib)
            out->m_kib = stored->m_kib;
    }
    /* Halve the memory while this device cannot hold it, never below the
     * stored value or the floor (an export "bounded by the device's ceiling"). */
    while (gz_sc_params_check(out) == GZ_SC_NEEDS_MORE_MEMORY && out->m_kib / 2 >= floor_m &&
           (!stored || out->m_kib / 2 >= stored->m_kib))
        out->m_kib /= 2;
}

/* ---- the vault ------------------------------------------------------------- */
gz_sc_err_t gz_sc_vault_new(const uint8_t chain[32], const uint8_t vault_id[16], const uint8_t msk[32],
                            const uint8_t seed[64], gz_sc_vault_t **out)
{
    *out = NULL;
    gz_sc_vault_t *v = sodium_malloc(sizeof *v);
    if (!v)
        return GZ_SC_NOMEM;
    memset(v, 0, sizeof *v);
    memcpy(v->chain, chain, 32);
    memcpy(v->vault_id, vault_id, 16);
    v->msk = sodium_malloc(32);
    v->seed = sodium_malloc(64);
    if (!v->msk || !v->seed) {
        gz_sc_vault_free(v);
        return GZ_SC_NOMEM;
    }
    memcpy(v->msk, msk, 32);
    memcpy(v->seed, seed, 64);
    sodium_mprotect_noaccess(v->msk);
    sodium_mprotect_noaccess(v->seed);
    *out = v;
    return GZ_SC_OK;
}

void sc_vault_set_kdf(gz_sc_vault_t *v, const gz_sc_kdf_params_t *p)
{
    v->kdf = *p;
    v->has_kdf = 1;
}

void gz_sc_vault_free(gz_sc_vault_t *v)
{
    if (!v)
        return;
    if (v->msk) {
        sodium_mprotect_readwrite(v->msk);
        sodium_free(v->msk);
    }
    if (v->seed) {
        sodium_mprotect_readwrite(v->seed);
        sodium_free(v->seed);
    }
    sodium_free(v);
}

void gz_sc_vault_ids(const gz_sc_vault_t *v, uint8_t chain[32], uint8_t vault_id[16])
{
    if (chain)
        memcpy(chain, v->chain, 32);
    if (vault_id)
        memcpy(vault_id, v->vault_id, 16);
}

int gz_sc_vault_same_msk(const gz_sc_vault_t *v, const uint8_t msk[32])
{
    sodium_mprotect_readonly(v->msk);
    int same = sodium_memcmp(v->msk, msk, 32) == 0;
    sodium_mprotect_noaccess(v->msk);
    SC_DECLASSIFY(&same, sizeof same);
    return same;
}

gz_sc_err_t gz_sc_vault_seed(const gz_sc_vault_t *v, uint8_t seed[64])
{
    sodium_mprotect_readonly(v->seed);
    memcpy(seed, v->seed, 64);
    sodium_mprotect_noaccess(v->seed);
    return GZ_SC_OK;
}

/* ---- framed-file keys -------------------------------------------------------- */
gz_sc_err_t gz_sc_framekey_derive(const uint8_t *ikm, size_t ikm_len, const char *label,
                                  const uint8_t chain[32], const uint8_t file_id[16],
                                  gz_sc_framekey_t **out)
{
    *out = NULL;
    gz_sc_framekey_t *k = sodium_malloc(sizeof *k);
    if (!k)
        return GZ_SC_NOMEM;
    uint8_t ctx[48];
    memcpy(ctx, chain, 32);
    memcpy(ctx + 32, file_id, 16);
    gz_sc_err_t e = sc_keys(ikm, ikm_len, label, ctx, sizeof ctx, &k->kp);
    if (e != GZ_SC_OK) {
        sodium_free(k);
        return e;
    }
    memcpy(k->file_id, file_id, 16);
    *out = k;
    return GZ_SC_OK;
}

void gz_sc_framekey_free(gz_sc_framekey_t *k)
{
    if (!k)
        return;
    sc_keys_free(&k->kp);
    sodium_free(k);
}
