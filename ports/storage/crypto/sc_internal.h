/* Internal to ports/storage/crypto. */
#ifndef GAZPACHO_SC_INTERNAL_H
#define GAZPACHO_SC_INTERNAL_H

#include "gz_storage_crypto.h"

#include <stddef.h>
#include <stdint.h>

#define GZ_SC_SODIUM_PINNED "1.0.22"

/* The test entry point (4.2, F24): compiled only into the test library. */
#ifdef GZ_SC_TEST_ENTRY
#include "gz_storage_crypto_test.h"
#endif

static inline void sc_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static inline void sc_put64(uint8_t *p, uint64_t v)
{
    sc_put32(p, (uint32_t)(v >> 32));
    sc_put32(p + 4, (uint32_t)v);
}
static inline uint32_t sc_get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline uint64_t sc_get64(const uint8_t *p)
{
    return ((uint64_t)sc_get32(p) << 32) | (uint64_t)sc_get32(p + 4);
}

/* A sealing key K and its nonce key NK (4.4, 5.2), 64 guarded bytes,
 * no access between uses. */
typedef struct {
    uint8_t *mem; /* K = mem[0..32), NK = mem[32..64) */
} sc_keypair_t;

struct gz_sc_framekey {
    sc_keypair_t kp;
    uint8_t file_id[16];
};

struct gz_sc_vault {
    uint8_t chain[32];
    uint8_t vault_id[16];
    uint8_t *msk;  /* 32 guarded bytes */
    uint8_t *seed; /* 64 guarded bytes */
};

/* derive(IKM, label, context) = HKDF-SHA256(salt "gazpacho/v1/storage",
 * IKM, info = label || 0x00 || context, 32). out: 32 bytes. */
gz_sc_err_t sc_derive(const uint8_t *ikm, size_t ikm_len, const char *label, const uint8_t *ctx,
                      size_t ctx_len, uint8_t out[32]);
/* keys(): K under label, NK under label || " nonce". */
gz_sc_err_t sc_keys(const uint8_t *ikm, size_t ikm_len, const char *label, const uint8_t *ctx, size_t ctx_len,
                    sc_keypair_t *kp);
void sc_keys_free(sc_keypair_t *kp);
/* seal() = nonce || XChaCha20-Poly1305(K, nonce, pt, ad), nonce = first 24
 * bytes of HMAC-SHA256(NK, r || u32(len ad) || ad || pt). out: 40 + pt_len. */
gz_sc_err_t sc_seal(const sc_keypair_t *kp, const uint8_t *pt, size_t pt_len, const uint8_t *ad, size_t ad_len,
                    uint8_t *out);
/* unseal(): 0 and the plaintext (in_len - 40 bytes) or -1. */
int sc_unseal(const sc_keypair_t *kp, const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len,
              uint8_t *pt);
/* The key commitment (4.6): HMAC-SHA256(derive(pk, label, ctx), ad). */
gz_sc_err_t sc_commitment(const uint8_t pk[32], const char *label, const uint8_t *ctx, size_t ctx_len,
                          const uint8_t *ad, size_t ad_len, uint8_t out[32]);
/* 1 if the commitment over ad under pk equals stored (constant time). */
int sc_commitment_ok(const uint8_t pk[32], const char *label, const uint8_t *ctx, size_t ctx_len,
                     const uint8_t *ad, size_t ad_len, const uint8_t stored[32]);

/* For the constant-time test: tells valgrind a value is public. No-op
 * outside that test build. */
#ifdef GZ_SC_CTIME
#include <valgrind/memcheck.h>
#define SC_DECLASSIFY(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define SC_DECLASSIFY(p, n) ((void)(p), (void)(n))
#endif

#endif
