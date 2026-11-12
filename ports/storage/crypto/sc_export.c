/* Exports .gzb (spec 11): profile 1 (the person's: passphrase or words) and
 * profile 2 (the host's copy: words only). Chunked as in STREAM: each chunk
 * is u32 n || seal(EK, part, ad = prefix || u64 index || u8 final). */
#include "sc_internal.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#define EX_MAGIC "GZBACKUP"
#define CHUNK_MIN 40u
#define CHUNK_MAX (GZ_SC_EXPORT_PART_MAX + 40u)

/* ---- the body ---------------------------------------------------------------- */
size_t gz_sc_export_body_len(size_t guard_len, int with_words, size_t entries_len)
{
    return 1 + 8 + 1 + (with_words ? 32 : 0) + 4 + guard_len + entries_len;
}

gz_sc_err_t gz_sc_export_body_begin(uint64_t created_ms, const uint8_t *entropy, const uint8_t *guard,
                                    size_t guard_len, uint8_t *out, size_t cap, size_t *used)
{
    size_t n = gz_sc_export_body_len(guard_len, entropy != NULL, 0);
    if (guard_len > UINT32_MAX)
        return GZ_SC_ARG;
    if (cap < n)
        return GZ_SC_BUFFER;
    size_t p = 0;
    out[p++] = 1;
    sc_put64(out + p, created_ms);
    p += 8;
    out[p++] = entropy ? 1 : 0;
    if (entropy) {
        memcpy(out + p, entropy, 32);
        p += 32;
    }
    sc_put32(out + p, (uint32_t)guard_len);
    p += 4;
    if (guard_len)
        memcpy(out + p, guard, guard_len);
    *used = n;
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_export_body_entry(uint8_t kind, uint64_t inc, uint64_t seq, const uint8_t *payload, size_t len,
                                    uint8_t *out, size_t cap, size_t *used)
{
    if (len > UINT32_MAX)
        return GZ_SC_ARG;
    if (*used > cap || cap - *used < 21 + len)
        return GZ_SC_BUFFER;
    uint8_t *o = out + *used;
    o[0] = kind;
    sc_put64(o + 1, inc);
    sc_put64(o + 9, seq);
    sc_put32(o + 17, (uint32_t)len);
    if (len)
        memcpy(o + 21, payload, len);
    *used += 21 + len;
    return GZ_SC_OK;
}

int gz_sc_export_body_next(const gz_sc_export_body_t *b, size_t *pos, uint8_t *kind, uint64_t *inc, uint64_t *seq,
                           const uint8_t **payload, size_t *len)
{
    if (*pos == b->entries_len)
        return 0;
    if (*pos > b->entries_len || b->entries_len - *pos < 21)
        return -1;
    const uint8_t *e = b->entries + *pos;
    uint32_t n = sc_get32(e + 17);
    if ((size_t)n > b->entries_len - *pos - 21)
        return -1;
    *kind = e[0];
    *inc = sc_get64(e + 1);
    *seq = sc_get64(e + 9);
    *payload = e + 21;
    *len = n;
    *pos += 21 + (size_t)n;
    return 1;
}

gz_sc_err_t gz_sc_export_body_parse(const uint8_t *b, size_t len, uint8_t profile, gz_sc_export_body_t *out)
{
    memset(out, 0, sizeof *out);
    if (len < 14 || b[0] != 1)
        return GZ_SC_DAMAGED;
    uint8_t flags = b[9];
    /* Bit 0 only; never in profile 2 (11). Unknown bits are refused. */
    if ((flags & ~1u) || (profile == 2 && (flags & 1)))
        return GZ_SC_DAMAGED;
    size_t p = 10;
    if (flags & 1) {
        if (len - p < 32)
            return GZ_SC_DAMAGED;
        out->entropy = b + p;
        p += 32;
    }
    if (len - p < 4)
        return GZ_SC_DAMAGED;
    uint32_t gl = sc_get32(b + p);
    p += 4;
    if ((size_t)gl > len - p)
        return GZ_SC_DAMAGED;
    out->created_ms = sc_get64(b + 1);
    out->flags = flags;
    out->guard = b + p;
    out->guard_len = gl;
    p += gl;
    out->entries = b + p;
    out->entries_len = len - p;
    /* Every entry must fit exactly. */
    size_t pos = 0;
    uint8_t k;
    uint64_t i, s;
    const uint8_t *pl;
    size_t pn;
    int r;
    while ((r = gz_sc_export_body_next(out, &pos, &k, &i, &s, &pl, &pn)) == 1)
        ;
    if (r < 0) {
        memset(out, 0, sizeof *out);
        return GZ_SC_DAMAGED;
    }
    return GZ_SC_OK;
}

/* ---- the file ---------------------------------------------------------------- */
static size_t prefix_len(uint8_t profile)
{
    return profile == 1 ? GZ_SC_EXPORT_SLOT_END : GZ_SC_EXPORT_HEAD;
}

size_t gz_sc_export_size(uint8_t profile, size_t body_len, size_t part)
{
    if (part == 0 || part > GZ_SC_EXPORT_PART_MAX || (profile != 1 && profile != 2))
        return 0;
    size_t chunks = body_len == 0 ? 1 : (body_len + part - 1) / part;
    return prefix_len(profile) + chunks * (4 + 40) + body_len;
}

static gz_sc_err_t backup_key(const uint8_t *seed, const uint8_t chain[32], uint8_t bk[32])
{
    return sc_derive(seed, 64, "backup", chain, 32, bk);
}

static gz_sc_err_t seal_chunks(const uint8_t *bk, const uint8_t *prefix, size_t plen, const uint8_t *body,
                               size_t body_len, size_t part, uint8_t *out, size_t *used)
{
    uint8_t ctx[48];
    memcpy(ctx, prefix + 10, 32);      /* chain */
    memcpy(ctx + 32, prefix + 42, 16); /* export_id */
    sc_keypair_t ek;
    gz_sc_err_t e = sc_keys(bk, 32, "export", ctx, sizeof ctx, &ek);
    if (e != GZ_SC_OK)
        return e;
    uint8_t *ad = malloc(plen + 9);
    if (!ad) {
        sc_keys_free(&ek);
        return GZ_SC_NOMEM;
    }
    memcpy(ad, prefix, plen);
    size_t chunks = body_len == 0 ? 1 : (body_len + part - 1) / part;
    for (size_t i = 0; i < chunks && e == GZ_SC_OK; i++) {
        size_t off = i * part, n = body_len - off < part ? body_len - off : part;
        sc_put64(ad + plen, (uint64_t)i);
        ad[plen + 8] = i + 1 == chunks ? 1 : 0;
        sc_put32(out + *used, (uint32_t)(n + 40));
        e = sc_seal(&ek, body ? body + off : NULL, n, ad, plen + 9, out + *used + 4);
        *used += 4 + 40 + n;
    }
    free(ad);
    sc_keys_free(&ek);
    return e;
}

gz_sc_err_t gz_sc_export_build(const gz_sc_vault_t *v, uint8_t profile, const uint8_t export_id[16],
                               const gz_sc_kdf_params_t *kdf, const uint8_t *salt, const uint8_t *pkx,
                               const uint8_t *body, size_t body_len, size_t part, uint8_t *out, size_t cap,
                               size_t *out_len)
{
    size_t need = gz_sc_export_size(profile, body_len, part);
    if (need == 0)
        return GZ_SC_ARG;
    if (profile == 1 && (!kdf || !salt || !pkx))
        return GZ_SC_ARG;
    if (profile == 2 && (kdf || salt || pkx))
        return GZ_SC_ARG;
    if (cap < need)
        return GZ_SC_BUFFER;
    gz_sc_export_body_t check;
    gz_sc_err_t e = gz_sc_export_body_parse(body, body_len, profile, &check);
    if (e != GZ_SC_OK)
        return GZ_SC_ARG; /* never seal a body the reader would refuse (profile 2: no words) */
    memcpy(out, EX_MAGIC, 8);
    out[8] = 1;
    out[9] = profile;
    memcpy(out + 10, v->chain, 32);
    memcpy(out + 42, export_id, 16);
    uint8_t *bk = sodium_malloc(32);
    if (!bk)
        return GZ_SC_NOMEM;
    sodium_mprotect_readonly(v->seed);
    e = backup_key(v->seed, v->chain, bk);
    sodium_mprotect_noaccess(v->seed);
    if (e == GZ_SC_OK && profile == 1) {
        if ((e = gz_sc_params_check(kdf)) == GZ_SC_OK) {
            uint8_t *s = out + GZ_SC_EXPORT_HEAD;
            s[0] = kdf->kdf;
            sc_put32(s + 1, kdf->t);
            sc_put32(s + 5, kdf->m_kib);
            s[9] = kdf->p;
            memcpy(s + 10, salt, 16);
            uint8_t ctx[48];
            memcpy(ctx, v->chain, 32);
            memcpy(ctx + 32, export_id, 16);
            e = sc_commitment(pkx, "backup commitment", ctx, sizeof ctx, out, 84, out + 84);
            sc_keypair_t kx;
            if (e == GZ_SC_OK && (e = sc_keys(pkx, 32, "backup wrap", ctx, sizeof ctx, &kx)) == GZ_SC_OK) {
                e = sc_seal(&kx, bk, 32, out, 84, out + 116);
                sc_keys_free(&kx);
            }
        }
    }
    size_t used = prefix_len(profile);
    if (e == GZ_SC_OK)
        e = seal_chunks(bk, out, used, body, body_len, part, out, &used);
    sodium_free(bk);
    if (e == GZ_SC_OK)
        *out_len = used;
    return e;
}

gz_sc_err_t gz_sc_export_parse(const uint8_t *data, size_t len, const uint8_t chain[32], gz_sc_export_info_t *info)
{
    if (len < GZ_SC_EXPORT_HEAD || memcmp(data, EX_MAGIC, 8) != 0 || data[8] != 1)
        return GZ_SC_NOT_THIS_FORMAT;
    if (memcmp(data + 10, chain, 32) != 0)
        return GZ_SC_OTHER_NETWORK;
    gz_sc_export_info_t in;
    memset(&in, 0, sizeof in);
    in.profile = data[9];
    memcpy(in.chain, data + 10, 32);
    memcpy(in.export_id, data + 42, 16);
    if (in.profile == 1) {
        if (len < GZ_SC_EXPORT_SLOT_END)
            return GZ_SC_TRUNCATED;
        const uint8_t *s = data + GZ_SC_EXPORT_HEAD;
        in.kdf.kdf = s[0];
        in.kdf.t = sc_get32(s + 1);
        in.kdf.m_kib = sc_get32(s + 5);
        in.kdf.p = s[9];
        memcpy(in.salt, s + 10, 16);
        gz_sc_err_t e = gz_sc_params_check(&in.kdf);
        if (e != GZ_SC_OK)
            return e; /* before any derivation (F9) */
    } else if (in.profile != 2) {
        return GZ_SC_NOT_THIS_FORMAT;
    }
    if (info)
        *info = in;
    return GZ_SC_OK;
}

static gz_sc_err_t open_chunks(const uint8_t *bk, const uint8_t *data, size_t len, size_t plen, uint8_t **body,
                               size_t *body_len)
{
    uint8_t ctx[48];
    memcpy(ctx, data + 10, 32);
    memcpy(ctx + 32, data + 42, 16);
    sc_keypair_t ek;
    gz_sc_err_t e = sc_keys(bk, 32, "export", ctx, sizeof ctx, &ek);
    if (e != GZ_SC_OK)
        return e;
    /* The body is never larger than the file. */
    uint8_t *out = malloc(len - plen + 1), *ad = malloc(plen + 9);
    if (!out || !ad) {
        free(out);
        free(ad);
        sc_keys_free(&ek);
        return GZ_SC_NOMEM;
    }
    memcpy(ad, data, plen);
    size_t pos = plen, got = 0;
    uint64_t i = 0;
    e = GZ_SC_TRUNCATED;
    for (;;) {
        if (len - pos < 4)
            break; /* truncated */
        uint32_t n = sc_get32(data + pos);
        if (n < CHUNK_MIN || n > CHUNK_MAX || (size_t)n > len - pos - 4)
            break; /* truncated */
        const uint8_t *sc = data + pos + 4;
        sc_put64(ad + plen, i);
        ad[plen + 8] = 1;
        if (sc_unseal(&ek, sc, n, ad, plen + 9, out + got) == 0) {
            got += n - 40;
            e = pos + 4 + n == len ? GZ_SC_OK : GZ_SC_TRAILING_DATA;
            break;
        }
        ad[plen + 8] = 0;
        if (sc_unseal(&ek, sc, n, ad, plen + 9, out + got) != 0) {
            e = GZ_SC_DAMAGED;
            break;
        }
        if (n == 40) {
            e = GZ_SC_EMPTY_CHUNK; /* F17 */
            break;
        }
        got += n - 40;
        pos += 4 + n;
        i++;
    }
    free(ad);
    sc_keys_free(&ek);
    if (e != GZ_SC_OK) {
        sodium_memzero(out, len - plen + 1);
        free(out);
        return e;
    }
    *body = out;
    *body_len = got;
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_export_open(const uint8_t *data, size_t len, const uint8_t chain[32], const uint8_t *pkx,
                              const uint8_t *seed, uint8_t **body, size_t *body_len)
{
    *body = NULL;
    *body_len = 0;
    gz_sc_export_info_t info;
    gz_sc_err_t e = gz_sc_export_parse(data, len, chain, &info);
    if (e != GZ_SC_OK)
        return e;
    if ((pkx == NULL) == (seed == NULL))
        return GZ_SC_ARG;
    if (info.profile == 2 && pkx)
        return GZ_SC_NEEDS_WORDS;
    uint8_t *bk = sodium_malloc(32);
    if (!bk)
        return GZ_SC_NOMEM;
    if (pkx) {
        uint8_t ctx[48];
        memcpy(ctx, chain, 32);
        memcpy(ctx + 32, info.export_id, 16);
        if (!sc_commitment_ok(pkx, "backup commitment", ctx, sizeof ctx, data, 84, data + 84)) {
            e = GZ_SC_WRONG_PASSPHRASE;
        } else {
            sc_keypair_t kx;
            if ((e = sc_keys(pkx, 32, "backup wrap", ctx, sizeof ctx, &kx)) == GZ_SC_OK) {
                if (sc_unseal(&kx, data + 116, 72, data, 84, bk) != 0)
                    e = GZ_SC_WRONG_PASSPHRASE;
                sc_keys_free(&kx);
            }
        }
    } else {
        e = backup_key(seed, chain, bk);
    }
    if (e == GZ_SC_OK)
        e = open_chunks(bk, data, len, prefix_len(info.profile), body, body_len);
    sodium_free(bk);
    if (e == GZ_SC_OK) {
        gz_sc_export_body_t b;
        SC_DECLASSIFY(*body, *body_len); /* the body's layout is parsed once opened */
        if (gz_sc_export_body_parse(*body, *body_len, info.profile, &b) != GZ_SC_OK) {
            sodium_memzero(*body, *body_len);
            free(*body);
            *body = NULL;
            *body_len = 0;
            e = GZ_SC_DAMAGED;
        }
    }
    return e;
}
