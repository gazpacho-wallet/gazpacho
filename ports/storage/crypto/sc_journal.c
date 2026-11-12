/* The journal's seal and open interface (spec 5.3, 5.4, 5.5), the mark file
 * (10.2), the guard file (10.1) and the start rule (6.3). The journal itself
 * (journal.md) owns the file, the scan and the torn-tail search; it calls
 * gz_sc_header_* once and gz_sc_frame_seal / gz_sc_frame_open per entry. */
#include "sc_internal.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#define JH_MAGIC "GZJOURNE"
#define MK_MAGIC "GZMARKS1"
#define GD_MAGIC "GZGUARDE"

/* ---- the journal header (5.3) --------------------------------------------- */
gz_sc_err_t gz_sc_header_seal(const gz_sc_vault_t *v, const uint8_t file_id[16], uint8_t out[GZ_SC_JHEADER_LEN])
{
    uint8_t h[GZ_SC_JHEADER_LEN], ctx[48];
    memcpy(h, JH_MAGIC, 8);
    h[8] = 1;
    memcpy(h + 9, v->chain, 32);
    memcpy(h + 41, v->vault_id, 16);
    memcpy(h + 57, file_id, 16);
    memcpy(ctx, v->chain, 32);
    memcpy(ctx + 32, file_id, 16);
    sc_keypair_t kr, kj;
    sodium_mprotect_readonly(v->seed);
    gz_sc_err_t e = sc_keys(v->seed, 64, "journal recovery", ctx, sizeof ctx, &kr);
    sodium_mprotect_noaccess(v->seed);
    if (e != GZ_SC_OK)
        return e;
    sodium_mprotect_readonly(v->msk);
    e = sc_seal(&kr, v->msk, 32, h, 73, h + 73);
    if (e == GZ_SC_OK)
        e = sc_keys(v->msk, 32, "journal", ctx, sizeof ctx, &kj);
    sodium_mprotect_noaccess(v->msk);
    sc_keys_free(&kr);
    if (e != GZ_SC_OK)
        return e;
    e = sc_seal(&kj, NULL, 0, h, 145, h + 145);
    sc_keys_free(&kj);
    if (e == GZ_SC_OK)
        memcpy(out, h, sizeof h);
    return e;
}

gz_sc_err_t gz_sc_header_clear(const uint8_t *hdr, size_t len, const uint8_t chain[32], uint8_t vault_id[16],
                               uint8_t file_id[16])
{
    if (len < GZ_SC_JHEADER_LEN || memcmp(hdr, JH_MAGIC, 8) != 0 || hdr[8] != 1)
        return GZ_SC_NOT_THIS_FORMAT;
    if (memcmp(hdr + 9, chain, 32) != 0)
        return GZ_SC_OTHER_NETWORK;
    if (vault_id)
        memcpy(vault_id, hdr + 41, 16);
    if (file_id)
        memcpy(file_id, hdr + 57, 16);
    return GZ_SC_OK;
}

static gz_sc_err_t tag_ok(const uint8_t *hdr, const uint8_t *msk, gz_sc_framekey_t **kj_out)
{
    gz_sc_framekey_t *kj;
    gz_sc_err_t e = gz_sc_framekey_derive(msk, 32, "journal", hdr + 9, hdr + 57, &kj);
    if (e != GZ_SC_OK)
        return e;
    uint8_t empty[1];
    if (sc_unseal(&kj->kp, hdr + 145, 40, hdr, 145, empty) != 0) {
        gz_sc_framekey_free(kj);
        return GZ_SC_NOT_THIS_WALLET;
    }
    if (kj_out)
        *kj_out = kj;
    else
        gz_sc_framekey_free(kj);
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_header_open(const uint8_t hdr[GZ_SC_JHEADER_LEN], const gz_sc_vault_t *v,
                              gz_sc_framekey_t **kj)
{
    *kj = NULL;
    gz_sc_err_t e = gz_sc_header_clear(hdr, GZ_SC_JHEADER_LEN, v->chain, NULL, NULL);
    if (e != GZ_SC_OK)
        return e;
    if (memcmp(hdr + 41, v->vault_id, 16) != 0)
        return GZ_SC_NOT_THIS_WALLET;
    sodium_mprotect_readonly(v->msk);
    e = tag_ok(hdr, v->msk, kj);
    sodium_mprotect_noaccess(v->msk);
    return e;
}

gz_sc_err_t gz_sc_header_recover(const uint8_t hdr[GZ_SC_JHEADER_LEN], const uint8_t chain[32],
                                 const uint8_t seed[64], uint8_t msk[32])
{
    gz_sc_err_t e = gz_sc_header_clear(hdr, GZ_SC_JHEADER_LEN, chain, NULL, NULL);
    if (e != GZ_SC_OK)
        return e;
    uint8_t ctx[48];
    memcpy(ctx, chain, 32);
    memcpy(ctx + 32, hdr + 57, 16);
    sc_keypair_t kr;
    if ((e = sc_keys(seed, 64, "journal recovery", ctx, sizeof ctx, &kr)) != GZ_SC_OK)
        return e;
    int rc = sc_unseal(&kr, hdr + 73, 72, hdr, 73, msk);
    sc_keys_free(&kr);
    if (rc != 0)
        return GZ_SC_NOT_THIS_WALLET;
    e = tag_ok(hdr, msk, NULL);
    if (e != GZ_SC_OK)
        sodium_memzero(msk, 32);
    return e;
}

/* ---- entries (5.4) ----------------------------------------------------------- */
static void frame_ad(const gz_sc_framekey_t *k, uint64_t offset, const uint8_t head[21], uint8_t ad[45])
{
    memcpy(ad, k->file_id, 16);
    sc_put64(ad + 16, offset);
    memcpy(ad + 24, head, 21);
}

gz_sc_err_t gz_sc_frame_seal(const gz_sc_framekey_t *k, uint64_t offset, uint8_t kind, uint64_t incarnation,
                             uint64_t sequence, const uint8_t *payload, size_t payload_len, uint8_t *out,
                             size_t out_cap, size_t *out_len)
{
    if (kind < 1 || kind > 3)
        return GZ_SC_ARG;
    if ((kind == 1 || kind == 3) && payload_len != 8)
        return GZ_SC_ARG;
    if (kind == 2 && payload_len < 4)
        return GZ_SC_ARG;
    if (payload_len > GZ_SC_FRAME_LEN_MAX - 57)
        return GZ_SC_ARG;
    if (kind == 3 && sc_get64(payload) != offset)
        return GZ_SC_ARG; /* a sync mark names its own offset (journal.md 3.3) */
    if (out_cap < GZ_SC_FRAME_OVERHEAD + payload_len)
        return GZ_SC_BUFFER;
    uint8_t ad[45], head[21];
    sc_put32(head, (uint32_t)(57 + payload_len));
    head[4] = kind;
    sc_put64(head + 5, incarnation);
    sc_put64(head + 13, sequence);
    frame_ad(k, offset, head, ad);
    gz_sc_err_t e = sc_seal(&k->kp, payload, payload_len, ad, sizeof ad, out + 21);
    if (e != GZ_SC_OK)
        return e; /* sc_seal writes nothing before its random draw succeeds */
    memcpy(out, head, sizeof head);
    *out_len = GZ_SC_FRAME_OVERHEAD + payload_len;
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_frame_open(const gz_sc_framekey_t *k, const uint8_t *data, size_t avail, uint64_t offset,
                             gz_sc_frame_t *f, uint8_t *payload, size_t payload_cap)
{
    if (avail < 4)
        return GZ_SC_INVALID;
    uint32_t ln = sc_get32(data);
    if (ln < GZ_SC_FRAME_LEN_MIN || ln > GZ_SC_FRAME_LEN_MAX || (size_t)ln > avail - 4)
        return GZ_SC_INVALID;
    uint8_t kind = data[4];
    if (kind < 1 || kind > 3 || ((kind == 1 || kind == 3) && ln != 65))
        return GZ_SC_INVALID;
    size_t plen = (size_t)ln - 57;
    uint8_t *pt = payload;
    uint8_t *own = NULL;
    if (!pt || payload_cap < plen) {
        if (payload)
            return GZ_SC_BUFFER;
        own = malloc(plen);
        if (!own)
            return GZ_SC_NOMEM;
        pt = own;
    }
    uint8_t ad[45];
    frame_ad(k, offset, data, ad);
    gz_sc_err_t e = GZ_SC_OK;
    if (sc_unseal(&k->kp, data + 21, (size_t)ln - 17, ad, sizeof ad, pt) != 0)
        e = GZ_SC_INVALID;
    else if (kind == 3 && (SC_DECLASSIFY(pt, 8), sc_get64(pt) != offset))
        e = GZ_SC_INVALID;
    if (e == GZ_SC_OK && f) {
        f->kind = kind;
        f->incarnation = sc_get64(data + 5);
        f->sequence = sc_get64(data + 13);
        f->entry_len = 4 + (size_t)ln;
        f->payload_len = plen;
    }
    if (own) {
        sodium_memzero(own, plen);
        free(own);
    } else if (e != GZ_SC_OK) {
        sodium_memzero(pt, plen);
    }
    return e;
}

/* ---- the mark file (10.2) ---------------------------------------------------- */
gz_sc_err_t gz_sc_mark_key(const gz_sc_vault_t *v, const uint8_t file_id[16], gz_sc_framekey_t **kh)
{
    sodium_mprotect_readonly(v->msk);
    gz_sc_err_t e = gz_sc_framekey_derive(v->msk, 32, "high water", v->chain, file_id, kh);
    sodium_mprotect_noaccess(v->msk);
    return e;
}

gz_sc_err_t gz_sc_mark_entry(const gz_sc_framekey_t *kh, const uint8_t header[GZ_SC_MARK_HEADER_LEN],
                             uint64_t at, uint64_t incarnation, uint64_t mark_offset,
                             uint8_t out[GZ_SC_MARK_ENTRY_LEN])
{
    uint8_t pt[16], ad[GZ_SC_MARK_HEADER_LEN + 8];
    sc_put64(pt, incarnation);
    sc_put64(pt + 8, mark_offset);
    memcpy(ad, header, GZ_SC_MARK_HEADER_LEN);
    sc_put64(ad + GZ_SC_MARK_HEADER_LEN, at);
    return sc_seal(&kh->kp, pt, sizeof pt, ad, sizeof ad, out);
}

gz_sc_err_t gz_sc_mark_new(const gz_sc_framekey_t *kh, const uint8_t chain[32],
                           uint8_t out[GZ_SC_MARK_HEADER_LEN + GZ_SC_MARK_ENTRY_LEN])
{
    memcpy(out, MK_MAGIC, 8);
    out[8] = 1;
    memcpy(out + 9, chain, 32);
    memcpy(out + 41, kh->file_id, 16);
    return gz_sc_mark_entry(kh, out, GZ_SC_MARK_HEADER_LEN, 0, 0, out + GZ_SC_MARK_HEADER_LEN);
}

gz_sc_mark_state_t gz_sc_mark_read(const gz_sc_framekey_t *kh, const uint8_t *data, size_t len,
                                   const uint8_t chain[32], const uint8_t file_id[16], uint64_t *incarnation,
                                   uint64_t *mark_offset, size_t *valid_end)
{
    if (len < GZ_SC_MARK_HEADER_LEN || memcmp(data, MK_MAGIC, 8) != 0 || data[8] != 1 ||
        memcmp(data + 9, chain, 32) != 0)
        return GZ_SC_MARK_NOT_A_MARK_FILE;
    if (memcmp(data + 41, file_id, 16) != 0)
        return GZ_SC_MARK_OTHER_JOURNAL;
    uint8_t ad[GZ_SC_MARK_HEADER_LEN + 8], pt[16];
    memcpy(ad, data, GZ_SC_MARK_HEADER_LEN);
    size_t pos = GZ_SC_MARK_HEADER_LEN, end = 0;
    int have = 0, bad = 0;
    uint64_t inc = 0, off = 0;
    while (len - pos >= GZ_SC_MARK_ENTRY_LEN) {
        sc_put64(ad + GZ_SC_MARK_HEADER_LEN, (uint64_t)pos);
        if (sc_unseal(&kh->kp, data + pos, GZ_SC_MARK_ENTRY_LEN, ad, sizeof ad, pt) != 0) {
            bad = 1;
        } else if (bad) {
            return GZ_SC_MARK_DAMAGED; /* an invalid entry before a valid one */
        } else {
            SC_DECLASSIFY(pt, sizeof pt); /* a mark point is public once opened */
            uint64_t i = sc_get64(pt), o = sc_get64(pt + 8);
            if (have && (i < inc || (i == inc && o < off)))
                return GZ_SC_MARK_DAMAGED; /* going backwards */
            inc = i;
            off = o;
            have = 1;
            end = pos + GZ_SC_MARK_ENTRY_LEN;
        }
        pos += GZ_SC_MARK_ENTRY_LEN;
    }
    if (!have)
        return GZ_SC_MARK_NO_ENTRY;
    if (incarnation)
        *incarnation = inc;
    if (mark_offset)
        *mark_offset = off;
    if (valid_end)
        *valid_end = end;
    return GZ_SC_MARK_OK;
}

/* ---- the guard file (10.1) ----------------------------------------------------- */
void gz_sc_guard_clear(gz_sc_guard_t *g)
{
    free(g->epochs);
    memset(g, 0, sizeof *g);
}

size_t gz_sc_guard_contents_len(const gz_sc_guard_t *g)
{
    return 18 + 8 * (size_t)g->n_epochs;
}

gz_sc_err_t gz_sc_guard_contents(const gz_sc_guard_t *g, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = gz_sc_guard_contents_len(g);
    if (cap < n)
        return GZ_SC_BUFFER;
    if (g->n_epochs && !g->epochs)
        return GZ_SC_ARG;
    sc_put64(out, g->counter);
    out[8] = (uint8_t)(g->n_epochs >> 8);
    out[9] = (uint8_t)g->n_epochs;
    for (size_t i = 0; i < g->n_epochs; i++) {
        sc_put32(out + 10 + 8 * i, g->epochs[i].epoch);
        sc_put32(out + 14 + 8 * i, g->epochs[i].highest_index);
    }
    sc_put64(out + 10 + 8 * (size_t)g->n_epochs, g->rounds_started);
    *out_len = n;
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_guard_parse(const uint8_t *c, size_t len, gz_sc_guard_t *g)
{
    memset(g, 0, sizeof *g);
    if (len < 18)
        return GZ_SC_DAMAGED;
    uint16_t n = (uint16_t)((c[8] << 8) | c[9]);
    if (len != 18 + 8 * (size_t)n)
        return GZ_SC_DAMAGED;
    gz_sc_epoch_t *ep = NULL;
    if (n) {
        ep = malloc(sizeof *ep * n);
        if (!ep)
            return GZ_SC_NOMEM;
        for (size_t i = 0; i < n; i++) {
            ep[i].epoch = sc_get32(c + 10 + 8 * i);
            ep[i].highest_index = sc_get32(c + 14 + 8 * i);
        }
    }
    g->counter = sc_get64(c);
    g->n_epochs = n;
    g->epochs = ep;
    g->rounds_started = sc_get64(c + 10 + 8 * (size_t)n);
    return GZ_SC_OK;
}

static gz_sc_err_t guard_key(const gz_sc_vault_t *v, sc_keypair_t *kg)
{
    sodium_mprotect_readonly(v->seed);
    gz_sc_err_t e = sc_keys(v->seed, 64, "guard", v->chain, 32, kg);
    sodium_mprotect_noaccess(v->seed);
    return e;
}

gz_sc_err_t gz_sc_guard_seal(const gz_sc_vault_t *v, const gz_sc_guard_t *g, uint8_t *out, size_t cap,
                             size_t *out_len)
{
    size_t n = gz_sc_guard_contents_len(g);
    if (cap < GZ_SC_GUARD_HEAD + 40 + n)
        return GZ_SC_BUFFER;
    uint8_t *c = malloc(n);
    if (!c)
        return GZ_SC_NOMEM;
    size_t cl;
    gz_sc_err_t e = gz_sc_guard_contents(g, c, n, &cl);
    sc_keypair_t kg = {NULL};
    if (e == GZ_SC_OK)
        e = guard_key(v, &kg);
    if (e == GZ_SC_OK) {
        memcpy(out, GD_MAGIC, 8);
        out[8] = 1;
        memcpy(out + 9, v->chain, 32);
        e = sc_seal(&kg, c, cl, out, GZ_SC_GUARD_HEAD, out + GZ_SC_GUARD_HEAD);
    }
    sc_keys_free(&kg);
    free(c);
    if (e == GZ_SC_OK)
        *out_len = GZ_SC_GUARD_HEAD + 40 + n;
    return e;
}

gz_sc_err_t gz_sc_guard_open(const gz_sc_vault_t *v, const uint8_t *data, size_t len, gz_sc_guard_t *g)
{
    memset(g, 0, sizeof *g);
    if (len < GZ_SC_GUARD_HEAD + 40 || memcmp(data, GD_MAGIC, 8) != 0 || data[8] != 1)
        return GZ_SC_NOT_THIS_FORMAT;
    if (memcmp(data + 9, v->chain, 32) != 0)
        return GZ_SC_OTHER_NETWORK;
    size_t n = len - GZ_SC_GUARD_HEAD - 40;
    uint8_t *c = malloc(n ? n : 1);
    if (!c)
        return GZ_SC_NOMEM;
    sc_keypair_t kg;
    gz_sc_err_t e = guard_key(v, &kg);
    if (e == GZ_SC_OK) {
        if (sc_unseal(&kg, data + GZ_SC_GUARD_HEAD, len - GZ_SC_GUARD_HEAD, data, GZ_SC_GUARD_HEAD, c) != 0)
            e = GZ_SC_DAMAGED;
        else
            e = (SC_DECLASSIFY(c, n), gz_sc_guard_parse(c, n, g));
        sc_keys_free(&kg);
    }
    free(c);
    return e;
}

/* ---- the start rule (6.3) ---------------------------------------------------- */
gz_sc_start_t gz_sc_start_rule(gz_sc_mark_state_t mark, uint64_t mark_inc, uint64_t mark_off,
                               gz_sc_err_t guard_state, uint64_t guard_counter,
                               const gz_sc_journal_view_t *j)
{
    /* Step 1: a guard or mark file absent, or a mark file with no valid entry
     * or a damaged one, while a key file exists: possibly old (review F6). */
    if (guard_state != GZ_SC_OK)
        return GZ_SC_START_POSSIBLY_OLD;
    if (mark == GZ_SC_MARK_NOT_A_MARK_FILE || mark == GZ_SC_MARK_NO_ENTRY || mark == GZ_SC_MARK_DAMAGED)
        return GZ_SC_START_POSSIBLY_OLD;
    /* Step 2: behind. */
    if (mark == GZ_SC_MARK_OTHER_JOURNAL)
        return GZ_SC_START_BEHIND;
    if (mark_inc > j->highest_incarnation)
        return GZ_SC_START_BEHIND;
    if (!(mark_inc == 0 && mark_off == 0) && !j->has_sync_mark(j->ctx, mark_inc, mark_off))
        return GZ_SC_START_BEHIND;
    if (guard_counter > j->newest_guard_counter)
        return GZ_SC_START_BEHIND;
    return GZ_SC_START_OK;
}
