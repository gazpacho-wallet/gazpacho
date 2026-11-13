/* A libFuzzer target for the scan and the open (written by review B of PR
 * 29), against an
 * independent reader written from spec/journal.md (draft 2's clear format)
 * here, not taken from journal.c. The input either is the file (raw mode) or
 * describes one, entry by entry, with correct checks unless told otherwise,
 * so the fuzzer reaches deep states: incarnation, batch and mark entries,
 * wrong offsets, flipped bits, garbage, cut lengths, unknown record types. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "journal.h"
#include "memfs.h"
#include "superscalar/sha256.h"

#define CAP 65536
static uint8_t F[CAP];

static uint32_t g32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static uint64_t g64(const uint8_t *p) { return (uint64_t)g32(p) << 32 | g32(p + 4); }
static void p32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static void p64(uint8_t *p, uint64_t v) { p32(p, (uint32_t)(v >> 32)); p32(p + 4, (uint32_t)v); }
static int chk(const uint8_t *d, size_t n, const uint8_t *c) { uint8_t h[32]; sha256(d, n, h); return memcmp(h, c, 8) == 0; }
static void seal(uint8_t *d, size_t n) { uint8_t h[32]; sha256(d, n, h); memcpy(d + n, h, 8); }

/* --- the independent reader ------------------------------------------------ */
typedef struct { int status; uint64_t V, highest, nb; } ind_t; /* status: gz_journal_status_t values */

static int known(uint32_t t)
{
    static const uint32_t k[] = {0x00040002, 0x00040004, 0x00040006, 0x0004000a, 0x00010002, 0x00010004,
        0x00010006, 0x00010008, 0x0001000a, 0x0001000c, 0x0001000e, 0x00010010, 0x00010012, 0x00010014,
        0x00010016, 0x00020002, 0x00020004, 0x00020006, 0x00020008, 0x0002000a, 0x0002000c, 0x0002000e,
        0x00030002, 0x00030004, 0x00030006};
    if ((t >> 16) == 0x7e57) return 1;
    for (size_t i = 0; i < sizeof k / sizeof *k; i++) if (k[i] == t) return 1;
    return 0;
}

/* Valid entry at p? Returns its size or 0. kind/inc/seq/val out. */
static uint64_t valid_at(const uint8_t *d, uint64_t E, uint64_t p, int *kind, uint64_t *inc, uint64_t *seq, int *badtype)
{
    if (E - p < 4) return 0;
    uint64_t L = g32(d + p);
    if (L < 21 || L > 8388625) return 0;
    if (E - p < 4 + L + 8) return 0;
    int k = d[p + 4];
    if (k < 1 || k > 3) return 0;
    if (k != 2 && L != 25) return 0;
    if (!chk(d + p, 4 + L, d + p + 4 + L)) return 0;
    *kind = k; *inc = g64(d + p + 5); *seq = g64(d + p + 13);
    const uint8_t *pl = d + p + 21; uint64_t pn = L - 17;
    if (k == 3 && g64(pl) != p) return 0;
    if (k == 2) {
        if (pn < 4) return 0;
        uint64_t n = g32(pl), q = 4;
        *badtype = 0;
        for (uint64_t i = 0; i < n; i++) {
            if (pn - q < 8) return 0;
            uint32_t t = g32(pl + q); uint64_t rl = g32(pl + q + 4);
            q += 8;
            if (pn - q < rl) return 0;
            if (!(t & 1) && !known(t) && !*badtype) *badtype = 1;
            q += rl;
        }
        if (q != pn) return 0;
    }
    return 4 + L + 8;
}

static ind_t ind_scan(const uint8_t *d, uint64_t E, const uint8_t chain[32])
{
    ind_t r = {0, 0, 0, 0};
    static const uint8_t mg[8] = {'G', 'Z', 'J', 'O', 'U', 'R', 'N', 'L'};
    if (E < 48 || memcmp(d, mg, 8) || !chk(d, 40, d + 40)) { r.status = GZ_JOURNAL_ERR_HEADER; return r; }
    if (memcmp(d + 8, chain, 32)) { r.status = GZ_JOURNAL_ERR_NETWORK; return r; }
    uint64_t p = 48, inc = 0, seq = 0;
    int bad = 0;
    for (;;) {
        int k, bt = 0; uint64_t i, s;
        uint64_t sz = p < E ? valid_at(d, E, p, &k, &i, &s, &bt) : 0;
        if (!sz) break;
        if (p == 48 && k != 1) { r.status = GZ_JOURNAL_ERR_ORDER; return r; }
        if (k == 1) { if (i <= inc || s != 0) { r.status = GZ_JOURNAL_ERR_ORDER; return r; } inc = i; seq = 0; }
        else if (i != inc) { r.status = GZ_JOURNAL_ERR_ORDER; return r; }
        else if (k == 3) { if (s != 0) { r.status = GZ_JOURNAL_ERR_ORDER; return r; } }
        else { if (s != seq + 1) { r.status = GZ_JOURNAL_ERR_ORDER; return r; } seq = s; r.nb++; if (bt) bad = 1; }
        p += sz;
    }
    r.V = p; r.highest = inc;
    if (p < E)
        for (uint64_t m = p + 1; m + 37 <= E; m++) {
            int k, bt; uint64_t i, s;
            if (valid_at(d, E, m, &k, &i, &s, &bt) && k == 3) { r.status = GZ_JOURNAL_ERR_CORRUPT; return r; }
        }
    if (bad) r.status = GZ_JOURNAL_ERR_UNKNOWN_RECORD;
    return r;
}

/* --- building a file from the input ---------------------------------------- */
static size_t build(const uint8_t *in, size_t n)
{
    if (n == 0) return 0;
    if (in[0] & 1) { size_t l = n - 1 < CAP ? n - 1 : CAP; memcpy(F, in + 1, l); return l; } /* raw */
    size_t len = gz_journal_encode_header(F, gz_journal_chain_signet);
    uint64_t inc = 0, seq = 0;
    size_t i = 1;
    while (i < n && len + 600 < CAP) {
        uint8_t op = in[i++], a = i < n ? in[i++] : 0;
        switch (op % 8) {
        case 0: inc += 1 + (a & 3); seq = 0; len += gz_journal_encode_small(F + len, 1, inc, 7); break;
        case 1: case 2: { /* a batch: a records, types chosen by the next bytes */
            uint8_t *e = F + len, *pl = e + 21;
            uint32_t nr = a % 4; size_t q = 4;
            p32(pl, nr);
            for (uint32_t r = 0; r < nr; r++) {
                uint8_t tb = i < n ? in[i++] : 0;
                uint32_t t = tb == 0xff ? 0x00050002u : tb == 0xfe ? 0x00050003u : 0x7e570001u;
                uint32_t rl = tb % 40;
                p32(pl + q, t); p32(pl + q + 4, rl); q += 8;
                for (uint32_t z = 0; z < rl; z++) pl[q + z] = (uint8_t)(z * 7 + tb);
                q += rl;
            }
            p32(e, (uint32_t)(17 + q)); e[4] = 2;
            uint64_t s = (a & 0x80) ? seq + 2 : seq + 1; /* sometimes a gap */
            p64(e + 5, (a & 0x40) ? inc + 1 : inc); p64(e + 13, s); seq = s;
            seal(e, 21 + q);
            len += 21 + q + 8;
            break;
        }
        case 3: len += gz_journal_encode_small(F + len, 3, inc, (a & 0x10) ? len + 1 : len); break;
        case 4: { size_t k = a % 60; for (size_t z = 0; z < k && i < n; z++) F[len++] = in[i++]; break; } /* garbage */
        case 5: if (len > 48) F[48 + (size_t)(a * 977u) % (len - 48)] ^= (uint8_t)(1u << (a & 7)); break; /* flip */
        case 6: if (len > 49) len -= 1 + a % (len - 48 > 64 ? 64 : len - 49); break;  /* cut */
        case 7: { size_t k = 1 + a % 32; memset(F + len, 0, k); len += k; break; } /* zeros */
        }
    }
    return len;
}

typedef struct { uint64_t n; } cnt_t;
static void cb(void *ctx, uint64_t off, uint32_t size, gz_batch_id_t id, const uint8_t *p, size_t l)
{ (void)off; (void)size; (void)id; (void)p; (void)l; ((cnt_t *)ctx)->n++; }

int LLVMFuzzerTestOneInput(const uint8_t *in, size_t n)
{
    size_t len = build(in, n);
    ind_t o = ind_scan(F, len, gz_journal_chain_signet);
    gz_journal_scan_t sc;
    cnt_t c = {0};
    gz_journal_status_t st = gz_journal_scan(F, len, gz_journal_chain_signet, &sc, cb, &c);
    if ((int)st != o.status) { fprintf(stderr, "scan %s, independent %s\n", gz_journal_status_name(st), gz_journal_status_name(o.status)); abort(); }
    if (st == GZ_JOURNAL_OK) {
        if (sc.valid_end != o.V || sc.highest_incarnation != o.highest || sc.n_batches != o.nb || c.n != o.nb) abort();
        if ((sc.verdict == GZ_JOURNAL_TORN) != (o.V < len)) abort();
    }
    /* The open on a memfs, with a start counter from the input. */
    memfs_t fs;
    memfs_init(&fs);
    memfs_put(&fs, "/n/" GZ_JOURNAL_FILE, F, len);
    uint64_t counter = n > 2 ? (uint64_t)in[n - 1] << (in[n - 2] % 64) : 0;
    gz_journal_config_t cfg = {0};
    cfg.dir = "/n"; cfg.chain = gz_journal_chain_signet; cfg.os = &fs.os; cfg.pull = 1; cfg.start_counter = counter;
    gz_journal_t *j = NULL;
    gz_journal_open_info_t info;
    gz_journal_status_t os = gz_journal_open(&j, &cfg, &info);
    size_t now; const uint8_t *after = memfs_get(&fs, "/n/" GZ_JOURNAL_FILE, &now);
    uint64_t hi = o.highest > counter ? o.highest : counter;
    if (st == GZ_JOURNAL_OK && hi >= GZ_JOURNAL_INCARNATION_LIMIT - 1) {
        if (os != GZ_JOURNAL_ERR_INCARNATION || now != len || memcmp(after, F, len)) abort();
    } else if (len < 48) {
        if (os != GZ_JOURNAL_ERR_HEADER) abort();
    } else if (os != st) {
        abort();
    } else if (os == GZ_JOURNAL_OK) {
        if (info.incarnation != hi + 1 || now != o.V + 74 || memcmp(after, F, o.V)) abort();
        gz_storage_reader_t rd = gz_journal_reader(j);
        gz_stored_batch_t sb; uint64_t k = 0;
        while (rd.next(rd.ctx, &sb)) k++;
        if (k != o.nb || gz_journal_failed(j)) abort();
        /* Save, flush, complete, close, reopen: everything is still there. */
        gz_record_t r = {0x7e570003u, {(const uint8_t *)"x", 1}};
        gz_action_t a = {.kind = GZ_ACTION_SAVE};
        a.u.save.batch.incarnation = info.incarnation; a.u.save.batch.sequence = 1;
        a.u.save.records = &r; a.u.save.n_records = 1;
        if (gz_journal_save(j, &a) != GZ_JOURNAL_OK) abort();
        gz_batch_id_t id;
        if (!gz_journal_complete(j, &id) || id.sequence != 1) abort();
        gz_journal_close(j); j = NULL;
        cfg.start_counter = 0;
        if (gz_journal_open(&j, &cfg, &info) != GZ_JOURNAL_OK) abort();
        rd = gz_journal_reader(j);
        k = 0;
        while (rd.next(rd.ctx, &sb)) k++;
        if (k != o.nb + 1) abort();
    } else {
        if (now != len || memcmp(after, F, len)) abort();
    }
    gz_journal_close(j);
    memfs_free(&fs);
    return 0;
}

#ifndef LIBFUZZER
int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 10000;
    uint64_t s = argc > 2 ? strtoull(argv[2], NULL, 10) : 1;
    static uint8_t buf[2048];
    for (long it = 0; it < iters; it++) {
        size_t n = 1 + (size_t)((s = s * 6364136223846793005ull + 1442695040888963407ull) >> 33) % sizeof buf;
        for (size_t k = 0; k < n; k++) { s = s * 6364136223846793005ull + 1442695040888963407ull; buf[k] = (uint8_t)(s >> 56); }
        buf[0] &= 0xfe;
        if (it % 10 == 0) buf[0] |= 1;
        LLVMFuzzerTestOneInput(buf, n);
    }
    printf("RESULT: PASS (fuzz_journal_open: %ld inputs)\n", iters);
    return 0;
}
#endif
