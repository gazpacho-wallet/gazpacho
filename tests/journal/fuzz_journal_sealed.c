/* The journal's scan of the sealed format (gz_journal_scan_sealed, storage
 * 5.3 to 5.5, journal.md 5). Two kinds of input:
 *   - raw bytes after a valid sealed header: the scan must not crash, and
 *     what it keeps must be well formed;
 *   - an odd first byte, then a recipe: a valid sealed journal is built (incarnation
 *     entries, batches of the recipe's records, a sync mark after each
 *     group), one byte of it flipped at an offset the input picks, and the
 *     scan must say exactly what journal.md 5 says: a flip before the last
 *     sync mark is corruption (refused), a flip in the last mark or after it
 *     is a torn tail cut at that mark's offset, a flip in the header refuses.
 * The table is a minimal one over the storage layer's own seal and open. */
#include "journal.h"
#include "gz_storage_crypto.h"
#include "gz_storage_crypto_test.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t CHAIN[32] = {0xf6, 0x1e, 0xee, 0x3b};
static const uint8_t FID[16] = {9, 8, 7};
static gz_sc_vault_t *vault;
static gz_sc_framekey_t *kj;
static uint8_t header[GZ_SC_JHEADER_LEN];

static void init(void)
{
    if (vault)
        return;
    uint8_t msk[32] = {3}, seed[64] = {2}, vid[16] = {1};
    if (gz_sc_init() != GZ_SC_OK || gz_sc_vault_new(CHAIN, vid, msk, seed, &vault) != GZ_SC_OK ||
        gz_sc_header_seal(vault, FID, header) != GZ_SC_OK || gz_sc_header_open(header, vault, &kj) != GZ_SC_OK)
        abort();
}

static gz_journal_status_t t_header(void *ctx, const uint8_t *d, size_t len, const uint8_t chain[32])
{
    (void)ctx;
    uint8_t v[16], f[16];
    gz_sc_err_t e = gz_sc_header_clear(d, len, chain, v, f);
    if (e == GZ_SC_OTHER_NETWORK)
        return GZ_JOURNAL_ERR_NETWORK;
    if (e != GZ_SC_OK)
        return GZ_JOURNAL_ERR_HEADER;
    gz_sc_framekey_t *k = NULL;
    if (memcmp(f, FID, 16) != 0 || gz_sc_header_open(d, vault, &k) != GZ_SC_OK)
        return GZ_JOURNAL_ERR_NOT_THIS_WALLET;
    gz_sc_framekey_free(k);
    return GZ_JOURNAL_OK;
}

static int t_seal(void *ctx, uint64_t off, uint8_t kind, uint64_t inc, uint64_t seq, const uint8_t *p, size_t len,
                  uint8_t *out)
{
    (void)ctx;
    size_t n;
    return gz_sc_frame_seal(kj, off, kind, inc, seq, p, len, out, len + GZ_SC_FRAME_OVERHEAD, &n) == GZ_SC_OK ? 0 : -1;
}

static int t_open(void *ctx, const uint8_t *q, uint64_t avail, uint64_t off, gz_journal_frame_t *f, uint8_t *pl,
                  size_t cap)
{
    (void)ctx;
    gz_sc_frame_t fr;
    if (gz_sc_frame_open(kj, q, (size_t)avail, off, &fr, pl, cap) != GZ_SC_OK)
        return 0;
    f->kind = fr.kind;
    f->incarnation = fr.incarnation;
    f->sequence = fr.sequence;
    f->size = fr.entry_len;
    f->payload_len = fr.payload_len;
    return 1;
}

static gz_journal_seal_t table(void)
{
    gz_journal_seal_t t;
    memset(&t, 0, sizeof t);
    t.header_len = GZ_SC_JHEADER_LEN;
    t.overhead = GZ_SC_FRAME_OVERHEAD;
    t.mark_size = GZ_SC_FRAME_OVERHEAD + 8;
    t.mark_length = GZ_SC_FRAME_OVERHEAD - 4 + 8;
    t.header_open = t_header;
    t.frame_seal = t_seal;
    t.frame_open = t_open;
    return t;
}

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--, v >>= 8)
        p[i] = (uint8_t)v;
}

static void check_kept(void *ctx, uint64_t off, uint32_t size, gz_batch_id_t id, const uint8_t *payload, size_t len)
{
    (void)ctx;
    (void)off;
    (void)size;
    (void)id;
    if (gz_journal_parse_batch(payload, len, NULL, 0, NULL) < 0)
        abort(); /* the scan keeps only batches whose records fill the payload */
}

static uint8_t file[1 << 16];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    init();
    gz_journal_seal_t t = table();
    gz_journal_scan_t sc;
    if (size == 0 || (data[0] & 1) == 0) {
        if (size + GZ_SC_JHEADER_LEN > sizeof file)
            return 0;
        memcpy(file, header, GZ_SC_JHEADER_LEN);
        memcpy(file + GZ_SC_JHEADER_LEN, data, size);
        gz_journal_scan_sealed(file, GZ_SC_JHEADER_LEN + size, CHAIN, &t, &sc, check_kept, NULL);
        if (sc.verdict != GZ_JOURNAL_REFUSED && sc.valid_end > GZ_SC_JHEADER_LEN + size)
            abort();
        return 0;
    }
    /* The recipe: data[1..2] the flip's offset, then groups of batches. */
    if (size < 4)
        return 0;
    size_t flip = ((size_t)data[1] << 8 | data[2]), at = GZ_SC_JHEADER_LEN, last_mark = 0;
    uint64_t inc = 0, seq = 0;
    uint8_t pl[600];
    memcpy(file, header, GZ_SC_JHEADER_LEN);
    for (size_t i = 3; i < size && at + 800 < sizeof file; i++) {
        uint8_t op = data[i];
        size_t n;
        if (inc == 0 || (op & 0xc0) == 0) { /* a new incarnation and its mark */
            inc++;
            seq = 0;
            put64(pl, 1700000000000ull);
            if (t_seal(NULL, at, 1, inc, 0, pl, 8, file + at) != 0)
                abort();
            at += 69;
        } else { /* a batch: one record of the recipe's length and bytes */
            uint32_t rlen = (uint32_t)(op & 0x3f) * 7u;
            memset(pl, 0, 12);
            pl[3] = 1;                     /* n_records 1 */
            pl[4] = 0x7e; pl[5] = 0x57;    /* a placeholder test type */
            pl[7] = 1;
            pl[8] = (uint8_t)(rlen >> 24); pl[9] = (uint8_t)(rlen >> 16);
            pl[10] = (uint8_t)(rlen >> 8); pl[11] = (uint8_t)rlen;
            for (uint32_t k = 0; k < rlen; k++)
                pl[12 + k] = data[(i + k) % size];
            n = 12 + rlen;
            if (t_seal(NULL, at, 2, inc, ++seq, pl, n, file + at) != 0)
                abort();
            at += n + GZ_SC_FRAME_OVERHEAD;
        }
        put64(pl, at); /* a sync mark after every entry: each one durable */
        if (t_seal(NULL, at, 3, inc, 0, pl, 8, file + at) != 0)
            abort();
        last_mark = at;
        at += 69;
    }
    if (last_mark == 0)
        return 0;
    /* Unharmed: clean. */
    if (gz_journal_scan_sealed(file, at, CHAIN, &t, &sc, check_kept, NULL) != GZ_JOURNAL_OK ||
        sc.verdict != GZ_JOURNAL_CLEAN || sc.valid_end != at || sc.highest_incarnation != inc)
        abort();
    flip %= at;
    file[flip] = (uint8_t)(file[flip] ^ (1u << (data[1] & 7)));
    gz_journal_status_t st = gz_journal_scan_sealed(file, at, CHAIN, &t, &sc, check_kept, NULL);
    if (flip < GZ_SC_JHEADER_LEN) {
        if (sc.verdict != GZ_JOURNAL_REFUSED)
            abort(); /* a damaged header refuses */
    } else if (flip < last_mark) {
        if (sc.verdict != GZ_JOURNAL_REFUSED || st != GZ_JOURNAL_ERR_CORRUPT)
            abort(); /* before a durable mark: corruption, never a tail */
    } else {
        if (sc.verdict != GZ_JOURNAL_TORN || sc.valid_end != last_mark || st != GZ_JOURNAL_OK)
            abort(); /* the last mark itself: a torn tail cut at its offset */
    }
    return 0;
}
