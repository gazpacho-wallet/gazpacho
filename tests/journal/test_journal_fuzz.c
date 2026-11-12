/* A mutation fuzzer for the journal's reader: valid journals are damaged at
 * random (flipped bits, overwritten bytes, cuts, insertions, copied and moved
 * ranges, re-checksummed entries) and given to the scan and to a full open.
 * Run under the sanitizers and valgrind; checks, for every input:
 *   - the scan and the open agree on the status;
 *   - a torn verdict cut at V scans clean, with the same counts;
 *   - after an accepted open the file is exactly data[0..V] plus a new
 *     incarnation and its mark, and the reader yields every kept batch;
 *   - a refused open leaves the file untouched.
 * Usage: test_journal_fuzz [iterations] [seed] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../check.h"
#include "harness.h"

static uint64_t rs;
static uint64_t rnd(void) { return h_mix(rs++); }

/* A valid journal written by the journal itself. */
static size_t make_seed(uint8_t *out, size_t cap, uint64_t seed)
{
    h_t *h = calloc(1, sizeof *h);
    memfs_init(&h->fs);
    h->guards = 1;
    h->next_step = seed * 100;
    for (int run = 0; run < 3; run++) {
        h_open(h, NULL);
        int steps = (int)((seed + (uint64_t)run) % 5);
        for (int s = 0; s < steps; s++) {
            h_step(h);
            if ((seed >> s) & 1) gz_journal_flush(h->j);
        }
        h_close(h);
    }
    size_t len;
    const uint8_t *d = memfs_get(&h->fs, H_JOURNAL, &len);
    if (len > cap) len = cap;
    memcpy(out, d, len);
    memfs_free(&h->fs);
    free(h);
    return len;
}

static size_t mutate(uint8_t *d, size_t len, size_t cap)
{
    int n = 1 + (int)(rnd() % 4);
    for (int i = 0; i < n && len > 0; i++) {
        size_t at = (size_t)(rnd() % len);
        switch (rnd() % 8) {
        case 0: d[at] ^= (uint8_t)(1u << (rnd() % 8)); break;
        case 1: d[at] = (uint8_t)rnd(); break;
        case 2: len = at; break;
        case 3: { /* insert */
            size_t k = 1 + (size_t)(rnd() % 40);
            if (len + k > cap) break;
            memmove(d + at + k, d + at, len - at);
            for (size_t q = 0; q < k; q++) d[at + q] = (uint8_t)rnd();
            len += k;
            break;
        }
        case 4: { /* copy a range to the end */
            size_t k = (size_t)(rnd() % (len - at + 1));
            if (len + k > cap) break;
            memmove(d + len, d + at, k);
            len += k;
            break;
        }
        case 5: { /* delete a range */
            size_t k = (size_t)(rnd() % (len - at + 1));
            memmove(d + at, d + at + k, len - at - k);
            len -= k;
            break;
        }
        case 6: { /* change an entry field and fix its checksum, if one starts here */
            if (len - at < 29) break;
            uint32_t l = (uint32_t)d[at] << 24 | (uint32_t)d[at + 1] << 16 | (uint32_t)d[at + 2] << 8 | d[at + 3];
            if (l < 21 || at + 4 + l + 8 > len) break;
            d[at + 4 + (rnd() % l)] ^= (uint8_t)(1u << (rnd() % 8));
            uint8_t hsh[32];
            sha256(d + at, 4 + l, hsh);
            memcpy(d + at + 4 + l, hsh, 8);
            break;
        }
        default: /* append zeros */
            if (len + 16 <= cap) { memset(d + len, 0, 16); len += 16; }
        }
    }
    return len;
}

typedef struct { uint64_t n; } count_t;
static void count_batch(void *ctx, uint64_t off, uint32_t size, gz_batch_id_t id, const uint8_t *p, size_t l)
{
    (void)off; (void)size; (void)id;
    ((count_t *)ctx)->n += gz_journal_parse_batch(p, l, NULL, 0, NULL) >= 0;
}

int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 20000;
    rs = argc > 2 ? strtoull(argv[2], NULL, 10) : 1;
    enum { CAP = 16384 };
    static uint8_t seeds[8][CAP], d[CAP];
    size_t seed_len[8];
    for (int s = 0; s < 8; s++) seed_len[s] = make_seed(seeds[s], CAP / 2, (uint64_t)s + 3);
    long verdicts[3] = {0, 0, 0}, mismatches = 0;
    for (long it = 0; it < iters; it++) {
        int s = (int)(rnd() % 8);
        memcpy(d, seeds[s], seed_len[s]);
        size_t len = mutate(d, seed_len[s], CAP);
        gz_journal_scan_t sc;
        count_t c = {0};
        gz_journal_status_t st = gz_journal_scan(d, len, gz_journal_chain_signet, &sc, count_batch, &c);
        verdicts[sc.verdict]++;
        int bad = (st == GZ_JOURNAL_OK) != (sc.verdict != GZ_JOURNAL_REFUSED) || sc.valid_end > len;
        if (st == GZ_JOURNAL_OK) bad |= c.n != sc.n_batches;
        if (sc.verdict == GZ_JOURNAL_TORN) {
            gz_journal_scan_t again;
            gz_journal_scan(d, (size_t)sc.valid_end, gz_journal_chain_signet, &again, NULL, NULL);
            bad |= again.verdict != GZ_JOURNAL_CLEAN || again.n_batches != sc.n_batches ||
                   again.n_records != sc.n_records || again.highest_incarnation != sc.highest_incarnation;
        }
        /* The full open on a memfs. */
        memfs_t fs;
        memfs_init(&fs);
        memfs_put(&fs, H_JOURNAL, d, len);
        gz_journal_t *j = NULL;
        gz_journal_config_t cfg = {H_DIR, gz_journal_chain_signet, 9, &fs.os, 0, 0, 0};
        gz_journal_status_t ost = gz_journal_open(&j, &cfg, NULL);
        size_t now;
        const uint8_t *after = memfs_get(&fs, H_JOURNAL, &now);
        if (len < GZ_JOURNAL_HEADER_LEN && ost == GZ_JOURNAL_ERR_HEADER) {
            /* nothing more to check */
        } else if (ost != st) {
            bad = 1;
        } else if (ost == GZ_JOURNAL_OK) {
            bad |= now != sc.valid_end + 74 || memcmp(after, d, (size_t)sc.valid_end) != 0;
            gz_storage_reader_t rd = gz_journal_reader(j);
            gz_stored_batch_t sb;
            uint64_t k = 0;
            while (rd.next(rd.ctx, &sb)) k++;
            bad |= k != sc.n_batches || gz_journal_failed(j);
            bad |= gz_journal_incarnation(j) != sc.highest_incarnation + 1;
        } else {
            bad |= now != len || memcmp(after, d, len) != 0;
        }
        gz_journal_close(j);
        memfs_free(&fs);
        if (bad && mismatches++ < 5) printf("  iteration %ld: status %s, open %s\n", it,
                                            gz_journal_status_name(st), gz_journal_status_name(ost));
    }
    printf("  %ld inputs: %ld clean, %ld torn, %ld refused\n", iters, verdicts[0], verdicts[1], verdicts[2]);
    CHECK(mismatches == 0);
    /* The fuzzer must reach every verdict, or it tests nothing. */
    CHECK(iters < 1000 || (verdicts[0] > 0 && verdicts[1] > 0 && verdicts[2] > 0));
    return check_done();
}
