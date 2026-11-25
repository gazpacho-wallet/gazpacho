/* Transaction sizes and fees for the funding engine: the signed funding's
 * virtual size, its bytes without witnesses, and the replacement fee of the
 * spend-back (composite-node.md 14.3). Hostile bytes: every read is bounded. */
#include "gazpacho/funding.h"
#include <string.h>

/* Bitcoin's CompactSize, minimally encoded. 0 if malformed or short. */
static size_t csize(const uint8_t *p, size_t n, uint64_t *v)
{
    if (n < 1) return 0;
    if (p[0] < 0xfd) { *v = p[0]; return 1; }
    if (p[0] == 0xfd) {
        if (n < 3) return 0;
        *v = (uint64_t)p[1] | (uint64_t)p[2] << 8;
        return *v < 0xfd ? 0 : 3;
    }
    if (p[0] == 0xfe) {
        if (n < 5) return 0;
        *v = (uint64_t)p[1] | (uint64_t)p[2] << 8 | (uint64_t)p[3] << 16 | (uint64_t)p[4] << 24;
        return *v <= 0xffff ? 0 : 5;
    }
    return 0; /* nothing here needs 64-bit counts */
}

/* Walks the transaction. Fills the offsets of the witness section (or 0 if
 * none), the end of the outputs, and the totals. */
typedef struct {
    int segwit;
    size_t outs_end;   /* offset after the last output */
    size_t wit_end;    /* offset of the lock time */
    size_t n_in;
} walk_t;

static int walk(const uint8_t *tx, size_t len, walk_t *w)
{
    size_t at = 4, k;
    uint64_t n_in, n_out, v;
    memset(w, 0, sizeof *w);
    if (!tx || len < 10 || len > GZ_FUND_MAX_SIGNED) return 0;
    if (tx[4] == 0x00) {
        if (tx[5] != 0x01) return 0;
        w->segwit = 1;
        at = 6;
    }
    if (!(k = csize(tx + at, len - at, &n_in))) return 0;
    at += k;
    if (n_in == 0 || n_in > GZ_FUND_MAX_INPUTS) return 0;
    for (uint64_t i = 0; i < n_in; i++) {
        if (len - at < 36) return 0;
        at += 36;
        if (!(k = csize(tx + at, len - at, &v))) return 0;
        at += k;
        if (v > len - at) return 0;
        at += (size_t)v;
        if (len - at < 4) return 0;
        at += 4;
    }
    if (!(k = csize(tx + at, len - at, &n_out))) return 0;
    at += k;
    if (n_out == 0 || n_out > 1000) return 0;
    for (uint64_t i = 0; i < n_out; i++) {
        if (len - at < 8) return 0;
        at += 8;
        if (!(k = csize(tx + at, len - at, &v))) return 0;
        at += k;
        if (v > len - at) return 0;
        at += (size_t)v;
    }
    w->outs_end = at;
    if (w->segwit) {
        int any = 0;
        for (uint64_t i = 0; i < n_in; i++) {
            uint64_t items;
            if (!(k = csize(tx + at, len - at, &items))) return 0;
            at += k;
            if (items > 100) return 0;
            if (items) any = 1;
            for (uint64_t j = 0; j < items; j++) {
                if (!(k = csize(tx + at, len - at, &v))) return 0;
                at += k;
                if (v > len - at) return 0;
                at += (size_t)v;
            }
        }
        if (!any) return 0; /* a segwit form with no witness is not canonical */
    }
    w->wit_end = at;
    if (len - at != 4) return 0;
    w->n_in = (size_t)n_in;
    return 1;
}

int gz_fund_tx_vsize(const uint8_t *tx, size_t len, uint64_t *vsize, size_t *base)
{
    walk_t w;
    size_t b;
    if (!walk(tx, len, &w)) return 0;
    /* Without witnesses: version, the inputs and outputs, the lock time. */
    b = w.segwit ? len - 2 - (w.wit_end - w.outs_end) : len;
    if (vsize) *vsize = ((uint64_t)b * 3 + (uint64_t)len + 3) / 4;
    if (base) *base = b;
    return 1;
}

int gz_fund_tx_strip(const uint8_t *tx, size_t len, uint8_t *out, size_t cap, size_t *out_len)
{
    walk_t w;
    size_t b;
    if (!out || !out_len || !walk(tx, len, &w)) return 0;
    if (!w.segwit) {
        if (len > cap) return 0;
        memcpy(out, tx, len);
        *out_len = len;
        return 1;
    }
    b = len - 2 - (w.wit_end - w.outs_end);
    if (b > cap) return 0;
    memcpy(out, tx, 4);
    memcpy(out + 4, tx + 6, w.outs_end - 6);
    memcpy(out + 4 + (w.outs_end - 6), tx + w.wit_end, 4);
    *out_len = b;
    return 1;
}

/* Every input of a segwit transaction carries a witness: 1, else 0. */
int gz_fund_tx_all_witness(const uint8_t *tx, size_t len);
int gz_fund_tx_all_witness(const uint8_t *tx, size_t len)
{
    walk_t w;
    size_t at, k;
    uint64_t items, v;
    if (!walk(tx, len, &w) || !w.segwit) return 0;
    at = w.outs_end;
    for (size_t i = 0; i < w.n_in; i++) {
        if (!(k = csize(tx + at, len - at, &items))) return 0;
        at += k;
        if (items == 0) return 0;
        for (uint64_t j = 0; j < items; j++) {
            if (!(k = csize(tx + at, len - at, &v))) return 0;
            at += k + (size_t)v;
        }
    }
    return 1;
}

uint64_t gz_fund_fee(uint64_t rate, uint64_t vsize)
{
    if (rate > UINT64_C(100000000) || vsize > UINT64_C(4000000)) return UINT64_MAX;
    return (rate * vsize + 999) / 1000;
}

uint64_t gz_fund_replace_fee(uint64_t package_fee, uint64_t package_vsize, uint64_t vsize,
                             uint64_t incremental)
{
    uint64_t inc = gz_fund_fee(incremental, vsize), fee;
    if (inc == UINT64_MAX || package_fee > UINT64_C(2100000000000000)) return UINT64_MAX;
    fee = package_fee + inc;
    /* Rule 6: a higher rate than the transaction it replaces, compared as
     * Core does, fee times the other's size. */
    if (package_vsize && vsize) {
        if (vsize > UINT64_C(4000000) || package_vsize > UINT64_C(4000000)) return UINT64_MAX;
        uint64_t floor_fee = package_fee * vsize / package_vsize + 1;
        if (fee < floor_fee) fee = floor_fee;
    }
    return fee;
}

uint64_t gz_fund_funding_fee_bound(const gz_fund_config_t *cfg, size_t n_coins)
{
    uint64_t n = n_coins == 0 ? 1 : n_coins > GZ_FUND_MAX_INPUTS ? GZ_FUND_MAX_INPUTS : n_coins;
    /* without witnesses: version, the input count (one byte up to 197),
     * 41 bytes an input, the output count, two P2TR outputs (43 bytes
     * each), the lock time */
    uint64_t base = 4 + 1 + 41 * n + 1 + 2 * 43 + 4;
    /* the marker and flag, and each input's witness at its largest */
    uint64_t wit = 2 + 67 * n;
    uint64_t vsize = (4 * base + wit + 3) / 4;
    if (cfg == NULL) return UINT64_MAX;
    return gz_fund_fee(cfg->feerate, vsize);
}

gz_fund_funds_t gz_fund_funds_short(const gz_fund_config_t *cfg, uint64_t set_aside_sat,
                                    uint64_t *need_sat, uint64_t *have_sat)
{
    uint64_t sat = 0, fee, need;
    size_t n = 0;
    int r;
    if (need_sat) *need_sat = 0;
    if (have_sat) *have_sat = 0;
    if (cfg == NULL || cfg->wallet.can_plan == NULL) return GZ_FUND_FUNDS_UNKNOWN;
    r = cfg->wallet.can_plan(cfg->wallet.ctx, set_aside_sat, cfg->feerate, &sat, &n);
    if (r != 0 && r != 1) return GZ_FUND_FUNDS_UNKNOWN;   /* -1, or anything else: never enough */
    fee = gz_fund_funding_fee_bound(cfg, n);
    need = fee == UINT64_MAX || set_aside_sat > UINT64_MAX - fee - GZ_FUND_CHANGE_DUST
               ? UINT64_MAX
               : set_aside_sat + fee + GZ_FUND_CHANGE_DUST;
    if (need_sat) *need_sat = need;
    if (have_sat) *have_sat = sat;
    return r == 1 ? GZ_FUND_FUNDS_OK : GZ_FUND_FUNDS_SHORT;
}
