/* spec/messages.md sections 4 and 7: see gazpacho/round_msg.h. */
#include "gazpacho/round_msg.h"
#include "gazpacho/signing.h"
#include <string.h>

static const uint8_t PROTOCOL[4] = {GZ_RMSG_PROTOCOL_0, GZ_RMSG_PROTOCOL_1, GZ_RMSG_PROTOCOL_2, GZ_RMSG_PROTOCOL_3};

static uint16_t be16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static uint64_t be64(const uint8_t *p) { return (uint64_t)be32(p) << 32 | be32(p + 4); }
static void wr16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static void wr64(uint8_t *p, uint64_t v) { wr32(p, (uint32_t)(v >> 32)); wr32(p + 4, (uint32_t)v); }

/* ---- envelope and hash ---- */

gz_rmsg_err_t gz_rmsg_open(const uint8_t *bytes, size_t len, uint16_t *kind, const uint8_t **scope,
                           const uint8_t **records, size_t *records_len)
{
    if (!bytes || len < GZ_RMSG_HEADER) return GZ_RMSG_E_SHORT;
    if (memcmp(bytes, PROTOCOL, 4) != 0) return GZ_RMSG_E_PROTOCOL;
    *kind = be16(bytes + 4);
    *scope = bytes + 6;
    *records = bytes + GZ_RMSG_HEADER;
    *records_len = len - GZ_RMSG_HEADER;
    return GZ_RMSG_OK;
}

size_t gz_rmsg_header(uint8_t *out, size_t cap, uint16_t kind, const uint8_t scope[32])
{
    if (cap < GZ_RMSG_HEADER) return 0;
    memcpy(out, PROTOCOL, 4);
    wr16(out + 4, kind);
    memcpy(out + 6, scope, 32);
    return GZ_RMSG_HEADER;
}

void gz_rmsg_hash(uint16_t kind, const uint8_t scope[32], const uint8_t *records, size_t signed_len, uint8_t out[32])
{
    gz_sign_sha256_t s;
    uint8_t k[2];
    wr16(k, kind);
    gz_sign_tagged_init(&s, "gazpacho/msg");
    gz_sign_sha256_write(&s, PROTOCOL, 4);
    gz_sign_sha256_write(&s, k, 2);
    gz_sign_sha256_write(&s, scope, 32);
    if (signed_len) gz_sign_sha256_write(&s, records, signed_len);
    gz_sign_sha256_done(&s, out);
}

/* ---- BigSize (BOLT 1) ---- */

static int bigsize_read(const uint8_t *p, size_t n, size_t *at, uint64_t *v)
{
    if (*at >= n) return 0;
    uint8_t b = p[*at];
    size_t w = b < 0xfd ? 0 : b == 0xfd ? 2 : b == 0xfe ? 4 : 8;
    if (n - *at - 1 < w) return 0;
    const uint8_t *q = p + *at + 1;
    uint64_t x = w == 0 ? b : w == 2 ? be16(q) : w == 4 ? be32(q) : be64(q);
    /* minimal: each width only for values the shorter one cannot hold */
    if ((w == 2 && x < 0xfd) || (w == 4 && x <= 0xffffu) || (w == 8 && x <= 0xffffffffu)) return 0;
    *at += 1 + w;
    *v = x;
    return 1;
}

static size_t bigsize_put(uint8_t *p, uint64_t v)
{
    if (v < 0xfd) { p[0] = (uint8_t)v; return 1; }
    if (v <= 0xffffu) { p[0] = 0xfd; wr16(p + 1, (uint32_t)v); return 3; }
    if (v <= 0xffffffffu) { p[0] = 0xfe; wr32(p + 1, (uint32_t)v); return 5; }
    p[0] = 0xff; wr64(p + 1, v); return 9;
}

void gz_rmsg_wr_init(gz_rmsg_wr_t *w, uint8_t *out, size_t cap) { w->p = out; w->n = 0; w->cap = cap; w->last = 0; w->bad = 0; }

uint8_t *gz_rmsg_reserve(gz_rmsg_wr_t *w, uint64_t type, size_t len)
{
    uint8_t h[18];
    if (w->bad) return NULL;
    if (w->n && type <= w->last) { w->bad = 1; return NULL; }
    size_t hn = bigsize_put(h, type);
    hn += bigsize_put(h + hn, len);
    if (w->cap - w->n < hn || w->cap - w->n - hn < len) { w->bad = 1; return NULL; }
    memcpy(w->p + w->n, h, hn);
    uint8_t *v = w->p + w->n + hn;
    w->n += hn + len;
    w->last = type;
    return v;
}

void gz_rmsg_put(gz_rmsg_wr_t *w, uint64_t type, const void *value, size_t len)
{
    uint8_t *v = gz_rmsg_reserve(w, type, len);
    if (v && len) memcpy(v, value, len);
}

int gz_rmsg_wr_ok(const gz_rmsg_wr_t *w) { return !w->bad; }

/* ---- the table-driven record reader ---- */

#define F_FIX GZ_RMSG_FIX
#define F_LIST GZ_RMSG_LIST
#define F_VAR GZ_RMSG_VAR
typedef gz_rmsg_field_t fld_t;
typedef gz_rmsg_got_t got_t;

static gz_rmsg_err_t parse(const uint8_t *r, size_t n, const fld_t *f, size_t nf, got_t *g, size_t *signed_len)
{
    size_t at = 0;
    uint64_t last = 0;
    int any = 0;
    memset(g, 0, nf * sizeof *g);
    *signed_len = n;
    if (!r && n) return GZ_RMSG_E_LENGTH;
    while (at < n) {
        size_t start = at;
        uint64_t t, l;
        if (any && last == GZ_RMSG_SIG_TYPE) return GZ_RMSG_E_AFTER_SIG;
        if (!bigsize_read(r, n, &at, &t)) return GZ_RMSG_E_BIGSIZE;
        if (any && t <= last) return GZ_RMSG_E_ORDER;
        if (!bigsize_read(r, n, &at, &l)) return GZ_RMSG_E_BIGSIZE;
        if (l > n - at) return GZ_RMSG_E_LENGTH;
        size_t i = 0;
        while (i < nf && f[i].type != t) i++;
        if (i == nf) {
            if ((t & 1u) == 0) return GZ_RMSG_E_UNKNOWN_EVEN;   /* unknown odd: skipped (and still signed over) */
        } else {
            const fld_t *d = &f[i];
            int ok = d->form == F_FIX ? l == d->a
                   : d->form == F_LIST ? l % d->a == 0 && l / d->a >= d->lo && l / d->a <= d->hi
                   : l >= d->lo && l <= d->hi;
            if (!ok) return GZ_RMSG_E_SIZE;
            g[i].v = r + at; g[i].len = (size_t)l; g[i].present = 1;
            if (t == GZ_RMSG_SIG_TYPE) *signed_len = start;
        }
        at += (size_t)l;
        last = t;
        any = 1;
    }
    for (size_t i = 0; i < nf; i++)
        if (f[i].required && !g[i].present) return GZ_RMSG_E_MISSING;
    return GZ_RMSG_OK;
}

gz_rmsg_err_t gz_rmsg_fields(const uint8_t *records, size_t len, const gz_rmsg_field_t *f, size_t nf, gz_rmsg_got_t *got,
                             size_t *signed_len)
{
    size_t sl;
    return parse(records, len, f, nf, got, signed_len ? signed_len : &sl);
}

#define NF(a) (sizeof (a) / sizeof (a)[0])
#define REQ 1
#define OPT 0

/* ---- round_propose (7.2) ---- */

enum {
    P_ROUND_ID, P_CHECK_ID, P_PURPOSE, P_ATTEMPT, P_TERMS_VERSION, P_TERMS_DIGEST, P_FUNDING, P_AMOUNT,
    P_SCRIPT, P_FUNDING_TX, P_PARTICIPANTS, P_TIERS, P_END, P_ANCHORS, P_FEE, P_DELAY, P_HASHES,
    P_FIXED, P_K, P_STEP, P_STATES, P_DIST, P_RANDOM, P_NONCES_DUE, P_SIGS_DUE, P_SIG, P_N
};
static const fld_t PROPOSE[P_N] = {
    {2, REQ, F_FIX, 32, 0, 0}, {4, REQ, F_FIX, 32, 0, 0}, {6, REQ, F_FIX, 1, 0, 0}, {7, OPT, F_FIX, 2, 0, 0},
    {8, REQ, F_FIX, 4, 0, 0}, {10, REQ, F_FIX, 32, 0, 0}, {12, REQ, F_FIX, 36, 0, 0}, {14, REQ, F_FIX, 8, 0, 0},
    {16, REQ, F_FIX, 34, 0, 0}, {18, REQ, F_VAR, 0, 60, 100000}, {20, REQ, F_LIST, 194, 2, 1001},
    {22, REQ, F_LIST, 4, 1, 8}, {24, REQ, F_FIX, 4, 0, 0}, {28, REQ, F_FIX, 1, 0, 0}, {30, REQ, F_FIX, 8, 0, 0},
    {32, REQ, F_FIX, 4, 0, 0}, {34, REQ, F_LIST, 36, 0, 4096}, {36, REQ, F_FIX, 1, 0, 0}, {38, REQ, F_FIX, 1, 0, 0},
    {40, REQ, F_FIX, 2, 0, 0}, {42, REQ, F_FIX, 2, 0, 0}, {44, OPT, F_VAR, 0, 4 + 9, 4 + 255 * 43},
    {46, REQ, F_FIX, 32, 0, 0}, {48, REQ, F_FIX, 4, 0, 0}, {50, REQ, F_FIX, 4, 0, 0}, {240, REQ, F_FIX, 64, 0, 0},
};

/* distribution (record 44): lock time, then outputs (u64 amount, u8 length <= 34, script), at least one. */
static int distribution_ok(const uint8_t *v, size_t len)
{
    size_t at = 4, outs = 0;
    while (at < len) {
        if (len - at < 9) return 0;
        size_t sl = v[at + 8];
        if (sl > 34 || len - at - 9 < sl) return 0;
        at += 9 + sl;
        outs++;
    }
    return outs > 0;
}

gz_rmsg_err_t gz_rmsg_propose_decode(const uint8_t *records, size_t len, gz_rmsg_propose_t *m)
{
    got_t g[P_N];
    size_t signed_len;
    gz_rmsg_err_t e = parse(records, len, PROPOSE, P_N, g, &signed_len);
    memset(m, 0, sizeof *m);
    if (e != GZ_RMSG_OK) return e;
    if (g[P_DIST].present && !distribution_ok(g[P_DIST].v, g[P_DIST].len)) return GZ_RMSG_E_VALUE;
    size_t np = g[P_PARTICIPANTS].len / 194;
    if (np > GZ_RMSG_MAX_PARTICIPANTS) return GZ_RMSG_E_CAPACITY;
    gz_tree_proposal_t *p = &m->p;
    m->round_id = g[P_ROUND_ID].v; m->check_id = g[P_CHECK_ID].v; m->host_random = g[P_RANDOM].v; m->sig = g[P_SIG].v;
    m->has_attempt = g[P_ATTEMPT].present;
    m->attempt = m->has_attempt ? be16(g[P_ATTEMPT].v) : 0;
    p->purpose = g[P_PURPOSE].v[0];
    p->terms_version = be32(g[P_TERMS_VERSION].v);
    memcpy(p->terms_digest, g[P_TERMS_DIGEST].v, 32);
    memcpy(p->funding_txid, g[P_FUNDING].v, 32);
    p->funding_vout = be32(g[P_FUNDING].v + 32);
    p->funding_amount = be64(g[P_AMOUNT].v);
    memcpy(p->funding_script, g[P_SCRIPT].v, 34);
    p->funding_script_len = 34;
    p->funding_tx = g[P_FUNDING_TX].v; p->funding_tx_len = g[P_FUNDING_TX].len;
    for (size_t i = 0; i < np; i++) {
        const uint8_t *q = g[P_PARTICIPANTS].v + 194 * i;
        memcpy(m->parts[i].factory_key, q, 33);
        memcpy(m->parts[i].contribution_key, q + 33, 33);
        memcpy(m->parts[i].bind_by_factory, q + 66, 64);
        memcpy(m->parts[i].bind_by_contribution, q + 130, 64);
    }
    p->participants = m->parts; p->n_participants = np;
    p->n_tiers = (uint8_t)(g[P_TIERS].len / 4);
    for (size_t t = 0; t < p->n_tiers; t++) p->tier_sizes[t] = be32(g[P_TIERS].v + 4 * t);
    p->end_height = be32(g[P_END].v);
    p->tree_anchors = g[P_ANCHORS].v[0];
    p->fee_per_tx = be64(g[P_FEE].v);
    p->lstock_delay = be32(g[P_DELAY].v);
    p->n_lstock_hashes = g[P_HASHES].len / 36;
    m->lstock_hashes = g[P_HASHES].len ? g[P_HASHES].v : NULL;
    p->fixed_levels = g[P_FIXED].v[0];
    p->k = g[P_K].v[0];
    p->layer_step = be16(g[P_STEP].v);
    p->layer_states = be16(g[P_STATES].v);
    p->has_distribution = (uint8_t)g[P_DIST].present;
    m->distribution = g[P_DIST].v; m->distribution_len = g[P_DIST].len;
    p->placement = 0;                     /* never sent: signing-round.md 4.1 fixes it */
    p->nonces_due_ms = be32(g[P_NONCES_DUE].v);
    p->sigs_due_ms = be32(g[P_SIGS_DUE].v);
    m->signed_len = signed_len;
    return GZ_RMSG_OK;
}

size_t gz_rmsg_propose_encode(const gz_rmsg_propose_in_t *in, uint8_t *out, size_t cap)
{
    const gz_tree_proposal_t *p = in ? in->p : NULL;
    if (!p || !in->round_id || !in->check_id || !in->host_random || !out) return 0;
    if (p->funding_script_len != 34 || !p->funding_tx || p->funding_tx_len < 60 || p->funding_tx_len > 100000) return 0;
    if (!p->participants || p->n_participants < 2 || p->n_participants > 1001) return 0;
    if (p->n_tiers < 1 || p->n_tiers > 8 || p->n_lstock_hashes > 4096 || (p->n_lstock_hashes && !in->lstock_hashes)) return 0;
    if (in->distribution && !distribution_ok(in->distribution, in->distribution_len)) return 0;
    gz_rmsg_wr_t w;
    uint8_t b[36], tiers[32], *q;
    gz_rmsg_wr_init(&w, out, cap);
    gz_rmsg_put(&w, 2, in->round_id, 32);
    gz_rmsg_put(&w, 4, in->check_id, 32);
    gz_rmsg_put(&w, 6, &p->purpose, 1);
    if (in->has_attempt) { wr16(b, in->attempt); gz_rmsg_put(&w, 7, b, 2); }
    wr32(b, p->terms_version); gz_rmsg_put(&w, 8, b, 4);
    gz_rmsg_put(&w, 10, p->terms_digest, 32);
    memcpy(b, p->funding_txid, 32); wr32(b + 32, p->funding_vout); gz_rmsg_put(&w, 12, b, 36);
    wr64(b, p->funding_amount); gz_rmsg_put(&w, 14, b, 8);
    gz_rmsg_put(&w, 16, p->funding_script, 34);
    gz_rmsg_put(&w, 18, p->funding_tx, p->funding_tx_len);
    /* participants: one record of 194-byte entries, written in place */
    q = gz_rmsg_reserve(&w, 20, 194 * p->n_participants);
    for (size_t i = 0; q && i < p->n_participants; i++, q += 194) {
        memcpy(q, p->participants[i].factory_key, 33);
        memcpy(q + 33, p->participants[i].contribution_key, 33);
        memcpy(q + 66, p->participants[i].bind_by_factory, 64);
        memcpy(q + 130, p->participants[i].bind_by_contribution, 64);
    }
    for (size_t i = 0; i < p->n_tiers; i++) wr32(tiers + 4 * i, p->tier_sizes[i]);
    gz_rmsg_put(&w, 22, tiers, 4u * p->n_tiers);
    wr32(b, p->end_height); gz_rmsg_put(&w, 24, b, 4);
    gz_rmsg_put(&w, 28, &p->tree_anchors, 1);
    wr64(b, p->fee_per_tx); gz_rmsg_put(&w, 30, b, 8);
    wr32(b, p->lstock_delay); gz_rmsg_put(&w, 32, b, 4);
    gz_rmsg_put(&w, 34, in->lstock_hashes, 36 * p->n_lstock_hashes);
    gz_rmsg_put(&w, 36, &p->fixed_levels, 1);
    gz_rmsg_put(&w, 38, &p->k, 1);
    wr16(b, p->layer_step); gz_rmsg_put(&w, 40, b, 2);
    wr16(b, p->layer_states); gz_rmsg_put(&w, 42, b, 2);
    if (in->distribution) gz_rmsg_put(&w, 44, in->distribution, in->distribution_len);
    gz_rmsg_put(&w, 46, in->host_random, 32);
    wr32(b, p->nonces_due_ms); gz_rmsg_put(&w, 48, b, 4);
    wr32(b, p->sigs_due_ms); gz_rmsg_put(&w, 50, b, 4);
    return w.bad ? 0 : w.n;
}

/* ---- the other kinds ---- */

static const fld_t NONCES[] = {{2, REQ, F_FIX, 32, 0, 0}, {4, REQ, F_FIX, 1, 0, 0}, {6, REQ, F_LIST, 134, 1, 256}};

gz_rmsg_err_t gz_rmsg_nonces_decode(const uint8_t *records, size_t len, gz_rmsg_nonces_t *m)
{
    got_t g[NF(NONCES)];
    size_t sl;
    gz_rmsg_err_t e = parse(records, len, NONCES, NF(NONCES), g, &sl);
    memset(m, 0, sizeof *m);
    if (e != GZ_RMSG_OK) return e;
    m->round_id = g[0].v; m->tier = g[1].v[0]; m->entries = g[2].v; m->n = g[2].len / 134;
    return GZ_RMSG_OK;
}

static const fld_t ALL_NONCES[] = {{2, REQ, F_FIX, 32, 0, 0}, {4, REQ, F_FIX, 1, 0, 0},
                                   {6, REQ, F_VAR, 0, 6 + 130, 256u * (6 + 1001u * 130)}};

gz_rmsg_err_t gz_rmsg_all_nonces_decode(const uint8_t *records, size_t len, gz_rmsg_all_nonces_t *m)
{
    got_t g[NF(ALL_NONCES)];
    size_t sl;
    gz_rmsg_err_t e = parse(records, len, ALL_NONCES, NF(ALL_NONCES), g, &sl);
    memset(m, 0, sizeof *m);
    if (e != GZ_RMSG_OK) return e;
    const uint8_t *v = g[2].v;
    size_t at = 0, n = 0;
    while (at < g[2].len) {
        if (n == GZ_RMSG_MAX_ENTRIES || g[2].len - at < 6) { memset(m, 0, sizeof *m); return GZ_RMSG_E_VALUE; }
        uint16_t k = be16(v + at + 4);
        if (k < 1 || k > 1001 || (g[2].len - at - 6) / 130 < k) { memset(m, 0, sizeof *m); return GZ_RMSG_E_VALUE; }
        m->item[n] = v + at; m->n_signers[n] = k;
        at += 6 + 130u * k;
        n++;
    }
    m->round_id = g[0].v; m->tier = g[1].v[0]; m->n = n;
    return GZ_RMSG_OK;
}

static const fld_t LIST68[] = {{2, REQ, F_FIX, 32, 0, 0}, {4, REQ, F_FIX, 1, 0, 0}, {6, REQ, F_LIST, 68, 1, 256},
                               {240, REQ, F_FIX, 64, 0, 0}};

static gz_rmsg_err_t list68(const uint8_t *records, size_t len, gz_rmsg_list68_t *m)
{
    got_t g[NF(LIST68)];
    size_t sl;
    gz_rmsg_err_t e = parse(records, len, LIST68, NF(LIST68), g, &sl);
    memset(m, 0, sizeof *m);
    if (e != GZ_RMSG_OK) return e;
    m->round_id = g[0].v; m->tier = g[1].v[0]; m->entries = g[2].v; m->n = g[2].len / 68;
    m->sig = g[3].v; m->signed_len = sl;
    return GZ_RMSG_OK;
}
/* Odd 7 (all_partials, not in Slice 1) in a tier result is skipped by the reader. */
gz_rmsg_err_t gz_rmsg_partial_sigs_decode(const uint8_t *r, size_t len, gz_rmsg_list68_t *m) { return list68(r, len, m); }
gz_rmsg_err_t gz_rmsg_tier_result_decode(const uint8_t *r, size_t len, gz_rmsg_list68_t *m) { return list68(r, len, m); }

static const fld_t COMPLETE[] = {{2, REQ, F_FIX, 32, 0, 0}, {240, REQ, F_FIX, 64, 0, 0}};
static const fld_t ACK[] = {{2, REQ, F_FIX, 32, 0, 0}, {4, REQ, F_FIX, 32, 0, 0}, {240, REQ, F_FIX, 64, 0, 0}};
static const fld_t ONE32[] = {{2, REQ, F_FIX, 32, 0, 0}};

gz_rmsg_err_t gz_rmsg_complete_decode(const uint8_t *records, size_t len, gz_rmsg_small_t *m)
{
    got_t g[NF(COMPLETE)];
    size_t sl;
    gz_rmsg_err_t e = parse(records, len, COMPLETE, NF(COMPLETE), g, &sl);
    memset(m, 0, sizeof *m);
    if (e != GZ_RMSG_OK) return e;
    m->round_id = g[0].v; m->sig = g[1].v; m->signed_len = sl;
    return GZ_RMSG_OK;
}

gz_rmsg_err_t gz_rmsg_ack_decode(const uint8_t *records, size_t len, gz_rmsg_small_t *m)
{
    got_t g[NF(ACK)];
    size_t sl;
    gz_rmsg_err_t e = parse(records, len, ACK, NF(ACK), g, &sl);
    memset(m, 0, sizeof *m);
    if (e != GZ_RMSG_OK) return e;
    m->round_id = g[0].v; m->held_digest = g[1].v; m->sig = g[2].v; m->signed_len = sl;
    return GZ_RMSG_OK;
}

gz_rmsg_err_t gz_rmsg_status_decode(const uint8_t *records, size_t len, gz_rmsg_small_t *m)
{
    got_t g[1];
    size_t sl;
    gz_rmsg_err_t e = parse(records, len, ONE32, 1, g, &sl);
    memset(m, 0, sizeof *m);
    if (e != GZ_RMSG_OK) return e;
    m->round_id = g[0].v; m->signed_len = len;
    return GZ_RMSG_OK;
}

gz_rmsg_err_t gz_rmsg_funded_decode(const uint8_t *records, size_t len, gz_rmsg_small_t *m)
{
    got_t g[1];
    size_t sl;
    gz_rmsg_err_t e = parse(records, len, ONE32, 1, g, &sl);
    memset(m, 0, sizeof *m);
    if (e != GZ_RMSG_OK) return e;
    m->funding_txid = g[0].v; m->signed_len = len;
    return GZ_RMSG_OK;
}

/* 5 (evidence, not in Slice 1) is odd and skipped by the reader. */
static const fld_t ABORT[] = {{2, REQ, F_FIX, 32, 0, 0}, {4, REQ, F_FIX, 2, 0, 0}, {7, OPT, F_VAR, 0, 1, 256},
                              {9, OPT, F_FIX, 1, 0, 0}, {11, OPT, F_LIST, 4, 1, 256}, {240, REQ, F_FIX, 64, 0, 0}};

gz_rmsg_err_t gz_rmsg_abort_decode(const uint8_t *records, size_t len, gz_rmsg_abort_t *m)
{
    got_t g[NF(ABORT)];
    size_t sl;
    gz_rmsg_err_t e = parse(records, len, ABORT, NF(ABORT), g, &sl);
    memset(m, 0, sizeof *m);
    if (e != GZ_RMSG_OK) return e;
    for (size_t i = 0; i < g[2].len; i++)
        if (g[2].v[i] < 0x20 || g[2].v[i] > 0x7e) return GZ_RMSG_E_VALUE;     /* ASCII, printable */
    m->round_id = g[0].v; m->reason = be16(g[1].v);
    m->detail = g[2].v; m->detail_len = g[2].len;
    m->has_tier = g[3].present; m->tier = g[3].present ? g[3].v[0] : 0;
    m->items = g[4].v; m->n_items = g[4].len / 4;
    m->sig = g[5].v; m->signed_len = sl;
    return GZ_RMSG_OK;
}

/* ---- hashes ---- */

void gz_rmsg_nonce_hash(const uint8_t round_id[32], uint8_t tier, uint32_t index, const uint8_t nonce[66], uint8_t out[32])
{
    gz_sign_sha256_t s;
    uint8_t b[5];
    b[0] = tier; wr32(b + 1, index);
    gz_sign_tagged_init(&s, "gazpacho/nonce");
    gz_sign_sha256_write(&s, round_id, 32);
    gz_sign_sha256_write(&s, b, 5);
    gz_sign_sha256_write(&s, nonce, 66);
    gz_sign_sha256_done(&s, out);
}

void gz_rmsg_nonceset_hash(const uint8_t (*nonces)[66], size_t n, uint8_t out[32])
{
    gz_sign_sha256_t s;
    gz_sign_tagged_init(&s, "gazpacho/nonceset");
    for (size_t i = 0; i < n; i++) gz_sign_sha256_write(&s, nonces[i], 66);
    gz_sign_sha256_done(&s, out);
}

void gz_rmsg_held_hash(const uint32_t *index, const uint8_t (*finals)[64], size_t n, uint8_t out[32])
{
    gz_sign_sha256_t s;
    gz_sign_tagged_init(&s, "gazpacho/held");
    for (size_t i = 0; i < n; i++) {
        uint8_t b[4];
        wr32(b, index[i]);
        gz_sign_sha256_write(&s, b, 4);
        gz_sign_sha256_write(&s, finals[i], 64);
    }
    gz_sign_sha256_done(&s, out);
}
