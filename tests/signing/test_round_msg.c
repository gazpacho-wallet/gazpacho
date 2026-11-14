/* Tests of the round message codecs (core/signing/round_msg.c) against
 * spec/messages.md sections 4 and 7: vector M1 (envelope, records, message
 * hash and signature), the round trip of every kind, and each rule of 4.2
 * broken in turn (messages.md section 12, tests 1 to 6). */
#include "gazpacho/round_msg.h"
#include "gazpacho/signing.h"
#include "../check.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t unhex(const char *h, uint8_t *out)
{
    size_t n = 0;
    while (*h) {
        if (*h == ' ' || *h == '\n') { h++; continue; }
        unsigned v;
        if (sscanf(h, "%2x", &v) != 1) abort();
        out[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

/* ---- M1: a lobby `ready`, the only section 11 vector of a signed message ---- */
static void test_m1(void)
{
    uint8_t msg[256], hash[32], want[32], key[33];
    size_t n = unhex("ce37 677a6601 0016 75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2"
                     "0220 75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2"
                     "0404 00000001"
                     "0620 d1db6ddfd5a2c12ae197036f285457ae6ceaf468c2a47fb71691dde4b1153942"
                     "f040 7eb07e7116d893db0aa57ca3c88fd1b7c67aeb5a0772923c08a4f10350197cbc"
                     "08c19ce8d566df618ab0df88d9773f5089c63b83d4fc99636a5ba7f433762627", msg);
    CHECK(n == 180);
    uint16_t kind;
    const uint8_t *scope, *rec;
    size_t rlen;
    CHECK(gz_rmsg_open(msg + 2, n - 2, &kind, &scope, &rec, &rlen) == GZ_RMSG_OK && kind == 22);
    /* records 2, 4, 6 then 240: the signature covers everything before 240 */
    size_t signed_len = 2 + 32 + 2 + 4 + 2 + 32;
    CHECK(rlen == signed_len + 2 + 64 && rec[signed_len] == 0xf0 && rec[signed_len + 1] == 0x40);
    gz_rmsg_hash(kind, scope, rec, signed_len, hash);
    unhex("683a9673360b942f37224c92dfeb58765fc9085e14bae4c6120b46c5be42f8d0", want);
    CHECK(memcmp(hash, want, 32) == 0);
    unhex("024322bd904fa9770421b0b48f08e961d473f3ee9a36a5bc85fa3cac30fa2e15ae", key);
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_xonly_pubkey xk;
    CHECK(secp256k1_xonly_pubkey_parse(ctx, &xk, key + 1));
    CHECK(secp256k1_schnorrsig_verify(ctx, rec + signed_len + 2, hash, 32, &xk));
    hash[0] ^= 1;
    CHECK(!secp256k1_schnorrsig_verify(ctx, rec + signed_len + 2, hash, 32, &xk));   /* the control */
    secp256k1_context_destroy(ctx);
    uint8_t h2[GZ_RMSG_HEADER];
    CHECK(gz_rmsg_header(h2, sizeof h2, kind, scope) == GZ_RMSG_HEADER && memcmp(h2, msg + 2, GZ_RMSG_HEADER) == 0);
    msg[2] ^= 1;
    CHECK(gz_rmsg_open(msg + 2, n - 2, &kind, &scope, &rec, &rlen) == GZ_RMSG_E_PROTOCOL);
    CHECK(gz_rmsg_open(msg + 2, GZ_RMSG_HEADER - 1, &kind, &scope, &rec, &rlen) == GZ_RMSG_E_SHORT);
}

/* ---- round_propose ---- */

typedef struct {
    gz_tree_proposal_t p;
    gz_tree_participant_t parts[GZ_RMSG_MAX_PARTICIPANTS + 1];
    uint8_t funding_tx[200], round_id[32], check_id[32], host_random[32], hashes[36 * 2];
    gz_rmsg_propose_in_t in;
} prop_t;

static void fill(uint8_t *p, size_t n, uint8_t seed) { for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(seed + 7 * i); }

static void prop_make(prop_t *x, size_t n_participants)
{
    memset(x, 0, sizeof *x);
    for (size_t i = 0; i < n_participants; i++) {
        fill(x->parts[i].factory_key, 33, (uint8_t)(1 + i));
        fill(x->parts[i].contribution_key, 33, (uint8_t)(40 + i));
        fill(x->parts[i].bind_by_factory, 64, (uint8_t)(80 + i));
        fill(x->parts[i].bind_by_contribution, 64, (uint8_t)(120 + i));
    }
    fill(x->funding_tx, sizeof x->funding_tx, 9);
    fill(x->round_id, 32, 11); fill(x->check_id, 32, 12); fill(x->host_random, 32, 13);
    gz_tree_proposal_t *p = &x->p;
    p->purpose = 1; p->terms_version = 0x01020304u; fill(p->terms_digest, 32, 14);
    fill(p->funding_txid, 32, 15); p->funding_vout = 0x00010203u; p->funding_amount = 802827u;
    p->funding_script[0] = 0x51; p->funding_script[1] = 0x20; fill(p->funding_script + 2, 32, 16); p->funding_script_len = 34;
    p->funding_tx = x->funding_tx; p->funding_tx_len = 154;
    p->participants = x->parts; p->n_participants = n_participants;
    p->n_tiers = 1; p->tier_sizes[0] = 45;
    p->end_height = 330796; p->tree_anchors = 1; p->fee_per_tx = 17; p->lstock_delay = 144;
    p->fixed_levels = 3; p->k = 1; p->layer_step = 144; p->layer_states = 4;
    p->nonces_due_ms = 60000; p->sigs_due_ms = 59999;
    x->in.round_id = x->round_id; x->in.check_id = x->check_id; x->in.host_random = x->host_random;
    x->in.p = p;
}

static uint8_t g_buf[1 << 17], g_buf2[1 << 17];

/* Encode with a stand-in signature; returns the records' length. */
static size_t prop_encode(const prop_t *x, uint8_t *out, size_t cap)
{
    size_t n = gz_rmsg_propose_encode(&x->in, out, cap);
    if (!n) return 0;
    uint8_t sig[64];
    fill(sig, 64, 99);
    gz_rmsg_wr_t w;
    gz_rmsg_wr_init(&w, out + n, cap - n);
    gz_rmsg_put(&w, GZ_RMSG_SIG_TYPE, sig, 64);
    return gz_rmsg_wr_ok(&w) ? n + w.n : 0;
}

static int prop_same(const gz_rmsg_propose_t *m, const prop_t *x)
{
    const gz_tree_proposal_t *a = &m->p, *b = &x->p;
    int ok = a->purpose == b->purpose && a->terms_version == b->terms_version && !memcmp(a->terms_digest, b->terms_digest, 32) &&
             !memcmp(a->funding_txid, b->funding_txid, 32) && a->funding_vout == b->funding_vout &&
             a->funding_amount == b->funding_amount && !memcmp(a->funding_script, b->funding_script, 34) &&
             a->funding_script_len == 34 && a->funding_tx_len == b->funding_tx_len &&
             !memcmp(a->funding_tx, b->funding_tx, b->funding_tx_len) && a->n_participants == b->n_participants &&
             a->n_tiers == b->n_tiers && a->end_height == b->end_height && a->tree_anchors == b->tree_anchors &&
             a->fee_per_tx == b->fee_per_tx && a->lstock_delay == b->lstock_delay && a->n_lstock_hashes == b->n_lstock_hashes &&
             a->fixed_levels == b->fixed_levels && a->k == b->k && a->layer_step == b->layer_step &&
             a->layer_states == b->layer_states && a->has_distribution == (x->in.distribution != NULL) && a->placement == 0 &&
             a->nonces_due_ms == b->nonces_due_ms && a->sigs_due_ms == b->sigs_due_ms &&
             !memcmp(m->round_id, x->round_id, 32) && !memcmp(m->check_id, x->check_id, 32) &&
             !memcmp(m->host_random, x->host_random, 32) && m->has_attempt == x->in.has_attempt && m->attempt == x->in.attempt;
    for (size_t t = 0; ok && t < b->n_tiers; t++) ok = a->tier_sizes[t] == b->tier_sizes[t];
    for (size_t i = 0; ok && i < b->n_participants; i++) ok = !memcmp(&a->participants[i], &b->participants[i], sizeof b->participants[i]);
    return ok;
}

/* Find record `type` in a stream; returns its offset (start of the type) or -1, and its total size. */
static long find_rec(const uint8_t *r, size_t n, uint64_t type, size_t *total, size_t *hdr)
{
    size_t at = 0;
    while (at < n) {
        size_t s = at;
        uint64_t t = r[at] < 0xfd ? r[at++] : (at += 3, (uint64_t)r[at - 2] << 8 | r[at - 1]);
        uint64_t l = r[at] < 0xfd ? r[at++] : (at += 3, (uint64_t)r[at - 2] << 8 | r[at - 1]);
        if (t == type) { *total = at - s + (size_t)l; *hdr = at - s; return (long)s; }
        at += (size_t)l;
    }
    return -1;
}

/* Replace bytes [at, at + cut) of g_buf (length n) by `ins` (k bytes), into g_buf2. */
static size_t splice(size_t n, size_t at, size_t cut, const uint8_t *ins, size_t k)
{
    if (at > n || cut > n - at || k > sizeof g_buf2 - (n - cut)) abort();
    size_t rest = n - at - cut;
    memcpy(g_buf2, g_buf, at);
    if (k) memcpy(g_buf2 + at, ins, k);
    if (rest) memmove(g_buf2 + at + k, g_buf + at + cut, rest);
    return n - cut + k;
}

static void test_propose(void)
{
    static prop_t x;
    gz_rmsg_propose_t *m = calloc(1, sizeof *m);
    for (size_t np = 2; np <= GZ_RMSG_MAX_PARTICIPANTS; np += 15) {
        prop_make(&x, np);
        size_t n = prop_encode(&x, g_buf, sizeof g_buf);
        CHECK(n > 0);
        CHECK(gz_rmsg_propose_decode(g_buf, n, m) == GZ_RMSG_OK && prop_same(m, &x));
        CHECK(m->signed_len == n - 66 && m->sig == g_buf + n - 64);
        if (np == 17) printf("  round_propose with 17 participants: %zu bytes of records\n", n);
    }
    /* optional records present: attempt, distribution, two node hashes */
    prop_make(&x, 4);
    static const uint8_t dist[] = {0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0x51, 0x02};
    x.in.has_attempt = 1; x.in.attempt = 7;
    x.in.distribution = dist; x.in.distribution_len = sizeof dist;
    fill(x.hashes, sizeof x.hashes, 3); x.in.lstock_hashes = x.hashes; x.p.n_lstock_hashes = 2;
    x.p.n_tiers = 2; x.p.tier_sizes[1] = 3;
    size_t n = prop_encode(&x, g_buf, sizeof g_buf);
    CHECK(n && gz_rmsg_propose_decode(g_buf, n, m) == GZ_RMSG_OK && prop_same(m, &x));
    CHECK(m->p.has_distribution && m->distribution_len == sizeof dist && m->lstock_hashes && m->p.n_lstock_hashes == 2);
    /* the encoder refuses what cannot be sent */
    prop_make(&x, 4);
    x.p.funding_script_len = 33; CHECK(gz_rmsg_propose_encode(&x.in, g_buf, sizeof g_buf) == 0);
    prop_make(&x, 4); x.p.funding_tx_len = 59; CHECK(gz_rmsg_propose_encode(&x.in, g_buf, sizeof g_buf) == 0);
    prop_make(&x, 1); CHECK(gz_rmsg_propose_encode(&x.in, g_buf, sizeof g_buf) == 0);
    prop_make(&x, 4); x.p.n_tiers = 9; CHECK(gz_rmsg_propose_encode(&x.in, g_buf, sizeof g_buf) == 0);
    prop_make(&x, 4); CHECK(gz_rmsg_propose_encode(&x.in, g_buf, 100) == 0);              /* short buffer */
    prop_make(&x, GZ_RMSG_MAX_PARTICIPANTS + 1);                                       /* more than this engine holds */
    n = prop_encode(&x, g_buf, sizeof g_buf);
    CHECK(n && gz_rmsg_propose_decode(g_buf, n, m) == GZ_RMSG_E_CAPACITY);

    /* each rule of 4.2 broken in turn, on a clean 4-participant proposal */
    prop_make(&x, 4);
    n = prop_encode(&x, g_buf, sizeof g_buf);
    size_t tot, hdr, k;
    long at;
    static const uint8_t nonmin[] = {0xfd, 0x00, 0x02};                       /* type 2 in three bytes */
    k = splice(n, 0, 1, nonmin, 3);
    CHECK(gz_rmsg_propose_decode(g_buf2, k, m) == GZ_RMSG_E_BIGSIZE);
    static const uint8_t nonmin_len[] = {0x02, 0xfd, 0x00, 0x20};            /* length 32 in three bytes */
    k = splice(n, 0, 2, nonmin_len, 4);
    CHECK(gz_rmsg_propose_decode(g_buf2, k, m) == GZ_RMSG_E_BIGSIZE);
    at = find_rec(g_buf, n, 4, &tot, &hdr);                                    /* record 4 written as a second 2 */
    memcpy(g_buf2, g_buf, n); g_buf2[at] = 2;
    CHECK(gz_rmsg_propose_decode(g_buf2, n, m) == GZ_RMSG_E_ORDER);
    memcpy(g_buf2, g_buf, n); g_buf2[at] = 1;                                  /* decreasing */
    CHECK(gz_rmsg_propose_decode(g_buf2, n, m) == GZ_RMSG_E_ORDER);
    CHECK(gz_rmsg_propose_decode(g_buf, n - 1, m) == GZ_RMSG_E_LENGTH);        /* 240 cut short */
    CHECK(gz_rmsg_propose_decode(g_buf, 0, m) == GZ_RMSG_E_MISSING);           /* empty stream */
    at = find_rec(g_buf, n, 24, &tot, &hdr);                                   /* record 26 (draft 1's placement) */
    static const uint8_t r26[] = {26, 1, 0}, r27[] = {27, 1, 5}, r25[] = {25, 0};
    k = splice(n, (size_t)at + tot, 0, r26, 3);
    CHECK(gz_rmsg_propose_decode(g_buf2, k, m) == GZ_RMSG_E_UNKNOWN_EVEN);
    k = splice(n, (size_t)at + tot, 0, r27, 3);                                /* odd: skipped, and signed over */
    CHECK(gz_rmsg_propose_decode(g_buf2, k, m) == GZ_RMSG_OK && m->signed_len == n - 66 + 3);
    k = splice(n, (size_t)at + tot, 0, r25, 2);                                /* an empty odd record */
    CHECK(gz_rmsg_propose_decode(g_buf2, k, m) == GZ_RMSG_OK);
    static const uint8_t after[] = {0xf1, 0};                                  /* a record after 240 */
    k = splice(n, n, 0, after, 2);
    CHECK(gz_rmsg_propose_decode(g_buf2, k, m) == GZ_RMSG_E_AFTER_SIG);
    CHECK(gz_rmsg_propose_decode(g_buf, n - 66, m) == GZ_RMSG_E_MISSING);      /* no 240 */
    static const uint16_t required[] = {2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 28, 30, 32, 34, 36, 38, 40, 42, 46, 48, 50};
    for (size_t i = 0; i < sizeof required / sizeof required[0]; i++) {
        at = find_rec(g_buf, n, required[i], &tot, &hdr);
        CHECK(at >= 0);
        k = splice(n, (size_t)at, tot, NULL, 0);
        gz_rmsg_err_t e = gz_rmsg_propose_decode(g_buf2, k, m);
        if (e != GZ_RMSG_E_MISSING) printf("  record %u removed: %d\n", required[i], (int)e);
        CHECK(e == GZ_RMSG_E_MISSING);
    }
    /* fixed sizes one short and one long; lists one byte off and over their bounds */
    static const struct { uint16_t type; int fixed; } sized[] = {{2, 1}, {4, 1}, {6, 1}, {8, 1}, {10, 1}, {12, 1}, {14, 1},
        {16, 1}, {24, 1}, {28, 1}, {30, 1}, {32, 1}, {36, 1}, {38, 1}, {40, 1}, {42, 1}, {46, 1}, {48, 1}, {50, 1},
        {20, 0}, {22, 0}, {34, 0}, {240, 1}};
    for (size_t i = 0; i < sizeof sized / sizeof sized[0]; i++)
        for (int d = -1; d <= 1; d += 2) {
            at = find_rec(g_buf, n, sized[i].type, &tot, &hdr);
            size_t vlen = tot - hdr;
            if (d < 0 && vlen == 0) continue;
            if (hdr != 2 || vlen + (size_t)d >= 0xfd) continue;                /* one-byte lengths only, here */
            memcpy(g_buf2, g_buf, n);
            uint8_t extra = 0;
            if (d > 0) { k = splice(n, (size_t)at + tot, 0, &extra, 1); }
            else { k = splice(n, (size_t)at + tot - 1, 1, NULL, 0); }
            g_buf2[at + 1] = (uint8_t)(vlen + (size_t)d);
            gz_rmsg_err_t e = gz_rmsg_propose_decode(g_buf2, k, m);
            if (e != GZ_RMSG_E_SIZE) printf("  record %u %+d byte: %d\n", sized[i].type, d, (int)e);
            CHECK(e == GZ_RMSG_E_SIZE);
        }
    prop_make(&x, 4); x.p.n_tiers = 8;                                         /* tier list at its bound: accepted */
    n = prop_encode(&x, g_buf, sizeof g_buf);
    CHECK(gz_rmsg_propose_decode(g_buf, n, m) == GZ_RMSG_OK && m->p.n_tiers == 8);
    at = find_rec(g_buf, n, 22, &tot, &hdr);                                   /* nine entries: refused */
    static const uint8_t four[4] = {0};
    k = splice(n, (size_t)at + tot, 0, four, 4); g_buf2[at + 1] = 36;
    CHECK(gz_rmsg_propose_decode(g_buf2, k, m) == GZ_RMSG_E_SIZE);
    /* distribution: outputs malformed */
    prop_make(&x, 4);
    static const uint8_t bad_dist[] = {0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 35};
    x.in.distribution = bad_dist; x.in.distribution_len = sizeof bad_dist;
    CHECK(gz_rmsg_propose_encode(&x.in, g_buf, sizeof g_buf) == 0);
    x.in.distribution = NULL;
    n = prop_encode(&x, g_buf, sizeof g_buf);
    at = find_rec(g_buf, n, 42, &tot, &hdr);
    static const uint8_t r44[] = {44, 13, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 34};   /* script length 34, no script */
    k = splice(n, (size_t)at + tot, 0, r44, sizeof r44);
    CHECK(gz_rmsg_propose_decode(g_buf2, k, m) == GZ_RMSG_E_VALUE);
    free(m);
}

/* ---- the other kinds ---- */

static size_t sig240(gz_rmsg_wr_t *w)
{
    uint8_t sig[64];
    fill(sig, 64, 5);
    gz_rmsg_put(w, 240, sig, 64);
    return gz_rmsg_wr_ok(w) ? w->n : 0;
}

static void test_kinds(void)
{
    uint8_t id[32], e134[134 * 3], e68[68 * 2], held[32];
    fill(id, 32, 1); fill(e134, sizeof e134, 2); fill(e68, sizeof e68, 3); fill(held, 32, 4);
    uint8_t tier = 0;
    gz_rmsg_wr_t w;
    size_t n;

    gz_rmsg_nonces_t mn;
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, &tier, 1); gz_rmsg_put(&w, 6, e134, sizeof e134);
    n = w.n;
    CHECK(gz_rmsg_nonces_decode(g_buf, n, &mn) == GZ_RMSG_OK && mn.n == 3 && memcmp(mn.entries, e134, sizeof e134) == 0 && mn.tier == 0);
    CHECK(gz_rmsg_nonces_decode(g_buf, sig240(&w), &mn) == GZ_RMSG_E_UNKNOWN_EVEN);   /* unsigned kind: 240 is unknown */
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, &tier, 1); gz_rmsg_put(&w, 6, e134, 133);
    CHECK(gz_rmsg_nonces_decode(g_buf, w.n, &mn) == GZ_RMSG_E_SIZE);
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, &tier, 1); gz_rmsg_put(&w, 6, e134, 0);
    CHECK(gz_rmsg_nonces_decode(g_buf, w.n, &mn) == GZ_RMSG_E_SIZE);              /* at least one entry */

    /* all_nonces: two items of 2 and 3 signers */
    static uint8_t blk[2 * 6 + 5 * 130];
    size_t b = 0;
    for (int it = 0; it < 2; it++) {
        uint16_t k = (uint16_t)(2 + it);
        blk[b] = 0; blk[b + 1] = 0; blk[b + 2] = 0; blk[b + 3] = (uint8_t)it; blk[b + 4] = 0; blk[b + 5] = (uint8_t)k;
        fill(blk + b + 6, 130u * k, (uint8_t)it);
        b += 6 + 130u * k;
    }
    gz_rmsg_all_nonces_t ma;
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, &tier, 1); gz_rmsg_put(&w, 6, blk, b);
    CHECK(gz_rmsg_all_nonces_decode(g_buf, w.n, &ma) == GZ_RMSG_OK && ma.n == 2 && ma.n_signers[0] == 2 && ma.n_signers[1] == 3);
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, &tier, 1); gz_rmsg_put(&w, 6, blk, b - 1);
    CHECK(gz_rmsg_all_nonces_decode(g_buf, w.n, &ma) == GZ_RMSG_E_VALUE);         /* the last block cut */
    blk[5] = 0;
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, &tier, 1); gz_rmsg_put(&w, 6, blk, b);
    CHECK(gz_rmsg_all_nonces_decode(g_buf, w.n, &ma) == GZ_RMSG_E_VALUE);         /* zero signers */
    /* Review B, mutant C73: 256 entries (the bound of messages.md and of the view's lists) are read;
     * a 257th, which fits one envelope (257 entries of one signer are 34,952 bytes), is refused
     * before it is written past the lists. */
    {
        static uint8_t many[257 * 136];
        static struct { gz_rmsg_all_nonces_t m; uint8_t after[64]; } v;
        for (size_t i = 0; i < 257; i++) {
            uint8_t *q = many + 136 * i;
            q[0] = 0; q[1] = 0; q[2] = (uint8_t)(i >> 8); q[3] = (uint8_t)i; q[4] = 0; q[5] = 1;
            fill(q + 6, 130, (uint8_t)i);
        }
        memset(&v, 0x5a, sizeof v);
        gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
        gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, &tier, 1); gz_rmsg_put(&w, 6, many, 256 * 136);
        CHECK(gz_rmsg_wr_ok(&w) && gz_rmsg_all_nonces_decode(g_buf, w.n, &v.m) == GZ_RMSG_OK && v.m.n == 256 && v.m.item[255] != NULL);
        gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
        gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, &tier, 1); gz_rmsg_put(&w, 6, many, 257 * 136);
        CHECK(gz_rmsg_wr_ok(&w) && w.n <= GZ_RMSG_MAX_RECORDS_ONE);
        CHECK(gz_rmsg_all_nonces_decode(g_buf, w.n, &v.m) == GZ_RMSG_E_VALUE && v.m.n == 0);
        for (size_t i = 0; i < sizeof v.after; i++) CHECK(v.after[i] == 0x5a);
    }

    gz_rmsg_list68_t ml;
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, &tier, 1); gz_rmsg_put(&w, 6, e68, sizeof e68);
    size_t unsigned_len = w.n;
    n = sig240(&w);
    CHECK(gz_rmsg_partial_sigs_decode(g_buf, n, &ml) == GZ_RMSG_OK && ml.n == 2 && ml.signed_len == unsigned_len);
    CHECK(gz_rmsg_tier_result_decode(g_buf, unsigned_len, &ml) == GZ_RMSG_E_MISSING);

    gz_rmsg_small_t ms;
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 3, held, 5); gz_rmsg_put(&w, 5, held, 0);   /* payouts, penalties: odd */
    n = sig240(&w);
    CHECK(gz_rmsg_complete_decode(g_buf, n, &ms) == GZ_RMSG_OK && ms.signed_len == n - 66);
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, held, 32);
    n = sig240(&w);
    CHECK(gz_rmsg_ack_decode(g_buf, n, &ms) == GZ_RMSG_OK && ms.held_digest == g_buf + 36);
    CHECK(gz_rmsg_complete_decode(g_buf, n, &ms) == GZ_RMSG_E_UNKNOWN_EVEN);       /* 4 is not complete's */
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32);
    CHECK(gz_rmsg_status_decode(g_buf, w.n, &ms) == GZ_RMSG_OK && ms.round_id == g_buf + 2);
    CHECK(gz_rmsg_funded_decode(g_buf, w.n, &ms) == GZ_RMSG_OK && ms.funding_txid == g_buf + 2);
    CHECK(gz_rmsg_status_decode(g_buf, sig240(&w), &ms) == GZ_RMSG_E_UNKNOWN_EVEN);

    gz_rmsg_abort_t mb;
    uint8_t reason[2] = {0, 12}, items[8] = {0, 0, 0, 1, 0, 0, 0, 2};
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, reason, 2); gz_rmsg_put(&w, 5, held, 3);
    gz_rmsg_put(&w, 7, "no key", 6); gz_rmsg_put(&w, 9, &tier, 1); gz_rmsg_put(&w, 11, items, 8);
    n = sig240(&w);
    CHECK(gz_rmsg_abort_decode(g_buf, n, &mb) == GZ_RMSG_OK && mb.reason == 12 && mb.detail_len == 6 &&
          mb.has_tier && mb.n_items == 2);
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 2, id, 32); gz_rmsg_put(&w, 4, reason, 2); gz_rmsg_put(&w, 7, "\x01", 1);
    CHECK(gz_rmsg_abort_decode(g_buf, sig240(&w), &mb) == GZ_RMSG_E_VALUE);       /* detail not printable ASCII */

    /* the writer refuses types out of order */
    gz_rmsg_wr_init(&w, g_buf, sizeof g_buf);
    gz_rmsg_put(&w, 4, id, 1); gz_rmsg_put(&w, 2, id, 1);
    CHECK(!gz_rmsg_wr_ok(&w));
}

/* ---- the hashes, against a direct computation ---- */
static void test_hashes(void)
{
    uint8_t id[32], nonce[66], a[32], b[32], pre[32 + 1 + 4 + 66];
    fill(id, 32, 1); fill(nonce, 66, 2);
    gz_rmsg_nonce_hash(id, 3, 0x01020304u, nonce, a);
    memcpy(pre, id, 32); pre[32] = 3; pre[33] = 1; pre[34] = 2; pre[35] = 3; pre[36] = 4; memcpy(pre + 37, nonce, 66);
    gz_sign_sha256_t s;
    gz_sign_tagged_init(&s, "gazpacho/nonce"); gz_sign_sha256_write(&s, pre, sizeof pre); gz_sign_sha256_done(&s, b);
    CHECK(memcmp(a, b, 32) == 0);
    uint8_t finals[2][64];
    uint32_t idx[2] = {0, 5};
    fill(finals[0], 128, 3);
    gz_rmsg_held_hash(idx, (const uint8_t (*)[64])finals, 2, a);
    uint8_t h[2 * 68] = {0};
    h[3] = 0; memcpy(h + 4, finals[0], 64); h[68 + 3] = 5; memcpy(h + 72, finals[1], 64);
    gz_sign_tagged_init(&s, "gazpacho/held"); gz_sign_sha256_write(&s, h, sizeof h); gz_sign_sha256_done(&s, b);
    CHECK(memcmp(a, b, 32) == 0);
}

/* Write a valid round_propose (4 participants), selector byte first, as a
 * seed for the fuzz target: usage test_round_msg --seed FILE. */
static int write_seed(const char *path)
{
    static prop_t x;
    prop_make(&x, 4);
    size_t n = prop_encode(&x, g_buf + 1, sizeof g_buf - 1);
    g_buf[0] = 0;
    FILE *f = fopen(path, "wb");
    if (!f || !n || fwrite(g_buf, 1, n + 1, f) != n + 1) return 1;
    return fclose(f) != 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--seed") == 0) return write_seed(argv[2]);
    test_m1();
    test_propose();
    test_kinds();
    test_hashes();
    return check_done();
}
