/* Exact tests of the engine's readers: SHA-256 against OpenSSL, the
 * transaction reader at every boundary, attaching and verifying, and the
 * message decoder for every kind at its limits. Included by test_signing.c. */
#ifndef GZ_TEST_SIGNING_DECODERS_H
#define GZ_TEST_SIGNING_DECODERS_H

#include "scenarios.h"
#include <openssl/sha.h>

static void test_sha256(void)
{
    static uint8_t data[2048];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i * 131 + 7);
    int bad = 0;
    for (size_t len = 0; len <= 300; len++) {
        uint8_t want[32], got[32];
        SHA256(data, len, want);
        for (size_t split = 0; split <= len; split += len / 7 + 1) {        /* in two writes, at many places */
            gz_sign_sha256_t s;
            gz_sign_sha256_init(&s);
            gz_sign_sha256_write(&s, data, split);
            gz_sign_sha256_write(&s, data + split, len - split);
            gz_sign_sha256_done(&s, got);
            bad += memcmp(got, want, 32) != 0;
            for (size_t b = 0; b < sizeof s; b++) bad += ((uint8_t *)&s)[b] != 0;   /* the state is wiped */
        }
    }
    uint8_t want[32], got[32];
    gz_sign_sha256_t s;
    SHA256(data, sizeof data, want);
    gz_sign_sha256_init(&s);
    for (size_t at = 0; at < sizeof data; at += 1 + at % 70) gz_sign_sha256_write(&s, data + at, (at + 1 + at % 70 > sizeof data ? sizeof data : at + 1 + at % 70) - at);
    gz_sign_sha256_done(&s, got);
    bad += memcmp(got, want, 32) != 0;
    CHECK(bad == 0);
}

/* Build a transaction: version 2, one input, the given outputs, a witness if `witness_len` >= 0. */
typedef struct { uint8_t b[110000]; size_t n; } txb_t;
static void tb(txb_t *t, const void *d, size_t n) { memcpy(t->b + t->n, d, n); t->n += n; }
static void tb8(txb_t *t, uint8_t v) { tb(t, &v, 1); }
static void tbvar(txb_t *t, uint64_t v, int width)                     /* width: 1, 3, 5 or 9 bytes, as asked */
{
    if (width == 1) { tb8(t, (uint8_t)v); return; }
    tb8(t, width == 3 ? 0xfd : width == 5 ? 0xfe : 0xff);
    for (int i = 0; i < width - 1; i++) tb8(t, (uint8_t)(v >> (8 * i)));
}
static void tx_build(txb_t *t, int segwit, uint64_t n_out, size_t script_len, int script_width, int witness_items, size_t witness_len)
{
    static const uint8_t ver[4] = {2, 0, 0, 0}, outpoint[36] = {0x11}, seq[4] = {0xfe, 0xff, 0xff, 0xff}, lock[4] = {0};
    t->n = 0;
    tb(t, ver, 4);
    if (segwit) { tb8(t, 0); tb8(t, 1); }
    tb8(t, 1); tb(t, outpoint, 36); tb8(t, 0); tb(t, seq, 4);
    tbvar(t, n_out, n_out < 0xfd ? 1 : 3);
    for (uint64_t o = 0; o < n_out; o++) {
        uint8_t amt[8] = {(uint8_t)o};
        tb(t, amt, 8);
        size_t sl = o == 0 ? script_len : 0;
        tbvar(t, sl, o == 0 ? script_width : 1);
        memset(t->b + t->n, 0x51, sl); t->n += sl;
    }
    if (segwit) {
        tb8(t, (uint8_t)witness_items);
        for (int w = 0; w < witness_items; w++) { tb8(t, (uint8_t)witness_len); memset(t->b + t->n, 0x22, witness_len); t->n += witness_len; }
    }
    tb(t, lock, 4);
}

static const uint8_t *d_point(void)
{
    static uint8_t x[32];
    uint8_t sk[32];
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xo;
    w_secret("test/factory", 0, sk);
    if (!secp256k1_keypair_create(w_ctx(), &kp, sk) || !secp256k1_keypair_xonly_pub(w_ctx(), &xo, NULL, &kp) ||
        !secp256k1_xonly_pubkey_serialize(w_ctx(), x, &xo)) abort();
    return x;
}

static void test_tx_reader(void)
{
    static txb_t t;
    gz_sign_tx_t tx;
    int bad = 0;
    /* the plain forms, and every cut of them refused, and a byte more refused */
    for (int segwit = 0; segwit <= 1; segwit++) {
        tx_build(&t, segwit, 2, 34, 1, 1, 64);
        CHECK(gz_sign_tx_parse(t.b, t.n, &tx));
        CHECK(tx.outpoint == t.b + (segwit ? 7 : 5) && tx.sequence == tx.outpoint + 37 && tx.outputs_at == (size_t)(tx.outpoint - t.b) + 41 + 1);
        CHECK(segwit ? tx.witness_item == t.b + t.n - 4 - 64 && tx.witness_len == 64 : tx.witness_item == NULL);
        CHECK(tx.outputs_end == tx.outputs_at + 8 + 1 + 34 + 8 + 1);
        for (size_t cut = 0; cut < t.n; cut++) bad += gz_sign_tx_parse(t.b, cut, &tx);
        t.b[t.n] = 0;
        bad += gz_sign_tx_parse(t.b, t.n + 1, &tx);
    }
    CHECK(bad == 0);
    /* the flag after a zero marker must be 1 */
    tx_build(&t, 1, 1, 0, 1, 1, 64); t.b[5] = 2; CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));
    /* inputs: exactly one; its script: empty */
    tx_build(&t, 0, 1, 0, 1, 0, 0); t.b[4] = 2; CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));
    tx_build(&t, 0, 1, 0, 1, 0, 0); t.b[41] = 1; CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));
    /* outputs: at least one, at most 1000 */
    tx_build(&t, 0, 0, 0, 1, 0, 0); CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));
    tx_build(&t, 0, 1000, 0, 1, 0, 0); CHECK(gz_sign_tx_parse(t.b, t.n, &tx));
    tx_build(&t, 0, 1001, 0, 1, 0, 0); CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));
    /* compact sizes: the shortest form only */
    tx_build(&t, 0, 1, 252, 3, 0, 0); CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));
    tx_build(&t, 0, 1, 253, 3, 0, 0); CHECK(gz_sign_tx_parse(t.b, t.n, &tx));
    tx_build(&t, 0, 1, 253, 1, 0, 0); CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));      /* one byte 0xfd: a prefix, then too short */
    tx_build(&t, 0, 1, 0xffff, 5, 0, 0); CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));
    tx_build(&t, 0, 1, 0x10000, 5, 0, 0); CHECK(gz_sign_tx_parse(t.b, t.n, &tx));
    tx_build(&t, 0, 1, 0x10000, 9, 0, 0); CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));   /* below 2^32 in nine bytes */
    /* a script longer than what is left */
    tx_build(&t, 0, 1, 34, 1, 0, 0); t.b[47 + 8] = 35; CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));
    /* the whole size: up to 100,000 bytes */
    tx_build(&t, 0, 1, 0, 5, 0, 0);
    size_t base = t.n;
    tx_build(&t, 0, 1, 100000 - base, 5, 0, 0); CHECK(t.n == 100000 && gz_sign_tx_parse(t.b, t.n, &tx));
    tx_build(&t, 0, 1, 100001 - base, 5, 0, 0); CHECK(t.n == 100001 && !gz_sign_tx_parse(t.b, t.n, &tx));
    /* witness: exactly one item, within the bytes */
    tx_build(&t, 1, 1, 0, 1, 2, 64); CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));
    tx_build(&t, 1, 1, 0, 1, 0, 0); CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));
    tx_build(&t, 1, 1, 0, 1, 1, 64); t.b[t.n - 4 - 64 - 1] = 69; CHECK(!gz_sign_tx_parse(t.b, t.n, &tx));
    /* attach: only to a transaction without a witness, only with room for it */
    tx_build(&t, 0, 2, 34, 1, 0, 0);
    uint8_t out[300], sig[64] = {7};
    CHECK(gz_sign_tx_attach(t.b, t.n, sig, out, t.n + 68) == t.n + 68);
    CHECK(gz_sign_tx_attach(t.b, t.n, sig, out, t.n + 67) == 0);
    CHECK(gz_sign_tx_parse(out, t.n + 68, &tx) && tx.witness_len == 64 && memcmp(tx.witness_item, sig, 64) == 0);
    CHECK(gz_sign_tx_attach(out, t.n + 68, sig, out + 150, 150) == 0);
    CHECK(gz_sign_tx_attach(t.b, t.n - 1, sig, out, sizeof out) == 0);
    /* verify: a key-path output script, a 64-byte item */
    uint8_t script[34] = {0x51, 0x20};
    memcpy(script + 2, d_point(), 32);
    tx_build(&t, 1, 1, 0, 1, 1, 64);
    CHECK(!gz_sign_tx_verify(w_ctx(), t.b, t.n, 1000, script));          /* a wrong signature */
    tx_build(&t, 1, 1, 0, 1, 1, 65);
    CHECK(!gz_sign_tx_verify(w_ctx(), t.b, t.n, 1000, script));
}

/* A message of `kind` with n entries of `each` bytes (index i in the first four), signed if `sig`. */
static size_t msg_build(uint8_t *b, uint8_t kind, uint16_t n, size_t each, int sig, uint8_t k)
{
    size_t at = 0;
    b[at++] = 'G'; b[at++] = 'S'; b[at++] = kind;
    memset(b + at, 0x33, 32); at += 32;
    if (kind == GZ_SIGN_MSG_ABORT) b[at++] = 4;
    b[at++] = 0; b[at++] = (uint8_t)(n >> 8); b[at++] = (uint8_t)n;
    for (uint16_t i = 0; i < n; i++) {
        size_t e = kind == GZ_SIGN_MSG_ALL_NONCES ? 5 + (size_t)k * 130 : each;
        memset(b + at, 0, e);
        b[at + 3] = (uint8_t)i;
        if (kind == GZ_SIGN_MSG_ALL_NONCES) b[at + 4] = k;
        at += e;
    }
    if (sig) { memset(b + at, 0x44, 64); at += 64; }
    return at;
}

static void test_decoder(void)
{
    static uint8_t b[GZ_SIGN_MAX_MSG + 200];
    gz_sign_msg_t m;
    int bad = 0;
    /* every kind with entries: at its limit accepted, past it refused, every cut and a byte more refused */
    static const struct { uint8_t kind; size_t each; int sig; } k[] = {
        {GZ_SIGN_MSG_NONCES, 134, 0}, {GZ_SIGN_MSG_ALL_NONCES, 0, 0}, {GZ_SIGN_MSG_PARTIALS, 68, 1}, {GZ_SIGN_MSG_RESULT, 68, 1}, {GZ_SIGN_MSG_ABORT, 4, 1}};
    for (size_t c = 0; c < 5; c++) {
        uint8_t signers = k[c].kind == GZ_SIGN_MSG_ALL_NONCES ? 3 : 0;
        size_t len = msg_build(b, k[c].kind, 2, k[c].each, k[c].sig, signers);
        CHECK(gz_sign_decode(b, len, &m) && m.kind == k[c].kind && m.n == 2 && m.tier == 0);
        CHECK(m.entry[0] == b + 35 + (k[c].kind == GZ_SIGN_MSG_ABORT) + 3);
        CHECK(m.signed_len == len - (k[c].sig ? 64u : 0u) && (k[c].sig ? m.sig == b + len - 64 : m.sig == NULL));
        if (k[c].kind == GZ_SIGN_MSG_ABORT) CHECK(m.reason == 4);
        for (size_t cut = 0; cut < len; cut++) bad += gz_sign_decode(b, cut, &m);
        b[len] = 0;
        bad += gz_sign_decode(b, len + 1, &m);
        len = msg_build(b, k[c].kind, GZ_SIGN_MAX_ITEMS, k[c].each, k[c].sig, signers);
        CHECK(gz_sign_decode(b, len, &m) && m.n == GZ_SIGN_MAX_ITEMS);
        len = msg_build(b, k[c].kind, GZ_SIGN_MAX_ITEMS + 1, k[c].each, k[c].sig, signers);
        CHECK(!gz_sign_decode(b, len, &m));
        len = msg_build(b, k[c].kind, 1, k[c].each, k[c].sig, signers);
        b[35 + (k[c].kind == GZ_SIGN_MSG_ABORT) + 3 + 3] = GZ_SIGN_MAX_ITEMS - 1;
        CHECK(gz_sign_decode(b, len, &m));
        b[35 + (k[c].kind == GZ_SIGN_MSG_ABORT) + 3 + 3] = GZ_SIGN_MAX_ITEMS;      /* an index past the limit */
        CHECK(!gz_sign_decode(b, len, &m));
    }
    CHECK(bad == 0);
    /* signers per item in a nonce set: 16 accepted, 17 refused */
    size_t len = msg_build(b, GZ_SIGN_MSG_ALL_NONCES, 1, 0, 0, GZ_SIGN_MAX_SIGNERS);
    CHECK(gz_sign_decode(b, len, &m) && m.entry[0][4] == GZ_SIGN_MAX_SIGNERS);
    len = msg_build(b, GZ_SIGN_MSG_ALL_NONCES, 1, 0, 0, GZ_SIGN_MAX_SIGNERS + 1);
    CHECK(!gz_sign_decode(b, len, &m));
    /* the kinds without entries */
    uint8_t p[35 + 34 + GZ_SIGN_MAX_PARAMS + 1 + 64];
    static const size_t plens[] = {0, 1, GZ_SIGN_MAX_PARAMS, GZ_SIGN_MAX_PARAMS + 1};
    for (size_t pi = 0; pi < 4; pi++) {
        size_t plen = plens[pi];
        size_t n = 0;
        p[n++] = 'G'; p[n++] = 'S'; p[n++] = GZ_SIGN_MSG_PROPOSE;
        memset(p + n, 1, 32 + 32); n += 64;
        p[n++] = (uint8_t)(plen >> 8); p[n++] = (uint8_t)plen;
        memset(p + n, 2, plen + 64); n += plen + 64;
        int ok = gz_sign_decode(p, n, &m);
        CHECK(ok == (plen <= GZ_SIGN_MAX_PARAMS));
        if (ok) {
            CHECK(m.host_random == p + 35 && m.params == p + 69 && m.params_len == plen && m.signed_len == 69 + plen && m.sig == p + 69 + plen);
            for (size_t cut = 0; cut < n; cut++) bad += gz_sign_decode(p, cut, &m);
            bad += gz_sign_decode(p, n + 1, &m);
        }
    }
    uint8_t c[35 + 32 + 64 + 1];
    memset(c, 9, sizeof c);
    c[0] = 'G'; c[1] = 'S';
    c[2] = GZ_SIGN_MSG_COMPLETE; CHECK(gz_sign_decode(c, 99, &m) && m.signed_len == 35 && m.sig == c + 35);
    CHECK(!gz_sign_decode(c, 98, &m) && !gz_sign_decode(c, 100, &m));
    c[2] = GZ_SIGN_MSG_ACK; CHECK(gz_sign_decode(c, 131, &m) && m.held == c + 35 && m.signed_len == 67);
    CHECK(!gz_sign_decode(c, 130, &m) && !gz_sign_decode(c, 66, &m) && !gz_sign_decode(c, 132, &m));
    c[2] = GZ_SIGN_MSG_STATUS; CHECK(gz_sign_decode(c, 35, &m) && !gz_sign_decode(c, 36, &m) && !gz_sign_decode(c, 34, &m));
    for (int kind = 0; kind < 256; kind++) {                        /* exactly nine kinds */
        c[2] = (uint8_t)kind;
        int any = gz_sign_decode(c, 35, &m) || gz_sign_decode(c, 99, &m) || gz_sign_decode(c, 131, &m);
        bad += any != (kind == GZ_SIGN_MSG_STATUS || kind == GZ_SIGN_MSG_COMPLETE || kind == GZ_SIGN_MSG_ACK);
    }
    c[2] = GZ_SIGN_MSG_STATUS; c[0] = 'g'; CHECK(!gz_sign_decode(c, 35, &m));
    c[0] = 'G'; c[1] = 's'; CHECK(!gz_sign_decode(c, 35, &m));
    CHECK(bad == 0);
    /* an abort with no room for its reason, and a message too long for any kind */
    len = msg_build(b, GZ_SIGN_MSG_ABORT, 0, 4, 1, 0);
    CHECK(gz_sign_decode(b, len, &m) && !gz_sign_decode(b, 35, &m) && !gz_sign_decode(b, 36, &m));
    len = msg_build(b, GZ_SIGN_MSG_ALL_NONCES, GZ_SIGN_MAX_ITEMS, 0, 0, GZ_SIGN_MAX_SIGNERS);
    CHECK(gz_sign_decode(b, len, &m) && len <= GZ_SIGN_MAX_MSG);
    CHECK(!gz_sign_decode(b, GZ_SIGN_MAX_MSG + 1, &m));
}

#endif
