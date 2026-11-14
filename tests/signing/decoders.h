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

/* A list message of `kind` with n entries of `each` bytes (index i in the first four), signed if `sig`. */
static size_t msg_build(uint8_t *b, uint16_t kind, uint16_t n, size_t each, int sig, uint16_t k)
{
    static uint8_t v[GZ_SIGN_MAX_MSG];
    uint8_t id[32], tier = 0;
    size_t at = 0;
    memset(id, 0x11, 32);
    for (uint16_t i = 0; i < n; i++) {
        size_t e = kind == GZ_SIGN_MSG_ALL_NONCES ? 6 + (size_t)k * 130 : each;
        memset(v + at, 0, e);
        v[at] = (uint8_t)(i >> 24); v[at + 1] = (uint8_t)(i >> 16); v[at + 2] = (uint8_t)(i >> 8); v[at + 3] = (uint8_t)i;
        if (kind == GZ_SIGN_MSG_ALL_NONCES) { v[at + 4] = (uint8_t)(k >> 8); v[at + 5] = (uint8_t)k; }
        at += e;
    }
    w_rec_t recs[3] = {{2, id, 32}, {4, &tier, 1}, {6, v, at}};
    return w_message(b, GZ_SIGN_MAX_MSG + 64, kind, recs, 3, sig ? 1 : -1);
}

/* gz_sign_decode: one view of round_msg.h's decoders. The codecs themselves
 * are tested in test_round_msg (every rule of messages.md 4.2 in turn); here,
 * that the view points where the decoders say, and refuses what they refuse. */
static void test_decoder(void)
{
    static uint8_t b[GZ_SIGN_MAX_MSG + 64];
    gz_sign_msg_t m;
    static const struct { uint16_t kind; size_t each; int sig; } k[] = {
        {GZ_SIGN_MSG_NONCES, 134, 0}, {GZ_SIGN_MSG_ALL_NONCES, 0, 0}, {GZ_SIGN_MSG_PARTIALS, 68, 1}, {GZ_SIGN_MSG_RESULT, 68, 1}};
    for (size_t c = 0; c < sizeof k / sizeof k[0]; c++) {
        size_t len = msg_build(b, k[c].kind, 2, k[c].each, k[c].sig, 3), bad = 0;
        CHECK(gz_sign_decode(b, len, &m) && m.kind == k[c].kind && m.n == 2 && m.tier == 0 && m.has_tier);
        CHECK(m.round_id == b + GZ_RMSG_HEADER + 2 && m.entry[0] == b + GZ_RMSG_HEADER + 34 + 3 + 2 + (2 * (k[c].kind == GZ_SIGN_MSG_ALL_NONCES ? 6 + 3 * 130 : k[c].each) >= 0xfd ? 2 : 0));
        CHECK(k[c].sig ? m.sig == b + len - 64 && m.signed_len == len - GZ_RMSG_HEADER - 66 : m.sig == NULL && m.signed_len == len - GZ_RMSG_HEADER);
        for (size_t cut = 0; cut < len; cut++) bad += gz_sign_decode(b, cut, &m);
        CHECK(bad == 0);
        b[0] ^= 1; CHECK(!gz_sign_decode(b, len, &m)); b[0] ^= 1;           /* another protocol */
        b[5] = 65; CHECK(!gz_sign_decode(b, len, &m)); b[5] = (uint8_t)k[c].kind;   /* an odd kind this engine does not know */
    }
    /* the largest a member's nonce set may be, and one past the decoder's bound */
    size_t len = msg_build(b, GZ_SIGN_MSG_ALL_NONCES, GZ_SIGN_MAX_ITEMS, 0, 0, GZ_SIGN_MAX_SIGNERS);
    CHECK(gz_sign_decode(b, len, &m) && m.n == GZ_SIGN_MAX_ITEMS && len <= GZ_SIGN_MAX_MSG);
    CHECK(m.entry[0][4] == 0 && m.entry[0][5] == GZ_SIGN_MAX_SIGNERS);
    /* the small kinds */
    uint8_t id[32], held[32], r2[2] = {0, 4}, z = 0;
    memset(id, 0x22, 32); memset(held, 0x33, 32);
    w_rec_t cr[1] = {{2, id, 32}}, ar[2] = {{2, id, 32}, {4, held, 32}}, br[2] = {{2, id, 32}, {4, r2, 2}};
    len = w_message(b, sizeof b, GZ_SIGN_MSG_COMPLETE, cr, 1, 0);
    CHECK(gz_sign_decode(b, len, &m) && m.kind == GZ_SIGN_MSG_COMPLETE && m.round_id == b + 40 && m.sig == b + len - 64 && m.signed_len == 34);
    len = w_message(b, sizeof b, GZ_SIGN_MSG_ACK, ar, 2, 1);
    CHECK(gz_sign_decode(b, len, &m) && m.held == b + 40 + 34 && m.signed_len == 68);
    len = w_message(b, sizeof b, GZ_SIGN_MSG_STATUS, cr, 1, -1);
    CHECK(gz_sign_decode(b, len, &m) && m.kind == GZ_SIGN_MSG_STATUS && m.sig == NULL);
    len = w_message(b, sizeof b, GZ_SIGN_MSG_STATUS, cr, 1, 0);
    CHECK(!gz_sign_decode(b, len, &m));                                    /* 240 in an unsigned kind */
    len = w_message(b, sizeof b, GZ_SIGN_MSG_ABORT, br, 2, 0);
    CHECK(gz_sign_decode(b, len, &m) && m.reason == 4 && !m.has_tier && m.n == 0);
    len = w_message(b, sizeof b, GZ_SIGN_MSG_ABORT, br, 2, -1);
    CHECK(!gz_sign_decode(b, len, &m));                                    /* a signed kind without 240 */
    len = w_message(b, sizeof b, GZ_SIGN_MSG_FUNDED, cr, 1, -1);
    CHECK(gz_sign_decode(b, len, &m) && m.held == b + 40 && m.round_id == NULL);
    /* a proposal: only its identifier is read here */
    len = w_message(b, sizeof b, GZ_SIGN_MSG_PROPOSE, cr, 1, -1);
    CHECK(gz_sign_decode(b, len, &m) && m.round_id == b + 40);
    w_rec_t pr[1] = {{4, id, 32}};
    len = w_message(b, sizeof b, GZ_SIGN_MSG_PROPOSE, pr, 1, -1);
    CHECK(!gz_sign_decode(b, len, &m));                                    /* record 2 is not first */
    (void)z;
}

#endif
