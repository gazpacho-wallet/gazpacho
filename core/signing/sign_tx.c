/* SHA-256, tagged hashes, and reading the transactions the engine signs.
 * Everything here reads only the bytes it is given, within their length. */
#include "gazpacho/signing.h"
#include <secp256k1_schnorrsig.h>
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR(x, n) ((x) >> (n) | (x) << (32 - (n)))

static void block(uint32_t h[8], const uint8_t p[64])
{
    uint32_t w[64], a[8];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    memcpy(a, h, sizeof a);
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = a[7] + (ROR(a[4], 6) ^ ROR(a[4], 11) ^ ROR(a[4], 25)) + ((a[4] & a[5]) ^ (~a[4] & a[6])) + K[i] + w[i];
        uint32_t t2 = (ROR(a[0], 2) ^ ROR(a[0], 13) ^ ROR(a[0], 22)) + ((a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]));
        memmove(a + 1, a, 7 * sizeof a[0]);
        a[4] += t1;
        a[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++) h[i] += a[i];
}

void gz_sign_sha256_init(gz_sign_sha256_t *s)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(s->h, iv, sizeof iv);
    s->n = 0;
}

void gz_sign_sha256_write(gz_sign_sha256_t *s, const uint8_t *data, size_t len)
{
    while (len) {
        size_t at = (size_t)(s->n % 64), take = 64 - at < len ? 64 - at : len;
        memcpy(s->buf + at, data, take);
        s->n += take; data += take; len -= take;
        if (s->n % 64 == 0) block(s->h, s->buf);
    }
}

void gz_sign_sha256_done(gz_sign_sha256_t *s, uint8_t out[32])
{
    uint8_t pad[72] = {0x80};
    uint64_t bits = s->n * 8;
    size_t padlen = 64 - (size_t)((s->n + 8) % 64);
    for (int i = 0; i < 8; i++) pad[padlen + (size_t)i] = (uint8_t)(bits >> (56 - 8 * i));
    gz_sign_sha256_write(s, pad, padlen + 8);
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(s->h[i / 4] >> (24 - 8 * (i % 4)));
    memset(s, 0, sizeof *s);
}

void gz_sign_tagged_init(gz_sign_sha256_t *s, const char *tag)
{
    uint8_t th[32];
    size_t n = 0;
    while (tag[n]) n++;
    gz_sign_sha256_init(s);
    gz_sign_sha256_write(s, (const uint8_t *)tag, n);
    gz_sign_sha256_done(s, th);
    gz_sign_sha256_init(s);
    gz_sign_sha256_write(s, th, 32);
    gz_sign_sha256_write(s, th, 32);
}

/* A canonical compact size at p[*at..len). Returns 0 if it does not fit or is not minimal. */
static int varint(const uint8_t *p, size_t len, size_t *at, uint64_t *v)
{
    if (*at >= len) return 0;
    uint8_t b = p[(*at)++];
    size_t n = b < 0xfd ? 0 : b == 0xfd ? 2 : b == 0xfe ? 4 : 8;
    if (n == 0) { *v = b; return 1; }
    if (len - *at < n) return 0;
    *v = 0;
    for (size_t i = 0; i < n; i++) *v |= (uint64_t)p[*at + i] << (8 * i);
    *at += n;
    return *v >= (n == 2 ? 0xfdu : n == 4 ? 0x10000u : 0x100000000u);
}

int gz_sign_tx_parse(const uint8_t *p, size_t len, gz_sign_tx_t *tx)
{
    size_t at = 4;
    uint64_t v;
    int segwit = 0;
    if (len < 10 || len > 100000) return 0;
    memset(tx, 0, sizeof *tx);
    tx->bytes = p; tx->len = len;
    if (p[4] == 0) {                                     /* marker and flag */
        if (p[5] != 1) return 0;
        segwit = 1; at = 6;
    }
    if (!varint(p, len, &at, &v) || v != 1 || len - at < 36 + 1 + 4) return 0;
    tx->outpoint = p + at; at += 36;
    if (!varint(p, len, &at, &v) || v != 0 || len - at < 4) return 0;   /* empty script */
    tx->sequence = p + at; at += 4;
    uint64_t n_out;
    if (!varint(p, len, &at, &n_out) || n_out == 0 || n_out > 1000) return 0;
    tx->outputs_at = at;
    for (uint64_t i = 0; i < n_out; i++) {
        if (len - at < 8) return 0;
        at += 8;
        if (!varint(p, len, &at, &v) || v > len - at) return 0;
        at += (size_t)v;
    }
    tx->outputs_end = at;
    if (segwit) {
        if (!varint(p, len, &at, &v) || v != 1) return 0;
        if (!varint(p, len, &at, &v) || v > len - at) return 0;
        tx->witness_item = p + at; tx->witness_len = (size_t)v;
        at += (size_t)v;
    }
    return len - at == 4;
}

static void sha(const uint8_t *d, size_t n, uint8_t out[32])
{
    gz_sign_sha256_t s;
    gz_sign_sha256_init(&s);
    gz_sign_sha256_write(&s, d, n);
    gz_sign_sha256_done(&s, out);
}

void gz_sign_taproot_sighash(const uint8_t version[4], const uint8_t locktime[4], const uint8_t hashes[5][32], uint32_t index,
                             uint8_t out[32])
{
    uint8_t epoch_type[2] = {0, 0}, spend_type = 0, idx[4];
    gz_sign_sha256_t s;
    gz_sign_tagged_init(&s, "TapSighash");
    gz_sign_sha256_write(&s, epoch_type, 2);                       /* epoch 0, hash type default */
    gz_sign_sha256_write(&s, version, 4);
    gz_sign_sha256_write(&s, locktime, 4);
    for (int k = 0; k < 5; k++) gz_sign_sha256_write(&s, hashes[k], 32);   /* prevouts .. outputs */
    gz_sign_sha256_write(&s, &spend_type, 1);                      /* key path, no annex */
    for (int b = 0; b < 4; b++) idx[b] = (uint8_t)(index >> (8 * b));
    gz_sign_sha256_write(&s, idx, 4);                              /* the input's index */
    gz_sign_sha256_done(&s, out);
}

void gz_sign_tx_sighash(const gz_sign_tx_t *tx, uint64_t amount, const uint8_t script[34], uint8_t out[32])
{
    uint8_t h[5][32], amt[8], ser[35] = {34};
    sha(tx->outpoint, 36, h[0]);                                   /* sha_prevouts */
    for (int i = 0; i < 8; i++) amt[i] = (uint8_t)(amount >> (8 * i));
    sha(amt, 8, h[1]);                                             /* sha_amounts */
    memcpy(ser + 1, script, 34);
    sha(ser, 35, h[2]);                                            /* sha_scriptpubkeys */
    sha(tx->sequence, 4, h[3]);                                    /* sha_sequences */
    sha(tx->bytes + tx->outputs_at, tx->outputs_end - tx->outputs_at, h[4]);   /* sha_outputs */
    gz_sign_taproot_sighash(tx->bytes, tx->bytes + tx->len - 4, (const uint8_t (*)[32])h, 0, out);
}

void gz_sign_taptweak(const uint8_t internal[32], const uint8_t *merkle_root, uint8_t out[32])
{
    gz_sign_sha256_t s;
    gz_sign_tagged_init(&s, "TapTweak");
    gz_sign_sha256_write(&s, internal, 32);
    if (merkle_root) gz_sign_sha256_write(&s, merkle_root, 32);
    gz_sign_sha256_done(&s, out);
}

size_t gz_sign_tx_attach(const uint8_t *p, size_t len, const uint8_t sig64[64], uint8_t *out, size_t cap)
{
    gz_sign_tx_t tx;
    if (!gz_sign_tx_parse(p, len, &tx) || tx.witness_item || cap < len + 2 + 2 + 64) return 0;
    memcpy(out, p, 4);
    out[4] = 0; out[5] = 1;
    memcpy(out + 6, p + 4, tx.outputs_end - 4);
    size_t at = 6 + tx.outputs_end - 4;
    out[at++] = 1; out[at++] = 64;
    memcpy(out + at, sig64, 64); at += 64;
    memcpy(out + at, p + len - 4, 4);
    return at + 4;
}

int gz_sign_tx_verify(const secp256k1_context *ctx, const uint8_t *signed_tx, size_t len, uint64_t amount, const uint8_t script[34])
{
    gz_sign_tx_t tx;
    uint8_t digest[32];
    secp256k1_xonly_pubkey key;
    if (!gz_sign_tx_parse(signed_tx, len, &tx) || !tx.witness_item || tx.witness_len != 64) return 0;
    if (script[0] != 0x51 || script[1] != 0x20 || !secp256k1_xonly_pubkey_parse(ctx, &key, script + 2)) return 0;
    gz_sign_tx_sighash(&tx, amount, script, digest);
    return secp256k1_schnorrsig_verify(ctx, tx.witness_item, digest, 32, &key);
}

int gz_sign_tx_output(const gz_sign_tx_t *tx, uint32_t vout, uint64_t *amount, const uint8_t **script, size_t *script_len)
{
    size_t at = tx->outputs_at;
    uint64_t v;
    for (uint32_t i = 0;; i++) {
        if (at >= tx->outputs_end || tx->outputs_end - at < 9) return 0;
        uint64_t a = 0;
        for (int b = 0; b < 8; b++) a |= (uint64_t)tx->bytes[at + (size_t)b] << (8 * b);
        at += 8;
        if (!varint(tx->bytes, tx->outputs_end, &at, &v) || v > tx->outputs_end - at) return 0;
        if (i == vout) { *amount = a; *script = tx->bytes + at; *script_len = (size_t)v; return 1; }
        at += (size_t)v;
    }
}

int gz_sign_tx_find_output(const uint8_t *p, size_t len, uint32_t vout, uint64_t *amount, const uint8_t **script, size_t *script_len)
{
    size_t at = 4;
    uint64_t n, v, k;
    int found = 0;
    if (len < 10 || len > 100000 || p[4] == 0) return 0;          /* no witness (messages.md 7.2 record 18) */
    if (!varint(p, len, &at, &n) || n == 0 || n > len) return 0;
    for (k = 0; k < n; k++) {
        if (len - at < 36) return 0;
        at += 36;
        if (!varint(p, len, &at, &v) || v > len - at) return 0;
        at += (size_t)v;
        if (len - at < 4) return 0;
        at += 4;
    }
    if (!varint(p, len, &at, &n) || n == 0 || n > len) return 0;
    for (k = 0; k < n; k++) {
        uint64_t a = 0;
        if (len - at < 8) return 0;
        for (int b = 0; b < 8; b++) a |= (uint64_t)p[at + (size_t)b] << (8 * b);
        at += 8;
        if (!varint(p, len, &at, &v) || v > len - at) return 0;
        if (k == vout) { *amount = a; *script = p + at; *script_len = (size_t)v; found = 1; }
        at += (size_t)v;
    }
    return found && len - at == 4;
}

void gz_sign_txid(const uint8_t *tx, size_t len, uint8_t out[32])
{
    uint8_t h[32];
    sha(tx, len, h);
    sha(h, 32, out);
}

/* ---- messages: one view of the decoders of round_msg.h ---- */

int gz_sign_decode(const uint8_t *b, size_t len, gz_sign_msg_t *m)
{
    const uint8_t *scope, *r;
    size_t rn, i;
    uint16_t kind;
    gz_rmsg_err_t err;
    /* Function scope, not per case: no ASan use-after-scope calls (isolation). */
    union { gz_rmsg_nonces_t n; gz_rmsg_all_nonces_t a; gz_rmsg_list68_t l; gz_rmsg_small_t s; gz_rmsg_abort_t ab; } d;
    memset(m, 0, sizeof *m);
    if (gz_rmsg_open(b, len, &kind, &scope, &r, &rn) != GZ_RMSG_OK) return 0;
    m->kind = kind; m->scope = scope; m->records = r; m->records_len = rn;
    switch (kind) {
    case GZ_SIGN_MSG_PROPOSE:
        /* Only the identifier here (record 2, the first a valid proposal
         * holds); the engine decodes the whole proposal itself
         * (gz_rmsg_propose_decode) into memory it owns. */
        if (rn < 34 || r[0] != 2 || r[1] != 32) break;
        m->round_id = r + 2;
        return 1;
    case GZ_SIGN_MSG_NONCES:
        if (gz_rmsg_nonces_decode(r, rn, &d.n) != GZ_RMSG_OK) break;
        m->round_id = d.n.round_id; m->tier = d.n.tier; m->has_tier = 1; m->n = (uint16_t)d.n.n;
        for (i = 0; i < d.n.n; i++) m->entry[i] = d.n.entries + 134 * i;
        m->signed_len = rn;
        return 1;
    case GZ_SIGN_MSG_ALL_NONCES:
        if (gz_rmsg_all_nonces_decode(r, rn, &d.a) != GZ_RMSG_OK) break;
        m->round_id = d.a.round_id; m->tier = d.a.tier; m->has_tier = 1; m->n = (uint16_t)d.a.n;
        for (i = 0; i < d.a.n; i++) m->entry[i] = d.a.item[i];
        m->signed_len = rn;
        return 1;
    case GZ_SIGN_MSG_PARTIALS: case GZ_SIGN_MSG_RESULT:
        err = kind == GZ_SIGN_MSG_PARTIALS ? gz_rmsg_partial_sigs_decode(r, rn, &d.l) : gz_rmsg_tier_result_decode(r, rn, &d.l);
        if (err != GZ_RMSG_OK) break;
        m->round_id = d.l.round_id; m->tier = d.l.tier; m->has_tier = 1; m->n = (uint16_t)d.l.n;
        for (i = 0; i < d.l.n; i++) m->entry[i] = d.l.entries + 68 * i;
        m->sig = d.l.sig; m->signed_len = d.l.signed_len;
        return 1;
    case GZ_SIGN_MSG_COMPLETE: case GZ_SIGN_MSG_ACK: case GZ_SIGN_MSG_STATUS: case GZ_SIGN_MSG_FUNDED:
        err = kind == GZ_SIGN_MSG_COMPLETE ? gz_rmsg_complete_decode(r, rn, &d.s)
            : kind == GZ_SIGN_MSG_ACK ? gz_rmsg_ack_decode(r, rn, &d.s)
            : kind == GZ_SIGN_MSG_STATUS ? gz_rmsg_status_decode(r, rn, &d.s) : gz_rmsg_funded_decode(r, rn, &d.s);
        if (err != GZ_RMSG_OK) break;
        m->round_id = d.s.round_id; m->held = kind == GZ_SIGN_MSG_FUNDED ? d.s.funding_txid : d.s.held_digest;
        m->sig = d.s.sig; m->signed_len = d.s.signed_len;
        return 1;
    case GZ_SIGN_MSG_ABORT:
        if (gz_rmsg_abort_decode(r, rn, &d.ab) != GZ_RMSG_OK) break;
        m->round_id = d.ab.round_id; m->reason = d.ab.reason; m->tier = d.ab.tier; m->has_tier = (uint8_t)d.ab.has_tier;
        m->n = (uint16_t)d.ab.n_items;
        for (i = 0; i < d.ab.n_items; i++) m->entry[i] = d.ab.items + 4 * i;
        m->sig = d.ab.sig; m->signed_len = d.ab.signed_len;
        return 1;
    default: break;
    }
    memset(m, 0, sizeof *m);
    return 0;
}
