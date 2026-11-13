/* Fuzz target for every round message decoder (core/signing/round_msg.c).
 * The first byte picks the decoder; the rest is the record stream.
 *
 * Properties, beyond "no crash, no undefined behaviour, no read outside the
 * input" (the sanitizers and libFuzzer judge those):
 *   - a refused message leaves its output zeroed;
 *   - an accepted round_propose re-encodes, the re-encoding decodes to the
 *     same proposal, and encoding that again gives the same bytes;
 *   - an accepted message's views lie inside the input. */
#include "gazpacho/round_msg.h"
#include <stdlib.h>
#include <string.h>

static int inside(const uint8_t *p, size_t n, const uint8_t *d, size_t len)
{
    return !p || (p >= d && p + n <= d + len);
}

static int zeroed(const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

#define REQUIRE(c) do { if (!(c)) abort(); } while (0)

static uint8_t enc1[1 << 18], enc2[1 << 18];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    const uint8_t *r = data + 1;
    size_t n = size - 1;
    switch (data[0] % 10) {
    case 0: {
        static gz_rmsg_propose_t m, m2;
        if (gz_rmsg_propose_decode(r, n, &m) != GZ_RMSG_OK) { REQUIRE(zeroed(&m, sizeof m)); break; }
        REQUIRE(inside(m.round_id, 32, r, n) && inside(m.sig, 64, r, n) && m.signed_len + 66 <= n);
        REQUIRE(inside(m.p.funding_tx, m.p.funding_tx_len, r, n));
        gz_rmsg_propose_in_t in = {m.round_id, m.check_id, m.host_random, m.has_attempt, m.attempt, &m.p,
                                   m.lstock_hashes, m.distribution, m.distribution_len};
        size_t k = gz_rmsg_propose_encode(&in, enc1, sizeof enc1);
        REQUIRE(k > 0 && k <= m.signed_len);           /* unknown odd records are not re-encoded */
        memcpy(enc1 + k, "\xf0\x40", 2); memcpy(enc1 + k + 2, m.sig, 64);
        REQUIRE(gz_rmsg_propose_decode(enc1, k + 66, &m2) == GZ_RMSG_OK);
        gz_rmsg_propose_in_t in2 = {m2.round_id, m2.check_id, m2.host_random, m2.has_attempt, m2.attempt, &m2.p,
                                    m2.lstock_hashes, m2.distribution, m2.distribution_len};
        size_t k2 = gz_rmsg_propose_encode(&in2, enc2, sizeof enc2);
        REQUIRE(k2 == k && memcmp(enc1, enc2, k) == 0);
        REQUIRE(m2.p.n_participants == m.p.n_participants && m2.p.funding_amount == m.p.funding_amount &&
                memcmp(m2.parts, m.parts, sizeof m.parts) == 0);
        break;
    }
    case 1: { gz_rmsg_nonces_t m; if (gz_rmsg_nonces_decode(r, n, &m) == GZ_RMSG_OK) REQUIRE(inside(m.entries, 134 * m.n, r, n)); else REQUIRE(zeroed(&m, sizeof m)); break; }
    case 2: {
        static gz_rmsg_all_nonces_t m;
        if (gz_rmsg_all_nonces_decode(r, n, &m) == GZ_RMSG_OK) {
            for (size_t i = 0; i < m.n; i++) REQUIRE(inside(m.item[i], 6 + 130u * m.n_signers[i], r, n));
        } else REQUIRE(zeroed(&m, sizeof m));
        break;
    }
    case 3: { gz_rmsg_list68_t m; if (gz_rmsg_partial_sigs_decode(r, n, &m) == GZ_RMSG_OK) REQUIRE(inside(m.entries, 68 * m.n, r, n) && inside(m.sig, 64, r, n)); else REQUIRE(zeroed(&m, sizeof m)); break; }
    case 4: { gz_rmsg_list68_t m; if (gz_rmsg_tier_result_decode(r, n, &m) == GZ_RMSG_OK) REQUIRE(inside(m.entries, 68 * m.n, r, n)); else REQUIRE(zeroed(&m, sizeof m)); break; }
    case 5: { gz_rmsg_small_t m; if (gz_rmsg_complete_decode(r, n, &m) == GZ_RMSG_OK) REQUIRE(inside(m.sig, 64, r, n)); else REQUIRE(zeroed(&m, sizeof m)); break; }
    case 6: { gz_rmsg_small_t m; if (gz_rmsg_ack_decode(r, n, &m) == GZ_RMSG_OK) REQUIRE(inside(m.held_digest, 32, r, n)); else REQUIRE(zeroed(&m, sizeof m)); break; }
    case 7: { gz_rmsg_small_t m; if (gz_rmsg_status_decode(r, n, &m) == GZ_RMSG_OK) REQUIRE(inside(m.round_id, 32, r, n)); else REQUIRE(zeroed(&m, sizeof m)); break; }
    case 8: { gz_rmsg_small_t m; if (gz_rmsg_funded_decode(r, n, &m) == GZ_RMSG_OK) REQUIRE(inside(m.funding_txid, 32, r, n)); else REQUIRE(zeroed(&m, sizeof m)); break; }
    default: {
        gz_rmsg_abort_t m;
        if (gz_rmsg_abort_decode(r, n, &m) == GZ_RMSG_OK) REQUIRE(inside(m.detail, m.detail_len, r, n) && inside(m.items, 4 * m.n_items, r, n));
        else REQUIRE(zeroed(&m, sizeof m));
        break;
    }
    }
    uint16_t kind;
    const uint8_t *scope, *rec;
    size_t rl;
    if (gz_rmsg_open(data, size, &kind, &scope, &rec, &rl) == GZ_RMSG_OK) REQUIRE(rec + rl == data + size);
    return 0;
}
