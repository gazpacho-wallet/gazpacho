/* Fuzz target: the transaction reader the checks use on the host's funding
 * transaction (C1, C4(d), H1). It must never read past the bytes, and what it
 * accepts must be exactly one transaction: every output and input it reports
 * lies inside the bytes. C4(d) on each of its own inputs: dead when spent by
 * another transaction, never when spent by the transaction itself. */
#include "gazpacho/tree.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    static const uint8_t other[32] = {0x5a};
    static const uint8_t script[34] = {0x51, 0x20};
    gz_tx_info_t info;
    size_t i;
    uint8_t txid[32], h[32];
    if (!gz_tx_parse(d, n, &info)) return 0;
    if (info.n_in == 0 || info.in_at > n || info.out_at > n) abort();
    gz_tx_txid(d, n, txid);
    for (i = 0; i < info.n_out; i++) {
        uint64_t amount;
        const uint8_t *s;
        size_t sl;
        if (!gz_tx_output(d, n, &info, i, &amount, &s, &sl)) abort();
        if (s < d || s + sl > d + n - 4) abort();
    }
    for (i = 0; i < info.n_in; i++) {
        const uint8_t *op;
        size_t sl;
        uint32_t seq;
        if (!gz_tx_input(d, n, &info, i, &op, &sl, &seq)) abort();
        if (op < d || op + 36 > d + n) abort();
        if (gz_tree_c4d_dead(d, n, op, txid) != 0) abort();
        if (memcmp(txid, other, 32) != 0 && gz_tree_c4d_dead(d, n, op, other) != 1) abort();
    }
    if (info.n_in == 1) (void)gz_tx_sighash1(d, n, 1000, script, 34, h);
    return 0;
}
