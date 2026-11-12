/* Fuzz target for gzt_tx_parse.  Properties checked on every input:
 *   - no crash, no out-of-bounds access (run under the memory-error checkers);
 *   - whatever parses serialises back to the identical bytes;
 *   - the legacy form of what parsed parses again, with the same txid;
 *   - weight is 3 x (size without witness) + (size of the input), counted;
 * With -DGZ_LIBFUZZER=ON this file alone is linked with libFuzzer
 * (-fsanitize=fuzzer; docs/notes/ci.md).  Otherwise fuzz_tx_main.c is the
 * driver: it mutates the official transactions for a given number of rounds
 * with a fixed seed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/wallet_tx.h"

static gzt_tx tx, tx2;
static uint8_t back[GZT_MAX_TX_BYTES];
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t n;
    uint8_t id1[32], id2[32];
    uint64_t w, vs;
    if (gzt_tx_parse(data, size, &tx) != GZT_OK) return 0;
    if (gzt_tx_serialize(&tx, GZT_SER_WITNESS, back, sizeof back, &n) != GZT_OK || n != size ||
        memcmp(back, data, size) != 0)
        abort();
    if (gzt_tx_serialize(&tx, GZT_SER_NO_WITNESS, back, sizeof back, &n) != GZT_OK) abort();
    /* the counted weight equals the weight of the real serialisations */
    if (gzt_tx_weight(&tx, &w, &vs) != GZT_OK || w != 3 * (uint64_t)n + size || vs != (w + 3) / 4)
        abort();
    if (gzt_tx_parse(back, n, &tx2) != GZT_OK) abort();
    if (gzt_tx_txid(&tx, id1) != GZT_OK || gzt_tx_txid(&tx2, id2) != GZT_OK ||
        memcmp(id1, id2, 32) != 0)
        abort();
    return 0;
}
