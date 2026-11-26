/* SPDX-License-Identifier: MIT */
/* The host's funding fault switches (test build only): see faults.h. */
#define _POSIX_C_SOURCE 200809L
#include "faults.h"

#ifdef GZP_TEST_BUILD
#include <stdio.h>
#include <string.h>

#include "gazpacho/chain.h"
#include "gazpacho/tree.h"

#define FT_FUNDINGS 16
#define FT_INPUTS 16

/* The fundings the wallet signed this run (by txid), and the inputs of
 * each, read from its signed bytes: a spend-back spends one of them. */
static struct {
    uint8_t txid[32];
    uint8_t in[FT_INPUTS][36];
    size_t n_in;
} ft[FT_FUNDINGS];
static size_t n_ft;
static gz_wallet_port_t real_port, noting_port;

static void txid_hex(const uint8_t txid[32], char hex[65])
{
    gz_hash_to_hex(txid, hex);
}

/* The inputs' outpoints of a transaction (witness or not), at most `max`.
 * -1 if it does not parse. */
static int inputs_of(const uint8_t *tx, size_t len, uint8_t (*in)[36], size_t max)
{
    static uint8_t bare[GZ_TX_MAX_BYTES];
    gz_tx_info_t info;
    size_t n = 0, k;
    if (len > sizeof bare || !gz_fund_tx_strip(tx, len, bare, sizeof bare, &n) || !gz_tx_parse(bare, n, &info))
        return -1;
    for (k = 0; k < info.n_in && k < max; k++) {
        const uint8_t *op;
        size_t sl;
        uint32_t seq;
        if (!gz_tx_input(bare, n, &info, k, &op, &sl, &seq)) return -1;
        memcpy(in[k], op, 36);
    }
    return (int)k;
}

static int funding_of(const uint8_t txid[32])
{
    for (size_t i = 0; i < n_ft; i++)
        if (memcmp(ft[i].txid, txid, 32) == 0) return (int)i;
    return -1;
}

/* A spend-back: a transaction spending an input of a funding signed this run. */
static int spend_back_of(const uint8_t *tx, size_t len)
{
    uint8_t in[FT_INPUTS][36];
    int n = inputs_of(tx, len, in, FT_INPUTS);
    for (int k = 0; k < n; k++)
        for (size_t i = 0; i < n_ft; i++)
            for (size_t j = 0; j < ft[i].n_in; j++)
                if (memcmp(ft[i].in[j], in[k], 36) == 0) return (int)i;
    return -1;
}

static int noting_sign_plan(void *ctx, const uint8_t txid[32], uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t id[32];
    int ok = real_port.sign_plan(ctx, txid, out, cap, out_len);
    if (ok && *out_len <= cap && gz_txid_from_raw(out, *out_len, id) && funding_of(id) < 0 && n_ft < FT_FUNDINGS) {
        int n = inputs_of(out, *out_len, ft[n_ft].in, FT_INPUTS);
        memcpy(ft[n_ft].txid, id, 32);
        ft[n_ft].n_in = n > 0 ? (size_t)n : 0;
        n_ft++;
    }
    return ok;
}

const gz_wallet_port_t *gzp_fault_port(const gzp_options_t *o, const gz_wallet_port_t *real)
{
    if (!real || !o->test_never_fund) return real;
    real_port = *real;
    noting_port = *real;
    noting_port.sign_plan = noting_sign_plan;
    return &noting_port;
}

int gzp_fault_broadcast(gzp_chain_t *c, const gzp_options_t *o, const uint8_t *tx, size_t len)
{
    uint8_t id[32];
    char hex[65];
    int i;
    (void)c;
    if (!o->test_never_fund || !gz_txid_from_raw(tx, len, id)) return 0;
    txid_hex(id, hex);
    if (funding_of(id) >= 0) {
        gzp_log("test-never-fund held txid=%s", hex);
        return 1;
    }
    if ((i = spend_back_of(tx, len)) >= 0) {
        char f[65];
        txid_hex(ft[i].txid, f);
        gzp_log("test-never-fund held-spend-back txid=%s funding=%s", hex, f);
        return 1;
    }
    return 0;
}

int gzp_fault_send_now(gzp_chain_t *c, const char *label, const uint8_t *tx, size_t len)
{
    gz_broadcast_result r;
    uint8_t id[32];
    char hex[65];
    if (!c || !c->active || !c->lookup.view) {
        gzp_log("%s-broadcast outcome=not-sent why=no-chain", label);
        return -1;
    }
    if (!gz_network_is_test(c->network)) {   /* never reached: options.c refuses mainnet */
        gzp_log("%s-broadcast outcome=not-sent why=mainnet", label);
        return -1;
    }
    if (len > GZ_TX_MAX_BYTES || !gz_txid_from_raw(tx, len, id)) {
        gzp_log("%s-broadcast outcome=not-sent why=not-a-transaction", label);
        return -1;
    }
    txid_hex(id, hex);
    memset(&r, 0, sizeof r);
    gz_chain_broadcast(c->lookup.view, tx, len, &r);
    gzp_log("%s-broadcast txid=%s outcome=%s result=%s reason=%s", label, hex,
            r.result == GZ_CHAIN_OK ? "accepted" : r.result == GZ_CHAIN_REJECTED ? "refused" : "not-sent",
            gz_chain_result_name(r.result), r.reason[0] ? r.reason : "-");
    return r.result == GZ_CHAIN_OK ? 1 : r.result == GZ_CHAIN_REJECTED ? 0 : -1;
}
#else
typedef int gzp_faults_release_empty;   /* the release program has no fault switches */
#endif
