/* The funding engine's needs of the wallet (step P4.5): the unsigned bytes
 * and spent outputs of a built funding, the spend-back, and H11's coin that
 * must be spent. */
#include <stdio.h>
#include <string.h>
#include "gazpacho/wallet_tx.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static secp256k1_context *ctx;
static gzw_xprv master;
static gzt_coin coins[3];
static uint8_t factory[34];

static void setup(void)
{
    static const uint64_t amounts[3] = {300000, 200000, 5000};
    uint8_t seed[32];
    memset(seed, 0x42, 32);
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    CHECK(gzw_bip32_master(ctx, seed, 32, &master, NULL));
    for (int i = 0; i < 3; i++) {
        gzw_bip86_output o;
        CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 0, (uint32_t)i, &o, NULL));
        memset(coins[i].txid, 0x10 + i, 32);
        coins[i].vout = (uint32_t)i;
        coins[i].amount = amounts[i];
        coins[i].index = (uint32_t)i;
        memcpy(coins[i].script, o.script_pubkey, 34);
    }
    factory[0] = 0x51;
    factory[1] = 0x20;
    memset(factory + 2, 0xab, 32);
}

static gzt_funding_request request(uint64_t amount)
{
    gzt_funding_request r;
    memset(&r, 0, sizeof r);
    r.net = GZT_NET_SIGNET;
    r.funding_script = factory;
    r.funding_script_len = 34;
    r.amount = amount;
    r.change_index = 50;
    r.fee.rate.sat_per_kvb = 100;
    r.fee.ceiling.sat_per_kvb = 1000;
    return r;
}

static void test_unsigned_and_prevouts(void)
{
    static gzt_funding f;
    gzt_funding_request r = request(100000);
    uint8_t aux[32], tx[GZT_MAX_TX_BYTES], script[64], txid[32];
    size_t len, sl;
    uint64_t amt;
    gzt_tx parsed;
    memset(aux, 1, 32);
    CHECK(gzt_funding_unsigned(&f, tx, sizeof tx, &len) == GZT_ERR_STATE);   /* not built */
    CHECK(gzt_funding_build(ctx, &master, &r, coins, 3, aux, &f) == GZT_OK);
    CHECK(gzt_funding_unsigned(&f, tx, sizeof tx, &len) == GZT_OK);
    CHECK(gzt_tx_parse(tx, len, &parsed) == GZT_OK && gzt_tx_txid(&parsed, txid) == GZT_OK);
    CHECK(memcmp(txid, f.info.txid, 32) == 0 && parsed.n_in == 1 && parsed.in[0].witness_count == 0);
    CHECK(memcmp(parsed.in[0].prev_txid, coins[0].txid, 32) == 0);   /* the largest coin first */
    CHECK(gzt_funding_unsigned(&f, tx, 10, &len) == GZT_ERR_BUFFER);
    CHECK(gzt_funding_prevout(&f, 0, &amt, script, sizeof script, &sl) == GZT_OK && amt == 300000 && sl == 34);
    CHECK(memcmp(script, coins[0].script, 34) == 0);
    CHECK(gzt_funding_prevout(&f, 1, &amt, script, sizeof script, &sl) == GZT_ERR_ARG);
    CHECK(gzt_funding_prevout(&f, 0, &amt, script, 10, &sl) == GZT_ERR_BUFFER);
    gzt_funding_wipe(&f);
}

static void test_must_spend(void)
{
    static gzt_funding f, g;
    gzt_funding_request r = request(100000);
    uint8_t aux[32], tx[GZT_MAX_TX_BYTES];
    size_t len;
    gzt_tx parsed;
    memset(aux, 1, 32);
    /* The smallest coin must be spent: it is input 0, with another to pay. */
    r.must_spend = 1;
    memcpy(r.must_txid, coins[2].txid, 32);
    r.must_vout = coins[2].vout;
    CHECK(gzt_funding_build(ctx, &master, &r, coins, 3, aux, &f) == GZT_OK);
    CHECK(gzt_funding_unsigned(&f, tx, sizeof tx, &len) == GZT_OK && gzt_tx_parse(tx, len, &parsed) == GZT_OK);
    CHECK(parsed.n_in == 2 && memcmp(parsed.in[0].prev_txid, coins[2].txid, 32) == 0 && parsed.in[0].prev_vout == 2);
    CHECK(memcmp(parsed.in[1].prev_txid, coins[0].txid, 32) == 0);
    {
        /* It can be signed. */
        uint8_t out[GZT_MAX_TX_BYTES];
        size_t n;
        CHECK(gzt_funding_release(ctx, &master, &f, f.info.txid, aux, out, sizeof out, &n) == GZT_OK);
    }
    /* The largest must be spent: alone, as without the rule. */
    memcpy(r.must_txid, coins[0].txid, 32);
    r.must_vout = 0;
    CHECK(gzt_funding_build(ctx, &master, &r, coins, 3, aux, &g) == GZT_OK && g.info.selection.n_selected == 1);
    /* Not offered. */
    r.must_vout = 7;
    CHECK(gzt_funding_build(ctx, &master, &r, coins, 3, aux, &g) == GZT_ERR_ARG);
    /* Cannot pay with it. */
    r = request(600000);
    r.must_spend = 1;
    memcpy(r.must_txid, coins[2].txid, 32);
    r.must_vout = 2;
    CHECK(gzt_funding_build(ctx, &master, &r, coins, 3, aux, &g) == GZT_ERR_FUNDS);
    gzt_funding_wipe(&f);
}

static void test_spend_back(void)
{
    static gzt_funding f;
    gzt_funding_request r = request(100000);
    uint8_t aux[32], out[GZT_MAX_TX_BYTES];
    size_t n;
    gzt_tx parsed;
    gzw_bip86_output dest;
    uint64_t w, vs;
    memset(aux, 1, 32);
    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 1, 2000, &dest, NULL));
    CHECK(gzt_funding_spend_back(ctx, &master, &f, 0, dest.script_pubkey, 34, 12, aux, out, sizeof out, &n) == GZT_ERR_STATE);
    CHECK(gzt_funding_build(ctx, &master, &r, coins, 3, aux, &f) == GZT_OK);
    CHECK(gzt_funding_spend_back(ctx, &master, &f, 0, dest.script_pubkey, 34, 12, aux, out, sizeof out, &n) == GZT_OK);
    CHECK(gzt_tx_parse(out, n, &parsed) == GZT_OK && parsed.n_in == 1 && parsed.n_out == 1);
    CHECK(memcmp(parsed.in[0].prev_txid, coins[0].txid, 32) == 0 && parsed.in[0].prev_vout == 0);
    CHECK(parsed.out[0].value == 300000 - 12 && parsed.in[0].witness_count == 1 && parsed.in[0].witness[0].len == 64);
    CHECK(parsed.in[0].sequence == 0xfffffffdu && parsed.version == 2);
    CHECK(gzt_tx_weight(&parsed, &w, &vs) == GZT_OK && vs == 111);
    /* Never to the factory, never below dust, never past the inputs. */
    CHECK(gzt_funding_spend_back(ctx, &master, &f, 0, factory, 34, 12, aux, out, sizeof out, &n) == GZT_ERR_SCRIPT);
    CHECK(gzt_funding_spend_back(ctx, &master, &f, 0, dest.script_pubkey, 34, 300000 - 100, aux, out, sizeof out, &n) ==
          GZT_ERR_DUST);
    CHECK(gzt_funding_spend_back(ctx, &master, &f, 1, dest.script_pubkey, 34, 12, aux, out, sizeof out, &n) == GZT_ERR_ARG);
    CHECK(gzt_funding_spend_back(ctx, &master, &f, 0, dest.script_pubkey, 34, 12, aux, out, 20, &n) == GZT_ERR_BUFFER);
    /* A fee above the input, and a destination that is not a witness program. */
    CHECK(gzt_funding_spend_back(ctx, &master, &f, 0, dest.script_pubkey, 34, 300001, aux, out, sizeof out, &n) ==
          GZT_ERR_DUST);
    {
        uint8_t p2pkh[25] = {0x76, 0xa9, 0x14};
        p2pkh[23] = 0x88;
        p2pkh[24] = 0xac;
        CHECK(gzt_funding_spend_back(ctx, &master, &f, 0, p2pkh, 25, 12, aux, out, sizeof out, &n) == GZT_ERR_SCRIPT);
    }
    gzt_funding_wipe(&f);
}

/* require_change: a selection that would leave no change takes another
 * coin; with none to take, GZT_ERR_FUNDS. */
static void test_require_change(void)
{
    static gzt_funding f, g, h;
    gzt_funding_request r = request(300000 - 62);
    uint8_t aux[32];
    memset(aux, 1, 32);
    CHECK(gzt_funding_build(ctx, &master, &r, coins, 3, aux, &f) == GZT_OK);
    CHECK(f.info.selection.n_selected == 1 && !f.info.has_change);   /* without it: no change */
    r.require_change = 1;
    CHECK(gzt_funding_build(ctx, &master, &r, coins, 3, aux, &g) == GZT_OK);
    CHECK(g.info.selection.n_selected == 2 && g.info.has_change);
    CHECK(gzt_funding_build(ctx, &master, &r, coins, 1, aux, &h) == GZT_ERR_FUNDS);
    gzt_funding_wipe(&f);
    gzt_funding_wipe(&g);
}

/* must_spend: the coin is not selected a second time when the selection
 * reaches its own place; and with more than 64 coins offered. */
static void test_must_reach(void)
{
    static gzt_funding f, g;
    static gzt_coin many[70];
    static gzt_tx parsed;
    gzt_funding_request r = request(400000);
    uint8_t aux[32], tx[GZT_MAX_TX_BYTES];
    size_t len;
    memset(aux, 1, 32);
    r.must_spend = 1;
    memcpy(r.must_txid, coins[0].txid, 32);   /* the largest, and two coins needed */
    r.must_vout = coins[0].vout;
    CHECK(gzt_funding_build(ctx, &master, &r, coins, 3, aux, &f) == GZT_OK);
    CHECK(gzt_funding_unsigned(&f, tx, sizeof tx, &len) == GZT_OK && gzt_tx_parse(tx, len, &parsed) == GZT_OK);
    CHECK(parsed.n_in == 2 && memcmp(parsed.in[0].prev_txid, coins[0].txid, 32) == 0 &&
          memcmp(parsed.in[1].prev_txid, coins[1].txid, 32) == 0);
    gzt_funding_wipe(&f);
    for (int i = 0; i < 70; i++) {
        gzw_bip86_output o;
        CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 0, (uint32_t)(10 + i), &o, NULL));
        memset(many[i].txid, 0x70, 32);
        many[i].txid[0] = (uint8_t)i;
        many[i].vout = (uint32_t)i;
        many[i].amount = i == 69 ? 1000 : 10000;   /* the must coin the smallest, past the best 64 */
        many[i].index = (uint32_t)(10 + i);
        memcpy(many[i].script, o.script_pubkey, 34);
    }
    r = request(50000);
    r.must_spend = 1;
    memcpy(r.must_txid, many[69].txid, 32);
    r.must_vout = 69;
    CHECK(gzt_funding_build(ctx, &master, &r, many, 70, aux, &g) == GZT_OK);
    CHECK(gzt_funding_unsigned(&g, tx, sizeof tx, &len) == GZT_OK && gzt_tx_parse(tx, len, &parsed) == GZT_OK);
    CHECK(parsed.n_in >= 2 && memcmp(parsed.in[0].prev_txid, many[69].txid, 32) == 0 && parsed.in[0].prev_vout == 69);
    for (uint32_t i = 1; i < parsed.n_in; i++) CHECK(parsed.in[i].prev_vout != 69);
    gzt_funding_wipe(&g);
    {
        /* Two coins with the same vout: the one named by txid and vout. */
        static gzt_coin two[3];
        static gzt_funding h;
        memcpy(two, coins, sizeof two);
        two[1].vout = 0;   /* coins 0 and 1 now share vout 0 */
        r = request(50000);
        r.must_spend = 1;
        memcpy(r.must_txid, two[0].txid, 32);
        r.must_vout = 0;
        CHECK(gzt_funding_build(ctx, &master, &r, two, 3, aux, &h) == GZT_OK);
        CHECK(gzt_funding_unsigned(&h, tx, sizeof tx, &len) == GZT_OK && gzt_tx_parse(tx, len, &parsed) == GZT_OK);
        CHECK(memcmp(parsed.in[0].prev_txid, two[0].txid, 32) == 0 && parsed.in[0].prev_vout == 0);
        gzt_funding_wipe(&h);
    }
}

int main(void)
{
    setup();
    test_unsigned_and_prevouts();
    test_must_spend();
    test_spend_back();
    test_require_change();
    test_must_reach();
    secp256k1_context_destroy(ctx);
    if (fails) return 1;
    printf("wallet funding port: all passed\n");
    return 0;
}
