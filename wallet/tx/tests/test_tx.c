/* Unit tests for gazpacho_wallet_tx: malformed input and caps, sizes and
 * fees, dust, networks, coin selection against an independent model, the
 * funding builder and its release gate.  Official vectors are in
 * test_tx_vectors.c. */
#include <openssl/sha.h>
#include <secp256k1_schnorrsig.h>

#include "tx_test.h"
#include "tx_vectors_data.h"

static uint8_t raw[GZT_MAX_TX_BYTES], back[GZT_MAX_TX_BYTES];
static gzt_tx tx, tx2;

/* ---- a byte writer for hand-made transactions ----------------------------- */

static size_t pos;
static void b(uint8_t v) { raw[pos++] = v; }
static void le(uint64_t v, int n) { for (int i = 0; i < n; i++) b((uint8_t)(v >> (8 * i))); }
static void fill(uint8_t v, size_t n) { while (n--) b(v); }

/* version, n_in inputs (script_sig of ss bytes), n_out outputs of value and
   script of sl bytes; optional witness of wc items of wl bytes per input. */
static size_t make(int segwit, size_t n_in, size_t ss, size_t n_out, uint64_t value, size_t sl,
                   size_t wc, size_t wl) {
    pos = 0;
    le(2, 4);
    if (segwit) { b(0); b(1); }
    b((uint8_t)n_in);
    for (size_t i = 0; i < n_in; i++) {
        fill((uint8_t)i, 32); le(0, 4); b((uint8_t)ss); fill(0xab, ss); le(0xffffffff, 4);
    }
    b((uint8_t)n_out);
    for (size_t i = 0; i < n_out; i++) { le(value, 8); b((uint8_t)sl); fill(0x51, sl); }
    if (segwit)
        for (size_t i = 0; i < n_in; i++) {
            b((uint8_t)wc);
            for (size_t j = 0; j < wc; j++) { b((uint8_t)wl); fill(0xcd, wl); }
        }
    le(0, 4);
    return pos;
}

static int all_zero(const void *p, size_t n) {
    const uint8_t *q = p;
    for (size_t i = 0; i < n; i++) if (q[i]) return 0;
    return 1;
}

static gzt_err parse_raw(size_t n) {
    gzt_err e = gzt_tx_parse(raw, n, &tx);
    if (e) CHECK(all_zero(&tx, sizeof tx));
    return e;
}

static void test_parse(void) {
    size_t n, m;
    CHECK(parse_raw(make(0, 1, 0, 1, 1000, 34, 0, 0)) == GZT_OK);
    CHECK(parse_raw(make(1, 2, 0, 2, 1000, 34, 1, 64)) == GZT_OK);
    CHECK(gzt_tx_serialize(&tx, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_OK);
    CHECK(m == pos && memcmp(back, raw, m) == 0);

    /* every truncation of both official transactions fails */
    const char *hex[2] = {BIP341_UNSIGNED, BIP341_SIGNED};
    int truncations_ok = 1;
    for (int k = 0; k < 2; k++) {
        n = unhex(hex[k], raw, sizeof raw);
        CHECK(parse_raw(n) == GZT_OK);
        for (size_t cut = 0; cut < n; cut++)
            if (gzt_tx_parse(raw, cut, &tx) == GZT_OK) truncations_ok = 0;
        raw[n] = 0;
        CHECK(parse_raw(n + 1) == GZT_ERR_PARSE); /* trailing byte */
    }
    CHECK(truncations_ok);

    /* canonical forms only */
    n = make(0, 1, 0, 1, 1000, 34, 0, 0);
    memmove(raw + 7, raw + 5, n - 5); raw[4] = 0xfd; raw[5] = 1; raw[6] = 0; /* 1 as fd0100 */
    CHECK(parse_raw(n + 2) == GZT_ERR_PARSE);
    n = make(1, 1, 0, 1, 1000, 34, 1, 64);
    raw[5] = 0x02;
    CHECK(parse_raw(n) == GZT_ERR_PARSE);              /* marker without flag 01 */
    CHECK(parse_raw(make(1, 2, 0, 1, 1000, 34, 0, 0)) == GZT_ERR_PARSE); /* superfluous witness */
    CHECK(parse_raw(make(0, 0, 0, 2, 1000, 34, 0, 0)) == GZT_ERR_PARSE); /* reads as marker, flag 02 */
    CHECK(parse_raw(make(1, 0, 0, 1, 1000, 34, 0, 0)) == GZT_ERR_PARSE); /* segwit, no inputs */
    CHECK(parse_raw(make(0, 1, 0, 0, 1000, 34, 0, 0)) == GZT_ERR_PARSE); /* no outputs */
    CHECK(parse_raw(make(0, 1, 0, 1, GZT_MAX_MONEY, 34, 0, 0)) == GZT_OK);
    CHECK(parse_raw(make(0, 1, 0, 1, GZT_MAX_MONEY + 1, 34, 0, 0)) == GZT_ERR_PARSE);
    CHECK(parse_raw(make(0, 1, 0, 2, GZT_MAX_MONEY / 2 + 1, 34, 0, 0)) == GZT_ERR_PARSE);
    CHECK(parse_raw(make(0, 1, 0, 2, GZT_MAX_MONEY / 2, 34, 0, 0)) == GZT_OK);
    n = make(0, 1, 0, 1, 1000, 34, 0, 0);
    raw[4 + 1 + 36] = 0x50; /* script_sig length beyond the end */
    CHECK(parse_raw(n) == GZT_ERR_PARSE);

    /* each cap, and one past it */
    CHECK(parse_raw(make(0, GZT_MAX_INPUTS, 0, 1, 1, 34, 0, 0)) == GZT_OK);
    CHECK(parse_raw(make(0, GZT_MAX_INPUTS + 1, 0, 1, 1, 34, 0, 0)) == GZT_ERR_LIMIT);
    CHECK(parse_raw(make(0, 1, 0, GZT_MAX_OUTPUTS, 1, 34, 0, 0)) == GZT_OK);
    CHECK(parse_raw(make(0, 1, 0, GZT_MAX_OUTPUTS + 1, 1, 34, 0, 0)) == GZT_ERR_LIMIT);
    CHECK(parse_raw(make(0, 1, GZT_MAX_SCRIPT, 1, 1, 34, 0, 0)) == GZT_OK);
    CHECK(parse_raw(make(0, 1, GZT_MAX_SCRIPT + 1, 1, 1, 34, 0, 0)) == GZT_ERR_LIMIT);
    CHECK(parse_raw(make(0, 1, 0, 1, 1, GZT_MAX_SCRIPT, 0, 0)) == GZT_OK);
    CHECK(parse_raw(make(0, 1, 0, 1, 1, GZT_MAX_SCRIPT + 1, 0, 0)) == GZT_ERR_LIMIT);
    CHECK(parse_raw(make(1, 1, 0, 1, 1, 34, GZT_MAX_WITNESS_ITEMS, 1)) == GZT_OK);
    CHECK(parse_raw(make(1, 1, 0, 1, 1, 34, GZT_MAX_WITNESS_ITEMS + 1, 1)) == GZT_ERR_LIMIT);
    CHECK(parse_raw(make(1, 1, 0, 1, 1, 34, 1, GZT_MAX_WITNESS_ITEM)) == GZT_OK);
    CHECK(parse_raw(make(1, 1, 0, 1, 1, 34, 1, GZT_MAX_WITNESS_ITEM + 1)) == GZT_ERR_LIMIT);

    /* the largest transaction the caps allow fits the stated buffer size */
    n = make(1, GZT_MAX_INPUTS, GZT_MAX_SCRIPT, GZT_MAX_OUTPUTS, 1, GZT_MAX_SCRIPT,
             GZT_MAX_WITNESS_ITEMS, GZT_MAX_WITNESS_ITEM);
    CHECK(n <= GZT_MAX_TX_BYTES && parse_raw(n) == GZT_OK);

    /* serialise refuses what it cannot write */
    CHECK(parse_raw(make(1, 1, 0, 1, 1000, 34, 1, 64)) == GZT_OK);
    CHECK(gzt_tx_serialize(&tx, GZT_SER_WITNESS, back, pos - 1, &m) == GZT_ERR_BUFFER);
    CHECK(gzt_tx_serialize(&tx, GZT_SER_WITNESS, back, pos, &m) == GZT_OK && m == pos);
    CHECK(gzt_tx_serialize(&tx, (gzt_ser_form)0, back, sizeof back, &m) == GZT_ERR_ARG);
    tx2 = tx; tx2.n_in = 0;
    CHECK(gzt_tx_serialize(&tx2, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_ERR_ARG);
    tx2 = tx; tx2.n_out = GZT_MAX_OUTPUTS + 1;
    CHECK(gzt_tx_serialize(&tx2, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_ERR_ARG);
    tx2 = tx; tx2.in[0].witness[0].len = GZT_MAX_WITNESS_ITEM + 1;
    CHECK(gzt_tx_serialize(&tx2, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_ERR_ARG);
    /* legacy form drops marker, flag and witness: 2 + 1 + 1 + 64 bytes */
    CHECK(gzt_tx_serialize(&tx, GZT_SER_NO_WITNESS, back, sizeof back, &m) == GZT_OK);
    CHECK(m == pos - 68);
}

/* ---- sizes and fees --------------------------------------------------------- */

static void test_sizes_and_fees(void) {
    /* the formula against the weight of real serialisations */
    int formula_ok = 1;
    for (size_t n_in = 1; n_in <= GZT_MAX_INPUTS; n_in++) {
        for (size_t n_out = 1; n_out <= 3; n_out++) {
            size_t lens[3] = {34, 22, 34};
            uint64_t w, vs;
            memset(&tx, 0, sizeof tx);
            tx.n_in = (uint32_t)n_in;
            tx.n_out = (uint32_t)n_out;
            for (size_t i = 0; i < n_in; i++) {
                tx.in[i].witness_count = 1;
                tx.in[i].witness[0].len = 64;
            }
            for (size_t i = 0; i < n_out; i++) tx.out[i].script_len = (uint16_t)lens[i];
            if (gzt_tx_weight(&tx, &w, &vs) != GZT_OK ||
                gzt_keypath_vsize(n_in, lens, n_out) != vs || vs != (w + 3) / 4)
                formula_ok = 0;
        }
    }
    CHECK(formula_ok);
    /* gzt_tx_weight (counted) and the formula against real serialisations,
       for every witness-program length of the destination, with and without
       change, and 1, 2, 63 and 64 inputs */
    static const size_t dest_lens[] = {22, 34, 4, 5, 10, 20, 33, 35, 41, 42};
    static const size_t n_ins[] = {1, 2, 63, 64};
    int counted_ok = 1;
    for (size_t d = 0; d < sizeof dest_lens / sizeof dest_lens[0]; d++)
        for (size_t c = 0; c < 2; c++)
            for (size_t k = 0; k < 4; k++) {
                size_t lens[2] = {dest_lens[d], 34}, lw, ln;
                uint64_t w, vs;
                memset(&tx, 0, sizeof tx);
                tx.n_in = (uint32_t)n_ins[k];
                tx.n_out = (uint32_t)(1 + c);
                for (size_t i = 0; i < tx.n_in; i++) {
                    tx.in[i].witness_count = 1;
                    tx.in[i].witness[0].len = 64;
                }
                for (size_t i = 0; i < tx.n_out; i++) tx.out[i].script_len = (uint16_t)lens[i];
                if (gzt_tx_weight(&tx, &w, &vs) != GZT_OK ||
                    gzt_tx_serialize(&tx, GZT_SER_WITNESS, back, sizeof back, &lw) != GZT_OK ||
                    gzt_tx_serialize(&tx, GZT_SER_NO_WITNESS, back, sizeof back, &ln) != GZT_OK ||
                    w != 3 * ln + lw || vs != (w + 3) / 4 ||
                    gzt_keypath_vsize(tx.n_in, lens, tx.n_out) != vs)
                    counted_ok = 0;
            }
    CHECK(counted_ok);
    size_t one = 34;
    CHECK(gzt_keypath_vsize(1, &one, 1) == 111); /* 1 in, 1 P2TR out: 444 WU / 4 */
    CHECK(gzt_keypath_vsize(0, &one, 1) == 0);
    CHECK(gzt_keypath_vsize(GZT_MAX_INPUTS + 1, &one, 1) == 0);

    gzt_feerate r = {GZT_FEERATE_TEST_DEFAULT_SAT_PER_KVB}, c, got;
    CHECK(r.sat_per_kvb == 100);
    CHECK(gzt_fee_for_vsize(r, 150) == 15);
    CHECK(gzt_fee_for_vsize(r, 153) == 16);
    CHECK(gzt_fee_for_vsize(r, 0) == 0);
    c.sat_per_kvb = GZT_FEERATE_MAX_SAT_PER_KVB;
    CHECK(gzt_fee_for_vsize(c, 1000000) == UINT64_C(100000000000));
    c.sat_per_kvb++;
    CHECK(gzt_fee_for_vsize(c, 1) == UINT64_MAX);
    CHECK(gzt_fee_for_vsize(r, 1000001) == UINT64_MAX);

    c.sat_per_kvb = 1000;
    CHECK(gzt_feerate_from_server(1000, c, &got) == GZT_OK && got.sat_per_kvb == 1000);
    CHECK(gzt_feerate_from_server(1001, c, &got) == GZT_ERR_FEE_CEILING && got.sat_per_kvb == 0);
    CHECK(gzt_feerate_from_server(0, c, &got) == GZT_ERR_ARG);
    c.sat_per_kvb = 0;
    CHECK(gzt_feerate_from_server(1, c, &got) == GZT_ERR_ARG);
    c.sat_per_kvb = GZT_FEERATE_MAX_SAT_PER_KVB + 1;
    CHECK(gzt_feerate_from_server(1, c, &got) == GZT_ERR_ARG);
}

static void test_dust_and_networks(void) {
    uint8_t s[45];
    memset(s, 0x11, sizeof s);
    s[0] = 0x51; s[1] = 32;
    CHECK(gzt_dust_limit(s, 34) == 330);
    s[0] = 0x00; s[1] = 20;
    CHECK(gzt_dust_limit(s, 22) == 294);
    s[1] = 32;
    CHECK(gzt_dust_limit(s, 34) == 330);
    s[1] = 21;
    CHECK(gzt_dust_limit(s, 23) == 0);             /* v0 needs 20 or 32 bytes */
    s[0] = 0x60; s[1] = 40;
    CHECK(gzt_is_witness_program(s, 42) == 1);     /* v16, 40 bytes */
    s[1] = 41;
    CHECK(gzt_is_witness_program(s, 43) == 0);
    s[0] = 0x52; s[1] = 2;
    CHECK(gzt_is_witness_program(s, 4) == 1);      /* v2, 2 bytes */
    s[1] = 1;
    CHECK(gzt_is_witness_program(s, 3) == 0);
    s[0] = 0x61; s[1] = 32;
    CHECK(gzt_is_witness_program(s, 34) == 0);     /* not OP_1..OP_16 */
    s[0] = 0x50;
    CHECK(gzt_is_witness_program(s, 34) == 0);
    s[0] = 0x6a; s[1] = 32;
    CHECK(gzt_dust_limit(s, 34) == 0);             /* OP_RETURN */
    uint8_t p2pkh[25] = {0x76, 0xa9, 0x14};
    CHECK(gzt_dust_limit(p2pkh, 25) == 0);
    s[0] = 0x51; s[1] = 33;
    CHECK(gzt_is_witness_program(s, 34) == 0);     /* push length disagrees */

    gzt_network net;
    gzw_network k;
    CHECK(gzt_network_from_name("mainnet", &net) == GZT_ERR_MAINNET);
    CHECK(gzt_network_from_name("bitcoin", &net) == GZT_ERR_ARG);
    CHECK(gzt_network_from_name("signet", &net) == GZT_OK && gzt_network_eq(net, GZT_NET_SIGNET));
    CHECK(gzt_network_to_keys(net, &k) == GZT_OK && k == GZW_NET_SIGNET);
    CHECK(gzt_network_from_name("testnet", &net) == GZT_OK && gzt_network_to_keys(net, &k) == 0 &&
          k == GZW_NET_TESTNET);
    CHECK(gzt_network_from_name("testnet4", &net) == GZT_OK && gzt_network_to_keys(net, &k) == 0 &&
          k == GZW_NET_TESTNET4);
    CHECK(gzt_network_from_name("regtest", &net) == GZT_OK && gzt_network_to_keys(net, &k) == 0 &&
          k == GZW_NET_REGTEST);
    CHECK(gzt_network_to_keys((gzt_network){0}, &k) == GZT_ERR_ARG);
    CHECK(gzt_network_to_keys((gzt_network){5}, &k) == GZT_ERR_ARG);
    for (int e = 0; e <= 14; e++) CHECK(gzt_err_text((gzt_err)e) != NULL);
}

/* ---- coin selection against an independent model ------------------------ */

static uint64_t rng = 0x9e3779b97f4a7c15u;
static uint64_t rnd(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}

static const gzt_coin *model_coins;
static int model_cmp(const void *x, const void *y) {
    const gzt_coin *a = &model_coins[*(const uint32_t *)x], *c = &model_coins[*(const uint32_t *)y];
    if (a->amount != c->amount) return a->amount > c->amount ? -1 : 1;
    int t = memcmp(a->txid, c->txid, 32);
    if (t) return t;
    return a->vout < c->vout ? -1 : a->vout > c->vout;
}

/* Written from docs/notes/wallet-tx.md section 1.7, with its own size
   arithmetic (11 vB per input of witness discount worked out by hand:
   input 41 bytes + 66/4 witness). */
static gzt_err model(const gzt_coin *coins, size_t n, uint64_t amount, uint64_t rate,
                     uint64_t ceil_rate, gzt_selection *out) {
    static uint32_t idx[GZT_MAX_COINS];
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < n; i++) idx[i] = (uint32_t)i;
    model_coins = coins;
    qsort(idx, n, sizeof idx[0], model_cmp);
    uint64_t total = 0;
    int over = 0;
    for (size_t k = 1; k <= n && k <= GZT_MAX_INPUTS; k++) {
        total += coins[idx[k - 1]].amount;
        uint64_t cs = k < 0xfd ? 1 : 3;
        uint64_t w_nc = 4 * (4 + cs + 41 * k + 1 + 43 + 4) + 2 + 66 * k;
        uint64_t vs_nc = (w_nc + 3) / 4, vs_c = (w_nc + 4 * 43 + 3) / 4;
        uint64_t f_nc = (vs_nc * rate + 999) / 1000, f_c = (vs_c * rate + 999) / 1000;
        if (total < amount + f_nc) continue;
        if (total - amount >= f_c + 330) {
            out->has_change = 1, out->change = total - amount - f_c, out->fee = f_c, out->vsize = vs_c;
        } else if ((total - amount) * 1000 <= ((vs_nc * ceil_rate + 999) / 1000) * 1000) {
            out->fee = total - amount, out->vsize = vs_nc;
        } else {
            over = 1;
            continue;
        }
        out->n_selected = (uint32_t)k;
        memcpy(out->selected, idx, k * sizeof idx[0]);
        out->total_in = total;
        return GZT_OK;
    }
    if (over) return GZT_ERR_FEE_CEILING;
    /* more coins than inputs allowed, and all of them would pay the no-change
       fee of a 64-input transaction: the cap is what stops it */
    uint64_t all = 0, w64 = 4 * (4 + 1 + 41 * 64 + 1 + 43 + 4) + 2 + 66 * 64;
    for (size_t i = 0; i < n; i++) all += coins[i].amount;
    if (n > GZT_MAX_INPUTS && all >= amount + (((w64 + 3) / 4) * rate + 999) / 1000)
        return GZT_ERR_LIMIT;
    return GZT_ERR_FUNDS;
}

static uint8_t P2TR_DEST[34] = {0x51, 0x20, 0xaa};

static void test_selection(void) {
    static gzt_coin coins[300], shuffled[300];
    static uint32_t perm[300];
    gzt_selection a, m, s;
    int agree = 1, stable = 1, balanced = 1, hits[15] = {0};
    for (int round = 0; round < 2000; round++) {
        size_t n = 1 + rnd() % (round % 10 == 0 ? 300 : 12);
        int scale = (int)(rnd() % 4);
        for (size_t i = 0; i < n; i++) {
            memset(&coins[i], 0, sizeof coins[i]);
            coins[i].txid[0] = (uint8_t)(rnd() % 4); /* ties in txid, and in amount below */
            coins[i].txid[1] = (uint8_t)i;
            coins[i].txid[2] = (uint8_t)(i >> 8);
            coins[i].vout = (uint32_t)(rnd() % 3);
            uint64_t base = scale == 0 ? 400 : scale == 1 ? 2000 : scale == 2 ? 100000 : 5;
            coins[i].amount = 330 + rnd() % base;
            if (rnd() % 4 == 0 && i) coins[i].amount = coins[i - 1].amount;
        }
        uint64_t amount = 330 + rnd() % (scale == 3 ? 2000 : 50000);
        gzt_fee_policy fp = {{100 + rnd() % 3000}, {0}};
        fp.ceiling.sat_per_kvb = fp.rate.sat_per_kvb + (rnd() % 2 ? 0 : rnd() % 5000);
        gzt_err e1 = gzt_select_coins(coins, n, P2TR_DEST, 34, amount, fp, &a);
        gzt_err e2 = model(coins, n, amount, fp.rate.sat_per_kvb, fp.ceiling.sat_per_kvb, &m);
        hits[e1 < 15 ? e1 : 14]++;
        if (e1 != e2 || memcmp(&a, &m, sizeof a) != 0) agree = 0;
        if (e1 == GZT_OK && a.total_in != amount + a.fee + a.change) balanced = 0;
        if (e1 == GZT_OK && a.has_change && a.change < 330) balanced = 0;
        /* shuffled: the same coins chosen, in the same order */
        for (size_t i = 0; i < n; i++) perm[i] = (uint32_t)i;
        for (size_t i = n; i > 1; i--) {
            size_t j = rnd() % i;
            uint32_t t = perm[i - 1]; perm[i - 1] = perm[j]; perm[j] = t;
        }
        for (size_t i = 0; i < n; i++) shuffled[i] = coins[perm[i]];
        if (gzt_select_coins(shuffled, n, P2TR_DEST, 34, amount, fp, &s) != e1) stable = 0;
        if (e1 == GZT_OK) {
            if (s.n_selected != a.n_selected || s.fee != a.fee || s.change != a.change) stable = 0;
            for (uint32_t i = 0; i < s.n_selected && i < a.n_selected; i++)
                if (perm[s.selected[i]] != a.selected[i]) stable = 0;
        }
    }
    CHECK(agree);
    CHECK(stable);
    CHECK(balanced);
    /* the random sets reach success, lack of funds and the ceiling */
    CHECK(hits[GZT_OK] > 100 && hits[GZT_ERR_FUNDS] > 20 && hits[GZT_ERR_FEE_CEILING] > 5);
    CHECK(hits[GZT_ERR_LIMIT] > 0);
    printf("selection: %d ok, %d funds, %d ceiling, %d limit of 2000 random sets\n", hits[GZT_OK],
           hits[GZT_ERR_FUNDS], hits[GZT_ERR_FEE_CEILING], hits[GZT_ERR_LIMIT]);

    /* refusals */
    gzt_fee_policy fp = {{100}, {1000}};
    memset(coins, 0, 3 * sizeof coins[0]);
    coins[0].amount = 100000; coins[0].txid[0] = 1;
    coins[1].amount = 50000;  coins[1].txid[0] = 2;
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, 10000, fp, &a) == GZT_OK);
    CHECK(a.n_selected == 1 && a.selected[0] == 0 && a.has_change && a.vsize == 154);
    CHECK(a.fee == 16 && a.change == 100000 - 10000 - 16);
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, 329, fp, &a) == GZT_ERR_DUST);
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, 330, fp, &a) == GZT_OK);
    uint8_t p2wpkh[22] = {0x00, 0x14};
    CHECK(gzt_select_coins(coins, 2, p2wpkh, 22, 293, fp, &a) == GZT_ERR_DUST);
    CHECK(gzt_select_coins(coins, 2, p2wpkh, 22, 294, fp, &a) == GZT_OK);
    /* a 2-byte program (P2A shape) would give a 64-byte transaction: refused;
       3 bytes is the shortest accepted */
    uint8_t short_prog[5] = {0x51, 0x02, 0x4e, 0x73, 0x00};
    CHECK(gzt_select_coins(coins, 2, short_prog, 4, 10000, fp, &a) == GZT_ERR_SCRIPT);
    short_prog[0] = 0x52; short_prog[1] = 0x03;
    CHECK(gzt_select_coins(coins, 2, short_prog, 5, 10000, fp, &a) == GZT_OK);
    uint8_t p2pkh[25] = {0x76, 0xa9, 0x14};
    CHECK(gzt_select_coins(coins, 2, p2pkh, 25, 10000, fp, &a) == GZT_ERR_SCRIPT);
    uint8_t ret[34] = {0x6a, 0x20};
    CHECK(gzt_select_coins(coins, 2, ret, 34, 10000, fp, &a) == GZT_ERR_SCRIPT);
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, 150000, fp, &a) == GZT_ERR_FUNDS);
    gzt_fee_policy bad = {{0}, {1000}};
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, 10000, bad, &a) == GZT_ERR_ARG);
    bad.rate.sat_per_kvb = 1001;
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, 10000, bad, &a) == GZT_ERR_FEE_CEILING);
    bad.rate.sat_per_kvb = 1000;
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, 10000, bad, &a) == GZT_OK);
    bad.ceiling.sat_per_kvb = bad.rate.sat_per_kvb = GZT_FEERATE_MAX_SAT_PER_KVB + 1;
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, 10000, bad, &a) == GZT_ERR_ARG);
    coins[2] = coins[0];
    CHECK(gzt_select_coins(coins, 3, P2TR_DEST, 34, 10000, fp, &a) == GZT_ERR_ARG); /* duplicate */
    coins[2].vout = 1;
    CHECK(gzt_select_coins(coins, 3, P2TR_DEST, 34, 10000, fp, &a) == GZT_OK);
    coins[2].amount = GZT_MAX_MONEY + 1;
    CHECK(gzt_select_coins(coins, 3, P2TR_DEST, 34, 10000, fp, &a) == GZT_ERR_ARG);
    coins[2].amount = GZT_MAX_MONEY;
    CHECK(gzt_select_coins(coins, 3, P2TR_DEST, 34, 10000, fp, &a) == GZT_ERR_ARG); /* total */
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, GZT_MAX_MONEY + 1, fp, &a) == GZT_ERR_ARG);
    CHECK(gzt_select_coins(coins, GZT_MAX_COINS + 1, P2TR_DEST, 34, 1000, fp, &a) == GZT_ERR_LIMIT);
    CHECK(gzt_select_coins(coins, 0, P2TR_DEST, 34, 1000, fp, &a) == GZT_ERR_ARG);

    /* small change given up to the fee, within the ceiling and beyond it */
    gzt_fee_policy tight = {{100}, {100}};
    coins[0].amount = 10000 + 12 + 100; /* fee without change 12 (111 vB), 100 left over */
    CHECK(gzt_select_coins(coins, 1, P2TR_DEST, 34, 10000, tight, &a) == GZT_ERR_FEE_CEILING);
    tight.ceiling.sat_per_kvb = 1009;   /* 112 sat for 111 vB is allowed */
    CHECK(gzt_select_coins(coins, 1, P2TR_DEST, 34, 10000, tight, &a) == GZT_OK);
    CHECK(!a.has_change && a.fee == 112 && a.vsize == 111);
    tight.ceiling.sat_per_kvb = 1000;   /* 111 sat allowed: one short */
    CHECK(gzt_select_coins(coins, 1, P2TR_DEST, 34, 10000, tight, &a) == GZT_ERR_FEE_CEILING);
    coins[0].amount = 10000 + 16 + 330; /* change of exactly 330 */
    CHECK(gzt_select_coins(coins, 1, P2TR_DEST, 34, 10000, fp, &a) == GZT_OK);
    CHECK(a.has_change && a.change == 330);
    coins[0].amount = 10000 + 16 + 329; /* 345 left over without change: 3.1 sat/vB */
    CHECK(gzt_select_coins(coins, 1, P2TR_DEST, 34, 10000, fp, &a) == GZT_ERR_FEE_CEILING);
    fp.ceiling.sat_per_kvb = 4000;
    CHECK(gzt_select_coins(coins, 1, P2TR_DEST, 34, 10000, fp, &a) == GZT_OK);
    CHECK(!a.has_change && a.fee == 345);

    /* more coins than inputs allowed, and all 64 largest needed: the
       selection is exactly those, largest first */
    static const size_t N = 100;
    for (size_t i = 0; i < N; i++) {
        size_t v = (i * 37) % N; /* a permutation of 0..99 */
        memset(&coins[i], 0, sizeof coins[i]);
        coins[i].txid[0] = (uint8_t)i;
        coins[i].amount = 1000 + v;
    }
    size_t one = 34;
    uint64_t top = 64 * 1000 + (36 + 99) * 64 / 2;
    gzt_fee_policy wide = {{100}, {100000}};
    uint64_t want = top - gzt_fee_for_vsize(wide.rate, gzt_keypath_vsize(64, &one, 1)) - 100;
    CHECK(gzt_select_coins(coins, N, P2TR_DEST, 34, want, wide, &a) == GZT_OK);
    int top_ok = a.n_selected == 64 && !a.has_change && a.total_in == top;
    for (uint32_t i = 0; top_ok && i < 64; i++) top_ok = coins[a.selected[i]].amount == 1099 - i;
    CHECK(top_ok);
    /* the 100 coins would pay, the 64 largest cannot: the cap, not the funds */
    CHECK(gzt_select_coins(coins, N, P2TR_DEST, 34, want + 101, wide, &a) == GZT_ERR_LIMIT);
    CHECK(gzt_select_coins(coins, 64, P2TR_DEST, 34, want + 101, wide, &a) == GZT_ERR_FUNDS);
    CHECK(gzt_select_coins(coins, N, P2TR_DEST, 34, 100000 + 4950, wide, &a) == GZT_ERR_FUNDS);
    /* the cap rule at its edge: all 100 coins exactly cover amount + the
       64-input fee */
    uint64_t fee64 = gzt_fee_for_vsize(wide.rate, gzt_keypath_vsize(64, &one, 1));
    CHECK(gzt_select_coins(coins, N, P2TR_DEST, 34, 104950 - fee64, wide, &a) == GZT_ERR_LIMIT);
    CHECK(gzt_select_coins(coins, N, P2TR_DEST, 34, 104950 - fee64 + 1, wide, &a) == GZT_ERR_FUNDS);
}

/* ---- the funding ------------------------------------------------------------ */

static void make_coin(const secp256k1_context *ctx, const gzw_xprv *master, gzt_coin *c,
                      uint32_t change, uint32_t index, uint64_t amount) {
    gzw_bip86_output o;
    memset(c, 0, sizeof *c);
    CHECK(gzw_bip86_output_from_master(ctx, master, GZW_NET_SIGNET, 0, change, index, &o, NULL));
    memcpy(c->script, o.script_pubkey, 34);
    c->txid[0] = (uint8_t)(0x40 + index);
    c->txid[1] = (uint8_t)change;
    c->vout = index % 3;
    c->change = change;
    c->index = index;
    c->amount = amount;
}

static int contains(const void *hay, size_t n, const uint8_t *needle, size_t m) {
    const uint8_t *h = hay;
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(h + i, needle, m) == 0) return 1;
    return 0;
}

/* Release must refuse and leave out zeroed (prefilled with 0xaa). */
static int refused(const secp256k1_context *ctx, const gzw_xprv *master, const gzt_funding *f,
                   const uint8_t *expect, const uint8_t *aux, gzt_err want) {
    size_t len = 99;
    memset(back, 0xaa, 500);
    gzt_err e = gzt_funding_release(ctx, master, f, expect, aux, back, 500, &len);
    return e == want && len == 0 && all_zero(back, 500);
}

static void test_funding(const secp256k1_context *ctx) {
    gzw_xprv master, other;
    static gzt_coin coins[GZT_MAX_INPUTS + 2];
    static gzt_funding f, g;
    gzt_spent_output spent[GZT_MAX_INPUTS];
    uint8_t aux[32], aux2[32], factory[34] = {0x51, 0x20}, wrong[32], seed[64];
    memset(aux, 0x5a, sizeof aux); /* no zero byte, so every byte of the rule shows */
    memset(aux2, 0xc3, sizeof aux2);
    memset(seed, 0x01, sizeof seed);
    size_t len;
    CHECK(public_master(ctx, &master));
    CHECK(gzw_bip32_master(ctx, seed, 64, &other, NULL));
    memset(factory + 2, 0xfa, 32);

    gzt_funding_request req = {GZT_NET_SIGNET, 0, factory, 34, 150000, 3, {{100}, {1000}}, NULL, 0};
    make_coin(ctx, &master, &coins[0], 0, 0, 100000);
    make_coin(ctx, &master, &coins[1], 0, 1, 80000);
    make_coin(ctx, &master, &coins[2], 1, 0, 1000);
    CHECK(gzt_funding_build(ctx, &master, &req, coins, 3, aux, &f) == GZT_OK);
    CHECK(f.info.vout == 0 && f.info.amount == 150000 && f.info.has_change);
    CHECK(f.info.selection.n_selected == 2 && f.info.change_index == 3);

    /* the held funding has no signature in it: the one build made for input 0
       (aux rule, same message) is nowhere in the struct, and no input has a
       witness */
    CHECK(gzt_funding_release(ctx, &master, &f, f.info.txid, aux, raw, sizeof raw, &len) == GZT_OK);
    CHECK(gzt_tx_parse(raw, len, &tx) == GZT_OK && tx.in[0].witness[0].len == 64);
    CHECK(!contains(&f, sizeof f, tx.in[0].witness[0].data, 64));
    CHECK(!contains(&f, sizeof f, tx.in[0].witness[0].data, 32)); /* not even R */
    CHECK(f.priv_tx.in[0].witness_count == 0 && f.priv_tx.in[1].witness_count == 0);

    /* the gate */
    memcpy(wrong, f.info.txid, 32);
    wrong[31] ^= 1;
    CHECK(refused(ctx, &master, &f, wrong, aux, GZT_ERR_STATE));
    memset(&g, 0, sizeof g);
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_STATE));
    g = f; g.priv_state = 3;
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_STATE));
    /* a forged info.txid, asked for: the recomputed txid differs */
    g = f; memset(g.info.txid, 0x42, 32);
    CHECK(refused(ctx, &master, &g, g.info.txid, aux, GZT_ERR_STATE));
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_STATE));
    /* the stored transaction edited (value moved from output 0 to change) */
    g = f; g.priv_tx.out[0].value -= 1000; g.priv_tx.out[1].value += 1000;
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_STATE));
    uint8_t edited[32];
    CHECK(gzt_tx_txid(&g.priv_tx, edited) == GZT_OK);
    memcpy(g.info.txid, edited, 32); /* and info.txid made to match it */
    CHECK(refused(ctx, &master, &g, edited, aux, GZT_ERR_STATE)); /* amount disagrees */
    g = f; g.priv_tx.out[1].value -= 1; /* fee no longer adds up */
    CHECK(gzt_tx_txid(&g.priv_tx, g.info.txid) == GZT_OK);
    CHECK(refused(ctx, &master, &g, g.info.txid, aux, GZT_ERR_STATE));
    g = f; g.priv_spent[0].amount += 1;
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_STATE));
    /* amounts beyond 21 million whose sums wrap round to the right totals */
    g = f; g.priv_spent[0].amount += UINT64_C(1) << 63; g.priv_spent[1].amount += UINT64_C(1) << 63;
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_STATE));
    g = f; g.priv_tx.out[1].value += UINT64_C(1) << 63; g.info.fee += UINT64_C(1) << 63;
    CHECK(gzt_tx_txid(&g.priv_tx, g.info.txid) == GZT_OK);
    CHECK(refused(ctx, &master, &g, g.info.txid, aux, GZT_ERR_STATE));
    g = f; g.priv_spent[0].script[33] ^= 1; /* signer refuses: key is not the script's */
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_KEY));
    g = f; g.priv_key_index[0] ^= 1;
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_KEY));
    /* counts beyond the caps are refused before anything is written */
    g = f; g.priv_tx.n_in = 200;
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_STATE));
    g = f; g.priv_tx.n_in = 0;
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_STATE));
    g = f; g.priv_tx.n_out = GZT_MAX_OUTPUTS + 1;
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_STATE));
    g = f; g.priv_tx.in[1].witness_count = 1; /* a witness in the held form */
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_STATE));
    g = f; g.priv_net.id = 0;
    CHECK(refused(ctx, &master, &g, f.info.txid, aux, GZT_ERR_ARG));
    /* another wallet's key, and a key that is not a master key */
    CHECK(refused(ctx, &other, &f, f.info.txid, aux, GZT_ERR_KEY));
    gzw_xprv child;
    CHECK(gzw_bip32_child_priv(ctx, &master, 1, &child, NULL));
    CHECK(refused(ctx, &child, &f, f.info.txid, aux, GZT_ERR_ARG));
    /* a buffer one byte short: refused, and nothing of the transaction left */
    size_t full = len;
    memset(back, 0xaa, full);
    CHECK(gzt_funding_release(ctx, &master, &f, f.info.txid, aux, back, full - 1, &len) ==
              GZT_ERR_BUFFER && len == 0 && all_zero(back, full - 1));
    CHECK(gzt_funding_release(ctx, &master, &f, f.info.txid, aux, back, full, &len) == GZT_OK &&
          len == full && memcmp(back, raw, full) == 0); /* same aux: the same bytes */

    /* released with other randomness: other signatures, the same txid */
    CHECK(gzt_funding_release(ctx, &master, &f, f.info.txid, aux2, raw, sizeof raw, &len) == GZT_OK);
    CHECK(len == full && memcmp(back, raw, len) != 0);

    /* the released bytes, checked from outside */
    uint8_t txid[32], hash[32];
    uint64_t w, vs;
    CHECK(gzt_tx_parse(raw, len, &tx) == GZT_OK);
    CHECK(gzt_tx_txid(&tx, txid) == GZT_OK && memcmp(txid, f.info.txid, 32) == 0);
    CHECK(gzt_tx_weight(&tx, &w, &vs) == GZT_OK && vs == f.info.vsize && vs == 212);
    CHECK(tx.version == 2 && tx.locktime == 0 && tx.n_in == 2 && tx.n_out == 2);
    CHECK(tx.out[0].value == 150000 && memcmp(tx.out[0].script, factory, 34) == 0);
    gzw_bip86_output ch;
    CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 0, 1, 3, &ch, NULL));
    CHECK(tx.out[1].script_len == 34 && memcmp(tx.out[1].script, ch.script_pubkey, 34) == 0);
    CHECK(180000 == tx.out[0].value + tx.out[1].value + f.info.fee && f.info.fee == 22);
    memset(spent, 0, sizeof spent);
    for (uint32_t i = 0; i < tx.n_in; i++) {
        const gzt_coin *c = &coins[f.info.selection.selected[i]];
        CHECK(memcmp(tx.in[i].prev_txid, c->txid, 32) == 0 && tx.in[i].prev_vout == c->vout);
        CHECK(tx.in[i].sequence == 0xfffffffeu && tx.in[i].script_sig_len == 0);
        spent[i].amount = c->amount;
        spent[i].script_len = 34;
        memcpy(spent[i].script, c->script, 34);
    }
    for (uint32_t i = 0; i < tx.n_in; i++) {
        secp256k1_xonly_pubkey pk;
        CHECK(tx.in[i].witness_count == 1 && tx.in[i].witness[0].len == 64);
        CHECK(gzt_sighash_keypath(&tx, spent, i, GZT_SIGHASH_DEFAULT, hash) == GZT_OK);
        CHECK(secp256k1_xonly_pubkey_parse(ctx, &pk, spent[i].script + 2));
        CHECK(secp256k1_schnorrsig_verify(ctx, tx.in[i].witness[0].data, hash, 32, &pk));
        /* input i was signed with SHA-256(aux || i, little-endian) as its
           auxiliary randomness (section 1.8, decision 8) */
        const gzt_coin *c = &coins[f.info.selection.selected[i]];
        secp256k1_keypair kp;
        uint8_t aux_in[36], aux_i[32], sig[64];
        memcpy(aux_in, aux2, 32);
        aux_in[32] = (uint8_t)i; aux_in[33] = aux_in[34] = aux_in[35] = 0;
        SHA256(aux_in, 36, aux_i);
        CHECK(gzw_bip86_tweaked_keypair(ctx, &master, GZW_NET_SIGNET, 0, c->change, c->index, &kp,
                                        NULL, NULL));
        CHECK(secp256k1_schnorrsig_sign32(ctx, sig, hash, &kp, aux_i));
        CHECK(memcmp(sig, tx.in[i].witness[0].data, 64) == 0);
    }
    /* the same request and coins in another order give the same transaction,
       and so does a rebuild with other randomness */
    gzt_coin rev[3] = {coins[2], coins[1], coins[0]};
    CHECK(gzt_funding_build(ctx, &master, &req, rev, 3, aux2, &g) == GZT_OK);
    CHECK(memcmp(g.info.txid, f.info.txid, 32) == 0);

    /* a build into a value that held something else gives the same bytes */
    static gzt_funding dirty;
    memset(&dirty, 0x77, sizeof dirty);
    CHECK(gzt_funding_build(ctx, &master, &req, coins, 3, aux, &dirty) == GZT_OK);
    CHECK(gzt_funding_build(ctx, &master, &req, coins, 3, aux, &g) == GZT_OK);
    CHECK(memcmp(&dirty, &g, sizeof g) == 0);

    /* a change-chain coin, in account 1, is spent and released correctly */
    {
        gzw_bip86_output o1, o2;
        gzt_coin ac[2];
        memset(ac, 0, sizeof ac);
        CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 1, 1, 5, &o1, NULL));
        CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 1, 0, 2, &o2, NULL));
        memcpy(ac[0].script, o1.script_pubkey, 34);
        ac[0].change = 1; ac[0].index = 5; ac[0].amount = 60000; ac[0].txid[0] = 0x91;
        memcpy(ac[1].script, o2.script_pubkey, 34);
        ac[1].change = 0; ac[1].index = 2; ac[1].amount = 50000; ac[1].txid[0] = 0x92;
        gzt_funding_request ra = req;
        ra.account = 1; ra.amount = 100000; ra.change_index = 6;
        CHECK(gzt_funding_build(ctx, &master, &ra, ac, 2, aux, &g) == GZT_OK);
        CHECK(g.info.selection.n_selected == 2 && g.info.selection.selected[0] == 0);
        CHECK(gzt_funding_release(ctx, &master, &g, g.info.txid, aux, raw, sizeof raw, &len) ==
              GZT_OK);
        CHECK(gzt_tx_parse(raw, len, &tx) == GZT_OK);
        gzt_spent_output sp[2];
        memset(sp, 0, sizeof sp);
        int sig_ok = 1;
        for (int i = 0; i < 2; i++) {
            sp[i].amount = ac[i].amount; sp[i].script_len = 34;
            memcpy(sp[i].script, ac[i].script, 34);
        }
        for (uint32_t i = 0; i < 2; i++) {
            secp256k1_xonly_pubkey pk;
            uint8_t hh[32];
            if (gzt_sighash_keypath(&tx, sp, i, 0, hh) != GZT_OK ||
                !secp256k1_xonly_pubkey_parse(ctx, &pk, sp[i].script + 2) ||
                !secp256k1_schnorrsig_verify(ctx, tx.in[i].witness[0].data, hh, 32, &pk))
                sig_ok = 0;
        }
        CHECK(sig_ok);
        gzw_bip86_output c6;
        CHECK(gzw_bip86_output_from_master(ctx, &master, GZW_NET_SIGNET, 1, 1, 6, &c6, NULL));
        CHECK(tx.n_out == 2 && memcmp(tx.out[1].script, c6.script_pubkey, 34) == 0);
    }

    /* every size from 1 to 64 inputs: the size the fee was paid for is the real one */
    int sizes_ok = 1;
    size_t one = 34;
    for (uint32_t n = 1; n <= GZT_MAX_INPUTS; n++) {
        for (uint32_t i = 0; i < n; i++) make_coin(ctx, &master, &coins[i], 0, i, 2000);
        uint64_t left = (n % 2) ? gzt_fee_for_vsize(req.fee.rate, gzt_keypath_vsize(n, &one, 1)) + 50
                                : 1500; /* odd: no change, a little over the fee; even: change */
        req.amount = 2000 * n - left; /* n - 1 coins are not enough */
        req.fee.ceiling.sat_per_kvb = 100000;
        if (gzt_funding_build(ctx, &master, &req, coins, n, aux, &g) != GZT_OK ||
            g.info.selection.n_selected != n || g.info.has_change != !(n % 2) ||
            gzt_funding_release(ctx, &master, &g, g.info.txid, aux, raw, sizeof raw, &len) != GZT_OK ||
            gzt_tx_parse(raw, len, &tx) != GZT_OK || gzt_tx_weight(&tx, &w, &vs) != GZT_OK ||
            vs != g.info.vsize || tx.out[0].value != req.amount || tx.n_in != n ||
            tx.in[n - 1].witness_count != 1 ||
            g.info.fee < gzt_fee_for_vsize(req.fee.rate, vs) ||
            g.info.fee > gzt_fee_for_vsize(req.fee.ceiling, vs))
            sizes_ok = 0;
    }
    CHECK(sizes_ok);
    req.amount = 150000;
    req.fee.ceiling.sat_per_kvb = 1000;
    make_coin(ctx, &master, &coins[0], 0, 0, 100000);
    make_coin(ctx, &master, &coins[1], 0, 1, 80000);
    make_coin(ctx, &master, &coins[2], 1, 0, 1000);

    /* refusals; *out is wiped on each */
    gzt_coin bad = coins[0];
    bad.index = 9; /* claims another path than its script's */
    gzt_coin set[2] = {bad, coins[1]};
    CHECK(gzt_funding_build(ctx, &master, &req, set, 2, aux, &g) == GZT_ERR_KEY);
    CHECK(all_zero(&g, sizeof g));
    req.change_index = 0; /* coin 2 is change index 0 */
    CHECK(gzt_funding_build(ctx, &master, &req, coins, 3, aux, &g) == GZT_ERR_ARG);
    gzt_coin first[3] = {coins[2], coins[0], coins[1]}; /* the same, offered first */
    CHECK(gzt_funding_build(ctx, &master, &req, first, 3, aux, &g) == GZT_ERR_ARG);
    req.change_index = 3;
    /* a change index already used by a coin that is not offered */
    uint32_t used[3] = {7, 3, 9};
    gzt_funding_request r2 = req;
    r2.used_change_indexes = used; r2.n_used_change_indexes = 3;
    CHECK(gzt_funding_build(ctx, &master, &r2, coins, 3, aux, &g) == GZT_ERR_ARG);
    r2.n_used_change_indexes = 1;
    CHECK(gzt_funding_build(ctx, &master, &r2, coins, 3, aux, &g) == GZT_OK);
    r2.used_change_indexes = used + 1; /* 3 first in the list */
    CHECK(gzt_funding_build(ctx, &master, &r2, coins, 3, aux, &g) == GZT_ERR_ARG);
    r2.used_change_indexes = NULL;
    CHECK(gzt_funding_build(ctx, &master, &r2, coins, 3, aux, &g) == GZT_ERR_ARG);
    r2 = req;
    r2.net.id = 0;
    CHECK(gzt_funding_build(ctx, &master, &r2, coins, 3, aux, &g) == GZT_ERR_ARG);
    r2 = req;
    r2.funding_script = ch.script_pubkey; /* paying the funding to our own change */
    CHECK(gzt_funding_build(ctx, &master, &r2, coins, 3, aux, &g) == GZT_ERR_ARG);
    r2 = req;
    r2.change_index = GZW_HARDENED;
    CHECK(gzt_funding_build(ctx, &master, &r2, coins, 3, aux, &g) == GZT_ERR_ARG);
    r2 = req;
    r2.account = GZW_HARDENED;
    CHECK(gzt_funding_build(ctx, &master, &r2, coins, 3, aux, &g) == GZT_ERR_ARG);
    r2 = req;
    r2.amount = 200;
    CHECK(gzt_funding_build(ctx, &master, &r2, coins, 3, aux, &g) == GZT_ERR_DUST);
    /* the funding output is P2TR and nothing else */
    uint8_t other_script[42];
    memset(other_script, 0xfa, sizeof other_script);
    static const struct { uint8_t v, push; size_t len; } SHAPES[] = {
        {0x00, 32, 34}, {0x00, 20, 22}, {0x52, 32, 34}, {0x60, 32, 34}, {0x51, 2, 4},
        {0x51, 31, 33}, {0x51, 33, 35}, {0x51, 40, 42}, {0x51, 32, 33}, {0x6a, 32, 34}};
    int shapes_ok = 1;
    for (size_t k = 0; k < sizeof SHAPES / sizeof SHAPES[0]; k++) {
        r2 = req;
        other_script[0] = SHAPES[k].v;
        other_script[1] = SHAPES[k].push;
        r2.funding_script = other_script;
        r2.funding_script_len = SHAPES[k].len;
        if (gzt_funding_build(ctx, &master, &r2, coins, 3, aux, &g) != GZT_ERR_SCRIPT) shapes_ok = 0;
    }
    CHECK(shapes_ok);
    other_script[0] = 0x51; other_script[1] = 0x20;
    r2.funding_script = other_script; r2.funding_script_len = 34;
    CHECK(gzt_funding_build(ctx, &master, &r2, coins, 3, aux, &g) == GZT_OK);
    CHECK(gzt_funding_build(ctx, &child, &req, coins, 3, aux, &g) == GZT_ERR_ARG);
    CHECK(gzt_funding_build(ctx, &master, &req, coins, 3, NULL, &g) == GZT_ERR_ARG);
    CHECK(all_zero(&g, sizeof g));

    gzt_funding_wipe(&f);
    CHECK(all_zero(&f, sizeof f));
    CHECK(refused(ctx, &master, &f, txid, aux, GZT_ERR_STATE));
    gzw_wipe(&master, sizeof master);
    gzw_wipe(&other, sizeof other);
    gzw_wipe(&child, sizeof child);
}

static void test_sign_and_sighash_refusals(const secp256k1_context *ctx) {
    gzt_spent_output spent[2];
    secp256k1_keypair kp;
    uint8_t key[32] = {1}, out[32], msg[GZT_SIGMSG_MAX], aux[32] = {0};
    size_t len;
    memset(&tx, 0, sizeof tx);
    memset(spent, 0, sizeof spent);
    tx.version = 2;
    tx.n_in = 2;
    tx.n_out = 1;
    tx.out[0].script_len = 34;
    CHECK(gzw_taproot_tweak_seckey(ctx, key, &kp, out));
    for (int i = 0; i < 2; i++) {
        spent[i].amount = 1000;
        spent[i].script_len = 34;
        spent[i].script[0] = 0x51;
        spent[i].script[1] = 0x20;
        memcpy(spent[i].script + 2, out, 32);
    }
    CHECK(gzt_sign_keypath(ctx, &tx, spent, 1, &kp, aux) == GZT_OK);
    CHECK(gzt_sign_keypath(ctx, &tx, spent, 2, &kp, aux) == GZT_ERR_ARG);
    spent[0].script[0] = 0x52; /* not version 1 */
    CHECK(gzt_sign_keypath(ctx, &tx, spent, 0, &kp, aux) == GZT_ERR_KEY);
    spent[0].script[0] = 0x51;
    spent[0].script_len = 33;
    CHECK(gzt_sign_keypath(ctx, &tx, spent, 0, &kp, aux) == GZT_ERR_KEY);
    spent[0].script_len = 34;
    spent[0].script[33] ^= 1;
    CHECK(gzt_sign_keypath(ctx, &tx, spent, 0, &kp, aux) == GZT_ERR_KEY);
    spent[0].script[33] ^= 1;
    spent[0].amount = GZT_MAX_MONEY + 1;
    CHECK(gzt_sign_keypath(ctx, &tx, spent, 0, &kp, aux) == GZT_ERR_ARG);
    spent[0].amount = 1000;

    static const uint8_t valid[] = {0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83};
    int types_ok = 1;
    for (int t = 0; t < 256; t++) {
        int want = memchr(valid, t, sizeof valid) != NULL;
        gzt_err e = gzt_sigmsg(&tx, spent, 0, (uint8_t)t, msg, &len);
        if ((e == GZT_OK) != want) types_ok = 0;
    }
    CHECK(types_ok);
    /* SINGLE needs an output at the input's index; input 1 has none */
    CHECK(gzt_sigmsg(&tx, spent, 1, GZT_SIGHASH_SINGLE, msg, &len) == GZT_ERR_ARG);
    CHECK(gzt_sigmsg(&tx, spent, 1, GZT_SIGHASH_ALL, msg, &len) == GZT_OK);
    CHECK(gzt_sigmsg(&tx, spent, 2, GZT_SIGHASH_ALL, msg, &len) == GZT_ERR_ARG);
    /* lengths from BIP 341: 174 with every hash, less for NONE, ANYONECANPAY */
    CHECK(gzt_sigmsg(&tx, spent, 0, GZT_SIGHASH_DEFAULT, msg, &len) == GZT_OK && len == 174);
    CHECK(gzt_sigmsg(&tx, spent, 0, GZT_SIGHASH_NONE, msg, &len) == GZT_OK && len == 142);
    CHECK(gzt_sigmsg(&tx, spent, 0, 0x81, msg, &len) == GZT_OK && len == 125);
}

/* Boundaries and caps found by the mutation run: each value at the limit and
   one past it, and every cap checked on an input or output after the first. */
static void test_boundaries(void) {
    size_t n, m, one = 34;
    /* compact sizes for the input count: minimal and too large is LIMIT,
       not minimal is PARSE, whatever the width */
    static const struct { uint8_t b[9]; size_t len; gzt_err want; } CS[] = {
        {{0xfd, 0xfd, 0x00}, 3, GZT_ERR_LIMIT}, {{0xfd, 0xfc, 0x00}, 3, GZT_ERR_PARSE},
        {{0xfe, 0x00, 0x00, 0x01, 0x00}, 5, GZT_ERR_LIMIT},
        {{0xfe, 0xff, 0xff, 0x00, 0x00}, 5, GZT_ERR_PARSE},
        {{0xff, 0, 0, 0, 0, 1, 0, 0, 0}, 9, GZT_ERR_LIMIT},
        {{0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}, 9, GZT_ERR_PARSE}};
    pos = 0; le(2, 4); b(0xfd); b(0xff);                   /* cut inside a compact size */
    CHECK(parse_raw(pos) == GZT_ERR_PARSE);
    for (size_t k = 0; k < sizeof CS / sizeof CS[0]; k++) {
        n = make(0, 1, 0, 1, 1000, 34, 0, 0);
        memmove(raw + 4 + CS[k].len, raw + 5, n - 5);
        memcpy(raw + 4, CS[k].b, CS[k].len);
        CHECK(parse_raw(n - 1 + CS[k].len) == CS[k].want);
    }
    /* Review M2: a zero length written in a longer form, where the input does
       not end there (scriptSig length; witness item length), and a witness
       count cut short by the end of the input.  Each must be PARSE. */
    static const uint8_t ZERO_FORMS[3][9] = {
        {0xfd, 0, 0}, {0xfe, 0, 0, 0, 0}, {0xff, 0, 0, 0, 0, 0, 0, 0, 0}};
    static const size_t ZERO_LENS[3] = {3, 5, 9};
    int zero_forms_ok = 1;
    for (int k = 0; k < 3; k++) {
        /* scriptSig length 0 at offset 4 + 1 + 36 */
        n = make(0, 1, 0, 1, 1000, 34, 0, 0);
        size_t ss = 4 + 1 + 36;
        memmove(raw + ss + ZERO_LENS[k], raw + ss + 1, n - ss - 1);
        memcpy(raw + ss, ZERO_FORMS[k], ZERO_LENS[k]);
        if (parse_raw(n - 1 + ZERO_LENS[k]) != GZT_ERR_PARSE) zero_forms_ok = 0;
        /* witness: each of the two inputs has one empty item;
           the empty item's length is the byte before the lock time */
        n = make(1, 2, 0, 1, 1000, 34, 1, 0);
        size_t wl = n - 4 - 1;
        CHECK(raw[wl] == 0 && raw[wl - 1] == 1);
        memmove(raw + wl + ZERO_LENS[k], raw + wl + 1, n - wl - 1);
        memcpy(raw + wl, ZERO_FORMS[k], ZERO_LENS[k]);
        if (parse_raw(n - 1 + ZERO_LENS[k]) != GZT_ERR_PARSE) zero_forms_ok = 0;
    }
    CHECK(zero_forms_ok);
    /* the minimal forms of the same transactions parse */
    CHECK(parse_raw(make(0, 1, 0, 1, 1000, 34, 0, 0)) == GZT_OK);
    CHECK(parse_raw(make(1, 2, 0, 1, 1000, 34, 1, 0)) == GZT_OK);
    /* three inputs; the last witness count is fd, fe or ff and only the four
       lock-time bytes follow */
    int cut_count_ok = 1;
    for (int k = 0; k < 3; k++) {
        n = make(1, 3, 0, 1, 1000, 34, 1, 1);
        size_t wc = n - 4 - 3; /* last input: 01 01 cd, then the lock time */
        CHECK(raw[wc] == 1 && raw[wc + 1] == 1);
        raw[wc] = (uint8_t)(0xfd + k);
        memset(raw + wc + 1, 0, 4);
        if (parse_raw(wc + 5) != GZT_ERR_PARSE) cut_count_ok = 0;
        /* the same where the count read before it was 0 (the review's input
           B): witnesses {one empty item}, {}, then the cut count.  A parser
           that kept the stale 0 as the count would accept, with the four
           bytes as the lock time */
        n = make(1, 3, 0, 1, 1000, 34, 1, 0);
        size_t ws = n - 4 - 6; /* 01 00 | 01 00 | 01 00, then the lock time */
        CHECK(raw[ws] == 1 && raw[ws + 1] == 0 && raw[ws + 4] == 1);
        raw[ws + 2] = 0;                     /* input 1: no witness items */
        raw[ws + 3] = (uint8_t)(0xfd + k);   /* input 2: the cut count */
        memset(raw + ws + 4, 0, 4);
        if (parse_raw(ws + 8) != GZT_ERR_PARSE) cut_count_ok = 0;
        raw[ws + 3] = 0;                     /* with a real 0 there it parses */
        if (parse_raw(ws + 8) != GZT_OK) cut_count_ok = 0;
    }
    CHECK(cut_count_ok);

    /* a script length of 34 written as fd 22 00 */
    n = make(0, 1, 0, 1, 1000, 34, 0, 0);
    size_t at = 4 + 1 + 41 + 1 + 8;
    memmove(raw + at + 3, raw + at + 1, n - at - 1);
    raw[at] = 0xfd; raw[at + 1] = 34; raw[at + 2] = 0;
    CHECK(parse_raw(n + 2) == GZT_ERR_PARSE);
    /* one output of 21 million and one of 2^64 - 1: the sum wraps */
    n = make(0, 1, 0, 2, GZT_MAX_MONEY, 34, 0, 0);
    memset(raw + 4 + 1 + 41 + 1 + 43, 0xff, 8);
    CHECK(parse_raw(n) == GZT_ERR_PARSE);

    /* serialising: caps on the second input and output, witness only on input 1 */
    CHECK(parse_raw(make(1, 2, 0, 2, 1000, 34, 1, 64)) == GZT_OK);
    tx2 = tx; tx2.in[1].script_sig_len = GZT_MAX_SCRIPT + 1;
    CHECK(gzt_tx_serialize(&tx2, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_ERR_ARG);
    tx2 = tx; tx2.in[1].witness_count = GZT_MAX_WITNESS_ITEMS + 1;
    CHECK(gzt_tx_serialize(&tx2, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_ERR_ARG);
    tx2 = tx; tx2.in[1].witness_count = 2; tx2.in[1].witness[1].len = GZT_MAX_WITNESS_ITEM + 1;
    CHECK(gzt_tx_serialize(&tx2, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_ERR_ARG);
    tx2 = tx; tx2.out[1].script_len = GZT_MAX_SCRIPT + 1;
    CHECK(gzt_tx_serialize(&tx2, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_ERR_ARG);
    CHECK(gzt_tx_txid(&tx2, back) == GZT_ERR_ARG && gzt_tx_wtxid(&tx2, back) == GZT_ERR_ARG);
    uint64_t w, vs;
    CHECK(gzt_tx_weight(&tx2, &w, &vs) == GZT_ERR_ARG);
    tx2 = tx; tx2.out[0].script_len = GZT_MAX_SCRIPT + 1;
    CHECK(gzt_tx_serialize(&tx2, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_ERR_ARG);
    tx2 = tx; tx2.in[1].witness[1].len = GZT_MAX_WITNESS_ITEM + 1; /* beyond the count */
    CHECK(gzt_tx_serialize(&tx2, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_OK);
    tx2 = tx; tx2.in[0].witness_count = 0;
    CHECK(gzt_tx_serialize(&tx2, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_OK);
    CHECK(back[4] == 0x00 && back[5] == 0x01);              /* still segwit */
    tx2.n_in = 1; tx2.in[1].witness_count = 1;              /* beyond n_in: ignored */
    CHECK(gzt_tx_serialize(&tx2, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_OK);
    CHECK(back[4] == 0x01);                                 /* legacy form */
    n = make(1, GZT_MAX_INPUTS, GZT_MAX_SCRIPT, GZT_MAX_OUTPUTS, 1, GZT_MAX_SCRIPT,
             GZT_MAX_WITNESS_ITEMS, GZT_MAX_WITNESS_ITEM);
    CHECK(parse_raw(n) == GZT_OK);
    CHECK(gzt_tx_serialize(&tx, GZT_SER_WITNESS, back, sizeof back, &m) == GZT_OK && m == n &&
          memcmp(back, raw, n) == 0);

    size_t lens[GZT_MAX_OUTPUTS + 1];
    for (size_t i = 0; i <= GZT_MAX_OUTPUTS; i++) lens[i] = 34;
    CHECK(gzt_keypath_vsize(1, lens, GZT_MAX_OUTPUTS) > 0);
    CHECK(gzt_keypath_vsize(1, lens, GZT_MAX_OUTPUTS + 1) == 0);
    lens[1] = GZT_MAX_SCRIPT;
    CHECK(gzt_keypath_vsize(1, lens, 2) > 0);
    lens[1] = GZT_MAX_SCRIPT + 1;
    CHECK(gzt_keypath_vsize(1, lens, 2) == 0);
    CHECK(gzt_keypath_vsize(GZT_MAX_INPUTS, &one, 1) > 0);

    gzt_feerate c = {GZT_FEERATE_MAX_SAT_PER_KVB}, got;
    CHECK(gzt_feerate_from_server(GZT_FEERATE_MAX_SAT_PER_KVB, c, &got) == GZT_OK);

    /* the signature hash: every spent output and output checked, the largest
       scripts fit, SINGLE with a 128-byte output */
    static gzt_spent_output spent[GZT_MAX_INPUTS + 1];
    uint8_t msg[GZT_SIGMSG_MAX], h[32];
    size_t len;
    gzt_sighash_parts parts;
    CHECK(parse_raw(make(0, GZT_MAX_INPUTS, 0, 2, 1000, GZT_MAX_SCRIPT, 0, 0)) == GZT_OK);
    memset(spent, 0, sizeof spent);
    for (int i = 0; i < GZT_MAX_INPUTS; i++) {
        spent[i].amount = 1;
        spent[i].script_len = GZT_MAX_SCRIPT;
    }
    CHECK(gzt_sighash_parts_compute(&tx, spent, &parts) == GZT_OK);
    CHECK(gzt_sigmsg(&tx, spent, 1, GZT_SIGHASH_SINGLE, msg, &len) == GZT_OK);
    CHECK(gzt_sighash_keypath(&tx, spent, 1, 0x04, h) == GZT_ERR_ARG);
    spent[1].script_len = GZT_MAX_SCRIPT + 1;
    CHECK(gzt_sighash_parts_compute(&tx, spent, &parts) == GZT_ERR_ARG);
    spent[1].script_len = GZT_MAX_SCRIPT;
    spent[1].amount = GZT_MAX_MONEY + 1;
    CHECK(gzt_sighash_parts_compute(&tx, spent, &parts) == GZT_ERR_ARG);
    spent[1].amount = GZT_MAX_MONEY;
    CHECK(gzt_sighash_parts_compute(&tx, spent, &parts) == GZT_OK);
    tx2 = tx; tx2.out[1].script_len = GZT_MAX_SCRIPT + 1;
    CHECK(gzt_sighash_parts_compute(&tx2, spent, &parts) == GZT_ERR_ARG);
    tx2 = tx; tx2.n_in = 0;
    CHECK(gzt_sighash_parts_compute(&tx2, spent, &parts) == GZT_ERR_ARG);
    tx2 = tx; tx2.n_in = GZT_MAX_INPUTS + 1;
    CHECK(gzt_sighash_parts_compute(&tx2, spent, &parts) == GZT_ERR_ARG);
    tx2 = tx; tx2.n_out = 0;
    CHECK(gzt_sighash_parts_compute(&tx2, spent, &parts) == GZT_ERR_ARG);
    tx2 = tx; tx2.n_out = GZT_MAX_OUTPUTS + 1;
    CHECK(gzt_sighash_parts_compute(&tx2, spent, &parts) == GZT_ERR_ARG);
    tx2 = tx; tx2.n_out = GZT_MAX_OUTPUTS;
    CHECK(gzt_sighash_parts_compute(&tx2, spent, &parts) == GZT_OK);
    tx2 = tx; tx2.out[0].script_len = GZT_MAX_SCRIPT + 1;
    CHECK(gzt_sighash_parts_compute(&tx2, spent, &parts) == GZT_ERR_ARG);
    tx2 = tx; tx2.n_out = 1; tx2.out[1].script_len = GZT_MAX_SCRIPT + 1; /* beyond n_out */
    CHECK(gzt_sighash_parts_compute(&tx2, spent, &parts) == GZT_OK);

    /* parsing from buffers of exactly the input's size, so that a read one
       byte too far is seen by the memory-error checkers */
    n = unhex(BIP341_SIGNED, raw, sizeof raw);
    int exact_ok = 1;
    for (size_t cut = 0; cut <= n; cut++) {
        uint8_t *p = malloc(cut ? cut : 1);
        if (!p) exit(1);
        memcpy(p, raw, cut);
        if ((gzt_tx_parse(p, cut, &tx2) == GZT_OK) != (cut == n)) exact_ok = 0;
        free(p);
    }
    CHECK(exact_ok);

    /* coin selection at its limits */
    static gzt_coin coins[GZT_MAX_COINS];
    gzt_selection a;
    gzt_fee_policy fp = {{100}, {GZT_FEERATE_MAX_SAT_PER_KVB}};
    memset(coins, 0, sizeof coins);
    for (size_t i = 0; i < GZT_MAX_COINS; i++) {
        coins[i].txid[0] = (uint8_t)i;
        coins[i].txid[1] = (uint8_t)(i >> 8);
        coins[i].amount = 1000;
    }
    CHECK(gzt_select_coins(coins, GZT_MAX_COINS, P2TR_DEST, 34, 500, fp, &a) == GZT_OK);
    coins[0].amount = GZT_MAX_MONEY - 1000;
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, GZT_MAX_MONEY, fp, &a) == GZT_ERR_FUNDS);
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, 500, fp, &a) == GZT_OK); /* sum is 21M */
    coins[0].amount = GZT_MAX_MONEY;
    CHECK(gzt_select_coins(coins, 1, P2TR_DEST, 34, 500, fp, &a) == GZT_OK);
    coins[1].amount = UINT64_MAX; /* would wrap the sum */
    CHECK(gzt_select_coins(coins, 2, P2TR_DEST, 34, 500, fp, &a) == GZT_ERR_ARG);
    coins[0].amount = GZT_MAX_MONEY + 1;
    CHECK(gzt_select_coins(coins, 1, P2TR_DEST, 34, 500, fp, &a) == GZT_ERR_ARG);
    coins[0].amount = coins[1].amount = 1000;
    coins[2] = coins[1];
    CHECK(gzt_select_coins(coins, 3, P2TR_DEST, 34, 500, fp, &a) == GZT_ERR_ARG);
}

/* Every pointer argument, NULL in turn: refused, never followed. */
static void test_null_arguments(const secp256k1_context *ctx) {
    static gzt_funding f;
    gzt_network net;
    gzt_feerate c = {1000};
    gzt_sighash_parts parts;
    gzt_spent_output spent;
    gzt_selection sel;
    gzt_coin coin;
    secp256k1_keypair kp;
    gzw_xprv master;
    uint8_t h[32], msg[GZT_SIGMSG_MAX], aux[32] = {0}, s[34] = {0x51, 0x20};
    uint64_t w, vs;
    size_t len, one = 34;
    memset(&spent, 0, sizeof spent);
    memset(&coin, 0, sizeof coin);
    CHECK(parse_raw(make(0, 1, 0, 1, 1000, 34, 0, 0)) == GZT_OK);
    CHECK(public_master(ctx, &master));
    uint8_t any_key[32] = {1};
    CHECK(gzw_taproot_tweak_seckey(ctx, any_key, &kp, NULL));
    gzt_fee_policy fp = {{100}, {1000}};
    gzt_funding_request req = {GZT_NET_SIGNET, 0, s, 34, 1000, 0, fp, NULL, 0};

    CHECK(gzt_network_from_name(NULL, &net) == GZT_ERR_ARG);
    CHECK(gzt_network_from_name("signet", NULL) == GZT_ERR_ARG);
    CHECK(gzt_network_to_keys(GZT_NET_SIGNET, NULL) == GZT_ERR_ARG);
    CHECK(gzt_feerate_from_server(100, c, NULL) == GZT_ERR_ARG);
    CHECK(gzt_is_witness_program(NULL, 34) == 0 && gzt_dust_limit(NULL, 34) == 0);
    CHECK(gzt_tx_serialize(NULL, GZT_SER_WITNESS, back, sizeof back, &len) == GZT_ERR_ARG);
    CHECK(gzt_tx_serialize(&tx, GZT_SER_WITNESS, NULL, sizeof back, &len) == GZT_ERR_ARG);
    CHECK(gzt_tx_serialize(&tx, GZT_SER_WITNESS, back, sizeof back, NULL) == GZT_ERR_ARG);
    CHECK(gzt_tx_parse(NULL, 10, &tx2) == GZT_ERR_ARG);
    CHECK(gzt_tx_parse(raw, 10, NULL) == GZT_ERR_ARG);
    CHECK(gzt_tx_txid(NULL, h) == GZT_ERR_ARG && gzt_tx_txid(&tx, NULL) == GZT_ERR_ARG);
    CHECK(gzt_tx_wtxid(NULL, h) == GZT_ERR_ARG && gzt_tx_wtxid(&tx, NULL) == GZT_ERR_ARG);
    CHECK(gzt_tx_weight(NULL, &w, &vs) == GZT_ERR_ARG);
    CHECK(gzt_tx_weight(&tx, NULL, &vs) == GZT_ERR_ARG && gzt_tx_weight(&tx, &w, NULL) == GZT_ERR_ARG);
    CHECK(gzt_keypath_vsize(1, NULL, 1) == 0 && gzt_keypath_vsize(1, &one, 0) == 0);
    CHECK(gzt_sighash_parts_compute(NULL, &spent, &parts) == GZT_ERR_ARG);
    CHECK(gzt_sighash_parts_compute(&tx, NULL, &parts) == GZT_ERR_ARG);
    CHECK(gzt_sighash_parts_compute(&tx, &spent, NULL) == GZT_ERR_ARG);
    CHECK(gzt_sigmsg(&tx, &spent, 0, 0, NULL, &len) == GZT_ERR_ARG);
    CHECK(gzt_sigmsg(&tx, &spent, 0, 0, msg, NULL) == GZT_ERR_ARG);
    CHECK(gzt_sigmsg(&tx, NULL, 0, 0, msg, &len) == GZT_ERR_ARG);
    CHECK(gzt_sighash_keypath(&tx, &spent, 0, 0, NULL) == GZT_ERR_ARG);
    CHECK(gzt_sign_keypath(NULL, &tx, &spent, 0, &kp, aux) == GZT_ERR_ARG);
    CHECK(gzt_sign_keypath(ctx, NULL, &spent, 0, &kp, aux) == GZT_ERR_ARG);
    CHECK(gzt_sign_keypath(ctx, &tx, &spent, 0, NULL, aux) == GZT_ERR_ARG);
    CHECK(gzt_sign_keypath(ctx, &tx, &spent, 0, &kp, NULL) == GZT_ERR_ARG);
    coin.amount = 100000;
    CHECK(gzt_select_coins(NULL, 1, s, 34, 1000, fp, &sel) == GZT_ERR_ARG);
    CHECK(gzt_select_coins(&coin, 1, NULL, 34, 1000, fp, &sel) == GZT_ERR_ARG);
    CHECK(gzt_select_coins(&coin, 1, s, 34, 1000, fp, NULL) == GZT_ERR_ARG);
    CHECK(gzt_funding_build(NULL, &master, &req, &coin, 1, aux, &f) == GZT_ERR_ARG);
    CHECK(gzt_funding_build(ctx, NULL, &req, &coin, 1, aux, &f) == GZT_ERR_ARG);
    CHECK(gzt_funding_build(ctx, &master, NULL, &coin, 1, aux, &f) == GZT_ERR_ARG);
    CHECK(gzt_funding_build(ctx, &master, &req, NULL, 1, aux, &f) == GZT_ERR_ARG);
    CHECK(gzt_funding_build(ctx, &master, &req, &coin, 1, aux, NULL) == GZT_ERR_ARG);
    req.funding_script = NULL;
    CHECK(gzt_funding_build(ctx, &master, &req, &coin, 1, aux, &f) == GZT_ERR_ARG);
    /* release, on a funding that is built, so that only the NULL can refuse */
    req.funding_script = s;
    make_coin(ctx, &master, &coin, 0, 0, 100000);
    CHECK(gzt_funding_build(ctx, &master, &req, &coin, 1, aux, &f) == GZT_OK);
    memcpy(h, f.info.txid, 32);
    CHECK(gzt_funding_release(ctx, &master, &f, h, aux, back, sizeof back, &len) == GZT_OK);
    CHECK(gzt_funding_release(NULL, &master, &f, h, aux, back, sizeof back, &len) == GZT_ERR_ARG);
    CHECK(gzt_funding_release(ctx, NULL, &f, h, aux, back, sizeof back, &len) == GZT_ERR_ARG);
    CHECK(gzt_funding_release(ctx, &master, NULL, h, aux, back, sizeof back, &len) == GZT_ERR_ARG);
    CHECK(gzt_funding_release(ctx, &master, &f, NULL, aux, back, sizeof back, &len) == GZT_ERR_ARG);
    CHECK(gzt_funding_release(ctx, &master, &f, h, NULL, back, sizeof back, &len) == GZT_ERR_ARG);
    CHECK(gzt_funding_release(ctx, &master, &f, h, aux, NULL, sizeof back, &len) == GZT_ERR_ARG);
    CHECK(gzt_funding_release(ctx, &master, &f, h, aux, back, sizeof back, NULL) == GZT_ERR_ARG);
    gzt_funding_wipe(NULL);
    gzt_funding_wipe(&f);
    gzw_wipe(&master, sizeof master);
}

int main(void) {
    secp256k1_context *ctx = test_ctx();
    test_null_arguments(ctx);
    test_boundaries();
    test_parse();
    test_sizes_and_fees();
    test_dust_and_networks();
    test_selection();
    test_funding(ctx);
    test_sign_and_sighash_refusals(ctx);
    secp256k1_context_destroy(ctx);
    return test_done("test_tx");
}
