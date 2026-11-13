/* slice1-attempt: the chain view (two signet operators, the comparing
 * backend) and the host's funding through the wallet library. The phrase
 * file is read here only to derive the master key (as gz-wallet-tx does);
 * nothing of it is printed. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "gazpacho/wallet_tx.h"
#include "gazpacho/chain.h"
#include "gazpacho/chain_esplora.h"
#include "gazpacho/chain_multi.h"
#include "gazpacho/chain_http.h"
#include "s1.h"

static const char *const SERVERS[2] = {"https://mempool.space/signet/api", "https://blockstream.info/signet/api"};
static const char *const OPERATORS[2] = {"mempool.space", "blockstream.info"};
static gz_http http;
static gz_chain servers[2], multi;
static int open_ok;

int s1_chain_open(void)
{
    gz_esplora_config cfg;
    gz_multi_config mc;
    if (!gz_http_curl_create(&http, NULL)) return 0;
    for (int i = 0; i < 2; i++) {
        gz_esplora_config_default(&cfg);
        cfg.base_url = SERVERS[i];
        cfg.operator_id = OPERATORS[i];
        if (gz_esplora_create(&cfg, &http, &servers[i]) != GZ_CHAIN_OK) return 0;
    }
    gz_multi_config_default(&mc, GZ_NET_SIGNET);
    mc.now_ms = http.now_ms;
    mc.clock_ctx = http.ctx;
    if (gz_multi_create(&mc, servers, 2, &multi) != GZ_CHAIN_OK) return 0;
    gz_chain_result r = gz_chain_check_network(&multi, GZ_NET_SIGNET);
    if (r != GZ_CHAIN_OK) { s1_log("chain: network check: %s", gz_chain_result_name(r)); return 0; }
    open_ok = 1;
    return 1;
}

static void report(const char *what)
{
    const gz_multi_report *rep = gz_multi_last_report(&multi);
    if (!rep) return;
    for (size_t i = 0; i < rep->server_count; i++)
        s1_log("chain:   %s: server %s answered %s", what, rep->operators[i], gz_chain_result_name(rep->answers[i].result));
}

int s1_chain_tip(uint32_t *tip)
{
    gz_chain_tip t;
    gz_chain_result r = gz_chain_tip_get(&multi, &t);
    if (r != GZ_CHAIN_OK) { s1_log("chain: tip: %s", gz_chain_result_name(r)); report("tip"); return 0; }
    *tip = t.height;
    return 1;
}

int s1_tx_confirmations(const uint8_t txid[32], uint32_t *height)
{
    gz_tx_status st;
    gz_chain_result r = gz_chain_tx_status(&multi, txid, &st);
    const gz_multi_report *rep = gz_multi_last_report(&multi);
    char id[65]; s1_hex_rev(id, txid, 32);
    if (rep)
        for (size_t i = 0; i < rep->server_count; i++) {
            const gz_multi_answer *a = &rep->answers[i];
            if (a->result == GZ_CHAIN_OK)
                s1_log("S1-RESULT operator %s: tx %s state %d height %u claimed confirmations %u (tip %u)", rep->operators[i], id,
                       (int)a->u.tx_status.state, a->u.tx_status.height, a->u.tx_status.claimed_confirmations,
                       a->u.tx_status.tip_height);
            else
                s1_log("S1-RESULT operator %s: tx %s: %s", rep->operators[i], id, gz_chain_result_name(a->result));
        }
    if (r != GZ_CHAIN_OK) { s1_log("chain: tx status (combined): %s", gz_chain_result_name(r)); return -1; }
    if (st.state != GZ_TX_CONFIRMED) return 0;
    *height = st.height;
    return (int)st.claimed_confirmations;
}

int s1_tx_output(const uint8_t txid[32], uint32_t vout, uint64_t *amount, uint8_t script[34])
{
    static uint8_t raw[400000];
    static gzt_tx tx;
    size_t len = 0;
    if (gz_chain_raw_tx(&multi, txid, raw, sizeof raw, &len) != GZ_CHAIN_OK) return 0;
    if (gzt_tx_parse(raw, len, &tx) != GZT_OK || vout >= tx.n_out || tx.out[vout].script_len != 34) return 0;
    *amount = tx.out[vout].value;
    memcpy(script, tx.out[vout].script, 34);
    return 1;
}

int s1_broadcast(const uint8_t *raw, size_t len)
{
    gz_broadcast_result br;
    gz_chain_result r = gz_chain_broadcast(&multi, raw, len, &br);
    const gz_multi_report *rep = gz_multi_last_report(&multi);
    if (rep)
        for (size_t i = 0; i < rep->server_count; i++) {
            const gz_broadcast_result *b = &rep->answers[i].u.broadcast;
            s1_log("S1-RESULT broadcast to %s: %s already_known %d http %ld %s", rep->operators[i],
                   gz_chain_result_name(b->result), (int)b->already_known, b->server_status, b->reason);
        }
    if (r != GZ_CHAIN_OK) s1_log("chain: broadcast (combined): %s", gz_chain_result_name(r));
    return r == GZ_CHAIN_OK;
}

/* ---- the wallet ---- */
#define PHRASE_FILE_MAX 1024
static gzw_xprv master;
static gzt_coin coins[256];
static size_t n_coins;
static uint32_t used[256];
static size_t n_used;
static gzt_funding F;

static int read_phrase_file(const char *path, char *phrase)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    size_t n = 0;
    int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 077) == 0 &&
             st.st_size <= PHRASE_FILE_MAX;
    while (ok && n <= PHRASE_FILE_MAX) {
        ssize_t r = read(fd, phrase + n, PHRASE_FILE_MAX + 1 - n);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) ok = 0;
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd);
    if (!ok || n > PHRASE_FILE_MAX || memchr(phrase, 0, n)) { gzw_wipe(phrase, PHRASE_FILE_MAX + 1); return 0; }
    phrase[n] = 0;
    return 1;
}

static void pause_ms(uint64_t ms)
{
    struct timespec ts = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

int s1_fund_prepare(void)
{
    static char phrase[PHRASE_FILE_MAX + 1];
    uint8_t seed[64];
    int ok = read_phrase_file(G.phrase_in, phrase) && gzw_phrase_check(phrase) == GZW_PHRASE_OK &&
             gzw_phrase_to_seed(phrase, NULL, seed) && gzw_bip32_master(G.secp, seed, 64, &master, NULL);
    gzw_wipe(phrase, sizeof phrase);
    gzw_wipe(seed, sizeof seed);
    if (!ok) { s1_log("fund: cannot use the phrase file"); return 0; }
    static gz_chain_output outs[64];
    uint64_t total = 0;
    for (uint32_t change = 0; change < 2; change++)
        for (uint32_t i = 0; i < 10; i++) {
            gzw_bip86_output o;
            if (!gzw_bip86_output_from_master(G.secp, &master, GZW_NET_SIGNET, 0, change, i, &o, NULL)) return 0;
            size_t count = 0;
            gz_chain_result r = GZ_CHAIN_UNREACHABLE;
            for (int t = 0; t < 5 && r != GZ_CHAIN_OK; t++) {
                if (t) pause_ms(2000u << t);
                r = gz_chain_script_outputs(&multi, o.script_pubkey, 34, outs, 64, &count, NULL);
            }
            if (r != GZ_CHAIN_OK) { s1_log("fund: coin lookup %u/%u: %s", change, i, gz_chain_result_name(r)); report("outputs"); return 0; }
            for (size_t k = 0; k < count && n_coins < 256; k++) {
                if (!outs[k].confirmed) { if (change == 1 && n_used < 256) used[n_used++] = i; continue; }
                gzt_coin *c = &coins[n_coins++];
                memset(c, 0, sizeof *c);
                memcpy(c->script, o.script_pubkey, 34);
                c->change = change; c->index = i;
                memcpy(c->txid, outs[k].txid, 32); c->vout = outs[k].vout; c->amount = outs[k].value;
                total += c->amount;
                char id[65]; s1_hex_rev(id, c->txid, 32);
                s1_log("fund: coin %s:%u %llu sat at m/86'/1'/0'/%u/%u", id, c->vout, (unsigned long long)c->amount, change, i);
            }
            pause_ms(250);
        }
    s1_log("fund: %zu confirmed coins, %llu sat", n_coins, (unsigned long long)total);
    return n_coins > 0;
}

int s1_fund_build(const uint8_t script[34], uint64_t amount, uint8_t *utx, size_t cap, size_t *len, uint8_t txid[32],
                  uint32_t *vout)
{
    gzt_funding_request req;
    memset(&req, 0, sizeof req);
    req.net = GZT_NET_SIGNET;
    req.account = 0;
    req.funding_script = script; req.funding_script_len = 34;
    req.amount = amount;
    req.change_index = G.change_index;
    req.fee.rate.sat_per_kvb = GZT_FEERATE_TEST_DEFAULT_SAT_PER_KVB;   /* 0.1 sat/vB */
    req.fee.ceiling.sat_per_kvb = 1000;
    req.used_change_indexes = used; req.n_used_change_indexes = n_used;
    uint8_t aux[32];
    if (getrandom(aux, 32, 0) != 32) return 0;
    gzt_err e = gzt_funding_build(G.secp, &master, &req, coins, n_coins, aux, &F);
    gzw_wipe(aux, 32);
    if (e) { s1_log("fund: build refused: %s", gzt_err_text(e)); return 0; }
    s1_log("fund: DRY RUN built: amount %llu fee %llu vsize %llu inputs %u change %llu at index %u", (unsigned long long)F.info.amount,
           (unsigned long long)F.info.fee, (unsigned long long)F.info.vsize, F.info.selection.n_selected,
           (unsigned long long)F.info.change, F.info.change_index);
    /* the unsigned transaction (legacy form) for round_propose's funding_tx */
    if (gzt_tx_serialize(&F.priv_tx, GZT_SER_NO_WITNESS, utx, cap, len) != GZT_OK) return 0;
    /* verify the outputs before anything is signed */
    if (F.priv_tx.out[F.info.vout].value != amount || F.priv_tx.out[F.info.vout].script_len != 34 ||
        memcmp(F.priv_tx.out[F.info.vout].script, script, 34)) { s1_log("fund: OUTPUT CHECK FAILED"); return 0; }
    for (uint32_t i = 0; i < F.priv_tx.n_out; i++) {
        char h[2 * GZT_MAX_SCRIPT + 1];
        s1_hex(h, F.priv_tx.out[i].script, F.priv_tx.out[i].script_len);
        s1_log("fund: output %u: %llu sat to %s", i, (unsigned long long)F.priv_tx.out[i].value, h);
    }
    memcpy(txid, F.info.txid, 32);
    *vout = F.info.vout;
    return 1;
}

int s1_fund_release(const uint8_t txid[32], uint8_t *raw, size_t cap, size_t *len)
{
    uint8_t aux[32];
    if (getrandom(aux, 32, 0) != 32) return 0;
    gzt_err e = gzt_funding_release(G.secp, &master, &F, txid, aux, raw, cap, len);
    gzw_wipe(aux, 32);
    if (e) s1_log("fund: release refused: %s", gzt_err_text(e));
    return e == GZT_OK;
}
