/* gz-wallet-tx: build, sign and send a funding transaction from a phrase file.
 *
 *   gz-wallet-tx decode                              (transaction hex on stdin)
 *   gz-wallet-tx plan --network NET --in FILE PAY --change-index N [FEE]
 *                     --coin TXID:VOUT:AMOUNT:CHANGE:INDEX ... [--release]
 *   gz-wallet-tx fund --network signet --in FILE PAY --change-index N [FEE]
 *                     [--scan N] [--expect-txid TXID] [--broadcast] [CHAIN]
 *   gz-wallet-tx broadcast --network signet --hex FILE [--in FILE] [DEST]
 *                     [--scan N] [--expect-txid TXID] [CHAIN]
 *   gz-wallet-tx confirm --network signet --txid TXID [CHAIN]
 *
 *   PAY is --to-address ADDR or --to-script HEX, and --amount SAT.
 *   FEE is --feerate SAT_PER_KVB (default 100, that is 0.1 sat/vB) or
 *   --feerate server, and --max-feerate SAT_PER_KVB (default 1000).
 *   DEST is --to-address ADDR or --to-script HEX: the one output that may
 *   pay outside the wallet.
 *   CHAIN is, optionally, --server URL [--operator NAME] given two to eight
 *   times instead of the two public signet servers, --pace MS (pause
 *   between two coin lookups, default 250) and --retry-pause MS (first pause
 *   before a failed lookup is asked again, default 2000, doubling, at most
 *   30000; a lookup is asked at most 5 times).
 *
 * "broadcast" sends exactly the bytes in FILE (hex), after checking that
 * they decode, are signed, and pay only outputs of the wallet in FILE
 * (indexes 0..N-1 of both chains) or the one DEST, and after looking up
 * every coin it spends (both servers must agree): it refuses an unknown
 * coin and a fee above --max-feerate (default 1000 sat/kvB) for its size.  "fund --expect-txid"
 * refuses to sign or send unless the built txid is the one given.  Every
 * server's answer to a broadcast is printed.
 *
 * "plan" works offline from coins given on the command line.  "fund" and
 * "confirm" ask the signet chain servers through the chain port (both
 * mempool.space and blockstream.info must agree); they exist only when the
 * program is built with the chain port.  "fund" looks for confirmed coins at
 * indexes 0..N-1 (default 20) of the receiving and change chains of account 0,
 * prints the plan, and sends only with --broadcast.  A rate from the servers
 * is used only if it is at or below --max-feerate.
 *
 * Outside the core: reads the phrase file and the OS random source.  Never
 * prints the phrase or a key.  Refuses mainnet.  The funding destination
 * must be a taproot output (the library refuses anything else).  The change
 * index is the caller's to track: give each one once.  "fund" also refuses a
 * change index that holds an unconfirmed coin; an index whose coins were
 * all spent cannot be seen this way (the servers list unspent outputs).
 * The transaction is signed when it is released (--release, --broadcast).
 * Exit status: 0 success, 1 failure, 2 wrong usage.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include "gazpacho/wallet_tx.h"
#ifdef GZT_WITH_CHAIN
#include "gazpacho/chain.h"
#include "gazpacho/chain_esplora.h"
#include "gazpacho/chain_multi.h"
#endif

#define PHRASE_FILE_MAX 1024
#define MAX_COINS 256
#define MAX_SERVERS 8
#define LOOKUP_TRIES 5
#define RETRY_PAUSE_MAX_MS 30000

static int usage(void) {
    fprintf(stderr,
            "usage: gz-wallet-tx decode < HEX\n"
            "       gz-wallet-tx plan --network NET --in FILE (--to-address A | --to-script HEX)\n"
            "            --amount SAT --change-index N [--feerate R] [--max-feerate C]\n"
            "            --coin TXID:VOUT:AMOUNT:CHANGE:INDEX ... [--release]\n"
            "       gz-wallet-tx fund --network signet --in FILE (--to-address A | --to-script HEX)\n"
            "            --amount SAT --change-index N [--feerate R|server] [--max-feerate C]\n"
            "            [--scan N] [--expect-txid TXID] [--broadcast] [CHAIN]\n"
            "       gz-wallet-tx broadcast --network signet --hex FILE [--in FILE]\n"
            "            [--to-address A | --to-script HEX] [--scan N] [--max-feerate C]\n"
            "            [--expect-txid TXID] [CHAIN]\n"
            "       gz-wallet-tx confirm --network signet --txid TXID [CHAIN]\n"
            "  CHAIN: (--server URL [--operator NAME]) x2..8, --pace MS, --retry-pause MS\n");
    return 2;
}

static void hex_out(const uint8_t *p, size_t n, int reverse) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[reverse ? n - 1 - i : i]);
}

static int unhex(const char *h, uint8_t *out, size_t cap, size_t *len) {
    size_t n = strlen(h);
    if (n % 2 || n / 2 > cap) return 0;
    for (size_t i = 0; i < n / 2; i++) {
        int v = 0;
        for (int k = 0; k < 2; k++) {
            char c = h[2 * i + k];
            int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
            if (d < 0) return 0;
            v = v * 16 + d;
        }
        out[i] = (uint8_t)v;
    }
    *len = n / 2;
    return 1;
}

static int txid_from_hex(const char *h, uint8_t out[32]) {
    uint8_t b[32];
    size_t n;
    if (!unhex(h, b, 32, &n) || n != 32) return 0;
    for (int i = 0; i < 32; i++) out[i] = b[31 - i];
    return 1;
}

static int parse_u64(const char *s, uint64_t max, uint64_t *out) {
    char *end;
    if (!s || !*s || *s == '-' || *s == '+') return 0;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || *end || v > max) return 0;
    *out = v;
    return 1;
}

/* The same rules as gz-wallet-keys: a regular file of this user, no group or
   other permission bits, at most PHRASE_FILE_MAX bytes, no zero byte. */
static int read_phrase_file(const char *path, char *phrase) {
    struct stat st;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    size_t n = 0;
    int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
             (st.st_mode & 077) == 0 && st.st_size <= PHRASE_FILE_MAX;
    while (ok && n <= PHRASE_FILE_MAX) {
        ssize_t r = read(fd, phrase + n, PHRASE_FILE_MAX + 1 - n);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) ok = 0;
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd);
    if (!ok || n > PHRASE_FILE_MAX || memchr(phrase, 0, n)) {
        gzw_wipe(phrase, PHRASE_FILE_MAX + 1);
        return 0;
    }
    phrase[n] = 0;
    return 1;
}

static int master_from_file(const secp256k1_context *ctx, const char *path, gzw_xprv *master) {
    static char phrase[PHRASE_FILE_MAX + 1];
    uint8_t seed[64];
    int ok = read_phrase_file(path, phrase) && gzw_phrase_check(phrase) == GZW_PHRASE_OK &&
             gzw_phrase_to_seed(phrase, NULL, seed) &&
             gzw_bip32_master(ctx, seed, 64, master, NULL);
    gzw_wipe(phrase, sizeof phrase);
    gzw_wipe(seed, sizeof seed);
    if (!ok) fprintf(stderr, "gz-wallet-tx: cannot use the phrase file %s\n", path);
    return ok;
}

typedef struct {
    const char *network, *in, *to_address, *to_script, *amount, *change_index, *feerate,
        *max_feerate, *scan, *txid, *hex, *expect_txid, *pace, *retry_pause;
    const char *coins[MAX_COINS];
    size_t n_coins;
    const char *servers[MAX_SERVERS], *operators[MAX_SERVERS];
    size_t n_servers;
    int release, broadcast;
} args;

static int parse_args(int argc, char **argv, args *a) {
    memset(a, 0, sizeof *a);
    a->feerate = "100";
    a->max_feerate = "1000";
    a->scan = "20";
    a->pace = "250";
    a->retry_pause = "2000";
    for (int i = 2; i < argc; i++) {
        const char *k = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(k, "--server") && v && a->n_servers < MAX_SERVERS) {
            a->servers[a->n_servers++] = v;
            i++;
            continue;
        }
        if (!strcmp(k, "--operator")) {
            /* names the server just before it, once */
            if (!v || !a->n_servers || a->operators[a->n_servers - 1]) return 0;
            a->operators[a->n_servers - 1] = v;
            i++;
            continue;
        }
        const char **slot = !strcmp(k, "--network") ? &a->network
                            : !strcmp(k, "--in") ? &a->in
                            : !strcmp(k, "--to-address") ? &a->to_address
                            : !strcmp(k, "--to-script") ? &a->to_script
                            : !strcmp(k, "--amount") ? &a->amount
                            : !strcmp(k, "--change-index") ? &a->change_index
                            : !strcmp(k, "--feerate") ? &a->feerate
                            : !strcmp(k, "--max-feerate") ? &a->max_feerate
                            : !strcmp(k, "--scan") ? &a->scan
                            : !strcmp(k, "--txid") ? &a->txid
                            : !strcmp(k, "--hex") ? &a->hex
                            : !strcmp(k, "--expect-txid") ? &a->expect_txid
                            : !strcmp(k, "--pace") ? &a->pace
                            : !strcmp(k, "--retry-pause") ? &a->retry_pause : NULL;
        if (!strcmp(k, "--release")) { a->release = 1; continue; }
        if (!strcmp(k, "--broadcast")) { a->broadcast = 1; continue; }
        if (!strcmp(k, "--coin") && v && a->n_coins < MAX_COINS) {
            a->coins[a->n_coins++] = v;
            i++;
            continue;
        }
        if (!slot || !v) return 0;
        *slot = v;
        i++;
    }
    return 1;
}

static int get_network(const char *name, gzt_network *net) {
    gzt_err e = name ? gzt_network_from_name(name, net) : GZT_ERR_ARG;
    if (e == GZT_ERR_MAINNET) fprintf(stderr, "gz-wallet-tx: refusing mainnet\n");
    else if (e) fprintf(stderr, "gz-wallet-tx: unknown network\n");
    return e == GZT_OK;
}

/* The destination script from --to-address or --to-script (exactly one). */
static int dest_script(const args *a, gzt_network net, uint8_t script[GZT_MAX_SCRIPT],
                       size_t *len_out) {
    size_t len = 0;
    if (a->to_address && !a->to_script) {
        gzw_network kn;
        int ver;
        uint8_t prog[40];
        if (gzt_network_to_keys(net, &kn) ||
            !gzw_segwit_address_decode(gzw_network_hrp(kn), a->to_address, &ver, prog, &len))
            return 0;
        script[0] = (uint8_t)(ver ? 0x50 + ver : 0);
        script[1] = (uint8_t)len;
        memcpy(script + 2, prog, len);
        len += 2;
    } else if (a->to_script && !a->to_address) {
        if (!unhex(a->to_script, script, GZT_MAX_SCRIPT, &len)) return 0;
    } else {
        return 0;
    }
    *len_out = len;
    return 1;
}

/* Fill the request from the arguments (everything except the fee rate). */
static int make_request(const args *a, gzt_network net, uint8_t script[GZT_MAX_SCRIPT],
                        gzt_funding_request *req) {
    uint64_t v;
    size_t len = 0;
    memset(req, 0, sizeof *req);
    req->net = net;
    if (!dest_script(a, net, script, &len)) return 0;
    req->funding_script = script;
    req->funding_script_len = len;
    if (!parse_u64(a->amount, GZT_MAX_MONEY, &req->amount)) return 0;
    if (!parse_u64(a->change_index, GZW_HARDENED - 1, &v)) return 0;
    req->change_index = (uint32_t)v;
    if (!parse_u64(a->max_feerate, GZT_FEERATE_MAX_SAT_PER_KVB, &req->fee.ceiling.sat_per_kvb))
        return 0;
    if (strcmp(a->feerate, "server") != 0 &&
        !parse_u64(a->feerate, GZT_FEERATE_MAX_SAT_PER_KVB, &req->fee.rate.sat_per_kvb))
        return 0;
    return 1;
}

/* The BIP 44 coin type of the derivation paths: 1 on every test network.
   The network was checked before, so the lookup cannot fail; if it ever
   did, 1 is still right, since mainnet is refused. */
static uint32_t coin_type(gzt_network net) {
    gzw_network kn;
    uint32_t c = 1;
    if (gzt_network_to_keys(net, &kn) || !gzw_network_coin_type(kn, &c)) return 1;
    return c;
}

static int coin_at(const secp256k1_context *ctx, const gzw_xprv *master, gzt_network net,
                   uint32_t change, uint32_t index, gzt_coin *c) {
    gzw_network kn;
    gzw_bip86_output o;
    if (gzt_network_to_keys(net, &kn) ||
        !gzw_bip86_output_from_master(ctx, master, kn, 0, change, index, &o, NULL))
        return 0;
    memcpy(c->script, o.script_pubkey, 34);
    c->change = change;
    c->index = index;
    return 1;
}

static int build_and_print(const secp256k1_context *ctx, const gzw_xprv *master,
                           const gzt_funding_request *req, const gzt_coin *coins, size_t n,
                           gzt_funding *f) {
    uint8_t aux[32];
    if (getrandom(aux, sizeof aux, 0) != (ssize_t)sizeof aux) return 0;
    gzt_err e = gzt_funding_build(ctx, master, req, coins, n, aux, f);
    gzw_wipe(aux, sizeof aux);
    if (e) {
        fprintf(stderr, "gz-wallet-tx: cannot build the funding: %s\n", gzt_err_text(e));
        return 0;
    }
    printf("txid ");
    hex_out(f->info.txid, 32, 1);
    printf("\nvout %u\namount %llu\nfee %llu\nvsize %llu\ninputs %u\n", f->info.vout,
           (unsigned long long)f->info.amount, (unsigned long long)f->info.fee,
           (unsigned long long)f->info.vsize, f->info.selection.n_selected);
    if (f->info.has_change)
        printf("change %llu at m/86'/%u'/0'/1/%u\n", (unsigned long long)f->info.change,
               coin_type(req->net), f->info.change_index);
    else
        printf("change none\n");
    return 1;
}

/* Sign and serialise the held funding (gzt_funding_release signs it now). */
static int release_signed(const secp256k1_context *ctx, const gzw_xprv *master,
                          const gzt_funding *f, uint8_t *raw, size_t cap, size_t *len) {
    uint8_t aux[32];
    if (getrandom(aux, sizeof aux, 0) != (ssize_t)sizeof aux) return 0;
    gzt_err e = gzt_funding_release(ctx, master, f, f->info.txid, aux, raw, cap, len);
    gzw_wipe(aux, sizeof aux);
    if (e) fprintf(stderr, "gz-wallet-tx: cannot release the funding: %s\n", gzt_err_text(e));
    return e == GZT_OK;
}

static int cmd_decode(void) {
    static char text[2 * GZT_MAX_TX_BYTES + 2];
    static uint8_t raw[GZT_MAX_TX_BYTES];
    static gzt_tx tx;
    size_t n = fread(text, 1, sizeof text - 1, stdin), len;
    uint8_t id[32];
    uint64_t w, vs;
    while (n && (text[n - 1] == '\n' || text[n - 1] == '\r' || text[n - 1] == ' ')) n--;
    text[n] = 0;
    if (!unhex(text, raw, sizeof raw, &len)) {
        fprintf(stderr, "gz-wallet-tx: not lower-case hex, or too long\n");
        return 1;
    }
    gzt_err e = gzt_tx_parse(raw, len, &tx);
    if (e) {
        fprintf(stderr, "gz-wallet-tx: %s\n", gzt_err_text(e));
        return 1;
    }
    gzt_tx_txid(&tx, id);
    printf("txid ");
    hex_out(id, 32, 1);
    gzt_tx_wtxid(&tx, id);
    printf("\nwtxid ");
    hex_out(id, 32, 1);
    gzt_tx_weight(&tx, &w, &vs);
    printf("\nweight %llu\nvsize %llu\ninputs %u\noutputs %u\n", (unsigned long long)w,
           (unsigned long long)vs, tx.n_in, tx.n_out);
    for (uint32_t i = 0; i < tx.n_out; i++) {
        printf("output %u %llu ", i, (unsigned long long)tx.out[i].value);
        hex_out(tx.out[i].script, tx.out[i].script_len, 0);
        printf("\n");
    }
    return 0;
}

static int cmd_plan(const secp256k1_context *ctx, const args *a) {
    static gzt_coin coins[MAX_COINS];
    static gzt_funding f;
    static uint8_t raw[GZT_MAX_TX_BYTES];
    uint8_t script[GZT_MAX_SCRIPT];
    gzt_funding_request req;
    gzt_network net;
    gzw_xprv master;
    int rc = 1;
    if (!get_network(a->network, &net)) return 1;
    if (!a->in || !a->n_coins || !make_request(a, net, script, &req) ||
        !strcmp(a->feerate, "server"))
        return usage();
    if (!master_from_file(ctx, a->in, &master)) return 1;
    for (size_t i = 0; i < a->n_coins; i++) {
        char txid[65];
        uint64_t vout, amount, change, index;
        char *s = strdup(a->coins[i]), *save = NULL, *f1 = strtok_r(s, ":", &save);
        char *f2 = strtok_r(NULL, ":", &save), *f3 = strtok_r(NULL, ":", &save);
        char *f4 = strtok_r(NULL, ":", &save), *f5 = strtok_r(NULL, ":", &save);
        int ok = f1 && strlen(f1) == 64 && f5 && !strtok_r(NULL, ":", &save) &&
                 parse_u64(f2, UINT32_MAX, &vout) && parse_u64(f3, GZT_MAX_MONEY, &amount) &&
                 parse_u64(f4, 1, &change) && parse_u64(f5, GZW_HARDENED - 1, &index);
        if (ok) {
            memcpy(txid, f1, 65);
            ok = txid_from_hex(txid, coins[i].txid) &&
                 coin_at(ctx, &master, net, (uint32_t)change, (uint32_t)index, &coins[i]);
            coins[i].vout = (uint32_t)vout;
            coins[i].amount = amount;
        }
        free(s);
        if (!ok) {
            fprintf(stderr, "gz-wallet-tx: bad --coin %s\n", a->coins[i]);
            goto out;
        }
    }
    if (!build_and_print(ctx, &master, &req, coins, a->n_coins, &f)) goto out;
    if (a->release) {
        size_t len;
        if (!release_signed(ctx, &master, &f, raw, sizeof raw, &len)) goto out;
        printf("signed ");
        hex_out(raw, len, 0);
        printf("\n");
    }
    rc = 0;
out:
    gzt_funding_wipe(&f);
    gzw_wipe(&master, sizeof master);
    return rc;
}

#ifdef GZT_WITH_CHAIN
static const char *const SIGNET_SERVERS[2] = {"https://mempool.space/signet/api",
                                              "https://blockstream.info/signet/api"};
/* who runs each, named rather than guessed from the host name */
static const char *const SIGNET_OPERATORS[2] = {"mempool.space", "blockstream.info"};

typedef struct {
    gz_http http;
    gz_chain servers[MAX_SERVERS], multi;
    size_t n;
    gz_network net; /* the chain port's name for the network chosen */
} chain_view;

static int chain_open(chain_view *cv, gzt_network net, const args *a) {
    gz_esplora_config cfg;
    gz_multi_config mc;
    memset(cv, 0, sizeof *cv);
    if (!gzt_network_eq(net, GZT_NET_SIGNET)) {
        fprintf(stderr, "gz-wallet-tx: the chain commands support signet only\n");
        return 0;
    }
    /* never fewer than two servers: the quorum of two operators is the rule */
    if (a->n_servers == 1) {
        fprintf(stderr, "gz-wallet-tx: give --server at least twice, or not at all\n");
        return 0;
    }
    /* the server list is signet's; the network is passed on, never assumed */
    if (!a->network || !gz_network_from_name(a->network, &cv->net) ||
        !gz_network_valid(cv->net) || cv->net == GZ_NET_MAINNET)
        return 0;
    if (!gz_http_curl_create(&cv->http, NULL)) return 0;
    size_t n = a->n_servers ? a->n_servers : 2;
    for (size_t i = 0; i < n; i++) {
        gz_esplora_config_default(&cfg);
        cfg.base_url = a->n_servers ? a->servers[i] : SIGNET_SERVERS[i];
        cfg.operator_id = a->n_servers ? a->operators[i] : SIGNET_OPERATORS[i];
        if (gz_esplora_create(&cfg, &cv->http, &cv->servers[i]) != GZ_CHAIN_OK) {
            fprintf(stderr, "gz-wallet-tx: not a usable server: %s\n", cfg.base_url);
            return 0;
        }
        cv->n = i + 1;
    }
    gz_multi_config_default(&mc, cv->net);
    mc.now_ms = cv->http.now_ms; /* the clock lag is timed by */
    mc.clock_ctx = cv->http.ctx;
    return gz_multi_create(&mc, cv->servers, cv->n, &cv->multi) == GZ_CHAIN_OK;
}

static void chain_close(chain_view *cv) {
    gz_chain_destroy(&cv->multi);
    for (size_t i = 0; i < cv->n; i++) gz_chain_destroy(&cv->servers[i]);
    gz_http_curl_destroy(&cv->http);
}

static void pause_ms(uint64_t ms) {
    struct timespec ts = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

/* What each server answered to the last call, one line each, to stderr. */
static void report_servers(const chain_view *cv) {
    const gz_multi_report *rep = gz_multi_last_report(&cv->multi);
    if (!rep) return;
    for (size_t i = 0; i < rep->server_count; i++)
        fprintf(stderr, "gz-wallet-tx:   server %zu (%s): %s\n", i + 1, rep->operators[i],
                gz_chain_result_name(rep->answers[i].result));
}

/* Failures a pause may cure: a server not reached or busy (429, 5xx), so
 * fewer than two operators answered, or one behind the other.  The servers
 * contradicting each other, a wrong network or a malformed answer is not
 * retried. */
static int transient(gz_chain_result r) {
    return r == GZ_CHAIN_UNREACHABLE || r == GZ_CHAIN_NO_QUORUM || r == GZ_CHAIN_LAG;
}

typedef gz_chain_result (*chain_call)(const chain_view *cv, void *arg);

/* Ask again after a pause (doubling, bounded) when a call failed in a way a
 * pause may cure.  The answer is still the comparing backend's: two
 * operators must agree on every try. */
static gz_chain_result with_retries(const chain_view *cv, chain_call call, void *arg,
                                    uint64_t first_pause, const char *what) {
    uint64_t wait = first_pause;
    gz_chain_result r = GZ_CHAIN_UNREACHABLE;
    for (int t = 1; t <= LOOKUP_TRIES; t++) {
        r = call(cv, arg);
        if (r == GZ_CHAIN_OK) return r;
        if (!transient(r) || t == LOOKUP_TRIES) break;
        fprintf(stderr, "gz-wallet-tx: lookup of %s: %s; asking again in %llu ms (try %d of %d)\n",
                what, gz_chain_result_name(r), (unsigned long long)wait, t + 1, LOOKUP_TRIES);
        report_servers(cv);
        pause_ms(wait);
        wait = wait * 2 > RETRY_PAUSE_MAX_MS ? RETRY_PAUSE_MAX_MS : wait * 2;
    }
    fprintf(stderr, "gz-wallet-tx: coin lookup failed at %s: %s\n", what, gz_chain_result_name(r));
    report_servers(cv);
    return r;
}

typedef struct {
    const gzt_coin *c;
    gz_chain_output *outs;
    size_t cap, *count;
} outputs_arg;

static gz_chain_result call_outputs(const chain_view *cv, void *p) {
    outputs_arg *o = p;
    *o->count = 0;
    return gz_chain_script_outputs(&cv->multi, o->c->script, 34, o->outs, o->cap, o->count, NULL);
}

/* One coin lookup of the scan, with retries. */
static gz_chain_result lookup(const chain_view *cv, const gzt_coin *c, uint32_t coin,
                              uint64_t first_pause, gz_chain_output *outs, size_t cap,
                              size_t *count) {
    char what[96];
    outputs_arg o = {c, outs, cap, count};
    snprintf(what, sizeof what, "%s index %u (m/86'/%u'/0'/%u/%u)",
             c->change ? "change" : "receive", c->index, coin, c->change, c->index);
    return with_retries(cv, call_outputs, &o, first_pause, what);
}

/* A previous transaction, any size the chain port accepts. */
#define PREV_TX_MAX 400000
typedef struct {
    const uint8_t *txid;
    uint8_t *buf;
    size_t len;
} raw_arg;

static gz_chain_result call_raw(const chain_view *cv, void *p) {
    raw_arg *r = p;
    return gz_chain_raw_tx(&cv->multi, r->txid, r->buf, PREV_TX_MAX, &r->len);
}

static int read_compact(const uint8_t *b, size_t len, size_t *i, uint64_t *v) {
    if (*i >= len) return 0;
    uint8_t f = b[(*i)++];
    size_t w = f == 0xfd ? 2 : f == 0xfe ? 4 : f == 0xff ? 8 : 0;
    if (!w) {
        *v = f;
        return 1;
    }
    if (len - *i < w) return 0;
    *v = 0;
    for (size_t k = 0; k < w; k++) *v |= (uint64_t)b[*i + k] << (8 * k);
    *i += w;
    return 1;
}

/* Output `vout` of a serialised transaction (either form), without the
 * library's caps, which are sized for this wallet's own transactions.  The
 * chain port has already checked that the bytes hash to the txid asked. */
static int prev_output(const uint8_t *b, size_t len, uint32_t vout, uint64_t *value,
                       const uint8_t **script, size_t *script_len) {
    size_t i = 4;
    uint64_t n, l;
    if (len < 10) return 0;
    if (b[4] == 0 && b[5] == 1) i = 6;
    if (!read_compact(b, len, &i, &n)) return 0;
    for (uint64_t k = 0; k < n; k++) {
        if (len - i < 36) return 0;
        i += 36;
        if (!read_compact(b, len, &i, &l) || l > len || len - i < l + 4) return 0;
        i += l + 4;
    }
    if (!read_compact(b, len, &i, &n) || vout >= n) return 0;
    for (uint64_t k = 0; k <= vout; k++) {
        if (len - i < 8) return 0;
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v |= (uint64_t)b[i + j] << (8 * j);
        i += 8;
        if (!read_compact(b, len, &i, &l) || l > len || len - i < l) return 0;
        if (k == vout) {
            *value = v;
            *script = b + i;
            *script_len = (size_t)l;
            return v <= GZT_MAX_MONEY;
        }
        i += l;
    }
    return 0;
}

/* Send raw to every server and print what each one answered. */
static int broadcast_and_report(const chain_view *cv, const uint8_t *raw, size_t len) {
    gz_broadcast_result br;
    memset(&br, 0, sizeof br);
    gz_chain_result r = gz_chain_broadcast(&cv->multi, raw, len, &br);
    const gz_multi_report *rep = gz_multi_last_report(&cv->multi);
    for (size_t i = 0; rep && rep->call == GZ_CALL_BROADCAST && i < rep->server_count; i++) {
        const gz_multi_answer *an = &rep->answers[i];
        const gz_broadcast_result *b = &an->u.broadcast;
        printf("server %zu (%s): ", i + 1, rep->operators[i]);
        if (an->result == GZ_CHAIN_OK && b->already_known)
            printf("already had it\n");
        else if (an->result == GZ_CHAIN_OK)
            printf("accepted\n");
        else if (an->result == GZ_CHAIN_REJECTED)
            printf("refused (HTTP %ld): %s\n", b->server_status, b->reason);
        else
            printf("no answer: %s (HTTP %ld)\n", gz_chain_result_name(an->result),
                   b->server_status);
    }
    if (r != GZ_CHAIN_OK) {
        fprintf(stderr, "gz-wallet-tx: broadcast failed: no server accepted it (%s)\n",
                gz_chain_result_name(r));
        return 0;
    }
    printf("broadcast ok\n");
    return 1;
}

static int pace_args(const args *a, uint64_t *pace, uint64_t *retry_pause) {
    return parse_u64(a->pace, 60000, pace) &&
           parse_u64(a->retry_pause, RETRY_PAUSE_MAX_MS, retry_pause);
}

static int cmd_fund(const secp256k1_context *ctx, const args *a) {
    static gzt_coin coins[MAX_COINS];
    static gzt_funding f;
    static uint8_t raw[GZT_MAX_TX_BYTES];
    static gz_chain_output outs[64];
    static uint32_t used[MAX_COINS];
    size_t n_used = 0;
    uint8_t script[GZT_MAX_SCRIPT], expect[32];
    gzt_funding_request req;
    gzt_network net;
    gzw_xprv master;
    chain_view cv;
    uint64_t scan, pace, retry_pause;
    size_t n = 0;
    int rc = 1;
    if (!get_network(a->network, &net)) return 1;
    if (!a->in || !make_request(a, net, script, &req) || !parse_u64(a->scan, 100, &scan) ||
        !pace_args(a, &pace, &retry_pause) ||
        (a->expect_txid && !txid_from_hex(a->expect_txid, expect)))
        return usage();
    if (!chain_open(&cv, net, a)) {
        fprintf(stderr, "gz-wallet-tx: cannot set up the chain servers\n");
        chain_close(&cv);
        return 1;
    }
    if (!master_from_file(ctx, a->in, &master)) goto out;
    if (!strcmp(a->feerate, "server")) {
        /* the chain port's policy for 6 blocks: on signet the fixed test-network
         * rate; elsewhere the servers' combined estimate for that target or a
         * faster one, never a slower one's */
        gz_fee_choice choice;
        gz_chain_result r = gz_chain_choose_fee_rate(&cv.multi, cv.net, 6,
                                                     req.fee.ceiling.sat_per_kvb, &choice);
        if (r != GZ_CHAIN_OK) {
            fprintf(stderr, "gz-wallet-tx: no fee estimate: %s\n", gz_chain_result_name(r));
            goto out;
        }
        gzt_err e = gzt_feerate_from_server(choice.sat_per_kvb, req.fee.ceiling, &req.fee.rate);
        if (e) {
            fprintf(stderr, "gz-wallet-tx: server rate %llu sat/kvB refused: %s\n",
                    (unsigned long long)choice.sat_per_kvb, gzt_err_text(e));
            goto out;
        }
    }
    printf("feerate %llu sat/kvB, ceiling %llu\n", (unsigned long long)req.fee.rate.sat_per_kvb,
           (unsigned long long)req.fee.ceiling.sat_per_kvb);
    for (uint32_t change = 0; change < 2; change++) {
        for (uint32_t i = 0; i < scan; i++) {
            gzt_coin c;
            size_t count = 0;
            memset(&c, 0, sizeof c);
            if (!coin_at(ctx, &master, net, change, i, &c)) goto out;
            if ((change || i) && pace) pause_ms(pace);
            if (lookup(&cv, &c, coin_type(net), retry_pause, outs, 64, &count) != GZ_CHAIN_OK)
                goto out;
            for (size_t k = 0; k < count && n < MAX_COINS; k++) {
                if (!outs[k].confirmed) {
                    /* not spendable yet, but its change index is taken */
                    if (change == 1 && n_used < MAX_COINS) used[n_used++] = i;
                    continue;
                }
                coins[n] = c;
                memcpy(coins[n].txid, outs[k].txid, 32);
                coins[n].vout = outs[k].vout;
                coins[n].amount = outs[k].value;
                n++;
            }
        }
    }
    printf("confirmed coins found %zu\n", n);
    req.used_change_indexes = used;
    req.n_used_change_indexes = n_used;
    if (!n || !build_and_print(ctx, &master, &req, coins, n, &f)) goto out;
    if (a->expect_txid && memcmp(expect, f.info.txid, 32) != 0) {
        fprintf(stderr, "gz-wallet-tx: the built txid is not --expect-txid %s; nothing signed "
                        "or sent\n", a->expect_txid);
        goto out;
    }
    if (a->broadcast) {
        size_t len;
        if (!release_signed(ctx, &master, &f, raw, sizeof raw, &len)) goto out;
        printf("signed ");
        hex_out(raw, len, 0);
        printf("\n");
        if (!broadcast_and_report(&cv, raw, len)) goto out;
    }
    rc = 0;
out:
    gzt_funding_wipe(&f);
    gzw_wipe(&master, sizeof master);
    chain_close(&cv);
    return rc;
}

/* Every input's previous output, looked up through the comparing backend
 * (same retries as the scan); the fee from the real size, refused above the
 * ceiling rate as the funding builder does: fee at most
 * ceil(vsize x ceiling / 1000). */
static int check_inputs(const chain_view *cv, const gzt_tx *tx, uint8_t (*wallet)[100][34],
                        uint64_t scan, uint32_t coin, uint64_t retry_pause, uint64_t max_rate) {
    static uint8_t prev[PREV_TX_MAX];
    uint64_t in_total = 0, out_total = 0, w, vs;
    for (uint32_t i = 0; i < tx->n_in; i++) {
        char what[128], hex[65];
        const uint8_t *script;
        size_t script_len;
        uint64_t value;
        int found = 0;
        for (int k = 0; k < 32; k++) snprintf(hex + 2 * k, 3, "%02x", tx->in[i].prev_txid[31 - k]);
        snprintf(what, sizeof what, "input %u (%s:%u)", i, hex, tx->in[i].prev_vout);
        raw_arg r = {tx->in[i].prev_txid, prev, 0};
        gz_chain_result res = with_retries(cv, call_raw, &r, retry_pause, what);
        if (res != GZ_CHAIN_OK) {
            fprintf(stderr, "gz-wallet-tx: the coin spent by input %u is not known to the "
                            "servers (%s); nothing sent\n", i, gz_chain_result_name(res));
            return 0;
        }
        if (!prev_output(prev, r.len, tx->in[i].prev_vout, &value, &script, &script_len)) {
            fprintf(stderr, "gz-wallet-tx: input %u spends an output its transaction does not "
                            "have; nothing sent\n", i);
            return 0;
        }
        in_total += value;
        printf("input %u %llu from ", i, (unsigned long long)value);
        for (uint32_t ch = 0; wallet && ch < 2 && !found; ch++)
            for (uint32_t k = 0; k < scan && !found; k++)
                if (script_len == 34 && !memcmp(script, wallet[ch][k], 34)) {
                    printf("this wallet at m/86'/%u'/0'/%u/%u\n", coin, ch, k);
                    found = 1;
                }
        if (!found) printf("%s\n", wallet ? "outside this wallet" : "a coin not checked");
    }
    for (uint32_t o = 0; o < tx->n_out; o++) out_total += tx->out[o].value;
    gzt_tx_weight(tx, &w, &vs);
    if (in_total < out_total || in_total > GZT_MAX_MONEY) {
        fprintf(stderr, "gz-wallet-tx: the outputs exceed the inputs; nothing sent\n");
        return 0;
    }
    uint64_t fee = in_total - out_total, limit = (vs * max_rate + 999) / 1000;
    printf("fee %llu\nvsize %llu\nfeerate %llu sat/kvB, ceiling %llu\n", (unsigned long long)fee,
           (unsigned long long)vs, (unsigned long long)(vs ? fee * 1000 / vs : 0),
           (unsigned long long)max_rate);
    if (fee > limit) {
        fprintf(stderr, "gz-wallet-tx: fee %llu sat is above the ceiling (%llu sat for %llu vB "
                        "at %llu sat/kvB); nothing sent\n", (unsigned long long)fee,
                (unsigned long long)limit, (unsigned long long)vs, (unsigned long long)max_rate);
        return 0;
    }
    return 1;
}

/* Read a file of hex (white space at the end allowed) into raw. */
static int read_hex_file(const char *path, uint8_t *raw, size_t cap, size_t *len) {
    static char text[2 * GZT_MAX_TX_BYTES + 2];
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    size_t n = fread(text, 1, sizeof text - 1, fp);
    int more = fgetc(fp) != EOF;
    fclose(fp);
    if (more) return 0;
    while (n && (text[n - 1] == '\n' || text[n - 1] == '\r' || text[n - 1] == ' ')) n--;
    text[n] = 0;
    return n && unhex(text, raw, cap, len);
}

static int cmd_broadcast(const secp256k1_context *ctx, const args *a) {
    static uint8_t raw[GZT_MAX_TX_BYTES];
    static gzt_tx tx;
    static uint8_t wallet[2][100][34];
    uint8_t dest[GZT_MAX_SCRIPT], id[32], expect[32];
    size_t dest_len = 0, len = 0;
    gzt_network net;
    gzw_xprv master;
    chain_view cv;
    uint64_t scan, pace, retry_pause, max_rate;
    int have_dest = a->to_address || a->to_script, have_wallet = 0, rc = 1;
    if (!get_network(a->network, &net)) return 1;
    if (!a->hex || (!a->in && !have_dest) || !parse_u64(a->scan, 100, &scan) ||
        !pace_args(a, &pace, &retry_pause) || (have_dest && !dest_script(a, net, dest, &dest_len)) ||
        !parse_u64(a->max_feerate, GZT_FEERATE_MAX_SAT_PER_KVB, &max_rate) || !max_rate ||
        (a->expect_txid && !txid_from_hex(a->expect_txid, expect)))
        return usage();
    if (!read_hex_file(a->hex, raw, sizeof raw, &len)) {
        fprintf(stderr, "gz-wallet-tx: %s: not one transaction in lower-case hex\n", a->hex);
        return 1;
    }
    gzt_err e = gzt_tx_parse(raw, len, &tx);
    if (e) {
        fprintf(stderr, "gz-wallet-tx: %s: %s\n", a->hex, gzt_err_text(e));
        return 1;
    }
    gzt_tx_txid(&tx, id);
    printf("txid ");
    hex_out(id, 32, 1);
    printf("\n");
    if (a->expect_txid && memcmp(id, expect, 32) != 0) {
        fprintf(stderr, "gz-wallet-tx: the txid is not --expect-txid %s; nothing sent\n",
                a->expect_txid);
        return 1;
    }
    for (uint32_t i = 0; i < tx.n_in; i++) {
        if (!tx.in[i].witness_count) {
            fprintf(stderr, "gz-wallet-tx: input %u is not signed; nothing sent\n", i);
            return 1;
        }
    }
    if (a->in) {
        if (!master_from_file(ctx, a->in, &master)) return 1;
        have_wallet = 1;
        for (uint32_t ch = 0; ch < 2; ch++) {
            for (uint32_t i = 0; i < scan; i++) {
                gzt_coin c;
                if (!coin_at(ctx, &master, net, ch, i, &c)) {
                    gzw_wipe(&master, sizeof master);
                    return 1;
                }
                memcpy(wallet[ch][i], c.script, 34);
            }
        }
        gzw_wipe(&master, sizeof master);
    }
    /* every output must be the stated destination or a wallet output */
    for (uint32_t o = 0; o < tx.n_out; o++) {
        const gzt_txout *out = &tx.out[o];
        int found = 0;
        printf("output %u %llu ", o, (unsigned long long)out->value);
        if (have_dest && out->script_len == dest_len && !memcmp(out->script, dest, dest_len)) {
            printf("to the stated destination\n");
            continue;
        }
        for (uint32_t ch = 0; have_wallet && ch < 2 && !found; ch++) {
            for (uint32_t i = 0; i < scan && !found; i++) {
                if (out->script_len == 34 && !memcmp(out->script, wallet[ch][i], 34)) {
                    printf("to this wallet at m/86'/%u'/0'/%u/%u\n", coin_type(net), ch, i);
                    found = 1;
                }
            }
        }
        if (!found) {
            printf("to ");
            hex_out(out->script, out->script_len, 0);
            printf("\n");
            fprintf(stderr, "gz-wallet-tx: output %u pays neither this wallet (indexes 0..%llu) "
                            "nor the stated destination; nothing sent\n",
                    o, (unsigned long long)scan - 1);
            return 1;
        }
    }
    if (!chain_open(&cv, net, a)) {
        fprintf(stderr, "gz-wallet-tx: cannot set up the chain servers\n");
    } else if (check_inputs(&cv, &tx, have_wallet ? wallet : NULL, scan, coin_type(net),
                            retry_pause, max_rate) &&
               broadcast_and_report(&cv, raw, len)) {
        rc = 0;
    }
    chain_close(&cv);
    return rc;
}

static int cmd_confirm(const args *a) {
    gzt_network net;
    chain_view cv;
    uint8_t txid[32];
    gz_confirmation conf;
    int rc = 1;
    if (!get_network(a->network, &net)) return 1;
    if (!a->txid || !txid_from_hex(a->txid, txid)) return usage();
    if (chain_open(&cv, net, a)) {
        gz_chain_result r = gz_chain_confirm_tx(&cv.multi, cv.net, txid, 6, &conf);
        if (r != GZ_CHAIN_OK) {
            fprintf(stderr, "gz-wallet-tx: %s\n", gz_chain_result_name(r));
        } else {
            const char *st = conf.status.state == GZ_TX_CONFIRMED ? "confirmed"
                             : conf.status.state == GZ_TX_MEMPOOL ? "mempool" : "unknown";
            /* the count checked along linked headers (at most 6 asked for),
             * not the servers' claim */
            printf("state %s\nheight %u\nconfirmations %u\n", st, conf.status.height,
                   conf.checked_confirmations);
            rc = 0;
        }
    }
    chain_close(&cv);
    return rc;
}
#endif

int main(int argc, char **argv) {
    args a;
    struct rlimit no_core = {0, 0};
    setrlimit(RLIMIT_CORE, &no_core);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    /* line by line, so output sent with the errors to one file stays in order */
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2 || !parse_args(argc, argv, &a)) return usage();
    if (!strcmp(argv[1], "decode")) return cmd_decode();
#ifdef GZT_WITH_CHAIN
    if (!strcmp(argv[1], "confirm")) return cmd_confirm(&a);
#endif
    if (strcmp(argv[1], "plan") && strcmp(argv[1], "fund") && strcmp(argv[1], "broadcast"))
        return usage();
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    uint8_t seed[32];
    if (!ctx || getrandom(seed, 32, 0) != 32 || !secp256k1_context_randomize(ctx, seed)) return 1;
    int rc = 2;
    if (!strcmp(argv[1], "plan")) rc = cmd_plan(ctx, &a);
#ifdef GZT_WITH_CHAIN
    else if (!strcmp(argv[1], "broadcast")) rc = cmd_broadcast(ctx, &a);
    else rc = cmd_fund(ctx, &a);
#else
    else fprintf(stderr, "gz-wallet-tx: built without the chain port; use plan\n");
#endif
    secp256k1_context_destroy(ctx);
    return rc;
}
