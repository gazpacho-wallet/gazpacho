/* gz-wallet-tx: build, sign and send a funding transaction from a phrase file.
 *
 *   gz-wallet-tx decode                              (transaction hex on stdin)
 *   gz-wallet-tx plan --network NET --in FILE PAY --change-index N [FEE]
 *                     --coin TXID:VOUT:AMOUNT:CHANGE:INDEX ... [--release]
 *   gz-wallet-tx fund --network signet --in FILE PAY --change-index N [FEE]
 *                     [--scan N] [--broadcast]
 *   gz-wallet-tx confirm --network signet --txid TXID
 *
 *   PAY is --to-address ADDR or --to-script HEX, and --amount SAT.
 *   FEE is --feerate SAT_PER_KVB (default 100, that is 0.1 sat/vB) or
 *   --feerate server, and --max-feerate SAT_PER_KVB (default 1000).
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

static int usage(void) {
    fprintf(stderr,
            "usage: gz-wallet-tx decode < HEX\n"
            "       gz-wallet-tx plan --network NET --in FILE (--to-address A | --to-script HEX)\n"
            "            --amount SAT --change-index N [--feerate R] [--max-feerate C]\n"
            "            --coin TXID:VOUT:AMOUNT:CHANGE:INDEX ... [--release]\n"
            "       gz-wallet-tx fund --network signet --in FILE (--to-address A | --to-script HEX)\n"
            "            --amount SAT --change-index N [--feerate R|server] [--max-feerate C]\n"
            "            [--scan N] [--broadcast]\n"
            "       gz-wallet-tx confirm --network signet --txid TXID\n");
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
        *max_feerate, *scan, *txid;
    const char *coins[MAX_COINS];
    size_t n_coins;
    int release, broadcast;
} args;

static int parse_args(int argc, char **argv, args *a) {
    memset(a, 0, sizeof *a);
    a->feerate = "100";
    a->max_feerate = "1000";
    a->scan = "20";
    for (int i = 2; i < argc; i++) {
        const char *k = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        const char **slot = !strcmp(k, "--network") ? &a->network
                            : !strcmp(k, "--in") ? &a->in
                            : !strcmp(k, "--to-address") ? &a->to_address
                            : !strcmp(k, "--to-script") ? &a->to_script
                            : !strcmp(k, "--amount") ? &a->amount
                            : !strcmp(k, "--change-index") ? &a->change_index
                            : !strcmp(k, "--feerate") ? &a->feerate
                            : !strcmp(k, "--max-feerate") ? &a->max_feerate
                            : !strcmp(k, "--scan") ? &a->scan
                            : !strcmp(k, "--txid") ? &a->txid : NULL;
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

/* Fill the request from the arguments (everything except the fee rate). */
static int make_request(const args *a, gzt_network net, uint8_t script[GZT_MAX_SCRIPT],
                        gzt_funding_request *req) {
    uint64_t v;
    size_t len = 0;
    memset(req, 0, sizeof *req);
    req->net = net;
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
        printf("change %llu at m/86'/coin'/0'/1/%u\n", (unsigned long long)f->info.change,
               f->info.change_index);
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

typedef struct {
    gz_http http;
    gz_chain servers[2], multi;
} chain_view;

static int chain_open(chain_view *cv, gzt_network net) {
    gz_esplora_config cfg;
    gz_multi_config mc;
    memset(cv, 0, sizeof *cv);
    if (!gzt_network_eq(net, GZT_NET_SIGNET)) {
        fprintf(stderr, "gz-wallet-tx: the chain commands support signet only\n");
        return 0;
    }
    if (!gz_http_curl_create(&cv->http, false)) return 0;
    for (int i = 0; i < 2; i++) {
        gz_esplora_config_default(&cfg);
        cfg.base_url = SIGNET_SERVERS[i];
        if (gz_esplora_create(&cfg, &cv->http, &cv->servers[i]) != GZ_CHAIN_OK) return 0;
    }
    gz_multi_config_default(&mc);
    return gz_multi_create(&mc, cv->servers, 2, &cv->multi) == GZ_CHAIN_OK;
}

static void chain_close(chain_view *cv) {
    gz_chain_destroy(&cv->multi);
    for (int i = 0; i < 2; i++) gz_chain_destroy(&cv->servers[i]);
    gz_http_curl_destroy(&cv->http);
}

static int cmd_fund(const secp256k1_context *ctx, const args *a) {
    static gzt_coin coins[MAX_COINS];
    static gzt_funding f;
    static uint8_t raw[GZT_MAX_TX_BYTES];
    static gz_chain_output outs[64];
    static uint32_t used[MAX_COINS];
    size_t n_used = 0;
    uint8_t script[GZT_MAX_SCRIPT];
    gzt_funding_request req;
    gzt_network net;
    gzw_xprv master;
    chain_view cv;
    uint64_t scan;
    size_t n = 0;
    int rc = 1;
    if (!get_network(a->network, &net)) return 1;
    if (!a->in || !make_request(a, net, script, &req) || !parse_u64(a->scan, 100, &scan))
        return usage();
    if (!chain_open(&cv, net)) {
        fprintf(stderr, "gz-wallet-tx: cannot set up the chain servers\n");
        chain_close(&cv);
        return 1;
    }
    if (!master_from_file(ctx, a->in, &master)) goto out;
    if (!strcmp(a->feerate, "server")) {
        gz_fee_estimates est;
        gz_chain_result r = gz_chain_fee_estimates(&cv.multi, &est);
        if (r != GZ_CHAIN_OK || est.count == 0) {
            fprintf(stderr, "gz-wallet-tx: no fee estimate: %s\n", gz_chain_result_name(r));
            goto out;
        }
        size_t pick = est.count - 1; /* the first target of at least 6 blocks */
        for (size_t i = 0; i < est.count; i++)
            if (est.entries[i].target >= 6) { pick = i; break; }
        gzt_err e = gzt_feerate_from_server(est.entries[pick].sat_per_kvb, req.fee.ceiling,
                                            &req.fee.rate);
        if (e) {
            fprintf(stderr, "gz-wallet-tx: server rate %llu sat/kvB refused: %s\n",
                    (unsigned long long)est.entries[pick].sat_per_kvb, gzt_err_text(e));
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
            gz_chain_result r = gz_chain_script_outputs(&cv.multi, c.script, 34, outs, 64, &count);
            if (r != GZ_CHAIN_OK) {
                fprintf(stderr, "gz-wallet-tx: coin lookup failed: %s\n", gz_chain_result_name(r));
                goto out;
            }
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
    if (a->broadcast) {
        size_t len;
        gz_broadcast_result br;
        if (!release_signed(ctx, &master, &f, raw, sizeof raw, &len)) goto out;
        printf("signed ");
        hex_out(raw, len, 0);
        printf("\n");
        gz_chain_result r = gz_chain_broadcast(&cv.multi, raw, len, &br);
        if (r != GZ_CHAIN_OK) {
            fprintf(stderr, "gz-wallet-tx: broadcast failed: %s %s\n", gz_chain_result_name(r),
                    br.reason);
            goto out;
        }
        printf("broadcast ok\n");
    }
    rc = 0;
out:
    gzt_funding_wipe(&f);
    gzw_wipe(&master, sizeof master);
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
    if (chain_open(&cv, net)) {
        gz_chain_result r = gz_chain_confirm_tx(&cv.multi, GZ_NET_SIGNET, txid, &conf);
        if (r != GZ_CHAIN_OK) {
            fprintf(stderr, "gz-wallet-tx: %s\n", gz_chain_result_name(r));
        } else {
            const char *st = conf.status.state == GZ_TX_CONFIRMED ? "confirmed"
                             : conf.status.state == GZ_TX_MEMPOOL ? "mempool" : "unknown";
            printf("state %s\nheight %u\nconfirmations %u\n", st, conf.status.height,
                   conf.status.confirmations);
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
    if (argc < 2 || !parse_args(argc, argv, &a)) return usage();
    if (!strcmp(argv[1], "decode")) return cmd_decode();
#ifdef GZT_WITH_CHAIN
    if (!strcmp(argv[1], "confirm")) return cmd_confirm(&a);
#endif
    if (strcmp(argv[1], "plan") && strcmp(argv[1], "fund")) return usage();
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    uint8_t seed[32];
    if (!ctx || getrandom(seed, 32, 0) != 32 || !secp256k1_context_randomize(ctx, seed)) return 1;
    int rc = 2;
    if (!strcmp(argv[1], "plan")) rc = cmd_plan(ctx, &a);
#ifdef GZT_WITH_CHAIN
    else rc = cmd_fund(ctx, &a);
#else
    else fprintf(stderr, "gz-wallet-tx: built without the chain port; use plan\n");
#endif
    secp256k1_context_destroy(ctx);
    return rc;
}
