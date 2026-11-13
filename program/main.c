/* SPDX-License-Identifier: MIT */
/* gazpacho: the Gazpacho wallet program (walking skeleton, stream S11).
 *
 *   gazpacho --data-dir DIR --role host|member [options]   (gazpacho --help)
 *
 * One program per data folder (a lock), test networks only (mainnet is
 * refused before anything is opened), host and member roles in one
 * executable. See docs/notes/program.md. */
#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <secp256k1.h>

#include "gazpacho/wallet_keys.h"

#include "datadir.h"
#include "executor.h"
#include "gzp.h"
#include "net.h"
#include "notify.h"
#include "pchain.h"
#include "testping.h"

#define RESTART_LIMIT 5

static volatile sig_atomic_t stop_flag;
static void on_signal(int sig)
{
    (void)sig;
    stop_flag = 1;
}

static gzp_exec_t ex;          /* large: kept off the stack */
static gzp_net_t net;
static gzp_chain_t chain;
static gzp_testping_t tp;
static gzp_datadir_t dir;

static int key_ok(const uint8_t key[32], void *ctx)
{
    return secp256k1_ec_seckey_verify((const secp256k1_context *)ctx, key);
}

#ifdef GZP_CORE_RANDOM_PURPOSE
static void net_random(void *ctx, gzp_purpose_t purpose, uint8_t *out, size_t len)
{
    (void)ctx;
    (void)purpose;
    gzp_os_random(out, len);
}
#else
static void net_random(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    gzp_os_random(out, len);
}
#endif

/* The wallet: 24 words from the stand-in seed file, and the first receive
 * address (BIP 86, account 0) as a check that the keys are reachable. */
static int wallet_open(const secp256k1_context *secp, gzw_network wnet, gzw_bip86_output *first)
{
    uint8_t entropy[32], seed[64];
    char phrase[GZW_PHRASE_MAX];
    gzw_xprv master;
    gzw_reason why;
    int rc = GZP_EXIT_DATA, ok;
    if (gzp_datadir_secret(&dir, "wallet-seed.standin", entropy, NULL, NULL) != 0) return GZP_EXIT_DATA;
    ok = gzw_phrase_from_entropy(entropy, phrase) == 1 && gzw_phrase_to_seed(phrase, "", seed) == 1 &&
         gzw_bip32_master(secp, seed, sizeof seed, &master, &why) == 1 &&
         gzw_bip86_output_from_master(secp, &master, wnet, 0, 0, 0, first, &why) == 1;
    if (ok) rc = 0;
    else fprintf(stderr, "gazpacho: cannot derive the wallet's keys\n");
    gzw_wipe(entropy, sizeof entropy);
    gzw_wipe(seed, sizeof seed);
    gzw_wipe(phrase, sizeof phrase);
    gzw_wipe(&master, sizeof master);
    return rc;
}

int main(int argc, char **argv)
{
    gzp_options_t opt;
    secp256k1_context *secp = NULL;
    uint8_t priv[32], rseed[32];
    gz_conn_limits_t lim;
    gz_random_port_t rnd;
    gzp_net_events_t nev;
    gz_network network;
    gzw_network wnet;
    gzw_bip86_output first;
    struct sigaction sa;
    char hex[67];
    int rc, i, restarts = 0;

    net.listen_fd = -1;
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
        gzp_usage();
        return 0;
    }
    if ((rc = gzp_options_parse(&opt, argc, argv)) != 0) return rc;
    gzp_log_set_name(opt.name);
    if (!gz_network_from_name(opt.network, &network) || !gz_network_is_test(network) ||
        !gzw_network_from_name(opt.network, &wnet) || wnet == GZW_NET_MAINNET) {
        fprintf(stderr, "gazpacho: refusing network %s\n", opt.network);
        return GZP_EXIT_USAGE;
    }

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    rc = gzp_datadir_open(&dir, opt.data_dir, opt.role == GZP_ROLE_HOST ? "host" : "member", opt.network);
    if (rc) return rc;

    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    gzp_os_random(rseed, sizeof rseed);
    if (!secp || !secp256k1_context_randomize(secp, rseed)) {
        fprintf(stderr, "gazpacho: cannot set up secp256k1\n");
        rc = GZP_EXIT_FAILED;
        goto out;
    }
    OPENSSL_cleanse(rseed, sizeof rseed);
    if ((rc = gzp_datadir_secret(&dir, "transport.key", priv, key_ok, secp)) != 0) goto out;
    if ((rc = wallet_open(secp, wnet, &first)) != 0) goto out;
    gzp_log("wallet network=%s first-address=%s", opt.network, first.address);

    /* The transport. */
    gz_conn_default_limits(&lim);
    lim.handshake_ms = opt.handshake_ms;
    lim.recv_ms = opt.recv_ms;
    lim.send_ms = opt.send_ms;
    rnd.fill = net_random;
    rnd.ctx = NULL;
    memset(&nev, 0, sizeof nev); /* the executor sets the events */
    if (gzp_net_init(&net, secp, priv, rnd, &lim, opt.reconnect_ms, &nev) != 0) {
        OPENSSL_cleanse(priv, sizeof priv);
        fprintf(stderr, "gazpacho: bad transport key\n");
        rc = GZP_EXIT_DATA;
        goto out;
    }
    OPENSSL_cleanse(priv, sizeof priv);
    gzp_hex(net.pub, 33, hex);
    if (opt.role == GZP_ROLE_HOST) {
        if (gzp_net_listen(&net, opt.listen_host, opt.listen_port) != 0) {
            rc = GZP_EXIT_FAILED;
            goto out;
        }
        gzp_log("listening address=%s:%u key=%s", opt.listen_host, (unsigned)net.bound_port, hex);
    } else {
        gzp_net_target(&net, opt.connect_host, opt.connect_port, opt.connect_key);
        gzp_log("member key=%s host-peer=%016llx", hex, (unsigned long long)gzp_peer_id(opt.connect_key));
    }

    /* The chain. */
    if (opt.no_chain) {
        gzp_chain_none(&chain, network);
        gzp_log("chain off");
    } else if ((rc = gzp_chain_open(&chain, opt.chain_urls[0], network, opt.chain_poll_ms)) != 0) {
        goto out;
    }
    if (opt.test_exit_after_chain) {
        if (chain.active) gzp_chain_show_outputs(&chain, first.script_pubkey, sizeof first.script_pubkey);
        rc = 0;
        goto out;
    }

    /* The local interface: the API server (PR 26) is not merged yet. */
    if (opt.no_interface) gzp_log("interface off");
    else gzp_log("interface not-built port=%u", (unsigned)(opt.interface_port ? opt.interface_port : 39735));

    gzp_testping_init(&tp, opt.test_pings, opt.test_ping_ms, opt.name);
    gzp_notify_lines(&ex.notify);
    ex.opt = &opt;
    ex.dir = &dir;
    ex.net = &net;
    ex.chain = &chain;
    ex.tp = &tp;
    ex.stop = &stop_flag;

    for (i = 1;; i++) {
        int r = gzp_exec_incarnation(&ex, i);
        if (r == GZP_RUN_STOP) {
            rc = 0;
            break;
        }
        if (r == GZP_RUN_FAILED) {
            rc = GZP_EXIT_DATA;
            break;
        }
        /* Fatal: start again from storage, under a new incarnation. Peers see
         * the connection go and send again what was not answered. */
        if (++restarts > RESTART_LIMIT) {
            gzp_log("stopping after %d restarts", RESTART_LIMIT);
            rc = GZP_EXIT_FAILED;
            break;
        }
        gzp_log("restart-from-storage after=%s", ex.fatal_why ? ex.fatal_why : "-");
        gzp_net_drop_all(&net);
    }
    gzp_log("stopped status=%d", rc);

out:
    gzp_net_free(&net);
    gzp_chain_close(&chain);
    if (secp) secp256k1_context_destroy(secp);
    gzp_datadir_close(&dir);
    return rc;
}
