/* SPDX-License-Identifier: MIT */
/* gazpacho: the Gazpacho wallet program (walking skeleton, stream S11).
 *
 *   gazpacho --data-dir DIR --role host|member [options]   (gazpacho --help)
 *
 * One program per data folder (a lock), signet or testnet4 only (mainnet is
 * refused before anything is opened), host and member roles in one
 * executable. gazpacho-test is the same program built with the transport's
 * test kind and the --test-* hooks. See docs/notes/program.md. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <secp256k1.h>

#include "gazpacho/wallet_keys.h"
#include "lnmsg.h"

#include "datadir.h"
#include "executor.h"
#include "gzp.h"
#include "net.h"
#include "notify.h"
#include "pchain.h"
#include "testping.h"

/* More than RESTART_LIMIT restarts from storage within RESTART_WINDOW_MS
 * stops the program (review of PR 27, M6): a fault that keeps coming back is
 * not retried for ever, and unrelated faults a month apart never add up. */
#define RESTART_LIMIT 5
#define RESTART_WINDOW_MS (10u * 60u * 1000u)
static uint64_t restart_at[RESTART_LIMIT + 1];

static volatile sig_atomic_t stop_flag;
static int stop_pipe[2] = {-1, -1};

/* The self-pipe: the one loop sees a stop as a readable descriptor
 * (contract-v2.md section 4), so it needs no fixed wake-up. */
static void on_signal(int sig)
{
    int saved = errno;
    (void)sig;
    stop_flag = 1;
    if (stop_pipe[1] >= 0 && write(stop_pipe[1], "x", 1) < 0) {
        /* full or closed: the flag is enough */
    }
    errno = saved;
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

/* The transport's own random type (noise.h): the system's source at each call. */
static void net_random(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    gzp_os_random(out, len);
}

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
    gzp_net_limits_t lim;
    gz_net_random_t rnd;
    gzp_net_events_t nev;
    gz_network network;
    gzw_network wnet;
    gzw_bip86_output first;
    struct sigaction sa;
    char hex[67];
    const uint8_t *chain_hash;
    int rc, i, restarts = 0, have_net = 0, have_dir = 0, stopped = 0;

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
    chain_hash = network == GZ_NET_SIGNET ? GZ_LN_CHAIN_SIGNET
               : network == GZ_NET_TESTNET4 ? GZ_LN_CHAIN_TESTNET4 : NULL;
    if (!chain_hash) {
        fprintf(stderr, "gazpacho: refusing network %s (signet or testnet4)\n", opt.network);
        return GZP_EXIT_USAGE;
    }

    if (pipe(stop_pipe) != 0 || fcntl(stop_pipe[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(stop_pipe[1], F_SETFL, O_NONBLOCK) != 0 || fcntl(stop_pipe[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(stop_pipe[1], F_SETFD, FD_CLOEXEC) != 0) {
        fprintf(stderr, "gazpacho: cannot make the stop pipe\n");
        return GZP_EXIT_FAILED;
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    /* Output lines go to whatever reads standard output; if it goes away the
     * program carries on (review of PR 27, M4). Sockets use MSG_NOSIGNAL. */
    signal(SIGPIPE, SIG_IGN);

    rc = gzp_datadir_open(&dir, opt.data_dir, opt.role == GZP_ROLE_HOST ? "host" : "member", opt.network);
    if (rc) return rc;
    have_dir = 1;

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

    /* The chain (before the transport: --check-chain needs nothing else). */
    if (opt.no_chain) {
        gzp_chain_none(&chain, network);
        gzp_log("chain off");
    } else if ((rc = gzp_chain_open(&chain, opt.chain_urls[0], network, opt.chain_poll_ms)) != 0) {
        OPENSSL_cleanse(priv, sizeof priv);
        goto out;
    }
    if (opt.check_chain) {
        OPENSSL_cleanse(priv, sizeof priv);
        if (chain.active) gzp_chain_show_outputs(&chain, first.script_pubkey, sizeof first.script_pubkey);
        rc = 0;
        goto out;
    }

    /* The transport (peers.h). Nothing listens or connects until the start. */
    lim.handshake_ms = opt.handshake_ms;
    lim.recv_ms = opt.recv_ms;
    lim.send_ms = opt.send_ms;
    lim.ping_ms = opt.ping_ms;
    lim.pong_ms = opt.pong_ms;
    lim.max_per_address = opt.max_per_address;
    rnd.fill = net_random;
    rnd.ctx = NULL;
    memset(&nev, 0, sizeof nev); /* the executor sets the events */
    i = gzp_net_init(&net, secp, priv, rnd, chain_hash, &lim, opt.reconnect_ms, &nev);
    OPENSSL_cleanse(priv, sizeof priv);
    if (i != 0) {
        fprintf(stderr, "gazpacho: the transport refused its configuration\n");
        rc = GZP_EXIT_DATA;
        goto out;
    }
    have_net = 1;
    gzp_hex(net.pub, 33, hex);
    if (opt.role == GZP_ROLE_HOST) {
        gzp_net_set_listen(&net, opt.listen_host, opt.listen_port);
        gzp_log("host key=%s", hex);
    } else {
        gzp_net_target(&net, opt.connect_host, opt.connect_port, opt.connect_key);
        gzp_log("member key=%s host-peer=%016llx", hex, (unsigned long long)gzp_peer_id(opt.connect_key));
    }

    /* The local interface: the API server is not wired yet (P5, P6). */
    if (opt.no_interface) gzp_log("interface off");
    else gzp_log("interface not-built port=%u", (unsigned)(opt.interface_port ? opt.interface_port
                                                         : network == GZ_NET_TESTNET4 ? 39736 : 39735));

#ifdef GZP_TEST_BUILD
    gzp_testping_init(&tp, opt.test_pings, opt.test_ping_ms, opt.name);
    gzp_testping_burst(&tp, opt.test_burst_n, opt.test_burst_bytes);
#endif
    gzp_notify_lines(&ex.notify);
    ex.opt = &opt;
    ex.dir = &dir;
    ex.net = &net;
    ex.chain = &chain;
    ex.tp = &tp;
    ex.stop = &stop_flag;
    ex.stop_fd = stop_pipe[0];

    for (i = 1;; i++) {
        int r = gzp_exec_incarnation(&ex, i);
        uint64_t now;
        if (r == GZP_RUN_STOP) {
            rc = 0;
            stopped = 1;
            break;
        }
        if (r == GZP_RUN_FAILED) {
            rc = GZP_EXIT_DATA;
            break;
        }
        if (r == GZP_RUN_POISONED) {
            /* Never start again in this process: it would read back what the
             * failed sync left in the page cache (store.h). */
            rc = GZP_EXIT_STORAGE;
            break;
        }
        /* Fatal: start again from storage, under a new incarnation. Every
         * connection and the listener close (peers see the loss and repair it
         * through their reconnect step); the next start opens them again. */
        /* The last RESTART_LIMIT + 1 restarts, in a ring: stop when the oldest
         * of them is within the window. */
        now = gzp_mono_ms();
        restart_at[restarts % (RESTART_LIMIT + 1)] = now;
        restarts++;
        if (restarts > RESTART_LIMIT && now - restart_at[restarts % (RESTART_LIMIT + 1)] <= RESTART_WINDOW_MS) {
            gzp_log("stopping after %d restarts within %u minutes", RESTART_LIMIT + 1, RESTART_WINDOW_MS / 60000u);
            rc = GZP_EXIT_FAILED;
            break;
        }
        gzp_log("restart-from-storage after=%s", ex.fatal_why ? ex.fatal_why : "-");
        if (gzp_net_reset(&net) != 0) {
            rc = GZP_EXIT_FAILED;
            break;
        }
        /* A stop asked for meanwhile is honoured before a new start (M6). */
        if (stop_flag) {
            gzp_log("stop during restart: no new start");
            rc = 0;
            stopped = 1;
            break;
        }
    }

out:
    /* The shutdown order (contract-v2.md section 4): the node is stopped (its
     * runner and every held action are gone with the incarnation); the API
     * server and the chain worker come here with P5 to P7; then every
     * connection closes without events; then storage; then the lock. */
    /* Each line reports the state of the other resources at that moment, read
     * from them, so a reordering shows (review of PR 27, M5). */
    if (stopped) gzp_log("shutdown node-stopped transport=%d storage=%d lock=%d", net.peers != NULL, ex.store_open,
                         dir.lock_fd >= 0);
    if (have_net) gzp_net_free(&net);
    if (stopped) gzp_log("shutdown connections-closed transport=%d storage=%d lock=%d", net.peers != NULL,
                         ex.store_open, dir.lock_fd >= 0);
    gzp_chain_close(&chain);
    gzp_exec_close_storage(&ex);
    if (stopped) gzp_log("shutdown storage-closed transport=%d storage=%d lock=%d", net.peers != NULL,
                         ex.store_open, dir.lock_fd >= 0);
    if (secp) secp256k1_context_destroy(secp);
    if (have_dir) gzp_datadir_close(&dir);
    if (stopped) gzp_log("shutdown lock-released transport=%d storage=%d lock=%d", net.peers != NULL,
                         ex.store_open, dir.lock_fd >= 0);
    if (rc == GZP_EXIT_STORAGE)
        fprintf(stderr, "gazpacho: a write to the journal failed and could not be undone; not restarted. "
                        "Check the disk, then remove %s/storage.failed\n", opt.data_dir);
    gzp_log("stopped status=%d", rc);
    return rc;
}
