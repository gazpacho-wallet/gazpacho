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
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <openssl/crypto.h>
#include <secp256k1.h>

#include "gazpacho/envelope.h"
#include "gazpacho/wallet_keys.h"
#include "lnmsg.h"

#include "datadir.h"
#include "executor.h"
#include "gzp.h"
#include "net.h"
#include "notify.h"
#include "pchain.h"
#include "store_unlock.h"
#include "testping.h"
#ifdef GZP_TEST_BUILD
#include "gz_storage_crypto_test.h"
#endif

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
#ifdef GZP_TEST_BUILD
#define DUMPING (opt.test_dump_journal)
#else
#define DUMPING 0
#endif
static gzp_testping_t tp;
static gzp_datadir_t dir;
static gzp_wallet_t *wallet;

#ifdef GZP_TEST_BUILD
/* --test-dump-journal: every batch and record of the journal, read only (the
 * stand-in's scan may cut a torn tail, as at any start). */
static int dump_journal(gzp_datadir_t *d, const gzp_options_t *o)
{
    gzp_store_t st;
    gzp_batch_t b;
    char err[200] = "";
    size_t i;
    if (!o->test_standin_store) {
        /* The sealed journal, read only, under the unlocked wallet's keys. */
        if (gzp_journal_dump(d->dir, wallet, err, sizeof err) != 0) {
            fprintf(stderr, "gazpacho: %s\n", err);
            return GZP_EXIT_DATA;
        }
        return 0;
    }
    if (gzp_standin_open(&st, d->dir, err, sizeof err) != 0) {
        fprintf(stderr, "gazpacho: %s\n", err);
        return GZP_EXIT_DATA;
    }
    st.ops->rewind(st.ctx);
    while (st.ops->next(st.ctx, &b)) {
        printf("journal-batch inc=%llu seq=%llu records=%zu\n", (unsigned long long)b.id.incarnation,
               (unsigned long long)b.id.sequence, b.n_records);
        for (i = 0; i < b.n_records; i++)
            printf("journal-record inc=%llu seq=%llu type=0x%08x len=%zu\n", (unsigned long long)b.id.incarnation,
                   (unsigned long long)b.id.sequence, (unsigned)b.records[i].type, b.records[i].bytes.len);
    }
    st.ops->close(st.ctx);
    fflush(stdout);
    return 0;
}
#endif

#ifdef GZP_TEST_BUILD
/* --test-append-batch: one batch through the store the unlock opened, under
 * its new incarnation, sequence 1. */
static int append_batch(const char *hex)
{
    size_t n = strlen(hex) / 2, at = 0, k = 0;
    uint8_t *b = malloc(n ? n : 1);
    gz_record_t recs[64];
    gzp_store_t st;
    gz_batch_id_t id;
    gz_batch_id_t done;
    int rc = GZP_EXIT_DATA;
    if (!b || !gzp_unhex(hex, n * 2, b, n) || gzp_wallet_take_store(wallet, &st) != 0) {
        free(b);
        return GZP_EXIT_USAGE;
    }
    while (at + 8 <= n && k < 64) {
        uint32_t t = gz_get_u32(b + at), l = gz_get_u32(b + at + 4);
        if (l > n - at - 8) break;
        recs[k].type = t;
        recs[k].bytes.data = b + at + 8;
        recs[k].bytes.len = l;
        k++;
        at += 8 + (size_t)l;
    }
    id.incarnation = gzp_journal_store_incarnation(&st);
    id.sequence = 1;
    if (at == n && st.ops->append(st.ctx, id, recs, k) == 0 && st.ops->complete(st.ctx, &done) == 1) rc = 0;
    st.ops->close(st.ctx);
    gzp_log("test-append-batch records=%zu status=%d", k, rc);
    free(b);
    return rc;
}
#endif

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
    uint8_t seed[64];
    gzw_xprv master;
    gzw_reason why;
    int rc = GZP_EXIT_DATA, ok;
    /* The BIP 39 seed is the unlocked storage layer's copy (storage 9.1). */
    if (gzp_wallet_seed(wallet, seed) != 0) return GZP_EXIT_DATA;
    ok = gzw_bip32_master(secp, seed, sizeof seed, &master, &why) == 1 &&
         gzw_bip86_output_from_master(secp, &master, wnet, 0, 0, 0, first, &why) == 1;
    if (ok) rc = 0;
    else fprintf(stderr, "gazpacho: cannot derive the wallet's keys\n");
    gzw_wipe(seed, sizeof seed);
    gzw_wipe(&master, sizeof master);
    return rc;
}

#ifdef GZP_TEST_BUILD
static int64_t wall_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
#endif

#ifdef GZP_TEST_BUILD
/* One job through the table, as the API's derivation thread and loop would. */
static int run_job(gzp_unlock_job_t *job)
{
    struct timespec d = {1, 100000000L}; /* one attempt a second */
    nanosleep(&d, NULL);
    gzp_wallet_begin(wallet, job);
    gzp_wallet_finish(wallet, job, wall_ms());
    return job->result.status;
}

/* --test-reveal-check: statuses only; every word is wiped here. */
static void reveal_check(const gzp_options_t *o)
{
    static gzp_unlock_job_t job, chk;
    uint8_t *pw = gz_sc_salloc(GZ_SC_PASS_IN_MAX + 1);
    static const int pos[3] = {1, 12, 24};
    int fd = pw ? open(o->test_passphrase_file, O_RDONLY | O_CLOEXEC) : -1;
    ssize_t r = fd >= 0 ? read(fd, pw, GZ_SC_PASS_IN_MAX + 1) : -1;
    size_t n;
    if (fd >= 0) close(fd);
    if (r < 0) {
        gz_sc_sfree(pw);
        return;
    }
    n = (size_t)r;
    if (n && pw[n - 1] == 10) n--;
    memset(&job, 0, sizeof job);
    job.op = GZP_UNLOCK_OP_REVEAL;
    job.passphrase = pw;
    job.passphrase_len = n;
    int st = run_job(&job);
    int full = 1;
    for (int i = 0; i < GZP_UNLOCK_WORDS; i++) full &= job.words[i][0] != 0;
    gzp_log("test-reveal status=%s words=%d", gzp_unlock_status_name(st), full ? GZP_UNLOCK_WORDS : 0);
    memset(&chk, 0, sizeof chk);
    chk.op = GZP_UNLOCK_OP_WORDS_CHECK;
    chk.passphrase = pw;
    chk.passphrase_len = n;
    for (int i = 0; i < 3; i++) {
        chk.positions[i] = pos[i];
        memcpy(chk.words[i], job.words[pos[i] - 1], GZP_UNLOCK_WORD_MAX);
    }
    gzp_log("test-words-check right status=%s", gzp_unlock_status_name(run_job(&chk)));
    chk.result.status = 0;
    memcpy(chk.words[1], job.words[pos[0] - 1], GZP_UNLOCK_WORD_MAX); /* position 12 given word 1 */
    if (!strcmp(job.words[pos[0] - 1], job.words[pos[1] - 1])) snprintf(chk.words[1], GZP_UNLOCK_WORD_MAX, "zoo");
    gzp_log("test-words-check changed status=%s", gzp_unlock_status_name(run_job(&chk)));
    OPENSSL_cleanse(&job, sizeof job);
    OPENSSL_cleanse(&chk, sizeof chk);
    memset(&job, 0, sizeof job);
    job.op = GZP_UNLOCK_OP_REVEAL;
    job.passphrase = (const uint8_t *)"not this wallet's passphrase at all";
    job.passphrase_len = strlen("not this wallet's passphrase at all");
    st = run_job(&job);
    full = job.words[0][0] != 0;
    gzp_log("test-reveal wrong status=%s words=%d", gzp_unlock_status_name(st), full ? 1 : 0);
    OPENSSL_cleanse(&job, sizeof job);
    gz_sc_sfree(pw);
}
#endif

#ifdef GZP_TEST_BUILD
/* --test-check-forged (review B of PR 54, M1): a wrong CHECK, then keys.gzk
 * forged with this wallet's ids over another passphrase and a CHECK with
 * that passphrase. Statuses and the count only. */
static void check_forged(void)
{
    static gzp_unlock_job_t job;
    static const char wrong[] = "not this wallet's passphrase at all";
    static const char forged[] = "the passphrase of a forged key file";
    gzp_unlock_result_t a;
    int st;
    memset(&job, 0, sizeof job);
    job.op = GZP_UNLOCK_OP_CHECK;
    job.passphrase = (const uint8_t *)wrong;
    job.passphrase_len = sizeof wrong - 1;
    gzp_log("test-check wrong status=%s", gzp_unlock_status_name(run_job(&job)));
    if (gzp_wallet_test_forge_keyfile(wallet, (const uint8_t *)forged, sizeof forged - 1) != 0) {
        gzp_log("test-check forged status=not-made wrong_in_row=0");
        return;
    }
    memset(&job, 0, sizeof job);
    job.op = GZP_UNLOCK_OP_CHECK;
    job.passphrase = (const uint8_t *)forged;
    job.passphrase_len = sizeof forged - 1;
    st = run_job(&job);
    memset(&a, 0, sizeof a);
    gzp_wallet_attempts(wallet, wall_ms(), &a);
    gzp_log("test-check forged status=%s wrong_in_row=%u", gzp_unlock_status_name(st), a.wrong_in_row);
    OPENSSL_cleanse(&job, sizeof job);
}
#endif

static const char *state_name(gzp_wallet_state_t s)
{
    return s == GZP_WALLET_NONE ? "none" : s == GZP_WALLET_LOCKED ? "locked" : "unlocked";
}

/* Come up locked and wait for the unlock (program.md 2, "Start order once
 * storage is encrypted"). The unlock path is the local interface (P5/P6,
 * program/unlock.h); gazpacho-test may unlock from --test-passphrase-file.
 * 0 once unlocked (storage open), -1 on a stop, or an exit status.
 * The passphrase is never logged: the output line gives the result only. */
#ifdef GZP_TEST_BUILD
/* --test-seed-check: seed() through the unlock.h table; results only, never
 * a byte of the seed. */
static void seed_check(int unlocked)
{
    gzp_unlock_t t = gzp_wallet_unlock_api(wallet);
    uint8_t s[64];
    int r, all_aa = 1, all_zero = 1;
    memset(s, 0xaa, sizeof s);
    r = t.seed(t.ctx, s);
    for (size_t i = 0; i < sizeof s; i++) {
        all_aa &= s[i] == 0xaa;
        all_zero &= s[i] == 0;
    }
    if (!unlocked) {
        gzp_log("test-seed locked rc=%d untouched=%d", r, all_aa);
        return;
    }
    gzp_log("test-seed unlocked rc=%d filled=%d", r, !all_aa && !all_zero);
    gzp_wallet_test_seed_fault(wallet, 1);
    memset(s, 0xaa, sizeof s);
    r = t.seed(t.ctx, s);
    all_zero = 1;
    for (size_t i = 0; i < sizeof s; i++) all_zero &= s[i] == 0;
    gzp_wallet_test_seed_fault(wallet, 0);
    gzp_log("test-seed fault rc=%d wiped=%d", r, all_zero);
    OPENSSL_cleanse(s, sizeof s);
}
#endif

static int wait_unlocked(const gzp_options_t *o)
{
    gzp_log("wallet state=%s", state_name(gzp_wallet_state(wallet)));
#ifdef GZP_TEST_BUILD
    if (o->test_seed_check) seed_check(0);
#endif
#ifdef GZP_TEST_BUILD
    if (o->test_passphrase_file) {
        gzp_unlock_job_t job;
        gzp_unlock_result_t pre;
        uint8_t *pw = gz_sc_salloc(GZ_SC_PASS_IN_MAX + 1); /* guarded, wiped when freed (8.4) */
        size_t n = 0;
        int fd = pw ? open(o->test_passphrase_file, O_RDONLY | O_CLOEXEC) : -1;
        ssize_t r = fd >= 0 ? read(fd, pw, GZ_SC_PASS_IN_MAX + 1) : -1;
        if (fd >= 0) close(fd);
        if (r < 0 || (size_t)r > GZ_SC_PASS_IN_MAX) {
            gz_sc_sfree(pw);
            fprintf(stderr, "gazpacho: cannot read the passphrase file\n");
            return GZP_EXIT_DATA;
        }
        n = (size_t)r;
        if (n && pw[n - 1] == 10) n--;
        memset(&job, 0, sizeof job);
        job.op = gzp_wallet_state(wallet) == GZP_WALLET_NONE ? GZP_UNLOCK_OP_CREATE : GZP_UNLOCK_OP_UNLOCK;
        job.passphrase = pw;
        job.passphrase_len = n;
        gzp_wallet_attempts(wallet, wall_ms(), &pre);
        /* One attempt a second, right or wrong (local-api.md 4.3): a test
         * restarting at once waits that second out, as a client would; a
         * delay after wrong passphrases is reported, not waited for. */
        if (pre.status == GZP_UNLOCK_BUSY && pre.wrong_in_row == 0 && pre.retry_after_s <= 2) {
            struct timespec d = {(time_t)pre.retry_after_s, 100000000L};
            nanosleep(&d, NULL);
            gzp_wallet_attempts(wallet, wall_ms(), &pre);
        }
        if (pre.status != GZP_UNLOCK_OK) {
            job.result = pre;
        } else {
            gzp_wallet_begin(wallet, &job);
            gzp_wallet_finish(wallet, &job, wall_ms());
        }
        gz_sc_sfree(pw);
        OPENSSL_cleanse(job.words, sizeof job.words);
        gzp_log("unlock op=%s status=%s wrong_in_row=%u attempts_left=%u retry_after_s=%u reason=%s",
                job.op == GZP_UNLOCK_OP_CREATE ? "create" : "unlock", gzp_unlock_status_name(job.result.status),
                job.result.wrong_in_row, job.result.attempts_left, job.result.retry_after_s,
                job.result.reason ? job.result.reason : "-");
        if (job.result.status != GZP_UNLOCK_OK) return GZP_EXIT_LOCKED_OUT;
        gzp_log("wallet state=%s", state_name(gzp_wallet_state(wallet)));
        if (o->test_reveal_check) reveal_check(o);
        if (o->test_seed_check) seed_check(1);
        if (o->test_check_forged) check_forged();
        return 0;
    }
#else
    (void)o;
#endif
    /* No unlock path in this build yet (the local interface is P5/P6): stay
     * locked, with nothing read, listening or connecting, until a stop. */
    gzp_log("locked: waiting for the local interface");
    while (!stop_flag) {
        struct pollfd pf;
        pf.fd = stop_pipe[0];
        pf.events = POLLIN;
        pf.revents = 0;
        if (poll(&pf, 1, -1) < 0 && errno != EINTR) break;
    }
    return -1; /* stopped while locked */
}

/* Storage 8.3 (review A of PR 54, M2): no core dumps and no same-user
 * ptrace, before any file is read; locked pages up to the hard limit. The
 * main process holds MSK, the seed and keys derived from them. */
static void no_dumps(void)
{
    struct rlimit rl = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        (void)setrlimit(RLIMIT_MEMLOCK, &rl);
    }
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

    no_dumps();

    /* The KDF helper (storage 8.4): this program, started by itself with a
     * socket on its standard input; it derives one key and exits. */
    if (argc == 2 && !strcmp(argv[1], "--gz-kdf-helper")) {
#ifdef GZP_TEST_BUILD
        /* gazpacho-test's helper takes its parent's test floor (--test-kdf-floor). */
        if (getenv("GZP_TEST_KDF_FLOOR")) gz_sc_test_set_floor(1, 8);
#endif
        return gz_sc_helper_main(0);
    }
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
        gzp_usage();
        return 0;
    }
    if ((rc = gzp_options_parse(&opt, argc, argv)) != 0) return rc;
    gzp_log_set_name(opt.name);
#ifdef GZP_TEST_BUILD
    {
        struct rlimit cl;
        int d = -1;
#ifdef __linux__
        d = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
#endif
        if (getrlimit(RLIMIT_CORE, &cl) != 0) cl.rlim_cur = (rlim_t)-1;
        gzp_log("process dumpable=%d core=%llu", d, (unsigned long long)cl.rlim_cur);
    }
#endif
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

    /* The chain first: a server on another network, or one that cannot be
     * reached, stops the start before anything is written to the data folder
     * (review of PR 50, L1). Not for --test-dump-journal, which reads only. */
    if (opt.no_chain || DUMPING) {
        gzp_chain_none(&chain, network);
        gzp_log("chain off");
    } else {
        gzp_chain_limits_t lim;
        memset(&lim, 0, sizeof lim);
#ifdef GZP_TEST_BUILD
        lim.small = opt.test_chain_small;
        lim.watches = (uint32_t)opt.test_chain_watches;
        lim.backlog = (size_t)opt.test_chain_backlog;
#endif
        if ((rc = gzp_chain_open(&chain, (const char *const *)opt.chain_urls,
                                 (const char *const *)opt.chain_operators, (size_t)opt.n_chain_urls, network,
                                 opt.chain_poll_ms, &lim)) != 0)
            return rc;
    }

#ifdef GZP_TEST_BUILD
    if (opt.test_dump_journal)
        rc = gzp_datadir_open_readonly(&dir, opt.data_dir, opt.role == GZP_ROLE_HOST ? "host" : "member", opt.network);
    else
#endif
    rc = gzp_datadir_open(&dir, opt.data_dir, opt.role == GZP_ROLE_HOST ? "host" : "member", opt.network);
    if (rc) {
        gzp_chain_close(&chain);
        return rc;
    }
    have_dir = 1;

    /* The folder lock is held; come up locked (storage 8.1). Nothing of the
     * journal is read, and nothing listens or connects, before the unlock. */
    {
        char self[GZP_PATH_MAX];
        ssize_t sl = readlink("/proc/self/exe", self, sizeof self - 1);
        if (sl <= 0) {
            fprintf(stderr, "gazpacho: cannot find this program for the KDF helper\n");
            rc = GZP_EXIT_FAILED;
            goto out;
        }
        self[sl] = 0;
        if ((rc = gzp_wallet_open(&wallet, dir.dir, chain_hash, self)) != 0) goto out;
    }
#ifdef GZP_TEST_BUILD
    if (opt.test_kdf_floor) gzp_wallet_test_kdf_floor(wallet);
    if (opt.test_dump_journal) gzp_wallet_test_keys_only(wallet);
    if (opt.test_kill_at) gzp_store_test_kill_at((unsigned)opt.test_kill_at);
    if (opt.test_power_cut_at) {
        gzp_store_test_power_cut();
        gzp_store_test_kill_at((unsigned)opt.test_power_cut_at);
    }
    if (opt.test_restore_from && !opt.test_standin_store) gzp_wallet_test_restore_from(wallet, opt.test_restore_from);
#endif
    rc = wait_unlocked(&opt);
    if (rc == -1) {
        rc = 0;
        stopped = 1;
        goto out;
    }
    if (rc) goto out;
#ifdef GZP_TEST_BUILD
    if (opt.test_dump_journal) {
        rc = dump_journal(&dir, &opt);
        goto out;
    }
    if (opt.test_append_batch) {
        rc = append_batch(opt.test_append_batch);
        goto out;
    }
#endif

    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    gzp_os_random(rseed, sizeof rseed);
    if (!secp || !secp256k1_context_randomize(secp, rseed)) {
        fprintf(stderr, "gazpacho: cannot set up secp256k1\n");
        rc = GZP_EXIT_FAILED;
        goto out;
    }
    OPENSSL_cleanse(rseed, sizeof rseed);
    /* The transport's key behind the key file: derived from the unlocked
     * seed (a stand-in until P8's per-member keys; transport.key is gone). */
    if (gzp_wallet_transport_key(wallet, key_ok, secp, priv) != 0) {
        fprintf(stderr, "gazpacho: cannot derive the transport key\n");
        rc = GZP_EXIT_DATA;
        goto out;
    }
    if ((rc = wallet_open(secp, wnet, &first)) != 0) goto out;
    gzp_log("wallet network=%s first-address=%s", opt.network, first.address);

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
    lim.max_queue = opt.max_queue;
    lim.max_conns = (unsigned)opt.test_max_conns;
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
        gzp_log("member key=%s host-peer=%016llx", hex, (unsigned long long)gzp_peer_id(opt.connect_key));
    }

    /* The local interface: the API server is not wired yet (P5, P6). */
    if (opt.no_interface) gzp_log("interface off");
    else gzp_log("interface not-built port=%u", (unsigned)(opt.interface_port ? opt.interface_port
                                                         : network == GZ_NET_TESTNET4 ? 39736 : 39735));

#ifdef GZP_TEST_BUILD
    gzp_testping_init(&tp, opt.test_pings, opt.test_ping_ms, opt.name, opt.test_engines);
    gzp_testping_burst(&tp, opt.test_burst_n, opt.test_burst_bytes);
    tp.exit_after_send = opt.test_exit_after_send;
    net.drop_kind = (unsigned)opt.test_drop_kind;
    net.single_key = opt.test_engines > 0;
    if (opt.test_commands) fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
#endif
    gzp_notify_lines(&ex.notify);
    ex.opt = &opt;
    ex.dir = &dir;
    ex.wallet = wallet;
    ex.net = &net;
    ex.chain_hash = chain_hash;
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
        if (r == GZP_RUN_LIMIT) {
            rc = GZP_EXIT_LIMIT;
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
#ifdef GZP_TEST_BUILD
        /* --test-stop-at-restart: a stop that arrives while the incarnation
         * ends, before the next start (M6; the window is too short to hit
         * from outside reliably). */
        if (opt.test_stop_at_restart) raise(SIGTERM);
#endif
        now = gzp_mono_ms();
        restart_at[restarts % (RESTART_LIMIT + 1)] = now;
        restarts++;
        if (restarts > RESTART_LIMIT && now - restart_at[restarts % (RESTART_LIMIT + 1)] <= RESTART_WINDOW_MS) {
            gzp_log("stopping after %d restarts within %u minutes", RESTART_LIMIT + 1, RESTART_WINDOW_MS / 60000u);
            rc = GZP_EXIT_FAILED;
            break;
        }
        /* mono: this machine's monotonic clock, so tests can compare lines of two processes. */
        gzp_log("restart-from-storage after=%s mono=%llu", ex.fatal_why ? ex.fatal_why : "-",
                (unsigned long long)gzp_mono_ms());
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
    gzp_chain_close(&chain); /* the worker joined: no event after this */
    if (have_net) gzp_net_free(&net);
    if (stopped) gzp_log("shutdown connections-closed transport=%d storage=%d lock=%d", net.peers != NULL,
                         ex.store_open, dir.lock_fd >= 0);
    gzp_exec_close_storage(&ex);
    gzp_wallet_free(wallet); /* every key wiped (storage 8.3) */
    wallet = NULL;
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
