/* Argon2id in a short-lived helper process (spec 8.3, 8.4; review F7, R2-6).
 *
 * libsodium's crypto_pwhash does not zero Argon2's blocks, and one block lets
 * guesses be tested at BLAKE2b speed, so the main process never runs it: the
 * program starts itself as `path --gz-kdf-helper` with a socket on standard
 * input, sends the request, reads PK and reaps the helper. The operating
 * system reclaims the helper's pages at exit.
 *
 * Request: "GZKDFRQ1", t (u32), m KiB (u32), salt (16), passphrase length
 * (u32), passphrase. Answer: status (u8: 0 ok, 1 parameters refused,
 * 2 derivation failed), locked (u8), PK (32). */
#define _GNU_SOURCE
#include "sc_internal.h"

#include <errno.h>
#include <signal.h>
#include <sodium.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/mman.h>
#include <sys/prctl.h>
#else
#include <sys/mman.h>
#endif

#define RQ_MAGIC "GZKDFRQ1"
#define RQ_HEAD 36
#define ANSWER 34

static int send_all(int fd, const void *p, size_t n)
{
    const uint8_t *b = p;
    while (n) {
        ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        b += w;
        n -= (size_t)w;
    }
    return 0;
}

static int recv_all(int fd, void *p, size_t n)
{
    uint8_t *b = p;
    while (n) {
        ssize_t r = read(fd, b, n);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return -1;
        b += r;
        n -= (size_t)r;
    }
    return 0;
}

static void no_dumps(void)
{
    struct rlimit rl = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &rl);
#if defined(__linux__)
    /* After execve, which restores dumpability; also blocks same-user ptrace. */
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

/* Lock every page now and later, but only where the limit allows the whole
 * derivation: with MCL_FUTURE a later mmap beyond RLIMIT_MEMLOCK would fail,
 * and a refused lock must not stop the derivation (8.3). */
static int lock_pages(uint64_t need_bytes)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0)
        return 0;
    rl.rlim_cur = rl.rlim_max;
    (void)setrlimit(RLIMIT_MEMLOCK, &rl);
    if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0)
        return 0;
    uint64_t slack = 64u << 20;
    if (rl.rlim_cur != RLIM_INFINITY && (uint64_t)rl.rlim_cur < need_bytes + slack)
        return 0;
    return mlockall(MCL_CURRENT | MCL_FUTURE) == 0;
}

int gz_sc_helper_main(int fd)
{
    no_dumps();
    uint8_t head[RQ_HEAD], ans[ANSWER];
    memset(ans, 0, sizeof ans);
    ans[0] = 2;
    if (recv_all(fd, head, sizeof head) != 0 || memcmp(head, RQ_MAGIC, 8) != 0)
        return 2;
    gz_sc_kdf_params_t p = {1, sc_get32(head + 8), sc_get32(head + 12), 1};
    uint32_t pw_len = sc_get32(head + 32);
    if (gz_sc_params_check(&p) != GZ_SC_OK || pw_len > GZ_SC_PASS_IN_MAX) {
        ans[0] = 1;
        return send_all(fd, ans, sizeof ans) == 0 ? 0 : 2;
    }
    ans[1] = (uint8_t)lock_pages((uint64_t)p.m_kib * 1024u);
    if (sodium_init() < 0)
        return 2;
    uint8_t *pw = sodium_malloc(pw_len ? pw_len : 1), *pk = sodium_malloc(32);
    int rc = 2;
    if (!pw || !pk || recv_all(fd, pw, pw_len) != 0)
        goto done;
    if (crypto_pwhash(pk, 32, (const char *)pw, pw_len, head + 16, p.t, (size_t)p.m_kib * 1024u,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        goto done; /* out of memory: a failure, never a wrong passphrase */
    sodium_memzero(pw, pw_len ? pw_len : 1);
    ans[0] = 0;
    memcpy(ans + 2, pk, 32);
    rc = send_all(fd, ans, sizeof ans) == 0 ? 0 : 2;
done:
    sodium_memzero(ans, sizeof ans);
    gz_sc_sfree(pw);
    gz_sc_sfree(pk);
    return rc;
}

gz_sc_err_t gz_sc_kdf_helper(void *ctx, const uint8_t *pw, size_t pw_len, const uint8_t salt[16],
                             const gz_sc_kdf_params_t *params, uint8_t pk[32], int *mem_locked)
{
    const char *path = ctx;
    if (!path || pw_len > GZ_SC_PASS_IN_MAX)
        return GZ_SC_ARG;
    gz_sc_err_t e = gz_sc_params_check(params);
    if (e != GZ_SC_OK)
        return e;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return GZ_SC_HELPER_FAILED;
    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        return GZ_SC_HELPER_FAILED;
    }
    if (pid == 0) {
        /* The child: only the socket, as standard input. No heap use here. */
        if (dup2(sv[1], 0) != 0)
            _exit(127);
#if defined(__linux__)
        (void)close_range(3, ~0u, 0);
#else
        long maxfd = sysconf(_SC_OPEN_MAX);
        for (long fd = 3; fd < (maxfd > 0 && maxfd < 65536 ? maxfd : 65536); fd++)
            close((int)fd);
#endif
        struct rlimit rl = {0, 0};
        (void)setrlimit(RLIMIT_CORE, &rl);
        execl(path, path, "--gz-kdf-helper", (char *)NULL);
        _exit(127);
    }
    close(sv[1]);
    uint8_t head[RQ_HEAD], ans[ANSWER];
    memcpy(head, RQ_MAGIC, 8);
    sc_put32(head + 8, params->t);
    sc_put32(head + 12, params->m_kib);
    memcpy(head + 16, salt, 16);
    sc_put32(head + 32, (uint32_t)pw_len);
    int ok = send_all(sv[0], head, sizeof head) == 0 && send_all(sv[0], pw, pw_len) == 0 &&
             recv_all(sv[0], ans, sizeof ans) == 0;
    close(sv[0]);
    int status = 0;
    pid_t w;
    do {
        w = waitpid(pid, &status, 0);
    } while (w < 0 && errno == EINTR);
    e = GZ_SC_HELPER_FAILED;
    if (ok && w == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        if (ans[0] == 0) {
            memcpy(pk, ans + 2, 32);
            if (mem_locked)
                *mem_locked = ans[1] == 1;
            e = GZ_SC_OK;
        } else if (ans[0] == 1) {
            e = GZ_SC_PARAMS_REFUSED;
        }
    }
    sodium_memzero(ans, sizeof ans);
    return e;
}

#ifdef GZ_SC_TEST_ENTRY
gz_sc_err_t gz_sc_test_kdf_inprocess(void *ctx, const uint8_t *pw, size_t pw_len, const uint8_t salt[16],
                                     const gz_sc_kdf_params_t *params, uint8_t pk[32], int *mem_locked)
{
    (void)ctx;
    gz_sc_err_t e = gz_sc_params_check(params);
    if (e != GZ_SC_OK)
        return e;
    if (mem_locked)
        *mem_locked = 0;
    if (crypto_pwhash(pk, 32, (const char *)pw, pw_len, salt, params->t, (size_t)params->m_kib * 1024u,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        return GZ_SC_HELPER_FAILED;
    return GZ_SC_OK;
}
#endif
