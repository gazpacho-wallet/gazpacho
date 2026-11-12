/* The connection layer between two local processes (the test forks). The
 * parent is the host; the child is a member, honest or not. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../check.h"
#include "hex.h"
#include "conn.h"

static secp256k1_context *secp;
static uint8_t HOST_KEY[32], MEMBER_KEY[32], HOST_PUB[33], MEMBER_PUB[33], OTHER_PUB[33];
static gz_conn_t host, member;
static uint8_t msg[GZ_NOISE_MAX_MSG];

static void counter_fill(void *ctx, uint8_t *out, size_t len)
{
    static uint8_t n = 1;
    (void)ctx;
    memset(out, 0x40, len);
    out[len - 1] = n++;
}
static const gz_random_port_t RNG = {counter_fill, NULL};

static void pub(const uint8_t k[32], uint8_t out[33])
{
    secp256k1_pubkey pk;
    size_t n = 33;
    CHECK(secp256k1_ec_pubkey_create(secp, &pk, k) && secp256k1_ec_pubkey_serialize(secp, out, &n, &pk, SECP256K1_EC_COMPRESSED));
}

static int64_t ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int raw_connect(uint16_t port)
{
    struct sockaddr_in a;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) _exit(90);
    return fd;
}

typedef void (*child_fn)(uint16_t port);

static pid_t spawn(child_fn f, uint16_t port)
{
    pid_t p = fork();
    if (p == 0) {
        signal(SIGPIPE, SIG_IGN); /* children write raw; the parent keeps the default */
        f(port);
        _exit(0);
    }
    return p;
}

static int child_status(pid_t p)
{
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
}

/* --- children ------------------------------------------------------------ */
static void honest(uint16_t port)
{
    size_t len;
    if (gz_conn_connect(&member, "127.0.0.1", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL)) _exit(10);
    if (!(fcntl(member.fd, F_GETFD) & FD_CLOEXEC) || !(fcntl(member.fd, F_GETFL) & O_NONBLOCK)) _exit(14);
    if (gz_conn_send(&member, (const uint8_t *)"\x80\x01hello", 7)) _exit(11);
    if (gz_conn_recv(&member, msg, sizeof msg, &len) || len != 7 || memcmp(msg, "\x80\x01HELLO", 7)) _exit(12);
    /* 600 more round trips: past the rotation point in both directions */
    {
        int i;
        for (i = 0; i < 600; i++)
            if (gz_conn_send(&member, (const uint8_t *)"\x80\x01x", 3) || gz_conn_recv(&member, msg, sizeof msg, &len) || len != 3) _exit(13);
    }
    gz_conn_close(&member);
}

static void wrong_pin(uint16_t port)
{
    gz_conn_err_t e = gz_conn_connect(&member, "127.0.0.1", port, secp, MEMBER_KEY, OTHER_PUB, RNG, NULL);
    _exit(e == GZ_CONN_ERR_CLOSED ? 0 : 20 + (int)e);
}

static void silent(uint16_t port)
{
    int fd = raw_connect(port);
    sleep(3);
    close(fd);
}

static void truncated_act(uint16_t port)
{
    int fd = raw_connect(port);
    uint8_t b[20] = {0};
    if (write(fd, b, sizeof b) != 20) _exit(30);
    close(fd);
}

/* Handshake, then send part of a message and close. */
static void closes_mid_message(uint16_t port)
{
    uint8_t out[64];
    size_t n;
    if (gz_conn_connect(&member, "127.0.0.1", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL)) _exit(40);
    if (gz_noise_encrypt(&member.noise, (const uint8_t *)"\x80\x01" "abc", 5, out, sizeof out, &n)) _exit(41);
    if (write(member.fd, out, 25) != 25) _exit(42);
    close(member.fd);
}

/* Handshake, then a valid header announcing 200 bytes, and no body. */
static void oversize(uint16_t port)
{
    static uint8_t out[300];
    size_t n;
    memset(msg, 0x80, 200);
    if (gz_conn_connect(&member, "127.0.0.1", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL)) _exit(50);
    if (gz_noise_encrypt(&member.noise, msg, 200, out, sizeof out, &n)) _exit(51);
    if (write(member.fd, out, 18) != 18) _exit(52);
    sleep(3);
    close(member.fd);
}

/* Handshake, then a valid message a byte at a time, 100 ms apart. */
static void trickle(uint16_t port)
{
    uint8_t out[64];
    size_t n, i;
    if (gz_conn_connect(&member, "127.0.0.1", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL)) _exit(60);
    if (gz_noise_encrypt(&member.noise, (const uint8_t *)"\x80\x01" "abc", 5, out, sizeof out, &n)) _exit(61);
    for (i = 0; i < n; i++) {
        struct timespec t = {0, 100000000};
        if (write(member.fd, out + i, 1) != 1) _exit(0); /* host gave up: expected */
        nanosleep(&t, NULL);
    }
    close(member.fd);
}

/* A message with a corrupted body MAC. */
static void bad_mac(uint16_t port)
{
    uint8_t out[64];
    size_t n;
    if (gz_conn_connect(&member, "127.0.0.1", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL)) _exit(70);
    if (gz_noise_encrypt(&member.noise, (const uint8_t *)"\x80\x01" "abc", 5, out, sizeof out, &n)) _exit(71);
    out[n - 1] ^= 1;
    if (write(member.fd, out, n) != (ssize_t)n) _exit(72);
    sleep(2);
    close(member.fd);
}

static void sleep_ms(int n)
{
    struct timespec t;
    t.tv_sec = n / 1000;
    t.tv_nsec = (long)(n % 1000) * 1000000;
    while (nanosleep(&t, &t) != 0 && errno == EINTR) {}
}

static int read_full(int fd, uint8_t *b, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, b + got, n - got);
        if (r <= 0) return 0;
        got += (size_t)r;
    }
    return 1;
}

/* Connects 1,500 ms late, then waits 200 ms before act one. */
static void late_slow(uint16_t port)
{
    gz_noise_t st;
    uint8_t a[66];
    int fd;
    sleep_ms(1500);
    fd = raw_connect(port);
    if (gz_noise_init_initiator(&st, secp, MEMBER_KEY, HOST_PUB, RNG) || gz_noise_act1_write(&st, a)) _exit(80);
    sleep_ms(200);
    if (write(fd, a, 50) != 50 || !read_full(fd, a, 50) || gz_noise_act2_read(&st, a, 50) ||
        gz_noise_act3_write(&st, a) || write(fd, a, 66) != 66) _exit(81);
    sleep_ms(500);
    close(fd);
}

/* Completes the handshake and closes at once. */
static void connect_and_close(uint16_t port)
{
    if (gz_conn_connect(&member, "127.0.0.1", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL)) _exit(82);
    gz_conn_close(&member);
}

/* Completes the handshake and never reads. */
static void never_reads(uint16_t port)
{
    if (gz_conn_connect(&member, "127.0.0.1", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL)) _exit(83);
    sleep(6);
}

/* Reads twenty full-size messages slowly and checks every byte. */
static void slow_reader(uint16_t port)
{
    size_t len, k;
    int i;
    if (gz_conn_connect(&member, "127.0.0.1", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL)) _exit(84);
    for (i = 0; i < 20; i++) {
        sleep_ms(20);
        if (gz_conn_recv(&member, msg, sizeof msg, &len) || len != GZ_NOISE_MAX_MSG) _exit(85);
        for (k = 0; k < len; k++)
            if (msg[k] != (uint8_t)(k % 251 + (size_t)i)) _exit(86);
    }
    gz_conn_close(&member);
}

/* A valid message, a byte every 20 ms: slow but within the deadline. */
static void trickle_ok(uint16_t port)
{
    uint8_t out[64];
    size_t n, i;
    if (gz_conn_connect(&member, "127.0.0.1", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL)) _exit(87);
    if (gz_noise_encrypt(&member.noise, (const uint8_t *)"\x80\x01" "abc", 5, out, sizeof out, &n)) _exit(88);
    for (i = 0; i < n; i++) {
        if (write(member.fd, out + i, 1) != 1) _exit(89);
        sleep_ms(20);
    }
    sleep_ms(500);
}

/* The header slowly (810 ms), then the body faster (540 ms): the whole
 * message takes longer than the 1,000 ms deadline, the body alone does not. */
static void body_trickle(uint16_t port)
{
    uint8_t out[64];
    size_t n, i;
    memset(msg, 0x80, 20);
    if (gz_conn_connect(&member, "127.0.0.1", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL)) _exit(90);
    if (gz_noise_encrypt(&member.noise, msg, 20, out, sizeof out, &n) || n != 54) _exit(91);
    for (i = 0; i < n; i++) {
        if (write(member.fd, out + i, 1) != 1) _exit(0);
        sleep_ms(i < 18 ? 45 : 15);
    }
    sleep_ms(500);
}

/* A host that accepts TCP and never answers act one. */
static int silent_lfd;
static void silent_host(uint16_t port)
{
    struct pollfd p;
    int fd;
    (void)port;
    p.fd = silent_lfd;
    p.events = POLLIN;
    if (poll(&p, 1, 5000) != 1 || (fd = accept(silent_lfd, NULL, NULL)) < 0) _exit(92);
    sleep(4);
    close(fd);
}

static int interrupts;

/* How late a deadline may fire and still pass: the timed call also does the
 * handshake's or message's own work, which valgrind and a loaded machine
 * slow down. Lower bounds stay exact: slowness only makes calls longer. A
 * deadline that never fires still fails each test: the peer closes or
 * completes its message (a different result code), or, with no peer, the
 * call hangs until CTest's timeout. The bound adds a limit on lateness. */
#define SLACK_MS 3000
static void on_alarm(int sig) { (void)sig; interrupts++; }

/* --- the host side of each case ------------------------------------------ */
static int lfd;
static uint16_t port;

static int accept_ms = 5000, send_ms = 10000;

static gz_conn_err_t host_accept(int handshake_ms, int recv_ms, size_t max_msg)
{
    gz_conn_limits_t l;
    gz_conn_default_limits(&l);
    l.accept_ms = accept_ms;
    l.handshake_ms = handshake_ms;
    l.recv_ms = recv_ms;
    l.send_ms = send_ms;
    l.max_msg = max_msg;
    return gz_conn_accept(&host, lfd, secp, HOST_KEY, RNG, &l, gz_conn_any_member, NULL);
}

/* A member check that records the key it was shown and says no. */
static uint8_t shown[33];
static int refuse_member(const uint8_t key[33], void *ctx)
{
    memcpy(shown, key, 33);
    *(int *)ctx += 1;
    return 0;
}

static void test_honest(void)
{
    uint8_t rs[33];
    size_t len;
    int i, ok = 0;
    pid_t p = spawn(honest, port);
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_OK);
    CHECK(gz_conn_remote_static(&host, rs) == GZ_CONN_OK && memcmp(rs, MEMBER_PUB, 33) == 0);
    CHECK((fcntl(host.fd, F_GETFD) & FD_CLOEXEC) && (fcntl(lfd, F_GETFD) & FD_CLOEXEC));
    CHECK((fcntl(host.fd, F_GETFL) & O_NONBLOCK) && (fcntl(lfd, F_GETFL) & O_NONBLOCK));
    /* An open connection is not reused: refused, and left working. */
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_ERR_BUSY);
    CHECK(gz_conn_connect(&host, "127.0.0.1", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL) == GZ_CONN_ERR_BUSY);
    CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_OK && len == 7 && !memcmp(msg, "\x80\x01hello", 7));
    CHECK(gz_conn_send(&host, (const uint8_t *)"\x80\x01HELLO", 7) == GZ_CONN_OK);
    for (i = 0; i < 600; i++)
        ok += gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_OK && gz_conn_send(&host, msg, len) == GZ_CONN_OK;
    CHECK(ok == 600);
    CHECK(host.noise.sn == 2 * 601 - 1000 && host.noise.rn == 2 * 601 - 1000); /* rotated once each way */
    CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_ERR_CLOSED);
    CHECK(host.fd == -1 && all_zero(&host.noise, sizeof host.noise) && all_zero(host.buf, sizeof host.buf));
    CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_ERR_CLOSED);
    CHECK(child_status(p) == 0);
}

static void test_wrong_pin(void)
{
    pid_t p = spawn(wrong_pin, port);
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_ERR_HANDSHAKE && host.noise_err == GZ_NOISE_ERR_MAC);
    CHECK(child_status(p) == 0); /* the member saw the host close, having received nothing */
    /* The next connection on the same gz_conn_t starts with no stale reason. */
    p = spawn(honest, port);
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_OK && host.noise_err == GZ_NOISE_OK);
    gz_conn_close(&host);
    kill(p, SIGKILL);
    child_status(p);
}

/* F3: the host's member check runs after the handshake, sees the member's
 * key, and its refusal closes the connection before any message is read. */
static void test_member_check(void)
{
    gz_conn_limits_t l;
    int calls = 0;
    pid_t p;
    gz_conn_default_limits(&l);
    l.accept_ms = 5000;
    CHECK(gz_conn_accept(&host, lfd, secp, HOST_KEY, RNG, &l, NULL, NULL) == GZ_CONN_ERR_ARGS);
    p = spawn(honest, port);
    CHECK(gz_conn_accept(&host, lfd, secp, HOST_KEY, RNG, &l, refuse_member, &calls) == GZ_CONN_ERR_NOT_MEMBER);
    CHECK(calls == 1 && memcmp(shown, MEMBER_PUB, 33) == 0 && host.fd == -1 && all_zero(&host.noise, sizeof host.noise));
    {
        int st = child_status(p); /* the member saw the close: its send (11) or its read (12) failed */
        CHECK(st == 11 || st == 12);
    }
}

static void test_timeouts(void)
{
    int64_t t0;
    pid_t p = spawn(silent, port);
    t0 = ms();
    CHECK(host_accept(400, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_ERR_TIMEOUT);
    CHECK(ms() - t0 >= 350 && ms() - t0 < 400 + SLACK_MS);
    kill(p, SIGKILL);
    child_status(p);
    /* Nobody connects at all. */
    t0 = ms();
    accept_ms = 300;
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_ERR_TIMEOUT && ms() - t0 >= 250 && ms() - t0 < 300 + SLACK_MS);
    accept_ms = 5000;
    /* F2: the handshake deadline starts at the connection, not at the call:
     * a member 1,500 ms late that sends act one 200 ms after connecting fits
     * a 1,200 ms handshake. A deadline counted from the call would expire
     * before the member even connects. The 1,000 ms left over is for the
     * handshake's own work, which valgrind and a loaded machine slow down. */
    p = spawn(late_slow, port);
    CHECK(host_accept(1200, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_OK);
    gz_conn_close(&host);
    CHECK(child_status(p) == 0);
    accept_ms = 5000;
    /* The member's side: a host that accepts TCP and never answers. */
    {
        gz_conn_limits_t l;
        uint16_t sport;
        CHECK(gz_conn_listen("127.0.0.1", 0, &silent_lfd, &sport) == GZ_CONN_OK);
        p = spawn(silent_host, sport);
        gz_conn_default_limits(&l);
        l.handshake_ms = 700;
        t0 = ms();
        CHECK(gz_conn_connect(&member, "127.0.0.1", sport, secp, MEMBER_KEY, HOST_PUB, RNG, &l) == GZ_CONN_ERR_TIMEOUT);
        CHECK(ms() - t0 >= 650 && ms() - t0 < 700 + SLACK_MS && member.fd == -1);
        kill(p, SIGKILL);
        child_status(p);
        close(silent_lfd);
    }
    /* The body shares the message's deadline: header slow, body faster, too late in all. */
    {
        size_t len;
        p = spawn(body_trickle, port);
        CHECK(host_accept(5000, 1000, GZ_NOISE_MAX_MSG) == GZ_CONN_OK);
        t0 = ms();
        CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_ERR_TIMEOUT);
        CHECK(ms() - t0 >= 950 && ms() - t0 < 1000 + SLACK_MS);
        kill(p, SIGKILL);
        child_status(p);
    }
    /* A peer that sends a message a byte at a time is cut off. */
    {
        size_t len;
        p = spawn(trickle, port);
        CHECK(host_accept(5000, 500, GZ_NOISE_MAX_MSG) == GZ_CONN_OK && host.noise_err == GZ_NOISE_OK);
        t0 = ms();
        CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_ERR_TIMEOUT);
        CHECK(ms() - t0 >= 450 && ms() - t0 < 500 + SLACK_MS);
        CHECK(child_status(p) == 0);
    }
}

static void test_broken_peers(void)
{
    size_t len;
    int64_t t0;
    pid_t p = spawn(truncated_act, port);
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_ERR_CLOSED);
    CHECK(child_status(p) == 0);

    p = spawn(closes_mid_message, port);
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_OK);
    CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_ERR_CLOSED);
    CHECK(child_status(p) == 0);

    /* The cap is applied as soon as the length is known, not after a wait for the body. */
    p = spawn(oversize, port);
    CHECK(host_accept(5000, 5000, 100) == GZ_CONN_OK);
    t0 = ms();
    CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_ERR_TOO_BIG);
    CHECK(ms() - t0 < 2500 && host.fd == -1); /* the peer waits 3 s before closing */
    kill(p, SIGKILL);
    child_status(p);
    /* One over the cap. */
    p = spawn(oversize, port);
    CHECK(host_accept(5000, 5000, 199) == GZ_CONN_OK);
    CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_ERR_TOO_BIG);
    kill(p, SIGKILL);
    child_status(p);
    /* The same at exactly the cap is accepted as far as the body wait. */
    p = spawn(oversize, port);
    CHECK(host_accept(5000, 500, 200) == GZ_CONN_OK);
    CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_ERR_TIMEOUT);
    kill(p, SIGKILL);
    child_status(p);

    p = spawn(bad_mac, port);
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_OK);
    CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_ERR_CRYPTO && host.noise_err == GZ_NOISE_ERR_MAC);
    CHECK(host.fd == -1);
    kill(p, SIGKILL);
    child_status(p);
}

static void test_local_limits(void)
{
    pid_t p = spawn(honest, port);
    size_t len;
    CHECK(host_accept(5000, 5000, 10) == GZ_CONN_OK);
    CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_OK && len == 7);
    CHECK(gz_conn_send(&host, msg, 11) == GZ_CONN_ERR_TOO_BIG && host.fd == -1);
    CHECK(gz_conn_send(&host, msg, 1) == GZ_CONN_ERR_CLOSED);
    CHECK(child_status(p) == 12);
    /* A cap above 65,535 changes nothing: the state machine still refuses. */
    p = spawn(honest, port);
    CHECK(host_accept(5000, 5000, 70000) == GZ_CONN_OK);
    CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_OK && len == 7);
    {
        static uint8_t huge[65536];
        CHECK(gz_conn_send(&host, huge, sizeof huge) == GZ_CONN_ERR_TOO_BIG && host.noise_err == GZ_NOISE_ERR_TOO_BIG);
    }
    CHECK(child_status(p) == 12);
    /* Connecting to a port nobody listens on. */
    {
        int fd;
        uint16_t free_port;
        CHECK(gz_conn_listen("127.0.0.1", 0, &fd, &free_port) == GZ_CONN_OK);
        close(fd);
        CHECK(gz_conn_connect(&member, "127.0.0.1", free_port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL) == GZ_CONN_ERR_SOCKET);
        /* Names are not looked up (no deadline could bound that), and say so. */
        CHECK(gz_conn_connect(&member, "localhost", port, secp, MEMBER_KEY, HOST_PUB, RNG, NULL) == GZ_CONN_ERR_ADDRESS);
        CHECK(gz_conn_listen("localhost", 0, &fd, &free_port) == GZ_CONN_ERR_ADDRESS);
    }
    /* Closing a zeroed gz_conn_t closes nothing, even when its fd field names a real descriptor. */
    {
        static gz_conn_t z;
        int fd = open("/dev/null", O_RDONLY);
        z.fd = fd;
        gz_conn_close(&z);
        CHECK(fd >= 0 && fcntl(fd, F_GETFD) != -1);
        close(fd);
    }
    /* A never-opened connection: send, receive and remote_static say it is closed. */
    {
        static gz_conn_t z;
        uint8_t rs[33];
        size_t len;
        CHECK(gz_conn_send(&z, (const uint8_t *)"\x80\x01", 2) == GZ_CONN_ERR_CLOSED);
        CHECK(gz_conn_recv(&z, msg, sizeof msg, &len) == GZ_CONN_ERR_CLOSED);
        CHECK(gz_conn_remote_static(&z, rs) == GZ_CONN_ERR_CLOSED);
    }
}

/* SIGPIPE is at its default in this process: a send to a closed peer must
 * fail, not kill the program. */
static void test_no_sigpipe(void)
{
    int i;
    gz_conn_err_t e = GZ_CONN_OK;
    pid_t p = spawn(connect_and_close, port);
    CHECK(signal(SIGPIPE, SIG_DFL) == SIG_DFL);
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_OK);
    CHECK(child_status(p) == 0);
    for (i = 0; i < 200 && e == GZ_CONN_OK; i++) e = gz_conn_send(&host, msg, 1000);
    CHECK(e == GZ_CONN_ERR_SOCKET && i > 1); /* the first sends are buffered, then EPIPE */
}

/* Full socket buffers: a slow reader gets every byte (writes wait on
 * EAGAIN); a reader that never reads is cut off by the send deadline. */
static void test_full_buffers(void)
{
    int i, ok = 0;
    gz_conn_err_t e = GZ_CONN_OK;
    int64_t t0 = 0;
    size_t k;
    pid_t p = spawn(slow_reader, port);
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_OK);
    for (i = 0; i < 20; i++) {
        for (k = 0; k < GZ_NOISE_MAX_MSG; k++) msg[k] = (uint8_t)(k % 251 + (size_t)i);
        ok += gz_conn_send(&host, msg, GZ_NOISE_MAX_MSG) == GZ_CONN_OK;
    }
    CHECK(ok == 20 && child_status(p) == 0);
    gz_conn_close(&host);
    p = spawn(never_reads, port);
    send_ms = 500;
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_OK);
    for (i = 0; i < 1000 && e == GZ_CONN_OK; i++) {
        t0 = ms();
        e = gz_conn_send(&host, msg, GZ_NOISE_MAX_MSG);
    }
    CHECK(e == GZ_CONN_ERR_TIMEOUT && i > 1 && ms() - t0 >= 450 && ms() - t0 < 500 + SLACK_MS && host.fd == -1);
    send_ms = 10000;
    kill(p, SIGKILL);
    child_status(p);
}

/* A signal every 5 ms, its handler installed without SA_RESTART, while a
 * slow peer sends a message: every interrupted wait resumes. */
static void test_interrupted_waits(void)
{
    struct sigaction sa;
    struct itimerval it;
    size_t len;
    pid_t p = spawn(trickle_ok, port);
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sigemptyset(&sa.sa_mask);
    CHECK(sigaction(SIGALRM, &sa, NULL) == 0);
    memset(&it, 0, sizeof it);
    it.it_interval.tv_usec = 5000;
    it.it_value.tv_usec = 5000;
    CHECK(setitimer(ITIMER_REAL, &it, NULL) == 0);
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_OK);
    CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_OK && len == 5 && !memcmp(msg, "\x80\x01" "abc", 5));
    memset(&it, 0, sizeof it);
    setitimer(ITIMER_REAL, &it, NULL);
    CHECK(interrupts > 50); /* the signals really came */
    gz_conn_close(&host);
    kill(p, SIGKILL);
    child_status(p);
}

int main(void)
{
    uint8_t other[32];
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    memset(HOST_KEY, 0x21, 32);
    memset(MEMBER_KEY, 0x11, 32);
    memset(other, 0x33, 32);
    pub(HOST_KEY, HOST_PUB);
    pub(MEMBER_KEY, MEMBER_PUB);
    pub(other, OTHER_PUB);
    CHECK(gz_conn_listen("127.0.0.1", 0, &lfd, &port) == GZ_CONN_OK && port != 0);
    test_honest();
    test_wrong_pin();
    test_member_check();
    test_timeouts();
    test_broken_peers();
    test_local_limits();
    test_no_sigpipe();
    test_full_buffers();
    test_interrupted_waits();
    close(lfd);
    secp256k1_context_destroy(secp);
    return check_done();
}
