/* The connection layer between two local processes (the test forks). The
 * parent is the host; the child is a member, honest or not. */
#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
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

/* --- the host side of each case ------------------------------------------ */
static int lfd;
static uint16_t port;

static gz_conn_err_t host_accept(int handshake_ms, int recv_ms, size_t max_msg)
{
    gz_conn_limits_t l;
    gz_conn_default_limits(&l);
    l.handshake_ms = handshake_ms;
    l.recv_ms = recv_ms;
    l.max_msg = max_msg;
    return gz_conn_accept(&host, lfd, secp, HOST_KEY, RNG, &l);
}

static void test_honest(void)
{
    uint8_t rs[33];
    size_t len;
    int i, ok = 0;
    pid_t p = spawn(honest, port);
    CHECK(host_accept(5000, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_OK);
    CHECK(gz_conn_remote_static(&host, rs) == GZ_CONN_OK && memcmp(rs, MEMBER_PUB, 33) == 0);
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
}

static void test_timeouts(void)
{
    int64_t t0;
    pid_t p = spawn(silent, port);
    t0 = ms();
    CHECK(host_accept(400, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_ERR_TIMEOUT);
    CHECK(ms() - t0 >= 350 && ms() - t0 < 2000);
    kill(p, SIGKILL);
    child_status(p);
    /* Nobody connects at all. */
    t0 = ms();
    CHECK(host_accept(300, 5000, GZ_NOISE_MAX_MSG) == GZ_CONN_ERR_TIMEOUT && ms() - t0 < 2000);
    /* A peer that sends a message a byte at a time is cut off. */
    {
        size_t len;
        p = spawn(trickle, port);
        CHECK(host_accept(5000, 500, GZ_NOISE_MAX_MSG) == GZ_CONN_OK);
        t0 = ms();
        CHECK(gz_conn_recv(&host, msg, sizeof msg, &len) == GZ_CONN_ERR_TIMEOUT);
        CHECK(ms() - t0 >= 450 && ms() - t0 < 2500);
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
    CHECK(ms() - t0 < 1000 && host.fd == -1);
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
    }
}

int main(void)
{
    uint8_t other[32];
    signal(SIGPIPE, SIG_IGN);
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
    test_timeouts();
    test_broken_peers();
    test_local_limits();
    close(lfd);
    secp256k1_context_destroy(secp);
    return check_done();
}
