/* POSIX TCP connection layer. See conn.h. */
#if defined(__linux__)
#define _GNU_SOURCE /* accept4 */
#else
#define _POSIX_C_SOURCE 200809L
#endif
#include "conn.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/crypto.h>

/* A peer's close must not kill the program with SIGPIPE. Linux has a
 * per-write flag; the BSDs and macOS have a per-socket option. A system with
 * neither must not build this file until one is added. */
#if defined(MSG_NOSIGNAL)
#define SEND_FLAGS MSG_NOSIGNAL
#elif defined(SO_NOSIGPIPE)
#define SEND_FLAGS 0
#else
#error "conn.c: no MSG_NOSIGNAL or SO_NOSIGPIPE on this system"
#endif

#define LIVE 0x6c697665u /* gz_conn_t.live while a socket is open */

/* Linux and the BSDs make a socket close-on-exec and non-blocking in the same
 * call that creates it, so a thread that starts another program between the
 * two cannot leak it. Elsewhere fcntl sets both just after. */
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
#define ATOMIC_FLAGS 1
#else
#define ATOMIC_FLAGS 0
#endif

void gz_conn_default_limits(gz_conn_limits_t *l)
{
    l->accept_ms = 0;
    l->handshake_ms = 10000;
    l->recv_ms = 30000;
    l->send_ms = 10000;
    l->max_msg = GZ_NOISE_MAX_MSG;
}

static int64_t now_ms(void)
{
    struct timespec ts;
    /* CLOCK_MONOTONIC is required by POSIX; without it no deadline means anything. */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) abort();
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static gz_conn_err_t die(gz_conn_t *c, gz_conn_err_t e)
{
    gz_conn_close(c);
    return e;
}

/* Every socket: non-blocking, closed in any program this one starts, and
 * (where the per-write flag is missing) never raising SIGPIPE. */
static int prepare_socket(int fd)
{
#if !defined(MSG_NOSIGNAL)
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one) != 0) return 0;
#endif
#if !ATOMIC_FLAGS
    {
        int fl = fcntl(fd, F_GETFL, 0), fdfl = fcntl(fd, F_GETFD, 0);
        if (fl < 0 || fdfl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0 ||
            fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC) != 0)
            return 0;
    }
#endif
    (void)fd;
    return 1;
}

static int new_socket(const struct addrinfo *ai)
{
#if ATOMIC_FLAGS
    return socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, ai->ai_protocol);
#else
    return socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#endif
}

static int accept_socket(int listen_fd)
{
#if ATOMIC_FLAGS
    return accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
    return accept(listen_fd, NULL, NULL);
#endif
}

static gz_conn_err_t wait_fd(int fd, short events, int64_t deadline)
{
    for (;;) {
        struct pollfd p;
        int64_t left = deadline - now_ms();
        int r;
        if (left <= 0) return GZ_CONN_ERR_TIMEOUT;
        p.fd = fd;
        p.events = events;
        p.revents = 0;
        r = poll(&p, 1, left > 60000 ? 60000 : (int)left);
        if (r > 0) return GZ_CONN_OK;
        if (r < 0 && errno != EINTR) return GZ_CONN_ERR_SOCKET;
    }
}

static gz_conn_err_t read_exact(int fd, uint8_t *buf, size_t n, int64_t deadline)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r > 0) { got += (size_t)r; continue; }
        if (r == 0) return GZ_CONN_ERR_CLOSED;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            gz_conn_err_t e = wait_fd(fd, POLLIN, deadline);
            if (e) return e;
            continue;
        }
        return GZ_CONN_ERR_SOCKET;
    }
    return GZ_CONN_OK;
}

static gz_conn_err_t write_all(int fd, const uint8_t *buf, size_t n, int64_t deadline)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = send(fd, buf + done, n - done, SEND_FLAGS);
        if (r > 0) { done += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            gz_conn_err_t e = wait_fd(fd, POLLOUT, deadline);
            if (e) return e;
            continue;
        }
        return GZ_CONN_ERR_SOCKET;
    }
    return GZ_CONN_OK;
}

/* 0 if `c` holds an open connection, which is left untouched. */
static int conn_init(gz_conn_t *c, const gz_conn_limits_t *limits)
{
    if (c->live == LIVE) return 0;
    c->fd = -1;
    c->noise_err = GZ_NOISE_OK;
    if (limits) c->limits = *limits;
    else gz_conn_default_limits(&c->limits);
    /* A max_msg above 65,535 changes nothing: the state machine refuses to
     * send more, and a received length cannot be more. */
    return 1;
}

static void set_fd(gz_conn_t *c, int fd)
{
    c->fd = fd;
    c->live = LIVE;
}

/* The state machine refused: during the handshake, or on a message. */
static gz_conn_err_t hs_refused(gz_conn_t *c, gz_noise_err_t ne)
{
    c->noise_err = ne;
    return die(c, GZ_CONN_ERR_HANDSHAKE);
}

static gz_conn_err_t msg_refused(gz_conn_t *c, gz_noise_err_t ne)
{
    c->noise_err = ne;
    return die(c, ne == GZ_NOISE_ERR_TOO_BIG ? GZ_CONN_ERR_TOO_BIG : GZ_CONN_ERR_CRYPTO);
}

static gz_conn_err_t resolve(const char *host, uint16_t port, int passive, struct addrinfo **res)
{
    struct addrinfo hints;
    char ps[8];
    int r;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    /* Numeric addresses only: no name lookup, which no deadline could bound. */
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | (passive ? AI_PASSIVE : 0);
    snprintf(ps, sizeof ps, "%u", (unsigned)port);
    r = getaddrinfo(host, ps, &hints, res);
    if (r == 0) return GZ_CONN_OK;
    return r == EAI_NONAME ? GZ_CONN_ERR_ADDRESS : GZ_CONN_ERR_SOCKET;
}

gz_conn_err_t gz_conn_listen(const char *host, uint16_t port, int *listen_fd, uint16_t *bound_port)
{
    struct addrinfo *res = NULL, *ai;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int fd = -1, one = 1;
    gz_conn_err_t e = resolve(host, port, 1, &res);
    if (e) return e;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = new_socket(ai);
        if (fd < 0) continue;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        /* Non-blocking even though accept follows a poll: a connection reset
         * between the two would otherwise block accept. */
        if (prepare_socket(fd) && bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, 16) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return GZ_CONN_ERR_SOCKET;
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) != 0) {
        close(fd);
        return GZ_CONN_ERR_SOCKET;
    }
    *bound_port = ntohs(ss.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
                                                 : ((struct sockaddr_in *)&ss)->sin_port);
    *listen_fd = fd;
    return GZ_CONN_OK;
}

gz_conn_err_t gz_conn_accept(gz_conn_t *c, int listen_fd, const secp256k1_context *secp,
                             const uint8_t ls_priv[32], gz_net_random_t random,
                             const gz_conn_limits_t *limits, gz_conn_member_fn is_member, void *member_ctx)
{
    uint8_t act[GZ_NOISE_ACT3_LEN], rs[33];
    int64_t deadline;
    gz_conn_err_t e;
    gz_noise_err_t ne;
    if (!conn_init(c, limits)) return GZ_CONN_ERR_BUSY;
    if (!is_member) return GZ_CONN_ERR_ARGS;
    ne = gz_noise_init_responder(&c->noise, secp, ls_priv, random);
    if (ne) return hs_refused(c, ne);
    deadline = c->limits.accept_ms > 0 ? now_ms() + c->limits.accept_ms : INT64_MAX;
    for (;;) {
        int fd;
        e = wait_fd(listen_fd, POLLIN, deadline);
        if (e) return die(c, e);
        fd = accept_socket(listen_fd);
        if (fd >= 0) {
            set_fd(c, fd);
            break;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != ECONNABORTED)
            return die(c, GZ_CONN_ERR_SOCKET);
    }
    /* The handshake's own deadline starts once there is a connection. */
    deadline = now_ms() + c->limits.handshake_ms;
    if (!prepare_socket(c->fd)) return die(c, GZ_CONN_ERR_SOCKET);
    if ((e = read_exact(c->fd, act, GZ_NOISE_ACT1_LEN, deadline))) return die(c, e);
    if ((ne = gz_noise_act1_read(&c->noise, act, GZ_NOISE_ACT1_LEN))) return hs_refused(c, ne);
    if ((ne = gz_noise_act2_write(&c->noise, act))) return hs_refused(c, ne);
    if ((e = write_all(c->fd, act, GZ_NOISE_ACT2_LEN, deadline))) return die(c, e);
    if ((e = read_exact(c->fd, act, GZ_NOISE_ACT3_LEN, deadline))) return die(c, e);
    if ((ne = gz_noise_act3_read(&c->noise, act, GZ_NOISE_ACT3_LEN))) return hs_refused(c, ne);
    if (gz_noise_remote_static(&c->noise, rs) || !is_member(rs, member_ctx)) return die(c, GZ_CONN_ERR_NOT_MEMBER);
    return GZ_CONN_OK;
}

static gz_conn_err_t tcp_connect(gz_conn_t *c, const char *host, uint16_t port, int64_t deadline)
{
    struct addrinfo *res = NULL, *ai;
    gz_conn_err_t e = resolve(host, port, 0, &res);
    if (e) return e;
    e = GZ_CONN_ERR_SOCKET;
    for (ai = res; ai; ai = ai->ai_next) {
        int err = 0, fd;
        socklen_t el = sizeof err;
        fd = new_socket(ai);
        if (fd < 0) continue;
        if (prepare_socket(fd)) {
            if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
                set_fd(c, fd);
                e = GZ_CONN_OK;
                break;
            }
            if (errno == EINPROGRESS) {
                e = wait_fd(fd, POLLOUT, deadline);
                if (!e && getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) {
                    set_fd(c, fd);
                    break;
                }
                if (!e) e = GZ_CONN_ERR_SOCKET;
            }
        }
        close(fd);
        if (e == GZ_CONN_ERR_TIMEOUT) break;
    }
    freeaddrinfo(res);
    return c->live == LIVE ? GZ_CONN_OK : e;
}

gz_conn_err_t gz_conn_connect(gz_conn_t *c, const char *host, uint16_t port,
                              const secp256k1_context *secp, const uint8_t ls_priv[32],
                              const uint8_t pinned_host[33], gz_net_random_t random,
                              const gz_conn_limits_t *limits)
{
    uint8_t act[GZ_NOISE_ACT3_LEN], rs[33];
    int64_t deadline;
    gz_conn_err_t e;
    gz_noise_err_t ne;
    if (!conn_init(c, limits)) return GZ_CONN_ERR_BUSY;
    deadline = now_ms() + c->limits.handshake_ms;
    if ((ne = gz_noise_init_initiator(&c->noise, secp, ls_priv, pinned_host, random)))
        return hs_refused(c, ne);
    if ((e = tcp_connect(c, host, port, deadline))) return die(c, e);
    if ((ne = gz_noise_act1_write(&c->noise, act))) return hs_refused(c, ne);
    if ((e = write_all(c->fd, act, GZ_NOISE_ACT1_LEN, deadline))) return die(c, e);
    if ((e = read_exact(c->fd, act, GZ_NOISE_ACT2_LEN, deadline))) return die(c, e);
    /* This is the pin: act two's MAC depends on ECDH with the pinned key. */
    if ((ne = gz_noise_act2_read(&c->noise, act, GZ_NOISE_ACT2_LEN))) return hs_refused(c, ne);
    if ((ne = gz_noise_act3_write(&c->noise, act))) return hs_refused(c, ne);
    /* A guard that cannot fail while the member is the initiator (rs is the
     * pin itself); kept against a later change to the state machine. */
    if (gz_noise_remote_static(&c->noise, rs) || CRYPTO_memcmp(rs, pinned_host, 33) != 0)
        return die(c, GZ_CONN_ERR_PIN);
    if ((e = write_all(c->fd, act, GZ_NOISE_ACT3_LEN, deadline))) return die(c, e);
    return GZ_CONN_OK;
}

gz_conn_err_t gz_conn_remote_static(const gz_conn_t *c, uint8_t out[33])
{
    if (c->live != LIVE) return GZ_CONN_ERR_CLOSED;
    return gz_noise_remote_static(&c->noise, out) ? GZ_CONN_ERR_CLOSED : GZ_CONN_OK;
}

gz_conn_err_t gz_conn_send(gz_conn_t *c, const uint8_t *msg, size_t len)
{
    size_t n;
    gz_noise_err_t ne;
    gz_conn_err_t e;
    if (c->live != LIVE) return GZ_CONN_ERR_CLOSED;
    if (len > c->limits.max_msg) return die(c, GZ_CONN_ERR_TOO_BIG);
    if ((ne = gz_noise_encrypt(&c->noise, msg, len, c->buf, sizeof c->buf, &n))) return msg_refused(c, ne);
    e = write_all(c->fd, c->buf, n, now_ms() + c->limits.send_ms);
    return e ? die(c, e) : GZ_CONN_OK;
}

gz_conn_err_t gz_conn_recv(gz_conn_t *c, uint8_t *out, size_t out_cap, size_t *len)
{
    int64_t deadline = now_ms() + c->limits.recv_ms; /* one deadline for header and body */
    size_t body;
    gz_noise_err_t ne;
    gz_conn_err_t e;
    if (c->live != LIVE) return GZ_CONN_ERR_CLOSED;
    if ((e = read_exact(c->fd, c->buf, GZ_NOISE_HDR_LEN, deadline))) return die(c, e);
    if ((ne = gz_noise_decrypt_header(&c->noise, c->buf, GZ_NOISE_HDR_LEN, &body))) return msg_refused(c, ne);
    if (body > c->limits.max_msg || body > out_cap) return die(c, GZ_CONN_ERR_TOO_BIG);
    if ((e = read_exact(c->fd, c->buf, body + GZ_NOISE_MAC_LEN, deadline))) return die(c, e);
    if ((ne = gz_noise_decrypt_body(&c->noise, c->buf, body + GZ_NOISE_MAC_LEN, out, out_cap)))
        return msg_refused(c, ne);
    *len = body;
    return GZ_CONN_OK;
}

void gz_conn_close(gz_conn_t *c)
{
    if (c->live == LIVE && c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->live = 0;
    gz_noise_wipe(&c->noise);
    OPENSSL_cleanse(c->buf, sizeof c->buf);
}

int gz_conn_any_member(const uint8_t key[33], void *ctx)
{
    (void)key;
    (void)ctx;
    return 1;
}

const char *gz_conn_err_name(gz_conn_err_t e)
{
    switch (e) {
    case GZ_CONN_OK: return "ok";
    case GZ_CONN_ERR_SOCKET: return "socket error";
    case GZ_CONN_ERR_TIMEOUT: return "timed out";
    case GZ_CONN_ERR_CLOSED: return "closed by peer";
    case GZ_CONN_ERR_HANDSHAKE: return "handshake refused";
    case GZ_CONN_ERR_PIN: return "host key is not the pinned key";
    case GZ_CONN_ERR_TOO_BIG: return "message over the size cap";
    case GZ_CONN_ERR_CRYPTO: return "message refused";
    case GZ_CONN_ERR_NOT_MEMBER: return "not a member";
    case GZ_CONN_ERR_BUSY: return "connection already open";
    case GZ_CONN_ERR_ARGS: return "invalid arguments";
    case GZ_CONN_ERR_ADDRESS: return "address must be numeric";
    }
    return "unknown";
}
