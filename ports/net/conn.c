/* POSIX TCP connection layer. See conn.h. */
#define _POSIX_C_SOURCE 200809L
#include "conn.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/crypto.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 /* systems without it: the program must ignore SIGPIPE */
#endif

void gz_conn_default_limits(gz_conn_limits_t *l)
{
    l->handshake_ms = 10000;
    l->recv_ms = 30000;
    l->send_ms = 10000;
    l->max_msg = GZ_NOISE_MAX_MSG;
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static gz_conn_err_t die(gz_conn_t *c, gz_conn_err_t e)
{
    gz_conn_close(c);
    return e;
}

static int set_nonblocking(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    return fl >= 0 && fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
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
        ssize_t r = send(fd, buf + done, n - done, MSG_NOSIGNAL);
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

static void conn_init(gz_conn_t *c, const gz_conn_limits_t *limits)
{
    c->fd = -1;
    c->noise_err = GZ_NOISE_OK;
    if (limits) c->limits = *limits;
    else gz_conn_default_limits(&c->limits);
    /* A max_msg above 65,535 changes nothing: the state machine refuses to
     * send more, and a received length cannot be more. */
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

gz_conn_err_t gz_conn_listen(const char *host, uint16_t port, int *listen_fd, uint16_t *bound_port)
{
    struct addrinfo hints, *res = NULL, *ai;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    char ps[8];
    int fd = -1, one = 1;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    snprintf(ps, sizeof ps, "%u", (unsigned)port);
    if (getaddrinfo(host, ps, &hints, &res) != 0) return GZ_CONN_ERR_SOCKET;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, 16) == 0 && set_nonblocking(fd)) break;
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
                             const uint8_t ls_priv[32], gz_random_port_t random,
                             const gz_conn_limits_t *limits)
{
    uint8_t act[GZ_NOISE_ACT3_LEN];
    int64_t deadline;
    gz_conn_err_t e;
    gz_noise_err_t ne;
    conn_init(c, limits);
    deadline = now_ms() + c->limits.handshake_ms;
    ne = gz_noise_init_responder(&c->noise, secp, ls_priv, random);
    if (ne) return hs_refused(c, ne);
    for (;;) {
        e = wait_fd(listen_fd, POLLIN, deadline);
        if (e) return die(c, e);
        c->fd = accept(listen_fd, NULL, NULL);
        if (c->fd >= 0) break;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != ECONNABORTED)
            return die(c, GZ_CONN_ERR_SOCKET);
    }
    if (!set_nonblocking(c->fd)) return die(c, GZ_CONN_ERR_SOCKET);
    if ((e = read_exact(c->fd, act, GZ_NOISE_ACT1_LEN, deadline))) return die(c, e);
    if ((ne = gz_noise_act1_read(&c->noise, act, GZ_NOISE_ACT1_LEN))) return hs_refused(c, ne);
    if ((ne = gz_noise_act2_write(&c->noise, act))) return hs_refused(c, ne);
    if ((e = write_all(c->fd, act, GZ_NOISE_ACT2_LEN, deadline))) return die(c, e);
    if ((e = read_exact(c->fd, act, GZ_NOISE_ACT3_LEN, deadline))) return die(c, e);
    if ((ne = gz_noise_act3_read(&c->noise, act, GZ_NOISE_ACT3_LEN))) return hs_refused(c, ne);
    return GZ_CONN_OK;
}

static gz_conn_err_t tcp_connect(gz_conn_t *c, const char *host, uint16_t port, int64_t deadline)
{
    struct addrinfo hints, *res = NULL, *ai;
    char ps[8];
    gz_conn_err_t e = GZ_CONN_ERR_SOCKET;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    snprintf(ps, sizeof ps, "%u", (unsigned)port);
    if (getaddrinfo(host, ps, &hints, &res) != 0) return GZ_CONN_ERR_SOCKET;
    for (ai = res; ai; ai = ai->ai_next) {
        int err = 0;
        socklen_t el = sizeof err;
        c->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (c->fd < 0) continue;
        if (set_nonblocking(c->fd)) {
            if (connect(c->fd, ai->ai_addr, ai->ai_addrlen) == 0) { e = GZ_CONN_OK; break; }
            if (errno == EINPROGRESS) {
                e = wait_fd(c->fd, POLLOUT, deadline);
                if (!e && getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) break;
                if (!e) e = GZ_CONN_ERR_SOCKET;
            }
        }
        close(c->fd);
        c->fd = -1;
        if (e == GZ_CONN_ERR_TIMEOUT) break;
    }
    freeaddrinfo(res);
    return c->fd < 0 ? e : GZ_CONN_OK;
}

gz_conn_err_t gz_conn_connect(gz_conn_t *c, const char *host, uint16_t port,
                              const secp256k1_context *secp, const uint8_t ls_priv[32],
                              const uint8_t pinned_host[33], gz_random_port_t random,
                              const gz_conn_limits_t *limits)
{
    uint8_t act[GZ_NOISE_ACT3_LEN], rs[33];
    int64_t deadline;
    gz_conn_err_t e;
    gz_noise_err_t ne;
    conn_init(c, limits);
    deadline = now_ms() + c->limits.handshake_ms;
    if ((ne = gz_noise_init_initiator(&c->noise, secp, ls_priv, pinned_host, random)))
        return hs_refused(c, ne);
    if ((e = tcp_connect(c, host, port, deadline))) return die(c, e);
    if ((ne = gz_noise_act1_write(&c->noise, act))) return hs_refused(c, ne);
    if ((e = write_all(c->fd, act, GZ_NOISE_ACT1_LEN, deadline))) return die(c, e);
    if ((e = read_exact(c->fd, act, GZ_NOISE_ACT2_LEN, deadline))) return die(c, e);
    if ((ne = gz_noise_act2_read(&c->noise, act, GZ_NOISE_ACT2_LEN))) return hs_refused(c, ne);
    if ((ne = gz_noise_act3_write(&c->noise, act))) return hs_refused(c, ne);
    if (gz_noise_remote_static(&c->noise, rs) || CRYPTO_memcmp(rs, pinned_host, 33) != 0)
        return die(c, GZ_CONN_ERR_PIN);
    if ((e = write_all(c->fd, act, GZ_NOISE_ACT3_LEN, deadline))) return die(c, e);
    return GZ_CONN_OK;
}

gz_conn_err_t gz_conn_remote_static(const gz_conn_t *c, uint8_t out[33])
{
    return gz_noise_remote_static(&c->noise, out) ? GZ_CONN_ERR_CLOSED : GZ_CONN_OK;
}

gz_conn_err_t gz_conn_send(gz_conn_t *c, const uint8_t *msg, size_t len)
{
    size_t n;
    gz_noise_err_t ne;
    gz_conn_err_t e;
    if (c->fd < 0) return GZ_CONN_ERR_CLOSED;
    if (len > c->limits.max_msg) return die(c, GZ_CONN_ERR_TOO_BIG);
    if ((ne = gz_noise_encrypt(&c->noise, msg, len, c->buf, sizeof c->buf, &n))) return msg_refused(c, ne);
    e = write_all(c->fd, c->buf, n, now_ms() + c->limits.send_ms);
    return e ? die(c, e) : GZ_CONN_OK;
}

gz_conn_err_t gz_conn_recv(gz_conn_t *c, uint8_t *out, size_t out_cap, size_t *len)
{
    int64_t deadline = now_ms() + c->limits.recv_ms;
    size_t body;
    gz_noise_err_t ne;
    gz_conn_err_t e;
    if (c->fd < 0) return GZ_CONN_ERR_CLOSED;
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
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    gz_noise_wipe(&c->noise);
    OPENSSL_cleanse(c->buf, sizeof c->buf);
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
    }
    return "unknown";
}
