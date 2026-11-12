/* Lobby connections over one poll loop. See peers.h and spec/transport.md. */
#if defined(__linux__)
#define _GNU_SOURCE /* accept4 */
#else
#define _POSIX_C_SOURCE 200809L
#endif
#include "peers.h"

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

#include "frame.h"
#include "lnmsg.h"
#include "wipe.h"

#if defined(MSG_NOSIGNAL)
#define SEND_FLAGS MSG_NOSIGNAL
#elif defined(SO_NOSIGPIPE)
#define SEND_FLAGS 0
#else
#error "peers.c: no MSG_NOSIGNAL or SO_NOSIGPIPE on this system"
#endif

#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
#define ATOMIC_FLAGS 1
#else
#define ATOMIC_FLAGS 0
#endif

#define MAX_LISTEN 4
#define RX_CAP (GZ_NOISE_MAX_MSG + GZ_NOISE_MAC_LEN)

enum { PH_TCP, PH_I_WAIT2, PH_R_WAIT1, PH_R_WAIT3, PH_OPEN };

typedef struct {
    uint64_t id;
    int fd, outbound, phase;
    int init_got;           /* the peer's init has been accepted (CONNECTED given) */
    int peer_init;          /* the peer's init arrived and was valid: a warning may be sent */
    int seated;             /* the caller says this connection holds a seat (gz_peers_set_seated) */
    struct sockaddr_storage addr; /* accepted connections: the peer's address */
    socklen_t addrlen;
    unsigned warnings;      /* WARNING events given for this connection */
    unsigned ignored;       /* messages ignored in the current window */
    int64_t ignored_window;
    gz_noise_t noise;
    uint8_t node_id[33];
    int have_id;
    uint8_t *rx;
    size_t rx_have, rx_need;
    int rx_body;
    uint8_t *tx;
    size_t tx_len, tx_off, tx_cap;
    int64_t t_start;        /* connection started: the handshake deadline */
    int64_t t_msg;          /* first byte of the message being read, or 0 */
    int64_t t_rx;           /* last whole message from the peer */
    int64_t t_tx;           /* last progress writing, or when the queue became non-empty */
    int ping_out;           /* a ping is waiting for its pong */
    int64_t t_ping;
    uint16_t ping_expect, ping_seq;
    unsigned pings_in_window;
    int64_t window_start;
    int warned;             /* a warning for a wrong protocol tag was sent */
    int closing;            /* refusing: flushing the warning, then closing */
    gz_peer_why_t close_why;
    int64_t close_by;
    char close_text[160];
    gz_env_reasm_t reasm;
} conn_t;

typedef struct evnode {
    gz_peer_event_t ev;
    uint8_t *body;
    struct evnode *next;
} evnode_t;

struct gz_peers {
    gz_peers_config_t cfg;
    int lfd[MAX_LISTEN];
    unsigned n_listen;
    conn_t **conns;
    unsigned n_conns, cap;   /* cap: max_conns plus max_handshakes */
    uint64_t next_id;
    evnode_t *head, *tail, *current;
    gz_peers_stats_t stats;
    uint8_t plain[GZ_NOISE_MAX_MSG]; /* a decrypted message, handled at once */
    uint8_t out[GZ_NOISE_MAX_MSG];   /* a message being built */
};

static void free_event(evnode_t *n);

static int64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) abort();
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

void gz_peers_default_config(gz_peers_config_t *c)
{
    memset(c, 0, sizeof *c);
    memcpy(c->chain, GZ_LN_CHAIN_SIGNET, 32);
    c->handshake_ms = 10000;
    c->ping_ms = 15000;
    c->pong_ms = 30000;
    c->recv_ms = 30000;
    c->send_ms = 10000;
    c->max_conns = 64;
    c->max_queue = 4u << 20;
    c->max_pings = 10;
    c->max_handshakes = 16;
    c->max_per_address = 4;
    c->max_ignored = 100;
    c->max_warning_events = 10;
}

/* ------------------------------------------------------------ events */

static evnode_t *push_event(gz_peers_t *p, const conn_t *c, gz_peer_ev_type_t type)
{
    evnode_t *n = calloc(1, sizeof *n);
    if (!n) abort(); /* an event that cannot be reported must not be lost silently */
    n->ev.type = type;
    n->ev.conn = c->id;
    n->ev.outbound = c->outbound;
    n->ev.have_node_id = c->have_id;
    if (c->have_id) memcpy(n->ev.node_id, c->node_id, 33);
    n->ev.was_connected = c->init_got;
    if (p->tail) p->tail->next = n;
    else p->head = n;
    p->tail = n;
    return n;
}

static void set_text(char *dst, const char *src)
{
    size_t i;
    for (i = 0; src && src[i] && i < 159; i++) dst[i] = src[i];
    dst[i] = 0;
}

/* ------------------------------------------------------------ connections */

static conn_t *find(gz_peers_t *p, uint64_t id)
{
    unsigned i;
    for (i = 0; i < p->n_conns; i++)
        if (p->conns[i]->id == id) return p->conns[i];
    return NULL;
}

static void destroy(gz_peers_t *p, conn_t *c)
{
    unsigned i;
    for (i = 0; i < p->n_conns; i++) {
        if (p->conns[i] == c) {
            p->conns[i] = p->conns[--p->n_conns];
            break;
        }
    }
    if (c->fd >= 0) close(c->fd);
    gz_noise_wipe(&c->noise);
    gz_env_reasm_reset(&c->reasm);
    free(c->rx);
    free(c->tx);
    OPENSSL_cleanse(c, sizeof *c);
    free(c);
}

/* The connection is gone: report it and free it. */
static void fail(gz_peers_t *p, conn_t *c, gz_peer_why_t why, int err, const char *text)
{
    evnode_t *n = push_event(p, c, GZ_PEER_EV_CLOSED);
    n->ev.why = why;
    n->ev.sys_errno = err;
    n->ev.noise_err = GZ_NOISE_OK;
    set_text(n->ev.text, text);
    destroy(p, c);
}

static void fail_noise(gz_peers_t *p, conn_t *c, gz_peer_why_t why, gz_noise_err_t ne)
{
    evnode_t *n = push_event(p, c, GZ_PEER_EV_CLOSED);
    n->ev.why = why;
    n->ev.noise_err = ne;
    set_text(n->ev.text, gz_noise_err_name(ne));
    destroy(p, c);
}

static int tx_room(conn_t *c, size_t need)
{
    if (c->tx_off && c->tx_cap - c->tx_len < need) {
        memmove(c->tx, c->tx + c->tx_off, c->tx_len - c->tx_off);
        c->tx_len -= c->tx_off;
        c->tx_off = 0;
    }
    if (c->tx_cap - c->tx_len < need) {
        size_t cap = c->tx_cap ? c->tx_cap : 4096;
        uint8_t *nb;
        while (cap - c->tx_len < need) cap *= 2;
        nb = realloc(c->tx, cap);
        if (!nb) return 0;
        c->tx = nb;
        c->tx_cap = cap;
    }
    return 1;
}

static size_t queued(const conn_t *c) { return c->tx_len - c->tx_off; }

static int q_raw(conn_t *c, const uint8_t *b, size_t n)
{
    if (!tx_room(c, n)) return 0;
    if (!queued(c)) c->t_tx = now_ms();
    memcpy(c->tx + c->tx_len, b, n);
    c->tx_len += n;
    return 1;
}

/* Encrypts one message onto the queue. 0 on failure (the state is then dead). */
static int q_msg(conn_t *c, const uint8_t *msg, size_t len)
{
    size_t n;
    if (!tx_room(c, len + GZ_NOISE_HDR_LEN + GZ_NOISE_MAC_LEN)) return 0;
    if (!queued(c)) c->t_tx = now_ms();
    if (gz_noise_encrypt(&c->noise, msg, len, c->tx + c->tx_len, c->tx_cap - c->tx_len, &n)) return 0;
    c->tx_len += n;
    return 1;
}

/* Refuse: a warning, then close once it is sent. */
static void refuse(gz_peers_t *p, conn_t *c, gz_peer_why_t why, const char *reason)
{
    size_t n;
    if (c->closing) return;
    c->closing = 1;
    c->close_why = why;
    set_text(c->close_text, reason);
    /* BOLT 1: nothing but init before the peer's init has arrived, so no
     * warning then (review of PR 23, F3). */
    if (c->phase == PH_OPEN && c->peer_init && !gz_ln_alert_write(GZ_LN_WARNING, reason, p->out, sizeof p->out, &n))
        q_msg(c, p->out, n);
    /* With nothing to send, the next round of timers closes it. */
    c->close_by = now_ms() + (queued(c) ? p->cfg.send_ms : 0);
}

static void finish_close(gz_peers_t *p, conn_t *c)
{
    fail(p, c, c->close_why, 0, c->close_text);
}

/* Handshake done: send init and wait for the peer's. */
static int start_open(gz_peers_t *p, conn_t *c)
{
    size_t n;
    c->phase = PH_OPEN;
    c->rx_need = GZ_NOISE_HDR_LEN;
    c->rx_have = 0;
    c->rx_body = 0;
    if (gz_ln_init_write(p->cfg.chain, p->out, sizeof p->out, &n) || !q_msg(c, p->out, n)) {
        fail(p, c, GZ_PEER_WHY_SOCKET, ENOMEM, "cannot queue init");
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------ messages */

static void send_ping(gz_peers_t *p, conn_t *c)
{
    size_t n;
    /* A different length each time, 1 to 16, so a late pong cannot pass for
     * the current one. */
    uint16_t want = (uint16_t)(1 + c->ping_seq++ % 16);
    if (gz_ln_ping_write(want, 0, p->out, sizeof p->out, &n) || !q_msg(c, p->out, n)) {
        fail(p, c, GZ_PEER_WHY_SOCKET, ENOMEM, "cannot queue ping");
        return;
    }
    c->ping_out = 1;
    c->ping_expect = want;
    c->t_ping = now_ms();
    p->stats.pings_sent++;
}

static void deliver(gz_peers_t *p, conn_t *c, const gz_env_msg_t *m)
{
    evnode_t *n = push_event(p, c, GZ_PEER_EV_MESSAGE);
    n->ev.kind = m->kind;
    memcpy(n->ev.scope, m->scope, 32);
    if (m->records_len) {
        n->body = malloc(m->records_len);
        if (!n->body) abort();
        memcpy(n->body, m->records, m->records_len);
    }
    n->ev.records = n->body;
    n->ev.records_len = m->records_len;
}

static int admit(gz_peers_t *p, conn_t *c);

/* Counts a message that changes nothing (an unknown odd type or kind, a
 * discovery kind, a wrong tag, a warning). More than max_ignored in one
 * pong_ms window is refused (review of PR 23, F7). 0 if refused. */
static int count_ignored(gz_peers_t *p, conn_t *c)
{
    int64_t now = now_ms();
    if (now - c->ignored_window >= p->cfg.pong_ms) {
        c->ignored_window = now;
        c->ignored = 0;
    }
    if (++c->ignored > p->cfg.max_ignored) {
        refuse(p, c, GZ_PEER_WHY_PROTOCOL, "too many ignored messages");
        return 0;
    }
    return 1;
}

static void on_envelope(gz_peers_t *p, conn_t *c, const uint8_t *m, size_t len)
{
    gz_env_side_t at = c->outbound ? GZ_ENV_AT_MEMBER : GZ_ENV_AT_HOST;
    gz_env_msg_t env, whole;
    const char *reason = NULL;
    gz_env_verdict_t v = gz_env_read(m, len, at, &env, &reason);
    size_t n;
    if (v == GZ_ENV_DELIVER && env.kind == GZ_ENV_KIND_PART) {
        v = gz_env_reasm_add(&c->reasm, &env, at, p->cfg.secp, &whole, &reason);
        if (v == GZ_ENV_DELIVER) env = whole;
    }
    switch (v) {
    case GZ_ENV_DELIVER:
        deliver(p, c, &env);
        /* The event holds its own copy: release the transfer now. */
        gz_env_reasm_reset(&c->reasm);
        break;
    case GZ_ENV_HELD:
        break;
    case GZ_ENV_IGNORE:
        count_ignored(p, c);
        break;
    case GZ_ENV_IGNORE_WARN:
        if (!count_ignored(p, c)) break;
        if (!c->warned && !gz_ln_alert_write(GZ_LN_WARNING, reason, p->out, sizeof p->out, &n)) {
            c->warned = 1;
            if (!q_msg(c, p->out, n)) fail(p, c, GZ_PEER_WHY_SOCKET, ENOMEM, "cannot queue warning");
        }
        break;
    case GZ_ENV_REFUSE:
        refuse(p, c, GZ_PEER_WHY_PROTOCOL, reason ? reason : "refused");
        break;
    }
}

/* One whole decrypted message. The connection may be gone afterwards: the
 * caller must look it up again. */
static void on_message(gz_peers_t *p, conn_t *c, const uint8_t *m, size_t len)
{
    uint16_t type, v;
    size_t n;
    int64_t now = now_ms();
    char text[160];
    gz_ln_err_t le;
    c->t_rx = now;
    if (len < 2) { refuse(p, c, GZ_PEER_WHY_PROTOCOL, "message shorter than its type"); return; }
    type = get16(m);
    if (!c->init_got) {
        /* BOLT 1: init is the first message, and nothing else comes before it. */
        if (type != GZ_LN_INIT) { refuse(p, c, GZ_PEER_WHY_INIT, "first message is not init"); return; }
        le = gz_ln_init_check(m, len, p->cfg.chain);
        if (le == GZ_LN_REQUIRED_FEATURE) { refuse(p, c, GZ_PEER_WHY_INIT, "init requires an unknown feature"); return; }
        if (le == GZ_LN_NETWORK) { refuse(p, c, GZ_PEER_WHY_INIT, "init networks is not exactly our chain"); return; }
        if (le) { refuse(p, c, GZ_PEER_WHY_INIT, "malformed init"); return; }
        c->peer_init = 1;
        if (!c->outbound && !admit(p, c)) return;
        c->init_got = 1;
        push_event(p, c, GZ_PEER_EV_CONNECTED);
        return;
    }
    switch (type) {
    case GZ_LN_INIT:
        refuse(p, c, GZ_PEER_WHY_PROTOCOL, "second init");
        return;
    case GZ_LN_PING:
        if (gz_ln_ping_read(m, len, &v)) { refuse(p, c, GZ_PEER_WHY_PROTOCOL, "malformed ping"); return; }
        p->stats.pings_received++;
        if (now - c->window_start >= p->cfg.pong_ms) {
            c->window_start = now;
            c->pings_in_window = 0;
        }
        if (++c->pings_in_window > p->cfg.max_pings) { refuse(p, c, GZ_PEER_WHY_PROTOCOL, "too many pings"); return; }
        if (v >= GZ_LN_PONG_IGNORE_FROM) return; /* BOLT 1: ignore */
        if (queued(c) + v + 4 > p->cfg.max_queue) return; /* the peer is not reading; its pong waits */
        if (gz_ln_pong_write(v, p->out, sizeof p->out, &n) || !q_msg(c, p->out, n)) {
            fail(p, c, GZ_PEER_WHY_SOCKET, ENOMEM, "cannot queue pong");
            return;
        }
        p->stats.pongs_sent++;
        return;
    case GZ_LN_PONG:
        if (gz_ln_pong_read(m, len, &v)) { refuse(p, c, GZ_PEER_WHY_PROTOCOL, "malformed pong"); return; }
        if (!c->ping_out) return; /* not asked for: harmless */
        if (v != c->ping_expect) { refuse(p, c, GZ_PEER_WHY_PROTOCOL, "pong of the wrong length"); return; }
        c->ping_out = 0;
        p->stats.pongs_received++;
        return;
    case GZ_LN_WARNING:
        if (gz_ln_alert_read(m, len, text, sizeof text)) { refuse(p, c, GZ_PEER_WHY_PROTOCOL, "malformed warning"); return; }
        if (!count_ignored(p, c)) return;
        /* The first few become events; the rest are only counted (F7). */
        if (c->warnings >= p->cfg.max_warning_events) {
            p->stats.warnings_dropped++;
            return;
        }
        c->warnings++;
        set_text(push_event(p, c, GZ_PEER_EV_WARNING)->ev.text, text);
        return;
    case GZ_LN_ERROR:
        if (gz_ln_alert_read(m, len, text, sizeof text)) set_text(text, "malformed error");
        fail(p, c, GZ_PEER_WHY_PEER_ERROR, 0, text);
        return;
    case GZ_ENV_TYPE:
        on_envelope(p, c, m, len);
        return;
    default:
        if (gz_msg_unknown_action(type) == GZ_MSG_CLOSE) refuse(p, c, GZ_PEER_WHY_PROTOCOL, "unknown even message");
        else count_ignored(p, c);
        return;
    }
}

/* rx holds rx_need bytes. Returns 0 if the connection was freed. */
static int unit_done(gz_peers_t *p, conn_t *c)
{
    gz_noise_err_t ne;
    uint8_t act[GZ_NOISE_ACT3_LEN];
    size_t body;
    uint64_t id = c->id;
    switch (c->phase) {
    case PH_I_WAIT2:
        /* The pin: act two's MAC depends on ECDH with the pinned key. */
        if ((ne = gz_noise_act2_read(&c->noise, c->rx, GZ_NOISE_ACT2_LEN)) ||
            (ne = gz_noise_act3_write(&c->noise, act))) {
            fail_noise(p, c, GZ_PEER_WHY_HANDSHAKE, ne);
            return 0;
        }
        if (!q_raw(c, act, GZ_NOISE_ACT3_LEN)) { fail(p, c, GZ_PEER_WHY_SOCKET, ENOMEM, "queue"); return 0; }
        return start_open(p, c);
    case PH_R_WAIT1:
        if ((ne = gz_noise_act1_read(&c->noise, c->rx, GZ_NOISE_ACT1_LEN)) ||
            (ne = gz_noise_act2_write(&c->noise, act))) {
            fail_noise(p, c, GZ_PEER_WHY_HANDSHAKE, ne);
            return 0;
        }
        if (!q_raw(c, act, GZ_NOISE_ACT2_LEN)) { fail(p, c, GZ_PEER_WHY_SOCKET, ENOMEM, "queue"); return 0; }
        c->phase = PH_R_WAIT3;
        c->rx_need = GZ_NOISE_ACT3_LEN;
        c->rx_have = 0;
        return 1;
    case PH_R_WAIT3:
        if ((ne = gz_noise_act3_read(&c->noise, c->rx, GZ_NOISE_ACT3_LEN))) {
            fail_noise(p, c, GZ_PEER_WHY_HANDSHAKE, ne);
            return 0;
        }
        if (gz_noise_remote_static(&c->noise, c->node_id)) { fail(p, c, GZ_PEER_WHY_HANDSHAKE, 0, "no key"); return 0; }
        c->have_id = 1;
        if (!p->cfg.is_member(c->node_id, p->cfg.member_ctx)) {
            fail(p, c, GZ_PEER_WHY_NOT_MEMBER, 0, "not a member");
            return 0;
        }
        return start_open(p, c);
    default:
        break;
    }
    if (!c->rx_body) {
        if ((ne = gz_noise_decrypt_header(&c->noise, c->rx, GZ_NOISE_HDR_LEN, &body))) {
            fail_noise(p, c, GZ_PEER_WHY_CRYPTO, ne);
            return 0;
        }
        c->rx_body = 1;
        c->rx_need = body + GZ_NOISE_MAC_LEN;
        c->rx_have = 0;
        return 1;
    }
    body = c->rx_need - GZ_NOISE_MAC_LEN;
    if ((ne = gz_noise_decrypt_body(&c->noise, c->rx, c->rx_need, p->plain, sizeof p->plain))) {
        fail_noise(p, c, GZ_PEER_WHY_CRYPTO, ne);
        return 0;
    }
    c->rx_body = 0;
    c->rx_need = GZ_NOISE_HDR_LEN;
    c->rx_have = 0;
    c->t_msg = 0;
    on_message(p, c, p->plain, body);
    gz_net_wipe(p->plain, body);
    return find(p, id) != NULL;
}

/* ------------------------------------------------------------ sockets */

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

static conn_t *new_conn(gz_peers_t *p, int fd, int outbound)
{
    conn_t *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->rx = malloc(RX_CAP);
    if (!c->rx) {
        free(c);
        return NULL;
    }
    c->id = ++p->next_id;
    c->fd = fd;
    c->outbound = outbound;
    c->t_start = c->t_rx = c->window_start = c->ignored_window = now_ms();
    gz_env_reasm_init(&c->reasm);
    p->conns[p->n_conns++] = c;
    return c;
}

static void do_read(gz_peers_t *p, conn_t *c)
{
    uint64_t id = c->id;
    int units = 0;
    while (units < 64) {
        ssize_t r = recv(c->fd, c->rx + c->rx_have, c->rx_need - c->rx_have, 0);
        if (r > 0) {
            if (c->phase == PH_OPEN && !c->rx_body && c->rx_have == 0) c->t_msg = now_ms();
            c->rx_have += (size_t)r;
            if (c->rx_have == c->rx_need) {
                units++;
                if (!unit_done(p, c)) return;
                if (!(c = find(p, id)) || c->closing) return;
            }
            continue;
        }
        if (r == 0) { fail(p, c, GZ_PEER_WHY_LOST, 0, "closed by the peer"); return; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        fail(p, c, errno == ECONNRESET ? GZ_PEER_WHY_LOST : GZ_PEER_WHY_SOCKET, errno, strerror(errno));
        return;
    }
}

static void do_write(gz_peers_t *p, conn_t *c)
{
    while (queued(c)) {
        ssize_t r = send(c->fd, c->tx + c->tx_off, queued(c), SEND_FLAGS);
        if (r > 0) {
            c->tx_off += (size_t)r;
            c->t_tx = now_ms();
            continue;
        }
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (c->closing) { finish_close(p, c); return; }
        fail(p, c, errno == EPIPE || errno == ECONNRESET ? GZ_PEER_WHY_LOST : GZ_PEER_WHY_SOCKET, errno,
             strerror(errno));
        return;
    }
    if (!queued(c)) c->tx_off = c->tx_len = 0;
    if (c->closing && !queued(c)) finish_close(p, c);
}

static void tcp_done(gz_peers_t *p, conn_t *c)
{
    int err = 0;
    socklen_t el = sizeof err;
    uint8_t act[GZ_NOISE_ACT1_LEN];
    gz_noise_err_t ne;
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0) err = errno;
    if (err == EINPROGRESS || err == EALREADY) return;
    if (err) {
        fail(p, c, err == ECONNREFUSED ? GZ_PEER_WHY_REFUSED : err == ETIMEDOUT ? GZ_PEER_WHY_TIMEOUT_CONNECT
                                                                                  : GZ_PEER_WHY_SOCKET,
             err, strerror(err));
        return;
    }
    if ((ne = gz_noise_act1_write(&c->noise, act))) { fail_noise(p, c, GZ_PEER_WHY_HANDSHAKE, ne); return; }
    if (!q_raw(c, act, GZ_NOISE_ACT1_LEN)) { fail(p, c, GZ_PEER_WHY_SOCKET, ENOMEM, "queue"); return; }
    c->phase = PH_I_WAIT2;
    c->rx_need = GZ_NOISE_ACT2_LEN;
    c->rx_have = 0;
}

/* The address part of a socket address (IPv4 or IPv6), for the
 * per-address cap. */
static int same_host(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET)
        return memcmp(&((const struct sockaddr_in *)a)->sin_addr, &((const struct sockaddr_in *)b)->sin_addr,
                      sizeof(struct in_addr)) == 0;
    if (a->ss_family == AF_INET6)
        return memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr, &((const struct sockaddr_in6 *)b)->sin6_addr,
                      sizeof(struct in6_addr)) == 0;
    return 0;
}

/* The oldest accepted connection matching `want`: 0 for one still in its
 * handshake (no valid init yet), 1 for an established one without a seat. */
static conn_t *oldest_inbound(gz_peers_t *p, int established_unseated)
{
    conn_t *best = NULL;
    unsigned i;
    for (i = 0; i < p->n_conns; i++) {
        conn_t *c = p->conns[i];
        if (c->outbound || c->closing) continue;
        if (established_unseated ? !(c->init_got && !c->seated) : c->init_got) continue;
        if (!best || c->t_start < best->t_start) best = c;
    }
    return best;
}

/* Admission of a member whose init has just been accepted (review of PR
 * 23, F1). Established connections are capped at max_conns; when full, the
 * oldest accepted connection without a seat is evicted, or, if every one
 * holds a seat, the newcomer is refused. 0 if `c` was refused. */
static int admit(gz_peers_t *p, conn_t *c)
{
    unsigned i, established = 0;
    for (i = 0; i < p->n_conns; i++)
        if (p->conns[i]->init_got && !p->conns[i]->closing) established++;
    if (established < p->cfg.max_conns) return 1;
    {
        conn_t *victim = oldest_inbound(p, 1);
        if (victim) {
            p->stats.evicted_unseated++;
            refuse(p, victim, GZ_PEER_WHY_EVICTED, "host full: evicted without a seat");
            return 1;
        }
    }
    p->stats.refused_full++;
    refuse(p, c, GZ_PEER_WHY_FULL, "host full");
    return 0;
}

static void do_accept(gz_peers_t *p, int lfd)
{
    for (;;) {
        conn_t *c;
        gz_noise_err_t ne;
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        unsigned i, same = 0, pending = 0;
#if ATOMIC_FLAGS
        int fd = accept4(lfd, (struct sockaddr *)&ss, &sl, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
        int fd = accept(lfd, (struct sockaddr *)&ss, &sl);
#endif
        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            return; /* EAGAIN, or out of descriptors: try again on the next poll */
        }
        for (i = 0; i < p->n_conns; i++) {
            const conn_t *o = p->conns[i];
            if (o->outbound) continue;
            if (same_host(&o->addr, &ss)) same++;
            if (!o->init_got) pending++;
        }
        /* At most max_per_address accepted connections from one address. */
        if (p->cfg.max_per_address && same >= p->cfg.max_per_address) {
            p->stats.refused_address++;
            close(fd);
            continue;
        }
        /* Handshakes in progress have their own budget; when it is full the
         * oldest gives way, so silent sockets cannot keep members out: an
         * honest handshake takes milliseconds. */
        if (pending >= p->cfg.max_handshakes) {
            conn_t *victim = oldest_inbound(p, 0);
            if (victim) {
                p->stats.evicted_handshakes++;
                fail(p, victim, GZ_PEER_WHY_EVICTED, 0, "handshake budget full: oldest evicted");
            }
        }
        if (p->n_conns >= p->cap || !prepare_socket(fd) || !(c = new_conn(p, fd, 0))) {
            p->stats.refused_full++;
            close(fd);
            continue;
        }
        memcpy(&c->addr, &ss, sizeof ss);
        c->addrlen = sl;
        if ((ne = gz_noise_init_responder(&c->noise, p->cfg.secp, p->cfg.static_key, p->cfg.random))) {
            fail_noise(p, c, GZ_PEER_WHY_HANDSHAKE, ne);
            continue;
        }
        c->phase = PH_R_WAIT1;
        c->rx_need = GZ_NOISE_ACT1_LEN;
    }
}

/* ------------------------------------------------------------ timers */

static int64_t next_deadline(const gz_peers_t *p, const conn_t *c)
{
    int64_t d = INT64_MAX, t;
#define EARLIER(x) do { t = (x); if (t < d) d = t; } while (0)
    if (c->closing) return c->close_by;
    if (!c->init_got) EARLIER(c->t_start + p->cfg.handshake_ms);
    else if (c->ping_out) EARLIER(c->t_ping + p->cfg.pong_ms);
    else EARLIER(c->t_rx + p->cfg.ping_ms);
    if (c->t_msg) EARLIER(c->t_msg + p->cfg.recv_ms);
    if (queued(c)) EARLIER(c->t_tx + p->cfg.send_ms);
#undef EARLIER
    return d;
}

static void run_timers(gz_peers_t *p)
{
    unsigned i = 0;
    int64_t now = now_ms();
    while (i < p->n_conns) {
        conn_t *c = p->conns[i];
        unsigned before = p->n_conns;
        if (c->closing) {
            if (now >= c->close_by) finish_close(p, c);
        } else if (!c->init_got && now - c->t_start >= p->cfg.handshake_ms) {
            fail(p, c, c->phase == PH_TCP ? GZ_PEER_WHY_TIMEOUT_CONNECT : GZ_PEER_WHY_TIMEOUT_HANDSHAKE, 0,
                 c->phase == PH_TCP ? "connect timed out" : "handshake timed out");
        } else if (c->t_msg && now - c->t_msg >= p->cfg.recv_ms) {
            fail(p, c, GZ_PEER_WHY_TIMEOUT_MESSAGE, 0, "message not finished in time");
        } else if (queued(c) && now - c->t_tx >= p->cfg.send_ms) {
            fail(p, c, GZ_PEER_WHY_TIMEOUT_SEND, 0, "peer is not reading");
        } else if (c->init_got && c->ping_out && now - c->t_ping >= p->cfg.pong_ms) {
            fail(p, c, GZ_PEER_WHY_TIMEOUT_PONG, 0, "no pong");
        } else if (c->init_got && !c->ping_out && now - c->t_rx >= p->cfg.ping_ms) {
            send_ping(p, c);
        }
        if (p->n_conns == before) i++; /* else the last connection moved into slot i */
    }
}

/* ------------------------------------------------------------ public */

gz_peers_t *gz_peers_new(const gz_peers_config_t *config)
{
    gz_peers_t *p;
    unsigned i;
    if (!config || !config->secp || !config->random.fill || !config->is_member || config->max_conns == 0 ||
        config->max_handshakes == 0 || config->max_ignored == 0 ||
        config->handshake_ms <= 0 || config->ping_ms <= 0 || config->pong_ms <= 0 || config->recv_ms <= 0 ||
        config->send_ms <= 0 || config->max_pings == 0)
        return NULL;
    p = calloc(1, sizeof *p);
    if (!p) return NULL;
    p->cap = config->max_conns + config->max_handshakes;
    p->conns = calloc(p->cap, sizeof *p->conns);
    if (!p->conns) {
        free(p);
        return NULL;
    }
    p->cfg = *config;
    for (i = 0; i < MAX_LISTEN; i++) p->lfd[i] = -1;
    return p;
}

void gz_peers_free(gz_peers_t *p)
{
    unsigned i;
    evnode_t *n;
    if (!p) return;
    while (p->n_conns) destroy(p, p->conns[0]);
    for (i = 0; i < p->n_listen; i++) close(p->lfd[i]);
    if (p->current) free_event(p->current);
    while ((n = p->head)) {
        p->head = n->next;
        free_event(n);
    }
    free(p->conns);
    OPENSSL_cleanse(p, sizeof *p);
    free(p);
}

gz_peers_err_t gz_peers_listen(gz_peers_t *p, const char *host, uint16_t port, uint16_t *bound_port)
{
    int fd;
    gz_conn_err_t e;
    if (p->n_listen >= MAX_LISTEN) return GZ_PEERS_ERR_LIMIT;
    e = gz_conn_listen(host, port, &fd, bound_port);
    if (e == GZ_CONN_ERR_ADDRESS) return GZ_PEERS_ERR_ADDRESS;
    if (e) return GZ_PEERS_ERR_SOCKET;
    p->lfd[p->n_listen++] = fd;
    return GZ_PEERS_OK;
}

gz_peers_err_t gz_peers_connect(gz_peers_t *p, const char *host, uint16_t port, const uint8_t pin[33],
                                const uint8_t static_key[32], uint64_t *conn)
{
    struct addrinfo hints, *res = NULL;
    char ps[8];
    int fd, r;
    conn_t *c;
    gz_noise_err_t ne;
    if (!pin || !conn) return GZ_PEERS_ERR_ARGS;
    {
        unsigned i, out = 0;
        for (i = 0; i < p->n_conns; i++) out += p->conns[i]->outbound || p->conns[i]->init_got;
        if (out >= p->cfg.max_conns || p->n_conns >= p->cap) return GZ_PEERS_ERR_LIMIT;
    }
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    snprintf(ps, sizeof ps, "%u", (unsigned)port);
    r = getaddrinfo(host, ps, &hints, &res);
    if (r) return r == EAI_NONAME ? GZ_PEERS_ERR_ADDRESS : GZ_PEERS_ERR_SOCKET;
#if ATOMIC_FLAGS
    fd = socket(res->ai_family, res->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, res->ai_protocol);
#else
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
#endif
    if (fd < 0 || !prepare_socket(fd)) {
        if (fd >= 0) close(fd);
        freeaddrinfo(res);
        return GZ_PEERS_ERR_SOCKET;
    }
    c = new_conn(p, fd, 1);
    if (!c) {
        close(fd);
        freeaddrinfo(res);
        return GZ_PEERS_ERR_MEMORY;
    }
    *conn = c->id;
    memcpy(c->node_id, pin, 33);
    c->have_id = 1;
    c->phase = PH_TCP;
    ne = gz_noise_init_initiator(&c->noise, p->cfg.secp, static_key ? static_key : p->cfg.static_key, pin,
                                 p->cfg.random);
    if (ne) {
        freeaddrinfo(res);
        fail_noise(p, c, GZ_PEER_WHY_HANDSHAKE, ne);
        return GZ_PEERS_OK; /* reported as an event, like every other outcome */
    }
    r = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (r == 0) tcp_done(p, c);
    else if (errno != EINPROGRESS && errno != EINTR)
        fail(p, c, errno == ECONNREFUSED ? GZ_PEER_WHY_REFUSED : GZ_PEER_WHY_SOCKET, errno, strerror(errno));
    return GZ_PEERS_OK;
}

static gz_peers_err_t ready_conn(gz_peers_t *p, uint64_t id, conn_t **out)
{
    conn_t *c = find(p, id);
    if (!c || c->closing) return GZ_PEERS_ERR_NO_CONN;
    if (!c->init_got) return GZ_PEERS_ERR_NOT_READY;
    *out = c;
    return GZ_PEERS_OK;
}

gz_peers_err_t gz_peers_send(gz_peers_t *p, uint64_t conn, uint16_t kind, const uint8_t scope[32],
                             const uint8_t *records, size_t records_len)
{
    conn_t *c;
    size_t n;
    unsigned count, i;
    uint8_t tid[32];
    gz_peers_err_t e = ready_conn(p, conn, &c);
    if (e) return e;
    if (kind == GZ_ENV_KIND_PART) return GZ_PEERS_ERR_ARGS; /* parts are made here, never by callers */
    if (records_len <= GZ_ENV_MAX_RECORDS) {
        if (queued(c) + records_len + 2 + GZ_ENV_HDR_LEN + 34 > p->cfg.max_queue) return GZ_PEERS_ERR_FULL;
        if (gz_env_write(kind, scope, records, records_len, p->out, sizeof p->out, &n)) return GZ_PEERS_ERR_ARGS;
        if (!q_msg(c, p->out, n)) { fail(p, c, GZ_PEER_WHY_SOCKET, ENOMEM, "cannot queue"); return GZ_PEERS_ERR_MEMORY; }
        gz_net_wipe(p->out, n);
        return GZ_PEERS_OK;
    }
    /* Members send no parts in slice 1 (messages.md section 5). */
    if (c->outbound || !(count = gz_env_part_count(records_len))) return GZ_PEERS_ERR_TOO_BIG;
    if (queued(c) + records_len + count * (2 + GZ_ENV_HDR_LEN + 100 + 34) > p->cfg.max_queue) return GZ_PEERS_ERR_FULL;
    gz_env_transfer_id(p->cfg.secp, kind, records, records_len, tid);
    for (i = 0; i < count; i++) {
        if (gz_env_write_part(tid, kind, scope, records, records_len, i, p->out, sizeof p->out, &n))
            return GZ_PEERS_ERR_ARGS; /* only before the first part: the arguments do not change */
        if (!q_msg(c, p->out, n)) { fail(p, c, GZ_PEER_WHY_SOCKET, ENOMEM, "cannot queue"); return GZ_PEERS_ERR_MEMORY; }
        gz_net_wipe(p->out, n);
    }
    return GZ_PEERS_OK;
}

gz_peers_err_t gz_peers_send_raw(gz_peers_t *p, uint64_t conn, const uint8_t *msg, size_t len)
{
    conn_t *c;
    gz_peers_err_t e = ready_conn(p, conn, &c);
    if (e) return e;
    if (len < 2 || len > GZ_NOISE_MAX_MSG) return GZ_PEERS_ERR_TOO_BIG;
    if (queued(c) + len + 34 > p->cfg.max_queue) return GZ_PEERS_ERR_FULL;
    if (!q_msg(c, msg, len)) { fail(p, c, GZ_PEER_WHY_SOCKET, ENOMEM, "cannot queue"); return GZ_PEERS_ERR_MEMORY; }
    return GZ_PEERS_OK;
}

gz_peers_err_t gz_peers_refuse(gz_peers_t *p, uint64_t conn, const char *reason)
{
    conn_t *c = find(p, conn);
    if (!c || c->closing) return GZ_PEERS_ERR_NO_CONN;
    refuse(p, c, GZ_PEER_WHY_LOCAL, reason ? reason : "refused");
    return GZ_PEERS_OK;
}

static void free_event(evnode_t *n)
{
    if (n->body) {
        gz_net_wipe(n->body, n->ev.records_len);
        free(n->body);
    }
    free(n);
}

gz_peers_err_t gz_peers_close(gz_peers_t *p, uint64_t conn)
{
    conn_t *c = find(p, conn);
    evnode_t **pp = &p->head, *n;
    if (!c) return GZ_PEERS_ERR_NO_CONN;
    destroy(p, c);
    /* Nothing more from this connection, not even what was already queued
     * (review of PR 23, F8). */
    p->tail = NULL;
    while ((n = *pp)) {
        if (n->ev.conn == conn) {
            *pp = n->next;
            free_event(n);
        } else {
            p->tail = n;
            pp = &n->next;
        }
    }
    return GZ_PEERS_OK;
}

gz_peers_err_t gz_peers_set_seated(gz_peers_t *p, uint64_t conn, int seated)
{
    conn_t *c = find(p, conn);
    if (!c) return GZ_PEERS_ERR_NO_CONN;
    c->seated = seated != 0;
    return GZ_PEERS_OK;
}

int gz_peers_test_plain_clear(const gz_peers_t *p)
{
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < sizeof p->plain; i++) acc |= p->plain[i];
    return acc == 0;
}

static int pop(gz_peers_t *p, gz_peer_event_t *ev)
{
    evnode_t *n = p->head;
    if (!n) return 0;
    p->head = n->next;
    if (!p->head) p->tail = NULL;
    n->next = NULL;
    p->current = n;
    *ev = n->ev;
    return 1;
}

int gz_peers_poll(gz_peers_t *p, int timeout_ms, gz_peer_event_t *ev)
{
    int64_t end = timeout_ms < 0 ? INT64_MAX : now_ms() + timeout_ms;
    if (p->current) {
        free_event(p->current);
        p->current = NULL;
    }
    for (;;) {
        struct pollfd *pf;
        uint64_t *ids;
        unsigned i, n = 0, total = p->n_listen + p->n_conns;
        int64_t now, wake = end;
        int r, wait;
        if (pop(p, ev)) return 1;
        pf = calloc(total ? total : 1, sizeof *pf);
        ids = calloc(total ? total : 1, sizeof *ids);
        if (!pf || !ids) abort();
        for (i = 0; i < p->n_listen; i++) {
            pf[n].fd = p->lfd[i];
            pf[n].events = POLLIN;
            ids[n++] = 0;
        }
        for (i = 0; i < p->n_conns; i++) {
            conn_t *c = p->conns[i];
            int64_t d = next_deadline(p, c);
            if (d < wake) wake = d;
            pf[n].fd = c->fd;
            pf[n].events = (short)((c->phase == PH_TCP ? 0 : c->closing ? 0 : POLLIN) |
                                   (c->phase == PH_TCP || queued(c) ? POLLOUT : 0));
            ids[n++] = c->id;
        }
        now = now_ms();
        wait = wake <= now ? 0 : wake - now > 60000 ? 60000 : (int)(wake - now);
        r = poll(pf, n, wait);
        if (r < 0 && errno != EINTR) {
            free(pf);
            free(ids);
            return 0;
        }
        for (i = 0; r > 0 && i < n; i++) {
            conn_t *c;
            if (!pf[i].revents) continue;
            if (ids[i] == 0) {
                do_accept(p, pf[i].fd);
                continue;
            }
            if (!(c = find(p, ids[i]))) continue;
            if (c->phase == PH_TCP) {
                tcp_done(p, c);
                continue;
            }
            if (pf[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                if (c->closing) {
                    /* Not reading any more; a hang-up ends the flush. */
                    if (pf[i].revents & (POLLHUP | POLLERR)) finish_close(p, c);
                    continue;
                }
                do_read(p, c);
                if (!(c = find(p, ids[i]))) continue;
            }
            if (queued(c)) do_write(p, c);
        }
        free(pf);
        free(ids);
        run_timers(p);
        if (pop(p, ev)) return 1;
        if (now_ms() >= end) return 0;
    }
}

void gz_peers_stats(const gz_peers_t *p, gz_peers_stats_t *s)
{
    unsigned i;
    *s = p->stats;
    s->open = p->n_conns;
    s->reassembly_bytes = 0;
    for (i = 0; i < p->n_conns; i++) s->reassembly_bytes += p->conns[i]->reasm.allocated;
}

const char *gz_peer_why_name(gz_peer_why_t w)
{
    switch (w) {
    case GZ_PEER_WHY_NONE: return "none";
    case GZ_PEER_WHY_LOST: return "connection lost";
    case GZ_PEER_WHY_REFUSED: return "connection refused";
    case GZ_PEER_WHY_TIMEOUT_CONNECT: return "connect timed out";
    case GZ_PEER_WHY_TIMEOUT_HANDSHAKE: return "handshake timed out";
    case GZ_PEER_WHY_TIMEOUT_PONG: return "no pong";
    case GZ_PEER_WHY_TIMEOUT_MESSAGE: return "message timed out";
    case GZ_PEER_WHY_TIMEOUT_SEND: return "send timed out";
    case GZ_PEER_WHY_HANDSHAKE: return "handshake refused";
    case GZ_PEER_WHY_NOT_MEMBER: return "not a member";
    case GZ_PEER_WHY_INIT: return "init refused";
    case GZ_PEER_WHY_PROTOCOL: return "message refused";
    case GZ_PEER_WHY_PEER_ERROR: return "peer sent an error";
    case GZ_PEER_WHY_CRYPTO: return "decryption failed";
    case GZ_PEER_WHY_SOCKET: return "socket error";
    case GZ_PEER_WHY_ADDRESS: return "address must be numeric";
    case GZ_PEER_WHY_LOCAL: return "refused by us";
    case GZ_PEER_WHY_EVICTED: return "evicted";
    case GZ_PEER_WHY_FULL: return "host full";
    }
    return "unknown";
}

const char *gz_peers_err_name(gz_peers_err_t e)
{
    switch (e) {
    case GZ_PEERS_OK: return "ok";
    case GZ_PEERS_ERR_ARGS: return "invalid arguments";
    case GZ_PEERS_ERR_NO_CONN: return "no such connection";
    case GZ_PEERS_ERR_NOT_READY: return "connection not ready";
    case GZ_PEERS_ERR_TOO_BIG: return "message too big";
    case GZ_PEERS_ERR_FULL: return "send queue full";
    case GZ_PEERS_ERR_LIMIT: return "connection limit";
    case GZ_PEERS_ERR_SOCKET: return "socket error";
    case GZ_PEERS_ERR_ADDRESS: return "address must be numeric";
    case GZ_PEERS_ERR_MEMORY: return "out of memory";
    }
    return "unknown";
}
