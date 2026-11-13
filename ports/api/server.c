/* SPDX-License-Identifier: MIT */
/* Listeners, the poll loop, accept with the same-user check, timers
 * (spec/local-api.md 3.1, 3.2, 3.4). One thread serves every connection;
 * passphrase operations run on the derivation thread (derive.c). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/sha.h>

#include "internal.h"

static void defaults(gz_api_limits *l)
{
    if (!l->max_connections) l->max_connections = 32;
    if (!l->max_header_lines) l->max_header_lines = GZ_MAX_HEADERS;
    if (l->max_header_lines > GZ_MAX_HEADERS) l->max_header_lines = GZ_MAX_HEADERS;
    if (!l->max_head_bytes || l->max_head_bytes > 16384) l->max_head_bytes = 16384;
    if (!l->max_body_bytes) l->max_body_bytes = 64 * 1024;
    if (!l->head_ms) l->head_ms = 10000;
    if (!l->body_ms) l->body_ms = 30000;
    if (!l->idle_ms) l->idle_ms = 60000;
    if (!l->idle_sign_out_ms) l->idle_sign_out_ms = 15 * 60 * 1000;
    if (!l->fresh_ms) l->fresh_ms = 5 * 60 * 1000;
    if (!l->start_token_ms) l->start_token_ms = 10 * 60 * 1000;
    if (!l->code_ms) l->code_ms = 10 * 60 * 1000;
    if (!l->tunnel_idle_ms) l->tunnel_idle_ms = 2 * 60 * 1000;
    if (!l->keepalive_ms) l->keepalive_ms = 15000;
    if (!l->merge_ms) l->merge_ms = 250;
    if (!l->stream_unsent_max) l->stream_unsent_max = 64 * 1024;
}

static int listen_tcp(gz_api_server *srv, int v6, uint16_t port, const char **err)
{
    int fd, one = 1;
    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof ss);
    fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        if (v6) return 0;                               /* no IPv6 on this machine */
        *err = "cannot open a socket";
        return -1;
    }
    /* no SO_REUSEADDR or SO_REUSEPORT (3.1) */
    if (v6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        a->sin6_family = AF_INET6;
        a->sin6_addr = in6addr_loopback;
        a->sin6_port = htons(port);
        sl = sizeof *a;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a->sin_port = htons(port);
        sl = sizeof *a;
    }
    if (bind(fd, (struct sockaddr *)&ss, sl) != 0) {
        int e = errno;
        close(fd);
        if (v6 && (e == EADDRNOTAVAIL || e == EAFNOSUPPORT)) return 0;
        /* it never picks another port by itself (3.1) */
        *err = e == EADDRINUSE ? "the interface port is in use by another program" : "cannot bind the interface port";
        return -1;
    }
    if (listen(fd, 64) != 0) {
        close(fd);
        *err = "cannot listen";
        return -1;
    }
    if (!srv->port) {
        sl = sizeof ss;
        getsockname(fd, (struct sockaddr *)&ss, &sl);
        srv->port = ntohs(v6 ? ((struct sockaddr_in6 *)&ss)->sin6_port : ((struct sockaddr_in *)&ss)->sin_port);
    }
    srv->lfd[srv->nl++] = fd;
    return 0;
}

static int listen_unix(gz_api_server *srv, const char **err)
{
    struct sockaddr_un a;
    struct stat st;
    mode_t old;
    int fd;
    if (strlen(srv->sock_path) >= sizeof a.sun_path) { *err = "the data folder's path is too long for the local socket"; return -1; }
    if (lstat(srv->sock_path, &st) == 0) {              /* a socket left by an earlier run of ours */
        if (!S_ISSOCK(st.st_mode) || st.st_uid != geteuid()) { *err = "interface.sock exists and is not ours"; return -1; }
        unlink(srv->sock_path);
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) { *err = "cannot open the local socket"; return -1; }
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path, srv->sock_path, strlen(srv->sock_path));
    old = umask(0177);                                  /* the socket 0600 from its first moment */
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        umask(old);
        close(fd);
        *err = "cannot bind the local socket";
        return -1;
    }
    umask(old);
    chmod(srv->sock_path, 0600);
    if (listen(fd, 16) != 0) { close(fd); *err = "cannot listen on the local socket"; return -1; }
    srv->lfd[srv->nl++] = fd;
    return 0;
}

/* The folder is the program's (contract-v2 11): made 0700, checked and locked
 * before the server exists. The server creates and checks nothing; a missing
 * folder refuses to start (T11.6). */
static int prepare_dir(gz_api_server *srv, const char *dir, const char **err)
{
    struct stat st;
    char real[PATH_MAX];
    if (!realpath(dir, real)) { *err = "the data folder does not exist"; return -1; }
    if (stat(real, &st) != 0 || !S_ISDIR(st.st_mode)) { *err = "the data folder is not a folder"; return -1; }
    if (strlen(real) >= sizeof srv->data_dir) { *err = "the data folder's path is too long"; return -1; }
    memcpy(srv->data_dir, real, strlen(real) + 1);
    return 0;
}

gz_api_server *gz_api_server_new(const gz_api_config *cfg, const char **err)
{
    gz_api_server *srv;
    const char *e = "out of memory", *rt;
    uint8_t h[32], rid[4];
    char hex[65];
    int i;
    if (!cfg || !cfg->backend || !cfg->backend->wallet_state || !cfg->backend->passphrase_op ||
        !cfg->backend->status || !cfg->backend->call || !cfg->backend->network || !cfg->backend->program_version ||
        !cfg->data_dir) {
        if (err) *err = "incomplete configuration";
        return NULL;
    }
    if (cfg->listen_address && strcmp(cfg->listen_address, "127.0.0.1") != 0 && strcmp(cfg->listen_address, "::1") != 0) {
        if (err) *err = "the interface listens on a loopback address only (127.0.0.1, ::1)";
        return NULL;
    }
    srv = calloc(1, sizeof *srv);
    if (!srv) { if (err) *err = e; return NULL; }
    srv->cfg = *cfg;
    srv->lim = cfg->limits;
    defaults(&srv->lim);
    srv->be = cfg->backend;
    srv->bectx = cfg->backend_ctx;
    srv->wake[0] = srv->wake[1] = srv->done_pipe[0] = srv->done_pipe[1] = -1;
    for (i = 0; i < 3; i++) srv->lfd[i] = -1;
    srv->expect_uid = cfg->override_uid ? cfg->expect_uid : (int64_t)geteuid();
    pthread_mutex_init(&srv->notify_mu, NULL);
    srv->cmds_tail = &srv->cmds;
    gz_http_settings(&srv->settings);
    if (prepare_dir(srv, cfg->data_dir, &e) != 0) goto fail;
    snprintf(srv->sock_path, sizeof srv->sock_path, "%s/interface.sock", srv->data_dir);
    snprintf(srv->redirect_path, sizeof srv->redirect_path, "%s/first-run.html", srv->data_dir);
    snprintf(srv->attempts_path, sizeof srv->attempts_path, "%s/attempts.gza", srv->data_dir);
    /* the socket token's folder: outside the data folder, named by a hash of its path (storage 12.2) */
    SHA256((const unsigned char *)srv->data_dir, strlen(srv->data_dir), h);
    gz_hex(h, 8, hex);
    rt = cfg->runtime_dir ? cfg->runtime_dir : getenv("XDG_RUNTIME_DIR");
    if (rt && rt[0] == '/')
        snprintf(srv->token_dir, sizeof srv->token_dir, "%s/gazpacho-%s", rt, hex);
    else
        snprintf(srv->token_dir, sizeof srv->token_dir, "/tmp/gazpacho-%lu-%s", (unsigned long)geteuid(), hex);
    snprintf(srv->token_path, sizeof srv->token_path, "%s/socket.token", srv->token_dir);
    if (gz_random(rid, sizeof rid) != 0) goto fail;
    gz_hex(rid, sizeof rid, srv->run_id);
    srv->peer_check_ok = gz_peer_check_available(srv);
    if (!srv->peer_check_ok)
        gz_log(srv, "Other accounts on this computer can reach Gazpacho's page; the passphrase is what keeps them out "
                    "(the same-user check is unavailable here)");
    srv->pc = calloc(gz_api_server_max_fds(srv), sizeof *srv->pc);
    srv->pfbuf = calloc(gz_api_server_max_fds(srv), sizeof *srv->pfbuf);
    if (!srv->pc || !srv->pfbuf) goto fail;
    if (pipe2(srv->wake, O_CLOEXEC | O_NONBLOCK) != 0 || pipe2(srv->done_pipe, O_CLOEXEC | O_NONBLOCK) != 0) {
        e = "cannot make a pipe";
        goto fail;
    }
    srv->port = cfg->port;
    if (!cfg->no_listen) {
        if (!cfg->no_interface) {
            if (listen_tcp(srv, 0, srv->port, &e) != 0) goto fail;
            if (!cfg->no_ipv6 && listen_tcp(srv, 1, srv->port, &e) != 0) goto fail;
        }
        if (!cfg->no_socket && listen_unix(srv, &e) != 0) goto fail;
    }
    snprintf(srv->refused_page, sizeof srv->refused_page,
             "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Gazpacho</title></head>\n"
             "<body><p>Open Gazpacho by typing its address yourself: http://127.0.0.1:%u/</p></body></html>\n",
             (unsigned)(srv->port ? srv->port : 39735));
    if (gz_derive_start(srv) != 0) { e = "cannot start the derivation thread"; goto fail; }
    if (srv->be->wallet_state(srv->bectx) == GZ_API_WALLET_NONE) {
        if (!cfg->no_interface && gz_first_run_start(srv) != 0) gz_log(srv, "warning: the first-run file could not be written");
    } else {
        unlink(srv->redirect_path);
        srv->first_run_closed = 1;
        gz_attempts_load(srv);
    }
    if (srv->be->wallet_state(srv->bectx) == GZ_API_WALLET_UNLOCKED) gz_socket_token_make(srv);
    return srv;
fail:
    if (err) *err = e;
    gz_api_server_free(srv);
    return NULL;
}

void gz_api_server_free(gz_api_server *srv)
{
    int i;
    if (!srv) return;
    /* the order of contract-v2 4: listeners first, then the derivation thread
     * (its job discarded), then the connections */
    gz_api_server_stop_listening(srv);
    gz_derive_stop(srv);
    while (srv->conns) gz_conn_free(srv, srv->conns);
    if (srv->redirect_path[0]) unlink(srv->redirect_path);   /* deleted at stop (4.3) */
    if (srv->token_path[0]) gz_socket_token_drop(srv);        /* deleted at stop (storage 12.2) */
    for (i = 0; i < 2; i++) {
        if (srv->wake[i] >= 0) close(srv->wake[i]);
        if (srv->done_pipe[i] >= 0) close(srv->done_pipe[i]);
    }
    gz_cmds_free(srv);
    free(srv->pc);
    free(srv->pfbuf);
    pthread_mutex_destroy(&srv->notify_mu);
    gz_wipe(srv, sizeof *srv);
    free(srv);
}

uint16_t gz_api_server_port(const gz_api_server *srv) { return srv->port; }
const char *gz_api_server_socket_path(const gz_api_server *srv) { return srv->sock_path; }
const char *gz_api_server_run_id(const gz_api_server *srv) { return srv->run_id; }

void gz_api_server_stop(gz_api_server *srv)
{
    char b = 0;
    ssize_t w;
    atomic_store_explicit(&srv->stop, 1, memory_order_relaxed);
    w = write(srv->wake[1], &b, 1);
    (void)w;
}

void gz_api_server_counters(gz_api_server *srv, gz_api_counters *out)
{
    *out = srv->ctr;
}

int gz_api_first_run_code(gz_api_server *srv, char out[12])
{
    int64_t exp;
    if (srv->be->wallet_state(srv->bectx) != GZ_API_WALLET_NONE || srv->first_run_closed) return -1;
    return gz_code_make(srv, out, &exp);
}

/* ---- the loop ------------------------------------------------------------------------- */
static void refuse_other_user(int fd)
{
    static const char body[] =
        "{\"code\":\"other_user\",\"message\":\"This connection belongs to another account on this computer.\","
        "\"field\":null,\"params\":{}}";
    char ans[1024];
    int n = snprintf(ans, sizeof ans,
                     "HTTP/1.1 403 Forbidden\r\n"
                     "Content-Type: application/json; charset=utf-8\r\n"
                     "Cross-Origin-Resource-Policy: same-origin\r\n"
                     "X-Content-Type-Options: nosniff\r\n"
                     "Referrer-Policy: same-origin\r\n"
                     "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
                     "Cache-Control: no-store\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n%s",
                     sizeof body - 1, body);
    if (n > 0 && (size_t)n < sizeof ans) {
        ssize_t w = send(fd, ans, (size_t)n, MSG_NOSIGNAL | MSG_DONTWAIT);
        (void)w;
    }
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

static void accept_all(gz_api_server *srv, int lfd, int is_unix)
{
    int k;
    for (k = 0; k < 16; k++) {                          /* bounded per turn: dispatch never runs long */
        int fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd < 0) return;
        /* 3.4: who is at the other end, before a byte is read */
        if (!gz_peer_same_user(srv, fd)) {
            gz_log(srv, "refused a connection from another account");
            if (is_unix) close(fd);
            else refuse_other_user(fd);
            continue;
        }
        if (srv->nconns >= srv->lim.max_connections) {  /* 3.1: 32 open connections */
            close(fd);
            continue;
        }
        if (!gz_conn_new(srv, fd, is_unix)) close(fd);
    }
}

static void flush(gz_api_server *srv, gz_conn *c)
{
    while (c->out.off < c->out.len && c->state != CS_DEAD) {
        ssize_t n = send(c->fd, c->out.buf + c->out.off, c->out.len - c->out.off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
            c->state = CS_DEAD;
            return;
        }
        c->out.off += (size_t)n;
    }
    if (c->state == CS_DEAD) return;
    if (c->stream) {
        if (c->out.off == c->out.len) {
            gz_out_free(&c->out);
            if (c->close_after) c->state = CS_DEAD;
        }
        return;
    }
    if (c->state == CS_WRITE && c->out.off == c->out.len) {
        gz_conn_after_write(srv, c);
        if (c->state == CS_WRITE) flush(srv, c);       /* the next pipelined answer */
    }
}

static void read_conn(gz_api_server *srv, gz_conn *c)
{
    uint8_t buf[8192];
    int k;
    for (k = 0; k < 8; k++) {                           /* at most 64 KiB a turn per connection */
        size_t room = c->in_cap - c->in_len;
        ssize_t n;
        if (c->stream) room = sizeof buf;               /* read and drop: only to see the close */
        if (room == 0) return;
        if (room > sizeof buf) room = sizeof buf;
        n = recv(c->fd, buf, room, 0);
        if (n == 0) { c->state = CS_DEAD; return; }
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) c->state = CS_DEAD;
            return;
        }
        if (!c->stream) gz_conn_input(srv, c, buf, (size_t)n);
        gz_wipe(buf, (size_t)n);
        if (c->state == CS_DEAD) return;
    }
}

size_t gz_api_server_max_fds(const gz_api_server *srv)
{
    return 2 + 3 + (size_t)srv->lim.max_connections;
}

/* The earliest deadline of the server, from now (ms), or -1. */
static int next_timeout(gz_api_server *srv)
{
    gz_conn *c;
    int64_t now = gz_now_ms(srv), deadline = INT64_MAX;
    gz_sessions_tick(srv, now, &deadline);
    gz_first_run_tick(srv, now, &deadline);
    gz_events_tick(srv, now, &deadline);
    for (c = srv->conns; c; c = c->next) {
        if (c->state == CS_DEAD) return 0;              /* to be freed at once */
        if (c->state == CS_STREAM || (c->state == CS_BUSY && !c->held)) continue;
        if (c->deadline < deadline) deadline = c->deadline;
    }
    if (deadline == INT64_MAX) return -1;
    if (deadline <= now) return 0;
    return deadline - now > INT32_MAX ? INT32_MAX : (int)(deadline - now);
}

size_t gz_api_server_pollfds(gz_api_server *srv, struct pollfd *fds, size_t cap, int *timeout_ms)
{
    gz_conn *c;
    size_t n = 0;
    int i;
    *timeout_ms = next_timeout(srv);
    srv->npc = 0;
    if (cap < 2 + (size_t)srv->nl) { *timeout_ms = 0; return 0; }
    fds[n].fd = srv->wake[0]; fds[n].events = POLLIN; fds[n].revents = 0; srv->pc[n++] = NULL;
    fds[n].fd = srv->done_pipe[0]; fds[n].events = POLLIN; fds[n].revents = 0; srv->pc[n++] = NULL;
    for (i = 0; i < srv->nl; i++) {
        fds[n].fd = srv->lfd[i]; fds[n].events = POLLIN; fds[n].revents = 0; srv->pc[n++] = NULL;
    }
    for (c = srv->conns; c && n < cap; c = c->next) {
        short ev = 0;
        if (c->fd < 0 || c->state == CS_DEAD) continue;
        if (c->stream || c->in_len < c->in_cap) ev |= POLLIN;
        if (c->out.off < c->out.len) ev |= POLLOUT;
        fds[n].fd = c->fd;
        fds[n].events = ev;
        fds[n].revents = 0;
        srv->pc[n++] = c;
    }
    srv->npc = n;
    return n;
}

int gz_api_server_dispatch(gz_api_server *srv, const struct pollfd *fds, size_t n)
{
    gz_conn *c, *next;
    size_t i;
    int64_t now;
    if (n > srv->npc) n = srv->npc;
    for (i = 0; i < n; i++) {
        short re = fds[i].revents;
        if (!re) continue;
        if (fds[i].fd == srv->wake[0]) {
            char b[64];
            while (read(srv->wake[0], b, sizeof b) > 0) {
            }
            gz_events_drain_notify(srv);
            gz_cmds_run(srv);
        } else if (fds[i].fd == srv->done_pipe[0]) {
            gz_derive_collect(srv);
        } else if (!srv->pc[i]) {
            int k;
            for (k = 0; k < srv->nl; k++)
                if (srv->lfd[k] == fds[i].fd && (re & POLLIN)) {
                    struct sockaddr_storage ss;
                    socklen_t sl = sizeof ss;
                    int is_unix = getsockname(srv->lfd[k], (struct sockaddr *)&ss, &sl) == 0 && ss.ss_family == AF_UNIX;
                    accept_all(srv, srv->lfd[k], is_unix);
                }
        } else {
            c = srv->pc[i];
            if (c->state == CS_DEAD) continue;
            if (re & (POLLIN | POLLHUP | POLLERR)) read_conn(srv, c);
            if (c->state != CS_DEAD && (re & (POLLERR | POLLNVAL))) c->state = CS_DEAD;
        }
    }
    srv->npc = 0;
    gz_cmds_run(srv);                                   /* commands queued from this thread too */
    now = gz_now_ms(srv);
    for (c = srv->conns; c; c = next) {
        next = c->next;
        if (c->state != CS_DEAD && c->out.off < c->out.len) flush(srv, c);
        if (c->state == CS_BUSY && c->held && now >= c->deadline) {
            /* no outcome within held_ms: the command may still be alive; retry with the same id */
            gz_held_answer(srv, c, 503, NULL, "node_busy", NULL, NULL);
            if (c->out.off < c->out.len) flush(srv, c);
        } else if (c->state != CS_DEAD && c->state != CS_BUSY && c->state != CS_STREAM && now >= c->deadline) {
            c->state = CS_DEAD;                         /* 3.1: slow head, slow body, idle keep-alive */
        }
        if (c->state == CS_DEAD) gz_conn_free(srv, c);
    }
    return 0;
}

int gz_api_server_poll(gz_api_server *srv, int timeout_ms)
{
    int t, r;
    size_t n = gz_api_server_pollfds(srv, srv->pfbuf, gz_api_server_max_fds(srv), &t);
    if (t < 0 || t > timeout_ms) t = timeout_ms;
    r = poll(srv->pfbuf, (nfds_t)n, t);
    if (r < 0 && errno != EINTR) return -1;
    if (r <= 0) {
        size_t i;
        for (i = 0; i < n; i++) srv->pfbuf[i].revents = 0;
    }
    return gz_api_server_dispatch(srv, srv->pfbuf, n);
}

int gz_api_server_run(gz_api_server *srv)
{
    signal(SIGPIPE, SIG_IGN);
    /* the stop is taken as run returns, so the loop can be run again (the tests pause it) */
    while (!atomic_exchange_explicit(&srv->stop, 0, memory_order_relaxed))
        if (gz_api_server_poll(srv, 1000) != 0) return -1;
    return 0;
}

void gz_api_server_stop_listening(gz_api_server *srv)
{
    int i;
    for (i = 0; i < srv->nl; i++)
        if (srv->lfd[i] >= 0) { close(srv->lfd[i]); srv->lfd[i] = -1; }
    srv->nl = 0;
    if (srv->sock_path[0] && !srv->cfg.no_socket && !srv->cfg.no_listen) unlink(srv->sock_path);
    srv->listening_stopped = 1;
}
