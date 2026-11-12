/* SPDX-License-Identifier: MIT */
/* The same-user check (spec/local-api.md 3.4, test 23.2 items 31 and 45,
 * 23.6 T12) with a real second account: run as root, a child process drops
 * to the "nobody" account and connects. Its connection must get 403
 * other_user before it sends a byte, through netlink and through
 * /proc/net/tcp alike; the parent's own connection is served. Without root
 * the test says so and passes (the override tests in test_server.c run
 * everywhere). */
#define _GNU_SOURCE
#include <dirent.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "check.h"
#include "fake_backend.h"

static gz_api_server *g_srv;

static void *run(void *a)
{
    (void)a;
    gz_api_server_run(g_srv);
    return NULL;
}

/* 1 if the answer at accept is 403 other_user, 0 if served, -1 on error */
static int probe(int port, int send_first)
{
    struct sockaddr_in a;
    char buf[2048], req[200];
    ssize_t n, got = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    if (send_first) {
        snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", port);
        if (send(fd, req, strlen(req), MSG_NOSIGNAL) < 0) { }
    }
    for (;;) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 3000) <= 0) break;
        n = recv(fd, buf + got, sizeof buf - 1 - (size_t)got, 0);
        if (n <= 0) break;
        got += n;
    }
    close(fd);
    buf[got] = 0;
    if (strstr(buf, "HTTP/1.1 403") && strstr(buf, "\"code\":\"other_user\"")) return 1;
    if (strstr(buf, "HTTP/1.1 200")) return 0;
    return -1;
}

/* The second account is a child forked before the server starts (so a
 * memory checker sees nothing of the server in it), dropped to "nobody",
 * which probes when told: {port, send_first} in, the result out. */
typedef struct { int port, send_first; } ask;
static int to_child[2], from_child[2];
static pid_t child;

static int nobody_start(void)
{
    if (pipe(to_child) != 0 || pipe(from_child) != 0) return -1;
    child = fork();
    if (child == 0) {
        ask q;
        close(to_child[1]);
        close(from_child[0]);
        if (setgroups(0, NULL) != 0 || setgid(65534) != 0 || setuid(65534) != 0) _exit(10);
        while (read(to_child[0], &q, sizeof q) == (ssize_t)sizeof q) {
            int r = probe(q.port, q.send_first);
            if (write(from_child[1], &r, sizeof r) != (ssize_t)sizeof r) _exit(11);
        }
        _exit(0);
    }
    close(to_child[0]);
    close(from_child[1]);
    return child > 0 ? 0 : -1;
}

/* 0 when the child's connection got 403 other_user at accept */
static int as_nobody(int port, int send_first)
{
    ask q = {port, send_first};
    int r = -1;
    if (write(to_child[1], &q, sizeof q) != (ssize_t)sizeof q) return -1;
    if (read(from_child[0], &r, sizeof r) != (ssize_t)sizeof r) return -1;
    return r == 1 ? 0 : 1;
}

static void nobody_stop(void)
{
    int st;
    close(to_child[1]);
    close(from_child[0]);
    waitpid(child, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static void one_mode(int mode)
{
    gz_api_config cfg;
    gz_fake fake;
    pthread_t th;
    char dir[] = "/tmp/gzpeer-XXXXXX", rt[] = "/tmp/gzpeerrt-XXXXXX";
    const char *err = NULL;
    int port;
    if (!mkdtemp(dir) || !mkdtemp(rt)) { CHECK(0); return; }
    if (nobody_start() != 0) { CHECK(0); return; }
    gz_fake_init(&fake, GZ_FAKE_LOCKED);
    memset(&cfg, 0, sizeof cfg);
    cfg.data_dir = dir;
    cfg.runtime_dir = rt;
    cfg.no_ipv6 = 1;
    cfg.no_socket = 1;
    cfg.peer_mode = mode;
    cfg.backend = &gz_fake_backend;
    cfg.backend_ctx = &fake;
    g_srv = gz_api_server_new(&cfg, &err);
    CHECK(g_srv != NULL);
    if (!g_srv) { printf("  %s\n", err); return; }
    port = gz_api_server_port(g_srv);
    pthread_create(&th, NULL, run, NULL);
    CHECK(probe(port, 1) == 0);                          /* this account: served */
    CHECK(as_nobody(port, 0) == 0);                      /* another: 403 at accept, nothing sent */
    CHECK(as_nobody(port, 1) == 0);                      /* also when it sends first */
    nobody_stop();
    gz_api_server_stop(g_srv);
    pthread_join(th, NULL);
    gz_api_server_free(g_srv);
    gz_fake_free(&fake);
    rmdir(rt);
    {
        char p[200];
        snprintf(p, sizeof p, "%s/attempts.gza", dir);
        unlink(p);
        rmdir(dir);
    }
}

int main(void)
{
    if (geteuid() != 0) {
        printf("SKIP: needs root to make a second account's connection (23.2 item 45); "
               "test_server.c covers the refusal with an expected-uid override\n");
        CHECK(1);
        return check_done();
    }
    one_mode(GZ_API_PEER_NETLINK_ONLY);
    one_mode(GZ_API_PEER_PROC_ONLY);
    one_mode(GZ_API_PEER_AUTO);
    return check_done();
}
