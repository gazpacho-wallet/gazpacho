/* SPDX-License-Identifier: MIT */
/* The server over real loopback sockets, against the fake backend: every
 * check of spec/local-api.md 3 and 5 (Host, Origin, fetch metadata, content
 * type, missing header, sizes, timeouts, the 33rd connection, another user),
 * the session lifecycle of 4, the attempt limits across a restart, request
 * ids (7.4), reserved calls (2), the event stream (10), files behind (4.7) and
 * the local socket (3.2, 4.6). Item numbers are 23.1 and 23.2's. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/sha.h>

#include "check.h"
#include "fake_backend.h"

int gz_api_route_count(void);
int gz_attempts_encode(const char *network, uint64_t counter, uint32_t wrong, uint64_t last, uint64_t until,
                       uint8_t out[85]);
int gz_attempts_decode(const char *network, const uint8_t in[85], uint64_t *counter, uint32_t *wrong,
                       uint64_t *last, uint64_t *until);
int gz_api_route_info(int i, int *method, const char **pattern, const char **release);

static _Atomic long long clock_off;
static pthread_mutex_t log_mu = PTHREAD_MUTEX_INITIALIZER;
static char log_text[1 << 16];
static size_t log_len;

/* A frozen clock (clock_freeze) moves only by clock_off, so checks of the
 * one-second delays do not depend on how fast the test runs (valgrind). */
static _Atomic int clock_frozen;
static _Atomic long long clock_frozen_at;

static int64_t real_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int64_t test_now(void *ctx)
{
    (void)ctx;
    return (atomic_load(&clock_frozen) ? atomic_load(&clock_frozen_at) : real_now()) + atomic_load(&clock_off);
}

static void clock_freeze(int on)
{
    if (on) atomic_store(&clock_frozen_at, real_now());
    atomic_store(&clock_frozen, on);
}

static void test_log(void *ctx, const char *line)
{
    size_t n = strlen(line);
    (void)ctx;
    pthread_mutex_lock(&log_mu);
    if (log_len + n + 2 < sizeof log_text) {
        memcpy(log_text + log_len, line, n);
        log_len += n;
        log_text[log_len++] = '\n';
        log_text[log_len] = 0;
    }
    pthread_mutex_unlock(&log_mu);
}

static void sleep_ms(int ms)
{
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* ---- a server in a thread ---------------------------------------------------------- */
typedef struct {
    gz_api_server *srv;
    gz_fake fake;
    pthread_t th;
    char dir[64], rt[64];
    int port;
    gz_api_config cfg;
} fixture;

static void *run(void *a)
{
    gz_api_server_run(((fixture *)a)->srv);
    return NULL;
}

static void rm_rf(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    char p[600];
    while (d && (e = readdir(d))) {
        struct stat st;
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        if (lstat(p, &st) == 0 && S_ISDIR(st.st_mode)) rm_rf(p);
        else unlink(p);
    }
    if (d) closedir(d);
    rmdir(dir);
}

static void fx_prepare(fixture *x, int scenario)
{
    memset(x, 0, sizeof *x);
    snprintf(x->dir, sizeof x->dir, "/tmp/gzapi-XXXXXX");
    snprintf(x->rt, sizeof x->rt, "/tmp/gzapirt-XXXXXX");
    if (!mkdtemp(x->dir) || !mkdtemp(x->rt)) abort();
    gz_fake_init(&x->fake, scenario);
    x->cfg.data_dir = x->dir;
    x->cfg.runtime_dir = x->rt;
    x->cfg.port = 0;
    x->cfg.no_ipv6 = 1;
    x->cfg.backend = &gz_fake_backend;
    x->cfg.backend_ctx = &x->fake;
    x->cfg.now_ms = test_now;
    x->cfg.log = test_log;
    x->cfg.limits.head_ms = 3000;
    x->cfg.limits.body_ms = 3000;
}

static int fx_go(fixture *x)
{
    const char *err = NULL;
    x->srv = gz_api_server_new(&x->cfg, &err);
    if (!x->srv) { printf("server: %s\n", err ? err : "?"); return -1; }
    x->fake.srv = x->srv;
    x->port = gz_api_server_port(x->srv);
    pthread_create(&x->th, NULL, run, x);
    return 0;
}

static void fx_halt(fixture *x)
{
    if (!x->srv) return;
    gz_api_server_stop(x->srv);
    pthread_join(x->th, NULL);
    gz_api_server_free(x->srv);
    x->srv = NULL;
}

static void fx_stop(fixture *x)
{
    fx_halt(x);
    gz_fake_free(&x->fake);
    rm_rf(x->dir);
    rm_rf(x->rt);
}

/* Reads of the fake's counters from the test thread, under its mutex (review B5). */
static int64_t fake_tmp;
static void fake_lock(fixture *x) { pthread_mutex_lock(&x->fake.mu); }
static void fake_unlock(fixture *x) { pthread_mutex_unlock(&x->fake.mu); }
#define FAKE_READ(x, expr) (fake_lock(x), fake_tmp = (int64_t)(expr), fake_unlock(x), fake_tmp)

/* The loop thread's functions (api.h: counters, first-run codes) are called
 * with the loop stopped, then the loop runs again (review B5). */
static void fx_pause(fixture *x)
{
    gz_api_server_stop(x->srv);
    pthread_join(x->th, NULL);
}

static void fx_resume(fixture *x) { pthread_create(&x->th, NULL, run, x); }

static void fx_counters(fixture *x, gz_api_counters *c)
{
    fx_pause(x);
    gz_api_server_counters(x->srv, c);
    fx_resume(x);
}

static int fx_first_run_code(fixture *x, char code[12])
{
    int r;
    fx_pause(x);
    r = gz_api_first_run_code(x->srv, code);
    fx_resume(x);
    return r;
}

/* ---- a raw HTTP client -------------------------------------------------------------- */
typedef struct {
    int status;
    char head[16384];
    char *body;
    size_t blen;
    int closed_without_answer;
} resp;

static void resp_free(resp *r) { free(r->body); memset(r, 0, sizeof *r); }

static int tcp_connect(int port)
{
    struct sockaddr_in a;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    return fd;
}

static int unix_connect(const char *path)
{
    struct sockaddr_un a;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", path);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    return fd;
}

/* Reads one answer (or until close, timeout_ms). */
static void read_answer(int fd, resp *r, int timeout_ms)
{
    size_t cap = 1 << 16, len = 0, hl = 0;
    char *buf = malloc(cap);
    long clen = -1;
    memset(r, 0, sizeof *r);
    for (;;) {
        struct pollfd p = {fd, POLLIN, 0};
        ssize_t n;
        if (poll(&p, 1, timeout_ms) <= 0) break;
        if (len + 4096 > cap) { cap *= 2; buf = realloc(buf, cap); }
        n = recv(fd, buf + len, cap - len - 1, 0);
        if (n <= 0) break;
        len += (size_t)n;
        buf[len] = 0;
        if (!hl) {
            char *e = strstr(buf, "\r\n\r\n");
            if (e && strncmp(buf, "HTTP/1.1 100", 12) == 0) {   /* skip 100 Continue */
                memmove(buf, e + 4, len - (size_t)(e + 4 - buf));
                len -= (size_t)(e + 4 - buf);
                buf[len] = 0;
                e = strstr(buf, "\r\n\r\n");
            }
            if (e) {
                char *cl;
                hl = (size_t)(e - buf) + 4;
                cl = strcasestr(buf, "\r\ncontent-length:");
                if (cl && cl < e) clen = strtol(cl + 17, NULL, 10);
            }
        }
        if (hl && clen >= 0 && len >= hl + (size_t)clen) break;
    }
    if (!hl) {
        r->closed_without_answer = 1;
        free(buf);
        return;
    }
    r->status = atoi(buf + 9);
    memcpy(r->head, buf, hl < sizeof r->head ? hl : sizeof r->head - 1);
    r->blen = len - hl;
    r->body = malloc(r->blen + 1);
    memcpy(r->body, buf + hl, r->blen);
    r->body[r->blen] = 0;
    free(buf);
}

static void raw(int port, const char *data, size_t n, resp *r)
{
    int fd = tcp_connect(port);
    if (fd < 0) { memset(r, 0, sizeof *r); r->closed_without_answer = 1; return; }
    if (send(fd, data, n, MSG_NOSIGNAL) < 0) { }
    read_answer(fd, r, 5000);
    close(fd);
}

static const char *hdr(const resp *r, const char *name)
{
    static char v[512];
    char pat[80];
    const char *p, *e;
    snprintf(pat, sizeof pat, "\r\n%s:", name);
    p = strcasestr(r->head, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p == ' ') p++;
    e = strstr(p, "\r\n");
    snprintf(v, sizeof v, "%.*s", (int)(e ? e - p : (long)strlen(p)), p);
    return v;
}

/* The interface's own request: Host, Origin, fetch metadata, the session. */
static char g_session[64];

static void api(fixture *x, resp *r, const char *method, const char *path, const char *body, const char *extra)
{
    char req[70000];
    int n = snprintf(req, sizeof req,
                     "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n"
                     "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n"
                     "%s%s%s%sConnection: close\r\n",
                     method, path, x->port, x->port, g_session[0] ? "X-Gazpacho-Session: " : "", g_session,
                     g_session[0] ? "\r\n" : "", extra ? extra : "");
    if (body) n += snprintf(req + n, sizeof req - (size_t)n, "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s",
                            strlen(body), body);
    else n += snprintf(req + n, sizeof req - (size_t)n, "\r\n");
    raw(x->port, req, (size_t)n, r);
}

static const char *jfield(const resp *r, const char *k)
{
    static char v[2048];
    gz_json_doc d;
    const gz_json *f;
    v[0] = 0;
    if (!r->body || gz_json_parse((const uint8_t *)r->body, r->blen, &d) != 0) return NULL;
    f = gz_json_get(d.root, k);
    if (f && f->type == GZ_JSON_STR) snprintf(v, sizeof v, "%s", f->s);
    else if (f && f->type == GZ_JSON_INT) snprintf(v, sizeof v, "%lld", (long long)f->i);
    else if (f && f->type == GZ_JSON_BOOL) snprintf(v, sizeof v, "%s", f->i ? "true" : "false");
    else if (f && f->type == GZ_JSON_NULL) snprintf(v, sizeof v, "null");
    else if (f) snprintf(v, sizeof v, "<container>");
    gz_json_free(&d);
    return f ? v : NULL;
}

static int is_code(const resp *r, int status, const char *code)
{
    const char *c = jfield(r, "code");
    int ok = r->status == status && c && strcmp(c, code) == 0;
    if (!ok) printf("  expected %d %s, got %d %s\n", status, code, r->status, r->body ? r->body : "(none)");
    return ok;
}

static int expect(fixture *x, const char *method, const char *path, const char *body, int status, const char *code)
{
    resp r;
    int ok;
    api(x, &r, method, path, body, NULL);
    ok = code ? is_code(&r, status, code) : r.status == status;
    if (!ok && !code) printf("  %s %s: expected %d, got %d %s\n", method, path, status, r.status, r.body ? r.body : "");
    resp_free(&r);
    return ok;
}

/* Every answer has the three headers of 5.4, never CORS (23.2 item 9). */
static int headers_ok(const resp *r)
{
    const char *v;
    int ok = 1;
    if (!(v = hdr(r, "Cross-Origin-Resource-Policy")) || strcmp(v, "same-origin") != 0) ok = 0;
    if (!(v = hdr(r, "X-Content-Type-Options")) || strcmp(v, "nosniff") != 0) ok = 0;
    if (!(v = hdr(r, "Referrer-Policy")) || strcmp(v, "same-origin") != 0) ok = 0;
    if (!hdr(r, "Content-Security-Policy")) ok = 0;
    if (strcasestr(r->head, "access-control-")) ok = 0;
    if (strcasestr(r->head, "set-cookie")) ok = 0;
    return ok;
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    char *b;
    long n;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    b = calloc(1, (size_t)n + 1);
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { }
    fclose(f);
    return b;
}

/* ---- first run, create, sign in -------------------------------------------------------- */
static void start_token_from_file(fixture *x, char tok[64])
{
    char path[200], *f, *p;
    snprintf(path, sizeof path, "%s/first-run.html", x->dir);
    f = read_file(path);
    tok[0] = 0;
    if (!f) return;
    p = strstr(f, "#start=");
    if (p) snprintf(tok, 64, "%.43s", p + 7);
    free(f);
}

static void sign_in(fixture *x, const char *pass)
{
    char body[200];
    resp r;
    g_session[0] = 0;
    snprintf(body, sizeof body, "{\"passphrase\":\"%s\"}", pass);
    api(x, &r, "POST", "/api/v1/session", body, NULL);
    if (r.status != 200) printf("  sign-in: %d %s\n", r.status, r.body ? r.body : "");
    snprintf(g_session, sizeof g_session, "%s", jfield(&r, "session") ? jfield(&r, "session") : "");
    resp_free(&r);
}

#define PASS "correct horse battery staple, test"

/* ---- 5.1 Host, 5.2 Origin and fetch metadata, 5.3 type, 3.1 limits ------------------------ */
static void test_walls(void)
{
    fixture x;
    resp r;
    char req[40000];
    int n, i;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    if (fx_go(&x)) { CHECK(0); return; }
    /* 23.2 items 1, 2: Host */
    {
        const char *hosts[] = {"Host: rebind.attacker.example:%d\r\n", "", "Host: 127.0.0.1:%d\r\nHost: 127.0.0.1:%d\r\n",
                               "Host: 127.0.0.1\r\n", "Host: 127.0.0.1:1%d\r\n", "Host: 0.0.0.0:%d\r\n",
                               "Host: LOCALHOST:%d\r\n", "Host: localhost\r\n"};
        for (i = 0; i < (int)(sizeof hosts / sizeof hosts[0]); i++) {
            char h[200];
            snprintf(h, sizeof h, hosts[i], x.port, x.port);
            n = snprintf(req, sizeof req, "GET / HTTP/1.1\r\n%sConnection: close\r\n\r\n", h);
            raw(x.port, req, (size_t)n, &r);
            CHECK(r.status == 421 && r.blen == 0 && headers_ok(&r));
            resp_free(&r);
            n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\n%sConnection: close\r\n\r\n", h);
            raw(x.port, req, (size_t)n, &r);
            CHECK(r.status == 421);
            resp_free(&r);
        }
        n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: localhost:%d\r\nConnection: close\r\n\r\n", x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(r.status == 200 && headers_ok(&r));
        CHECK(jfield(&r, "run_id") && strlen(jfield(&r, "run_id")) == 8);
        resp_free(&r);
        n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: [::1]:%d\r\nConnection: close\r\n\r\n", x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(r.status == 200);
        resp_free(&r);
    }
    /* 23.2 items 3-7: Origin */
    {
        const char *origins[] = {"", "Origin: null\r\n", "Origin: http://127.0.0.1:8080\r\n", "Origin: https://127.0.0.1:%d\r\n",
                                 "Origin: http://evil.example\r\n", "Origin: http://127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n",
                                 "Origin: file://127.0.0.1:%d\r\n", "Origin: http://127.0.0.1:%d/\r\n"};
        for (i = 0; i < (int)(sizeof origins / sizeof origins[0]); i++) {
            char o[200];
            snprintf(o, sizeof o, origins[i], x.port, x.port);
            n = snprintf(req, sizeof req,
                         "POST /api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n%sContent-Type: application/json\r\n"
                         "Content-Length: 16\r\nConnection: close\r\n\r\n{\"passphrase\":1}", x.port, o);
            raw(x.port, req, (size_t)n, &r);
            CHECK(is_code(&r, 403, "forbidden_origin") && headers_ok(&r));
            resp_free(&r);
        }
        /* GET with a foreign Origin follows the same rule */
        n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:8080\r\n"
                                      "Connection: close\r\n\r\n", x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(is_code(&r, 403, "forbidden_origin"));
        resp_free(&r);
    }
    /* fetch metadata: items 29, 30 and 11 */
    {
        const char *sites[] = {"cross-site", "same-site", "none"};
        for (i = 0; i < 3; i++) {
            n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nSec-Fetch-Site: %s\r\n"
                                          "Connection: close\r\n\r\n", x.port, sites[i]);
            raw(x.port, req, (size_t)n, &r);
            CHECK(is_code(&r, 403, "forbidden_origin"));
            resp_free(&r);
        }
        n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nSec-Fetch-Site: same-origin\r\n"
                                      "Sec-Fetch-Dest: image\r\nConnection: close\r\n\r\n", x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(is_code(&r, 403, "forbidden_origin"));
        resp_free(&r);
        /* static: none works; cross-site is a plain page, not a bare 403 (N15); a wallet exists */
        n = snprintf(req, sizeof req, "GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nSec-Fetch-Site: none\r\n"
                                      "Connection: close\r\n\r\n", x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(r.status == 200 && strstr(r.body, "<h1>Gazpacho</h1>") && headers_ok(&r));
        CHECK(hdr(&r, "X-Frame-Options") && strcmp(hdr(&r, "X-Frame-Options"), "DENY") == 0);
        CHECK(hdr(&r, "Cross-Origin-Opener-Policy") && hdr(&r, "Cross-Origin-Embedder-Policy"));
        CHECK(strstr(hdr(&r, "Content-Security-Policy"), "trusted-types 'none'") != NULL);
        CHECK(strcmp(hdr(&r, "Cache-Control"), "no-store") == 0);
        resp_free(&r);
        n = snprintf(req, sizeof req, "GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nSec-Fetch-Site: cross-site\r\n"
                                      "Sec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\nConnection: close\r\n\r\n", x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(r.status == 403 && strstr(r.body, "Open Gazpacho by typing its address yourself") && headers_ok(&r));
        resp_free(&r);
        /* a static file never answers outside its exact path (item 23) */
        {
            const char *paths[] = {"/../journal.gzj", "/%2e%2e/", "/..%5c", "/index.html/", "/%c0%ae%c0%ae/", "//index.html"};
            for (i = 0; i < 6; i++) {
                n = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", paths[i], x.port);
                raw(x.port, req, (size_t)n, &r);
                CHECK(r.status == 404 || r.status == 400);
                resp_free(&r);
            }
        }
    }
    /* 5.3: JSON only, before the body is read; OPTIONS; no CORS (items 3, 5, 9) */
    {
        const char *types[] = {"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x",
                               "application/json; charset=latin-1", "application/jsonx"};
        for (i = 0; i < 5; i++) {
            n = snprintf(req, sizeof req,
                         "POST /api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n"
                         "Content-Type: %s\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}", x.port, x.port, types[i]);
            raw(x.port, req, (size_t)n, &r);
            CHECK(is_code(&r, 415, "bad_content_type"));
            resp_free(&r);
        }
        n = snprintf(req, sizeof req, "OPTIONS /api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://evil.example\r\n"
                                      "Access-Control-Request-Method: POST\r\nConnection: close\r\n\r\n", x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(is_code(&r, 405, "no_cors") && headers_ok(&r));
        resp_free(&r);
    }
    /* 3.1: request smuggling, upgrades (items 13, 24) */
    {
        n = snprintf(req, sizeof req, "POST /api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n"
                                      "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                                      "2\r\n{}\r\n0\r\n\r\n", x.port, x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(is_code(&r, 411, "length_required"));
        resp_free(&r);
        n = snprintf(req, sizeof req, "POST /api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n"
                                      "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n"
                                      "Connection: close\r\n\r\n{}", x.port, x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(r.status == 400);
        resp_free(&r);
        n = snprintf(req, sizeof req, "GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: Upgrade\r\n"
                                      "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                     x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(is_code(&r, 400, "no_upgrade"));
        resp_free(&r);
        n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.0\r\nHost: 127.0.0.1:%d\r\n\r\n", x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(r.status == 400);
        resp_free(&r);
        n = snprintf(req, sizeof req, "GET http://127.0.0.1:%d/api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", x.port, x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(r.status == 400);
        resp_free(&r);
    }
    /* 3.1 sizes (item 25): 70 KiB body, 20 KiB of headers, 65 header lines; 64 lines pass */
    {
        char *big = malloc(80000);
        memset(big, 'a', 72000);
        big[72000] = 0;
        n = snprintf(req, sizeof req, "POST /api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n"
                                      "Content-Type: application/json\r\nContent-Length: 71680\r\nConnection: close\r\n\r\n",
                     x.port, x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(is_code(&r, 413, "too_large"));
        resp_free(&r);
        n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Pad: %.20480s\r\n\r\n", x.port, big);
        raw(x.port, req, (size_t)n, &r);
        CHECK(is_code(&r, 431, "headers_too_large"));
        resp_free(&r);
        for (i = 0; i < 2; i++) {
            int lines = i ? 65 : 64, k;
            n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n", x.port);
            for (k = 2; k < lines; k++) n += snprintf(req + n, sizeof req - (size_t)n, "X-L%d: v\r\n", k);
            n += snprintf(req + n, sizeof req - (size_t)n, "\r\n");
            raw(x.port, req, (size_t)n, &r);
            if (i) CHECK(is_code(&r, 431, "headers_too_large"));
            else CHECK(r.status == 200);
            resp_free(&r);
        }
        free(big);
    }
    /* secrets in a URL (item 22): refused, and the value is in no log */
    {
        const char *qs[] = {"token", "code", "phrase", "session", "Password", "words"};
        for (i = 0; i < 6; i++) {
            char path[200];
            snprintf(path, sizeof path, "/api/v1/lobbies?%s=SECRETVALUE%d", qs[i], i);
            CHECK(expect(&x, "GET", path, NULL, 400, "secret_in_url"));
        }
        pthread_mutex_lock(&log_mu);
        CHECK(strstr(log_text, "SECRETVALUE") == NULL);
        pthread_mutex_unlock(&log_mu);
        CHECK(expect(&x, "GET", "/api/v1/version?x=1", NULL, 400, "unknown_field"));
    }
    /* two session headers: signed out, even on a call that needs no session */
    {
        resp r2;
        g_session[0] = 0;
        api(&x, &r2, "GET", "/api/v1/version", NULL, "X-Gazpacho-Session: AAAA\r\nX-Gazpacho-Session: BBBB\r\n");
        CHECK(is_code(&r2, 401, "not_signed_in"));
        resp_free(&r2);
    }
    /* missing or wrong session: locked wallet answers 423; the four open calls answer */
    {
        g_session[0] = 0;
        CHECK(expect(&x, "GET", "/api/v1/lobbies", NULL, 423, "wallet_locked"));
        CHECK(expect(&x, "GET", "/api/v1/session", NULL, 200, NULL));
        CHECK(expect(&x, "GET", "/api/v1/version", NULL, 200, NULL));
        CHECK(expect(&x, "GET", "/api/v1/status", NULL, 200, NULL));
        CHECK(expect(&x, "GET", "/api/v1/nothing", NULL, 404, "not_found"));
        CHECK(expect(&x, "DELETE", "/api/v1/version", NULL, 405, "method_not_allowed"));
    }
    fx_stop(&x);
}

/* 3.1: slow headers and bodies are closed; the 33rd connection is refused (item 25). */
static void test_timeouts(void)
{
    fixture x;
    int fds[33], i, fd, closed;
    resp r;
    char req[300];
    int64_t t0;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    x.cfg.limits.head_ms = 400;
    x.cfg.limits.body_ms = 400;
    x.cfg.limits.idle_ms = 600;
    x.cfg.limits.max_head_bytes = 4096;
    if (fx_go(&x)) { CHECK(0); return; }
    /* the head limit holds even when the whole head arrives in one read */
    {
        char big[6000], pad[5001];
        int len;
        memset(pad, 'p', 5000);
        pad[5000] = 0;
        len = snprintf(big, sizeof big, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Pad: %.4900s\r\n"
                                        "Connection: close\r\n\r\n", x.port, pad);
        raw(x.port, big, (size_t)len, &r);
        CHECK(is_code(&r, 431, "headers_too_large"));
        resp_free(&r);
        len = snprintf(big, sizeof big, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Pad: %.3000s\r\n"
                                        "Connection: close\r\n\r\n", x.port, pad);
        raw(x.port, big, (size_t)len, &r);
        CHECK(r.status == 200);
        resp_free(&r);
    }
    /* one byte at a time: closed at the head limit */
    fd = tcp_connect(x.port);
    snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", x.port);
    t0 = test_now(NULL);
    closed = 0;
    for (i = 0; req[i] && !closed; i++) {
        char b;
        if (send(fd, req + i, 1, MSG_NOSIGNAL) < 0) closed = 1;
        sleep_ms(60);
        if (recv(fd, &b, 1, MSG_DONTWAIT) == 0) closed = 1;
    }
    CHECK(closed);
    CHECK(test_now(NULL) - t0 >= 350 && test_now(NULL) - t0 < 3000);
    close(fd);
    /* a body that never arrives */
    fd = tcp_connect(x.port);
    snprintf(req, sizeof req, "POST /api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n"
                              "Content-Type: application/json\r\nContent-Length: 50\r\n\r\n{\"pa", x.port, x.port);
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    read_answer(fd, &r, 3000);
    CHECK(r.closed_without_answer);
    resp_free(&r);
    close(fd);
    /* an idle keep-alive connection is closed */
    fd = tcp_connect(x.port);
    read_answer(fd, &r, 3000);
    CHECK(r.closed_without_answer);
    resp_free(&r);
    close(fd);
    /* 32 connections, then the 33rd is closed at once */
    for (i = 0; i < 32; i++) fds[i] = tcp_connect(x.port);
    sleep_ms(100);
    fds[32] = tcp_connect(x.port);
    read_answer(fds[32], &r, 300);
    CHECK(r.closed_without_answer);
    resp_free(&r);
    {
        gz_api_counters c;
        fx_counters(&x, &c);
        CHECK(c.connections_open <= 32);
    }
    for (i = 0; i < 33; i++) close(fds[i]);
    fx_stop(&x);
}

/* 3.4: another account is refused before a byte is read (item 31). */
static void test_other_user(void)
{
    fixture x;
    resp r;
    int fd;
    fx_prepare(&x, GZ_FAKE_FIRST_RUN);
    x.cfg.override_uid = 1;
    x.cfg.expect_uid = (int64_t)getuid() + 1;          /* as if this test were another account */
    if (fx_go(&x)) { CHECK(0); return; }
    fd = tcp_connect(x.port);
    read_answer(fd, &r, 3000);                           /* nothing sent: the answer comes at accept */
    CHECK(is_code(&r, 403, "other_user") && headers_ok(&r));
    resp_free(&r);
    close(fd);
    fd = unix_connect(gz_api_server_socket_path(x.srv));
    CHECK(fd >= 0);
    {
        static const char q[] = "GET /api/v1/version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        if (send(fd, q, sizeof q - 1, MSG_NOSIGNAL) < 0) { }
    }
    read_answer(fd, &r, 3000);
    CHECK(r.closed_without_answer);                      /* the local socket: closed at accept, never answered */
    resp_free(&r);
    close(fd);
    {
        gz_api_counters c;
        fx_counters(&x, &c);
        CHECK(c.handler_calls == 0);
    }
    fx_stop(&x);
    /* the netlink family hidden: /proc/net/tcp gives the same answer */
    fx_prepare(&x, GZ_FAKE_FIRST_RUN);
    x.cfg.peer_mode = GZ_API_PEER_PROC_ONLY;
    if (fx_go(&x)) { CHECK(0); return; }
    g_session[0] = 0;
    CHECK(expect(&x, "GET", "/api/v1/version", NULL, 200, NULL));
    fx_halt(&x);
    x.cfg.override_uid = 1;
    x.cfg.expect_uid = (int64_t)getuid() + 1;
    if (fx_go(&x)) { CHECK(0); return; }
    fd = tcp_connect(x.port);
    read_answer(fd, &r, 3000);
    CHECK(is_code(&r, 403, "other_user"));
    resp_free(&r);
    close(fd);
    fx_stop(&x);
    /* neither available (the test switch): served, and status says unavailable */
    fx_prepare(&x, GZ_FAKE_LOCKED);
    x.cfg.peer_mode = GZ_API_PEER_UNAVAILABLE;
    x.cfg.override_uid = 1;
    x.cfg.expect_uid = (int64_t)getuid() + 1;
    if (fx_go(&x)) { CHECK(0); return; }
    g_session[0] = 0;
    api(&x, &r, "GET", "/api/v1/status", NULL, NULL);
    CHECK(r.status == 200 && strstr(r.body, "\"peer_check\":\"unavailable\"") && strstr(r.body, "\"dates_hidden\":true"));
    resp_free(&r);
    fx_stop(&x);
}

/* 4.3, 4.5, 4.8, 4.9: first run to normal session, and every way a session ends. */
static void test_sessions(void)
{
    fixture x;
    resp r;
    char tok[64], body[600], first[64], path[200];
    int i;
    struct stat st;
    fx_prepare(&x, GZ_FAKE_FIRST_RUN);
    if (fx_go(&x)) { CHECK(0); return; }
    /* the redirect file: 0600 in a 0700 folder; the token only in its fragment */
    snprintf(path, sizeof path, "%s/first-run.html", x.dir);
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    CHECK(stat(x.dir, &st) == 0 && (st.st_mode & 0777) == 0700);
    start_token_from_file(&x, tok);
    CHECK(strlen(tok) == 43);
    g_session[0] = 0;
    api(&x, &r, "GET", "/api/v1/session", NULL, NULL);
    CHECK(r.status == 200 && strcmp(jfield(&r, "wallet"), "none") == 0 && strcmp(jfield(&r, "signed_in"), "false") == 0);
    resp_free(&r);
    /* a navigation from the redirect file: cross-site, while no wallet exists */
    {
        char req[400];
        int n = snprintf(req, sizeof req, "GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nSec-Fetch-Site: cross-site\r\n"
                                          "Sec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\nConnection: close\r\n\r\n", x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(r.status == 200);
        resp_free(&r);
    }
    /* junk tokens count nothing (R5); the real one then works once */
    for (i = 0; i < 5; i++) {
        snprintf(body, sizeof body, "{\"start_token\":\"%s%d\"}", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", i);
        CHECK(expect(&x, "POST", "/api/v1/session/start", body, 401, "bad_code"));
    }
    snprintf(body, sizeof body, "{\"start_token\":\"%s\"}", tok);
    api(&x, &r, "POST", "/api/v1/session/start", body, NULL);
    CHECK(r.status == 200 && strcmp(jfield(&r, "kind"), "setup") == 0);
    snprintf(g_session, sizeof g_session, "%s", jfield(&r, "session"));
    resp_free(&r);
    CHECK(access(path, F_OK) != 0);                      /* the file goes at the first presentation */
    api(&x, &r, "POST", "/api/v1/session/start", body, NULL);
    CHECK(is_code(&r, 409, "token_used") && strstr(r.body, "used_at"));
    resp_free(&r);
    /* the setup session's calls only (N6) */
    CHECK(expect(&x, "GET", "/api/v1/lobbies", NULL, 403, "not_setup_call"));
    CHECK(expect(&x, "GET", "/api/v1/wallet/setup", NULL, 200, NULL));
    CHECK(expect(&x, "GET", "/api/v1/status", NULL, 200, NULL));
    /* create: passphrases differ, weak, confirm; then the words, once */
    CHECK(expect(&x, "POST", "/api/v1/wallet/create",
                 "{\"confirm\":\"create_wallet\",\"passphrase\":\"" PASS "\",\"confirm_passphrase\":\"other\"}", 400,
                 "passphrases_differ"));
    api(&x, &r, "POST", "/api/v1/wallet/create", "{\"confirm\":\"create_wallet\",\"passphrase\":\"short\",\"confirm_passphrase\":\"short\"}", NULL);
    CHECK(is_code(&r, 400, "weak_passphrase") && strstr(r.body, "\"reason\":\"too_short\"") && strstr(r.body, "\"minimum\":15"));
    resp_free(&r);
    CHECK(expect(&x, "POST", "/api/v1/wallet/create",
                 "{\"confirm\":\"create\",\"passphrase\":\"" PASS "\",\"confirm_passphrase\":\"" PASS "\"}", 409, "confirm_mismatch"));
    api(&x, &r, "POST", "/api/v1/wallet/create",
        "{\"confirm\":\"create_wallet\",\"passphrase\":\"" PASS "\",\"confirm_passphrase\":\"" PASS "\"}", NULL);
    CHECK(r.status == 200 && strstr(r.body, "\"words\":[\"abandon\"") && strstr(r.body, "\"shown_until\":\"this_answer\""));
    CHECK(strcmp(hdr(&r, "Cache-Control"), "no-store") == 0);
    resp_free(&r);
    CHECK(expect(&x, "POST", "/api/v1/wallet/create",
                 "{\"confirm\":\"create_wallet\",\"passphrase\":\"" PASS "\",\"confirm_passphrase\":\"" PASS "\"}", 403,
                 "not_setup_session"));
    /* the session is normal now, its fresh window open (4.3) */
    api(&x, &r, "GET", "/api/v1/session", NULL, NULL);
    CHECK(strcmp(jfield(&r, "kind"), "normal") == 0 && strcmp(jfield(&r, "fresh_until_at"), "null") != 0);
    resp_free(&r);
    /* no start token or code is ever accepted again */
    {
        char old[64];
        snprintf(old, sizeof old, "%s", g_session);
        g_session[0] = 0;
        CHECK(expect(&x, "POST", "/api/v1/session/start", "{\"code\":\"ABCDE-FGHJK\"}", 409, "wallet_exists"));
        snprintf(g_session, sizeof g_session, "%s", old);
    }
    /* kind A: reveal needs the passphrase even inside the window (4.8) */
    CHECK(expect(&x, "POST", "/api/v1/wallet/phrase/reveal", "{\"confirm\":\"show_words\"}", 400, "missing_field"));
    CHECK(expect(&x, "POST", "/api/v1/wallet/phrase/reveal", "{\"confirm\":\"show\",\"passphrase\":\"" PASS "\"}", 409,
                 "confirm_mismatch"));
    api(&x, &r, "POST", "/api/v1/wallet/phrase/reveal", "{\"confirm\":\"show_words\",\"passphrase\":\"" PASS "\"}", NULL);
    CHECK(r.status == 200 && strstr(r.body, "\"art\""));
    resp_free(&r);
    /* the words check: positions only; the passphrase; one answer per check_id (12.3, item 35) */
    {
        char check_id[64], words[200];
        gz_json_doc d;
        const gz_json *pos;
        int p[3] = {0, 0, 0}, k = 0;
        api(&x, &r, "POST", "/api/v1/wallet/phrase/check-start", "{}", NULL);
        CHECK(r.status == 200 && strstr(r.body, "\"checks_left_today\":3"));
        snprintf(check_id, sizeof check_id, "%s", jfield(&r, "check_id"));
        if (gz_json_parse((const uint8_t *)r.body, r.blen, &d) == 0) {
            for (pos = gz_json_get(d.root, "positions")->child; pos && k < 3; pos = pos->next) p[k++] = (int)pos->i;
            gz_json_free(&d);
        }
        resp_free(&r);
        CHECK(p[0] >= 1 && p[0] < p[1] && p[1] < p[2] && p[2] <= 24);
        snprintf(body, sizeof body, "{\"check_id\":\"%s\",\"passphrase\":\"wrong passphrase here\",\"words\":[\"a\",\"b\",\"c\"]}", check_id);
        CHECK(expect(&x, "POST", "/api/v1/wallet/phrase/check", body, 401, "wrong_passphrase"));
        atomic_fetch_add(&clock_off, 2000);              /* past the one-second delay */
        snprintf(words, sizeof words, "\"%s\",\"%s\",\"%s\"", p[0] == 24 ? "art" : "abandon", p[1] == 24 ? "art" : "abandon",
                 p[2] == 24 ? "art" : "abandon");
        snprintf(body, sizeof body, "{\"check_id\":\"%s\",\"passphrase\":\"" PASS "\",\"words\":[%s]}", check_id, words);
        api(&x, &r, "POST", "/api/v1/wallet/phrase/check", body, NULL);
        CHECK(r.status == 200 && strcmp(jfield(&r, "ok"), "true") == 0 && jfield(&r, "checked_at"));
        resp_free(&r);
        CHECK(expect(&x, "POST", "/api/v1/wallet/phrase/check", body, 400, "bad_value"));   /* spent */
        /* a failed check: ok false, never which position, and the session ends (4.9) */
        api(&x, &r, "POST", "/api/v1/wallet/phrase/check-start", "{}", NULL);
        snprintf(check_id, sizeof check_id, "%s", jfield(&r, "check_id"));
        resp_free(&r);
        snprintf(body, sizeof body, "{\"check_id\":\"%s\",\"passphrase\":\"" PASS "\",\"words\":[\"zoo\",\"zoo\",\"zoo\"]}", check_id);
        api(&x, &r, "POST", "/api/v1/wallet/phrase/check", body, NULL);
        CHECK(r.status == 200 && strcmp(r.body, "{\"ok\":false}") == 0);
        resp_free(&r);
        CHECK(expect(&x, "GET", "/api/v1/conditions", NULL, 401, "not_signed_in"));
    }
    /* sign in again; GET /session; DELETE ends it with Clear-Site-Data */
    sign_in(&x, PASS);
    CHECK(strlen(g_session) == 43);
    CHECK(expect(&x, "POST", "/api/v1/wallet/finish-setup", "{\"preset\":\"everyday\",\"find\":\"browse\"}", 200, NULL));
    CHECK(expect(&x, "POST", "/api/v1/wallet/finish-setup", "{\"preset\":\"everyday\",\"find\":\"join_for_me\"}", 400, "bad_value"));
    api(&x, &r, "DELETE", "/api/v1/session", NULL, NULL);
    CHECK(r.status == 204 && r.blen == 0 && hdr(&r, "Clear-Site-Data") && headers_ok(&r));
    resp_free(&r);
    CHECK(expect(&x, "GET", "/api/v1/conditions", NULL, 401, "not_signed_in"));
    /* bound to its Host (4.2): a token from 127.0.0.1 is refused under localhost */
    sign_in(&x, PASS);
    {
        char req[600];
        int n = snprintf(req, sizeof req, "GET /api/v1/conditions HTTP/1.1\r\nHost: localhost:%d\r\nX-Gazpacho-Session: %s\r\n"
                                          "Connection: close\r\n\r\n", x.port, g_session);
        raw(x.port, req, (size_t)n, &r);
        CHECK(is_code(&r, 401, "not_signed_in"));
        resp_free(&r);
    }
    /* a Cookie grants nothing (item 8) */
    {
        char req[600];
        int n = snprintf(req, sizeof req, "GET /api/v1/conditions HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nCookie: gz_session_%d=%s\r\n"
                                          "Connection: close\r\n\r\n", x.port, x.port, g_session);
        raw(x.port, req, (size_t)n, &r);
        CHECK(is_code(&r, 401, "not_signed_in"));
        resp_free(&r);
    }
    /* a ninth sign-in ends the session unused longest (item 47) */
    snprintf(first, sizeof first, "%s", g_session);
    for (i = 0; i < 8; i++) {
        atomic_fetch_add(&clock_off, 10);
        sign_in(&x, PASS);
    }
    {
        char last[64];
        snprintf(last, sizeof last, "%s", g_session);
        snprintf(g_session, sizeof g_session, "%s", first);
        CHECK(expect(&x, "GET", "/api/v1/conditions", NULL, 401, "not_signed_in"));
        snprintf(g_session, sizeof g_session, "%s", last);
        CHECK(expect(&x, "GET", "/api/v1/conditions", NULL, 200, NULL));
    }
    /* kind B: revoke-all needs a fresh sign-in after 5 minutes (items 20, 39) */
    atomic_fetch_add(&clock_off, 6 * 60 * 1000);
    CHECK(expect(&x, "POST", "/api/v1/session/revoke-all", "{\"confirm\":\"revoke_all\"}", 403, "fresh_sign_in_needed"));
    CHECK(expect(&x, "POST", "/api/v1/session/fresh", "{\"passphrase\":\"" PASS "\"}", 200, NULL));
    CHECK(expect(&x, "POST", "/api/v1/session/revoke-all", "{\"confirm\":\"no\"}", 409, "confirm_mismatch"));
    api(&x, &r, "POST", "/api/v1/session/revoke-all", "{\"confirm\":\"revoke_all\"}", NULL);
    CHECK(r.status == 204 && hdr(&r, "Clear-Site-Data"));
    resp_free(&r);
    CHECK(expect(&x, "GET", "/api/v1/conditions", NULL, 401, "not_signed_in"));
    /* idle sign-out (item 19): only the person's input keeps a session (F9) */
    sign_in(&x, PASS);
    atomic_fetch_add(&clock_off, 10 * 60 * 1000);
    CHECK(expect(&x, "GET", "/api/v1/conditions", NULL, 200, NULL));   /* a background read: no refresh */
    atomic_fetch_add(&clock_off, 6 * 60 * 1000);
    CHECK(expect(&x, "GET", "/api/v1/conditions", NULL, 401, "not_signed_in"));
    sign_in(&x, PASS);
    atomic_fetch_add(&clock_off, 10 * 60 * 1000);
    api(&x, &r, "GET", "/api/v1/conditions", NULL, "X-Gazpacho-User: 1\r\n");
    CHECK(r.status == 200);
    resp_free(&r);
    atomic_fetch_add(&clock_off, 6 * 60 * 1000);
    CHECK(expect(&x, "GET", "/api/v1/conditions", NULL, 200, NULL));
    /* signing out never locks: the wallet stays unlocked (4.7) */
    g_session[0] = 0;
    api(&x, &r, "GET", "/api/v1/session", NULL, NULL);
    CHECK(strcmp(jfield(&r, "wallet"), "unlocked") == 0);
    resp_free(&r);
    fx_stop(&x);
}

/* 4.3, D15: one counter, checked before the derivation, kept across a restart. */
static void test_attempts(void)
{
    fixture x;
    char path[200];
    unsigned char b[85];
    uint64_t counter, last, until, counter2;
    uint32_t wrong;
    FILE *f;
    int i;
    clock_freeze(1);
    fx_prepare(&x, GZ_FAKE_LOCKED);
    if (fx_go(&x)) { CHECK(0); return; }
    snprintf(path, sizeof path, "%s/attempts.gza", x.dir);
    /* the program found no attempts file: the strictest state (storage 12.3) */
    g_session[0] = 0;
    CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 429, "rate_limited"));
    atomic_fetch_add(&clock_off, 901 * 1000);
    /* wrong: counted; a second at once: rate limited, not counted */
    CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"wrong one, number 1\"}", 401, "wrong_passphrase"));
    CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"wrong one, number 2\"}", 429, "rate_limited"));
    /* requests refused by a wall touch no counter (4.3) */
    {
        char req[400];
        resp r;
        int n = snprintf(req, sizeof req, "POST /api/v1/session HTTP/1.1\r\nHost: evil.example:%d\r\nContent-Type: application/json\r\n"
                                          "Content-Length: 27\r\nConnection: close\r\n\r\n{\"passphrase\":\"xxxxxxxxx\"}", x.port);
        raw(x.port, req, (size_t)n, &r);
        CHECK(r.status == 421);
        resp_free(&r);
    }
    for (i = 2; i <= 6; i++) {
        atomic_fetch_add(&clock_off, 70 * 1000);
        CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"still wrong, sorry\"}", 401, "wrong_passphrase"));
    }
    /* 6 wrong in a row: the delay is 2 s, then doubles; kind A and fresh share the counter */
    f = fopen(path, "rb");
    CHECK(f && fread(b, 1, 85, f) == 85);
    if (f) fclose(f);
    CHECK(gz_attempts_decode("signet", b, &counter, &wrong, &last, &until) == 0);
    CHECK(wrong == 6 && until - last == 2);
    fx_halt(&x);                                         /* a restart keeps the delay */
    if (fx_go(&x)) { CHECK(0); return; }
    {
        resp r;
        api(&x, &r, "POST", "/api/v1/session", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", NULL);
        CHECK(is_code(&r, 429, "rate_limited") && strstr(r.body, "retry_after_s"));
        resp_free(&r);
    }
    atomic_fetch_add(&clock_off, 3000);
    CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"wrong, the seventh\"}", 401, "wrong_passphrase"));
    f = fopen(path, "rb");
    CHECK(f && fread(b, 1, 85, f) == 85);
    if (f) fclose(f);
    CHECK(gz_attempts_decode("signet", b, &counter2, &wrong, &last, &until) == 0 && wrong == 7 && until - last == 4);
    CHECK(counter2 > counter);
    /* a right passphrase resets it */
    atomic_fetch_add(&clock_off, 5000);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    CHECK(strlen(g_session) == 43);
    f = fopen(path, "rb");
    CHECK(f && fread(b, 1, 85, f) == 85);
    if (f) fclose(f);
    CHECK(gz_attempts_decode("signet", b, &counter, &wrong, &last, &until) == 0 && wrong == 0);
    /* the words calls and fresh sign-in raise the same counter (item 17) */
    CHECK(expect(&x, "POST", "/api/v1/wallet/phrase/reveal", "{\"confirm\":\"show_words\",\"passphrase\":\"not the right one\"}",
                 401, "wrong_passphrase"));
    CHECK(expect(&x, "POST", "/api/v1/session/fresh", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 429, "rate_limited"));
    atomic_fetch_add(&clock_off, 1500);
    CHECK(expect(&x, "POST", "/api/v1/session/fresh", "{\"passphrase\":\"also not right at all\"}", 401, "wrong_passphrase"));
    f = fopen(path, "rb");
    CHECK(f && fread(b, 1, 85, f) == 85);
    if (f) fclose(f);
    CHECK(gz_attempts_decode("signet", b, &counter, &wrong, &last, &until) == 0 && wrong == 2);
    /* a damaged or deleted file: refused for 15 minutes (item 17) */
    fx_halt(&x);
    unlink(path);
    if (fx_go(&x)) { CHECK(0); return; }
    g_session[0] = 0;
    CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 429, "rate_limited"));
    atomic_fetch_add(&clock_off, 14 * 60 * 1000);
    CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 429, "rate_limited"));
    atomic_fetch_add(&clock_off, 2 * 60 * 1000);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    CHECK(strlen(g_session) == 43);
    fx_halt(&x);
    f = fopen(path, "r+b");
    if (f) { fseek(f, 50, SEEK_SET); fputc(0x55, f); fclose(f); }
    if (fx_go(&x)) { CHECK(0); return; }
    g_session[0] = 0;
    CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 429, "rate_limited"));
    fx_stop(&x);
    /* a derivation that fails is not counted (storage 8.4) */
    fx_prepare(&x, GZ_FAKE_LOCKED);
    if (fx_go(&x)) { CHECK(0); return; }
    atomic_fetch_add(&clock_off, 901 * 1000);
    pthread_mutex_lock(&x.fake.mu);
    x.fake.derivation_fails_next = 1;
    pthread_mutex_unlock(&x.fake.mu);
    CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 503, "passphrase_not_checked"));
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    CHECK(strlen(g_session) == 43);
    fx_stop(&x);
}

/* 4.3, item 46: 32 passphrases at once start one derivation; one waits; the rest 429. */
typedef struct { fixture *x; int status; } flood_arg;
static void *flood_one(void *a)
{
    flood_arg *f = a;
    resp r;
    char req[600];
    int n = snprintf(req, sizeof req, "POST /api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n"
                                      "Content-Type: application/json\r\nContent-Length: 40\r\nConnection: close\r\n\r\n"
                                      "{\"passphrase\":\"flood flood flood flood\"}", f->x->port, f->x->port);
    raw(f->x->port, req, (size_t)n, &r);
    f->status = r.status;
    resp_free(&r);
    return NULL;
}

static void test_flood(void)
{
    fixture x;
    pthread_t th[20];
    flood_arg a[20];
    int i, wrong = 0, limited = 0;
    gz_api_counters c;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    x.fake.pp_delay_ms = 400;
    if (fx_go(&x)) { CHECK(0); return; }
    atomic_fetch_add(&clock_off, 901 * 1000);
    /* frozen: under valgrind the 20 requests may take longer than the one-second delay to arrive */
    clock_freeze(1);
    for (i = 0; i < 20; i++) { a[i].x = &x; pthread_create(&th[i], NULL, flood_one, &a[i]); }
    for (i = 0; i < 20; i++) pthread_join(th[i], NULL);
    clock_freeze(0);
    for (i = 0; i < 20; i++) {
        if (a[i].status == 401) wrong++;
        else if (a[i].status == 429) limited++;
    }
    fx_counters(&x, &c);
    /* the gate is checked again when the waiting job starts (review F2): exactly one per window */
    if (!(wrong == 1 && wrong + limited == 20)) {
        printf("  flood:");
        for (i = 0; i < 20; i++) printf(" %d", a[i].status);
        printf(" (max concurrent %d, inside %d)\n", c.derivations_max_concurrent, (int)FAKE_READ(&x, x.fake.max_inside));
    }
    CHECK(wrong == 1 && wrong + limited == 20);
    CHECK(c.derivations_max_concurrent == 1 && FAKE_READ(&x, x.fake.max_inside) == 1);
    fx_stop(&x);
}

/* 7.4 request ids, 23.1 items 5, 17, 18; kind A replay runs no derivation. */
static void test_request_ids(void)
{
    fixture x;
    resp r;
    char body[2000], digest[80], draft[1200];
    int64_t before;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    if (fx_go(&x)) { CHECK(0); return; }
    atomic_fetch_add(&clock_off, 901 * 1000);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    api(&x, &r, "GET", "/api/v1/lobbies/lob_7k2q", NULL, NULL);
    CHECK(r.status == 200);
    {
        char *p = strstr(r.body, "\"digest\":\"");
        snprintf(digest, sizeof digest, "%.64s", p ? p + 10 : "");
    }
    resp_free(&r);
    snprintf(body, sizeof body, "{\"request_id\":\"req_join_0000000001\",\"seen_current_digest\":\"%s\"}", digest);
    api(&x, &r, "POST", "/api/v1/lobbies/lob_7k2q/join", body, NULL);
    CHECK(r.status == 202 && strstr(r.body, "\"seat\":\"joining\"") && !strstr(r.body, "replayed"));
    resp_free(&r);
    /* the same again: the first answer, replayed, nothing new */
    snprintf(body, sizeof body, "{ \"seen_current_digest\" : \"%s\", \"request_id\":\"req_join_0000000001\" }", digest);
    api(&x, &r, "POST", "/api/v1/lobbies/lob_7k2q/join", body, NULL);
    CHECK(r.status == 202 && strstr(r.body, "\"replayed\":true") && strstr(r.body, "\"seat\":\"joining\""));
    resp_free(&r);
    /* the same id, another body or another path: request_id_reused */
    snprintf(body, sizeof body, "{\"request_id\":\"req_join_0000000001\",\"seen_current_digest\":\"%s\",\"ready\":true}", digest);
    api(&x, &r, "POST", "/api/v1/lobbies/lob_7k2q/join", body, NULL);
    CHECK(is_code(&r, 409, "request_id_reused") && strstr(r.body, "/api/v1/lobbies/{lob}/join"));
    resp_free(&r);
    CHECK(expect(&x, "POST", "/api/v1/lobbies/lob_7k2q/leave", "{\"request_id\":\"req_join_0000000001\"}", 409, "request_id_reused"));
    CHECK(expect(&x, "POST", "/api/v1/lobbies/lob_7k2q/leave", "{\"request_id\":\"short\"}", 400, "bad_value"));
    /* the same id and body on another path: reused, not replayed */
    CHECK(expect(&x, "POST", "/api/v1/lobbies/lob_7k2q/leave", "{\"request_id\":\"req_leave_00000001\"}", 202, NULL));
    CHECK(expect(&x, "POST", "/api/v1/lobbies/lob_b19d/leave", "{\"request_id\":\"req_leave_00000001\"}", 409,
                 "request_id_reused"));
    CHECK(expect(&x, "POST", "/api/v1/lobbies/lob_7k2q/leave", "{}", 400, "missing_field"));
    /* host open: kind A, an echo, the passphrase, then a replay without a derivation */
    snprintf(draft, sizeof draft,
             "{\"name\":\"My first lobby\",\"profile\":\"standard\",\"target\":50,\"minimum\":30,\"deadline_at\":%lld,"
             "\"on_shortfall\":\"cancel\",\"channel_sat\":500000,\"joining_fee_sat\":{\"now\":1000,\"min\":500,\"max\":1500}}",
             (long long)(test_now(NULL) / 1000 + 86400));
    api(&x, &r, "POST", "/api/v1/host/preview", draft, NULL);
    CHECK(r.status == 200 && strstr(r.body, "\"can_open\":true"));
    {
        char dd[80];
        snprintf(dd, sizeof dd, "%s", jfield(&r, "draft_digest"));
        resp_free(&r);
        snprintf(body, sizeof body, "{\"request_id\":\"req_open_0000000001\",\"draft\":%s,\"draft_digest\":\"%s\","
                                    "\"confirm_funding_sat\":1,\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", draft, dd);
        before = FAKE_READ(&x, x.fake.derivations);
        CHECK(expect(&x, "POST", "/api/v1/host/lobbies", body, 409, "confirm_mismatch"));
        CHECK(FAKE_READ(&x, x.fake.derivations) == before);            /* refused before any derivation */
        snprintf(body, sizeof body, "{\"request_id\":\"req_open_0000000001\",\"draft\":%s,\"draft_digest\":\"%s\","
                                    "\"confirm_funding_sat\":37500000}", draft, dd);
        CHECK(expect(&x, "POST", "/api/v1/host/lobbies", body, 400, "missing_field"));
        snprintf(body, sizeof body, "{\"request_id\":\"req_open_0000000001\",\"draft\":%s,\"draft_digest\":\"%s\","
                                    "\"confirm_funding_sat\":37500000,\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", draft, dd);
        api(&x, &r, "POST", "/api/v1/host/lobbies", body, NULL);
        CHECK(r.status == 201 && strstr(r.body, "\"id\":\"lob_4c08\""));
        resp_free(&r);
        before = FAKE_READ(&x, x.fake.derivations);
        snprintf(body, sizeof body, "{\"request_id\":\"req_open_0000000001\",\"draft\":%s,\"draft_digest\":\"%s\","
                                    "\"confirm_funding_sat\":37500000,\"passphrase\":\"any other passphrase\"}", draft, dd);
        api(&x, &r, "POST", "/api/v1/host/lobbies", body, NULL);
        CHECK(r.status == 201 && strstr(r.body, "\"replayed\":true"));
        resp_free(&r);
        CHECK(FAKE_READ(&x, x.fake.derivations) == before);
    }
    /* kind B with an echo: the early start (4.8) */
    atomic_fetch_add(&clock_off, 6 * 60 * 1000);
    CHECK(expect(&x, "POST", "/api/v1/host/lobbies/lob_4c08/start", "{\"request_id\":\"req_start_000000001\",\"confirm_funding_max_sat\":37500000}",
                 403, "fresh_sign_in_needed"));
    CHECK(expect(&x, "POST", "/api/v1/session/fresh", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 200, NULL));
    CHECK(expect(&x, "POST", "/api/v1/host/lobbies/lob_4c08/start", "{\"request_id\":\"req_start_000000002\",\"confirm_funding_max_sat\":1}",
                 409, "confirm_mismatch"));
    CHECK(expect(&x, "POST", "/api/v1/host/lobbies/lob_4c08/start", "{\"request_id\":\"req_start_000000003\",\"confirm_funding_max_sat\":37500000}",
                 409, "below_minimum"));
    /* lock while hosting an Open lobby (D20) */
    CHECK(expect(&x, "POST", "/api/v1/wallet/lock", "{\"confirm\":\"lock_wallet\",\"confirm_locked\":\"nobody_watching\"}", 409,
                 "hosting_lobby_open"));
    fx_stop(&x);
}

/* 2: every reserved call answers 501 with its release (23.1 item 8). */
static void test_reserved(void)
{
    fixture x;
    int i, n = gz_api_route_count(), seen = 0;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    if (fx_go(&x)) { CHECK(0); return; }
    atomic_fetch_add(&clock_off, 901 * 1000);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    for (i = 0; i < n; i++) {
        int method;
        const char *pattern, *release;
        char path[300], want[64], *o = path;
        const char *p;
        static const char *const M[] = {"OTHER", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"};
        resp r;
        gz_api_route_info(i, &method, &pattern, &release);
        if (strcmp(release, "S1") == 0) continue;
        for (p = pattern; *p;) {                          /* fill each {x} with an id */
            if (*p == '{') { o += sprintf(o, "x1"); p = strchr(p, '}') + 1; }
            else *o++ = *p++;
        }
        *o = 0;
        api(&x, &r, M[method], path, method == 1 ? NULL : "{}", NULL);
        snprintf(want, sizeof want, "\"release\":\"%s\"", release);
        CHECK(is_code(&r, 501, "not_in_this_release") && strstr(r.body, want));
        resp_free(&r);
        seen++;
    }
    CHECK(seen > 80);
    {
        gz_api_counters c;
        fx_counters(&x, &c);
        CHECK(c.handler_calls == 0);                     /* no reserved call reaches the backend */
    }
    fx_stop(&x);
}

/* 7.1, 6: bad JSON, unknown fields, wrong types. */
static void test_bodies(void)
{
    fixture x;
    const char *bad[] = {"{\"a\":1,\"a\":1}", "[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]", "{\"n\":9007199254740992}",
                         "{\"s\":\"\xff\"}", "{\"s\":\"\\ud800\"}", "not json", "[1]", "{\"n\":1.5}"};
    int i;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    if (fx_go(&x)) { CHECK(0); return; }
    atomic_fetch_add(&clock_off, 901 * 1000);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    for (i = 0; i < 8; i++) CHECK(expect(&x, "POST", "/api/v1/conditions/preview", bad[i], 400, "bad_json"));
    CHECK(expect(&x, "POST", "/api/v1/conditions/preview", "{\"conditions\":{},\"extra\":1}", 400, "unknown_field"));
    CHECK(expect(&x, "POST", "/api/v1/conditions/preview", "{\"conditions\":5}", 400, "bad_value"));
    CHECK(expect(&x, "POST", "/api/v1/conditions/preview", "{\"conditions\":{\"nonsense\":1}}", 400, "unknown_field"));
    CHECK(expect(&x, "POST", "/api/v1/conditions/preview", NULL, 400, "missing_field"));
    CHECK(expect(&x, "GET", "/api/v1/lobbies?limit=0", NULL, 400, "bad_value"));
    CHECK(expect(&x, "GET", "/api/v1/lobbies?limit=50&show=fits&sort=fit", NULL, 200, NULL));
    CHECK(expect(&x, "GET", "/api/v1/lobbies?sort=sideways", NULL, 400, "bad_value"));
    /* a known parameter of another call is still unknown here */
    CHECK(expect(&x, "GET", "/api/v1/lobbies?state=open", NULL, 400, "unknown_field"));
    CHECK(expect(&x, "GET", "/api/v1/lobbies?cursor=a&cursor=b", NULL, 400, "bad_value"));
    CHECK(expect(&x, "GET", "/api/v1/lobbies/lob_nothere", NULL, 404, "not_found"));
    CHECK(expect(&x, "GET", "/api/v1/lobbies/7f3a00", NULL, 404, "not_found"));
    /* the conditions copying rule's gate: loosening needs a fresh sign-in and the exact list (item 4) */
    atomic_fetch_add(&clock_off, 6 * 60 * 1000);
    CHECK(expect(&x, "PUT", "/api/v1/conditions", "{\"conditions\":{\"max_joining_fee_sat\":5000},\"based_on_version\":7}",
                 403, "fresh_sign_in_needed"));
    CHECK(expect(&x, "PUT", "/api/v1/conditions", "{\"conditions\":{\"max_joining_fee_sat\":1500},\"based_on_version\":7}", 200, NULL));
    CHECK(expect(&x, "PUT", "/api/v1/conditions", "{\"conditions\":{\"max_joining_fee_sat\":1400},\"based_on_version\":7}",
                 409, "changed_elsewhere"));
    CHECK(expect(&x, "POST", "/api/v1/session/fresh", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 200, NULL));
    CHECK(expect(&x, "PUT", "/api/v1/conditions",
                 "{\"conditions\":{\"max_joining_fee_sat\":5000},\"based_on_version\":8,\"confirm_loosens\":[]}", 409, "confirm_mismatch"));
    CHECK(expect(&x, "PUT", "/api/v1/conditions",
                 "{\"conditions\":{\"max_joining_fee_sat\":5000},\"based_on_version\":8,\"confirm_loosens\":[\"max_joining_fee_sat\"]}",
                 200, NULL));
    /* pause, and resume as kind B (D6, item 7) */
    CHECK(expect(&x, "PUT", "/api/v1/pause", "{\"on\":true}", 200, NULL));
    CHECK(expect(&x, "PUT", "/api/v1/pause", "{\"on\":false}", 409, "confirm_mismatch"));
    atomic_fetch_add(&clock_off, 6 * 60 * 1000);
    CHECK(expect(&x, "PUT", "/api/v1/pause", "{\"on\":false,\"confirm\":\"resume\"}", 403, "fresh_sign_in_needed"));
    fx_stop(&x);
}

/* 10: one stream, caps, events with local ids only, the session event, replay. */
static void test_events(void)
{
    fixture x;
    int fds[3], i, n;
    char req[600], buf[8192], digest[80], body[300], last_id[64];
    resp r;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    if (fx_go(&x)) { CHECK(0); return; }
    atomic_fetch_add(&clock_off, 901 * 1000);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    n = snprintf(req, sizeof req, "GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Gazpacho-Session: %s\r\n"
                                  "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Dest: empty\r\n\r\n", x.port, g_session);
    for (i = 0; i < 3; i++) {
        fds[i] = tcp_connect(x.port);
        send(fds[i], req, (size_t)n, MSG_NOSIGNAL);
        sleep_ms(300);
    }
    /* two per session; the third 429, before any event (F10) */
    read_answer(fds[2], &r, 2000);
    CHECK(is_code(&r, 429, "too_many_streams"));
    resp_free(&r);
    close(fds[2]);
    {
        ssize_t k = recv(fds[0], buf, sizeof buf - 1, 0);
        buf[k > 0 ? k : 0] = 0;
        CHECK(strstr(buf, "HTTP/1.1 200") && strstr(buf, "text/event-stream") && strstr(buf, "Transfer-Encoding: chunked"));
        CHECK(strstr(buf, "Cross-Origin-Resource-Policy: same-origin") != NULL);
    }
    /* an event names an area and a local id, never content (10.2) */
    api(&x, &r, "GET", "/api/v1/lobbies/lob_7k2q", NULL, NULL);
    {
        char *p = strstr(r.body, "\"digest\":\"");
        snprintf(digest, sizeof digest, "%.64s", p ? p + 10 : "");
    }
    resp_free(&r);
    snprintf(body, sizeof body, "{\"request_id\":\"req_join_0000000009\",\"seen_current_digest\":\"%s\"}", digest);
    CHECK(expect(&x, "POST", "/api/v1/lobbies/lob_7k2q/join", body, 202, NULL));
    sleep_ms(400);
    {
        ssize_t k = recv(fds[0], buf, sizeof buf - 1, MSG_DONTWAIT);
        char *p;
        buf[k > 0 ? k : 0] = 0;
        CHECK(strstr(buf, "event: change") && strstr(buf, "\"topic\":\"lobby\",\"id\":\"lob_7k2q\""));
        CHECK(strstr(buf, digest) == NULL);
        p = strstr(buf, "id: ");
        last_id[0] = 0;
        if (p) sscanf(p + 4, "%63s", last_id);
        CHECK(strncmp(last_id, gz_api_server_run_id(x.srv), 8) == 0);
    }
    /* a reconnect with Last-Event-ID replays; an unknown run gets one reset */
    close(fds[1]);
    sleep_ms(100);
    {
        int fd = tcp_connect(x.port);
        char r2[800];
        int m = snprintf(r2, sizeof r2, "GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Gazpacho-Session: %s\r\n"
                                        "Last-Event-ID: deadbeef-3\r\n\r\n", x.port, g_session);
        ssize_t k;
        send(fd, r2, (size_t)m, MSG_NOSIGNAL);
        sleep_ms(200);
        k = recv(fd, buf, sizeof buf - 1, 0);
        buf[k > 0 ? k : 0] = 0;
        CHECK(strstr(buf, "\"topic\":\"reset\"") != NULL);
        close(fd);
    }
    /* the same run: the events after Last-Event-ID, and not another stream's reset */
    sleep_ms(200);
    {
        int fd = tcp_connect(x.port);
        char r2[800], lobby_ev[80];
        unsigned long long seq = strtoull(strchr(last_id, '-') ? strchr(last_id, '-') + 1 : "0", NULL, 10);
        int m = snprintf(r2, sizeof r2, "GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Gazpacho-Session: %s\r\n"
                                        "Last-Event-ID: %s\r\n\r\n", x.port, g_session, last_id);
        ssize_t k;
        send(fd, r2, (size_t)m, MSG_NOSIGNAL);
        sleep_ms(300);
        k = recv(fd, buf, sizeof buf - 1, 0);
        buf[k > 0 ? k : 0] = 0;
        snprintf(lobby_ev, sizeof lobby_ev, "\"seq\":%llu}", seq);
        CHECK(seq > 0 && strstr(buf, "\"topic\":\"status\"") != NULL);
        CHECK(strstr(buf, lobby_ev) == NULL);           /* nothing at or before the id */
        CHECK(strstr(buf, "\"topic\":\"reset\"") == NULL);
        close(fd);
    }
    /* signing out ends the stream with a session event (10.2) */
    CHECK(expect(&x, "DELETE", "/api/v1/session", NULL, 204, NULL));
    sleep_ms(200);
    {
        size_t got = 0;
        for (;;) {
            ssize_t k;
            struct pollfd p = {fds[0], POLLIN, 0};
            if (poll(&p, 1, 1000) <= 0) break;
            k = recv(fds[0], buf + got, sizeof buf - 1 - got, 0);
            if (k <= 0) break;
            got += (size_t)k;
        }
        buf[got] = 0;
        CHECK(strstr(buf, "\"topic\":\"session\"") && strstr(buf, "0\r\n\r\n"));
    }
    close(fds[0]);
    /* an EventSource cannot send the header: 401 (item 12) */
    g_session[0] = 0;
    CHECK(expect(&x, "GET", "/api/v1/events", NULL, 401, "not_signed_in"));
    fx_stop(&x);
}

/* 4.7: files behind; 3.2, 4.6: the local socket. */
static void test_files_behind_and_socket(void)
{
    fixture x;
    resp r;
    int fd;
    char req[1200], token[64], tdir[600];
    fx_prepare(&x, GZ_FAKE_LOCKED);
    if (fx_go(&x)) { CHECK(0); return; }
    atomic_fetch_add(&clock_off, 901 * 1000);
    /* the locked socket answers only version, status and unlock, without a token */
    fd = unix_connect(gz_api_server_socket_path(x.srv));
    snprintf(req, sizeof req, "GET /api/v1/lobbies HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    read_answer(fd, &r, 2000);
    CHECK(is_code(&r, 401, "not_signed_in"));
    resp_free(&r);
    close(fd);
    fd = unix_connect(gz_api_server_socket_path(x.srv));
    snprintf(req, sizeof req, "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    read_answer(fd, &r, 2000);
    CHECK(r.status == 200 && strstr(r.body, "\"wallet\":\"locked\"") && strstr(r.body, "\"dates_hidden\":false"));
    resp_free(&r);
    close(fd);
    fd = unix_connect(gz_api_server_socket_path(x.srv));
    snprintf(req, sizeof req, "GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n");
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    read_answer(fd, &r, 2000);
    CHECK(r.status == 421);                              /* the socket's Host is localhost only */
    resp_free(&r);
    close(fd);
    /* files behind: a files_behind session, its five calls only */
    pthread_mutex_lock(&x.fake.mu);
    x.fake.files_behind_next = 1;
    pthread_mutex_unlock(&x.fake.mu);
    g_session[0] = 0;
    api(&x, &r, "POST", "/api/v1/session", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", NULL);
    CHECK(r.status == 200 && strstr(r.body, "\"kind\":\"files_behind\"") && strstr(r.body, "\"cause\":\"behind\""));
    snprintf(g_session, sizeof g_session, "%s", jfield(&r, "session") ? jfield(&r, "session") : "");
    resp_free(&r);
    CHECK(expect(&x, "GET", "/api/v1/lobbies", NULL, 403, "not_files_behind_call"));
    api(&x, &r, "GET", "/api/v1/status", NULL, NULL);
    CHECK(r.status == 200 && strstr(r.body, "\"wallet\":\"files_behind\"") && strstr(r.body, "\"code\":\"files_behind\""));
    resp_free(&r);
    /* on the socket, unlock answers 409 files_behind */
    fd = unix_connect(gz_api_server_socket_path(x.srv));
    snprintf(req, sizeof req, "POST /api/v1/wallet/unlock HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
                              "Content-Length: %zu\r\nConnection: close\r\n\r\n{\"passphrase\":\"%s\"}",
             strlen(GZ_FAKE_PASSPHRASE) + 17, GZ_FAKE_PASSPHRASE);
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    read_answer(fd, &r, 2000);
    CHECK(is_code(&r, 409, "files_behind"));
    resp_free(&r);
    close(fd);
    CHECK(expect(&x, "POST", "/api/v1/wallet/start-as-restore", "{\"confirm\":\"restore\",\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}",
                 409, "confirm_mismatch"));
    CHECK(expect(&x, "POST", "/api/v1/wallet/start-as-restore", "{\"confirm\":\"restore_new_keys\"}", 400, "missing_field"));
    atomic_fetch_add(&clock_off, 2000);
    api(&x, &r, "POST", "/api/v1/wallet/start-as-restore", "{\"confirm\":\"restore_new_keys\",\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", NULL);
    CHECK(r.status == 202 && strstr(r.body, "\"wallet\":\"restoring\""));
    resp_free(&r);
    CHECK(expect(&x, "GET", "/api/v1/lobbies", NULL, 200, NULL));   /* the session became normal */
    /* now unlocked: the socket token exists, owner-only, outside the data folder */
    {
        struct stat st;
        char *t;
        unsigned char h[32];
        (void)h;
        snprintf(tdir, sizeof tdir, "%s", x.rt);
        {
            DIR *d = opendir(x.rt);
            struct dirent *e;
            tdir[0] = 0;
            while (d && (e = readdir(d)))
                if (strncmp(e->d_name, "gazpacho-", 9) == 0) snprintf(tdir, sizeof tdir, "%s/%s", x.rt, e->d_name);
            if (d) closedir(d);
        }
        CHECK(tdir[0] && stat(tdir, &st) == 0 && (st.st_mode & 0777) == 0700);
        snprintf(req, sizeof req, "%s/socket.token", tdir);
        CHECK(stat(req, &st) == 0 && (st.st_mode & 0777) == 0600);
        t = read_file(req);
        snprintf(token, sizeof token, "%s", t ? t : "");
        free(t);
        CHECK(strlen(token) == 43);
    }
    /* bearer: on the socket only; never with Origin; never with a session */
    fd = unix_connect(gz_api_server_socket_path(x.srv));
    snprintf(req, sizeof req, "GET /api/v1/lobbies HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", token);
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    read_answer(fd, &r, 2000);
    CHECK(r.status == 200);
    resp_free(&r);
    close(fd);
    fd = unix_connect(gz_api_server_socket_path(x.srv));
    snprintf(req, sizeof req, "GET /api/v1/lobbies HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nOrigin: http://localhost\r\n"
                              "Connection: close\r\n\r\n", token);
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    read_answer(fd, &r, 2000);
    CHECK(is_code(&r, 403, "forbidden_origin"));
    resp_free(&r);
    close(fd);
    fd = unix_connect(gz_api_server_socket_path(x.srv));
    snprintf(req, sizeof req, "GET /api/v1/lobbies HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nX-Gazpacho-Session: %s\r\n"
                              "Connection: close\r\n\r\n", token, g_session);
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    read_answer(fd, &r, 2000);
    CHECK(is_code(&r, 400, "two_credentials"));
    resp_free(&r);
    close(fd);
    snprintf(req, sizeof req, "GET /api/v1/lobbies HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n",
             x.port, token);
    raw(x.port, req, strlen(req), &r);
    CHECK(is_code(&r, 400, "bearer_not_on_tcp"));
    resp_free(&r);
    /* the socket-only calls are not on the TCP port */
    CHECK(expect(&x, "POST", "/api/v1/first-run-codes", "{}", 404, "not_found"));
    /* bearer: no fresh sign-in, still the echo (item 17) */
    atomic_fetch_add(&clock_off, 6 * 60 * 1000);
    fd = unix_connect(gz_api_server_socket_path(x.srv));
    snprintf(req, sizeof req, "POST /api/v1/session/revoke-all HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n"
                              "Content-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"confirm\":\"x\"}", token);
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    read_answer(fd, &r, 2000);
    CHECK(is_code(&r, 409, "confirm_mismatch"));
    resp_free(&r);
    close(fd);
    /* lock: something to watch, so fresh and confirm_locked (4.7); then sessions end, the token goes */
    CHECK(expect(&x, "POST", "/api/v1/wallet/lock", "{\"confirm\":\"lock_wallet\"}", 403, "fresh_sign_in_needed"));
    CHECK(expect(&x, "POST", "/api/v1/session/fresh", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 200, NULL));
    CHECK(expect(&x, "POST", "/api/v1/wallet/lock", "{\"confirm\":\"lock_wallet\"}", 409, "confirm_mismatch"));
    CHECK(expect(&x, "POST", "/api/v1/wallet/lock", "{\"confirm\":\"lock_wallet\",\"confirm_locked\":\"nobody_watching\",\"confirm_unlock_by_height\":5}",
                 409, "confirm_mismatch"));
    CHECK(expect(&x, "POST", "/api/v1/wallet/lock", "{\"confirm\":\"lock_wallet\",\"confirm_locked\":\"nobody_watching\"}", 202, NULL));
    CHECK(expect(&x, "GET", "/api/v1/lobbies", NULL, 423, "wallet_locked"));
    snprintf(req, sizeof req, "%s/socket.token", tdir);
    CHECK(access(req, F_OK) != 0);
    /* unlock over the socket with the passphrase: 200, a new token */
    atomic_fetch_add(&clock_off, 2000);
    fd = unix_connect(gz_api_server_socket_path(x.srv));
    snprintf(req, sizeof req, "POST /api/v1/wallet/unlock HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
                              "Content-Length: %zu\r\nConnection: close\r\n\r\n{\"passphrase\":\"%s\"}",
             strlen(GZ_FAKE_PASSPHRASE) + 17, GZ_FAKE_PASSPHRASE);
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    read_answer(fd, &r, 2000);
    CHECK(r.status == 200 && strstr(r.body, "\"wallet\":\"unlocked\""));
    resp_free(&r);
    close(fd);
    snprintf(req, sizeof req, "%s/socket.token", tdir);
    {
        char *t = read_file(req);
        CHECK(t && strlen(t) == 43 && strcmp(t, token) != 0);
        free(t);
    }
    fx_stop(&x);
    /* first run on the socket: a code, which works once, and five wrong cancel them (4.3) */
    fx_prepare(&x, GZ_FAKE_FIRST_RUN);
    if (fx_go(&x)) { CHECK(0); return; }
    {
        char code[32], body[200];
        int i;
        fd = unix_connect(gz_api_server_socket_path(x.srv));
        snprintf(req, sizeof req, "POST /api/v1/first-run-codes HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
                                  "Content-Length: 2\r\nConnection: close\r\n\r\n{}");
        send(fd, req, strlen(req), MSG_NOSIGNAL);
        read_answer(fd, &r, 2000);
        CHECK(r.status == 200 && jfield(&r, "code") && strlen(jfield(&r, "code")) == 11);
        snprintf(code, sizeof code, "%s", jfield(&r, "code") ? jfield(&r, "code") : "");
        resp_free(&r);
        close(fd);
        g_session[0] = 0;
        clock_freeze(1);
        for (i = 0; i < 4; i++) {
            atomic_fetch_add(&clock_off, 1100);
            CHECK(expect(&x, "POST", "/api/v1/session/start", "{\"code\":\"00000-00000\"}", 401, "bad_code"));
        }
        CHECK(expect(&x, "POST", "/api/v1/session/start", "{\"code\":\"00000-00001\"}", 429, "rate_limited"));
        clock_freeze(0);
        atomic_fetch_add(&clock_off, 1100);
        snprintf(body, sizeof body, "{\"code\":\"%s\"}", code);
        api(&x, &r, "POST", "/api/v1/session/start", body, NULL);
        CHECK(r.status == 200 && strstr(r.body, "\"kind\":\"setup\""));
        resp_free(&r);
        atomic_fetch_add(&clock_off, 1100);
        CHECK(expect(&x, "POST", "/api/v1/session/start", body, 401, "bad_code"));   /* one use */
    }
    fx_stop(&x);
    /* five wrong codes in a row cancel every code that existed then */
    fx_prepare(&x, GZ_FAKE_FIRST_RUN);
    if (fx_go(&x)) { CHECK(0); return; }
    {
        char code[16], body[200];
        int i;
        CHECK(fx_first_run_code(&x, code) == 0 && strlen(code) == 11);
        g_session[0] = 0;
        for (i = 0; i < 5; i++) {
            atomic_fetch_add(&clock_off, 1100);
            CHECK(expect(&x, "POST", "/api/v1/session/start", "{\"code\":\"00000-00000\"}", i < 4 ? 401 : 429,
                         i < 4 ? "bad_code" : "too_many_attempts"));
        }
        atomic_fetch_add(&clock_off, 1100);
        snprintf(body, sizeof body, "{\"code\":\"%s\"}", code);
        CHECK(expect(&x, "POST", "/api/v1/session/start", body, 401, "bad_code"));
    }
    fx_stop(&x);
}

/* 3.1 binding rules (23.2 items 27, 28): loopback only; a taken port refuses to start. */
static void test_binding(void)
{
    fixture x;
    const char *err = NULL;
    gz_api_server *s;
    int fd, one = 1;
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    const char *bad[] = {"0.0.0.0", "::", "192.0.2.10", "localhost"};
    int i;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    for (i = 0; i < 4; i++) {
        x.cfg.listen_address = bad[i];
        s = gz_api_server_new(&x.cfg, &err);
        CHECK(s == NULL && err && strstr(err, "loopback"));
        if (s) gz_api_server_free(s);
    }
    x.cfg.listen_address = "127.0.0.1";
    /* a port another program holds */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(fd, (struct sockaddr *)&a, sizeof a) == 0 && listen(fd, 1) == 0);
    getsockname(fd, (struct sockaddr *)&a, &al);
    x.cfg.port = ntohs(a.sin_port);
    err = NULL;
    s = gz_api_server_new(&x.cfg, &err);
    CHECK(s == NULL && err && strstr(err, "in use"));  /* it never picks another port */
    if (s) gz_api_server_free(s);
    close(fd);
    /* the folder is the program's (contract-v2 11, T11.6): a missing one refuses to
     * start and nothing is created; the server checks no mode (decision 16 reversed) */
    {
        char missing[300];
        struct stat st;
        const char *given = x.cfg.data_dir;
        snprintf(missing, sizeof missing, "%s/not-made", x.dir);
        x.cfg.data_dir = missing;
        x.cfg.port = 0;
        err = NULL;
        s = gz_api_server_new(&x.cfg, &err);
        CHECK(s == NULL && err && strstr(err, "does not exist"));
        CHECK(stat(missing, &st) != 0 && errno == ENOENT);
        if (s) gz_api_server_free(s);
        x.cfg.data_dir = given;
    }
    fx_stop(&x);
}

/* 3.3, item 40: the extra tunnel port, off by default. */
static void test_tunnel(void)
{
    fixture x;
    resp r;
    char req[600];
    int n, tp = 41111;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    x.cfg.tunnel_port = (uint16_t)tp;
    if (fx_go(&x)) { CHECK(0); return; }
    atomic_fetch_add(&clock_off, 901 * 1000);
    /* the tunnel port is accepted in Host and Origin, and no hand-over between tabs */
    n = snprintf(req, sizeof req, "POST /api/v1/session HTTP/1.1\r\nHost: localhost:%d\r\nOrigin: http://localhost:%d\r\n"
                                  "Content-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n"
                                  "{\"passphrase\":\"%s\"}", tp, tp, strlen(GZ_FAKE_PASSPHRASE) + 17, GZ_FAKE_PASSPHRASE);
    raw(x.port, req, (size_t)n, &r);
    CHECK(r.status == 200 && strstr(r.body, "\"handover\":false"));
    snprintf(g_session, sizeof g_session, "%s", jfield(&r, "session") ? jfield(&r, "session") : "");
    resp_free(&r);
    /* a session made under the tunnel's Host is refused under the program's own */
    CHECK(expect(&x, "GET", "/api/v1/conditions", NULL, 401, "not_signed_in"));
    n = snprintf(req, sizeof req, "GET /api/v1/conditions HTTP/1.1\r\nHost: localhost:%d\r\nX-Gazpacho-Session: %s\r\n"
                                  "Connection: close\r\n\r\n", tp, g_session);
    raw(x.port, req, (size_t)n, &r);
    CHECK(r.status == 200);
    resp_free(&r);
    /* it ends 2 minutes after its last request naming the port */
    atomic_fetch_add(&clock_off, 125 * 1000);
    raw(x.port, req, (size_t)n, &r);
    CHECK(is_code(&r, 401, "not_signed_in"));
    resp_free(&r);
    /* any other port is still refused */
    n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: localhost:%d\r\nConnection: close\r\n\r\n", tp + 1);
    raw(x.port, req, (size_t)n, &r);
    CHECK(r.status == 421);
    resp_free(&r);
    fx_stop(&x);
}

/* ---- review A of PR 26 (F3: behaviour no test checked) and contract-v2 P5 ---------------------- */
static void sock_req(fixture *x, const char *req, resp *r)
{
    int fd = unix_connect(gz_api_server_socket_path(x->srv));
    memset(r, 0, sizeof *r);
    if (fd < 0) { r->closed_without_answer = 1; return; }
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    read_answer(fd, r, 3000);
    close(fd);
}

static void token_dir_of(fixture *x, char out[300])
{
    char real[PATH_MAX], hex[17];
    unsigned char h[32];
    int i;
    out[0] = 0;
    if (!realpath(x->dir, real)) return;
    SHA256((const unsigned char *)real, strlen(real), h);
    for (i = 0; i < 8; i++) snprintf(hex + 2 * i, 3, "%02x", h[i]);
    snprintf(out, 300, "%s/gazpacho-%s", x->rt, hex);
}

static void socket_token(fixture *x, char tok[64])
{
    char d[300], p[340], *t;
    token_dir_of(x, d);
    snprintf(p, sizeof p, "%s/socket.token", d);
    t = read_file(p);
    snprintf(tok, 64, "%s", t ? t : "");
    free(t);
}

static void write_attempts(fixture *x, const char *network, uint32_t wrong, uint64_t last, uint64_t until)
{
    char p[200];
    uint8_t b[85];
    FILE *f;
    snprintf(p, sizeof p, "%s/attempts.gza", x->dir);
    CHECK(gz_attempts_encode(network, 5, wrong, last, until, b) == 0);
    f = fopen(p, "wb");
    if (f) { fwrite(b, 1, sizeof b, f); fclose(f); }
    chmod(p, 0600);
}

static int read_attempts(fixture *x, uint32_t *wrong, uint64_t *last, uint64_t *until)
{
    char p[200];
    uint8_t b[85];
    uint64_t counter;
    FILE *f;
    snprintf(p, sizeof p, "%s/attempts.gza", x->dir);
    f = fopen(p, "rb");
    if (!f) return -1;
    if (fread(b, 1, 85, f) != 85) { fclose(f); return -1; }
    fclose(f);
    return gz_attempts_decode("signet", b, &counter, wrong, last, until);
}

static void test_review_walls(void)
{
    fixture x;
    resp r;
    char req[1200], tok[64], old[64];
    struct stat st;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    if (fx_go(&x)) { CHECK(0); return; }
    atomic_fetch_add(&clock_off, 901 * 1000);
    /* socket-mode-open: the local socket is 0600 from its first moment */
    CHECK(stat(gz_api_server_socket_path(x.srv), &st) == 0 && (st.st_mode & 0777) == 0600);
    /* get-with-body: a GET with a body is refused, not parsed */
    snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\n"
                              "Content-Length: 2\r\nConnection: close\r\n\r\n{}", x.port);
    raw(x.port, req, strlen(req), &r);
    CHECK(is_code(&r, 400, "bad_request"));
    resp_free(&r);
    /* static-query-ok: a static page takes no query */
    snprintf(req, sizeof req, "GET /?x=1 HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", x.port);
    raw(x.port, req, strlen(req), &r);
    CHECK(r.status == 404);
    resp_free(&r);
    /* 421-keeps-alive: a wrong Host closes the connection; a request after it is never served */
    snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: evil.example\r\n\r\n"
                              "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", x.port);
    raw(x.port, req, strlen(req), &r);
    CHECK(r.status == 421 && hdr(&r, "Connection") && strcasecmp(hdr(&r, "Connection"), "close") == 0);
    CHECK(r.body && strstr(r.body, "HTTP/1.1 200") == NULL);
    resp_free(&r);
    /* empty-passphrase-derived: an empty passphrase is refused before any derivation */
    {
        int64_t before = FAKE_READ(&x, x.fake.derivations);
        CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"\"}", 400, "bad_value"));
        CHECK(FAKE_READ(&x, x.fake.derivations) == before);
    }
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    CHECK(strlen(g_session) == 43);
    socket_token(&x, tok);
    CHECK(strlen(tok) == 43);
    /* bearer-unchecked: a token of the right form that is not ours */
    snprintf(req, sizeof req, "GET /api/v1/lobbies HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %.43s\r\nConnection: close\r\n\r\n",
             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    sock_req(&x, req, &r);
    CHECK(is_code(&r, 401, "not_signed_in"));
    resp_free(&r);
    /* two-authorization: two Authorization headers, even both right */
    snprintf(req, sizeof req, "GET /api/v1/lobbies HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n"
                              "Authorization: Bearer %s\r\nConnection: close\r\n\r\n", tok, tok);
    sock_req(&x, req, &r);
    CHECK(is_code(&r, 400, "two_credentials"));
    resp_free(&r);
    /* bearer-may-create: the socket token is not a setup session */
    snprintf(req, sizeof req, "POST /api/v1/wallet/create HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n"
                              "Content-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", tok,
             strlen("{\"confirm\":\"create_wallet\",\"passphrase\":\"" PASS "\",\"confirm_passphrase\":\"" PASS "\"}"),
             "{\"confirm\":\"create_wallet\",\"passphrase\":\"" PASS "\",\"confirm_passphrase\":\"" PASS "\"}");
    sock_req(&x, req, &r);
    CHECK(is_code(&r, 403, "not_setup_session"));
    resp_free(&r);
    /* revoke-keeps-socket-token: revoke-all rotates the socket token; the old one is refused */
    snprintf(old, sizeof old, "%s", tok);
    CHECK(expect(&x, "POST", "/api/v1/session/revoke-all", "{\"confirm\":\"revoke_all\"}", 204, NULL));
    socket_token(&x, tok);
    CHECK(strlen(tok) == 43 && strcmp(tok, old) != 0);
    snprintf(req, sizeof req, "GET /api/v1/lobbies HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", old);
    sock_req(&x, req, &r);
    CHECK(is_code(&r, 401, "not_signed_in"));
    resp_free(&r);
    /* normal-session-while-locked: a normal session while the files are behind answers 423 */
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    pthread_mutex_lock(&x.fake.mu);
    x.fake.wallet = GZ_API_WALLET_FILES_BEHIND;
    pthread_mutex_unlock(&x.fake.mu);
    CHECK(expect(&x, "GET", "/api/v1/lobbies", NULL, 423, "wallet_locked"));
    pthread_mutex_lock(&x.fake.mu);
    x.fake.wallet = GZ_API_WALLET_UNLOCKED;
    pthread_mutex_unlock(&x.fake.mu);
    fx_stop(&x);
}

static void test_review_setup(void)
{
    fixture x;
    resp r;
    char tok[64], code[16], body[400], path[200];
    fx_prepare(&x, GZ_FAKE_FIRST_RUN);
    if (fx_go(&x)) { CHECK(0); return; }
    start_token_from_file(&x, tok);
    CHECK(strlen(tok) == 43);
    /* a setup session from a code, while the start token is still unspent */
    CHECK(fx_first_run_code(&x, code) == 0);
    g_session[0] = 0;
    snprintf(body, sizeof body, "{\"code\":\"%s\"}", code);
    api(&x, &r, "POST", "/api/v1/session/start", body, NULL);
    CHECK(r.status == 200);
    snprintf(g_session, sizeof g_session, "%s", jfield(&r, "session") ? jfield(&r, "session") : "");
    resp_free(&r);
    /* confirm-pass-length-only: two passphrases of one length that differ */
    CHECK(expect(&x, "POST", "/api/v1/wallet/create",
                 "{\"confirm\":\"create_wallet\",\"passphrase\":\"" PASS "\",\"confirm_passphrase\":\"" PASS "X\"}", 400,
                 "passphrases_differ"));
    CHECK(expect(&x, "POST", "/api/v1/wallet/create",
                 "{\"confirm\":\"create_wallet\",\"passphrase\":\"correct horse battery staple, tesA\","
                 "\"confirm_passphrase\":\"correct horse battery staple, tesB\"}", 400, "passphrases_differ"));
    /* done with a fault (storage GZ_SC_DONE_WITH_FAULT): in force, so done, with a warning */
    pthread_mutex_lock(&x.fake.mu);
    x.fake.fault_next = 1;
    pthread_mutex_unlock(&x.fake.mu);
    api(&x, &r, "POST", "/api/v1/wallet/create",
        "{\"confirm\":\"create_wallet\",\"passphrase\":\"" PASS "\",\"confirm_passphrase\":\"" PASS "\"}", NULL);
    CHECK(r.status == 200 && r.body && strstr(r.body, "\"words\"") &&
          strstr(r.body, "\"warning\":{\"code\":\"done_with_fault\",\"fault\":\"mark_file\"}"));
    resp_free(&r);
    CHECK(FAKE_READ(&x, x.fake.wallet) == GZ_API_WALLET_UNLOCKED);
    /* create-keeps-first-run: the start token's file and every code go at create (4.9) */
    snprintf(path, sizeof path, "%s/first-run.html", x.dir);
    CHECK(access(path, F_OK) != 0);
    CHECK(fx_first_run_code(&x, code) != 0);
    fx_stop(&x);
}

static void test_review_attempts(void)
{
    fixture x;
    resp r;
    uint32_t wrong;
    uint64_t last, until;
    int i;
    int64_t now_s;
    /* attempts-other-network: a file of another network is the strictest state */
    fx_prepare(&x, GZ_FAKE_LOCKED);
    now_s = test_now(NULL) / 1000;
    write_attempts(&x, "testnet4", 0, 0, 0);
    if (fx_go(&x)) { CHECK(0); return; }
    g_session[0] = 0;
    CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 429, "rate_limited"));
    fx_stop(&x);
    /* a clock set back: a loaded delay is capped at 900 s (F5.2) */
    fx_prepare(&x, GZ_FAKE_LOCKED);
    now_s = test_now(NULL) / 1000;
    write_attempts(&x, "signet", 20, (uint64_t)now_s, (uint64_t)now_s + 50000);
    if (fx_go(&x)) { CHECK(0); return; }
    api(&x, &r, "POST", "/api/v1/session", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", NULL);
    CHECK(is_code(&r, 429, "rate_limited"));
    {
        const char *p = r.body ? strstr(r.body, "\"retry_after_s\":") : NULL;
        CHECK(p && atol(p + 16) <= 900);
    }
    resp_free(&r);
    fx_stop(&x);
    /* delay-cap-1800: the delay doubles to 900 s and stays there */
    clock_freeze(1);
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    if (fx_go(&x)) { CHECK(0); clock_freeze(0); return; }
    for (i = 0; i < 17; i++) {
        atomic_fetch_add(&clock_off, 2000 * 1000);
        CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"wrong, over and over\"}", 401, "wrong_passphrase"));
    }
    CHECK(read_attempts(&x, &wrong, &last, &until) == 0 && wrong == 17 && until - last == 900);
    /* the file cannot be written: passphrases are refused, not counted (F5.1) */
    {
        char p[200], q[240];
        snprintf(p, sizeof p, "%s/attempts.gza", x.dir);
        unlink(p);
        mkdir(p, 0700);                                   /* the rename over it fails, even for root */
        snprintf(q, sizeof q, "%s/keep", p);
        close(open(q, O_WRONLY | O_CREAT, 0600));
        atomic_fetch_add(&clock_off, 2000 * 1000);
        CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"wrong, over and over\"}", 401, "wrong_passphrase"));
        CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 503, "passphrase_not_checked"));
        unlink(q);
        rmdir(p);
        CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", 429, "rate_limited"));
    }
    clock_freeze(0);
    fx_stop(&x);
}

static void test_review_words(void)
{
    fixture x;
    resp r;
    char id[64], body[400], other[64];
    int i;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    if (fx_go(&x)) { CHECK(0); return; }
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    snprintf(other, sizeof other, "%s", g_session);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    /* check-id-any-session: a check_id belongs to the session that started it */
    api(&x, &r, "POST", "/api/v1/wallet/phrase/check-start", "{}", NULL);
    CHECK(r.status == 200);
    snprintf(id, sizeof id, "%s", jfield(&r, "check_id") ? jfield(&r, "check_id") : "");
    resp_free(&r);
    {
        char mine[64];
        snprintf(mine, sizeof mine, "%s", g_session);
        snprintf(g_session, sizeof g_session, "%s", other);
        snprintf(body, sizeof body, "{\"check_id\":\"%s\",\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\",\"words\":[\"a\",\"b\",\"c\"]}", id);
        CHECK(expect(&x, "POST", "/api/v1/wallet/phrase/check", body, 400, "bad_value"));
        snprintf(g_session, sizeof g_session, "%s", mine);
    }
    /* checks-left-zero-ok: three checks a day; a fourth is refused before any derivation */
    for (i = 0; i < 3; i++) {
        api(&x, &r, "POST", "/api/v1/wallet/phrase/check-start", "{}", NULL);
        snprintf(id, sizeof id, "%s", jfield(&r, "check_id") ? jfield(&r, "check_id") : "");
        resp_free(&r);
        snprintf(body, sizeof body, "{\"check_id\":\"%s\",\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\",\"words\":[\"abandon\",\"abandon\",\"abandon\"]}", id);
        api(&x, &r, "POST", "/api/v1/wallet/phrase/check", body, NULL);
        CHECK(r.status == 200);
        resp_free(&r);
        sign_in(&x, GZ_FAKE_PASSPHRASE);               /* a failed check ends the session (4.9) */
    }
    api(&x, &r, "POST", "/api/v1/wallet/phrase/check-start", "{}", NULL);
    snprintf(id, sizeof id, "%s", jfield(&r, "check_id") ? jfield(&r, "check_id") : "");
    resp_free(&r);
    {
        int64_t before = FAKE_READ(&x, x.fake.derivations);
        snprintf(body, sizeof body, "{\"check_id\":\"%s\",\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\",\"words\":[\"abandon\",\"abandon\",\"abandon\"]}", id);
        CHECK(expect(&x, "POST", "/api/v1/wallet/phrase/check", body, 429, "rate_limited"));
        CHECK(FAKE_READ(&x, x.fake.derivations) == before);
    }
    fx_stop(&x);
}

/* token-dir-mode-any: a token folder that is not owner-only is refused, and status says so (F5.5) */
static void test_review_token_dir(void)
{
    fixture x;
    resp r;
    char d[300];
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    token_dir_of(&x, d);
    CHECK(mkdir(d, 0755) == 0);
    chmod(d, 0755);
    if (fx_go(&x)) { CHECK(0); return; }
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    {
        char p[340];
        snprintf(p, sizeof p, "%s/socket.token", d);
        CHECK(access(p, F_OK) != 0);
    }
    api(&x, &r, "GET", "/api/v1/status", NULL, NULL);
    CHECK(r.status == 200 && r.body && strstr(r.body, "\"socket_token\":\"folder_refused\""));
    resp_free(&r);
    fx_stop(&x);
    rmdir(d);
}

/* head-deadline-off, body-deadline-idle: the head and body limits, not the idle one */
static int closed_within(int fd, int ms)
{
    char b[512];
    int64_t t0 = real_now();
    for (;;) {
        struct pollfd p = {fd, POLLIN, 0};
        int left = ms - (int)(real_now() - t0);
        ssize_t n;
        if (left <= 0) return 0;
        if (poll(&p, 1, left) <= 0) return 0;
        n = recv(fd, b, sizeof b, 0);
        if (n <= 0) return 1;
    }
}

static void test_review_deadlines(void)
{
    fixture x;
    char req[300];
    int fd, i;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    x.cfg.limits.head_ms = 800;
    x.cfg.limits.body_ms = 800;
    x.cfg.limits.idle_ms = 20000;
    if (fx_go(&x)) { CHECK(0); return; }
    /* a head sent a byte at a time is closed at head_ms from its first byte */
    fd = tcp_connect(x.port);
    snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n", x.port);
    for (i = 0; i < 6; i++) { send(fd, req + i, 1, MSG_NOSIGNAL); sleep_ms(150); }
    CHECK(closed_within(fd, 2500));
    close(fd);
    /* a body that stops is closed at body_ms */
    fd = tcp_connect(x.port);
    snprintf(req, sizeof req, "POST /api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n"
                              "Content-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"pa", x.port, x.port);
    send(fd, req, strlen(req), MSG_NOSIGNAL);
    CHECK(closed_within(fd, 2500));
    close(fd);
    fx_stop(&x);
}

/* merge-off, stream-unsent-unbounded: events of one topic merge; a stream nobody reads is closed */
static void test_review_streams(void)
{
    fixture x;
    char req[600], buf[16384];
    int fd, n, k, seen = 0;
    gz_api_counters ctr;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.cfg.limits.merge_ms = 400;
    x.cfg.limits.stream_unsent_max = 4096;
    if (fx_go(&x)) { CHECK(0); return; }
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    n = snprintf(req, sizeof req, "GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Gazpacho-Session: %s\r\n"
                                  "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Dest: empty\r\n\r\n", x.port, g_session);
    fd = tcp_connect(x.port);
    send(fd, req, (size_t)n, MSG_NOSIGNAL);
    sleep_ms(300);
    while (recv(fd, buf, sizeof buf, MSG_DONTWAIT) > 0) {
    }
    gz_api_notify(x.srv, "factory", "fac_merge");
    gz_api_notify(x.srv, "factory", "fac_merge");
    gz_api_notify(x.srv, "factory", "fac_merge");
    sleep_ms(150);                                      /* inside the merge window */
    k = (int)recv(fd, buf, sizeof buf - 1, MSG_DONTWAIT);
    buf[k > 0 ? k : 0] = 0;
    {
        const char *p = buf;
        while ((p = strstr(p, "fac_merge"))) { seen++; p++; }
    }
    CHECK(seen == 1);
    close(fd);
    /* nobody reads: past stream_unsent_max the stream is closed */
    fd = tcp_connect(x.port);
    {
        int small = 1024;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    }
    send(fd, req, (size_t)n, MSG_NOSIGNAL);
    sleep_ms(300);
    for (k = 0; k < 4000; k++) {
        char id[40];
        snprintf(id, sizeof id, "fac_%d", k);
        gz_api_notify(x.srv, "factory", id);
        if (k % 200 == 0) sleep_ms(20);
    }
    sleep_ms(500);
    fx_counters(&x, &ctr);
    CHECK(ctr.streams_open == 0);
    close(fd);
    fx_stop(&x);
}

/* ---- P5: generations, held answers, node_stopped, one loop ---------------------------------- */
typedef struct { fixture *x; const char *body; int status; char code[48]; } bg_arg;

static void *bg_sign_in(void *a)
{
    bg_arg *b = a;
    resp r;
    api(b->x, &r, "POST", "/api/v1/session", b->body, NULL);
    b->status = r.status;
    snprintf(b->code, sizeof b->code, "%s", jfield(&r, "code") ? jfield(&r, "code") : "");
    resp_free(&r);
    return NULL;
}

static void test_p5_generation(void)
{
    fixture x;
    pthread_t th;
    bg_arg b;
    uint32_t wrong;
    uint64_t last, until;
    int64_t installs;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.fake.pp_delay_ms = 400;
    if (fx_go(&x)) { CHECK(0); return; }
    g_session[0] = 0;
    /* a lock during a right sign-in: discarded, nothing installed (T4.4) */
    installs = FAKE_READ(&x, x.fake.installs);
    memset(&b, 0, sizeof b);
    b.x = &x;
    b.body = "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}";
    pthread_create(&th, NULL, bg_sign_in, &b);
    sleep_ms(150);
    gz_api_server_new_generation(x.srv);
    pthread_join(th, NULL);
    CHECK(b.status == 503 && strcmp(b.code, "passphrase_not_checked") == 0);
    CHECK(FAKE_READ(&x, x.fake.installs) == installs && FAKE_READ(&x, x.fake.wallet) == GZ_API_WALLET_LOCKED);
    /* ... and a wrong one is still counted */
    sleep_ms(1100);
    memset(&b, 0, sizeof b);
    b.x = &x;
    b.body = "{\"passphrase\":\"wrong during a lock\"}";
    pthread_create(&th, NULL, bg_sign_in, &b);
    sleep_ms(150);
    gz_api_server_new_generation(x.srv);
    pthread_join(th, NULL);
    CHECK(b.status == 503);
    CHECK(read_attempts(&x, &wrong, &last, &until) == 0 && wrong == 1);
    fx_stop(&x);
}

static int no_answer_yet(int fd, int ms)
{
    struct pollfd p = {fd, POLLIN, 0};
    return poll(&p, 1, ms) == 0;
}

static int api_open(fixture *x, const char *method, const char *path, const char *body)
{
    char req[4000];
    int fd = tcp_connect(x->port);
    int n = snprintf(req, sizeof req,
                     "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\nSec-Fetch-Site: same-origin\r\n"
                     "Sec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\nX-Gazpacho-Session: %s\r\nConnection: close\r\n"
                     "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s",
                     method, path, x->port, x->port, g_session, strlen(body), body);
    send(fd, req, (size_t)n, MSG_NOSIGNAL);
    return fd;
}

static void test_p5_held(void)
{
    fixture x;
    resp r;
    int fd, fd2;
    char path[80], digest[80], join1[300], join2[300];
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.cfg.limits.held_ms = 600;
    if (fx_go(&x)) { CHECK(0); return; }
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    /* an acting call answers only once its save is confirmed */
    pthread_mutex_lock(&x.fake.mu);
    x.fake.hold = 1;
    pthread_mutex_unlock(&x.fake.mu);
    fd = api_open(&x, "PUT", "/api/v1/pause", "{\"on\":true}");
    CHECK(no_answer_yet(fd, 200));
    gz_fake_release(&x.fake);
    read_answer(fd, &r, 2000);
    CHECK(r.status == 200);
    resp_free(&r);
    close(fd);
    /* resume (kind B: the sign-in's fresh window), held the same way */
    fd = api_open(&x, "PUT", "/api/v1/pause", "{\"on\":false,\"confirm\":\"resume\"}");
    CHECK(no_answer_yet(fd, 200));
    gz_fake_release(&x.fake);
    read_answer(fd, &r, 2000);
    CHECK(r.status == 200 && r.body && strstr(r.body, "\"state\":\"off\""));
    resp_free(&r);
    close(fd);
    /* no outcome within held_ms: 503 node_busy; the retry is held, not acted again */
    pthread_mutex_lock(&x.fake.mu);
    x.fake.hold_forever = 1;
    pthread_mutex_unlock(&x.fake.mu);
    snprintf(path, sizeof path, "/api/v1/lobbies/%s/join", "lob_7k2q");
    api(&x, &r, "GET", "/api/v1/lobbies/lob_7k2q", NULL, NULL);
    {
        char *p = r.body ? strstr(r.body, "\"digest\":\"") : NULL;
        snprintf(digest, sizeof digest, "%.64s", p ? p + 10 : "");
    }
    resp_free(&r);
    snprintf(join1, sizeof join1, "{\"request_id\":\"rid-held-0000000001\",\"seen_current_digest\":\"%s\"}", digest);
    snprintf(join2, sizeof join2, "{\"request_id\":\"rid-held-0000000002\"}");   /* a leave */
    {
        int64_t acted = FAKE_READ(&x, x.fake.acted);
        fd = api_open(&x, "POST", path, join1);
        read_answer(fd, &r, 3000);
        CHECK(is_code(&r, 503, "node_busy"));
        resp_free(&r);
        close(fd);
        fd2 = api_open(&x, "POST", path, join1);
        CHECK(no_answer_yet(fd2, 200));
        CHECK(FAKE_READ(&x, x.fake.acted) == acted + 1);
        pthread_mutex_lock(&x.fake.mu);
        x.fake.hold_forever = 0;
        pthread_mutex_unlock(&x.fake.mu);
        gz_fake_release(&x.fake);
        read_answer(fd2, &r, 2000);
        CHECK(r.status == 202 && r.body && strstr(r.body, "\"replayed\":true"));
        resp_free(&r);
        close(fd2);
        CHECK(FAKE_READ(&x, x.fake.acted) == acted + 1);
        /* the same id with another body: the engine's 409 */
        api(&x, &r, "POST", path, "{\"request_id\":\"rid-held-0000000001\",\"seen_current_digest\":\""
                                  "1111111111111111111111111111111111111111111111111111111111111111\"}", NULL);
        CHECK(is_code(&r, 409, "request_id_reused"));
        resp_free(&r);
    }
    /* a restart of the node: held calls answer 503 node_stopped, reason rebuilding */
    pthread_mutex_lock(&x.fake.mu);
    x.fake.hold_forever = 1;
    pthread_mutex_unlock(&x.fake.mu);
    fd = api_open(&x, "POST", "/api/v1/lobbies/lob_7k2q/leave", join2);
    sleep_ms(150);
    gz_api_server_node_stopped(x.srv, "rebuilding");
    read_answer(fd, &r, 2000);
    CHECK(is_code(&r, 503, "node_stopped") && strstr(r.body, "\"reason\":\"rebuilding\""));
    resp_free(&r);
    close(fd);
    pthread_mutex_lock(&x.fake.mu);
    x.fake.hold_forever = 0;
    x.fake.hold = 0;
    pthread_mutex_unlock(&x.fake.mu);
    gz_fake_release(&x.fake);
    fx_stop(&x);
}

/* dispatch never spins: an idle server uses next to no CPU (T4.3 style) */
static void test_p5_idle(void)
{
    fixture x;
    struct timespec a, b;
    int64_t used;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    if (fx_go(&x)) { CHECK(0); return; }
    sleep_ms(200);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &a);
    sleep_ms(2000);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &b);
    used = (int64_t)(b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
    if (used >= 100) printf("  idle CPU %lld ms in 2 s\n", (long long)used);
    CHECK(used < 100);
    /* shutdown, first step: listeners close (the loop has stopped) */
    gz_api_server_stop(x.srv);
    pthread_join(x.th, NULL);
    gz_api_server_stop_listening(x.srv);
    CHECK(tcp_connect(x.port) < 0);
    CHECK(access(gz_api_server_socket_path(x.srv), F_OK) != 0);
    gz_api_server_free(x.srv);
    x.srv = NULL;
    fx_stop(&x);
}

/* ---- review B of PR 26 (B1-B4, B6) and review A's last two survivors ----------------------- */
static int api_open_as(fixture *x, const char *method, const char *path, const char *body, const char *session)
{
    char req[8000], sh[128];
    int fd = tcp_connect(x->port), n;
    sh[0] = 0;
    if (session && session[0]) snprintf(sh, sizeof sh, "X-Gazpacho-Session: %s\r\n", session);
    n = snprintf(req, sizeof req,
                 "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\nSec-Fetch-Site: same-origin\r\n"
                 "Sec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n%sConnection: close\r\n"
                 "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s",
                 method, path, x->port, x->port, sh, strlen(body), body);
    if (fd >= 0 && n > 0 && n < (int)sizeof req) send(fd, req, (size_t)n, MSG_NOSIGNAL);
    return fd;
}

static int sock_open(fixture *x, const char *req)
{
    int fd = unix_connect(gz_api_server_socket_path(x->srv));
    if (fd >= 0) send(fd, req, strlen(req), MSG_NOSIGNAL);
    return fd;
}

static int stream_open_tcp(fixture *x, const char *session, const char *lei)
{
    char req[600], lh[120];
    int fd = tcp_connect(x->port), n;
    lh[0] = 0;
    if (lei) snprintf(lh, sizeof lh, "Last-Event-ID: %s\r\n", lei);
    n = snprintf(req, sizeof req, "GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Gazpacho-Session: %s\r\n"
                                  "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Dest: empty\r\n%s\r\n", x->port, session, lh);
    if (fd >= 0) send(fd, req, (size_t)n, MSG_NOSIGNAL);
    return fd;
}

/* Appends what arrives within ms to buf (NUL-terminated); 1 if the other end closed. */
static int drain(int fd, char *buf, size_t cap, int ms)
{
    size_t len = strlen(buf);
    int64_t t0 = real_now();
    for (;;) {
        struct pollfd p = {fd, POLLIN, 0};
        int left = ms - (int)(real_now() - t0);
        ssize_t n;
        if (left <= 0) return 0;
        if (poll(&p, 1, left) <= 0) return 0;
        if (len + 1 >= cap) {
            char junk[4096];
            if (recv(fd, junk, sizeof junk, 0) <= 0) return 1;
            continue;
        }
        n = recv(fd, buf + len, cap - 1 - len, 0);
        if (n <= 0) return 1;
        len += (size_t)n;
        buf[len] = 0;
    }
}

static int count_of(const char *hay, const char *needle)
{
    int k = 0;
    const char *p = hay;
    while ((p = strstr(p, needle))) { k++; p++; }
    return k;
}

static void host_open_body(fixture *x, char *body, size_t cap, const char *rid)
{
    char draft[600], dd[80];
    resp r;
    snprintf(draft, sizeof draft,
             "{\"name\":\"My first lobby\",\"profile\":\"standard\",\"target\":50,\"minimum\":30,\"deadline_at\":%lld,"
             "\"on_shortfall\":\"cancel\",\"channel_sat\":500000,\"joining_fee_sat\":{\"now\":1000,\"min\":500,\"max\":1500}}",
             (long long)(test_now(NULL) / 1000 + 86400));
    api(x, &r, "POST", "/api/v1/host/preview", draft, NULL);
    snprintf(dd, sizeof dd, "%s", jfield(&r, "draft_digest") ? jfield(&r, "draft_digest") : "");
    resp_free(&r);
    snprintf(body, cap, "{\"request_id\":\"%s\",\"draft\":%s,\"draft_digest\":\"%s\",\"confirm_funding_sat\":37500000,"
                        "\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", rid, draft, dd);
}

/* A connection opened, and accepted, before the clock moves: its request is
 * read in the server's next turn, before an expiry tick can run, so a lazy
 * expiry check is what answers it. */
static int open_idle(fixture *x)
{
    int fd = tcp_connect(x->port);
    sleep_ms(100);
    return fd;
}

static void api_on(fixture *x, int fd, resp *r, const char *method, const char *path, const char *body)
{
    char req[4000];
    int n = snprintf(req, sizeof req,
                     "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n"
                     "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n%s%s%sConnection: close\r\n",
                     method, path, x->port, x->port, g_session[0] ? "X-Gazpacho-Session: " : "", g_session,
                     g_session[0] ? "\r\n" : "");
    if (body)
        n += snprintf(req + n, sizeof req - (size_t)n, "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s",
                      strlen(body), body);
    else
        n += snprintf(req + n, sizeof req - (size_t)n, "\r\n");
    send(fd, req, (size_t)n, MSG_NOSIGNAL);
    read_answer(fd, r, 3000);
    close(fd);
}

#define LOCK_BODY "{\"confirm\":\"lock_wallet\",\"confirm_locked\":\"nobody_watching\"}"
#define REVEAL_BODY "{\"confirm\":\"show_words\",\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}"
#define RIGHT_BODY "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}"

/* B1, T4.4 through POST /wallet/lock (never a hand-made new_generation): a
 * sign-in and a kind A action are submitted, and the lock lands while the
 * sign-in derives. Neither installs, acts or answers success; the waiting one
 * is refused without a derivation. Then a kind A action deriving when the
 * lock lands. */
static void test_b1_lock(void)
{
    fixture x;
    resp r;
    char me[64], body[2400];
    int fd1, fd2;
    int64_t der, acted;
    gz_api_counters ctr;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.fake.pp_delay_ms = 400;
    if (fx_go(&x)) { CHECK(0); return; }
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    snprintf(me, sizeof me, "%s", g_session);
    host_open_body(&x, body, sizeof body, "req_open_b1_000001");
    der = FAKE_READ(&x, x.fake.derivations);
    acted = FAKE_READ(&x, x.fake.acted);
    fd1 = api_open_as(&x, "POST", "/api/v1/session", RIGHT_BODY, NULL);    /* a check: the wallet is unlocked */
    sleep_ms(100);
    fd2 = api_open_as(&x, "POST", "/api/v1/host/lobbies", body, me);     /* waits behind it */
    sleep_ms(100);
    api(&x, &r, "POST", "/api/v1/wallet/lock", LOCK_BODY, NULL);
    CHECK(r.status == 202 && r.body && strstr(r.body, "\"wallet\":\"locked\""));
    resp_free(&r);
    read_answer(fd1, &r, 3000);
    CHECK(is_code(&r, 503, "passphrase_not_checked"));
    resp_free(&r);
    close(fd1);
    read_answer(fd2, &r, 3000);
    CHECK(is_code(&r, 503, "passphrase_not_checked"));
    resp_free(&r);
    close(fd2);
    CHECK(FAKE_READ(&x, x.fake.derivations) == der + 1);
    CHECK(FAKE_READ(&x, x.fake.acted) == acted + 1 && FAKE_READ(&x, x.fake.host_open) == 0);   /* the lock only */
    fx_counters(&x, &ctr);
    CHECK(ctr.sessions_open == 0);                      /* no normal session while locked (4.9) */
    /* a kind A action whose derivation runs when the lock lands */
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    snprintf(me, sizeof me, "%s", g_session);
    host_open_body(&x, body, sizeof body, "req_open_b1_000002");
    acted = FAKE_READ(&x, x.fake.acted);
    fd2 = api_open_as(&x, "POST", "/api/v1/host/lobbies", body, me);
    sleep_ms(150);
    api(&x, &r, "POST", "/api/v1/wallet/lock", LOCK_BODY, NULL);
    CHECK(r.status == 202);
    resp_free(&r);
    read_answer(fd2, &r, 3000);
    CHECK(is_code(&r, 503, "passphrase_not_checked"));
    resp_free(&r);
    close(fd2);
    CHECK(FAKE_READ(&x, x.fake.acted) == acted + 1 && FAKE_READ(&x, x.fake.host_open) == 0);   /* the lock only */
    CHECK(FAKE_READ(&x, x.fake.wallet) == GZ_API_WALLET_LOCKED);
    fx_stop(&x);
}

/* B2: a job whose session (or socket token) ended while it derived answers
 * 401 not_signed_in: no words, no action. */
static void test_b2_ended_session(void)
{
    fixture x;
    resp r;
    char a[64], b[64], tok[64], body[2400], req[1200];
    int fd;
    int64_t acted;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.fake.pp_delay_ms = 400;
    if (fx_go(&x)) { CHECK(0); return; }
    /* revoke-all from another session while the words are derived */
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    snprintf(a, sizeof a, "%s", g_session);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    snprintf(b, sizeof b, "%s", g_session);
    fd = api_open_as(&x, "POST", "/api/v1/wallet/phrase/reveal", REVEAL_BODY, a);
    sleep_ms(150);
    CHECK(expect(&x, "POST", "/api/v1/session/revoke-all", "{\"confirm\":\"revoke_all\"}", 204, NULL));
    read_answer(fd, &r, 3000);
    CHECK(is_code(&r, 401, "not_signed_in") && !strstr(r.body, "\"words\""));
    resp_free(&r);
    close(fd);
    /* the same session signs out */
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    snprintf(a, sizeof a, "%s", g_session);
    fd = api_open_as(&x, "POST", "/api/v1/wallet/phrase/reveal", REVEAL_BODY, a);
    sleep_ms(150);
    CHECK(expect(&x, "DELETE", "/api/v1/session", NULL, 204, NULL));
    read_answer(fd, &r, 3000);
    CHECK(is_code(&r, 401, "not_signed_in") && !strstr(r.body, "\"words\""));
    resp_free(&r);
    close(fd);
    /* a kind A action of a revoked session acts nothing */
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    snprintf(a, sizeof a, "%s", g_session);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    snprintf(b, sizeof b, "%s", g_session);
    host_open_body(&x, body, sizeof body, "req_open_b2_000001");
    acted = FAKE_READ(&x, x.fake.acted);
    fd = api_open_as(&x, "POST", "/api/v1/host/lobbies", body, a);
    sleep_ms(150);
    CHECK(expect(&x, "POST", "/api/v1/session/revoke-all", "{\"confirm\":\"revoke_all\"}", 204, NULL));
    read_answer(fd, &r, 3000);
    CHECK(is_code(&r, 401, "not_signed_in"));
    resp_free(&r);
    close(fd);
    CHECK(FAKE_READ(&x, x.fake.acted) == acted && FAKE_READ(&x, x.fake.host_open) == 0);
    /* the socket token rotated (revoke-all) while a bearer reveal derived */
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    socket_token(&x, tok);
    CHECK(strlen(tok) == 43);
    snprintf(req, sizeof req, "POST /api/v1/wallet/phrase/reveal HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n"
                              "Content-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
             tok, strlen(REVEAL_BODY), REVEAL_BODY);
    fd = sock_open(&x, req);
    sleep_ms(150);
    CHECK(expect(&x, "POST", "/api/v1/session/revoke-all", "{\"confirm\":\"revoke_all\"}", 204, NULL));
    read_answer(fd, &r, 3000);
    CHECK(is_code(&r, 401, "not_signed_in") && !strstr(r.body, "\"words\""));
    resp_free(&r);
    close(fd);
    fx_stop(&x);
}

/* B3: one check_id, one answer: the second request with it, sent while the
 * first derives, is refused at once and starts no derivation. */
static void test_b3_check_id(void)
{
    fixture x;
    resp r;
    char id[64], body[400];
    int fd1, fd2;
    int64_t der;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.fake.pp_delay_ms = 400;
    if (fx_go(&x)) { CHECK(0); return; }
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    api(&x, &r, "POST", "/api/v1/wallet/phrase/check-start", "{}", NULL);
    snprintf(id, sizeof id, "%s", jfield(&r, "check_id") ? jfield(&r, "check_id") : "");
    resp_free(&r);
    snprintf(body, sizeof body, "{\"check_id\":\"%s\",\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\",\"words\":[\"abandon\",\"abandon\",\"abandon\"]}", id);
    der = FAKE_READ(&x, x.fake.derivations);
    fd1 = api_open_as(&x, "POST", "/api/v1/wallet/phrase/check", body, g_session);
    sleep_ms(100);
    fd2 = api_open_as(&x, "POST", "/api/v1/wallet/phrase/check", body, g_session);
    read_answer(fd2, &r, 3000);
    CHECK(is_code(&r, 400, "bad_value") && jfield(&r, "field") && strcmp(jfield(&r, "field"), "/check_id") == 0);
    resp_free(&r);
    close(fd2);
    read_answer(fd1, &r, 3000);
    CHECK(r.status == 200 && r.body && strstr(r.body, "\"ok\":"));
    resp_free(&r);
    close(fd1);
    CHECK(FAKE_READ(&x, x.fake.derivations) == der + 1);
    fx_stop(&x);
}

/* B4: the one-second delay is kept in milliseconds: a wrong passphrase at x.990 s
 * and another at x+1.005 s are one derivation, not two. Also a session past its
 * idle sign-out is refused at once, before the expiry tick (b-lazy-expiry-off). */
static void test_b4_ms_delay(void)
{
    fixture x;
    resp r;
    int64_t der, t;
    clock_freeze(1);
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.cfg.limits.idle_sign_out_ms = 5000;
    if (fx_go(&x)) { CHECK(0); clock_freeze(0); return; }
    t = test_now(NULL) % 1000;
    atomic_fetch_add(&clock_off, (990 - t + 1000) % 1000);
    g_session[0] = 0;
    der = FAKE_READ(&x, x.fake.derivations);
    CHECK(expect(&x, "POST", "/api/v1/session", "{\"passphrase\":\"wrong at the end of a second\"}", 401, "wrong_passphrase"));
    {
        /* the file keeps the delay's end rounded up: x+2, never x+1 (a restart then never shortens it) */
        uint32_t wrong;
        uint64_t last, until;
        CHECK(read_attempts(&x, &wrong, &last, &until) == 0 && (int64_t)until == (test_now(NULL) + 1000 + 999) / 1000);
    }
    atomic_fetch_add(&clock_off, 15);
    api(&x, &r, "POST", "/api/v1/session", "{\"passphrase\":\"wrong just after the second\"}", NULL);
    CHECK(is_code(&r, 429, "rate_limited") && strstr(r.body, "\"retry_after_s\":1}"));
    resp_free(&r);
    CHECK(FAKE_READ(&x, x.fake.derivations) == der + 1);
    atomic_fetch_add(&clock_off, 1000);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    CHECK(strlen(g_session) == 43);
    {
        int fd = open_idle(&x);
        atomic_fetch_add(&clock_off, 6000);
        api_on(&x, fd, &r, "GET", "/api/v1/lobbies", NULL);
        CHECK(is_code(&r, 401, "not_signed_in"));
        resp_free(&r);
    }
    clock_freeze(0);
    fx_stop(&x);
}

/* B6: unlocked status needs a session; a connection closed while its job
 * derives; node_stopped leaves a derivation alone; pipelining; HEAD; the
 * check's positions and expiry. */
static void test_b6_basics(void)
{
    fixture x;
    resp r;
    char req[800], buf[16384], id[64], body[400], keep[64];
    gz_api_counters c0, c1;
    int fd, fd2, i, n;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.fake.pp_delay_ms = 400;
    if (fx_go(&x)) { CHECK(0); return; }
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    /* b-status-unlocked-anyone: unlocked, the full status needs a session */
    snprintf(keep, sizeof keep, "%s", g_session);
    g_session[0] = 0;
    CHECK(expect(&x, "GET", "/api/v1/status", NULL, 401, "not_signed_in"));
    snprintf(g_session, sizeof g_session, "%s", keep);
    /* b-conn-free-job-kept: a connection that closes while its job derives is never answered or used */
    fx_counters(&x, &c0);
    fd = api_open_as(&x, "POST", "/api/v1/session", RIGHT_BODY, NULL);
    sleep_ms(100);
    close(fd);
    sleep_ms(50);
    fd2 = tcp_connect(x.port);                          /* likely the closed one's memory */
    sleep_ms(600);
    CHECK(no_answer_yet(fd2, 50));
    n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", x.port);
    send(fd2, req, (size_t)n, MSG_NOSIGNAL);
    read_answer(fd2, &r, 2000);
    CHECK(r.status == 200 && r.body && strstr(r.body, "\"run_id\""));
    resp_free(&r);
    close(fd2);
    fx_counters(&x, &c1);
    CHECK(c1.sessions_open == c0.sessions_open);
    /* b-node-stopped-hits-derivation: a node stop answers held calls, not a derivation */
    fd = api_open_as(&x, "POST", "/api/v1/session", RIGHT_BODY, NULL);
    sleep_ms(100);
    gz_api_server_node_stopped(x.srv, "rebuilding");
    read_answer(fd, &r, 3000);
    CHECK(r.status == 200);
    resp_free(&r);
    close(fd);
    /* b-pipelined-dropped: a second request in the same packet is served */
    n = snprintf(req, sizeof req, "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                                  "GET /api/v1/version HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", x.port, x.port);
    fd = tcp_connect(x.port);
    send(fd, req, (size_t)n, MSG_NOSIGNAL);
    buf[0] = 0;
    drain(fd, buf, sizeof buf, 2000);
    CHECK(count_of(buf, "HTTP/1.1 200") == 2);
    close(fd);
    /* b-head-sends-body: HEAD has the headers of GET and no body */
    n = snprintf(req, sizeof req, "HEAD / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", x.port);
    fd = tcp_connect(x.port);
    send(fd, req, (size_t)n, MSG_NOSIGNAL);
    buf[0] = 0;
    drain(fd, buf, sizeof buf, 2000);
    {
        const char *e = strstr(buf, "\r\n\r\n"), *cl = strcasestr(buf, "\r\ncontent-length: ");
        CHECK(strncmp(buf, "HTTP/1.1 200", 12) == 0 && e && e[4] == 0 && cl && atol(cl + 18) > 0);
    }
    close(fd);
    /* b-check-positions-repeat: three distinct positions, rising, 1 to 24 */
    for (i = 0; i < 60; i++) {
        int p[3] = {0, 0, 0};
        const char *q;
        api(&x, &r, "POST", "/api/v1/wallet/phrase/check-start", "{}", NULL);
        q = r.body ? strstr(r.body, "\"positions\":[") : NULL;
        CHECK(q && sscanf(q + 13, "%d,%d,%d", &p[0], &p[1], &p[2]) == 3 && 1 <= p[0] && p[0] < p[1] && p[1] < p[2] &&
              p[2] <= 24);
        resp_free(&r);
    }
    /* b-check-id-never-expires: a check_id lives 10 minutes */
    api(&x, &r, "POST", "/api/v1/wallet/phrase/check-start", "{}", NULL);
    snprintf(id, sizeof id, "%s", jfield(&r, "check_id") ? jfield(&r, "check_id") : "");
    resp_free(&r);
    atomic_fetch_add(&clock_off, 601 * 1000);
    sleep_ms(1300);                                     /* the expiry tick runs */
    snprintf(body, sizeof body, "{\"check_id\":\"%s\",\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\",\"words\":[\"a\",\"b\",\"c\"]}", id);
    CHECK(expect(&x, "POST", "/api/v1/wallet/phrase/check", body, 400, "bad_value"));
    fx_stop(&x);
}

/* A's words-check-ungated: while the attempts delay runs, a words check is
 * refused with that delay, before anything else of it (the daily budget
 * included), as every passphrase call is (4.3). */
static void test_b6_words_gate(void)
{
    fixture x;
    resp r;
    char id[64], body[400];
    int i;
    int64_t der;
    clock_freeze(1);
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    if (fx_go(&x)) { CHECK(0); clock_freeze(0); return; }
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    for (i = 0; i < 3; i++) {                           /* the day's three checks */
        api(&x, &r, "POST", "/api/v1/wallet/phrase/check-start", "{}", NULL);
        snprintf(id, sizeof id, "%s", jfield(&r, "check_id") ? jfield(&r, "check_id") : "");
        resp_free(&r);
        snprintf(body, sizeof body, "{\"check_id\":\"%s\",\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\",\"words\":[\"abandon\",\"abandon\",\"abandon\"]}", id);
        CHECK(expect(&x, "POST", "/api/v1/wallet/phrase/check", body, 200, NULL));
        sign_in(&x, GZ_FAKE_PASSPHRASE);                /* a failed check ends the session (4.9) */
    }
    CHECK(expect(&x, "POST", "/api/v1/session/fresh", "{\"passphrase\":\"not it, not it at all\"}", 401, "wrong_passphrase"));
    api(&x, &r, "POST", "/api/v1/wallet/phrase/check-start", "{}", NULL);
    snprintf(id, sizeof id, "%s", jfield(&r, "check_id") ? jfield(&r, "check_id") : "");
    resp_free(&r);
    der = FAKE_READ(&x, x.fake.derivations);
    snprintf(body, sizeof body, "{\"check_id\":\"%s\",\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\",\"words\":[\"abandon\",\"abandon\",\"abandon\"]}", id);
    api(&x, &r, "POST", "/api/v1/wallet/phrase/check", body, NULL);
    CHECK(is_code(&r, 429, "rate_limited") && strstr(r.body, "\"retry_after_s\":1}"));
    resp_free(&r);
    CHECK(FAKE_READ(&x, x.fake.derivations) == der);
    clock_freeze(0);
    fx_stop(&x);
}

/* First-run codes and the start token: a dash only after the fifth symbol;
 * past their lifetime they are refused at once, before the expiry tick; and
 * A's revoke-keeps-start-token: revoke-all closes the first run (4.9). */
static void test_b6_codes(void)
{
    fixture x;
    resp r;
    int fd;
    char code[16], bad[16], body[200], tok[64], path[200];
    clock_freeze(1);
    fx_prepare(&x, GZ_FAKE_FIRST_RUN);
    x.cfg.limits.code_ms = 4000;
    x.cfg.limits.start_token_ms = 8000;
    if (fx_go(&x)) { CHECK(0); clock_freeze(0); return; }
    start_token_from_file(&x, tok);
    CHECK(strlen(tok) == 43);
    CHECK(fx_first_run_code(&x, code) == 0 && strlen(code) == 11 && code[5] == '-');
    g_session[0] = 0;
    snprintf(bad, sizeof bad, "%.4s-%c%.5s", code, code[4], code + 6);
    snprintf(body, sizeof body, "{\"code\":\"%s\"}", bad);
    CHECK(expect(&x, "POST", "/api/v1/session/start", body, 401, "bad_code"));
    fd = open_idle(&x);
    atomic_fetch_add(&clock_off, 5000);
    snprintf(body, sizeof body, "{\"code\":\"%s\"}", code);
    api_on(&x, fd, &r, "POST", "/api/v1/session/start", body);
    CHECK(is_code(&r, 401, "code_expired"));
    resp_free(&r);
    fd = open_idle(&x);
    atomic_fetch_add(&clock_off, 4000);
    snprintf(body, sizeof body, "{\"start_token\":\"%s\"}", tok);
    api_on(&x, fd, &r, "POST", "/api/v1/session/start", body);
    CHECK(is_code(&r, 401, "code_expired"));
    resp_free(&r);
    clock_freeze(0);
    fx_stop(&x);
    /* a wallet that appears by another way than create, as a backend may report
     * one: the person signs in and revokes everything; the first run closes */
    fx_prepare(&x, GZ_FAKE_FIRST_RUN);
    if (fx_go(&x)) { CHECK(0); return; }
    snprintf(path, sizeof path, "%s/first-run.html", x.dir);
    CHECK(access(path, F_OK) == 0);
    pthread_mutex_lock(&x.fake.mu);
    x.fake.wallet = GZ_API_WALLET_LOCKED;
    memcpy(x.fake.pass, GZ_FAKE_PASSPHRASE, strlen(GZ_FAKE_PASSPHRASE));
    x.fake.pass_len = strlen(GZ_FAKE_PASSPHRASE);
    pthread_mutex_unlock(&x.fake.mu);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    CHECK(strlen(g_session) == 43);
    CHECK(expect(&x, "POST", "/api/v1/session/revoke-all", "{\"confirm\":\"revoke_all\"}", 204, NULL));
    CHECK(access(path, F_OK) != 0);
    fx_stop(&x);
}

/* Stream lifetimes: the keep-alive comment; a sign-out ends that session's
 * streams only; its `session` event is a gap no reconnect replays; a lock ends
 * the socket token's streams too. */
static void test_b6_streams(void)
{
    fixture x;
    resp r;
    char a[64], b[64], tok[64], req[600], lei[80];
    char *ba = calloc(1, 65536), *bb = calloc(1, 65536), *bc = calloc(1, 65536), *bs = calloc(1, 65536);
    int fa, fb, fc, fs;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.cfg.limits.keepalive_ms = 300;
    if (fx_go(&x)) { CHECK(0); return; }
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    snprintf(a, sizeof a, "%s", g_session);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    snprintf(b, sizeof b, "%s", g_session);
    fa = stream_open_tcp(&x, a, NULL);
    fb = stream_open_tcp(&x, b, NULL);
    drain(fa, ba, 65536, 800);
    drain(fb, bb, 65536, 100);
    CHECK(strstr(ba, ": keep-alive") != NULL);          /* b-keepalive-never */
    gz_api_notify(x.srv, "factory", "fac_one");
    drain(fb, bb, 65536, 400);
    {
        const char *p = NULL, *q = bb;
        while ((q = strstr(q, "id: "))) { p = q; q++; }
        lei[0] = 0;
        if (p) sscanf(p + 4, "%79[^\n]", lei);
    }
    CHECK(lei[0] && strstr(bb, "fac_one"));
    /* b-signout-ends-all-streams: a's sign-out ends a's stream, not b's */
    snprintf(g_session, sizeof g_session, "%s", a);
    CHECK(expect(&x, "DELETE", "/api/v1/session", NULL, 204, NULL));
    CHECK(drain(fa, ba, 65536, 1500) == 1 && strstr(ba, "\"topic\":\"session\""));
    gz_api_notify(x.srv, "factory", "fac_two");
    bb[0] = 0;
    CHECK(drain(fb, bb, 65536, 700) == 0 && strstr(bb, "fac_two"));
    /* b-replay-gaps: b's reconnect replays fac_two, never a's own event */
    fc = stream_open_tcp(&x, b, lei);
    CHECK(drain(fc, bc, 65536, 500) == 0 && strstr(bc, "fac_two") && !strstr(bc, "\"topic\":\"\""));
    close(fc);
    /* b-bearer-streams-survive: a lock ends the socket token's streams */
    socket_token(&x, tok);
    snprintf(req, sizeof req, "GET /api/v1/events HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n\r\n", tok);
    fs = sock_open(&x, req);
    drain(fs, bs, 65536, 300);
    CHECK(strncmp(bs, "HTTP/1.1 200", 12) == 0);
    snprintf(g_session, sizeof g_session, "%s", b);
    api(&x, &r, "POST", "/api/v1/wallet/lock", LOCK_BODY, NULL);
    CHECK(r.status == 202);
    resp_free(&r);
    CHECK(drain(fs, bs, 65536, 1500) == 1 && strstr(bs, "\"topic\":\"session\""));
    close(fa);
    close(fb);
    close(fs);
    free(ba);
    free(bb);
    free(bc);
    free(bs);
    fx_stop(&x);
}

/* b-merge-evict-drops-pending: a merge slot evicted while its event waits
 * sends that event first. */
static void test_b6_merge_evict(void)
{
    fixture x;
    char *buf = calloc(1, 1 << 17);
    int fs, i;
    clock_freeze(1);
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.cfg.limits.merge_ms = 60000;
    if (fx_go(&x)) { CHECK(0); clock_freeze(0); return; }
    gz_api_notify(x.srv, "factory", "fac_pend");        /* the run's first event: the oldest merge slot */
    sleep_ms(100);
    atomic_fetch_add(&clock_off, 10);
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    fs = stream_open_tcp(&x, g_session, NULL);
    drain(fs, buf, 1 << 17, 300);
    buf[0] = 0;
    gz_api_notify(x.srv, "factory", "fac_pend");        /* inside its window: waits */
    sleep_ms(50);
    for (i = 0; i < 80; i++) {                          /* fills every slot, then evicts the oldest */
        char id[16];
        snprintf(id, sizeof id, "fac_n%d", i);
        gz_api_notify(x.srv, "factory", id);
        if (i % 20 == 19) sleep_ms(50);
    }
    drain(fs, buf, 1 << 17, 500);
    CHECK(count_of(buf, "\"id\":\"fac_pend\"") == 1 && strstr(buf, "fac_n79"));
    close(fs);
    free(buf);
    clock_freeze(0);
    fx_stop(&x);
}

/* b-emit-to-closing-stream: once a stream has its `session` event and is
 * closing, no later event is added to it. The client reads nothing for a
 * while so the stream's data waits in the server. */
static void test_b6_closing_stream(void)
{
    fixture x;
    struct sockaddr_in sa;
    char req[600];
    char *buf = calloc(1, 4 << 20);
    int fd, n, i, small = 1024;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.cfg.limits.stream_unsent_max = 4 << 20;
    if (fx_go(&x)) { CHECK(0); return; }
    sign_in(&x, GZ_FAKE_PASSPHRASE);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)x.port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0);
    n = snprintf(req, sizeof req, "GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Gazpacho-Session: %s\r\n"
                                  "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Dest: empty\r\n\r\n", x.port, g_session);
    send(fd, req, (size_t)n, MSG_NOSIGNAL);
    sleep_ms(200);
    for (i = 0; i < 3000; i++) {                        /* far more than the kernel's buffers hold */
        char id[16];
        snprintf(id, sizeof id, "fac_f%d", i);
        gz_api_notify(x.srv, "factory", id);
        if (i % 40 == 39) sleep_ms(5);              /* fast: the stream must back up in the server; an
                                                       overfull notify queue only turns an event into reset */
    }
    sleep_ms(200);
    CHECK(expect(&x, "DELETE", "/api/v1/session", NULL, 204, NULL));
    gz_api_notify(x.srv, "factory", "fac_late");
    sleep_ms(200);
    CHECK(drain(fd, buf, 4 << 20, 30000) == 1);
    CHECK(strstr(buf, "fac_f1") && strstr(buf, "\"topic\":\"session\"") && !strstr(buf, "fac_late"));
    close(fd);
    free(buf);
    fx_stop(&x);
}

/* b-stop-queued-leaked: at shutdown the running and the waiting job are both
 * answered 503 passphrase_not_checked, and freed. */
static void test_b6_shutdown(void)
{
    fixture x;
    resp r;
    int fd1, fd2;
    fx_prepare(&x, GZ_FAKE_LOCKED);
    write_attempts(&x, "signet", 0, 0, 0);
    x.fake.pp_delay_ms = 600;
    if (fx_go(&x)) { CHECK(0); return; }
    g_session[0] = 0;
    fd1 = api_open_as(&x, "POST", "/api/v1/session", RIGHT_BODY, NULL);
    sleep_ms(100);
    fd2 = api_open_as(&x, "POST", "/api/v1/session", RIGHT_BODY, NULL);
    sleep_ms(100);
    fx_halt(&x);
    read_answer(fd2, &r, 2000);
    CHECK(is_code(&r, 503, "passphrase_not_checked"));
    resp_free(&r);
    read_answer(fd1, &r, 2000);
    CHECK(is_code(&r, 503, "passphrase_not_checked"));
    resp_free(&r);
    close(fd1);
    close(fd2);
    fx_stop(&x);
}

int main(void)
{
    test_binding();
    test_tunnel();
    test_walls();
    test_timeouts();
    test_other_user();
    test_sessions();
    test_attempts();
    clock_freeze(0);
    test_flood();
    test_request_ids();
    test_reserved();
    test_bodies();
    test_events();
    test_files_behind_and_socket();
    test_review_walls();
    test_review_setup();
    test_review_attempts();
    test_review_words();
    test_review_token_dir();
    test_review_deadlines();
    test_review_streams();
    test_p5_generation();
    test_p5_held();
    test_p5_idle();
    test_b1_lock();
    test_b2_ended_session();
    test_b3_check_id();
    test_b4_ms_delay();
    test_b6_basics();
    test_b6_words_gate();
    test_b6_codes();
    test_b6_streams();
    test_b6_merge_evict();
    test_b6_closing_stream();
    test_b6_shutdown();
    return check_done();
}
