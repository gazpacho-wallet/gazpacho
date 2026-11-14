/* SPDX-License-Identifier: MIT */
/* Fuzz target (spec/local-api.md 23.5): the HTTP request parser (llhttp)
 * with every check of sections 3-8 and the routing, on a connection with no
 * socket, against the fake backend with passphrase operations run inline.
 * The first byte chooses raw bytes or a request built from the route table
 * (a valid head, so the fuzzer reaches the handlers), the TCP port or the
 * local socket, and where the input is split into reads. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fake_backend.h"
#include "internal.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n);
int gz_api_route_count(void);
int gz_api_route_info(int i, int *method, const char **pattern, const char **release);

static gz_api_server *srv;
static gz_fake fake;
static char dir[64];

static void cleanup(void)
{
    char p[128];
    if (srv) gz_api_server_free(srv);
    gz_fake_free(&fake);
    snprintf(p, sizeof p, "%s/attempts.gza", dir);
    unlink(p);
    rmdir(dir);
}

static void setup(void)
{
    gz_api_config cfg;
    const char *err;
    snprintf(dir, sizeof dir, "/tmp/gzfuzz-XXXXXX");
    if (!mkdtemp(dir)) abort();
    gz_fake_init(&fake, GZ_FAKE_LOCKED);
    memset(&cfg, 0, sizeof cfg);
    cfg.data_dir = dir;
    cfg.runtime_dir = dir;
    cfg.port = 39735;
    cfg.no_listen = 1;
    cfg.sync_derivation = 1;
    cfg.backend = &gz_fake_backend;
    cfg.backend_ctx = &fake;
    srv = gz_api_server_new(&cfg, &err);
    if (!srv) abort();
    fake.srv = srv;
    atexit(cleanup);
}

static const char *const BODIES[] = {
    "{}", "{\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}", "{\"passphrase\":\"wrong\"}",
    "{\"confirm\":\"revoke_all\"}", "{\"on\":true}", "{\"on\":false,\"confirm\":\"resume\"}",
    "{\"request_id\":\"fuzz_request_000001\",\"seen_current_digest\":\"d0\"}",
    "{\"request_id\":\"fuzz_request_000002\"}", "{\"conditions\":{\"max_joining_fee_sat\":5000}}",
    "{\"conditions\":{\"min_members\":1},\"based_on_version\":7,\"confirm_loosens\":[]}",
    "{\"confirm\":\"show_words\",\"passphrase\":\"" GZ_FAKE_PASSPHRASE "\"}",
    "{\"confirm\":\"lock_wallet\",\"confirm_locked\":\"nobody_watching\"}",
    "{\"host\":\"02c7e1b2a4d6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192@a.example:9735\"}",
    "{\"name\":\"x\",\"target\":5,\"minimum\":3,\"deadline_at\":4000000000,\"channel_sat\":50000}",
    "{\"start_token\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}", "{\"code\":\"ABCDE-FGHJK\"}",
    "{\"preset\":\"everyday\",\"find\":\"browse\"}", "{\"check_id\":\"x\",\"passphrase\":\"p\",\"words\":[\"a\",\"b\",\"c\"]}",
};
static const char *const M[] = {"OTHER", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"};

static size_t build(const uint8_t *d, size_t n, char *out, size_t cap, const char *token)
{
    int nr = gz_api_route_count(), method, k = 0;
    const char *pattern, *rel, *body, *p;
    char path[300], *o = path;
    size_t len, blen;
    gz_api_route_info(d[1] % nr, &method, &pattern, &rel);
    for (p = pattern; *p;) {
        if (*p == '{') {
            static const char *const IDS[] = {"lob_7k2q", "lob_4c08", "fac_2d91", "a19c3b5e7d2f4c11", "q_1", "act_1182", "x"};
            o += sprintf(o, "%s", IDS[(d[2] + k++) % 7]);
            p = strchr(p, '}') + 1;
        } else {
            *o++ = *p++;
        }
    }
    *o = 0;
    body = BODIES[d[3] % (sizeof BODIES / sizeof BODIES[0])];
    blen = strlen(body);
    len = (size_t)snprintf(out, cap,
                           "%s %s%s HTTP/1.1\r\nHost: 127.0.0.1:39735\r\nOrigin: http://127.0.0.1:39735\r\n"
                           "Sec-Fetch-Site: same-origin\r\n%s%s%s%sContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n",
                           M[method], path, (d[4] & 1) ? "?limit=5" : "", (d[4] & 2) ? "X-Gazpacho-Session: " : "",
                           (d[4] & 2) ? token : "", (d[4] & 2) ? "\r\n" : "", (d[4] & 4) ? "X-Gazpacho-User: 1\r\n" : "",
                           method == 1 || method == 2 ? (size_t)0 : blen + (n > 5 ? n - 5 : 0));
    if (method != 1 && method != 2 && len + blen + n < cap) {
        memcpy(out + len, body, blen);
        len += blen;
        if (n > 5) {                                    /* the rest mutates the end of the body */
            memcpy(out + len, d + 5, n - 5);
            len += n - 5;
        }
    }
    return len;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
    static char buf[1 << 17];
    gz_conn *c;
    size_t len, off = 0, step;
    char token[48];
    gz_session *s;
    if (!srv) setup();
    if (n < 5 || n > 60000) return 0;
    /* a fresh fake each time; one valid session to reach the handlers */
    pthread_mutex_destroy(&fake.mu);
    gz_fake_init(&fake, GZ_FAKE_LOCKED);
    fake.srv = srv;
    if (data[0] & 0x40) fake.wallet = GZ_API_WALLET_UNLOCKED;
    s = gz_session_new(srv, (data[0] & 0x20) ? SK_SETUP : SK_NORMAL, "127.0.0.1:39735");
    if (!s) return 0;
    if (data[0] & 0x10) s->fresh_until = INT64_MAX;
    gz_b64url(s->token, sizeof s->token, token);
    if (data[0] & 1) {
        len = build(data, n, buf, sizeof buf, token);
    } else {
        len = n - 1;
        memcpy(buf, data + 1, len);
    }
    c = gz_conn_new(srv, -1, (data[0] & 2) ? 1 : 0);
    if (!c) return 0;
    step = (data[0] & 0x0c) ? (size_t)(1 + (data[0] >> 2) % 17) : len;
    while (off < len && c->state != CS_DEAD) {
        size_t k = len - off < step ? len - off : step;
        gz_conn_input(srv, c, (const uint8_t *)buf + off, k);
        off += k;
        while (c->state == CS_WRITE) gz_conn_after_write(srv, c);
        gz_out_free(&c->out);
    }
    gz_conn_free(srv, c);
    gz_sessions_end_all(srv);
    return 0;
}
