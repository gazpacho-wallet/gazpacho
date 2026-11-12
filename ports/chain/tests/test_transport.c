/*
 * The libcurl transport against servers on this machine: a hostile plain
 * HTTP server and HTTPS servers with good and bad certificates, all started
 * by local-servers.sh (local_server.py). Nothing here leaves 127.0.0.1.
 *
 *   chain_test_transport HTTP_PORT GOOD_PORT WRONGNAME_PORT SELFSIGNED_PORT CA_FILE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/chain_http.h"

static int checks, failed;

#define CHECK(cond)                                                              \
  do {                                                                           \
    checks++;                                                                    \
    if (!(cond)) {                                                               \
      failed++;                                                                  \
      fprintf(stderr, "  %s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
    }                                                                            \
  } while (0)

#define T_CHECK_URL(cond, what)                                                       \
  do {                                                                                \
    checks++;                                                                         \
    if (!(cond)) {                                                                    \
      failed++;                                                                       \
      fprintf(stderr, "  %s:%d: check failed for %s: %s\n", __FILE__, __LINE__, what, #cond); \
    }                                                                                 \
  } while (0)

typedef struct result {
  gz_http_result r;
  long status;
  size_t len;
  uint64_t elapsed_ms;
  uint8_t body[8192];
} result;

static result get(gz_http *h, const char *url, size_t cap, uint32_t timeout_ms) {
  result out;
  gz_http_request req;
  gz_http_response resp;
  memset(&out, 0, sizeof out);
  memset(&req, 0, sizeof req);
  memset(&resp, 0, sizeof resp);
  if (cap > sizeof out.body) cap = sizeof out.body;
  req.url = url;
  req.timeout_ms = timeout_ms;
  uint64_t t0 = h->now_ms(h->ctx);
  out.r = h->request(h->ctx, &req, out.body, cap, &resp);
  out.elapsed_ms = h->now_ms(h->ctx) - t0;
  out.status = resp.status;
  out.len = resp.len;
  return out;
}

int main(int argc, char **argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: %s HTTP_PORT GOOD_PORT WRONGNAME_PORT SELFSIGNED_PORT CA_FILE\n", argv[0]);
    return 2;
  }
  char base[64], url[256];
  snprintf(base, sizeof base, "http://127.0.0.1:%s", argv[1]);
  gz_http h, trusting;
  gz_http_curl_config with_ca = {argv[5]};
  if (!gz_http_curl_create(&h, NULL) || !gz_http_curl_create(&trusting, &with_ca)) return 2;
  result r;

  /* the ordinary case, over plain http to this machine */
  snprintf(url, sizeof url, "%s/ok", base);
  r = get(&h, url, 100, 3000);
  CHECK(r.r == GZ_HTTP_OK && r.status == 200 && r.len == 6 && memcmp(r.body, "330437", 6) == 0);
  snprintf(url, sizeof url, "http://localhost:%s/ok", argv[1]);
  r = get(&h, url, 100, 3000);
  CHECK(r.r == GZ_HTTP_OK && r.status == 200);

  /* what it says about itself, and nothing more */
  snprintf(url, sizeof url, "%s/agent", base);
  r = get(&h, url, 200, 3000);
  CHECK(r.r == GZ_HTTP_OK && r.len == strlen(GZ_HTTP_USER_AGENT) &&
        memcmp(r.body, GZ_HTTP_USER_AGENT, r.len) == 0);

  /* size cap: a stated length above the cap, an unstated one, and a body
   * that never ends. The last must be cut off at the cap, long before the
   * time limit. */
  snprintf(url, sizeof url, "%s/big", base);
  r = get(&h, url, 1000, 3000);
  CHECK(r.r == GZ_HTTP_E_TOO_LARGE && r.len == 0);
  snprintf(url, sizeof url, "%s/bigchunked", base);
  r = get(&h, url, 1000, 3000);
  CHECK(r.r == GZ_HTTP_E_TOO_LARGE);
  snprintf(url, sizeof url, "%s/endless", base);
  r = get(&h, url, 4096, 8000);
  CHECK(r.r == GZ_HTTP_E_TOO_LARGE);
  CHECK(r.elapsed_ms < 3000);
  /* exactly at the cap is fine */
  snprintf(url, sizeof url, "%s/ok", base);
  r = get(&h, url, 6, 3000);
  CHECK(r.r == GZ_HTTP_OK && r.len == 6);
  r = get(&h, url, 5, 3000);
  CHECK(r.r == GZ_HTTP_E_TOO_LARGE);

  /* redirects are reported, not followed */
  snprintf(url, sizeof url, "%s/redir", base);
  r = get(&h, url, 100, 3000);
  CHECK(r.r == GZ_HTTP_OK && r.status == 302 && r.len == 0);

  /* time limit: a server that does not answer, and one that drips */
  snprintf(url, sizeof url, "%s/slow", base);
  r = get(&h, url, 100, 700);
  CHECK(r.r == GZ_HTTP_E_TIMEOUT);
  CHECK(r.elapsed_ms >= 600 && r.elapsed_ms < 3000);
  snprintf(url, sizeof url, "%s/trickle", base);
  r = get(&h, url, 8000, 900);
  CHECK(r.r == GZ_HTTP_E_TIMEOUT && r.elapsed_ms < 3000);

  /* compressed data is not expanded: the body is the 80-odd bytes sent, not
   * the 50,000 they would unpack to */
  snprintf(url, sizeof url, "%s/gzip", base);
  r = get(&h, url, 8192, 3000);
  CHECK(r.r == GZ_HTTP_OK && r.len < 200 && r.body[0] == 0x1f && r.body[1] == 0x8b);
  /* 800 kB of response headers is not swallowed */
  snprintf(url, sizeof url, "%s/hugeheader", base);
  r = get(&h, url, 100, 3000);
  CHECK(r.r != GZ_HTTP_OK);

  /* a POST carries the body as text/plain */
  gz_http_request req;
  gz_http_response resp;
  uint8_t buf[256];
  memset(&req, 0, sizeof req);
  snprintf(url, sizeof url, "%s/post", base);
  req.url = url;
  req.post = true;
  req.body = (const uint8_t *)"0200beef";
  req.body_len = 8;
  req.timeout_ms = 3000;
  CHECK(h.request(h.ctx, &req, buf, sizeof buf, &resp) == GZ_HTTP_OK && resp.status == 200);
  CHECK(resp.len == 19 && memcmp(buf, "text/plain|0200beef", 19) == 0);

  /* plain http anywhere but this machine is refused before anything is
   * sent: at once, not after a connection attempt */
  static const char *not_local[] = {
      "http://192.0.2.1/ok",          "http://example.com/ok",
      "http://localhost.example.com/", "http://127.0.0.1.example.com/",
      "http://127.0.0.2/ok", /* address-check: allow (loopback range, not one of the three names) */
      "ftp://127.0.0.1/ok",
      "file:///etc/hostname",         "gopher://127.0.0.1/",
      "127.0.0.1/ok",
      /* review E: the part before '@' is user information, the host is after it */
      "http://localhost:1@review-check.invalid/api",
      "http://127.0.0.1:1@review-check.invalid/api",
      "http://[::1]:80@review-check.invalid/api",
      "http://localhost@review-check.invalid/api",
      "http://localhost%40review-check.invalid/api",
      "http://localhost\\@review-check.invalid/api",
      "http://LOCALHOST/ok",           /* only the canonical spelling */
      "http://localhost./ok",
      "http://[::1/ok",                /* no closing bracket */
      "http://localhost:/ok",          /* a colon and no port */
      "http://localhost:123456/ok",
      "http://localhost:80x/ok",
  };
  for (size_t i = 0; i < sizeof not_local / sizeof not_local[0]; i++) {
    r = get(&h, not_local[i], 100, 4000);
    T_CHECK_URL(r.r == GZ_HTTP_E_FAILED && r.elapsed_ms < 500, not_local[i]);
  }
  /* user information is refused over https too, before anything is sent */
  snprintf(url, sizeof url, "https://user@localhost:%s/ok", argv[2]);
  r = get(&trusting, url, 100, 5000);
  T_CHECK_URL(r.r == GZ_HTTP_E_FAILED && r.elapsed_ms < 500, url);
  snprintf(url, sizeof url, "https://user:pw@localhost:%s/ok", argv[2]);
  r = get(&trusting, url, 100, 5000);
  T_CHECK_URL(r.r == GZ_HTTP_E_FAILED && r.elapsed_ms < 500, url);
  /* the same server without it is reached (the positive control below) */
  /* a path, a query and a fragment after the authority are fine */
  snprintf(url, sizeof url, "%s/ok?x=1", base);
  r = get(&h, url, 100, 3000);
  CHECK(r.r == GZ_HTTP_OK && r.status == 404);
  snprintf(url, sizeof url, "http://[::1]:%s/ok", argv[1]);
  r = get(&h, url, 100, 3000);
  CHECK(r.r == GZ_HTTP_OK || r.r == GZ_HTTP_E_CONNECT); /* allowed; the server listens on IPv4 only */
  /* a request without a time limit is refused */
  snprintf(url, sizeof url, "%s/ok", base);
  r = get(&h, url, 100, 0);
  CHECK(r.r == GZ_HTTP_E_FAILED);

  /* TLS. Positive control first: a certificate for localhost signed by the
   * authority this transport was told to trust. */
  snprintf(url, sizeof url, "https://localhost:%s/ok", argv[2]);
  r = get(&trusting, url, 100, 5000);
  CHECK(r.r == GZ_HTTP_OK && r.status == 200 && r.len == 6);
  /* the same server through a transport that does not know that authority */
  r = get(&h, url, 100, 5000);
  CHECK(r.r == GZ_HTTP_E_CONNECT);
  /* a certificate signed by the trusted authority, but for another name */
  snprintf(url, sizeof url, "https://localhost:%s/ok", argv[3]);
  r = get(&trusting, url, 100, 5000);
  CHECK(r.r == GZ_HTTP_E_CONNECT);
  /* a self-signed certificate for the right name */
  snprintf(url, sizeof url, "https://localhost:%s/ok", argv[4]);
  r = get(&trusting, url, 100, 5000);
  CHECK(r.r == GZ_HTTP_E_CONNECT);
  r = get(&h, url, 100, 5000);
  CHECK(r.r == GZ_HTTP_E_CONNECT);
  /* https to a port that speaks plain http */
  snprintf(url, sizeof url, "https://localhost:%s/ok", argv[1]);
  r = get(&trusting, url, 100, 5000);
  CHECK(r.r != GZ_HTTP_OK);

  gz_http_curl_destroy(&h);
  gz_http_curl_destroy(&trusting);
  printf("test_transport: %d checks, %d failed\n", checks, failed);
  return failed == 0 ? 0 : 1;
}
