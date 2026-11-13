/*
 * gz_http: the small transport the Esplora backend does all its outside
 * effects through: one HTTP request, the clock, and sleeping. Tests replace
 * it with a fake; programs use the libcurl one below.
 */
#ifndef GAZPACHO_CHAIN_HTTP_H
#define GAZPACHO_CHAIN_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum gz_http_result {
  GZ_HTTP_OK = 0,          /* a complete response was received (any status) */
  GZ_HTTP_E_CONNECT = 1,   /* name lookup, connection or TLS failed */
  GZ_HTTP_E_TIMEOUT = 2,   /* the time limit passed */
  GZ_HTTP_E_TOO_LARGE = 3, /* the body is larger than the caller's buffer */
  GZ_HTTP_E_FAILED = 4     /* anything else */
} gz_http_result;

typedef struct gz_http_request {
  const char *url;      /* zero-terminated, absolute */
  bool post;            /* false: GET. true: POST with `body` */
  const uint8_t *body;  /* POST body, sent as text/plain; NULL for GET */
  size_t body_len;
  uint32_t timeout_ms;  /* whole-request limit; never zero */
} gz_http_request;

typedef struct gz_http_response {
  long status; /* HTTP status code */
  size_t len;  /* bytes written to the caller's buffer */
} gz_http_response;

/*
 * The transport. All three functions are required.
 *
 * request: performs one request and writes the response body into buf, at
 *   most `cap` bytes. A body longer than `cap` must make the call fail with
 *   GZ_HTTP_E_TOO_LARGE; it must never be truncated silently, and the
 *   transport must stop reading once the cap is passed. Must not follow
 *   redirects and must return within timeout_ms (plus scheduling noise).
 * now_ms: a clock that never goes backwards, in milliseconds.
 * sleep_ms: waits.
 *
 * The struct is copied by the backend; `ctx` must outlive every backend that
 * uses it.
 */
typedef struct gz_http {
  void *ctx;
  gz_http_result (*request)(void *ctx, const gz_http_request *req, uint8_t *buf, size_t cap,
                            gz_http_response *resp);
  uint64_t (*now_ms)(void *ctx);
  void (*sleep_ms)(void *ctx, uint32_t ms);
} gz_http;

/* What the libcurl transport sends as its User-Agent header on every
 * request. A common browser string (the one Tor Browser sends), so that the
 * header does not tell a chain server that the client is Gazpacho. It says
 * nothing about the user or machine. */
#define GZ_HTTP_USER_AGENT "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"

typedef struct gz_http_curl_config {
  /* Optional. A file of certificate authorities to trust INSTEAD of the
   * system's, for a server the user runs with a private certificate.
   * NULL: the system's authorities. Copied. */
  const char *ca_file;
  /* Optional. A SOCKS5 proxy that resolves names itself, written
   * "socks5h://HOST:PORT" (Tor: "socks5h://127.0.0.1:9050"). Any other
   * scheme, user information or a missing port is refused: the transport is
   * not created. NULL or "": no proxy at all. Either way the proxy
   * environment variables (http_proxy, https_proxy, ALL_PROXY, NO_PROXY and
   * the like) are never used. Requests to this machine (localhost,
   * 127.0.0.1, [::1]) bypass the proxy. Copied. */
  const char *proxy;
} gz_http_curl_config;

/* True if `proxy` is a proxy setting gz_http_curl_create accepts: NULL, "",
 * or "socks5h://HOST:PORT" with a plain host (letters, digits, '.', '-', or
 * an address in brackets) and a port of 1 to 5 digits. */
bool gz_http_proxy_valid(const char *proxy);

/*
 * The libcurl transport (http_curl.c; built only when libcurl is found).
 *
 * - HTTPS only. Plain http is accepted for exactly three hosts, this machine
 *   under its usual names: localhost, 127.0.0.1 and [::1]. Any other http
 *   address is refused before anything is sent (GZ_HTTP_E_FAILED). The host
 *   is read from the URL's authority by a strict parser, and libcurl's own
 *   parse of the URL must find the same host; the request is made with that
 *   parsed URL. A URL with user information ("user@host",
 *   "localhost:1@other-host"), percent-encoding or any other character
 *   outside a plain host and port in its authority is refused, whatever the
 *   scheme.
 * - The server's certificate and host name are always verified.
 * - Redirects are not followed; a 3xx status is returned as it is.
 * - The body is counted as it arrives and the transfer is stopped as soon as
 *   it passes the caller's cap.
 * - Compressed responses are not requested.
 * - The proxy is set explicitly, from `cfg->proxy` only (socks5h or none);
 *   the proxy environment variables are ignored.
 * - POSIX only: it uses clock_gettime and nanosleep. A Windows build needs
 *   another transport behind the same gz_http interface.
 *
 * `cfg` may be NULL for the defaults. On success *out is ready to use;
 * release it with gz_http_curl_destroy. Returns false if libcurl could not
 * be initialised or the proxy setting is refused.
 */
bool gz_http_curl_create(gz_http *out, const gz_http_curl_config *cfg);
void gz_http_curl_destroy(gz_http *http);

#ifdef __cplusplus
}
#endif

#endif /* GAZPACHO_CHAIN_HTTP_H */
