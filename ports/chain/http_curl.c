/*
 * The libcurl implementation of gz_http. HTTPS with certificate checking,
 * no redirects, a hard time limit and a hard size limit on every request.
 * POSIX only (clock_gettime, nanosleep).
 */
#define _POSIX_C_SOURCE 200809L

#include "gazpacho/chain_http.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>

typedef struct curl_ctx {
  CURL *easy;
  char *ca_file; /* NULL: the system's certificate authorities */
} curl_ctx;

typedef struct sink {
  uint8_t *buf;
  size_t cap;
  size_t len;
  bool overflow;
} sink;

static size_t on_body(char *data, size_t size, size_t nmemb, void *userdata) {
  sink *s = userdata;
  size_t n = size * nmemb;
  if (n > s->cap - s->len) {
    s->overflow = true;
    return 0; /* makes libcurl abort the transfer */
  }
  memcpy(s->buf + s->len, data, n);
  s->len += n;
  return n;
}

/* True for http://localhost, http://127.0.0.1 and http://[::1], each
 * followed by a port, a path or nothing. */
static bool is_loopback_http(const char *url) {
  static const char *const hosts[] = {"localhost", "127.0.0.1", "[::1]"};
  if (strncmp(url, "http://", 7) != 0) return false;
  const char *rest = url + 7;
  for (size_t i = 0; i < sizeof hosts / sizeof hosts[0]; i++) {
    size_t n = strlen(hosts[i]);
    if (strncmp(rest, hosts[i], n) == 0 && (rest[n] == '\0' || rest[n] == ':' || rest[n] == '/'))
      return true;
  }
  return false;
}

static gz_http_result curl_request(void *ctx, const gz_http_request *req, uint8_t *buf, size_t cap,
                                   gz_http_response *resp) {
  curl_ctx *c = ctx;
  sink s = {buf, cap, 0, false};
  struct curl_slist *headers = NULL;
  if (c == NULL || req == NULL || req->url == NULL || buf == NULL || resp == NULL ||
      req->timeout_ms == 0)
    return GZ_HTTP_E_FAILED;
  resp->status = 0;
  resp->len = 0;

  /* https only; plain http for this machine alone */
  bool https = strncmp(req->url, "https://", 8) == 0;
  bool local_http = is_loopback_http(req->url);
  if (!https && !local_http) return GZ_HTTP_E_FAILED;

  CURL *e = c->easy;
  curl_easy_reset(e);
  /* Every option matters to safety or to the limits, so a failure to set
   * any of them fails the request instead of running without it. */
  bool ok = true;
  ok = ok && curl_easy_setopt(e, CURLOPT_URL, req->url) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_PROTOCOLS_STR, https ? "https" : "http") == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_FOLLOWLOCATION, 0L) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_NOSIGNAL, 1L) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_NOPROGRESS, 1L) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_TIMEOUT_MS, (long)req->timeout_ms) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_CONNECTTIMEOUT_MS, (long)req->timeout_ms) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_SSL_VERIFYPEER, 1L) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_SSL_VERIFYHOST, 2L) == CURLE_OK;
  if (c->ca_file != NULL) {
    ok = ok && curl_easy_setopt(e, CURLOPT_CAINFO, c->ca_file) == CURLE_OK;
    ok = ok && curl_easy_setopt(e, CURLOPT_CAPATH, NULL) == CURLE_OK;
  }
  ok = ok && curl_easy_setopt(e, CURLOPT_USERAGENT, GZ_HTTP_USER_AGENT) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, on_body) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_WRITEDATA, &s) == CURLE_OK;
  /* refuse early when the server states a length above the cap; on_body
   * enforces the cap regardless of what the server states */
  ok = ok && curl_easy_setopt(e, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)cap) == CURLE_OK;
  if (ok && req->post) {
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    ok = headers != NULL;
    ok = ok && curl_easy_setopt(e, CURLOPT_HTTPHEADER, headers) == CURLE_OK;
    ok = ok && curl_easy_setopt(e, CURLOPT_POST, 1L) == CURLE_OK;
    ok = ok && curl_easy_setopt(e, CURLOPT_POSTFIELDS,
                                req->body != NULL ? (const char *)req->body : "") == CURLE_OK;
    ok = ok && curl_easy_setopt(e, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)req->body_len) ==
                   CURLE_OK;
  }
  if (!ok) {
    curl_slist_free_all(headers);
    return GZ_HTTP_E_FAILED;
  }

  CURLcode rc = curl_easy_perform(e);
  curl_slist_free_all(headers);
  if (s.overflow || rc == CURLE_FILESIZE_EXCEEDED) return GZ_HTTP_E_TOO_LARGE;
  switch (rc) {
    case CURLE_OK: break;
    case CURLE_OPERATION_TIMEDOUT: return GZ_HTTP_E_TIMEOUT;
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_RESOLVE_PROXY:
    case CURLE_COULDNT_CONNECT:
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_PEER_FAILED_VERIFICATION:
    case CURLE_SSL_CERTPROBLEM:
    case CURLE_SSL_CACERT_BADFILE: return GZ_HTTP_E_CONNECT;
    default: return GZ_HTTP_E_FAILED;
  }
  long status = 0;
  if (curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK) return GZ_HTTP_E_FAILED;
  resp->status = status;
  resp->len = s.len;
  return GZ_HTTP_OK;
}

static uint64_t curl_now_ms(void *ctx) {
  struct timespec ts;
  (void)ctx;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void curl_sleep_ms(void *ctx, uint32_t ms) {
  struct timespec ts;
  (void)ctx;
  ts.tv_sec = (time_t)(ms / 1000u);
  ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
  while (nanosleep(&ts, &ts) != 0) {
    /* interrupted: sleep the remainder */
  }
}

bool gz_http_curl_create(gz_http *out, const gz_http_curl_config *cfg) {
  if (out == NULL) return false;
  memset(out, 0, sizeof *out);
  /* libcurl keeps its own process-wide reference count here; this library
   * holds no global state of its own */
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return false;
  curl_ctx *c = calloc(1, sizeof *c);
  if (c == NULL) {
    curl_global_cleanup();
    return false;
  }
  if (cfg != NULL && cfg->ca_file != NULL) {
    size_t n = strlen(cfg->ca_file);
    c->ca_file = malloc(n + 1);
    if (c->ca_file != NULL) memcpy(c->ca_file, cfg->ca_file, n + 1);
  }
  c->easy = curl_easy_init();
  if (c->easy == NULL || (cfg != NULL && cfg->ca_file != NULL && c->ca_file == NULL)) {
    if (c->easy != NULL) curl_easy_cleanup(c->easy);
    free(c->ca_file);
    free(c);
    curl_global_cleanup();
    return false;
  }
  out->ctx = c;
  out->request = curl_request;
  out->now_ms = curl_now_ms;
  out->sleep_ms = curl_sleep_ms;
  return true;
}

void gz_http_curl_destroy(gz_http *http) {
  if (http == NULL || http->ctx == NULL) return;
  curl_ctx *c = http->ctx;
  curl_easy_cleanup(c->easy);
  free(c->ca_file);
  free(c);
  curl_global_cleanup();
  memset(http, 0, sizeof *http);
}
