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

#define HOST_CAP 256

static bool is_alnum(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

/*
 * Reads the scheme and the authority of an absolute URL. True only for
 * "http://" or "https://", then a host, then optionally ':' and a port of 1
 * to 5 digits, then '/', '?', '#' or the end. The host is letters, digits,
 * '.' and '-', or an address in brackets made of hex digits, ':' and '.'.
 * Anything else in the authority makes it false: in particular user
 * information ("user@", "localhost:1@other-host"), percent-encoding and
 * backslashes, which other parsers read differently. Writes the host.
 */
static bool split_url(const char *url, bool *https, char host[HOST_CAP]) {
  size_t scheme;
  if (strncmp(url, "https://", 8) == 0) {
    scheme = 8;
    *https = true;
  } else if (strncmp(url, "http://", 7) == 0) {
    scheme = 7;
    *https = false;
  } else {
    return false;
  }
  const char *auth = url + scheme;
  size_t end = strcspn(auth, "/?#");
  size_t host_len = 0;
  if (auth[0] == '[') {
    while (host_len < end && auth[host_len] != ']') {
      char c = auth[host_len];
      bool ok = host_len == 0 || is_alnum(c) || c == ':' || c == '.';
      if (!ok) return false;
      host_len++;
    }
    if (host_len == end) return false; /* no closing bracket */
    host_len++;
  } else {
    while (host_len < end && auth[host_len] != ':') {
      char c = auth[host_len];
      if (!is_alnum(c) && c != '.' && c != '-') return false;
      host_len++;
    }
  }
  if (host_len == 0 || host_len >= HOST_CAP) return false;
  if (host_len < end) {
    size_t digits = end - host_len - 1;
    if (auth[host_len] != ':' || digits == 0 || digits > 5) return false;
    for (size_t i = host_len + 1; i < end; i++) {
      if (auth[i] < '0' || auth[i] > '9') return false;
    }
  }
  memcpy(host, auth, host_len);
  host[host_len] = '\0';
  return true;
}

/* This machine, under the three names plain http is allowed for. */
static bool is_loopback_host(const char *host) {
  return strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0 ||
         strcmp(host, "[::1]") == 0;
}

/*
 * Has libcurl parse the URL too, and requires that it finds the same host
 * and no user name or password. The parsed handle is what the request is
 * then made with (CURLOPT_CURLU), so the URL checked is the URL used.
 * NULL if libcurl reads it differently or cannot parse it.
 */
static CURLU *parse_with_curl(const char *url, const char *host) {
  CURLU *u = curl_url();
  char *got = NULL;
  bool ok = u != NULL && curl_url_set(u, CURLUPART_URL, url, 0) == CURLUE_OK;
  ok = ok && curl_url_get(u, CURLUPART_USER, &got, 0) == CURLUE_NO_USER;
  ok = ok && curl_url_get(u, CURLUPART_PASSWORD, &got, 0) == CURLUE_NO_PASSWORD;
  ok = ok && curl_url_get(u, CURLUPART_HOST, &got, 0) == CURLUE_OK && got != NULL &&
       strcmp(got, host) == 0;
  curl_free(got);
  if (!ok) {
    curl_url_cleanup(u);
    return NULL;
  }
  return u;
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

  /* https only; plain http for this machine alone; never user information */
  bool https = false;
  char host[HOST_CAP];
  if (!split_url(req->url, &https, host)) return GZ_HTTP_E_FAILED;
  bool local_http = !https && is_loopback_host(host);
  if (!https && !local_http) return GZ_HTTP_E_FAILED;
  CURLU *parsed = parse_with_curl(req->url, host);
  if (parsed == NULL) return GZ_HTTP_E_FAILED;

  CURL *e = c->easy;
  curl_easy_reset(e);
  /* Every option matters to safety or to the limits, so a failure to set
   * any of them fails the request instead of running without it. */
  bool ok = true;
  ok = ok && curl_easy_setopt(e, CURLOPT_CURLU, parsed) == CURLE_OK;
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
    curl_easy_reset(e);
    curl_url_cleanup(parsed);
    return GZ_HTTP_E_FAILED;
  }

  CURLcode rc = curl_easy_perform(e);
  curl_slist_free_all(headers);
  (void)curl_easy_setopt(e, CURLOPT_CURLU, NULL); /* not kept past this request */
  curl_url_cleanup(parsed);
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
