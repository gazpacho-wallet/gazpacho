/*
 * The libcurl implementation of gz_http. HTTPS with certificate checking,
 * no redirects, a hard time limit and a hard size limit on every request.
 * POSIX only (clock_gettime, pthreads).
 *
 * A request runs on libcurl's multi interface with one transfer, so that
 * another thread can end it at once (gz_http_curl_interrupt): the wait for
 * the socket is curl_multi_poll, which curl_multi_wakeup interrupts, and the
 * wait between retries is on a condition variable.
 */
#define _POSIX_C_SOURCE 200809L

#include "gazpacho/chain_http.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>

typedef struct curl_ctx {
  CURL *easy;
  CURLM *multi;
  char *ca_file; /* NULL: the system's certificate authorities */
  char *proxy;   /* NULL: no proxy; else "socks5h://HOST:PORT" */
  /* set and cleared by gz_http_curl_interrupt, from any thread */
  atomic_bool interrupted;
  pthread_mutex_t mu; /* guards the wait in curl_sleep_ms */
  pthread_cond_t cv;  /* on the monotonic clock */
} curl_ctx;

/* How long one wait for the transfer's socket may last before the interrupt
 * flag is looked at again; curl_multi_wakeup normally ends it sooner. */
#define POLL_SLICE_MS 200

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

bool gz_http_proxy_valid(const char *proxy) {
  static const char scheme[] = "socks5h://";
  if (proxy == NULL || proxy[0] == '\0') return true;
  if (strncmp(proxy, scheme, sizeof scheme - 1) != 0) return false;
  const char *auth = proxy + sizeof scheme - 1;
  size_t end = strlen(auth);
  if (end > 0 && auth[end - 1] == '/') end--; /* one trailing slash */
  size_t host_len = 0;
  if (auth[0] == '[') {
    /* an IPv6 address: hex digits, ':' and '.', at least two ':' (so not
     * empty, not "[:]" and not a bracketed IPv4 address) */
    size_t colons = 0;
    host_len = 1;
    while (host_len < end && auth[host_len] != ']') {
      char c = auth[host_len];
      bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
      if (!hex && c != ':' && c != '.') return false;
      if (c == ':') colons++;
      host_len++;
    }
    if (host_len == end || colons < 2) return false;
    host_len++;
  } else {
    /* a name or IPv4 address: labels of letters, digits and '-', separated
     * by single dots; no label empty or starting with '-' */
    bool label_start = true;
    while (host_len < end && auth[host_len] != ':') {
      char c = auth[host_len];
      if (c == '.') {
        if (label_start) return false;
        label_start = true;
      } else if (is_alnum(c) || (c == '-' && !label_start)) {
        label_start = false;
      } else {
        return false;
      }
      host_len++;
    }
    if (label_start) return false; /* empty, or ends with '.' */
  }
  if (host_len >= HOST_CAP) return false;
  /* the port is required (libcurl would otherwise assume 1080), 1 to 65535 */
  if (host_len >= end || auth[host_len] != ':') return false;
  size_t digits = end - host_len - 1;
  if (digits == 0 || digits > 5) return false;
  unsigned long port = 0;
  for (size_t i = host_len + 1; i < end; i++) {
    if (auth[i] < '0' || auth[i] > '9') return false;
    port = port * 10u + (unsigned long)(auth[i] - '0');
  }
  return port >= 1 && port <= 65535;
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
  if (atomic_load(&c->interrupted)) return GZ_HTTP_E_FAILED;

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
  /* The proxy is always set: "" turns proxies off, including those named in
   * the environment (http_proxy, https_proxy, ALL_PROXY), which libcurl
   * would otherwise follow silently. NOPROXY "" likewise overrides NO_PROXY.
   * With a proxy configured, this machine is reached directly. */
  ok = ok && curl_easy_setopt(e, CURLOPT_PROXY, c->proxy != NULL ? c->proxy : "") == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_NOPROXY,
                              c->proxy != NULL ? "localhost,127.0.0.1,::1" : "") == CURLE_OK;
  /* offer "no authentication" only: never GSSAPI, which would start a
   * Kerberos exchange with the proxy and could reveal the user's principal */
  ok = ok && curl_easy_setopt(e, CURLOPT_SOCKS5_AUTH, (long)CURLAUTH_NONE) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_USERAGENT, GZ_HTTP_USER_AGENT) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, on_body) == CURLE_OK;
  ok = ok && curl_easy_setopt(e, CURLOPT_WRITEDATA, &s) == CURLE_OK;
  /* refuse early when the server states a length above the cap; on_body
   * enforces the cap regardless of what the server states */
  ok = ok && curl_easy_setopt(e, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)cap) == CURLE_OK;
  if (ok && req->post) {
    bool json = req->content_type != NULL && strcmp(req->content_type, "application/json") == 0;
    headers = curl_slist_append(headers, json ? "Content-Type: application/json"
                                              : "Content-Type: text/plain");
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

  /* One transfer on the multi handle, driven here, so that an interrupt from
   * another thread ends it between two waits. */
  CURLcode rc = CURLE_FAILED_INIT;
  bool stopped = false;
  if (curl_multi_add_handle(c->multi, e) == CURLM_OK) {
    int running = 1;
    CURLMcode mc = CURLM_OK;
    while (running != 0) {
      mc = curl_multi_perform(c->multi, &running);
      if (mc != CURLM_OK) break;
      if (atomic_load(&c->interrupted)) {
        stopped = true;
        break;
      }
      if (running != 0) {
        mc = curl_multi_poll(c->multi, NULL, 0, POLL_SLICE_MS, NULL);
        if (mc != CURLM_OK) break;
      }
    }
    if (!stopped && mc == CURLM_OK) {
      int left = 0;
      CURLMsg *m;
      while ((m = curl_multi_info_read(c->multi, &left)) != NULL) {
        if (m->msg == CURLMSG_DONE && m->easy_handle == e) rc = m->data.result;
      }
    }
    (void)curl_multi_remove_handle(c->multi, e);
  }
  curl_slist_free_all(headers);
  (void)curl_easy_setopt(e, CURLOPT_CURLU, NULL); /* not kept past this request */
  curl_url_cleanup(parsed);
  if (stopped) return GZ_HTTP_E_FAILED;
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

/* Waits `ms`, or until gz_http_curl_interrupt(.., true). */
static void curl_sleep_ms(void *ctx, uint32_t ms) {
  curl_ctx *c = ctx;
  struct timespec until;
  if (c == NULL || clock_gettime(CLOCK_MONOTONIC, &until) != 0) return;
  until.tv_sec += (time_t)(ms / 1000u);
  until.tv_nsec += (long)(ms % 1000u) * 1000000L;
  if (until.tv_nsec >= 1000000000L) {
    until.tv_sec += 1;
    until.tv_nsec -= 1000000000L;
  }
  pthread_mutex_lock(&c->mu);
  while (!atomic_load(&c->interrupted)) {
    if (pthread_cond_timedwait(&c->cv, &c->mu, &until) == ETIMEDOUT) break;
  }
  pthread_mutex_unlock(&c->mu);
}

void gz_http_curl_interrupt(gz_http *http, bool on) {
  if (http == NULL || http->ctx == NULL || http->request != curl_request) return;
  curl_ctx *c = http->ctx;
  /* the flag changes under the mutex so that a sleeper cannot miss it
   * between its test and its wait */
  pthread_mutex_lock(&c->mu);
  atomic_store(&c->interrupted, on);
  if (on) pthread_cond_broadcast(&c->cv);
  pthread_mutex_unlock(&c->mu);
  if (on) (void)curl_multi_wakeup(c->multi);
}

void gz_http_curl_interrupt_hook(void *http, bool on) { gz_http_curl_interrupt(http, on); }

bool gz_http_curl_async_dns(void) {
  const curl_version_info_data *v = curl_version_info(CURLVERSION_NOW);
  return v != NULL && (v->features & CURL_VERSION_ASYNCHDNS) != 0;
}

bool gz_http_curl_create(gz_http *out, const gz_http_curl_config *cfg) {
  if (out == NULL) return false;
  memset(out, 0, sizeof *out);
  if (cfg != NULL && !gz_http_proxy_valid(cfg->proxy)) return false;
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
  if (cfg != NULL && cfg->proxy != NULL && cfg->proxy[0] != '\0') {
    size_t n = strlen(cfg->proxy);
    c->proxy = malloc(n + 1);
    if (c->proxy != NULL) memcpy(c->proxy, cfg->proxy, n + 1);
  }
  c->easy = curl_easy_init();
  c->multi = curl_multi_init();
  atomic_init(&c->interrupted, false);
  pthread_condattr_t attr;
  bool sync_ok = pthread_mutex_init(&c->mu, NULL) == 0;
  if (sync_ok) {
    sync_ok = pthread_condattr_init(&attr) == 0;
    if (sync_ok) {
      sync_ok = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0 &&
                pthread_cond_init(&c->cv, &attr) == 0;
      pthread_condattr_destroy(&attr);
    }
    if (!sync_ok) pthread_mutex_destroy(&c->mu);
  }
  bool want_proxy = cfg != NULL && cfg->proxy != NULL && cfg->proxy[0] != '\0';
  if (c->easy == NULL || c->multi == NULL || !sync_ok ||
      (cfg != NULL && cfg->ca_file != NULL && c->ca_file == NULL) ||
      (want_proxy && c->proxy == NULL)) {
    if (sync_ok) {
      pthread_cond_destroy(&c->cv);
      pthread_mutex_destroy(&c->mu);
    }
    if (c->easy != NULL) curl_easy_cleanup(c->easy);
    if (c->multi != NULL) curl_multi_cleanup(c->multi);
    free(c->ca_file);
    free(c->proxy);
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
  curl_multi_cleanup(c->multi);
  pthread_cond_destroy(&c->cv);
  pthread_mutex_destroy(&c->mu);
  free(c->ca_file);
  free(c->proxy);
  free(c);
  curl_global_cleanup();
  memset(http, 0, sizeof *http);
}
