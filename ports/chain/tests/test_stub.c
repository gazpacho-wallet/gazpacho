/*
 * The chain worker over real HTTP: the libcurl transport, two Esplora
 * backends and the comparing backend against tests/watch_stub.py, which
 * plays two chain servers from the scenes this program publishes (the
 * made-up chain of sim.h, written out by sim_dump). Run by watch-stub.sh.
 *
 *   chain_test_stub PORT WORKDIR
 *
 * Each scenario states the exact sequence of events. GZ_CHAINW_SOURCES
 * events are followed apart from that sequence (await_sources): the two
 * servers cannot be changed in one instant, so a pass that falls between the
 * two changes may see one server behind for a moment.
 */
#define _POSIX_C_SOURCE 200809L

#include <poll.h>
#include <sys/stat.h>
#include <time.h>

#include "test.h"

#include "gazpacho/chain_esplora.h"
#include "simtest.h"

static int g_port;
static const char *g_work;
static unsigned g_scene;
static long g_mark[2]; /* asked() looks at the stub logs from here on */

typedef struct sx {
  sim_net net; /* the model only: what the two servers are to say */
  gz_http http;
  gz_chain server[2], multi;
  gz_chainw_config cfg;
  gz_chainw *w;
  char extra[2][128]; /* fault lines for each server (watch_stub.py) */
  char log[8192];
  gz_chain_result sources;
} sx;

static uint64_t ms_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void nap(unsigned ms) {
  struct timespec ts = {ms / 1000u, (long)(ms % 1000u) * 1000000L};
  nanosleep(&ts, NULL);
}

static void die(const char *what) {
  fprintf(stderr, "chain_test_stub: %s\n", what);
  exit(2);
}

/* Writes the scene and switches the stub to it in one rename. */
static void publish(sx *x) {
  char dir[600], path[700], tmp[700];
  snprintf(dir, sizeof dir, "%s/s%u", g_work, ++g_scene);
  if (mkdir(dir, 0700) != 0) die("cannot make a scene directory");
  for (int i = 0; i < 2; i++) {
    snprintf(path, sizeof path, "%s/%c.routes", dir, "ab"[i]);
    FILE *f = fopen(path, "w");
    if (f == NULL) die("cannot write a scene");
    sim_dump(&x->net.view[i], f);
    if (x->extra[i][0] != 0) fprintf(f, "%s\n", x->extra[i]);
    fclose(f);
  }
  snprintf(tmp, sizeof tmp, "%s/current.tmp", g_work);
  snprintf(path, sizeof path, "%s/current", g_work);
  FILE *f = fopen(tmp, "w");
  if (f == NULL) die("cannot write the scene name");
  fprintf(f, "s%u\n", g_scene);
  fclose(f);
  if (rename(tmp, path) != 0) die("cannot switch the scene");
}

static void sx_open(sx *x, uint32_t timeout_ms) {
  static const char *const host[2] = {"127.0.0.1", "localhost"};
  static const char *const op[2] = {"op-a", "op-b"};
  char base[128];
  memset(x, 0, sizeof *x);
  sim_net_init(&x->net, false);
  if (!gz_http_curl_create(&x->http, NULL)) die("cannot set up the transport");
  for (int i = 0; i < 2; i++) {
    gz_esplora_config c;
    gz_esplora_config_default(&c);
    snprintf(base, sizeof base, "http://%s:%d/%c", host[i], g_port, "ab"[i]);
    c.base_url = base;
    c.operator_id = op[i];
    c.timeout_ms = timeout_ms;
    c.max_attempts = 1;
    c.backoff_ms = 1;
    c.min_interval_ms = 0;
    if (gz_esplora_create(&c, &x->http, &x->server[i]) != GZ_CHAIN_OK) die("cannot make a backend");
  }
  gz_multi_config mc;
  gz_multi_config_default(&mc, GZ_NET_SIGNET);
  mc.now_ms = x->http.now_ms;
  mc.clock_ctx = x->http.ctx;
  if (gz_multi_create(&mc, x->server, 2, &x->multi) != GZ_CHAIN_OK) die("cannot compare servers");
  gz_chainw_config_default(&x->cfg, &x->multi, GZ_NET_SIGNET);
  x->cfg.tip_poll_ms = 80;
  x->cfg.retry_ms = 80;
  x->cfg.retry_max_ms = 320;
  x->cfg.max_watches = 8;
  x->cfg.broadcast_attempts = 3;
  x->cfg.broadcast_backoff_ms = 40;
  x->cfg.broadcast_backoff_max_ms = 80;
  x->cfg.header_window = 16;
  x->cfg.max_catchup = 6;
  x->cfg.interrupt = gz_http_curl_interrupt_hook;
  x->cfg.interrupt_ctx = &x->http;
  x->sources = GZ_CHAIN_OK;
}

static void sx_start(sx *x) {
  publish(x);
  x->w = gz_chainw_new(&x->cfg);
  if (x->w == NULL) die("cannot start the worker");
}

static void sx_close(sx *x) {
  gz_chainw_free(x->w);
  gz_chain_destroy(&x->multi);
  gz_chain_destroy(&x->server[0]);
  gz_chain_destroy(&x->server[1]);
  gz_http_curl_destroy(&x->http);
  sim_net_free(&x->net);
}

static void both(sx *x, int branch, uint32_t tip) {
  for (int i = 0; i < 2; i++) {
    x->net.view[i].branch = branch;
    x->net.view[i].tip = tip;
  }
}
static void pool(sx *x, int tx, bool in) { x->net.view[0].mempool[tx] = x->net.view[1].mempool[tx] = in; }

static void drain(sx *x) {
  gz_chainw_event ev;
  while (gz_chainw_take(x->w, &ev)) {
    if (ev.kind == GZ_CHAINW_SOURCES) {
      x->sources = ev.sources;
      continue;
    }
    size_t at = strlen(x->log);
    if (at + 200 >= sizeof x->log) continue;
    if (at) at += (size_t)snprintf(x->log + at, sizeof x->log - at, " | ");
    st_format(&x->net.world, &ev, x->log + at, sizeof x->log - at);
  }
}

static void wait_fd(sx *x, uint64_t end) {
  uint64_t now = ms_now();
  struct pollfd p = {gz_chainw_fd(x->w), POLLIN, 0};
  if (now < end) (void)poll(&p, 1, (int)(end - now > 100 ? 100 : end - now));
}

/* True once the log ends with `want`. */
static bool await(sx *x, const char *want, unsigned limit_ms) {
  uint64_t end = ms_now() + limit_ms;
  size_t wl = strlen(want);
  for (;;) {
    drain(x);
    size_t ll = strlen(x->log);
    if (ll >= wl && strcmp(x->log + ll - wl, want) == 0) return true;
    if (ms_now() >= end) return false;
    wait_fd(x, end);
  }
}

/* True once the servers are worth `want`. */
static bool await_sources(sx *x, gz_chain_result want, unsigned limit_ms) {
  uint64_t end = ms_now() + limit_ms;
  for (;;) {
    drain(x);
    if (x->sources == want) return true;
    if (ms_now() >= end) return false;
    wait_fd(x, end);
  }
}

/* Bytes the stub has logged for a server so far. */
static long log_size(int server) {
  char path[700];
  long size = 0;
  snprintf(path, sizeof path, "%s/%c.log", g_work, "ab"[server]);
  FILE *f = fopen(path, "r");
  if (f == NULL) return 0;
  if (fseek(f, 0, SEEK_END) == 0) size = ftell(f);
  fclose(f);
  return size;
}

/* True if the stub has logged a request containing `needle` for a server. */
static bool asked(int server, const char *needle) {
  char path[700], line[512];
  bool found = false;
  snprintf(path, sizeof path, "%s/%c.log", g_work, "ab"[server]);
  FILE *f = fopen(path, "r");
  if (f == NULL) return false;
  (void)fseek(f, g_mark[server], SEEK_SET);
  while (!found && fgets(line, sizeof line, f) != NULL) found = strstr(line, needle) != NULL;
  fclose(f);
  return found;
}

#define LOG_IS(x, want)                                                                \
  do {                                                                                 \
    T->checks++;                                                                       \
    if (strcmp((x)->log, (want)) != 0) {                                               \
      T->failed++;                                                                     \
      fprintf(stderr, "  %s:%d: events\n     got: %s\n  wanted: %s\n", __FILE__, __LINE__, \
              (x)->log, (want));                                                       \
    }                                                                                  \
  } while (0)

#define TXID(x, i) ((x)->net.world.tx[i].id)
#define LONG_MS 60000u

/* Publishes the model and waits for the event that must end what follows. */
#define STEP(x, want)        \
  do {                       \
    publish(x);              \
    CHECK(await(x, want, LONG_MS)); \
  } while (0)

static void test_confirm_reorg_confirm(test_state *T) {
  sx x;
  sx_open(&x, 2000);
  sx_start(&x);
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(await(&x, "tip 1003", LONG_MS));
  pool(&x, SIM_T, true);
  STEP(&x, "mempool T");
  both(&x, SIM_A, SIM_H0 + 5);
  STEP(&x, "confirmed T n=1 at a5");
  both(&x, SIM_B, SIM_H0 + 5);
  STEP(&x, "unconfirmed T mempool");
  both(&x, SIM_B, SIM_H0 + 6);
  STEP(&x, "confirmed T n=1 at b6");
  both(&x, SIM_B, SIM_H0 + 7);
  STEP(&x, "confirmed T n=2 at b6");
  both(&x, SIM_B, SIM_H0 + 8);
  STEP(&x, "confirmed T n=3 at b6 buried");
  LOG_IS(&x, "tip 1003 | mempool T | tip 1005 | confirmed T n=1 at a5 | reorg from 1004 gone 2 | "
             "tip 1005 | unconfirmed T mempool | tip 1006 | confirmed T n=1 at b6 | tip 1007 | "
             "confirmed T n=2 at b6 | tip 1008 | confirmed T n=3 at b6 buried");
  sx_close(&x);
}

static void test_double_spend(test_state *T) {
  sx x;
  sx_open(&x, 2000);
  both(&x, SIM_B, SIM_H0 + 6);
  sx_start(&x);
  CHECK(gz_chainw_watch_outpoint(x.w, x.net.world.p, 0, 2, 0) == GZ_CHAINW_OK);
  CHECK(await(&x, "tip 1006", LONG_MS));
  pool(&x, SIM_S1, true);
  STEP(&x, "spent P:0 by S1 n=0");
  pool(&x, SIM_S1, false);
  both(&x, SIM_B, SIM_H0 + 7);
  STEP(&x, "spent P:0 by S2#1 n=1 at b7 replaced");
  both(&x, SIM_B, SIM_H0 + 8);
  STEP(&x, "spent P:0 by S2#1 n=2 at b7 buried");
  LOG_IS(&x, "tip 1006 | spent P:0 by S1 n=0 | tip 1007 | spent P:0 by S2#1 n=1 at b7 replaced | "
             "tip 1008 | spent P:0 by S2#1 n=2 at b7 buried");
  sx_close(&x);
}

static void test_server_lags(test_state *T) {
  sx x;
  sx_open(&x, 2000);
  sx_start(&x);
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(await(&x, "tip 1003", LONG_MS));
  x.net.view[0].tip = SIM_H0 + 5;
  x.net.view[1].tip = SIM_H0 + 4;
  STEP(&x, "tip 1004");
  CHECK(await_sources(&x, GZ_CHAIN_LAG, LONG_MS));
  nap(400);
  drain(&x);
  LOG_IS(&x, "tip 1003 | tip 1004"); /* the confirmation one server has is not told */
  x.net.view[1].tip = SIM_H0 + 5;
  STEP(&x, "confirmed T n=1 at a5");
  CHECK(await_sources(&x, GZ_CHAIN_OK, LONG_MS));
  LOG_IS(&x, "tip 1003 | tip 1004 | tip 1005 | confirmed T n=1 at a5");
  sx_close(&x);
}

static void test_servers_disagree(test_state *T) {
  sx x;
  sx_open(&x, 2000);
  sx_start(&x);
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(await(&x, "tip 1003", LONG_MS));
  /* two different blocks at one height */
  both(&x, SIM_A, SIM_H0 + 5);
  x.net.view[1].branch = SIM_B;
  publish(&x);
  CHECK(await_sources(&x, GZ_CHAIN_DISAGREE, LONG_MS));
  nap(400);
  drain(&x);
  LOG_IS(&x, "tip 1003");
  x.net.view[1].branch = SIM_A;
  STEP(&x, "confirmed T n=1 at a5");
  CHECK(await_sources(&x, GZ_CHAIN_OK, LONG_MS));
  /* one server hides the transaction: asked again (the watch is set again),
   * the servers contradict each other and nothing is told */
  x.net.view[1].hide[SIM_T] = true;
  publish(&x);
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(await_sources(&x, GZ_CHAIN_DISAGREE, LONG_MS));
  nap(300);
  drain(&x);
  LOG_IS(&x, "tip 1003 | tip 1005 | confirmed T n=1 at a5");
  x.net.view[1].hide[SIM_T] = false;
  STEP(&x, "confirmed T n=1 at a5");
  CHECK(await_sources(&x, GZ_CHAIN_OK, LONG_MS));
  LOG_IS(&x, "tip 1003 | tip 1005 | confirmed T n=1 at a5 | confirmed T n=1 at a5");
  sx_close(&x);
}

static void test_server_lies_about_depth(test_state *T) {
  sx x;
  sx_open(&x, 2000);
  sx_start(&x);
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(await(&x, "tip 1003", LONG_MS));
  /* both say it confirmed two blocks earlier than it did */
  both(&x, SIM_A, SIM_H0 + 5);
  x.net.view[0].lie_height = x.net.view[1].lie_height = -2;
  STEP(&x, "tip 1005");
  CHECK(await_sources(&x, GZ_CHAIN_DISAGREE, LONG_MS));
  x.net.view[0].lie_height = x.net.view[1].lie_height = 0;
  STEP(&x, "confirmed T n=1 at a5");
  CHECK(await_sources(&x, GZ_CHAIN_OK, LONG_MS));
  /* both put blocks that do not link on top of it */
  both(&x, SIM_A, SIM_H0 + 8);
  x.net.view[0].graft = x.net.view[1].graft = SIM_H0 + 6;
  publish(&x);
  CHECK(await_sources(&x, GZ_CHAIN_BAD_PROOF, LONG_MS));
  nap(400);
  drain(&x);
  LOG_IS(&x, "tip 1003 | tip 1005 | confirmed T n=1 at a5"); /* no depth was added */
  x.net.view[0].graft = x.net.view[1].graft = 0;
  STEP(&x, "confirmed T n=4 at a5 buried");
  LOG_IS(&x, "tip 1003 | tip 1005 | confirmed T n=1 at a5 | tip 1008 | confirmed T n=4 at a5 buried");
  sx_close(&x);
}

static void test_mempool_eviction(test_state *T) {
  sx x;
  sx_open(&x, 2000);
  sx_start(&x);
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(gz_chainw_watch_outpoint(x.w, x.net.world.p, 0, 3, 0) == GZ_CHAINW_OK);
  CHECK(await(&x, "tip 1003", LONG_MS));
  pool(&x, SIM_T, true);
  STEP(&x, "mempool T");
  pool(&x, SIM_S1, true);
  STEP(&x, "spent P:0 by S1 n=0");
  pool(&x, SIM_T, false);
  STEP(&x, "evicted T");
  pool(&x, SIM_S1, false);
  STEP(&x, "unspent P:0 was S1");
  LOG_IS(&x, "tip 1003 | mempool T | spent P:0 by S1 n=0 | evicted T | unspent P:0 was S1");
  sx_close(&x);
}

static void posts(sx *x, int rule, int package) {
  x->net.view[0].post = x->net.view[1].post = rule;
  x->net.view[0].package = x->net.view[1].package = package;
}

static void test_broadcast_rejected_then_accepted(test_state *T) {
  sx x;
  char hex[65];
  sx_open(&x, 2000);
  const sim_tx *t = &x.net.world.tx[SIM_T], *k = &x.net.world.tx[SIM_K];
  sim_hex(t->id, hex);
  posts(&x, SIM_POST_REJECT, SIM_PKG_NONE);
  g_mark[0] = log_size(0); /* earlier scenarios asked about T */
  g_mark[1] = log_size(1);
  sx_start(&x);
  /* the funding txid is known and must not be asked about yet */
  CHECK(gz_chainw_watch_tx(x.w, t->id, 3, GZ_CHAINW_NOT_BEFORE) == GZ_CHAINW_OK);
  CHECK(await(&x, "tip 1003", LONG_MS));
  both(&x, SIM_A, SIM_H0 + 4);
  STEP(&x, "tip 1004");
  CHECK(!asked(0, hex) && !asked(1, hex));
  CHECK(asked(0, "GET /blocks/tip/height") && asked(1, "GET /blocks/tip/height"));
  /* refused, with the reason the server gave */
  CHECK(gz_chainw_broadcast(x.w, 1, t->raw, t->len) == GZ_CHAINW_OK);
  CHECK(await(&x, "broadcast #1 rejected final tries=1", LONG_MS));
  /* accepted; the host then says so and the watch is released */
  posts(&x, SIM_POST_ACCEPT, SIM_PKG_NONE);
  publish(&x);
  CHECK(gz_chainw_broadcast(x.w, 2, t->raw, t->len) == GZ_CHAINW_OK);
  CHECK(await(&x, "broadcast #2 accepted final tries=1", LONG_MS));
  CHECK(asked(0, "POST /tx 122") && asked(1, "POST /tx 122"));
  CHECK(!asked(0, hex) && !asked(1, hex));
  pool(&x, SIM_T, true);
  publish(&x);
  CHECK(gz_chainw_release(x.w, t->id, 100) == GZ_CHAINW_OK);
  CHECK(await(&x, "mempool T", LONG_MS));
  CHECK(asked(0, hex) && asked(1, hex));
  /* again: the servers already have it */
  posts(&x, SIM_POST_KNOWN, SIM_PKG_NONE);
  publish(&x);
  CHECK(gz_chainw_broadcast(x.w, 3, t->raw, t->len) == GZ_CHAINW_OK);
  CHECK(await(&x, "broadcast #3 already-known final tries=1", LONG_MS));
  /* nobody answers: said once, tried three times, then final */
  posts(&x, SIM_POST_DOWN, SIM_PKG_NONE);
  publish(&x);
  CHECK(gz_chainw_broadcast(x.w, 4, t->raw, t->len) == GZ_CHAINW_OK);
  CHECK(await(&x, "broadcast #4 unreachable final tries=3", LONG_MS));
  /* a package where no server takes packages: an explicit, final outcome */
  CHECK(gz_chainw_broadcast_package(x.w, 5, t->raw, t->len, k->raw, k->len) == GZ_CHAINW_OK);
  CHECK(await(&x, "broadcast #5 no-package-relay final tries=1 package parent=no-package-relay "
                  "child=no-package-relay",
              LONG_MS));
  CHECK(asked(0, "POST /txs/package 251") && asked(0, "POST /v1/txs/package 251"));
  /* one server takes them, at the second address */
  x.net.view[1].package = SIM_PKG_OK_V1;
  publish(&x);
  CHECK(gz_chainw_broadcast_package(x.w, 6, t->raw, t->len, k->raw, k->len) == GZ_CHAINW_OK);
  CHECK(await(&x, "broadcast #6 accepted final tries=1 package parent=accepted child=accepted",
              LONG_MS));
  /* and one that refuses the pair */
  x.net.view[1].package = SIM_PKG_NONE;
  x.net.view[0].package = SIM_PKG_FAIL;
  publish(&x);
  CHECK(gz_chainw_broadcast_package(x.w, 7, t->raw, t->len, k->raw, k->len) == GZ_CHAINW_OK);
  CHECK(await(&x, "broadcast #7 rejected final tries=1 package parent=rejected child=rejected",
              LONG_MS));
  LOG_IS(&x, "tip 1003 | tip 1004 | broadcast #1 rejected final tries=1 | "
             "broadcast #2 accepted final tries=1 | mempool T | "
             "broadcast #3 already-known final tries=1 | broadcast #4 unreachable tries=1 | "
             "broadcast #4 unreachable final tries=3 | "
             "broadcast #5 no-package-relay final tries=1 package parent=no-package-relay "
             "child=no-package-relay | "
             "broadcast #6 accepted final tries=1 package parent=accepted child=accepted | "
             "broadcast #7 rejected final tries=1 package parent=rejected child=rejected");
  sx_close(&x);
}

#define TIMED(call, limit_ms)                                                    \
  do {                                                                           \
    uint64_t t0_ = ms_now();                                                     \
    call;                                                                        \
    uint64_t took_ = ms_now() - t0_;                                             \
    T->checks++;                                                                 \
    if (took_ > (limit_ms)) {                                                    \
      T->failed++;                                                               \
      fprintf(stderr, "  %s:%d: %s took %llu ms (limit %u)\n", __FILE__, __LINE__, #call, \
              (unsigned long long)took_, (unsigned)(limit_ms));                  \
    }                                                                            \
  } while (0)

/* The stub answers every request after 30 s. Nothing the loop calls waits
 * for it, and shutdown does not either. */
static void test_stall_30s(test_state *T) {
  sx x;
  gz_chainw_event ev;
  sx_open(&x, 30000);
  snprintf(x.extra[0], sizeof x.extra[0], "X delay 30000 *");
  snprintf(x.extra[1], sizeof x.extra[1], "X delay 30000 *");
  const sim_tx *t = &x.net.world.tx[SIM_S2];
  char hex[65];
  sim_hex(t->id, hex);
  long mark = log_size(0);
  uint64_t begun = ms_now();
  sx_start(&x);
  /* wait until a request is on the wire (the stub logs it on arrival) */
  uint64_t end = ms_now() + LONG_MS;
  while (log_size(0) <= mark && ms_now() < end) nap(10);
  CHECK(log_size(0) > mark);
  int rc = -1;
  TIMED(rc = gz_chainw_watch_tx(x.w, t->id, 3, 0), 250);
  CHECK(rc == GZ_CHAINW_OK);
  TIMED(rc = gz_chainw_watch_outpoint(x.w, t->id, 1, 3, 0), 250);
  CHECK(rc == GZ_CHAINW_OK);
  TIMED(rc = gz_chainw_broadcast(x.w, 1, t->raw, t->len), 250);
  CHECK(rc == GZ_CHAINW_OK);
  TIMED(rc = gz_chainw_take(x.w, &ev), 250);
  CHECK(rc == 0);
  TIMED((void)gz_chainw_reset(x.w), 250);
  nap(300);
  TIMED(rc = gz_chainw_take(x.w, &ev), 250);
  CHECK(rc == 0);
  /* shutdown with the request in flight: well inside the 2 s the program has */
  TIMED(gz_chainw_free(x.w), 2000);
  CHECK(ms_now() - begun < 20000);
  x.w = NULL;
  gz_chain_destroy(&x.multi);
  gz_chain_destroy(&x.server[0]);
  gz_chain_destroy(&x.server[1]);
  gz_http_curl_destroy(&x.http);
  sim_net_free(&x.net);
}

/* What a server does at the level of the connection: it drops it in the
 * middle of a body, drips the body out, sends megabytes, hangs up, answers
 * 502. None of it stops the worker or is told as anything; when the server
 * behaves again, the truth arrives. */
static void test_hostile_connections(test_state *T) {
  static const char *const faults[] = {"X drop *",       "X drip *",       "X huge *",
                                       "X close *",      "X status 502 *", "X drop /status",
                                       "X huge /header", "X close /hex",   "X drip /merkle-proof",
                                       "X status 500 /outspend"};
  sx x;
  sx_open(&x, 700);
  both(&x, SIM_A, SIM_H0 + 6);
  sx_start(&x);
  CHECK(await(&x, "tip 1006", LONG_MS));
  for (size_t i = 0; i < sizeof faults / sizeof faults[0]; i++) {
    for (int servers = 1; servers <= 3; servers += 2) {
      snprintf(x.extra[0], sizeof x.extra[0], "%s", faults[i]);
      snprintf(x.extra[1], sizeof x.extra[1], "%s", servers == 3 ? faults[i] : "");
      publish(&x);
      /* a new generation, so that everything is asked again from nothing */
      (void)gz_chainw_reset(x.w);
      x.log[0] = 0;
      x.sources = GZ_CHAIN_OK;
      CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 3, 0) == GZ_CHAINW_OK);
      CHECK(gz_chainw_watch_outpoint(x.w, x.net.world.p, 0, 3, 0) == GZ_CHAINW_OK);
      uint64_t until = ms_now() + LONG_MS;
      while (x.sources == GZ_CHAIN_OK && ms_now() < until) {
        nap(20);
        drain(&x);
      }
      nap(300);
      drain(&x);
      const char *full = "tip 1006 | confirmed T n=2 at a5 | spent P:0 by S1 n=1 at a6";
      T->checks++;
      /* what gets through is true and is not everything: a beginning of
       * the full sequence */
      if (strlen(x.log) >= strlen(full) || strncmp(x.log, "tip 1006", strlen(x.log) < 8 ? strlen(x.log) : 8) != 0) {
        T->failed++;
        fprintf(stderr, "  with \"%s\" on %s: told \"%s\"\n", faults[i],
                servers == 3 ? "both servers" : "one server", x.log);
      }
      CHECK(x.sources != GZ_CHAIN_OK);
      x.extra[0][0] = 0;
      x.extra[1][0] = 0;
      publish(&x);
      /* the two watches are asked one after the other and the fault may end
       * between them, so either may be told first; each exactly once */
      const char *t_told = "confirmed T n=2 at a5", *p_told = "spent P:0 by S1 n=1 at a6";
      uint64_t limit = ms_now() + LONG_MS;
      while ((strstr(x.log, t_told) == NULL || strstr(x.log, p_told) == NULL) && ms_now() < limit) {
        nap(20);
        drain(&x);
      }
      nap(200);
      drain(&x);
      bool ok = strstr(x.log, t_told) != NULL && strstr(x.log, p_told) != NULL &&
                strlen(x.log) == strlen(full) && strncmp(x.log, "tip 1006 | ", 11) == 0;
      T->checks++;
      if (!ok) {
        T->failed++;
        fprintf(stderr, "  after \"%s\" on %s: told \"%s\"\n", faults[i],
                servers == 3 ? "both servers" : "one server", x.log);
      }
      CHECK(await_sources(&x, GZ_CHAIN_OK, LONG_MS));
    }
  }
  sx_close(&x);
}

int main(int argc, char **argv) {
  test_state state = {0, 0, 0}, *T = &state;
  if (argc != 3) {
    fprintf(stderr, "usage: chain_test_stub PORT WORKDIR\n");
    return 2;
  }
  g_port = atoi(argv[1]);
  g_work = argv[2];
  RUN(test_confirm_reorg_confirm);
  RUN(test_double_spend);
  RUN(test_server_lags);
  RUN(test_servers_disagree);
  RUN(test_server_lies_about_depth);
  RUN(test_mempool_eviction);
  RUN(test_broadcast_rejected_then_accepted);
  RUN(test_stall_30s);
  RUN(test_hostile_connections);
  TEST_MAIN_END("chain_watch_stub");
}
