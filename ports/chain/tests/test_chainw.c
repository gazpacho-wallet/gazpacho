/*
 * The chain worker (chainw.c): the thread, the queues and the descriptor,
 * against the simulated servers of sim.h on the real clock.
 *
 *  - the loop-side calls return at once while a server stalls for 30 s;
 *  - shutdown and reset with a request in flight are quick;
 *  - a full event queue delays the worker and loses nothing;
 *  - a generation never sees the events of the one before;
 *  - watches, requests, events and shutdown racing (run under
 *    ThreadSanitizer by the chain-tsan build, docs/notes/chain-port.md).
 */
#define _POSIX_C_SOURCE 200809L

#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

#include "test.h"

#include "simtest.h"

typedef struct wx {
  sim_net net;
  sim_stack stack;
  gz_chainw_config cfg;
  gz_chainw *w;
  char log[8192]; /* every event taken, " | " between them */
  size_t n_events;
  uint64_t last_generation;
  bool keep_sources; /* false: GZ_CHAINW_SOURCES events are counted and not logged */
} wx;

static uint64_t ms_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void nap(unsigned ms) {
  struct timespec ts = {ms / 1000u, (long)(ms % 1000u) * 1000000L};
  nanosleep(&ts, NULL);
}

static void wx_open(wx *x) {
  memset(x, 0, sizeof *x);
  sim_net_init(&x->net, true);
  if (!sim_stack_open(&x->stack, &x->net)) {
    fprintf(stderr, "cannot build the backends\n");
    exit(2);
  }
  gz_chainw_config_default(&x->cfg, &x->stack.multi, GZ_NET_SIGNET);
  x->cfg.tip_poll_ms = 40;
  x->cfg.retry_ms = 40;
  x->cfg.retry_max_ms = 160;
  x->cfg.max_watches = 8;
  x->cfg.max_requests = 64;
  x->cfg.max_results = 64;
  x->cfg.broadcast_attempts = 3;
  x->cfg.broadcast_backoff_ms = 20;
  x->cfg.broadcast_backoff_max_ms = 40;
  x->cfg.header_window = 16;
  x->cfg.max_catchup = 6;
  x->cfg.interrupt = sim_interrupt;
  x->cfg.interrupt_ctx = &x->net;
}

static void wx_start(wx *x) {
  x->w = gz_chainw_new(&x->cfg);
  if (x->w == NULL) {
    fprintf(stderr, "cannot start the worker\n");
    exit(2);
  }
}

static void wx_close(wx *x) {
  gz_chainw_free(x->w);
  sim_stack_close(&x->stack);
  sim_net_free(&x->net);
}

static void views(wx *x, int branch, uint32_t tip) {
  sim_lock(&x->net);
  for (int i = 0; i < 2; i++) {
    x->net.view[i].branch = branch;
    x->net.view[i].tip = tip;
  }
  sim_unlock(&x->net);
}

static void stall(wx *x, bool on) {
  sim_lock(&x->net);
  x->net.stall = on;
  pthread_cond_broadcast(&x->net.cv);
  sim_unlock(&x->net);
}

/* Takes every waiting event into the log. */
static void drain(wx *x) {
  gz_chainw_event ev;
  while (gz_chainw_take(x->w, &ev)) {
    size_t at = strlen(x->log);
    /* a change of the servers between two requests of one pass can show as
     * a moment of lag; it delays what is told and changes nothing else */
    bool skip = ev.kind == GZ_CHAINW_SOURCES && !x->keep_sources;
    if (!skip && at + 200 < sizeof x->log) {
      if (at) at += (size_t)snprintf(x->log + at, sizeof x->log - at, " | ");
      st_format(&x->net.world, &ev, x->log + at, sizeof x->log - at);
    }
    x->n_events++;
    x->last_generation = ev.generation;
  }
}

/* Waits, as a loop would (poll on the descriptor), until the log ends with
 * `want` or `limit_ms` pass. True if it did. */
static bool await(wx *x, const char *want, unsigned limit_ms) {
  uint64_t end = ms_now() + limit_ms;
  size_t wl = strlen(want);
  for (;;) {
    drain(x);
    size_t ll = strlen(x->log);
    if (ll >= wl && strcmp(x->log + ll - wl, want) == 0) return true;
    uint64_t now = ms_now();
    if (now >= end) return false;
    struct pollfd p = {gz_chainw_fd(x->w), POLLIN, 0};
    (void)poll(&p, 1, (int)(end - now > 100 ? 100 : end - now));
  }
}

static bool readable(wx *x) {
  struct pollfd p = {gz_chainw_fd(x->w), POLLIN, 0};
  return poll(&p, 1, 0) == 1 && (p.revents & POLLIN) != 0;
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
/* Generous: the machine is shared and the test also runs under valgrind. */
#define LONG_MS 60000u

/* ---- the descriptor, the order, the generation ---------------------------- */

static void test_events_through_the_descriptor(test_state *T) {
  wx x;
  wx_open(&x);
  wx_start(&x);
  CHECK(gz_chainw_fd(x.w) >= 0);
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(gz_chainw_watch_outpoint(x.w, x.net.world.p, 0, 3, 0) == GZ_CHAINW_OK);
  CHECK(await(&x, "tip 1003", LONG_MS));
  CHECK(x.last_generation == 1);
  /* drained: not readable, and nothing to take */
  gz_chainw_event ev;
  CHECK(!readable(&x));
  CHECK(gz_chainw_take(x.w, &ev) == 0);
  views(&x, SIM_A, SIM_H0 + 6);
  CHECK(await(&x, "spent P:0 by S1 n=1 at a6", LONG_MS));
  LOG_IS(&x, "tip 1003 | tip 1006 | confirmed T n=2 at a5 | spent P:0 by S1 n=1 at a6");
  /* readable exactly while something waits */
  views(&x, SIM_A, SIM_H0 + 7);
  uint64_t end = ms_now() + LONG_MS;
  while (!readable(&x) && ms_now() < end) nap(5);
  CHECK(readable(&x));
  nap(150);
  CHECK(readable(&x));
  CHECK(await(&x, "spent P:0 by S1 n=2 at a6", LONG_MS));
  CHECK(!readable(&x));
  /* dropping a watch: nothing more about it */
  CHECK(gz_chainw_unwatch_outpoint(x.w, x.net.world.p, 0) == GZ_CHAINW_OK);
  CHECK(gz_chainw_unwatch_outpoint(x.w, x.net.world.p, 0) == GZ_CHAINW_OK); /* not set: fine */
  views(&x, SIM_A, SIM_H0 + 8);
  CHECK(await(&x, "tip 1008", LONG_MS));
  nap(200);
  drain(&x);
  LOG_IS(&x, "tip 1003 | tip 1006 | confirmed T n=2 at a5 | spent P:0 by S1 n=1 at a6 | tip 1007 | "
             "confirmed T n=3 at a5 buried | spent P:0 by S1 n=2 at a6 | tip 1008");
  gz_chainw_stats st;
  gz_chainw_stats_get(x.w, &st);
  CHECK(st.watches == 1 && st.generation == 1 && st.queued_events == 0 && st.events >= 8);
  wx_close(&x);
}

/* ---- the loop is never held up -------------------------------------------- */

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

/* What "at once" means here: the machine is shared and loaded, and the same
 * test runs under valgrind. The server stalls for 30,000 ms. */
#define AT_ONCE_MS 250u

static void test_loop_calls_never_block(test_state *T) {
  wx x;
  gz_chainw_event ev;
  gz_chainw_stats st;
  const sim_tx *t, *k;
  sim_request_timeout_ms = 30000; /* each request may take 30 s */
  wx_open(&x);
  sim_request_timeout_ms = 2000;
  t = &x.net.world.tx[SIM_T];
  k = &x.net.world.tx[SIM_K];
  stall(&x, true); /* every request hangs until its time limit */
  uint64_t begun = ms_now();
  TIMED(wx_start(&x), AT_ONCE_MS);
  /* let the worker walk into its first request */
  while (sim_requests(&x.net) == 0 && ms_now() - begun < LONG_MS) nap(5);
  CHECK(sim_requests(&x.net) >= 1);
  int rc = -1;
  TIMED(rc = gz_chainw_watch_tx(x.w, t->id, 3, 0), AT_ONCE_MS);
  CHECK(rc == GZ_CHAINW_OK);
  TIMED(rc = gz_chainw_watch_outpoint(x.w, x.net.world.p, 0, 3, GZ_CHAINW_NOT_BEFORE), AT_ONCE_MS);
  CHECK(rc == GZ_CHAINW_OK);
  TIMED(rc = gz_chainw_release(x.w, x.net.world.p, 10), AT_ONCE_MS);
  CHECK(rc == GZ_CHAINW_OK);
  TIMED(rc = gz_chainw_unwatch_tx(x.w, t->id), AT_ONCE_MS);
  CHECK(rc == GZ_CHAINW_OK);
  TIMED(rc = gz_chainw_broadcast(x.w, 1, t->raw, t->len), AT_ONCE_MS);
  CHECK(rc == GZ_CHAINW_OK);
  TIMED(rc = gz_chainw_broadcast_package(x.w, 2, t->raw, t->len, k->raw, k->len), AT_ONCE_MS);
  CHECK(rc == GZ_CHAINW_OK);
  TIMED(rc = gz_chainw_take(x.w, &ev), AT_ONCE_MS);
  CHECK(rc == 0); /* nothing has been learnt: the server has not answered */
  TIMED(gz_chainw_stats_get(x.w, &st), AT_ONCE_MS);
  CHECK(st.queued_requests == 6 && st.broadcasts == 2 && st.watches == 1 && st.passes == 0);
  CHECK(!readable(&x));
  /* a thousand more calls, all refused or queued at once */
  uint64_t t0 = ms_now();
  unsigned busy = 0;
  for (int i = 0; i < 1000; i++) {
    if (gz_chainw_release(x.w, t->id, 0) == GZ_CHAINW_BUSY) busy++;
    (void)gz_chainw_take(x.w, &ev);
  }
  CHECK(ms_now() - t0 < 2000);
  CHECK(busy == 1000 - (64 - 6)); /* the queue holds 64; the rest are refused, not lost in a wait */
  /* a reset with the request still hanging: at once too, and it ends the request */
  uint64_t g = 0;
  TIMED(g = gz_chainw_reset(x.w), AT_ONCE_MS);
  CHECK(g == 2);
  gz_chainw_stats_get(x.w, &st);
  CHECK(st.queued_requests == 0 && st.broadcasts == 0 && st.watches == 0 && st.generation == 2);
  /* all of this within the first request, which would have taken 30 s */
  CHECK(ms_now() - begun < 20000);
  /* and so is shutdown */
  TIMED(gz_chainw_free(x.w), 3000);
  CHECK(ms_now() - begun < 25000);
  sim_stack_close(&x.stack);
  sim_net_free(&x.net);
}

static void test_shutdown_in_flight(test_state *T) {
  /* stopped while idle, while waiting between passes, while in a request,
   * while the event queue is full: each joins quickly */
  for (int mode = 0; mode < 4; mode++) {
    wx x;
    sim_request_timeout_ms = 30000;
    wx_open(&x);
    sim_request_timeout_ms = 2000;
    if (mode == 3) x.cfg.max_results = 2;
    wx_start(&x);
    if (mode == 1) CHECK(await(&x, "tip 1003", LONG_MS));
    if (mode == 2) {
      CHECK(await(&x, "tip 1003", LONG_MS));
      stall(&x, true);
      unsigned before = sim_requests(&x.net);
      uint64_t end = ms_now() + LONG_MS;
      while (sim_requests(&x.net) == before && ms_now() < end) nap(5);
    }
    if (mode == 3) {
      for (int i = 0; i < SIM_NTX; i++)
        CHECK(gz_chainw_watch_tx(x.w, TXID(&x, i), 3, 0) == GZ_CHAINW_OK);
      views(&x, SIM_A, SIM_H0 + 8);
      gz_chainw_stats st;
      uint64_t end = ms_now() + LONG_MS;
      do {
        nap(5);
        gz_chainw_stats_get(x.w, &st);
      } while (st.waits == 0 && ms_now() < end);
      CHECK(st.waits >= 1 && st.queued_events == 2);
    }
    TIMED(gz_chainw_free(x.w), 3000);
    /* the chain is usable again by its owner after the worker is gone */
    stall(&x, false);
    gz_chain_tip tip;
    CHECK_RESULT(gz_chain_tip_get(&x.stack.multi, &tip), GZ_CHAIN_OK);
    sim_stack_close(&x.stack);
    sim_net_free(&x.net);
  }
  /* without an interrupt hook the worker is still joined, after the request
   * in flight has run into its time limit (400 ms here) */
  wx x;
  sim_request_timeout_ms = 400;
  wx_open(&x);
  sim_request_timeout_ms = 2000;
  x.cfg.interrupt = NULL;
  stall(&x, true);
  wx_start(&x);
  uint64_t end = ms_now() + LONG_MS;
  while (sim_requests(&x.net) == 0 && ms_now() < end) nap(5);
  TIMED(gz_chainw_free(x.w), 5000);
  gz_chainw_free(NULL);
  sim_stack_close(&x.stack);
  sim_net_free(&x.net);
}

/* ---- a full queue delays, and loses nothing ------------------------------- */

static void test_full_queue_loses_nothing(test_state *T) {
  wx x;
  gz_chainw_stats st;
  wx_open(&x);
  x.cfg.max_results = 2;
  wx_start(&x);
  CHECK(await(&x, "tip 1003", LONG_MS));
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 6, 0) == GZ_CHAINW_OK);
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_S1), 6, 0) == GZ_CHAINW_OK);
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_K), 6, 0) == GZ_CHAINW_OK);
  CHECK(gz_chainw_watch_outpoint(x.w, x.net.world.p, 0, 6, 0) == GZ_CHAINW_OK);
  CHECK(gz_chainw_watch_outpoint(x.w, TXID(&x, SIM_T), 0, 6, 0) == GZ_CHAINW_OK);
  views(&x, SIM_A, SIM_H0 + 8);
  /* the loop does not take anything: the worker fills the two places and waits */
  uint64_t end = ms_now() + LONG_MS;
  do {
    nap(5);
    gz_chainw_stats_get(x.w, &st);
  } while (st.waits == 0 && ms_now() < end);
  CHECK(st.waits >= 1 && st.queued_events == 2);
  nap(300);
  gz_chainw_stats_get(x.w, &st);
  CHECK(st.queued_events == 2);
  /* now it takes them, one wake-up at a time: all six arrive, in order */
  CHECK(await(&x, "spent T:0 by K n=2 at a7", LONG_MS));
  LOG_IS(&x, "tip 1003 | tip 1008 | confirmed T n=4 at a5 | confirmed S1 n=3 at a6 | "
             "confirmed K n=2 at a7 | spent P:0 by S1 n=3 at a6 | spent T:0 by K n=2 at a7");
  /* tips waiting in a full queue are replaced, not queued and not lost:
   * three new blocks while nothing is taken, one tip at the end */
  views(&x, SIM_A, SIM_H0 + 9);
  nap(200);
  views(&x, SIM_A, SIM_H0 + 10);
  nap(200);
  views(&x, SIM_A, SIM_H0 + 11);
  CHECK(await(&x, "spent T:0 by K n=5 at a7", LONG_MS));
  CHECK(strstr(x.log, "tip 1011") != NULL);
  /* which counts were told on the way depends on which tips the worker saw;
   * that each watch reached its depth does not */
  CHECK(strstr(x.log, " at a5 buried") != NULL);
  CHECK(strstr(x.log, " at a6 buried") != NULL);
  wx_close(&x);
}

/* ---- reset: a new generation never sees the old one ----------------------- */

static void test_reset(test_state *T) {
  wx x;
  gz_chainw_event ev;
  gz_chainw_stats st;
  wx_open(&x);
  wx_start(&x);
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 3, 0) == GZ_CHAINW_OK);
  views(&x, SIM_A, SIM_H0 + 5);
  /* events are waiting, and the descriptor says so */
  uint64_t end = ms_now() + LONG_MS;
  do {
    nap(5);
    gz_chainw_stats_get(x.w, &st);
  } while (st.queued_events < 2 && ms_now() < end);
  CHECK(readable(&x));
  CHECK(gz_chainw_broadcast(x.w, 9, x.net.world.tx[SIM_S1].raw, x.net.world.tx[SIM_S1].len) ==
        GZ_CHAINW_OK);
  CHECK(gz_chainw_reset(x.w) == 2);
  /* gone: the events, the wake-up, the watches, the broadcast */
  CHECK(!readable(&x) || gz_chainw_take(x.w, &ev) == 1);
  gz_chainw_stats_get(x.w, &st);
  CHECK(st.watches == 0 && st.broadcasts == 0 && st.generation == 2);
  /* the new generation starts with the tip and knows no watch */
  CHECK(await(&x, "tip 1005", LONG_MS));
  LOG_IS(&x, "tip 1005");
  CHECK(x.last_generation == 2);
  nap(300);
  drain(&x);
  LOG_IS(&x, "tip 1005");
  /* a watch set again is told again */
  CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(await(&x, "confirmed T n=1 at a5", LONG_MS));
  LOG_IS(&x, "tip 1005 | confirmed T n=1 at a5");
  /* twenty resets in a row, each while the worker is busy */
  for (int i = 0; i < 20; i++) {
    CHECK(gz_chainw_watch_tx(x.w, TXID(&x, SIM_T), 3, 0) == GZ_CHAINW_OK);
    CHECK(gz_chainw_reset(x.w) == (uint64_t)(3 + i));
  }
  x.log[0] = 0;
  CHECK(await(&x, "tip 1005", LONG_MS));
  CHECK(x.last_generation == 22);
  nap(200);
  drain(&x);
  LOG_IS(&x, "tip 1005");
  wx_close(&x);
}

/* ---- limits: refused, never an error, never a wait ------------------------ */

static void test_limits(test_state *T) {
  wx x;
  uint8_t id[32];
  gz_chainw_config c;
  wx_open(&x);
  /* configurations that are refused */
  c = x.cfg;
  c.network = GZ_NET_MAINNET;
  CHECK(gz_chainw_new(&c) == NULL);
  c = x.cfg;
  c.chain = NULL;
  CHECK(gz_chainw_new(&c) == NULL);
  c = x.cfg;
  c.max_results = 1;
  CHECK(gz_chainw_new(&c) == NULL);
  c = x.cfg;
  c.max_requests = 0;
  CHECK(gz_chainw_new(&c) == NULL);
  c = x.cfg;
  c.max_watches = GZ_CHAINW_WATCHES_LIMIT + 1;
  CHECK(gz_chainw_new(&c) == NULL);
  CHECK(gz_chainw_new(NULL) == NULL);
  gz_chainw_config_default(&c, &x.stack.multi, GZ_NET_SIGNET);
  CHECK(c.tip_poll_ms == 60000 && c.burial_depth == 3 && c.max_watches == 256 &&
        c.max_requests == 1024 && c.max_results == 4096 && c.header_window == 288);

  wx_start(&x);
  memset(id, 0, sizeof id);
  for (uint8_t i = 0; i < 8; i++) {
    id[5] = i;
    CHECK(gz_chainw_watch_tx(x.w, id, 1, GZ_CHAINW_NOT_BEFORE) == GZ_CHAINW_OK);
  }
  /* the ninth is refused; one that is set is not a ninth */
  CHECK(gz_chainw_watch_outpoint(x.w, id, 0, 1, 0) == GZ_CHAINW_FULL);
  CHECK(gz_chainw_watch_tx(x.w, id, 2, 0) == GZ_CHAINW_OK);
  CHECK(gz_chainw_unwatch_tx(x.w, id) == GZ_CHAINW_OK);
  CHECK(gz_chainw_watch_outpoint(x.w, id, 0, 1, 0) == GZ_CHAINW_OK);
  CHECK(gz_chainw_watch_outpoint(x.w, id, 1, 1, 0) == GZ_CHAINW_FULL);
  /* bad arguments */
  CHECK(gz_chainw_watch_tx(x.w, NULL, 1, 0) == GZ_CHAINW_INVALID);
  CHECK(gz_chainw_watch_tx(x.w, id, GZ_CHAINW_MAX_DEPTH + 1, 0) == GZ_CHAINW_INVALID);
  CHECK(gz_chainw_watch_tx(x.w, id, 1, 4) == GZ_CHAINW_INVALID);
  CHECK(gz_chainw_watch_tx(NULL, id, 1, 0) == GZ_CHAINW_INVALID);
  CHECK(gz_chainw_unwatch_tx(x.w, NULL) == GZ_CHAINW_INVALID);
  CHECK(gz_chainw_release(x.w, NULL, 0) == GZ_CHAINW_INVALID);
  CHECK(gz_chainw_broadcast(x.w, 1, id, sizeof id) == GZ_CHAINW_INVALID);
  CHECK(gz_chainw_broadcast(x.w, 1, NULL, 0) == GZ_CHAINW_INVALID);
  const sim_tx *t = &x.net.world.tx[SIM_T];
  CHECK(gz_chainw_broadcast_package(x.w, 1, id, sizeof id, t->raw, t->len) == GZ_CHAINW_INVALID);
  CHECK(gz_chainw_take(x.w, NULL) == 0 && gz_chainw_take(NULL, NULL) == 0);
  CHECK(gz_chainw_fd(NULL) == -1 && gz_chainw_reset(NULL) == 0);
  /* sixteen broadcasts wait at most; the seventeenth is refused */
  sim_lock(&x.net);
  x.net.view[0].post = x.net.view[1].post = SIM_POST_DOWN;
  sim_unlock(&x.net);
  stall(&x, true);
  for (uint64_t i = 0; i < GZ_CHAINW_MAX_BROADCASTS; i++)
    CHECK(gz_chainw_broadcast(x.w, i, t->raw, t->len) == GZ_CHAINW_OK);
  CHECK(gz_chainw_broadcast(x.w, 99, t->raw, t->len) == GZ_CHAINW_FULL);
  stall(&x, false);
  /* each of the sixteen gets its final event, and then there is room again */
  unsigned finals = 0;
  uint64_t end = ms_now() + LONG_MS;
  gz_chainw_event ev;
  while (finals < GZ_CHAINW_MAX_BROADCASTS && ms_now() < end) {
    if (!gz_chainw_take(x.w, &ev)) {
      nap(5);
    } else if (ev.kind == GZ_CHAINW_BROADCAST && ev.broadcast.final) {
      CHECK(ev.broadcast.outcome == GZ_CHAINW_UNREACHABLE && ev.broadcast.attempts == 3);
      finals++;
    }
  }
  CHECK(finals == GZ_CHAINW_MAX_BROADCASTS);
  CHECK(gz_chainw_broadcast(x.w, 100, t->raw, t->len) == GZ_CHAINW_OK);
  wx_close(&x);
}

/* ---- broadcasts and the held-back watch, through the worker --------------- */

static void test_broadcast_and_release(test_state *T) {
  wx x;
  char hex[65];
  const sim_tx *t, *k;
  wx_open(&x);
  t = &x.net.world.tx[SIM_T];
  k = &x.net.world.tx[SIM_K];
  sim_hex(t->id, hex);
  wx_start(&x);
  /* a member: it knows the funding txid before anyone has broadcast it */
  CHECK(gz_chainw_watch_tx(x.w, t->id, 3, GZ_CHAINW_NOT_BEFORE) == GZ_CHAINW_OK);
  CHECK(await(&x, "tip 1003", LONG_MS));
  views(&x, SIM_A, SIM_H0 + 4);
  CHECK(await(&x, "tip 1004", LONG_MS));
  CHECK(!sim_log_has(&x.net, hex));
  /* a broadcast of something else does not name it either */
  sim_lock(&x.net);
  x.net.view[0].post = SIM_POST_REJECT;
  x.net.view[1].post = SIM_POST_REJECT;
  sim_unlock(&x.net);
  CHECK(gz_chainw_broadcast(x.w, 41, x.net.world.tx[SIM_S1].raw, x.net.world.tx[SIM_S1].len) ==
        GZ_CHAINW_OK);
  CHECK(await(&x, "broadcast #41 rejected final tries=1", LONG_MS));
  sim_lock(&x.net);
  x.net.view[0].post = SIM_POST_ACCEPT;
  x.net.view[1].post = SIM_POST_ACCEPT;
  x.net.view[1].package = SIM_PKG_OK;
  sim_unlock(&x.net);
  CHECK(gz_chainw_broadcast(x.w, 42, x.net.world.tx[SIM_S1].raw, x.net.world.tx[SIM_S1].len) ==
        GZ_CHAINW_OK);
  CHECK(await(&x, "broadcast #42 accepted final tries=1", LONG_MS));
  CHECK(!sim_log_has(&x.net, hex));
  /* the host says it has broadcast: released after 300 ms, then seen */
  sim_lock(&x.net);
  x.net.view[0].mempool[SIM_T] = x.net.view[1].mempool[SIM_T] = true;
  sim_unlock(&x.net);
  uint64_t released = ms_now();
  CHECK(gz_chainw_release(x.w, t->id, 300) == GZ_CHAINW_OK);
  CHECK(await(&x, "mempool T", LONG_MS));
  CHECK(ms_now() - released >= 300);
  CHECK(sim_log_has(&x.net, hex));
  /* a package, both transactions reported */
  CHECK(gz_chainw_broadcast_package(x.w, 43, t->raw, t->len, k->raw, k->len) == GZ_CHAINW_OK);
  CHECK(await(&x, "broadcast #43 accepted final tries=1 package parent=accepted child=accepted",
              LONG_MS));
  sim_lock(&x.net);
  x.net.view[1].package = SIM_PKG_NONE;
  sim_unlock(&x.net);
  CHECK(gz_chainw_broadcast_package(x.w, 44, t->raw, t->len, k->raw, k->len) == GZ_CHAINW_OK);
  CHECK(await(&x, "broadcast #44 no-package-relay final tries=1 package parent=no-package-relay "
                  "child=no-package-relay",
              LONG_MS));
  wx_close(&x);
}

/* ---- everything at once ---------------------------------------------------- */

typedef struct chaos {
  wx *x;
  atomic_int stop;
  uint64_t seed;
} chaos;

static uint64_t next(uint64_t *s) {
  *s ^= *s << 13;
  *s ^= *s >> 7;
  *s ^= *s << 17;
  return *s;
}

/* The servers: blocks come and go, branches switch, mempools change, one
 * server or both fail in every way, requests stall and are let go. */
static void *chaos_servers(void *arg) {
  chaos *c = arg;
  uint64_t s = c->seed | 1;
  while (!c->stop) {
    uint64_t r = next(&s);
    sim_net *n = &c->x->net;
    sim_lock(n);
    sim_view *v = &n->view[r & 1];
    switch ((r >> 1) % 9) {
      case 0: n->view[0].tip = n->view[1].tip = SIM_H0 + 3 + (uint32_t)((r >> 8) % 9); break;
      case 1: v->tip = SIM_H0 + 3 + (uint32_t)((r >> 8) % 9); break;
      case 2: n->view[0].branch = n->view[1].branch = (int)((r >> 8) % 3); break;
      case 3: v->mempool[(r >> 8) % SIM_NTX] = (r >> 12) & 1; break;
      case 4: v->fault = (int)((r >> 8) % 8); v->seed = r; v->cut = (size_t)((r >> 20) % 90); break;
      case 5: n->view[0].fault = n->view[1].fault = SIM_FAULT_NONE; break;
      case 6: n->stall = (r >> 8) % 4 == 0; pthread_cond_broadcast(&n->cv); break;
      case 7: v->post = (int)((r >> 8) % 4); v->package = (int)((r >> 12) % 5); break;
      default: v->hide[(r >> 8) % SIM_NTX] = (r >> 12) % 4 == 0; break;
    }
    sim_unlock(n);
    nap(1 + (unsigned)((r >> 40) % 3));
  }
  return NULL;
}

static void test_everything_races(test_state *T) {
  unsigned rounds = getenv("GZ_CHAINW_ROUNDS") ? (unsigned)atoi(getenv("GZ_CHAINW_ROUNDS")) : 40;
  uint64_t taken = 0, calls = 0;
  for (unsigned round = 0; round < rounds; round++) {
    wx x;
    chaos c;
    pthread_t th;
    uint64_t s = 0x9e3779b97f4a7c15ULL * (round + 1);
    sim_request_timeout_ms = 60;
    wx_open(&x);
    sim_request_timeout_ms = 2000;
    x.cfg.max_results = 2 + round % 5;
    x.cfg.max_requests = 4 + round % 9;
    x.cfg.tip_poll_ms = 2;
    x.cfg.retry_ms = 1;
    x.cfg.retry_max_ms = 4;
    x.cfg.broadcast_backoff_ms = 1;
    x.cfg.broadcast_backoff_max_ms = 2;
    if (round % 7 == 6) x.cfg.interrupt = NULL;
    wx_start(&x);
    c.x = &x;
    c.stop = 0;
    c.seed = s;
    pthread_create(&th, NULL, chaos_servers, &c);
    uint64_t end = ms_now() + 40 + round % 60;
    uint64_t generation = 1;
    while (ms_now() < end) {
      uint64_t r = next(&s);
      const sim_tx *t = &x.net.world.tx[(r >> 8) % SIM_NTX];
      const sim_tx *u = &x.net.world.tx[(r >> 12) % SIM_NTX];
      gz_chainw_event ev;
      gz_chainw_stats st;
      int rc = GZ_CHAINW_OK;
      calls++;
      switch (r % 12) {
        case 0: rc = gz_chainw_watch_tx(x.w, t->id, (uint32_t)((r >> 16) % 5), (r >> 20) & 1); break;
        case 1: rc = gz_chainw_watch_outpoint(x.w, (r >> 16) & 1 ? x.net.world.p : t->id, 0, 3, (r >> 20) & 1); break;
        case 2: rc = gz_chainw_unwatch_tx(x.w, t->id); break;
        case 3: rc = gz_chainw_unwatch_outpoint(x.w, x.net.world.p, 0); break;
        case 4: rc = gz_chainw_release(x.w, t->id, (uint32_t)((r >> 16) % 4)); break;
        case 5: rc = gz_chainw_broadcast(x.w, r, t->raw, t->len); break;
        case 6: rc = gz_chainw_broadcast_package(x.w, r, t->raw, t->len, u->raw, u->len); break;
        case 7: if ((r >> 16) % 8 == 0) generation = gz_chainw_reset(x.w); break;
        case 8: gz_chainw_stats_get(x.w, &st); break;
        default:
          if (gz_chainw_take(x.w, &ev)) {
            taken++;
            /* never an event of a generation that was reset away */
            if (ev.generation != generation || ev.kind < GZ_CHAINW_TIP || ev.kind > GZ_CHAINW_REORG) {
              T->failed++;
              fprintf(stderr, "  round %u: event kind %d of generation %llu in generation %llu\n", round,
                      (int)ev.kind, (unsigned long long)ev.generation, (unsigned long long)generation);
            }
          }
          break;
      }
      if (rc < GZ_CHAINW_OK || rc > GZ_CHAINW_INVALID) T->failed++;
    }
    /* shut down with all of it in flight; the servers still misbehaving */
    TIMED(gz_chainw_free(x.w), 3000);
    c.stop = 1;
    pthread_join(th, NULL);
    sim_stack_close(&x.stack);
    sim_net_free(&x.net);
  }
  T->checks++;
  printf("     %u rounds, %llu loop calls, %llu events taken\n", rounds, (unsigned long long)calls,
         (unsigned long long)taken);
  CHECK(calls > 1000);
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  RUN(test_limits);
  RUN(test_events_through_the_descriptor);
  RUN(test_loop_calls_never_block);
  RUN(test_shutdown_in_flight);
  RUN(test_full_queue_loses_nothing);
  RUN(test_reset);
  RUN(test_broadcast_and_release);
  RUN(test_everything_races);
  TEST_MAIN_END("chain_chainw");
}
