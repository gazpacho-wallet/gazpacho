/*
 * The chain worker: one thread that owns the gz_chain and the watch engine
 * (watch.c), behind two bounded queues and a wake descriptor. See
 * chain_watch.h.
 *
 * Locking. One mutex guards everything the two threads share: both queues,
 * the mirror of the watch set, the generation and the flags. The engine and
 * the gz_chain are touched by the worker thread only, and never with the
 * mutex held while they do I/O. The loop-side calls take the mutex for a few
 * instructions and never wait on a condition variable, so they cannot block
 * on the network or on the worker.
 */
#define _POSIX_C_SOURCE 200809L

#include "gazpacho/chain_watch.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "watch.h"

typedef enum req_kind {
  REQ_WATCH_TX = 1,
  REQ_WATCH_OUTPOINT,
  REQ_DROP_TX,
  REQ_DROP_OUTPOINT,
  REQ_RELEASE,
  REQ_BROADCAST
} req_kind;

typedef struct request {
  req_kind kind;
  uint8_t txid[GZ_HASH_LEN];
  uint32_t vout, depth, delay_ms;
  unsigned flags;
  uint64_t id;
  uint8_t *parent, *tx; /* heap copies, owned by the request until the engine takes them */
  size_t parent_len, len;
} request;

/* The loop's own record of which watches are set, so that it can refuse one
 * too many without asking the worker. */
typedef struct mirror {
  bool tx; /* else an outpoint */
  uint8_t txid[GZ_HASH_LEN];
  uint32_t vout;
} mirror;

struct gz_chainw {
  gz_chainw_config cfg;
  pthread_mutex_t mu;
  pthread_cond_t work; /* the worker sleeps here between passes */
  pthread_cond_t room; /* the worker waits here for room in the event queue */
  pthread_t thread;
  int wake_r, wake_w;
  /* all below under mu */
  request *reqs;
  size_t req_head, req_count;
  gz_chainw_event *events;
  size_t ev_head, ev_count;
  mirror *set;
  size_t set_count;
  size_t broadcasts; /* accepted and without a final event queued yet */
  uint64_t generation;
  bool reset_pending; /* the engine still holds the previous generation */
  bool stop;
  uint64_t passes, n_events, waits, diverged;
  /* worker thread only */
  gz_watch *engine;
};

static uint64_t monotonic_ms(void *ctx) {
  struct timespec ts;
  (void)ctx;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

void gz_chainw_config_default(gz_chainw_config *cfg, gz_chain *chain, gz_network network) {
  if (cfg == NULL) return;
  memset(cfg, 0, sizeof *cfg);
  cfg->chain = chain;
  cfg->network = network;
  cfg->tip_poll_ms = 60000;
  cfg->retry_ms = 5000;
  cfg->retry_max_ms = 300000;
  cfg->burial_depth = 3;
  cfg->max_watches = 256;
  cfg->max_requests = 1024;
  cfg->max_results = 4096;
  cfg->broadcast_attempts = 6;
  cfg->broadcast_backoff_ms = 2000;
  cfg->broadcast_backoff_max_ms = 60000;
  cfg->header_window = 2 * GZ_CHAINW_MAX_DEPTH;
  cfg->max_catchup = GZ_CHAINW_MAX_DEPTH;
  cfg->max_link = 52560;
}

/* ---- the event queue (worker side) --------------------------------------- */

static void request_free(request *r) {
  free(r->parent);
  free(r->tx);
  r->parent = r->tx = NULL;
}

/* Called with mu held. Makes the descriptor readable. */
static void wake_set(gz_chainw *w) {
  char one = 1;
  ssize_t n;
  do {
    n = write(w->wake_w, &one, 1);
  } while (n < 0 && errno == EINTR);
  /* EAGAIN: a byte is already there, which is all that is wanted */
}

/* Called with mu held. Makes the descriptor unreadable. */
static void wake_clear(gz_chainw *w) {
  char buf[16];
  for (;;) {
    ssize_t n = read(w->wake_r, buf, sizeof buf);
    if (n > 0) continue;
    if (n < 0 && errno == EINTR) continue;
    break;
  }
}

static bool engine_stop(void *ctx) {
  gz_chainw *w = ctx;
  pthread_mutex_lock(&w->mu);
  bool stop = w->stop || w->reset_pending;
  pthread_mutex_unlock(&w->mu);
  return stop;
}

/*
 * The engine's `emit`: queues one event for the loop. Never drops one: when
 * the queue is full it waits for gz_chainw_take to make room. A tip (or a
 * sources event) that is still the newest thing in the queue is replaced by
 * the newer one, which keeps the order and needs no room. An event made
 * while a reset or a stop is pending belongs to nobody and is discarded.
 */
static void engine_emit(void *ctx, const gz_chainw_event *ev) {
  gz_chainw *w = ctx;
  pthread_mutex_lock(&w->mu);
  bool waited = false;
  while (!w->stop && !w->reset_pending && w->ev_count == w->cfg.max_results) {
    /* coalescing needs no room */
    gz_chainw_event *last = &w->events[(w->ev_head + w->ev_count - 1) % w->cfg.max_results];
    if ((ev->kind == GZ_CHAINW_TIP || ev->kind == GZ_CHAINW_SOURCES) && last->kind == ev->kind) break;
    if (!waited) w->waits++;
    waited = true;
    pthread_cond_wait(&w->room, &w->mu);
  }
  if (!w->stop && !w->reset_pending) {
    gz_chainw_event *last =
        w->ev_count > 0 ? &w->events[(w->ev_head + w->ev_count - 1) % w->cfg.max_results] : NULL;
    if (ev->kind == GZ_CHAINW_BROADCAST && ev->broadcast.final && w->broadcasts > 0) w->broadcasts--;
    if (last != NULL && (ev->kind == GZ_CHAINW_TIP || ev->kind == GZ_CHAINW_SOURCES) &&
        last->kind == ev->kind) {
      *last = *ev;
      last->generation = w->generation;
    } else {
      gz_chainw_event *slot = &w->events[(w->ev_head + w->ev_count) % w->cfg.max_results];
      *slot = *ev;
      slot->generation = w->generation;
      if (w->ev_count == 0) wake_set(w);
      w->ev_count++;
    }
    w->n_events++;
  }
  pthread_mutex_unlock(&w->mu);
}

/* ---- the worker thread --------------------------------------------------- */

/* Called with mu held, from the worker. Hands every queued request to the
 * engine. Engine calls here are memory only. */
static void apply_requests(gz_chainw *w) {
  while (w->req_count > 0) {
    request *r = &w->reqs[w->req_head];
    int rc = GZ_CHAINW_OK;
    switch (r->kind) {
      case REQ_WATCH_TX: rc = gz_watch_tx(w->engine, r->txid, r->depth, r->flags); break;
      case REQ_WATCH_OUTPOINT:
        rc = gz_watch_outpoint(w->engine, r->txid, r->vout, r->depth, r->flags);
        break;
      case REQ_DROP_TX: gz_watch_drop_tx(w->engine, r->txid); break;
      case REQ_DROP_OUTPOINT: gz_watch_drop_outpoint(w->engine, r->txid, r->vout); break;
      case REQ_RELEASE: gz_watch_release(w->engine, r->txid, r->delay_ms); break;
      case REQ_BROADCAST:
        /* the engine takes the copies; the loop already checked the limit */
        rc = gz_watch_broadcast(w->engine, r->id, r->parent, r->parent_len, r->tx, r->len);
        r->parent = r->tx = NULL;
        break;
    }
    /* the loop side checked the same limits: a refusal here means the two
     * counts went apart, which the tests require never to happen */
    if (rc != GZ_CHAINW_OK) w->diverged++;
    w->req_head = (w->req_head + 1) % w->cfg.max_requests;
    w->req_count--;
  }
}

/* Called by the engine between chain calls: requests queued meanwhile are
 * handed over, so that a broadcast does not wait for the end of a long pass. */
static void engine_between(void *ctx) {
  gz_chainw *w = ctx;
  pthread_mutex_lock(&w->mu);
  if (!w->stop && !w->reset_pending) apply_requests(w);
  pthread_mutex_unlock(&w->mu);
}

static void *worker_main(void *arg) {
  gz_chainw *w = arg;
  pthread_mutex_lock(&w->mu);
  for (;;) {
    if (w->stop) break;
    if (w->reset_pending) {
      /* the loop has already purged both queues; now the engine forgets */
      gz_watch_clear(w->engine);
      w->reset_pending = false;
      if (w->cfg.interrupt != NULL) w->cfg.interrupt(w->cfg.interrupt_ctx, false);
    }
    apply_requests(w);
    uint32_t wait = gz_watch_wait_ms(w->engine);
    if (wait > 0) {
      struct timespec until;
      clock_gettime(CLOCK_MONOTONIC, &until);
      until.tv_sec += (time_t)(wait / 1000u);
      until.tv_nsec += (long)(wait % 1000u) * 1000000L;
      if (until.tv_nsec >= 1000000000L) {
        until.tv_sec += 1;
        until.tv_nsec -= 1000000000L;
      }
      /* woken early by a request, a reset or a stop: look again */
      (void)pthread_cond_timedwait(&w->work, &w->mu, &until);
      continue;
    }
    pthread_mutex_unlock(&w->mu);
    (void)gz_watch_step(w->engine); /* the only place that waits on the network */
    pthread_mutex_lock(&w->mu);
    w->passes++;
  }
  pthread_mutex_unlock(&w->mu);
  return NULL;
}

/* ---- the loop side ------------------------------------------------------- */

static bool set_nonblocking_cloexec(int fd) {
  int fl = fcntl(fd, F_GETFL);
  if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) return false;
  int fdfl = fcntl(fd, F_GETFD);
  return fdfl >= 0 && fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC) == 0;
}

gz_chainw *gz_chainw_new(const gz_chainw_config *cfg) {
  if (cfg == NULL || cfg->max_requests == 0 || cfg->max_requests > 1000000 ||
      cfg->max_results < 2 || cfg->max_results > 1000000 ||
      cfg->max_requests < cfg->max_watches + GZ_CHAINW_MAX_BROADCASTS)
    return NULL;
  gz_chainw *w = calloc(1, sizeof *w);
  if (w == NULL) return NULL;
  w->cfg = *cfg;
  w->wake_r = w->wake_w = -1;
  if (w->cfg.now_ms == NULL) {
    w->cfg.now_ms = monotonic_ms;
    w->cfg.clock_ctx = NULL;
  }
  gz_watch_config ec;
  memset(&ec, 0, sizeof ec);
  ec.chain = cfg->chain;
  ec.network = cfg->network;
  ec.tip_poll_ms = cfg->tip_poll_ms;
  ec.retry_ms = cfg->retry_ms;
  ec.retry_max_ms = cfg->retry_max_ms;
  ec.burial_depth = cfg->burial_depth;
  ec.max_watches = cfg->max_watches;
  ec.broadcast_attempts = cfg->broadcast_attempts;
  ec.broadcast_backoff_ms = cfg->broadcast_backoff_ms;
  ec.broadcast_backoff_max_ms = cfg->broadcast_backoff_max_ms;
  ec.header_window = cfg->header_window;
  ec.max_catchup = cfg->max_catchup;
  ec.max_link = cfg->max_link;
  ec.report_synced = cfg->report_synced;
  ec.now_ms = w->cfg.now_ms;
  ec.clock_ctx = w->cfg.clock_ctx;
  ec.stop = engine_stop;
  ec.stop_ctx = w;
  ec.between = engine_between;
  ec.between_ctx = w;
  ec.emit = engine_emit;
  ec.emit_ctx = w;
  w->engine = gz_watch_new(&ec); /* refuses mainnet and limits out of range */
  w->reqs = calloc(cfg->max_requests, sizeof *w->reqs);
  w->events = calloc(cfg->max_results, sizeof *w->events);
  w->set = w->engine != NULL ? calloc(cfg->max_watches, sizeof *w->set) : NULL;
  int fds[2] = {-1, -1};
  bool ok = w->engine != NULL && w->reqs != NULL && w->events != NULL && w->set != NULL;
  ok = ok && pipe(fds) == 0;
  if (ok) {
    w->wake_r = fds[0];
    w->wake_w = fds[1];
    ok = set_nonblocking_cloexec(fds[0]) && set_nonblocking_cloexec(fds[1]);
  }
  bool have_mu = false, have_work = false, have_room = false;
  if (ok) {
    pthread_condattr_t attr;
    have_mu = pthread_mutex_init(&w->mu, NULL) == 0;
    ok = have_mu && pthread_condattr_init(&attr) == 0;
    if (ok) {
      ok = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0;
      have_work = ok && pthread_cond_init(&w->work, &attr) == 0;
      have_room = have_work && pthread_cond_init(&w->room, NULL) == 0;
      ok = have_room;
      pthread_condattr_destroy(&attr);
    }
  }
  w->generation = 1;
  if (ok) ok = pthread_create(&w->thread, NULL, worker_main, w) == 0;
  if (!ok) {
    if (have_room) pthread_cond_destroy(&w->room);
    if (have_work) pthread_cond_destroy(&w->work);
    if (have_mu) pthread_mutex_destroy(&w->mu);
    if (w->wake_r >= 0) close(w->wake_r);
    if (w->wake_w >= 0) close(w->wake_w);
    gz_watch_free(w->engine);
    free(w->reqs);
    free(w->events);
    free(w->set);
    free(w);
    return NULL;
  }
  return w;
}

int gz_chainw_fd(const gz_chainw *w) { return w != NULL ? w->wake_r : -1; }

/* Called with mu held. Queues a request and wakes the worker. */
static int enqueue(gz_chainw *w, const request *r) {
  if (w->req_count == w->cfg.max_requests) return GZ_CHAINW_BUSY;
  w->reqs[(w->req_head + w->req_count) % w->cfg.max_requests] = *r;
  w->req_count++;
  pthread_cond_signal(&w->work);
  return GZ_CHAINW_OK;
}

static mirror *set_find(gz_chainw *w, bool tx, const uint8_t txid[GZ_HASH_LEN], uint32_t vout) {
  for (size_t i = 0; i < w->set_count; i++) {
    mirror *m = &w->set[i];
    if (m->tx == tx && m->vout == vout && memcmp(m->txid, txid, GZ_HASH_LEN) == 0) return m;
  }
  return NULL;
}

static int watch_any(gz_chainw *w, bool tx, const uint8_t txid[GZ_HASH_LEN], uint32_t vout,
                     uint32_t depth, unsigned flags) {
  if (w == NULL || txid == NULL || depth > GZ_CHAINW_MAX_DEPTH ||
      (flags & ~GZ_CHAINW_NOT_BEFORE) != 0)
    return GZ_CHAINW_INVALID;
  request r;
  memset(&r, 0, sizeof r);
  r.kind = tx ? REQ_WATCH_TX : REQ_WATCH_OUTPOINT;
  memcpy(r.txid, txid, GZ_HASH_LEN);
  r.vout = vout;
  r.depth = depth;
  r.flags = flags;
  pthread_mutex_lock(&w->mu);
  int rc;
  bool known = set_find(w, tx, txid, vout) != NULL;
  if (!known && w->set_count == w->cfg.max_watches) {
    rc = GZ_CHAINW_FULL;
  } else {
    rc = enqueue(w, &r);
    if (rc == GZ_CHAINW_OK && !known) {
      mirror *m = &w->set[w->set_count++];
      m->tx = tx;
      m->vout = vout;
      memcpy(m->txid, txid, GZ_HASH_LEN);
    }
  }
  pthread_mutex_unlock(&w->mu);
  return rc;
}

int gz_chainw_watch_tx(gz_chainw *w, const uint8_t txid[GZ_HASH_LEN], uint32_t depth,
                       unsigned flags) {
  return watch_any(w, true, txid, 0, depth, flags);
}

int gz_chainw_watch_outpoint(gz_chainw *w, const uint8_t txid[GZ_HASH_LEN], uint32_t vout,
                             uint32_t depth, unsigned flags) {
  return watch_any(w, false, txid, vout, depth, flags);
}

static int unwatch_any(gz_chainw *w, bool tx, const uint8_t txid[GZ_HASH_LEN], uint32_t vout) {
  if (w == NULL || txid == NULL) return GZ_CHAINW_INVALID;
  request r;
  memset(&r, 0, sizeof r);
  r.kind = tx ? REQ_DROP_TX : REQ_DROP_OUTPOINT;
  memcpy(r.txid, txid, GZ_HASH_LEN);
  r.vout = vout;
  pthread_mutex_lock(&w->mu);
  int rc = GZ_CHAINW_OK;
  mirror *m = set_find(w, tx, txid, vout);
  if (m != NULL) {
    rc = enqueue(w, &r);
    if (rc == GZ_CHAINW_OK) *m = w->set[--w->set_count];
  }
  pthread_mutex_unlock(&w->mu);
  return rc;
}

int gz_chainw_unwatch_tx(gz_chainw *w, const uint8_t txid[GZ_HASH_LEN]) {
  return unwatch_any(w, true, txid, 0);
}

int gz_chainw_unwatch_outpoint(gz_chainw *w, const uint8_t txid[GZ_HASH_LEN], uint32_t vout) {
  return unwatch_any(w, false, txid, vout);
}

int gz_chainw_release(gz_chainw *w, const uint8_t txid[GZ_HASH_LEN], uint32_t delay_ms) {
  if (w == NULL || txid == NULL) return GZ_CHAINW_INVALID;
  request r;
  memset(&r, 0, sizeof r);
  r.kind = REQ_RELEASE;
  memcpy(r.txid, txid, GZ_HASH_LEN);
  r.delay_ms = delay_ms;
  pthread_mutex_lock(&w->mu);
  int rc = enqueue(w, &r);
  pthread_mutex_unlock(&w->mu);
  return rc;
}

static uint8_t *copy_bytes(const uint8_t *p, size_t len) {
  uint8_t *c = malloc(len ? len : 1);
  if (c != NULL && len) memcpy(c, p, len);
  return c;
}

int gz_chainw_broadcast_package(gz_chainw *w, uint64_t id, const uint8_t *parent,
                                size_t parent_len, const uint8_t *child, size_t child_len) {
  uint8_t txid[GZ_HASH_LEN];
  if (w == NULL || child == NULL || child_len > GZ_TX_MAX_BYTES ||
      !gz_txid_from_raw(child, child_len, txid))
    return GZ_CHAINW_INVALID;
  if (parent != NULL &&
      (parent_len > GZ_TX_MAX_BYTES || !gz_txid_from_raw(parent, parent_len, txid)))
    return GZ_CHAINW_INVALID;
  request r;
  memset(&r, 0, sizeof r);
  r.kind = REQ_BROADCAST;
  r.id = id;
  r.tx = copy_bytes(child, child_len);
  r.len = child_len;
  if (parent != NULL) {
    r.parent = copy_bytes(parent, parent_len);
    r.parent_len = parent_len;
  }
  if (r.tx == NULL || (parent != NULL && r.parent == NULL)) {
    request_free(&r);
    return GZ_CHAINW_INVALID;
  }
  pthread_mutex_lock(&w->mu);
  int rc = w->broadcasts == GZ_CHAINW_MAX_BROADCASTS ? GZ_CHAINW_FULL : enqueue(w, &r);
  if (rc == GZ_CHAINW_OK) w->broadcasts++;
  pthread_mutex_unlock(&w->mu);
  if (rc != GZ_CHAINW_OK) request_free(&r);
  return rc;
}

int gz_chainw_broadcast(gz_chainw *w, uint64_t id, const uint8_t *raw, size_t len) {
  return gz_chainw_broadcast_package(w, id, NULL, 0, raw, len);
}

int gz_chainw_take(gz_chainw *w, gz_chainw_event *out) {
  if (w == NULL || out == NULL) return 0;
  int got = 0;
  pthread_mutex_lock(&w->mu);
  if (w->ev_count > 0) {
    *out = w->events[w->ev_head];
    w->ev_head = (w->ev_head + 1) % w->cfg.max_results;
    w->ev_count--;
    if (w->ev_count == 0) wake_clear(w);
    pthread_cond_signal(&w->room);
    got = 1;
  }
  pthread_mutex_unlock(&w->mu);
  return got;
}

uint64_t gz_chainw_reset(gz_chainw *w) {
  if (w == NULL) return 0;
  pthread_mutex_lock(&w->mu);
  while (w->req_count > 0) {
    request_free(&w->reqs[w->req_head]);
    w->req_head = (w->req_head + 1) % w->cfg.max_requests;
    w->req_count--;
  }
  w->ev_head = w->ev_count = 0;
  wake_clear(w);
  w->set_count = 0;
  w->broadcasts = 0;
  w->generation++;
  w->reset_pending = true;
  uint64_t g = w->generation;
  /* end the request in progress; the worker allows them again once its
   * engine has forgotten the old generation */
  if (w->cfg.interrupt != NULL) w->cfg.interrupt(w->cfg.interrupt_ctx, true);
  pthread_cond_broadcast(&w->work);
  pthread_cond_broadcast(&w->room);
  pthread_mutex_unlock(&w->mu);
  return g;
}

void gz_chainw_stats_get(gz_chainw *w, gz_chainw_stats *out) {
  if (w == NULL || out == NULL) return;
  pthread_mutex_lock(&w->mu);
  out->generation = w->generation;
  out->passes = w->passes;
  out->events = w->n_events;
  out->waits = w->waits;
  out->diverged = w->diverged;
  out->watches = w->set_count;
  out->broadcasts = w->broadcasts;
  out->queued_events = w->ev_count;
  out->queued_requests = w->req_count;
  pthread_mutex_unlock(&w->mu);
}

void gz_chainw_free(gz_chainw *w) {
  if (w == NULL) return;
  pthread_mutex_lock(&w->mu);
  w->stop = true;
  if (w->cfg.interrupt != NULL) w->cfg.interrupt(w->cfg.interrupt_ctx, true);
  pthread_cond_broadcast(&w->work);
  pthread_cond_broadcast(&w->room);
  pthread_mutex_unlock(&w->mu);
  pthread_join(w->thread, NULL);
  /* the chain can be used again by whoever owns it */
  if (w->cfg.interrupt != NULL) w->cfg.interrupt(w->cfg.interrupt_ctx, false);
  while (w->req_count > 0) {
    request_free(&w->reqs[w->req_head]);
    w->req_head = (w->req_head + 1) % w->cfg.max_requests;
    w->req_count--;
  }
  gz_watch_free(w->engine);
  pthread_cond_destroy(&w->room);
  pthread_cond_destroy(&w->work);
  pthread_mutex_destroy(&w->mu);
  close(w->wake_r);
  close(w->wake_w);
  free(w->reqs);
  free(w->events);
  free(w->set);
  free(w);
}
