/*
 * The watch engine (watch.c) against the made-up chain of sim.h, through the
 * real Esplora backend and the real comparing backend, on a clock the test
 * moves. Every scenario states the exact sequence of events it expects, in
 * the one-line form of simtest.h.
 *
 *   GZ_SIM_GRIND=1 chain_test_watch   prints sim_nonces.h again
 */
#include "test.h"

#include "../esplora_parse.h"
#include "../watch.h"
#include "simtest.h"

typedef struct fx {
  sim_net net;
  sim_stack stack;
  gz_watch *e;
  st_rec rec;
  gz_watch_config cfg;
  char line[4096];
} fx;

static void fx_config(fx *f) {
  memset(&f->cfg, 0, sizeof f->cfg);
  f->cfg.chain = &f->stack.multi;
  f->cfg.network = GZ_NET_SIGNET;
  f->cfg.tip_poll_ms = 1000;
  f->cfg.retry_ms = 500;
  f->cfg.retry_max_ms = 1000;
  f->cfg.burial_depth = 3;
  f->cfg.max_watches = 8;
  f->cfg.broadcast_attempts = 3;
  f->cfg.broadcast_backoff_ms = 100;
  f->cfg.broadcast_backoff_max_ms = 400;
  f->cfg.header_window = 16;
  f->cfg.max_catchup = 6;
  f->cfg.now_ms = sim_clock;
  f->cfg.clock_ctx = &f->net;
  f->cfg.emit = st_record;
  f->cfg.emit_ctx = &f->rec;
}

static void fx_open(fx *f) {
  memset(f, 0, sizeof *f);
  sim_net_init(&f->net, false);
  if (!sim_stack_open(&f->stack, &f->net)) {
    fprintf(stderr, "cannot build the backends\n");
    exit(2);
  }
  f->rec.w = &f->net.world;
  fx_config(f);
}

static void fx_start(fx *f) {
  f->e = gz_watch_new(&f->cfg);
  if (f->e == NULL) {
    fprintf(stderr, "cannot make the engine\n");
    exit(2);
  }
}

static void fx_close(fx *f) {
  gz_watch_free(f->e);
  sim_stack_close(&f->stack);
  sim_net_free(&f->net);
}

/* Both servers on `branch` at `tip`. */
static void both(fx *f, int branch, uint32_t tip) {
  for (int i = 0; i < 2; i++) {
    f->net.view[i].branch = branch;
    f->net.view[i].tip = tip;
  }
}
static void pool(fx *f, int tx, bool in) { f->net.view[0].mempool[tx] = f->net.view[1].mempool[tx] = in; }

/* One second passes, one pass; what was told. */
static const char *go(fx *f) {
  f->net.now += 1000;
  (void)gz_watch_step(f->e);
  st_join(&f->rec, f->line, sizeof f->line);
  return f->line;
}

#define SEQ(got, want)                                                                 \
  do {                                                                                 \
    const char *got_ = (got);                                                          \
    T->checks++;                                                                       \
    if (strcmp(got_, (want)) != 0) {                                                   \
      T->failed++;                                                                     \
      fprintf(stderr, "  %s:%d: events\n     got: %s\n  wanted: %s\n", __FILE__, __LINE__, got_, \
              (want));                                                                 \
    }                                                                                  \
  } while (0)

#define TXID(f, i) ((f)->net.world.tx[i].id)

/* ---- the scenarios -------------------------------------------------------- */

static void test_confirm_reorg_confirm(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  SEQ(go(&f), "tip 1003");
  SEQ(go(&f), "");
  pool(&f, SIM_T, true);
  SEQ(go(&f), "mempool T");
  SEQ(go(&f), "");
  both(&f, SIM_A, SIM_H0 + 5);
  SEQ(go(&f), "tip 1005 | confirmed T n=1 at a5");
  SEQ(go(&f), "");
  /* the block that held it is replaced; the other branch has not mined it yet */
  both(&f, SIM_B, SIM_H0 + 5);
  SEQ(go(&f), "reorg from 1004 gone 2 | tip 1005 | unconfirmed T mempool");
  SEQ(go(&f), "");
  both(&f, SIM_B, SIM_H0 + 6);
  SEQ(go(&f), "tip 1006 | confirmed T n=1 at b6");
  both(&f, SIM_B, SIM_H0 + 7);
  SEQ(go(&f), "tip 1007 | confirmed T n=2 at b6");
  both(&f, SIM_B, SIM_H0 + 8);
  SEQ(go(&f), "tip 1008 | confirmed T n=3 at b6 buried");
  /* past the burial depth nothing more is told */
  both(&f, SIM_B, SIM_H0 + 10);
  SEQ(go(&f), "tip 1010");
  fx_close(&f);
}

static void test_reorg_moves_a_confirmation(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(gz_watch_outpoint(f.e, f.net.world.p, 0, 3, 0) == GZ_CHAINW_OK);
  SEQ(go(&f), "tip 1003");
  both(&f, SIM_A, SIM_H0 + 6);
  SEQ(go(&f), "tip 1006 | confirmed T n=2 at a5 | spent P:0 by S1 n=1 at a6");
  both(&f, SIM_A, SIM_H0 + 7);
  SEQ(go(&f), "tip 1007 | confirmed T n=3 at a5 buried | spent P:0 by S1 n=2 at a6");
  both(&f, SIM_A, SIM_H0 + 8);
  SEQ(go(&f), "tip 1008 | spent P:0 by S1 n=3 at a6 buried");
  /* a five-block reorganisation: T is now one block later, and another
   * transaction spends the outpoint */
  both(&f, SIM_B, SIM_H0 + 8);
  SEQ(go(&f), "reorg from 1004 gone 5 | tip 1008 | unconfirmed T | confirmed T n=3 at b6 buried | "
              "spent P:0 by S2 n=2 at b7 replaced reorg");
  both(&f, SIM_B, SIM_H0 + 9);
  SEQ(go(&f), "tip 1009 | spent P:0 by S2 n=3 at b7 buried");
  fx_close(&f);
}

static void test_depth_goes_down(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 6, 0) == GZ_CHAINW_OK);
  both(&f, SIM_A, SIM_H0 + 9);
  SEQ(go(&f), "tip 1009 | confirmed T n=5 at a5");
  /* three blocks replaced by two: the block of T stays, its depth drops */
  both(&f, SIM_C, SIM_H0 + 8);
  SEQ(go(&f), "reorg from 1007 gone 3 | tip 1008 | confirmed T n=4 at a5 reorg");
  SEQ(go(&f), "");
  /* servers showing an older tip of the same chain change nothing */
  both(&f, SIM_C, SIM_H0 + 7);
  SEQ(go(&f), "");
  both(&f, SIM_C, SIM_H0 + 8);
  SEQ(go(&f), "");
  fx_close(&f);
}

static void test_double_spend(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_outpoint(f.e, f.net.world.p, 0, 3, 0) == GZ_CHAINW_OK);
  both(&f, SIM_B, SIM_H0 + 6);
  SEQ(go(&f), "tip 1006");
  pool(&f, SIM_S1, true);
  SEQ(go(&f), "spent P:0 by S1 n=0");
  SEQ(go(&f), "");
  /* a block confirms the other spender */
  pool(&f, SIM_S1, false);
  both(&f, SIM_B, SIM_H0 + 7);
  SEQ(go(&f), "tip 1007 | spent P:0 by S2 n=1 at b7 replaced");
  both(&f, SIM_B, SIM_H0 + 8);
  SEQ(go(&f), "tip 1008 | spent P:0 by S2 n=2 at b7");
  both(&f, SIM_B, SIM_H0 + 9);
  SEQ(go(&f), "tip 1009 | spent P:0 by S2 n=3 at b7 buried");
  fx_close(&f);

  /* a confirmed spender reorganised out, the outpoint unspent again, then
   * spent in the mempool by the other */
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_outpoint(f.e, f.net.world.p, 0, 3, 0) == GZ_CHAINW_OK);
  SEQ(go(&f), "tip 1003");
  both(&f, SIM_A, SIM_H0 + 6);
  SEQ(go(&f), "tip 1006 | spent P:0 by S1 n=1 at a6");
  both(&f, SIM_B, SIM_H0 + 6);
  SEQ(go(&f), "reorg from 1004 gone 3 | tip 1006 | unspent P:0 was S1 reorg");
  pool(&f, SIM_S2, true);
  SEQ(go(&f), "spent P:0 by S2 n=0");
  /* and the same spender back to the mempool after being confirmed */
  both(&f, SIM_B, SIM_H0 + 7);
  SEQ(go(&f), "tip 1007 | spent P:0 by S2 n=1 at b7");
  both(&f, SIM_A, SIM_H0 + 5);
  SEQ(go(&f), "reorg from 1004 gone 4 | tip 1005 | spent P:0 by S2 n=0 reorg");
  fx_close(&f);
}

static void test_server_lags(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  SEQ(go(&f), "tip 1003");
  /* one server is a block behind: the agreed tip is the lower one, and the
   * confirmation only one server has yet is not told */
  f.net.view[0].tip = SIM_H0 + 5;
  f.net.view[1].tip = SIM_H0 + 4;
  SEQ(go(&f), "tip 1004 | sources server-lagging");
  SEQ(go(&f), "");
  SEQ(go(&f), "");
  f.net.view[1].tip = SIM_H0 + 5;
  SEQ(go(&f), "tip 1005 | confirmed T n=1 at a5 | sources ok");
  /* lag that does not end is disagreement after 30 minutes */
  f.net.view[0].tip = SIM_H0 + 7;
  f.net.view[1].tip = SIM_H0 + 6;
  CHECK(gz_watch_outpoint(f.e, f.net.world.tx[SIM_T].id, 0, 3, 0) == GZ_CHAINW_OK);
  SEQ(go(&f), "tip 1006 | confirmed T n=2 at a5 | sources server-lagging");
  f.net.now += 31u * 60u * 1000u;
  SEQ(go(&f), "sources servers-disagree");
  f.net.view[1].tip = SIM_H0 + 7;
  SEQ(go(&f), "tip 1007 | confirmed T n=3 at a5 buried | spent T:0 by K n=1 at a7 | sources ok");
  fx_close(&f);
}

static void test_server_far_behind_or_elsewhere(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  /* six blocks apart: no agreed tip, nothing is told */
  f.net.view[0].tip = SIM_H0 + 9;
  f.net.view[1].tip = SIM_H0 + 3;
  SEQ(go(&f), "sources servers-disagree");
  SEQ(go(&f), "");
  f.net.view[1].tip = SIM_H0 + 9;
  SEQ(go(&f), "tip 1009 | confirmed T n=5 at a5 buried | sources ok");
  /* both servers fall far behind what was checked: not believed */
  both(&f, SIM_A, SIM_H0 + 3);
  SEQ(go(&f), "sources servers-disagree");
  SEQ(go(&f), "");
  both(&f, SIM_A, SIM_H0 + 9);
  SEQ(go(&f), "sources ok");
  fx_close(&f);

  /* a server on another chain is left out, and one operator is no quorum */
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  both(&f, SIM_A, SIM_H0 + 6);
  f.net.view[1].mainnet = true;
  SEQ(go(&f), "sources no-quorum");
  SEQ(go(&f), "");
  fx_close(&f);
  /* both on another chain */
  fx_open(&f);
  fx_start(&f);
  f.net.view[0].mainnet = f.net.view[1].mainnet = true;
  SEQ(go(&f), "sources wrong-network");
  fx_close(&f);
}

static void test_servers_disagree(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  SEQ(go(&f), "tip 1003");
  /* two different blocks at one height */
  f.net.view[0].tip = f.net.view[1].tip = SIM_H0 + 5;
  f.net.view[1].branch = SIM_B;
  SEQ(go(&f), "sources servers-disagree");
  SEQ(go(&f), "");
  f.net.view[1].branch = SIM_A;
  SEQ(go(&f), "tip 1005 | confirmed T n=1 at a5 | sources ok");
  fx_close(&f);

  /* one server hides a confirmed transaction that is not above its tip */
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  both(&f, SIM_A, SIM_H0 + 6);
  f.net.view[1].hide[SIM_T] = true;
  SEQ(go(&f), "tip 1006 | sources servers-disagree");
  SEQ(go(&f), "");
  f.net.view[1].hide[SIM_T] = false;
  SEQ(go(&f), "confirmed T n=2 at a5 | sources ok");
  fx_close(&f);
}

static void test_server_lies_about_depth(test_state *T) {
  fx f;
  /* both servers say T confirmed two blocks earlier than it did */
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  both(&f, SIM_A, SIM_H0 + 5);
  f.net.view[0].lie_height = f.net.view[1].lie_height = -2;
  SEQ(go(&f), "tip 1005 | sources servers-disagree");
  SEQ(go(&f), "");
  f.net.view[0].lie_height = f.net.view[1].lie_height = 0;
  SEQ(go(&f), "confirmed T n=1 at a5 | sources ok");
  fx_close(&f);

  /* both servers claim a tip four blocks above the chain they can show */
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  both(&f, SIM_A, SIM_H0 + 5);
  SEQ(go(&f), "tip 1005 | confirmed T n=1 at a5");
  f.net.view[0].claim_tip = f.net.view[1].claim_tip = SIM_H0 + 9;
  SEQ(go(&f), "sources malformed");
  SEQ(go(&f), "");
  f.net.view[0].claim_tip = f.net.view[1].claim_tip = 0;
  SEQ(go(&f), "sources ok");
  fx_close(&f);

  /* both servers put blocks of another branch on top of the block of T: the
   * headers do not link, so none of them adds depth */
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  both(&f, SIM_A, SIM_H0 + 5);
  SEQ(go(&f), "tip 1005 | confirmed T n=1 at a5");
  both(&f, SIM_A, SIM_H0 + 8);
  f.net.view[0].graft = f.net.view[1].graft = SIM_H0 + 6;
  SEQ(go(&f), "sources bad-proof");
  SEQ(go(&f), "");
  f.net.view[0].graft = f.net.view[1].graft = 0;
  SEQ(go(&f), "tip 1008 | confirmed T n=4 at a5 buried | sources ok");
  fx_close(&f);
}

static void test_mempool_eviction(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(gz_watch_outpoint(f.e, f.net.world.p, 0, 3, 0) == GZ_CHAINW_OK);
  SEQ(go(&f), "tip 1003");
  pool(&f, SIM_T, true);
  pool(&f, SIM_S1, true);
  SEQ(go(&f), "mempool T | spent P:0 by S1 n=0");
  pool(&f, SIM_T, false);
  SEQ(go(&f), "evicted T");
  SEQ(go(&f), "");
  pool(&f, SIM_S1, false);
  SEQ(go(&f), "unspent P:0 was S1");
  /* seen by one server only: neither seen nor gone until both say the same */
  f.net.view[0].mempool[SIM_T] = true;
  f.net.view[0].mempool[SIM_S2] = true;
  SEQ(go(&f), "");
  pool(&f, SIM_T, true);
  pool(&f, SIM_S2, true);
  SEQ(go(&f), "mempool T | spent P:0 by S2 n=0");
  f.net.view[1].mempool[SIM_T] = false;
  f.net.view[1].mempool[SIM_S2] = false;
  SEQ(go(&f), "");
  pool(&f, SIM_T, false);
  pool(&f, SIM_S2, false);
  SEQ(go(&f), "evicted T | unspent P:0 was S2");
  fx_close(&f);
}

static uint8_t *dup_tx(const sim_tx *t) {
  uint8_t *p = malloc(t->len);
  memcpy(p, t->raw, t->len);
  return p;
}

static int send_tx(fx *f, uint64_t id, int tx) {
  const sim_tx *t = &f->net.world.tx[tx];
  return gz_watch_broadcast(f->e, id, NULL, 0, dup_tx(t), t->len);
}

static int send_pair(fx *f, uint64_t id, int parent, int child) {
  const sim_tx *p = &f->net.world.tx[parent], *c = &f->net.world.tx[child];
  return gz_watch_broadcast(f->e, id, dup_tx(p), p->len, dup_tx(c), c->len);
}

static void test_broadcast_rejected_then_accepted(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  SEQ(go(&f), "tip 1003");
  f.net.view[0].post = f.net.view[1].post = SIM_POST_REJECT;
  CHECK(send_tx(&f, 1, SIM_T) == GZ_CHAINW_OK);
  CHECK(gz_watch_broadcasts(f.e) == 1);
  (void)gz_watch_step(f.e);
  CHECK(f.rec.n == 1 && strstr(f.rec.ev[0].broadcast.reason, "min relay fee not met, 6 < 11") != NULL);
  CHECK(f.rec.n == 1 && f.rec.ev[0].broadcast.server_status == 400);
  CHECK(f.rec.n == 1 && memcmp(f.rec.ev[0].txid, TXID(&f, SIM_T), 32) == 0);
  CHECK(f.rec.n == 1 && f.rec.ev[0].broadcast.server_count == 2 &&
        f.rec.ev[0].broadcast.servers[1].result == GZ_CHAIN_REJECTED);
  st_join(&f.rec, f.line, sizeof f.line);
  SEQ(f.line, "broadcast #1 rejected final tries=1");
  CHECK(gz_watch_broadcasts(f.e) == 0);
  SEQ(go(&f), "");
  f.net.view[0].post = f.net.view[1].post = SIM_POST_ACCEPT;
  CHECK(send_tx(&f, 2, SIM_T) == GZ_CHAINW_OK);
  SEQ(go(&f), "broadcast #2 accepted final tries=1 | mempool T");
  /* again: the servers have it */
  f.net.view[0].post = f.net.view[1].post = SIM_POST_KNOWN;
  CHECK(send_tx(&f, 3, SIM_T) == GZ_CHAINW_OK);
  SEQ(go(&f), "broadcast #3 already-known final tries=1");
  /* one refuses, one accepts: accepted */
  f.net.view[0].post = SIM_POST_REJECT;
  f.net.view[1].post = SIM_POST_ACCEPT;
  CHECK(send_tx(&f, 4, SIM_S1) == GZ_CHAINW_OK);
  SEQ(go(&f), "broadcast #4 accepted final tries=1");
  /* not a transaction: refused before anything is queued */
  uint8_t *junk = malloc(10);
  memset(junk, 7, 10);
  CHECK(gz_watch_broadcast(f.e, 5, NULL, 0, junk, 10) == GZ_CHAINW_INVALID);
  fx_close(&f);
}

static void test_broadcast_unreachable_backoff(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  SEQ(go(&f), "tip 1003");
  f.net.view[0].post = f.net.view[1].post = SIM_POST_DOWN;
  CHECK(send_tx(&f, 7, SIM_T) == GZ_CHAINW_OK);
  f.net.now += 1;
  (void)gz_watch_step(f.e);
  st_join(&f.rec, f.line, sizeof f.line);
  SEQ(f.line, "broadcast #7 unreachable tries=1");
  unsigned posts = f.net.view[0].posts;
  /* the second try waits 100 ms */
  f.net.now += 99;
  CHECK(gz_watch_wait_ms(f.e) == 1);
  (void)gz_watch_step(f.e);
  CHECK(f.net.view[0].posts == posts);
  f.net.now += 1;
  (void)gz_watch_step(f.e);
  CHECK(f.net.view[0].posts == posts + 1);
  CHECK(f.rec.n == 0); /* said once already */
  /* the third, 200 ms later, is the last */
  f.net.now += 199;
  (void)gz_watch_step(f.e);
  CHECK(f.net.view[0].posts == posts + 1);
  f.net.now += 1;
  (void)gz_watch_step(f.e);
  st_join(&f.rec, f.line, sizeof f.line);
  SEQ(f.line, "broadcast #7 unreachable final tries=3");
  CHECK(gz_watch_broadcasts(f.e) == 0);
  /* unreachable, then a server comes back */
  CHECK(send_tx(&f, 8, SIM_T) == GZ_CHAINW_OK);
  SEQ(go(&f), "broadcast #8 unreachable tries=1");
  f.net.view[1].post = SIM_POST_ACCEPT;
  SEQ(go(&f), "broadcast #8 accepted final tries=2");
  /* at most 16 at a time; the next is refused, not lost */
  f.net.view[1].post = SIM_POST_DOWN;
  for (uint64_t i = 0; i < GZ_CHAINW_MAX_BROADCASTS; i++) CHECK(send_tx(&f, 100 + i, SIM_T) == GZ_CHAINW_OK);
  CHECK(send_tx(&f, 200, SIM_T) == GZ_CHAINW_FULL);
  /* every one of them gets its final event */
  unsigned finals = 0;
  for (int i = 0; i < 6; i++) {
    f.net.now += 1000;
    (void)gz_watch_step(f.e);
    for (size_t k = 0; k < f.rec.n; k++)
      if (f.rec.ev[k].kind == GZ_CHAINW_BROADCAST && f.rec.ev[k].broadcast.final) finals++;
    f.rec.n = 0;
  }
  CHECK(finals == GZ_CHAINW_MAX_BROADCASTS);
  CHECK(gz_watch_broadcasts(f.e) == 0);
  fx_close(&f);
}

static void test_package(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  SEQ(go(&f), "tip 1003");
  /* no server has a package endpoint: said so, and never sent one by one */
  CHECK(send_pair(&f, 1, SIM_T, SIM_K) == GZ_CHAINW_OK);
  (void)gz_watch_step(f.e);
  CHECK(f.rec.n == 1 && strcmp(f.rec.ev[0].broadcast.reason,
                               "no chain server accepts transaction packages") == 0);
  CHECK(f.rec.n == 1 && f.rec.ev[0].broadcast.detail == GZ_CHAIN_UNSUPPORTED);
  CHECK(f.rec.n == 1 && memcmp(f.rec.ev[0].txid, TXID(&f, SIM_K), 32) == 0 &&
        memcmp(f.rec.ev[0].broadcast.parent_txid, TXID(&f, SIM_T), 32) == 0);
  st_join(&f.rec, f.line, sizeof f.line);
  SEQ(f.line, "broadcast #1 no-package-relay final tries=1 package parent=no-package-relay "
              "child=no-package-relay");
  CHECK(f.net.view[0].posts == 0 && f.net.view[1].posts == 0);
  CHECK(f.net.view[0].packages == 2 && f.net.view[1].packages == 2); /* both paths tried */
  /* one server has it, under the second path */
  f.net.view[1].package = SIM_PKG_OK_V1;
  CHECK(send_pair(&f, 2, SIM_T, SIM_K) == GZ_CHAINW_OK);
  SEQ(go(&f), "broadcast #2 accepted final tries=1 package parent=accepted child=accepted");
  CHECK(f.net.view[1].mempool[SIM_T] && f.net.view[1].mempool[SIM_K]);
  CHECK(f.net.view[0].posts == 0 && f.net.view[1].posts == 0);
  /* the server refuses the package: the outcome of each transaction, and why */
  f.net.view[0].package = SIM_PKG_FAIL;
  f.net.view[1].package = SIM_PKG_NONE;
  CHECK(send_pair(&f, 3, SIM_T, SIM_K) == GZ_CHAINW_OK);
  (void)gz_watch_step(f.e);
  CHECK(f.rec.n == 1 && strcmp(f.rec.ev[0].broadcast.reason, "transaction failed") == 0);
  st_join(&f.rec, f.line, sizeof f.line);
  SEQ(f.line, "broadcast #3 rejected final tries=1 package parent=rejected child=rejected");
  /* the only server with the endpoint is down: tried again, then unreachable,
   * not "no package relay" */
  f.net.view[0].package = SIM_PKG_DOWN;
  CHECK(send_pair(&f, 4, SIM_T, SIM_K) == GZ_CHAINW_OK);
  SEQ(go(&f), "broadcast #4 unreachable tries=1 package parent=unreachable child=unreachable");
  SEQ(go(&f), "");
  SEQ(go(&f), "broadcast #4 unreachable final tries=3 package parent=unreachable child=unreachable");
  fx_close(&f);
}

static void test_package_calls(test_state *T) {
  fx f;
  gz_package_result pr;
  fx_open(&f);
  const sim_tx *p = &f.net.world.tx[SIM_T], *c = &f.net.world.tx[SIM_K];
  /* one server */
  CHECK_RESULT(gz_chain_broadcast_package(&f.stack.server[0], p->raw, p->len, c->raw, c->len, &pr),
               GZ_CHAIN_UNSUPPORTED);
  CHECK(pr.parent.result == GZ_CHAIN_UNSUPPORTED && pr.child.result == GZ_CHAIN_UNSUPPORTED);
  f.net.view[0].package = SIM_PKG_OK;
  CHECK_RESULT(gz_chain_broadcast_package(&f.stack.server[0], p->raw, p->len, c->raw, c->len, &pr),
               GZ_CHAIN_OK);
  CHECK(pr.parent.result == GZ_CHAIN_OK && memcmp(pr.parent.txid, p->id, 32) == 0);
  CHECK(pr.child.result == GZ_CHAIN_OK && memcmp(pr.child.txid, c->id, 32) == 0);
  CHECK(pr.server_status == 200 && pr.reason[0] == 0);
  CHECK(f.net.view[0].packages == 3); /* two paths the first time, one now */
  f.net.view[0].package = SIM_PKG_FAIL;
  CHECK_RESULT(gz_chain_broadcast_package(&f.stack.server[0], p->raw, p->len, c->raw, c->len, &pr),
               GZ_CHAIN_REJECTED);
  CHECK(pr.parent.result == GZ_CHAIN_REJECTED && pr.child.result == GZ_CHAIN_REJECTED);
  CHECK(strcmp(pr.parent.reason, "min relay fee not met, 0 < 61") == 0);
  CHECK(strcmp(pr.child.reason, "bad-txns-inputs-missingorspent") == 0);
  CHECK(strcmp(pr.reason, "transaction failed") == 0);
  /* arguments */
  CHECK_RESULT(gz_chain_broadcast_package(&f.stack.server[0], p->raw, 10, c->raw, c->len, &pr),
               GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_broadcast_package(&f.stack.server[0], p->raw, p->len, c->raw, 9, &pr),
               GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_broadcast_package(&f.stack.server[0], NULL, p->len, c->raw, c->len, &pr),
               GZ_CHAIN_INVALID_ARG);
  CHECK(f.net.view[0].packages == 4);
  /* a garbled answer is not an acceptance */
  f.net.view[0].package = SIM_PKG_OK;
  f.net.view[0].fault = SIM_FAULT_TRUNCATE;
  f.net.view[0].cut = 40;
  f.net.view[0].fault_path = "package";
  CHECK_RESULT(gz_chain_broadcast_package(&f.stack.server[0], p->raw, p->len, c->raw, c->len, &pr),
               GZ_CHAIN_MALFORMED);
  f.net.view[0].fault = SIM_FAULT_NONE;
  /* a server on another chain is never sent a package */
  f.net.view[1].mainnet = true;
  f.net.view[1].package = SIM_PKG_OK;
  unsigned before = f.net.view[1].packages;
  f.net.view[0].package = SIM_PKG_NONE;
  CHECK_RESULT(gz_chain_broadcast_package(&f.stack.multi, p->raw, p->len, c->raw, c->len, &pr),
               GZ_CHAIN_UNSUPPORTED);
  CHECK(f.net.view[1].packages == before);
  sim_stack_close(&f.stack);
  sim_net_free(&f.net);

  /* the parser, on what Bitcoin Core answers */
  gz_es_package pk;
  uint8_t a[32], b[32];
  memset(a, 0xaa, 32);
  memset(b, 0xbb, 32);
#define A64 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define B64 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  const char *ok = "{\"package_msg\":\"success\",\"tx-results\":{\"w1\":{\"txid\":\"" A64
                   "\",\"vsize\":110},\"w2\":{\"txid\":\"" B64 "\",\"fees\":{\"base\":0.1}}},"
                   "\"replaced-transactions\":[]}";
  CHECK(gz_es_parse_package(ok, strlen(ok), a, b, &pk) && pk.accepted);
  /* "success" without one of our transactions listed is not acceptance */
  const char *one = "{\"package_msg\":\"success\",\"tx-results\":{\"w1\":{\"txid\":\"" A64 "\"}}}";
  CHECK(gz_es_parse_package(one, strlen(one), a, b, &pk) && !pk.accepted && pk.parent_listed &&
        !pk.child_listed);
  const char *err = "{\"package_msg\":\"transaction failed\",\"tx-results\":{\"w1\":{\"txid\":\"" A64
                    "\",\"error\":\"too-long-mempool-chain\"},\"w2\":{\"txid\":\"" B64 "\"}}}";
  CHECK(gz_es_parse_package(err, strlen(err), a, b, &pk) && !pk.accepted && pk.parent_failed &&
        !pk.child_failed && strcmp(pk.parent_error, "too-long-mempool-chain") == 0);
  /* an error on a transaction beats "success" */
  const char *mixed = "{\"package_msg\":\"success\",\"tx-results\":{\"w1\":{\"txid\":\"" A64
                      "\",\"error\":\"x\"},\"w2\":{\"txid\":\"" B64 "\"}}}";
  CHECK(gz_es_parse_package(mixed, strlen(mixed), a, b, &pk) && !pk.accepted);
  const char *bad[] = {"", "[]", "{}", "{\"tx-results\":{}}", "{\"package_msg\":1}",
                       "{\"package_msg\":\"success\",\"tx-results\":[]}",
                       "{\"package_msg\":\"success\",\"tx-results\":{\"w\":1}}",
                       "{\"package_msg\":\"success\",\"tx-results\":{\"w\":{\"txid\":\"zz\"}}}",
                       "{\"package_msg\":\"success\",\"tx-results\":{\"w\":{\"txid\":\"" A64
                       "\",\"error\":7}}}"};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
    CHECK(!gz_es_parse_package(bad[i], strlen(bad[i]), a, b, &pk));
}

/* ---- privacy: not before -------------------------------------------------- */

static void test_not_before(test_state *T) {
  fx f;
  char hex[65];
  fx_open(&f);
  fx_start(&f);
  sim_hex(TXID(&f, SIM_T), hex);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, GZ_CHAINW_NOT_BEFORE) == GZ_CHAINW_OK);
  CHECK(gz_watch_outpoint(f.e, TXID(&f, SIM_T), 0, 3, GZ_CHAINW_NOT_BEFORE) == GZ_CHAINW_OK);
  CHECK(gz_watch_outpoint(f.e, f.net.world.p, 0, 3, 0) == GZ_CHAINW_OK);
  SEQ(go(&f), "tip 1003");
  pool(&f, SIM_T, true);
  SEQ(go(&f), "");
  /* it confirms, is buried and even spent: still no server is asked */
  both(&f, SIM_A, SIM_H0 + 8);
  SEQ(go(&f), "tip 1008 | spent P:0 by S1 n=3 at a6 buried");
  SEQ(go(&f), "");
  /* setting the watch again does not let it out */
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, GZ_CHAINW_NOT_BEFORE) == GZ_CHAINW_OK);
  SEQ(go(&f), "");
  CHECK(sim_requests(&f.net) > 20);
  CHECK(!sim_log_has(&f.net, hex));
  /* released with a delay of 2.5 s */
  gz_watch_release(f.e, TXID(&f, SIM_T), 2500);
  CHECK(gz_watch_wait_ms(f.e) <= 2500);
  SEQ(go(&f), "");
  SEQ(go(&f), "");
  CHECK(!sim_log_has(&f.net, hex));
  /* a second release cannot push the first one back */
  gz_watch_release(f.e, TXID(&f, SIM_T), 60000);
  SEQ(go(&f), "confirmed T n=4 at a5 buried | spent T:0 by K n=2 at a7");
  CHECK(sim_log_has(&f.net, hex));
  /* once released, a watch set again with the flag is not held back */
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, GZ_CHAINW_NOT_BEFORE) == GZ_CHAINW_OK);
  SEQ(go(&f), "confirmed T n=4 at a5 buried");
  fx_close(&f);

  /* never released: never asked, and the engine does not spin on it */
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, GZ_CHAINW_NOT_BEFORE) == GZ_CHAINW_OK);
  SEQ(go(&f), "tip 1003");
  CHECK(gz_watch_wait_ms(f.e) == 1000);
  for (int i = 0; i < 20; i++) SEQ(go(&f), "");
  CHECK(!sim_log_has(&f.net, hex));
  /* release with no delay */
  gz_watch_release(f.e, TXID(&f, SIM_T), 0);
  CHECK(gz_watch_wait_ms(f.e) == 0);
  pool(&f, SIM_T, true);
  SEQ(go(&f), "mempool T");
  fx_close(&f);
}

/* ---- the watch set -------------------------------------------------------- */

static void test_watch_set(test_state *T) {
  fx f;
  uint8_t id[32];
  fx_open(&f);
  fx_start(&f);
  memset(id, 0, sizeof id);
  for (uint8_t i = 0; i < 8; i++) {
    id[0] = i;
    CHECK(gz_watch_outpoint(f.e, id, i, 1, 0) == GZ_CHAINW_OK);
  }
  CHECK(gz_watch_count(f.e) == 8);
  /* one too many is refused, and nothing changes */
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_FULL);
  CHECK(gz_watch_count(f.e) == 8);
  /* one already set is not one more */
  CHECK(gz_watch_outpoint(f.e, id, 7, 2, 0) == GZ_CHAINW_OK);
  CHECK(gz_watch_count(f.e) == 8);
  /* the same txid as a transaction watch, or another output, is another watch */
  CHECK(gz_watch_outpoint(f.e, id, 6, 2, 0) == GZ_CHAINW_FULL);
  CHECK(gz_watch_tx(f.e, id, 2, 0) == GZ_CHAINW_FULL);
  gz_watch_drop_outpoint(f.e, id, 7);
  CHECK(gz_watch_count(f.e) == 7);
  gz_watch_drop_outpoint(f.e, id, 7); /* not set: nothing */
  gz_watch_drop_tx(f.e, id);
  CHECK(gz_watch_count(f.e) == 7);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), GZ_CHAINW_MAX_DEPTH + 1, 0) == GZ_CHAINW_INVALID);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 2) == GZ_CHAINW_INVALID);
  CHECK(gz_watch_tx(f.e, NULL, 3, 0) == GZ_CHAINW_INVALID);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), GZ_CHAINW_MAX_DEPTH, 0) == GZ_CHAINW_OK);
  fx_close(&f);

  /* set again: the state found is told again, with the real count; depth 0
   * is the configured burial depth; a dropped watch tells nothing more */
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 0, 0) == GZ_CHAINW_OK);
  both(&f, SIM_A, SIM_H0 + 9);
  SEQ(go(&f), "tip 1009 | confirmed T n=5 at a5 buried");
  SEQ(go(&f), "");
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 7, 0) == GZ_CHAINW_OK);
  SEQ(go(&f), "confirmed T n=5 at a5");
  both(&f, SIM_A, SIM_H0 + 10);
  SEQ(go(&f), "tip 1010 | confirmed T n=6 at a5");
  gz_watch_drop_tx(f.e, TXID(&f, SIM_T));
  both(&f, SIM_A, SIM_H0 + 11);
  SEQ(go(&f), "tip 1011");
  /* clear: nothing is watched, and the tip is told again */
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 0, 0) == GZ_CHAINW_OK);
  CHECK(send_tx(&f, 1, SIM_T) == GZ_CHAINW_OK);
  gz_watch_clear(f.e);
  CHECK(gz_watch_count(f.e) == 0 && gz_watch_broadcasts(f.e) == 0);
  SEQ(go(&f), "tip 1011");
  gz_chain_tip tip;
  CHECK(gz_watch_tip(f.e, &tip) && tip.height == SIM_H0 + 11);
  fx_close(&f);
}

static void test_config(test_state *T) {
  fx f;
  fx_open(&f);
  gz_watch_config c = f.cfg;
  CHECK(gz_watch_config_valid(&c));
  c.network = GZ_NET_MAINNET;
  CHECK(!gz_watch_config_valid(&c) && gz_watch_new(&c) == NULL);
  c.network = GZ_NET_INVALID;
  CHECK(!gz_watch_config_valid(&c));
  c.network = GZ_NET_TESTNET4;
  CHECK(gz_watch_config_valid(&c));
#define BAD(field, value) \
  c = f.cfg;              \
  c.field = value;        \
  CHECK(!gz_watch_config_valid(&c))
  BAD(chain, NULL);
  BAD(now_ms, NULL);
  BAD(emit, NULL);
  BAD(tip_poll_ms, 0);
  BAD(retry_ms, 0);
  BAD(retry_max_ms, 499);
  BAD(burial_depth, 0);
  BAD(burial_depth, GZ_CHAINW_MAX_DEPTH + 1);
  BAD(max_watches, 0);
  BAD(max_watches, GZ_CHAINW_WATCHES_LIMIT + 1);
  BAD(broadcast_attempts, 0);
  BAD(broadcast_backoff_ms, 0);
  BAD(broadcast_backoff_max_ms, 99);
  BAD(header_window, 3);
  BAD(max_catchup, 0);
  BAD(max_catchup, 17);
#undef BAD
  c = f.cfg;
  c.burial_depth = GZ_CHAINW_MAX_DEPTH;
  c.max_watches = GZ_CHAINW_WATCHES_LIMIT;
  c.header_window = 4;
  c.max_catchup = 4;
  c.retry_max_ms = 500;
  c.broadcast_backoff_max_ms = 100;
  CHECK(gz_watch_config_valid(&c));
  CHECK(!gz_watch_config_valid(NULL));
  sim_stack_close(&f.stack);
  sim_net_free(&f.net);
}

/* ---- the header chain ----------------------------------------------------- */

static void test_headers(test_state *T) {
  fx f;
  /* a tip further ahead than max_catchup: the headers begin again at the
   * tip and are followed back to the block of the transaction */
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 144, 0) == GZ_CHAINW_OK);
  SEQ(go(&f), "tip 1003");
  both(&f, SIM_A, SIM_H0 + 11);
  SEQ(go(&f), "tip 1011 | confirmed T n=7 at a5");
  fx_close(&f);

  /* a block older than the window can reach: counted once, by the
   * confirmation check, up to the depth asked for, and not followed */
  fx_open(&f);
  f.cfg.header_window = 4;
  f.cfg.max_catchup = 4;
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(gz_watch_outpoint(f.e, f.net.world.p, 0, 5, 0) == GZ_CHAINW_OK);
  both(&f, SIM_A, SIM_H0 + 10);
  SEQ(go(&f), "tip 1010 | confirmed T n=3 at a5 buried | spent P:0 by S1 n=5 at a6 buried");
  both(&f, SIM_A, SIM_H0 + 11);
  SEQ(go(&f), "tip 1011");
  fx_close(&f);

  /* a reorganisation further back than the headers kept */
  fx_open(&f);
  f.cfg.header_window = 4;
  f.cfg.max_catchup = 4;
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  both(&f, SIM_A, SIM_H0 + 5);
  SEQ(go(&f), "tip 1005 | confirmed T n=1 at a5");
  both(&f, SIM_A, SIM_H0 + 8);
  SEQ(go(&f), "tip 1008 | confirmed T n=4 at a5 buried");
  both(&f, SIM_B, SIM_H0 + 8);
  SEQ(go(&f), "reorg from 1005 gone 4 | tip 1008 | unconfirmed T | confirmed T n=3 at b6 buried");
  fx_close(&f);

  /* the window slides; a confirmation that leaves it stays counted */
  fx_open(&f);
  f.cfg.header_window = 4;
  f.cfg.max_catchup = 1;
  fx_start(&f);
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 6, 0) == GZ_CHAINW_OK);
  both(&f, SIM_A, SIM_H0 + 5);
  SEQ(go(&f), "tip 1005 | confirmed T n=1 at a5");
  for (uint32_t h = 6; h <= 10; h++) {
    char want[64];
    both(&f, SIM_A, SIM_H0 + h);
    snprintf(want, sizeof want, "tip %u | confirmed T n=%u at a5%s", SIM_H0 + h, h - 4,
             h == 10 ? " buried" : "");
    SEQ(go(&f), want);
  }
  fx_close(&f);
}

static void test_retry_backoff(test_state *T) {
  fx f;
  fx_open(&f);
  f.cfg.retry_ms = 500;
  f.cfg.retry_max_ms = 3000;
  fx_start(&f);
  SEQ(go(&f), "tip 1003");
  f.net.view[0].fault = f.net.view[1].fault = SIM_FAULT_DOWN;
  SEQ(go(&f), "sources unreachable");
  /* 500, 1000, 2000, 3000, 3000 ms between the tries that follow */
  static const uint32_t waits[] = {500, 1000, 2000, 3000, 3000};
  for (size_t i = 0; i < 5; i++) {
    unsigned before = sim_requests(&f.net);
    CHECK(gz_watch_wait_ms(f.e) == waits[i]);
    f.net.now += waits[i] - 1;
    (void)gz_watch_step(f.e);
    CHECK(sim_requests(&f.net) == before);
    f.net.now += 1;
    CHECK(gz_watch_wait_ms(f.e) == 0);
    (void)gz_watch_step(f.e);
    CHECK(sim_requests(&f.net) > before);
    CHECK(f.rec.n == 0); /* still unreachable: said once */
  }
  f.net.view[0].fault = f.net.view[1].fault = SIM_FAULT_NONE;
  f.net.now += 3000;
  (void)gz_watch_step(f.e);
  st_join(&f.rec, f.line, sizeof f.line);
  SEQ(f.line, "sources ok");
  /* and the next failure starts from the first wait again */
  f.net.view[0].fault = f.net.view[1].fault = SIM_FAULT_500;
  SEQ(go(&f), "sources unreachable");
  CHECK(gz_watch_wait_ms(f.e) == 500);
  fx_close(&f);
}

/* An idle engine asks for the tip once per tip_poll_ms and nothing else. */
static void test_idle(test_state *T) {
  fx f;
  fx_open(&f);
  fx_start(&f);
  CHECK(gz_watch_wait_ms(f.e) == 0);
  SEQ(go(&f), "tip 1003");
  CHECK(gz_watch_wait_ms(f.e) == 1000);
  unsigned before = sim_requests(&f.net);
  (void)gz_watch_step(f.e); /* nothing due */
  CHECK(sim_requests(&f.net) == before);
  f.net.now += 999;
  (void)gz_watch_step(f.e);
  CHECK(sim_requests(&f.net) == before);
  CHECK(gz_watch_wait_ms(f.e) == 1);
  /* a new watch is looked at at once */
  CHECK(gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0) == GZ_CHAINW_OK);
  CHECK(gz_watch_wait_ms(f.e) == 0);
  (void)gz_watch_step(f.e);
  CHECK(sim_requests(&f.net) > before);
  CHECK(gz_watch_wait_ms(f.e) == 1);
  /* a confirmation that stands is counted along the headers, not asked again */
  both(&f, SIM_A, SIM_H0 + 5);
  SEQ(go(&f), "tip 1005 | confirmed T n=1 at a5");
  char hex[65];
  sim_hex(TXID(&f, SIM_T), hex);
  sim_lock(&f.net);
  f.net.log_len = 0;
  if (f.net.log) f.net.log[0] = 0;
  sim_unlock(&f.net);
  both(&f, SIM_A, SIM_H0 + 6);
  SEQ(go(&f), "tip 1006 | confirmed T n=2 at a5");
  CHECK(!sim_log_has(&f.net, hex));
  fx_close(&f);
}

/* ---- nothing a server sends is fatal -------------------------------------- */

static bool true_event(const char *line, bool both_lie) {
  static const char *const ok[] = {"tip 1006", "tip 1003", "tip 1004", "tip 1005",
                                   "confirmed T n=2 at a5", "confirmed T n=1 at a5",
                                   "spent P:0 by S1 n=1 at a6"};
  if (strncmp(line, "sources ", 8) == 0) return true;
  /* two servers telling the same lie about what is unconfirmed are believed:
   * nothing can check that (docs/notes/chain-port.md section 6) */
  if (both_lie && strcmp(line, "mempool T") == 0) return true;
  for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++)
    if (strcmp(line, ok[i]) == 0) return true;
  return false;
}

static unsigned hostile_left_out;

static void hostile_case(test_state *T, int fault, const char *path, int servers, size_t cut,
                         uint64_t seed, const char *garbage) {
  fx f;
  char line[256], last_sources[256] = "";
  unsigned confirmed = 0, spent = 0, wrong = 0;
  fx_open(&f);
  fx_start(&f);
  (void)gz_watch_tx(f.e, TXID(&f, SIM_T), 3, 0);
  (void)gz_watch_outpoint(f.e, f.net.world.p, 0, 3, 0);
  both(&f, SIM_A, SIM_H0 + 6);
  for (int s = 0; s < 2; s++) {
    if (!(servers & (1 << s))) continue;
    sim_view *v = &f.net.view[s];
    v->fault = fault;
    v->fault_path = path;
    v->cut = cut;
    v->seed = seed;
    v->garbage = (const uint8_t *)garbage;
    v->garbage_len = garbage ? strlen(garbage) : 0;
  }
  for (int step = 0; step < 8; step++) {
    if (step == 4) f.net.view[0].fault = f.net.view[1].fault = SIM_FAULT_NONE;
    f.net.now += 1000;
    (void)gz_watch_step(f.e);
    for (size_t i = 0; i < f.rec.n; i++) {
      st_format(&f.net.world, &f.rec.ev[i], line, sizeof line);
      if (strncmp(line, "sources ", 8) == 0) snprintf(last_sources, sizeof last_sources, "%s", line);
      if (!true_event(line, servers == 3 && fault == SIM_FAULT_GARBAGE)) {
        wrong++;
        fprintf(stderr, "  fault %d on %s (servers %d, cut %zu, seed %llu): told \"%s\"\n", fault,
                path ? path : "everything", servers, cut, (unsigned long long)seed, line);
      }
      if (strcmp(line, "confirmed T n=2 at a5") == 0) confirmed++;
      if (strcmp(line, "spent P:0 by S1 n=1 at a6") == 0) spent++;
    }
    f.rec.n = 0;
  }
  T->checks++;
  /* nothing false was told, and once the servers behave the truth arrives,
   * exactly once */
  bool told = confirmed == 1 && spent == 1;
  /* The one answer that is remembered: a server whose block 0 was once seen
   * to be another chain stays left out (chain-port.md section 5), so after
   * a false block 0 nothing more is told, and the sources say why. */
  bool left_out = (fault == SIM_FAULT_GARBAGE || fault == SIM_FAULT_FLIP) &&
                  (path == NULL || strstr(path, "block-height") != NULL) && confirmed == 0 &&
                  spent == 0 &&
                  (strcmp(last_sources, "sources no-quorum") == 0 ||
                   strcmp(last_sources, "sources wrong-network") == 0);
  if (left_out) hostile_left_out++;
  if (wrong != 0 || !(told || left_out) || f.rec.dropped != 0) {
    T->failed++;
    fprintf(stderr, "  fault %d on %s (servers %d, cut %zu, seed %llu): wrong=%u confirmed=%u spent=%u\n",
            fault, path ? path : "everything", servers, cut, (unsigned long long)seed, wrong,
            confirmed, spent);
  }
  fx_close(&f);
}

static void test_hostile_servers(test_state *T) {
  static const char *const paths[] = {NULL, "/blocks/tip", "/block-height/", "/header", "/status",
                                      "/hex", "/merkle-proof", "/outspend", "/txid/0", "/block/"};
  static const char *const garbage[] = {
      "", "{", "null", "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[", "{\"confirmed\":true}",
      "{\"spent\":true}", "999999999999999999999999", "-1", "\xff\xfe", "{\"confirmed\":false}",
      "{\"spent\":false}", "0000000000000000000000000000000000000000000000000000000000000000"};
  static const size_t cuts[] = {0, 1, 2, 9, 19, 40, 63, 64, 65, 100, 159, 161};
  for (size_t p = 0; p < sizeof paths / sizeof paths[0]; p++) {
    for (int servers = 1; servers <= 3; servers++) {
      hostile_case(T, SIM_FAULT_DOWN, paths[p], servers, 0, 0, NULL);
      hostile_case(T, SIM_FAULT_TIMEOUT, paths[p], servers, 0, 0, NULL);
      hostile_case(T, SIM_FAULT_500, paths[p], servers, 0, 0, NULL);
      hostile_case(T, SIM_FAULT_HUGE, paths[p], servers, 0, 0, NULL);
      for (size_t g = 0; g < sizeof garbage / sizeof garbage[0]; g++)
        hostile_case(T, SIM_FAULT_GARBAGE, paths[p], servers, 0, 0, garbage[g]);
      for (size_t c = 0; c < sizeof cuts / sizeof cuts[0]; c++)
        hostile_case(T, SIM_FAULT_TRUNCATE, paths[p], servers, cuts[c], 0, NULL);
      for (uint64_t seed = 1; seed <= 40; seed++)
        hostile_case(T, SIM_FAULT_FLIP, paths[p], servers, 0, seed * 0x9e3779b97f4a7c15ULL, NULL);
    }
  }
  printf("     %u cases ended with a server left out for a false block 0\n", hostile_left_out);
  CHECK(hostile_left_out > 0 && hostile_left_out < 40);
}

/* ---- reading the input of a spender --------------------------------------- */

static void test_tx_input(test_state *T) {
  sim_world w;
  uint8_t id[32];
  uint32_t vout = 9;
  sim_world_init(&w);
  const sim_tx *s = &w.tx[SIM_S1];
  CHECK(gz_watch_tx_input(s->raw, s->len, 0, id, &vout) && vout == 0 && memcmp(id, w.p, 32) == 0);
  CHECK(!gz_watch_tx_input(s->raw, s->len, 1, id, &vout));
  CHECK(!gz_watch_tx_input(s->raw, 5, 0, id, &vout));
  CHECK(!gz_watch_tx_input(s->raw, 40, 0, id, &vout));
  CHECK(gz_watch_tx_input(s->raw, 41, 0, id, &vout));
  CHECK(!gz_watch_tx_input(NULL, 41, 0, id, &vout));
  /* two inputs, with a script on the first, and the witness form */
  uint8_t two[160];
  size_t p = 0;
  memset(two, 0, sizeof two);
  two[0] = 2;
  p = 4;
  two[p++] = 0;
  two[p++] = 1; /* marker and flag */
  two[p++] = 2;
  memset(two + p, 0x31, 32);
  two[p + 32] = 5;
  p += 36;
  size_t script_at = p;
  two[p++] = 3;
  p += 3;
  p += 4;
  memset(two + p, 0x32, 32);
  two[p + 32] = 0x01;
  two[p + 33] = 0x02;
  two[p + 34] = 0x03;
  two[p + 35] = 0x04;
  p += 36;
  two[p++] = 0;
  p += 4;
  CHECK(gz_watch_tx_input(two, p, 0, id, &vout) && vout == 5 && id[0] == 0x31);
  CHECK(gz_watch_tx_input(two, p, 1, id, &vout) && vout == 0x04030201u && id[31] == 0x32);
  CHECK(!gz_watch_tx_input(two, p, 2, id, &vout));
  CHECK(!gz_watch_tx_input(two, p - 6, 1, id, &vout));
  CHECK(gz_watch_tx_input(two, p - 5, 1, id, &vout));
  two[script_at] = 200; /* a script longer than what is left */
  CHECK(!gz_watch_tx_input(two, p, 1, id, &vout));
  two[script_at] = 0xfd; /* a three-byte length that runs off the end */
  CHECK(!gz_watch_tx_input(two, script_at + 2, 1, id, &vout));
  two[script_at] = 0xff; /* an eight-byte length far past the end */
  memset(two + script_at + 1, 0xff, 8);
  CHECK(!gz_watch_tx_input(two, p, 1, id, &vout));
}

/* A server that names a spender which does not spend the outpoint. */
static void test_false_spender(test_state *T) {
  fx f;
  char body[400], hex[65];
  fx_open(&f);
  fx_start(&f);
  /* both servers answer the question about P:0 by naming K, a real
   * transaction in their mempools that spends something else (T:0) */
  sim_hex(TXID(&f, SIM_K), hex);
  snprintf(body, sizeof body,
           "{\"spent\":true,\"txid\":\"%s\",\"vin\":0,\"status\":{\"confirmed\":false}}", hex);
  CHECK(gz_watch_outpoint(f.e, f.net.world.p, 0, 3, 0) == GZ_CHAINW_OK);
  pool(&f, SIM_T, true);
  pool(&f, SIM_K, true);
  for (int i = 0; i < 2; i++) {
    f.net.view[i].fault = SIM_FAULT_GARBAGE;
    f.net.view[i].fault_path = "/outspend";
    f.net.view[i].garbage = (const uint8_t *)body;
    f.net.view[i].garbage_len = strlen(body);
  }
  SEQ(go(&f), "tip 1003 | sources bad-proof");
  SEQ(go(&f), "");
  /* and a spender nobody has: nothing is told, and it is asked again */
  sim_hex(f.net.world.p, hex);
  snprintf(body, sizeof body,
           "{\"spent\":true,\"txid\":\"%s\",\"vin\":0,\"status\":{\"confirmed\":false}}", hex);
  for (int i = 0; i < 2; i++) f.net.view[i].garbage_len = strlen(body);
  SEQ(go(&f), "sources ok");
  SEQ(go(&f), "");
  /* the truth, once they tell it */
  f.net.view[0].fault = f.net.view[1].fault = SIM_FAULT_NONE;
  pool(&f, SIM_S1, true);
  SEQ(go(&f), "spent P:0 by S1 n=0");
  fx_close(&f);
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  if (getenv("GZ_SIM_GRIND") != NULL) {
    sim_world w;
    sim_world_init(&w); /* prints and exits */
  }
  RUN(test_config);
  RUN(test_tx_input);
  RUN(test_idle);
  RUN(test_confirm_reorg_confirm);
  RUN(test_reorg_moves_a_confirmation);
  RUN(test_depth_goes_down);
  RUN(test_double_spend);
  RUN(test_server_lags);
  RUN(test_server_far_behind_or_elsewhere);
  RUN(test_servers_disagree);
  RUN(test_server_lies_about_depth);
  RUN(test_mempool_eviction);
  RUN(test_broadcast_rejected_then_accepted);
  RUN(test_broadcast_unreachable_backoff);
  RUN(test_package);
  RUN(test_package_calls);
  RUN(test_not_before);
  RUN(test_watch_set);
  RUN(test_headers);
  RUN(test_retry_backoff);
  RUN(test_false_spender);
  RUN(test_hostile_servers);
  TEST_MAIN_END("chain_watch");
}
