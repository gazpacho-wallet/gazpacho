/*
 * Fuzz target for the watch engine. The input is a script: it moves the two
 * simulated chain servers of sim.h (blocks, branches, mempools), makes one
 * or both of them misbehave in every way sim.h knows, including answering
 * any request with bytes taken from the input itself, and drives the engine
 * (watches set, dropped and released, broadcasts, packages, passes).
 *
 * Whatever the servers do, the engine must not crash, and must never tell a
 * confirmation that is not true of the made-up chain: every block it names
 * is a block of that chain at that height, every transaction it calls
 * confirmed is in that block, every spender spends the outpoint it is said
 * to spend. (A proof-of-work header cannot be made up by a fuzzer, which is
 * the point: nothing else is believed about depth.)
 *
 * Plain driver: CTest test chain_fuzz_watch. libFuzzer: GZ_LIBFUZZER.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../watch.h"
#include "simtest.h"

typedef struct fz {
  sim_net net;
  sim_stack stack;
  gz_watch *e;
} fz;

static void must(int ok) {
  if (!ok) abort();
}

static const sim_block *world_block(const sim_world *w, uint32_t height, const uint8_t *id) {
  for (int br = 0; br < 3; br++) {
    const sim_block *b = sim_block_of(w, br, height);
    if (b != NULL && memcmp(b->id, id, GZ_HASH_LEN) == 0) return b;
  }
  return NULL;
}

static void check_event(void *ctx, const gz_chainw_event *ev) {
  fz *f = ctx;
  const sim_world *w = &f->net.world;
  const sim_block *b;
  uint8_t prev[GZ_HASH_LEN];
  uint32_t vout = 0;
  switch (ev->kind) {
    case GZ_CHAINW_TIP: must(world_block(w, ev->height, ev->block_hash) != NULL); break;
    case GZ_CHAINW_TX_CONFIRMED:
      b = world_block(w, ev->height, ev->block_hash);
      must(b != NULL && b->tx >= 0 && memcmp(w->tx[b->tx].id, ev->txid, GZ_HASH_LEN) == 0);
      must(ev->confirmations >= 1 && ev->confirmations <= SIM_LEN);
      break;
    case GZ_CHAINW_OUTPOINT_SPENT: {
      int which = -1;
      for (int i = 0; i < SIM_NTX; i++)
        if (memcmp(w->tx[i].id, ev->txid, GZ_HASH_LEN) == 0) which = i;
      must(which >= 0);
      must(gz_watch_tx_input(w->tx[which].raw, w->tx[which].len, ev->vin, prev, &vout));
      must(memcmp(prev, ev->outpoint_txid, GZ_HASH_LEN) == 0 && vout == ev->outpoint_vout);
      if (ev->confirmations > 0) {
        b = world_block(w, ev->height, ev->block_hash);
        must(b != NULL && b->tx == which && ev->confirmations <= SIM_LEN);
      }
      break;
    }
    case GZ_CHAINW_REORG: must(ev->disconnected >= 1); break;
    case GZ_CHAINW_BROADCAST:
      must(ev->broadcast.attempts >= 1 && ev->broadcast.outcome >= GZ_CHAINW_ACCEPTED &&
           ev->broadcast.outcome <= GZ_CHAINW_NO_PACKAGE_RELAY);
      must(memchr(ev->broadcast.reason, 0, sizeof ev->broadcast.reason) != NULL);
      break;
    case GZ_CHAINW_SOURCES:
    case GZ_CHAINW_TX_MEMPOOL:
    case GZ_CHAINW_TX_EVICTED:
    case GZ_CHAINW_TX_UNCONFIRMED:
    case GZ_CHAINW_OUTPOINT_UNSPENT:
    case GZ_CHAINW_SYNCED:
    case GZ_CHAINW_TIP_SYNCED: break;
    case GZ_CHAINW_WATCH_FAILED: must(ev->sources == GZ_CHAIN_TOO_LARGE); break;
    case GZ_CHAINW_WATCH_PENDING: must(ev->sources == GZ_CHAIN_OK || ev->sources == GZ_CHAIN_TOO_LARGE); break;
    default: must(0);
  }
}

static uint8_t *dup_tx(const sim_tx *t) {
  uint8_t *p = malloc(t->len);
  if (p != NULL) memcpy(p, t->raw, t->len);
  return p;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const char *const paths[] = {NULL, "/blocks/tip", "/block-height/", "/header", "/status",
                                      "/hex", "/merkle-proof", "/outspend", "/txid/0", "/block/",
                                      "/tx", "package"};
  fz f;
  gz_watch_config cfg;
  size_t at = 0;
  unsigned steps = 0;
  memset(&f, 0, sizeof f);
  sim_net_init(&f.net, false);
  must(sim_stack_open(&f.stack, &f.net));
  memset(&cfg, 0, sizeof cfg);
  cfg.report_synced = true;   /* the SYNCED reports too (step P4.5) */
  cfg.chain = &f.stack.multi;
  cfg.network = GZ_NET_SIGNET;
  cfg.tip_poll_ms = 1000;
  cfg.retry_ms = 500;
  cfg.retry_max_ms = 1000;
  cfg.burial_depth = 3;
  cfg.max_watches = 6;
  cfg.broadcast_attempts = 2;
  cfg.broadcast_backoff_ms = 100;
  cfg.broadcast_backoff_max_ms = 200;
  cfg.header_window = 6;
  cfg.max_catchup = 4;
  cfg.max_link = 32;
  cfg.now_ms = sim_clock;
  cfg.clock_ctx = &f.net;
  cfg.emit = check_event;
  cfg.emit_ctx = &f;
  f.e = gz_watch_new(&cfg);
  must(f.e != NULL);

#define NEXT() (at < size ? data[at++] : 0)
  while (at < size && steps < 64) {
    uint8_t op = NEXT(), a = NEXT();
    sim_view *v = &f.net.view[a & 1];
    const sim_tx *t = &f.net.world.tx[(a >> 1) % SIM_NTX];
    const uint8_t *id = (a >> 3) & 1 ? f.net.world.p : t->id;
    switch (op % 16) {
      case 0:
      case 1:
        f.net.now += 1000;
        (void)gz_watch_step(f.e);
        (void)gz_watch_wait_ms(f.e);
        steps++;
        break;
      case 2: f.net.view[0].tip = f.net.view[1].tip = SIM_H0 + 3 + (a >> 4) % 9; break;
      case 3: v->tip = SIM_H0 + 3 + (a >> 4) % 9; break;
      case 4: f.net.view[0].branch = f.net.view[1].branch = (a >> 4) % 3; break;
      case 5: v->branch = (a >> 4) % 3; break;
      case 6: v->mempool[(a >> 1) % SIM_NTX] = (a >> 7) & 1; break;
      case 7: {
        uint8_t n = NEXT();
        v->fault = (a >> 1) % 8;
        v->fault_path = paths[(a >> 4) % (sizeof paths / sizeof paths[0])];
        v->cut = n;
        v->seed = ((uint64_t)n << 16) | a;
        /* the answer is the next n bytes of the input */
        if (n > size - at) n = (uint8_t)(size - at);
        v->garbage = data + at;
        v->garbage_len = n;
        at += n;
        break;
      }
      case 8: f.net.view[0].fault = f.net.view[1].fault = SIM_FAULT_NONE; break;
      case 9: (void)gz_watch_tx(f.e, id, (a >> 4) % 6, (a >> 7) & 1); break;
      case 10: (void)gz_watch_outpoint(f.e, id, (a >> 4) & 1, (a >> 5) % 4, (a >> 7) & 1); break;
      case 11:
        if (a & 1) {
          gz_watch_drop_tx(f.e, id);
        } else {
          gz_watch_drop_outpoint(f.e, id, (a >> 4) & 1);
        }
        break;
      case 12: gz_watch_release(f.e, id, (uint32_t)(a >> 4) * 300u); break;
      case 13: {
        const sim_tx *u = &f.net.world.tx[(a >> 4) % SIM_NTX];
        (void)gz_watch_broadcast(f.e, a, a & 1 ? dup_tx(u) : NULL, a & 1 ? u->len : 0, dup_tx(t),
                                 t->len);
        break;
      }
      case 14:
        v->post = (a >> 1) % 4;
        v->package = (a >> 3) % 5;
        v->hide[(a >> 6) % SIM_NTX] = (a >> 5) & 1;
        break;
      default:
        switch ((a >> 1) % 5) {
          case 0: v->lie_height = (int)((a >> 4) % 7) - 3; break;
          case 1: v->graft = (a >> 4) % 2 ? SIM_H0 + 4 + (a >> 5) % 6 : 0; break;
          case 2: v->claim_tip = (a >> 4) % 2 ? SIM_H0 + (a >> 5) * 4u : 0; break;
          case 3: v->mainnet = (a >> 4) & 1; break;
          default: gz_watch_clear(f.e); break;
        }
        break;
    }
  }
  gz_watch_free(f.e);
  sim_stack_close(&f.stack);
  sim_net_free(&f.net);
  return 0;
}
