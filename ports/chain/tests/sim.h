/*
 * A small made-up chain and two chain servers that tell it, for the tests of
 * the watch engine and the chain worker.
 *
 * The world is fixed: 12 heights, with two branches from the fifth on, a
 * handful of transactions, and block headers that meet signet's proof-of-work
 * limit (nonces in sim_nonces.h; `GZ_SIM_GRIND=1 chain_test_watch` grinds
 * them again and prints the file). What changes in a test is each server's
 * VIEW of it: which branch, how high, what is in its mempool, and how it
 * misbehaves. A view answers Esplora requests exactly as a server would, so
 * the tests run the real Esplora backend and the real comparing backend:
 *
 *   - in process, through sim_transport (a gz_http with a clock the test
 *     moves, or the real clock for the threaded tests);
 *   - over real HTTP, through tests/watch_stub.py, which serves the route
 *     tables sim_dump writes.
 *
 *   height      1000 1001 1002 1003 | 1004 1005 1006 1007 1008 .. 1011
 *   branch A     c0   c1   c2   c3  |  a4   a5*  a6'  a7"  a8  ..  a11
 *   branch B     c0   c1   c2   c3  |  b4   b5   b6*  b7^  b8  ..  b11
 *
 *   *  holds T, the watched transaction (a funding-like one)
 *   '  holds S1, which spends the watched outpoint P:0
 *   ^  holds S2, which also spends P:0 (the double spend)
 *   "  holds K, a child of T (spends T:0); branch C holds K at 1007 too
 *   S2 spends P:0 with its second input (vin 1); T spends Q:0
 */
#ifndef GZ_CHAIN_SIM_H
#define GZ_CHAIN_SIM_H

#include <pthread.h>
#include <stdio.h>

#include "gazpacho/chain.h"
#include "gazpacho/chain_http.h"

#define SIM_H0 1000u
#define SIM_COMMON 4u
#define SIM_LEN 12u
#define SIM_TOP (SIM_H0 + SIM_LEN - 1)
#define SIM_C_LEN 2u
#define SIM_C_TOP (SIM_H0 + 8)
#define SIM_BLOCKS (SIM_COMMON + 2 * (SIM_LEN - SIM_COMMON) + SIM_C_LEN)

/* Branch C is branch A up to a6, then two empty blocks of its own at 1007
 * and 1008, where it ends: a reorganisation that leaves a5 and a6 in place
 * and makes the chain shorter. */
enum { SIM_A = 0, SIM_B = 1, SIM_C = 2 };
enum { SIM_T = 0, SIM_S1 = 1, SIM_S2 = 2, SIM_K = 3, SIM_NTX = 4 };

typedef struct sim_tx {
  uint8_t id[GZ_HASH_LEN];
  uint8_t raw[160];
  size_t len;
} sim_tx;

typedef struct sim_block {
  uint8_t header[GZ_HEADER_LEN];
  uint8_t id[GZ_HASH_LEN];
  uint32_t height;
  sim_tx coinbase;
  int tx; /* the one other transaction it holds (SIM_T ...), or -1 */
} sim_block;

typedef struct sim_world {
  sim_block common[SIM_COMMON];
  sim_block branch[2][SIM_LEN - SIM_COMMON];
  sim_block c[SIM_C_LEN];
  sim_block weak; /* a6 with another nonce: its hash does not meet the target */
  sim_tx tx[SIM_NTX];
  uint8_t p[GZ_HASH_LEN]; /* the txid of the watched outpoint P:0 */
  uint8_t q[GZ_HASH_LEN]; /* T spends Q:0 */
} sim_world;

/* Builds the world. Aborts the test program if a nonce in sim_nonces.h does
 * not fit (unless GZ_SIM_GRIND is set: then it grinds and prints the file). */
void sim_world_init(sim_world *w);
const sim_block *sim_block_of(const sim_world *w, int branch, uint32_t height);

/* How a server misbehaves. */
enum {
  SIM_FAULT_NONE = 0,
  SIM_FAULT_DOWN,     /* cannot be connected to */
  SIM_FAULT_TIMEOUT,  /* never answers within the time limit */
  SIM_FAULT_500,      /* answers 500 */
  SIM_FAULT_GARBAGE,  /* answers 200 with `garbage` as the body */
  SIM_FAULT_TRUNCATE, /* answers the right body cut to `cut` bytes */
  SIM_FAULT_HUGE,     /* answers more than the caller's room */
  SIM_FAULT_FLIP      /* answers the right body with one byte changed (by `seed`) */
};
enum { SIM_POST_ACCEPT = 0, SIM_POST_KNOWN, SIM_POST_REJECT, SIM_POST_DOWN };
enum {
  SIM_PKG_NONE = 0, /* no package endpoint: 404 */
  SIM_PKG_OK,       /* at /txs/package: accepts */
  SIM_PKG_OK_V1,    /* only at /v1/txs/package: accepts */
  SIM_PKG_FAIL,     /* at /txs/package: refuses the parent (and so the child) */
  SIM_PKG_DOWN,
  SIM_PKG_BUSY_FIRST, /* /txs/package answers 429; /v1/txs/package accepts */
  SIM_PKG_KNOWN       /* at /txs/package: accepts, both already in its mempool */
};

typedef struct sim_view {
  const sim_world *w;
  int branch;
  uint32_t tip;
  bool mempool[SIM_NTX];
  int fault;
  const char *fault_path; /* NULL: every request; else those whose path contains it */
  const uint8_t *garbage;
  size_t garbage_len;
  size_t cut;
  uint64_t seed;
  bool mainnet;       /* says its block 0 is mainnet's */
  uint32_t claim_tip; /* not 0: what /blocks/tip/height says, whatever it holds */
  bool hide[SIM_NTX]; /* says it never saw the transaction */
  bool weak;          /* at 1006 it serves the block without proof of work */
  uint32_t graft;     /* not 0: from this height up it serves the other branch */
  uint32_t graft_below; /* not 0: below this height (from 1004) it serves the other branch */
  bool pin_t;           /* says T is in a5 whatever it holds */
  const char *reject_reason; /* not NULL: the words of a refusal of POST /tx */
  /* after the flip_after-th request whose path contains flip_path, it moves
   * to branch flip_to (that answer is still from the old branch) */
  const char *flip_path;
  unsigned flip_after, flip_seen;
  int flip_to;
  int lie_height;     /* added to the height it states for a confirmed transaction */
  int post;
  int package;
  unsigned posts, packages;
  /* serves this transaction's bytes with another witness added (one item,
   * not checked: nothing here validates scripts, and nothing reads a
   * witness): the same txid, another wtxid, as a host can make for its own
   * funding and give each server its own (C-2) */
  bool alt_witness[SIM_NTX];
} sim_view;

void sim_view_init(sim_view *v, const sim_world *w, int branch, uint32_t tip);

/* One request to a view. Returns false for a transport failure of the given
 * kind (*failure is a gz_http_result); else true with the status and body.
 * `out` has `cap` bytes; a longer body is cut and *len says the full size. */
bool sim_respond(sim_view *v, bool post, const char *path, const uint8_t *body, size_t body_len,
                 char *out, size_t cap, long *status, size_t *len, int *failure);

/* Writes every route of a view, for watch_stub.py:
 *   G <path> <status> <hex body>       P <path> <rule>
 * Paths not listed fall to the stub's own defaults, which are sim_respond's. */
void sim_dump(sim_view *v, FILE *f);

/* ---- two servers behind a gz_http ---------------------------------------- */

#define SIM_BASE_A "https://a.test/api"
#define SIM_BASE_B "https://b.test/api"

typedef struct sim_net {
  sim_world world;
  sim_view view[2];
  pthread_mutex_t mu; /* guards the views, the log and the flags below */
  pthread_cond_t cv;
  /* the clock: a number the test moves, or the real one */
  bool real_time;
  uint64_t now;
  /* every request URL, one per line */
  char *log;
  size_t log_len, log_cap;
  unsigned requests;
  /* real_time only: requests wait here until the test lets go */
  bool stall;
  int stall_view;          /* -1: both servers; else only this one */
  const char *stall_path;  /* NULL: every request; else those whose path contains it */
  unsigned stalled;        /* requests waiting in a stall now */
  unsigned stall_aborts;   /* stalled requests ended by sim_interrupt */
  /* real_time only: requests to delay_view (-1: both) whose path contains
   * delay_path are answered after delay_ms */
  uint32_t delay_ms;
  int delay_view;
  const char *delay_path;
  bool interrupted;
} sim_net;

void sim_net_init(sim_net *n, bool real_time);
void sim_net_free(sim_net *n);
gz_http sim_transport(sim_net *n);
uint64_t sim_clock(void *net);
/* gz_chainw_config.interrupt for the simulated transport. */
void sim_interrupt(void *net, bool on);
void sim_lock(sim_net *n);
void sim_unlock(sim_net *n);
/* True if any request so far had `needle` in its URL. */
bool sim_log_has(sim_net *n, const char *needle);
unsigned sim_requests(sim_net *n);

/* The backends over the simulated servers: one Esplora backend each and the
 * comparing backend over the two. */
typedef struct sim_stack {
  gz_http http;
  gz_chain server[2];
  gz_chain multi;
} sim_stack;
bool sim_stack_open(sim_stack *s, sim_net *n);
/* The time limit sim_stack_open gives each request; 2000 unless a test changes it. */
extern uint32_t sim_request_timeout_ms;
void sim_stack_close(sim_stack *s);

void sim_hex(const uint8_t hash[GZ_HASH_LEN], char out[2 * GZ_HASH_LEN + 1]);

#endif /* GZ_CHAIN_SIM_H */
