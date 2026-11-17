/* SPDX-License-Identifier: MIT */
/* The chain adapter: BROADCAST and WATCH actions out, chain events in, over
 * the chain worker (ports/chain, chain_watch.h; docs/notes/chain-port.md
 * sections 16 to 23).
 *
 * At open, before the loop runs: check that each chain server's block 0 is
 * the configured network's (a mainnet server, or any other network's, is
 * refused) and read the tip, both blocking and bounded by the backends' time
 * limits. Then one worker thread owns every chain call. The loop gives
 * gzp_chain_fd to poll(), and takes the worker's events with gzp_chain_take,
 * which turns them into the core's GZ_CHAIN_* events. Nothing the loop calls
 * here waits on the network.
 *
 * A refusal by the worker is never ignored (chain_watch.h, M4 of the review
 * of PR 43): BUSY on a watch, and BUSY or FULL on a broadcast, is kept in a
 * backlog and asked again at every turn, in order; a full backlog, a watch
 * set that is full, or a watch the worker calls invalid is fatal for the
 * incarnation (contract v2). A broadcast of bytes that are not a transaction
 * is answered with a BROADCAST_RESULT REFUSED.
 *
 * A restart from storage calls gzp_chain_restart: the worker forgets every
 * watch, request and event of the old incarnation, and the new node sets its
 * watches again at its start (node.h rule 4). */
#ifndef GZP_PCHAIN_H
#define GZP_PCHAIN_H

#include <stddef.h>
#include <stdint.h>

#include "gazpacho/chain.h"
#include "gazpacho/chain_watch.h"
#include "gazpacho/event.h"
#ifdef GZP_HAVE_CURL
#include "gazpacho/chain_http.h"
#endif

#define GZP_MAX_WATCHES 256
#define GZP_CHAIN_SERVERS 4
/* Requests the worker refused as BUSY (or FULL, for a broadcast), kept and
 * asked again. One more is fatal for the incarnation. */
#define GZP_CHAIN_BACKLOG 1024
/* How soon the loop asks again while the backlog holds something. */
#define GZP_CHAIN_RETRY_MS 50

typedef struct gzp_chain_req gzp_chain_req_t;

typedef struct {
    int active;
    gz_network network;
    gz_chain servers[GZP_CHAIN_SERVERS];
    size_t n_servers;
    gz_chain multi;     /* the comparing backend, with two servers or more */
    gz_chain *view;     /* what the worker asks: multi, or the one server */
    gz_chainw *w;
    int have_tip;       /* the last tip told to the node */
    gz_chain_tip tip;
    uint64_t next_id;   /* broadcast ids */
    gzp_chain_req_t *backlog;
    size_t n_backlog;
    uint64_t refusals;  /* BUSY or FULL answers kept in the backlog, ever */
    /* BROADCAST_RESULT events made here (bytes that are not a transaction),
     * waiting for gzp_chain_take */
    uint8_t refused_txids[16][32];
    size_t n_refused;
    char reason[128];   /* the reason bytes of the event last taken */
#ifdef GZP_HAVE_CURL
    int have_http;
    gz_http http;
#endif
} gzp_chain_t;

/* No chain (--no-chain): every action is written to the output and dropped. */
void gzp_chain_none(gzp_chain_t *c, gz_network network);

/* Connect to the Esplora servers at urls[0..n) (one, or two or more of
 * different operators, compared), check each one's block 0 against
 * `network`, read the tip, and start the worker. `small`: a test build's
 * small queues (16 watches, 32 requests). Returns 0, or a GZP_EXIT_* status
 * after printing why. */
int gzp_chain_open(gzp_chain_t *c, const char *const *urls, size_t n, gz_network network,
                   uint32_t poll_ms, int small);

/* The descriptor that is readable while the worker has events; -1 without
 * a chain. */
int gzp_chain_fd(const gzp_chain_t *c);
/* -1 (no deadline), or how soon the loop should call gzp_chain_retry. */
int gzp_chain_timeout(const gzp_chain_t *c, uint64_t now_ms);

/* Actions. 0, or -1: fatal for the incarnation (why in the output). */
int gzp_chain_watch_tx(gzp_chain_t *c, const uint8_t txid[32], uint32_t depth);
int gzp_chain_watch_outpoint(gzp_chain_t *c, const uint8_t txid[32], uint32_t vout, uint32_t depth);
int gzp_chain_broadcast(gzp_chain_t *c, const uint8_t *tx, size_t len);
/* Asks the worker again for what it refused. 0, or -1: fatal. */
int gzp_chain_retry(gzp_chain_t *c);

/* One event for the node: 1 and *ev (its reason bytes valid until the next
 * call), 0 when none waits. Events the core has no kind for are written to
 * the output and skipped. */
int gzp_chain_take(gzp_chain_t *c, gz_event_t *ev);

/* Read-only, before the loop: the unspent outputs paying `script`, written
 * to the output (--check-chain). */
int gzp_chain_show_outputs(gzp_chain_t *c, const uint8_t *script, size_t len);

/* A restart from storage: the worker forgets the old incarnation (its
 * watches, requests and events), and so does the backlog. */
void gzp_chain_restart(gzp_chain_t *c);
/* Stops and joins the worker, then frees the backends and the transport. */
void gzp_chain_close(gzp_chain_t *c);

#endif
