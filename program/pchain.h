/* SPDX-License-Identifier: MIT */
/* The chain adapter: BROADCAST and WATCH actions out, chain events in, over
 * the merged chain view (ports/chain).
 *
 * What this skeleton does: at start, check that the chain server's block 0 is
 * the configured network's (a mainnet server is refused like any other wrong
 * network), read its tip, and from then on ask for the tip every
 * chain_poll_ms and give the node GZ_CHAIN_NEW_TIP when it changes. WATCH
 * actions are recorded (and re-registered by the node at every start), but
 * turning them into SCRIPT_SPENT / TX_CONFIRMED / OUTPOINT_SPENT events is
 * the chain watch loop (stream S8), not built here. BROADCAST goes to the
 * server; the core has no event for its outcome yet, so the result is only
 * written to the output.
 *
 * Every chain call blocks the one loop for up to the backend's timeouts
 * (chain.h, "Blocking"). See docs/notes/program.md, "Mismatches". */
#ifndef GZP_PCHAIN_H
#define GZP_PCHAIN_H

#include <stddef.h>
#include <stdint.h>

#include "gazpacho/chain.h"
#ifdef GZP_HAVE_CURL
#include "gazpacho/chain_http.h"
#endif

#define GZP_MAX_WATCHES 256

typedef struct {
    int active;
    gz_chain chain;
    gz_network network;
    uint32_t poll_ms;
    uint64_t next_poll_ms;
    int have_tip;
    gz_chain_tip tip;
    uint8_t *watch_scripts[GZP_MAX_WATCHES];
    size_t watch_lens[GZP_MAX_WATCHES];
    size_t n_watches;
#ifdef GZP_HAVE_CURL
    int have_http;
    gz_http http;
#endif
} gzp_chain_t;

/* No chain (--no-chain): every action is written to the output and dropped. */
void gzp_chain_none(gzp_chain_t *c, gz_network network);

/* Connect to one Esplora server, check its block 0 against `network` and read
 * its tip. Returns 0, or a GZP_EXIT_* status after printing why. */
int gzp_chain_open(gzp_chain_t *c, const char *url, gz_network network, uint32_t poll_ms);

/* The tip, if a poll is due: 1 and *height when it changed, else 0. */
int gzp_chain_poll(gzp_chain_t *c, uint64_t now_ms, uint32_t *height);
int gzp_chain_timeout(const gzp_chain_t *c, uint64_t now_ms);

void gzp_chain_watch_script(gzp_chain_t *c, const uint8_t *script, size_t len);
void gzp_chain_broadcast(gzp_chain_t *c, const uint8_t *tx, size_t len);

/* Read-only: the unspent outputs paying `script`, written to the output. */
int gzp_chain_show_outputs(gzp_chain_t *c, const uint8_t *script, size_t len);

/* Forget the watches (they are set again by the node at its next start). */
void gzp_chain_forget_watches(gzp_chain_t *c);
void gzp_chain_close(gzp_chain_t *c);

#endif
