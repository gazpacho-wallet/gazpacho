/* The funding engine's wallet port over wallet/tx (composite-node.md 14.1;
 * docs/notes/funding.md 7). Written on integration-slice1 (P4.6), for #56 to
 * fold in.
 *
 * The coins are the wallet's own BIP 86 outputs (account 0, receive and
 * change chains), read from the chain port by a thread of its own started
 * at the program's start (a slow server never holds the loop or a stop),
 * confirmed ones only (review A of PR 56, M5). A plan holds its coins until
 * it is released; the holds are in memory, kept across the in-process
 * restarts of one run. The master key is derived from the unlocked seed
 * (unlock.h) and wiped at close.
 *
 * The funds check's dry run (can_plan, funding.h) runs the wallet's own
 * selection over the coins plan would offer, with the same fee policy; a
 * new coin list keeps every plan's holds, by outpoint; coins in the mempool
 * are never offered, and change (the change chain: a funding's change, a
 * spend-back) only once it is `burial` deep (review of PR 80, N-1).
 *
 * STAND-INS (docs/notes/integration.md): coins are read once, at the start
 * (a coin received later is seen at the next start); `adopt` holds again only
 * a plan this run made (after a process restart, a journal's plan is
 * refused, so it is never signed); in the test build without a chain, one
 * invented coin paying the wallet's first address, so that the tests that
 * run without a chain still reach Funding through the real engine and the
 * real wallet code (nothing is ever broadcast: there is no chain). */
#ifndef GZP_WPORT_H
#define GZP_WPORT_H

#include <pthread.h>
#include <secp256k1.h>
#include <stddef.h>
#include <stdint.h>

#include "gazpacho/funding.h"
#include "gazpacho/wallet_keys.h"
#include "gazpacho/wallet_tx.h"
#include "pchain.h"
#include "unlock.h"

#define GZP_WPORT_COINS 256
#define GZP_WPORT_PLANS 8

typedef struct {
    const secp256k1_context *secp;
    gzw_xprv master;
    int have_master;
    gzw_network wnet;
    gzt_network net;
    gzt_coin coins[GZP_WPORT_COINS];
    uint8_t held[GZP_WPORT_COINS];      /* plan index + 1, or 0 */
    size_t n_coins;
    gzt_funding plans[GZP_WPORT_PLANS];
    uint8_t used[GZP_WPORT_PLANS];
    uint32_t next_change;
    int published;                /* a coin list has been published (scan or invent) */
    uint32_t burial;              /* the funding engine's B: change counts once this deep */
    gz_wallet_port_t port;
    /* the scan thread (gzp_wport_scan_start) */
    pthread_mutex_t mu;           /* coins, n_coins, held and next_change, between the scan and the port */
    pthread_t th;
    int th_on;
    volatile int stop;
    const char *url;
    uint32_t gap;
    void *http_live;              /* the scan's HTTP client while it runs, to interrupt it */
} gzp_wport_t;

/* The master key from the unlocked seed. `burial` is the funding engine's B, as the node
 * is given it (gz_node_config_t.funding_burial; 0: the engine's default): change
 * is offered once that deep. 0, or -1. */
int gzp_wport_open(gzp_wport_t *w, const secp256k1_context *secp, const gzp_unlock_t *unlock, gzw_network wnet,
                   uint32_t burial);
/* The confirmed coins of the first `gap` receive and change addresses, asked of the Esplora server
 * at `url` through a client of its own: the chain worker's, which runs in its own thread, is never
 * used from the loop's. Starts a thread for it and returns: 0, or -1. A plan made
 * before the scan has published finds no coin (outcome Failed, as with an empty wallet). */
int gzp_wport_scan_start(gzp_wport_t *w, const char *url, uint32_t gap);
/* Publishes a coin list (the scan's, or a test's), under the mutex: each
 * coin with the height of its block (0: in the mempool) and the tip it was
 * read at. The coin list `plan` and `can_plan` offer. 0, or -1. */
int gzp_wport_publish(gzp_wport_t *w, const gzt_coin *coins, const uint32_t *heights, size_t n, uint32_t tip);
/* Test build, no chain: one invented coin paying the first receive address. */
int gzp_wport_invent(gzp_wport_t *w);
void gzp_wport_close(gzp_wport_t *w);

#endif
