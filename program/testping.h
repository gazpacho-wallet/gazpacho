/* SPDX-License-Identifier: MIT */
/* Test traffic (--test-pings): the placeholder node only answers pings, so
 * something outside it must send them. This module sends N pings to each
 * connected peer, one every ping_ms, payload "<name>/<k>", straight through
 * the network adapter, and watches the pongs that come back (which are also
 * given to the node, which ignores them). A ping not yet answered is sent
 * again whenever its peer connects again, so a ping lost with a crashed
 * process is not lost for the test. Output lines:
 *     pong peer=ID k=K dup=0|1
 *     pings-done peer=ID n=N           once every ping to that peer is answered
 * Not part of the program proper; it goes when the first engine arrives. */
#ifndef GZP_TESTPING_H
#define GZP_TESTPING_H

#include <stddef.h>
#include <stdint.h>

#include "net.h"

#define GZP_TESTPING_MAX 20000

typedef struct {
    int used;
    uint64_t peer_id;
    int sent;                       /* pings 0..sent-1 have been sent at least once */
    uint8_t answered[GZP_TESTPING_MAX];
    int n_answered;
    int done;
} gzp_tp_peer_t;

typedef struct {
    int n, every_ms;
    int burst_n, burst_bytes;      /* --test-burst: sent at each connection */
    const char *name;
    uint64_t next_ms;
    gzp_tp_peer_t peers[GZP_MAX_CONNS];
} gzp_testping_t;

void gzp_testping_init(gzp_testping_t *t, int n, int every_ms, const char *name);
/* At each connection, send n messages of ytes bytes (\"GZPX\" and filler, which
 * the node ignores): a burst for the start-queue cap test. */
void gzp_testping_burst(gzp_testping_t *t, int n, int bytes);
/* A peer connected: send again every ping it has not answered. */
void gzp_testping_connected(gzp_testping_t *t, gzp_net_t *net, uint64_t peer_id);
/* A message from a peer: notes a pong to one of our pings. */
void gzp_testping_message(gzp_testping_t *t, uint64_t peer_id, const uint8_t *b, size_t len);
/* Send the next ping to every connected peer when due. */
void gzp_testping_tick(gzp_testping_t *t, gzp_net_t *net, uint64_t now_ms);
int gzp_testping_timeout(const gzp_testping_t *t, uint64_t now_ms);

#endif
