/* SPDX-License-Identifier: MIT */
/* Test traffic (--test-pings): the test engine only answers pings, so
 * something outside it must send them. This module sends N pings to each
 * connected peer and to each of the peer's test engines (--test-engines,
 * areas 0x7e57 and 0x7e58), one round every ping_ms, payload "<name>/<k>", as
 * kind 32767 straight through the network adapter (test_engine.h), and
 * watches the replies that come back (which are also given to the node,
 * whose test engine acknowledges them). A ping not yet answered is sent again
 * whenever its peer connects again, so a ping lost with a crashed process is
 * not lost for the test. Output lines:
 *     pong peer=ID k=K area=A dup=0|1
 *     pings-done peer=ID n=N           once every ping to that peer is answered
 * Not part of the program proper; test builds only. */
#ifndef GZP_TESTPING_H
#define GZP_TESTPING_H

#include <stddef.h>
#include <stdint.h>

#include "net.h"

#define GZP_TESTPING_MAX 20000
#define GZP_TESTPING_AREAS 2

typedef struct {
    int used;
    uint8_t key[33];
    int sent;                       /* pings 0..sent-1 have been sent at least once */
    uint8_t answered[GZP_TESTPING_AREAS][GZP_TESTPING_MAX];
    int n_answered;
    int done;
} gzp_tp_peer_t;

typedef struct {
    int n, every_ms, areas;
    int burst_n, burst_bytes;      /* --test-burst: sent at each connection */
    int exit_after_send;           /* --test-exit-after-send: _exit once ping 0 has left */
    uint64_t exit_at;              /* when to exit, once ping 0 has been sent */
    const char *name;
    uint64_t next_ms;
    gzp_tp_peer_t peers[GZP_MAX_CONNS];
} gzp_testping_t;

void gzp_testping_init(gzp_testping_t *t, int n, int every_ms, const char *name, int areas);
/* At each connection, send n messages of `bytes` bytes ("GZPX" and filler,
 * which the test engine ignores): a burst for the start-queue cap test. */
void gzp_testping_burst(gzp_testping_t *t, int n, int bytes);
/* A peer connected: send again every ping it has not answered. */
void gzp_testping_connected(gzp_testping_t *t, gzp_net_t *net, const uint8_t key[33]);
/* A message from a peer: notes a reply to one of our pings. */
void gzp_testping_message(gzp_testping_t *t, const uint8_t key[33], uint16_t kind, const uint8_t *records,
                          size_t len);
/* Send the next ping to every connected peer when due. */
void gzp_testping_tick(gzp_testping_t *t, gzp_net_t *net, uint64_t now_ms);
int gzp_testping_timeout(const gzp_testping_t *t, uint64_t now_ms);

#endif
