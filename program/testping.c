/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/node.h"
#include "gzp.h"
#include "testping.h"

#ifdef GZP_TEST_BUILD /* test traffic exists only in gazpacho-test */

void gzp_testping_init(gzp_testping_t *t, int n, int every_ms, const char *name)
{
    memset(t, 0, sizeof *t);
    t->n = n > GZP_TESTPING_MAX ? GZP_TESTPING_MAX : n;
    t->every_ms = every_ms;
    t->name = name;
}

static gzp_tp_peer_t *peer(gzp_testping_t *t, uint64_t id, int make)
{
    int i;
    for (i = 0; i < GZP_MAX_CONNS; i++)
        if (t->peers[i].used && t->peers[i].peer_id == id) return &t->peers[i];
    if (!make) return NULL;
    for (i = 0; i < GZP_MAX_CONNS; i++)
        if (!t->peers[i].used) {
            memset(&t->peers[i], 0, sizeof t->peers[i]);
            t->peers[i].used = 1;
            t->peers[i].peer_id = id;
            return &t->peers[i];
        }
    return NULL;
}

static void send_ping(gzp_testping_t *t, gzp_net_t *net, uint64_t id, int k)
{
    uint8_t msg[GZ_PING_PREFIX_LEN + GZ_PING_MAX_PAYLOAD];
    int pl = snprintf((char *)msg + 4, GZ_PING_MAX_PAYLOAD, "%s/%d", t->name, k);
    memcpy(msg, "GZPI", 4);
    if (pl <= 0 || pl >= GZ_PING_MAX_PAYLOAD) return;
    gzp_net_send(net, id, msg, 4 + (size_t)pl);
}

void gzp_testping_connected(gzp_testping_t *t, gzp_net_t *net, uint64_t id)
{
    gzp_tp_peer_t *p;
    int k;
    if (t->n <= 0 || !(p = peer(t, id, 1))) return;
    for (k = 0; k < p->sent; k++)
        if (!p->answered[k]) send_ping(t, net, id, k);
}

void gzp_testping_message(gzp_testping_t *t, uint64_t id, const uint8_t *b, size_t len)
{
    gzp_tp_peer_t *p;
    size_t nl;
    char buf[GZ_PING_MAX_PAYLOAD + 1];
    char *end;
    long k;
    if (t->n <= 0 || len < 4 || memcmp(b, "GZPO", 4) || !(p = peer(t, id, 0))) return;
    nl = strlen(t->name);
    if (len - 4 > GZ_PING_MAX_PAYLOAD) return;
    memcpy(buf, b + 4, len - 4);
    buf[len - 4] = 0;
    if (strncmp(buf, t->name, nl) || buf[nl] != '/') return;
    k = strtol(buf + nl + 1, &end, 10);
    if (*end || k < 0 || k >= t->n || k >= p->sent) return;
    gzp_log("pong peer=%016llx k=%ld dup=%d", (unsigned long long)id, k, p->answered[k] ? 1 : 0);
    if (!p->answered[k]) {
        p->answered[k] = 1;
        p->n_answered++;
    }
    if (!p->done && p->n_answered == t->n) {
        p->done = 1;
        gzp_log("pings-done peer=%016llx n=%d", (unsigned long long)id, t->n);
    }
}

void gzp_testping_tick(gzp_testping_t *t, gzp_net_t *net, uint64_t now)
{
    int i;
    if (t->n <= 0 || now < t->next_ms) return;
    t->next_ms = now + (uint64_t)t->every_ms;
    if (net->queueing) return;
    for (i = 0; i < GZP_MAX_CONNS; i++) {
        gzp_conn_t *np = &net->conns[i];
        gzp_tp_peer_t *p;
        if (!np->used || !(p = peer(t, np->peer_id, 1)) || p->sent >= t->n) continue;
        send_ping(t, net, np->peer_id, p->sent);
        p->sent++;
    }
}

int gzp_testping_timeout(const gzp_testping_t *t, uint64_t now)
{
    if (t->n <= 0) return -1;
    return t->next_ms > now ? (int)(t->next_ms - now) : 0;
}
#else
typedef int gzp_no_testping_in_release_t;
#endif
