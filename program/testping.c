/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gazpacho/envelope.h"
#include "gzp.h"
#include "testping.h"

#ifdef GZP_TEST_BUILD /* test traffic exists only in gazpacho-test */
#include "gazpacho/test_engine.h"

void gzp_testping_init(gzp_testping_t *t, int n, int every_ms, const char *name, int areas)
{
    memset(t, 0, sizeof *t);
    t->n = n > GZP_TESTPING_MAX ? GZP_TESTPING_MAX : n;
    t->every_ms = every_ms;
    t->name = name;
    t->areas = areas < 1 ? 1 : areas > GZP_TESTPING_AREAS ? GZP_TESTPING_AREAS : areas;
}

static gzp_tp_peer_t *peer(gzp_testping_t *t, const uint8_t key[33], int make)
{
    int i;
    for (i = 0; i < GZP_MAX_CONNS; i++)
        if (t->peers[i].used && !memcmp(t->peers[i].key, key, 33)) return &t->peers[i];
    if (!make) return NULL;
    for (i = 0; i < GZP_MAX_CONNS; i++)
        if (!t->peers[i].used) {
            memset(&t->peers[i], 0, sizeof t->peers[i]);
            t->peers[i].used = 1;
            memcpy(t->peers[i].key, key, 33);
            return &t->peers[i];
        }
    return NULL;
}

/* A test-kind message: record 1 the tag and body, record 3 the engine. */
static void send_test(gzp_net_t *net, const uint8_t key[33], const char tag[4], const uint8_t *body, size_t blen,
                      unsigned area)
{
    uint8_t rec[4 + 128], recs[160], a[2], scope[32];
    size_t at = 0;
    gz_link_t l;
    if (blen > 128) return;
    memcpy(rec, tag, 4);
    if (blen) memcpy(rec + 4, body, blen);
    gz_put_u16(a, (uint16_t)area);
    if (gz_rec_put(recs, sizeof recs, &at, GZ_TE_REC_TAG, rec, 4 + blen) != GZ_OK ||
        gz_rec_put(recs, sizeof recs, &at, GZ_TE_REC_AREA, a, 2) != GZ_OK)
        return;
    memset(scope, 0, sizeof scope);
    memcpy(l.local.key, net->pub, 33);
    memcpy(l.remote.key, key, 33);
    gzp_net_send(net, &l, GZ_TE_KIND, scope, recs, at);
}

static void send_ping(gzp_testping_t *t, gzp_net_t *net, const uint8_t key[33], int k)
{
    char p[GZ_TE_MAX_PAYLOAD];
    int pl = snprintf(p, sizeof p, "%s/%d", t->name, k), a;
    if (pl <= 0 || pl >= (int)sizeof p) return;
    for (a = 0; a < t->areas; a++) send_test(net, key, "GZPI", (const uint8_t *)p, (size_t)pl, 0x7e57u + (unsigned)a);
    /* --test-exit-after-send: the ping is in the transport's queue, which the
     * loop flushes; the program exits a few turns later (gzp_testping_tick),
     * before it handles the reply. */
    if (t->exit_after_send && k == 0 && !t->exit_at) t->exit_at = gzp_mono_ms() + 1;
}

void gzp_testping_burst(gzp_testping_t *t, int n, int bytes)
{
    t->burst_n = n;
    t->burst_bytes = bytes;
}

void gzp_testping_connected(gzp_testping_t *t, gzp_net_t *net, const uint8_t key[33])
{
    gzp_tp_peer_t *p;
    int k, a;
    if (t->burst_n > 0 && t->burst_bytes >= 4) {
        /* GZPX filler as one record 1: bytes counts the whole record. */
        size_t blen = (size_t)t->burst_bytes;
        uint8_t *m = malloc(blen + 16), scope[32];
        if (m) {
            size_t at = 0;
            gz_link_t l;
            uint8_t *r = malloc(blen);
            if (r) {
                memset(r, 'x', blen);
                memcpy(r, "GZPX", 4);
                if (gz_rec_put(m, blen + 16, &at, GZ_TE_REC_TAG, r, blen) == GZ_OK) {
                    memset(scope, 0, sizeof scope);
                    memcpy(l.local.key, net->pub, 33);
                    memcpy(l.remote.key, key, 33);
                    for (k = 0; k < t->burst_n; k++) gzp_net_send(net, &l, GZ_TE_KIND, scope, m, at);
                }
                free(r);
            }
            gzp_log("burst-sent peer=%016llx n=%d bytes=%d", (unsigned long long)gzp_peer_id(key), t->burst_n,
                    t->burst_bytes);
            free(m);
        }
    }
    if (t->n <= 0 || !(p = peer(t, key, 1))) return;
    for (k = 0; k < p->sent; k++)
        for (a = 0; a < t->areas; a++)
            if (!p->answered[a][k]) {
                send_ping(t, net, key, k);
                break;
            }
}

void gzp_testping_message(gzp_testping_t *t, const uint8_t key[33], uint16_t kind, const uint8_t *records, size_t len)
{
    gzp_tp_peer_t *p;
    gz_bytes_t r, ar, s = {records, len};
    size_t nl;
    char buf[GZ_TE_MAX_PAYLOAD + 1];
    char *end;
    long k;
    unsigned area = 0x7e57u, a;
    if (t->n <= 0 || kind != GZ_TE_KIND || !(p = peer(t, key, 0))) return;
    if (gz_rec_find(s, GZ_TE_REC_TAG, &r) != 1 || r.len < 12 || memcmp(r.data, "GZPO", 4)) return;
    if (gz_rec_find(s, GZ_TE_REC_AREA, &ar) == 1 && ar.len == 2) area = gz_get_u16(ar.data);
    a = area - 0x7e57u;
    if (a >= (unsigned)t->areas) return;
    nl = strlen(t->name);
    if (r.len - 12 > GZ_TE_MAX_PAYLOAD) return;
    memcpy(buf, r.data + 12, r.len - 12);
    buf[r.len - 12] = 0;
    if (strncmp(buf, t->name, nl) || buf[nl] != '/') return;
    k = strtol(buf + nl + 1, &end, 10);
    if (*end || k < 0 || k >= t->n || k >= p->sent) return;
    gzp_log("pong peer=%016llx k=%ld area=0x%04x dup=%d", (unsigned long long)gzp_peer_id(key), k, area,
            p->answered[a][k] ? 1 : 0);
    if (!p->answered[a][k]) {
        p->answered[a][k] = 1;
        p->n_answered++;
    }
    if (!p->done && p->n_answered == t->n * t->areas) {
        p->done = 1;
        gzp_log("pings-done peer=%016llx n=%d", (unsigned long long)gzp_peer_id(key), t->n);
    }
}

void gzp_testping_tick(gzp_testping_t *t, gzp_net_t *net, uint64_t now)
{
    int i;
    if (t->exit_at && now >= t->exit_at) {
        gzp_log("test-exit after-send k=0");
        fflush(stdout);
        _exit(GZP_EXIT_TEST);
    }
    if (t->n <= 0 || now < t->next_ms) return;
    t->next_ms = now + (uint64_t)t->every_ms;
    if (net->queueing) return;
    for (i = 0; i < GZP_MAX_CONNS; i++) {
        gzp_conn_t *np = &net->conns[i];
        gzp_tp_peer_t *p;
        if (!np->used || !(p = peer(t, np->key, 1)) || p->sent >= t->n) continue;
        p->sent++;
        send_ping(t, net, np->key, p->sent - 1);
    }
}

int gzp_testping_timeout(const gzp_testping_t *t, uint64_t now)
{
    if (t->exit_at) return t->exit_at > now ? (int)(t->exit_at - now) : 0;
    if (t->n <= 0) return -1;
    return t->next_ms > now ? (int)(t->next_ms - now) : 0;
}
#else
typedef int gzp_no_testping_in_release_t;
#endif
