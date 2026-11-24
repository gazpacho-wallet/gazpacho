/* A hostile peer, the chain and the user, driven by a byte source: every
 * event they can cause, in any order and any content. The node must answer
 * each with GZ_OK (node.h, the engine rule): peers, the chain and the person
 * never cause a node error. Shared by test_node_hostile.c (a seeded run) and
 * fuzz_node.c (libFuzzer). */
#ifndef GZ_NODE_HOSTILE_H
#define GZ_NODE_HOSTILE_H

#include "node_test.h"

typedef struct {
    const uint8_t *p;
    size_t n, at;
    uint64_t x;        /* when the bytes run out: a generator */
} src_t;

static inline uint8_t src_byte(src_t *s)
{
    if (s->at < s->n) return s->p[s->at++];
    s->x ^= s->x << 13;
    s->x ^= s->x >> 7;
    s->x ^= s->x << 17;
    return (uint8_t)s->x;
}

static inline uint32_t src_u32(src_t *s)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v = v << 8 | src_byte(s);
    return v;
}

/* Test commands a user could send that are not the test engine's own
 * deliberate bugs (which exist to show the composite catches them). */
static inline int bug_command(uint16_t code)
{
    return code == GZ_TE_CMD_FAIL || code == GZ_TE_CMD_BROADCAST || code == GZ_TE_CMD_SELF_HANDOFF_NOW ||
           code == GZ_TE_CMD_BIG_TIMER || code == GZ_TE_CMD_HANDOFF;
}

/* One hostile event. Returns the node's status. */
static inline gz_status_t hostile_step(h_t *h, src_t *s)
{
    static const uint16_t kinds[] = {16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 63, 64, 66, 70, 76, 78, 80,
                                     81, 82, 128, 159, 32767, 2, 0, 65535};
    uint8_t scope[32], rec[512], body[100];
    size_t at = 0;
    uint8_t op = src_byte(s);
    if (h->n_pending > 24) { /* the runner holds at most 32 unconfirmed batches */
        h->confirm_auto = 1;
        h_confirm_all(h);
    }
    uint32_t who = src_byte(s) % 24;
    gz_link_t l;
    if (h->host) {
        l = h_host_link(who);
    } else {
        uint8_t a[33], b[33];
        h_key('K', 2 * (1 + who % 3), a);
        h_key(who & 1 ? 'H' : 'X', 0, b);
        l = h_link(a, b);
    }
    memset(scope, 0, sizeof scope);
    if (src_byte(s) & 1) memset(scope, 1 + src_byte(s) % 4, sizeof scope);
    h->auto_connect = 0; /* a peer may send on a link the node never saw connect, or closed */
    h->clock += src_byte(s) * 37u;
    if ((src_byte(s) & 31) == 0) h_clock_back(h, 5000); /* the wall clock may jump back */
    switch (op % 10) {
    case 0:
    case 1:
        return h_peer(h, &l, op & 1, src_byte(s) & 1);
    case 2:
    case 3:
    case 4: {
        /* A message: random kind and records. */
        uint16_t kind = kinds[src_byte(s) % (sizeof kinds / sizeof kinds[0])];
        size_t n = src_byte(s) % 200;
        for (size_t i = 0; i < n; i++) rec[i] = src_byte(s);
        return h_msg(h, &l, kind, scope, rec, n);
    }
    case 5: {
        /* A well-formed test message with a random tag. */
        static const char *tags[] = {"GZPI", "GZPO", "GZPA", "GZPH", "GZPX", "ABCD"};
        size_t blen = src_byte(s) % 90;
        for (size_t i = 0; i < blen; i++) body[i] = src_byte(s);
        if (src_byte(s) & 1) gz_put_u64(body, src_byte(s) % 8);
        return h_test_msg(h, &l, tags[src_byte(s) % 6], body, blen, (uint16_t)(0x7e56 + src_byte(s) % 4));
    }
    case 6:
        return h_timer(h, (uint64_t)src_u32(s) << 32 | src_u32(s));
    case 7: {
        gz_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_CHAIN;
        ev.u.chain.kind = (gz_chain_kind_t)(1 + src_byte(s) % 6);
        memset(ev.u.chain.txid, src_byte(s) % 100, 32); /* among the txids the commands below watch */
        memset(ev.u.chain.outpoint.txid, ev.u.chain.txid[0], 32);
        ev.u.chain.outpoint.vout = src_byte(s) % 2;
        ev.u.chain.confirmations = src_byte(s);
        ev.u.chain.height = src_u32(s);
        ev.u.chain.outcome = (gz_broadcast_outcome_t)(1 + src_byte(s) % 3);
        return h_event(h, &ev);
    }
    case 8: {
        /* A user command: a code from the ranges, random arguments. */
        static const uint16_t codes[] = {0x7e01, 0x7e02, 0x7e05, 0x7e06, 0x7e07, 0x7e09, 0x7e0c, 0x7e80, 0x7e81,
                                         0x7e82, 0x7e83, 0x7e84, 0x7e85, 0x7e05, 0x7e0c, 0x7e84, 0x0101, 0x0301,
                                         0x0401, 0x0d01, 0x0d02, 0x0d03, 0x0109, 0x0d7f, 0x7e7f, 0};
        /* Addresses a person or an invitation could give: good, and bad in
         * every way the address rule and the program's own parsing refuse. */
        static const char *addrs[] = {"127.0.0.1:1", "not-an-address", "no-port-here", "127.0.0.1", "127.0.0.1:",
                                      ":1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:99999", "host:1",
                                      "[::1]:1", "[::1:1", "192.0.2.4:01", "999.999.999.999:1", "", "1:1:1",
                                      "127.0.0.1:1 ", "127.0.0.1:-1", "0000000000000000000000000000000000000000000000000000000000000000:1",
                                      "00000000000000000000000000000000000000000000000000000000000000000000000000000000:1"};
        const char *addr = (src_byte(s) & 3) ? addrs[0] : addrs[src_byte(s) % (sizeof addrs / sizeof addrs[0])];
        uint16_t code = codes[src_byte(s) % (sizeof codes / sizeof codes[0])];
        uint8_t c2[2], a[64], role = src_byte(s) & 1, mk[33];
        if (bug_command(code)) return GZ_OK;
        gz_put_u16(c2, code);
        /* Now and then an API request (P6a): an id, a method, a path and a
         * digest, from a few, so that replays and reused ids come too. */
        static const char *rids[] = {"Aq4mT9cV2xE7nR0aW5zK", "Bq4mT9cV2xE7nR0aW5zK", "short"};
        int api = (src_byte(s) & 3) == 0;
        const char *rid = api ? rids[src_byte(s) % 3] : "r";
        uint8_t dg[32];
        gz_rec_put(rec, sizeof rec, &at, 0, (const uint8_t *)rid, strlen(rid));
        if (api) {
            memset(dg, src_byte(s) % 3, sizeof dg);
            gz_rec_put(rec, sizeof rec, &at, 2, (const uint8_t *)"POST", 4);
            gz_rec_put(rec, sizeof rec, &at, 4, (const uint8_t *)"/api/v1/x", 9);
            gz_rec_put(rec, sizeof rec, &at, 6, dg, 32);
        }
        if (code) gz_rec_put(rec, sizeof rec, &at, 8, c2, 2);
        if (src_byte(s) & 1) {
            uint8_t area[2];
            gz_put_u16(area, (uint16_t)(0x7e57 + src_byte(s) % 2));
            gz_rec_put(rec, sizeof rec, &at, 10, area, 2);
        }
        h_key('H', 0, mk);
        if (code == 0x7e01) {
            /* Hosts enough to pass the engine's table of targets. */
            h_key('H', src_byte(s) % 6, mk);
            gz_rec_put(rec, sizeof rec, &at, 12, mk, 33);
            gz_rec_put(rec, sizeof rec, &at, 14, (const uint8_t *)addr, strlen(addr));
        } else if (code == 0x7e05 || code == 0x7e0c || code == 0x7e84) {
            /* Watches: a hundred txids, more than any engine's budget or the
             * registry holds. */
            uint8_t txid[32], d[4];
            memset(txid, src_byte(s) % 100, sizeof txid);
            gz_put_u32(d, src_byte(s) % 4);
            if (code == 0x7e84) gz_rec_put(rec, sizeof rec, &at, 12, scope, 32);
            gz_rec_put(rec, sizeof rec, &at, code == 0x7e84 ? 14 : 12, txid, 32);
            if (code == 0x7e0c) {
                uint8_t vout[4];
                gz_put_u32(vout, src_byte(s) % 2);
                gz_rec_put(rec, sizeof rec, &at, 14, vout, 4);
            }
            gz_rec_put(rec, sizeof rec, &at, code == 0x7e05 ? 14 : 16, d, 4);
        } else if (code >= 0x7e80) {
            gz_rec_put(rec, sizeof rec, &at, 12, scope, 32);
            if (code == 0x7e82) h_key('M', who, mk);
            gz_rec_put(rec, sizeof rec, &at, 14, code == 0x7e82 ? mk : &role, code == 0x7e82 ? 33 : 1);
            h_key('H', 0, mk);
            gz_rec_put(rec, sizeof rec, &at, 16, mk, 33);
            gz_rec_put(rec, sizeof rec, &at, 18, (const uint8_t *)addr, strlen(addr));
            a[0] = 0;
            a[1] = 0;
            a[2] = 0;
            a[3] = (uint8_t)(src_byte(s) % 50);
            gz_rec_put(rec, sizeof rec, &at, 20, a, 4);
            a[0] = src_byte(s) & 1;
            gz_rec_put(rec, sizeof rec, &at, 22, a, 1);
        } else {
            size_t n = src_byte(s) % 60;
            for (size_t i = 0; i < n; i++) a[i] = src_byte(s);
            gz_rec_put(rec, sizeof rec, &at, 12, a, n % 40);
            gz_rec_put(rec, sizeof rec, &at, 14, a, 4);
            gz_rec_put(rec, sizeof rec, &at, 16, scope, 32);
            gz_rec_put(rec, sizeof rec, &at, 18, a, n % 20);
        }
        gz_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_USER_COMMAND;
        ev.u.user.bytes.data = rec;
        ev.u.user.bytes.len = (src_byte(s) & 15) ? at : (size_t)src_byte(s) % (at + 1);
        return h_event(h, &ev);
    }
    default: {
        /* A restart from storage now and then: the node starts from what it saved. */
        if ((src_byte(s) & 15) == 0) return h_restart(h);
        h->confirm_auto = src_byte(s) & 1;
        if (h->confirm_auto) h_confirm_all(h);
        return GZ_OK;
    }
    }
}

#endif
