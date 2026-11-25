/* SPDX-License-Identifier: MIT */
/* The network adapter without a network (program/net.c): CONNECT targets
 * (the address parsed, a second CONNECT to the same host replacing the
 * address, the table's limit, DISCONNECT ending one), and SENDs dropped when
 * there is no connection or the link's local key is not ours. Each address
 * is copied into a heap block of exactly its length, so a read past its end
 * is an AddressSanitizer report. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gzp.h"
#include "keys.h"
#include "keys_standin.h"
#include "lnmsg.h"
#include "net.h"

static gzp_keys_t keys;            /* P8: the key port over the test words (entropy all zero) */
static gzp_seed_standin_t seedsrc;

static int failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static void fill(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(i * 7 + 1);
}

static int connect_addr(gzp_net_t *n, uint8_t k, const char *addr)
{
    uint8_t key[33];
    size_t len = strlen(addr);
    uint8_t *b = malloc(len ? len : 1);
    int r;
    if (!b) abort();
    memcpy(b, addr, len);
    memset(key, k, sizeof key);
    key[0] = 2;
    r = gzp_net_connect(n, key, b, len, 0, 2);
    free(b);
    return r;
}

static int targets(const gzp_net_t *n)
{
    int c = 0;
    for (int i = 0; i < GZP_MAX_TARGETS; i++) c += n->targets[i].used;
    return c;
}

int main(void)
{
    static gzp_net_t n;
    secp256k1_context *secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    uint8_t priv[32], scope[32] = {0}, chain[32];
    gz_net_random_t rnd = {fill, NULL};
    gzp_net_limits_t lim = {1000, 1000, 1000, 1000, 1000, -1, 0, 0};
    gzp_net_events_t ev;
    gz_link_t l;
    memset(&ev, 0, sizeof ev);
    memset(priv, 0x11, sizeof priv);
    memcpy(chain, GZ_LN_CHAIN_SIGNET, 32);
    CHECK(gzp_net_init(&n, secp, priv, rnd, chain, &lim, 100, &ev) == 0);
    n.single_key = 1; /* as a test build with test engines: every index is the transport key */
    {
        uint8_t zero[32] = {0};
        gzp_seed_source_t src;
        CHECK(gzp_seed_standin_from_entropy(&seedsrc, zero) == 0);
        src = gzp_seed_standin_source(&seedsrc);
        CHECK(gzp_keys_init(&keys, secp, GZW_NET_SIGNET, &src, NULL) == 1);
    }

    CHECK(connect_addr(&n, 1, "127.0.0.1:9736") == 0 && targets(&n) == 1);
    CHECK(!strcmp(n.targets[0].host, "127.0.0.1") && n.targets[0].port == 9736 && n.targets[0].index == 2);
    CHECK(connect_addr(&n, 1, "127.0.0.1:1") == 0 && targets(&n) == 1); /* the same host: the address replaced */
    CHECK(!strcmp(n.targets[0].host, "127.0.0.1") && n.targets[0].port == 1);
    /* A CONNECT the adapter cannot keep is reported and counted, never an
     * error the caller must make fatal (1, not -1). */
    CHECK(connect_addr(&n, 2, "") == 1);
    CHECK(connect_addr(&n, 2, "not-an-address") == 1 && connect_addr(&n, 2, "no-port-here") == 1);
    CHECK(n.connect_failed == 3);
    CHECK(connect_addr(&n, 3, "[::1]:9735") == 0 && !strcmp(n.targets[1].host, "::1") && n.targets[1].port == 9735);
    gz_link_t l6;
    memcpy(l6.local.key, n.pub, 33);
    memset(l6.remote.key, 3, 33);
    l6.remote.key[0] = 2;
    gzp_net_disconnect(&n, &l6, 0);
    n.connect_failed = 0;
    CHECK(connect_addr(&n, 2, "127.0.0.1") != 0);
    CHECK(connect_addr(&n, 2, ":80") != 0);
    CHECK(connect_addr(&n, 2, "127.0.0.1:0") != 0);
    CHECK(connect_addr(&n, 2, "127.0.0.1:65536") != 0);
    CHECK(connect_addr(&n, 2, "127.0.0.1:12x") != 0);
    CHECK(connect_addr(&n, 2, "1234567890123456789012345678901234567890123456789012345678901234567890:1") != 0);
    CHECK(targets(&n) == 1);
    for (int i = 0; i < GZP_MAX_TARGETS - 1; i++) CHECK(connect_addr(&n, (uint8_t)(10 + i), "127.0.0.1:2") == 0);
    CHECK(connect_addr(&n, 99, "127.0.0.1:2") == 1 && targets(&n) == GZP_MAX_TARGETS);
    CHECK(n.connect_failed == 7); /* the six bad addresses above and the full table */

    /* DISCONNECT stops keeping the target. */
    memcpy(l.local.key, n.pub, 33);
    memset(l.remote.key, 1, 33);
    l.remote.key[0] = 2;
    gzp_net_disconnect(&n, &l, 0);
    CHECK(targets(&n) == GZP_MAX_TARGETS - 1);

    /* SENDs: dropped with no connection, and with a local key not ours. */
    CHECK(gzp_net_send(&n, &l, 16, scope, NULL, 0) == 1);
    /* Kind 0xffff, reserved (action.h; the lobby's bridge until P4.2): never on the
     * wire. The adapter refuses it whatever the link, and the executor makes
     * that fatal. This fails if the adapter is ever asked to send it and does. */
    CHECK(gzp_net_send(&n, &l, GZ_SEND_KIND_RESERVED, scope, NULL, 0) == -2);
    CHECK(n.dropped_unconnected == 1);
    l.local.key[5] ^= 1;
    CHECK(gzp_net_send(&n, &l, 16, scope, NULL, 0) == 1);
    CHECK(n.dropped_unconnected == 2);

    CHECK(gzp_net_reset(&n) == 0 && targets(&n) == 0);

    /* Per-lobby keys (P4.2, P8): every (epoch, index) is a key of its own,
     * the key port's (keys.h), and none is the transport key; only the
     * current epoch has keys. Two CONNECTs to one host with two
     * keys are two targets and two links; a DISCONNECT ends its own link's. */
    {
        uint8_t k0[33], k1[33], k3[33], k1e[33], sec[32], host[33], msg[32], sig[64], s2[32], p2[33];
        gz_link_t a1, a3;
        n.single_key = 0;
        memset(host, 7, 33);
        host[0] = 2;
        memset(msg, 0x5a, 32);
        CHECK(!gzp_net_key(&n, 0, 1, sec, k0)); /* no key port: no per-lobby key */
        n.key_fn = gzp_keys_net_fn;
        n.key_ctx = &keys;
        CHECK(gzp_net_key(&n, 0, 0, sec, k0) && gzp_keys_lobby_raw(&keys, 0, 0, s2, p2, NULL) && !memcmp(k0, p2, 33) &&
              !memcmp(sec, s2, 32) && memcmp(k0, n.pub, 33) && memcmp(sec, priv, 32));
        CHECK(gzp_net_key(&n, 0, 1, NULL, k1) && gzp_net_key(&n, 0, 3, NULL, k3) && !gzp_net_key(&n, 9, 1, NULL, k1e));
        gzp_keys_set_epoch(&keys, 9);
        CHECK(gzp_net_key(&n, 9, 1, NULL, k1e) && !gzp_net_key(&n, 0, 1, NULL, p2));
        gzp_keys_set_epoch(&keys, 0);
        CHECK(memcmp(k1, k0, 33) && memcmp(k3, k0, 33) && memcmp(k1, k3, 33) && memcmp(k1, k1e, 33));
        uint8_t notkey[33];
        memset(notkey, 0xff, 33);
        notkey[0] = 2;
        CHECK(gzp_net_point_ok(&n, k1) && gzp_net_point_ok(&n, k3) && !gzp_net_point_ok(&n, notkey));
        CHECK(gzp_net_sign(&n, 0, 1, msg, sig) && gzp_net_verify(&n, k1, msg, sig) && !gzp_net_verify(&n, k3, msg, sig));
        CHECK(gzp_net_sign(&n, 0, GZP_NET_KEY_STATIC, msg, sig) && gzp_net_verify(&n, n.pub, msg, sig));
        CHECK(gzp_net_key(&n, 0, GZP_NET_KEY_STATIC, NULL, k0) && !memcmp(k0, n.pub, 33));
        /* No CONNECT can name the static key, nor any index of 2^31 or more. */
        n.connect_failed = 0;
        CHECK(gzp_net_connect(&n, host, (const uint8_t *)"127.0.0.1:9", 11, 0, GZP_NET_KEY_STATIC) == 1 &&
              gzp_net_connect(&n, host, (const uint8_t *)"127.0.0.1:9", 11, 0, 0x80000000u) == 1 &&
              n.connect_failed == 2 && targets(&n) == 0);
        msg[0] ^= 1;
        CHECK(!gzp_net_verify(&n, n.pub, msg, sig));
        CHECK(gzp_net_connect(&n, host, (const uint8_t *)"127.0.0.1:9", 11, 0, 1) == 0 &&
              gzp_net_connect(&n, host, (const uint8_t *)"127.0.0.1:9", 11, 0, 3) == 0 && targets(&n) == 2);
        CHECK(gzp_net_connect(&n, host, (const uint8_t *)"127.0.0.1:8", 11, 0, 3) == 0 && targets(&n) == 2);
        memcpy(a1.local.key, k1, 33);
        memcpy(a1.remote.key, host, 33);
        memcpy(a3.local.key, k3, 33);
        memcpy(a3.remote.key, host, 33);
        gzp_net_disconnect(&n, &a3, 0);
        CHECK(targets(&n) == 1 && n.targets[0].used + n.targets[1].used == 1);
        /* A send on a link whose key is ours but which has no connection is
         * dropped as not connected; on a key that is not ours, as not ours. */
        n.dropped_unconnected = 0;
        CHECK(gzp_net_send(&n, &a1, 16, scope, NULL, 0) == 1 && gzp_net_send(&n, &a3, 16, scope, NULL, 0) == 1 &&
              n.dropped_unconnected == 2);
        gzp_net_disconnect(&n, &a1, 0);
        CHECK(targets(&n) == 0);
        /* With the single key of a test build with test engines, every index is the transport key. */
        n.single_key = 1;
        CHECK(gzp_net_key(&n, 0, 5, NULL, k1) && !memcmp(k1, n.pub, 33));
    }
    CHECK(gzp_net_reset(&n) == 0 && targets(&n) == 0);
    gzp_net_free(&n);
    gzp_keys_free(&keys);
    gzp_seed_standin_close(&seedsrc);
    secp256k1_context_destroy(secp);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("net: all checks passed\n");
    return 0;
}
