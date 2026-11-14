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
#include "lnmsg.h"
#include "net.h"

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
    gzp_net_limits_t lim = {1000, 1000, 1000, 1000, 1000, -1, 0};
    gzp_net_events_t ev;
    gz_link_t l;
    memset(&ev, 0, sizeof ev);
    memset(priv, 0x11, sizeof priv);
    memcpy(chain, GZ_LN_CHAIN_SIGNET, 32);
    CHECK(gzp_net_init(&n, secp, priv, rnd, chain, &lim, 100, &ev) == 0);

    CHECK(connect_addr(&n, 1, "127.0.0.1:9736") == 0 && targets(&n) == 1);
    CHECK(!strcmp(n.targets[0].host, "127.0.0.1") && n.targets[0].port == 9736 && n.targets[0].index == 2);
    CHECK(connect_addr(&n, 1, "127.0.0.1:1") == 0 && targets(&n) == 1); /* the same host: the address replaced */
    CHECK(!strcmp(n.targets[0].host, "127.0.0.1") && n.targets[0].port == 1);
    CHECK(connect_addr(&n, 2, "") != 0);
    CHECK(connect_addr(&n, 2, "127.0.0.1") != 0);
    CHECK(connect_addr(&n, 2, ":80") != 0);
    CHECK(connect_addr(&n, 2, "127.0.0.1:0") != 0);
    CHECK(connect_addr(&n, 2, "127.0.0.1:65536") != 0);
    CHECK(connect_addr(&n, 2, "127.0.0.1:12x") != 0);
    CHECK(connect_addr(&n, 2, "1234567890123456789012345678901234567890123456789012345678901234567890:1") != 0);
    CHECK(targets(&n) == 1);
    for (int i = 0; i < GZP_MAX_TARGETS - 1; i++) CHECK(connect_addr(&n, (uint8_t)(10 + i), "127.0.0.1:2") == 0);
    CHECK(connect_addr(&n, 99, "127.0.0.1:2") != 0 && targets(&n) == GZP_MAX_TARGETS);

    /* DISCONNECT stops keeping the target. */
    memcpy(l.local.key, n.pub, 33);
    memset(l.remote.key, 1, 33);
    l.remote.key[0] = 2;
    gzp_net_disconnect(&n, &l, 0);
    CHECK(targets(&n) == GZP_MAX_TARGETS - 1);

    /* SENDs: dropped with no connection, and with a local key not ours. */
    CHECK(gzp_net_send(&n, &l, 16, scope, NULL, 0) == 1);
    l.local.key[5] ^= 1;
    CHECK(gzp_net_send(&n, &l, 16, scope, NULL, 0) == 1);
    CHECK(n.dropped_unconnected == 2);

    CHECK(gzp_net_reset(&n) == 0 && targets(&n) == 0);
    gzp_net_free(&n);
    secp256k1_context_destroy(secp);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("net: all checks passed\n");
    return 0;
}
