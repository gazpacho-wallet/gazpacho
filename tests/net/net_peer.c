/* A peer for testing gz-net from the outside (tests/net/test_gz_net.sh).
 * Its ping and pong encoding is written here from the description in
 * gz-net.c's header, not taken from gz-net's code.
 *
 *   net_peer even PORT PIN     member: ping, then an unknown even message;
 *                              exit 0 if the host then closes (not a timeout)
 *   net_peer odd PORT PIN      member: an unknown odd message, then a ping;
 *                              exit 0 if the pong still comes
 *   net_peer badpong           host: print "listening PORT NODE_ID", accept one
 *                              member, answer its ping with the wrong sequence */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "conn.h"

static gz_conn_t c;
static secp256k1_context *secp;

static void done(void)
{
    gz_conn_close(&c);
    secp256k1_context_destroy(secp);
}
static uint8_t buf[GZ_NOISE_MAX_MSG];

static void counter(void *ctx, uint32_t purpose, uint8_t *out, size_t len)
{ (void)purpose;
    static uint8_t n = 1;
    (void)ctx;
    memset(out, 0x55, len);
    out[len - 1] = n++;
}

/* type 32769 (0x8001), TLV: 01 01 kind, 03 01 seq (one byte, non-zero) */
static int send_ping(int kind, uint8_t seq)
{
    uint8_t m[8] = {0x80, 0x01, 0x01, 0x01, 0, 0x03, 0x01, 0};
    m[4] = (uint8_t)kind;
    m[7] = seq;
    return gz_conn_send(&c, m, sizeof m) == GZ_CONN_OK;
}

static int is_pong(const uint8_t *m, size_t n, uint8_t seq)
{
    static const uint8_t want[8] = {0x80, 0x01, 0x01, 0x01, 0x02, 0x03, 0x01, 0};
    return n == 8 && memcmp(m, want, 7) == 0 && m[7] == seq;
}

int main(int argc, char **argv)
{
    static const uint8_t key[32] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                                    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                                    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
    gz_random_port_t rng = {counter, NULL};
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    atexit(done);
    gz_conn_limits_t lim;
    uint8_t pin[33];
    size_t n;
    int i;
    gz_conn_default_limits(&lim);
    lim.recv_ms = 5000;
    if (argc == 2 && !strcmp(argv[1], "badpong")) {
        secp256k1_pubkey pk;
        size_t pl = 33;
        int lfd;
        uint16_t port;
        if (gz_conn_listen("127.0.0.1", 0, &lfd, &port)) return 3;
        if (!secp256k1_ec_pubkey_create(secp, &pk, key) ||
            !secp256k1_ec_pubkey_serialize(secp, pin, &pl, &pk, SECP256K1_EC_COMPRESSED))
            return 3;
        printf("listening %u ", (unsigned)port);
        for (i = 0; i < 33; i++) printf("%02x", pin[i]);
        printf("\n");
        fflush(stdout);
        lim.accept_ms = 10000;
        if (gz_conn_accept(&c, lfd, secp, key, rng, &lim, gz_conn_any_member, NULL)) return 4;
        if (gz_conn_recv(&c, buf, sizeof buf, &n) || n < 8 || buf[4] != 1) return 5;
        buf[4] = 2;
        buf[n - 1] ^= 1; /* wrong sequence number (its last byte) */
        if (gz_conn_send(&c, buf, n)) return 6;
        gz_conn_recv(&c, buf, sizeof buf, &n); /* until the member closes */
        return 0;
    }
    if (argc != 4 || strlen(argv[3]) != 66) return 2;
    for (i = 0; i < 33; i++) {
        unsigned v;
        if (sscanf(argv[3] + 2 * i, "%2x", &v) != 1) return 2; /* test input, written by the test */
        pin[i] = (uint8_t)v;
    }
    if (gz_conn_connect(&c, "127.0.0.1", (uint16_t)atoi(argv[2]), secp, key, pin, rng, &lim)) return 7;
    if (!strcmp(argv[1], "even")) {
        static const uint8_t even[4] = {0x80, 0x02, 0xaa, 0xbb};
        gz_conn_err_t e;
        if (!send_ping(1, 9) || gz_conn_recv(&c, buf, sizeof buf, &n) || !is_pong(buf, n, 9)) return 8;
        if (gz_conn_send(&c, even, sizeof even)) return 9;
        e = gz_conn_recv(&c, buf, sizeof buf, &n);
        return e == GZ_CONN_ERR_CLOSED || e == GZ_CONN_ERR_SOCKET ? 0 : 10; /* a close, not a timeout or a reply */
    }
    if (!strcmp(argv[1], "odd")) {
        static const uint8_t odd[4] = {0x80, 0x03, 0xaa, 0xbb};
        if (gz_conn_send(&c, odd, sizeof odd) || !send_ping(1, 7)) return 11;
        if (gz_conn_recv(&c, buf, sizeof buf, &n) || !is_pong(buf, n, 7)) return 12;
        gz_conn_close(&c);
        return 0;
    }
    return 2;
}
