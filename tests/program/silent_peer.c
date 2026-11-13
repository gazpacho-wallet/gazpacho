/* SPDX-License-Identifier: MIT */
/* A client for program_slow_peers (contract-v2.md T6): complete a BOLT 8
 * handshake with a host, then send nothing at all (no init) and wait.
 *
 *   gzp_silent_peer PORT HOST_KEY_HEX SECONDS
 *
 * Prints "handshake-done" once the handshake is complete, then sleeps SECONDS;
 * the host's output shows when it closed the connection. Uses
 * conn.h, which only tools and tests do. */
#if defined(__linux__)
#define _GNU_SOURCE
#include <sys/random.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <secp256k1.h>

#include "conn.h"

static void os_fill(void *ctx, uint8_t *out, size_t len)
{
    size_t done = 0;
    (void)ctx;
    while (done < len) {
        ssize_t r = getrandom(out + done, len - done, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) abort();
        done += (size_t)r;
    }
}

static int unhex(const char *s, uint8_t *out, size_t n)
{
    size_t i;
    if (strlen(s) != 2 * n) return 0;
    for (i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

static gz_conn_t conn;

int main(int argc, char **argv)
{
    uint8_t pin[33], key[32];
    gz_net_random_t rnd = {os_fill, NULL};
    secp256k1_context *secp;
    int secs;
    if (argc != 4 || !unhex(argv[2], pin, 33) || (secs = atoi(argv[3])) <= 0) {
        fprintf(stderr, "usage: gzp_silent_peer PORT HOST_KEY_HEX SECONDS\n");
        return 2;
    }
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    do {
        os_fill(NULL, key, 32);
    } while (!secp256k1_ec_seckey_verify(secp, key));
    if (gz_conn_connect(&conn, "127.0.0.1", (uint16_t)atoi(argv[1]), secp, key, pin, rnd, NULL) != GZ_CONN_OK) {
        printf("handshake-failed\n");
        return 1;
    }
    printf("handshake-done\n");
    fflush(stdout);
    /* Read nothing and send nothing: the host must close this at its deadline. */
    sleep((unsigned)secs);
    fflush(stdout);
    gz_conn_close(&conn);
    secp256k1_context_destroy(secp);
    return 0;
}
