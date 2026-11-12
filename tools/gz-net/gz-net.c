/* gz-net: complete a BOLT 8 handshake between two local processes and
 * exchange a ping and pong of custom messages (type 32769); or hold a lobby
 * connection (init, BOLT 1 ping and pong, factory messages) for a while.
 *
 * Addresses (--host) must be numeric.
 *
 *   gz-net listen  [--host H] [--port P] [--key-file F] [--accept N]
 *   gz-net connect --port P --pin HEX [--host H] [--key-file F] [--count N]
 *   gz-net serve   [--host H] [--port P] [--key-file F] [--accept N]
 *                  [--ping-ms N] [--pong-ms N] [--seconds N]
 *   gz-net join    --port P --pin HEX [--host H] [--key-file F]
 *                  [--ping-ms N] [--pong-ms N] [--seconds N]
 *
 * listen prints "listening PORT NODE_ID" once bound, then "peer NODE_ID" and
 * "done PINGS" for each connection. connect prints "ok COUNT". A key file
 * holds a 32-byte secret key as 64 hex digits; without one a throwaway key is
 * made. Keys are never printed. Exit status 0 only if everything succeeded.
 *
 * The custom message's payload is a TLV stream: type 1 is the kind (1 byte:
 * 1 ping, 2 pong), type 3 the sequence number (tu64).
 *
 * serve is a stand-in lobby host (transport only): it prints "listening PORT
 * NODE_ID", answers each hello with a lobby_status for an unknown lobby, and
 * after N connections have closed prints "done" with its ping counters; it
 * fails if a connection ends other than by the member closing it, or after
 * --seconds (default 3600). join connects, sends hello, waits for the
 * status, stays connected for --seconds (default 10) while pings keep the
 * connection alive, and prints "ok pings=N pongs=N". Both use the 15 s ping
 * and 30 s pong timeout of messages.md section 2 unless told otherwise. */
#if defined(__linux__)
#define _GNU_SOURCE
#include <sys/random.h> /* getrandom */
#else
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <unistd.h> /* getentropy */
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/crypto.h>
#include <secp256k1.h>

#include "conn.h"
#include "frame.h"
#include "peers.h"

#define PING_TYPE 32769
#define KIND_PING 1
#define KIND_PONG 2

/* Randomness straight from the kernel, with no buffer of future key bytes
 * left in the process. The port cannot report a failure, so a failure ends
 * the program rather than hand out weak keys. */
static void os_fill(void *ctx, uint8_t *out, size_t len)
{
    size_t done = 0;
    (void)ctx;
    while (done < len) {
#if defined(__linux__)
        ssize_t r = getrandom(out + done, len - done, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        done += (size_t)r;
#else
        size_t n = len - done > 256 ? 256 : len - done;
        if (getentropy(out + done, n) != 0) break;
        done += n;
#endif
    }
    if (done != len) {
        fprintf(stderr, "gz-net: cannot read randomness from the system\n");
        abort();
    }
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Exactly 2n hex digits, nothing else. */
static int hex_decode(const char *s, size_t slen, uint8_t *out, size_t n)
{
    size_t i;
    if (slen != 2 * n) return 0;
    for (i = 0; i < n; i++) {
        int hi = hex_digit(s[2 * i]), lo = hex_digit(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return 1;
}

/* A whole decimal number in [min, max], nothing else. */
static int parse_num(const char *s, long min, long max, long *out)
{
    char *end;
    long v;
    if (*s < '0' || *s > '9') return 0;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || *end || v < min || v > max) return 0;
    *out = v;
    return 1;
}

static void hex_print(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", p[i]);
}

/* A key file is 64 hex digits and an optional line end, nothing else. */
static int load_key(const char *path, uint8_t key[32])
{
    char buf[80];
    size_t n;
    int ok;
    FILE *f;
    if (!path) {
        os_fill(NULL, key, 32);
        return 1;
    }
    f = fopen(path, "rb");
    if (!f) return 0;
    n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n > 64 && buf[n - 1] == '\n') n--;
    if (n > 64 && buf[n - 1] == '\r') n--;
    ok = hex_decode(buf, n, key, 32);
    OPENSSL_cleanse(buf, sizeof buf);
    return ok;
}

static int check_kind(const gz_tlv_record_t *r, void *ctx)
{
    (void)ctx;
    return r->len == 1 && (r->value[0] == KIND_PING || r->value[0] == KIND_PONG);
}

static int check_seq(const gz_tlv_record_t *r, void *ctx)
{
    uint64_t v;
    (void)ctx;
    return gz_tu_read(r->value, r->len, 8, &v) == GZ_FRAME_OK;
}

static const gz_tlv_known_t KNOWN[] = {{1, check_kind}, {3, check_seq}};

static size_t make_ping(uint8_t *out, size_t cap, int kind, uint64_t seq)
{
    uint8_t tlv[32], k = (uint8_t)kind, t[8];
    gz_tlv_writer_t w;
    size_t n = 0;
    gz_tlv_writer_init(&w, tlv, sizeof tlv);
    gz_tlv_put(&w, 1, &k, 1);
    gz_tlv_put(&w, 3, t, gz_tu_write(seq, t));
    if (w.err || gz_msg_write(PING_TYPE, tlv, w.len, out, cap, &n)) return 0;
    return n;
}

/* 1: a ping or pong was read; 0: a message to ignore; -1: close. */
static int read_ping(const uint8_t *msg, size_t len, int *kind, uint64_t *seq)
{
    uint16_t type;
    const uint8_t *rest;
    size_t rest_len, n;
    gz_tlv_record_t rec[2];
    if (gz_msg_parse(msg, len, &type, &rest, &rest_len)) return -1;
    if (type != PING_TYPE) return gz_msg_unknown_action(type) == GZ_MSG_IGNORE ? 0 : -1;
    if (gz_tlv_parse(rest, rest_len, KNOWN, 2, NULL, rec, 2, &n) || n != 2) return -1;
    *kind = rec[0].value[0];
    gz_tu_read(rec[1].value, rec[1].len, 8, seq);
    return 1;
}

static gz_conn_t conn; /* 64 KiB buffer: kept off the stack */

static void report(const char *what, gz_conn_err_t e)
{
    if (conn.noise_err != GZ_NOISE_OK)
        fprintf(stderr, "gz-net: %s: %s (%s)\n", what, gz_conn_err_name(e), gz_noise_err_name(conn.noise_err));
    else
        fprintf(stderr, "gz-net: %s: %s\n", what, gz_conn_err_name(e));
}

static int cmd_listen(const char *host, uint16_t port, const uint8_t key[32],
                      const secp256k1_context *secp, gz_random_port_t rnd, int accepts)
{
    uint8_t pub[33], msg[GZ_MSG_MAX], out[64];
    secp256k1_pubkey pk;
    size_t n = 33, len, olen;
    uint16_t bound;
    int lfd, i, failures = 0;
    gz_conn_err_t le;
    if (!secp256k1_ec_pubkey_create(secp, &pk, key) ||
        !secp256k1_ec_pubkey_serialize(secp, pub, &n, &pk, SECP256K1_EC_COMPRESSED)) {
        fprintf(stderr, "gz-net: invalid key\n");
        return 1;
    }
    if ((le = gz_conn_listen(host, port, &lfd, &bound))) {
        fprintf(stderr, "gz-net: cannot listen on %s:%u: %s\n", host, (unsigned)port, gz_conn_err_name(le));
        return 1;
    }
    printf("listening %u ", (unsigned)bound);
    hex_print(pub, 33);
    printf("\n");
    fflush(stdout);
    for (i = 0; i < accepts; i++) {
        gz_conn_limits_t lim;
        gz_conn_err_t e;
        int pings = 0, r, kind;
        uint64_t seq;
        gz_conn_default_limits(&lim);
        /* Waits for a connection without limit; the handshake has 10 s.
         * Any member key is accepted, as in slice 1's host (spec, rule 13). */
        e = gz_conn_accept(&conn, lfd, secp, key, rnd, &lim, gz_conn_any_member, NULL);
        if (e) {
            report("accept", e);
            failures++;
            continue;
        }
        gz_conn_remote_static(&conn, pub);
        printf("peer ");
        hex_print(pub, 33);
        printf("\n");
        fflush(stdout);
        while ((e = gz_conn_recv(&conn, msg, sizeof msg, &len)) == GZ_CONN_OK) {
            r = read_ping(msg, len, &kind, &seq);
            if (r < 0 || (r == 1 && kind != KIND_PING)) { e = GZ_CONN_ERR_CRYPTO; break; }
            if (r == 0) continue;
            olen = make_ping(out, sizeof out, KIND_PONG, seq);
            if ((e = gz_conn_send(&conn, out, olen))) break;
            pings++;
        }
        gz_conn_close(&conn);
        if (e != GZ_CONN_ERR_CLOSED || pings == 0) {
            fprintf(stderr, "gz-net: connection ended: %s\n", gz_conn_err_name(e));
            failures++;
        }
        printf("done %d\n", pings);
        fflush(stdout);
    }
    return failures ? 1 : 0;
}

static int cmd_connect(const char *host, uint16_t port, const uint8_t key[32], const uint8_t pin[33],
                       const secp256k1_context *secp, gz_random_port_t rnd, int count)
{
    uint8_t msg[GZ_MSG_MAX], out[64];
    size_t len, olen;
    int i, r, kind;
    uint64_t seq;
    gz_conn_err_t e = gz_conn_connect(&conn, host, port, secp, key, pin, rnd, NULL);
    if (e) {
        report("connect", e);
        return 1;
    }
    for (i = 0; i < count; i++) {
        olen = make_ping(out, sizeof out, KIND_PING, (uint64_t)i + 1000);
        if ((e = gz_conn_send(&conn, out, olen))) break;
        if ((e = gz_conn_recv(&conn, msg, sizeof msg, &len))) break;
        r = read_ping(msg, len, &kind, &seq);
        if (r != 1 || kind != KIND_PONG || seq != (uint64_t)i + 1000) {
            fprintf(stderr, "gz-net: bad pong\n");
            gz_conn_close(&conn);
            return 1;
        }
    }
    gz_conn_close(&conn);
    if (e) {
        fprintf(stderr, "gz-net: %s\n", gz_conn_err_name(e));
        return 1;
    }
    printf("ok %d\n", count);
    return 0;
}

/* ------------------------------------------------- lobby connections ---- */

/* The test lobby's scope: any nonzero 32 bytes will do for the transport. */
static const uint8_t TEST_SCOPE[32] = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};

/* lobby_status for an unknown lobby: lobby state 0, seat state 0, version 0,
 * no seats (messages.md 6.1 and 6.7). */
static const uint8_t UNKNOWN_STATUS[] = {2, 1, 0, 4, 1, 0, 6, 4, 0, 0, 0, 0, 8, 2, 0, 0, 10, 2, 0, 0};

typedef struct {
    long ping_ms, pong_ms, seconds;
} lobby_opts_t;

static gz_peers_t *lobby_peers(const uint8_t key[32], const secp256k1_context *secp, gz_random_port_t rnd,
                               const lobby_opts_t *o)
{
    gz_peers_config_t cfg;
    gz_peers_default_config(&cfg);
    cfg.secp = secp;
    memcpy(cfg.static_key, key, 32);
    cfg.random = rnd;
    cfg.is_member = gz_conn_any_member; /* slice 1's host (transport.md rule 13) */
    if (o->ping_ms > 0) cfg.ping_ms = (int)o->ping_ms;
    if (o->pong_ms > 0) cfg.pong_ms = (int)o->pong_ms;
    /* Only for pings faster than messages.md's 15 s (the test settings): a
     * peer with the same settings pings about once per ping_ms, so allow
     * three times that in each pong_ms window on top of the usual 10. */
    if (cfg.ping_ms < 15000) cfg.max_pings = (unsigned)(10 + 3 * cfg.pong_ms / cfg.ping_ms);
    return gz_peers_new(&cfg);
}

static void print_close(const gz_peer_event_t *ev)
{
    printf("closed ");
    if (ev->have_node_id) hex_print(ev->node_id, 33);
    else printf("-");
    printf(" %s%s%s\n", gz_peer_why_name(ev->why), ev->text[0] ? ": " : "", ev->text);
    fflush(stdout);
}

static int cmd_serve(const char *host, uint16_t port, const uint8_t key[32], const secp256k1_context *secp,
                     gz_random_port_t rnd, int accepts, const lobby_opts_t *o)
{
    uint8_t pub[33];
    secp256k1_pubkey pk;
    size_t n = 33;
    uint16_t bound;
    int closed = 0, failures = 0, hellos = 0;
    gz_peers_stats_t st;
    gz_peer_event_t ev;
    gz_peers_err_t pe;
    int64_t deadline;
    struct timespec ts;
    gz_peers_t *p = lobby_peers(key, secp, rnd, o);
    if (!p || !secp256k1_ec_pubkey_create(secp, &pk, key) ||
        !secp256k1_ec_pubkey_serialize(secp, pub, &n, &pk, SECP256K1_EC_COMPRESSED)) {
        fprintf(stderr, "gz-net: invalid key or options\n");
        gz_peers_free(p);
        return 1;
    }
    if ((pe = gz_peers_listen(p, host, port, &bound))) {
        fprintf(stderr, "gz-net: cannot listen on %s:%u: %s\n", host, (unsigned)port, gz_peers_err_name(pe));
        gz_peers_free(p);
        return 1;
    }
    printf("listening %u ", (unsigned)bound);
    hex_print(pub, 33);
    printf("\n");
    fflush(stdout);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    deadline = (int64_t)ts.tv_sec + o->seconds;
    while (closed < accepts) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        if ((int64_t)ts.tv_sec >= deadline) {
            printf("timeout\n");
            failures++;
            break;
        }
        if (!gz_peers_poll(p, 1000, &ev)) continue;
        switch (ev.type) {
        case GZ_PEER_EV_CONNECTED:
            printf("peer ");
            hex_print(ev.node_id, 33);
            printf("\n");
            break;
        case GZ_PEER_EV_MESSAGE:
            if (ev.kind == GZ_ENV_KIND_HELLO) {
                static const uint8_t zero[32];
                hellos++;
                printf("hello\n");
                /* A status needs a lobby's scope; a scope-zero hello gets the test lobby's. */
                if (gz_peers_send(p, ev.conn, GZ_ENV_KIND_LOBBY_STATUS,
                                  memcmp(ev.scope, zero, 32) ? ev.scope : TEST_SCOPE, UNKNOWN_STATUS,
                                  sizeof UNKNOWN_STATUS) != GZ_PEERS_OK)
                    failures++;
            }
            break;
        case GZ_PEER_EV_WARNING:
            printf("warning %s\n", ev.text);
            break;
        case GZ_PEER_EV_CLOSED:
            print_close(&ev);
            closed++;
            /* A member ending its stay closes the connection: that is the
             * only good ending. */
            if (ev.why != GZ_PEER_WHY_LOST || !ev.was_connected) failures++;
            break;
        }
        fflush(stdout);
    }
    gz_peers_stats(p, &st);
    printf("done pings_sent=%llu pongs_received=%llu pings_received=%llu pongs_sent=%llu hellos=%d\n",
           (unsigned long long)st.pings_sent, (unsigned long long)st.pongs_received,
           (unsigned long long)st.pings_received, (unsigned long long)st.pongs_sent, hellos);
    gz_peers_free(p);
    return failures || hellos < accepts ? 1 : 0;
}

static int cmd_join(const char *host, uint16_t port, const uint8_t key[32], const uint8_t pin[33],
                    const secp256k1_context *secp, gz_random_port_t rnd, const lobby_opts_t *o)
{
    uint64_t id;
    int connected = 0, status = 0, rc = 1;
    gz_peers_stats_t st;
    gz_peer_event_t ev;
    gz_peers_err_t pe;
    struct timespec ts;
    int64_t end_ms = -1, now;
    gz_peers_t *p = lobby_peers(key, secp, rnd, o);
    if (!p) {
        fprintf(stderr, "gz-net: invalid options\n");
        return 1;
    }
    if ((pe = gz_peers_connect(p, host, port, pin, NULL, &id))) {
        fprintf(stderr, "gz-net: connect: %s\n", gz_peers_err_name(pe));
        gz_peers_free(p);
        return 1;
    }
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        now = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        if (end_ms >= 0 && now >= end_ms) break;
        if (!gz_peers_poll(p, end_ms < 0 ? 1000 : (int)(end_ms - now), &ev)) continue;
        if (ev.type == GZ_PEER_EV_CONNECTED) {
            connected = 1;
            printf("connected ");
            hex_print(ev.node_id, 33);
            printf("\n");
            if (gz_peers_send(p, id, GZ_ENV_KIND_HELLO, TEST_SCOPE, NULL, 0)) break;
            end_ms = now + o->seconds * 1000;
        } else if (ev.type == GZ_PEER_EV_MESSAGE && ev.kind == GZ_ENV_KIND_LOBBY_STATUS) {
            status = 1;
            printf("status\n");
        } else if (ev.type == GZ_PEER_EV_WARNING) {
            printf("warning %s\n", ev.text);
        } else if (ev.type == GZ_PEER_EV_CLOSED) {
            print_close(&ev);
            gz_peers_free(p);
            return 1;
        }
        fflush(stdout);
    }
    gz_peers_stats(p, &st);
    /* Held for the whole stay, answered by the host, and, if the stay was
     * long enough for pings, kept alive by them. */
    if (connected && status && (o->seconds * 1000 < 3 * o->ping_ms || st.pongs_received > 0)) {
        printf("ok pings=%llu pongs=%llu\n", (unsigned long long)st.pings_sent,
               (unsigned long long)st.pongs_received);
        rc = 0;
    } else {
        printf("fail connected=%d status=%d pongs=%llu\n", connected, status, (unsigned long long)st.pongs_received);
    }
    gz_peers_free(p);
    return rc;
}

static int usage(void)
{
    fprintf(stderr, "usage: gz-net listen [--host H] [--port P] [--key-file F] [--accept N]\n"
                    "       gz-net connect --port P --pin HEX [--host H] [--key-file F] [--count N]\n"
                    "       gz-net serve [--host H] [--port P] [--key-file F] [--accept N]\n"
                    "                    [--ping-ms N] [--pong-ms N] [--seconds N]\n"
                    "       gz-net join --port P --pin HEX [--host H] [--key-file F]\n"
                    "                   [--ping-ms N] [--pong-ms N] [--seconds N]\n");
    return 2;
}

int main(int argc, char **argv)
{
    const char *host = "127.0.0.1", *key_file = NULL, *pin_hex = NULL;
    long port = -1, number = 1;
    lobby_opts_t lo = {15000, 30000, -1};
    uint8_t key[32], pin[33], seed[32];
    gz_random_port_t rnd = {os_fill, NULL};
    secp256k1_context *secp;
    int i, rc;
    if (argc < 2) return usage();
    for (i = 2; i + 1 < argc; i += 2) {
        int ok = 1;
        if (!strcmp(argv[i], "--host")) host = argv[i + 1];
        else if (!strcmp(argv[i], "--port")) ok = parse_num(argv[i + 1], 0, 65535, &port);
        else if (!strcmp(argv[i], "--key-file")) key_file = argv[i + 1];
        else if (!strcmp(argv[i], "--pin")) pin_hex = argv[i + 1];
        else if (!strcmp(argv[i], "--accept") || !strcmp(argv[i], "--count")) ok = parse_num(argv[i + 1], 1, 100000, &number);
        else if (!strcmp(argv[i], "--ping-ms")) ok = parse_num(argv[i + 1], 1, 3600000, &lo.ping_ms);
        else if (!strcmp(argv[i], "--pong-ms")) ok = parse_num(argv[i + 1], 1, 3600000, &lo.pong_ms);
        else if (!strcmp(argv[i], "--seconds")) ok = parse_num(argv[i + 1], 0, 1000000, &lo.seconds);
        else ok = 0;
        if (!ok) return usage();
    }
    if (i != argc) return usage();
    /* SIGPIPE is left at its default: the connection layer never raises it. */
    if (!load_key(key_file, key)) {
        fprintf(stderr, "gz-net: cannot read key file\n");
        return 1;
    }
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    os_fill(NULL, seed, sizeof seed);
    rc = secp && secp256k1_context_randomize(secp, seed);
    OPENSSL_cleanse(seed, sizeof seed);
    if (!rc) return 1;
    if (!strcmp(argv[1], "listen")) {
        rc = cmd_listen(host, (uint16_t)(port < 0 ? 0 : port), key, secp, rnd, (int)number);
    } else if (!strcmp(argv[1], "connect")) {
        if (port < 1 || !pin_hex || !hex_decode(pin_hex, strlen(pin_hex), pin, 33))
            rc = usage();
        else
            rc = cmd_connect(host, (uint16_t)port, key, pin, secp, rnd, (int)number);
    } else if (!strcmp(argv[1], "serve")) {
        if (lo.seconds < 0) lo.seconds = 3600;
        rc = cmd_serve(host, (uint16_t)(port < 0 ? 0 : port), key, secp, rnd, (int)number, &lo);
    } else if (!strcmp(argv[1], "join")) {
        if (lo.seconds < 0) lo.seconds = 10;
        if (port < 1 || !pin_hex || !hex_decode(pin_hex, strlen(pin_hex), pin, 33))
            rc = usage();
        else
            rc = cmd_join(host, (uint16_t)port, key, pin, secp, rnd, &lo);
    } else {
        rc = usage();
    }
    OPENSSL_cleanse(key, sizeof key);
    secp256k1_context_destroy(secp);
    return rc;
}
