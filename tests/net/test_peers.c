/* Lobby connections (ports/net/peers.c): the host and members in one process
 * over loopback, and hostile members in forked children that speak through
 * the blocking connection layer. Timings are generous so the test also
 * passes under valgrind. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../check.h"
#include "peers.h"
#include "lnmsg.h"
#include "frame.h"

static secp256k1_context *secp;
static uint8_t HOST_KEY[32], MEM_KEY[32], MEM_KEY2[32], CHILD_KEY[32];
static uint8_t HOST_PUB[33], MEM_PUB[33], MEM_PUB2[33], CHILD_PUB[33];
static uint8_t SCOPE[32];

static void counter_fill(void *ctx, uint8_t *out, size_t len)
{
    static uint8_t n = 1;
    (void)ctx;
    memset(out, 0x40, len);
    out[len - 1] = n++;
}
static const gz_random_port_t RNG = {counter_fill, NULL};

static void pub(const uint8_t k[32], uint8_t out[33])
{
    secp256k1_pubkey pk;
    size_t n = 33;
    CHECK(secp256k1_ec_pubkey_create(secp, &pk, k) && secp256k1_ec_pubkey_serialize(secp, out, &n, &pk, SECP256K1_EC_COMPRESSED));
}

static int64_t ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int refuse_all(const uint8_t key[33], void *ctx)
{
    (void)key;
    (void)ctx;
    return 0;
}

static gz_peers_t *mk(const uint8_t key[32], int ping, int pong, gz_conn_member_fn is_member,
                      void (*tweak)(gz_peers_config_t *))
{
    gz_peers_config_t c;
    gz_peers_default_config(&c);
    c.secp = secp;
    memcpy(c.static_key, key, 32);
    c.random = RNG;
    c.is_member = is_member ? is_member : gz_conn_any_member;
    c.handshake_ms = 4000;
    c.ping_ms = ping;
    c.pong_ms = pong;
    if (tweak) tweak(&c);
    return gz_peers_new(&c);
}

/* ------------------------------------------------ an event log per side */

#define LOG 256
typedef struct {
    gz_peers_t *p;
    struct {
        gz_peer_event_t ev;
        uint8_t *body;
        int used;
    } e[LOG];
    int n;
} side_t;

static side_t S[2]; /* 0: host, 1: member */

static void reset_log(void)
{
    int s, i;
    for (s = 0; s < 2; s++) {
        for (i = 0; i < S[s].n; i++) free(S[s].e[i].body);
        S[s].n = 0;
    }
}

static void pump(int ms_total)
{
    int64_t end = ms() + ms_total;
    do {
        int s;
        for (s = 0; s < 2; s++) {
            gz_peer_event_t ev;
            if (!S[s].p) continue;
            while (gz_peers_poll(S[s].p, 1, &ev)) {
                int i = S[s].n < LOG ? S[s].n++ : LOG - 1;
                S[s].e[i].ev = ev;
                S[s].e[i].used = 0;
                S[s].e[i].body = NULL;
                if (ev.records_len) {
                    S[s].e[i].body = malloc(ev.records_len);
                    memcpy(S[s].e[i].body, ev.records, ev.records_len);
                }
                S[s].e[i].ev.records = S[s].e[i].body;
            }
        }
    } while (ms() < end);
}

/* The first unused event of a type on a side, waiting up to ms. */
static gz_peer_event_t *expect(int side, gz_peer_ev_type_t type, int wait_ms)
{
    int64_t end = ms() + wait_ms;
    for (;;) {
        int i;
        for (i = 0; i < S[side].n; i++) {
            if (!S[side].e[i].used && S[side].e[i].ev.type == type) {
                S[side].e[i].used = 1;
                return &S[side].e[i].ev;
            }
        }
        if (ms() >= end) return NULL;
        pump(5);
    }
}

/* 1 if no event of the type comes in the time. */
static int quiet(int side, gz_peer_ev_type_t type, int wait_ms)
{
    gz_peer_event_t *e = expect(side, type, wait_ms);
    if (e) e->type = 0;
    return e == NULL;
}

static void free_sides(void)
{
    gz_peers_free(S[0].p);
    gz_peers_free(S[1].p);
    S[0].p = S[1].p = NULL;
    reset_log();
}

/* A host listening, and a member connected to it. Returns the host's
 * connection id; *mconn gets the member's. */
static uint64_t pair(int ping, int pong, void (*tweak)(gz_peers_config_t *), uint64_t *mconn, uint16_t *port_out)
{
    uint16_t port;
    gz_peer_event_t *e;
    S[0].p = mk(HOST_KEY, ping, pong, NULL, tweak);
    S[1].p = mk(MEM_KEY, ping, pong, NULL, tweak);
    CHECK(S[0].p && S[1].p);
    CHECK(gz_peers_listen(S[0].p, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, NULL, mconn) == GZ_PEERS_OK);
    e = expect(1, GZ_PEER_EV_CONNECTED, 5000);
    CHECK(e && e->conn == *mconn && e->outbound == 1 && e->have_node_id && memcmp(e->node_id, HOST_PUB, 33) == 0);
    e = expect(0, GZ_PEER_EV_CONNECTED, 5000);
    CHECK(e && e->outbound == 0 && e->have_node_id && memcmp(e->node_id, MEM_PUB, 33) == 0);
    if (port_out) *port_out = port;
    return e ? e->conn : 0;
}

/* round_all_nonces (68) with one item of `signers` signers: a valid body of
 * about 130 bytes per signer. */
static size_t nonces_body(size_t signers, uint8_t *out, size_t cap)
{
    gz_tlv_writer_t w;
    static uint8_t items[1 << 20], z[32];
    size_t il = 6 + signers * 130;
    memset(items, 7, il);
    memset(items, 0, 6);
    items[4] = (uint8_t)(signers >> 8);
    items[5] = (uint8_t)signers;
    gz_tlv_writer_init(&w, out, cap);
    gz_tlv_put(&w, 2, z, 32);
    gz_tlv_put(&w, 4, z, 1);
    gz_tlv_put(&w, 6, items, il);
    CHECK(w.err == GZ_FRAME_OK);
    return w.len;
}

static const uint8_t STATUS[] = {2, 1, 0, 4, 1, 0, 6, 4, 0, 0, 0, 0, 8, 2, 0, 0, 10, 2, 0, 0};
static uint8_t big[1 << 20];

/* ------------------------------------------------ honest connections */

static void test_basic(void)
{
    uint64_t hc, mc, mc2;
    uint16_t port;
    gz_peer_event_t *e;
    size_t n;
    static const uint8_t zero[32];
    hc = pair(15000, 30000, NULL, &mc, &port);
    /* hello from the member, with its node id. */
    CHECK(gz_peers_send(S[1].p, mc, GZ_ENV_KIND_HELLO, zero, NULL, 0) == GZ_PEERS_OK);
    e = expect(0, GZ_PEER_EV_MESSAGE, 5000);
    CHECK(e && e->kind == 16 && e->conn == hc && e->records_len == 0 && memcmp(e->scope, zero, 32) == 0 &&
          memcmp(e->node_id, MEM_PUB, 33) == 0);
    /* lobby_status from the host. */
    CHECK(gz_peers_send(S[0].p, hc, GZ_ENV_KIND_LOBBY_STATUS, SCOPE, STATUS, sizeof STATUS) == GZ_PEERS_OK);
    e = expect(1, GZ_PEER_EV_MESSAGE, 5000);
    CHECK(e && e->kind == 28 && e->records_len == sizeof STATUS && memcmp(e->records, STATUS, sizeof STATUS) == 0 &&
          memcmp(e->scope, SCOPE, 32) == 0 && memcmp(e->node_id, HOST_PUB, 33) == 0);
    /* A large message from the host arrives whole, once: split into parts and
     * put back together (sections 5 and 12, test 9). */
    n = nonces_body(1500, big, sizeof big);
    CHECK(n > 3 * 65000 && n < 4 * 65000);
    CHECK(gz_peers_send(S[0].p, hc, GZ_ENV_KIND_ROUND_ALL_NONCES, SCOPE, big, n) == GZ_PEERS_OK);
    e = expect(1, GZ_PEER_EV_MESSAGE, 30000);
    CHECK(e && e->kind == 68 && e->records_len == n && memcmp(e->records, big, n) == 0);
    /* Released at once after delivery (F6), and the decrypted bytes wiped. */
    {
        gz_peers_stats_t st;
        gz_peers_stats(S[1].p, &st);
        CHECK(st.reassembly_bytes == 0);
        CHECK(gz_peers_test_plain_clear(S[1].p) && gz_peers_test_plain_clear(S[0].p));
    }
    CHECK(quiet(1, GZ_PEER_EV_MESSAGE, 200));
    /* The largest, 1 MiB, also arrives; one byte more is refused. */
    n = nonces_body((GZ_ENV_MAX_WHOLE - 200) / 130, big, sizeof big);
    CHECK(gz_peers_send(S[0].p, hc, GZ_ENV_KIND_ROUND_ALL_NONCES, SCOPE, big, n) == GZ_PEERS_OK);
    e = expect(1, GZ_PEER_EV_MESSAGE, 60000);
    CHECK(e && e->records_len == n && memcmp(e->records, big, n) == 0);
    CHECK(gz_peers_send(S[0].p, hc, 68, SCOPE, big, GZ_ENV_MAX_WHOLE + 1) == GZ_PEERS_ERR_TOO_BIG);
    /* The send queue holds at most 4 MiB: without polling nothing is
     * written, so the fourth 1 MiB message does not fit. The three that did
     * arrive whole. */
    CHECK(gz_peers_send(S[0].p, hc, GZ_ENV_KIND_ROUND_ALL_NONCES, SCOPE, big, n) == GZ_PEERS_OK);
    CHECK(gz_peers_send(S[0].p, hc, GZ_ENV_KIND_ROUND_ALL_NONCES, SCOPE, big, n) == GZ_PEERS_OK);
    CHECK(gz_peers_send(S[0].p, hc, GZ_ENV_KIND_ROUND_ALL_NONCES, SCOPE, big, n) == GZ_PEERS_OK);
    CHECK(gz_peers_send(S[0].p, hc, GZ_ENV_KIND_ROUND_ALL_NONCES, SCOPE, big, n) == GZ_PEERS_ERR_FULL);
    CHECK(gz_peers_send(S[0].p, hc, GZ_ENV_KIND_LOBBY_STATUS, SCOPE, STATUS, sizeof STATUS) == GZ_PEERS_OK);
    {
        int k;
        for (k = 0; k < 3; k++) {
            e = expect(1, GZ_PEER_EV_MESSAGE, 60000);
            CHECK(e && e->kind == 68 && e->records_len == n);
        }
        e = expect(1, GZ_PEER_EV_MESSAGE, 10000);
        CHECK(e && e->kind == 28);
    }
    /* A member sends no parts. */
    CHECK(gz_peers_send(S[1].p, mc, GZ_ENV_KIND_ROUND_NONCES, SCOPE, big, GZ_ENV_MAX_RECORDS + 1) == GZ_PEERS_ERR_TOO_BIG);
    /* Bad calls. */
    CHECK(gz_peers_send(S[1].p, mc + 100, 16, zero, NULL, 0) == GZ_PEERS_ERR_NO_CONN);
    CHECK(gz_peers_send(S[0].p, hc, GZ_ENV_KIND_PART, SCOPE, big, 10) == GZ_PEERS_ERR_ARGS);
    CHECK(gz_peers_send_raw(S[1].p, mc, big, 1) == GZ_PEERS_ERR_TOO_BIG);
    CHECK(gz_peers_close(S[1].p, mc + 100) == GZ_PEERS_ERR_NO_CONN);
    CHECK(gz_peers_refuse(S[1].p, mc + 100, "x") == GZ_PEERS_ERR_NO_CONN);
    CHECK(gz_peers_connect(S[1].p, "localhost", port, HOST_PUB, NULL, &mc2) == GZ_PEERS_ERR_ADDRESS);
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, NULL, NULL, &mc2) == GZ_PEERS_ERR_ARGS);
    /* A second connection with another key (a fresh key per connection,
     * messages.md section 2): the host sees the other node id. Before the
     * peer's init, nothing can be sent. */
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, MEM_KEY2, &mc2) == GZ_PEERS_OK);
    CHECK(gz_peers_send(S[1].p, mc2, 16, zero, NULL, 0) == GZ_PEERS_ERR_NOT_READY);
    e = expect(0, GZ_PEER_EV_CONNECTED, 5000);
    CHECK(e && memcmp(e->node_id, MEM_PUB2, 33) == 0 && e->conn != hc);
    e = expect(1, GZ_PEER_EV_CONNECTED, 5000);
    CHECK(e && e->conn == mc2);
    /* The member closes the first one: the host learns it was lost, and from
     * whom. No event on the side that closed. */
    CHECK(gz_peers_close(S[1].p, mc) == GZ_PEERS_OK);
    e = expect(0, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->conn == hc && e->why == GZ_PEER_WHY_LOST && e->was_connected && memcmp(e->node_id, MEM_PUB, 33) == 0);
    CHECK(quiet(1, GZ_PEER_EV_CLOSED, 200));
    CHECK(gz_peers_send(S[1].p, mc, 16, zero, NULL, 0) == GZ_PEERS_ERR_NO_CONN);
    {
        gz_peers_stats_t st;
        gz_peers_stats(S[0].p, &st);
        CHECK(st.open == 1);
    }
    free_sides();
}

/* An idle connection stays open for many times the old 30 s idle cut (here
 * scaled down: recv_ms 400, idle 3 s), kept alive by pings. */
/* The peer pings at most once per 50 ms, so at most 16 in one 800 ms
 * window: 25 is never reached in a window, but is well passed in 4 s if the
 * window never restarts. */
static void short_recv(gz_peers_config_t *c)
{
    c->recv_ms = 400;
    c->max_pings = 25;
}

static void test_keepalive(void)
{
    uint64_t hc, mc;
    gz_peers_stats_t hs, ms_;
    static const uint8_t zero[32];
    gz_peer_event_t *e;
    hc = pair(50, 800, short_recv, &mc, NULL);
    pump(4000);
    CHECK(quiet(0, GZ_PEER_EV_CLOSED, 0) && quiet(1, GZ_PEER_EV_CLOSED, 0));
    gz_peers_stats(S[0].p, &hs);
    gz_peers_stats(S[1].p, &ms_);
    CHECK(hs.pings_sent + ms_.pings_sent >= 20);
    CHECK(hs.pongs_received == hs.pings_sent || hs.pongs_received + 1 == hs.pings_sent);
    CHECK(ms_.pongs_received == ms_.pings_sent || ms_.pongs_received + 1 == ms_.pings_sent);
    CHECK(hs.pongs_sent == hs.pings_received && ms_.pongs_sent == ms_.pings_received);
    CHECK(hs.pings_received == ms_.pings_sent || hs.pings_received + 1 == ms_.pings_sent);
    /* Still usable. */
    CHECK(gz_peers_send(S[1].p, mc, GZ_ENV_KIND_HELLO, zero, NULL, 0) == GZ_PEERS_OK);
    e = expect(0, GZ_PEER_EV_MESSAGE, 5000);
    CHECK(e && e->conn == hc && e->kind == 16);
    free_sides();
}

/* ------------------------------------------------ hostile members */

enum { CH_SILENT, CH_BAD_PONG, CH_TRICKLE, CH_PING_FIRST, CH_NO_READ, CH_SHORT, CH_EVEN_FEATURE, CH_JUNK };

/* Reads until the host closes; 5 if a warning came (none may come before
 * our init has been accepted, BOLT 1), else 0. */
static void no_warning_then_exit(gz_conn_t *c, uint8_t *m, size_t cap)
{
    size_t n;
    while (gz_conn_recv(c, m, cap, &n) == GZ_CONN_OK)
        if (n >= 2 && m[0] == 0 && m[1] == GZ_LN_WARNING) _exit(5);
    _exit(0);
}

static pid_t child(uint16_t port, int how)
{
    pid_t pid = fork();
    gz_conn_t *c;
    uint8_t m[70000];
    size_t n;
    if (pid) return pid;
    alarm(30);
    c = calloc(1, sizeof *c);
    if (!c || gz_conn_connect(c, "127.0.0.1", port, secp, CHILD_KEY, HOST_PUB, RNG, NULL)) _exit(1);
    if (how == CH_PING_FIRST) {
        gz_ln_ping_write(1, 0, m, sizeof m, &n);
        gz_conn_send(c, m, n);
        no_warning_then_exit(c, m, sizeof m);
    }
    if (how == CH_EVEN_FEATURE) {
        /* init with feature bit 0 (even, unknown) and networks = [signet] */
        static const uint8_t init_even[] = {0, 16, 0, 0, 0, 1, 1, 1, 32};
        memcpy(m, init_even, sizeof init_even);
        memcpy(m + sizeof init_even, GZ_LN_CHAIN_SIGNET, 32);
        gz_conn_send(c, m, sizeof init_even + 32);
        no_warning_then_exit(c, m, sizeof m);
    }
    gz_ln_init_write(GZ_LN_CHAIN_SIGNET, m, sizeof m, &n);
    if (gz_conn_send(c, m, n) || gz_conn_recv(c, m, sizeof m, &n) || m[1] != GZ_LN_INIT) _exit(2);
    if (how == CH_JUNK) {
        /* Never reads; after a second sends bytes the host must not read
         * while it refuses; after three seconds hangs up. */
        uint8_t junk[1000];
        memset(junk, 0x77, sizeof junk);
        sleep(1);
        if (write(c->fd, junk, sizeof junk) != (ssize_t)sizeof junk) _exit(3);
        sleep(2);
        _exit(0);
    }
    if (how == CH_SILENT || how == CH_NO_READ) {
        sleep(20);
        _exit(0);
    }
    if (how == CH_SHORT) {
        /* A one-byte message: shorter than its type. */
        m[0] = 0x80;
        gz_conn_send(c, m, 1);
        sleep(20);
        _exit(0);
    }
    if (how == CH_TRICKLE) {
        uint8_t ct[100];
        gz_ln_ping_write(1, 0, m, sizeof m, &n);
        gz_noise_encrypt(&c->noise, m, n, ct, sizeof ct, &n);
        if (write(c->fd, ct, 10) != 10) _exit(3);
        sleep(20);
        _exit(0);
    }
    /* CH_BAD_PONG: answer every ping with one byte too many. */
    while (gz_conn_recv(c, m, sizeof m, &n) == GZ_CONN_OK) {
        uint16_t want;
        if (gz_ln_ping_read(m, n, &want) == GZ_LN_OK) {
            gz_ln_pong_write((uint16_t)(want + 1), m, sizeof m, &n);
            gz_conn_send(c, m, n);
        }
    }
    _exit(0);
}

static void reap(pid_t pid)
{
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

static void ping_fast(gz_peers_config_t *c) { c->recv_ms = 300; c->send_ms = 400; }

static void hostile(int how, gz_peer_why_t want, const char *text, int ping, int pong)
{
    uint16_t port;
    pid_t pid;
    gz_peer_event_t *e;
    S[0].p = mk(HOST_KEY, ping, pong, NULL, ping_fast);
    CHECK(gz_peers_listen(S[0].p, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    pid = child(port, how);
    if (how != CH_PING_FIRST && how != CH_EVEN_FEATURE) {
        e = expect(0, GZ_PEER_EV_CONNECTED, 5000);
        CHECK(e && memcmp(e->node_id, CHILD_PUB, 33) == 0);
        if (how == CH_NO_READ && e) {
            /* Fill the queue until it is full; the child never reads, so the
             * send deadline passes. */
            gz_peers_err_t pe = GZ_PEERS_OK;
            int i;
            for (i = 0; i < 64; i++) {
                pe = gz_peers_send(S[0].p, e->conn, 68, SCOPE, big, GZ_ENV_MAX_WHOLE);
                if (pe != GZ_PEERS_OK) break;
                pump(5);
            }
            /* Under valgrind the send deadline may pass before the queue is
             * full; the queue limit itself is tested in test_basic. */
            CHECK(pe == GZ_PEERS_ERR_FULL || pe == GZ_PEERS_ERR_NO_CONN);
        }
    }
    e = expect(0, GZ_PEER_EV_CLOSED, 8000);
    CHECK(e && e->why == want);
    if (e && e->why != want) printf("  got %s (%s), wanted %s\n", gz_peer_why_name(e->why), e->text, gz_peer_why_name(want));
    if (e && text) CHECK(strcmp(e->text, text) == 0);
    if (e) CHECK(e->have_node_id && memcmp(e->node_id, CHILD_PUB, 33) == 0);
    if (how == CH_PING_FIRST || how == CH_EVEN_FEATURE) {
        int st = -1, k;
        for (k = 0; k < 500 && waitpid(pid, &st, WNOHANG) == 0; k++) pump(10);
        CHECK(k < 500 && WIFEXITED(st) && WEXITSTATUS(st) == 0); /* no warning before init (F3) */
        free_sides();
        return;
    }
    reap(pid);
    free_sides();
}

static void test_hostile(void)
{
    /* No pong: closed after pong_ms. */
    hostile(CH_SILENT, GZ_PEER_WHY_TIMEOUT_PONG, "no pong", 100, 500);
    /* A pong of the wrong length. */
    hostile(CH_BAD_PONG, GZ_PEER_WHY_PROTOCOL, "pong of the wrong length", 100, 2000);
    /* A message started and never finished. */
    hostile(CH_TRICKLE, GZ_PEER_WHY_TIMEOUT_MESSAGE, NULL, 20000, 30000);
    /* Anything before init. */
    hostile(CH_PING_FIRST, GZ_PEER_WHY_INIT, "first message is not init", 20000, 30000);
    /* init with an unknown even feature bit: closed, no warning. */
    hostile(CH_EVEN_FEATURE, GZ_PEER_WHY_INIT, "init requires an unknown feature", 20000, 30000);
    /* A message shorter than its 2-byte type. */
    hostile(CH_SHORT, GZ_PEER_WHY_PROTOCOL, "message shorter than its type", 20000, 30000);
    /* A member that never reads. */
    hostile(CH_NO_READ, GZ_PEER_WHY_TIMEOUT_SEND, NULL, 20000, 30000);
}

/* One connection per case: the member sends something, the host reacts. */
static void raw_case(const char *hex, gz_peer_why_t want, const char *text)
{
    uint64_t hc, mc;
    uint8_t m[400];
    size_t n = 0;
    gz_peer_event_t *e;
    const char *h = hex;
    while (h[0] && h[1]) {
        unsigned v;
        sscanf(h, "%2x", &v);
        m[n++] = (uint8_t)v;
        h += 2;
    }
    hc = pair(20000, 30000, NULL, &mc, NULL);
    CHECK(gz_peers_send_raw(S[1].p, mc, m, n) == GZ_PEERS_OK);
    e = expect(0, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->conn == hc && e->why == want && e->was_connected);
    if (e && e->why != want) printf("  %s: got %s (%s)\n", hex, gz_peer_why_name(e->why), e->text);
    if (e && text) CHECK(strcmp(e->text, text) == 0);
    if (want == GZ_PEER_WHY_PROTOCOL) {
        /* The member was told why, then the host closed. */
        e = expect(1, GZ_PEER_EV_WARNING, 5000);
        CHECK(e && text && strcmp(e->text, text) == 0);
        e = expect(1, GZ_PEER_EV_CLOSED, 5000);
        CHECK(e && e->why == GZ_PEER_WHY_LOST && e->was_connected);
    }
    free_sides();
}

static void test_messages(void)
{
    uint64_t hc, mc;
    gz_peer_event_t *e;
    uint8_t m[200];
    size_t n;
    static const uint8_t zero[32];
    gz_peers_stats_t st;
    /* Refused by the host, with a warning (messages.md section 1). */
    raw_case("8020", GZ_PEER_WHY_PROTOCOL, "unknown even message");
    raw_case("0010000000000120f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000", GZ_PEER_WHY_PROTOCOL,
             "second init");
    raw_case("001200", GZ_PEER_WHY_PROTOCOL, "malformed ping");
    raw_case("0013000200", GZ_PEER_WHY_PROTOCOL, "malformed pong");
    raw_case("0001" "00", GZ_PEER_WHY_PROTOCOL, "malformed warning");
    /* lobby_status from a member: a kind in the wrong direction. */
    raw_case("ce37677a6601001c" "75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2"
             "020100040100060400000000080200000a020000", GZ_PEER_WHY_PROTOCOL, "kind in the wrong direction");
    /* A part from a member (members send no parts). */
    raw_case("ce37677a66010002" "75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2", GZ_PEER_WHY_PROTOCOL,
             "kind in the wrong direction");
    /* An unknown even kind; a malformed record stream. */
    raw_case("ce37677a66010024" "75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2", GZ_PEER_WHY_PROTOCOL,
             "unknown even kind");
    raw_case("ce37677a66010010" "75e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a424f2" "0205", GZ_PEER_WHY_PROTOCOL,
             "record past the end");
    raw_case("ce37677a6601", GZ_PEER_WHY_PROTOCOL, "factory message too short");
    /* A BOLT 1 error closes at once. */
    raw_case("0011" "0000000000000000000000000000000000000000000000000000000000000000" "0004" "6f6f7073",
             GZ_PEER_WHY_PEER_ERROR, "oops");

    /* Kept: a warning, an unknown odd message, an unknown odd kind, a
     * discovery kind, and a wrong protocol tag (one warning back, however
     * many). Then hello still arrives. */
    hc = pair(20000, 30000, NULL, &mc, NULL);
    CHECK(gz_ln_alert_write(GZ_LN_WARNING, "careful", m, sizeof m, &n) == 0);
    CHECK(gz_peers_send_raw(S[1].p, mc, m, n) == GZ_PEERS_OK);
    e = expect(0, GZ_PEER_EV_WARNING, 5000);
    CHECK(e && strcmp(e->text, "careful") == 0 && e->conn == hc && memcmp(e->node_id, MEM_PUB, 33) == 0);
    CHECK(gz_peers_send_raw(S[1].p, mc, (const uint8_t *)"\x80\x01odd", 5) == GZ_PEERS_OK);
    CHECK(gz_peers_send(S[1].p, mc, 37, SCOPE, NULL, 0) == GZ_PEERS_OK);
    CHECK(gz_peers_send(S[1].p, mc, 130, SCOPE, (const uint8_t *)"\xfd", 1) == GZ_PEERS_OK);
    memset(m, 0, 40);
    m[0] = 0xce; m[1] = 0x37; m[2] = 0x67; m[3] = 0x7a; m[4] = 0x66; m[5] = 0x02; m[7] = 16;
    CHECK(gz_peers_send_raw(S[1].p, mc, m, 40) == GZ_PEERS_OK);
    CHECK(gz_peers_send_raw(S[1].p, mc, m, 40) == GZ_PEERS_OK);
    CHECK(gz_peers_send(S[1].p, mc, GZ_ENV_KIND_HELLO, zero, NULL, 0) == GZ_PEERS_OK);
    e = expect(0, GZ_PEER_EV_MESSAGE, 5000);
    CHECK(e && e->kind == 16);
    CHECK(quiet(0, GZ_PEER_EV_MESSAGE, 200));
    e = expect(1, GZ_PEER_EV_WARNING, 5000);
    CHECK(e && strcmp(e->text, "unknown factory protocol") == 0);
    CHECK(quiet(1, GZ_PEER_EV_WARNING, 300));
    /* Pings: one asking for 65,532 bytes or more is ignored; 65,531 is
     * answered; an unasked pong is harmless. */
    gz_peers_stats(S[0].p, &st);
    CHECK(gz_ln_ping_write(65532, 0, m, sizeof m, &n) == 0 && gz_peers_send_raw(S[1].p, mc, m, n) == GZ_PEERS_OK);
    CHECK(gz_ln_ping_write(65535, 0, m, sizeof m, &n) == 0 && gz_peers_send_raw(S[1].p, mc, m, n) == GZ_PEERS_OK);
    CHECK(gz_ln_ping_write(65531, 0, m, sizeof m, &n) == 0 && gz_peers_send_raw(S[1].p, mc, m, n) == GZ_PEERS_OK);
    CHECK(gz_ln_pong_write(3, m, sizeof m, &n) == 0 && gz_peers_send_raw(S[1].p, mc, m, n) == GZ_PEERS_OK);
    pump(500);
    {
        gz_peers_stats_t st2;
        gz_peers_stats(S[0].p, &st2);
        CHECK(st2.pings_received == st.pings_received + 3 && st2.pongs_sent == st.pongs_sent + 1);
    }
    CHECK(quiet(0, GZ_PEER_EV_CLOSED, 0) && quiet(1, GZ_PEER_EV_CLOSED, 0));
    /* Too many pings in one window: refused. */
    {
        int i;
        for (i = 0; i < 10; i++) {
            gz_ln_ping_write(1, 0, m, sizeof m, &n);
            gz_peers_send_raw(S[1].p, mc, m, n);
        }
    }
    e = expect(0, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->why == GZ_PEER_WHY_PROTOCOL && strcmp(e->text, "too many pings") == 0);
    free_sides();

    /* The host refuses a member above the envelope (gz_peers_refuse). */
    hc = pair(20000, 30000, NULL, &mc, NULL);
    CHECK(gz_peers_refuse(S[0].p, hc, "seat limit") == GZ_PEERS_OK);
    CHECK(gz_peers_refuse(S[0].p, hc, "again") == GZ_PEERS_ERR_NO_CONN);
    CHECK(gz_peers_send(S[0].p, hc, 28, SCOPE, STATUS, sizeof STATUS) == GZ_PEERS_ERR_NO_CONN);
    e = expect(0, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->why == GZ_PEER_WHY_LOCAL && strcmp(e->text, "seat limit") == 0);
    e = expect(1, GZ_PEER_EV_WARNING, 5000);
    CHECK(e && strcmp(e->text, "seat limit") == 0);
    e = expect(1, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->why == GZ_PEER_WHY_LOST);
    free_sides();
}

/* ------------------------------------------------ failures to connect */

static void other_chain(gz_peers_config_t *c) { memset(c->chain, 0x6f, 32); }
static void short_handshake(gz_peers_config_t *c) { c->handshake_ms = 1500; }
static void two_conns(gz_peers_config_t *c) { c->max_conns = 2; }

static void test_connect_failures(void)
{
    uint16_t port;
    uint64_t mc, mc2, mc3;
    gz_peer_event_t *e;
    int fd, lfd;
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int64_t t0;

    /* Refused: nobody listens on the port. */
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(lfd, (struct sockaddr *)&a, sizeof a) == 0 && getsockname(lfd, (struct sockaddr *)&a, &al) == 0);
    close(lfd);
    S[1].p = mk(MEM_KEY, 20000, 30000, NULL, NULL);
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", ntohs(a.sin_port), HOST_PUB, NULL, &mc) == GZ_PEERS_OK);
    e = expect(1, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->conn == mc && e->why == GZ_PEER_WHY_REFUSED && !e->was_connected && e->have_node_id);
    free_sides();

    /* A listener that never answers: the member's handshake times out. */
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    al = sizeof a;
    a.sin_port = 0;
    CHECK(bind(lfd, (struct sockaddr *)&a, sizeof a) == 0 && listen(lfd, 4) == 0 &&
          getsockname(lfd, (struct sockaddr *)&a, &al) == 0);
    S[1].p = mk(MEM_KEY, 20000, 30000, NULL, short_handshake);
    t0 = ms();
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", ntohs(a.sin_port), HOST_PUB, NULL, &mc) == GZ_PEERS_OK);
    e = expect(1, GZ_PEER_EV_CLOSED, 6000);
    CHECK(e && e->why == GZ_PEER_WHY_TIMEOUT_HANDSHAKE && ms() - t0 >= 1400);
    close(lfd);
    free_sides();

    /* A wrong pin: the host does not hold that key, so act one fails its MAC
     * at the host, which closes; the member sees the connection lost. */
    S[0].p = mk(HOST_KEY, 20000, 30000, NULL, NULL);
    S[1].p = mk(MEM_KEY, 20000, 30000, NULL, NULL);
    CHECK(gz_peers_listen(S[0].p, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, MEM_PUB2, NULL, &mc) == GZ_PEERS_OK);
    e = expect(0, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->why == GZ_PEER_WHY_HANDSHAKE && e->noise_err == GZ_NOISE_ERR_MAC && !e->was_connected &&
          !e->have_node_id);
    e = expect(1, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && !e->was_connected && e->why == GZ_PEER_WHY_LOST && memcmp(e->node_id, MEM_PUB2, 33) == 0);
    free_sides();

    /* A silent connection holds only its own slot (review F2): while it sits
     * in its handshake, a member connects and is served; then the silent one
     * times out. */
    S[0].p = mk(HOST_KEY, 20000, 30000, NULL, short_handshake);
    S[1].p = mk(MEM_KEY, 20000, 30000, NULL, NULL);
    CHECK(gz_peers_listen(S[0].p, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    a.sin_port = htons(port);
    CHECK(connect(fd, (struct sockaddr *)&a, sizeof a) == 0);
    pump(100);
    t0 = ms();
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, NULL, &mc) == GZ_PEERS_OK);
    CHECK(expect(1, GZ_PEER_EV_CONNECTED, 5000) != NULL);
    CHECK(ms() - t0 < 1400);
    e = expect(0, GZ_PEER_EV_CONNECTED, 5000);
    CHECK(e && memcmp(e->node_id, MEM_PUB, 33) == 0);
    e = expect(0, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->why == GZ_PEER_WHY_TIMEOUT_HANDSHAKE && !e->have_node_id && !e->was_connected);
    close(fd);
    free_sides();

    /* Another chain in init: each side refuses the other's. */
    S[0].p = mk(HOST_KEY, 20000, 30000, NULL, NULL);
    S[1].p = mk(MEM_KEY, 20000, 30000, NULL, other_chain);
    CHECK(gz_peers_listen(S[0].p, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, NULL, &mc) == GZ_PEERS_OK);
    e = expect(0, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && !e->was_connected && (e->why == GZ_PEER_WHY_INIT || e->why == GZ_PEER_WHY_LOST));
    e = expect(1, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && !e->was_connected && (e->why == GZ_PEER_WHY_INIT || e->why == GZ_PEER_WHY_LOST));
    CHECK(quiet(0, GZ_PEER_EV_CONNECTED, 0) && quiet(1, GZ_PEER_EV_CONNECTED, 0));
    free_sides();

    /* The host's member check refuses the key. */
    S[0].p = mk(HOST_KEY, 20000, 30000, refuse_all, NULL);
    S[1].p = mk(MEM_KEY, 20000, 30000, NULL, NULL);
    CHECK(gz_peers_listen(S[0].p, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, NULL, &mc) == GZ_PEERS_OK);
    e = expect(0, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->why == GZ_PEER_WHY_NOT_MEMBER && e->have_node_id && memcmp(e->node_id, MEM_PUB, 33) == 0);
    e = expect(1, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->why == GZ_PEER_WHY_LOST && !e->was_connected);
    free_sides();

    /* At most max_conns connections: the third is closed at once. */
    S[0].p = mk(HOST_KEY, 20000, 30000, NULL, two_conns);
    S[1].p = mk(MEM_KEY, 20000, 30000, NULL, NULL);
    CHECK(gz_peers_listen(S[0].p, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, NULL, &mc) == GZ_PEERS_OK);
    CHECK(expect(1, GZ_PEER_EV_CONNECTED, 5000) != NULL);
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, MEM_KEY2, &mc2) == GZ_PEERS_OK);
    CHECK(expect(1, GZ_PEER_EV_CONNECTED, 5000) != NULL);
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, NULL, &mc3) == GZ_PEERS_OK);
    /* With every slot taken by members without seats, the newcomer evicts
     * the oldest (transport.md L9). */
    e = expect(1, GZ_PEER_EV_CONNECTED, 5000);
    CHECK(e && e->conn == mc3);
    e = expect(1, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->conn == mc && e->why == GZ_PEER_WHY_LOST && e->was_connected);
    e = expect(0, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->why == GZ_PEER_WHY_EVICTED && e->was_connected);
    {
        gz_peers_stats_t st;
        gz_peers_stats(S[0].p, &st);
        CHECK(st.open == 2 && st.evicted_unseated == 1);
    }
    free_sides();

    /* Bad configurations. */
    {
        gz_peers_config_t c;
        gz_peers_default_config(&c);
        CHECK(gz_peers_new(&c) == NULL);
        CHECK(gz_peers_new(NULL) == NULL);
        c.secp = secp;
        c.random = RNG;
        c.is_member = gz_conn_any_member;
        c.ping_ms = 0;
        CHECK(gz_peers_new(&c) == NULL);
        c.ping_ms = 1;
        S[0].p = gz_peers_new(&c);
        CHECK(S[0].p != NULL);
        CHECK(gz_peers_listen(S[0].p, "nowhere", 0, &port) == GZ_PEERS_ERR_ADDRESS);
        free_sides();
    }
}

/* ------------------------------------------------ admission (review F1) */

/* src: a source address in host byte order (a second loopback address
 * stands for another member's machine), or 0 for any. */
static int raw_socket_from(uint32_t src, uint16_t port)
{
    struct sockaddr_in a;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    if (src) {
        a.sin_addr.s_addr = htonl(src);
        if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    }
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    /* Non-blocking: with the host's backlog full a blocking connect would
     * wait for the kernel's SYN retries. */
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    return fd;
}

/* 1 if the host has closed this socket (EOF or reset), without waiting. */
static int closed_by_host(int fd)
{
    char b;
    ssize_t r = recv(fd, &b, 1, MSG_DONTWAIT);
    return r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOTCONN);
}

#define OTHER_LOOPBACK 0x7f000002u /* the loopback network's second address */

static void no_address_cap(gz_peers_config_t *c) { c->max_per_address = 0; }
static void three_slots(gz_peers_config_t *c) { c->max_per_address = 0; c->max_conns = 3; }

static void test_admission(void)
{
    uint16_t port;
    int fds[40], i, connected = 0;
    uint64_t mc, a[3];
    gz_peer_event_t *e;
    gz_peers_stats_t st;
    int64_t end;

    /* Silent sockets, each reopened as soon as the host drops it: 40 of
     * them against a budget of 16. An honest member still gets in. */
    S[0].p = mk(HOST_KEY, 20000, 30000, NULL, no_address_cap);
    S[1].p = mk(MEM_KEY, 20000, 30000, NULL, NULL);
    CHECK(gz_peers_listen(S[0].p, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    for (i = 0; i < 40; i++) fds[i] = raw_socket_from(0, port);
    pump(200);
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, NULL, &mc) == GZ_PEERS_OK);
    end = ms() + 5000;
    while (!connected && ms() < end) {
        for (i = 0; i < 40; i++)
            if (fds[i] < 0 || closed_by_host(fds[i])) {
                if (fds[i] >= 0) close(fds[i]);
                fds[i] = raw_socket_from(0, port);
            }
        pump(5);
        for (i = 0; i < S[1].n; i++)
            if (S[1].e[i].ev.type == GZ_PEER_EV_CONNECTED) connected = 1;
    }
    CHECK(connected);
    gz_peers_stats(S[0].p, &st);
    CHECK(st.evicted_handshakes > 0);
    e = expect(0, GZ_PEER_EV_CLOSED, 0);
    CHECK(e && e->why == GZ_PEER_WHY_EVICTED && !e->was_connected && !e->have_node_id);
    for (i = 0; i < 40; i++) if (fds[i] >= 0) close(fds[i]);
    free_sides();

    /* At most 4 connections from one address: a fifth from OTHER_LOOPBACK is
     * closed at once, while 127.0.0.1 is still served. */
    S[0].p = mk(HOST_KEY, 20000, 30000, NULL, NULL);
    S[1].p = mk(MEM_KEY, 20000, 30000, NULL, NULL);
    CHECK(gz_peers_listen(S[0].p, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    for (i = 0; i < 5; i++) {
        fds[i] = raw_socket_from(OTHER_LOOPBACK, port);
        CHECK(fds[i] >= 0);
        pump(50);
    }
    pump(200);
    for (i = 0; i < 4; i++) CHECK(!closed_by_host(fds[i]));
    CHECK(closed_by_host(fds[4]));
    gz_peers_stats(S[0].p, &st);
    CHECK(st.refused_address == 1);
    CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, NULL, &mc) == GZ_PEERS_OK);
    CHECK(expect(1, GZ_PEER_EV_CONNECTED, 5000) != NULL);
    for (i = 0; i < 5; i++) close(fds[i]);
    free_sides();

    /* Established members without seats holding every slot: a newcomer
     * evicts the oldest of them. Once every slot holds a seat, a newcomer
     * is refused. */
    S[0].p = mk(HOST_KEY, 20000, 30000, NULL, three_slots);
    S[1].p = mk(MEM_KEY, 20000, 30000, NULL, NULL);
    CHECK(gz_peers_listen(S[0].p, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    {
        static uint8_t keys[5][32];
        uint64_t hconn[5], m4, m5;
        for (i = 0; i < 5; i++) memset(keys[i], 0x51 + i, 32);
        for (i = 0; i < 3; i++) {
            CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, keys[i], &a[i]) == GZ_PEERS_OK);
            CHECK(expect(1, GZ_PEER_EV_CONNECTED, 5000) != NULL);
            e = expect(0, GZ_PEER_EV_CONNECTED, 5000);
            hconn[i] = e ? e->conn : 0;
            pump(20); /* distinct start times */
        }
        CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, keys[3], &m4) == GZ_PEERS_OK);
        e = expect(0, GZ_PEER_EV_CONNECTED, 5000);
        CHECK(e != NULL);
        hconn[3] = e ? e->conn : 0;
        e = expect(0, GZ_PEER_EV_CLOSED, 5000);
        CHECK(e && e->conn == hconn[0] && e->why == GZ_PEER_WHY_EVICTED && e->was_connected);
        e = expect(1, GZ_PEER_EV_WARNING, 5000);
        CHECK(e && e->conn == a[0] && strcmp(e->text, "host full: evicted without a seat") == 0);
        e = expect(1, GZ_PEER_EV_CLOSED, 5000);
        CHECK(e && e->conn == a[0]);
        gz_peers_stats(S[0].p, &st);
        CHECK(st.evicted_unseated == 1);
        /* The lobby seats all three now connected. */
        CHECK(gz_peers_set_seated(S[0].p, hconn[1], 1) == GZ_PEERS_OK);
        CHECK(gz_peers_set_seated(S[0].p, hconn[2], 1) == GZ_PEERS_OK);
        CHECK(gz_peers_set_seated(S[0].p, hconn[3], 1) == GZ_PEERS_OK);
        CHECK(gz_peers_set_seated(S[0].p, hconn[0], 1) == GZ_PEERS_ERR_NO_CONN);
        CHECK(gz_peers_connect(S[1].p, "127.0.0.1", port, HOST_PUB, keys[4], &m5) == GZ_PEERS_OK);
        e = expect(0, GZ_PEER_EV_CLOSED, 5000);
        CHECK(e && e->why == GZ_PEER_WHY_FULL && !e->was_connected);
        e = expect(1, GZ_PEER_EV_WARNING, 5000);
        CHECK(e && e->conn == m5 && strcmp(e->text, "host full") == 0);
        /* The member had the host's init, so it saw itself connected. */
        e = expect(1, GZ_PEER_EV_CLOSED, 5000);
        CHECK(e && e->conn == m5 && e->why == GZ_PEER_WHY_LOST);
        gz_peers_stats(S[0].p, &st);
        CHECK(st.refused_full == 1 && st.evicted_unseated == 1);
        CHECK(quiet(0, GZ_PEER_EV_CLOSED, 300));
    }
    free_sides();
}

/* ------------------------------------------------ review of PR 23: F7, F8, fairness, refusing */

static void test_limits(void)
{
    uint64_t hc, mc;
    uint8_t m[200];
    size_t n;
    int i, got = 0;
    gz_peer_event_t *e, ev;
    gz_peers_stats_t st;
    static const uint8_t zero[32];

    /* Warnings: the first 10 are events, the rest counted; ignored traffic
     * past 100 in a window is refused. */
    hc = pair(20000, 30000, NULL, &mc, NULL);
    CHECK(gz_ln_alert_write(GZ_LN_WARNING, "w", m, sizeof m, &n) == 0);
    for (i = 0; i < 12; i++) gz_peers_send_raw(S[1].p, mc, m, n);
    pump(500);
    for (i = 0; i < 10; i++) CHECK(expect(0, GZ_PEER_EV_WARNING, 0) != NULL);
    CHECK(quiet(0, GZ_PEER_EV_WARNING, 0));
    gz_peers_stats(S[0].p, &st);
    CHECK(st.warnings_dropped == 2);
    for (i = 0; i < 88; i++) gz_peers_send_raw(S[1].p, mc, (const uint8_t *)"\x80\x01odd", 5);
    pump(300);
    CHECK(quiet(0, GZ_PEER_EV_CLOSED, 0));
    gz_peers_send_raw(S[1].p, mc, (const uint8_t *)"\x80\x01odd", 5);
    e = expect(0, GZ_PEER_EV_CLOSED, 5000);
    CHECK(e && e->conn == hc && e->why == GZ_PEER_WHY_PROTOCOL && strcmp(e->text, "too many ignored messages") == 0);
    free_sides();

    /* Events queued for a connection are dropped when it is closed (F8). */
    hc = pair(20000, 30000, NULL, &mc, NULL);
    for (i = 0; i < 3; i++) gz_peers_send(S[1].p, mc, GZ_ENV_KIND_HELLO, zero, NULL, 0);
    for (i = 0; i < 50; i++) gz_peers_poll(S[1].p, 2, &ev);
    for (i = 0; i < 500; i++)
        if (gz_peers_poll(S[0].p, 10, &ev) && ev.type == GZ_PEER_EV_MESSAGE) break;
    CHECK(i < 500 && ev.conn == hc);
    CHECK(gz_peers_close(S[0].p, hc) == GZ_PEERS_OK);
    for (i = 0; i < 30; i++)
        if (gz_peers_poll(S[0].p, 10, &ev) && ev.conn == hc) got++;
    CHECK(got == 0);
    free_sides();

    free_sides();
}

static void test_fairness(void)
{
    uint64_t hc, mc, bc, bh = 0;
    uint16_t port;
    gz_peers_t *b;
    gz_peer_event_t ev, *e;
    int i, index = -1, k = 0, ok = 0;
    int64_t end;
    static const uint8_t zero[32];
    hc = pair(20000, 30000, NULL, &mc, &port);
    b = mk(MEM_KEY2, 20000, 30000, NULL, NULL);
    CHECK(b && gz_peers_connect(b, "127.0.0.1", port, HOST_PUB, NULL, &bc) == GZ_PEERS_OK);
    end = ms() + 5000;
    while (!ok && ms() < end) {
        pump(2);
        if (gz_peers_poll(b, 2, &ev) && ev.type == GZ_PEER_EV_CONNECTED) ok = 1;
    }
    CHECK(ok);
    e = expect(0, GZ_PEER_EV_CONNECTED, 5000);
    if (e) bh = e->conn;
    CHECK(bh && bh != hc);
    /* Member A queues 300 messages, member B one; both are flushed to the
     * host's socket buffers before the host reads anything. */
    for (i = 0; i < 300; i++) gz_peers_send(S[1].p, mc, GZ_ENV_KIND_HELLO, zero, NULL, 0);
    gz_peers_send(b, bc, GZ_ENV_KIND_HELLO, SCOPE, NULL, 0);
    for (i = 0; i < 100; i++) {
        gz_peers_poll(S[1].p, 1, &ev);
        gz_peers_poll(b, 1, &ev);
    }
    while (k < 301 && gz_peers_poll(S[0].p, 2000, &ev)) {
        if (ev.type != GZ_PEER_EV_MESSAGE) continue;
        if (ev.conn == bh) index = k;
        k++;
    }
    /* 64 units (32 messages) of A per round, then B's. */
    CHECK(k == 301 && index >= 0 && index < 150);
    gz_peers_free(b);
    free_sides();
}

/* A refused connection whose peer does not read: the host stops reading
 * from it (no busy loop while the peer keeps sending) and ends at the
 * peer's hang-up rather than at send_ms. */
static void slow_send(gz_peers_config_t *c) { c->send_ms = 6000; }

static void test_refusing(void)
{
    uint16_t port;
    pid_t pid;
    gz_peer_event_t *e, ev;
    int i;
    S[0].p = mk(HOST_KEY, 20000, 30000, NULL, slow_send);
    CHECK(gz_peers_listen(S[0].p, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    pid = child(port, CH_JUNK);
    e = expect(0, GZ_PEER_EV_CONNECTED, 5000);
    CHECK(e != NULL);
    if (e) {
        uint64_t hc = e->conn;
        int64_t t0, end;
        clock_t c0;
        for (i = 0; i < 4; i++)
            if (gz_peers_send(S[0].p, hc, 68, SCOPE, big, GZ_ENV_MAX_WHOLE) != GZ_PEERS_OK) break;
        pump(300);
        CHECK(gz_peers_refuse(S[0].p, hc, "enough") == GZ_PEERS_OK);
        t0 = ms();
        pump(1200); /* the child's bytes arrive meanwhile */
        c0 = clock();
        end = ms() + 1000;
        while (ms() < end) CHECK(!gz_peers_poll(S[0].p, (int)(end - ms()), &ev));
        CHECK((double)(clock() - c0) / CLOCKS_PER_SEC < 0.5);
        e = expect(0, GZ_PEER_EV_CLOSED, 8000);
        CHECK(e && e->why == GZ_PEER_WHY_LOCAL && ms() - t0 < 5000);
    }
    reap(pid);
    free_sides();
}

int main(void)
{
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    memset(HOST_KEY, 0x21, 32);
    memset(MEM_KEY, 0x11, 32);
    memset(MEM_KEY2, 0x12, 32);
    memset(CHILD_KEY, 0x13, 32);
    memset(SCOPE, 0x75, 32);
    pub(HOST_KEY, HOST_PUB);
    pub(MEM_KEY, MEM_PUB);
    pub(MEM_KEY2, MEM_PUB2);
    pub(CHILD_KEY, CHILD_PUB);
    puts("== basic");
    fflush(stdout);
    test_basic();
    test_keepalive();
    test_hostile();
    test_messages();
    test_connect_failures();
    puts("== admission");
    fflush(stdout);
    test_admission();
    puts("== limits");
    fflush(stdout);
    test_limits();
    puts("== refusing");
    fflush(stdout);
    test_refusing();
    puts("== fairness");
    fflush(stdout);
    test_fairness();
    secp256k1_context_destroy(secp);
    return check_done();
}
