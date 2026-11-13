/* Kind 32767, test traffic (contract v2, section 7), in a build with
 * GZ_TEST_KINDS: scope all zero, any valid records, either direction, never
 * split. The release library ignores it (test_envelope checks that). */
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../check.h"
#include "envelope.h"
#include "frame.h"
#include "peers.h"

#ifndef GZ_TEST_KINDS
#error "test_testkind.c is built with GZ_TEST_KINDS"
#endif

static secp256k1_context *secp;

static void counter_fill(void *ctx, uint8_t *out, size_t len)
{
    static uint8_t n = 1;
    (void)ctx;
    memset(out, 0x40, len);
    out[len - 1] = n++;
}

static int64_t ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static gz_peers_t *mk(uint8_t fillbyte)
{
    gz_peers_config_t c;
    gz_peers_default_config(&c);
    c.secp = secp;
    memset(c.static_key, fillbyte, 32);
    c.random.fill = counter_fill;
    c.random.ctx = NULL;
    c.is_member = gz_conn_any_member;
    return gz_peers_new(&c);
}

/* A small event log for the two sides, so polling one never loses the
 * other's events. */
static gz_peers_t *side[2];
static struct {
    gz_peer_event_t ev;
    uint8_t body[100];
    int used;
} lg[2][64];
static int nlg[2];

static int wait_ev(int who, gz_peer_ev_type_t type, gz_peer_event_t *out, uint8_t *body)
{
    int64_t end = ms() + 5000;
    for (;;) {
        int s2, i;
        for (i = 0; i < nlg[who]; i++)
            if (!lg[who][i].used && lg[who][i].ev.type == type) {
                lg[who][i].used = 1;
                *out = lg[who][i].ev;
                if (body) memcpy(body, lg[who][i].body, sizeof lg[who][i].body);
                return 1;
            }
        if (ms() >= end) return 0;
        for (s2 = 0; s2 < 2; s2++) {
            gz_peer_event_t ev;
            while (gz_peers_poll(side[s2], 2, &ev) && nlg[s2] < 64) {
                lg[s2][nlg[s2]].ev = ev;
                lg[s2][nlg[s2]].used = 0;
                if (ev.records_len && ev.records_len <= sizeof lg[s2][0].body) memcpy(lg[s2][nlg[s2]].body, ev.records, ev.records_len);
                nlg[s2]++;
            }
        }
    }
}

int main(void)
{
    static const uint8_t zero[32];
    uint8_t scope[32], rec[64], body[100];
    (void)0;
    static uint8_t big[70000];
    gz_tlv_writer_t w;
    gz_peer_event_t ev;
    gz_peers_t *host, *mem;
    uint64_t mc, hc;
    uint16_t port;
    secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    memset(scope, 0x33, 32);
    gz_tlv_writer_init(&w, rec, sizeof rec);
    gz_tlv_put(&w, 1, (const uint8_t *)"GZPI", 4);

    /* The envelope: zero scope, either side; any odd record; no scope, no even record. */
    CHECK(GZ_ENV_KIND_TEST == 32767);
    CHECK(gz_env_check(GZ_ENV_KIND_TEST, zero, rec, w.len, GZ_ENV_AT_HOST, NULL) == GZ_ENV_DELIVER);
    CHECK(gz_env_check(GZ_ENV_KIND_TEST, zero, rec, w.len, GZ_ENV_AT_MEMBER, NULL) == GZ_ENV_DELIVER);
    CHECK(gz_env_check(GZ_ENV_KIND_TEST, zero, NULL, 0, GZ_ENV_AT_HOST, NULL) == GZ_ENV_DELIVER);
    CHECK(gz_env_check(GZ_ENV_KIND_TEST, scope, rec, w.len, GZ_ENV_AT_HOST, NULL) == GZ_ENV_REFUSE);
    rec[0] = 2;
    CHECK(gz_env_check(GZ_ENV_KIND_TEST, zero, rec, w.len, GZ_ENV_AT_HOST, NULL) == GZ_ENV_REFUSE);
    rec[0] = 1;

    /* Through the transport, both ways, kind and scope intact. */
    host = mk(0x21);
    mem = mk(0x11);
    CHECK(host && mem);
    side[0] = host;
    side[1] = mem;
    CHECK(gz_peers_listen(host, "127.0.0.1", 0, &port) == GZ_PEERS_OK);
    {
        secp256k1_pubkey pk;
        uint8_t pin[33], k[32];
        size_t n = 33;
        memset(k, 0x21, 32);
        CHECK(secp256k1_ec_pubkey_create(secp, &pk, k) &&
              secp256k1_ec_pubkey_serialize(secp, pin, &n, &pk, SECP256K1_EC_COMPRESSED));
        CHECK(gz_peers_connect(mem, "127.0.0.1", port, pin, NULL, &mc) == GZ_PEERS_OK);
    }
    CHECK(wait_ev(0, GZ_PEER_EV_CONNECTED, &ev, NULL));
    hc = ev.conn;
    CHECK(wait_ev(1, GZ_PEER_EV_CONNECTED, &ev, NULL));
    CHECK(gz_peers_send(mem, mc, GZ_ENV_KIND_TEST, zero, rec, w.len) == GZ_PEERS_OK);
    CHECK(wait_ev(0, GZ_PEER_EV_MESSAGE, &ev, body));
    CHECK(ev.kind == GZ_ENV_KIND_TEST && memcmp(ev.scope, zero, 32) == 0 && ev.records_len == w.len &&
          memcmp(body, rec, w.len) == 0);
    CHECK(gz_peers_send(host, hc, GZ_ENV_KIND_TEST, zero, rec, w.len) == GZ_PEERS_OK);
    CHECK(wait_ev(1, GZ_PEER_EV_MESSAGE, &ev, body));
    CHECK(ev.kind == GZ_ENV_KIND_TEST && ev.records_len == w.len);
    /* Never split: 70,000 bytes from the host are refused, and the refusal
     * closes the connection (contract v2, section 1). */
    CHECK(gz_peers_send(host, hc, GZ_ENV_KIND_TEST, zero, big, sizeof big) == GZ_PEERS_ERR_TOO_BIG);
    CHECK(wait_ev(0, GZ_PEER_EV_CLOSED, &ev, NULL));
    CHECK(ev.conn == hc && ev.why == GZ_PEER_WHY_SEND_REFUSED);
    CHECK(wait_ev(1, GZ_PEER_EV_CLOSED, &ev, NULL));
    CHECK(ev.why == GZ_PEER_WHY_LOST);
    gz_peers_free(host);
    gz_peers_free(mem);
    secp256k1_context_destroy(secp);
    return check_done();
}
