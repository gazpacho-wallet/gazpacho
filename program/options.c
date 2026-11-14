/* SPDX-License-Identifier: MIT */
/* Command line, output lines, clocks, randomness and hex for the program. */
#if defined(__linux__)
#define _GNU_SOURCE
#include <sys/random.h>
#else
#define _DEFAULT_SOURCE
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "gzp.h"

static const char *log_name = "gazpacho";

void gzp_log_set_name(const char *name)
{
    log_name = name ? name : "gazpacho";
}

void gzp_log(const char *fmt, ...)
{
    va_list ap;
    printf("%s ", log_name);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

uint64_t gzp_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

uint64_t gzp_wall_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

void gzp_os_random(uint8_t *out, size_t len)
{
    size_t done = 0;
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
        fprintf(stderr, "gazpacho: cannot read randomness from the system\n");
        abort();
    }
}

void gzp_hex(const uint8_t *p, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 15];
    }
    out[2 * n] = 0;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int gzp_unhex(const char *s, size_t slen, uint8_t *out, size_t n)
{
    size_t i;
    if (slen != 2 * n) return 0;
    for (i = 0; i < n; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return 1;
}

void gzp_usage(void)
{
    fprintf(stderr,
        "usage: gazpacho --data-dir DIR --role host|member [options]\n"
        "  --network signet|testnet4     test networks only; mainnet is refused (default signet)\n"
        "  --listen ADDR:PORT            host: where members connect (default 127.0.0.1:9736)\n"
        "  --connect KEY@ADDR:PORT       member: the host's key (66 hex) and numeric address\n"
        "  --interface-port PORT         the local interface's port (served once the API server is merged)\n"
        "  --no-interface                no local interface\n"
        "  --chain-url URL               an Esplora chain server (https); --no-chain for none\n"
        "  --chain-poll-ms MS            how often to ask for the chain tip (default 60000)\n"
        "  --name LABEL                  label for output lines (default: the role)\n"
        "  --check-chain                 check the chain server (read-only) and stop\n"
        "  --handshake-ms, --recv-ms, --send-ms, --ping-ms, --pong-ms MS   transport timers\n"
        "  --reconnect-ms MS             member: first reconnect delay, doubling to 60 s (default 1000)\n"
        "  --max-per-address N           host: accepted connections per address (0: no cap)\n");
#ifdef GZP_TEST_BUILD
    fprintf(stderr,
        "tests only (gazpacho-test):\n"
        "  --test-pings N --test-ping-ms MS   send N placeholder pings to each peer\n"
        "  --test-crash-at-ping K        exit once the batch with the K-th ping record is durable\n"
        "  --test-storage-fail-at K      make the K-th journal append fail (first incarnation)\n"
        "  --test-start-delay-ms MS      keep the start open (inputs queued) this long\n"
        "  --test-listen-during-start    host: listen before the start completes\n"
        "  --test-restore-from FILE      put FILE in place as the journal, as a restore\n"
        "  --test-sync-fail-at K [--test-cut-fail]   the K-th batch's sync fails (and its undo)\n"
        "  --test-crash-after-counter    exit between the start counter and the incarnation entry\n"
        "  --test-timer-ms MS            a test timer in the executor's table\n"
        "  --test-burst NxBYTES          send N messages of BYTES at each connection\n"
        "  --test-oversize-send BYTES    pad every node send (too big is fatal)\n"
        "  --test-node-error-at K        treat the K-th delivered event as a node error\n"
        "  --test-node-error-always      ... in every incarnation, not only the first\n"
        "  --test-stop-at-restart        a SIGTERM to itself as an incarnation ends\n");
#endif
}

static int num(const char *s, long min, long max, long *out)
{
    char *end;
    long v;
    if (!s || *s < '0' || *s > '9') return 0;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || *end || v < min || v > max) return 0;
    *out = v;
    return 1;
}

/* "ADDR:PORT" with a numeric address (IPv4 or a bracketed IPv6). */
static int addr_port(const char *s, char host[GZP_ADDR_MAX], uint16_t *port)
{
    const char *colon;
    size_t hl;
    long p;
    if (!s) return 0;
    if (s[0] == '[') {
        const char *close = strchr(s, ']');
        if (!close || close[1] != ':') return 0;
        hl = (size_t)(close - s - 1);
        if (hl == 0 || hl >= GZP_ADDR_MAX) return 0;
        memcpy(host, s + 1, hl);
        colon = close + 1;
    } else {
        colon = strrchr(s, ':');
        if (!colon) return 0;
        hl = (size_t)(colon - s);
        if (hl == 0 || hl >= GZP_ADDR_MAX) return 0;
        memcpy(host, s, hl);
    }
    host[hl] = 0;
    if (!num(colon + 1, 0, 65535, &p)) return 0;
    *port = (uint16_t)p;
    return 1;
}

int gzp_options_parse(gzp_options_t *o, int argc, char **argv)
{
    int i;
    long v = 0;
    memset(o, 0, sizeof *o);
    o->network = "signet";
    strcpy(o->listen_host, "127.0.0.1");
    o->listen_port = 9736;
    o->chain_poll_ms = 60000;
    o->handshake_ms = 10000;
    o->recv_ms = 30000;
    o->send_ms = 10000;
    o->ping_ms = 15000;
    o->pong_ms = 30000;
    o->reconnect_ms = 1000;
    o->max_per_address = -1;
    o->test_ping_ms = 100;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i], *val = i + 1 < argc ? argv[i + 1] : NULL;
        int takes = 1, ok = 1;
#ifndef GZP_TEST_BUILD
        /* The release build has no test hooks (contract-v2.md, T12), and not
         * even their names (review B of PR 27, B4): any --test-* is refused
         * here, before it is looked at. */
        if (!strncmp(a, "--test-", 7)) {
            fprintf(stderr, "gazpacho: %s exists only in the test build (gazpacho-test)\n", a);
            return GZP_EXIT_USAGE;
        }
#endif
        if (!strcmp(a, "--no-interface")) { o->no_interface = 1; takes = 0; }
        else if (!strcmp(a, "--no-chain")) { o->no_chain = 1; takes = 0; }
        else if (!strcmp(a, "--check-chain")) { o->check_chain = 1; takes = 0; }
#ifdef GZP_TEST_BUILD
        else if (!strcmp(a, "--test-listen-during-start")) { o->test_listen_during_start = 1; takes = 0; }
        else if (!strcmp(a, "--test-cut-fail")) { o->test_cut_fail = 1; takes = 0; }
        else if (!strcmp(a, "--test-crash-after-counter")) { o->test_crash_after_counter = 1; takes = 0; }
        else if (!strcmp(a, "--test-node-error-always")) { o->test_node_error_always = 1; takes = 0; }
        else if (!strcmp(a, "--test-stop-at-restart")) { o->test_stop_at_restart = 1; takes = 0; }
#endif
        else if (!val) ok = 0;
        else if (!strcmp(a, "--data-dir")) o->data_dir = val;
        else if (!strcmp(a, "--role")) {
            if (!strcmp(val, "host")) o->role = GZP_ROLE_HOST;
            else if (!strcmp(val, "member")) o->role = GZP_ROLE_MEMBER;
            else ok = 0;
        }
        else if (!strcmp(a, "--network")) o->network = val;
        else if (!strcmp(a, "--listen")) ok = addr_port(val, o->listen_host, &o->listen_port);
        else if (!strcmp(a, "--connect")) {
            const char *at = strchr(val, '@');
            ok = at && gzp_unhex(val, (size_t)(at - val), o->connect_key, 33) &&
                 addr_port(at + 1, o->connect_host, &o->connect_port) && o->connect_port != 0;
            o->have_connect = ok;
        }
        else if (!strcmp(a, "--interface-port")) { ok = num(val, 1, 65535, &v); o->interface_port = (uint16_t)v; }
        else if (!strcmp(a, "--chain-url")) {
            ok = o->n_chain_urls < GZP_MAX_CHAIN_URLS;
            if (ok) o->chain_urls[o->n_chain_urls++] = val;
        }
        else if (!strcmp(a, "--chain-poll-ms")) { ok = num(val, 100, 86400000, &v); o->chain_poll_ms = (uint32_t)v; }
        else if (!strcmp(a, "--handshake-ms")) { ok = num(val, 10, 600000, &v); o->handshake_ms = (int)v; }
        else if (!strcmp(a, "--recv-ms")) { ok = num(val, 10, 600000, &v); o->recv_ms = (int)v; }
        else if (!strcmp(a, "--send-ms")) { ok = num(val, 10, 600000, &v); o->send_ms = (int)v; }
        else if (!strcmp(a, "--reconnect-ms")) { ok = num(val, 10, 600000, &v); o->reconnect_ms = (int)v; }
        else if (!strcmp(a, "--ping-ms")) { ok = num(val, 10, 600000, &v); o->ping_ms = (int)v; }
        else if (!strcmp(a, "--pong-ms")) { ok = num(val, 10, 600000, &v); o->pong_ms = (int)v; }
        else if (!strcmp(a, "--max-per-address")) { ok = num(val, 0, 1000, &v); o->max_per_address = (int)v; }
        else if (!strcmp(a, "--name")) o->name = val;
#ifdef GZP_TEST_BUILD
        else if (!strcmp(a, "--test-pings")) { ok = num(val, 0, 20000, &v); o->test_pings = (int)v; }
        else if (!strcmp(a, "--test-ping-ms")) { ok = num(val, 1, 600000, &v); o->test_ping_ms = (int)v; }
        else if (!strcmp(a, "--test-crash-at-ping")) { ok = num(val, 1, 1000000, &v); o->test_crash_at_ping = (int)v; }
        else if (!strcmp(a, "--test-storage-fail-at")) { ok = num(val, 1, 1000000, &v); o->test_storage_fail_at = (int)v; }
        else if (!strcmp(a, "--test-start-delay-ms")) { ok = num(val, 0, 600000, &v); o->test_start_delay_ms = (int)v; }
        else if (!strcmp(a, "--test-restore-from")) o->test_restore_from = val;
        else if (!strcmp(a, "--test-sync-fail-at")) { ok = num(val, 1, 1000000, &v); o->test_sync_fail_at = (int)v; }
        else if (!strcmp(a, "--test-timer-ms")) { ok = num(val, 1, 600000, &v); o->test_timer_ms = (int)v; }
        else if (!strcmp(a, "--test-burst")) {
            const char *x = strchr(val, 'x');
            long nb = 0;
            ok = x && num(x + 1, 1, 65000, &v);
            if (ok) {
                char nbuf[16];
                size_t l = (size_t)(x - val);
                ok = l > 0 && l < sizeof nbuf;
                if (ok) { memcpy(nbuf, val, l); nbuf[l] = 0; ok = num(nbuf, 1, 20000, &nb); }
            }
            o->test_burst_n = (int)nb;
            o->test_burst_bytes = (int)v;
        }
        else if (!strcmp(a, "--test-oversize-send")) { ok = num(val, 1, 2000000, &v); o->test_oversize_send = (int)v; }
        else if (!strcmp(a, "--test-node-error-at")) { ok = num(val, 1, 1000000, &v); o->test_node_error_at = (int)v; }
#endif
        else ok = 0;
        if (!ok) {
            fprintf(stderr, "gazpacho: bad argument: %s%s%s\n", a, takes && val ? " " : "", takes && val ? val : "");
            gzp_usage();
            return GZP_EXIT_USAGE;
        }
        i += takes;
    }
    /* Mainnet first: whatever else is wrong, a request for mainnet is answered
     * with the refusal (SLICES.md rule 3; messages.md section 2, init). */
    if (!strcmp(o->network, "mainnet") || !strcmp(o->network, "bitcoin")) {
        fprintf(stderr, "gazpacho: refusing to run on mainnet: this build runs on test networks only\n");
        return GZP_EXIT_USAGE;
    }
    if (strcmp(o->network, "signet") && strcmp(o->network, "testnet4")) {
        fprintf(stderr, "gazpacho: unknown network %s (signet or testnet4)\n", o->network);
        return GZP_EXIT_USAGE;
    }
    if (!o->data_dir || !o->role) {
        fprintf(stderr, "gazpacho: --data-dir and --role are required\n");
        gzp_usage();
        return GZP_EXIT_USAGE;
    }
    if (o->role == GZP_ROLE_MEMBER && !o->have_connect) {
        fprintf(stderr, "gazpacho: a member needs --connect KEY@ADDR:PORT\n");
        return GZP_EXIT_USAGE;
    }
    if (o->role == GZP_ROLE_HOST && o->have_connect) {
        fprintf(stderr, "gazpacho: --connect is for a member\n");
        return GZP_EXIT_USAGE;
    }
    if (o->no_chain && o->n_chain_urls) {
        fprintf(stderr, "gazpacho: --no-chain and --chain-url together\n");
        return GZP_EXIT_USAGE;
    }
    if (o->check_chain && o->no_chain) {
        fprintf(stderr, "gazpacho: --check-chain needs --chain-url\n");
        return GZP_EXIT_USAGE;
    }
    if (!o->no_chain && o->n_chain_urls == 0) {
        fprintf(stderr, "gazpacho: give --chain-url (an Esplora server for %s) or --no-chain\n", o->network);
        return GZP_EXIT_USAGE;
    }
    if (o->n_chain_urls > 1) {
        fprintf(stderr, "gazpacho: one --chain-url for now (the comparing backend is not wired yet)\n");
        return GZP_EXIT_USAGE;
    }
    if (o->no_interface && o->interface_port) {
        fprintf(stderr, "gazpacho: --no-interface and --interface-port together\n");
        return GZP_EXIT_USAGE;
    }
    if (!o->name) o->name = o->role == GZP_ROLE_HOST ? "host" : "member";
    return 0;
}
