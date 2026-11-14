/* SPDX-License-Identifier: MIT */
/* The chain adapter. See pchain.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef GZP_HAVE_CURL
#include "gazpacho/chain_esplora.h"
#include "gazpacho/chain_http.h"
#endif

#include "gzp.h"
#include "pchain.h"

void gzp_chain_none(gzp_chain_t *c, gz_network network)
{
    memset(c, 0, sizeof *c);
    c->network = network;
}

int gzp_chain_open(gzp_chain_t *c, const char *url, gz_network network, uint32_t poll_ms)
{
#ifdef GZP_HAVE_CURL
    gz_esplora_config cfg;
    gz_http_curl_config hc;
    gz_chain_result r;
    gz_network seen = GZ_NET_INVALID;
    char hex[65];
    gzp_chain_none(c, network);
    /* Refuse mainnet whatever the caller asked: the program only ever runs
     * on a test network (options.c refuses --network mainnet already). */
    if (!gz_network_is_test(network)) {
        fprintf(stderr, "gazpacho: refusing a chain view on %s\n", gz_network_name(network));
        return GZP_EXIT_USAGE;
    }
    memset(&hc, 0, sizeof hc);
    if (!gz_http_curl_create(&c->http, &hc)) {
        fprintf(stderr, "gazpacho: cannot set up HTTPS\n");
        return GZP_EXIT_CHAIN;
    }
    c->have_http = 1;
    gz_esplora_config_default(&cfg);
    cfg.base_url = url;
    if ((r = gz_esplora_create(&cfg, &c->http, &c->chain)) != GZ_CHAIN_OK) {
        fprintf(stderr, "gazpacho: chain server %s refused: %s\n", url, gz_chain_result_name(r));
        gzp_chain_close(c);
        return GZP_EXIT_CHAIN;
    }
    r = gz_chain_identify_network(&c->chain, &seen);
    if (r == GZ_CHAIN_OK && seen != network) r = GZ_CHAIN_WRONG_NETWORK;
    if (r != GZ_CHAIN_OK) {
        if (r == GZ_CHAIN_WRONG_NETWORK)
            fprintf(stderr, "gazpacho: the chain server %s is on %s, not %s: refused\n", url,
                    seen == GZ_NET_INVALID ? "an unknown network" : gz_network_name(seen),
                    gz_network_name(network));
        else
            fprintf(stderr, "gazpacho: cannot check the chain server %s: %s\n", url, gz_chain_result_name(r));
        gzp_chain_close(c);
        return GZP_EXIT_CHAIN;
    }
    if ((r = gz_chain_tip_get(&c->chain, &c->tip)) != GZ_CHAIN_OK) {
        fprintf(stderr, "gazpacho: cannot read the chain tip from %s: %s\n", url, gz_chain_result_name(r));
        gzp_chain_close(c);
        return GZP_EXIT_CHAIN;
    }
    c->active = 1;
    c->have_tip = 1;
    c->poll_ms = poll_ms;
    gz_hash_to_hex(c->tip.hash, hex);
    gzp_log("chain network=%s tip=%u hash=%s", gz_network_name(network), c->tip.height, hex);
    return 0;
#else
    (void)url;
    (void)poll_ms;
    gzp_chain_none(c, network);
    fprintf(stderr, "gazpacho: built without libcurl: only --no-chain is available\n");
    return GZP_EXIT_USAGE;
#endif
}

int gzp_chain_poll(gzp_chain_t *c, uint64_t now, uint32_t *height)
{
    gz_chain_tip t;
    gz_chain_result r;
    if (!c->active || now < c->next_poll_ms) return 0;
    c->next_poll_ms = now + c->poll_ms;
    r = gz_chain_tip_get(&c->chain, &t);
    if (r != GZ_CHAIN_OK) {
        gzp_log("chain-poll-failed why=%s", gz_chain_result_name(r));
        return 0;
    }
    if (c->have_tip && t.height == c->tip.height && !memcmp(t.hash, c->tip.hash, 32)) return 0;
    c->tip = t;
    c->have_tip = 1;
    *height = t.height;
    gzp_log("chain-tip height=%u", t.height);
    return 1;
}

int gzp_chain_timeout(const gzp_chain_t *c, uint64_t now)
{
    if (!c->active) return -1;
    return c->next_poll_ms > now ? (int)(c->next_poll_ms - now) : 0;
}

void gzp_chain_watch_script(gzp_chain_t *c, const uint8_t *script, size_t len)
{
    size_t i;
    uint8_t *copy;
    for (i = 0; i < c->n_watches; i++)
        if (c->watch_lens[i] == len && !memcmp(c->watch_scripts[i], script, len)) return;
    if (c->n_watches == GZP_MAX_WATCHES || !(copy = malloc(len ? len : 1))) {
        gzp_log("watch-dropped len=%zu", len);
        return;
    }
    if (len) memcpy(copy, script, len);
    c->watch_scripts[c->n_watches] = copy;
    c->watch_lens[c->n_watches++] = len;
    gzp_log("watch script-len=%zu watches=%zu", len, c->n_watches);
}

void gzp_chain_broadcast(gzp_chain_t *c, const uint8_t *tx, size_t len)
{
    gz_broadcast_result br;
    gz_chain_result r;
    char hex[65];
    if (!c->active) {
        gzp_log("broadcast-dropped len=%zu why=no-chain", len);
        return;
    }
    if (!gz_network_is_test(c->network)) { /* never reached: options.c refuses mainnet */
        gzp_log("broadcast-refused why=mainnet");
        return;
    }
    r = gz_chain_broadcast(&c->chain, tx, len, &br);
    if (r == GZ_CHAIN_OK) {
        gz_hash_to_hex(br.txid, hex);
        gzp_log("broadcast txid=%s known=%d", hex, br.already_known ? 1 : 0);
    } else {
        gzp_log("broadcast-failed why=%s", gz_chain_result_name(r));
    }
}

int gzp_chain_show_outputs(gzp_chain_t *c, const uint8_t *script, size_t len)
{
    gz_chain_output outs[32];
    size_t n = 0, i;
    uint64_t total = 0;
    gz_chain_result r;
    if (!c->active) return -1;
    r = gz_chain_script_outputs(&c->chain, script, len, outs, 32, &n, NULL);
    if (r != GZ_CHAIN_OK) {
        gzp_log("wallet-outputs-failed why=%s", gz_chain_result_name(r));
        return -1;
    }
    for (i = 0; i < n; i++) total += outs[i].value;
    gzp_log("wallet-outputs count=%zu total_sat=%llu", n, (unsigned long long)total);
    return 0;
}

void gzp_chain_forget_watches(gzp_chain_t *c)
{
    size_t i;
    for (i = 0; i < c->n_watches; i++) free(c->watch_scripts[i]);
    c->n_watches = 0;
}

void gzp_chain_close(gzp_chain_t *c)
{
    gzp_chain_forget_watches(c);
    if (c->chain.ops) gz_chain_destroy(&c->chain);
#ifdef GZP_HAVE_CURL
    if (c->have_http) gz_http_curl_destroy(&c->http);
    c->have_http = 0;
#endif
    c->active = 0;
}
