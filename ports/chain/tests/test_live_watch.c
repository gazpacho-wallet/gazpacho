/*
 * Opt-in only (GZ_LIVE_TESTS), never in CI: the chain worker against the two
 * public signet servers. It watches a known confirmed transaction and one of
 * its outputs, and the tip, and prints what it was told. It only reads: this
 * program has no call that broadcasts.
 */
#define _POSIX_C_SOURCE 200809L

#include <poll.h>
#include <time.h>

#include "test.h"

#include "gazpacho/chain_esplora.h"
#include "gazpacho/chain_multi.h"
#include "gazpacho/chain_watch.h"

static uint64_t ms_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

int main(void) {
  static const char *const base[2] = {"https://mempool.space/signet/api",
                                      "https://blockstream.info/signet/api"};
  static const char *const op[2] = {"mempool.space", "blockstream.info"};
  test_state state = {0, 0, 0}, *T = &state;
  gz_http http;
  gz_chain server[2], multi;
  uint8_t tx_a[GZ_HASH_LEN], spender[GZ_HASH_LEN];
  char hex[65];
  bool tip = false, confirmed = false, spent = false;
  test_hash(TX_A, tx_a);
  test_hash(TX_SPENDER, spender);
  CHECK(gz_http_curl_create(&http, NULL));
  for (int i = 0; i < 2; i++) {
    gz_esplora_config c;
    gz_esplora_config_default(&c);
    c.base_url = base[i];
    c.operator_id = op[i];
    CHECK_RESULT(gz_esplora_create(&c, &http, &server[i]), GZ_CHAIN_OK);
  }
  gz_multi_config mc;
  gz_multi_config_default(&mc, GZ_NET_SIGNET);
  mc.now_ms = http.now_ms;
  mc.clock_ctx = http.ctx;
  CHECK_RESULT(gz_multi_create(&mc, server, 2, &multi), GZ_CHAIN_OK);
  gz_chainw_config cfg;
  gz_chainw_config_default(&cfg, &multi, GZ_NET_SIGNET);
  cfg.interrupt = gz_http_curl_interrupt_hook;
  cfg.interrupt_ctx = &http;
  printf("libcurl resolves names without blocking: %s\n", gz_http_curl_async_dns() ? "yes" : "no");
  gz_chainw *w = gz_chainw_new(&cfg);
  CHECK(w != NULL);
  if (w == NULL) return 1;
  CHECK(gz_chainw_watch_tx(w, tx_a, 6, 0) == GZ_CHAINW_OK);
  CHECK(gz_chainw_watch_outpoint(w, tx_a, 0, 6, 0) == GZ_CHAINW_OK);
  uint64_t begun = ms_now(), end = begun + 240000;
  while (!(tip && confirmed && spent) && ms_now() < end) {
    struct pollfd p = {gz_chainw_fd(w), POLLIN, 0};
    gz_chainw_event ev;
    (void)poll(&p, 1, 1000);
    while (gz_chainw_take(w, &ev)) {
      printf("%6llu ms  %-14s", (unsigned long long)(ms_now() - begun), gz_chainw_kind_name(ev.kind));
      switch (ev.kind) {
        case GZ_CHAINW_TIP:
          gz_hash_to_hex(ev.block_hash, hex);
          printf(" height %u %s\n", ev.height, hex);
          tip = true;
          break;
        case GZ_CHAINW_TX_CONFIRMED:
          gz_hash_to_hex(ev.txid, hex);
          printf(" %s at %u, %u checked%s\n", hex, ev.height, ev.confirmations, ev.buried ? ", buried" : "");
          CHECK(memcmp(ev.txid, tx_a, GZ_HASH_LEN) == 0 && ev.height == 329438 && ev.confirmations == 6 &&
                ev.buried);
          confirmed = true;
          break;
        case GZ_CHAINW_OUTPOINT_SPENT:
          gz_hash_to_hex(ev.txid, hex);
          printf(" output %u spent by %s input %u at %u, %u checked%s\n", ev.outpoint_vout, hex, ev.vin,
                 ev.height, ev.confirmations, ev.buried ? ", buried" : "");
          CHECK(memcmp(ev.txid, spender, GZ_HASH_LEN) == 0 && ev.vin == 0 && ev.height == 329439 &&
                ev.confirmations == 6);
          spent = true;
          break;
        case GZ_CHAINW_SOURCES: printf(" %s\n", gz_chain_result_name(ev.sources)); break;
        default: printf("\n"); break;
      }
    }
  }
  CHECK(tip && confirmed && spent);
  uint64_t t0 = ms_now();
  gz_chainw_free(w);
  printf("shutdown took %llu ms\n", (unsigned long long)(ms_now() - t0));
  gz_chain_destroy(&multi);
  gz_chain_destroy(&server[0]);
  gz_chain_destroy(&server[1]);
  gz_http_curl_destroy(&http);
  TEST_MAIN_END("chain_live_watch");
}
