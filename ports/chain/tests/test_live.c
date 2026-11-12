/*
 * Live test. Opt-in only (cmake -DGZ_LIVE_TESTS=ON); never in the default
 * ctest run or in CI. Asks the two signet chain servers listed in
 * docs/CHAIN-SERVERS.md, through the real HTTPS transport, for the tip and
 * for a known confirmed signet transaction, and requires them to agree.
 * Makes about 60 requests in total, spaced by the backend's rate limit.
 */
#include "test.h"

#include "gazpacho/chain_esplora.h"
#include "gazpacho/chain_multi.h"

#define MEMPOOL "https://mempool.space/signet/api"
#define BLOCKSTREAM "https://blockstream.info/signet/api"

typedef struct live {
  gz_http http;
  gz_chain server[2];
  gz_chain multi;
} live;

static void test_transport_limits(test_state *T) {
  gz_http http;
  gz_http_request req;
  gz_http_response resp;
  uint8_t buf[256];
  CHECK(gz_http_curl_create(&http, NULL));
  memset(&req, 0, sizeof req);
  req.url = MEMPOOL "/blocks/tip/height";
  req.timeout_ms = 15000;
  CHECK(http.request(http.ctx, &req, buf, sizeof buf, &resp) == GZ_HTTP_OK);
  CHECK(resp.status == 200 && resp.len >= 6 && resp.len <= 10);
  /* the size cap: a 64-character answer into room for 8 */
  req.url = MEMPOOL "/blocks/tip/hash";
  CHECK(http.request(http.ctx, &req, buf, 8, &resp) == GZ_HTTP_E_TOO_LARGE);
  /* the time limit: nothing completes in one millisecond */
  req.timeout_ms = 1;
  gz_http_result r = http.request(http.ctx, &req, buf, sizeof buf, &resp);
  CHECK(r == GZ_HTTP_E_TIMEOUT);
  /* plain http is refused by this transport */
  req.timeout_ms = 15000;
  req.url = "http://mempool.space/signet/api/blocks/tip/height";
  CHECK(http.request(http.ctx, &req, buf, sizeof buf, &resp) != GZ_HTTP_OK);
  /* a host that does not exist */
  req.url = "https://no-such-host.invalid/api/blocks/tip/height";
  CHECK(http.request(http.ctx, &req, buf, sizeof buf, &resp) == GZ_HTTP_E_CONNECT);
  gz_http_curl_destroy(&http);
}

static void test_two_signet_servers_agree(test_state *T) {
  live x;
  gz_multi_config mc;
  static const char *const urls[2] = {MEMPOOL, BLOCKSTREAM};
  memset(&x, 0, sizeof x);
  CHECK(gz_http_curl_create(&x.http, NULL));
  for (int i = 0; i < 2; i++) {
    gz_esplora_config cfg;
    gz_esplora_config_default(&cfg);
    cfg.base_url = urls[i];
    CHECK_RESULT(gz_esplora_create(&cfg, &x.http, &x.server[i]), GZ_CHAIN_OK);
  }
  gz_multi_config_default(&mc, GZ_NET_SIGNET);
  mc.now_ms = x.http.now_ms;
  mc.clock_ctx = x.http.ctx;
  CHECK_RESULT(gz_multi_create(&mc, x.server, 2, &x.multi), GZ_CHAIN_OK);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);
  char hex[65];

  gz_chain_tip tip;
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_OK);
  gz_hash_to_hex(tip.hash, hex);
  printf("  tip: agreed height %lu %s (mempool.space %lu, blockstream.info %lu)\n",
         (unsigned long)tip.height, hex, (unsigned long)rep->answers[0].u.tip.height,
         (unsigned long)rep->answers[1].u.tip.height);
  CHECK(tip.height > 329439);

  uint8_t a[GZ_HASH_LEN], h38[GZ_HASH_LEN], spender[GZ_HASH_LEN], none[GZ_HASH_LEN];
  test_hash(TX_A, a);
  test_hash(HASH_329438, h38);
  test_hash(TX_SPENDER, spender);
  test_hash(TX_NONE, none);

  gz_tx_status st;
  CHECK_RESULT(gz_chain_tx_status(&x.multi, a, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_CONFIRMED && st.height == 329438);
  CHECK(memcmp(st.block_hash, h38, GZ_HASH_LEN) == 0);
  CHECK(st.claimed_confirmations == st.tip_height - 329438 + 1);
  printf("  tx %s: confirmed at 329438, %lu confirmations\n", TX_A, (unsigned long)st.claimed_confirmations);
  CHECK_RESULT(gz_chain_tx_status(&x.multi, none, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_UNKNOWN);

  gz_confirmation conf;
  CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_OK);
  CHECK(conf.status.state == GZ_TX_CONFIRMED && conf.proof.depth == 8 && conf.proof.pos == 1);
  CHECK(conf.checked_confirmations == 6 && conf.block.tx_count == 243);
  printf("  proof: %lu steps, coinbase cross-checked, %lu confirmations by linked headers, both servers\n",
         (unsigned long)conf.proof.depth, (unsigned long)conf.checked_confirmations);

  gz_outspend o;
  CHECK_RESULT(gz_chain_outspend(&x.multi, a, 0, &o), GZ_CHAIN_OK);
  CHECK(o.spent && o.height == 329439 && memcmp(o.spender_txid, spender, GZ_HASH_LEN) == 0);

  uint8_t script[32], raw[1024], check[GZ_HASH_LEN];
  size_t script_len = 0, n = 0;
  gz_chain_output outs[16];
  CHECK(gz_hex_decode(SCRIPT_A2, strlen(SCRIPT_A2), script, sizeof script, &script_len));
  gz_chain_result r = gz_chain_script_outputs(&x.multi, script, script_len, outs, 16, &n, NULL);
  CHECK_RESULT(r, GZ_CHAIN_OK);
  printf("  script %s: %zu unspent output(s), both servers identical\n", SCRIPT_A2, n);

  CHECK_RESULT(gz_chain_raw_tx(&x.multi, a, raw, sizeof raw, &n), GZ_CHAIN_OK);
  CHECK(n == 244 && gz_txid_from_raw(raw, n, check) && memcmp(check, a, GZ_HASH_LEN) == 0);

  /* Fee estimates are opinions: the two operators may be within the allowed
   * spread or not. Either is a correct outcome; both must have answered. */
  gz_fee_estimates f;
  gz_fee_choice choice;
  r = gz_chain_fee_estimates(&x.multi, &f);
  CHECK(r == GZ_CHAIN_OK || r == GZ_CHAIN_DISAGREE);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[1].result == GZ_CHAIN_OK);
  printf("  fees: combined verdict %s; next block: mempool.space %llu, blockstream.info %llu sat/kvB\n",
         gz_chain_result_name(r),
         (unsigned long long)rep->answers[0].u.fees.entries[0].sat_per_kvb,
         (unsigned long long)rep->answers[1].u.fees.entries[0].sat_per_kvb);
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.multi, GZ_NET_SIGNET, 6, 200000, &choice), GZ_CHAIN_OK);
  CHECK(choice.sat_per_kvb == 100 && choice.source == GZ_FEE_FROM_TEST_DEFAULT);

  /* the servers are on signet and on no other network */
  CHECK_RESULT(gz_chain_check_network(&x.server[0], GZ_NET_SIGNET), GZ_CHAIN_OK);
  CHECK_RESULT(gz_chain_check_network(&x.server[1], GZ_NET_SIGNET), GZ_CHAIN_OK);
  CHECK_RESULT(gz_chain_check_network(&x.server[0], GZ_NET_MAINNET), GZ_CHAIN_WRONG_NETWORK);

  gz_chain_destroy(&x.multi);
  gz_chain_destroy(&x.server[0]);
  gz_chain_destroy(&x.server[1]);
  gz_http_curl_destroy(&x.http);
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  RUN(test_transport_limits);
  RUN(test_two_signet_servers_agree);
  TEST_MAIN_END("test_live");
}
