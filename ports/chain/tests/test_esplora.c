/* The Esplora backend against a fake transport loaded with recorded signet
 * answers: every call, malformed answers, retries, rate limit, time limits
 * and size caps. */
#include "test.h"

#include "../esplora_parse.h"
#include "gazpacho/chain_esplora.h"

#define BASE "https://chain.test/signet/api"

typedef struct fixture {
  fake_http fake;
  gz_chain chain;
} fixture;

static void fx_open(fixture *x) {
  gz_esplora_config cfg;
  gz_http http;
  fake_init(&x->fake);
  fake_load_honest(&x->fake, BASE, false);
  http = fake_transport(&x->fake);
  gz_esplora_config_default(&cfg);
  cfg.base_url = BASE;
  if (gz_esplora_create(&cfg, &http, &x->chain) != GZ_CHAIN_OK) {
    fprintf(stderr, "cannot create backend\n");
    exit(2);
  }
}

static void fx_close(fixture *x) {
  gz_chain_destroy(&x->chain);
  fake_free(&x->fake);
}

/* ---- creation ---- */

static void test_create_validates(test_state *T) {
  fake_http fake;
  gz_esplora_config cfg;
  gz_chain c;
  fake_init(&fake);
  gz_http http = fake_transport(&fake);
  gz_esplora_config_default(&cfg);
  CHECK(cfg.timeout_ms > 0 && cfg.max_attempts >= 1 && cfg.min_interval_ms > 0);
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_INVALID_ARG); /* no address */
  static const char *bad[] = {
      "",
      "mempool.space/signet/api",
      "ftp://mempool.space/api",
      "https://",
      "https://mempool.space/signet/api/",          /* trailing slash */
      "https://mempool.space/api?x=1",              /* query */
      "https://mempool.space/api#frag",
      "https://user@mempool.space/api",             /* credentials */
      "https://mempool.space/a pi",
      "https://mempool.space/api\r\nHost: evil",    /* header injection */
      "https://mempool.space/%2e%2e/api",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    cfg.base_url = bad[i];
    CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_INVALID_ARG);
    CHECK(c.ctx == NULL);
  }
  char longurl[400];
  memset(longurl, 'a', sizeof longurl);
  memcpy(longurl, "https://", 8);
  longurl[sizeof longurl - 1] = '\0';
  cfg.base_url = longurl;
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_INVALID_ARG);

  cfg.base_url = BASE;
  cfg.timeout_ms = 0; /* a request without a time limit is refused */
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_INVALID_ARG);
  gz_esplora_config_default(&cfg);
  cfg.base_url = BASE;
  cfg.max_attempts = 0;
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_INVALID_ARG);
  cfg.max_attempts = 100; /* unbounded retries are refused */
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_INVALID_ARG);
  gz_esplora_config_default(&cfg);
  cfg.base_url = BASE;
  cfg.max_response_bytes = (size_t)1 << 30;
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_INVALID_ARG);
  gz_esplora_config_default(&cfg);
  cfg.base_url = BASE;
  gz_http broken = http;
  broken.sleep_ms = NULL;
  CHECK_RESULT(gz_esplora_create(&cfg, &broken, &c), GZ_CHAIN_INVALID_ARG);

  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_OK);
  gz_chain_destroy(&c);
  CHECK(c.ctx == NULL && c.ops == NULL);
  gz_chain_destroy(&c); /* twice is harmless */
  gz_chain_destroy(NULL);
  fake_free(&fake);
}

static void test_argument_checks(test_state *T) {
  fixture x;
  gz_chain_tip tip;
  gz_tx_status st;
  gz_chain_output outs[2];
  uint8_t txid[GZ_HASH_LEN] = {0}, buf[8];
  size_t n;
  fx_open(&x);
  gz_chain none = {NULL, NULL};
  CHECK_RESULT(gz_chain_tip_get(NULL, &tip), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_tip_get(&none, &tip), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_tip_get(&x.chain, NULL), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_tx_status(&x.chain, NULL, &st), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_block_hash(&x.chain, GZ_MAX_HEIGHT + 1u, txid), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_script_outputs(&x.chain, buf, 0, outs, 2, &n, NULL), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_script_outputs(&x.chain, buf, GZ_SCRIPT_MAX_LEN + 1, outs, 2, &n, NULL),
               GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_script_outputs(&x.chain, buf, 4, outs, 0, &n, NULL), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_raw_tx(&x.chain, txid, buf, 0, &n), GZ_CHAIN_INVALID_ARG);
  CHECK(x.fake.requests == 0); /* nothing was sent for any of these */
  fx_close(&x);
}

/* ---- tip, block hash, header ---- */

static void test_tip(test_state *T) {
  fixture x;
  gz_chain_tip tip;
  uint8_t want[GZ_HASH_LEN];
  fx_open(&x);
  CHECK_RESULT(gz_chain_tip_get(&x.chain, &tip), GZ_CHAIN_OK);
  test_hash(HASH_329439, want);
  CHECK(tip.height == TIP_HEIGHT);
  CHECK(memcmp(tip.hash, want, GZ_HASH_LEN) == 0);
  CHECK(x.fake.requests == 2 && x.fake.unexpected == 0);
  CHECK(fake_hits(&x.fake, false, BASE "/blocks/tip/height") == 1);
  CHECK(fake_hits(&x.fake, false, BASE "/block-height/329439") == 1);

  static const char *bad_heights[] = {"",       "abc",     "-1",       "329439\n",  " 329439",
                                      "0329439", "3.5",    "1e5",      "4294967296", "2147483648",
                                      "329439x", "0x10",   "+5",       "329 439"};
  for (size_t i = 0; i < sizeof bad_heights / sizeof bad_heights[0]; i++) {
    fake_set(&x.fake, false, BASE "/blocks/tip/height", 200, bad_heights[i]);
    CHECK_RESULT(gz_chain_tip_get(&x.chain, &tip), GZ_CHAIN_MALFORMED);
  }
  /* a server whose own tip has no block */
  fake_set(&x.fake, false, BASE "/blocks/tip/height", 200, "329440");
  CHECK_RESULT(gz_chain_tip_get(&x.chain, &tip), GZ_CHAIN_MALFORMED);
  fx_close(&x);
}

static void test_block_hash(test_state *T) {
  fixture x;
  uint8_t h[GZ_HASH_LEN], want[GZ_HASH_LEN];
  fx_open(&x);
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 329438, h), GZ_CHAIN_OK);
  test_hash(HASH_329438, want);
  CHECK(memcmp(h, want, GZ_HASH_LEN) == 0);
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 329440, h), GZ_CHAIN_NOT_FOUND);
  fake_set(&x.fake, false, BASE "/block-height/7", 400, "Invalid number");
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 7, h), GZ_CHAIN_REJECTED);
  fake_set(&x.fake, false, BASE "/block-height/7", 301, "moved");
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 7, h), GZ_CHAIN_MALFORMED);
  fake_set(&x.fake, false, BASE "/block-height/7", 204, "");
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 7, h), GZ_CHAIN_MALFORMED);

  static const char *bad[] = {
      "",
      "0000000e272942ba41a93bf06e25f0171c0efc02710e7cd58735243e712a1cf",    /* 63 */
      "0000000E272942BA41A93BF06E25F0171C0EFC02710E7CD58735243E712A1CF4",   /* upper case */
      "0000000e272942ba41a93bf06e25f0171c0efc02710e7cd58735243e712a1cfg",   /* not hex */
      "\"0000e272942ba41a93bf06e25f0171c0efc02710e7cd58735243e712a1cf4\"", /* quoted */
      "0000000e272942ba41a93bf06e25f0171c0efc02710e7cd58735243e712a1c\n",    /* newline */
      "<html>Just a moment...</html>",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    fake_set(&x.fake, false, BASE "/block-height/7", 200, bad[i]);
    CHECK_RESULT(gz_chain_block_hash(&x.chain, 7, h), GZ_CHAIN_MALFORMED);
  }
  fx_close(&x);
}

static void test_block_header(test_state *T) {
  fixture x;
  uint8_t hdr[GZ_HEADER_LEN], hash[GZ_HASH_LEN], want[GZ_HASH_LEN];
  size_t len;
  fx_open(&x);
  CHECK_RESULT(gz_chain_block_header(&x.chain, 329438, hdr), GZ_CHAIN_OK);
  gz_header_hash(hdr, hash);
  test_hash(HASH_329438, want);
  CHECK(memcmp(hash, want, GZ_HASH_LEN) == 0);
  CHECK_RESULT(gz_chain_block_header(&x.chain, 329440, hdr), GZ_CHAIN_NOT_FOUND);

  /* a header that is real but is not the block the server named */
  char *other = test_read_data("header_329437.txt", &len);
  fake_set(&x.fake, false, BASE "/block/" HASH_329438 "/header", 200, other);
  CHECK_RESULT(gz_chain_block_header(&x.chain, 329438, hdr), GZ_CHAIN_MALFORMED);
  /* one changed character */
  char *real = test_read_data("header_329438.txt", &len);
  real[100] = real[100] == '0' ? '1' : '0';
  fake_set(&x.fake, false, BASE "/block/" HASH_329438 "/header", 200, real);
  CHECK_RESULT(gz_chain_block_header(&x.chain, 329438, hdr), GZ_CHAIN_MALFORMED);
  real[158] = '\0'; /* too short */
  fake_set(&x.fake, false, BASE "/block/" HASH_329438 "/header", 200, real);
  CHECK_RESULT(gz_chain_block_header(&x.chain, 329438, hdr), GZ_CHAIN_MALFORMED);
  fake_set(&x.fake, false, BASE "/block/" HASH_329438 "/header", 200, "zz");
  CHECK_RESULT(gz_chain_block_header(&x.chain, 329438, hdr), GZ_CHAIN_MALFORMED);
  /* the server named a hash and then denies having it */
  fake_set(&x.fake, false, BASE "/block/" HASH_329438 "/header", 404, "Block not found");
  CHECK_RESULT(gz_chain_block_header(&x.chain, 329438, hdr), GZ_CHAIN_MALFORMED);
  free(other);
  free(real);
  fx_close(&x);
}

/* ---- transaction status ---- */

static void test_tx_status(test_state *T) {
  fixture x;
  gz_tx_status st;
  uint8_t a[GZ_HASH_LEN], none[GZ_HASH_LEN], sp[GZ_HASH_LEN], want[GZ_HASH_LEN];
  fx_open(&x);
  test_hash(TX_A, a);
  test_hash(TX_NONE, none);
  test_hash(TX_SPENDER, sp);

  CHECK_RESULT(gz_chain_tx_status(&x.chain, a, &st), GZ_CHAIN_OK);
  test_hash(HASH_329438, want);
  CHECK(st.state == GZ_TX_CONFIRMED && st.height == 329438);
  CHECK(memcmp(st.block_hash, want, GZ_HASH_LEN) == 0);
  CHECK(st.tip_height == TIP_HEIGHT && st.claimed_confirmations == 2);

  /* never seen: status says unconfirmed and the transaction itself is absent */
  CHECK_RESULT(gz_chain_tx_status(&x.chain, none, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_UNKNOWN && st.claimed_confirmations == 0);

  /* in the mempool: unconfirmed and the transaction is served */
  fake_set(&x.fake, false, BASE "/tx/" TX_SPENDER "/status", 200, "{\"confirmed\":false}");
  CHECK_RESULT(gz_chain_tx_status(&x.chain, sp, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_MEMPOOL && st.height == 0 && st.claimed_confirmations == 0);

  /* "in the mempool", but the bytes served are another transaction */
  fake_set_file(&x.fake, BASE "/tx/" TX_SPENDER "/hex", 200, "tx_a_hex.txt");
  CHECK_RESULT(gz_chain_tx_status(&x.chain, sp, &st), GZ_CHAIN_MALFORMED);

  /* confirmed above the server's own tip */
  fake_set(&x.fake, false, BASE "/blocks/tip/height", 200, "329437");
  CHECK_RESULT(gz_chain_tx_status(&x.chain, a, &st), GZ_CHAIN_MALFORMED);
  CHECK(st.state == GZ_TX_UNKNOWN); /* nothing leaked into the output */

  /* status endpoint answering 404 is taken as unknown */
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/status", 404, "Transaction not found");
  CHECK_RESULT(gz_chain_tx_status(&x.chain, a, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_UNKNOWN);
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/status", 400, "Invalid hex string");
  CHECK_RESULT(gz_chain_tx_status(&x.chain, a, &st), GZ_CHAIN_REJECTED);
  fx_close(&x);
}

#define H38 "\"" HASH_329438 "\""

static void test_status_parser_strict(test_state *T) {
  gz_es_status st;
  const char *good = "{\"confirmed\":true,\"block_height\":329438,\"block_hash\":" H38 ",\"block_time\":1793823982}";
  CHECK(gz_es_parse_status(good, strlen(good), &st) && st.confirmed && st.height == 329438);
  const char *reordered = "{\"block_time\":1,\"block_hash\":" H38 ",\"confirmed\":true,\"block_height\":5}";
  CHECK(gz_es_parse_status(reordered, strlen(reordered), &st) && st.height == 5);
  CHECK(gz_es_parse_status("{\"confirmed\":false}", 19, &st) && !st.confirmed);
  static const char *bad[] = {
      "",
      "{}",
      "[]",
      "null",
      "true",
      "\"confirmed\"",
      "{\"confirmed\":1}",
      "{\"confirmed\":\"true\"}",
      "{\"confirmed\":null}",
      "{\"confirmed\":true}", /* confirmed with no block */
      "{\"confirmed\":true,\"block_height\":329438,\"block_time\":1}",
      "{\"confirmed\":true,\"block_height\":329438,\"block_hash\":" H38 "}",
      "{\"confirmed\":true,\"block_hash\":" H38 ",\"block_time\":1}",
      "{\"confirmed\":false,\"block_height\":329438}", /* unconfirmed with a block */
      "{\"confirmed\":false,\"block_height\":null}",
      "{\"confirmed\":true,\"block_height\":-1,\"block_hash\":" H38 ",\"block_time\":1}",
      "{\"confirmed\":true,\"block_height\":329438.0,\"block_hash\":" H38 ",\"block_time\":1}",
      "{\"confirmed\":true,\"block_height\":\"329438\",\"block_hash\":" H38 ",\"block_time\":1}",
      "{\"confirmed\":true,\"block_height\":99999999999,\"block_hash\":" H38 ",\"block_time\":1}",
      "{\"confirmed\":true,\"block_height\":2147483648,\"block_hash\":" H38 ",\"block_time\":1}",
      "{\"confirmed\":true,\"block_height\":1,\"block_hash\":\"abcd\",\"block_time\":1}",
      "{\"confirmed\":true,\"block_height\":1,\"block_hash\":7,\"block_time\":1}",
      "{\"confirmed\":true,\"block_height\":1,\"block_hash\":" H38 ",\"block_time\":-5}",
      "{\"confirmed\":true,\"block_height\":1,\"block_hash\":" H38 ",\"block_time\":99999999999}",
      "{\"confirmed\":true,\"block_height\":1,\"block_hash\":" H38 ",\"block_time\":1,\"extra\":0}",
      "{\"confirmed\":true,\"block_height\":1,\"block_height\":2,\"block_hash\":" H38 ",\"block_time\":1}",
      "{\"confirmed\":false,\"confirmed\":true,\"block_height\":1,\"block_hash\":" H38 ",\"block_time\":1}",
      "{\"Confirmed\":false}",
      "{\"confirmed\":false} x",
      "{\"confirmed\":false}{\"confirmed\":true}",
      "[{\"confirmed\":false}]",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    T->checks++;
    if (gz_es_parse_status(bad[i], strlen(bad[i]), &st)) {
      T->failed++;
      fprintf(stderr, "  accepted malformed status #%zu: %s\n", i, bad[i]);
    }
  }
}

/* ---- outputs paying a script ---- */

static void test_script_outputs(test_state *T) {
  fixture x;
  gz_chain_output outs[4];
  uint8_t script[64], a[GZ_HASH_LEN], h38[GZ_HASH_LEN];
  size_t script_len = 0, n = 99;
  fx_open(&x);
  CHECK(gz_hex_decode(SCRIPT_A2, strlen(SCRIPT_A2), script, sizeof script, &script_len));
  test_hash(TX_A, a);
  test_hash(HASH_329438, h38);

  CHECK_RESULT(gz_chain_script_outputs(&x.chain, script, script_len, outs, 4, &n, NULL), GZ_CHAIN_OK);
  CHECK(n == 1);
  CHECK(memcmp(outs[0].txid, a, GZ_HASH_LEN) == 0 && outs[0].vout == 2 && outs[0].value == 43000);
  CHECK(outs[0].confirmed && outs[0].height == 329438);
  CHECK(memcmp(outs[0].block_hash, h38, GZ_HASH_LEN) == 0);
  /* the lookup key is SHA-256(script) in hash order, not reversed: only that
   * address is routed in the fake, as only that one answers on real servers */
  CHECK(strcmp(x.fake.last_url, BASE "/scripthash/" SCRIPT_A2_HASH "/utxo") == 0);
  CHECK(x.fake.unexpected == 0);

  fake_set(&x.fake, false, BASE "/scripthash/" SCRIPT_A2_HASH "/utxo", 200, "[]");
  CHECK_RESULT(gz_chain_script_outputs(&x.chain, script, script_len, outs, 4, &n, NULL), GZ_CHAIN_OK);
  CHECK(n == 0);

  /* two entries, one in the mempool, returned sorted by txid then vout */
  const char *two =
      "[{\"txid\":\"" TX_SPENDER "\",\"vout\":1,\"status\":{\"confirmed\":false},\"value\":5},"
      "{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":true,\"block_height\":329438,"
      "\"block_hash\":" H38 ",\"block_time\":1793823982},\"value\":43000}]";
  fake_set(&x.fake, false, BASE "/scripthash/" SCRIPT_A2_HASH "/utxo", 200, two);
  CHECK_RESULT(gz_chain_script_outputs(&x.chain, script, script_len, outs, 4, &n, NULL), GZ_CHAIN_OK);
  CHECK(n == 2);
  CHECK(memcmp(outs[0].txid, outs[1].txid, GZ_HASH_LEN) < 0);
  int mempool_entries = (!outs[0].confirmed) + (!outs[1].confirmed);
  CHECK(mempool_entries == 1);

  /* more entries than the caller has room for */
  CHECK_RESULT(gz_chain_script_outputs(&x.chain, script, script_len, outs, 1, &n, NULL),
               GZ_CHAIN_TOO_LARGE);
  CHECK(n == 0);
  fx_close(&x);
}

#define UTXO_OK_FIELDS "\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":false},\"value\":43000"

static void test_utxo_parser_strict(test_state *T) {
  gz_chain_output outs[4];
  size_t n;
  const char *good = "[{" UTXO_OK_FIELDS "}]";
  CHECK(gz_es_parse_utxos(good, strlen(good), outs, 4, &n) == GZ_ES_PARSE_OK && n == 1);
  static const char *bad[] = {
      "",
      "{}",
      "null",
      "[1]",
      "[[]]",
      "[{}]",
      "[{" UTXO_OK_FIELDS "},]",
      "[{" UTXO_OK_FIELDS ",\"extra\":1}]",
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":false}}]",   /* no value */
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"value\":43000}]",                     /* no status */
      "[{\"vout\":2,\"status\":{\"confirmed\":false},\"value\":43000}]",          /* no txid */
      "[{\"txid\":\"" TX_A "\",\"status\":{\"confirmed\":false},\"value\":43000}]",
      "[{\"txid\":\"" TX_A "\",\"vout\":-2,\"status\":{\"confirmed\":false},\"value\":43000}]",
      "[{\"txid\":\"" TX_A "\",\"vout\":4294967296,\"status\":{\"confirmed\":false},\"value\":1}]",
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":false},\"value\":-1}]",
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":false},\"value\":4.3e4}]",
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":false},\"value\":43000.5}]",
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":false},\"value\":\"43000\"}]",
      /* more than 21 million bitcoin */
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":false},\"value\":2100000000000001}]",
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":false},\"value\":18446744073709551616}]",
      "[{\"txid\":\"8690\",\"vout\":2,\"status\":{\"confirmed\":false},\"value\":43000}]",
      "[{\"txid\":null,\"vout\":2,\"status\":{\"confirmed\":false},\"value\":43000}]",
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":true,\"value\":43000}]",
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":true},\"value\":43000}]",
      /* the same outpoint twice */
      "[{" UTXO_OK_FIELDS "},{" UTXO_OK_FIELDS "}]",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    T->checks++;
    if (gz_es_parse_utxos(bad[i], strlen(bad[i]), outs, 4, &n) != GZ_ES_PARSE_MALFORMED) {
      T->failed++;
      fprintf(stderr, "  accepted malformed utxo list #%zu: %s\n", i, bad[i]);
    }
  }
  /* exactly the largest amount is allowed */
  const char *max = "[{\"txid\":\"" TX_A "\",\"vout\":0,\"status\":{\"confirmed\":false},\"value\":2100000000000000}]";
  CHECK(gz_es_parse_utxos(max, strlen(max), outs, 4, &n) == GZ_ES_PARSE_OK &&
        outs[0].value == GZ_MAX_MONEY);

  /* a server claiming far more outputs than the caller has room for: the
   * count is taken from what is actually there, never from a number */
  static char many[60000];
  size_t pos = 0;
  many[pos++] = '[';
  for (int i = 0; i < 300; i++) {
    pos += (size_t)snprintf(many + pos, sizeof many - pos,
                            "%s{\"txid\":\"" TX_A "\",\"vout\":%d,\"status\":{\"confirmed\":false},\"value\":1}",
                            i ? "," : "", i);
  }
  many[pos++] = ']';
  gz_chain_output room[8];
  CHECK(gz_es_parse_utxos(many, pos, room, 8, &n) != GZ_ES_PARSE_OK);
  static gz_chain_output big[300];
  CHECK(gz_es_parse_utxos(many, pos, big, 300, &n) == GZ_ES_PARSE_OK && n == 300);
  CHECK(big[0].vout == 0 && big[299].vout == 299);
  CHECK(gz_es_parse_utxos(many, pos, big, 299, &n) == GZ_ES_PARSE_TOO_MANY);
}

/* ---- outspend ---- */

static void test_outspend(test_state *T) {
  fixture x;
  gz_outspend o;
  uint8_t a[GZ_HASH_LEN], sp[GZ_HASH_LEN], h39[GZ_HASH_LEN];
  fx_open(&x);
  test_hash(TX_A, a);
  test_hash(TX_SPENDER, sp);
  test_hash(HASH_329439, h39);

  CHECK_RESULT(gz_chain_outspend(&x.chain, a, 0, &o), GZ_CHAIN_OK);
  CHECK(o.spent && o.spender_vin == 0 && o.confirmed && o.height == 329439);
  CHECK(memcmp(o.spender_txid, sp, GZ_HASH_LEN) == 0);
  CHECK(memcmp(o.block_hash, h39, GZ_HASH_LEN) == 0);

  CHECK_RESULT(gz_chain_outspend(&x.chain, a, 2, &o), GZ_CHAIN_OK);
  CHECK(!o.spent && o.height == 0 && !o.confirmed);

  /* spent by a transaction still in the mempool */
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/outspend/2", 200,
           "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":3,\"status\":{\"confirmed\":false}}");
  CHECK_RESULT(gz_chain_outspend(&x.chain, a, 2, &o), GZ_CHAIN_OK);
  CHECK(o.spent && o.spender_vin == 3 && !o.confirmed && o.height == 0);

  static const char *bad[] = {
      "",
      "{}",
      "[]",
      "{\"spent\":\"false\"}",
      "{\"spent\":0}",
      "{\"spent\":true}", /* spent, by nothing */
      "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":0}",
      "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"status\":{\"confirmed\":false}}",
      "{\"spent\":true,\"vin\":0,\"status\":{\"confirmed\":false}}",
      "{\"spent\":false,\"txid\":\"" TX_SPENDER "\"}", /* unspent, with a spender */
      "{\"spent\":false,\"vin\":0}",
      "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":-1,\"status\":{\"confirmed\":false}}",
      "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":4294967296,\"status\":{\"confirmed\":false}}",
      "{\"spent\":true,\"txid\":\"xyz\",\"vin\":0,\"status\":{\"confirmed\":false}}",
      "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":0,\"status\":{}}",
      "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":0,\"status\":{\"confirmed\":true}}",
      "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":0,\"status\":[]}",
      "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":0,\"status\":{\"confirmed\":false},\"x\":1}",
      "{\"spent\":false,\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":0,\"status\":{\"confirmed\":false}}",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    fake_set(&x.fake, false, BASE "/tx/" TX_A "/outspend/2", 200, bad[i]);
    T->checks++;
    if (gz_chain_outspend(&x.chain, a, 2, &o) != GZ_CHAIN_MALFORMED) {
      T->failed++;
      fprintf(stderr, "  accepted malformed outspend #%zu: %s\n", i, bad[i]);
    }
    CHECK(!o.spent);
  }
  fx_close(&x);
}

/* ---- raw transaction ---- */

static void test_raw_tx(test_state *T) {
  fixture x;
  uint8_t a[GZ_HASH_LEN], none[GZ_HASH_LEN], buf[1024], check[GZ_HASH_LEN];
  size_t len = 0;
  fx_open(&x);
  test_hash(TX_A, a);
  test_hash(TX_NONE, none);

  CHECK_RESULT(gz_chain_raw_tx(&x.chain, a, buf, sizeof buf, &len), GZ_CHAIN_OK);
  CHECK(len == 244);
  CHECK(gz_txid_from_raw(buf, len, check) && memcmp(check, a, GZ_HASH_LEN) == 0);
  CHECK_RESULT(gz_chain_raw_tx(&x.chain, a, buf, 244, &len), GZ_CHAIN_OK); /* fits exactly */
  CHECK_RESULT(gz_chain_raw_tx(&x.chain, a, buf, 243, &len), GZ_CHAIN_TOO_LARGE);
  CHECK(len == 0);
  CHECK_RESULT(gz_chain_raw_tx(&x.chain, none, buf, sizeof buf, &len), GZ_CHAIN_NOT_FOUND);

  /* a real transaction, but not the one asked for */
  fake_set_file(&x.fake, BASE "/tx/" TX_A "/hex", 200, "tx_spender_hex.txt");
  CHECK_RESULT(gz_chain_raw_tx(&x.chain, a, buf, sizeof buf, &len), GZ_CHAIN_MALFORMED);
  CHECK(len == 0);

  size_t hex_len;
  char *hex = test_read_data("tx_a_hex.txt", &hex_len);
  hex[120] = hex[120] == '0' ? '1' : '0'; /* one output byte changed */
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/hex", 200, hex);
  CHECK_RESULT(gz_chain_raw_tx(&x.chain, a, buf, sizeof buf, &len), GZ_CHAIN_MALFORMED);
  hex[hex_len - 1] = '\0'; /* odd number of characters */
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/hex", 200, hex);
  CHECK_RESULT(gz_chain_raw_tx(&x.chain, a, buf, sizeof buf, &len), GZ_CHAIN_MALFORMED);
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/hex", 200, "");
  CHECK_RESULT(gz_chain_raw_tx(&x.chain, a, buf, sizeof buf, &len), GZ_CHAIN_MALFORMED);
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/hex", 200, "not hex at all");
  CHECK_RESULT(gz_chain_raw_tx(&x.chain, a, buf, sizeof buf, &len), GZ_CHAIN_MALFORMED);
  free(hex);
  fx_close(&x);
}

/* ---- Merkle proof ---- */

static void test_merkle_proof_call(test_state *T) {
  fixture x;
  gz_merkle_proof p;
  uint8_t a[GZ_HASH_LEN], none[GZ_HASH_LEN], hdr[GZ_HEADER_LEN];
  fx_open(&x);
  test_hash(TX_A, a);
  test_hash(TX_NONE, none);
  CHECK_RESULT(gz_chain_merkle_proof(&x.chain, a, &p), GZ_CHAIN_OK);
  CHECK(p.block_height == 329438 && p.pos == 1 && p.depth == 8);
  CHECK_RESULT(gz_chain_block_header(&x.chain, 329438, hdr), GZ_CHAIN_OK);
  CHECK(gz_merkle_verify(a, &p, hdr));
  CHECK_RESULT(gz_chain_merkle_proof(&x.chain, none, &p), GZ_CHAIN_NOT_FOUND);
  CHECK(p.depth == 0);
  fx_close(&x);
}

static void test_merkle_parser_strict(test_state *T) {
  gz_merkle_proof p;
  char buf[4096];
  const char *one_tx = "{\"block_height\":5,\"merkle\":[],\"pos\":0}";
  CHECK(gz_es_parse_merkle_proof(one_tx, strlen(one_tx), &p) && p.depth == 0);
  static const char *bad[] = {
      "",
      "{}",
      "[]",
      "{\"block_height\":5,\"merkle\":[]}",
      "{\"block_height\":5,\"pos\":0}",
      "{\"merkle\":[],\"pos\":0}",
      "{\"block_height\":5,\"merkle\":[],\"pos\":1}", /* position outside a tree of one */
      "{\"block_height\":5,\"merkle\":[\"" TX_A "\"],\"pos\":2}",
      "{\"block_height\":5,\"merkle\":[\"" TX_A "\"],\"pos\":-1}",
      "{\"block_height\":5,\"merkle\":[\"" TX_A "\"],\"pos\":4294967296}",
      "{\"block_height\":-5,\"merkle\":[\"" TX_A "\"],\"pos\":0}",
      "{\"block_height\":5,\"merkle\":[\"abcd\"],\"pos\":0}",
      "{\"block_height\":5,\"merkle\":[7],\"pos\":0}",
      "{\"block_height\":5,\"merkle\":[[\"" TX_A "\"]],\"pos\":0}",
      "{\"block_height\":5,\"merkle\":[null],\"pos\":0}",
      "{\"block_height\":5,\"merkle\":\"" TX_A "\",\"pos\":0}",
      "{\"block_height\":5,\"merkle\":{},\"pos\":0}",
      "{\"block_height\":5,\"merkle\":[],\"pos\":0,\"extra\":true}",
      "{\"block_height\":5,\"merkle\":[],\"merkle\":[],\"pos\":0}",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    T->checks++;
    if (gz_es_parse_merkle_proof(bad[i], strlen(bad[i]), &p)) {
      T->failed++;
      fprintf(stderr, "  accepted malformed proof #%zu: %s\n", i, bad[i]);
    }
  }
  /* 32 nodes is the most accepted; 33 is refused */
  for (int count = 32; count <= 33; count++) {
    size_t pos = (size_t)snprintf(buf, sizeof buf, "{\"block_height\":5,\"merkle\":[");
    for (int i = 0; i < count; i++)
      pos += (size_t)snprintf(buf + pos, sizeof buf - pos, "%s\"" TX_A "\"", i ? "," : "");
    pos += (size_t)snprintf(buf + pos, sizeof buf - pos, "],\"pos\":7}");
    CHECK(gz_es_parse_merkle_proof(buf, pos, &p) == (count == 32));
  }
}

/* ---- broadcast ---- */

static size_t load_raw(const char *file, uint8_t *out, size_t cap) {
  size_t len, raw_len = 0;
  char *hex = test_read_data(file, &len);
  if (!gz_hex_decode(hex, len, out, cap, &raw_len)) exit(2);
  free(hex);
  return raw_len;
}

static void test_broadcast(test_state *T) {
  fixture x;
  gz_broadcast_result br;
  uint8_t raw[1024], a[GZ_HASH_LEN];
  size_t hex_len;
  fx_open(&x);
  size_t len = load_raw("tx_a_hex.txt", raw, sizeof raw);
  char *hex = test_read_data("tx_a_hex.txt", &hex_len);
  test_hash(TX_A, a);

  fake_set(&x.fake, true, BASE "/tx", 200, TX_A);
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_OK);
  CHECK(br.result == GZ_CHAIN_OK && br.server_status == 200 && br.reason[0] == '\0');
  CHECK(memcmp(br.txid, a, GZ_HASH_LEN) == 0);
  /* what went over the wire is the lowercase hex of the transaction */
  CHECK(x.fake.last_body_len == hex_len && memcmp(x.fake.last_body, hex, hex_len) == 0);

  /* the txid may come back with a newline or spaces around it */
  fake_set(&x.fake, true, BASE "/tx", 200, TX_A "\n");
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_OK);
  fake_set(&x.fake, true, BASE "/tx", 200, " \t" TX_A "\r\n ");
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_OK);
  CHECK(memcmp(br.txid, a, GZ_HASH_LEN) == 0 && !br.already_known);
  fake_set(&x.fake, true, BASE "/tx", 200, TX_A "\n" TX_A); /* but only one txid */
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_MALFORMED);
  fake_set(&x.fake, true, BASE "/tx", 200, " \n ");
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_MALFORMED);

  /* an ordinary refusal, with the server's words kept */
  const char *low_fee = "sendrawtransaction RPC error -26: min relay fee not met, 110 < 141";
  fake_set(&x.fake, true, BASE "/tx", 400, low_fee);
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_REJECTED);
  CHECK(br.result == GZ_CHAIN_REJECTED && br.server_status == 400 && !br.already_known);
  CHECK(strcmp(br.reason, low_fee) == 0);

  /* "I already have it", in the two operators' own recorded words. The
   * server does have transaction A (confirmed), so this is success. */
  char *m = test_read_data("post_known_mempool.txt", NULL);
  char *b = test_read_data("post_known_blockstream.txt", NULL);
  fake_set(&x.fake, true, BASE "/tx", 400, m);
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_OK);
  CHECK(br.result == GZ_CHAIN_OK && br.already_known && br.server_status == 400);
  CHECK(memcmp(br.txid, a, GZ_HASH_LEN) == 0);
  CHECK(strcmp(br.reason, m) == 0); /* the words are still there to read */
  fake_set(&x.fake, true, BASE "/tx", 400, b);
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_OK);
  CHECK(br.already_known && strcmp(br.reason, b) == 0);
  /* also when the transaction is only in its mempool */
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/status", 200, "{\"confirmed\":false}");
  fake_set(&x.fake, true, BASE "/tx", 400, "sendrawtransaction RPC error -27: Transaction already in block chain");
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_OK);
  CHECK(br.already_known);
  /* A server that says "already known" but cannot show the transaction is
   * not believed: that stays a refusal. */
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/hex", 404, "Transaction not found");
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_REJECTED);
  CHECK(!br.already_known && br.result == GZ_CHAIN_REJECTED);
  CHECK(strstr(br.reason, "already in block chain") != NULL);
  fake_set_file(&x.fake, BASE "/tx/" TX_A "/hex", 200, "tx_a_hex.txt");
  fake_set_file(&x.fake, BASE "/tx/" TX_A "/status", 200, "tx_a_status.json");

  CHECK(gz_es_reason_is_already_known("txn-already-in-mempool"));
  CHECK(gz_es_reason_is_already_known("TXN-ALREADY-KNOWN"));
  CHECK(gz_es_reason_is_already_known("sendrawtransaction RPC error: {\"code\":-27,\"message\":\"Transaction outputs already in utxo set\"}"));
  CHECK(!gz_es_reason_is_already_known("min relay fee not met"));
  CHECK(!gz_es_reason_is_already_known("bad-txns-inputs-missingorspent"));
  CHECK(!gz_es_reason_is_already_known(""));
  CHECK(!gz_es_reason_is_already_known(NULL));

  /* a long reason with control and non-ASCII bytes is cut and cleaned */
  char nasty[600];
  memset(nasty, 'A', sizeof nasty);
  nasty[3] = '\n';
  nasty[4] = (char)0xff;
  nasty[5] = 0x1b;
  nasty[sizeof nasty - 1] = '\0';
  fake_set(&x.fake, true, BASE "/tx", 400, nasty);
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_REJECTED);
  CHECK(strlen(br.reason) == GZ_REASON_MAX - 1);
  CHECK(br.reason[3] == '?' && br.reason[4] == '?' && br.reason[5] == '?' && br.reason[6] == 'A');

  /* "accepted", but the id returned is not the id of what was sent */
  fake_set(&x.fake, true, BASE "/tx", 200, TX_B);
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_MALFORMED);
  fake_set(&x.fake, true, BASE "/tx", 200, "ok");
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_MALFORMED);
  fake_set(&x.fake, true, BASE "/tx", 302, "");
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_MALFORMED);

  /* bytes that are not a transaction are never sent */
  unsigned before = x.fake.requests;
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len - 1, &br), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_broadcast(&x.chain, (const uint8_t *)"zz", 2, &br), GZ_CHAIN_INVALID_ARG);
  CHECK(br.result == GZ_CHAIN_INVALID_ARG);
  CHECK(x.fake.requests == before);
  free(hex);
  free(m);
  free(b);
  fx_close(&x);
}

static void test_broadcast_retry_rules(test_state *T) {
  fixture x;
  gz_broadcast_result br;
  uint8_t raw[1024];
  fx_open(&x);
  size_t len = load_raw("tx_a_hex.txt", raw, sizeof raw);
  fake_set(&x.fake, true, BASE "/tx", 200, TX_A);

  /* a timeout may mean the server acted: not repeated, reported unreachable */
  fake_once(&x.fake, true, BASE "/tx", GZ_HTTP_E_TIMEOUT, 0, "", 1);
  unsigned before = x.fake.requests;
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_UNREACHABLE);
  CHECK(x.fake.requests == before + 1);
  CHECK(br.server_status == 0);
  /* the same for a 5xx answer */
  fake_once(&x.fake, true, BASE "/tx", GZ_HTTP_OK, 502, "bad gateway", 1);
  before = x.fake.requests;
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_UNREACHABLE);
  CHECK(x.fake.requests == before + 1);
  /* never connected: nothing was sent, so it is tried again */
  fake_once(&x.fake, true, BASE "/tx", GZ_HTTP_E_CONNECT, 0, "", 2);
  before = x.fake.requests;
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_OK);
  CHECK(x.fake.requests == before + 3);
  /* 429 is a refusal to look at the request: tried again */
  fake_once(&x.fake, true, BASE "/tx", GZ_HTTP_OK, 429, "slow down", 1);
  before = x.fake.requests;
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_OK);
  CHECK(x.fake.requests == before + 2);
  fx_close(&x);
}

/* ---- fee estimates ---- */

static const gz_fee_estimate *find_fee(const gz_fee_estimates *f, uint16_t target) {
  for (size_t i = 0; i < f->count; i++)
    if (f->entries[i].target == target) return &f->entries[i];
  return NULL;
}

static void test_fee_estimates(test_state *T) {
  fixture x;
  gz_fee_estimates f;
  fx_open(&x);
  /* mempool.space's recorded answer, which arrives with status 203 */
  CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_OK);
  CHECK(f.count == 28);
  CHECK(f.entries[0].target == 1 && f.entries[0].sat_per_kvb == 1000);
  CHECK(find_fee(&f, 3) != NULL && find_fee(&f, 3)->sat_per_kvb == 500);
  CHECK(find_fee(&f, 1008) != NULL && find_fee(&f, 1008)->sat_per_kvb == 100);
  CHECK(f.entries[27].target == 1008);
  for (size_t i = 1; i < f.count; i++) CHECK(f.entries[i - 1].target < f.entries[i].target);

  /* blockstream.info's recorded answer: unordered keys, long fractions */
  fake_set_file(&x.fake, BASE "/fee-estimates", 200, "fee_estimates_blockstream.json");
  CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_OK);
  CHECK(f.count == 28);
  CHECK(find_fee(&f, 1) != NULL && find_fee(&f, 1)->sat_per_kvb == 10000);
  CHECK(find_fee(&f, 8) != NULL && find_fee(&f, 8)->sat_per_kvb == 3398);
  CHECK(find_fee(&f, 144) != NULL && find_fee(&f, 144)->sat_per_kvb == 100); /* 0.0999.. rounded up */

  static const char *bad[] = {
      "",
      "[]",
      "[1,2]",
      "null",
      "{\"1\":-1}",
      "{\"1\":\"1.0\"}",
      "{\"1\":null}",
      "{\"1\":1e3}",
      "{\"1\":{}}",
      "{\"0\":1}",
      "{\"1009\":1}",
      "{\"01\":1}",
      "{\"-1\":1}",
      "{\"1.5\":1}",
      "{\"abc\":1}",
      "{\"\":1}",
      "{\"1\":1,\"1\":2}",
      "{\"1\":99999999999999999999}",
      "{\"1\":3000000000000}", /* above every coin there is, per kvB */
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    fake_set(&x.fake, false, BASE "/fee-estimates", 200, bad[i]);
    T->checks++;
    if (gz_chain_fee_estimates(&x.chain, &f) != GZ_CHAIN_MALFORMED) {
      T->failed++;
      fprintf(stderr, "  accepted malformed fee answer #%zu: %s\n", i, bad[i]);
    }
    CHECK(f.count == 0);
  }
  fake_set(&x.fake, false, BASE "/fee-estimates", 200, "{}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_OK);
  CHECK(f.count == 0);

  /* more targets than the interface keeps */
  char buf[4096];
  size_t pos = 0;
  buf[pos++] = '{';
  for (int i = 1; i <= GZ_FEE_MAX_TARGETS + 1; i++)
    pos += (size_t)snprintf(buf + pos, sizeof buf - pos, "%s\"%d\":1", i > 1 ? "," : "", i);
  buf[pos++] = '}';
  buf[pos] = '\0';
  fake_set(&x.fake, false, BASE "/fee-estimates", 200, buf);
  CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_MALFORMED);
  fx_close(&x);
}

/* ---- retries, backoff, rate limit, time limit ---- */

static void test_retries_and_backoff(test_state *T) {
  fixture x;
  uint8_t h[GZ_HASH_LEN];
  fx_open(&x);
  const char *url = BASE "/block-height/329438";

  /* two failures, then an answer */
  fake_once(&x.fake, false, url, GZ_HTTP_E_TIMEOUT, 0, "", 1);
  fake_once(&x.fake, false, url, GZ_HTTP_E_CONNECT, 0, "", 1);
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 329438, h), GZ_CHAIN_OK);
  CHECK(x.fake.requests == 3);
  CHECK(x.fake.n_sleeps == 2 && x.fake.sleeps[0] == 500 && x.fake.sleeps[1] == 1000);

  /* 429 and 503 are "try later" */
  fake_once(&x.fake, false, url, GZ_HTTP_OK, 429, "Too Many Requests", 1);
  fake_once(&x.fake, false, url, GZ_HTTP_OK, 503, "Service Unavailable", 1);
  x.fake.requests = 0;
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 329438, h), GZ_CHAIN_OK);
  CHECK(x.fake.requests == 3);

  /* a server that never recovers: exactly max_attempts tries, then give up */
  fake_once(&x.fake, false, url, GZ_HTTP_OK, 500, "oops", 50);
  x.fake.requests = 0;
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 329438, h), GZ_CHAIN_UNREACHABLE);
  CHECK(x.fake.requests == 3);
  x.fake.requests = 0;
  x.fake.down = true;
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 329437, h), GZ_CHAIN_UNREACHABLE);
  CHECK(x.fake.requests == 3);
  x.fake.down = false;

  /* a definite answer is not retried, whatever it is */
  x.fake.requests = 0;
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 329440, h), GZ_CHAIN_NOT_FOUND);
  CHECK(x.fake.requests == 1);
  fx_close(&x);
}

static void test_rate_limit(test_state *T) {
  fixture x;
  uint8_t h[GZ_HASH_LEN];
  fx_open(&x);
  for (int i = 0; i < 5; i++)
    CHECK_RESULT(gz_chain_block_hash(&x.chain, 329438, h), GZ_CHAIN_OK);
  CHECK(x.fake.requests == 5);
  /* no two requests start less than min_interval_ms (250) apart */
  for (unsigned i = 1; i < x.fake.requests; i++)
    CHECK(x.fake.starts[i] - x.fake.starts[i - 1] >= 250);
  /* and it does not wait when enough time has passed anyway */
  size_t sleeps = x.fake.n_sleeps;
  x.fake.now_ms += 10000;
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 329438, h), GZ_CHAIN_OK);
  CHECK(x.fake.n_sleeps == sleeps);
  fx_close(&x);
}

static void test_time_limit_on_every_request(test_state *T) {
  fixture x;
  gz_chain_tip tip;
  gz_tx_status st;
  gz_fee_estimates f;
  uint8_t a[GZ_HASH_LEN];
  fx_open(&x);
  test_hash(TX_A, a);
  CHECK_RESULT(gz_chain_tip_get(&x.chain, &tip), GZ_CHAIN_OK);
  CHECK(x.fake.last_timeout_ms == 15000);
  CHECK_RESULT(gz_chain_tx_status(&x.chain, a, &st), GZ_CHAIN_OK);
  CHECK(x.fake.last_timeout_ms == 15000);
  CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_OK);
  CHECK(x.fake.last_timeout_ms == 15000);
  /* a server that only ever times out */
  fake_once(&x.fake, false, BASE "/blocks/tip/height", GZ_HTTP_E_TIMEOUT, 0, "", 50);
  CHECK_RESULT(gz_chain_tip_get(&x.chain, &tip), GZ_CHAIN_UNREACHABLE);
  CHECK(tip.height == 0);
  fx_close(&x);
}

/* ---- size caps ---- */

static void test_size_caps(test_state *T) {
  fixture x;
  gz_chain_tip tip;
  gz_tx_status st;
  gz_outspend o;
  gz_merkle_proof p;
  gz_fee_estimates f;
  gz_chain_output outs[2];
  uint8_t a[GZ_HASH_LEN], h[GZ_HASH_LEN], hdr[GZ_HEADER_LEN], script[32];
  size_t n, script_len;
  static char huge[700000];
  fx_open(&x);
  test_hash(TX_A, a);
  CHECK(gz_hex_decode(SCRIPT_A2, strlen(SCRIPT_A2), script, sizeof script, &script_len));
  memset(huge, '1', sizeof huge - 1);
  huge[sizeof huge - 1] = '\0';

  /* each call asks the transport for no more than it can need */
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 329438, h), GZ_CHAIN_OK);
  CHECK(x.fake.last_cap == 64);
  CHECK_RESULT(gz_chain_block_header(&x.chain, 329438, hdr), GZ_CHAIN_OK);
  CHECK(x.fake.last_cap == 160);
  CHECK_RESULT(gz_chain_outspend(&x.chain, a, 0, &o), GZ_CHAIN_OK);
  CHECK(x.fake.last_cap <= 512);
  CHECK_RESULT(gz_chain_merkle_proof(&x.chain, a, &p), GZ_CHAIN_OK);
  CHECK(x.fake.last_cap <= 4096);
  CHECK_RESULT(gz_chain_script_outputs(&x.chain, script, script_len, outs, 2, &n, NULL), GZ_CHAIN_OK);
  CHECK(x.fake.last_cap <= 2 * 320 + 16);

  /* an oversized body on every endpoint is refused, not read */
  fake_set(&x.fake, false, BASE "/blocks/tip/height", 200, "12345678901");
  CHECK_RESULT(gz_chain_tip_get(&x.chain, &tip), GZ_CHAIN_TOO_LARGE);
  fake_set(&x.fake, false, BASE "/blocks/tip/height", 200, "329439");
  fake_set(&x.fake, false, BASE "/block-height/329438", 200, huge);
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 329438, h), GZ_CHAIN_TOO_LARGE);
  CHECK_RESULT(gz_chain_block_header(&x.chain, 329438, hdr), GZ_CHAIN_TOO_LARGE);
  fake_set(&x.fake, false, BASE "/block/" HASH_329439 "/header", 200, huge);
  CHECK_RESULT(gz_chain_block_header(&x.chain, 329439, hdr), GZ_CHAIN_TOO_LARGE);
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/status", 200, huge);
  CHECK_RESULT(gz_chain_tx_status(&x.chain, a, &st), GZ_CHAIN_TOO_LARGE);
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/outspend/0", 200, huge);
  CHECK_RESULT(gz_chain_outspend(&x.chain, a, 0, &o), GZ_CHAIN_TOO_LARGE);
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/merkle-proof", 200, huge);
  CHECK_RESULT(gz_chain_merkle_proof(&x.chain, a, &p), GZ_CHAIN_TOO_LARGE);
  fake_set(&x.fake, false, BASE "/fee-estimates", 200, huge);
  CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_TOO_LARGE);
  fake_set(&x.fake, false, BASE "/scripthash/" SCRIPT_A2_HASH "/utxo", 200, huge);
  CHECK_RESULT(gz_chain_script_outputs(&x.chain, script, script_len, outs, 2, &n, NULL),
               GZ_CHAIN_TOO_LARGE);
  /* a transaction larger than the whole response buffer (512 KiB) */
  static uint8_t txbuf[400000];
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/hex", 200, huge);
  CHECK_RESULT(gz_chain_raw_tx(&x.chain, a, txbuf, sizeof txbuf, &n), GZ_CHAIN_TOO_LARGE);
  /* an oversized refusal text on broadcast */
  uint8_t raw[1024];
  gz_broadcast_result br;
  size_t len = load_raw("tx_a_hex.txt", raw, sizeof raw);
  fake_set(&x.fake, true, BASE "/tx", 400, huge);
  CHECK_RESULT(gz_chain_broadcast(&x.chain, raw, len, &br), GZ_CHAIN_TOO_LARGE);
  /* an oversize answer is not retried */
  x.fake.requests = 0;
  CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_TOO_LARGE);
  CHECK(x.fake.requests == 1);

  /* a transport that breaks its promise and reports more bytes than the cap
   * must not make the backend read past its buffer */
  x.fake.overrun = true;
  CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_TOO_LARGE);
  CHECK_RESULT(gz_chain_block_hash(&x.chain, 329438, h), GZ_CHAIN_TOO_LARGE);
  fx_close(&x);
}

/* ---- a small response buffer still works and still caps ---- */

static void test_small_buffer(test_state *T) {
  fake_http fake;
  gz_esplora_config cfg;
  gz_chain c;
  uint8_t a[GZ_HASH_LEN], buf[1024];
  gz_tx_status st;
  size_t n;
  fake_init(&fake);
  fake_load_honest(&fake, BASE, false);
  gz_http http = fake_transport(&fake);
  gz_esplora_config_default(&cfg);
  cfg.base_url = BASE;
  cfg.max_response_bytes = 4096;
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_OK);
  test_hash(TX_A, a);
  CHECK_RESULT(gz_chain_raw_tx(&c, a, buf, sizeof buf, &n), GZ_CHAIN_OK);
  CHECK(n == 244 && fake.last_cap <= 4096);
  CHECK_RESULT(gz_chain_tx_status(&c, a, &st), GZ_CHAIN_OK);
  static char big[9000];
  memset(big, 'a', sizeof big - 1);
  fake_set(&fake, false, BASE "/tx/" TX_A "/hex", 200, big);
  CHECK_RESULT(gz_chain_raw_tx(&c, a, buf, sizeof buf, &n), GZ_CHAIN_TOO_LARGE);
  gz_chain_destroy(&c);
  fake_free(&fake);
}

/* ---- block summary ---- */

static void test_block_summary(test_state *T) {
  fixture x;
  gz_block_summary s;
  uint8_t h38[GZ_HASH_LEN], cb[GZ_HASH_LEN];
  size_t len;
  fx_open(&x);
  test_hash(HASH_329438, h38);
  test_hash(TX_COINBASE, cb);
  CHECK_RESULT(gz_chain_block_summary(&x.chain, 329438, &s), GZ_CHAIN_OK);
  CHECK(memcmp(s.hash, h38, GZ_HASH_LEN) == 0 && s.tx_count == 243);
  CHECK(memcmp(s.coinbase_txid, cb, GZ_HASH_LEN) == 0);
  CHECK_RESULT(gz_chain_block_summary(&x.chain, 329440, &s), GZ_CHAIN_NOT_FOUND);
  CHECK_RESULT(gz_chain_block_summary(&x.chain, GZ_MAX_HEIGHT + 1u, &s), GZ_CHAIN_INVALID_ARG);

  /* a description of some other block */
  fake_set_file(&x.fake, BASE "/block/" HASH_329438, 200, "block_329439.json");
  CHECK_RESULT(gz_chain_block_summary(&x.chain, 329438, &s), GZ_CHAIN_MALFORMED);
  CHECK(s.tx_count == 0);
  /* the right id but another height */
  char *json = test_read_data("block_329438.json", &len);
  char *at = strstr(json, "\"height\":329438");
  CHECK(at != NULL);
  if (at != NULL) memcpy(at, "\"height\":329430", 15);
  fake_set(&x.fake, false, BASE "/block/" HASH_329438, 200, json);
  CHECK_RESULT(gz_chain_block_summary(&x.chain, 329438, &s), GZ_CHAIN_MALFORMED);
  free(json);
  fake_set_file(&x.fake, BASE "/block/" HASH_329438, 200, "block_329438.json");
  fake_set(&x.fake, false, BASE "/block/" HASH_329438 "/txid/0", 200, "nonsense");
  CHECK_RESULT(gz_chain_block_summary(&x.chain, 329438, &s), GZ_CHAIN_MALFORMED);
  fake_set(&x.fake, false, BASE "/block/" HASH_329438 "/txid/0", 404, "tx index out of range");
  CHECK_RESULT(gz_chain_block_summary(&x.chain, 329438, &s), GZ_CHAIN_MALFORMED);
  fx_close(&x);
}

#define BLOCK_FIELDS_BEFORE_COUNT \
  "\"id\":\"" HASH_329438 "\",\"height\":329438,\"version\":536870912,\"timestamp\":1793823982,"
#define BLOCK_FIELDS_AFTER_COUNT                                                              \
  "\"size\":122599,\"weight\":271387,\"merkle_root\":\"" HASH_329437 "\","                    \
  "\"previousblockhash\":\"" HASH_329437 "\",\"mediantime\":1793816297,\"nonce\":162450084," \
  "\"bits\":487902597,\"difficulty\":0.048"

static void test_block_parser_strict(test_state *T) {
  gz_es_block b;
  size_t len;
  char *real = test_read_data("block_329438.json", &len);
  CHECK(gz_es_parse_block(real, len, &b) && b.tx_count == 243 && b.height == 329438);
  free(real);
  const char *good = "{" BLOCK_FIELDS_BEFORE_COUNT "\"tx_count\":1," BLOCK_FIELDS_AFTER_COUNT "}";
  CHECK(gz_es_parse_block(good, strlen(good), &b) && b.tx_count == 1);
  /* block 0 has no predecessor; a negative version is a legal header value */
  const char *genesis =
      "{\"id\":\"" HASH_329438 "\",\"height\":0,\"version\":-1,\"timestamp\":1,\"tx_count\":1,"
      "\"size\":285,\"weight\":1140,\"merkle_root\":\"" HASH_329437 "\",\"previousblockhash\":null,"
      "\"mediantime\":1,\"nonce\":1,\"bits\":1,\"difficulty\":1}";
  CHECK(gz_es_parse_block(genesis, strlen(genesis), &b) && b.height == 0);
  static const char *bad[] = {
      "",
      "{}",
      "[]",
      "{" BLOCK_FIELDS_BEFORE_COUNT BLOCK_FIELDS_AFTER_COUNT "}",                       /* no tx_count */
      "{" BLOCK_FIELDS_BEFORE_COUNT "\"tx_count\":0," BLOCK_FIELDS_AFTER_COUNT "}",     /* an empty block */
      "{" BLOCK_FIELDS_BEFORE_COUNT "\"tx_count\":-3," BLOCK_FIELDS_AFTER_COUNT "}",
      "{" BLOCK_FIELDS_BEFORE_COUNT "\"tx_count\":1000001," BLOCK_FIELDS_AFTER_COUNT "}",
      "{" BLOCK_FIELDS_BEFORE_COUNT "\"tx_count\":4294967297," BLOCK_FIELDS_AFTER_COUNT "}",
      "{" BLOCK_FIELDS_BEFORE_COUNT "\"tx_count\":\"243\"," BLOCK_FIELDS_AFTER_COUNT "}",
      "{" BLOCK_FIELDS_BEFORE_COUNT "\"tx_count\":2.5," BLOCK_FIELDS_AFTER_COUNT "}",
      "{" BLOCK_FIELDS_BEFORE_COUNT "\"tx_count\":1,\"tx_count\":2," BLOCK_FIELDS_AFTER_COUNT "}",
      "{" BLOCK_FIELDS_BEFORE_COUNT "\"tx_count\":1," BLOCK_FIELDS_AFTER_COUNT ",\"extras\":{}}",
      "{" BLOCK_FIELDS_BEFORE_COUNT "\"tx_count\":1}",                                  /* fields missing */
      "{\"id\":\"abcd\",\"height\":1,\"version\":1,\"timestamp\":1,\"tx_count\":1," BLOCK_FIELDS_AFTER_COUNT "}",
      "{\"id\":\"" HASH_329438 "\",\"height\":2147483648,\"version\":1,\"timestamp\":1,\"tx_count\":1,"
      BLOCK_FIELDS_AFTER_COUNT "}",
      "{\"id\":\"" HASH_329438 "\",\"height\":1,\"version\":1.5,\"timestamp\":1,\"tx_count\":1,"
      BLOCK_FIELDS_AFTER_COUNT "}",
      "{\"id\":\"" HASH_329438 "\",\"height\":1,\"version\":1,\"timestamp\":-1,\"tx_count\":1,"
      BLOCK_FIELDS_AFTER_COUNT "}",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    T->checks++;
    if (gz_es_parse_block(bad[i], strlen(bad[i]), &b)) {
      T->failed++;
      fprintf(stderr, "  accepted malformed block #%zu: %s\n", i, bad[i]);
    }
  }
}

/* ---- which network a server is on ---- */

static void test_network_check(test_state *T) {
  fixture x;
  gz_network found = GZ_NET_MAINNET;
  fx_open(&x);
  CHECK_RESULT(gz_chain_check_network(&x.chain, GZ_NET_SIGNET), GZ_CHAIN_OK);
  CHECK(fake_hits(&x.fake, false, BASE "/block-height/0") == 1);
  CHECK_RESULT(gz_chain_check_network(&x.chain, GZ_NET_MAINNET), GZ_CHAIN_WRONG_NETWORK);
  CHECK_RESULT(gz_chain_check_network(&x.chain, GZ_NET_TESTNET4), GZ_CHAIN_WRONG_NETWORK);
  CHECK_RESULT(gz_chain_check_network(&x.chain, GZ_NET_TESTNET3), GZ_CHAIN_WRONG_NETWORK);
  CHECK_RESULT(gz_chain_check_network(&x.chain, GZ_NET_INVALID), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_check_network(&x.chain, (gz_network)12), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_identify_network(&x.chain, &found), GZ_CHAIN_OK);
  CHECK(found == GZ_NET_SIGNET);

  static const struct {
    const char *genesis;
    gz_network net;
  } nets[] = {{GENESIS_MAINNET, GZ_NET_MAINNET},
              {GENESIS_TESTNET3, GZ_NET_TESTNET3},
              {GENESIS_TESTNET4, GZ_NET_TESTNET4}};
  for (size_t i = 0; i < 3; i++) {
    fake_set(&x.fake, false, BASE "/block-height/0", 200, nets[i].genesis);
    CHECK_RESULT(gz_chain_identify_network(&x.chain, &found), GZ_CHAIN_OK);
    CHECK(found == nets[i].net);
    CHECK_RESULT(gz_chain_check_network(&x.chain, nets[i].net), GZ_CHAIN_OK);
    CHECK_RESULT(gz_chain_check_network(&x.chain, GZ_NET_SIGNET), GZ_CHAIN_WRONG_NETWORK);
  }
  /* some other chain altogether (a private signet, say) */
  fake_set(&x.fake, false, BASE "/block-height/0", 200, HASH_329437);
  CHECK_RESULT(gz_chain_identify_network(&x.chain, &found), GZ_CHAIN_WRONG_NETWORK);
  CHECK(found == GZ_NET_INVALID);
  CHECK_RESULT(gz_chain_check_network(&x.chain, GZ_NET_SIGNET), GZ_CHAIN_WRONG_NETWORK);
  /* a chain with no block 0 */
  fake_set(&x.fake, false, BASE "/block-height/0", 404, "Block not found");
  CHECK_RESULT(gz_chain_check_network(&x.chain, GZ_NET_SIGNET), GZ_CHAIN_WRONG_NETWORK);
  /* could not ask: that is not "wrong network" */
  x.fake.down = true;
  CHECK_RESULT(gz_chain_check_network(&x.chain, GZ_NET_SIGNET), GZ_CHAIN_UNREACHABLE);
  fx_close(&x);
}

/* ---- the fee rate policy ---- */

static void test_choose_fee_rate(test_state *T) {
  fixture x;
  gz_fee_choice c;
  fx_open(&x);
  /* Test networks: 0.1 sat/vB, and the server is not even asked. */
  static const gz_network tests[] = {GZ_NET_SIGNET, GZ_NET_TESTNET3, GZ_NET_TESTNET4};
  for (size_t i = 0; i < 3; i++) {
    CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, tests[i], 6, 200000, &c), GZ_CHAIN_OK);
    CHECK(c.sat_per_kvb == 100 && c.source == GZ_FEE_FROM_TEST_DEFAULT && !c.capped);
  }
  CHECK(x.fake.requests == 0);
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_SIGNET, 6, 50, &c), GZ_CHAIN_OK);
  CHECK(c.sat_per_kvb == 50 && c.capped); /* the caller's ceiling still binds */

  /* Mainnet: from the estimates, never above the caller's ceiling. */
  fake_set(&x.fake, false, BASE "/fee-estimates", 200, "{\"1\":80.5,\"6\":20,\"144\":2}");
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_MAINNET, 6, 200000, &c), GZ_CHAIN_OK);
  CHECK(c.sat_per_kvb == 20000 && c.source == GZ_FEE_FROM_SERVERS && !c.capped);
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_MAINNET, 100, 200000, &c), GZ_CHAIN_OK);
  CHECK(c.sat_per_kvb == 20000); /* highest listed target not above 100 is 6 */
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_MAINNET, 1000, 200000, &c), GZ_CHAIN_OK);
  CHECK(c.sat_per_kvb == 2000);
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_MAINNET, 1, 200000, &c), GZ_CHAIN_OK);
  CHECK(c.sat_per_kvb == 80500);
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_MAINNET, 1, 30000, &c), GZ_CHAIN_OK);
  CHECK(c.sat_per_kvb == 30000 && c.capped);
  /* a server cannot talk the rate down to nothing */
  fake_set(&x.fake, false, BASE "/fee-estimates", 200, "{\"1\":0,\"6\":0.01}");
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_MAINNET, 6, 200000, &c), GZ_CHAIN_OK);
  CHECK(c.sat_per_kvb == GZ_FEE_MIN_SAT_PER_KVB);
  /* no estimates, or none obtainable: no rate, not a guess */
  fake_set(&x.fake, false, BASE "/fee-estimates", 200, "{}");
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_MAINNET, 6, 200000, &c), GZ_CHAIN_NOT_FOUND);
  CHECK(c.sat_per_kvb == 0 && c.source == GZ_FEE_FROM_NONE);
  x.fake.down = true;
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_MAINNET, 6, 200000, &c),
               GZ_CHAIN_UNREACHABLE);
  /* the ceiling is not optional, and neither is the network */
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_SIGNET, 6, 0, &c), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_INVALID, 6, 1000, &c), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.chain, GZ_NET_SIGNET, 0, 1000, &c), GZ_CHAIN_INVALID_ARG);
  fx_close(&x);
}

static void test_fee_parser_upper_bound(test_state *T) {
  gz_fee_estimates f;
  const char *at_limit = "{\"1\":5000}";
  const char *above = "{\"1\":5000.001}";
  const char *far_above = "{\"1\":2100000000000}";
  CHECK(gz_es_parse_fee_estimates(at_limit, strlen(at_limit), &f) &&
        f.entries[0].sat_per_kvb == GZ_FEE_MAX_SAT_PER_KVB);
  CHECK(!gz_es_parse_fee_estimates(above, strlen(above), &f));
  CHECK(!gz_es_parse_fee_estimates(far_above, strlen(far_above), &f));
}

/* ---- gaps found by the reviewer's mutation run ---- */

static gz_chain_result counting_broadcast(void *ctx, const uint8_t *raw, size_t len,
                                          gz_broadcast_result *out) {
  (void)raw;
  (void)len;
  (void)out;
  (*(int *)ctx)++;
  return GZ_CHAIN_OK;
}

static void test_front_checks_before_any_backend(test_state *T) {
  /* The front must refuse bad input itself, not rely on a backend to. */
  fixture x;
  gz_chain_ops ops;
  int calls = 0;
  gz_broadcast_result br;
  uint8_t hdr[GZ_HEADER_LEN], raw[1024];
  gz_tx_status st;
  fx_open(&x);
  memset(&ops, 0, sizeof ops);
  ops.broadcast = counting_broadcast;
  gz_chain stub = {&calls, &ops};
  size_t len = load_raw("tx_a_hex.txt", raw, sizeof raw);
  CHECK_RESULT(gz_chain_broadcast(&stub, raw, len - 1, &br), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_broadcast(&stub, (const uint8_t *)"\x01\x02", 2, &br), GZ_CHAIN_INVALID_ARG);
  CHECK(calls == 0);
  CHECK_RESULT(gz_chain_broadcast(&stub, raw, len, &br), GZ_CHAIN_OK);
  CHECK(calls == 1);

  /* a well-formed transaction that is simply too big is not sent either */
  size_t big_len = 4 + 1 + 41 + 1 + 8 + 5 + (GZ_TX_MAX_BYTES + 100) + 4;
  uint8_t *big = calloc(1, big_len);
  if (big == NULL) exit(2);
  size_t p = 0;
  big[p] = 2; p += 4;
  big[p++] = 1;
  memset(big + p, 0x22, 36); p += 36;
  big[p++] = 0;
  memset(big + p, 0xff, 4); p += 4;
  big[p++] = 1;
  p += 8;
  uint32_t script_len = GZ_TX_MAX_BYTES + 100;
  big[p++] = 0xfe;
  big[p++] = (uint8_t)script_len; big[p++] = (uint8_t)(script_len >> 8);
  big[p++] = (uint8_t)(script_len >> 16); big[p++] = (uint8_t)(script_len >> 24);
  memset(big + p, 0x6a, script_len); p += script_len;
  p += 4;
  CHECK(p == big_len);
  uint8_t id[GZ_HASH_LEN];
  CHECK(gz_txid_from_raw(big, big_len, id)); /* it is a transaction */
  CHECK_RESULT(gz_chain_broadcast(&stub, big, big_len, &br), GZ_CHAIN_INVALID_ARG);
  CHECK(calls == 1);
  unsigned before = x.fake.requests;
  CHECK_RESULT(gz_chain_broadcast(&x.chain, big, big_len, &br), GZ_CHAIN_INVALID_ARG);
  CHECK(x.fake.requests == before);
  free(big);

  /* a height no chain can have */
  CHECK_RESULT(gz_chain_block_header(&x.chain, GZ_MAX_HEIGHT + 1u, hdr), GZ_CHAIN_INVALID_ARG);
  CHECK(x.fake.requests == before);
  /* a backend that lacks a call is refused, not jumped into */
  CHECK_RESULT(gz_chain_tx_status(&stub, raw, &st), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_chain_block_header(&stub, 1, hdr), GZ_CHAIN_INVALID_ARG);
  gz_chain_info info;
  CHECK(!gz_chain_describe(&stub, &info) && info.host[0] == '\0');
  fx_close(&x);
}

static void test_parser_bounds_from_review(test_state *T) {
  uint8_t hdr[GZ_HEADER_LEN];
  gz_merkle_proof p;
  size_t len;
  /* a header must be all 160 characters, not a prefix of them */
  char *hex = test_read_data("header_329438.txt", &len);
  CHECK(gz_es_parse_header(hex, 160, hdr));
  CHECK(!gz_es_parse_header(hex, 158, hdr));
  CHECK(!gz_es_parse_header(hex, 2, hdr));
  CHECK(!gz_es_parse_header(hex, 0, hdr));
  free(hex);
  /* a proof's height has the same bound as every other height */
  const char *ok = "{\"block_height\":2147483647,\"merkle\":[],\"pos\":0}";
  const char *over = "{\"block_height\":2147483648,\"merkle\":[],\"pos\":0}";
  CHECK(gz_es_parse_merkle_proof(ok, strlen(ok), &p));
  CHECK(!gz_es_parse_merkle_proof(over, strlen(over), &p));
}

static void test_fee_status_codes(test_state *T) {
  fixture x;
  gz_fee_estimates f;
  fx_open(&x);
  static const long refused[] = {201, 204, 206, 301, 302, 304};
  for (size_t i = 0; i < sizeof refused / sizeof refused[0]; i++) {
    fake_set(&x.fake, false, BASE "/fee-estimates", refused[i], "{\"1\":1}");
    CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_MALFORMED);
  }
  fake_set(&x.fake, false, BASE "/fee-estimates", 403, "{\"1\":1}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_REJECTED);
  fake_set(&x.fake, false, BASE "/fee-estimates", 404, "{\"1\":1}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_MALFORMED);
  fake_set(&x.fake, false, BASE "/fee-estimates", 203, "{\"1\":1}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.chain, &f), GZ_CHAIN_OK);
  fx_close(&x);
}

static void test_backoff_is_capped(test_state *T) {
  fake_http fake;
  gz_esplora_config cfg;
  gz_chain c;
  uint8_t h[GZ_HASH_LEN];
  fake_init(&fake);
  gz_http http = fake_transport(&fake);
  gz_esplora_config_default(&cfg);
  cfg.base_url = BASE;
  cfg.max_attempts = 8;
  cfg.backoff_ms = 8000;
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_OK);
  fake.down = true;
  CHECK_RESULT(gz_chain_block_hash(&c, 5, h), GZ_CHAIN_UNREACHABLE);
  CHECK(fake.requests == 8 && fake.n_sleeps == 7);
  CHECK(fake.sleeps[0] == 8000 && fake.sleeps[1] == 16000);
  for (size_t i = 2; i < 7; i++) CHECK(fake.sleeps[i] == 30000); /* never longer than 30 s */
  gz_chain_destroy(&c);
  fake_free(&fake);
}

static void test_describe_and_addresses(test_state *T) {
  fake_http fake;
  gz_esplora_config cfg;
  gz_chain c;
  gz_chain_info info;
  fake_init(&fake);
  gz_http http = fake_transport(&fake);
  gz_esplora_config_default(&cfg);

  cfg.base_url = "https://Mempool.Space:443/signet/api";
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_OK);
  CHECK(gz_chain_describe(&c, &info));
  CHECK(strcmp(info.host, "mempool.space") == 0);
  CHECK(strcmp(info.operator_id, "mempool.space") == 0);
  CHECK(strcmp(info.endpoint, "https://mempool.space/signet/api") == 0); /* normalised */
  gz_chain_destroy(&c);

  cfg.base_url = "https://esplora.internal.example.org:8443/api";
  cfg.operator_id = "my-own-node";
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_OK);
  CHECK(gz_chain_describe(&c, &info));
  CHECK(strcmp(info.host, "esplora.internal.example.org") == 0);
  CHECK(strcmp(info.operator_id, "my-own-node") == 0);
  CHECK(strcmp(info.endpoint, "https://esplora.internal.example.org:8443/api") == 0);
  gz_chain_destroy(&c);
  cfg.operator_id = "Not Allowed!";
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_INVALID_ARG);
  cfg.operator_id = "";
  CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_INVALID_ARG);
  cfg.operator_id = NULL;

  /* plain http: this machine only */
  static const char *local[] = {"http://localhost:3002/api", "http://127.0.0.1:3002",
                                "http://[::1]:3002/api", "http://localhost"};
  for (size_t i = 0; i < sizeof local / sizeof local[0]; i++) {
    cfg.base_url = local[i];
    CHECK_RESULT(gz_esplora_create(&cfg, &http, &c), GZ_CHAIN_OK);
    gz_chain_destroy(&c);
  }
  static const char *refused[] = {
      "http://mempool.space/signet/api", /* a public server over plain http */
      "http://198.51.100.10:3002/api",
      "http://localhost.evil.example/api",
      "http://127.0.0.1.evil.example/api",
      "http://127.0.0.2/api",
      "https://[2001:db8::1]/api", /* only the loopback address may be bracketed */
      "https://mempool.space:0/api",
      "https://mempool.space:65536/api",
      "https://mempool.space:44a/api",
      "https://mempool.space:/api",
      "https://:443/api",
      "https://mem_pool.space/api",
  };
  for (size_t i = 0; i < sizeof refused / sizeof refused[0]; i++) {
    cfg.base_url = refused[i];
    T->checks++;
    if (gz_esplora_create(&cfg, &http, &c) != GZ_CHAIN_INVALID_ARG) {
      T->failed++;
      fprintf(stderr, "  accepted address %s\n", refused[i]);
      gz_chain_destroy(&c);
    }
  }
  fake_free(&fake);
}

/* ---- checked confirmation on one server ---- */

static void test_confirm_tx_single_server(test_state *T) {
  fixture x;
  gz_confirmation conf;
  uint8_t a[GZ_HASH_LEN], b[GZ_HASH_LEN], none[GZ_HASH_LEN], cb[GZ_HASH_LEN], sp[GZ_HASH_LEN];
  fx_open(&x);
  test_hash(TX_A, a);
  test_hash(TX_B, b);
  test_hash(TX_NONE, none);
  test_hash(TX_COINBASE, cb);
  test_hash(TX_SPENDER, sp);

  /* Transaction A is in block 329438 and the recorded chain ends at 329439:
   * two confirmations can be checked however many are asked for. */
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_OK);
  CHECK(conf.status.state == GZ_TX_CONFIRMED && conf.status.claimed_confirmations == 2);
  CHECK(conf.checked_confirmations == 2);
  CHECK(conf.proof.depth == 8 && conf.proof.pos == 1 && conf.block.tx_count == 243);
  CHECK(memcmp(conf.block.coinbase_txid, cb, GZ_HASH_LEN) == 0);
  CHECK(x.fake.unexpected == 0);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 2, &conf), GZ_CHAIN_OK);
  CHECK(conf.checked_confirmations == 2);
  /* asked for one: no later header is fetched */
  unsigned hits = fake_hits(&x.fake, false, BASE "/block/" HASH_329439 "/header");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 1, &conf), GZ_CHAIN_OK);
  CHECK(conf.checked_confirmations == 1);
  CHECK(fake_hits(&x.fake, false, BASE "/block/" HASH_329439 "/header") == hits);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 0, &conf), GZ_CHAIN_OK);
  CHECK(conf.checked_confirmations == 1); /* zero is read as one */
  /* the coinbase itself, at position 0 */
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, cb, 6, &conf), GZ_CHAIN_OK);
  CHECK(conf.proof.pos == 0 && conf.checked_confirmations == 2);
  /* transaction B, the spender in the next block, and one nobody has */
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, b, 6, &conf), GZ_CHAIN_OK);
  CHECK(conf.proof.pos == 2);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, sp, 6, &conf), GZ_CHAIN_OK);
  CHECK(conf.status.height == 329439 && conf.checked_confirmations == 1 &&
        conf.block.tx_count == 74 && conf.proof.depth == 7);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, none, 6, &conf), GZ_CHAIN_OK);
  CHECK(conf.status.state == GZ_TX_UNKNOWN && conf.checked_confirmations == 0);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_INVALID, a, 6, &conf), GZ_CHAIN_INVALID_ARG);

  /* The same server asked as if it were another network: refused at once. */
  unsigned before = x.fake.requests;
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_MAINNET, a, 6, &conf), GZ_CHAIN_WRONG_NETWORK);
  CHECK(x.fake.requests == before + 1); /* only block 0 was asked for */
  CHECK(conf.status.state == GZ_TX_UNKNOWN);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_TESTNET4, a, 6, &conf), GZ_CHAIN_WRONG_NETWORK);
  /* A server that claims mainnet's block 0 but serves these headers fails
   * mainnet's proof-of-work rule. */
  fake_set(&x.fake, false, BASE "/block-height/0", 200, GENESIS_MAINNET);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_MAINNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  fake_set(&x.fake, false, BASE "/block-height/0", 200, GENESIS_SIGNET);
  fx_close(&x);
}

static void test_confirm_tx_lies_about_inclusion(test_state *T) {
  fixture x;
  gz_confirmation conf;
  uint8_t a[GZ_HASH_LEN], b[GZ_HASH_LEN], none[GZ_HASH_LEN], sp[GZ_HASH_LEN];
  size_t plen;
  fx_open(&x);
  test_hash(TX_A, a);
  test_hash(TX_B, b);
  test_hash(TX_NONE, none);
  test_hash(TX_SPENDER, sp);

  /* A proof whose branch is right but which says it is for another height. */
  char *moved = test_read_data("tx_a_merkle_proof.json", &plen);
  char *digits = strstr(moved, "329438");
  CHECK(digits != NULL);
  if (digits != NULL) memcpy(digits, "329439", 6);
  fake_set(&x.fake, false, BASE "/tx/" TX_A "/merkle-proof", 200, moved);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  CHECK(conf.status.state == GZ_TX_UNKNOWN && conf.checked_confirmations == 0);
  free(moved);
  fake_set_file(&x.fake, BASE "/tx/" TX_A "/merkle-proof", 200, "tx_a_merkle_proof.json");

  /* An invented confirmation for a transaction nobody has: the server cannot
   * produce the transaction itself. */
  fake_set_file(&x.fake, BASE "/tx/" TX_NONE "/status", 200, "tx_a_status.json");
  fake_set_file(&x.fake, BASE "/tx/" TX_NONE "/merkle-proof", 200, "tx_a_merkle_proof.json");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, none, 6, &conf), GZ_CHAIN_BAD_PROOF);

  /* An invented confirmation for a REAL transaction: the spender exists (it
   * is in block 329439) and is claimed to be in block 329438, backed by the
   * genuine proof of transaction A. Everything is well formed; only the
   * Merkle fold against the header shows it is false. */
  fake_set_file(&x.fake, BASE "/tx/" TX_SPENDER "/status", 200, "tx_a_status.json");
  fake_set_file(&x.fake, BASE "/tx/" TX_SPENDER "/merkle-proof", 200, "tx_a_merkle_proof.json");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, sp, 6, &conf), GZ_CHAIN_BAD_PROOF);
  /* ...or with no proof offered at all */
  fake_set(&x.fake, false, BASE "/tx/" TX_SPENDER "/merkle-proof", 404,
           "Transaction not found or is unconfirmed");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, sp, 6, &conf), GZ_CHAIN_BAD_PROOF);

  /* A real transaction claimed to be in a different real block. */
  fake_set_file(&x.fake, BASE "/tx/" TX_A "/status", 200, "tx_spender_status.json"); /* says 329439 */
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  fake_set_file(&x.fake, BASE "/tx/" TX_A "/status", 200, "tx_a_status.json");

  /* The status names a block hash that is not the block at that height. */
  fake_set(&x.fake, false, BASE "/tx/" TX_B "/status", 200,
           "{\"confirmed\":true,\"block_height\":329438,\"block_hash\":\"" HASH_329437
           "\",\"block_time\":1}");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, b, 6, &conf), GZ_CHAIN_BAD_PROOF);
  fake_set_file(&x.fake, BASE "/tx/" TX_B "/status", 200, "tx_b_status.json");

  /* Confirmed "in" a height the server then has no block for. */
  fake_set(&x.fake, false, BASE "/tx/" TX_B "/status", 200,
           "{\"confirmed\":true,\"block_height\":329440,\"block_hash\":\"" HASH_329438
           "\",\"block_time\":1}");
  fake_set(&x.fake, false, BASE "/blocks/tip/height", 200, "329440");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, b, 6, &conf), GZ_CHAIN_BAD_PROOF);
  fx_close(&x);
}

static void test_confirm_tx_tree_shape(test_state *T) {
  fixture x;
  gz_confirmation conf;
  uint8_t a[GZ_HASH_LEN], b[GZ_HASH_LEN];
  size_t len;
  fx_open(&x);
  test_hash(TX_A, a);
  test_hash(TX_B, b);

  /* The server understates the number of transactions: the proof is then
   * one step too long for the block it describes. */
  char *json = test_read_data("block_329438.json", &len);
  char *at = strstr(json, "\"tx_count\":243");
  CHECK(at != NULL);
  if (at != NULL) memcpy(at, "\"tx_count\":100", 14);
  fake_set(&x.fake, false, BASE "/block/" HASH_329438, 200, json);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  /* the coinbase itself has no second proof to cross-check with: only the
   * depth rule catches the understated count there */
  uint8_t cbid[GZ_HASH_LEN];
  test_hash(TX_COINBASE, cbid);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, cbid, 6, &conf), GZ_CHAIN_BAD_PROOF);
  /* ...or overstates it */
  if (at != NULL) memcpy(at, "\"tx_count\":999", 14);
  fake_set(&x.fake, false, BASE "/block/" HASH_329438, 200, json);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, cbid, 6, &conf), GZ_CHAIN_BAD_PROOF);
  free(json);
  fake_set_file(&x.fake, BASE "/block/" HASH_329438, 200, "block_329438.json");

  /* The "first transaction" the server names is not a coinbase. */
  fake_set(&x.fake, false, BASE "/block/" HASH_329438 "/txid/0", 200, TX_B);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  /* It names the transaction being proved as the first one. */
  fake_set(&x.fake, false, BASE "/block/" HASH_329438 "/txid/0", 200, TX_A);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  fake_set_file(&x.fake, BASE "/block/" HASH_329438 "/txid/0", 200, "block_329438_txid_0.txt");

  /* The coinbase is real but the server will not prove it. */
  fake_set(&x.fake, false, BASE "/tx/" TX_COINBASE "/merkle-proof", 404,
           "Transaction not found or is unconfirmed");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  /* ...or proves it at another position (transaction B's proof, position 2) */
  fake_set_file(&x.fake, BASE "/tx/" TX_COINBASE "/merkle-proof", 200, "tx_b_merkle_proof.json");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  /* ...or with a proof for the next block's coinbase (other height, depth 7) */
  fake_set_file(&x.fake, BASE "/tx/" TX_COINBASE "/merkle-proof", 200,
                "tx_coinbase_329439_merkle_proof.json");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  /* ...or will not show the coinbase transaction */
  fake_set_file(&x.fake, BASE "/tx/" TX_COINBASE "/merkle-proof", 200, "tx_coinbase_merkle_proof.json");
  fake_set(&x.fake, false, BASE "/tx/" TX_COINBASE "/hex", 404, "Transaction not found");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  fake_set_file(&x.fake, BASE "/tx/" TX_COINBASE "/hex", 200, "tx_coinbase_hex.txt");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_OK);

  /* A Merkle inner node passed off as a transaction: its "raw transaction"
   * would be the 64 bytes of its two children, which is never accepted. */
  uint8_t pair[64], node[GZ_HASH_LEN], cb[GZ_HASH_LEN];
  char node_hex[65], url[FAKE_URL_MAX], pair_hex[129];
  test_hash(TX_COINBASE, cb);
  memcpy(pair, cb, 32);
  memcpy(pair + 32, a, 32);
  gz_sha256d(pair, 64, node);
  gz_hash_to_hex(node, node_hex);
  for (int i = 0; i < 64; i++) snprintf(pair_hex + 2 * i, 3, "%02x", pair[i]);
  snprintf(url, sizeof url, BASE "/tx/%s/status", node_hex);
  fake_set_file(&x.fake, url, 200, "tx_a_status.json");
  snprintf(url, sizeof url, BASE "/tx/%s/hex", node_hex);
  fake_set(&x.fake, false, url, 200, pair_hex);
  gz_chain_result r = gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, node, 6, &conf);
  CHECK(r != GZ_CHAIN_OK);
  CHECK(conf.status.state == GZ_TX_UNKNOWN && conf.checked_confirmations == 0);
  fx_close(&x);
}

static void test_confirm_tx_header_chain(test_state *T) {
  fixture x;
  gz_confirmation conf;
  uint8_t a[GZ_HASH_LEN];
  fx_open(&x);
  test_hash(TX_A, a);

  /* The reviewer's case: a server claiming a tip a million blocks up. The
   * claim is passed on as a claim; the checked number does not move. */
  fake_set(&x.fake, false, BASE "/blocks/tip/height", 200, "1329439");
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_OK);
  CHECK(conf.status.claimed_confirmations == 1000002);
  CHECK(conf.checked_confirmations == 2);
  fake_set(&x.fake, false, BASE "/blocks/tip/height", 200, "329439");

  /* The block after ours does not build on ours: here the server offers
   * block 329437's header as the block at height 329439. */
  fake_set(&x.fake, false, BASE "/block-height/329439", 200, HASH_329437);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_BAD_PROOF);
  CHECK(conf.checked_confirmations == 0);
  /* not asked to look past the block itself: not looked at */
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 1, &conf), GZ_CHAIN_OK);
  CHECK(conf.checked_confirmations == 1);
  fake_set(&x.fake, false, BASE "/block-height/329439", 200, HASH_329439);

  /* a later header that cannot be fetched is a failure, not a shorter count */
  fake_once(&x.fake, false, BASE "/block/" HASH_329439 "/header", GZ_HTTP_E_TIMEOUT, 0, "", 3);
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 6, &conf), GZ_CHAIN_UNREACHABLE);
  CHECK(conf.checked_confirmations == 0);
  /* more is asked for than the limit: cut to the limit, still two here */
  CHECK_RESULT(gz_chain_confirm_tx(&x.chain, GZ_NET_SIGNET, a, 1000000, &conf), GZ_CHAIN_OK);
  CHECK(conf.checked_confirmations == 2);
  fx_close(&x);
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  RUN(test_create_validates);
  RUN(test_argument_checks);
  RUN(test_tip);
  RUN(test_block_hash);
  RUN(test_block_header);
  RUN(test_tx_status);
  RUN(test_status_parser_strict);
  RUN(test_script_outputs);
  RUN(test_utxo_parser_strict);
  RUN(test_outspend);
  RUN(test_raw_tx);
  RUN(test_merkle_proof_call);
  RUN(test_merkle_parser_strict);
  RUN(test_broadcast);
  RUN(test_broadcast_retry_rules);
  RUN(test_fee_estimates);
  RUN(test_retries_and_backoff);
  RUN(test_rate_limit);
  RUN(test_time_limit_on_every_request);
  RUN(test_size_caps);
  RUN(test_small_buffer);
  RUN(test_block_summary);
  RUN(test_block_parser_strict);
  RUN(test_network_check);
  RUN(test_choose_fee_rate);
  RUN(test_fee_parser_upper_bound);
  RUN(test_front_checks_before_any_backend);
  RUN(test_parser_bounds_from_review);
  RUN(test_fee_status_codes);
  RUN(test_backoff_is_capped);
  RUN(test_describe_and_addresses);
  RUN(test_confirm_tx_single_server);
  RUN(test_confirm_tx_lies_about_inclusion);
  RUN(test_confirm_tx_tree_shape);
  RUN(test_confirm_tx_header_chain);
  TEST_MAIN_END("test_esplora");
}
