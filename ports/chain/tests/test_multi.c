/* The comparing backend over two and three Esplora backends, each on its own
 * fake transport loaded with the recorded signet answers. Lying servers are
 * made by replacing single answers. */
#include "test.h"

#include "gazpacho/chain_esplora.h"
#include "gazpacho/chain_multi.h"

static const char *const BASES[3] = {"https://one.test/api", "https://two.test/api",
                                     "https://three.test/api"};
#define B0 "https://one.test/api"
#define B1 "https://two.test/api"
#define B2 "https://three.test/api"

typedef struct mfx {
  size_t n;
  fake_http fake[3];
  gz_chain server[3];
  gz_chain multi;
} mfx;

static void mfx_open(mfx *x, size_t n) {
  gz_multi_config mc;
  memset(x, 0, sizeof *x);
  x->n = n;
  for (size_t i = 0; i < n; i++) {
    gz_esplora_config cfg;
    fake_init(&x->fake[i]);
    fake_load_honest(&x->fake[i], BASES[i], false);
    gz_http http = fake_transport(&x->fake[i]);
    gz_esplora_config_default(&cfg);
    cfg.base_url = BASES[i];
    if (gz_esplora_create(&cfg, &http, &x->server[i]) != GZ_CHAIN_OK) exit(2);
  }
  gz_multi_config_default(&mc, GZ_NET_SIGNET);
  if (gz_multi_create(&mc, x->server, n, &x->multi) != GZ_CHAIN_OK) exit(2);
}

static void mfx_close(mfx *x) {
  gz_chain_destroy(&x->multi);
  for (size_t i = 0; i < x->n; i++) {
    gz_chain_destroy(&x->server[i]);
    fake_free(&x->fake[i]);
  }
}

static size_t load_raw(const char *file, uint8_t *out, size_t cap) {
  size_t len, raw_len = 0;
  char *hex = test_read_data(file, &len);
  if (!gz_hex_decode(hex, len, out, cap, &raw_len)) exit(2);
  free(hex);
  return raw_len;
}

typedef struct ids {
  uint8_t a[GZ_HASH_LEN], b[GZ_HASH_LEN], spender[GZ_HASH_LEN], none[GZ_HASH_LEN];
  uint8_t h37[GZ_HASH_LEN], h38[GZ_HASH_LEN], h39[GZ_HASH_LEN];
  uint8_t script[32];
  size_t script_len;
} ids;

static void ids_init(ids *k) {
  test_hash(TX_A, k->a);
  test_hash(TX_B, k->b);
  test_hash(TX_SPENDER, k->spender);
  test_hash(TX_NONE, k->none);
  test_hash(HASH_329437, k->h37);
  test_hash(HASH_329438, k->h38);
  test_hash(HASH_329439, k->h39);
  if (!gz_hex_decode(SCRIPT_A2, strlen(SCRIPT_A2), k->script, sizeof k->script, &k->script_len))
    exit(2);
}

#define CONFIRMED_38 \
  "{\"confirmed\":true,\"block_height\":329438,\"block_hash\":\"" HASH_329438 "\",\"block_time\":1793823982}"
#define CONFIRMED_39 \
  "{\"confirmed\":true,\"block_height\":329439,\"block_hash\":\"" HASH_329439 "\",\"block_time\":1793824361}"
#define UTXO_A2_CONFIRMED \
  "{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":" CONFIRMED_38 ",\"value\":43000}"

/* ---- agreement ---- */

static void test_two_servers_agree_on_everything(test_state *T) {
  mfx x;
  ids k;
  gz_chain_tip tip;
  gz_tx_status st;
  gz_outspend o;
  gz_merkle_proof p;
  gz_fee_estimates f;
  gz_block_summary sum;
  gz_chain_output outs[4];
  gz_confirmation conf;
  uint8_t h[GZ_HASH_LEN], hdr[GZ_HEADER_LEN], raw[1024];
  size_t n;
  bool differs = true;
  mfx_open(&x, 2);
  ids_init(&k);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);
  CHECK(rep != NULL && rep->call == GZ_CALL_NONE);
  CHECK(gz_multi_last_report(&x.server[0]) == NULL); /* not a comparing backend */
  CHECK(gz_multi_operator_count(&x.multi) == 2 && gz_multi_operator_count(&x.server[0]) == 0);
  CHECK(x.fake[0].requests == 0 && x.fake[1].requests == 0); /* creating sends nothing */

  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_OK);
  CHECK(tip.height == TIP_HEIGHT && memcmp(tip.hash, k.h39, GZ_HASH_LEN) == 0);
  CHECK(rep->call == GZ_CALL_TIP && rep->verdict == GZ_CHAIN_OK && rep->server_count == 2);
  CHECK(rep->operator_count == 2 && !rep->unconfirmed_differs);
  CHECK(strcmp(rep->operators[0], "one.test") == 0 && strcmp(rep->operators[1], "two.test") == 0);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[1].result == GZ_CHAIN_OK);
  CHECK(rep->answers[1].u.tip.height == TIP_HEIGHT);
  /* each server's network was checked once, before its first answer counted */
  CHECK(fake_hits(&x.fake[0], false, B0 "/block-height/0") == 1);
  CHECK(fake_hits(&x.fake[1], false, B1 "/block-height/0") == 1);

  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329438, h), GZ_CHAIN_OK);
  CHECK(memcmp(h, k.h38, GZ_HASH_LEN) == 0);
  CHECK_RESULT(gz_chain_block_header(&x.multi, 329438, hdr), GZ_CHAIN_OK);
  gz_header_hash(hdr, h);
  CHECK(memcmp(h, k.h38, GZ_HASH_LEN) == 0);
  CHECK_RESULT(gz_chain_block_summary(&x.multi, 329438, &sum), GZ_CHAIN_OK);
  CHECK(sum.tx_count == 243 && memcmp(sum.hash, k.h38, GZ_HASH_LEN) == 0);

  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_CONFIRMED && st.height == 329438 && st.claimed_confirmations == 2);
  CHECK(!st.unconfirmed_differs);
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.none, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_UNKNOWN && !st.unconfirmed_differs);

  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, &differs),
               GZ_CHAIN_OK);
  CHECK(n == 1 && outs[0].vout == 2 && outs[0].value == 43000 && !differs);
  CHECK(rep->call == GZ_CALL_SCRIPT_OUTPUTS && rep->answers[1].u.outputs.count == 1);

  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_OK);
  CHECK(o.spent && o.confirmed && memcmp(o.spender_txid, k.spender, GZ_HASH_LEN) == 0);
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 2, &o), GZ_CHAIN_OK);
  CHECK(!o.spent && !o.unconfirmed_differs);

  CHECK_RESULT(gz_chain_raw_tx(&x.multi, k.a, raw, sizeof raw, &n), GZ_CHAIN_OK);
  CHECK(n == 244 && gz_txid_from_raw(raw, n, h) && memcmp(h, k.a, GZ_HASH_LEN) == 0);

  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_OK);
  CHECK(gz_merkle_verify(k.a, &p, hdr));

  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_OK);
  CHECK(f.count == 28 && f.entries[0].target == 1 && f.entries[0].sat_per_kvb == 1000);

  /* the checked confirmation, with every step compared across servers */
  CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.a, 6, &conf), GZ_CHAIN_OK);
  CHECK(conf.status.state == GZ_TX_CONFIRMED && conf.checked_confirmations == 2);

  /* both saying "no" is an agreed answer too */
  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329440, h), GZ_CHAIN_NOT_FOUND);
  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.none, &p), GZ_CHAIN_NOT_FOUND);
  CHECK_RESULT(gz_chain_raw_tx(&x.multi, k.none, raw, sizeof raw, &n), GZ_CHAIN_NOT_FOUND);
  CHECK(x.fake[0].unexpected == 0 && x.fake[1].unexpected == 0);
  CHECK(fake_hits(&x.fake[0], false, B0 "/block-height/0") <= 2); /* remembered, plus confirm's own check */
  mfx_close(&x);
}

/* ---- one server must never be compared with itself ---- */

static gz_chain make_server(fake_http *fake, const char *url, const char *operator_id) {
  gz_esplora_config cfg;
  gz_chain c;
  gz_http http = fake_transport(fake);
  gz_esplora_config_default(&cfg);
  cfg.base_url = url;
  cfg.operator_id = operator_id;
  if (gz_esplora_create(&cfg, &http, &c) != GZ_CHAIN_OK) exit(2);
  return c;
}

static void test_duplicate_servers_refused(test_state *T) {
  mfx x;
  gz_multi_config mc;
  gz_chain m, pair[2];
  fake_http fake;
  mfx_open(&x, 2);
  fake_init(&fake);
  gz_multi_config_default(&mc, GZ_NET_SIGNET);

  /* the same handle twice */
  pair[0] = x.server[0];
  pair[1] = x.server[0];
  CHECK_RESULT(gz_multi_create(&mc, pair, 2, &m), GZ_CHAIN_INVALID_ARG);
  CHECK(m.ctx == NULL);

  /* two backends, the same address */
  gz_chain same_url = make_server(&fake, B0, NULL);
  pair[1] = same_url;
  CHECK_RESULT(gz_multi_create(&mc, pair, 2, &m), GZ_CHAIN_INVALID_ARG);
  gz_chain_destroy(&same_url);
  /* the same address written differently */
  static const char *variants[] = {"https://ONE.test/api", "https://one.test:443/api",
                                   /* the same host under another path or port */
                                   "https://one.test/signet/api", "https://one.test:8443/api"};
  for (size_t i = 0; i < sizeof variants / sizeof variants[0]; i++) {
    gz_chain v = make_server(&fake, variants[i], NULL);
    pair[1] = v;
    CHECK_RESULT(gz_multi_create(&mc, pair, 2, &m), GZ_CHAIN_INVALID_ARG);
    /* naming a different operator does not make one host two servers */
    gz_chain_destroy(&v);
    v = make_server(&fake, variants[i], "someone-else");
    pair[1] = v;
    CHECK_RESULT(gz_multi_create(&mc, pair, 2, &m), GZ_CHAIN_INVALID_ARG);
    gz_chain_destroy(&v);
  }
  /* a duplicate anywhere in a longer list */
  gz_chain three[3] = {x.server[0], x.server[1], x.server[0]};
  CHECK_RESULT(gz_multi_create(&mc, three, 3, &m), GZ_CHAIN_INVALID_ARG);
  fake_free(&fake);
  mfx_close(&x);
}

static void test_one_operator_is_not_two(test_state *T) {
  /* Two different hosts of one operator, both honest and in full agreement.
   * They are one voice: nothing is confirmed. */
  fake_http fake[3];
  gz_chain s[3], m;
  gz_multi_config mc;
  gz_tx_status st;
  gz_chain_tip tip;
  uint8_t a[GZ_HASH_LEN];
  test_hash(TX_A, a);
  for (int i = 0; i < 3; i++) fake_init(&fake[i]);
  fake_load_honest(&fake[0], "https://a.bigco.test/api", false);
  fake_load_honest(&fake[1], "https://b.bigco.test/api", false);
  fake_load_honest(&fake[2], B2, false);
  s[0] = make_server(&fake[0], "https://a.bigco.test/api", NULL);
  s[1] = make_server(&fake[1], "https://b.bigco.test/api", NULL);
  s[2] = make_server(&fake[2], B2, NULL);
  gz_multi_config_default(&mc, GZ_NET_SIGNET);

  CHECK_RESULT(gz_multi_create(&mc, s, 2, &m), GZ_CHAIN_OK);
  CHECK(gz_multi_operator_count(&m) == 1);
  CHECK_RESULT(gz_chain_tx_status(&m, a, &st), GZ_CHAIN_NO_QUORUM);
  CHECK(st.state == GZ_TX_UNKNOWN);
  const gz_multi_report *rep = gz_multi_last_report(&m);
  CHECK(rep->operator_count == 1 && rep->server_count == 2);
  CHECK(strcmp(rep->operators[0], "bigco.test") == 0 && strcmp(rep->operators[1], "bigco.test") == 0);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[1].result == GZ_CHAIN_OK);
  CHECK_RESULT(gz_chain_tip_get(&m, &tip), GZ_CHAIN_NO_QUORUM);
  gz_chain_destroy(&m);

  /* with a server of a second operator there are two voices */
  CHECK_RESULT(gz_multi_create(&mc, s, 3, &m), GZ_CHAIN_OK);
  CHECK(gz_multi_operator_count(&m) == 2);
  CHECK_RESULT(gz_chain_tx_status(&m, a, &st), GZ_CHAIN_OK);
  /* ...but if that second operator is down, the first one's two servers are
   * again not enough */
  fake[2].down = true;
  CHECK_RESULT(gz_chain_tx_status(&m, a, &st), GZ_CHAIN_NO_QUORUM);
  gz_chain_destroy(&m);

  /* operators named by the user: the same name on two hosts is one operator */
  gz_chain_destroy(&s[1]);
  gz_chain_destroy(&s[2]);
  fake[2].down = false;
  s[1] = make_server(&fake[1], "https://b.bigco.test/api", "acme");
  s[2] = make_server(&fake[2], B2, "acme");
  gz_chain named[2] = {s[1], s[2]};
  CHECK_RESULT(gz_multi_create(&mc, named, 2, &m), GZ_CHAIN_OK);
  CHECK(gz_multi_operator_count(&m) == 1);
  CHECK_RESULT(gz_chain_tx_status(&m, a, &st), GZ_CHAIN_NO_QUORUM);
  gz_chain_destroy(&m);
  for (int i = 0; i < 3; i++) {
    gz_chain_destroy(&s[i]);
    fake_free(&fake[i]);
  }
}

/* ---- a server on another network ---- */

static void test_wrong_network_server_never_counts(test_state *T) {
  mfx x;
  ids k;
  gz_chain_tip tip;
  gz_tx_status st;
  gz_broadcast_result br;
  uint8_t raw[1024];
  mfx_open(&x, 2);
  ids_init(&k);
  size_t len = load_raw("tx_a_hex.txt", raw, sizeof raw);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);
  /* Server two answers everything exactly like server one, but its block 0
   * is mainnet's. */
  fake_set(&x.fake[1], false, B1 "/block-height/0", 200, GENESIS_MAINNET);
  fake_set(&x.fake[0], true, B0 "/tx", 200, TX_A);
  fake_set(&x.fake[1], true, B1 "/tx", 200, TX_A);

  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_NO_QUORUM);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK);
  CHECK(rep->answers[1].result == GZ_CHAIN_WRONG_NETWORK);
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_NO_QUORUM);
  CHECK(rep->answers[1].result == GZ_CHAIN_WRONG_NETWORK);
  /* it was asked for block 0 once and for nothing else, ever */
  CHECK(x.fake[1].requests == 1);
  /* a broadcast is not sent to it */
  CHECK_RESULT(gz_chain_broadcast(&x.multi, raw, len, &br), GZ_CHAIN_OK);
  CHECK(fake_hits(&x.fake[0], true, B0 "/tx") == 1 && fake_hits(&x.fake[1], true, B1 "/tx") == 0);
  CHECK(rep->answers[1].result == GZ_CHAIN_WRONG_NETWORK);
  CHECK(x.fake[1].requests == 1);
  mfx_close(&x);

  /* both servers on mainnet while signet was asked for: nothing at all */
  mfx_open(&x, 2);
  fake_set(&x.fake[0], false, B0 "/block-height/0", 200, GENESIS_MAINNET);
  fake_set(&x.fake[1], false, B1 "/block-height/0", 200, GENESIS_MAINNET);
  fake_set(&x.fake[0], true, B0 "/tx", 200, TX_A);
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_WRONG_NETWORK);
  CHECK(tip.height == 0);
  CHECK_RESULT(gz_chain_broadcast(&x.multi, raw, len, &br), GZ_CHAIN_WRONG_NETWORK);
  CHECK(fake_hits(&x.fake[0], true, B0 "/tx") == 0);
  mfx_close(&x);

  /* a server whose block 0 could not be fetched is asked again next time */
  mfx_open(&x, 2);
  fake_once(&x.fake[1], false, B1 "/block-height/0", GZ_HTTP_E_CONNECT, 0, "", 3);
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_NO_QUORUM);
  CHECK(gz_multi_last_report(&x.multi)->answers[1].result == GZ_CHAIN_UNREACHABLE);
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_OK);
  /* a comparing backend cannot be made without saying which network */
  gz_multi_config mc;
  gz_chain m;
  gz_multi_config_default(&mc, GZ_NET_INVALID);
  CHECK_RESULT(gz_multi_create(&mc, x.server, 2, &m), GZ_CHAIN_INVALID_ARG);
  memset(&mc, 0, sizeof mc);
  mc.quorum = 2;
  mc.max_outputs = 16;
  mc.fee_ceiling_sat_per_kvb = 1000;
  mc.fee_disagree_factor = 3;
  CHECK_RESULT(gz_multi_create(&mc, x.server, 2, &m), GZ_CHAIN_INVALID_ARG); /* zeroed network */
  mfx_close(&x);
}

/* ---- the tip rule ---- */

static void test_tip_rule(test_state *T) {
  mfx x;
  ids k;
  gz_chain_tip tip;
  mfx_open(&x, 2);
  ids_init(&k);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);

  /* one block apart on the same chain: the lower tip is the answer */
  fake_set(&x.fake[0], false, B0 "/blocks/tip/height", 200, "329438");
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_OK);
  CHECK(tip.height == 329438 && memcmp(tip.hash, k.h38, GZ_HASH_LEN) == 0);
  CHECK(rep->answers[0].u.tip.height == 329438 && rep->answers[1].u.tip.height == 329439);
  /* the same, the other way round */
  fake_set(&x.fake[0], false, B0 "/blocks/tip/height", 200, "329439");
  fake_set(&x.fake[1], false, B1 "/blocks/tip/height", 200, "329438");
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_OK);
  CHECK(tip.height == 329438);
  fake_set(&x.fake[1], false, B1 "/blocks/tip/height", 200, "329439");

  /* two blocks apart: more than a block arriving late explains */
  fake_set(&x.fake[0], false, B0 "/blocks/tip/height", 200, "329437");
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_DISAGREE);
  CHECK(tip.height == 0);
  CHECK(rep->verdict == GZ_CHAIN_DISAGREE);
  CHECK(rep->answers[0].u.tip.height == 329437 && rep->answers[1].u.tip.height == 329439);

  /* one block apart, but the server ahead is on a different chain: its
   * block at the lower height is not the lower server's tip */
  fake_set(&x.fake[0], false, B0 "/blocks/tip/height", 200, "329438");
  fake_set(&x.fake[1], false, B1 "/block-height/329438", 200, HASH_329437);
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_DISAGREE);
  /* ...or it claims to be ahead yet has no block at the lower height */
  fake_set(&x.fake[1], false, B1 "/block-height/329438", 404, "Block not found");
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_DISAGREE);
  fake_set(&x.fake[1], false, B1 "/block-height/329438", 200, HASH_329438);

  /* one block apart, and the server ahead cannot be asked about the lower
   * height: nothing was compared */
  fake_once(&x.fake[1], false, B1 "/block-height/329438", GZ_HTTP_E_CONNECT, 0, "", 3);
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_NO_QUORUM);

  /* same height, different block */
  fake_set(&x.fake[0], false, B0 "/blocks/tip/height", 200, "329439");
  fake_set(&x.fake[1], false, B1 "/block-height/329439", 200, HASH_329437);
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_DISAGREE);
  mfx_close(&x);
}

/* ---- contradictions about confirmed data ---- */

static void test_disagree_block_hash_and_header(test_state *T) {
  mfx x;
  uint8_t h[GZ_HASH_LEN], hdr[GZ_HEADER_LEN];
  gz_block_summary sum;
  mfx_open(&x, 2);
  /* server two serves a different (self-consistent) block at 329438 */
  fake_set(&x.fake[1], false, B1 "/block-height/329438", 200, HASH_329437);
  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329438, h), GZ_CHAIN_DISAGREE);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[1].result == GZ_CHAIN_OK);
  CHECK(memcmp(rep->answers[0].u.block_hash, rep->answers[1].u.block_hash, GZ_HASH_LEN) != 0);
  CHECK_RESULT(gz_chain_block_header(&x.multi, 329438, hdr), GZ_CHAIN_DISAGREE);
  CHECK(memcmp(rep->answers[0].u.header, rep->answers[1].u.header, GZ_HEADER_LEN) != 0);
  fake_set(&x.fake[1], false, B1 "/block-height/329438", 200, HASH_329438);

  /* the block summary: a different transaction count, a different first txid */
  size_t len;
  char *json = test_read_data("block_329438.json", &len);
  char *at = strstr(json, "\"tx_count\":243");
  if (at != NULL) memcpy(at, "\"tx_count\":244", 14);
  fake_set(&x.fake[1], false, B1 "/block/" HASH_329438, 200, json);
  free(json);
  CHECK_RESULT(gz_chain_block_summary(&x.multi, 329438, &sum), GZ_CHAIN_DISAGREE);
  CHECK(sum.tx_count == 0);
  fake_set_file(&x.fake[1], B1 "/block/" HASH_329438, 200, "block_329438.json");
  fake_set(&x.fake[1], false, B1 "/block/" HASH_329438 "/txid/0", 200, TX_B);
  CHECK_RESULT(gz_chain_block_summary(&x.multi, 329438, &sum), GZ_CHAIN_DISAGREE);

  /* one has the block, the other says there is none, and both claim the
   * same tip: that is not lag */
  fake_set(&x.fake[1], false, B1 "/block-height/329438", 404, "Block not found");
  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329438, h), GZ_CHAIN_DISAGREE);
  CHECK(rep->answers[1].result == GZ_CHAIN_NOT_FOUND);
  mfx_close(&x);
}

static void test_disagree_tx_status(test_state *T) {
  mfx x;
  ids k;
  gz_tx_status st;
  mfx_open(&x, 2);
  ids_init(&k);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);

  /* confirmed on one, never seen on the other, both at the same tip: a
   * server is hiding it (or inventing it) */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/status", 200, "{\"confirmed\":false}");
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/hex", 404, "Transaction not found");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_DISAGREE);
  CHECK(st.state == GZ_TX_UNKNOWN && st.claimed_confirmations == 0); /* caller gets nothing */
  CHECK(rep->answers[0].u.tx_status.state == GZ_TX_CONFIRMED);
  CHECK(rep->answers[1].u.tx_status.state == GZ_TX_UNKNOWN);

  /* confirmed on one, in the mempool on the other, same tip */
  fake_set_file(&x.fake[1], B1 "/tx/" TX_A "/hex", 200, "tx_a_hex.txt");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_DISAGREE);
  CHECK(rep->answers[1].u.tx_status.state == GZ_TX_MEMPOOL);

  /* confirmed on both, in different blocks */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/status", 200,
           "{\"confirmed\":true,\"block_height\":329438,\"block_hash\":\"" HASH_329437
           "\",\"block_time\":1793823982}");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_DISAGREE);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[1].result == GZ_CHAIN_OK);
  /* confirmed on both, same hash, different heights */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/status", 200,
           "{\"confirmed\":true,\"block_height\":329437,\"block_hash\":\"" HASH_329438
           "\",\"block_time\":1793823982}");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_DISAGREE);

  /* agreement again, with different claimed tips: the lower claim is passed on */
  fake_set_file(&x.fake[1], B1 "/tx/" TX_A "/status", 200, "tx_a_status.json");
  fake_set(&x.fake[1], false, B1 "/blocks/tip/height", 200, "329445");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_OK);
  CHECK(st.claimed_confirmations == 2 && st.tip_height == TIP_HEIGHT);
  CHECK(rep->answers[1].u.tx_status.claimed_confirmations == 8);
  mfx_close(&x);
}

/* ---- lag has its own result ---- */

static void test_lag_is_not_disagreement(test_state *T) {
  mfx x;
  ids k;
  gz_tx_status st;
  gz_outspend o;
  gz_merkle_proof p;
  gz_chain_output outs[4];
  uint8_t h[GZ_HASH_LEN];
  size_t n;
  mfx_open(&x, 2);
  ids_init(&k);
  /* Server two has not yet seen block 329439. It reports tip 329438, has
   * the spender only in its mempool, and has no block at 329439. */
  fake_set(&x.fake[1], false, B1 "/blocks/tip/height", 200, "329438");
  fake_set(&x.fake[1], false, B1 "/block-height/329439", 404, "Block not found");
  fake_set(&x.fake[1], false, B1 "/tx/" TX_SPENDER "/status", 200, "{\"confirmed\":false}");
  fake_set(&x.fake[1], false, B1 "/tx/" TX_SPENDER "/merkle-proof", 404,
           "Transaction not found or is unconfirmed");
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/outspend/0", 200,
           "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":0,\"status\":{\"confirmed\":false}}");

  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.spender, &st), GZ_CHAIN_LAG);
  CHECK(st.state == GZ_TX_UNKNOWN); /* still not an answer */
  CHECK(gz_multi_last_report(&x.multi)->verdict == GZ_CHAIN_LAG);
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_LAG);
  CHECK(!o.spent);
  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329439, h), GZ_CHAIN_LAG);
  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.spender, &p), GZ_CHAIN_LAG);
  /* an output confirmed in the new block, which the slower server still
   * lists as unconfirmed */
  fake_set(&x.fake[0], false, B0 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200,
           "[{\"txid\":\"" TX_SPENDER "\",\"vout\":0,\"status\":" CONFIRMED_39 ",\"value\":7}]");
  fake_set(&x.fake[1], false, B1 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200,
           "[{\"txid\":\"" TX_SPENDER "\",\"vout\":0,\"status\":{\"confirmed\":false},\"value\":7}]");
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, NULL),
               GZ_CHAIN_LAG);
  CHECK(n == 0);
  /* things from before the new block are unaffected */
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_CONFIRMED);

  /* A server two blocks behind is not "lagging by a block". */
  fake_set(&x.fake[1], false, B1 "/blocks/tip/height", 200, "329437");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.spender, &st), GZ_CHAIN_DISAGREE);
  /* A server "one behind" on a different chain is not lagging either. */
  fake_set(&x.fake[1], false, B1 "/blocks/tip/height", 200, "329438");
  fake_set(&x.fake[1], false, B1 "/block-height/329438", 200, HASH_329437);
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.spender, &st), GZ_CHAIN_DISAGREE);
  mfx_close(&x);
}

/* ---- differences that are only about unconfirmed data ---- */

static void test_unconfirmed_differences_do_not_blank_the_view(test_state *T) {
  mfx x;
  ids k;
  gz_tx_status st;
  gz_outspend o;
  gz_chain_output outs[4];
  size_t n = 9;
  bool differs = false;
  mfx_open(&x, 2);
  ids_init(&k);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);

  /* The reviewer's case: someone sends 1 satoshi to the watched script and
   * only one server has seen it yet. The confirmed output must still show. */
  fake_set(&x.fake[1], false, B1 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200,
           "[" UTXO_A2_CONFIRMED ",{\"txid\":\"" TX_B
           "\",\"vout\":0,\"status\":{\"confirmed\":false},\"value\":1}]");
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, &differs),
               GZ_CHAIN_OK);
  CHECK(n == 1 && outs[0].confirmed && outs[0].value == 43000);
  CHECK(differs && rep->unconfirmed_differs);
  CHECK(rep->answers[0].u.outputs.count == 1 && rep->answers[1].u.outputs.count == 2);
  /* the same with the servers the other way round */
  fake_set_file(&x.fake[1], B1 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200, "utxo_script_a2.json");
  fake_set(&x.fake[0], false, B0 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200,
           "[{\"txid\":\"" TX_B "\",\"vout\":0,\"status\":{\"confirmed\":false},\"value\":1},"
           UTXO_A2_CONFIRMED "]");
  differs = false;
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, &differs),
               GZ_CHAIN_OK);
  CHECK(n == 1 && outs[0].value == 43000 && differs);
  /* an unconfirmed output both servers list is part of the answer */
  fake_set(&x.fake[1], false, B1 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200,
           "[" UTXO_A2_CONFIRMED ",{\"txid\":\"" TX_B
           "\",\"vout\":0,\"status\":{\"confirmed\":false},\"value\":1}]");
  differs = true;
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, &differs),
               GZ_CHAIN_OK);
  CHECK(n == 2 && !differs && !rep->unconfirmed_differs);
  /* the same unconfirmed outpoint with different amounts is not agreed */
  fake_set(&x.fake[1], false, B1 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200,
           "[" UTXO_A2_CONFIRMED ",{\"txid\":\"" TX_B
           "\",\"vout\":0,\"status\":{\"confirmed\":false},\"value\":2}]");
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, &differs),
               GZ_CHAIN_OK);
  CHECK(n == 1 && differs);

  /* a transaction one server has in its mempool and the other has not seen */
  fake_set(&x.fake[0], false, B0 "/tx/" TX_SPENDER "/status", 200, "{\"confirmed\":false}");
  fake_set(&x.fake[1], false, B1 "/tx/" TX_SPENDER "/status", 200, "{\"confirmed\":false}");
  fake_set(&x.fake[1], false, B1 "/tx/" TX_SPENDER "/hex", 404, "Transaction not found");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.spender, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_UNKNOWN && st.unconfirmed_differs && rep->unconfirmed_differs);
  CHECK(rep->answers[0].u.tx_status.state == GZ_TX_MEMPOOL);
  /* both have it in the mempool */
  fake_set_file(&x.fake[1], B1 "/tx/" TX_SPENDER "/hex", 200, "tx_spender_hex.txt");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.spender, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_MEMPOOL && !st.unconfirmed_differs);

  /* an unconfirmed spend only one server reports: flagged, not hidden and
   * not taken as fact */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/outspend/2", 200,
           "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":3,\"status\":{\"confirmed\":false}}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 2, &o), GZ_CHAIN_OK);
  CHECK(!o.spent && o.unconfirmed_differs && rep->unconfirmed_differs);
  CHECK(rep->answers[1].u.outspend.spent && !rep->answers[0].u.outspend.spent);
  /* both report the same unconfirmed spend */
  fake_set(&x.fake[0], false, B0 "/tx/" TX_A "/outspend/2", 200,
           "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":3,\"status\":{\"confirmed\":false}}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 2, &o), GZ_CHAIN_OK);
  CHECK(o.spent && !o.confirmed && !o.unconfirmed_differs && o.spender_vin == 3);
  /* they report different unconfirmed spenders (a replacement in flight) */
  fake_set(&x.fake[0], false, B0 "/tx/" TX_A "/outspend/2", 200,
           "{\"spent\":true,\"txid\":\"" TX_B "\",\"vin\":0,\"status\":{\"confirmed\":false}}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 2, &o), GZ_CHAIN_OK);
  CHECK(!o.spent && o.unconfirmed_differs);
  fake_set(&x.fake[0], false, B0 "/tx/" TX_A "/outspend/2", 200,
           "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":4,\"status\":{\"confirmed\":false}}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 2, &o), GZ_CHAIN_OK);
  CHECK(!o.spent && o.unconfirmed_differs);
  mfx_close(&x);
}

static void test_lying_server_omits_a_spend(test_state *T) {
  mfx x;
  ids k;
  gz_outspend o;
  mfx_open(&x, 2);
  ids_init(&k);
  /* The watched output TX_A:0 has been spent in a block. Server two hides it. */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/outspend/0", 200, "{\"spent\":false}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_DISAGREE);
  CHECK(!o.spent && o.height == 0); /* no answer is handed over as if agreed */
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);
  CHECK(rep->call == GZ_CALL_OUTSPEND && rep->verdict == GZ_CHAIN_DISAGREE);
  /* both answers are there for the caller to act on: one server says spent */
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[0].u.outspend.spent);
  CHECK(memcmp(rep->answers[0].u.outspend.spender_txid, k.spender, GZ_HASH_LEN) == 0);
  CHECK(rep->answers[1].result == GZ_CHAIN_OK && !rep->answers[1].u.outspend.spent);
  /* the same with the liar listed first */
  fake_set_file(&x.fake[1], B1 "/tx/" TX_A "/outspend/0", 200, "tx_a_outspend_0.json");
  fake_set(&x.fake[0], false, B0 "/tx/" TX_A "/outspend/0", 200, "{\"spent\":false}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_DISAGREE);

  /* other contradictions about a confirmed spend */
  fake_set(&x.fake[0], false, B0 "/tx/" TX_A "/outspend/0", 200,
           "{\"spent\":true,\"txid\":\"" TX_B "\",\"vin\":0,\"status\":" CONFIRMED_39 "}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_DISAGREE); /* another spender */
  fake_set(&x.fake[0], false, B0 "/tx/" TX_A "/outspend/0", 200,
           "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":1,\"status\":" CONFIRMED_39 "}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_DISAGREE); /* another input */
  fake_set(&x.fake[0], false, B0 "/tx/" TX_A "/outspend/0", 200,
           "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":0,\"status\":" CONFIRMED_38 "}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_DISAGREE); /* another block */
  fake_set(&x.fake[0], false, B0 "/tx/" TX_A "/outspend/0", 200,
           "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":0,\"status\":{\"confirmed\":false}}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_DISAGREE); /* same tip: not lag */
  mfx_close(&x);
}

static void test_disagree_script_outputs(test_state *T) {
  mfx x;
  ids k;
  gz_chain_output outs[4];
  size_t n = 7;
  mfx_open(&x, 2);
  ids_init(&k);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);
  const char *url1 = B1 "/scripthash/" SCRIPT_A2_HASH "/utxo";
  /* one server hides the confirmed output */
  fake_set(&x.fake[1], false, url1, 200, "[]");
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, NULL),
               GZ_CHAIN_DISAGREE);
  CHECK(n == 0);
  CHECK(rep->answers[0].u.outputs.count == 1 && rep->answers[1].u.outputs.count == 0);
  CHECK(rep->answers[0].u.outputs.items[0].value == 43000);
  /* one server lists a confirmed output the other does not have */
  fake_set(&x.fake[1], false, url1, 200,
           "[" UTXO_A2_CONFIRMED ",{\"txid\":\"" TX_B "\",\"vout\":0,\"status\":" CONFIRMED_38
           ",\"value\":5}]");
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, NULL),
               GZ_CHAIN_DISAGREE);
  /* a different amount for the same confirmed output */
  fake_set(&x.fake[1], false, url1, 200,
           "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":" CONFIRMED_38 ",\"value\":43001}]");
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, NULL),
               GZ_CHAIN_DISAGREE);
  /* the same output and amount, said to be in another block */
  fake_set(&x.fake[1], false, url1, 200,
           "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":true,\"block_height\":329438,"
           "\"block_hash\":\"" HASH_329437 "\",\"block_time\":1793823982},\"value\":43000}]");
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, NULL),
               GZ_CHAIN_DISAGREE);
  /* ...or at another height */
  fake_set(&x.fake[1], false, url1, 200,
           "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":true,\"block_height\":329437,"
           "\"block_hash\":\"" HASH_329438 "\",\"block_time\":1793823982},\"value\":43000}]");
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, NULL),
               GZ_CHAIN_DISAGREE);
  /* the same outputs in a different order are the same answer */
  const char *two_ab =
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":" CONFIRMED_38 ",\"value\":1},"
      "{\"txid\":\"" TX_B "\",\"vout\":0,\"status\":" CONFIRMED_38 ",\"value\":2}]";
  const char *two_ba =
      "[{\"txid\":\"" TX_B "\",\"vout\":0,\"status\":" CONFIRMED_38 ",\"value\":2},"
      "{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":" CONFIRMED_38 ",\"value\":1}]";
  fake_set(&x.fake[0], false, B0 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200, two_ab);
  fake_set(&x.fake[1], false, url1, 200, two_ba);
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, NULL),
               GZ_CHAIN_OK);
  CHECK(n == 2);
  mfx_close(&x);
}

static void test_disagree_raw_tx_and_proof(test_state *T) {
  mfx x;
  ids k;
  gz_merkle_proof p;
  uint8_t raw[1024];
  size_t n = 5, len;
  mfx_open(&x, 2);
  ids_init(&k);
  /* Server two alters a witness byte. The txid still matches, so only the
   * byte comparison can notice. */
  char *hex = test_read_data("tx_a_hex.txt", &len);
  hex[len - 20] = hex[len - 20] == '0' ? '1' : '0';
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/hex", 200, hex);
  free(hex);
  CHECK_RESULT(gz_chain_raw_tx(&x.server[1], k.a, raw, sizeof raw, &n), GZ_CHAIN_OK);
  CHECK_RESULT(gz_chain_raw_tx(&x.multi, k.a, raw, sizeof raw, &n), GZ_CHAIN_DISAGREE);
  CHECK(n == 0 && raw[0] == 0 && raw[100] == 0); /* nothing handed over */

  /* proofs that differ in one thing each */
  char *json = test_read_data("tx_a_merkle_proof.json", &len);
  char *pos = strstr(json, "\"pos\":1");
  CHECK(pos != NULL);
  if (pos != NULL) pos[6] = '3'; /* position only */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/merkle-proof", 200, json);
  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_DISAGREE);
  CHECK(p.depth == 0);
  if (pos != NULL) pos[6] = '1';
  char *height = strstr(json, "329438");
  if (height != NULL) memcpy(height, "329439", 6); /* height only */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/merkle-proof", 200, json);
  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_DISAGREE);
  if (height != NULL) memcpy(height, "329438", 6);
  char *node = strstr(json, "84c32f9b");
  CHECK(node != NULL);
  if (node != NULL) node[0] = '9'; /* one node only */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/merkle-proof", 200, json);
  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_DISAGREE);
  free(json);
  /* one has a proof, the other says not confirmed, same tip */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/merkle-proof", 404,
           "Transaction not found or is unconfirmed");
  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_DISAGREE);
  mfx_close(&x);
}

/* ---- backends that are not what they say ---- */

typedef struct stub {
  int broadcasts;
} stub;

static gz_chain_result stub_block_hash(void *ctx, uint32_t height, uint8_t out[GZ_HASH_LEN]) {
  (void)ctx;
  if (height != 0) return GZ_CHAIN_NOT_FOUND;
  test_hash(GENESIS_SIGNET, out);
  return GZ_CHAIN_OK;
}

/* Fails, but writes into the caller's buffer first. */
static gz_chain_result scribble_raw_tx(void *ctx, const uint8_t txid[GZ_HASH_LEN], uint8_t *buf,
                                       size_t cap, size_t *len) {
  (void)ctx;
  (void)txid;
  memset(buf, 0xee, cap);
  *len = cap;
  return GZ_CHAIN_UNREACHABLE;
}

/* Says OK and hands back a different (real) transaction. */
static gz_chain_result wrong_raw_tx(void *ctx, const uint8_t txid[GZ_HASH_LEN], uint8_t *buf,
                                    size_t cap, size_t *len) {
  (void)ctx;
  (void)txid;
  *len = load_raw("tx_spender_hex.txt", buf, cap);
  return GZ_CHAIN_OK;
}

/* Says it accepted the broadcast, under another txid. */
static gz_chain_result wrong_broadcast(void *ctx, const uint8_t *raw, size_t len,
                                       gz_broadcast_result *out) {
  (void)raw;
  (void)len;
  ((stub *)ctx)->broadcasts++;
  test_hash(TX_B, out->txid);
  out->result = GZ_CHAIN_OK;
  return GZ_CHAIN_OK;
}

static void test_backends_are_not_taken_at_their_word(test_state *T) {
  mfx x;
  ids k;
  gz_multi_config mc;
  gz_chain m;
  gz_chain_ops ops;
  stub st = {0};
  uint8_t raw[1024], check[GZ_HASH_LEN], tx[1024];
  size_t n = 0;
  gz_broadcast_result br;
  mfx_open(&x, 2);
  ids_init(&k);
  gz_multi_config_default(&mc, GZ_NET_SIGNET);
  memset(&ops, 0, sizeof ops);
  ops.block_hash = stub_block_hash;

  /* a third backend fails after writing into the caller's buffer: the
   * agreed bytes are what comes back */
  ops.raw_tx = scribble_raw_tx;
  gz_chain three[3] = {x.server[0], x.server[1], {&st, &ops}};
  CHECK_RESULT(gz_multi_create(&mc, three, 3, &m), GZ_CHAIN_OK);
  CHECK(gz_multi_operator_count(&m) == 3); /* a backend that cannot name itself stands alone */
  CHECK_RESULT(gz_chain_raw_tx(&m, k.a, raw, sizeof raw, &n), GZ_CHAIN_OK);
  CHECK(n == 244);
  CHECK(gz_txid_from_raw(raw, n, check) && memcmp(check, k.a, GZ_HASH_LEN) == 0);
  CHECK(gz_multi_last_report(&m)->answers[2].result == GZ_CHAIN_UNREACHABLE);

  /* a backend that returns another transaction as if it were the one asked
   * for: its answer is thrown out, not compared */
  ops.raw_tx = wrong_raw_tx;
  CHECK_RESULT(gz_chain_raw_tx(&m, k.a, raw, sizeof raw, &n), GZ_CHAIN_OK);
  CHECK(gz_multi_last_report(&m)->answers[2].result == GZ_CHAIN_MALFORMED);
  CHECK(gz_txid_from_raw(raw, n, check) && memcmp(check, k.a, GZ_HASH_LEN) == 0);
  gz_chain_destroy(&m);
  /* ...and two such backends do not make an answer */
  stub st2 = {0};
  gz_chain liars[2] = {{&st, &ops}, {&st2, &ops}};
  CHECK_RESULT(gz_multi_create(&mc, liars, 2, &m), GZ_CHAIN_OK);
  CHECK_RESULT(gz_chain_raw_tx(&m, k.a, raw, sizeof raw, &n), GZ_CHAIN_MALFORMED);
  CHECK(n == 0);

  /* a backend that "accepts" a broadcast under another txid has not
   * accepted it */
  ops.broadcast = wrong_broadcast;
  size_t len = load_raw("tx_a_hex.txt", tx, sizeof tx);
  CHECK_RESULT(gz_chain_broadcast(&m, tx, len, &br), GZ_CHAIN_MALFORMED);
  CHECK(st.broadcasts == 1 && st2.broadcasts == 1);
  CHECK(gz_multi_last_report(&m)->answers[0].result == GZ_CHAIN_MALFORMED);
  gz_chain_destroy(&m);
  mfx_close(&x);
}

/* ---- a server that invents a confirmation ---- */

static void test_lying_server_invents_a_confirmation(test_state *T) {
  mfx x;
  ids k;
  gz_tx_status st;
  gz_confirmation conf;
  mfx_open(&x, 2);
  ids_init(&k);
  /* The spender is a real transaction (in block 329439). Server two claims
   * it confirmed in block 329438 and backs the claim with the real proof of
   * transaction A. */
  fake_set_file(&x.fake[1], B1 "/tx/" TX_SPENDER "/status", 200, "tx_a_status.json");
  fake_set_file(&x.fake[1], B1 "/tx/" TX_SPENDER "/merkle-proof", 200, "tx_a_merkle_proof.json");

  /* caught by the liar's own proof failing against the header ... */
  CHECK_RESULT(gz_chain_confirm_tx(&x.server[1], GZ_NET_SIGNET, k.spender, 6, &conf),
               GZ_CHAIN_BAD_PROOF);
  /* ... and caught by the honest server contradicting it */
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.spender, &st), GZ_CHAIN_DISAGREE);
  CHECK(st.state == GZ_TX_UNKNOWN);
  CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.spender, 6, &conf), GZ_CHAIN_DISAGREE);
  CHECK(conf.status.state == GZ_TX_UNKNOWN);

  /* If every server tells the same lie the comparison passes, and the Merkle
   * proof against the header is what still catches it. */
  fake_set_file(&x.fake[0], B0 "/tx/" TX_SPENDER "/status", 200, "tx_a_status.json");
  fake_set_file(&x.fake[0], B0 "/tx/" TX_SPENDER "/merkle-proof", 200, "tx_a_merkle_proof.json");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.spender, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_CONFIRMED && st.height == 329438); /* the unchecked claim looks agreed */
  CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.spender, 6, &conf),
               GZ_CHAIN_BAD_PROOF);
  CHECK(conf.status.state == GZ_TX_UNKNOWN && conf.checked_confirmations == 0);
  mfx_close(&x);
}

static void test_invented_tip_does_not_raise_confirmations(test_state *T) {
  mfx x;
  ids k;
  gz_confirmation conf;
  gz_tx_status st;
  mfx_open(&x, 2);
  ids_init(&k);
  /* one server claims a tip a million blocks up */
  fake_set(&x.fake[1], false, B1 "/blocks/tip/height", 200, "1329439");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_OK);
  CHECK(st.claimed_confirmations == 2); /* the lower claim */
  CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.a, 6, &conf), GZ_CHAIN_OK);
  CHECK(conf.checked_confirmations == 2);
  /* both do: the claim goes up, the checked number does not */
  fake_set(&x.fake[0], false, B0 "/blocks/tip/height", 200, "1329439");
  CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.a, 6, &conf), GZ_CHAIN_OK);
  CHECK(conf.status.claimed_confirmations == 1000002);
  CHECK(conf.checked_confirmations == 2);
  mfx_close(&x);
}

/* ---- servers that are down ---- */

static void test_one_down_of_two(test_state *T) {
  mfx x;
  ids k;
  gz_chain_tip tip;
  gz_tx_status st;
  gz_outspend o;
  gz_merkle_proof p;
  gz_fee_estimates f;
  gz_block_summary sum;
  gz_chain_output outs[4];
  gz_confirmation conf;
  uint8_t h[GZ_HASH_LEN], hdr[GZ_HEADER_LEN], raw[1024];
  size_t n;
  mfx_open(&x, 2);
  ids_init(&k);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_OK); /* both known to be on signet */
  x.fake[1].down = true;

  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_NO_QUORUM);
  CHECK(tip.height == 0);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[0].u.tip.height == TIP_HEIGHT);
  CHECK(rep->answers[1].result == GZ_CHAIN_UNREACHABLE);
  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329438, h), GZ_CHAIN_NO_QUORUM);
  CHECK_RESULT(gz_chain_block_header(&x.multi, 329438, hdr), GZ_CHAIN_NO_QUORUM);
  CHECK_RESULT(gz_chain_block_summary(&x.multi, 329438, &sum), GZ_CHAIN_NO_QUORUM);
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_NO_QUORUM);
  CHECK(st.state == GZ_TX_UNKNOWN && st.claimed_confirmations == 0);
  CHECK(rep->answers[0].u.tx_status.state == GZ_TX_CONFIRMED); /* reported, not returned */
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, NULL),
               GZ_CHAIN_NO_QUORUM);
  CHECK(n == 0);
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_NO_QUORUM);
  CHECK(!o.spent);
  CHECK_RESULT(gz_chain_raw_tx(&x.multi, k.a, raw, sizeof raw, &n), GZ_CHAIN_NO_QUORUM);
  CHECK(n == 0);
  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_NO_QUORUM);
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_NO_QUORUM);
  CHECK(f.count == 0);
  CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.a, 6, &conf), GZ_CHAIN_NO_QUORUM);
  /* a single "not found" is not an agreed "not found" either */
  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329440, h), GZ_CHAIN_NO_QUORUM);

  /* both down: the common failure is named */
  x.fake[0].down = true;
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_UNREACHABLE);
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_UNREACHABLE);
  mfx_close(&x);

  /* down from the very start: its network was never checked, same result */
  mfx_open(&x, 2);
  x.fake[1].down = true;
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_NO_QUORUM);
  CHECK(gz_multi_last_report(&x.multi)->answers[1].result == GZ_CHAIN_UNREACHABLE);
  mfx_close(&x);
}

static void test_one_down_of_three(test_state *T) {
  mfx x;
  ids k;
  gz_chain_tip tip;
  gz_tx_status st;
  gz_outspend o;
  gz_merkle_proof p;
  gz_fee_estimates f;
  gz_block_summary sum;
  gz_chain_output outs[4];
  gz_confirmation conf;
  uint8_t h[GZ_HASH_LEN], hdr[GZ_HEADER_LEN], raw[1024];
  size_t n;
  mfx_open(&x, 3);
  ids_init(&k);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);

  for (size_t down = 0; down < 3; down++) {
    x.fake[0].down = x.fake[1].down = x.fake[2].down = false;
    x.fake[down].down = true;
    CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_OK);
    CHECK(tip.height == TIP_HEIGHT);
    CHECK(rep->server_count == 3 && rep->answers[down].result == GZ_CHAIN_UNREACHABLE);
    CHECK_RESULT(gz_chain_block_hash(&x.multi, 329438, h), GZ_CHAIN_OK);
    CHECK_RESULT(gz_chain_block_header(&x.multi, 329438, hdr), GZ_CHAIN_OK);
    CHECK_RESULT(gz_chain_block_summary(&x.multi, 329438, &sum), GZ_CHAIN_OK);
    CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_OK);
    CHECK(st.state == GZ_TX_CONFIRMED && st.claimed_confirmations == 2);
    CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n, NULL),
                 GZ_CHAIN_OK);
    CHECK(n == 1);
    CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_OK);
    CHECK(o.spent);
    CHECK_RESULT(gz_chain_raw_tx(&x.multi, k.a, raw, sizeof raw, &n), GZ_CHAIN_OK);
    CHECK(n == 244 && gz_txid_from_raw(raw, n, h) && memcmp(h, k.a, GZ_HASH_LEN) == 0);
    CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_OK);
    CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_OK);
    CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.a, 6, &conf), GZ_CHAIN_OK);
    CHECK(conf.checked_confirmations == 2);
  }
  /* two down of three: no answer */
  x.fake[0].down = true;
  x.fake[1].down = false;
  x.fake[2].down = true;
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_NO_QUORUM);
  mfx_close(&x);
}

static void test_three_servers_one_wrong(test_state *T) {
  mfx x;
  ids k;
  gz_tx_status st;
  gz_outspend o;
  mfx_open(&x, 3);
  ids_init(&k);
  /* a server sending rubbish counts as down: the other two still answer */
  fake_set(&x.fake[2], false, B2 "/tx/" TX_A "/status", 200, "<html>busy</html>");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_OK);
  CHECK(gz_multi_last_report(&x.multi)->answers[2].result == GZ_CHAIN_MALFORMED);
  /* a server giving a well-formed contradiction about a confirmed spend
   * withholds the answer, even though two others agree: there is no vote */
  fake_set(&x.fake[2], false, B2 "/tx/" TX_A "/outspend/0", 200, "{\"spent\":false}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_DISAGREE);
  CHECK(!o.spent);
  mfx_close(&x);
}

/* ---- broadcast ---- */

static void test_broadcast(test_state *T) {
  mfx x;
  ids k;
  gz_broadcast_result br;
  gz_chain_tip tip;
  uint8_t raw[1024];
  mfx_open(&x, 3);
  ids_init(&k);
  size_t len = load_raw("tx_a_hex.txt", raw, sizeof raw);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);
  const char *refusal = "sendrawtransaction RPC error -26: min relay fee not met";
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_OK);

  /* all accept; all were sent it */
  fake_set(&x.fake[0], true, B0 "/tx", 200, TX_A);
  fake_set(&x.fake[1], true, B1 "/tx", 200, TX_A);
  fake_set(&x.fake[2], true, B2 "/tx", 200, TX_A);
  CHECK_RESULT(gz_chain_broadcast(&x.multi, raw, len, &br), GZ_CHAIN_OK);
  CHECK(memcmp(br.txid, k.a, GZ_HASH_LEN) == 0);
  CHECK(fake_hits(&x.fake[0], true, B0 "/tx") == 1 && fake_hits(&x.fake[1], true, B1 "/tx") == 1 &&
        fake_hits(&x.fake[2], true, B2 "/tx") == 1);

  /* one accepts, one refuses, one is down: success, with each result kept */
  fake_set(&x.fake[0], true, B0 "/tx", 400, refusal);
  x.fake[2].down = true;
  CHECK_RESULT(gz_chain_broadcast(&x.multi, raw, len, &br), GZ_CHAIN_OK);
  CHECK(br.result == GZ_CHAIN_OK && memcmp(br.txid, k.a, GZ_HASH_LEN) == 0);
  CHECK(rep->call == GZ_CALL_BROADCAST && rep->verdict == GZ_CHAIN_OK);
  CHECK(rep->answers[0].result == GZ_CHAIN_REJECTED);
  CHECK(strcmp(rep->answers[0].u.broadcast.reason, refusal) == 0);
  CHECK(rep->answers[1].result == GZ_CHAIN_OK);
  CHECK(rep->answers[2].result == GZ_CHAIN_UNREACHABLE);

  /* none accepts, one refuses: refused, with the reason */
  fake_set(&x.fake[1], true, B1 "/tx", 200, TX_B); /* "accepts" something else: malformed */
  CHECK_RESULT(gz_chain_broadcast(&x.multi, raw, len, &br), GZ_CHAIN_REJECTED);
  CHECK(strcmp(br.reason, refusal) == 0 && br.server_status == 400);
  CHECK(rep->answers[1].result == GZ_CHAIN_MALFORMED);

  /* a server that already has the transaction counts as having taken it */
  char *known = test_read_data("post_known_blockstream.txt", NULL);
  fake_set(&x.fake[1], true, B1 "/tx", 400, known);
  free(known);
  CHECK_RESULT(gz_chain_broadcast(&x.multi, raw, len, &br), GZ_CHAIN_OK);
  CHECK(br.already_known && memcmp(br.txid, k.a, GZ_HASH_LEN) == 0);

  /* nobody reachable */
  x.fake[0].down = x.fake[1].down = true;
  CHECK_RESULT(gz_chain_broadcast(&x.multi, raw, len, &br), GZ_CHAIN_UNREACHABLE);

  /* not a transaction: nothing is sent to anyone */
  x.fake[0].down = x.fake[1].down = x.fake[2].down = false;
  unsigned before = x.fake[0].requests + x.fake[1].requests + x.fake[2].requests;
  CHECK_RESULT(gz_chain_broadcast(&x.multi, raw, len - 3, &br), GZ_CHAIN_INVALID_ARG);
  CHECK(x.fake[0].requests + x.fake[1].requests + x.fake[2].requests == before);
  mfx_close(&x);
}

/* ---- fees ---- */

static void test_fee_rule(test_state *T) {
  mfx x;
  gz_fee_estimates f;
  gz_fee_choice choice;
  mfx_open(&x, 2);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);

  /* only targets every server lists; the LOWER rate for each */
  fake_set(&x.fake[0], false, B0 "/fee-estimates", 200, "{\"1\":5.5,\"6\":2,\"144\":1}");
  fake_set(&x.fake[1], false, B1 "/fee-estimates", 200, "{\"1\":4,\"6\":3.25,\"1008\":1}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_OK);
  CHECK(f.count == 2);
  CHECK(f.entries[0].target == 1 && f.entries[0].sat_per_kvb == 4000);
  CHECK(f.entries[1].target == 6 && f.entries[1].sat_per_kvb == 2000);
  CHECK(rep->answers[0].u.fees.count == 3 && rep->answers[1].u.fees.entries[0].sat_per_kvb == 4000);

  /* The reviewer's case: one server at 0.1 sat/vB, one at 2000. No single
   * server sets the rate: this is a disagreement, not "2000". */
  fake_set(&x.fake[0], false, B0 "/fee-estimates", 200, "{\"1\":0.1,\"6\":0.1}");
  fake_set(&x.fake[1], false, B1 "/fee-estimates", 200, "{\"1\":2000,\"6\":2000}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_DISAGREE);
  CHECK(f.count == 0);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[1].result == GZ_CHAIN_OK);
  /* and no rate comes out of it on mainnet rules */
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.multi, GZ_NET_MAINNET, 6, 200000, &choice),
               GZ_CHAIN_DISAGREE);
  CHECK(choice.sat_per_kvb == 0);
  /* while on a test network the fixed rate is used and nobody is asked */
  unsigned before = x.fake[0].requests + x.fake[1].requests;
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.multi, GZ_NET_SIGNET, 6, 200000, &choice), GZ_CHAIN_OK);
  CHECK(choice.sat_per_kvb == 100 && choice.source == GZ_FEE_FROM_TEST_DEFAULT);
  CHECK(x.fake[0].requests + x.fake[1].requests == before);

  /* the recorded signet answers of the two operators (1 against 10 sat/vB
   * for the next block) are too far apart as well */
  fake_set_file(&x.fake[0], B0 "/fee-estimates", 203, "fee_estimates_mempool.json");
  fake_set_file(&x.fake[1], B1 "/fee-estimates", 200, "fee_estimates_blockstream.json");
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_DISAGREE);

  /* the edge of the rule: factor 3 plus 1 sat/vB of slack */
  fake_set(&x.fake[0], false, B0 "/fee-estimates", 200, "{\"1\":10}");
  fake_set(&x.fake[1], false, B1 "/fee-estimates", 200, "{\"1\":31}"); /* = 3 * 10 + 1 */
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_OK);
  CHECK(f.entries[0].sat_per_kvb == 10000);
  fake_set(&x.fake[1], false, B1 "/fee-estimates", 200, "{\"1\":31.001}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_DISAGREE);
  /* small rates: within the slack whatever the ratio */
  fake_set(&x.fake[0], false, B0 "/fee-estimates", 200, "{\"1\":0.1}");
  fake_set(&x.fake[1], false, B1 "/fee-estimates", 200, "{\"1\":1}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_OK);
  CHECK(f.entries[0].sat_per_kvb == 100);

  /* servers that agree on a high rate: cut at the ceiling (200 sat/vB) */
  fake_set(&x.fake[0], false, B0 "/fee-estimates", 200, "{\"1\":900}");
  fake_set(&x.fake[1], false, B1 "/fee-estimates", 200, "{\"1\":950}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_OK);
  CHECK(f.entries[0].sat_per_kvb == 200000);
  CHECK_RESULT(gz_chain_choose_fee_rate(&x.multi, GZ_NET_MAINNET, 1, 50000, &choice), GZ_CHAIN_OK);
  CHECK(choice.sat_per_kvb == 50000 && choice.capped); /* the caller's own, lower ceiling */

  /* one server down: no estimate from a single operator */
  x.fake[1].down = true;
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_NO_QUORUM);
  mfx_close(&x);

  /* the caller's ceiling and the rule's numbers are checked at creation */
  mfx_open(&x, 2);
  gz_multi_config mc;
  gz_chain m;
  gz_multi_config_default(&mc, GZ_NET_SIGNET);
  CHECK(mc.fee_ceiling_sat_per_kvb == 200000 && mc.fee_disagree_factor == 3);
  mc.fee_ceiling_sat_per_kvb = 0;
  CHECK_RESULT(gz_multi_create(&mc, x.server, 2, &m), GZ_CHAIN_INVALID_ARG);
  mc.fee_ceiling_sat_per_kvb = GZ_FEE_MAX_SAT_PER_KVB + 1;
  CHECK_RESULT(gz_multi_create(&mc, x.server, 2, &m), GZ_CHAIN_INVALID_ARG);
  mc.fee_ceiling_sat_per_kvb = 2000;
  mc.fee_disagree_factor = 0;
  CHECK_RESULT(gz_multi_create(&mc, x.server, 2, &m), GZ_CHAIN_INVALID_ARG);
  mc.fee_disagree_factor = 1;
  mc.fee_disagree_slack_sat_per_kvb = 0;
  CHECK_RESULT(gz_multi_create(&mc, x.server, 2, &m), GZ_CHAIN_OK);
  /* a caller-chosen ceiling of 2 sat/vB, and the strictest rule: equal or nothing */
  fake_set(&x.fake[0], false, B0 "/fee-estimates", 200, "{\"1\":7}");
  fake_set(&x.fake[1], false, B1 "/fee-estimates", 200, "{\"1\":7}");
  CHECK_RESULT(gz_chain_fee_estimates(&m, &f), GZ_CHAIN_OK);
  CHECK(f.entries[0].sat_per_kvb == 2000);
  fake_set(&x.fake[1], false, B1 "/fee-estimates", 200, "{\"1\":7.001}");
  CHECK_RESULT(gz_chain_fee_estimates(&m, &f), GZ_CHAIN_DISAGREE);
  gz_chain_destroy(&m);
  mfx_close(&x);
}

/* ---- creation ---- */

static void test_create_and_single_server(test_state *T) {
  mfx x;
  ids k;
  gz_multi_config mc;
  gz_chain m;
  gz_tx_status st;
  mfx_open(&x, 2);
  ids_init(&k);
  gz_multi_config_default(&mc, GZ_NET_SIGNET);
  CHECK(mc.quorum == 2 && mc.tip_slack == 1 && mc.network == GZ_NET_SIGNET);
  CHECK_RESULT(gz_multi_create(&mc, x.server, 0, &m), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_multi_create(&mc, NULL, 2, &m), GZ_CHAIN_INVALID_ARG);
  mc.quorum = 1; /* an "agreement" of one server is refused outright */
  CHECK_RESULT(gz_multi_create(&mc, x.server, 2, &m), GZ_CHAIN_INVALID_ARG);
  CHECK(m.ctx == NULL);
  mc.quorum = 2;
  mc.tip_slack = 7; /* "the same chain" cannot be stretched without bound */
  CHECK_RESULT(gz_multi_create(&mc, x.server, 2, &m), GZ_CHAIN_INVALID_ARG);
  mc.tip_slack = 1;
  gz_chain empty[2] = {{NULL, NULL}, {NULL, NULL}};
  CHECK_RESULT(gz_multi_create(&mc, empty, 2, &m), GZ_CHAIN_INVALID_ARG);

  /* more servers than the backend has room for: nine real, distinct ones */
  fake_http fake;
  gz_chain nine[GZ_MULTI_MAX_SERVERS + 1];
  fake_init(&fake);
  for (int i = 0; i <= GZ_MULTI_MAX_SERVERS; i++) {
    char url[64];
    snprintf(url, sizeof url, "https://host%d.test/api", i);
    nine[i] = make_server(&fake, url, NULL);
  }
  CHECK_RESULT(gz_multi_create(&mc, nine, GZ_MULTI_MAX_SERVERS + 1, &m), GZ_CHAIN_INVALID_ARG);
  CHECK(m.ctx == NULL);
  CHECK_RESULT(gz_multi_create(&mc, nine, GZ_MULTI_MAX_SERVERS, &m), GZ_CHAIN_OK);
  CHECK(gz_multi_operator_count(&m) == GZ_MULTI_MAX_SERVERS);
  gz_chain_destroy(&m);
  for (int i = 0; i <= GZ_MULTI_MAX_SERVERS; i++) gz_chain_destroy(&nine[i]);
  fake_free(&fake);

  /* one server only: allowed so its answer can be shown, never returned */
  CHECK_RESULT(gz_multi_create(&mc, x.server, 1, &m), GZ_CHAIN_OK);
  CHECK(gz_multi_operator_count(&m) == 1);
  CHECK_RESULT(gz_chain_tx_status(&m, k.a, &st), GZ_CHAIN_NO_QUORUM);
  CHECK(st.state == GZ_TX_UNKNOWN);
  CHECK(gz_multi_last_report(&m)->server_count == 1);
  CHECK(gz_multi_last_report(&m)->answers[0].u.tx_status.state == GZ_TX_CONFIRMED);
  gz_chain_destroy(&m);
  CHECK(gz_multi_last_report(&m) == NULL);

  /* a quorum of three over three servers needs all three */
  mfx_close(&x);
  mfx_open(&x, 3);
  mc.quorum = 3;
  CHECK_RESULT(gz_multi_create(&mc, x.server, 3, &m), GZ_CHAIN_OK);
  CHECK_RESULT(gz_chain_tx_status(&m, k.a, &st), GZ_CHAIN_OK);
  x.fake[2].down = true;
  CHECK_RESULT(gz_chain_tx_status(&m, k.a, &st), GZ_CHAIN_NO_QUORUM);
  gz_chain_destroy(&m);
  mfx_close(&x);
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  RUN(test_two_servers_agree_on_everything);
  RUN(test_duplicate_servers_refused);
  RUN(test_one_operator_is_not_two);
  RUN(test_wrong_network_server_never_counts);
  RUN(test_tip_rule);
  RUN(test_disagree_block_hash_and_header);
  RUN(test_disagree_tx_status);
  RUN(test_lag_is_not_disagreement);
  RUN(test_unconfirmed_differences_do_not_blank_the_view);
  RUN(test_lying_server_omits_a_spend);
  RUN(test_disagree_script_outputs);
  RUN(test_disagree_raw_tx_and_proof);
  RUN(test_backends_are_not_taken_at_their_word);
  RUN(test_lying_server_invents_a_confirmation);
  RUN(test_invented_tip_does_not_raise_confirmations);
  RUN(test_one_down_of_two);
  RUN(test_one_down_of_three);
  RUN(test_three_servers_one_wrong);
  RUN(test_broadcast);
  RUN(test_fee_rule);
  RUN(test_create_and_single_server);
  TEST_MAIN_END("test_multi");
}
