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
    fake_load_honest(&x->fake[i], BASES[i], i == 1);
    gz_http http = fake_transport(&x->fake[i]);
    gz_esplora_config_default(&cfg);
    cfg.base_url = BASES[i];
    if (gz_esplora_create(&cfg, &http, &x->server[i]) != GZ_CHAIN_OK) exit(2);
  }
  gz_multi_config_default(&mc);
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

/* ---- agreement ---- */

static void test_two_servers_agree_on_everything(test_state *T) {
  mfx x;
  ids k;
  gz_chain_tip tip;
  gz_tx_status st;
  gz_outspend o;
  gz_merkle_proof p;
  gz_fee_estimates f;
  gz_chain_output outs[4];
  gz_confirmation conf;
  uint8_t h[GZ_HASH_LEN], hdr[GZ_HEADER_LEN], raw[1024];
  size_t n;
  mfx_open(&x, 2);
  ids_init(&k);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);
  CHECK(rep != NULL && rep->call == GZ_CALL_NONE);
  CHECK(gz_multi_last_report(&x.server[0]) == NULL); /* not a comparing backend */

  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_OK);
  CHECK(tip.height == TIP_HEIGHT && memcmp(tip.hash, k.h39, GZ_HASH_LEN) == 0);
  CHECK(rep->call == GZ_CALL_TIP && rep->verdict == GZ_CHAIN_OK && rep->server_count == 2);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[1].result == GZ_CHAIN_OK);
  CHECK(rep->answers[1].u.tip.height == TIP_HEIGHT);

  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329438, h), GZ_CHAIN_OK);
  CHECK(memcmp(h, k.h38, GZ_HASH_LEN) == 0);
  CHECK_RESULT(gz_chain_block_header(&x.multi, 329438, hdr), GZ_CHAIN_OK);
  gz_header_hash(hdr, h);
  CHECK(memcmp(h, k.h38, GZ_HASH_LEN) == 0);

  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_CONFIRMED && st.height == 329438 && st.confirmations == 2);
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.none, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_UNKNOWN);

  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n), GZ_CHAIN_OK);
  CHECK(n == 1 && outs[0].vout == 2 && outs[0].value == 43000);
  CHECK(rep->call == GZ_CALL_SCRIPT_OUTPUTS && rep->answers[1].u.outputs.count == 1);

  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_OK);
  CHECK(o.spent && memcmp(o.spender_txid, k.spender, GZ_HASH_LEN) == 0);
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 2, &o), GZ_CHAIN_OK);
  CHECK(!o.spent);

  CHECK_RESULT(gz_chain_raw_tx(&x.multi, k.a, raw, sizeof raw, &n), GZ_CHAIN_OK);
  CHECK(n == 244 && gz_txid_from_raw(raw, n, h) && memcmp(h, k.a, GZ_HASH_LEN) == 0);

  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_OK);
  CHECK(gz_merkle_verify(k.a, &p, hdr));

  /* fees: both recorded answers list the same 28 targets; the higher rate
   * is taken for each (mempool.space said 1, blockstream.info said 10) */
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_OK);
  CHECK(f.count == 28 && f.entries[0].target == 1 && f.entries[0].sat_per_kvb == 10000);
  CHECK(rep->answers[0].u.fees.entries[0].sat_per_kvb == 1000);
  CHECK(rep->answers[1].u.fees.count == 28);

  /* the checked confirmation, with every step compared across servers */
  CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.a, &conf), GZ_CHAIN_OK);
  CHECK(conf.status.state == GZ_TX_CONFIRMED && conf.status.confirmations == 2);

  /* both saying "no" is an agreed answer too */
  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329440, h), GZ_CHAIN_NOT_FOUND);
  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.none, &p), GZ_CHAIN_NOT_FOUND);
  CHECK_RESULT(gz_chain_raw_tx(&x.multi, k.none, raw, sizeof raw, &n), GZ_CHAIN_NOT_FOUND);
  CHECK(x.fake[0].unexpected == 0 && x.fake[1].unexpected == 0);
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

/* ---- each kind of disagreement ---- */

static void test_disagree_block_hash_and_header(test_state *T) {
  mfx x;
  uint8_t h[GZ_HASH_LEN], hdr[GZ_HEADER_LEN];
  mfx_open(&x, 2);
  /* server two serves a different (self-consistent) block at 329438 */
  fake_set(&x.fake[1], false, B1 "/block-height/329438", 200, HASH_329437);
  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329438, h), GZ_CHAIN_DISAGREE);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[1].result == GZ_CHAIN_OK);
  CHECK(memcmp(rep->answers[0].u.block_hash, rep->answers[1].u.block_hash, GZ_HASH_LEN) != 0);
  CHECK_RESULT(gz_chain_block_header(&x.multi, 329438, hdr), GZ_CHAIN_DISAGREE);
  CHECK(memcmp(rep->answers[0].u.header, rep->answers[1].u.header, GZ_HEADER_LEN) != 0);
  /* one has the block, the other says there is none */
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

  /* confirmed on one, never seen on the other (a server hiding it) */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/status", 200, "{\"confirmed\":false}");
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/hex", 404, "Transaction not found");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_DISAGREE);
  CHECK(st.state == GZ_TX_UNKNOWN && st.confirmations == 0); /* caller gets nothing */
  CHECK(rep->answers[0].u.tx_status.state == GZ_TX_CONFIRMED);
  CHECK(rep->answers[1].u.tx_status.state == GZ_TX_UNKNOWN);

  /* confirmed on one, in the mempool on the other */
  fake_set_file(&x.fake[1], B1 "/tx/" TX_A "/hex", 200, "tx_a_hex.txt");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_DISAGREE);
  CHECK(rep->answers[1].u.tx_status.state == GZ_TX_MEMPOOL);

  /* confirmed on both, in different blocks */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/status", 200,
           "{\"confirmed\":true,\"block_height\":329438,\"block_hash\":\"" HASH_329437
           "\",\"block_time\":1793823982}");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_DISAGREE);
  /* confirmed on both, same hash, different heights */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/status", 200,
           "{\"confirmed\":true,\"block_height\":329437,\"block_hash\":\"" HASH_329438
           "\",\"block_time\":1793823982}");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_DISAGREE);

  /* agreement again, with different tips: the lower confirmation count wins */
  fake_set_file(&x.fake[1], B1 "/tx/" TX_A "/status", 200, "tx_a_status.json");
  fake_set(&x.fake[1], false, B1 "/blocks/tip/height", 200, "329445");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_OK);
  CHECK(st.confirmations == 2 && st.tip_height == TIP_HEIGHT);
  CHECK(rep->answers[1].u.tx_status.confirmations == 8);
  mfx_close(&x);
}

static void test_lying_server_omits_a_spend(test_state *T) {
  mfx x;
  ids k;
  gz_outspend o;
  mfx_open(&x, 2);
  ids_init(&k);
  /* The watched output TX_A:0 has been spent. Server two hides it. */
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

  /* other differences about a spend */
  fake_set(&x.fake[0], false, B0 "/tx/" TX_A "/outspend/0", 200,
           "{\"spent\":true,\"txid\":\"" TX_B "\",\"vin\":0,\"status\":{\"confirmed\":true,"
           "\"block_height\":329439,\"block_hash\":\"" HASH_329439 "\",\"block_time\":1793824361}}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_DISAGREE); /* another spender */
  fake_set(&x.fake[0], false, B0 "/tx/" TX_A "/outspend/0", 200,
           "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":1,\"status\":{\"confirmed\":true,"
           "\"block_height\":329439,\"block_hash\":\"" HASH_329439 "\",\"block_time\":1793824361}}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_DISAGREE); /* another input */
  fake_set(&x.fake[0], false, B0 "/tx/" TX_A "/outspend/0", 200,
           "{\"spent\":true,\"txid\":\"" TX_SPENDER "\",\"vin\":0,\"status\":{\"confirmed\":false}}");
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_DISAGREE); /* unconfirmed vs confirmed */
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
  /* one server hides the output */
  fake_set(&x.fake[1], false, B1 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200, "[]");
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n),
               GZ_CHAIN_DISAGREE);
  CHECK(n == 0);
  CHECK(rep->answers[0].u.outputs.count == 1 && rep->answers[1].u.outputs.count == 0);
  CHECK(rep->answers[0].u.outputs.items[0].value == 43000);
  /* one server reports a different amount */
  fake_set(&x.fake[1], false, B1 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200,
           "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":true,\"block_height\":329438,"
           "\"block_hash\":\"" HASH_329438 "\",\"block_time\":1793823982},\"value\":43001}]");
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n),
               GZ_CHAIN_DISAGREE);
  /* one server invents an extra, unconfirmed output */
  fake_set(&x.fake[1], false, B1 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200,
           "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":true,\"block_height\":329438,"
           "\"block_hash\":\"" HASH_329438 "\",\"block_time\":1793823982},\"value\":43000},"
           "{\"txid\":\"" TX_B "\",\"vout\":0,\"status\":{\"confirmed\":false},\"value\":100000000}]");
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n),
               GZ_CHAIN_DISAGREE);
  /* the same outputs in a different order are the same answer */
  const char *two_ab =
      "[{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":false},\"value\":1},"
      "{\"txid\":\"" TX_B "\",\"vout\":0,\"status\":{\"confirmed\":false},\"value\":2}]";
  const char *two_ba =
      "[{\"txid\":\"" TX_B "\",\"vout\":0,\"status\":{\"confirmed\":false},\"value\":2},"
      "{\"txid\":\"" TX_A "\",\"vout\":2,\"status\":{\"confirmed\":false},\"value\":1}]";
  fake_set(&x.fake[0], false, B0 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200, two_ab);
  fake_set(&x.fake[1], false, B1 "/scripthash/" SCRIPT_A2_HASH "/utxo", 200, two_ba);
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n), GZ_CHAIN_OK);
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

  /* a proof that differs (here: another transaction's) */
  fake_set_file(&x.fake[1], B1 "/tx/" TX_A "/merkle-proof", 200, "tx_b_merkle_proof.json");
  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_DISAGREE);
  CHECK(p.depth == 0);
  /* one has a proof, the other says not confirmed */
  fake_set(&x.fake[1], false, B1 "/tx/" TX_A "/merkle-proof", 404,
           "Transaction not found or is unconfirmed");
  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_DISAGREE);
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
  /* TX_NONE is in no block. Server two claims it confirmed in block 329438
   * and backs the claim with the real proof of another transaction. */
  fake_set_file(&x.fake[1], B1 "/tx/" TX_NONE "/status", 200, "tx_a_status.json");
  fake_set_file(&x.fake[1], B1 "/tx/" TX_NONE "/merkle-proof", 200, "tx_a_merkle_proof.json");

  /* caught by the liar's own proof failing against the header ... */
  CHECK_RESULT(gz_chain_confirm_tx(&x.server[1], GZ_NET_SIGNET, k.none, &conf), GZ_CHAIN_BAD_PROOF);
  /* ... and caught by the honest server disagreeing */
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.none, &st), GZ_CHAIN_DISAGREE);
  CHECK(st.state == GZ_TX_UNKNOWN);
  CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.none, &conf), GZ_CHAIN_DISAGREE);
  CHECK(conf.status.state == GZ_TX_UNKNOWN);

  /* If every server tells the same lie the comparison passes, and the Merkle
   * proof against the header is what still catches it. */
  fake_set_file(&x.fake[0], B0 "/tx/" TX_NONE "/status", 200, "tx_a_status.json");
  fake_set_file(&x.fake[0], B0 "/tx/" TX_NONE "/merkle-proof", 200, "tx_a_merkle_proof.json");
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.none, &st), GZ_CHAIN_OK);
  CHECK(st.state == GZ_TX_CONFIRMED); /* the unchecked claim looks agreed */
  CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.none, &conf), GZ_CHAIN_BAD_PROOF);
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
  gz_chain_output outs[4];
  gz_confirmation conf;
  uint8_t h[GZ_HASH_LEN], hdr[GZ_HEADER_LEN], raw[1024];
  size_t n;
  mfx_open(&x, 2);
  ids_init(&k);
  x.fake[1].down = true;
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);

  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_NO_QUORUM);
  CHECK(tip.height == 0);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[0].u.tip.height == TIP_HEIGHT);
  CHECK(rep->answers[1].result == GZ_CHAIN_UNREACHABLE);
  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329438, h), GZ_CHAIN_NO_QUORUM);
  CHECK_RESULT(gz_chain_block_header(&x.multi, 329438, hdr), GZ_CHAIN_NO_QUORUM);
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_NO_QUORUM);
  CHECK(st.state == GZ_TX_UNKNOWN && st.confirmations == 0);
  CHECK(rep->answers[0].u.tx_status.state == GZ_TX_CONFIRMED); /* reported, not returned */
  CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n),
               GZ_CHAIN_NO_QUORUM);
  CHECK(n == 0);
  CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_NO_QUORUM);
  CHECK(!o.spent);
  CHECK_RESULT(gz_chain_raw_tx(&x.multi, k.a, raw, sizeof raw, &n), GZ_CHAIN_NO_QUORUM);
  CHECK(n == 0);
  CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_NO_QUORUM);
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_NO_QUORUM);
  CHECK(f.count == 0);
  CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.a, &conf), GZ_CHAIN_NO_QUORUM);
  /* a single "not found" is not an agreed "not found" either */
  CHECK_RESULT(gz_chain_block_hash(&x.multi, 329440, h), GZ_CHAIN_NO_QUORUM);

  /* both down: the common failure is named */
  x.fake[0].down = true;
  CHECK_RESULT(gz_chain_tip_get(&x.multi, &tip), GZ_CHAIN_UNREACHABLE);
  CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_UNREACHABLE);
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
    CHECK_RESULT(gz_chain_tx_status(&x.multi, k.a, &st), GZ_CHAIN_OK);
    CHECK(st.state == GZ_TX_CONFIRMED && st.confirmations == 2);
    CHECK_RESULT(gz_chain_script_outputs(&x.multi, k.script, k.script_len, outs, 4, &n),
                 GZ_CHAIN_OK);
    CHECK(n == 1);
    CHECK_RESULT(gz_chain_outspend(&x.multi, k.a, 0, &o), GZ_CHAIN_OK);
    CHECK(o.spent);
    CHECK_RESULT(gz_chain_raw_tx(&x.multi, k.a, raw, sizeof raw, &n), GZ_CHAIN_OK);
    CHECK(n == 244 && gz_txid_from_raw(raw, n, h) && memcmp(h, k.a, GZ_HASH_LEN) == 0);
    CHECK_RESULT(gz_chain_merkle_proof(&x.multi, k.a, &p), GZ_CHAIN_OK);
    CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_OK);
    CHECK_RESULT(gz_chain_confirm_tx(&x.multi, GZ_NET_SIGNET, k.a, &conf), GZ_CHAIN_OK);
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
  /* a server giving a well-formed different answer withholds the answer,
   * even though two others agree: there is no majority vote */
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
  uint8_t raw[1024];
  mfx_open(&x, 3);
  ids_init(&k);
  size_t len = load_raw("tx_a_hex.txt", raw, sizeof raw);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);
  const char *refusal = "sendrawtransaction RPC error -26: min relay fee not met";

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
  mfx_open(&x, 2);
  const gz_multi_report *rep = gz_multi_last_report(&x.multi);

  /* only targets every server lists; the higher rate for each */
  fake_set(&x.fake[0], false, B0 "/fee-estimates", 200, "{\"1\":5.5,\"6\":2,\"144\":1}");
  fake_set(&x.fake[1], false, B1 "/fee-estimates", 200, "{\"1\":4,\"6\":3.25,\"1008\":1}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_OK);
  CHECK(f.count == 2);
  CHECK(f.entries[0].target == 1 && f.entries[0].sat_per_kvb == 5500);
  CHECK(f.entries[1].target == 6 && f.entries[1].sat_per_kvb == 3250);

  /* an absurd rate discards that server's whole answer */
  fake_set(&x.fake[1], false, B1 "/fee-estimates", 200, "{\"1\":4,\"6\":50000}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_NO_QUORUM);
  CHECK(f.count == 0);
  CHECK(rep->answers[0].result == GZ_CHAIN_OK && rep->answers[1].result == GZ_CHAIN_MALFORMED);
  mfx_close(&x);

  /* with a third server the two sane answers are enough */
  mfx_open(&x, 3);
  fake_set(&x.fake[0], false, B0 "/fee-estimates", 200, "{\"1\":5.5}");
  fake_set(&x.fake[1], false, B1 "/fee-estimates", 200, "{\"1\":50000}");
  fake_set(&x.fake[2], false, B2 "/fee-estimates", 200, "{\"1\":6}");
  CHECK_RESULT(gz_chain_fee_estimates(&x.multi, &f), GZ_CHAIN_OK);
  CHECK(f.count == 1 && f.entries[0].sat_per_kvb == 6000);
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
  gz_multi_config_default(&mc);
  CHECK(mc.quorum == 2 && mc.tip_slack == 1);
  CHECK_RESULT(gz_multi_create(&mc, x.server, 0, &m), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_multi_create(&mc, x.server, GZ_MULTI_MAX_SERVERS + 1, &m), GZ_CHAIN_INVALID_ARG);
  CHECK_RESULT(gz_multi_create(&mc, NULL, 2, &m), GZ_CHAIN_INVALID_ARG);
  mc.quorum = 1; /* an "agreement" of one server is refused outright */
  CHECK_RESULT(gz_multi_create(&mc, x.server, 2, &m), GZ_CHAIN_INVALID_ARG);
  CHECK(m.ctx == NULL);
  mc.quorum = 2;
  gz_chain empty[2] = {{NULL, NULL}, {NULL, NULL}};
  CHECK_RESULT(gz_multi_create(&mc, empty, 2, &m), GZ_CHAIN_INVALID_ARG);

  /* one server only: allowed so its answer can be shown, never returned */
  CHECK_RESULT(gz_multi_create(&mc, x.server, 1, &m), GZ_CHAIN_OK);
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
  RUN(test_tip_rule);
  RUN(test_disagree_block_hash_and_header);
  RUN(test_disagree_tx_status);
  RUN(test_lying_server_omits_a_spend);
  RUN(test_disagree_script_outputs);
  RUN(test_disagree_raw_tx_and_proof);
  RUN(test_lying_server_invents_a_confirmation);
  RUN(test_one_down_of_two);
  RUN(test_one_down_of_three);
  RUN(test_three_servers_one_wrong);
  RUN(test_broadcast);
  RUN(test_fee_rule);
  RUN(test_create_and_single_server);
  TEST_MAIN_END("test_multi");
}
