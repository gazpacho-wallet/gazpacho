/* Block headers, proof of work, Merkle proofs and txid computation, against
 * real recorded signet, testnet4 and mainnet data. */
#include "test.h"

#include "../esplora_parse.h"

static void load_header(const char *file, uint8_t out[GZ_HEADER_LEN]) {
  size_t len;
  char *hex = test_read_data(file, &len);
  if (!gz_es_parse_header(hex, len, out)) {
    fprintf(stderr, "bad recorded header %s\n", file);
    exit(2);
  }
  free(hex);
}

static void load_proof(const char *file, gz_merkle_proof *out) {
  size_t len;
  char *json = test_read_data(file, &len);
  if (!gz_es_parse_merkle_proof(json, len, out)) {
    fprintf(stderr, "bad recorded proof %s\n", file);
    exit(2);
  }
  free(json);
}

static size_t load_tx(const char *file, uint8_t *out, size_t cap) {
  size_t len, raw_len = 0;
  char *hex = test_read_data(file, &len);
  if (!gz_hex_decode(hex, len, out, cap, &raw_len)) {
    fprintf(stderr, "bad recorded transaction %s\n", file);
    exit(2);
  }
  free(hex);
  return raw_len;
}

static void test_hex_helpers(test_state *T) {
  uint8_t h[GZ_HASH_LEN], buf[4];
  char hex[65];
  size_t n = 99;
  CHECK(gz_hash_from_hex(HASH_329438, 64, h));
  CHECK(h[31] == 0x00 && h[28] == 0x0e && h[0] == 0xf4); /* reversed */
  gz_hash_to_hex(h, hex);
  CHECK(strcmp(hex, HASH_329438) == 0);
  CHECK(!gz_hash_from_hex(HASH_329438, 63, h));
  CHECK(!gz_hash_from_hex(HASH_329438 "00", 66, h));
  CHECK(!gz_hash_from_hex("0000000E272942ba41a93bf06e25f0171c0efc02710e7cd58735243e712a1cf4", 64, h)); /* upper case */
  CHECK(!gz_hash_from_hex("g000000e272942ba41a93bf06e25f0171c0efc02710e7cd58735243e712a1cf4", 64, h));
  CHECK(gz_hex_decode("00ff10", 6, buf, 4, &n) && n == 3 && buf[1] == 0xff);
  CHECK(!gz_hex_decode("00ff1", 5, buf, 4, &n));       /* odd length */
  CHECK(!gz_hex_decode("0011223344", 10, buf, 4, &n)); /* does not fit */
  CHECK(!gz_hex_decode("0x", 2, buf, 4, &n));
  CHECK(gz_hex_decode("", 0, buf, 4, &n) && n == 0);
}

static void test_names(test_state *T) {
  gz_network n;
  CHECK(gz_network_from_name("signet", &n) && n == GZ_NET_SIGNET);
  CHECK(gz_network_from_name("testnet4", &n) && n == GZ_NET_TESTNET4);
  CHECK(gz_network_from_name("testnet", &n) && n == GZ_NET_TESTNET3);
  CHECK(gz_network_from_name("mainnet", &n) && n == GZ_NET_MAINNET);
  CHECK(!gz_network_from_name("regtest", &n));
  CHECK(!gz_network_from_name("", &n));
  CHECK(strcmp(gz_chain_result_name(GZ_CHAIN_DISAGREE), "servers-disagree") == 0);
  CHECK(strcmp(gz_chain_result_name((gz_chain_result)999), "unknown") == 0);
}

static void test_header_parse_and_hash(test_state *T) {
  uint8_t raw[GZ_HEADER_LEN], hash[GZ_HASH_LEN], want[GZ_HASH_LEN];
  gz_block_header h;
  char hex[65];
  load_header("header_329438.txt", raw);
  gz_header_parse(raw, &h);
  CHECK(h.version == 0x20000000);
  CHECK(h.time == 1793823982u);
  CHECK(h.bits == 487902597u); /* 0x1d14cd85, as the server's block JSON says */
  CHECK(h.nonce == 162450084u);
  gz_hash_to_hex(h.prev_hash, hex);
  CHECK(strcmp(hex, HASH_329437) == 0);
  gz_hash_to_hex(h.merkle_root, hex);
  CHECK(strcmp(hex, "ed439195afe5a1b1d1af2c493858c485dd1f30f78e37b694de00f521d9d67a05") == 0);
  gz_header_hash(raw, hash);
  test_hash(HASH_329438, want);
  CHECK(memcmp(hash, want, GZ_HASH_LEN) == 0);
}

static void test_header_links(test_state *T) {
  uint8_t a[GZ_HEADER_LEN], b[GZ_HEADER_LEN], c[GZ_HEADER_LEN];
  load_header("header_329437.txt", a);
  load_header("header_329438.txt", b);
  load_header("header_329439.txt", c);
  CHECK(gz_header_links(a, b));
  CHECK(gz_header_links(b, c));
  CHECK(!gz_header_links(a, c)); /* skips one */
  CHECK(!gz_header_links(b, a)); /* wrong direction */
  a[76] ^= 1;                    /* any change to the predecessor breaks the link */
  CHECK(!gz_header_links(a, b));
}

static void test_bits_to_target(test_state *T) {
  uint8_t t[GZ_HASH_LEN];
  CHECK(gz_bits_to_target(0x1d00ffff, t));
  CHECK(t[0] == 0 && t[3] == 0 && t[4] == 0xff && t[5] == 0xff && t[6] == 0 && t[31] == 0);
  CHECK(gz_bits_to_target(0x1e0377ae, t));
  CHECK(t[2] == 0x03 && t[3] == 0x77 && t[4] == 0xae && t[5] == 0);
  CHECK(gz_bits_to_target(0x03123456, t));
  CHECK(t[28] == 0 && t[29] == 0x12 && t[30] == 0x34 && t[31] == 0x56);
  CHECK(gz_bits_to_target(0x02123456, t));
  CHECK(t[29] == 0 && t[30] == 0x12 && t[31] == 0x34);
  CHECK(gz_bits_to_target(0x04123456, t));
  CHECK(t[28] == 0x12 && t[29] == 0x34 && t[30] == 0x56 && t[31] == 0);
  CHECK(gz_bits_to_target(0x20123456, t));
  CHECK(t[0] == 0x12 && t[1] == 0x34 && t[2] == 0x56);
  CHECK(!gz_bits_to_target(0, t));          /* zero */
  CHECK(!gz_bits_to_target(0x1d000000, t)); /* zero mantissa */
  CHECK(!gz_bits_to_target(0x01003456, t)); /* shifts down to zero */
  CHECK(!gz_bits_to_target(0x1d80ffff, t)); /* sign bit */
  CHECK(!gz_bits_to_target(0x21123456, t)); /* overflows 256 bits */
  CHECK(!gz_bits_to_target(0x23000001, t));
  CHECK(!gz_bits_to_target(0xff7fffff, t));
}

static void test_pow_mainnet(test_state *T) {
  uint8_t genesis[GZ_HEADER_LEN], one[GZ_HEADER_LEN], bad[GZ_HEADER_LEN], hash[GZ_HASH_LEN];
  char hex[65];
  load_header("mainnet_header_0.txt", genesis);
  load_header("mainnet_header_1.txt", one);
  gz_header_hash(genesis, hash);
  gz_hash_to_hex(hash, hex);
  CHECK(strcmp(hex, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f") == 0);
  CHECK(gz_header_check_pow(genesis, GZ_NET_MAINNET) == GZ_POW_OK);
  CHECK(gz_header_check_pow(one, GZ_NET_MAINNET) == GZ_POW_OK);
  CHECK(gz_header_links(genesis, one));

  memcpy(bad, one, GZ_HEADER_LEN);
  bad[76] ^= 0x01; /* a different nonce: the work is gone */
  CHECK(gz_header_check_pow(bad, GZ_NET_MAINNET) == GZ_POW_HASH_ABOVE);
  memcpy(bad, one, GZ_HEADER_LEN);
  bad[36] ^= 0x01; /* a different Merkle root */
  CHECK(gz_header_check_pow(bad, GZ_NET_MAINNET) == GZ_POW_HASH_ABOVE);

  /* a header that claims an easier target than mainnet allows */
  memcpy(bad, one, GZ_HEADER_LEN);
  bad[72] = 0xff; bad[73] = 0xff; bad[74] = 0x7f; bad[75] = 0x20; /* 0x207fffff, regtest's */
  CHECK(gz_header_check_pow(bad, GZ_NET_MAINNET) == GZ_POW_TOO_EASY);
  memcpy(bad, one, GZ_HEADER_LEN);
  memset(bad + 72, 0, 4);
  CHECK(gz_header_check_pow(bad, GZ_NET_MAINNET) == GZ_POW_BAD_BITS);
  bad[74] = 0x80; bad[75] = 0x1d; /* negative */
  CHECK(gz_header_check_pow(bad, GZ_NET_MAINNET) == GZ_POW_BAD_BITS);
}

static void test_pow_testnet4(test_state *T) {
  uint8_t h[GZ_HEADER_LEN], next[GZ_HEADER_LEN];
  load_header("testnet4_header_a.txt", h);
  load_header("testnet4_header_b.txt", next);
  CHECK(gz_header_check_pow(h, GZ_NET_TESTNET4) == GZ_POW_OK);
  CHECK(gz_header_check_pow(next, GZ_NET_TESTNET4) == GZ_POW_OK);
  CHECK(gz_header_links(h, next));
  h[4] ^= 0x01;
  CHECK(gz_header_check_pow(h, GZ_NET_TESTNET4) == GZ_POW_HASH_ABOVE);
}

static void test_pow_signet(test_state *T) {
  uint8_t h[GZ_HEADER_LEN];
  load_header("header_329438.txt", h);
  /* passes on signet, where it proves nothing; the same header is far too
   * easy for a proof-of-work network */
  CHECK(gz_header_check_pow(h, GZ_NET_SIGNET) == GZ_POW_OK);
  CHECK(gz_header_check_pow(h, GZ_NET_MAINNET) == GZ_POW_TOO_EASY);
  CHECK(gz_header_check_pow(h, GZ_NET_TESTNET4) == GZ_POW_TOO_EASY);
  CHECK(gz_header_check_pow(h, GZ_NET_TESTNET3) == GZ_POW_TOO_EASY);
  h[76] ^= 0x01;
  CHECK(gz_header_check_pow(h, GZ_NET_SIGNET) == GZ_POW_HASH_ABOVE);
}

static void test_txid_from_raw(test_state *T) {
  uint8_t raw[1024], txid[GZ_HASH_LEN], want[GZ_HASH_LEN];
  size_t len;

  len = load_tx("tx_a_hex.txt", raw, sizeof raw); /* segwit */
  CHECK(len == 244);
  CHECK(gz_txid_from_raw(raw, len, txid));
  test_hash(TX_A, want);
  CHECK(memcmp(txid, want, GZ_HASH_LEN) == 0);
  /* every shorter prefix and any trailing byte must be refused */
  int accepted = 0;
  for (size_t cut = 0; cut < len; cut++) accepted += gz_txid_from_raw(raw, cut, txid) ? 1 : 0;
  CHECK(accepted == 0);
  raw[len] = 0;
  CHECK(!gz_txid_from_raw(raw, len + 1, txid));
  /* changing a witness byte keeps the txid; changing an output changes it */
  raw[len - 10] ^= 0xff;
  CHECK(gz_txid_from_raw(raw, len, txid) && memcmp(txid, want, GZ_HASH_LEN) == 0);
  raw[60] ^= 0x01;
  CHECK(!gz_txid_from_raw(raw, len, txid) || memcmp(txid, want, GZ_HASH_LEN) != 0);

  len = load_tx("tx_spender_hex.txt", raw, sizeof raw);
  CHECK(gz_txid_from_raw(raw, len, txid));
  test_hash(TX_SPENDER, want);
  CHECK(memcmp(txid, want, GZ_HASH_LEN) == 0);

  len = load_tx("mainnet_legacy_tx_hex.txt", raw, sizeof raw); /* no witness */
  CHECK(gz_txid_from_raw(raw, len, txid));
  test_hash("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", want);
  CHECK(memcmp(txid, want, GZ_HASH_LEN) == 0);
  accepted = 0;
  for (size_t cut = 0; cut < len; cut++) accepted += gz_txid_from_raw(raw, cut, txid) ? 1 : 0;
  CHECK(accepted == 0);

  /* an input count written the long way (not canonical) is refused */
  uint8_t odd[1100];
  memcpy(odd, raw, 4);
  odd[4] = 0xfd; odd[5] = 0x01; odd[6] = 0x00;
  memcpy(odd + 7, raw + 5, len - 5);
  CHECK(raw[4] == 0x01);
  CHECK(!gz_txid_from_raw(odd, len + 2, txid));
  /* lengths that point past the end */
  memcpy(odd, raw, len);
  odd[4] = 0xff;
  CHECK(!gz_txid_from_raw(odd, len, txid));
  memset(odd, 0xff, sizeof odd);
  CHECK(!gz_txid_from_raw(odd, sizeof odd, txid));
  memset(odd, 0, sizeof odd);
  CHECK(!gz_txid_from_raw(odd, sizeof odd, txid));
  CHECK(!gz_txid_from_raw(odd, 0, txid));
  CHECK(!gz_txid_from_raw(NULL, 10, txid));
}

static void test_merkle_real_proofs(test_state *T) {
  uint8_t h38[GZ_HEADER_LEN], h39[GZ_HEADER_LEN], a[GZ_HASH_LEN], b[GZ_HASH_LEN], s[GZ_HASH_LEN];
  gz_merkle_proof pa, pb, ps;
  load_header("header_329438.txt", h38);
  load_header("header_329439.txt", h39);
  load_proof("tx_a_merkle_proof.json", &pa);
  load_proof("tx_b_merkle_proof.json", &pb);
  load_proof("tx_spender_merkle_proof.json", &ps);
  test_hash(TX_A, a);
  test_hash(TX_B, b);
  test_hash(TX_SPENDER, s);
  CHECK(pa.block_height == 329438 && pa.pos == 1 && pa.depth == 8);
  CHECK(gz_merkle_verify(a, &pa, h38));
  CHECK(gz_merkle_verify(b, &pb, h38));
  CHECK(gz_merkle_verify(s, &ps, h39));
}

static void test_merkle_wrong_block(test_state *T) {
  uint8_t h37[GZ_HEADER_LEN], h38[GZ_HEADER_LEN], h39[GZ_HEADER_LEN], a[GZ_HASH_LEN], s[GZ_HASH_LEN];
  gz_merkle_proof pa, ps;
  load_header("header_329437.txt", h37);
  load_header("header_329438.txt", h38);
  load_header("header_329439.txt", h39);
  load_proof("tx_a_merkle_proof.json", &pa);
  load_proof("tx_spender_merkle_proof.json", &ps);
  test_hash(TX_A, a);
  test_hash(TX_SPENDER, s);
  CHECK(!gz_merkle_verify(a, &pa, h39)); /* right proof, next block's header */
  CHECK(!gz_merkle_verify(a, &pa, h37)); /* previous block's header */
  CHECK(!gz_merkle_verify(s, &ps, h38));
}

static void test_merkle_tampered(test_state *T) {
  uint8_t h38[GZ_HEADER_LEN], a[GZ_HASH_LEN], b[GZ_HASH_LEN];
  gz_merkle_proof pa, pb, p;
  load_header("header_329438.txt", h38);
  load_proof("tx_a_merkle_proof.json", &pa);
  load_proof("tx_b_merkle_proof.json", &pb);
  test_hash(TX_A, a);
  test_hash(TX_B, b);

  /* one flipped bit in any node, at any level */
  int accepted = 0;
  for (uint32_t i = 0; i < pa.depth; i++) {
    for (int byte = 0; byte < GZ_HASH_LEN; byte++) {
      p = pa;
      p.nodes[i][byte] ^= 0x01;
      accepted += gz_merkle_verify(a, &p, h38) ? 1 : 0;
    }
  }
  CHECK(accepted == 0);
  /* wrong position */
  p = pa; p.pos = 0;
  CHECK(!gz_merkle_verify(a, &p, h38));
  p = pa; p.pos = 3;
  CHECK(!gz_merkle_verify(a, &p, h38));
  /* a branch cut short or extended */
  p = pa; p.depth = 7;
  CHECK(!gz_merkle_verify(a, &p, h38));
  p = pa; p.depth = 9;
  CHECK(!gz_merkle_verify(a, &p, h38));
  /* two nodes swapped */
  p = pa;
  memcpy(p.nodes[0], pa.nodes[1], GZ_HASH_LEN);
  memcpy(p.nodes[1], pa.nodes[0], GZ_HASH_LEN);
  CHECK(!gz_merkle_verify(a, &p, h38));
  /* another transaction's proof, and another txid with this proof */
  CHECK(!gz_merkle_verify(a, &pb, h38));
  CHECK(!gz_merkle_verify(b, &pa, h38));
  /* a different txid */
  a[0] ^= 0x01;
  CHECK(!gz_merkle_verify(a, &pa, h38));
}

static void test_merkle_shape_limits(test_state *T) {
  uint8_t header[GZ_HEADER_LEN], txid[GZ_HASH_LEN], root[GZ_HASH_LEN];
  gz_merkle_proof p;
  memset(&p, 0, sizeof p);
  memset(header, 0, sizeof header);
  memset(txid, 0x42, sizeof txid);
  /* a block with one transaction: the root is the txid, the branch is empty */
  memcpy(header + 36, txid, GZ_HASH_LEN);
  CHECK(gz_merkle_verify(txid, &p, header));
  p.pos = 1; /* no position 1 in a tree of one */
  CHECK(!gz_merkle_verify(txid, &p, header));
  CHECK(!gz_merkle_root_from_proof(txid, &p, root));
  p.pos = 0;
  p.depth = GZ_MERKLE_MAX_DEPTH + 1;
  CHECK(!gz_merkle_root_from_proof(txid, &p, root));
  p.depth = 3;
  p.pos = 8; /* needs four levels */
  CHECK(!gz_merkle_root_from_proof(txid, &p, root));
  p.pos = 7;
  CHECK(gz_merkle_root_from_proof(txid, &p, root));
  p.depth = GZ_MERKLE_MAX_DEPTH;
  p.pos = UINT32_MAX;
  CHECK(gz_merkle_root_from_proof(txid, &p, root));
  CHECK(!gz_merkle_verify(NULL, &p, header));
  CHECK(!gz_merkle_verify(txid, NULL, header));
  CHECK(!gz_merkle_verify(txid, &p, NULL));
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  RUN(test_hex_helpers);
  RUN(test_names);
  RUN(test_header_parse_and_hash);
  RUN(test_header_links);
  RUN(test_bits_to_target);
  RUN(test_pow_mainnet);
  RUN(test_pow_testnet4);
  RUN(test_pow_signet);
  RUN(test_txid_from_raw);
  RUN(test_merkle_real_proofs);
  RUN(test_merkle_wrong_block);
  RUN(test_merkle_tampered);
  RUN(test_merkle_shape_limits);
  TEST_MAIN_END("test_headers");
}
