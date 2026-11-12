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

/* ---- networks: zero is not a network ---- */

static void test_network_identity(test_state *T) {
  gz_network zeroed;
  uint8_t g[GZ_HASH_LEN], want[GZ_HASH_LEN], hdr[GZ_HEADER_LEN];
  memset(&zeroed, 0, sizeof zeroed);
  CHECK(zeroed == GZ_NET_INVALID); /* a zeroed setting never means mainnet */
  CHECK(!gz_network_valid(zeroed));
  CHECK(!gz_network_valid((gz_network)5));
  CHECK(gz_network_valid(GZ_NET_MAINNET) && gz_network_valid(GZ_NET_SIGNET));
  CHECK(!gz_network_is_test(GZ_NET_MAINNET) && !gz_network_is_test(GZ_NET_INVALID));
  CHECK(gz_network_is_test(GZ_NET_SIGNET) && gz_network_is_test(GZ_NET_TESTNET3) &&
        gz_network_is_test(GZ_NET_TESTNET4));
  CHECK(strcmp(gz_network_name(GZ_NET_INVALID), "invalid") == 0);
  CHECK(strcmp(gz_network_name((gz_network)77), "invalid") == 0);
  CHECK(!gz_network_from_name("invalid", &zeroed));
  CHECK(!gz_network_genesis(GZ_NET_INVALID, g));
  static const struct {
    gz_network n;
    const char *hex;
  } all[] = {{GZ_NET_MAINNET, GENESIS_MAINNET},
             {GZ_NET_TESTNET3, GENESIS_TESTNET3},
             {GZ_NET_TESTNET4, GENESIS_TESTNET4},
             {GZ_NET_SIGNET, GENESIS_SIGNET}};
  for (size_t i = 0; i < 4; i++) {
    test_hash(all[i].hex, want);
    CHECK(gz_network_genesis(all[i].n, g) && memcmp(g, want, GZ_HASH_LEN) == 0);
  }
  /* the mainnet constant is the hash of the recorded mainnet block 0 */
  load_header("mainnet_header_0.txt", hdr);
  gz_header_hash(hdr, g);
  test_hash(GENESIS_MAINNET, want);
  CHECK(memcmp(g, want, GZ_HASH_LEN) == 0);
  /* proof of work for no network at all is refused, not treated as some default */
  CHECK(gz_header_check_pow(hdr, GZ_NET_INVALID) == GZ_POW_BAD_NETWORK);
  CHECK(gz_header_check_pow(hdr, (gz_network)9) == GZ_POW_BAD_NETWORK);
}

static void test_signet_pow_limit(test_state *T) {
  /* a header claiming regtest's target (the easiest there is) is too easy
   * for signet, whatever its hash */
  uint8_t h[GZ_HEADER_LEN];
  load_header("header_329438.txt", h);
  h[72] = 0xff; h[73] = 0xff; h[74] = 0x7f; h[75] = 0x20; /* 0x207fffff */
  CHECK(gz_header_check_pow(h, GZ_NET_SIGNET) == GZ_POW_TOO_EASY);
  h[72] = 0xaf; h[73] = 0x77; h[74] = 0x03; h[75] = 0x1e; /* one above signet's limit */
  CHECK(gz_header_check_pow(h, GZ_NET_SIGNET) == GZ_POW_TOO_EASY);
}

static void test_operator_from_host(test_state *T) {
  char op[GZ_OPERATOR_MAX];
  CHECK(gz_operator_from_host("mempool.space", op) && strcmp(op, "mempool.space") == 0);
  CHECK(gz_operator_from_host("api.mempool.space", op) && strcmp(op, "mempool.space") == 0);
  CHECK(gz_operator_from_host("a.b.c.Blockstream.INFO", op) && strcmp(op, "blockstream.info") == 0);
  /* this machine is one operator under each of its names */
  CHECK(gz_operator_from_host("localhost", op) && strcmp(op, "this-machine") == 0);
  CHECK(gz_operator_from_host("127.0.0.1", op) && strcmp(op, "this-machine") == 0);
  CHECK(gz_operator_from_host("[::1]", op) && strcmp(op, "this-machine") == 0);
  CHECK(gz_operator_from_host("LocalHost.", op) && strcmp(op, "this-machine") == 0);
  CHECK(gz_operator_from_host("203.0.113.3", op) && strcmp(op, "203.0.113.3") == 0); /* not "113.3" */
  /* review A: a trailing dot is the same host, so the same operator */
  CHECK(gz_operator_from_host("mempool.space.", op) && strcmp(op, "mempool.space") == 0);
  CHECK(gz_operator_from_host("blockstream.info.", op) && strcmp(op, "blockstream.info") == 0);
  CHECK(gz_operator_from_host("api.Mempool.Space.", op) && strcmp(op, "mempool.space") == 0);
  CHECK(gz_operator_from_host("203.0.113.3.", op) && strcmp(op, "203.0.113.3") == 0);
  CHECK(gz_operator_from_host("XN--BCHER-KVA.example", op) && strcmp(op, "xn--bcher-kva.example") == 0);
  CHECK(!gz_operator_from_host("mempool.space..", op) && op[0] == '\0');
  CHECK(!gz_operator_from_host("0203.0.113.3", op));
  CHECK(!gz_operator_from_host("", op));
  CHECK(!gz_operator_from_host(NULL, op));
  char longhost[300];
  memset(longhost, 'a', sizeof longhost - 1);
  longhost[sizeof longhost - 1] = '\0';
  CHECK(!gz_operator_from_host(longhost, op));
}

static void test_host_normalise(test_state *T) {
  char out[GZ_HOST_MAX];
  static const struct {
    const char *in, *want;
  } good[] = {
      {"mempool.space", "mempool.space"},       {"mempool.space.", "mempool.space"},
      {"MEMPOOL.Space", "mempool.space"},       {"MEMPOOL.SPACE.", "mempool.space"},
      {"xn--bcher-kva.example", "xn--bcher-kva.example"},
      {"XN--BCHER-KVA.EXAMPLE.", "xn--bcher-kva.example"},
      {"localhost", "localhost"},               {"localhost.", "localhost"},
      {"127.0.0.1", "127.0.0.1"},               {"127.0.0.1.", "127.0.0.1"},
      {"[::1]", "[::1]"},                       {"0.0.0.0", "0.0.0.0"},
      {"203.0.113.255", "203.0.113.255"},   {"a-b.c", "a-b.c"},
      {"1password.example", "1password.example"}, {"x", "x"},
  };
  for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
    T->checks++;
    if (!gz_host_normalise(good[i].in, strlen(good[i].in), out) || strcmp(out, good[i].want) != 0) {
      T->failed++;
      fprintf(stderr, "  %s: wanted %s, got %s\n", good[i].in, good[i].want, out);
    }
  }
  static const char *const bad[] = {
      "", ".", "..", "mempool.space..", ".mempool.space", "mem..pool", "-a.space", "a-.space",
      "a.-b", "user@mempool.space", "mempool.space:443", "mempool.space/api", "mempool%2espace",
      "m\xc3\xa9mpool.space", "mem pool.space", "mem_pool.space", "[::2]", "[0:0:0:0:0:0:0:1]",
      "[::1]x", "127.1", "127.0.1", "0x7f.0.0.1", "0x7f000001", "2130706433", "127.000.0.1",
      "192.0.02.4", "192.0.2.256", "192.0.2.4.5", "a.123", "192.0.2.4..", "localhost..",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    T->checks++;
    if (gz_host_normalise(bad[i], strlen(bad[i]), out) || out[0] != '\0') {
      T->failed++;
      fprintf(stderr, "  accepted host %s as %s\n", bad[i], out);
    }
  }
  /* exactly 63 characters in a label, not 64; the whole name below GZ_HOST_MAX */
  char label[80];
  memset(label, 'a', 64);
  label[64] = '\0';
  CHECK(!gz_host_normalise(label, 64, out));
  CHECK(gz_host_normalise(label, 63, out) && strlen(out) == 63);
  char longname[GZ_HOST_MAX + 2];
  for (size_t i = 0; i < sizeof longname - 1; i++) longname[i] = (i % 2) ? '.' : 'a';
  longname[sizeof longname - 1] = '\0';
  CHECK(!gz_host_normalise(longname, strlen(longname), out));
  CHECK(gz_host_normalise(longname, GZ_HOST_MAX - 1, out)); /* "a.a. ... .a", 127 characters */
  longname[GZ_HOST_MAX - 1] = '.';
  CHECK(gz_host_normalise(longname, GZ_HOST_MAX, out)); /* the same with the root dot */
  CHECK(strlen(out) == GZ_HOST_MAX - 1);
  CHECK(!gz_host_normalise(NULL, 3, out));
  /* the length given is what is read: no terminator needed */
  CHECK(gz_host_normalise("mempool.space/signet", 13, out) && strcmp(out, "mempool.space") == 0);
  CHECK(gz_host_is_loopback("localhost") && gz_host_is_loopback("127.0.0.1") &&
        gz_host_is_loopback("[::1]"));
  CHECK(!gz_host_is_loopback("localhost.") && !gz_host_is_loopback("LOCALHOST") &&
        !gz_host_is_loopback("127.0.0.2") && /* address-check: allow (loopback range) */
        !gz_host_is_loopback(NULL));
}

static void test_operator_names(test_state *T) {
  static const char *const good[] = {"acme", "mempool.space", "my-own-node", "op1", "a.b.c", "0"};
  static const char *const bad[] = {"",     "Acme", "acme.", ".acme", "a..b", "-acme",
                                    "acme-", "a b",  "a_b",   "a@b",  NULL};
  for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) CHECK(gz_operator_name_valid(good[i]));
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) CHECK(!gz_operator_name_valid(bad[i]));
  char longname[GZ_OPERATOR_MAX + 1];
  memset(longname, 'a', sizeof longname - 1);
  longname[sizeof longname - 1] = '\0';
  CHECK(!gz_operator_name_valid(longname));
  longname[GZ_OPERATOR_MAX - 1] = '\0';
  CHECK(gz_operator_name_valid(longname));
}

/* ---- transactions that must be refused ---- */

static size_t put_tx(uint8_t *out, unsigned n_in, unsigned n_out, size_t out_script_len) {
  /* a legacy transaction with empty input scripts and outputs of the given
   * script length (below 253) */
  size_t p = 0;
  out[p++] = 2; out[p++] = 0; out[p++] = 0; out[p++] = 0;
  out[p++] = (uint8_t)n_in;
  for (unsigned i = 0; i < n_in; i++) {
    memset(out + p, 0x11, 36); p += 36;
    out[p++] = 0;
    memset(out + p, 0xff, 4); p += 4;
  }
  out[p++] = (uint8_t)n_out;
  for (unsigned i = 0; i < n_out; i++) {
    memset(out + p, 0, 8); p += 8;
    out[p++] = (uint8_t)out_script_len;
    memset(out + p, 0x51, out_script_len); p += out_script_len;
  }
  memset(out + p, 0, 4); p += 4;
  return p;
}

static void test_tx_shapes_refused(test_state *T) {
  uint8_t tx[512], txid[GZ_HASH_LEN];
  size_t len = put_tx(tx, 1, 1, 6);
  CHECK(len == 4 + 1 + 41 + 1 + 15 + 4);
  CHECK(gz_txid_from_raw(tx, len, txid)); /* the builder makes valid transactions */
  len = put_tx(tx, 0, 1, 6); /* no inputs */
  CHECK(!gz_txid_from_raw(tx, len, txid));
  len = put_tx(tx, 1, 0, 6); /* no outputs */
  CHECK(!gz_txid_from_raw(tx, len, txid));
  len = put_tx(tx, 2, 0, 6);
  CHECK(!gz_txid_from_raw(tx, len, txid));
  len = put_tx(tx, 0, 0, 6);
  CHECK(!gz_txid_from_raw(tx, len, txid));
  CHECK(!gz_tx_is_coinbase(tx, len));

  /* No inputs, written so the zero cannot be mistaken for the segwit marker
   * (00 01): two outputs after it. */
  len = put_tx(tx, 0, 2, 6);
  CHECK(tx[4] == 0x00 && tx[5] == 0x02);
  CHECK(!gz_txid_from_raw(tx, len, txid));
  /* And the segwit form with no inputs: marker, flag, then a zero count. */
  uint8_t sw[64];
  size_t p = 0;
  sw[p++] = 2; sw[p++] = 0; sw[p++] = 0; sw[p++] = 0;
  sw[p++] = 0x00; sw[p++] = 0x01; /* marker and flag */
  sw[p++] = 0x00;                 /* no inputs */
  sw[p++] = 0x01;                 /* one output */
  memset(sw + p, 0, 8); p += 8;
  sw[p++] = 0x06;
  memset(sw + p, 0x51, 6); p += 6;
  memset(sw + p, 0, 4); p += 4; /* no witnesses for no inputs; locktime */
  CHECK(!gz_txid_from_raw(sw, p, txid));

  /* A length of 2^64-1 must not wrap the read position back into the
   * buffer: here it would land exactly on a 4-byte "locktime" at the end. */
  uint8_t wrap[67];
  memset(wrap, 0, sizeof wrap);
  p = 0;
  wrap[p++] = 2; p += 3;            /* version */
  wrap[p++] = 1;                    /* one input */
  memset(wrap + p, 0x11, 36); p += 36;
  wrap[p++] = 0;                    /* empty script */
  memset(wrap + p, 0xff, 4); p += 4;
  wrap[p++] = 1;                    /* one output, at 46 */
  p += 8;                           /* value */
  wrap[p++] = 0xff;                 /* script length: 8 bytes follow */
  memset(wrap + p, 0xff, 8); p += 8; /* 2^64 - 1 */
  CHECK(p == 64);
  CHECK(!gz_txid_from_raw(wrap, sizeof wrap, txid));
}

static void test_64_byte_transaction_refused(test_state *T) {
  /* One input, one output, a 4-byte output script: 4+1+41+1+9+4+4 = 64. */
  uint8_t tx[512], txid[GZ_HASH_LEN], node[GZ_HASH_LEN];
  size_t len = put_tx(tx, 1, 1, 4);
  CHECK(len == 64);
  CHECK(!gz_txid_from_raw(tx, len, txid));
  /* one byte either side is an ordinary transaction */
  len = put_tx(tx, 1, 1, 3);
  CHECK(len == 63 && gz_txid_from_raw(tx, len, txid));
  len = put_tx(tx, 1, 1, 5);
  CHECK(len == 65 && gz_txid_from_raw(tx, len, txid));

  /* Review c13: the rule measures the serialization WITHOUT witness data.
   * The 64-byte body with a witness added (69 bytes in all) is refused... */
  uint8_t sw[80];
  len = put_tx(tx, 1, 1, 4);
  size_t p = 0;
  memcpy(sw, tx, 4); p = 4;
  sw[p++] = 0x00; sw[p++] = 0x01;      /* marker, flag */
  memcpy(sw + p, tx + 4, 56); p += 56; /* inputs and outputs */
  sw[p++] = 0x01;                      /* one witness item */
  sw[p++] = 0x01; sw[p++] = 0x42;      /* of one byte */
  memcpy(sw + p, tx + 60, 4); p += 4;  /* locktime */
  CHECK(p == 69 && !gz_txid_from_raw(sw, p, txid));
  /* ...and a segwit transaction that is 64 bytes only WITH its witness (60
   * without) is an ordinary one */
  len = put_tx(tx, 1, 1, 0);
  CHECK(len == 60);
  memcpy(sw, tx, 4); p = 4;
  sw[p++] = 0x00; sw[p++] = 0x01;
  memcpy(sw + p, tx + 4, 52); p += 52;
  sw[p++] = 0x01; sw[p++] = 0x00;      /* one witness item, empty */
  memcpy(sw + p, tx + 56, 4); p += 4;
  CHECK(p == 64 && gz_txid_from_raw(sw, p, txid));
  uint8_t legacy_id[GZ_HASH_LEN];
  CHECK(gz_txid_from_raw(tx, len, legacy_id) && memcmp(legacy_id, txid, GZ_HASH_LEN) == 0);

  /* Why: the two halves of 64 bytes are a left and a right Merkle node. The
   * real block's first two txids, glued together, hash to an inner node of
   * block 329438, and a proof one step shorter "proves" that node. */
  uint8_t h38[GZ_HEADER_LEN], a[GZ_HASH_LEN], cb[GZ_HASH_LEN], pair[64];
  gz_merkle_proof pa, shorter;
  load_header("header_329438.txt", h38);
  load_proof("tx_a_merkle_proof.json", &pa);
  test_hash(TX_A, a);
  test_hash(TX_COINBASE, cb);
  memcpy(pair, cb, 32);
  memcpy(pair + 32, a, 32);
  gz_sha256d(pair, 64, node);
  memset(&shorter, 0, sizeof shorter);
  shorter.block_height = pa.block_height;
  shorter.pos = 0;
  shorter.depth = pa.depth - 1;
  memcpy(shorter.nodes, pa.nodes + 1, (size_t)shorter.depth * GZ_HASH_LEN);
  CHECK(gz_merkle_verify(node, &shorter, h38)); /* the branch alone cannot tell */
  CHECK(!gz_txid_from_raw(pair, 64, txid));     /* but no 64-byte "transaction" is accepted */
  /* and the depth is wrong for a block of 243 transactions */
  CHECK(shorter.depth != gz_merkle_depth_for_count(243));
  CHECK(pa.depth == gz_merkle_depth_for_count(243));
}

static void test_merkle_depth_for_count(test_state *T) {
  CHECK(gz_merkle_depth_for_count(0) == 0);
  CHECK(gz_merkle_depth_for_count(1) == 0);
  CHECK(gz_merkle_depth_for_count(2) == 1);
  CHECK(gz_merkle_depth_for_count(3) == 2);
  CHECK(gz_merkle_depth_for_count(4) == 2);
  CHECK(gz_merkle_depth_for_count(5) == 3);
  CHECK(gz_merkle_depth_for_count(74) == 7);
  CHECK(gz_merkle_depth_for_count(128) == 7);
  CHECK(gz_merkle_depth_for_count(129) == 8);
  CHECK(gz_merkle_depth_for_count(243) == 8);
  CHECK(gz_merkle_depth_for_count(256) == 8);
  CHECK(gz_merkle_depth_for_count(257) == 9);
  CHECK(gz_merkle_depth_for_count(UINT32_MAX) == 32);
}

static void test_merkle_duplicated_last_position_refused(test_state *T) {
  /* A block of three transactions a, b, c. Bitcoin pairs c with a copy of
   * itself. Position 2 is c; "position 3" is that copy and is no transaction. */
  uint8_t a[GZ_HASH_LEN], b[GZ_HASH_LEN], c[GZ_HASH_LEN], ab[GZ_HASH_LEN], cc[GZ_HASH_LEN];
  uint8_t pair[64], header[GZ_HEADER_LEN], root[GZ_HASH_LEN];
  gz_merkle_proof p;
  memset(a, 0xa1, sizeof a);
  memset(b, 0xb2, sizeof b);
  memset(c, 0xc3, sizeof c);
  memcpy(pair, a, 32); memcpy(pair + 32, b, 32); gz_sha256d(pair, 64, ab);
  memcpy(pair, c, 32); memcpy(pair + 32, c, 32); gz_sha256d(pair, 64, cc);
  memcpy(pair, ab, 32); memcpy(pair + 32, cc, 32); gz_sha256d(pair, 64, root);
  memset(header, 0, sizeof header);
  memcpy(header + 36, root, 32);

  memset(&p, 0, sizeof p);
  p.depth = 2;
  p.pos = 2;
  memcpy(p.nodes[0], c, 32);
  memcpy(p.nodes[1], ab, 32);
  CHECK(gz_merkle_verify(c, &p, header)); /* the real last transaction */
  p.pos = 3;
  CHECK(!gz_merkle_verify(c, &p, header)); /* its copy */
  CHECK(!gz_merkle_root_from_proof(c, &p, root));
  /* an ordinary left-hand position in the same tree still verifies */
  p.pos = 0;
  memcpy(p.nodes[0], b, 32);
  memcpy(p.nodes[1], cc, 32);
  CHECK(gz_merkle_verify(a, &p, header));
  p.pos = 1; /* b, with a on its left: different nodes, so allowed */
  memcpy(p.nodes[0], a, 32);
  CHECK(gz_merkle_verify(b, &p, header));
  /* a real coinbase check on recorded data */
  uint8_t raw[1024];
  size_t len = load_tx("tx_coinbase_hex.txt", raw, sizeof raw);
  CHECK(gz_tx_is_coinbase(raw, len));
  len = load_tx("tx_a_hex.txt", raw, sizeof raw);
  CHECK(!gz_tx_is_coinbase(raw, len));
  len = load_tx("mainnet_legacy_tx_hex.txt", raw, sizeof raw);
  CHECK(!gz_tx_is_coinbase(raw, len));
  CHECK(!gz_tx_is_coinbase(raw, 10));
  CHECK(!gz_tx_is_coinbase(NULL, 100));
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  RUN(test_network_identity);
  RUN(test_signet_pow_limit);
  RUN(test_operator_from_host);
  RUN(test_host_normalise);
  RUN(test_operator_names);
  RUN(test_tx_shapes_refused);
  RUN(test_64_byte_transaction_refused);
  RUN(test_merkle_depth_for_count);
  RUN(test_merkle_duplicated_last_position_refused);
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
