/*
 * Fuzz target for everything in ports/chain that reads bytes a chain server
 * chose: the JSON tokenizer, every Esplora answer parser, the transaction
 * parser and the host and hex helpers. The first byte picks the parser, the
 * rest is the answer. The answer is copied into a heap block of exactly its
 * size, with no terminating zero, so that reading one byte too far is seen
 * by AddressSanitizer.
 *
 * Built two ways (docs/notes/ci.md): with the plain driver in fuzz_main.c as
 * the CTest test chain_fuzz_parse, and with libFuzzer when GZ_LIBFUZZER is
 * ON. The starting corpus is fuzz/corpus/chain_parse/ (the recorded signet
 * answers of tests/data/, each behind its parser's byte).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/chain.h"

#include "../esplora_parse.h"
#include "../json.h"

#define PARSERS 16

static void must(int ok) {
  if (!ok) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) return 0;
  unsigned which = data[0] % PARSERS;
  size_t len = size - 1;
  char *s = malloc(len ? len : 1);
  if (s == NULL) return 0;
  if (len) memcpy(s, data + 1, len);

  switch (which) {
    case 0: {
      gz_json_tok toks[64];
      size_t n = 0;
      if (gz_chain_json_parse(s, len, toks, 64, &n)) {
        must(n >= 1 && n <= 64);
        for (size_t i = 0; i < n; i++) {
          must(toks[i].start <= toks[i].end && toks[i].end <= len);
          must(toks[i].next > i && toks[i].next <= n);
        }
      }
      break;
    }
    case 1: {
      uint32_t h = 0;
      if (gz_es_parse_height(s, len, &h)) must(h <= GZ_MAX_HEIGHT);
      break;
    }
    case 2: {
      uint8_t hdr[GZ_HEADER_LEN];
      if (gz_es_parse_header(s, len, hdr)) must(len == 2 * GZ_HEADER_LEN);
      break;
    }
    case 3: {
      gz_es_status st;
      if (gz_es_parse_status(s, len, &st) && st.confirmed) must(st.height <= GZ_MAX_HEIGHT);
      break;
    }
    case 4: {
      gz_outspend o;
      if (gz_es_parse_outspend(s, len, &o) && o.spent && o.confirmed)
        must(o.height <= GZ_MAX_HEIGHT);
      break;
    }
    case 5: {
      gz_chain_output outs[8];
      size_t n = 0;
      if (gz_es_parse_utxos(s, len, outs, 8, &n) == GZ_ES_PARSE_OK) {
        must(n <= 8);
        for (size_t i = 0; i < n; i++) must(outs[i].value <= GZ_MAX_MONEY);
      }
      break;
    }
    case 6: {
      gz_merkle_proof p;
      if (gz_es_parse_merkle_proof(s, len, &p)) {
        uint8_t leaf[GZ_HASH_LEN] = {1}, root[GZ_HASH_LEN];
        must(p.depth <= GZ_MERKLE_MAX_DEPTH);
        (void)gz_merkle_root_from_proof(leaf, &p, root);
      }
      break;
    }
    case 7: {
      gz_fee_estimates f;
      if (gz_es_parse_fee_estimates(s, len, &f)) {
        must(f.count <= GZ_FEE_MAX_TARGETS);
        for (size_t i = 0; i < f.count; i++) must(f.entries[i].sat_per_kvb <= GZ_FEE_MAX_SAT_PER_KVB);
      }
      break;
    }
    case 8: {
      gz_es_block b;
      if (gz_es_parse_block(s, len, &b)) must(b.tx_count >= 1 && b.tx_count <= GZ_MAX_BLOCK_TXS);
      break;
    }
    case 9: {
      /* the refusal text is a C string by the time it is looked at */
      char reason[GZ_REASON_MAX];
      size_t n = len < sizeof reason - 1 ? len : sizeof reason - 1;
      memcpy(reason, s, n);
      reason[n] = '\0';
      (void)gz_es_reason_is_already_known(reason);
      break;
    }
    case 10: {
      uint8_t txid[GZ_HASH_LEN];
      if (gz_txid_from_raw((const uint8_t *)s, len, txid))
        (void)gz_tx_is_coinbase((const uint8_t *)s, len);
      break;
    }
    case 11: {
      uint8_t h[GZ_HASH_LEN];
      char hex[2 * GZ_HASH_LEN + 1];
      if (gz_hash_from_hex(s, len, h)) {
        gz_hash_to_hex(h, hex);
        must(len == 2 * GZ_HASH_LEN && memcmp(hex, s, len) == 0);
      }
      break;
    }
    case 12: {
      uint8_t out[64];
      size_t n = 0;
      if (gz_hex_decode(s, len, out, sizeof out, &n)) must(n <= sizeof out && n * 2 == len);
      break;
    }
    case 13: {
      char host[GZ_HOST_MAX], again[GZ_HOST_MAX], op[GZ_OPERATOR_MAX];
      if (gz_host_normalise(s, len, host)) {
        /* the canonical form is a fixed point */
        must(gz_host_normalise(host, strlen(host), again) && strcmp(host, again) == 0);
        (void)gz_host_is_loopback(host);
        (void)gz_operator_from_host(host, op);
      }
      break;
    }
    case 14: {
      /* the first 80 bytes as a header, on every network */
      if (len >= GZ_HEADER_LEN) {
        gz_block_header h;
        uint8_t id[GZ_HASH_LEN];
        gz_header_parse((const uint8_t *)s, &h);
        gz_header_hash((const uint8_t *)s, id);
        for (int net = 0; net <= 5; net++) (void)gz_header_check_pow((const uint8_t *)s, (gz_network)net);
      }
      break;
    }
    default: {
      uint64_t v = 0;
      if (gz_parse_u64(s, len, &v)) must(len >= 1 && len <= 20);
      break;
    }
  }
  free(s);
  return 0;
}
