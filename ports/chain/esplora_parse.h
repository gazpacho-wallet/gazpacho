/*
 * Parsers for Esplora response bodies. Internal to ports/chain; exposed in a
 * header so the unit tests and the mutation tests can call them directly.
 * A real fuzzer (libFuzzer or AFL++) should be attached to exactly these
 * functions, plus gz_json_parse and gz_txid_from_raw.
 *
 * Every parser takes the body as bytes with a length (no terminating zero is
 * assumed), accepts only the exact shape documented in
 * docs/notes/chain-port.md, and writes its output only on success.
 */
#ifndef GAZPACHO_CHAIN_ESPLORA_PARSE_H
#define GAZPACHO_CHAIN_ESPLORA_PARSE_H

#include "gazpacho/chain.h"

/* Most outputs one scripthash answer may list, whatever the caller's room. */
#define GZ_ES_MAX_UTXOS 1024
/* Largest confirmation target accepted in a fee answer. */
#define GZ_ES_MAX_FEE_TARGET 1008

typedef struct gz_es_status {
  bool confirmed;
  uint32_t height;
  uint8_t block_hash[GZ_HASH_LEN];
} gz_es_status;

typedef enum gz_es_parse_result {
  GZ_ES_PARSE_OK = 0,
  GZ_ES_PARSE_MALFORMED = 1,
  GZ_ES_PARSE_TOO_MANY = 2,
  GZ_ES_PARSE_NO_MEMORY = 3
} gz_es_parse_result;

/* "330438": digits only, no leading zero, at most GZ_MAX_HEIGHT. */
bool gz_es_parse_height(const char *s, size_t len, uint32_t *out);
/* Exactly 160 lowercase hex characters. */
bool gz_es_parse_header(const char *s, size_t len, uint8_t out[GZ_HEADER_LEN]);
/* {"confirmed":false} or {"confirmed":true,"block_height":N,"block_hash":"..","block_time":N} */
bool gz_es_parse_status(const char *s, size_t len, gz_es_status *out);
/* {"spent":false} or {"spent":true,"txid":"..","vin":N,"status":{..}} */
bool gz_es_parse_outspend(const char *s, size_t len, gz_outspend *out);
/* [{"txid":"..","vout":N,"status":{..},"value":N}, ...]; output sorted by
 * (txid, vout); a repeated outpoint is malformed; more than `cap` entries is
 * GZ_ES_PARSE_TOO_MANY. `cap` above GZ_ES_MAX_UTXOS is treated as that. */
gz_es_parse_result gz_es_parse_utxos(const char *s, size_t len, gz_chain_output *out, size_t cap,
                                     size_t *count);
/* {"block_height":N,"merkle":["..",...],"pos":N} with pos below 2^depth. */
bool gz_es_parse_merkle_proof(const char *s, size_t len, gz_merkle_proof *out);
/* {"1":87.882,"2":87.882,...}: keys are targets 1..GZ_ES_MAX_FEE_TARGET,
 * values non-negative decimals in sat/vB. Output sorted by target. */
bool gz_es_parse_fee_estimates(const char *s, size_t len, gz_fee_estimates *out);

#endif /* GAZPACHO_CHAIN_ESPLORA_PARSE_H */
