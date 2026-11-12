/*
 * A minimal strict JSON tokenizer for chain server answers. Internal to
 * ports/chain.
 *
 * It allocates nothing: the caller supplies the token array. It is stricter
 * than JSON where that costs nothing for the answers we read:
 *  - the input must be exactly one value, with only JSON whitespace around it;
 *  - a value more than GZ_JSON_MAX_DEPTH levels down is refused (the outermost
 *    value is level 1 and every value counts, numbers and strings included;
 *    the deepest answer we read, the output list, reaches level 4);
 *  - an object with more than GZ_JSON_MAX_MEMBERS members is refused;
 *  - two members of one object with the same key (compared as written) are
 *    refused;
 *  - bytes outside printable ASCII are refused everywhere, including inside
 *    strings (escape sequences are checked for form and left undecoded).
 * Numbers are not converted here; gz_json_u64 and gz_json_decimal_scaled
 * convert exactly, without floating point.
 */
#ifndef GAZPACHO_CHAIN_JSON_H
#define GAZPACHO_CHAIN_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define GZ_JSON_MAX_DEPTH 6
#define GZ_JSON_MAX_MEMBERS 128

typedef enum gz_json_type {
  GZ_JSON_OBJECT = 1,
  GZ_JSON_ARRAY,
  GZ_JSON_STRING,
  GZ_JSON_NUMBER,
  GZ_JSON_TRUE,
  GZ_JSON_FALSE,
  GZ_JSON_NULL
} gz_json_type;

typedef struct gz_json_tok {
  uint8_t type;   /* gz_json_type */
  uint32_t start; /* first byte of the value; for a string, after the quote */
  uint32_t end;   /* one past the last byte; for a string, the closing quote */
  uint32_t size;  /* object: members; array: elements; otherwise 0 */
  uint32_t next;  /* index of the first token after this value's subtree */
} gz_json_tok;

/*
 * Token layout: a value is one token followed by its children. An object's
 * children are key, value, key, value ... (each key a STRING token); an
 * array's are its elements. Step over a value with tok.next.
 *
 * Returns true and sets *count on success. Returns false on any syntax
 * error, any rule above, or more than `cap` tokens.
 */
bool gz_json_parse(const char *s, size_t len, gz_json_tok *toks, size_t cap, size_t *count);

/* True if the token is a string whose bytes equal the zero-terminated `lit`. */
bool gz_json_str_eq(const char *s, const gz_json_tok *t, const char *lit);

/* Converts a NUMBER token made only of digits (no sign, fraction, exponent,
 * or leading zero) to a uint64. False otherwise or on overflow. */
bool gz_json_u64(const char *s, const gz_json_tok *t, uint64_t *out);

/* Same conversion for a run of bytes (used for decimal object keys). */
bool gz_parse_u64(const char *s, size_t len, uint64_t *out);

/* Converts a NUMBER token of the form digits[.digits] (no sign, no exponent)
 * to value * 10^scale, rounded up, exactly. False otherwise or on overflow. */
bool gz_json_decimal_scaled(const char *s, const gz_json_tok *t, unsigned scale, uint64_t *out);

#endif /* GAZPACHO_CHAIN_JSON_H */
