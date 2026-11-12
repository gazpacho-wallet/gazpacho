/* Strict JSON tokenizer. See json.h for the rules. */
#include "json.h"

#include <string.h>

typedef struct parser {
  const char *s;
  size_t len;
  size_t pos;
  gz_json_tok *toks;
  size_t cap;
  size_t n;
} parser;

static bool parse_value(parser *p, unsigned depth);

static void skip_ws(parser *p) {
  while (p->pos < p->len) {
    char c = p->s[p->pos];
    if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
    p->pos++;
  }
}

/* Reserves a token and returns its index, or (size_t)-1 if the array is full. */
static size_t new_tok(parser *p, gz_json_type type) {
  if (p->n >= p->cap) return (size_t)-1;
  gz_json_tok *t = &p->toks[p->n];
  t->type = (uint8_t)type;
  t->start = (uint32_t)p->pos;
  t->end = (uint32_t)p->pos;
  t->size = 0;
  t->next = 0;
  return p->n++;
}

static bool is_hex_digit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

static bool parse_string(parser *p) {
  if (p->pos >= p->len || p->s[p->pos] != '"') return false;
  p->pos++;
  size_t idx = new_tok(p, GZ_JSON_STRING);
  if (idx == (size_t)-1) return false;
  for (;;) {
    if (p->pos >= p->len) return false;
    unsigned char c = (unsigned char)p->s[p->pos];
    if (c == '"') break;
    if (c < 0x20 || c > 0x7e) return false;
    if (c == '\\') {
      p->pos++;
      if (p->pos >= p->len) return false;
      char e = p->s[p->pos];
      if (e == 'u') {
        if (p->len - p->pos < 5) return false;
        for (int i = 1; i <= 4; i++) {
          if (!is_hex_digit(p->s[p->pos + (size_t)i])) return false;
        }
        p->pos += 4;
      } else if (e != '"' && e != '\\' && e != '/' && e != 'b' && e != 'f' && e != 'n' &&
                 e != 'r' && e != 't') {
        return false;
      }
    }
    p->pos++;
  }
  p->toks[idx].end = (uint32_t)p->pos;
  p->pos++; /* closing quote */
  p->toks[idx].next = (uint32_t)p->n;
  return true;
}

static bool parse_number(parser *p) {
  size_t idx = new_tok(p, GZ_JSON_NUMBER);
  if (idx == (size_t)-1) return false;
  if (p->pos < p->len && p->s[p->pos] == '-') p->pos++;
  if (p->pos >= p->len || !is_digit(p->s[p->pos])) return false;
  if (p->s[p->pos] == '0') {
    p->pos++;
  } else {
    while (p->pos < p->len && is_digit(p->s[p->pos])) p->pos++;
  }
  if (p->pos < p->len && p->s[p->pos] == '.') {
    p->pos++;
    if (p->pos >= p->len || !is_digit(p->s[p->pos])) return false;
    while (p->pos < p->len && is_digit(p->s[p->pos])) p->pos++;
  }
  if (p->pos < p->len && (p->s[p->pos] == 'e' || p->s[p->pos] == 'E')) {
    p->pos++;
    if (p->pos < p->len && (p->s[p->pos] == '+' || p->s[p->pos] == '-')) p->pos++;
    if (p->pos >= p->len || !is_digit(p->s[p->pos])) return false;
    while (p->pos < p->len && is_digit(p->s[p->pos])) p->pos++;
  }
  p->toks[idx].end = (uint32_t)p->pos;
  p->toks[idx].next = (uint32_t)p->n;
  return true;
}

static bool parse_literal(parser *p, const char *lit, gz_json_type type) {
  size_t n = strlen(lit);
  if (p->len - p->pos < n || memcmp(p->s + p->pos, lit, n) != 0) return false;
  size_t idx = new_tok(p, type);
  if (idx == (size_t)-1) return false;
  p->pos += n;
  p->toks[idx].end = (uint32_t)p->pos;
  p->toks[idx].next = (uint32_t)p->n;
  return true;
}

static bool same_bytes(const parser *p, const gz_json_tok *a, const gz_json_tok *b) {
  size_t la = a->end - a->start, lb = b->end - b->start;
  return la == lb && memcmp(p->s + a->start, p->s + b->start, la) == 0;
}

static bool parse_object(parser *p, unsigned depth) {
  size_t idx = new_tok(p, GZ_JSON_OBJECT);
  if (idx == (size_t)-1) return false;
  p->pos++; /* '{' */
  skip_ws(p);
  if (p->pos < p->len && p->s[p->pos] == '}') {
    p->pos++;
  } else {
    for (;;) {
      skip_ws(p);
      size_t key = p->n;
      if (!parse_string(p)) return false;
      /* refuse a key already used in this object */
      for (size_t i = idx + 1; i < key; i = p->toks[i + 1].next) {
        if (same_bytes(p, &p->toks[i], &p->toks[key])) return false;
      }
      skip_ws(p);
      if (p->pos >= p->len || p->s[p->pos] != ':') return false;
      p->pos++;
      skip_ws(p);
      if (!parse_value(p, depth + 1)) return false;
      if (++p->toks[idx].size > GZ_JSON_MAX_MEMBERS) return false;
      skip_ws(p);
      if (p->pos >= p->len) return false;
      if (p->s[p->pos] == ',') {
        p->pos++;
        continue;
      }
      if (p->s[p->pos] == '}') {
        p->pos++;
        break;
      }
      return false;
    }
  }
  p->toks[idx].end = (uint32_t)p->pos;
  p->toks[idx].next = (uint32_t)p->n;
  return true;
}

static bool parse_array(parser *p, unsigned depth) {
  size_t idx = new_tok(p, GZ_JSON_ARRAY);
  if (idx == (size_t)-1) return false;
  p->pos++; /* '[' */
  skip_ws(p);
  if (p->pos < p->len && p->s[p->pos] == ']') {
    p->pos++;
  } else {
    for (;;) {
      skip_ws(p);
      if (!parse_value(p, depth + 1)) return false;
      p->toks[idx].size++;
      skip_ws(p);
      if (p->pos >= p->len) return false;
      if (p->s[p->pos] == ',') {
        p->pos++;
        continue;
      }
      if (p->s[p->pos] == ']') {
        p->pos++;
        break;
      }
      return false;
    }
  }
  p->toks[idx].end = (uint32_t)p->pos;
  p->toks[idx].next = (uint32_t)p->n;
  return true;
}

static bool parse_value(parser *p, unsigned depth) {
  if (depth > GZ_JSON_MAX_DEPTH) return false;
  if (p->pos >= p->len) return false;
  char c = p->s[p->pos];
  switch (c) {
    case '{': return parse_object(p, depth);
    case '[': return parse_array(p, depth);
    case '"': return parse_string(p);
    case 't': return parse_literal(p, "true", GZ_JSON_TRUE);
    case 'f': return parse_literal(p, "false", GZ_JSON_FALSE);
    case 'n': return parse_literal(p, "null", GZ_JSON_NULL);
    default:
      if (c == '-' || is_digit(c)) return parse_number(p);
      return false;
  }
}

bool gz_json_parse(const char *s, size_t len, gz_json_tok *toks, size_t cap, size_t *count) {
  if (s == NULL || toks == NULL || count == NULL) return false;
  if (len > (size_t)0x7fffffff || cap > (size_t)0x7fffffff) return false;
  parser p = {s, len, 0, toks, cap, 0};
  skip_ws(&p);
  if (!parse_value(&p, 1)) return false;
  skip_ws(&p);
  if (p.pos != p.len) return false;
  *count = p.n;
  return true;
}

bool gz_json_str_eq(const char *s, const gz_json_tok *t, const char *lit) {
  if (t->type != GZ_JSON_STRING) return false;
  size_t n = strlen(lit);
  return (size_t)(t->end - t->start) == n && memcmp(s + t->start, lit, n) == 0;
}

bool gz_parse_u64(const char *s, size_t len, uint64_t *out) {
  if (len == 0 || len > 20) return false;
  if (len > 1 && s[0] == '0') return false;
  uint64_t v = 0;
  for (size_t i = 0; i < len; i++) {
    if (!is_digit(s[i])) return false;
    uint64_t d = (uint64_t)(s[i] - '0');
    if (v > (UINT64_MAX - d) / 10) return false;
    v = v * 10 + d;
  }
  *out = v;
  return true;
}

bool gz_json_u64(const char *s, const gz_json_tok *t, uint64_t *out) {
  if (t->type != GZ_JSON_NUMBER) return false;
  return gz_parse_u64(s + t->start, t->end - t->start, out);
}

bool gz_json_decimal_scaled(const char *s, const gz_json_tok *t, unsigned scale, uint64_t *out) {
  if (t->type != GZ_JSON_NUMBER) return false;
  const char *p = s + t->start;
  size_t len = t->end - t->start;
  size_t i = 0;
  uint64_t v = 0;
  /* the tokenizer already checked the number's form; here anything but
   * digits[.digits] is refused */
  while (i < len && is_digit(p[i])) {
    uint64_t d = (uint64_t)(p[i] - '0');
    if (v > (UINT64_MAX - d) / 10) return false;
    v = v * 10 + d;
    i++;
  }
  if (i == 0) return false;
  bool round_up = false;
  unsigned used = 0;
  if (i < len) {
    if (p[i] != '.') return false;
    i++;
    for (; i < len; i++) {
      if (!is_digit(p[i])) return false;
      if (used < scale) {
        uint64_t d = (uint64_t)(p[i] - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
        used++;
      } else if (p[i] != '0') {
        round_up = true;
      }
    }
  }
  for (; used < scale; used++) {
    if (v > UINT64_MAX / 10) return false;
    v *= 10;
  }
  if (round_up) {
    if (v == UINT64_MAX) return false;
    v++;
  }
  *out = v;
  return true;
}
