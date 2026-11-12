/* The strict JSON tokenizer and its exact number conversions. */
#include "test.h"

#include "../json.h"

static bool parses(const char *s) {
  gz_json_tok toks[64];
  size_t n;
  return gz_json_parse(s, strlen(s), toks, 64, &n);
}

static void test_accepts_valid(test_state *T) {
  CHECK(parses("{}"));
  CHECK(parses("[]"));
  CHECK(parses(" { \"a\" : 1 , \"b\" : [ true , false , null ] } \n"));
  CHECK(parses("\"text\""));
  CHECK(parses("0"));
  CHECK(parses("-12.5e+3"));
  CHECK(parses("{\"a\":{\"b\":{\"c\":[1,2,3]}}}"));
  CHECK(parses("\"esc \\\" \\\\ \\/ \\b \\f \\n \\r \\t \\u00e9\""));
}

static void test_token_layout(test_state *T) {
  const char *s = "{\"a\":[1,{\"x\":true}],\"b\":\"hi\"}";
  gz_json_tok t[32];
  size_t n = 0;
  CHECK(gz_json_parse(s, strlen(s), t, 32, &n));
  CHECK(n == 9);
  CHECK(t[0].type == GZ_JSON_OBJECT && t[0].size == 2 && t[0].next == 9);
  CHECK(gz_json_str_eq(s, &t[1], "a"));
  CHECK(t[2].type == GZ_JSON_ARRAY && t[2].size == 2 && t[2].next == 7);
  CHECK(t[3].type == GZ_JSON_NUMBER);
  CHECK(t[4].type == GZ_JSON_OBJECT && t[4].size == 1 && t[4].next == 7);
  CHECK(gz_json_str_eq(s, &t[7], "b"));
  CHECK(gz_json_str_eq(s, &t[8], "hi"));
  CHECK(!gz_json_str_eq(s, &t[8], "h"));
  CHECK(!gz_json_str_eq(s, &t[3], "1"));
}

static void test_rejects_malformed(test_state *T) {
  static const char *bad[] = {
      "",          " ",           "{",           "}",          "[",          "]",
      "{]",        "[}",          "{\"a\"}",     "{\"a\":}",   "{\"a\":1,}", "[1,]",
      "[,1]",      "{,}",         "{a:1}",       "{'a':1}",    "{\"a\":1 \"b\":2}",
      "[1 2]",     "tru",         "truee",       "nul",        "True",       "01",
      "-",         "1.",          ".5",          "1e",         "1e+",        "+1",
      "0x10",      "\"abc",       "\"a\\x\"",    "\"\\u12g4\"", "\"\\u12\"", "\"tab\there\"",
      "{} {}",     "{}x",         "1 2",         "[1]]",       "NaN",        "Infinity",
      "{\"a\":1}}", "\xef\xbb\xbf{}", "\"caf\xc3\xa9\"", "{\"a\":1,\"a\":2}",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    if (parses(bad[i])) {
      T->failed++;
      fprintf(stderr, "  accepted malformed input #%zu: %s\n", i, bad[i]);
    }
    T->checks++;
  }
  /* a zero byte inside the input */
  gz_json_tok toks[8];
  size_t n;
  CHECK(!gz_json_parse("{\"a\":1}\0", 8, toks, 8, &n));
  CHECK(!gz_json_parse("\"a\0b\"", 5, toks, 8, &n));
}

static void test_duplicate_keys_rejected(test_state *T) {
  CHECK(!parses("{\"confirmed\":false,\"confirmed\":true}"));
  CHECK(!parses("{\"a\":1,\"b\":2,\"c\":{\"x\":1},\"a\":3}"));
  /* the same key in different objects is fine */
  CHECK(parses("{\"a\":{\"a\":1},\"b\":{\"a\":2}}"));
  CHECK(parses("[{\"a\":1},{\"a\":2}]"));
}

static void test_depth_limit(test_state *T) {
  CHECK(parses("[[[[[1]]]]]"));    /* the number is at level 6: allowed */
  CHECK(!parses("[[[[[[1]]]]]]")); /* level 7: refused */
  CHECK(parses("[[[[[[]]]]]]"));   /* six arrays, nothing deeper */
  CHECK(!parses("[[[[[[[]]]]]]]"));
  char deep[5000];
  memset(deep, '[', sizeof deep - 1);
  deep[sizeof deep - 1] = '\0';
  CHECK(!parses(deep)); /* must not recurse 5000 deep */
}

static void test_token_and_member_limits(test_state *T) {
  gz_json_tok toks[4];
  size_t n;
  CHECK(gz_json_parse("[1,2,3]", 7, toks, 4, &n) && n == 4);
  CHECK(!gz_json_parse("[1,2,3,4]", 9, toks, 4, &n));
  /* an object with more members than the limit */
  static char big[8192];
  static gz_json_tok many[600];
  size_t pos = 0;
  big[pos++] = '{';
  for (int i = 0; i <= GZ_JSON_MAX_MEMBERS; i++) {
    pos += (size_t)snprintf(big + pos, sizeof big - pos, "%s\"k%d\":1", i ? "," : "", i);
  }
  big[pos++] = '}';
  CHECK(!gz_json_parse(big, pos, many, 600, &n));
}

static bool u64(const char *s, uint64_t *out) {
  gz_json_tok t[2];
  size_t n;
  if (!gz_json_parse(s, strlen(s), t, 2, &n)) return false;
  return gz_json_u64(s, &t[0], out);
}

static void test_exact_integers(test_state *T) {
  uint64_t v = 0;
  CHECK(u64("0", &v) && v == 0);
  CHECK(u64("43000", &v) && v == 43000);
  CHECK(u64("18446744073709551615", &v) && v == UINT64_MAX);
  CHECK(!u64("18446744073709551616", &v)); /* overflow */
  CHECK(!u64("99999999999999999999999", &v));
  CHECK(!u64("-1", &v));
  CHECK(!u64("1.0", &v));
  CHECK(!u64("1e3", &v));
  CHECK(!u64("\"1\"", &v));
  CHECK(!u64("true", &v));
  CHECK(gz_parse_u64("1008", 4, &v) && v == 1008);
  CHECK(!gz_parse_u64("01", 2, &v));
  CHECK(!gz_parse_u64("", 0, &v));
  CHECK(!gz_parse_u64("1a", 2, &v));
}

static bool dec(const char *s, uint64_t *out) {
  gz_json_tok t[2];
  size_t n;
  if (!gz_json_parse(s, strlen(s), t, 2, &n)) return false;
  return gz_json_decimal_scaled(s, &t[0], 3, out);
}

static void test_exact_decimals(test_state *T) {
  uint64_t v = 0;
  CHECK(dec("1", &v) && v == 1000);
  CHECK(dec("0.5", &v) && v == 500);
  CHECK(dec("14.201", &v) && v == 14201);
  CHECK(dec("10.0", &v) && v == 10000);
  CHECK(dec("0.09999999999999999", &v) && v == 100); /* rounded up */
  CHECK(dec("1.0001", &v) && v == 1001);             /* rounded up */
  CHECK(dec("1.0000", &v) && v == 1000);
  CHECK(dec("0", &v) && v == 0);
  CHECK(!dec("-1", &v));
  CHECK(!dec("1e3", &v));
  CHECK(!dec("1.5e0", &v));
  CHECK(!dec("18446744073709551615", &v)); /* overflows once scaled */
  CHECK(!dec("\"1.0\"", &v));
}

int main(void) {
  test_state state = {0, 0, 0}, *T = &state;
  RUN(test_accepts_valid);
  RUN(test_token_layout);
  RUN(test_rejects_malformed);
  RUN(test_duplicate_keys_rejected);
  RUN(test_depth_limit);
  RUN(test_token_and_member_limits);
  RUN(test_exact_integers);
  RUN(test_exact_decimals);
  TEST_MAIN_END("test_json");
}
