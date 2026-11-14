/* SPDX-License-Identifier: MIT */
/* The strict JSON parser, the writer, text from other people (5.6) and the
 * request digest under RFC 8785 (7.4), with vector E15 of
 * tools/spec-vectors.py and RFC 8785's own examples. */
#include <stdio.h>
#include <string.h>

#include <openssl/sha.h>

#include "check.h"
#include "gazpacho/api_json.h"

static int parses(const char *s)
{
    gz_json_doc d;
    int r = gz_json_parse((const uint8_t *)s, strlen(s), &d);
    gz_json_free(&d);
    return r == 0;
}

static int parses_n(const char *s, size_t n)
{
    gz_json_doc d;
    int r = gz_json_parse((const uint8_t *)s, n, &d);
    gz_json_free(&d);
    return r == 0;
}

static void canon(const char *in, int strip, char *out, size_t cap)
{
    gz_json_doc d;
    gz_jw w;
    out[0] = 0;
    if (gz_json_parse((const uint8_t *)in, strlen(in), &d) != 0) { snprintf(out, cap, "PARSE FAILED"); return; }
    gz_jw_init(&w);
    gz_json_jcs(d.root, strip, &w);
    snprintf(out, cap, "%s", w.buf ? w.buf : "");
    gz_jw_free(&w);
    gz_json_free(&d);
}

static void digest_hex(const char *in, char out[65])
{
    gz_json_doc d;
    uint8_t h[32];
    int i;
    out[0] = 0;
    if (gz_json_parse((const uint8_t *)in, strlen(in), &d) != 0) return;
    if (gz_json_jcs_digest(d.root, h) == 0)
        for (i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", h[i]);
    gz_json_free(&d);
}

static void test_parser(void)
{
    char deep[200];
    int i;
    CHECK(parses("{}"));
    CHECK(parses(" {\"a\" : [1, -2, true, false, null, \"x\"]} \n"));
    CHECK(parses("{\"n\":9007199254740991}"));
    CHECK(parses("{\"n\":-9007199254740991}"));
    CHECK(!parses("{\"n\":9007199254740992}"));            /* 2^53: 23.2 item 26 */
    CHECK(!parses("{\"n\":-9007199254740992}"));
    CHECK(!parses("{\"n\":1.5}"));
    CHECK(!parses("{\"n\":1e3}"));
    CHECK(!parses("{\"n\":01}"));
    CHECK(!parses("{\"n\":-}"));
    CHECK(!parses("{\"a\":1,\"a\":2}"));                  /* duplicate names */
    CHECK(!parses("{\"a\":1,\"\\u0061\":2}"));            /* the same name, escaped */
    CHECK(!parses("{\"a\":1,}"));
    CHECK(!parses("{\"a\" 1}"));
    CHECK(!parses("{} x"));
    CHECK(!parses("\xef\xbb\xbf{}"));                     /* byte order mark */
    CHECK(!parses("{\"s\":\"\xff\"}"));                   /* invalid UTF-8 */
    CHECK(!parses("{\"s\":\"\xc0\xaf\"}"));               /* overlong */
    CHECK(!parses("{\"s\":\"\xed\xa0\x80\"}"));           /* an encoded surrogate */
    CHECK(!parses("{\"s\":\"\xf4\x90\x80\x80\"}"));       /* above U+10FFFF */
    CHECK(!parses("{\"s\":\"\\ud800\"}"));                /* lone high surrogate */
    CHECK(!parses("{\"s\":\"\\udc00\"}"));                /* lone low surrogate */
    CHECK(!parses("{\"s\":\"\\ud800\\u0041\"}"));
    CHECK(parses("{\"s\":\"\\ud83d\\ude00\"}"));
    CHECK(!parses("{\"s\":\"a\nb\"}"));                   /* raw control character */
    CHECK(!parses("{\"s\":\"\\x\"}"));
    CHECK(!parses("{\"s\":\"abc"));
    CHECK(!parses("{\"s\":\"abc\\"));
    CHECK(!parses("{\"s\":tru}"));
    CHECK(parses("{\"s\":\"\\u0000\"}"));
    CHECK(parses_n("{}", 2));
    CHECK(!parses_n("{}\0", 3));                         /* a NUL after the value */
    CHECK(!parses(""));
    /* depth: 16 levels pass, 17 are refused (7.1) */
    deep[0] = 0;
    for (i = 0; i < 16; i++) strcat(deep, "[");
    for (i = 0; i < 16; i++) strcat(deep, "]");
    CHECK(parses(deep));
    deep[0] = 0;
    for (i = 0; i < 17; i++) strcat(deep, "[");
    for (i = 0; i < 17; i++) strcat(deep, "]");
    CHECK(!parses(deep));
    {
        gz_json_doc d;
        const char *s = "{\"a\":{\"b\":\"\\u00e9\\n\"},\"c\":[1,2,3]}";
        CHECK(gz_json_parse((const uint8_t *)s, strlen(s), &d) == 0);
        CHECK(gz_json_get(d.root, "c")->len == 3);
        CHECK(strcmp(gz_json_get(gz_json_get(d.root, "a"), "b")->s, "\xc3\xa9\n") == 0);
        CHECK(gz_json_get(d.root, "zz") == NULL);
        gz_json_free(&d);
        CHECK(d.root == NULL && d.blocks == NULL);
    }
}

static void test_jcs(void)
{
    char out[1024], d1[65], d2[65];
    /* RFC 8785 3.2.2, the string and literal parts (numbers are integers here) */
    canon("{\"string\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\", \"literals\": [null, true, false]}",
          0, out, sizeof out);
    CHECK(strcmp(out, "{\"literals\":[null,true,false],\"string\":\"\xe2\x82\xac$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}") == 0);
    /* RFC 8785 3.2.3: sorting by UTF-16 code units */
    canon("{\"\\u20ac\":\"Euro Sign\",\"\\r\":\"Carriage Return\",\"\\ufb33\":\"Hebrew Letter Dalet With Dagesh\","
          "\"1\":\"One\",\"\\ud83d\\ude00\":\"Emoji: Grinning Face\",\"\\u0080\":\"Control\","
          "\"\\u00f6\":\"Latin Small Letter O With Diaeresis\"}",
          0, out, sizeof out);
    CHECK(strcmp(out, "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\xc2\x80\":\"Control\","
                      "\"\xc3\xb6\":\"Latin Small Letter O With Diaeresis\",\"\xe2\x82\xac\":\"Euro Sign\","
                      "\"\xf0\x9f\x98\x80\":\"Emoji: Grinning Face\",\"\xef\xac\xb3\":\"Hebrew Letter Dalet With Dagesh\"}") == 0);
    /* a name outside the BMP sorts before U+FFFF (spec-vectors' own assert) */
    canon("{\"\\uffff\":2,\"\\ud83d\\ude00\":1}", 0, out, sizeof out);
    CHECK(strcmp(out, "{\"\xf0\x9f\x98\x80\":1,\"\xef\xbf\xbf\":2}") == 0);
    /* 23.1 item 18: member order, white space and escaping do not change the digest */
    digest_hex("{\"a\":\"\xc3\xa9\",\"b\":[1,2]}", d1);
    digest_hex("{ \"b\" : [ 1 , 2 ] , \"a\" : \"\\u00e9\" }", d2);
    CHECK(d1[0] && strcmp(d1, d2) == 0);
    /* the top-level passphrase is removed; a nested one is not */
    digest_hex("{\"request_id\":\"x\",\"passphrase\":\"one\"}", d1);
    digest_hex("{\"passphrase\":\"two\",\"request_id\":\"x\"}", d2);
    CHECK(strcmp(d1, d2) == 0);
    digest_hex("{\"request_id\":\"x\",\"o\":{\"passphrase\":\"one\"}}", d1);
    digest_hex("{\"request_id\":\"x\",\"o\":{\"passphrase\":\"two\"}}", d2);
    CHECK(strcmp(d1, d2) != 0);
    canon("{\"passphrase\":\"secret\",\"a\":1}", 1, out, sizeof out);
    CHECK(strcmp(out, "{\"a\":1}") == 0 && !strstr(out, "secret"));
}

/* Vector E15 of tools/spec-vectors.py (local-api.md 7.4): canonical bytes and digest. */
#define E15_BODY \
    "{\"request_id\":\"e15_test_request_0001\",\"passphrase\":\"not digested\"," \
    "\"name\":\"Caf\\u00e9 \\u00bd \\ud83d\\ude00 tab\\there\",\"note\":\"unit\\u001fsep \\\"q\\\" \\\\\"," \
    "\"confirm_funding_sat\":250000,\"draft\":{\"z\":[3,2,1],\"a\":{\"b\":true,\"a\":null}}," \
    "\"\\u00e9t\\u00e9\":-7,\"Zed\":0}"
#include "e15_vector.h"

static void test_e15(void)
{
    char out[1024], d[65], d2[65];
    canon(E15_BODY, 1, out, sizeof out);
    CHECK(strcmp(out, E15_CANONICAL) == 0);
    digest_hex(E15_BODY, d);
    CHECK(strcmp(d, E15_DIGEST) == 0);
    /* the same digest for any passphrase value */
    digest_hex("{\"Zed\":0,\"passphrase\":\"another\",\"request_id\":\"e15_test_request_0001\","
               "\"name\":\"Caf\xc3\xa9 \xc2\xbd \xf0\x9f\x98\x80 tab\\there\",\"note\":\"unit\\u001fsep \\\"q\\\" \\\\\","
               "\"confirm_funding_sat\":250000,\"draft\":{\"a\":{\"a\":null,\"b\":true},\"z\":[3,2,1]},"
               "\"\xc3\xa9t\xc3\xa9\":-7}",
               d2);
    CHECK(strcmp(d, d2) == 0);
}

static void test_writer(void)
{
    gz_jw w;
    gz_jw_init(&w);
    gz_jw_obj(&w);
    gz_jw_kstr(&w, "a", "q\"\\\x01\n\xc3\xa9\xff");
    gz_jw_kint(&w, "n", -9007199254740991LL);
    gz_jw_key(&w, "l");
    gz_jw_arr(&w);
    gz_jw_int(&w, 0);
    gz_jw_bool(&w, 1);
    gz_jw_null(&w);
    gz_jw_end_arr(&w);
    gz_jw_end_obj(&w);
    CHECK(!w.err);
    CHECK(strcmp(w.buf, "{\"a\":\"q\\\"\\\\\\u0001\\n\xc3\xa9\xef\xbf\xbd\",\"n\":-9007199254740991,\"l\":[0,true,null]}") == 0);
    gz_jw_free(&w);
    /* misuse is caught, never a malformed answer */
    gz_jw_init(&w);
    gz_jw_obj(&w);
    gz_jw_int(&w, 1);                                   /* a value without a key */
    CHECK(w.err);
    gz_jw_free(&w);
    gz_jw_init(&w);
    gz_jw_arr(&w);
    gz_jw_end_obj(&w);
    CHECK(w.err);
    gz_jw_free(&w);
}

static void test_text(void)
{
    gz_jw w;
    gz_jw_init(&w);
    gz_jw_obj(&w);
    /* bidirectional override, zero-width space, BOM, a control character, newline kept */
    gz_jw_text(&w, "t", "a\xe2\x80\xae" "b\xe2\x80\x8b" "c\xef\xbb\xbf" "d\x07" "e\nf\xc2\x85g", "host", 100);
    gz_jw_text(&w, "u", "\xc3\xa9\xc3\xa9\xc3\xa9", "member", 5);   /* cut on a character boundary */
    gz_jw_text(&w, "v", "<script>x</script>", "sender", 100);
    gz_jw_end_obj(&w);
    CHECK(!w.err);
    CHECK(strcmp(w.buf, "{\"t\":{\"text\":\"abcde\\nfg\",\"by\":\"host\",\"checked\":false},"
                        "\"u\":{\"text\":\"\xc3\xa9\xc3\xa9\",\"by\":\"member\",\"checked\":false},"
                        "\"v\":{\"text\":\"<script>x</script>\",\"by\":\"sender\",\"checked\":false}}") == 0);
    gz_jw_free(&w);
    CHECK(gz_json_is_format_char(0x200b));
    CHECK(gz_json_is_format_char(0x202e));
    CHECK(gz_json_is_format_char(0x2066));
    CHECK(gz_json_is_format_char(0xe0041));
    CHECK(!gz_json_is_format_char('a'));
    CHECK(!gz_json_is_format_char(0x2028));
}

int main(void)
{
    test_parser();
    test_jcs();
    test_e15();
    test_writer();
    test_text();
    return check_done();
}
