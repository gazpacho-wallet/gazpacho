/* SPDX-License-Identifier: MIT */
/* Fuzz target (spec/local-api.md 23.5): the strict JSON parser, the RFC 8785
 * canonical form and the writer. Properties: the canonical form of anything
 * accepted parses again and is a fixed point; the writer's output for any
 * text (including invalid UTF-8) always parses. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/api_json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
    gz_json_doc d, d2;
    gz_jw w, w2, t;
    char *text;
    if (n > 65536) return 0;
    if (gz_json_parse(data, n, &d) == 0) {
        uint8_t dig[32];
        gz_jw_init(&w);
        gz_json_jcs(d.root, 0, &w);
        if (w.err) abort();
        if (gz_json_parse((const uint8_t *)w.buf, w.len, &d2) != 0) abort();
        gz_jw_init(&w2);
        gz_json_jcs(d2.root, 0, &w2);
        if (w2.len != w.len || memcmp(w.buf, w2.buf, w.len) != 0) abort();
        if (d.root->type == GZ_JSON_OBJ && gz_json_jcs_digest(d.root, dig) != 0) abort();
        gz_jw_free(&w2);
        gz_json_free(&d2);
        gz_jw_free(&w);
        gz_json_free(&d);
    }
    text = malloc(n + 1);
    if (!text) return 0;
    memcpy(text, data, n);
    text[n] = 0;
    gz_jw_init(&t);
    gz_jw_obj(&t);
    gz_jw_kstr(&t, "s", text);
    gz_jw_text(&t, "x", text, "host", n % 300);
    gz_jw_end_obj(&t);
    if (t.err || gz_json_parse((const uint8_t *)t.buf, t.len, &d2) != 0) abort();
    gz_json_free(&d2);
    gz_jw_free(&t);
    free(text);
    return 0;
}
