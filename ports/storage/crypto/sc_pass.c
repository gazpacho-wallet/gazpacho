/* The passphrase (spec 4.1, 14): NFC with utf8proc, the refusal rules, and
 * the generated six-word passphrase from the EFF large word list.
 * These functions branch on the passphrase: they run at set-up and change,
 * not on every unlock, and are not constant time. */
#include "sc_internal.h"
#include "sc_pass.h"

#include <sodium.h>
#include <string.h>
#include <utf8proc.h>

#define NFC_OPTS (UTF8PROC_STABLE | UTF8PROC_COMPOSE)
#define FOLD_OPTS (UTF8PROC_STABLE | UTF8PROC_COMPOSE | UTF8PROC_CASEFOLD)

/* in (UTF-8) to normalised UTF-8 in guarded memory. */
static gz_sc_err_t map_guarded(const uint8_t *in, size_t len, utf8proc_option_t opts, uint8_t **out,
                               size_t *out_len, size_t *code_points)
{
    *out = NULL;
    if (len > GZ_SC_PASS_IN_MAX)
        return GZ_SC_ARG;
    utf8proc_ssize_t need = utf8proc_decompose(in, (utf8proc_ssize_t)len, NULL, 0, opts);
    if (need < 0)
        return GZ_SC_ARG; /* invalid UTF-8 */
    /* Room for the code points, and for reencode's UTF-8 in place. */
    size_t cps = (size_t)need + 1;
    utf8proc_int32_t *buf = sodium_malloc(cps * sizeof(utf8proc_int32_t));
    if (!buf)
        return GZ_SC_NOMEM;
    utf8proc_ssize_t n = utf8proc_decompose(in, (utf8proc_ssize_t)len, buf, need, opts);
    if (n < 0 || n > need) {
        sodium_free(buf);
        return GZ_SC_ARG;
    }
    n = utf8proc_normalize_utf32(buf, n, opts);
    if (n < 0) {
        sodium_free(buf);
        return GZ_SC_ARG;
    }
    if (code_points)
        *code_points = (size_t)n;
    utf8proc_ssize_t bytes = utf8proc_reencode(buf, n, opts);
    if (bytes < 0) {
        sodium_free(buf);
        return GZ_SC_ARG;
    }
    uint8_t *o = sodium_malloc((size_t)bytes + 1);
    if (!o) {
        sodium_free(buf);
        return GZ_SC_NOMEM;
    }
    memcpy(o, buf, (size_t)bytes);
    o[bytes] = 0;
    sodium_free(buf);
    *out = o;
    *out_len = (size_t)bytes;
    return GZ_SC_OK;
}

gz_sc_err_t gz_sc_pass_nfc(const uint8_t *in, size_t len, uint8_t **out, size_t *out_len, size_t *code_points)
{
    return map_guarded(in, len, NFC_OPTS, out, out_len, code_points);
}

/* Ignored when comparing with "gazpacho" or the wallet's name: ASCII digits
 * ("with or without digits") and spaces. */
static int ignored_char(uint8_t c)
{
    return (c >= '0' && c <= '9') || c == ' ';
}

/* Equal after dropping ASCII digits and spaces from both (a: folded passphrase). */
static int equal_ignoring_digits(const uint8_t *a, size_t al, const uint8_t *b, size_t bl)
{
    size_t i = 0, j = 0;
    for (;;) {
        while (i < al && ignored_char(a[i]))
            i++;
        while (j < bl && ignored_char(b[j]))
            j++;
        if (i == al || j == bl)
            return i == al && j == bl;
        if (a[i] != b[j])
            return 0;
        i++;
        j++;
    }
}

/* Three or more of the wallet's words in their order, as whole ASCII-letter
 * tokens of the folded passphrase (a subsequence, not necessarily adjacent). */
static int has_words_in_order(const uint8_t *f, size_t fl, const char *const *words, size_t n_words)
{
    size_t best[64] = {0};
    if (n_words > 64)
        n_words = 64;
    size_t i = 0, longest = 0;
    while (i < fl) {
        while (i < fl && !(f[i] >= 'a' && f[i] <= 'z'))
            i++;
        size_t s = i;
        while (i < fl && f[i] >= 'a' && f[i] <= 'z')
            i++;
        size_t tl = i - s;
        if (tl == 0)
            continue;
        /* Positions this token matches, longest chain ending there. Walk
         * positions downwards so one token extends a chain only once. */
        for (size_t j = n_words; j-- > 0;) {
            if (!words[j] || strlen(words[j]) != tl || memcmp(words[j], f + s, tl) != 0)
                continue;
            size_t before = 0;
            for (size_t k = 0; k < j; k++)
                if (best[k] > before)
                    before = best[k];
            if (before + 1 > best[j])
                best[j] = before + 1;
            if (best[j] > longest)
                longest = best[j];
        }
    }
    return longest >= 3;
}

gz_sc_pass_rule_t sc_pass_check_list(const uint8_t *nfc, size_t len, const char *wallet_name,
                                     const char *const *words, size_t n_words, const char *const *blocklist,
                                     size_t n_block)
{
    uint8_t *f = NULL;
    size_t fl = 0, cps = 0;
    gz_sc_pass_rule_t r = GZ_SC_PASS_OK;
    /* The input is already NFC; count its code points with the same pass. */
    uint8_t *again = NULL;
    size_t al = 0;
    if (len > GZ_SC_PASS_MAX_BYTES)
        return GZ_SC_PASS_TOO_LONG;
    if (map_guarded(nfc, len, NFC_OPTS, &again, &al, &cps) != GZ_SC_OK)
        return GZ_SC_PASS_NOT_UTF8;
    gz_sc_sfree(again);
    if (cps < GZ_SC_PASS_MIN_CP)
        return GZ_SC_PASS_TOO_SHORT;
    if (map_guarded(nfc, len, FOLD_OPTS, &f, &fl, NULL) != GZ_SC_OK)
        return GZ_SC_PASS_NOT_UTF8;
    for (size_t i = 0; i < n_block && r == GZ_SC_PASS_OK; i++) {
        uint8_t *b = NULL;
        size_t bl = 0;
        if (map_guarded((const uint8_t *)blocklist[i], strlen(blocklist[i]), FOLD_OPTS, &b, &bl, NULL) == GZ_SC_OK &&
            bl == fl && memcmp(b, f, fl) == 0)
            r = GZ_SC_PASS_COMMON;
        gz_sc_sfree(b);
    }
    if (r == GZ_SC_PASS_OK && equal_ignoring_digits(f, fl, (const uint8_t *)"gazpacho", 8))
        r = GZ_SC_PASS_NAME;
    if (r == GZ_SC_PASS_OK && wallet_name && wallet_name[0]) {
        uint8_t *n = NULL;
        size_t nl = 0;
        if (map_guarded((const uint8_t *)wallet_name, strlen(wallet_name), FOLD_OPTS, &n, &nl, NULL) == GZ_SC_OK &&
            equal_ignoring_digits(f, fl, n, nl))
            r = GZ_SC_PASS_NAME;
        gz_sc_sfree(n);
    }
    if (r == GZ_SC_PASS_OK && words && has_words_in_order(f, fl, words, n_words))
        r = GZ_SC_PASS_WORDS;
    gz_sc_sfree(f);
    return r;
}

/* Bundled blocklist: open point 3 of the spec (which list, which licence) is
 * not decided. The mechanism is in place and tested with a test list. */
static const char *const bundled_blocklist[1] = {""};

gz_sc_pass_rule_t gz_sc_pass_check(const uint8_t *nfc, size_t len, const char *wallet_name,
                                   const char *const *words, size_t n_words)
{
    return sc_pass_check_list(nfc, len, wallet_name, words, n_words, bundled_blocklist, 0);
}

gz_sc_err_t gz_sc_pass_generate(char **out, size_t *out_len)
{
    *out = NULL;
    size_t cap = 6 * (GZ_SC_EFF_WORD_MAX + 1) + 1;
    char *o = sodium_malloc(cap);
    if (!o)
        return GZ_SC_NOMEM;
    size_t p = 0;
    for (int w = 0; w < 6; w++) {
        uint16_t v;
        do {
            uint8_t b[2];
            gz_sc_err_t e = gz_sc_random(b, 2);
            if (e != GZ_SC_OK) {
                sodium_free(o);
                return e;
            }
            v = (uint16_t)((b[0] << 8) | b[1]);
            sodium_memzero(b, 2);
        } while (v >= 62208u); /* 8 x 7776: no modulo bias */
        const char *word = gz_sc_eff_words[v % GZ_SC_EFF_WORDS];
        size_t wl = strlen(word);
        if (w)
            o[p++] = ' ';
        memcpy(o + p, word, wl);
        p += wl;
        v = 0;
    }
    o[p] = 0;
    *out = o;
    *out_len = p;
    return GZ_SC_OK;
}
