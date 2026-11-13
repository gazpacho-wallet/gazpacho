/* The passphrase (spec 4.1, 14): NFC with utf8proc, the refusal rules, and
 * the generated six-word passphrase from the EFF large word list.
 * NFC and the refusal rules branch on the passphrase (inside utf8proc too):
 * a local timing side channel below 8.3's "same-user attacker while
 * unlocked" line (docs/notes/storage-crypto.md). The generated passphrase is
 * drawn and assembled in constant time (review A, L5). */
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

/* Valid UTF-8 and byte for byte its own NFC form; *cps gets the count. */
static gz_sc_pass_rule_t nfc_form(const uint8_t *pw, size_t len, size_t *cps)
{
    uint8_t *again = NULL;
    size_t al = 0;
    /* Out of memory as well as invalid UTF-8: refused, never accepted unchecked. */
    if (map_guarded(pw, len, NFC_OPTS, &again, &al, cps) != GZ_SC_OK)
        return GZ_SC_PASS_NOT_UTF8;
    int same = al == len && memcmp(again, pw, len) == 0;
    gz_sc_sfree(again);
    return same ? GZ_SC_PASS_OK : GZ_SC_PASS_NOT_NFC;
}

gz_sc_pass_rule_t gz_sc_pass_check_form(const uint8_t *pw, size_t len)
{
    if (len > GZ_SC_PASS_MAX_BYTES)
        return GZ_SC_PASS_TOO_LONG;
    size_t cps = 0;
    gz_sc_pass_rule_t r = nfc_form(pw, len, &cps);
    if (r != GZ_SC_PASS_OK)
        return r;
    /* Review B, L3: Unicode's normalization stability covers assigned code
     * points only; a later version may give an unassigned one a combining
     * class or a decomposition, and with it other NFC bytes and another key.
     * U+0000 ends a C string somewhere along the way. pw is valid UTF-8 here. */
    for (utf8proc_ssize_t at = 0; (size_t)at < len;) {
        utf8proc_int32_t cp;
        utf8proc_ssize_t n = utf8proc_iterate(pw + at, (utf8proc_ssize_t)len - at, &cp);
        if (n <= 0)
            return GZ_SC_PASS_NOT_UTF8;
        if (cp == 0)
            return GZ_SC_PASS_NUL;
        if (utf8proc_category(cp) == UTF8PROC_CATEGORY_CN)
            return GZ_SC_PASS_UNASSIGNED;
        at += n;
    }
    return cps < GZ_SC_PASS_MIN_CP ? GZ_SC_PASS_TOO_SHORT : GZ_SC_PASS_OK;
}

int sc_pass_is_nfc(const uint8_t *pw, size_t len)
{
    if (len > GZ_SC_PASS_IN_MAX)
        return 0;
    size_t cps;
    return nfc_form(pw, len, &cps) == GZ_SC_PASS_OK;
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

/* The bundled list: lowercase ASCII, sorted bytewise; f is the folded passphrase. */
static int in_bundled(const uint8_t *f, size_t fl)
{
    size_t lo = 0, hi = GZ_SC_BLOCK_N;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const uint8_t *w = (const uint8_t *)gz_sc_blocklist[mid];
        size_t wl = strlen((const char *)w), n = wl < fl ? wl : fl;
        int c = memcmp(w, f, n);
        if (c == 0)
            c = wl < fl ? -1 : (wl > fl ? 1 : 0);
        if (c == 0)
            return 1;
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return 0;
}

/* An explicit list (tests): each entry case-folded as the passphrase is. */
static int in_list(const uint8_t *f, size_t fl, const char *const *list, size_t n)
{
    int hit = 0;
    for (size_t i = 0; i < n && !hit; i++) {
        uint8_t *b = NULL;
        size_t bl = 0;
        if (map_guarded((const uint8_t *)list[i], strlen(list[i]), FOLD_OPTS, &b, &bl, NULL) == GZ_SC_OK &&
            bl == fl && memcmp(b, f, fl) == 0)
            hit = 1;
        gz_sc_sfree(b);
    }
    return hit;
}

gz_sc_pass_rule_t sc_pass_check_list(const uint8_t *nfc, size_t len, const char *wallet_name,
                                     const char *const *words, size_t n_words, const char *const *blocklist,
                                     size_t n_block)
{
    gz_sc_pass_rule_t r = gz_sc_pass_check_form(nfc, len);
    if (r != GZ_SC_PASS_OK)
        return r;
    uint8_t *f = NULL;
    size_t fl = 0;
    if (map_guarded(nfc, len, FOLD_OPTS, &f, &fl, NULL) != GZ_SC_OK)
        return GZ_SC_PASS_NOT_UTF8;
    if (blocklist ? in_list(f, fl, blocklist, n_block) : in_bundled(f, fl))
        r = GZ_SC_PASS_COMMON;
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

gz_sc_pass_rule_t gz_sc_pass_check(const uint8_t *nfc, size_t len, const char *wallet_name,
                                   const char *const *words, size_t n_words)
{
    return sc_pass_check_list(nfc, len, wallet_name, words, n_words, NULL, 0);
}

/* ---- the generated passphrase, in constant time ---------------------------- */
/* An optimisation barrier: without it gcc -O2 turns "x |= s & mask" back into
 * a branch on the mask (storage_ctime caught it at sc_pass.c, RelWithDebInfo). */
static inline uint32_t value_barrier(uint32_t x)
{
    __asm__ __volatile__("" : "+r"(x));
    return x;
}
/* All-ones if a == b, else 0; a, b below 2^31. */
static uint32_t ct_eq(uint32_t a, uint32_t b)
{
    uint32_t x = a ^ b;
    return value_barrier((uint32_t)0 - (uint32_t)(1u ^ ((x | (0u - x)) >> 31)));
}
/* All-ones if a >= b, else 0; a, b below 2^31. */
static uint32_t ct_ge(uint32_t a, uint32_t b)
{
    return value_barrier((uint32_t)0 - (uint32_t)(1u ^ ((a - b) >> 31)));
}

#define SLOT (GZ_SC_EFF_WORD_MAX + 1)
#define OUT_MAX (6 * GZ_SC_EFF_WORD_MAX + 5)

gz_sc_err_t gz_sc_pass_generate(char **out, size_t *out_len)
{
    *out = NULL;
    /* slots: six words of up to 9 bytes; lens: their lengths. All secret. */
    uint8_t *slots = sodium_malloc(6 * SLOT);
    char *o = sodium_malloc(OUT_MAX + 1);
    if (!slots || !o) {
        gz_sc_sfree(slots);
        gz_sc_sfree(o);
        return GZ_SC_NOMEM;
    }
    memset(slots, 0, 6 * SLOT);
    uint32_t lens[6] = {0};
    for (int w = 0; w < 6; w++) {
        uint32_t v;
        int reject;
        do {
            uint8_t b[2];
            gz_sc_err_t e = gz_sc_random(b, 2);
            if (e != GZ_SC_OK) {
                sodium_free(slots);
                sodium_free(o);
                return e;
            }
            v = ((uint32_t)b[0] << 8) | b[1];
            sodium_memzero(b, 2);
            reject = v >= 62208u; /* 8 x 7776: no modulo bias */
            SC_DECLASSIFY(&reject, sizeof reject); /* a thrown-away draw says nothing of the kept one */
        } while (reject);
        /* v mod 7776 without a division: at most one of these subtracts. */
        for (uint32_t k = 7; k >= 1; k--)
            v -= ct_ge(v, k * GZ_SC_EFF_WORDS) & (k * GZ_SC_EFF_WORDS);
        /* Read every word, keep the chosen one's bytes and length. */
        uint8_t *slot = slots + w * SLOT;
        uint32_t len = 0;
        for (uint32_t i = 0; i < GZ_SC_EFF_WORDS; i++) {
            uint32_t m = ct_eq(value_barrier(i), v);
            const char *word = gz_sc_eff_words[i];
            uint32_t wl = (uint32_t)strlen(word); /* public: every word is read */
            for (uint32_t j = 0; j < wl; j++)
                slot[j] = (uint8_t)(slot[j] | ((uint8_t)word[j] & m));
            len |= wl & m;
        }
        lens[w] = len;
        v = 0;
    }
    /* Join with single spaces: each output byte reads every slot byte. */
    uint32_t start[6];
    start[0] = 0;
    for (int w = 1; w < 6; w++)
        start[w] = start[w - 1] + lens[w - 1] + 1;
    for (uint32_t q = 0; q < OUT_MAX; q++) {
        uint32_t byte = 0, qb = value_barrier(q);
        for (int w = 0; w < 6; w++) {
            for (uint32_t j = 0; j < GZ_SC_EFF_WORD_MAX; j++) {
                /* Opaque loop counters: otherwise gcc folds start[w] + j into
                 * an induction variable and ends the loop on a secret compare. */
                uint32_t jb = value_barrier(j);
                uint32_t m = ct_eq(qb, start[w] + jb) & ~ct_ge(jb, lens[w]);
                byte |= slots[w * SLOT + j] & m;
            }
            if (w)
                byte |= ' ' & ct_eq(qb, start[w] - 1);
        }
        o[q] = (char)byte;
    }
    o[OUT_MAX] = 0;
    size_t total = start[5] + lens[5];
    sodium_memzero(start, sizeof start);
    sodium_memzero(lens, sizeof lens);
    sodium_free(slots);
    *out = o;
    *out_len = total;
    return GZ_SC_OK;
}
