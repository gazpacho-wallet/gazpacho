/* Recovery phrases (BIP 39, English).
 *
 * Checking a phrase and stretching it into a seed use the imported
 * SuperScalar code (core/superscalar/src/bip39.c), which is verified against
 * the official vectors in wallet/vectors/.  Making a phrase from entropy is
 * done here instead of with the imported bip39_entropy_to_mnemonic(), because
 * that function copies the entropy to the heap and frees it without wiping.
 * The word list is the imported one. */
#include "gazpacho/wallet_keys.h"

#include <string.h>

#include <openssl/sha.h>

#include "superscalar/bip39.h"
#include "bip39_wordlist.h" /* imported, core/superscalar/src */

int gzw_phrase_from_entropy(const unsigned char entropy32[32],
                            char phrase_out[GZW_PHRASE_MAX]) {
    unsigned char buf[33];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char back[32];
    size_t pos = 0;
    int ok = 0;

    if (!phrase_out) return 0;
    if (!entropy32) {
        phrase_out[0] = '\0';
        return 0;
    }

    /* 256 bits of entropy followed by the first 8 bits of its SHA-256. */
    memcpy(buf, entropy32, 32);
    phrase_out[0] = '\0';
    SHA256(buf, 32, hash);
    buf[32] = hash[0];

    /* 264 bits = 24 groups of 11 bits, most significant bit first. */
    for (size_t w = 0; w < 24; w++) {
        unsigned idx = 0;
        for (size_t b = 0; b < 11; b++) {
            size_t bit = w * 11 + b;
            idx = (idx << 1) | ((buf[bit / 8] >> (7 - bit % 8)) & 1u);
        }
        const char *word = bip39_wordlist_en[idx];
        size_t wlen = strlen(word);
        if (pos + (w > 0) + wlen + 1 > GZW_PHRASE_MAX) goto done;
        if (w > 0) phrase_out[pos++] = ' ';
        memcpy(phrase_out + pos, word, wlen);
        pos += wlen;
    }
    phrase_out[pos] = '\0';

    /* Decode what was written and require the same entropy back. */
    memset(back, 0, sizeof(back));
    if (bip39_mnemonic_to_entropy(phrase_out, back, sizeof(back)) != 32) goto done;
    if (!gzw_ct_equal(back, buf, 32)) goto done;
    ok = 1;

done:
    gzw_wipe(buf, sizeof(buf));
    gzw_wipe(hash, sizeof(hash));
    gzw_wipe(back, sizeof(back));
    if (!ok) gzw_wipe(phrase_out, GZW_PHRASE_MAX);
    return ok;
}

gzw_phrase_status gzw_phrase_check(const char *phrase) {
    if (!phrase) return GZW_PHRASE_ERR_WORD_COUNT;
    switch (bip39_check(phrase)) {
    case BIP39_OK:
        return GZW_PHRASE_OK;
    case BIP39_ERR_WORD_COUNT:
        return GZW_PHRASE_ERR_WORD_COUNT;
    case BIP39_ERR_UNKNOWN_WORD:
        return GZW_PHRASE_ERR_UNKNOWN_WORD;
    case BIP39_ERR_CHECKSUM:
        return GZW_PHRASE_ERR_CHECKSUM;
    }
    return GZW_PHRASE_ERR_CHECKSUM;
}

const char *gzw_phrase_status_text(gzw_phrase_status status) {
    switch (status) {
    case GZW_PHRASE_OK:
        return "valid";
    case GZW_PHRASE_ERR_WORD_COUNT:
        return "a recovery phrase has 12, 15, 18, 21 or 24 words";
    case GZW_PHRASE_ERR_UNKNOWN_WORD:
        return "a word is not in the BIP 39 English word list";
    case GZW_PHRASE_ERR_CHECKSUM:
        return "the checksum does not match (a word is wrong or out of order)";
    }
    return "invalid";
}

int gzw_phrase_to_seed(const char *phrase, const char *passphrase,
                       unsigned char seed_out64[64]) {
    if (!seed_out64) return 0;
    gzw_wipe(seed_out64, 64);
    if (!phrase) return 0;
    if (passphrase) {
        for (const unsigned char *p = (const unsigned char *)passphrase; *p; p++)
            if (*p >= 0x80) return 0;
    }
    if (gzw_phrase_check(phrase) != GZW_PHRASE_OK) return 0;
    if (!bip39_mnemonic_to_seed(phrase, passphrase, seed_out64)) {
        gzw_wipe(seed_out64, 64);
        return 0;
    }
    return 1;
}
