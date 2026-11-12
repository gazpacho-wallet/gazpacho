/* Segwit addresses per BIP 173 (Bech32) and BIP 350 (Bech32m), and networks.
 *
 * Written here because the imported bech32m.c encodes a plain byte string
 * (as used for offers).  A segwit address is different: the witness version
 * is one 5-bit symbol of its own, placed before the regrouped program, and
 * version 0 uses the older Bech32 checksum.  The imported decoder also
 * accepts mixed case and keeps a lazily filled global table. */
#include "gazpacho/wallet_keys.h"

#include <string.h>

#define BECH32_CONST 1u
#define BECH32M_CONST 0x2bc830a3u
#define BECH32_MAX_LEN 90

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t polymod_step(uint32_t c, unsigned v) {
    unsigned c0 = c >> 25;
    c = ((c & 0x1ffffffu) << 5) ^ v;
    if (c0 & 1) c ^= 0x3b6a57b2u;
    if (c0 & 2) c ^= 0x26508e6du;
    if (c0 & 4) c ^= 0x1ea119fau;
    if (c0 & 8) c ^= 0x3d4233ddu;
    if (c0 & 16) c ^= 0x2a1462b3u;
    return c;
}

/* Polymod over the expanded prefix followed by the 5-bit values. */
static uint32_t polymod_hrp_data(const char *hrp, size_t hrp_len,
                                 const unsigned char *vals, size_t nvals) {
    uint32_t c = 1;
    for (size_t i = 0; i < hrp_len; i++)
        c = polymod_step(c, (unsigned char)hrp[i] >> 5);
    c = polymod_step(c, 0);
    for (size_t i = 0; i < hrp_len; i++)
        c = polymod_step(c, (unsigned char)hrp[i] & 0x1f);
    for (size_t i = 0; i < nvals; i++) c = polymod_step(c, vals[i]);
    return c;
}

static int charset_value(char ch) {
    for (int i = 0; i < 32; i++)
        if (CHARSET[i] == ch) return i;
    return -1;
}

/* Split and check a Bech32/Bech32m string.  On success hrp_out holds the
   lower-case prefix, vals_out the 5-bit data without the checksum, and the
   return value says which checksum matched. */
static gzw_bech32_kind bech32_decode(const char *str, char hrp_out[84],
                                     unsigned char vals_out[BECH32_MAX_LEN],
                                     size_t *nvals_out) {
    unsigned char vals[BECH32_MAX_LEN];
    size_t len, sep, nvals;
    int have_lower = 0, have_upper = 0;
    uint32_t pm;

    if (!str) return GZW_BECH32_NONE;
    len = strnlen(str, BECH32_MAX_LEN + 1);
    if (len < 8 || len > BECH32_MAX_LEN) return GZW_BECH32_NONE;

    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)str[i];
        if (ch < 33 || ch > 126) return GZW_BECH32_NONE;
        if (ch >= 'a' && ch <= 'z') have_lower = 1;
        if (ch >= 'A' && ch <= 'Z') have_upper = 1;
    }
    if (have_lower && have_upper) return GZW_BECH32_NONE;

    /* The separator is the last '1'. */
    sep = len;
    for (size_t i = len; i > 0; i--) {
        if (str[i - 1] == '1') {
            sep = i - 1;
            break;
        }
    }
    if (sep == len || sep == 0 || sep > 83) return GZW_BECH32_NONE;
    nvals = len - sep - 1;
    if (nvals < 6) return GZW_BECH32_NONE;

    for (size_t i = 0; i < sep; i++) {
        char ch = str[i];
        if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
        hrp_out[i] = ch;
    }
    hrp_out[sep] = '\0';

    for (size_t i = 0; i < nvals; i++) {
        char ch = str[sep + 1 + i];
        int v;
        if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
        v = charset_value(ch);
        if (v < 0) return GZW_BECH32_NONE;
        vals[i] = (unsigned char)v;
    }

    pm = polymod_hrp_data(hrp_out, sep, vals, nvals);
    if (pm != BECH32_CONST && pm != BECH32M_CONST) return GZW_BECH32_NONE;

    memcpy(vals_out, vals, nvals - 6);
    *nvals_out = nvals - 6;
    return pm == BECH32M_CONST ? GZW_BECH32_BECH32M : GZW_BECH32_BECH32;
}

gzw_bech32_kind gzw_bech32_check(const char *str) {
    char hrp[84];
    unsigned char vals[BECH32_MAX_LEN];
    size_t nvals = 0;
    return bech32_decode(str, hrp, vals, &nvals);
}

int gzw_segwit_address_encode(const char *hrp, int witness_version,
                              const unsigned char *program, size_t program_len,
                              char out[GZW_ADDRESS_MAX]) {
    unsigned char vals[BECH32_MAX_LEN];
    size_t nvals = 0, hrp_len, pos = 0;
    uint32_t acc = 0, pm, konst;
    int bits = 0;

    if (!out) return 0;
    out[0] = '\0';
    if (!hrp || !program) return 0;
    if (witness_version < 0 || witness_version > 16) return 0;
    if (program_len < 2 || program_len > 40) return 0;
    if (witness_version == 0 && program_len != 20 && program_len != 32) return 0;

    hrp_len = strnlen(hrp, 84);
    if (hrp_len == 0 || hrp_len > 83) return 0;
    for (size_t i = 0; i < hrp_len; i++) {
        unsigned char ch = (unsigned char)hrp[i];
        if (ch < 33 || ch > 126 || (ch >= 'A' && ch <= 'Z')) return 0;
    }

    /* Witness version, then the program regrouped from 8 to 5 bits with
       zero padding. */
    vals[nvals++] = (unsigned char)witness_version;
    for (size_t i = 0; i < program_len; i++) {
        acc = (acc << 8) | program[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            vals[nvals++] = (unsigned char)((acc >> bits) & 0x1f);
        }
    }
    if (bits > 0) vals[nvals++] = (unsigned char)((acc << (5 - bits)) & 0x1f);

    if (hrp_len + 1 + nvals + 6 > BECH32_MAX_LEN) return 0;

    konst = (witness_version == 0) ? BECH32_CONST : BECH32M_CONST;
    pm = polymod_hrp_data(hrp, hrp_len, vals, nvals);
    for (int i = 0; i < 6; i++) pm = polymod_step(pm, 0);
    pm ^= konst;

    memcpy(out, hrp, hrp_len);
    pos = hrp_len;
    out[pos++] = '1';
    for (size_t i = 0; i < nvals; i++) out[pos++] = CHARSET[vals[i]];
    for (int i = 0; i < 6; i++) out[pos++] = CHARSET[(pm >> (5 * (5 - i))) & 0x1f];
    out[pos] = '\0';
    return 1;
}

int gzw_segwit_address_decode(const char *hrp, const char *address,
                              int *witness_version_out,
                              unsigned char program_out[40],
                              size_t *program_len_out) {
    char got_hrp[84];
    unsigned char vals[BECH32_MAX_LEN];
    unsigned char prog[40];
    size_t nvals = 0, plen = 0;
    uint32_t acc = 0;
    int bits = 0;
    int version;
    gzw_bech32_kind kind;

    if (!hrp || !address || !witness_version_out || !program_out ||
        !program_len_out)
        return 0;

    kind = bech32_decode(address, got_hrp, vals, &nvals);
    if (kind == GZW_BECH32_NONE) return 0;
    if (strcmp(got_hrp, hrp) != 0) return 0;
    if (nvals < 1) return 0;

    version = vals[0];
    if (version > 16) return 0;
    /* Version 0 must carry the Bech32 checksum, every other version Bech32m. */
    if (version == 0 && kind != GZW_BECH32_BECH32) return 0;
    if (version != 0 && kind != GZW_BECH32_BECH32M) return 0;

    for (size_t i = 1; i < nvals; i++) {
        acc = (acc << 5) | vals[i];
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (plen >= sizeof(prog)) return 0;
            prog[plen++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    /* At most 4 bits of padding, all zero. */
    if (bits >= 5) return 0;
    if ((acc & ((1u << bits) - 1u)) != 0) return 0;

    if (plen < 2 || plen > 40) return 0;
    if (version == 0 && plen != 20 && plen != 32) return 0;

    *witness_version_out = version;
    memcpy(program_out, prog, plen);
    *program_len_out = plen;
    return 1;
}

/* ---- networks ------------------------------------------------------------- */

int gzw_network_from_name(const char *name, gzw_network *out) {
    static const gzw_network all[] = {GZW_NET_MAINNET, GZW_NET_TESTNET,
                                      GZW_NET_TESTNET4, GZW_NET_SIGNET,
                                      GZW_NET_REGTEST};
    if (!name || !out) return 0;
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        if (strcmp(name, gzw_network_name(all[i])) == 0) {
            *out = all[i];
            return 1;
        }
    }
    return 0;
}

const char *gzw_network_name(gzw_network net) {
    switch (net) {
    case GZW_NET_MAINNET:
        return "mainnet";
    case GZW_NET_TESTNET:
        return "testnet";
    case GZW_NET_TESTNET4:
        return "testnet4";
    case GZW_NET_SIGNET:
        return "signet";
    case GZW_NET_REGTEST:
        return "regtest";
    }
    return NULL;
}

const char *gzw_network_hrp(gzw_network net) {
    switch (net) {
    case GZW_NET_MAINNET:
        return "bc";
    case GZW_NET_TESTNET:
    case GZW_NET_TESTNET4:
    case GZW_NET_SIGNET:
        return "tb";
    case GZW_NET_REGTEST:
        return "bcrt";
    }
    return NULL;
}

int gzw_network_coin_type(gzw_network net, uint32_t *coin_out) {
    if (!coin_out) return 0;
    switch (net) {
    case GZW_NET_MAINNET:
        *coin_out = 0;
        return 1;
    case GZW_NET_TESTNET:
    case GZW_NET_TESTNET4:
    case GZW_NET_SIGNET:
    case GZW_NET_REGTEST:
        *coin_out = 1;
        return 1;
    }
    return 0;
}
