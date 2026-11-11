#ifndef GAZPACHO_WALLET_KEYS_H
#define GAZPACHO_WALLET_KEYS_H

/*
 * gazpacho_wallet_keys: key handling for the on-chain wallet.
 *
 *   recovery phrase (BIP 39)  ->  seed  ->  master key and children (BIP 32)
 *   ->  single-key taproot outputs (BIP 86, BIP 341)  ->  addresses (BIP 350)
 *
 * The library does no I/O, reads no randomness and keeps no global state.
 * Entropy and the secp256k1 context are handed in by the caller.  The context
 * must have been made with secp256k1_context_create(SECP256K1_CONTEXT_NONE)
 * (the static context cannot make public keys); the caller should randomise
 * it with secp256k1_context_randomize() where it has randomness.
 *
 * Every function returns 1 on success and 0 on failure unless it says
 * otherwise.  On failure every output holding key material is zeroed.
 * No function writes secret material to a log, a stream or an error string.
 * Callers wipe the secrets they receive with gzw_wipe() when done.
 */

#include <stddef.h>
#include <stdint.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- secrets hygiene ------------------------------------------------------ */

/* Overwrite len bytes at p with zeros in a way the compiler may not remove.
   p may be NULL when len is 0. */
void gzw_wipe(void *p, size_t len);

/* Compare len bytes in time that does not depend on their contents.
   Returns 1 if equal, 0 if not. */
int gzw_ct_equal(const void *a, const void *b, size_t len);

/* ---- networks ------------------------------------------------------------- */

typedef enum {
    GZW_NET_MAINNET = 0,
    GZW_NET_TESTNET = 1,   /* testnet3 */
    GZW_NET_TESTNET4 = 2,
    GZW_NET_SIGNET = 3,
    GZW_NET_REGTEST = 4
} gzw_network;

/* Parse "mainnet", "testnet", "testnet4", "signet" or "regtest". */
int gzw_network_from_name(const char *name, gzw_network *out);

/* The name of a network as accepted by gzw_network_from_name, or NULL for a
   value outside the enum. */
const char *gzw_network_name(gzw_network net);

/* Address prefix (human-readable part): "bc" for mainnet, "tb" for testnet,
   testnet4 and signet, "bcrt" for regtest.  NULL for a value outside the enum. */
const char *gzw_network_hrp(gzw_network net);

/* BIP 44 coin type used in derivation paths: 0 for mainnet, 1 for every test
   network.  Returns 1 and sets *coin_out, or 0 for a value outside the enum. */
int gzw_network_coin_type(gzw_network net, uint32_t *coin_out);

/* ---- recovery phrase (BIP 39, English) ------------------------------------ */

/* Buffer size that holds any phrase with its terminating NUL
   (24 words of at most 8 letters, 23 spaces). */
#define GZW_PHRASE_MAX 216

typedef enum {
    GZW_PHRASE_OK = 0,
    GZW_PHRASE_ERR_WORD_COUNT,   /* not 12, 15, 18, 21 or 24 words */
    GZW_PHRASE_ERR_UNKNOWN_WORD, /* a word is not in the English word list */
    GZW_PHRASE_ERR_CHECKSUM      /* the words are known but the checksum fails */
} gzw_phrase_status;

/* Make the 24-word phrase for 32 bytes of caller-supplied entropy.
   The entropy must come from a cryptographic random source; this library has
   none.  phrase_out receives lower-case words separated by single spaces.
   The result is decoded again and compared with the entropy before returning. */
int gzw_phrase_from_entropy(const unsigned char entropy32[32],
                            char phrase_out[GZW_PHRASE_MAX]);

/* Check a phrase: word count, word list membership and checksum.  Words may be
   separated and surrounded by ASCII whitespace.  NULL is a word-count error. */
gzw_phrase_status gzw_phrase_check(const char *phrase);

/* A fixed description of a gzw_phrase_check result.  Never contains any part
   of a phrase. */
const char *gzw_phrase_status_text(gzw_phrase_status status);

/* Derive the 64-byte BIP 39 seed (PBKDF2-HMAC-SHA512, 2048 rounds) from a
   phrase and an optional passphrase (NULL or "" for none).  An invalid phrase
   is refused.  A passphrase with any non-ASCII byte is refused, because
   BIP 39 requires Unicode normalisation (NFKD) that this library does not do
   and a different normalisation would silently give a different wallet. */
int gzw_phrase_to_seed(const char *phrase, const char *passphrase,
                       unsigned char seed_out64[64]);

/* ---- extended keys (BIP 32) ----------------------------------------------- */

#define GZW_HARDENED 0x80000000u

/* Buffer size for a Base58Check extended key (111 characters) with NUL. */
#define GZW_XKEY_STR_MAX 113

/* An extended private key.  SECRET: wipe with gzw_wipe() after use. */
typedef struct {
    uint8_t depth;              /* 0 for the master key */
    uint8_t parent_fingerprint[4];
    uint32_t child_number;      /* includes GZW_HARDENED when hardened */
    unsigned char chain_code[32];
    unsigned char key[32];      /* private key, big-endian, in 1..n-1 */
} gzw_xprv;

/* An extended public key.  Not secret, but it reveals every address below it. */
typedef struct {
    uint8_t depth;
    uint8_t parent_fingerprint[4];
    uint32_t child_number;
    unsigned char chain_code[32];
    unsigned char pubkey[33];   /* compressed public key */
} gzw_xpub;

/* Master key from a seed of 16 to 64 bytes: HMAC-SHA512("Bitcoin seed", seed).
   Fails if the left half is 0 or not below the group order (BIP 32). */
int gzw_bip32_master(const secp256k1_context *ctx,
                     const unsigned char *seed, size_t seed_len,
                     gzw_xprv *out);

/* Private parent to private child (CKDpriv), hardened when index has
   GZW_HARDENED set.  Fails at depth 255 and in the cases BIP 32 calls invalid
   (left half not below the order, or child key zero).  out may be the same
   object as parent. */
int gzw_bip32_child_priv(const secp256k1_context *ctx, const gzw_xprv *parent,
                         uint32_t index, gzw_xprv *out);

/* Public parent to public child (CKDpub).  Hardened indexes are refused: a
   hardened child cannot be derived from a public key.  out may be the same
   object as parent. */
int gzw_bip32_child_pub(const secp256k1_context *ctx, const gzw_xpub *parent,
                        uint32_t index, gzw_xpub *out);

/* The extended public key of an extended private key (the BIP 32 "N" function). */
int gzw_bip32_neuter(const secp256k1_context *ctx, const gzw_xprv *xprv,
                     gzw_xpub *out);

/* Walk path[0..path_len-1] from start with gzw_bip32_child_priv. */
int gzw_bip32_derive_priv(const secp256k1_context *ctx, const gzw_xprv *start,
                          const uint32_t *path, size_t path_len, gzw_xprv *out);

/* Walk path[0..path_len-1] from start with gzw_bip32_child_pub. */
int gzw_bip32_derive_pub(const secp256k1_context *ctx, const gzw_xpub *start,
                         const uint32_t *path, size_t path_len, gzw_xpub *out);

/* Base58Check text of an extended private key: "xprv..." when mainnet is
   non-zero, "tprv..." otherwise.  The text is SECRET. */
int gzw_xprv_to_string(const gzw_xprv *xprv, int mainnet,
                       char out[GZW_XKEY_STR_MAX]);

/* Base58Check text of an extended public key: "xpub..." or "tpub...". */
int gzw_xpub_to_string(const gzw_xpub *xpub, int mainnet,
                       char out[GZW_XKEY_STR_MAX]);

/* Parse "xprv..."/"tprv...".  Refuses: bad characters or checksum, wrong
   length, unknown or public version bytes, a key byte prefix other than 00,
   a key that is 0 or not below the group order, and depth 0 with a non-zero
   parent fingerprint or child number.  *mainnet_out (may be NULL) is set to 1
   for xprv and 0 for tprv. */
int gzw_xprv_from_string(const secp256k1_context *ctx, const char *str,
                         gzw_xprv *out, int *mainnet_out);

/* Parse "xpub..."/"tpub...".  Refuses the same malformations as
   gzw_xprv_from_string, private version bytes, and a key that is not a valid
   compressed point. */
int gzw_xpub_from_string(const secp256k1_context *ctx, const char *str,
                         gzw_xpub *out, int *mainnet_out);

/* Write a derivation path as text, for example "m/86'/1'/0'/0/0".
   Returns 0 if out is too small.  GZW_PATH_STR_MAX holds any 5-step path. */
#define GZW_PATH_STR_MAX 64
int gzw_path_to_string(const uint32_t *path, size_t path_len,
                       char *out, size_t out_max);

/* ---- addresses (BIP 173 / BIP 350) ---------------------------------------- */

/* Buffer size for any segwit address (at most 90 characters) with NUL. */
#define GZW_ADDRESS_MAX 91

/* Encode a witness program as a segwit address.  Version 0 uses Bech32 and
   needs a 20- or 32-byte program; versions 1 to 16 use Bech32m and need 2 to
   40 bytes.  hrp must be lower-case. */
int gzw_segwit_address_encode(const char *hrp, int witness_version,
                              const unsigned char *program, size_t program_len,
                              char out[GZW_ADDRESS_MAX]);

/* Decode a segwit address and check everything BIP 173 and BIP 350 require:
   length, character set, no mixed case, the prefix equals hrp, the checksum,
   the checksum kind for the witness version, padding, and program length.
   program_out must hold 40 bytes. */
int gzw_segwit_address_decode(const char *hrp, const char *address,
                              int *witness_version_out,
                              unsigned char program_out[40],
                              size_t *program_len_out);

typedef enum {
    GZW_BECH32_NONE = 0,   /* not a valid string of either kind */
    GZW_BECH32_BECH32 = 1, /* BIP 173 checksum */
    GZW_BECH32_BECH32M = 2 /* BIP 350 checksum */
} gzw_bech32_kind;

/* Check a general Bech32/Bech32m string (any prefix, any payload) and say
   which checksum it carries.  Used to run the BIP 350 string vectors. */
gzw_bech32_kind gzw_bech32_check(const char *str);

/* ---- single-key taproot (BIP 341, BIP 86) --------------------------------- */

/* Output key Q = P + H_TapTweak(P)*G for an internal key P with no script
   tree (BIP 341, BIP 86).  Keys are 32-byte x-only.  *parity_out (may be NULL)
   receives 1 if Q has odd Y, else 0. */
int gzw_taproot_output_key(const secp256k1_context *ctx,
                           const unsigned char internal_key32[32],
                           unsigned char output_key_out32[32],
                           int *parity_out);

/* The scriptPubKey OP_1 <32-byte output key>: 0x51 0x20 followed by the key. */
void gzw_p2tr_script_pubkey(const unsigned char output_key32[32],
                            unsigned char spk_out34[34]);

/* The address of a taproot output key on a network.  The address is decoded
   again and compared with the key before returning. */
int gzw_p2tr_address(gzw_network net, const unsigned char output_key32[32],
                     char out[GZW_ADDRESS_MAX]);

/* Decode a taproot address of the given network back to its output key.
   Fails for another network's prefix, a wrong checksum, or anything that is
   not witness version 1 with a 32-byte program. */
int gzw_p2tr_address_decode(gzw_network net, const char *address,
                            unsigned char output_key_out32[32]);

/* The public description of one wallet output.  Nothing in it is secret. */
typedef struct {
    uint32_t path[5];              /* m/86'/coin'/account'/change/index */
    unsigned char internal_key[32];
    unsigned char output_key[32];
    unsigned char script_pubkey[34];
    char address[GZW_ADDRESS_MAX];
} gzw_bip86_output;

/* Fill path with m/86'/coin'/account'/change/index for the network.
   account and index must be below 2^31; change must be 0 (receiving) or 1. */
int gzw_bip86_path(gzw_network net, uint32_t account, uint32_t change,
                   uint32_t index, uint32_t path_out[5]);

/* The account key m/86'/coin'/account' as an extended private key (SECRET). */
int gzw_bip86_account_xprv(const secp256k1_context *ctx, const gzw_xprv *master,
                           gzw_network net, uint32_t account, gzw_xprv *out);

/* The account key m/86'/coin'/account' as an extended public key. */
int gzw_bip86_account_xpub(const secp256k1_context *ctx, const gzw_xprv *master,
                           gzw_network net, uint32_t account, gzw_xpub *out);

/* Describe the output at change/index below an account's extended public key
   (public derivation only).  account is used only to fill in the path. */
int gzw_bip86_output_from_xpub(const secp256k1_context *ctx,
                               const gzw_xpub *account_xpub, gzw_network net,
                               uint32_t account, uint32_t change, uint32_t index,
                               gzw_bip86_output *out);

/* Describe the output at m/86'/coin'/account'/change/index below a master
   key.  The key is derived twice, once by private derivation all the way and
   once by public derivation below the account key; the call fails unless both
   give the same output. */
int gzw_bip86_output_from_master(const secp256k1_context *ctx,
                                 const gzw_xprv *master, gzw_network net,
                                 uint32_t account, uint32_t change,
                                 uint32_t index, gzw_bip86_output *out);

/* The tweaked key pair that signs a key-path spend of the output at
   m/86'/coin'/account'/change/index: private key d (negated first if its
   point has odd Y) plus H_TapTweak(P), per BIP 341.  The pair's x-only public
   key equals output_out->output_key; that is checked before returning.
   keypair_out is SECRET: wipe it with gzw_wipe() after signing.
   output_out may be NULL. */
int gzw_bip86_tweaked_keypair(const secp256k1_context *ctx,
                              const gzw_xprv *master, gzw_network net,
                              uint32_t account, uint32_t change, uint32_t index,
                              secp256k1_keypair *keypair_out,
                              gzw_bip86_output *output_out);

/* The tweaked key pair for a bare 32-byte private key (no derivation).
   output_key_out32 (may be NULL) receives the x-only output key.
   keypair_out is SECRET. */
int gzw_taproot_tweak_seckey(const secp256k1_context *ctx,
                             const unsigned char seckey32[32],
                             secp256k1_keypair *keypair_out,
                             unsigned char output_key_out32[32]);

#ifdef __cplusplus
}
#endif

#endif /* GAZPACHO_WALLET_KEYS_H */
