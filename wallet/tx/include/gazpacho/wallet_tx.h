#ifndef GAZPACHO_WALLET_TX_H
#define GAZPACHO_WALLET_TX_H

/*
 * gazpacho_wallet_tx: on-chain wallet transactions (first cut, Slice 1).
 *
 *   transactions (serialise, parse, txid, weight)  ->  BIP 341 key-path
 *   signature hash  ->  BIP 86 key-path signing  ->  fees and coin selection
 *   ->  the factory funding, held until it is explicitly released
 *
 * The specification, the tests and the decisions are in docs/notes/wallet-tx.md.
 * Like gazpacho_wallet_keys, this library does no I/O, reads no randomness,
 * allocates nothing and keeps no global state.  Every function returns
 * GZT_OK (0) or a gzt_err.  Outputs are only meaningful on GZT_OK.
 * Mainnet cannot be named: gzt_network has no mainnet value.
 */

#include <stddef.h>
#include <stdint.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include "gazpacho/wallet_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GZT_OK = 0,
    GZT_ERR_ARG = 1,         /* NULL, value out of range, inconsistent arguments */
    GZT_ERR_MAINNET = 2,     /* mainnet was asked for; this version refuses it */
    GZT_ERR_PARSE = 3,       /* the bytes are not a canonical transaction */
    GZT_ERR_LIMIT = 4,       /* well formed so far, but beyond this library's caps */
    GZT_ERR_SCRIPT = 5,      /* destination not accepted (funding: P2TR only) */
    GZT_ERR_DUST = 6,        /* amount below the dust limit of its script */
    GZT_ERR_FEE_CEILING = 7, /* the rate or the real fee rate is above the caller's ceiling */
    GZT_ERR_FUNDS = 8,       /* the coins cannot pay the amount and the fee */
    GZT_ERR_KEY = 9,         /* a key could not be derived, or does not match the script */
    GZT_ERR_SIGN = 10,       /* signing, or verifying the new signature, failed */
    GZT_ERR_STATE = 11,      /* funding: not built yet, or not the txid asked for */
    GZT_ERR_BUFFER = 12,     /* the output buffer is too small */
    GZT_ERR_INTERNAL = 13    /* a self-check failed; report it */
} gzt_err;

/* A fixed description.  Never NULL, never contains key material. */
const char *gzt_err_text(gzt_err e);

/* ---- networks: no mainnet value, and 0 is not a network ------------------- */

/* A struct, not an enum, so that it cannot be mixed up with gzw_network or
   gz_network (both enums, both with mainnet as 0) or with a plain number:
   any such mix-up is a compile error, whatever the warning flags. */
typedef struct { uint8_t id; } gzt_network;

#define GZT_NET_SIGNET ((gzt_network){1})
#define GZT_NET_TESTNET3 ((gzt_network){2})
#define GZT_NET_TESTNET4 ((gzt_network){3})
#define GZT_NET_REGTEST ((gzt_network){4})

static inline int gzt_network_eq(gzt_network a, gzt_network b) { return a.id == b.id; }

/* "signet", "testnet", "testnet4", "regtest".  "mainnet" is GZT_ERR_MAINNET,
   anything else GZT_ERR_ARG. */
gzt_err gzt_network_from_name(const char *name, gzt_network *out);
/* The key library's value for a network; GZT_ERR_ARG for any other id. */
gzt_err gzt_network_to_keys(gzt_network net, gzw_network *out);

/* ---- amounts and fee rates ------------------------------------------------ */

#define GZT_MAX_MONEY UINT64_C(2100000000000000)

/* A fee rate in satoshi per 1000 virtual bytes.  A struct so that it cannot
   be passed where an amount is expected, or the other way round. */
typedef struct { uint64_t sat_per_kvb; } gzt_feerate;

/* The project's rate for test networks: 0.1 sat/vB. */
#define GZT_FEERATE_TEST_DEFAULT_SAT_PER_KVB UINT64_C(100)
/* Largest rate accepted anywhere (100,000 sat/vB); keeps products in range. */
#define GZT_FEERATE_MAX_SAT_PER_KVB UINT64_C(100000000)

/* ceil(vsize * rate / 1000).  Requires rate <= GZT_FEERATE_MAX_SAT_PER_KVB
   and vsize <= 1,000,000; otherwise returns UINT64_MAX. */
uint64_t gzt_fee_for_vsize(gzt_feerate rate, uint64_t vsize);

/* The only way a rate reported by a chain server becomes a gzt_feerate.
   Refuses (GZT_ERR_FEE_CEILING) a rate above the caller's ceiling; refuses
   (GZT_ERR_ARG) a rate of 0 or a ceiling of 0 or above the maximum. */
gzt_err gzt_feerate_from_server(uint64_t server_sat_per_kvb, gzt_feerate ceiling,
                                gzt_feerate *out);

/* 1 if script is a witness program: OP_0 with a 20- or 32-byte push, or
   OP_1..OP_16 with a 2- to 40-byte push.  OP_RETURN and legacy scripts are 0. */
int gzt_is_witness_program(const uint8_t *script, size_t len);

/* Dust limit of an output paying a witness program, as Bitcoin Core computes
   it at 3 sat/vB: (8 + 1 + len + 67) * 3.  0 if not a witness program. */
uint64_t gzt_dust_limit(const uint8_t *script, size_t len);

/* ---- transactions --------------------------------------------------------- */

#define GZT_MAX_INPUTS 64
#define GZT_MAX_OUTPUTS 16
#define GZT_MAX_SCRIPT 128
#define GZT_MAX_WITNESS_ITEMS 4
#define GZT_MAX_WITNESS_ITEM 80

typedef struct {
    uint16_t len;
    uint8_t data[GZT_MAX_WITNESS_ITEM];
} gzt_witness_item;

typedef struct {
    uint8_t prev_txid[32];   /* internal byte order, as in the serialisation */
    uint32_t prev_vout;
    uint16_t script_sig_len;
    uint8_t script_sig[GZT_MAX_SCRIPT];
    uint32_t sequence;
    uint8_t witness_count;
    gzt_witness_item witness[GZT_MAX_WITNESS_ITEMS];
} gzt_txin;

typedef struct {
    uint64_t value;
    uint16_t script_len;
    uint8_t script[GZT_MAX_SCRIPT];
} gzt_txout;

typedef struct {
    uint32_t version;        /* the 4 bytes as an unsigned number */
    uint32_t n_in, n_out;
    gzt_txin in[GZT_MAX_INPUTS];
    gzt_txout out[GZT_MAX_OUTPUTS];
    uint32_t locktime;
} gzt_tx;

/* Largest serialisation of a gzt_tx (bounded by the caps). */
#define GZT_MAX_TX_BYTES 60000

typedef enum {
    GZT_SER_NO_WITNESS = 1,  /* legacy form: what the txid commits to */
    GZT_SER_WITNESS = 2      /* segwit form if any input has a witness, else legacy */
} gzt_ser_form;

/* Serialise.  GZT_ERR_ARG for counts or lengths outside the caps or n_in or
   n_out of 0; GZT_ERR_BUFFER if cap is too small. */
gzt_err gzt_tx_serialize(const gzt_tx *tx, gzt_ser_form form, uint8_t *out, size_t cap,
                         size_t *len_out);

/* Parse hostile bytes; see the rules in docs/notes/wallet-tx.md section 1.2.
   Whatever is accepted serialises (GZT_SER_WITNESS) to exactly the same
   bytes.  *out is zeroed on failure. */
gzt_err gzt_tx_parse(const uint8_t *raw, size_t len, gzt_tx *out);

/* Double SHA-256 of the legacy form (txid) or of the full form (wtxid), in
   internal byte order.  Reverse for display. */
gzt_err gzt_tx_txid(const gzt_tx *tx, uint8_t out[32]);
gzt_err gzt_tx_wtxid(const gzt_tx *tx, uint8_t out[32]);

/* Weight and virtual size (weight / 4 rounded up). */
gzt_err gzt_tx_weight(const gzt_tx *tx, uint64_t *weight_out, uint64_t *vsize_out);

/* The virtual size of a transaction whose n_in inputs are all taproot
   key-path spends with a 64-byte signature and empty scriptSig, paying to
   n_out outputs with the given script lengths.  0 if out of range. */
uint64_t gzt_keypath_vsize(size_t n_in, const size_t *out_script_lens, size_t n_out);

/* ---- BIP 341 signature hash, key path ------------------------------------- */

/* The output an input spends: needed by the signature hash for every input. */
typedef struct {
    uint64_t amount;
    uint16_t script_len;
    uint8_t script[GZT_MAX_SCRIPT];
} gzt_spent_output;

/* Single SHA-256 of all prevouts, amounts, spent scripts, sequences, outputs. */
typedef struct {
    uint8_t prevouts[32], amounts[32], scripts[32], sequences[32], outputs[32];
} gzt_sighash_parts;

gzt_err gzt_sighash_parts_compute(const gzt_tx *tx, const gzt_spent_output *spent,
                                  gzt_sighash_parts *out);

#define GZT_SIGHASH_DEFAULT 0x00
#define GZT_SIGHASH_ALL 0x01
#define GZT_SIGHASH_NONE 0x02
#define GZT_SIGHASH_SINGLE 0x03
#define GZT_SIGHASH_ANYONECANPAY 0x80
#define GZT_SIGMSG_MAX 256

/* BIP 341 SigMsg(hash_type, 0) for input in_index (without the epoch byte),
   no annex.  spent has tx->n_in entries.  GZT_ERR_ARG for an unknown hash
   type, or SINGLE with no output at in_index. */
gzt_err gzt_sigmsg(const gzt_tx *tx, const gzt_spent_output *spent, uint32_t in_index,
                   uint8_t hash_type, uint8_t out[GZT_SIGMSG_MAX], size_t *len_out);

/* hash_TapSighash(0x00 || SigMsg). */
gzt_err gzt_sighash_keypath(const gzt_tx *tx, const gzt_spent_output *spent,
                            uint32_t in_index, uint8_t hash_type, uint8_t out[32]);

/* ---- signing ------------------------------------------------------------- */

/* Sign input in_index with SIGHASH_DEFAULT.  spent[in_index].script must be
   OP_1 <32 bytes> and equal the x-only key of keypair (from
   gzw_bip86_tweaked_keypair), else GZT_ERR_KEY.  The signature is verified
   against that key, then written as the input's only witness item (64
   bytes).  aux32 is fresh randomness from the caller (BIP 340). */
gzt_err gzt_sign_keypath(const secp256k1_context *ctx, gzt_tx *tx,
                         const gzt_spent_output *spent, uint32_t in_index,
                         const secp256k1_keypair *keypair, const uint8_t aux32[32]);

/* ---- coin selection ------------------------------------------------------- */

/* A coin of this wallet: a BIP 86 output at m/86'/coin'/account'/change/index.
   The account and network are given with the request. */
typedef struct {
    uint8_t txid[32];        /* internal byte order */
    uint32_t vout;
    uint64_t amount;
    uint32_t change;         /* 0 receiving, 1 change */
    uint32_t index;
    uint8_t script[34];      /* OP_1 <output key>, checked against the key when signing */
} gzt_coin;

typedef struct {
    gzt_feerate rate;        /* the rate to pay */
    gzt_feerate ceiling;     /* highest real rate the caller accepts; >= rate */
} gzt_fee_policy;

typedef struct {
    uint32_t n_selected;
    uint32_t selected[GZT_MAX_INPUTS]; /* indexes into the caller's coins, in input order */
    uint64_t total_in;
    uint64_t fee;
    uint64_t vsize;
    int has_change;
    uint64_t change;         /* 0 when has_change is 0 */
} gzt_selection;

/* At most this many coins may be offered to gzt_select_coins (GZT_ERR_LIMIT). */
#define GZT_MAX_COINS 4096

/* Choose coins to pay exactly amount to dest, with a P2TR change output if
   the change would be at least its dust limit.  The rules, in order, are in
   docs/notes/wallet-tx.md section 1.7.  The result does not depend on the
   order of coins.  dest must be a witness program of at least 5 bytes (a
   2-byte program would make a one-input transaction below the 65-byte
   relay minimum).  The real fee rate is at most the ceiling, except that
   the fee is rounded up to a whole satoshi (less than 1 sat over).
   GZT_ERR_LIMIT when the coins would pay but only with more than
   GZT_MAX_INPUTS of them. */
gzt_err gzt_select_coins(const gzt_coin *coins, size_t n_coins, const uint8_t *dest,
                         size_t dest_len, uint64_t amount, gzt_fee_policy fee,
                         gzt_selection *out);

/* ---- the factory funding -------------------------------------------------- */

typedef struct {
    gzt_network net;
    uint32_t account;                /* below 2^31 */
    const uint8_t *funding_script;   /* the factory's output: OP_1 <32 bytes>, nothing else */
    size_t funding_script_len;       /* 34 */
    uint64_t amount;
    uint32_t change_index;           /* change goes to m/86'/coin'/account'/1/change_index */
    gzt_fee_policy fee;
    /* Change indexes already used (for example by coins not offered, such as
       unconfirmed ones).  change_index must not be among them, nor equal the
       change index of any offered coin.  May be NULL when n_used is 0. */
    const uint32_t *used_change_indexes;
    size_t n_used_change_indexes;
} gzt_funding_request;

typedef struct {
    uint8_t txid[32];        /* internal byte order; the tree spends txid:vout */
    uint32_t vout;           /* always 0 */
    uint64_t amount;
    uint64_t fee;
    uint64_t vsize;
    int has_change;
    uint64_t change;
    uint32_t change_index;
    gzt_selection selection;
} gzt_funding_info;

/* Holds an unsigned funding until it is released.  It contains no signature:
   copying or reading it gives nothing that can be broadcast.  Read `info`;
   the other members are private. */
typedef struct {
    gzt_funding_info info;
    int priv_state;                                /* 0 empty, 1 built */
    gzt_network priv_net;
    uint32_t priv_account;
    gzt_tx priv_tx;                                /* unsigned */
    gzt_spent_output priv_spent[GZT_MAX_INPUTS];
    uint32_t priv_key_change[GZT_MAX_INPUTS];
    uint32_t priv_key_index[GZT_MAX_INPUTS];
} gzt_funding;

/* Select and build; sign every input, verify, check the signed size, then
   throw the signatures away, so that the funding is known to be signable
   and its size and fee are exact.  master must be a master key (depth 0).
   aux32 is fresh randomness.  On failure *out is wiped. */
gzt_err gzt_funding_build(const secp256k1_context *ctx, const gzw_xprv *master,
                          const gzt_funding_request *req, const gzt_coin *coins,
                          size_t n_coins, const uint8_t aux32[32], gzt_funding *out);

/* Sign and serialise the funding.  Call it after the whole tree is signed.
   Refused (GZT_ERR_STATE) unless f was built, its transaction is within the
   caps, and the txid recomputed from it equals both expect_txid and
   f->info.txid, and its amounts agree with info.  The signatures are made
   here, with aux32 (fresh randomness), and verified; the txid does not
   depend on them.  May be called again (to broadcast again).  On any
   failure out[0..cap) is zeroed. */
gzt_err gzt_funding_release(const secp256k1_context *ctx, const gzw_xprv *master,
                            const gzt_funding *f, const uint8_t expect_txid[32],
                            const uint8_t aux32[32], uint8_t *out, size_t cap,
                            size_t *len_out);

/* Wipe everything. */
void gzt_funding_wipe(gzt_funding *f);

#ifdef __cplusplus
}
#endif

#endif /* GAZPACHO_WALLET_TX_H */
