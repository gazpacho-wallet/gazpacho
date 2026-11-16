/* The signing round's messages as spec/messages.md sections 4 and 7 encode
 * them: the envelope, the record (TLV) rules of 4.2, the message hash of 4.3,
 * and one decoder and encoder per round kind (64 to 81), with round_propose
 * decoded into core/tree's gz_tree_proposal_t, which both the host's builder
 * and the member's checks (gz_tree_member_check) take.
 *
 * Pure functions over caller memory: no allocation, no I/O, nothing kept.
 * Every decoder reads hostile bytes and either accepts the whole message under
 * every rule below or refuses it; a refused message leaves nothing usable in
 * the output. Decoded views point into the caller's bytes.
 *
 * The rules (messages.md 4.2): `type` and `length` are BigSize, minimally
 * encoded; types strictly increase; a length past the end is refused; an
 * unknown even type is refused, an unknown odd type skipped; every required
 * record is present; a fixed-size record has exactly its size; a list is a
 * whole number of entries between its bounds; record 240 (the signature),
 * when present, is the last record. A signed kind without 240 is refused. */
#ifndef GAZPACHO_ROUND_MSG_H
#define GAZPACHO_ROUND_MSG_H

#include "gazpacho/tree.h"
#include <stddef.h>
#include <stdint.h>

/* The envelope (messages.md 4): protocol (4), kind (u16), scope (32), records. */
#define GZ_RMSG_PROTOCOL_0 0x67
#define GZ_RMSG_PROTOCOL_1 0x7a
#define GZ_RMSG_PROTOCOL_2 0x66
#define GZ_RMSG_PROTOCOL_3 0x01
#define GZ_RMSG_HEADER     38
#define GZ_RMSG_MAX_RECORDS_ONE 65495u     /* records of one unsplit envelope */
#define GZ_RMSG_MAX_WHOLE  1048576u        /* a reassembled host message (messages.md 5) */
#define GZ_RMSG_SIG_TYPE   240

/* Kinds of section 7. */
enum {
    GZ_KIND_ROUND_PROPOSE = 64, GZ_KIND_ROUND_NONCES = 66, GZ_KIND_ROUND_ALL_NONCES = 68,
    GZ_KIND_ROUND_PARTIAL_SIGS = 70, GZ_KIND_ROUND_TIER_RESULT = 72, GZ_KIND_ROUND_COMPLETE = 74,
    GZ_KIND_ROUND_ACK = 76, GZ_KIND_ROUND_ABORT = 78, GZ_KIND_ROUND_STATUS_REQUEST = 80,
    GZ_KIND_FACTORY_FUNDED = 81
};

/* Why a message was refused (for counters and tests; never sent). */
typedef enum {
    GZ_RMSG_OK = 0,
    GZ_RMSG_E_SHORT,          /* shorter than its envelope header */
    GZ_RMSG_E_PROTOCOL,       /* the 4 protocol bytes differ: ignore, warn once */
    GZ_RMSG_E_KIND,           /* not the kind asked for */
    GZ_RMSG_E_BIGSIZE,        /* a type or length not minimally encoded, or cut off */
    GZ_RMSG_E_ORDER,          /* a type repeated or decreasing */
    GZ_RMSG_E_LENGTH,         /* a length past the end of the stream */
    GZ_RMSG_E_UNKNOWN_EVEN,   /* an even type this kind does not define */
    GZ_RMSG_E_AFTER_SIG,      /* a record after 240 */
    GZ_RMSG_E_MISSING,        /* a required record (240 included) absent */
    GZ_RMSG_E_SIZE,           /* a record of the wrong size, or a list off a whole entry or out of bounds */
    GZ_RMSG_E_VALUE,          /* a structured value malformed (all_nonces blocks, distribution, detail) */
    GZ_RMSG_E_CAPACITY        /* well formed, but more than this engine holds (GZ_RMSG_MAX_*) */
} gz_rmsg_err_t;

/* What this engine holds at most (the messages allow more). */
#define GZ_RMSG_MAX_PARTICIPANTS 32     /* GZ_SIGN_MAX_PARTICIPANTS */
#define GZ_RMSG_MAX_ENTRIES      256    /* nonces, partials, finals, items: messages.md bound */

/* ---- the envelope and the message hash ---- */

/* Split `bytes` (protocol || kind || scope || records). */
gz_rmsg_err_t gz_rmsg_open(const uint8_t *bytes, size_t len, uint16_t *kind, const uint8_t **scope,
                           const uint8_t **records, size_t *records_len);
/* Write the header; returns GZ_RMSG_HEADER, or 0 if `cap` is short. */
size_t gz_rmsg_header(uint8_t *out, size_t cap, uint16_t kind, const uint8_t scope[32]);
/* msg_hash = TH("gazpacho/msg", protocol || kind || scope || records[0..signed_len)). */
void gz_rmsg_hash(uint16_t kind, const uint8_t scope[32], const uint8_t *records, size_t signed_len, uint8_t out[32]);

/* ---- a record writer: types must be given in increasing order ---- */
typedef struct { uint8_t *p; size_t n, cap; uint64_t last; int bad; } gz_rmsg_wr_t;
void gz_rmsg_wr_init(gz_rmsg_wr_t *w, uint8_t *out, size_t cap);
void gz_rmsg_put(gz_rmsg_wr_t *w, uint64_t type, const void *value, size_t len);
/* Write a record's type and length and return where its `len` value bytes
 * go, for the caller to fill; NULL (and the writer marked bad) if it does not
 * fit or the type does not increase. */
uint8_t *gz_rmsg_reserve(gz_rmsg_wr_t *w, uint64_t type, size_t len);
/* 1 if every record fitted and every type increased. */
int gz_rmsg_wr_ok(const gz_rmsg_wr_t *w);

/* ---- the record reader, for other TLV streams under the same rules ----
 * (the journal's records, journal.md 9: "a TLV stream under the rules of
 * messages.md section 4.2"). One field per known type: GZ_RMSG_FIX exactly
 * `a` bytes; GZ_RMSG_LIST entries of `a` bytes, `lo` to `hi` of them;
 * GZ_RMSG_VAR `lo` to `hi` bytes. got[i] is field i, when present. */
enum { GZ_RMSG_FIX = 1, GZ_RMSG_LIST, GZ_RMSG_VAR };
typedef struct { uint16_t type; uint8_t required, form; uint32_t a, lo, hi; } gz_rmsg_field_t;
typedef struct { const uint8_t *v; size_t len; int present; } gz_rmsg_got_t;
gz_rmsg_err_t gz_rmsg_fields(const uint8_t *records, size_t len, const gz_rmsg_field_t *fields, size_t n_fields,
                             gz_rmsg_got_t *got, size_t *signed_len);

/* ---- per-kind views ---- */

/* round_propose (7.2). `p` borrows from the bytes, except its participants,
 * which point at `parts`. */
typedef struct {
    const uint8_t *round_id, *check_id, *host_random, *sig;
    int has_attempt; uint16_t attempt;
    gz_tree_proposal_t p;
    gz_tree_participant_t parts[GZ_RMSG_MAX_PARTICIPANTS];
    const uint8_t *lstock_hashes;       /* n_lstock_hashes x (u32 node, 32 hash) */
    const uint8_t *distribution; size_t distribution_len;
    size_t signed_len;                  /* records before 240: what msg_hash covers */
} gz_rmsg_propose_t;
gz_rmsg_err_t gz_rmsg_propose_decode(const uint8_t *records, size_t len, gz_rmsg_propose_t *m);

/* What the host fills to encode a proposal. */
typedef struct {
    const uint8_t *round_id, *check_id, *host_random;   /* 32 each */
    int has_attempt; uint16_t attempt;
    const gz_tree_proposal_t *p;        /* participants, funding transaction, fields */
    const uint8_t *lstock_hashes;       /* p->n_lstock_hashes entries of 36 bytes */
    const uint8_t *distribution; size_t distribution_len;   /* NULL: not sent */
} gz_rmsg_propose_in_t;
/* The records before 240. Returns their length, or 0 if `cap` is short or a
 * value cannot be encoded. Append the signature with gz_rmsg_put(.., 240, ..). */
size_t gz_rmsg_propose_encode(const gz_rmsg_propose_in_t *in, uint8_t *out, size_t cap);

/* round_nonces (7.3): entries of 134 (u32 index, 66 nonce, 64 nonce_sig). */
typedef struct { const uint8_t *round_id; uint8_t tier; const uint8_t *entries; size_t n; } gz_rmsg_nonces_t;
gz_rmsg_err_t gz_rmsg_nonces_decode(const uint8_t *records, size_t len, gz_rmsg_nonces_t *m);

/* round_all_nonces (7.4): items, each (u32 index, u16 n_signers, then
 * n_signers x (66 nonce, 64 nonce_sig)). item[k] points at item k's index. */
typedef struct {
    const uint8_t *round_id; uint8_t tier;
    size_t n; const uint8_t *item[GZ_RMSG_MAX_ENTRIES]; uint16_t n_signers[GZ_RMSG_MAX_ENTRIES];
} gz_rmsg_all_nonces_t;
gz_rmsg_err_t gz_rmsg_all_nonces_decode(const uint8_t *records, size_t len, gz_rmsg_all_nonces_t *m);

/* round_partial_sigs (7.5): entries of 68 (u32 index, 32 psig, 32 nonce_set_digest), signed.
 * round_tier_result (7.6): entries of 68 (u32 index, 64 final), signed. */
typedef struct { const uint8_t *round_id; uint8_t tier; const uint8_t *entries; size_t n; const uint8_t *sig; size_t signed_len; } gz_rmsg_list68_t;
gz_rmsg_err_t gz_rmsg_partial_sigs_decode(const uint8_t *records, size_t len, gz_rmsg_list68_t *m);
gz_rmsg_err_t gz_rmsg_tier_result_decode(const uint8_t *records, size_t len, gz_rmsg_list68_t *m);

/* round_complete (7.7), round_ack (7.8, held_digest), round_status_request
 * (7.10, unsigned), factory_funded (7.11, unsigned). */
typedef struct { const uint8_t *round_id, *held_digest, *funding_txid, *sig; size_t signed_len; } gz_rmsg_small_t;
gz_rmsg_err_t gz_rmsg_complete_decode(const uint8_t *records, size_t len, gz_rmsg_small_t *m);
gz_rmsg_err_t gz_rmsg_ack_decode(const uint8_t *records, size_t len, gz_rmsg_small_t *m);
gz_rmsg_err_t gz_rmsg_status_decode(const uint8_t *records, size_t len, gz_rmsg_small_t *m);
gz_rmsg_err_t gz_rmsg_funded_decode(const uint8_t *records, size_t len, gz_rmsg_small_t *m);

/* round_abort (7.9). */
typedef struct {
    const uint8_t *round_id, *sig; uint16_t reason;
    const uint8_t *detail; size_t detail_len;
    int has_tier; uint8_t tier;
    const uint8_t *items; size_t n_items;   /* u32 each */
    size_t signed_len;
} gz_rmsg_abort_t;
gz_rmsg_err_t gz_rmsg_abort_decode(const uint8_t *records, size_t len, gz_rmsg_abort_t *m);

/* ---- the hashes of section 7 ---- */
/* TH("gazpacho/nonce", round_id || u8 tier || u32 index || public nonce) (7.3). */
void gz_rmsg_nonce_hash(const uint8_t round_id[32], uint8_t tier, uint32_t index, const uint8_t nonce[66], uint8_t out[32]);
/* TH("gazpacho/nonceset", every signer's nonce in signer order) (7.5). */
void gz_rmsg_nonceset_hash(const uint8_t (*nonces)[66], size_t n, uint8_t out[32]);
/* TH("gazpacho/held", for each item in index order: u32 index || final) (7.8). */
void gz_rmsg_held_hash(const uint32_t *index, const uint8_t (*finals)[64], size_t n, uint8_t out[32]);

#endif
