/* Gazpacho's factory message envelope (spec/messages.md sections 3 to 5).
 *
 * A factory message is a Lightning message of the odd custom type 52791 whose
 * payload is the 4-byte protocol tag 67 7a 66 01, a u16 kind, a 32-byte scope
 * and a BOLT 1 TLV stream of records. Messages whose records would exceed
 * 65,495 bytes travel as parts (kind 2) and are put back together before
 * anything else is checked.
 *
 * No input or output. The only allocation is the reassembly buffer of one
 * transfer (at most 1 MiB), owned by a gz_env_reasm_t. */
#ifndef GAZPACHO_NET_ENVELOPE_H
#define GAZPACHO_NET_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>
#include <secp256k1.h>

#define GZ_ENV_TYPE 52791u            /* 0xce37: SHA256("gazpacho factory message")[0:2] | 0x8001 */
#define GZ_ENV_HDR_LEN 38             /* protocol 4, kind 2, scope 32 */
#define GZ_ENV_MAX_RECORDS 65495u     /* 65,535 less the 2-byte type and the header */
#define GZ_ENV_PART_DATA 65000u       /* data per part; every part but the last is full */
#define GZ_ENV_MAX_WHOLE 1048576u     /* largest whole message, host to member */
#define GZ_ENV_MAX_PARTS 17u          /* ceil(1 MiB / 65,000) */
#define GZ_ENV_SIG_TYPE 240u          /* record 240 is the signature, always last */

#define GZ_ENV_KIND_PART 2
#define GZ_ENV_KIND_HELLO 16
#define GZ_ENV_KIND_TERMS_OFFER 18
#define GZ_ENV_KIND_JOIN 20
#define GZ_ENV_KIND_READY 22
#define GZ_ENV_KIND_UNREADY 24
#define GZ_ENV_KIND_LEAVE 26
#define GZ_ENV_KIND_LOBBY_STATUS 28
#define GZ_ENV_KIND_READY_CHECK 30
#define GZ_ENV_KIND_START 32
#define GZ_ENV_KIND_CANCEL 34
#define GZ_ENV_KIND_ROUND_PROPOSE 64
#define GZ_ENV_KIND_ROUND_NONCES 66
#define GZ_ENV_KIND_ROUND_ALL_NONCES 68
#define GZ_ENV_KIND_ROUND_PARTIAL_SIGS 70
#define GZ_ENV_KIND_ROUND_TIER_RESULT 72
#define GZ_ENV_KIND_ROUND_COMPLETE 74
#define GZ_ENV_KIND_ROUND_ACK 76
#define GZ_ENV_KIND_ROUND_ABORT 78
#define GZ_ENV_KIND_ROUND_STATUS_REQUEST 80
#define GZ_ENV_KIND_FACTORY_FUNDED 81

extern const uint8_t GZ_ENV_PROTOCOL[4]; /* 67 7a 66 01 */

/* Which side of a connection receives: the host (it accepted the
 * connection) or the member (it made it). The direction rule of 4.1 and the
 * rule that members send no parts depend on it. */
typedef enum { GZ_ENV_AT_HOST = 1, GZ_ENV_AT_MEMBER = 2 } gz_env_side_t;

/* What the receiver does with a message (messages.md section 1). */
typedef enum {
    GZ_ENV_DELIVER = 0,  /* a whole, valid message: hand it on */
    GZ_ENV_HELD,         /* a valid part, kept until its transfer completes */
    GZ_ENV_IGNORE,       /* do nothing, send nothing, keep the connection */
    GZ_ENV_IGNORE_WARN,  /* ignore; send a warning if none was sent on this connection (wrong protocol tag) */
    GZ_ENV_REFUSE        /* send a warning with the reason, then close */
} gz_env_verdict_t;

/* One record of a factory message, pointing into the message's bytes. */
typedef struct {
    uint64_t type;
    const uint8_t *value;
    size_t len;
} gz_env_record_t;

/* A message read from the wire, or put back together from parts. The
 * pointers stay valid while the bytes they point into do. */
typedef struct {
    uint16_t kind;
    const uint8_t *scope;   /* 32 bytes */
    const uint8_t *records; /* the TLV stream */
    size_t records_len;
} gz_env_msg_t;

/* Encoding. Writes type 52791, the tag, kind, scope and records, refusing
 * records over 65,495 bytes (split those). Returns 0 on success. */
int gz_env_write(uint16_t kind, const uint8_t scope[32], const uint8_t *records, size_t records_len,
                 uint8_t *out, size_t out_cap, size_t *out_len);

/* Splitting (section 5). For a body over 65,495 bytes and at most 1 MiB,
 * gz_env_part_count gives the number of parts (0 if the body must not be
 * split), gz_env_transfer_id the transfer's name, TH("gazpacho/part", u16
 * inner_kind || body), and gz_env_write_part writes part `index` as a whole
 * Lightning message. inner_kind 2 is refused. */
unsigned gz_env_part_count(size_t body_len);
void gz_env_transfer_id(const secp256k1_context *secp, uint16_t inner_kind, const uint8_t *body, size_t body_len,
                        uint8_t out[32]);
int gz_env_write_part(const uint8_t transfer_id[32], uint16_t inner_kind, const uint8_t scope[32],
                      const uint8_t *body, size_t body_len, unsigned index,
                      uint8_t *out, size_t out_cap, size_t *out_len);

/* TH(tag, bytes): BIP 340's tagged hash. */
void gz_env_tagged_hash(const secp256k1_context *secp, const char *tag,
                        const uint8_t *bytes, size_t len, uint8_t out[32]);

/* msg_hash of section 4.3 for a message with a signature: TH("gazpacho/msg",
 * protocol || kind || scope || every record byte before record 240). 0 if the
 * message has no record 240. */
int gz_env_msg_hash(const secp256k1_context *secp, const gz_env_msg_t *m, uint8_t out[32]);

/* Verifies record 240 under a 33-byte key (BIP 340, x coordinate). 1 if it
 * verifies. */
int gz_env_verify(const secp256k1_context *secp, const gz_env_msg_t *m, const uint8_t key[33]);

/* Reading one whole Lightning message of type 52791 (the caller has read the
 * type). Checks the header, the generic record rules of 4.2 (minimal BigSize,
 * strictly increasing types, no length past the end, nothing after 240), the
 * kind's odd/even and direction rules (4.1), the scope rule (4) and, for a
 * known kind, its record table: required records present, sizes exact, lists
 * whole and within bounds, unknown even records refused, unknown odd records
 * skipped. On GZ_ENV_DELIVER `out` describes the message; a part (kind 2)
 * gives GZ_ENV_DELIVER too and is passed on to gz_env_reasm_add. `reason` (if
 * not NULL) gets a short ASCII reason for IGNORE_WARN and REFUSE. */
gz_env_verdict_t gz_env_read(const uint8_t *msg, size_t len, gz_env_side_t at, gz_env_msg_t *out,
                             const char **reason);

/* The record checks alone, for a whole (possibly reassembled) message of a
 * given kind received at `at`. Used by gz_env_read and after reassembly. */
gz_env_verdict_t gz_env_check(uint16_t kind, const uint8_t scope[32], const uint8_t *records, size_t len,
                              gz_env_side_t at, const char **reason);

/* Every record of a stream that gz_env_check accepted, in order, unknown odd
 * records included. Returns the number written (at most cap), or -1 if the
 * stream is malformed. */
int gz_env_records(const uint8_t *records, size_t len, gz_env_record_t *out, size_t cap);

/* The record of a given type, or NULL. */
const gz_env_record_t *gz_env_find(const gz_env_record_t *recs, int n, uint64_t type);

/* Reassembly of parts (section 5): one transfer per direction per
 * connection, at most 1 MiB, freed when it completes, fails or is reset. */
typedef struct {
    uint8_t *buf;          /* total_len bytes while a transfer is open */
    uint8_t transfer_id[32];
    uint8_t scope[32];
    uint16_t inner_kind, count;
    uint32_t total_len;
    uint32_t held;         /* bit i: part i is held */
    size_t allocated;      /* bytes held by buf, for the memory bound */
} gz_env_reasm_t;

void gz_env_reasm_init(gz_env_reasm_t *r);
/* Drops an open transfer, or releases a completed one, wiping and freeing
 * its memory. A caller calls it as soon as it has used a delivered message
 * (messages.md 5: freed when the transfer completes). */
void gz_env_reasm_reset(gz_env_reasm_t *r);

/* Adds a part that gz_env_read delivered. GZ_ENV_HELD while the transfer is
 * incomplete; GZ_ENV_IGNORE for a byte-for-byte duplicate; GZ_ENV_DELIVER
 * when it completes, with `out` pointing into the reassembly buffer (valid
 * until gz_env_reasm_reset, which the caller then calls; the next call on
 * `r` also releases it) after the whole message passed gz_env_check;
 * GZ_ENV_REFUSE otherwise (the transfer is then dropped). */
gz_env_verdict_t gz_env_reasm_add(gz_env_reasm_t *r, const gz_env_msg_t *part, gz_env_side_t at,
                                  const secp256k1_context *secp, gz_env_msg_t *out, const char **reason);

/* The bLIP-56 adapter (section 10). Not used in slice 1: a slice 1 build
 * never sends type 32800. These map bytes only, for vectors M0 and M3. */
#define GZ_ENV_BLIP56_TYPE 32800u
extern const uint8_t GZ_ENV_FACTORY_PROTOCOL_ID[32]; /* SHA256("SuperScalar/1") */
/* supported_factory_protocols naming only our id (40 bytes). */
int gz_env_blip56_supported(uint8_t *out, size_t out_cap, size_t *out_len);
/* A native message (type 52791 included) to a factory_piggyback message. */
int gz_env_blip56_wrap(const uint8_t *native, size_t len, uint8_t *out, size_t out_cap, size_t *out_len);
/* A factory_piggyback message to the native message; refuses a missing TLV 0
 * or 1024, or another protocol id. */
int gz_env_blip56_unwrap(const uint8_t *msg, size_t len, uint8_t *out, size_t out_cap, size_t *out_len);

#endif
