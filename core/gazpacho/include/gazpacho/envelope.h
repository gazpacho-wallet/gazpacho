/* Saved messages and TLV streams in the core (composite-node.md section 6).
 *
 * A factory message is (kind, scope, records), the triple of messages.md
 * section 4. What the core sends and receives is that triple (action.h,
 * event.h); the program adds the protocol tag and the carrier. A message an
 * engine SAVES, to resend it byte for byte after a restart, is kept as an
 * envelope (journal.md section 9): the 4-byte protocol tag 67 7a 66 01, the
 * u16 kind, big-endian, the 32-byte scope, then the records.
 *
 * Records, here and in every record the core saves, are TLV streams under
 * BOLT 1's rules (messages.md section 4.2): BigSize type and length, types
 * strictly increasing. The readers below never read past the stream and
 * refuse a malformed one.
 *
 * Pure functions: no state, no input or output. */
#ifndef GAZPACHO_ENVELOPE_H
#define GAZPACHO_ENVELOPE_H

#include "gazpacho/types.h"

#define GZ_ENVELOPE_TAG_LEN 4
#define GZ_ENVELOPE_HDR_LEN 38   /* tag 4, kind 2, scope 32 */

/* The kinds the core names (messages.md section 4.1). */
#define GZ_MSG_KIND_PART          2
#define GZ_MSG_KIND_HELLO         16
#define GZ_MSG_KIND_LOBBY_STATUS  28
#define GZ_MSG_KIND_LOBBY_FIRST   16   /* the lobby range, 16 to 63 (36: the 1.0.0 receipt) */
#define GZ_MSG_KIND_LOBBY_LAST    63
#define GZ_MSG_KIND_ROUND_FIRST   64   /* the signing range, 64 to 80 */
#define GZ_MSG_KIND_ROUND_LAST    80
#define GZ_MSG_KIND_FACTORY_FUNDED 81
#define GZ_MSG_KIND_DISCOVERY_FIRST 128
#define GZ_MSG_KIND_DISCOVERY_LAST  159
#define GZ_MSG_KIND_TEST          32767 /* test builds only (contract-v2.md section 7) */

/* The protocol tag is 67 7a 66 01 (envelope.c). */

/* Write the envelope of (kind, scope, records) to out[0..cap): the tag, the
 * kind, the scope, the records. Returns GZ_OK and its length in *len;
 * GZ_ERR_ARGUMENT for a NULL argument (records may be empty);
 * GZ_ERR_NO_SPACE if it does not fit (out untouched). */
gz_status_t gz_env_join(uint16_t kind, const uint8_t scope[32], gz_bytes_t records,
                        uint8_t *out, size_t cap, size_t *len);

/* Read an envelope back: its kind, scope and records (pointing into
 * `envelope`). Returns GZ_OK; GZ_ERR_CORRUPT if it is shorter than the header
 * or does not start with the tag. */
gz_status_t gz_env_split(gz_bytes_t envelope, uint16_t *kind, uint8_t scope[32], gz_bytes_t *records);

/* BigSize (BOLT 1): write `v` to out (9 bytes at most), returning the length;
 * read one minimally encoded value, returning its length or 0 if malformed or
 * short. */
size_t gz_bigsize_put(uint64_t v, uint8_t out[9]);
size_t gz_bigsize_get(const uint8_t *in, size_t len, uint64_t *v);

/* Walk a TLV stream. 1 if the whole stream is well formed (minimal BigSize,
 * strictly increasing types, no length past the end), else 0. */
int gz_rec_valid(gz_bytes_t stream);

/* The value of record `type` in a well-formed stream: 1 and *value set if it
 * is there, 0 if it is not, -1 if the stream is malformed. */
int gz_rec_find(gz_bytes_t stream, uint64_t type, gz_bytes_t *value);

/* Append one record to out[*at..cap): type, length, value. Returns GZ_OK and
 * advances *at; GZ_ERR_NO_SPACE if it does not fit (nothing written). The
 * caller keeps types increasing; value does not overlap out. */
gz_status_t gz_rec_put(uint8_t *out, size_t cap, size_t *at, uint64_t type, const uint8_t *value, size_t len);

/* Big-endian fixed-width integers, for record fields. */
void gz_put_u16(uint8_t out[2], uint16_t v);
void gz_put_u32(uint8_t out[4], uint32_t v);
void gz_put_u64(uint8_t out[8], uint64_t v);
uint16_t gz_get_u16(const uint8_t in[2]);
uint32_t gz_get_u32(const uint8_t in[4]);
uint64_t gz_get_u64(const uint8_t in[8]);

#endif
