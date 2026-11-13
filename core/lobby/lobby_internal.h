/* Internal helpers shared by the lobby sources. Not part of the interface. */
#ifndef GAZPACHO_LOBBY_INTERNAL_H
#define GAZPACHO_LOBBY_INTERNAL_H

#include "gazpacho/lobby.h"
#include "gazpacho/tree.h"
#include "../tree/internal.h"   /* core/tree's SHA-256: one copy in the core */

/* A BOLT 1 TLV stream being read: types strictly increasing, BigSize
 * minimal, no length past the end. */
typedef struct {
    const uint8_t *p; size_t len, at;
    int started; uint64_t type;
    const uint8_t *v; size_t vlen;
} gz_lw_tlv_t;
/* 1 with the next record, 0 at the end, -1 if the stream is invalid. */
int gz_lw_tlv_next(gz_lw_tlv_t *t);
int gz_lw_bigsize(const uint8_t *p, size_t len, size_t *at, uint64_t *v);
size_t gz_lw_put_bigsize(uint8_t *out, uint64_t v);
uint64_t gz_lw_get(const uint8_t *p, size_t n);
void gz_lw_put(uint8_t *p, uint64_t v, size_t n);

/* TH(tag, d) through core/tree's SHA-256. */
void gz_la_tagged(const char *tag, const uint8_t *d, size_t len, uint8_t out[32]);

gz_status_t gz_la_send(gz_action_list_t *o, uint64_t peer, const uint8_t *b, size_t n);
gz_status_t gz_la_save(gz_action_list_t *o, const gz_record_t *r, size_t n);
/* `r` may be a stack record: gz_action_list_add copies the record and its
 * bytes into the list (action.h). */
gz_status_t gz_la_save1(gz_action_list_t *o, uint32_t type, const uint8_t *b, size_t n);
gz_status_t gz_la_timer(gz_action_list_t *o, uint64_t id, uint64_t delay_ms);
gz_status_t gz_la_notify(gz_action_list_t *o, uint32_t code, const uint8_t *b, size_t n);
/* BOLT 1 warning, then GZ_NOTE_CLOSE for the peer. */
gz_status_t gz_la_refuse(gz_action_list_t *o, uint64_t peer, const char *why);
/* GZ_NOTE_COMMAND_REFUSED, and GZ_OK. */
gz_status_t gz_la_cmd_refused(gz_action_list_t *o, uint8_t cmd, int lobby_state);
int gz_la_verified(const gz_lobby_crypto_t *c, const uint8_t *msg, const gz_lobby_msg_t *m,
                   const uint8_t key[33]);
size_t gz_la_put_blob(uint8_t *p, const uint8_t *b, size_t n);
int gz_la_get_blob(const uint8_t *p, size_t len, size_t *at, const uint8_t **b, size_t *n);
int gz_la_freeze_ok(const uint8_t *p, size_t len);

/* core/tree's crypto provider over the lobby's port (verify and point
 * validity only: receipt needs no key aggregation). */
void gz_la_tree_crypto(const gz_lobby_crypto_t *c, gz_tree_crypto_t *out);
/* Decode records the engine saved itself, under the lobby's policy: the outer
 * rules (digest written) and the current values against them. 1 if valid. */
int gz_la_decode_terms(const uint8_t *outer, size_t olen, const uint8_t *cur, size_t clen,
                       gz_terms_outer_t *o, uint8_t od[32], gz_terms_current_t *c, uint8_t cd[32]);
/* The build parameters for `members` members (signers - 1), from gz_tree_params. */
void gz_la_shape(const gz_terms_outer_t *o, uint16_t members, gz_lobby_handoff_t *ho);

/* Stop on the first failed append. */
#define TRY(x) do { gz_status_t st_ = (x); if (st_ != GZ_OK) return st_; } while (0)

#endif
