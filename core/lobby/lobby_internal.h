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

/* SEND the envelope `env` (tag, kind, scope, records) on `link`: the action
 * carries the kind, the scope and the records (action.h). An envelope
 * shorter than its header is a bug. */
gz_status_t gz_la_send(gz_action_list_t *o, const gz_link_t *link, const uint8_t *env, size_t n);
gz_status_t gz_la_save(gz_action_list_t *o, const gz_record_t *r, size_t n);
/* `r` may be a stack record: gz_action_list_add copies the record and its
 * bytes into the list (action.h). */
gz_status_t gz_la_save1(gz_action_list_t *o, uint32_t type, const uint8_t *b, size_t n);
gz_status_t gz_la_timer(gz_action_list_t *o, uint64_t id, uint64_t delay_ms);
gz_status_t gz_la_notify(gz_action_list_t *o, uint32_t code, const uint8_t *b, size_t n);
/* DISCONNECT `link` with `why` REFUSED: the transport sends the warning. */
gz_status_t gz_la_refuse(gz_action_list_t *o, const gz_link_t *link);
gz_status_t gz_la_seated(gz_action_list_t *o, const uint8_t key[33], int seated);
/* GZ_NOTE_COMMAND_REFUSED, and GZ_OK. */
gz_status_t gz_la_cmd_refused(gz_action_list_t *o, uint8_t cmd, int lobby_state);
/* GZ_NOTE_NO_KEY for key `which`. */
gz_status_t gz_la_no_key(gz_action_list_t *o, uint32_t which);
/* A decoded message signed by `key` (record 240). */
int gz_la_verified(const gz_lobby_crypto_t *c, const gz_lobby_msg_t *m, const uint8_t key[33]);
/* The envelope of a received message, to save it: its length, or 0 if it
 * does not fit `cap`. */
size_t gz_la_env(uint16_t kind, const uint8_t scope[32], const uint8_t *records, size_t len, uint8_t *out,
                 size_t cap);

/* ---- records (journal.md section 9): TLV streams, scope first ------------
 *
 * Every Lobby record is a TLV stream under messages.md 4.2 whose first field,
 * type 2, is the lobby's scope. The other fields are even types from 4 up,
 * each record's own (the table is in docs/notes/lobby.md section 1). */
typedef struct { uint8_t *b; size_t cap, at; int bad; } gz_lr_t;
void gz_lr_start(gz_lr_t *w, uint8_t *buf, size_t cap, const uint8_t scope[32]);
void gz_lr_put(gz_lr_t *w, uint64_t type, const uint8_t *v, size_t n);
void gz_lr_int(gz_lr_t *w, uint64_t type, uint64_t v, size_t width);
/* The record's length; 0 if a field did not fit (a bug: the buffers are
 * sized from the table of largest records). */
size_t gz_lr_done(const gz_lr_t *w);
/* Save a built record; GZ_ERR_BUG if it did not fit its buffer. */
gz_status_t gz_lr_save(gz_action_list_t *o, uint32_t type, const gz_lr_t *w);

/* A record read back: its even fields 2 to GZ_LF_MAX by type / 2. A field
 * that is absent has v NULL. */
#define GZ_LF_MAX 20
typedef struct { const uint8_t *v[GZ_LF_MAX / 2 + 1]; size_t n[GZ_LF_MAX / 2 + 1]; } gz_lf_t;
/* 1 if `p` is a well-formed record whose scope is `scope` (any scope if
 * NULL), with no even field above GZ_LF_MAX; odd fields are skipped. */
int gz_lf_read(const uint8_t *p, size_t len, const uint8_t *scope, gz_lf_t *f);
/* 1 if every even field of `f` is one a record of `type` has (the table in
 * act.c): an even field this version does not know in that record is not
 * skipped, it makes the record one this version cannot read. */
int gz_lf_known(uint32_t type, const gz_lf_t *f);
/* The field `type` if it is there with exactly `n` bytes, else NULL. */
const uint8_t *gz_lf_fixed(const gz_lf_t *f, unsigned type, size_t n);
/* The field `type` if it is there with at most `max` bytes: 1 and set. */
int gz_lf_blob(const gz_lf_t *f, unsigned type, size_t max, const uint8_t **v, size_t *n);

/* A FREEZE record's fields: the signed ready_check names exactly them. */
int gz_la_freeze_ok(const gz_lf_t *f);

/* core/tree's crypto provider over the lobby's port (verify and point
 * validity only: receipt needs no key aggregation). */
void gz_la_tree_crypto(const gz_lobby_crypto_t *c, gz_tree_crypto_t *out);
/* Decode records the engine saved itself, under the lobby's policy: the outer
 * rules (digest written) and the current values against them. 1 if valid. */
int gz_la_decode_terms(const uint8_t *outer, size_t olen, const uint8_t *cur, size_t clen,
                       gz_terms_outer_t *o, uint8_t od[32], gz_terms_current_t *c, uint8_t cd[32]);
/* The build parameters for `members` members (signers - 1), from gz_tree_params. */
void gz_la_shape(const gz_terms_outer_t *o, uint16_t members, gz_lobby_handoff_t *ho);
/* The records of a lobby_status into an envelope buffer of
 * GZ_LOBBY_STATUS_MAX bytes; its length. */
size_t gz_la_status(const uint8_t scope[32], uint8_t lobby_state, uint8_t seat_state, uint32_t version,
                    uint16_t joined, uint16_t ready, int with_reason, uint16_t reason,
                    uint8_t buf[GZ_LOBBY_STATUS_MAX]);

/* Stop on the first failed append. */
#define TRY(x) do { gz_status_t st_ = (x); if (st_ != GZ_OK) return st_; } while (0)

#endif
