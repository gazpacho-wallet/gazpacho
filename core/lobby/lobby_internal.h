/* Internal helpers shared by the lobby sources. Not part of the interface. */
#ifndef GAZPACHO_LOBBY_INTERNAL_H
#define GAZPACHO_LOBBY_INTERNAL_H

#include "gazpacho/lobby.h"

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


gz_status_t gz_la_send(gz_action_list_t *o, uint64_t peer, const uint8_t *b, size_t n);
gz_status_t gz_la_save(gz_action_list_t *o, const gz_record_t *r, size_t n);
gz_status_t gz_la_save1(gz_action_list_t *o, uint32_t type, const uint8_t *b, size_t n);
gz_status_t gz_la_timer(gz_action_list_t *o, uint64_t id, uint64_t delay_ms);
gz_status_t gz_la_notify(gz_action_list_t *o, uint32_t code, const uint8_t *b, size_t n);
/* BOLT 1 warning, then GZ_NOTE_CLOSE for the peer. */
gz_status_t gz_la_refuse(gz_action_list_t *o, uint64_t peer, const char *why);
int gz_la_verified(const gz_lobby_crypto_t *c, const uint8_t *msg, const gz_lobby_msg_t *m,
                   const uint8_t key[33]);
size_t gz_la_put_blob(uint8_t *p, const uint8_t *b, size_t n);
int gz_la_get_blob(const uint8_t *p, size_t len, size_t *at, const uint8_t **b, size_t *n);
int gz_la_freeze_ok(const uint8_t *p, size_t len);

/* Stop on the first failed append. */
#define TRY(x) do { gz_status_t st_ = (x); if (st_ != GZ_OK) return st_; } while (0)

#endif
