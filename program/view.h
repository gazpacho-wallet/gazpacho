/* SPDX-License-Identifier: MIT */
/* The program's view (contract-v2.md 11): for each (object kind, id), the
 * latest bytes a view NOTIFY gave. The API backend reads it on the loop
 * thread. It is cleared at every start from storage and rebuilt from the
 * start's notices (node rule 7). */
#ifndef GZP_VIEW_H
#define GZP_VIEW_H

#include <stddef.h>
#include <stdint.h>

#include "gazpacho/api_backend.h"

#define GZP_VIEW_MAX 512
#define GZP_VIEW_ID_MAX 64

typedef struct {
    uint32_t kind;                     /* GZ_VIEW_* */
    char id[GZP_VIEW_ID_MAX + 1];      /* printable ASCII */
    uint64_t version;
    uint8_t *bytes;                    /* the whole TLV stream as the notice gave it */
    size_t len;
} gzp_view_obj_t;

typedef struct {
    gzp_view_obj_t obj[GZP_VIEW_MAX];
    size_t n;
    uint64_t dropped;                  /* notices refused: malformed, an older version, or a full table */
} gzp_view_t;

/* A view NOTIFY of kind k (code GZ_NOTIFY_VIEW(k)): stores, replaces or (gone)
 * removes the object. 1 if the view changed (id_out then names the object),
 * 0 if not (an older or equal version, or a refused notice). */
int gzp_view_apply(gzp_view_t *v, uint32_t kind, const uint8_t *bytes, size_t len, char id_out[GZP_VIEW_ID_MAX + 1]);
const gzp_view_obj_t *gzp_view_find(const gzp_view_t *v, uint32_t kind, const char *id);
void gzp_view_clear(gzp_view_t *v);
/* The API event topic (local-api.md 10.2) for a view kind. */
const char *gzp_view_topic(uint32_t kind);

/* 1 for a member's lobby view, 2 for a hosted lobby's, 0 for any other kind. */
int gzp_view_lobby_class(uint32_t kind);

/* GET /api/v1/status's attention list (local-api.md 11.4) from the core's
 * kind 7 items (docs/notes/view-objects.md 5): code, lobby_id, lobby_role
 * (joined or hosted: the item's GZ_VAT_ROLE, else the lobby's own view kind,
 * else the code), and
 * params (lobby_id and lobby_role, and need_sat, have_sat for
 * host_funds_short, count for member_refused, each required). Oldest first
 * (since_at, then id); the server orders them by tier. An item of an unknown
 * code, whose lobby has no role, or without its numbers is left out, counted
 * in `skipped`, and named in `dropped` (the first GZP_ATT_DROPPED_MAX, as
 * "id why") for the program's log. */
#define GZP_ATT_DROPPED_MAX 8
#define GZP_ATT_PARAMS_MAX 192
typedef struct {
    char id[GZ_API_MAX_ATTENTION][GZP_VIEW_ID_MAX + 1];
    char lobby[GZ_API_MAX_ATTENTION][GZP_VIEW_ID_MAX + 1];
    char params[GZ_API_MAX_ATTENTION][GZP_ATT_PARAMS_MAX];
    gz_api_attention item[GZ_API_MAX_ATTENTION];
    int n;
    int skipped;
    char dropped[GZP_ATT_DROPPED_MAX][GZP_VIEW_ID_MAX + 24];
} gzp_attention_t;
void gzp_view_attention(const gzp_view_t *v, gzp_attention_t *out);

#endif
