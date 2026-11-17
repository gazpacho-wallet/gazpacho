/* SPDX-License-Identifier: MIT */
/* The program's view (contract-v2.md 11): for each (object kind, id), the
 * latest bytes a view NOTIFY gave. The API backend reads it on the loop
 * thread. It is cleared at every start from storage and rebuilt from the
 * start's notices (node rule 7). */
#ifndef GZP_VIEW_H
#define GZP_VIEW_H

#include <stddef.h>
#include <stdint.h>

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

#endif
