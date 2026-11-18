/* SPDX-License-Identifier: MIT */
/* The program's view: see view.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/command.h"
#include "gazpacho/envelope.h"
#include "view.h"

static int printable_id(const uint8_t *p, size_t n)
{
    size_t i;
    if (n < 1 || n > GZP_VIEW_ID_MAX) return 0;
    for (i = 0; i < n; i++)
        if (p[i] < 33 || p[i] > 126) return 0;
    return 1;
}

static gzp_view_obj_t *find(gzp_view_t *v, uint32_t kind, const char *id)
{
    size_t i;
    for (i = 0; i < v->n; i++)
        if (v->obj[i].kind == kind && strcmp(v->obj[i].id, id) == 0) return &v->obj[i];
    return NULL;
}

int gzp_view_apply(gzp_view_t *v, uint32_t kind, const uint8_t *bytes, size_t len, char id_out[GZP_VIEW_ID_MAX + 1])
{
    gz_bytes_t all = {bytes, len}, f;
    char id[GZP_VIEW_ID_MAX + 1];
    uint64_t version = 0;
    int gone;
    gzp_view_obj_t *o;
    uint8_t *copy;
    if (gz_rec_find(all, GZ_VIEW_REC_ID, &f) != 1 || !printable_id(f.data, f.len)) {
        v->dropped++;
        return 0;
    }
    memcpy(id, f.data, f.len);
    id[f.len] = 0;
    if (gz_rec_find(all, GZ_VIEW_REC_VERSION, &f) == 1) {
        if (f.len != 8) {
            v->dropped++;
            return 0;
        }
        version = gz_get_u64(f.data);
    }
    gone = gz_rec_find(all, GZ_VIEW_REC_GONE, &f) == 1;
    o = find(v, kind, id);
    if (o && version && o->version && version <= o->version) return 0;   /* never older (node rule 8) */
    if (gone) {
        if (!o) return 0;
        free(o->bytes);
        *o = v->obj[--v->n];
        memset(&v->obj[v->n], 0, sizeof v->obj[v->n]);
        snprintf(id_out, GZP_VIEW_ID_MAX + 1, "%s", id);
        return 1;
    }
    if (!o) {
        if (v->n == GZP_VIEW_MAX) {
            v->dropped++;
            return 0;
        }
        o = &v->obj[v->n++];
        memset(o, 0, sizeof *o);
        o->kind = kind;
        memcpy(o->id, id, strlen(id) + 1);
    }
    copy = malloc(len ? len : 1);
    if (!copy) abort();
    memcpy(copy, bytes, len);
    free(o->bytes);
    o->bytes = copy;
    o->len = len;
    o->version = version;
    snprintf(id_out, GZP_VIEW_ID_MAX + 1, "%s", id);
    return 1;
}

const gzp_view_obj_t *gzp_view_find(const gzp_view_t *v, uint32_t kind, const char *id)
{
    return find((gzp_view_t *)v, kind, id);
}

void gzp_view_clear(gzp_view_t *v)
{
    size_t i;
    for (i = 0; i < v->n; i++) free(v->obj[i].bytes);
    memset(v->obj, 0, sizeof v->obj);
    v->n = 0;
}

const char *gzp_view_topic(uint32_t kind)
{
    switch (kind) {
    case GZ_VIEW_LOBBY: return "lobby";
    case GZ_VIEW_HOST_LOBBY: return "host_lobby";
    case GZ_VIEW_FACTORY: return "factory";
    case GZ_VIEW_WALLET: return "wallet";
    case GZ_VIEW_ACTIVITY: return "activity";
    default: return "status";      /* status, attention, doing, connection */
    }
}

int gzp_view_lobby_class(uint32_t kind)
{
    return kind == GZ_VIEW_LOBBY ? 1 : kind == GZ_VIEW_HOST_LOBBY ? 2 : 0;
}
