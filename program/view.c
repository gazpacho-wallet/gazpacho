/* SPDX-License-Identifier: MIT */
/* The program's view: see view.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/command.h"
#include "gazpacho/envelope.h"
#include "gazpacho/view.h"
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

/* ---- attention (local-api.md 11.4) ---------------------------------------- */

static const char *att_code(uint8_t code)
{
    switch (code) {
    case GZ_ATT_UNLOCK_TO_TAKE_PART: return "unlock_to_take_part";
    case GZ_ATT_LOBBY_LEFT_OUT: return "lobby_left_out";
    case GZ_ATT_MEMBER_REFUSED: return "member_refused";
    case GZ_ATT_HOST_FUNDS_SHORT: return "host_funds_short";
    default: return NULL;
    }
}

/* The lobby's role: its own view says it (kind 2 joined, kind 3 hosted);
 * without one, the codes that only one role raises. */
static const char *att_role(const gzp_view_t *v, const char *lobby, uint8_t code)
{
    if (gzp_view_find(v, GZ_VIEW_HOST_LOBBY, lobby)) return "hosted";
    if (gzp_view_find(v, GZ_VIEW_LOBBY, lobby)) return "joined";
    if (code == GZ_ATT_MEMBER_REFUSED || code == GZ_ATT_HOST_FUNDS_SHORT) return "hosted";
    if (code == GZ_ATT_UNLOCK_TO_TAKE_PART) return "joined";
    return NULL;
}

typedef struct {
    const gzp_view_obj_t *o;
    uint64_t since;
} att_ref_t;

void gzp_view_attention(const gzp_view_t *v, gzp_attention_t *out)
{
    att_ref_t ref[GZP_VIEW_MAX];
    size_t n = 0, i, j;
    memset(out, 0, sizeof *out);
    for (i = 0; i < v->n; i++) {
        gz_bytes_t all = {v->obj[i].bytes, v->obj[i].len}, f;
        if (v->obj[i].kind != GZ_VIEW_ATTENTION) continue;
        ref[n].o = &v->obj[i];
        ref[n].since = gz_rec_find(all, GZ_VAT_SINCE, &f) == 1 && f.len == 8 ? gz_get_u64(f.data) : 0;
        n++;
    }
    for (i = 1; i < n; i++)                           /* oldest first, then by id: stable across calls */
        for (j = i; j > 0 && (ref[j - 1].since > ref[j].since ||
                              (ref[j - 1].since == ref[j].since && strcmp(ref[j - 1].o->id, ref[j].o->id) > 0)); j--) {
            att_ref_t t = ref[j];
            ref[j] = ref[j - 1];
            ref[j - 1] = t;
        }
    for (i = 0; i < n; i++) {
        gz_bytes_t all = {ref[i].o->bytes, ref[i].o->len}, f;
        int k = out->n, w;
        uint8_t code = gz_rec_find(all, GZ_VAT_CODE, &f) == 1 && f.len == 1 ? f.data[0] : 0;
        const char *name = att_code(code), *role;
        if (!name || k == GZ_API_MAX_ATTENTION || gz_rec_find(all, GZ_VAT_LOBBY, &f) != 1 || !printable_id(f.data, f.len)) {
            out->skipped++;
            continue;
        }
        memcpy(out->lobby[k], f.data, f.len);
        out->lobby[k][f.len] = 0;
        role = att_role(v, out->lobby[k], code);
        if (!role) {
            out->skipped++;
            continue;
        }
        snprintf(out->id[k], sizeof out->id[k], "%s", ref[i].o->id);
        w = snprintf(out->params[k], sizeof out->params[k], "{\"lobby_id\":\"%s\",\"lobby_role\":\"%s\"", out->lobby[k], role);
        if (code == GZ_ATT_HOST_FUNDS_SHORT) {
            gz_bytes_t nd, hv;
            if (gz_rec_find(all, GZ_VAT_NEED, &nd) != 1 || nd.len != 8 || gz_rec_find(all, GZ_VAT_HAVE, &hv) != 1 || hv.len != 8) {
                out->skipped++;
                continue;
            }
            w += snprintf(out->params[k] + w, sizeof out->params[k] - (size_t)w, ",\"need_sat\":%llu,\"have_sat\":%llu",
                          (unsigned long long)gz_get_u64(nd.data), (unsigned long long)gz_get_u64(hv.data));
        }
        if (code == GZ_ATT_MEMBER_REFUSED && gz_rec_find(all, GZ_VAT_COUNT, &f) == 1 && f.len == 2)
            w += snprintf(out->params[k] + w, sizeof out->params[k] - (size_t)w, ",\"count\":%u", (unsigned)gz_get_u16(f.data));
        snprintf(out->params[k] + w, sizeof out->params[k] - (size_t)w, "}");
        out->item[k].id = out->id[k];
        out->item[k].code = name;
        out->item[k].lobby_id = out->lobby[k];
        out->item[k].lobby_role = role;
        out->item[k].params_json = out->params[k];
        out->n++;
    }
}
