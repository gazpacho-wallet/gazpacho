/* SPDX-License-Identifier: MIT */
/* The lobby, hosting and discovery objects of the local API, from the core's
 * view (W12; api_lobby.c). */
#ifndef GZP_API_LOBBY_H
#define GZP_API_LOBBY_H

#include "gazpacho/api_json.h"
#include "api.h"

void gzp_api_lobby_json(gzp_api_t *a, gz_jw *w, const gzp_view_obj_t *o, int row);
void gzp_api_host_lobby_json(gzp_api_t *a, gz_jw *w, const gzp_view_obj_t *o, int row);
const gzp_view_obj_t *gzp_api_find(gzp_api_t *a, uint32_t kind, const char *id);
int gzp_api_scope_of(gzp_api_t *a, const char *id, int host, uint8_t scope[32], const gzp_view_obj_t **obj);
int gzp_api_parse_host(const char *s, uint8_t key[33], char *addr, size_t cap);
int gzp_api_unhex32(const char *s, uint8_t out[32]);

#endif
