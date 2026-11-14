/* SPDX-License-Identifier: MIT */
/* The user adapter: NOTIFY actions out to the interface.
 *
 * NOTIFY carries (u32 code, bytes). The local API server (PR 26, branch
 * api-server) publishes changes as gz_api_notify(server, topic, id): a topic
 * of local-api.md section 10.2 and a local id, merged within 250 ms, with no
 * payload; the client then reads the state through the API's calls. So the
 * adapter will map each code to (topic, id) and the facts behind it to the
 * backend's status (api_backend.h). Until PR 26 is merged, the sink writes
 * one output line per NOTIFY. */
#ifndef GZP_NOTIFY_H
#define GZP_NOTIFY_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    void (*emit)(void *ctx, uint32_t code, const uint8_t *bytes, size_t len);
    void *ctx;
} gzp_notify_sink_t;

/* The output-line sink. */
void gzp_notify_lines(gzp_notify_sink_t *s);

#endif
