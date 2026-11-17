/* The engine interface inside the composite (composite-node.md section 2.3).
 * Internal to core/node: engines never see the composite, and never call one
 * another; every cross-engine call goes through a hook the composite fills,
 * inside a bracket (handoff.c).
 *
 * THE ENGINE RULE (node.h): an engine returns an error only for a bug, or for
 * exhausted fixed memory that its own caps should have prevented. A condition
 * that a peer, the chain, the wallet port, the key port or a user command can
 * cause is never an error: it returns GZ_OK with a refusal, an outcome, a
 * counted drop or a notice. The composite checks what it can: timer ids below
 * 2^32, BROADCAST from the funding engine only, and, in test builds, every
 * step against the engine's declared worst step, the bracket's save
 * adjacency and re-entry. */
#ifndef GZ_NODE_ENGINE_H
#define GZ_NODE_ENGINE_H

#include "gazpacho/node.h"

typedef struct {
    uint16_t area;                         /* its journal area: also its timer and command tag */
    /* Load one record of an area it reads, in journal order: memory only. */
    gz_status_t (*load)(void *e, const gz_record_t *rec, gz_batch_id_t at);
    /* The start's actions, over one or more calls (`*more`). */
    gz_status_t (*resume)(void *e, gz_action_list_t *out, int *more);
    gz_status_t (*handle)(void *e, const gz_event_t *ev, gz_action_list_t *out);
    size_t max_step_actions, max_step_bytes; /* its worst step (8.3) */
    size_t max_timers;                     /* timers it may have set at once (7.1) */
} gz_engine_ops_t;

#endif
