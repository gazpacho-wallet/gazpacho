/* The signing engine behind the node's two calls (node.h: start and handle),
 * for the program's composite node: docs/notes/program.md section 8, item 1
 * ("an engine is reached only through gz_node_handle and gz_node_start"), on
 * PR 27, which is not merged. This is the adapter only: the program, its
 * composite node and its multi-process tests come with PR 27 and contract
 * v2's P4.
 *
 * What it adds to gz_sign_start and gz_sign_handle:
 *   - gz_sign_node_wants: which events are the signing engine's, so a
 *     composite can route each event to one engine: a message whose envelope
 *     kind is a round kind (messages.md 4.1, 64 to 81), the engine's own
 *     timer, and peer connections (the reconnect step, contract v2 node rule
 *     6). Storage confirmations it does not need (its saves are plain saves).
 *   - Node rule 5 at the seam: with the restore marker, the node's restore
 *     batch (key_epoch, restored, guard; journal.md 8.2) must be the first
 *     action of the start. The composite lists it before calling here; a
 *     restored start that finds anything else first is refused, so the
 *     engine's own saves can never come first.
 *   - The start in steps (node.h): the engine's start is one step, so *more
 *     is 0 after the first call. */
#ifndef GAZPACHO_SIGNING_NODE_H
#define GAZPACHO_SIGNING_NODE_H

#include "gazpacho/signing.h"

typedef struct {
    gz_sign_t *engine;              /* caller-allocated (large), prepared by gz_sign_node_init */
    int started;
} gz_sign_node_t;

/* 1 if the composite node should give `ev` to the signing engine. */
int gz_sign_node_wants(const gz_event_t *ev);

/* gz_sign_init on `engine`, kept in `n`. */
gz_status_t gz_sign_node_init(gz_sign_node_t *n, gz_sign_t *engine, const gz_sign_config_t *cfg, const gz_ports_t *ports,
                              uint64_t incarnation);

/* node.h's start. GZ_ERR_ARGUMENT for a restored start whose action list
 * does not begin with the node's restore batch (a SAVE). */
gz_status_t gz_sign_node_start(gz_sign_node_t *n, const gz_storage_reader_t *storage, gz_action_list_t *out, int *more);

/* node.h's handle: the events gz_sign_node_wants accepts; any other is
 * GZ_OK with nothing done. GZ_ERR_ARGUMENT before the start has run. */
gz_status_t gz_sign_node_handle(gz_sign_node_t *n, const gz_event_t *ev, gz_action_list_t *out);

#endif
