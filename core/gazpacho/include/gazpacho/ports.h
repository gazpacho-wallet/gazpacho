/* Ports: the functions the program around the core must supply.
 *
 * Only what the core has to call synchronously is here: randomness, the
 * current time, and reading storage back when a node starts. Writing to
 * storage, the network and the chain are not ports in this sense. The core
 * asks for them through actions (action.h) and hears back through events
 * (event.h), so it never blocks on them.
 *
 * Memory is not a port either: the core works in storage its caller provides
 * (see action.h for why).
 *
 * Each port carries a `ctx` pointer that the core passes back unchanged. The
 * caller owns it and keeps it valid for as long as the node that holds the
 * ports. */
#ifndef GAZPACHO_PORTS_H
#define GAZPACHO_PORTS_H

#include "gazpacho/action.h"

/* What a draw of random bytes is for. Every request is tagged.
 *
 * GZ_RANDOM_SECRET: the bytes become (part of) a one-time secret, such as the
 *   session_id32 from which a MuSig2 secret nonce is made, and nothing else in
 *   Slice 1. A secret request is a promise by both sides:
 *     - the program's port: in a release build it reads the operating
 *       system's random source at the moment of the call, and keeps no state
 *       from which the bytes could be produced again: no generator whose state
 *       is saved, restored or logged. A seeded source exists only in simulator
 *       builds. The port never journals, logs or puts the bytes in an event;
 *     - the engine: the bytes go into no action. They are never saved, sent,
 *       broadcast, shown or watched, as they are or copied. What is derived
 *       from them (a public nonce) may leave; the bytes themselves may not.
 *   The simulator checks the engine's side on every action it carries out
 *   (sim.h, "secrets never leave").
 * GZ_RANDOM_ORDINARY: everything else, including randomness that is saved or
 *   sent on purpose: the restore epoch (safety-rule.md R2), the host's random
 *   values, check identifiers and lobby salts. Such bytes must never be drawn
 *   with the secret tag, whose bytes are never journaled.
 *
 * The tag changes nothing about the bytes and proves nothing on its own.
 * Whether one-time secrets repeat is checked on the secrets themselves, never
 * on what the port was asked for. */
typedef enum {
    GZ_RANDOM_ORDINARY = 0,
    GZ_RANDOM_SECRET = 1
} gz_random_purpose_t;

/* Randomness. `fill` writes `len` unpredictable bytes to `out`, for the
 * purpose given (above). In production this is the operating system's
 * generator; in the simulator it is a seeded generator, which is what makes a
 * run repeatable.
 *
 * The port may repeat itself: a machine restored from a snapshot comes back
 * with its generator's state, and the core cannot see that from inside. An
 * engine must therefore not derive anything whose reuse is fatal from the
 * port alone, nor from anything a restore can rewind (a counter in the
 * journal, for example). It must mix in something that never repeats, such
 * as the runner's incarnation, which the surrounding program keeps out of
 * reach of a restore (runner.h). The simulator has a fault that makes the
 * port repeat after a restore, and an invariant over the secrets nodes
 * actually used, to catch code that gets this wrong. */
typedef struct {
    void (*fill)(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len);
    void *ctx;
} gz_random_port_t;

/* Clock. `now_ms` returns the current time in milliseconds since an epoch of
 * the caller's choosing. The core uses it only to stamp what it records. It
 * never waits on it: waiting is done by asking for a timer. The clock may
 * jump, forwards or backwards; nothing in the core may assume it does not. */
typedef struct {
    uint64_t (*now_ms)(void *ctx);
    void *ctx;
} gz_clock_port_t;

typedef struct {
    gz_random_port_t random;
    gz_clock_port_t clock;
} gz_ports_t;

/* One batch as read back from storage. */
typedef struct {
    gz_batch_id_t id;               /* the identifier it was saved under */
    const gz_record_t *records;
    size_t n_records;
} gz_stored_batch_t;

/* Reading storage back, used only while a node starts (node.h). Storage is
 * not handed over as one array: the node walks it, batch by batch, oldest
 * first, as often as it needs to.
 *
 *   next    Fill `*batch` with the next durable batch and return 1, or return
 *           0 when there are no more. What `*batch` points to stays valid
 *           only until the next call of `next` or `rewind`.
 *   rewind  Go back to before the oldest batch.
 *
 * `incarnation` is the incarnation the node is starting under: the number
 * given to its runner. Batches saved before the start have a smaller one;
 * those its own runner saves during the start have this one. The node
 * refuses storage that holds a later one, or whose identifiers do not
 * strictly increase (GZ_ERR_CORRUPT).
 *
 * `restored` is THE RESTORE MARKER: 1 if storage was restored from a
 * backup (a backup file imported as the journal, journal.md section 8.2) and
 * the node has not yet answered that restore with a durable batch; 0
 * otherwise. The node cannot tell a restore from what it reads, so the
 * program must say so. The node's answer is its restore batch (for the
 * engines: key_epoch, restored and guard), which it puts FIRST in the actions
 * of its first start step, so that its runner issues it as sequence 1 of the
 * incarnation and holds everything outward behind its confirmation. The
 * program keeps the marker at 1, start after start, until a batch with
 * sequence 1 of an incarnation started with the marker set is durable; only
 * then is the restore answered. (A start that crashes before that batch is
 * durable has not answered it.) The marker is given at start because that is
 * before any event and before the program connects to anyone.
 *
 * STORAGE MAY CHANGE DURING A START, between two calls of gz_node_start, but
 * only by gaining batches, never by losing or altering one:
 *   - batches the starting node's own runner hands over, as they become
 *     durable;
 *   - batches an earlier program handed over before it stopped, which a slow
 *     storage layer may complete late. They take their place in the journal
 *     before any batch of the new incarnation. Every such batch must be
 *     settled, durable or gone for good, before storage accepts the first
 *     batch of the new incarnation, and so at the latest when the start
 *     finishes. A storage layer that keeps its journal in order does this
 *     anyway: the new program's first batch goes after everything the old
 *     one left. Without it, a reply the start resends for such a batch
 *     would wait behind the start's own saves, and the start could not save
 *     its records last. */
typedef struct {
    int (*next)(void *ctx, gz_stored_batch_t *batch);
    void (*rewind)(void *ctx);
    void *ctx;
    uint64_t incarnation;
    int restored;
} gz_storage_reader_t;

#endif
