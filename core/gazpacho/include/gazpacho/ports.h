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

/* What a draw of random bytes is for. The tag changes nothing about the bytes
 * in production. It is there so a test harness can keep a log of every draw
 * and check rules about particular kinds, above all that a one-time secret is
 * never produced twice. */
#define GZ_RANDOM_OTHER  0u
#define GZ_RANDOM_SECRET 1u     /* a one-time secret: must never repeat */

/* Randomness. `fill` writes `len` unpredictable bytes to `out`; `purpose` is
 * one of the tags above. In production this is the operating system's
 * generator; in the simulator it is a seeded generator, which is what makes a
 * run repeatable.
 *
 * A program restored from a backup or a snapshot must not come back with a
 * generator that repeats what it produced before. The core cannot see that
 * from inside, so engines must not rely on the port alone for anything whose
 * reuse is fatal; the simulator has a fault that makes the port repeat after
 * a restore, to catch code that does. */
typedef struct {
    void (*fill)(void *ctx, uint32_t purpose, uint8_t *out, size_t len);
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
 * given to its runner. Every batch in storage has a smaller one. */
typedef struct {
    int (*next)(void *ctx, gz_stored_batch_t *batch);
    void (*rewind)(void *ctx);
    void *ctx;
    uint64_t incarnation;
} gz_storage_reader_t;

#endif
