/* Ports: the functions the program around the core must supply.
 *
 * Only what the core has to call synchronously is here: randomness and the
 * current time. Storage, the network and the chain are not ports in this
 * sense. The core asks for them through actions (action.h) and hears back
 * through events (event.h), so it never blocks on them.
 *
 * Memory is not a port either: the core works in storage its caller provides
 * (see action.h for why).
 *
 * Each port carries a `ctx` pointer that the core passes back unchanged. The
 * caller owns it and keeps it valid for as long as the node that holds the
 * ports. */
#ifndef GAZPACHO_PORTS_H
#define GAZPACHO_PORTS_H

#include "gazpacho/types.h"

/* Randomness. `fill` writes `len` unpredictable bytes to `out`. In production
 * this is the operating system's generator; in the simulator it is a seeded
 * generator, which is what makes a run repeatable. */
typedef struct {
    void (*fill)(void *ctx, uint8_t *out, size_t len);
    void *ctx;
} gz_random_port_t;

/* Clock. `now_ms` returns the current time in milliseconds since an epoch of
 * the caller's choosing. The core uses it only to stamp what it records. It
 * never waits on it: waiting is done by asking for a timer. */
typedef struct {
    uint64_t (*now_ms)(void *ctx);
    void *ctx;
} gz_clock_port_t;

typedef struct {
    gz_random_port_t random;
    gz_clock_port_t clock;
} gz_ports_t;

#endif
