/* Basic types shared by every part of the Gazpacho core. */
#ifndef GAZPACHO_TYPES_H
#define GAZPACHO_TYPES_H

#include <stddef.h>
#include <stdint.h>

/* Result of a core call. Anything other than GZ_OK leaves its target unchanged. */
typedef enum {
    GZ_OK = 0,
    GZ_ERR_ARGUMENT,        /* a required argument is missing or malformed */
    GZ_ERR_NO_SPACE,        /* the caller-provided storage is full */
    GZ_ERR_REFUSED,         /* the runner could not accept a list: fatal for the node (runner.h) */
    GZ_ERR_FAILED,          /* the runner has failed and releases nothing further (runner.h) */
    GZ_ERR_REENTRANT,       /* the runner was called from inside its own executor callback */
    GZ_ERR_STALE_BATCH,     /* a confirmation for a batch issued before the last restart: ignored */
    GZ_ERR_UNKNOWN_BATCH,   /* a confirmation for a batch never issued, or already confirmed */
    GZ_ERR_OUT_OF_ORDER     /* a confirmation that skips an earlier unconfirmed batch */
} gz_status_t;

/* Identifier of one save batch. Issued by the runner, never by a node, and
 * never reused: `incarnation` is the number the surrounding program gave the
 * runner when it started (strictly greater at every start, see runner.h) and
 * `sequence` counts that runner's batches from 1. */
typedef struct {
    uint64_t incarnation;
    uint64_t sequence;
} gz_batch_id_t;

/* A read-only byte string. The core never frees `data`; who owns it is stated
 * wherever a gz_bytes_t appears. `data` may be NULL only when `len` is 0. */
typedef struct {
    const uint8_t *data;
    size_t len;
} gz_bytes_t;

#endif
