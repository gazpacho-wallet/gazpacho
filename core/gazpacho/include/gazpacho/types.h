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
    GZ_ERR_DUPLICATE_BATCH, /* a save batch reuses an identifier still in play */
    GZ_ERR_UNKNOWN_BATCH    /* a confirmation names a batch that is not awaiting one */
} gz_status_t;

/* A read-only byte string. The core never frees `data`; who owns it is stated
 * wherever a gz_bytes_t appears. `data` may be NULL only when `len` is 0. */
typedef struct {
    const uint8_t *data;
    size_t len;
} gz_bytes_t;

#endif
