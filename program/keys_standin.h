/* SPDX-License-Identifier: MIT */
/* STAND-IN seed source (docs/notes/keys.md 9): the BIP 39 seed of the
 * stand-in wallet-seed.standin (32 bytes of entropy, 64 hex, mode 0600,
 * datadir.h), read once at start and held until gzp_seed_standin_close.
 * Unencrypted, so for test networks only. The storage layer's unlocked seed
 * replaces it (S6, through program/unlock.h). */
#ifndef GZP_KEYS_STANDIN_H
#define GZP_KEYS_STANDIN_H

#include <stdint.h>

#include "datadir.h"
#include "keys.h"

typedef struct {
    uint8_t seed[64];   /* SECRET */
    int have;
} gzp_seed_standin_t;

/* Read (or create) the file and make the seed: 0, or GZP_EXIT_DATA after
 * printing why to stderr (never the secret). */
int gzp_seed_standin_open(gzp_seed_standin_t *s, const gzp_datadir_t *d);
/* From fixed entropy (tests). 0 or -1. */
int gzp_seed_standin_from_entropy(gzp_seed_standin_t *s, const uint8_t entropy[32]);
/* The seed source over it. */
gzp_seed_source_t gzp_seed_standin_source(gzp_seed_standin_t *s);
void gzp_seed_standin_close(gzp_seed_standin_t *s);

#endif
