/* Deterministic random generator for tests and the simulator.
 *
 * ChaCha20 (RFC 8439) keyed from a 64-bit seed and a 64-bit stream number.
 * Same seed and stream, same bytes, on every machine. Never linked into the
 * core library and never to be used for real keys or nonces. */
#ifndef GAZPACHO_SIM_RNG_H
#define GAZPACHO_SIM_RNG_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t key[8];
    uint32_t nonce[3];
    uint32_t counter;      /* next block to generate */
    uint8_t block[64];     /* current block of output */
    size_t used;           /* bytes of `block` already handed out */
} sim_rng_t;

/* The ChaCha20 block function of RFC 8439 section 2.3. Exposed so the test can
 * check it against the RFC's vector. */
void sim_chacha20_block(const uint32_t key[8], uint32_t counter, const uint32_t nonce[3],
                        uint8_t out[64]);

/* Start a generator. Different `stream` values under one seed give
 * independent sequences (one per simulated node, one for the scheduler). */
void sim_rng_init(sim_rng_t *rng, uint64_t seed, uint64_t stream);

/* Write the next `len` bytes of the sequence to `out`. */
void sim_rng_fill(sim_rng_t *rng, uint8_t *out, size_t len);

/* The next 64 bits of the sequence. */
uint64_t sim_rng_u64(sim_rng_t *rng);

/* A uniform value in [0, bound). `bound` must be at least 1. */
uint64_t sim_rng_below(sim_rng_t *rng, uint64_t bound);

/* 1 with probability `per_mille` / 1000, else 0. Always draws one value, so a
 * run's later choices do not depend on which probabilities are zero. */
int sim_rng_chance(sim_rng_t *rng, uint32_t per_mille);

#endif
