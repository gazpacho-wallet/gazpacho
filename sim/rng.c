#include "rng.h"
#include <string.h>

static uint32_t rotl(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

static void quarter_round(uint32_t s[16], int a, int b, int c, int d)
{
    s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 16);
    s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 12);
    s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 8);
    s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 7);
}

void sim_chacha20_block(const uint32_t key[8], uint32_t counter, const uint32_t nonce[3],
                        uint8_t out[64])
{
    uint32_t init[16] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
    uint32_t s[16];
    memcpy(init + 4, key, 8 * sizeof(uint32_t));
    init[12] = counter;
    memcpy(init + 13, nonce, 3 * sizeof(uint32_t));
    memcpy(s, init, sizeof s);
    for (int round = 0; round < 10; round++) {
        quarter_round(s, 0, 4, 8, 12);
        quarter_round(s, 1, 5, 9, 13);
        quarter_round(s, 2, 6, 10, 14);
        quarter_round(s, 3, 7, 11, 15);
        quarter_round(s, 0, 5, 10, 15);
        quarter_round(s, 1, 6, 11, 12);
        quarter_round(s, 2, 7, 8, 13);
        quarter_round(s, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = s[i] + init[i];
        out[4 * i]     = (uint8_t)v;
        out[4 * i + 1] = (uint8_t)(v >> 8);
        out[4 * i + 2] = (uint8_t)(v >> 16);
        out[4 * i + 3] = (uint8_t)(v >> 24);
    }
}

void sim_rng_init(sim_rng_t *rng, uint64_t seed, uint64_t stream)
{
    memset(rng, 0, sizeof *rng);
    rng->key[0] = (uint32_t)seed;
    rng->key[1] = (uint32_t)(seed >> 32);
    rng->key[2] = (uint32_t)stream;
    rng->key[3] = (uint32_t)(stream >> 32);
    rng->used = sizeof rng->block;   /* nothing generated yet */
}

void sim_rng_fill(sim_rng_t *rng, uint8_t *out, size_t len)
{
    while (len > 0) {
        if (rng->used == sizeof rng->block) {
            sim_chacha20_block(rng->key, rng->counter++, rng->nonce, rng->block);
            rng->used = 0;
        }
        size_t take = sizeof rng->block - rng->used;
        if (take > len) take = len;
        memcpy(out, rng->block + rng->used, take);
        rng->used += take;
        out += take;
        len -= take;
    }
}

uint64_t sim_rng_u64(sim_rng_t *rng)
{
    uint8_t b[8];
    uint64_t v = 0;
    sim_rng_fill(rng, b, sizeof b);
    for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i);
    return v;
}

uint64_t sim_rng_below(sim_rng_t *rng, uint64_t bound)
{
    /* Reject the short top range so every value is equally likely. */
    uint64_t limit = UINT64_MAX - UINT64_MAX % bound;
    uint64_t v;
    do { v = sim_rng_u64(rng); } while (v >= limit);
    return v % bound;
}

int sim_rng_chance(sim_rng_t *rng, uint32_t per_mille)
{
    return sim_rng_below(rng, 1000) < per_mille;
}
