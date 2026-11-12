/* Tests for the simulator's deterministic generator (sim/rng.c). */
#include "rng.h"
#include "../check.h"
#include <string.h>

/* RFC 8439 section 2.3.2: the ChaCha20 block function test vector. */
static void test_rfc8439_block(void)
{
    static const uint8_t want[64] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };
    uint32_t key[8];
    const uint32_t nonce[3] = {0x09000000u, 0x4a000000u, 0x00000000u};
    uint8_t out[64];
    for (uint32_t i = 0; i < 8; i++)
        key[i] = (4 * i) | (4 * i + 1) << 8 | (4 * i + 2) << 16 | (4 * i + 3) << 24;
    sim_chacha20_block(key, 1, nonce, out);
    CHECK(memcmp(out, want, 64) == 0);
}

static void test_same_seed_same_bytes(void)
{
    sim_rng_t a, b;
    uint8_t x[300], y[300];
    sim_rng_init(&a, 12345, 7);
    sim_rng_init(&b, 12345, 7);
    sim_rng_fill(&a, x, sizeof x);
    /* The same sequence however it is cut up. */
    sim_rng_fill(&b, y, 1);
    sim_rng_fill(&b, y + 1, 63);
    sim_rng_fill(&b, y + 64, 0);
    sim_rng_fill(&b, y + 64, 100);
    sim_rng_fill(&b, y + 164, 136);
    CHECK(memcmp(x, y, sizeof x) == 0);
    CHECK(sim_rng_u64(&a) == sim_rng_u64(&b));
}

static void test_seeds_and_streams_differ(void)
{
    sim_rng_t a, b, c;
    uint8_t x[64], y[64], z[64];
    sim_rng_init(&a, 1, 0);
    sim_rng_init(&b, 2, 0);
    sim_rng_init(&c, 1, 1);
    sim_rng_fill(&a, x, 64); sim_rng_fill(&b, y, 64); sim_rng_fill(&c, z, 64);
    CHECK(memcmp(x, y, 64) != 0);
    CHECK(memcmp(x, z, 64) != 0);
    CHECK(memcmp(y, z, 64) != 0);
}

static void test_below_and_chance(void)
{
    sim_rng_t r;
    unsigned counts[7] = {0};
    int in_range = 1, never = 0, always = 0, half = 0;
    sim_rng_init(&r, 99, 0);
    for (int i = 0; i < 70000; i++) {
        uint64_t v = sim_rng_below(&r, 7);
        in_range &= v < 7;
        if (v < 7) counts[v]++;
    }
    CHECK(in_range);
    for (int i = 0; i < 7; i++) CHECK(counts[i] > 9500 && counts[i] < 10500);
    CHECK(sim_rng_below(&r, 1) == 0);
    for (int i = 0; i < 10000; i++) {
        never += sim_rng_chance(&r, 0);
        always += sim_rng_chance(&r, 1000);
        half += sim_rng_chance(&r, 500);
    }
    CHECK(never == 0 && always == 10000);
    CHECK(half > 4700 && half < 5300);
}

int main(void)
{
    test_rfc8439_block();
    test_same_seed_same_bytes();
    test_seeds_and_streams_differ();
    test_below_and_chance();
    return check_done();
}
