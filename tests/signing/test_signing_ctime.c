/* Constant time of the signing engine's own code around secrets (review A,
 * F8), under valgrind's memcheck: secrets are marked undefined, so a branch
 * or a memory index that depends on one is reported. As in libsecp256k1's
 * ctime test, a library call's success (which depends only on whether a key
 * is valid) is declassified, here through the engine's GZ_SIGN_DECLASSIFY
 * hook, and the library runs with SECP256K1_CONTEXT_DECLASSIFY.
 *
 * Checked: a member making a nonce (the secret randomness, the factory
 * secret and both keypairs' secret halves undefined), the host signing an
 * item with a live secret nonce (its k1, k2 and the factory keypair
 * undefined), and wipe_secrets. Each must report nothing.
 *
 * Without valgrind the marks do nothing and the test only runs the paths:
 * it is registered (as signing_ctime) to run under memcheck only. */
#include <valgrind/memcheck.h>
#define GZ_SIGN_DECLASSIFY(p, n) VALGRIND_MAKE_MEM_DEFINED(p, n)
#include "../../core/signing/signing.c"
#include "world.h"
#include "../check.h"
#include "harness.h"

static gz_sign_round_t *round_of(harness_t *h, uint32_t g)
{
    gz_sign_round_t *best = NULL;
    for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
        gz_sign_round_t *r = &h->p[g].e->rounds[k];
        if (r->state != GZ_SIGN_ROUND_FREE && (!best || r->seq > best->seq)) best = r;
    }
    return best;
}

static void (*g_fill_orig)(void *, gz_random_purpose_t, uint8_t *, size_t);
static void fill_secret_undefined(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    g_fill_orig(ctx, purpose, out, len);
    if (purpose == GZ_RANDOM_SECRET) VALGRIND_MAKE_MEM_UNDEFINED(out, len);
}

int main(void)
{
    harness_t h;
    static gz_sign_round_t scratch;
    uint8_t out[32];
    unsigned long before, after;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("  under valgrind: %s\n", RUNNING_ON_VALGRIND ? "yes" : "no (the marks do nothing)");
#ifdef SECP256K1_CONTEXT_DECLASSIFY
    secp256k1_context *dctx = secp256k1_context_create(SECP256K1_CONTEXT_DECLASSIFY);
#else
    secp256k1_context *dctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
#endif
    secp256k1_context_set_illegal_callback(dctx, on_illegal, NULL);
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    /* the host once every nonce is in: its own secret nonce still unused */
    while (h.nq && h_newest(&h, 0)->tier_state[0] != GZ_SIGN_TIER_SIGNED) h_deliver(&h, 0, 0);
    gz_sign_t *e0 = h.p[0].e;
    gz_sign_round_t *r0 = round_of(&h, 0);
    CHECK(r0 && r0->secnonce_serial[0]);
    if (r0 && r0->secnonce_serial[0]) {
        const secp256k1_context *saved = e0->cfg.ctx;
        e0->cfg.ctx = dctx;
        VALGRIND_MAKE_MEM_UNDEFINED(r0->secnonce[0].data + 4, 64);      /* k1, k2 (the magic and public key are public) */
        VALGRIND_MAKE_MEM_UNDEFINED(&e0->factory_kp, 32);              /* the keypair's secret half */
        before = VALGRIND_COUNT_ERRORS;
        int ok = sign_item(e0, r0, 0, out);
        VALGRIND_MAKE_MEM_DEFINED(out, 32);                            /* a partial signature is public */
        after = VALGRIND_COUNT_ERRORS;
        VALGRIND_MAKE_MEM_DEFINED(&e0->factory_kp, sizeof e0->factory_kp);
        e0->cfg.ctx = saved;
        printf("  sign_item: ok %d, reports %lu\n", ok, after - before);
        CHECK(ok && after == before);
    }
    /* a member's nonce: the secret port's bytes, the factory secret and both keypairs undefined */
    gz_sign_t *e1 = h.p[1].e;
    gz_sign_round_t *r1 = round_of(&h, 1);
    CHECK(r1 != NULL);
    if (r1) {
        scratch = *r1;
        int i = -1, s = -1;
        for (int k = 0; k < scratch.def.n_items && i < 0; k++)
            if ((s = pos_of(&scratch.def.items[k], scratch.me)) >= 0) i = k;
        CHECK(i >= 0);
        if (i >= 0) {
            scratch.have_nonce[i] &= ~bit((unsigned)s);
            scratch.secnonce_serial[i] = 0;
            const secp256k1_context *saved = e1->cfg.ctx;
            e1->cfg.ctx = dctx;
            g_fill_orig = e1->ports.random.fill;
            e1->ports.random.fill = fill_secret_undefined;
            VALGRIND_MAKE_MEM_UNDEFINED(e1->cfg.factory_secret, 32);
            VALGRIND_MAKE_MEM_UNDEFINED(&e1->factory_kp, 32);
            VALGRIND_MAKE_MEM_UNDEFINED(&e1->contribution_kp, 32);
            before = VALGRIND_COUNT_ERRORS;
            int ok = make_nonce(e1, &scratch, i);
            VALGRIND_MAKE_MEM_DEFINED(scratch.nonce[i][s], 66);           /* the public nonce and its signature are public */
            VALGRIND_MAKE_MEM_DEFINED(scratch.nonce_sig[i][s], 64);
            after = VALGRIND_COUNT_ERRORS;
            printf("  make_nonce: ok %d, reports %lu\n", ok, after - before);
            CHECK(ok && after == before);
            before = VALGRIND_COUNT_ERRORS;
            wipe_secrets(&scratch);
            after = VALGRIND_COUNT_ERRORS;
            printf("  wipe_secrets: reports %lu\n", after - before);
            CHECK(after == before);
            VALGRIND_MAKE_MEM_DEFINED(e1->cfg.factory_secret, 32);
            VALGRIND_MAKE_MEM_DEFINED(&e1->factory_kp, sizeof e1->factory_kp);
            VALGRIND_MAKE_MEM_DEFINED(&e1->contribution_kp, sizeof e1->contribution_kp);
            e1->ports.random.fill = g_fill_orig;
            e1->cfg.ctx = saved;
        }
    }
    h_free(&h);
    secp256k1_context_destroy(dctx);
    printf("  illegal-argument callbacks: %d\n", g_illegal);
    CHECK(g_illegal == 0);
    if (g_ctx) secp256k1_context_destroy(g_ctx);
    return check_done();
}
