/* Constant time of the signer's own code around secrets, under valgrind's
 * memcheck (as tests/signing/test_signing_ctime.c): the held key pairs are
 * marked undefined, so a branch or a memory index that depends on one is
 * reported. A library call's success and a finished signature are
 * declassified through the signer's GZ_SG_DECLASSIFY hook, and libsecp256k1
 * runs with SECP256K1_CONTEXT_DECLASSIFY, as in its own ctime test.
 *
 * Checked: the host signing an envelope (deterministic and fresh) with its
 * long-term key undefined; a member signing with its contribution key
 * undefined; a refusal after the key is held; dropping a slot and wiping the
 * signer with the keys still undefined. Each must report nothing.
 *
 * Without valgrind the marks do nothing and the test only runs the paths:
 * it is registered (as signer_ctime) to run under memcheck only. */
#include <valgrind/memcheck.h>
#define GZ_SG_DECLASSIFY(p, n) VALGRIND_MAKE_MEM_DEFINED(p, n)
#include "../signer.c"
#include "../../tests/check.h"

#include <stdio.h>
#include <stdlib.h>

static int seed_fn(void *c, uint8_t out[64])
{
    (void)c;
    for (int i = 0; i < 64; i++) out[i] = (uint8_t)i;
    return 1;
}

static void fill(void *c, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    (void)c; (void)purpose;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(0xa0 + i);
}

static gz_signer_t *make(secp256k1_context *ctx, gz_sg_role_t role)
{
    gz_sg_config_t c;
    gz_signer_t *sg = malloc(gz_signer_size());
    memset(&c, 0, sizeof c);
    c.secp = ctx;
    c.role = role;
    c.network = GZW_NET_SIGNET;
    c.epoch = 7;
    c.seed.seed = seed_fn;
    c.random.fill = fill;
    CHECK(sg && gz_signer_init(sg, gz_signer_size(), &c) == GZ_SG_OK);
    return sg;
}

int main(void)
{
    static const uint8_t rec[] = {0x02, 0x03, 0x61, 0x62, 0x63, 0x05, 0x01, 0xff};
    uint8_t pub[33], sig[64];
    gz_sg_slot_t s;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("  under valgrind: %s\n", RUNNING_ON_VALGRIND ? "yes" : "no (the marks do nothing)");
#ifdef SECP256K1_CONTEXT_DECLASSIFY
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_DECLASSIFY);
#else
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
#endif
    for (int i = 0; i < 32; i++) s.scope[i] = (uint8_t)(0x40 + i);
    s.epoch = 7;
    s.key_index = 4;

    gz_signer_t *h = make(ctx, GZ_SG_ROLE_HOST);
    CHECK(gz_sg_slot_add(h, &s, pub, NULL) == GZ_SG_OK);
    VALGRIND_MAKE_MEM_UNDEFINED(&h->host_kp, sizeof h->host_kp);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, s.scope, 72, rec, sizeof rec, 0, sig) == GZ_SG_OK);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, s.scope, 18, rec, sizeof rec, 1, sig) == GZ_SG_OK);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, s.scope, 22, rec, sizeof rec, 1, sig) == GZ_SG_E_KIND);
    gz_sg_slot_drop(h, s.scope);
    gz_signer_wipe(h);
    free(h);

    gz_signer_t *m = make(ctx, GZ_SG_ROLE_MEMBER);
    CHECK(gz_sg_slot_add(m, &s, pub, NULL) == GZ_SG_OK);
    VALGRIND_MAKE_MEM_UNDEFINED(&m->slots[0].contribution_kp, sizeof m->slots[0].contribution_kp);
    CHECK(gz_sg_sign_envelope(m, GZ_SG_KEY_CONTRIBUTION, s.scope, 22, rec, sizeof rec, 1, sig) == GZ_SG_OK);
    CHECK(gz_sg_sign_envelope(m, GZ_SG_KEY_CONTRIBUTION, s.scope, 78, rec, sizeof rec, 0, sig) == GZ_SG_E_KIND);
    gz_sg_slot_drop(m, s.scope);
    gz_signer_wipe(m);
    free(m);

    secp256k1_context_destroy(ctx);
    return check_done();
}
