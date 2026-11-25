/* Constant time of the signer's own code around secrets, under valgrind's
 * memcheck (as tests/signing/test_signing_ctime.c): the held key pairs are
 * marked undefined, so a branch or a memory index that depends on one is
 * reported. A library call's success and a finished signature are
 * declassified through the signer's GZ_SG_DECLASSIFY hook, and libsecp256k1
 * runs with SECP256K1_CONTEXT_DECLASSIFY, as in its own ctime test.
 *
 * Checked: the seed the seed source gives and the aux_rand the random port
 * gives are marked undefined, so the derivation (BIP 32 in wallet/src/bip32.c,
 * built here with its own declassify hook, and the signer's walk and key
 * pairs) and every signature run with secret-marked data (review B of #71,
 * M3). The host derives its key and its factory key, signs and refuses; a
 * member adds two slots, signs and refuses; slots are dropped and the signers
 * wiped. Each must report nothing.
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
    VALGRIND_MAKE_MEM_UNDEFINED(out, 64);   /* the seed is secret: derivation runs under the marks */
    return 1;
}

static void fill(void *c, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    (void)c; (void)purpose;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(0xa0 + i);
    VALGRIND_MAKE_MEM_UNDEFINED(out, len);  /* aux_rand is secret too (review B of #71, M3) */
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
    c.max_feerate = 1000;
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
    s.key_index = 1;

    gz_signer_t *h = make(ctx, GZ_SG_ROLE_HOST);
    CHECK(gz_sg_host_pub(h, pub) == GZ_SG_OK);            /* the host key, derived from the marked seed */
    CHECK(gz_sg_slot_add(h, &s, pub, NULL) == GZ_SG_OK);  /* and its factory key */
    VALGRIND_MAKE_MEM_UNDEFINED(&h->host_kp, sizeof h->host_kp);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, s.scope, 72, rec, sizeof rec, sig) == GZ_SG_OK);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, s.scope, 30, rec, sizeof rec, sig) == GZ_SG_OK);
    CHECK(gz_sg_sign_envelope(h, GZ_SG_KEY_HOST, s.scope, 22, rec, sizeof rec, sig) == GZ_SG_E_KIND);
    gz_sg_slot_drop(h, s.scope);
    gz_signer_wipe(h);
    free(h);

    gz_signer_t *m = make(ctx, GZ_SG_ROLE_MEMBER);
    CHECK(gz_sg_slot_add(m, &s, pub, NULL) == GZ_SG_OK);
    VALGRIND_MAKE_MEM_UNDEFINED(&m->slots[0].contribution_kp, sizeof m->slots[0].contribution_kp);
    CHECK(gz_sg_sign_envelope(m, GZ_SG_KEY_CONTRIBUTION, s.scope, 22, rec, sizeof rec, sig) == GZ_SG_OK);
    CHECK(gz_sg_sign_envelope(m, GZ_SG_KEY_CONTRIBUTION, s.scope, 30, rec, sizeof rec, sig) == GZ_SG_E_KIND);
    /* a second slot of the member: the pair overlap check under the marks */
    {
        gz_sg_slot_t s2 = s;
        s2.scope[0] ^= 1;
        s2.key_index = 2;
        CHECK(gz_sg_slot_add(m, &s2, pub, NULL) == GZ_SG_E_SLOT);
        s2.key_index = 3;
        CHECK(gz_sg_slot_add(m, &s2, pub, NULL) == GZ_SG_OK);
    }
    gz_sg_slot_drop(m, s.scope);
    gz_signer_wipe(m);
    free(m);

    secp256k1_context_destroy(ctx);
    return check_done();
}
