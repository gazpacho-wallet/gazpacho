/* Audit e2e, H1 (two trees on one funding outpoint), the auditor's own scenario, kept as the
 * regression test: a host signs two proposals of one check and attempt, on one funding outpoint, whose
 * trees differ (end heights a block apart), and both reach member 1 while the first is in its nonce
 * step. Two harness worlds share the fixed keys, so world 2's host stands in for the same host. The
 * member must hold one round on the outpoint, refuse the second proposal with reason 11 (C7) and never
 * sign the second tree. Exit status 1 if two trees are signed on the outpoint or the abort is not
 * reason 11. */
/* audit: two proposals for one (check, attempt) on one funding outpoint, with
 * different trees, both held in their nonce step at one member. Does the
 * member release partial signatures for both (C7: one tree per funding
 * output, ever)? Built inside tests/signing so that it reuses the harness. */
int test_signing_main_unused(int argc, char **argv);
#define main test_signing_main_unused
#include "test_signing.c"
#undef main

typedef struct { uint32_t from, to; size_t len; uint8_t *b; } aud_msg_t;

static aud_msg_t aud_take(harness_t *h, long i)
{
    aud_msg_t m = {h->q[i].from, h->q[i].to, h->q[i].len, malloc(h->q[i].len)};
    memcpy(m.b, h->q[i].b, m.len);
    h_drop_msg(h, (size_t)i);
    return m;
}

static long aud_last_kind(const harness_t *h, uint32_t from, uint32_t to, uint8_t kind)
{
    long r = -1;
    for (size_t i = 0; i < h->nq; i++)
        if (h->q[i].from == from && h->q[i].to == to && h_kind_of(h->q[i].b, h->q[i].len) == kind) r = (long)i;
    return r;
}

static int aud_active_on(const gz_sign_t *e, const uint8_t txid[32], uint32_t vout)
{
    int n = 0;
    for (int i = 0; i < GZ_SIGN_MAX_ROUNDS; i++)
        if (e->rounds[i].state == GZ_SIGN_ROUND_ACTIVE && !memcmp(e->rounds[i].def.funding_txid, txid, 32) &&
            e->rounds[i].def.funding_vout == vout) n++;
    return n;
}

int main(void)
{
    static harness_t h, h2;
    aud_msg_t propB, nB, all[16];
    size_t n_all = 0;
    long i;
    setvbuf(stdout, NULL, _IONBF, 0);
    h_init(&h, 3);
    h_init(&h2, 3);
    h.p[0].e->cfg.retry = NULL;
    h2.p[0].e->cfg.retry = NULL;
    /* A: the honest attempt, tree T1, on outpoint O (WF_SAME_TREE: every attempt on one outpoint). */
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    /* B: the same host key (the worlds' keys are fixed), the same check and attempt 1, the same outpoint,
     * another tree T2 (the last leaf's version changed): a second proposal the host signs. */
    h2.builder.mutate = other_tree;
    CHECK(h_begin(&h2, 1, 3, WF_SAME_TREE) == GZ_OK);
    const gz_sign_round_t *ra = h_newest(&h, 0), *rb = h_newest(&h2, 0);
    CHECK(ra && rb);
    printf("A id %02x%02x.. B id %02x%02x..; same outpoint: %d; same tree digest: %d; same check: %d attempts %u %u\n",
           ra->id[0], ra->id[1], rb->id[0], rb->id[1],
           !memcmp(ra->def.funding_txid, rb->def.funding_txid, 32) && ra->def.funding_vout == rb->def.funding_vout,
           !memcmp(ra->def.tree_digest, rb->def.tree_digest, 32), !memcmp(ra->check_id, rb->check_id, 32),
           (unsigned)ra->attempt, (unsigned)rb->attempt);
    i = q_find(&h2, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(i >= 0);
    propB = aud_take(&h2, i);
    /* Member 1 gets A, then B. */
    i = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(i >= 0);
    h_deliver(&h, (size_t)i, 0);
    h.builder.mutate = other_tree;               /* member 1 builds T2 from B's parameters, as the host did */
    h_inject(&h, 0, 1, propB.b, propB.len);
    h.builder.mutate = NULL;
    printf("member 1 rounds Active on O after both proposals: %d (exposures %zu)\n",
           aud_active_on(h.p[1].e, ra->def.funding_txid, ra->def.funding_vout), h.p[1].e->n_exposures);
    long ab = aud_last_kind(&h, 1, 0, GZ_SIGN_MSG_ABORT);
    int reason_ok = 0;
    if (ab >= 0) {
        gz_sign_msg_t am;
        reason_ok = gz_sign_decode(h.q[ab].b, h.q[ab].len, &am) && am.reason == gz_sign_reason(GZ_SIGN_WHY_OTHER_TREE, 0);
    }
    printf("member 1 abort reason 11: %s\n", reason_ok ? "yes" : "no");
    printf("member 1 abort queued to host: %s\n", ab >= 0 ? "yes" : "no");
    /* B's nonces from member 1 go to B's host. */
    i = aud_last_kind(&h, 1, 0, GZ_SIGN_MSG_NONCES);
    CHECK(i >= 0);
    nB = aud_take(&h, i);
    h_inject(&h2, 1, 0, nB.b, nB.len);
    /* B runs in h2 with its members 2 and 3; whatever goes to party 1 is held. */
    while (h2.nq) {
        if (h2.q[0].to == 1) { if (n_all < 16) all[n_all++] = aud_take(&h2, 0); else h_drop_msg(&h2, 0); }
        else h_deliver(&h2, 0, 0);
    }
    /* A completes in h: member 1 releases its partial signatures for T1. */
    h_flush(&h, 100000);
    printf("after A: host A state %d, member 1 exposures %zu\n", (int)h_find(&h, 0, ra->id)->state, h.p[1].e->n_exposures);
    /* Now B's nonce sets reach member 1. */
    size_t sent_before = h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS);
    for (size_t k = 0; k < n_all; k++)
        if (h_kind_of(all[k].b, all[k].len) == GZ_SIGN_MSG_ALL_NONCES) h_inject(&h, 0, 1, all[k].b, all[k].len);
    size_t sent_after = h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS);
    const gz_sign_t *e1 = h.p[1].e;
    int two_trees = 0;
    for (size_t a = 0; a < e1->n_exposures; a++)
        for (size_t b = a + 1; b < e1->n_exposures; b++)
            if (!memcmp(e1->exposures[a].funding.txid, e1->exposures[b].funding.txid, 32) &&
                e1->exposures[a].funding.vout == e1->exposures[b].funding.vout &&
                memcmp(e1->exposures[a].tree_digest, e1->exposures[b].tree_digest, 32)) two_trees = 1;
    printf("member 1 partial-signature messages sent for B: %zu; exposures %zu; two trees on one outpoint: %s\n",
           sent_after - sent_before, e1->n_exposures, two_trees ? "YES (C7 broken)" : "no");
    printf("RESULT %s\n", two_trees ? "C7-VIOLATED" : "C7-HELD");
    return two_trees || !reason_ok ? 1 : 0;
}
