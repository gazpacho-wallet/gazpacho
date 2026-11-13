/* The simulator run: one host and 3 to 8 members under drops, duplicates,
 * reordering, broken connections and crashes (with unconfirmed saves lost),
 * checking safety invariants on every message that leaves a node, and, once
 * the faults stop, that the lobby starts with every member.
 *
 * usage: test_lobby_sim SEEDS [PROFILE]   profile 0 mixed, 1 crashes, 2 network, 3 none */
#include "../check.h"
#include "world.h"
#include "../../core/lobby/lobby_internal.h"

static unsigned long inv_fail, n_checks, n_starts, n_readies;

static void inv(int ok, const char *what, world_t *w)
{
    if (!ok) {
        if (inv_fail < 10) printf("INVARIANT %s at t=%llu\n", what, (unsigned long long)(w->now - W_T0));
        inv_fail++;
    }
}

/* Versions seen on the wire, and the freeze. */
static uint8_t seen_digest[16][32];
static int seen_version[16], n_seen;
static int frozen; static uint32_t frozen_v; static uint8_t frozen_d[32];
static uint8_t outer_digest[32];

static const w_rec_t *find_rec(const w_node_t *d, uint32_t type, const uint8_t *bytes, size_t n, size_t at)
{
    size_t k;
    for (k = 0; k < d->n_recs; k++) {
        const w_rec_t *r = &d->recs[k];
        if (r->type != type) continue;
        if (!bytes) return r;
        if (at + n <= r->n && memcmp(r->b + at, bytes, n) == 0) return r;
        if (type == GZ_REC_START_SENT) {           /* bytes anywhere in the record */
            size_t j;
            for (j = 0; j + n <= r->n; j++) if (memcmp(r->b + j, bytes, n) == 0) return r;
        }
    }
    return NULL;
}

static void on_wire(world_t *w, int from, int to, const uint8_t *b, size_t n)
{
    gz_lobby_msg_t m;
    w_node_t *d = &w->node[from];
    if (gz_lobby_decode(b, n, &m) != GZ_DEC_OK) return;
    n_checks++;
    switch (m.kind) {
    case GZ_KIND_TERMS_OFFER: {
        gz_lterms_outer_t o;
        gz_lterms_current_t c;
        uint8_t cd[32];
        int k;
        gz_lterms_outer_decode(m.outer, m.outer_len, &o);
        gz_lterms_current_decode(m.current, m.current_len, &o, outer_digest, &c);
        gz_lterms_current_digest(m.current, m.current_len, cd);
        for (k = 0; k < n_seen; k++)
            if (seen_version[k] == (int)c.version) inv(memcmp(seen_digest[k], cd, 32) == 0, "two values under one version", w);
        if (k == n_seen && n_seen < 16) { seen_version[n_seen] = (int)c.version; memcpy(seen_digest[n_seen++], cd, 32); }
        if (frozen) inv(c.version == frozen_v && memcmp(cd, frozen_d, 32) == 0, "a version after the freeze", w);
        /* the host holds what it offers: lobby_opened or current_signed */
        inv(find_rec(d, GZ_REC_LOBBY_OPENED, NULL, 0, 0) != NULL, "offer before lobby_opened", w);
        break;
    }
    case GZ_KIND_READY_CHECK:
        if (!frozen) { frozen = 1; frozen_v = m.version; memcpy(frozen_d, m.current_digest, 32); }
        inv(m.version == frozen_v && memcmp(m.current_digest, frozen_d, 32) == 0, "check at other values", w);
        {
            const w_rec_t *r = find_rec(d, GZ_REC_FREEZE, NULL, 0, 0);
            inv(r && gz_lw_get(r->b + 32, 4) == m.version && memcmp(r->b + 36, m.current_digest, 32) == 0,
                "check sent before the freeze was saved", w);
        }
        break;
    case GZ_KIND_START:
        n_starts++;
        inv(find_rec(d, GZ_REC_START_SENT, b, n, 0) != NULL, "start sent before start_sent was saved", w);
        inv(m.signers <= w->node[0].host->terms.target + 1 && m.signers >= 4, "signers out of bounds", w);
        break;
    case GZ_KIND_READY: {
        /* saved before it left, names values the member's conditions accept */
        const w_rec_t *r = find_rec(d, GZ_REC_READY_SENT, b, n, 0);
        size_t k;
        int ok = 0;
        n_readies++;
        inv(r != NULL && r->n == n, "ready sent before it was saved", w);
        inv(!d->mem->ended, "ready after the end", w);
        for (k = 0; k < d->n_recs; k++) {
            const w_rec_t *t = &d->recs[k];
            gz_lterms_outer_t o;
            gz_lterms_current_t c;
            const uint8_t *ob, *cb;
            size_t at = 0, on, cn;
            uint8_t term;
            int cls;
            if (t->type != GZ_REC_TERMS_RECEIVED) continue;
            gz_la_get_blob(t->b, t->n, &at, &ob, &on);
            at += 64;
            gz_la_get_blob(t->b, t->n, &at, &cb, &cn);
            if (!gz_lterms_outer_decode(ob, on, &o) || !gz_lterms_current_decode(cb, cn, &o, outer_digest, &c)) continue;
            if (c.version != m.version) continue;
            cls = gz_lterms_classify(&o, &c, &d->cond, &term);
            ok = m.has_check_id ? cls != GZ_FIT_NO : gz_lterms_ready_ok(cls, &d->cond);
        }
        inv(ok, "ready for values the member's conditions refuse, or not saved", w);
        break;
    }
    case GZ_KIND_JOIN:
        inv(find_rec(d, GZ_REC_JOINED, b, n, 0) != NULL, "join sent before it was saved", w);
        break;
    case GZ_KIND_LEAVE:
        inv(0, "an honest host made a member leave", w);
        break;
    default: break;
    }
    (void)to;
}

static int run(uint64_t seed, int profile, unsigned long *tot)
{
    static world_t w;
    int n = 3 + (int)(seed % 6), i, ok = 1;
    uint8_t cd2[32];
    w_init(&w, n, seed, NULL);
    w.on_wire = on_wire;
    gz_lterms_outer_digest(w.outer, w.outer_len, outer_digest);
    gz_lterms_current_digest(w.current, w.current_len, cd2);
    n_seen = 0; frozen = 0;
    if (profile == 0 || profile == 2) { w.drop_pm = 3; w.dup_pm = 20; w.reorder_pm = 20; w.cut_pm = 2; }
    if (profile == 0 || profile == 1) w.crash_pm = profile == 1 ? 6 : 2;
    w_start(&w);
    w_run(&w, 9000, 1);                               /* faults for 450 s */
    for (i = 1; i <= n; i++) w_link(&w, i, 0);         /* then every connection is made again */
    w_run(&w, 4500, 0);                               /* past the deadline and the window */
    tot[0] += w.drops; tot[1] += w.dups; tot[2] += w.reorders; tot[3] += w.crashes; tot[4] += w.cuts;
    if (w.failures) { printf("seed %llu: %lu engine failures\n", (unsigned long long)seed, w.failures); ok = 0; }
    /* Liveness. Below the target (n < 8) the start comes at the deadline, after
     * the faults: every member. At the target a check may come during the
     * faults and start with those who answered (messages.md 6.9): at least
     * the minimum. Either way every member in the host's set, and only those,
     * is handed over for that check, with the frozen digest. */
    if (w.node[0].host->state != GZ_LOBBY_SIGNING || w.node[0].n_handoffs != 1) {
        printf("seed %llu (n %d, profile %d): host state %d, handoffs %d\n", (unsigned long long)seed, n, profile,
               w.node[0].host->state, w.node[0].n_handoffs);
        ok = 0;
    } else {
        const w_handoff_t *hh = &w.node[0].handoffs[w.node[0].n_handoffs - 1];
        int want = n < 8 ? n + 1 : 0;
        if ((want ? hh->n_participants != want : hh->n_participants < 4) || memcmp(hh->digest, cd2, 32) != 0) {
            int k;
            printf("seed %llu: handoff set: %d handoffs, last has %d participants, digest %s; host seats",
                   (unsigned long long)seed, w.node[0].n_handoffs, hh->n_participants,
                   memcmp(hh->digest, cd2, 32) ? "other" : "T2");
            for (k = 0; k < w.node[0].host->n_seats; k++) printf(" %d", w.node[0].host->seats[k].state);
            for (k = 1; k <= n; k++)
                printf(" | m%d hand %d ended %d left %d", k, w.node[k].n_handoffs, w.node[k].mem->ended, w.node[k].mem->left);
            printf("\n");
            ok = 0;
        }
        /* the host's hand-off: itself first, each member's own factory key, every
         * binding valid, the build parameters of T1 for that many members */
        if (!w_params_ok(hh, hh->n_participants - 1) || hh->role != 1 || hh->min_members != 0 || hh->start_len != 0 ||
            hh->signers != hh->n_participants || memcmp(hh->participants[0], w.node[0].keys.key[1].pub, 33) != 0 ||
            memcmp(hh->factory[0], w.node[0].keys.key[3].pub, 33) != 0) {
            printf("seed %llu: host hand-off parameters\n", (unsigned long long)seed);
            ok = 0;
        }
        for (i = 1; i < hh->n_participants; i++) {
            int k, found = 0;
            for (k = 1; k <= n; k++)
                if (memcmp(hh->participants[i], w.node[k].keys.key[2].pub, 33) == 0)
                    found = memcmp(hh->factory[i], w.node[k].keys.key[3].pub, 33) == 0;
            if (!found) { printf("seed %llu: participant %d keys\n", (unsigned long long)seed, i); ok = 0; }
        }
        for (i = 1; i <= n; i++) {
            const w_node_t *d = &w.node[i];
            int k, got = 0, in_set = 0, other = 0;
            for (k = 0; k < d->n_handoffs; k++)
                if (!w_params_ok(&d->handoffs[k], d->handoffs[k].signers - 1) || d->handoffs[k].start_len == 0 ||
                    d->handoffs[k].min_members != d->cond.min_members || d->handoffs[k].n_participants != 0)
                    other = 1;
            for (k = 1; k < hh->n_participants; k++) in_set |= memcmp(hh->participants[k], d->keys.key[2].pub, 33) == 0;
            for (k = 0; k < d->n_handoffs; k++) {
                int same = memcmp(d->handoffs[k].check, hh->check, 32) == 0;
                if (d->handoffs[k].role == 1 && same && memcmp(d->handoffs[k].digest, cd2, 32) == 0 &&
                    d->handoffs[k].signers == hh->n_participants)
                    got = 1;
                if (!same || memcmp(d->handoffs[k].digest, cd2, 32) != 0) other = 1;
            }
            if (got != in_set || other) {
                printf("seed %llu: member %d handed over %d, in the set %d, other %d\n", (unsigned long long)seed, i,
                       got, in_set, other);
                ok = 0;
            }
        }
    }
    w_free(&w);
    return ok;
}

int main(int argc, char **argv)
{
    unsigned long seeds = argc > 1 ? strtoul(argv[1], NULL, 10) : 50, s, failed = 0, tot[5] = {0, 0, 0, 0, 0};
    int profile = argc > 2 ? atoi(argv[2]) : 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    for (s = 1; s <= seeds; s++) if (!run(s * 7919u + (unsigned long)profile, profile, tot)) failed++;
    printf("sim: profile %d, %lu seeds, %lu failed; %lu messages checked, %lu starts, %lu readies; "
           "faults: %lu drops, %lu duplicates, %lu reorders, %lu crashes, %lu cuts; %lu invariant failures\n",
           profile, seeds, failed, n_checks, n_starts, n_readies, tot[0], tot[1], tot[2], tot[3], tot[4], inv_fail);
    CHECK(failed == 0);
    CHECK(inv_fail == 0);
    CHECK(n_starts > 0 && n_readies > 0);
    /* the faults of the profile happened */
    if (profile == 0 || profile == 2) CHECK(tot[0] > 0 && tot[1] > 0 && tot[2] > 0 && tot[4] > 0);
    if (profile == 0 || profile == 1) CHECK(tot[3] > 0);
    return check_done();
}
