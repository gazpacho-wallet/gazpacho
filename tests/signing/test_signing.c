/* Tests of the signing round engine (core/signing), mostly in the simulator.
 *
 * usage: test_signing [SECTION] [quick|tiny]
 *   SECTION   run one section only (blocks, decoders, golden, model, faults,
 *             honest, t1, crashes, restores); CTest registers each on its own
 *   quick     a smaller set (for mutants)
 *   tiny      smaller still, every section's paths kept (for valgrind)
 *
 * Every run checks, after every step: no secret nonce value is ever held
 * twice and none outlives its round or tier (judged on the secret bytes);
 * the library's illegal-argument callback never fires; a member round that
 * ever sent a partial signature is never Aborted; and, unless a test says
 * otherwise, no party sends two different contributions under one
 * (round, item). */
#include "world.h"
#include "../check.h"
#include "scenarios.h"
#include "model.h"
#include "decoders.h"

static int g_quick;
/* The digest of fixed-generator outputs (test_definitions). After an intended
 * change: run "test_signing known", check, update. */
#define KNOWN_ANSWERS 0x5c8c45744e0a3f63ull

typedef struct {
    int done;                   /* the host's newest round has every ack */
    int members_complete;       /* members of that round holding it complete, same held set */
    int members_in_round;
    uint32_t attempts;
    uint64_t counters_host[8];
    uint64_t blame_fault, blame_silent;
    const gz_sign_round_t *first_failed;
} outcome_t;

static int w_states_ok(const sim_t *sim, void *ctx, const char **why)
{
    world_t *w = ctx;
    (void)sim;
    for (int n = 1; n < W_MAX_NODES; n++) {
        if (!w->nodes[n]) continue;
        for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
            const gz_sign_round_t *r = &w->nodes[n]->eng.rounds[k];
            if (r->state == GZ_SIGN_ROUND_ABORTED && r->ever_partial) { *why = "a member round that sent a partial signature was Aborted"; return 0; }
        }
    }
    return 1;
}

static sim_t *start_sim(world_t *w, sim_config_t *c, int contrib_check)
{
    sim_t *sim = sim_create(c);
    sim_add_invariant(sim, w_secrets_ok, w);
    sim_add_invariant(sim, w_states_ok, w);
    if (contrib_check) sim_add_invariant(sim, w_contrib_ok, w);
    return sim;
}

static void dump(const world_t *w)
{
    for (int n = 0; n < W_MAX_NODES; n++) {
        if (!w->nodes[n]) continue;
        const gz_sign_t *e = &w->nodes[n]->eng;
        printf("    node %d attempts %u:", n, e->attempts);
        for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
            const gz_sign_round_t *r = &e->rounds[k];
            if (r->state == GZ_SIGN_ROUND_FREE) continue;
            printf(" [seq %u id %02x st %u t %u ts %u%u why %u bl %x ep %u ack %x]", r->seq, r->id[0], r->state, r->tier,
                   r->tier_state[0], r->tier_state[1], r->why, r->blamed, r->ever_partial, r->acked);
        }
        printf("\n");
    }
}

/* Begin, run, quiesce, settle; report. */
static outcome_t drive(world_t *w, sim_t *sim, uint32_t members, uint8_t tiers, uint8_t flags, uint64_t steps)
{
    outcome_t o;
    uint8_t p[W_PARAMS];
    memset(&o, 0, sizeof o);
    w_params(p, tiers, 1, w_mask(members), flags);
    sim_user_command(sim, 0, p, sizeof p);
    /* Faults on for `steps`, then a quiet tail; either part ends once the host holds every ack. */
    for (int quiet = 0; quiet < 2; quiet++) {
        for (uint64_t s = 0; s < (quiet ? 3000 : steps) && !sim_failed(sim); s++) {
            sim_step(sim);
            const gz_sign_round_t *r = w->nodes[0] ? gz_sign_latest(&w->nodes[0]->eng) : NULL;
            if (w->nodes[0] && !r && s % 20 == 19) sim_user_command(sim, 0, p, sizeof p);
            if (r && r->state == GZ_SIGN_ROUND_DONE) break;
        }
        if (!quiet) sim_quiesce(sim);
    }
    if (sim_failed(sim)) printf("  sim failed at step %llu: %s\n", (unsigned long long)sim_failure_step(sim), sim_failure_reason(sim));
    const gz_sign_t *h = w->nodes[0] ? &w->nodes[0]->eng : NULL;
    const gz_sign_round_t *r = h ? gz_sign_latest(h) : NULL;
    if (!h || !r) return o;
    o.attempts = h->attempts;
    memcpy(o.counters_host, h->counters, sizeof o.counters_host);
    o.blame_fault = h->counters[GZ_SIGN_COUNT_BLAME_FAULT];
    o.blame_silent = h->counters[GZ_SIGN_COUNT_BLAME_SILENT];
    for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++)
        if (h->rounds[k].state == GZ_SIGN_ROUND_FAILED && (!o.first_failed || h->rounds[k].seq < o.first_failed->seq))
            o.first_failed = &h->rounds[k];
    o.done = r->state == GZ_SIGN_ROUND_DONE;
    if (!o.done && getenv("GZ_TRACE")) {
        size_t tl;
        const char *t = sim_trace(sim, &tl);
        FILE *fp = fopen(getenv("GZ_TRACE"), "wx");
        if (fp) { fwrite(t, 1, tl, fp); fclose(fp); }
    }
    o.members_in_round = r->def.n_participants - 1;
    for (int j = 1; j < r->def.n_participants; j++) {
        w_node_t *n = w->nodes[r->def.participants[j].peer];
        if (!n) continue;
        for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
            const gz_sign_round_t *mr = &n->eng.rounds[k];
            if (mr->state == GZ_SIGN_ROUND_COMPLETE && memcmp(mr->id, r->id, 32) == 0 &&
                memcmp(mr->final_sig, r->final_sig, sizeof r->final_sig) == 0) o.members_complete++;
        }
    }
    return o;
}

static void world_reset(world_t *w)
{
    free(w->seen); free(w->contrib);
    w_builder_t keep = w->builder;
    int attempts = w->max_attempts;
    memset(w, 0, sizeof *w);
    w->builder = keep;
    w->max_attempts = attempts;
}

/* ---- 1. building blocks ---- */

static void hex(const char *h, uint8_t *out) { for (size_t i = 0; h[2 * i]; i++) sscanf(h + 2 * i, "%2hhx", &out[i]); }

static void test_blocks(void)
{
    static const struct { const char *in, *out; } v[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"}};
    for (size_t i = 0; i < 3; i++) {
        uint8_t got[32], want[32];
        gz_sign_sha256_t s;
        gz_sign_sha256_init(&s);
        gz_sign_sha256_write(&s, (const uint8_t *)v[i].in, strlen(v[i].in));
        gz_sign_sha256_done(&s, got);
        hex(v[i].out, want);
        CHECK(memcmp(got, want, 32) == 0);
    }
    /* A tree's transactions parse; damaged ones do not. */
    gz_sign_def_t d;
    factory_t *f = NULL;
    uint8_t p[W_PARAMS];
    gz_sign_tx_t tx;
    w_params(p, 1, 1, w_mask(3), 0);
    CHECK(w_build_tree(p, W_PARAMS, &d, &f) && f);
    const gz_sign_item_t *it = &d.items[0];
    CHECK(gz_sign_tx_parse(it->tx, it->tx_len, &tx) && !tx.witness_item);
    CHECK(!gz_sign_tx_parse(it->tx, it->tx_len - 1, &tx));
    uint8_t bad[GZ_SIGN_MAX_TX + 8];
    memcpy(bad, it->tx, it->tx_len); bad[it->tx_len] = 0;
    CHECK(!gz_sign_tx_parse(bad, it->tx_len + 1u, &tx));                 /* trailing byte */
    memcpy(bad, it->tx, it->tx_len); bad[4] = 2;
    CHECK(!gz_sign_tx_parse(bad, it->tx_len, &tx));                      /* two inputs */
    memcpy(bad, it->tx, it->tx_len); bad[41] = 0xfd;
    CHECK(!gz_sign_tx_parse(bad, it->tx_len, &tx));                      /* a non-minimal or overlong script length */
    factory_free(f); free(f);
}

/* ---- 2. honest rounds under every network fault ---- */

static void test_honest(void)
{
    static const uint32_t sizes[] = {3, 4, 8};
    world_t w;
    memset(&w, 0, sizeof w);
    for (size_t z = 0; z < 3; z++)
        for (int profile = 0; profile < 6; profile++)
            for (uint8_t tiers = 1; tiers <= 2; tiers++) {
                if (g_quick && (sizes[z] == 8 || profile % 2)) continue;
                if (g_quick > 1 && (z > 0 || (profile != 0 && profile != 5))) continue;
                world_reset(&w);
                sim_config_t c = w_config(&w, 1000u * sizes[z] + 10u * (uint32_t)profile + tiers, sizes[z]);
                if (profile == 1 || profile == 5) c.drop_pm = 150;
                if (profile == 2 || profile == 5) c.duplicate_pm = 500;
                if (profile == 3 || profile == 5) { c.delay_pm = 500; c.max_delay_steps = 8; }
                if (profile == 4 || profile == 5) c.reorder_pm = 600;
                if (profile == 5) { c.save_delay_pm = 300; c.max_save_delay_steps = 3; c.confirm_delay_pm = 300; c.max_confirm_delay_steps = 3; }
                sim_t *sim = start_sim(&w, &c, 1);
                outcome_t o = drive(&w, sim, sizes[z], tiers, 0, 1500);
                const sim_stats_t *st = sim_stats(sim);
                int fault_seen = profile == 0 || (profile == 1 && st->messages_dropped) ||
                                 (profile == 2 && st->messages_duplicated) || (profile == 3 && st->messages_delayed) ||
                                 (profile == 4 && st->deliveries_reordered) ||
                                 (profile == 5 && st->messages_dropped && st->messages_duplicated && st->messages_delayed);
                if (!o.done || o.members_complete != (int)sizes[z] || !fault_seen)
                    printf("  honest: members %u profile %d tiers %u: done %d complete %d/%d attempts %u fault-seen %d\n",
                           sizes[z], profile, tiers, o.done, o.members_complete, (int)sizes[z], o.attempts, fault_seen);
                if (!o.done || o.members_complete != (int)sizes[z]) dump(&w);
                CHECK(!sim_failed(sim));
                CHECK(o.done && o.members_complete == (int)sizes[z]);
                CHECK(fault_seen);
                CHECK(o.blame_fault == 0);
                CHECK(w.secrets_checked > 0 && w.zero_checks > 0);
                CHECK(o.counters_host[GZ_SIGN_COUNT_PSIGS_VERIFIED] > 0 && o.counters_host[GZ_SIGN_COUNT_FINALS_VERIFIED] > 0);
                sim_destroy(sim);
            }
    world_reset(&w);
}

/* The engine's signed transactions, checked by the imported verifier with its
 * own signature hash and tweaked keys: an independent opinion. */
static void test_import_agrees(void)
{
    world_t w;
    memset(&w, 0, sizeof w);
    sim_config_t c = w_config(&w, 77, 4);
    sim_t *sim = start_sim(&w, &c, 1);
    outcome_t o = drive(&w, sim, 4, 1, 0, 400);
    CHECK(o.done);
    const gz_sign_round_t *r = gz_sign_latest(&w.nodes[0]->eng);
    if (!r) { sim_destroy(sim); world_reset(&w); return; }
    gz_sign_def_t d;
    factory_t *f = NULL;
    uint8_t p[W_PARAMS];
    w_params(p, 1, o.attempts, w_mask(4), 0);
    CHECK(memcmp(r->params, p, W_PARAMS) == 0 && w_build_tree(p, W_PARAMS, &d, &f));
    for (size_t i = 0; f && i < f->n_nodes; i++) {
        uint8_t tx[GZ_SIGN_MAX_TX + 80];
        size_t n = gz_sign_tx_attach(d.items[i].tx, d.items[i].tx_len, r->final_sig[i], tx, sizeof tx);
        tx_buf_reset(&f->nodes[i].signed_tx);   /* the builder allocated it */
        tx_buf_write_bytes(&f->nodes[i].signed_tx, tx, n);
        f->nodes[i].is_signed = 1;
    }
    CHECK(f && factory_verify_all(f) == 1);
    if (f) {
        f->nodes[f->n_nodes - 1].signed_tx.data[f->nodes[f->n_nodes - 1].signed_tx.len - 10] ^= 1;
        CHECK(factory_verify_all(f) == 0);                          /* the control: a damaged one is refused */
        factory_free(f); free(f);
    }
    sim_destroy(sim);
    world_reset(&w);
}

/* ---- 2b. T1's shape at its smallest and largest ----
 * terms.md T7: level arity [3] up to 4 members, [4, 3] above, every interior
 * level fixed, one-member pseudo-Spilman leaves. At 16 members the round has
 * 17 participants (the bit masks' seventeenth position is used by the root)
 * and 45 items (docs/notes/slice1-attempt.md, mismatch 7). The result is
 * checked again by the imported verifier. */
static void test_t1(void)
{
    static const struct { uint32_t members; uint16_t items; } t[] = {{3, 8}, {16, 45}};
    world_t w;
    memset(&w, 0, sizeof w);
    for (size_t z = 0; z < 2; z++) {
        uint32_t m = t[z].members;
        world_reset(&w);
        sim_config_t c = w_config(&w, 31000 + m, m);
        if (!g_quick) { c.drop_pm = 30; c.duplicate_pm = 100; c.reorder_pm = 200; }
        sim_t *sim = start_sim(&w, &c, 1);
        outcome_t o = drive(&w, sim, m, 1, WF_T1, 6000);
        const gz_sign_round_t *r = w.nodes[0] ? gz_sign_latest(&w.nodes[0]->eng) : NULL;
        if (!o.done || o.members_complete != (int)m) {
            printf("  t1: members %u: done %d complete %d attempts %u\n", m, o.done, o.members_complete, o.attempts);
            dump(&w);
        }
        CHECK(!sim_failed(sim));
        CHECK(o.done && o.members_complete == (int)m);
        CHECK(o.blame_fault == 0);
        CHECK(r && r->def.n_participants == m + 1 && r->def.n_items == t[z].items);
        CHECK(r && r->def.items[0].n_signers == m + 1 && r->have_psig[0] == (m + 1 >= 32 ? 0xffffffffu : (1u << (m + 1)) - 1u));
        CHECK(r && r->acked == ((((uint32_t)1u << (m + 1)) - 1u) & ~1u));
        if (r) {
            gz_sign_def_t d;
            factory_t *f = NULL;
            uint8_t p[W_PARAMS];
            w_params(p, 1, o.attempts, w_mask(m), WF_T1);
            CHECK(memcmp(r->params, p, W_PARAMS) == 0 && w_build_tree(p, W_PARAMS, &d, &f));
            for (size_t i = 0; f && i < f->n_nodes; i++) {
                uint8_t tx[GZ_SIGN_MAX_TX + 80];
                size_t n = gz_sign_tx_attach(d.items[i].tx, d.items[i].tx_len, r->final_sig[i], tx, sizeof tx);
                tx_buf_reset(&f->nodes[i].signed_tx);
                tx_buf_write_bytes(&f->nodes[i].signed_tx, tx, n);
                f->nodes[i].is_signed = 1;
            }
            CHECK(f && factory_verify_all(f) == 1);
            size_t ps_leaves = 0;
            for (size_t i = 0; f && i < f->n_nodes; i++)
                if (f->nodes[i].is_ps_leaf) { ps_leaves++; CHECK(f->nodes[i].n_signers == 2); }
            CHECK(ps_leaves == m);                       /* one one-member pseudo-Spilman leaf per member */
            if (f) { factory_free(f); free(f); }
        }
        sim_destroy(sim);
    }
    world_reset(&w);
}

/* ---- 3. a crash of each party at each step, with a replayed proposal ---- */

static void test_crashes(void)
{
    world_t w;
    memset(&w, 0, sizeof w);
    uint64_t crashed = 0, runs = 0, replays = 0;
    for (uint32_t node = 0; node <= 3; node++)
        for (uint32_t k = 0; k < (g_quick > 1 ? 12u : g_quick ? 24u : 60u); k += g_quick > 1 ? 4u : g_quick ? 3u : 1u) {
            world_reset(&w);
            sim_config_t c = w_config(&w, 5000 + node * 100 + k, 3);
            sim_t *sim = start_sim(&w, &c, 1);
            sim_crash_after_releases(sim, node, k);
            uint8_t p[W_PARAMS];
            w_params(p, 2, 1, w_mask(3), 0);
            sim_user_command(sim, 0, p, sizeof p);
            for (int s = 0; s < 40; s++) sim_step(sim);
            if (node && w.first_proposal_len) {                    /* the proposal again, after the restart */
                sim_send_message(sim, 0, node, w.first_proposal, w.first_proposal_len);
                replays++;
            }
            outcome_t o = drive(&w, sim, 3, 2, 0, 300);
            for (uint32_t m = 1; m <= 3 && w.first_proposal_len; m++)   /* and once more to everyone at the end */
                sim_send_message(sim, 0, m, w.first_proposal, w.first_proposal_len);
            for (int s = 0; s < 30; s++) sim_step(sim);
            crashed += sim_stats(sim)->crashes_in_release;
            runs++;
            if (!o.done || o.members_complete != 3) printf("  crash node %u at release %u: done %d complete %d attempts %u\n", node, k, o.done, o.members_complete, o.attempts);
            CHECK(!sim_failed(sim));
            CHECK(o.done && o.members_complete == 3);
            CHECK(o.blame_fault == 0);
            sim_destroy(sim);
        }
    printf("  crashes: %llu runs, %llu crashes inside releases, %llu replayed proposals\n",
           (unsigned long long)runs, (unsigned long long)crashed, (unsigned long long)replays);
    CHECK(crashed >= runs * 3 / 4);                                 /* the fault happened in most runs */
    world_reset(&w);
}

/* ---- 4. restore from an old backup with repeating randomness ---- */

static void test_restores(void)
{
    world_t w;
    memset(&w, 0, sizeof w);
    uint64_t repeated_draws = 0, runs = 0, second = 0, restores = 0;
    for (uint32_t node = 0; node <= 3; node++)
        for (uint32_t when = 6; when < (g_quick > 1 ? 12u : g_quick ? 20u : 40u); when += 3)
            for (size_t keep = 0; keep < 4; keep++) {
                if (g_quick > 1 && (node > 1 || keep > 1)) continue;
                world_reset(&w);
                sim_config_t c = w_config(&w, 9000 + node * 1000 + when * 10 + keep, 3);
                c.restore_repeats_random = 1;
                sim_t *sim = start_sim(&w, &c, 0);
                uint8_t p[W_PARAMS];
                w_params(p, 1, 1, w_mask(3), 0);
                sim_user_command(sim, 0, p, sizeof p);
                for (uint32_t s = 0; s < when; s++) sim_step(sim);
                size_t have = sim_storage_count(sim_node_storage(sim, node));
                sim_restore_backup(sim, node, keep < have ? keep : have ? have - 1 : 0);
                restores++;
                if (w.first_proposal_len && node) sim_send_message(sim, 0, node, w.first_proposal, w.first_proposal_len);
                outcome_t o = drive(&w, sim, 3, 1, 0, 300);
                /* Did the port really repeat? Two secret draws with the same bytes. */
                size_t nd = sim_node_draw_count(sim, node);
                for (size_t i = 0; i < nd; i++)
                    for (size_t j = i + 1; j < nd; j++) {
                        const sim_draw_t *a = sim_node_draw(sim, node, i), *b = sim_node_draw(sim, node, j);
                        if (a->purpose == GZ_RANDOM_SECRET && b->purpose == GZ_RANDOM_SECRET && a->incarnation != b->incarnation &&
                            memcmp(a->bytes, b->bytes, 32) == 0) repeated_draws++;
                    }
                second += w.second_contributions;
                runs++;
                if (!o.done) { printf("  restore node %u at %u keep %zu: attempts %u\n", node, when, keep, o.attempts); dump(&w); }
                CHECK(!sim_failed(sim));
                CHECK(o.done);
                sim_destroy(sim);
            }
    printf("  restores: %llu runs, %llu repeated secret draws, %llu second contributions after a restore (S5, not built)\n",
           (unsigned long long)runs, (unsigned long long)repeated_draws, (unsigned long long)second);
    CHECK(repeated_draws > 0);
    CHECK(restores == runs);
    world_reset(&w);
}

/* ---- 5. faults: the right party is named, nothing reaches the library unparsed ---- */

static outcome_t fault_run(world_t *w, int fault, int node, uint32_t members, uint8_t flags, sim_t **out)
{
    world_reset(w);
    w->fault = fault; w->fault_node = node;
    if (fault != WX_ALTER_NONCE && fault != WX_SWAP_NONCE && fault != WX_BAD_RESULT) w->max_attempts = 0;
    sim_config_t c = w_config(w, 30000 + (uint64_t)fault * 10 + (uint64_t)node, members);
    sim_t *sim = start_sim(w, &c, fault != WX_EQUIVOCATE && fault != WX_PARTIAL_TWICE);
    outcome_t o = drive(w, sim, members, 1, flags, 600);
    CHECK(!sim_failed(sim));
    *out = sim;                 /* the caller destroys it after its checks: node state lives there */
    return o;
}

static void test_faults(void)
{
    world_t w;
    memset(&w, 0, sizeof w);
    static const struct { int fault, node; uint8_t why; } blamed[] = {
        {WX_BAD_PARTIAL, 2, GZ_SIGN_WHY_BAD_PARTIAL}, {WX_BAD_SCALAR, 3, GZ_SIGN_WHY_BAD_PARTIAL},
        {WX_EQUIVOCATE, 1, GZ_SIGN_WHY_EQUIVOCATION}, {WX_BAD_POINT, 1, GZ_SIGN_WHY_BAD_NONCE},
        {WX_PARTIAL_TWICE, 1, GZ_SIGN_WHY_EQUIVOCATION}};
    for (size_t i = 0; i < sizeof blamed / sizeof blamed[0]; i++) {
        sim_t *sim;
        outcome_t o = fault_run(&w, blamed[i].fault, blamed[i].node, 4, 0, &sim);
        const gz_sign_round_t *f = o.first_failed;
        /* participant index = party index here: the first attempt has every member */
        if (!f || f->blamed != (1u << blamed[i].node) || f->why != blamed[i].why)
            printf("  fault %d: blamed %x why %d\n", blamed[i].fault, f ? f->blamed : 0, f ? f->why : -1);
        CHECK(f && f->blamed == (1u << blamed[i].node) && f->why == blamed[i].why);
        CHECK(o.done && o.members_in_round == 3 && o.members_complete == 3);   /* the next attempt, without it */
        CHECK(g_illegal == 0);
        sim_destroy(sim);
    }
    /* The host alters someone's nonce, or moves a signed nonce to another item: members refuse
     * before any partial signature, and nobody is blamed for it. */
    for (int fault = WX_ALTER_NONCE; fault <= WX_ALTER_NONCE + 1; fault++) {
        int fx = fault == WX_ALTER_NONCE ? WX_ALTER_NONCE : WX_SWAP_NONCE;
        sim_t *sim;
        w.max_attempts = 1;                         /* judge the first attempt */
        outcome_t o = fault_run(&w, fx, 0, 4, 0, &sim);
        CHECK(!o.done);
        CHECK(w.sends_partials == 0);
        CHECK(o.blame_fault == 0);
        int refused = 0;
        for (int n = 1; n <= 4; n++)
            for (int k = 0; w.nodes[n] && k < GZ_SIGN_MAX_ROUNDS; k++)
                refused += w.nodes[n]->eng.rounds[k].state == GZ_SIGN_ROUND_ABORTED && w.nodes[n]->eng.rounds[k].why == GZ_SIGN_WHY_BAD_NONCE;
        if (refused == 0) printf("  fault %d: no member refused\n", fx);
        CHECK(refused > 0);
        sim_destroy(sim);
    }
    /* The host sends a wrong final signature: members stay Unfinished, never Aborted, and hold nothing wrong. */
    {
        sim_t *sim;
        w.max_attempts = 1;
        outcome_t o = fault_run(&w, WX_BAD_RESULT, 0, 3, 0, &sim);
        int unfinished = 0;
        for (int n = 1; n <= 3; n++)
            for (int k = 0; w.nodes[n] && k < GZ_SIGN_MAX_ROUNDS; k++) {
                unfinished += w.nodes[n]->eng.rounds[k].state == GZ_SIGN_ROUND_UNFINISHED && w.nodes[n]->eng.rounds[k].why == GZ_SIGN_WHY_BAD_RESULT;
                CHECK(w.nodes[n]->eng.rounds[k].state != GZ_SIGN_ROUND_COMPLETE);
            }
        CHECK(unfinished > 0);
        (void)o;
        sim_destroy(sim);
    }
    /* Everything twice from the host: no harm. */
    {
        sim_t *sim = NULL;
        outcome_t o = fault_run(&w, WX_REPEAT_ALL, 0, 3, 0, &sim);
        if (!o.done) dump(&w);
        CHECK(o.done && o.members_complete == 3);
        uint64_t dups = 0;
        for (int n = 1; n <= 3; n++) dups += w.nodes[n] ? w.nodes[n]->eng.counters[GZ_SIGN_COUNT_DUPLICATES] : 0;
        CHECK(dups > 0);
        sim_destroy(sim);
    }
    /* Definitions the engine must refuse before anything is signed. */
    static const uint8_t refuse[] = {WF_DUP_KEY, WF_BAD_MODE, WF_DUP_SIGNER, WF_BAD_SCRIPT};
    for (size_t i = 0; i < sizeof refuse; i++) {
        world_reset(&w);
        sim_config_t c = w_config(&w, 40000 + i, 3);
        sim_t *sim = start_sim(&w, &c, 1);
        uint8_t p[W_PARAMS];
        w_params(p, 1, 1, w_mask(3), refuse[i]);
        static gz_action_t slots[64];
        static uint8_t bytes[65536];
        gz_action_list_t list;
        gz_action_list_init(&list, slots, 64, bytes, sizeof bytes);
        CHECK(gz_sign_begin(&w.nodes[0]->eng, p, W_PARAMS, &list) == GZ_ERR_ARGUMENT && list.count == 0);
        w_params(p, 1, 1, w_mask(3), 0);
        CHECK(gz_sign_begin(&w.nodes[0]->eng, p, W_PARAMS, &list) == GZ_OK);   /* the control: the clean tree is accepted */
        sim_destroy(sim);
    }
    /* A host restart on one funding outpoint: the next attempt has a new identifier (S4) and completes. */
    {
        world_reset(&w);
        sim_config_t c = w_config(&w, 50001, 3);
        sim_t *sim = start_sim(&w, &c, 1);
        sim_crash_after_releases(sim, 0, 6);
        outcome_t o = drive(&w, sim, 3, 1, WF_SAME_TREE, 300);
        CHECK(sim_stats(sim)->crashes_in_release == 1);
        CHECK(o.done && o.members_complete == 3 && o.attempts >= 2);
        sim_destroy(sim);
    }
    world_reset(&w);
}

/* ---- 6. definitions refused, and known answers ---- */

static uint64_t g_fill;
static void det_fill(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len)
{
    (void)ctx; (void)purpose;
    for (size_t i = 0; i < len; i++) { g_fill = g_fill * 6364136223846793005ull + 1442695040888963407ull; out[i] = (uint8_t)(g_fill >> 56); }
}
static uint64_t det_now(void *ctx) { (void)ctx; return 0; }

static void eng_init(gz_sign_t *e, w_builder_t *b, uint32_t g)
{
    gz_sign_config_t c;
    gz_ports_t ports = {{det_fill, NULL}, {det_now, NULL}};
    memset(&c, 0, sizeof c);
    c.host = g == 0; c.ctx = w_ctx();
    w_secret("test/factory", g, c.factory_secret);
    w_secret("test/contribution", g, c.contribution_secret);
    c.build = w_build; c.retry = w_retry; c.build_ctx = b;
    c.tick_ms = 1; c.resend_ticks = 4; c.deadline_ticks = 80; c.max_attempts = 4;
    CHECK(gz_sign_init(e, &c, &ports, 7) == GZ_OK);
}

/* Up to n participants: fresh keys that sign nothing. */
static void grow_participants(gz_sign_def_t *d, int n)
{
    for (int g = d->n_participants; g < n && g < GZ_SIGN_MAX_PARTICIPANTS; g++) {
        uint8_t sk[32];
        secp256k1_keypair kp;
        secp256k1_pubkey pk;
        secp256k1_xonly_pubkey x;
        size_t l = 33;
        w_secret("test/factory", 100u + (uint32_t)g, sk);
        if (!secp256k1_keypair_create(w_ctx(), &kp, sk) || !secp256k1_keypair_pub(w_ctx(), &pk, &kp) ||
            !secp256k1_ec_pubkey_serialize(w_ctx(), d->participants[g].factory_key, &l, &pk, SECP256K1_EC_COMPRESSED)) abort();
        w_secret("test/contribution", 100u + (uint32_t)g, sk);
        if (!secp256k1_keypair_create(w_ctx(), &kp, sk) || !secp256k1_keypair_xonly_pub(w_ctx(), &x, NULL, &kp) ||
            !secp256k1_xonly_pubkey_serialize(w_ctx(), d->participants[g].contribution_key, &x)) abort();
        d->participants[g].peer = 100u + (uint32_t)g;
    }
    d->n_participants = (uint8_t)n;
}

/* Item `it` signed by participants 0..n-1, its spent script made to match. */
static void all_sign(gz_sign_def_t *d, gz_sign_item_t *it, int n)
{
    secp256k1_pubkey pks[GZ_SIGN_MAX_SIGNERS], tw_pk;
    const secp256k1_pubkey *ptr[GZ_SIGN_MAX_SIGNERS];
    secp256k1_xonly_pubkey agg, x;
    secp256k1_musig_keyagg_cache c;
    uint8_t ser[32], tw[32];
    gz_sign_sha256_t th;
    it->n_signers = (uint8_t)n;
    for (int k = 0; k < n; k++) {
        it->signers[k] = (uint8_t)k;
        if (!secp256k1_ec_pubkey_parse(w_ctx(), &pks[k], d->participants[k].factory_key, 33)) abort();
        ptr[k] = &pks[k];
    }
    if (!secp256k1_musig_pubkey_agg(w_ctx(), NULL, &agg, &c, ptr, (size_t)n) || !secp256k1_xonly_pubkey_serialize(w_ctx(), ser, &agg)) abort();
    gz_sign_tagged_init(&th, "TapTweak");
    gz_sign_sha256_write(&th, ser, 32);
    if (it->has_merkle_root) gz_sign_sha256_write(&th, it->merkle_root, 32);
    gz_sign_sha256_done(&th, tw);
    if (!secp256k1_musig_pubkey_xonly_tweak_add(w_ctx(), &tw_pk, &c, tw) || !secp256k1_xonly_pubkey_from_pubkey(w_ctx(), &x, NULL, &tw_pk) ||
        !secp256k1_xonly_pubkey_serialize(w_ctx(), it->spent_script + 2, &x)) abort();
}

/* The item's transaction grown to exactly `len` bytes with one more output (it must still parse). */
static void pad_tx(gz_sign_item_t *it, size_t len)
{
    uint8_t t[GZ_SIGN_MAX_TX + 64];
    gz_sign_tx_t tx;
    if (!gz_sign_tx_parse(it->tx, it->tx_len, &tx) || tx.outputs_at < 1) abort();
    size_t at = tx.outputs_end, add = len - it->tx_len;
    memcpy(t, it->tx, at);
    while (add) {                                  /* outputs of at most 252 script bytes (a one-byte length) */
        size_t script = add - 9 > 252 ? (add - 9 - 252 < 9 ? add - 9 - 9 : 252) : add - 9;
        t[tx.outputs_at - 1]++;                    /* the output count (one byte here) */
        memset(t + at, 0, 8);
        t[at + 8] = (uint8_t)script;
        memset(t + at + 9, 0x6a, script);
        at += 9 + script; add -= 9 + script;
    }
    memcpy(t + at, it->tx + it->tx_len - 4, 4);
    if (len <= GZ_SIGN_MAX_TX) { memcpy(it->tx, t, len); it->tx_len = (uint16_t)len; }
    else it->tx_len = (uint16_t)len;               /* past the limit: refused before its bytes are read */
}

static void damage(gz_sign_def_t *d, int which)
{
    gz_sign_item_t *it = &d->items[d->n_items - 1];
    switch (which) {
    case 1: d->n_participants = 1; break;
    case 2: d->n_participants = GZ_SIGN_MAX_PARTICIPANTS + 1; break;
    case 3: d->n_tiers = 0; break;
    case 4: d->n_tiers = GZ_SIGN_MAX_TIERS + 1; break;
    case 5: d->n_items = 0; break;
    case 6: d->n_items = GZ_SIGN_MAX_ITEMS + 1; break;
    case 7: d->participants[1].factory_key[0] = 5; break;                      /* not a key */
    case 8: memset(d->participants[1].contribution_key, 0xff, 32); break;     /* not a key */
    case 9: d->n_tiers = 3; it->tier = 2; break;                              /* a tier skipped */
    case 10: d->items[0].tier = 1; d->n_tiers = 2; break;                     /* tiers out of order */
    case 11: it->n_signers = 1; break;
    case 12: it->signers[it->n_signers - 1] = d->n_participants; break;       /* no such participant */
    case 13: it->n_signers = GZ_SIGN_MAX_SIGNERS + 1; break;
    case 14: it->tx_len = GZ_SIGN_MAX_TX + 1; break;
    case 15: it->tx_len--; break;                                             /* truncated */
    case 16: it->has_merkle_root = 2; break;
    case 17: d->participants[2].peer = d->participants[1].peer; break;
    case 18: memcpy(d->participants[2].contribution_key, d->participants[1].contribution_key, 32); break;
    case 19: it->spent_amount++; break;            /* accepted: the digest changes, the definition stays valid */
    case 20: {                                     /* accepted: another valid contribution key (S6: it is in the identifier) */
        uint8_t sk[32];
        secp256k1_keypair kp;
        secp256k1_xonly_pubkey x;
        w_secret("test/contribution", 50, sk);
        if (!secp256k1_keypair_create(w_ctx(), &kp, sk) || !secp256k1_keypair_xonly_pub(w_ctx(), &x, NULL, &kp) ||
            !secp256k1_xonly_pubkey_serialize(w_ctx(), d->participants[1].contribution_key, &x)) abort();
        break;
    }
    case 21: d->purpose ^= 1; break;               /* accepted: another purpose */
    /* at the limits: accepted (22 to 26); one past them: refused (27 to 30) */
    case 22: case 25: case 29: grow_participants(d, which == 29 ? GZ_SIGN_MAX_PARTICIPANTS + 1 : GZ_SIGN_MAX_PARTICIPANTS);
        if (which == 25) all_sign(d, it, GZ_SIGN_MAX_SIGNERS);
        break;
    case 23: d->n_tiers = GZ_SIGN_MAX_TIERS;                               /* the items in reverse, so that children come first (C6) */
        for (int i = 0; i < d->n_items / 2; i++) { gz_sign_item_t t = d->items[i]; d->items[i] = d->items[d->n_items - 1 - i]; d->items[d->n_items - 1 - i] = t; }
        for (int i = 0; i < d->n_items; i++) d->items[i].tier = (uint8_t)(i * GZ_SIGN_MAX_TIERS / d->n_items);
        break;
    case 24: case 28:
        for (int i = d->n_items; i < GZ_SIGN_MAX_ITEMS; i++) d->items[i] = d->items[i % 10];
        d->n_items = which == 24 ? GZ_SIGN_MAX_ITEMS : GZ_SIGN_MAX_ITEMS;
        if (which == 28) d->items[GZ_SIGN_MAX_ITEMS - 1].tx_len = 0;
        break;
    case 26: case 27: pad_tx(&d->items[0], which == 26 ? GZ_SIGN_MAX_TX : GZ_SIGN_MAX_TX + 1); break;
    case 30: d->n_participants = 2; break;         /* members dropped from the list, still signers: refused */
    case 31: {                                     /* two participants' contribution keys exchanged */
        uint8_t t[32];
        memcpy(t, d->participants[1].contribution_key, 32);
        memcpy(d->participants[1].contribution_key, d->participants[2].contribution_key, 32);
        memcpy(d->participants[2].contribution_key, t, 32);
        break;
    }
    /* review B: refused by one line each */
    case 32: d->n_tiers = 2;                     /* B6: the root (item 0) alone in tier 0, before its children: against C6 */
        for (int i = 1; i < d->n_items; i++) d->items[i].tier = 1;
        break;
    case 33: {                                   /* mutant D48: the last item (a leaf nobody spends) carries a witness */
        uint8_t t[GZ_SIGN_MAX_TX];
        size_t n = it->tx_len;
        gz_sign_tx_t x;
        if (n + 68 > GZ_SIGN_MAX_TX) abort();
        memcpy(t, it->tx, 4); t[4] = 0; t[5] = 1;
        memcpy(t + 6, it->tx + 4, n - 8);
        t[n - 2] = 1; t[n - 1] = 64; memset(t + n, 0x11, 64);
        memcpy(t + n + 64, it->tx + n - 4, 4);
        if (!gz_sign_tx_parse(t, n + 68, &x) || !x.witness_item) abort();
        memcpy(it->tx, t, n + 68); it->tx_len = (uint16_t)(n + 68);
        break;
    }
    default: break;
    }
}

static size_t begin_proposal(w_builder_t *b, uint8_t flags, uint8_t *out, size_t cap)
{
    static gz_sign_t e;
    static gz_action_t slots[64];
    static uint8_t bytes[1u << 16];
    gz_action_list_t list;
    uint8_t p[W_PARAMS];
    size_t n = 0;
    g_fill = 1;
    eng_init(&e, b, 0);
    gz_action_list_init(&list, slots, 64, bytes, sizeof bytes);
    w_params(p, 1, 1, w_mask(3), flags);
    if (gz_sign_begin(&e, p, W_PARAMS, &list) == GZ_OK)
        for (size_t k = 0; k < list.count; k++)
            if (list.slots[k].kind == GZ_ACTION_SEND && list.slots[k].u.send.bytes.len <= cap) {
                n = list.slots[k].u.send.bytes.len;
                memcpy(out, list.slots[k].u.send.bytes.data, n);
                break;
            }
    gz_sign_wipe(&e);
    return n;
}

static void test_definitions(int print)
{
    w_builder_t b;
    uint8_t clean[256], other[256];
    memset(&b, 0, sizeof b);
    b.mutate = damage;
    size_t n = begin_proposal(&b, 0, clean, sizeof clean);
    CHECK(n > 0);                                                   /* the control */
    for (int which = 1; which <= 18; which++) {
        b.which = which;
        size_t m = begin_proposal(&b, 0, other, sizeof other);
        if (m) printf("  definition damage %d was accepted\n", which);
        CHECK(m == 0);
    }
    /* Whatever changes the definition or the parameters changes the identifier. */
    for (int which = 19; which <= 26; which++) {
        b.which = which;
        size_t m = begin_proposal(&b, 0, other, sizeof other);
        if (!(m > 0 && memcmp(other + 3, clean + 3, 32) != 0)) printf("  definition change %d: not accepted with a new identifier\n", which);
        CHECK(m > 0 && memcmp(other + 3, clean + 3, 32) != 0);
    }
    for (int which = 27; which <= 30; which++) {
        b.which = which;
        size_t m = begin_proposal(&b, 0, other, sizeof other);
        if (m) printf("  definition damage %d was accepted\n", which);
        CHECK(m == 0);
    }
    /* review B: a parent signed before its children (32, C6); an item with a witness (33) */
    for (int which = 32; which <= 33; which++) {
        b.which = which;
        size_t m = begin_proposal(&b, 0, other, sizeof other);
        if (m) printf("  definition damage %d was accepted\n", which);
        CHECK(m == 0);
    }
    /* exchanged contribution keys: the host (participant 0) accepts; the member whose factory key is
     * at one place and whose contribution key at another must not take a seat */
    {
        static gz_sign_t mem;
        static gz_action_t ms[16];
        static uint8_t mb[4096];
        gz_action_list_t ml;
        gz_event_t ev;
        gz_sign_msg_t msg;
        b.which = 31;
        size_t m = begin_proposal(&b, 0, other, sizeof other);
        CHECK(m > 0);
        eng_init(&mem, &b, 1);
        gz_action_list_init(&ml, ms, 16, mb, sizeof mb);
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_MESSAGE_RECEIVED; ev.u.message.bytes.data = other; ev.u.message.bytes.len = m;
        CHECK(gz_sign_handle(&mem, &ev, &ml) == GZ_OK && ml.count == 1 && ml.slots[0].kind == GZ_ACTION_SEND);
        CHECK(ml.count == 1 && gz_sign_decode(ml.slots[0].u.send.bytes.data, ml.slots[0].u.send.bytes.len, &msg) &&
              msg.kind == GZ_SIGN_MSG_ABORT && msg.reason == GZ_SIGN_WHY_INVALID_ROUND && gz_sign_latest(&mem) == NULL);
        gz_sign_wipe(&mem);
    }
    /* the smallest round: the host and one member */
    {
        static gz_sign_t host;
        static gz_action_t hs[16];
        static uint8_t hb[4096];
        gz_action_list_t hl;
        uint8_t p[W_PARAMS];
        b.which = 0;
        eng_init(&host, &b, 0);
        gz_action_list_init(&hl, hs, 16, hb, sizeof hb);
        w_params(p, 1, 1, w_mask(1), 0);
        CHECK(gz_sign_begin(&host, p, W_PARAMS, &hl) == GZ_OK && hl.count == 2);
        gz_sign_wipe(&host);
    }
    size_t m;
    b.which = 0;
    m = begin_proposal(&b, 0x80, other, sizeof other);             /* an unused flag: same tree, other parameters */
    CHECK(m > 0 && memcmp(other + 3, clean + 3, 32) != 0);
    m = begin_proposal(&b, 0, other, sizeof other);                /* the same: the same bytes */
    CHECK(m == n && memcmp(other, clean, n) == 0);

    /* Known answers, from a fixed generator: the proposal, then a member's nonces for it.
     * They pin the identifier's preimage, the nonce function's inputs and the nonce signatures. */
    static gz_sign_t mem;
    static gz_action_t slots[64];
    static uint8_t bytes[1u << 16];
    gz_action_list_t list;
    gz_event_t ev;
    uint8_t d[32];
    gz_sign_sha256_t s;
    eng_init(&mem, &b, 1);
    gz_action_list_init(&list, slots, 64, bytes, sizeof bytes);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_MESSAGE_RECEIVED; ev.u.message.peer_id = 0; ev.u.message.bytes.data = clean; ev.u.message.bytes.len = n;
    CHECK(gz_sign_handle(&mem, &ev, &list) == GZ_OK && list.count == 2);
    gz_sign_sha256_init(&s);
    gz_sign_sha256_write(&s, clean, n);
    for (size_t k = 0; k < list.count; k++)
        if (list.slots[k].kind == GZ_ACTION_SEND) gz_sign_sha256_write(&s, list.slots[k].u.send.bytes.data, list.slots[k].u.send.bytes.len);
    gz_sign_sha256_done(&s, d);
    uint64_t got = 0;
    for (int i = 0; i < 8; i++) got = got << 8 | d[i];
    if (print) printf("#define KNOWN_ANSWERS 0x%016llxull\n", (unsigned long long)got);
    CHECK(got == KNOWN_ANSWERS);
    gz_sign_wipe(&mem);
}

/* ---- 7. scripted scenarios, pinned ---- */

/* Transcript digests of the scenarios (scenarios.h). After an intended change:
 * run "test_signing golden-print", check what changed, update. */
static const uint64_t SC_KNOWN[N_SCENARIOS] = {
    0xd03b9f9431dac65eull, /* honest-1 */
    0x2194270548af9ba8ull, /* honest-2 */
    0x078fe346a984f1b9ull, /* duplicates */
    0x46d6a04cd44d0694ull, /* member-restart-nonces */
    0x21bb37c488cd6e2full, /* member-restart-signed */
    0x31ad452181598affull, /* tier-abort */
    0xe34be8e9b5657922ull, /* host-restarts */
    0xe63b77395b661278ull, /* timers */
    0x58434ee23b6a9ab3ull, /* host-faults */
    0x757f95def267ca85ull, /* member-faults */
    0x81f5aeecf46474b1ull, /* proposals */
    0xb94a1eeef3ddc1b7ull, /* journal */
    0xab2dc4750a4db095ull, /* edges */
};

static void test_golden(int print)
{
    for (int k = 0; k < N_SCENARIOS; k++) {
        int before = check_failures;
        uint64_t d = run_scenario(k);
        if (print) printf("    0x%016llxull, /* %s */\n", (unsigned long long)d, SC_NAMES[k]);
        else if (d != SC_KNOWN[k]) printf("  scenario %s: transcript %016llx, pinned %016llx\n", SC_NAMES[k], (unsigned long long)d, (unsigned long long)SC_KNOWN[k]);
        if (check_failures != before) printf("  scenario %s: %d checks failed\n", SC_NAMES[k], check_failures - before);
        if (!print) CHECK(d == SC_KNOWN[k]);
    }
}

/* ---- 8. the independent model on random sequences ---- */

static void test_model(int runs)
{
    model_stats_t st;
    memset(&st, 0, sizeof st);
    for (int k = 0; k < runs; k++) CHECK(model_run((uint64_t)k + 1, &st));
    printf("  model: %llu runs, %llu events, %llu restarts, %llu replays, %llu duplicates, %llu drops; %llu completed, %llu ran out of attempts; %llu checks, %llu violations\n",
           (unsigned long long)st.runs, (unsigned long long)st.events, (unsigned long long)st.restarts, (unsigned long long)st.replays,
           (unsigned long long)st.dups, (unsigned long long)st.drops, (unsigned long long)st.done, (unsigned long long)st.exhausted,
           (unsigned long long)st.checks, (unsigned long long)st.violations);
    CHECK(st.violations == 0 && st.restarts > 0 && st.replays > 0 && st.dups > 0 && st.drops > 0);
    CHECK(st.done >= st.runs * 9 / 10);
}

/* Review A, F1: an error leaves the engine refusing every call until a start
 * rebuilds it from storage, and the start recovers it. */
static void test_errors(void)
{
    static gz_action_t slots[1];
    static uint8_t bytes[64];
    gz_action_list_t small;
    harness_t h;
    h_init(&h, 3);
    /* the host: a begin whose actions do not fit */
    uint8_t p[W_PARAMS];
    w_params(p, 1, 1, w_mask(3), 0);
    gz_action_list_init(&small, slots, 1, bytes, sizeof bytes);
    CHECK(gz_sign_begin(h.p[0].e, p, W_PARAMS, &small) == GZ_ERR_NO_SPACE && small.count == 0 && small.used == 0);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_ERR_FAILED);
    gz_event_t tick;
    memset(&tick, 0, sizeof tick);
    tick.kind = GZ_EVENT_TIMER_FIRED; tick.u.timer.timer_id = 0x5347u;
    gz_action_list_init(&small, h_slots, 512, h_bytes, sizeof h_bytes);
    CHECK(gz_sign_handle(h.p[0].e, &tick, &small) == GZ_ERR_FAILED && small.count == 0);
    CHECK(h_restart(&h, 0) == GZ_OK && h_newest(&h, 0) == NULL && h.p[0].e->attempts == 0);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    /* a member: a proposal whose answer does not fit */
    long k = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(k >= 0);
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_MESSAGE_RECEIVED; ev.u.message.peer_id = 0;
    ev.u.message.bytes.data = h.q[k].b; ev.u.message.bytes.len = h.q[k].len;
    gz_action_list_init(&small, slots, 1, bytes, sizeof bytes);
    CHECK(gz_sign_handle(h.p[1].e, &ev, &small) == GZ_ERR_NO_SPACE && small.count == 0);
    size_t nonces = h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES);
    CHECK(h_deliver(&h, (size_t)k, 1) == GZ_ERR_FAILED && h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == nonces);
    CHECK(h_restart(&h, 1) == GZ_OK && h_newest(&h, 1) == NULL);
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
    for (uint32_t j = 1; j <= 3; j++) CHECK(h_newest(&h, j) && h_newest(&h, j)->state == GZ_SIGN_ROUND_COMPLETE);
    /* the same with a start that cannot emit: still failed, and a later start recovers */
    gz_storage_reader_t rd = {h_next, h_rewind, &h.p[2], h.p[2].incarnation, 0};
    int more = 1;
    gz_action_list_init(&small, slots, 0, bytes, 0);
    CHECK(gz_sign_start(h.p[2].e, &rd, &small, &more) != GZ_OK && small.count == 0);
    gz_action_list_init(&small, h_slots, 512, h_bytes, sizeof h_bytes);
    CHECK(gz_sign_handle(h.p[2].e, &tick, &small) == GZ_ERR_FAILED && small.count == 0);
    gz_action_list_init(&small, h_slots, 512, h_bytes, sizeof h_bytes);
    CHECK(gz_sign_start(h.p[2].e, &rd, &small, &more) == GZ_OK && more == 0);
    CHECK(h_newest(&h, 2) && h_newest(&h, 2)->state == GZ_SIGN_ROUND_COMPLETE);
    h_free(&h);
}

/* Review A, F3: a new round pushes out a round that is over (here a newer
 * Aborted one) before a Complete one, however old. */
static void test_eviction_order(void)
{
    harness_t h;
    uint8_t ids[GZ_SIGN_MAX_ROUNDS][32];
    h_init(&h, 3);
    for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        memcpy(ids[k], h_newest(&h, 0)->id, 32);
        h_flush(&h, 100000);
    }
    gz_sign_round_t *last = (gz_sign_round_t *)(uintptr_t)h_find(&h, 1, ids[GZ_SIGN_MAX_ROUNDS - 1]);
    CHECK(last && last->state == GZ_SIGN_ROUND_COMPLETE);
    if (last) last->state = GZ_SIGN_ROUND_ABORTED;      /* as if the newest had ended before its partial signatures */
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 1)->state == GZ_SIGN_ROUND_COMPLETE);
    CHECK(h_find(&h, 1, ids[0]) != NULL && h_find(&h, 1, ids[GZ_SIGN_MAX_ROUNDS - 1]) == NULL);
    h_free(&h);
}

/* Review A, F2: ordinary use never fills a fixed list. Many rounds; every
 * party starts again from its journal, every member still takes part, and
 * the first identifier is still refused. */
static void test_many_rounds(int rounds)
{
    harness_t h;
    h_init(&h, 3);
    h.max_attempts = 100000;
    CHECK(h_restart(&h, 0) == GZ_OK);
    int stopped = -1;
    for (int k = 0; k < rounds; k++) {
        CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
        h_flush(&h, 100000);
        for (uint32_t j = 1; j <= 3; j++)
            if (stopped < 0 && h_newest(&h, j)->state != GZ_SIGN_ROUND_COMPLETE) stopped = k;
    }
    CHECK(stopped < 0 && h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
    for (uint32_t g = 0; g <= 3; g++) CHECK(h_restart(&h, g) == GZ_OK && h.p[g].e->n_known == (size_t)rounds - GZ_SIGN_MAX_ROUNDS);
    const h_sent_t *p0 = h_sent_kind(&h, 0, GZ_SIGN_MSG_PROPOSE, 0);
    size_t nonces = h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES);
    h_inject(&h, 0, 1, p0->b, p0->len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], GZ_SIGN_WHY_KNOWN_ROUND, 0xff, 0, NULL) && h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == nonces);
    printf("  many rounds: %d, each party starts again; refused identifiers held %zu\n", rounds, h.p[1].e->n_known);
    h_free(&h);
}

/* Review B, B5: a member's rounds with partial signatures out come back from
 * a restart as they were. Five rounds, each with its partial signatures sent
 * and its result withheld: a new proposal leaves the one before it
 * Unfinished, which no record says. After a restart the same rounds are in
 * memory in the same states: the newest still waits for its result, the
 * others are Unfinished, not running again. */
static void test_restart_keeps_unfinished(void)
{
    harness_t h;
    uint8_t ids[5][32];
    const gz_sign_round_t *r;
    h_init(&h, 1);
    for (int k = 0; k < 5; k++) {
        CHECK(h_begin(&h, 1, 1, 0) == GZ_OK);
        memcpy(ids[k], h_newest(&h, 0)->id, 32);
        while (h.nq) {                              /* the host's result and round_complete never reach the member */
            long q;
            while ((q = q_find(&h, 0, 1, GZ_SIGN_MSG_RESULT)) >= 0 || (q = q_find(&h, 0, 1, GZ_SIGN_MSG_COMPLETE)) >= 0) h_drop_msg(&h, (size_t)q);
            if (h.nq) h_deliver(&h, 0, 0);
        }
        r = h_find(&h, 1, ids[k]);
        CHECK(r && r->state == GZ_SIGN_ROUND_ACTIVE && r->ever_partial);
    }
    for (int pass = 0; pass < 2; pass++) {
        CHECK(h_find(&h, 1, ids[0]) == NULL);
        for (int k = 1; k < 5; k++) {
            r = h_find(&h, 1, ids[k]);
            CHECK(r && r->ever_partial && r->state == (k == 4 ? GZ_SIGN_ROUND_ACTIVE : GZ_SIGN_ROUND_UNFINISHED));
        }
        if (pass == 0) CHECK(h_restart(&h, 1) == GZ_OK);
    }
    h_free(&h);
}

int main(int argc, char **argv)
{
    const char *only = "";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "quick")) g_quick = g_quick > 1 ? g_quick : 1;
        else if (!strcmp(argv[i], "tiny")) g_quick = 2;
        else only = argv[i];
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    int stop = getenv("GZ_STOP_ON_FAIL") != NULL;          /* for mutation runs: stop at the first failing section */
#define SECTION(name, call) \
    do { if (!*only || !strcmp(only, name)) call; if ((g_quick || stop) && check_failures) return check_done(); } while (0)
    if (!strcmp(only, "known")) { test_definitions(1); return 0; }
    if (!strcmp(only, "golden-print")) { test_golden(1); return check_done(); }
    SECTION("blocks", (test_blocks(), test_import_agrees(), test_definitions(0)));
    SECTION("decoders", (test_sha256(), test_tx_reader(), test_decoder()));
    SECTION("golden", test_golden(0));
    SECTION("model", test_model(g_quick > 1 ? 4 : g_quick ? 20 : 120));
    SECTION("faults", test_faults());
    SECTION("honest", test_honest());
    SECTION("t1", test_t1());
    SECTION("crashes", test_crashes());
    SECTION("restores", test_restores());
    SECTION("errors", (test_errors(), test_eviction_order(), test_restart_keeps_unfinished(), test_many_rounds(g_quick ? 60 : 1000)));
    printf("  illegal-argument callbacks: %d\n", g_illegal);
    CHECK(g_illegal == 0);
    if (g_ctx) secp256k1_context_destroy(g_ctx);
    return check_done();
}
