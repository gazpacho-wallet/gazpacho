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
#define KNOWN_ANSWERS 0xad0154c39ed26b9bull

typedef struct {
    int done;                   /* the host's newest round has every ack */
    int members_complete;       /* members of that round holding it complete, same held set */
    int members_in_round;
    uint32_t attempts;
    uint64_t counters_host[9];
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
        w_node_t *n = r->def.peer[j] < W_MAX_NODES ? w->nodes[r->def.peer[j]] : NULL;
        if (!n) continue;
        for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
            const gz_sign_round_t *mr = &n->eng.rounds[k];
            int same_finals = 1;
            for (int i = 0; i < r->def.n_items; i++)         /* the finals of its own items, as the host holds them */
                for (int s = 0; s < r->def.items[i].n_signers; s++)
                    if (r->def.items[i].signers[s] == j && memcmp(mr->final_sig[i], r->final_sig[i], 64) != 0) same_finals = 0;
            if (mr->state == GZ_SIGN_ROUND_COMPLETE && memcmp(mr->id, r->id, 32) == 0 && same_finals) o.members_complete++;
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
    memset(w->builder.epoch, 0, sizeof w->builder.epoch);      /* a new world: every party in its first epoch */
    w->builder.n_outcomes = 0;
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
    CHECK(w_build_params(p, &d, &f) && f);
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
    uint8_t q[W_PARAMS];
    w_params(p, 1, o.attempts, w_mask(4), 0);
    w_params_of(r, q, 0);
    CHECK(memcmp(q, p, W_PARAMS) == 0 && w_build_params(p, &d, &f));
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
            uint8_t q[W_PARAMS];
            w_params(p, 1, o.attempts, w_mask(m), WF_T1);
            w_params_of(r, q, WF_T1);
            CHECK(memcmp(q, p, W_PARAMS) == 0 && w_build_params(p, &d, &f));
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
    uint64_t repeated_draws = 0, runs = 0, second = 0, restores = 0, epochs = 0;
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
                for (uint32_t g = 1; g <= 3; g++) epochs += w.builder.epoch[g];
                runs++;
                if (!o.done) { printf("  restore node %u at %u keep %zu: attempts %u\n", node, when, keep, o.attempts); dump(&w); }
                CHECK(!sim_failed(sim));
                CHECK(o.done);
                sim_destroy(sim);
            }
    printf("  restores: %llu runs, %llu repeated secret draws, %llu second contributions after a restore, %llu new key epochs\n",
           (unsigned long long)runs, (unsigned long long)repeated_draws, (unsigned long long)second, (unsigned long long)epochs);
    CHECK(repeated_draws > 0);
    CHECK(second == 0);                 /* S5: a restored member contributes only under its new keys */
    CHECK(epochs > 0);
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
        w_params(p, 1, 1, w_mask(3), refuse[i] & WF_DUP_KEY);          /* a key twice: in the proposal */
        w.builder.damage = (uint8_t)(refuse[i] & ~WF_DUP_KEY);           /* the others: in what the builder returns */
        static gz_action_t slots[64];
        static uint8_t bytes[1u << 17];
        gz_action_list_t list;
        gz_action_list_init(&list, slots, 64, bytes, sizeof bytes);
        CHECK(w_begin_params(&w.nodes[0]->eng, &w.builder, p, W_PARAMS, &list) == GZ_ERR_ARGUMENT && list.count == 0);
        w.builder.damage = 0;
        w_params(p, 1, 1, w_mask(3), 0);
        CHECK(w_begin_params(&w.nodes[0]->eng, &w.builder, p, W_PARAMS, &list) == GZ_OK);   /* the control: the clean tree is accepted */
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

/* The item's transaction grown to exactly `len` bytes with more outputs (it must still parse). */
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

/* Damage to what the builder returns (the items, the tiers, the lobby fields). */
/* The P2TR output of an item's signers in the order listed, tweaked as the engine tweaks them. */
static void script_of(const gz_sign_def_t *d, const gz_sign_item_t *it, uint8_t out[34])
{
    secp256k1_pubkey pks[GZ_SIGN_MAX_SIGNERS], tw;
    const secp256k1_pubkey *ptr[GZ_SIGN_MAX_SIGNERS];
    secp256k1_xonly_pubkey agg, x;
    secp256k1_musig_keyagg_cache c;
    uint8_t ser[32], t32[32];
    gz_sign_sha256_t th;
    for (int k = 0; k < it->n_signers; k++) {
        if (!secp256k1_ec_pubkey_parse(w_ctx(), &pks[k], d->participants[it->signers[k]].factory_key, 33)) abort();
        ptr[k] = &pks[k];
    }
    if (!secp256k1_musig_pubkey_agg(w_ctx(), NULL, &agg, &c, ptr, it->n_signers) || !secp256k1_xonly_pubkey_serialize(w_ctx(), ser, &agg)) abort();
    gz_sign_tagged_init(&th, "TapTweak");
    gz_sign_sha256_write(&th, ser, 32);
    if (it->has_merkle_root) gz_sign_sha256_write(&th, it->merkle_root, 32);
    gz_sign_sha256_done(&th, t32);
    if (!secp256k1_musig_pubkey_xonly_tweak_add(w_ctx(), &tw, &c, t32) || !secp256k1_xonly_pubkey_from_pubkey(w_ctx(), &x, NULL, &tw)) abort();
    out[0] = 0x51; out[1] = 0x20;
    if (!secp256k1_xonly_pubkey_serialize(w_ctx(), out + 2, &x)) abort();
}

/* Every `len`-byte run equal to `from` in b[0..n) becomes `to`. */
static void swap_bytes(uint8_t *b, size_t n, const uint8_t *from, const uint8_t *to, size_t len)
{
    for (size_t i = 0; i + len <= n; i++)
        if (memcmp(b + i, from, len) == 0) { memcpy(b + i, to, len); i += len - 1; }
}

/* Review A, F7: an item that the host does not sign, the tree kept consistent
 * around it (its parent pays the new script, and every transaction id that
 * changes is followed by the item that spends it), so that only the engine's
 * "the host signs every item" line can refuse it. */
static void item_without_host(gz_sign_def_t *d)
{
    static uint8_t before[GZ_SIGN_MAX_ITEMS][32];
    uint8_t old[34], now[32];
    int x = -1;
    for (int i = d->n_items - 1; i > 0 && x < 0; i--)
        if (d->items[i].n_signers >= 3 && d->items[i].signers[0] == 0) x = i;
    if (x < 0) abort();
    gz_sign_item_t *it = &d->items[x];
    for (int i = 0; i < d->n_items; i++) gz_sign_txid(d->items[i].tx, d->items[i].tx_len, before[i]);
    memcpy(old, it->spent_script, 34);
    it->n_signers--;
    memmove(it->signers, it->signers + 1, it->n_signers);
    script_of(d, it, it->spent_script);
    for (int p = 0; p < d->n_items; p++)                       /* the parent: the item whose transaction it spends */
        if (memcmp(it->tx + 5, before[p], 32) == 0) swap_bytes(d->items[p].tx, d->items[p].tx_len, old, it->spent_script, 34);
    for (int pass = 0; pass < d->n_items; pass++)
        for (int j = 0; j < d->n_items; j++) {
            gz_sign_txid(d->items[j].tx, d->items[j].tx_len, now);
            if (memcmp(now, before[j], 32) == 0) continue;
            for (int i = 0; i < d->n_items; i++)
                if (i != j && memcmp(d->items[i].tx + 5, before[j], 32) == 0) memcpy(d->items[i].tx + 5, now, 32);
            memcpy(before[j], now, 32);
        }
}

static void damage(gz_sign_def_t *d, int which)
{
    gz_sign_item_t *it = &d->items[d->n_items - 1];
    switch (which) {
    case 1: d->n_tiers = 0; break;
    case 2: d->n_tiers = GZ_SIGN_MAX_TIERS + 1; break;
    case 3: d->n_items = 0; break;
    case 4: d->n_items = GZ_SIGN_MAX_ITEMS + 1; break;
    case 5: d->n_tiers = 3; it->tier = 2; break;                              /* a tier skipped */
    case 6: d->items[0].tier = 1; d->n_tiers = 2; break;                     /* tiers out of order */
    case 7: it->n_signers = 1; break;
    case 8: it->signers[it->n_signers - 1] = 40; break;                       /* no such participant */
    case 9: it->n_signers = GZ_SIGN_MAX_SIGNERS + 1; break;
    case 10: it->tx_len = GZ_SIGN_MAX_TX + 1; break;
    case 11: it->tx_len--; break;                                            /* truncated */
    case 12: it->has_merkle_root = 2; break;
    case 13: d->peer[2] = d->peer[1]; break;                                 /* two members, one peer */
    case 14: it->spent_amount++; break;                                      /* not what its parent pays */
    case 15: { uint8_t s = it->signers[0]; it->signers[0] = it->signers[1]; it->signers[1] = s; break; }   /* host not first */
    case 16: d->host_key[1] ^= 1; break;                                     /* not participant 0's key */
    case 17: it->tx[5] ^= 1; break;                                          /* spends an outpoint nothing makes */
    case 18: it->mode = 1; break;                                            /* script path: not in Slice 1 */
    case 19: it->spent_script[5] ^= 1; break;                                /* not the aggregate */
    case 20: d->items[0].tx[5] ^= 1; break;                                  /* the root does not spend the funding */
    /* at the limits: accepted (21 to 23); one past them: refused (24, 25) */
    case 21: d->n_tiers = GZ_SIGN_MAX_TIERS;
        for (int i = 0; i < d->n_items; i++) d->items[i].tier = (uint8_t)(i * GZ_SIGN_MAX_TIERS / d->n_items);
        break;
    case 22: for (int i = d->n_items; i < GZ_SIGN_MAX_ITEMS; i++) d->items[i] = d->items[i % d->n_items];
        d->n_items = GZ_SIGN_MAX_ITEMS;
        break;
    case 23: case 24: pad_tx(it, which == 23 ? GZ_SIGN_MAX_TX : GZ_SIGN_MAX_TX + 1); break;   /* the last item: a leaf nobody spends */
    case 25: for (int i = d->n_items; i < GZ_SIGN_MAX_ITEMS; i++) d->items[i] = d->items[i % d->n_items];
        d->n_items = GZ_SIGN_MAX_ITEMS; d->items[GZ_SIGN_MAX_ITEMS - 1].tx_len = 0;
        break;
    /* review A, F7: refused by one line each */
    case 26: item_without_host(d); break;                                    /* the host does not sign an item */
    case 27: d->items[0].n_signers--; break;     /* the root without the last participant (with proposal damage 27) */
    default: break;
    }
}

/* Damage to what the host proposes. */
static void damage_proposal(gz_tree_proposal_t *p, int which)
{
    gz_tree_participant_t *pt = (gz_tree_participant_t *)(uintptr_t)p->participants;
    switch (which) {
    case 101: p->n_participants = 1; break;
    case 102: p->n_participants = GZ_SIGN_MAX_PARTICIPANTS + 1; break;
    case 103: pt[1].factory_key[0] = 5; break;                                   /* not a key */
    case 104: memset(pt[1].contribution_key + 1, 0xff, 32); break;              /* not a key */
    case 105: memcpy(pt[2].contribution_key, pt[1].contribution_key, 33); break;
    case 106: memcpy(pt[2].factory_key, pt[1].contribution_key, 33); break;    /* one key in both roles */
    case 107: memcpy(pt[0].contribution_key, w_keys(5)->c, 33); break;         /* the host's key is not the terms' */
    case 108: p->funding_amount++; break;                                       /* not the funding output's */
    case 109: p->funding_vout = 1; break;                                       /* no such output */
    case 110: p->funding_txid[3] ^= 1; break;                                   /* not the funding transaction's */
    case 111: p->tier_sizes[0]++; break;
    case 112: p->purpose = 2; break;                                            /* creation only */
    case 113: p->n_lstock_hashes = 1; break;                                    /* none in Slice 1 */
    case 114: p->has_distribution = 1; break;
    case 115: p->funding_script[5] ^= 1; break;                                 /* not the aggregate */
    case 116: memcpy(pt[1].contribution_key, pt[1].factory_key, 33); break;    /* one member's two keys the same */
    case 27: {                         /* the funding paid to all participants but the last (C1, with damage 27) */
        uint8_t keys[GZ_SIGN_MAX_PARTICIPANTS][33], spk[34];
        uint8_t *tx = (uint8_t *)(uintptr_t)p->funding_tx;
        for (size_t i = 0; i + 1 < p->n_participants; i++) memcpy(keys[i], pt[i].factory_key, 33);
        if (!w_agg_script((const uint8_t (*)[33])keys, p->n_participants - 1, spk)) abort();
        swap_bytes(tx, p->funding_tx_len, p->funding_script, spk, 34);
        memcpy(p->funding_script, spk, 34);
        gz_sign_txid(tx, p->funding_tx_len, p->funding_txid);
        break;
    }
    /* accepted, with a new identifier */
    case 121: memcpy(pt[1].contribution_key, w_keys(50)->c, 33); break;        /* contribution keys are inside (S6) */
    case 122: p->terms_digest[0] ^= 1; break;
    case 123: { uint8_t t[33];                                                  /* two members' contribution keys exchanged */
        memcpy(t, pt[1].contribution_key, 33); memcpy(pt[1].contribution_key, pt[2].contribution_key, 33);
        memcpy(pt[2].contribution_key, t, 33); break; }
    default: break;
    }
}

static size_t begin_proposal(w_builder_t *b, uint32_t attempt, uint8_t *out, size_t cap)
{
    static gz_sign_t e;
    static gz_action_t slots[64];
    static uint8_t bytes[1u << 17];
    gz_action_list_t list;
    uint8_t p[W_PARAMS];
    size_t n = 0;
    g_fill = 1;
    eng_init(&e, b, 0);
    gz_action_list_init(&list, slots, 64, bytes, sizeof bytes);
    w_params(p, 1, attempt, w_mask(3), 0);
    if (w_begin_params(&e, b, p, W_PARAMS, &list) == GZ_OK)
        for (size_t k = 0; k < list.count; k++)
            if (list.slots[k].kind == GZ_ACTION_SEND && list.slots[k].u.send.bytes.len <= cap) {
                n = list.slots[k].u.send.bytes.len;
                memcpy(out, list.slots[k].u.send.bytes.data, n);
                break;
            }
    CHECK(gz_sign_latest(&e) == NULL || n > 0);
    gz_sign_wipe(&e);
    return n;
}

static const uint8_t *id_of(const uint8_t *msg) { return msg + GZ_RMSG_HEADER + 2; }

static void test_definitions(int print)
{
    static w_builder_t b;
    static uint8_t clean[GZ_SIGN_MAX_PROPOSAL], other[GZ_SIGN_MAX_PROPOSAL];
    memset(&b, 0, sizeof b);
    size_t n = begin_proposal(&b, 1, clean, sizeof clean);
    CHECK(n > 0);                                                   /* the control */
    b.mutate = damage;
    for (int which = 1; which <= 25; which++) {
        if (which >= 21 && which <= 23) continue;
        b.which = which;
        size_t m = begin_proposal(&b, 1, other, sizeof other);
        if (m) printf("  definition damage %d was accepted\n", which);
        CHECK(m == 0);
    }
    /* at the limits: accepted, and the identifier changes with what changed */
    for (int which = 21; which <= 23; which++) {
        b.which = which;
        size_t m = begin_proposal(&b, 1, other, sizeof other);
        if (!(m > 0 && memcmp(id_of(other), id_of(clean), 32) != 0)) printf("  definition change %d: not accepted with a new identifier\n", which);
        CHECK(m > 0 && memcmp(id_of(other), id_of(clean), 32) != 0);
    }
    /* review A, F7: an item the host does not sign (26); a root without every participant, the
     * funding made to match (27, C1). Each is consistent everywhere else. */
    for (int which = 26; which <= 27; which++) {
        b.which = which;
        b.mutate_proposal = which == 27 ? damage_proposal : NULL;
        size_t m = begin_proposal(&b, 1, other, sizeof other);
        if (m) printf("  definition damage %d was accepted\n", which);
        CHECK(m == 0);
    }
    b.mutate = NULL;
    b.mutate_proposal = damage_proposal;
    for (int which = 101; which <= 116; which++) {
        b.which = which;
        size_t m = begin_proposal(&b, 1, other, sizeof other);
        if (m) printf("  proposal damage %d was accepted\n", which);
        CHECK(m == 0);
    }
    for (int which = 121; which <= 123; which++) {
        b.which = which;
        size_t m = begin_proposal(&b, 1, other, sizeof other);
        if (!(m > 0 && memcmp(id_of(other), id_of(clean), 32) != 0)) printf("  proposal change %d: not accepted with a new identifier\n", which);
        CHECK(m > 0 && memcmp(id_of(other), id_of(clean), 32) != 0);
    }
    /* exchanged contribution keys: the host (participant 0) accepts; the member whose factory key is
     * at one place and whose contribution key at another has no current key there: reason 12 (S5) */
    {
        static gz_sign_t mem;
        static gz_action_t ms[16];
        static uint8_t mb[4096];
        gz_action_list_t ml;
        gz_event_t ev;
        gz_sign_msg_t msg;
        b.which = 123;
        size_t m = begin_proposal(&b, 1, other, sizeof other);
        CHECK(m > 0);
        b.mutate_proposal = NULL;
        eng_init(&mem, &b, 1);
        gz_action_list_init(&ml, ms, 16, mb, sizeof mb);
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_MESSAGE_RECEIVED; ev.u.message.bytes.data = other; ev.u.message.bytes.len = m;
        CHECK(gz_sign_handle(&mem, &ev, &ml) == GZ_OK && ml.count == 1 && ml.slots[0].kind == GZ_ACTION_SEND);
        CHECK(ml.count == 1 && gz_sign_decode(ml.slots[0].u.send.bytes.data, ml.slots[0].u.send.bytes.len, &msg) &&
              msg.kind == GZ_SIGN_MSG_ABORT && msg.reason == 12 && gz_sign_latest(&mem) == NULL);
        gz_sign_wipe(&mem);
    }
    b.mutate_proposal = NULL;
    /* the smallest round: the host and one member */
    {
        static gz_sign_t host;
        static gz_action_t hs[16];
        static uint8_t hb[1u << 15];
        gz_action_list_t hl;
        uint8_t p[W_PARAMS];
        eng_init(&host, &b, 0);
        gz_action_list_init(&hl, hs, 16, hb, sizeof hb);
        w_params(p, 1, 1, w_mask(1), 0);
        CHECK(w_begin_params(&host, &b, p, W_PARAMS, &hl) == GZ_OK && hl.count == 2);
        gz_sign_wipe(&host);
    }
    size_t m;
    m = begin_proposal(&b, 2, other, sizeof other);                 /* another attempt: a new identifier */
    CHECK(m > 0 && memcmp(id_of(other), id_of(clean), 32) != 0);
    m = begin_proposal(&b, 1, other, sizeof other);                 /* the same: the same bytes */
    CHECK(m == n && memcmp(other, clean, n) == 0);

    /* The identifier and tree digest the engine computes are core/tree's
     * definitions of messages.md 7.1 and 7.12, on the items it holds: the
     * engine's computation against an independent writing of the preimage. */
    {
        static gz_sign_t host;
        static gz_action_t hs[16];
        static uint8_t hb[1u << 15];
        gz_action_list_t hl;
        uint8_t p[W_PARAMS], d1[32], d2[32];
        gz_sign_sha256_t s;
        eng_init(&host, &b, 0);
        gz_action_list_init(&hl, hs, 16, hb, sizeof hb);
        w_params(p, 2, 1, w_mask(3), 0);
        CHECK(w_begin_params(&host, &b, p, W_PARAMS, &hl) == GZ_OK);
        const gz_sign_round_t *r = gz_sign_latest(&host);
        CHECK(r != NULL);
        if (r) {
            static gz_rmsg_propose_t pr;
            gz_sign_msg_t mm;
            CHECK(gz_sign_decode(r->proposal, r->proposal_len, &mm) && gz_rmsg_propose_decode(mm.records, mm.records_len, &pr) == GZ_RMSG_OK);
            /* 7.1, written out field by field */
            static const uint8_t proto[4] = {0x67, 0x7a, 0x66, 0x01};
            uint8_t b4[4], b8[8], b2[2], b1;
            gz_sign_tagged_init(&s, "gazpacho/round_id");
            gz_sign_sha256_write(&s, proto, 4);
            gz_sign_sha256_write(&s, r->def.chain, 32);
            gz_sign_sha256_write(&s, w_keys(0)->c, 33);
            gz_sign_sha256_write(&s, r->def.outer_digest, 32);
            gz_sign_sha256_write(&s, pr.p.terms_digest, 32);
            gz_sign_sha256_write(&s, pr.p.funding_txid, 32);
            w_wr32(b4, pr.p.funding_vout); gz_sign_sha256_write(&s, b4, 4);
            for (int k = 0; k < 8; k++) b8[k] = (uint8_t)(pr.p.funding_amount >> (56 - 8 * k));
            gz_sign_sha256_write(&s, b8, 8);
            b2[0] = 0; b2[1] = (uint8_t)pr.p.n_participants; gz_sign_sha256_write(&s, b2, 2);
            for (size_t k = 0; k < pr.p.n_participants; k++) gz_sign_sha256_write(&s, pr.p.participants[k].factory_key, 33);
            for (size_t k = 0; k < pr.p.n_participants; k++) gz_sign_sha256_write(&s, pr.p.participants[k].contribution_key, 33);
            b1 = 1; gz_sign_sha256_write(&s, &b1, 1);
            b1 = pr.p.n_tiers; gz_sign_sha256_write(&s, &b1, 1);
            for (int t = 0; t < pr.p.n_tiers; t++) { w_wr32(b4, pr.p.tier_sizes[t]); gz_sign_sha256_write(&s, b4, 4); }
            w_wr32(b4, r->def.n_items); gz_sign_sha256_write(&s, b4, 4);
            for (int i = 0; i < r->def.n_items; i++) {
                const gz_sign_item_t *it = &r->def.items[i];
                gz_sign_tx_t tx;
                uint8_t sh[32], tw[32], ser[32];
                CHECK(gz_sign_tx_parse(it->tx, it->tx_len, &tx));
                w_wr32(b4, (uint32_t)i); gz_sign_sha256_write(&s, b4, 4);
                gz_sign_sha256_write(&s, tx.outpoint, 32);
                w_wr32(b4, (uint32_t)tx.outpoint[32] | (uint32_t)tx.outpoint[33] << 8 | (uint32_t)tx.outpoint[34] << 16 | (uint32_t)tx.outpoint[35] << 24);
                gz_sign_sha256_write(&s, b4, 4);
                gz_sign_tx_sighash(&tx, it->spent_amount, it->spent_script, sh);
                gz_sign_sha256_write(&s, sh, 32);
                b1 = 0; gz_sign_sha256_write(&s, &b1, 1);
                {   /* the tweak, from the signers' keys by the imported code's aggregation */
                    secp256k1_pubkey pks[GZ_SIGN_MAX_SIGNERS];
                    musig_keyagg_t ka;
                    for (int k = 0; k < it->n_signers; k++) CHECK(secp256k1_ec_pubkey_parse(w_ctx(), &pks[k], pr.p.participants[it->signers[k]].factory_key, 33));
                    CHECK(musig_aggregate_keys(w_ctx(), &ka, pks, it->n_signers));
                    secp256k1_xonly_pubkey_serialize(w_ctx(), ser, &ka.agg_pubkey);
                    if (it->has_merkle_root) { uint8_t pm[64]; memcpy(pm, ser, 32); memcpy(pm + 32, it->merkle_root, 32); sha256_tagged("TapTweak", pm, 64, tw); }
                    else sha256_tagged("TapTweak", ser, 32, tw);
                }
                gz_sign_sha256_write(&s, tw, 32);
                b2[0] = 0; b2[1] = it->n_signers; gz_sign_sha256_write(&s, b2, 2);
                for (int k = 0; k < it->n_signers; k++) { b2[1] = it->signers[k]; gz_sign_sha256_write(&s, b2, 2); }
            }
            gz_sign_sha256_write(&s, pr.host_random, 32);
            gz_sign_sha256_done(&s, d1);
            CHECK(memcmp(d1, r->id, 32) == 0);
            gz_sign_round_id(&r->def, (const uint8_t (*)[32])r->digest, (const uint8_t (*)[32])r->tweak, pr.host_random, d2);
            CHECK(memcmp(d2, r->id, 32) == 0);
            /* the tree digest leaves out what 7.12 says: another host random, another contribution key, the same digest */
            uint8_t t1[32], t2[32];
            gz_sign_tree_digest(&r->def, (const uint8_t (*)[32])r->digest, (const uint8_t (*)[32])r->tweak, t1);
            CHECK(memcmp(t1, r->def.tree_digest, 32) == 0);
            static gz_sign_def_t dd;
            dd = r->def;
            memcpy(dd.participants[1].contribution_key, w_keys(60)->c, 33);
            dd.terms_digest[0] ^= 1;
            gz_sign_tree_digest(&dd, (const uint8_t (*)[32])r->digest, (const uint8_t (*)[32])r->tweak, t2);
            CHECK(memcmp(t1, t2, 32) == 0);
            gz_sign_round_id(&dd, (const uint8_t (*)[32])r->digest, (const uint8_t (*)[32])r->tweak, pr.host_random, d2);
            CHECK(memcmp(d2, r->id, 32) != 0);
            dd.participants[1].factory_key[5] ^= 1;      /* a factory key is in the tree digest */
            gz_sign_tree_digest(&dd, (const uint8_t (*)[32])r->digest, (const uint8_t (*)[32])r->tweak, t2);
            CHECK(memcmp(t1, t2, 32) != 0);
        }
        gz_sign_wipe(&host);
    }

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
    0x3019f11ce6c6371eull, /* honest-1 */
    0x7a78b533f85ecff7ull, /* honest-2 */
    0xc21484d1023cd007ull, /* duplicates */
    0xe83624ff1416866bull, /* member-restart-nonces */
    0x21a11886f51c4816ull, /* member-restart-signed */
    0x1635a14fd7cdd09eull, /* tier-abort */
    0x2be676722e9b47f1ull, /* host-restarts */
    0x827ec25cef459ac8ull, /* timers */
    0xed2046bfca206e0bull, /* host-faults */
    0x418e111b10c8cd05ull, /* member-faults */
    0xbca0101572ec4e6bull, /* proposals */
    0xae05e02a4cf14ec0ull, /* journal */
    0x7fb24c9747b965cbull, /* edges */
    0x9463dda8569004e0ull, /* reconnect */
    0x586454ffe0af7a41ull, /* records */
    0x4e3c836601ddc368ull, /* exposure */
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

/* ---- seeds for fuzz_signing_replay: real journals, in its input form ---- */

static int write_journal(const char *dir, const char *name, const harness_t *h, uint32_t g, uint8_t hooks)
{
    char path[512];
    FILE *f;
    uint64_t batch = 0;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    if (!(f = fopen(path, "wb"))) return 0;
    fputc(g == 0 ? 1 : (int)((g - 1) << 1), f);
    fputc(hooks, f);
    for (size_t i = 0; i < h->p[g].n_recs; i++) {
        const h_rec_t *r = &h->p[g].recs[i];
        uint8_t b[7];
        if (r->len > 0xffff) continue;
        if (i && r->batch != batch) fputc(0, f);
        batch = r->batch;
        b[0] = 1;
        for (int k = 0; k < 4; k++) b[1 + k] = (uint8_t)(r->type >> (8 * k));
        b[5] = (uint8_t)r->len; b[6] = (uint8_t)(r->len >> 8);
        fwrite(b, 1, 7, f);
        fwrite(r->b, 1, r->len, f);
    }
    /* a tick and one message after the start: the proposal the host sent first, again */
    fputc(3, f);
    if (h->n_sent && h->sent[0].len <= 0xffff) {
        uint8_t m[4] = {2, 0, (uint8_t)h->sent[0].len, (uint8_t)(h->sent[0].len >> 8)};
        fwrite(m, 1, 4, f);
        fwrite(h->sent[0].b, 1, h->sent[0].len, f);
    }
    fclose(f);
    return 1;
}

static int replay_seeds(const char *dir)
{
    harness_t h;
    int ok = 1;
    /* a whole two-tier round: every party's journal */
    h_init(&h, 3);
    CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
    h_flush(&h, 100000);
    ok &= write_journal(dir, "host-done", &h, 0, 1) && write_journal(dir, "member-done", &h, 1, 1);
    h_free(&h);
    /* a member after its partial signatures, a host collecting them */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (h.nq && h_count_kind(&h, 2, GZ_SIGN_MSG_PARTIALS) == 0) h_deliver(&h, 0, 0);
    ok &= write_journal(dir, "member-signed", &h, 2, 0) && write_journal(dir, "host-collecting", &h, 0, 0);
    h_free(&h);
    /* a member in the nonce phase */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    while (h.nq && h_count_kind(&h, 3, GZ_SIGN_MSG_NONCES) == 0) h_deliver(&h, 0, 0);
    ok &= write_journal(dir, "member-nonces", &h, 3, 1);
    h_free(&h);
    return ok && check_done() == 0 ? 0 : 1;
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
    CHECK(w_begin_params(h.p[0].e, &h.builder, p, W_PARAMS, &small) == GZ_ERR_NO_SPACE && small.count == 0 && small.used == 0);
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
    for (uint32_t g = 1; g <= 3; g++) CHECK(h.p[g].e->n_exposures == (size_t)rounds && !h.p[g].e->exposures_lost);   /* C7: each kept */
    const h_sent_t *p0 = h_sent_kind(&h, 0, GZ_SIGN_MSG_PROPOSE, 0);
    size_t nonces = h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES);
    h_inject(&h, 0, 1, p0->b, p0->len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], R(GZ_SIGN_WHY_KNOWN_ROUND), WHOLE, 0, NULL) && h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == nonces);
    printf("  many rounds: %d, each party starts again; refused identifiers held %zu\n", rounds, h.p[1].e->n_known);
    h_free(&h);
}

/* Review A, F4: a member's signed abort. Reason 3 (it restarted) is honest
 * once in a lobby, the second is blamed; reason 6 (another round on its
 * outputs) is blamed unless the host holds another round on that outpoint. */
static void test_abort_blame(void)
{
    harness_t h;
    uint8_t buf[512], id[32];
    const gz_sign_round_t *r, *f;
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    r = h_newest(&h, 0);
    memcpy(id, r->id, 32);
    h_inject(&h, 1, 0, buf, make_abort(buf, id, 3, 1));                 /* party 1 is participant 1 */
    f = h_find(&h, 0, id);
    CHECK(f && f->state == GZ_SIGN_ROUND_FAILED && f->blamed == 0);
    r = h_newest(&h, 0);                                                /* the retry, everyone kept */
    CHECK(r && r->state == GZ_SIGN_ROUND_ACTIVE && memcmp(r->id, id, 32) != 0 && r->def.n_participants == 4);
    memcpy(id, r->id, 32);
    h_inject(&h, 1, 0, buf, make_abort(buf, id, 3, 1));                 /* a second restart in the lobby */
    f = h_find(&h, 0, id);
    CHECK(f && f->state == GZ_SIGN_ROUND_FAILED && f->blamed == 2u);
    r = h_newest(&h, 0);                                                /* the retry leaves party 1 out */
    CHECK(r && r->state == GZ_SIGN_ROUND_ACTIVE && r->def.n_participants == 3 && r->def.peer[1] == 2);
    memcpy(id, r->id, 32);
    h_inject(&h, 2, 0, buf, make_abort(buf, id, 6, 2));                 /* no other round on its outpoint */
    f = h_find(&h, 0, id);
    CHECK(f && f->state == GZ_SIGN_ROUND_FAILED && f->blamed == 2u);
    h_free(&h);
    /* reason 6 while the host holds a finished round on the same outpoint: not blamed */
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    h_flush(&h, 100000);
    CHECK(h_newest(&h, 0)->state == GZ_SIGN_ROUND_DONE);
    CHECK(h_begin(&h, 1, 3, WF_SAME_TREE) == GZ_OK);
    r = h_newest(&h, 0);
    memcpy(id, r->id, 32);
    h_inject(&h, 1, 0, buf, make_abort(buf, id, 6, 1));
    f = h_find(&h, 0, id);
    CHECK(f && f->state == GZ_SIGN_ROUND_FAILED && f->blamed == 0);
    /* and a new lobby (the program's next begin) forgets who restarted */
    h_free(&h);
}

/* Review A, F6: a tier result that names an item of the tier the member does
 * not sign, with that item's valid final signature, in place of one of its
 * own. The count still matches; the member must refuse it (Unfinished,
 * nothing saved, no partial signature for the next tier: C6). */
static void test_result_foreign_item(void)
{
    harness_t h;
    static uint8_t bad[GZ_SIGN_MAX_MSG];
    gz_sign_msg_t msg;
    h_init(&h, 3);
    CHECK(h_begin(&h, 2, 3, 0) == GZ_OK);
    while (h.nq && q_find(&h, 0, 1, GZ_SIGN_MSG_RESULT) < 0) h_deliver(&h, 0, 0);
    long i = q_find(&h, 0, 1, GZ_SIGN_MSG_RESULT);
    CHECK(i >= 0);
    if (i < 0) { h_free(&h); return; }
    const gz_sign_round_t *hr = h_newest(&h, 0), *m = h_newest(&h, 1);
    size_t len = h.q[i].len;
    memcpy(bad, h.q[i].b, len);
    CHECK(gz_sign_decode(bad, len, &msg) && msg.n >= 1);
    uint32_t k = 0xffffffffu;
    for (uint32_t x = 0; x < hr->def.n_items && k == 0xffffffffu; x++)
        if (hr->def.items[x].tier == msg.tier && !items_of_has(hr, m->me, (int)x) && hr->have_final[x]) k = x;
    CHECK(k != 0xffffffffu);
    if (k == 0xffffffffu) { h_free(&h); return; }
    uint8_t *e0 = (uint8_t *)(uintptr_t)msg.entry[0];
    e0[0] = (uint8_t)(k >> 24); e0[1] = (uint8_t)(k >> 16); e0[2] = (uint8_t)(k >> 8); e0[3] = (uint8_t)k;
    memcpy(e0 + 4, hr->final_sig[k], 64);
    w_resign(bad, len, 0);
    h_drop_msg(&h, (size_t)i);
    size_t recs = h.p[1].n_recs, psigs = h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS), nonces = h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES);
    h_inject(&h, 0, 1, bad, len);
    CHECK(m->state == GZ_SIGN_ROUND_UNFINISHED && m->why == GZ_SIGN_WHY_BAD_RESULT && h.p[1].n_recs == recs);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_PARTIALS) == psigs && h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == nonces);
    h_free(&h);
}

/* Review A, F7 (D11): a proposal whose envelope scope is not the lobby the
 * builder names, validly signed by the host: refused as an invalid round. */
static void test_proposal_scope(void)
{
    harness_t h;
    static uint8_t bad[GZ_SIGN_MAX_PROPOSAL];
    h_init(&h, 3);
    CHECK(h_begin(&h, 1, 3, 0) == GZ_OK);
    long i = q_find(&h, 0, 1, GZ_SIGN_MSG_PROPOSE);
    CHECK(i >= 0);
    if (i < 0) { h_free(&h); return; }
    size_t len = h.q[i].len;
    memcpy(bad, h.q[i].b, len);
    bad[6] ^= 1;                                                        /* the envelope's scope */
    w_resign(bad, len, 0);
    h_drop_msg(&h, (size_t)i);
    size_t nonces = h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES);
    h_inject(&h, 0, 1, bad, len);
    CHECK(check_abort(&h.sent[h.n_sent - 1], R(GZ_SIGN_WHY_INVALID_ROUND), WHOLE, 0, NULL) && h.sent[h.n_sent - 1].party == 1);
    CHECK(h_count_kind(&h, 1, GZ_SIGN_MSG_NONCES) == nonces && h_newest(&h, 1) == NULL);
    h_free(&h);
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "replay-seeds")) return replay_seeds(argv[2]);
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
    SECTION("errors", (test_errors(), test_eviction_order(), test_abort_blame(), test_result_foreign_item(), test_proposal_scope(), test_many_rounds(g_quick ? 60 : 1000)));
    printf("  illegal-argument callbacks: %d\n", g_illegal);
    CHECK(g_illegal == 0);
    if (g_ctx) secp256k1_context_destroy(g_ctx);
    return check_done();
}
