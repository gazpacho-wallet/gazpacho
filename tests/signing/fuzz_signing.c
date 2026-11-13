/* Fuzzing of every decoder the signing engine has: messages, transactions and
 * its own journal records, alone and inside running rounds. Random mutation
 * of real inputs, seeded and repeatable; not coverage-guided (no such fuzzer
 * on the build machine). Meant to be run in the sanitizer build too.
 *
 * usage: fuzz_signing [ITERATIONS [SIM_SEEDS]]   (default 20000 20) */
#include "world.h"
#include "../check.h"

typedef struct { uint8_t *b; size_t len; } sample_t;
static sample_t g_samples[512];
static size_t g_n_samples;
static uint64_t g_lcg = 88172645463325252ull;
static uint64_t rnd(void) { g_lcg = g_lcg * 6364136223846793005ull + 1442695040888963407ull; return g_lcg >> 33; }

static void keep_sample(void *ctx, uint32_t index, const gz_action_t *a)
{
    w_observe(ctx, index, a);
    if (g_n_samples < 512 && a->u.send.bytes.len) {
        g_samples[g_n_samples].b = malloc(a->u.send.bytes.len);
        memcpy(g_samples[g_n_samples].b, a->u.send.bytes.data, a->u.send.bytes.len);
        g_samples[g_n_samples++].len = a->u.send.bytes.len;
    }
}

static size_t mutate(uint8_t *b, size_t len, size_t cap)
{
    switch (rnd() % 6) {
    case 0: for (int i = 0; i < 1 + (int)(rnd() % 8) && len; i++) b[rnd() % len] ^= (uint8_t)(1u << rnd() % 8); return len;
    case 1: return len ? (size_t)(rnd() % len) : 0;
    case 2: { size_t add = rnd() % 64; if (len + add > cap) add = cap - len; for (size_t i = 0; i < add; i++) b[len + i] = (uint8_t)rnd(); return len + add; }
    case 3: if (len > 40) { b[35 + rnd() % 6] = (uint8_t)rnd(); } return len;
    case 4: if (len) memset(b + rnd() % len, rnd() % 2 ? 0xff : 0, 1 + rnd() % 8 > len ? 1 : 1 + rnd() % 8); return len;
    default: { size_t n = rnd() % cap; for (size_t i = 0; i < n; i++) b[i] = (uint8_t)rnd(); return n; }
    }
}

/* A decoded message must point only inside its bytes. */
static int decoded_sane(const uint8_t *b, size_t len, const gz_sign_msg_t *m)
{
    if (m->signed_len > len || (m->sig && (m->sig < b || m->sig + 64 > b + len))) return 0;
    for (int i = 0; i < m->n; i++) if (m->entry[i] < b || m->entry[i] + 4 > b + len) return 0;
    return m->kind >= GZ_SIGN_MSG_PROPOSE && m->kind <= GZ_SIGN_MSG_ABORT;
}

/* A reader over a list of (type, bytes) records, one per batch. */
typedef struct { gz_record_t recs[256]; size_t n, at; } fz_store_t;
static int fz_next(void *ctx, gz_stored_batch_t *b)
{
    fz_store_t *s = ctx;
    if (s->at >= s->n) return 0;
    b->id.incarnation = 1; b->id.sequence = s->at + 1;
    b->records = &s->recs[s->at++]; b->n_records = 1;
    return 1;
}
static void fz_rewind(void *ctx) { ((fz_store_t *)ctx)->at = 0; }
static void fz_fill(void *ctx, gz_random_purpose_t purpose, uint8_t *out, size_t len) { (void)ctx; (void)purpose; for (size_t i = 0; i < len; i++) out[i] = (uint8_t)rnd(); }
static uint64_t fz_now(void *ctx) { (void)ctx; return 0; }

int main(int argc, char **argv)
{
    long iterations = argc > 1 ? atol(argv[1]) : 20000, seeds = argc > 2 ? atol(argv[2]) : 20;
    static world_t w;
    static uint8_t buf[GZ_SIGN_MAX_MSG + 64];
    uint64_t accepted = 0, fuzzed = 0, journal_ok = 0, journal_corrupt = 0;

    /* 1. Real messages and journals from an honest two-tier round. */
    sim_config_t c = w_config(&w, 4242, 4);
    c.ops.observe = keep_sample;
    sim_t *sim = sim_create(&c);
    uint8_t p[W_PARAMS];
    w_params(p, 2, 1, w_mask(4), 0);
    sim_user_command(sim, 0, p, sizeof p);
    sim_run(sim, 400);
    CHECK(gz_sign_latest(&w.nodes[0]->eng) && gz_sign_latest(&w.nodes[0]->eng)->state == GZ_SIGN_ROUND_DONE);
    CHECK(g_n_samples > 20);

    /* 2. Message decoder. */
    for (long it = 0; it < iterations; it++) {
        const sample_t *s = &g_samples[rnd() % g_n_samples];
        memcpy(buf, s->b, s->len);
        size_t len = mutate(buf, s->len, sizeof buf);
        gz_sign_msg_t m;
        if (gz_sign_decode(buf, len, &m)) { accepted++; CHECK(decoded_sane(buf, len, &m)); }
    }
    /* 3. Transaction reader, attach and verify. */
    gz_sign_def_t d;
    CHECK(w_build_tree(p, W_PARAMS, &d, NULL));
    for (long it = 0; it < iterations; it++) {
        const gz_sign_item_t *item = &d.items[rnd() % d.n_items];
        uint8_t out[GZ_SIGN_MAX_TX + 200], sig[64] = {1};
        gz_sign_tx_t tx;
        memcpy(buf, item->tx, item->tx_len);
        size_t len = mutate(buf, item->tx_len, GZ_SIGN_MAX_TX + 64);
        if (gz_sign_tx_parse(buf, len, &tx)) {
            CHECK(tx.outputs_at <= tx.outputs_end && tx.outputs_end <= len && tx.outpoint + 36 <= buf + len);
            uint8_t h[32];
            gz_sign_tx_sighash(&tx, item->spent_amount, item->spent_script, h);
        }
        size_t n = gz_sign_tx_attach(buf, len, sig, out, sizeof out);
        if (n) CHECK(!gz_sign_tx_verify(w_ctx(), out, n, item->spent_amount, item->spent_script));
    }
    /* 4. The engine's own journal, damaged one record at a time, read by a fresh engine. */
    static gz_sign_t eng;
    for (uint32_t node = 0; node < 2; node++) {
        const sim_storage_t *st = sim_node_storage(sim, node);
        static fz_store_t store;
        static uint8_t copies[256][GZ_SIGN_MAX_MSG / 8];
        for (long it = 0; it < iterations / 10; it++) {
            store.n = 0;
            for (size_t i = 0; i < sim_storage_count(st) && store.n < 256; i++) {
                size_t len;
                const uint8_t *b = sim_storage_batch_bytes(st, i, &len);
                uint32_t l = (uint32_t)b[4] | (uint32_t)b[5] << 8 | (uint32_t)b[6] << 16 | (uint32_t)b[7] << 24;
                if (l > sizeof copies[0] - 64) continue;
                memcpy(copies[store.n], b + 8, l);
                store.recs[store.n].type = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
                store.recs[store.n].bytes.data = copies[store.n];
                store.recs[store.n].bytes.len = l;
                store.n++;
            }
            if (!store.n) break;
            size_t victim = rnd() % store.n;
            store.recs[victim].bytes.len = mutate(copies[victim], store.recs[victim].bytes.len, sizeof copies[0]);
            if (rnd() % 8 == 0) store.recs[victim].type ^= 1u << (rnd() % 32);
            gz_sign_config_t cfg;
            memset(&cfg, 0, sizeof cfg);
            cfg.host = node == 0; cfg.ctx = w_ctx();
            w_secret("test/factory", node, cfg.factory_secret);
            w_secret("test/contribution", node, cfg.contribution_secret);
            cfg.build = w_build; cfg.retry = w_retry; cfg.build_ctx = &w.builder;
            cfg.tick_ms = 1; cfg.resend_ticks = 4; cfg.deadline_ticks = 80; cfg.max_attempts = 4;
            gz_ports_t ports = {{fz_fill, NULL}, {fz_now, NULL}};
            CHECK(gz_sign_init(&eng, &cfg, &ports, 2) == GZ_OK);
            gz_storage_reader_t reader = {fz_next, fz_rewind, &store, 2, 0};
            static gz_action_t slots[256];
            static uint8_t bytes[1u << 20];
            gz_action_list_t list;
            int more = 1;
            gz_action_list_init(&list, slots, 256, bytes, sizeof bytes);
            gz_status_t r = gz_sign_start(&eng, &reader, &list, &more);
            if (r != GZ_OK && r != GZ_ERR_CORRUPT) printf("  journal start: status %d\n", (int)r);
            CHECK(r == GZ_OK || r == GZ_ERR_CORRUPT);
            if (r == GZ_OK) journal_ok++; else journal_corrupt++;
            gz_sign_wipe(&eng);
        }
    }
    sim_destroy(sim);

    /* 5. Running rounds with damaged traffic from every party, network faults on. */
    for (long seed = 0; seed < seeds; seed++) {
        free(w.seen); free(w.contrib);
        memset(&w, 0, sizeof w);
        w.fuzz_pm = 150; w.fuzz_state = (uint64_t)seed + 1;
        c = w_config(&w, 70000 + (uint64_t)seed, 3 + (uint32_t)(seed % 2));
        c.drop_pm = 50; c.duplicate_pm = 100; c.reorder_pm = 200; c.crash_pm = 5;
        sim = sim_create(&c);
        sim_add_invariant(sim, w_secrets_ok, &w);
        w_params(p, (uint8_t)(1 + seed % 2), 1, w_mask(3 + (uint32_t)(seed % 2)), 0);
        sim_user_command(sim, 0, p, sizeof p);
        sim_run(sim, 800);
        if (sim_failed(sim)) printf("  fuzz seed %ld: %s at %llu\n", seed, sim_failure_reason(sim), (unsigned long long)sim_failure_step(sim));
        CHECK(!sim_failed(sim));
        fuzzed += w.fuzzed;
        sim_destroy(sim);
    }
    printf("  decoder: %ld inputs, %llu accepted; journals: %llu read, %llu refused as corrupt; rounds: %ld, %llu messages damaged\n",
           iterations, (unsigned long long)accepted, (unsigned long long)journal_ok, (unsigned long long)journal_corrupt,
           seeds, (unsigned long long)fuzzed);
    CHECK(fuzzed > 0 && journal_corrupt > 0 && accepted > 0);
    CHECK(g_illegal == 0);
    for (size_t i = 0; i < g_n_samples; i++) free(g_samples[i].b);
    free(w.seen); free(w.contrib);
    secp256k1_context_destroy(g_ctx);
    return check_done();
}
