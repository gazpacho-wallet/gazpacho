/* The signing engine behind the node's two calls (core/signing/signing_node.c):
 * the routing a composite node uses, node rule 5 at the seam, and whole
 * rounds in the simulator with every party reached only through the
 * adapter, crashes, restores and network faults on. */
#include "gazpacho/signing_node.h"
#include "world.h"
#include "../check.h"

static gz_sign_node_t g_nodes[W_MAX_NODES];

/* The composite's start: its restore batch first (journal.md 8.2), then the engine through the adapter. */
static gz_status_t n_start(void *node, gz_action_list_t *out, int *more)
{
    w_node_t *n = node;
    int restored = sim_storage_restored(n->storage);
    gz_storage_reader_t r = {w_next, w_rewind, n, sim_storage_incarnation(n->storage), restored};
    g_nodes[n->index].engine = &n->eng;
    g_nodes[n->index].started = 0;
    if (restored) {
        uint8_t ep[4];
        w_wr32(ep, n->index ? n->w->builder.epoch[n->index] : 0);
        gz_record_t rec = {W_REC_KEY_EPOCH, {ep, 4}};
        gz_action_t a = {.kind = GZ_ACTION_SAVE};
        a.u.save.records = &rec; a.u.save.n_records = 1;
        gz_status_t s0 = gz_action_list_add(out, &a);
        if (s0 != GZ_OK) return s0;
    }
    return gz_sign_node_start(&g_nodes[n->index], &r, out, more);
}

static gz_status_t n_handle(void *node, const gz_event_t *ev, gz_action_list_t *out)
{
    w_node_t *n = node;
    if (ev->kind == GZ_EVENT_USER_COMMAND) {           /* the composite's: the host begins */
        gz_status_t st = w_begin_params(&n->eng, &n->w->builder, ev->u.user.bytes.data, ev->u.user.bytes.len, out);
        return st == GZ_ERR_ARGUMENT ? GZ_OK : st;
    }
    return gz_sign_node_handle(&g_nodes[n->index], ev, out);
}

static void test_routing(void)
{
    gz_event_t ev;
    uint8_t env[GZ_RMSG_HEADER] = {0x67, 0x7a, 0x66, 0x01, 0, 64};
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_MESSAGE_RECEIVED; ev.u.message.bytes.data = env; ev.u.message.bytes.len = sizeof env;
    for (unsigned k = 0; k < 0x200; k++) {             /* the round kinds, 64 to 81, and nothing else */
        env[4] = (uint8_t)(k >> 8); env[5] = (uint8_t)k;
        CHECK(gz_sign_node_wants(&ev) == (k >= 64 && k <= 81));
    }
    env[4] = 0; env[5] = 64;
    env[3] = 2; CHECK(!gz_sign_node_wants(&ev)); env[3] = 1;   /* another protocol */
    ev.u.message.bytes.len = GZ_RMSG_HEADER - 1; CHECK(!gz_sign_node_wants(&ev));
    ev.u.message.bytes.data = NULL; ev.u.message.bytes.len = 0; CHECK(!gz_sign_node_wants(&ev));
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_TIMER_FIRED; ev.u.timer.timer_id = 0x5347u; CHECK(gz_sign_node_wants(&ev));
    ev.u.timer.timer_id = 1; CHECK(!gz_sign_node_wants(&ev));
    ev.kind = GZ_EVENT_PEER_CONNECTED; CHECK(gz_sign_node_wants(&ev));
    ev.kind = GZ_EVENT_PEER_DISCONNECTED; CHECK(!gz_sign_node_wants(&ev));
    ev.kind = GZ_EVENT_STORAGE_CONFIRMED; CHECK(!gz_sign_node_wants(&ev));
    ev.kind = GZ_EVENT_USER_COMMAND; CHECK(!gz_sign_node_wants(&ev));
    CHECK(!gz_sign_node_wants(NULL));
}

static int nothing(void *ctx, gz_stored_batch_t *b) { (void)ctx; (void)b; return 0; }
static void norewind(void *ctx) { (void)ctx; }
static void fill(void *ctx, gz_random_purpose_t p, uint8_t *out, size_t len) { (void)ctx; (void)p; for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(i * 7 + 1); }
static uint64_t now(void *ctx) { (void)ctx; return 0; }

static void test_seam(void)
{
    static gz_sign_t e;
    static w_builder_t b;
    static gz_action_t slots[16];
    static uint8_t bytes[4096];
    gz_sign_node_t n;
    gz_sign_config_t c;
    gz_ports_t ports = {{fill, NULL}, {now, NULL}};
    gz_storage_reader_t r = {nothing, norewind, NULL, 3, 1};
    gz_action_list_t l;
    gz_event_t ev;
    int more = 1;
    memset(&c, 0, sizeof c);
    c.ctx = w_ctx(); c.build = w_build; c.build_ctx = &b; c.tick_ms = 1;
    w_secret("test/factory", 1, c.factory_secret); w_secret("test/contribution", 1, c.contribution_secret);
    CHECK(gz_sign_node_init(&n, &e, &c, &ports, 3) == GZ_OK);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_TIMER_FIRED; ev.u.timer.timer_id = 0x5347u;
    gz_action_list_init(&l, slots, 16, bytes, sizeof bytes);
    CHECK(gz_sign_node_handle(&n, &ev, &l) == GZ_ERR_ARGUMENT);          /* not before the start */
    /* a restored start with nothing listed before it: refused, nothing done */
    CHECK(gz_sign_node_start(&n, &r, &l, &more) == GZ_ERR_ARGUMENT && l.count == 0 && more == 1);
    /* with the node's restore batch first: the engine starts after it */
    uint8_t ep[4] = {0, 0, 0, 7};
    gz_record_t rec = {W_REC_KEY_EPOCH, {ep, 4}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &rec; a.u.save.n_records = 1;
    CHECK(gz_action_list_add(&l, &a) == GZ_OK);
    CHECK(gz_sign_node_start(&n, &r, &l, &more) == GZ_OK && more == 0 && l.slots[0].kind == GZ_ACTION_SAVE);
    CHECK(l.count == 2 && l.slots[1].kind == GZ_ACTION_SET_TIMER);      /* re-armed at start (node.h rule 4) */
    /* events that are not the engine's: nothing */
    gz_action_list_init(&l, slots, 16, bytes, sizeof bytes);
    ev.u.timer.timer_id = 99;
    CHECK(gz_sign_node_handle(&n, &ev, &l) == GZ_OK && l.count == 0);
    ev.u.timer.timer_id = 0x5347u;
    CHECK(gz_sign_node_handle(&n, &ev, &l) == GZ_OK && l.count == 1);   /* its timer: set again */
    gz_sign_wipe(&e);
}

static void test_rounds(uint64_t seeds)
{
    static world_t w;
    uint32_t done = 0, runs = 0;
    for (uint64_t seed = 1; seed <= seeds; seed++) {
        free(w.seen); free(w.contrib);
        memset(&w, 0, sizeof w);
        sim_config_t c = w_config(&w, 81000 + seed, 3);
        c.ops.start = n_start; c.ops.handle = n_handle;
        c.drop_pm = 50; c.duplicate_pm = 100; c.reorder_pm = 200;
        if (seed % 2 == 0) c.crash_pm = 10;
        if (seed % 3 == 0) { c.restore_pm = 5; c.restore_repeats_random = 1; }
        sim_t *sim = sim_create(&c);
        sim_add_invariant(sim, w_secrets_ok, &w);
        uint8_t p[W_PARAMS];
        w_params(p, (uint8_t)(1 + seed % 2), 1, w_mask(3), 0);
        sim_user_command(sim, 0, p, sizeof p);
        for (int quiet = 0; quiet < 2; quiet++) {
            for (int s = 0; s < (quiet ? 3000 : 1500) && !sim_failed(sim); s++) {
                sim_step(sim);
                const gz_sign_round_t *r = w.nodes[0] ? gz_sign_latest(&w.nodes[0]->eng) : NULL;
                if (w.nodes[0] && !r && s % 20 == 19) sim_user_command(sim, 0, p, sizeof p);
                if (r && r->state == GZ_SIGN_ROUND_DONE) break;
            }
            if (!quiet) sim_quiesce(sim);
        }
        if (sim_failed(sim)) printf("  seed %llu: %s\n", (unsigned long long)seed, sim_failure_reason(sim));
        CHECK(!sim_failed(sim));
        const gz_sign_round_t *r = w.nodes[0] ? gz_sign_latest(&w.nodes[0]->eng) : NULL;
        done += r && r->state == GZ_SIGN_ROUND_DONE;
        runs++;
        sim_destroy(sim);
    }
    printf("  rounds through the adapter: %u of %u done\n", done, runs);
    CHECK(done == runs);
    free(w.seen); free(w.contrib);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_routing();
    test_seam();
    test_rounds(argc > 1 && !strcmp(argv[1], "tiny") ? 3 : 6);   /* tiny: for valgrind */
    printf("  illegal-argument callbacks: %d\n", g_illegal);
    CHECK(g_illegal == 0);
    if (g_ctx) secp256k1_context_destroy(g_ctx);
    return check_done();
}
