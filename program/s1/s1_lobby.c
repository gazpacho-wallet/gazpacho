/* slice1-attempt: the lobby engine, its crypto port and the test terms. */
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include "gazpacho/lobby.h"
#include "s1.h"

static gz_lobby_host_t H;
static gz_lobby_member_t M;

/* ---- crypto port ---- */
static int c_verify(void *ctx, const uint8_t pub[33], const uint8_t msg[32], const uint8_t sig[64])
{
    (void)ctx;
    secp256k1_xonly_pubkey x;
    if (!secp256k1_xonly_pubkey_parse(G.secp, &x, pub + 1)) return 0;
    return secp256k1_schnorrsig_verify(G.secp, sig, msg, 32, &x);
}
static int c_point_ok(void *ctx, const uint8_t pub[33])
{
    (void)ctx;
    secp256k1_pubkey p;
    return (pub[0] == 2 || pub[0] == 3) && secp256k1_ec_pubkey_parse(G.secp, &p, pub, 33);
}
static int c_sign(void *ctx, uint32_t which, const uint8_t msg[32], uint8_t sig[64])
{
    (void)ctx;
    const uint8_t *sk = which == GZ_LOBBY_KEY_HOST ? G.host_sk
                      : which == GZ_LOBBY_KEY_CONTRIBUTION ? G.ckey_sk
                      : which == GZ_LOBBY_KEY_FACTORY ? G.fkey_sk : NULL;
    if (!sk) return 0;
    secp256k1_keypair kp;
    uint8_t aux[32];
    G.ports.random.fill(G.ports.random.ctx, GZ_RANDOM_ORDINARY, aux, 32);
    int ok = secp256k1_keypair_create(G.secp, &kp, sk) && secp256k1_schnorrsig_sign32(G.secp, sig, msg, &kp, aux);
    memset(&kp, 0, sizeof kp);
    return ok;
}
static gz_lobby_crypto_t CRYPTO = {c_verify, c_point_ok, c_sign, NULL};

/* ---- the signing hand-off ---- */
static gz_status_t s_begin(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out)
{
    (void)ctx;
    static s1_handoff_t x;
    memset(&x, 0, sizeof x);
    x.role = h->role;
    memcpy(x.scope, h->scope, 32);
    memcpy(x.current_digest, h->current_digest, 32);
    x.version = h->version;
    x.outer = h->outer; x.outer_len = h->outer_len;
    x.current = h->current; x.current_len = h->current_len;
    if (h->participants) {
        if (h->n_participants > S1_MAX_PARTS) { s1_log("lobby: too many participants %u", h->n_participants); return GZ_ERR_ARGUMENT; }
        x.n_parts = h->n_participants;
        for (int i = 0; i < h->n_participants; i++) {
            memcpy(x.parts[i].fkey, h->participants[i].factory_key, 33);
            memcpy(x.parts[i].ckey, h->participants[i].contribution_key, 33);
            memcpy(x.parts[i].bind_f, h->participants[i].bind_by_factory, 64);
            memcpy(x.parts[i].bind_c, h->participants[i].bind_by_contribution, 64);
        }
    }
    s1_log("lobby: hand-off to signing: role %d, signers %u, version %u, levels %u D %u", h->role, h->signers,
           h->version, h->n_levels, h->fixed_levels);
    return s1_sign_begin(&x, out) ? GZ_OK : GZ_ERR_ARGUMENT;
}
static gz_status_t s_cancel(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out)
{
    (void)ctx; (void)scope; (void)out;
    s1_log("lobby: cancel reached signing, reason %u", reason);
    return GZ_OK;
}
static gz_lobby_signing_t SIGNING = {s_begin, s_cancel, NULL};

static void check(gz_status_t st, const char *what)
{
    if (st != GZ_OK) { s1_log("lobby call %s failed: %d", what, (int)st); s1_die("lobby engine error (fatal, as lobby.h says)"); }
}

/* ---- host ---- */
void s1_lobby_host_open(uint16_t target, uint16_t minimum, uint64_t channel_sat, uint8_t scope_out[32])
{
    static gz_lterms_outer_t o;
    static gz_lterms_current_t c;
    static uint8_t outer[GZ_TERMS_OUTER_MAX], cur[GZ_TERMS_CURRENT_MAX];
    gz_lobby_host_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, G.fkey_pk, 33);
    cfg.listed = 1;
    cfg.network = GZ_LOBBY_NET_SIGNET;
    check(gz_lobby_host_init(&H, &G.ports, &CRYPTO, &SIGNING, &cfg), "host_init");

    memset(&o, 0, sizeof o);
    memcpy(o.chain, gz_lterms_genesis(GZ_LOBBY_NET_SIGNET), 32);
    memcpy(o.host_key, G.host_pk, 33);
    G.ports.random.fill(G.ports.random.ctx, GZ_RANDOM_ORDINARY, o.salt, 16);
    o.profile = 2; o.on_shortfall = 0; o.switches = 0;
    o.target = target; o.minimum = minimum;
    o.deadline = G.ports.clock.now_ms(G.ports.clock.ctx) / 1000 + 3600;
    o.ready_window_ms = 30000; o.signing_budget_ms = 600000; o.step_timeout_ms = 60000;
    o.lifetime_blocks = 144; o.winddown_blocks = 36; o.tree_feerate = 100; o.channel_sat = channel_sat;
    o.n_shapes = 2;
    o.shapes[0].max_members = 4; o.shapes[0].n_interior = 0; o.shapes[0].leaf_kind = 3;
    o.shapes[1].max_members = 16; o.shapes[1].n_interior = 1; o.shapes[1].interior[0] = 4; o.shapes[1].leaf_kind = 3;
    o.n_adj = 3;
    o.adj[0].type = 64; o.adj[0].min = 0; o.adj[0].max = 2000;
    o.adj[1].type = 66; o.adj[1].min = 0; o.adj[1].max = 1000;
    o.adj[2].type = 68; o.adj[2].min = 100; o.adj[2].max = 2500;
    size_t olen = gz_lterms_outer_encode(&o, outer, sizeof outer);
    if (!olen) s1_die("outer terms do not encode");
    gz_lterms_outer_t od;
    if (!gz_lterms_outer_decode(outer, olen, &od)) s1_die("outer terms do not decode");
    memset(&c, 0, sizeof c);
    gz_lterms_outer_digest(outer, olen, c.outer_digest);
    c.version = 1; c.n_adj = 3;
    c.adj_type[0] = 64; c.adj_value[0] = 500;
    c.adj_type[1] = 66; c.adj_value[1] = 1000;
    c.adj_type[2] = 68; c.adj_value[2] = 1000;
    size_t clen = gz_lterms_current_encode(&c, &od, cur, sizeof cur);
    if (!clen) s1_die("current terms do not encode");
    memcpy(scope_out, c.outer_digest, 32);
    gz_action_list_t *l = s1_list();
    check(gz_lobby_host_open(&H, outer, olen, cur, clen, l), "host_open");
    s1_exec(l);
    s1_log("lobby: opened, target %u minimum %u channel %llu sat, outer %zu bytes, current %zu bytes", target, minimum,
           (unsigned long long)channel_sat, olen, clen);
}

void s1_lobby_round_result(int outcome)
{
    gz_action_list_t *l = s1_list();
    check(gz_lobby_host_round_result(&H, outcome, NULL, 0, l), "round_result");
    s1_exec(l);
    s1_log("lobby: round result %d given; lobby state %d", outcome, H.state);
}

/* ---- member ---- */
void s1_lobby_member_init(const uint8_t scope[32], const uint8_t host_key[33])
{
    gz_lobby_conditions_t cond;
    memset(&cond, 0, sizeof cond);
    cond.profiles = 1u << 2;
    cond.life_min = 100; cond.life_max = 1000; cond.wind_max = 500; cond.rate_max = 1000;
    cond.chan_min = G.member_bad ? 200000 : 50000;   /* the refusing member wants more than the terms give */
    cond.adj_max[0] = 2000; cond.adj_max[1] = 1000; cond.adj_max[2] = 2500;
    cond.min_members = 3;
    check(gz_lobby_member_init(&M, &G.ports, &CRYPTO, &SIGNING, &cond, scope, host_key, G.ckey_pk, G.fkey_pk, 1),
          "member_init");
    s1_log("lobby: member ready to join, own minimum channel %llu sat", (unsigned long long)cond.chan_min);
}

int s1_lobby_member_records(const uint8_t **outer, size_t *outer_len, const uint8_t **outer_sig,
                            const uint8_t **current, size_t *current_len, const uint8_t **current_sig)
{
    if (!M.have_terms) return 0;
    *outer = M.outer; *outer_len = M.outer_len; *outer_sig = M.outer_sig;
    *current = M.current; *current_len = M.current_len; *current_sig = M.current_sig;
    return 1;
}

/* ---- inputs ---- */
static void feed(const gz_lobby_input_t *in)
{
    gz_action_list_t *l = s1_list();
    check(G.host ? gz_lobby_host_handle(&H, in, l) : gz_lobby_member_handle(&M, in, l), "handle");
    s1_exec(l);
}
void s1_lobby_connected(uint64_t conn, const uint8_t key[33])
{
    gz_lobby_input_t in = {.kind = GZ_LIN_CONNECTED, .peer_id = conn, .peer_key = key};
    feed(&in);
}
void s1_lobby_disconnected(uint64_t conn)
{
    gz_lobby_input_t in = {.kind = GZ_LIN_DISCONNECTED, .peer_id = conn};
    feed(&in);
}
void s1_lobby_message(uint64_t conn, const uint8_t *msg, size_t len)
{
    gz_lobby_input_t in = {.kind = GZ_LIN_MESSAGE, .peer_id = conn, .bytes = msg, .len = len};
    feed(&in);
}
void s1_lobby_timer(uint64_t id)
{
    gz_lobby_input_t in = {.kind = GZ_LIN_TIMER, .timer_id = id};
    feed(&in);
}
