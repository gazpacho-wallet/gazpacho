/* slice1-attempt: the signing engine, the builder from trees from terms, the
 * member's checks (gz_tree_import_member_check, gz_tree_may_ack), and the
 * host's funding and burial steps. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <secp256k1.h>
#include "gazpacho/signing.h"
#include "gazpacho/tree.h"
#include "gazpacho/tree_import.h"
#include "s1.h"

#define HOST_SELF_PEER UINT64_C(0xfffffffffffffff0)
#define CONFS_BURIED 3          /* B on signet (exit.md 4.3) */

static gz_sign_t *E;
static int inited;
static gz_tree_t *TREE;
static gz_tree_import_t *SCRATCH;
static gz_tree_crypto_t CR;

/* what this party knows of the lobby */
static uint8_t outer_rec[4096], current_rec[1024];
static size_t outer_len, current_len;
static uint8_t scope[32], frozen_digest[32];
static uint32_t frozen_version;
static gz_terms_outer_t T;
static gz_terms_current_t C;
static gz_tree_conditions_t COND;

/* the proposal as decoded (both sides) */
static gz_tree_proposal_t P;
static gz_tree_participant_t PARTS[S1_MAX_PARTS];
static uint8_t funding_tx[1024]; static size_t funding_tx_len;
static uint32_t n_nodes_sent;
static gz_tree_verdict_t VERDICT;
static int have_verdict;

/* progress */
static int round_logged, tree_written, ack_tip_set;
static uint32_t ack_tip;
static int fund_stage;          /* host: 1 all acks, 2 released, 3 broadcast, 4 active */
static uint64_t next_chain_ms;
static int member_live;
static uint8_t fund_raw[60000]; static size_t fund_raw_len;

static uint64_t now_ms(void) { return G.ports.clock.now_ms(G.ports.clock.ctx); }

/* ---- params: this attempt's own encoding of the proposal (messages.md 7.2 is not what the engine carries) ---- */
typedef struct { uint8_t *b; size_t n, cap; int bad; } wr_t;
static void put(wr_t *w, const void *d, size_t n) { if (w->n + n > w->cap) { w->bad = 1; return; } memcpy(w->b + w->n, d, n); w->n += n; }
static void put32(wr_t *w, uint32_t v) { uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v}; put(w, b, 4); }
static void put64(wr_t *w, uint64_t v) { put32(w, (uint32_t)(v >> 32)); put32(w, (uint32_t)v); }
typedef struct { const uint8_t *b; size_t n, at; int bad; } rd_t;
static void get(rd_t *r, void *d, size_t n) { if (r->at + n > r->n) { r->bad = 1; memset(d, 0, n); return; } memcpy(d, r->b + r->at, n); r->at += n; }
static uint32_t get32(rd_t *r) { uint8_t b[4]; get(r, b, 4); return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3]; }
static uint64_t get64(rd_t *r) { uint64_t h = get32(r); return h << 32 | get32(r); }

static size_t encode_params(uint8_t *out, size_t cap, const s1_part_t *parts, uint16_t n_parts)
{
    wr_t w = {out, 0, cap, 0};
    put32(&w, P.terms_version); put(&w, P.terms_digest, 32);
    put(&w, P.funding_txid, 32); put32(&w, P.funding_vout); put64(&w, P.funding_amount);
    put(&w, P.funding_script, 34);
    put32(&w, (uint32_t)funding_tx_len); put(&w, funding_tx, funding_tx_len);
    put32(&w, P.end_height); put64(&w, P.fee_per_tx); put32(&w, P.lstock_delay);
    put32(&w, P.fixed_levels); put32(&w, n_nodes_sent);
    put32(&w, P.nonces_due_ms); put32(&w, P.sigs_due_ms);
    put32(&w, n_parts);
    for (int i = 0; i < n_parts; i++) {
        put(&w, parts[i].fkey, 33); put(&w, parts[i].ckey, 33); put(&w, parts[i].bind_f, 64); put(&w, parts[i].bind_c, 64);
    }
    return w.bad ? 0 : w.n;
}

static int decode_params(const uint8_t *b, size_t n)
{
    rd_t r = {b, n, 0, 0};
    memset(&P, 0, sizeof P);
    P.purpose = 1;
    P.terms_version = get32(&r); get(&r, P.terms_digest, 32);
    get(&r, P.funding_txid, 32); P.funding_vout = get32(&r); P.funding_amount = get64(&r);
    get(&r, P.funding_script, 34); P.funding_script_len = 34;
    uint32_t tl = get32(&r);
    if (tl > sizeof funding_tx) return 0;
    get(&r, funding_tx, tl); funding_tx_len = tl;
    P.funding_tx = funding_tx; P.funding_tx_len = tl;
    P.end_height = get32(&r); P.fee_per_tx = get64(&r); P.lstock_delay = get32(&r);
    P.fixed_levels = (uint8_t)get32(&r); n_nodes_sent = get32(&r);
    P.nonces_due_ms = get32(&r); P.sigs_due_ms = get32(&r);
    uint32_t np = get32(&r);
    if (np < 2 || np > S1_MAX_PARTS) return 0;
    for (uint32_t i = 0; i < np; i++) {
        get(&r, PARTS[i].factory_key, 33); get(&r, PARTS[i].contribution_key, 33);
        get(&r, PARTS[i].bind_by_factory, 64); get(&r, PARTS[i].bind_by_contribution, 64);
    }
    P.participants = PARTS; P.n_participants = np;
    P.n_tiers = 1; P.tier_sizes[0] = n_nodes_sent;
    P.tree_anchors = 1; P.k = 1; P.layer_step = GZ_TREE_SLICE1_STEP; P.layer_states = GZ_TREE_SLICE1_STATES;
    P.n_lstock_hashes = 0; P.has_distribution = 0; P.placement = 0;
    return !r.bad && r.at == n;
}

static void tree_in_from_P(gz_tree_build_in_t *in, uint8_t levels[GZ_TREE_MAX_LEVELS], size_t n_levels,
                           uint8_t (*mkeys)[33])
{
    memset(in, 0, sizeof *in);
    in->levels = levels; in->n_levels = n_levels; in->fixed_levels = P.fixed_levels;
    in->n_members = (uint32_t)P.n_participants - 1;
    in->host_key = PARTS[0].factory_key;
    for (size_t i = 1; i < P.n_participants; i++) memcpy(mkeys[i - 1], PARTS[i].factory_key, 33);
    in->member_keys = (const uint8_t (*)[33])mkeys;
    in->end_height = P.end_height; in->fee_per_tx = P.fee_per_tx; in->lstock_csv = P.lstock_delay;
    memcpy(in->funding_txid, P.funding_txid, 32); in->funding_vout = P.funding_vout;
    in->funding_amount = P.funding_amount; memcpy(in->funding_script, P.funding_script, 34);
}

/* ---- the builder the engine calls with a proposal's parameters ---- */
static int build(void *ctx, const uint8_t *params, size_t len, gz_sign_def_t *out)
{
    (void)ctx;
    if (!decode_params(params, len)) { s1_log("sign: builder refused: parameters do not decode"); return 0; }
    if (G.host) {
        static uint8_t mkeys[S1_MAX_PARTS][33];
        uint8_t levels[GZ_TREE_MAX_LEVELS];
        const gz_shape_entry_t *e = gz_tree_shape_for(&T, (uint32_t)P.n_participants - 1);
        if (!e) { s1_log("sign: no shape"); return 0; }
        size_t nl = gz_tree_levels(e, levels);
        gz_tree_build_in_t in;
        tree_in_from_P(&in, levels, nl, mkeys);
        gz_tree_b_err_t be = gz_tree_build(&in, &CR, TREE);
        if (be != GZ_TREE_B_OK) { s1_log("sign: host tree build refused: %d", (int)be); return 0; }
    } else {
        gz_tree_member_in_t mi;
        const uint8_t *orec, *osig, *crec, *csig;
        size_t ol, cl;
        static gz_terms_policy_t pol = {1};
        if (!s1_lobby_member_records(&orec, &ol, &osig, &crec, &cl, &csig)) { s1_log("sign: no stored terms"); return 0; }
        memset(&mi, 0, sizeof mi);
        mi.outer = &T; mi.outer_digest = scope; mi.frozen = &C; mi.frozen_digest = frozen_digest;
        mi.outer_rec = outer_rec; mi.outer_rec_len = outer_len; mi.outer_sig = osig;
        mi.frozen_rec = current_rec; mi.frozen_rec_len = current_len; mi.frozen_sig = csig;
        (void)orec; (void)ol; (void)crec; (void)cl;
        mi.host_pinned_key = G.host_pk;
        mi.policy = &pol;
        mi.ready_outer_digest = scope; mi.ready_version = frozen_version; mi.ready_current_digest = frozen_digest;
        mi.own_factory_key = G.fkey_pk; mi.own_contribution_key = G.ckey_pk;
        mi.cond = &COND; mi.tip = G.tip;
        mi.crypto = &CR;
        gz_tree_import_member_check((secp256k1_context *)G.secp, &mi, &P, TREE, SCRATCH, &VERDICT);
        if (VERDICT.check != GZ_CHK_OK) {
            s1_log("sign: MEMBER CHECK REFUSED: %s (reason %u, at %d)", gz_chk_name(VERDICT.check), VERDICT.reason, VERDICT.at);
            return 0;
        }
        have_verdict = 1;
        char d[65]; s1_hex(d, VERDICT.tree_digest, 32);
        s1_log("sign: member check OK: own member %u depth %u leave_by %lld tree digest %s", VERDICT.own_member,
               VERDICT.own_depth, (long long)VERDICT.leave_by, d);
    }
    /* the round from the tree: node i is item i, tier 0, key path */
    memset(out, 0, sizeof *out);
    out->purpose = 1; out->n_tiers = 1;
    if (P.n_participants > GZ_SIGN_MAX_PARTICIPANTS || TREE->n_nodes > GZ_SIGN_MAX_ITEMS) {
        s1_log("sign: round too big for the engine: %zu participants, %u items", P.n_participants, TREE->n_nodes);
        return 0;
    }
    out->n_participants = (uint8_t)P.n_participants;
    for (size_t i = 0; i < P.n_participants; i++) {
        memcpy(out->participants[i].factory_key, PARTS[i].factory_key, 33);
        memcpy(out->participants[i].contribution_key, PARTS[i].contribution_key + 1, 32);   /* x-only */
        if (G.host) out->participants[i].peer = i == 0 ? HOST_SELF_PEER : s1_conn_for_key(PARTS[i].contribution_key);
        else out->participants[i].peer = i == 0 ? G.host_conn : UINT64_C(0x100000) + i;
        if (!out->participants[i].peer) { s1_log("sign: no connection for participant %zu", i); return 0; }
    }
    out->n_items = TREE->n_nodes;
    for (int i = 0; i < TREE->n_nodes; i++) {
        const gz_tree_node_t *nd = &TREE->node[i];
        gz_sign_item_t *it = &out->items[i];
        it->tier = 0; it->mode = GZ_SIGN_MODE_KEYPATH;
        it->has_merkle_root = nd->has_merkle; memcpy(it->merkle_root, nd->merkle, 32);
        if (1u + nd->count > GZ_SIGN_MAX_SIGNERS) { s1_log("sign: node %d has too many signers", i); return 0; }
        it->n_signers = (uint8_t)(1 + nd->count);
        it->signers[0] = 0;
        for (int k = 0; k < nd->count; k++) it->signers[1 + k] = (uint8_t)(1 + nd->first + k);
        it->spent_amount = nd->spent_amount; memcpy(it->spent_script, nd->spent_script, 34);
        if (nd->tx_len > GZ_SIGN_MAX_TX) { s1_log("sign: node %d tx %u bytes over the engine's limit", i, nd->tx_len); return 0; }
        it->tx_len = nd->tx_len; memcpy(it->tx, nd->tx, nd->tx_len);
    }
    return 1;
}

static int may_ack(void *ctx)
{
    (void)ctx;
    if (G.host || !have_verdict) return 1;
    ack_tip = G.tip; ack_tip_set = 1;
    int ok = gz_tree_may_ack(P.end_height, VERDICT.own_depth, ack_tip, &COND);
    s1_log("sign: gz_tree_may_ack(end %u, depth %u, tip %u) = %d", P.end_height, VERDICT.own_depth, ack_tip, ok);
    return ok;
}

/* ---- storage reader for the engine's start: empty (no restart in this attempt) ---- */
static int rd_next(void *ctx, gz_stored_batch_t *b) { (void)ctx; (void)b; return 0; }
static void rd_rewind(void *ctx) { (void)ctx; }

static int engine_init(void)
{
    if (inited) return 1;
    E = calloc(1, sizeof *E);
    TREE = calloc(1, sizeof *TREE);
    SCRATCH = calloc(1, sizeof *SCRATCH);
    if (!E || !TREE || !SCRATCH) s1_die("out of memory");
    gz_tree_secp_crypto((secp256k1_context *)G.secp, &CR);
    gz_sign_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.host = G.host; cfg.ctx = G.secp;
    memcpy(cfg.factory_secret, G.fkey_sk, 32);
    memcpy(cfg.contribution_secret, G.host ? G.host_sk : G.ckey_sk, 32);
    cfg.build = build; cfg.retry = NULL; cfg.build_ctx = NULL;
    cfg.may_ack = may_ack;
    cfg.tick_ms = 1000; cfg.resend_ticks = 5; cfg.deadline_ticks = 300; cfg.max_attempts = 3;
    if (gz_sign_init(E, &cfg, &G.ports, now_ms()) != GZ_OK) { s1_log("sign: init refused"); return 0; }
    gz_storage_reader_t rd = {rd_next, rd_rewind, NULL, now_ms(), 0};
    gz_action_list_t *l = s1_list();
    int more = 1;
    while (more) if (gz_sign_start(E, &rd, l, &more) != GZ_OK) { s1_log("sign: start refused"); return 0; }
    s1_exec(l);
    COND.min_own_channel_sat = 50000; COND.max_fee_per_tx_sat = 10000;
    COND.min_lstock_delay = 1; COND.max_lstock_delay = 65535;
    COND.min_members = 3; COND.max_members = 16;
    COND.exit = gz_exit_signet(); COND.funding_deadline_blocks = 36; COND.end_window = 6;
    inited = 1;
    return 1;
}

static int take_terms(const s1_handoff_t *h)
{
    gz_terms_policy_t pol = {1};
    if (h->outer_len > sizeof outer_rec || h->current_len > sizeof current_rec) return 0;
    memcpy(outer_rec, h->outer, h->outer_len); outer_len = h->outer_len;
    memcpy(current_rec, h->current, h->current_len); current_len = h->current_len;
    memcpy(scope, h->scope, 32); memcpy(frozen_digest, h->current_digest, 32); frozen_version = h->version;
    gz_terms_err_t e = gz_terms_decode_outer(outer_rec, outer_len, &pol, &T);
    if (e != GZ_TERMS_OK) { s1_log("sign: tree terms decoder refuses the lobby's outer record: %s", gz_terms_err_name(e)); return 0; }
    e = gz_terms_decode_current(current_rec, current_len, &T, &C);
    if (e != GZ_TERMS_OK) { s1_log("sign: tree terms decoder refuses the lobby's current record: %s", gz_terms_err_name(e)); return 0; }
    uint8_t d[32];
    gz_terms_outer_digest(outer_rec, outer_len, d);
    if (memcmp(d, scope, 32)) { s1_log("sign: MISMATCH: tree's outer digest differs from the lobby's scope"); return 0; }
    gz_terms_current_digest(current_rec, current_len, d);
    if (memcmp(d, frozen_digest, 32)) { s1_log("sign: MISMATCH: tree's current digest differs from the lobby's"); return 0; }
    return 1;
}

/* A fake funding transaction for the loopback run: one made-up input. */
static size_t fake_funding(const uint8_t script[34], uint64_t amount, uint8_t *out, uint8_t txid[32])
{
    size_t n = 0;
    out[n++] = 2; out[n++] = 0; out[n++] = 0; out[n++] = 0;
    out[n++] = 1;
    G.ports.random.fill(G.ports.random.ctx, GZ_RANDOM_ORDINARY, out + n, 32); n += 32;
    memset(out + n, 0, 4); n += 4;
    out[n++] = 0;
    out[n++] = 0xfd; out[n++] = 0xff; out[n++] = 0xff; out[n++] = 0xff;
    out[n++] = 1;
    for (int i = 0; i < 8; i++) out[n++] = (uint8_t)(amount >> (8 * i));
    out[n++] = 34; memcpy(out + n, script, 34); n += 34;
    memset(out + n, 0, 4); n += 4;
    gz_tx_txid(out, n, txid);
    return n;
}

int s1_sign_begin(const s1_handoff_t *h, gz_action_list_t *out)
{
    if (!engine_init() || !take_terms(h)) return 0;
    if (!G.host) {
        s1_log("sign: member waits for the proposal (frozen version %u)", frozen_version);
        return 1;
    }
    /* host: the proposal */
    uint32_t n = (uint32_t)h->n_parts - 1;
    gz_tree_params_t tp;
    gz_tree_p_err_t pe = gz_tree_params(&T, n, &tp);
    if (pe != GZ_TREE_P_OK) { s1_log("sign: gz_tree_params refused: %d", (int)pe); return 0; }
    s1_log("sign: tree for %u members: levels %zu D %u V %u fee/tx %llu funding %llu sat", n, tp.n_levels, tp.D, tp.V,
           (unsigned long long)tp.fee_per_tx, (unsigned long long)tp.funding_amount);
    static uint8_t mk[S1_MAX_PARTS][33];
    for (uint32_t i = 0; i < n; i++) memcpy(mk[i], h->parts[1 + i].fkey, 33);
    uint8_t internal[32], output[32], script[34];
    if (!CR.agg_tweak(CR.ctx, h->parts[0].fkey, (const uint8_t (*)[33])mk, n, NULL, internal, output)) {
        s1_log("sign: aggregate key failed"); return 0;
    }
    script[0] = 0x51; script[1] = 0x20; memcpy(script + 2, output, 32);
    memset(&P, 0, sizeof P);
    P.terms_version = h->version; memcpy(P.terms_digest, h->current_digest, 32);
    memcpy(P.funding_script, script, 34); P.funding_amount = tp.funding_amount;
    if (G.fake_chain) {
        funding_tx_len = fake_funding(script, tp.funding_amount, funding_tx, P.funding_txid);
        P.funding_vout = 0;
    } else {
        if (!s1_fund_build(script, tp.funding_amount, funding_tx, sizeof funding_tx, &funding_tx_len, P.funding_txid,
                           &P.funding_vout)) { s1_log("sign: the wallet could not build the funding"); return 0; }
    }
    char tx[65]; s1_hex_rev(tx, P.funding_txid, 32);
    s1_log("S1-RESULT funding-txid %s vout %u amount %llu (unsigned, held)", tx, P.funding_vout, (unsigned long long)P.funding_amount);
    P.end_height = G.tip + T.lifetime_blocks + T.winddown_blocks;
    P.fee_per_tx = tp.fee_per_tx; P.lstock_delay = GZ_TREE_LSTOCK_DEFAULT; P.fixed_levels = tp.D;
    P.nonces_due_ms = 30000; P.sigs_due_ms = 30000;
    /* the node count: build once */
    {
        static uint8_t mkeys[S1_MAX_PARTS][33];
        gz_tree_build_in_t in;
        static gz_tree_participant_t tmp[S1_MAX_PARTS];
        for (int i = 0; i < h->n_parts; i++) memcpy(tmp[i].factory_key, h->parts[i].fkey, 33);
        memcpy(PARTS, tmp, sizeof tmp);
        P.participants = PARTS; P.n_participants = h->n_parts;
        tree_in_from_P(&in, tp.levels, tp.n_levels, mkeys);
        gz_tree_b_err_t be = gz_tree_build(&in, &CR, TREE);
        if (be != GZ_TREE_B_OK) { s1_log("sign: tree build refused: %d", (int)be); return 0; }
        n_nodes_sent = TREE->n_nodes;
        s1_log("sign: tree has %u transactions", TREE->n_nodes);
    }
    static uint8_t params[GZ_SIGN_MAX_PARAMS];
    size_t plen = encode_params(params, sizeof params, h->parts, h->n_parts);
    if (!plen) { s1_log("sign: parameters do not fit %d bytes", GZ_SIGN_MAX_PARAMS); return 0; }
    gz_status_t st = gz_sign_begin(E, params, plen, out);
    s1_log("sign: round begun with %zu bytes of parameters: %d", plen, (int)st);
    return st == GZ_OK;
}

static void write_tree(const gz_sign_round_t *r)
{
    if (tree_written) return;
    for (int i = 0; i < r->def.n_items; i++) if (!r->have_final[i]) return;
    static uint8_t buf[GZ_SIGN_MAX_TX + 80];
    char path[512], hex[2 * (GZ_SIGN_MAX_TX + 80) + 1], id[65];
    for (int i = 0; i < r->def.n_items; i++) {
        size_t n = gz_tx_attach(r->def.items[i].tx, r->def.items[i].tx_len, r->final_sig[i], buf, sizeof buf);
        int ok = n && gz_tx_verify(G.secp, buf, n, r->def.items[i].spent_amount, r->def.items[i].spent_script);
        uint8_t txid[32];
        gz_tx_txid(r->def.items[i].tx, r->def.items[i].tx_len, txid);
        s1_hex_rev(id, txid, 32);
        s1_log("S1-RESULT tree-tx %d txid %s signers %u verified %d", i, id, r->def.items[i].n_signers, ok);
        snprintf(path, sizeof path, "%s/tree-%02d.hex", G.dir, i);
        FILE *f = fopen(path, "w");
        if (f) { s1_hex(hex, buf, n); fprintf(f, "%s\n", hex); fclose(f); }
    }
    tree_written = 1;
}

static void after_event(void)
{
    const gz_sign_round_t *r = gz_sign_latest(E);
    if (!r) return;
    if (r->state != round_logged) {
        s1_log("sign: round state %d (tier %u, why %u)", r->state, r->tier, r->why);
        round_logged = r->state;
    }
    if (G.host) {
        if (r->state == GZ_ROUND_DONE && fund_stage == 0) {
            write_tree(r);
            s1_log("S1-RESULT all-acks: every member acknowledged the tree");
            fund_stage = 1;
        } else if (r->state == GZ_ROUND_FAILED && fund_stage == 0) {
            s1_log("S1-RESULT signing-failed blamed 0x%x why %u", r->blamed, r->why);
            fund_stage = -1;
            s1_lobby_round_result(4);
        }
    } else {
        if (r->state == GZ_ROUND_COMPLETE) write_tree(r);
        if (r->state == GZ_ROUND_ABORTED) s1_log("S1-RESULT member-aborted why %u", r->why);
    }
}

void s1_sign_event(const gz_event_t *ev)
{
    if (!inited) {
        if (ev->kind == GZ_EVENT_MESSAGE_RECEIVED) s1_log("sign: a signing message before the hand-off: dropped");
        return;
    }
    gz_action_list_t *l = s1_list();
    gz_status_t st = gz_sign_handle(E, ev, l);
    if (st != GZ_OK) { s1_log("sign: handle failed %d", (int)st); s1_die("signing engine error"); }
    s1_exec(l);
    after_event();
}

void s1_sign_timer(uint64_t id)
{
    gz_event_t ev = {.kind = GZ_EVENT_TIMER_FIRED};
    ev.u.timer.timer_id = id;
    s1_sign_event(&ev);
}

void s1_sign_poll(void)
{
    if (!inited) return;
    char id[65];
    if (G.host) {
        if (fund_stage == 1) {
            if (G.fake_chain) { fund_stage = 3; s1_log("S1-RESULT fake funding: nothing broadcast"); s1_lobby_round_result(1); return; }
            if (!s1_fund_release(P.funding_txid, fund_raw, sizeof fund_raw, &fund_raw_len)) { s1_log("S1-RESULT funding release failed"); fund_stage = -1; return; }
            char path[512]; snprintf(path, sizeof path, "%s/funding.hex", G.dir);
            FILE *f = fopen(path, "w");
            static char hex[120001];
            s1_hex(hex, fund_raw, fund_raw_len);
            if (f) { fprintf(f, "%s\n", hex); fclose(f); }
            s1_log("S1-RESULT funding signed (%zu bytes) at %s; waiting for the gate %s", fund_raw_len, path, G.gate ? G.gate : "(none)");
            fund_stage = 2;
        } else if (fund_stage == 2) {
            struct stat st;
            if (G.gate && stat(G.gate, &st) != 0) return;
            int ok = s1_broadcast(fund_raw, fund_raw_len);
            s1_hex_rev(id, P.funding_txid, 32);
            s1_log("S1-RESULT broadcast %s: %s", id, ok ? "accepted" : "FAILED");
            if (!ok) { fund_stage = -1; return; }
            fund_stage = 3;
            s1_lobby_round_result(1);
            next_chain_ms = now_ms() + 30000;
        } else if (fund_stage == 3) {
            if (G.fake_chain) { fund_stage = 4; s1_lobby_round_result(2); s1_log("S1-RESULT factory active (fake chain)"); return; }
            if (now_ms() < next_chain_ms) return;
            next_chain_ms = now_ms() + 30000;
            uint32_t h = 0;
            int c = s1_tx_confirmations(P.funding_txid, &h);
            s1_log("host: funding confirmations %d (block %u)", c, h);
            if (c >= CONFS_BURIED) { fund_stage = 4; s1_lobby_round_result(2); s1_log("S1-RESULT factory active: funding buried at %d confirmations", c); }
        }
        return;
    }
    /* member: watch the funding once acked */
    const gz_sign_round_t *r = gz_sign_latest(E);
    if (!r || r->state != GZ_ROUND_COMPLETE || member_live || G.fake_chain || !have_verdict) return;
    if (now_ms() < next_chain_ms) return;
    next_chain_ms = now_ms() + 30000;
    uint32_t h = 0;
    int c = s1_tx_confirmations(P.funding_txid, &h);
    s1_log("member: funding confirmations %d (block %u)", c, h);
    gz_tree_c11_in_t ci;
    memset(&ci, 0, sizeof ci);
    ci.tip = G.tip; ci.ack_tip = ack_tip; ci.cond = &COND;
    static uint8_t seen_script[34];
    uint64_t seen_amount = 0;
    int seen = c > 0 && s1_tx_output(P.funding_txid, P.funding_vout, &seen_amount, seen_script);
    ci.seen = seen; ci.seen_amount = seen_amount; ci.seen_script = seen_script; ci.seen_script_len = 34;
    ci.confirmations = c > 0 ? (uint32_t)c : 0;
    ci.buried_at = c >= CONFS_BURIED ? h + CONFS_BURIED - 1 : 0;
    ci.funding_amount = P.funding_amount; ci.funding_script = P.funding_script; ci.holds_whole_tree = tree_written;
    ci.end_height = P.end_height; ci.own_depth = VERDICT.own_depth;
    gz_c11_t v = gz_tree_c11(&ci);
    if (v != GZ_C11_WAIT) {
        s1_log("S1-RESULT member C11 verdict %d (%s) at %d confirmations", (int)v,
               v == GZ_C11_LIVE ? "live" : v == GZ_C11_ABANDONED ? "abandoned" : "mismatch", c);
        member_live = 1;
    }
}
