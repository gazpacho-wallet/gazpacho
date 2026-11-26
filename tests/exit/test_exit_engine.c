/* The exit engine's tree half (spec/exit.md 6.8; Slice 1.5 plan item P3),
 * over trees built from T1 at depths 1, 2 and 3 (3, 4 and 16 members) and a
 * 256-member tree, driven through the real runner (save before send)
 * against a pretend chain and a pretend chain view that follow action.h's
 * watch contract.
 *
 * The pretend chain: a transaction enters the mempool if its inputs exist and
 * are not spent, its lock time is final at the next block (BIP 65 finality:
 * only when some input's sequence is not final), its relative locks are met
 * (BIP 68, version 2 or more), and, with a relay floor set, its fee rate meets
 * the floor, or the next broadcast is its child and the two together do (a
 * package, as P4 will send adjacent parent and child broadcasts). A block
 * mines every mempool transaction whose inputs were confirmed in an earlier
 * block (one tree level per block, as TRUC makes it) and whose locks are met
 * at its height. Every broadcast gets a result event.
 *
 * THE KEYS ARE TEST KEYS. The signatures are fixed bytes; the verifier the
 * tests hand the plan functions accepts them unless a test says otherwise. */
#include "../tree/tree_test.h"
#include "gazpacho/command.h"
#include "gazpacho/envelope.h"
#include "gazpacho/exit_engine.h"
#include "gazpacho/runner.h"
#include "gazpacho/tree_import.h"

#define TIP0 290000u
#define END  (TIP0 + 180u)
#define BUR  3u

static const uint8_t SCOPE[32] = { 0x5c, 0x0e, 0x01 };
static const uint8_t OTHER_SCOPE[32] = { 0x5c, 0x0e, 0x02 };

/* ---- the tree ----------------------------------------------------------- */

static gz_tree_t TREE;
static gz_tree_params_t P;
static uint8_t SIGS[GZ_TREE_MAX_NODES][64];
static gz_tree_crypto_t CR;
static uint8_t HOSTK[33], MEM[GZ_TREE_MAX_MEMBERS][33];
static uint32_t NMEM;
static gz_outpoint_t FUND;
static uint64_t FUND_AMT;
static int VERIFY_OK = 1;
static unsigned VERIFY_CALLS;

static int fake_verify(void *ctx, const uint8_t *tx, size_t len, uint64_t amount, const uint8_t script[34])
{
    (void)ctx; (void)tx; (void)len; (void)amount;
    VERIFY_CALLS++;
    return script[0] == 0x51 && script[1] == 0x20 && VERIFY_OK;
}

/* Shapes past 16 members for the 256-member tree: the first interior list
 * the split rule takes. */
static int big_terms(gz_terms_outer_t *t, uint32_t n)
{
    static const uint8_t cand[][4] = { { 4, 4, 4, 0 }, { 4, 4, 4, 4 }, { 8, 8, 0, 0 }, { 16, 16, 0, 0 } };
    gz_tree_params_t q;
    for (size_t c = 0; c < sizeof cand / sizeof cand[0]; c++) {
        t->n_shapes = 3;
        t->shapes[2].max_members = 256;
        t->shapes[2].n_interior = 0;
        for (int k = 0; k < 4 && cand[c][k]; k++) t->shapes[2].interior[t->shapes[2].n_interior++] = cand[c][k];
        t->shapes[2].leaf_kind = 3;
        if (gz_tree_params(t, n, &q) == GZ_TREE_P_OK) return 1;
    }
    return 0;
}

static void build(uint32_t n)
{
    gz_terms_outer_t t;
    gz_tree_build_in_t in;
    uint8_t internal[32], okey[32];
    char label[64];
    t1_terms(&t);
    t.target = 16;
    if (n > 16) {
        t.target = (uint16_t)n;
        if (!big_terms(&t, n)) { printf("no shape for %u members\n", n); abort(); }
    }
    gz_tree_secp_crypto(test_ctx(), &CR);
    test_pub("host", HOSTK);
    for (uint32_t i = 0; i < n; i++) {
        snprintf(label, sizeof label, "member %u factory", i + 1);
        test_pub(label, MEM[i]);
    }
    if (gz_tree_params(&t, n, &P) != GZ_TREE_P_OK) abort();
    memset(&in, 0, sizeof in);
    in.levels = P.levels;
    in.n_levels = P.n_levels;
    in.fixed_levels = P.D;
    in.n_members = n;
    in.host_key = HOSTK;
    in.member_keys = (const uint8_t(*)[33])MEM;
    in.end_height = END;
    in.tree_feerate = P.tree_feerate;
    in.lstock_csv = 144;
    tr_sha256((const uint8_t *)"gazpacho test funding", 21, in.funding_txid);
    in.funding_vout = 0;
    in.funding_amount = P.funding_amount;
    if (!CR.agg_tweak(CR.ctx, HOSTK, (const uint8_t(*)[33])MEM, n, NULL, internal, okey)) abort();
    in.funding_script[0] = 0x51; in.funding_script[1] = 0x20;
    memcpy(in.funding_script + 2, okey, 32);
    if (gz_tree_build(&in, &CR, &TREE) != GZ_TREE_B_OK) abort();
    for (uint32_t i = 0; i < TREE.n_nodes; i++)
        for (int j = 0; j < 64; j++) SIGS[i][j] = (uint8_t)(i * 7 + j + 1);
    memcpy(FUND.txid, in.funding_txid, 32);
    FUND.vout = 0;
    FUND_AMT = in.funding_amount;
    NMEM = n;
}

static gz_xe_tree_in_t tin(void)
{
    gz_xe_tree_in_t r;
    memset(&r, 0, sizeof r);
    memcpy(r.scope, SCOPE, 32);
    r.tree = &TREE;
    r.sigs = (const uint8_t(*)[64])SIGS;
    r.member_keys = (const uint8_t(*)[33])MEM;
    r.n_members = NMEM;
    r.end_height = END;
    r.c = gz_exit_signet();
    r.verify = fake_verify;
    return r;
}

/* The first member whose leaf is at depth d, or -1. */
static int member_at(uint8_t d)
{
    for (uint32_t i = 0; i < NMEM; i++)
        if (P.depth[i] == d) return (int)i;
    return -1;
}

/* ---- the pretend chain --------------------------------------------------- */

typedef struct {
    uint8_t txid[32];
    size_t n_in;
    uint8_t in[GZ_XE_MAX_SWEEP_IN + 1][36];
    uint32_t seq[GZ_XE_MAX_SWEEP_IN + 1];
    uint32_t n_out, locktime, version, height;   /* height 0: in the mempool */
    uint64_t outv[16];
    int live;
} ctx_t;

static ctx_t T[1024];
static size_t NT;
static uint32_t TIP, HASHSEQ, FORCED;
static uint64_t FLOOR;                       /* relay floor, sat/kvB; 0 none */
static int REJECT_V2;                        /* refuse every version-2 transaction (the sweeps) */
static uint8_t HOLD[32];                     /* a transaction no block takes */
static int HOLD_ON;

static void op36(const gz_outpoint_t *o, uint8_t b[36])
{
    memcpy(b, o->txid, 32);
    b[32] = (uint8_t)o->vout; b[33] = (uint8_t)(o->vout >> 8); b[34] = (uint8_t)(o->vout >> 16); b[35] = (uint8_t)(o->vout >> 24);
}

static uint32_t vout_of(const uint8_t b[36])
{
    return (uint32_t)b[32] | (uint32_t)b[33] << 8 | (uint32_t)b[34] << 16 | (uint32_t)b[35] << 24;
}

static int tx_find(const uint8_t txid[32])
{
    for (size_t i = 0; i < NT; i++)
        if (T[i].live && memcmp(T[i].txid, txid, 32) == 0) return (int)i;
    return -1;
}

/* The height an output was confirmed at (the funding: below TIP0), 0 in a
 * mempool, -1 if it does not exist. */
static int64_t out_height(const uint8_t b[36])
{
    uint32_t vout = vout_of(b);
    if (memcmp(b, FUND.txid, 32) == 0) return vout == FUND.vout ? (int64_t)TIP0 - 10 : -1;
    int i = tx_find(b);
    if (i < 0 || vout >= T[i].n_out) return -1;
    return T[i].height;
}

static uint64_t out_value(const uint8_t b[36])
{
    uint32_t vout = vout_of(b);
    if (memcmp(b, FUND.txid, 32) == 0) return FUND_AMT;
    int i = tx_find(b);
    if (i < 0 || vout >= 16) return 0;
    return T[i].outv[vout];
}

static int spender(const uint8_t b[36])
{
    int best = -1;
    for (size_t i = 0; i < NT; i++) {
        if (!T[i].live) continue;
        for (size_t k = 0; k < T[i].n_in; k++)
            if (memcmp(T[i].in[k], b, 36) == 0 && (best < 0 || T[i].height)) best = (int)i;
    }
    return best;
}

static void evict(int i)
{
    uint8_t b[36];
    T[i].live = 0;
    for (uint32_t v = 0; v < T[i].n_out; v++) {
        gz_outpoint_t o;
        memcpy(o.txid, T[i].txid, 32);
        o.vout = v;
        op36(&o, b);
        int s = spender(b);
        if (s >= 0) evict(s);
    }
}

/* BIP 65 and BIP 68 at block height h (h = TIP + 1 for the mempool). */
static int locks_met(const ctx_t *t, uint32_t h)
{
    int any_open = 0;
    for (size_t k = 0; k < t->n_in; k++) {
        uint32_t s = t->seq[k];
        if (s != 0xffffffffu) any_open = 1;
        if (t->version >= 2 && !(s & 0x80000000u) && !(s & 0x00400000u)) {
            int64_t ch = out_height(t->in[k]);
            if (ch <= 0 || (int64_t)h < ch + (int64_t)(s & 0xffffu)) return 0;
        }
    }
    if (t->locktime && any_open && t->locktime < 500000000u && t->locktime >= h) return 0;
    return 1;
}

/* 1 accepted; 0 refused; 2 refused below the floor only. */
static int chain_try(const uint8_t *raw, size_t len, int ignore_floor, uint64_t *fee, uint64_t *vs)
{
    uint8_t bare[GZ_XE_MAX_SWEEP], txid[32];
    size_t bl;
    int wit;
    gz_tx_info_t info;
    uint64_t in_sum = 0, out_sum = 0;
    if (!gz_xe_strip_witness(raw, len, bare, sizeof bare, &bl, &wit)) return 0;
    if (!gz_tx_parse(bare, bl, &info) || info.n_in > GZ_XE_MAX_SWEEP_IN + 1) return 0;
    gz_tx_txid(bare, bl, txid);
    if (tx_find(txid) >= 0) return 1;
    if (REJECT_V2 && info.version == 2) return 0;
    if (NT + 1 >= sizeof T / sizeof T[0]) abort();
    ctx_t *t = &T[NT];
    memset(t, 0, sizeof *t);
    t->version = info.version;
    t->locktime = info.locktime;
    for (size_t k = 0; k < info.n_in; k++) {
        const uint8_t *op;
        size_t sl;
        if (!gz_tx_input(bare, bl, &info, k, &op, &sl, &t->seq[k])) return 0;
        if (out_height(op) < 0 || spender(op) >= 0) return 0;
        memcpy(t->in[k], op, 36);
        in_sum += out_value(op);
    }
    t->n_in = info.n_in;
    t->n_out = (uint32_t)info.n_out;
    for (size_t k = 0; k < info.n_out; k++) {
        const uint8_t *sc;
        size_t sl;
        uint64_t v = 0;
        if (!gz_tx_output(bare, bl, &info, k, &v, &sc, &sl)) return 0;
        if (k < 16) t->outv[k] = v;
        out_sum += v;
    }
    if (!locks_met(t, TIP + 1)) return 0;
    *fee = in_sum > out_sum ? in_sum - out_sum : 0;
    *vs = (3 * bl + len + 3) / 4;
    if (!ignore_floor && FLOOR && *fee * 1000 < FLOOR * *vs) return 2;
    memcpy(t->txid, txid, 32);
    t->live = 1;
    NT++;
    return 1;
}

/* Someone else's transaction spending `o`, evicting a mempool rival. */
static void chain_force(const gz_outpoint_t *o)
{
    uint8_t b[36], label[16] = "forced spend";
    op36(o, b);
    int s = spender(b);
    if (s >= 0) evict(s);
    ctx_t *t = &T[NT++];
    memset(t, 0, sizeof *t);
    label[13] = (uint8_t)++FORCED;
    tr_sha256(label, sizeof label, t->txid);
    t->n_in = 1;
    t->seq[0] = 0xffffffffu;
    memcpy(t->in[0], b, 36);
    t->n_out = 1;
    t->version = 2;
    t->live = 1;
}

static void chain_mine(void)
{
    TIP++;
    HASHSEQ++;
    for (size_t i = 0; i < NT; i++) {
        ctx_t *t = &T[i];
        int ok = t->live && t->height == 0 && locks_met(t, TIP);
        if (HOLD_ON && memcmp(t->txid, HOLD, 32) == 0) ok = 0;
        for (size_t k = 0; ok && k < t->n_in; k++) {
            int64_t h = out_height(t->in[k]);
            ok = h > 0 && h < (int64_t)TIP;
        }
        if (ok) t->height = TIP;
    }
}

/* A reorganisation at the same height that leaves `txid` and what came at
 * or after its block out (back to the mempool). */
static void chain_unconfirm(const uint8_t txid[32])
{
    int i = tx_find(txid);
    if (i < 0) abort();
    uint32_t h = T[i].height;
    for (size_t k = 0; k < NT; k++)
        if (T[k].live && T[k].height >= h) T[k].height = 0;
    HASHSEQ++;
}

static void chain_vanish(const uint8_t txid[32])
{
    int i = tx_find(txid);
    if (i >= 0) evict(i);
}

/* ---- the program around the engine --------------------------------------- */

static gz_xe_t X;
static gz_xe_plan_t PLAN;
static gz_runner_t RUN;
static gz_runner_slot_t RSLOTS[8192];
static uint8_t RBYTES[2u << 20];
static gz_action_t LSLOTS[GZ_XE_MAX_STEP_ACTIONS];
static uint8_t LBYTES[1u << 20];
static gz_action_list_t L;
static uint64_t INC;

typedef struct { uint32_t type; size_t off, len; } jrec_t;
static uint8_t JPOOL[8u << 20];
static size_t JUSED, NJ;
static jrec_t J[8192];
static gz_batch_id_t PEND[64];
static size_t NPEND;

static uint8_t BC[8192][32];
static uint32_t BC_TIP[8192];
static size_t NBC;
static int DROP_BCAST;
static char LOGS[512][96];
static size_t NLOG;
static uint64_t DIGEST;

/* Broadcast results, delivered after each step. */
static struct { uint8_t txid[32]; int outcome; } RES[256];
static size_t NRES;
/* A parent refused below the floor alone, waiting for its child. */
static uint8_t PPAR[GZ_XE_MAX_SIGNED];
static size_t PPAR_LEN;
static uint8_t PPAR_TXID[32];

typedef struct {
    int is_tx;
    gz_outpoint_t op;           /* is_tx: op.txid is the txid */
    uint32_t depth;
    int used, fresh, known, failed, pending;
    uint8_t last[32];
    uint32_t last_conf;
} watch_t;
static watch_t W[4096];
static size_t NW;

/* Watches the view answers with FAILED (spent deeper than it follows), or
 * holds with PENDING. */
static gz_outpoint_t FAIL_OP[4];
static size_t N_FAIL_OP;
static uint8_t FAIL_TX[4][32];
static size_t N_FAIL_TX;
static gz_outpoint_t PEND_OP;
static int PEND_ON;
static int HASH_SKEW;                         /* TIP_SYNCED names another block */

static void mix(const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) { DIGEST ^= b[i]; DIGEST *= 1099511628211ull; }
}

static int same_op(const gz_outpoint_t *a, const gz_outpoint_t *b)
{
    return a->vout == b->vout && memcmp(a->txid, b->txid, 32) == 0;
}

static watch_t *watch_find(int is_tx, const gz_outpoint_t *o)
{
    for (size_t i = 0; i < NW; i++)
        if (W[i].used && W[i].is_tx == is_tx && memcmp(W[i].op.txid, o->txid, 32) == 0
            && (is_tx || W[i].op.vout == o->vout))
            return &W[i];
    return NULL;
}

static size_t n_watches(void)
{
    size_t n = 0;
    for (size_t i = 0; i < NW; i++) n += W[i].used != 0;
    return n;
}

static void result(const uint8_t txid[32], int outcome)
{
    if (NRES < 256) { memcpy(RES[NRES].txid, txid, 32); RES[NRES].outcome = outcome; NRES++; }
}

static void txid_of(const uint8_t *raw, size_t len, uint8_t txid[32])
{
    uint8_t bare[GZ_XE_MAX_SWEEP];
    size_t bl;
    int wit;
    if (!gz_xe_strip_witness(raw, len, bare, sizeof bare, &bl, &wit)) abort();
    gz_tx_txid(bare, bl, txid);
}

/* A parent left waiting with no child after it: refused. */
static void flush_parent(void)
{
    if (PPAR_LEN) result(PPAR_TXID, GZ_BROADCAST_REFUSED);
    PPAR_LEN = 0;
}

static void chain_broadcast(const uint8_t *raw, size_t len)
{
    uint64_t fee, vs, pfee, pvs;
    uint8_t txid[32];
    int r;
    txid_of(raw, len, txid);
    if (PPAR_LEN) {                                /* the child of a parent below the floor? */
        int ok = chain_try(PPAR, PPAR_LEN, 1, &pfee, &pvs) == 1;
        int c = ok ? chain_try(raw, len, 1, &fee, &vs) : 0;
        if (ok && c == 1 && (pfee + fee) * 1000 >= FLOOR * (pvs + vs)) {
            result(PPAR_TXID, GZ_BROADCAST_ACCEPTED);
            result(txid, GZ_BROADCAST_ACCEPTED);
            PPAR_LEN = 0;
            return;
        }
        if (c == 1) chain_vanish(txid);
        if (ok) chain_vanish(PPAR_TXID);
        flush_parent();
    }
    r = chain_try(raw, len, 0, &fee, &vs);
    if (r == 2 && len <= sizeof PPAR) {
        memcpy(PPAR, raw, len);
        PPAR_LEN = len;
        memcpy(PPAR_TXID, txid, 32);
        return;
    }
    result(txid, r == 1 ? GZ_BROADCAST_ACCEPTED : GZ_BROADCAST_REFUSED);
}

static void exec(void *ctx, const gz_action_t *a)
{
    (void)ctx;
    mix(&a->kind, sizeof a->kind);
    switch (a->kind) {
    case GZ_ACTION_SAVE:
        for (size_t i = 0; i < a->u.save.n_records; i++) {
            const gz_record_t *r = &a->u.save.records[i];
            if (JUSED + r->bytes.len > sizeof JPOOL || NJ == sizeof J / sizeof J[0]) abort();
            memcpy(JPOOL + JUSED, r->bytes.data, r->bytes.len);
            J[NJ].type = r->type; J[NJ].off = JUSED; J[NJ].len = r->bytes.len;
            JUSED += r->bytes.len;
            NJ++;
            mix(&r->type, 4);
            mix(r->bytes.data, r->bytes.len);
        }
        PEND[NPEND++] = a->u.save.batch;
        break;
    case GZ_ACTION_BROADCAST:
        mix(a->u.broadcast.tx.data, a->u.broadcast.tx.len);
        if (DROP_BCAST) break;
        if (NBC == sizeof BC / sizeof BC[0]) abort();
        txid_of(a->u.broadcast.tx.data, a->u.broadcast.tx.len, BC[NBC]);
        BC_TIP[NBC++] = TIP;
        chain_broadcast(a->u.broadcast.tx.data, a->u.broadcast.tx.len);
        break;
    case GZ_ACTION_WATCH_OUTPOINT:
    case GZ_ACTION_WATCH_TX: {
        int is_tx = a->kind == GZ_ACTION_WATCH_TX;
        gz_outpoint_t o;
        memset(&o, 0, sizeof o);
        if (is_tx) memcpy(o.txid, a->u.watch_tx.txid, 32);
        else o = a->u.watch_outpoint.outpoint;
        watch_t *w = watch_find(is_tx, &o);
        mix(&o, sizeof o);
        if (!w) { w = &W[NW++]; memset(w, 0, sizeof *w); w->op = o; w->is_tx = is_tx; w->used = 1; }
        w->depth = is_tx ? a->u.watch_tx.depth : a->u.watch_outpoint.depth;
        w->fresh = 1;
        w->known = 0;
        w->failed = 0;
        w->pending = 0;
        break;
    }
    case GZ_ACTION_UNWATCH: {
        gz_outpoint_t o = a->u.unwatch.what;
        if (a->u.unwatch.is_tx) o.vout = 0;
        watch_t *w = watch_find(a->u.unwatch.is_tx, &o);
        if (w) w->used = 0;
        break;
    }
    case GZ_ACTION_NOTIFY: {
        gz_bytes_t v;
        mix(a->u.notify.bytes.data, a->u.notify.bytes.len);
        if (a->u.notify.code == GZ_NOTIFY_LOG && gz_rec_find(a->u.notify.bytes, 0, &v) == 1 && NLOG < 512) {
            size_t n = v.len < 95 ? v.len : 95;
            memcpy(LOGS[NLOG], v.data, n);
            LOGS[NLOG++][n] = 0;
        }
        break;
    }
    default:
        break;
    }
}

static void deliver_results(void);

static void submit(void)
{
    CHECK(gz_runner_submit(&RUN, &L) == GZ_OK);
    for (size_t i = 0; i < NPEND; i++) CHECK(gz_runner_confirm(&RUN, PEND[i]) == GZ_OK);
    NPEND = 0;
    flush_parent();
}

static void feed(const gz_event_t *ev)
{
    gz_action_list_reset(&L);
    CHECK(gz_xe_handle(&X, ev, &L) == GZ_OK);
    submit();
    deliver_results();
}

static int DELIVERING;
static void deliver_results(void)
{
    if (DELIVERING) return;
    DELIVERING = 1;
    for (size_t i = 0; i < NRES; i++) {
        gz_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = GZ_EVENT_CHAIN;
        ev.u.chain.kind = GZ_CHAIN_BROADCAST_RESULT;
        memcpy(ev.u.chain.txid, RES[i].txid, 32);
        ev.u.chain.outcome = (gz_broadcast_outcome_t)RES[i].outcome;
        if (RES[i].outcome == GZ_BROADCAST_REFUSED) {
            ev.u.chain.reason.data = (const uint8_t *)"min relay fee not met";
            ev.u.chain.reason.len = 21;
        }
        gz_action_list_reset(&L);
        CHECK(gz_xe_handle(&X, &ev, &L) == GZ_OK);
        CHECK(gz_runner_submit(&RUN, &L) == GZ_OK);
        for (size_t k = 0; k < NPEND; k++) CHECK(gz_runner_confirm(&RUN, PEND[k]) == GZ_OK);
        NPEND = 0;
    }
    NRES = 0;
    DELIVERING = 0;
}

static void chain_ev_full(gz_chain_kind_t k, uint32_t height, const gz_outpoint_t *o, const uint8_t *txid, uint32_t conf,
                          int is_tx)
{
    gz_event_t ev;
    uint32_t h = HASHSEQ + (k == GZ_CHAIN_TIP_SYNCED ? (uint32_t)HASH_SKEW : 0u);
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_CHAIN;
    ev.u.chain.kind = k;
    ev.u.chain.height = height;
    if (o) ev.u.chain.outpoint = *o;
    if (txid) memcpy(ev.u.chain.txid, txid, 32);
    ev.u.chain.confirmations = conf;
    ev.u.chain.is_tx = is_tx;
    ev.u.chain.block_hash[0] = (uint8_t)h; ev.u.chain.block_hash[1] = (uint8_t)(h >> 8);
    ev.u.chain.block_hash[31] = 1;
    feed(&ev);
}

static void chain_ev(gz_chain_kind_t k, uint32_t height, const gz_outpoint_t *o, const uint8_t *txid, uint32_t conf)
{
    chain_ev_full(k, height, o, txid, conf, 0);
}

static int is_failed(const watch_t *w)
{
    if (w->is_tx) {
        for (size_t i = 0; i < N_FAIL_TX; i++) if (memcmp(FAIL_TX[i], w->op.txid, 32) == 0) return 1;
        return 0;
    }
    for (size_t i = 0; i < N_FAIL_OP; i++) if (same_op(&FAIL_OP[i], &w->op)) return 1;
    return 0;
}

/* What the chain view says about one watch now (action.h's rules). */
static void report(watch_t *w, int first)
{
    if (w->failed || w->pending) return;
    if (w->is_tx) {
        int i = tx_find(w->op.txid);
        uint32_t conf = i >= 0 && T[i].height ? TIP - T[i].height + 1 : 0;
        uint8_t txid[32];
        memcpy(txid, w->op.txid, 32);
        if (conf && (first || (conf != w->last_conf && conf <= w->depth) || !w->known)) {
            w->known = 1;
            w->last_conf = conf;
            chain_ev_full(GZ_CHAIN_TX_CONFIRMED, T[i].height, NULL, txid, conf, 1);
        } else if (!conf && w->known) {
            w->known = 0;
            w->last_conf = 0;
            chain_ev_full(GZ_CHAIN_TX_UNCONFIRMED, 0, NULL, txid, 0, 1);
        }
        return;
    }
    uint8_t b[36];
    op36(&w->op, b);
    int s = spender(b);
    if (s < 0) return;   /* a vanished spender is not reported */
    uint32_t conf = T[s].height ? TIP - T[s].height + 1 : 0;
    int same = w->known && memcmp(w->last, T[s].txid, 32) == 0;
    int tell = first || !same || (conf != w->last_conf && (conf == 0 || conf <= w->depth));
    if (!tell) return;
    w->known = 1;
    memcpy(w->last, T[s].txid, 32);
    w->last_conf = conf;
    gz_outpoint_t o = w->op;
    uint8_t txid[32];
    memcpy(txid, T[s].txid, 32);
    chain_ev(GZ_CHAIN_OUTPOINT_SPENT, T[s].height, &o, txid, conf);
}

static void synced_ev(watch_t *w, gz_chain_kind_t k)
{
    gz_outpoint_t o = w->op;
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_CHAIN;
    ev.u.chain.kind = k;
    ev.u.chain.is_tx = w->is_tx;
    if (w->is_tx) memcpy(ev.u.chain.txid, o.txid, 32);
    else ev.u.chain.outpoint = o;
    feed(&ev);
}

/* Answer every watch set since the last answer: its state, then SYNCED
 * (or FAILED, or PENDING). */
static void settle(void)
{
    for (int again = 1; again;) {
        again = 0;
        for (size_t i = 0; i < NW; i++) {
            if (!W[i].used || !W[i].fresh) continue;
            W[i].fresh = 0;
            again = 1;
            if (is_failed(&W[i])) { W[i].failed = 1; synced_ev(&W[i], GZ_CHAIN_WATCH_FAILED); continue; }
            if (PEND_ON && !W[i].is_tx && same_op(&PEND_OP, &W[i].op)) {
                W[i].pending = 1;
                synced_ev(&W[i], GZ_CHAIN_WATCH_PENDING);
                continue;
            }
            report(&W[i], 1);
            synced_ev(&W[i], GZ_CHAIN_WATCH_SYNCED);
        }
    }
}

static void release_pending(void)
{
    PEND_ON = 0;
    for (size_t i = 0; i < NW; i++)
        if (W[i].used && W[i].pending) {
            W[i].pending = 0;
            report(&W[i], 1);
            synced_ev(&W[i], GZ_CHAIN_WATCH_SYNCED);
        }
}

static void tip_events(void)
{
    chain_ev(GZ_CHAIN_NEW_TIP, TIP, NULL, NULL, 0);
    for (size_t i = 0; i < NW; i++)
        if (W[i].used && !W[i].fresh) report(&W[i], 0);
    settle();
    chain_ev(GZ_CHAIN_TIP_SYNCED, TIP, NULL, NULL, 0);
    settle();
}

static void block(void)
{
    chain_mine();
    tip_events();
}

static int ended(uint8_t *how)
{
    uint8_t h = 0;
    int e = gz_xe_has_ended(&X, &h);
    if (how) *how = h;
    return e;
}

static void run_until_end(unsigned limit)
{
    for (unsigned i = 0; i < limit && !ended(NULL); i++) block();
}

/* ---- the sweep port ------------------------------------------------------ */

typedef struct {
    uint32_t tip, locktime;
    size_t n;
    gz_xe_sweep_in_t in[GZ_XE_MAX_SWEEP_IN];
} call_t;
static call_t CALLS[256];
static size_t NCALL;
/* Port faults (T2): 0 none; 1 fails; 2 input 0's txid altered; 3 lock time
 * + 1; 4 every non-CSV sequence final; 5 an extra input; 6 the last input
 * missing; 7 the first two swapped; 8 the last input's witness empty; 9
 * version 1; 10 a scriptSig on input 0; 11 no witness at all; 12 the last
 * input's txid altered; 13 every CSV sequence one short. */
static int MODE;

static void le32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

static int fake_sweep(void *ctx, const uint8_t scope[32], const gz_xe_sweep_in_t *in, size_t n, uint32_t locktime,
                      uint8_t *tx, size_t cap, size_t *tx_len)
{
    gz_xe_sweep_in_t ins[GZ_XE_MAX_SWEEP_IN + 1];
    size_t at = 0, ni = n;
    uint64_t sum = 0;
    (void)ctx;
    if (memcmp(scope, SCOPE, 32) != 0 || n == 0 || n > GZ_XE_MAX_SWEEP_IN || NCALL >= 256) return 0;
    CALLS[NCALL].tip = TIP;
    CALLS[NCALL].locktime = locktime;
    CALLS[NCALL].n = n;
    memcpy(CALLS[NCALL].in, in, n * sizeof *in);
    NCALL++;
    if (MODE == 1 || cap < 128 + (n + 1) * 120) return 0;
    memcpy(ins, in, n * sizeof *in);
    for (size_t i = 0; i < n; i++) sum += in[i].amount;
    if (MODE == 2) ins[0].outpoint.txid[0] ^= 1;
    if (MODE == 12) ins[n - 1].outpoint.txid[0] ^= 1;
    if (MODE == 5) { memset(&ins[ni], 0, sizeof ins[ni]); ins[ni].outpoint = FUND; ni++; }
    if (MODE == 6 && ni > 1) ni--;
    if (MODE == 7 && ni > 1) { gz_xe_sweep_in_t t = ins[0]; ins[0] = ins[1]; ins[1] = t; }
    le32(tx + at, MODE == 9 ? 1 : 2); at += 4;
    if (MODE != 11) { tx[at++] = 0; tx[at++] = 1; }
    tx[at++] = (uint8_t)ni;
    for (size_t i = 0; i < ni; i++) {
        uint32_t seq = ins[i].csv ? (MODE == 13 ? ins[i].csv - 1 : ins[i].csv) : (MODE == 4 ? 0xffffffffu : 0xfffffffeu);
        op36(&ins[i].outpoint, tx + at); at += 36;
        if (MODE == 10 && i == 0) { tx[at++] = 1; tx[at++] = 0x51; }
        else tx[at++] = 0;
        le32(tx + at, seq); at += 4;
    }
    tx[at++] = 1;
    for (int i = 0; i < 8; i++) tx[at++] = (uint8_t)((sum - 500) >> (8 * i));
    tx[at++] = 34; tx[at++] = 0x51; tx[at++] = 0x20;
    memset(tx + at, 0xab, 32); at += 32;
    if (MODE != 11)
        for (size_t i = 0; i < ni; i++) {
            if (MODE == 8 && i == ni - 1) { tx[at++] = 0; continue; }
            tx[at++] = 1; tx[at++] = 64; memset(tx + at, 0x77, 64); at += 64;
        }
    le32(tx + at, MODE == 3 ? locktime + 1 : locktime); at += 4;
    *tx_len = at;
    return 1;
}

/* ---- set-up --------------------------------------------------------------- */

static void reset_chain(void)
{
    NT = 0;
    TIP = TIP0;
    HASHSEQ = 1;
    FORCED = 0;
    FLOOR = 0;
    REJECT_V2 = 0;
    HOLD_ON = 0;
    N_FAIL_OP = 0;
    N_FAIL_TX = 0;
    PEND_ON = 0;
    HASH_SKEW = 0;
    PPAR_LEN = 0;
}

static void reset_engine(void)
{
    gz_xe_port_t port = { fake_sweep, NULL };
    NJ = 0; JUSED = 0; NPEND = 0; NBC = 0; NLOG = 0; NW = 0; NCALL = 0; NRES = 0;
    DIGEST = 14695981039346656037ull;
    DROP_BCAST = 0; MODE = 0; VERIFY_OK = 1;
    CHECK(gz_xe_init(&X, SCOPE, &port) == GZ_OK);
    CHECK(gz_runner_init(&RUN, RSLOTS, sizeof RSLOTS / sizeof RSLOTS[0], RBYTES, sizeof RBYTES, ++INC, exec, NULL) == GZ_OK);
    gz_action_list_init(&L, LSLOTS, sizeof LSLOTS / sizeof LSLOTS[0], LBYTES, sizeof LBYTES);
}

static void begin(uint8_t why)
{
    int refused = -1;
    gz_action_list_reset(&L);
    CHECK(gz_xe_begin(&X, &PLAN, why, &L, &refused) == GZ_OK);
    CHECK(refused == 0);
    submit();
    deliver_results();
    settle();
}

/* A crash and a start from the journal (the runner, the watches and the
 * engine's memory are gone; the journal and the chain stay). Returns the
 * kinds of the first two actions of the start step, and the first
 * broadcast's txid. */
static uint8_t FIRST_TXID[32];
static void restart(gz_action_kind_t first[2])
{
    gz_xe_port_t port = { fake_sweep, NULL };
    int more = 1;
    DROP_BCAST = 0;
    NW = 0;
    NPEND = 0;
    CHECK(gz_xe_init(&X, SCOPE, &port) == GZ_OK);
    CHECK(gz_runner_init(&RUN, RSLOTS, sizeof RSLOTS / sizeof RSLOTS[0], RBYTES, sizeof RBYTES, ++INC, exec, NULL) == GZ_OK);
    for (size_t i = 0; i < NJ; i++) {
        gz_record_t r;
        gz_batch_id_t at = { INC - 1, i + 1 };
        r.type = J[i].type;
        r.bytes.data = JPOOL + J[i].off;
        r.bytes.len = J[i].len;
        CHECK(gz_xe_load(&X, &r, at) == GZ_OK);
    }
    gz_action_list_reset(&L);
    CHECK(gz_xe_resume(&X, &L, &more) == GZ_OK);
    CHECK(more == 0);
    first[0] = L.count > 0 ? L.slots[0].kind : (gz_action_kind_t)0;
    first[1] = L.count > 1 ? L.slots[1].kind : (gz_action_kind_t)0;
    memset(FIRST_TXID, 0, 32);
    if (L.count > 0 && L.slots[0].kind == GZ_ACTION_BROADCAST)
        txid_of(L.slots[0].u.broadcast.tx.data, L.slots[0].u.broadcast.tx.len, FIRST_TXID);
    submit();
    deliver_results();
    tip_events();
}

static const uint8_t *step_txid(size_t i) { return PLAN.node[PLAN.step[i].node].txid; }

static int first_bcast(const uint8_t txid[32])
{
    for (size_t i = 0; i < NBC; i++)
        if (memcmp(BC[i], txid, 32) == 0) return (int)i;
    return -1;
}

static size_t count_bcast_after(const uint8_t txid[32], size_t from)
{
    size_t n = 0;
    for (size_t i = from; i < NBC; i++) n += memcmp(BC[i], txid, 32) == 0;
    return n;
}

static int has_log(const char *what)
{
    size_t n = strlen(what);
    for (size_t i = 0; i < NLOG; i++)
        if (strncmp(LOGS[i], what, n) == 0) return 1;
    return 0;
}

static size_t count_log(const char *what)
{
    size_t n = strlen(what), c = 0;
    for (size_t i = 0; i < NLOG; i++) c += strncmp(LOGS[i], what, n) == 0;
    return c;
}

/* The last journaled exit_step state of step i, 0 if none. */
static int journal_step(size_t i)
{
    int st = 0;
    for (size_t k = 0; k < NJ; k++) {
        gz_bytes_t s = { JPOOL + J[k].off, J[k].len }, v;
        if (J[k].type != GZ_XE_REC_STEP) continue;
        if (gz_rec_find(s, 2, &v) != 1 || v.len != 2 || gz_get_u16(v.data) != i) continue;
        if (gz_rec_find(s, 6, &v) == 1 && v.len == 1) st = v.data[0];
    }
    return st;
}

static size_t journal_count(uint32_t type)
{
    size_t n = 0;
    for (size_t k = 0; k < NJ; k++) n += J[k].type == type;
    return n;
}

static size_t journal_done(uint8_t how)
{
    size_t n = 0;
    for (size_t k = 0; k < NJ; k++) {
        gz_bytes_t s = { JPOOL + J[k].off, J[k].len }, v;
        if (J[k].type == GZ_XE_REC_SWEEP_DONE && gz_rec_find(s, 4, &v) == 1 && v.len == 1 && v.data[0] == how) n++;
    }
    return n;
}

static int journal_class(const gz_outpoint_t *o, uint8_t cls)
{
    for (size_t k = 0; k < NJ; k++) {
        gz_bytes_t s = { JPOOL + J[k].off, J[k].len }, v, c;
        if (J[k].type != GZ_XE_REC_SEEN) continue;
        if (gz_rec_find(s, 2, &v) != 1 || v.len != 36) continue;
        /* the outpoint as saved: txid, then the index as a big-endian u32 */
        if (memcmp(v.data, o->txid, 32) != 0 || gz_get_u32(v.data + 32) != o->vout) continue;
        if (gz_rec_find(s, 6, &c) == 1 && c.len == 1 && c.data[0] == cls) return 1;
    }
    return 0;
}

static void fresh_member(uint32_t n, uint8_t d, int *member)
{
    gz_xe_tree_in_t in;
    uint8_t own[33];
    build(n);
    *member = member_at(d);
    CHECK(*member >= 0);
    if (*member < 0) abort();
    in = tin();
    memcpy(own, MEM[*member], 33);
    CHECK(gz_xe_plan_member(&in, (uint32_t)*member, own, &PLAN) == GZ_XE_PLAN_OK);
    CHECK(PLAN.n_steps == (uint16_t)(d + 2));
    reset_chain();
    reset_engine();
    tip_events();
}

/* Put the first k steps of `p` on chain, as a sibling would, one a block. */
static void confirm_steps(const gz_xe_plan_t *p, size_t k)
{
    uint64_t fee, vs;
    for (size_t i = 0; i < k; i++) {
        CHECK(chain_try(p->step[i].tx, p->step[i].len, 1, &fee, &vs) == 1);
        chain_mine();
    }
}

static void confirm_prefix(size_t k) { confirm_steps(&PLAN, k); }

static void host_plan(uint32_t n, const uint8_t *owed)
{
    gz_xe_tree_in_t in;
    build(n);
    in = tin();
    CHECK(gz_xe_plan_host(&in, owed, &PLAN) == GZ_XE_PLAN_OK);
    reset_chain();
    reset_engine();
    tip_events();
}

static int is_child_of(uint16_t c, uint16_t p) { return PLAN.node[c].parent == p; }

static int host_index(const uint8_t txid[32])
{
    for (uint16_t i = 0; i < PLAN.n_nodes; i++)
        if (memcmp(PLAN.node[i].txid, txid, 32) == 0) return i;
    return -1;
}

static int offered(const gz_outpoint_t *o)
{
    for (size_t c = 0; c < NCALL; c++)
        for (size_t i = 0; i < CALLS[c].n; i++)
            if (same_op(&CALLS[c].in[i].outpoint, o)) return 1;
    return 0;
}

static void input_op(const gz_xe_plan_t *p, uint16_t i, gz_outpoint_t *o)
{
    if (p->node[i].parent == GZ_XE_FUNDING) { *o = p->funding; return; }
    memcpy(o->txid, p->node[p->node[i].parent].txid, 32);
    o->vout = p->node[i].parent_vout;
}

/* ---- 1. plans, and starting ------------------------------------------------- */

static void test_plans(void)
{
    gz_xe_tree_in_t in;
    uint8_t own[33];
    static gz_tree_t SAVED;
    int refused;
    build(4);
    in = tin();
    memcpy(own, MEM[1], 33);
    CHECK(gz_xe_plan_member(&in, 1, own, &PLAN) == GZ_XE_PLAN_OK);
    CHECK(gz_xe_plan_member(&in, 2, own, &PLAN) == GZ_XE_PLAN_NOT_OURS);     /* another member's leaf */
    CHECK(gz_xe_plan_member(&in, 4, own, &PLAN) == GZ_XE_PLAN_NOT_OURS);     /* past the members */
    memcpy(own, HOSTK, 33);
    CHECK(gz_xe_plan_member(&in, 0, own, &PLAN) == GZ_XE_PLAN_NOT_OURS);     /* the host's key */
    CHECK(gz_xe_plan_member(NULL, 0, own, &PLAN) == GZ_XE_PLAN_ARGUMENT);
    CHECK(gz_xe_plan_host(&in, NULL, &PLAN) == GZ_XE_PLAN_OK);
    CHECK(PLAN.host && PLAN.n_steps == 1 && PLAN.n_nodes == TREE.n_nodes);

    /* The verifier: required, and asked about every step (M7). */
    memcpy(own, MEM[1], 33);
    VERIFY_CALLS = 0;
    CHECK(gz_xe_plan_member(&in, 1, own, &PLAN) == GZ_XE_PLAN_OK && VERIFY_CALLS == PLAN.n_steps);
    VERIFY_OK = 0;
    CHECK(gz_xe_plan_member(&in, 1, own, &PLAN) == GZ_XE_PLAN_BAD_SIGNATURE);
    CHECK(gz_xe_plan_host(&in, NULL, &PLAN) == GZ_XE_PLAN_BAD_SIGNATURE);
    VERIFY_OK = 1;
    in.verify = NULL;
    CHECK(gz_xe_plan_member(&in, 1, own, &PLAN) == GZ_XE_PLAN_ARGUMENT);
    in = tin();
    /* A member with a channel or a balance is not the tree half (M5). */
    in.has_channel = 1;
    CHECK(gz_xe_plan_member(&in, 1, own, &PLAN) == GZ_XE_PLAN_NOT_TREE_HALF);
    in.has_channel = 0;
    in.balance_sat = 1;
    CHECK(gz_xe_plan_member(&in, 1, own, &PLAN) == GZ_XE_PLAN_NOT_TREE_HALF);
    in = tin();

    /* A tree whose transactions do not chain, or are not what the tree says. */
    memcpy(&SAVED, &TREE, sizeof TREE);
    {
        gz_tree_node_t *lf = &TREE.node[TREE.leaf_state[1]];
        lf->tx[10] ^= 1;                                       /* the leaf's input altered */
        gz_tx_txid(lf->tx, lf->tx_len, lf->txid);
        CHECK(gz_xe_plan_member(&in, 1, own, &PLAN) == GZ_XE_PLAN_BAD_TREE);
        memcpy(&TREE, &SAVED, sizeof TREE);
        lf->tx[0] = 2;                                         /* version 2, not TRUC */
        gz_tx_txid(lf->tx, lf->tx_len, lf->txid);
        CHECK(gz_xe_plan_member(&in, 1, own, &PLAN) == GZ_XE_PLAN_BAD_TREE);
        memcpy(&TREE, &SAVED, sizeof TREE);
        lf->tx[lf->tx_len - 4 - 4 - 1 - 8] ^= 1;               /* the anchor's value (low byte) */
        gz_tx_txid(lf->tx, lf->tx_len, lf->txid);
        CHECK(gz_xe_plan_member(&in, 1, own, &PLAN) == GZ_XE_PLAN_BAD_TREE);
        memcpy(&TREE, &SAVED, sizeof TREE);
        TREE.node[0].tx[0] = 2;                                /* the root, for the host */
        gz_tx_txid(TREE.node[0].tx, TREE.node[0].tx_len, TREE.node[0].txid);
        CHECK(gz_xe_plan_host(&in, NULL, &PLAN) == GZ_XE_PLAN_BAD_TREE);
    }
    memcpy(&TREE, &SAVED, sizeof TREE);
    CHECK(gz_xe_plan_member(&in, 1, own, &PLAN) == GZ_XE_PLAN_OK);

    /* begin: no tip yet (L5); another factory's plan; twice. */
    reset_chain();
    reset_engine();
    gz_action_list_reset(&L);
    CHECK(gz_xe_begin(&X, &PLAN, GZ_XE_WHY_USER, &L, &refused) == GZ_OK && refused == GZ_XE_REFUSED_NO_TIP && L.count == 0);
    tip_events();
    gz_action_list_reset(&L);
    CHECK(gz_xe_begin(&X, NULL, GZ_XE_WHY_USER, &L, &refused) == GZ_OK && refused == GZ_XE_REFUSED_NO_PLAN && L.count == 0);
    memcpy(PLAN.scope, OTHER_SCOPE, 32);
    gz_action_list_reset(&L);
    CHECK(gz_xe_begin(&X, &PLAN, GZ_XE_WHY_USER, &L, &refused) == GZ_OK && refused == GZ_XE_REFUSED_SCOPE && L.count == 0);
    memcpy(PLAN.scope, SCOPE, 32);
    begin(GZ_XE_WHY_USER);
    gz_action_list_reset(&L);
    CHECK(gz_xe_begin(&X, &PLAN, GZ_XE_WHY_USER, &L, &refused) == GZ_OK && refused == GZ_XE_REFUSED_STARTED && L.count == 0);
    gz_action_list_reset(&L);
    CHECK(gz_xe_set_plan(&X, &PLAN, &L, &refused) == GZ_OK && refused == GZ_XE_REFUSED_STARTED && L.count == 0);

    /* The plan saved when live, replaced, then started with the plan held (M4). */
    {
        static gz_xe_plan_t FIRST;
        gz_action_kind_t first[2];
        gz_xe_tree_in_t hin = tin();
        uint8_t owed[GZ_TREE_MAX_MEMBERS / 8];
        memset(owed, 0, sizeof owed);
        owed[0] = 2;                                           /* member 1 owed */
        CHECK(gz_xe_plan_host(&hin, NULL, &FIRST) == GZ_XE_PLAN_OK);
        CHECK(gz_xe_plan_host(&hin, owed, &PLAN) == GZ_XE_PLAN_OK);
        reset_chain();
        reset_engine();
        tip_events();
        gz_action_list_reset(&L);
        CHECK(gz_xe_set_plan(&X, &FIRST, &L, &refused) == GZ_OK && refused == 0);
        submit();
        gz_action_list_reset(&L);
        CHECK(gz_xe_set_plan(&X, &PLAN, &L, &refused) == GZ_OK && refused == 0);   /* the owed list changed */
        submit();
        CHECK(journal_count(GZ_XE_REC_PLAN) == 2 && journal_count(GZ_XE_REC_STARTED) == 0);
        CHECK(NW == 0 && NBC == 0);                                                 /* not started: nothing */
        restart(first);                                                             /* both plans load */
        CHECK(n_watches() == 0);
        gz_action_list_reset(&L);
        CHECK(gz_xe_begin(&X, NULL, GZ_XE_WHY_HOST_RECOVER, &L, &refused) == GZ_OK && refused == 0);
        submit();
        settle();
        CHECK(journal_count(GZ_XE_REC_PLAN) == 2 && journal_count(GZ_XE_REC_STARTED) == 1);
        CHECK(X.plan.owed[0] == 2);                                                 /* the later plan */
        restart(first);
        CHECK(X.plan.owed[0] == 2);

        /* A plan after the start is a corrupt journal; so is a host plan
         * without its owed list (M3). */
        {
            gz_xe_port_t port = { fake_sweep, NULL };
            gz_record_t r;
            gz_batch_id_t at = { 1, 1 };
            size_t plan_at = 0;
            for (size_t k = 0; k < NJ; k++) if (J[k].type == GZ_XE_REC_PLAN) plan_at = k;
            CHECK(gz_xe_init(&X, SCOPE, &port) == GZ_OK);
            for (size_t k = 0; k < NJ; k++) {
                r.type = J[k].type; r.bytes.data = JPOOL + J[k].off; r.bytes.len = J[k].len;
                CHECK(gz_xe_load(&X, &r, at) == GZ_OK);
            }
            r.type = GZ_XE_REC_PLAN; r.bytes.data = JPOOL + J[plan_at].off; r.bytes.len = J[plan_at].len;
            CHECK(gz_xe_load(&X, &r, at) == GZ_ERR_CORRUPT);
            CHECK(gz_xe_init(&X, SCOPE, &port) == GZ_OK);
            r.bytes.len = J[plan_at].len - 34;                    /* field 16 (32 bytes) cut off */
            CHECK(gz_xe_load(&X, &r, at) == GZ_ERR_CORRUPT);
        }
    }

    /* Records that are not ones: a corrupt journal; a spend_seen the plan
     * does not name: ignored (L3). */
    {
        gz_xe_port_t port = { fake_sweep, NULL };
        static const uint8_t junk[] = { 0x00, 0x20, 0x01 };
        gz_record_t r = { GZ_XE_REC_PLAN, { junk, sizeof junk } };
        gz_batch_id_t at = { 1, 1 };
        uint8_t step[192], zero[36];
        size_t n = 0;
        CHECK(gz_xe_init(&X, SCOPE, &port) == GZ_OK);
        CHECK(gz_xe_load(&X, &r, at) == GZ_ERR_CORRUPT);
        CHECK(gz_xe_init(&X, SCOPE, &port) == GZ_OK);
        CHECK(gz_rec_put(step, sizeof step, &n, 0, SCOPE, 32) == GZ_OK);
        r.type = GZ_XE_REC_STEP;
        r.bytes.data = step;
        r.bytes.len = n;
        CHECK(gz_xe_load(&X, &r, at) == GZ_ERR_CORRUPT);            /* a step before the plan */
        r.type = 0x00010018u;                                       /* another engine's record */
        CHECK(gz_xe_load(&X, &r, at) == GZ_OK);
        /* a plan, then a spend_seen of an outpoint not in it */
        for (size_t k = 0; k < NJ; k++)
            if (J[k].type == GZ_XE_REC_PLAN) {
                r.type = GZ_XE_REC_PLAN; r.bytes.data = JPOOL + J[k].off; r.bytes.len = J[k].len;
                CHECK(gz_xe_load(&X, &r, at) == GZ_OK);
                break;
            }
        memset(zero, 0x99, sizeof zero);
        CHECK(gz_rec_put(step, sizeof step, &n, 2, zero, 36) == GZ_OK);
        CHECK(gz_rec_put(step, sizeof step, &n, 4, zero, 32) == GZ_OK);
        zero[0] = GZ_XE_S8;
        CHECK(gz_rec_put(step, sizeof step, &n, 6, zero, 1) == GZ_OK);
        CHECK(gz_rec_put(step, sizeof step, &n, 8, zero + 1, 4) == GZ_OK);
        r.type = GZ_XE_REC_SEEN;
        r.bytes.data = step;
        r.bytes.len = n;
        CHECK(gz_xe_load(&X, &r, at) == GZ_OK);
    }
}

/* ---- 2. a member's path: the order ---------------------------------------- */

static void test_member_path(uint32_t n, uint8_t d)
{
    int m;
    uint8_t how = 0;
    fresh_member(n, d, &m);
    begin(GZ_XE_WHY_USER);
    run_until_end(4 * (d + 2) + 10);
    CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);
    int last = -1;
    for (size_t i = 0; i < PLAN.n_steps; i++) {
        int b = first_bcast(step_txid(i));
        CHECK(b > last);                                            /* in path order */
        CHECK(b >= 0 && (size_t)b + 1 < NBC);
        if (b >= 0) {
            CHECK(memcmp(BC[b + 1], PLAN.step[i].child_txid, 32) == 0);   /* its child right after */
            CHECK(BC_TIP[b] == TIP0 + (uint32_t)i);                 /* one level per block */
            int t = tx_find(step_txid(i));
            CHECK(t >= 0 && T[t].height == TIP0 + (uint32_t)i + 1);
            last = b;
        }
        CHECK(journal_step(i) == GZ_XE_ST_BURIED);
    }
    CHECK(n_watches() == 0);                                        /* every watch dropped */
    CHECK(journal_class(&FUND, GZ_XE_S1));
    CHECK(!has_log("exit_step_late") && !has_log("exit_step_held_back"));
    {
        gz_outpoint_t a;
        memcpy(a.txid, step_txid(0), 32);
        a.vout = PLAN.node[PLAN.step[0].node].n_out - 1u;
        CHECK(journal_class(&a, GZ_XE_S9A));                       /* its own child on the anchor */
    }
}

/* ---- 3. skipping what is confirmed (U-2) ---------------------------------- */

static void test_skip(uint32_t n, uint8_t d)
{
    int m;
    for (size_t k = 0; k <= (size_t)d + 2; k++) {
        uint8_t how = 0;
        fresh_member(n, d, &m);
        confirm_prefix(k);
        tip_events();
        begin(GZ_XE_WHY_USER);
        run_until_end(4 * (d + 2) + 10);
        CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);
        for (size_t i = 0; i < PLAN.n_steps; i++) {
            if (i < k) CHECK(first_bcast(step_txid(i)) < 0);       /* never sent */
            else CHECK(first_bcast(step_txid(i)) >= 0);
        }
    }
    /* Two members: the second publishes only what the first did not (U-2). */
    {
        uint8_t own[33], how = 0;
        gz_xe_tree_in_t in;
        int a = -1, b = -1;
        static gz_xe_plan_t FIRST;
        build(n);
        a = member_at(d);                                           /* the second at any depth: 3 members have one at depth 1 */
        for (uint32_t i = 0; i < NMEM && b < 0; i++)
            if ((int)i != a) b = (int)i;
        CHECK(a >= 0 && b >= 0);
        if (a < 0 || b < 0) return;
        in = tin();
        reset_chain();
        reset_engine();
        tip_events();
        memcpy(own, MEM[a], 33);
        CHECK(gz_xe_plan_member(&in, (uint32_t)a, own, &PLAN) == GZ_XE_PLAN_OK);
        memcpy(&FIRST, &PLAN, sizeof PLAN);
        begin(GZ_XE_WHY_USER);
        run_until_end(40);
        CHECK(ended(&how));
        reset_engine();
        tip_events();
        memcpy(own, MEM[b], 33);
        CHECK(gz_xe_plan_member(&in, (uint32_t)b, own, &PLAN) == GZ_XE_PLAN_OK);
        begin(GZ_XE_WHY_USER);
        run_until_end(40);
        CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);
        size_t shared = 0;
        for (size_t i = 0; i < PLAN.n_steps && i < FIRST.n_steps; i++)
            if (memcmp(step_txid(i), FIRST.node[FIRST.step[i].node].txid, 32) == 0) shared = i + 1;
        CHECK(shared >= 1 && shared < PLAN.n_steps);
        for (size_t i = 0; i < PLAN.n_steps; i++)
            CHECK((first_bcast(step_txid(i)) < 0) == (i < shared));
    }
}

/* ---- 4. a restart with part of the path confirmed -------------------------- */

static void test_restart(uint32_t n, uint8_t d)
{
    int m;
    uint8_t how = 0;
    gz_action_kind_t first[2];

    /* a: crash after step 2 is sent; step 2 confirms while the program is down. */
    fresh_member(n, d, &m);
    begin(GZ_XE_WHY_USER);
    while (journal_step(2) != GZ_XE_ST_SENT && TIP < TIP0 + 20) block();
    CHECK(journal_step(2) == GZ_XE_ST_SENT);
    chain_mine();                                                   /* while down */
    size_t mark = NBC;
    restart(first);
    CHECK(first[0] == GZ_ACTION_BROADCAST && first[1] == GZ_ACTION_BROADCAST);   /* the sent step and its child first */
    CHECK(memcmp(FIRST_TXID, step_txid(2), 32) == 0);
    CHECK(count_bcast_after(step_txid(0), mark) == 0 && count_bcast_after(step_txid(1), mark) == 0);
    run_until_end(40);
    CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);

    /* b: the broadcast of step 1 lost in the crash (saved, never sent). */
    fresh_member(n, d, &m);
    begin(GZ_XE_WHY_USER);
    DROP_BCAST = 1;
    block();                                                        /* the root confirms; step 1 saved, its broadcast lost */
    CHECK(journal_step(0) >= GZ_XE_ST_CONFIRMED);
    CHECK(journal_step(1) == GZ_XE_ST_SENT && tx_find(step_txid(1)) < 0);
    restart(first);
    CHECK(tx_find(step_txid(1)) >= 0);                              /* sent at the start */
    run_until_end(40);
    CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);

    /* c: a sibling confirms steps 1 and 2 while the program is down. */
    fresh_member(n, d, &m);
    begin(GZ_XE_WHY_USER);
    block();                                                        /* the root confirmed, step 1 sent */
    CHECK(journal_step(1) == GZ_XE_ST_SENT);
    chain_mine();                                                   /* step 1 confirms */
    {
        uint64_t fee, vs;
        CHECK(chain_try(PLAN.step[2].tx, PLAN.step[2].len, 1, &fee, &vs) == 1);
    }
    chain_mine();                                                   /* step 2 confirms */
    mark = NBC;
    restart(first);
    run_until_end(40);
    CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);
    CHECK(count_bcast_after(step_txid(2), mark) == 0);              /* never sent by this member */
    CHECK(count_bcast_after(step_txid(0), mark) == 0);
    for (size_t i = 3; i < PLAN.n_steps; i++) CHECK(count_bcast_after(step_txid(i), mark) >= 1);
}

/* ---- 5. the host: the root, then the timeouts (S1) ------------------------- */

static void test_host_s1(uint32_t n)
{
    uint8_t how = 0;
    host_plan(n, NULL);
    begin(GZ_XE_WHY_HOST_RECOVER);
    CHECK(first_bcast(PLAN.node[0].txid) == 0);                     /* the root kickoff at once */
    while (TIP < END - 6) block();
    CHECK(NCALL == 0);                                              /* nothing before E - 5 */
    block();                                                        /* tip E - 5 */
    CHECK(NCALL == 1);
    if (NCALL != 1) return;
    CHECK(CALLS[0].tip == END - 5 && CALLS[0].locktime == END - 5);
    size_t kids = 0;
    uint64_t sum = 0, outs = 0;
    for (uint16_t c = 0; c < PLAN.n_nodes; c++)
        if (is_child_of(c, 0)) { kids++; outs += PLAN.node[c].in_amount; }
    CHECK(CALLS[0].n == kids);
    for (size_t i = 0; i < CALLS[0].n; i++) {
        const gz_xe_sweep_in_t *s = &CALLS[0].in[i];
        CHECK(s->what == GZ_XE_OUT_INPUT && is_child_of(s->node, 0) && s->lock == END - 5 && s->csv == 0);
        CHECK(memcmp(s->outpoint.txid, PLAN.node[0].txid, 32) == 0 && s->amount == PLAN.node[s->node].in_amount);
        CHECK(journal_class(&s->outpoint, GZ_XE_S1) == 0);
        sum += s->amount;
    }
    CHECK(sum == outs);
    run_until_end(20);
    CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
    CHECK(NCALL == 1);
    CHECK(n_watches() == 0);
    CHECK(journal_class(&FUND, GZ_XE_S1));
    CHECK(journal_class(&CALLS[0].in[0].outpoint, GZ_XE_S2));          /* host-side classes (T6) */
    CHECK(journal_done(GZ_XE_SWEEP_SETTLED) == 1);
}

/* ---- 6. the host after a member's path: untouched subtrees (S4, R5, T1) ---- */

static void test_host_s4(uint32_t n, uint8_t d, int owe)
{
    uint8_t own[33], how = 0, owed[GZ_TREE_MAX_MEMBERS / 8];
    static gz_xe_plan_t MPLAN;
    gz_xe_tree_in_t in;
    gz_action_kind_t first[2];
    int m;
    build(n);
    m = member_at(d);
    CHECK(m >= 0);
    if (m < 0) return;
    in = tin();
    memcpy(own, MEM[m], 33);
    CHECK(gz_xe_plan_member(&in, (uint32_t)m, own, &MPLAN) == GZ_XE_PLAN_OK);
    memset(owed, 0, sizeof owed);
    int other = m == 0 ? (int)NMEM - 1 : 0;                     /* a member whose subtree stays untouched */
    if (owe) {
        owed[m / 8] |= (uint8_t)(1u << (m % 8));               /* T1: the member whose leaf is on chain */
        owed[other / 8] |= (uint8_t)(1u << (other % 8));
    }
    host_plan(n, owe ? owed : NULL);
    confirm_steps(&MPLAN, MPLAN.n_steps);                       /* the member's path on chain first */
    tip_events();
    begin(GZ_XE_WHY_HOST_RECOVER);
    uint16_t leaf = MPLAN.step[MPLAN.n_steps - 1].node;
    const uint8_t *leaf_txid = MPLAN.node[leaf].txid;
    uint32_t h_leaf = (uint32_t)gz_exit_h_leaf(END, d);
    if (owe) {
        while (TIP < h_leaf - 5) block();
        restart(first);                                         /* the owed list survives a start */
        while (TIP < h_leaf + 200) block();
    } else {
        while (!ended(NULL) && TIP < END + 200) block();
    }
    CHECK(first_bcast(PLAN.node[0].txid) < 0);                      /* the root was already there */

    /* Every output offered once, at the first tip it may be spent, never one with an owed member below. */
    uint64_t swept = 0;
    size_t n_offered = 0;
    int lt = tx_find(leaf_txid);
    CHECK(lt >= 0);
    for (size_t c = 0; c < NCALL; c++) {
        uint32_t lock = 0;
        for (size_t i = 0; i < CALLS[c].n; i++) {
            const gz_xe_sweep_in_t *s = &CALLS[c].in[i];
            const gz_xe_node_t *nd = &PLAN.node[s->node];
            n_offered++;
            swept += s->amount;
            if (s->lock > lock) lock = s->lock;
            if (s->what == GZ_XE_OUT_INPUT) {
                CHECK(s->lock == nd->cltv && CALLS[c].tip == nd->cltv);
                CHECK(!(owe && (uint32_t)m >= nd->first && (uint32_t)m < (uint32_t)nd->first + nd->count));
                CHECK(!(owe && (uint32_t)other >= nd->first && (uint32_t)other < (uint32_t)nd->first + nd->count));
            } else if (s->what == GZ_XE_OUT_CHANNEL) {
                CHECK(!owe);                                         /* T1: never, even after H_leaf + 200 */
                CHECK(memcmp(s->outpoint.txid, leaf_txid, 32) == 0 && s->outpoint.vout == 0);
                CHECK(s->lock == nd->cltv && CALLS[c].tip == nd->cltv);             /* H_leaf, not H_leaf - 1 */
                CHECK(nd->cltv == h_leaf);
            } else {
                CHECK(s->what == GZ_XE_OUT_SPARE && s->outpoint.vout == 1 && s->csv == 144);
                CHECK(lt >= 0 && CALLS[c].tip == T[lt].height + 143);                /* 144 confirmations, not 143 */
            }
            for (size_t c2 = 0; c2 < NCALL; c2++)
                for (size_t i2 = 0; i2 < CALLS[c2].n; i2++)
                    if ((c2 != c || i2 != i) && same_op(&CALLS[c2].in[i2].outpoint, &s->outpoint))
                        CHECK(0);                                    /* offered twice */
        }
        CHECK(CALLS[c].locktime == lock);
    }
    if (owe) {
        CHECK(!ended(NULL));                                        /* the owed member's channel stays */
        return;
    }
    CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
    /* The member's path as the host classed it (S1), its sweeps (S2, S3). */
    for (size_t i = 0; i < MPLAN.n_steps; i++) {
        gz_outpoint_t o;
        input_op(&MPLAN, (uint16_t)i, &o);
        CHECK(journal_class(&o, GZ_XE_S1));
    }
    {
        gz_outpoint_t o;
        memcpy(o.txid, leaf_txid, 32);
        o.vout = 0;
        CHECK(journal_class(&o, GZ_XE_S2));
        o.vout = 1;
        CHECK(journal_class(&o, GZ_XE_S3));
    }
    /* The coins: the funding = what was swept + each published transaction's fee and anchor. */
    uint64_t kept = 0;
    for (size_t i = 0; i < MPLAN.n_steps; i++) {
        const gz_xe_node_t *nd = &MPLAN.node[MPLAN.step[i].node];
        uint64_t out = nd->chan_amount + nd->spare_amount;
        for (uint16_t c = 0; c < PLAN.n_nodes; c++) {
            const gz_xe_node_t *hp = &PLAN.node[c];
            if (hp->parent != GZ_XE_FUNDING && memcmp(PLAN.node[hp->parent].txid, nd->txid, 32) == 0) out += hp->in_amount;
        }
        kept += nd->in_amount - out;
    }
    CHECK(FUND_AMT == swept + kept);
    CHECK(n_offered >= 2);
}

/* ---- 7. what a spend means ------------------------------------------------- */

static void test_classes(void)
{
    int m;
    uint8_t how = 0;

    /* S9b: a stranger's child on the root's anchor; the exit goes on. */
    fresh_member(4, 2, &m);
    begin(GZ_XE_WHY_USER);
    {
        gz_outpoint_t a;
        memcpy(a.txid, step_txid(0), 32);
        a.vout = PLAN.node[PLAN.step[0].node].n_out - 1u;
        block();                                                    /* the root confirms */
        chain_force(&a);                                            /* evicts our child */
        run_until_end(40);
        CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);
        CHECK(journal_class(&a, GZ_XE_S9B) && !journal_class(&a, GZ_XE_S9A));
        CHECK(!has_log("unexplained_spend"));
    }

    /* S2: step 1's input taken above its timeout height (the host's leaf),
     * buried: the end. */
    fresh_member(4, 2, &m);
    confirm_prefix(1);
    {
        gz_outpoint_t o;
        const gz_xe_node_t *s1 = &PLAN.node[PLAN.step[1].node];
        memcpy(o.txid, step_txid(0), 32);
        o.vout = s1->parent_vout;
        while (TIP < s1->cltv) chain_mine();
        chain_force(&o);
        chain_mine();                                               /* in block cltv + 1 */
        chain_mine();
        chain_mine();
        tip_events();
        begin(GZ_XE_WHY_USER);
        CHECK(ended(&how) && how == GZ_XE_END_HOST_TIMEOUT);
        CHECK(journal_class(&o, GZ_XE_S2));
        CHECK(NBC == 0);
    }

    /* S8: the same spend at exactly its timeout height (T6). */
    fresh_member(4, 2, &m);
    confirm_prefix(1);
    {
        gz_outpoint_t o;
        const gz_xe_node_t *s1 = &PLAN.node[PLAN.step[1].node];
        memcpy(o.txid, step_txid(0), 32);
        o.vout = s1->parent_vout;
        while (TIP < s1->cltv - 1) chain_mine();
        chain_force(&o);
        chain_mine();                                               /* in block cltv */
        chain_mine();
        chain_mine();
        tip_events();
        begin(GZ_XE_WHY_USER);
        CHECK(ended(&how) && how == GZ_XE_END_UNEXPLAINED);
        CHECK(journal_class(&o, GZ_XE_S8) && !journal_class(&o, GZ_XE_S2));
        CHECK(has_log("unexplained_spend"));
    }

    /* S8 at one confirmation, then gone in a reorganisation: classified, but
     * no end before B (M1); the path goes on. */
    fresh_member(4, 2, &m);
    confirm_prefix(1);
    tip_events();
    begin(GZ_XE_WHY_USER);                                          /* step 1 sent */
    {
        gz_outpoint_t o;
        uint8_t forced[32];
        memcpy(o.txid, step_txid(0), 32);
        o.vout = PLAN.node[PLAN.step[1].node].parent_vout;
        chain_force(&o);                                            /* evicts step 1 */
        memcpy(forced, T[NT - 1].txid, 32);
        block();                                                    /* the stranger at 1 confirmation */
        CHECK(journal_class(&o, GZ_XE_S8));
        CHECK(!ended(NULL));
        chain_unconfirm(forced);
        tip_events();                                               /* the same height, another block */
        chain_vanish(forced);
        run_until_end(40);
        CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);
    }
}

/* ---- 8. reorganisations (R3, T4) ------------------------------------------- */

static void test_reorg(void)
{
    int m;
    uint8_t how = 0;
    /* A confirmed step taken out. */
    fresh_member(4, 2, &m);
    begin(GZ_XE_WHY_USER);
    block();
    block();
    CHECK(journal_step(1) == GZ_XE_ST_CONFIRMED);
    size_t mark = NBC;
    chain_unconfirm(step_txid(1));
    tip_events();                                                   /* the same height, another block */
    CHECK(journal_step(1) == GZ_XE_ST_SENT);                        /* missing again */
    block();
    CHECK(count_bcast_after(step_txid(1), mark) >= 1);              /* and sent again */
    run_until_end(40);
    CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);

    /* A buried step taken out. */
    fresh_member(4, 2, &m);
    begin(GZ_XE_WHY_USER);
    for (int i = 0; i < 4; i++) block();
    CHECK(journal_step(0) == GZ_XE_ST_BURIED);
    chain_unconfirm(step_txid(0));
    tip_events();
    CHECK(journal_step(0) == GZ_XE_ST_SENT);
    run_until_end(40);
    CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);
}

/* ---- 9. no decision on an unsynced view ----------------------------------- */

static void test_unsynced(void)
{
    int refused = -1;
    build(4);
    {
        gz_xe_tree_in_t in = tin();
        uint8_t own[33];
        memcpy(own, MEM[0], 33);
        CHECK(gz_xe_plan_member(&in, 0, own, &PLAN) == GZ_XE_PLAN_OK);
    }
    reset_chain();
    reset_engine();
    chain_ev(GZ_CHAIN_NEW_TIP, TIP, NULL, NULL, 0);                 /* no TIP_SYNCED yet */
    gz_action_list_reset(&L);
    CHECK(gz_xe_begin(&X, &PLAN, GZ_XE_WHY_USER, &L, &refused) == GZ_OK && refused == 0);
    submit();
    CHECK(NBC == 0);
    settle();                                                       /* every watch synced */
    CHECK(NBC == 0);                                                /* still no tip synced */
    chain_ev(GZ_CHAIN_TIP_SYNCED, TIP, NULL, NULL, 0);
    CHECK(NBC == 2 && first_bcast(step_txid(0)) == 0);              /* the root and its child */
    /* A TIP_SYNCED for another block at the same height decides nothing. */
    chain_mine();
    chain_ev(GZ_CHAIN_NEW_TIP, TIP, NULL, NULL, 0);
    size_t before = NBC;
    for (size_t i = 0; i < NW; i++) if (W[i].used) report(&W[i], 0);
    CHECK(NBC == before);
    HASH_SKEW = 7;
    chain_ev(GZ_CHAIN_TIP_SYNCED, TIP, NULL, NULL, 0);
    HASH_SKEW = 0;
    CHECK(first_bcast(step_txid(1)) < 0);
    chain_ev(GZ_CHAIN_TIP_SYNCED, TIP, NULL, NULL, 0);
    settle();
    CHECK(first_bcast(step_txid(1)) >= 0);

    /* A watch told pending holds the factory until it syncs (T3). */
    reset_chain();
    reset_engine();
    tip_events();
    PEND_OP = FUND;
    PEND_ON = 1;
    begin(GZ_XE_WHY_USER);
    CHECK(NBC == 0);
    tip_events();
    CHECK(NBC == 0);
    release_pending();
    CHECK(first_bcast(step_txid(0)) == 0);

    /* The host too (T3). */
    host_plan(4, NULL);
    reset_engine();
    chain_ev(GZ_CHAIN_NEW_TIP, TIP, NULL, NULL, 0);
    gz_action_list_reset(&L);
    CHECK(gz_xe_begin(&X, &PLAN, GZ_XE_WHY_HOST_RECOVER, &L, &refused) == GZ_OK && refused == 0);
    submit();
    settle();
    CHECK(NBC == 0);
    chain_ev(GZ_CHAIN_TIP_SYNCED, TIP, NULL, NULL, 0);
    CHECK(first_bcast(PLAN.node[0].txid) == 0);
}

/* ---- 10. failed watches: spent deeper than the view follows (H1, T3) ------- */

static void test_failed(void)
{
    int m;
    uint8_t how = 0;
    gz_action_kind_t first[2];

    /* The member's root buried long ago: a start must not take it for missing. */
    fresh_member(4, 2, &m);
    begin(GZ_XE_WHY_USER);
    for (int i = 0; i < 4; i++) block();
    CHECK(journal_step(0) == GZ_XE_ST_BURIED);
    FAIL_OP[N_FAIL_OP++] = FUND;
    memcpy(FAIL_TX[N_FAIL_TX++], step_txid(0), 32);
    size_t mark = NBC, steps_before = journal_count(GZ_XE_REC_STEP);
    restart(first);
    CHECK(count_bcast_after(step_txid(0), mark) == 0);              /* never sent again */
    CHECK(journal_step(0) == GZ_XE_ST_BURIED);                      /* no false "left the chain" */
    CHECK(has_log("exit_watch_failed"));
    run_until_end(40);
    CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);
    CHECK(count_bcast_after(step_txid(0), mark) == 0);
    CHECK(journal_count(GZ_XE_REC_STEP) > steps_before);

    /* The funding spent long ago by something else: at risk, the end. */
    fresh_member(4, 2, &m);
    chain_force(&FUND);
    for (int i = 0; i < 3; i++) chain_mine();
    FAIL_OP[N_FAIL_OP++] = FUND;
    tip_events();
    begin(GZ_XE_WHY_USER);
    CHECK(ended(&how) && how == GZ_XE_END_UNEXPLAINED);
    CHECK(NBC == 0 && has_log("exit_watch_failed") && has_log("unexplained_spend"));

    /* The host: a root output spent long ago by something else is never swept. */
    host_plan(4, NULL);
    {
        gz_outpoint_t o;
        uint16_t c = 0;
        while (c < PLAN.n_nodes && !is_child_of(c, 0)) c++;
        input_op(&PLAN, c, &o);
        FAIL_OP[N_FAIL_OP++] = o;
        begin(GZ_XE_WHY_HOST_RECOVER);
        block();                                                    /* the root confirms */
        chain_force(&o);
        while (!ended(NULL) && TIP < END + 20) block();
        CHECK(!offered(&o));
        CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
        CHECK(has_log("exit_watch_failed"));
    }

    /* The host: a member's kickoff confirmed long ago (its input's watch and
     * its txid's both failed): the frontier goes on below it. */
    {
        static gz_xe_plan_t MPLAN;
        gz_xe_tree_in_t in;
        uint8_t own[33];
        gz_outpoint_t o;
        build(4);
        m = member_at(2);
        in = tin();
        memcpy(own, MEM[m], 33);
        CHECK(gz_xe_plan_member(&in, (uint32_t)m, own, &MPLAN) == GZ_XE_PLAN_OK);
        host_plan(4, NULL);
        confirm_steps(&MPLAN, 2);
        tip_events();
        input_op(&MPLAN, 1, &o);
        FAIL_OP[N_FAIL_OP++] = o;
        memcpy(FAIL_TX[N_FAIL_TX++], MPLAN.node[MPLAN.step[1].node].txid, 32);
        begin(GZ_XE_WHY_HOST_RECOVER);
        while (!ended(NULL) && TIP < END + 20) block();
        int k = host_index(MPLAN.node[MPLAN.step[1].node].txid);
        int below = 0;
        CHECK(k >= 0);
        for (size_t c = 0; c < NCALL; c++)
            for (size_t i = 0; i < CALLS[c].n; i++)
                if (k >= 0 && PLAN.node[CALLS[c].in[i].node].parent == (uint16_t)k) below = 1;
        CHECK(below);
        CHECK(!offered(&o));
        CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
    }
}

/* ---- 11. the sweep port: every fault is an outcome (M2, T2) ---------------- */

static void test_port(void)
{
    uint8_t how = 0;
    for (int mode = 1; mode <= 12; mode++) {
        host_plan(4, NULL);
        begin(GZ_XE_WHY_HOST_RECOVER);
        MODE = mode;
        while (TIP < END - 5) block();
        chain_ev(GZ_CHAIN_TIP_SYNCED, TIP, NULL, NULL, 0);          /* another decision, the same tip */
        CHECK(NCALL == 1 && CALLS[0].n >= 2);
        CHECK(X.port_refused == 1);
        if (X.port_refused != 1) printf("port mode %d not refused\n", mode);
        CHECK(journal_count(GZ_XE_REC_SWEEP) == 0);
        CHECK(NBC == 2);                                            /* the root and its child only */
        block();                                                    /* once per tip */
        CHECK(NCALL == 2);
        MODE = 0;
        block();
        CHECK(NCALL == 3 && journal_count(GZ_XE_REC_SWEEP) == 1);
        run_until_end(20);
        CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
    }

    /* A spare sweep with a sequence one short of its delay: refused. */
    {
        static gz_xe_plan_t MPLAN;
        gz_xe_tree_in_t in;
        uint8_t own[33];
        gz_outpoint_t sp;
        int m;
        build(4);
        m = member_at(2);
        in = tin();
        memcpy(own, MEM[m], 33);
        CHECK(gz_xe_plan_member(&in, (uint32_t)m, own, &MPLAN) == GZ_XE_PLAN_OK);
        host_plan(4, NULL);
        confirm_steps(&MPLAN, MPLAN.n_steps);
        tip_events();
        MODE = 13;
        begin(GZ_XE_WHY_HOST_RECOVER);
        memcpy(sp.txid, MPLAN.node[MPLAN.step[MPLAN.n_steps - 1].node].txid, 32);
        sp.vout = 1;
        int lt = tx_find(sp.txid);
        while (lt >= 0 && TIP < T[lt].height + 150) block();
        CHECK(offered(&sp));
        CHECK(X.port_refused >= 1);
        uint8_t b[36];
        op36(&sp, b);
        CHECK(spender(b) < 0);
    }

    /* A sweep the chain refuses: seen nowhere, retired after its life, its
     * inputs offered again (M2, item 3). */
    host_plan(4, NULL);
    begin(GZ_XE_WHY_HOST_RECOVER);
    REJECT_V2 = 1;
    while (TIP < END - 5) block();
    CHECK(NCALL == 1 && journal_count(GZ_XE_REC_SWEEP) == 1);
    while (TIP < END - 5 + GZ_XE_SWEEP_LIFE - 1) block();
    CHECK(journal_done(GZ_XE_SWEEP_RETIRED) == 0);
    block();
    CHECK(journal_done(GZ_XE_SWEEP_RETIRED) == 1 && has_log("host_sweep_retired"));
    CHECK(has_log("host_sweep_refused"));
    CHECK(NCALL == 2);                                              /* offered again at once */
    REJECT_V2 = 0;
    run_until_end(20);
    CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
}

/* ---- 12. a sweep losing an input; the own-transaction exclusion ------------ */

static void test_dead_sweep(void)
{
    uint8_t how = 0;
    host_plan(4, NULL);
    begin(GZ_XE_WHY_HOST_RECOVER);
    while (TIP < END - 5) block();
    CHECK(NCALL == 1);
    gz_outpoint_t o = CALLS[0].in[0].outpoint;
    size_t n0 = CALLS[0].n;
    chain_force(&o);                                                /* evicts the sweep */
    block();
    block();
    CHECK(NCALL == 1 && journal_done(GZ_XE_SWEEP_DEAD) == 0);      /* not dead before B */
    block();                                                        /* the stranger buried */
    CHECK(journal_done(GZ_XE_SWEEP_DEAD) == 1);
    CHECK(NCALL == 2 && CALLS[1].n == n0 - 1);
    for (size_t i = 0; i < CALLS[1].n; i++) CHECK(!same_op(&CALLS[1].in[i].outpoint, &o));
    run_until_end(20);
    CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
    CHECK(journal_class(&o, GZ_XE_S8));

    /* A root output whose own tree transaction sits in a mempool is not swept. */
    {
        static gz_xe_plan_t MPLAN;
        gz_xe_tree_in_t in;
        uint8_t own[33];
        gz_outpoint_t k1;
        uint64_t fee, vs;
        int m;
        build(4);
        m = member_at(2);
        in = tin();
        memcpy(own, MEM[m], 33);
        CHECK(gz_xe_plan_member(&in, (uint32_t)m, own, &MPLAN) == GZ_XE_PLAN_OK);
        host_plan(4, NULL);
        begin(GZ_XE_WHY_HOST_RECOVER);
        while (TIP < END - 6) block();
        memcpy(HOLD, MPLAN.node[MPLAN.step[1].node].txid, 32);
        HOLD_ON = 1;
        CHECK(chain_try(MPLAN.step[1].tx, MPLAN.step[1].len, 1, &fee, &vs) == 1);
        block();                                                    /* E - 5 */
        input_op(&MPLAN, 1, &k1);
        CHECK(NCALL == 1);
        CHECK(!offered(&k1));
        /* It vanishes unreported: asked about again after its stale tips, then swept (L2). */
        chain_vanish(HOLD);
        HOLD_ON = 0;
        for (unsigned i = 0; i < GZ_XE_STALE_TIPS + 2; i++) block();
        CHECK(offered(&k1));
    }
}

/* ---- 13. the sweep reorganised out; the funding spent elsewhere ----------- */

static void test_host_chain(void)
{
    uint8_t how = 0;
    host_plan(4, NULL);
    begin(GZ_XE_WHY_HOST_RECOVER);
    while (TIP < END - 4) block();                                  /* the sweep at 1 confirmation */
    CHECK(NCALL == 1);
    uint8_t sw[32];
    {
        uint8_t b[36];
        op36(&CALLS[0].in[0].outpoint, b);
        int s = spender(b);
        CHECK(s >= 0 && T[s].height == END - 4);
        if (s < 0) return;
        memcpy(sw, T[s].txid, 32);
    }
    CHECK(journal_done(GZ_XE_SWEEP_SETTLED) == 0);
    chain_unconfirm(sw);
    tip_events();                                                   /* reported at 0 confirmations */
    chain_vanish(sw);                                               /* then gone, unreported */
    size_t mark = NBC;
    block();
    CHECK(count_bcast_after(sw, mark) >= 1);                        /* the same sweep again */
    run_until_end(20);
    CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
    CHECK(NCALL == 1);

    /* The funding spent by something else and buried: the end (L4). */
    host_plan(4, NULL);
    chain_force(&FUND);
    chain_mine();
    tip_events();
    begin(GZ_XE_WHY_HOST_RECOVER);
    CHECK(!ended(NULL));                                            /* not before B */
    block();
    block();
    CHECK(ended(&how) && how == GZ_XE_END_FUNDING_SPENT);
    CHECK(has_log("funding_spent_elsewhere"));
    CHECK(first_bcast(PLAN.node[0].txid) < 0);
}

/* ---- 14. host restarts (T5) ------------------------------------------------ */

static void test_host_restart(void)
{
    uint8_t how = 0;
    gz_action_kind_t first[2];

    /* A live sweep sent again first. */
    host_plan(4, NULL);
    begin(GZ_XE_WHY_HOST_RECOVER);
    while (TIP < END - 5) block();
    CHECK(NCALL == 1);
    uint8_t sw[32];
    memcpy(sw, BC[NBC - 1], 32);
    restart(first);
    CHECK(first[0] == GZ_ACTION_BROADCAST && memcmp(FIRST_TXID, sw, 32) == 0);
    run_until_end(20);
    CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED && NCALL == 1);

    /* A sweep saved, its broadcast lost in the crash. */
    host_plan(4, NULL);
    begin(GZ_XE_WHY_HOST_RECOVER);
    while (TIP < END - 6) block();
    DROP_BCAST = 1;
    block();
    CHECK(NCALL == 1 && journal_count(GZ_XE_REC_SWEEP) == 1);
    restart(first);
    CHECK(first[0] == GZ_ACTION_BROADCAST);
    run_until_end(20);
    CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED && NCALL == 1);

    /* More than 16 sweeps over a life, every one retired but the last. */
    host_plan(4, NULL);
    begin(GZ_XE_WHY_HOST_RECOVER);
    REJECT_V2 = 1;
    while (NCALL < 18 && TIP < END + 200) block();
    CHECK(NCALL >= 18 && journal_count(GZ_XE_REC_SWEEP) >= 17);
    restart(first);                                                 /* loads, no slot short */
    CHECK(first[0] == GZ_ACTION_BROADCAST);
    REJECT_V2 = 0;
    run_until_end(30);
    CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
}

/* ---- 15. relay floors: packages, and a step held back (B5, B7) ------------- */

static void test_floor(void)
{
    int m;
    uint8_t how = 0;
    /* At 1 sat/vB each step goes only with its child, which follows it. */
    fresh_member(4, 2, &m);
    FLOOR = 1000;
    begin(GZ_XE_WHY_USER);
    run_until_end(40);
    CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);
    /* At 10 sat/vB not even the package: refused every block, held back. */
    fresh_member(4, 2, &m);
    FLOOR = 10000;
    begin(GZ_XE_WHY_USER);
    for (int i = 0; i < 8; i++) block();
    CHECK(tx_find(step_txid(0)) < 0);
    CHECK(count_log("exit_step_held_back") == 1);
    FLOOR = 0;
    run_until_end(40);
    CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);
}

/* ---- 16. a late step ------------------------------------------------------- */

static void test_late(void)
{
    int m;
    fresh_member(4, 2, &m);
    int64_t due = gz_exit_step_due((int64_t)END, 2, 0, 5, &PLAN.c);
    while ((int64_t)TIP <= due) chain_mine();
    tip_events();
    begin(GZ_XE_WHY_USER);
    CHECK(has_log("exit_step_late"));
}

/* ---- 17. 256 members (T7) -------------------------------------------------- */

static void test_256(void)
{
    gz_xe_tree_in_t in;
    uint8_t own[33], how = 0;
    gz_action_kind_t first[2];
    build(256);
    in = tin();
    CHECK(gz_xe_plan_host(&in, NULL, &PLAN) == GZ_XE_PLAN_OK);
    CHECK(PLAN.n_nodes == TREE.n_nodes);
    reset_chain();
    reset_engine();
    tip_events();
    begin(GZ_XE_WHY_HOST_RECOVER);                                  /* the plan record fits one step */
    CHECK(journal_count(GZ_XE_REC_PLAN) == 1);
    restart(first);                                                 /* and loads back */
    CHECK(X.plan.n_nodes == TREE.n_nodes);
    memcpy(own, MEM[255], 33);
    CHECK(gz_xe_plan_member(&in, 255, own, &PLAN) == GZ_XE_PLAN_OK);
    reset_chain();
    reset_engine();
    tip_events();
    begin(GZ_XE_WHY_USER);
    run_until_end(4u * PLAN.n_steps + 10u);
    CHECK(ended(&how) && how == GZ_XE_END_TREE_PATH_DONE);
}

/* ---- 18. the same events, the same actions -------------------------------- */

static uint64_t one_run(void)
{
    int m;
    fresh_member(16, 3, &m);
    begin(GZ_XE_WHY_USER);
    run_until_end(40);
    return DIGEST;
}

int main(void)
{
    gz_action_list_init(&L, LSLOTS, sizeof LSLOTS / sizeof LSLOTS[0], LBYTES, sizeof LBYTES);
    test_plans();
    test_member_path(3, 1);
    test_member_path(4, 2);
    test_member_path(16, 3);
    test_skip(4, 2);
    test_skip(16, 3);
    test_skip(3, 1);
    test_restart(4, 2);
    test_restart(16, 3);
    test_host_s1(3);
    test_host_s1(4);
    test_host_s1(16);
    test_host_s4(4, 2, 0);
    test_host_s4(16, 3, 0);
    test_host_s4(3, 1, 0);
    test_host_s4(4, 2, 1);
    test_host_s4(16, 3, 1);
    test_classes();
    test_reorg();
    test_unsynced();
    test_failed();
    test_port();
    test_dead_sweep();
    test_host_chain();
    test_host_restart();
    test_floor();
    test_late();
    test_256();
    {
        uint64_t a = one_run(), b = one_run();
        CHECK(a == b);
    }
    return check_done();
}
