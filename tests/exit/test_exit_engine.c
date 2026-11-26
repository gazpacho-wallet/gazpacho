/* The exit engine's tree half (spec/exit.md 6.8; Slice 1.5 plan item P3),
 * over trees built from T1 at depths 1, 2 and 3 (3, 4 and 16 members), driven
 * through the real runner (save before send) against a pretend chain and a
 * pretend chain view that follow action.h's watch contract.
 *
 * The pretend chain: a transaction enters the mempool if its inputs exist and
 * are not spent, and its lock time is final at the next block; a block mines
 * every mempool transaction whose inputs were confirmed in an earlier block
 * (so one tree level per block, as TRUC makes it) and whose lock time is
 * below the block's height. Relative lock times are not modelled: the test
 * checks the engine's timing of the spare sweep itself.
 *
 * THE KEYS ARE TEST KEYS. The signatures are fixed bytes: the engine does not
 * verify them (the program does, before the hand-over). */
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

static void build(uint32_t n)
{
    gz_terms_outer_t t;
    gz_tree_build_in_t in;
    uint8_t internal[32], okey[32];
    char label[64];
    t1_terms(&t);
    t.target = 16;
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
    uint8_t in[GZ_XE_MAX_SWEEP_IN][36];
    uint32_t n_out, locktime, height;   /* height 0: in the mempool */
    int live;
} ctx_t;

static ctx_t T[512];
static size_t NT;
static uint32_t TIP, HASHSEQ, FORCED;

static void op36(const gz_outpoint_t *o, uint8_t b[36])
{
    memcpy(b, o->txid, 32);
    b[32] = (uint8_t)o->vout; b[33] = (uint8_t)(o->vout >> 8); b[34] = (uint8_t)(o->vout >> 16); b[35] = (uint8_t)(o->vout >> 24);
}

static int tx_find(const uint8_t txid[32])
{
    for (size_t i = 0; i < NT; i++)
        if (T[i].live && memcmp(T[i].txid, txid, 32) == 0) return (int)i;
    return -1;
}

/* Output `b` exists: the funding, or an output of a live transaction (a
 * confirmed one at a height below `below` when below is not 0). */
static int out_exists(const uint8_t b[36], uint32_t below)
{
    uint32_t vout = (uint32_t)b[32] | (uint32_t)b[33] << 8 | (uint32_t)b[34] << 16 | (uint32_t)b[35] << 24;
    if (memcmp(b, FUND.txid, 32) == 0) return vout == FUND.vout;
    int i = tx_find(b);
    if (i < 0 || vout >= T[i].n_out) return 0;
    if (below) return T[i].height != 0 && T[i].height < below;
    return 1;
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

static int chain_accept(const uint8_t *raw, size_t len)
{
    uint8_t bare[GZ_XE_MAX_SWEEP], txid[32];
    size_t bl;
    int wit;
    gz_tx_info_t info;
    if (!gz_xe_strip_witness(raw, len, bare, sizeof bare, &bl, &wit)) return 0;
    if (!gz_tx_parse(bare, bl, &info) || info.n_in > GZ_XE_MAX_SWEEP_IN) return 0;
    gz_tx_txid(bare, bl, txid);
    if (tx_find(txid) >= 0) return 1;
    if (info.locktime > TIP && info.locktime < 500000000u) return 0;   /* not final at TIP + 1 */
    ctx_t *t = &T[NT];
    memset(t, 0, sizeof *t);
    for (size_t k = 0; k < info.n_in; k++) {
        const uint8_t *op;
        size_t sl;
        uint32_t seq;
        if (!gz_tx_input(bare, bl, &info, k, &op, &sl, &seq)) return 0;
        if (!out_exists(op, 0) || spender(op) >= 0) return 0;
        memcpy(t->in[k], op, 36);
    }
    if (NT + 1 >= sizeof T / sizeof T[0]) abort();
    memcpy(t->txid, txid, 32);
    t->n_in = info.n_in;
    t->n_out = (uint32_t)info.n_out;
    t->locktime = info.locktime;
    t->live = 1;
    NT++;
    return 1;
}

/* A transaction of someone else's spending `o`, evicting a mempool rival. */
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
    memcpy(t->in[0], b, 36);
    t->n_out = 1;
    t->live = 1;
}

static void chain_mine(void)
{
    TIP++;
    HASHSEQ++;
    for (size_t i = 0; i < NT; i++) {
        ctx_t *t = &T[i];
        int ok = t->live && t->height == 0 && (t->locktime == 0 || t->locktime < TIP);
        for (size_t k = 0; ok && k < t->n_in; k++) ok = out_exists(t->in[k], TIP);
        if (ok) t->height = TIP;
    }
}

/* A reorganisation at the same height that leaves `txid` and what spends it out. */
static void chain_unconfirm(const uint8_t txid[32])
{
    int i = tx_find(txid);
    if (i < 0) abort();
    for (size_t k = 0; k < NT; k++)
        if (T[k].live && T[k].height >= T[i].height) T[k].height = 0;
    HASHSEQ++;
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

static uint8_t BC[4096][32];
static uint32_t BC_TIP[4096];
static size_t NBC;
static int DROP_BCAST;
static char LOGS[256][96];
static size_t NLOG;
static uint64_t DIGEST;

typedef struct {
    gz_outpoint_t op;
    uint32_t depth;
    int used, fresh, known;
    uint8_t last[32];
    uint32_t last_conf;
} watch_t;
static watch_t W[4096];
static size_t NW;

static void mix(const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) { DIGEST ^= b[i]; DIGEST *= 1099511628211ull; }
}

static watch_t *watch_find(const gz_outpoint_t *o)
{
    for (size_t i = 0; i < NW; i++)
        if (W[i].used && W[i].op.vout == o->vout && memcmp(W[i].op.txid, o->txid, 32) == 0) return &W[i];
    return NULL;
}

static size_t n_watches(void)
{
    size_t n = 0;
    for (size_t i = 0; i < NW; i++) n += W[i].used != 0;
    return n;
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
    case GZ_ACTION_BROADCAST: {
        uint8_t bare[GZ_XE_MAX_SWEEP];
        size_t bl;
        int wit;
        mix(a->u.broadcast.tx.data, a->u.broadcast.tx.len);
        if (DROP_BCAST) break;
        if (!gz_xe_strip_witness(a->u.broadcast.tx.data, a->u.broadcast.tx.len, bare, sizeof bare, &bl, &wit)) abort();
        gz_tx_txid(bare, bl, BC[NBC]);
        BC_TIP[NBC++] = TIP;
        chain_accept(a->u.broadcast.tx.data, a->u.broadcast.tx.len);
        break;
    }
    case GZ_ACTION_WATCH_OUTPOINT: {
        watch_t *w = watch_find(&a->u.watch_outpoint.outpoint);
        mix(&a->u.watch_outpoint.outpoint, sizeof(gz_outpoint_t));
        if (!w) { w = &W[NW++]; memset(w, 0, sizeof *w); w->op = a->u.watch_outpoint.outpoint; w->used = 1; }
        w->depth = a->u.watch_outpoint.depth;
        w->fresh = 1;
        w->known = 0;
        break;
    }
    case GZ_ACTION_UNWATCH: {
        watch_t *w = a->u.unwatch.is_tx ? NULL : watch_find(&a->u.unwatch.what);
        if (w) w->used = 0;
        break;
    }
    case GZ_ACTION_NOTIFY: {
        gz_bytes_t v;
        mix(a->u.notify.bytes.data, a->u.notify.bytes.len);
        if (a->u.notify.code == GZ_NOTIFY_LOG && gz_rec_find(a->u.notify.bytes, 0, &v) == 1 && NLOG < 256) {
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

static void submit(void)
{
    CHECK(gz_runner_submit(&RUN, &L) == GZ_OK);
    for (size_t i = 0; i < NPEND; i++) CHECK(gz_runner_confirm(&RUN, PEND[i]) == GZ_OK);
    NPEND = 0;
}

static void feed(const gz_event_t *ev)
{
    gz_action_list_reset(&L);
    CHECK(gz_xe_handle(&X, ev, &L) == GZ_OK);
    submit();
}

static void chain_ev(gz_chain_kind_t k, uint32_t height, const gz_outpoint_t *o, const uint8_t *txid, uint32_t conf)
{
    gz_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = GZ_EVENT_CHAIN;
    ev.u.chain.kind = k;
    ev.u.chain.height = height;
    if (o) ev.u.chain.outpoint = *o;
    if (txid) memcpy(ev.u.chain.txid, txid, 32);
    ev.u.chain.confirmations = conf;
    ev.u.chain.block_hash[0] = (uint8_t)HASHSEQ; ev.u.chain.block_hash[1] = (uint8_t)(HASHSEQ >> 8);
    ev.u.chain.block_hash[31] = 1;
    feed(&ev);
}

/* What the chain view says about one watch now (action.h's rules). */
static void report(watch_t *w, int first)
{
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

/* Answer every watch set since the last answer: its state, then SYNCED. */
static void settle(void)
{
    for (int again = 1; again;) {
        again = 0;
        for (size_t i = 0; i < NW; i++) {
            if (!W[i].used || !W[i].fresh) continue;
            W[i].fresh = 0;
            report(&W[i], 1);
            gz_outpoint_t o = W[i].op;
            gz_event_t ev;
            memset(&ev, 0, sizeof ev);
            ev.kind = GZ_EVENT_CHAIN;
            ev.u.chain.kind = GZ_CHAIN_WATCH_SYNCED;
            ev.u.chain.outpoint = o;
            ev.u.chain.is_tx = 0;
            feed(&ev);
            again = 1;
        }
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
static int PORT_FAIL, PORT_WRONG;

static void le32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

static int fake_sweep(void *ctx, const uint8_t scope[32], const gz_xe_sweep_in_t *in, size_t n, uint32_t locktime,
                      uint8_t *tx, size_t cap, size_t *tx_len)
{
    size_t at = 0;
    uint64_t sum = 0;
    (void)ctx;
    if (memcmp(scope, SCOPE, 32) != 0 || n == 0 || n > GZ_XE_MAX_SWEEP_IN || NCALL >= 256) return 0;
    CALLS[NCALL].tip = TIP;
    CALLS[NCALL].locktime = locktime;
    CALLS[NCALL].n = n;
    memcpy(CALLS[NCALL].in, in, n * sizeof *in);
    NCALL++;
    if (PORT_FAIL) return 0;
    if (cap < 64 + n * 110) return 0;
    le32(tx + at, 2); at += 4;
    tx[at++] = 0; tx[at++] = 1;
    tx[at++] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) {
        op36(&in[i].outpoint, tx + at); at += 36;
        tx[at++] = 0;
        le32(tx + at, in[i].csv ? in[i].csv : 0xfffffffeu); at += 4;
        sum += in[i].amount;
    }
    if (PORT_WRONG) tx[5 + 1 + 1] ^= 1;   /* the first input's txid altered */
    tx[at++] = 1;
    for (int i = 0; i < 8; i++) tx[at++] = (uint8_t)((sum - 500) >> (8 * i));
    tx[at++] = 34; tx[at++] = 0x51; tx[at++] = 0x20;
    memset(tx + at, 0xab, 32); at += 32;
    for (size_t i = 0; i < n; i++) { tx[at++] = 1; tx[at++] = 64; memset(tx + at, 0x77, 64); at += 64; }
    le32(tx + at, locktime); at += 4;
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
}

static void reset_engine(void)
{
    gz_xe_port_t port = { fake_sweep, NULL };
    NJ = 0; JUSED = 0; NPEND = 0; NBC = 0; NLOG = 0; NW = 0; NCALL = 0; DIGEST = 14695981039346656037ull;
    DROP_BCAST = 0; PORT_FAIL = 0; PORT_WRONG = 0;
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
    settle();
}

/* A crash and a start from the journal (the runner, the watches and the
 * engine's memory are gone; the journal and the chain stay). Returns the
 * kinds of the first two actions of the start step. */
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
    submit();
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

static int journal_class(const gz_outpoint_t *o, uint8_t cls)
{
    uint8_t b[36];
    op36(o, b);
    for (size_t k = 0; k < NJ; k++) {
        gz_bytes_t s = { JPOOL + J[k].off, J[k].len }, v, c;
        if (J[k].type != GZ_XE_REC_SEEN) continue;
        if (gz_rec_find(s, 2, &v) != 1 || v.len != 36) continue;
        /* the outpoint as saved: txid, then the index as a big-endian u32 */
        if (memcmp(v.data, b, 32) != 0 || gz_get_u32(v.data + 32) != o->vout) continue;
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

/* Put the first k steps of PLAN on chain, as a sibling would, one a block. */
static void confirm_prefix(size_t k)
{
    for (size_t i = 0; i < k; i++) {
        CHECK(chain_accept(PLAN.step[i].tx, PLAN.step[i].len));
        chain_mine();
    }
}

/* ---- 1. plans: refusals ---------------------------------------------------- */

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

    /* A tree whose transactions do not chain, or are not what the tree says. */
    memcpy(&SAVED, &TREE, sizeof TREE);
    memcpy(own, MEM[1], 33);
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

    /* begin: another factory's plan; twice. */
    reset_chain();
    reset_engine();
    tip_events();
    memcpy(PLAN.scope, OTHER_SCOPE, 32);
    gz_action_list_reset(&L);
    CHECK(gz_xe_begin(&X, &PLAN, GZ_XE_WHY_USER, &L, &refused) == GZ_OK && refused == 2 && L.count == 0);
    memcpy(PLAN.scope, SCOPE, 32);
    begin(GZ_XE_WHY_USER);
    gz_action_list_reset(&L);
    CHECK(gz_xe_begin(&X, &PLAN, GZ_XE_WHY_USER, &L, &refused) == GZ_OK && refused == 1 && L.count == 0);

    /* A record that is not one: a corrupt journal. */
    {
        gz_xe_port_t port = { fake_sweep, NULL };
        static const uint8_t junk[] = { 0x00, 0x20, 0x01 };
        gz_record_t r = { GZ_XE_REC_PLAN, { junk, sizeof junk } };
        gz_batch_id_t at = { 1, 1 };
        uint8_t step[64];
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
    CHECK(count_bcast_after(step_txid(0), mark) == 0 && count_bcast_after(step_txid(1), mark) == 0);
    CHECK(count_bcast_after(step_txid(2), mark) >= 1);
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
    CHECK(chain_accept(PLAN.step[2].tx, PLAN.step[2].len));
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
        sum += s->amount;
    }
    CHECK(sum == outs);
    run_until_end(20);
    CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
    CHECK(NCALL == 1);
    CHECK(n_watches() == 0);
}

/* ---- 6. the host after a member's path: untouched subtrees (S4, R5) -------- */

static void test_host_s4(uint32_t n, uint8_t d, int owe)
{
    uint8_t own[33], how = 0, owed[GZ_TREE_MAX_MEMBERS / 8];
    static gz_xe_plan_t MPLAN;
    gz_xe_tree_in_t in;
    int m;
    build(n);
    m = member_at(d);
    CHECK(m >= 0);
    if (m < 0) return;
    in = tin();
    memcpy(own, MEM[m], 33);
    CHECK(gz_xe_plan_member(&in, (uint32_t)m, own, &MPLAN) == GZ_XE_PLAN_OK);
    int other = m == 0 ? 1 : 0;
    memset(owed, 0, sizeof owed);
    if (owe) owed[other / 8] |= (uint8_t)(1u << (other % 8));
    host_plan(n, owe ? owed : NULL);
    {   /* the member's path on chain first */
        for (size_t i = 0; i < MPLAN.n_steps; i++) {
            CHECK(chain_accept(MPLAN.step[i].tx, MPLAN.step[i].len));
            chain_mine();
        }
        tip_events();
    }
    begin(GZ_XE_WHY_HOST_RECOVER);
    while (!ended(NULL) && TIP < END + 200) block();
    CHECK(first_bcast(PLAN.node[0].txid) < 0);                      /* the root was already there */

    /* Every output offered once, at the first tip it may be spent, never one with an owed member below. */
    uint64_t swept = 0;
    size_t offered = 0;
    uint16_t leaf = MPLAN.step[MPLAN.n_steps - 1].node;   /* the member's plan index */
    const uint8_t *leaf_txid = MPLAN.node[leaf].txid;
    int lt = tx_find(leaf_txid);
    CHECK(lt >= 0);
    for (size_t c = 0; c < NCALL; c++) {
        uint32_t lock = 0;
        for (size_t i = 0; i < CALLS[c].n; i++) {
            const gz_xe_sweep_in_t *s = &CALLS[c].in[i];
            const gz_xe_node_t *nd = &PLAN.node[s->node];
            offered++;
            swept += s->amount;
            if (s->lock > lock) lock = s->lock;
            if (s->what == GZ_XE_OUT_INPUT) {
                CHECK(s->lock == nd->cltv && CALLS[c].tip == nd->cltv);
                CHECK(!(owe && (uint32_t)other >= nd->first && (uint32_t)other < (uint32_t)nd->first + nd->count));
            } else if (s->what == GZ_XE_OUT_CHANNEL) {
                CHECK(memcmp(s->outpoint.txid, leaf_txid, 32) == 0 && s->outpoint.vout == 0);
                CHECK(s->lock == nd->cltv && CALLS[c].tip == nd->cltv);             /* H_leaf, not H_leaf - 1 */
                CHECK(nd->cltv == (uint32_t)gz_exit_h_leaf(END, d));
            } else {
                CHECK(s->what == GZ_XE_OUT_SPARE && s->outpoint.vout == 1 && s->csv == 144);
                CHECK(lt >= 0 && CALLS[c].tip == T[lt].height + 143);                /* 144 confirmations, not 143 */
            }
            for (size_t c2 = 0; c2 < NCALL; c2++)
                for (size_t i2 = 0; i2 < CALLS[c2].n; i2++)
                    if ((c2 != c || i2 != i) && CALLS[c2].in[i2].outpoint.vout == s->outpoint.vout
                        && memcmp(CALLS[c2].in[i2].outpoint.txid, s->outpoint.txid, 32) == 0)
                        CHECK(0);                                    /* offered twice */
        }
        CHECK(CALLS[c].locktime == lock);
    }
    if (owe) {
        CHECK(!ended(NULL));                                        /* the owed member's subtree stays */
        return;
    }
    CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
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
    CHECK(offered >= 2);
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

    /* S2: step 1's input taken above its timeout height: the host's leaf. */
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
        tip_events();
        begin(GZ_XE_WHY_USER);
        CHECK(ended(&how) && how == GZ_XE_END_HOST_TIMEOUT);
        CHECK(journal_class(&o, GZ_XE_S2));
        CHECK(NBC == 0);
    }

    /* S8: the same spend below its timeout height. */
    fresh_member(4, 2, &m);
    confirm_prefix(1);
    {
        gz_outpoint_t o;
        memcpy(o.txid, step_txid(0), 32);
        o.vout = PLAN.node[PLAN.step[1].node].parent_vout;
        chain_force(&o);
        chain_mine();
        tip_events();
        begin(GZ_XE_WHY_USER);
        CHECK(ended(&how) && how == GZ_XE_END_UNEXPLAINED);
        CHECK(journal_class(&o, GZ_XE_S8));
        CHECK(has_log("unexplained_spend"));
        CHECK(NBC == 0);
    }
}

/* ---- 8. a reorganisation removes a confirmed step (R3) --------------------- */

static void test_reorg(void)
{
    int m;
    uint8_t how = 0;
    fresh_member(4, 2, &m);
    begin(GZ_XE_WHY_USER);
    block();
    block();
    CHECK(journal_step(1) == GZ_XE_ST_CONFIRMED);
    size_t mark = NBC;
    chain_unconfirm(step_txid(1));
    tip_events();                                                   /* the same height, another block */
    CHECK(journal_step(1) == GZ_XE_ST_SENT);                        /* missing again */
    CHECK(count_bcast_after(step_txid(1), mark) >= 1);              /* and sent again */
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
    /* A new tip closes it again: a new watch's answer is waited for. */
    chain_mine();
    chain_ev(GZ_CHAIN_NEW_TIP, TIP, NULL, NULL, 0);
    size_t before = NBC;
    for (size_t i = 0; i < NW; i++) if (W[i].used) report(&W[i], 0);
    CHECK(NBC == before);
    chain_ev(GZ_CHAIN_TIP_SYNCED, TIP, NULL, NULL, 0);
    settle();
    CHECK(first_bcast(step_txid(1)) >= 0);
}

/* ---- 10. the host's port: failures are outcomes --------------------------- */

static void test_port(void)
{
    uint8_t how = 0;
    host_plan(4, NULL);
    begin(GZ_XE_WHY_HOST_RECOVER);
    PORT_FAIL = 1;
    while (TIP < END - 4) block();
    CHECK(NCALL == 2);                                              /* E - 5, E - 4: refused, retried */
    PORT_FAIL = 0;
    PORT_WRONG = 1;                                                 /* spends the wrong outpoint */
    block();
    CHECK(NCALL == 3 && X.port_refused >= 2);
    for (size_t i = 0; i < NBC; i++) CHECK(memcmp(BC[i], PLAN.node[0].txid, 32) == 0
                                           || memcmp(BC[i], PLAN.step[0].child_txid, 32) == 0);
    PORT_WRONG = 0;
    run_until_end(20);
    CHECK(ended(&how) && how == GZ_XE_END_HOST_RECOVERED);
}

/* ---- 11. the same events, the same actions -------------------------------- */

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
    test_host_s4(16, 3, 1);
    test_classes();
    test_reorg();
    test_unsynced();
    test_port();
    {
        uint64_t a = one_run(), b = one_run();
        CHECK(a == b);
    }
    return check_done();
}
