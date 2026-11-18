/* The funding engine. See gazpacho/funding.h and docs/notes/composite-node.md
 * sections 9, 12.1, 14 and the P4.5 notes in docs/notes/funding.md. */
#include "gazpacho/funding.h"
#include <string.h>

int gz_fund_tx_all_witness(const uint8_t *tx, size_t len);   /* txsize.c */

#define CLEAR(p) memset((p), 0, sizeof *(p))

static size_t cstrlen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

/* Record fields (journal.md 9, Funding area; every type even). */
enum {
    P_SCOPE = 2, P_CHECK = 4, P_ATTEMPT = 6, P_MODE = 8, P_FEERATE = 10, P_TX = 12, P_PREV = 14, P_VOUT = 16,
    P_TIP = 18, P_RELEASED = 20
};
enum { S1_SCOPE = 2, S1_TXID = 4, S1_TX = 6 };
enum {
    T_SCOPE = 2, T_TXID = 4, T_STATE = 6, T_HEIGHT = 8, T_DEADLINE = 10,
    T_FTX = 12, T_VOUT = 14, T_AMOUNT = 16, T_SCRIPT = 18, T_ACK_TIP = 20, T_END = 22, T_DEPTH = 24,
    T_WHOLE = 26, T_EXIT = 28, T_DBLOCKS = 30, T_SB = 32, T_SB_FEE = 34, T_SB_ESC = 36, T_SB_INDEX = 38
};

void gz_fund_config_default(gz_fund_config_t *cfg, int host)
{
    if (!cfg) return;
    CLEAR(cfg);
    cfg->host = host ? 1 : 0;
    cfg->mode = GZ_HOST_FUNDING_AUTO;
    cfg->feerate = 100;
    cfg->incremental = 100;
    cfg->incremental_high = 1000;
    cfg->burial = 3;
    cfg->funding_deadline_blocks = 36;
    cfg->tick_ms = 0;
}

gz_status_t gz_fund_init(gz_fund_t *f, const gz_fund_config_t *cfg, const gz_ports_t *ports)
{
    if (!f || !cfg || !ports || !cfg->hooks.report) return GZ_ERR_ARGUMENT;
    if (cfg->host && (!cfg->wallet.plan || !cfg->wallet.sign_plan || !cfg->wallet.adopt || !cfg->wallet.release ||
                      !cfg->wallet.spend_back))
        return GZ_ERR_ARGUMENT;
    if (cfg->burial == 0 || cfg->burial > 1000 || cfg->funding_deadline_blocks > 100000 || cfg->feerate == 0 ||
        cfg->feerate > 100000000u || cfg->incremental > cfg->incremental_high || cfg->incremental_high > 100000000u ||
        (cfg->mode != GZ_HOST_FUNDING_AUTO && cfg->mode != GZ_HOST_FUNDING_CONFIRM))
        return GZ_ERR_ARGUMENT;
    memset(f, 0, sizeof *f);
    f->cfg = *cfg;
    f->ports = *ports;
    return GZ_OK;
}

/* ---- small helpers ------------------------------------------------------ */

static int is_terminal(int st)
{
    return st == GZ_FUND_ST_LIVE || st == GZ_FUND_ST_DEAD || st == GZ_FUND_ST_FAILED || st == GZ_FUND_ST_LIVE_LATE;
}

static gz_fund_factory_t *find_txid(gz_fund_t *f, const uint8_t scope[32], const uint8_t txid[32])
{
    for (size_t i = 0; i < GZ_FUND_MAX_FACTORIES; i++)
        if (f->fac[i].used && memcmp(f->fac[i].scope, scope, 32) == 0 && memcmp(f->fac[i].funding.txid, txid, 32) == 0)
            return &f->fac[i];
    return NULL;
}

/* The newest factory of a scope. */
static gz_fund_factory_t *find_scope(gz_fund_t *f, const uint8_t scope[32])
{
    gz_fund_factory_t *best = NULL;
    for (size_t i = 0; i < GZ_FUND_MAX_FACTORIES; i++)
        if (f->fac[i].used && memcmp(f->fac[i].scope, scope, 32) == 0 && (!best || f->fac[i].seq > best->seq))
            best = &f->fac[i];
    return best;
}

static gz_fund_factory_t *alloc(gz_fund_t *f)
{
    for (size_t i = 0; i < GZ_FUND_MAX_FACTORIES; i++)
        if (!f->fac[i].used) {
            gz_fund_factory_t *x = &f->fac[i];
            memset(x, 0, sizeof *x);
            x->used = 1;
            x->seq = ++f->seq;
            return x;
        }
    return NULL;
}

static void remember_end(gz_fund_t *f, const uint8_t scope[32], int state, uint32_t height)
{
    gz_fund_ended_t *e = &f->ended[f->ended_next];
    memcpy(e->scope, scope, 32);
    e->state = (uint8_t)state;
    e->height = height;
    f->ended_next = (f->ended_next + 1) % GZ_FUND_MAX_ENDED;
    if (f->n_ended < GZ_FUND_MAX_ENDED) f->n_ended++;
}

static size_t n_watch(const gz_fund_t *f, const gz_fund_factory_t *x)
{
    size_t n = x->n_in < GZ_FUND_WATCH_INPUTS ? x->n_in : GZ_FUND_WATCH_INPUTS;
    return f->cfg.host ? 2 : 1 + n;
}

static void outpoint_of(const uint8_t op36[36], gz_outpoint_t *o)
{
    memcpy(o->txid, op36, 32);
    o->vout = (uint32_t)op36[32] | (uint32_t)op36[33] << 8 | (uint32_t)op36[34] << 16 | (uint32_t)op36[35] << 24;
}

/* Is this watch also held by another factory that watches now? */
static int held_elsewhere(const gz_fund_t *f, const gz_fund_factory_t *x, int is_tx, const uint8_t key[36])
{
    for (size_t i = 0; i < GZ_FUND_MAX_FACTORIES; i++) {
        const gz_fund_factory_t *y = &f->fac[i];
        if (!y->used || y == x || !y->watching) continue;
        if (is_tx && memcmp(y->funding.txid, key, 32) == 0) return 1;
        if (!is_tx)
            for (size_t k = 0; k < n_watch(f, y) - 1; k++)
                if (memcmp(y->ins[k], key, 36) == 0) return 1;
    }
    return 0;
}

static uint32_t depth_of(const gz_fund_t *f, const gz_fund_factory_t *x)
{
    /* The host's burial depth; a member's own B (its conditions, C11). */
    return f->cfg.host || x->exit.B == 0 ? f->cfg.burial : x->exit.B;
}

static gz_status_t add(gz_action_list_t *out, const gz_action_t *a)
{
    return gz_action_list_add(out, a);
}

static gz_status_t set_watches(gz_fund_t *f, gz_fund_factory_t *x, gz_action_list_t *out)
{
    gz_action_t a;
    gz_status_t st;
    size_t n = n_watch(f, x);
    if (x->watching) return GZ_OK;
    /* Count only what no other factory already holds (the registry keeps one
     * per key). By the limits this always fits: 16 factories, 3 each. */
    size_t extra = 0;
    uint8_t key[36];
    memset(key, 0, 36);
    memcpy(key, x->funding.txid, 32);
    if (!held_elsewhere(f, x, 1, key)) extra++;
    for (size_t k = 0; k < n - 1; k++)
        if (!held_elsewhere(f, x, 0, x->ins[k])) extra++;
    if (f->n_watches + extra > GZ_FUND_MAX_WATCHES) return GZ_ERR_BUG;
    CLEAR(&a);
    a.kind = GZ_ACTION_WATCH_TX;
    memcpy(a.u.watch_tx.txid, x->funding.txid, 32);
    a.u.watch_tx.depth = depth_of(f, x);
    if ((st = add(out, &a)) != GZ_OK) return st;
    for (size_t k = 0; k < n - 1; k++) {
        CLEAR(&a);
        a.kind = GZ_ACTION_WATCH_OUTPOINT;
        outpoint_of(x->ins[k], &a.u.watch_outpoint.outpoint);
        a.u.watch_outpoint.depth = depth_of(f, x);
        if ((st = add(out, &a)) != GZ_OK) return st;
    }
    f->n_watches += extra;
    x->watching = 1;
    return GZ_OK;
}

/* The engine no longer needs a watch: an UNWATCH into the list of the call
 * under way (the composite drops it if another engine still asks). */
static void unwatch_out(gz_fund_t *f, int is_tx, const gz_outpoint_t *o)
{
    gz_action_t a;
    gz_status_t st;
    CLEAR(&a);
    a.kind = GZ_ACTION_UNWATCH;
    a.u.unwatch.is_tx = is_tx;
    a.u.unwatch.what = *o;
    if (!f->cur_out) {
        f->cur_st = GZ_ERR_ARGUMENT;   /* only a call with a list watches */
        return;
    }
    if ((st = add(f->cur_out, &a)) != GZ_OK && f->cur_st == GZ_OK) f->cur_st = st;
}

static void drop_watches(gz_fund_t *f, gz_fund_factory_t *x)
{
    uint8_t key[36];
    gz_outpoint_t o;
    if (!x->watching) return;
    x->watching = 0;
    memset(key, 0, 36);
    memcpy(key, x->funding.txid, 32);
    if (!held_elsewhere(f, x, 1, key)) {
        memcpy(o.txid, x->funding.txid, 32);
        o.vout = 0;
        unwatch_out(f, 1, &o);
        f->n_watches--;
    }
    for (size_t k = 0; k < n_watch(f, x) - 1; k++)
        if (!held_elsewhere(f, x, 0, x->ins[k])) {
            outpoint_of(x->ins[k], &o);
            unwatch_out(f, 0, &o);
            f->n_watches--;
        }
}

/* A factory ends: remembered for the slot end conditions, then freed. */
static void finish(gz_fund_t *f, gz_fund_factory_t *x, int state)
{
    drop_watches(f, x);
    remember_end(f, x->scope, state, f->tip);
    memset(x, 0, sizeof *x);
}

static gz_status_t arm_tick(gz_fund_t *f, gz_action_list_t *out, uint64_t delay)
{
    gz_action_t a;
    CLEAR(&a);
    a.kind = GZ_ACTION_SET_TIMER;
    a.u.set_timer.timer_id = GZ_FUND_TIMER_TICK;
    a.u.set_timer.delay_ms = delay;
    f->tick_armed = 1;
    return add(out, &a);
}

static void hex8(const uint8_t *p, char *s)
{
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        s[2 * i] = h[p[i] >> 4];
        s[2 * i + 1] = h[p[i] & 15];
    }
}

/* A log notice: "<what> scope=<16 hex>". */
static gz_status_t log_note(gz_fund_t *f, gz_action_list_t *out, const char *what, const uint8_t scope[32])
{
    char text[96];
    size_t n = 0, at = 0;
    uint8_t *buf = f->scratch;
    gz_action_t a;
    gz_status_t st;
    while (what[n] && n < 60) n++;
    memcpy(text, what, n);
    memcpy(text + n, " scope=", 7);
    hex8(scope, text + n + 7);
    if ((st = gz_rec_put(buf, 128, &at, 0, (const uint8_t *)text, n + 7 + 16)) != GZ_OK) return st;
    CLEAR(&a);
    a.kind = GZ_ACTION_NOTIFY;
    a.u.notify.code = GZ_NOTIFY_LOG;
    a.u.notify.bytes.data = buf;
    a.u.notify.bytes.len = at;
    return add(out, &a);
}

/* The attention item "confirm funding" (12.1): version 1 shown, 2 gone. */
static gz_status_t attention(gz_fund_t *f, gz_action_list_t *out, const uint8_t scope[32], int gone)
{
    char id[40] = "confirm-funding-";
    uint8_t *buf = f->scratch, ver[8];
    size_t at = 0;
    gz_action_t a;
    gz_status_t st;
    hex8(scope, id + 16);
    if ((st = gz_rec_put(buf, 256, &at, GZ_VIEW_REC_ID, (const uint8_t *)id, 32)) != GZ_OK) return st;
    if (gone && (st = gz_rec_put(buf, 256, &at, GZ_VIEW_REC_GONE, NULL, 0)) != GZ_OK) return st;
    gz_put_u64(ver, gone ? 2 : 1);
    if ((st = gz_rec_put(buf, 256, &at, GZ_VIEW_REC_VERSION, ver, 8)) != GZ_OK) return st;
    if ((st = gz_rec_put(buf, 256, &at, 6, scope, 32)) != GZ_OK) return st;
    CLEAR(&a);
    a.kind = GZ_ACTION_NOTIFY;
    a.u.notify.code = GZ_NOTIFY_VIEW(GZ_VIEW_ATTENTION);
    a.u.notify.bytes.data = buf;
    a.u.notify.bytes.len = at;
    return add(out, &a);
}

static gz_status_t broadcast(gz_action_list_t *out, const uint8_t *tx, size_t len)
{
    gz_action_t a;
    CLEAR(&a);
    a.kind = GZ_ACTION_BROADCAST;
    a.u.broadcast.tx.data = tx;
    a.u.broadcast.tx.len = len;
    return add(out, &a);
}

/* ---- records ------------------------------------------------------------ */

/* 1 if the stream is valid and every even type is in `allowed`. */
static int fields_ok(gz_bytes_t s, const uint8_t *allowed, size_t n_allowed)
{
    size_t at = 0, k;
    uint64_t type, len;
    if (!gz_rec_valid(s)) return 0;
    while (at < s.len) {
        if (!(k = gz_bigsize_get(s.data + at, s.len - at, &type))) return 0;
        at += k;
        if (!(k = gz_bigsize_get(s.data + at, s.len - at, &len))) return 0;
        at += k;
        if (len > s.len - at) return 0;
        at += (size_t)len;
        if (!(type & 1)) {
            size_t i;
            for (i = 0; i < n_allowed; i++)
                if (allowed[i] == type) break;
            if (i == n_allowed) return 0;
        }
    }
    return 1;
}

/* A required field of exactly `len` bytes (len 0: any length up to max). */
static int field(gz_bytes_t s, uint64_t type, size_t len, size_t max, gz_bytes_t *v)
{
    if (gz_rec_find(s, type, v) != 1) return 0;
    if (len) return v->len == len;
    return v->len <= max;
}

static int opt_field(gz_bytes_t s, uint64_t type, size_t len, gz_bytes_t *v, int *present)
{
    int r = gz_rec_find(s, type, v);
    *present = r == 1;
    if (r < 0) return 0;
    return !*present || v->len == len;
}

typedef struct {
    uint8_t *buf;
    size_t cap, at;
    gz_status_t st;
} enc_t;

static void put(enc_t *e, uint64_t type, const void *data, size_t len)
{
    if (e->st == GZ_OK) e->st = gz_rec_put(e->buf, e->cap, &e->at, type, (const uint8_t *)data, len);
}
static void put_u8(enc_t *e, uint64_t type, uint8_t v) { put(e, type, &v, 1); }
static void put_u16(enc_t *e, uint64_t type, uint16_t v) { uint8_t b[2]; gz_put_u16(b, v); put(e, type, b, 2); }
static void put_u32(enc_t *e, uint64_t type, uint32_t v) { uint8_t b[4]; gz_put_u32(b, v); put(e, type, b, 4); }
static void put_u64(enc_t *e, uint64_t type, uint64_t v) { uint8_t b[8]; gz_put_u64(b, v); put(e, type, b, 8); }

static size_t enc_plan(gz_fund_t *f, const gz_fund_factory_t *x, uint8_t *buf, size_t cap, gz_status_t *st)
{
    enc_t e = { buf, cap, 0, GZ_OK };
    uint8_t *p = f->work;
    size_t at = 0;
    for (size_t i = 0; i < x->n_in; i++) {
        gz_put_u64(p + at, x->prev[i].amount);
        p[at + 8] = x->prev[i].script_len;
        memcpy(p + at + 9, x->prev[i].script, x->prev[i].script_len);
        at += 9u + x->prev[i].script_len;
    }
    put(&e, P_SCOPE, x->scope, 32);
    put(&e, P_CHECK, x->check, 32);
    put_u16(&e, P_ATTEMPT, x->attempt);
    put_u8(&e, P_MODE, (uint8_t)x->mode);
    put_u64(&e, P_FEERATE, x->feerate);
    put(&e, P_TX, x->tx, x->tx_len);
    put(&e, P_PREV, p, at);
    put_u32(&e, P_VOUT, x->funding.vout);
    if (x->plan_tip_known) put_u32(&e, P_TIP, x->plan_tip);
    if (x->released) put_u8(&e, P_RELEASED, 1);
    *st = e.st;
    return e.at;
}

static size_t enc_status(const gz_fund_factory_t *x, int state, uint32_t height, int first, uint8_t *buf, size_t cap,
                         gz_status_t *st)
{
    enc_t e = { buf, cap, 0, GZ_OK };
    put(&e, T_SCOPE, x->scope, 32);
    put(&e, T_TXID, x->funding.txid, 32);
    put_u8(&e, T_STATE, (uint8_t)state);
    put_u32(&e, T_HEIGHT, height);
    put_u32(&e, T_DEADLINE, x->deadline);
    if (first) {
        uint8_t ex[16];
        put(&e, T_FTX, x->tx, x->tx_len);
        put_u32(&e, T_VOUT, x->funding.vout);
        put_u64(&e, T_AMOUNT, x->amount);
        put(&e, T_SCRIPT, x->script, 34);
        put_u32(&e, T_ACK_TIP, x->ack_tip);
        put_u32(&e, T_END, x->end_height);
        put_u8(&e, T_DEPTH, x->own_depth);
        put_u8(&e, T_WHOLE, x->whole_tree);
        gz_put_u32(ex, x->exit.A);
        gz_put_u32(ex + 4, x->exit.B);
        gz_put_u32(ex + 8, x->exit.M);
        gz_put_u32(ex + 12, x->exit.M_host);
        put(&e, T_EXIT, ex, 16);
        put_u32(&e, T_DBLOCKS, x->deadline_blocks);
    }
    if (x->sb_len && state == GZ_FUND_ST_ABANDONED) {
        put(&e, T_SB, x->sb, x->sb_len);
        put_u64(&e, T_SB_FEE, x->sb_fee);
        put_u8(&e, T_SB_ESC, (uint8_t)x->sb_escalated);
        put_u32(&e, T_SB_INDEX, x->sb_index);
    }
    *st = e.st;
    return e.at;
}

/* SAVE of one or two records from scratch. */
static gz_status_t save(gz_action_list_t *out, const gz_record_t *recs, size_t n)
{
    gz_action_t a;
    CLEAR(&a);
    a.kind = GZ_ACTION_SAVE;
    a.u.save.records = recs;
    a.u.save.n_records = n;
    return add(out, &a);
}

static gz_status_t save_status(gz_fund_t *f, gz_fund_factory_t *x, int state, int first, gz_action_list_t *out)
{
    gz_record_t r;
    gz_status_t st;
    size_t n = enc_status(x, state, f->tip, first, f->scratch, sizeof f->scratch, &st);
    if (st != GZ_OK) return st;
    r.type = GZ_FUND_REC_STATUS;
    r.bytes.data = f->scratch;
    r.bytes.len = n;
    return save(out, &r, 1);
}

/* ---- the funding transaction ------------------------------------------- */

/* Checks a plan the wallet returned: within the limits, no witness, the
 * output at `vout` pays exactly amount to script, one spent output per input,
 * every one a witness program (H1's last check, early), `must` spent. Fills
 * the outpoints of the first inputs. */
static int plan_ok(gz_fund_factory_t *x, const gz_outpoint_t *must)
{
    gz_tx_info_t info;
    uint64_t amt;
    const uint8_t *scr;
    size_t slen;
    int found = 0, have_must = !must;
    if (x->tx_len > GZ_FUND_MAX_TX || !gz_tx_parse(x->tx, x->tx_len, &info)) return 0;
    if (info.n_in == 0 || info.n_in > GZ_FUND_MAX_INPUTS || info.n_in != x->n_in) return 0;
    for (size_t i = 0; i < info.n_out; i++) {
        if (!gz_tx_output(x->tx, x->tx_len, &info, i, &amt, &scr, &slen)) return 0;
        if (amt == x->amount && slen == 34 && memcmp(scr, x->script, 34) == 0) {
            if (found) return 0; /* the factory's output twice: which one would the tree spend? */
            found = 1;
            x->funding.vout = (uint32_t)i;
            if (i != 0) return 0;   /* output 0, as the signer's adopt checks (review B, M-3) */
        }
    }
    /* Exactly two outputs: the factory's and the wallet's change, which H16's
     * child spends; nothing unknown (review A of PR 56, M2). */
    if (!found || info.n_out != 2) return 0;
    for (size_t i = 0; i < info.n_in; i++) {
        const uint8_t *op;
        size_t sl;
        uint32_t seq;
        const gz_fund_prevout_t *p = &x->prev[i];
        if (!gz_tx_input(x->tx, x->tx_len, &info, i, &op, &sl, &seq) || sl != 0) return 0;
        if (p->script_len < 4 || p->script_len > GZ_FUND_MAX_SCRIPT || p->script[1] != p->script_len - 2u ||
            (p->script[0] != 0x00 && (p->script[0] < 0x51 || p->script[0] > 0x60)) ||
            (p->script[0] == 0x00 && p->script_len != 22 && p->script_len != 34))
            return 0;
        if (p->amount == 0 || p->amount > UINT64_C(2100000000000000)) return 0;
        if (i < GZ_FUND_WATCH_INPUTS) memcpy(x->ins[i], op, 36);
        if (i == 0) memcpy(x->in0, op, 36);
        if (must && i == 0) {   /* input 0: members watch it, the next plan takes it */
            gz_outpoint_t o;
            outpoint_of(op, &o);
            if (memcmp(o.txid, must->txid, 32) == 0 && o.vout == must->vout) have_must = 1;
        }
    }
    gz_tx_txid(x->tx, x->tx_len, x->funding.txid);
    return have_must;
}

/* The funding's fee: what its inputs bring less what it pays. */
static uint64_t funding_fee(const gz_fund_factory_t *x)
{
    gz_tx_info_t info;
    uint64_t in = 0, outs = 0, a;
    const uint8_t *s;
    size_t l;
    if (!gz_tx_parse(x->tx, x->tx_len, &info)) return 0;
    for (size_t i = 0; i < x->n_in; i++) in += x->prev[i].amount;
    for (size_t i = 0; i < info.n_out; i++)
        if (gz_tx_output(x->tx, x->tx_len, &info, i, &a, &s, &l)) outs += a;
    return in > outs ? in - outs : 0;
}

/* The signed bytes are the plan, with a witness on every input. */
static int signed_ok(gz_fund_t *f, const gz_fund_factory_t *x, const uint8_t *tx, size_t len)
{
    size_t n;
    if (len > GZ_FUND_MAX_SIGNED || !gz_fund_tx_all_witness(tx, len)) return 0;
    if (!gz_fund_tx_strip(tx, len, f->work, sizeof f->work, &n)) return 0;
    return n == x->tx_len && memcmp(f->work, x->tx, n) == 0;
}

/* ---- hand-offs ---------------------------------------------------------- */

static gz_status_t plan_failed(gz_fund_t *f, const uint8_t scope[32], const char *why, gz_action_list_t *out,
                               gz_fund_plan_out_t *res)
{
    f->refused++;
    res->ok = 0;
    return log_note(f, out, why, scope);
}

/* H11 (review A of PR 56, M1): the attempt of `old` released a partial
 * signature and no plan spending its input 0 was accepted. It is marked and
 * saved again, so neither a later attempt nor a restart reuses its outpoint
 * or forgets the input that must be spent. */
static gz_status_t keep_released(gz_fund_t *f, gz_fund_factory_t *old, gz_action_list_t *out)
{
    gz_record_t r;
    gz_status_t st;
    size_t n;
    if (old->released) return GZ_OK;
    old->released = 1;
    n = enc_plan(f, old, f->scratch, sizeof f->scratch, &st);
    if (st != GZ_OK) return st;
    r.type = GZ_FUND_REC_PLAN;
    r.bytes.data = f->scratch;
    r.bytes.len = n;
    return save(out, &r, 1);
}

static gz_status_t plan_refused(gz_fund_t *f, gz_fund_factory_t *old, int released, const uint8_t scope[32],
                                const char *why, gz_action_list_t *out, gz_fund_plan_out_t *res)
{
    gz_status_t st;
    if (old && released && (st = keep_released(f, old, out)) != GZ_OK) return st;
    return plan_failed(f, scope, why, out, res);
}

gz_status_t gz_fund_host_plan(gz_fund_t *f, const gz_fund_plan_in_t *in, gz_action_list_t *out,
                              gz_fund_plan_out_t *res)
{
    gz_fund_factory_t *old, *x;
    gz_outpoint_t must;
    int use_must = 0;
    gz_record_t r;
    gz_status_t st;
    size_t n;
    if (!f || !in || !out || !res || !f->cfg.host) return GZ_ERR_ARGUMENT;
    CLEAR(res);
    old = find_scope(f, in->scope);
    if (old && old->state != 0) return plan_failed(f, in->scope, "funding-plan-refused already-funded", out, res);
    if (old && !in->released && !old->released && old->amount == in->amount && memcmp(old->script, in->script, 34) == 0) {
        /* Nothing was released: the same funding outpoint may serve the next
         * attempt (safety-rule.md C7: no record yet). Its deadline's basis is
         * the tip at this attempt, saved again (review B, M-1); no pass of an
         * earlier attempt's H1 counts for this one (L-3). */
        old->h1_ok = 0;
        old->signed_len = 0;
        if (f->tip_known && (!old->plan_tip_known || old->plan_tip != f->tip)) {
            old->plan_tip = f->tip;
            old->plan_tip_known = 1;
            n = enc_plan(f, old, f->scratch, sizeof f->scratch, &st);
            if (st != GZ_OK) return st;
            r.type = GZ_FUND_REC_PLAN;
            r.bytes.data = f->scratch;
            r.bytes.len = n;
            if ((st = save(out, &r, 1)) != GZ_OK) return st;
        }
        res->ok = 1;
        res->tx = old->tx;
        res->tx_len = old->tx_len;
        res->funding = old->funding;
        return GZ_OK;
    }
    if (old && (in->released || old->released)) {
        /* H11: the new plan spends input 0 of the released one, which is
         * kept until a plan that does is accepted. */
        outpoint_of(old->in0, &must);
        use_must = 1;
    }
    x = alloc(f);
    if (!x) return plan_refused(f, old, in->released, in->scope, "funding-plan-failed table-full", out, res);
    memcpy(x->scope, in->scope, 32);
    memcpy(x->check, in->check, 32);
    x->attempt = in->attempt;
    x->mode = f->cfg.mode;
    x->feerate = f->cfg.feerate;
    x->amount = in->amount;
    memcpy(x->script, in->script, 34);
    if (in->script[0] != 0x51 || in->script[1] != 0x20 || in->amount == 0) {
        memset(x, 0, sizeof *x);
        return plan_refused(f, old, in->released, in->scope, "funding-plan-failed bad-output", out, res);
    }
    /* The previous plan's coins (H11's among them) are offered again; if no
     * new plan is accepted, the wallet adopts the previous one again. */
    if (old) f->cfg.wallet.release(f->cfg.wallet.ctx, old->tx, old->tx_len);
    n = 0;
    if (!f->cfg.wallet.plan(f->cfg.wallet.ctx, x->amount, x->script, x->feerate, use_must ? &must : NULL, x->tx,
                            sizeof x->tx, &x->tx_len, x->prev, GZ_FUND_MAX_INPUTS, &n) ||
        x->tx_len > sizeof x->tx || n > GZ_FUND_MAX_INPUTS) {
        memset(x, 0, sizeof *x);
        if (old) (void)f->cfg.wallet.adopt(f->cfg.wallet.ctx, old->tx, old->tx_len, old->script, old->amount);
        return plan_refused(f, old, in->released, in->scope, "funding-plan-failed wallet", out, res);
    }
    x->n_in = n;
    if (!plan_ok(x, use_must ? &must : NULL)) {
        f->cfg.wallet.release(f->cfg.wallet.ctx, x->tx, x->tx_len);
        memset(x, 0, sizeof *x);
        if (old) (void)f->cfg.wallet.adopt(f->cfg.wallet.ctx, old->tx, old->tx_len, old->script, old->amount);
        return plan_refused(f, old, in->released, in->scope, "funding-plan-failed refused-plan", out, res);
    }
    x->plan_tip = f->tip;
    x->plan_tip_known = f->tip_known;
    if (old) memset(old, 0, sizeof *old);
    n = enc_plan(f, x, f->scratch, sizeof f->scratch, &st);
    if (st != GZ_OK) return st;
    r.type = GZ_FUND_REC_PLAN;
    r.bytes.data = f->scratch;
    r.bytes.len = n;
    if ((st = save(out, &r, 1)) != GZ_OK) return st;
    res->ok = 1;
    res->tx = x->tx;
    res->tx_len = x->tx_len;
    res->funding = x->funding;
    return GZ_OK;
}

int gz_fund_host_h1(gz_fund_t *f, const gz_fund_h1_in_t *in)
{
    gz_fund_factory_t *x;
    gz_tree_h1_in_t h;
    const uint8_t *scripts[GZ_FUND_MAX_INPUTS];
    size_t lens[GZ_FUND_MAX_INPUTS], at, n;
    int r;
    if (!f || !in || !f->cfg.host) return GZ_H1_ARGUMENT;
    x = find_scope(f, in->scope);
    if (!x || x->state != 0) return GZ_FUND_H1_NO_PLAN;
    x->h1_ok = 0;
    x->signed_len = 0;
    for (size_t i = 0; i < x->n_in; i++) {
        scripts[i] = x->prev[i].script;
        lens[i] = x->prev[i].script_len;
    }
    CLEAR(&h);
    h.n_members = in->n_members;
    h.acked = in->acked;
    h.n_nodes = in->n_nodes;
    h.signed_ok = in->signed_ok;
    h.proposed_tx = in->proposed_tx;
    h.proposed_len = in->proposed_len;
    h.to_sign_tx = x->tx;       /* the plan: equal to the proposal, or H1 fails (A11) */
    h.to_sign_len = x->tx_len;
    h.prev_scripts = scripts;
    h.prev_script_lens = lens;
    h.n_prev = x->n_in;
    r = (int)gz_tree_h1(&h, &at);
    if (r != GZ_H1_OK) return r;
    {
        /* Too late for a burial by the deadline this outcome would set: the
         * lobby is told now, before it saves Funding (review B, N-1). */
        int known = x->plan_tip_known || f->tip_known;
        uint32_t dl = (x->plan_tip_known ? x->plan_tip : f->tip) + f->cfg.funding_deadline_blocks;
        if (known && f->tip_known && f->tip + f->cfg.burial - 1 > dl) return GZ_FUND_H1_TOO_LATE;
    }
    if (x->mode == GZ_HOST_FUNDING_AUTO) {
        n = 0;
        if (!f->cfg.wallet.sign_plan(f->cfg.wallet.ctx, x->funding.txid, x->signed_tx, sizeof x->signed_tx, &n) ||
            n > sizeof x->signed_tx)
            return GZ_FUND_H1_SIGN;
        if (!signed_ok(f, x, x->signed_tx, n)) return GZ_FUND_H1_SIGNED;
        x->signed_len = n;
    }
    x->h1_ok = 1;
    return GZ_H1_OK;
}

static void set_deadline(gz_fund_t *f, gz_fund_factory_t *x)
{
    /* A member's deadline is its ack tip + 36, and its ack comes after the
     * plan: from the host's tip at the plan, with no burial added, the
     * host's deadline is not later than a member's whose chain view is not
     * behind the host's (review A of PR 56, M3; funding.md 5, decision 3,
     * pending the owner). Without a tip at the plan, the first one known. */
    if (x->plan_tip_known || f->tip_known) {
        x->deadline = (x->plan_tip_known ? x->plan_tip : f->tip) + f->cfg.funding_deadline_blocks;
        x->deadline_pending = 0;
    } else {
        x->deadline = 0;
        x->deadline_pending = 1;
    }
}

/* Signed: funding_signed and its status in one save, then the broadcast and
 * the watches. */
static gz_status_t commit_signed(gz_fund_t *f, gz_fund_factory_t *x, gz_action_list_t *out)
{
    gz_record_t r[2];
    gz_status_t st;
    enc_t e = { f->scratch, sizeof f->scratch, 0, GZ_OK };
    size_t n2;
    put(&e, S1_SCOPE, x->scope, 32);
    put(&e, S1_TXID, x->funding.txid, 32);
    put(&e, S1_TX, x->signed_tx, x->signed_len);
    if (e.st != GZ_OK) return e.st;
    r[0].type = GZ_FUND_REC_SIGNED;
    r[0].bytes.data = f->scratch;
    r[0].bytes.len = e.at;
    n2 = enc_status(x, GZ_FUND_ST_BROADCAST, f->tip, 0, f->scratch + e.at, sizeof f->scratch - e.at, &st);
    if (st != GZ_OK) return st;
    r[1].type = GZ_FUND_REC_STATUS;
    r[1].bytes.data = f->scratch + e.at;
    r[1].bytes.len = n2;
    if ((st = save(out, r, 2)) != GZ_OK) return st;
    x->state = GZ_FUND_ST_BROADCAST;
    if ((st = broadcast(out, x->signed_tx, x->signed_len)) != GZ_OK) return st;
    return set_watches(f, x, out);
}

static gz_status_t gz_fund_host_apply_in(gz_fund_t *f, const uint8_t scope[32], gz_action_list_t *out)
{
    gz_fund_factory_t *x;
    gz_status_t st;
    if (!f || !scope || !out || !f->cfg.host) return GZ_ERR_ARGUMENT;
    x = find_scope(f, scope);
    if (!x || x->state != 0) return GZ_ERR_ARGUMENT;   /* apply without a plan: the composite's bug */
    if (!x->h1_ok) {
        /* H1 failed: nothing is broadcast; the coins go back (14.2). */
        f->cfg.wallet.release(f->cfg.wallet.ctx, x->tx, x->tx_len);
        if ((st = save_status(f, x, GZ_FUND_ST_FAILED, 0, out)) != GZ_OK) return st;
        if ((st = log_note(f, out, "funding-h1-failed", x->scope)) != GZ_OK) return st;
        finish(f, x, GZ_FUND_ST_FAILED);
        return GZ_OK;
    }
    x->h1_ok = 0;
    set_deadline(f, x);
    if (x->mode == GZ_HOST_FUNDING_CONFIRM) {
        if ((st = save_status(f, x, GZ_FUND_ST_AWAITING, 0, out)) != GZ_OK) return st;
        x->state = GZ_FUND_ST_AWAITING;
        return attention(f, out, x->scope, 0);
    }
    return commit_signed(f, x, out);
}

static gz_status_t gz_fund_host_drop_in(gz_fund_t *f, const uint8_t scope[32], gz_action_list_t *out)
{
    gz_fund_factory_t *x;
    gz_status_t st;
    if (!f || !scope || !out || !f->cfg.host) return GZ_ERR_ARGUMENT;
    x = find_scope(f, scope);
    if (!x || x->state != 0) return GZ_OK;
    f->cfg.wallet.release(f->cfg.wallet.ctx, x->tx, x->tx_len);
    if ((st = save_status(f, x, GZ_FUND_ST_FAILED, 0, out)) != GZ_OK) return st;
    finish(f, x, GZ_FUND_ST_FAILED);
    return GZ_OK;
}

/* Inputs and their outpoints of an unsigned funding the member holds. */
static int member_tx_ok(gz_fund_factory_t *x)
{
    gz_tx_info_t info;
    uint64_t amt;
    const uint8_t *scr, *op;
    size_t slen;
    uint32_t seq;
    if (x->tx_len > GZ_FUND_MAX_TX || !gz_tx_parse(x->tx, x->tx_len, &info)) return 0;
    if (info.n_in == 0 || info.n_in > GZ_FUND_MAX_INPUTS) return 0;
    if (!gz_tx_output(x->tx, x->tx_len, &info, x->funding.vout, &amt, &scr, &slen)) return 0;
    if (amt != x->amount || slen != 34 || memcmp(scr, x->script, 34) != 0) return 0;
    {
        uint8_t txid[32];
        gz_tx_txid(x->tx, x->tx_len, txid);
        if (memcmp(txid, x->funding.txid, 32) != 0) return 0;
    }
    x->n_in = info.n_in;
    for (size_t i = 0; i < info.n_in && i < GZ_FUND_WATCH_INPUTS; i++) {
        if (!gz_tx_input(x->tx, x->tx_len, &info, i, &op, &slen, &seq)) return 0;
        memcpy(x->ins[i], op, 36);
        if (i == 0) memcpy(x->in0, op, 36);
    }
    return 1;
}

static gz_fund_factory_t *member_room(gz_fund_t *f)
{
    gz_fund_factory_t *x = alloc(f), *old = NULL;
    if (x) return x;
    /* Full: the oldest Abandoned creation stops being followed (it blocks
     * nothing, C10; a late burial of it is then not seen until a restart). */
    for (size_t i = 0; i < GZ_FUND_MAX_FACTORIES; i++)
        if (f->fac[i].state == GZ_FUND_ST_ABANDONED && (!old || f->fac[i].seq < old->seq)) old = &f->fac[i];
    if (!old) return NULL;
    drop_watches(f, old);
    memset(old, 0, sizeof *old);
    return alloc(f);
}

static gz_status_t gz_fund_member_acked_in(gz_fund_t *f, const gz_fund_acked_in_t *in, gz_action_list_t *out)
{
    gz_fund_factory_t *x, *const tmpp = &f->tmp;
    gz_status_t st;
    if (!f || !in || !out || f->cfg.host || !in->funding_tx) return GZ_ERR_ARGUMENT;
    if (in->funding_tx_len > GZ_FUND_MAX_TX) return GZ_ERR_ARGUMENT;  /* the signing engine holds at most this */
    if ((x = find_txid(f, in->scope, in->funding.txid)) != NULL) return GZ_OK;   /* given twice: rule 3 */
    memset(tmpp, 0, sizeof *tmpp);
    x = tmpp;
    memcpy(x->scope, in->scope, 32);
    memcpy(x->tx, in->funding_tx, in->funding_tx_len);
    x->tx_len = in->funding_tx_len;
    x->funding = in->funding;
    x->amount = in->amount;
    memcpy(x->script, in->script, 34);
    x->ack_tip = in->ack_tip;
    x->end_height = in->end_height;
    x->own_depth = in->own_depth;
    x->whole_tree = in->whole_tree ? 1 : 0;
    x->exit = in->exit;
    x->deadline_blocks = in->deadline_blocks;
    x->deadline = in->ack_tip + in->deadline_blocks;
    if (!member_tx_ok(x)) return GZ_ERR_ARGUMENT;   /* the signing engine checked all this (C1) */
    if ((st = save_status(f, x, GZ_FUND_ST_ACKED, 1, out)) != GZ_OK) return st;
    gz_fund_factory_t *slot = member_room(f);
    if (!slot) {
        /* Past the table: followed to its deadline only (never live). */
        size_t i;
        f->untracked++;
        for (i = 0; i < GZ_FUND_MAX_ENDED; i++)
            if (!f->pending[i].used) break;
        if (i == GZ_FUND_MAX_ENDED) {
            /* Oldest pending: give it up now, as abandoned, on the next tick. */
            uint32_t lo = UINT32_MAX;
            size_t j = 0;
            for (size_t k = 0; k < GZ_FUND_MAX_ENDED; k++)
                if (f->pending[k].deadline < lo) { lo = f->pending[k].deadline; j = k; }
            f->pending[j].deadline = 0;
            f->dropped++;
            i = GZ_FUND_MAX_ENDED;
        }
        if (i < GZ_FUND_MAX_ENDED) {
            f->pending[i].used = 1;
            memcpy(f->pending[i].scope, x->scope, 32);
            f->pending[i].funding = x->funding;
            f->pending[i].deadline = x->deadline;
        }
        return arm_tick(f, out, f->cfg.tick_ms);
    }
    uint64_t seq = slot->seq;
    *slot = *tmpp;
    slot->used = 1;
    slot->seq = seq;
    slot->state = GZ_FUND_ST_ACKED;
    return set_watches(f, slot, out);
}

/* ---- the slot end conditions ------------------------------------------- */

gz_fund_scope_t gz_fund_scope_state(const gz_fund_t *f, const uint8_t scope[32], uint32_t *until)
{
    const gz_fund_factory_t *best = NULL;
    if (until) *until = 0;
    if (!f || !scope) return GZ_FUND_SCOPE_NONE;
    for (size_t i = 0; i < GZ_FUND_MAX_FACTORIES; i++)
        if (f->fac[i].used && memcmp(f->fac[i].scope, scope, 32) == 0 && (!best || f->fac[i].seq > best->seq))
            best = &f->fac[i];
    if (best) {
        if (until) *until = best->deadline + f->cfg.burial;   /* the deadline, and a burial after it */
        return best->state == GZ_FUND_ST_ABANDONED ? GZ_FUND_SCOPE_ABANDONED : GZ_FUND_SCOPE_OPEN;
    }
    for (size_t i = 0; i < GZ_FUND_MAX_ENDED; i++)
        if (f->pending[i].used && memcmp(f->pending[i].scope, scope, 32) == 0) {
            if (until) *until = f->pending[i].deadline + f->cfg.burial;
            return GZ_FUND_SCOPE_OPEN;
        }
    /* The newest ended entry for the scope. */
    for (size_t k = 0; k < f->n_ended; k++) {
        size_t i = (f->ended_next + GZ_FUND_MAX_ENDED - 1 - k) % GZ_FUND_MAX_ENDED;
        if (memcmp(f->ended[i].scope, scope, 32) != 0) continue;
        switch (f->ended[i].state) {
        case GZ_FUND_ST_LIVE:
        case GZ_FUND_ST_LIVE_LATE: return GZ_FUND_SCOPE_LIVE;
        case GZ_FUND_ST_DEAD: return GZ_FUND_SCOPE_DEAD;
        case GZ_FUND_ST_ABANDONED: return GZ_FUND_SCOPE_ABANDONED;
        default: return GZ_FUND_SCOPE_FAILED;
        }
    }
    return GZ_FUND_SCOPE_NONE;
}

/* ---- load --------------------------------------------------------------- */

static const uint8_t plan_fields[] = { P_SCOPE, P_CHECK, P_ATTEMPT, P_MODE, P_FEERATE, P_TX, P_PREV, P_VOUT, P_TIP,
                                       P_RELEASED };
static const uint8_t signed_fields[] = { S1_SCOPE, S1_TXID, S1_TX };
static const uint8_t status_fields[] = { T_SCOPE, T_TXID, T_STATE, T_HEIGHT, T_DEADLINE, T_FTX, T_VOUT,
                                         T_AMOUNT, T_SCRIPT, T_ACK_TIP, T_END, T_DEPTH, T_WHOLE, T_EXIT,
                                         T_DBLOCKS, T_SB, T_SB_FEE, T_SB_ESC, T_SB_INDEX };

static gz_status_t load_plan(gz_fund_t *f, gz_bytes_t s)
{
    gz_bytes_t v[8], tipv, relv;
    gz_fund_factory_t *x, *old;
    size_t at = 0, n = 0;
    int has_tip, has_rel;
    if (!f->cfg.host || !fields_ok(s, plan_fields, sizeof plan_fields)) return GZ_ERR_CORRUPT;
    if (!field(s, P_SCOPE, 32, 0, &v[0]) || !field(s, P_CHECK, 32, 0, &v[1]) || !field(s, P_ATTEMPT, 2, 0, &v[2]) ||
        !field(s, P_MODE, 1, 0, &v[3]) || !field(s, P_FEERATE, 8, 0, &v[4]) ||
        !field(s, P_TX, 0, GZ_FUND_MAX_TX, &v[5]) || !field(s, P_PREV, 0, 9u * GZ_FUND_MAX_INPUTS * 6u, &v[6]) ||
        !field(s, P_VOUT, 4, 0, &v[7]))
        return GZ_ERR_CORRUPT;
    if (v[3].data[0] > 1) return GZ_ERR_CORRUPT;
    if (!opt_field(s, P_TIP, 4, &tipv, &has_tip) || !opt_field(s, P_RELEASED, 1, &relv, &has_rel) ||
        (has_rel && relv.data[0] != 1))
        return GZ_ERR_CORRUPT;
    old = find_scope(f, v[0].data);
    if (old && old->state != 0) return GZ_ERR_CORRUPT;   /* a plan after the scope's funding: not ours */
    if (old) memset(old, 0, sizeof *old);                /* superseded (H11), its coins released */
    x = alloc(f);
    if (!x) return GZ_ERR_CORRUPT;                       /* more open plans than this engine ever makes */
    memcpy(x->scope, v[0].data, 32);
    memcpy(x->check, v[1].data, 32);
    x->attempt = gz_get_u16(v[2].data);
    x->mode = v[3].data[0];
    x->feerate = gz_get_u64(v[4].data);
    if (has_tip) {
        x->plan_tip = gz_get_u32(tipv.data);
        x->plan_tip_known = 1;
    }
    x->released = has_rel;
    memcpy(x->tx, v[5].data, v[5].len);
    x->tx_len = v[5].len;
    while (at < v[6].len) {
        gz_fund_prevout_t *p;
        if (n == GZ_FUND_MAX_INPUTS || v[6].len - at < 9) return GZ_ERR_CORRUPT;
        p = &x->prev[n];
        p->amount = gz_get_u64(v[6].data + at);
        p->script_len = v[6].data[at + 8];
        if (p->script_len > GZ_FUND_MAX_SCRIPT || v[6].len - at - 9 < p->script_len) return GZ_ERR_CORRUPT;
        memcpy(p->script, v[6].data + at + 9, p->script_len);
        at += 9u + p->script_len;
        n++;
    }
    x->n_in = n;
    {
        /* The output: amount and script from the transaction at vout. */
        gz_tx_info_t info;
        const uint8_t *scr;
        size_t sl;
        x->funding.vout = gz_get_u32(v[7].data);
        if (!gz_tx_parse(x->tx, x->tx_len, &info) ||
            !gz_tx_output(x->tx, x->tx_len, &info, x->funding.vout, &x->amount, &scr, &sl) || sl != 34)
            return GZ_ERR_CORRUPT;
        memcpy(x->script, scr, 34);
    }
    if (!plan_ok(x, NULL)) return GZ_ERR_CORRUPT;
    return GZ_OK;
}

static gz_status_t load_signed(gz_fund_t *f, gz_bytes_t s)
{
    gz_bytes_t sc, id, tx;
    gz_fund_factory_t *x;
    if (!f->cfg.host || !fields_ok(s, signed_fields, sizeof signed_fields)) return GZ_ERR_CORRUPT;
    if (!field(s, S1_SCOPE, 32, 0, &sc) || !field(s, S1_TXID, 32, 0, &id) || !field(s, S1_TX, 0, GZ_FUND_MAX_SIGNED, &tx))
        return GZ_ERR_CORRUPT;
    x = find_txid(f, sc.data, id.data);
    if (!x || (x->state != 0 && x->state != GZ_FUND_ST_AWAITING)) return GZ_ERR_CORRUPT;
    if (!signed_ok(f, x, tx.data, tx.len)) return GZ_ERR_CORRUPT;
    memcpy(x->signed_tx, tx.data, tx.len);
    x->signed_len = tx.len;
    return GZ_OK;
}

static int legal_step(int host, int from, int to)
{
    if (host) {
        switch (from) {
        case 0: return to == GZ_FUND_ST_AWAITING || to == GZ_FUND_ST_BROADCAST || to == GZ_FUND_ST_FAILED;
        case GZ_FUND_ST_AWAITING:
            return to == GZ_FUND_ST_AWAITING || to == GZ_FUND_ST_BROADCAST || to == GZ_FUND_ST_ABANDONED;
        case GZ_FUND_ST_BROADCAST:
            return to == GZ_FUND_ST_BROADCAST || to == GZ_FUND_ST_LIVE || to == GZ_FUND_ST_DEAD || to == GZ_FUND_ST_ABANDONED;
        case GZ_FUND_ST_ABANDONED:
            return to == GZ_FUND_ST_ABANDONED || to == GZ_FUND_ST_DEAD || to == GZ_FUND_ST_LIVE_LATE;
        default: return 0;
        }
    }
    switch (from) {
    case GZ_FUND_ST_ACKED:
        return to == GZ_FUND_ST_LIVE || to == GZ_FUND_ST_DEAD || to == GZ_FUND_ST_ABANDONED;
    case GZ_FUND_ST_ABANDONED: return to == GZ_FUND_ST_LIVE || to == GZ_FUND_ST_DEAD;
    default: return 0;
    }
}

static gz_status_t load_status(gz_fund_t *f, gz_bytes_t s)
{
    gz_bytes_t sc, id, stv, h, dl, v;
    gz_fund_factory_t *x;
    int state, present;
    if (!fields_ok(s, status_fields, sizeof status_fields)) return GZ_ERR_CORRUPT;
    if (!field(s, T_SCOPE, 32, 0, &sc) || !field(s, T_TXID, 32, 0, &id) || !field(s, T_STATE, 1, 0, &stv) ||
        !field(s, T_HEIGHT, 4, 0, &h) || !field(s, T_DEADLINE, 4, 0, &dl))
        return GZ_ERR_CORRUPT;
    state = stv.data[0];
    if (state < GZ_FUND_ST_ACKED || state > GZ_FUND_ST_LIVE_LATE) return GZ_ERR_CORRUPT;
    if (gz_rec_find(s, T_FTX, &v) == 1) {
        /* A member's first status: everything C11 and C4(d) need. */
        gz_bytes_t vo, am, scr, at, en, dp, wh, ex, db;
        gz_fund_factory_t *const tmpp = &f->tmp;
        if (f->cfg.host || state != GZ_FUND_ST_ACKED || v.len > GZ_FUND_MAX_TX) return GZ_ERR_CORRUPT;
        if (!field(s, T_VOUT, 4, 0, &vo) || !field(s, T_AMOUNT, 8, 0, &am) || !field(s, T_SCRIPT, 34, 0, &scr) ||
            !field(s, T_ACK_TIP, 4, 0, &at) || !field(s, T_END, 4, 0, &en) || !field(s, T_DEPTH, 1, 0, &dp) ||
            !field(s, T_WHOLE, 1, 0, &wh) || !field(s, T_EXIT, 16, 0, &ex) || !field(s, T_DBLOCKS, 4, 0, &db))
            return GZ_ERR_CORRUPT;
        if (find_txid(f, sc.data, id.data)) return GZ_ERR_CORRUPT;   /* acked twice */
        memset(tmpp, 0, sizeof *tmpp);
        memcpy(tmpp->scope, sc.data, 32);
        memcpy(tmpp->funding.txid, id.data, 32);
        memcpy(tmpp->tx, v.data, v.len);
        tmpp->tx_len = v.len;
        tmpp->funding.vout = gz_get_u32(vo.data);
        tmpp->amount = gz_get_u64(am.data);
        memcpy(tmpp->script, scr.data, 34);
        tmpp->ack_tip = gz_get_u32(at.data);
        tmpp->end_height = gz_get_u32(en.data);
        tmpp->own_depth = dp.data[0];
        tmpp->whole_tree = wh.data[0] ? 1 : 0;
        tmpp->exit.A = gz_get_u32(ex.data);
        tmpp->exit.B = gz_get_u32(ex.data + 4);
        tmpp->exit.M = gz_get_u32(ex.data + 8);
        tmpp->exit.M_host = gz_get_u32(ex.data + 12);
        tmpp->deadline_blocks = gz_get_u32(db.data);
        tmpp->deadline = gz_get_u32(dl.data);
        if (wh.data[0] > 1 || tmpp->deadline != tmpp->ack_tip + tmpp->deadline_blocks || !member_tx_ok(tmpp))
            return GZ_ERR_CORRUPT;
        x = member_room(f);
        if (!x) {
            /* Only possible after a long attack (more than 16 creations
             * waiting): followed to its deadline, as at the time. */
            for (size_t i = 0; i < GZ_FUND_MAX_ENDED; i++)
                if (!f->pending[i].used) {
                    f->pending[i].used = 1;
                    memcpy(f->pending[i].scope, tmpp->scope, 32);
                    f->pending[i].funding = tmpp->funding;
                    f->pending[i].deadline = tmpp->deadline;
                    return GZ_OK;
                }
            f->dropped++;
            return GZ_OK;
        }
        uint64_t seq = x->seq;
        *x = *tmpp;
        x->used = 1;
        x->seq = seq;
        x->state = GZ_FUND_ST_ACKED;
        return GZ_OK;
    }
    x = find_txid(f, sc.data, id.data);
    if (!x) {
        /* A creation no longer followed (past the table, or given up): a
         * later status of it changes nothing here. */
        for (size_t i = 0; i < GZ_FUND_MAX_ENDED; i++)
            if (f->pending[i].used && memcmp(f->pending[i].scope, sc.data, 32) == 0 &&
                memcmp(f->pending[i].funding.txid, id.data, 32) == 0) {
                f->pending[i].used = 0;
                remember_end(f, sc.data, state, gz_get_u32(h.data));
                return GZ_OK;
            }
        if (!f->cfg.host) {
            remember_end(f, sc.data, state, gz_get_u32(h.data));
            return GZ_OK;
        }
        return GZ_ERR_CORRUPT;
    }
    if (!legal_step(f->cfg.host, x->state, state)) return GZ_ERR_CORRUPT;
    if (f->cfg.host && state == GZ_FUND_ST_BROADCAST && !x->signed_len) return GZ_ERR_CORRUPT;
    x->deadline = gz_get_u32(dl.data);
    if (gz_rec_find(s, T_SB, &v) == 1) {
        gz_bytes_t fe, es, ix;
        if (!f->cfg.host || state != GZ_FUND_ST_ABANDONED || v.len > GZ_FUND_MAX_SPEND_BACK || !field(s, T_SB_FEE, 8, 0, &fe) ||
            !opt_field(s, T_SB_ESC, 1, &es, &present) || !present || !field(s, T_SB_INDEX, 4, 0, &ix))
            return GZ_ERR_CORRUPT;
        memcpy(x->sb, v.data, v.len);
        x->sb_len = v.len;
        x->sb_fee = gz_get_u64(fe.data);
        if (es.data[0] > 2) return GZ_ERR_CORRUPT;
        x->sb_escalated = es.data[0];
        x->sb_index = gz_get_u32(ix.data);
        if (x->sb_index >= x->n_in || !gz_fund_tx_vsize(x->sb, x->sb_len, NULL, NULL)) return GZ_ERR_CORRUPT;
        {
            size_t bl;
            if (!gz_fund_tx_strip(x->sb, x->sb_len, f->work, sizeof f->work, &bl)) return GZ_ERR_CORRUPT;
            gz_tx_txid(f->work, bl, x->sb_txid);
        }
    }
    if (is_terminal(state)) {
        finish(f, x, state);
        f->ended[(f->ended_next + GZ_FUND_MAX_ENDED - 1) % GZ_FUND_MAX_ENDED].height = gz_get_u32(h.data);
        return GZ_OK;
    }
    x->state = state;
    return GZ_OK;
}

gz_status_t gz_fund_load(void *e, const gz_record_t *rec, gz_batch_id_t at)
{
    gz_fund_t *f = (gz_fund_t *)e;
    (void)at;
    if (!f || !rec || (rec->bytes.len && !rec->bytes.data)) return GZ_ERR_ARGUMENT;
    switch (rec->type) {
    case GZ_FUND_REC_PLAN: return load_plan(f, rec->bytes);
    case GZ_FUND_REC_SIGNED: return load_signed(f, rec->bytes);
    case GZ_FUND_REC_STATUS: return load_status(f, rec->bytes);
    default: return GZ_ERR_CORRUPT;   /* every type of the area is even: must be understood */
    }
}

/* ---- resume ------------------------------------------------------------- */

gz_status_t gz_fund_resume(void *e, gz_action_list_t *out, int *more)
{
    gz_fund_t *f = (gz_fund_t *)e;
    gz_status_t st;
    if (!f || !out || !more) return GZ_ERR_ARGUMENT;
    *more = 0;
    while (f->resume_at < GZ_FUND_MAX_FACTORIES) {
        gz_fund_factory_t *x = &f->fac[f->resume_at++];
        size_t before = out->count;
        if (!x->used) continue;
        if (f->cfg.host) {
            /* The wallet's hold is in its memory only (A11). */
            if (!f->cfg.wallet.adopt(f->cfg.wallet.ctx, x->tx, x->tx_len, x->script, x->amount) &&
                (st = log_note(f, out, "funding-adopt-refused", x->scope)) != GZ_OK)
                return st;
            if (x->state == GZ_FUND_ST_AWAITING && (st = attention(f, out, x->scope, 0)) != GZ_OK) return st;
            if (x->state == GZ_FUND_ST_BROADCAST && (st = broadcast(out, x->signed_tx, x->signed_len)) != GZ_OK)
                return st;
            if (x->state == GZ_FUND_ST_ABANDONED && x->sb_len && (st = broadcast(out, x->sb, x->sb_len)) != GZ_OK)
                return st;
            if ((x->state == GZ_FUND_ST_AWAITING || x->state == GZ_FUND_ST_BROADCAST) && !x->deadline) x->deadline_pending = 1;
        }
        if (x->state != 0 && x->state != GZ_FUND_ST_AWAITING) {
            /* The chain facts come back through these watches (H-1). */
            x->resyncing = 1;
            x->reported = 0;
            if ((st = set_watches(f, x, out)) != GZ_OK) return st;
        }
        x->due = 1;
        if (out->count != before) {
            *more = 1;
            return GZ_OK;
        }
    }
    /* Deadlines need the tip, which the chain gives next; the tick then runs. */
    for (size_t i = 0; i < GZ_FUND_MAX_ENDED; i++)
        if (f->pending[i].used) return arm_tick(f, out, f->cfg.tick_ms);
    for (size_t i = 0; i < GZ_FUND_MAX_FACTORIES; i++)
        if (f->fac[i].used) return arm_tick(f, out, f->cfg.tick_ms);
    return GZ_OK;
}

/* ---- the spend-back (14.3) ---------------------------------------------- */

/* Index of the input to spend back: input 0 if it pays the fee and dust,
 * else the largest. */
static uint32_t sb_input(const gz_fund_factory_t *x)
{
    uint32_t best = 0;
    if (x->prev[0].amount > 1000) return 0;
    for (uint32_t i = 1; i < x->n_in; i++)
        if (x->prev[i].amount > x->prev[best].amount) best = i;
    return best;
}

/* Builds the spend-back at `level`: 0 the ordinary rate (nothing to
 * replace), 1 the smallest fee that replaces the funding with the
 * increment of Core 29.1, 2 the same with the increment of 28.x and 29.0.
 * 1 on success, 0 if the wallet failed or returned something else. */
static int make_spend_back(gz_fund_t *f, gz_fund_factory_t *x, int level)
{
    int replace = level > 0 && x->signed_len;
    uint64_t inc = level == 2 ? f->cfg.incremental_high : f->cfg.incremental;
    uint8_t tx[GZ_FUND_MAX_SPEND_BACK];   /* x->sb is kept until the new one is whole */
    size_t len = 0, base;
    uint64_t vsize, fee, need, pf = 0, pv = 0;
    uint32_t idx = sb_input(x);
    if (replace && x->signed_len) {
        pf = funding_fee(x);
        if (!gz_fund_tx_vsize(x->signed_tx, x->signed_len, &pv, NULL)) return 0;
    }
    /* A first guess at the size of a one-in, one-out key-path spend. */
    fee = replace ? gz_fund_replace_fee(pf, pv, 111, inc) : gz_fund_fee(x->feerate, 111);
    for (int round = 0; round < 3; round++) {
        if (fee == UINT64_MAX || fee >= x->prev[idx].amount) return 0;
        if (!f->cfg.wallet.spend_back(f->cfg.wallet.ctx, x->funding.txid, idx, fee, tx, GZ_FUND_MAX_SPEND_BACK, &len) ||
            len > GZ_FUND_MAX_SPEND_BACK || !gz_fund_tx_vsize(tx, len, &vsize, &base))
            return 0;
        need = replace ? gz_fund_replace_fee(pf, pv, vsize, inc) : gz_fund_fee(x->feerate, vsize);
        if (need == fee) break;
        fee = need;
        if (round == 2) return 0;
    }
    /* The ceiling: never above the top of the ladder, level 2 on this size
     * (signer.md's "ceiling x vsize" would refuse level 2; review B, M-3). */
    if (fee > (replace ? gz_fund_replace_fee(pf, pv, vsize, f->cfg.incremental_high) : gz_fund_fee(x->feerate, vsize)))
        return 0;
    /* What the wallet made: one input, the chosen outpoint, one output that
     * does not pay the factory, and exactly the fee asked. */
    {
        gz_tx_info_t info;
        const uint8_t *op, *scr;
        size_t sl, n;
        uint32_t seq;
        uint64_t amt;
        gz_tx_info_t finfo;
        const uint8_t *fop;
        if (!gz_fund_tx_strip(tx, len, f->work, sizeof f->work, &n) || !gz_tx_parse(f->work, n, &info)) return 0;
        if (info.n_in != 1 || info.n_out != 1) return 0;
        if (!gz_tx_input(f->work, n, &info, 0, &op, &sl, &seq) || sl != 0) return 0;
        if (!gz_tx_parse(x->tx, x->tx_len, &finfo) || !gz_tx_input(x->tx, x->tx_len, &finfo, idx, &fop, &sl, &seq) ||
            memcmp(op, fop, 36) != 0)
            return 0;
        if (!gz_tx_output(f->work, n, &info, 0, &amt, &scr, &sl)) return 0;
        if (sl == 34 && memcmp(scr, x->script, 34) == 0) return 0;
        if (amt + fee != x->prev[idx].amount) return 0;
        gz_tx_txid(f->work, n, x->sb_txid);
    }
    memcpy(x->sb, tx, len);
    x->sb_len = len;
    x->sb_fee = fee;
    x->sb_index = idx;
    x->sb_escalated = replace ? level : 0;
    return 1;
}

/* ---- the tick ----------------------------------------------------------- */

static gz_status_t report(gz_fund_t *f, gz_fund_factory_t *x, gz_fund_report_kind_t kind, gz_action_list_t *out)
{
    gz_fund_report_t r;
    CLEAR(&r);
    r.kind = kind;
    r.host = f->cfg.host;
    memcpy(r.scope, x->scope, 32);
    r.funding = x->funding;
    r.cancel_reason = (kind == GZ_FUND_R_DEAD || kind == GZ_FUND_R_ABANDONED) ? GZ_FUND_CANCEL_FUNDING : 0;
    r.height = f->tip;
    return f->cfg.hooks.report(f->cfg.hooks.ctx, &r, out);
}

/* The funding txid is buried. */
static int buried(const gz_fund_t *f, const gz_fund_factory_t *x)
{
    return x->conf >= depth_of(f, x);
}

/* Host: buried by its deadline (a burial after it is funded late, M3). */
static int buried_in_time(const gz_fund_t *f, const gz_fund_factory_t *x)
{
    if (!buried(f, x)) return 0;
    return x->deadline_pending || x->conf_height + depth_of(f, x) - 1 <= x->deadline;
}

/* After a start, have the chain facts come back (review B of PR 56, H-1)?
 * Only when the chain view has answered every watch of the factory set at
 * this start (GZ_CHAIN_WATCH_SYNCED): what it found came just before. No
 * count of tips stands in for it: a block can come before the answers. */
static int facts_back(const gz_fund_t *f, gz_fund_factory_t *x)
{
    unsigned all;
    if (!f->tip_synced) return 0;   /* the answers for this tip are not all in (integration B12) */
    if (!x->resyncing) return 1;
    all = (2u << (n_watch(f, x) - 1)) - 1u;
    if ((x->reported & all) == all) x->resyncing = 0;
    return !x->resyncing;
}

/* The funding or a spend of a watched input has a confirmation: no new fee
 * level, nothing sent again (review A of PR 56, L10). */
static int sb_settled(const gz_fund_factory_t *x)
{
    if (x->conf > 0) return 1;
    for (size_t k = 0; k < GZ_FUND_WATCH_INPUTS && k < x->n_in; k++)
        if (x->spender_known[k] && x->spender_conf[k] > 0) return 1;
    return 0;
}

/* Watched input k spent by another transaction, buried. */
static int input_dead(const gz_fund_t *f, const gz_fund_factory_t *x, size_t *which)
{
    for (size_t k = 0; k < GZ_FUND_WATCH_INPUTS && k < x->n_in; k++) {
        if (!x->spender_known[k] || x->spender_conf[k] < depth_of(f, x)) continue;
        if (gz_tree_c4d_dead(x->tx, x->tx_len, x->ins[k], x->spender[k])) {
            if (which) *which = k;
            return 1;
        }
    }
    return 0;
}

static gz_status_t end_with(gz_fund_t *f, gz_fund_factory_t *x, int state, int kind, gz_action_list_t *out)
{
    gz_status_t st;
    if ((st = save_status(f, x, state, 0, out)) != GZ_OK) return st;
    if (kind && (st = report(f, x, (gz_fund_report_kind_t)kind, out)) != GZ_OK) return st;
    finish(f, x, state);
    return GZ_OK;
}

/* Abandon (host): the status with the spend-back, the report, then the
 * spend-back's broadcast. */
static gz_status_t host_abandon(gz_fund_t *f, gz_fund_factory_t *x, gz_action_list_t *out)
{
    gz_status_t st;
    int was_signed = x->state == GZ_FUND_ST_BROADCAST;
    int late = buried(f, x);   /* buried after the deadline: funded late, nothing to spend back */
    int ok = late ? 0 : make_spend_back(f, x, was_signed && x->seen ? 1 : 0);
    if (!ok) x->sb_len = 0;
    if ((st = save_status(f, x, GZ_FUND_ST_ABANDONED, 0, out)) != GZ_OK) return st;
    x->state = GZ_FUND_ST_ABANDONED;
    if ((st = report(f, x, GZ_FUND_R_ABANDONED, out)) != GZ_OK) return st;
    if (!was_signed && (st = attention(f, out, x->scope, 1)) != GZ_OK) return st;
    if (late) return GZ_OK;   /* the next tick: funded late */
    if (!ok) return log_note(f, out, "funding-spend-back-failed", x->scope);
    if ((st = broadcast(out, x->sb, x->sb_len)) != GZ_OK) return st;
    return set_watches(f, x, out);
}

/* One factory's change, if one is due: 1 if something was done. */
static gz_status_t step_host(gz_fund_t *f, gz_fund_factory_t *x, gz_action_list_t *out, int *did)
{
    size_t k;
    *did = 1;
    if (x->deadline_pending && f->tip_known && (x->state == GZ_FUND_ST_AWAITING || x->state == GZ_FUND_ST_BROADCAST)) {
        /* No tip was known at the outcome: the deadline from the first one, saved. */
        set_deadline(f, x);
        return save_status(f, x, x->state, 0, out);
    }
    switch (x->state) {
    case GZ_FUND_ST_BROADCAST:
        if (buried_in_time(f, x)) return end_with(f, x, GZ_FUND_ST_LIVE, GZ_FUND_R_LIVE, out);
        if (input_dead(f, x, &k)) return end_with(f, x, GZ_FUND_ST_DEAD, GZ_FUND_R_DEAD, out);
        if (!x->deadline_pending && f->tip_known && f->tip > x->deadline && facts_back(f, x)) return host_abandon(f, x, out);
        if (x->rebroadcast) {
            x->rebroadcast = 0;
            return broadcast(out, x->signed_tx, x->signed_len);
        }
        break;
    case GZ_FUND_ST_AWAITING:
        if (!x->deadline_pending && f->tip_known && f->tip > x->deadline && facts_back(f, x)) return host_abandon(f, x, out);
        break;
    case GZ_FUND_ST_ABANDONED:
        if (buried(f, x)) return end_with(f, x, GZ_FUND_ST_LIVE_LATE, GZ_FUND_R_FUNDED_LATE, out);
        if (input_dead(f, x, &k)) return end_with(f, x, GZ_FUND_ST_DEAD, 0, out);
        if (sb_settled(x)) break;   /* mined: no new level, no re-broadcast */
        if (!facts_back(f, x)) {   /* after a start: the facts first (H-1); what is pending waits */
            *did = 0;
            return GZ_OK;
        }
        if (x->escalate || (x->rebroadcast && !x->sb_len)) {
            /* Refused, or not made at the deadline: one level up, at most
             * the higher increment. A funding never signed has nothing to
             * replace. */
            int level = x->sb_len ? x->sb_escalated + 1 : (x->seen ? 1 : 0);
            gz_status_t st;
            x->escalate = 0;
            x->rebroadcast = 0;
            if ((x->sb_len && !x->signed_len) || level > 2) break;
            if (!make_spend_back(f, x, level)) break;
            if ((st = save_status(f, x, GZ_FUND_ST_ABANDONED, 0, out)) != GZ_OK) return st;
            if ((st = broadcast(out, x->sb, x->sb_len)) != GZ_OK) return st;
            return set_watches(f, x, out);
        }
        if (x->rebroadcast && x->sb_len) {
            x->rebroadcast = 0;
            return broadcast(out, x->sb, x->sb_len);
        }
        break;
    default:
        break;
    }
    x->rebroadcast = 0;
    x->escalate = 0;
    *did = 0;
    return GZ_OK;
}

static gz_status_t step_member(gz_fund_t *f, gz_fund_factory_t *x, gz_action_list_t *out, int *did)
{
    gz_tree_c11_in_t c;
    gz_tree_conditions_t cond;
    gz_c11_t v;
    *did = 1;
    if (input_dead(f, x, NULL)) return end_with(f, x, GZ_FUND_ST_DEAD, GZ_FUND_R_DEAD, out);
    if (!f->tip_known) {
        *did = 0;
        return GZ_OK;
    }
    CLEAR(&cond);
    cond.exit = x->exit;
    cond.funding_deadline_blocks = x->deadline_blocks;
    CLEAR(&c);
    c.tip = f->tip;
    c.ack_tip = x->ack_tip;
    c.cond = &cond;
    c.seen = x->conf > 0;
    c.seen_amount = x->amount;   /* the txid commits to its outputs: the held transaction's */
    c.seen_script = x->script;
    c.seen_script_len = 34;
    c.confirmations = x->conf;
    c.buried_at = x->conf_height + depth_of(f, x) - 1;
    c.funding_amount = x->amount;
    c.funding_script = x->script;
    c.holds_whole_tree = x->whole_tree;
    c.end_height = x->end_height;
    c.own_depth = x->own_depth;
    v = gz_tree_c11(&c);
    if (v == GZ_C11_LIVE) return end_with(f, x, GZ_FUND_ST_LIVE, GZ_FUND_R_LIVE, out);
    if (v == GZ_C11_ABANDONED && x->state == GZ_FUND_ST_ACKED && facts_back(f, x)) {
        gz_status_t st;
        if ((st = save_status(f, x, GZ_FUND_ST_ABANDONED, 0, out)) != GZ_OK) return st;
        x->state = GZ_FUND_ST_ABANDONED;
        return report(f, x, GZ_FUND_R_ABANDONED, out);
    }
    *did = 0;
    return GZ_OK;
}

static gz_status_t tick(gz_fund_t *f, gz_action_list_t *out)
{
    gz_status_t st;
    f->tick_armed = 0;
    /* Creations past the table: their deadline only. */
    for (size_t i = 0; i < GZ_FUND_MAX_ENDED; i++) {
        if (!f->pending[i].used || !f->tip_known || f->tip <= f->pending[i].deadline) continue;
        gz_fund_factory_t *const tmpp = &f->tmp;
        memset(tmpp, 0, sizeof *tmpp);
        memcpy(tmpp->scope, f->pending[i].scope, 32);
        tmpp->funding = f->pending[i].funding;
        tmpp->deadline = f->pending[i].deadline;
        f->pending[i].used = 0;
        if ((st = save_status(f, tmpp, GZ_FUND_ST_ABANDONED, 0, out)) != GZ_OK) return st;
        if ((st = report(f, tmpp, GZ_FUND_R_ABANDONED, out)) != GZ_OK) return st;
        remember_end(f, tmpp->scope, GZ_FUND_ST_ABANDONED, f->tip);
        return arm_tick(f, out, f->cfg.tick_ms);
    }
    for (size_t n = 0; n < GZ_FUND_MAX_FACTORIES; n++) {
        gz_fund_factory_t *x = &f->fac[f->cursor];
        int did = 0;
        f->cursor = (f->cursor + 1) % GZ_FUND_MAX_FACTORIES;
        if (!x->used || !x->due) continue;
        x->due = 0;
        st = f->cfg.host ? step_host(f, x, out, &did) : step_member(f, x, out, &did);
        if (st != GZ_OK) return st;
        if (did) {
            /* One change per tick (8.3): the factory may have more due. */
            if (x->used) x->due = 1;
            return arm_tick(f, out, f->cfg.tick_ms);
        }
    }
    return GZ_OK;
}

/* ---- events ------------------------------------------------------------- */

static void chain_event(gz_fund_t *f, const gz_chain_event_t *c)
{
    if (c->kind == GZ_CHAIN_TIP_SYNCED && f->tip_known && c->height == f->tip) f->tip_synced = 1;
    for (size_t i = 0; i < GZ_FUND_MAX_FACTORIES; i++) {
        gz_fund_factory_t *x = &f->fac[i];
        if (x->used && c->kind == GZ_CHAIN_TIP_SYNCED) x->due = 1;
        if (!x->used || !x->watching) continue;
        if ((c->kind == GZ_CHAIN_TX_CONFIRMED || c->kind == GZ_CHAIN_TX_UNCONFIRMED) &&
            memcmp(c->txid, x->funding.txid, 32) == 0) {
            if (c->kind == GZ_CHAIN_TX_CONFIRMED && c->confirmations > 0) {
                x->conf = c->confirmations;
                x->conf_height = c->height;
                x->seen = 1;
            } else {
                x->conf = 0;   /* reorganised away: counting starts again */
                x->conf_height = 0;
            }
            x->due = 1;
        }
        if (c->kind == GZ_CHAIN_WATCH_SYNCED && x->resyncing) {
            if (c->is_tx && memcmp(c->txid, x->funding.txid, 32) == 0) x->reported |= 1u;
            for (size_t k = 0; !c->is_tx && k < GZ_FUND_WATCH_INPUTS && k < x->n_in; k++) {
                gz_outpoint_t o;
                outpoint_of(x->ins[k], &o);
                if (memcmp(o.txid, c->outpoint.txid, 32) == 0 && o.vout == c->outpoint.vout) x->reported |= 2u << k;
            }
            x->due = 1;
        }
        if (c->kind == GZ_CHAIN_OUTPOINT_SPENT) {
            for (size_t k = 0; k < GZ_FUND_WATCH_INPUTS && k < x->n_in; k++) {
                gz_outpoint_t o;
                outpoint_of(x->ins[k], &o);
                if (memcmp(o.txid, c->outpoint.txid, 32) != 0 || o.vout != c->outpoint.vout) continue;
                memcpy(x->spender[k], c->txid, 32);
                x->spender_conf[k] = c->confirmations;
                x->spender_known[k] = 1;
                if (memcmp(c->txid, x->funding.txid, 32) == 0) x->seen = 1;
                x->due = 1;
            }
        }
        if (c->kind == GZ_CHAIN_BROADCAST_RESULT && f->cfg.host && c->outcome == GZ_BROADCAST_REFUSED &&
            x->state == GZ_FUND_ST_ABANDONED && x->sb_len && memcmp(c->txid, x->sb_txid, 32) == 0) {
            x->escalate = 1;
            x->due = 1;
        }
    }
}

static gz_status_t command(gz_fund_t *f, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t rid, code, scope;
    uint16_t status = 200;
    const char *err = NULL;
    gz_fund_factory_t *x = NULL;
    gz_status_t st;
    uint8_t *buf;
    size_t at = 0, n = 0;
    gz_action_t a;
    uint8_t s2[2];
    if (gz_rec_find(cmd, GZ_CMD_REC_REQUEST_ID, &rid) != 1 || rid.len == 0 || rid.len > GZ_CMD_MAX_REQUEST_ID) {
        f->dropped++;   /* no request id: nobody to answer */
        return GZ_OK;
    }
    for (size_t i = 0; i < rid.len; i++)
        if (rid.data[i] < 0x20 || rid.data[i] > 0x7e) {
            f->dropped++;
            return GZ_OK;
        }
    if (gz_rec_find(cmd, GZ_CMD_REC_COMMAND, &code) != 1 || code.len != 2 ||
        gz_get_u16(code.data) != GZ_CMD_FUNDING_CONFIRM) {
        status = 404;
        err = "unknown_command";
    } else if (gz_rec_find(cmd, 12, &scope) != 1 || scope.len != 32) {
        status = 400;
        err = "bad_request";
    } else if (!f->cfg.host || !(x = find_scope(f, scope.data))) {
        status = 404;
        err = "no_such_funding";
    } else if (x->state != GZ_FUND_ST_AWAITING) {
        status = 409;
        err = "refused_now";
    } else if (!x->deadline_pending && f->tip_known && f->tip + f->cfg.burial - 1 > x->deadline) {
        status = 409;   /* a burial by the deadline is no longer possible (review B, M-1) */
        err = "too_late";
    } else if (!f->cfg.wallet.sign_plan(f->cfg.wallet.ctx, x->funding.txid, x->signed_tx, sizeof x->signed_tx, &n) ||
               n > sizeof x->signed_tx || !signed_ok(f, x, x->signed_tx, n)) {
        status = 503;
        err = "wallet_failed";
    }
    if (status == 200) {
        x->signed_len = n;
        if ((st = commit_signed(f, x, out)) != GZ_OK) return st;
        if ((st = attention(f, out, x->scope, 1)) != GZ_OK) return st;
    }
    buf = f->scratch + sizeof f->scratch - 256;
    if ((st = gz_rec_put(buf, 256, &at, GZ_RESULT_REC_REQUEST_ID, rid.data, rid.len)) != GZ_OK) return st;
    gz_put_u16(s2, status);
    if ((st = gz_rec_put(buf, 256, &at, GZ_RESULT_REC_STATUS, s2, 2)) != GZ_OK) return st;
    if (err && (st = gz_rec_put(buf, 256, &at, GZ_RESULT_REC_ERROR, (const uint8_t *)err, cstrlen(err))) != GZ_OK)
        return st;
    CLEAR(&a);
    a.kind = GZ_ACTION_NOTIFY;
    a.u.notify.code = GZ_NOTIFY_COMMAND_RESULT;
    a.u.notify.bytes.data = buf;
    a.u.notify.bytes.len = at;
    return add(out, &a);
}

static gz_status_t gz_fund_handle_in(void *e, const gz_event_t *ev, gz_action_list_t *out)
{
    gz_fund_t *f = (gz_fund_t *)e;
    if (!f || !ev || !out) return GZ_ERR_ARGUMENT;
    switch (ev->kind) {
    case GZ_EVENT_TIMER_FIRED:
        if (ev->u.timer.timer_id != GZ_FUND_TIMER_TICK) {
            f->dropped++;
            return GZ_OK;
        }
        return tick(f, out);
    case GZ_EVENT_CHAIN:
        if (ev->u.chain.kind == GZ_CHAIN_NEW_TIP) {
            int any = 0;
            f->tip = ev->u.chain.height;
            f->tip_known = 1;
            f->tip_synced = 0;   /* its reports may still be coming */
            for (size_t i = 0; i < GZ_FUND_MAX_FACTORIES; i++)
                if (f->fac[i].used) {
                    gz_fund_factory_t *y = &f->fac[i];
                    y->due = 1;
                    y->rebroadcast = 1;
                    any = 1;
                }
            for (size_t i = 0; i < GZ_FUND_MAX_ENDED; i++)
                if (f->pending[i].used) any = 1;
            return any ? arm_tick(f, out, f->cfg.tick_ms) : GZ_OK;
        }
        if (ev->u.chain.kind == GZ_CHAIN_TIP_SYNCED) {
            int any = 0;
            chain_event(f, &ev->u.chain);
            for (size_t i = 0; i < GZ_FUND_MAX_FACTORIES; i++)
                if (f->fac[i].used) any = 1;
            return any && !f->tick_armed ? arm_tick(f, out, f->cfg.tick_ms) : GZ_OK;
        }
        chain_event(f, &ev->u.chain);
        return f->tick_armed ? GZ_OK : arm_tick(f, out, f->cfg.tick_ms);
    case GZ_EVENT_USER_COMMAND:
        return command(f, ev->u.user.bytes, out);
    case GZ_EVENT_MESSAGE_RECEIVED:
        /* factory_funded (81): a hint, never relied on (messages.md 7.11). */
        f->dropped++;
        return GZ_OK;
    default:
        return GZ_OK;
    }
}

/* ---- the public calls: the list of the call under way, for UNWATCH ------ */

static gz_status_t done(gz_fund_t *f, gz_status_t st)
{
    gz_status_t u = f->cur_st;
    f->cur_out = NULL;
    f->cur_st = GZ_OK;
    return st != GZ_OK ? st : u;
}

gz_status_t gz_fund_host_apply(gz_fund_t *f, const uint8_t scope[32], gz_action_list_t *out)
{
    if (!f) return GZ_ERR_ARGUMENT;
    f->cur_out = out;
    return done(f, gz_fund_host_apply_in(f, scope, out));
}

gz_status_t gz_fund_host_drop(gz_fund_t *f, const uint8_t scope[32], gz_action_list_t *out)
{
    if (!f) return GZ_ERR_ARGUMENT;
    f->cur_out = out;
    return done(f, gz_fund_host_drop_in(f, scope, out));
}

gz_status_t gz_fund_member_acked(gz_fund_t *f, const gz_fund_acked_in_t *in, gz_action_list_t *out)
{
    if (!f) return GZ_ERR_ARGUMENT;
    f->cur_out = out;
    return done(f, gz_fund_member_acked_in(f, in, out));
}

gz_status_t gz_fund_handle(void *e, const gz_event_t *ev, gz_action_list_t *out)
{
    gz_fund_t *f = (gz_fund_t *)e;
    if (!f) return GZ_ERR_ARGUMENT;
    f->cur_out = out;
    return done(f, gz_fund_handle_in(e, ev, out));
}
