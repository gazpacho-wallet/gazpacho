/* The exit engine, tree half. See gazpacho/exit_engine.h and spec/exit.md 6.8. */
#include "gazpacho/exit_engine.h"
#include "gazpacho/command.h"
#include "gazpacho/envelope.h"
#include <string.h>

#define CLEAR(p) memset((p), 0, sizeof *(p))

/* Record fields (exit.md 6.8; every required type even). */
enum { F_SCOPE = 0 };
enum { PL_ROLE = 2, PL_FUND = 4, PL_E = 6, PL_MEMBER = 8, PL_CONSTS = 10, PL_NODES = 12, PL_STEPS = 14, PL_OWED = 16 };
enum { SR_WHY = 2, SR_TIP = 4 };
enum { SP_INDEX = 2, SP_TXID = 4, SP_STATE = 6, SP_HEIGHT = 8 };
enum { SW_TXID = 2, SW_TX = 4, SW_TIP = 6 };
enum { SD_TXID = 2, SD_HOW = 4, SD_TIP = 6 };
enum { EN_HOW = 2, EN_HEIGHT = 4 };
enum { SE_OUTPOINT = 2, SE_SPENDER = 4, SE_CLASS = 6, SE_HEIGHT = 8 };

/* What a fact is about. */
enum { K_IN = 1, K_CHAN, K_SPARE, K_ANCHOR, K_TX };

static const uint8_t P2A[4] = { 0x51, 0x02, 0x4e, 0x73 };

/* ---- transactions --------------------------------------------------------- */

static int varint(const uint8_t *p, size_t len, size_t *at, uint64_t *v)
{
    if (*at >= len) return 0;
    uint8_t b = p[(*at)++];
    size_t n = b < 0xfd ? 0 : b == 0xfd ? 2 : b == 0xfe ? 4 : 8;
    if (n == 0) { *v = b; return 1; }
    if (n > len - *at) return 0;
    *v = 0;
    for (size_t i = 0; i < n; i++) *v |= (uint64_t)p[*at + i] << (8 * i);
    *at += n;
    return 1;
}

static int skip(size_t len, size_t *at, uint64_t n)
{
    if (n > len - *at) return 0;
    *at += (size_t)n;
    return 1;
}

int gz_xe_strip_witness(const uint8_t *tx, size_t len, uint8_t *out, size_t cap, size_t *out_len, int *had_witness)
{
    size_t at = 6, body;
    uint64_t n_in, n_out, v, items;
    gz_tx_info_t info;
    if (!tx || !out || !out_len || !had_witness || len < 10) return 0;
    if (tx[4] != 0 || tx[5] != 1) {
        if (len > cap || !gz_tx_parse(tx, len, &info)) return 0;
        memcpy(out, tx, len);
        *out_len = len;
        *had_witness = 0;
        return 1;
    }
    if (!varint(tx, len, &at, &n_in) || n_in == 0 || n_in > 100000) return 0;
    for (uint64_t i = 0; i < n_in; i++)
        if (!skip(len, &at, 36) || !varint(tx, len, &at, &v) || !skip(len, &at, v) || !skip(len, &at, 4)) return 0;
    if (!varint(tx, len, &at, &n_out) || n_out > 100000) return 0;
    for (uint64_t i = 0; i < n_out; i++)
        if (!skip(len, &at, 8) || !varint(tx, len, &at, &v) || !skip(len, &at, v)) return 0;
    body = at;
    for (uint64_t i = 0; i < n_in; i++) {
        if (!varint(tx, len, &at, &items)) return 0;
        for (uint64_t k = 0; k < items; k++)
            if (!varint(tx, len, &at, &v) || !skip(len, &at, v)) return 0;
    }
    if (len - at != 4 || body - 6 + 8 > cap) return 0;
    memcpy(out, tx, 4);
    memcpy(out + 4, tx + 6, body - 6);
    memcpy(out + 4 + (body - 6), tx + len - 4, 4);
    *out_len = body - 6 + 8;
    *had_witness = 1;
    return gz_tx_parse(out, *out_len, &info);
}

void gz_xe_anchor_child(const uint8_t txid[32], uint32_t vout, uint8_t out[GZ_XE_CHILD_LEN])
{
    size_t at = 0;
    out[at++] = 3; out[at++] = 0; out[at++] = 0; out[at++] = 0;          /* version 3 */
    out[at++] = 1;
    memcpy(out + at, txid, 32); at += 32;
    for (int i = 0; i < 4; i++) out[at++] = (uint8_t)(vout >> (8 * i));
    out[at++] = 0;                                                       /* empty scriptSig */
    out[at++] = 0xfd; out[at++] = 0xff; out[at++] = 0xff; out[at++] = 0xff;
    out[at++] = 1;
    memset(out + at, 0, 8); at += 8;                                     /* 0 sat */
    out[at++] = 5;
    out[at++] = 0x6a; out[at++] = 0x03; out[at++] = 0; out[at++] = 0; out[at++] = 0;
    memset(out + at, 0, 4);                                              /* lock time 0 */
}

static void op_bytes(const gz_outpoint_t *o, uint8_t b[36])
{
    memcpy(b, o->txid, 32);
    for (int i = 0; i < 4; i++) b[32 + i] = (uint8_t)(o->vout >> (8 * i));
}

static int same_op(const gz_outpoint_t *a, const gz_outpoint_t *b)
{
    return a->vout == b->vout && memcmp(a->txid, b->txid, 32) == 0;
}

/* An unsigned tree transaction: version 3, one input spending `in`, the txid
 * `txid`, `n_out` outputs of which the last is a 240-sat P2A. */
static int check_unsigned(const uint8_t *tx, size_t len, const gz_outpoint_t *in, const uint8_t txid[32], uint8_t n_out)
{
    gz_tx_info_t info;
    const uint8_t *op, *script;
    size_t sl;
    uint32_t seq;
    uint64_t amount;
    uint8_t want[36], got[32];
    if (!gz_tx_parse(tx, len, &info) || info.version != GZ_TREE_TX_VERSION || info.n_in != 1) return 0;
    if (info.n_out != n_out || n_out < 2) return 0;
    if (!gz_tx_input(tx, len, &info, 0, &op, &sl, &seq) || sl != 0) return 0;
    op_bytes(in, want);
    if (memcmp(op, want, 36) != 0) return 0;
    if (!gz_tx_output(tx, len, &info, info.n_out - 1, &amount, &script, &sl)) return 0;
    if (amount != GZ_TREE_ANCHOR_SAT || sl != 4 || memcmp(script, P2A, 4) != 0) return 0;
    gz_tx_txid(tx, len, got);
    return memcmp(got, txid, 32) == 0;
}

static void input_of(const gz_xe_plan_t *p, size_t i, gz_outpoint_t *o)
{
    const gz_xe_node_t *n = &p->node[i];
    if (n->parent == GZ_XE_FUNDING) { *o = p->funding; return; }
    memcpy(o->txid, p->node[n->parent].txid, 32);
    o->vout = n->parent_vout;
}

/* The structure of a plan, and every step's signed bytes against it. */
static int plan_check(const gz_xe_plan_t *p)
{
    uint8_t bare[GZ_XE_MAX_SIGNED];
    gz_outpoint_t in;
    size_t bl;
    int wit;
    if (p->n_nodes == 0 || p->n_nodes > GZ_XE_MAX_NODES || p->n_steps == 0 || p->n_steps > GZ_XE_MAX_STEPS) return 0;
    if (p->c.B == 0) return 0;
    for (size_t i = 0; i < p->n_nodes; i++) {
        const gz_xe_node_t *n = &p->node[i];
        if (n->kind < GZ_NODE_FIXED || n->kind > GZ_NODE_LEAF_STATE) return 0;
        if (n->n_out < 2 || n->n_out > GZ_TREE_MAX_OUTPUTS) return 0;
        if (i == 0) { if (n->parent != GZ_XE_FUNDING) return 0; continue; }
        if (n->parent >= i) return 0;                       /* parents first: no cycle */
        if (n->parent_vout + 1u >= p->node[n->parent].n_out) return 0;   /* never the anchor */
        if (n->kind == GZ_NODE_LEAF_STATE && n->n_out < 3) return 0;
    }
    for (size_t k = 0; k < p->n_steps; k++) {
        const gz_xe_step_t *s = &p->step[k];
        if (s->node >= p->n_nodes || s->len > GZ_XE_MAX_SIGNED) return 0;
        if (k > 0 && p->node[s->node].parent != p->step[k - 1].node) return 0;   /* a path, root first */
        if (k == 0 && s->node != 0) return 0;
        if (!gz_xe_strip_witness(s->tx, s->len, bare, sizeof bare, &bl, &wit) || !wit) return 0;
        input_of(p, s->node, &in);
        if (!check_unsigned(bare, bl, &in, p->node[s->node].txid, p->node[s->node].n_out)) return 0;
    }
    if (!p->host && p->n_steps != p->n_nodes) return 0;
    if (p->host && p->n_steps != 1) return 0;
    return 1;
}

static void derive_children(gz_xe_plan_t *p)
{
    for (size_t k = 0; k < p->n_steps; k++) {
        gz_xe_step_t *s = &p->step[k];
        const gz_xe_node_t *n = &p->node[s->node];
        gz_xe_anchor_child(n->txid, n->n_out - 1u, s->child);
        gz_tx_txid(s->child, GZ_XE_CHILD_LEN, s->child_txid);
    }
}

/* ---- plans ------------------------------------------------------------------ */

static int copy_node(const gz_tree_node_t *s, uint16_t parent, gz_xe_node_t *d)
{
    CLEAR(d);
    if (s->n_out < 2 || s->n_out > GZ_TREE_MAX_OUTPUTS) return 0;
    memcpy(d->txid, s->txid, 32);
    d->parent = parent;
    d->parent_vout = s->parent_vout;
    d->kind = s->kind;
    d->depth = s->depth;
    d->n_out = s->n_out;
    d->first = s->first;
    d->count = s->count;
    d->cltv = s->cltv;
    d->in_amount = s->spent_amount;
    if (s->kind == GZ_NODE_LEAF_STATE) {
        if (s->n_out < 3 || s->out_kind[0] != GZ_OUT_CHANNEL || s->out_kind[1] != GZ_OUT_LSTOCK) return 0;
        d->chan_amount = s->out_amount[0];
        d->spare_amount = s->out_amount[1];
        d->spare_csv = s->lstock_csv;
    }
    return 1;
}

static int make_signed(const gz_tree_node_t *s, const uint8_t sig[64], gz_xe_step_t *d)
{
    size_t ul = s->tx_len, at = 0;
    if (ul < 10 || ul + 68 > GZ_XE_MAX_SIGNED) return 0;
    memcpy(d->tx, s->tx, 4); at = 4;
    d->tx[at++] = 0; d->tx[at++] = 1;
    memcpy(d->tx + at, s->tx + 4, ul - 8); at += ul - 8;
    d->tx[at++] = 1; d->tx[at++] = 64;
    memcpy(d->tx + at, sig, 64); at += 64;
    memcpy(d->tx + at, s->tx + ul - 4, 4); at += 4;
    d->len = (uint16_t)at;
    return 1;
}

static gz_xe_plan_err_t plan_args(const gz_xe_tree_in_t *in, gz_xe_plan_t *out)
{
    const gz_tree_t *t;
    if (!in || !in->tree || !in->sigs || !in->member_keys || !in->verify || !out) return GZ_XE_PLAN_ARGUMENT;
    t = in->tree;
    if (t->n_nodes == 0 || t->n_nodes > GZ_XE_MAX_NODES || t->n_members == 0 || t->n_members > GZ_TREE_MAX_MEMBERS
        || in->n_members != t->n_members || in->c.B == 0)
        return GZ_XE_PLAN_ARGUMENT;
    memset(out, 0, sizeof *out);
    memcpy(out->scope, in->scope, 32);
    memcpy(out->funding.txid, t->node[0].spent_txid, 32);
    out->funding.vout = t->node[0].spent_vout;
    out->end_height = in->end_height;
    out->c = in->c;
    return GZ_XE_PLAN_OK;
}

/* The program's signature check of every publishable step (exit.md 6.8). */
static int steps_verified(const gz_xe_tree_in_t *in, const gz_xe_plan_t *p, const uint16_t *tree_index)
{
    for (size_t k = 0; k < p->n_steps; k++) {
        const gz_tree_node_t *s = &in->tree->node[tree_index[k]];
        if (in->verify(in->verify_ctx, p->step[k].tx, p->step[k].len, s->spent_amount, s->spent_script) != 1) return 0;
    }
    return 1;
}

gz_xe_plan_err_t gz_xe_plan_member(const gz_xe_tree_in_t *in, uint32_t member, const uint8_t own_key[33],
                                   gz_xe_plan_t *out)
{
    uint16_t idx[GZ_XE_MAX_STEPS], order[GZ_XE_MAX_STEPS];
    size_t n = 0;
    gz_xe_plan_err_t e;
    if (!own_key) return GZ_XE_PLAN_ARGUMENT;
    if ((e = plan_args(in, out)) != GZ_XE_PLAN_OK) return e;
    if (in->has_channel || in->balance_sat) return GZ_XE_PLAN_NOT_TREE_HALF;
    const gz_tree_t *t = in->tree;
    if (member >= t->n_members || memcmp(in->member_keys[member], own_key, 33) != 0) return GZ_XE_PLAN_NOT_OURS;
    uint16_t leaf = t->leaf_state[member];
    if (leaf >= t->n_nodes) return GZ_XE_PLAN_BAD_TREE;
    const gz_tree_node_t *L = &t->node[leaf];
    if (L->kind != GZ_NODE_LEAF_STATE || L->count != 1 || L->first != member) return GZ_XE_PLAN_NOT_OURS;
    for (int cur = leaf;;) {
        if (n == GZ_XE_MAX_STEPS) return GZ_XE_PLAN_BAD_TREE;
        idx[n++] = (uint16_t)cur;
        int par = t->node[cur].parent;
        if (par < 0) break;
        if (par >= cur) return GZ_XE_PLAN_BAD_TREE;
        cur = par;
    }
    if (idx[n - 1] != 0) return GZ_XE_PLAN_BAD_TREE;
    out->member = member;
    out->n_nodes = (uint16_t)n;
    out->n_steps = (uint16_t)n;
    for (size_t k = 0; k < n; k++) {
        const gz_tree_node_t *s = &t->node[idx[n - 1 - k]];
        order[k] = idx[n - 1 - k];
        if (!copy_node(s, k == 0 ? GZ_XE_FUNDING : (uint16_t)(k - 1), &out->node[k])) return GZ_XE_PLAN_BAD_TREE;
        out->step[k].node = (uint16_t)k;
        if (!make_signed(s, in->sigs[idx[n - 1 - k]], &out->step[k])) return GZ_XE_PLAN_BAD_TREE;
    }
    if (!plan_check(out)) return GZ_XE_PLAN_BAD_TREE;
    if (!steps_verified(in, out, order)) return GZ_XE_PLAN_BAD_SIGNATURE;
    derive_children(out);
    return GZ_XE_PLAN_OK;
}

gz_xe_plan_err_t gz_xe_plan_host(const gz_xe_tree_in_t *in, const uint8_t *owed, gz_xe_plan_t *out)
{
    uint16_t root[1];
    gz_xe_plan_err_t e;
    gz_outpoint_t inp;
    root[0] = 0;
    if ((e = plan_args(in, out)) != GZ_XE_PLAN_OK) return e;
    const gz_tree_t *t = in->tree;
    out->host = 1;
    out->n_nodes = t->n_nodes;
    for (size_t i = 0; i < t->n_nodes; i++) {
        const gz_tree_node_t *s = &t->node[i];
        uint16_t parent;
        if (i == 0) { if (s->parent >= 0) return GZ_XE_PLAN_BAD_TREE; parent = GZ_XE_FUNDING; }
        else { if (s->parent < 0 || (size_t)s->parent >= i) return GZ_XE_PLAN_BAD_TREE; parent = (uint16_t)s->parent; }
        if (!copy_node(s, parent, &out->node[i])) return GZ_XE_PLAN_BAD_TREE;
        input_of(out, i, &inp);
        if (!check_unsigned(s->tx, s->tx_len, &inp, s->txid, s->n_out)) return GZ_XE_PLAN_BAD_TREE;
    }
    out->n_steps = 1;
    out->step[0].node = 0;
    if (!make_signed(&t->node[0], in->sigs[0], &out->step[0])) return GZ_XE_PLAN_BAD_TREE;
    if (owed)
        for (size_t m = 0; m < t->n_members; m++)
            if (owed[m / 8] & (1u << (m % 8))) out->owed[m / 8] |= (uint8_t)(1u << (m % 8));
    if (!plan_check(out)) return GZ_XE_PLAN_BAD_TREE;
    if (!steps_verified(in, out, root)) return GZ_XE_PLAN_BAD_SIGNATURE;
    derive_children(out);
    return GZ_XE_PLAN_OK;
}

/* ---- actions ---------------------------------------------------------------- */

static gz_status_t add(gz_action_list_t *out, const gz_action_t *a)
{
    return gz_action_list_add(out, a);
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

static gz_status_t save(gz_action_list_t *out, const gz_record_t *recs, size_t n)
{
    gz_action_t a;
    CLEAR(&a);
    a.kind = GZ_ACTION_SAVE;
    a.u.save.records = recs;
    a.u.save.n_records = n;
    return add(out, &a);
}

static void hex8(const uint8_t *p, char *s)
{
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) { s[2 * i] = h[p[i] >> 4]; s[2 * i + 1] = h[p[i] & 15]; }
}

/* A log notice: "<what> scope=<16 hex>". */
static gz_status_t log_note(const gz_xe_t *x, gz_action_list_t *out, const char *what)
{
    char text[96];
    uint8_t buf[128];
    size_t n = 0, at = 0;
    gz_action_t a;
    gz_status_t st;
    while (what[n] && n < 60) n++;
    memcpy(text, what, n);
    memcpy(text + n, " scope=", 7);
    hex8(x->scope, text + n + 7);
    if ((st = gz_rec_put(buf, sizeof buf, &at, 0, (const uint8_t *)text, n + 7 + 16)) != GZ_OK) return st;
    CLEAR(&a);
    a.kind = GZ_ACTION_NOTIFY;
    a.u.notify.code = GZ_NOTIFY_LOG;
    a.u.notify.bytes.data = buf;
    a.u.notify.bytes.len = at;
    return add(out, &a);
}

/* ---- facts and watches -------------------------------------------------------- */

static gz_xe_fact_t *fact_of(gz_xe_t *x, int kind, size_t i)
{
    switch (kind) {
    case K_IN: return &x->in[i];
    case K_CHAN: return &x->chan[i];
    case K_SPARE: return &x->spare[i];
    case K_TX: return &x->txw[i];
    default: return &x->anchor[i];
    }
}

static void outpoint_of(const gz_xe_t *x, int kind, size_t i, gz_outpoint_t *o)
{
    const gz_xe_plan_t *p = &x->plan;
    if (kind == K_IN) { input_of(p, i, o); return; }
    if (kind == K_ANCHOR) {
        const gz_xe_node_t *n = &p->node[p->step[i].node];
        memcpy(o->txid, n->txid, 32);
        o->vout = n->n_out - 1u;
        return;
    }
    memcpy(o->txid, p->node[i].txid, 32);
    o->vout = kind == K_SPARE ? 1 : 0;            /* K_TX: the txid alone */
}

/* The outpoint watch of `o`, or NULL. */
static gz_xe_fact_t *find_fact(gz_xe_t *x, const gz_outpoint_t *o, int *kind, size_t *idx)
{
    const gz_xe_plan_t *p = &x->plan;
    gz_outpoint_t c;
    for (size_t i = 0; i < p->n_nodes; i++) {
        input_of(p, i, &c);
        if (same_op(&c, o)) { *kind = K_IN; *idx = i; return &x->in[i]; }
        if (p->node[i].kind == GZ_NODE_LEAF_STATE && memcmp(p->node[i].txid, o->txid, 32) == 0) {
            if (o->vout == 0) { *kind = K_CHAN; *idx = i; return &x->chan[i]; }
            if (o->vout == 1) { *kind = K_SPARE; *idx = i; return &x->spare[i]; }
        }
    }
    for (size_t k = 0; k < p->n_steps; k++) {
        outpoint_of(x, K_ANCHOR, k, &c);
        if (same_op(&c, o)) { *kind = K_ANCHOR; *idx = k; return &x->anchor[k]; }
    }
    return NULL;
}

/* The txid watch of `txid`, or NULL. */
static gz_xe_fact_t *find_txw(gz_xe_t *x, const uint8_t txid[32])
{
    for (size_t i = 0; i < x->plan.n_nodes; i++)
        if (memcmp(x->plan.node[i].txid, txid, 32) == 0) return &x->txw[i];
    return NULL;
}

/* Set a watch (again, when `again`): its facts start afresh. */
static gz_status_t set_watch(gz_xe_t *x, int kind, size_t i, int again, gz_action_list_t *out)
{
    gz_xe_fact_t *f = fact_of(x, kind, i);
    gz_action_t a;
    gz_status_t st;
    if (f->watched && !again) return GZ_OK;
    CLEAR(&a);
    if (kind == K_TX) {
        a.kind = GZ_ACTION_WATCH_TX;
        memcpy(a.u.watch_tx.txid, x->plan.node[i].txid, 32);
        a.u.watch_tx.depth = x->plan.c.B;
    } else {
        a.kind = GZ_ACTION_WATCH_OUTPOINT;
        outpoint_of(x, kind, i, &a.u.watch_outpoint.outpoint);
        a.u.watch_outpoint.depth = x->plan.c.B;
    }
    if ((st = add(out, &a)) != GZ_OK) return st;
    if (!f->watched) x->n_watches++;
    if (!f->watched || f->synced) x->n_unsynced++;
    f->watched = 1;
    f->synced = 0;
    f->known = 0;
    f->failed = 0;
    f->zero_known = 0;
    f->conf = 0;
    f->height = 0;
    return GZ_OK;
}

static gz_status_t watch(gz_xe_t *x, int kind, size_t i, gz_action_list_t *out)
{
    return set_watch(x, kind, i, 0, out);
}

static gz_status_t unwatch(gz_xe_t *x, int kind, size_t i, gz_action_list_t *out)
{
    gz_xe_fact_t *f = fact_of(x, kind, i);
    gz_action_t a;
    gz_status_t st;
    if (!f->watched) return GZ_OK;
    CLEAR(&a);
    a.kind = GZ_ACTION_UNWATCH;
    a.u.unwatch.is_tx = kind == K_TX;
    outpoint_of(x, kind, i, &a.u.unwatch.what);
    if ((st = add(out, &a)) != GZ_OK) return st;
    if (!f->synced) x->n_unsynced--;
    f->watched = 0;
    x->n_watches--;
    return GZ_OK;
}

/* Confirmations now: counted from the block when known, since a watch
 * reports counts only up to its depth. */
static uint32_t confs(const gz_xe_t *x, const gz_xe_fact_t *f)
{
    if (!f->known || f->conf == 0) return 0;
    if (f->height && x->tip_known && x->tip >= f->height) {
        uint32_t c = x->tip - f->height + 1;
        return c > f->conf ? c : f->conf;
    }
    return f->conf;
}

/* Node i's own transaction is on chain: its confirmations, else 0. When its
 * input's watch failed (spent deeper than the view follows), its txid
 * watch answers: a confirmation, or a failure (deeper still). */
static uint32_t node_conf(const gz_xe_t *x, size_t i)
{
    const gz_xe_fact_t *f = &x->in[i], *t = &x->txw[i];
    if (f->known && memcmp(f->spender, x->plan.node[i].txid, 32) == 0) return confs(x, f);
    if (f->failed && t->watched && t->synced) {
        if (t->failed) return GZ_XE_DEEP;
        return confs(x, t);
    }
    return 0;
}

/* ---- records ------------------------------------------------------------------ */

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

/* A record header written in place, its value to follow at e->at. */
static uint8_t *put_hdr(enc_t *e, uint64_t type, size_t len)
{
    uint8_t h[18];
    size_t n;
    if (e->st != GZ_OK) return NULL;
    n = gz_bigsize_put(type, h);
    n += gz_bigsize_put(len, h + n);
    if (n > e->cap - e->at || len > e->cap - e->at - n) { e->st = GZ_ERR_NO_SPACE; return NULL; }
    memcpy(e->buf + e->at, h, n);
    e->at += n;
    uint8_t *v = e->buf + e->at;
    e->at += len;
    return v;
}

static void put_outpoint(enc_t *e, uint64_t type, const gz_outpoint_t *o)
{
    uint8_t b[36];
    memcpy(b, o->txid, 32);
    gz_put_u32(b + 32, o->vout);
    put(e, type, b, 36);
}

static void get_outpoint(const uint8_t b[36], gz_outpoint_t *o)
{
    memcpy(o->txid, b, 32);
    o->vout = gz_get_u32(b + 32);
}

static size_t enc_plan(const gz_xe_plan_t *p, uint8_t *buf, size_t cap, gz_status_t *st)
{
    enc_t e = { buf, cap, 0, GZ_OK };
    uint8_t c[16], *v;
    size_t steps = 0;
    put(&e, F_SCOPE, p->scope, 32);
    put_u8(&e, PL_ROLE, (uint8_t)(p->host ? 1 : 0));
    put_outpoint(&e, PL_FUND, &p->funding);
    put_u32(&e, PL_E, p->end_height);
    put_u32(&e, PL_MEMBER, p->member);
    gz_put_u32(c, p->c.A); gz_put_u32(c + 4, p->c.B); gz_put_u32(c + 8, p->c.M); gz_put_u32(c + 12, p->c.M_host);
    put(&e, PL_CONSTS, c, 16);
    if ((v = put_hdr(&e, PL_NODES, (size_t)p->n_nodes * GZ_XE_NODE_ENC)) != NULL) {
        for (size_t i = 0; i < p->n_nodes; i++, v += GZ_XE_NODE_ENC) {
            const gz_xe_node_t *n = &p->node[i];
            memcpy(v, n->txid, 32);
            gz_put_u16(v + 32, n->parent);
            v[34] = n->parent_vout; v[35] = n->kind; v[36] = n->depth; v[37] = n->n_out;
            gz_put_u16(v + 38, n->first);
            gz_put_u16(v + 40, n->count);
            gz_put_u32(v + 42, n->cltv);
            gz_put_u64(v + 46, n->in_amount);
            gz_put_u64(v + 54, n->chan_amount);
            gz_put_u64(v + 62, n->spare_amount);
            gz_put_u32(v + 70, n->spare_csv);
        }
    }
    for (size_t k = 0; k < p->n_steps; k++) steps += 4u + p->step[k].len;
    if ((v = put_hdr(&e, PL_STEPS, steps)) != NULL) {
        for (size_t k = 0; k < p->n_steps; k++) {
            gz_put_u16(v, p->step[k].node);
            gz_put_u16(v + 2, p->step[k].len);
            memcpy(v + 4, p->step[k].tx, p->step[k].len);
            v += 4u + p->step[k].len;
        }
    }
    if (p->host) put(&e, PL_OWED, p->owed, sizeof p->owed);
    *st = e.st;
    return e.at;
}

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

static int field(gz_bytes_t s, uint64_t type, size_t len, gz_bytes_t *v)
{
    if (gz_rec_find(s, type, v) != 1) return 0;
    return len == 0 || v->len == len;
}

static int dec_plan(gz_bytes_t s, gz_xe_plan_t *p)
{
    static const uint8_t allowed[] = { F_SCOPE, PL_ROLE, PL_FUND, PL_E, PL_MEMBER, PL_CONSTS, PL_NODES, PL_STEPS, PL_OWED };
    gz_bytes_t v;
    int r;
    if (!fields_ok(s, allowed, sizeof allowed)) return 0;
    memset(p, 0, sizeof *p);
    if (!field(s, F_SCOPE, 32, &v)) return 0;
    memcpy(p->scope, v.data, 32);
    if (!field(s, PL_ROLE, 1, &v) || v.data[0] > 1) return 0;
    p->host = v.data[0];
    if (!field(s, PL_FUND, 36, &v)) return 0;
    get_outpoint(v.data, &p->funding);
    if (!field(s, PL_E, 4, &v)) return 0;
    p->end_height = gz_get_u32(v.data);
    if (!field(s, PL_MEMBER, 4, &v)) return 0;
    p->member = gz_get_u32(v.data);
    if (!field(s, PL_CONSTS, 16, &v)) return 0;
    p->c.A = gz_get_u32(v.data); p->c.B = gz_get_u32(v.data + 4);
    p->c.M = gz_get_u32(v.data + 8); p->c.M_host = gz_get_u32(v.data + 12);
    if (!field(s, PL_NODES, 0, &v) || v.len == 0 || v.len % GZ_XE_NODE_ENC != 0
        || v.len / GZ_XE_NODE_ENC > GZ_XE_MAX_NODES)
        return 0;
    p->n_nodes = (uint16_t)(v.len / GZ_XE_NODE_ENC);
    for (size_t i = 0; i < p->n_nodes; i++) {
        const uint8_t *b = v.data + i * GZ_XE_NODE_ENC;
        gz_xe_node_t *n = &p->node[i];
        memcpy(n->txid, b, 32);
        n->parent = gz_get_u16(b + 32);
        n->parent_vout = b[34]; n->kind = b[35]; n->depth = b[36]; n->n_out = b[37];
        n->first = gz_get_u16(b + 38);
        n->count = gz_get_u16(b + 40);
        n->cltv = gz_get_u32(b + 42);
        n->in_amount = gz_get_u64(b + 46);
        n->chan_amount = gz_get_u64(b + 54);
        n->spare_amount = gz_get_u64(b + 62);
        n->spare_csv = gz_get_u32(b + 70);
    }
    if (!field(s, PL_STEPS, 0, &v)) return 0;
    for (size_t at = 0; at < v.len;) {
        if (p->n_steps == GZ_XE_MAX_STEPS || v.len - at < 4) return 0;
        gz_xe_step_t *st = &p->step[p->n_steps++];
        st->node = gz_get_u16(v.data + at);
        st->len = gz_get_u16(v.data + at + 2);
        at += 4;
        if (st->len > GZ_XE_MAX_SIGNED || st->len > v.len - at) return 0;
        memcpy(st->tx, v.data + at, st->len);
        at += st->len;
    }
    /* The owed list: required for the host, absent for a member (6.8). */
    if ((r = gz_rec_find(s, PL_OWED, &v)) < 0) return 0;
    if (p->host) {
        if (r != 1 || v.len != sizeof p->owed) return 0;
        memcpy(p->owed, v.data, sizeof p->owed);
    } else if (r == 1) {
        return 0;
    }
    return plan_check(p);
}

static gz_status_t save_step(gz_xe_t *x, size_t i, uint8_t state, uint32_t height, gz_action_list_t *out)
{
    uint8_t buf[128];
    enc_t e = { buf, sizeof buf, 0, GZ_OK };
    gz_record_t r;
    put(&e, F_SCOPE, x->scope, 32);
    put_u16(&e, SP_INDEX, (uint16_t)i);
    put(&e, SP_TXID, x->plan.node[x->plan.step[i].node].txid, 32);
    put_u8(&e, SP_STATE, state);
    put_u32(&e, SP_HEIGHT, height);
    if (e.st != GZ_OK) return e.st;
    r.type = GZ_XE_REC_STEP;
    r.bytes.data = buf;
    r.bytes.len = e.at;
    x->st[i].state = state;
    return save(out, &r, 1);
}

static gz_status_t save_seen(gz_xe_t *x, const gz_outpoint_t *o, const gz_xe_fact_t *f, uint8_t cls, gz_action_list_t *out)
{
    uint8_t buf[160];
    enc_t e = { buf, sizeof buf, 0, GZ_OK };
    gz_record_t r;
    put(&e, F_SCOPE, x->scope, 32);
    put_outpoint(&e, SE_OUTPOINT, o);
    put(&e, SE_SPENDER, f->spender, 32);
    put_u8(&e, SE_CLASS, cls);
    put_u32(&e, SE_HEIGHT, f->height);
    if (e.st != GZ_OK) return e.st;
    r.type = GZ_XE_REC_SEEN;
    r.bytes.data = buf;
    r.bytes.len = e.at;
    return save(out, &r, 1);
}

/* ---- the engine --------------------------------------------------------------- */

gz_status_t gz_xe_init(gz_xe_t *x, const uint8_t scope[32], const gz_xe_port_t *port)
{
    if (!x || !scope) return GZ_ERR_ARGUMENT;
    memset(x, 0, sizeof *x);
    memcpy(x->scope, scope, 32);
    if (port) x->port = *port;
    return GZ_OK;
}

static gz_xe_sweep_t *live_sweep(gz_xe_t *x, const uint8_t txid[32])
{
    for (size_t k = 0; k < GZ_XE_MAX_SWEEPS; k++)
        if (x->sweep[k].used && memcmp(x->sweep[k].txid, txid, 32) == 0) return &x->sweep[k];
    return NULL;
}

/* exit.md 8, without the spender's bytes (6.8, "Classes"). A spend is
 * classified at its first confirmation, while the sweep it may be is live. */
static uint8_t classify(gz_xe_t *x, int kind, size_t i, const gz_xe_fact_t *f)
{
    const gz_xe_plan_t *p = &x->plan;
    switch (kind) {
    case K_IN: {
        const gz_xe_node_t *n = &p->node[i];
        if (memcmp(f->spender, n->txid, 32) == 0) return GZ_XE_S1;
        if (p->host) return live_sweep(x, f->spender) ? GZ_XE_S2 : GZ_XE_S8;
        return n->cltv != 0 && f->height > n->cltv ? GZ_XE_S2 : GZ_XE_S8;
    }
    case K_CHAN:
        return p->host && live_sweep(x, f->spender) ? GZ_XE_S2 : GZ_XE_S8;
    case K_SPARE:
        return p->host && live_sweep(x, f->spender) ? GZ_XE_S3 : GZ_XE_S8;
    default:
        return memcmp(f->spender, p->step[i].child_txid, 32) == 0 ? GZ_XE_S9A : GZ_XE_S9B;
    }
}

/* Save spend_seen for every confirmed spend not yet recorded. */
static gz_status_t classify_all(gz_xe_t *x, gz_action_list_t *out)
{
    static const int kinds[] = { K_IN, K_CHAN, K_SPARE, K_ANCHOR };
    gz_status_t st;
    gz_outpoint_t o;
    for (size_t k = 0; k < 4; k++) {
        size_t n = kinds[k] == K_ANCHOR ? x->plan.n_steps : x->plan.n_nodes;
        for (size_t i = 0; i < n; i++) {
            gz_xe_fact_t *f = fact_of(x, kinds[k], i);
            if (!f->watched || !f->known || f->conf == 0) continue;
            if (f->recorded && memcmp(f->rec_spender, f->spender, 32) == 0) continue;
            outpoint_of(x, kinds[k], i, &o);
            if ((st = save_seen(x, &o, f, classify(x, kinds[k], i, f), out)) != GZ_OK) return st;
            f->recorded = 1;
            memcpy(f->rec_spender, f->spender, 32);
        }
    }
    return GZ_OK;
}

/* One exit_watch_failed notice per failed watch. */
static gz_status_t note_failed(gz_xe_t *x, gz_xe_fact_t *f, gz_action_list_t *out)
{
    if (f->noted) return GZ_OK;
    f->noted = 1;
    return log_note(x, out, "exit_watch_failed");
}

static gz_status_t end_exit(gz_xe_t *x, uint8_t how, gz_action_list_t *out)
{
    uint8_t buf[96];
    enc_t e = { buf, sizeof buf, 0, GZ_OK };
    gz_record_t r;
    gz_status_t st;
    const char *note;
    put(&e, F_SCOPE, x->scope, 32);
    put_u8(&e, EN_HOW, how);
    put_u32(&e, EN_HEIGHT, x->tip);
    if (e.st != GZ_OK) return e.st;
    r.type = GZ_XE_REC_ENDED;
    r.bytes.data = buf;
    r.bytes.len = e.at;
    if ((st = save(out, &r, 1)) != GZ_OK) return st;
    x->ended = 1;
    x->ended_how = how;
    for (size_t i = 0; i < x->plan.n_nodes; i++) {
        if ((st = unwatch(x, K_IN, i, out)) != GZ_OK || (st = unwatch(x, K_CHAN, i, out)) != GZ_OK
            || (st = unwatch(x, K_SPARE, i, out)) != GZ_OK || (st = unwatch(x, K_TX, i, out)) != GZ_OK)
            return st;
    }
    for (size_t k = 0; k < x->plan.n_steps; k++)
        if ((st = unwatch(x, K_ANCHOR, k, out)) != GZ_OK) return st;
    note = how == GZ_XE_END_UNEXPLAINED ? "unexplained_spend at_risk exit_ended"
         : how == GZ_XE_END_FUNDING_SPENT ? "funding_spent_elsewhere exit_ended" : "exit_ended";
    return log_note(x, out, note);
}

static gz_status_t send_step(gz_xe_t *x, size_t i, gz_action_list_t *out)
{
    const gz_xe_step_t *s = &x->plan.step[i];
    gz_status_t st;
    if ((st = broadcast(out, s->tx, s->len)) != GZ_OK) return st;
    if ((st = broadcast(out, s->child, GZ_XE_CHILD_LEN)) != GZ_OK) return st;
    x->st[i].last_bcast = x->tip;
    x->st[i].bcast_known = 1;
    return GZ_OK;
}

/* A step's own transaction reported with 0 confirmations after a
 * confirmation: a reorganisation, the only way back to missing. */
static int own_reorged(const gz_xe_t *x, size_t node)
{
    const gz_xe_fact_t *f = &x->in[node], *t = &x->txw[node];
    if (f->known && f->conf == 0 && memcmp(f->spender, x->plan.node[node].txid, 32) == 0) return 1;
    return f->failed && t->watched && t->known && t->conf == 0;
}

/* Bring step i's journaled state up to the chain's. */
static gz_status_t step_records(gz_xe_t *x, size_t i, gz_action_list_t *out)
{
    size_t node = x->plan.step[i].node;
    uint32_t c = node_conf(x, node), B = x->plan.c.B;
    gz_status_t st;
    uint8_t now = x->st[i].state;
    if (c >= B && now < GZ_XE_ST_BURIED) {
        if ((st = save_step(x, i, GZ_XE_ST_BURIED, x->in[node].height, out)) != GZ_OK) return st;
        return unwatch(x, K_ANCHOR, i, out);
    }
    if (c >= 1 && c < B && now < GZ_XE_ST_CONFIRMED)
        return save_step(x, i, GZ_XE_ST_CONFIRMED, x->in[node].height, out);
    if (c == 0 && now >= GZ_XE_ST_CONFIRMED && own_reorged(x, node)) {   /* never on absence alone */
        if ((st = save_step(x, i, GZ_XE_ST_SENT, x->tip, out)) != GZ_OK) return st;
        x->st[i].bcast_known = 0;
        return watch(x, K_ANCHOR, i, out);
    }
    return GZ_OK;
}

/* Step i is due: send it, or send it again at a new tip. */
static gz_status_t step_due(gz_xe_t *x, size_t i, gz_action_list_t *out)
{
    gz_status_t st;
    if (x->st[i].state == 0) {
        if ((st = save_step(x, i, GZ_XE_ST_SENT, x->tip, out)) != GZ_OK) return st;
        return send_step(x, i, out);
    }
    if (!x->st[i].bcast_known || x->st[i].last_bcast != x->tip) return send_step(x, i, out);
    return GZ_OK;
}

/* The input of a node's watch failed: learn from its txid. *wait is 1
 * while the txid watch is being set. */
static gz_status_t failed_input(gz_xe_t *x, size_t node, int *wait, gz_action_list_t *out)
{
    gz_xe_fact_t *f = &x->in[node], *t = &x->txw[node];
    gz_status_t st;
    *wait = 1;
    if ((st = note_failed(x, f, out)) != GZ_OK) return st;
    if (!t->watched) return watch(x, K_TX, node, out);
    *wait = 0;                                     /* synced (decide waits for every watch) */
    return GZ_OK;
}

static gz_status_t decide_member(gz_xe_t *x, gz_action_list_t *out)
{
    const gz_xe_plan_t *p = &x->plan;
    gz_status_t st;
    size_t i;
    int wait;
    for (i = 0; i < p->n_steps; i++)
        if ((st = step_records(x, i, out)) != GZ_OK) return st;
    for (i = 0; i < p->n_steps; i++)
        if (node_conf(x, p->step[i].node) == 0) break;
    if (i == p->n_steps) {
        if (x->st[i - 1].state == GZ_XE_ST_BURIED) return end_exit(x, GZ_XE_END_TREE_PATH_DONE, out);
        return GZ_OK;
    }
    {
        size_t node = p->step[i].node;
        const gz_xe_fact_t *f = &x->in[node];
        if (f->failed) {                           /* spent long ago: never sent */
            if ((st = failed_input(x, node, &wait, out)) != GZ_OK || wait) return st;
            /* Its txid is not on chain: something else spent it, long ago (S8). */
            return end_exit(x, GZ_XE_END_UNEXPLAINED, out);
        }
        if (f->known && f->conf >= 1 && memcmp(f->spender, p->node[node].txid, 32) != 0) {
            /* Taken by something else: the end only once it is buried (6.8). */
            if (confs(x, f) >= p->c.B) {
                uint8_t cls = classify(x, K_IN, node, f);
                return end_exit(x, cls == GZ_XE_S2 ? GZ_XE_END_HOST_TIMEOUT : GZ_XE_END_UNEXPLAINED, out);
            }
        }
    }
    if ((st = step_due(x, i, out)) != GZ_OK) return st;
    {
        uint32_t d = (uint32_t)p->n_steps - 2u;
        int64_t due = gz_exit_step_due((int64_t)p->end_height, d, (uint32_t)i, d + 3u, &p->c);
        if ((int64_t)x->tip > due && !x->st[i].late) {
            x->st[i].late = 1;
            return log_note(x, out, "exit_step_late");
        }
    }
    return GZ_OK;
}

static int owed_below(const gz_xe_plan_t *p, uint32_t first, uint32_t count)
{
    for (uint32_t m = first; m < first + count && m < GZ_TREE_MAX_MEMBERS; m++)
        if (p->owed[m / 8] & (1u << (m % 8))) return 1;
    return 0;
}

static int in_sweep(const gz_xe_t *x, const gz_outpoint_t *o)
{
    for (size_t k = 0; k < GZ_XE_MAX_SWEEPS; k++) {
        const gz_xe_sweep_t *s = &x->sweep[k];
        if (!s->used) continue;
        for (size_t j = 0; j < s->n_in; j++)
            if (same_op(&s->in[j], o)) return 1;
    }
    return 0;
}

/* Free of any spender that counts: unspent, or spent only in a mempool by
 * something that is neither the output's own tree transaction nor a live
 * sweep of ours. A failed watch is spent (6.8). */
static int sweepable(gz_xe_t *x, const gz_xe_fact_t *f, const uint8_t *own_txid)
{
    if (!f->watched || !f->synced || f->failed) return 0;
    if (!f->known) return 1;
    if (f->conf != 0) return 0;
    if (own_txid && memcmp(f->spender, own_txid, 32) == 0) return 0;
    return live_sweep(x, f->spender) == NULL;
}

/* Every input of a segwit transaction carries a witness of at least one item. */
static int all_witnessed(const uint8_t *tx, size_t len)
{
    size_t at = 6;
    uint64_t n_in, n_out, v, items;
    if (len < 10 || tx[4] != 0 || tx[5] != 1) return 0;
    if (!varint(tx, len, &at, &n_in)) return 0;
    for (uint64_t i = 0; i < n_in; i++)
        if (!skip(len, &at, 36) || !varint(tx, len, &at, &v) || !skip(len, &at, v) || !skip(len, &at, 4)) return 0;
    if (!varint(tx, len, &at, &n_out)) return 0;
    for (uint64_t i = 0; i < n_out; i++)
        if (!skip(len, &at, 8) || !varint(tx, len, &at, &v) || !skip(len, &at, v)) return 0;
    for (uint64_t i = 0; i < n_in; i++) {
        if (!varint(tx, len, &at, &items) || items == 0) return 0;
        for (uint64_t k = 0; k < items; k++)
            if (!varint(tx, len, &at, &v) || !skip(len, &at, v)) return 0;
    }
    return len - at == 4;
}

/* Read a sweep's inputs; check them against `want` when given (6.8). */
static int sweep_parse(const uint8_t *tx, size_t len, uint8_t *work, size_t cap, gz_xe_sweep_t *s,
                       const gz_xe_sweep_in_t *want, size_t n_want, uint32_t locktime)
{
    size_t bl, sl;
    int wit;
    gz_tx_info_t info;
    const uint8_t *op;
    uint32_t seq;
    uint8_t b[36];
    if (len > GZ_XE_MAX_SWEEP || !gz_xe_strip_witness(tx, len, work, cap, &bl, &wit) || !wit) return 0;
    if (!all_witnessed(tx, len)) return 0;
    if (!gz_tx_parse(work, bl, &info) || info.n_in == 0 || info.n_in > GZ_XE_MAX_SWEEP_IN) return 0;
    if (want && (info.n_in != n_want || info.locktime != locktime || info.version < 2)) return 0;
    for (size_t k = 0; k < info.n_in; k++) {
        if (!gz_tx_input(work, bl, &info, k, &op, &sl, &seq)) return 0;
        s->in[k].vout = (uint32_t)op[32] | (uint32_t)op[33] << 8 | (uint32_t)op[34] << 16 | (uint32_t)op[35] << 24;
        memcpy(s->in[k].txid, op, 32);
        if (want) {
            op_bytes(&want[k].outpoint, b);
            if (memcmp(op, b, 36) != 0 || sl != 0) return 0;
            if (want[k].csv ? seq != want[k].csv : seq == 0xffffffffu) return 0;
        }
    }
    s->n_in = (uint16_t)info.n_in;
    gz_tx_txid(work, bl, s->txid);
    memcpy(s->tx, tx, len);
    s->len = (uint16_t)len;
    return 1;
}

static gz_xe_sweep_t *sweep_slot(gz_xe_t *x)
{
    for (size_t k = 0; k < GZ_XE_MAX_SWEEPS; k++)
        if (!x->sweep[k].used) return &x->sweep[k];
    return NULL;
}

/* A sweep settled, dead or retired: saved, then its slot and inputs free. */
static gz_status_t sweep_done(gz_xe_t *x, gz_xe_sweep_t *s, uint8_t how, gz_action_list_t *out)
{
    uint8_t buf[96];
    enc_t e = { buf, sizeof buf, 0, GZ_OK };
    gz_record_t r;
    gz_status_t st;
    put(&e, F_SCOPE, x->scope, 32);
    put(&e, SD_TXID, s->txid, 32);
    put_u8(&e, SD_HOW, how);
    put_u32(&e, SD_TIP, x->tip);
    if (e.st != GZ_OK) return e.st;
    r.type = GZ_XE_REC_SWEEP_DONE;
    r.bytes.data = buf;
    r.bytes.len = e.at;
    if ((st = save(out, &r, 1)) != GZ_OK) return st;
    memset(s, 0, sizeof *s);
    if (how == GZ_XE_SWEEP_DEAD) return log_note(x, out, "host_sweep_dead");
    if (how == GZ_XE_SWEEP_RETIRED) return log_note(x, out, "host_sweep_retired");
    return GZ_OK;
}

static gz_status_t new_sweep(gz_xe_t *x, gz_xe_sweep_t *s, const gz_xe_sweep_in_t *c, size_t n, gz_action_list_t *out)
{
    uint32_t lock = 0;
    size_t len = 0;
    gz_status_t st;
    enc_t e = { x->rec, sizeof x->rec, 0, GZ_OK };
    gz_record_t r;
    x->port_tip = x->tip;                          /* once per tip (6.8) */
    x->port_tip_known = 1;
    if (!x->port.sweep) return GZ_OK;
    for (size_t k = 0; k < n; k++)
        if (c[k].lock > lock) lock = c[k].lock;
    memset(s, 0, sizeof *s);
    if (!x->port.sweep(x->port.ctx, x->scope, c, n, lock, x->work, sizeof x->work, &len) || len > sizeof x->work) {
        x->port_refused++;
        return GZ_OK;
    }
    if (!sweep_parse(x->work, len, x->work2, sizeof x->work2, s, c, n, lock)) {
        memset(s, 0, sizeof *s);
        x->port_refused++;
        return GZ_OK;
    }
    put(&e, F_SCOPE, x->scope, 32);
    put(&e, SW_TXID, s->txid, 32);
    put(&e, SW_TX, s->tx, s->len);
    put_u32(&e, SW_TIP, x->tip);
    if (e.st != GZ_OK) return e.st;
    r.type = GZ_XE_REC_SWEEP;
    r.bytes.data = x->rec;
    r.bytes.len = e.at;
    if ((st = save(out, &r, 1)) != GZ_OK) return st;
    s->used = 1;
    s->born_tip = x->tip;
    if ((st = broadcast(out, s->tx, s->len)) != GZ_OK) return st;
    s->last_bcast = x->tip;
    s->bcast_known = 1;
    return GZ_OK;
}

/* Every live sweep: settled, dead, retired, or sent again at a new tip. */
static gz_status_t tend_sweeps(gz_xe_t *x, gz_action_list_t *out)
{
    uint32_t B = x->plan.c.B;
    gz_status_t st;
    int kind;
    size_t idx;
    for (size_t k = 0; k < GZ_XE_MAX_SWEEPS; k++) {
        gz_xe_sweep_t *s = &x->sweep[k];
        int dead = 0, settled = 1;
        if (!s->used) continue;
        for (size_t j = 0; j < s->n_in; j++) {
            const gz_xe_fact_t *f = find_fact(x, &s->in[j], &kind, &idx);
            int ours = f && f->known && memcmp(f->spender, s->txid, 32) == 0;
            if (ours) s->sighted = 1;
            if (!f || f->failed || (f->known && !ours && confs(x, f) >= B)) dead = 1;
            if (!(ours && confs(x, f) >= B)) settled = 0;
        }
        if (dead) { if ((st = sweep_done(x, s, GZ_XE_SWEEP_DEAD, out)) != GZ_OK) return st; continue; }
        if (settled) { if ((st = sweep_done(x, s, GZ_XE_SWEEP_SETTLED, out)) != GZ_OK) return st; continue; }
        if (!s->sighted && x->tip >= s->born_tip + GZ_XE_SWEEP_LIFE) {
            if ((st = sweep_done(x, s, GZ_XE_SWEEP_RETIRED, out)) != GZ_OK) return st;
            continue;
        }
        if (!s->bcast_known || s->last_bcast != x->tip) {
            if ((st = broadcast(out, s->tx, s->len)) != GZ_OK) return st;
            s->last_bcast = x->tip;
            s->bcast_known = 1;
        }
    }
    return GZ_OK;
}

/* What is due now (6.8, H15). Each parent's children are found by scanning
 * every node: O(N^2) in N <= 800 per decision, bounded. */
static gz_status_t offer(gz_xe_t *x, gz_action_list_t *out)
{
    const gz_xe_plan_t *p = &x->plan;
    gz_xe_sweep_in_t *cand = x->cand;
    gz_xe_sweep_t *s;
    gz_outpoint_t o;
    size_t n_c = 0;
    uint32_t lc;
    if (x->port_tip_known && x->port_tip == x->tip) return GZ_OK;
    for (size_t n = 1; n < p->n_nodes && n_c < GZ_XE_MAX_SWEEP_IN; n++) {
        const gz_xe_node_t *nd = &p->node[n];
        if (nd->parent == GZ_XE_FUNDING || node_conf(x, nd->parent) == 0) continue;
        if (nd->cltv == 0 || x->tip < nd->cltv || owed_below(p, nd->first, nd->count)) continue;
        input_of(p, n, &o);
        if (!sweepable(x, &x->in[n], nd->txid) || in_sweep(x, &o)) continue;
        cand[n_c].outpoint = o; cand[n_c].amount = nd->in_amount; cand[n_c].lock = nd->cltv; cand[n_c].csv = 0;
        cand[n_c].node = (uint16_t)n; cand[n_c].what = GZ_XE_OUT_INPUT;
        n_c++;
    }
    for (size_t n = 0; n < p->n_nodes; n++) {
        const gz_xe_node_t *nd = &p->node[n];
        if (nd->kind != GZ_NODE_LEAF_STATE || (lc = node_conf(x, n)) == 0) continue;
        memcpy(o.txid, nd->txid, 32);
        o.vout = 0;
        if (n_c < GZ_XE_MAX_SWEEP_IN && nd->cltv != 0 && x->tip >= nd->cltv && !owed_below(p, nd->first, 1)
            && sweepable(x, &x->chan[n], NULL) && !in_sweep(x, &o)) {
            cand[n_c].outpoint = o; cand[n_c].amount = nd->chan_amount; cand[n_c].lock = nd->cltv; cand[n_c].csv = 0;
            cand[n_c].node = (uint16_t)n; cand[n_c].what = GZ_XE_OUT_CHANNEL;
            n_c++;
        }
        o.vout = 1;
        if (n_c < GZ_XE_MAX_SWEEP_IN && nd->spare_csv != 0 && lc >= nd->spare_csv
            && sweepable(x, &x->spare[n], NULL) && !in_sweep(x, &o)) {
            cand[n_c].outpoint = o; cand[n_c].amount = nd->spare_amount; cand[n_c].lock = 0; cand[n_c].csv = nd->spare_csv;
            cand[n_c].node = (uint16_t)n; cand[n_c].what = GZ_XE_OUT_SPARE;
            n_c++;
        }
    }
    if (!n_c) return GZ_OK;
    if (!(s = sweep_slot(x))) {
        if (x->slot_tip_known && x->slot_tip == x->tip) return GZ_OK;
        x->slot_tip = x->tip;
        x->slot_tip_known = 1;
        return log_note(x, out, "host_sweep_no_slot");
    }
    return new_sweep(x, s, cand, n_c, out);
}

static gz_status_t decide_host(gz_xe_t *x, gz_action_list_t *out)
{
    const gz_xe_plan_t *p = &x->plan;
    uint32_t B = p->c.B;
    gz_status_t st;
    int added = 0, wait;

    if ((st = step_records(x, 0, out)) != GZ_OK) return st;
    if (node_conf(x, 0) == 0) {
        const gz_xe_fact_t *f = &x->in[0];
        if (f->failed) {                           /* the funding spent long ago */
            if ((st = failed_input(x, 0, &wait, out)) != GZ_OK || wait) return st;
            return end_exit(x, GZ_XE_END_FUNDING_SPENT, out);
        }
        if (f->known && f->conf >= 1) {           /* the funding went elsewhere (S8) */
            if (confs(x, f) >= B) return end_exit(x, GZ_XE_END_FUNDING_SPENT, out);
            return GZ_OK;
        }
        return step_due(x, 0, out);
    }

    /* The frontier: the outputs of every confirmed tree transaction, and the
     * txid of every child whose input's watch failed. */
    for (size_t n = 0; n < p->n_nodes; n++) {
        if (node_conf(x, n) == 0) continue;
        for (size_t c = n + 1; c < p->n_nodes; c++) {
            if (p->node[c].parent != n) continue;
            if (!x->in[c].watched) {
                if ((st = watch(x, K_IN, c, out)) != GZ_OK) return st;
                added = 1;
            } else if (x->in[c].failed && !x->txw[c].watched) {
                if ((st = note_failed(x, &x->in[c], out)) != GZ_OK || (st = watch(x, K_TX, c, out)) != GZ_OK) return st;
                added = 1;
            }
        }
        if (p->node[n].kind == GZ_NODE_LEAF_STATE && (!x->chan[n].watched || !x->spare[n].watched)) {
            if ((st = watch(x, K_CHAN, n, out)) != GZ_OK || (st = watch(x, K_SPARE, n, out)) != GZ_OK) return st;
            added = 1;
        }
    }
    for (size_t n = 0; n < p->n_nodes; n++) {     /* a leaf output's failed watch: noted */
        if (x->chan[n].failed && (st = note_failed(x, &x->chan[n], out)) != GZ_OK) return st;
        if (x->spare[n].failed && (st = note_failed(x, &x->spare[n], out)) != GZ_OK) return st;
    }
    if (added) return GZ_OK;                       /* their answers first */

    if ((st = tend_sweeps(x, out)) != GZ_OK) return st;
    if ((st = offer(x, out)) != GZ_OK) return st;

    /* The end: the root buried and every output watched spent and buried
     * (a failed watch: spent long ago). */
    if (node_conf(x, 0) < B) return GZ_OK;
    for (size_t n = 0; n < p->n_nodes; n++) {
        const gz_xe_fact_t *fs[3];
        fs[0] = &x->in[n]; fs[1] = &x->chan[n]; fs[2] = &x->spare[n];
        for (size_t k = 0; k < 3; k++)
            if (fs[k]->watched && !fs[k]->failed && !(fs[k]->known && confs(x, fs[k]) >= B)) return GZ_OK;
    }
    for (size_t k = 0; k < GZ_XE_MAX_SWEEPS; k++)
        if (x->sweep[k].used) return GZ_OK;
    return end_exit(x, GZ_XE_END_HOST_RECOVERED, out);
}

/* A spend seen only in a mempool for GZ_XE_STALE_TIPS tips is asked about
 * again: a spender that vanishes is never reported (action.h). */
static gz_status_t refresh_stale(gz_xe_t *x, int *again, gz_action_list_t *out)
{
    static const int kinds[] = { K_IN, K_CHAN, K_SPARE, K_ANCHOR };
    gz_status_t st;
    *again = 0;
    for (size_t k = 0; k < 4; k++) {
        size_t n = kinds[k] == K_ANCHOR ? x->plan.n_steps : x->plan.n_nodes;
        for (size_t i = 0; i < n; i++) {
            gz_xe_fact_t *f = fact_of(x, kinds[k], i);
            if (!f->watched || !f->known || f->conf != 0 || !f->zero_known) continue;
            if (x->tip < f->zero_tip + GZ_XE_STALE_TIPS) continue;
            if ((st = set_watch(x, kinds[k], i, 1, out)) != GZ_OK) return st;
            *again = 1;
        }
    }
    return GZ_OK;
}

static gz_status_t decide(gz_xe_t *x, gz_action_list_t *out)
{
    gz_status_t st;
    int again;
    if (!x->started || x->ended || !x->tip_known || !x->tip_synced || x->n_unsynced) return GZ_OK;
    if ((st = refresh_stale(x, &again, out)) != GZ_OK || again) return st;
    if ((st = classify_all(x, out)) != GZ_OK) return st;
    return x->plan.host ? decide_host(x, out) : decide_member(x, out);
}

static gz_status_t set_watches(gz_xe_t *x, gz_action_list_t *out)
{
    gz_status_t st;
    int kind;
    size_t idx;
    if (x->plan.host) {
        if ((st = watch(x, K_IN, 0, out)) != GZ_OK) return st;
        if (x->st[0].state != GZ_XE_ST_BURIED && (st = watch(x, K_ANCHOR, 0, out)) != GZ_OK) return st;
        for (size_t k = 0; k < GZ_XE_MAX_SWEEPS; k++) {
            const gz_xe_sweep_t *s = &x->sweep[k];
            if (!s->used) continue;
            for (size_t j = 0; j < s->n_in; j++) {
                if (find_fact(x, &s->in[j], &kind, &idx) && (st = watch(x, kind, idx, out)) != GZ_OK) return st;
            }
        }
        return GZ_OK;
    }
    for (size_t i = 0; i < x->plan.n_steps; i++) {
        if ((st = watch(x, K_IN, x->plan.step[i].node, out)) != GZ_OK) return st;
        if (x->st[i].state != GZ_XE_ST_BURIED && (st = watch(x, K_ANCHOR, i, out)) != GZ_OK) return st;
    }
    return GZ_OK;
}

/* Hold `plan` and append its exit_plan record to `r` (in x->scratch). */
static gz_status_t hold_plan(gz_xe_t *x, const gz_xe_plan_t *plan, gz_record_t *r, size_t *used)
{
    gz_status_t st;
    size_t n;
    x->plan = *plan;
    derive_children(&x->plan);
    n = enc_plan(&x->plan, x->scratch, sizeof x->scratch, &st);
    if (st != GZ_OK) return st;
    r->type = GZ_XE_REC_PLAN;
    r->bytes.data = x->scratch;
    r->bytes.len = n;
    *used = n;
    x->have_plan = 1;
    return GZ_OK;
}

static int plan_refusal(const gz_xe_t *x, const gz_xe_plan_t *plan)
{
    if (plan && memcmp(plan->scope, x->scope, 32) != 0) return GZ_XE_REFUSED_SCOPE;
    if (x->started || x->ended) return GZ_XE_REFUSED_STARTED;
    return 0;
}

gz_status_t gz_xe_set_plan(gz_xe_t *x, const gz_xe_plan_t *plan, gz_action_list_t *out, int *refused)
{
    gz_record_t r;
    gz_status_t st;
    size_t n;
    if (!x || !plan || !out || !refused) return GZ_ERR_ARGUMENT;
    if ((*refused = plan_refusal(x, plan)) != 0) return GZ_OK;
    if (!plan_check(plan)) return GZ_ERR_ARGUMENT;              /* not a plan from gz_xe_plan_* */
    if ((st = hold_plan(x, plan, &r, &n)) != GZ_OK) return st;
    return save(out, &r, 1);
}

gz_status_t gz_xe_begin(gz_xe_t *x, const gz_xe_plan_t *plan, uint8_t reason, gz_action_list_t *out, int *refused)
{
    gz_record_t r[2];
    gz_status_t st;
    size_t n1 = 0, k = 0;
    enc_t e;
    if (!x || !out || !refused) return GZ_ERR_ARGUMENT;
    if ((*refused = plan_refusal(x, plan)) != 0) return GZ_OK;
    if (!x->tip_known) { *refused = GZ_XE_REFUSED_NO_TIP; return GZ_OK; }
    if (!plan && !x->have_plan) { *refused = GZ_XE_REFUSED_NO_PLAN; return GZ_OK; }
    if (plan) {
        if (!plan_check(plan)) return GZ_ERR_ARGUMENT;
        if ((st = hold_plan(x, plan, &r[k++], &n1)) != GZ_OK) return st;
    }
    e.buf = x->scratch + n1; e.cap = sizeof x->scratch - n1; e.at = 0; e.st = GZ_OK;
    put(&e, F_SCOPE, x->scope, 32);
    put_u8(&e, SR_WHY, reason);
    put_u32(&e, SR_TIP, x->tip);
    if (e.st != GZ_OK) return e.st;
    r[k].type = GZ_XE_REC_STARTED; r[k].bytes.data = x->scratch + n1; r[k].bytes.len = e.at;
    k++;
    if ((st = save(out, r, k)) != GZ_OK) return st;
    x->started = 1;
    x->reason = reason;
    if ((st = set_watches(x, out)) != GZ_OK) return st;
    return decide(x, out);
}

gz_status_t gz_xe_load(void *e, const gz_record_t *rec, gz_batch_id_t at)
{
    static const uint8_t f_started[] = { F_SCOPE, SR_WHY, SR_TIP };
    static const uint8_t f_step[] = { F_SCOPE, SP_INDEX, SP_TXID, SP_STATE, SP_HEIGHT };
    static const uint8_t f_sweep[] = { F_SCOPE, SW_TXID, SW_TX, SW_TIP };
    static const uint8_t f_done[] = { F_SCOPE, SD_TXID, SD_HOW, SD_TIP };
    static const uint8_t f_ended[] = { F_SCOPE, EN_HOW, EN_HEIGHT };
    static const uint8_t f_seen[] = { F_SCOPE, SE_OUTPOINT, SE_SPENDER, SE_CLASS, SE_HEIGHT };
    gz_xe_t *x = e;
    gz_bytes_t s, v, id, sp, tp;
    gz_xe_sweep_t *slot = NULL;
    gz_outpoint_t o;
    int kind;
    size_t idx;
    gz_xe_fact_t *f;
    (void)at;
    if (!x || !rec) return GZ_ERR_ARGUMENT;
    switch (rec->type) {
    case GZ_XE_REC_PLAN: case GZ_XE_REC_STARTED: case GZ_XE_REC_STEP: case GZ_XE_REC_SWEEP:
    case GZ_XE_REC_SWEEP_DONE: case GZ_XE_REC_ENDED: case GZ_XE_REC_SEEN:
        break;
    default:
        return GZ_OK;                                            /* not this engine's */
    }
    s = rec->bytes;
    if (!gz_rec_valid(s) || !field(s, F_SCOPE, 32, &v)) return GZ_ERR_CORRUPT;
    if (memcmp(v.data, x->scope, 32) != 0) return GZ_OK;         /* another factory's */
    if (rec->type == GZ_XE_REC_PLAN) {                           /* a later plan replaces, until started */
        if (x->started || x->ended || !dec_plan(s, &x->plan)) return GZ_ERR_CORRUPT;
        derive_children(&x->plan);
        x->have_plan = 1;
        return GZ_OK;
    }
    if (!x->have_plan) return GZ_ERR_CORRUPT;
    switch (rec->type) {
    case GZ_XE_REC_STARTED:
        if (x->started || !fields_ok(s, f_started, sizeof f_started) || !field(s, SR_WHY, 1, &v)) return GZ_ERR_CORRUPT;
        x->started = 1;
        x->reason = v.data[0];
        return GZ_OK;
    case GZ_XE_REC_STEP: {
        uint16_t i;
        if (!fields_ok(s, f_step, sizeof f_step) || !field(s, SP_INDEX, 2, &v)) return GZ_ERR_CORRUPT;
        i = gz_get_u16(v.data);
        if (i >= x->plan.n_steps || !field(s, SP_TXID, 32, &v)
            || memcmp(v.data, x->plan.node[x->plan.step[i].node].txid, 32) != 0 || !field(s, SP_STATE, 1, &v)
            || v.data[0] < GZ_XE_ST_SENT || v.data[0] > GZ_XE_ST_BURIED)
            return GZ_ERR_CORRUPT;
        x->st[i].state = v.data[0];
        return GZ_OK;
    }
    case GZ_XE_REC_SWEEP:
        if (!x->plan.host || !fields_ok(s, f_sweep, sizeof f_sweep) || !field(s, SW_TX, 0, &v)
            || !field(s, SW_TXID, 32, &id) || !field(s, SW_TIP, 4, &tp))
            return GZ_ERR_CORRUPT;
        if (live_sweep(x, id.data) || !(slot = sweep_slot(x))) return GZ_ERR_CORRUPT;   /* more than 16 live */
        if (!sweep_parse(v.data, v.len, x->work, sizeof x->work, slot, NULL, 0, 0)
            || memcmp(slot->txid, id.data, 32) != 0) {
            memset(slot, 0, sizeof *slot);
            return GZ_ERR_CORRUPT;
        }
        slot->used = 1;
        slot->born_tip = gz_get_u32(tp.data);
        return GZ_OK;
    case GZ_XE_REC_SWEEP_DONE:
        if (!fields_ok(s, f_done, sizeof f_done) || !field(s, SD_TXID, 32, &id) || !(slot = live_sweep(x, id.data)))
            return GZ_ERR_CORRUPT;
        memset(slot, 0, sizeof *slot);
        return GZ_OK;
    case GZ_XE_REC_ENDED:
        if (!fields_ok(s, f_ended, sizeof f_ended) || !field(s, EN_HOW, 1, &v)) return GZ_ERR_CORRUPT;
        x->ended = 1;
        x->ended_how = v.data[0];
        return GZ_OK;
    default:                                                     /* spend_seen */
        if (!fields_ok(s, f_seen, sizeof f_seen) || !field(s, SE_OUTPOINT, 36, &v) || !field(s, SE_SPENDER, 32, &sp))
            return GZ_ERR_CORRUPT;
        get_outpoint(v.data, &o);
        if (!(f = find_fact(x, &o, &kind, &idx))) return GZ_OK;   /* not in the plan: ignored (6.8) */
        f->recorded = 1;
        memcpy(f->rec_spender, sp.data, 32);
        return GZ_OK;
    }
}

gz_status_t gz_xe_resume(void *e, gz_action_list_t *out, int *more)
{
    gz_xe_t *x = e;
    gz_status_t st;
    if (!x || !out || !more) return GZ_ERR_ARGUMENT;
    *more = 0;
    if (!x->have_plan || !x->started || x->ended) return GZ_OK;
    /* Every step journaled sent, and every live sweep, before anything else (6.3). */
    for (size_t i = 0; i < x->plan.n_steps; i++)
        if (x->st[i].state == GZ_XE_ST_SENT) {
            if ((st = send_step(x, i, out)) != GZ_OK) return st;
            x->st[i].bcast_known = 0;                            /* no tip yet */
        }
    for (size_t k = 0; k < GZ_XE_MAX_SWEEPS; k++)
        if (x->sweep[k].used && (st = broadcast(out, x->sweep[k].tx, x->sweep[k].len)) != GZ_OK) return st;
    return set_watches(x, out);
}

/* A refused broadcast: counted per step, logged per sweep (6.8). */
static gz_status_t on_refused(gz_xe_t *x, const gz_chain_event_t *c, gz_action_list_t *out)
{
    if (!x->have_plan || !x->started || x->ended) return GZ_OK;
    for (size_t i = 0; i < x->plan.n_steps; i++) {
        if (memcmp(x->plan.node[x->plan.step[i].node].txid, c->txid, 32) != 0) continue;
        if (++x->st[i].refused >= (x->plan.c.A ? x->plan.c.A : 1) && !x->st[i].held) {
            x->st[i].held = 1;
            return log_note(x, out, "exit_step_held_back");
        }
        return GZ_OK;
    }
    if (live_sweep(x, c->txid)) return log_note(x, out, "host_sweep_refused");
    return GZ_OK;
}

gz_status_t gz_xe_handle(void *e, const gz_event_t *ev, gz_action_list_t *out)
{
    gz_xe_t *x = e;
    const gz_chain_event_t *c;
    gz_xe_fact_t *f;
    int kind;
    size_t idx;
    if (!x || !ev || !out) return GZ_ERR_ARGUMENT;
    if (ev->kind != GZ_EVENT_CHAIN) return GZ_OK;
    c = &ev->u.chain;
    switch (c->kind) {
    case GZ_CHAIN_NEW_TIP:
        x->tip = c->height;
        x->tip_known = 1;
        x->tip_synced = 0;
        memcpy(x->tip_hash, c->block_hash, 32);
        return GZ_OK;
    case GZ_CHAIN_TIP_SYNCED: {
        int given = 0;
        for (size_t k = 0; k < 32; k++) given |= c->block_hash[k];
        if (!x->tip_known || c->height != x->tip || (given && memcmp(c->block_hash, x->tip_hash, 32) != 0)) {
            x->dropped++;
            return GZ_OK;
        }
        x->tip_synced = 1;
        break;
    }
    case GZ_CHAIN_OUTPOINT_SPENT:
        f = x->have_plan ? find_fact(x, &c->outpoint, &kind, &idx) : NULL;
        if (!f || !f->watched) { x->dropped++; return GZ_OK; }
        f->known = 1;
        memcpy(f->spender, c->txid, 32);
        f->conf = c->confirmations;
        f->height = c->confirmations ? c->height : 0;
        f->zero_known = c->confirmations == 0 && x->tip_known;
        f->zero_tip = x->tip;
        break;
    case GZ_CHAIN_TX_CONFIRMED:
    case GZ_CHAIN_TX_UNCONFIRMED:
        f = x->have_plan ? find_txw(x, c->txid) : NULL;
        if (!f || !f->watched) { x->dropped++; return GZ_OK; }
        f->known = 1;
        memcpy(f->spender, c->txid, 32);
        f->conf = c->kind == GZ_CHAIN_TX_CONFIRMED ? c->confirmations : 0;
        f->height = f->conf ? c->height : 0;
        break;
    case GZ_CHAIN_WATCH_SYNCED:
    case GZ_CHAIN_WATCH_FAILED:
        if (!x->have_plan) f = NULL;
        else if (c->is_tx) f = find_txw(x, c->txid);
        else f = find_fact(x, &c->outpoint, &kind, &idx);
        if (!f || !f->watched) { x->dropped++; return GZ_OK; }
        if (!f->synced) { f->synced = 1; x->n_unsynced--; }
        if (c->kind == GZ_CHAIN_WATCH_FAILED) f->failed = 1;
        break;
    case GZ_CHAIN_BROADCAST_RESULT:
        if (c->outcome == GZ_BROADCAST_REFUSED) return on_refused(x, c, out);
        return GZ_OK;
    default:
        return GZ_OK;                                            /* PENDING holds the factory */
    }
    return decide(x, out);
}

int gz_xe_step_state(const gz_xe_t *x, size_t i)
{
    size_t first;
    if (!x || !x->have_plan || i >= x->plan.n_steps) return 0;
    {
        uint32_t c = node_conf(x, x->plan.step[i].node);
        if (c >= x->plan.c.B) return GZ_XE_ST_BURIED;
        if (c >= 1) return GZ_XE_ST_CONFIRMED;
    }
    if (x->st[i].state == GZ_XE_ST_SENT) return GZ_XE_ST_SENT;
    if (!x->started) return GZ_XE_ST_PENDING;
    for (first = 0; first < x->plan.n_steps; first++)
        if (node_conf(x, x->plan.step[first].node) == 0) break;
    if (i == first) return GZ_XE_ST_DUE;
    return i == first + 1 ? GZ_XE_ST_WAITING : GZ_XE_ST_PENDING;
}

int gz_xe_has_ended(const gz_xe_t *x, uint8_t *how)
{
    if (!x || !x->ended) return 0;
    if (how) *how = x->ended_how;
    return 1;
}
