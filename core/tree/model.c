/* The tree, rebuilt from the rules (tree.h, "Two builds, one tree").
 *
 * What the import does for an advanceless tree, written out (pin e657395,
 * src/factory.c):
 *   add_node :153-230        a node's spending script: P2TR of the MuSig2
 *                            aggregate of host + its members, tweaked with
 *                            the one-leaf tree <h> CLTV DROP <host> CHECKSIG
 *                            when h > 0, else BIP 86
 *   build_subtree :1604-1880 ko height E - 5 (2d - 1), state E - 10 d, root
 *                            kickoff none (saturating at 0); a fixed kickoff
 *                            pays (input - fee - anchor) to its children in
 *                            equal shares, the remainder to the last; a leaf
 *                            kickoff pays input - fee - anchor to its state
 *   setup_ps_leaf_outputs :1291-1330  channel (the state's own spending
 *                            script) and spare liquidity, half each, the
 *                            remainder to the spare liquidity; dust 546
 *   build_l_stock_spk :315   spare liquidity: the state's aggregate tweaked
 *                            with the one-leaf tree <csv> CSV DROP <host> CHECKSIG
 *   node_nsequence :129-150  fixed kickoff and pseudo-Spilman leaf 0xFFFFFFFE,
 *                            leaf kickoff 0xFFFFFFFF
 *   factory_append_tree_anchor :499  the 240-sat P2A output, last
 *   tx_builder.c:65-110      version 2, one input, empty scriptSig, lock time 0
 *   factory_build_tree :1882 its minimum funding check
 */
#include "gazpacho/tree.h"
#include "internal.h"

#include <string.h>

static const uint8_t P2A[4] = {0x51, 0x02, 0x4e, 0x73};

/* encode_scriptnum (tapscript.c:11-38): OP_0, OP_1..OP_16, else a minimal
 * little-endian push with a sign byte when the top bit is set. */
static size_t scriptnum(uint8_t *out, uint32_t v)
{
    uint8_t tmp[5];
    size_t n = 0;
    if (v == 0) { out[0] = 0x00; return 1; }
    if (v <= 16) { out[0] = (uint8_t)(0x50 + v); return 1; }
    while (v) { tmp[n++] = (uint8_t)v; v >>= 8; }
    if (tmp[n - 1] & 0x80) tmp[n++] = 0;
    out[0] = (uint8_t)n;
    memcpy(out + 1, tmp, n);
    return n + 1;
}

/* <v> OP_CLTV (0xb1) or OP_CSV (0xb2), OP_DROP, <32-byte key>, OP_CHECKSIG;
 * then its BIP 341 leaf hash (leaf version 0xc0). */
static void timelock_leaf(uint32_t v, uint8_t op, const uint8_t host33[33], uint8_t leaf_hash[32])
{
    uint8_t script[64];
    size_t n = scriptnum(script, v);
    uint8_t pre[2];
    tr_sha256_t s;
    script[n++] = op;
    script[n++] = 0x75;
    script[n++] = 0x20;
    memcpy(script + n, host33 + 1, 32);
    n += 32;
    script[n++] = 0xac;
    pre[0] = 0xc0;
    pre[1] = (uint8_t)n;
    tr_tagged_init(&s, "TapLeaf");
    tr_sha256_write(&s, pre, 2);
    tr_sha256_write(&s, script, n);
    tr_sha256_done(&s, leaf_hash);
}

static void taptweak(const uint8_t internal[32], const uint8_t *merkle, uint8_t out[32])
{
    tr_sha256_t s;
    tr_tagged_init(&s, "TapTweak");
    tr_sha256_write(&s, internal, 32);
    if (merkle) tr_sha256_write(&s, merkle, 32);
    tr_sha256_done(&s, out);
}

static void p2tr(uint8_t script[34], const uint8_t key[32])
{
    script[0] = 0x51;
    script[1] = 0x20;
    memcpy(script + 2, key, 32);
}

typedef struct {
    const gz_tree_build_in_t *in;
    const gz_tree_crypto_t *cr;
    gz_tree_t *t;
    gz_tree_b_err_t err;
} bld_t;

static uint32_t height_less(uint32_t E, uint32_t off) { return E > off ? E - off : 0; }

/* add_node: kind, signers, parent link, the node's own spending script. */
static int add_node(bld_t *b, uint8_t kind, uint32_t depth, uint32_t first, uint32_t count, int parent,
                    uint32_t parent_vout, uint32_t cltv, uint64_t input)
{
    gz_tree_t *t = b->t;
    gz_tree_node_t *n;
    uint8_t out_key[32];
    if (t->n_nodes >= GZ_TREE_MAX_NODES) { b->err = GZ_TREE_B_ARGUMENT; return -1; }
    n = &t->node[t->n_nodes];
    memset(n, 0, sizeof *n);
    n->kind = kind;
    n->depth = (uint8_t)depth;
    n->parent = (int16_t)parent;
    n->parent_vout = (uint8_t)parent_vout;
    n->first = (uint16_t)first;
    n->count = (uint16_t)count;
    n->cltv = cltv;
    n->spent_amount = input;
    n->nsequence = kind == GZ_NODE_LEAF_KICKOFF ? 0xffffffffu : 0xfffffffeu;
    if (cltv > 0) {
        timelock_leaf(cltv, 0xb1, b->in->host_key, n->merkle);
        n->has_merkle = 1;
    }
    if (!b->cr->agg_tweak(b->cr->ctx, b->in->host_key, b->in->member_keys + first, count,
                          n->has_merkle ? n->merkle : NULL, n->internal, out_key)) {
        b->err = GZ_TREE_B_CRYPTO;
        return -1;
    }
    taptweak(n->internal, n->has_merkle ? n->merkle : NULL, n->tweak);
    p2tr(n->spent_script, out_key);
    return (int)t->n_nodes++;
}

static void add_output(gz_tree_node_t *n, uint8_t kind, uint64_t amount, const uint8_t *script, uint8_t len)
{
    n->out_kind[n->n_out] = kind;
    n->out_amount[n->n_out] = amount;
    n->out_script_len[n->n_out] = len;
    memcpy(n->out_script[n->n_out], script, len);
    n->n_out++;
}

static int subtree(bld_t *b, uint32_t first, uint32_t count, int parent, uint32_t parent_vout, uint32_t depth,
                   uint64_t input)
{
    const gz_tree_build_in_t *in = b->in;
    gz_tree_t *t = b->t;
    uint64_t fee = in->fee_per_tx, cost;
    uint32_t a = tr_level(in->levels, in->n_levels, depth);
    uint32_t ko = depth == 0 ? 0 : height_less(in->end_height, (2 * depth - 1) * GZ_TREE_TIMEOUT_STEP);
    uint32_t st = depth == 0 ? in->end_height : height_less(in->end_height, 2 * depth * GZ_TREE_TIMEOUT_STEP);
    int leaf = a == GZ_TERMS_LEAF_PS && count == 1;
    if (depth >= GZ_TREE_MAX_DEPTH) { b->err = GZ_TREE_B_ARGUMENT; return 0; }
    if (fee > UINT64_MAX - GZ_TREE_ANCHOR_SAT) { b->err = GZ_TREE_B_UNDERFUNDED; return 0; }
    cost = fee + GZ_TREE_ANCHOR_SAT;
    if (!leaf) {
        uint32_t sizes[16], k, j, off = first;
        int ko_idx, child_first[16];
        uint64_t budget, per, rem;
        k = tr_children(in->levels, in->n_levels, count, depth, sizes);
        if (k == 0) { b->err = GZ_TREE_B_SPLIT; return 0; }
        /* Every interior node must be fixed (kickoff-only): fixed_levels = D. */
        if (depth >= in->fixed_levels) { b->err = GZ_TREE_B_FIXED_LEVELS; return 0; }
        ko_idx = add_node(b, GZ_NODE_FIXED, depth, first, count, parent, parent_vout, ko, input);
        if (ko_idx < 0) return 0;
        if (input <= cost) { b->err = GZ_TREE_B_UNDERFUNDED; return 0; }
        budget = input - cost;
        per = budget / k;
        rem = budget - per * k;
        for (j = 0; j < k; j++) {
            child_first[j] = t->n_nodes;
            if (!subtree(b, off, sizes[j], ko_idx, j, depth + 1, per + (j == k - 1 ? rem : 0))) return 0;
            off += sizes[j];
        }
        for (j = 0; j < k; j++)
            add_output(&t->node[ko_idx], GZ_OUT_CHILD, per + (j == k - 1 ? rem : 0),
                       t->node[child_first[j]].spent_script, 34);
        add_output(&t->node[ko_idx], GZ_OUT_ANCHOR, GZ_TREE_ANCHOR_SAT, P2A, 4);
        return 1;
    } else {
        int ko_idx, st_idx;
        uint64_t ko_out, total, per;
        gz_tree_node_t *s;
        uint8_t lmerkle[32], linternal[32], lkey[32], lscript[34];
        uint32_t csv = in->lstock_csv ? in->lstock_csv : GZ_TREE_LSTOCK_DEFAULT;
        ko_idx = add_node(b, GZ_NODE_LEAF_KICKOFF, depth, first, 1, parent, parent_vout, ko, input);
        if (ko_idx < 0) return 0;
        st_idx = add_node(b, GZ_NODE_LEAF_STATE, depth, first, 1, ko_idx, 0, st, 0);
        if (st_idx < 0) return 0;
        if (input <= cost) { b->err = GZ_TREE_B_UNDERFUNDED; return 0; }
        ko_out = input - cost;
        add_output(&t->node[ko_idx], GZ_OUT_STATE, ko_out, t->node[st_idx].spent_script, 34);
        add_output(&t->node[ko_idx], GZ_OUT_ANCHOR, GZ_TREE_ANCHOR_SAT, P2A, 4);
        s = &t->node[st_idx];
        s->spent_amount = ko_out;
        total = ko_out > cost ? ko_out - cost : 0;
        per = total / 2;
        if (per < GZ_TREE_DUST_SAT) { b->err = GZ_TREE_B_DUST; return 0; }
        timelock_leaf(csv, 0xb2, in->host_key, lmerkle);
        if (!b->cr->agg_tweak(b->cr->ctx, in->host_key, in->member_keys + first, 1, lmerkle, linternal, lkey)
            || !tr_eq(linternal, s->internal, 32)) {
            b->err = GZ_TREE_B_CRYPTO;
            return 0;
        }
        p2tr(lscript, lkey);
        s->lstock_csv = csv;
        add_output(s, GZ_OUT_CHANNEL, per, s->spent_script, 34);
        add_output(s, GZ_OUT_LSTOCK, per + (total - per * 2), lscript, 34);
        add_output(s, GZ_OUT_ANCHOR, GZ_TREE_ANCHOR_SAT, P2A, 4);
        t->leaf_state[first] = (uint16_t)st_idx;
        return 1;
    }
}

static size_t put_varint(uint8_t *p, uint64_t v)
{
    if (v < 0xfd) { p[0] = (uint8_t)v; return 1; }
    p[0] = 0xfd; p[1] = (uint8_t)v; p[2] = (uint8_t)(v >> 8);   /* never more than 0xffff here */
    return 3;
}

static void serialise(gz_tree_node_t *n)
{
    uint8_t *p = n->tx;
    size_t i = 0, o;
    tr_le32(p, 2); i = 4;                       /* version */
    p[i++] = 1;                                 /* one input */
    memcpy(p + i, n->spent_txid, 32); i += 32;
    tr_le32(p + i, n->spent_vout); i += 4;
    p[i++] = 0;                                 /* empty scriptSig */
    tr_le32(p + i, n->nsequence); i += 4;
    p[i++] = n->n_out;
    for (o = 0; o < n->n_out; o++) {
        tr_le64(p + i, n->out_amount[o]); i += 8;
        i += put_varint(p + i, n->out_script_len[o]);
        memcpy(p + i, n->out_script[o], n->out_script_len[o]);
        i += n->out_script_len[o];
    }
    tr_le32(p + i, 0); i += 4;                  /* lock time */
    n->tx_len = (uint16_t)i;
    tr_sha256d(n->tx, i, n->txid);
}

gz_tree_b_err_t gz_tree_build(const gz_tree_build_in_t *in, const gz_tree_crypto_t *cr, gz_tree_t *t)
{
    bld_t b;
    uint8_t depths[GZ_TREE_MAX_MEMBERS], D = 0, out_key[32];
    uint32_t i;
    uint64_t ub, min_funding;
    if (!in || !cr || !cr->agg_tweak || !t || !in->host_key || !in->member_keys || !in->levels
        || in->n_levels < 1 || in->n_levels > GZ_TREE_MAX_LEVELS || in->n_members < 1
        || in->n_members > GZ_TREE_MAX_MEMBERS)
        return GZ_TREE_B_ARGUMENT;
    memset(t, 0, sizeof *t);
    t->n_members = in->n_members;
    if (!gz_tree_split(in->levels, in->n_levels, in->n_members, depths)) return GZ_TREE_B_SPLIT;
    for (i = 0; i < in->n_members; i++)
        if (depths[i] > D) D = depths[i];
    if (in->fixed_levels != D) return GZ_TREE_B_FIXED_LEVELS;
    /* factory_build_tree's minimum: 2 (2 leaves - 1) fee + 1,092 per leaf. */
    ub = 2 * (2 * (uint64_t)in->n_members - 1);
    if (in->fee_per_tx > (UINT64_MAX - 1092 * (uint64_t)in->n_members) / ub) return GZ_TREE_B_IMPORT_MINIMUM;
    min_funding = ub * in->fee_per_tx + 1092 * (uint64_t)in->n_members;
    if (in->funding_amount < min_funding) return GZ_TREE_B_IMPORT_MINIMUM;
    if (!cr->agg_tweak(cr->ctx, in->host_key, in->member_keys, in->n_members, NULL, t->funding_internal, out_key))
        return GZ_TREE_B_CRYPTO;
    b.in = in; b.cr = cr; b.t = t; b.err = GZ_TREE_B_OK;
    if (!subtree(&b, 0, in->n_members, -1, 0, 0, in->funding_amount)) return b.err ? b.err : GZ_TREE_B_SPLIT;
    for (i = 0; i < t->n_nodes; i++) {
        gz_tree_node_t *n = &t->node[i];
        if (n->parent < 0) {
            memcpy(n->spent_txid, in->funding_txid, 32);
            n->spent_vout = in->funding_vout;
        } else {
            memcpy(n->spent_txid, t->node[n->parent].txid, 32);
            n->spent_vout = n->parent_vout;
        }
        serialise(n);
        gz_tx_sighash1(n->tx, n->tx_len, n->spent_amount, n->spent_script, 34, n->sighash);
    }
    return GZ_TREE_B_OK;
}

/* ---------------------------------------------------------- transactions */

static int read_varint(const uint8_t *p, size_t len, size_t *i, uint64_t *v)
{
    uint8_t f;
    size_t need, k;
    if (*i >= len) return 0;
    f = p[(*i)++];
    if (f < 0xfd) { *v = f; return 1; }
    need = f == 0xfd ? 2 : f == 0xfe ? 4 : 8;
    if (len - *i < need) return 0;
    *v = 0;
    for (k = need; k > 0; k--) *v = *v << 8 | p[*i + k - 1];
    *i += need;
    /* canonical only, as Bitcoin Core's deserialiser */
    return !((f == 0xfd && *v < 0xfd) || (f == 0xfe && *v < 0x10000) || (f == 0xff && *v < 0x100000000ull));
}

int gz_tx_parse(const uint8_t *tx, size_t len, gz_tx_info_t *info)
{
    size_t i = 4, k;
    uint64_t n, l;
    if (!tx || !info || len < 10) return 0;
    info->version = tr_rd_le32(tx);
    if (!read_varint(tx, len, &i, &n) || n == 0 || n > 10000) return 0;   /* 0: a witness marker */
    info->n_in = (size_t)n;
    info->in_at = i;
    for (k = 0; k < info->n_in; k++) {
        if (len - i < 36) return 0;
        i += 36;
        if (!read_varint(tx, len, &i, &l) || l > len - i) return 0;
        i += (size_t)l;
        if (len - i < 4) return 0;
        i += 4;
    }
    if (!read_varint(tx, len, &i, &n) || n > 10000) return 0;
    info->n_out = (size_t)n;
    info->out_at = i;
    for (k = 0; k < info->n_out; k++) {
        if (len - i < 8) return 0;
        i += 8;
        if (!read_varint(tx, len, &i, &l) || l > len - i) return 0;
        i += (size_t)l;
    }
    if (len - i != 4) return 0;
    info->locktime = tr_rd_le32(tx + i);
    return 1;
}

int gz_tx_output(const uint8_t *tx, size_t len, const gz_tx_info_t *info, size_t idx, uint64_t *amount,
                 const uint8_t **script, size_t *script_len)
{
    size_t i = info->out_at, k;
    uint64_t l;
    if (idx >= info->n_out) return 0;
    for (k = 0; k <= idx; k++) {
        uint64_t a = tr_rd_le64(tx + i);
        i += 8;
        if (!read_varint(tx, len, &i, &l)) return 0;
        if (k == idx) {
            if (amount) *amount = a;
            if (script) *script = tx + i;
            if (script_len) *script_len = (size_t)l;
            return 1;
        }
        i += (size_t)l;
    }
    return 0;
}

int gz_tx_input(const uint8_t *tx, size_t len, const gz_tx_info_t *info, size_t idx, const uint8_t **outpoint,
                size_t *script_len, uint32_t *sequence)
{
    size_t i = info->in_at, k;
    uint64_t l;
    if (idx >= info->n_in) return 0;
    for (k = 0; k <= idx; k++) {
        const uint8_t *op = tx + i;
        i += 36;
        if (!read_varint(tx, len, &i, &l)) return 0;
        if (k == idx) {
            if (outpoint) *outpoint = op;
            if (script_len) *script_len = (size_t)l;
            if (sequence) *sequence = tr_rd_le32(tx + i + (size_t)l);
            return 1;
        }
        i += (size_t)l + 4;
    }
    return 0;
}

void gz_tx_txid(const uint8_t *tx, size_t len, uint8_t txid[32])
{
    tr_sha256d(tx, len, txid);
}

int gz_tx_sighash1(const uint8_t *tx, size_t len, uint64_t amount, const uint8_t *script, size_t script_len,
                   uint8_t out[32])
{
    gz_tx_info_t info;
    const uint8_t *op;
    size_t sl;
    uint32_t seq;
    uint8_t h[32], b[9], m[1 + 4 + 4];
    tr_sha256_t s, x;
    if (!gz_tx_parse(tx, len, &info) || info.n_in != 1 || !script || script_len > 0xfc) return 0;
    if (!gz_tx_input(tx, len, &info, 0, &op, &sl, &seq)) return 0;
    tr_tagged_init(&s, "TapSighash");
    m[0] = 0x00;                               /* epoch */
    tr_sha256_write(&s, m, 1);
    m[0] = 0x00;                               /* SIGHASH_DEFAULT */
    tr_le32(m + 1, info.version);
    tr_le32(m + 5, info.locktime);
    tr_sha256_write(&s, m, 9);
    tr_sha256(op, 36, h);                      /* sha_prevouts */
    tr_sha256_write(&s, h, 32);
    tr_le64(b, amount);                        /* sha_amounts */
    tr_sha256(b, 8, h);
    tr_sha256_write(&s, h, 32);
    tr_sha256_init(&x);                        /* sha_scriptpubkeys */
    b[0] = (uint8_t)script_len;
    tr_sha256_write(&x, b, 1);
    tr_sha256_write(&x, script, script_len);
    tr_sha256_done(&x, h);
    tr_sha256_write(&s, h, 32);
    tr_le32(b, seq);                           /* sha_sequences */
    tr_sha256(b, 4, h);
    tr_sha256_write(&s, h, 32);
    tr_sha256(tx + info.out_at, len - 4 - info.out_at, h);   /* sha_outputs */
    tr_sha256_write(&s, h, 32);
    m[0] = 0x00;                               /* spend type: key path, no annex */
    tr_le32(m + 1, 0);                         /* input index */
    tr_sha256_write(&s, m, 5);
    tr_sha256_done(&s, out);
    return 1;
}

/* -------------------------------------------------- 7.12 and 7.1 digests */

static void w_u8(tr_sha256_t *s, uint32_t v) { uint8_t b = (uint8_t)v; tr_sha256_write(s, &b, 1); }
static void w_u16(tr_sha256_t *s, uint32_t v) { uint8_t b[2]; tr_be16(b, v); tr_sha256_write(s, b, 2); }
static void w_u32(tr_sha256_t *s, uint32_t v) { uint8_t b[4]; tr_be32(b, v); tr_sha256_write(s, b, 4); }
static void w_u64(tr_sha256_t *s, uint64_t v) { uint8_t b[8]; tr_be64(b, v); tr_sha256_write(s, b, 8); }
static void w_outpoint(tr_sha256_t *s, const uint8_t txid[32], uint32_t vout)
{
    tr_sha256_write(s, txid, 32);
    w_u32(s, vout);                             /* big-endian here (messages.md section 1) */
}

static void w_items(tr_sha256_t *s, const gz_tree_t *t)
{
    uint32_t i, k;
    w_u32(s, t->n_nodes);
    for (i = 0; i < t->n_nodes; i++) {
        const gz_tree_node_t *n = &t->node[i];
        w_u32(s, i);
        w_outpoint(s, n->spent_txid, n->spent_vout);
        tr_sha256_write(s, n->sighash, 32);
        w_u8(s, 0);                             /* key path */
        tr_sha256_write(s, n->tweak, 32);
        w_u16(s, 1 + (uint32_t)n->count);
        w_u16(s, 0);                            /* the host */
        for (k = 0; k < n->count; k++) w_u16(s, 1 + (uint32_t)n->first + k);
    }
}

void gz_tree_digest(const gz_tree_t *t, const uint8_t chain[32], const uint8_t funding_txid[32], uint32_t funding_vout,
                    uint64_t funding_amount, const gz_tree_participant_t *ps, size_t np, uint8_t out[32])
{
    tr_sha256_t s;
    size_t i;
    tr_tagged_init(&s, "gazpacho/tree");
    tr_sha256_write(&s, chain, 32);
    w_outpoint(&s, funding_txid, funding_vout);
    w_u64(&s, funding_amount);
    w_u16(&s, (uint32_t)np);
    for (i = 0; i < np; i++) tr_sha256_write(&s, ps[i].factory_key, 33);
    w_items(&s, t);
    tr_sha256_done(&s, out);
}

void gz_tree_round_id(const gz_tree_t *t, const uint8_t chain[32], const uint8_t host_key[33],
                      const uint8_t outer_digest[32], const uint8_t terms_digest[32], const uint8_t funding_txid[32],
                      uint32_t funding_vout, uint64_t funding_amount, const gz_tree_participant_t *ps, size_t np,
                      const uint8_t host_random[32], uint8_t out[32])
{
    static const uint8_t protocol[4] = {0x67, 0x7a, 0x66, 0x01};
    tr_sha256_t s;
    size_t i;
    tr_tagged_init(&s, "gazpacho/round_id");
    tr_sha256_write(&s, protocol, 4);
    tr_sha256_write(&s, chain, 32);
    tr_sha256_write(&s, host_key, 33);
    tr_sha256_write(&s, outer_digest, 32);
    tr_sha256_write(&s, terms_digest, 32);
    w_outpoint(&s, funding_txid, funding_vout);
    w_u64(&s, funding_amount);
    w_u16(&s, (uint32_t)np);
    for (i = 0; i < np; i++) tr_sha256_write(&s, ps[i].factory_key, 33);
    for (i = 0; i < np; i++) tr_sha256_write(&s, ps[i].contribution_key, 33);
    w_u8(&s, 1);                                /* purpose: creation */
    w_u8(&s, 1);                                /* one tier */
    w_u32(&s, t->n_nodes);                      /* its size */
    w_items(&s, t);
    tr_sha256_write(&s, host_random, 32);
    tr_sha256_done(&s, out);
}
