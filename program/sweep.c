/* SPDX-License-Identifier: MIT */
/* The host's timeout sweep of a factory (test build): see sweep.h.
 *
 * Slice 1's INTERIM spend rules (spec/exit.md 3.2, rule H15): the funding
 * output has no timeout, so the host first publishes the pre-signed root
 * kickoff (every signer's key path, from the journal: the round's proposal
 * and the host's final signatures); every output of the root kickoff is then
 * the host's alone from its timeout height, through the timeout leaf
 * `<cltv> OP_CLTV OP_DROP <host key> OP_CHECKSIG`. The host sweeps such an
 * output only if no member below it is owed anything (H15), and never before
 * its height. Nothing here broadcasts: the lines are for the caller. */
#define _POSIX_C_SOURCE 200809L
#include "sweep.h"

#ifdef GZP_TEST_BUILD
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include "gazpacho/envelope.h"
#include "gazpacho/round_msg.h"
#include "gazpacho/signing.h"
#include "gazpacho/terms.h"
#include "gazpacho/tree.h"
#include "gazpacho/tree_import.h"
#include "superscalar/factory.h"
#include "superscalar/tx_builder.h"
#include "gzp.h"
#include "keys.h"
#include "store.h"

#define SW_MAX 8
#define SW_LOBBY_OPENED   0x00010002u   /* journal.md 9: lobby_opened (2 scope, 4 outer) */
#define SW_ROUND_PROPOSAL 0x00020004u   /* round_proposal (2 round id, 4 the round_propose) */
#define SW_ROUND_SIGNED   0x00020008u   /* round_signed (2 round id, 4 tier, 6 finals of 68) */

typedef struct {
    uint8_t scope[32];
    uint8_t *outer;
    size_t outer_len;
} sw_lobby_t;

typedef struct {
    uint8_t id[32];
    uint8_t *proposal;      /* the round_propose bytes */
    size_t proposal_len;
    uint8_t *finals;        /* entries of 68: u32 index, 64 */
    size_t n_finals;
} sw_round_t;

typedef struct {
    sw_lobby_t lobby[SW_MAX];
    size_t n_lobby;
    sw_round_t round[SW_MAX];
    size_t n_round;
} sw_scan_t;

static uint8_t *dup_bytes(const uint8_t *p, size_t n)
{
    uint8_t *c = malloc(n ? n : 1);
    if (c && n) memcpy(c, p, n);
    return c;
}

static sw_round_t *round_of(sw_scan_t *s, const uint8_t id[32])
{
    for (size_t i = 0; i < s->n_round; i++)
        if (!memcmp(s->round[i].id, id, 32)) return &s->round[i];
    if (s->n_round == SW_MAX) return NULL;
    memset(&s->round[s->n_round], 0, sizeof s->round[0]);
    memcpy(s->round[s->n_round].id, id, 32);
    return &s->round[s->n_round++];
}

/* gzp_journal_walk's callback: what the sweep needs, the latest of each. */
static void on_record(void *ctx, const gz_record_t *rec)
{
    sw_scan_t *s = ctx;
    gz_bytes_t a, b;
    if (rec->type == SW_LOBBY_OPENED) {
        if (gz_rec_find(rec->bytes, 2, &a) != 1 || a.len != 32 || gz_rec_find(rec->bytes, 4, &b) != 1) return;
        for (size_t i = 0; i < s->n_lobby; i++)
            if (!memcmp(s->lobby[i].scope, a.data, 32)) return;
        if (s->n_lobby == SW_MAX) return;
        memcpy(s->lobby[s->n_lobby].scope, a.data, 32);
        s->lobby[s->n_lobby].outer = dup_bytes(b.data, b.len);
        s->lobby[s->n_lobby].outer_len = b.len;
        s->n_lobby++;
    } else if (rec->type == SW_ROUND_PROPOSAL) {
        sw_round_t *r;
        if (gz_rec_find(rec->bytes, 2, &a) != 1 || a.len != 32 || gz_rec_find(rec->bytes, 4, &b) != 1) return;
        if (!(r = round_of(s, a.data))) return;
        free(r->proposal);
        r->proposal = dup_bytes(b.data, b.len);
        r->proposal_len = b.len;
    } else if (rec->type == SW_ROUND_SIGNED) {
        sw_round_t *r;
        if (gz_rec_find(rec->bytes, 2, &a) != 1 || a.len != 32 || gz_rec_find(rec->bytes, 6, &b) != 1 || b.len % 68)
            return;
        if (!(r = round_of(s, a.data))) return;
        free(r->finals);
        r->finals = dup_bytes(b.data, b.len);
        r->n_finals = b.len / 68;
    }
}

static void hex(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static void hex_rev(const uint8_t *b, size_t n)
{
    for (size_t i = n; i > 0; i--) printf("%02x", b[i - 1]);
}

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* BigSize-free Bitcoin varint. */
static int rd_var(const uint8_t *t, size_t n, size_t *at, uint64_t *v)
{
    if (*at >= n) return 0;
    uint8_t f = t[(*at)++];
    unsigned w = f < 0xfd ? 0 : f == 0xfd ? 2 : f == 0xfe ? 4 : 8;
    if (!w) { *v = f; return 1; }
    if (n - *at < w) return 0;
    *v = 0;
    for (unsigned i = 0; i < w; i++) *v |= (uint64_t)t[*at + i] << (8 * i);
    *at += w;
    return 1;
}

/* The virtual size of a serialized transaction (with or without witness). */
static size_t vsize_of(const uint8_t *t, size_t n)
{
    size_t at = 4, wstart = 0, wend = 0;
    uint64_t nin, nout, k;
    int seg = n > 6 && t[4] == 0 && t[5] == 1;
    if (seg) at += 2;
    if (!rd_var(t, n, &at, &nin)) return 0;
    for (uint64_t i = 0; i < nin; i++) {
        at += 36;
        if (!rd_var(t, n, &at, &k)) return 0;
        at += k + 4;
    }
    if (!rd_var(t, n, &at, &nout)) return 0;
    for (uint64_t i = 0; i < nout; i++) {
        at += 8;
        if (!rd_var(t, n, &at, &k)) return 0;
        at += k;
    }
    if (seg) {
        wstart = at;
        for (uint64_t i = 0; i < nin; i++) {
            uint64_t items;
            if (!rd_var(t, n, &at, &items)) return 0;
            for (uint64_t j = 0; j < items; j++) {
                if (!rd_var(t, n, &at, &k)) return 0;
                at += k;
            }
        }
        wend = at;
    }
    if (at + 4 != n) return 0;
    size_t base = n - (seg ? 2 + (wend - wstart) : 0);
    size_t weight = base * 3 + n;
    return (weight + 3) / 4;
}

static const sw_lobby_t *lobby_of(const sw_scan_t *s, const uint8_t scope[32])
{
    for (size_t i = 0; i < s->n_lobby; i++)
        if (!memcmp(s->lobby[i].scope, scope, 32)) return &s->lobby[i];
    return NULL;
}

/* One funded round: the signed tree, then the root kickoff's timeout spends. */
/* The host's factory key of a round: its per-lobby pair at (epoch, index + 1) of the lobby's slot keys
 * (core/node/signslot.c, gz_sg_keys), found by its public key among the first epochs and indices. */
static int host_factory_pair(const gzp_sweep_in_t *in, const uint8_t want[33], secp256k1_keypair *kp)
{
    uint8_t sec[32], pub[33];
    for (uint32_t e = 0; e < 4; e++)
        for (uint32_t i = 0; i < 1024; i++) {
            if (!gzp_keys_lobby_raw(in->keys, e, i, sec, pub, NULL)) continue;
            if (memcmp(pub, want, 33) == 0) {
                int ok = secp256k1_keypair_create(in->secp, kp, sec);
                OPENSSL_cleanse(sec, sizeof sec);
                if (ok) printf("sweep-key epoch=%u index=%u\n", e, i);
                return ok;
            }
        }
    OPENSSL_cleanse(sec, sizeof sec);
    return 0;
}

static int sweep_round(const gzp_sweep_in_t *in, const sw_scan_t *s, const sw_round_t *r)
{
    secp256k1_keypair hkp_s;
    const secp256k1_keypair *hkp = &hkp_s;
    uint16_t kind = 0;
    const uint8_t *scope = NULL, *records = NULL;
    size_t records_len = 0;
    gz_rmsg_propose_t m;
    gz_terms_outer_t o;
    gz_tree_params_t prm;
    gz_tree_build_in_t bi;
    gz_tree_crypto_t cr;
    gz_tree_t *t = NULL;
    factory_t *f = NULL;
    secp256k1_pubkey *pks = NULL;
    uint8_t (*keys)[33] = NULL;
    int rc = 1;
    if (gz_rmsg_open(r->proposal, r->proposal_len, &kind, &scope, &records, &records_len) != GZ_RMSG_OK ||
        gz_rmsg_propose_decode(records, records_len, &m) != GZ_RMSG_OK) {
        printf("sweep-error why=proposal-unreadable\n");
        return 1;
    }
    const sw_lobby_t *lb = lobby_of(s, scope);
    if (!lb || gz_terms_parse_outer(lb->outer, lb->outer_len, &o) != GZ_TERMS_OK) {
        printf("sweep-error why=no-terms\n");
        return 1;
    }
    const gz_tree_proposal_t *p = &m.p;
    if (p->n_participants < 2 || p->n_participants > GZ_TREE_MAX_MEMBERS + 1) return 1;
    if (!host_factory_pair(in, p->participants[0].factory_key, &hkp_s)) {
        printf("sweep-error why=not-this-host\n");
        return 1;
    }
    uint32_t n = (uint32_t)p->n_participants - 1;
    if (gz_tree_params(&o, n, &prm) != GZ_TREE_P_OK) { printf("sweep-error why=no-params\n"); goto done; }
    t = calloc(1, sizeof *t);
    keys = calloc(n, 33);
    pks = calloc(n + 1, sizeof *pks);
    f = calloc(1, sizeof *f);
    if (!t || !keys || !pks || !f) goto done;
    for (uint32_t i = 0; i < n; i++) memcpy(keys[i], p->participants[i + 1].factory_key, 33);
    memset(&bi, 0, sizeof bi);
    bi.levels = prm.levels;
    bi.n_levels = prm.n_levels;
    bi.fixed_levels = p->fixed_levels;
    bi.n_members = n;
    bi.host_key = p->participants[0].factory_key;
    bi.member_keys = (const uint8_t(*)[33])keys;
    bi.end_height = p->end_height;
    bi.tree_feerate = p->tree_feerate;
    bi.lstock_csv = p->lstock_delay;
    memcpy(bi.funding_txid, p->funding_txid, 32);
    bi.funding_vout = p->funding_vout;
    bi.funding_amount = p->funding_amount;
    memcpy(bi.funding_script, p->funding_script, 34);
    gz_tree_secp_crypto(in->secp, &cr);
    if (gz_tree_build(&bi, &cr, t) != GZ_TREE_B_OK) { printf("sweep-error why=tree\n"); goto done; }
    printf("sweep-round id=");
    hex(r->id, 32);
    printf(" members=%u nodes=%u end=%u funding=", n, (unsigned)t->n_nodes, p->end_height);
    hex_rev(p->funding_txid, 32);
    printf(":%u amount=%llu finals=%zu\n", p->funding_vout, (unsigned long long)p->funding_amount, r->n_finals);

    /* The signed tree: each node's own transaction with the final key-path signature. */
    for (uint16_t i = 0; i < t->n_nodes; i++) {
        const gz_tree_node_t *nd = &t->node[i];
        const uint8_t *sig = NULL;
        uint8_t stx[GZ_TREE_MAX_TX + 80];
        secp256k1_xonly_pubkey xk;
        for (size_t k = 0; k < r->n_finals; k++)
            if (be32(r->finals + 68 * k) == i) sig = r->finals + 68 * k + 4;
        if (!sig) { printf("sweep-error why=no-final node=%u\n", i); goto done; }
        if (!secp256k1_xonly_pubkey_parse(in->secp, &xk, nd->spent_script + 2) ||
            !secp256k1_schnorrsig_verify(in->secp, sig, nd->sighash, 32, &xk)) {
            printf("sweep-error why=final-invalid node=%u\n", i);
            goto done;
        }
        size_t sl = gz_sign_tx_attach(nd->tx, nd->tx_len, sig, stx, sizeof stx);
        if (!sl) { printf("sweep-error why=attach node=%u\n", i); goto done; }
        printf("sweep-tree node=%u parent=%d vout=%u kind=%u depth=%u first=%u count=%u cltv=%u txid=", i, nd->parent,
               nd->parent_vout, nd->kind, nd->depth, nd->first, nd->count, nd->cltv);
        hex_rev(nd->txid, 32);
        printf(" vsize=%zu tx=", vsize_of(stx, sl));
        hex(stx, sl);
        printf("\n");
    }

    /* The import's tree, for the timeout leaves (public keys only; the host signs alone). */
    if (!secp256k1_ec_pubkey_parse(in->secp, &pks[0], p->participants[0].factory_key, 33)) goto done;
    for (uint32_t i = 0; i < n; i++)
        if (!secp256k1_ec_pubkey_parse(in->secp, &pks[i + 1], keys[i], 33)) goto done;
    factory_init_from_pubkeys(f, in->secp, pks, n + 1, GZ_TREE_SLICE1_STEP, GZ_TREE_SLICE1_STATES);
    if (!f->nodes || !factory_set_level_arity(f, bi.levels, bi.n_levels)) goto done;
    factory_set_static_near_root(f, bi.fixed_levels);
    factory_set_ps_subfactory_arity(f, 1);
    factory_set_l_stock_csv(f, bi.lstock_csv);
    if (!factory_set_placement_mode(f, PLACEMENT_SEQUENTIAL)) goto done;
    f->use_tree_anchor = 1;
    f->use_hashlock_poison = 0;
    f->tree_fee_rate = bi.tree_feerate;
    f->build_quiet = 1;
    f->cltv_timeout = bi.end_height;
    if (!factory_set_funding(f, bi.funding_txid, bi.funding_vout, bi.funding_amount, bi.funding_script, 34) ||
        !factory_build_tree(f) || f->n_nodes != t->n_nodes) {
        printf("sweep-error why=import\n");
        goto done;
    }
    for (uint16_t i = 0; i < t->n_nodes; i++)
        if (f->nodes[i].unsigned_tx.len != t->node[i].tx_len ||
            memcmp(f->nodes[i].unsigned_tx.data, t->node[i].tx, t->node[i].tx_len) != 0) {
            printf("sweep-error why=import-differs node=%u\n", i);
            goto done;
        }

    /* Every output of the root kickoff that a node of the tree spends: the host's alone from its height. */
    rc = 0;
    for (uint16_t i = 1; i < t->n_nodes; i++) {
        const gz_tree_node_t *nd = &t->node[i];
        if (nd->parent != 0) continue;
        int owed = in->owed_member > 0 && (uint32_t)in->owed_member >= nd->first + 1u &&
                   (uint32_t)in->owed_member <= (uint32_t)nd->first + nd->count;
        if (owed) {
            printf("sweep-refused node=%u vout=%u why=owed member=%d\n", i, nd->parent_vout, in->owed_member);
            continue;
        }
        if (in->height < nd->cltv) {
            printf("sweep-refused node=%u vout=%u why=not-yet locktime=%u height=%u\n", i, nd->parent_vout, nd->cltv,
                   in->height);
            if (!in->force) continue;
        }
        tx_buf_t out;
        uint64_t fee = 0;
        int ok = 0;
        tx_buf_init(&out, 512);
        /* Twice: the size at a zero fee, then the fee at the tree's rate for that size, rounded up. */
        for (int pass = 0; pass < 2; pass++) {
            tx_buf_free(&out);
            tx_buf_init(&out, 512);
            ok = factory_build_timeout_spend_tx(f, f->nodes[0].txid, nd->parent_vout, nd->spent_amount, (int)i, hkp,
                                                in->to_script, in->to_len, fee ? fee : 1, &out);
            if (!ok) break;
            size_t vs = vsize_of(out.data, out.len);
            fee = (vs * in->feerate + 999) / 1000;
        }
        if (!ok || nd->spent_amount <= fee || nd->spent_amount - fee < 330) {
            printf("sweep-error why=spend node=%u\n", i);
            tx_buf_free(&out);
            rc = 1;
            continue;
        }
        printf("sweep-spend node=%u vout=%u amount=%llu fee=%llu out=%llu locktime=%u vsize=%zu tx=", i,
               nd->parent_vout, (unsigned long long)nd->spent_amount, (unsigned long long)fee,
               (unsigned long long)(nd->spent_amount - fee), nd->cltv, vsize_of(out.data, out.len));
        hex(out.data, out.len);
        printf("\n");
        tx_buf_free(&out);
    }
done:
    OPENSSL_cleanse(&hkp_s, sizeof hkp_s);
    if (f && f->nodes) factory_free(f);
    free(f);
    free(pks);
    free(keys);
    free(t);
    return rc;
}

int gzp_sweep_run(const gzp_sweep_in_t *in)
{
    sw_scan_t s;
    char err[200] = "";
    int rc = 0, any = 0;
    memset(&s, 0, sizeof s);
    if (gzp_journal_walk(in->dir, in->wallet, on_record, &s, err, sizeof err) != 0) {
        fprintf(stderr, "gazpacho: %s\n", err);
        return GZP_EXIT_DATA;
    }
    for (size_t i = 0; i < s.n_round; i++) {
        if (!s.round[i].proposal || !s.round[i].finals) continue;
        any = 1;
        if (sweep_round(in, &s, &s.round[i])) rc = GZP_EXIT_DATA;
    }
    if (!any) printf("sweep-none why=no-signed-round\n");
    for (size_t i = 0; i < s.n_lobby; i++) free(s.lobby[i].outer);
    for (size_t i = 0; i < s.n_round; i++) {
        free(s.round[i].proposal);
        free(s.round[i].finals);
    }
    fflush(stdout);
    return rc;
}
#else
typedef int gzp_sweep_release_empty;   /* the release program has no sweep */
#endif
