/* tree_shapes: scale check of the tree shape Gazpacho plans to use.
 *
 * Builds a factory tree with pseudo-Spilman leaves (one member per leaf) under
 * wide interior levels, using only the imported SuperScalar code, signs every
 * node in this one process with all the keys, verifies every signature, and
 * prints one table row per case.
 *
 * Not part of the default CTest run. Results are recorded in
 * docs/notes/tree-scale-check.md.
 *
 * usage:
 *   tree_shapes                       run the built-in list of cases, one child
 *                                     process per case, print a Markdown table
 *   tree_shapes MEMBERS SHAPE STATIC  run one case in this process
 *
 *   MEMBERS  number of members (the host is added as participant 0)
 *   SHAPE    "ps" for pseudo-Spilman leaves under two-way levels all the way,
 *            or a comma list of level widths from the root down ending in
 *            "ps", for example "16,ps" or "8,8,ps"
 *   STATIC   number of levels from the root that are fixed (no timed layer)
 *
 * Inputs are deterministic: participant i has secret key = 32-byte big-endian
 * integer i+1, funding outpoint aa..aa:0, placement sequential. Signing nonces
 * are not deterministic (the imported code reads /dev/urandom), so signatures
 * differ between runs; transaction IDs do not. */
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>

#define STEP_BLOCKS       144
#define STATES_PER_LAYER  4
#define CLTV_TIMEOUT      100000u
#define SATS_PER_MEMBER   100000u
#define CASE_TIMEOUT_SECS 900

typedef struct {
    size_t  members;
    uint8_t arities[FACTORY_MAX_LEVELS + 8];
    size_t  n_arities;          /* 0 = uniform pseudo-Spilman */
    uint32_t static_levels;
    char    shape_text[64];
} shape_case_t;

typedef struct {
    int      built, signed_ok, verified_imported;
    size_t   n_nodes, verified_own, root_signers, max_signers;
    size_t   leaves, ps_single_leaves;
    size_t   path_txs;          /* transactions on the longest exit path */
    size_t   path_timed;        /* of those, how many carry a relative delay */
    uint32_t path_delay;        /* largest sum of relative delays on any exit path */
    size_t   path_bytes;        /* largest signed size of any exit path */
    uint32_t counter_layers;    /* timed layers in the imported counter */
    uint32_t ewt_built, ewt_shape;
    size_t   max_tx_bytes, max_tx_outputs, no_anchor_nodes;
    double   secs_build, secs_sign, secs_verify;
} result_t;

static double now_secs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Parse "ps" or "16,8,ps" into a case. Returns 0 on a malformed shape. */
static int parse_shape(const char *text, shape_case_t *c)
{
    char buf[64];
    snprintf(c->shape_text, sizeof c->shape_text, "%s", text);
    snprintf(buf, sizeof buf, "%s", text);
    c->n_arities = 0;
    if (strcmp(buf, "ps") == 0) return 1;
    for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
        if (c->n_arities >= sizeof c->arities) return 0;
        if (strcmp(tok, "ps") == 0) {
            c->arities[c->n_arities++] = (uint8_t)FACTORY_ARITY_PS;
            continue;
        }
        long v = strtol(tok, NULL, 10);
        if (v < 4 || v > 255) return 0;   /* 1, 2 and 3 have special meanings upstream */
        c->arities[c->n_arities++] = (uint8_t)v;
    }
    return c->n_arities > 0 && c->arities[c->n_arities - 1] == FACTORY_ARITY_PS;
}

/* Deterministic keys: participant i has secret key i+1. */
static int make_keys(const secp256k1_context *ctx, size_t n,
                     secp256k1_keypair *kps, secp256k1_pubkey *pks)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char sk[32] = {0};
        uint32_t v = (uint32_t)(i + 1);
        sk[28] = (unsigned char)(v >> 24); sk[29] = (unsigned char)(v >> 16);
        sk[30] = (unsigned char)(v >> 8);  sk[31] = (unsigned char)v;
        if (!secp256k1_keypair_create(ctx, &kps[i], sk)) return 0;
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }
    return 1;
}

/* Funding script: key-path-only taproot output of everyone's aggregate key,
 * computed the same way tests/test_reference_tree.c does. */
static int funding_script(const secp256k1_context *ctx, const secp256k1_pubkey *pks,
                          size_t n, unsigned char spk[34])
{
    musig_keyagg_t ka;
    unsigned char internal[32], tweak[32];
    secp256k1_pubkey tweaked;
    secp256k1_xonly_pubkey tweaked_x;
    if (!musig_aggregate_keys(ctx, &ka, pks, n)) return 0;
    secp256k1_xonly_pubkey_serialize(ctx, internal, &ka.agg_pubkey);
    sha256_tagged("TapTweak", internal, 32, tweak);
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked, &ka.cache, tweak)) return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_x, NULL, &tweaked)) return 0;
    build_p2tr_script_pubkey(spk, &tweaked_x);
    return 1;
}

/* The output a node spends: its parent's output, or the funding output. */
static void spent_output(const factory_t *f, const factory_node_t *nd,
                         const unsigned char **spk, size_t *spk_len, uint64_t *amount)
{
    if (nd->parent_index < 0) {
        *spk = f->funding_spk; *spk_len = f->funding_spk_len; *amount = f->funding_amount_sats;
        return;
    }
    const tx_output_t *o = &f->nodes[nd->parent_index].outputs[nd->parent_vout];
    *spk = o->script_pubkey; *spk_len = o->script_pubkey_len; *amount = o->amount_sats;
}

/* Check one node without trusting the imported verifier's bookkeeping:
 * the transaction ID is the double hash of the unsigned bytes, the input points
 * at the parent's transaction and output, and the signature in the signed
 * transaction verifies against the key in the script of the output it spends. */
static int verify_node(const factory_t *f, const factory_node_t *nd)
{
    const unsigned char *spk; size_t spk_len; uint64_t amount;
    unsigned char txid[32], sighash[32];
    secp256k1_xonly_pubkey key;

    if (!nd->is_built || !nd->is_signed) return 0;
    if (nd->unsigned_tx.len < 41 || nd->signed_tx.len < 70) return 0;
    sha256_double(nd->unsigned_tx.data, nd->unsigned_tx.len, txid);
    if (memcmp(txid, nd->txid, 32) != 0) return 0;

    const unsigned char *in = nd->unsigned_tx.data + 5;   /* version(4) + input count(1) */
    const unsigned char *want_txid = nd->parent_index < 0
        ? f->funding_txid : f->nodes[nd->parent_index].txid;
    uint32_t want_vout = nd->parent_index < 0 ? f->funding_vout : nd->parent_vout;
    uint32_t vout = (uint32_t)in[32] | (uint32_t)in[33] << 8 | (uint32_t)in[34] << 16 | (uint32_t)in[35] << 24;
    if (nd->unsigned_tx.data[4] != 1 || memcmp(in, want_txid, 32) != 0 || vout != want_vout) return 0;

    spent_output(f, nd, &spk, &spk_len, &amount);
    if (spk_len != 34 || spk[0] != 0x51 || spk[1] != 0x20) return 0;
    if (!secp256k1_xonly_pubkey_parse(f->ctx, &key, spk + 2)) return 0;
    if (!compute_taproot_sighash(sighash, nd->unsigned_tx.data, nd->unsigned_tx.len,
                                 0, spk, spk_len, amount, nd->nsequence)) return 0;
    return secp256k1_schnorrsig_verify(f->ctx, nd->signed_tx.data + nd->signed_tx.len - 68,
                                       sighash, 32, &key);
}

/* Relative delay in blocks that a node's input imposes (BIP 68), 0 if none. */
static uint32_t relative_delay(const factory_node_t *nd)
{
    if (nd->nsequence & 0x80000000u) return 0;   /* relative lock disabled */
    if (nd->nsequence & 0x00400000u) return 0;   /* time-based: not used by the tree */
    return nd->nsequence & 0xFFFFu;
}

static int has_anchor(const factory_node_t *nd)
{
    for (size_t i = 0; i < nd->n_outputs; i++)
        if (nd->outputs[i].script_pubkey_len == 4 && nd->outputs[i].amount_sats == 240) return 1;
    return 0;
}

/* Fill the per-path and per-node measurements from a built (and signed) tree. */
static void measure(const factory_t *f, result_t *r)
{
    r->n_nodes = f->n_nodes;
    r->root_signers = f->nodes[0].n_signers;
    r->leaves = (size_t)f->n_leaf_nodes;
    r->counter_layers = f->counter.n_layers;
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *nd = &f->nodes[i];
        if (nd->n_signers > r->max_signers) r->max_signers = nd->n_signers;
        if (nd->signed_tx.len > r->max_tx_bytes) {
            r->max_tx_bytes = nd->signed_tx.len;
            r->max_tx_outputs = nd->n_outputs;
        }
        if (!has_anchor(nd)) r->no_anchor_nodes++;
    }
    for (int l = 0; l < f->n_leaf_nodes; l++) {
        const factory_node_t *leaf = &f->nodes[f->leaf_node_indices[l]];
        size_t txs = 0, timed = 0, bytes = 0; uint32_t delay = 0;
        if (leaf->is_ps_leaf && leaf->n_signers == 2 && leaf->n_subfactories == 0)
            r->ps_single_leaves++;
        for (int idx = (int)f->leaf_node_indices[l]; idx >= 0; idx = f->nodes[idx].parent_index) {
            const factory_node_t *nd = &f->nodes[idx];
            txs++; bytes += nd->signed_tx.len;
            delay += relative_delay(nd);
            if (relative_delay(nd)) timed++;
        }
        if (txs > r->path_txs) r->path_txs = txs;
        if (timed > r->path_timed) r->path_timed = timed;
        if (delay > r->path_delay) r->path_delay = delay;
        if (bytes > r->path_bytes) r->path_bytes = bytes;
    }
}

/* Build, sign and verify one case. Returns 0 only on a setup error. */
static int run_case(const shape_case_t *c, result_t *r)
{
    size_t n = c->members + 1;
    unsigned char spk[34], ftxid[32];
    memset(r, 0, sizeof *r);
    memset(ftxid, 0xaa, 32);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair *kps = calloc(n, sizeof *kps);
    secp256k1_pubkey *pks = calloc(n, sizeof *pks);
    factory_t *f = calloc(1, sizeof *f);
    if (!ctx || !kps || !pks || !f) return 0;
    if (!make_keys(ctx, n, kps, pks) || !funding_script(ctx, pks, n, spk)) return 0;

    r->ewt_shape = factory_compute_ewt_for_shape(c->n_arities ? c->arities : NULL, c->n_arities,
                                                 FACTORY_ARITY_PS, c->members, c->static_levels,
                                                 STEP_BLOCKS, STATES_PER_LAYER);
    double t0 = now_secs();
    if (!factory_init(f, ctx, kps, n, STEP_BLOCKS, STATES_PER_LAYER)) return 0;
    if (c->n_arities) factory_set_level_arity(f, c->arities, c->n_arities);
    else              factory_set_arity(f, FACTORY_ARITY_PS);
    if (c->static_levels) factory_set_static_near_root(f, c->static_levels);
    f->placement_mode = PLACEMENT_SEQUENTIAL;   /* order never depends on a sort */
    f->cltv_timeout = CLTV_TIMEOUT;
    f->use_tree_anchor = 1;
    factory_set_funding(f, ftxid, 0, (uint64_t)n * SATS_PER_MEMBER + 1000000u, spk, 34);
    r->built = factory_build_tree(f) && f->n_nodes > 0 &&
               memcmp(f->nodes[0].spending_spk, spk, 34) == 0;
    double t1 = now_secs();
    r->secs_build = t1 - t0;
    if (r->built) {
        r->signed_ok = factory_sign_all(f);
        double t2 = now_secs();
        r->secs_sign = t2 - t1;
        if (r->signed_ok) {
            r->verified_imported = factory_verify_all(f);
            for (size_t i = 0; i < f->n_nodes; i++)
                r->verified_own += (size_t)verify_node(f, &f->nodes[i]);
            r->secs_verify = now_secs() - t2;
        }
        r->ewt_built = factory_early_warning_time(f);
        measure(f, r);
    }
    factory_free(f); free(f); free(kps); free(pks);
    secp256k1_context_destroy(ctx);
    return 1;
}

static void print_header(void)
{
    printf("| Members | Shape | Fixed levels | Built | Signed | Verified (own check / nodes) | Imported verifier | "
           "Nodes | Root signers | Leaves (one-member PS / all) | Txs on longest exit | Timed txs on it | "
           "Exit delay, blocks (summed from txs) | Imported: layers | Imported: delay built / by shape | "
           "Largest tx, bytes (outputs) | Longest exit, bytes | Nodes without anchor | "
           "Build s | Sign s | Verify s | Peak MB |\n");
    printf("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
}

static void print_row(const shape_case_t *c, const result_t *r)
{
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("| %zu | %s | %u | %s | %s | %zu / %zu | %s | %zu | %zu | %zu / %zu | %zu | %zu | %u | %u | %u / %u | "
           "%zu (%zu) | %zu | %zu | %.2f | %.2f | %.2f | %.1f |\n",
           c->members, c->shape_text, c->static_levels,
           r->built ? "yes" : "NO", r->built ? (r->signed_ok ? "yes" : "NO") : "-",
           r->verified_own, r->n_nodes, r->signed_ok ? (r->verified_imported ? "pass" : "FAIL") : "-",
           r->n_nodes, r->root_signers, r->ps_single_leaves, r->leaves,
           r->path_txs, r->path_timed, r->path_delay, r->counter_layers, r->ewt_built, r->ewt_shape,
           r->max_tx_bytes, r->max_tx_outputs, r->path_bytes, r->no_anchor_nodes,
           r->secs_build, r->secs_sign, r->secs_verify, (double)ru.ru_maxrss / 1024.0);
    fflush(stdout);
}

/* 1 if the case did everything asked: built, signed, every node verified by
 * both checks, and every leaf is a one-member pseudo-Spilman leaf. */
static int case_ok(const result_t *r)
{
    return r->built && r->signed_ok && r->verified_imported &&
           r->verified_own == r->n_nodes && r->ps_single_leaves == r->leaves;
}

/* Run one case in a child process so a crash or a limit in the imported code
 * ends that case only, and peak memory is measured per case. */
static int run_in_child(const shape_case_t *c)
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) return 0;
    if (pid == 0) {
        result_t r;
        alarm(CASE_TIMEOUT_SECS);
        if (!run_case(c, &r)) { printf("| %zu | %s | %u | setup error |\n", c->members, c->shape_text, c->static_levels); _exit(2); }
        print_row(c, &r);
        _exit(case_ok(&r) ? 0 : 1);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return 0;
    if (WIFSIGNALED(status))
        printf("| %zu | %s | %u | ENDED BY SIGNAL %d |\n", c->members, c->shape_text, c->static_levels, WTERMSIG(status));
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(int argc, char **argv)
{
    static const size_t sizes[] = {16, 32, 64, 127, 255, 256, 512, 1000};
    static const struct { const char *shape; uint32_t fixed; } shapes[] = {
        {"ps", 0}, {"4,ps", 0}, {"8,ps", 0}, {"16,ps", 0}, {"16,ps", 1},
        {"4,4,ps", 0}, {"8,8,ps", 0}, {"8,8,ps", 2}, {"15,15,ps", 2},
        {"16,16,ps", 0}, {"16,16,ps", 2}, {"16,16,16,ps", 3},
    };
    shape_case_t c;
    result_t r;

    if (argc == 4) {
        memset(&c, 0, sizeof c);
        c.members = (size_t)strtoul(argv[1], NULL, 10);
        c.static_levels = (uint32_t)strtoul(argv[3], NULL, 10);
        if (c.members < 1 || !parse_shape(argv[2], &c)) { fprintf(stderr, "bad arguments\n"); return 2; }
        if (!run_case(&c, &r)) { fprintf(stderr, "setup error\n"); return 2; }
        print_header();
        print_row(&c, &r);
        return case_ok(&r) ? 0 : 1;
    }
    if (argc != 1) { fprintf(stderr, "usage: %s [MEMBERS SHAPE STATIC]\n", argv[0]); return 2; }

    size_t ok = 0, total = 0;
    print_header();
    for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
        for (size_t k = 0; k < sizeof shapes / sizeof shapes[0]; k++) {
            memset(&c, 0, sizeof c);
            c.members = sizes[s];
            c.static_levels = shapes[k].fixed;
            if (!parse_shape(shapes[k].shape, &c)) return 2;
            total++;
            ok += (size_t)run_in_child(&c);
        }
    }
    printf("\n%zu of %zu cases built, signed, verified and had one member per pseudo-Spilman leaf.\n", ok, total);
    return 0;
}
