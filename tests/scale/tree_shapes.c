/* tree_shapes: scale check of the tree shape Gazpacho plans to use.
 *
 * Builds a factory tree with pseudo-Spilman leaves (one member per leaf) under
 * wide interior levels, using only the imported SuperScalar code, signs every
 * node in this one process with all the keys, verifies every signature, and
 * prints one table row per case.
 *
 * Every signature is checked twice. The first check is this program's own and
 * takes nothing from the imported code but the transaction bytes: it parses
 * each transaction, finds the output it spends by parsing the parent's bytes,
 * computes the BIP 341 signature hash itself (with OpenSSL's SHA-256, not the
 * imported one) and verifies the signature against the key in that output's
 * script. The second opinion is the imported factory_verify_all.
 *
 * Not part of the default CTest run. Results are recorded in
 * docs/notes/tree-scale-check.md.
 *
 * usage:
 *   tree_shapes                       run the built-in list of cases, one child
 *                                     process per case, print a Markdown table
 *   tree_shapes MEMBERS SHAPE STATIC  run one case in this process
 *   tree_shapes defects               reproduce two defects of the imported
 *                                     tree builder directly (see the note)
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
#include <openssl/sha.h>
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
#define ANCHOR_SATS       240u

typedef struct {
    size_t  members;
    uint8_t arities[FACTORY_MAX_LEVELS + 8];
    size_t  n_arities;          /* 0 = uniform pseudo-Spilman */
    uint32_t static_levels;
    char    shape_text[64];
} shape_case_t;

typedef struct {
    int      built, signed_ok, verified_imported, counter_sane;
    uint32_t layers_after_init; /* what factory_init left in the timed-layer counter */
    size_t   n_nodes, verified_own, controls_rejected, root_signers, max_signers;
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

/* ---- this program's own reading of the transactions ---- */

static uint32_t le32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static size_t read_varint(const unsigned char *p, uint64_t *v)
{
    if (p[0] < 0xfd) { *v = p[0]; return 1; }
    if (p[0] == 0xfd) { *v = (uint64_t)p[1] | (uint64_t)p[2] << 8; return 3; }
    *v = le32(p + 1);
    return 5;
}

/* An unsigned transaction with one input, as laid out in its bytes:
 * version(4) count(1)=1 txid(32) vout(4) script-length(1)=0 sequence(4)
 * output-count outputs... locktime(4). */
typedef struct {
    const unsigned char *bytes; size_t len;
    const unsigned char *prev_txid; uint32_t prev_vout, sequence;
    size_t outputs_start, outputs_end; uint64_t n_outputs;
} parsed_tx_t;

static int parse_tx(const unsigned char *u, size_t len, parsed_tx_t *tx)
{
    if (len < 4 + 1 + 41 + 1 + 4 || u[4] != 1 || u[41] != 0) return 0;
    tx->bytes = u; tx->len = len;
    tx->prev_txid = u + 5; tx->prev_vout = le32(u + 37); tx->sequence = le32(u + 42);
    size_t p = 46 + read_varint(u + 46, &tx->n_outputs);
    tx->outputs_start = p;
    for (uint64_t i = 0; i < tx->n_outputs; i++) {
        uint64_t script_len;
        if (p + 9 > len) return 0;
        p += 8;
        p += read_varint(u + p, &script_len);
        if (p + script_len > len) return 0;
        p += script_len;
    }
    tx->outputs_end = p;
    return p + 4 == len;
}

/* Output `want` of a parsed transaction: its amount and script. */
static int tx_output(const parsed_tx_t *tx, uint32_t want, uint64_t *amount,
                     const unsigned char **script, size_t *script_len)
{
    size_t p = tx->outputs_start;
    for (uint64_t i = 0; i < tx->n_outputs; i++) {
        uint64_t a = 0, sl;
        for (int k = 0; k < 8; k++) a |= (uint64_t)tx->bytes[p + k] << (8 * k);
        p += 8;
        p += read_varint(tx->bytes + p, &sl);
        if (i == want) { *amount = a; *script = tx->bytes + p; *script_len = (size_t)sl; return 1; }
        p += sl;
    }
    return 0;
}

static void sha256d(const unsigned char *data, size_t len, unsigned char out[32])
{
    unsigned char once[32];
    SHA256(data, len, once);
    SHA256(once, 32, out);
}

/* BIP 341 signature hash for the one input of `tx`, key path, default hash
 * type, spending an output of `amount` with script `script`. */
static void own_sighash(const parsed_tx_t *tx, uint64_t amount, const unsigned char *script,
                        size_t script_len, unsigned char out[32])
{
    unsigned char msg[64 + 175], *m = msg, tag[32], ser[64], amt[8];
    SHA256((const unsigned char *)"TapSighash", 10, tag);
    memcpy(m, tag, 32); m += 32;
    memcpy(m, tag, 32); m += 32;
    *m++ = 0x00;                                            /* epoch */
    *m++ = 0x00;                                            /* hash type: default */
    memcpy(m, tx->bytes, 4); m += 4;                        /* version */
    memcpy(m, tx->bytes + tx->len - 4, 4); m += 4;          /* locktime */
    SHA256(tx->prev_txid, 36, m); m += 32;                  /* the outpoint spent */
    for (int k = 0; k < 8; k++) amt[k] = (unsigned char)(amount >> (8 * k));
    SHA256(amt, 8, m); m += 32;                             /* its amount */
    ser[0] = (unsigned char)script_len;
    memcpy(ser + 1, script, script_len);
    SHA256(ser, 1 + script_len, m); m += 32;                /* its script */
    SHA256(tx->bytes + 42, 4, m); m += 32;                  /* the sequence, from the bytes */
    SHA256(tx->bytes + tx->outputs_start, tx->outputs_end - tx->outputs_start, m); m += 32;   /* outputs */
    *m++ = 0x00;                                            /* key path, no annex */
    memset(m, 0, 4); m += 4;                                /* input index */
    SHA256(msg, (size_t)(m - msg), out);
}

/* Check one node from the bytes alone. `amount_error` is added to the amount
 * of the output spent: a non-zero value must make the check fail, which is
 * how the check itself is tested. Returns 1 if everything holds:
 *   - the transaction is well formed and its ID is the double hash of its bytes;
 *   - its input names the double hash of the parent's bytes and the right output;
 *   - the signed transaction is the unsigned one plus a single 64-byte witness;
 *   - that signature verifies, under this program's own signature hash,
 *     against the key in the script of the output being spent. */
static int verify_node(const factory_t *f, const factory_node_t *nd, uint64_t amount_error)
{
    const unsigned char *u = nd->unsigned_tx.data, *s = nd->signed_tx.data, *script;
    size_t ul = nd->unsigned_tx.len, sl = nd->signed_tx.len, script_len;
    unsigned char txid[32], parent_txid[32], sighash[32];
    parsed_tx_t tx, parent;
    uint64_t amount;
    secp256k1_xonly_pubkey key;

    if (!nd->is_built || !nd->is_signed || !parse_tx(u, ul, &tx)) return 0;
    sha256d(u, ul, txid);
    if (memcmp(txid, nd->txid, 32) != 0) return 0;

    if (nd->parent_index < 0) {
        if (memcmp(tx.prev_txid, f->funding_txid, 32) != 0 || tx.prev_vout != f->funding_vout) return 0;
        amount = f->funding_amount_sats; script = f->funding_spk; script_len = f->funding_spk_len;
    } else {
        const factory_node_t *par = &f->nodes[nd->parent_index];
        if (!parse_tx(par->unsigned_tx.data, par->unsigned_tx.len, &parent)) return 0;
        sha256d(par->unsigned_tx.data, par->unsigned_tx.len, parent_txid);
        if (memcmp(tx.prev_txid, parent_txid, 32) != 0 || tx.prev_vout != nd->parent_vout) return 0;
        if (!tx_output(&parent, tx.prev_vout, &amount, &script, &script_len)) return 0;
    }
    if (script_len != 34 || script[0] != 0x51 || script[1] != 0x20) return 0;

    /* signed = version, marker 00, flag 01, the rest of the unsigned bytes up
     * to the locktime, one witness item of 64 bytes, locktime */
    if (sl != ul + 2 + 66 || memcmp(s, u, 4) != 0 || s[4] != 0 || s[5] != 1 ||
        memcmp(s + 6, u + 4, ul - 8) != 0 || s[ul - 2] != 1 || s[ul - 1] != 0x40 ||
        memcmp(s + sl - 4, u + ul - 4, 4) != 0)
        return 0;

    own_sighash(&tx, amount + amount_error, script, script_len, sighash);
    if (!secp256k1_xonly_pubkey_parse(f->ctx, &key, script + 2)) return 0;
    return secp256k1_schnorrsig_verify(f->ctx, s + ul, sighash, 32, &key);
}

/* Relative delay in blocks that a node's input imposes (BIP 68), read from
 * the sequence field in its bytes. 0 if none. */
static uint32_t relative_delay(const factory_node_t *nd)
{
    uint32_t sequence = le32(nd->unsigned_tx.data + 42);
    if (sequence & 0x80000000u) return 0;   /* relative lock disabled */
    if (sequence & 0x00400000u) return 0;   /* time-based: not used by the tree */
    return sequence & 0xFFFFu;
}

static int has_anchor(const factory_node_t *nd)
{
    for (size_t i = 0; i < nd->n_outputs; i++)
        if (nd->outputs[i].script_pubkey_len == 4 && nd->outputs[i].amount_sats == ANCHOR_SATS) return 1;
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

/* 1 if the timed-layer counter is in a state its own definition allows.
 * factory_init leaves it otherwise for 257 or more members (see the note);
 * the arity call that follows is what puts it right, and everything after
 * depends on that. */
static int counter_is_sane(const factory_t *f)
{
    uint32_t states = 1;
    if (f->counter.n_layers < 1 || f->counter.n_layers > DW_MAX_LAYERS) return 0;
    for (uint32_t i = 0; i < f->counter.n_layers; i++) states *= STATES_PER_LAYER;
    for (uint32_t i = 0; i < f->counter.n_layers; i++)
        if (f->counter.layers[i].config.step_blocks != STEP_BLOCKS ||
            f->counter.layers[i].config.max_states != STATES_PER_LAYER ||
            f->counter.layers[i].current_state != 0) return 0;
    return f->counter.total_states == states && f->counter.current_epoch == 0;
}

/* Initialise a factory for a case, up to and including the shape. Returns 0
 * on a setup error. */
static factory_t *start_factory(const shape_case_t *c, secp256k1_context *ctx,
                                const secp256k1_keypair *kps, size_t n, result_t *r)
{
    factory_t *f = calloc(1, sizeof *f);
    if (!f || !factory_init(f, ctx, kps, n, STEP_BLOCKS, STATES_PER_LAYER)) return NULL;
    r->layers_after_init = f->counter.n_layers;
    /* The arity must be set straight after factory_init: it is what repairs
     * the counter. */
    if (c->n_arities) factory_set_level_arity(f, c->arities, c->n_arities);
    else              factory_set_arity(f, FACTORY_ARITY_PS);
    if (c->static_levels) factory_set_static_near_root(f, c->static_levels);
    r->counter_sane = counter_is_sane(f);
    f->placement_mode = PLACEMENT_SEQUENTIAL;   /* order never depends on a sort */
    f->cltv_timeout = CLTV_TIMEOUT;
    f->use_tree_anchor = 1;
    return f;
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
    if (!ctx || !kps || !pks) return 0;
    if (!make_keys(ctx, n, kps, pks) || !funding_script(ctx, pks, n, spk)) return 0;

    r->ewt_shape = factory_compute_ewt_for_shape(c->n_arities ? c->arities : NULL, c->n_arities,
                                                 FACTORY_ARITY_PS, c->members, c->static_levels,
                                                 STEP_BLOCKS, STATES_PER_LAYER);
    double t0 = now_secs();
    factory_t *f = start_factory(c, ctx, kps, n, r);
    if (!f) return 0;
    factory_set_funding(f, ftxid, 0, (uint64_t)n * SATS_PER_MEMBER + 1000000u, spk, 34);
    r->built = r->counter_sane && factory_build_tree(f) && f->n_nodes > 0 &&
               memcmp(f->nodes[0].spending_spk, spk, 34) == 0;
    double t1 = now_secs();
    r->secs_build = t1 - t0;
    if (r->built) {
        r->signed_ok = factory_sign_all(f);
        double t2 = now_secs();
        r->secs_sign = t2 - t1;
        if (r->signed_ok) {
            r->verified_imported = factory_verify_all(f);
            for (size_t i = 0; i < f->n_nodes; i++) {
                r->verified_own += (size_t)verify_node(f, &f->nodes[i], 0);
                r->controls_rejected += (size_t)!verify_node(f, &f->nodes[i], 1);
            }
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
    printf("| Members | Shape | Fixed levels | Built | Signed | Verified (own check / nodes) | Own check rejects a wrong amount (nodes) | Imported verifier | "
           "Nodes | Root signers | Leaves (one-member PS / all) | Txs on longest exit | Timed txs on it | "
           "Exit delay, blocks (summed from txs) | Imported: layers after init / after shape | Imported: delay built / by shape | "
           "Largest tx, bytes (outputs) | Longest exit, bytes | Nodes without anchor | "
           "Build s | Sign s | Verify s | Peak MB |\n");
    printf("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
}

static void print_row(const shape_case_t *c, const result_t *r)
{
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("| %zu | %s | %u | %s | %s | %zu / %zu | %zu | %s | %zu | %zu | %zu / %zu | %zu | %zu | %u | %u / %u | %u / %u | "
           "%zu (%zu) | %zu | %zu | %.2f | %.2f | %.2f | %.1f |\n",
           c->members, c->shape_text, c->static_levels,
           r->built ? "yes" : r->counter_sane ? "NO" : "NO (counter not sane)", r->built ? (r->signed_ok ? "yes" : "NO") : "-",
           r->verified_own, r->n_nodes, r->controls_rejected, r->signed_ok ? (r->verified_imported ? "pass" : "FAIL") : "-",
           r->n_nodes, r->root_signers, r->ps_single_leaves, r->leaves,
           r->path_txs, r->path_timed, r->path_delay, r->layers_after_init, r->counter_layers, r->ewt_built, r->ewt_shape,
           r->max_tx_bytes, r->max_tx_outputs, r->path_bytes, r->no_anchor_nodes,
           r->secs_build, r->secs_sign, r->secs_verify, (double)ru.ru_maxrss / 1024.0);
    fflush(stdout);
}

/* 1 if the case did everything asked: built, signed, every node verified by
 * both checks, the own check refused a wrong amount at every node, and every
 * leaf is a one-member pseudo-Spilman leaf. */
static int case_ok(const result_t *r)
{
    return r->built && r->signed_ok && r->verified_imported &&
           r->verified_own == r->n_nodes && r->controls_rejected == r->n_nodes &&
           r->ps_single_leaves == r->leaves;
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

/* ---- direct reproduction of two defects in the imported tree builder ---- */

/* Build (without signing) the tree for a case. Returns NULL if it does not build. */
static factory_t *build_only(size_t members, const char *shape, secp256k1_context *ctx)
{
    shape_case_t c;
    result_t r;
    size_t n = members + 1;
    unsigned char spk[34], ftxid[32];
    secp256k1_keypair *kps = calloc(n, sizeof *kps);
    secp256k1_pubkey *pks = calloc(n, sizeof *pks);
    memset(&c, 0, sizeof c); memset(&r, 0, sizeof r); memset(ftxid, 0xaa, 32);
    c.members = members;
    if (!kps || !pks || !parse_shape(shape, &c) || !make_keys(ctx, n, kps, pks) || !funding_script(ctx, pks, n, spk)) return NULL;
    factory_t *f = start_factory(&c, ctx, kps, n, &r);
    if (!f) return NULL;
    factory_set_funding(f, ftxid, 0, (uint64_t)n * SATS_PER_MEMBER + 1000000u, spk, 34);
    free(kps); free(pks);
    return factory_build_tree(f) ? f : NULL;
}

static uint64_t outputs_total(const factory_node_t *nd)
{
    uint64_t total = 0;
    for (size_t i = 0; i < nd->n_outputs; i++) total += nd->outputs[i].amount_sats;
    return total;
}

/* A node with 16 child outputs gets no anchor, yet the anchor's 240 sats are
 * still taken out of what it passes on. Returns 1 if reproduced. */
static int defect_anchor_dropped(secp256k1_context *ctx)
{
    factory_t *f = build_only(32, "16,ps", ctx);
    size_t wide = 0, wide_without_anchor = 0, wide_overpaying = 0, others_with_anchor = 0, others_exact = 0, others = 0;
    if (!f) { printf("anchor: the 32-member 16,ps tree did not build\n"); return 0; }
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *nd = &f->nodes[i];
        uint64_t left_as_fee = nd->input_amount - outputs_total(nd);
        if (nd->n_outputs == FACTORY_MAX_OUTPUTS) {
            wide++;
            wide_without_anchor += (size_t)!has_anchor(nd);
            wide_overpaying += left_as_fee == f->fee_per_tx + ANCHOR_SATS;
        } else {
            others++;
            others_with_anchor += (size_t)has_anchor(nd);
            others_exact += left_as_fee == f->fee_per_tx;
        }
    }
    printf("anchor: 32 members, shape 16,ps, anchors on, fee %llu sats per transaction\n", (unsigned long long)f->fee_per_tx);
    printf("  nodes with %d outputs: %zu; of those without an anchor output: %zu; of those leaving fee + %u sats unspent: %zu\n",
           FACTORY_MAX_OUTPUTS, wide, wide_without_anchor, ANCHOR_SATS, wide_overpaying);
    printf("  all other nodes: %zu; with an anchor output: %zu; leaving exactly the fee: %zu\n", others, others_with_anchor, others_exact);
    int reproduced = wide > 0 && wide_without_anchor == wide && wide_overpaying == wide &&
                     others_with_anchor == others && others_exact == others;
    factory_free(f); free(f);
    return reproduced;
}

/* A wide level given no more members than its width makes one leaf of all of
 * them instead of pseudo-Spilman leaves, without reporting anything.
 * Returns 1 if reproduced. */
static int defect_leaf_type_changed(secp256k1_context *ctx)
{
    factory_t *wanted = build_only(16, "4,ps", ctx), *got = build_only(16, "8,8,ps", ctx);
    result_t a, b;
    if (!wanted || !got) { printf("leaves: a 16-member tree did not build\n"); return 0; }
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    measure(wanted, &a); measure(got, &b);
    size_t members_per_leaf = got->nodes[got->leaf_node_indices[0]].n_signers - 1;
    printf("leaves: 16 members; a shape ending in ps asks for 16 one-member pseudo-Spilman leaves\n");
    printf("  shape 4,ps:   %zu leaves, %zu of them one-member pseudo-Spilman\n", a.leaves, a.ps_single_leaves);
    printf("  shape 8,8,ps: %zu leaves, %zu of them one-member pseudo-Spilman; members in the first leaf: %zu; "
           "factory_build_tree returned success\n", b.leaves, b.ps_single_leaves, members_per_leaf);
    int reproduced = a.leaves == 16 && a.ps_single_leaves == 16 && b.leaves == 8 && b.ps_single_leaves == 0 &&
                     members_per_leaf == 2;
    factory_free(wanted); free(wanted); factory_free(got); free(got);
    return reproduced;
}

static int run_defects(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    int anchor = defect_anchor_dropped(ctx), leaves = defect_leaf_type_changed(ctx);
    printf("anchor silently dropped at %d outputs: %s\n", FACTORY_MAX_OUTPUTS, anchor ? "REPRODUCED" : "not reproduced");
    printf("leaf type silently changed: %s\n", leaves ? "REPRODUCED" : "not reproduced");
    secp256k1_context_destroy(ctx);
    return anchor && leaves ? 0 : 1;
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

    if (argc == 2 && strcmp(argv[1], "defects") == 0) return run_defects();
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
    if (argc != 1) { fprintf(stderr, "usage: %s [MEMBERS SHAPE STATIC | defects]\n", argv[0]); return 2; }

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
