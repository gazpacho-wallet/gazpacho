/* test_reference_tree: rebuild the SuperScalar factory tree for 4 and 8 clients
 * from the documented fixed inputs and compare every transaction ID (and the
 * funding scriptPubKey and per-node metadata) with
 * tests/reference/superscalar-tree-txids.txt.
 *
 * Inputs (see the header of the reference file):
 *   participant i (0 = LSP, 1..N = clients, slot order) has secret key = integer (i+1)
 *   funding outpoint aaaa...aa:0, 1,000,000 sats, cltv 1000, step_blocks 10,
 *   states_per_layer 4, leaf arity FACTORY_ARITY_PS, use_tree_anchor = 1,
 *   placement = factory_init_from_pubkeys default.
 * A third case replays the cross-check against a real regtest run
 * (4 clients, secret keys 1,2,3,5,4, funding 3039...ce2f:0, cltv 247).
 *
 * usage: test_reference_tree [reference-file]
 * exit 0 = all match, 1 = mismatch (names the node), 2 = setup/IO error. */
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Defined in the imported util.c, not declared in any imported header. */
extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

#ifndef GZ_REFERENCE_FILE
#define GZ_REFERENCE_FILE "tests/reference/superscalar-tree-txids.txt"
#endif

#define MAXLINES 64
#define LINELEN  512

typedef struct { char l[MAXLINES][LINELEN]; size_t n; } lines_t;

static int g_fail = 0;

/* Build the tree; fill out with "funding_spk", "n_clients ..." and "node ..." lines
 * in the exact format of the reference file. */
static int gen_tree(size_t nc, const unsigned char *keys, const char *ftxid_hex,
                    uint32_t fvout, uint64_t famt, uint32_t cltv, lines_t *out)
{
    const uint16_t step = 10;
    const uint32_t spl = 4;
    size_t n = nc + 1;
    unsigned char ftxid[32];
    if (!hex_decode(ftxid_hex, ftxid, 32)) return 0;
    reverse_bytes(ftxid, 32);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[64]; secp256k1_pubkey pks[64];
    for (size_t i = 0; i < n; i++) {
        unsigned char sk[32]; memset(sk, 0, 32); sk[31] = keys[i];
        if (!secp256k1_keypair_create(ctx, &kps[i], sk)) return 0;
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, n)) return 0;
    unsigned char internal_ser[32], tweak[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey);
    sha256_tagged("TapTweak", internal_ser, 32, tweak);
    musig_keyagg_t tmp = ka; secp256k1_pubkey tpk; secp256k1_xonly_pubkey txo;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &tmp.cache, tweak)) return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &txo, NULL, &tpk)) return 0;
    unsigned char spk[34]; build_p2tr_script_pubkey(spk, &txo);
    char hx[200]; hex_encode(spk, 34, hx);
    snprintf(out->l[out->n++], LINELEN, "funding_spk %s", hx);

    factory_t *f = calloc(1, sizeof(*f));
    if (!f || !factory_alloc_default_arrays(f)) return 0;
    factory_set_arity(f, FACTORY_ARITY_PS);
    factory_free(f);  /* same sequence as superscalar_lsp's stateless creation path */
    factory_init_from_pubkeys(f, ctx, pks, n, step, spl);
    factory_set_arity(f, FACTORY_ARITY_PS);
    f->cltv_timeout = cltv;
    f->use_tree_anchor = 1;
    factory_set_funding(f, ftxid, fvout, famt, spk, 34);
    if (!factory_build_tree(f)) { fprintf(stderr, "factory_build_tree failed\n"); return 0; }
    snprintf(out->l[out->n++], LINELEN,
             "n_clients %zu n_nodes %zu fee_per_tx %llu cltv %u step %u states_per_layer %u",
             nc, f->n_nodes, (unsigned long long)f->fee_per_tx, cltv, step, spl);
    for (size_t i = 0; i < f->n_nodes && out->n < MAXLINES; i++) {
        factory_node_t *nd = &f->nodes[i];
        unsigned char t[32]; memcpy(t, nd->txid, 32); reverse_bytes(t, 32);
        hex_encode(t, 32, hx);
        snprintf(out->l[out->n++], LINELEN,
                 "node %zu type %s parent %d vout %u n_outputs %zu unsigned_len %zu txid %s", i,
                 nd->type == NODE_KICKOFF ? "kickoff" : nd->type == NODE_STATE ? "state" : "ps_subfactory",
                 nd->parent_index, nd->parent_vout, nd->n_outputs, nd->unsigned_tx.len, hx);
    }
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

static void trim(char *s) { size_t k = strlen(s); while (k && (s[k-1] == '\n' || s[k-1] == '\r' || s[k-1] == ' ')) s[--k] = 0; }

static const char *txid_of(const char *line) { const char *p = strstr(line, " txid "); return p ? p + 6 : ""; }

/* Compare generated lines with the reference lines of one section. */
static void compare(const char *label, const lines_t *got, const lines_t *ref)
{
    if (got->n != ref->n) {
        printf("FAIL %s: line count differs (reference %zu, built %zu)\n", label, ref->n, got->n);
        g_fail = 1;
    }
    size_t m = got->n < ref->n ? got->n : ref->n, bad = 0;
    for (size_t i = 0; i < m; i++) {
        if (strcmp(got->l[i], ref->l[i]) == 0) continue;
        bad++; g_fail = 1;
        if (strncmp(got->l[i], "node ", 5) == 0) {
            size_t idx = (size_t)strtoul(got->l[i] + 5, NULL, 10);
            if (strcmp(txid_of(got->l[i]), txid_of(ref->l[i])) != 0)
                printf("FAIL %s: node %zu txid differs\n  reference %s\n  built     %s\n", label, idx,
                       txid_of(ref->l[i]), txid_of(got->l[i]));
            else
                printf("FAIL %s: node %zu metadata differs\n  reference %s\n  built     %s\n", label, idx, ref->l[i], got->l[i]);
        } else {
            printf("FAIL %s: line differs\n  reference %s\n  built     %s\n", label, ref->l[i], got->l[i]);
        }
    }
    if (!bad && got->n == ref->n) printf("ok   %s: %zu lines match\n", label, got->n);
}

/* Read the reference section whose header line contains `marker` (stop at blank line). */
static int read_section(FILE *fp, const char *marker, lines_t *out, int crosscheck)
{
    char buf[LINELEN];
    rewind(fp);
    int in = 0;
    while (fgets(buf, sizeof buf, fp)) {
        trim(buf);
        if (!in) { if (strstr(buf, marker)) in = 1; continue; }
        if (crosscheck) {
            if (strncmp(buf, "node ", 5) == 0 && out->n < MAXLINES) strcpy(out->l[out->n++], buf);
            continue;
        }
        if (buf[0] == 0) { if (out->n) break; else continue; }
        if (strncmp(buf, "(run twice", 10) == 0) continue;
        if (out->n < MAXLINES) strcpy(out->l[out->n++], buf);
    }
    return in && out->n > 0;
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : GZ_REFERENCE_FILE;
    const char *FT = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    FILE *fp = fopen(path, "r");
    if (!fp) { fprintf(stderr, "cannot open reference file %s\n", path); return 2; }

    static lines_t ref, got;
    unsigned char keys[16];
    for (int i = 0; i < 16; i++) keys[i] = (unsigned char)(i + 1);

    const int sizes[2] = {4, 8};
    for (int s = 0; s < 2; s++) {
        char marker[64], label[64];
        snprintf(marker, sizeof marker, "N=%d clients", sizes[s]);
        snprintf(label, sizeof label, "N=%d", sizes[s]);
        memset(&ref, 0, sizeof ref); memset(&got, 0, sizeof got);
        if (!read_section(fp, marker, &ref, 0)) { fprintf(stderr, "reference section '%s' not found\n", marker); return 2; }
        if (!gen_tree((size_t)sizes[s], keys, FT, 0, 1000000, 1000, &got)) { fprintf(stderr, "tree build failed (%s)\n", label); return 2; }
        compare(label, &got, &ref);
    }

    /* Cross-check against the real regtest run: only the 14 txids are recorded. */
    {
        unsigned char k2[5] = {1, 2, 3, 5, 4};
        memset(&ref, 0, sizeof ref); memset(&got, 0, sizeof got);
        if (!read_section(fp, "Cross-check against a real regtest run", &ref, 1)) { fprintf(stderr, "cross-check section not found\n"); return 2; }
        if (!gen_tree(4, k2, "303946d2e446b1ff7141f96c1d9b44e08fa40ca424362a6f457a59347f93ce2f", 0, 1000000, 247, &got)) return 2;
        size_t bad = 0, cnt = 0;
        for (size_t i = 2; i < got.n; i++) {          /* skip funding_spk, n_clients */
            size_t idx = i - 2; cnt++;
            char want[LINELEN];
            if (idx >= ref.n) { bad++; printf("FAIL real-run: node %zu missing in reference\n", idx); continue; }
            snprintf(want, sizeof want, "%s", strrchr(ref.l[idx], ' ') + 1);
            if (strcmp(want, txid_of(got.l[i])) != 0) {
                bad++; printf("FAIL real-run: node %zu txid differs\n  reference %s\n  built     %s\n", idx, want, txid_of(got.l[i]));
            }
        }
        if (cnt != ref.n) { bad++; printf("FAIL real-run: node count differs (reference %zu, built %zu)\n", ref.n, cnt); }
        if (bad) g_fail = 1; else printf("ok   real-run cross-check: %zu txids match\n", cnt);
    }
    fclose(fp);
    printf(g_fail ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return g_fail ? 1 : 0;
}
