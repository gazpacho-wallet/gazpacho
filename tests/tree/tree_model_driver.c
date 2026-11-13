/* The C side of tests/tree/model_check.py: reads one command per line on
 * standard input, answers one line each. Uses the pure library only.
 *
 *   split L N              -> "ok d1,d2,..." | "refuse"       (L: levels, comma-separated)
 *   req L N CHANNEL FEE    -> R | "refuse"
 *   path L N MEMBER        -> "d o1,o2,..." | "refuse"
 *   params HEX N           -> "D V FEE R" | error name        (decoded outer record, any chain)
 *   exit E D N I LATE      -> "h_leaf lsc leave_by step_due unlock_by t0,t1,..."  ("-" for none)
 *   vsize K                -> vsize
 *   outer HEX              -> "<err> <digest> <re-encoded hex or ->"
 *   current OUTERHEX HEX   -> "<err> <digest> <re-encoded hex or ->"
 */
#include "gazpacho/terms.h"
#include "gazpacho/tree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t parse_levels(const char *s, uint8_t *levels)
{
    size_t n = 0;
    while (*s && n < GZ_TREE_MAX_LEVELS) {
        levels[n++] = (uint8_t)strtoul(s, (char **)&s, 10);
        if (*s == ',') s++;
    }
    return n;
}

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    unsigned v;
    while (s[0] && s[1] && n < cap && sscanf(s, "%2x", &v) == 1) { out[n++] = (uint8_t)v; s += 2; }
    return n;
}

static void hex(const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", b[i]);
}

static gz_terms_outer_t O;
static gz_terms_current_t C;

int main(void)
{
    static char line[1 << 16], a[1 << 15], b[1 << 15];
    static uint8_t buf[8192], buf2[8192];
    uint8_t levels[GZ_TREE_MAX_LEVELS], depths[1000];
    const gz_terms_policy_t any = {0};
    while (fgets(line, sizeof line, stdin)) {
        unsigned long long x1, x2, x3, x4, x5;
        if (sscanf(line, "split %s %llu", a, &x1) == 2) {
            size_t nl = parse_levels(a, levels);
            if (x1 > 1000 || !gz_tree_split(levels, nl, (uint32_t)x1, depths)) { printf("refuse\n"); continue; }
            printf("ok ");
            for (x2 = 0; x2 < x1; x2++) printf("%s%u", x2 ? "," : "", (unsigned)depths[x2]);
            printf("\n");
        } else if (sscanf(line, "req %s %llu %llu %llu", a, &x1, &x2, &x3) == 4) {
            size_t nl = parse_levels(a, levels);
            uint64_t r;
            if (gz_tree_requirement(levels, nl, (uint32_t)x1, x2, x3, &r)) printf("%llu\n", (unsigned long long)r);
            else printf("refuse\n");
        } else if (sscanf(line, "path %s %llu %llu", a, &x1, &x2) == 3) {
            size_t nl = parse_levels(a, levels), k, i;
            uint8_t outs[GZ_TREE_MAX_DEPTH + 2], d;
            k = gz_tree_member_path(levels, nl, (uint32_t)x1, (uint32_t)x2, &d, outs);
            if (!k) { printf("refuse\n"); continue; }
            printf("%u ", (unsigned)d);
            for (i = 0; i < k; i++) printf("%s%u", i ? "," : "", (unsigned)outs[i]);
            printf("\n");
        } else if (sscanf(line, "params %s %llu", a, &x1) == 2) {
            size_t n = unhex(a, buf, sizeof buf);
            gz_terms_err_t e = gz_terms_decode_outer(buf, n, &any, &O);
            gz_tree_params_t p;
            gz_tree_p_err_t pe;
            if (e != GZ_TERMS_OK) { printf("%s\n", gz_terms_err_name(e)); continue; }
            pe = gz_tree_params(&O, (uint32_t)x1, &p);
            if (pe != GZ_TREE_P_OK) { printf("params_%d\n", (int)pe); continue; }
            printf("%u %u %llu %llu\n", (unsigned)p.D, (unsigned)p.V, (unsigned long long)p.fee_per_tx, (unsigned long long)p.funding_amount);
        } else if (sscanf(line, "exit %llu %llu %llu %llu %llu", &x1, &x2, &x3, &x4, &x5) == 5) {
            const gz_exit_consts_t sig = GZ_EXIT_SIGNET_INIT, *c = &sig;
            uint32_t i;
            printf("%lld %lld %lld %lld %lld ", (long long)gz_exit_h_leaf((int64_t)x1, (uint32_t)x2),
                   (long long)gz_exit_last_safe_confirm((int64_t)x1, (uint32_t)x2, c),
                   (long long)gz_exit_leave_by((int64_t)x1, (uint32_t)x2, (uint32_t)x3, c),
                   (long long)gz_exit_step_due((int64_t)x1, (uint32_t)x2, (uint32_t)x4, (uint32_t)x3, c),
                   (long long)gz_exit_unlock_by((int64_t)x1, (uint32_t)x2, (uint32_t)x3, (int)x5, c));
            for (i = 0; i < x2 + 3; i++) {
                int none;
                long long h = (long long)gz_exit_path_timeout((int64_t)x1, (uint32_t)x2, i, &none);
                if (none) printf("%s-", i ? "," : "");
                else printf("%s%lld", i ? "," : "", h);
            }
            printf("\n");
        } else if (sscanf(line, "vsize %llu", &x1) == 1) {
            printf("%u\n", gz_tree_vsize((uint32_t)x1));
        } else if (sscanf(line, "outer %s", a) == 1) {
            size_t n = unhex(a, buf, sizeof buf), m;
            uint8_t d[32];
            gz_terms_err_t e = gz_terms_decode_outer(buf, n, &any, &O);
            gz_terms_outer_digest(buf, n, d);
            printf("%s ", gz_terms_err_name(e));
            hex(d, 32);
            m = e == GZ_TERMS_OK ? gz_terms_encode_outer(&O, buf2, sizeof buf2) : 0;
            printf(" ");
            if (m) hex(buf2, m); else printf("-");
            printf("\n");
        } else if (sscanf(line, "current %s %s", a, b) == 2) {
            size_t n = unhex(a, buf, sizeof buf), m;
            uint8_t d[32];
            gz_terms_err_t e = gz_terms_decode_outer(buf, n, &any, &O);
            if (e == GZ_TERMS_OK) {
                n = unhex(b, buf, sizeof buf);
                e = gz_terms_decode_current(buf, n, &O, &C);
                gz_terms_current_digest(buf, n, d);
            } else memset(d, 0, 32);
            printf("%s ", gz_terms_err_name(e));
            hex(d, 32);
            m = e == GZ_TERMS_OK ? gz_terms_encode_current(&C, buf2, sizeof buf2) : 0;
            printf(" ");
            if (m) hex(buf2, m); else printf("-");
            printf("\n");
        } else {
            printf("?\n");
        }
        fflush(stdout);
    }
    return 0;
}
