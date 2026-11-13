/* exit.md section 4: vectors X1, X2 and X3 (tools/spec-vectors.py section X),
 * and the signing-time check at its boundary. */
#include "../check.h"
#include "gazpacho/tree.h"

#include <string.h>

#define TIP 290000
#define E (TIP + 144 + 36)

static const gz_exit_consts_t SIG = GZ_EXIT_SIGNET_INIT;
static const gz_exit_consts_t *C = &SIG;

static void x1(void)
{
    /* d = 1, 2, 3: every timeout on the path; the root kickoff has none; the
     * smallest is H_leaf = E - 10 d, shared by the leaf transaction and the
     * commitment. */
    static const int64_t want[3][6] = {
        {-1, E - 5, E - 10, E - 10, 0, 0},
        {-1, E - 5, E - 15, E - 20, E - 20, 0},
        {-1, E - 5, E - 15, E - 25, E - 30, E - 30},
    };
    uint32_t d, i;
    for (d = 1; d <= 3; d++) {
        int64_t lo = INT64_MAX;
        for (i = 0; i < d + 3; i++) {
            int none;
            int64_t h = gz_exit_path_timeout(E, d, i, &none);
            if (i == 0) CHECK(none);
            else { CHECK(!none && h == want[d - 1][i]); if (h < lo) lo = h; }
        }
        CHECK(lo == gz_exit_h_leaf(E, d) && lo == E - 10 * (int64_t)d);
    }
    CHECK(C->A == 6 && C->B == 3 && C->M == 14 && C->M_host == 8);
}

static void x2(void)
{
    /* The depth of every member, by member count (T1's shapes). */
    static const uint8_t L3[1] = {3}, L43[2] = {4, 3};
    static const uint8_t d3[3] = {1, 2, 2};
    uint8_t depths[16], outs[GZ_TREE_MAX_DEPTH + 2], d;
    uint32_t n, i;
    size_t k;
    CHECK(gz_tree_split(L3, 1, 3, depths) && memcmp(depths, d3, 3) == 0);
    CHECK(gz_tree_split(L3, 1, 4, depths));
    for (i = 0; i < 4; i++) CHECK(depths[i] == 2);
    for (n = 5; n <= 7; n++) {
        int one = 0, two = 0;
        CHECK(gz_tree_split(L43, 2, n, depths));
        for (i = 0; i < n; i++) { one += depths[i] == 1; two += depths[i] == 2; }
        CHECK(one > 0 && one + two == (int)n);
    }
    CHECK(gz_tree_split(L43, 2, 8, depths));
    for (i = 0; i < 8; i++) CHECK(depths[i] == 2);
    for (n = 9; n <= 15; n++) {
        int two = 0, three = 0;
        CHECK(gz_tree_split(L43, 2, n, depths));
        for (i = 0; i < n; i++) { two += depths[i] == 2; three += depths[i] == 3; }
        CHECK(two > 0 && three > 0 && two + three == (int)n);
    }
    CHECK(gz_tree_split(L43, 2, 16, depths));
    for (i = 0; i < 16; i++) CHECK(depths[i] == 3);
    /* Path shapes and sizes: (3, member 1) d = 1, kickoff outputs [2, 1, 2]. */
    k = gz_tree_member_path(L3, 1, 3, 0, &d, outs);
    CHECK(k == 3 && d == 1 && outs[0] == 2 && outs[1] == 1 && outs[2] == 2);
    k = gz_tree_member_path(L3, 1, 3, 1, &d, outs);
    CHECK(k == 4 && d == 2 && outs[0] == 2 && outs[1] == 2 && outs[2] == 1 && outs[3] == 2);
    k = gz_tree_member_path(L43, 2, 16, 15, &d, outs);
    CHECK(k == 5 && d == 3 && outs[0] == 4 && outs[1] == 2 && outs[2] == 2);
    k = gz_tree_member_path(L43, 2, 5, 0, &d, outs);   /* sizes 2, 1, 1, 1: member 1 is deeper */
    CHECK(k == 4 && d == 2 && outs[0] == 4 && outs[1] == 2);
    k = gz_tree_member_path(L43, 2, 5, 4, &d, outs);
    CHECK(k == 3 && d == 1 && outs[0] == 4);
    CHECK(gz_tree_member_path(L43, 2, 5, 5, &d, outs) == 0);   /* no such member */
    /* vsizes: 167 for two outputs, 253 for four, 124 for the leaf's kickoff. */
    CHECK(gz_tree_vsize(2) == 167 && gz_tree_vsize(4) == 253 && gz_tree_vsize(1) == 124);
}

static void x3(void)
{
    uint32_t d, i;
    for (d = 1; d <= 3; d++) {
        int64_t lb = gz_exit_leave_by(E, d, d + 3, C), lsc = gz_exit_last_safe_confirm(E, d, C);
        CHECK(lsc == E - 10 * (int64_t)d - 2);
        CHECK(gz_exit_step_due(E, d, d + 3, d + 3, C) == lsc - C->M);
        CHECK(gz_exit_step_due(E, d, 1, d + 3, C) == lb + C->A);
        for (i = 1; i < d + 3; i++)
            CHECK(gz_exit_step_due(E, d, i + 1, d + 3, C) - gz_exit_step_due(E, d, i, d + 3, C) == C->A);
        CHECK(gz_exit_host_force_by(E, d, d + 3, C) == lb + 6);   /* leave_by + M_spike */
        /* The signing-time check passes for T1 at X_TIP with a 36-block funding deadline. */
        CHECK(gz_exit_signing_check(E, d, TIP + 36, C));
    }
    CHECK(gz_exit_leave_by(E, 1, 4, C) == E - 50);
    CHECK(gz_exit_leave_by(E, 2, 5, C) == E - 66);
    CHECK(gz_exit_leave_by(E, 3, 6, C) == E - 82);
    /* d = 2 with 5, 3, 1 of 5 steps missing: E - 66, E - 54, E - 42. */
    CHECK(gz_exit_leave_by(E, 2, 3, C) == E - 54);
    CHECK(gz_exit_leave_by(E, 2, 1, C) == E - 20 - 2 - 6 - 14);
    /* unlock_by (exit.md 5.6). */
    CHECK(gz_exit_unlock_by(E, 2, 5, 0, C) == E - 42);
    CHECK(gz_exit_unlock_by(E, 2, 3, 1, C) == E - 54);
    CHECK(gz_exit_unlock_by(E, 2, 2, 1, C) == gz_exit_leave_by(E, 2, 2, C));
    CHECK(gz_exit_unlock_by(E, 2, 1, 0, C) == E - 42);
}

static void signing_check_boundary(void)
{
    /* leave_by(d = 2) = E - 66 = 290114. The check needs leave_by >= deadline
     * + B + 1, so the latest deadline is 290110. */
    CHECK(gz_exit_signing_check(E, 2, 290110, C));
    CHECK(gz_exit_signing_check(E, 2, 290109, C));
    CHECK(!gz_exit_signing_check(E, 2, 290111, C));
    /* An end height near zero gives negative dates, never a wrapped one. */
    CHECK(gz_exit_leave_by(10, 3, 6, C) < 0);
    CHECK(!gz_exit_signing_check(10, 3, 0, C));
}

int main(void)
{
    x1();
    x2();
    x3();
    signing_check_boundary();
    return check_done();
}
