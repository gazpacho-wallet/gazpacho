/* spec/exit.md sections 4.1 to 4.4 (and 5.6's unlock_by): deadline
 * arithmetic on heights. Signed 64-bit throughout: an end height near zero
 * gives dates below zero, never a wrapped huge one. */
#include "gazpacho/tree.h"

gz_exit_consts_t gz_exit_signet(void)
{
    gz_exit_consts_t c = GZ_EXIT_SIGNET_INIT;
    return c;
}

#define STEP ((int64_t)GZ_TREE_TIMEOUT_STEP)

int64_t gz_exit_path_timeout(int64_t E, uint32_t d, uint32_t i, int *none)
{
    int64_t j = i;
    if (none) *none = 0;
    if (i < d) {                          /* a fixed kickoff at depth j = i */
        if (j == 0) { if (none) *none = 1; return 0; }
        return E - (2 * j - 1) * STEP;
    }
    if (i == d) {                         /* the leaf's kickoff at depth d */
        if (d == 0) { if (none) *none = 1; return 0; }
        return E - (2 * (int64_t)d - 1) * STEP;
    }
    return gz_exit_h_leaf(E, d);          /* the leaf transaction and the commitment */
}

int64_t gz_exit_h_leaf(int64_t E, uint32_t d)
{
    return E - 2 * (int64_t)d * STEP;
}

int64_t gz_exit_last_safe_confirm(int64_t E, uint32_t d, const gz_exit_consts_t *c)
{
    return gz_exit_h_leaf(E, d) - ((int64_t)c->B - 1);
}

int64_t gz_exit_leave_by(int64_t E, uint32_t d, uint32_t n_missing, const gz_exit_consts_t *c)
{
    return gz_exit_last_safe_confirm(E, d, c) - (int64_t)n_missing * c->A - c->M;
}

int64_t gz_exit_step_due(int64_t E, uint32_t d, uint32_t i, uint32_t n_missing, const gz_exit_consts_t *c)
{
    return gz_exit_last_safe_confirm(E, d, c) - ((int64_t)n_missing - (int64_t)i) * c->A - c->M;
}

int64_t gz_exit_host_force_by(int64_t E, uint32_t d, uint32_t n_host, const gz_exit_consts_t *c)
{
    return gz_exit_last_safe_confirm(E, d, c) - (int64_t)n_host * c->A - c->M_host;
}

int64_t gz_exit_unlock_by(int64_t E, uint32_t d, uint32_t n_missing, int tree_late, const gz_exit_consts_t *c)
{
    if (!tree_late) return gz_exit_last_safe_confirm(E, d, c) - c->A - c->M;
    return gz_exit_leave_by(E, d, n_missing, c);
}

int gz_exit_signing_check(int64_t E, uint32_t d, int64_t funding_deadline, const gz_exit_consts_t *c)
{
    return gz_exit_leave_by(E, d, d + 3, c) >= funding_deadline + (int64_t)c->B + 1;
}
