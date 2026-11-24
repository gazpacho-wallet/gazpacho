/* SPDX-License-Identifier: MIT */
/* The release program's passphrase layer until encrypted storage is wired in
 * (branch s5-s6-program): there is none. The wallet reads as locked, and every
 * passphrase call answers storage_failed with reason "not_built", so the API
 * says plainly that sign-in is not available yet. The test stand-in
 * (unlock_standin.c) is never compiled into this program. */
#include <string.h>

#include "gzp.h"
#include "unlock.h"
#include "unlock_impl.h"

static gzp_wallet_state_t none_state(void *ctx)
{
    (void)ctx;
    return GZP_WALLET_LOCKED;
}

static void none_attempts(void *ctx, int64_t now_ms, gzp_unlock_result_t *out)
{
    (void)ctx;
    (void)now_ms;
    memset(out, 0, sizeof *out);
    out->status = GZP_UNLOCK_OK;
}

static void none_begin(void *ctx, gzp_unlock_job_t *job)
{
    (void)ctx;
    memset(&job->result, 0, sizeof job->result);
    job->result.status = GZP_UNLOCK_STORAGE_FAILED;
    job->result.reason = "not_built";
}

static void none_finish(void *ctx, gzp_unlock_job_t *job, int64_t now_ms)
{
    (void)ctx;
    (void)job;
    (void)now_ms;
}

static int none_seed(void *ctx, uint8_t out64[64])
{
    (void)ctx;
    (void)out64;
    return -1;                                /* never unlocked */
}

static void none_lock(void *ctx)
{
    (void)ctx;
}

void gzp_unlock_impl(gzp_unlock_t *u, gzp_datadir_t *dir)
{
    (void)dir;
    u->state = none_state;
    u->attempts = none_attempts;
    u->begin = none_begin;
    u->finish = none_finish;
    u->discard = none_finish;
    u->lock = none_lock;
    u->seed = none_seed;
    u->ctx = NULL;
    gzp_log("unlock not-built: encrypted storage is not in this program yet");
}
