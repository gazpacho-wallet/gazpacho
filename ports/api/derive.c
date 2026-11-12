/* SPDX-License-Identifier: MIT */
/* The derivation slot (spec/local-api.md 4.3; storage 8.2): passphrase
 * operations run one at a time on a thread of their own, with at most one
 * waiting. A request that finds both places taken is answered rate_limited by
 * the caller, without counting as wrong. Finished jobs return to the loop
 * thread through a pipe. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"

void gz_job_free(gz_job *j)
{
    if (!j) return;
    if (j->pass) {
        gz_wipe(j->pass, j->pass_len);
        free(j->pass);
    }
    gz_wipe(j, sizeof *j);
    free(j);
}

static void *worker(void *arg)
{
    gz_api_server *srv = arg;
    pthread_mutex_lock(&srv->mu);
    for (;;) {
        gz_job *j;
        while (!srv->worker_quit && !srv->running) pthread_cond_wait(&srv->cv, &srv->mu);
        if (srv->worker_quit) break;
        j = srv->running;
        pthread_mutex_unlock(&srv->mu);
        srv->be->passphrase_op(srv->bectx, &j->pp);
        pthread_mutex_lock(&srv->mu);
        j->next = srv->done;
        srv->done = j;
        srv->running = srv->queued;                     /* the waiting job starts next */
        srv->queued = NULL;
        {
            char b = 1;
            ssize_t w = write(srv->done_pipe[1], &b, 1);
            (void)w;
        }
    }
    pthread_mutex_unlock(&srv->mu);
    return NULL;
}

int gz_derive_start(gz_api_server *srv)
{
    if (srv->cfg.sync_derivation) return 0;
    if (pthread_mutex_init(&srv->mu, NULL) != 0) return -1;
    if (pthread_cond_init(&srv->cv, NULL) != 0) return -1;
    if (pthread_create(&srv->worker, NULL, worker, srv) != 0) return -1;
    srv->worker_started = 1;
    return 0;
}

void gz_derive_stop(gz_api_server *srv)
{
    gz_job *j;
    if (!srv->worker_started) return;
    pthread_mutex_lock(&srv->mu);
    srv->worker_quit = 1;
    pthread_cond_signal(&srv->cv);
    pthread_mutex_unlock(&srv->mu);
    pthread_join(srv->worker, NULL);
    srv->worker_started = 0;
    while ((j = srv->done)) { srv->done = j->next; gz_job_free(j); }
    gz_job_free(srv->running);
    gz_job_free(srv->queued);
    srv->running = srv->queued = NULL;
    pthread_mutex_destroy(&srv->mu);
    pthread_cond_destroy(&srv->cv);
}

int gz_derive_submit(gz_api_server *srv, gz_job *j)
{
    int concurrent;
    j->pp.passphrase = j->pass;
    j->pp.passphrase_len = j->pass_len;
    j->next = NULL;
    if (srv->cfg.sync_derivation) {
        srv->ctr.derivations_started++;
        if (srv->ctr.derivations_max_concurrent < 1) srv->ctr.derivations_max_concurrent = 1;
        srv->be->passphrase_op(srv->bectx, &j->pp);
        gz_job_finished(srv, j);
        return 0;
    }
    pthread_mutex_lock(&srv->mu);
    if (!srv->running) {
        srv->running = j;
        pthread_cond_signal(&srv->cv);
    } else if (!srv->queued) {
        srv->queued = j;
        if (srv->ctr.derivations_queued_max < 1) srv->ctr.derivations_queued_max = 1;
    } else {
        pthread_mutex_unlock(&srv->mu);
        return -1;                                      /* both places taken */
    }
    srv->ctr.derivations_started++;
    concurrent = 1;                                     /* only ever one running */
    if (srv->ctr.derivations_max_concurrent < concurrent) srv->ctr.derivations_max_concurrent = concurrent;
    pthread_mutex_unlock(&srv->mu);
    return 0;
}

/* Loop thread: answer every finished job. */
void gz_derive_collect(gz_api_server *srv)
{
    gz_job *list, *j;
    char b[64];
    if (!srv->worker_started) return;
    while (read(srv->done_pipe[0], b, sizeof b) > 0) {
    }
    pthread_mutex_lock(&srv->mu);
    list = srv->done;
    srv->done = NULL;
    if (srv->running) pthread_cond_signal(&srv->cv);
    pthread_mutex_unlock(&srv->mu);
    /* the list is newest first; answer in the order they ran */
    {
        gz_job *rev = NULL;
        while ((j = list)) { list = j->next; j->next = rev; rev = j; }
        list = rev;
    }
    while ((j = list)) {
        list = j->next;
        j->next = NULL;
        gz_job_finished(srv, j);
    }
}
