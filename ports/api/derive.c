/* SPDX-License-Identifier: MIT */
/* The derivation slot (spec/local-api.md 4.3; storage 8.2): passphrase
 * operations run one at a time on a thread of their own, with at most one
 * waiting. A request that finds both places taken is answered rate_limited by
 * the caller, without counting as wrong.
 *
 * The two places are the loop thread's: the worker only runs the job it is
 * handed and returns it through a pipe. A finished job keeps its place until
 * the loop has collected it and counted its result, and only then does the
 * waiting job start, after the attempts delay is checked again (review F2):
 * so neither the waiting job nor a request arriving between "derived" and
 * "collected" can pass a delay that the running job's wrong result opens.
 *
 * Generations (contract-v2 section 4): every job records the generation it was
 * submitted under; one that finishes under a newer one is discarded (nothing
 * installed) but its result is still counted. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
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

uint64_t gz_generation(gz_api_server *srv)
{
    uint64_t g;
    pthread_mutex_lock(&srv->notify_mu);
    g = srv->generation;
    pthread_mutex_unlock(&srv->notify_mu);
    return g;
}

void gz_api_server_new_generation(gz_api_server *srv)
{
    pthread_mutex_lock(&srv->notify_mu);
    srv->generation++;
    pthread_mutex_unlock(&srv->notify_mu);
}

static void *worker(void *arg)
{
    gz_api_server *srv = arg;
    pthread_mutex_lock(&srv->mu);
    for (;;) {
        gz_job *j;
        while (!srv->worker_quit && !srv->to_run) pthread_cond_wait(&srv->cv, &srv->mu);
        if (srv->worker_quit) break;
        j = srv->to_run;
        srv->to_run = NULL;
        pthread_mutex_unlock(&srv->mu);
        srv->be->passphrase_op(srv->bectx, &j->pp);    /* derives only (api_backend.h) */
        pthread_mutex_lock(&srv->mu);
        j->next = srv->done;
        srv->done = j;
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

/* Joins the thread; every job not yet answered is answered as not checked
 * (shutdown) and wiped. */
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
    while ((j = srv->done)) {
        srv->done = j->next;
        if (j == srv->slot_running) srv->slot_running = NULL;
        if (srv->be->passphrase_discard) srv->be->passphrase_discard(srv->bectx, &j->pp);
        gz_job_refuse(srv, j, 503, "passphrase_not_checked", NULL);
    }
    if (srv->to_run == srv->slot_running) srv->to_run = NULL;
    if (srv->slot_running) gz_job_refuse(srv, srv->slot_running, 503, "passphrase_not_checked", NULL);
    if (srv->slot_queued) gz_job_refuse(srv, srv->slot_queued, 503, "passphrase_not_checked", NULL);
    srv->slot_running = srv->slot_queued = srv->to_run = NULL;
    pthread_mutex_destroy(&srv->mu);
    pthread_cond_destroy(&srv->cv);
}

static void run(gz_api_server *srv, gz_job *j)
{
    srv->slot_running = j;
    srv->ctr.derivations_started++;
    if (srv->ctr.derivations_max_concurrent < 1) srv->ctr.derivations_max_concurrent = 1;   /* only ever one */
    pthread_mutex_lock(&srv->mu);
    srv->to_run = j;
    pthread_cond_signal(&srv->cv);
    pthread_mutex_unlock(&srv->mu);
}

int gz_derive_submit(gz_api_server *srv, gz_job *j)
{
    j->pp.passphrase = j->pass;
    j->pp.passphrase_len = j->pass_len;
    j->pp.generation = gz_generation(srv);
    j->next = NULL;
    if (srv->cfg.sync_derivation) {
        srv->ctr.derivations_started++;
        if (srv->ctr.derivations_max_concurrent < 1) srv->ctr.derivations_max_concurrent = 1;
        srv->be->passphrase_op(srv->bectx, &j->pp);
        gz_job_finished(srv, j);
        return 0;
    }
    if (!srv->slot_running) {
        run(srv, j);
    } else if (!srv->slot_queued) {
        srv->slot_queued = j;
        if (srv->ctr.derivations_queued_max < 1) srv->ctr.derivations_queued_max = 1;
    } else {
        return -1;                                      /* both places taken */
    }
    return 0;
}

/* The waiting job may start: the running place is free. Its gate is checked
 * now, with every finished result counted (review F2), and so is its
 * generation. */
static void promote(gz_api_server *srv)
{
    while (!srv->slot_running && srv->slot_queued) {
        gz_job *q = srv->slot_queued;
        int64_t retry = 0;
        srv->slot_queued = NULL;
        if (q->pp.generation != gz_generation(srv)) {
            gz_job_refuse(srv, q, 503, "passphrase_not_checked", NULL);   /* never derived: nothing to count */
            continue;
        }
        if (gz_job_gated(q) && srv->att_loaded && gz_attempts_gate(srv, gz_now_ms(srv) / 1000, &retry)) {
            char params[48];
            if (retry < 0) {
                gz_job_refuse(srv, q, 503, "passphrase_not_checked", NULL);
            } else {
                snprintf(params, sizeof params, "{\"retry_after_s\":%lld}", (long long)retry);
                gz_job_refuse(srv, q, 429, "rate_limited", params);       /* not counted */
            }
            continue;
        }
        run(srv, q);
    }
}

/* Loop thread: answer every finished job, then start the waiting one. */
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
        if (j == srv->slot_running) srv->slot_running = NULL;
        gz_job_finished(srv, j);
    }
    promote(srv);
}
