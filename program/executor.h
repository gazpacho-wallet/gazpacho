/* SPDX-License-Identifier: MIT */
/* The executor: the one poll loop that drives the node and its runner and
 * carries out every action. See docs/notes/program.md, "The executor loop".
 *
 * One incarnation: gzp_exec_incarnation opens storage (the fence and a new
 * durable incarnation), makes a node and a runner, starts the node from
 * storage, then runs the loop until a stop is asked for (GZP_RUN_STOP) or
 * something fatal happens (GZP_RUN_RESTART: the runner refused a list or
 * failed, storage failed, the node returned an error). main.c starts a new
 * incarnation after a restart, up to a limit. The network adapter and its
 * connections outlive incarnations; nothing of the node or the runner does. */
#ifndef GZP_EXECUTOR_H
#define GZP_EXECUTOR_H

#include <signal.h>

#include "gazpacho/node.h"
#include "gazpacho/runner.h"

#include "datadir.h"
#include "gzp.h"
#include "net.h"
#include "notify.h"
#include "pchain.h"
#include "store.h"
#include "testping.h"

#define GZP_RUN_STOP    0
#define GZP_RUN_RESTART 1
#define GZP_RUN_FAILED  2   /* storage cannot even be opened: no restart */

#define GZP_RUNNER_SLOTS 256
#define GZP_RUNNER_BYTES (256u * 1024u)
#define GZP_LIST_SLOTS 128
#define GZP_LIST_BYTES (128u * 1024u)
#define GZP_MAX_TIMERS 64

typedef struct {
    int used;
    uint64_t id, due_ms;
} gzp_timer_t;

typedef struct {
    const gzp_options_t *opt;
    gzp_datadir_t *dir;
    gzp_net_t *net;
    gzp_chain_t *chain;
    gzp_notify_sink_t notify;
    gzp_testping_t *tp;
    volatile sig_atomic_t *stop;

    /* one incarnation */
    gzp_store_t store;
    uint64_t incarnation;
    gz_node_t node;
    gz_runner_t runner;
    gz_runner_slot_t rslots[GZP_RUNNER_SLOTS];
    uint8_t rbytes[GZP_RUNNER_BYTES];
    gz_action_t lslots[GZP_LIST_SLOTS];
    uint8_t lbytes[GZP_LIST_BYTES];
    gz_action_list_t list;
    gzp_timer_t timers[GZP_MAX_TIMERS];
    int starting;            /* inside the start: counts resent replies */
    unsigned resent;
    int fatal;               /* set anywhere; the loop returns GZP_RUN_RESTART */
    const char *fatal_why;
    int storage_broken;      /* an append failed inside the executor callback */
    uint64_t pings_saved;    /* ping records made durable (tests) */
    unsigned appends;        /* appends in this program's life (tests) */
} gzp_exec_t;

int gzp_exec_incarnation(gzp_exec_t *ex, int number);

#endif
