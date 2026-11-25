/* SPDX-License-Identifier: MIT */
/* The local API server inside the program (P5; contract-v2.md 4 and 11;
 * docs/notes/program.md rows 4 and 11).
 *
 * One server per process, made after the data folder is locked and before
 * the first start; it outlives incarnations, as the transport does. The
 * executor's one poll() covers its descriptors (gzp_api_pollfds,
 * gzp_api_dispatch). The node's NOTIFYs feed it (gzp_api_notify): a view
 * object goes into the view table and becomes an event of its topic; a
 * command result answers the call it holds. The backend (api.c) answers the
 * API's calls from the view, the chain adapter and the passphrase layer
 * (unlock.h).
 *
 * What the node cannot serve yet is answered honestly: the lobby, host,
 * factory, conditions, pause and activity objects need the core's view
 * objects and its API engine (composite-node.md 10 step 9; contract-v2.md
 * 11; P6a). Until they come, a list is empty, an object is 404, and an
 * acting call is 501 not_in_this_release with params.needs. */
#ifndef GZP_API_H
#define GZP_API_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include "gazpacho/api.h"
#include "gazpacho/command.h"
#include "gazpacho/view.h"
#include "datadir.h"
#include "gzp.h"
#include "pchain.h"
#include "unlock.h"
#include "view.h"

#define GZP_API_HELD 64

typedef struct gzp_api {
    gz_api_server *srv;               /* NULL: no interface (--no-interface, or the port refused) */
    const gzp_options_t *opt;
    gzp_chain_t *chain;
    gzp_unlock_t unlock;
    gzp_view_t view;
    int node_running;                 /* the node has finished its start (the view is rebuilt) */
    int lock_pending;                 /* locked: the loop stops the node, then waits for an unlock */
    uint64_t views_received[8];       /* view NOTIFYs by kind (kinds 0-6, 7 = any other), said at close in the test build */
    int setup_done;                   /* finish-setup in this run, or a wallet that existed at start */
    const char *network;              /* "signet" or "testnet4" */
    struct {                          /* calls held until the node's command result (contract-v2.md 11) */
        int used;
        char request_id[GZ_CMD_MAX_REQUEST_ID + 1];
        uint64_t handle;
        int call;                     /* GZ_API_C_*: how its answer is written (api_calls.c) */
        /* The core's result came before the object it names reached the view
         * (the node emits a bracket's views after its result): the answer
         * waits for that object, or for the end of the node's batch. */
        int waiting, status;
        uint64_t waiting_since;       /* the monotonic clock, ms */
        char object[GZ_LOCAL_ID_MAX + 1], params[700];
    } held[GZP_API_HELD];
    /* What the program knows of the node for the calls (W12): the member
     * signing in force (gz_node_member_signing, from the executor), and a
     * host's long-term key, which a draft's terms name. */
    int member_signing;
    uint8_t host_key[33];
    int host_key_set;
    /* While a held call's answer is written: the core said it is a replay,
     * so the object carries "replayed": true (7.4; review of #79, L1). */
    int answer_replayed;
    /* The executor's way to give the node a USER_COMMAND (its TLV stream);
     * 0 delivered, -1 the node is not running. */
    int (*command)(void *ctx, const uint8_t *tlv, size_t len);
    void *command_ctx;
} gzp_api_t;

/* 0, or a GZP_EXIT_* code. A refused port is not an error: the interface is
 * off and an output line says why (local-api.md 3.1). */
int gzp_api_open(gzp_api_t *a, const gzp_options_t *opt, gzp_datadir_t *dir, const char *network,
                 gzp_chain_t *chain);
void gzp_api_close(gzp_api_t *a);

size_t gzp_api_max_fds(const gzp_api_t *a);
size_t gzp_api_pollfds(gzp_api_t *a, struct pollfd *fds, size_t cap, int *timeout_ms);
void gzp_api_dispatch(gzp_api_t *a, const struct pollfd *fds, size_t n);

/* The NOTIFY sink (notify.h): the node's notices into the view and the event stream. */
void gzp_api_notify(void *ctx, uint32_t code, const uint8_t *bytes, size_t len);

/* The node starts from storage: the view is cleared and every held call is
 * answered 503 node_stopped (rebuilding); then the start's notices rebuild it. */
void gzp_api_node_starting(gzp_api_t *a);
/* The executor's side of a lock (unlock.h: the program stops the node). */
int gzp_api_lock_pending(const gzp_api_t *a);
/* While the node is stopped for a lock: unlocked again? (Clears the lock.) */
int gzp_api_unlocked(gzp_api_t *a);
void gzp_api_node_started(gzp_api_t *a);

/* Give the node a command for a held call: request_id, method, path, digest,
 * code, then the arguments (a TLV stream of records 12 and up). Returns
 * GZ_API_HELD and keeps the handle, or an error status with err filled. */
int gzp_api_send_command(gzp_api_t *a, const gz_api_call *c, uint16_t code, const uint8_t *args, size_t args_len,
                         gz_api_error *err);

/* api_calls.c: the lobby, hosting, discovery, conditions, pause and signing
 * calls (-1: not one of them), and the answer of a held one. */
int gzp_api_lobby_call(gzp_api_t *a, const gz_api_call *c, gz_jw *w, gz_api_error *err);
void gzp_api_answer(gzp_api_t *a, int call, const char *object, const char *params, gz_jw *w);

#endif
