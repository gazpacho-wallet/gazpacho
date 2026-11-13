/* SPDX-License-Identifier: MIT */
/* The local API server (spec/local-api.md draft 4): HTTP/1.1 on loopback and
 * on the local socket, the browser checks, sign-in and sessions, the event
 * stream, status, and every Slice 1 call routed to a backend
 * (gazpacho/api_backend.h). POSIX; the same-user check is Linux's (3.4). */
#ifndef GAZPACHO_API_H
#define GAZPACHO_API_H

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include "gazpacho/api_backend.h"

typedef struct gz_api_server gz_api_server;

/* Limits of 3.1 and lifetimes of 4.2-4.8. Zero fields take the spec's value;
 * tests shorten the times. */
typedef struct gz_api_limits {
    int max_connections;       /* 32 */
    int max_header_lines;      /* 64 */
    size_t max_head_bytes;     /* 16 KiB: request line and headers */
    size_t max_body_bytes;     /* 64 KiB */
    int64_t head_ms;           /* 10 s */
    int64_t body_ms;           /* 30 s */
    int64_t idle_ms;           /* 60 s keep-alive */
    int64_t idle_sign_out_ms;  /* 15 min (4.7, D3) */
    int64_t fresh_ms;          /* 5 min (4.8) */
    int64_t start_token_ms;    /* 10 min (4.3) */
    int64_t code_ms;           /* 10 min */
    int64_t tunnel_idle_ms;    /* 2 min (3.3) */
    int64_t keepalive_ms;      /* 15 s event-stream comment (10.3) */
    int64_t merge_ms;          /* 250 ms per topic and id (10.3) */
    size_t stream_unsent_max;  /* 64 KiB (10.3) */
    int64_t held_ms;           /* 30 s: an acting call with no outcome answers 503 node_busy (contract-v2 11) */
} gz_api_limits;

enum gz_api_peer_mode {
    GZ_API_PEER_AUTO = 0,      /* netlink sock_diag, then /proc/net/tcp{,6} */
    GZ_API_PEER_NETLINK_ONLY,  /* tests */
    GZ_API_PEER_PROC_ONLY,     /* tests: as if the netlink family were missing */
    GZ_API_PEER_UNAVAILABLE    /* tests (23.2 item 31): as if neither could be read */
};

typedef struct gz_api_config {
    const char *data_dir;      /* required: a folder the program has made, checked
                                  (0700, owned by this user) and locked; the server
                                  creates and checks nothing, and writes only its own
                                  files in it (redirect file, interface.sock, attempts.gza).
                                  A missing folder refuses to start (contract-v2 11) */
    const char *runtime_dir;   /* parent of the socket token folder; NULL: $XDG_RUNTIME_DIR, else /tmp */
    int no_ipv6;               /* do not also listen on ::1 (3.1: on by default) */
    int no_interface;          /* --no-interface: no TCP listener, the local socket only */
    const char *listen_address;/* NULL; anything but "127.0.0.1" or "::1" refuses to start (3.1) */
    uint16_t port;             /* 39735 signet; 0 = any free port (tests only) */
    uint16_t tunnel_port;      /* 0 = off (3.3) */
    int no_socket;             /* no local socket (tests) */
    int no_listen;             /* no listener at all (fuzzing) */
    int sync_derivation;       /* run passphrase operations inline (fuzzing) */
    int peer_mode;             /* enum gz_api_peer_mode */
    int override_uid;          /* tests: expect_uid instead of geteuid() */
    int64_t expect_uid;
    gz_api_limits limits;
    const gz_api_backend *backend;
    void *backend_ctx;
    /* Called when the first-run redirect file is written (4.3), with its path
     * (never the token), so the program can open the browser on it. */
    void (*on_first_run_file)(void *ctx, const char *path);
    /* Fixed terminal lines (access log, warnings): never a secret. */
    void (*log)(void *ctx, const char *line);
    void *ctx;
    /* Clock override for tests: milliseconds since the epoch. NULL = real clock. */
    int64_t (*now_ms)(void *ctx);
} gz_api_config;

/* Threads (review B5). The loop thread is the one thread that calls
 * gz_api_server_pollfds and gz_api_server_dispatch (or gz_api_server_poll or
 * gz_api_server_run); the program's loop of contract-v2 section 4. Each
 * function below says where it may be called:
 *   any thread      safe at any time, from any thread (a mutex or an atomic,
 *                   and the wake pipe; the work is done on the loop thread);
 *   loop thread     only on the loop thread, or on any one thread while no
 *                   thread runs the loop (before the first turn, or after
 *                   gz_api_server_run has returned: the tests stop the loop,
 *                   call these, and run it again);
 *   fixed           any thread: a value set by gz_api_server_new that never
 *                   changes.
 * The backend's own calls are in api_backend.h (passphrase_op is the
 * derivation thread's; everything else is called on the loop thread). */

/* NULL and a reason in err (static text) on failure. Before any other call,
 * on the thread that will run the loop or hand the server to it. */
gz_api_server *gz_api_server_new(const gz_api_config *cfg, const char **err);
/* One loop for everything (contract-v2 section 4). The program's loop calls
 * pollfds, then poll(), then dispatch, on one thread.
 *
 * gz_api_server_pollfds writes the descriptors the server waits on (the
 * listeners, the connections, the wake pipe and the derivation thread's done
 * pipe) to fds[0..cap) and returns how many, at most gz_api_server_max_fds;
 * *timeout_ms is the time to the next head, body, idle, keep-alive, merge,
 * expiry or held-answer deadline, or -1 for none. The descriptors are valid
 * until the next dispatch.
 *
 * gz_api_server_dispatch, after poll(): serves what is ready, finishes
 * passphrase jobs of the current generation, answers held calls, sends merged
 * events and acts on every deadline that has passed. Never blocks (the
 * same-user lookup is bounded, peer.c). fds and n as pollfds wrote them, with
 * revents filled. 0, or -1 if the server can no longer work.
 *
 * max_fds: fixed. pollfds and dispatch: loop thread. */
size_t gz_api_server_max_fds(const gz_api_server *srv);
size_t gz_api_server_pollfds(gz_api_server *srv, struct pollfd *fds, size_t cap, int *timeout_ms);
int gz_api_server_dispatch(gz_api_server *srv, const struct pollfd *fds, size_t n);

/* For gz-api-fake and the tests, which have no loop of their own: one
 * pollfds, poll() of at most timeout_ms, dispatch; and a loop of them until
 * gz_api_server_stop. The program uses pollfds and dispatch. Loop thread
 * (the thread that calls them is the loop thread while they run). run takes
 * the stop as it returns, so it may be called again afterwards. */
int gz_api_server_poll(gz_api_server *srv, int timeout_ms);
int gz_api_server_run(gz_api_server *srv);
/* gz_api_server_run returns. Any thread, and async-signal-safe (an atomic
 * store and a write to the wake pipe). */
void gz_api_server_stop(gz_api_server *srv);

/* A lock, a stop or a restart of the node: every passphrase job queued or
 * running now is discarded when it finishes (its secrets wiped, nothing
 * installed, answered 503 passphrase_not_checked); a wrong passphrase among
 * them is still counted (4.3). The server calls it itself at a lock
 * (POST /wallet/lock, and gz_api_locked). Any thread. */
void gz_api_server_new_generation(gz_api_server *srv);

/* The node stopped (a restart from storage, contract-v2 11): every held call
 * is answered 503 node_stopped with params.reason (e.g. "rebuilding"); the
 * client retries with the same request_id. Any thread; carried out on the
 * loop thread. */
void gz_api_server_node_stopped(gz_api_server *srv, const char *reason);

/* Shutdown, first step (contract-v2 4): the listeners close and every new
 * request is answered 503 node_stopped (reason "stopping"). Loop thread. The
 * program then stops the node, and gz_api_server_free joins the derivation
 * thread (its job discarded) before it closes the connections. */
void gz_api_server_stop_listening(gz_api_server *srv);

/* Deletes the redirect file and the socket token, wipes every secret, frees.
 * Once no thread runs the loop or calls the server any more (stop, join the
 * loop's thread, then free). Answers already written to a connection (the
 * passphrase jobs it refuses) are sent once, without waiting. */
void gz_api_server_free(gz_api_server *srv);

/* The outcome of a held call (api_backend.h, GZ_API_HELD), once every save
 * it asked for is confirmed: status 200, 201, 202 or 204 with body (a JSON
 * object, or NULL for {}), or an error status with err. A handle whose
 * connection is gone, or was answered 503 node_busy, is ignored: the answer
 * is discarded, the command is not. Any thread; the answer is written on the
 * loop thread. */
void gz_api_call_done(gz_api_server *srv, uint64_t handle, int status, const char *body, const gz_api_error *err);

/* Fixed. */
/* Fixed. */
uint16_t gz_api_server_port(const gz_api_server *srv);
const char *gz_api_server_socket_path(const gz_api_server *srv);
const char *gz_api_server_run_id(const gz_api_server *srv);

/* Something changed (10.2). Any thread. topic is a topic of 10.2; id a
 * local id or NULL. Events of one topic and id are merged within 250 ms. */
void gz_api_notify(gz_api_server *srv, const char *topic, const char *id);

/* A held lock has completed (4.7): the backend dropped the storage key after
 * the round ended. Every session ends and the socket token is deleted.
 * Loop thread only. */
void gz_api_locked(gz_api_server *srv);

/* A first-run code for the terminal (4.3), only while no wallet exists.
 * 0 and the code (11 bytes with the dash, NUL-terminated) on success. Loop
 * thread (the program's terminal command reaches it through the loop). */
int gz_api_first_run_code(gz_api_server *srv, char out[12]);

/* Counters for tests (23.2 item 46). Loop thread: the tests stop the loop to
 * read them. */
typedef struct gz_api_counters {
    int derivations_started, derivations_max_concurrent, derivations_queued_max;
    int streams_open, sessions_open, connections_open;
    int handler_calls;          /* backend calls made (23.2: "no handler runs") */
} gz_api_counters;
void gz_api_server_counters(gz_api_server *srv, gz_api_counters *out);

#endif
