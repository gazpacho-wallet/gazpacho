/* SPDX-License-Identifier: MIT */
/* The local API server (spec/local-api.md draft 4): HTTP/1.1 on loopback and
 * on the local socket, the browser checks, sign-in and sessions, the event
 * stream, status, and every Slice 1 call routed to a backend
 * (gazpacho/api_backend.h). POSIX; the same-user check is Linux's (3.4). */
#ifndef GAZPACHO_API_H
#define GAZPACHO_API_H

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
} gz_api_limits;

enum gz_api_peer_mode {
    GZ_API_PEER_AUTO = 0,      /* netlink sock_diag, then /proc/net/tcp{,6} */
    GZ_API_PEER_NETLINK_ONLY,  /* tests */
    GZ_API_PEER_PROC_ONLY,     /* tests: as if the netlink family were missing */
    GZ_API_PEER_UNAVAILABLE    /* tests (23.2 item 31): as if neither could be read */
};

typedef struct gz_api_config {
    const char *data_dir;      /* required; created 0700 if missing, refused if open to others */
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

/* NULL and a reason in err (static text) on failure. */
gz_api_server *gz_api_server_new(const gz_api_config *cfg, const char **err);
/* Runs until gz_api_server_stop. 0 on a clean stop. */
int gz_api_server_run(gz_api_server *srv);
/* One loop iteration of at most timeout_ms. */
int gz_api_server_poll(gz_api_server *srv, int timeout_ms);
/* Async-signal-safe and thread-safe. */
void gz_api_server_stop(gz_api_server *srv);
/* Deletes the redirect file and the socket token, wipes every secret, frees. */
void gz_api_server_free(gz_api_server *srv);

uint16_t gz_api_server_port(const gz_api_server *srv);
const char *gz_api_server_socket_path(const gz_api_server *srv);
const char *gz_api_server_run_id(const gz_api_server *srv);

/* Something changed (10.2). Thread-safe. topic is a topic of 10.2; id a
 * local id or NULL. Events of one topic and id are merged within 250 ms. */
void gz_api_notify(gz_api_server *srv, const char *topic, const char *id);

/* A held lock has completed (4.7): the backend dropped the storage key after
 * the round ended. Every session ends and the socket token is deleted.
 * Loop thread only. */
void gz_api_locked(gz_api_server *srv);

/* A first-run code for the terminal (4.3), only while no wallet exists.
 * 0 and the code (11 bytes with the dash, NUL-terminated) on success. */
int gz_api_first_run_code(gz_api_server *srv, char out[12]);

/* Counters for tests (23.2 item 46). */
typedef struct gz_api_counters {
    int derivations_started, derivations_max_concurrent, derivations_queued_max;
    int streams_open, sessions_open, connections_open;
    int handler_calls;          /* backend calls made (23.2: "no handler runs") */
} gz_api_counters;
void gz_api_server_counters(gz_api_server *srv, gz_api_counters *out);

#endif
