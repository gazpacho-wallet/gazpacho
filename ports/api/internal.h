/* SPDX-License-Identifier: MIT */
/* Internals of the local API server. Not installed; not for backends. */
#ifndef GAZPACHO_API_INTERNAL_H
#define GAZPACHO_API_INTERNAL_H

#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "gazpacho/api.h"
#include "llhttp.h"

#define GZ_SESSIONS_MAX 8
#define GZ_TOKEN_LEN 32
#define GZ_TOKEN_B64 43
#define GZ_CODES_MAX 3
#define GZ_EVENTS_KEPT 256
#define GZ_STREAMS_PER_SESSION 2
#define GZ_STREAMS_MAX 8
#define GZ_MERGE_SLOTS 64

/* ---- utilities (util.c) ------------------------------------------------------- */
void gz_wipe(void *p, size_t n);
int gz_random(void *out, size_t n);                      /* 0 on success */
void gz_b64url(const uint8_t *in, size_t n, char *out);  /* out: 4n/3 rounded up + 1 */
int gz_b64url_decode(const char *in, size_t n, uint8_t *out, size_t outn); /* exact length */
int gz_ct_eq(const void *a, const void *b, size_t n);    /* constant time, 1 if equal */
void gz_hex(const uint8_t *in, size_t n, char *out);
int64_t gz_now_ms(gz_api_server *srv);
void gz_log(gz_api_server *srv, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;
int gz_valid_id(const char *s, size_t min, size_t max);  /* [A-Za-z0-9_-] */
const char *gz_error_message(const char *code);          /* fixed text per code (8) */
const char *gz_http_reason(int status);

/* ---- output buffer ---------------------------------------------------------------- */
typedef struct {
    char *buf;
    size_t len, off, cap;
} gz_out;
int gz_out_add(gz_out *o, const void *p, size_t n);
void gz_out_free(gz_out *o);                             /* wipes */

/* ---- requests -------------------------------------------------------------------- */
#define GZ_HBUF (16384 + 512)
#define GZ_MAX_HEADERS 64

typedef struct {
    uint32_t name_off, name_len, value_off, value_len;
} gz_hdr;

enum gz_method { M_OTHER = 0, M_GET, M_HEAD, M_POST, M_PUT, M_PATCH, M_DELETE, M_OPTIONS };

typedef struct gz_route gz_route;

typedef struct {
    int method;
    const char *url;                 /* in hbuf */
    char path[1024];                 /* path part, not decoded */
    char query[2048];                /* query part, or "" */
    gz_hdr h[GZ_MAX_HEADERS];
    int nh;
    /* one value per header the server reads; "" when absent; dup set when repeated */
    const char *host, *origin, *sec_site, *sec_mode, *sec_dest, *ctype, *auth, *session,
               *user, *last_event_id, *connection, *upgrade, *expect;
    int host_count, origin_count, session_count, auth_count, ctype_count;
    int has_te, has_cl;
    uint64_t content_length;
    uint8_t *body;
    size_t body_len, body_cap;
    /* routing */
    const gz_route *route;
    char id1[96], id2[96];
    char *qname[GZ_API_MAX_QUERY], *qvalue[GZ_API_MAX_QUERY];
    char qbuf[2048];
    int nq;
    int64_t t0;
    gz_json_doc doc;
    int have_doc;
    uint64_t log_session;
    int sess_slot;                   /* the session's slot, -1 none */
    uint64_t sess_no;
    int bearer;
    int fresh;
    uint8_t digest[32];              /* request_id calls (7.4) */
    int have_digest;
} gz_req;

enum gz_conn_state { CS_HEAD = 0, CS_BODY, CS_BUSY, CS_WRITE, CS_STREAM, CS_DEAD };

typedef struct gz_job gz_job;
typedef struct gz_session gz_session;

typedef struct gz_conn {
    int fd;                          /* -1 for a virtual connection (fuzzing) */
    int is_unix;
    int state;
    llhttp_t parser;
    uint8_t *in;
    size_t in_len, in_cap;
    char hbuf[GZ_HBUF];
    size_t hlen;
    int last_cb;                     /* 0 none, 1 field, 2 value */
    int value_started;
    int fault;                       /* 0, or an HTTP status our callback chose */
    int srv_max_lines;
    size_t head_fed;
    int head_done, msg_done, paused_at_head, kick;
    gz_req req;
    gz_out out;
    int close_after;
    int64_t deadline;
    int64_t opened_ms;
    /* event stream */
    int stream;
    int stream_session;              /* session slot, or -1 for a bearer stream */
    uint64_t stream_session_no;
    int64_t next_keepalive;
    /* a passphrase operation waiting for its answer */
    gz_job *job;
    /* an acting call held for its outcome (gz_api_call_done), 0 none */
    uint64_t held;
    struct gz_conn *next;
} gz_conn;

/* ---- sessions (session.c) ------------------------------------------------------- */
enum gz_session_kind { SK_SETUP = 1, SK_FILES_BEHIND, SK_NORMAL };

struct gz_session {
    int used;
    uint8_t token[GZ_TOKEN_LEN];
    char host[300];                  /* the Host it was made under (4.2) */
    int kind;
    uint64_t no;
    int64_t started, last_input, last_used, fresh_until;
    int tunnel;
    int64_t tunnel_last;
};

/* ---- passphrase jobs (derive.c) --------------------------------------------------- */
enum gz_job_purpose {
    JP_SIGN_IN = 1, JP_FRESH, JP_UNLOCK_SOCKET, JP_CREATE, JP_RESTORE, JP_REVEAL, JP_WORDS_CHECK,
    JP_START_AS_RESTORE, JP_KIND_A
};

struct gz_job {
    gz_api_pp_job pp;
    int purpose;
    gz_conn *conn;                   /* NULL once the connection is gone */
    int sess_slot;
    uint64_t sess_no;
    char host[300];
    int was_locked;
    uint8_t *pass;                   /* copy, wiped */
    size_t pass_len;
    gz_job *next;
};

/* ---- events (events.c) ------------------------------------------------------------- */
typedef struct {
    uint64_t seq;
    char topic[16];
    char id[72];
} gz_event;

typedef struct {
    char topic[16];
    char id[72];
    int64_t last_emit;
    int pending;
} gz_merge;

/* ---- the server ---------------------------------------------------------------- */
struct gz_api_server {
    gz_api_config cfg;
    gz_api_limits lim;
    const gz_api_backend *be;
    void *bectx;
    int lfd[3];                      /* 127.0.0.1, ::1, local socket */
    int nl;
    uint16_t port;
    char data_dir[512];
    char sock_path[600];
    char redirect_path[600];
    char token_dir[600];
    char token_path[640];
    char attempts_path[600];
    char run_id[9];
    int wake[2];
    atomic_int stop;                 /* gz_api_server_stop, from any thread or a signal handler (review B5) */
    gz_conn *conns;
    int nconns;
    gz_api_counters ctr;
    int peer_check_ok;               /* status interface.peer_check */
    int64_t expect_uid;
    /* sessions */
    gz_session sess[GZ_SESSIONS_MAX];
    uint64_t next_session_no;
    /* socket token (4.6) */
    int have_socket_token;
    uint8_t socket_token[GZ_TOKEN_LEN];
    /* first run (4.3) */
    int have_start_token;
    uint8_t start_token[GZ_TOKEN_LEN];
    int64_t start_token_made, first_run_launched_at;
    int have_spent_token;
    uint8_t spent_token_hash[32];
    int64_t spent_at;
    char codes[GZ_CODES_MAX][11];    /* 10 symbols, no dash */
    int64_t code_made[GZ_CODES_MAX];
    int code_wrong;
    int64_t code_last_try;
    int first_run_closed;            /* a wallet was made: no token or code ever again */
    /* words check (12.3) */
    char check_id[24];
    int check_positions[3];
    int64_t check_expires;
    uint64_t check_session_no;
    /* attempts (4.3, storage 12.3) */
    uint64_t att_counter;
    uint32_t att_wrong;
    int64_t att_last_wrong, att_blocked_until;
    int att_loaded;
    int att_unsaved;                 /* the file could not be written: passphrases refused (F5.1) */
    int token_dir_refused;           /* the socket token folder is not ours (F5.5) */
    /* derivation slot */
    pthread_t worker;
    int worker_started;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    /* loop thread only: the job deriving (or finished, not yet collected) and the one waiting */
    gz_job *slot_running, *slot_queued;
    /* under mu: handed to the worker; finished */
    gz_job *to_run, *done;
    int done_pipe[2];
    int worker_quit;
    uint64_t generation;             /* under notify_mu (gz_api_server_new_generation) */
    /* events */
    gz_event ev[GZ_EVENTS_KEPT];
    uint64_t seq;
    gz_merge merge[GZ_MERGE_SLOTS];
    pthread_mutex_t notify_mu;
    struct { char topic[16]; char id[72]; } notify_q[64];
    int notify_n;
    /* commands from other threads (call_done, node_stopped), under notify_mu */
    struct gz_cmd *cmds, **cmds_tail;
    uint64_t next_handle;
    /* the loop (pollfds / dispatch) */
    gz_conn **pc;                    /* the connection behind each descriptor written */
    size_t npc;
    struct pollfd *pfbuf;            /* for gz_api_server_poll */
    int listening_stopped;
    /* static pages */
    char refused_page[512];
    llhttp_settings_t settings;
};

/* conn and http (http.c) */
void gz_conn_input(gz_api_server *srv, gz_conn *c, const uint8_t *data, size_t n);
void gz_conn_process(gz_api_server *srv, gz_conn *c);
void gz_conn_after_write(gz_api_server *srv, gz_conn *c);
void gz_http_settings(llhttp_settings_t *s);
void gz_conn_reset(gz_conn *c, gz_api_server *srv);
gz_conn *gz_conn_new(gz_api_server *srv, int fd, int is_unix);
void gz_conn_free(gz_api_server *srv, gz_conn *c);

enum gz_body_kind { BK_JSON = 0, BK_PAGE, BK_EMPTY, BK_STATIC };
void gz_respond(gz_api_server *srv, gz_conn *c, int status, int kind, const char *extra_headers,
                const char *body, size_t len);
void gz_respond_error(gz_api_server *srv, gz_conn *c, int status, const char *code, const char *field,
                      const char *params_json);
void gz_respond_json(gz_api_server *srv, gz_conn *c, int status, gz_jw *w, const char *extra);

/* route.c */
int gz_route_head(gz_api_server *srv, gz_conn *c);        /* 0: continue; 1: answered */
void gz_route_dispatch(gz_api_server *srv, gz_conn *c);
void gz_job_finished(gz_api_server *srv, gz_job *j);
void gz_job_refuse(gz_api_server *srv, gz_job *j, int status, const char *code, const char *params);
int gz_job_gated(const gz_job *j);
void gz_held_answer(gz_api_server *srv, gz_conn *c, int status, const char *body, const char *code,
                    const char *field, const char *params);
void gz_cmds_run(gz_api_server *srv);
void gz_cmds_free(gz_api_server *srv);
const char *gz_route_pattern(const gz_req *r);

/* session.c */
gz_session *gz_session_find(gz_api_server *srv, const char *header, const char *host);
gz_session *gz_session_new(gz_api_server *srv, int kind, const char *host);
void gz_session_end(gz_api_server *srv, gz_session *s);
void gz_sessions_end_all(gz_api_server *srv);
int gz_session_fresh(gz_api_server *srv, const gz_session *s);
void gz_sessions_tick(gz_api_server *srv, int64_t now, int64_t *next);
int gz_socket_token_make(gz_api_server *srv);
void gz_socket_token_drop(gz_api_server *srv);
int gz_socket_token_check(gz_api_server *srv, const char *auth_header);
int gz_first_run_start(gz_api_server *srv);
void gz_first_run_close(gz_api_server *srv);
void gz_first_run_tick(gz_api_server *srv, int64_t now, int64_t *next);
int gz_code_make(gz_api_server *srv, char out[12], int64_t *expires);
const char *gz_code_present(gz_api_server *srv, const char *typed);
const char *gz_start_token_present(gz_api_server *srv, const char *b64, int64_t *used_at);
int gz_tunnel_host(gz_api_server *srv, const char *host);
/* attempts */
void gz_attempts_load(gz_api_server *srv);
int gz_attempts_gate(gz_api_server *srv, int64_t now_s, int64_t *retry_after);
void gz_attempts_wrong(gz_api_server *srv, int64_t now_s);
void gz_attempts_right(gz_api_server *srv);
void gz_attempts_fresh_file(gz_api_server *srv);
int gz_attempts_encode(const char *network, uint64_t counter, uint32_t wrong, uint64_t last,
                       uint64_t until, uint8_t out[85]);
int gz_attempts_decode(const char *network, const uint8_t in[85], uint64_t *counter, uint32_t *wrong,
                       uint64_t *last, uint64_t *until);

/* derive.c */
int gz_derive_start(gz_api_server *srv);
void gz_derive_stop(gz_api_server *srv);
int gz_derive_submit(gz_api_server *srv, gz_job *j);     /* 0 queued/running; -1 slot full */
void gz_derive_collect(gz_api_server *srv);
uint64_t gz_generation(gz_api_server *srv);
void gz_job_free(gz_job *j);

/* events.c */
void gz_events_notify(gz_api_server *srv, const char *topic, const char *id);
void gz_events_tick(gz_api_server *srv, int64_t now, int64_t *next);
void gz_stream_open(gz_api_server *srv, gz_conn *c, int session_slot, uint64_t session_no);
void gz_streams_end_session(gz_api_server *srv, int slot, uint64_t session_no, int bearer_too);
int gz_streams_count(gz_api_server *srv, int slot, uint64_t session_no, int *total);
void gz_events_drain_notify(gz_api_server *srv);

/* status.c */
int gz_status_write(gz_api_server *srv, gz_jw *w, int has_session, int dates_ok);
int gz_doing_rank(const char *code);
const char *gz_chain_state_name(int s);
const char *gz_chain_view(int s);
const char *gz_watching_state(const gz_api_status_facts *f, int locked);
const char *gz_headline(const gz_api_status_facts *f, const char **tier);
const char *gz_attention_tier(const char *code, int at_risk_override);
int gz_tier_rank(const char *tier);

/* peer.c */
int gz_peer_same_user(gz_api_server *srv, int fd);       /* 1 same user, 0 refuse */
int gz_peer_check_available(gz_api_server *srv);

/* static.c */
int gz_static_lookup(const char *path, const char **body, size_t *len, int *is_page);
const char *gz_page_headers(void);

#endif
