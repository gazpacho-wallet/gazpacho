/* SPDX-License-Identifier: MIT */
/* The local API server's backend interface (spec/local-api.md).
 *
 * The server (ports/api) owns HTTP, the browser checks of section 5, sessions
 * and sign-in (4), the attempt limits (4.3), request ids (7.4), the event
 * stream (10) and the status tables (11.2). Everything the wallet knows comes
 * from a backend through this table: the real one is the `gazpacho` program's
 * (stream S11, over storage from S6), and fake/fake_backend.c is the test one.
 *
 * Threads. passphrase_op runs on the server's derivation thread, at most one
 * at a time, and only derives: it turns the passphrase (and words) into keys
 * or a result, writes no file and touches nothing the loop thread uses (the
 * node, the runner, storage, the view). passphrase_done, on the loop thread,
 * installs what it produced: it writes the key file, guard, start counter and
 * first journal for create, restore and start-as-restore, opens storage and
 * starts the node. A job queued before gz_api_server_new_generation is
 * discarded when it finishes, its secrets wiped (passphrase_discard).
 * Every other entry runs on the loop thread.
 *
 * Acting calls (contract-v2 section 11, local-api.md 7.4). A call that acts
 * carries a handle; the backend submits the command, with its request_id and
 * digest, and returns GZ_API_HELD; it answers with gz_api_call_done once the
 * save is confirmed. The engine, not the server, owns request ids: it answers
 * 409 request_id_reused, changed_elsewhere and review_expired, and replays a
 * known id (with "replayed": true; a pending one is held for the same
 * outcome). The server answers 503 node_busy after 30 s and 503 node_stopped
 * on a restart; the client retries with the same request_id.
 *
 * Secrets. A job's passphrase and words are owned by the server, which wipes
 * them after passphrase_done. A backend copies neither anywhere but its own
 * storage, and never logs them. */
#ifndef GAZPACHO_API_BACKEND_H
#define GAZPACHO_API_BACKEND_H

#include <stddef.h>
#include <stdint.h>

#include "gazpacho/api_json.h"

/* ---- wallet state, as the sign-in rules need it (4.2, 4.7) ------------------ */
enum gz_api_wallet {
    GZ_API_WALLET_NONE = 0,       /* no wallet: first-run calls only */
    GZ_API_WALLET_LOCKED,         /* exists, storage key not in memory */
    GZ_API_WALLET_FILES_BEHIND,   /* an unlock found the files behind (4.7) */
    GZ_API_WALLET_UNLOCKED
};

/* ---- passphrase operations (storage 8.2), run on the derivation thread ------ */
enum gz_api_pp_op {
    GZ_API_PP_UNLOCK = 1,         /* POST /session while locked, POST /wallet/unlock */
    GZ_API_PP_CHECK,              /* while unlocked: sign-in, fresh, kind A calls */
    GZ_API_PP_CREATE,             /* set up: words out */
    GZ_API_PP_RESTORE,            /* set up from words in */
    GZ_API_PP_REVEAL,             /* words out */
    GZ_API_PP_WORDS_CHECK,        /* compare 3 words at positions */
    GZ_API_PP_START_AS_RESTORE    /* files_behind -> restore under a new epoch */
};

enum gz_api_pp_result {
    GZ_API_PPR_OK = 0,
    GZ_API_PPR_WRONG,             /* wrong passphrase: counted */
    GZ_API_PPR_NOT_CHECKED,       /* the derivation failed: not counted (503) */
    GZ_API_PPR_FILES_BEHIND,      /* unlock: files older than the last saved state; reason = cause */
    GZ_API_PPR_NODE_STOPPED,      /* unlock: journal corrupt or storage failed; reason */
    GZ_API_PPR_WEAK,              /* create/restore: storage 4.1; reason, a = length, b = minimum */
    GZ_API_PPR_EXISTS,            /* create/restore over a wallet */
    GZ_API_PPR_NO_WALLET,
    GZ_API_PPR_BAD_WORDS,         /* restore: reason "position" (a = 1-based) or "checksum" */
    GZ_API_PPR_NOT_FILES_BEHIND,
    GZ_API_PPR_WORDS_DIFFER,      /* words check: ok = false (the passphrase was right) */
    /* set-up (create, restore), start-as-restore and, later, passphrase change
     * and recovery: the change is in force, but a step after it failed
     * (storage GZ_SC_DONE_WITH_FAULT); reason = what (printable, [a-z_]).
     * Answered as done, with a warning; never as a failure. */
    GZ_API_PPR_DONE_WITH_FAULT
};

#define GZ_API_WORDS 24
#define GZ_API_WORD_MAX 16
typedef struct gz_api_pp_job {
    int op;                                   /* enum gz_api_pp_op */
    const uint8_t *passphrase;                /* not NUL-terminated */
    size_t passphrase_len;
    char words[GZ_API_WORDS][GZ_API_WORD_MAX];/* restore and check in; create and reveal out */
    int nwords;
    int positions[3];                         /* words check: 1-based */
    /* results */
    int result;                               /* enum gz_api_pp_result */
    const char *reason;                       /* static text */
    int64_t a, b;
    /* set by the server */
    uint64_t generation;                      /* gz_api_server_new_generation count at submit */
    /* the backend's own product (derived keys), installed by passphrase_done,
     * wiped by passphrase_discard */
    void *out;
} gz_api_pp_job;

/* ---- status facts (section 11), resolved by the server's tables ------------- */
enum gz_api_st_wallet {
    GZ_API_STW_NONE = 0, GZ_API_STW_CREATED_NOT_FINISHED, GZ_API_STW_READY, GZ_API_STW_LOCKED,
    GZ_API_STW_FILES_BEHIND, GZ_API_STW_RESTORING, GZ_API_STW_NODE_STOPPED
};
enum gz_api_chain_state {
    GZ_API_CHAIN_AGREE = 0, GZ_API_CHAIN_LAGGING, GZ_API_CHAIN_CATCHING_UP, GZ_API_CHAIN_ONE_SOURCE,
    GZ_API_CHAIN_DISAGREE, GZ_API_CHAIN_UNREACHABLE, GZ_API_CHAIN_OFFLINE_BY_CHOICE,
    GZ_API_CHAIN_STATES
};

/* Locked headline conditions (4.7's table), any combination. */
enum gz_api_locked_flag {
    GZ_API_LF_HOST_CLOSED_ALL      = 1u << 0,  /* every channel with something to take out closed by the host */
    GZ_API_LF_HOST_CLOSED_PAYMENT  = 1u << 1,  /* ... with an unsettled incoming payment: at_risk */
    GZ_API_LF_DEADLINE_PASSED      = 1u << 2,
    GZ_API_LF_PAST_UNLOCK_BY       = 1u << 3,
    GZ_API_LF_TREE_STEP_LATE       = 1u << 4,
    GZ_API_LF_SECOND_STAGE         = 1u << 5,
    GZ_API_LF_PAYMENT_SECRET       = 1u << 6,
    GZ_API_LF_WAITING_FOR_UNLOCK   = 1u << 7,
    GZ_API_LF_PUBLISHING           = 1u << 8,
    GZ_API_LF_OLD_STATE_ANSWERED   = 1u << 9,
    GZ_API_LF_SOMETHING_TO_TAKE_OUT= 1u << 10, /* known to have something to take out */
    GZ_API_LF_CANNOT_TELL          = 1u << 11, /* nobody_locked and cannot tell what is to take out (1.0.0) */
    GZ_API_LF_BEFORE_LEAVE_BY      = 1u << 12
};

typedef struct gz_api_doing {
    const char *code;         /* a doing.code of 11.2 */
    const char *lobby_id;     /* or NULL */
    const char *params_json;  /* a JSON object, or NULL for {} */
    int64_t since_at;         /* 0 = null */
} gz_api_doing;

typedef struct gz_api_attention {
    const char *id;
    const char *code;         /* an attention code of 11.4; the tier comes from its table */
    const char *due_json;     /* a date (7.2) or NULL */
    const char *params_json;  /* or NULL */
    const char *lobby_id, *factory_id;
    int at_risk_override;     /* exit_needs_fee_coin past WARN_LEAD: at_risk */
} gz_api_attention;

#define GZ_API_MAX_DOING 32
#define GZ_API_MAX_ATTENTION 64
typedef struct gz_api_status_facts {
    const char *network;              /* "signet", "testnet4" */
    int test_coins;
    int wallet;                       /* enum gz_api_st_wallet */
    const char *wallet_reason;        /* files_behind cause, node_stopped reason */
    int chain_state;                  /* enum gz_api_chain_state */
    int64_t chain_height, chain_since_at;
    int servers_agreeing, operators, lag_blocks;
    /* unlocked shape */
    int64_t version;
    const char *pause_state;          /* off, on, held_for_signing */
    int64_t pause_since_at;
    const char *pause_lobby_id;
    const char *lock_state;           /* NULL, held_for_signing, held_for_payment */
    const char *lock_lobby_id;
    int64_t lock_since_at;
    int memory_locked;
    const char *host_links_json;      /* JSON array or NULL for [] */
    int has_something_to_watch;       /* any factory not ended/dead, hosted factory, unresolved round (11.2) */
    int watching_behind;
    int64_t behind_minutes;
    int64_t last_check_height, last_check_at, safe_absence_blocks;
    int factories_watched;
    const char *open_by_json, *unlock_by_json, *next_date_json, *hosting_json, *take_out_alone_json;
    int64_t can_send_sat, can_receive_sat, on_chain_free_sat, set_aside_sat, inside_factories_sat,
            forming_sat, hosted_factories_sat, as_of_height;
    gz_api_doing doing[GZ_API_MAX_DOING];
    int ndoing;
    gz_api_attention attention[GZ_API_MAX_ATTENTION];
    int nattention;
    /* locked shape (4.7) */
    const char *lock_since;           /* "start" or "lock" */
    int64_t locked_since_at;
    int watcher_runs;                 /* 0 in every Slice 1 build */
    const char *watching_reason;      /* no_bundle, ... or NULL */
    unsigned locked_flags;            /* enum gz_api_locked_flag */
    const char *watcher_doing;        /* doing.params.watcher: watching, off, ... */
    int64_t leave_by_locked_height, leave_by_locked_at, unlock_by_height, unlock_by_at;
    int64_t next_action_height, next_action_at;
    const char *next_action_what;
} gz_api_status_facts;

/* ---- data calls -------------------------------------------------------------- */
/* Every Slice 1 call the server hands on (2.1). Session, sign-in, version,
 * events and the words are the server's own and do not appear here. */
enum gz_api_call_id {
    GZ_API_C_NONE = 0,
    GZ_API_C_LOCK,                 /* POST /wallet/lock */
    GZ_API_C_PAUSE,                /* PUT /pause */
    GZ_API_C_SETUP_GET,            /* GET /wallet/setup */
    GZ_API_C_RESTORE_GET,          /* GET /wallet/restore */
    GZ_API_C_FINISH_SETUP,         /* POST /wallet/finish-setup */
    GZ_API_C_BACKUP_GET,           /* GET /backup */
    GZ_API_C_CONDITIONS_GET, GZ_API_C_CONDITIONS_PREVIEW, GZ_API_C_CONDITIONS_PUT,
    GZ_API_C_DISCOVERY_QUERY, GZ_API_C_DISCOVERY_QUERY_GET, GZ_API_C_CONNECTIONS_GET,
    GZ_API_C_LOBBIES, GZ_API_C_LOBBY, GZ_API_C_JOIN, GZ_API_C_READY, GZ_API_C_LEAVE,
    GZ_API_C_HOST_PREVIEW, GZ_API_C_HOST_OPEN, GZ_API_C_HOST_LOBBIES, GZ_API_C_HOST_LOBBY,
    GZ_API_C_HOST_START, GZ_API_C_HOST_CANCEL, GZ_API_C_HOST_SEAT_REMOVE,
    GZ_API_C_FACTORIES, GZ_API_C_FACTORY, GZ_API_C_FACTORY_DATES,
    GZ_API_C_WALLET, GZ_API_C_WALLET_ADDRESS,
    GZ_API_C_ACTIVITY, GZ_API_C_ACTIVITY_ONE,
    GZ_API_C_COUNT
};

enum gz_api_phase {
    GZ_API_PHASE_ACT = 0,          /* do it */
    GZ_API_PHASE_CHECK             /* kind A: check everything but the passphrase, change nothing */
};

#define GZ_API_MAX_QUERY 8
typedef struct gz_api_call {
    int id;                        /* enum gz_api_call_id */
    int phase;                     /* enum gz_api_phase */
    const char *path_id;           /* {id} of the path, or NULL */
    const char *path_id2;          /* {seat} of the path, or NULL */
    const gz_json *body;           /* parsed request body (an object), or NULL */
    const char *query_name[GZ_API_MAX_QUERY], *query_value[GZ_API_MAX_QUERY];
    int nquery;
    int fresh;                     /* a fresh sign-in holds (4.8), or a bearer on the socket */
    int bearer;                    /* local socket with the socket token */
    int64_t now;                   /* Unix seconds */
    /* acting calls (contract-v2 11): 0 for a call that only reads */
    uint64_t handle;               /* for gz_api_call_done when the backend returns GZ_API_HELD */
    const char *request_id;        /* the client's (7.4), or NULL */
    const uint8_t *digest;         /* 32 bytes: RFC 8785 of the body without its passphrase */
    const char *method;            /* "POST", "PUT", "DELETE" */
    const char *path;              /* the path with its ids filled in */
    const char *pattern;           /* the route, e.g. "/api/v1/lobbies/{lob}/join" */
} gz_api_call;

/* call's return for an acting call whose outcome comes later (gz_api_call_done). */
#define GZ_API_HELD 1

typedef struct gz_api_error {
    const char *code;              /* an error code of 8.1 or the call's own */
    const char *field;             /* JSON pointer or NULL */
    char params[768];              /* a JSON object, or "" for {} */
} gz_api_error;

/* What a call did to sessions, beyond its answer. */
enum gz_api_effect {
    GZ_API_EFFECT_NONE = 0,
    GZ_API_EFFECT_LOCKED           /* the storage key was dropped: every session ends (4.9) */
};

typedef struct gz_api_backend {
    const char *program_version;   /* "0.1.0" */
    const char *network;           /* "signet" */

    int (*wallet_state)(void *be);                       /* enum gz_api_wallet */
    void (*passphrase_op)(void *be, gz_api_pp_job *job); /* derivation thread */
    /* Loop thread, after passphrase_op, before the answer; may be NULL. */
    void (*passphrase_done)(void *be, gz_api_pp_job *job);
    /* Fill f; the server resolves the tables and writes the answer. 0 on success. */
    int (*status)(void *be, gz_api_status_facts *f);
    /* A data call: write the answer object to out and return its HTTP status
     * (200, 201, 202, 204), or fill err and return the error status; an acting
     * call (handle != 0) may return GZ_API_HELD instead. In GZ_API_PHASE_CHECK
     * (kind A, before the derivation) return 0 to go on to the passphrase,
     * or any status to answer now (an error, or the replay of a known id).
     * *effect is GZ_API_EFFECT_NONE unless the call says otherwise. */
    int (*call)(void *be, const gz_api_call *c, gz_jw *out, gz_api_error *err, int *effect);
    /* The server's sessions all ended (lock, revoke-all) or a session ended;
     * optional, for a backend that keeps per-session state. */
    void (*sessions_changed)(void *be);
    /* Words checks left in the last 24 hours (12.3, journal record words_check_attempts);
     * when none, *retry_after_s says when the next is allowed. */
    int (*words_checks_left)(void *be, int64_t now, int64_t *retry_after_s);
    /* Loop thread, instead of passphrase_done for a job of an older generation:
     * wipe job->out; install nothing. May be NULL. */
    void (*passphrase_discard)(void *be, gz_api_pp_job *job);
} gz_api_backend;

/* Fill err's params with a printf-style JSON object body ("{...}"). */
void gz_api_err_set(gz_api_error *err, const char *code, const char *field, const char *params_fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 4, 5)))
#endif
    ;

#endif
