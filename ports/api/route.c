/* SPDX-License-Identifier: MIT */
/* Routing and the checks of spec/local-api.md sections 3-8, in the order
 * 4.3 gives: Host (5.1), then Origin and fetch metadata (5.2), content type
 * (5.3), the session or setup checks (4.2-4.6), and only then any attempt
 * counter, derivation or handler. A request refused by any of them touches no
 * counter and reaches no backend. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "internal.h"

/* ---- the route table ------------------------------------------------------------ */
enum { R_S1 = 0, R_100, R_110, R_LATER };
enum {
    H_CALL = 0, H_VERSION, H_SESSION_GET, H_SESSION_POST, H_SESSION_START, H_SESSION_FRESH, H_SESSION_DELETE,
    H_REVOKE_ALL, H_START_AS_RESTORE, H_UNLOCK, H_FIRST_RUN_CODES, H_EVENTS, H_STATUS, H_CREATE, H_RESTORE,
    H_REVEAL, H_CHECK_START, H_CHECK, H_HOST_OPEN, H_PAUSE, H_LOCK, H_RESERVED
};
#define F_NOSESS 0x01   /* no session needed (4.4) */
#define F_SOCKET 0x02   /* local socket only */
#define F_SETUP  0x04   /* open to a setup session (4.3) */
#define F_FB     0x08   /* open to a files_behind session (4.7) */
#define F_RID    0x10   /* request_id required (7.4) */
#define F_FRESH  0x20   /* kind B: a fresh sign-in, always (4.8) */
#define F_KINDA  0x40   /* kind A: the passphrase in the request (4.8) */
#define F_ACT    0x80   /* acts: held until the save is confirmed (contract-v2 11) */

enum { T_STR = 1, T_INT, T_BOOL, T_OBJ, T_ARR };
typedef struct { const char *name; int type; int req; } field;

struct gz_route {
    int method;
    const char *pattern;
    int release;
    int handler;
    int call;
    unsigned flags;
    const field *schema;
    const char *query;      /* allowed query names, comma separated */
};

static const field S_NONE[] = {{NULL, 0, 0}};
static const field S_PASS[] = {{"passphrase", T_STR, 1}, {NULL, 0, 0}};
static const field S_START[] = {{"start_token", T_STR, 0}, {"code", T_STR, 0}, {NULL, 0, 0}};
static const field S_LOCK[] = {{"confirm", T_STR, 1}, {"confirm_locked", T_STR, 0},
                               {"confirm_unlock_by_height", T_INT, 0}, {NULL, 0, 0}};
static const field S_CONFIRM[] = {{"confirm", T_STR, 1}, {NULL, 0, 0}};
static const field S_CONFIRM_PASS[] = {{"confirm", T_STR, 1}, {"passphrase", T_STR, 1}, {NULL, 0, 0}};
static const field S_PAUSE[] = {{"on", T_BOOL, 1}, {"confirm", T_STR, 0}, {NULL, 0, 0}};
static const field S_CREATE[] = {{"confirm", T_STR, 1}, {"passphrase", T_STR, 1}, {"confirm_passphrase", T_STR, 1},
                                 {NULL, 0, 0}};
static const field S_CHECK[] = {{"check_id", T_STR, 1}, {"passphrase", T_STR, 1}, {"words", T_ARR, 1},
                                {NULL, 0, 0}};
static const field S_RESTORE[] = {{"words", T_ARR, 1}, {"passphrase", T_STR, 1}, {"confirm_passphrase", T_STR, 1},
                                  {NULL, 0, 0}};
static const field S_FINISH[] = {{"preset", T_STR, 1}, {"find", T_STR, 1}, {NULL, 0, 0}};
static const field S_COND_PREVIEW[] = {{"conditions", T_OBJ, 1}, {NULL, 0, 0}};
static const field S_COND_PUT[] = {{"conditions", T_OBJ, 1}, {"based_on_version", T_INT, 1}, {"preset", T_STR, 0},
                                   {"confirm_loosens", T_ARR, 0}, {NULL, 0, 0}};
static const field S_QUERY[] = {{"host", T_STR, 1}, {NULL, 0, 0}};
static const field S_JOIN[] = {{"request_id", T_STR, 1}, {"seen_current_digest", T_STR, 1}, {"ready", T_BOOL, 0},
                               {NULL, 0, 0}};
static const field S_READY[] = {{"request_id", T_STR, 1}, {"ready", T_BOOL, 1}, {"seen_current_digest", T_STR, 1},
                                {NULL, 0, 0}};
static const field S_RID[] = {{"request_id", T_STR, 1}, {NULL, 0, 0}};
static const field S_DRAFT[] = {
    {"name", T_STR, 0}, {"description", T_STR, 0}, {"profile", T_STR, 0}, {"target", T_INT, 0},
    {"minimum", T_INT, 0}, {"deadline_at", T_INT, 0}, {"on_shortfall", T_STR, 0}, {"ready_window_ms", T_INT, 0},
    {"signing_budget_ms", T_INT, 0}, {"step_timeout_ms", T_INT, 0}, {"lifetime_blocks", T_INT, 0},
    {"winddown_blocks", T_INT, 0}, {"channel_sat", T_INT, 0}, {"tree_feerate_sat_per_kvb", T_INT, 0},
    {"shape", 0, 0}, {"joining_fee_sat", T_OBJ, 0}, {"fee_base_msat", T_OBJ, 0}, {"fee_ppm", T_OBJ, 0},
    {"listed", T_BOOL, 0}, {"switches", T_OBJ, 0}, {"reserved", T_OBJ, 0}, {NULL, 0, 0}};
static const field S_HOST_OPEN[] = {{"request_id", T_STR, 1}, {"draft", T_OBJ, 1}, {"draft_digest", T_STR, 1},
                                    {"confirm_funding_sat", T_INT, 1}, {"passphrase", T_STR, 1}, {NULL, 0, 0}};
static const field S_HOST_START[] = {{"request_id", T_STR, 1}, {"confirm_funding_max_sat", T_INT, 1},
                                     {NULL, 0, 0}};
static const field S_SEAT[] = {{"request_id", T_STR, 1}, {"confirm_seat", T_STR, 1}, {"reason", T_STR, 0},
                               {NULL, 0, 0}};

#define S1(m, p, h, call, fl, sc, q) {m, p, R_S1, h, call, fl, sc, q}
#define RES(m, p, rel) {m, p, rel, H_RESERVED, 0, 0, NULL, NULL}

static const gz_route ROUTES[] = {
    /* session and unlocking (4.5, 4.6) */
    S1(M_GET, "/api/v1/session", H_SESSION_GET, 0, F_NOSESS, NULL, NULL),
    S1(M_POST, "/api/v1/session", H_SESSION_POST, 0, F_NOSESS, S_PASS, NULL),
    S1(M_DELETE, "/api/v1/session", H_SESSION_DELETE, 0, F_SETUP | F_FB, S_NONE, NULL),
    S1(M_POST, "/api/v1/session/start", H_SESSION_START, 0, F_NOSESS, S_START, NULL),
    S1(M_POST, "/api/v1/session/fresh", H_SESSION_FRESH, 0, 0, S_PASS, NULL),
    S1(M_POST, "/api/v1/session/revoke-all", H_REVOKE_ALL, 0, F_FRESH, S_CONFIRM, NULL),
    S1(M_POST, "/api/v1/wallet/lock", H_LOCK, GZ_API_C_LOCK, F_ACT, S_LOCK, NULL),
    S1(M_POST, "/api/v1/wallet/start-as-restore", H_START_AS_RESTORE, 0, F_FB | F_KINDA, S_CONFIRM_PASS, NULL),
    S1(M_POST, "/api/v1/wallet/unlock", H_UNLOCK, 0, F_SOCKET, S_PASS, NULL),
    S1(M_POST, "/api/v1/first-run-codes", H_FIRST_RUN_CODES, 0, F_SOCKET, S_NONE, NULL),
    /* version, events, status (6, 10, 11) */
    S1(M_GET, "/api/v1/version", H_VERSION, 0, F_NOSESS, NULL, NULL),
    S1(M_GET, "/api/v1/events", H_EVENTS, 0, F_SETUP | F_FB, NULL, NULL),
    S1(M_GET, "/api/v1/status", H_STATUS, 0, F_SETUP | F_FB, NULL, NULL),
    S1(M_PUT, "/api/v1/pause", H_PAUSE, GZ_API_C_PAUSE, F_ACT, S_PAUSE, NULL),
    /* keys (12) */
    S1(M_GET, "/api/v1/wallet/setup", H_CALL, GZ_API_C_SETUP_GET, F_SETUP, NULL, NULL),
    S1(M_POST, "/api/v1/wallet/create", H_CREATE, 0, F_SETUP, S_CREATE, NULL),
    S1(M_POST, "/api/v1/wallet/phrase/reveal", H_REVEAL, 0, F_SETUP | F_KINDA, S_CONFIRM_PASS, NULL),
    S1(M_POST, "/api/v1/wallet/phrase/check-start", H_CHECK_START, 0, F_SETUP, S_NONE, NULL),
    S1(M_POST, "/api/v1/wallet/phrase/check", H_CHECK, 0, F_SETUP | F_KINDA, S_CHECK, NULL),
    S1(M_POST, "/api/v1/wallet/restore", H_RESTORE, 0, F_SETUP, S_RESTORE, NULL),
    S1(M_GET, "/api/v1/wallet/restore", H_CALL, GZ_API_C_RESTORE_GET, F_SETUP, NULL, NULL),
    S1(M_POST, "/api/v1/wallet/finish-setup", H_CALL, GZ_API_C_FINISH_SETUP, F_SETUP, S_FINISH, NULL),
    S1(M_GET, "/api/v1/backup", H_CALL, GZ_API_C_BACKUP_GET, 0, NULL, NULL),
    /* conditions (13) */
    S1(M_GET, "/api/v1/conditions", H_CALL, GZ_API_C_CONDITIONS_GET, 0, NULL, NULL),
    S1(M_POST, "/api/v1/conditions/preview", H_CALL, GZ_API_C_CONDITIONS_PREVIEW, 0, S_COND_PREVIEW, NULL),
    S1(M_PUT, "/api/v1/conditions", H_CALL, GZ_API_C_CONDITIONS_PUT, F_ACT, S_COND_PUT, NULL),
    /* finding the host (21, 20.3) */
    S1(M_POST, "/api/v1/discovery/query", H_CALL, GZ_API_C_DISCOVERY_QUERY, 0, S_QUERY, NULL),
    S1(M_GET, "/api/v1/discovery/queries/{q}", H_CALL, GZ_API_C_DISCOVERY_QUERY_GET, 0, NULL, NULL),
    S1(M_GET, "/api/v1/settings/connections", H_CALL, GZ_API_C_CONNECTIONS_GET, 0, NULL, NULL),
    /* lobbies (14) */
    S1(M_GET, "/api/v1/lobbies", H_CALL, GZ_API_C_LOBBIES, 0, NULL, "show,sort,cursor,limit"),
    S1(M_GET, "/api/v1/lobbies/{lob}", H_CALL, GZ_API_C_LOBBY, 0, NULL, NULL),
    S1(M_POST, "/api/v1/lobbies/{lob}/join", H_CALL, GZ_API_C_JOIN, F_RID | F_ACT, S_JOIN, NULL),
    S1(M_PUT, "/api/v1/lobbies/{lob}/ready", H_CALL, GZ_API_C_READY, F_RID | F_ACT, S_READY, NULL),
    S1(M_POST, "/api/v1/lobbies/{lob}/leave", H_CALL, GZ_API_C_LEAVE, F_RID | F_ACT, S_RID, NULL),
    /* hosting (15) */
    S1(M_POST, "/api/v1/host/preview", H_CALL, GZ_API_C_HOST_PREVIEW, 0, S_DRAFT, NULL),
    S1(M_POST, "/api/v1/host/lobbies", H_HOST_OPEN, GZ_API_C_HOST_OPEN, F_RID | F_KINDA | F_ACT, S_HOST_OPEN, NULL),
    S1(M_GET, "/api/v1/host/lobbies", H_CALL, GZ_API_C_HOST_LOBBIES, 0, NULL, "state,cursor,limit"),
    S1(M_GET, "/api/v1/host/lobbies/{lob}", H_CALL, GZ_API_C_HOST_LOBBY, 0, NULL, NULL),
    S1(M_POST, "/api/v1/host/lobbies/{lob}/start", H_CALL, GZ_API_C_HOST_START, F_RID | F_FRESH | F_ACT, S_HOST_START, NULL),
    S1(M_POST, "/api/v1/host/lobbies/{lob}/cancel", H_CALL, GZ_API_C_HOST_CANCEL, F_RID | F_ACT, S_RID, NULL),
    S1(M_DELETE, "/api/v1/host/lobbies/{lob}/seats/{seat}", H_CALL, GZ_API_C_HOST_SEAT_REMOVE, F_RID | F_FRESH | F_ACT,
       S_SEAT, NULL),
    /* factories (16) */
    S1(M_GET, "/api/v1/factories", H_CALL, GZ_API_C_FACTORIES, 0, NULL, "cursor,limit"),
    S1(M_GET, "/api/v1/factories/{fac}", H_CALL, GZ_API_C_FACTORY, 0, NULL, NULL),
    S1(M_GET, "/api/v1/factories/{fac}/dates", H_CALL, GZ_API_C_FACTORY_DATES, 0, NULL, NULL),
    /* funding (18) */
    S1(M_GET, "/api/v1/wallet", H_CALL, GZ_API_C_WALLET, 0, NULL, NULL),
    S1(M_POST, "/api/v1/wallet/address", H_CALL, GZ_API_C_WALLET_ADDRESS, 0, S_NONE, NULL),
    /* record (19) */
    S1(M_GET, "/api/v1/activity", H_CALL, GZ_API_C_ACTIVITY, 0, NULL, "show,cursor,limit"),
    S1(M_GET, "/api/v1/activity/{act}", H_CALL, GZ_API_C_ACTIVITY_ONE, 0, NULL, NULL),

    /* 1.1.0 reserved (2) */
    RES(M_POST, "/api/v1/receiving-room/quote", R_110),
    RES(M_POST, "/api/v1/receiving-room/buy", R_110),
    RES(M_GET, "/api/v1/receiving-room/auto", R_110),
    RES(M_PUT, "/api/v1/receiving-room/auto", R_110),
    RES(M_POST, "/api/v1/host/factories/{x}/sell-room", R_110),
    RES(M_PUT, "/api/v1/wallet/payout", R_110),
    /* later reserved */
    RES(M_PUT, "/api/v1/wallet/payout/outside", R_LATER),
    RES(M_POST, "/api/v1/lobbies/{x}/rule-request", R_LATER),
    RES(M_GET, "/api/v1/lobbies/{x}/chat", R_LATER),
    RES(M_PUT, "/api/v1/host/schedule", R_LATER),
    RES(M_GET, "/api/v1/glossary", R_LATER),
    RES(M_GET, "/api/v1/discovery/hosts", R_LATER),
    /* 1.0.0, not in Slice 1 (2.1: "this table is the whole Slice 1 list") */
    RES(M_POST, "/api/v1/wallet/passphrase", R_100),
    RES(M_POST, "/api/v1/wallet/replace", R_100),
    RES(M_POST, "/api/v1/wallet/remove", R_100),
    RES(M_GET, "/api/v1/wallet/coins", R_100),
    RES(M_GET, "/api/v1/wallet/transactions", R_100),
    RES(M_POST, "/api/v1/wallet/send/preview", R_100),
    RES(M_POST, "/api/v1/wallet/send", R_100),
    RES(M_POST, "/api/v1/wallet/transactions/{x}/speed-up/preview", R_100),
    RES(M_POST, "/api/v1/wallet/transactions/{x}/speed-up", R_100),
    RES(M_POST, "/api/v1/payments/decode", R_100),
    RES(M_POST, "/api/v1/payments", R_100),
    RES(M_GET, "/api/v1/payments", R_100),
    RES(M_GET, "/api/v1/payments/{x}", R_100),
    RES(M_POST, "/api/v1/invoices", R_100),
    RES(M_GET, "/api/v1/invoices/{x}", R_100),
    RES(M_POST, "/api/v1/factories/{x}/leave-alone/preview", R_100),
    RES(M_POST, "/api/v1/factories/{x}/leave-alone", R_100),
    RES(M_GET, "/api/v1/factories/{x}/leave-alone", R_100),
    RES(M_GET, "/api/v1/factories/{x}/move", R_100),
    RES(M_POST, "/api/v1/factories/{x}/move", R_100),
    RES(M_GET, "/api/v1/schedule", R_100),
    RES(M_POST, "/api/v1/backup/export", R_100),
    RES(M_POST, "/api/v1/backup/import", R_100),
    RES(M_POST, "/api/v1/backup/ask-host", R_100),
    RES(M_GET, "/api/v1/backup/restore", R_100),
    RES(M_PUT, "/api/v1/backup/host-copy", R_100),
    RES(M_DELETE, "/api/v1/attention/{x}", R_100),
    RES(M_GET, "/api/v1/while-closed/{x}", R_100),
    RES(M_POST, "/api/v1/while-closed/{x}/seen", R_100),
    RES(M_GET, "/api/v1/settings/wallet", R_100),
    RES(M_PATCH, "/api/v1/settings/wallet", R_100),
    RES(M_GET, "/api/v1/settings/watching", R_100),
    RES(M_PATCH, "/api/v1/settings/watching", R_100),
    RES(M_POST, "/api/v1/settings/watching/offline", R_100),
    RES(M_PATCH, "/api/v1/settings/connections", R_100),
    RES(M_POST, "/api/v1/settings/connections/servers", R_100),
    RES(M_DELETE, "/api/v1/settings/connections/servers/{x}", R_100),
    RES(M_POST, "/api/v1/settings/connections/check", R_100),
    RES(M_POST, "/api/v1/settings/connections/hosts", R_100),
    RES(M_DELETE, "/api/v1/settings/connections/hosts", R_100),
    RES(M_GET, "/api/v1/settings/application", R_100),
    RES(M_PATCH, "/api/v1/settings/application", R_100),
    RES(M_GET, "/api/v1/about", R_100),
    RES(M_GET, "/api/v1/logs", R_100),
    RES(M_GET, "/api/v1/discovery", R_100),
    RES(M_POST, "/api/v1/discovery/refresh", R_100),
    RES(M_POST, "/api/v1/invitations", R_100),
    RES(M_GET, "/api/v1/lobbies/{x}/terms/sealed", R_100),
    RES(M_PUT, "/api/v1/lobbies/{x}/members/{x}/blocked", R_100),
    RES(M_POST, "/api/v1/host/lobbies/{x}/values", R_100),
    RES(M_POST, "/api/v1/host/lobbies/{x}/invitations", R_100),
    RES(M_GET, "/api/v1/host/lobbies/{x}/requests", R_100),
    RES(M_POST, "/api/v1/host/lobbies/{x}/requests/{x}/approve", R_100),
    RES(M_POST, "/api/v1/host/lobbies/{x}/requests/{x}/refuse", R_100),
    RES(M_PUT, "/api/v1/host/lists", R_100),
    RES(M_PUT, "/api/v1/host/notes/{x}", R_100),
    RES(M_GET, "/api/v1/host/factories", R_100),
    RES(M_GET, "/api/v1/host/factories/{x}", R_100),
    RES(M_POST, "/api/v1/host/factories/{x}/force-path/preview", R_100),
    RES(M_POST, "/api/v1/host/factories/{x}/force-path", R_100),
    RES(M_POST, "/api/v1/host/factories/{x}/wind-down", R_100),
    RES(M_POST, "/api/v1/host/factories/{x}/force-close/preview", R_100),
    RES(M_POST, "/api/v1/host/factories/{x}/force-close", R_100),
    RES(M_GET, "/api/v1/host/earnings", R_100),
    RES(M_GET, "/api/v1/host/setup", R_100),
    RES(M_PATCH, "/api/v1/host/setup", R_100),
    RES(M_PUT, "/api/v1/host/node", R_100),
    RES(M_POST, "/api/v1/host/node/test", R_100),
    RES(M_DELETE, "/api/v1/host/node", R_100),
    RES(M_POST, "/api/v1/host/backup", R_100),
};

#define NROUTES (sizeof ROUTES / sizeof ROUTES[0])

const char *gz_route_pattern(const gz_req *r)
{
    return r->route ? r->route->pattern : (r->path[0] && strncmp(r->path, "/api/", 5) != 0 ? "static" : "-");
}

/* Exported for tests: every reserved route and its release. */
int gz_api_route_count(void);
int gz_api_route_count(void) { return (int)NROUTES; }
int gz_api_route_info(int i, int *method, const char **pattern, const char **release);
int gz_api_route_info(int i, int *method, const char **pattern, const char **release)
{
    static const char *const REL[] = {"S1", "1.0.0", "1.1.0", "later"};
    if (i < 0 || i >= (int)NROUTES) return -1;
    *method = ROUTES[i].method;
    *pattern = ROUTES[i].pattern;
    *release = REL[ROUTES[i].release];
    return 0;
}

static int seg_ok(const char *kind, const char *s, size_t n)
{
    char b[128];
    size_t i;
    if (n == 0 || n >= sizeof b) return 0;
    memcpy(b, s, n);
    b[n] = 0;
    if (strcmp(kind, "{lob}") == 0) return strncmp(b, "lob_", 4) == 0 && gz_valid_id(b + 4, 1, 60);
    if (strcmp(kind, "{fac}") == 0) return strncmp(b, "fac_", 4) == 0 && gz_valid_id(b + 4, 1, 60);
    if (strcmp(kind, "{seat}") == 0) {
        if (n != 16) return 0;
        for (i = 0; i < n; i++)
            if (!((b[i] >= '0' && b[i] <= '9') || (b[i] >= 'a' && b[i] <= 'f'))) return 0;
        return 1;
    }
    if (strcmp(kind, "{x}") == 0) return gz_valid_id(b, 1, 80);
    return gz_valid_id(b, 1, 64);                      /* {q}, {act}: opaque local ids (7.3) */
}

/* 1: matched (ids filled in r), 0: no match. */
static int match(const char *pattern, const char *path, gz_req *r)
{
    const char *p = pattern, *q = path;
    int nid = 0;
    while (*p && *q) {
        const char *pe = strchr(p + 1, '/'), *qe = strchr(q + 1, '/');
        size_t pl = pe ? (size_t)(pe - p) : strlen(p), ql = qe ? (size_t)(qe - q) : strlen(q);
        if (p[1] == '{') {
            char kind[16];
            if (pl - 1 >= sizeof kind) return 0;
            memcpy(kind, p + 1, pl - 1);
            kind[pl - 1] = 0;
            if (*q != '/' || !seg_ok(kind, q + 1, ql - 1)) return 0;
            if (r) {
                char *dst = nid == 0 ? r->id1 : r->id2;
                memcpy(dst, q + 1, ql - 1);
                dst[ql - 1] = 0;
            }
            nid++;
        } else if (pl != ql || memcmp(p, q, pl) != 0) {
            return 0;
        }
        p += pl;
        q += ql;
    }
    return *p == 0 && *q == 0;
}

/* ---- small helpers ------------------------------------------------------------------ */
static int hdr_is(const gz_conn *c, const gz_hdr *h, const char *name)
{
    return h->name_len == strlen(name) && strncasecmp(c->hbuf + h->name_off, name, h->name_len) == 0;
}

static void collect_headers(gz_conn *c)
{
    gz_req *r = &c->req;
    int i;
    r->host = r->origin = r->sec_site = r->sec_mode = r->sec_dest = r->ctype = r->auth = r->session = r->user =
        r->last_event_id = r->connection = r->upgrade = r->expect = "";
    for (i = 0; i < r->nh; i++) {
        const gz_hdr *h = &r->h[i];
        const char *v = c->hbuf + h->value_off;
        if (hdr_is(c, h, "host")) { r->host = v; r->host_count++; }
        else if (hdr_is(c, h, "origin")) { r->origin = v; r->origin_count++; }
        else if (hdr_is(c, h, "sec-fetch-site")) { r->sec_site = v; r->origin_count += r->sec_site[0] ? 0 : 0; }
        else if (hdr_is(c, h, "sec-fetch-mode")) r->sec_mode = v;
        else if (hdr_is(c, h, "sec-fetch-dest")) r->sec_dest = v;
        else if (hdr_is(c, h, "content-type")) { r->ctype = v; r->ctype_count++; }
        else if (hdr_is(c, h, "authorization")) { r->auth = v; r->auth_count++; }
        else if (hdr_is(c, h, "x-gazpacho-session")) { r->session = v; r->session_count++; }
        else if (hdr_is(c, h, "x-gazpacho-user")) r->user = v;
        else if (hdr_is(c, h, "last-event-id")) r->last_event_id = v;
        else if (hdr_is(c, h, "connection")) r->connection = v;
        else if (hdr_is(c, h, "upgrade")) r->upgrade = v;
        else if (hdr_is(c, h, "expect")) r->expect = v;
        else if (hdr_is(c, h, "transfer-encoding")) r->has_te = 1;
        else if (hdr_is(c, h, "content-length")) r->has_cl = 1;
    }
}

static int has_token(const char *list, const char *tok)
{
    size_t n = strlen(tok);
    const char *p = list;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (strncasecmp(p, tok, n) == 0 && (p[n] == 0 || p[n] == ',' || p[n] == ' ' || p[n] == '\t')) return 1;
        while (*p && *p != ',') p++;
    }
    return 0;
}

static int host_allowed(gz_api_server *srv, const gz_conn *c, const char *host)
{
    char b[64];
    unsigned ports[2];
    int i, np = 1;
    if (c->is_unix) return strcmp(host, "localhost") == 0;
    ports[0] = srv->port;
    if (srv->cfg.tunnel_port) ports[np++] = srv->cfg.tunnel_port;
    for (i = 0; i < np; i++) {
        snprintf(b, sizeof b, "127.0.0.1:%u", ports[i]);
        if (strcmp(host, b) == 0) return 1;
        snprintf(b, sizeof b, "localhost:%u", ports[i]);
        if (strcmp(host, b) == 0) return 1;
        snprintf(b, sizeof b, "[::1]:%u", ports[i]);
        if (strcmp(host, b) == 0) return 1;
    }
    return 0;
}

static int origin_matches(const gz_req *r)
{
    return strncmp(r->origin, "http://", 7) == 0 && strcmp(r->origin + 7, r->host) == 0;
}

static int json_ctype(const char *ct)
{
    const char *p;
    if (strncasecmp(ct, "application/json", 16) != 0) return 0;
    p = ct + 16;
    if (*p == 0) return 1;
    while (*p == ' ') p++;
    if (*p != ';') return 0;
    p++;
    while (*p == ' ') p++;
    return strcasecmp(p, "charset=utf-8") == 0;
}

static int pct(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes %XX and '+' in place; -1 on a bad escape or a NUL. */
static int unescape(char *s)
{
    char *o = s;
    while (*s) {
        if (*s == '%') {
            int a = pct(s[1]), b = a < 0 ? -1 : pct(s[2]);
            if (a < 0 || b < 0 || (a == 0 && b == 0)) return -1;
            *o++ = (char)(a * 16 + b);
            s += 3;
        } else if (*s == '+') {
            *o++ = ' ';
            s++;
        } else {
            *o++ = *s++;
        }
    }
    *o = 0;
    return 0;
}

static const char *const SECRET_NAMES[] = {"token", "code", "phrase", "words", "seed", "key",
                                           "password", "invoice", "session", "backup"};

static int name_is_secret(const char *n)
{
    size_t i;
    for (i = 0; i < sizeof SECRET_NAMES / sizeof SECRET_NAMES[0]; i++)
        if (strcasecmp(n, SECRET_NAMES[i]) == 0) return 1;
    return 0;
}

/* Splits the query; 0 ok, else answered. */
static int parse_query(gz_api_server *srv, gz_conn *c)
{
    gz_req *r = &c->req;
    char *p, *save = NULL, *part;
    if (!r->query[0]) return 0;
    snprintf(r->qbuf, sizeof r->qbuf, "%s", r->query);
    for (part = strtok_r(r->qbuf, "&", &save); part; part = strtok_r(NULL, "&", &save)) {
        p = strchr(part, '=');
        if (p) *p++ = 0;
        if (unescape(part) != 0) { gz_respond_error(srv, c, 400, "bad_value", NULL, NULL); return 1; }
        if (name_is_secret(part)) {                      /* its value is never logged (5.5) */
            gz_respond_error(srv, c, 400, "secret_in_url", NULL, NULL);
            return 1;
        }
        if (r->nq >= GZ_API_MAX_QUERY) { gz_respond_error(srv, c, 400, "bad_value", NULL, NULL); return 1; }
        if (p && unescape(p) != 0) { gz_respond_error(srv, c, 400, "bad_value", NULL, NULL); return 1; }
        r->qname[r->nq] = part;
        r->qvalue[r->nq] = p ? p : (char *)"";
        r->nq++;
    }
    return 0;
}

static int check_query(gz_api_server *srv, gz_conn *c)
{
    gz_req *r = &c->req;
    int i, j;
    for (i = 0; i < r->nq; i++) {
        const char *n = r->qname[i], *v = r->qvalue[i], *allowed = r->route->query;
        char fieldname[80];
        size_t nl = strlen(n);
        const char *a = allowed;
        int ok = 0;
        while (a && *a) {
            const char *e = strchr(a, ',');
            size_t al = e ? (size_t)(e - a) : strlen(a);
            if (al == nl && memcmp(a, n, nl) == 0) ok = 1;
            a = e ? e + 1 : a + al;
        }
        snprintf(fieldname, sizeof fieldname, "?%s", n);
        if (!ok) { gz_respond_error(srv, c, 400, "unknown_field", fieldname, NULL); return 1; }
        for (j = 0; j < i; j++)
            if (strcmp(r->qname[j], n) == 0) { gz_respond_error(srv, c, 400, "bad_value", fieldname, NULL); return 1; }
        if (strcmp(n, "limit") == 0) {
            char *end;
            long v2 = strtol(v, &end, 10);
            if (!*v || *end || v2 < 1 || v2 > 200) { gz_respond_error(srv, c, 400, "bad_value", fieldname, NULL); return 1; }
        } else if (strcmp(n, "cursor") == 0) {
            if (!gz_valid_id(v, 1, 128)) { gz_respond_error(srv, c, 400, "bad_value", fieldname, NULL); return 1; }
        } else {
            static const char *const ENUMS[][2] = {
                {"show", "fits,all"}, {"sort", "fit,start,joining_fee,channel"},
                {"state", "open,funding,running,ended"}};
            const char *list = NULL;
            size_t k, vl = strlen(v);
            int found = 0;
            if (r->route->call == GZ_API_C_ACTIVITY && strcmp(n, "show") == 0) list = "all,payments,by_app,refusals";
            for (k = 0; !list && k < sizeof ENUMS / sizeof ENUMS[0]; k++)
                if (strcmp(ENUMS[k][0], n) == 0) list = ENUMS[k][1];
            while (list && *list) {
                const char *e = strchr(list, ',');
                size_t ll = e ? (size_t)(e - list) : strlen(list);
                if (ll == vl && memcmp(list, v, vl) == 0) found = 1;
                list = e ? e + 1 : list + ll;
            }
            if (!found) { gz_respond_error(srv, c, 400, "bad_value", fieldname, NULL); return 1; }
        }
    }
    return 0;
}

/* ---- the head: every check before the body is read -------------------------------------- */
static int map_method(llhttp_t *p)
{
    switch (llhttp_get_method(p)) {
    case HTTP_GET: return M_GET;
    case HTTP_HEAD: return M_HEAD;
    case HTTP_POST: return M_POST;
    case HTTP_PUT: return M_PUT;
    case HTTP_PATCH: return M_PATCH;
    case HTTP_DELETE: return M_DELETE;
    case HTTP_OPTIONS: return M_OPTIONS;
    default: return M_OTHER;
    }
}

static void refuse_page(gz_api_server *srv, gz_conn *c)
{
    c->close_after = 1;
    gz_respond(srv, c, 403, BK_PAGE, NULL, srv->refused_page, strlen(srv->refused_page));
}

static int answer(gz_api_server *srv, gz_conn *c, int status, const char *code, const char *field)
{
    c->close_after = 1;                                  /* refused before the body: never read it */
    gz_respond_error(srv, c, status, code, field, NULL);
    return 1;
}

static int wallet_state(gz_api_server *srv) { return srv->be->wallet_state(srv->bectx); }

/* The session, bearer or tokenless rules (3.2, 4.2-4.7). 0 to go on. */
static int authorize(gz_api_server *srv, gz_conn *c)
{
    gz_req *r = &c->req;
    const gz_route *rt = r->route;
    int ws = wallet_state(srv);
    gz_session *s;
    r->sess_slot = -1;
    if (c->is_unix) {
        if (r->auth[0]) {
            if (!gz_socket_token_check(srv, r->auth)) return answer(srv, c, 401, "not_signed_in", NULL);
            r->bearer = 1;
            r->fresh = 1;                               /* bearer requests need no fresh sign-in (4.6) */
            return 0;
        }
        /* no token: only these, while there is no token to hold (3.2, 4.6) */
        if (ws != GZ_API_WALLET_UNLOCKED) {
            if (rt->handler == H_VERSION || rt->handler == H_STATUS) return 0;
            if (rt->handler == H_UNLOCK && ws == GZ_API_WALLET_LOCKED) return 0;
            if (rt->handler == H_UNLOCK && ws == GZ_API_WALLET_FILES_BEHIND) return 0;
            if (rt->handler == H_START_AS_RESTORE && ws == GZ_API_WALLET_FILES_BEHIND) return 0;
            if (rt->handler == H_FIRST_RUN_CODES && ws == GZ_API_WALLET_NONE) return 0;
        }
        return answer(srv, c, 401, "not_signed_in", NULL);
    }
    if (rt->flags & F_SOCKET) return answer(srv, c, 404, "not_found", NULL);
    s = r->session_count == 1 ? gz_session_find(srv, r->session, r->host) : NULL;
    if (r->session_count > 1) return answer(srv, c, 401, "not_signed_in", NULL);
    if (s) {
        r->sess_slot = (int)(s - srv->sess);
        r->sess_no = s->no;
        r->log_session = s->no;
        r->fresh = gz_session_fresh(srv, s);
    }
    if (rt->flags & F_NOSESS) return 0;
    if (rt->handler == H_STATUS && !s &&
        (ws == GZ_API_WALLET_LOCKED || ws == GZ_API_WALLET_FILES_BEHIND))
        return 0;                                       /* the locked shape, to anyone who passed the walls */
    if (ws == GZ_API_WALLET_LOCKED) return answer(srv, c, 423, "wallet_locked", NULL);
    if (!s) {
        if (ws == GZ_API_WALLET_FILES_BEHIND) return answer(srv, c, 423, "wallet_locked", NULL);
        return answer(srv, c, 401, "not_signed_in", NULL);
    }
    if (s->kind == SK_SETUP && !(rt->flags & F_SETUP)) return answer(srv, c, 403, "not_setup_call", NULL);
    if (s->kind == SK_FILES_BEHIND && !(rt->flags & F_FB))
        return answer(srv, c, 403, "not_files_behind_call", NULL);
    if (s->kind == SK_NORMAL && ws != GZ_API_WALLET_UNLOCKED) return answer(srv, c, 423, "wallet_locked", NULL);
    return 0;
}

int gz_route_head(gz_api_server *srv, gz_conn *c)
{
    gz_req *r = &c->req;
    const char *url, *q;
    size_t i, plen;
    int is_api, path_known = 0, method_seen = 0;
    collect_headers(c);
    r->t0 = gz_now_ms(srv);
    r->method = map_method(&c->parser);
    r->sess_slot = -1;
    /* 5.1: Host, before anything else, static files included */
    if (r->host_count != 1 || !host_allowed(srv, c, r->host)) {
        c->close_after = 1;
        gz_respond(srv, c, 421, BK_EMPTY, NULL, NULL, 0);
        return 1;
    }
    /* shutting down (contract-v2 4): no new request is served */
    if (srv->listening_stopped) {
        c->close_after = 1;
        gz_respond_error(srv, c, 503, "node_stopped", NULL, "{\"reason\":\"stopping\"}");
        return 1;
    }
    if (llhttp_get_http_major(&c->parser) != 1 || llhttp_get_http_minor(&c->parser) != 1)
        return answer(srv, c, 400, "bad_request", NULL);
    /* 3.1: no upgrade, no chunked request body */
    if (r->upgrade[0] || has_token(r->connection, "upgrade")) return answer(srv, c, 400, "no_upgrade", NULL);
    if (r->has_te) return answer(srv, c, 411, "length_required", NULL);
    if (r->method == M_OPTIONS) return answer(srv, c, 405, "no_cors", NULL);
    if (r->method == M_OTHER) return answer(srv, c, 405, "method_not_allowed", NULL);
    /* the request target */
    url = r->url ? r->url : "";
    if (url[0] != '/') return answer(srv, c, 400, "bad_request", NULL);
    q = strchr(url, '?');
    plen = q ? (size_t)(q - url) : strlen(url);
    if (plen >= sizeof r->path || (q && strlen(q + 1) >= sizeof r->query)) return answer(srv, c, 404, "not_found", NULL);
    memcpy(r->path, url, plen);
    r->path[plen] = 0;
    snprintf(r->query, sizeof r->query, "%s", q ? q + 1 : "");
    if (strchr(r->query, '#')) return answer(srv, c, 400, "bad_request", NULL);
    if (parse_query(srv, c)) { c->close_after = 1; return 1; }
    /* 4.6: credentials */
    if (r->auth_count > 1) return answer(srv, c, 400, "two_credentials", NULL);
    if (r->auth[0]) {
        if (!c->is_unix) return answer(srv, c, 400, "bearer_not_on_tcp", NULL);
        if (r->session[0]) return answer(srv, c, 400, "two_credentials", NULL);
    }
    /* 5.2: Origin and fetch metadata */
    is_api = strncmp(r->path, "/api/", 5) == 0 || strcmp(r->path, "/api") == 0;
    if (c->is_unix) {
        if (r->origin_count) return answer(srv, c, 403, "forbidden_origin", NULL);
    } else {
        int unsafe = r->method != M_GET && r->method != M_HEAD;
        if (r->origin_count > 1) return answer(srv, c, 403, "forbidden_origin", NULL);
        if ((unsafe || r->origin_count) && !origin_matches(r)) {
            if (!is_api) { refuse_page(srv, c); return 1; }
            return answer(srv, c, 403, "forbidden_origin", NULL);
        }
        if (r->sec_site[0]) {
            int ok = strcmp(r->sec_site, "same-origin") == 0;
            if (!is_api && strcmp(r->sec_site, "none") == 0) ok = 1;
            /* the first-run exception: the redirect file's navigation, while no wallet exists */
            if (!is_api && strcmp(r->path, "/") == 0 && r->method == M_GET && strcmp(r->sec_site, "cross-site") == 0 &&
                strcmp(r->sec_mode, "navigate") == 0 && strcmp(r->sec_dest, "document") == 0 &&
                wallet_state(srv) == GZ_API_WALLET_NONE)
                ok = 1;
            if (!ok) {
                if (!is_api) { refuse_page(srv, c); return 1; }
                return answer(srv, c, 403, "forbidden_origin", NULL);
            }
        }
        if (is_api && r->sec_dest[0] && strcmp(r->sec_dest, "empty") != 0)
            return answer(srv, c, 403, "forbidden_origin", NULL);
    }
    /* 5.3 and 3.1: the body's type and size, before it is read */
    r->content_length = c->parser.content_length;
    if (r->has_cl && r->content_length > srv->lim.max_body_bytes) return answer(srv, c, 413, "too_large", NULL);
    if (r->has_cl && r->content_length > 0) {
        if (r->method == M_GET || r->method == M_HEAD) return answer(srv, c, 400, "bad_request", NULL);
        if (r->ctype_count != 1 || !json_ctype(r->ctype)) return answer(srv, c, 415, "bad_content_type", NULL);
    }
    /* static files (5.4): compiled in, exact paths only */
    if (!is_api) {
        const char *body;
        size_t len;
        int page;
        if (r->method != M_GET && r->method != M_HEAD) return answer(srv, c, 405, "method_not_allowed", NULL);
        if (r->nq) return answer(srv, c, 404, "not_found", NULL);
        if (!gz_static_lookup(r->path, &body, &len, &page)) return answer(srv, c, 404, "not_found", NULL);
        r->route = NULL;
        c->state = CS_BODY;
        return 0;
    }
    for (i = 0; i < plen; i++) {
        char ch = r->path[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '/' ||
              ch == '_' || ch == '-'))
            return answer(srv, c, 404, "not_found", NULL);
    }
    for (i = 0; i < NROUTES; i++) {
        if (!match(ROUTES[i].pattern, r->path, NULL)) continue;
        path_known = 1;
        if (ROUTES[i].method != r->method) continue;
        method_seen = 1;
        r->route = &ROUTES[i];
        match(ROUTES[i].pattern, r->path, r);
        break;
    }
    if (!path_known) return answer(srv, c, 404, "not_found", NULL);
    if (!method_seen) return answer(srv, c, 405, "method_not_allowed", NULL);
    if (authorize(srv, c)) return 1;
    if (r->route->release != R_S1) {
        static const char *const REL[] = {"S1", "1.0.0", "1.1.0", "later"};
        char params[64];
        snprintf(params, sizeof params, "{\"release\":\"%s\"}", REL[r->route->release]);
        c->close_after = 1;
        gz_respond_error(srv, c, 501, "not_in_this_release", NULL, params);
        return 1;
    }
    if (r->route->query == NULL && r->nq) return answer(srv, c, 400, "unknown_field", NULL);
    if (r->nq && check_query(srv, c)) { c->close_after = 1; return 1; }
    if (r->has_cl && r->content_length > 0) {
        r->body = malloc((size_t)r->content_length);
        if (!r->body) return answer(srv, c, 503, "rate_limited", NULL);
        r->body_cap = (size_t)r->content_length;
        if (strcasecmp(r->expect, "100-continue") == 0 && c->fd >= 0) {
            static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
            gz_out_add(&c->out, cont, sizeof cont - 1);
        }
    }
    return 0;
}

static const char *method_name(int m)
{
    switch (m) {
    case M_GET: return "GET";
    case M_HEAD: return "HEAD";
    case M_POST: return "POST";
    case M_PUT: return "PUT";
    case M_PATCH: return "PATCH";
    case M_DELETE: return "DELETE";
    default: return "OTHER";
    }
}

/* ---- the body: schema (6, 7.1) ------------------------------------------------------------- */
static int check_schema(gz_api_server *srv, gz_conn *c, const gz_json *body)
{
    const field *sc = c->req.route ? c->req.route->schema : NULL;
    const gz_json *m;
    char ptr[80];
    if (!sc) sc = S_NONE;
    for (m = body->child; m; m = m->next) {
        const field *f;
        int known = 0;
        for (f = sc; f->name; f++) {
            if (strlen(f->name) != m->key_len || memcmp(f->name, m->key, m->key_len) != 0) continue;
            known = 1;
            snprintf(ptr, sizeof ptr, "/%s", f->name);
            if ((f->type == T_STR && m->type != GZ_JSON_STR) || (f->type == T_INT && m->type != GZ_JSON_INT) ||
                (f->type == T_BOOL && m->type != GZ_JSON_BOOL) || (f->type == T_OBJ && m->type != GZ_JSON_OBJ) ||
                (f->type == T_ARR && m->type != GZ_JSON_ARR)) {
                gz_respond_error(srv, c, 400, "bad_value", ptr, NULL);
                return 1;
            }
        }
        if (!known) {
            gz_jw w;
            gz_jw_init(&w);
            gz_jw_bytes(&w, "/", 1);
            gz_jw_bytes(&w, m->key, m->key_len < 64 ? m->key_len : 64);
            gz_respond_error(srv, c, 400, "unknown_field", w.err ? "/" : w.buf, NULL);
            gz_jw_free(&w);
            return 1;
        }
    }
    for (; sc->name; sc++) {
        if (sc->req && !gz_json_get(body, sc->name)) {
            snprintf(ptr, sizeof ptr, "/%s", sc->name);
            gz_respond_error(srv, c, 400, "missing_field", ptr, NULL);
            return 1;
        }
    }
    return 0;
}

static const char *jstr(const gz_json *body, const char *k)
{
    const gz_json *v = gz_json_get(body, k);
    return v && v->type == GZ_JSON_STR ? v->s : NULL;
}

static void confirm_mismatch(gz_api_server *srv, gz_conn *c, const char *field, const char *expected,
                             const char *got)
{
    gz_jw w;
    gz_jw_init(&w);
    gz_jw_obj(&w);
    gz_jw_kstr(&w, "expected", expected);
    gz_jw_kstr(&w, "got", got);
    gz_jw_end_obj(&w);
    gz_respond_error(srv, c, 409, "confirm_mismatch", field, w.err ? NULL : w.buf);
    gz_jw_free(&w);
}

/* ---- passphrase jobs ------------------------------------------------------------------------- */
static gz_session *req_session(gz_api_server *srv, int slot, uint64_t no)
{
    if (slot < 0 || slot >= GZ_SESSIONS_MAX) return NULL;
    if (!srv->sess[slot].used || srv->sess[slot].no != no) return NULL;
    return &srv->sess[slot];
}

static int start_job(gz_api_server *srv, gz_conn *c, int purpose, int op, const gz_json *body)
{
    gz_req *r = &c->req;
    const char *pass = jstr(body, "passphrase");
    int64_t retry = 0, now_ms = gz_mono_ms(srv);
    gz_job *j;
    size_t plen;
    if (!pass) { gz_respond_error(srv, c, 400, "missing_field", "/passphrase", NULL); return 1; }
    plen = gz_json_get(body, "passphrase")->len;
    if (plen == 0 || plen > 4096) { gz_respond_error(srv, c, 400, "bad_value", "/passphrase", NULL); return 1; }
    /* 4.3: the attempts file's delay, then the slot, before any derivation */
    if (srv->att_loaded && op != GZ_API_PP_CREATE && op != GZ_API_PP_RESTORE &&
        gz_attempts_gate(srv, now_ms, &retry)) {
        char params[48];
        if (retry < 0) { gz_respond_error(srv, c, 503, "passphrase_not_checked", NULL, NULL); return 1; }
        snprintf(params, sizeof params, "{\"retry_after_s\":%lld}", (long long)retry);
        gz_respond_error(srv, c, 429, "rate_limited", NULL, params);
        return 1;
    }
    j = calloc(1, sizeof *j);
    if (!j) { gz_respond_error(srv, c, 503, "passphrase_not_checked", NULL, NULL); return 1; }
    j->pass = malloc(plen);
    if (!j->pass) { free(j); gz_respond_error(srv, c, 503, "passphrase_not_checked", NULL, NULL); return 1; }
    memcpy(j->pass, pass, plen);
    j->pass_len = plen;
    j->purpose = purpose;
    j->pp.op = op;
    j->conn = c;
    j->sess_slot = r->sess_slot;
    j->sess_no = r->sess_no;
    j->was_locked = wallet_state(srv) != GZ_API_WALLET_UNLOCKED;
    j->bearer = r->bearer;
    j->token_gen = srv->token_gen;
    snprintf(j->host, sizeof j->host, "%s", r->host);
    if (op == GZ_API_PP_RESTORE || op == GZ_API_PP_WORDS_CHECK) {
        const gz_json *wa = gz_json_get(body, "words"), *wv;
        int n = 0;
        for (wv = wa ? wa->child : NULL; wv; wv = wv->next) {
            if (wv->type != GZ_JSON_STR || wv->len == 0 || wv->len >= GZ_API_WORD_MAX || n >= GZ_API_WORDS) {
                gz_job_free(j);
                gz_respond_error(srv, c, 400, "bad_value", "/words", NULL);
                return 1;
            }
            memcpy(j->pp.words[n++], wv->s, wv->len);
        }
        if (n != (op == GZ_API_PP_RESTORE ? GZ_API_WORDS : 3)) {
            gz_job_free(j);
            gz_respond_error(srv, c, 400, "bad_value", "/words", NULL);
            return 1;
        }
        j->pp.nwords = n;
        if (op == GZ_API_PP_WORDS_CHECK) {
            memcpy(j->pp.positions, srv->check_positions, sizeof j->pp.positions);
            memcpy(j->check_id, srv->check_id, sizeof j->check_id);
        }
    }
    c->job = j;
    c->state = CS_BUSY;
    if (gz_derive_submit(srv, j) != 0) {                /* both places taken: not counted (4.3) */
        c->job = NULL;
        gz_job_free(j);
        gz_respond_error(srv, c, 429, "rate_limited", NULL, "{\"retry_after_s\":1}");
        return 1;
    }
    return 0;
}

static void words_answer(gz_jw *w, const gz_api_pp_job *pp)
{
    int i;
    gz_jw_key(w, "words");
    gz_jw_arr(w);
    for (i = 0; i < GZ_API_WORDS; i++) gz_jw_str(w, pp->words[i]);
    gz_jw_end_arr(w);
}

static void session_fields(gz_api_server *srv, gz_jw *w, const gz_session *s)
{
    gz_api_status_facts f;
    int ws = wallet_state(srv);
    int64_t now = gz_now_ms(srv);
    memset(&f, 0, sizeof f);
    if (ws == GZ_API_WALLET_UNLOCKED) srv->be->status(srv->bectx, &f);
    gz_jw_kstr(w, "wallet", ws == GZ_API_WALLET_NONE ? "none" : ws == GZ_API_WALLET_LOCKED ? "locked"
                            : ws == GZ_API_WALLET_FILES_BEHIND ? "files_behind" : "unlocked");
    gz_jw_kbool(w, "signed_in", s != NULL);
    if (s) {
        gz_jw_kstr(w, "kind", s->kind == SK_SETUP ? "setup" : s->kind == SK_FILES_BEHIND ? "files_behind" : "normal");
        gz_jw_kint(w, "session_no", (int64_t)s->no);
        if (now < s->fresh_until) gz_jw_kint(w, "fresh_until_at", s->fresh_until / 1000);
        else gz_jw_knull(w, "fresh_until_at");
        gz_jw_kint(w, "idle_sign_out_at", (s->last_input + srv->lim.idle_sign_out_ms) / 1000);
        gz_jw_kint(w, "started_at", s->started / 1000);
    }
    gz_jw_kbool(w, "handover", srv->cfg.tunnel_port == 0);
    if (s) {
        gz_jw_key(w, "lock");
        if (f.lock_state) {
            gz_jw_obj(w);
            gz_jw_kstr(w, "state", f.lock_state);
            gz_jw_kstr(w, "lobby_id", f.lock_lobby_id);
            gz_jw_kint(w, "since_at", f.lock_since_at);
            gz_jw_end_obj(w);
        } else {
            gz_jw_null(w);
        }
    } else {
        gz_jw_key(w, "first_run_launched_at");
        if (srv->first_run_launched_at && ws == GZ_API_WALLET_NONE) gz_jw_int(w, srv->first_run_launched_at);
        else gz_jw_null(w);
    }
}

static void answer_new_session(gz_api_server *srv, gz_conn *c, gz_session *s, int status, const char *cause)
{
    gz_jw w;
    char b64[GZ_TOKEN_B64 + 1];
    gz_b64url(s->token, sizeof s->token, b64);
    gz_jw_init(&w);
    gz_jw_obj(&w);
    gz_jw_kstr(&w, "session", b64);
    session_fields(srv, &w, s);
    if (cause) {
        gz_jw_key(&w, "params");
        gz_jw_obj(&w);
        gz_jw_kstr(&w, "cause", cause);
        gz_jw_end_obj(&w);
    }
    gz_jw_end_obj(&w);
    gz_respond_json(srv, c, status, &w, NULL);
    gz_jw_free(&w);
    gz_wipe(b64, sizeof b64);
}

static void unlocked_now(gz_api_server *srv)
{
    if (!srv->have_socket_token) gz_socket_token_make(srv);   /* made at unlock (storage 12.2) */
    gz_events_notify(srv, "status", NULL);
}

static void wallet_made(gz_api_server *srv)
{
    gz_first_run_close(srv);                             /* every start token and code, for good (4.9) */
    gz_attempts_fresh_file(srv);
    gz_socket_token_make(srv);
    gz_events_notify(srv, "wallet", NULL);
    gz_events_notify(srv, "status", NULL);
}

static void warning(gz_jw *w, const char *fault)
{
    gz_jw_key(w, "warning");
    gz_jw_obj(w);
    gz_jw_kstr(w, "code", "done_with_fault");
    gz_jw_kstr(w, "fault", fault);
    gz_jw_end_obj(w);
}

static void call_backend(gz_api_server *srv, gz_conn *c, int phase_check, int *answered);

int gz_job_gated(const gz_job *j)
{
    return j->pp.op != GZ_API_PP_CREATE && j->pp.op != GZ_API_PP_RESTORE;   /* these cannot be wrong */
}

/* A words check is over: its check_id is free again, and spent if the check
 * was answered (one answer per check_id, 12.3). A newer check-start's id is
 * left alone. */
static void check_release(gz_api_server *srv, gz_job *j, int answered)
{
    if (j->purpose != JP_WORDS_CHECK || !j->check_id[0] || strcmp(srv->check_id, j->check_id) != 0) return;
    srv->check_busy = 0;
    if (answered) gz_wipe(srv->check_id, sizeof srv->check_id);
}

/* A job answered without its result (never derived, or discarded): frees it. */
void gz_job_refuse(gz_api_server *srv, gz_job *j, int status, const char *code, const char *params)
{
    gz_conn *c = j->conn;
    check_release(srv, j, 0);
    if (c) {
        c->job = NULL;
        if (c->state != CS_DEAD) gz_respond_error(srv, c, status, code, NULL, params);
    }
    gz_job_free(j);
}

static void count_result(gz_api_server *srv, const gz_api_pp_job *pp, int64_t now_ms)
{
    if (pp->result == GZ_API_PPR_WRONG) {
        if (srv->att_last_wrong_ms && now_ms - srv->att_last_wrong_ms < 2000)
            gz_log(srv, "wrong passphrases are arriving faster than a person types: another program may be trying");
        gz_attempts_wrong(srv, now_ms);
        gz_log(srv, "wrong passphrase (%u in a row)", (unsigned)srv->att_wrong);
    } else if (pp->result == GZ_API_PPR_OK || pp->result == GZ_API_PPR_WORDS_DIFFER ||
               pp->result == GZ_API_PPR_FILES_BEHIND) {
        if (pp->op != GZ_API_PP_CREATE && pp->op != GZ_API_PP_RESTORE && srv->att_loaded) gz_attempts_right(srv);
    }
}

void gz_job_finished(gz_api_server *srv, gz_job *j)
{
    gz_conn *c = j->conn;
    gz_api_pp_job *pp = &j->pp;
    const char *fault = NULL;
    gz_session *s = req_session(srv, j->sess_slot, j->sess_no);
    int64_t now = gz_now_ms(srv), now_s = now / 1000, mono = gz_mono_ms(srv);
    int verified = 0;
    if (pp->generation != gz_generation(srv)) {
        /* a lock, stop or restart since it was queued: nothing is installed, but a
         * wrong passphrase still counts (contract-v2 4, T4.4) */
        if (pp->result == GZ_API_PPR_WRONG) count_result(srv, pp, mono);
        if (srv->be->passphrase_discard) srv->be->passphrase_discard(srv->bectx, pp);
        gz_job_refuse(srv, j, 503, "passphrase_not_checked", NULL);
        return;
    }
    /* The wallet was locked since the passphrase was sent to be checked against
     * the unlocked one (review B1). The lock's new generation refuses such a
     * job first; this is the second guard. Nothing is installed or done; a
     * wrong passphrase still counts. */
    if (!j->was_locked && wallet_state(srv) != GZ_API_WALLET_UNLOCKED) {
        if (pp->result == GZ_API_PPR_WRONG) count_result(srv, pp, mono);
        if (srv->be->passphrase_discard) srv->be->passphrase_discard(srv->bectx, pp);
        gz_job_refuse(srv, j, 503, "passphrase_not_checked", NULL);
        return;
    }
    /* The session or socket token it was sent with was signed out, revoked or
     * dropped while it derived (review B2): nothing is installed, done or
     * answered for it (the 24 words are wiped with the job); a wrong passphrase
     * still counts. */
    if ((j->purpose != JP_SIGN_IN && j->sess_slot >= 0 && !s) || (j->bearer && j->token_gen != srv->token_gen)) {
        if (pp->result == GZ_API_PPR_WRONG) count_result(srv, pp, mono);
        if (srv->be->passphrase_discard) srv->be->passphrase_discard(srv->bectx, pp);
        gz_job_refuse(srv, j, 401, "not_signed_in", NULL);
        return;
    }
    if (srv->be->passphrase_done) srv->be->passphrase_done(srv->bectx, pp);   /* installs, on this thread */
    if (c) c->job = NULL;
    if (c && c->state == CS_DEAD) c = NULL;
    /* done with a fault (storage): in force, so done, with a warning (never a failure) */
    if (pp->result == GZ_API_PPR_DONE_WITH_FAULT) {
        fault = pp->reason && gz_valid_id(pp->reason, 1, 40) ? pp->reason : "fault";
        pp->result = GZ_API_PPR_OK;
        gz_log(srv, "the change is in force, but a step after it failed (%s)", fault);
        gz_events_notify(srv, "status", NULL);
    }
    /* the counter, whatever happens to the connection */
    count_result(srv, pp, mono);
    if (pp->result == GZ_API_PPR_OK || pp->result == GZ_API_PPR_WORDS_DIFFER || pp->result == GZ_API_PPR_FILES_BEHIND)
        verified = 1;
    if (pp->result == GZ_API_PPR_WRONG) {
        if (c) gz_respond_error(srv, c, 401, "wrong_passphrase", NULL, NULL);
        goto out;
    }
    if (pp->result == GZ_API_PPR_NOT_CHECKED) {
        if (c) gz_respond_error(srv, c, 503, "passphrase_not_checked", NULL, NULL);
        goto out;
    }
    switch (j->purpose) {
    case JP_SIGN_IN:
        if (pp->result == GZ_API_PPR_OK) {
            gz_session *ns;
            if (j->was_locked) unlocked_now(srv);
            if (!c) break;
            ns = gz_session_new(srv, SK_NORMAL, j->host);
            if (!ns) { gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"session\"}"); break; }
            ns->fresh_until = now + srv->lim.fresh_ms;  /* the sign-in itself opens the window (4.8) */
            c->req.log_session = ns->no;
            answer_new_session(srv, c, ns, 200, NULL);
        } else if (pp->result == GZ_API_PPR_FILES_BEHIND) {
            gz_session *ns;
            if (!c) break;
            ns = gz_session_new(srv, SK_FILES_BEHIND, j->host);
            if (!ns) { gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"session\"}"); break; }
            answer_new_session(srv, c, ns, 200, pp->reason ? pp->reason : "behind");
        } else if (pp->result == GZ_API_PPR_NODE_STOPPED) {
            char params[80];
            snprintf(params, sizeof params, "{\"reason\":\"%s\"}", pp->reason ? pp->reason : "storage_failed");
            if (c) gz_respond_error(srv, c, 503, "node_stopped", NULL, params);
        } else if (pp->result == GZ_API_PPR_NO_WALLET) {
            if (c) gz_respond_error(srv, c, 409, "no_wallet", NULL, NULL);
        } else if (c) {
            gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"sign_in\"}");
        }
        break;
    case JP_UNLOCK_SOCKET:
        if (pp->result == GZ_API_PPR_OK) {
            gz_jw w;
            if (j->was_locked) unlocked_now(srv);
            if (!c) break;
            gz_jw_init(&w);
            gz_jw_obj(&w);
            gz_jw_kstr(&w, "wallet", "unlocked");
            gz_jw_end_obj(&w);
            gz_respond_json(srv, c, 200, &w, NULL);
            gz_jw_free(&w);
        } else if (pp->result == GZ_API_PPR_FILES_BEHIND) {
            char params[64];
            snprintf(params, sizeof params, "{\"cause\":\"%s\"}", pp->reason ? pp->reason : "behind");
            if (c) gz_respond_error(srv, c, 409, "files_behind", NULL, params);
        } else if (pp->result == GZ_API_PPR_NODE_STOPPED) {
            char params[80];
            snprintf(params, sizeof params, "{\"reason\":\"%s\"}", pp->reason ? pp->reason : "storage_failed");
            if (c) gz_respond_error(srv, c, 503, "node_stopped", NULL, params);
        } else if (c) {
            gz_respond_error(srv, c, 409, "no_wallet", NULL, NULL);
        }
        break;
    case JP_FRESH:
        if (pp->result == GZ_API_PPR_OK && s) {
            gz_jw w;
            s->fresh_until = now + srv->lim.fresh_ms;
            if (!c) break;
            gz_jw_init(&w);
            gz_jw_obj(&w);
            gz_jw_kint(&w, "fresh_until_at", s->fresh_until / 1000);
            gz_jw_end_obj(&w);
            gz_respond_json(srv, c, 200, &w, NULL);
            gz_jw_free(&w);
        } else if (c) {
            gz_respond_error(srv, c, 401, "not_signed_in", NULL, NULL);
        }
        break;
    case JP_CREATE:
    case JP_RESTORE:
        if (pp->result == GZ_API_PPR_OK) {
            wallet_made(srv);
            if (s) {
                s->kind = SK_NORMAL;                    /* the setup session becomes normal (4.3) */
                s->fresh_until = now + srv->lim.fresh_ms;
            }
            if (!c) break;
            {
                gz_jw w;
                gz_jw_init(&w);
                gz_jw_obj(&w);
                if (j->purpose == JP_CREATE) {
                    words_answer(&w, pp);
                    gz_jw_kstr(&w, "shown_until", "this_answer");
                } else {
                    gz_jw_kstr(&w, "state", "restoring");
                }
                if (fault) warning(&w, fault);
                gz_jw_end_obj(&w);
                gz_respond_json(srv, c, j->purpose == JP_CREATE ? 200 : 202, &w, NULL);
                gz_jw_free(&w);
            }
        } else if (c) {
            if (pp->result == GZ_API_PPR_WEAK) {
                gz_jw w;
                gz_jw_init(&w);
                gz_jw_obj(&w);
                gz_jw_kstr(&w, "reason", pp->reason ? pp->reason : "too_short");
                if (pp->reason && strcmp(pp->reason, "too_short") == 0) {
                    gz_jw_kint(&w, "length", pp->a);
                    gz_jw_kint(&w, "minimum", pp->b);
                }
                gz_jw_end_obj(&w);
                gz_respond_error(srv, c, 400, "weak_passphrase", "/passphrase", w.err ? NULL : w.buf);
                gz_jw_free(&w);
            } else if (pp->result == GZ_API_PPR_EXISTS) {
                gz_respond_error(srv, c, 409, "wallet_exists", NULL, NULL);
            } else if (pp->result == GZ_API_PPR_BAD_WORDS) {
                char params[64];
                if (pp->reason && strcmp(pp->reason, "checksum") == 0) snprintf(params, sizeof params, "{\"reason\":\"checksum\"}");
                else snprintf(params, sizeof params, "{\"position\":%lld}", (long long)pp->a);
                gz_respond_error(srv, c, 400, "bad_words", "/words", params);
            } else {
                gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"create\"}");
            }
        }
        break;
    case JP_REVEAL:
        if (!c) break;
        if (pp->result == GZ_API_PPR_OK) {
            gz_jw w;
            gz_jw_init(&w);
            gz_jw_obj(&w);
            words_answer(&w, pp);
            gz_jw_end_obj(&w);
            gz_respond_json(srv, c, 200, &w, NULL);
            gz_jw_free(&w);
        } else {
            gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"reveal\"}");
        }
        break;
    case JP_WORDS_CHECK:
        if (pp->result == GZ_API_PPR_OK || pp->result == GZ_API_PPR_WORDS_DIFFER) {
            int ok = pp->result == GZ_API_PPR_OK;
            check_release(srv, j, 1);                   /* one answer per check_id */
            gz_events_notify(srv, "status", NULL);
            if (c) {
                gz_jw w;
                gz_jw_init(&w);
                gz_jw_obj(&w);
                gz_jw_kbool(&w, "ok", ok);
                if (ok) gz_jw_kint(&w, "checked_at", now_s);
                gz_jw_end_obj(&w);
                gz_respond_json(srv, c, 200, &w, NULL);
                gz_jw_free(&w);
            }
            if (!ok && s) gz_session_end(srv, s);        /* a failed check ends the session (4.9) */
        } else if (c) {
            gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"check\"}");
        }
        break;
    case JP_START_AS_RESTORE:
        if (pp->result == GZ_API_PPR_OK) {
            unlocked_now(srv);
            if (s) { s->kind = SK_NORMAL; s->fresh_until = 0; }
            gz_events_notify(srv, "reset", NULL);
            if (c) {
                gz_jw w;
                gz_jw_init(&w);
                gz_jw_obj(&w);
                gz_jw_kstr(&w, "wallet", "restoring");
                if (fault) warning(&w, fault);
                gz_jw_end_obj(&w);
                gz_respond_json(srv, c, 202, &w, NULL);
                gz_jw_free(&w);
            }
        } else if (c) {
            if (pp->result == GZ_API_PPR_NOT_FILES_BEHIND) gz_respond_error(srv, c, 409, "not_files_behind", NULL, NULL);
            else gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"restore\"}");
        }
        break;
    case JP_KIND_A:
        if (!c) break;                                   /* nobody to answer: nothing is done */
        if (pp->result == GZ_API_PPR_OK) {
            int answered = 0;
            call_backend(srv, c, 0, &answered);
        } else {
            gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"kind_a\"}");
        }
        break;
    }
out:
    (void)verified;
    check_release(srv, j, 0);                            /* wrong or not checked: the id stays usable */
    gz_job_free(j);
}

/* ---- the backend call --------------------------------------------------------------------------- */
static void call_backend(gz_api_server *srv, gz_conn *c, int phase_check, int *answered)
{
    gz_req *r = &c->req;
    gz_api_call call;
    gz_api_error err;
    gz_jw w;
    int status, effect = GZ_API_EFFECT_NONE, i, acts = (r->route->flags & F_ACT) && !phase_check;
    memset(&call, 0, sizeof call);
    memset(&err, 0, sizeof err);
    call.id = r->route->call;
    call.phase = phase_check ? GZ_API_PHASE_CHECK : GZ_API_PHASE_ACT;
    call.path_id = r->id1[0] ? r->id1 : NULL;
    call.path_id2 = r->id2[0] ? r->id2 : NULL;
    call.body = r->have_doc ? r->doc.root : NULL;
    for (i = 0; i < r->nq; i++) {
        call.query_name[i] = r->qname[i];
        call.query_value[i] = r->qvalue[i];
    }
    call.nquery = r->nq;
    call.fresh = r->fresh || r->bearer;
    call.bearer = r->bearer;
    call.now = gz_now_ms(srv) / 1000;
    call.method = method_name(r->method);
    call.path = r->path;
    call.pattern = r->route->pattern;
    if (r->have_digest) {
        call.request_id = jstr(r->doc.root, "request_id");
        call.digest = r->digest;
    }
    if (acts) call.handle = ++srv->next_handle;
    gz_jw_init(&w);
    srv->ctr.handler_calls++;
    status = srv->be->call(srv->bectx, &call, &w, &err, &effect);
    *answered = 1;
    if (status == GZ_API_HELD && acts) {
        /* held until the backend's outcome (gz_api_call_done), at most held_ms (contract-v2 11) */
        c->held = call.handle;
        c->state = CS_BUSY;
        c->deadline = gz_now_ms(srv) + srv->lim.held_ms;
    } else if (status >= 400) {
        gz_respond_error(srv, c, status, err.code ? err.code : "internal", err.field, err.params);
    } else if (phase_check && status == 0) {
        *answered = 0;                                   /* kind A: on to the passphrase */
    } else if (status >= 200 && status <= 204 && !w.err) {
        if (status == 204) {
            gz_respond(srv, c, 204, BK_JSON, NULL, NULL, 0);
        } else {
            if (!w.len) gz_jw_bytes(&w, "{}", 2);
            gz_respond_json(srv, c, status, &w, NULL);
        }
    } else {
        gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"backend_status\"}");
    }
    gz_jw_free(&w);
    if (effect == GZ_API_EFFECT_LOCKED) gz_api_locked(srv);
}

/* An acting call's outcome reaches its connection (loop thread). */
void gz_held_answer(gz_api_server *srv, gz_conn *c, int status, const char *body, const char *code,
                    const char *field, const char *params)
{
    c->held = 0;
    if (status >= 400) {
        gz_respond_error(srv, c, status, code && code[0] ? code : "internal", field, params && params[0] ? params : NULL);
    } else if (status == 204) {
        gz_respond(srv, c, 204, BK_JSON, NULL, NULL, 0);
    } else if (status >= 200 && status <= 203) {
        const char *b = body && body[0] ? body : "{}";
        gz_respond(srv, c, status, BK_JSON, NULL, b, strlen(b));
    } else {
        gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"backend_status\"}");
    }
}

/* ---- commands from other threads ----------------------------------------------------------------- */
enum { CMD_CALL_DONE = 1, CMD_NODE_STOPPED };
struct gz_cmd {
    int kind;
    uint64_t handle;
    int status;
    char *body;
    char code[48], field[80], params[768], reason[40];
    struct gz_cmd *next;
};

static void cmd_push(gz_api_server *srv, struct gz_cmd *m)
{
    char b = 0;
    ssize_t wr;
    pthread_mutex_lock(&srv->notify_mu);
    m->next = NULL;
    if (!srv->cmds_tail) srv->cmds_tail = &srv->cmds;
    *srv->cmds_tail = m;
    srv->cmds_tail = &m->next;
    pthread_mutex_unlock(&srv->notify_mu);
    wr = write(srv->wake[1], &b, 1);
    (void)wr;
}

void gz_api_call_done(gz_api_server *srv, uint64_t handle, int status, const char *body, const gz_api_error *err)
{
    struct gz_cmd *m = calloc(1, sizeof *m);
    if (!m) return;                                      /* the connection then answers node_busy */
    m->kind = CMD_CALL_DONE;
    m->handle = handle;
    m->status = status;
    if (body) m->body = strdup(body);
    if (err) {
        snprintf(m->code, sizeof m->code, "%s", err->code ? err->code : "internal");
        if (err->field) snprintf(m->field, sizeof m->field, "%s", err->field);
        snprintf(m->params, sizeof m->params, "%s", err->params);
    }
    cmd_push(srv, m);
}

void gz_api_server_node_stopped(gz_api_server *srv, const char *reason)
{
    struct gz_cmd *m = calloc(1, sizeof *m);
    if (!m) return;
    m->kind = CMD_NODE_STOPPED;
    snprintf(m->reason, sizeof m->reason, "%s", reason && gz_valid_id(reason, 1, 32) ? reason : "rebuilding");
    cmd_push(srv, m);
}

static void cmd_free(struct gz_cmd *m)
{
    if (m->body) { gz_wipe(m->body, strlen(m->body)); free(m->body); }
    gz_wipe(m, sizeof *m);
    free(m);
}

void gz_cmds_run(gz_api_server *srv)
{
    struct gz_cmd *list, *m;
    gz_conn *c;
    pthread_mutex_lock(&srv->notify_mu);
    list = srv->cmds;
    srv->cmds = NULL;
    srv->cmds_tail = &srv->cmds;
    pthread_mutex_unlock(&srv->notify_mu);
    while ((m = list)) {
        list = m->next;
        if (m->kind == CMD_CALL_DONE) {
            for (c = srv->conns; c; c = c->next)
                if (c->held == m->handle && c->state == CS_BUSY) {
                    gz_held_answer(srv, c, m->status, m->body, m->code, m->field[0] ? m->field : NULL, m->params);
                    break;
                }
        } else if (m->kind == CMD_NODE_STOPPED) {
            char params[80];
            snprintf(params, sizeof params, "{\"reason\":\"%s\"}", m->reason);
            for (c = srv->conns; c; c = c->next)
                if (c->held && c->state == CS_BUSY) gz_held_answer(srv, c, 503, NULL, "node_stopped", NULL, params);
        }
        cmd_free(m);
    }
}

void gz_cmds_free(gz_api_server *srv)
{
    struct gz_cmd *m;
    while ((m = srv->cmds)) { srv->cmds = m->next; cmd_free(m); }
    srv->cmds_tail = &srv->cmds;
}

void gz_api_locked(gz_api_server *srv)
{
    gz_api_server_new_generation(srv);                   /* jobs in flight are discarded (contract-v2 4, review B1) */
    gz_sessions_end_all(srv);                            /* sessions end when the key is dropped (4.9) */
    gz_socket_token_drop(srv);
    gz_events_notify(srv, "status", NULL);
}

/* ---- dispatch: the body is complete ---------------------------------------------------------- */
static void handle(gz_api_server *srv, gz_conn *c);

void gz_route_dispatch(gz_api_server *srv, gz_conn *c)
{
    gz_req *r = &c->req;
    gz_session *s;
    if (!r->route) {                                     /* a static file: checked at the head */
        const char *body;
        size_t len;
        int page;
        gz_static_lookup(r->path, &body, &len, &page);
        gz_respond(srv, c, 200, page ? BK_PAGE : BK_STATIC, NULL, body, len);
        return;
    }
    if (r->body_len) {
        int pr = gz_json_parse(r->body, r->body_len, &r->doc);
        gz_wipe(r->body, r->body_cap);                   /* the parsed copy is all that is kept */
        if (pr != 0) {
            gz_respond_error(srv, c, 400, "bad_json", NULL, NULL);
            goto done;
        }
        r->have_doc = 1;
        if (r->doc.root->type != GZ_JSON_OBJ) {
            gz_respond_error(srv, c, 400, "bad_json", NULL, NULL);
            goto done;
        }
        if (check_schema(srv, c, r->doc.root)) goto done;
    } else {
        const field *sc = r->route->schema;
        for (; sc && sc->name; sc++)
            if (sc->req) {
                char ptr[80];
                snprintf(ptr, sizeof ptr, "/%s", sc->name);
                gz_respond_error(srv, c, 400, "missing_field", ptr, NULL);
                goto done;
            }
    }
    /* the session was used; only the person's own input keeps it awake (4.7, review F9) */
    s = req_session(srv, r->sess_slot, r->sess_no);
    if (s) {
        int64_t now = gz_now_ms(srv);
        s->last_used = now;
        if (strcmp(r->user, "1") == 0) s->last_input = now;
        if (s->tunnel && gz_tunnel_host(srv, r->host)) s->tunnel_last = now;
    }
    /* 7.4: request ids. The server checks the form and computes the digest
     * (RFC 8785 without the passphrase); the engine owns the id: the 409s and
     * the replays are the backend's (contract-v2 11). */
    if (r->route->flags & F_RID) {
        const char *id = jstr(r->doc.root, "request_id");
        if (!id || !gz_valid_id(id, 16, 64)) {
            gz_respond_error(srv, c, 400, "bad_value", "/request_id", NULL);
            goto done;
        }
        if (gz_json_jcs_digest(r->doc.root, r->digest) != 0) {
            gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"digest\"}");
            goto done;
        }
        r->have_digest = 1;
    }
    /* 4.8 kind B: a fresh sign-in, always for these */
    if ((r->route->flags & F_FRESH) && !r->fresh && !r->bearer) {
        gz_respond_error(srv, c, 403, "fresh_sign_in_needed", NULL, NULL);
        goto done;
    }
    handle(srv, c);
done:
    return;
}

static void handle(gz_api_server *srv, gz_conn *c)
{
    gz_req *r = &c->req;
    const gz_json *body = r->have_doc ? r->doc.root : NULL;
    int ws = wallet_state(srv);
    gz_session *s = req_session(srv, r->sess_slot, r->sess_no);
    gz_jw w;
    int answered;
    gz_jw_init(&w);
    switch (r->route->handler) {
    case H_VERSION:
        gz_jw_obj(&w);
        gz_jw_kstr(&w, "api", "1.0");
        gz_jw_kstr(&w, "program", srv->be->program_version);
        gz_jw_kstr(&w, "network", srv->be->network);
        gz_jw_kstr(&w, "run_id", srv->run_id);
        gz_jw_end_obj(&w);
        gz_respond_json(srv, c, 200, &w, NULL);
        break;
    case H_SESSION_GET:
        gz_jw_obj(&w);
        session_fields(srv, &w, s);
        gz_jw_end_obj(&w);
        gz_respond_json(srv, c, 200, &w, NULL);
        break;
    case H_SESSION_POST:
        if (ws == GZ_API_WALLET_NONE) { gz_respond_error(srv, c, 409, "no_wallet", NULL, NULL); break; }
        if (start_job(srv, c, JP_SIGN_IN, ws == GZ_API_WALLET_UNLOCKED ? GZ_API_PP_CHECK : GZ_API_PP_UNLOCK, body))
            break;
        break;
    case H_SESSION_START: {
        const char *tok = jstr(body, "start_token"), *code = jstr(body, "code"), *e;
        int64_t used_at = 0;
        gz_session *ns;
        if ((tok != NULL) == (code != NULL)) {
            gz_respond_error(srv, c, 400, tok ? "bad_value" : "missing_field", "/start_token", NULL);
            break;
        }
        if (ws != GZ_API_WALLET_NONE || srv->first_run_closed) {
            gz_respond_error(srv, c, 409, "wallet_exists", NULL, NULL);
            break;
        }
        e = tok ? gz_start_token_present(srv, tok, &used_at) : gz_code_present(srv, code);
        if (e) {
            char params[48];
            params[0] = 0;
            if (strcmp(e, "token_used") == 0) snprintf(params, sizeof params, "{\"used_at\":%lld}", (long long)used_at);
            if (strcmp(e, "rate_limited") == 0) snprintf(params, sizeof params, "{\"retry_after_s\":1}");
            gz_respond_error(srv, c,
                             strcmp(e, "token_used") == 0 ? 409
                             : (strcmp(e, "rate_limited") == 0 || strcmp(e, "too_many_attempts") == 0) ? 429 : 401,
                             e, NULL, params);
            break;
        }
        ns = gz_session_new(srv, SK_SETUP, r->host);
        if (!ns) { gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"session\"}"); break; }
        {
            char b64[GZ_TOKEN_B64 + 1];
            gz_b64url(ns->token, sizeof ns->token, b64);
            gz_jw_obj(&w);
            gz_jw_kstr(&w, "session", b64);
            gz_jw_kstr(&w, "kind", "setup");
            gz_jw_end_obj(&w);
            gz_wipe(b64, sizeof b64);
        }
        gz_respond_json(srv, c, 200, &w, NULL);
        break;
    }
    case H_SESSION_FRESH:
        if (start_job(srv, c, JP_FRESH, GZ_API_PP_CHECK, body)) break;
        break;
    case H_SESSION_DELETE:
        if (s) gz_session_end(srv, s);
        gz_respond(srv, c, 204, BK_JSON, "Clear-Site-Data: \"cache\", \"storage\"\r\n", NULL, 0);
        break;
    case H_REVOKE_ALL: {
        const char *cf = jstr(body, "confirm");
        if (strcmp(cf, "revoke_all") != 0) { confirm_mismatch(srv, c, "/confirm", "revoke_all", cf); break; }
        gz_sessions_end_all(srv);
        gz_wipe(srv->codes, sizeof srv->codes);
        if (srv->have_start_token) gz_first_run_close(srv);
        if (srv->have_socket_token) gz_socket_token_make(srv);   /* rotated (4.9) */
        gz_log(srv, "every session was revoked");
        gz_respond(srv, c, 204, BK_JSON, "Clear-Site-Data: \"cache\", \"storage\"\r\n", NULL, 0);
        break;
    }
    case H_LOCK:
        /* a lock stops every passphrase job in flight, held lock or not (review B1) */
        gz_api_server_new_generation(srv);
        call_backend(srv, c, 0, &answered);
        break;
    case H_START_AS_RESTORE: {
        const char *cf = jstr(body, "confirm");
        if (strcmp(cf, "restore_new_keys") != 0) { confirm_mismatch(srv, c, "/confirm", "restore_new_keys", cf); break; }
        if (ws != GZ_API_WALLET_FILES_BEHIND) { gz_respond_error(srv, c, 409, "not_files_behind", NULL, NULL); break; }
        if (!c->is_unix && (!s || s->kind != SK_FILES_BEHIND)) {
            gz_respond_error(srv, c, 409, "not_files_behind", NULL, NULL);
            break;
        }
        if (start_job(srv, c, JP_START_AS_RESTORE, GZ_API_PP_START_AS_RESTORE, body)) break;
        break;
    }
    case H_UNLOCK:
        if (ws == GZ_API_WALLET_NONE) { gz_respond_error(srv, c, 409, "no_wallet", NULL, NULL); break; }
        if (start_job(srv, c, JP_UNLOCK_SOCKET, ws == GZ_API_WALLET_UNLOCKED ? GZ_API_PP_CHECK : GZ_API_PP_UNLOCK, body))
            break;
        break;
    case H_FIRST_RUN_CODES: {
        char code[12];
        int64_t exp;
        if (ws != GZ_API_WALLET_NONE || srv->first_run_closed) { gz_respond_error(srv, c, 409, "wallet_exists", NULL, NULL); break; }
        if (gz_code_make(srv, code, &exp) != 0) { gz_respond_error(srv, c, 500, "internal", NULL, NULL); break; }
        gz_jw_obj(&w);
        gz_jw_kstr(&w, "code", code);
        gz_jw_kint(&w, "expires_at", exp);
        gz_jw_end_obj(&w);
        gz_wipe(code, sizeof code);
        gz_respond_json(srv, c, 200, &w, NULL);
        break;
    }
    case H_EVENTS: {
        int total, mine = gz_streams_count(srv, r->bearer ? -1 : r->sess_slot, r->bearer ? 0 : r->sess_no, &total);
        if (mine >= GZ_STREAMS_PER_SESSION || total >= GZ_STREAMS_MAX) {
            gz_respond_error(srv, c, 429, "too_many_streams", NULL, NULL);
            break;
        }
        gz_stream_open(srv, c, r->bearer ? -1 : r->sess_slot, r->bearer ? 0 : r->sess_no);
        break;
    }
    case H_STATUS: {
        int locked = ws == GZ_API_WALLET_LOCKED || ws == GZ_API_WALLET_FILES_BEHIND;
        int dates_ok = s != NULL || c->is_unix || srv->peer_check_ok;
        if (!locked && !s && !r->bearer) { gz_respond_error(srv, c, 401, "not_signed_in", NULL, NULL); break; }
        if (gz_status_write(srv, &w, locked, dates_ok) != 0) {
            gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"status\"}");
            break;
        }
        gz_respond_json(srv, c, 200, &w, NULL);
        break;
    }
    case H_CREATE:
    case H_RESTORE: {
        const gz_json *p1 = gz_json_get(body, "passphrase"), *p2 = gz_json_get(body, "confirm_passphrase");
        if (!r->bearer && (!s || s->kind != SK_SETUP)) { gz_respond_error(srv, c, 403, "not_setup_session", NULL, NULL); break; }
        if (r->bearer) { gz_respond_error(srv, c, 403, "not_setup_session", NULL, NULL); break; }
        if (r->route->handler == H_CREATE) {
            const char *cf = jstr(body, "confirm");
            if (strcmp(cf, "create_wallet") != 0) { confirm_mismatch(srv, c, "/confirm", "create_wallet", cf); break; }
        }
        if (p1->len != p2->len || !gz_ct_eq(p1->s, p2->s, p1->len)) {
            gz_respond_error(srv, c, 400, "passphrases_differ", "/confirm_passphrase", NULL);
            break;
        }
        if (ws != GZ_API_WALLET_NONE) { gz_respond_error(srv, c, 409, "wallet_exists", NULL, NULL); break; }
        if (start_job(srv, c, r->route->handler == H_CREATE ? JP_CREATE : JP_RESTORE,
                      r->route->handler == H_CREATE ? GZ_API_PP_CREATE : GZ_API_PP_RESTORE, body))
            break;
        break;
    }
    case H_REVEAL: {
        const char *cf = jstr(body, "confirm");
        if (strcmp(cf, "show_words") != 0) { confirm_mismatch(srv, c, "/confirm", "show_words", cf); break; }
        if (ws != GZ_API_WALLET_UNLOCKED) { gz_respond_error(srv, c, 409, "no_wallet", NULL, NULL); break; }
        if (start_job(srv, c, JP_REVEAL, GZ_API_PP_REVEAL, body)) break;
        break;
    }
    case H_CHECK_START: {
        uint8_t rb[16 + 8];
        int64_t retry = 0, now = gz_now_ms(srv);
        int left, i, k;
        if (ws != GZ_API_WALLET_UNLOCKED) { gz_respond_error(srv, c, 409, "no_wallet", NULL, NULL); break; }
        left = srv->be->words_checks_left ? srv->be->words_checks_left(srv->bectx, now / 1000, &retry) : 3;
        if (gz_random(rb, sizeof rb) != 0) { gz_respond_error(srv, c, 500, "internal", NULL, NULL); break; }
        gz_b64url(rb, 16, srv->check_id);                  /* a new check-start replaces any unused one */
        srv->check_busy = 0;
        for (i = 0; i < 3; i++) {                          /* three distinct positions, 1 to 24 */
            int p;
            uint32_t x = rb[16 + 2 * i] | ((uint32_t)rb[17 + 2 * i] << 8);
            for (;;) {
                p = (int)(x % 24) + 1;
                for (k = 0; k < i; k++)
                    if (srv->check_positions[k] == p) break;
                if (k == i) break;
                x = x / 24 + 7 + (uint32_t)i;
            }
            srv->check_positions[i] = p;
        }
        for (i = 0; i < 2; i++)
            for (k = 0; k < 2 - i; k++)
                if (srv->check_positions[k] > srv->check_positions[k + 1]) {
                    int t = srv->check_positions[k];
                    srv->check_positions[k] = srv->check_positions[k + 1];
                    srv->check_positions[k + 1] = t;
                }
        srv->check_expires = now + 10 * 60 * 1000;
        srv->check_session_no = r->bearer ? 0 : r->sess_no;
        gz_jw_obj(&w);
        gz_jw_kstr(&w, "check_id", srv->check_id);
        gz_jw_key(&w, "positions");
        gz_jw_arr(&w);
        for (i = 0; i < 3; i++) gz_jw_int(&w, srv->check_positions[i]);
        gz_jw_end_arr(&w);
        gz_jw_kint(&w, "checks_left_today", left);
        gz_jw_kint(&w, "expires_at", srv->check_expires / 1000);
        gz_jw_end_obj(&w);
        gz_respond_json(srv, c, 200, &w, NULL);
        break;
    }
    case H_CHECK: {
        const char *id = jstr(body, "check_id");
        int64_t retry = 0, now_s = gz_now_ms(srv) / 1000, gate;
        uint8_t want[16], got[16];
        int same = srv->check_id[0] && strlen(id) == 22 &&
                   gz_b64url_decode(srv->check_id, 22, want, sizeof want) == 0 &&
                   gz_b64url_decode(id, 22, got, sizeof got) == 0 && gz_ct_eq(want, got, 16);   /* F5.3 */
        gz_wipe(want, sizeof want);
        gz_wipe(got, sizeof got);
        if (!same || srv->check_busy || srv->check_session_no != (r->bearer ? 0 : r->sess_no)) {
            gz_respond_error(srv, c, 400, "bad_value", "/check_id", NULL);
            break;
        }
        if (srv->att_loaded && gz_attempts_gate(srv, gz_mono_ms(srv), &gate)) {
            char params[48];
            if (gate < 0) { gz_respond_error(srv, c, 503, "passphrase_not_checked", NULL, NULL); break; }
            snprintf(params, sizeof params, "{\"retry_after_s\":%lld}", (long long)gate);
            gz_respond_error(srv, c, 429, "rate_limited", NULL, params);
            break;
        }
        if (srv->be->words_checks_left && srv->be->words_checks_left(srv->bectx, now_s, &retry) <= 0) {
            char params[48];
            snprintf(params, sizeof params, "{\"retry_after_s\":%lld}", (long long)retry);
            gz_respond_error(srv, c, 429, "rate_limited", NULL, params);   /* before any derivation (12.3) */
            break;
        }
        srv->check_busy = 1;                             /* until its answer: a second request is refused (review B3) */
        if (start_job(srv, c, JP_WORDS_CHECK, GZ_API_PP_WORDS_CHECK, body)) srv->check_busy = 0;
        break;
    }
    case H_HOST_OPEN:
        /* kind A: everything but the passphrase first, so a refused request costs no derivation */
        call_backend(srv, c, 1, &answered);
        if (answered) break;
        if (start_job(srv, c, JP_KIND_A, GZ_API_PP_CHECK, body)) break;
        break;
    case H_PAUSE: {
        const gz_json *on = gz_json_get(body, "on");
        if (!on->i) {                                    /* resume: kind B (4.8, D6) */
            const char *cf = jstr(body, "confirm");
            if (!r->fresh && !r->bearer) { gz_respond_error(srv, c, 403, "fresh_sign_in_needed", NULL, NULL); break; }
            if (!cf || strcmp(cf, "resume") != 0) { confirm_mismatch(srv, c, "/confirm", "resume", cf); break; }
        }
        call_backend(srv, c, 0, &answered);
        break;
    }
    case H_CALL:
        call_backend(srv, c, 0, &answered);
        break;
    default:
        gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"handler\"}");
    }
    gz_jw_free(&w);
}
