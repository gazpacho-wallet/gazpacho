/* SPDX-License-Identifier: MIT */
/* The local API server inside the program: see api.h. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "gazpacho/api_json.h"
#include "gazpacho/command.h"
#include "gazpacho/envelope.h"
#include "api.h"
#include "api_lobby.h"
#include "gazpacho/view.h"
#include "unlock_impl.h"

/* ---- the passphrase layer behind the server's passphrase operations ---------- */

static int wallet_state(void *be)
{
    gzp_api_t *a = be;
    switch (a->unlock.state(a->unlock.ctx)) {
    case GZP_WALLET_NONE: return GZ_API_WALLET_NONE;
    case GZP_WALLET_UNLOCKED: return GZ_API_WALLET_UNLOCKED;
    default: return GZ_API_WALLET_LOCKED;
    }
}

static int op_of(int api_op)
{
    switch (api_op) {
    case GZ_API_PP_UNLOCK: return GZP_UNLOCK_OP_UNLOCK;
    case GZ_API_PP_CHECK: return GZP_UNLOCK_OP_CHECK;
    case GZ_API_PP_CREATE: return GZP_UNLOCK_OP_CREATE;
    case GZ_API_PP_RESTORE: return GZP_UNLOCK_OP_RESTORE;
    case GZ_API_PP_REVEAL: return GZP_UNLOCK_OP_REVEAL;
    case GZ_API_PP_WORDS_CHECK: return GZP_UNLOCK_OP_WORDS_CHECK;
    default: return 0;   /* start-as-restore: no files-behind state without encrypted storage */
    }
}

static void map_result(const gzp_unlock_result_t *r, gz_api_pp_job *job)
{
    job->reason = r->reason;
    job->a = job->b = 0;
    switch (r->status) {
    case GZP_UNLOCK_OK: job->result = GZ_API_PPR_OK; break;
    case GZP_UNLOCK_WRONG: job->result = GZ_API_PPR_WRONG; break;
    case GZP_UNLOCK_NO_WALLET: job->result = GZ_API_PPR_NO_WALLET; break;
    case GZP_UNLOCK_EXISTS: job->result = GZ_API_PPR_EXISTS; break;
    case GZP_UNLOCK_WEAK:
        job->result = GZ_API_PPR_WEAK;
        job->a = r->length;
        job->b = r->minimum;
        break;
    case GZP_UNLOCK_BAD_WORDS:
        job->result = GZ_API_PPR_BAD_WORDS;
        job->a = r->position;
        break;
    case GZP_UNLOCK_FILES_BEHIND: job->result = GZ_API_PPR_FILES_BEHIND; break;
    case GZP_UNLOCK_WORDS_DIFFER: job->result = GZ_API_PPR_WORDS_DIFFER; break;
    case GZP_UNLOCK_STORAGE_FAILED:
        job->result = GZ_API_PPR_NODE_STOPPED;
        job->reason = r->reason && !strcmp(r->reason, "not_built") ? "not_built" : "storage_failed";
        break;
    default: job->result = GZ_API_PPR_NOT_CHECKED; break;   /* busy, not checked: never counted */
    }
}

/* Derivation thread: only derives (api_backend.h). */
static void pp_op(void *be, gz_api_pp_job *job)
{
    gzp_api_t *a = be;
    gzp_unlock_job_t *u = calloc(1, sizeof *u);
    int i;
    job->out = u;
    if (!u) {
        job->result = GZ_API_PPR_NOT_CHECKED;
        return;
    }
    u->op = op_of(job->op);
    if (!u->op) {
        job->result = GZ_API_PPR_NOT_FILES_BEHIND;
        return;
    }
    u->passphrase = job->passphrase;
    u->passphrase_len = job->passphrase_len;
    for (i = 0; i < GZ_API_WORDS && i < GZP_UNLOCK_WORDS; i++) memcpy(u->words[i], job->words[i], GZP_UNLOCK_WORD_MAX);
    for (i = 0; i < 3; i++) u->positions[i] = job->positions[i];
    a->unlock.begin(a->unlock.ctx, u);
    map_result(&u->result, job);
}

static void wipe_job(gzp_unlock_job_t *u)
{
    OPENSSL_cleanse(u, sizeof *u);
    free(u);
}

/* Loop thread: install, then hand the words out where the call returns them. */
static void pp_done(void *be, gz_api_pp_job *job)
{
    gzp_api_t *a = be;
    gzp_unlock_job_t *u = job->out;
    int i;
    job->out = NULL;
    if (!u) return;
    u->passphrase = job->passphrase;
    u->passphrase_len = job->passphrase_len;
    if (u->op) a->unlock.finish(a->unlock.ctx, u, (int64_t)gzp_mono_ms());
    if (u->op) map_result(&u->result, job);
    if (job->result == GZ_API_PPR_OK && (u->op == GZP_UNLOCK_OP_CREATE || u->op == GZP_UNLOCK_OP_REVEAL)) {
        for (i = 0; i < GZ_API_WORDS; i++) memcpy(job->words[i], u->words[i], GZ_API_WORD_MAX);
        job->nwords = GZ_API_WORDS;
    }
    if (job->result == GZ_API_PPR_OK && u->op == GZP_UNLOCK_OP_RESTORE) a->setup_done = 0;
    wipe_job(u);
}

static void pp_discard(void *be, gz_api_pp_job *job)
{
    gzp_api_t *a = be;
    gzp_unlock_job_t *u = job->out;
    job->out = NULL;
    if (!u) return;
    u->passphrase = NULL;
    u->passphrase_len = 0;
    if (u->op) a->unlock.discard(a->unlock.ctx, u, (int64_t)gzp_mono_ms());
    wipe_job(u);
}

/* Words checks left in 24 hours: the program keeps none of its own yet (P6a's
 * API engine saves them, local-api.md 7.5); the server's limit applies. */
static int words_checks_left(void *be, int64_t now, int64_t *retry)
{
    (void)be;
    (void)now;
    *retry = 0;
    return 3;
}

/* ---- status (local-api.md 11) --------------------------------------------- */

static int status(void *be, gz_api_status_facts *f)
{
    gzp_api_t *a = be;
    int w = wallet_state(a);
    f->network = a->network;
    f->test_coins = 1;
    f->wallet = w == GZ_API_WALLET_NONE ? GZ_API_STW_NONE
              : w == GZ_API_WALLET_LOCKED ? GZ_API_STW_LOCKED
              : !a->node_running ? GZ_API_STW_NODE_STOPPED
              : a->setup_done ? GZ_API_STW_READY : GZ_API_STW_CREATED_NOT_FINISHED;
    if (f->wallet == GZ_API_STW_NODE_STOPPED) f->wallet_reason = "rebuilding";
    /* The chain view, honestly: the program asks one server, so a known tip is
     * one source, never "agree" (11.2's table). */
    if (!a->chain || !a->chain->active) f->chain_state = GZ_API_CHAIN_UNREACHABLE;
    else if (!a->chain->have_tip) f->chain_state = GZ_API_CHAIN_CATCHING_UP;
    else f->chain_state = GZ_API_CHAIN_ONE_SOURCE;
    f->chain_height = a->chain && a->chain->have_tip ? (int64_t)a->chain->tip.height : 0;
    f->servers_agreeing = a->chain && a->chain->have_tip ? 1 : 0;
    f->operators = f->servers_agreeing;
    f->version = 1;
    f->pause_state = "off";
    f->memory_locked = 0;
    f->has_something_to_watch = 0;
    f->lock_since = "start";
    f->watcher_runs = 0;
    f->watching_reason = "no_bundle";
    f->as_of_height = f->chain_height;
    return 0;
}

/* ---- calls ------------------------------------------------------------------ */

static int not_yet(gz_api_error *err, const char *needs)
{
    gz_api_err_set(err, "not_in_this_release", NULL, "{\"release\":\"slice1\",\"needs\":\"%s\"}", needs);
    return 501;
}

static void empty_page(gz_jw *w, const gzp_api_t *a)
{
    gz_jw_obj(w);
    gz_jw_key(w, "items");
    gz_jw_arr(w);
    gz_jw_end_arr(w);
    gz_jw_knull(w, "next_cursor");
    gz_jw_key(w, "as_of");
    gz_jw_obj(w);
    gz_jw_kint(w, "height", a->chain && a->chain->have_tip ? (int64_t)a->chain->tip.height : 0);
    gz_jw_kint(w, "at", (int64_t)(gzp_wall_ms() / 1000));
    gz_jw_end_obj(w);
    gz_jw_end_obj(w);
}

static const char *jstr(const gz_json *b, const char *k)
{
    const gz_json *v = b ? gz_json_get(b, k) : NULL;
    return v && v->type == GZ_JSON_STR ? v->s : NULL;
}

/* GET /api/v1/signing (14.3), from the status object's GZ_VST_SIGNING. */
static void signing_get(gzp_api_t *a, gz_jw *w)
{
    static const char *const name[] = {"at_join", "auto", "when_unlocked"};
    const gzp_view_obj_t *o = gzp_view_find(&a->view, GZ_VIEW_STATUS, GZ_VIEW_STATUS_ID);
    gz_bytes_t all = {o ? o->bytes : NULL, o ? o->len : 0}, v;
    int now = a->member_signing, pend = 0xff;
    uint32_t version = 0;
    if (o && gz_rec_find(all, GZ_VST_SIGNING, &v) == 1 && v.len == 7) {
        now = v.data[0];
        pend = v.data[1];
        version = gz_get_u32(v.data + 2);
    }
    gz_jw_obj(w);
    gz_jw_kstr(w, "member_signing", name[now % 3]);
    if (pend < 3) gz_jw_kstr(w, "pending", name[pend]);
    else gz_jw_knull(w, "pending");
    gz_jw_kraw(w, "available", "[\"at_join\",\"auto\"]");
    gz_jw_knull(w, "node_gate");
    gz_jw_kstr(w, "host_funding", "auto");
    gz_jw_kint(w, "version", version);
    gz_jw_end_obj(w);
}

static int call(void *be, const gz_api_call *c, gz_jw *w, gz_api_error *err, int *effect)
{
    gzp_api_t *a = be;
    int unlocked = wallet_state(a) == GZ_API_WALLET_UNLOCKED;
    switch (c->id) {
    case GZ_API_C_SETUP_GET:
        gz_jw_obj(w);
        gz_jw_kstr(w, "state", wallet_state(a) == GZ_API_WALLET_NONE ? "none" : a->setup_done ? "ready" : "created_not_finished");
        gz_jw_kstr(w, "network", a->network);
        gz_jw_kraw(w, "networks", strcmp(a->network, "signet") == 0
                   ? "[{\"id\":\"signet\",\"available\":true},{\"id\":\"testnet4\",\"available\":false,\"reason\":\"one_operator\"},"
                     "{\"id\":\"mainnet\",\"available\":false,\"reason\":\"switched_off_in_release\"}]"
                   : "[{\"id\":\"signet\",\"available\":false,\"reason\":\"other_network\"},{\"id\":\"testnet4\",\"available\":true},"
                     "{\"id\":\"mainnet\",\"available\":false,\"reason\":\"switched_off_in_release\"}]");
        gz_jw_kint(w, "words", 24);
        gz_jw_end_obj(w);
        return 200;
    case GZ_API_C_FINISH_SETUP: {
        const char *find = jstr(c->body, "find");
        if (!unlocked) { gz_api_err_set(err, "no_wallet", NULL, NULL); return 409; }
        if (!find || strcmp(find, "browse") != 0) {
            gz_api_err_set(err, "bad_value", "/find", "{\"allowed\":[\"browse\"]}");
            return 400;
        }
        /* The preset is the API engine's to save with the conditions (P6a). */
        a->setup_done = 1;
        gz_jw_obj(w);
        gz_jw_kstr(w, "state", "ready");
        gz_jw_end_obj(w);
        gz_api_notify(a->srv, "status", NULL);
        return 200;
    }
    case GZ_API_C_RESTORE_GET:
        gz_jw_obj(w);
        gz_jw_kstr(w, "state", "done");
        gz_jw_kint(w, "on_chain_found_sat", 0);
        gz_jw_kstr(w, "factories", "none");
        gz_jw_kraw(w, "lost_seats", "[]");
        gz_jw_end_obj(w);
        return 200;
    case GZ_API_C_BACKUP_GET:
        gz_jw_obj(w);
        gz_jw_key(w, "words");
        gz_jw_obj(w);
        gz_jw_knull(w, "checked_at");          /* saved by the API engine (P6a, 7.5) */
        gz_jw_kint(w, "checks_left_today", 3);
        gz_jw_end_obj(w);
        gz_jw_end_obj(w);
        return 200;
    case GZ_API_C_CONNECTIONS_GET: {
        int tip = a->chain && a->chain->have_tip;
        char srv[300];
        snprintf(srv, sizeof srv,
                 "{\"mode\":\"public\",\"servers\":[{\"id\":\"s1\",\"name\":\"configured server\",\"operator\":\"unknown\","
                 "\"protocol\":\"https\",\"state\":\"%s\",\"height\":%lld,\"checked_at\":null}],\"own_server\":null,\"own_node\":null}",
                 !a->chain || !a->chain->active ? "unreachable" : tip ? "ok" : "catching_up",
                 tip ? (long long)a->chain->tip.height : 0LL);
        gz_jw_obj(w);
        gz_jw_kint(w, "version", 1);
        gz_jw_kraw(w, "chain", a->chain && a->chain->active ? srv
                   : "{\"mode\":\"public\",\"servers\":[],\"own_server\":null,\"own_node\":null}");
        gz_jw_kraw(w, "listings", "{\"nostr\":{\"on\":false},\"relays\":[]}");
        gz_jw_kraw(w, "hosts", "[]");
        gz_jw_kraw(w, "privacy", "{\"route\":\"direct\"}");
        gz_jw_end_obj(w);
        return 200;
    }
    case GZ_API_C_FACTORIES:
    case GZ_API_C_ACTIVITY:
        /* Factories (P4.5) and activity entries (P6b) are not in the view yet. */
        empty_page(w, a);
        return 200;
    case GZ_API_C_FACTORY:
    case GZ_API_C_FACTORY_DATES:
    case GZ_API_C_ACTIVITY_ONE:
        gz_api_err_set(err, "not_found", NULL, NULL);
        return 404;
    case GZ_API_C_WALLET:
        gz_jw_obj(w);
        gz_jw_kint(w, "free_sat", 0);
        gz_jw_kint(w, "unconfirmed_sat", 0);
        gz_jw_kint(w, "set_aside_sat", 0);
        gz_jw_kraw(w, "set_aside_for", "[]");
        gz_jw_kraw(w, "coins", "[]");
        gz_jw_kint(w, "as_of_height", a->chain && a->chain->have_tip ? (int64_t)a->chain->tip.height : 0);
        gz_jw_kstr(w, "chain_view", "in_doubt");   /* one source (11.2) */
        gz_jw_end_obj(w);
        return 200;
    case GZ_API_C_LOCK: {
        const char *cf = jstr(c->body, "confirm");
        if (!cf || strcmp(cf, "lock_wallet") != 0) {
            gz_api_err_set(err, "confirm_mismatch", "/confirm", "{\"expected\":\"lock_wallet\"}");
            return 409;
        }
        a->unlock.lock(a->unlock.ctx);
        a->lock_pending = 1;                           /* the loop stops the node next (unlock.h) */
        *effect = GZ_API_EFFECT_LOCKED;
        gz_jw_obj(w);
        gz_jw_kstr(w, "wallet", "locked");
        gz_jw_end_obj(w);
        return 202;
    }
    case GZ_API_C_WALLET_ADDRESS:
        return not_yet(err, "wallet");
    case GZ_API_C_SIGNING_GET:
        signing_get(a, w);
        return 200;
    default: {
        /* Conditions, discovery, joining, readying, hosting, pause and the
         * signing setting: the core's lobby and API engine (api_calls.c). */
        int st;
        if (!unlocked) {
            gz_api_err_set(err, "locked", NULL, NULL);
            return 409;
        }
        st = gzp_api_lobby_call(a, c, w, err);
        return st >= 0 ? st : not_yet(err, "core-view");
    }
    }
}

/* One backend per process; its network is set when the server is made. */
static gz_api_backend gzp_backend = {
    "0.1.0", "signet", wallet_state, pp_op, pp_done, status, call, NULL, words_checks_left, pp_discard,
};

/* ---- held calls and the node's notices ---------------------------------------- */

int gzp_api_send_command(gzp_api_t *a, const gz_api_call *c, uint16_t code, const uint8_t *args, size_t args_len,
                         gz_api_error *err)
{
    uint8_t *buf;
    uint8_t c2[2];
    size_t at = 0, cap = args_len + 1200, n;
    int i, slot = -1, rc;
    if (!a->node_running || !a->command) {
        gz_api_err_set(err, "node_stopped", NULL, "{\"reason\":\"rebuilding\"}");
        return 503;
    }
    n = c->request_id ? strlen(c->request_id) : 0;
    if (!n || n > GZ_CMD_MAX_REQUEST_ID) {
        gz_api_err_set(err, "missing_field", "/request_id", NULL);
        return 400;
    }
    for (i = 0; i < GZP_API_HELD; i++)
        if (!a->held[i].used) { slot = i; break; }
    if (slot < 0) {
        gz_api_err_set(err, "rate_limited", NULL, "{\"retry_after_s\":1}");
        return 429;
    }
    if (!(buf = malloc(cap))) abort();
    gz_put_u16(c2, code);
    rc = gz_rec_put(buf, cap, &at, GZ_CMD_REC_REQUEST_ID, (const uint8_t *)c->request_id, n) == GZ_OK &&
         (!c->method || gz_rec_put(buf, cap, &at, GZ_CMD_REC_METHOD, (const uint8_t *)c->method, strlen(c->method)) == GZ_OK) &&
         (!c->path || gz_rec_put(buf, cap, &at, GZ_CMD_REC_PATH, (const uint8_t *)c->path, strlen(c->path)) == GZ_OK) &&
         (!c->digest || gz_rec_put(buf, cap, &at, GZ_CMD_REC_DIGEST, c->digest, 32) == GZ_OK) &&
         gz_rec_put(buf, cap, &at, GZ_CMD_REC_COMMAND, c2, 2) == GZ_OK;
    if (rc && args_len) {
        memcpy(buf + at, args, args_len);
        at += args_len;
    }
    a->held[slot].used = 1;
    memcpy(a->held[slot].request_id, c->request_id, n + 1);
    a->held[slot].handle = c->handle;
    a->held[slot].call = c->id;
    if (!rc || a->command(a->command_ctx, buf, at) != 0) {
        a->held[slot].used = 0;
        free(buf);
        gz_api_err_set(err, "node_stopped", NULL, "{\"reason\":\"rebuilding\"}");
        return 503;
    }
    free(buf);
    return GZ_API_HELD;
}

/* A held call's 2xx answer: the object it acted on, as the view holds it now. */
static void finish_held(gzp_api_t *a, int i)
{
    gz_jw w;
    char *body;
    a->held[i].used = 0;
    a->held[i].waiting = 0;
    gz_jw_init(&w);
    gzp_api_answer(a, a->held[i].call, a->held[i].object[0] ? a->held[i].object : NULL, a->held[i].params, &w);
    body = malloc(w.len + 1);
    if (!body) abort();
    if (w.len) memcpy(body, w.buf, w.len);
    body[w.len] = 0;
    gz_api_call_done(a->srv, a->held[i].handle, a->held[i].status, w.err ? "{}" : body, NULL);
    free(body);
    gz_jw_free(&w);
}

static int in_view(gzp_api_t *a, const char *id)
{
    return gzp_api_find(a, GZ_VIEW_LOBBY, id) || gzp_api_find(a, GZ_VIEW_HOST_LOBBY, id) ||
           gzp_api_find(a, GZ_VIEW_DISCOVERY, id);
}

static void command_result(gzp_api_t *a, const uint8_t *bytes, size_t len)
{
    gz_bytes_t all = {bytes, len}, f;
    static char code[64];   /* the error code, kept until the next result (the answer may be written later) */
    char rid[GZ_CMD_MAX_REQUEST_ID + 1];
    int i, st;
    gz_api_error e;
    if (gz_rec_find(all, GZ_RESULT_REC_REQUEST_ID, &f) != 1 || f.len < 1 || f.len > GZ_CMD_MAX_REQUEST_ID) return;
    memcpy(rid, f.data, f.len);
    rid[f.len] = 0;
    if (gz_rec_find(all, GZ_RESULT_REC_STATUS, &f) != 1 || f.len != 2) return;
    st = gz_get_u16(f.data);
    for (i = 0; i < GZP_API_HELD; i++) {
        if (!a->held[i].used || strcmp(a->held[i].request_id, rid) != 0) continue;
        a->held[i].used = 0;
        {
            /* The object acted on (result field 6) and the core's params
             * (field 8): the answer is the object as the view now holds it
             * (7.4: also for a replay). */
            char object[GZ_LOCAL_ID_MAX + 1], params[700];
            object[0] = params[0] = 0;
            if (gz_rec_find(all, GZ_RESULT_REC_OBJECT, &f) == 1 && f.len <= GZ_LOCAL_ID_MAX) {
                memcpy(object, f.data, f.len);
                object[f.len] = 0;
            }
            if (gz_rec_find(all, GZ_RESULT_REC_PARAMS, &f) == 1 && f.len < sizeof params) {
                memcpy(params, f.data, f.len);
                params[f.len] = 0;
            }
            if (st >= 200 && st < 300) {
                a->held[i].used = 1;
                a->held[i].status = st;
                memcpy(a->held[i].object, object, sizeof object);
                snprintf(a->held[i].params, sizeof a->held[i].params, "%s", params);
                if (object[0] && !in_view(a, object)) {   /* its view comes next, in the same batch */
                    a->held[i].waiting = 1;
                    a->held[i].waiting_since = gzp_mono_ms();
                } else {
                    finish_held(a, i);
                }
            } else {
                memset(&e, 0, sizeof e);
                code[0] = 0;
                if (gz_rec_find(all, GZ_RESULT_REC_ERROR, &f) == 1 && f.len < sizeof code) {
                    memcpy(code, f.data, f.len);
                    code[f.len] = 0;
                }
                /* The core's missing_field is a new request that wanted the
                 * passphrase and came without it (field 28, api_calls.c). */
                gz_api_err_set(&e, code[0] ? code : "internal", strcmp(code, "missing_field") ? NULL : "/passphrase", "%s",
                               params[0] == '{' ? params : "{}");
                e.code = code[0] ? code : "internal";
                gz_api_call_done(a->srv, a->held[i].handle, st, NULL, &e);
            }
        }
        return;
    }
}

void gzp_api_notify(void *ctx, uint32_t code, const uint8_t *bytes, size_t len)
{
    gzp_api_t *a = ctx;
    char id[GZP_VIEW_ID_MAX + 1];
    if ((code >> 16) == 1) {
        uint32_t kind = code & 0xffffu;
        a->views_received[kind < 7 ? kind : 7]++;
        if (gzp_view_apply(&a->view, kind, bytes, len, id) && a->srv && a->node_running) {
            gz_api_notify(a->srv, gzp_view_topic(kind), kind == GZ_VIEW_STATUS ? NULL : id);
            for (int i = 0; i < GZP_API_HELD; i++)
                if (a->held[i].used && a->held[i].waiting && !strcmp(a->held[i].object, id)) finish_held(a, i);
        }
    } else if (code == GZ_NOTIFY_COMMAND_RESULT) {
        if (a->srv) command_result(a, bytes, len);
    }
    /* Log notices and the lobby's own notes are shown by the test build's
     * output lines only (executor.c); the release program prints none (N1). */
}

void gzp_api_node_starting(gzp_api_t *a)
{
    int i;
    a->node_running = 0;
    gzp_view_clear(&a->view);
    for (i = 0; i < GZP_API_HELD; i++) a->held[i].used = 0;
    if (a->srv) gz_api_server_node_stopped(a->srv, "rebuilding");
}

int gzp_api_lock_pending(const gzp_api_t *a)
{
    return a->lock_pending;
}

int gzp_api_unlocked(gzp_api_t *a)
{
    if (a->unlock.state(a->unlock.ctx) != GZP_WALLET_UNLOCKED) return 0;
    a->lock_pending = 0;
    return 1;
}

void gzp_api_node_started(gzp_api_t *a)
{
    a->node_running = 1;
    if (a->srv) gz_api_notify(a->srv, "reset", NULL);
}

/* ---- the server ------------------------------------------------------------------ */

static void server_log(void *ctx, const char *line)
{
    (void)ctx;
    gzp_log("api %s", line);
}

static void first_run_file(void *ctx, const char *path)
{
    (void)ctx;
    gzp_log("first-run open file://%s", path);   /* the path only: the token is inside the owner-only file (4.3) */
}

int gzp_api_open(gzp_api_t *a, const gzp_options_t *opt, gzp_datadir_t *dir, const char *network, gzp_chain_t *chain)
{
    gz_api_config cfg;
    const char *why = NULL;
    memset(a, 0, sizeof *a);
    a->opt = opt;
    a->chain = chain;
    a->network = network;
    gzp_unlock_impl(&a->unlock, dir);
    a->setup_done = a->unlock.state(a->unlock.ctx) != GZP_WALLET_NONE;
    if (opt->no_interface) {
        gzp_log("interface off");
        return 0;
    }
    memset(&cfg, 0, sizeof cfg);
    cfg.data_dir = dir->dir;
    cfg.port = opt->interface_port ? opt->interface_port : strcmp(network, "testnet4") == 0 ? 39736 : 39735;
    gzp_backend.network = network;
    cfg.backend = &gzp_backend;
    cfg.backend_ctx = a;
    cfg.log = server_log;
    cfg.on_first_run_file = first_run_file;
    a->srv = gz_api_server_new(&cfg, &why);
    if (!a->srv) {
        /* The port is taken, or loopback refused: the interface is off, the
         * program goes on, and never picks another port (3.1). */
        gzp_log("interface refused port=%u why=%s", (unsigned)cfg.port, why ? why : "-");
        return 0;
    }
    gzp_log("interface listening http://127.0.0.1:%u/", (unsigned)gz_api_server_port(a->srv));
    return 0;
}

void gzp_api_close(gzp_api_t *a)
{
#ifdef GZP_TEST_BUILD
    /* Every view the core sent this process, by kind: tests read it to know
     * when the core emits lobby views (tests/web/check_p6a_fixme.py). */
    {
        unsigned long long n[3] = {0, 0, 0};
        uint32_t k;
        for (k = 0; k < 8; k++) {
            n[gzp_view_lobby_class(k)] += a->views_received[k];
            if (gzp_view_lobby_class(k)) n[0] += a->views_received[k];
        }
        gzp_log("views received lobby=%llu host_lobby=%llu all=%llu", n[1], n[2], n[0]);
    }
#endif
    if (a->srv) {
        gz_api_server_stop_listening(a->srv);
        gz_api_server_free(a->srv);
        a->srv = NULL;
    }
    gzp_view_clear(&a->view);
}

size_t gzp_api_max_fds(const gzp_api_t *a)
{
    return a->srv ? gz_api_server_max_fds(a->srv) : 0;
}

size_t gzp_api_pollfds(gzp_api_t *a, struct pollfd *fds, size_t cap, int *timeout_ms)
{
    size_t n;
    uint64_t now = gzp_mono_ms();
    *timeout_ms = -1;
    if (!a->srv) return 0;
    n = gz_api_server_pollfds(a->srv, fds, cap, timeout_ms);
    /* The loop wakes when a waiting answer's 2 s are up (gzp_api_dispatch). */
    for (int i = 0; i < GZP_API_HELD; i++)
        if (a->held[i].used && a->held[i].waiting) {
            uint64_t due = a->held[i].waiting_since + 2000;
            int t = due > now ? (int)(due - now) : 0;
            if (*timeout_ms < 0 || t < *timeout_ms) *timeout_ms = t;
        }
    return n;
}

void gzp_api_dispatch(gzp_api_t *a, const struct pollfd *fds, size_t n)
{
    /* A held answer whose object has not reached the view in 2 s: never a
     * 2xx without it (that silent answer sent the page to a lobby named
     * "undefined"), but 503 view_pending with the request id. The action was
     * taken; a retry with that id is answered from the replay table, with the
     * object as the view then holds it (local-api.md 7.4). */
    for (int i = 0; a->srv && i < GZP_API_HELD; i++)
        if (a->held[i].used && a->held[i].waiting && gzp_mono_ms() - a->held[i].waiting_since >= 2000) {
            gz_api_error e;
            memset(&e, 0, sizeof e);
            gz_api_err_set(&e, "view_pending", NULL, "{\"request_id\":\"%s\"}", a->held[i].request_id);
            e.code = "view_pending";
            a->held[i].used = 0;
            a->held[i].waiting = 0;
            gz_api_call_done(a->srv, a->held[i].handle, 503, NULL, &e);
        }
    if (a->srv && gz_api_server_dispatch(a->srv, fds, n) != 0) {
        gzp_log("interface failed: closed");
        gz_api_server_free(a->srv);
        a->srv = NULL;
    }
}
