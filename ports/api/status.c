/* SPDX-License-Identifier: MIT */
/* GET /api/v1/status (spec/local-api.md 11, 4.7): the backend gives facts;
 * the binding tables are here, once: the doing.code priority (11.2), the
 * chain-view table, the watching.state precedence, the attention tiers (11.4)
 * and the locked headline table (4.7). Exactly one value of each holds. */
#include <stdio.h>
#include <string.h>

#include "internal.h"

/* 11.2 doing.code, in priority order (first wins). looking_tell and
 * looking_join share a priority. */
static const char *const DOING[] = {
    "node_stopped", "files_behind", "wallet_locked", "no_wallet", "restoring", "answering_old_state",
    "signing", "moving", "signing_unfinished", "move_unfinished", "leaving_alone", "left_behind",
    "chain_in_doubt", "awaiting_funding", "paused", "ready_check", "in_lobby_not_ready",
    "in_lobby_not_counted", "in_lobby_waiting", "looking_tell", "looking_join", "looking_nothing_fits",
    "budget_used", "creation_dead", "creation_abandoned", "refused", "refused_by_host", "lobby_cancelled",
    "not_chosen", "idle_in_factory", "idle_no_factory",
};

int gz_doing_rank(const char *code)
{
    int i;
    for (i = 0; i < (int)(sizeof DOING / sizeof DOING[0]); i++) {
        if (strcmp(DOING[i], code) == 0) {
            if (strcmp(code, "looking_join") == 0) return i - 1;   /* same as looking_tell */
            if (i > 20) return i - 1;
            return i;
        }
    }
    return -1;
}

static const char *const CHAIN[GZ_API_CHAIN_STATES] = {
    "agree", "lagging", "catching_up", "one_source", "disagree", "unreachable", "offline_by_choice"};

const char *gz_chain_state_name(int s)
{
    return s >= 0 && s < GZ_API_CHAIN_STATES ? CHAIN[s] : NULL;
}

/* The chain-view table (11.2): trusted only for agree and lagging. */
const char *gz_chain_view(int s)
{
    return s == GZ_API_CHAIN_AGREE || s == GZ_API_CHAIN_LAGGING ? "trusted" : "in_doubt";
}

static int chain_doubt(int s) { return strcmp(gz_chain_view(s), "in_doubt") == 0; }

/* watching.state precedence (11.2), first match wins. */
const char *gz_watching_state(const gz_api_status_facts *f, int locked)
{
    if (locked && !f->watcher_runs) return "nobody_locked";
    if (f->wallet == GZ_API_STW_RESTORING) return "nobody_restoring";
    if (!f->has_something_to_watch) return "nothing_to_watch";
    if (f->chain_state == GZ_API_CHAIN_OFFLINE_BY_CHOICE) return "nobody_offline";
    if (locked) return "watcher_locked";
    if (chain_doubt(f->chain_state)) return "nobody_chain_in_doubt";
    return "this_app";
}

/* 11.4: the tier of each attention code. */
static const char *const ATTENTION[][2] = {
    {"chain_disagree", "at_risk"}, {"chain_one_source", "at_risk"}, {"chain_unreachable", "at_risk"},
    {"chain_catching_up", "important"}, {"signing_unfinished", "at_risk"}, {"node_stopped", "at_risk"},
    {"nobody_watching", "at_risk"}, {"watching_behind", "at_risk"}, {"funding_reorganised", "at_risk"},
    {"old_state_published", "at_risk"}, {"branch_partly_on_chain", "important"}, {"move_last_try", "act_now"},
    {"leave_step_due", "act_now"}, {"open_app_by", "act_now"}, {"host_not_answering", "important"},
    {"payments_paused_by_host", "important"}, {"factory_backup_missing", "important"},
    {"factory_backup_old", "important"}, {"words_not_checked", "important"},
    {"restored_factories_unknown", "important"}, {"storage_nearly_full", "important"},
    {"restored_seats_lost", "important"}, {"terms_changed", "heads_up"}, {"date_near", "heads_up"},
    {"refused_to_sign", "record"}, {"use_own_chain_server", "recommended"}, {"choose_watching", "recommended"},
    {"host_can_start", "important"}, {"host_funds_short", "important"}, {"host_members_not_moved", "important"},
    {"host_listing_renew", "important"}, {"host_node_missing", "important"}, {"exit_needs_fee_coin", "important"},
    {"payments_stopped_for_exit", "important"}, {"exit_step_late", "at_risk"},
    {"exit_step_held_back", "at_risk"}, {"exit_fee_budget_reached", "act_now"}, {"exit_missed", "at_risk"},
    {"funding_double_spent", "at_risk"}, {"restored_commitment_choice", "at_risk"},
    {"unexplained_spend", "at_risk"},
};

const char *gz_attention_tier(const char *code, int at_risk_override)
{
    size_t i;
    for (i = 0; i < sizeof ATTENTION / sizeof ATTENTION[0]; i++) {
        if (strcmp(ATTENTION[i][0], code) == 0) {
            if (at_risk_override && strcmp(code, "exit_needs_fee_coin") == 0) return "at_risk";
            return ATTENTION[i][1];
        }
    }
    return NULL;
}

int gz_tier_rank(const char *tier)
{
    static const char *const T[] = {"at_risk", "act_now", "important", "recommended", "heads_up", "record"};
    int i;
    for (i = 0; i < 6; i++)
        if (strcmp(T[i], tier) == 0) return i;
    return 6;
}

/* The locked headline table (4.7), first match wins; *tier NULL for "—". */
const char *gz_headline(const gz_api_status_facts *f, const char **tier)
{
    unsigned x = f->locked_flags;
    const char *ws = gz_watching_state(f, 1);
    int nobody = strcmp(ws, "nobody_locked") == 0;
    *tier = "at_risk";
    if (x & GZ_API_LF_HOST_CLOSED_ALL) {
        *tier = (x & GZ_API_LF_HOST_CLOSED_PAYMENT) ? "at_risk" : "important";
        return "host_closed";
    }
    if (x & GZ_API_LF_DEADLINE_PASSED) return "deadline_passed_while_locked";
    if (x & GZ_API_LF_PAST_UNLOCK_BY) return "past_unlock_by";
    if (x & GZ_API_LF_TREE_STEP_LATE) return "tree_step_late";
    if (x & GZ_API_LF_SECOND_STAGE) return "second_stage_after_breach";
    if (x & GZ_API_LF_PAYMENT_SECRET) return "payment_secret_released";
    if (x & GZ_API_LF_WAITING_FOR_UNLOCK) return "waiting_for_unlock";
    if (x & GZ_API_LF_PUBLISHING) return "publishing_tree_steps";
    if (f->watching_reason && strcmp(f->watching_reason, "penalty_file_short") == 0 && !nobody)
        return "penalty_file_short";
    if (x & GZ_API_LF_OLD_STATE_ANSWERED) return "old_state_answered";
    if (f->wallet == GZ_API_STW_FILES_BEHIND) return "files_behind";
    if (nobody && (x & GZ_API_LF_SOMETHING_TO_TAKE_OUT)) return "nobody_watching_at_risk";
    *tier = "important";
    if (nobody && (x & GZ_API_LF_CANNOT_TELL)) return "nobody_watching_locked";
    if ((x & GZ_API_LF_SOMETHING_TO_TAKE_OUT) && (x & GZ_API_LF_BEFORE_LEAVE_BY)) return "unlock_before";
    *tier = NULL;
    return "nothing_needs_you";
}

static const char *wallet_name(int w)
{
    switch (w) {
    case GZ_API_STW_NONE: return "none";
    case GZ_API_STW_CREATED_NOT_FINISHED: return "created_not_finished";
    case GZ_API_STW_READY: return "ready";
    case GZ_API_STW_LOCKED: return "locked";
    case GZ_API_STW_FILES_BEHIND: return "files_behind";
    case GZ_API_STW_RESTORING: return "restoring";
    case GZ_API_STW_NODE_STOPPED: return "node_stopped";
    default: return NULL;
    }
}

static void w_date_or_null(gz_jw *w, const char *k, int64_t height, int64_t at)
{
    gz_jw_key(w, k);
    if (!height) { gz_jw_null(w); return; }
    gz_jw_obj(w);
    gz_jw_kint(w, "height", height);
    gz_jw_kint(w, "at_estimate", at);
    gz_jw_end_obj(w);
}

static int write_locked(gz_api_server *srv, const gz_api_status_facts *f, gz_jw *w, int dates_ok)
{
    const char *tier, *headline = gz_headline(f, &tier);
    const char *ws = gz_watching_state(f, 1);
    const char *reason = f->watching_reason;
    const char *doing = "wallet_locked";
    int hide = !dates_ok;
    if (strcmp(ws, "watcher_locked") == 0 && !reason && chain_doubt(f->chain_state)) reason = "chain_in_doubt";
    if (strcmp(ws, "nobody_locked") == 0 && !reason) reason = "no_bundle";
    if (strcmp(ws, "nothing_to_watch") == 0) reason = NULL;
    if (f->wallet == GZ_API_STW_FILES_BEHIND) doing = "files_behind";
    if (f->wallet == GZ_API_STW_NODE_STOPPED) doing = "node_stopped";
    gz_jw_obj(w);
    gz_jw_kstr(w, "wallet", f->wallet == GZ_API_STW_FILES_BEHIND ? "files_behind"
                             : f->wallet == GZ_API_STW_NODE_STOPPED ? "node_stopped" : "locked");
    gz_jw_key(w, "network");
    gz_jw_obj(w);
    gz_jw_kstr(w, "id", f->network);
    gz_jw_kbool(w, "test_coins", f->test_coins);
    gz_jw_end_obj(w);
    gz_jw_key(w, "lock");
    gz_jw_obj(w);
    gz_jw_kstr(w, "since", f->lock_since ? f->lock_since : "start");
    gz_jw_kint(w, "since_at", f->locked_since_at);
    gz_jw_end_obj(w);
    if (f->wallet == GZ_API_STW_FILES_BEHIND) {
        gz_jw_key(w, "files_behind");
        gz_jw_obj(w);
        gz_jw_kstr(w, "cause", f->wallet_reason ? f->wallet_reason : "behind");
        gz_jw_end_obj(w);
    }
    gz_jw_key(w, "watching");
    gz_jw_obj(w);
    gz_jw_kstr(w, "state", ws);
    gz_jw_kstr(w, "reason", reason);
    gz_jw_key(w, "headline");
    gz_jw_obj(w);
    gz_jw_kstr(w, "code", headline);
    gz_jw_kstr(w, "tier", tier);
    gz_jw_end_obj(w);
    gz_jw_kbool(w, "dates_hidden", hide);
    if (!hide) {
        gz_jw_kint(w, "factories_watched", f->factories_watched);
        w_date_or_null(w, "leave_by_locked", f->leave_by_locked_height, f->leave_by_locked_at);
        w_date_or_null(w, "unlock_by", f->unlock_by_height, f->unlock_by_at);
        gz_jw_key(w, "next_action");
        if (!f->next_action_height) {
            gz_jw_null(w);
        } else {
            gz_jw_obj(w);
            gz_jw_kint(w, "height", f->next_action_height);
            gz_jw_kint(w, "at_estimate", f->next_action_at);
            gz_jw_kstr(w, "what", f->next_action_what);
            gz_jw_end_obj(w);
        }
        gz_jw_kstr(w, "health", strncmp(ws, "nobody", 6) == 0 || strcmp(ws, "nothing_to_watch") == 0
                                     ? "not_applicable" : (f->watching_behind ? "behind" : "up_to_date"));
        if (f->last_check_height) gz_jw_kint(w, "last_check_height", f->last_check_height);
        else gz_jw_knull(w, "last_check_height");
    }
    gz_jw_end_obj(w);
    gz_jw_key(w, "doing");
    gz_jw_obj(w);
    gz_jw_kstr(w, "code", doing);
    gz_jw_key(w, "params");
    gz_jw_obj(w);
    if (strcmp(doing, "files_behind") == 0) gz_jw_kstr(w, "cause", f->wallet_reason ? f->wallet_reason : "behind");
    else if (strcmp(doing, "node_stopped") == 0) gz_jw_kstr(w, "reason", f->wallet_reason ? f->wallet_reason : "storage_failed");
    else gz_jw_kstr(w, "watcher", f->watcher_runs ? (f->watcher_doing ? f->watcher_doing : "watching") : "off");
    gz_jw_end_obj(w);
    gz_jw_end_obj(w);
    gz_jw_key(w, "connection");
    gz_jw_obj(w);
    gz_jw_key(w, "chain");
    gz_jw_obj(w);
    gz_jw_kstr(w, "state", gz_chain_state_name(f->chain_state));
    gz_jw_kint(w, "height", f->chain_height);
    gz_jw_end_obj(w);
    gz_jw_end_obj(w);
    gz_jw_key(w, "interface");
    gz_jw_obj(w);
    gz_jw_kstr(w, "peer_check", srv->peer_check_ok ? "same_user_only" : "unavailable");
    gz_jw_end_obj(w);
    gz_jw_end_obj(w);
    return 0;
}

static int write_unlocked(gz_api_server *srv, gz_api_status_facts *f, gz_jw *w)
{
    const gz_api_doing *best = NULL;
    gz_api_doing extra[4];
    int nextra = 0, best_rank = 1000, i, t;
    const char *ws = gz_watching_state(f, 0);
    if (!wallet_name(f->wallet) || !gz_chain_state_name(f->chain_state)) return -1;
    /* values the server adds from the facts themselves */
    memset(extra, 0, sizeof extra);
    if (f->wallet == GZ_API_STW_NONE) extra[nextra++].code = "no_wallet";
    if (f->wallet == GZ_API_STW_RESTORING) extra[nextra++].code = "restoring";
    if (chain_doubt(f->chain_state) && f->wallet != GZ_API_STW_NONE) extra[nextra++].code = "chain_in_doubt";
    if (f->pause_state && strcmp(f->pause_state, "on") == 0) extra[nextra++].code = "paused";
    for (i = 0; i < f->ndoing + nextra; i++) {
        const gz_api_doing *d = i < f->ndoing ? &f->doing[i] : &extra[i - f->ndoing];
        int r = gz_doing_rank(d->code);
        if (r < 0) return -1;                           /* a value outside the table is a backend bug */
        if (strcmp(d->code, "wallet_locked") == 0 || strcmp(d->code, "files_behind") == 0) return -1;
        if (r < best_rank) { best_rank = r; best = d; }
    }
    for (i = 0; i < f->nattention; i++) {
        const char *tier = gz_attention_tier(f->attention[i].code, f->attention[i].at_risk_override);
        if (!tier) return -1;
        if (strcmp(tier, "act_now") == 0 && !f->attention[i].due_json) return -1;   /* act_now has a date */
    }
    gz_jw_obj(w);
    gz_jw_kint(w, "version", f->version);
    gz_jw_key(w, "network");
    gz_jw_obj(w);
    gz_jw_kstr(w, "id", f->network);
    gz_jw_kbool(w, "test_coins", f->test_coins);
    gz_jw_end_obj(w);
    gz_jw_kstr(w, "wallet", wallet_name(f->wallet));
    gz_jw_key(w, "pause");
    gz_jw_obj(w);
    gz_jw_kstr(w, "state", f->pause_state ? f->pause_state : "off");
    if (f->pause_since_at) gz_jw_kint(w, "since_at", f->pause_since_at);
    else gz_jw_knull(w, "since_at");
    gz_jw_kstr(w, "lobby_id", f->pause_lobby_id);
    gz_jw_end_obj(w);
    gz_jw_key(w, "lock");
    if (!f->lock_state) {
        gz_jw_null(w);
    } else {
        gz_jw_obj(w);
        gz_jw_kstr(w, "state", f->lock_state);
        if (strcmp(f->lock_state, "held_for_signing") == 0) gz_jw_kstr(w, "lobby_id", f->lock_lobby_id);
        gz_jw_kint(w, "since_at", f->lock_since_at);
        gz_jw_end_obj(w);
    }
    gz_jw_key(w, "interface");
    gz_jw_obj(w);
    gz_jw_kstr(w, "peer_check", srv->peer_check_ok ? "same_user_only" : "unavailable");
    gz_jw_kbool(w, "memory_locked", f->memory_locked);
    gz_jw_end_obj(w);
    gz_jw_key(w, "doing");
    gz_jw_obj(w);
    gz_jw_kstr(w, "code", best ? best->code : "idle_no_factory");
    gz_jw_kstr(w, "lobby_id", best ? best->lobby_id : NULL);
    gz_jw_kraw(w, "params", best && best->params_json ? best->params_json : "{}");
    if (best && best->since_at) gz_jw_kint(w, "since_at", best->since_at);
    else gz_jw_knull(w, "since_at");
    gz_jw_end_obj(w);
    gz_jw_key(w, "connection");
    gz_jw_obj(w);
    gz_jw_key(w, "chain");
    gz_jw_obj(w);
    gz_jw_kstr(w, "state", gz_chain_state_name(f->chain_state));
    gz_jw_kint(w, "height", f->chain_height);
    gz_jw_kint(w, "servers_agreeing", f->servers_agreeing);
    gz_jw_kint(w, "operators", f->operators);
    if (f->chain_since_at) gz_jw_kint(w, "since_at", f->chain_since_at);
    else gz_jw_knull(w, "since_at");
    if (f->chain_state == GZ_API_CHAIN_LAGGING) {
        gz_jw_key(w, "params");
        gz_jw_obj(w);
        gz_jw_kint(w, "blocks", f->lag_blocks);
        gz_jw_end_obj(w);
    }
    gz_jw_end_obj(w);
    gz_jw_kraw(w, "host_links", f->host_links_json ? f->host_links_json : "[]");
    gz_jw_kbool(w, "offline_by_choice", f->chain_state == GZ_API_CHAIN_OFFLINE_BY_CHOICE);
    gz_jw_end_obj(w);
    gz_jw_key(w, "watching");
    gz_jw_obj(w);
    gz_jw_kstr(w, "state", ws);
    gz_jw_kstr(w, "health", strncmp(ws, "nobody", 6) == 0 || strcmp(ws, "nothing_to_watch") == 0
                                 ? "not_applicable" : (f->watching_behind ? "behind" : "up_to_date"));
    if (f->watching_behind && strcmp(ws, "this_app") == 0) {
        gz_jw_key(w, "params");
        gz_jw_obj(w);
        gz_jw_kint(w, "minutes", f->behind_minutes);
        gz_jw_end_obj(w);
    }
    if (f->last_check_height) gz_jw_kint(w, "last_check_height", f->last_check_height);
    else gz_jw_knull(w, "last_check_height");
    if (f->last_check_at) gz_jw_kint(w, "last_check_at", f->last_check_at);
    else gz_jw_knull(w, "last_check_at");
    gz_jw_kint(w, "safe_absence_blocks", f->safe_absence_blocks);
    gz_jw_kraw(w, "open_by", f->open_by_json);
    gz_jw_kraw(w, "unlock_by", f->unlock_by_json);
    gz_jw_kint(w, "factories_watched", f->factories_watched);
    gz_jw_end_obj(w);
    gz_jw_kraw(w, "next_date", f->next_date_json);
    gz_jw_key(w, "auto_join");
    gz_jw_obj(w);
    gz_jw_kstr(w, "state", "off");
    gz_jw_end_obj(w);
    gz_jw_kraw(w, "hosting", f->hosting_json);
    gz_jw_key(w, "money");
    gz_jw_obj(w);
    gz_jw_kint(w, "can_send_sat", f->can_send_sat);
    gz_jw_kint(w, "can_receive_sat", f->can_receive_sat);
    gz_jw_kraw(w, "take_out_alone", f->take_out_alone_json);
    gz_jw_kint(w, "on_chain_free_sat", f->on_chain_free_sat);
    gz_jw_kint(w, "set_aside_sat", f->set_aside_sat);
    gz_jw_kint(w, "inside_factories_sat", f->inside_factories_sat);
    gz_jw_kint(w, "forming_sat", f->forming_sat);
    gz_jw_kint(w, "hosted_factories_sat", f->hosted_factories_sat);
    gz_jw_knull(w, "covered_sat");
    gz_jw_kint(w, "as_of_height", f->as_of_height);
    gz_jw_kstr(w, "chain_view", gz_chain_view(f->chain_state));
    gz_jw_end_obj(w);
    gz_jw_key(w, "attention");
    gz_jw_arr(w);
    for (t = 0; t < 6; t++) {                           /* most important first; stable within a tier */
        for (i = 0; i < f->nattention; i++) {
            const gz_api_attention *a = &f->attention[i];
            const char *tier = gz_attention_tier(a->code, a->at_risk_override);
            if (gz_tier_rank(tier) != t) continue;
            gz_jw_obj(w);
            gz_jw_kstr(w, "id", a->id);
            gz_jw_kstr(w, "tier", tier);
            gz_jw_kstr(w, "code", a->code);
            gz_jw_kraw(w, "due", a->due_json);
            if (a->lobby_id) gz_jw_kstr(w, "lobby_id", a->lobby_id);
            if (a->factory_id) gz_jw_kstr(w, "factory_id", a->factory_id);
            gz_jw_kraw(w, "params", a->params_json ? a->params_json : "{}");
            gz_jw_end_obj(w);
        }
    }
    gz_jw_end_arr(w);
    gz_jw_knull(w, "while_closed");
    gz_jw_end_obj(w);
    return 0;
}

/* locked_shape: the wallet is locked or its files are behind (4.7). dates_ok:
 * the caller passed the same-user check, is on the local socket, or holds a
 * session (4.7, review R6). */
int gz_status_write(gz_api_server *srv, gz_jw *w, int locked_shape, int dates_ok)
{
    gz_api_status_facts f;
    memset(&f, 0, sizeof f);
    f.network = srv->be->network;
    f.test_coins = 1;
    f.memory_locked = 1;
    if (srv->be->status(srv->bectx, &f) != 0) return -1;
    if (f.ndoing < 0 || f.ndoing > GZ_API_MAX_DOING || f.nattention < 0 || f.nattention > GZ_API_MAX_ATTENTION)
        return -1;
    if (locked_shape) {
        if (f.wallet != GZ_API_STW_LOCKED && f.wallet != GZ_API_STW_FILES_BEHIND && f.wallet != GZ_API_STW_NODE_STOPPED)
            f.wallet = GZ_API_STW_LOCKED;
        return write_locked(srv, &f, w, dates_ok);
    }
    return write_unlocked(srv, &f, w);
}
