/* SPDX-License-Identifier: MIT */
/* The binding tables of spec/local-api.md 11.2, 11.4 and 4.7: doing.code
 * priority (every pair), the chain-view table, the watching.state
 * precedence, attention tiers and order, the locked headline table, and the
 * locked status shape with its hidden dates (review R6). */
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "internal.h"

static gz_api_status_facts g_facts;

static int st(void *be, gz_api_status_facts *f)
{
    (void)be;
    *f = g_facts;
    return 0;
}

static int ws(void *be) { (void)be; return GZ_API_WALLET_UNLOCKED; }
static void pp(void *be, gz_api_pp_job *j) { (void)be; (void)j; }
static int call(void *be, const gz_api_call *c, gz_jw *w, gz_api_error *e, int *eff)
{
    (void)be; (void)c; (void)w; (void)e; (void)eff;
    return 500;
}

static const gz_api_backend BE = {"t", "signet", ws, pp, NULL, st, call, NULL, NULL};

static const char *const DOING[] = {
    "node_stopped", "files_behind", "wallet_locked", "no_wallet", "restoring", "answering_old_state",
    "signing", "moving", "signing_unfinished", "move_unfinished", "leaving_alone", "left_behind",
    "chain_in_doubt", "awaiting_funding", "paused", "ready_check", "in_lobby_not_ready",
    "in_lobby_not_counted", "in_lobby_waiting", "looking_tell", "looking_join", "looking_nothing_fits",
    "budget_used", "creation_dead", "creation_abandoned", "refused", "refused_by_host", "lobby_cancelled",
    "not_chosen", "idle_in_factory", "idle_no_factory"};
#define ND ((int)(sizeof DOING / sizeof DOING[0]))

static gz_api_server *mk(void)
{
    gz_api_server *s = calloc(1, sizeof *s);
    s->be = &BE;
    s->peer_check_ok = 1;
    return s;
}

static int write_status(gz_api_server *s, int locked, int dates_ok, gz_json_doc *doc)
{
    gz_jw w;
    int r;
    gz_jw_init(&w);
    r = gz_status_write(s, &w, locked, dates_ok);
    if (r == 0) r = gz_json_parse((const uint8_t *)w.buf, w.len, doc);
    gz_jw_free(&w);
    return r;
}

static const char *path_str(const gz_json *root, const char *a, const char *b)
{
    const gz_json *v = gz_json_get(root, a);
    if (b) v = gz_json_get(v, b);
    return v && v->type == GZ_JSON_STR ? v->s : NULL;
}

static void base(void)
{
    memset(&g_facts, 0, sizeof g_facts);
    g_facts.network = "signet";
    g_facts.test_coins = 1;
    g_facts.wallet = GZ_API_STW_READY;
    g_facts.chain_state = GZ_API_CHAIN_AGREE;
    g_facts.has_something_to_watch = 1;
    g_facts.pause_state = "off";
}

static void test_doing_pairs(void)
{
    gz_api_server *s = mk();
    int i, j;
    /* the unlocked shape never carries wallet_locked or files_behind (those are the locked shape's) */
    for (i = 0; i < ND; i++) {
        for (j = 0; j < ND; j++) {
            gz_json_doc d;
            int ri = gz_doing_rank(DOING[i]), rj = gz_doing_rank(DOING[j]);
            const char *want = ri <= rj ? DOING[i] : DOING[j], *got;
            if (!strcmp(DOING[i], "wallet_locked") || !strcmp(DOING[j], "wallet_locked") ||
                !strcmp(DOING[i], "files_behind") || !strcmp(DOING[j], "files_behind"))
                continue;
            base();
            g_facts.doing[0].code = DOING[j];
            g_facts.doing[1].code = DOING[i];
            g_facts.ndoing = 2;
            if (write_status(s, 0, 1, &d) != 0) { CHECK(0); continue; }
            got = path_str(d.root, "doing", "code");
            if (ri == rj) CHECK(got && (strcmp(got, DOING[i]) == 0 || strcmp(got, DOING[j]) == 0));
            else CHECK(got && strcmp(got, want) == 0);
            gz_json_free(&d);
        }
    }
    /* the order is the table's */
    for (i = 1; i < ND; i++) CHECK(gz_doing_rank(DOING[i - 1]) <= gz_doing_rank(DOING[i]));
    CHECK(gz_doing_rank("looking_tell") == gz_doing_rank("looking_join"));
    CHECK(gz_doing_rank("signing_unfinished") < gz_doing_rank("paused"));   /* a pause never hides it (F7) */
    CHECK(gz_doing_rank("chain_in_doubt") < gz_doing_rank("paused"));
    CHECK(gz_doing_rank("nonsense") < 0);
    /* a value outside the table is a backend bug: 500, never a guess */
    {
        gz_jw w;
        base();
        g_facts.doing[0].code = "nonsense";
        g_facts.ndoing = 1;
        gz_jw_init(&w);
        CHECK(gz_status_write(s, &w, 0, 1) != 0);
        gz_jw_free(&w);
    }
    /* paused with an unfinished round: signing_unfinished (23.1 item 14) */
    {
        gz_json_doc d;
        base();
        g_facts.pause_state = "on";
        g_facts.doing[0].code = "signing_unfinished";
        g_facts.ndoing = 1;
        CHECK(write_status(s, 0, 1, &d) == 0);
        CHECK(strcmp(path_str(d.root, "doing", "code"), "signing_unfinished") == 0);
        CHECK(strcmp(path_str(d.root, "pause", "state"), "on") == 0);
        gz_json_free(&d);
        base();
        g_facts.pause_state = "on";
        CHECK(write_status(s, 0, 1, &d) == 0);
        CHECK(strcmp(path_str(d.root, "doing", "code"), "paused") == 0);
        gz_json_free(&d);
        base();
        CHECK(write_status(s, 0, 1, &d) == 0);
        CHECK(strcmp(path_str(d.root, "doing", "code"), "idle_no_factory") == 0);
        gz_json_free(&d);
    }
    free(s);
}

static void test_chain_table(void)
{
    static const struct {
        int state;
        const char *view, *watching, *doing;
    } T[] = {
        {GZ_API_CHAIN_AGREE, "trusted", "this_app", "awaiting_funding"},
        {GZ_API_CHAIN_LAGGING, "trusted", "this_app", "awaiting_funding"},
        {GZ_API_CHAIN_CATCHING_UP, "in_doubt", "nobody_chain_in_doubt", "chain_in_doubt"},
        {GZ_API_CHAIN_ONE_SOURCE, "in_doubt", "nobody_chain_in_doubt", "chain_in_doubt"},
        {GZ_API_CHAIN_DISAGREE, "in_doubt", "nobody_chain_in_doubt", "chain_in_doubt"},
        {GZ_API_CHAIN_UNREACHABLE, "in_doubt", "nobody_chain_in_doubt", "chain_in_doubt"},
        {GZ_API_CHAIN_OFFLINE_BY_CHOICE, "in_doubt", "nobody_offline", "chain_in_doubt"},
    };
    gz_api_server *s = mk();
    size_t i;
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        gz_json_doc d;
        base();
        g_facts.chain_state = T[i].state;
        g_facts.doing[0].code = "awaiting_funding";
        g_facts.ndoing = 1;
        CHECK(write_status(s, 0, 1, &d) == 0);
        CHECK(strcmp(path_str(d.root, "money", "chain_view"), T[i].view) == 0);
        CHECK(strcmp(path_str(d.root, "watching", "state"), T[i].watching) == 0);
        CHECK(strcmp(path_str(d.root, "doing", "code"), T[i].doing) == 0);
        CHECK(strcmp(gz_json_get(gz_json_get(d.root, "connection"), "chain")->child->s, gz_chain_state_name(T[i].state)) == 0);
        CHECK(gz_json_get(gz_json_get(d.root, "connection"), "offline_by_choice")->i ==
              (T[i].state == GZ_API_CHAIN_OFFLINE_BY_CHOICE));
        CHECK(strcmp(path_str(d.root, "watching", "health"),
                     strncmp(T[i].watching, "nobody", 6) == 0 ? "not_applicable" : "up_to_date") == 0);
        gz_json_free(&d);
    }
    /* nothing to watch wins over the chain table; the money view still follows it (11.2) */
    {
        gz_json_doc d;
        base();
        g_facts.chain_state = GZ_API_CHAIN_DISAGREE;
        g_facts.has_something_to_watch = 0;
        CHECK(write_status(s, 0, 1, &d) == 0);
        CHECK(strcmp(path_str(d.root, "watching", "state"), "nothing_to_watch") == 0);
        CHECK(strcmp(path_str(d.root, "money", "chain_view"), "in_doubt") == 0);
        gz_json_free(&d);
        base();
        g_facts.wallet = GZ_API_STW_RESTORING;
        CHECK(write_status(s, 0, 1, &d) == 0);
        CHECK(strcmp(path_str(d.root, "watching", "state"), "nobody_restoring") == 0);
        CHECK(strcmp(path_str(d.root, "doing", "code"), "restoring") == 0);
        gz_json_free(&d);
    }
    free(s);
}

static void test_attention(void)
{
    gz_api_server *s = mk();
    gz_json_doc d;
    const gz_json *a;
    base();
    g_facts.attention[0].id = "att_1";
    g_facts.attention[0].code = "terms_changed";
    g_facts.attention[1].id = "att_2";
    g_facts.attention[1].code = "words_not_checked";
    g_facts.attention[2].id = "att_3";
    g_facts.attention[2].code = "chain_one_source";
    g_facts.attention[3].id = "att_4";
    g_facts.attention[3].code = "refused_to_sign";
    g_facts.nattention = 4;
    CHECK(write_status(s, 0, 1, &d) == 0);
    a = gz_json_get(d.root, "attention");
    CHECK(a && a->len == 4);
    if (a && a->len == 4) {                              /* most important first */
        CHECK(strcmp(path_str(a->child, "code", NULL), "chain_one_source") == 0);
        CHECK(strcmp(path_str(a->child, "tier", NULL), "at_risk") == 0);
        CHECK(strcmp(path_str(a->child->next, "code", NULL), "words_not_checked") == 0);
        CHECK(strcmp(path_str(a->child->next->next, "tier", NULL), "heads_up") == 0);
        CHECK(strcmp(path_str(a->child->next->next->next, "tier", NULL), "record") == 0);
    }
    gz_json_free(&d);
    /* act_now always has a date: without one the answer is refused, not softened */
    {
        gz_jw w;
        base();
        g_facts.attention[0].id = "att_9";
        g_facts.attention[0].code = "move_last_try";
        g_facts.nattention = 1;
        gz_jw_init(&w);
        CHECK(gz_status_write(s, &w, 0, 1) != 0);
        gz_jw_free(&w);
        g_facts.attention[0].due_json = "{\"kind\":\"move_try\"}";
        CHECK(write_status(s, 0, 1, &d) == 0);
        gz_json_free(&d);
        base();
        g_facts.attention[0].id = "att_9";
        g_facts.attention[0].code = "unknown_code";
        g_facts.nattention = 1;
        gz_jw_init(&w);
        CHECK(gz_status_write(s, &w, 0, 1) != 0);
        gz_jw_free(&w);
    }
    CHECK(strcmp(gz_attention_tier("exit_needs_fee_coin", 0), "important") == 0);
    CHECK(strcmp(gz_attention_tier("exit_needs_fee_coin", 1), "at_risk") == 0);
    CHECK(strcmp(gz_attention_tier("terms_changed", 1), "heads_up") == 0);
    free(s);
}

static void test_headlines(void)
{
    static const struct {
        unsigned flags;
        int watcher;
        const char *reason;
        int wallet;
        const char *code, *tier;
    } T[] = {
        {GZ_API_LF_HOST_CLOSED_ALL | GZ_API_LF_PAST_UNLOCK_BY, 1, NULL, GZ_API_STW_LOCKED, "host_closed", "important"},
        {GZ_API_LF_HOST_CLOSED_ALL | GZ_API_LF_HOST_CLOSED_PAYMENT, 1, NULL, GZ_API_STW_LOCKED, "host_closed", "at_risk"},
        {GZ_API_LF_DEADLINE_PASSED | GZ_API_LF_PAST_UNLOCK_BY, 1, NULL, GZ_API_STW_LOCKED, "deadline_passed_while_locked", "at_risk"},
        {GZ_API_LF_PAST_UNLOCK_BY | GZ_API_LF_TREE_STEP_LATE, 1, NULL, GZ_API_STW_LOCKED, "past_unlock_by", "at_risk"},
        {GZ_API_LF_TREE_STEP_LATE | GZ_API_LF_PUBLISHING, 1, NULL, GZ_API_STW_LOCKED, "tree_step_late", "at_risk"},
        {GZ_API_LF_SECOND_STAGE | GZ_API_LF_PAYMENT_SECRET, 1, NULL, GZ_API_STW_LOCKED, "second_stage_after_breach", "at_risk"},
        {GZ_API_LF_PAYMENT_SECRET | GZ_API_LF_WAITING_FOR_UNLOCK, 1, NULL, GZ_API_STW_LOCKED, "payment_secret_released", "at_risk"},
        {GZ_API_LF_WAITING_FOR_UNLOCK | GZ_API_LF_PUBLISHING, 1, NULL, GZ_API_STW_LOCKED, "waiting_for_unlock", "at_risk"},
        {GZ_API_LF_PUBLISHING, 1, "penalty_file_short", GZ_API_STW_LOCKED, "publishing_tree_steps", "at_risk"},
        {GZ_API_LF_OLD_STATE_ANSWERED, 1, "penalty_file_short", GZ_API_STW_LOCKED, "penalty_file_short", "at_risk"},
        {GZ_API_LF_OLD_STATE_ANSWERED, 1, NULL, GZ_API_STW_LOCKED, "old_state_answered", "at_risk"},
        {GZ_API_LF_SOMETHING_TO_TAKE_OUT, 0, "no_bundle", GZ_API_STW_FILES_BEHIND, "files_behind", "at_risk"},
        {GZ_API_LF_SOMETHING_TO_TAKE_OUT, 0, "watcher_off", GZ_API_STW_LOCKED, "nobody_watching_at_risk", "at_risk"},
        {GZ_API_LF_CANNOT_TELL, 0, "no_key_store", GZ_API_STW_LOCKED, "nobody_watching_locked", "important"},
        {GZ_API_LF_SOMETHING_TO_TAKE_OUT | GZ_API_LF_BEFORE_LEAVE_BY, 1, NULL, GZ_API_STW_LOCKED, "unlock_before", "important"},
        {0, 0, "no_bundle", GZ_API_STW_LOCKED, "nothing_needs_you", NULL},   /* every Slice 1 wallet */
        {0, 1, NULL, GZ_API_STW_LOCKED, "nothing_needs_you", NULL},
    };
    size_t i;
    for (i = 0; i < sizeof T / sizeof T[0]; i++) {
        const char *tier, *code;
        base();
        g_facts.wallet = T[i].wallet;
        g_facts.locked_flags = T[i].flags;
        g_facts.watcher_runs = T[i].watcher;
        g_facts.watching_reason = T[i].reason;
        code = gz_headline(&g_facts, &tier);
        CHECK(strcmp(code, T[i].code) == 0);
        CHECK((tier == NULL) == (T[i].tier == NULL));
        if (tier && T[i].tier) CHECK(strcmp(tier, T[i].tier) == 0);
        if (strcmp(code, T[i].code) != 0) printf("  headline row %zu: got %s\n", i, code);
    }
}

static void test_locked_shape(void)
{
    gz_api_server *s = mk();
    gz_json_doc d;
    const gz_json *w;
    /* Slice 1 after a restart (23.2 item 41): nobody_locked, no_bundle, nothing_needs_you */
    base();
    g_facts.wallet = GZ_API_STW_LOCKED;
    g_facts.lock_since = "start";
    g_facts.locked_since_at = 1794434000;
    g_facts.chain_height = 330437;
    CHECK(write_status(s, 1, 1, &d) == 0);
    CHECK(strcmp(path_str(d.root, "wallet", NULL), "locked") == 0);
    w = gz_json_get(d.root, "watching");
    CHECK(strcmp(path_str(w, "state", NULL), "nobody_locked") == 0);
    CHECK(strcmp(path_str(w, "reason", NULL), "no_bundle") == 0);
    CHECK(strcmp(path_str(gz_json_get(w, "headline"), "code", NULL), "nothing_needs_you") == 0);
    CHECK(gz_json_get(gz_json_get(w, "headline"), "tier")->type == GZ_JSON_NULL);
    CHECK(gz_json_get(w, "dates_hidden")->i == 0);
    CHECK(gz_json_get(w, "factories_watched") != NULL);
    CHECK(strcmp(path_str(d.root, "doing", "code"), "wallet_locked") == 0);
    CHECK(strcmp(path_str(gz_json_get(d.root, "doing"), "params", "watcher"), "off") == 0);
    CHECK(gz_json_get(d.root, "money") == NULL && gz_json_get(d.root, "attention") == NULL);
    CHECK(gz_json_get(d.root, "pause") == NULL);
    gz_json_free(&d);
    /* the peer check unavailable and no session: dates hidden (review R6) */
    s->peer_check_ok = 0;
    CHECK(write_status(s, 1, 0, &d) == 0);
    w = gz_json_get(d.root, "watching");
    CHECK(gz_json_get(w, "dates_hidden")->i == 1);
    CHECK(gz_json_get(w, "factories_watched") == NULL && gz_json_get(w, "unlock_by") == NULL &&
          gz_json_get(w, "leave_by_locked") == NULL && gz_json_get(w, "next_action") == NULL &&
          gz_json_get(w, "last_check_height") == NULL);
    CHECK(strcmp(path_str(d.root, "interface", "peer_check"), "unavailable") == 0);
    CHECK(gz_json_get(gz_json_get(d.root, "connection"), "chain") != NULL);   /* the tip is public */
    gz_json_free(&d);
    s->peer_check_ok = 1;
    /* files behind (4.7, review R3) */
    base();
    g_facts.wallet = GZ_API_STW_FILES_BEHIND;
    g_facts.wallet_reason = "possibly_old";
    CHECK(write_status(s, 1, 1, &d) == 0);
    CHECK(strcmp(path_str(d.root, "wallet", NULL), "files_behind") == 0);
    CHECK(strcmp(path_str(d.root, "files_behind", "cause"), "possibly_old") == 0);
    CHECK(strcmp(path_str(d.root, "doing", "code"), "files_behind") == 0);
    CHECK(strcmp(path_str(gz_json_get(d.root, "watching"), "headline", "code"), "files_behind") == 0);
    gz_json_free(&d);
    /* a locked watcher with the chain in doubt keeps watcher_locked, reason chain_in_doubt (D6) */
    base();
    g_facts.wallet = GZ_API_STW_LOCKED;
    g_facts.watcher_runs = 1;
    g_facts.chain_state = GZ_API_CHAIN_DISAGREE;
    CHECK(write_status(s, 1, 1, &d) == 0);
    CHECK(strcmp(path_str(d.root, "watching", "state"), "watcher_locked") == 0);
    CHECK(strcmp(path_str(d.root, "watching", "reason"), "chain_in_doubt") == 0);
    gz_json_free(&d);
    free(s);
}

int main(void)
{
    test_doing_pairs();
    test_chain_table();
    test_attention();
    test_headlines();
    test_locked_shape();
    return check_done();
}
