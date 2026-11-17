/* SPDX-License-Identifier: MIT */
/* TEST ONLY: the fake backend. See fake_backend.h. Every answer has the shape
 * spec/local-api.md draft 4 gives; the numbers are invented but consistent
 * (the funding a draft needs, the digest of its terms, the fit of a lobby
 * against the conditions), so the interface can be wired against it. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "fake_backend.h"

#define LOBBY_ID "lob_7k2q"
#define LOBBY2_ID "lob_b19d"
#define HOST_LOBBY_ID "lob_4c08"
#define FACTORY_ID "fac_2d91"
#define SEAT_ID "a19c3b5e7d2f4c11"
#define HOST_KEY "02c7e1b2a4d6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192"
#define TIP 330437
#define HOST_FACTORY_ID "fac_h001"

/* the story's stages (member: m_stage; host: h_stage) and the member's outcome */
enum { MS_OPEN = 0, MS_READY_CHECK, MS_SIGNING, MS_FUNDING, MS_ACTIVE, MS_CANCELLED };
enum { MO_NONE = 0, MO_REFUSED, MO_UNFINISHED, MO_CANCELLED, MO_STARTED };

static int64_t free_sat(const gz_fake *f)
{
    return 42000000 - f->set_aside_sat - f->h_funded_sat;
}

/* anything to watch (11.2): the fixed picture's factory, or the story's */
static int watching(const gz_fake *f)
{
    if (!f->story) return f->has_factory;
    return f->m_stage == MS_FUNDING || f->m_stage == MS_ACTIVE || f->m_outcome == MO_UNFINISHED ||
           f->h_stage == MS_FUNDING || f->h_stage == MS_ACTIVE;
}

static const char *const TEST_WORDS[24] = {
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "art"};

static int64_t now_s(gz_fake *f)
{
    return f->now_override ? f->now_override : (int64_t)time(NULL);
}

void gz_fake_init(gz_fake *f, int scenario)
{
    int i;
    memset(f, 0, sizeof *f);
    pthread_mutex_init(&f->mu, NULL);
    f->wallet = GZ_API_WALLET_NONE;
    f->chain_state = GZ_API_CHAIN_AGREE;
    f->cond_version = 7;
    f->cond_max_joining_fee_sat = 2000;
    f->cond_min_members = 20;
    f->cond_min_confirmations = 3;
    f->cond_max_fee_ppm = 1000;
    snprintf(f->cond_preset, sizeof f->cond_preset, "everyday");
    f->has_factory = 1;
    if (scenario == GZ_FAKE_LOCKED) {
        f->wallet = GZ_API_WALLET_LOCKED;
        f->setup_ready = 1;
        f->pass_len = strlen(GZ_FAKE_PASSPHRASE);
        memcpy(f->pass, GZ_FAKE_PASSPHRASE, f->pass_len);
        for (i = 0; i < 24; i++) snprintf(f->words[i], sizeof f->words[i], "%s", TEST_WORDS[i]);
    }
}

static void engine_free(gz_fake *f);

void gz_fake_free(gz_fake *f)
{
    engine_free(f);
    pthread_mutex_destroy(&f->mu);
    OPENSSL_cleanse(f, sizeof *f);
}

static int pass_ok(gz_fake *f, const gz_api_pp_job *j)
{
    /* TEST ONLY: no key derivation, a constant-time comparison */
    return f->pass_len && j->passphrase_len == f->pass_len && CRYPTO_memcmp(j->passphrase, f->pass, f->pass_len) == 0;
}

/* storage 4.1's refusals, approximately (no NFC here: test-only) */
static const char *weak(const gz_api_pp_job *j, int64_t *len)
{
    size_t i, cps = 0;
    char low[1100];
    for (i = 0; i < j->passphrase_len; i++)
        if ((j->passphrase[i] & 0xc0) != 0x80) cps++;
    *len = (int64_t)cps;
    if (j->passphrase_len > 1024) return "too_long";
    if (cps < 15) return "too_short";
    for (i = 0; i < j->passphrase_len && i < sizeof low - 1; i++)
        low[i] = (char)(j->passphrase[i] >= 'A' && j->passphrase[i] <= 'Z' ? j->passphrase[i] + 32 : j->passphrase[i]);
    low[i] = 0;
    if (strcmp(low, "passwordpassword") == 0 || strcmp(low, "123456789012345") == 0) return "too_common";
    if (strncmp(low, "gazpacho", 8) == 0 && strspn(low + 8, "0123456789") == strlen(low + 8)) return "names_the_wallet";
    if (strstr(low, "abandon abandon abandon")) return "uses_the_words";
    return NULL;
}

/* Derivation thread: only derives (contract-v2 section 4). It reads what it
 * compares against and writes nothing but the job: every change of state is
 * made by pp_done on the loop thread, which the server skips for a job of an
 * older generation. */
static void pp_op(void *be, gz_api_pp_job *j)
{
    gz_fake *f = be;
    int i, delay;
    pthread_mutex_lock(&f->mu);
    delay = f->pp_delay_ms;                          /* a test switch, set from other threads */
    f->inside++;
    if (f->inside > f->max_inside) f->max_inside = f->inside;
    f->derivations++;
    pthread_mutex_unlock(&f->mu);
    if (delay) {
        struct timespec ts = {delay / 1000, (long)(delay % 1000) * 1000000L};
        nanosleep(&ts, NULL);
    }
    pthread_mutex_lock(&f->mu);
    j->result = GZ_API_PPR_OK;
    if (f->derivation_fails_next) {
        f->derivation_fails_next = 0;                    /* a test switch, not wallet state */
        j->result = GZ_API_PPR_NOT_CHECKED;
        goto out;
    }
    switch (j->op) {
    case GZ_API_PP_UNLOCK:
    case GZ_API_PP_CHECK:
        if (f->wallet == GZ_API_WALLET_NONE) { j->result = GZ_API_PPR_NO_WALLET; break; }
        if (!pass_ok(f, j)) { j->result = GZ_API_PPR_WRONG; break; }
        if (j->op == GZ_API_PP_UNLOCK && (f->files_behind_next || f->wallet == GZ_API_WALLET_FILES_BEHIND)) {
            j->result = GZ_API_PPR_FILES_BEHIND;
            j->reason = "behind";
        }
        break;
    case GZ_API_PP_CREATE:
    case GZ_API_PP_RESTORE: {
        int64_t len;
        const char *w;
        if (f->wallet != GZ_API_WALLET_NONE) { j->result = GZ_API_PPR_EXISTS; break; }
        w = weak(j, &len);
        if (w) {
            j->result = GZ_API_PPR_WEAK;
            j->reason = w;
            j->a = len;
            j->b = 15;
            break;
        }
        if (j->op == GZ_API_PP_RESTORE) {
            int bad = 0;
            for (i = 0; i < 24 && !bad; i++) {
                size_t k, n = strlen(j->words[i]);
                if (n < 3 || n > 8) bad = i + 1;
                for (k = 0; k < n && !bad; k++)
                    if (j->words[i][k] < 'a' || j->words[i][k] > 'z') bad = i + 1;
            }
            if (bad) { j->result = GZ_API_PPR_BAD_WORDS; j->reason = "position"; j->a = bad; break; }
            for (i = 0; i < 24; i++)
                if (strcmp(j->words[i], TEST_WORDS[i]) != 0) { j->result = GZ_API_PPR_BAD_WORDS; j->reason = "checksum"; }
            if (j->result != GZ_API_PPR_OK) break;
        }
        if (j->op == GZ_API_PP_CREATE)                   /* the new words, out (the "derived" product) */
            for (i = 0; i < 24; i++) snprintf(j->words[i], sizeof j->words[i], "%s", TEST_WORDS[i]);
        j->nwords = j->op == GZ_API_PP_CREATE ? 24 : 0;
        break;
    }
    case GZ_API_PP_REVEAL:
        if (!pass_ok(f, j)) { j->result = GZ_API_PPR_WRONG; break; }
        for (i = 0; i < 24; i++) snprintf(j->words[i], sizeof j->words[i], "%s", f->words[i]);
        j->nwords = 24;
        break;
    case GZ_API_PP_WORDS_CHECK:
        if (!pass_ok(f, j)) { j->result = GZ_API_PPR_WRONG; break; }
        for (i = 0; i < 3; i++) {
            int p = j->positions[i];
            if (p < 1 || p > 24 || strcmp(j->words[i], f->words[p - 1]) != 0) j->result = GZ_API_PPR_WORDS_DIFFER;
        }
        break;
    case GZ_API_PP_START_AS_RESTORE:
        if (f->wallet != GZ_API_WALLET_FILES_BEHIND) { j->result = GZ_API_PPR_NOT_FILES_BEHIND; break; }
        if (!pass_ok(f, j)) { j->result = GZ_API_PPR_WRONG; break; }
        break;
    default:
        j->result = GZ_API_PPR_NOT_CHECKED;
    }
    if (j->result == GZ_API_PPR_OK && f->fault_next &&
        (j->op == GZ_API_PP_CREATE || j->op == GZ_API_PP_RESTORE || j->op == GZ_API_PP_START_AS_RESTORE)) {
        j->result = GZ_API_PPR_DONE_WITH_FAULT;          /* storage GZ_SC_DONE_WITH_FAULT: in force */
        j->reason = "mark_file";
    }
out:
    f->inside--;
    pthread_mutex_unlock(&f->mu);
}

/* Loop thread: install what pp_op produced (the program writes its files and
 * starts the node here). */
static void pp_install(gz_fake *f, gz_api_pp_job *j);
static void pp_done(void *be, gz_api_pp_job *j)
{
    gz_fake *f = be;
    pthread_mutex_lock(&f->mu);
    f->installs++;
    if (j->result == GZ_API_PPR_DONE_WITH_FAULT) f->fault_next = 0;
    {
        int ok_like = j->result == GZ_API_PPR_DONE_WITH_FAULT;
        if (ok_like) j->result = GZ_API_PPR_OK;          /* installed as done ... */
        pp_install(f, j);
        if (ok_like) j->result = GZ_API_PPR_DONE_WITH_FAULT;   /* ... and reported with its warning */
    }
    pthread_mutex_unlock(&f->mu);
}

static void pp_install(gz_fake *f, gz_api_pp_job *j)
{
    int i;
    switch (j->op) {
    case GZ_API_PP_UNLOCK:
        if (j->result == GZ_API_PPR_FILES_BEHIND) {
            f->files_behind_next = 0;
            f->wallet = GZ_API_WALLET_FILES_BEHIND;
        } else if (j->result == GZ_API_PPR_OK) {
            f->wallet = GZ_API_WALLET_UNLOCKED;
        }
        break;
    case GZ_API_PP_CREATE:
    case GZ_API_PP_RESTORE:
        if (j->result != GZ_API_PPR_OK) break;
        if (j->passphrase_len > sizeof f->pass) break;
        memcpy(f->pass, j->passphrase, j->passphrase_len);
        f->pass_len = j->passphrase_len;
        for (i = 0; i < 24; i++) snprintf(f->words[i], sizeof f->words[i], "%s", TEST_WORDS[i]);
        if (j->op == GZ_API_PP_RESTORE) f->restoring = 1;
        f->wallet = GZ_API_WALLET_UNLOCKED;
        break;
    case GZ_API_PP_WORDS_CHECK:
        if (j->result == GZ_API_PPR_OK || j->result == GZ_API_PPR_WORDS_DIFFER) {
            int64_t t = now_s(f);
            int oldest = 0;
            /* the attempt is saved with the answer (12.3, 7.5) */
            for (i = 1; i < 3; i++)
                if (f->check_times[i] < f->check_times[oldest]) oldest = i;
            f->check_times[oldest] = t;
            if (j->result == GZ_API_PPR_OK) f->words_checked_at = t;
        }
        break;
    case GZ_API_PP_START_AS_RESTORE:
        if (j->result == GZ_API_PPR_OK) {
            f->wallet = GZ_API_WALLET_UNLOCKED;
            f->restoring = 1;
        }
        break;
    default:
        break;
    }
}

static int wallet_state(void *be)
{
    gz_fake *f = be;
    int w;
    pthread_mutex_lock(&f->mu);
    w = f->wallet;
    pthread_mutex_unlock(&f->mu);
    return w;
}

static int words_checks_left(void *be, int64_t now, int64_t *retry)
{
    gz_fake *f = be;
    int i, left = 3;
    int64_t oldest = 0;
    pthread_mutex_lock(&f->mu);
    for (i = 0; i < 3; i++)
        if (f->check_times[i] && now - f->check_times[i] < 86400) {
            left--;
            if (!oldest || f->check_times[i] < oldest) oldest = f->check_times[i];
        }
    pthread_mutex_unlock(&f->mu);
    *retry = left > 0 ? 0 : oldest + 86400 - now;
    return left;
}

/* ---- shapes ------------------------------------------------------------------------ */
static void date(gz_jw *w, const char *kind, int64_t height, const char *at_zero, const char *source,
                 const char *prov)
{
    int64_t left = height - TIP;
    gz_jw_obj(w);
    gz_jw_kstr(w, "kind", kind);
    gz_jw_kint(w, "due_height", height);
    gz_jw_kint(w, "blocks_left", left);
    gz_jw_kint(w, "due_at_estimate", 1794434400 + left * 600);
    gz_jw_key(w, "at_zero");
    gz_jw_obj(w);
    gz_jw_kstr(w, "code", at_zero);
    gz_jw_key(w, "needs");
    gz_jw_arr(w);
    gz_jw_end_arr(w);
    gz_jw_end_obj(w);
    gz_jw_kstr(w, "source", source);
    gz_jw_key(w, "provenance");
    gz_jw_obj(w);
    gz_jw_kstr(w, "code", prov);
    gz_jw_key(w, "inputs");
    gz_jw_obj(w);
    gz_jw_end_obj(w);
    gz_jw_end_obj(w);
    gz_jw_kstr(w, "state", left < 0 ? "passed" : left < 144 ? "soon" : "ok");
    gz_jw_end_obj(w);
}

static void hex_of(const char *seed, char out[65])
{
    unsigned char h[32];
    SHA256((const unsigned char *)seed, strlen(seed), h);
    {
        static const char x[] = "0123456789abcdef";
        int i;
        for (i = 0; i < 32; i++) { out[2 * i] = x[h[i] >> 4]; out[2 * i + 1] = x[h[i] & 15]; }
        out[64] = 0;
    }
}

static void range(gz_jw *w, const char *k, int64_t lo, int64_t hi)
{
    gz_jw_key(w, k);
    gz_jw_obj(w);
    gz_jw_kint(w, "min", lo);
    gz_jw_kint(w, "max", hi);
    gz_jw_end_obj(w);
}

/* 13.3, the host's terms */
static void terms(gz_jw *w, const char *seed, int64_t fee_lo, int64_t fee_now, int64_t fee_hi, int sealed,
                  int64_t target, int64_t minimum, int64_t chan)
{
    char fp[65], dg[65], shortfp[16];
    hex_of(seed, fp);
    snprintf(dg, sizeof dg, "%s", fp);
    dg[0] = 'd';
    snprintf(shortfp, sizeof shortfp, "%.4s\xe2\x80\xa6%.4s", fp, fp + 60);
    gz_jw_obj(w);
    if (sealed) gz_jw_kstr(w, "fingerprint", fp);
    else gz_jw_knull(w, "fingerprint");
    if (sealed) gz_jw_kstr(w, "fingerprint_short", shortfp);
    else gz_jw_knull(w, "fingerprint_short");
    gz_jw_key(w, "host");
    gz_jw_obj(w);
    gz_jw_kstr(w, "key", HOST_KEY);
    /* text by another party, with format characters the writer removes (5.6) */
    gz_jw_text(w, "alias", "Tomato\xe2\x80\xae Garden\xe2\x80\x8b", "host", 64);
    gz_jw_end_obj(w);
    gz_jw_kbool(w, "signatures_checked", sealed);
    gz_jw_key(w, "outer");
    gz_jw_obj(w);
    gz_jw_kstr(w, "chain", "signet");
    gz_jw_kstr(w, "profile", "standard");
    gz_jw_kint(w, "target", target);
    gz_jw_kint(w, "minimum", minimum);
    gz_jw_kint(w, "deadline_at", 1794441600);
    gz_jw_kstr(w, "on_shortfall", "cancel");
    gz_jw_kint(w, "ready_window_ms", 60000);
    gz_jw_kint(w, "signing_budget_ms", 600000);
    gz_jw_kint(w, "step_timeout_ms", 60000);
    gz_jw_kint(w, "lifetime_blocks", 4752);
    gz_jw_kint(w, "winddown_blocks", 432);
    gz_jw_kint(w, "channel_sat", chan);
    gz_jw_kint(w, "tree_feerate_sat_per_kvb", 100);
    gz_jw_kraw(w, "switches", "{\"names\":false,\"chat\":false,\"rule_requests\":false}");
    gz_jw_kraw(w, "shape", "[{\"max_members\":4,\"interior\":[],\"leaf\":\"one_member\"},"
                           "{\"max_members\":16,\"interior\":[4],\"leaf\":\"one_member\"}]");
    gz_jw_text(w, "description", "Weekdays only.\nSigned terms; <b>no</b> markup is ever rendered.", "host", 1000);
    gz_jw_end_obj(w);
    gz_jw_key(w, "ranges");
    gz_jw_obj(w);
    range(w, "joining_fee_sat", fee_lo, fee_hi);
    range(w, "fee_base_msat", 1000, 1000);
    range(w, "fee_ppm", 300, 800);
    gz_jw_end_obj(w);
    gz_jw_key(w, "current");
    gz_jw_obj(w);
    gz_jw_kint(w, "version", 3);
    gz_jw_kstr(w, "digest", dg);
    gz_jw_key(w, "values");
    gz_jw_obj(w);
    gz_jw_kint(w, "joining_fee_sat", fee_now);
    gz_jw_kint(w, "fee_base_msat", 1000);
    gz_jw_kint(w, "fee_ppm", 500);
    gz_jw_end_obj(w);
    gz_jw_end_obj(w);
    gz_jw_knull(w, "frozen");
    gz_jw_key(w, "derived");
    gz_jw_obj(w);
    gz_jw_kint(w, "exit_blocks", 864);
    gz_jw_kint(w, "depth", 2);
    gz_jw_kint(w, "funding_at_minimum_sat", minimum * chan * 3 / 2);
    gz_jw_kint(w, "funding_at_target_sat", target * chan * 3 / 2);
    gz_jw_end_obj(w);
    gz_jw_kraw(w, "reserved", "{\"receiving_room_fee_ppm\":null,\"joining_fee_chain_share\":null,"
                              "\"newcomer_seats_pct\":null,\"invitation_only\":null}");
    gz_jw_end_obj(w);
}

static const char *digest_of(const char *seed, char out[65])
{
    hex_of(seed, out);
    out[0] = 'd';
    return out;
}

/* 13.4 against the fake's conditions */
static int fits(gz_fake *f, int64_t fee_hi)
{
    return fee_hi <= f->cond_max_joining_fee_sat;
}

static void fit(gz_jw *w, gz_fake *f, int64_t fee_lo, int64_t fee_now, int64_t fee_hi)
{
    int ok = fits(f, fee_hi);
    gz_jw_obj(w);
    gz_jw_kstr(w, "class", ok ? "fits" : "does_not_fit");
    gz_jw_kstr(w, "compared_with", "whole_range");
    gz_jw_kint(w, "conditions_version", f->cond_version);
    gz_jw_key(w, "rows");
    gz_jw_arr(w);
    gz_jw_obj(w);
    gz_jw_kstr(w, "term", "profile");
    gz_jw_kstr(w, "offered", "standard");
    gz_jw_kraw(w, "yours", "[\"safety\",\"standard\"]");
    gz_jw_kstr(w, "result", "fits");
    gz_jw_end_obj(w);
    gz_jw_obj(w);
    gz_jw_kstr(w, "term", "members");
    gz_jw_kraw(w, "offered", "{\"minimum\":30,\"target\":50}");
    gz_jw_kint(w, "yours", f->cond_min_members);
    gz_jw_kstr(w, "result", f->cond_min_members <= 30 ? "fits" : "fails");
    gz_jw_end_obj(w);
    gz_jw_obj(w);
    gz_jw_kstr(w, "term", "joining_fee_sat");
    gz_jw_key(w, "offered");
    gz_jw_obj(w);
    gz_jw_kint(w, "min", fee_lo);
    gz_jw_kint(w, "max", fee_hi);
    gz_jw_kint(w, "now", fee_now);
    gz_jw_end_obj(w);
    gz_jw_kint(w, "yours", f->cond_max_joining_fee_sat);
    gz_jw_kstr(w, "result", ok ? "fits" : "fails");
    gz_jw_end_obj(w);
    gz_jw_end_arr(w);
    gz_jw_kint(w, "counted_from", f->cond_min_members > 30 ? f->cond_min_members : 30);
    gz_jw_end_obj(w);
}

static const char *seat_name(gz_fake *f, const char *id)
{
    if (strcmp(id, LOBBY_ID) != 0) {
        if (!f->story || strcmp(id, LOBBY2_ID) != 0) return "none";
        if (f->joining_answer == 2) return "joining";
        if (f->left2) return "left";
        if (!f->joined2) return "none";
        return f->ready2 ? "ready" : "joined_not_ready";
    }
    if (f->joining_answer == 1) return "joining";
    if (f->left) return "left";
    if (!f->joined) return "none";
    if (f->story && f->m_stage >= MS_SIGNING && f->m_stage <= MS_ACTIVE) return "chosen";
    return f->ready ? "ready" : "joined_not_ready";
}

/* ---- the interface's story (TEST ONLY; gz-api-fake --story) ----------------------------------
 * The same shapes as the fixed picture, with the lobbies' stages, the member's
 * round and outcome, the funding and the factories taken from the story's
 * state, which gz_fake_cmd moves on. */
static const char *const M_STAGE[] = {"open", "ready_check", "signing", "funding", "active", "cancelled"};
#define FUNDING_TXID "9f1c2a7e5d3b4c6a8e0f1d2c3b4a59687766554433221100ffeeddccbbaa9988"

static const char *funding_state(int conf)
{
    return conf == 0 ? "broadcast" : conf < 3 ? "confirming" : "buried";
}

/* The failures of the story's refusal: a number; a list and a range (profiles,
 * payment_sizes_sat, 13.1); or none (a safety check). */
#define LIST_FAILURES "[{\"condition\":\"profiles\",\"yours\":[\"safety\",\"standard\"],\"offered\":\"starter\"}," \
                      "{\"condition\":\"payment_sizes_sat\",\"yours\":{\"min\":100,\"max\":200000},\"offered\":{\"min\":1000,\"max\":500000}}]"
static void refusal_failures(const gz_fake *f, char *buf, size_t n)
{
    if (f->m_refuse_kind == 1) snprintf(buf, n, "%s", LIST_FAILURES);
    else if (f->m_refuse_kind == 2) snprintf(buf, n, "[]");
    else snprintf(buf, n, "[{\"condition\":\"min_members\",\"yours\":%lld,\"offered\":18}]", (long long)f->cond_min_members);
}

/* 14.1 round: the member's creation round, with the program's own checks */
static void story_round(gz_jw *w, gz_fake *f)
{
    static const char *const RS[] = {"", "checking", "nonces_sent", "signed", "awaiting_funding", "unfinished",
                                     "aborted", "live"};
    int refused = f->m_outcome == MO_REFUSED;
    int sent = f->m_round >= 3 && f->m_round != 6;
    gz_jw_obj(w);
    gz_jw_kstr(w, "state", RS[f->m_round]);
    gz_jw_kint(w, "attempt", 1);
    gz_jw_key(w, "signatures");
    gz_jw_obj(w);
    gz_jw_kint(w, "done", !sent ? 0 : f->m_round == 3 || f->m_round == 5 ? 11 : 17);
    gz_jw_kint(w, "of", 17);
    gz_jw_end_obj(w);
    if (sent) gz_jw_kint(w, "sent_at", 1794434404);
    else gz_jw_knull(w, "sent_at");
    if (sent) gz_jw_kint(w, "last_heard_at", 1794434404);
    else gz_jw_knull(w, "last_heard_at");
    gz_jw_kint(w, "checked_to_height", TIP);
    if (f->m_round == 5) {
        gz_jw_key(w, "unfinished_deadline");
        date(w, "unfinished_deadline", TIP + 36, "round_abandoned", "worked_out", "signing_budget_from_sent");
    } else {
        gz_jw_knull(w, "unfinished_deadline");
    }
    gz_jw_key(w, "checks");
    gz_jw_arr(w);
    gz_jw_raw(w, "{\"check\":\"fingerprint_same\",\"ok\":true}");
    gz_jw_raw(w, "{\"check\":\"frozen_values_inside_limits\",\"ok\":true}");
    gz_jw_raw(w, refused && f->m_refuse_kind != 2 ? "{\"check\":\"tree_inside_conditions\",\"ok\":false,\"params\":{\"members\":18}}"
                                                   : "{\"check\":\"tree_inside_conditions\",\"ok\":true,\"params\":{\"members\":30}}");
    gz_jw_raw(w, refused && f->m_refuse_kind == 2 ? "{\"check\":\"safety_checks\",\"ok\":false}" : "{\"check\":\"safety_checks\",\"ok\":true}");
    gz_jw_end_arr(w);
    gz_jw_end_obj(w);
}

static void story_funding(gz_jw *w, int conf, int64_t amount)
{
    gz_jw_obj(w);
    gz_jw_kstr(w, "txid", FUNDING_TXID);
    gz_jw_kstr(w, "state", funding_state(conf));
    gz_jw_kint(w, "confirmations", conf);
    gz_jw_kint(w, "needed", 3);
    gz_jw_key(w, "deadline");
    date(w, "funding_deadline", TIP + 36, "round_abandoned", "worked_out", "ack_height_plus_deadline");
    gz_jw_kint(w, "amount_sat", amount);
    gz_jw_end_obj(w);
}

static void story_lobby(gz_jw *w, gz_fake *f, const char *id, int row)
{
    int first = strcmp(id, LOBBY_ID) == 0;
    int in = first ? f->joined : f->joined2, rdy = in && (first ? f->ready : f->ready2);
    int gone = first ? f->left : f->left2;
    int started = first && (f->m_stage == MS_FUNDING || f->m_stage == MS_ACTIVE);
    int64_t lo = first ? 500 : 3000, now = first ? 1000 : 4000, hi = first ? 1500 : 5000;
    char fp[65];
    hex_of(id, fp);
    gz_jw_obj(w);
    gz_jw_kstr(w, "id", id);
    gz_jw_kstr(w, "fingerprint", fp);
    gz_jw_text(w, "name", first ? "Tomato Garden, daily factory" : "Basil Corner <script>alert(1)</script>", "host", 120);
    gz_jw_key(w, "host");
    gz_jw_obj(w);
    gz_jw_kstr(w, "key", HOST_KEY);
    gz_jw_text(w, "alias", "Tomato Garden", "host", 64);
    gz_jw_kstr(w, "address", "tomato.example:9735");
    gz_jw_knull(w, "record");
    gz_jw_end_obj(w);
    gz_jw_kstr(w, "source", "direct_query");
    gz_jw_kbool(w, "listed", 1);
    gz_jw_kstr(w, "stage", first ? M_STAGE[f->m_stage] : "open");
    if (!row) {
        gz_jw_key(w, "terms");
        terms(w, id, lo, now, hi, 1, 50, 30, 500000);
    }
    gz_jw_key(w, "fit");
    fit(w, f, lo, now, hi);
    gz_jw_key(w, "start_rule");
    gz_jw_obj(w);
    gz_jw_kint(w, "target", 50);
    gz_jw_kint(w, "minimum", 30);
    gz_jw_key(w, "deadline");
    date(w, "lobby_starts_by", TIP + 12, "lobby_applies_start_rule", "signed_term", "term_start_plus_life");
    gz_jw_kstr(w, "on_shortfall", "cancel");
    gz_jw_end_obj(w);
    gz_jw_key(w, "counts");
    gz_jw_obj(w);
    gz_jw_kint(w, "joined", 29 + (in ? 1 : 0));
    gz_jw_kint(w, "ready", 29 + (rdy ? 1 : 0));
    gz_jw_end_obj(w);
    gz_jw_key(w, "you");
    gz_jw_obj(w);
    gz_jw_kstr(w, "seat", seat_name(f, id));
    if (!row) {
        if (rdy) gz_jw_kint(w, "ready_for_version", 3);
        else gz_jw_knull(w, "ready_for_version");
        gz_jw_kbool(w, "counted", rdy);
        if (in) gz_jw_kint(w, "conditions_copied_at", 1794427320);
        else gz_jw_knull(w, "conditions_copied_at");
        gz_jw_text(w, "appear_as", "Lemon-39", "you", 64);
        gz_jw_knull(w, "standby");
        if (first && f->m_outcome == MO_REFUSED) {
            gz_jw_key(w, "outcome");
            gz_jw_obj(w);
            gz_jw_kstr(w, "code", "refused_at_check");
            char fl[400];
            gz_jw_kstr(w, "which", f->m_refuse_kind == 2 ? "safety_check" : "conditions");
            refusal_failures(f, fl, sizeof fl);
            gz_jw_kraw(w, "failures", fl);
            gz_jw_end_obj(w);
        } else if (first && f->m_outcome == MO_UNFINISHED) {
            gz_jw_kraw(w, "outcome", "{\"code\":\"signing_unfinished\",\"cancel_received\":null}");
        } else if (first && f->m_outcome == MO_CANCELLED) {
            gz_jw_kraw(w, "outcome", "{\"code\":\"cancelled\",\"reason\":\"deadline_below_minimum\",\"not_your_doing\":true}");
        } else if (first && f->m_outcome == MO_STARTED) {
            gz_jw_kraw(w, "outcome", "{\"code\":\"started\"}");
        } else if (gone) {
            gz_jw_kraw(w, "outcome", "{\"code\":\"left\",\"reason\":\"user\"}");
        } else {
            gz_jw_knull(w, "outcome");
        }
    }
    gz_jw_end_obj(w);
    if (!row) {
        if (first && f->m_round) {
            gz_jw_key(w, "round");
            story_round(w, f);
        } else {
            gz_jw_knull(w, "round");
        }
        if (started) {
            gz_jw_key(w, "funding");
            story_funding(w, f->m_conf, 22500000);
            gz_jw_kstr(w, "factory_id", FACTORY_ID);
        } else {
            gz_jw_knull(w, "funding");
            gz_jw_knull(w, "factory_id");
        }
        gz_jw_knull(w, "members");
        gz_jw_knull(w, "terms_change");
    } else {
        gz_jw_kint(w, "channel_sat", 500000);
        range(w, "joining_fee_sat", lo, hi);
        gz_jw_kint(w, "exit_blocks", 864);
    }
    gz_jw_end_obj(w);
}

static void story_host_lobby(gz_jw *w, gz_fake *f)
{
    static const char *const HR[] = {"", "collecting_nonces", "collecting_signatures", "complete", "funding", "funded"};
    static const char *const NAMES[] = {"Fig-12", "Plum-3", "Olive-27", "Pear-8", "Lime-41", "Kiwi-5", "Date-19", "Rose-2"};
    char fp[65], sid[24];
    int i, shown = f->h_ready > 8 ? 8 : f->h_ready;
    int open = !f->host_cancelled && f->h_stage == MS_OPEN;
    int can = open && f->h_ready >= f->h_minimum;
    hex_of(HOST_LOBBY_ID, fp);
    gz_jw_obj(w);
    gz_jw_kstr(w, "id", HOST_LOBBY_ID);
    gz_jw_kstr(w, "fingerprint", fp);
    gz_jw_text(w, "name", f->h_name, "you", 120);
    gz_jw_kstr(w, "stage", f->host_cancelled ? "cancelled" : M_STAGE[f->h_stage]);
    gz_jw_key(w, "terms");
    terms(w, HOST_LOBBY_ID, 500, 1000, 1500, 1, f->h_target, f->h_minimum, f->h_channel);
    gz_jw_key(w, "counts");
    gz_jw_obj(w);
    gz_jw_kint(w, "joined", f->h_ready);
    gz_jw_kint(w, "ready", f->h_ready);
    gz_jw_end_obj(w);
    gz_jw_kbool(w, "can_start_now", can);
    gz_jw_key(w, "start_blocked_by");
    gz_jw_arr(w);
    if (open && !can) gz_jw_str(w, "below_minimum");
    gz_jw_end_arr(w);
    gz_jw_key(w, "funding");
    gz_jw_obj(w);
    gz_jw_kint(w, "needed_at_minimum_sat", f->h_minimum * f->h_channel * 3 / 2);
    gz_jw_kint(w, "needed_at_target_sat", f->h_target * f->h_channel * 3 / 2);
    gz_jw_kint(w, "set_aside_sat", f->set_aside_sat);
    gz_jw_kint(w, "wallet_free_sat", free_sat(f));
    gz_jw_end_obj(w);
    gz_jw_key(w, "seats");
    gz_jw_arr(w);
    for (i = 0; i < shown; i++) {
        if (i == 0) snprintf(sid, sizeof sid, "%s", SEAT_ID);
        else snprintf(sid, sizeof sid, "b%015d", i);
        gz_jw_obj(w);
        gz_jw_kstr(w, "seat", sid);
        gz_jw_text(w, "name", NAMES[i], "member", 64);
        gz_jw_kstr(w, "state", f->h_stage >= MS_SIGNING ? "chosen" : "ready");
        gz_jw_kint(w, "joined_at", 1794427000 + i * 60);
        gz_jw_kbool(w, "can_remove", open);
        gz_jw_end_obj(w);
    }
    if (f->h_left_seen) {                              /* a member that left at its own check, as the host sees it */
        gz_jw_obj(w);
        gz_jw_kstr(w, "seat", "c000000000000001");
        gz_jw_text(w, "name", "Sage-7", "member", 64);
        gz_jw_kstr(w, "state", "left");
        gz_jw_kint(w, "joined_at", 1794427900);
        gz_jw_kbool(w, "can_remove", 0);
        gz_jw_end_obj(w);
    }
    gz_jw_end_arr(w);
    gz_jw_knull(w, "standby");
    if (f->h_round) {
        gz_jw_key(w, "round");
        gz_jw_obj(w);
        gz_jw_kstr(w, "state", HR[f->h_round]);
        gz_jw_kint(w, "attempt", f->h_left_seen ? 2 : 1);
        gz_jw_kint(w, "answered", f->h_round == 1 ? f->h_ready / 2 : f->h_ready);
        gz_jw_kint(w, "of", f->h_ready);
        gz_jw_kint(w, "silent", 0);
        gz_jw_end_obj(w);
    } else {
        gz_jw_knull(w, "round");
    }
    gz_jw_kraw(w, "listing", "{\"published\":[\"direct_query\"],\"renew_by\":null}");
    if (f->h_stage == MS_FUNDING || f->h_stage == MS_ACTIVE) {
        gz_jw_key(w, "funding_tx");
        gz_jw_obj(w);
        gz_jw_kstr(w, "txid", FUNDING_TXID);
        gz_jw_kstr(w, "state", funding_state(f->h_conf));
        gz_jw_kint(w, "confirmations", f->h_conf);
        gz_jw_kint(w, "needed", 3);
        gz_jw_kint(w, "broadcast_at", 1794434410);
        gz_jw_end_obj(w);
        gz_jw_kstr(w, "factory_id", HOST_FACTORY_ID);
    } else {
        gz_jw_knull(w, "funding_tx");
        gz_jw_knull(w, "factory_id");
    }
    gz_jw_end_obj(w);
}

/* 16.1: the member's factory, or (host) the one this program funded */
static void story_factory(gz_jw *w, gz_fake *f, int row, int host)
{
    int live = (host ? f->h_stage : f->m_stage) == MS_ACTIVE, conf = host ? f->h_conf : f->m_conf;
    int64_t members = host ? f->h_ready : 30, chan = host ? f->h_channel : 500000;
    const char *fid = host ? HOST_FACTORY_ID : FACTORY_ID;
    char fp[65];
    hex_of(fid, fp);
    gz_jw_obj(w);
    gz_jw_kstr(w, "id", fid);
    gz_jw_kstr(w, "fingerprint", fp);
    gz_jw_kstr(w, "lobby_id", host ? HOST_LOBBY_ID : LOBBY_ID);
    if (host) gz_jw_text(w, "name", f->h_name, "you", 120);
    else gz_jw_text(w, "name", "Tomato Garden, factory 12", "host", 120);
    gz_jw_kstr(w, "role", host ? "host" : "member");
    gz_jw_kstr(w, "state", live ? "live" : "awaiting_funding");
    gz_jw_kint(w, "members", members);
    if (!row) {
        gz_jw_key(w, "host");
        gz_jw_obj(w);
        gz_jw_kstr(w, "key", HOST_KEY);
        gz_jw_text(w, "alias", host ? f->h_name : "Tomato Garden", host ? "you" : "host", 64);
        gz_jw_kstr(w, "link", "connected");
        gz_jw_kint(w, "last_heard_at", 1794434390);
        gz_jw_end_obj(w);
        gz_jw_key(w, "terms");
        terms(w, fid, 1000, 1000, 1000, 1, host ? f->h_target : 50, host ? f->h_minimum : 30, chan);
        if (host) gz_jw_knull(w, "saved_copy_activity_id");
        else gz_jw_kstr(w, "saved_copy_activity_id", "act_2002");
        gz_jw_key(w, "funding");
        gz_jw_obj(w);
        gz_jw_kstr(w, "txid", FUNDING_TXID);
        gz_jw_kint(w, "vout", 0);
        gz_jw_kint(w, "amount_sat", members * chan * 3 / 2);
        gz_jw_kstr(w, "state", funding_state(conf));
        gz_jw_kint(w, "confirmations", conf);
        gz_jw_kint(w, "needed", 3);
        gz_jw_kint(w, "height", TIP - 1);
        gz_jw_end_obj(w);
        if (host)
            gz_jw_kraw(w, "tree", "{\"depth\":1,\"levels\":[{\"kind\":\"fixed\",\"width\":4}],\"path\":null,\"leaf\":\"one_member\"}");
        else
            gz_jw_kraw(w, "tree", "{\"depth\":2,\"levels\":[{\"kind\":\"fixed\",\"width\":4},{\"kind\":\"fixed\",\"width\":2}],"
                                  "\"path\":[{\"level\":1,\"index\":1,\"of\":4,\"members_below\":13},"
                                  "{\"level\":2,\"index\":0,\"of\":2,\"members_below\":1}],\"leaf\":\"one_member\"}");
        gz_jw_knull(w, "channel");                      /* Slice 1: no channels (16.1) */
        gz_jw_knull(w, "channels");
        gz_jw_key(w, "dates");
        gz_jw_arr(w);
        if (!live) date(w, "funding_deadline", TIP + 144, "round_abandoned", "worked_out", "ack_height_plus_deadline");
        date(w, "factory_ends", TIP + 4752, "factory_end_rule_applies", "signed_term", "term_start_plus_life");
        gz_jw_end_arr(w);
        gz_jw_knull(w, "exit");
        gz_jw_knull(w, "exit_progress");
        gz_jw_knull(w, "move");
        gz_jw_knull(w, "unfinished_round");
        gz_jw_kraw(w, "trouble", "[]");
        if (host) {
            gz_jw_key(w, "host_view");
            gz_jw_obj(w);
            gz_jw_kint(w, "funded_sat", members * chan * 3 / 2);
            gz_jw_kint(w, "members_online", members);
            gz_jw_kint(w, "members_moved", 0);
            gz_jw_kint(w, "fee_funds_ready_sat", 0);
            gz_jw_kraw(w, "deadlines", "[]");
            gz_jw_key(w, "tree");
            gz_jw_obj(w);
            gz_jw_kint(w, "depth", 1);
            gz_jw_kraw(w, "levels", "[{\"kind\":\"fixed\",\"width\":4}]");
            gz_jw_kint(w, "leaves", members);
            gz_jw_kstr(w, "leaf", "one_member");
            gz_jw_kint(w, "members", members);
            gz_jw_end_obj(w);
            gz_jw_end_obj(w);
        } else {
            gz_jw_knull(w, "host_view");
        }
    }
    gz_jw_end_obj(w);
}

/* 19: what the story has done so far, newest first (before the fixed picture's two entries) */
static void story_activity(gz_jw *w, gz_fake *f)
{
#define ENTRY(id, kind, lob, fac, who, rule, params) \
    gz_jw_raw(w, "{\"id\":\"" id "\",\"at\":1794434400,\"kind\":\"" kind "\",\"lobby_id\":" lob ",\"factory_id\":" fac \
                 ",\"who_decided\":\"" who "\",\"rule\":" rule ",\"params\":" params "}")
    if (f->h_stage == MS_ACTIVE)
        ENTRY("act_2106", "factory_live", "\"" HOST_LOBBY_ID "\"", "\"" HOST_FACTORY_ID "\"", "the_chain",
              "{\"code\":\"confirmations_required\",\"params\":{}}", "{}");
    if (f->h_stage == MS_FUNDING || f->h_stage == MS_ACTIVE)
        ENTRY("act_2105", "funded", "\"" HOST_LOBBY_ID "\"", "\"" HOST_FACTORY_ID "\"", "the_app",
              "{\"code\":\"start_rule\",\"params\":{}}", "{}");
    if (f->host_open)
        ENTRY("act_2104", "lobby_opened", "\"" HOST_LOBBY_ID "\"", "null", "you", "null", "{}");
    if (f->m_outcome == MO_STARTED)
        ENTRY("act_2006", "factory_live", "\"" LOBBY_ID "\"", "\"" FACTORY_ID "\"", "the_chain",
              "{\"code\":\"confirmations_required\",\"params\":{}}", "{}");
    if (f->m_stage == MS_FUNDING || f->m_stage == MS_ACTIVE)
        ENTRY("act_2005", "signed", "\"" LOBBY_ID "\"", "\"" FACTORY_ID "\"", "the_app",
              "{\"code\":\"joining_was_consent\",\"params\":{}}", "{}");
    if (f->m_outcome == MO_UNFINISHED)
        ENTRY("act_2004", "signing_unfinished", "\"" LOBBY_ID "\"", "null", "the_app", "null", "{}");
    if (f->m_outcome == MO_CANCELLED)
        ENTRY("act_2003", "lobby_cancelled", "\"" LOBBY_ID "\"", "null", "the_host",
              "{\"code\":\"start_rule\",\"params\":{}}", "{\"reason\":\"deadline_below_minimum\"}");
    if (f->m_outcome == MO_REFUSED) {
        char e[900], fl[400];
        refusal_failures(f, fl, sizeof fl);
        snprintf(e, sizeof e,
                 "{\"id\":\"act_2001\",\"at\":1794434400,\"kind\":\"refused\",\"lobby_id\":\"" LOBBY_ID "\","
                 "\"factory_id\":null,\"who_decided\":\"the_app\","
                 "\"rule\":{\"code\":\"my_conditions\",\"params\":{\"conditions_version\":%lld}},"
                 "\"params\":{\"failures\":%s,"
                 "\"nothing_signed\":true}}",
                 (long long)f->cond_version, fl);
        gz_jw_raw(w, e);
    }
    if (f->joined || f->m_outcome != MO_NONE || f->m_stage != MS_OPEN)
        ENTRY("act_2002", "joined", "\"" LOBBY_ID "\"", "null", "you",
              "{\"code\":\"joining_was_consent\",\"params\":{}}", "{}");
#undef ENTRY
}

/* 11: what the story adds to the status facts. The strings live in f->st_buf. */
static void story_status(gz_fake *f, gz_api_status_facts *s)
{
    gz_jw jw;
    const char *nd = NULL;
    int64_t nd_height = 0;
    int m_in = f->m_stage == MS_FUNDING || f->m_stage == MS_ACTIVE, h_in = f->h_stage == MS_FUNDING || f->h_stage == MS_ACTIVE;
    s->has_something_to_watch = watching(f);
    s->factories_watched = (m_in ? 1 : 0) + (h_in ? 1 : 0);
    s->hosted_factories_sat = f->h_funded_sat;
    s->hosting_json = NULL;
    if (f->host_open && !f->host_cancelled) {
        snprintf(f->st_buf[0], sizeof f->st_buf[0], "{\"lobbies_open\":%d,\"factories\":%d,\"next_date\":null}",
                 h_in ? 0 : 1, h_in ? 1 : 0);
        s->hosting_json = f->st_buf[0];
    }
    s->next_date_json = NULL;
    if (f->wallet != GZ_API_WALLET_UNLOCKED) return;
#define DO(c, lob, pj) do { \
        s->doing[s->ndoing].code = (c); \
        s->doing[s->ndoing].lobby_id = (lob); \
        s->doing[s->ndoing].params_json = (pj); \
        s->ndoing++; \
    } while (0)
#define ATT(i_, c, lob, fac, pj) do { \
        s->attention[s->nattention].id = (i_); \
        s->attention[s->nattention].code = (c); \
        s->attention[s->nattention].lobby_id = (lob); \
        s->attention[s->nattention].factory_id = (fac); \
        s->attention[s->nattention].params_json = (pj); \
        s->nattention++; \
    } while (0)
    if (f->m_stage == MS_FUNDING) {
        snprintf(f->st_buf[1], sizeof f->st_buf[1], "{\"factory_id\":\"" FACTORY_ID "\",\"confirmations\":%d,\"needed\":3}", f->m_conf);
        DO("awaiting_funding", LOBBY_ID, f->st_buf[1]);
        nd = "funding_deadline";
        nd_height = TIP + 144;
    } else if (f->m_stage == MS_ACTIVE) {
        DO("idle_in_factory", NULL, "{\"factory_id\":\"" FACTORY_ID "\"}");
        nd = "factory_ends";
        nd_height = TIP + 4752;
    } else if (f->m_stage == MS_SIGNING && f->m_outcome == MO_NONE) {
        snprintf(f->st_buf[1], sizeof f->st_buf[1], "{\"of\":17,\"done\":%d}", f->m_round >= 3 ? 11 : 0);
        DO("signing", LOBBY_ID, f->st_buf[1]);
    } else if (f->m_stage == MS_READY_CHECK) {
        DO("ready_check", LOBBY_ID, "{}");
    } else if (f->joined && f->m_outcome == MO_NONE) {
        if (f->ready) DO("in_lobby_waiting", LOBBY_ID, "{\"ready\":30,\"target\":50,\"minimum\":30}");
        else DO("in_lobby_not_ready", LOBBY_ID, "{\"reasons\":[\"user_choice\"]}");
        nd = "lobby_starts_by";
        nd_height = TIP + 12;
    }
    if (f->m_outcome == MO_REFUSED) {
        char fl[300];
        refusal_failures(f, fl, sizeof fl);
        snprintf(f->st_buf[2], sizeof f->st_buf[2], "{\"failures\":%s}", fl);
        DO("refused", LOBBY_ID, f->st_buf[2]);
        ATT("att_r1", "refused_to_sign", LOBBY_ID, NULL, "{\"lobby_id\":\"" LOBBY_ID "\",\"activity_id\":\"act_2001\"}");
    }
    if (f->m_outcome == MO_UNFINISHED) {
        DO("signing_unfinished", LOBBY_ID, "{\"purpose\":\"start\",\"cancel_received\":null}");
        ATT("att_s1", "signing_unfinished", LOBBY_ID, NULL,
            "{\"lobby_id\":\"" LOBBY_ID "\",\"purpose\":\"start\",\"sent_at\":1794434404,\"last_heard_at\":1794434404,"
            "\"checked_to_height\":330437,\"cancel_received\":null}");
    }
    if (f->m_outcome == MO_CANCELLED) DO("lobby_cancelled", LOBBY_ID, "{\"reason\":\"deadline_below_minimum\"}");
    if (f->joined2) {
        if (f->ready2) DO("in_lobby_waiting", LOBBY2_ID, "{\"ready\":30,\"target\":50,\"minimum\":30}");
        else DO("in_lobby_not_ready", LOBBY2_ID, "{\"reasons\":[\"user_choice\"]}");
    }
    if (f->h_stage == MS_FUNDING && !m_in) {
        snprintf(f->st_buf[3], sizeof f->st_buf[3], "{\"factory_id\":\"" HOST_FACTORY_ID "\",\"confirmations\":%d,\"needed\":3}", f->h_conf);
        DO("awaiting_funding", HOST_LOBBY_ID, f->st_buf[3]);
    } else if (f->h_stage == MS_ACTIVE && !m_in) {
        DO("idle_in_factory", NULL, "{\"factory_id\":\"" HOST_FACTORY_ID "\"}");
    }
    if (f->chain_state == GZ_API_CHAIN_DISAGREE) ATT("att_c1", "chain_disagree", NULL, NULL, "{\"since_at\":1794431000,\"servers\":2}");
    if (f->chain_state == GZ_API_CHAIN_ONE_SOURCE) ATT("att_c2", "chain_one_source", NULL, NULL, "{\"since_at\":1794431000}");
    if (f->chain_state == GZ_API_CHAIN_UNREACHABLE) ATT("att_c3", "chain_unreachable", NULL, NULL, "{\"since_at\":1794431000}");
    if (f->chain_state == GZ_API_CHAIN_CATCHING_UP) ATT("att_c4", "chain_catching_up", NULL, NULL, "{\"since_at\":1794431000}");
    if (f->host_open && !f->host_cancelled && f->h_stage == MS_OPEN && f->h_ready >= f->h_minimum)
        ATT("att_h1", "host_can_start", HOST_LOBBY_ID, NULL, "{\"lobby_id\":\"" HOST_LOBBY_ID "\"}");
    if (f->restoring) ATT("att_x1", "restored_factories_unknown", NULL, NULL, "{}");
#undef DO
#undef ATT
    if (nd) {
        gz_jw_init(&jw);
        date(&jw, nd, nd_height, nd[0] == 'l' ? "lobby_applies_start_rule" : nd[1] == 'u' ? "round_abandoned" : "factory_end_rule_applies",
             nd[0] == 'l' || nd[1] == 'a' ? "signed_term" : "worked_out",
             nd[1] == 'u' ? "ack_height_plus_deadline" : "term_start_plus_life");
        if (!jw.err && jw.len < sizeof f->st_buf[4]) {
            memcpy(f->st_buf[4], jw.buf, jw.len);
            f->st_buf[4][jw.len] = 0;
            s->next_date_json = f->st_buf[4];
        }
        gz_jw_free(&jw);
    }
}

static void lobby(gz_jw *w, gz_fake *f, const char *id, int row)
{
    int first = strcmp(id, LOBBY_ID) == 0;
    int64_t lo = first ? 500 : 3000, now = first ? 1000 : 4000, hi = first ? 1500 : 5000;
    char fp[65];
    if (f->story) { story_lobby(w, f, id, row); return; }
    hex_of(id, fp);
    gz_jw_obj(w);
    gz_jw_kstr(w, "id", id);
    gz_jw_kstr(w, "fingerprint", fp);
    gz_jw_text(w, "name", first ? "Tomato Garden, daily factory" : "Basil Corner <script>alert(1)</script>", "host", 120);
    gz_jw_key(w, "host");
    gz_jw_obj(w);
    gz_jw_kstr(w, "key", HOST_KEY);
    gz_jw_text(w, "alias", "Tomato Garden", "host", 64);
    gz_jw_kstr(w, "address", "tomato.example:9735");
    gz_jw_knull(w, "record");
    gz_jw_end_obj(w);
    gz_jw_kstr(w, "source", "direct_query");
    gz_jw_kbool(w, "listed", 1);
    gz_jw_kstr(w, "stage", "open");
    if (!row) {
        gz_jw_key(w, "terms");
        terms(w, id, lo, now, hi, 1, 50, 30, 500000);
    }
    gz_jw_key(w, "fit");
    fit(w, f, lo, now, hi);
    gz_jw_key(w, "start_rule");
    gz_jw_obj(w);
    gz_jw_kint(w, "target", 50);
    gz_jw_kint(w, "minimum", 30);
    gz_jw_key(w, "deadline");
    date(w, "lobby_starts_by", TIP + 12, "lobby_applies_start_rule", "signed_term", "term_start_plus_life");
    gz_jw_kstr(w, "on_shortfall", "cancel");
    gz_jw_end_obj(w);
    gz_jw_kraw(w, "counts", "{\"joined\":38,\"ready\":38}");
    gz_jw_key(w, "you");
    gz_jw_obj(w);
    gz_jw_kstr(w, "seat", seat_name(f, id));
    if (!row) {
        if (first && f->ready) gz_jw_kint(w, "ready_for_version", 3);
        else gz_jw_knull(w, "ready_for_version");
        gz_jw_kbool(w, "counted", first && f->ready);
        if (first && f->joined) gz_jw_kint(w, "conditions_copied_at", 1794427320);
        else gz_jw_knull(w, "conditions_copied_at");
        gz_jw_text(w, "appear_as", "Lemon-39", "you", 64);
        gz_jw_knull(w, "standby");                     /* provisional: null until standby messages exist */
        if (first && f->left) gz_jw_kraw(w, "outcome", "{\"code\":\"left\",\"reason\":\"user\"}");
        else gz_jw_knull(w, "outcome");
    }
    gz_jw_end_obj(w);
    if (!row) {
        gz_jw_knull(w, "round");
        gz_jw_knull(w, "funding");
        gz_jw_knull(w, "factory_id");
        gz_jw_knull(w, "members");
        gz_jw_knull(w, "terms_change");
    } else {
        gz_jw_kint(w, "channel_sat", 500000);
        range(w, "joining_fee_sat", lo, hi);
        gz_jw_kint(w, "exit_blocks", 864);
    }
    gz_jw_end_obj(w);
}

static void host_lobby(gz_jw *w, gz_fake *f)
{
    char fp[65];
    if (f->story) { story_host_lobby(w, f); return; }
    hex_of(HOST_LOBBY_ID, fp);
    gz_jw_obj(w);
    gz_jw_kstr(w, "id", HOST_LOBBY_ID);
    gz_jw_kstr(w, "fingerprint", fp);
    gz_jw_text(w, "name", "My first lobby", "you", 120);
    gz_jw_kstr(w, "stage", f->host_cancelled ? "cancelled" : "open");
    gz_jw_key(w, "terms");
    terms(w, HOST_LOBBY_ID, 500, 1000, 1500, 1, 50, 30, 500000);
    gz_jw_key(w, "counts");
    gz_jw_obj(w);
    gz_jw_kint(w, "joined", f->host_seat_removed ? 0 : 1);
    gz_jw_kint(w, "ready", f->host_seat_removed ? 0 : 1);
    gz_jw_end_obj(w);
    gz_jw_kbool(w, "can_start_now", 0);
    gz_jw_kraw(w, "start_blocked_by", "[\"below_minimum\"]");
    gz_jw_key(w, "funding");
    gz_jw_obj(w);
    gz_jw_kint(w, "needed_at_minimum_sat", 22500000);
    gz_jw_kint(w, "needed_at_target_sat", 37500000);
    gz_jw_kint(w, "set_aside_sat", f->set_aside_sat);
    gz_jw_kint(w, "wallet_free_sat", free_sat(f));
    gz_jw_end_obj(w);
    gz_jw_key(w, "seats");
    gz_jw_arr(w);
    if (!f->host_seat_removed) {
        gz_jw_obj(w);
        gz_jw_kstr(w, "seat", SEAT_ID);
        gz_jw_text(w, "name", "Fig-12", "member", 64);
        gz_jw_kstr(w, "state", "ready");
        gz_jw_kint(w, "joined_at", 1794427000);
        gz_jw_kbool(w, "can_remove", !f->host_cancelled);
        gz_jw_end_obj(w);
    }
    gz_jw_end_arr(w);
    gz_jw_knull(w, "standby");
    gz_jw_knull(w, "round");
    gz_jw_kraw(w, "listing", "{\"published\":[\"direct_query\"],\"renew_by\":null}");
    gz_jw_knull(w, "funding_tx");
    gz_jw_knull(w, "factory_id");
    gz_jw_end_obj(w);
}

static void factory(gz_jw *w, gz_fake *f, int row)
{
    (void)f;
    gz_jw_obj(w);
    gz_jw_kstr(w, "id", FACTORY_ID);
    {
        char fp[65];
        hex_of(FACTORY_ID, fp);
        gz_jw_kstr(w, "fingerprint", fp);
    }
    gz_jw_kstr(w, "lobby_id", "lob_2d91");
    gz_jw_text(w, "name", "Tomato Garden, factory 12", "host", 120);
    gz_jw_kstr(w, "role", "member");
    gz_jw_kstr(w, "state", "awaiting_funding");
    gz_jw_kint(w, "members", 50);
    if (!row) {
        gz_jw_key(w, "host");
        gz_jw_obj(w);
        gz_jw_kstr(w, "key", HOST_KEY);
        gz_jw_text(w, "alias", "Tomato Garden", "host", 64);
        gz_jw_kstr(w, "link", "connected");
        gz_jw_kint(w, "last_heard_at", 1794434390);
        gz_jw_end_obj(w);
        gz_jw_key(w, "terms");
        terms(w, FACTORY_ID, 1000, 1000, 1000, 1, 50, 30, 500000);
        gz_jw_kstr(w, "saved_copy_activity_id", "act_1001");
        gz_jw_kraw(w, "funding", "{\"txid\":\"9f1c2a7e5d3b4c6a8e0f1d2c3b4a59687766554433221100ffeeddccbbaa9988\","
                                 "\"vout\":0,\"amount_sat\":37500000,\"state\":\"confirming\",\"confirmations\":1,"
                                 "\"needed\":3,\"height\":330436}");
        gz_jw_kraw(w, "tree", "{\"depth\":2,\"levels\":[{\"kind\":\"fixed\",\"width\":4},{\"kind\":\"fixed\",\"width\":2}],"
                              "\"path\":[{\"level\":1,\"index\":1,\"of\":4,\"members_below\":13},"
                              "{\"level\":2,\"index\":0,\"of\":2,\"members_below\":1}],\"leaf\":\"one_member\"}");
        gz_jw_knull(w, "channel");                      /* Slice 1: no channels (16.1) */
        gz_jw_knull(w, "channels");
        gz_jw_key(w, "dates");
        gz_jw_arr(w);
        date(w, "funding_deadline", TIP + 144, "round_abandoned", "worked_out", "ack_height_plus_deadline");
        date(w, "factory_ends", TIP + 4752, "factory_end_rule_applies", "signed_term", "term_start_plus_life");
        gz_jw_end_arr(w);
        gz_jw_knull(w, "exit");
        gz_jw_knull(w, "exit_progress");
        gz_jw_knull(w, "move");
        gz_jw_knull(w, "unfinished_round");
        gz_jw_kraw(w, "trouble", "[]");
        gz_jw_knull(w, "host_view");
    }
    gz_jw_end_obj(w);
}

static void conditions(gz_jw *w, gz_fake *f)
{
    gz_jw_obj(w);
    gz_jw_kint(w, "version", f->cond_version);
    gz_jw_kstr(w, "preset", f->cond_preset);
    gz_jw_key(w, "conditions");
    gz_jw_obj(w);
    gz_jw_kraw(w, "profiles", "[\"safety\",\"standard\"]");
    gz_jw_kint(w, "min_members", f->cond_min_members);
    gz_jw_kint(w, "min_channel_sat", 200000);
    gz_jw_kint(w, "max_joining_fee_sat", f->cond_max_joining_fee_sat);
    gz_jw_kint(w, "max_fee_base_msat", 2000);
    gz_jw_kint(w, "max_fee_ppm", f->cond_max_fee_ppm);
    gz_jw_knull(w, "max_receiving_room_fee_ppm");
    gz_jw_kint(w, "min_life_blocks", 1008);
    gz_jw_kint(w, "max_life_blocks", 6480);
    gz_jw_kint(w, "max_exit_blocks", 1008);
    gz_jw_kint(w, "min_confirmations", f->cond_min_confirmations);
    gz_jw_kraw(w, "payment_sizes_sat", "{\"min\":100,\"max\":200000}");
    gz_jw_knull(w, "max_move_fee_sat");
    gz_jw_kstr(w, "seat_cost", "none");
    gz_jw_kstr(w, "compare_with", "whole_range");
    gz_jw_kint(w, "host_min_factories_funded", 0);
    gz_jw_kbool(w, "host_proof_required", 0);
    gz_jw_kraw(w, "hosts_trusted", "[]");
    gz_jw_kraw(w, "hosts_avoided", "[]");
    gz_jw_kraw(w, "people_blocked", "[]");
    gz_jw_kstr(w, "appear_as", "temporary_name");
    gz_jw_kstr(w, "move_to_next", "by_itself_if_fits");
    gz_jw_end_obj(w);
    gz_jw_kraw(w, "limits", "{\"min_members\":[2,512],\"min_confirmations\":[2,100],\"max_exit_blocks\":[144,4320]}");
    gz_jw_kraw(w, "presets", "[{\"id\":\"cautious\",\"conditions\":{\"max_joining_fee_sat\":1000,\"min_members\":30}},"
                             "{\"id\":\"everyday\",\"conditions\":{\"max_joining_fee_sat\":2000,\"min_members\":20}},"
                             "{\"id\":\"wide\",\"conditions\":{\"max_joining_fee_sat\":5000,\"min_members\":10}}]");
    gz_jw_key(w, "fit_summary");
    gz_jw_obj(w);
    gz_jw_kint(w, "listed", 2);
    gz_jw_kint(w, "fit", fits(f, 5000) ? 2 : 1);
    gz_jw_kint(w, "fits_only_now", 0);
    gz_jw_key(w, "excluded_most_by");
    if (fits(f, 5000)) {
        gz_jw_null(w);
    } else {
        gz_jw_obj(w);
        gz_jw_kstr(w, "condition", "max_joining_fee_sat");
        gz_jw_kint(w, "yours", f->cond_max_joining_fee_sat);
        gz_jw_kint(w, "lobbies_excluded", 1);
        gz_jw_end_obj(w);
    }
    gz_jw_end_obj(w);
    gz_jw_key(w, "copied_into");
    gz_jw_arr(w);
    if (f->joined && !f->left) gz_jw_raw(w, "{\"lobby_id\":\"lob_7k2q\",\"copied_at\":1794427320,\"version\":6}");
    gz_jw_end_arr(w);
    gz_jw_kbool(w, "editable", 1);
    gz_jw_end_obj(w);
}

/* ---- conditions: what loosens (13.2) ----------------------------------------------------- */
static const char *const MAX_FIELDS[] = {"max_joining_fee_sat", "max_fee_base_msat", "max_fee_ppm", "max_life_blocks",
                                         "max_exit_blocks"};
static const char *const MIN_FIELDS[] = {"min_members", "min_channel_sat", "min_life_blocks", "min_confirmations"};
static const char *const KNOWN_COND[] = {
    "profiles", "min_members", "min_channel_sat", "max_joining_fee_sat", "max_fee_base_msat", "max_fee_ppm",
    "max_receiving_room_fee_ppm", "min_life_blocks", "max_life_blocks", "max_exit_blocks", "min_confirmations",
    "payment_sizes_sat", "max_move_fee_sat", "seat_cost", "compare_with", "host_min_factories_funded",
    "host_proof_required", "hosts_trusted", "hosts_avoided", "people_blocked", "appear_as", "move_to_next"};

static int64_t current_cond(gz_fake *f, const char *k)
{
    if (strcmp(k, "max_joining_fee_sat") == 0) return f->cond_max_joining_fee_sat;
    if (strcmp(k, "min_members") == 0) return f->cond_min_members;
    if (strcmp(k, "min_confirmations") == 0) return f->cond_min_confirmations;
    if (strcmp(k, "max_fee_ppm") == 0) return f->cond_max_fee_ppm;
    if (strcmp(k, "max_fee_base_msat") == 0) return 2000;
    if (strcmp(k, "max_life_blocks") == 0) return 6480;
    if (strcmp(k, "max_exit_blocks") == 0) return 1008;
    if (strcmp(k, "min_channel_sat") == 0) return 200000;
    if (strcmp(k, "min_life_blocks") == 0) return 1008;
    return 0;
}

/* -1 refused (err set), else the number of loosened fields written to names */
static int examine(gz_fake *f, const gz_json *cond, const char *names[12], gz_api_error *err)
{
    const gz_json *m;
    int n = 0;
    size_t i;
    static char field[96];
    for (m = cond->child; m; m = m->next) {
        int known = 0;
        for (i = 0; i < sizeof KNOWN_COND / sizeof KNOWN_COND[0]; i++)
            if (strlen(KNOWN_COND[i]) == m->key_len && memcmp(KNOWN_COND[i], m->key, m->key_len) == 0) known = 1;
        snprintf(field, sizeof field, "/conditions/%.*s", (int)(m->key_len < 60 ? m->key_len : 60), m->key);
        if (!known) { gz_api_err_set(err, "unknown_field", field, NULL); return -1; }
    }
    for (i = 0; i < sizeof MAX_FIELDS / sizeof MAX_FIELDS[0]; i++) {
        const gz_json *v = gz_json_get(cond, MAX_FIELDS[i]);
        if (!v) continue;
        snprintf(field, sizeof field, "/conditions/%s", MAX_FIELDS[i]);
        if (v->type != GZ_JSON_INT || v->i < 0) { gz_api_err_set(err, "bad_value", field, NULL); return -1; }
        if (v->i > current_cond(f, MAX_FIELDS[i])) names[n++] = MAX_FIELDS[i];
    }
    for (i = 0; i < sizeof MIN_FIELDS / sizeof MIN_FIELDS[0]; i++) {
        const gz_json *v = gz_json_get(cond, MIN_FIELDS[i]);
        if (!v) continue;
        snprintf(field, sizeof field, "/conditions/%s", MIN_FIELDS[i]);
        if (v->type != GZ_JSON_INT || v->i < 0) { gz_api_err_set(err, "bad_value", field, NULL); return -1; }
        if (strcmp(MIN_FIELDS[i], "min_members") == 0 && (v->i < 2 || v->i > 512)) {
            gz_api_err_set(err, "bad_value", field, "{\"min\":2,\"max\":512}");
            return -1;
        }
        if (strcmp(MIN_FIELDS[i], "min_confirmations") == 0 && v->i < 3) {
            gz_api_err_set(err, "below_floor", field, "{\"floor\":3,\"yours\":%lld}", (long long)v->i);
            return -1;
        }
        if (v->i < current_cond(f, MIN_FIELDS[i])) names[n++] = MIN_FIELDS[i];
    }
    m = gz_json_get(cond, "compare_with");
    if (m && m->type == GZ_JSON_STR && strcmp(m->s, "current_value") == 0) names[n++] = "compare_with";
    return n;
}

static void apply_cond(gz_fake *f, const gz_json *cond)
{
    const gz_json *v;
    if ((v = gz_json_get(cond, "max_joining_fee_sat")) && v->type == GZ_JSON_INT) f->cond_max_joining_fee_sat = v->i;
    if ((v = gz_json_get(cond, "min_members")) && v->type == GZ_JSON_INT) f->cond_min_members = v->i;
    if ((v = gz_json_get(cond, "min_confirmations")) && v->type == GZ_JSON_INT) f->cond_min_confirmations = v->i;
    if ((v = gz_json_get(cond, "max_fee_ppm")) && v->type == GZ_JSON_INT) f->cond_max_fee_ppm = v->i;
}

/* ---- the host's draft (15.1) ------------------------------------------------------------- */
static int64_t jint(const gz_json *o, const char *k, int64_t dflt)
{
    const gz_json *v = gz_json_get(o, k);
    return v && v->type == GZ_JSON_INT ? v->i : dflt;
}

static void draft_digest(const gz_json *draft, char out[65])
{
    gz_jw cw;
    unsigned char h[32];
    static const char x[] = "0123456789abcdef";
    int i;
    gz_jw_init(&cw);
    gz_json_jcs(draft, 0, &cw);
    SHA256((const unsigned char *)(cw.buf ? cw.buf : ""), cw.len, h);
    gz_jw_free(&cw);
    for (i = 0; i < 32; i++) { out[2 * i] = x[h[i] >> 4]; out[2 * i + 1] = x[h[i] & 15]; }
    out[64] = 0;
}

typedef struct {
    int64_t at_min, at_target;
    const char *problems[12][2];
    int nproblems;
    const char *cannot[6];
    int ncannot;
} preview;

static void do_preview(gz_fake *f, const gz_json *d, int64_t now, preview *p)
{
    const gz_json *v;
    int64_t target = jint(d, "target", 0), minimum = jint(d, "minimum", 0), chan = jint(d, "channel_sat", 0);
    int64_t deadline = jint(d, "deadline_at", 0);
    memset(p, 0, sizeof *p);
#define PROBLEM(fl, code) do { if (p->nproblems < 12) { p->problems[p->nproblems][0] = fl; p->problems[p->nproblems++][1] = code; } } while (0)
    v = gz_json_get(d, "name");
    if (!v || v->type != GZ_JSON_STR || v->len == 0) PROBLEM("/name", "name_missing");
    if (!deadline) PROBLEM("/deadline_at", "deadline_missing");
    else if (deadline <= now) PROBLEM("/deadline_at", "deadline_past");
    if (minimum < 2) PROBLEM("/minimum", "minimum_too_small");
    if (target < minimum) PROBLEM("/target", "target_below_minimum");
    if (target > 512) PROBLEM("/target", "target_too_large");
    if (chan < 10000) PROBLEM("/channel_sat", "channel_too_small");
    v = gz_json_get(d, "profile");
    if (v && (v->type != GZ_JSON_STR || strcmp(v->s, "standard") != 0)) PROBLEM("/profile", "profile_not_in_slice");
    v = gz_json_get(d, "on_shortfall");
    if (v && (v->type != GZ_JSON_STR || strcmp(v->s, "cancel") != 0)) PROBLEM("/on_shortfall", "on_shortfall_not_in_slice");
    v = gz_json_get(d, "reserved");
    if (v && v->type == GZ_JSON_OBJ) {
        const gz_json *m;
        for (m = v->child; m; m = m->next)
            if (m->type != GZ_JSON_NULL) { PROBLEM("/reserved", "reserved_term_set"); break; }
    }
    v = gz_json_get(d, "joining_fee_sat");
    if (v && v->type == GZ_JSON_OBJ) {
        int64_t lo = jint(v, "min", 0), hi = jint(v, "max", 0), nw = jint(v, "now", 0);
        if (lo > hi) PROBLEM("/joining_fee_sat", "range_inverted");
        else if (nw < lo || nw > hi) PROBLEM("/joining_fee_sat", "now_outside_range");
    }
#undef PROBLEM
    p->at_min = minimum * chan * 3 / 2;
    p->at_target = target * chan * 3 / 2;
    if (p->nproblems) p->cannot[p->ncannot++] = "problems";
    if (p->at_target > free_sat(f)) p->cannot[p->ncannot++] = "funds_short";
    if (f->host_open && !f->host_cancelled) p->cannot[p->ncannot++] = "already_hosting";
    if (f->chain_state != GZ_API_CHAIN_AGREE && f->chain_state != GZ_API_CHAIN_LAGGING)
        p->cannot[p->ncannot++] = "chain_in_doubt";
}

static void story_host_opened(gz_fake *f, const gz_json *d)
{
    const gz_json *n = gz_json_get(d, "name");
    f->h_stage = MS_OPEN;
    f->h_round = 0;
    f->h_ready = 0;
    f->h_conf = 0;
    f->h_left_seen = 0;
    f->h_funded_sat = 0;
    f->h_target = jint(d, "target", 50);
    f->h_minimum = jint(d, "minimum", 30);
    f->h_channel = jint(d, "channel_sat", 500000);
    snprintf(f->h_name, sizeof f->h_name, "%s", n && n->type == GZ_JSON_STR ? n->s : "My lobby");
}

/* ---- the calls ------------------------------------------------------------------------------- */
static int not_found(gz_api_error *err) { gz_api_err_set(err, "not_found", NULL, NULL); return 404; }

static int call_inner(void *be, const gz_api_call *c, gz_jw *w, gz_api_error *err, int *effect)
{
    gz_fake *f = be;
    const gz_json *b = c->body;
    int status = 200, i;
    pthread_mutex_lock(&f->mu);
    switch (c->id) {
    case GZ_API_C_SETUP_GET:
        gz_jw_obj(w);
        gz_jw_kstr(w, "state", f->wallet == GZ_API_WALLET_NONE ? "none" : f->restoring ? "restoring"
                               : f->setup_ready ? "ready" : "created_not_finished");
        gz_jw_kstr(w, "network", "signet");
        gz_jw_kraw(w, "networks", "[{\"id\":\"signet\",\"available\":true},"
                                  "{\"id\":\"testnet4\",\"available\":false,\"reason\":\"one_operator\"},"
                                  "{\"id\":\"mainnet\",\"available\":false,\"reason\":\"switched_off_in_release\"}]");
        gz_jw_kint(w, "words", 24);
        gz_jw_end_obj(w);
        break;
    case GZ_API_C_RESTORE_GET:
        gz_jw_obj(w);
        gz_jw_kstr(w, "state", f->restoring ? "scanning_chain" : "done");
        gz_jw_kint(w, "on_chain_found_sat", f->restoring ? 48000 : 0);
        gz_jw_kstr(w, "factories", "need_backup");
        gz_jw_kraw(w, "lost_seats", "[]");
        gz_jw_end_obj(w);
        break;
    case GZ_API_C_FINISH_SETUP: {
        const gz_json *p = gz_json_get(b, "preset"), *fd = gz_json_get(b, "find");
        if (f->wallet == GZ_API_WALLET_NONE) { gz_api_err_set(err, "no_wallet", NULL, NULL); status = 409; break; }
        if (strcmp(p->s, "cautious") != 0 && strcmp(p->s, "everyday") != 0 && strcmp(p->s, "wide") != 0) {
            gz_api_err_set(err, "bad_value", "/preset", NULL);
            status = 400;
            break;
        }
        if (strcmp(fd->s, "browse") != 0) {           /* tell_me and join_for_me are 1.0.0 (12.3) */
            gz_api_err_set(err, "bad_value", "/find", "{\"allowed\":[\"browse\"]}");
            status = 400;
            break;
        }
        f->setup_ready = 1;
        snprintf(f->cond_preset, sizeof f->cond_preset, "%s", p->s);
        gz_jw_obj(w);
        gz_jw_kstr(w, "state", "ready");
        gz_jw_end_obj(w);
        break;
    }
    case GZ_API_C_BACKUP_GET: {
        int left = 3;
        for (i = 0; i < 3; i++)
            if (f->check_times[i] && c->now - f->check_times[i] < 86400) left--;
        gz_jw_obj(w);
        gz_jw_key(w, "words");                          /* S1: the words part only (12.5) */
        gz_jw_obj(w);
        if (f->words_checked_at) gz_jw_kint(w, "checked_at", f->words_checked_at);
        else gz_jw_knull(w, "checked_at");
        gz_jw_kint(w, "checks_left_today", left);
        gz_jw_end_obj(w);
        gz_jw_end_obj(w);
        break;
    }
    case GZ_API_C_CONDITIONS_GET:
        conditions(w, f);
        break;
    case GZ_API_C_CONDITIONS_PREVIEW:
    case GZ_API_C_CONDITIONS_PUT: {
        const char *names[12];
        const gz_json *cond = gz_json_get(b, "conditions");
        int n = examine(f, cond, names, err);
        if (n < 0) { status = strcmp(err->code, "below_floor") == 0 ? 409 : 400; break; }
        if (c->id == GZ_API_C_CONDITIONS_PREVIEW) {
            int64_t fee = jint(cond, "max_joining_fee_sat", f->cond_max_joining_fee_sat);
            gz_jw_obj(w);
            gz_jw_key(w, "fit_summary");
            gz_jw_obj(w);
            gz_jw_kint(w, "listed", 2);
            gz_jw_kint(w, "fit", fee >= 5000 ? 2 : fee >= 1500 ? 1 : 0);
            gz_jw_kint(w, "fits_only_now", 0);
            gz_jw_knull(w, "excluded_most_by");
            gz_jw_end_obj(w);
            gz_jw_key(w, "would_leave");
            gz_jw_arr(w);
            if (f->joined && !f->left && fee < 1500)
                gz_jw_raw(w, "{\"lobby_id\":\"lob_7k2q\",\"failures\":[{\"condition\":\"max_joining_fee_sat\","
                             "\"yours\":1000,\"offered\":1500}]}");
            gz_jw_end_arr(w);
            gz_jw_key(w, "loosens");
            gz_jw_arr(w);
            for (i = 0; i < n; i++) gz_jw_str(w, names[i]);
            gz_jw_end_arr(w);
            gz_jw_kraw(w, "problems", "[]");
            gz_jw_end_obj(w);
            break;
        }
        if (f->story && f->m_stage == MS_SIGNING) {       /* not during the seconds of signing (13.1) */
            gz_api_err_set(err, "signing_now", NULL, NULL);
            status = 409;
            break;
        }
        if (jint(b, "based_on_version", -1) != f->cond_version) {
            gz_api_err_set(err, "changed_elsewhere", "/based_on_version", "{\"version\":%lld}", (long long)f->cond_version);
            status = 409;
            break;
        }
        if (n > 0) {                                    /* loosening: kind B, with the exact list (4.8) */
            const gz_json *cl = gz_json_get(b, "confirm_loosens"), *e;
            int match = cl != NULL && (int)cl->len == n;
            if (!c->fresh) { gz_api_err_set(err, "fresh_sign_in_needed", NULL, NULL); status = 403; break; }
            for (i = 0; match && i < n; i++) {
                int seen = 0;
                for (e = cl->child; e; e = e->next)
                    if (e->type == GZ_JSON_STR && strcmp(e->s, names[i]) == 0) seen = 1;
                if (!seen) match = 0;
            }
            if (!match) {
                char list[256];
                size_t o = 0;
                list[0] = 0;
                for (i = 0; i < n && o < sizeof list - 40; i++)
                    o += (size_t)snprintf(list + o, sizeof list - o, "%s\"%s\"", i ? "," : "", names[i]);
                gz_api_err_set(err, "confirm_mismatch", "/confirm_loosens", "{\"expected\":[%s]}", list);
                status = 409;
                break;
            }
        }
        {
            int left_now = 0;
            int64_t fee = jint(cond, "max_joining_fee_sat", f->cond_max_joining_fee_sat);
            apply_cond(f, cond);
            f->cond_version++;
            snprintf(f->cond_preset, sizeof f->cond_preset, "custom");
            if (f->joined && !f->left && fee < 1500) {   /* tightening leaves a lobby that no longer fits (13.2) */
                f->left = 1;
                f->joined = 0;
                left_now = 1;
            }
            conditions(w, f);
            /* the GET answer plus left_lobbies: reopen the object */
            if (w->len && w->buf[w->len - 1] == '}') {
                w->len--;
                w->depth = 1;
                w->count[0] = 1;
                gz_jw_key(w, "left_lobbies");
                gz_jw_arr(w);
                if (left_now) gz_jw_str(w, LOBBY_ID);
                gz_jw_end_arr(w);
                gz_jw_end_obj(w);
            }
            if (f->srv) gz_api_notify(f->srv, "conditions", NULL);
        }
        break;
    }
    case GZ_API_C_DISCOVERY_QUERY: {
        const char *h = gz_json_get(b, "host")->s;
        size_t n = strlen(h), k;
        int ok = n >= 66;
        for (k = 0; ok && k < 66; k++)
            if (!((h[k] >= '0' && h[k] <= '9') || (h[k] >= 'a' && h[k] <= 'f'))) ok = 0;
        if (ok && n > 66 && h[66] != '@') ok = 0;
        if (!ok) { gz_api_err_set(err, "bad_host_address", "/host", NULL); status = 400; break; }
        if (f->query_last_at && c->now - f->query_last_at < 10) {   /* once per 10 s per host (21) */
            gz_api_err_set(err, "rate_limited", NULL, "{\"retry_after_s\":%lld}", (long long)(10 - (c->now - f->query_last_at)));
            status = 429;
            break;
        }
        f->query_last_at = c->now;
        f->query_no++;
        gz_jw_obj(w);
        {
            char q[32];
            snprintf(q, sizeof q, "q_%lld", (long long)f->query_no);
            gz_jw_kstr(w, "query_id", q);
            gz_jw_kstr(w, "state", "asking");
            if (f->srv) gz_api_notify(f->srv, "discovery", q);
        }
        gz_jw_end_obj(w);
        status = 202;
        break;
    }
    case GZ_API_C_DISCOVERY_QUERY_GET: {
        char q[32];
        snprintf(q, sizeof q, "q_%lld", (long long)f->query_no);
        if (!f->query_no || strcmp(c->path_id, q) != 0) { status = not_found(err); break; }
        gz_jw_obj(w);
        gz_jw_kstr(w, "query_id", q);
        gz_jw_kstr(w, "state", "answered");
        gz_jw_kraw(w, "lobbies", "[\"lob_7k2q\",\"lob_b19d\"]");
        gz_jw_knull(w, "failed_because");
        gz_jw_kint(w, "asked_at", f->query_last_at);
        gz_jw_kint(w, "answered_at", f->query_last_at);
        gz_jw_end_obj(w);
        break;
    }
    case GZ_API_C_CONNECTIONS_GET:
        gz_jw_obj(w);
        gz_jw_kint(w, "version", 3);
        gz_jw_kraw(w, "chain", "{\"mode\":\"public\",\"servers\":["
                               "{\"id\":\"s1\",\"name\":\"signet-a.example\",\"operator\":\"Operator A\",\"protocol\":\"http\","
                               "\"state\":\"ok\",\"height\":330437,\"checked_at\":1794434280},"
                               "{\"id\":\"s2\",\"name\":\"signet-b.example\",\"operator\":\"Operator B\",\"protocol\":\"http\","
                               "\"state\":\"ok\",\"height\":330437,\"checked_at\":1794434280}],"
                               "\"own_server\":null,\"own_node\":null}");
        gz_jw_kraw(w, "listings", "{\"nostr\":{\"on\":false},\"relays\":[]}");
        gz_jw_key(w, "hosts");
        gz_jw_arr(w);
        if (f->query_no) gz_jw_raw(w, "{\"key\":\"" HOST_KEY "\",\"address\":\"tomato.example:9735\",\"source\":\"added\"}");
        gz_jw_end_arr(w);
        gz_jw_kraw(w, "privacy", "{\"route\":\"direct\"}");
        gz_jw_end_obj(w);
        break;
    case GZ_API_C_LOBBIES: {
        int only_fits = 0;
        for (i = 0; i < c->nquery; i++)
            if (strcmp(c->query_name[i], "show") == 0 && strcmp(c->query_value[i], "fits") == 0) only_fits = 1;
        gz_jw_obj(w);
        gz_jw_key(w, "items");
        gz_jw_arr(w);
        lobby(w, f, LOBBY_ID, 1);
        if (!only_fits || fits(f, 5000)) lobby(w, f, LOBBY2_ID, 1);
        gz_jw_end_arr(w);
        gz_jw_knull(w, "next_cursor");
        gz_jw_kraw(w, "as_of", "{\"height\":330437,\"at\":1794434400}");
        gz_jw_end_obj(w);
        break;
    }
    case GZ_API_C_LOBBY:
        if (strcmp(c->path_id, LOBBY_ID) != 0 && strcmp(c->path_id, LOBBY2_ID) != 0) { status = not_found(err); break; }
        lobby(w, f, c->path_id, 0);
        break;
    case GZ_API_C_JOIN: {
        char dg[65];
        int first = strcmp(c->path_id, LOBBY_ID) == 0;
        if (!first && strcmp(c->path_id, LOBBY2_ID) != 0) { status = not_found(err); break; }
        if (f->pause_on) { gz_api_err_set(err, "paused", NULL, NULL); status = 409; break; }
        if (f->story && first && f->m_stage != MS_OPEN) { gz_api_err_set(err, "not_open", NULL, NULL); status = 409; break; }
        if (f->story ? (first ? f->joined : f->joined2) : f->joined) { gz_api_err_set(err, "already_in_lobby", NULL, "{\"lobby_id\":\"" LOBBY_ID "\"}"); status = 409; break; }
        if (f->chain_state != GZ_API_CHAIN_AGREE && f->chain_state != GZ_API_CHAIN_LAGGING) {
            gz_api_err_set(err, "chain_in_doubt", NULL, NULL);
            status = 409;
            break;
        }
        if (f->story && f->join_list_fail) {             /* a refusal on a list and a range, with both values */
            f->join_list_fail = 0;
            gz_api_err_set(err, "conditions_not_met", NULL, "{\"failures\":%s}", LIST_FAILURES);
            status = 409;
            break;
        }
        if (!fits(f, first ? 1500 : 5000)) {           /* a refusal carries both numbers (8) */
            gz_api_err_set(err, "conditions_not_met", NULL,
                           "{\"failures\":[{\"condition\":\"max_joining_fee_sat\",\"yours\":%lld,\"offered\":%d}]}",
                           (long long)f->cond_max_joining_fee_sat, first ? 1500 : 5000);
            status = 409;
            break;
        }
        if (strcmp(gz_json_get(b, "seen_current_digest")->s, digest_of(c->path_id, dg)) != 0) {
            gz_api_err_set(err, "terms_changed", "/seen_current_digest", "{\"current_version\":3}");
            status = 409;
            break;
        }
        {
            const gz_json *rd = gz_json_get(b, "ready");
            if (f->story && !first) {
                f->joined2 = 1;
                f->left2 = 0;
                f->ready2 = rd && rd->i;
            } else {
                f->joined = 1;
                f->left = 0;
                f->ready = rd && rd->i;
                f->m_stage = MS_OPEN;
                f->m_round = 0;
                f->m_outcome = MO_NONE;
            }
        }
        f->joining_answer = f->story && !first ? 2 : 1;                          /* the answer says "joining"; the host's answer is an event */
        lobby(w, f, c->path_id, 0);
        f->joining_answer = 0;
        status = 202;
        if (f->srv) gz_api_notify(f->srv, "lobby", c->path_id);
        if (f->srv) gz_api_notify(f->srv, "status", NULL);
        break;
    }
    case GZ_API_C_READY: {
        char dg[65];
        int second = f->story && strcmp(c->path_id, LOBBY2_ID) == 0;
        if (!second && strcmp(c->path_id, LOBBY_ID) != 0) { status = not_found(err); break; }
        if (!(second ? f->joined2 : f->joined)) { gz_api_err_set(err, "not_joined", NULL, NULL); status = 409; break; }
        if (f->story && !second && f->m_stage >= MS_SIGNING) { gz_api_err_set(err, "too_late", NULL, NULL); status = 409; break; }
        if (f->pause_on && gz_json_get(b, "ready")->i) { gz_api_err_set(err, "paused", NULL, NULL); status = 409; break; }
        if (strcmp(gz_json_get(b, "seen_current_digest")->s, digest_of(c->path_id, dg)) != 0) {
            gz_api_err_set(err, "terms_changed", "/seen_current_digest", "{\"current_version\":3}");
            status = 409;
            break;
        }
        if (second) f->ready2 = (int)gz_json_get(b, "ready")->i;
        else f->ready = (int)gz_json_get(b, "ready")->i;
        lobby(w, f, c->path_id, 0);
        status = 202;
        if (f->srv) gz_api_notify(f->srv, "lobby", c->path_id);
        if (f->story && f->srv) gz_api_notify(f->srv, "status", NULL);
        break;
    }
    case GZ_API_C_LEAVE: {
        int second = f->story && strcmp(c->path_id, LOBBY2_ID) == 0;
        if (!second && strcmp(c->path_id, LOBBY_ID) != 0) { status = not_found(err); break; }
        if (!(second ? f->joined2 : f->joined)) { gz_api_err_set(err, "not_joined", NULL, NULL); status = 409; break; }
        if (f->partials_out || (f->story && !second && (f->m_round == 3 || f->m_round == 5))) {
            gz_api_err_set(err, "too_late", NULL, "{\"round\":{\"state\":\"signed\"}}");
            status = 409;
            break;
        }
        if (second) {
            f->joined2 = 0;
            f->ready2 = 0;
            f->left2 = 1;
        } else {
            f->joined = 0;
            f->ready = 0;
            f->left = 1;
            f->m_stage = MS_OPEN;
            f->m_round = 0;
            f->m_outcome = MO_NONE;
        }
        lobby(w, f, c->path_id, 0);
        status = 202;
        if (f->srv) gz_api_notify(f->srv, "lobby", c->path_id);
        if (f->story && f->srv) gz_api_notify(f->srv, "status", NULL);
        break;
    }
    case GZ_API_C_HOST_PREVIEW:
    case GZ_API_C_HOST_OPEN: {
        const gz_json *d = c->id == GZ_API_C_HOST_PREVIEW ? b : gz_json_get(b, "draft");
        char dg[65];
        preview p;
        do_preview(f, d, c->now, &p);
        draft_digest(d, dg);
        if (c->id == GZ_API_C_HOST_OPEN) {
            int64_t echo = jint(b, "confirm_funding_sat", -1);
            if (strcmp(gz_json_get(b, "draft_digest")->s, dg) != 0) {
                gz_api_err_set(err, "draft_changed", "/draft_digest", NULL);
                status = 409;
                break;
            }
            if (p.ncannot) {
                gz_api_err_set(err, p.cannot[0], NULL, NULL);
                status = 409;
                break;
            }
            if (echo != p.at_target) {                  /* the echo of what the preview showed (4.8) */
                gz_api_err_set(err, "confirm_mismatch", "/confirm_funding_sat",
                               "{\"expected\":%lld,\"got\":%lld}", (long long)p.at_target, (long long)echo);
                status = 409;
                break;
            }
            if (c->phase == GZ_API_PHASE_CHECK) { status = 0; break; }   /* go on to the passphrase */
            f->host_open = 1;
            f->host_cancelled = 0;
            f->host_seat_removed = 0;
            f->set_aside_sat = p.at_target;
            if (f->story) story_host_opened(f, d);
            host_lobby(w, f);
            status = 201;
            if (f->srv) gz_api_notify(f->srv, "host_lobby", HOST_LOBBY_ID);
            if (f->srv) gz_api_notify(f->srv, "status", NULL);
            break;
        }
        gz_jw_obj(w);
        gz_jw_kstr(w, "draft_digest", dg);
        gz_jw_key(w, "as_members_see_it");
        terms(w, "draft", 500, 1000, 1500, 0, f->story ? jint(d, "target", 50) : 50, f->story ? jint(d, "minimum", 30) : 30,
              f->story ? jint(d, "channel_sat", 500000) : 500000);
        gz_jw_kint(w, "funding_at_minimum_sat", p.at_min);
        gz_jw_kint(w, "funding_at_target_sat", p.at_target);
        gz_jw_kint(w, "chain_fee_estimate_sat", 1000);
        gz_jw_kint(w, "wallet_free_sat", free_sat(f));
        gz_jw_kint(w, "set_aside_elsewhere_sat", f->set_aside_sat);
        gz_jw_key(w, "covers");
        gz_jw_obj(w);
        gz_jw_kbool(w, "minimum", p.at_min <= free_sat(f));
        gz_jw_kbool(w, "target", p.at_target <= free_sat(f));
        gz_jw_end_obj(w);
        gz_jw_key(w, "dates");
        gz_jw_arr(w);
        date(w, "lobby_starts_by", TIP + 15, "lobby_applies_start_rule", "signed_term", "term_start_plus_life");
        date(w, "factory_ends", TIP + 4752, "factory_end_rule_applies", "signed_term", "term_start_plus_life");
        gz_jw_end_arr(w);
        gz_jw_key(w, "host_deadlines");
        gz_jw_arr(w);
        date(w, "host_fund_by", TIP + 30, "lobby_cancelled", "worked_out", "signing_budget_from_sent");
        gz_jw_end_arr(w);
        gz_jw_key(w, "problems");
        gz_jw_arr(w);
        for (i = 0; i < p.nproblems; i++) {
            gz_jw_obj(w);
            gz_jw_kstr(w, "field", p.problems[i][0]);
            gz_jw_kstr(w, "code", p.problems[i][1]);
            gz_jw_end_obj(w);
        }
        gz_jw_end_arr(w);
        gz_jw_kbool(w, "can_open", p.ncannot == 0);
        gz_jw_key(w, "cannot_open_because");
        gz_jw_arr(w);
        for (i = 0; i < p.ncannot; i++) gz_jw_str(w, p.cannot[i]);
        gz_jw_end_arr(w);
        gz_jw_end_obj(w);
        break;
    }
    case GZ_API_C_HOST_LOBBIES:
        gz_jw_obj(w);
        gz_jw_key(w, "items");
        gz_jw_arr(w);
        if (f->host_open) host_lobby(w, f);
        gz_jw_end_arr(w);
        gz_jw_knull(w, "next_cursor");
        gz_jw_kraw(w, "as_of", "{\"height\":330437,\"at\":1794434400}");
        gz_jw_end_obj(w);
        break;
    case GZ_API_C_HOST_LOBBY:
        if (!f->host_open || strcmp(c->path_id, HOST_LOBBY_ID) != 0) {
            if (strcmp(c->path_id, LOBBY_ID) == 0) { gz_api_err_set(err, "not_host", NULL, NULL); status = 403; break; }
            status = not_found(err);
            break;
        }
        host_lobby(w, f);
        break;
    case GZ_API_C_HOST_START:
        if (!f->host_open || strcmp(c->path_id, HOST_LOBBY_ID) != 0) { status = not_found(err); break; }
        if (f->host_cancelled || (f->story && f->h_stage != MS_OPEN)) { gz_api_err_set(err, "not_open", NULL, NULL); status = 409; break; }
        if (jint(b, "confirm_funding_max_sat", -1) != f->set_aside_sat) {
            gz_api_err_set(err, "confirm_mismatch", "/confirm_funding_max_sat", "{\"expected\":%lld,\"got\":%lld}",
                           (long long)f->set_aside_sat, (long long)jint(b, "confirm_funding_max_sat", -1));
            status = 409;
            break;
        }
        if (f->pause_on) { gz_api_err_set(err, "paused", NULL, NULL); status = 409; break; }
        if (f->story && f->h_ready >= f->h_minimum) {     /* an early start (15.2) */
            f->h_stage = MS_READY_CHECK;
            host_lobby(w, f);
            status = 202;
            if (f->srv) gz_api_notify(f->srv, "host_lobby", HOST_LOBBY_ID);
            if (f->srv) gz_api_notify(f->srv, "status", NULL);
            break;
        }
        if (f->story)
            gz_api_err_set(err, "below_minimum", NULL, "{\"ready\":%d,\"minimum\":%lld}", f->h_ready, (long long)f->h_minimum);
        else
            gz_api_err_set(err, "below_minimum", NULL, "{\"ready\":%d,\"minimum\":30}", f->host_seat_removed ? 0 : 1);
        status = 409;
        break;
    case GZ_API_C_HOST_CANCEL:
        if (!f->host_open || strcmp(c->path_id, HOST_LOBBY_ID) != 0) { status = not_found(err); break; }
        if (f->partials_out || (f->story && f->h_stage >= MS_SIGNING)) { gz_api_err_set(err, "too_late", NULL, NULL); status = 409; break; }
        f->host_cancelled = 1;
        f->set_aside_sat = 0;
        host_lobby(w, f);
        status = 202;
        if (f->srv) gz_api_notify(f->srv, "host_lobby", HOST_LOBBY_ID);
        if (f->story && f->srv) gz_api_notify(f->srv, "status", NULL);
        break;
    case GZ_API_C_HOST_SEAT_REMOVE:
        if (f->story) {
            if (!f->host_open || f->host_cancelled || strcmp(c->path_id, HOST_LOBBY_ID) != 0 || f->h_ready < 1) {
                status = not_found(err);
                break;
            }
            if (strcmp(gz_json_get(b, "confirm_seat")->s, c->path_id2) != 0) {
                gz_api_err_set(err, "confirm_mismatch", "/confirm_seat", "{\"expected\":\"%s\"}", c->path_id2);
                status = 409;
                break;
            }
            if (f->h_stage != MS_OPEN) { gz_api_err_set(err, "frozen", NULL, NULL); status = 409; break; }
            f->h_ready--;
            host_lobby(w, f);
            status = 202;
            if (f->srv) gz_api_notify(f->srv, "host_lobby", HOST_LOBBY_ID);
            break;
        }
        if (!f->host_open || strcmp(c->path_id, HOST_LOBBY_ID) != 0 || f->host_seat_removed ||
            strcmp(c->path_id2, SEAT_ID) != 0) {
            status = not_found(err);
            break;
        }
        if (strcmp(gz_json_get(b, "confirm_seat")->s, c->path_id2) != 0) {
            gz_api_err_set(err, "confirm_mismatch", "/confirm_seat", "{\"expected\":\"%s\"}", c->path_id2);
            status = 409;
            break;
        }
        f->host_seat_removed = 1;
        host_lobby(w, f);
        status = 202;
        break;
    case GZ_API_C_FACTORIES:
        gz_jw_obj(w);
        gz_jw_key(w, "items");
        gz_jw_arr(w);
        if (f->story) {
            if (f->h_stage == MS_FUNDING || f->h_stage == MS_ACTIVE) story_factory(w, f, 1, 1);
            if (f->m_stage == MS_FUNDING || f->m_stage == MS_ACTIVE) story_factory(w, f, 1, 0);
        } else if (f->has_factory) {
            factory(w, f, 1);
        }
        gz_jw_end_arr(w);
        gz_jw_knull(w, "next_cursor");
        gz_jw_kraw(w, "as_of", "{\"height\":330437,\"at\":1794434400}");
        gz_jw_end_obj(w);
        break;
    case GZ_API_C_FACTORY:
    case GZ_API_C_FACTORY_DATES: {
        int host = f->story && strcmp(c->path_id, HOST_FACTORY_ID) == 0 && (f->h_stage == MS_FUNDING || f->h_stage == MS_ACTIVE);
        int mine = strcmp(c->path_id, FACTORY_ID) == 0 &&
                   (f->story ? f->m_stage == MS_FUNDING || f->m_stage == MS_ACTIVE : f->has_factory);
        int live = f->story && (host ? f->h_stage : f->m_stage) == MS_ACTIVE;
        if (!host && !mine) { status = not_found(err); break; }
        if (c->id == GZ_API_C_FACTORY) {
            if (f->story) story_factory(w, f, 0, host);
            else factory(w, f, 0);
            break;
        }
        gz_jw_obj(w);
        gz_jw_key(w, "dates");
        gz_jw_arr(w);
        if (!live) date(w, "funding_deadline", TIP + 144, "round_abandoned", "worked_out", "ack_height_plus_deadline");
        date(w, "factory_ends", TIP + 4752, "factory_end_rule_applies", "signed_term", "term_start_plus_life");
        gz_jw_end_arr(w);
        gz_jw_end_obj(w);
        break;
    }
    case GZ_API_C_WALLET:
        gz_jw_obj(w);
        gz_jw_kint(w, "free_sat", free_sat(f));
        gz_jw_kint(w, "unconfirmed_sat", 0);
        gz_jw_kint(w, "set_aside_sat", f->set_aside_sat);
        gz_jw_key(w, "set_aside_for");
        gz_jw_arr(w);
        if (f->set_aside_sat) {
            gz_jw_obj(w);
            gz_jw_kstr(w, "lobby_id", HOST_LOBBY_ID);
            gz_jw_kint(w, "amount_sat", f->set_aside_sat);
            gz_jw_end_obj(w);
        }
        gz_jw_end_arr(w);
        gz_jw_kraw(w, "coins", "[{\"txid\":\"4e2a9c1b7d5f3e6a8b0c2d4e6f8a0b1c3d5e7f9a1b3c5d7e9f0a2b4c6d8e0f1a\","
                               "\"vout\":1,\"amount_sat\":42000000,\"confirmations\":12,\"received_at\":1794430000,"
                               "\"held_for\":null}]");
        gz_jw_kint(w, "as_of_height", TIP);
        gz_jw_kstr(w, "chain_view", f->chain_state <= GZ_API_CHAIN_LAGGING ? "trusted" : "in_doubt");
        gz_jw_end_obj(w);
        break;
    case GZ_API_C_WALLET_ADDRESS: {
        /* TEST ONLY: not a real address (no valid checksum); a new one each time */
        char a[80];
        f->address_no++;
        snprintf(a, sizeof a, "tb1pfake%056lld", (long long)f->address_no);
        gz_jw_obj(w);
        gz_jw_kstr(w, "address", a);
        gz_jw_end_obj(w);
        break;
    }
    case GZ_API_C_ACTIVITY:
        gz_jw_obj(w);
        gz_jw_key(w, "items");
        gz_jw_arr(w);
        if (f->story) story_activity(w, f);
        gz_jw_raw(w, "{\"id\":\"act_1182\",\"at\":1794426000,\"kind\":\"refused\",\"lobby_id\":\"lob_b19d\","
                     "\"factory_id\":null,\"who_decided\":\"the_app\","
                     "\"rule\":{\"code\":\"my_conditions\",\"params\":{\"conditions_version\":7}},"
                     "\"params\":{\"failures\":[{\"condition\":\"max_joining_fee_sat\",\"yours\":2000,\"offered\":5000}],"
                     "\"nothing_signed\":true}}");
        gz_jw_raw(w, "{\"id\":\"act_1001\",\"at\":1794420000,\"kind\":\"wallet_created\",\"lobby_id\":null,"
                     "\"factory_id\":null,\"who_decided\":\"you\",\"rule\":null,\"params\":{}}");
        gz_jw_end_arr(w);
        gz_jw_knull(w, "next_cursor");
        gz_jw_kraw(w, "as_of", "{\"height\":330437,\"at\":1794434400}");
        gz_jw_end_obj(w);
        break;
    case GZ_API_C_ACTIVITY_ONE: {
        /* the story adds two entries with saved copies: the refusal at the check, and the join */
        int at_check = f->story && strcmp(c->path_id, "act_2001") == 0 && f->m_outcome == MO_REFUSED;
        int join = f->story && strcmp(c->path_id, "act_2002") == 0;
        int now_lobby = at_check || join;
        if (!now_lobby && strcmp(c->path_id, "act_1182") != 0) { status = not_found(err); break; }
        gz_jw_obj(w);
        gz_jw_kstr(w, "id", c->path_id);
        gz_jw_kint(w, "at", now_lobby ? 1794434400 : 1794426000);
        gz_jw_kstr(w, "kind", join ? "joined" : "refused");
        gz_jw_kstr(w, "lobby_id", now_lobby ? LOBBY_ID : LOBBY2_ID);
        gz_jw_knull(w, "factory_id");
        gz_jw_kstr(w, "who_decided", join ? "you" : "the_app");
        if (join) gz_jw_kraw(w, "rule", "{\"code\":\"joining_was_consent\",\"params\":{}}");
        else gz_jw_kraw(w, "rule", "{\"code\":\"my_conditions\",\"params\":{\"conditions_version\":7}}");
        if (join) {
            gz_jw_kraw(w, "params", "{}");
        } else if (at_check) {
            gz_jw_key(w, "params");
            gz_jw_obj(w);
            char fl[400];
            refusal_failures(f, fl, sizeof fl);
            gz_jw_kraw(w, "failures", fl);
            gz_jw_kbool(w, "nothing_signed", 1);
            gz_jw_end_obj(w);
        } else {
            gz_jw_kraw(w, "params", "{\"failures\":[{\"condition\":\"max_joining_fee_sat\",\"yours\":2000,\"offered\":5000}],"
                                    "\"nothing_signed\":true}");
        }
        gz_jw_key(w, "saved_copy");
        gz_jw_obj(w);
        gz_jw_kint(w, "saved_at", now_lobby ? 1794434400 : 1794426000);
        gz_jw_key(w, "terms");
        if (now_lobby) terms(w, LOBBY_ID, 500, 1000, 1500, 1, 50, 30, 500000);
        else terms(w, LOBBY2_ID, 3000, 4000, 5000, 1, 50, 30, 500000);
        gz_jw_key(w, "fit");
        if (now_lobby) fit(w, f, 500, 1000, 1500);
        else fit(w, f, 3000, 4000, 5000);
        gz_jw_kraw(w, "conditions", "{\"max_joining_fee_sat\":2000,\"min_members\":20}");
        gz_jw_end_obj(w);
        gz_jw_end_obj(w);
        break;
    }
    case GZ_API_C_PAUSE: {
        int on = (int)gz_json_get(b, "on")->i;
        int left_lobby = 0;
        if (on && !f->pause_on) {
            f->pause_on = 1;
            f->pause_since = c->now;
            if (f->joined && !f->partials_out && !(f->story && f->m_stage >= MS_SIGNING)) {
                f->joined = 0;
                f->ready = 0;
                f->left = 1;
                left_lobby = 1;
                f->m_stage = MS_OPEN;
            }
            if (f->joined2) { f->joined2 = 0; f->ready2 = 0; f->left2 = 1; }
        } else if (!on) {
            f->pause_on = 0;
            f->pause_since = 0;
        }
        gz_jw_obj(w);
        gz_jw_key(w, "pause");
        gz_jw_obj(w);
        gz_jw_kstr(w, "state", f->pause_on ? (f->partials_out ? "held_for_signing" : "on") : "off");
        if (f->pause_since) gz_jw_kint(w, "since_at", f->pause_since);
        else gz_jw_knull(w, "since_at");
        if (f->pause_on && f->partials_out) gz_jw_kstr(w, "lobby_id", LOBBY_ID);
        else gz_jw_knull(w, "lobby_id");
        gz_jw_end_obj(w);
        gz_jw_key(w, "left_lobbies");
        gz_jw_arr(w);
        if (left_lobby) gz_jw_str(w, LOBBY_ID);
        gz_jw_end_arr(w);
        gz_jw_kraw(w, "aborted_lobbies", "[]");
        if (f->pause_on && f->partials_out) gz_jw_kstr(w, "held_lobby", LOBBY_ID);
        else gz_jw_knull(w, "held_lobby");
        gz_jw_end_obj(w);
        status = f->pause_on && f->partials_out ? 202 : 200;
        if (f->srv) gz_api_notify(f->srv, "status", NULL);
        break;
    }
    case GZ_API_C_LOCK: {
        const char *cf = gz_json_get(b, "confirm")->s;
        const gz_json *cl = gz_json_get(b, "confirm_locked");
        if (strcmp(cf, "lock_wallet") != 0) {
            gz_api_err_set(err, "confirm_mismatch", "/confirm", "{\"expected\":\"lock_wallet\"}");
            status = 409;
            break;
        }
        if (f->host_open && !f->host_cancelled) {    /* cancel it first (4.7, D20) */
            gz_api_err_set(err, "hosting_lobby_open", NULL, "{\"lobby_id\":\"" HOST_LOBBY_ID "\"}");
            status = 409;
            break;
        }
        if (watching(f)) {                            /* something needs watching: like going offline */
            if (!c->fresh) { gz_api_err_set(err, "fresh_sign_in_needed", NULL, NULL); status = 403; break; }
            if (!cl || cl->type != GZ_JSON_STR || strcmp(cl->s, "nobody_watching") != 0) {
                gz_api_err_set(err, "confirm_mismatch", "/confirm_locked", "{\"expected\":\"nobody_watching\"}");
                status = 409;
                break;
            }
            if (gz_json_get(b, "confirm_unlock_by_height")) {   /* unlock_by is null in Slice 1 */
                gz_api_err_set(err, "confirm_mismatch", "/confirm_unlock_by_height", "{\"expected\":null}");
                status = 409;
                break;
            }
        }
        gz_jw_obj(w);
        if (f->partials_out) {                        /* held, not refused; sessions stay valid (4.7) */
            gz_jw_key(w, "lock");
            gz_jw_obj(w);
            gz_jw_kstr(w, "state", "held_for_signing");
            gz_jw_kstr(w, "lobby_id", LOBBY_ID);
            gz_jw_end_obj(w);
        } else {
            gz_jw_kstr(w, "wallet", "locked");
            f->wallet = GZ_API_WALLET_LOCKED;
            *effect = GZ_API_EFFECT_LOCKED;
        }
        gz_jw_end_obj(w);
        status = 202;
        break;
    }
    default:
        gz_api_err_set(err, "internal", NULL, "{\"ref\":\"fake\"}");
        status = 500;
    }
    pthread_mutex_unlock(&f->mu);
    return status;
}

/* ---- the engine's part of acting calls (contract-v2 11) -------------------------------- */
/* TEST ONLY, the shape S11's engine takes: request ids are the engine's (the
 * 409 and the replay, from memory here, from the journal in the program); an
 * acting call is answered once its save is confirmed, so the fake can hold it
 * (f->hold) until gz_fake_release, as a slow storage would. */
struct gz_fake_rid {
    char id[65], method[8], path[1024], pattern[96];
    uint8_t digest[32];
    int status;
    char *answer;                     /* the first answer (a JSON object) */
    int pending;                      /* held: its save not yet confirmed */
    uint64_t handle;                  /* the first call's handle while pending */
    uint64_t waiters[8];              /* retries held for the same outcome */
    int nwait;
};

struct gz_fake_held {
    uint64_t handle;
    int status;
    char *answer;
    struct gz_fake_rid *rid;
};

static struct gz_fake_rid *rid_find(gz_fake *f, const char *id)
{
    int i;
    for (i = 0; i < f->nrids; i++)
        if (strcmp(f->rids[i]->id, id) == 0) return f->rids[i];
    return NULL;
}

/* answer + "replayed": true (7.4) */
static void replayed(gz_jw *w, const char *answer)
{
    size_t n = strlen(answer);
    if (n >= 2 && answer[n - 1] == '}') {
        gz_jw_bytes(w, answer, n - 1);
        if (n > 2) gz_jw_bytes(w, ",", 1);
        gz_jw_bytes(w, "\"replayed\":true}", 16);
    } else {
        gz_jw_bytes(w, "{\"replayed\":true}", 17);
    }
}

static char *replayed_copy(const char *answer)
{
    gz_jw w;
    char *s;
    gz_jw_init(&w);
    replayed(&w, answer);
    s = w.err ? NULL : strdup(w.buf);
    gz_jw_free(&w);
    return s;
}

static int call(void *be, const gz_api_call *c, gz_jw *w, gz_api_error *err, int *effect)
{
    gz_fake *f = be;
    int status;
    if (c->request_id && c->digest) {
        struct gz_fake_rid *e;
        pthread_mutex_lock(&f->mu);
        e = rid_find(f, c->request_id);
        if (e) {
            int same = strcmp(e->method, c->method) == 0 && strcmp(e->path, c->path) == 0 &&
                       CRYPTO_memcmp(e->digest, c->digest, 32) == 0;
            if (!same) {
                gz_api_err_set(err, "request_id_reused", NULL, "{\"first\":{\"method\":\"%s\",\"path\":\"%s\"}}",
                               e->method, e->pattern);
                pthread_mutex_unlock(&f->mu);
                return 409;
            }
            if (e->pending) {
                /* the first is alive and unconfirmed: this retry waits for the same outcome */
                if (c->phase == GZ_API_PHASE_CHECK) { pthread_mutex_unlock(&f->mu); return 0; }
                if (c->handle && e->nwait < 8) {
                    e->waiters[e->nwait++] = c->handle;
                    pthread_mutex_unlock(&f->mu);
                    return GZ_API_HELD;
                }
                pthread_mutex_unlock(&f->mu);
                gz_api_err_set(err, "rate_limited", NULL, "{\"retry_after_s\":1}");
                return 429;
            }
            replayed(w, e->answer);                     /* acts nothing a second time */
            status = e->status;
            pthread_mutex_unlock(&f->mu);
            return status;
        }
        pthread_mutex_unlock(&f->mu);
    }
    status = call_inner(be, c, w, err, effect);
    if (c->phase == GZ_API_PHASE_CHECK || !c->handle || status < 200 || status > 299 || w->err) return status;
    pthread_mutex_lock(&f->mu);
    f->acted++;
    {
        const char *ans = w->len ? w->buf : "{}";
        struct gz_fake_rid *e = NULL;
        int hold = f->hold && *effect == GZ_API_EFFECT_NONE;   /* a lock's effect is the loop's: never held here */
        if (c->request_id && c->digest) {               /* saved in the action's first batch (7.4) */
            struct gz_fake_rid **grown = realloc(f->rids, (size_t)(f->nrids + 1) * sizeof *grown);
            e = calloc(1, sizeof *e);
            if (grown) f->rids = grown;
            if (grown && e && (e->answer = strdup(ans))) {
                snprintf(e->id, sizeof e->id, "%s", c->request_id);
                snprintf(e->method, sizeof e->method, "%s", c->method);
                snprintf(e->path, sizeof e->path, "%s", c->path);
                snprintf(e->pattern, sizeof e->pattern, "%s", c->pattern);
                memcpy(e->digest, c->digest, 32);
                e->status = status;
                f->rids[f->nrids++] = e;
            } else {
                free(e);
                e = NULL;
            }
        }
        if (hold) {
            struct gz_fake_held **grown = realloc(f->held, (size_t)(f->nheld + 1) * sizeof *grown);
            struct gz_fake_held *h = calloc(1, sizeof *h);
            if (grown) f->held = grown;
            if (grown && h && (h->answer = strdup(ans))) {
                h->handle = c->handle;
                h->status = status;
                h->rid = e;
                if (e) { e->pending = 1; e->handle = c->handle; }
                f->held[f->nheld++] = h;
                pthread_mutex_unlock(&f->mu);
                return GZ_API_HELD;
            }
            free(h);
        }
    }
    pthread_mutex_unlock(&f->mu);
    return status;
}

/* The held saves are confirmed: every held call is answered (and every retry
 * waiting for the same outcome, with "replayed": true). Any thread. */
/* TEST ONLY: one line of the story's script (gz-api-fake reads them from its
 * standard input, and --auto-ms sends "step" by itself). It changes the
 * story's state under the lock and tells the server which areas changed
 * afterwards, as the program's engine would. Any thread. */
int gz_fake_cmd(gz_fake *f, const char *line)
{
    static const char *const CHAIN[] = {"agree", "lagging", "catching_up", "one_source", "disagree", "unreachable",
                                        "offline_by_choice"};
    int rc = 0, n_status = 0, n_lobby = 0, n_host = 0, n_factory = 0, n_chain = 0, n_wallet = 0, release = 0, i;
    pthread_mutex_lock(&f->mu);
    if (strcmp(line, "step") == 0) {
        /* the lobby this wallet joined */
        if (f->m_outcome == MO_UNFINISHED || f->m_outcome == MO_CANCELLED) {
            /* stays as it is */
        } else if (f->m_stage == MS_OPEN && f->joined && f->ready) {
            f->m_stage = MS_READY_CHECK;                 /* the start rule is met */
            n_lobby = 1;
        } else if (f->m_stage == MS_READY_CHECK) {
            f->m_stage = MS_SIGNING;
            f->m_round = 1;
            if (f->m_refuse_next) {                      /* the app's own check fails: it refuses before any nonce */
                f->m_refuse_next = 0;
                f->m_outcome = MO_REFUSED;
                f->m_round = 6;
                f->m_stage = MS_OPEN;
                f->joined = 0;
                f->ready = 0;
                f->left = 1;
            }
            n_lobby = 1;
        } else if (f->m_stage == MS_SIGNING && f->m_round < 3) {
            f->m_round++;
            n_lobby = 1;
        } else if (f->m_stage == MS_SIGNING) {
            f->m_stage = MS_FUNDING;                     /* complete: waiting for the host's funding */
            f->m_round = 4;
            f->m_conf = 0;
            n_lobby = n_factory = 1;
        } else if (f->m_stage == MS_FUNDING) {
            if (++f->m_conf >= 3) {
                f->m_stage = MS_ACTIVE;
                f->m_round = 7;
                f->m_outcome = MO_STARTED;
            }
            n_lobby = n_factory = 1;
        }
        /* the lobby this wallet hosts */
        if (f->host_open && !f->host_cancelled) {
            if (f->h_stage == MS_OPEN && f->h_ready < f->h_target) {
                int more = (int)(f->h_target / 3);
                f->h_ready += more < 1 ? 1 : more;
                if (f->h_ready >= f->h_target) {         /* the target: the ready check runs at once (15.2) */
                    f->h_ready = (int)f->h_target;
                    f->h_stage = MS_READY_CHECK;
                }
                n_host = 1;
            } else if (f->h_stage == MS_READY_CHECK) {
                f->h_stage = MS_SIGNING;
                f->h_round = 1;
                n_host = 1;
            } else if (f->h_stage == MS_SIGNING && f->h_round < 3) {
                f->h_round++;
                n_host = 1;
            } else if (f->h_stage == MS_SIGNING) {
                f->h_stage = MS_FUNDING;                 /* funding last, by itself (owner decision 16a) */
                f->h_round = 4;
                f->h_conf = 0;
                f->h_funded_sat = f->h_ready * f->h_channel * 3 / 2;
                f->set_aside_sat = 0;
                n_host = n_factory = n_wallet = 1;
            } else if (f->h_stage == MS_FUNDING) {
                if (++f->h_conf >= 3) {
                    f->h_stage = MS_ACTIVE;
                    f->h_round = 5;
                }
                n_host = n_factory = 1;
            }
        }
        n_status = n_lobby || n_host;
    } else if (strcmp(line, "member-refuse") == 0) {
        f->m_refuse_next = 1;
        f->m_refuse_kind = 0;
    } else if (strcmp(line, "member-refuse-list") == 0) {
        f->m_refuse_next = 1;
        f->m_refuse_kind = 1;
    } else if (strcmp(line, "member-refuse-safety") == 0) {
        f->m_refuse_next = 1;
        f->m_refuse_kind = 2;
    } else if (strcmp(line, "join-refuse-list") == 0) {
        f->join_list_fail = 1;
    } else if (strcmp(line, "member-unfinished") == 0) {
        if (f->m_stage == MS_SIGNING) {
            f->m_round = 5;
            f->m_outcome = MO_UNFINISHED;
            n_lobby = n_status = 1;
        }
    } else if (strcmp(line, "member-cancel") == 0) {
        if (f->joined && f->m_stage <= MS_READY_CHECK) {
            f->m_stage = MS_CANCELLED;
            f->m_outcome = MO_CANCELLED;
            n_lobby = n_status = 1;
        }
    } else if (strncmp(line, "host-seats ", 11) == 0) {
        if (f->host_open && !f->host_cancelled && f->h_stage == MS_OPEN) {
            int n = atoi(line + 11);
            f->h_ready = n < 0 ? 0 : n > f->h_target ? (int)f->h_target : n;
            if (f->h_ready >= f->h_target) f->h_stage = MS_READY_CHECK;
            n_host = n_status = 1;
        }
    } else if (strcmp(line, "host-leave") == 0) {
        /* a member's own check failed: it left before any signature, and the lobby is Open again */
        if (f->h_stage == MS_READY_CHECK || f->h_stage == MS_SIGNING) {
            f->h_left_seen = 1;
            if (f->h_ready > 0) f->h_ready--;
            f->h_stage = MS_OPEN;
            f->h_round = 0;
            n_host = n_status = 1;
        }
    } else if (strncmp(line, "chain ", 6) == 0) {
        rc = -1;
        for (i = 0; i < GZ_API_CHAIN_STATES; i++)
            if (strcmp(line + 6, CHAIN[i]) == 0) {
                f->chain_state = i;
                n_chain = n_status = 1;
                rc = 0;
            }
    } else if (strcmp(line, "hold on") == 0) {
        f->hold = 1;
        f->hold_forever = 0;
    } else if (strcmp(line, "hold forever") == 0) {
        f->hold = 1;
        f->hold_forever = 1;
    } else if (strcmp(line, "hold off") == 0) {
        f->hold = 0;
        f->hold_forever = 0;
        release = 1;
    } else if (strcmp(line, "release") == 0) {
        f->hold_forever = 0;
        release = 1;
    } else if (strcmp(line, "restore-done") == 0) {
        f->restoring = 0;
        n_wallet = n_status = 1;
    } else if (strcmp(line, "files-behind") == 0) {
        f->files_behind_next = 1;
    } else if (strncmp(line, "pp-delay ", 9) == 0) {
        f->pp_delay_ms = atoi(line + 9);
    } else if (strcmp(line, "fail-derivation") == 0) {
        f->derivation_fails_next = 1;
    } else {
        rc = -1;
    }
    pthread_mutex_unlock(&f->mu);
    if (release) gz_fake_release(f);
    if (f->srv) {
        if (n_lobby) gz_api_notify(f->srv, "lobby", LOBBY_ID);
        if (n_host) gz_api_notify(f->srv, "host_lobby", HOST_LOBBY_ID);
        if (n_factory) gz_api_notify(f->srv, "factory", NULL);
        if (n_chain) gz_api_notify(f->srv, "chain", NULL);
        if (n_wallet) gz_api_notify(f->srv, "wallet", NULL);
        if (n_lobby || n_host) gz_api_notify(f->srv, "activity", NULL);
        if (n_status) gz_api_notify(f->srv, "status", NULL);
    }
    return rc;
}

void gz_fake_release(gz_fake *f)
{
    int i, k, left = 0;
    pthread_mutex_lock(&f->mu);
    for (i = 0; i < f->nheld; i++) {
        struct gz_fake_held *h = f->held[i];
        if (f->hold_forever) { f->held[left++] = h; continue; }
        if (f->srv) gz_api_call_done(f->srv, h->handle, h->status, h->answer, NULL);
        if (h->rid) {
            char *rep = replayed_copy(h->answer);
            h->rid->pending = 0;
            for (k = 0; k < h->rid->nwait; k++)
                if (f->srv) gz_api_call_done(f->srv, h->rid->waiters[k], h->status, rep ? rep : h->answer, NULL);
            h->rid->nwait = 0;
            free(rep);
        }
        free(h->answer);
        free(h);
    }
    f->nheld = left;
    pthread_mutex_unlock(&f->mu);
}

static void engine_free(gz_fake *f)
{
    int i;
    for (i = 0; i < f->nrids; i++) { free(f->rids[i]->answer); free(f->rids[i]); }
    free(f->rids);
    for (i = 0; i < f->nheld; i++) { free(f->held[i]->answer); free(f->held[i]); }
    free(f->held);
    f->rids = NULL;
    f->held = NULL;
    f->nrids = f->nheld = 0;
}

static int status(void *be, gz_api_status_facts *s)
{
    gz_fake *f = be;
    int i;
    pthread_mutex_lock(&f->mu);
    s->network = "signet";
    s->test_coins = 1;
    s->chain_state = f->chain_state;
    s->chain_height = TIP;
    s->servers_agreeing = f->chain_state <= GZ_API_CHAIN_LAGGING ? 2 : 1;
    s->operators = s->servers_agreeing;
    s->chain_since_at = 1794431000;
    s->lag_blocks = 2;
    s->memory_locked = 1;
    s->version = 412;
    switch (f->wallet) {
    case GZ_API_WALLET_NONE: s->wallet = GZ_API_STW_NONE; break;
    case GZ_API_WALLET_LOCKED: s->wallet = GZ_API_STW_LOCKED; break;
    case GZ_API_WALLET_FILES_BEHIND: s->wallet = GZ_API_STW_FILES_BEHIND; s->wallet_reason = "behind"; break;
    default:
        s->wallet = f->restoring ? GZ_API_STW_RESTORING : f->setup_ready ? GZ_API_STW_READY : GZ_API_STW_CREATED_NOT_FINISHED;
    }
    s->pause_state = f->pause_on ? (f->partials_out ? "held_for_signing" : "on") : "off";
    s->pause_since_at = f->pause_since;
    s->pause_lobby_id = f->pause_on && f->partials_out ? LOBBY_ID : NULL;
    s->has_something_to_watch = f->has_factory;
    s->last_check_height = TIP;
    s->last_check_at = 1794434280;
    s->safe_absence_blocks = 2016;
    s->factories_watched = f->has_factory;
    s->open_by_json = NULL;
    s->unlock_by_json = NULL;
    s->on_chain_free_sat = free_sat(f);
    s->set_aside_sat = f->set_aside_sat;
    s->as_of_height = TIP;
    s->hosting_json = f->host_open && !f->host_cancelled ? "{\"lobbies_open\":1,\"factories\":0,\"next_date\":null}" : NULL;
    if (f->story) {
        story_status(f, s);
    } else {
        if (f->has_factory && f->wallet == GZ_API_WALLET_UNLOCKED) {
            s->doing[s->ndoing].code = "awaiting_funding";
            s->doing[s->ndoing].params_json = "{\"factory_id\":\"" FACTORY_ID "\"}";
            s->ndoing++;
        }
        if (f->joined && f->wallet == GZ_API_WALLET_UNLOCKED) {
            s->doing[s->ndoing].code = f->ready ? "in_lobby_not_counted" : "in_lobby_not_ready";
            s->doing[s->ndoing].lobby_id = LOBBY_ID;
            s->doing[s->ndoing].params_json = f->ready ? "{}" : "{\"reasons\":[\"user_choice\"]}";
            s->ndoing++;
        }
    }
    for (i = 0; i < f->doing_extra_n && s->ndoing < GZ_API_MAX_DOING; i++) s->doing[s->ndoing++] = f->doing_extra[i];
    if (f->wallet == GZ_API_WALLET_UNLOCKED && !f->words_checked_at) {
        s->attention[s->nattention].id = "att_1";
        s->attention[s->nattention].code = "words_not_checked";
        s->nattention++;
    }
    for (i = 0; i < f->attention_extra_n && s->nattention < GZ_API_MAX_ATTENTION; i++)
        s->attention[s->nattention++] = f->attention_extra[i];
    s->lock_since = "start";
    s->locked_since_at = 1794434000;
    s->watcher_runs = 0;                              /* Slice 1 builds no watcher (4.7) */
    s->watching_reason = "no_bundle";
    pthread_mutex_unlock(&f->mu);
    return 0;
}

const gz_api_backend gz_fake_backend = {
    "0.1.0-fake", "signet", wallet_state, pp_op, pp_done, status, call, NULL, words_checks_left, NULL,
};
