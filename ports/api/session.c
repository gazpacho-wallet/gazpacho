/* SPDX-License-Identifier: MIT */
/* Sessions (spec/local-api.md 4.2, 4.4, 4.7-4.9), the socket token (4.6,
 * storage 12.2), the first run's start token, redirect file and codes (4.3),
 * and the attempts file (4.3, storage 12.3, mode 1 as Slice 1 uses it). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "internal.h"

/* ---- files ------------------------------------------------------------------------ */
/* Writes data to path through a fresh owner-only temporary file and a rename,
 * never following a link at either name. */
static int write_private(const char *path, const void *data, size_t n)
{
    char tmp[700];
    int fd, ok;
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) return -1;
    unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    ok = write(fd, data, n) == (ssize_t)n && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok || rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* ---- sessions ------------------------------------------------------------------------ */
static void session_drop(gz_api_server *srv, gz_session *s)
{
    int slot = (int)(s - srv->sess);
    gz_streams_end_session(srv, slot, s->no, 0);
    gz_wipe(s, sizeof *s);
    srv->ctr.sessions_open--;
}

void gz_session_end(gz_api_server *srv, gz_session *s)
{
    if (!s || !s->used) return;
    session_drop(srv, s);
    if (srv->be->sessions_changed) srv->be->sessions_changed(srv->bectx);
}

void gz_sessions_end_all(gz_api_server *srv)
{
    int i;
    for (i = 0; i < GZ_SESSIONS_MAX; i++)
        if (srv->sess[i].used) session_drop(srv, &srv->sess[i]);
    gz_streams_end_session(srv, -1, 0, 1);              /* bearer streams too */
    if (srv->be->sessions_changed) srv->be->sessions_changed(srv->bectx);
}

int gz_tunnel_host(gz_api_server *srv, const char *host)
{
    char b[64];
    if (!srv->cfg.tunnel_port) return 0;
    snprintf(b, sizeof b, ":%u", (unsigned)srv->cfg.tunnel_port);
    return strlen(host) > strlen(b) && strcmp(host + strlen(host) - strlen(b), b) == 0;
}

gz_session *gz_session_new(gz_api_server *srv, int kind, const char *host)
{
    gz_session *s = NULL, *oldest = NULL;
    int64_t now = gz_now_ms(srv);
    int i;
    for (i = 0; i < GZ_SESSIONS_MAX; i++) {
        if (!srv->sess[i].used) { s = &srv->sess[i]; break; }
        if (!oldest || srv->sess[i].last_used < oldest->last_used) oldest = &srv->sess[i];
    }
    if (!s) {                                           /* a ninth: the one unused longest ends (4.2) */
        gz_session_end(srv, oldest);
        s = oldest;
    }
    memset(s, 0, sizeof *s);
    if (gz_random(s->token, sizeof s->token) != 0) return NULL;
    s->used = 1;
    s->kind = kind;
    s->no = ++srv->next_session_no;
    s->started = s->last_input = s->last_used = s->tunnel_last = now;
    snprintf(s->host, sizeof s->host, "%s", host);
    s->tunnel = gz_tunnel_host(srv, host);
    srv->ctr.sessions_open++;
    return s;
}

static int session_expired(gz_api_server *srv, const gz_session *s, int64_t now)
{
    if (now - s->last_input >= srv->lim.idle_sign_out_ms) return 1;
    if (s->tunnel && now - s->tunnel_last >= srv->lim.tunnel_idle_ms) return 1;
    return 0;
}

gz_session *gz_session_find(gz_api_server *srv, const char *header, const char *host)
{
    uint8_t tok[GZ_TOKEN_LEN];
    gz_session *match = NULL;
    int64_t now = gz_now_ms(srv);
    int i;
    if (!header || strlen(header) != GZ_TOKEN_B64) return NULL;
    if (gz_b64url_decode(header, GZ_TOKEN_B64, tok, sizeof tok) != 0) return NULL;
    for (i = 0; i < GZ_SESSIONS_MAX; i++)
        if (srv->sess[i].used && gz_ct_eq(srv->sess[i].token, tok, sizeof tok)) match = &srv->sess[i];
    gz_wipe(tok, sizeof tok);
    if (!match) return NULL;
    if (session_expired(srv, match, now)) {
        gz_session_end(srv, match);
        return NULL;
    }
    if (strcmp(match->host, host) != 0) return NULL;    /* valid only under its own Host (4.2) */
    return match;
}

int gz_session_fresh(gz_api_server *srv, const gz_session *s)
{
    return s && gz_now_ms(srv) < s->fresh_until;
}

void gz_sessions_tick(gz_api_server *srv, int64_t now, int64_t *next)
{
    int i;
    gz_conn *c;
    for (i = 0; i < GZ_SESSIONS_MAX; i++) {
        gz_session *s = &srv->sess[i];
        int64_t t;
        if (!s->used) continue;
        if (s->tunnel)                                  /* an open stream naming the port keeps it */
            for (c = srv->conns; c; c = c->next)
                if (c->stream && c->stream_session == i && c->stream_session_no == s->no) s->tunnel_last = now;
        if (session_expired(srv, s, now)) {
            gz_log(srv, "session %llu signed out (idle)", (unsigned long long)s->no);
            gz_session_end(srv, s);
            continue;
        }
        t = s->last_input + srv->lim.idle_sign_out_ms;
        if (s->tunnel && s->tunnel_last + srv->lim.tunnel_idle_ms < t) t = s->tunnel_last + srv->lim.tunnel_idle_ms;
        if (t < *next) *next = t;
    }
}

/* ---- the socket token (4.6, storage 12.2) ----------------------------------------------- */
static int token_dir_ok(const char *dir)
{
    struct stat st;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) return 0;
    if (lstat(dir, &st) != 0) return 0;
    /* an existing folder with another owner, other permissions or a link in its place is refused */
    return S_ISDIR(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 0777) == 0700;
}

int gz_socket_token_make(gz_api_server *srv)
{
    char b64[GZ_TOKEN_B64 + 1];
    int r;
    srv->have_socket_token = 0;
    if (gz_random(srv->socket_token, sizeof srv->socket_token) != 0) return -1;
    if (!token_dir_ok(srv->token_dir)) {
        /* another account may have made it first (/tmp fallback, review F5.5): refused, and status says so */
        srv->token_dir_refused = 1;
        gz_log(srv, "warning: the socket token folder is not owner-only; the command line cannot sign in");
        gz_wipe(srv->socket_token, sizeof srv->socket_token);
        return -1;
    }
    srv->token_dir_refused = 0;
    gz_b64url(srv->socket_token, sizeof srv->socket_token, b64);
    r = write_private(srv->token_path, b64, GZ_TOKEN_B64);
    gz_wipe(b64, sizeof b64);
    if (r != 0) {
        gz_wipe(srv->socket_token, sizeof srv->socket_token);
        return -1;
    }
    srv->have_socket_token = 1;
    return 0;
}

void gz_socket_token_drop(gz_api_server *srv)
{
    unlink(srv->token_path);
    rmdir(srv->token_dir);
    gz_wipe(srv->socket_token, sizeof srv->socket_token);
    srv->have_socket_token = 0;
}

int gz_socket_token_check(gz_api_server *srv, const char *auth)
{
    uint8_t tok[GZ_TOKEN_LEN];
    int ok;
    if (!srv->have_socket_token || strncmp(auth, "Bearer ", 7) != 0) return 0;
    auth += 7;
    if (strlen(auth) != GZ_TOKEN_B64 || gz_b64url_decode(auth, GZ_TOKEN_B64, tok, sizeof tok) != 0) return 0;
    ok = gz_ct_eq(tok, srv->socket_token, sizeof tok);
    gz_wipe(tok, sizeof tok);
    return ok;
}

/* ---- first run (4.3) -------------------------------------------------------------------- */
int gz_first_run_start(gz_api_server *srv)
{
    char b64[GZ_TOKEN_B64 + 1], page[512];
    int n, r;
    unlink(srv->redirect_path);                         /* a spent token left by a crash */
    if (srv->cfg.no_listen || !srv->port) return 0;
    if (gz_random(srv->start_token, sizeof srv->start_token) != 0) return -1;
    gz_b64url(srv->start_token, sizeof srv->start_token, b64);
    n = snprintf(page, sizeof page,
                 "<!doctype html>\n<meta charset=\"utf-8\">\n"
                 "<meta http-equiv=\"refresh\" content=\"0;url=http://127.0.0.1:%u/#start=%s\">\n"
                 "<a href=\"http://127.0.0.1:%u/#start=%s\">Open Gazpacho</a>\n",
                 (unsigned)srv->port, b64, (unsigned)srv->port, b64);
    gz_wipe(b64, sizeof b64);
    r = (n > 0 && (size_t)n < sizeof page) ? write_private(srv->redirect_path, page, (size_t)n) : -1;
    gz_wipe(page, sizeof page);
    if (r != 0) {
        gz_wipe(srv->start_token, sizeof srv->start_token);
        return -1;
    }
    srv->have_start_token = 1;
    srv->start_token_made = gz_now_ms(srv);
    if (srv->cfg.on_first_run_file) {
        srv->first_run_launched_at = srv->start_token_made / 1000;
        srv->cfg.on_first_run_file(srv->cfg.ctx, srv->redirect_path);
    }
    return 0;
}

static void spend_start_token(gz_api_server *srv, int64_t now)
{
    SHA256(srv->start_token, sizeof srv->start_token, srv->spent_token_hash);
    srv->have_spent_token = 1;
    srv->spent_at = now;
    gz_wipe(srv->start_token, sizeof srv->start_token);
    srv->have_start_token = 0;
    unlink(srv->redirect_path);
}

void gz_first_run_close(gz_api_server *srv)
{
    if (srv->have_start_token) unlink(srv->redirect_path);
    gz_wipe(srv->start_token, sizeof srv->start_token);
    srv->have_start_token = 0;
    gz_wipe(srv->codes, sizeof srv->codes);
    memset(srv->code_made, 0, sizeof srv->code_made);
    srv->first_run_closed = 1;
}

void gz_first_run_tick(gz_api_server *srv, int64_t now, int64_t *next)
{
    int i;
    if (srv->have_start_token) {
        int64_t t = srv->start_token_made + srv->lim.start_token_ms;
        if (now >= t) spend_start_token(srv, now);     /* expired: the file goes too */
        else if (t < *next) *next = t;
    }
    for (i = 0; i < GZ_CODES_MAX; i++) {
        if (!srv->codes[i][0]) continue;
        if (now >= srv->code_made[i] + srv->lim.code_ms) {
            gz_wipe(srv->codes[i], sizeof srv->codes[i]);
        } else if (srv->code_made[i] + srv->lim.code_ms < *next) {
            *next = srv->code_made[i] + srv->lim.code_ms;
        }
    }
    if (srv->check_id[0] && now >= srv->check_expires) gz_wipe(srv->check_id, sizeof srv->check_id);
}

/* The start token's first presentation spends it, whatever follows (4.3).
 * Returns NULL and the token spent, or an error code. A wrong token changes
 * nothing and counts nothing (review R5). */
const char *gz_start_token_present(gz_api_server *srv, const char *b64, int64_t *used_at)
{
    uint8_t tok[GZ_TOKEN_LEN], h[32];
    int64_t now = gz_now_ms(srv);
    const char *res = "bad_code";
    if (strlen(b64) != GZ_TOKEN_B64 || gz_b64url_decode(b64, GZ_TOKEN_B64, tok, sizeof tok) != 0)
        return "bad_code";
    if (srv->have_start_token && gz_ct_eq(tok, srv->start_token, sizeof tok)) {
        int expired = now >= srv->start_token_made + srv->lim.start_token_ms;
        spend_start_token(srv, now);
        res = expired ? "code_expired" : NULL;
    } else if (srv->have_spent_token) {
        SHA256(tok, sizeof tok, h);
        if (gz_ct_eq(h, srv->spent_token_hash, sizeof h)) {
            res = "token_used";
            *used_at = srv->spent_at / 1000;
        }
    }
    gz_wipe(tok, sizeof tok);
    return res;
}

static const char CODE_ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";   /* Crockford's 32 symbols */

int gz_code_make(gz_api_server *srv, char out[12], int64_t *expires)
{
    uint8_t r[10];
    int i, slot = -1;
    int64_t now = gz_now_ms(srv);
    for (i = 0; i < GZ_CODES_MAX; i++)
        if (!srv->codes[i][0]) { slot = i; break; }
    if (slot < 0) {                                     /* at most 3 unused: the oldest goes */
        slot = 0;
        for (i = 1; i < GZ_CODES_MAX; i++)
            if (srv->code_made[i] < srv->code_made[slot]) slot = i;
    }
    if (gz_random(r, sizeof r) != 0) return -1;
    for (i = 0; i < 10; i++) srv->codes[slot][i] = CODE_ALPHABET[r[i] & 31];
    srv->codes[slot][10] = 0;
    srv->code_made[slot] = now;
    gz_wipe(r, sizeof r);
    memcpy(out, srv->codes[slot], 5);
    out[5] = '-';
    memcpy(out + 6, srv->codes[slot] + 5, 5);
    out[11] = 0;
    *expires = (now + srv->lim.code_ms) / 1000;
    return 0;
}

/* Returns NULL when a live code matched (and is spent), else an error code. */
const char *gz_code_present(gz_api_server *srv, const char *typed)
{
    char norm[11];
    size_t n = 0, i;
    int64_t now = gz_now_ms(srv);
    int match = -1, k;
    if (srv->code_last_try && now - srv->code_last_try < 1000) return "rate_limited";
    srv->code_last_try = now;
    for (i = 0; typed[i]; i++) {
        char c = typed[i];
        if (c == '-' && n == 5) continue;
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        if (c == 'O') c = '0';
        if (c == 'I' || c == 'L') c = '1';
        if (n >= 10 || !strchr(CODE_ALPHABET, c) || c == 0) { n = 11; break; }
        norm[n++] = c;
    }
    if (n == 10) {
        norm[10] = 0;
        for (k = 0; k < GZ_CODES_MAX; k++)
            if (srv->codes[k][0] && gz_ct_eq(srv->codes[k], norm, 10)) match = k;
    }
    gz_wipe(norm, sizeof norm);
    if (match >= 0) {
        int expired = now >= srv->code_made[match] + srv->lim.code_ms;
        gz_wipe(srv->codes[match], sizeof srv->codes[match]);
        srv->code_wrong = 0;
        return expired ? "code_expired" : NULL;
    }
    if (++srv->code_wrong >= 5) {                       /* 5 wrong in a row cancel every code (4.3) */
        gz_wipe(srv->codes, sizeof srv->codes);
        srv->code_wrong = 0;
        return "too_many_attempts";
    }
    return "bad_code";
}

/* ---- the attempts file (storage 12.3, mode 1) ------------------------------------------- */
static int chain_hash(const char *network, uint8_t out[32])
{
    const char *display;
    int i;
    if (strcmp(network, "signet") == 0)
        display = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
    else if (strcmp(network, "testnet4") == 0)
        display = "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043";
    else
        return -1;                                      /* mainnet is never accepted */
    for (i = 0; i < 32; i++) {                          /* internal byte order: the display reversed */
        unsigned v;
        sscanf(display + 2 * i, "%2x", &v);
        out[31 - i] = (uint8_t)v;
    }
    return 0;
}

static void be64(uint8_t *p, uint64_t v) { int i; for (i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; } }
static uint64_t rd64(const uint8_t *p) { uint64_t v = 0; int i; for (i = 0; i < 8; i++) v = (v << 8) | p[i]; return v; }

int gz_attempts_encode(const char *network, uint64_t counter, uint32_t wrong, uint64_t last, uint64_t until,
                       uint8_t out[85])
{
    uint8_t h[32];
    memcpy(out, "GZTRIES1", 8);
    if (chain_hash(network, out + 8) != 0) return -1;
    be64(out + 40, counter);
    out[48] = (uint8_t)(wrong >> 24);
    out[49] = (uint8_t)(wrong >> 16);
    out[50] = (uint8_t)(wrong >> 8);
    out[51] = (uint8_t)wrong;
    be64(out + 52, last);
    be64(out + 60, until);
    out[68] = 1;                                        /* mode 1: checksum (no key store in Slice 1) */
    SHA256(out, 69, h);
    memcpy(out + 69, h, 16);
    return 0;
}

int gz_attempts_decode(const char *network, const uint8_t in[85], uint64_t *counter, uint32_t *wrong,
                       uint64_t *last, uint64_t *until)
{
    uint8_t chain[32], h[32];
    if (memcmp(in, "GZTRIES1", 8) != 0 || chain_hash(network, chain) != 0 || memcmp(in + 8, chain, 32) != 0)
        return -1;
    if (in[68] != 1) return -1;                         /* mode 2 needs a key Slice 1 never has */
    SHA256(in, 69, h);
    if (!gz_ct_eq(h, in + 69, 16)) return -1;
    *counter = rd64(in + 40);
    *wrong = ((uint32_t)in[48] << 24) | ((uint32_t)in[49] << 16) | ((uint32_t)in[50] << 8) | in[51];
    *last = rd64(in + 52);
    *until = rd64(in + 60);
    return 0;
}

static void attempts_save(gz_api_server *srv)
{
    uint8_t b[85];
    srv->att_counter++;
    if (gz_attempts_encode(srv->be->network, srv->att_counter, srv->att_wrong, (uint64_t)srv->att_last_wrong,
                           (uint64_t)srv->att_blocked_until, b) != 0 ||
        write_private(srv->attempts_path, b, sizeof b) != 0) {
        if (!srv->att_unsaved) gz_log(srv, "warning: the attempts file could not be written: passphrases are refused until it can be");
        srv->att_unsaved = 1;                           /* fail closed (review F5.1): gz_attempts_gate refuses */
        return;
    }
    srv->att_unsaved = 0;
}

void gz_attempts_load(gz_api_server *srv)
{
    uint8_t b[86];
    int fd;
    ssize_t n = -1;
    uint64_t counter, last, until;
    uint32_t wrong;
    int64_t now = gz_now_ms(srv) / 1000;
    srv->att_loaded = 1;
    fd = open(srv->attempts_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        n = read(fd, b, sizeof b);
        close(fd);
    }
    if (n == 85 && gz_attempts_decode(srv->be->network, b, &counter, &wrong, &last, &until) == 0) {
        srv->att_counter = counter;
        srv->att_wrong = wrong;
        srv->att_last_wrong = (int64_t)last;
        srv->att_blocked_until = (int64_t)until;
        /* a clock set back must not block for longer than the ceiling (review F5.2) */
        if (srv->att_blocked_until > now + 900) srv->att_blocked_until = now + 900;
        return;
    }
    /* missing, damaged or of another network: the strictest state, from now (storage 12.3) */
    gz_log(srv, "the attempts file is missing or damaged: sign-in is refused for 15 minutes");
    srv->att_wrong = 0;
    srv->att_last_wrong = 0;
    srv->att_blocked_until = now + 900;
    attempts_save(srv);
}

int gz_attempts_gate(gz_api_server *srv, int64_t now_s, int64_t *retry_after)
{
    if (srv->att_unsaved) {                             /* the count could not be kept: nothing is checked */
        attempts_save(srv);                             /* try again; the retry is on the loop thread */
        if (srv->att_unsaved) { *retry_after = -1; return 1; }
    }
    if (now_s < srv->att_blocked_until) {
        *retry_after = srv->att_blocked_until - now_s;
        return 1;
    }
    return 0;
}

/* One attempt per second; after 5 wrong in a row the delay doubles with each
 * further wrong attempt, up to 15 minutes (4.3, D15). */
void gz_attempts_wrong(gz_api_server *srv, int64_t now_s)
{
    int64_t delay = 1;
    srv->att_wrong++;
    if (srv->att_wrong > 5) {
        uint32_t k = srv->att_wrong - 5;
        delay = k >= 10 ? 900 : ((int64_t)1 << k);
        if (delay > 900) delay = 900;
    }
    srv->att_last_wrong = now_s;
    srv->att_blocked_until = now_s + delay;
    attempts_save(srv);
}

void gz_attempts_right(gz_api_server *srv)
{
    if (srv->att_wrong == 0 && srv->att_blocked_until == 0) return;
    srv->att_wrong = 0;
    srv->att_blocked_until = 0;
    attempts_save(srv);
}

void gz_attempts_fresh_file(gz_api_server *srv)
{
    srv->att_wrong = 0;
    srv->att_last_wrong = 0;
    srv->att_blocked_until = 0;
    srv->att_loaded = 1;
    attempts_save(srv);
}
