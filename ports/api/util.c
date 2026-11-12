/* SPDX-License-Identifier: MIT */
/* Small helpers for the local API server. */
#define _POSIX_C_SOURCE 200809L
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "internal.h"

void gz_wipe(void *p, size_t n)
{
    if (p && n) OPENSSL_cleanse(p, n);
}

int gz_random(void *out, size_t n)
{
    return RAND_bytes(out, (int)n) == 1 ? 0 : -1;
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void gz_b64url(const uint8_t *in, size_t n, char *out)
{
    size_t i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = B64[v >> 18];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63];
        out[o++] = B64[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = B64[v >> 18];
        out[o++] = B64[(v >> 12) & 63];
    } else if (n - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = B64[v >> 18];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63];
    }
    out[o] = 0;
}

static int b64v(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

/* Decodes exactly outn bytes from exactly the canonical number of characters;
 * any other length, a padding character or non-zero spare bits fail. */
int gz_b64url_decode(const char *in, size_t n, uint8_t *out, size_t outn)
{
    size_t want = (outn * 4 + 2) / 3, i, o = 0;
    uint32_t acc = 0;
    int bits = 0;
    if (n != want) return -1;
    for (i = 0; i < n; i++) {
        int v = b64v(in[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outn) return -1;
            out[o++] = (uint8_t)(acc >> bits);
            acc &= (1u << bits) - 1;
        }
    }
    if (o != outn || acc != 0) return -1;
    return 0;
}

int gz_ct_eq(const void *a, const void *b, size_t n)
{
    return CRYPTO_memcmp(a, b, n) == 0;
}

void gz_hex(const uint8_t *in, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[2 * i] = h[in[i] >> 4];
        out[2 * i + 1] = h[in[i] & 15];
    }
    out[2 * n] = 0;
}

int64_t gz_now_ms(gz_api_server *srv)
{
    struct timespec ts;
    if (srv && srv->cfg.now_ms) return srv->cfg.now_ms(srv->cfg.ctx);
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void gz_log(gz_api_server *srv, const char *fmt, ...)
{
    char line[512];
    va_list ap;
    if (!srv->cfg.log) return;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    srv->cfg.log(srv->cfg.ctx, line);
}

int gz_valid_id(const char *s, size_t min, size_t max)
{
    size_t n = 0;
    for (; s[n]; n++) {
        char c = s[n];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
              c == '-'))
            return 0;
        if (n >= max) return 0;
    }
    return n >= min && n <= max;
}

int gz_out_add(gz_out *o, const void *p, size_t n)
{
    if (o->cap - o->len < n) {
        size_t cap = o->cap ? o->cap : 1024;
        char *nb;
        while (cap - o->len < n) cap *= 2;
        nb = malloc(cap);
        if (!nb) return -1;
        if (o->buf) {
            memcpy(nb, o->buf, o->len);
            OPENSSL_cleanse(o->buf, o->cap);
            free(o->buf);
        }
        o->buf = nb;
        o->cap = cap;
    }
    memcpy(o->buf + o->len, p, n);
    o->len += n;
    return 0;
}

void gz_out_free(gz_out *o)
{
    if (o->buf) {
        OPENSSL_cleanse(o->buf, o->cap);
        free(o->buf);
    }
    memset(o, 0, sizeof *o);
}

void gz_api_err_set(gz_api_error *err, const char *code, const char *field, const char *params_fmt, ...)
{
    va_list ap;
    err->code = code;
    err->field = field;
    err->params[0] = 0;
    if (params_fmt) {
        va_start(ap, params_fmt);
        vsnprintf(err->params, sizeof err->params, params_fmt, ap);
        va_end(ap);
    }
}

/* Fixed English text per code (8): never a quote of the request. */
const char *gz_error_message(const char *code)
{
    static const char *const t[][2] = {
        {"bad_json", "The request body is not valid JSON for this API."},
        {"bad_value", "A field's value is outside its rules."},
        {"unknown_field", "The request has a field this version does not know."},
        {"missing_field", "A required field is missing."},
        {"secret_in_url", "Secrets never go in a URL."},
        {"two_credentials", "Send one credential only."},
        {"bearer_not_on_tcp", "The socket token is accepted on the local socket only."},
        {"no_upgrade", "Upgrades are not offered."},
        {"bad_request", "The request is not valid HTTP/1.1 for this program."},
        {"not_signed_in", "Not signed in."},
        {"wrong_passphrase", "Wrong passphrase."},
        {"wallet_locked", "The wallet is locked."},
        {"other_user", "This connection belongs to another account on this computer."},
        {"not_setup_call", "Only the first-run calls are open to a setup session."},
        {"not_setup_session", "This call needs the setup session of the first run."},
        {"not_files_behind_call", "Only the files-behind calls are open to this session."},
        {"files_behind", "These files are older than this wallet's last saved state."},
        {"not_files_behind", "The wallet is not in the files-behind state."},
        {"passphrase_not_checked", "The passphrase could not be checked. Try again."},
        {"token_used", "This start link was already used."},
        {"bad_code", "That code or link is not valid."},
        {"code_expired", "That code or link has expired."},
        {"too_many_attempts", "Too many wrong codes; the codes were cancelled."},
        {"wallet_exists", "A wallet already exists."},
        {"no_wallet", "There is no wallet yet."},
        {"hosting_lobby_open", "Cancel the lobby you host before locking."},
        {"weak_passphrase", "This passphrase does not meet the rules."},
        {"passphrases_differ", "The two passphrases differ."},
        {"bad_words", "Those words are not a valid wallet phrase."},
        {"forbidden_origin", "This request did not come from Gazpacho's own page."},
        {"fresh_sign_in_needed", "Type your passphrase again for this."},
        {"confirm_mismatch", "The confirmation does not match what would be done."},
        {"request_id_reused", "This request id was used for another request."},
        {"too_many_streams", "Too many windows are following this app."},
        {"not_found", "Not found."},
        {"method_not_allowed", "Method not allowed."},
        {"no_cors", "Cross-origin requests are not served."},
        {"length_required", "Request bodies need Content-Length."},
        {"too_large", "The request is too large."},
        {"bad_content_type", "Request bodies must be application/json."},
        {"bad_host", "Misdirected request."},
        {"headers_too_large", "The request headers are too large."},
        {"rate_limited", "Too many attempts. Wait and try again."},
        {"not_in_this_release", "This call is not in this release."},
        {"node_stopped", "The wallet's core has stopped."},
        {"internal", "Internal error."},
        {"changed_elsewhere", "This changed elsewhere; read it again."},
        {"paused", "Gazpacho is paused."},
        {"signing_now", "This cannot change during signing."},
        {"chain_in_doubt", "The chain view is in doubt."},
        {"wallet_restoring", "The wallet is waiting for current data after a restore."},
    };
    size_t i;
    for (i = 0; i < sizeof t / sizeof t[0]; i++)
        if (strcmp(t[i][0], code) == 0) return t[i][1];
    return "The request was refused.";
}

const char *gz_http_reason(int status)
{
    switch (status) {
    case 100: return "Continue";
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 413: return "Content Too Large";
    case 415: return "Unsupported Media Type";
    case 421: return "Misdirected Request";
    case 423: return "Locked";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default: return "Unknown";
    }
}
