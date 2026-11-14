/* SPDX-License-Identifier: MIT */
/* HTTP/1.1 requests through llhttp (strict mode), with the limits of
 * spec/local-api.md 3.1, and responses with the headers of 5.4. One request at
 * a time per connection: the parser pauses at the end of the head and at the
 * end of each message, so every check of section 5 runs before the body is
 * read and before the next request is looked at. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "internal.h"

#define C_OF(p) ((gz_conn *)(p)->data)

static int hb_add(gz_conn *c, const char *at, size_t n)
{
    if (c->hlen + n + 1 > sizeof c->hbuf) {
        c->fault = 431;
        return -1;
    }
    memcpy(c->hbuf + c->hlen, at, n);
    c->hlen += n;
    return 0;
}

static int cb_message_begin(llhttp_t *p)
{
    gz_conn *c = C_OF(p);
    c->hlen = 0;
    c->last_cb = 0;
    c->req.nh = 0;
    c->req.url = NULL;
    return 0;
}

static int cb_url(llhttp_t *p, const char *at, size_t n)
{
    gz_conn *c = C_OF(p);
    if (!c->req.url) c->req.url = c->hbuf + c->hlen;
    return hb_add(c, at, n);
}

static int cb_url_complete(llhttp_t *p)
{
    gz_conn *c = C_OF(p);
    if (!c->req.url) c->req.url = c->hbuf + c->hlen;
    c->hbuf[c->hlen++] = 0;
    return 0;
}

static int cb_field(llhttp_t *p, const char *at, size_t n)
{
    gz_conn *c = C_OF(p);
    if (c->last_cb != 1) {
        if (c->req.nh >= c->srv_max_lines) {
            c->fault = 431;
            return -1;
        }
        c->req.h[c->req.nh].name_off = (uint32_t)c->hlen;
        c->req.h[c->req.nh].name_len = 0;
        c->req.h[c->req.nh].value_off = 0;
        c->req.h[c->req.nh].value_len = 0;
        c->req.nh++;
        c->last_cb = 1;
        c->value_started = 0;
    }
    c->req.h[c->req.nh - 1].name_len += (uint32_t)n;
    return hb_add(c, at, n);
}

static int cb_field_complete(llhttp_t *p)
{
    gz_conn *c = C_OF(p);
    if (c->hlen + 1 > sizeof c->hbuf) { c->fault = 431; return -1; }
    c->hbuf[c->hlen++] = 0;
    return 0;
}

static int cb_value(llhttp_t *p, const char *at, size_t n)
{
    gz_conn *c = C_OF(p);
    gz_hdr *h = &c->req.h[c->req.nh - 1];
    if (!c->value_started) {
        h->value_off = (uint32_t)c->hlen;
        h->value_len = 0;
        c->value_started = 1;
    }
    c->last_cb = 2;
    h->value_len += (uint32_t)n;
    return hb_add(c, at, n);
}

static int cb_value_complete(llhttp_t *p)
{
    gz_conn *c = C_OF(p);
    gz_hdr *h = &c->req.h[c->req.nh - 1];
    if (!c->value_started) {
        h->value_off = (uint32_t)c->hlen;
        h->value_len = 0;
    }
    c->value_started = 0;
    c->last_cb = 2;
    if (c->hlen + 1 > sizeof c->hbuf) { c->fault = 431; return -1; }
    c->hbuf[c->hlen++] = 0;
    return 0;
}

static int cb_headers_complete(llhttp_t *p)
{
    gz_conn *c = C_OF(p);
    c->paused_at_head = 1;
    return HPE_PAUSED;
}

static int cb_body(llhttp_t *p, const char *at, size_t n)
{
    gz_conn *c = C_OF(p);
    if (c->req.body_len + n > c->req.body_cap) {
        c->fault = 413;
        return -1;
    }
    memcpy(c->req.body + c->req.body_len, at, n);
    c->req.body_len += n;
    return 0;
}

static int cb_message_complete(llhttp_t *p)
{
    gz_conn *c = C_OF(p);
    c->msg_done = 1;
    return HPE_PAUSED;
}

void gz_http_settings(llhttp_settings_t *s)
{
    llhttp_settings_init(s);
    s->on_message_begin = cb_message_begin;
    s->on_url = cb_url;
    s->on_url_complete = cb_url_complete;
    s->on_header_field = cb_field;
    s->on_header_field_complete = cb_field_complete;
    s->on_header_value = cb_value;
    s->on_header_value_complete = cb_value_complete;
    s->on_headers_complete = cb_headers_complete;
    s->on_body = cb_body;
    s->on_message_complete = cb_message_complete;
}

static void req_clear(gz_req *r)
{
    if (r->have_doc) gz_json_free(&r->doc);
    if (r->body) {
        gz_wipe(r->body, r->body_cap);
        free(r->body);
    }
    gz_wipe(r, sizeof *r);
}

void gz_conn_reset(gz_conn *c, gz_api_server *srv)
{
    req_clear(&c->req);
    gz_wipe(c->hbuf, c->hlen);
    c->hlen = 0;
    c->last_cb = 0;
    c->value_started = 0;
    c->fault = 0;
    c->head_fed = 0;
    c->head_done = 0;
    c->msg_done = 0;
    c->paused_at_head = 0;
    c->kick = 0;
    c->state = CS_HEAD;
    llhttp_init(&c->parser, HTTP_REQUEST, &srv->settings);
    c->parser.data = c;
    c->deadline = gz_now_ms(srv) + srv->lim.idle_ms;
}

gz_conn *gz_conn_new(gz_api_server *srv, int fd, int is_unix)
{
    gz_conn *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->fd = fd;
    c->is_unix = is_unix;
    c->in_cap = srv->lim.max_head_bytes + 4096;
    c->in = malloc(c->in_cap);
    if (!c->in) { free(c); return NULL; }
    c->srv_max_lines = srv->lim.max_header_lines;
    c->stream_session = -1;
    c->opened_ms = gz_now_ms(srv);
    gz_conn_reset(c, srv);
    c->next = srv->conns;
    srv->conns = c;
    srv->nconns++;
    srv->ctr.connections_open = srv->nconns;
    return c;
}

void gz_conn_free(gz_api_server *srv, gz_conn *c)
{
    gz_conn **pp;
    for (pp = &srv->conns; *pp; pp = &(*pp)->next)
        if (*pp == c) { *pp = c->next; break; }
    srv->nconns--;
    srv->ctr.connections_open = srv->nconns;
    if (c->job) c->job->conn = NULL;
    if (c->stream) srv->ctr.streams_open--;
    if (c->fd >= 0) close(c->fd);
    req_clear(&c->req);
    gz_wipe(c->hbuf, sizeof c->hbuf);
    gz_wipe(c->in, c->in_cap);
    free(c->in);
    gz_out_free(&c->out);
    free(c);
}

/* ---- responses ------------------------------------------------------------------ */
static const char COMMON_HEADERS[] =
    "Cross-Origin-Resource-Policy: same-origin\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "Referrer-Policy: same-origin\r\n";
static const char CSP_NONE[] = "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n";

void gz_respond(gz_api_server *srv, gz_conn *c, int status, int kind, const char *extra_headers,
                const char *body, size_t len)
{
    char head[2048];
    int n;
    const char *ctype = "";
    if (kind == BK_JSON) ctype = "Content-Type: application/json; charset=utf-8\r\n";
    else if (kind == BK_PAGE) ctype = "Content-Type: text/html; charset=utf-8\r\n";
    if (status == 204) len = 0;
    if (c->req.method == M_HEAD) body = NULL;
    n = snprintf(head, sizeof head,
                 "HTTP/1.1 %d %s\r\n%s%s%sCache-Control: no-store\r\n%sContent-Length: %zu\r\n%s\r\n",
                 status, gz_http_reason(status), ctype, COMMON_HEADERS,
                 kind == BK_PAGE ? gz_page_headers() : CSP_NONE,
                 extra_headers ? extra_headers : "",
                 len, c->close_after ? "Connection: close\r\n" : "");
    if (n < 0 || (size_t)n >= sizeof head) { c->state = CS_DEAD; return; }
    if (gz_out_add(&c->out, head, (size_t)n) != 0 ||
        (body && len && status != 204 && gz_out_add(&c->out, body, len) != 0)) {
        c->state = CS_DEAD;
        return;
    }
    if (c->state != CS_STREAM) {
        c->state = CS_WRITE;
        c->deadline = gz_now_ms(srv) + srv->lim.idle_ms;   /* a client that never reads is closed */
    }
    if (srv->cfg.log && status != 100) {
        static const char *const M[] = {"OTHER", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"};
        int m = c->req.method >= 0 && c->req.method <= 7 ? c->req.method : 0;
        /* time, method, the path pattern, status, duration, session number: nothing else (5.5) */
        gz_log(srv, "%s %s %d %lldms s%llu", M[m], gz_route_pattern(&c->req), status,
               (long long)(gz_now_ms(srv) - (c->req.t0 ? c->req.t0 : gz_now_ms(srv))),
               (unsigned long long)c->req.log_session);
    }
}

void gz_respond_error(gz_api_server *srv, gz_conn *c, int status, const char *code, const char *field,
                      const char *params_json)
{
    gz_jw w;
    gz_jw_init(&w);
    gz_jw_obj(&w);
    gz_jw_kstr(&w, "code", code);
    gz_jw_kstr(&w, "message", gz_error_message(code));
    gz_jw_kstr(&w, "field", field);
    gz_jw_kraw(&w, "params", params_json && params_json[0] ? params_json : "{}");
    gz_jw_end_obj(&w);
    if (w.err) {
        c->state = CS_DEAD;
    } else {
        gz_respond(srv, c, status, BK_JSON, NULL, w.buf, w.len);
    }
    gz_jw_free(&w);
}

void gz_respond_json(gz_api_server *srv, gz_conn *c, int status, gz_jw *w, const char *extra)
{
    if (w->err) {
        gz_respond_error(srv, c, 500, "internal", NULL, "{\"ref\":\"jw\"}");
        return;
    }
    gz_respond(srv, c, status, BK_JSON, extra, w->buf ? w->buf : "", w->len);
}

/* ---- feeding the parser ------------------------------------------------------------- */
static void consume(gz_conn *c, size_t n)
{
    if (n >= c->in_len) {
        gz_wipe(c->in, c->in_len);
        c->in_len = 0;
        return;
    }
    memmove(c->in, c->in + n, c->in_len - n);
    gz_wipe(c->in + c->in_len - n, n);
    c->in_len -= n;
}

static void fail(gz_api_server *srv, gz_conn *c, int status)
{
    c->close_after = 1;
    switch (status) {
    case 431: gz_respond_error(srv, c, 431, "headers_too_large", NULL, NULL); break;
    case 413: gz_respond_error(srv, c, 413, "too_large", NULL, NULL); break;
    default: gz_respond_error(srv, c, 400, "bad_request", NULL, NULL); break;
    }
}

void gz_conn_process(gz_api_server *srv, gz_conn *c)
{
    while ((c->state == CS_HEAD || c->state == CS_BODY) && (c->in_len > 0 || c->kick)) {
        size_t n = c->in_len, used;
        llhttp_errno_t e;
        c->kick = 0;
        if (!c->head_done) {
            size_t room = srv->lim.max_head_bytes - c->head_fed;
            if (n > room) n = room;
            if (n == 0) { fail(srv, c, 431); return; }
            if (c->head_fed == 0 && c->hlen == 0) c->deadline = gz_now_ms(srv) + srv->lim.head_ms;
        }
        e = llhttp_execute(&c->parser, (const char *)c->in, n);
        if (e == HPE_OK) {
            used = n;
        } else if (e == HPE_PAUSED) {
            used = (size_t)(llhttp_get_error_pos(&c->parser) - (const char *)c->in);
        } else {
            fail(srv, c, c->fault ? c->fault : 400);
            return;
        }
        if (!c->head_done) c->head_fed += used;
        consume(c, used);
        if (e == HPE_PAUSED) {
            llhttp_resume(&c->parser);
            if (c->paused_at_head) {
                c->paused_at_head = 0;
                c->head_done = 1;
                c->req.method = 0;
                if (gz_route_head(srv, c)) return;     /* answered: refused before the body */
                c->state = CS_BODY;
                c->deadline = gz_now_ms(srv) + srv->lim.body_ms;
                c->kick = 1;                           /* a message with no body completes at once */
                continue;
            }
            if (c->msg_done) {
                c->state = CS_BUSY;
                gz_route_dispatch(srv, c);
                return;
            }
        }
        if (!c->head_done && c->head_fed >= srv->lim.max_head_bytes) {
            fail(srv, c, 431);
            return;
        }
    }
}

void gz_conn_input(gz_api_server *srv, gz_conn *c, const uint8_t *data, size_t n)
{
    if (c->state == CS_DEAD) return;
    if (c->state == CS_STREAM) {                       /* a stream reads nothing more */
        return;
    }
    if (c->in_cap - c->in_len < n) {
        /* More pipelined bytes than a head can hold while one request is served:
         * a client that sends far ahead is closed. */
        c->state = CS_DEAD;
        return;
    }
    memcpy(c->in + c->in_len, data, n);
    c->in_len += n;
    gz_conn_process(srv, c);
}

/* After every byte of a response is written. */
void gz_conn_after_write(gz_api_server *srv, gz_conn *c)
{
    if (c->state != CS_WRITE) return;
    gz_out_free(&c->out);
    if (c->close_after || !llhttp_should_keep_alive(&c->parser)) {
        c->state = CS_DEAD;
        return;
    }
    gz_conn_reset(c, srv);
    if (c->in_len) gz_conn_process(srv, c);
}
