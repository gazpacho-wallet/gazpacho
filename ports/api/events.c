/* SPDX-License-Identifier: MIT */
/* The event stream (spec/local-api.md 10): server-sent events read with
 * fetch(), as an HTTP/1.1 chunked answer. An event names an area and a local
 * id, never content. seq rises by one per event in a run; the last 256 are
 * kept for a reconnect with Last-Event-ID; events of one topic and id are
 * merged within 250 ms; a comment every 15 s; at most 2 streams per session
 * and 8 in all; a stream whose unsent data passes 64 KiB is closed. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"

static const char *const TOPICS[] = {"status", "session", "chain", "lobby", "host_lobby", "conditions", "factory",
                                     "payments", "wallet", "activity", "discovery", "settings", "hosting", "reset"};

static int topic_ok(const char *t)
{
    size_t i;
    for (i = 0; i < sizeof TOPICS / sizeof TOPICS[0]; i++)
        if (strcmp(t, TOPICS[i]) == 0) return 1;
    return 0;
}

static void stream_chunk(gz_api_server *srv, gz_conn *c, const char *data, size_t n)
{
    char head[24];
    int h = snprintf(head, sizeof head, "%zx\r\n", n);
    if (c->state == CS_DEAD) return;
    if (gz_out_add(&c->out, head, (size_t)h) != 0 || gz_out_add(&c->out, data, n) != 0 ||
        gz_out_add(&c->out, "\r\n", 2) != 0) {
        c->state = CS_DEAD;
        return;
    }
    if (c->out.len - c->out.off > srv->lim.stream_unsent_max) {
        gz_log(srv, "event stream closed: more than 64 KiB unsent");
        c->state = CS_DEAD;                             /* its reconnect gets reset */
    }
}

static size_t event_text(gz_api_server *srv, const gz_event *e, char *out, size_t cap)
{
    int n;
    if (e->id[0])
        n = snprintf(out, cap, "id: %s-%llu\nevent: change\ndata: {\"topic\":\"%s\",\"id\":\"%s\",\"seq\":%llu}\n\n",
                     srv->run_id, (unsigned long long)e->seq, e->topic, e->id, (unsigned long long)e->seq);
    else
        n = snprintf(out, cap, "id: %s-%llu\nevent: change\ndata: {\"topic\":\"%s\",\"seq\":%llu}\n\n",
                     srv->run_id, (unsigned long long)e->seq, e->topic, (unsigned long long)e->seq);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

static void emit(gz_api_server *srv, const char *topic, const char *id)
{
    gz_event *e;
    gz_conn *c;
    char text[256];
    size_t n;
    srv->seq++;
    e = &srv->ev[srv->seq % GZ_EVENTS_KEPT];
    e->seq = srv->seq;
    snprintf(e->topic, sizeof e->topic, "%s", topic);
    snprintf(e->id, sizeof e->id, "%s", id ? id : "");
    n = event_text(srv, e, text, sizeof text);
    for (c = srv->conns; c; c = c->next)
        if (c->stream && c->state == CS_STREAM && !c->close_after) stream_chunk(srv, c, text, n);
}

void gz_events_notify(gz_api_server *srv, const char *topic, const char *id)
{
    int64_t now = gz_now_ms(srv);
    int i, slot = -1, oldest = 0;
    if (!topic_ok(topic)) return;
    if (id && (!gz_valid_id(id, 1, 64))) return;        /* a local id only (7.3) */
    for (i = 0; i < GZ_MERGE_SLOTS; i++) {
        gz_merge *m = &srv->merge[i];
        if (m->topic[0] && strcmp(m->topic, topic) == 0 && strcmp(m->id, id ? id : "") == 0) { slot = i; break; }
        if (srv->merge[i].last_emit < srv->merge[oldest].last_emit && !srv->merge[i].pending) oldest = i;
    }
    if (slot < 0) {
        gz_merge *m = &srv->merge[oldest];
        if (m->pending) emit(srv, m->topic, m->id[0] ? m->id : NULL);
        memset(m, 0, sizeof *m);
        snprintf(m->topic, sizeof m->topic, "%s", topic);
        snprintf(m->id, sizeof m->id, "%s", id ? id : "");
        slot = oldest;
    }
    if (srv->merge[slot].last_emit && now - srv->merge[slot].last_emit < srv->lim.merge_ms) {
        srv->merge[slot].pending = 1;                   /* the latest wins; one event at the slot's time */
        return;
    }
    srv->merge[slot].last_emit = now;
    srv->merge[slot].pending = 0;
    emit(srv, topic, id);
}

void gz_events_tick(gz_api_server *srv, int64_t now, int64_t *next)
{
    int i;
    gz_conn *c;
    for (i = 0; i < GZ_MERGE_SLOTS; i++) {
        gz_merge *m = &srv->merge[i];
        if (!m->pending) continue;
        if (now >= m->last_emit + srv->lim.merge_ms) {
            m->pending = 0;
            m->last_emit = now;
            emit(srv, m->topic, m->id[0] ? m->id : NULL);
        } else if (m->last_emit + srv->lim.merge_ms < *next) {
            *next = m->last_emit + srv->lim.merge_ms;
        }
    }
    for (c = srv->conns; c; c = c->next) {
        if (!c->stream || c->state != CS_STREAM) continue;
        if (now >= c->next_keepalive) {
            static const char ka[] = ": keep-alive\n\n";
            stream_chunk(srv, c, ka, sizeof ka - 1);
            c->next_keepalive = now + srv->lim.keepalive_ms;
        }
        if (c->next_keepalive < *next) *next = c->next_keepalive;
    }
}

void gz_events_drain_notify(gz_api_server *srv)
{
    struct { char topic[16]; char id[72]; } q[64];
    int n, i;
    pthread_mutex_lock(&srv->notify_mu);
    n = srv->notify_n;
    memcpy(q, srv->notify_q, sizeof q[0] * (size_t)n);
    srv->notify_n = 0;
    pthread_mutex_unlock(&srv->notify_mu);
    for (i = 0; i < n; i++) gz_events_notify(srv, q[i].topic, q[i].id[0] ? q[i].id : NULL);
}

void gz_api_notify(gz_api_server *srv, const char *topic, const char *id)
{
    char b = 1;
    ssize_t w;
    pthread_mutex_lock(&srv->notify_mu);
    if (srv->notify_n < 64) {
        snprintf(srv->notify_q[srv->notify_n].topic, sizeof srv->notify_q[0].topic, "%s", topic);
        snprintf(srv->notify_q[srv->notify_n].id, sizeof srv->notify_q[0].id, "%s", id ? id : "");
        srv->notify_n++;
    } else {
        /* too many at once: draw everything again */
        snprintf(srv->notify_q[63].topic, sizeof srv->notify_q[0].topic, "reset");
        srv->notify_q[63].id[0] = 0;
    }
    pthread_mutex_unlock(&srv->notify_mu);
    if (srv->wake[1] >= 0) {
        w = write(srv->wake[1], &b, 1);
        (void)w;
    }
}

int gz_streams_count(gz_api_server *srv, int slot, uint64_t session_no, int *total)
{
    gz_conn *c;
    int mine = 0;
    *total = 0;
    for (c = srv->conns; c; c = c->next) {
        if (!c->stream || c->state == CS_DEAD) continue;
        (*total)++;
        if (c->stream_session == slot && c->stream_session_no == session_no) mine++;
    }
    return mine;
}

/* Starts the stream on c and replays from Last-Event-ID (10.3). */
void gz_stream_open(gz_api_server *srv, gz_conn *c, int session_slot, uint64_t session_no)
{
    static const char head[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-store\r\n"
        "Cross-Origin-Resource-Policy: same-origin\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: same-origin\r\n"
        "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n";
    const char *lei = c->req.last_event_id;
    char text[256];
    size_t n;
    c->stream = 1;
    c->stream_session = session_slot;
    c->stream_session_no = session_no;
    c->state = CS_STREAM;
    c->next_keepalive = gz_now_ms(srv) + srv->lim.keepalive_ms;
    c->deadline = INT64_MAX;
    if (gz_out_add(&c->out, head, sizeof head - 1) != 0) { c->state = CS_DEAD; return; }
    srv->ctr.streams_open++;
    if (lei && lei[0]) {
        size_t rl = strlen(srv->run_id);
        unsigned long long last = 0;
        char *end = NULL;
        int same_run = strncmp(lei, srv->run_id, rl) == 0 && lei[rl] == '-';
        if (same_run) last = strtoull(lei + rl + 1, &end, 10);
        if (same_run && end && *end == 0 && last <= srv->seq &&
            (srv->seq - last) < GZ_EVENTS_KEPT) {
            uint64_t s;
            for (s = last + 1; s <= srv->seq; s++) {
                const gz_event *e = &srv->ev[s % GZ_EVENTS_KEPT];
                if (e->seq != s || !e->topic[0]) continue;   /* another stream's own event */
                n = event_text(srv, e, text, sizeof text);
                stream_chunk(srv, c, text, n);
            }
        } else {
            gz_event e;
            memset(&e, 0, sizeof e);
            e.seq = ++srv->seq;                         /* one reset, only to this stream */
            snprintf(e.topic, sizeof e.topic, "reset");
            srv->ev[e.seq % GZ_EVENTS_KEPT].seq = e.seq;  /* kept as a gap: never replayed to others */
            srv->ev[e.seq % GZ_EVENTS_KEPT].topic[0] = 0;
            n = event_text(srv, &e, text, sizeof text);
            stream_chunk(srv, c, text, n);
        }
    }
}

/* Ends the streams of one session with a `session` event (10.2); slot -1 with
 * bearer_too ends bearer streams (lock, revoke-all). */
void gz_streams_end_session(gz_api_server *srv, int slot, uint64_t session_no, int bearer_too)
{
    gz_conn *c;
    for (c = srv->conns; c; c = c->next) {
        char text[200];
        int n;
        if (!c->stream || c->state != CS_STREAM || c->close_after) continue;
        if (slot >= 0 && !(c->stream_session == slot && c->stream_session_no == session_no)) continue;
        if (slot < 0 && !(bearer_too && c->stream_session < 0)) continue;
        srv->seq++;
        srv->ev[srv->seq % GZ_EVENTS_KEPT].seq = srv->seq;    /* a gap in the ring: this stream's only */
        srv->ev[srv->seq % GZ_EVENTS_KEPT].topic[0] = 0;
        n = snprintf(text, sizeof text, "id: %s-%llu\nevent: change\ndata: {\"topic\":\"session\",\"seq\":%llu}\n\n",
                     srv->run_id, (unsigned long long)srv->seq, (unsigned long long)srv->seq);
        stream_chunk(srv, c, text, (size_t)n);
        if (gz_out_add(&c->out, "0\r\n\r\n", 5) != 0) c->state = CS_DEAD;
        c->close_after = 1;                             /* closed once written */
    }
}
