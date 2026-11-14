/* The slot stand-in (test builds): in P4.1 a slot's engine is this, in place
 * of the lobby that P4.2 brings. It shows routing reach the right slot, a
 * slot's timers carry its generation, and seats bind connections. Area
 * 0x7e59; it saves nothing. Its notices:
 *   slot-open gen=G host=H     slot-msg gen=G kind=K     slot-peer gen=G up=U
 *   slot-timer gen=G id=I */
#include "internal.h"

#ifdef GZ_TEST_KINDS
#include <string.h>

#define TS_TIMER 0x4c000001u   /* the lobby's first timer id */

static gz_status_t ts_log(const ts_t *s, gz_action_list_t *out, const char *what, const char *k, uint64_t v)
{
    char text[96];
    uint8_t buf[120];
    size_t n = 0, at = 0;
    char d[24];
    int m;
    const char *parts[3] = {what, " gen=", NULL};
    for (int p = 0; p < 2; p++)
        for (const char *q = parts[p]; *q && n + 1 < sizeof text; q++) text[n++] = *q;
    uint64_t vals[2] = {s->gen, v};
    for (int p = 0; p < 2; p++) {
        if (p == 1) {
            if (n + 1 < sizeof text) text[n++] = ' ';
            for (const char *q = k; *q && n + 1 < sizeof text; q++) text[n++] = *q;
            if (n + 1 < sizeof text) text[n++] = '=';
        }
        uint64_t x = vals[p];
        m = 0;
        do {
            d[m++] = (char)('0' + x % 10);
            x /= 10;
        } while (x);
        while (m > 0 && n + 1 < sizeof text) text[n++] = d[--m];
    }
    gz_status_t st = gz_rec_put(buf, sizeof buf, &at, 0, (const uint8_t *)text, n);
    if (st != GZ_OK) return st;
    gz_action_t a = {.kind = GZ_ACTION_NOTIFY};
    a.u.notify.code = GZ_NOTIFY_LOG;
    a.u.notify.bytes.data = buf;
    a.u.notify.bytes.len = at;
    return gz_action_list_add(out, &a);
}

gz_status_t ts_open(ts_t *s, uint16_t gen, int host, const uint8_t scope[32], uint32_t timer_ms, gz_action_list_t *out)
{
    gz_status_t st;
    s->gen = gen;
    s->host = host;
    memcpy(s->scope, scope, 32);
    s->timer_ms = timer_ms;
    if (timer_ms) {
        gz_action_t a = {.kind = GZ_ACTION_SET_TIMER};
        a.u.set_timer.timer_id = TS_TIMER;
        a.u.set_timer.delay_ms = timer_ms;
        if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
    }
    return ts_log(s, out, "slot-open", "host", (uint64_t)host);
}

gz_status_t ts_seat(ts_t *s, const gz_node_id_t *member, int seated, gz_action_list_t *out)
{
    (void)s;
    gz_action_t a = {.kind = GZ_ACTION_SET_SEATED};
    a.u.set_seated.member = *member;
    a.u.set_seated.seated = seated;
    return gz_action_list_add(out, &a);
}

static gz_status_t ts_load(void *e, const gz_record_t *rec, gz_batch_id_t at)
{
    (void)e;
    (void)rec;
    (void)at;
    return GZ_ERR_CORRUPT; /* it saves nothing */
}

static gz_status_t ts_resume(void *e, gz_action_list_t *out, int *more)
{
    (void)e;
    (void)out;
    *more = 0;
    return GZ_OK;
}

static gz_status_t ts_handle(void *e, const gz_event_t *ev, gz_action_list_t *out)
{
    ts_t *s = e;
    switch (ev->kind) {
    case GZ_EVENT_MESSAGE_RECEIVED: return ts_log(s, out, "slot-msg", "kind", ev->u.message.kind);
    case GZ_EVENT_PEER_CONNECTED: return ts_log(s, out, "slot-peer", "up", 1);
    case GZ_EVENT_PEER_DISCONNECTED: return ts_log(s, out, "slot-peer", "up", 0);
    case GZ_EVENT_TIMER_FIRED: return ts_log(s, out, "slot-timer", "id", ev->u.timer.timer_id);
    default: return GZ_OK;
    }
}

static const gz_engine_ops_t TS_OPS = {
    GZ_AREA_TEST_SLOT, ts_load, ts_resume, ts_handle, TS_MAX_STEP_ACTIONS, TS_MAX_STEP_BYTES, TS_MAX_TIMERS,
};

const gz_engine_ops_t *gz_ts_ops(void)
{
    return &TS_OPS;
}
#else
typedef int gz_no_test_slot_in_release_t;
#endif
