/* Small helpers that append actions, shared by the host and the member. */
#include "lobby_internal.h"
#include <string.h>

gz_status_t gz_la_send(gz_action_list_t *o, uint64_t peer, const uint8_t *b, size_t n)
{
    gz_action_t a;
    a.kind = GZ_ACTION_SEND;
    a.u.send.peer_id = peer;
    a.u.send.bytes.data = b;
    a.u.send.bytes.len = n;
    return gz_action_list_add(o, &a);
}

gz_status_t gz_la_save(gz_action_list_t *o, const gz_record_t *r, size_t n)
{
    gz_action_t a;
    memset(&a, 0, sizeof a);
    a.kind = GZ_ACTION_SAVE;
    a.u.save.records = r;
    a.u.save.n_records = n;
    return gz_action_list_add(o, &a);
}

gz_status_t gz_la_save1(gz_action_list_t *o, uint32_t type, const uint8_t *b, size_t n)
{
    gz_record_t r;
    r.type = type;
    r.bytes.data = b;
    r.bytes.len = n;
    return gz_la_save(o, &r, 1);
}

gz_status_t gz_la_timer(gz_action_list_t *o, uint64_t id, uint64_t delay_ms)
{
    gz_action_t a;
    a.kind = GZ_ACTION_SET_TIMER;
    a.u.set_timer.timer_id = id;
    a.u.set_timer.delay_ms = delay_ms;
    return gz_action_list_add(o, &a);
}

gz_status_t gz_la_notify(gz_action_list_t *o, uint32_t code, const uint8_t *b, size_t n)
{
    gz_action_t a;
    a.kind = GZ_ACTION_NOTIFY;
    a.u.notify.code = code;
    a.u.notify.bytes.data = b;
    a.u.notify.bytes.len = n;
    return gz_action_list_add(o, &a);
}

gz_status_t gz_la_refuse(gz_action_list_t *o, uint64_t peer, const char *why)
{
    uint8_t w[96], p[8];
    size_t n = gz_lobby_warning(why, w, sizeof w);
    gz_status_t st = gz_la_send(o, peer, w, n);
    gz_lw_put(p, peer, 8);
    return st != GZ_OK ? st : gz_la_notify(o, GZ_NOTE_CLOSE, p, 8);
}

gz_status_t gz_la_cmd_refused(gz_action_list_t *o, uint8_t cmd, int lobby_state)
{
    uint8_t n[2];
    n[0] = cmd;
    n[1] = (uint8_t)lobby_state;
    return gz_la_notify(o, GZ_NOTE_COMMAND_REFUSED, n, 2);
}

void gz_la_tagged(const char *tag, const uint8_t *d, size_t len, uint8_t out[32])
{
    tr_sha256_t s;
    tr_tagged_init(&s, tag);
    tr_sha256_write(&s, d, len);
    tr_sha256_done(&s, out);
}

/* A verified message: decoded, and signed by `key` when it carries record 240. */
int gz_la_verified(const gz_lobby_crypto_t *c, const uint8_t *msg, const gz_lobby_msg_t *m,
                   const uint8_t key[33])
{
    uint8_t h[32];
    if (!m->sig) return 0;
    gz_lobby_msg_hash(msg, m, h);
    return c->verify(c->ctx, key, h, m->sig) == 1;
}

/* Append a u16 length then the bytes. */
size_t gz_la_put_blob(uint8_t *p, const uint8_t *b, size_t n)
{
    gz_lw_put(p, n, 2);
    if (n) memcpy(p + 2, b, n);
    return 2 + n;
}

/* Read a u16-length blob at *at; 1 and advances, or 0. */
int gz_la_get_blob(const uint8_t *p, size_t len, size_t *at, const uint8_t **b, size_t *n)
{
    if (len - *at < 2) return 0;
    *n = (size_t)gz_lw_get(p + *at, 2);
    if (len - *at - 2 < *n) return 0;
    *b = p + *at + 2;
    *at += 2 + *n;
    return 1;
}

/* A FREEZE record: check_id, version, digest, then the signed ready_check
 * that names exactly those, and nothing after it. */
int gz_la_freeze_ok(const uint8_t *p, size_t len)
{
    const uint8_t *b;
    size_t at = 68, n;
    gz_lobby_msg_t m;
    if (len < 70 || !gz_la_get_blob(p, len, &at, &b, &n) || at != len ||
        gz_lobby_decode(b, n, &m) != GZ_DEC_OK || m.kind != GZ_KIND_READY_CHECK)
        return 0;
    return memcmp(m.check_id, p, 32) == 0 && m.version == gz_lw_get(p + 32, 4) &&
           memcmp(m.current_digest, p + 36, 32) == 0;
}

int gz_lobby_start_rule(uint16_t target, uint16_t minimum, uint64_t deadline_s, uint64_t now_s,
                        uint32_t ready)
{
    if (ready >= target) return GZ_RULE_CHECK;
    if (now_s < deadline_s) return GZ_RULE_WAIT;
    return ready >= minimum ? GZ_RULE_CHECK : GZ_RULE_CANCEL;
}

int gz_lobby_choose(uint16_t target, uint16_t minimum, const uint16_t *mins, int n, int *chosen)
{
    int k = 0, i, j, dropped;
    for (i = 0; i < n && k < target; i++) chosen[k++] = i;
    do {
        dropped = 0;
        for (i = 0, j = 0; i < k; i++) {
            if (mins[chosen[i]] > k) { dropped = 1; continue; }
            chosen[j++] = chosen[i];
        }
        k = j;
    } while (dropped);
    return k >= minimum ? k : -1;
}
