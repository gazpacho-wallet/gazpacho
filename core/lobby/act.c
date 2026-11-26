/* Small helpers that append actions and build or read records, shared by the
 * host and the member. */
#include "lobby_internal.h"
#include <string.h>

/* ---- the table of largest records (lobby.h) ----------------------------- */

static const gz_lobby_rec_max_t REC_MAX[] = {
    {GZ_REC_LOBBY_OPENED, GZ_LOBBY_REC_MAX_OPENED, "lobby_opened"},
    {GZ_REC_TERMS_VERSION, GZ_LOBBY_REC_MAX_VERSION, "terms_version"},
    {GZ_REC_SEAT, GZ_LOBBY_REC_MAX_SEAT, "seat"},
    {GZ_REC_FREEZE, GZ_LOBBY_REC_MAX_FREEZE, "freeze"},
    {GZ_REC_LOBBY_ENDED, GZ_LOBBY_REC_MAX_ENDED, "lobby_ended"},
    {GZ_REC_TERMS_RECEIVED, GZ_LOBBY_REC_MAX_TERMS, "terms_received"},
    {GZ_REC_JOINED, GZ_LOBBY_REC_MAX_JOINED, "joined"},
    {GZ_REC_READY_SENT, GZ_LOBBY_REC_MAX_READY_SENT, "ready_sent"},
    {GZ_REC_HOST_FAULT, GZ_LOBBY_REC_MAX_HOST_FAULT, "host_fault"},
    {GZ_REC_START_SENT, GZ_LOBBY_REC_MAX_START_SENT, "start_sent"},
    {GZ_REC_START_RECEIVED, GZ_LOBBY_REC_MAX_START_RECEIVED, "start_received"},
    {GZ_REC_LOBBY_STATE, GZ_LOBBY_REC_MAX_STATE, "lobby_state"},
    {GZ_REC_SEAT_KEY, GZ_LOBBY_REC_MAX_SEAT_KEY, "seat_key"},
};
#define N_REC_MAX (sizeof REC_MAX / sizeof REC_MAX[0])

/* GZ_LOBBY_REC_MAX is the largest row, and a field's length fits the three
 * bytes GZ_LOBBY_FIELD allows for it. */
_Static_assert(GZ_LOBBY_REC_MAX >= GZ_LOBBY_REC_MAX_OPENED && GZ_LOBBY_REC_MAX >= GZ_LOBBY_REC_MAX_VERSION &&
               GZ_LOBBY_REC_MAX >= GZ_LOBBY_REC_MAX_SEAT && GZ_LOBBY_REC_MAX >= GZ_LOBBY_REC_MAX_FREEZE &&
               GZ_LOBBY_REC_MAX >= GZ_LOBBY_REC_MAX_ENDED && GZ_LOBBY_REC_MAX >= GZ_LOBBY_REC_MAX_JOINED &&
               GZ_LOBBY_REC_MAX >= GZ_LOBBY_REC_MAX_READY_SENT && GZ_LOBBY_REC_MAX >= GZ_LOBBY_REC_MAX_HOST_FAULT &&
               GZ_LOBBY_REC_MAX >= GZ_LOBBY_REC_MAX_START_RECEIVED && GZ_LOBBY_REC_MAX >= GZ_LOBBY_REC_MAX_STATE,
               "GZ_LOBBY_REC_MAX is the largest record");
_Static_assert(GZ_LOBBY_MAX_SEATS * GZ_LOBBY_START_ITEM <= 0xffffu, "a start_sent list fits a 16-bit length");
/* journal.md 3: a batch is one journal entry of at most 8 MiB of payload. A lobby step saves no more than a
 * record for each seat and a few of its own; even at the largest record each (start_sent, 13,496 bytes after
 * K1), that is under half a MiB. */
_Static_assert((GZ_LOBBY_MAX_SEATS + 8u) * (GZ_LOBBY_REC_MAX + 8u) <= 8u * 1024u * 1024u,
               "a lobby batch fits one journal entry (8 MiB)");
_Static_assert(GZ_LOBBY_MAX_ADDRESS == GZ_CONNECT_MAX_ADDRESS, "a member's address is a CONNECT address");
_Static_assert(GZ_LOBBY_MAX_ENV <= GZ_SEND_MAX_RECORDS, "an envelope's records fit a SEND");

/* The even fields each record type has, beside the scope (field 2): bit
 * t / 2 for field t. The layouts are at the top of host.c and member.c. */
#define FLD(t) ((uint32_t)1 << ((t) / 2))
static const struct { uint32_t type, fields; } REC_FIELDS[] = {
    {GZ_REC_LOBBY_OPENED, FLD(4) | FLD(6) | FLD(8) | FLD(10)},
    {GZ_REC_TERMS_VERSION, FLD(4) | FLD(6)},
    {GZ_REC_SEAT, FLD(4) | FLD(6) | FLD(10) | FLD(12) | FLD(14) | FLD(16) | FLD(18) | FLD(20)},   /* 8 gone (K1) */
    {GZ_REC_FREEZE, FLD(4) | FLD(6) | FLD(8) | FLD(10)},
    {GZ_REC_LOBBY_ENDED, FLD(4) | FLD(6) | FLD(8) | FLD(10)},
    {GZ_REC_TERMS_RECEIVED, FLD(4) | FLD(6) | FLD(8) | FLD(10)},
    {GZ_REC_JOINED, FLD(4)},
    {GZ_REC_READY_SENT, FLD(4) | FLD(6)},
    {GZ_REC_HOST_FAULT, FLD(4) | FLD(6) | FLD(8)},
    {GZ_REC_START_SENT, FLD(4) | FLD(6) | FLD(8)},
    {GZ_REC_START_RECEIVED, FLD(4)},
    {GZ_REC_LOBBY_STATE, FLD(4) | FLD(6)},
    {GZ_REC_SEAT_KEY, FLD(4) | FLD(6) | FLD(8) | FLD(10)},
};
_Static_assert(sizeof REC_FIELDS / sizeof REC_FIELDS[0] == N_REC_MAX, "one row of fields for each record type");

int gz_lf_known(uint32_t type, const gz_lf_t *f)
{
    uint32_t known = 0;
    unsigned t;
    size_t i;
    for (i = 0; i < N_REC_MAX; i++)
        if (REC_FIELDS[i].type == type) known = REC_FIELDS[i].fields;
    for (t = 4; t <= GZ_LF_MAX; t += 2)
        if (f->v[t / 2] && !(known & FLD(t))) return 0;
    return 1;
}

const gz_lobby_rec_max_t *gz_lobby_rec_table(size_t *n)
{
    if (n) *n = N_REC_MAX;
    return REC_MAX;
}

uint32_t gz_lobby_rec_max(uint32_t type)
{
    size_t i;
    for (i = 0; i < N_REC_MAX; i++)
        if (REC_MAX[i].type == type) return REC_MAX[i].max;
    return 0;
}

/* ---- actions ------------------------------------------------------------ */

gz_status_t gz_la_send(gz_action_list_t *o, const gz_link_t *link, const uint8_t *env, size_t n)
{
    gz_action_t a;
    if (n < GZ_LOBBY_ENV_HDR) return GZ_ERR_BUG;
    memset(&a, 0, sizeof a);
    a.kind = GZ_ACTION_SEND;
    a.u.send.link = *link;
    a.u.send.kind = (uint16_t)gz_lw_get(env + 4, 2);
    memcpy(a.u.send.scope, env + 6, 32);
    a.u.send.records.data = env + GZ_LOBBY_ENV_HDR;
    a.u.send.records.len = n - GZ_LOBBY_ENV_HDR;
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
    memset(&a, 0, sizeof a);
    a.kind = GZ_ACTION_SET_TIMER;
    a.u.set_timer.timer_id = id;
    a.u.set_timer.delay_ms = delay_ms;
    return gz_action_list_add(o, &a);
}

gz_status_t gz_la_notify(gz_action_list_t *o, uint32_t code, const uint8_t *b, size_t n)
{
    gz_action_t a;
    memset(&a, 0, sizeof a);
    a.kind = GZ_ACTION_NOTIFY;
    a.u.notify.code = code;
    a.u.notify.bytes.data = b;
    a.u.notify.bytes.len = n;
    return gz_action_list_add(o, &a);
}

gz_status_t gz_la_refuse(gz_action_list_t *o, const gz_link_t *link)
{
    gz_action_t a;
    memset(&a, 0, sizeof a);
    a.kind = GZ_ACTION_DISCONNECT;
    a.u.disconnect.link = *link;
    a.u.disconnect.why = GZ_DISCONNECT_REFUSED;
    return gz_action_list_add(o, &a);
}

gz_status_t gz_la_seated(gz_action_list_t *o, const uint8_t key[33], int seated)
{
    gz_action_t a;
    memset(&a, 0, sizeof a);
    a.kind = GZ_ACTION_SET_SEATED;
    memcpy(a.u.set_seated.member.key, key, 33);
    a.u.set_seated.seated = seated ? 1 : 0;
    return gz_action_list_add(o, &a);
}

gz_status_t gz_la_cmd_refused(gz_action_list_t *o, uint8_t cmd, int lobby_state)
{
    uint8_t n[2];
    n[0] = cmd;
    n[1] = (uint8_t)lobby_state;
    return gz_la_notify(o, GZ_NOTE_COMMAND_REFUSED, n, 2);
}

gz_status_t gz_la_no_key(gz_action_list_t *o, uint32_t which)
{
    uint8_t k = (uint8_t)which;
    return gz_la_notify(o, GZ_NOTE_NO_KEY, &k, 1);
}

gz_status_t gz_la_sign_env(gz_lobby_enc_t *e, const gz_lobby_crypto_t *c, uint32_t which, gz_action_list_t *o,
                           size_t *len)
{
    *len = 0;
    if (e->bad) return GZ_ERR_BUG;                                     /* RULE-LOBBY:TOO_LARGE_NOT_NO_KEY */
    *len = gz_lobby_enc_sign(e, c, which);
    if (*len) return GZ_OK;
    if (e->bad) return GZ_ERR_BUG;                                     /* the signature record did not fit */
    return gz_la_no_key(o, which);
}

void gz_la_tagged(const char *tag, const uint8_t *d, size_t len, uint8_t out[32])
{
    tr_sha256_t s;
    tr_tagged_init(&s, tag);
    tr_sha256_write(&s, d, len);
    tr_sha256_done(&s, out);
}

int gz_la_verified(const gz_lobby_crypto_t *c, const gz_lobby_msg_t *m, const uint8_t key[33])
{
    uint8_t h[32];
    if (!m->sig) return 0;
    gz_lobby_msg_hash(m, h);
    return c->verify(c->ctx, key, h, m->sig) == 1;
}

size_t gz_la_env(uint16_t kind, const uint8_t scope[32], const uint8_t *records, size_t len, uint8_t *out,
                 size_t cap)
{
    gz_lobby_enc_t e;
    if (cap < GZ_LOBBY_ENV_HDR || len > cap - GZ_LOBBY_ENV_HDR) return 0;
    gz_lobby_enc_start(&e, out, cap, kind, scope);
    if (len) memcpy(out + GZ_LOBBY_ENV_HDR, records, len);
    return GZ_LOBBY_ENV_HDR + len;
}

size_t gz_la_status(const uint8_t scope[32], uint8_t lobby_state, uint8_t seat_state, uint32_t version,
                    uint16_t joined, uint16_t ready, int with_reason, uint16_t reason,
                    uint8_t buf[GZ_LOBBY_STATUS_MAX])
{
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, buf, GZ_LOBBY_STATUS_MAX, GZ_KIND_LOBBY_STATUS, scope);
    gz_lobby_enc_u8(&e, 2, lobby_state);
    gz_lobby_enc_u8(&e, 4, seat_state);
    gz_lobby_enc_u32(&e, 6, version);
    gz_lobby_enc_u16(&e, 8, joined);
    gz_lobby_enc_u16(&e, 10, ready);
    if (with_reason) gz_lobby_enc_u16(&e, 13, reason);
    return gz_lobby_enc_done(&e);
}

gz_status_t gz_lobby_host_unknown(const gz_link_t *link, const uint8_t scope[32], gz_action_list_t *out)
{
    uint8_t buf[GZ_LOBBY_STATUS_MAX];
    if (!link || !scope || !out) return GZ_ERR_ARGUMENT;
    return gz_la_send(out, link, buf, gz_la_status(scope, GZ_LOBBY_UNKNOWN, GZ_SEAT_NONE, 0, 0, 0, 0, 0, buf));
}

gz_status_t gz_lobby_host_ended(const gz_link_t *link, const uint8_t scope[32], uint8_t final_state,
                                uint16_t reason, const uint8_t *cancel, size_t cancel_len,
                                gz_action_list_t *out)
{
    uint8_t buf[GZ_LOBBY_STATUS_MAX];
    gz_lobby_msg_t m;
    if (!link || !scope || !out) return GZ_ERR_ARGUMENT;
    TRY(gz_la_send(out, link, buf, gz_la_status(scope, final_state, GZ_SEAT_NONE, 0, 0, 0, reason != 0, reason, buf)));
    /* Only a cancel of this lobby is sent on: the bytes come from storage. */
    if (!cancel || !cancel_len || cancel_len > GZ_LOBBY_MAX_SAVED_MSG ||
        gz_lobby_decode_env(cancel, cancel_len, &m) != GZ_DEC_OK || m.kind != GZ_KIND_CANCEL ||
        memcmp(m.scope, scope, 32) != 0)
        return GZ_OK;
    return gz_la_send(out, link, cancel, cancel_len);
}

/* ---- records ------------------------------------------------------------ */

void gz_lr_start(gz_lr_t *w, uint8_t *buf, size_t cap, const uint8_t scope[32])
{
    w->b = buf; w->cap = cap; w->at = 0; w->bad = 0;
    gz_lr_put(w, 2, scope, 32);
}

void gz_lr_put(gz_lr_t *w, uint64_t type, const uint8_t *v, size_t n)
{
    uint8_t h[18];
    size_t hn;
    if (w->bad) return;
    hn = gz_lw_put_bigsize(h, type);
    hn += gz_lw_put_bigsize(h + hn, n);
    if (w->cap - w->at < hn || w->cap - w->at - hn < n) { w->bad = 1; return; }
    memcpy(w->b + w->at, h, hn);
    if (n) memcpy(w->b + w->at + hn, v, n);
    w->at += hn + n;
}

void gz_lr_int(gz_lr_t *w, uint64_t type, uint64_t v, size_t width)
{
    uint8_t b[8];
    gz_lw_put(b, v, width);
    gz_lr_put(w, type, b, width);
}

size_t gz_lr_done(const gz_lr_t *w) { return w->bad ? 0 : w->at; }

gz_status_t gz_lr_save(gz_action_list_t *o, uint32_t type, const gz_lr_t *w)
{
    if (w->bad) return GZ_ERR_BUG;
    return gz_la_save1(o, type, w->b, w->at);
}

int gz_lf_read(const uint8_t *p, size_t len, const uint8_t *scope, gz_lf_t *f)
{
    gz_lw_tlv_t t;
    int r;
    memset(f, 0, sizeof *f);
    if (!p && len) return 0;
    memset(&t, 0, sizeof t);
    t.p = p;
    t.len = len;
    while ((r = gz_lw_tlv_next(&t)) == 1) {
        if (t.type % 2) continue;                     /* an odd field: later versions' */
        if (t.type < 2 || t.type > GZ_LF_MAX) return 0;
        f->v[t.type / 2] = t.v;
        f->n[t.type / 2] = t.vlen;
    }
    if (r < 0 || !f->v[1] || f->n[1] != 32) return 0;
    return !scope || memcmp(f->v[1], scope, 32) == 0;
}

const uint8_t *gz_lf_fixed(const gz_lf_t *f, unsigned type, size_t n)
{
    return f->v[type / 2] && f->n[type / 2] == n ? f->v[type / 2] : NULL;
}

int gz_lf_blob(const gz_lf_t *f, unsigned type, size_t max, const uint8_t **v, size_t *n)
{
    if (!f->v[type / 2] || f->n[type / 2] > max) return 0;
    *v = f->v[type / 2];
    *n = f->n[type / 2];
    return 1;
}

int gz_lobby_rec_scope(const gz_record_t *rec, uint8_t scope[32])
{
    gz_lf_t f;
    if (!rec || !scope || !gz_lobby_rec_max(rec->type) || rec->bytes.len > gz_lobby_rec_max(rec->type) ||
        !gz_lf_read(rec->bytes.data, rec->bytes.len, NULL, &f) || !gz_lf_known(rec->type, &f))
        return 0;
    memcpy(scope, f.v[1], 32);
    return 1;
}

int gz_lobby_rec_ended(const gz_record_t *rec, uint8_t scope[32], uint8_t *state, uint16_t *reason,
                       const uint8_t **cancel, size_t *cancel_len)
{
    gz_lf_t f;
    const uint8_t *s, *r;
    if (!rec || !scope || !state || !reason || !cancel || !cancel_len || rec->type != GZ_REC_LOBBY_ENDED ||
        rec->bytes.len > GZ_LOBBY_REC_MAX_ENDED || !gz_lf_read(rec->bytes.data, rec->bytes.len, NULL, &f) ||
        !gz_lf_known(rec->type, &f) || !(s = gz_lf_fixed(&f, 4, 1)) || !(r = gz_lf_fixed(&f, 6, 2)))
        return 0;
    *cancel = NULL;
    *cancel_len = 0;
    if (f.v[4] && !gz_lf_blob(&f, 8, GZ_LOBBY_MAX_SAVED_MSG, cancel, cancel_len)) return 0;
    memcpy(scope, f.v[1], 32);
    *state = s[0];
    *reason = (uint16_t)gz_lw_get(r, 2);
    return 1;
}

/* A FREEZE record: 4 check_id, 6 version, 8 digest, 10 the signed
 * ready_check that names exactly those. */
int gz_la_freeze_ok(const gz_lf_t *f)
{
    const uint8_t *check = gz_lf_fixed(f, 4, 32), *ver = gz_lf_fixed(f, 6, 4), *dig = gz_lf_fixed(f, 8, 32), *b;
    size_t n;
    gz_lobby_msg_t m;
    if (!check || !ver || !dig || !gz_lf_blob(f, 10, GZ_LOBBY_MAX_SAVED_MSG, &b, &n) ||
        gz_lobby_decode_env(b, n, &m) != GZ_DEC_OK || m.kind != GZ_KIND_READY_CHECK)
        return 0;
    return memcmp(m.check_id, check, 32) == 0 && m.version == gz_lw_get(ver, 4) &&
           memcmp(m.current_digest, dig, 32) == 0 && memcmp(m.scope, f->v[1], 32) == 0;
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
