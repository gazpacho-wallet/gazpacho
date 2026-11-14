/* The test engine: the old placeholder ping behind the composite. See
 * core/node/include/gazpacho/test_engine.h. Test builds only. */
#include "internal.h"

#ifdef GZ_TEST_KINDS
#include "gazpacho/test_engine.h"
#include <string.h>

/* ---- small helpers ------------------------------------------------------ */

typedef struct {
    char s[120];
    size_t n;
} text_t;

static void t_str(text_t *t, const char *s)
{
    while (*s && t->n + 1 < sizeof t->s) t->s[t->n++] = *s++;
    t->s[t->n] = 0;
}

static void t_u64(text_t *t, uint64_t v)
{
    char d[24];
    int k = 0;
    do {
        d[k++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (k > 0 && t->n + 1 < sizeof t->s) t->s[t->n++] = d[--k];
    t->s[t->n] = 0;
}

static void t_hex16(text_t *t, uint16_t v)
{
    static const char hex[] = "0123456789abcdef";
    t_str(t, "0x");
    for (int i = 3; i >= 0 && t->n + 1 < sizeof t->s; i--) t->s[t->n++] = hex[(v >> (4 * i)) & 15];
    t->s[t->n] = 0;
}

static gz_status_t notify(gz_action_list_t *out, uint32_t code, const uint8_t *b, size_t n)
{
    gz_action_t a = {.kind = GZ_ACTION_NOTIFY};
    a.u.notify.code = code;
    a.u.notify.bytes.data = b;
    a.u.notify.bytes.len = n;
    return gz_action_list_add(out, &a);
}

static gz_status_t log_text(gz_action_list_t *out, const text_t *t)
{
    uint8_t buf[140];
    size_t at = 0;
    gz_status_t st = gz_rec_put(buf, sizeof buf, &at, 0, (const uint8_t *)t->s, t->n);
    return st == GZ_OK ? notify(out, GZ_NOTIFY_LOG, buf, at) : st;
}

static gz_status_t save1(te_t *t, uint16_t kind, const uint8_t *b, size_t n, gz_action_list_t *out)
{
    gz_record_t r = {((uint32_t)t->area << 16) | kind, {b, n}};
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = &r;
    a.u.save.n_records = 1;
    return gz_action_list_add(out, &a);
}

static gz_status_t timer(gz_action_list_t *out, uint64_t id, uint64_t ms)
{
    gz_action_t a = {.kind = GZ_ACTION_SET_TIMER};
    a.u.set_timer.timer_id = id;
    a.u.set_timer.delay_ms = ms;
    return gz_action_list_add(out, &a);
}

/* The view object: id "test-<area>", version = pings saved (node.h rules 7, 8). */
static gz_status_t view(te_t *t, gz_action_list_t *out)
{
    uint8_t buf[64], v[8];
    char id[10] = "test-";
    static const char hex[] = "0123456789abcdef";
    size_t at = 0;
    for (int i = 0; i < 4; i++) id[5 + i] = hex[(t->area >> (4 * (3 - i))) & 15];
    gz_put_u64(v, t->saved);
    gz_status_t st = gz_rec_put(buf, sizeof buf, &at, GZ_VIEW_REC_ID, (const uint8_t *)id, 9);
    if (st == GZ_OK) st = gz_rec_put(buf, sizeof buf, &at, GZ_VIEW_REC_VERSION, v, 8);
    return st == GZ_OK ? notify(out, GZ_NOTIFY_VIEW(GZ_VIEW_STATUS), buf, at) : st;
}

/* SEND a test message on `link`: record 1 tag and body, record 3 the area,
 * record 5 `pad` zero bytes. The records are built in the list's own bytes
 * would be simplest; a stack buffer of the largest one is used instead, so
 * the pad comes from a second copy. */
static gz_status_t send_msg(te_t *t, const gz_link_t *link, const char tag[4], const uint8_t *body, size_t blen,
                            uint32_t pad, gz_action_list_t *out)
{
    static const uint8_t zeros[256] = {0};
    uint8_t head[4 + 8 + 64 + 32], area[2];
    size_t at = 0, i;
    gz_status_t st;
    if (blen > 72) return GZ_ERR_BUG;
    /* Reserve the whole stream in the list's byte block, then write it. */
    uint8_t rec[4 + 8 + 64];
    memcpy(rec, tag, 4);
    if (blen) memcpy(rec + 4, body, blen);
    gz_put_u16(area, t->area);
    if ((st = gz_rec_put(head, sizeof head, &at, GZ_TE_REC_TAG, rec, 4 + blen)) != GZ_OK) return st;
    if ((st = gz_rec_put(head, sizeof head, &at, GZ_TE_REC_AREA, area, 2)) != GZ_OK) return st;
    gz_action_t a = {.kind = GZ_ACTION_SEND};
    a.u.send.link = *link;
    a.u.send.kind = GZ_TE_KIND;
    if (!pad) {
        a.u.send.records.data = head;
        a.u.send.records.len = at;
        return gz_action_list_add(out, &a);
    }
    /* With padding: add the SEND with an empty stream, then grow it in the
     * list's byte block (its records are the last bytes the list used). */
    uint8_t ph[9 + 9];
    size_t hn = gz_bigsize_put(GZ_TE_REC_PAD, ph);
    hn += gz_bigsize_put(pad, ph + hn);
    size_t total = at + hn + pad;
    if (out->count >= out->n_slots || out->used > out->n_bytes || total > out->n_bytes - out->used)
        return GZ_ERR_NO_SPACE;
    uint8_t *dst = out->bytes + out->used;
    memcpy(dst, head, at);
    memcpy(dst + at, ph, hn);
    for (i = 0; i < pad; i += sizeof zeros) {
        size_t k = pad - i < sizeof zeros ? pad - i : sizeof zeros;
        memcpy(dst + at + hn + i, zeros, k);
    }
    out->used += total;
    a.u.send.records.data = dst;
    a.u.send.records.len = total;
    out->slots[out->count++] = a;
    return GZ_OK;
}

static int key_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static int link_eq(const gz_link_t *a, const gz_link_t *b)
{
    return key_eq(a->local.key, b->local.key, 33) && key_eq(a->remote.key, b->remote.key, 33);
}

static int add_pending(te_t *t, uint64_t serial, const gz_link_t *link, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < TE_MAX_PENDING; i++) {
        te_pending_t *q = &t->pending[i];
        if (q->used) continue;
        q->used = 1;
        q->serial = serial;
        q->link = *link;
        q->len = (uint8_t)n;
        if (n) memcpy(q->payload, p, n);
        t->n_pending++;
        return 1;
    }
    return 0;
}

static te_pending_t *find_pending(te_t *t, uint64_t serial, const gz_link_t *link)
{
    for (size_t i = 0; i < TE_MAX_PENDING; i++)
        if (t->pending[i].used && t->pending[i].serial == serial && (!link || link_eq(&t->pending[i].link, link)))
            return &t->pending[i];
    return NULL;
}

/* ---- the engine --------------------------------------------------------- */

gz_status_t te_init(te_t *t, uint16_t area, int host, const gz_ports_t *ports, const gz_key_port_t *keys,
                    const te_hooks_t *hooks, uint64_t incarnation)
{
    memset(t, 0, sizeof *t);
    t->incarnation = incarnation;
    t->area = area;
    t->host = host;
    t->ports = *ports;
    t->keys = *keys;
    t->hooks = *hooks;
    t->next_serial = 1;
    return GZ_OK;
}

static gz_status_t te_load(void *e, const gz_record_t *rec, gz_batch_id_t at)
{
    te_t *t = e;
    const uint8_t *b = rec->bytes.data;
    size_t n = rec->bytes.len;
    (void)at;
    switch (rec->type & 0xffffu) {
    case GZ_TE_PING: {
        gz_link_t l;
        if (n < GZ_TE_PING_HEADER || n > GZ_TE_PING_HEADER + GZ_TE_MAX_PAYLOAD) return GZ_ERR_CORRUPT;
        memcpy(l.local.key, b + 8, 33);
        memcpy(l.remote.key, b + 41, 33);
        uint64_t serial = gz_get_u64(b + 74);
        if ((serial & 0xffffffffu) >= t->next_serial) t->next_serial = (serial & 0xffffffffu) + 1;
        t->saved++;
        /* Saved only while there was room, so it fits again. */
        if (!add_pending(t, serial, &l, b + GZ_TE_PING_HEADER, n - GZ_TE_PING_HEADER)) return GZ_ERR_CORRUPT;
        return GZ_OK;
    }
    case GZ_TE_ACKED:
        if (n == 0 || n % 8) return GZ_ERR_CORRUPT;
        for (size_t k = 0; k < n; k += 8) {
            te_pending_t *q = find_pending(t, gz_get_u64(b + k), NULL);
            if (q) {
                q->used = 0;
                t->n_pending--;
            }
        }
        return GZ_OK;
    case GZ_TE_CONNECT: {
        if (n < 41 + 1 || n > 41 + 64) return GZ_ERR_CORRUPT;
        te_target_t *g = NULL;
        for (size_t i = 0; i < t->n_targets; i++)
            if (key_eq(t->targets[i].host.key, b, 33)) g = &t->targets[i]; /* a later record: the address replaced */
        if (!g) {
            if (t->n_targets == TE_MAX_TARGETS) return GZ_ERR_CORRUPT;
            g = &t->targets[t->n_targets++];
        }
        memcpy(g->host.key, b, 33);
        g->epoch = gz_get_u32(b + 33);
        g->index = gz_get_u32(b + 37);
        g->addr_len = (uint8_t)(n - 41);
        memcpy(g->addr, b + 41, n - 41);
        return GZ_OK;
    }
    case GZ_TE_HANDOFF_A:
    case GZ_TE_HANDOFF_B:
    case 0x0002u: /* contract v1's "sent" and restore records, retired */
    case 0x0003u:
        return GZ_OK;
    }
    return GZ_ERR_CORRUPT;
}

static gz_status_t te_connect(te_t *t, const te_target_t *g, gz_action_list_t *out)
{
    (void)t;
    gz_action_t a = {.kind = GZ_ACTION_CONNECT};
    a.u.connect.host = g->host;
    a.u.connect.address.data = g->addr;
    a.u.connect.address.len = g->addr_len;
    a.u.connect.key_epoch = g->epoch;
    a.u.connect.key_index = g->index;
    return gz_action_list_add(out, &a);
}

/* The start: CONNECT again (rule 4) and the view (rule 7). Nothing is saved
 * and nothing is resent: replies go out again when the peer asks (rule 6). */
static gz_status_t te_resume(void *e, gz_action_list_t *out, int *more)
{
    te_t *t = e;
    gz_status_t st = GZ_OK;
    *more = 0;
    for (size_t i = 0; i < t->n_targets && st == GZ_OK; i++) st = te_connect(t, &t->targets[i], out);
    return st == GZ_OK ? view(t, out) : st;
}

/* The next replies on one link being answered, oldest first, within one
 * step's bounds. */
static gz_status_t resend_chunk(te_t *t, te_limit_t *l, gz_action_list_t *out)
{
    size_t sent = 0, bytes = 0;
    gz_status_t st;
    for (;;) {
        te_pending_t *best = NULL;
        for (size_t i = 0; i < TE_MAX_PENDING; i++) {
            te_pending_t *q = &t->pending[i];
            if (q->used && q->serial > l->after && link_eq(&q->link, &l->link) && (!best || q->serial < best->serial))
                best = q;
        }
        if (!best) {
            l->resending = 0;
            return GZ_OK;
        }
        if (sent == GZ_TE_RESEND_CHUNK || bytes + 100 + t->pad > TE_CHUNK_BYTES) return GZ_OK;
        uint8_t body[8 + 64];
        gz_put_u64(body, best->serial);
        memcpy(body + 8, best->payload, best->len);
        if ((st = send_msg(t, &best->link, "GZPO", body, 8 + (size_t)best->len, t->pad, out)) != GZ_OK) return st;
        l->after = best->serial;
        sent++;
        bytes += 100 + t->pad;
    }
}

/* One chunk for one of the links still being answered (round-robin: one
 * state change per event, 8.3), and the continuation timer while any is. */
static gz_status_t resend_step(te_t *t, te_limit_t *first, gz_action_list_t *out)
{
    gz_status_t st = GZ_OK;
    te_limit_t *l = first;
    for (size_t k = 0; !l && k < TE_MAX_LIMITS; k++) {
        te_limit_t *c = &t->limits[(t->resend_turn + k) % TE_MAX_LIMITS];
        if (c->used && c->resending) {
            l = c;
            t->resend_turn = (t->resend_turn + k + 1) % TE_MAX_LIMITS;
        }
    }
    if (l) st = resend_chunk(t, l, out);
    for (size_t i = 0; st == GZ_OK && i < TE_MAX_LIMITS; i++)
        if (t->limits[i].used && t->limits[i].resending) return timer(out, 2, 0);
    return st;
}

/* The link's entry if a hello on it may be answered now: at most one answer
 * a second per link (per link, not per connection). NULL if not, or if every
 * entry is still sending an answer. */
static te_limit_t *hello_allowed(te_t *t, const gz_link_t *link)
{
    uint64_t now = t->ports.clock.now_ms(t->ports.clock.ctx);
    te_limit_t *spare = NULL;
    for (size_t i = 0; i < TE_MAX_LIMITS; i++) {
        te_limit_t *l = &t->limits[i];
        if (l->used && link_eq(&l->link, link)) {
            if (now >= l->last_ms && now - l->last_ms < 1000) return NULL;
            l->last_ms = now;
            return l;
        }
        if (l->used && l->resending) continue;
        if (!spare || !l->used || (spare->used && l->last_ms < spare->last_ms)) spare = l;
    }
    if (!spare) return NULL;
    memset(spare, 0, sizeof *spare);
    spare->used = 1;
    spare->link = *link;
    spare->last_ms = now;
    return spare;
}

static gz_status_t on_message(te_t *t, const gz_event_t *ev, gz_action_list_t *out)
{
    gz_bytes_t r;
    const gz_link_t *link = &ev->u.message.link;
    gz_status_t st;
    if (gz_rec_find(ev->u.message.records, GZ_TE_REC_TAG, &r) != 1 || r.len < 4) return GZ_OK;
    const uint8_t *body = r.data + 4;
    size_t blen = r.len - 4;
    if (!memcmp(r.data, "GZPI", 4)) {
        uint8_t rec[GZ_TE_PING_HEADER + GZ_TE_MAX_PAYLOAD], reply[8 + GZ_TE_MAX_PAYLOAD];
        if (blen > GZ_TE_MAX_PAYLOAD) return GZ_OK;
        if (t->n_pending == TE_MAX_PENDING) {
            /* A full table is a peer's doing: counted, never an error. */
            text_t x = {{0}, 0};
            t->dropped++;
            t_str(&x, "test-ping-dropped area=");
            t_hex16(&x, t->area);
            return log_text(out, &x);
        }
        /* The serial: the incarnation, then a count. A restore can rewind the
         * count (it is read back from the journal) but never the incarnation
         * (ports.h), so an acknowledgement still in flight for a reply of
         * before the restore never matches a later ping's serial. */
        uint64_t serial = (t->incarnation & 0xffffffffu) << 32 | (t->next_serial & 0xffffffffu);
        gz_put_u64(rec, t->ports.clock.now_ms(t->ports.clock.ctx));
        memcpy(rec + 8, link->local.key, 33);
        memcpy(rec + 41, link->remote.key, 33);
        gz_put_u64(rec + 74, serial);
        if (blen) memcpy(rec + GZ_TE_PING_HEADER, body, blen);
        if ((st = save1(t, GZ_TE_PING, rec, GZ_TE_PING_HEADER + blen, out)) != GZ_OK) return st;
        gz_put_u64(reply, serial);
        if (blen) memcpy(reply + 8, body, blen);
        if ((st = send_msg(t, link, "GZPO", reply, 8 + blen, t->pad, out)) != GZ_OK) return st;
        t->next_serial++;
        t->saved++;
        add_pending(t, serial, link, body, blen);
        return view(t, out);
    }
    if (!memcmp(r.data, "GZPO", 4)) {
        text_t x = {{0}, 0};
        if (blen < 8) return GZ_OK;
        st = send_msg(t, link, "GZPA", body, 8, 0, out);
        if (st != GZ_OK) return st;
        t_str(&x, "test-reply area=");
        t_hex16(&x, t->area);
        t_str(&x, " serial=");
        t_u64(&x, gz_get_u64(body) & 0xffffffffu);
        t_str(&x, " incarnation=");
        t_u64(&x, gz_get_u64(body) >> 32);
        return log_text(out, &x);
    }
    if (!memcmp(r.data, "GZPA", 4)) {
        if (blen != 8) return GZ_OK;
        uint64_t serial = gz_get_u64(body);
        te_pending_t *q = find_pending(t, serial, link);
        if (!q) return GZ_OK; /* a repeat: already acknowledged */
        if ((st = save1(t, GZ_TE_ACKED, body, 8, out)) != GZ_OK) return st;
        q->used = 0;
        t->n_pending--;
        return GZ_OK;
    }
    if (!memcmp(r.data, "GZPH", 4)) {
        te_limit_t *l = hello_allowed(t, link);
        if (!l) return GZ_OK;
        l->after = 0;
        l->resending = 1;
        return resend_step(t, l, out);
    }
    return GZ_OK; /* GZPX and anything else: ignored */
}

static int cmd_arg(gz_bytes_t cmd, uint64_t type, size_t len, gz_bytes_t *v)
{
    return gz_rec_find(cmd, type, v) == 1 && (len == 0 || v->len == len);
}

static gz_status_t result(gz_action_list_t *out, gz_bytes_t cmd, uint16_t status, const char *error)
{
    return np_command_result(out, cmd, status, error);
}

static gz_status_t on_command(te_t *t, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t v, w, x, y;
    gz_status_t st;
    uint16_t code = 0;
    if (cmd_arg(cmd, GZ_CMD_REC_COMMAND, 2, &v)) code = gz_get_u16(v.data);
    switch (code) {
    case GZ_TE_CMD_CONNECT: {
        if (!cmd_arg(cmd, 12, 33, &v) || !cmd_arg(cmd, 14, 0, &w) || w.len == 0 || w.len > 64)
            return result(out, cmd, 400, "bad_request");
        size_t at = t->n_targets;
        for (size_t i = 0; i < t->n_targets; i++)
            if (key_eq(t->targets[i].host.key, v.data, 33)) at = i;
        if (at < t->n_targets && t->targets[at].addr_len == w.len && !memcmp(t->targets[at].addr, w.data, w.len))
            return result(out, cmd, 200, NULL); /* the same host and address: it stands */
        if (at == TE_MAX_TARGETS) return result(out, cmd, 409, "too_many_hosts");
        te_target_t g;
        uint8_t rec[41 + 64];
        memcpy(g.host.key, v.data, 33);
        g.epoch = 0;
        /* A new host: a new index pair. The same host at another address:
         * the same key, the address replaced (contract-v2.md section 3). */
        g.index = at < t->n_targets ? t->targets[at].index : (uint32_t)(2 * (t->n_targets + 1));
        g.addr_len = (uint8_t)w.len;
        memcpy(g.addr, w.data, w.len);
        memcpy(rec, g.host.key, 33);
        gz_put_u32(rec + 33, g.epoch);
        gz_put_u32(rec + 37, g.index);
        memcpy(rec + 41, g.addr, g.addr_len);
        /* The key's index pair is saved before the handshake shows the key. */
        if ((st = save1(t, GZ_TE_CONNECT, rec, 41 + w.len, out)) != GZ_OK) return st;
        if ((st = te_connect(t, &g, out)) != GZ_OK) return st;
        t->targets[at] = g;
        if (at == t->n_targets) t->n_targets++;
        return result(out, cmd, 200, NULL);
    }
    case GZ_TE_CMD_TIMER:
        if (!cmd_arg(cmd, 12, 4, &v)) return result(out, cmd, 400, "bad_request");
        if ((st = timer(out, 1, gz_get_u32(v.data))) != GZ_OK) return st;
        return result(out, cmd, 200, NULL);
    case GZ_TE_CMD_HANDOFF: {
        uint8_t tag[8];
        if (!cmd_arg(cmd, 12, 2, &v)) return result(out, cmd, 400, "bad_request");
        int between = cmd_arg(cmd, 14, 1, &w) && w.data[0] == 1;
        gz_put_u64(tag, ++t->handoff_tag);
        if ((st = save1(t, GZ_TE_HANDOFF_A, tag, 8, out)) != GZ_OK) return st;
        if (between) {
            /* An engine that sends between its saves, straight after the
             * first: the bracket check. */
            text_t x2 = {{0}, 0};
            t_str(&x2, "test-handoff between");
            if ((st = log_text(out, &x2)) != GZ_OK) return st;
        }
        if ((st = timer(out, 3, 600000)) != GZ_OK) return st;
        if ((st = t->hooks.handoff(t->hooks.ctx, t->area, gz_get_u16(v.data), t->handoff_tag, out)) != GZ_OK)
            return st;
        return result(out, cmd, 200, NULL);
    }
    case GZ_TE_CMD_FAIL:
        if (!cmd_arg(cmd, 12, 4, &v)) return result(out, cmd, 400, "bad_request");
        t->fail_in = gz_get_u32(v.data);
        return result(out, cmd, 200, NULL);
    case GZ_TE_CMD_WATCH: {
        if (!cmd_arg(cmd, 12, 32, &v) || !cmd_arg(cmd, 14, 4, &w)) return result(out, cmd, 400, "bad_request");
        gz_action_t a = {.kind = GZ_ACTION_WATCH_TX};
        memcpy(a.u.watch_tx.txid, v.data, 32);
        a.u.watch_tx.depth = gz_get_u32(w.data);
        if (!a.u.watch_tx.depth) return result(out, cmd, 400, "bad_request");
        if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
        return result(out, cmd, 200, NULL);
    }
    case GZ_TE_CMD_WATCH_OUTPOINT: {
        if (!cmd_arg(cmd, 12, 32, &v) || !cmd_arg(cmd, 14, 4, &w) || !cmd_arg(cmd, 16, 4, &x))
            return result(out, cmd, 400, "bad_request");
        gz_action_t a = {.kind = GZ_ACTION_WATCH_OUTPOINT};
        memcpy(a.u.watch_outpoint.outpoint.txid, v.data, 32);
        a.u.watch_outpoint.outpoint.vout = gz_get_u32(w.data);
        a.u.watch_outpoint.depth = gz_get_u32(x.data);
        if (!a.u.watch_outpoint.depth) return result(out, cmd, 400, "bad_request");
        if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
        return result(out, cmd, 200, NULL);
    }
    case GZ_TE_CMD_SEND: {
        gz_link_t l;
        size_t i;
        if (!cmd_arg(cmd, 12, 33, &v) || !cmd_arg(cmd, 14, 2, &w) || !cmd_arg(cmd, 16, 32, &x) ||
            !cmd_arg(cmd, 18, 0, &y) || y.len > TE_MAX_SEND || !gz_rec_valid(y))
            return result(out, cmd, 400, "bad_request");
        uint16_t kind = gz_get_u16(w.data);
        if (kind == 0 || kind == 2) return result(out, cmd, 400, "bad_request");
        memcpy(l.remote.key, v.data, 33);
        if (t->host) {
            if (!t->keys.host_pub || !t->keys.host_pub(t->keys.ctx, l.local.key)) return result(out, cmd, 404, "no_key");
        } else {
            for (i = 0; i < t->n_targets; i++)
                if (key_eq(t->targets[i].host.key, v.data, 33)) break;
            if (i == t->n_targets || !t->keys.pub ||
                !t->keys.pub(t->keys.ctx, t->targets[i].epoch, t->targets[i].index, l.local.key))
                return result(out, cmd, 404, "no_key");
        }
        gz_action_t a = {.kind = GZ_ACTION_SEND};
        a.u.send.link = l;
        a.u.send.kind = kind;
        memcpy(a.u.send.scope, x.data, 32);
        a.u.send.records = y;
        if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
        return result(out, cmd, 200, NULL);
    }
    case GZ_TE_CMD_BIG_REPLY:
        if (!cmd_arg(cmd, 12, 4, &v)) return result(out, cmd, 400, "bad_request");
        t->pad = gz_get_u32(v.data) > TE_MAX_PAD ? TE_MAX_PAD : gz_get_u32(v.data);
        return result(out, cmd, 200, NULL);
    case GZ_TE_CMD_BROADCAST: {
        static const uint8_t tx[4] = {1, 2, 3, 4};
        gz_action_t a = {.kind = GZ_ACTION_BROADCAST};
        a.u.broadcast.tx.data = tx;
        a.u.broadcast.tx.len = sizeof tx;
        if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
        return result(out, cmd, 200, NULL);
    }
    case GZ_TE_CMD_SELF_HANDOFF:
    case GZ_TE_CMD_SELF_HANDOFF_NOW: {
        uint8_t tag[8];
        gz_put_u64(tag, ++t->handoff_tag);
        if ((st = save1(t, GZ_TE_HANDOFF_A, tag, 8, out)) != GZ_OK) return st;
        st = code == GZ_TE_CMD_SELF_HANDOFF
                 ? t->hooks.handoff(t->hooks.ctx, t->area, t->area, t->handoff_tag, out)
                 : t->hooks.handoff_now(t->hooks.ctx, t->area, t->area, t->handoff_tag, out);
        /* No result after a deferred hand-off: anything outward appended now
         * would sit between this save and the deferred one (7.4). */
        return st;
    }
    case GZ_TE_CMD_BIG_TIMER:
        if ((st = timer(out, UINT64_C(1) << 32, 1000)) != GZ_OK) return st;
        return result(out, cmd, 200, NULL);
    case GZ_TE_CMD_FLOOD: {
        if (!cmd_arg(cmd, 12, 4, &v)) return result(out, cmd, 400, "bad_request");
        text_t x2 = {{0}, 0};
        t_str(&x2, "test-flood");
        for (uint32_t i = 0, n = gz_get_u32(v.data); i < n; i++)
            if ((st = log_text(out, &x2)) != GZ_OK) return st;
        return GZ_OK;
    }
    case GZ_TE_CMD_TWO_SAVES: {
        uint8_t tag[8];
        int between = cmd_arg(cmd, 12, 1, &v) && v.data[0] == 1;
        gz_put_u64(tag, ++t->handoff_tag);
        if ((st = save1(t, GZ_TE_HANDOFF_A, tag, 8, out)) != GZ_OK) return st;
        if (between) {
            text_t x2 = {{0}, 0};
            t_str(&x2, "test-two-saves between");
            if ((st = log_text(out, &x2)) != GZ_OK) return st;
        }
        if ((st = save1(t, GZ_TE_HANDOFF_B, tag, 8, out)) != GZ_OK) return st;
        return result(out, cmd, 200, NULL);
    }
    }
    return result(out, cmd, 404, "unknown_command");
}

gz_status_t te_take_handoff(te_t *t, uint64_t tag, gz_action_list_t *out)
{
    uint8_t b[8];
    text_t x = {{0}, 0};
    gz_put_u64(b, tag);
    gz_status_t st = save1(t, GZ_TE_HANDOFF_B, b, 8, out);
    if (st != GZ_OK) return st;
    t_str(&x, "test-handoff taken area=");
    t_hex16(&x, t->area);
    t_str(&x, " tag=");
    t_u64(&x, tag);
    return log_text(out, &x);
}

static gz_status_t te_handle(void *e, const gz_event_t *ev, gz_action_list_t *out)
{
    te_t *t = e;
    text_t x = {{0}, 0};
    gz_status_t st;
    if (t->fail_in && --t->fail_in == 0) {
        /* --test-node-error-at in an engine: a save, then an error. The
         * composite rolls the save back with the list and poisons itself. */
        uint8_t tag[8];
        gz_put_u64(tag, ~UINT64_C(0));
        if ((st = save1(t, GZ_TE_HANDOFF_A, tag, 8, out)) != GZ_OK) return st;
        return GZ_ERR_NO_SPACE;
    }
    switch (ev->kind) {
    case GZ_EVENT_MESSAGE_RECEIVED:
        return on_message(t, ev, out);
    case GZ_EVENT_PEER_CONNECTED:
        /* The reconnect step (rule 6): the side that connected asks. */
        if (!ev->u.peer.outbound) return GZ_OK;
        return send_msg(t, &ev->u.peer.link, "GZPH", NULL, 0, 0, out);
    case GZ_EVENT_PEER_DISCONNECTED:
        for (size_t i = 0; i < TE_MAX_LIMITS; i++)
            if (t->limits[i].used && link_eq(&t->limits[i].link, &ev->u.peer.link)) t->limits[i].resending = 0;
        return GZ_OK;
    case GZ_EVENT_TIMER_FIRED:
        if (ev->u.timer.timer_id == 2) return resend_step(t, NULL, out);
        t_str(&x, "test-timer area=");
        t_hex16(&x, t->area);
        t_str(&x, " id=");
        t_u64(&x, ev->u.timer.timer_id);
        return log_text(out, &x);
    case GZ_EVENT_CHAIN:
        t_str(&x, "test-chain area=");
        t_hex16(&x, t->area);
        t_str(&x, " kind=");
        t_u64(&x, (uint64_t)ev->u.chain.kind);
        t_str(&x, " conf=");
        t_u64(&x, ev->u.chain.confirmations);
        t_str(&x, " height=");
        t_u64(&x, ev->u.chain.height);
        return log_text(out, &x);
    case GZ_EVENT_USER_COMMAND:
        return on_command(t, ev->u.user.bytes, out);
    case GZ_EVENT_STORAGE_CONFIRMED:
        t->batches++;
        return GZ_OK;
    }
    return GZ_OK;
}

static const gz_engine_ops_t TE_OPS = {
    0x7e57, te_load, te_resume, te_handle, TE_MAX_STEP_ACTIONS, TE_MAX_STEP_BYTES, TE_MAX_TIMERS,
};

const gz_engine_ops_t *gz_te_ops(void)
{
    return &TE_OPS;
}
#else
typedef int gz_no_test_engine_in_release_t;
#endif
