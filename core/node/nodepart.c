/* The node part (composite-node.md sections 2.4, 2.5, 3 and 10): the restore
 * batch, connection binding on the host, the unbound-connection caps and the
 * per-link `hello` limits, slots and their generations, and carrying out the
 * routing decisions of route.c. Its actions are made inside brackets whose
 * engine is the node part (area 0x0004). */
#include "internal.h"
#include <string.h>

gz_status_t gz_c_slot_inline(gz_node_t *c, int eng, gz_status_t (*fn)(gz_node_t *, int, gz_action_list_t *),
                             gz_action_list_t *out);

/* strlen, which the core may not call (tools/check-core-isolation.sh). */
static size_t cstr_len(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static uint64_t now_ms(gz_node_t *c)
{
    return c->ports.clock.now_ms(c->ports.clock.ctx);
}

/* The monotonic clock (ports.h): every interval the node part measures. A
 * wall clock stepped back never keeps a silent connection open. */
static uint64_t mono_ms(gz_node_t *c)
{
    return c->ports.clock.mono_ms(c->ports.clock.ctx);
}

/* ---- notices ------------------------------------------------------------ */

gz_status_t np_log(gz_node_t *c, gz_action_list_t *out, const char *text)
{
    uint8_t buf[200];
    size_t at = 0, n = cstr_len(text);
    (void)c;
    if (n > 160) n = 160;
    gz_status_t st = gz_rec_put(buf, sizeof buf, &at, 0, (const uint8_t *)text, n);
    if (st != GZ_OK) return st;
    gz_action_t a = {.kind = GZ_ACTION_NOTIFY};
    a.u.notify.code = GZ_NOTIFY_LOG;
    a.u.notify.bytes.data = buf;
    a.u.notify.bytes.len = at;
    return gz_action_list_add(out, &a);
}

static const char *drop_name(int why)
{
    switch (why) {
    case DROP_KIND: return "kind";
    case DROP_DISCOVERY: return "discovery";
    case DROP_FUNDED: return "factory-funded";
    case DROP_NO_SLOT: return "no-slot";
    case DROP_SCOPE_ZERO: return "scope-zero";
    case DROP_LINK: return "link";
    case DROP_REBIND: return "rebind";
    case DROP_HELLO_LIMIT: return "hello-limit";
    case DROP_NO_ENGINE: return "no-engine";
    case DROP_TIMER: return "timer";
    case DROP_CONFIRM: return "confirm";
    case DROP_UNCONNECTED: return "unconnected";
    }
    return "?";
}

static void fmt_u(char *p, size_t cap, size_t *at, uint64_t v)
{
    char d[24];
    int n = 0;
    do {
        d[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n > 0 && *at + 1 < cap) p[(*at)++] = d[--n];
    p[*at] = 0;
}

static void fmt_s(char *p, size_t cap, size_t *at, const char *s)
{
    while (*s && *at + 1 < cap) p[(*at)++] = *s++;
    p[*at] = 0;
}

/* A counted drop, with a log notice naming why. Never an error (node.h). */
gz_status_t np_drop(gz_node_t *c, int why, uint16_t kind, gz_action_list_t *out)
{
    char text[96];
    size_t at = 0;
    c->np.drops[why]++;
    /* A peer can cause a drop with every message: the notices are limited. */
    if (c->np.drops[why] > NP_DROP_NOTICES && (c->np.drops[why] & (c->np.drops[why] - 1)) != 0) return GZ_OK;
    text[0] = 0;
    fmt_s(text, sizeof text, &at, "drop why=");
    fmt_s(text, sizeof text, &at, drop_name(why));
    fmt_s(text, sizeof text, &at, " kind=");
    fmt_u(text, sizeof text, &at, kind);
    fmt_s(text, sizeof text, &at, " count=");
    fmt_u(text, sizeof text, &at, c->np.drops[why]);
    return np_log(c, out, text);
}

gz_status_t np_command_result(gz_action_list_t *out, gz_bytes_t cmd, uint16_t status, const char *error)
{
    uint8_t buf[200], st2[2];
    size_t at = 0;
    gz_bytes_t rid;
    gz_status_t st = GZ_OK;
    if (gz_rec_find(cmd, GZ_CMD_REC_REQUEST_ID, &rid) != 1 || rid.len > GZ_CMD_MAX_REQUEST_ID) {
        rid.data = (const uint8_t *)"-";
        rid.len = 1;
    }
    gz_put_u16(st2, status);
    st = gz_rec_put(buf, sizeof buf, &at, GZ_RESULT_REC_REQUEST_ID, rid.data, rid.len);
    if (st == GZ_OK) st = gz_rec_put(buf, sizeof buf, &at, GZ_RESULT_REC_STATUS, st2, 2);
    if (st == GZ_OK && error)
        st = gz_rec_put(buf, sizeof buf, &at, GZ_RESULT_REC_ERROR, (const uint8_t *)error, cstr_len(error));
    if (st != GZ_OK) return st;
    gz_action_t a = {.kind = GZ_ACTION_NOTIFY};
    a.u.notify.code = GZ_NOTIFY_COMMAND_RESULT;
    a.u.notify.bytes.data = buf;
    a.u.notify.bytes.len = at;
    return gz_action_list_add(out, &a);
}

/* ---- load and the restore batch ----------------------------------------- */

/* A guard record is the guard file's contents without its check, as storage
 * reads it (journal.md 8.3): "GZGUARD1", the chain (32), counter (u64),
 * n_epochs (u16), per epoch its number and highest index (u32, u32; oldest
 * first), rounds_started (u64). */
static const uint8_t GUARD_MAGIC[8] = {'G', 'Z', 'G', 'U', 'A', 'R', 'D', '1'};

/* A new current epoch. The one before it joins the older ones; with no
 * key_epoch record yet that is installation's epoch 0, unless the record is
 * epoch 0 itself. */
static void new_epoch(gz_node_t *c, uint32_t epoch)
{
    np_t *p = &c->np;
    if (p->have_epoch || epoch != 0) {
        if (p->n_old_epochs == NP_MAX_OLD_EPOCHS) {
            memmove(&p->old_epochs[0], &p->old_epochs[1], (NP_MAX_OLD_EPOCHS - 1) * sizeof p->old_epochs[0]);
            p->n_old_epochs--;
        }
        p->old_epochs[p->n_old_epochs][0] = p->have_epoch ? p->epoch : 0;
        p->old_epochs[p->n_old_epochs][1] = p->highest_index;
        p->n_old_epochs++;
    }
    p->epoch = epoch;
    p->have_epoch = 1;
    p->highest_index = 0;
}

/* The epoch list of a guard record the node wrote: every epoch it knew then,
 * oldest first, the current one last. After a restore that list holds epochs
 * of the guard file which no key_epoch record of this journal names (the
 * restore batch's union, below), so it replaces what the key_epoch records
 * gave. A list that does not end in the current epoch is not the node's own
 * view of now, and is left alone. */
static void guard_epochs(gz_node_t *c, const uint8_t *e, size_t n)
{
    np_t *p = &c->np;
    if (n == 0 || gz_get_u32(e + 8 * (n - 1)) != (p->have_epoch ? p->epoch : 0)) return;
    size_t older = n - 1, skip = older > NP_MAX_OLD_EPOCHS ? older - NP_MAX_OLD_EPOCHS : 0;
    p->n_old_epochs = 0;
    for (size_t i = skip; i < older; i++, p->n_old_epochs++) {
        p->old_epochs[p->n_old_epochs][0] = gz_get_u32(e + 8 * i);
        p->old_epochs[p->n_old_epochs][1] = gz_get_u32(e + 8 * i + 4);
    }
    if (gz_get_u32(e + 8 * (n - 1) + 4) > p->highest_index) p->highest_index = gz_get_u32(e + 8 * (n - 1) + 4);
}

/* The guard file's contents, given with the restore marker (ports.h): kept
 * for the restore batch. One that is not a guard for this chain is as if
 * there were none. Of more epochs than the node holds, the newest are kept. */
void np_guard_file(gz_node_t *c, gz_bytes_t guard)
{
    np_t *p = &c->np;
    const uint8_t *b = guard.data;
    size_t n, skip;
    p->have_file = 0;
    if (!b || guard.len < NP_GUARD_HEAD || memcmp(b, GUARD_MAGIC, 8) != 0 || memcmp(b + 8, c->cfg.chain, 32) != 0)
        return;
    n = gz_get_u16(b + 48);
    if (guard.len != NP_GUARD_HEAD + 8 * n) return;
    p->have_file = 1;
    p->file_counter = gz_get_u64(b + 40);
    p->file_rounds = gz_get_u64(b + 50 + 8 * n);
    skip = n > NP_MAX_OLD_EPOCHS + 1 ? n - (NP_MAX_OLD_EPOCHS + 1) : 0;
    p->n_file_epochs = 0;
    for (size_t i = skip; i < n; i++, p->n_file_epochs++) {
        p->file_epochs[p->n_file_epochs][0] = gz_get_u32(b + 50 + 8 * i);
        p->file_epochs[p->n_file_epochs][1] = gz_get_u32(b + 50 + 8 * i + 4);
    }
}

gz_status_t np_load(gz_node_t *c, const gz_record_t *rec, gz_batch_id_t at)
{
    gz_bytes_t v;
    (void)at;
    switch (rec->type) {
    case GZ_RECORD_KEY_EPOCH:
        if (gz_rec_find(rec->bytes, 2, &v) != 1 || v.len != 4) return GZ_ERR_CORRUPT;
        new_epoch(c, gz_get_u32(v.data));
        return GZ_OK;
    case GZ_RECORD_KEY_INDEX:
        if (gz_rec_find(rec->bytes, 2, &v) != 1 || v.len != 4) return GZ_ERR_CORRUPT;
        if (gz_get_u32(v.data) > c->np.highest_index) c->np.highest_index = gz_get_u32(v.data);
        return GZ_OK;
    case GZ_RECORD_GUARD: {
        /* The epochs are known from the key_epoch and key_index records; the
         * guard gives its counter and the rounds started. */
        const uint8_t *b = rec->bytes.data;
        size_t len = rec->bytes.len, n;
        if (len < NP_GUARD_HEAD || memcmp(b, GUARD_MAGIC, 8) != 0) return GZ_ERR_CORRUPT;
        n = gz_get_u16(b + 48);
        if (len != NP_GUARD_HEAD + 8 * n) return GZ_ERR_CORRUPT;
        if (gz_get_u64(b + 40) >= c->np.guard_counter) {
            c->np.guard_counter = gz_get_u64(b + 40);
            c->np.rounds_started = gz_get_u64(b + 50 + 8 * n);
            guard_epochs(c, b + 50, n);
        }
        return GZ_OK;
    }
    case GZ_RECORD_RESTORED:
        return gz_rec_valid(rec->bytes) ? GZ_OK : GZ_ERR_CORRUPT;
    case GZ_RECORD_SLOT_OPENED:
        return gz_ls_load_opened(c, rec);
    case GZ_RECORD_SLOT_CLOSED:
        return gz_ls_load_closed(c, rec);
    }
    return GZ_ERR_CORRUPT; /* every Slice 1 type is even: an unknown one stops the start */
}

/* The restore epoch: 31 bits of a bijective 64-bit mix (the SplitMix64
 * finaliser) of the draw XOR the incarnation times an odd constant. Two
 * restores have different incarnations (runner.h keeps the incarnation out
 * of a restore's reach), so even if the port repeats the draw, the inputs to
 * the mix differ, and so do the 64-bit outputs; the 31 bits kept then match
 * by chance only, as safety-rule.md R2 counts. */
static uint32_t restore_epoch(uint64_t drawn, uint64_t incarnation)
{
    uint64_t x = drawn ^ (incarnation * 0x9E3779B97F4A7C15ull);
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    x ^= x >> 31;
    return (uint32_t)(x >> 33);
}

static gz_status_t save_records(gz_action_list_t *out, const gz_record_t *recs, size_t n)
{
    gz_action_t a = {.kind = GZ_ACTION_SAVE};
    a.u.save.records = recs;
    a.u.save.n_records = n;
    return gz_action_list_add(out, &a);
}

static size_t epoch_record(uint8_t *buf, size_t cap, uint32_t epoch)
{
    uint8_t e[4];
    size_t at = 0;
    gz_put_u32(e, epoch);
    return gz_rec_put(buf, cap, &at, 2, e, 4) == GZ_OK ? at : 0;
}

/* The guard record of the node's state now: every epoch, the current one
 * last. `buf` holds NP_GUARD_HEAD + 8 * (NP_MAX_OLD_EPOCHS + 1) bytes. */
static size_t guard_record(const gz_node_t *c, uint8_t *buf)
{
    const np_t *p = &c->np;
    size_t at = 50;
    memcpy(buf, GUARD_MAGIC, 8);
    memcpy(buf + 8, c->cfg.chain, 32);
    gz_put_u64(buf + 40, p->guard_counter);
    gz_put_u16(buf + 48, (uint16_t)(p->n_old_epochs + 1));
    for (uint32_t i = 0; i < p->n_old_epochs; i++, at += 8) {
        gz_put_u32(buf + at, p->old_epochs[i][0]);
        gz_put_u32(buf + at + 4, p->old_epochs[i][1]);
    }
    gz_put_u32(buf + at, p->have_epoch ? p->epoch : 0);
    gz_put_u32(buf + at + 4, p->highest_index);
    gz_put_u64(buf + at + 8, p->rounds_started);
    return at + 16;
}

static int find_epoch(uint32_t (*list)[2], uint32_t n, uint32_t epoch)
{
    for (uint32_t i = 0; i < n; i++)
        if (list[i][0] == epoch) return (int)i;
    return -1;
}

/* THE GUARD AT A RESTORE (journal.md 8.3). The journal the node loaded is the
 * backup; the guard file is outside the backup set and may be newer, listing
 * epochs used after the backup was made (R7 needs them to derive the keys of
 * later factories). The restore batch's guard record replaces the file, so
 * it must hold no less than the file did: the node takes the union of the
 * two epoch lists here, the larger of the two counters and of the two counts
 * of rounds started, before it adds the new epoch. Order: the list with the
 * higher counter is the newer view and keeps its order; an epoch only the
 * other list has is older than all of it. Past NP_MAX_OLD_EPOCHS + 1 the
 * oldest are forgotten. */
static void merge_guard_file(gz_node_t *c)
{
    np_t *p = &c->np;
    uint32_t own[NP_MAX_OLD_EPOCHS + 1][2], all[2 * (NP_MAX_OLD_EPOCHS + 1)][2];
    uint32_t n_own = 0, n = 0, i, skip;
    uint32_t (*newer)[2], (*older)[2], n_newer, n_older;
    if (!p->have_file) return;
    for (i = 0; i < p->n_old_epochs; i++, n_own++) {
        own[n_own][0] = p->old_epochs[i][0];
        own[n_own][1] = p->old_epochs[i][1];
    }
    own[n_own][0] = p->have_epoch ? p->epoch : 0;
    own[n_own][1] = p->highest_index;
    n_own++;
    if (p->file_counter > p->guard_counter) {
        newer = p->file_epochs;
        n_newer = p->n_file_epochs;
        older = own;
        n_older = n_own;
    } else {
        newer = own;
        n_newer = n_own;
        older = p->file_epochs;
        n_older = p->n_file_epochs;
    }
    for (i = 0; i < n_older; i++)
        if (find_epoch(newer, n_newer, older[i][0]) < 0) {
            all[n][0] = older[i][0];
            all[n][1] = older[i][1];
            n++;
        }
    for (i = 0; i < n_newer; i++, n++) {
        int k = find_epoch(older, n_older, newer[i][0]);
        all[n][0] = newer[i][0];
        all[n][1] = k >= 0 && older[k][1] > newer[i][1] ? older[k][1] : newer[i][1];
    }
    skip = n > NP_MAX_OLD_EPOCHS + 1 ? n - (NP_MAX_OLD_EPOCHS + 1) : 0;
    p->n_old_epochs = 0;
    for (i = skip; i + 1 < n; i++, p->n_old_epochs++) {
        p->old_epochs[p->n_old_epochs][0] = all[i][0];
        p->old_epochs[p->n_old_epochs][1] = all[i][1];
    }
    p->epoch = all[n - 1][0];
    p->highest_index = all[n - 1][1];
    p->have_epoch = 1;
    if (p->file_counter > p->guard_counter) p->guard_counter = p->file_counter;
    if (p->file_rounds > p->rounds_started) p->rounds_started = p->file_rounds;
    p->have_file = 0;
}

static int epoch_known(const gz_node_t *c, uint32_t epoch)
{
    const np_t *p = &c->np;
    if (epoch == (p->have_epoch ? p->epoch : 0)) return 1;
    for (uint32_t i = 0; i < p->n_old_epochs; i++)
        if (p->old_epochs[i][0] == epoch) return 1;
    return 0;
}

/* key_epoch, restored and guard, alone (node.h rule 5; journal.md 8.2). The
 * epoch is drawn with the ordinary tag: it is saved and backed up. It is
 * never 0 and never one the node knows; each further draw is mixed with a
 * count, so a port that repeats itself cannot hold the loop. */
gz_status_t np_restore_batch(gz_node_t *c, gz_action_list_t *out)
{
    uint8_t eb[16], rb[32], gb[NP_GUARD_HEAD + 8 * (NP_MAX_OLD_EPOCHS + 1)], drawn[8], v[8];
    uint32_t epoch;
    uint64_t again = 0;
    size_t at = 0;
    gz_record_t recs[3];
    merge_guard_file(c);
    do {
        c->ports.random.fill(c->ports.random.ctx, GZ_RANDOM_ORDINARY, drawn, sizeof drawn);
        epoch = restore_epoch(gz_get_u64(drawn) + again++, c->incarnation);
    } while (epoch == 0 || epoch_known(c, epoch));
    recs[0].type = GZ_RECORD_KEY_EPOCH;
    recs[0].bytes.data = eb;
    recs[0].bytes.len = epoch_record(eb, sizeof eb, epoch);
    gz_put_u64(v, now_ms(c));
    if (gz_rec_put(rb, sizeof rb, &at, 2, v, 8) != GZ_OK) return GZ_ERR_BUG;
    gz_put_u64(v, c->np.newest_incarnation);
    if (gz_rec_put(rb, sizeof rb, &at, 4, v, 8) != GZ_OK) return GZ_ERR_BUG;
    recs[1].type = GZ_RECORD_RESTORED;
    recs[1].bytes.data = rb;
    recs[1].bytes.len = at;
    /* The node's memory moves to the new epoch before the save is listed: a
     * list that cannot take the batch stops the node (composite.c). */
    new_epoch(c, epoch);
    c->np.guard_counter++;
    recs[2].type = GZ_RECORD_GUARD;
    recs[2].bytes.data = gb;
    recs[2].bytes.len = guard_record(c, gb);
    return save_records(out, recs, 3);
}

/* The node part's resume. The start saves nothing but the restore batch
 * (contract-v2.md section 1). Epoch 0 at installation (journal.md 8.2 step 1)
 * is implied while no key_epoch record exists: no key is allocated before
 * P4.2, which saves key_epoch 0 in the batch of the first key_index. */
gz_status_t np_resume(gz_node_t *c, gz_action_list_t *out)
{
    (void)out;
    if (!c->np.have_epoch) c->np.epoch = 0;
    return GZ_OK;
}

/* ---- connections (host) ------------------------------------------------- */

int np_conn_find(const gz_node_t *c, const gz_link_t *link)
{
    for (int i = 0; i < NP_MAX_CONNS; i++)
        if (c->np.conns[i].used && np_same_link(&c->np.conns[i].link, link)) return i;
    return -1;
}

/* A connection the node part takes messages from: reported connected, not
 * reported gone, and not one whose close it has asked for. */
static int conn_live(const np_conn_t *k)
{
    return k->used && k->connected && !k->closing;
}

/* Live connections whose key holds no seat, bound or not: the ones the cap,
 * the push-out and the idle rule are about (internal.h, CONNECTIONS). */
static uint32_t unseated(const gz_node_t *c)
{
    uint32_t n = 0;
    for (int i = 0; i < NP_MAX_CONNS; i++)
        if (conn_live(&c->np.conns[i]) && !c->np.conns[i].seated) n++;
    return n;
}

static gz_status_t disconnect(gz_action_list_t *out, const gz_link_t *link, uint16_t why)
{
    gz_action_t a = {.kind = GZ_ACTION_DISCONNECT};
    a.u.disconnect.link = *link;
    a.u.disconnect.why = why;
    return gz_action_list_add(out, &a);
}

static gz_status_t set_timer(gz_action_list_t *out, uint32_t id, uint64_t delay)
{
    gz_action_t a = {.kind = GZ_ACTION_SET_TIMER};
    a.u.set_timer.timer_id = id;
    a.u.set_timer.delay_ms = delay;
    return gz_action_list_add(out, &a);
}

/* Set the idle timer for the earliest unseated connection's deadline. */
static gz_status_t arm_idle(gz_node_t *c, gz_action_list_t *out)
{
    uint64_t due = 0, now = mono_ms(c);
    for (int i = 0; i < NP_MAX_CONNS; i++) {
        const np_conn_t *k = &c->np.conns[i];
        if (!conn_live(k) || k->seated) continue;
        uint64_t d = k->since_ms + NP_IDLE_MS;
        if (k->unseated_ms + NP_UNSEATED_MAX_MS < d) d = k->unseated_ms + NP_UNSEATED_MAX_MS;
        if (!due || d < due) due = d;
    }
    if (!due || due == c->np.idle_due_ms) return GZ_OK;
    c->np.idle_due_ms = due;
    return set_timer(out, NP_TIMER_IDLE, due > now ? due - now : 0);
}

/* The node part has asked for this link's close (DISCONNECT): from now on
 * nothing is taken from it, and it no longer counts. Its entry stays until
 * its PEER_DISCONNECTED, which a bound slot's lobby must still be given. */
static void conn_closing(gz_node_t *c, const gz_link_t *link)
{
    int i = np_conn_find(c, link);
    if (i >= 0 && c->np.conns[i].connected) c->np.conns[i].closing = 1;
}

/* Forget a connection that is gone; its hello limits stay with its link
 * (contract v2: limits per link, not per connection). */
static void conn_gone(gz_node_t *c, int i)
{
    np_conn_t *k = &c->np.conns[i];
    k->connected = 0;
    k->closing = 0;
    k->seated = 0;
    k->slot = -1;
}

/* Silent: it has sent nothing, and has had NP_SILENT_GRACE_MS to do so. */
static int silent(const np_conn_t *k, uint64_t now)
{
    return !k->spoke && now - k->since_ms >= NP_SILENT_GRACE_MS;
}

/* Close the oldest silent unseated connection (B7): never a seated one. */
static gz_status_t push_out_one(gz_node_t *c, gz_action_list_t *out)
{
    int best = -1;
    uint64_t now = mono_ms(c);
    for (int i = 0; i < NP_MAX_CONNS; i++) {
        const np_conn_t *k = &c->np.conns[i];
        if (!conn_live(k) || k->seated) continue;
        if (best < 0 || (silent(k, now) > silent(&c->np.conns[best], now)) ||
            (silent(k, now) == silent(&c->np.conns[best], now) && k->since_ms < c->np.conns[best].since_ms))
            best = i;
    }
    if (best < 0) return GZ_OK;
    gz_status_t st = disconnect(out, &c->np.conns[best].link, GZ_DISCONNECT_IDLE);
    c->np.conns[best].closing = 1;
    return st;
}

/* Keep the cap: while more than NP_MAX_UNSEATED connections hold no seat,
 * the oldest silent one goes. */
static gz_status_t keep_cap(gz_node_t *c, gz_action_list_t *out)
{
    gz_status_t st = GZ_OK;
    while (st == GZ_OK && unseated(c) > NP_MAX_UNSEATED) st = push_out_one(c, out);
    return st;
}

/* A table entry for a link: its own, a free one, or the one longest gone
 * (an entry being closed that no slot waits to hear of counts as gone). -1
 * if every entry holds a connection. */
static int conn_slot(gz_node_t *c, const gz_link_t *link)
{
    int i = np_conn_find(c, link), best = -1;
    if (i >= 0) return i;
    for (i = 0; i < NP_MAX_CONNS; i++) {
        const np_conn_t *k = &c->np.conns[i];
        if (!k->used) return i;
        if ((!k->connected || (k->closing && k->slot < 0)) &&
            (best < 0 || k->since_ms < c->np.conns[best].since_ms))
            best = i;
    }
    return best;
}

static gz_status_t host_connected(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    gz_status_t st;
    int i = conn_slot(c, &ev->u.peer.link), s = gz_route_slot_seated(c, &ev->u.peer.link.remote);
    /* The link's last connection was never reported gone (the program reports
     * it first, contract-v2.md section 2; this is the second guard): its
     * slot's lobby hears of the end before the new beginning. */
    if (i >= 0 && c->np.conns[i].used && c->np.conns[i].connected && np_same_link(&c->np.conns[i].link, &ev->u.peer.link)) {
        int was = c->np.conns[i].slot;
        conn_gone(c, i);
        if (was >= 0 && c->slots[was].state == SLOT_OPEN) {
            gz_event_t gone = *ev;
            gone.kind = GZ_EVENT_PEER_DISCONNECTED;
            if ((st = gz_c_bracket(c, ENG_SLOT0 + was, &gone, out)) != GZ_OK) return st;
        }
    }
    if ((st = gz_c_node_bracket_begin(c, out)) != GZ_OK) return st;
    /* A newcomer without a seat when the unseated places are taken, or any
     * newcomer when the table is full, pushes one out first; the newcomer
     * itself is never the one to go. */
    if (i < 0 || (s < 0 && unseated(c) >= NP_MAX_UNSEATED)) {
        st = push_out_one(c, out);
        if (st == GZ_OK && i < 0) i = conn_slot(c, &ev->u.peer.link);
    }
    if (st == GZ_OK && i < 0) {
        /* Every entry holds a connection that stays, which the transport's
         * own limit (the same number, node.h) keeps from happening: refuse
         * this one. */
        st = disconnect(out, &ev->u.peer.link, GZ_DISCONNECT_REFUSED);
        if (st == GZ_OK) st = gz_c_node_bracket_end(c, out);
        else c->bracket_on = 0;
        return st;
    }
    if (st == GZ_OK) {
        np_conn_t *k = &c->np.conns[i];
        int same = k->used && np_same_link(&k->link, &ev->u.peer.link);
        if (!same) memset(k, 0, sizeof *k);
        k->used = 1;
        k->connected = 1;
        k->closing = 0;
        k->link = ev->u.peer.link;
        k->since_ms = mono_ms(c);
        k->unseated_ms = k->since_ms;
        k->spoke = 0;
        k->slot = s;
        k->seated = s >= 0;
        if (s < 0) st = arm_idle(c, out);
    }
    if (st == GZ_OK) st = gz_c_node_bracket_end(c, out);
    else c->bracket_on = 0;
    if (st == GZ_OK && s >= 0) st = gz_c_bracket(c, ENG_SLOT0 + s, ev, out);
    return st;
}

static gz_status_t to_tests(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    for (int e = ENG_TEST0; e < ENG_TEST0 + c->n_test; e++) {
        gz_status_t st = gz_c_bracket(c, e, ev, out);
        if (st != GZ_OK) return st;
    }
    return GZ_OK;
}

/* PEER_CONNECTED and PEER_DISCONNECTED (section 5). */
gz_status_t np_peer(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    gz_status_t st = GZ_OK;
    if (c->cfg.host) {
        if (ev->kind == GZ_EVENT_PEER_CONNECTED) {
            st = host_connected(c, ev, out);
        } else {
            int i = np_conn_find(c, &ev->u.peer.link);
            int s = i >= 0 && c->np.conns[i].connected ? c->np.conns[i].slot : -1;
            if (i >= 0) conn_gone(c, i);
            if (s >= 0 && c->slots[s].state == SLOT_OPEN) st = gz_c_bracket(c, ENG_SLOT0 + s, ev, out);
        }
    } else {
        int s = gz_route_member_slot_of_link(c, &ev->u.peer.link);
        if (s >= 0) st = gz_c_bracket(c, ENG_SLOT0 + s, ev, out);
    }
    return st == GZ_OK ? to_tests(c, ev, out) : st;
}

/* A slot's engine marked a seat, or gave one up (SET_SEATED, noted after its
 * bracket): the key's connection is seated, and bound to the slot if it was
 * not bound; or it is unseated again, and the cap and the idle rule apply to
 * it from now (np_idle_check at the bracket's end). */
void np_seat_changed(gz_node_t *c, int slot, const gz_node_id_t *member, int seated)
{
    for (int i = 0; i < NP_MAX_CONNS; i++) {
        np_conn_t *k = &c->np.conns[i];
        if (!k->used || !k->connected || !np_same_key(&k->link.remote, member)) continue;
        if (seated) {
            k->seated = 1;
            if (k->slot < 0) k->slot = slot;
        } else if (k->seated && gz_route_slot_seated(c, member) < 0) {
            k->seated = 0;
            k->since_ms = mono_ms(c);
            k->unseated_ms = k->since_ms;
            c->np.idle_check = 1;
        }
    }
}

/* After a bracket in which a seat was given up: the cap, then the idle timer.
 * The actions are the node part's, appended after the bracket's own. */
gz_status_t np_idle_check(gz_node_t *c, gz_action_list_t *out)
{
    gz_status_t st;
    if (!c->np.idle_check) return GZ_OK;
    c->np.idle_check = 0;
    if ((st = keep_cap(c, out)) != GZ_OK) return st;
    return arm_idle(c, out);
}

/* The per-link hello limits (messages.md 6.1, per link): one answer a second;
 * 20 ignored in 10 minutes close the connection. 1: answer; 0: ignored. */
static int hello_allowed(gz_node_t *c, int i, int *close)
{
    np_conn_t *k = &c->np.conns[i];
    uint64_t now = mono_ms(c);
    *close = 0;
    if (!k->hello_last_ms || now < k->hello_last_ms || now - k->hello_last_ms >= NP_HELLO_GAP_MS) {
        k->hello_last_ms = now ? now : 1;
        return 1;
    }
    if (!k->hello_window_ms || now < k->hello_window_ms || now - k->hello_window_ms >= NP_HELLO_WINDOW_MS) {
        k->hello_window_ms = now ? now : 1;
        k->hello_ignored = 0;
    }
    if (++k->hello_ignored >= NP_HELLO_IGNORED_MAX) *close = 1;
    return 0;
}

/* lobby_status with lobby state 0 alone, under the asked scope
 * (messages.md 6.1 and 6.7; gz_lobby_host_unknown in P4.2). */
static gz_status_t answer_unknown(gz_action_list_t *out, const gz_link_t *link, const uint8_t scope[32])
{
    uint8_t rec[32], z4[4] = {0, 0, 0, 0};
    size_t at = 0;
    gz_status_t st = gz_rec_put(rec, sizeof rec, &at, 2, z4, 1);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof rec, &at, 4, z4, 1);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof rec, &at, 6, z4, 4);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof rec, &at, 8, z4, 2);
    if (st == GZ_OK) st = gz_rec_put(rec, sizeof rec, &at, 10, z4, 2);
    if (st != GZ_OK) return st;
    gz_action_t a = {.kind = GZ_ACTION_SEND};
    a.u.send.link = *link;
    a.u.send.kind = GZ_MSG_KIND_LOBBY_STATUS;
    memcpy(a.u.send.scope, scope, 32);
    a.u.send.records.data = rec;
    a.u.send.records.len = at;
    return gz_action_list_add(out, &a);
}

static gz_status_t node_only(gz_node_t *c, gz_action_list_t *out, int why, uint16_t kind, const gz_link_t *refuse)
{
    gz_status_t st = gz_c_node_bracket_begin(c, out);
    if (st == GZ_OK) st = np_drop(c, why, kind, out);
    if (st == GZ_OK && refuse) st = disconnect(out, refuse, GZ_DISCONNECT_REFUSED);
    if (st == GZ_OK && refuse) conn_closing(c, refuse); /* nothing more is taken from it */
    if (st == GZ_OK) return gz_c_node_bracket_end(c, out);
    c->bracket_on = 0;
    return st;
}

static gz_status_t limited_hello(gz_node_t *c, int conn, const gz_event_t *ev, int unknown, gz_action_list_t *out)
{
    int close = 0, ok = hello_allowed(c, conn, &close);
    gz_status_t st;
    if (!ok) return node_only(c, out, DROP_HELLO_LIMIT, ev->u.message.kind, close ? &ev->u.message.link : NULL);
    if (unknown) {
        if ((st = gz_c_node_bracket_begin(c, out)) != GZ_OK) return st;
        /* 1: an unknown scope. 2 + n: ended lobby n of the index. */
        st = unknown > 1 ? gz_ls_ended_answer(c, unknown - 2, &ev->u.message.link, out)
                         : answer_unknown(out, &ev->u.message.link, ev->u.message.scope);
        if (st == GZ_OK) return gz_c_node_bracket_end(c, out);
        c->bracket_on = 0;
        return st;
    }
    /* The listing: every listed host slot answers, at most NP_MAX_LISTED. */
    int n = 0;
    for (int s = 0; s < GZ_NODE_MAX_SLOTS && n < NP_MAX_LISTED; s++) {
        if (c->slots[s].state != SLOT_OPEN || !c->slots[s].host || !c->slots[s].listed) continue;
        n++;
        if ((st = gz_c_bracket(c, ENG_SLOT0 + s, ev, out)) != GZ_OK) return st;
    }
    return GZ_OK;
}

gz_status_t np_message(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out)
{
    const gz_link_t *link = &ev->u.message.link;
    int conn = -1;
    if (c->cfg.host) {
        conn = np_conn_find(c, link);
        /* A link the node part does not hold as connected: one it closed or
         * refused whose last messages are still on their way, or one never
         * reported. Dropped and counted, whatever the kind: it binds nothing,
         * no engine hears of it, and it gets no answer. */
        if (conn < 0 || !conn_live(&c->np.conns[conn]))
            return node_only(c, out, DROP_UNCONNECTED, ev->u.message.kind, NULL);
        c->np.conns[conn].spoke = 1;
        c->np.conns[conn].since_ms = mono_ms(c);
    }
    rt_t r = gz_route_message(c, conn, link, ev->u.message.kind, ev->u.message.scope, ev->u.message.records);
    switch (r.kind) {
    case RT_DROP:   return node_only(c, out, r.drop, ev->u.message.kind, NULL);
    case RT_REFUSE: return node_only(c, out, r.drop, ev->u.message.kind, link);
    case RT_SLOT:   return gz_c_bracket(c, ENG_SLOT0 + r.slot, ev, out);
    case RT_BIND: {
        gz_event_t pc;
        gz_status_t st;
        c->np.conns[conn].slot = r.slot; /* bound, and still unseated: the idle rule and the push-out apply */
        memset(&pc, 0, sizeof pc);
        pc.kind = GZ_EVENT_PEER_CONNECTED;
        pc.u.peer.link = *link;
        if ((st = gz_c_bracket(c, ENG_SLOT0 + r.slot, &pc, out)) != GZ_OK) return st;
        return gz_c_bracket(c, ENG_SLOT0 + r.slot, ev, out);
    }
    case RT_SIGNING:
        return node_only(c, out, DROP_NO_ENGINE, ev->u.message.kind, NULL); /* P4.3 */
    case RT_TEST:   return gz_c_bracket(c, r.eng, ev, out);
    case RT_LISTING: return limited_hello(c, conn, ev, 0, out);
    case RT_UNKNOWN_HELLO: return limited_hello(c, conn, ev, 1, out);
    case RT_ENDED_HELLO: return limited_hello(c, conn, ev, 2 + r.slot, out);
    }
    return node_only(c, out, DROP_KIND, ev->u.message.kind, NULL);
}

/* The node part's timers: the idle timer closes unseated connections silent
 * for 60 s; the continuation timer (8.3) has no work before P4.2's pause. */
gz_status_t np_timer(gz_node_t *c, uint32_t id, gz_action_list_t *out)
{
#ifdef GZ_TEST_KINDS
    if (id == NP_TIMER_SIGN) return gz_ss_timer(c, out);
#endif
    gz_status_t st = gz_c_node_bracket_begin(c, out);
    if (st != GZ_OK) return st;
    if (id == NP_TIMER_IDLE) {
        uint64_t now = mono_ms(c);
        c->np.idle_due_ms = 0;
        for (int i = 0; i < NP_MAX_CONNS && st == GZ_OK; i++) {
            np_conn_t *k = &c->np.conns[i];
            if (!conn_live(k) || k->seated) continue;
            if (now < k->since_ms + NP_IDLE_MS && now < k->unseated_ms + NP_UNSEATED_MAX_MS) continue;
            st = disconnect(out, &k->link, GZ_DISCONNECT_IDLE);
            k->closing = 1;
        }
        if (st == GZ_OK) st = arm_idle(c, out);
    }
    if (id == NP_TIMER_CONTINUE) st = gz_ls_closing_timer(c, out);
    if (st == GZ_OK) return gz_c_node_bracket_end(c, out);
    c->bracket_on = 0;
    return st;
}

/* ---- slots (test commands in P4.1; the lobby opens them from P4.2) ------- */

#ifdef GZ_TEST_KINDS
static int arg(gz_bytes_t cmd, uint64_t type, size_t len, gz_bytes_t *v)
{
    return gz_rec_find(cmd, type, v) == 1 && (len == 0 || v->len == len);
}

static int free_gen_ok(const gz_node_t *c, uint16_t gen)
{
    if (gen == 0) return 0;
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++)
        if (c->slots[i].state != SLOT_FREE && c->slots[i].gen == gen) return 0;
    return 1;
}

/* The test commands on a slot (close, seat, round, watch, save) are for the
 * stand-in's slots only: a slot that holds a lobby is opened and closed by
 * its lobby alone, with its records. For them such a slot is no slot. */
static int standin_slot(const gz_node_t *c, const uint8_t scope[32])
{
    int i = gz_route_slot_by_scope(c, scope);
    return i >= 0 && c->slots[i].kind == SLOT_KIND_STANDIN ? i : -1;
}

static gz_status_t open_inline(gz_node_t *c, int eng, gz_action_list_t *out)
{
    slot_t *s = &c->slots[eng - ENG_SLOT0];
    return ts_open(&s->ts, s->gen, s->host, s->scope, s->ts.timer_ms, out);
}

static gz_status_t seat_inline(gz_node_t *c, int eng, gz_action_list_t *out)
{
    return ts_seat(&c->slots[eng - ENG_SLOT0].ts, &c->np.seat_key, c->np.seat_val, out);
}

static gz_status_t watch_inline(gz_node_t *c, int eng, gz_action_list_t *out)
{
    return ts_watch(&c->slots[eng - ENG_SLOT0].ts, c->np.seat_key.key, (uint32_t)c->np.seat_val, out);
}

static gz_status_t save_inline(gz_node_t *c, int eng, gz_action_list_t *out)
{
    return ts_save(&c->slots[eng - ENG_SLOT0].ts, out);
}

static gz_status_t slot_open(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t scope, role, hk, addr, v;
    int i, free_i = -1;
    gz_status_t st;
    if (!arg(cmd, 12, 32, &scope) || !arg(cmd, 14, 1, &role)) return np_command_result(out, cmd, 400, "bad_request");
    if (gz_route_slot_by_scope(c, scope.data) >= 0) return np_command_result(out, cmd, 409, "lobby_exists");
    for (i = 0; i < GZ_NODE_MAX_SLOTS; i++)
        if (c->slots[i].state == SLOT_FREE) {
            free_i = i;
            break;
        }
    if (free_i < 0) return np_command_result(out, cmd, 409, "too_many_lobbies"); /* refused, not an error */
    slot_t *s = &c->slots[free_i];
    memset(s, 0, sizeof *s);
    s->host = role.data[0] == 1;
    if (!s->host && (!arg(cmd, 16, 33, &hk) || !arg(cmd, 18, 0, &addr)))
        return np_command_result(out, cmd, 400, "bad_request");
    /* The address rule (action.h), before anything is kept: a refusal. */
    if (!s->host && !gz_connect_address_ok(addr)) return np_command_result(out, cmd, 400, "bad_address");
    do {
        c->slot_serial++;
    } while (!free_gen_ok(c, (uint16_t)c->slot_serial));
    s->state = SLOT_OPEN;
    s->serial = c->slot_serial;
    s->gen = (uint16_t)s->serial;
    memcpy(s->scope, scope.data, 32);
    if (arg(cmd, 20, 4, &v)) s->ts.timer_ms = gz_get_u32(v.data);
    if (arg(cmd, 22, 1, &v)) s->listed = v.data[0] != 0;
    if (!s->host) {
        memcpy(s->host_key.key, hk.data, 33);
        s->key_epoch = c->np.epoch;
        s->key_index = 2 * s->serial; /* P4.2 saves the pair in key_index, with the guard */
        gz_action_t a = {.kind = GZ_ACTION_CONNECT};
        a.u.connect.host = s->host_key;
        a.u.connect.address = addr;
        a.u.connect.key_epoch = s->key_epoch;
        a.u.connect.key_index = s->key_index;
        if ((st = gz_action_list_add(out, &a)) != GZ_OK) return st;
    }
    gz_c_engine_opened(c, ENG_SLOT0 + free_i);
    if ((st = gz_c_slot_inline(c, ENG_SLOT0 + free_i, open_inline, out)) != GZ_OK) return st;
    return np_command_result(out, cmd, 200, NULL);
}

static gz_status_t slot_close(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t scope;
    gz_status_t st;
    int i;
    if (!arg(cmd, 12, 32, &scope) || (i = standin_slot(c, scope.data)) < 0)
        return np_command_result(out, cmd, 404, "no_such_lobby");
    slot_t *s = &c->slots[i];
    if ((st = gz_timer_cancel_slot(s, out)) != GZ_OK) return st;
    if (!s->host) {
        gz_link_t l;
        if (gz_route_slot_link(c, i, &l) && (st = disconnect(out, &l, GZ_DISCONNECT_DONE)) != GZ_OK) return st;
    }
    s->state = SLOT_FREE;
    /* Its seats end with it, and its engine's watches and unconfirmed batches
     * are no longer anyone's: the next slot at this index inherits nothing. */
    gz_c_engine_closed(c, ENG_SLOT0 + i);
    for (int k = 0; k < NP_MAX_CONNS; k++) {
        np_conn_t *n = &c->np.conns[k];
        int was = n->seated;
        if (!n->used || !n->connected) continue;
        if (n->slot == i) {
            n->slot = -1; /* unbound again, and unseated: the cap and the idle rule apply */
            n->since_ms = mono_ms(c);
        }
        /* A seat in the closed slot is gone, whichever slot the connection is
         * bound to; a seat in another Open slot stands. */
        n->seated = gz_route_slot_seated(c, &n->link.remote) >= 0;
        if (was && !n->seated) n->since_ms = n->unseated_ms = mono_ms(c);
    }
    /* The cap holds at once: the excess is closed now, the silent first. */
    if ((st = keep_cap(c, out)) != GZ_OK) return st;
    if ((st = arm_idle(c, out)) != GZ_OK) return st;
    return np_command_result(out, cmd, 200, NULL);
}

static gz_status_t slot_seat(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t scope, key, v;
    gz_status_t st;
    int i;
    if (!arg(cmd, 12, 32, &scope) || !arg(cmd, 14, 33, &key) || (i = standin_slot(c, scope.data)) < 0 ||
        !c->slots[i].host)
        return np_command_result(out, cmd, 404, "no_such_lobby");
    memcpy(c->np.seat_key.key, key.data, 33);
    c->np.seat_val = !(arg(cmd, 16, 1, &v) && v.data[0] == 0);
    /* A full seat table is the person's doing here: a refusal, as the lobby
     * refuses a join past its seats. (A slot's engine that marks more seats
     * than the table holds broke its own cap: GZ_ERR_BUG, handoff.c.) */
    if (c->np.seat_val && c->slots[i].n_seated == SLOT_MAX_SEATS) {
        size_t k;
        for (k = 0; k < c->slots[i].n_seated; k++)
            if (np_same_key(&c->slots[i].seated[k], &c->np.seat_key)) break;
        if (k == c->slots[i].n_seated) return np_command_result(out, cmd, 409, "too_many_seats");
    }
    /* The SET_SEATED is noted when the bracket closes (handoff.c): a
     * connection of that key, unbound now, is then seated and bound. */
    if ((st = gz_c_slot_inline(c, ENG_SLOT0 + i, seat_inline, out)) != GZ_OK) return st;
    return np_command_result(out, cmd, 200, NULL);
}

/* slot-watch and slot-save: the stand-in asks for a watch, or saves a record,
 * as a slot's lobby or its funding plan will. */
static gz_status_t slot_watch(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t scope, txid, depth;
    gz_status_t st;
    int i, n = 0;
    if (!arg(cmd, 12, 32, &scope) || (i = standin_slot(c, scope.data)) < 0)
        return np_command_result(out, cmd, 404, "no_such_lobby");
    if (!arg(cmd, 14, 32, &txid) || !arg(cmd, 16, 4, &depth) || gz_get_u32(depth.data) == 0)
        return np_command_result(out, cmd, 400, "bad_request");
    /* The stand-in's own cap: past its budget of watches, a refusal. */
    for (int w = 0; w < MAX_WATCHES; w++) {
        if (!c->watches[w].used || !(c->watches[w].mask & (1u << (ENG_SLOT0 + i)))) continue;
        if (c->watches[w].is_tx && !memcmp(c->watches[w].key, txid.data, 32)) {
            n = -1; /* one it already has: only the depth can change */
            break;
        }
        n++;
    }
    if (n >= TS_MAX_WATCHES) return np_command_result(out, cmd, 409, "too_many_watches");
    memcpy(c->np.seat_key.key, txid.data, 32);
    c->np.seat_val = (int)gz_get_u32(depth.data);
    if ((st = gz_c_slot_inline(c, ENG_SLOT0 + i, watch_inline, out)) != GZ_OK) return st;
    return np_command_result(out, cmd, 200, NULL);
}

static gz_status_t slot_save(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_bytes_t scope;
    gz_status_t st;
    int i;
    if (!arg(cmd, 12, 32, &scope) || (i = standin_slot(c, scope.data)) < 0)
        return np_command_result(out, cmd, 404, "no_such_lobby");
    if ((st = gz_c_slot_inline(c, ENG_SLOT0 + i, save_inline, out)) != GZ_OK) return st;
    return np_command_result(out, cmd, 200, NULL);
}
#endif

/* Node-part commands (0x7e80 and up in test builds; 0x04xx from P4.2). */
gz_status_t np_command(gz_node_t *c, uint16_t code, gz_bytes_t cmd, gz_action_list_t *out)
{
    gz_status_t st = gz_c_node_bracket_begin(c, out);
    if (st != GZ_OK) return st;
    switch (code) {
#ifdef GZ_TEST_KINDS
    case 0x7e80: st = slot_open(c, cmd, out); break;
    case 0x7e81: st = slot_close(c, cmd, out); break;
    case 0x7e82: st = slot_seat(c, cmd, out); break;
    case 0x7e83: {
        gz_bytes_t scope;
        int i;
        if (arg(cmd, 12, 32, &scope) && (i = standin_slot(c, scope.data)) >= 0) {
            c->slots[i].round_ok = 1;
            st = np_command_result(out, cmd, 200, NULL);
        } else {
            st = np_command_result(out, cmd, 404, "no_such_lobby");
        }
        break;
    }
    case 0x7e84: st = slot_watch(c, cmd, out); break;
    case 0x7e85: st = slot_save(c, cmd, out); break;
#endif
    default: st = gz_ls_command(c, code, cmd, out); break; /* the lobby's, the gate's, or unknown_command */
    }
    if (st == GZ_OK) return gz_c_node_bracket_end(c, out);
    c->bracket_on = 0;
    return st;
}

/* ---- for a slot's lobby (lobbyslot.c) ------------------------------------- */

uint64_t np_mono(gz_node_t *c)
{
    return mono_ms(c);
}

gz_status_t np_set_timer(gz_action_list_t *out, uint32_t id, uint64_t delay)
{
    return set_timer(out, id, delay);
}

gz_status_t np_disconnect(gz_action_list_t *out, const gz_link_t *link, uint16_t why)
{
    return disconnect(out, link, why);
}

/* A slot is Free: its timers are cancelled, its engine's watches and
 * unconfirmed batches are nobody's, and every connection bound to it is
 * unbound and unseated again, the cap kept in this step (section 3). */
gz_status_t np_slot_freed(gz_node_t *c, int i, gz_action_list_t *out)
{
    slot_t *s = &c->slots[i];
    gz_status_t st;
    if ((st = gz_timer_cancel_slot(s, out)) != GZ_OK) return st;
    s->state = SLOT_FREE;
    gz_c_engine_closed(c, ENG_SLOT0 + i);
    for (int k = 0; k < NP_MAX_CONNS; k++) {
        np_conn_t *n = &c->np.conns[k];
        int was = n->seated;
        if (!n->used || !n->connected) continue;
        if (n->slot == i) {
            n->slot = -1;
            n->since_ms = mono_ms(c);
        }
        n->seated = gz_route_slot_seated(c, &n->link.remote) >= 0;
        if (was && !n->seated) n->since_ms = n->unseated_ms = mono_ms(c);
    }
    if ((st = keep_cap(c, out)) != GZ_OK) return st;
    return arm_idle(c, out);
}

/* A slot's first batch (7.4): key_epoch 0 the first time a key is allocated
 * (journal.md 8.2 step 1), key_index for the pair `first`, `first` + 1 (the
 * contribution key and the factory key), the guard (8.3: with every
 * key_index; its epochs and highest indexes are the union the restore batch
 * made, T-P42-3), then `extra` (slot_opened). The lobby's own first record
 * follows it in the list and joins the batch. */
gz_status_t np_save_pair(gz_node_t *c, uint32_t first, const gz_record_t *extra, gz_action_list_t *out)
{
    uint8_t eb[16], kb[16], gb[NP_GUARD_HEAD + 8 * (NP_MAX_OLD_EPOCHS + 1)], v[4];
    gz_record_t recs[4];
    size_t n = 0, at = 0;
    np_t *p = &c->np;
    if (first <= p->highest_index || first + 1 < first) return gz_c_bug(c, ENG_NODE); /* never an index twice */
    if (!p->have_epoch) {
        recs[n].type = GZ_RECORD_KEY_EPOCH;
        recs[n].bytes.data = eb;
        recs[n].bytes.len = epoch_record(eb, sizeof eb, 0);
        n++;
        p->epoch = 0;
        p->have_epoch = 1;
    }
    p->highest_index = first + 1;
    gz_put_u32(v, p->highest_index);
    if (gz_rec_put(kb, sizeof kb, &at, 2, v, 4) != GZ_OK) return gz_c_bug(c, ENG_NODE);
    recs[n].type = GZ_RECORD_KEY_INDEX;
    recs[n].bytes.data = kb;
    recs[n].bytes.len = at;
    n++;
    p->guard_counter++;
    recs[n].type = GZ_RECORD_GUARD;
    recs[n].bytes.data = gb;
    recs[n].bytes.len = guard_record(c, gb);
    n++;
    recs[n++] = *extra;
    return save_records(out, recs, n);
}
