/* Sequence fuzz target (review A of PR 30, S9; strengthened after review B):
 * each input is a script. Its first byte picks a host fed signed messages,
 * connections, timers, clock steps, commands and restarts from up to 64
 * member keys (enough to reach the caps: 16 unseated connections, 48
 * connections, target + standbys seats taken, 4 x target creations), or a
 * member fed the same from its host. With the vectors' terms (target 8),
 * 4 x target is 32: the creation cap stops a 33rd seat first, so the
 * 32-seat table's own refusal is not reached here (test_lobby restores a
 * full table). The plain driver counts the scripts that reach the creation
 * cap and the budget timers that fire in Signing (the B3 check below). The engines live across the whole script, so the stateful
 * rules are reached: a refused ready (F5), strangers and failed checks (F6),
 * joins that are refused (F8), restarts in Signing (F3), commands at the
 * wrong moment (F10), a chosen seat that leaves and comes back (B1).
 *
 * Both engines are given a model of the signing engine (review B's), which
 * remembers the checks it began, with their participants, and the checks it
 * finished, and checks the hand-off:
 *   V1  a check whose outcome the lobby saved is never handed over again;
 *   V2  one check never names other participants (host).
 *
 * A restart is a crash: the saves of the last action list survive only up to
 * a point the script picks, as storage may lose a batch that was never
 * confirmed. What the runner had sent by then (a send is held until every
 * save listed before it is confirmed) must be justified by what survived:
 *   host    a `start` by its check's `start_sent`, a `ready_check` by the
 *           `freeze`, a `cancel` by `lobby_ended`, a seat notice by the
 *           seat's record, a status showing Funding or Active by `lobby_state`;
 *   member  a `join` by `joined` and a `ready` by `ready_sent` (the same
 *           bytes), a `leave` by its `lobby_ended`.
 * So moving a save after the send it justifies fails here.
 *
 * Also, after every step:
 *   - every engine call returns GZ_OK (a duplicate CONNECTED is not made);
 *   - host: each seat in memory equals its last saved `seat` record (state,
 *     min_members, version), so nothing is changed without its save;
 *   - host: one input verifies at most two signatures;
 *   - host: a connection from a key without a seat starts no ready check;
 *   - member: the signing engine is begun only for a check the member may
 *     still sign for (gz_lobby_member_may_sign);
 *   - a restart from the saved records succeeds, and so does its resume.
 * A failed check aborts, so libFuzzer and the plain driver both report it. */
#include "lobby_test.h"
#include "../../core/lobby/lobby_internal.h"
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
unsigned long lobby_seq_stats[10];  /* steps, seats, checks, starts, begins, restarts, refused, cancels,
                                       lobbies at the creation cap, budget timers in Signing */

#define MUST(c) do { if (!(c)) { fprintf(stderr, "fuzz_lobby_seq: %s (step %lu)\n", #c, lobby_seq_stats[0]); abort(); } } while (0)
#define NK 64                        /* member keys; any may stay a stranger */
#define NONE ((size_t)-1)

static int ready_;
static lt_signer_t HOST, K[NK];
static uint8_t SCOPE[32], T1[512], T2[128], T3[128], CD[3][32];
static size_t T1N, T2N, T3N;
static uint64_t NOW, rnd;
static gz_action_t slots[256];
static uint8_t abytes[1 << 19];
static gz_action_list_t L;
static unsigned long STEP;

typedef struct { uint32_t type; size_t n; uint8_t *b; } rec_t;
static rec_t RECS[1024];
static size_t NREC;

static uint64_t c_now(void *ctx) { (void)ctx; return NOW; }
static void c_rand(void *ctx, gz_random_purpose_t p, uint8_t *o, size_t n)
{
    size_t i;
    (void)ctx; (void)p;
    for (i = 0; i < n; i++) { rnd ^= rnd << 13; rnd ^= rnd >> 7; rnd ^= rnd << 17; o[i] = (uint8_t)rnd; }
}

static void setup(void)
{
    int i;
    char label[48];
    if (ready_) return;
    lt_key(&HOST.key[1], "host"); lt_key(&HOST.key[3], "host factory");
    for (i = 0; i < NK; i++) {
        snprintf(label, sizeof label, "member %d contribution", i + 1); lt_key(&K[i].key[2], label);
        snprintf(label, sizeof label, "member %d factory", i + 1); lt_key(&K[i].key[3], label);
    }
    T1N = lt_unhex(LT_T1, T1, sizeof T1);
    T2N = lt_unhex(LT_T2, T2, sizeof T2);
    T3N = lt_unhex(LT_T3, T3, sizeof T3);
    gz_terms_outer_digest(T1, T1N, SCOPE);
    gz_terms_current_digest(T2, T2N, CD[1]);
    gz_terms_current_digest(T3, T3N, CD[2]);
    ready_ = 1;
}

static gz_ports_t ports(void)
{
    gz_ports_t p;
    p.random.fill = c_rand; p.random.ctx = NULL;
    p.clock.now_ms = c_now; p.clock.ctx = NULL;
    return p;
}

static void lreset(void) { gz_action_list_init(&L, slots, 256, abytes, sizeof abytes); }

static int sends_kind(uint16_t kind)
{
    size_t i;
    int c = 0;
    gz_lobby_msg_t m;
    for (i = 0; i < L.count; i++)
        if (L.slots[i].kind == GZ_ACTION_SEND &&
            gz_lobby_decode(L.slots[i].u.send.bytes.data, L.slots[i].u.send.bytes.len, &m) == GZ_DEC_OK && m.kind == kind)
            c++;
    return c;
}

static int refused_now(void)
{
    size_t i;
    for (i = 0; i < L.count; i++)
        if (L.slots[i].kind == GZ_ACTION_NOTIFY && L.slots[i].u.notify.code == GZ_NOTE_COMMAND_REFUSED) return 1;
    return 0;
}

/* ------------------------------------------------- storage and crashes */

/* The last list, action by action, for a crash: which records each save
 * holds, and a copy of what each send or notice carried. */
typedef struct {
    int kind;                        /* GZ_ACTION_* */
    size_t r0, r1;                   /* SAVE: RECS[r0..r1) */
    uint8_t b[320]; size_t n;        /* SEND (whole message, if it fits) or NOTIFY bytes */
    uint32_t code;
} la_t;
static la_t LA[256];
static size_t NLA;

/* Keep the list's saves (pending until the next step: a crash then may lose
 * a suffix of them), and remember the list. */
static void keep(void)
{
    size_t i, j;
    NLA = 0;
    for (i = 0; i < L.count; i++) {
        const gz_action_t *a = &L.slots[i];
        la_t *x = &LA[NLA++];
        memset(x, 0, sizeof *x);
        x->kind = a->kind;
        if (a->kind == GZ_ACTION_SAVE) {
            x->r0 = NREC;
            for (j = 0; j < a->u.save.n_records && NREC < 1024; j++) {
                const gz_record_t *r = &a->u.save.records[j];
                RECS[NREC].type = r->type;
                RECS[NREC].n = r->bytes.len;
                RECS[NREC].b = malloc(r->bytes.len + 1);
                MUST(RECS[NREC].b != NULL);
                memcpy(RECS[NREC].b, r->bytes.data, r->bytes.len);
                NREC++;
            }
            x->r1 = NREC;
        } else if (a->kind == GZ_ACTION_SEND && a->u.send.bytes.len <= sizeof x->b) {
            x->n = a->u.send.bytes.len;
            memcpy(x->b, a->u.send.bytes.data, x->n);
        } else if (a->kind == GZ_ACTION_NOTIFY) {
            x->code = a->u.notify.code;
            x->n = a->u.notify.bytes.len < sizeof x->b ? a->u.notify.bytes.len : sizeof x->b;
            memcpy(x->b, a->u.notify.bytes.data, x->n);
        }
    }
}

static void drop_recs(void)
{
    size_t i;
    for (i = 0; i < NREC; i++) free(RECS[i].b);
    NREC = 0;
    NLA = 0;
}

/* The signing engine's side, a model (review B): begun and finished checks. */
typedef struct {
    uint8_t check[32]; int n;
    uint8_t ck[GZ_LOBBY_MAX_SEATS + 1][33], fk[GZ_LOBBY_MAX_SEATS + 1][33];
    unsigned long step; size_t pos;   /* when, and where in that step's list, it was begun */
} beg_t;
typedef struct { uint8_t check[32]; size_t rec; } end_t;   /* rec: the lobby's saved outcome, or NONE */
static beg_t BEG[64];
static end_t ENDS[64];
static int NBEG, NEND;

static end_t *ended(const uint8_t *check)
{
    int k;
    for (k = 0; k < NEND; k++) if (memcmp(ENDS[k].check, check, 32) == 0) return &ENDS[k];
    return NULL;
}

/* The signing engine finished `check`; the lobby saved the outcome in the
 * last list (its record of `type`), or nothing was saved. */
static void finish(const uint8_t *check, size_t from, uint32_t type1, uint32_t type2)
{
    end_t *e = ended(check);
    size_t i, rec = NONE;
    for (i = from; i < NREC; i++) if (RECS[i].type == type1 || RECS[i].type == type2) rec = i;
    if (!e && NEND < 64) { e = &ENDS[NEND++]; memcpy(e->check, check, 32); e->rec = NONE; }
    if (e && rec != NONE) e->rec = rec;
}

static void model_reset(void) { NBEG = NEND = 0; }

/* A durable record of `type` whose bytes start with `pre` (n bytes). */
static int durable(uint32_t type, const uint8_t *pre, size_t n)
{
    size_t i;
    for (i = 0; i < NREC; i++)
        if (RECS[i].type == type && RECS[i].n >= n && (n == 0 || memcmp(RECS[i].b, pre, n) == 0)) return 1;
    return 0;
}

static int durable_exact(uint32_t type, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < NREC; i++)
        if (RECS[i].type == type && RECS[i].n == n && memcmp(RECS[i].b, b, n) == 0) return 1;
    return 0;
}

/* A crash: the last list's saves survive up to the `keep`th save action.
 * Then what the runner had sent by then must be justified by what survived. */
static void crash(uint8_t arg, int host)
{
    size_t i, ns = 0, kept, p = NLA, cut = NREC;
    int k;
    for (i = 0; i < NLA; i++) ns += LA[i].kind == GZ_ACTION_SAVE;
    kept = arg % (ns + 1);
    for (i = 0, k = 0; i < NLA; i++)
        if (LA[i].kind == GZ_ACTION_SAVE && (size_t)k++ == kept) { p = i; cut = LA[i].r0; break; }
    for (i = cut; i < NREC; i++) free(RECS[i].b);
    NREC = cut;
    for (k = 0; k < NEND; k++) if (ENDS[k].rec != NONE && ENDS[k].rec >= NREC) ENDS[k].rec = NONE;
    for (k = 0; k < NBEG; k++)                        /* a begin after a lost save never happened */
        if (BEG[k].step == STEP && BEG[k].pos > p) { BEG[k] = BEG[--NBEG]; k--; }
    for (i = 0; i < p; i++) {                         /* sent before the crash */
        gz_lobby_msg_t m;
        const la_t *x = &LA[i];
        if (x->kind == GZ_ACTION_NOTIFY && x->code == GZ_NOTE_SEATED && x->n == 34) MUST(durable(GZ_REC_SEAT, x->b, 33));
        if (x->kind != GZ_ACTION_SEND || !x->n || gz_lobby_decode(x->b, x->n, &m) != GZ_DEC_OK) continue;
        if (host) {
            if (m.kind == GZ_KIND_START) MUST(durable(GZ_REC_START_SENT, m.check_id, 32));
            if (m.kind == GZ_KIND_READY_CHECK) MUST(durable(GZ_REC_FREEZE, NULL, 0));
            if (m.kind == GZ_KIND_CANCEL) MUST(durable(GZ_REC_LOBBY_ENDED, NULL, 0));
            if (m.kind == GZ_KIND_LOBBY_STATUS && (m.lobby_state == GZ_LOBBY_FUNDING || m.lobby_state == GZ_LOBBY_ACTIVE))
                MUST(durable(GZ_REC_LOBBY_STATE, &m.lobby_state, 1));
        } else {
            static const uint8_t left0 = 0;
            if (m.kind == GZ_KIND_JOIN) MUST(durable_exact(GZ_REC_JOINED, x->b, x->n));
            if (m.kind == GZ_KIND_READY) MUST(durable_exact(GZ_REC_READY_SENT, x->b, x->n));
            if (m.kind == GZ_KIND_LEAVE) MUST(durable(GZ_REC_LOBBY_ENDED, &left0, 1));
        }
    }
    NLA = 0;
}

/* ------------------------------------------------------------- the host */

static gz_lobby_host_t H;
static int CONN[NK];

static gz_status_t h_begin(void *ctx, const gz_lobby_handoff_t *ho, gz_action_list_t *out)
{
    end_t *e;
    int i, k;
    (void)ctx;
    MUST(ho->participants && ho->n_participants == ho->signers && ho->n_participants >= 2 && ho->role == 1);
    if ((e = ended(ho->check_id)) != NULL) {          /* V1; otherwise ignored, as the header says */
        MUST(e->rec == NONE);
        return GZ_OK;
    }
    for (k = 0; k < NBEG; k++)
        if (memcmp(BEG[k].check, ho->check_id, 32) == 0) {   /* V2 */
            MUST(ho->resume && BEG[k].n == ho->n_participants);
            for (i = 0; i < ho->n_participants; i++)
                MUST(memcmp(BEG[k].ck[i], ho->participants[i].contribution_key, 33) == 0 &&
                     memcmp(BEG[k].fk[i], ho->participants[i].factory_key, 33) == 0);
            return GZ_OK;
        }
    lobby_seq_stats[4]++;
    if (NBEG == 64) return GZ_OK;
    BEG[NBEG].n = ho->n_participants;
    memcpy(BEG[NBEG].check, ho->check_id, 32);
    for (i = 0; i < ho->n_participants && i <= GZ_LOBBY_MAX_SEATS; i++) {
        memcpy(BEG[NBEG].ck[i], ho->participants[i].contribution_key, 33);
        memcpy(BEG[NBEG].fk[i], ho->participants[i].factory_key, 33);
    }
    BEG[NBEG].step = STEP;
    BEG[NBEG].pos = out->count;
    NBEG++;
    return GZ_OK;
}

static gz_status_t h_cancel(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out)
{
    (void)ctx; (void)out;
    MUST(memcmp(scope, SCOPE, 32) == 0 && reason >= 1 && reason <= 3);
    return GZ_OK;
}

static gz_status_t h_left(void *ctx, const uint8_t scope[32], const uint8_t ckey[33], gz_action_list_t *out)
{
    (void)ctx; (void)scope; (void)out;
    MUST(H.state == GZ_LOBBY_SIGNING);                /* only a chosen seat, while its round runs */
    {
        uint16_t k;
        int found = 0;
        for (k = 0; k < H.n_seats; k++)
            if (memcmp(H.seats[k].ckey, ckey, 33) == 0) found = H.seats[k].chosen && H.seats[k].state == GZ_SEAT_LEFT;
        MUST(found);
    }
    return GZ_OK;
}

static gz_status_t h_in(int kind, int who, const uint8_t *b, size_t n, uint64_t timer)
{
    gz_lobby_input_t in;
    memset(&in, 0, sizeof in);
    in.kind = kind; in.peer_id = 100 + (uint64_t)who; in.peer_key = K[who].key[2].pub;
    in.bytes = b; in.len = n; in.timer_id = timer;
    lreset();
    return gz_lobby_host_handle(&H, &in, &L);
}

static void host_boot(int restore, uint16_t standbys)
{
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(&HOST);
    gz_lobby_host_config_t cfg;
    gz_lobby_signing_t sg;
    size_t i;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, HOST.key[3].pub, 33);
    cfg.standbys = standbys;
    memset(&sg, 0, sizeof sg);
    sg.begin = h_begin; sg.cancel = h_cancel; sg.member_left = h_left;
    MUST(gz_lobby_host_init(&H, &p, &cr, &sg, &cfg) == GZ_OK);
    lreset();
    if (!restore) {
        MUST(gz_lobby_host_open(&H, T1, T1N, T2, T2N, &L) == GZ_OK);
        keep();
        return;
    }
    for (i = 0; i < NREC; i++) {
        gz_record_t r;
        r.type = RECS[i].type; r.bytes.data = RECS[i].b; r.bytes.len = RECS[i].n;
        MUST(gz_lobby_host_restore(&H, &r) == GZ_OK);
    }
    MUST(gz_lobby_host_resume(&H, &L) == GZ_OK);
    keep();
    memset(CONN, 0, sizeof CONN);                     /* a restart closes every connection */
}

/* Every seat in memory is its last saved record. */
static void seats_saved(void)
{
    uint16_t s;
    size_t i;
    for (s = 0; s < H.n_seats; s++) {
        const gz_lobby_seat_t *t = &H.seats[s];
        const rec_t *last = NULL;
        for (i = 0; i < NREC; i++)
            if (RECS[i].type == GZ_REC_SEAT && RECS[i].n >= 209 && memcmp(RECS[i].b, t->ckey, 33) == 0) last = &RECS[i];
        MUST(last != NULL);
        MUST(last->b[194] == t->state && gz_lw_get(last->b + 195, 2) == t->min_members &&
             gz_lw_get(last->b + 197, 4) == t->ready_version && memcmp(last->b + 33, t->fkey, 33) == 0);
    }
}

static size_t join_msg(uint8_t *buf, size_t cap, int who, int fkey_of, int bad)
{
    uint8_t b[32], sf[64], sc[64];
    gz_lobby_enc_t e;
    gz_lobby_binding(SCOPE, K[fkey_of].key[3].pub, K[who].key[2].pub, b);
    lt_sign(&K[fkey_of], 3, b, sf);
    lt_sign(&K[who], 2, b, sc);
    if (bad) sf[bad % 64] ^= 1;
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_JOIN, SCOPE);
    gz_lobby_enc_record(&e, 2, K[fkey_of].key[3].pub, 33);
    gz_lobby_enc_record(&e, 4, sf, 64);
    gz_lobby_enc_record(&e, 6, sc, 64);
    return gz_lobby_enc_done(&e);
}

static void host_script(const uint8_t *d, size_t n)
{
    static uint8_t buf[600];
    size_t at, bn;
    gz_lobby_enc_t e;
    gz_lobby_crypto_t cr;
    gz_status_t st;
    drop_recs();
    model_reset();
    host_boot(0, (uint16_t)(d[0] % 3));
    memset(CONN, 0, sizeof CONN);
    for (at = 1; at + 3 <= n; at += 3) {
        int op = d[at] % 13, who = d[at + 1] % NK;
        uint8_t arg = d[at + 2];
        unsigned long v0 = HOST.verifies;
        int seated_key;
        STEP++;
        lobby_seq_stats[0]++;
        if (op != 0 && op != 11 && op != 12 && !CONN[who]) op = 0;   /* messages need a connection */
        {
            const gz_lobby_seat_t *s = NULL;
            uint16_t k;
            for (k = 0; k < H.n_seats; k++) if (memcmp(H.seats[k].ckey, K[who].key[2].pub, 33) == 0) s = &H.seats[k];
            seated_key = s && (s->state == GZ_SEAT_JOINED || s->state == GZ_SEAT_READY);
        }
        switch (op) {
        case 0:                                                       /* connect */
            if (CONN[who]) { st = h_in(GZ_LIN_DISCONNECTED, who, NULL, 0, 0); CONN[who] = 0; break; }
            st = h_in(GZ_LIN_CONNECTED, who, NULL, 0, 0);
            CONN[who] = 1;
            if (!seated_key) MUST(sends_kind(GZ_KIND_READY_CHECK) == 0);   /* F6 */
            break;
        case 1:
            st = h_in(GZ_LIN_DISCONNECTED, who, NULL, 0, 0);
            CONN[who] = 0;
            break;
        case 2:
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_HELLO, arg & 1 ? SCOPE : (const uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
            bn = gz_lobby_enc_done(&e);
            st = h_in(GZ_LIN_MESSAGE, who, buf, bn, 0);
            break;
        case 3: case 4:                                               /* join; 4: another factory key, maybe invalid */
            bn = join_msg(buf, sizeof buf, who, op == 3 ? who : (arg >> 1) % NK, op == 4 && (arg & 1) ? 1 + (arg >> 1) : 0);
            st = h_in(GZ_LIN_MESSAGE, who, buf, bn, 0);
            break;
        case 5: {                                                     /* ready */
            uint32_t ver = arg % 4 == 3 ? H.values.version : (uint32_t)(1 + arg % 2);
            cr = lt_crypto(&K[who]);
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_READY, SCOPE);
            gz_lobby_enc_record(&e, 2, SCOPE, 32);
            gz_lobby_enc_u32(&e, 4, ver);
            gz_lobby_enc_record(&e, 6, ver == H.values.version ? H.current_digest : CD[ver <= 2 ? ver : 1], 32);
            if (arg & 8) gz_lobby_enc_record(&e, 8, H.check_id, 32);
            if (arg & 16) gz_lobby_enc_u16(&e, 11, (uint16_t)(arg >> 5) * 2);
            bn = gz_lobby_enc_sign(&e, &cr, GZ_LOBBY_KEY_CONTRIBUTION);
            st = h_in(GZ_LIN_MESSAGE, who, buf, bn, 0);
            break;
        }
        case 6: case 7:                                               /* unready, leave */
            gz_lobby_enc_start(&e, buf, sizeof buf, op == 6 ? GZ_KIND_UNREADY : GZ_KIND_LEAVE, SCOPE);
            if (arg & 1) gz_lobby_enc_u16(&e, 1, arg % 4);
            bn = gz_lobby_enc_done(&e);
            st = h_in(GZ_LIN_MESSAGE, who, buf, bn, 0);
            break;
        case 8: {                                                     /* a timer */
            static const uint64_t T[5] = {GZ_LOBBY_TIMER_WINDOW, GZ_LOBBY_TIMER_IDLE, GZ_LOBBY_TIMER_STATUS,
                                          GZ_LOBBY_TIMER_DEADLINE, GZ_LOBBY_TIMER_BUDGET};
            int signing = H.state == GZ_LOBBY_SIGNING;
            if (arg % 5 == 4 && signing) lobby_seq_stats[9]++;
            st = h_in(GZ_LIN_TIMER, who, NULL, 0, T[arg % 5]);
            if (arg % 5 == 0 && sends_kind(GZ_KIND_START)) lobby_seq_stats[3]++;
            if (arg % 5 == 4 && signing) MUST(L.count == 0 && H.state == GZ_LOBBY_SIGNING);   /* B3 */
            break;
        }
        case 9:                                                       /* the clock */
            NOW += (arg & 128) ? (uint64_t)(arg & 127) * 60000 : (uint64_t)arg * 100;
            st = GZ_OK;
            lreset();
            break;
        case 10: {                                                    /* commands, and the signing engine's outcome */
            uint8_t chk[32];
            int was = H.state, outcome = 0;
            size_t from = NREC;
            memcpy(chk, H.check_id, 32);
            lreset();
            switch (arg % 5) {
            case 0: { uint64_t v[3] = {500 + (uint64_t)arg, 1000, 1000}; st = gz_lobby_host_set_values(&H, v, 3, &L); break; }
            case 1: st = gz_lobby_host_remove(&H, K[who].key[2].pub, &L); break;
            case 2: st = gz_lobby_host_cancel(&H, (uint16_t)(1 + arg % 3), &L); break;
            case 3: outcome = GZ_LOBBY_ROUND_RETRY;
                    st = gz_lobby_host_round_result(&H, outcome, K[who].key[2].pub, 1, &L); break;
            default: outcome = 1 + (arg >> 3) % 4;
                     st = gz_lobby_host_round_result(&H, outcome, NULL, 0, &L); break;
            }
            if (st == GZ_ERR_ARGUMENT && arg % 5 == 0) st = GZ_OK;   /* values outside the ranges */
            if (st == GZ_OK && outcome && !refused_now()) {
                MUST(was >= GZ_LOBBY_SIGNING);
                if (outcome == GZ_LOBBY_ROUND_FUNDING || outcome == GZ_LOBBY_ROUND_ACTIVE) MUST(H.state != was);   /* B3: taken */
                keep();
                finish(chk, from, GZ_REC_LOBBY_STATE, GZ_REC_LOBBY_ENDED);
                MUST(HOST.verifies - v0 <= 2);
                seats_saved();
                continue;
            }
            break;
        }
        case 11:                                                      /* a crash and a restart */
            crash(arg, 1);
            host_boot(1, (uint16_t)(d[0] % 3));
            lobby_seq_stats[5]++;
            seats_saved();
            continue;
        default:                                                      /* a garbled message */
            bn = join_msg(buf, sizeof buf, who, who, 0);
            buf[arg % bn] ^= (uint8_t)(1 + (arg >> 4));
            if (!CONN[who]) { st = GZ_OK; lreset(); break; }
            st = h_in(GZ_LIN_MESSAGE, who, buf, bn, 0);
            break;
        }
        MUST(st == GZ_OK);
        keep();
        lobby_seq_stats[2] += (unsigned long)(sends_kind(GZ_KIND_READY_CHECK) > 0);
        MUST(HOST.verifies - v0 <= 2);                                /* F8: never a flood of verifications */
        seats_saved();                                                /* F5 */
    }
    lobby_seq_stats[1] += H.n_seats;
    lobby_seq_stats[7] += H.state >= GZ_LOBBY_CANCELLED;
    lobby_seq_stats[8] += H.created >= 4u * H.terms.target;
}

/* ------------------------------------------------------------ the member */

static gz_lobby_member_t M;
static int MCONN;

static gz_status_t m_begin(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out)
{
    end_t *e;
    (void)ctx; (void)out;
    MUST(gz_lobby_member_may_sign(&M, h->check_id));
    MUST(h->limits && h->outer_sig && h->current_sig && h->pinned_key && h->values);
    if ((e = ended(h->check_id)) != NULL) MUST(e->rec == NONE);   /* V1 */
    lobby_seq_stats[4]++;
    return GZ_OK;
}

static void member_boot(int restore)
{
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(&K[0]);
    gz_lobby_conditions_t cond = lt_cond_fits();
    gz_lobby_signing_t sg;
    size_t i;
    memset(&sg, 0, sizeof sg);
    sg.begin = m_begin;
    MUST(gz_lobby_member_init(&M, &p, &cr, &sg, &cond, SCOPE, HOST.key[1].pub, K[0].key[2].pub, K[0].key[3].pub, 1) == GZ_OK);
    MCONN = 0;
    if (!restore) return;
    for (i = 0; i < NREC; i++) {
        gz_record_t r;
        r.type = RECS[i].type; r.bytes.data = RECS[i].b; r.bytes.len = RECS[i].n;
        MUST(gz_lobby_member_restore(&M, &r) == GZ_OK);
    }
    lreset();
    MUST(gz_lobby_member_resume(&M, &L) == GZ_OK);
    keep();
}

static gz_status_t m_in(int kind, const uint8_t *b, size_t n, uint64_t timer)
{
    gz_lobby_input_t in;
    memset(&in, 0, sizeof in);
    in.kind = kind; in.peer_id = 1; in.peer_key = HOST.key[1].pub;
    in.bytes = b; in.len = n; in.timer_id = timer;
    lreset();
    return gz_lobby_member_handle(&M, &in, &L);
}

/* A check the member answers anew is a new round in this script (the
 * script reuses three check ids; a real host's are random). */
static void answered_anew(size_t from)
{
    size_t i;
    int k;
    gz_lobby_msg_t g;
    for (i = from; i < NREC; i++)
        if (RECS[i].type == GZ_REC_READY_SENT && RECS[i].n > 1 && gz_lobby_decode(RECS[i].b, RECS[i].n, &g) == GZ_DEC_OK &&
            g.has_check_id)
            for (k = 0; k < NEND; k++)
                if (memcmp(ENDS[k].check, g.check_id, 32) == 0) { ENDS[k] = ENDS[--NEND]; k--; }
}

static void member_script(const uint8_t *d, size_t n)
{
    static uint8_t buf[70000], big[66000];
    gz_lobby_enc_t e;
    gz_lobby_crypto_t hc = lt_crypto(&HOST);
    uint8_t chk[32], os[64], cs[64];
    size_t at, bn, from;
    gz_status_t st;
    drop_recs();
    model_reset();
    member_boot(0);
    memset(big, 0x61, sizeof big);
    for (at = 1; at + 3 <= n; at += 3) {
        int op = d[at] % 11;
        uint8_t a1 = d[at + 1], arg = d[at + 2];
        STEP++;
        lobby_seq_stats[0]++;
        memset(chk, 0x40 + (a1 % 3), 32);
        from = NREC;
        if (op >= 2 && op <= 6 && !MCONN) op = 0;
        switch (op) {
        case 0:
            st = m_in(MCONN ? GZ_LIN_DISCONNECTED : GZ_LIN_CONNECTED, NULL, 0, 0);
            MCONN = !MCONN;
            break;
        case 1: case 9: {                                             /* user commands */
            gz_lobby_conditions_t c = lt_cond_fits();
            lreset();
            if (arg % 3 == 0) st = gz_lobby_member_unready(&M, &L);
            else if (arg % 3 == 1 && op == 9) st = gz_lobby_member_leave(&M, &L);
            else {
                if (arg & 8) LT_ADJ(c, 0) = arg & 16 ? 400 : 1000;
                c.current_only = (arg >> 5) & 1;
                st = gz_lobby_member_set_conditions(&M, &c, &L);
            }
            break;
        }
        case 2: {                                                     /* terms_offer T2 or T3 */
            const uint8_t *c = arg & 1 ? T3 : T2;
            size_t cn = arg & 1 ? T3N : T2N;
            uint8_t cd[32];
            gz_terms_current_digest(c, cn, cd);
            lt_sign(&HOST, 1, SCOPE, os);
            lt_sign(&HOST, 1, cd, cs);
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_TERMS_OFFER, SCOPE);
            gz_lobby_enc_record(&e, 2, T1, T1N); gz_lobby_enc_record(&e, 4, os, 64);
            gz_lobby_enc_record(&e, 6, c, cn); gz_lobby_enc_record(&e, 8, cs, 64);
            bn = gz_lobby_enc_done(&e);
            st = m_in(GZ_LIN_MESSAGE, buf, bn, 0);
            break;
        }
        case 3:                                                       /* ready_check */
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_READY_CHECK, SCOPE);
            gz_lobby_enc_record(&e, 2, chk, 32);
            gz_lobby_enc_u32(&e, 4, 1 + arg % 2);
            gz_lobby_enc_record(&e, 6, CD[1 + arg % 2], 32);
            gz_lobby_enc_u32(&e, 8, arg & 4 ? 29999 : 30000);
            bn = gz_lobby_enc_sign(&e, &hc, GZ_LOBBY_KEY_HOST);
            st = m_in(GZ_LIN_MESSAGE, buf, bn, 0);
            break;
        case 4:                                                       /* start */
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_START, SCOPE);
            gz_lobby_enc_record(&e, 2, chk, 32);
            gz_lobby_enc_u8(&e, 4, (uint8_t)(1 + arg % 2));
            gz_lobby_enc_u16(&e, 6, (uint16_t)(4 + arg % 6));
            bn = gz_lobby_enc_sign(&e, &hc, GZ_LOBBY_KEY_HOST);
            st = m_in(GZ_LIN_MESSAGE, buf, bn, 0);
            break;
        case 5:                                                       /* cancel, possibly oversized (m17) */
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_CANCEL, SCOPE);
            gz_lobby_enc_u16(&e, 2, (uint16_t)(1 + arg % 3));
            if (arg & 4) gz_lobby_enc_record(&e, 3, big, (size_t)(arg >> 3) * (arg & 128 ? 2000 : 9));
            bn = gz_lobby_enc_sign(&e, &hc, GZ_LOBBY_KEY_HOST);
            if (!bn) { st = GZ_OK; lreset(); break; }
            st = m_in(GZ_LIN_MESSAGE, buf, bn, 0);
            break;
        case 6:                                                       /* lobby_status */
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_LOBBY_STATUS, SCOPE);
            gz_lobby_enc_u8(&e, 2, (uint8_t)(arg % 8));
            gz_lobby_enc_u8(&e, 4, (uint8_t)(a1 % 8));
            gz_lobby_enc_u32(&e, 6, 1 + (arg >> 6));
            gz_lobby_enc_u16(&e, 8, 3); gz_lobby_enc_u16(&e, 10, 2);
            if (arg & 32) gz_lobby_enc_u16(&e, 13, 5);
            bn = gz_lobby_enc_done(&e);
            st = m_in(GZ_LIN_MESSAGE, buf, bn, 0);
            break;
        case 7:
            st = m_in(GZ_LIN_TIMER, NULL, 0, GZ_LOBBY_TIMER_RETRY);
            break;
        case 8:                                                       /* a crash and a restart */
            crash(arg, 0);
            member_boot(1);
            lobby_seq_stats[5]++;
            continue;
        default: {                                                    /* the signing engine's outcome */
            gz_lobby_msg_t g;
            uint8_t sc[32];
            int outcome = 1 + arg % 4, began = M.start_len && M.role == 1 &&
                          gz_lobby_decode(M.start_msg, M.start_len, &g) == GZ_DEC_OK;
            int other = outcome == GZ_LOBBY_ROUND_RETRY && (arg & 64);   /* a Retry naming another check */
            size_t q;
            memset(sc, 0, sizeof sc);
            if (began) memcpy(sc, g.check_id, 32);
            lreset();
            if (other) {
                sc[0] ^= 1;
                st = gz_lobby_member_round_result(&M, outcome, sc, &L);
                for (q = 0; q < L.count; q++) MUST(L.slots[q].kind != GZ_ACTION_SAVE);   /* ignored */
                break;
            }
            st = gz_lobby_member_round_result(&M, outcome, sc, &L);
            if (st == GZ_OK && began && outcome != GZ_LOBBY_ROUND_FAILED && !refused_now()) {
                keep();
                finish(sc, from, GZ_REC_LOBBY_STATE, GZ_REC_LOBBY_STATE);
                continue;
            }
            break;
        }
        }
        MUST(st == GZ_OK);
        keep();
        answered_anew(from);
    }
    lobby_seq_stats[6] += (unsigned long)M.ended;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    setup();
    if (size < 1 || size > 3000) return 0;
    NOW = 1794441600000ull - (uint64_t)(data[0] >> 1) * 60000;   /* up to 127 minutes before T1's deadline */
    rnd = 0x9e3779b97f4a7c15ull ^ size;
    HOST.verifies = 0;
    if (data[0] % 2 == 0) host_script(data, size);
    else member_script(data, size);
    drop_recs();
    return 0;
}
