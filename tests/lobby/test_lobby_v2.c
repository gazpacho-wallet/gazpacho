/* Contract v2 of the lobby engine (lobby.h), what test_lobby.c does not
 * already hold:
 *   - the largest record of every type: each row of gz_lobby_rec_table built
 *     at its largest legal content, through the real engines where they can
 *     produce it (32 seats all answering a check, terms of 4,096 bytes with
 *     every adjustable type, saved messages of 256 bytes) and with gz_lr_*
 *     where they cannot; no larger than its row; taken by the engine's own
 *     restore, also padded to exactly the row's size; refused one byte over;
 *   - the member's signing gate, by outcome: what is saved, what is sent,
 *     what the host then counts;
 *   - gz_lobby_member_accepted: each condition flips the answer, and the
 *     hand-off it fills is the one `begin` got;
 *   - a port that will not sign (GZ_NOTE_NO_KEY): GZ_OK, nothing saved,
 *     nothing changed;
 *   - the node part's helpers: gz_lobby_host_unknown, gz_lobby_host_ended,
 *     gz_lobby_rec_ended, gz_lobby_rec_scope, the round_ok pair. */
#include "../check.h"
#include "lobby_test.h"
#include <stdlib.h>

/* ------------------------------------------------------------ helpers */

typedef struct { gz_action_list_t l; gz_action_t s[256]; uint8_t b[1 << 19]; } acts_t;
static acts_t A;
static unsigned long OVERSIZE;

static void acts_reset(void) { gz_action_list_init(&A.l, A.s, 256, A.b, sizeof A.b); }

static int kind_of(const gz_action_t *a)
{
    gz_lobby_msg_t m;
    if (a->kind != GZ_ACTION_SEND) return -1;
    return lt_send_decode(a, &m) == GZ_DEC_OK ? m.kind : -2;
}

static int sends(int kind)
{
    size_t i;
    int c = 0;
    for (i = 0; i < A.l.count; i++) c += kind_of(&A.s[i]) == kind;
    return c;
}

static int all_sends(void)
{
    size_t i;
    int c = 0;
    for (i = 0; i < A.l.count; i++) c += A.s[i].kind == GZ_ACTION_SEND;
    return c;
}

/* Saved records of `type` in the last list; every saved record is checked
 * against the table of largest records on the way. */
static int saves(uint32_t type)
{
    size_t i, j;
    int c = 0;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_SAVE)
            for (j = 0; j < A.s[i].u.save.n_records; j++) {
                const gz_record_t *r = &A.s[i].u.save.records[j];
                if (!lt_rec_fits(r->type, r->bytes.len)) OVERSIZE++;
                c += r->type == type;
            }
    return c;
}

static int any_save(void)
{
    size_t i;
    for (i = 0; i < A.l.count; i++) if (A.s[i].kind == GZ_ACTION_SAVE) return 1;
    return 0;
}

/* The first saved record of `type` in the last list. */
static const gz_record_t *saved(uint32_t type)
{
    size_t i, j;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_SAVE)
            for (j = 0; j < A.s[i].u.save.n_records; j++)
                if (A.s[i].u.save.records[j].type == type) return &A.s[i].u.save.records[j];
    return NULL;
}

/* The index in the list of the first save of a record of `type`, and of the
 * first send of `kind`; -1 if none. */
static int save_at(uint32_t type)
{
    size_t i, j;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_SAVE)
            for (j = 0; j < A.s[i].u.save.n_records; j++)
                if (A.s[i].u.save.records[j].type == type) return (int)i;
    return -1;
}
static int send_at(int kind)
{
    size_t i;
    for (i = 0; i < A.l.count; i++) if (kind_of(&A.s[i]) == kind) return (int)i;
    return -1;
}

static int note(uint32_t code, int a, int b)
{
    size_t i;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_NOTIFY && A.s[i].u.notify.code == code &&
            (a < 0 || (A.s[i].u.notify.bytes.len > 0 && A.s[i].u.notify.bytes.data[0] == a)) &&
            (b < 0 || (A.s[i].u.notify.bytes.len > 1 && A.s[i].u.notify.bytes.data[1] == b)))
            return 1;
    return 0;
}

static int notes(uint32_t code)
{
    size_t i;
    int c = 0;
    for (i = 0; i < A.l.count; i++) c += A.s[i].kind == GZ_ACTION_NOTIFY && A.s[i].u.notify.code == code;
    return c;
}

static int timers(uint64_t id)
{
    size_t i;
    int c = 0;
    for (i = 0; i < A.l.count; i++) c += A.s[i].kind == GZ_ACTION_SET_TIMER && A.s[i].u.set_timer.timer_id == id;
    return c;
}

static int last_sent(int kind, gz_lobby_msg_t *m)
{
    size_t i;
    int found = 0;
    for (i = 0; i < A.l.count; i++)
        if (kind_of(&A.s[i]) == kind) { lt_send_decode(&A.s[i], m); found = 1; }
    return found;
}

#define NM 33                        /* members 1 to 32 */
static lt_signer_t HOST, MEM[NM];
static uint8_t T1[512], T2[128], SCOPE[32], CD2[32];
static size_t T1N, T2N;
static gz_terms_outer_t T1O;
static uint64_t CLOCK;
static uint8_t RAND_NEXT = 0x31;
static uint64_t c_now(void *ctx) { (void)ctx; return CLOCK; }
static void c_rand(void *ctx, gz_random_purpose_t p, uint8_t *o, size_t n) { (void)ctx; (void)p; memset(o, RAND_NEXT++, n); }

#define W_T0 1794441000000ull        /* 10 minutes before T1's deadline */
#define DEADLINE_MS 1794441600000ull

static gz_ports_t ports(void)
{
    gz_ports_t p;
    p.random.fill = c_rand; p.random.ctx = NULL;
    p.clock.now_ms = c_now; p.clock.ctx = NULL;
    return p;
}

/* ---- kept records: a journal for a restore ---- */

typedef struct { gz_record_t r[512]; size_t n; } journal_t;

static void keep(journal_t *j)
{
    size_t i, k;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_SAVE)
            for (k = 0; k < A.s[i].u.save.n_records && j->n < 512; k++) {
                gz_record_t r = A.s[i].u.save.records[k];
                uint8_t *b = malloc(r.bytes.len + 1);
                if (!lt_rec_fits(r.type, r.bytes.len)) OVERSIZE++;
                memcpy(b, r.bytes.data, r.bytes.len);
                r.bytes.data = b;
                j->r[j->n++] = r;
            }
}

static void journal_free(journal_t *j)
{
    size_t i;
    for (i = 0; i < j->n; i++) free((void *)j->r[i].bytes.data);
    j->n = 0;
}

/* The largest record of `type` in the journal; -1 if none. */
static int largest(const journal_t *j, uint32_t type)
{
    size_t i;
    int at = -1;
    for (i = 0; i < j->n; i++)
        if (j->r[i].type == type && (at < 0 || j->r[i].bytes.len > j->r[at].bytes.len)) at = (int)i;
    return at;
}

/* ---- envelopes ---- */

static uint8_t PADB[400];

static size_t join_env(uint8_t *buf, size_t cap, const uint8_t *scope, int who)
{
    uint8_t b[32], sf[64], sc[64];
    gz_lobby_enc_t e;
    gz_lobby_binding(scope, MEM[who].key[3].pub, MEM[who].key[2].pub, b);
    lt_sign(&MEM[who], 3, b, sf);
    lt_sign(&MEM[who], 2, b, sc);
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_JOIN, scope);
    gz_lobby_enc_record(&e, 2, MEM[who].key[3].pub, 33);
    gz_lobby_enc_record(&e, 4, sf, 64);
    gz_lobby_enc_record(&e, 6, sc, 64);
    return gz_lobby_enc_done(&e);
}

/* A member's ready; `pad` > 0 adds an unknown odd record of that many bytes. */
static size_t ready_env(uint8_t *buf, size_t cap, const uint8_t *scope, int who, uint32_t version, const uint8_t *digest,
                        const uint8_t *check, uint16_t min, size_t pad)
{
    gz_lobby_enc_t e;
    gz_lobby_crypto_t cr = lt_crypto(&MEM[who]);
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_READY, scope);
    gz_lobby_enc_record(&e, 2, scope, 32);
    gz_lobby_enc_u32(&e, 4, version);
    gz_lobby_enc_record(&e, 6, digest, 32);
    if (check) gz_lobby_enc_record(&e, 8, check, 32);
    if (pad) gz_lobby_enc_record(&e, 9, PADB, pad);
    if (min) gz_lobby_enc_u16(&e, 11, min);
    return gz_lobby_enc_sign(&e, &cr, GZ_LOBBY_KEY_CONTRIBUTION);
}

/* unready or leave; reason < 0: none. */
static size_t reason_env(uint8_t *buf, size_t cap, const uint8_t *scope, uint16_t kind, int reason)
{
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, buf, cap, kind, scope);
    if (reason >= 0) gz_lobby_enc_u16(&e, 1, (uint16_t)reason);
    return gz_lobby_enc_done(&e);
}

/* A host's signed message: ready_check (check, version, digest), start (check,
 * role, signers) or cancel (reason); `pad` > 0 adds an unknown odd record. */
static size_t host_env(uint8_t *buf, size_t cap, const uint8_t *scope, uint16_t kind, const uint8_t *check,
                       uint32_t version, const uint8_t *digest, uint8_t role, uint16_t signers, uint16_t reason,
                       size_t pad, lt_signer_t *signer)
{
    gz_lobby_enc_t e;
    gz_lobby_crypto_t cr = lt_crypto(signer);
    gz_lobby_enc_start(&e, buf, cap, kind, scope);
    if (kind == GZ_KIND_READY_CHECK) {
        gz_lobby_enc_record(&e, 2, check, 32);
        gz_lobby_enc_u32(&e, 4, version);
        gz_lobby_enc_record(&e, 6, digest, 32);
        gz_lobby_enc_u32(&e, 8, 30000);
        if (pad) gz_lobby_enc_record(&e, 9, PADB, pad);
    } else if (kind == GZ_KIND_START) {
        gz_lobby_enc_record(&e, 2, check, 32);
        gz_lobby_enc_u8(&e, 4, role);
        gz_lobby_enc_u16(&e, 6, signers);
        if (pad) gz_lobby_enc_record(&e, 7, PADB, pad);
    } else {
        gz_lobby_enc_u16(&e, 2, reason);
        if (pad) gz_lobby_enc_record(&e, 3, PADB, pad);
    }
    return gz_lobby_enc_sign(&e, &cr, GZ_LOBBY_KEY_HOST);
}

/* The same, padded so that the envelope is exactly `want` bytes; 0 if it cannot be. */
static size_t host_env_sized(uint8_t *buf, size_t cap, const uint8_t *scope, uint16_t kind, const uint8_t *check,
                             uint32_t version, const uint8_t *digest, uint8_t role, uint16_t signers, uint16_t reason,
                             size_t want)
{
    size_t pad, n;
    for (pad = 1; pad < 250; pad++) {
        n = host_env(buf, cap, scope, kind, check, version, digest, role, signers, reason, pad, &HOST);
        if (n == want) return n;
    }
    return 0;
}

static size_t ready_env_sized(uint8_t *buf, size_t cap, const uint8_t *scope, int who, uint32_t version,
                              const uint8_t *digest, const uint8_t *check, size_t want)
{
    size_t pad, n;
    for (pad = 1; pad < 250; pad++) {
        n = ready_env(buf, cap, scope, who, version, digest, check, 0, pad);
        if (n == want) return n;
    }
    return 0;
}

static size_t offer_env(uint8_t *buf, size_t cap, const uint8_t *scope, const uint8_t *o, size_t on, const uint8_t *c,
                        size_t cn, lt_signer_t *signer)
{
    uint8_t od[32], cd[32], os[64], cs[64];
    gz_lobby_enc_t e;
    gz_terms_outer_digest(o, on, od);
    gz_terms_current_digest(c, cn, cd);
    lt_sign(signer, 1, od, os);
    lt_sign(signer, 1, cd, cs);
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_TERMS_OFFER, scope);
    gz_lobby_enc_record(&e, 2, o, on);
    gz_lobby_enc_record(&e, 4, os, 64);
    gz_lobby_enc_record(&e, 6, c, cn);
    gz_lobby_enc_record(&e, 8, cs, 64);
    return gz_lobby_enc_done(&e);
}

static size_t status_env(uint8_t *buf, size_t cap, const uint8_t *scope, uint8_t lobby, uint8_t seat, uint32_t version)
{
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_LOBBY_STATUS, scope);
    gz_lobby_enc_u8(&e, 2, lobby); gz_lobby_enc_u8(&e, 4, seat); gz_lobby_enc_u32(&e, 6, version);
    gz_lobby_enc_u16(&e, 8, 1); gz_lobby_enc_u16(&e, 10, 1);
    return gz_lobby_enc_done(&e);
}

/* ---- the host ---- */

static gz_link_t hlink(int who) { return lt_link(HOST.key[1].pub, MEM[who].key[2].pub); }

static void host_new(gz_lobby_host_t *h, lt_signer_t *keys, const gz_lobby_signing_t *sg, uint16_t standbys)
{
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(keys);
    gz_lobby_host_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, HOST.key[3].pub, 33);
    cfg.standbys = standbys;
    CHECK(gz_lobby_host_init(h, &p, &cr, sg, &cfg) == GZ_OK);
}

static gz_status_t hin(gz_lobby_host_t *h, int kind, int who, const uint8_t *b, size_t n)
{
    gz_lobby_input_t in;
    gz_link_t l = hlink(who);
    acts_reset();
    if (kind != GZ_LIN_MESSAGE) lt_in(&in, kind, &l);
    else if (!lt_in_env(&in, &l, b, n)) return GZ_ERR_BUG;
    return gz_lobby_host_handle(h, &in, &A.l);
}

static gz_status_t htimer(gz_lobby_host_t *h, uint64_t id)
{
    gz_lobby_input_t in;
    lt_in(&in, GZ_LIN_TIMER, NULL);
    in.timer_id = id;
    acts_reset();
    return gz_lobby_host_handle(h, &in, &A.l);
}

/* The seat state in the last status sent to member `who`; -1 if none. */
static int seat_shown(int who)
{
    gz_lobby_msg_t g;
    size_t i;
    int r = -1;
    for (i = 0; i < A.l.count; i++)
        if (kind_of(&A.s[i]) == GZ_KIND_LOBBY_STATUS && memcmp(A.s[i].u.send.link.remote.key, MEM[who].key[2].pub, 33) == 0) {
            lt_send_decode(&A.s[i], &g);
            r = g.seat_state;
        }
    return r;
}

static gz_lobby_seat_t *seat(gz_lobby_host_t *h, int who)
{
    uint16_t i;
    for (i = 0; i < h->n_seats; i++) if (memcmp(h->seats[i].ckey, MEM[who].key[2].pub, 33) == 0) return &h->seats[i];
    return NULL;
}

/* Member `who` connects, joins and readies (version and digest as the host has them). */
static void seat_up(gz_lobby_host_t *h, int who)
{
    uint8_t buf[600];
    size_t n;
    hin(h, GZ_LIN_CONNECTED, who, NULL, 0);
    n = join_env(buf, sizeof buf, h->scope, who);
    hin(h, GZ_LIN_MESSAGE, who, buf, n);
    n = ready_env(buf, sizeof buf, h->scope, who, h->values.version, h->current_digest, NULL, 0, 0);
    hin(h, GZ_LIN_MESSAGE, who, buf, n);
}

/* ---- the member ---- */

static int GATE = 1, GATE_ASKED;
static int gate_fn(void *ctx, const uint8_t scope[32])
{
    (void)ctx; (void)scope;
    GATE_ASKED++;
    return GATE;
}

static gz_lobby_handoff_t BEGUN;
static int N_BEGUN, N_RESUMED, N_CANCELLED;
static gz_status_t cap_begin(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out)
{
    (void)ctx; (void)out;
    BEGUN = *h;
    N_BEGUN++;
    N_RESUMED += h->resume != 0;
    return GZ_OK;
}
static gz_status_t cap_cancel(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out)
{
    (void)ctx; (void)scope; (void)reason; (void)out;
    N_CANCELLED++;
    return GZ_OK;
}
static gz_lobby_signing_t cap_signing(void)
{
    gz_lobby_signing_t s;
    s.begin = cap_begin; s.cancel = cap_cancel; s.member_left = NULL; s.ctx = NULL;
    return s;
}

static gz_link_t mlink(int who) { return lt_link(MEM[who].key[2].pub, HOST.key[1].pub); }

/* Member `who` of the lobby `scope`, as init leaves it; with the gate if `gated`. */
static void member_new(gz_lobby_member_t *m, int who, lt_signer_t *keys, const uint8_t *scope, int gated,
                       const gz_lobby_conditions_t *cond)
{
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(keys);
    gz_lobby_signing_t sg = cap_signing();
    gz_lobby_gate_t gate;
    gate.may_answer = gate_fn; gate.ctx = NULL;
    CHECK(lt_member_init(m, &p, &cr, &sg, gated ? &gate : NULL, cond, scope, HOST.key[1].pub, MEM[who].key[2].pub,
                         MEM[who].key[3].pub, 1) == GZ_OK);
}

static gz_status_t m_in(gz_lobby_member_t *m, int who, int kind)
{
    gz_lobby_input_t in;
    gz_link_t l = mlink(who);
    lt_in(&in, kind, &l);
    acts_reset();
    return gz_lobby_member_handle(m, &in, &A.l);
}

static gz_status_t feed(gz_lobby_member_t *m, int who, const uint8_t *b, size_t n)
{
    gz_lobby_input_t in;
    gz_link_t l = mlink(who);
    acts_reset();
    if (!lt_in_env(&in, &l, b, n)) return GZ_ERR_BUG;
    return gz_lobby_member_handle(m, &in, &A.l);
}

/* What the member's last list sends, delivered to the host as member `who`
 * (in order). The last of the host's lists is left in A. */
static void to_host(gz_lobby_host_t *h, int who)
{
    static uint8_t env[8][GZ_LOBBY_MAX_SAVED_MSG + 64];
    size_t n[8], k = 0, i;
    for (i = 0; i < A.l.count && k < 8; i++)
        if (A.s[i].kind == GZ_ACTION_SEND && (n[k] = lt_send_env(&A.s[i], env[k], sizeof env[k])) != 0) k++;
    for (i = 0; i < k; i++) CHECK(hin(h, GZ_LIN_MESSAGE, who, env[i], n[i]) == GZ_OK);
}

/* ---------------------------------------- the node part's helpers */

static void test_helpers(void)
{
    static gz_lobby_host_t h;
    gz_link_t l = hlink(5);
    gz_lobby_msg_t g;
    uint8_t other[32], cancel[300], bad[300], rb[GZ_LOBBY_REC_MAX_ENDED + 8], sc[32], st;
    uint16_t reason;
    const uint8_t *ec;
    size_t cn, ecn, rn;
    gz_record_t r;
    memset(other, 0x77, 32);

    /* unknown: one lobby_status, lobby state 0 and nothing else, on the link, under the scope asked */
    acts_reset();
    CHECK(gz_lobby_host_unknown(&l, other, &A.l) == GZ_OK && A.l.count == 1 && last_sent(GZ_KIND_LOBBY_STATUS, &g));
    CHECK(memcmp(g.scope, other, 32) == 0 && g.lobby_state == 0 && g.seat_state == 0 && g.version == 0 && g.joined == 0 &&
          g.ready == 0 && !g.has_reason && memcmp(&A.s[0].u.send.link, &l, sizeof l) == 0);
    CHECK(gz_lobby_host_unknown(NULL, other, &A.l) == GZ_ERR_ARGUMENT && gz_lobby_host_unknown(&l, NULL, &A.l) == GZ_ERR_ARGUMENT &&
          gz_lobby_host_unknown(&l, other, NULL) == GZ_ERR_ARGUMENT);

    /* ended: the final state and its reason, then the saved cancel if it is this lobby's */
    cn = host_env(cancel, sizeof cancel, other, GZ_KIND_CANCEL, NULL, 0, NULL, 0, 0, 3, 0, &HOST);
    acts_reset();
    CHECK(gz_lobby_host_ended(&l, other, GZ_LOBBY_FAILED, 3, cancel, cn, &A.l) == GZ_OK && A.l.count == 2);
    CHECK(kind_of(&A.s[0]) == GZ_KIND_LOBBY_STATUS && kind_of(&A.s[1]) == GZ_KIND_CANCEL);
    CHECK(last_sent(GZ_KIND_LOBBY_STATUS, &g) && g.lobby_state == GZ_LOBBY_FAILED && g.has_reason && g.reason == 3 &&
          g.seat_state == GZ_SEAT_NONE && memcmp(g.scope, other, 32) == 0);
    {
        static uint8_t env[400];
        CHECK(lt_send_env(&A.s[1], env, sizeof env) == cn && memcmp(env, cancel, cn) == 0);   /* byte for byte */
        CHECK(memcmp(&A.s[1].u.send.link, &l, sizeof l) == 0);
    }
    acts_reset();                                       /* no cancel kept: the status alone; reason 0: none shown */
    CHECK(gz_lobby_host_ended(&l, other, GZ_LOBBY_CANCELLED, 0, NULL, 0, &A.l) == GZ_OK && A.l.count == 1 &&
          last_sent(GZ_KIND_LOBBY_STATUS, &g) && g.lobby_state == GZ_LOBBY_CANCELLED && !g.has_reason);
    acts_reset();
    CHECK(gz_lobby_host_ended(&l, other, GZ_LOBBY_CANCELLED, 2, cancel, 0, &A.l) == GZ_OK && A.l.count == 1);
    /* bytes from storage that are no cancel of this lobby are not sent on */
    acts_reset();                                       /* another lobby's */
    CHECK(gz_lobby_host_ended(&l, SCOPE, GZ_LOBBY_CANCELLED, 2, cancel, cn, &A.l) == GZ_OK && A.l.count == 1);
    rn = host_env(bad, sizeof bad, other, GZ_KIND_START, other, 0, NULL, 1, 4, 0, 0, &HOST);
    acts_reset();                                       /* another kind */
    CHECK(gz_lobby_host_ended(&l, other, GZ_LOBBY_CANCELLED, 2, bad, rn, &A.l) == GZ_OK && A.l.count == 1);
    memcpy(bad, cancel, cn);
    bad[0] ^= 1;
    acts_reset();                                       /* no envelope */
    CHECK(gz_lobby_host_ended(&l, other, GZ_LOBBY_CANCELLED, 2, bad, cn, &A.l) == GZ_OK && A.l.count == 1);
    acts_reset();                                       /* cut short */
    CHECK(gz_lobby_host_ended(&l, other, GZ_LOBBY_CANCELLED, 2, cancel, cn - 1, &A.l) == GZ_OK && A.l.count == 1);
    rn = host_env_sized(bad, sizeof bad, other, GZ_KIND_CANCEL, NULL, 0, NULL, 0, 0, 2, GZ_LOBBY_MAX_SAVED_MSG + 1);
    acts_reset();                                       /* larger than a saved message */
    CHECK(rn == 257 && gz_lobby_host_ended(&l, other, GZ_LOBBY_CANCELLED, 2, bad, rn, &A.l) == GZ_OK && A.l.count == 1);
    rn = host_env_sized(bad, sizeof bad, other, GZ_KIND_CANCEL, NULL, 0, NULL, 0, 0, 2, GZ_LOBBY_MAX_SAVED_MSG);
    acts_reset();                                       /* the largest: sent */
    CHECK(rn == 256 && gz_lobby_host_ended(&l, other, GZ_LOBBY_CANCELLED, 2, bad, rn, &A.l) == GZ_OK && A.l.count == 2);
    CHECK(gz_lobby_host_ended(NULL, other, 6, 2, NULL, 0, &A.l) == GZ_ERR_ARGUMENT &&
          gz_lobby_host_ended(&l, NULL, 6, 2, NULL, 0, &A.l) == GZ_ERR_ARGUMENT &&
          gz_lobby_host_ended(&l, other, 6, 2, NULL, 0, NULL) == GZ_ERR_ARGUMENT);

    /* rec_ended and rec_scope on what a host saves when it cancels */
    CLOCK = W_T0 - 3600000;
    host_new(&h, &HOST, NULL, 0);
    acts_reset();
    CHECK(gz_lobby_host_open(&h, T1, T1N, T2, T2N, &A.l) == GZ_OK && saved(GZ_REC_LOBBY_OPENED) != NULL);
    CHECK(!gz_lobby_host_round_ok(&h));
    if (saved(GZ_REC_LOBBY_OPENED)) {
        memset(sc, 0, 32);
        CHECK(gz_lobby_rec_scope(saved(GZ_REC_LOBBY_OPENED), sc) && memcmp(sc, SCOPE, 32) == 0);
        CHECK(!gz_lobby_rec_ended(saved(GZ_REC_LOBBY_OPENED), sc, &st, &reason, &ec, &ecn));   /* not a lobby_ended */
    }
    acts_reset();
    CHECK(gz_lobby_host_cancel(&h, 2, &A.l) == GZ_OK && saved(GZ_REC_LOBBY_ENDED) != NULL);
    if (saved(GZ_REC_LOBBY_ENDED)) {
        static uint8_t eb[GZ_LOBBY_REC_MAX_ENDED];
        gz_record_t er = *saved(GZ_REC_LOBBY_ENDED);
        const gz_record_t *e = &er;
        memcpy(eb, er.bytes.data, er.bytes.len);          /* out of the action list, which is reused below */
        er.bytes.data = eb;
        memset(sc, 0, 32);
        CHECK(gz_lobby_rec_ended(e, sc, &st, &reason, &ec, &ecn) && memcmp(sc, SCOPE, 32) == 0 && st == GZ_LOBBY_CANCELLED &&
              reason == 2 && ecn == h.cancel_len && ecn > 0 && memcmp(ec, h.cancel_msg, ecn) == 0);
        CHECK(gz_lobby_rec_scope(e, sc) && memcmp(sc, SCOPE, 32) == 0);
        /* the saved cancel is the one the node part resends for a late hello */
        acts_reset();
        CHECK(gz_lobby_host_ended(&l, sc, st, reason, ec, ecn, &A.l) == GZ_OK && sends(GZ_KIND_CANCEL) == 1);
        /* every pointer, and each way the record can be wrong */
        CHECK(!gz_lobby_rec_ended(NULL, sc, &st, &reason, &ec, &ecn) && !gz_lobby_rec_ended(e, NULL, &st, &reason, &ec, &ecn) &&
              !gz_lobby_rec_ended(e, sc, NULL, &reason, &ec, &ecn) && !gz_lobby_rec_ended(e, sc, &st, NULL, &ec, &ecn) &&
              !gz_lobby_rec_ended(e, sc, &st, &reason, NULL, &ecn) && !gz_lobby_rec_ended(e, sc, &st, &reason, &ec, NULL));
        r = *e;
        r.bytes.len -= 1;
        CHECK(!gz_lobby_rec_ended(&r, sc, &st, &reason, &ec, &ecn) && !gz_lobby_rec_scope(&r, sc));
        r = *e;
        r.type = GZ_REC_SEAT;
        CHECK(!gz_lobby_rec_ended(&r, sc, &st, &reason, &ec, &ecn));
        r.type = 0x0001001au;                           /* not a lobby record */
        CHECK(!gz_lobby_rec_scope(&r, sc));
        r.type = GZ_REC_LOBBY_ENDED;
        r.bytes.data = rb;
        r.bytes.len = lt_rec_with(e->bytes.data, e->bytes.len, 6, NULL, 0, rb, sizeof rb);   /* no reason */
        CHECK(r.bytes.len > 0 && !gz_lobby_rec_ended(&r, sc, &st, &reason, &ec, &ecn) && gz_lobby_rec_scope(&r, sc));
        r.bytes.len = lt_rec_with(e->bytes.data, e->bytes.len, 12, sc, 1, rb, sizeof rb);    /* an even field it has not */
        CHECK(r.bytes.len > 0 && !gz_lobby_rec_ended(&r, sc, &st, &reason, &ec, &ecn) && !gz_lobby_rec_scope(&r, sc));
        r.bytes.len = lt_rec_ended(rb, sizeof rb, SCOPE, 0, 2, NULL, 0);                     /* a member's own leave */
        CHECK(gz_lobby_rec_ended(&r, sc, &st, &reason, &ec, &ecn) && st == 0 && reason == 2 && ecn == 0 && ec == NULL);
        CHECK(!gz_lobby_rec_scope(NULL, sc) && !gz_lobby_rec_scope(&r, NULL));
    }
    /* the table: twelve rows, each type once, the largest of all is GZ_LOBBY_REC_MAX */
    {
        size_t nt = 0, i, k;
        const gz_lobby_rec_max_t *t = gz_lobby_rec_table(&nt);
        uint32_t top = 0;
        CHECK(t != NULL && nt == 12 && gz_lobby_rec_table(NULL) == t);
        for (i = 0; i < nt; i++) {
            CHECK(t[i].max >= GZ_LOBBY_REC_SCOPE && t[i].name && t[i].name[0] && gz_lobby_rec_max(t[i].type) == t[i].max);
            for (k = 0; k < i; k++) CHECK(t[k].type != t[i].type);
            if (t[i].max > top) top = t[i].max;
        }
        CHECK(top == GZ_LOBBY_REC_MAX && gz_lobby_rec_max(0) == 0 && gz_lobby_rec_max(0x0001001au) == 0 &&
              gz_lobby_rec_max(0x00010000u) == 0);
        {   /* and each row is lobby.h's constant for its type: what every buffer is sized from */
            static const struct { uint32_t type, max; } want[] = {
                {GZ_REC_LOBBY_OPENED, GZ_LOBBY_REC_MAX_OPENED}, {GZ_REC_TERMS_VERSION, GZ_LOBBY_REC_MAX_VERSION},
                {GZ_REC_SEAT, GZ_LOBBY_REC_MAX_SEAT}, {GZ_REC_FREEZE, GZ_LOBBY_REC_MAX_FREEZE},
                {GZ_REC_LOBBY_ENDED, GZ_LOBBY_REC_MAX_ENDED}, {GZ_REC_TERMS_RECEIVED, GZ_LOBBY_REC_MAX_TERMS},
                {GZ_REC_JOINED, GZ_LOBBY_REC_MAX_JOINED}, {GZ_REC_READY_SENT, GZ_LOBBY_REC_MAX_READY_SENT},
                {GZ_REC_HOST_FAULT, GZ_LOBBY_REC_MAX_HOST_FAULT}, {GZ_REC_START_SENT, GZ_LOBBY_REC_MAX_START_SENT},
                {GZ_REC_START_RECEIVED, GZ_LOBBY_REC_MAX_START_RECEIVED}, {GZ_REC_LOBBY_STATE, GZ_LOBBY_REC_MAX_STATE},
            };
            for (i = 0; i < sizeof want / sizeof want[0]; i++) CHECK(gz_lobby_rec_max(want[i].type) == want[i].max);
            CHECK(sizeof want / sizeof want[0] == nt);
            CHECK(GZ_LOBBY_REC_MAX_OPENED == 5300 && GZ_LOBBY_REC_MAX_VERSION == 1132 && GZ_LOBBY_REC_MAX_SEAT == 537 &&
                  GZ_LOBBY_REC_MAX_FREEZE == 376 && GZ_LOBBY_REC_MAX_ENDED == 312 && GZ_LOBBY_REC_MAX_JOINED == 296 &&
                  GZ_LOBBY_REC_MAX_READY_SENT == 296 && GZ_LOBBY_REC_MAX_HOST_FAULT == 2225 &&
                  GZ_LOBBY_REC_MAX_START_SENT == 9400 && GZ_LOBBY_REC_MAX_START_RECEIVED == 296 && GZ_LOBBY_REC_MAX_STATE == 77);
        }
    }
}

/* ------------------------------------------------- a port that will not sign */

static void test_no_key(void)
{
    static gz_lobby_host_t h;
    static gz_lobby_member_t m;
    static uint8_t ob[8000];
    lt_signer_t hk = HOST, mk = MEM[1];
    gz_lobby_conditions_t cond = lt_cond_fits();
    uint8_t buf[600], chk[32];
    size_t n, on;
    int i;
    gz_lobby_msg_t g;
    uint64_t v[3] = {1500, 1000, 1000};

    /* HOST. set_values: the note, nothing saved, nothing sent, the values as they were */
    CLOCK = W_T0 - 3600000;
    host_new(&h, &hk, NULL, 0);
    acts_reset();
    CHECK(gz_lobby_host_open(&h, T1, T1N, T2, T2N, &A.l) == GZ_OK);
    for (i = 1; i <= 7; i++) { seat_up(&h, i); CLOCK += 1000; }
    hk.fail_sign = 1;
    acts_reset();
    CHECK(gz_lobby_host_set_values(&h, v, 3, &A.l) == GZ_OK && note(GZ_NOTE_NO_KEY, GZ_LOBBY_KEY_HOST, -1) && A.l.count == 1);
    CHECK(h.values.version == 1 && memcmp(h.current_digest, CD2, 32) == 0 && h.current_len == T2N);
    /* values a person composed wrongly: an error of the two validating calls, nothing appended or changed */
    {
        uint64_t bad[3] = {2001, 1000, 1000};
        acts_reset();
        CHECK(gz_lobby_host_set_values(&h, bad, 3, &A.l) == GZ_ERR_ARGUMENT && A.l.count == 0 && h.values.version == 1);
        CHECK(gz_lobby_host_set_values(&h, v, 2, &A.l) == GZ_ERR_ARGUMENT && A.l.count == 0 && h.values.version == 1);
    }
    /* the eighth seat reaches the target: the check cannot be signed. Nothing
     * is frozen, saved for it, or sent as a check; the lobby stays Open */
    hin(&h, GZ_LIN_CONNECTED, 8, NULL, 0);
    n = join_env(buf, sizeof buf, SCOPE, 8);
    CHECK(hin(&h, GZ_LIN_MESSAGE, 8, buf, n) == GZ_OK);
    n = ready_env(buf, sizeof buf, SCOPE, 8, 1, CD2, NULL, 0, 0);
    CHECK(hin(&h, GZ_LIN_MESSAGE, 8, buf, n) == GZ_OK && note(GZ_NOTE_NO_KEY, GZ_LOBBY_KEY_HOST, -1));
    CHECK(h.state == GZ_LOBBY_OPEN && !h.frozen && !h.check_open && saves(GZ_REC_FREEZE) == 0 &&
          sends(GZ_KIND_READY_CHECK) == 0 && timers(GZ_LOBBY_TIMER_WINDOW) == 0 && saves(GZ_REC_SEAT) == 1);
    /* the key is back: the rule is applied again at the next seat event */
    hk.fail_sign = 0;
    hin(&h, GZ_LIN_DISCONNECTED, 8, NULL, 0);
    CHECK(hin(&h, GZ_LIN_CONNECTED, 8, NULL, 0) == GZ_OK && sends(GZ_KIND_READY_CHECK) == 8 && saves(GZ_REC_FREEZE) == 1 &&
          h.state == GZ_LOBBY_READY_CHECK && h.frozen);
    CHECK(last_sent(GZ_KIND_READY_CHECK, &g));
    memcpy(chk, g.check_id, 32);
    for (i = 1; i <= 8; i++) {
        n = ready_env(buf, sizeof buf, SCOPE, i, 1, CD2, chk, 0, 0);
        hin(&h, GZ_LIN_MESSAGE, i, buf, n);
    }
    /* the window closes and the starts cannot be signed: a check that started
     * nobody. No start_sent, no start, not Signing, no budget begun */
    hk.fail_sign = 1;
    CHECK(htimer(&h, GZ_LOBBY_TIMER_WINDOW) == GZ_OK && note(GZ_NOTE_NO_KEY, GZ_LOBBY_KEY_HOST, -1));
    CHECK(h.state == GZ_LOBBY_OPEN && h.check_failed && !any_save() && sends(GZ_KIND_START) == 0 && h.budget_ms == 0 &&
          !gz_lobby_host_round_ok(&h));
    for (i = 0; i < h.n_seats; i++) CHECK(h.seats[i].start_len == 0 && !h.seats[i].chosen);
    /* cancel: the lobby ends all the same, without a signed cancel: saved with
     * no cancel, every seat told the end and its reason by lobby_status */
    CLOCK += 2000;
    acts_reset();
    CHECK(gz_lobby_host_cancel(&h, 2, &A.l) == GZ_OK && note(GZ_NOTE_NO_KEY, GZ_LOBBY_KEY_HOST, -1) && h.state == GZ_LOBBY_CANCELLED);
    CHECK(saves(GZ_REC_LOBBY_ENDED) == 1 && sends(GZ_KIND_CANCEL) == 0 && sends(GZ_KIND_LOBBY_STATUS) == 8 && h.cancel_len == 0);
    CHECK(save_at(GZ_REC_LOBBY_ENDED) == 0);
    if (saved(GZ_REC_LOBBY_ENDED)) {
        uint8_t want[64];
        size_t wn = lt_rec_ended(want, sizeof want, SCOPE, GZ_LOBBY_CANCELLED, 2, NULL, 0);
        CHECK(saved(GZ_REC_LOBBY_ENDED)->bytes.len == wn && memcmp(saved(GZ_REC_LOBBY_ENDED)->bytes.data, want, wn) == 0);
    }
    CHECK(last_sent(GZ_KIND_LOBBY_STATUS, &g) && g.lobby_state == GZ_LOBBY_CANCELLED && g.has_reason && g.reason == 2);
    /* a deadline does not wait for a key either: cancelled, reason 1 */
    CLOCK = W_T0 - 3600000;
    hk.fail_sign = 0;
    host_new(&h, &hk, NULL, 0);
    acts_reset();
    CHECK(gz_lobby_host_open(&h, T1, T1N, T2, T2N, &A.l) == GZ_OK);
    seat_up(&h, 1);
    hk.fail_sign = 1;
    CLOCK = DEADLINE_MS;
    CHECK(htimer(&h, GZ_LOBBY_TIMER_DEADLINE) == GZ_OK && h.state == GZ_LOBBY_CANCELLED && h.end_reason == 1 &&
          note(GZ_NOTE_NO_KEY, GZ_LOBBY_KEY_HOST, -1) && saves(GZ_REC_LOBBY_ENDED) == 1 && sends(GZ_KIND_CANCEL) == 0);

    /* MEMBER. The factory key missing: no join, nothing saved, nothing sent */
    CLOCK = W_T0 - 3600000;
    member_new(&m, 1, &mk, SCOPE, 0, &cond);
    m_in(&m, 1, GZ_LIN_CONNECTED);
    on = offer_env(ob, sizeof ob, SCOPE, T1, T1N, T2, T2N, &HOST);
    mk.fail_sign = 1;
    CHECK(feed(&m, 1, ob, on) == GZ_OK && note(GZ_NOTE_NO_KEY, GZ_LOBBY_KEY_FACTORY, -1) && A.l.count == 1 && !m.joined &&
          m.have_terms && !m.ready && m.join_len == 0);
    acts_reset();                                       /* and again at the person's word: still nothing */
    CHECK(gz_lobby_member_set_conditions(&m, &cond, &A.l) == GZ_OK && notes(GZ_NOTE_NO_KEY) == 1 && A.l.count == 1 && !m.joined);
    mk.fail_sign = 0;                                   /* the key is back: joined and ready */
    acts_reset();
    CHECK(gz_lobby_member_set_conditions(&m, &cond, &A.l) == GZ_OK && sends(GZ_KIND_JOIN) == 1 && sends(GZ_KIND_READY) == 1 &&
          saves(GZ_REC_JOINED) == 1 && saves(GZ_REC_READY_SENT) == 1 && m.joined && m.ready);
    /* a ready that cannot be signed: the note; not ready for the new values, nothing saved for them */
    {
        uint8_t t3[128], ob3[8000];
        size_t t3n = lt_unhex(LT_T3, t3, sizeof t3), on3;
        on3 = offer_env(ob3, sizeof ob3, SCOPE, T1, T1N, t3, t3n, &HOST);
        mk.fail_sign = 1;
        CHECK(feed(&m, 1, ob3, on3) == GZ_OK && note(GZ_NOTE_NO_KEY, GZ_LOBBY_KEY_CONTRIBUTION, -1) && A.l.count == 1);
        CHECK(m.values.version == 2 && m.ready_version == 1 && m.saved_version == 1 && !any_save());
        /* a check at those values: no answer can be signed. Not frozen, no freeze saved */
        {
            uint8_t cd3[32];
            gz_terms_current_digest(t3, t3n, cd3);
            memset(chk, 0x51, 32);
            n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_READY_CHECK, chk, 2, cd3, 0, 0, 0, 0, &HOST);
            CHECK(feed(&m, 1, buf, n) == GZ_OK && note(GZ_NOTE_NO_KEY, GZ_LOBBY_KEY_CONTRIBUTION, -1) && A.l.count == 1 &&
                  !m.frozen && !m.has_answered && !gz_lobby_member_round_ok(&m));
            mk.fail_sign = 0;                           /* the host asks again: answered, the freeze saved first */
            CHECK(feed(&m, 1, buf, n) == GZ_OK && sends(GZ_KIND_READY) == 1 && saves(GZ_REC_FREEZE) == 1 &&
                  saves(GZ_REC_TERMS_RECEIVED) == 1 && saves(GZ_REC_READY_SENT) == 1 && m.frozen && m.has_answered &&
                  gz_lobby_member_round_ok(&m) && save_at(GZ_REC_FREEZE) < send_at(GZ_KIND_READY));
        }
    }
}

/* ------------------------------------------------- the largest records */

static uint8_t BO[GZ_TERMS_OUTER_MAX], BC[GZ_TERMS_CURRENT_MAX], BC2[GZ_TERMS_CURRENT_MAX], BSCOPE[32], BCD[32];
static size_t BON, BCN, BC2N;
static gz_terms_outer_t BOO;

/* The largest terms the terms library takes: T1 with target 32, every
 * adjustable type (the three known and the 32 odd ones of 64 to 127), and an
 * unknown odd record of display text filling the outer record to exactly
 * 4,096 bytes; the current record with a value for each adjustable type. */
static void big_terms(void)
{
    static gz_terms_outer_t o;
    static uint8_t enc[GZ_TERMS_OUTER_MAX];
    gz_terms_current_t c, c2;
    gz_lw_tlv_t t;
    gz_terms_range_t adj[GZ_TERMS_MAX_ADJ];
    size_t en, at = 0, pad, start;
    unsigned ty, na = 0, k;
    o = T1O;
    o.target = 32;
    o.shapes[1].max_members = 40;
    for (ty = 64; ty <= 127 && na < GZ_TERMS_MAX_ADJ; ty++) {
        if (ty % 2 == 0) {
            for (k = 0; k < T1O.n_adj; k++) if (T1O.adj[k].type == ty) adj[na++] = T1O.adj[k];
        } else {
            adj[na].type = (uint8_t)ty; adj[na].min = 0; adj[na].max = 1000;
            na++;
        }
    }
    memcpy(o.adj, adj, na * sizeof adj[0]);
    o.n_adj = (uint8_t)na;
    CHECK(na == 35);
    en = gz_terms_encode_outer(&o, enc, sizeof enc);
    CHECK(en > 0 && en + 4 + 253 <= GZ_TERMS_OUTER_MAX);
    memset(&t, 0, sizeof t);
    t.p = enc; t.len = en;
    at = en;
    while (start = t.at, gz_lw_tlv_next(&t) == 1)
        if (t.type >= 64) { at = start; break; }
    pad = GZ_TERMS_OUTER_MAX - en - 4;
    memcpy(BO, enc, at);
    BO[at] = 63; BO[at + 1] = 0xfd; BO[at + 2] = (uint8_t)(pad >> 8); BO[at + 3] = (uint8_t)pad;
    memset(BO + at + 4, 0x20, pad);
    memcpy(BO + at + 4 + pad, enc + at, en - at);
    BON = en + 4 + pad;
    CHECK(BON == GZ_TERMS_OUTER_MAX && lt_outer(BO, BON, &BOO) && BOO.target == 32 && BOO.n_adj == 35);
    gz_terms_outer_digest(BO, BON, BSCOPE);
    memset(&c, 0, sizeof c);
    memcpy(c.outer_digest, BSCOPE, 32);
    c.version = 1;
    c.n_values = (uint8_t)na;
    for (k = 0; k < na; k++) {
        c.val[k].type = adj[k].type;
        c.val[k].value = adj[k].type == 64 ? 500 : adj[k].type % 2 == 0 ? 1000 : 7;
    }
    BCN = gz_terms_encode_current(&c, BC, sizeof BC);
    CHECK(BCN > 0 && lt_current(BC, BCN, &BOO, BSCOPE, &c2) && c2.n_values == 35);
    gz_terms_current_digest(BC, BCN, BCD);
    c.val[1].value = 8;                                 /* other values under the same version: an equivocation */
    BC2N = gz_terms_encode_current(&c, BC2, sizeof BC2);
    CHECK(BC2N == BCN && lt_current(BC2, BC2N, &BOO, BSCOPE, &c2));
    printf("  largest terms: outer %zu bytes, current %zu bytes\n", BON, BCN);
}

/* `rec` (n bytes) and an odd field after it, so that it is exactly `want`
 * bytes: a later version's field, which every reader skips. 0 if it cannot be. */
static size_t padded(const uint8_t *rec, size_t n, size_t want, uint8_t *out, size_t cap)
{
    size_t d, at = n;
    if (want < n + 2 || want > cap) return 0;
    memcpy(out, rec, n);
    d = want - n;
    if (d == 255 || d == 256) {                         /* two fields: 102 bytes, then the rest */
        out[at++] = 0xf9; out[at++] = 100;
        memset(out + at, 0, 100);
        at += 100;
        d -= 102;
    }
    out[at++] = 0xfb;
    if (d - 2 < 253) { out[at++] = (uint8_t)(d - 2); memset(out + at, 0, d - 2); at += d - 2; }
    else {
        out[at++] = 0xfd; out[at++] = (uint8_t)((d - 4) >> 8); out[at++] = (uint8_t)(d - 4);
        memset(out + at, 0, d - 4);
        at += d - 4;
    }
    return at == want ? at : 0;
}

static gz_lobby_conditions_t BCOND;

/* A fresh engine (host or member 1 of the big lobby) restored from the
 * journal's records before index `upto`, then given `r`: its answer. */
static gz_status_t restore_then(const journal_t *j, size_t upto, int host, const gz_record_t *r)
{
    static gz_lobby_host_t h;
    static gz_lobby_member_t m;
    size_t i;
    if (host) host_new(&h, &HOST, NULL, 0);
    else member_new(&m, 1, &MEM[1], BSCOPE, 0, &BCOND);
    for (i = 0; i < upto && i < j->n; i++)
        if ((host ? gz_lobby_host_restore(&h, &j->r[i]) : gz_lobby_member_restore(&m, &j->r[i])) != GZ_OK) return GZ_ERR_BUG;
    return host ? gz_lobby_host_restore(&h, r) : gz_lobby_member_restore(&m, r);
}

static int COVERED[16];

/* One row of the table on one side: the largest record of `type` the engine
 * saved in `j` is within its row, is taken by the engine's own restore, is
 * taken padded to exactly the row's size, and is refused one byte over. */
static void row(const journal_t *j, int host, uint32_t type)
{
    static uint8_t big[GZ_LOBBY_REC_MAX + 8];
    const gz_lobby_rec_max_t *t;
    size_t nt, i, n;
    gz_record_t r;
    int at = largest(j, type);
    uint32_t max = gz_lobby_rec_max(type);
    t = gz_lobby_rec_table(&nt);
    CHECK(at >= 0 && max != 0);
    if (at < 0 || !max) return;
    r = j->r[at];
    CHECK(r.bytes.len <= max);
    CHECK(restore_then(j, (size_t)at, host, &r) == GZ_OK);
    n = padded(r.bytes.data, r.bytes.len, max, big, sizeof big);
    CHECK(n == max);
    r.bytes.data = big;
    r.bytes.len = n;
    CHECK(restore_then(j, (size_t)at, host, &r) == GZ_OK);              /* exactly the table's value */
    n = padded(j->r[at].bytes.data, j->r[at].bytes.len, (size_t)max + 1, big, sizeof big);
    CHECK(n == (size_t)max + 1);
    r.bytes.len = n;
    CHECK(restore_then(j, (size_t)at, host, &r) == GZ_ERR_CORRUPT);     /* one byte more */
    {
        uint8_t sc[32];                                                /* the node part's reader has the same bound */
        CHECK(!gz_lobby_rec_scope(&r, sc));
        r.bytes.len = max;
        n = padded(j->r[at].bytes.data, j->r[at].bytes.len, max, big, sizeof big);
        CHECK(n == max && gz_lobby_rec_scope(&r, sc) && memcmp(sc, BSCOPE, 32) == 0);
    }
    for (i = 0; i < nt && i < 16; i++) if (t[i].type == type) COVERED[i]++;
}

static const char *rec_name(uint32_t type)
{
    size_t nt, i;
    const gz_lobby_rec_max_t *t = gz_lobby_rec_table(&nt);
    for (i = 0; i < nt; i++) if (t[i].type == type) return t[i].name;
    return "?";
}

static void test_largest(void)
{
    static gz_lobby_host_t h, h2;
    static gz_lobby_member_t m, mf;
    static journal_t HJ, MJ, FJ;
    static uint8_t ob[8000], ob2[8000], buf[600], rb[GZ_LOBBY_REC_MAX + 8], list[GZ_LOBBY_MAX_SEATS * GZ_LOBBY_START_ITEM + 300];
    uint8_t chk[32], c1[32];
    size_t n, on, i, nt;
    const gz_lobby_rec_max_t *tab = gz_lobby_rec_table(&nt);
    gz_lobby_msg_t g;
    gz_record_t r;
    int k, at;

    big_terms();
    BCOND = lt_cond_fits();
    memset(c1, 0xc1, 32);

    /* THE HOST: the big terms, a new version, 32 seats (the first one's ready
     * the largest a seat keeps), all answering a check: the largest start_sent
     * the engine makes; then a retry and a cancel */
    CLOCK = W_T0 - 3600000;
    host_new(&h, &HOST, NULL, 0);
    acts_reset();
    CHECK(gz_lobby_host_open(&h, BO, BON, BC, BCN, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_OPENED) == 1);
    keep(&HJ);
    CHECK(memcmp(h.scope, BSCOPE, 32) == 0 && h.terms.target == 32);
    {
        uint64_t v[GZ_TERMS_MAX_ADJ];
        for (i = 0; i < 35; i++) v[i] = h.values.val[i].value;
        v[0] = 600;
        acts_reset();
        CHECK(gz_lobby_host_set_values(&h, v, 35, &A.l) == GZ_OK && saves(GZ_REC_TERMS_VERSION) == 1 && h.values.version == 2);
        keep(&HJ);
    }
    for (k = 1; k <= 32; k++) {
        CHECK(hin(&h, GZ_LIN_CONNECTED, k, NULL, 0) == GZ_OK);
        CLOCK += 1000;
        n = join_env(buf, sizeof buf, BSCOPE, k);
        CHECK(hin(&h, GZ_LIN_MESSAGE, k, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1);
        keep(&HJ);
        n = k == 1 ? ready_env_sized(buf, sizeof buf, BSCOPE, k, 2, h.current_digest, NULL, GZ_LOBBY_MAX_SAVED_MSG)
                   : ready_env(buf, sizeof buf, BSCOPE, k, 2, h.current_digest, NULL, 0, 0);
        CHECK(n > 0 && hin(&h, GZ_LIN_MESSAGE, k, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1);
        keep(&HJ);
    }
    CHECK(h.n_seats == 32 && h.state == GZ_LOBBY_READY_CHECK && sends(GZ_KIND_READY_CHECK) == 32 && h.seats[0].ready_len == 256);
    CHECK(last_sent(GZ_KIND_READY_CHECK, &g));
    memcpy(chk, g.check_id, 32);
    for (k = 1; k <= 32; k++) {
        n = k == 1 ? ready_env_sized(buf, sizeof buf, BSCOPE, k, 2, h.current_digest, chk, GZ_LOBBY_MAX_SAVED_MSG)
                   : ready_env(buf, sizeof buf, BSCOPE, k, 2, h.current_digest, chk, 0, 0);
        CHECK(n > 0 && hin(&h, GZ_LIN_MESSAGE, k, buf, n) == GZ_OK);
        keep(&HJ);
    }
    CHECK(htimer(&h, GZ_LOBBY_TIMER_WINDOW) == GZ_OK && h.state == GZ_LOBBY_SIGNING && sends(GZ_KIND_START) == 32 &&
          saves(GZ_REC_START_SENT) == 1);
    keep(&HJ);
    for (k = 0; k < 32; k++) CHECK(h.seats[k].chosen && h.seats[k].start_len > 0);
    acts_reset();
    CHECK(gz_lobby_host_round_result(&h, GZ_LOBBY_ROUND_RETRY, NULL, 0, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_STATE) == 1);
    keep(&HJ);
    acts_reset();
    CHECK(gz_lobby_host_cancel(&h, 2, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_ENDED) == 1);
    keep(&HJ);
    /* the whole journal restores, and the host resumes */
    host_new(&h2, &HOST, NULL, 0);
    for (i = 0; i < HJ.n; i++) CHECK(gz_lobby_host_restore(&h2, &HJ.r[i]) == GZ_OK);
    acts_reset();
    CHECK(gz_lobby_host_resume(&h2, &A.l) == GZ_OK && h2.state == GZ_LOBBY_CANCELLED && h2.n_seats == 32);

    /* A MEMBER of the same lobby (version 1 of the values): terms of 4,096
     * bytes, then a ready check, a start and a cancel of 256 bytes each */
    CLOCK = W_T0 - 3600000;
    member_new(&m, 1, &MEM[1], BSCOPE, 0, &BCOND);
    m_in(&m, 1, GZ_LIN_CONNECTED);
    on = offer_env(ob, sizeof ob, BSCOPE, BO, BON, BC, BCN, &HOST);
    CHECK(on > 0 && feed(&m, 1, ob, on) == GZ_OK && saves(GZ_REC_TERMS_RECEIVED) == 1 && saves(GZ_REC_JOINED) == 1 &&
          saves(GZ_REC_READY_SENT) == 1 && m.joined && m.ready);
    keep(&MJ);
    n = host_env_sized(buf, sizeof buf, BSCOPE, GZ_KIND_READY_CHECK, c1, 1, BCD, 0, 0, 0, GZ_LOBBY_MAX_SAVED_MSG);
    CHECK(n == 256 && feed(&m, 1, buf, n) == GZ_OK && saves(GZ_REC_FREEZE) == 1 && saves(GZ_REC_READY_SENT) == 1 && m.frozen);
    keep(&MJ);
    n = host_env_sized(buf, sizeof buf, BSCOPE, GZ_KIND_START, c1, 0, NULL, 1, 4, 0, GZ_LOBBY_MAX_SAVED_MSG);
    CHECK(n == 256 && feed(&m, 1, buf, n) == GZ_OK && saves(GZ_REC_START_RECEIVED) == 1 && m.start_len == 256);
    keep(&MJ);
    n = host_env_sized(buf, sizeof buf, BSCOPE, GZ_KIND_START, c1, 0, NULL, 1, 4, 0, GZ_LOBBY_MAX_SAVED_MSG + 1);
    {   /* a start of 257 bytes is not kept, so not taken (a second member, the same way) */
        static gz_lobby_member_t mx;
        uint8_t ck[300];
        size_t cn2 = host_env(ck, sizeof ck, BSCOPE, GZ_KIND_READY_CHECK, c1, 1, BCD, 0, 0, 0, 0, &HOST);
        member_new(&mx, 1, &MEM[1], BSCOPE, 0, &BCOND);
        m_in(&mx, 1, GZ_LIN_CONNECTED);
        feed(&mx, 1, ob, on);
        feed(&mx, 1, ck, cn2);
        CHECK(n == 257 && feed(&mx, 1, buf, n) == GZ_OK && A.l.count == 0 && mx.start_len == 0);
    }
    acts_reset();
    CHECK(gz_lobby_member_round_result(&m, GZ_LOBBY_ROUND_RETRY, c1, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_STATE) == 1);
    keep(&MJ);
    n = host_env_sized(buf, sizeof buf, BSCOPE, GZ_KIND_CANCEL, NULL, 0, NULL, 0, 0, 2, GZ_LOBBY_MAX_SAVED_MSG);
    CHECK(n == 256 && feed(&m, 1, buf, n) == GZ_OK && saves(GZ_REC_LOBBY_ENDED) == 1 && m.ended);
    keep(&MJ);
    {
        static gz_lobby_member_t m2;
        member_new(&m2, 1, &MEM[1], BSCOPE, 0, &BCOND);
        for (i = 0; i < MJ.n; i++) CHECK(gz_lobby_member_restore(&m2, &MJ.r[i]) == GZ_OK);
        acts_reset();
        CHECK(gz_lobby_member_resume(&m2, &A.l) == GZ_OK && m2.ended && m2.frozen && m2.outer_len == GZ_TERMS_OUTER_MAX);
    }
    /* ANOTHER MEMBER sees two current records under one version: the largest
     * host_fault the engine makes (each piece of evidence a whole record and
     * its signature) */
    member_new(&mf, 1, &MEM[1], BSCOPE, 0, &BCOND);
    m_in(&mf, 1, GZ_LIN_CONNECTED);
    CHECK(feed(&mf, 1, ob, on) == GZ_OK);
    keep(&FJ);
    on = offer_env(ob2, sizeof ob2, BSCOPE, BO, BON, BC2, BC2N, &HOST);
    CHECK(feed(&mf, 1, ob2, on) == GZ_OK && saves(GZ_REC_HOST_FAULT) == 1 && saves(GZ_REC_LOBBY_ENDED) == 1 &&
          note(GZ_NOTE_HOST_FAULT, GZ_FAULT_TWO_VALUES, -1) && mf.ended && mf.left);
    keep(&FJ);

    /* EVERY ROW OF THE TABLE, on each side that has the record */
    memset(COVERED, 0, sizeof COVERED);
    row(&HJ, 1, GZ_REC_LOBBY_OPENED);
    row(&HJ, 1, GZ_REC_TERMS_VERSION);
    row(&HJ, 1, GZ_REC_SEAT);
    row(&HJ, 1, GZ_REC_FREEZE);
    row(&HJ, 1, GZ_REC_START_SENT);
    row(&HJ, 1, GZ_REC_LOBBY_STATE);
    row(&HJ, 1, GZ_REC_LOBBY_ENDED);
    row(&MJ, 0, GZ_REC_TERMS_RECEIVED);
    row(&MJ, 0, GZ_REC_JOINED);
    row(&MJ, 0, GZ_REC_READY_SENT);
    row(&MJ, 0, GZ_REC_FREEZE);
    row(&MJ, 0, GZ_REC_START_RECEIVED);
    row(&MJ, 0, GZ_REC_LOBBY_STATE);
    row(&MJ, 0, GZ_REC_LOBBY_ENDED);
    row(&FJ, 0, GZ_REC_HOST_FAULT);
    for (i = 0; i < nt; i++) {
        CHECK(COVERED[i] >= 1);
        if (!COVERED[i]) printf("  no largest record for row %s\n", tab[i].name);
    }
    /* the sizes the engines reached: the records whose content they can fill */
    CHECK(HJ.r[largest(&HJ, GZ_REC_LOBBY_OPENED)].bytes.len == 34 + 4 + BON + 66 + 4 + BCN + 66);
    CHECK(MJ.r[largest(&MJ, GZ_REC_TERMS_RECEIVED)].bytes.len == 34 + 4 + BON + 66 + 4 + BCN + 66);
    CHECK(HJ.r[largest(&HJ, GZ_REC_SEAT)].bytes.len == 34 + 35 + 35 + 66 + 66 + 3 + 4 + 6 + 10 + 4 + 256);
    CHECK(MJ.r[largest(&MJ, GZ_REC_FREEZE)].bytes.len == 34 + 34 + 6 + 34 + 4 + 256);
    CHECK(MJ.r[largest(&MJ, GZ_REC_START_RECEIVED)].bytes.len == 34 + 4 + 256);
    CHECK(MJ.r[largest(&MJ, GZ_REC_LOBBY_ENDED)].bytes.len == 34 + 3 + 4 + 4 + 256);
    CHECK(MJ.r[largest(&MJ, GZ_REC_LOBBY_STATE)].bytes.len == 34 + 3 + 34);
    CHECK(FJ.r[largest(&FJ, GZ_REC_HOST_FAULT)].bytes.len == 34 + 3 + 2 * (4 + BCN + 64));
    CHECK(HJ.r[largest(&HJ, GZ_REC_START_SENT)].bytes.len == 34 + 34 + 10 + 4 + 32 * (35 + 145));
    for (i = 0; i < nt; i++) {
        int a = largest(&HJ, tab[i].type), b = largest(&MJ, tab[i].type), c = largest(&FJ, tab[i].type);
        size_t best = 0;
        if (a >= 0 && HJ.r[a].bytes.len > best) best = HJ.r[a].bytes.len;
        if (b >= 0 && MJ.r[b].bytes.len > best) best = MJ.r[b].bytes.len;
        if (c >= 0 && FJ.r[c].bytes.len > best) best = FJ.r[c].bytes.len;
        printf("  %-15s largest saved %5zu of %5u\n", rec_name(tab[i].type), best, (unsigned)tab[i].max);
    }

    /* WHAT THE ENGINES CANNOT FILL, built with gz_lr_*: the largest legal
     * content of each, taken; one byte more of content, refused. */
    /* start_sent: 32 seats, each start an envelope of 256 bytes */
    at = largest(&HJ, GZ_REC_START_SENT);
    if (at >= 0) {
        gz_lr_t w;
        size_t ln = 0, before257 = 0;
        int which;
        for (which = 0; which < 2; which++) {           /* 0: every start 256 bytes; 1: the last one 257 */
            ln = 0;
            for (k = 1; k <= 32; k++) {
                size_t want = which == 1 && k == 32 ? 257 : 256;
                /* a start is 145 bytes; an odd record of want - 147 bytes fills it */
                n = host_env(buf, sizeof buf, BSCOPE, GZ_KIND_START, chk, 0, NULL, 1, 33, 0, want - 147, &HOST);
                CHECK(n == want);
                memcpy(list + ln, MEM[k].key[2].pub, 33);
                gz_lw_put(list + ln + 33, n, 2);
                memcpy(list + ln + 35, buf, n);
                if (k == 32) before257 = ln;
                ln += 35 + n;
            }
            gz_lr_start(&w, rb, sizeof rb, BSCOPE);
            gz_lr_put(&w, 4, chk, 32);
            gz_lr_int(&w, 6, CLOCK, 8);
            gz_lr_put(&w, 8, list, ln);
            r.type = GZ_REC_START_SENT; r.bytes.data = rb; r.bytes.len = gz_lr_done(&w);
            if (which == 0) {
                CHECK(ln == GZ_LOBBY_MAX_SEATS * GZ_LOBBY_START_ITEM && r.bytes.len > 0 && r.bytes.len <= GZ_LOBBY_REC_MAX_START_SENT);
                CHECK(restore_then(&HJ, (size_t)at, 1, &r) == GZ_OK);
                printf("  start_sent      largest legal %5zu of %5u\n", r.bytes.len, (unsigned)GZ_LOBBY_REC_MAX_START_SENT);
            } else {
                CHECK(r.bytes.len > 0 && restore_then(&HJ, (size_t)at, 1, &r) == GZ_ERR_CORRUPT);
            }
        }
        (void)before257;
    }
    /* joined and ready_sent: a signed message of 256 bytes; 257 is not one the engine saved */
    at = largest(&MJ, GZ_REC_JOINED);
    if (at >= 0) {
        uint8_t msg[300], sf[64], sc[64], b32[32];
        gz_lobby_enc_t e;
        size_t L;
        gz_lobby_binding(BSCOPE, MEM[1].key[3].pub, MEM[1].key[2].pub, b32);
        lt_sign(&MEM[1], 3, b32, sf);
        lt_sign(&MEM[1], 2, b32, sc);
        for (L = 256; L <= 257; L++) {
            gz_lobby_enc_start(&e, msg, sizeof msg, GZ_KIND_JOIN, BSCOPE);
            gz_lobby_enc_record(&e, 2, MEM[1].key[3].pub, 33);
            gz_lobby_enc_record(&e, 4, sf, 64);
            gz_lobby_enc_record(&e, 6, sc, 64);
            gz_lobby_enc_record(&e, 7, (const uint8_t *)"a display name of 32 bytes ....!", 32);
            gz_lobby_enc_record(&e, 9, PADB, L - 205 - 34 - 2);
            n = gz_lobby_enc_done(&e);
            CHECK(n == L);
            r.type = GZ_REC_JOINED; r.bytes.data = rb; r.bytes.len = lt_rec_msg(rb, sizeof rb, BSCOPE, msg, n);
            CHECK(r.bytes.len > 0 && (L == 257 || r.bytes.len <= GZ_LOBBY_REC_MAX_JOINED));
            CHECK(restore_then(&MJ, (size_t)at, 0, &r) == (L == 256 ? GZ_OK : GZ_ERR_CORRUPT));
        }
    }
    at = largest(&MJ, GZ_REC_READY_SENT);
    if (at >= 0) {
        uint8_t msg[300];
        size_t L;
        for (L = 256; L <= 257; L++) {
            n = ready_env_sized(msg, sizeof msg, BSCOPE, 1, 1, BCD, c1, L);
            CHECK(n == L);
            r.type = GZ_REC_READY_SENT; r.bytes.data = rb; r.bytes.len = lt_rec_msg(rb, sizeof rb, BSCOPE, msg, n);
            CHECK(r.bytes.len > 0 && (L == 257 || r.bytes.len <= GZ_LOBBY_REC_MAX_READY_SENT));
            CHECK(restore_then(&MJ, (size_t)at, 0, &r) == (L == 256 ? GZ_OK : GZ_ERR_CORRUPT));
        }
    }
    /* host_fault: two pieces of evidence of 1,088 bytes (a current record of 1,024 and its signature) */
    at = largest(&FJ, GZ_REC_HOST_FAULT);
    if (at >= 0) {
        static uint8_t ev[GZ_LOBBY_EVIDENCE_MAX + 1];
        gz_lr_t w;
        size_t L;
        memset(ev, 0x5e, sizeof ev);
        for (L = GZ_LOBBY_EVIDENCE_MAX; L <= GZ_LOBBY_EVIDENCE_MAX + 1; L++) {
            gz_lr_start(&w, rb, sizeof rb, BSCOPE);
            gz_lr_int(&w, 4, GZ_FAULT_AFTER_FREEZE, 1);
            gz_lr_put(&w, 6, ev, GZ_LOBBY_EVIDENCE_MAX);
            gz_lr_put(&w, 8, ev, L);
            r.type = GZ_REC_HOST_FAULT; r.bytes.data = rb; r.bytes.len = gz_lr_done(&w);
            CHECK(r.bytes.len > 0 && (L > GZ_LOBBY_EVIDENCE_MAX || r.bytes.len <= GZ_LOBBY_REC_MAX_HOST_FAULT));
            CHECK(restore_then(&FJ, (size_t)at, 0, &r) == (L == GZ_LOBBY_EVIDENCE_MAX ? GZ_OK : GZ_ERR_CORRUPT));
        }
    }
    /* freeze and lobby_ended: the saved message one byte over */
    at = largest(&MJ, GZ_REC_FREEZE);
    if (at >= 0) {
        uint8_t msg[300];
        n = host_env_sized(msg, sizeof msg, BSCOPE, GZ_KIND_READY_CHECK, c1, 1, BCD, 0, 0, 0, 257);
        r.type = GZ_REC_FREEZE; r.bytes.data = rb;
        r.bytes.len = lt_rec_freeze(rb, sizeof rb, BSCOPE, c1, 1, BCD, msg, n);
        CHECK(n == 257 && r.bytes.len > 0 && restore_then(&MJ, (size_t)at, 0, &r) == GZ_ERR_CORRUPT);
        n = host_env_sized(msg, sizeof msg, BSCOPE, GZ_KIND_CANCEL, NULL, 0, NULL, 0, 0, 2, 257);
        r.type = GZ_REC_LOBBY_ENDED;
        r.bytes.len = lt_rec_ended(rb, sizeof rb, BSCOPE, GZ_LOBBY_CANCELLED, 2, msg, n);
        CHECK(n == 257 && r.bytes.len > 0 && restore_then(&MJ, MJ.n - 1, 0, &r) == GZ_ERR_CORRUPT);
        CHECK(restore_then(&HJ, HJ.n - 1, 1, &r) == GZ_ERR_CORRUPT);
    }
    /* a record of another lobby is not this engine's, on either side: also a
     * scope that differs in one byte, the first or the last */
    at = largest(&HJ, GZ_REC_SEAT);
    if (at >= 0) {
        uint8_t near[32];
        int b;
        r = HJ.r[at];
        CHECK(restore_then(&HJ, (size_t)at, 1, &r) == GZ_OK);
        r.bytes.data = rb;
        r.bytes.len = lt_rec_with(HJ.r[at].bytes.data, HJ.r[at].bytes.len, 2, SCOPE, 32, rb, sizeof rb);
        CHECK(r.bytes.len == HJ.r[at].bytes.len && restore_then(&HJ, (size_t)at, 1, &r) == GZ_ERR_CORRUPT);
        for (b = 0; b < 32; b += 31) {
            memcpy(near, BSCOPE, 32);
            near[b] ^= 1;
            r.bytes.len = lt_rec_with(HJ.r[at].bytes.data, HJ.r[at].bytes.len, 2, near, 32, rb, sizeof rb);
            CHECK(r.bytes.len == HJ.r[at].bytes.len && restore_then(&HJ, (size_t)at, 1, &r) == GZ_ERR_CORRUPT);
            r.type = GZ_REC_READY_SENT;
            r.bytes.len = lt_rec_unready(rb, sizeof rb, near, 2);
            CHECK(restore_then(&MJ, MJ.n, 0, &r) == GZ_ERR_CORRUPT);
            r.bytes.len = lt_rec_unready(rb, sizeof rb, BSCOPE, 2);
            CHECK(restore_then(&MJ, MJ.n, 0, &r) == GZ_OK);                     /* the control */
            r.type = GZ_REC_SEAT;
        }
    }
    /* an even field its record type has not makes a record this version
     * cannot read (an odd one is skipped: the padding above), on each side */
    {
        static const struct { int host; uint32_t type; unsigned field; } extra[] = {
            {1, GZ_REC_LOBBY_OPENED, 12}, {1, GZ_REC_TERMS_VERSION, 8}, {1, GZ_REC_FREEZE, 12}, {1, GZ_REC_START_SENT, 10},
            {1, GZ_REC_LOBBY_STATE, 8}, {1, GZ_REC_LOBBY_ENDED, 10}, {0, GZ_REC_TERMS_RECEIVED, 12}, {0, GZ_REC_JOINED, 6},
            {0, GZ_REC_READY_SENT, 8}, {0, GZ_REC_FREEZE, 12}, {0, GZ_REC_START_RECEIVED, 6}, {0, GZ_REC_LOBBY_STATE, 8},
            {0, GZ_REC_LOBBY_ENDED, 10},
        };
        uint8_t one = 1;
        for (i = 0; i < sizeof extra / sizeof extra[0]; i++) {
            const journal_t *j = extra[i].host ? &HJ : &MJ;
            at = largest(j, extra[i].type);
            CHECK(at >= 0);
            if (at < 0) continue;
            r = j->r[at];
            CHECK(restore_then(j, (size_t)at, extra[i].host, &r) == GZ_OK);
            r.bytes.data = rb;
            r.bytes.len = lt_rec_with(j->r[at].bytes.data, j->r[at].bytes.len, extra[i].field, &one, 1, rb, sizeof rb);
            CHECK(r.bytes.len == j->r[at].bytes.len + 3 && restore_then(j, (size_t)at, extra[i].host, &r) == GZ_ERR_CORRUPT);
        }
        at = largest(&FJ, GZ_REC_HOST_FAULT);
        if (at >= 0) {
            r = FJ.r[at];
            r.bytes.data = rb;
            r.bytes.len = lt_rec_with(FJ.r[at].bytes.data, FJ.r[at].bytes.len, 10, &one, 1, rb, sizeof rb);
            CHECK(r.bytes.len > 0 && restore_then(&FJ, (size_t)at, 0, &r) == GZ_ERR_CORRUPT);
        }
    }
    at = largest(&MJ, GZ_REC_START_RECEIVED);
    if (at >= 0) {
        r = MJ.r[at];
        r.bytes.data = rb;
        r.bytes.len = lt_rec_with(MJ.r[at].bytes.data, MJ.r[at].bytes.len, 2, SCOPE, 32, rb, sizeof rb);
        CHECK(r.bytes.len == MJ.r[at].bytes.len && restore_then(&MJ, (size_t)at, 0, &r) == GZ_ERR_CORRUPT);
        /* and each side refuses the other side's record types */
        r = MJ.r[at];
        CHECK(restore_then(&HJ, HJ.n, 1, &r) == GZ_ERR_CORRUPT);
        r = HJ.r[largest(&HJ, GZ_REC_SEAT)];
        CHECK(restore_then(&MJ, MJ.n, 0, &r) == GZ_ERR_CORRUPT);
        r = HJ.r[largest(&HJ, GZ_REC_START_SENT)];
        CHECK(restore_then(&MJ, MJ.n, 0, &r) == GZ_ERR_CORRUPT);
        r = HJ.r[largest(&HJ, GZ_REC_TERMS_VERSION)];
        CHECK(restore_then(&MJ, MJ.n, 0, &r) == GZ_ERR_CORRUPT);
        r = MJ.r[largest(&MJ, GZ_REC_JOINED)];
        CHECK(restore_then(&HJ, HJ.n, 1, &r) == GZ_ERR_CORRUPT);
        r = MJ.r[largest(&MJ, GZ_REC_READY_SENT)];
        CHECK(restore_then(&HJ, HJ.n, 1, &r) == GZ_ERR_CORRUPT);
        r = MJ.r[largest(&MJ, GZ_REC_TERMS_RECEIVED)];
        CHECK(restore_then(&HJ, HJ.n, 1, &r) == GZ_ERR_CORRUPT);
        r = FJ.r[largest(&FJ, GZ_REC_HOST_FAULT)];
        CHECK(restore_then(&HJ, HJ.n, 1, &r) == GZ_ERR_CORRUPT);
    }
    journal_free(&HJ);
    journal_free(&MJ);
    journal_free(&FJ);
}

/* ------------------------------------------------- the signing gate */

static void test_gate(void)
{
    static gz_lobby_host_t h;
    static gz_lobby_member_t m, m2;
    static journal_t J;
    static uint8_t ob[8000];
    gz_lobby_conditions_t cond = lt_cond_fits();
    uint8_t buf[600], chk[32], chk2[32];
    size_t n, on, i;
    gz_lobby_msg_t g;
    gz_lobby_seat_t *s;
    int k;

    /* 1. A closed gate at the join: the member joins, and does not ready. The
     * host seats it Joined. Told once: "unlock to take part". */
    CLOCK = W_T0 - 3600000;
    host_new(&h, &HOST, NULL, 0);
    acts_reset();
    CHECK(gz_lobby_host_open(&h, T1, T1N, T2, T2N, &A.l) == GZ_OK);
    hin(&h, GZ_LIN_CONNECTED, 1, NULL, 0);
    GATE = 0;
    member_new(&m, 1, &MEM[1], SCOPE, 1, &cond);
    m_in(&m, 1, GZ_LIN_CONNECTED);
    on = offer_env(ob, sizeof ob, SCOPE, T1, T1N, T2, T2N, &HOST);
    CHECK(feed(&m, 1, ob, on) == GZ_OK && saves(GZ_REC_TERMS_RECEIVED) == 1 && saves(GZ_REC_JOINED) == 1 &&
          saves(GZ_REC_READY_SENT) == 0 && sends(GZ_KIND_JOIN) == 1 && sends(GZ_KIND_READY) == 0 && all_sends() == 1 &&
          notes(GZ_NOTE_LOCKED) == 1 && m.joined && !m.ready);
    keep(&J);
    to_host(&h, 1);
    s = seat(&h, 1);
    CHECK(s && s->state == GZ_SEAT_JOINED && seat_shown(1) == GZ_SEAT_JOINED && s->n_changes == 1);
    CHECK(feed(&m, 1, ob, on) == GZ_OK && A.l.count == 0);                       /* the same terms again: quiet */
    acts_reset();                                       /* the person says ready while it is closed: told again, no ready */
    CHECK(gz_lobby_member_ready(&m, &A.l) == GZ_OK && notes(GZ_NOTE_LOCKED) == 1 && A.l.count == 1 && !m.ready);
    /* a ready check while locked and not ready: `unready` reason 3 at once, never a ready; nothing frozen or saved */
    memset(chk, 0x71, 32);
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_READY_CHECK, chk, 1, CD2, 0, 0, 0, 0, &HOST);
    CHECK(feed(&m, 1, buf, n) == GZ_OK && sends(GZ_KIND_UNREADY) == 1 && sends(GZ_KIND_READY) == 0 && saves(GZ_REC_READY_SENT) == 1 &&
          !m.frozen && !m.has_answered && last_sent(GZ_KIND_UNREADY, &g) && g.has_reason && g.reason == 3);
    CHECK(notes(GZ_NOTE_LOCKED) == 0 && !gz_lobby_member_accepted(&m, chk, 1, NULL));   /* told already for this closing */

    /* 2. The gate opens: the member readies (saved first), and the host seats it Ready */
    GATE = 1;
    acts_reset();
    CHECK(gz_lobby_member_gate_opened(&m, &A.l) == GZ_OK && saves(GZ_REC_READY_SENT) == 1 && sends(GZ_KIND_READY) == 1 &&
          save_at(GZ_REC_READY_SENT) < send_at(GZ_KIND_READY) && m.ready && notes(GZ_NOTE_LOCKED) == 0);
    CHECK(last_sent(GZ_KIND_READY, &g) && !g.has_check_id && g.version == 1);
    keep(&J);
    to_host(&h, 1);
    s = seat(&h, 1);
    CHECK(s && s->state == GZ_SEAT_READY && s->n_changes == 2 && !s->locked);
    acts_reset();                                       /* opened again: nothing to do */
    CHECK(gz_lobby_member_gate_opened(&m, &A.l) == GZ_OK && A.l.count == 0);
    acts_reset();                                       /* "closed" while it is open: nothing */
    CHECK(gz_lobby_member_gate_closed(&m, &A.l) == GZ_OK && A.l.count == 0 && m.ready);

    /* 3. The gate closes on a Ready member with no check in flight: the
     * locked unready, saved first (ready_sent with reason 3), then sent */
    GATE = 0;
    acts_reset();
    CHECK(gz_lobby_member_gate_closed(&m, &A.l) == GZ_OK && A.l.count == 3 && A.s[0].kind == GZ_ACTION_SAVE &&
          kind_of(&A.s[1]) == GZ_KIND_UNREADY && A.s[2].kind == GZ_ACTION_NOTIFY && A.s[2].u.notify.code == GZ_NOTE_LOCKED &&
          A.s[2].u.notify.bytes.len == 0 && !m.ready);
    CHECK(last_sent(GZ_KIND_UNREADY, &g) && g.has_reason && g.reason == 3);
    if (saved(GZ_REC_READY_SENT)) {
        uint8_t want[64];
        size_t wn = lt_rec_unready(want, sizeof want, SCOPE, 3);
        CHECK(saved(GZ_REC_READY_SENT)->bytes.len == wn && memcmp(saved(GZ_REC_READY_SENT)->bytes.data, want, wn) == 0);
    }
    keep(&J);
    to_host(&h, 1);
    /* the host: the seat is out of the count, marked locked, and the change is not counted against its limit */
    s = seat(&h, 1);
    CHECK(s && s->state == GZ_SEAT_JOINED && s->locked && s->n_changes == 2 && saves(GZ_REC_SEAT) == 1 &&
          seat_shown(1) == GZ_SEAT_JOINED);
    acts_reset();                                       /* closed again without an opening: nothing more */
    CHECK(gz_lobby_member_gate_closed(&m, &A.l) == GZ_OK && A.l.count == 0);
    /* restarted here: the unready is the lock's, not the user's, so opening the gate readies again */
    member_new(&m2, 1, &MEM[1], SCOPE, 1, &cond);
    for (i = 0; i < J.n; i++) CHECK(gz_lobby_member_restore(&m2, &J.r[i]) == GZ_OK);
    CHECK(m2.joined && !m2.ready && !m2.user_unready && m2.unready_reason == 3);
    acts_reset();
    CHECK(gz_lobby_member_resume(&m2, &A.l) == GZ_OK && A.l.count == 1 && A.s[0].kind == GZ_ACTION_CONNECT);   /* not ready: nothing to lock out */
    m_in(&m2, 1, GZ_LIN_CONNECTED);
    n = status_env(buf, sizeof buf, SCOPE, GZ_LOBBY_OPEN, GZ_SEAT_READY, 1);    /* the host lost that unready: said again, reason 3 */
    CHECK(feed(&m2, 1, buf, n) == GZ_OK && sends(GZ_KIND_UNREADY) == 1 && last_sent(GZ_KIND_UNREADY, &g) && g.reason == 3);
    GATE = 1;
    acts_reset();
    CHECK(gz_lobby_member_gate_opened(&m2, &A.l) == GZ_OK && sends(GZ_KIND_READY) == 1 && m2.ready);
    GATE = 1;
    acts_reset();
    CHECK(gz_lobby_member_gate_opened(&m, &A.l) == GZ_OK && sends(GZ_KIND_READY) == 1 && saves(GZ_REC_READY_SENT) == 1 && m.ready);
    keep(&J);
    to_host(&h, 1);
    s = seat(&h, 1);                                    /* the ready after "locked": not counted either */
    CHECK(s && s->state == GZ_SEAT_READY && s->n_changes == 2 && !s->locked && saves(GZ_REC_SEAT) == 1);

    /* 4. WHAT THE HOST COUNTS. The free pair is one per check window. The
     * seat has 2 counted changes (join, ready) and used its free pair. Each
     * further locked/ready pair counts 2: after four of them it has 10, and
     * a fifth pair's ready is refused by the limit of 10 changes in 10
     * minutes (its unready, a move out, is always taken). */
    {
        uint8_t un3[64], rd[300];
        size_t un3n = reason_env(un3, sizeof un3, SCOPE, GZ_KIND_UNREADY, 3), rn;
        rn = ready_env(rd, sizeof rd, SCOPE, 1, 1, CD2, NULL, 0, 0);
        for (k = 1; k <= 4; k++) {
            CHECK(hin(&h, GZ_LIN_MESSAGE, 1, un3, un3n) == GZ_OK && saves(GZ_REC_SEAT) == 1 && s->state == GZ_SEAT_JOINED && s->locked);
            CHECK(s->n_changes == 2 + 2 * k - 1);
            CHECK(hin(&h, GZ_LIN_MESSAGE, 1, rd, rn) == GZ_OK && saves(GZ_REC_SEAT) == 1 && s->state == GZ_SEAT_READY);
            CHECK(s->n_changes == 2 + 2 * k);
        }
        CHECK(s->n_changes == 10);
        CHECK(hin(&h, GZ_LIN_MESSAGE, 1, un3, un3n) == GZ_OK && saves(GZ_REC_SEAT) == 1 && s->state == GZ_SEAT_JOINED);
        CHECK(hin(&h, GZ_LIN_MESSAGE, 1, rd, rn) == GZ_OK && !any_save() && s->state == GZ_SEAT_JOINED &&
              seat_shown(1) == GZ_SEAT_JOINED);                                  /* refused: over the limit */
        /* a seat that never said "locked" has no free pair: ten changes, then refused */
        hin(&h, GZ_LIN_CONNECTED, 2, NULL, 0);
        CLOCK += 1000;
        n = join_env(buf, sizeof buf, SCOPE, 2);
        CHECK(hin(&h, GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1);
        {
            uint8_t un2[64], rd2[300];
            size_t un2n = reason_env(un2, sizeof un2, SCOPE, GZ_KIND_UNREADY, 2), r2n;
            gz_lobby_seat_t *s2 = seat(&h, 2);
            r2n = ready_env(rd2, sizeof rd2, SCOPE, 2, 1, CD2, NULL, 0, 0);
            for (k = 1; k <= 9; k++)
                CHECK(hin(&h, GZ_LIN_MESSAGE, 2, k % 2 ? rd2 : un2, k % 2 ? r2n : un2n) == GZ_OK && saves(GZ_REC_SEAT) == 1);
            CHECK(s2 && s2->n_changes == 10 && s2->state == GZ_SEAT_READY && !s2->locked);
            CHECK(hin(&h, GZ_LIN_MESSAGE, 2, un2, un2n) == GZ_OK && saves(GZ_REC_SEAT) == 1);
            CHECK(hin(&h, GZ_LIN_MESSAGE, 2, rd2, r2n) == GZ_OK && !any_save() && s2->state == GZ_SEAT_JOINED);
            /* and an unready with reason 3 from a seat over its limit is still taken (a move out), its ready after it not */
            CLOCK += 600000;                            /* ten minutes on: both seats' windows are clear */
            CHECK(hin(&h, GZ_LIN_MESSAGE, 2, rd2, r2n) == GZ_OK && saves(GZ_REC_SEAT) == 1 && s2->state == GZ_SEAT_READY);
        }
        CHECK(hin(&h, GZ_LIN_MESSAGE, 1, rd, rn) == GZ_OK && saves(GZ_REC_SEAT) == 1 && s->state == GZ_SEAT_READY);
        /* A NEW CHECK WINDOW gives a new free pair: six more seats ready, the
         * target is reached, a check begins */
        for (k = 3; k <= 8; k++) { CLOCK += 1000; seat_up(&h, k); }
        CHECK(h.state == GZ_LOBBY_READY_CHECK && h.window_no == 1 && last_sent(GZ_KIND_READY_CHECK, &g));
        memcpy(chk, g.check_id, 32);
        /* seat 1 used window 0's pair: in the new window its changes are not
         * counted again (the ring of counted changes does not move) */
        k = s->changes_at;
        CHECK(hin(&h, GZ_LIN_MESSAGE, 1, un3, un3n) == GZ_OK && saves(GZ_REC_SEAT) == 1 && s->state == GZ_SEAT_JOINED &&
              s->locked && s->changes_at == k);                                  /* free again */
        rn = ready_env(rd, sizeof rd, SCOPE, 1, 1, CD2, chk, 0, 0);
        CHECK(hin(&h, GZ_LIN_MESSAGE, 1, rd, rn) == GZ_OK && saves(GZ_REC_SEAT) == 1 && s->state == GZ_SEAT_READY &&
              s->changes_at == k && s->answered && !s->locked);                  /* and its ready, which answers the check */
        CHECK(hin(&h, GZ_LIN_MESSAGE, 1, un3, un3n) == GZ_OK && s->changes_at == (k + 1) % 10 && s->locked);   /* a second pair in */
        CHECK(hin(&h, GZ_LIN_MESSAGE, 1, rd, rn) == GZ_OK && s->changes_at == (k + 2) % 10);                   /* that window: counted */
        {   /* a seat that never said "locked" before: its first pair free (2 counted changes stay 2), its second counted */
            gz_lobby_seat_t *s3 = seat(&h, 3);
            rn = ready_env(rd, sizeof rd, SCOPE, 3, 1, CD2, chk, 0, 0);
            CHECK(s3 && s3->n_changes == 2);
            CHECK(hin(&h, GZ_LIN_MESSAGE, 3, un3, un3n) == GZ_OK && s3->n_changes == 2 && s3->state == GZ_SEAT_JOINED && s3->locked);
            CHECK(hin(&h, GZ_LIN_MESSAGE, 3, rd, rn) == GZ_OK && s3->n_changes == 2 && s3->state == GZ_SEAT_READY && !s3->locked);
            CHECK(hin(&h, GZ_LIN_MESSAGE, 3, un3, un3n) == GZ_OK && s3->n_changes == 3 && s3->state == GZ_SEAT_JOINED);
            CHECK(hin(&h, GZ_LIN_MESSAGE, 3, rd, rn) == GZ_OK && s3->n_changes == 4 && s3->state == GZ_SEAT_READY);
            /* an unready that gives no reason, or another, is no lock: counted from the first */
            s3 = seat(&h, 4);
            rn = ready_env(rd, sizeof rd, SCOPE, 4, 1, CD2, chk, 0, 0);
            un3n = reason_env(un3, sizeof un3, SCOPE, GZ_KIND_UNREADY, -1);
            CHECK(s3 && s3->n_changes == 2);
            CHECK(hin(&h, GZ_LIN_MESSAGE, 4, un3, un3n) == GZ_OK && s3->n_changes == 3 && !s3->locked);
            CHECK(hin(&h, GZ_LIN_MESSAGE, 4, rd, rn) == GZ_OK && s3->n_changes == 4);
        }
    }

    /* 5. An answered check runs to its end: the gate closing withdraws nothing */
    CLOCK = W_T0 - 3600000;
    GATE = 1;
    N_BEGUN = N_RESUMED = 0;
    journal_free(&J);
    member_new(&m, 1, &MEM[1], SCOPE, 1, &cond);
    m_in(&m, 1, GZ_LIN_CONNECTED);
    CHECK(feed(&m, 1, ob, on) == GZ_OK && m.ready);
    keep(&J);
    memset(chk, 0x72, 32);
    memset(chk2, 0x73, 32);
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_READY_CHECK, chk, 1, CD2, 0, 0, 0, 0, &HOST);
    CHECK(feed(&m, 1, buf, n) == GZ_OK && sends(GZ_KIND_READY) == 1 && saves(GZ_REC_FREEZE) == 1 && m.has_answered);
    keep(&J);
    GATE = 0;
    acts_reset();
    CHECK(gz_lobby_member_gate_closed(&m, &A.l) == GZ_OK && A.l.count == 0 && m.ready && m.has_answered &&
          gz_lobby_member_accepted(&m, chk, 1, NULL));
    /* a restart with the check in flight: every gate is closed at a start, and still nothing is withdrawn */
    member_new(&m2, 1, &MEM[1], SCOPE, 1, &cond);
    for (i = 0; i < J.n; i++) CHECK(gz_lobby_member_restore(&m2, &J.r[i]) == GZ_OK);
    acts_reset();
    CHECK(gz_lobby_member_resume(&m2, &A.l) == GZ_OK && A.l.count == 1 && A.s[0].kind == GZ_ACTION_CONNECT && m2.ready &&
          gz_lobby_member_accepted(&m2, chk, 1, NULL));
    /* the same check asked again: the same saved answer, though the gate is closed */
    CHECK(feed(&m, 1, buf, n) == GZ_OK && sends(GZ_KIND_READY) == 1 && !any_save() && A.l.count == 1);
    /* a start for it: taken and begun, gate closed or not */
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_START, chk, 0, NULL, 1, 4, 0, 0, &HOST);
    CHECK(feed(&m, 1, buf, n) == GZ_OK && saves(GZ_REC_START_RECEIVED) == 1 && N_BEGUN == 1);
    keep(&J);
    /* restarted between the start and the round: resumed, not locked out */
    member_new(&m2, 1, &MEM[1], SCOPE, 1, &cond);
    for (i = 0; i < J.n; i++) CHECK(gz_lobby_member_restore(&m2, &J.r[i]) == GZ_OK);
    acts_reset();
    CHECK(gz_lobby_member_resume(&m2, &A.l) == GZ_OK && A.l.count == 1 && N_RESUMED == 1 && m2.ready && !any_save());
    /* the round ends in a retry while the gate is closed: the check is over, the seat leaves the count */
    acts_reset();
    CHECK(gz_lobby_member_round_result(&m, GZ_LOBBY_ROUND_RETRY, chk, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_STATE) == 1 &&
          saves(GZ_REC_READY_SENT) == 1 && sends(GZ_KIND_UNREADY) == 1 && notes(GZ_NOTE_LOCKED) == 1 && !m.ready);
    CHECK(last_sent(GZ_KIND_UNREADY, &g) && g.reason == 3 && save_at(GZ_REC_READY_SENT) < send_at(GZ_KIND_UNREADY));
    keep(&J);
    /* the next check, still locked: unready reason 3 again, no ready, nothing saved */
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_READY_CHECK, chk2, 1, CD2, 0, 0, 0, 0, &HOST);
    CHECK(feed(&m, 1, buf, n) == GZ_OK && sends(GZ_KIND_UNREADY) == 1 && sends(GZ_KIND_READY) == 0 && saves(GZ_REC_READY_SENT) == 1 &&
          !gz_lobby_member_accepted(&m, chk2, 1, NULL));
    /* after the freeze, opening the gate readies for the frozen version, plainly (no check named) */
    GATE = 1;
    acts_reset();
    CHECK(gz_lobby_member_gate_opened(&m, &A.l) == GZ_OK && sends(GZ_KIND_READY) == 1 && last_sent(GZ_KIND_READY, &g) &&
          !g.has_check_id && g.version == 1 && m.frozen && m.ready);
    /* and the check, asked again now that it is open, is answered */
    CHECK(feed(&m, 1, buf, n) == GZ_OK && sends(GZ_KIND_READY) == 1 && last_sent(GZ_KIND_READY, &g) && g.has_check_id &&
          memcmp(g.check_id, chk2, 32) == 0 && gz_lobby_member_accepted(&m, chk2, 1, NULL));

    /* 6. Ready, the gate closed, and the check it answered over without it
     * (not chosen): the next check finds a Ready seat behind a closed gate.
     * It is answered with the locked unready, saved first; never a ready. */
    GATE = 0;
    k = N_BEGUN;
    acts_reset();
    CHECK(gz_lobby_member_gate_closed(&m, &A.l) == GZ_OK && A.l.count == 0 && m.ready);   /* check 2 in flight */
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_START, chk2, 0, NULL, 2, 4, 0, 0, &HOST);
    /* Not chosen, behind a closed gate: the check is over for this member, so
     * its seat leaves the count at once (the locked unready, saved first). A
     * locked member is never left counted Ready for the host's next check. */
    CHECK(gz_lobby_member_check_in_flight(&m));
    CHECK(feed(&m, 1, buf, n) == GZ_OK && saves(GZ_REC_START_RECEIVED) == 1 && N_BEGUN == k && !m.ready &&
          !gz_lobby_member_check_in_flight(&m) && sends(GZ_KIND_READY) == 0 && sends(GZ_KIND_UNREADY) == 1 &&
          saves(GZ_REC_READY_SENT) == 1 && save_at(GZ_REC_READY_SENT) < send_at(GZ_KIND_UNREADY) &&
          save_at(GZ_REC_START_RECEIVED) < save_at(GZ_REC_READY_SENT) + 1 &&
          notes(GZ_NOTE_LOCKED) == 1 && last_sent(GZ_KIND_UNREADY, &g) && g.reason == 3);
    if (saved(GZ_REC_READY_SENT)) {
        const uint8_t *fv;
        size_t fl;
        CHECK(lt_rec_field(saved(GZ_REC_READY_SENT)->bytes.data, saved(GZ_REC_READY_SENT)->bytes.len, 6, &fv, &fl) && fl == 2 &&
              fv[0] == 0 && fv[1] == 3);
        CHECK(!lt_rec_field(saved(GZ_REC_READY_SENT)->bytes.data, saved(GZ_REC_READY_SENT)->bytes.len, 4, &fv, &fl));
    }
    /* the next check finds the seat locked: "locked" again, nothing saved, no ready */
    memset(chk, 0x74, 32);
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_READY_CHECK, chk, 1, CD2, 0, 0, 0, 0, &HOST);
    CHECK(feed(&m, 1, buf, n) == GZ_OK && sends(GZ_KIND_READY) == 0 && sends(GZ_KIND_UNREADY) == 1 && saves(GZ_REC_READY_SENT) == 1 &&
          !m.ready && last_sent(GZ_KIND_UNREADY, &g) && g.reason == 3);

    /* 7. A restart of a Ready member with no check in flight: its gate is
     * closed at the start, so resume saves the locked unready (nothing can be
     * sent yet); the host learns it when the member comes back */
    GATE = 1;
    journal_free(&J);
    member_new(&m, 1, &MEM[1], SCOPE, 1, &cond);
    m_in(&m, 1, GZ_LIN_CONNECTED);
    CHECK(feed(&m, 1, ob, on) == GZ_OK && m.ready);
    keep(&J);
    GATE = 0;
    member_new(&m2, 1, &MEM[1], SCOPE, 1, &cond);
    for (i = 0; i < J.n; i++) CHECK(gz_lobby_member_restore(&m2, &J.r[i]) == GZ_OK);
    CHECK(m2.ready);
    acts_reset();
    CHECK(gz_lobby_member_resume(&m2, &A.l) == GZ_OK && A.l.count == 3 && A.s[0].kind == GZ_ACTION_CONNECT &&
          A.s[1].kind == GZ_ACTION_SAVE && A.s[2].kind == GZ_ACTION_NOTIFY && A.s[2].u.notify.code == GZ_NOTE_LOCKED &&
          saves(GZ_REC_READY_SENT) == 1 && all_sends() == 0 && !m2.ready && m2.unready_reason == 3);
    CHECK(m_in(&m2, 1, GZ_LIN_CONNECTED) == GZ_OK && sends(GZ_KIND_HELLO) == 1);
    n = status_env(buf, sizeof buf, SCOPE, GZ_LOBBY_OPEN, GZ_SEAT_READY, 1);
    CHECK(feed(&m2, 1, buf, n) == GZ_OK && sends(GZ_KIND_UNREADY) == 1 && last_sent(GZ_KIND_UNREADY, &g) && g.reason == 3);
    /* the same restart with the gate open (member_signing AUTO has none): nothing is withdrawn */
    GATE = 1;
    member_new(&m2, 1, &MEM[1], SCOPE, 1, &cond);
    for (i = 0; i < J.n; i++) CHECK(gz_lobby_member_restore(&m2, &J.r[i]) == GZ_OK);
    acts_reset();
    CHECK(gz_lobby_member_resume(&m2, &A.l) == GZ_OK && A.l.count == 1 && m2.ready);
    member_new(&m2, 1, &MEM[1], SCOPE, 0, &cond);
    for (i = 0; i < J.n; i++) CHECK(gz_lobby_member_restore(&m2, &J.r[i]) == GZ_OK);
    GATE = 0;
    GATE_ASKED = 0;
    acts_reset();
    CHECK(gz_lobby_member_resume(&m2, &A.l) == GZ_OK && A.l.count == 1 && m2.ready && GATE_ASKED == 0);   /* no gate: never asked */

    /* 8. The user's own unready is the user's: an open gate does not ready for them; their word does */
    GATE = 1;
    member_new(&m, 1, &MEM[1], SCOPE, 1, &cond);
    m_in(&m, 1, GZ_LIN_CONNECTED);
    feed(&m, 1, ob, on);
    acts_reset();
    CHECK(gz_lobby_member_unready(&m, &A.l) == GZ_OK && last_sent(GZ_KIND_UNREADY, &g) && g.reason == 2);
    GATE = 0;
    acts_reset();
    CHECK(gz_lobby_member_gate_closed(&m, &A.l) == GZ_OK && A.l.count == 0);     /* not ready: nothing to lock out */
    GATE = 1;
    acts_reset();
    CHECK(gz_lobby_member_gate_opened(&m, &A.l) == GZ_OK && A.l.count == 0 && !m.ready);
    acts_reset();
    CHECK(gz_lobby_member_ready(&m, &A.l) == GZ_OK && sends(GZ_KIND_READY) == 1 && m.ready && !m.user_unready);
    acts_reset();                                       /* ready already: the command is refused, nothing changes */
    CHECK(gz_lobby_member_ready(&m, &A.l) == GZ_OK && note(GZ_NOTE_COMMAND_REFUSED, GZ_CMD_READY, -1) && A.l.count == 1);
    GATE = 1;
    journal_free(&J);
}

/* ------------------------------------------------- the accepted record */

/* Two hand-offs name the same round: every field but `resume`, by content. */
static int same_handoff(const gz_lobby_handoff_t *a, const gz_lobby_handoff_t *b)
{
    if (a->role != b->role || a->outer_len != b->outer_len || a->current_len != b->current_len || a->version != b->version ||
        a->signers != b->signers || a->n_participants != b->n_participants || a->participants != b->participants ||
        a->n_levels != b->n_levels || a->fixed_levels != b->fixed_levels || memcmp(a->levels, b->levels, 8) != 0 ||
        a->k != b->k || a->tree_anchors != b->tree_anchors || a->layer_step != b->layer_step ||
        a->layer_states != b->layer_states || a->min_members != b->min_members || a->start_len != b->start_len ||
        a->budget_end_ms != b->budget_end_ms || a->attempt != b->attempt)
        return 0;
    if (!a->scope || !b->scope || !a->pinned_key || !b->pinned_key || !a->outer || !b->outer || !a->current || !b->current ||
        !a->outer_sig || !b->outer_sig || !a->current_sig || !b->current_sig || !a->current_digest || !b->current_digest ||
        !a->check_id || !b->check_id || !a->terms || !b->terms || !a->values || !b->values || !a->limits || !b->limits)
        return 0;
    if ((a->start_bytes == NULL) != (b->start_bytes == NULL)) return 0;
    return memcmp(a->scope, b->scope, 32) == 0 && memcmp(a->pinned_key, b->pinned_key, 33) == 0 &&
           memcmp(a->outer, b->outer, a->outer_len) == 0 && memcmp(a->current, b->current, a->current_len) == 0 &&
           memcmp(a->outer_sig, b->outer_sig, 64) == 0 && memcmp(a->current_sig, b->current_sig, 64) == 0 &&
           memcmp(a->current_digest, b->current_digest, 32) == 0 && memcmp(a->check_id, b->check_id, 32) == 0 &&
           gz_terms_outer_equal(a->terms, b->terms) && gz_terms_current_equal(a->values, b->values) &&
           memcmp(a->limits, b->limits, sizeof *a->limits) == 0 &&
           (a->start_len == 0 || memcmp(a->start_bytes, b->start_bytes, a->start_len) == 0);
}

/* A member that has the terms, is ready, and has answered check `chk`. */
static void answered(gz_lobby_member_t *m, const gz_lobby_conditions_t *cond, const uint8_t *chk, journal_t *j)
{
    static uint8_t ob[8000];
    uint8_t buf[400];
    size_t on = offer_env(ob, sizeof ob, SCOPE, T1, T1N, T2, T2N, &HOST), n;
    member_new(m, 1, &MEM[1], SCOPE, 0, cond);
    m_in(m, 1, GZ_LIN_CONNECTED);
    CHECK(feed(m, 1, ob, on) == GZ_OK && m->ready);
    if (j) keep(j);
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_READY_CHECK, chk, 1, CD2, 0, 0, 0, 0, &HOST);
    CHECK(feed(m, 1, buf, n) == GZ_OK && m->has_answered && m->frozen);
    if (j) keep(j);
}

static void test_accepted(void)
{
    static gz_lobby_member_t m, m2;
    static journal_t J;
    gz_lobby_conditions_t cond = lt_cond_fits();
    gz_lobby_handoff_t ho, ho2;
    uint8_t a[32], b[32], other[32], buf[400];
    size_t n, i;
    memset(a, 0xa1, 32);
    memset(b, 0xb1, 32);
    memset(other, 0xee, 32);
    cond.min_members = 3;

    /* nothing answered: no */
    member_new(&m, 1, &MEM[1], SCOPE, 0, &cond);
    CHECK(!gz_lobby_member_accepted(&m, a, 1, NULL) && !gz_lobby_member_round_ok(&m));
    /* answered: yes for that check, attempt 1 (0 is read as 1), and the whole hand-off is filled */
    N_BEGUN = N_RESUMED = 0;
    answered(&m, &cond, a, &J);
    CHECK(gz_lobby_member_accepted(&m, a, 1, NULL) && gz_lobby_member_accepted(&m, a, 0, NULL) && gz_lobby_member_round_ok(&m));
    CHECK(!gz_lobby_member_accepted(NULL, a, 1, NULL) && !gz_lobby_member_accepted(&m, NULL, 1, NULL));
    memset(&ho, 0xff, sizeof ho);
    CHECK(gz_lobby_member_accepted(&m, a, 1, &ho));
    /* a proposal that comes without a start: no count, no shape, no start bytes: the count is the proposal's */
    CHECK(ho.role == 1 && ho.resume == 0 && ho.signers == 0 && ho.n_levels == 0 && ho.start_bytes == NULL && ho.start_len == 0 &&
          ho.participants == NULL && ho.n_participants == 0 && ho.budget_end_ms == 0 && ho.attempt == 1);
    CHECK(memcmp(ho.scope, SCOPE, 32) == 0 && memcmp(ho.pinned_key, HOST.key[1].pub, 33) == 0 && ho.outer_len == T1N &&
          memcmp(ho.outer, T1, T1N) == 0 && ho.current_len == T2N && memcmp(ho.current, T2, T2N) == 0 && ho.version == 1 &&
          memcmp(ho.current_digest, CD2, 32) == 0 && memcmp(ho.check_id, a, 32) == 0 && ho.min_members == 3 &&
          ho.limits == &m.cond.limits && ho.terms == &m.terms && ho.values == &m.values && ho.k == 1 && ho.tree_anchors == 1);
    CHECK(lt_verify(NULL, HOST.key[1].pub, SCOPE, ho.outer_sig) && lt_verify(NULL, HOST.key[1].pub, CD2, ho.current_sig));

    /* CONDITION 4: no higher attempt. Until understudies every check has the one attempt */
    CHECK(!gz_lobby_member_accepted(&m, a, 2, NULL) && !gz_lobby_member_accepted(&m, a, 0xffffffffu, &ho2));
    /* CONDITION 1: the newest check answered, and not withdrawn */
    CHECK(!gz_lobby_member_accepted(&m, other, 1, NULL));                        /* a check it never answered */
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_READY_CHECK, b, 1, CD2, 0, 0, 0, 0, &HOST);
    CHECK(feed(&m, 1, buf, n) == GZ_OK && sends(GZ_KIND_READY) == 1);            /* a newer check answered: */
    CHECK(!gz_lobby_member_accepted(&m, a, 1, NULL) && gz_lobby_member_accepted(&m, b, 1, NULL));   /* only the newest */
    acts_reset();
    CHECK(gz_lobby_member_unready(&m, &A.l) == GZ_OK);                           /* withdrawn: */
    CHECK(!gz_lobby_member_accepted(&m, b, 1, NULL) && !gz_lobby_member_accepted(&m, a, 1, NULL));   /* neither */
    acts_reset();
    CHECK(gz_lobby_member_ready(&m, &A.l) == GZ_OK && sends(GZ_KIND_READY) == 1 && m.ready);
    CHECK(!gz_lobby_member_accepted(&m, b, 1, NULL));                            /* ready again, plainly: still no answer to it */
    CHECK(feed(&m, 1, buf, n) == GZ_OK && sends(GZ_KIND_READY) == 1 && gz_lobby_member_accepted(&m, b, 1, NULL));   /* asked again: answered */
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_CANCEL, NULL, 0, NULL, 0, 0, 2, 0, &HOST);
    CHECK(feed(&m, 1, buf, n) == GZ_OK && m.ended && !gz_lobby_member_accepted(&m, b, 1, NULL));   /* the lobby ended */

    /* CONDITION 2: no saved start with role 2 (not chosen) for that attempt */
    answered(&m, &cond, a, NULL);
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_START, a, 0, NULL, 2, 5, 0, 0, &HOST);
    CHECK(gz_lobby_member_accepted(&m, a, 1, NULL));
    CHECK(feed(&m, 1, buf, n) == GZ_OK && saves(GZ_REC_START_RECEIVED) == 1 && N_BEGUN == 0);
    CHECK(!gz_lobby_member_accepted(&m, a, 1, NULL) && !gz_lobby_member_accepted(&m, a, 0, &ho2));
    /* role 1 (chosen): accepted, and the hand-off is exactly what `begin` got for that check */
    journal_free(&J);
    N_BEGUN = 0;
    answered(&m, &cond, a, &J);
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_START, a, 0, NULL, 1, 5, 0, 0, &HOST);
    CHECK(feed(&m, 1, buf, n) == GZ_OK && saves(GZ_REC_START_RECEIVED) == 1 && N_BEGUN == 1);
    keep(&J);
    memset(&ho, 0xff, sizeof ho);
    CHECK(gz_lobby_member_accepted(&m, a, 1, &ho) && same_handoff(&ho, &BEGUN) && BEGUN.resume == 0);
    CHECK(ho.signers == 5 && ho.start_len == n && memcmp(ho.start_bytes, buf, n) == 0 && ho.n_levels == 1 && ho.levels[0] == 3 &&
          ho.fixed_levels == 2 && ho.layer_step == 144 && ho.layer_states == 4 && ho.limits == BEGUN.limits &&
          ho.start_bytes == BEGUN.start_bytes && ho.scope == BEGUN.scope && ho.terms == BEGUN.terms);
    CHECK(gz_lobby_member_accepted(&m, a, 0, &ho2) && same_handoff(&ho, &ho2));
    /* the same after a restart: the record restored says the same, and the resumed `begin` gets the same */
    member_new(&m2, 1, &MEM[1], SCOPE, 0, &cond);
    for (i = 0; i < J.n; i++) CHECK(gz_lobby_member_restore(&m2, &J.r[i]) == GZ_OK);
    CHECK(gz_lobby_member_accepted(&m2, a, 1, &ho2) && same_handoff(&ho, &ho2) && ho2.scope == m2.scope);
    acts_reset();
    CHECK(gz_lobby_member_resume(&m2, &A.l) == GZ_OK && N_BEGUN == 2 && BEGUN.resume == 1 && same_handoff(&ho2, &BEGUN));

    /* CONDITION 3: the attempt is not spent. A Retry for the check spends it... */
    acts_reset();
    CHECK(gz_lobby_member_round_result(&m, GZ_LOBBY_ROUND_RETRY, a, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_STATE) == 1);
    CHECK(!gz_lobby_member_accepted(&m, a, 1, NULL) && !gz_lobby_member_accepted(&m, a, 0, NULL));
    keep(&J);
    member_new(&m2, 1, &MEM[1], SCOPE, 0, &cond);       /* ...and stays spent across a restart: nothing resumes */
    for (i = 0; i < J.n; i++) CHECK(gz_lobby_member_restore(&m2, &J.r[i]) == GZ_OK);
    acts_reset();
    CHECK(!gz_lobby_member_accepted(&m2, a, 1, NULL) && gz_lobby_member_resume(&m2, &A.l) == GZ_OK && N_BEGUN == 2);
    /* ...so does Funding (a saved outcome), and Active after it */
    answered(&m, &cond, a, NULL);
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_START, a, 0, NULL, 1, 5, 0, 0, &HOST);
    CHECK(feed(&m, 1, buf, n) == GZ_OK && gz_lobby_member_accepted(&m, a, 1, NULL));
    acts_reset();
    CHECK(gz_lobby_member_round_result(&m, GZ_LOBBY_ROUND_FUNDING, NULL, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_STATE) == 1);
    CHECK(!gz_lobby_member_accepted(&m, a, 1, NULL));
    acts_reset();
    CHECK(gz_lobby_member_round_result(&m, GZ_LOBBY_ROUND_ACTIVE, NULL, &A.l) == GZ_OK && !gz_lobby_member_accepted(&m, a, 1, NULL));
    /* A Retry spends the check also when the member holds no start for it but
     * its answer is to that check (the proposal came without a start): saved,
     * with the check it names; the answer is gone, live and after a restart */
    journal_free(&J);
    answered(&m, &cond, a, &J);
    CHECK(m.start_len == 0 && gz_lobby_member_accepted(&m, a, 1, NULL));
    acts_reset();
    CHECK(gz_lobby_member_round_result(&m, GZ_LOBBY_ROUND_RETRY, other, &A.l) == GZ_OK && A.l.count == 0 &&
          gz_lobby_member_accepted(&m, a, 1, NULL));                             /* another check's Retry: ignored */
    acts_reset();
    CHECK(gz_lobby_member_round_result(&m, GZ_LOBBY_ROUND_RETRY, a, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_STATE) == 1 &&
          A.l.count == 1 && !gz_lobby_member_accepted(&m, a, 1, NULL) && !m.has_answered && m.ready);
    if (saved(GZ_REC_LOBBY_STATE)) {
        uint8_t want[80];
        size_t wn = lt_rec_state(want, sizeof want, SCOPE, GZ_LOBBY_OPEN, a);
        CHECK(saved(GZ_REC_LOBBY_STATE)->bytes.len == wn && memcmp(saved(GZ_REC_LOBBY_STATE)->bytes.data, want, wn) == 0);
    }
    keep(&J);
    acts_reset();                                       /* spent: a second Retry for it saves nothing */
    CHECK(gz_lobby_member_round_result(&m, GZ_LOBBY_ROUND_RETRY, a, &A.l) == GZ_OK && A.l.count == 0);
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_START, a, 0, NULL, 1, 5, 0, 0, &HOST);
    N_BEGUN = 0;                                        /* a start for the spent check, resent by the host: ignored */
    CHECK(feed(&m, 1, buf, n) == GZ_OK && A.l.count == 0 && N_BEGUN == 0);
    member_new(&m2, 1, &MEM[1], SCOPE, 0, &cond);
    for (i = 0; i < J.n; i++) CHECK(gz_lobby_member_restore(&m2, &J.r[i]) == GZ_OK);
    CHECK(!gz_lobby_member_accepted(&m2, a, 1, NULL) && !m2.has_answered && m2.ready);
    /* the next check is a new attempt: answered and accepted */
    n = host_env(buf, sizeof buf, SCOPE, GZ_KIND_READY_CHECK, b, 1, CD2, 0, 0, 0, 0, &HOST);
    CHECK(feed(&m, 1, buf, n) == GZ_OK && sends(GZ_KIND_READY) == 1 && gz_lobby_member_accepted(&m, b, 1, NULL) &&
          !gz_lobby_member_accepted(&m, a, 1, NULL));
    journal_free(&J);
}

/* ------------------------------- a member's end survives a restart */

/* Every record of the last list, appended to a small journal. */
typedef struct { uint32_t type; size_t n; uint8_t b[GZ_LOBBY_REC_MAX_OPENED]; } kept_t;
static kept_t KEPT[8];
static size_t N_KEPT;

static void keep_last(void)
{
    size_t i, j;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_SAVE)
            for (j = 0; j < A.s[i].u.save.n_records && N_KEPT < 8; j++) {
                const gz_record_t *r = &A.s[i].u.save.records[j];
                CHECK(r->bytes.len <= sizeof KEPT[0].b);
                KEPT[N_KEPT].type = r->type;
                KEPT[N_KEPT].n = r->bytes.len;
                memcpy(KEPT[N_KEPT].b, r->bytes.data, r->bytes.len);
                N_KEPT++;
            }
}

static int restore_kept(gz_lobby_member_t *m)
{
    size_t i;
    for (i = 0; i < N_KEPT; i++) {
        gz_record_t r;
        r.type = KEPT[i].type;
        r.bytes.data = KEPT[i].b;
        r.bytes.len = KEPT[i].n;
        if (gz_lobby_member_restore(m, &r) != GZ_OK) return 0;
    }
    return 1;
}

/* A member removed by the host, and one whose host's terms were refused
 * before any seat, are over for good: the end is saved before anything shows
 * it, and a restarted member neither asks, joins nor readies again. */
static void test_ended_saved(void)
{
    static gz_lobby_member_t m, m2;
    static uint8_t ob[8000], rb[GZ_LOBBY_REC_MAX_ENDED + 8];
    gz_lobby_conditions_t cond = lt_cond_fits();
    uint8_t buf[600], v;
    size_t n, on;
    gz_record_t r;
    static lt_signer_t other;
    memset(&other, 0, sizeof other);
    lt_key(&other.key[1], "another host");

    CLOCK = W_T0 - 3600000;
    GATE = 1;
    N_KEPT = 0;
    member_new(&m, 1, &MEM[1], SCOPE, 0, &cond);
    m_in(&m, 1, GZ_LIN_CONNECTED);
    on = offer_env(ob, sizeof ob, SCOPE, T1, T1N, T2, T2N, &HOST);
    CHECK(feed(&m, 1, ob, on) == GZ_OK && m.joined && m.ready && saves(GZ_REC_JOINED) == 1);
    keep_last();
    /* removed: saved first, told once, final */
    n = status_env(buf, sizeof buf, SCOPE, GZ_LOBBY_OPEN, GZ_SEAT_REMOVED, 1);
    CHECK(feed(&m, 1, buf, n) == GZ_OK && saves(GZ_REC_LOBBY_ENDED) == 1 && notes(GZ_NOTE_ENDED) == 1 &&
          all_sends() == 0 && m.ended && !m.ready && !m.left && !m.never_joined &&
          m.end_how == GZ_LOBBY_END_REMOVED);
    keep_last();
    CHECK(feed(&m, 1, buf, n) == GZ_OK && A.l.count == 0);            /* told again: nothing more */
    CHECK(feed(&m, 1, ob, on) == GZ_OK && A.l.count == 0);
    /* the restart: still over, for the same reason; it asks nothing and joins nothing */
    member_new(&m2, 1, &MEM[1], SCOPE, 0, &cond);
    CHECK(restore_kept(&m2) && m2.ended && !m2.ready && !m2.left && !m2.never_joined && m2.joined &&
          m2.end_how == GZ_LOBBY_END_REMOVED);
    CHECK(m_in(&m2, 1, GZ_LIN_CONNECTED) == GZ_OK && all_sends() == 0 && !any_save());
    CHECK(feed(&m2, 1, ob, on) == GZ_OK && A.l.count == 0);
    acts_reset();
    CHECK(gz_lobby_member_ready(&m2, &A.l) == GZ_OK && note(GZ_NOTE_COMMAND_REFUSED, GZ_CMD_READY, -1) && !any_save());
    /* a `how` this version does not know, or one beside a cancel's state, is not read */
    if (N_KEPT) {
        const kept_t *e = &KEPT[N_KEPT - 1];
        r.type = GZ_REC_LOBBY_ENDED;
        r.bytes.data = rb;
        v = 4;
        r.bytes.len = lt_rec_with(e->b, e->n, 10, &v, 1, rb, sizeof rb);
        member_new(&m2, 1, &MEM[1], SCOPE, 0, &cond);
        CHECK(e->type == GZ_REC_LOBBY_ENDED && r.bytes.len > 0 && gz_lobby_member_restore(&m2, &r) == GZ_ERR_CORRUPT);
        v = 0;
        r.bytes.len = lt_rec_with(e->b, e->n, 10, &v, 1, rb, sizeof rb);
        CHECK(r.bytes.len > 0 && gz_lobby_member_restore(&m2, &r) == GZ_ERR_CORRUPT);
        v = GZ_LOBBY_CANCELLED;
        r.bytes.len = lt_rec_with(e->b, e->n, 4, &v, 1, rb, sizeof rb);
        CHECK(r.bytes.len > 0 && gz_lobby_member_restore(&m2, &r) == GZ_ERR_CORRUPT);
    }

    /* terms refused before any seat: the member never got in, and stays out */
    N_KEPT = 0;
    member_new(&m, 2, &MEM[2], SCOPE, 0, &cond);
    m_in(&m, 2, GZ_LIN_CONNECTED);
    on = offer_env(ob, sizeof ob, SCOPE, T1, T1N, T2, T2N, &other);   /* not the pinned key */
    CHECK(feed(&m, 2, ob, on) == GZ_OK && saves(GZ_REC_LOBBY_ENDED) == 1 && save_at(GZ_REC_LOBBY_ENDED) == 0 &&
          m.ended && m.never_joined && m.end_how == GZ_LOBBY_END_BAD_TERMS && all_sends() == 0);
    keep_last();
    member_new(&m2, 2, &MEM[2], SCOPE, 0, &cond);
    CHECK(N_KEPT == 1 && restore_kept(&m2) && m2.ended && m2.never_joined && !m2.joined &&
          m2.end_how == GZ_LOBBY_END_BAD_TERMS);
    CHECK(m_in(&m2, 2, GZ_LIN_CONNECTED) == GZ_OK && all_sends() == 0);
    on = offer_env(ob, sizeof ob, SCOPE, T1, T1N, T2, T2N, &HOST);    /* an honest offer later: too late */
    CHECK(feed(&m2, 2, ob, on) == GZ_OK && A.l.count == 0 && !m2.joined);
}

int main(void)
{
    int i;
    char label[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    memset(&HOST, 0, sizeof HOST);
    memset(PADB, 0x20, sizeof PADB);
    lt_key(&HOST.key[1], "host");
    lt_key(&HOST.key[3], "host factory");
    for (i = 0; i < NM; i++) {
        snprintf(label, sizeof label, "member %d contribution", i);
        lt_key(&MEM[i].key[2], label);
        snprintf(label, sizeof label, "member %d factory", i);
        lt_key(&MEM[i].key[3], label);
    }
    T1N = lt_unhex(LT_T1, T1, sizeof T1);
    T2N = lt_unhex(LT_T2, T2, sizeof T2);
    lt_outer(T1, T1N, &T1O);
    gz_terms_outer_digest(T1, T1N, SCOPE);
    gz_terms_current_digest(T2, T2N, CD2);
    test_helpers();
    test_no_key();
    test_largest();
    test_gate();
    test_accepted();
    test_ended_saved();
    CHECK(OVERSIZE == 0);
    return check_done();
}
