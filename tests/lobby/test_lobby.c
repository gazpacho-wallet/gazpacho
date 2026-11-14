/* Lobby scenarios (messages.md 12, tests 15 to 26 and 56; terms.md 12, tests
 * 10 to 14 and 20), the Slice 1 "member whose conditions are not met refuses"
 * condition, standbys, removal, the deadline. */
#include "../check.h"
#include "world.h"
#include "../../core/lobby/lobby_internal.h"

/* ------------------------------------------------------------ helpers */

typedef struct { gz_action_list_t l; gz_action_t s[256]; uint8_t b[1 << 18]; } acts_t;
static acts_t A;

static void acts_reset(void) { gz_action_list_init(&A.l, A.s, 256, A.b, sizeof A.b); }

static int kind_of(const gz_action_t *a)
{
    gz_lobby_msg_t m;
    if (a->kind != GZ_ACTION_SEND) return -1;
    if (a->u.send.bytes.len >= 2 && a->u.send.bytes.data[0] == 0 && a->u.send.bytes.data[1] == 1) return 1; /* warning */
    return gz_lobby_decode(a->u.send.bytes.data, a->u.send.bytes.len, &m) == GZ_DEC_OK ? m.kind : -2;
}

static int sends(int kind)
{
    size_t i;
    int c = 0;
    for (i = 0; i < A.l.count; i++) c += kind_of(&A.s[i]) == kind;
    return c;
}

static int saves(uint32_t type)
{
    size_t i, j;
    int c = 0;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_SAVE)
            for (j = 0; j < A.s[i].u.save.n_records; j++) c += A.s[i].u.save.records[j].type == type;
    return c;
}

static int any_save(void)
{
    size_t i;
    for (i = 0; i < A.l.count; i++) if (A.s[i].kind == GZ_ACTION_SAVE) return 1;
    return 0;
}

static int note(uint32_t code, int a, int b)
{
    size_t i;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_NOTIFY && A.s[i].u.notify.code == code &&
            (a < 0 || A.s[i].u.notify.bytes.data[0] == a) && (b < 0 || A.s[i].u.notify.bytes.data[1] == b))
            return 1;
    return 0;
}

/* A user command refused now: GZ_OK, nothing changed, the notice (lobby.h ERRORS). */
static int refused(int cmd) { return note(GZ_NOTE_COMMAND_REFUSED, cmd, -1); }

static int timers(uint64_t id)
{
    size_t i;
    int c = 0;
    for (i = 0; i < A.l.count; i++)
        c += A.s[i].kind == GZ_ACTION_SET_TIMER && A.s[i].u.set_timer.timer_id == id;
    return c;
}

/* The last send of `kind`, decoded. */
static int last_sent(int kind, gz_lobby_msg_t *m, const uint8_t **raw, size_t *n)
{
    size_t i;
    int found = 0;
    for (i = 0; i < A.l.count; i++)
        if (kind_of(&A.s[i]) == kind) {
            gz_lobby_decode(A.s[i].u.send.bytes.data, A.s[i].u.send.bytes.len, m);
            if (raw) { *raw = A.s[i].u.send.bytes.data; *n = A.s[i].u.send.bytes.len; }
            found = 1;
        }
    return found;
}

/* The record that justifies a send is listed before it: some save holding a
 * record of `type` comes before the first send of `kind`, which exists. */
static int before(int kind, uint32_t type)
{
    size_t i, j;
    int saved = 0;
    for (i = 0; i < A.l.count; i++) {
        if (kind_of(&A.s[i]) == kind) return saved;
        if (A.s[i].kind == GZ_ACTION_SAVE)
            for (j = 0; j < A.s[i].u.save.n_records; j++) saved |= A.s[i].u.save.records[j].type == type;
    }
    return 0;
}

static lt_signer_t HOST, OTHER, M1;
static uint8_t T1[512], T2[128], T3[128], SCOPE[32];
static size_t T1N, T2N, T3N;
static gz_terms_outer_t T1O;
static uint64_t CLOCK = W_T0;
static uint64_t c_now(void *ctx) { (void)ctx; return CLOCK; }
static uint8_t RAND_NEXT = 0x5a;
static void c_rand(void *ctx, gz_random_purpose_t p, uint8_t *o, size_t n) { (void)ctx; (void)p; memset(o, RAND_NEXT++, n); }

static gz_ports_t ports(void)
{
    gz_ports_t p;
    p.random.fill = c_rand; p.random.ctx = NULL;
    p.clock.now_ms = c_now; p.clock.ctx = NULL;
    return p;
}

static size_t offer(uint8_t *buf, size_t cap, const uint8_t *scope, const uint8_t *o, size_t on,
                    const uint8_t *c, size_t cn, lt_signer_t *signer)
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

static gz_status_t feed(gz_lobby_member_t *m, const uint8_t *b, size_t n)
{
    gz_lobby_input_t in;
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_MESSAGE; in.peer_id = W_HOST_PEER; in.bytes = b; in.len = n;
    acts_reset();
    return gz_lobby_member_handle(m, &in, &A.l);
}

static void member_up(gz_lobby_member_t *m, const gz_lobby_conditions_t *cond)
{
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(&M1);
    gz_lobby_input_t in;
    gz_lobby_member_init(m, &p, &cr, NULL, cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1);
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_CONNECTED; in.peer_id = W_HOST_PEER; in.peer_key = HOST.key[1].pub;
    acts_reset();
    gz_lobby_member_handle(m, &in, &A.l);
}

static size_t host_msg(uint8_t *buf, size_t cap, uint16_t kind, const uint8_t *check, uint32_t version,
                       const uint8_t *digest, uint32_t window, uint8_t role, lt_signer_t *signer)
{
    gz_lobby_enc_t e;
    gz_lobby_crypto_t cr = lt_crypto(signer);
    gz_lobby_enc_start(&e, buf, cap, kind, SCOPE);
    if (kind == GZ_KIND_READY_CHECK) {
        gz_lobby_enc_record(&e, 2, check, 32);
        gz_lobby_enc_u32(&e, 4, version);
        gz_lobby_enc_record(&e, 6, digest, 32);
        gz_lobby_enc_u32(&e, 8, window);
    } else if (kind == GZ_KIND_START) {
        gz_lobby_enc_record(&e, 2, check, 32);
        gz_lobby_enc_u8(&e, 4, role);
        gz_lobby_enc_u16(&e, 6, 4);
    } else {
        gz_lobby_enc_u16(&e, 2, (uint16_t)version);
    }
    return gz_lobby_enc_sign(&e, &cr, GZ_LOBBY_KEY_HOST);
}

/* The two pieces of evidence in the HOST_FAULT record of the last list, and
 * the reason of the leave that followed. 1 if both were found. */
static int fault_evidence(const uint8_t **a, size_t *an, const uint8_t **b, size_t *bn, uint16_t *leave_reason)
{
    size_t i, j, at = 1;
    gz_lobby_msg_t g;
    int found = 0;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_SAVE)
            for (j = 0; j < A.s[i].u.save.n_records; j++)
                if (A.s[i].u.save.records[j].type == GZ_REC_HOST_FAULT) {
                    const uint8_t *e = A.s[i].u.save.records[j].bytes.data;
                    size_t el = A.s[i].u.save.records[j].bytes.len;
                    found = gz_la_get_blob(e, el, &at, a, an) && gz_la_get_blob(e, el, &at, b, bn) && at == el;
                }
    *leave_reason = last_sent(GZ_KIND_LEAVE, &g, NULL, NULL) && g.has_reason ? g.reason : 0;
    return found;
}

/* Fill this much stack below the caller with 0xa5 (see the leave test). */
static int seated_notes(const uint8_t *key, int seated);
static void poison_stack(void)
{
    volatile uint8_t b[65536];
    size_t i;
    for (i = 0; i < sizeof b; i++) b[i] = 0xa5;
}

/* --------------------------------------------- member, hostile host */

static void test_member_hostile(void)
{
    static gz_lobby_member_t m;
    static uint8_t buf[8000], b2[8000];
    gz_lobby_conditions_t cond = lt_cond_fits();
    gz_terms_outer_t o = T1O;
    uint8_t x[600], cd2[32], cd3[32], check[32];
    size_t n, xn;
    gz_lobby_msg_t g;

    gz_terms_current_digest(T2, T2N, cd2);
    gz_terms_current_digest(T3, T3N, cd3);
    /* hello first */
    member_up(&m, &cond);
    CHECK(sends(GZ_KIND_HELLO) == 1);
    /* test 18: other key; scope not the outer digest; mainnet; value out of range */
    n = offer(buf, sizeof buf, SCOPE, T1, T1N, T2, T2N, &OTHER);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(1) == 1 && !any_save() && !m.have_terms);
    {
        uint8_t sc[32];
        memcpy(sc, SCOPE, 32); sc[0] ^= 1;
        n = offer(buf, sizeof buf, sc, T1, T1N, T2, T2N, &HOST);
        CHECK(feed(&m, buf, n) == GZ_OK && sends(1) == 0 && !any_save());   /* another lobby: ignored */
    }
    memcpy(o.chain, T1O.chain, 32); o.chain[0] ^= 0xff;                     /* not signet */
    xn = gz_terms_encode_outer(&o, x, sizeof x);
    {
        uint8_t sc[32], cur[128];
        gz_terms_current_t v;
        size_t cn;
        gz_terms_outer_digest(x, xn, sc);
        lt_current(T2, T2N, &T1O, SCOPE, &v);
        memcpy(v.outer_digest, sc, 32);
        cn = gz_terms_encode_current(&v, cur, sizeof cur);
        member_up(&m, &cond);
        memcpy(m.scope, sc, 32);
        n = offer(buf, sizeof buf, sc, x, xn, cur, cn, &HOST);
        CHECK(feed(&m, buf, n) == GZ_OK && sends(1) == 1 && !any_save());
    }
    member_up(&m, &cond);
    {
        uint8_t t5[128];
        size_t t5n = lt_unhex("022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4"
                              "24f2040400000003400800000000000007d1420800000000000003e844080000"
                              "0000000003e8", t5, sizeof t5);
        n = offer(buf, sizeof buf, SCOPE, T1, T1N, t5, t5n, &HOST);
        CHECK(feed(&m, buf, n) == GZ_OK && sends(1) == 1 && !any_save());
    }
    /* honest offer: join and ready, saved first */
    n = offer(buf, sizeof buf, SCOPE, T1, T1N, T2, T2N, &HOST);
    CHECK(feed(&m, buf, n) == GZ_OK);
    CHECK(saves(GZ_REC_TERMS_RECEIVED) == 1 && saves(GZ_REC_JOINED) == 1 && saves(GZ_REC_READY_SENT) == 1);
    CHECK(sends(GZ_KIND_JOIN) == 1 && sends(GZ_KIND_READY) == 1);
    CHECK(before(GZ_KIND_JOIN, GZ_REC_JOINED) && before(GZ_KIND_JOIN, GZ_REC_TERMS_RECEIVED) && before(GZ_KIND_READY, GZ_REC_READY_SENT));
    CHECK(feed(&m, buf, n) == GZ_OK && A.l.count == 0);                     /* duplicate: ignored */
    /* test 10 / 19: two records under version 2 */
    {
        uint8_t c2[128];
        size_t c2n;
        gz_terms_current_t v;
        n = offer(buf, sizeof buf, SCOPE, T1, T1N, T3, T3N, &HOST);
        CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_READY) == 1 && saves(GZ_REC_TERMS_RECEIVED) == 1);
        n = offer(buf, sizeof buf, SCOPE, T1, T1N, T2, T2N, &HOST);           /* version 1 again */
        CHECK(feed(&m, buf, n) == GZ_OK && A.l.count == 0);
        lt_current(T3, T3N, &T1O, SCOPE, &v);
        v.val[1].value = 999;
        c2n = gz_terms_encode_current(&v, c2, sizeof c2);
        n = offer(buf, sizeof buf, SCOPE, T1, T1N, c2, c2n, &HOST);
        CHECK(feed(&m, buf, n) == GZ_OK && saves(GZ_REC_HOST_FAULT) == 1 && sends(GZ_KIND_LEAVE) == 1);
        {
            gz_lobby_msg_t lg;
            CHECK(last_sent(GZ_KIND_LEAVE, &lg, NULL, NULL) && lg.has_reason && lg.reason == 3);   /* host fault seen */
        }
        CHECK(note(GZ_NOTE_HOST_FAULT, GZ_FAULT_TWO_VALUES, -1) && before(GZ_KIND_LEAVE, GZ_REC_HOST_FAULT) && m.ended);
        /* the evidence: both records, each with a valid host signature */
        {
            size_t i, j;
            for (i = 0; i < A.l.count; i++)
                if (A.s[i].kind == GZ_ACTION_SAVE)
                    for (j = 0; j < A.s[i].u.save.n_records; j++)
                        if (A.s[i].u.save.records[j].type == GZ_REC_HOST_FAULT) {
                            const uint8_t *e = A.s[i].u.save.records[j].bytes.data, *ra, *rb;
                            size_t at = 1, an, bn;
                            uint8_t d1[32], d2[32];
                            CHECK(gz_la_get_blob(e, A.s[i].u.save.records[j].bytes.len, &at, &ra, &an));
                            CHECK(gz_la_get_blob(e, A.s[i].u.save.records[j].bytes.len, &at, &rb, &bn));
                            gz_terms_current_digest(ra, an - 64, d1);
                            gz_terms_current_digest(rb, bn - 64, d2);
                            CHECK(lt_verify(NULL, HOST.key[1].pub, d1, ra + an - 64));
                            CHECK(lt_verify(NULL, HOST.key[1].pub, d2, rb + bn - 64));
                            CHECK(memcmp(d1, d2, 32) != 0);
                        }
        }
        CHECK(feed(&m, buf, n) == GZ_OK && A.l.count == 0);                 /* ended: nothing more */
    }
    /* tests 20, 21, 26: ready checks */
    member_up(&m, &cond);
    n = offer(buf, sizeof buf, SCOPE, T1, T1N, T2, T2N, &HOST);
    feed(&m, buf, n);
    memset(check, 7, 32);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, check, 2, cd3, 30000, 0, &HOST);   /* not accepted yet */
    CHECK(feed(&m, x, xn) == GZ_OK && sends(GZ_KIND_READY) == 0 && sends(GZ_KIND_HELLO) == 1 && !any_save());
    n = offer(b2, sizeof b2, SCOPE, T1, T1N, T3, T3N, &HOST);
    CHECK(feed(&m, b2, n) == GZ_OK && saves(GZ_REC_FREEZE) == 1);         /* the waiting check answered */
    CHECK(last_sent(GZ_KIND_READY, &g, NULL, NULL) && g.has_check_id && g.version == 2 && memcmp(g.check_id, check, 32) == 0);
    CHECK(m.frozen && m.frozen_version == 2);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, check, 2, cd3, 30000, 0, &HOST);
    {
        const uint8_t *r1; size_t r1n;
        uint8_t keep[300]; size_t keepn;
        last_sent(GZ_KIND_READY, &g, &r1, &r1n);
        memcpy(keep, r1, r1n); keepn = r1n;
        feed(&m, b2, n);
        CHECK(feed(&m, x, xn) == GZ_OK && last_sent(GZ_KIND_READY, &g, &r1, &r1n) && r1n == keepn &&
              memcmp(r1, keep, r1n) == 0 && !any_save());               /* the same saved bytes */
    }
    CHECK(feed(&m, x, xn - 1) == GZ_OK && sends(1) == 1);                   /* malformed: refused */
    {   /* a start for a check it did not answer: ignored; for the answered one: saved */
        uint8_t other[32], st[200];
        size_t sn;
        memset(other, 8, 32);
        sn = host_msg(st, sizeof st, GZ_KIND_START, other, 0, NULL, 0, 1, &HOST);
        CHECK(feed(&m, st, sn) == GZ_OK && A.l.count == 0);
        sn = host_msg(st, sizeof st, GZ_KIND_START, check, 0, NULL, 0, 1, &OTHER);
        CHECK(feed(&m, st, sn) == GZ_OK && sends(1) == 1 && !any_save());   /* forged */
        sn = host_msg(st, sizeof st, GZ_KIND_START, check, 0, NULL, 0, 1, &HOST);
        CHECK(feed(&m, st, sn) == GZ_OK && saves(GZ_REC_START_RECEIVED) == 1 && note(GZ_NOTE_STARTED, 1, -1));
        CHECK(feed(&m, st, sn) == GZ_OK && A.l.count == 0);                 /* duplicate */
    }
    /* test 20: a new version after the freeze */
    {
        uint8_t c4[128];
        size_t c4n;
        gz_terms_current_t v;
        lt_current(T3, T3N, &T1O, SCOPE, &v);
        v.version = 3;
        c4n = gz_terms_encode_current(&v, c4, sizeof c4);
        n = offer(buf, sizeof buf, SCOPE, T1, T1N, c4, c4n, &HOST);
        CHECK(feed(&m, buf, n) == GZ_OK && saves(GZ_REC_HOST_FAULT) == 1 && sends(GZ_KIND_LEAVE) == 1);
        CHECK(note(GZ_NOTE_HOST_FAULT, GZ_FAULT_AFTER_FREEZE, -1));
        {   /* the evidence: the frozen record and the new one, each with the host's signature */
            const uint8_t *ea, *eb;
            size_t ean, ebn;
            uint16_t why;
            uint8_t d1[32], d2[32];
            CHECK(fault_evidence(&ea, &ean, &eb, &ebn, &why) && why == 3);
            CHECK(ean == T3N + 64 && memcmp(ea, T3, T3N) == 0 && ebn == c4n + 64 && memcmp(eb, c4, c4n) == 0);
            gz_terms_current_digest(ea, ean - 64, d1);
            gz_terms_current_digest(eb, ebn - 64, d2);
            CHECK(lt_verify(NULL, HOST.key[1].pub, d1, ea + ean - 64) && lt_verify(NULL, HOST.key[1].pub, d2, eb + ebn - 64));
        }
    }
    /* a ready check at other values after the freeze: fault */
    member_up(&m, &cond);
    feed(&m, b2, n = offer(b2, sizeof b2, SCOPE, T1, T1N, T3, T3N, &HOST));
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, check, 2, cd3, 30000, 0, &HOST);
    feed(&m, x, xn);
    memset(check, 9, 32);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, check, 1, cd2, 30000, 0, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && saves(GZ_REC_HOST_FAULT) == 1 && sends(GZ_KIND_LEAVE) == 1);
    {   /* evidence: frozen digest and version, then the check's */
        const uint8_t *ea, *eb;
        size_t ean, ebn;
        uint16_t why;
        CHECK(fault_evidence(&ea, &ean, &eb, &ebn, &why) && why == 3 && ean == 36 && ebn == 36);
        CHECK(memcmp(ea, cd3, 32) == 0 && ea[35] == 2 && memcmp(eb, cd2, 32) == 0 && eb[35] == 1);
    }
    /* the frozen version again but another digest: a fault too */
    member_up(&m, &cond);
    feed(&m, b2, n);
    memset(check, 7, 32);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, check, 2, cd3, 30000, 0, &HOST);
    feed(&m, x, xn);
    memset(check, 10, 32);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, check, 2, cd2, 30000, 0, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && saves(GZ_REC_HOST_FAULT) == 1 && sends(GZ_KIND_LEAVE) == 1);
    /* not frozen: the latest version with another digest is not answered; terms are fetched */
    member_up(&m, &cond);
    feed(&m, b2, n);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, check, 2, cd2, 30000, 0, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && sends(GZ_KIND_READY) == 0 && sends(GZ_KIND_HELLO) == 1 && !any_save());
    /* a member that only fits now joins without readying, and answers a check
     * whose values fit: the check is the freeze, after which they are fixed
     * (terms.md 9; review A, S2). Values that do not fit are not answered. */
    {
        gz_lobby_conditions_t c2 = cond;
        LT_ADJ(c2, 0) = 1000;
        member_up(&m, &c2);
        n = offer(buf, sizeof buf, SCOPE, T1, T1N, T2, T2N, &HOST);
        CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_JOIN) == 1 && sends(GZ_KIND_READY) == 0 && m.joined && !m.ready);
        xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, check, 1, cd2, 30000, 0, &HOST);
        CHECK(feed(&m, x, xn) == GZ_OK && sends(GZ_KIND_READY) == 1 && saves(GZ_REC_FREEZE) == 1 && m.frozen);
        CHECK(before(GZ_KIND_READY, GZ_REC_FREEZE));
        LT_ADJ(c2, 0) = 499;                                      /* 500 now: does not fit */
        member_up(&m, &c2);
        feed(&m, buf, n);
        CHECK(!m.joined && feed(&m, x, xn) == GZ_OK && A.l.count == 0);
        n = offer(b2, sizeof b2, SCOPE, T1, T1N, T3, T3N, &HOST);   /* restore b2 for what follows */
    }
    /* a check whose window is not the terms' */
    member_up(&m, &cond);
    feed(&m, b2, n);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, check, 2, cd3, 29999, 0, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && sends(1) == 1 && sends(GZ_KIND_READY) == 0);
    /* cancel: saved, then the end is reported */
    member_up(&m, &cond);
    feed(&m, b2, n);
    xn = host_msg(x, sizeof x, GZ_KIND_CANCEL, NULL, 2, NULL, 0, 0, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && saves(GZ_REC_LOBBY_ENDED) == 1 && note(GZ_NOTE_ENDED, GZ_LOBBY_CANCELLED, -1));
    /* messages a member never accepts */
    member_up(&m, &cond);
    {
        gz_lobby_enc_t e;
        gz_lobby_enc_start(&e, x, sizeof x, GZ_KIND_HELLO, SCOPE);
        CHECK(feed(&m, x, gz_lobby_enc_done(&e)) == GZ_OK && sends(1) == 1);
    }
    /* a connection to another key than the pinned one */
    {
        gz_lobby_input_t in;
        memset(&in, 0, sizeof in);
        in.kind = GZ_LIN_CONNECTED; in.peer_id = 5; in.peer_key = OTHER.key[1].pub;
        acts_reset();
        CHECK(gz_lobby_member_handle(&m, &in, &A.l) == GZ_OK && note(GZ_NOTE_CLOSE, -1, -1) && sends(1) == 1);
    }
}

/* T6 and terms.md test 14 on the member alone. */
static void test_member_classes(void)
{
    static gz_lobby_member_t m;
    static uint8_t buf[8000];
    gz_lobby_conditions_t cond = lt_cond_fits();
    size_t n;
    LT_ADJ(cond, 0) = 1000;
    member_up(&m, &cond);
    n = offer(buf, sizeof buf, SCOPE, T1, T1N, T2, T2N, &HOST);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_JOIN) == 1 && sends(GZ_KIND_READY) == 0 &&
          note(GZ_NOTE_REFUSED, GZ_FIT_NOW, 64) && saves(GZ_REC_JOINED) == 1 && saves(GZ_REC_READY_SENT) == 0);
    cond.current_only = 1;
    member_up(&m, &cond);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_JOIN) == 1 && sends(GZ_KIND_READY) == 1);
    n = offer(buf, sizeof buf, SCOPE, T1, T1N, T3, T3N, &HOST);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_UNREADY) == 1 && note(GZ_NOTE_UNREADY, GZ_FIT_NO, 64));
    {
        gz_lobby_msg_t g;
        CHECK(last_sent(GZ_KIND_UNREADY, &g, NULL, NULL) && g.has_reason && g.reason == 1);   /* conditions */
    }
    CHECK(sends(GZ_KIND_READY) == 0 && saves(GZ_REC_READY_SENT) == 1 && saves(GZ_REC_TERMS_RECEIVED) == 0);
    {   /* the same refusal is told once; told again after the values fitted in between */
        uint8_t c5[128], ob[8000];
        size_t c5n, on;
        gz_terms_current_t v;
        lt_current(T3, T3N, &T1O, SCOPE, &v);
        v.version = 3; v.val[0].value = 1600;
        c5n = gz_terms_encode_current(&v, c5, sizeof c5);
        on = offer(ob, sizeof ob, SCOPE, T1, T1N, c5, c5n, &HOST);
        CHECK(feed(&m, ob, on) == GZ_OK && !note(GZ_NOTE_REFUSED, -1, -1) && !note(GZ_NOTE_UNREADY, -1, -1) && !any_save());
        v.version = 4; v.val[0].value = 900;
        c5n = gz_terms_encode_current(&v, c5, sizeof c5);
        on = offer(ob, sizeof ob, SCOPE, T1, T1N, c5, c5n, &HOST);
        CHECK(feed(&m, ob, on) == GZ_OK && sends(GZ_KIND_READY) == 1);   /* fits now: ready again */
        v.version = 5; v.val[0].value = 1700;
        c5n = gz_terms_encode_current(&v, c5, sizeof c5);
        on = offer(ob, sizeof ob, SCOPE, T1, T1N, c5, c5n, &HOST);
        CHECK(feed(&m, ob, on) == GZ_OK && sends(GZ_KIND_UNREADY) == 1 && note(GZ_NOTE_UNREADY, GZ_FIT_NO, 64));
        v.version = 6; v.val[0].value = 1800;                          /* failing again, the same way: quiet */
        c5n = gz_terms_encode_current(&v, c5, sizeof c5);
        on = offer(ob, sizeof ob, SCOPE, T1, T1N, c5, c5n, &HOST);
        CHECK(feed(&m, ob, on) == GZ_OK && A.l.count == 0);
        {   /* and a check at these values, which fail its conditions, is not answered */
            uint8_t xc[300], ck[32], d6[32];
            size_t xcn;
            memset(ck, 0x66, 32);
            gz_terms_current_digest(c5, c5n, d6);
            xcn = host_msg(xc, sizeof xc, GZ_KIND_READY_CHECK, ck, 6, d6, 30000, 0, &HOST);
            CHECK(feed(&m, xc, xcn) == GZ_OK && sends(GZ_KIND_READY) == 0 && !any_save());
        }
    }
    {   /* unready by its conditions, then ready again at the same version when they loosen */
        gz_lobby_conditions_t c3 = cond;
        LT_ADJ(c3, 0) = 2000;
        acts_reset();
        CHECK(gz_lobby_member_set_conditions(&m, &c3, &A.l) == GZ_OK && sends(GZ_KIND_READY) == 1);
    }
    /* the Slice 1 condition: channel below the member's minimum */
    cond = lt_cond_fits();
    cond.limits.min_channel_sat = 100001;
    member_up(&m, &cond);
    n = offer(buf, sizeof buf, SCOPE, T1, T1N, T2, T2N, &HOST);
    CHECK(feed(&m, buf, n) == GZ_OK && note(GZ_NOTE_REFUSED, GZ_FIT_NO, 30) && sends(GZ_KIND_JOIN) == 0 && !any_save());
    cond = lt_cond_fits(); cond.limits.profiles = 1u << 1;
    member_up(&m, &cond);
    CHECK(feed(&m, buf, n) == GZ_OK && note(GZ_NOTE_REFUSED, GZ_FIT_NO, 8));
    cond = lt_cond_fits(); cond.limits.min_lifetime = 145;
    member_up(&m, &cond);
    CHECK(feed(&m, buf, n) == GZ_OK && note(GZ_NOTE_REFUSED, GZ_FIT_NO, 26));
    {   /* a member that has not joined (no automatic join) answers no check, though the terms fit */
        static gz_lobby_member_t mj;
        gz_ports_t pj = ports();
        gz_lobby_crypto_t cj = lt_crypto(&M1);
        gz_lobby_conditions_t cf = lt_cond_fits();
        gz_lobby_input_t ij;
        uint8_t xc[300], ck[32], d2[32];
        size_t xcn;
        gz_lobby_member_init(&mj, &pj, &cj, NULL, &cf, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 0);
        memset(&ij, 0, sizeof ij);
        ij.kind = GZ_LIN_CONNECTED; ij.peer_id = W_HOST_PEER; ij.peer_key = HOST.key[1].pub;
        acts_reset();
        gz_lobby_member_handle(&mj, &ij, &A.l);
        n = offer(buf, sizeof buf, SCOPE, T1, T1N, T2, T2N, &HOST);
        CHECK(feed(&mj, buf, n) == GZ_OK && sends(GZ_KIND_JOIN) == 0 && !mj.joined && mj.have_terms);
        memset(ck, 0x67, 32);
        gz_terms_current_digest(T2, T2N, d2);
        xcn = host_msg(xc, sizeof xc, GZ_KIND_READY_CHECK, ck, 1, d2, 30000, 0, &HOST);
        CHECK(feed(&mj, xc, xcn) == GZ_OK && A.l.count == 0);
    }
    /* a user unready is kept across a restart */
    cond = lt_cond_fits();
    member_up(&m, &cond);
    feed(&m, buf, n);
    acts_reset();
    CHECK(gz_lobby_member_unready(&m, &A.l) == GZ_OK && sends(GZ_KIND_UNREADY) == 1 && saves(GZ_REC_READY_SENT) == 1);
    {
        gz_lobby_msg_t g;
        uint8_t ob2[8000];
        size_t on2 = offer(ob2, sizeof ob2, SCOPE, T1, T1N, T3, T3N, &HOST);
        CHECK(last_sent(GZ_KIND_UNREADY, &g, NULL, NULL) && g.has_reason && g.reason == 2);   /* the user's choice */
        CHECK(feed(&m, ob2, on2) == GZ_OK && sends(GZ_KIND_READY) == 0);   /* new values: still not ready by itself */
        acts_reset();
        CHECK(gz_lobby_member_set_conditions(&m, &cond, &A.l) == GZ_OK && sends(GZ_KIND_READY) == 1);   /* until asked */
        acts_reset();
        CHECK(gz_lobby_member_unready(&m, &A.l) == GZ_OK);
        n = offer(buf, sizeof buf, SCOPE, T1, T1N, T2, T2N, &HOST);
    }
    {
        gz_record_t r;
        uint8_t two = 2;
        static gz_lobby_member_t m2;
        member_up(&m2, &cond);
        r.type = GZ_REC_READY_SENT; r.bytes.data = &two; r.bytes.len = 1;
        gz_lobby_member_restore(&m2, &r);
        CHECK(feed(&m2, buf, n) == GZ_OK && sends(GZ_KIND_JOIN) == 1 && sends(GZ_KIND_READY) == 0);
        {   /* and a ready check is not answered either */
            uint8_t x[300], chk[32], cd2[32];
            size_t xn;
            memset(chk, 3, 32);
            gz_terms_current_digest(T2, T2N, cd2);
            xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
            CHECK(feed(&m2, x, xn) == GZ_OK && sends(GZ_KIND_READY) == 0 && !any_save());
        }
    }
}

static size_t status_msg(uint8_t *buf, size_t cap, uint8_t lobby, uint8_t seat, uint32_t version, int reason)
{
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_LOBBY_STATUS, SCOPE);
    gz_lobby_enc_u8(&e, 2, lobby);
    gz_lobby_enc_u8(&e, 4, seat);
    gz_lobby_enc_u32(&e, 6, version);
    gz_lobby_enc_u16(&e, 8, 1);
    gz_lobby_enc_u16(&e, 10, 1);
    if (reason >= 0) gz_lobby_enc_u16(&e, 13, (uint16_t)reason);
    return gz_lobby_enc_done(&e);
}

/* The member's answers to lobby_status, its records and its restart. */
static void test_member_details(void)
{
    static gz_lobby_member_t m, m2;
    static uint8_t offer2[8000];
    gz_lobby_conditions_t cond = lt_cond_fits();
    uint8_t buf[600], cd2[32], chk[32], x[600];
    size_t n2, n, xn, i, j;
    gz_record_t recs[32];
    uint8_t *store[32];
    size_t nrec = 0;
    gz_lobby_input_t in;
    gz_terms_current_digest(T2, T2N, cd2);
    cond.min_members = 3;
    member_up(&m, &cond);
    n2 = offer(offer2, sizeof offer2, SCOPE, T1, T1N, T2, T2N, &HOST);
#define MKEEP() for (i = 0; i < A.l.count; i++) if (A.s[i].kind == GZ_ACTION_SAVE) \
    for (j = 0; j < A.s[i].u.save.n_records; j++) { recs[nrec] = A.s[i].u.save.records[j]; \
        store[nrec] = malloc(recs[nrec].bytes.len + 1); \
        memcpy(store[nrec], recs[nrec].bytes.data, recs[nrec].bytes.len); recs[nrec].bytes.data = store[nrec]; nrec++; }
    feed(&m, offer2, n2); MKEEP();
    {   /* the ready carries the member's own minimum */
        gz_lobby_msg_t g;
        CHECK(last_sent(GZ_KIND_READY, &g, NULL, NULL) && g.has_min_members && g.min_members == 3 && !g.has_check_id);
    }
    /* the answer to hello, before our join arrived: nothing resent */
    n = status_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_NONE, 1, -1);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_JOIN) == 0 && note(GZ_NOTE_SEAT, GZ_LOBBY_OPEN, GZ_SEAT_NONE));
    CHECK(feed(&m, buf, n) == GZ_OK && A.l.count == 0);                 /* the same status: nothing new */
    /* Joined at the version we are ready for: the host lost our ready; at most 3 times */
    n = status_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_JOINED, 1, -1);
    for (i = 0; i < 5; i++) {
        CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_READY) == (i < 3) && sends(GZ_KIND_JOIN) == (i < 3) && !any_save());
    }
    /* a newer version than we know: fetch the terms */
    n = status_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_READY, 2, -1);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_HELLO) == 1);
    /* refused for a limit: try again later, by a timer, then join and ready again */
    n = status_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_REFUSED, 1, -1);
    CHECK(feed(&m, buf, n) == GZ_OK && timers(GZ_LOBBY_TIMER_RETRY) == 1 && sends(GZ_KIND_JOIN) == 0);
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_RETRY;
    acts_reset();
    CHECK(gz_lobby_member_handle(&m, &in, &A.l) == GZ_OK && sends(GZ_KIND_JOIN) == 1 && sends(GZ_KIND_READY) == 1 && !any_save());
    in.timer_id = GZ_LOBBY_TIMER_STATUS;                               /* not the member's timer */
    acts_reset();
    CHECK(gz_lobby_member_handle(&m, &in, &A.l) == GZ_OK && A.l.count == 0);
    for (i = 0; i < 29; i++) feed(&m, buf, n);
    CHECK(feed(&m, buf, n) == GZ_OK && timers(GZ_LOBBY_TIMER_RETRY) == 0);   /* 30 tries per connection */
    /* the ready check, then a start for it, then restart from the records */
    memset(chk, 0x41, 32);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && saves(GZ_REC_FREEZE) == 1 && sends(GZ_KIND_READY) == 1 && before(GZ_KIND_READY, GZ_REC_FREEZE));
    CHECK(saves(GZ_REC_TERMS_RECEIVED) == 0);            /* version 1 is saved already */
    MKEEP();
    {
        gz_lobby_msg_t g;
        CHECK(last_sent(GZ_KIND_READY, &g, NULL, NULL) && g.has_check_id && memcmp(g.check_id, chk, 32) == 0 && g.min_members == 3);
    }
    xn = host_msg(x, sizeof x, GZ_KIND_START, chk, 0, NULL, 0, 2, &HOST);   /* not chosen: no hand-off */
    CHECK(feed(&m, x, xn) == GZ_OK && saves(GZ_REC_START_RECEIVED) == 1 && note(GZ_NOTE_STARTED, 2, -1) && m.role == 2);
    MKEEP();
    /* the freeze record, and each way it can be wrong */
    for (i = 0; i < nrec; i++)
        if (recs[i].type == GZ_REC_FREEZE) {
            uint8_t v[400];
            size_t vn = recs[i].bytes.len, q;
            gz_record_t r2 = recs[i];
            CHECK(vn > 70 && vn < sizeof v && gz_la_freeze_ok(recs[i].bytes.data, vn));
            for (q = 0; q < 6; q++) {
                memcpy(v, recs[i].bytes.data, vn);
                r2.bytes.data = v;
                r2.bytes.len = vn;
                if (q == 0) v[3] ^= 1;                   /* another check id */
                if (q == 1) v[35] ^= 1;                  /* another version */
                if (q == 2) v[40] ^= 1;                  /* another digest */
                if (q == 3) { v[vn] = 0; r2.bytes.len = vn + 1; }   /* a byte after the check */
                if (q == 4) v[68 + 2 + 7] = GZ_KIND_START;          /* not a ready_check */
                if (q == 5) r2.bytes.len = 69;
                CHECK(!gz_la_freeze_ok(v, r2.bytes.len));
                member_up(&m2, &cond);
                CHECK(gz_lobby_member_restore(&m2, &r2) == GZ_ERR_CORRUPT && !m2.frozen);
            }
            {   /* a well-formed message of another kind (a start for the same check) */
                uint8_t st[200];
                size_t sn = host_msg(st, sizeof st, GZ_KIND_START, chk, 0, NULL, 0, 1, &HOST);
                memcpy(v, chk, 32);
                memset(v + 32, 0, 36);
                vn = 68 + gz_la_put_blob(v + 68, st, sn);
                CHECK(!gz_la_freeze_ok(v, vn));
            }
        }
    member_up(&m2, &cond);
    for (i = 0; i < nrec; i++) CHECK(gz_lobby_member_restore(&m2, &recs[i]) == GZ_OK);
    CHECK(m2.joined && m2.ready && m2.frozen && m2.frozen_version == 1 && memcmp(m2.frozen_digest, cd2, 32) == 0);
    CHECK(m2.has_answered && memcmp(m2.answered_check, chk, 32) == 0 && m2.role == 2 && m2.start_len == m.start_len);
    CHECK(memcmp(m2.start_msg, m.start_msg, m.start_len) == 0 && m2.ready_len == m.ready_len &&
          memcmp(m2.ready_msg, m.ready_msg, m.ready_len) == 0 && m2.ready_version == 1);
    CHECK(m2.join_len == m.join_len && memcmp(m2.join_msg, m.join_msg, m.join_len) == 0 && m2.saved_version == 1);
    CHECK(m2.outer_len == T1N && memcmp(m2.outer, T1, T1N) == 0 && m2.current_len == T2N && memcmp(m2.current, T2, T2N) == 0);
    CHECK(memcmp(m2.outer_sig, m.outer_sig, 64) == 0 && memcmp(m2.current_sig, m.current_sig, 64) == 0 && m2.have_terms);
    {   /* the host's own signatures, as they came */
        uint8_t s1[64], s2[64];
        lt_sign(&HOST, 1, SCOPE, s1);
        lt_sign(&HOST, 1, cd2, s2);
        CHECK(memcmp(m2.outer_sig, s1, 64) == 0 && memcmp(m2.current_sig, s2, 64) == 0);
    }
    CHECK(!m2.ended && !m2.left && !m2.user_unready);
    /* the restarted member answers the same check with the same saved bytes */
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
    CHECK(feed(&m2, x, xn) == GZ_OK && sends(GZ_KIND_READY) == 1 && !any_save());
    {
        const uint8_t *r; size_t rn;
        gz_lobby_msg_t g;
        CHECK(last_sent(GZ_KIND_READY, &g, &r, &rn) && rn == m.ready_len && memcmp(r, m.ready_msg, rn) == 0);
    }
    /* removed, or refused as invalid: the end */
    n = status_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_REMOVED, 1, -1);
    CHECK(feed(&m2, buf, n) == GZ_OK && m2.ended && !m2.ready);
    CHECK(feed(&m2, offer2, n2) == GZ_OK && A.l.count == 0);
    member_up(&m2, &cond);
    feed(&m2, offer2, n2);
    n = status_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_REFUSED, 1, 5);
    CHECK(feed(&m2, buf, n) == GZ_OK && m2.ended && timers(GZ_LOBBY_TIMER_RETRY) == 0);
    /* a start that is not well formed: refused */
    member_up(&m2, &cond);
    feed(&m2, offer2, n2);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
    feed(&m2, x, xn);
    xn = host_msg(x, sizeof x, GZ_KIND_START, chk, 0, NULL, 0, 3, &HOST);   /* role 3 */
    CHECK(feed(&m2, x, xn) == GZ_OK && sends(1) == 1 && !any_save());
    /* a leave from the user: saved, then sent; a second one refused. The stack
     * is filled with 0xa5 first, so a record byte the engine leaves unwritten
     * shows as 0xa5 instead of a lucky zero. */
    acts_reset();
    poison_stack();
    CHECK(gz_lobby_member_leave(&m2, &A.l) == GZ_OK && before(GZ_KIND_LEAVE, GZ_REC_LOBBY_ENDED) && m2.ended && m2.left);
    {   /* the leave says why (2, the user's choice), and so does the record: state 0, reason 2, no cancel */
        gz_lobby_msg_t g;
        size_t q;
        CHECK(last_sent(GZ_KIND_LEAVE, &g, NULL, NULL) && g.has_reason && g.reason == 2 && saves(GZ_REC_HOST_FAULT) == 0);
        for (q = 0; q < A.l.count; q++)
            if (A.s[q].kind == GZ_ACTION_SAVE && A.s[q].u.save.records[0].type == GZ_REC_LOBBY_ENDED)
                CHECK(A.s[q].u.save.records[0].bytes.len == 5 &&
                      memcmp(A.s[q].u.save.records[0].bytes.data, "\0\0\2\0\0", 5) == 0);
    }
    acts_reset();
    acts_reset();
    CHECK(gz_lobby_member_leave(&m2, &A.l) == GZ_OK && refused(GZ_CMD_LEAVE) && !any_save());
    CHECK(gz_lobby_member_unready(&m2, &A.l) == GZ_OK && refused(GZ_CMD_UNREADY) && !any_save());
    acts_reset();
    CHECK(gz_lobby_member_set_conditions(&m2, &cond, &A.l) == GZ_OK && A.l.count == 0);   /* gone: nothing joins again */
    /* new conditions take effect at once: a looser limit readies, a tighter one unreadies */
    {
        gz_lobby_conditions_t c2 = lt_cond_fits();
        LT_ADJ(c2, 0) = 1000;
        member_up(&m2, &c2);
        CHECK(feed(&m2, offer2, n2) == GZ_OK && sends(GZ_KIND_JOIN) == 1 && sends(GZ_KIND_READY) == 0 &&
              note(GZ_NOTE_REFUSED, GZ_FIT_NOW, 64));
        c2.current_only = 1;
        acts_reset();
        CHECK(gz_lobby_member_set_conditions(&m2, &c2, &A.l) == GZ_OK && sends(GZ_KIND_JOIN) == 0 && sends(GZ_KIND_READY) == 1);
        LT_ADJ(c2, 0) = 400;
        acts_reset();
        CHECK(gz_lobby_member_set_conditions(&m2, &c2, &A.l) == GZ_OK && sends(GZ_KIND_UNREADY) == 1 &&
              note(GZ_NOTE_UNREADY, GZ_FIT_NO, 64));
        acts_reset();
        CHECK(gz_lobby_member_set_conditions(&m2, &c2, &A.l) == GZ_OK && sends(GZ_KIND_UNREADY) == 0 &&
              note(GZ_NOTE_REFUSED, GZ_FIT_NO, 64));       /* already unready: told again, nothing sent */
    }
    for (i = 0; i < nrec; i++) free(store[i]);
}

/* -------------------------------------------- host, hostile members */

static gz_lobby_host_t H;
static lt_signer_t MEM[40];
static int WHO;
static uint8_t CHK[32];

static gz_status_t hin(int kind, int who, const uint8_t *b, size_t n)
{
    gz_lobby_input_t in;
    memset(&in, 0, sizeof in);
    in.kind = kind; in.peer_id = W_PEER(who); in.bytes = b; in.len = n;
    in.peer_key = MEM[who].key[2].pub;
    WHO = who;
    acts_reset();
    return gz_lobby_host_handle(&H, &in, &A.l);
}

static size_t join_msg(uint8_t *buf, size_t cap, int who, const uint8_t *fkey, int sign_f, int sign_c)
{
    uint8_t b[32], sf[64], sc[64];
    gz_lobby_enc_t e;
    gz_lobby_binding(SCOPE, fkey, MEM[who].key[2].pub, b);
    lt_sign(&MEM[sign_f], 3, b, sf);
    lt_sign(&MEM[sign_c], 2, b, sc);
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_JOIN, SCOPE);
    gz_lobby_enc_record(&e, 2, fkey, 33);
    gz_lobby_enc_record(&e, 4, sf, 64);
    gz_lobby_enc_record(&e, 6, sc, 64);
    return gz_lobby_enc_done(&e);
}

static size_t ready_msg(uint8_t *buf, size_t cap, int who, uint32_t version, const uint8_t *digest,
                        const uint8_t *check, uint16_t min)
{
    gz_lobby_enc_t e;
    gz_lobby_crypto_t cr = lt_crypto(&MEM[who]);
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_READY, SCOPE);
    gz_lobby_enc_record(&e, 2, SCOPE, 32);
    gz_lobby_enc_u32(&e, 4, version);
    gz_lobby_enc_record(&e, 6, digest, 32);
    if (check) gz_lobby_enc_record(&e, 8, check, 32);
    if (min) gz_lobby_enc_u16(&e, 11, min);
    return gz_lobby_enc_sign(&e, &cr, GZ_LOBBY_KEY_CONTRIBUTION);
}

/* The seat state in the last status sent to the member the last input came from. */
static int status_seat(void)
{
    gz_lobby_msg_t g;
    size_t i;
    int r = -1;
    for (i = 0; i < A.l.count; i++)
        if (kind_of(&A.s[i]) == GZ_KIND_LOBBY_STATUS && A.s[i].u.send.peer_id == W_PEER(WHO)) {
            gz_lobby_decode(A.s[i].u.send.bytes.data, A.s[i].u.send.bytes.len, &g);
            r = g.seat_state;
        }
    return r;
}

/* The last lobby_status sent to member `who`, decoded; 0 if none. */
static int status_to(int who, gz_lobby_msg_t *g)
{
    size_t i;
    int found = 0;
    for (i = 0; i < A.l.count; i++)
        if (kind_of(&A.s[i]) == GZ_KIND_LOBBY_STATUS && A.s[i].u.send.peer_id == W_PEER(who)) {
            gz_lobby_decode(A.s[i].u.send.bytes.data, A.s[i].u.send.bytes.len, g);
            found = 1;
        }
    return found;
}

static gz_status_t hin(int kind, int who, const uint8_t *b, size_t n);
/* A new connection for member `who` (its per-connection counts start afresh). */
static void fresh(int who) { hin(GZ_LIN_DISCONNECTED, who, NULL, 0); hin(GZ_LIN_CONNECTED, who, NULL, 0); }

/* The check of the start a member holds (zeros if none): what its signing
 * engine names in a Retry for the round it was handed. */
static const uint8_t *held_check(const gz_lobby_member_t *m)
{
    static uint8_t c[32];
    gz_lobby_msg_t g;
    memset(c, 0, sizeof c);
    if (m->start_len && gz_lobby_decode(m->start_msg, m->start_len, &g) == GZ_DEC_OK) memcpy(c, g.check_id, 32);
    return c;
}

static void host_open(uint16_t standbys)
{
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(&HOST);
    gz_lobby_host_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, HOST.key[3].pub, 33);
    cfg.standbys = standbys;
    gz_lobby_host_init(&H, &p, &cr, NULL, &cfg);
    acts_reset();
    CHECK(gz_lobby_host_open(&H, T1, T1N, T2, T2N, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_OPENED) == 1);
}

static void test_host_hostile(void)
{
    uint8_t buf[600], cd2[32], cd3[32], un0[64];
    size_t n, un0n;
    int i;
    gz_lobby_enc_t e0;
    gz_lobby_enc_start(&e0, un0, sizeof un0, GZ_KIND_UNREADY, SCOPE);
    un0n = gz_lobby_enc_done(&e0);
    gz_terms_current_digest(T2, T2N, cd2);
    gz_terms_current_digest(T3, T3N, cd3);
    CLOCK = W_T0 - 3600000;                     /* an hour before the deadline */
    host_open(0);
    for (i = 1; i <= 10; i++) hin(GZ_LIN_CONNECTED, i, NULL, 0);
    /* hello: terms and status */
    {
        gz_lobby_enc_t e;
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_HELLO, SCOPE);
        n = gz_lobby_enc_done(&e);
        CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1 && sends(GZ_KIND_LOBBY_STATUS) == 1);
        /* test 25: flood, answered once a second, closed after 20 ignored */
        for (i = 0; i < 20; i++) { hin(GZ_LIN_MESSAGE, 1, buf, n); CHECK(A.l.count == 0); }
        hin(GZ_LIN_MESSAGE, 1, buf, n);
        CHECK(sends(1) == 1 && note(GZ_NOTE_CLOSE, -1, -1));
        {   /* the close names the connection: the 8-byte peer id */
            size_t q;
            int named = 0;
            for (q = 0; q < A.l.count; q++)
                if (A.s[q].kind == GZ_ACTION_NOTIFY && A.s[q].u.notify.code == GZ_NOTE_CLOSE)
                    named = A.s[q].u.notify.bytes.len == 8 && memcmp(A.s[q].u.notify.bytes.data, "\0\0\0\0\0\0\x03\xe9", 8) == 0;
            CHECK(named);
            CHECK(A.s[0].kind == GZ_ACTION_SEND && A.s[0].u.send.peer_id == W_PEER(1));
        }
        CLOCK += 1000;
        hin(GZ_LIN_MESSAGE, 2, buf, n);
        CHECK(sends(GZ_KIND_TERMS_OFFER) == 1);
    }
    /* test 22, 43: joins */
    n = join_msg(buf, sizeof buf, 1, MEM[1].key[3].pub, 1, 1);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_JOINED);
    CHECK(before(GZ_KIND_LOBBY_STATUS, GZ_REC_SEAT));
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_JOINED);   /* duplicate */
    n = join_msg(buf, sizeof buf, 1, MEM[2].key[3].pub, 2, 1);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED); /* other fkey */
    {
        gz_lobby_msg_t g5;
        CHECK(status_to(1, &g5) && g5.has_reason && g5.reason == 5);
    }
    CLOCK += 1000;
    n = join_msg(buf, sizeof buf, 2, MEM[1].key[3].pub, 1, 2);                  /* another seat's factory key */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    {   /* refused as invalid: reason 5 */
        gz_lobby_msg_t g5;
        CHECK(status_to(2, &g5) && g5.has_reason && g5.reason == 5);
    }
    n = join_msg(buf, sizeof buf, 2, HOST.key[3].pub, 0, 2);                    /* the host's factory key */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    fresh(2);                                         /* three refused as invalid close a connection (F8) */
    n = join_msg(buf, sizeof buf, 2, MEM[2].key[3].pub, 3, 2);                  /* bad bind_by_factory */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    n = join_msg(buf, sizeof buf, 2, MEM[2].key[3].pub, 2, 3);                  /* bad bind_by_contribution */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    fresh(2);
    n = join_msg(buf, sizeof buf, 2, MEM[1].key[2].pub, 1, 2);                  /* another seat's contribution key */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    n = join_msg(buf, sizeof buf, 2, MEM[2].key[3].pub, 2, 2);
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1);
    CLOCK += 1000;
    /* a ready naming the latest version but another digest: not ready */
    {
        uint8_t wrong[32];
        memcpy(wrong, cd2, 32); wrong[0] ^= 1;
        n = ready_msg(buf, sizeof buf, 1, 1, wrong, NULL, 0);
        CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_JOINED);
    }
    /* the largest ready a seat keeps is 256 bytes; one byte more is not kept, so not taken */
    {
        size_t L;
        for (L = 75; L >= 74; L--) {
            gz_lobby_enc_t e;
            gz_lobby_crypto_t cr = lt_crypto(&MEM[1]);
            uint8_t pad[80];
            memset(pad, 0x20, sizeof pad);
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_READY, SCOPE);
            gz_lobby_enc_record(&e, 2, SCOPE, 32);
            gz_lobby_enc_u32(&e, 4, 1);
            gz_lobby_enc_record(&e, 6, cd2, 32);
            gz_lobby_enc_record(&e, 9, pad, L);
            n = gz_lobby_enc_sign(&e, &cr, GZ_LOBBY_KEY_CONTRIBUTION);
            CHECK(n == 182 + L);
            CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && status_seat() == (L == 74 ? GZ_SEAT_READY : GZ_SEAT_JOINED));
            CHECK(saves(GZ_REC_SEAT) == (L == 74));
        }
        hin(GZ_LIN_MESSAGE, 1, un0, un0n);              /* back to Joined for what follows */
        CHECK(saves(GZ_REC_SEAT) == 1);
    }
    /* test 23: ready naming an old version during a change */
    n = ready_msg(buf, sizeof buf, 1, 1, cd2, NULL, 0);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_READY);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && !any_save());               /* duplicate: not saved */
    {
        uint64_t v[3] = {1500, 1000, 1000};
        acts_reset();
        CHECK(gz_lobby_host_set_values(&H, v, 3, &A.l) == GZ_OK && saves(GZ_REC_TERMS_VERSION) == 1);
        CHECK(sends(GZ_KIND_TERMS_OFFER) == 2 && before(GZ_KIND_TERMS_OFFER, GZ_REC_TERMS_VERSION));
        {   /* the host signed exactly T3 */
            gz_lobby_msg_t g;
            last_sent(GZ_KIND_TERMS_OFFER, &g, NULL, NULL);
            CHECK(g.current_len == T3N && memcmp(g.current, T3, T3N) == 0);
        }
    }
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && status_seat() == GZ_SEAT_JOINED && !any_save());
    {
        gz_lobby_msg_t g;
        last_sent(GZ_KIND_LOBBY_STATUS, &g, NULL, NULL);
        CHECK(g.version == 2 && g.ready == 0 && g.joined == 2);
    }
    n = ready_msg(buf, sizeof buf, 1, 2, cd3, NULL, 0);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && status_seat() == GZ_SEAT_READY);
    /* a ready signed by another key: refused */
    n = ready_msg(buf, sizeof buf, 3, 2, cd3, NULL, 0);
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && sends(1) == 1);
    /* wrong direction */
    n = host_msg(buf, sizeof buf, GZ_KIND_CANCEL, NULL, 2, NULL, 0, 0, &HOST);
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && sends(1) == 1 && H.state == GZ_LOBBY_OPEN);
    fresh(2);                                         /* the host asked for that connection to close */
    /* test 56: a seat that loops ready/unready: past 10 changes in 10 minutes a
     * move into Ready is refused; moves out are always saved */
    {
        int saved = 0;
        uint8_t un[64];
        size_t unn;
        gz_lobby_enc_t e;
        gz_lobby_enc_start(&e, un, sizeof un, GZ_KIND_UNREADY, SCOPE);
        unn = gz_lobby_enc_done(&e);
        n = ready_msg(buf, sizeof buf, 2, 2, cd3, NULL, 0);
        for (i = 0; i < 50; i++) {
            hin(GZ_LIN_MESSAGE, 2, buf, n); saved += saves(GZ_REC_SEAT);
            hin(GZ_LIN_MESSAGE, 2, un, unn); saved += saves(GZ_REC_SEAT);
            CLOCK += 100;
        }
        /* the join used one of the ten: five readies, and their five unreadies,
         * which are never limited (review B, B6) and take the seat out */
        CHECK(saved == 10);
        CHECK(H.seats[1].state == GZ_SEAT_JOINED);
        hin(GZ_LIN_MESSAGE, 2, buf, n);        /* past the limit a ready is ignored: answered, nothing saved */
        CHECK(!any_save() && status_seat() == GZ_SEAT_JOINED && H.seats[1].state == GZ_SEAT_JOINED);
        CLOCK += 600000;
        hin(GZ_LIN_MESSAGE, 2, buf, n);
        CHECK(saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_READY);
        hin(GZ_LIN_MESSAGE, 2, un, unn);
        CHECK(saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_JOINED);
        /* leave then join on the same connection: a second creation is refused */
        {
            gz_lobby_enc_t e2;
            uint8_t lv[64];
            gz_lobby_enc_start(&e2, lv, sizeof lv, GZ_KIND_LEAVE, SCOPE);
            hin(GZ_LIN_MESSAGE, 2, lv, gz_lobby_enc_done(&e2));
            CHECK(status_seat() == GZ_SEAT_LEFT && saves(GZ_REC_SEAT) == 1);
            CLOCK += 2000;
            n = join_msg(buf, sizeof buf, 2, MEM[2].key[3].pub, 2, 2);
            hin(GZ_LIN_MESSAGE, 2, buf, n);
            CHECK(saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_JOINED);   /* this connection's first join */
            CHECK(hin(GZ_LIN_MESSAGE, 2, lv, gz_lobby_enc_done(&e2)) == GZ_OK && status_seat() == GZ_SEAT_LEFT);
            CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
            hin(GZ_LIN_DISCONNECTED, 2, NULL, 0);
            hin(GZ_LIN_CONNECTED, 2, NULL, 0);
            CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_JOINED);
        }
    }
    /* the limit's edge: ten changes at one instant; refused 599,999 ms later, allowed at 600,000 */
    {
        uint8_t un[64], lv[64], rd[300];
        size_t unn, lvn, rn;
        uint64_t t0;
        gz_lobby_enc_t e;
        gz_lobby_enc_start(&e, un, sizeof un, GZ_KIND_UNREADY, SCOPE);
        unn = gz_lobby_enc_done(&e);
        gz_lobby_enc_start(&e, lv, sizeof lv, GZ_KIND_LEAVE, SCOPE);
        lvn = gz_lobby_enc_done(&e);
        CLOCK += 2000;
        t0 = CLOCK;
        n = join_msg(buf, sizeof buf, 5, MEM[5].key[3].pub, 5, 5);
        CHECK(hin(GZ_LIN_MESSAGE, 5, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1);
        rn = ready_msg(rd, sizeof rd, 5, 2, cd3, NULL, 0);
        for (i = 0; i < 9; i++) {
            if (i % 2 == 0) hin(GZ_LIN_MESSAGE, 5, rd, rn); else hin(GZ_LIN_MESSAGE, 5, un, unn);
            CHECK(saves(GZ_REC_SEAT) == 1);
        }
        /* the eleventh, an unready: never limited (review B, B6) */
        CHECK(hin(GZ_LIN_MESSAGE, 5, un, unn) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_JOINED);
        CHECK(hin(GZ_LIN_MESSAGE, 5, rd, rn) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_JOINED);   /* the twelfth */
        CLOCK = t0 + 599999;
        CHECK(hin(GZ_LIN_MESSAGE, 5, rd, rn) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_JOINED);
        CLOCK = t0 + 600000;
        CHECK(hin(GZ_LIN_MESSAGE, 5, rd, rn) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_READY);
        CHECK(hin(GZ_LIN_MESSAGE, 5, lv, lvn) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_LEFT);
        /* ten changes a millisecond apart: the window slides change by change */
        CLOCK += 2000;
        t0 = CLOCK;
        n = join_msg(buf, sizeof buf, 6, MEM[6].key[3].pub, 6, 6);
        CHECK(hin(GZ_LIN_MESSAGE, 6, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1);
        {
            rn = ready_msg(rd, sizeof rd, 6, 2, cd3, NULL, 0);
            for (i = 0; i < 9; i++) {
                CLOCK = t0 + 1 + i;
                if (i % 2 == 0) hin(GZ_LIN_MESSAGE, 6, rd, rn); else hin(GZ_LIN_MESSAGE, 6, un, unn);
                CHECK(saves(GZ_REC_SEAT) == 1);
            }
            CLOCK = t0 + 600000;                         /* the first change has left the window */
            CHECK(hin(GZ_LIN_MESSAGE, 6, un, unn) == GZ_OK && saves(GZ_REC_SEAT) == 1);
            CHECK(hin(GZ_LIN_MESSAGE, 6, rd, rn) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_JOINED);   /* the second has not */
            CLOCK = t0 + 600001;
            CHECK(hin(GZ_LIN_MESSAGE, 6, rd, rn) == GZ_OK && saves(GZ_REC_SEAT) == 1);
            CLOCK = t0 + 600002;
            CHECK(hin(GZ_LIN_MESSAGE, 6, lv, lvn) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_LEFT);
        }
    }
    /* removal before the start: the seat cannot come back */
    acts_reset();
    WHO = 2;
    CHECK(gz_lobby_host_remove(&H, MEM[2].key[2].pub, &A.l) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_REMOVED);
    CLOCK += 2000;
    hin(GZ_LIN_DISCONNECTED, 2, NULL, 0);
    hin(GZ_LIN_CONNECTED, 2, NULL, 0);
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REMOVED);
    /* after the freeze the host signs no new version */
    for (i = 3; i <= 4; i++) {
        CLOCK += 1000;
        n = join_msg(buf, sizeof buf, i, MEM[i].key[3].pub, i, i);
        hin(GZ_LIN_MESSAGE, i, buf, n);
        n = ready_msg(buf, sizeof buf, i, 2, cd3, NULL, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CLOCK = 1794441600000ull;                                                   /* the deadline */
    {
        gz_lobby_input_t in;
        uint64_t v[3] = {0, 0, 100};
        memset(&in, 0, sizeof in);
        in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_DEADLINE;
        acts_reset();
        CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && saves(GZ_REC_FREEZE) == 1 && sends(GZ_KIND_READY_CHECK) == 3);
        CHECK(before(GZ_KIND_READY_CHECK, GZ_REC_FREEZE) && H.state == GZ_LOBBY_READY_CHECK);
        {
            gz_lobby_msg_t g0;
            CHECK(last_sent(GZ_KIND_READY_CHECK, &g0, NULL, NULL));
            memcpy(CHK, g0.check_id, 32);
        }
        acts_reset();
        CHECK(gz_lobby_host_set_values(&H, v, 3, &A.l) == GZ_OK && A.l.count == 1 && refused(GZ_CMD_SET_VALUES));
        /* test 24: a stale check id is not counted; the open one is */
        {
            uint8_t stale[32], *chk = CHK;
            gz_lobby_msg_t g;
            memset(stale, 1, 32);
            n = ready_msg(buf, sizeof buf, 1, 2, cd3, stale, 0);
            hin(GZ_LIN_MESSAGE, 1, buf, n);
            n = ready_msg(buf, sizeof buf, 3, 2, cd3, chk, 0);
            hin(GZ_LIN_MESSAGE, 3, buf, n);
            n = ready_msg(buf, sizeof buf, 4, 2, cd3, chk, 0);
            hin(GZ_LIN_MESSAGE, 4, buf, n);
            in.timer_id = GZ_LOBBY_TIMER_WINDOW;
            acts_reset();
            /* two answered: below the minimum, and the deadline has passed: cancelled */
            CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_START) == 0 && sends(GZ_KIND_CANCEL) == 6);
            CHECK(status_to(5, &g) && g.lobby_state == GZ_LOBBY_CANCELLED && g.seat_state == GZ_SEAT_LEFT &&
                  g.has_reason && g.reason == 1);          /* a seat that left hears the end too, with the reason */
            CHECK(saves(GZ_REC_LOBBY_ENDED) == 1 && H.state == GZ_LOBBY_CANCELLED && before(GZ_KIND_CANCEL, GZ_REC_LOBBY_ENDED));
        }
    }
}

static uint8_t SENT[4][300];
static size_t SENT_LEN[4];

/* The host's restart: the freeze and the versions survive; a resumed host
 * resends the saved start after hello. */
static void test_host_restart(void)
{
    static gz_lobby_host_t H2;
    uint8_t buf[600], cd3[32];
    size_t n, i;
    gz_record_t recs[64];
    uint8_t *store[64];
    size_t nrec = 0, k, kk;
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(&HOST);
    gz_lobby_host_config_t cfg;
    gz_lobby_input_t in;
    gz_terms_current_digest(T3, T3N, cd3);
    CLOCK = W_T0;
    host_open(0);
#define KEEP() for (kk = 0; kk < A.l.count; kk++) if (A.s[kk].kind == GZ_ACTION_SAVE) \
    for (k = 0; k < A.s[kk].u.save.n_records; k++) { recs[nrec] = A.s[kk].u.save.records[k]; \
        store[nrec] = malloc(recs[nrec].bytes.len + 1); memcpy(store[nrec], recs[nrec].bytes.data, recs[nrec].bytes.len); \
        recs[nrec].bytes.data = store[nrec]; nrec++; }
    KEEP();
    {
        uint64_t v[3] = {1500, 1000, 1000};
        acts_reset();
        gz_lobby_host_set_values(&H, v, 3, &A.l);
        KEEP();
    }
    for (i = 1; i <= 3; i++) {
        hin(GZ_LIN_CONNECTED, (int)i, NULL, 0);
        CLOCK += 1000;
        n = join_msg(buf, sizeof buf, (int)i, MEM[i].key[3].pub, (int)i, (int)i);
        hin(GZ_LIN_MESSAGE, (int)i, buf, n); KEEP();
        n = ready_msg(buf, sizeof buf, (int)i, 2, cd3, NULL, 0);
        hin(GZ_LIN_MESSAGE, (int)i, buf, n); KEEP();
        if (saves(GZ_REC_SEAT)) { memcpy(SENT[i - 1], buf, n); SENT_LEN[i - 1] = n; }
    }
    CLOCK = 1794441600000ull;
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_DEADLINE;
    acts_reset(); gz_lobby_host_handle(&H, &in, &A.l); KEEP();
    {
        gz_lobby_msg_t g;
        uint8_t chk[32];
        last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL);
        memcpy(chk, g.check_id, 32);
        for (i = 1; i <= 3; i++) {
            n = ready_msg(buf, sizeof buf, (int)i, 2, cd3, chk, (uint16_t)(i == 3 ? 4 : 0));
            hin(GZ_LIN_MESSAGE, (int)i, buf, n); KEEP();
            if (saves(GZ_REC_SEAT)) { memcpy(SENT[i - 1], buf, n); SENT_LEN[i - 1] = n; }   /* the seat changed */
        }
        in.timer_id = GZ_LOBBY_TIMER_WINDOW;
        acts_reset(); gz_lobby_host_handle(&H, &in, &A.l); KEEP();
        /* member 3 asked for at least 4: dropped; 2 left is below the minimum 3 */
        CHECK(sends(GZ_KIND_START) == 0 && H.state == GZ_LOBBY_CANCELLED);
    }
    /* rebuild from the records: same lobby, frozen, version 2, ended */
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, HOST.key[3].pub, 33);
    gz_lobby_host_init(&H2, &p, &cr, NULL, &cfg);
    for (i = 0; i < nrec; i++) CHECK(gz_lobby_host_restore(&H2, &recs[i]) == GZ_OK);
    CHECK(H2.frozen && H2.values.version == 2 && H2.state == GZ_LOBBY_CANCELLED && H2.n_seats == 3);
    CHECK(memcmp(H2.current, T3, T3N) == 0 && H2.seats[2].min_members == 4);
    /* every saved field of every seat comes back as it was */
    for (i = 0; i < 3; i++) {
        const gz_lobby_seat_t *a = &H.seats[i], *b = &H2.seats[i];
        CHECK(memcmp(a->ckey, b->ckey, 33) == 0 && memcmp(a->fkey, b->fkey, 33) == 0);
        CHECK(memcmp(a->bind_f, b->bind_f, 64) == 0 && memcmp(a->bind_c, b->bind_c, 64) == 0);
        CHECK(a->state == b->state && a->min_members == b->min_members && a->ready_version == b->ready_version);
        CHECK(a->join_seq == b->join_seq && a->join_seq == i + 1 && a->ready_len == b->ready_len && a->ready_len > 0);
        CHECK(memcmp(a->ready_msg, b->ready_msg, a->ready_len) == 0 && b->ready_version == 2);
        CHECK(b->ready_len == SENT_LEN[i] && memcmp(b->ready_msg, SENT[i], SENT_LEN[i]) == 0);   /* the bytes it signed */
    }
    CHECK(memcmp(H2.scope, H.scope, 32) == 0 && memcmp(H2.current_digest, H.current_digest, 32) == 0);
    CHECK(memcmp(H2.outer_sig, H.outer_sig, 64) == 0 && memcmp(H2.current_sig, H.current_sig, 64) == 0);
    CHECK(H2.end_reason == 1 && H2.cancel_len == H.cancel_len && memcmp(H2.cancel_msg, H.cancel_msg, H.cancel_len) == 0);
    CHECK(H2.next_seq == 3 && memcmp(&H2.me, &H.me, sizeof H.me) == 0);
    acts_reset();
    CHECK(gz_lobby_host_resume(&H2, &A.l) == GZ_OK);
    /* a damaged record stops the start */
    {
        gz_record_t bad = recs[0];
        static gz_lobby_host_t H3;
        bad.bytes.len -= 1;
        gz_lobby_host_init(&H3, &p, &cr, NULL, &cfg);
        CHECK(gz_lobby_host_restore(&H3, &bad) == GZ_ERR_CORRUPT);
        /* a freeze for another version than the one restored before it */
        gz_lobby_host_init(&H3, &p, &cr, NULL, &cfg);
        CHECK(gz_lobby_host_restore(&H3, &recs[0]) == GZ_OK);          /* lobby_opened: version 1 */
        for (i = 0; i < nrec; i++)
            if (recs[i].type == GZ_REC_FREEZE) CHECK(gz_lobby_host_restore(&H3, &recs[i]) == GZ_ERR_CORRUPT && !H3.frozen);
        /* at most 32 seats come back */
        for (i = 0; i < 33; i++) {
            uint8_t sr[211];
            gz_record_t r;
            memset(sr, 0, sizeof sr);
            sr[0] = 2; sr[1] = (uint8_t)i; sr[194] = GZ_SEAT_LEFT;
            r.type = GZ_REC_SEAT; r.bytes.data = sr; r.bytes.len = sizeof sr;
            CHECK(gz_lobby_host_restore(&H3, &r) == (i < 32 ? GZ_OK : GZ_ERR_CORRUPT));
        }
        CHECK(H3.n_seats == 32);
        /* a seat record holding the largest ready, 256 bytes */
        {
            static uint8_t sr[209 + 2 + 257];
            gz_record_t r;
            memset(sr, 0, sizeof sr);
            sr[0] = 3; sr[194] = GZ_SEAT_READY; sr[209] = 1; sr[210] = 0;
            memset(sr + 211, 0x77, 257);
            r.type = GZ_REC_SEAT; r.bytes.data = sr; r.bytes.len = sizeof sr - 1;
            gz_lobby_host_init(&H3, &p, &cr, NULL, &cfg);
            CHECK(gz_lobby_host_restore(&H3, &r) == GZ_OK && H3.seats[0].ready_len == 256);
            sr[210] = 1;                                                /* 257: more than a seat keeps */
            r.bytes.len = sizeof sr;
            CHECK(gz_lobby_host_restore(&H3, &r) == GZ_ERR_CORRUPT);
        }
        /* a host restarted after its deadline sets the deadline timer due at once */
        gz_lobby_host_init(&H3, &p, &cr, NULL, &cfg);
        CHECK(gz_lobby_host_restore(&H3, &recs[0]) == GZ_OK);
        CLOCK = 1794441600000ull + 5000;
        acts_reset();
        CHECK(gz_lobby_host_resume(&H3, &A.l) == GZ_OK && timers(GZ_LOBBY_TIMER_DEADLINE) == 1 && A.s[0].u.set_timer.delay_ms == 0);
        CLOCK = 1794441600000ull - 5000;
        acts_reset();
        CHECK(gz_lobby_host_resume(&H3, &A.l) == GZ_OK && A.s[0].u.set_timer.delay_ms == 5000);
        /* a host whose port will not sign opens nothing */
        {
            lt_signer_t ns = HOST;
            gz_lobby_crypto_t cn = lt_crypto(&ns);
            ns.fail_sign = 1;
            gz_lobby_host_init(&H3, &p, &cn, NULL, &cfg);
            acts_reset();
            CHECK(gz_lobby_host_open(&H3, T1, T1N, T2, T2N, &A.l) == GZ_ERR_ARGUMENT && A.l.count == 0);
        }
    }
    for (i = 0; i < nrec; i++) free(store[i]);
}

static size_t hello_msg(uint8_t *buf, size_t cap, const uint8_t *scope)
{
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_HELLO, scope);
    return gz_lobby_enc_done(&e);
}

/* Smaller host duties: status contents and their pacing, scope-zero hello,
 * seat states during signing, damaged records. */
static void test_host_details(void)
{
    static const uint8_t zero[32];
    uint8_t buf[600], cd2[32], other[32];
    size_t n;
    int i;
    gz_lobby_msg_t g;
    gz_lobby_input_t in;
    gz_terms_current_digest(T2, T2N, cd2);
    CLOCK = W_T0 - 3600000;
    host_open(0);
    for (i = 1; i <= 6; i++) hin(GZ_LIN_CONNECTED, i, NULL, 0);
    /* an unknown lobby: status with lobby state 0 and nothing else */
    memcpy(other, SCOPE, 32); other[5] ^= 1;
    n = hello_msg(buf, sizeof buf, other);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 0 && status_to(1, &g));
    CHECK(g.lobby_state == 0 && g.seat_state == 0 && g.version == 0 && g.joined == 0 && g.ready == 0 && !g.has_reason);
    /* scope zero: an unlisted lobby is never named */
    CLOCK += 1000;
    n = hello_msg(buf, sizeof buf, zero);
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && A.l.count == 0);
    CLOCK += 1000;
    H.cfg.listed = 1;                                   /* listed: at most 4 answers a second in all */
    for (i = 3; i <= 6; i++) { hin(GZ_LIN_MESSAGE, i, buf, n); CHECK(sends(GZ_KIND_TERMS_OFFER) == 1); }
    hin(GZ_LIN_MESSAGE, 1, buf, n);
    CHECK(A.l.count == 0);
    CLOCK += 1000;
    hin(GZ_LIN_MESSAGE, 1, buf, n);
    CHECK(sends(GZ_KIND_TERMS_OFFER) == 1);
    H.cfg.listed = 0;
    /* broadcasts reach every seat, the first connection too, at most once a second */
    n = join_msg(buf, sizeof buf, 1, MEM[1].key[3].pub, 1, 1);
    hin(GZ_LIN_MESSAGE, 1, buf, n);
    CLOCK += 1000;
    n = join_msg(buf, sizeof buf, 2, MEM[2].key[3].pub, 2, 2);
    hin(GZ_LIN_MESSAGE, 2, buf, n);
    CHECK(status_to(1, &g) && g.joined == 2 && g.seat_state == GZ_SEAT_JOINED && timers(GZ_LOBBY_TIMER_STATUS) == 0);
    n = ready_msg(buf, sizeof buf, 2, 1, cd2, NULL, 0);           /* in the same millisecond */
    hin(GZ_LIN_MESSAGE, 2, buf, n);
    CHECK(!status_to(1, &g) && timers(GZ_LOBBY_TIMER_STATUS) == 1);   /* member 1 waits */
    {
        size_t q;
        for (q = 0; q < A.l.count; q++)
            if (A.s[q].kind == GZ_ACTION_SET_TIMER) CHECK(A.s[q].u.set_timer.delay_ms == 1000);
    }
    CLOCK += 1000;
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_STATUS;
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && status_to(1, &g) && g.ready == 1 && !status_to(2, &g));
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && A.l.count == 0);   /* nothing left waiting */
    /* the deadline timer before the deadline sets itself again */
    in.timer_id = GZ_LOBBY_TIMER_DEADLINE;
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && timers(GZ_LOBBY_TIMER_DEADLINE) == 1);
    CHECK(A.s[0].u.set_timer.delay_ms == 1794441600000ull - CLOCK);
    /* to the start: four ready, one asks for at least 5 */
    for (i = 3; i <= 4; i++) {
        CLOCK += 1000;
        n = join_msg(buf, sizeof buf, i, MEM[i].key[3].pub, i, i);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    for (i = 1; i <= 4; i++) {
        n = ready_msg(buf, sizeof buf, i, 1, cd2, NULL, (uint16_t)(i == 4 ? 5 : 0));
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CLOCK = 1794441600000ull;
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_READY_CHECK) == 4);
    {
        uint8_t chk[32];
        const uint8_t *raw;
        size_t rawn, q;
        last_sent(GZ_KIND_READY_CHECK, &g, &raw, &rawn);
        memcpy(chk, g.check_id, 32);
        CHECK(g.version == 1 && memcmp(g.current_digest, cd2, 32) == 0 && g.answer_within_ms == 30000);
        CHECK(gz_la_verified(&H.crypto, raw, &g, HOST.key[1].pub));
        for (q = 0; q < A.l.count; q++)        /* freeze: check id, version, digest, the signed check */
            if (A.s[q].kind == GZ_ACTION_SAVE && A.s[q].u.save.records[0].type == GZ_REC_FREEZE) {
                const uint8_t *r = A.s[q].u.save.records[0].bytes.data;
                CHECK(A.s[q].u.save.records[0].bytes.len == 70 + rawn && memcmp(r, chk, 32) == 0);
                CHECK(r[35] == 1 && memcmp(r + 36, cd2, 32) == 0 && memcmp(r + 70, raw, rawn) == 0);
            }
        for (i = 1; i <= 4; i++) {
            n = ready_msg(buf, sizeof buf, i, 1, cd2, chk, (uint16_t)(i == 4 ? 5 : 0));
            hin(GZ_LIN_MESSAGE, i, buf, n);
            CHECK(status_to(i, &g) && g.lobby_state == GZ_LOBBY_READY_CHECK);
        }
    }
    CLOCK += 2000;
    in.timer_id = GZ_LOBBY_TIMER_WINDOW;
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_START) == 4 && H.state == GZ_LOBBY_SIGNING);
    CHECK(status_to(1, &g) && g.lobby_state == GZ_LOBBY_SIGNING && g.seat_state == GZ_SEAT_CHOSEN);   /* told at once */
    CHECK(status_to(4, &g) && g.lobby_state == GZ_LOBBY_SIGNING && g.seat_state == GZ_SEAT_NOT_CHOSEN);
    CHECK(before(GZ_KIND_START, GZ_REC_START_SENT));
    {
        gz_lobby_msg_t st;
        int role[5] = {0, 0, 0, 0, 0};
        size_t q;
        for (q = 0; q < A.l.count; q++)
            if (kind_of(&A.s[q]) == GZ_KIND_START) {
                gz_lobby_decode(A.s[q].u.send.bytes.data, A.s[q].u.send.bytes.len, &st);
                role[A.s[q].u.send.peer_id - 1000] = st.role;
                CHECK(st.signers == 4);
            }
        CHECK(role[1] == 1 && role[2] == 1 && role[3] == 1 && role[4] == 2);
    }
    /* seat states during signing: chosen 3, not chosen 4; the start resent to the chosen only */
    CLOCK += 2000;
    for (i = 1; i <= 4; i++) {
        n = hello_msg(buf, sizeof buf, SCOPE);
        hin(GZ_LIN_MESSAGE, i, buf, n);
        CHECK(status_to(i, &g) && g.lobby_state == GZ_LOBBY_SIGNING && g.seat_state == (i < 4 ? GZ_SEAT_CHOSEN : GZ_SEAT_NOT_CHOSEN));
        CHECK(sends(GZ_KIND_START) == (i < 4));
    }
    /* a chosen seat's unready is ignored; a standby's ready is answered and changes nothing */
    {
        uint8_t un[64];
        gz_lobby_enc_t e;
        gz_lobby_enc_start(&e, un, sizeof un, GZ_KIND_UNREADY, SCOPE);
        CHECK(hin(GZ_LIN_MESSAGE, 1, un, gz_lobby_enc_done(&e)) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_CHOSEN);
    }
    /* the end: cancel, and the reason in every later status */
    acts_reset();
    CHECK(gz_lobby_host_cancel(&H, 0, &A.l) == GZ_ERR_ARGUMENT && gz_lobby_host_cancel(&H, 4, &A.l) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_host_cancel(&H, 3, &A.l) == GZ_OK && H.state == GZ_LOBBY_FAILED && sends(GZ_KIND_CANCEL) == 4);
    CLOCK += 2000;
    n = hello_msg(buf, sizeof buf, SCOPE);
    hin(GZ_LIN_MESSAGE, 2, buf, n);
    CHECK(status_to(2, &g) && g.lobby_state == GZ_LOBBY_FAILED && g.has_reason && g.reason == 3 && sends(GZ_KIND_CANCEL) == 1);
    hin(GZ_LIN_MESSAGE, 5, buf, n);                     /* a connection with no seat: the state, not the cancel */
    CHECK(status_to(5, &g) && g.lobby_state == GZ_LOBBY_FAILED && sends(GZ_KIND_CANCEL) == 0);
    acts_reset();
    CHECK(gz_lobby_host_cancel(&H, 2, &A.l) == GZ_OK && refused(GZ_CMD_CANCEL) && !any_save());
    CHECK(gz_lobby_host_remove(&H, MEM[1].key[2].pub, &A.l) == GZ_OK && refused(GZ_CMD_REMOVE) && !any_save());
    /* damaged records of every type stop a start, at every short length */
    {
        static gz_lobby_host_t H2;
        static gz_lobby_member_t M2;
        gz_ports_t p = ports();
        gz_lobby_crypto_t cr = lt_crypto(&HOST);
        gz_lobby_host_config_t cfg;
        gz_lobby_conditions_t cond = lt_cond_fits();
        uint32_t t;
        size_t len;
        int bad_host = 0, bad_member = 0;
        memset(&cfg, 0, sizeof cfg);
        for (t = GZ_REC_LOBBY_OPENED; t <= GZ_REC_LOBBY_STATE; t += 2) {
            for (len = 0; len < 3 * 140; len++) {   /* three fillings, lengths 0 to 139, exactly that long */
                gz_record_t r;
                size_t fill = len / 140, rl = len % 140;
                uint8_t *b = malloc(rl ? rl : 1);
                memset(b, fill == 0 ? 0xff : 0, rl ? rl : 1);
                if (fill == 2 && rl > 1) b[1] = 3;           /* a short blob length where one is read */
                r.type = t; r.bytes.data = b; r.bytes.len = rl;
                gz_lobby_host_init(&H2, &p, &cr, NULL, &cfg);
                if (gz_lobby_host_restore(&H2, &r) != GZ_ERR_CORRUPT && t != GZ_REC_TERMS_RECEIVED &&
                    t != GZ_REC_JOINED && t != GZ_REC_READY_SENT && t != GZ_REC_HOST_FAULT && t != GZ_REC_START_RECEIVED)
                    { bad_host++; printf("  host accepted damaged record %x of %zu bytes\n", (unsigned)t, rl); }
                gz_lobby_member_init(&M2, &p, &cr, NULL, &cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1);
                if (gz_lobby_member_restore(&M2, &r) != GZ_ERR_CORRUPT &&
                    (t == GZ_REC_TERMS_RECEIVED || t == GZ_REC_FREEZE ||
                     (t == GZ_REC_LOBBY_ENDED && !(fill > 0 && rl == 5)) ||   /* zeros, 5 bytes: a member's own leave */
                     (t == GZ_REC_READY_SENT && rl > 1) || (t == GZ_REC_START_RECEIVED && rl > 0)))
                    { bad_member++; printf("  member accepted damaged record %x of %zu bytes\n", (unsigned)t, rl); }
                free(b);
            }
        }
        CHECK(bad_host == 0 && bad_member == 0);
    }
}

/* Only a Ready seat's reconnect is a seat event (decision 8; b21): after a
 * check that started nobody and saw no change, a Joined seat that reconnects
 * starts no new check, and a Ready one does. */
static void test_reconnect_joined(void)
{
    uint8_t buf[600], cd2[32];
    size_t n;
    int i;
    gz_lobby_input_t in;
    gz_terms_current_digest(T2, T2N, cd2);
    CLOCK = W_T0 - 3600000;
    host_open(1);                                     /* one standby place: nine seats */
    for (i = 1; i <= 9; i++) {
        hin(GZ_LIN_CONNECTED, i, NULL, 0);
        CLOCK += 1000;
        n = join_msg(buf, sizeof buf, i, MEM[i].key[3].pub, i, i);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    for (i = 1; i <= 8; i++) {                        /* member 9 stays Joined */
        n = ready_msg(buf, sizeof buf, i, 1, cd2, NULL, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CHECK(H.state == GZ_LOBBY_READY_CHECK && H.n_seats == 9);
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_WINDOW;
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_START) == 0 &&
          sends(GZ_KIND_READY_CHECK) == 0 && H.state == GZ_LOBBY_OPEN);
    hin(GZ_LIN_DISCONNECTED, 9, NULL, 0);
    CHECK(hin(GZ_LIN_CONNECTED, 9, NULL, 0) == GZ_OK && sends(GZ_KIND_READY_CHECK) == 0 && H.state == GZ_LOBBY_OPEN);
    hin(GZ_LIN_DISCONNECTED, 1, NULL, 0);
    CHECK(hin(GZ_LIN_CONNECTED, 1, NULL, 0) == GZ_OK && sends(GZ_KIND_READY_CHECK) > 0 && H.state == GZ_LOBBY_READY_CHECK);
}

/* The ready check: an answer withdrawn by unready no longer counts; a failed
 * check before the deadline leaves the lobby Open, and the next change starts
 * a new check with a new identifier. */
static void test_host_checks(void)
{
    uint8_t buf[600], cd2[32], chk[32], un[64];
    size_t n, unn;
    int i;
    gz_lobby_msg_t g;
    gz_lobby_input_t in;
    gz_lobby_enc_t e;
    gz_terms_current_digest(T2, T2N, cd2);
    gz_lobby_enc_start(&e, un, sizeof un, GZ_KIND_UNREADY, SCOPE);
    unn = gz_lobby_enc_done(&e);
    CLOCK = W_T0 - 3600000;
    host_open(0);
    for (i = 1; i <= 8; i++) {
        hin(GZ_LIN_CONNECTED, i, NULL, 0);
        CLOCK += 1000;
        n = join_msg(buf, sizeof buf, i, MEM[i].key[3].pub, i, i);
        hin(GZ_LIN_MESSAGE, i, buf, n);
        n = ready_msg(buf, sizeof buf, i, 1, cd2, NULL, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
        CHECK(sends(GZ_KIND_READY_CHECK) == (i == 8 ? 8 : 0));     /* the target starts the check at once */
    }
    CHECK(H.state == GZ_LOBBY_READY_CHECK && last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL));
    memcpy(chk, g.check_id, 32);
    n = ready_msg(buf, sizeof buf, 1, 1, cd2, chk, 0);
    hin(GZ_LIN_MESSAGE, 1, buf, n);                                 /* answers, */
    CHECK(sends(GZ_KIND_READY_CHECK) == 0);                          /* (no second check while one is open) */
    hin(GZ_LIN_MESSAGE, 1, un, unn);                                /* withdraws, */
    CHECK(sends(GZ_KIND_READY_CHECK) == 0 && saves(GZ_REC_SEAT) == 1);
    n = ready_msg(buf, sizeof buf, 1, 1, cd2, NULL, 0);
    hin(GZ_LIN_MESSAGE, 1, buf, n);                                 /* and is ready again without answering */
    CHECK(sends(GZ_KIND_READY_CHECK) == 0);
    for (i = 2; i <= 3; i++) {
        n = ready_msg(buf, sizeof buf, i, 1, cd2, chk, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
        CHECK(sends(GZ_KIND_READY_CHECK) == 0 && !any_save());
    }
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_WINDOW;
    acts_reset();
    /* Member 1 changed during that check, so the rule is applied again as the
     * window closes: a new check at once, with a new identifier (b20). */
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_START) == 0 && sends(GZ_KIND_CANCEL) == 0);
    CHECK(H.state == GZ_LOBBY_READY_CHECK && H.frozen && !any_save() && sends(GZ_KIND_READY_CHECK) == 8);
    CHECK(last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL) && memcmp(g.check_id, chk, 32) != 0);
    memcpy(chk, g.check_id, 32);
    {   /* frozen for ever: no new values */
        uint64_t v[3] = {600, 1000, 1000};
        acts_reset();
        CHECK(gz_lobby_host_set_values(&H, v, 3, &A.l) == GZ_OK && A.l.count == 1 && refused(GZ_CMD_SET_VALUES));
    }
    /* after a check in which nothing changed, nothing starts one until a change */
    CLOCK += 5000;
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_START) == 0 && H.state == GZ_LOBBY_OPEN);
    CHECK(sends(GZ_KIND_READY_CHECK) == 0);
    n = ready_msg(buf, sizeof buf, 4, 1, cd2, NULL, 0);
    CHECK(hin(GZ_LIN_MESSAGE, 4, buf, n) == GZ_OK && sends(GZ_KIND_READY_CHECK) == 0);   /* a duplicate */
    /* a ready seat that comes back on a new connection is counted again: a check */
    hin(GZ_LIN_DISCONNECTED, 4, NULL, 0);
    CHECK(A.l.count == 0);
    hin(GZ_LIN_CONNECTED, 4, NULL, 0);
    CHECK(sends(GZ_KIND_READY_CHECK) == 8);
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_START) == 0 && H.state == GZ_LOBBY_OPEN);
    hin(GZ_LIN_MESSAGE, 5, un, unn);
    CHECK(sends(GZ_KIND_READY_CHECK) == 0);                          /* 7 ready: below the target */
    n = ready_msg(buf, sizeof buf, 5, 1, cd2, NULL, 0);
    CHECK(hin(GZ_LIN_MESSAGE, 5, buf, n) == GZ_OK && sends(GZ_KIND_READY_CHECK) == 8 && saves(GZ_REC_FREEZE) == 0);
    CHECK(last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL) && memcmp(g.check_id, chk, 32) != 0 && g.version == 1);
    /* no standby seats: a join during the check is refused, the seat is not made */
    hin(GZ_LIN_CONNECTED, 9, NULL, 0);
    CLOCK += 1000;
    n = join_msg(buf, sizeof buf, 9, MEM[9].key[3].pub, 9, 9);
    CHECK(hin(GZ_LIN_MESSAGE, 9, buf, n) == GZ_OK && status_seat() == GZ_SEAT_REFUSED && !any_save() && H.n_seats == 8);
    /* a removal during the check: the seat gets no start */
    acts_reset();
    CHECK(gz_lobby_host_remove(&H, MEM[2].key[2].pub, &A.l) == GZ_OK && saves(GZ_REC_SEAT) == 1);
    memcpy(chk, g.check_id, 32);
    for (i = 1; i <= 8; i++) {                                       /* member 3, an answer last time, is silent */
        if (i == 3) continue;
        n = ready_msg(buf, sizeof buf, i, 1, cd2, chk, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    n = ready_msg(buf, sizeof buf, 4, 1, cd2, NULL, 2);              /* a later ready without the check: */
    CHECK(hin(GZ_LIN_MESSAGE, 4, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1);   /* its answer stands */
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_START) == 6 && H.state == GZ_LOBBY_SIGNING);
    {
        size_t q;
        for (q = 0; q < A.l.count; q++)
            CHECK(kind_of(&A.s[q]) != GZ_KIND_START || (A.s[q].u.send.peer_id != W_PEER(2) && A.s[q].u.send.peer_id != W_PEER(3)));
        /* start_sent: the check, then each started seat's key and its exact start bytes */
        for (q = 0; q < A.l.count; q++)
            if (A.s[q].kind == GZ_ACTION_SAVE && A.s[q].u.save.records[0].type == GZ_REC_START_SENT) {
                const uint8_t *r = A.s[q].u.save.records[0].bytes.data;
                size_t rl = A.s[q].u.save.records[0].bytes.len, at = 42, k, sent = 0;
                CHECK(memcmp(r, chk, 32) == 0 && gz_lw_get(r + 32, 8) == CLOCK && r[40] == 0 && r[41] == 6);
                for (k = 0; k < 6 && at + 35 <= rl; k++) {
                    const uint8_t *b; size_t bn, j;
                    at += 33;
                    CHECK(gz_la_get_blob(r, rl, &at, &b, &bn));
                    for (j = 0; j < A.l.count; j++)
                        if (kind_of(&A.s[j]) == GZ_KIND_START && A.s[j].u.send.bytes.len == bn &&
                            memcmp(A.s[j].u.send.bytes.data, b, bn) == 0 &&
                            memcmp(r + at - bn - 2 - 33, MEM[A.s[j].u.send.peer_id - 1000].key[2].pub, 33) == 0)
                            sent++;
                }
                CHECK(sent == 6 && at == rl);
                {   /* the same record with a budget of 0 is damaged (b14) */
                    uint8_t *z = malloc(rl);
                    gz_record_t rec;
                    uint64_t budget = H.budget_ms;
                    CHECK(z != NULL);
                    memcpy(z, r, rl);
                    memset(z + 32, 0, 8);
                    rec.type = GZ_REC_START_SENT; rec.bytes.data = z; rec.bytes.len = rl;
                    CHECK(gz_lobby_host_restore(&H, &rec) == GZ_ERR_CORRUPT);
                    H.budget_ms = budget;                       /* the rest it rewrote is the same */
                    free(z);
                }
            }
    }
    /* the window timer again: nothing (the check is closed) */
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && A.l.count == 0);
    /* with a standby seat, a late arrival joins during signing and is shown as it is */
    H.cfg.standbys = 1;
    hin(GZ_LIN_CONNECTED, 10, NULL, 0);
    CLOCK += 1000;
    n = join_msg(buf, sizeof buf, 10, MEM[10].key[3].pub, 10, 10);
    CHECK(hin(GZ_LIN_MESSAGE, 10, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_to(10, &g));
    CHECK(g.lobby_state == GZ_LOBBY_SIGNING && g.seat_state == GZ_SEAT_JOINED);
    n = ready_msg(buf, sizeof buf, 10, 1, cd2, NULL, 0);
    CHECK(hin(GZ_LIN_MESSAGE, 10, buf, n) == GZ_OK && status_seat() == GZ_SEAT_READY && saves(GZ_REC_SEAT) == 1);
    /* a chosen seat cannot change its ready while it signs, but can leave */
    n = ready_msg(buf, sizeof buf, 1, 1, cd2, NULL, 3);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_CHOSEN);
    {
        uint8_t lv[64];
        gz_lobby_enc_t e2;
        gz_lobby_enc_start(&e2, lv, sizeof lv, GZ_KIND_LEAVE, SCOPE);
        CHECK(hin(GZ_LIN_MESSAGE, 1, lv, gz_lobby_enc_done(&e2)) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_LEFT);
    }
    /* after signing, readies change nothing */
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_FUNDING, NULL, 0, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_STATE) == 1);
    n = ready_msg(buf, sizeof buf, 10, 1, cd2, NULL, 4);
    CHECK(hin(GZ_LIN_MESSAGE, 10, buf, n) == GZ_OK && !any_save() && status_to(10, &g) && g.lobby_state == GZ_LOBBY_FUNDING);
}

/* At most 4 x target seats are ever created (messages.md 6, review 3 F13), and
 * joins are closed outside Open when the lobby has no standby seats. */
static void test_host_creations(void)
{
    uint8_t buf[600], lv[64];
    size_t n, lvn;
    int c;
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, lv, sizeof lv, GZ_KIND_LEAVE, SCOPE);
    lvn = gz_lobby_enc_done(&e);
    CLOCK = W_T0 - 3600000;
    host_open(0);
    for (c = 0; c <= 32; c++) {
        int who = 1 + c % 11;
        CLOCK += 1000;
        hin(GZ_LIN_DISCONNECTED, who, NULL, 0);
        hin(GZ_LIN_CONNECTED, who, NULL, 0);
        n = join_msg(buf, sizeof buf, who, MEM[who].key[3].pub, who, who);
        hin(GZ_LIN_MESSAGE, who, buf, n);
        if (c < 32) {
            CHECK(status_seat() == GZ_SEAT_JOINED && saves(GZ_REC_SEAT) == 1);
            hin(GZ_LIN_MESSAGE, who, lv, lvn);
            CHECK(status_seat() == GZ_SEAT_LEFT);
        } else {
            CHECK(status_seat() == GZ_SEAT_REFUSED && !any_save());          /* the 33rd */
        }
    }
    CHECK(H.created == 32);
    /* the seats: the target, and no more without standbys; one leaves, one more fits */
    CLOCK = W_T0 - 3600000;
    host_open(0);
    for (c = 1; c <= 9; c++) {
        CLOCK += 1000;
        hin(GZ_LIN_CONNECTED, c, NULL, 0);
        n = join_msg(buf, sizeof buf, c, MEM[c].key[3].pub, c, c);
        hin(GZ_LIN_MESSAGE, c, buf, n);
        CHECK(status_seat() == (c <= 8 ? GZ_SEAT_JOINED : GZ_SEAT_REFUSED));
    }
    {
        gz_lobby_msg_t g;
        CHECK(status_to(9, &g) && !g.has_reason && g.joined == 8);    /* full: no reason, connection kept */
    }
    hin(GZ_LIN_MESSAGE, 1, lv, lvn);
    hin(GZ_LIN_DISCONNECTED, 9, NULL, 0);
    hin(GZ_LIN_CONNECTED, 9, NULL, 0);
    CLOCK += 1000;
    n = join_msg(buf, sizeof buf, 9, MEM[9].key[3].pub, 9, 9);
    CHECK(hin(GZ_LIN_MESSAGE, 9, buf, n) == GZ_OK && status_seat() == GZ_SEAT_JOINED);
}

/* The signers are taken in order of joining, which is not the order of the
 * seat table once a seat has left and joined again. */
static uint8_t ORDER[GZ_LOBBY_MAX_SEATS + 1][33];
static int N_ORDER;
static gz_status_t order_begin(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out)
{
    uint16_t i;
    (void)ctx; (void)out;
    N_ORDER = h->n_participants;
    for (i = 0; i < h->n_participants && i <= GZ_LOBBY_MAX_SEATS; i++) memcpy(ORDER[i], h->participants[i].contribution_key, 33);
    return GZ_OK;
}

static void test_host_order(void)
{
    uint8_t buf[600], cd2[32], lv[64], chk[32];
    size_t n, lvn;
    int i;
    gz_lobby_enc_t e;
    gz_lobby_msg_t g;
    gz_lobby_input_t in;
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(&HOST);
    gz_lobby_signing_t sg;
    gz_lobby_host_config_t cfg;
    static const int joined[4] = {2, 3, 4, 1};
    gz_terms_current_digest(T2, T2N, cd2);
    gz_lobby_enc_start(&e, lv, sizeof lv, GZ_KIND_LEAVE, SCOPE);
    lvn = gz_lobby_enc_done(&e);
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, HOST.key[3].pub, 33);
    sg.begin = order_begin; sg.cancel = NULL; sg.ctx = NULL;
    CLOCK = W_T0 - 3600000;
    gz_lobby_host_init(&H, &p, &cr, &sg, &cfg);
    acts_reset();
    gz_lobby_host_open(&H, T1, T1N, T2, T2N, &A.l);
    for (i = 1; i <= 4; i++) hin(GZ_LIN_CONNECTED, i, NULL, 0);
    CLOCK += 1000;
    n = join_msg(buf, sizeof buf, 1, MEM[1].key[3].pub, 1, 1);
    hin(GZ_LIN_MESSAGE, 1, buf, n);
    hin(GZ_LIN_MESSAGE, 1, lv, lvn);                                 /* member 1 leaves: its slot stays first */
    for (i = 2; i <= 4; i++) {
        CLOCK += 1000;
        n = join_msg(buf, sizeof buf, i, MEM[i].key[3].pub, i, i);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CLOCK += 1000;
    hin(GZ_LIN_DISCONNECTED, 1, NULL, 0);
    hin(GZ_LIN_CONNECTED, 1, NULL, 0);
    n = join_msg(buf, sizeof buf, 1, MEM[1].key[3].pub, 1, 1);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && status_seat() == GZ_SEAT_JOINED);   /* and joins again, last */
    for (i = 1; i <= 4; i++) {
        n = ready_msg(buf, sizeof buf, i, 1, cd2, NULL, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CLOCK = 1794441600000ull;
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_DEADLINE;
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL));
    memcpy(chk, g.check_id, 32);
    for (i = 4; i >= 1; i--) {                                       /* answers in another order again */
        n = ready_msg(buf, sizeof buf, i, 1, cd2, chk, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    in.timer_id = GZ_LOBBY_TIMER_WINDOW;
    acts_reset();
    N_ORDER = 0;
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_START) == 4 && N_ORDER == 5);
    CHECK(memcmp(ORDER[0], HOST.key[1].pub, 33) == 0);
    for (i = 0; i < 4; i++) CHECK(memcmp(ORDER[i + 1], MEM[joined[i]].key[2].pub, 33) == 0);
}

/* A join on the connection of `who`, the binding signed by any two keys. */
static size_t join_by(uint8_t *buf, size_t cap, int who, const uint8_t *fkey, lt_signer_t *fs, uint32_t fw,
                      lt_signer_t *cs, uint32_t cw)
{
    uint8_t b[32], sf[64], sc[64];
    gz_lobby_enc_t e;
    gz_lobby_binding(SCOPE, fkey, MEM[who].key[2].pub, b);
    lt_sign(fs, fw, b, sf);
    lt_sign(cs, cw, b, sc);
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_JOIN, SCOPE);
    gz_lobby_enc_record(&e, 2, fkey, 33);
    gz_lobby_enc_record(&e, 4, sf, 64);
    gz_lobby_enc_record(&e, 6, sc, 64);
    return gz_lobby_enc_done(&e);
}

/* Keys a seat may not use, each with a binding that verifies, so that only
 * the key rule can refuse it; and the seat table's own size. */
static void test_host_join_keys(void)
{
    uint8_t buf[600], lv[64];
    size_t n, lvn;
    int i;
    gz_lobby_msg_t g;
    gz_lobby_enc_t e;
    lt_signer_t save[3];
    gz_lobby_enc_start(&e, lv, sizeof lv, GZ_KIND_LEAVE, SCOPE);
    lvn = gz_lobby_enc_done(&e);
    CLOCK = W_T0 - 3600000;
    host_open(0);
    for (i = 1; i <= 8; i++) hin(GZ_LIN_CONNECTED, i, NULL, 0);
    CLOCK += 1000;
    n = join_msg(buf, sizeof buf, 1, MEM[1].key[3].pub, 1, 1);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && status_seat() == GZ_SEAT_JOINED);
#define REFUSED5() (status_seat() == GZ_SEAT_REFUSED && status_to(WHO, &g) && g.has_reason && g.reason == 5 && !any_save())
    CLOCK += 1000;
    n = join_by(buf, sizeof buf, 2, HOST.key[3].pub, &HOST, 3, &MEM[2], 2);        /* the host's factory key */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && REFUSED5());
    n = join_by(buf, sizeof buf, 2, HOST.key[1].pub, &HOST, 1, &MEM[2], 2);        /* the host's own key */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && REFUSED5());
    fresh(2);
    n = join_by(buf, sizeof buf, 2, MEM[2].key[2].pub, &MEM[2], 2, &MEM[2], 2);    /* the same key twice */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && REFUSED5());
    n = join_by(buf, sizeof buf, 2, MEM[1].key[2].pub, &MEM[1], 2, &MEM[2], 2);    /* seat 1's contribution key */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && REFUSED5());
    /* connections whose own key is one a seat may not have */
    save[0] = MEM[3]; save[1] = MEM[4]; save[2] = MEM[5];
    MEM[3].key[2] = HOST.key[3];                                                   /* the host's factory key */
    MEM[4].key[2] = HOST.key[1];                                                   /* the host's key */
    MEM[5].key[2] = MEM[1].key[3];                                                 /* seat 1's factory key */
    for (i = 3; i <= 5; i++) {
        hin(GZ_LIN_DISCONNECTED, i, NULL, 0);
        hin(GZ_LIN_CONNECTED, i, NULL, 0);
        n = join_by(buf, sizeof buf, i, save[i - 3].key[3].pub, &save[i - 3], 3, &MEM[i], 2);
        CHECK(hin(GZ_LIN_MESSAGE, i, buf, n) == GZ_OK && REFUSED5());
    }
    MEM[3] = save[0]; MEM[4] = save[1]; MEM[5] = save[2];
    for (i = 3; i <= 5; i++) { hin(GZ_LIN_DISCONNECTED, i, NULL, 0); hin(GZ_LIN_CONNECTED, i, NULL, 0); }
    /* and the same keys are fine once the seat that held them has left */
    hin(GZ_LIN_MESSAGE, 1, lv, lvn);
    n = join_by(buf, sizeof buf, 2, MEM[1].key[3].pub, &MEM[1], 3, &MEM[2], 2);
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && status_seat() == GZ_SEAT_JOINED);
#undef REFUSED5
    /* with a standby seat, joins are taken during a ready check too; never after signing */
    H.cfg.standbys = 1;
    H.state = GZ_LOBBY_READY_CHECK;
    CLOCK += 1000;
    n = join_msg(buf, sizeof buf, 6, MEM[6].key[3].pub, 6, 6);
    CHECK(hin(GZ_LIN_MESSAGE, 6, buf, n) == GZ_OK && status_seat() == GZ_SEAT_JOINED);
    H.state = GZ_LOBBY_FUNDING;
    CLOCK += 1000;
    n = join_msg(buf, sizeof buf, 7, MEM[7].key[3].pub, 7, 7);
    CHECK(hin(GZ_LIN_MESSAGE, 7, buf, n) == GZ_OK && status_seat() == GZ_SEAT_REFUSED && !any_save());
    H.cfg.standbys = 0;
    H.state = GZ_LOBBY_OPEN;
    CHECK(hin(GZ_LIN_MESSAGE, 7, buf, n) == GZ_OK && status_seat() == GZ_SEAT_JOINED);
    /* the seat table holds 32: with target 20, a 33rd new key finds it full */
    {
        gz_terms_outer_t o = T1O;
        gz_terms_current_t c;
        static uint8_t ob[512], cb[128];
        size_t on, cn;
        uint8_t od[32];
        gz_ports_t p = ports();
        gz_lobby_crypto_t cr = lt_crypto(&HOST);
        gz_lobby_host_config_t cfg;
        o.target = 20;
        o.shapes[1].max_members = 40;
        on = gz_terms_encode_outer(&o, ob, sizeof ob);
        gz_terms_outer_digest(ob, on, od);
        lt_current(T2, T2N, &T1O, SCOPE, &c);
        memcpy(c.outer_digest, od, 32);
        cn = gz_terms_encode_current(&c, cb, sizeof cb);
        memset(&cfg, 0, sizeof cfg);
        memcpy(cfg.factory_key, HOST.key[3].pub, 33);
        gz_lobby_host_init(&H, &p, &cr, NULL, &cfg);
        acts_reset();
        CHECK(gz_lobby_host_open(&H, ob, on, cb, cn, &A.l) == GZ_OK);
        for (i = 1; i <= 33; i++) {
            uint8_t bnd[32], sf[64], sc[64];
            gz_lobby_enc_t j;
            CLOCK += 1000;
            hin(GZ_LIN_CONNECTED, i, NULL, 0);
            gz_lobby_binding(od, MEM[i].key[3].pub, MEM[i].key[2].pub, bnd);
            lt_sign(&MEM[i], 3, bnd, sf);
            lt_sign(&MEM[i], 2, bnd, sc);
            gz_lobby_enc_start(&j, buf, sizeof buf, GZ_KIND_JOIN, od);
            gz_lobby_enc_record(&j, 2, MEM[i].key[3].pub, 33);
            gz_lobby_enc_record(&j, 4, sf, 64);
            gz_lobby_enc_record(&j, 6, sc, 64);
            n = gz_lobby_enc_done(&j);
            hin(GZ_LIN_MESSAGE, i, buf, n);
            CHECK(status_to(i, &g) && g.seat_state == (i <= 32 ? GZ_SEAT_JOINED : GZ_SEAT_REFUSED));
            gz_lobby_enc_start(&j, lv, sizeof lv, GZ_KIND_LEAVE, od);
            hin(GZ_LIN_MESSAGE, i, lv, gz_lobby_enc_done(&j));
        }
        CHECK(H.n_seats == 32 && H.created == 32);
    }
}

/* Every record the last action list saved, kept for a restart. */
static gz_record_t KEPT[256];
static uint8_t *KEPT_B[256];
static size_t N_KEPT;
static void keep_all(void)
{
    size_t i, j;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_SAVE)
            for (j = 0; j < A.s[i].u.save.n_records && N_KEPT < 256; j++) {
                KEPT[N_KEPT] = A.s[i].u.save.records[j];
                KEPT_B[N_KEPT] = malloc(KEPT[N_KEPT].bytes.len + 1);
                memcpy(KEPT_B[N_KEPT], KEPT[N_KEPT].bytes.data, KEPT[N_KEPT].bytes.len);
                KEPT[N_KEPT].bytes.data = KEPT_B[N_KEPT];
                N_KEPT++;
            }
}

static void restore_kept(gz_lobby_host_t *h)
{
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(&HOST);
    gz_lobby_host_config_t cfg;
    size_t i;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, HOST.key[3].pub, 33);
    gz_lobby_host_init(h, &p, &cr, NULL, &cfg);
    for (i = 0; i < N_KEPT; i++) CHECK(gz_lobby_host_restore(h, &KEPT[i]) == GZ_OK);
}

/* A host that restarts while its members sign: the starts come back byte for
 * byte, a chosen seat gets its start again after hello, the others do not;
 * then Funding, Active, and a retry that reopens the lobby, each restored. */
static void test_host_restart_signing(void)
{
    static gz_lobby_host_t R;
    uint8_t buf[600], cd2[32], chk[32], starts[5][200];
    size_t n, slen[5], i;
    int k;
    gz_lobby_msg_t g;
    gz_lobby_input_t in;
    gz_terms_current_digest(T2, T2N, cd2);
    N_KEPT = 0;
    CLOCK = W_T0 - 3600000;
    host_open(0); keep_all();
    for (k = 1; k <= 4; k++) {
        hin(GZ_LIN_CONNECTED, k, NULL, 0);
        CLOCK += 1000;
        n = join_msg(buf, sizeof buf, k, MEM[k].key[3].pub, k, k);
        hin(GZ_LIN_MESSAGE, k, buf, n); keep_all();
        n = ready_msg(buf, sizeof buf, k, 1, cd2, NULL, (uint16_t)(k == 4 ? 5 : 0));
        hin(GZ_LIN_MESSAGE, k, buf, n); keep_all();
    }
    CLOCK = 1794441600000ull;
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_DEADLINE;
    acts_reset();
    gz_lobby_host_handle(&H, &in, &A.l); keep_all();
    last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL);
    memcpy(chk, g.check_id, 32);
    for (k = 1; k <= 4; k++) {
        n = ready_msg(buf, sizeof buf, k, 1, cd2, chk, (uint16_t)(k == 4 ? 5 : 0));
        hin(GZ_LIN_MESSAGE, k, buf, n); keep_all();
    }
    in.timer_id = GZ_LOBBY_TIMER_WINDOW;
    acts_reset();
    CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_START) == 4);
    keep_all();
    memset(slen, 0, sizeof slen);
    for (i = 0; i < A.l.count; i++)
        if (kind_of(&A.s[i]) == GZ_KIND_START) {
            k = (int)(A.s[i].u.send.peer_id - 1000);
            memcpy(starts[k], A.s[i].u.send.bytes.data, A.s[i].u.send.bytes.len);
            slen[k] = A.s[i].u.send.bytes.len;
        }
    /* the restart */
    restore_kept(&R);
    CHECK(R.state == GZ_LOBBY_SIGNING && R.frozen && memcmp(R.check_id, chk, 32) == 0);
    for (k = 1; k <= 4; k++) {
        const gz_lobby_seat_t *s = &R.seats[k - 1];
        CHECK(s->start_len == slen[k] && memcmp(s->start_msg, starts[k], slen[k]) == 0 && s->chosen == (k < 4));
    }
    acts_reset();
    CHECK(gz_lobby_host_resume(&R, &A.l) == GZ_OK && timers(GZ_LOBBY_TIMER_DEADLINE) == 1);   /* signing: the deadline too (B4) */
    CHECK(A.l.count == 6 && seated_notes(NULL, 1) == 4);           /* the seats again, for the transport */
    CHECK(timers(GZ_LOBBY_TIMER_BUDGET) == 1);                     /* and the signing budget's timer (F3) */
    for (k = 1; k <= 4; k++) {
        gz_lobby_input_t c;
        memset(&c, 0, sizeof c);
        c.kind = GZ_LIN_CONNECTED; c.peer_id = W_PEER(k); c.peer_key = MEM[k].key[2].pub;
        acts_reset();
        gz_lobby_host_handle(&R, &c, &A.l);
        n = hello_msg(buf, sizeof buf, SCOPE);
        c.kind = GZ_LIN_MESSAGE; c.bytes = buf; c.len = n;
        acts_reset();
        CHECK(gz_lobby_host_handle(&R, &c, &A.l) == GZ_OK);
        CHECK(sends(GZ_KIND_START) == (k < 4));
        if (k < 4) {
            const uint8_t *raw; size_t rn;
            CHECK(last_sent(GZ_KIND_START, &g, &raw, &rn) && rn == slen[k] && memcmp(raw, starts[k], rn) == 0);
        }
    }
    /* Funding and Active come back; so does Open after a retry */
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_FUNDING, NULL, 0, &A.l) == GZ_OK); keep_all();
    restore_kept(&R);
    CHECK(R.state == GZ_LOBBY_FUNDING);
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_ACTIVE, NULL, 0, &A.l) == GZ_OK); keep_all();
    restore_kept(&R);
    CHECK(R.state == GZ_LOBBY_ACTIVE);
    for (i = 0; i < N_KEPT; i++) free(KEPT_B[i]);
    /* a retry */
    N_KEPT = 0;
    CLOCK = W_T0 - 3600000;
    host_open(0); keep_all();
    {
        uint8_t st = GZ_LOBBY_OPEN;
        gz_record_t r;
        r.type = GZ_REC_LOBBY_STATE; r.bytes.data = &st; r.bytes.len = 1;
        restore_kept(&R);
        CHECK(gz_lobby_host_restore(&R, &r) == GZ_OK && R.state == GZ_LOBBY_OPEN);
        st = GZ_LOBBY_SIGNING;
        CHECK(gz_lobby_host_restore(&R, &r) == GZ_ERR_CORRUPT);
        st = GZ_LOBBY_CANCELLED;
        CHECK(gz_lobby_host_restore(&R, &r) == GZ_ERR_CORRUPT);
        st = GZ_LOBBY_ACTIVE;
        CHECK(gz_lobby_host_restore(&R, &r) == GZ_OK && R.state == GZ_LOBBY_ACTIVE);
    }
    for (i = 0; i < N_KEPT; i++) free(KEPT_B[i]);
    N_KEPT = 0;
}

/* The host's commands at the edges of when they apply. */
/* `first_min`: the min_members of the first seat to join, in both readies. */
static void drive_to_signing(int members, uint16_t first_min)
{
    uint8_t buf[600], cd2[32], chk[32];
    size_t n;
    int k;
    gz_lobby_msg_t g;
    gz_lobby_input_t in;
    gz_terms_current_digest(T2, T2N, cd2);
    CLOCK = W_T0 - 3600000;
    for (k = 0; k < (int)N_KEPT; k++) free(KEPT_B[k]);
    N_KEPT = 0;
    host_open(0); keep_all();
    for (k = 1; k <= members; k++) {
        hin(GZ_LIN_CONNECTED, k, NULL, 0);
        CLOCK += 1000;
        n = join_msg(buf, sizeof buf, k, MEM[k].key[3].pub, k, k);
        hin(GZ_LIN_MESSAGE, k, buf, n); keep_all();
        n = ready_msg(buf, sizeof buf, k, 1, cd2, NULL, k == 1 ? first_min : 0);
        hin(GZ_LIN_MESSAGE, k, buf, n); keep_all();
    }
    CLOCK = 1794441600000ull;
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_DEADLINE;
    acts_reset();
    gz_lobby_host_handle(&H, &in, &A.l); keep_all();
    last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL);
    memcpy(chk, g.check_id, 32);
    for (k = 1; k <= members; k++) {
        n = ready_msg(buf, sizeof buf, k, 1, cd2, chk, k == 1 ? first_min : 0);
        hin(GZ_LIN_MESSAGE, k, buf, n); keep_all();
    }
    in.timer_id = GZ_LOBBY_TIMER_WINDOW;
    acts_reset();
    gz_lobby_host_handle(&H, &in, &A.l); keep_all();
}

static void test_host_commands(void)
{
    uint8_t failed[3 * 33], lv[64];
    gz_lobby_msg_t g;
    gz_lobby_enc_t e;
    /* cancel while Open, by the host's choice; reason 1 is the host's to give too */
    CLOCK = W_T0 - 3600000;
    host_open(0);
    hin(GZ_LIN_CONNECTED, 1, NULL, 0);
    acts_reset();
    CHECK(gz_lobby_host_cancel(&H, 2, &A.l) == GZ_OK && H.state == GZ_LOBBY_CANCELLED && H.end_reason == 2 && saves(GZ_REC_LOBBY_ENDED) == 1);
    host_open(0);
    acts_reset();
    CHECK(gz_lobby_host_cancel(&H, 1, &A.l) == GZ_OK && H.end_reason == 1);
    /* signing: no removal, no cancel reason out of range; a retry naming two seats and one unknown */
    drive_to_signing(5, 0);
    CHECK(H.state == GZ_LOBBY_SIGNING && sends(GZ_KIND_START) == 5);
    acts_reset();
    CHECK(gz_lobby_host_remove(&H, MEM[1].key[2].pub, &A.l) == GZ_OK && A.l.count == 1 && refused(GZ_CMD_REMOVE));
    memcpy(failed, MEM[2].key[2].pub, 33);
    memcpy(failed + 33, MEM[11].key[2].pub, 33);                     /* no such seat */
    memcpy(failed + 66, MEM[4].key[2].pub, 33);
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_RETRY, NULL, 2, &A.l) == GZ_ERR_ARGUMENT);
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_RETRY, failed, 3, &A.l) == GZ_OK && H.state == GZ_LOBBY_READY_CHECK);
    CHECK(saves(GZ_REC_SEAT) == 2 && saves(GZ_REC_LOBBY_STATE) == 1);
    CHECK(H.seats[1].state == GZ_SEAT_JOINED && H.seats[3].state == GZ_SEAT_JOINED && H.seats[0].state == GZ_SEAT_READY);
    CHECK(sends(GZ_KIND_READY_CHECK) == 5);                          /* past the deadline: a new check at once */
    keep_all();
    {   /* the second attempt: 1, 3 and 5 answer and are started; a restart takes the second start, not the first */
        uint8_t buf[600], cd2[32], chk[32];
        size_t n;
        int k;
        gz_lobby_input_t in;
        static gz_lobby_host_t R;
        gz_terms_current_digest(T2, T2N, cd2);
        last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL);
        memcpy(chk, g.check_id, 32);
        for (k = 1; k <= 5; k += 2) {
            n = ready_msg(buf, sizeof buf, k, 1, cd2, chk, 0);
            hin(GZ_LIN_MESSAGE, k, buf, n); keep_all();
        }
        memset(&in, 0, sizeof in);
        in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_WINDOW;
        acts_reset();
        CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_START) == 3);
        keep_all();
        restore_kept(&R);
        CHECK(R.state == GZ_LOBBY_SIGNING && memcmp(R.check_id, chk, 32) == 0);
        for (k = 1; k <= 5; k++) {
            CHECK(R.seats[k - 1].chosen == (k % 2 == 1));
            CHECK((R.seats[k - 1].start_len > 0) == (k % 2 == 1));
            CHECK(R.seats[k - 1].state == (k % 2 == 1 ? GZ_SEAT_READY : GZ_SEAT_JOINED));
        }
    }
    /* a retry is only for signing; a failed round ends the lobby, reason 3 */
    drive_to_signing(3, 0);
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_FUNDING, NULL, 0, &A.l) == GZ_OK);
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_RETRY, failed, 1, &A.l) == GZ_OK && refused(GZ_CMD_ROUND_RESULT));
    CHECK(gz_lobby_host_round_result(&H, 99, NULL, 0, &A.l) == GZ_ERR_ARGUMENT);
    drive_to_signing(3, 0);
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_FAILED, NULL, 0, &A.l) == GZ_OK && H.state == GZ_LOBBY_FAILED);
    CHECK(H.end_reason == 3 && last_sent(GZ_KIND_CANCEL, &g, NULL, NULL) && g.reason == 3);
    /* the first seat to join asks for more members than there are: it is the one left out */
    drive_to_signing(4, 5);
    CHECK(H.state == GZ_LOBBY_SIGNING && sends(GZ_KIND_START) == 4 && !H.seats[0].chosen && H.seats[1].chosen);
    {
        gz_lobby_msg_t st;
        CHECK(last_sent(GZ_KIND_START, &st, NULL, NULL) && st.signers == 4);
    }
    /* a seat that has left cannot be removed */
    CLOCK = W_T0 - 3600000;
    host_open(0);
    hin(GZ_LIN_CONNECTED, 1, NULL, 0);
    {
        uint8_t buf[600];
        size_t n = join_msg(buf, sizeof buf, 1, MEM[1].key[3].pub, 1, 1);
        hin(GZ_LIN_MESSAGE, 1, buf, n);
    }
    gz_lobby_enc_start(&e, lv, sizeof lv, GZ_KIND_LEAVE, SCOPE);
    hin(GZ_LIN_MESSAGE, 1, lv, gz_lobby_enc_done(&e));
    acts_reset();
    CHECK(gz_lobby_host_remove(&H, MEM[1].key[2].pub, &A.l) == GZ_OK && refused(GZ_CMD_REMOVE));
}

/* The 4 x target creation limit counts creations, rejoins included, and a
 * restarted host counts them from its records. */
static void test_host_creations_restart(void)
{
    uint8_t buf[600], lv[64];
    size_t n, lvn, i;
    int c;
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, lv, sizeof lv, GZ_KIND_LEAVE, SCOPE);
    lvn = gz_lobby_enc_done(&e);
    for (i = 0; i < N_KEPT; i++) free(KEPT_B[i]);
    N_KEPT = 0;
    CLOCK = W_T0 - 3600000;
    host_open(0); keep_all();
    for (c = 0; c < 31; c++) {
        int who = 1 + c % 11;
        CLOCK += 1000;
        hin(GZ_LIN_DISCONNECTED, who, NULL, 0);
        hin(GZ_LIN_CONNECTED, who, NULL, 0);
        n = join_msg(buf, sizeof buf, who, MEM[who].key[3].pub, who, who);
        hin(GZ_LIN_MESSAGE, who, buf, n); keep_all();
        CHECK(status_seat() == GZ_SEAT_JOINED);
        hin(GZ_LIN_MESSAGE, who, lv, lvn); keep_all();
    }
    CHECK(H.created == 31 && H.n_seats == 11);
    restore_kept(&H);
    CHECK(H.created == 31 && H.n_seats == 11);
    acts_reset();
    gz_lobby_host_resume(&H, &A.l);
    CLOCK += 1000;
    hin(GZ_LIN_CONNECTED, 12, NULL, 0);
    n = join_msg(buf, sizeof buf, 12, MEM[12].key[3].pub, 12, 12);
    CHECK(hin(GZ_LIN_MESSAGE, 12, buf, n) == GZ_OK && status_seat() == GZ_SEAT_JOINED);   /* the 32nd */
    CLOCK += 1000;
    hin(GZ_LIN_CONNECTED, 13, NULL, 0);
    n = join_msg(buf, sizeof buf, 13, MEM[13].key[3].pub, 13, 13);
    CHECK(hin(GZ_LIN_MESSAGE, 13, buf, n) == GZ_OK && status_seat() == GZ_SEAT_REFUSED && !any_save());   /* the 33rd */
    for (i = 0; i < N_KEPT; i++) free(KEPT_B[i]);
    N_KEPT = 0;
}

/* Arguments, inputs from nowhere, and records a host must not open with. */
static void test_api_edges(void)
{
    static gz_lobby_host_t h2;
    static gz_lobby_member_t m2;
    gz_ports_t p = ports(), bad;
    gz_lobby_crypto_t cr = lt_crypto(&HOST), crb;
    gz_lobby_host_config_t cfg;
    gz_lobby_conditions_t cond = lt_cond_fits();
    gz_lobby_input_t in;
    uint8_t buf[700], other[32], big[GZ_TERMS_OUTER_MAX + 2];
    size_t n;
    int i;
    uint64_t v[3] = {1, 1, 100};
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, HOST.key[3].pub, 33);
    /* host: every pointer, every port */
    CHECK(gz_lobby_host_init(NULL, &p, &cr, NULL, &cfg) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_host_init(&h2, NULL, &cr, NULL, &cfg) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_host_init(&h2, &p, NULL, NULL, &cfg) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_host_init(&h2, &p, &cr, NULL, NULL) == GZ_ERR_ARGUMENT);
    crb = cr; crb.verify = NULL; CHECK(gz_lobby_host_init(&h2, &p, &crb, NULL, &cfg) == GZ_ERR_ARGUMENT);
    crb = cr; crb.sign = NULL; CHECK(gz_lobby_host_init(&h2, &p, &crb, NULL, &cfg) == GZ_ERR_ARGUMENT);
    crb = cr; crb.point_ok = NULL; CHECK(gz_lobby_host_init(&h2, &p, &crb, NULL, &cfg) == GZ_ERR_ARGUMENT);
    bad = p; bad.random.fill = NULL; CHECK(gz_lobby_host_init(&h2, &bad, &cr, NULL, &cfg) == GZ_ERR_ARGUMENT);
    bad = p; bad.clock.now_ms = NULL; CHECK(gz_lobby_host_init(&h2, &bad, &cr, NULL, &cfg) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_host_init(&h2, &p, &cr, NULL, &cfg) == GZ_OK);
    acts_reset();
    /* records a host refuses to open with */
    {
        gz_terms_outer_t o = T1O;
        uint8_t ob[512], od[32], cb[128];
        size_t on, cn;
        gz_terms_current_t c;
        o.chain[0] ^= 1;                                         /* not signet */
        on = gz_terms_encode_outer(&o, ob, sizeof ob);
        CHECK(gz_lobby_host_open(&h2, ob, on, T2, T2N, &A.l) == GZ_ERR_ARGUMENT);
        o = T1O; o.target = 31; o.shapes[1].max_members = 40;   /* 31 seats: fits; with 2 standbys: no */
        on = gz_terms_encode_outer(&o, ob, sizeof ob);
        gz_terms_outer_digest(ob, on, od);
        lt_current(T2, T2N, &T1O, SCOPE, &c);
        memcpy(c.outer_digest, od, 32);
        cn = gz_terms_encode_current(&c, cb, sizeof cb);
        cfg.standbys = 2;
        gz_lobby_host_init(&h2, &p, &cr, NULL, &cfg);
        CHECK(gz_lobby_host_open(&h2, ob, on, cb, cn, &A.l) == GZ_ERR_ARGUMENT);
        cfg.standbys = 1;
        gz_lobby_host_init(&h2, &p, &cr, NULL, &cfg);
        CHECK(gz_lobby_host_open(&h2, ob, on, cb, cn, &A.l) == GZ_OK);
        cfg.standbys = 0;
        gz_lobby_host_init(&h2, &p, &cr, NULL, &cfg);
        memset(big, 0, sizeof big);
        CHECK(gz_lobby_host_open(&h2, big, GZ_TERMS_OUTER_MAX + 1, T2, T2N, &A.l) == GZ_ERR_ARGUMENT);
        CHECK(gz_lobby_host_open(&h2, NULL, T1N, T2, T2N, &A.l) == GZ_ERR_ARGUMENT);
        CHECK(gz_lobby_host_open(&h2, T1, T1N, NULL, T2N, &A.l) == GZ_ERR_ARGUMENT);
        CHECK(gz_lobby_host_open(&h2, T1, T1N, T3 + 1, T3N - 1, &A.l) == GZ_ERR_ARGUMENT);
        CHECK(gz_lobby_host_open(&h2, T1, T1N, T2, T2N, NULL) == GZ_ERR_ARGUMENT);
        {   /* a host key that is not the key the port signs with */
            lt_signer_t wrong = OTHER;
            gz_lobby_crypto_t cw = lt_crypto(&wrong);
            wrong.key[3] = HOST.key[3];
            gz_lobby_host_init(&h2, &p, &cw, NULL, &cfg);
            CHECK(gz_lobby_host_open(&h2, T1, T1N, T2, T2N, &A.l) == GZ_ERR_ARGUMENT);
        }
        gz_lobby_host_init(&h2, &p, &cr, NULL, &cfg);
        CHECK(gz_lobby_host_open(&h2, T1, T1N, T2, T2N, &A.l) == GZ_OK);
        CHECK(gz_lobby_host_open(&h2, T1, T1N, T2, T2N, &A.l) == GZ_ERR_ARGUMENT);   /* once */
    }
    CHECK(gz_lobby_host_handle(NULL, &in, &A.l) == GZ_ERR_ARGUMENT && gz_lobby_host_handle(&h2, NULL, &A.l) == GZ_ERR_ARGUMENT);
    memset(&in, 0, sizeof in);
    CHECK(gz_lobby_host_handle(&h2, &in, NULL) == GZ_ERR_ARGUMENT && gz_lobby_host_handle(&h2, &in, &A.l) == GZ_ERR_ARGUMENT);
    in.kind = GZ_LIN_CONNECTED; in.peer_id = 9;                      /* no key */
    CHECK(gz_lobby_host_handle(&h2, &in, &A.l) == GZ_ERR_ARGUMENT);
    in.peer_key = MEM[9].key[2].pub;
    CHECK(gz_lobby_host_handle(&h2, &in, &A.l) == GZ_OK && gz_lobby_host_handle(&h2, &in, &A.l) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_host_set_values(NULL, v, 3, &A.l) == GZ_ERR_ARGUMENT && gz_lobby_host_set_values(&h2, NULL, 3, &A.l) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_host_set_values(&h2, v, 3, NULL) == GZ_ERR_ARGUMENT && gz_lobby_host_set_values(&h2, v, 2, &A.l) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_host_remove(NULL, MEM[1].key[2].pub, &A.l) == GZ_ERR_ARGUMENT && gz_lobby_host_remove(&h2, NULL, &A.l) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_host_remove(&h2, MEM[1].key[2].pub, &A.l) == GZ_OK && refused(GZ_CMD_REMOVE));   /* no such seat */
    CHECK(gz_lobby_host_cancel(NULL, 1, &A.l) == GZ_ERR_ARGUMENT && gz_lobby_host_cancel(&h2, 1, NULL) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_host_round_result(&h2, GZ_LOBBY_ROUND_FUNDING, NULL, 0, &A.l) == GZ_OK && refused(GZ_CMD_ROUND_RESULT));   /* not signing */
    CHECK(gz_lobby_host_restore(NULL, NULL) == GZ_ERR_ARGUMENT && gz_lobby_host_resume(NULL, &A.l) == GZ_ERR_ARGUMENT);
    /* inputs from nowhere: a message from an unknown peer, a timer not ours, the deadline outside Open */
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_MESSAGE; in.peer_id = 4242; in.bytes = T1; in.len = T1N;
    acts_reset();
    CHECK(gz_lobby_host_handle(&h2, &in, &A.l) == GZ_OK && A.l.count == 0);
    in.kind = GZ_LIN_TIMER; in.timer_id = 77;
    CHECK(gz_lobby_host_handle(&h2, &in, &A.l) == GZ_OK && A.l.count == 0);
    h2.state = GZ_LOBBY_READY_CHECK;
    in.timer_id = GZ_LOBBY_TIMER_DEADLINE;
    CHECK(gz_lobby_host_handle(&h2, &in, &A.l) == GZ_OK && A.l.count == 0);
    h2.state = GZ_LOBBY_OPEN;
    in.kind = GZ_LIN_MESSAGE; in.peer_id = 9; in.bytes = NULL; in.len = 5;   /* no bytes: nothing */
    CHECK(gz_lobby_host_handle(&h2, &in, &A.l) == GZ_OK && A.l.count == 0);
    in.kind = GZ_LIN_DISCONNECTED; in.peer_id = 4242;                /* not connected: nothing */
    CHECK(gz_lobby_host_handle(&h2, &in, &A.l) == GZ_OK && A.l.count == 0);
    /* a connected peer: the wrong protocol warned about once; another lobby refused */
    in.kind = GZ_LIN_MESSAGE; in.peer_id = 9;
    memcpy(buf, T1, 0);
    {
        gz_lobby_enc_t e;
        gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_HELLO, SCOPE);
        n = gz_lobby_enc_done(&e);
        buf[5] = 2;                                                  /* protocol 67 7a 66 02 */
        in.bytes = buf; in.len = n;
        acts_reset();
        CHECK(gz_lobby_host_handle(&h2, &in, &A.l) == GZ_OK && sends(1) == 1 && note(GZ_NOTE_CLOSE, -1, -1) == 0);
        acts_reset();
        CHECK(gz_lobby_host_handle(&h2, &in, &A.l) == GZ_OK && A.l.count == 0);
        memcpy(other, SCOPE, 32); other[1] ^= 1;
        n = join_msg(buf, sizeof buf, 9, MEM[9].key[3].pub, 9, 9);
        memcpy(buf + 8, other, 32);
        in.len = n;
        acts_reset();
        CHECK(gz_lobby_host_handle(&h2, &in, &A.l) == GZ_OK && sends(1) == 1 && note(GZ_NOTE_CLOSE, -1, -1) && !any_save());
    }
    /* the connection table: keys without a seat hold at most 16 places; the
     * 17th pushes out the oldest of them (review A, F7) */
    gz_lobby_host_init(&h2, &p, &cr, NULL, &cfg);
    acts_reset();
    gz_lobby_host_open(&h2, T1, T1N, T2, T2N, &A.l);
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_CONNECTED; in.peer_key = MEM[1].key[2].pub;
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++) {
        in.peer_id = 5000 + (uint64_t)i;
        acts_reset();
        CHECK(gz_lobby_host_handle(&h2, &in, &A.l) == GZ_OK);
        if (i < GZ_LOBBY_MAX_UNSEATED) CHECK(sends(1) == 0);
        else CHECK(sends(1) == 1 && A.s[0].u.send.peer_id == 5000 + (uint64_t)(i - GZ_LOBBY_MAX_UNSEATED) &&
                   note(GZ_NOTE_CLOSE, -1, -1));
    }
    {
        int used = 0;
        for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++) used += h2.conns[i].used;
        CHECK(used == GZ_LOBBY_MAX_UNSEATED);
    }
    /* member: every pointer */
    CHECK(gz_lobby_member_init(NULL, &p, &cr, NULL, &cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_init(&m2, NULL, &cr, NULL, &cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_init(&m2, &p, NULL, NULL, &cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_init(&m2, &p, &cr, NULL, NULL, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_init(&m2, &p, &cr, NULL, &cond, NULL, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_init(&m2, &p, &cr, NULL, &cond, SCOPE, NULL, M1.key[2].pub, M1.key[3].pub, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_init(&m2, &p, &cr, NULL, &cond, SCOPE, HOST.key[1].pub, NULL, M1.key[3].pub, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_init(&m2, &p, &cr, NULL, &cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, NULL, 1) == GZ_ERR_ARGUMENT);
    crb = cr; crb.verify = NULL;
    CHECK(gz_lobby_member_init(&m2, &p, &crb, NULL, &cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1) == GZ_ERR_ARGUMENT);
    crb = cr; crb.sign = NULL;
    CHECK(gz_lobby_member_init(&m2, &p, &crb, NULL, &cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_init(&m2, &p, &cr, NULL, &cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1) == GZ_OK);
    memset(&in, 0, sizeof in);
    CHECK(gz_lobby_member_handle(NULL, &in, &A.l) == GZ_ERR_ARGUMENT && gz_lobby_member_handle(&m2, NULL, &A.l) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_handle(&m2, &in, NULL) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_restore(NULL, NULL) == GZ_ERR_ARGUMENT && gz_lobby_member_restore(&m2, NULL) == GZ_ERR_ARGUMENT);
    acts_reset();
    CHECK(gz_lobby_member_unready(&m2, &A.l) == GZ_OK && refused(GZ_CMD_UNREADY) && gz_lobby_member_unready(NULL, &A.l) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_leave(NULL, &A.l) == GZ_ERR_ARGUMENT && gz_lobby_member_leave(&m2, NULL) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_set_conditions(NULL, &cond, &A.l) == GZ_ERR_ARGUMENT && gz_lobby_member_set_conditions(&m2, NULL, &A.l) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_set_conditions(&m2, &cond, NULL) == GZ_ERR_ARGUMENT);
    in.kind = GZ_LIN_CONNECTED; in.peer_id = 1;                      /* no key: refused */
    acts_reset();
    CHECK(gz_lobby_member_handle(&m2, &in, &A.l) == GZ_OK && sends(1) == 1 && !m2.connected);
    in.kind = GZ_LIN_MESSAGE; in.bytes = T1; in.len = T1N;           /* not connected: nothing */
    acts_reset();
    CHECK(gz_lobby_member_handle(&m2, &in, &A.l) == GZ_OK && A.l.count == 0);
    in.kind = GZ_LIN_TIMER; in.timer_id = 77;
    CHECK(gz_lobby_member_handle(&m2, &in, &A.l) == GZ_OK && A.l.count == 0);
    in.kind = 99;
    CHECK(gz_lobby_member_handle(&m2, &in, &A.l) == GZ_OK && A.l.count == 0);
}

static int M_STARTS, M_CANCELS;
static uint16_t M_CANCEL_REASON;
static gz_status_t m_cancel(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out)
{
    (void)ctx; (void)out;
    if (memcmp(scope, SCOPE, 32) == 0) M_CANCELS++;
    M_CANCEL_REASON = reason;
    return GZ_OK;
}
static uint16_t M_SIGNERS;
static uint8_t M_LEVELS;
static gz_status_t m_begin(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out)
{
    (void)ctx; (void)out;
    M_STARTS++;
    M_SIGNERS = h->signers;
    M_LEVELS = h->n_levels;
    return GZ_OK;
}

static size_t start_with(uint8_t *buf, size_t cap, const uint8_t *check, uint8_t role, uint16_t signers)
{
    gz_lobby_enc_t e;
    gz_lobby_crypto_t cr = lt_crypto(&HOST);
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_START, SCOPE);
    gz_lobby_enc_record(&e, 2, check, 32);
    gz_lobby_enc_u8(&e, 4, role);
    gz_lobby_enc_u16(&e, 6, signers);
    return gz_lobby_enc_sign(&e, &cr, GZ_LOBBY_KEY_HOST);
}

/* The member's connection, its starts across two checks, its end. */
static void test_member_more(void)
{
    static gz_lobby_member_t m;
    static uint8_t ob[8000];
    gz_lobby_conditions_t cond = lt_cond_fits();
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(&M1);
    gz_lobby_signing_t sg;
    gz_lobby_input_t in;
    uint8_t buf[600], x[600], cd2[32], chk1[32], chk2[32];
    size_t n, on, xn, q;
    int i;
    gz_terms_current_digest(T2, T2N, cd2);
    sg.begin = m_begin; sg.cancel = m_cancel; sg.ctx = NULL;
    gz_lobby_member_init(&m, &p, &cr, &sg, &cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1);
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_CONNECTED; in.peer_id = W_HOST_PEER; in.peer_key = HOST.key[1].pub;
    acts_reset();
    gz_lobby_member_handle(&m, &in, &A.l);
    on = offer(ob, sizeof ob, SCOPE, T1, T1N, T2, T2N, &HOST);
    feed(&m, ob, on);
    /* a new version: the member readies for it and saves it once; a check at it saves no second copy */
    {
        uint8_t ob3[8000], cd3[32];
        size_t on3 = offer(ob3, sizeof ob3, SCOPE, T1, T1N, T3, T3N, &HOST);
        gz_terms_current_digest(T3, T3N, cd3);
        CHECK(feed(&m, ob3, on3) == GZ_OK && sends(GZ_KIND_READY) == 1 && saves(GZ_REC_TERMS_RECEIVED) == 1);
        memset(chk1, 0x60, 32);
        xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk1, 2, cd3, 30000, 0, &HOST);
        CHECK(feed(&m, x, xn) == GZ_OK && sends(GZ_KIND_READY) == 1 && saves(GZ_REC_TERMS_RECEIVED) == 0);
        memcpy(cd2, cd3, 32);                                       /* the frozen values from here on */
    }
    /* two checks, two starts: each is taken, and each hands over */
    memset(chk1, 0x61, 32); memset(chk2, 0x62, 32);
    M_STARTS = 0;
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk1, 2, cd2, 30000, 0, &HOST);
    feed(&m, x, xn);
    n = start_with(buf, sizeof buf, chk1, 1, 4);
    CHECK(feed(&m, buf, n) == GZ_OK && M_STARTS == 1 && M_SIGNERS == 4 && M_LEVELS == 1 && saves(GZ_REC_START_RECEIVED) == 1);
    for (q = 0; q < A.l.count; q++)
        if (A.s[q].kind == GZ_ACTION_NOTIFY && A.s[q].u.notify.code == GZ_NOTE_STARTED)
            CHECK(A.s[q].u.notify.bytes.len == 3 && A.s[q].u.notify.bytes.data[0] == 1 && A.s[q].u.notify.bytes.data[2] == 4);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk2, 2, cd2, 30000, 0, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && sends(GZ_KIND_READY) == 1);
    n = start_with(buf, sizeof buf, chk2, 1, 20);                  /* 19 members: T1 has no shape for them */
    CHECK(feed(&m, buf, n) == GZ_OK && M_STARTS == 2 && M_SIGNERS == 20 && M_LEVELS == 0 && saves(GZ_REC_START_RECEIVED) == 1);
    CHECK(feed(&m, buf, n) == GZ_OK && M_STARTS == 2 && A.l.count == 0);   /* the same again */
    n = start_with(buf, sizeof buf, chk2, 1, 1);                   /* one signer: refused */
    CHECK(feed(&m, buf, n) == GZ_OK && sends(1) == 1);
    /* a message from another peer, while connected: ignored */
    in.kind = GZ_LIN_MESSAGE; in.peer_id = 77; in.bytes = ob; in.len = on;
    acts_reset();
    CHECK(gz_lobby_member_handle(&m, &in, &A.l) == GZ_OK && A.l.count == 0);
    /* resends and retries are counted per connection */
    n = status_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_JOINED, 2, -1);
    for (i = 0; i < 3; i++) feed(&m, buf, n);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_READY) == 0);
    n = status_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_REFUSED, 1, -1);
    for (i = 0; i < 30; i++) feed(&m, buf, n);
    CHECK(feed(&m, buf, n) == GZ_OK && timers(GZ_LOBBY_TIMER_RETRY) == 0);
    in.kind = GZ_LIN_DISCONNECTED; in.peer_id = 77;                  /* not the host's connection */
    acts_reset();
    CHECK(gz_lobby_member_handle(&m, &in, &A.l) == GZ_OK && m.connected);
    in.peer_id = W_HOST_PEER;
    CHECK(gz_lobby_member_handle(&m, &in, &A.l) == GZ_OK && !m.connected);
    in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_RETRY;      /* no connection: nothing to send */
    acts_reset();
    CHECK(gz_lobby_member_handle(&m, &in, &A.l) == GZ_OK && A.l.count == 0);
    in.kind = GZ_LIN_MESSAGE; in.bytes = ob; in.len = on;            /* nothing from a closed connection */
    CHECK(gz_lobby_member_handle(&m, &in, &A.l) == GZ_OK && A.l.count == 0);
    in.kind = GZ_LIN_CONNECTED; in.peer_key = HOST.key[1].pub;
    acts_reset();
    CHECK(gz_lobby_member_handle(&m, &in, &A.l) == GZ_OK && sends(GZ_KIND_HELLO) == 1 && m.connected);
    n = status_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_JOINED, 2, -1);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_READY) == 1);   /* counted again */
    n = status_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_REFUSED, 1, -1);
    CHECK(feed(&m, buf, n) == GZ_OK && timers(GZ_LOBBY_TIMER_RETRY) == 1);
    for (q = 0; q < A.l.count; q++) if (A.s[q].kind == GZ_ACTION_SET_TIMER) CHECK(A.s[q].u.set_timer.delay_ms == 1500);
    /* the end: a cancel for a failed signing, saved with its reason and bytes; then nothing */
    xn = host_msg(x, sizeof x, GZ_KIND_CANCEL, NULL, 3, NULL, 0, 0, &HOST);
    M_CANCELS = 0;
    CHECK(feed(&m, x, xn) == GZ_OK && note(GZ_NOTE_ENDED, GZ_LOBBY_FAILED, -1) && m.ended && !m.ready);
    CHECK(M_CANCELS == 1 && M_CANCEL_REASON == 3);                  /* the signing engine is told */
    CHECK(feed(&m, x, xn) == GZ_OK && M_CANCELS == 1);              /* once */
    for (q = 0; q < A.l.count; q++)
        if (A.s[q].kind == GZ_ACTION_SAVE && A.s[q].u.save.records[0].type == GZ_REC_LOBBY_ENDED) {
            const uint8_t *r = A.s[q].u.save.records[0].bytes.data;
            CHECK(A.s[q].u.save.records[0].bytes.len == 5 + xn && r[0] == GZ_LOBBY_FAILED && r[1] == 0 && r[2] == 3);
            CHECK(r[3] == (uint8_t)(xn >> 8) && r[4] == (uint8_t)xn && memcmp(r + 5, x, xn) == 0);
        }
    for (q = 0; q < A.l.count; q++)
        if (A.s[q].kind == GZ_ACTION_NOTIFY && A.s[q].u.notify.code == GZ_NOTE_ENDED)
            CHECK(A.s[q].u.notify.bytes.len == 3 && A.s[q].u.notify.bytes.data[2] == 3);
    CHECK(feed(&m, ob, on) == GZ_OK && A.l.count == 0);
    in.kind = GZ_LIN_TIMER; in.timer_id = GZ_LOBBY_TIMER_RETRY;
    acts_reset();
    CHECK(gz_lobby_member_handle(&m, &in, &A.l) == GZ_OK && A.l.count == 0);
    in.kind = GZ_LIN_CONNECTED;
    acts_reset();
    CHECK(gz_lobby_member_handle(&m, &in, &A.l) == GZ_OK && sends(GZ_KIND_HELLO) == 0);   /* ended: no hello */
    /* member-to-host kinds sent to a member: refused, each */
    {
        static const uint16_t kinds[5] = {GZ_KIND_HELLO, GZ_KIND_JOIN, GZ_KIND_READY, GZ_KIND_UNREADY, GZ_KIND_LEAVE};
        int k2;
        for (k2 = 0; k2 < 5; k2++) {
            gz_lobby_enc_t e;
            uint8_t a64[64];
            memset(a64, 1, 64);
            gz_lobby_member_init(&m, &p, &cr, &sg, &cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1);
            in.kind = GZ_LIN_CONNECTED; in.peer_id = W_HOST_PEER; in.peer_key = HOST.key[1].pub;
            acts_reset();
            gz_lobby_member_handle(&m, &in, &A.l);
            gz_lobby_enc_start(&e, buf, sizeof buf, kinds[k2], SCOPE);
            if (kinds[k2] == GZ_KIND_JOIN) {
                gz_lobby_enc_record(&e, 2, M1.key[3].pub, 33); gz_lobby_enc_record(&e, 4, a64, 64); gz_lobby_enc_record(&e, 6, a64, 64);
            }
            if (kinds[k2] == GZ_KIND_READY) {
                gz_lobby_enc_record(&e, 2, SCOPE, 32); gz_lobby_enc_u32(&e, 4, 1); gz_lobby_enc_record(&e, 6, cd2, 32);
                gz_lobby_enc_record(&e, 240, a64, 64);
            }
            n = gz_lobby_enc_done(&e);
            CHECK(feed(&m, buf, n) == GZ_OK && sends(1) == 1 && note(GZ_NOTE_CLOSE, -1, -1) && !any_save());
        }
    }
    /* records read back: an unready by the user then a ready; a start record that is not a start; a leave */
    {
        uint8_t two = 2, rd[300], lvr[5] = {0, 0, 2, 0, 0};
        size_t rn = ready_msg(rd, sizeof rd, 1, 1, cd2, chk1, 0);
        gz_record_t r;
        gz_lobby_member_init(&m, &p, &cr, &sg, &cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1);
        r.type = GZ_REC_READY_SENT; r.bytes.data = &two; r.bytes.len = 1;
        CHECK(gz_lobby_member_restore(&m, &r) == GZ_OK && m.user_unready && !m.ready);
        r.bytes.data = rd; r.bytes.len = rn;
        CHECK(gz_lobby_member_restore(&m, &r) == GZ_OK && !m.user_unready && m.ready && m.has_answered);
        r.type = GZ_REC_START_RECEIVED;
        CHECK(gz_lobby_member_restore(&m, &r) == GZ_ERR_CORRUPT && m.start_len == 0);
        r.type = GZ_REC_LOBBY_ENDED; r.bytes.data = lvr; r.bytes.len = 5;
        CHECK(gz_lobby_member_restore(&m, &r) == GZ_OK && m.ended && m.left);
    }
}

/* Contract v2 and the updated messages.md: hello limits per member key
 * across its connections (6.1), connections closed that send neither hello
 * nor join within 60 s, seats marked for the transport, the party's own
 * network (2, 6.2), and a seat of an older restore epoch not resumed. */
static gz_lobby_conditions_t cond_fits_g;
static const uint8_t *cd2_of(void)
{
    static uint8_t d[32];
    gz_terms_current_digest(T2, T2N, d);
    return d;
}

static int seated_notes(const uint8_t *key, int seated)
{
    size_t i;
    int c = 0;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_NOTIFY && A.s[i].u.notify.code == GZ_NOTE_SEATED &&
            A.s[i].u.notify.bytes.len == 34 && (!key || memcmp(A.s[i].u.notify.bytes.data, key, 33) == 0) &&
            A.s[i].u.notify.bytes.data[33] == seated)
            c++;
    return c;
}

/* 1 if the last list saves a seat record before it gives the seated notice. */
static int seat_saved_first(void)
{
    size_t i;
    int saved = 0;
    for (i = 0; i < A.l.count; i++) {
        if (A.s[i].kind == GZ_ACTION_SAVE && A.s[i].u.save.records[0].type == GZ_REC_SEAT) saved = 1;
        if (A.s[i].kind == GZ_ACTION_NOTIFY && A.s[i].u.notify.code == GZ_NOTE_SEATED) return saved;
    }
    return 0;
}

static gz_status_t timer_in(uint64_t id)
{
    gz_lobby_input_t in;
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_TIMER; in.timer_id = id;
    acts_reset();
    return gz_lobby_host_handle(&H, &in, &A.l);
}

static gz_status_t lk_in(int i, int kind, const uint8_t *key, const uint8_t *b, size_t n)
{
    gz_lobby_input_t in;
    memset(&in, 0, sizeof in);
    in.kind = kind; in.peer_id = 5000u + (uint64_t)i; in.bytes = b; in.len = n;
    in.peer_key = key;
    acts_reset();
    return gz_lobby_host_handle(&H, &in, &A.l);
}

static void test_contract_v2(void)
{
    uint8_t buf[600], lv[64];
    size_t n, lvn;
    int k;
    gz_lobby_enc_t e;
    cond_fits_g = lt_cond_fits();
    gz_lobby_enc_start(&e, lv, sizeof lv, GZ_KIND_LEAVE, SCOPE);
    lvn = gz_lobby_enc_done(&e);

    /* 1. hello: answered once a second per key, whatever the connection */
    CLOCK = W_T0 - 3600000;
    host_open(0);
    hin(GZ_LIN_CONNECTED, 1, NULL, 0);
    CHECK(timers(GZ_LOBBY_TIMER_IDLE) == 1);
    n = hello_msg(buf, sizeof buf, SCOPE);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1);
    hin(GZ_LIN_DISCONNECTED, 1, NULL, 0);
    hin(GZ_LIN_CONNECTED, 1, NULL, 0);
    CHECK(timers(GZ_LOBBY_TIMER_IDLE) == 0);                         /* armed already */
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && A.l.count == 0);  /* a new connection: still ignored */
    for (k = 0; k < 19; k++) {                                       /* 20 ignored in all, across reconnects */
        if (k % 5 == 0) { hin(GZ_LIN_DISCONNECTED, 1, NULL, 0); hin(GZ_LIN_CONNECTED, 1, NULL, 0); }
        CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && A.l.count == 0);
    }
    hin(GZ_LIN_DISCONNECTED, 1, NULL, 0);
    hin(GZ_LIN_CONNECTED, 1, NULL, 0);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && sends(1) == 1 && note(GZ_NOTE_CLOSE, -1, -1));  /* the 21st */
    CLOCK += 1000;                                                   /* the next second: answered, */
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && note(GZ_NOTE_CLOSE, -1, -1));   /* but over 20 ignored stays over */
    CLOCK += 600000;                                                 /* ten minutes on: the count starts again */
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1);
    for (k = 0; k < 20; k++) { hin(GZ_LIN_MESSAGE, 1, buf, n); CHECK(A.l.count == 0); }
    hin(GZ_LIN_MESSAGE, 1, buf, n);
    CHECK(note(GZ_NOTE_CLOSE, -1, -1));
    hin(GZ_LIN_CONNECTED, 2, NULL, 0);                               /* another key has its own count */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1);

    /* 2. a connection that sends neither hello nor join is closed after 60 s */
    CLOCK = W_T0 - 3600000;
    host_open(0);
    hin(GZ_LIN_CONNECTED, 3, NULL, 0);
    CHECK(timers(GZ_LOBBY_TIMER_IDLE) == 1 && A.s[0].u.set_timer.delay_ms == GZ_LOBBY_IDLE_MS);
    CLOCK += 20000;
    hin(GZ_LIN_CONNECTED, 4, NULL, 0);
    CLOCK += 10000;
    hin(GZ_LIN_CONNECTED, 5, NULL, 0);
    n = join_msg(buf, sizeof buf, 5, MEM[5].key[3].pub, 5, 5);      /* a join counts as speaking */
    hin(GZ_LIN_MESSAGE, 5, buf, n);
    CLOCK += 29999;                                                  /* 3 has waited 59,999 ms */
    CHECK(timer_in(GZ_LOBBY_TIMER_IDLE) == GZ_OK && sends(1) == 0 && timers(GZ_LOBBY_TIMER_IDLE) == 1);
    CHECK(A.s[A.l.count - 1].u.set_timer.delay_ms == 1);
    CLOCK += 1;
    CHECK(timer_in(GZ_LOBBY_TIMER_IDLE) == GZ_OK && sends(1) == 1 && A.s[0].u.send.peer_id == W_PEER(3));
    CHECK(timers(GZ_LOBBY_TIMER_IDLE) == 1 && A.s[A.l.count - 1].u.set_timer.delay_ms == 20000);
    hin(GZ_LIN_CONNECTED, 7, NULL, 0);                               /* armed by the sweep: not again */
    CHECK(timers(GZ_LOBBY_TIMER_IDLE) == 0);
    hin(GZ_LIN_DISCONNECTED, 7, NULL, 0);
    CHECK(timer_in(GZ_LOBBY_TIMER_IDLE) == GZ_OK && sends(1) == 0);  /* 3 is not closed twice */
    CLOCK += 20000;
    CHECK(timer_in(GZ_LOBBY_TIMER_IDLE) == GZ_OK && sends(1) == 1 && A.s[0].u.send.peer_id == W_PEER(4));
    CHECK(timers(GZ_LOBBY_TIMER_IDLE) == 0);                         /* 5 joined: nobody left to watch */
    /* a seated key's new connection that says nothing is closed too (b04) */
    hin(GZ_LIN_DISCONNECTED, 5, NULL, 0);
    hin(GZ_LIN_CONNECTED, 5, NULL, 0);
    CHECK(timers(GZ_LOBBY_TIMER_IDLE) == 1);
    CLOCK += GZ_LOBBY_IDLE_MS;
    CHECK(timer_in(GZ_LOBBY_TIMER_IDLE) == GZ_OK && sends(1) == 1 && A.s[0].u.send.peer_id == W_PEER(5));
    CHECK(timers(GZ_LOBBY_TIMER_IDLE) == 0);
    hin(GZ_LIN_CONNECTED, 6, NULL, 0);                               /* and the next connection arms it again */
    CHECK(timers(GZ_LOBBY_TIMER_IDLE) == 1);
    n = hello_msg(buf, sizeof buf, SCOPE);
    hin(GZ_LIN_MESSAGE, 6, buf, n);
    CLOCK += 60000;
    CHECK(timer_in(GZ_LOBBY_TIMER_IDLE) == GZ_OK && sends(1) == 0);  /* it said hello */

    /* 3. seats marked for the transport: at join, at leave and removal, at every start */
    {
        static gz_lobby_host_t R;
        size_t q;
        for (q = 0; q < N_KEPT; q++) free(KEPT_B[q]);
        N_KEPT = 0;
        CLOCK = W_T0 - 3600000;
        host_open(0); keep_all();
        for (k = 1; k <= 3; k++) {
            hin(GZ_LIN_CONNECTED, k, NULL, 0);
            CLOCK += 1000;
            n = join_msg(buf, sizeof buf, k, MEM[k].key[3].pub, k, k);
            hin(GZ_LIN_MESSAGE, k, buf, n); keep_all();
            CHECK(seated_notes(MEM[k].key[2].pub, 1) == 1 && seat_saved_first());
            CHECK(hin(GZ_LIN_MESSAGE, k, buf, n) == GZ_OK && seated_notes(NULL, 1) == 0);   /* a duplicate */
        }
        n = ready_msg(buf, sizeof buf, 1, 1, cd2_of(), NULL, 0);
        CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && seated_notes(NULL, 1) == 0 && seated_notes(NULL, 0) == 0);
        keep_all();
        CHECK(hin(GZ_LIN_MESSAGE, 2, lv, lvn) == GZ_OK && seated_notes(MEM[2].key[2].pub, 0) == 1 && seat_saved_first());
        keep_all();
        acts_reset();
        CHECK(gz_lobby_host_remove(&H, MEM[3].key[2].pub, &A.l) == GZ_OK && seated_notes(MEM[3].key[2].pub, 0) == 1);
        keep_all();
        CLOCK += 1000;
        n = join_msg(buf, sizeof buf, 2, MEM[2].key[3].pub, 2, 2);   /* joins again on a new connection */
        hin(GZ_LIN_DISCONNECTED, 2, NULL, 0);
        hin(GZ_LIN_CONNECTED, 2, NULL, 0);
        CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && seated_notes(MEM[2].key[2].pub, 1) == 1);
        keep_all();
        restore_kept(&R);
        acts_reset();
        CHECK(gz_lobby_host_resume(&R, &A.l) == GZ_OK && seated_notes(NULL, 1) == 2 && seated_notes(NULL, 0) == 0);
        CHECK(seated_notes(MEM[1].key[2].pub, 1) == 1 && seated_notes(MEM[2].key[2].pub, 1) == 1);
        {
            gz_lobby_input_t ci;                                     /* timers do not survive a restart */
            memset(&ci, 0, sizeof ci);
            ci.kind = GZ_LIN_CONNECTED; ci.peer_id = W_PEER(9); ci.peer_key = MEM[9].key[2].pub;
            acts_reset();
            CHECK(gz_lobby_host_handle(&R, &ci, &A.l) == GZ_OK && timers(GZ_LOBBY_TIMER_IDLE) == 1);
        }
        for (q = 0; q < N_KEPT; q++) free(KEPT_B[q]);
        N_KEPT = 0;
    }

    /* 4. one policy, core/tree's (review A, F4): what it refuses, neither side
     * takes. testnet4 waits for the tree's policy (docs/notes/lobby.md). */
    {
        static gz_terms_outer_t o;
        static gz_lobby_host_t h4;
        static gz_lobby_member_t m4;
        static uint8_t ob[8000];
        static const uint8_t TESTNET4[32] = {
            0x43, 0xf0, 0x8b, 0xda, 0xb0, 0x50, 0xe3, 0x5b, 0x56, 0x7c, 0x86, 0x4b, 0x91, 0xf4, 0x7f, 0x50,
            0xae, 0x72, 0x5a, 0xe2, 0xde, 0x53, 0xbc, 0xfb, 0xba, 0xf2, 0x84, 0xda, 0x00, 0x00, 0x00, 0x00};
        uint8_t t4[512], c4[128], d4[32];
        size_t t4n, c4n, on;
        gz_terms_current_t c;
        gz_ports_t p = ports();
        gz_lobby_crypto_t cr = lt_crypto(&HOST), cm = lt_crypto(&M1);
        gz_lobby_host_config_t cfg;
        gz_lobby_input_t in;
        int v;
        memset(&cfg, 0, sizeof cfg);
        memcpy(cfg.factory_key, HOST.key[3].pub, 33);
        memset(&in, 0, sizeof in);
        in.kind = GZ_LIN_CONNECTED; in.peer_id = W_HOST_PEER; in.peer_key = HOST.key[1].pub;
        for (v = 0; v < 5; v++) {
            o = T1O;
            if (v == 0) memcpy(o.chain, TESTNET4, 32);
            if (v == 1) o.on_shortfall = 1;                          /* carry-over (review A, t02) */
            if (v == 2) o.channel_sat = 2100000000000000ull;          /* no tree can be funded */
            if (v == 3) memcpy(o.host_key, OTHER.key[1].pub, 33);     /* signed by the pinned key (m12) */
            t4n = gz_terms_encode_outer(&o, t4, sizeof t4);
            gz_terms_outer_digest(t4, t4n, d4);
            lt_current(T2, T2N, &T1O, SCOPE, &c);
            memcpy(c.outer_digest, d4, 32);
            c4n = gz_terms_encode_current(&c, c4, sizeof c4);
            gz_lobby_host_init(&h4, &p, &cr, NULL, &cfg);
            acts_reset();
            CHECK(gz_lobby_host_open(&h4, t4, t4n, c4, c4n, &A.l) == (v == 4 ? GZ_OK : GZ_ERR_ARGUMENT));
            on = offer(ob, sizeof ob, d4, t4, t4n, c4, c4n, v == 3 ? &OTHER : &HOST);   /* m12: its own key signs */
            gz_lobby_member_init(&m4, &p, &cm, NULL, &cond_fits_g, d4, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1);
            acts_reset();
            gz_lobby_member_handle(&m4, &in, &A.l);
            if (v < 4) CHECK(feed(&m4, ob, on) == GZ_OK && sends(1) == 1 && note(GZ_NOTE_CLOSE, -1, -1) &&
                             !m4.have_terms && !any_save());
            else CHECK(feed(&m4, ob, on) == GZ_OK && sends(GZ_KIND_JOIN) == 1 && m4.have_terms);
        }
    }

    /* 5. after a restore the member has new keys: its old seat is not resumed, it joins again */
    {
        static gz_lobby_member_t ma, mb;
        static uint8_t ob[8000];
        gz_record_t recs[16];
        uint8_t *store[16];
        size_t nrec = 0, q, j;
        lt_signer_t nb = M1;
        gz_ports_t p = ports();
        gz_lobby_crypto_t ca = lt_crypto(&M1), cb;
        gz_lobby_input_t in;
        gz_lobby_msg_t g;
        lt_key(&nb.key[3], "member 1 factory, epoch 2");
        cb = lt_crypto(&nb);
        n = offer(ob, sizeof ob, SCOPE, T1, T1N, T2, T2N, &HOST);
        memset(&in, 0, sizeof in);
        in.kind = GZ_LIN_CONNECTED; in.peer_id = W_HOST_PEER; in.peer_key = HOST.key[1].pub;
        gz_lobby_member_init(&ma, &p, &ca, NULL, &cond_fits_g, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1);
        acts_reset();
        gz_lobby_member_handle(&ma, &in, &A.l);
        feed(&ma, ob, n);
        for (q = 0; q < A.l.count; q++)
            if (A.s[q].kind == GZ_ACTION_SAVE)
                for (j = 0; j < A.s[q].u.save.n_records && nrec < 16; j++) {
                    recs[nrec] = A.s[q].u.save.records[j];
                    store[nrec] = malloc(recs[nrec].bytes.len + 1);
                    memcpy(store[nrec], recs[nrec].bytes.data, recs[nrec].bytes.len);
                    recs[nrec].bytes.data = store[nrec];
                    nrec++;
                }
        CHECK(nrec == 3 && ma.joined && ma.ready);
        gz_lobby_member_init(&mb, &p, &cb, NULL, &cond_fits_g, SCOPE, HOST.key[1].pub, M1.key[2].pub, nb.key[3].pub, 1);
        for (q = 0; q < nrec; q++) CHECK(gz_lobby_member_restore(&mb, &recs[q]) == GZ_OK);
        CHECK(!mb.joined && !mb.ready && mb.join_len == 0 && mb.ready_len == 0);
        acts_reset();
        gz_lobby_member_handle(&mb, &in, &A.l);
        CHECK(feed(&mb, ob, n) == GZ_OK && sends(GZ_KIND_JOIN) == 1);
        CHECK(last_sent(GZ_KIND_JOIN, &g, NULL, NULL) && memcmp(g.factory_key, nb.key[3].pub, 33) == 0);
        gz_lobby_member_init(&ma, &p, &ca, NULL, &cond_fits_g, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1);
        for (q = 0; q < nrec; q++) CHECK(gz_lobby_member_restore(&ma, &recs[q]) == GZ_OK);
        CHECK(ma.joined && ma.ready);                               /* the same keys: resumed */
        {
            static gz_lobby_member_t mc;
            gz_record_t er;
            uint8_t eb[600];
            int found = 0;
            acts_reset();
            CHECK(gz_lobby_member_leave(&ma, &A.l) == GZ_OK);
            for (q = 0; q < A.l.count; q++)
                if (A.s[q].kind == GZ_ACTION_SAVE)
                    for (j = 0; j < A.s[q].u.save.n_records; j++)
                        if (A.s[q].u.save.records[j].type == GZ_REC_LOBBY_ENDED &&
                            A.s[q].u.save.records[j].bytes.len <= sizeof eb) {
                            er = A.s[q].u.save.records[j];
                            memcpy(eb, er.bytes.data, er.bytes.len);
                            er.bytes.data = eb;
                            found = 1;
                        }
            CHECK(found && eb[0] == 0);
            gz_lobby_member_init(&mc, &p, &cb, NULL, &cond_fits_g, SCOPE, HOST.key[1].pub, M1.key[2].pub, nb.key[3].pub, 1);
            for (q = 0; q < nrec; q++) CHECK(gz_lobby_member_restore(&mc, &recs[q]) == GZ_OK);
            CHECK(gz_lobby_member_restore(&mc, &er) == GZ_OK && !mc.ended && !mc.left);   /* the old seat left */
            acts_reset();
            gz_lobby_member_handle(&mc, &in, &A.l);
            CHECK(feed(&mc, ob, n) == GZ_OK && sends(GZ_KIND_JOIN) == 1);
            eb[0] = GZ_LOBBY_CANCELLED;                              /* the lobby itself ended: it stays ended */
            gz_lobby_member_init(&mc, &p, &cb, NULL, &cond_fits_g, SCOPE, HOST.key[1].pub, M1.key[2].pub, nb.key[3].pub, 1);
            for (q = 0; q < nrec; q++) CHECK(gz_lobby_member_restore(&mc, &recs[q]) == GZ_OK);
            CHECK(gz_lobby_member_restore(&mc, &er) == GZ_OK && mc.ended && mc.lobby_state == GZ_LOBBY_CANCELLED);
        }
        for (q = 0; q < nrec; q++) free(store[q]);
    }

    /* 6. hello limits: kept for the 64 most recent keys, the oldest pushed out first */
    {
        static lt_key_t lk[GZ_LOBBY_MAX_LINKS + 1];
        char label[48];
        int i;
        n = hello_msg(buf, sizeof buf, SCOPE);
        for (i = 0; i <= GZ_LOBBY_MAX_LINKS; i++) {
            snprintf(label, sizeof label, "link key %d", i);
            lt_key(&lk[i], label);
        }
        CLOCK = W_T0 - 3600000;
        host_open(0);
#define LK_HELLO(i) (lk_in((i), GZ_LIN_DISCONNECTED, lk[i].pub, NULL, 0), lk_in((i), GZ_LIN_CONNECTED, lk[i].pub, NULL, 0), lk_in((i), GZ_LIN_MESSAGE, lk[i].pub, buf, n))
        for (i = 0; i < 2; i++) { CHECK(LK_HELLO(i) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1); CLOCK += 1; }
        CHECK(LK_HELLO(0) == GZ_OK && A.l.count == 0);               /* two keys: each keeps its own */
        CHECK(LK_HELLO(1) == GZ_OK && A.l.count == 0);
        for (i = 2; i < GZ_LOBBY_MAX_LINKS; i++) {
            CHECK(LK_HELLO(i) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1);
            lk_in(i, GZ_LIN_DISCONNECTED, lk[i].pub, NULL, 0);
            CLOCK += 1;
        }
        CHECK(LK_HELLO(0) == GZ_OK && A.l.count == 0);               /* 64 keys: all still kept */
        CHECK(LK_HELLO(GZ_LOBBY_MAX_LINKS - 1) == GZ_OK && A.l.count == 0);
        CHECK(LK_HELLO(GZ_LOBBY_MAX_LINKS) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1);   /* a 65th */
        CHECK(LK_HELLO(1) == GZ_OK && A.l.count == 0);               /* 1 is kept, */
        CHECK(LK_HELLO(0) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1);   /* 0, the oldest, starts afresh */
#undef LK_HELLO

        /* a new window begins exactly ten minutes after the last one began */
        CLOCK = W_T0 - 3600000;
        host_open(0);
        hin(GZ_LIN_CONNECTED, 7, NULL, 0);
        CHECK(hin(GZ_LIN_MESSAGE, 7, buf, n) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1);
        for (k = 0; k < 20; k++) { CLOCK += 1; CHECK(hin(GZ_LIN_MESSAGE, 7, buf, n) == GZ_OK && A.l.count == 0); }
        CLOCK += 599500 - 20;
        CHECK(hin(GZ_LIN_MESSAGE, 7, buf, n) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1);
        CLOCK += 501;                                                /* 600,000 ms after the window began */
        CHECK(hin(GZ_LIN_MESSAGE, 7, buf, n) == GZ_OK && A.l.count == 0 && !note(GZ_NOTE_CLOSE, -1, -1));
    }
}


/* ---------------------------------------- review A of PR 30: findings */

static struct { int begins, resumes, cancels, lefts, limits, sigs; uint16_t signers; } SG;
static gz_status_t sg_begin(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out)
{
    (void)ctx; (void)out;
    if (h->resume) SG.resumes++; else SG.begins++;
    SG.signers = h->signers;
    SG.limits = h->limits != NULL;
    SG.sigs = h->outer_sig && h->current_sig && h->pinned_key && h->values &&
              lt_verify(NULL, h->pinned_key, h->scope, h->outer_sig) &&
              lt_verify(NULL, h->pinned_key, h->current_digest, h->current_sig);
    return GZ_OK;
}
static gz_status_t sg_cancel(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out)
{
    (void)ctx; (void)scope; (void)reason; (void)out;
    SG.cancels++;
    return GZ_OK;
}
static gz_status_t sg_left(void *ctx, const uint8_t scope[32], const uint8_t ckey[33], gz_action_list_t *out)
{
    (void)ctx; (void)scope; (void)ckey; (void)out;
    SG.lefts++;
    return GZ_OK;
}
static gz_lobby_signing_t sg(void)
{
    gz_lobby_signing_t s;
    s.begin = sg_begin; s.cancel = sg_cancel; s.member_left = sg_left; s.ctx = NULL;
    return s;
}

static gz_status_t m_in(gz_lobby_member_t *m, int kind)
{
    gz_lobby_input_t in;
    memset(&in, 0, sizeof in);
    in.kind = kind; in.peer_id = W_HOST_PEER; in.peer_key = HOST.key[1].pub;
    acts_reset();
    return gz_lobby_member_handle(m, &in, &A.l);
}

static void member_sg(gz_lobby_member_t *m, const gz_lobby_conditions_t *cond)
{
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(&M1);
    gz_lobby_signing_t s = sg();
    gz_lobby_member_init(m, &p, &cr, &s, cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1);
    m_in(m, GZ_LIN_CONNECTED);
}

static size_t st_msg(uint8_t *buf, size_t cap, uint8_t lobby, uint8_t seat, uint32_t version)
{
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_LOBBY_STATUS, SCOPE);
    gz_lobby_enc_u8(&e, 2, lobby); gz_lobby_enc_u8(&e, 4, seat); gz_lobby_enc_u32(&e, 6, version);
    gz_lobby_enc_u16(&e, 8, 1); gz_lobby_enc_u16(&e, 10, 1);
    return gz_lobby_enc_done(&e);
}

/* The member's saved records, kept across lists for a restore. */
static gz_record_t MK[64];
static uint8_t *MKB[64];
static size_t N_MK;
static void mkeep(void)
{
    size_t i, j;
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_SAVE)
            for (j = 0; j < A.s[i].u.save.n_records && N_MK < 64; j++) {
                MK[N_MK] = A.s[i].u.save.records[j];
                MKB[N_MK] = malloc(MK[N_MK].bytes.len + 1);
                memcpy(MKB[N_MK], MK[N_MK].bytes.data, MK[N_MK].bytes.len);
                MK[N_MK].bytes.data = MKB[N_MK];
                N_MK++;
            }
}
static void mfree(void)
{
    size_t i;
    for (i = 0; i < N_MK; i++) free(MKB[i]);
    N_MK = 0;
}
static void mrestore(gz_lobby_member_t *m, const gz_lobby_conditions_t *cond)
{
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(&M1);
    gz_lobby_signing_t s = sg();
    size_t i;
    gz_lobby_member_init(m, &p, &cr, &s, cond, SCOPE, HOST.key[1].pub, M1.key[2].pub, M1.key[3].pub, 1);
    for (i = 0; i < N_MK; i++) CHECK(gz_lobby_member_restore(m, &MK[i]) == GZ_OK);
}

static int has_conn(uint64_t id)
{
    int i;
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++) if (H.conns[i].used && H.conns[i].peer_id == id) return 1;
    return 0;
}

static int closed_peer(uint64_t id)
{
    size_t i;
    uint8_t b[8];
    gz_lw_put(b, id, 8);
    for (i = 0; i < A.l.count; i++)
        if (A.s[i].kind == GZ_ACTION_NOTIFY && A.s[i].u.notify.code == GZ_NOTE_CLOSE &&
            A.s[i].u.notify.bytes.len == 8 && memcmp(A.s[i].u.notify.bytes.data, b, 8) == 0)
            return 1;
    return 0;
}

/* Member i joins and readies (min_members `min`) on a new connection. */
static void seat_up(int i, uint16_t min)
{
    uint8_t buf[600];
    size_t n;
    hin(GZ_LIN_CONNECTED, i, NULL, 0);
    n = join_msg(buf, sizeof buf, i, MEM[i].key[3].pub, i, i);
    hin(GZ_LIN_MESSAGE, i, buf, n);
    n = ready_msg(buf, sizeof buf, i, 1, cd2_of(), NULL, min);
    hin(GZ_LIN_MESSAGE, i, buf, n);
}

static void test_review_member(void)
{
    static gz_lobby_member_t m, m2;
    static uint8_t buf[70000], x[600];
    gz_lobby_conditions_t cond = lt_cond_fits(), tight;
    uint8_t chk[32], cd2[32];
    size_t n, xn, on;
    gz_lobby_msg_t g;
    static uint8_t ob[8000];
    memcpy(cd2, cd2_of(), 32);
    memset(chk, 0x3c, 32);
    on = offer(ob, sizeof ob, SCOPE, T1, T1N, T2, T2N, &HOST);

    /* F1: answered, then the user unreadied: the start is kept, never begun */
    memset(&SG, 0, sizeof SG);
    member_sg(&m, &cond);
    CHECK(feed(&m, ob, on) == GZ_OK && sends(GZ_KIND_READY) == 1);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && sends(GZ_KIND_READY) == 1 && gz_lobby_member_may_sign(&m, chk));
    acts_reset();
    CHECK(gz_lobby_member_unready(&m, &A.l) == GZ_OK && sends(GZ_KIND_UNREADY) == 1);
    CHECK(!gz_lobby_member_may_sign(&m, chk) && !m.has_answered && m.has_withdrawn);
    xn = host_msg(x, sizeof x, GZ_KIND_START, chk, 0, NULL, 0, 1, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && saves(GZ_REC_START_RECEIVED) == 1 && note(GZ_NOTE_STARTED, 1, -1) && SG.begins == 0);
    /* the same after an unready for the member's conditions */
    member_sg(&m, &cond);
    feed(&m, ob, on);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
    feed(&m, x, xn);
    tight = cond; LT_ADJ(tight, 0) = 400;
    acts_reset();
    CHECK(gz_lobby_member_set_conditions(&m, &tight, &A.l) == GZ_OK && sends(GZ_KIND_UNREADY) == 1);
    xn = host_msg(x, sizeof x, GZ_KIND_START, chk, 0, NULL, 0, 1, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && saves(GZ_REC_START_RECEIVED) == 1 && SG.begins == 0);
    /* a start for no check the member answered or withdrew from: ignored */
    {
        uint8_t other[32];
        memset(other, 0x3d, 32);
        xn = host_msg(x, sizeof x, GZ_KIND_START, other, 0, NULL, 0, 1, &HOST);
        CHECK(feed(&m, x, xn) == GZ_OK && A.l.count == 0);
    }

    /* the control, with F3 and F9: still ready, begun once with all it needs;
     * restarted between start and round_propose, begun again as a resume */
    memset(&SG, 0, sizeof SG);
    mfree();
    member_sg(&m, &cond);
    CHECK(feed(&m, ob, on) == GZ_OK); mkeep();
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK); mkeep();
    xn = host_msg(x, sizeof x, GZ_KIND_START, chk, 0, NULL, 0, 1, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && SG.begins == 1 && SG.resumes == 0 && SG.signers == 4 && SG.limits && SG.sigs);
    mkeep();
    CHECK(feed(&m, x, xn) == GZ_OK && A.l.count == 0 && SG.begins == 1);          /* a duplicate */
    mrestore(&m2, &cond);
    CHECK(m2.start_len == xn && gz_lobby_member_may_sign(&m2, chk));
    acts_reset();
    CHECK(gz_lobby_member_resume(&m2, &A.l) == GZ_OK && SG.resumes == 1 && SG.begins == 1);
    CHECK(m_in(&m2, GZ_LIN_CONNECTED) == GZ_OK && sends(GZ_KIND_HELLO) == 1);
    CHECK(feed(&m2, x, xn) == GZ_OK && A.l.count == 0 && SG.begins == 1);         /* the host's resend */
    /* the signing engine's outcome for the member (F9) */
    acts_reset();
    CHECK(gz_lobby_member_round_result(&m2, 99, NULL, &A.l) == GZ_ERR_ARGUMENT && gz_lobby_member_round_result(NULL, 1, NULL, &A.l) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_member_round_result(&m2, GZ_LOBBY_ROUND_FUNDING, NULL, &A.l) == GZ_OK && m2.lobby_state == GZ_LOBBY_FUNDING &&
          note(GZ_NOTE_SEAT, GZ_LOBBY_FUNDING, -1) && saves(GZ_REC_LOBBY_STATE) == 1);
    acts_reset();                                      /* funded: no retry, and Funding once */
    CHECK(gz_lobby_member_round_result(&m2, GZ_LOBBY_ROUND_RETRY, held_check(&m2), &A.l) == GZ_OK && refused(GZ_CMD_ROUND_RESULT) && m2.start_len == xn);
    acts_reset();
    CHECK(gz_lobby_member_round_result(&m2, GZ_LOBBY_ROUND_FUNDING, NULL, &A.l) == GZ_OK && refused(GZ_CMD_ROUND_RESULT) && !any_save());
    CHECK(gz_lobby_member_round_result(&m2, GZ_LOBBY_ROUND_FAILED, NULL, &A.l) == GZ_OK);
    /* unreadied after the start, then restarted: nothing resumes */
    acts_reset();
    CHECK(gz_lobby_member_unready(&m, &A.l) == GZ_OK); mkeep();
    mrestore(&m2, &cond);
    acts_reset();
    CHECK(gz_lobby_member_resume(&m2, &A.l) == GZ_OK && A.l.count == 0 && SG.resumes == 1);
    CHECK(gz_lobby_member_resume(NULL, &A.l) == GZ_ERR_ARGUMENT);

    /* a version lower than the frozen one is ignored, not a fault (messages.md 6.2) */
    {
        uint8_t o3[8000];
        size_t o3n = offer(o3, sizeof o3, SCOPE, T1, T1N, T3, T3N, &HOST);
        static gz_lobby_member_t mf;
        member_sg(&mf, &cond);
        feed(&mf, o3, o3n);                            /* version 2 */
        {
            uint8_t cd3[32];
            gz_terms_current_digest(T3, T3N, cd3);
            xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 2, cd3, 30000, 0, &HOST);
        }
        CHECK(feed(&mf, x, xn) == GZ_OK && mf.frozen && mf.frozen_version == 2);
        CHECK(feed(&mf, ob, on) == GZ_OK && A.l.count == 0 && !mf.ended);   /* version 1 */
        CHECK(feed(&mf, o3, o3n) == GZ_OK && A.l.count == 0 && !mf.ended);  /* the same: a duplicate */
    }
    /* may_sign needs every condition */
    {
        static gz_lobby_member_t ms;
        uint8_t other[32];
        memset(other, 0x3e, 32);
        member_sg(&ms, &cond);
        feed(&ms, ob, on);
        CHECK(!gz_lobby_member_may_sign(&ms, chk));                  /* not frozen, no answer */
        xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
        feed(&ms, x, xn);
        CHECK(gz_lobby_member_may_sign(&ms, chk) && !gz_lobby_member_may_sign(&ms, other));
        CHECK(!gz_lobby_member_may_sign(NULL, chk) && !gz_lobby_member_may_sign(&ms, NULL));
        ms.ended = 1; CHECK(!gz_lobby_member_may_sign(&ms, chk)); ms.ended = 0;
        ms.user_unready = 1; CHECK(!gz_lobby_member_may_sign(&ms, chk)); ms.user_unready = 0;
        ms.ready = 0; CHECK(!gz_lobby_member_may_sign(&ms, chk)); ms.ready = 1;
        ms.frozen = 0; CHECK(!gz_lobby_member_may_sign(&ms, chk)); ms.frozen = 1;
        ms.ready_version = 2; CHECK(!gz_lobby_member_may_sign(&ms, chk)); ms.ready_version = 1;
        CHECK(gz_lobby_member_may_sign(&ms, chk));
        /* resume: role 2, or an ended member, begins nothing */
        memset(&SG, 0, sizeof SG);
        xn = host_msg(x, sizeof x, GZ_KIND_START, chk, 0, NULL, 0, 2, &HOST);
        CHECK(feed(&ms, x, xn) == GZ_OK && saves(GZ_REC_START_RECEIVED) == 1 && SG.begins == 0);
        acts_reset();
        CHECK(gz_lobby_member_resume(&ms, &A.l) == GZ_OK && SG.resumes == 0 && A.l.count == 0);
        ms.role = 1; ms.ended = 1;
        CHECK(gz_lobby_member_resume(&ms, &A.l) == GZ_OK && SG.resumes == 0);
        ms.ended = 0;
        CHECK(gz_lobby_member_resume(&ms, &A.l) == GZ_OK && SG.resumes == 1);   /* the control */
        CHECK(gz_lobby_member_resume(&ms, NULL) == GZ_ERR_ARGUMENT);
        CHECK(gz_lobby_member_round_result(&ms, 0, NULL, &A.l) == GZ_ERR_ARGUMENT && gz_lobby_member_round_result(&ms, 5, NULL, &A.l) == GZ_ERR_ARGUMENT);
        CHECK(gz_lobby_member_round_result(&ms, GZ_LOBBY_ROUND_ACTIVE, NULL, NULL) == GZ_ERR_ARGUMENT);
        ms.ended = 1;                                  /* a completed creation is taken after a cancel too (B3) */
        acts_reset();
        CHECK(gz_lobby_member_round_result(&ms, GZ_LOBBY_ROUND_ACTIVE, NULL, &A.l) == GZ_OK && !refused(GZ_CMD_ROUND_RESULT) &&
              saves(GZ_REC_LOBBY_STATE) == 1 && ms.lobby_state == GZ_LOBBY_ACTIVE);
        acts_reset();
        CHECK(gz_lobby_member_round_result(&ms, GZ_LOBBY_ROUND_ACTIVE, NULL, &A.l) == GZ_OK && refused(GZ_CMD_ROUND_RESULT) && !any_save());
        CHECK(gz_lobby_member_round_result(&ms, GZ_LOBBY_ROUND_RETRY, held_check(&ms), &A.l) == GZ_OK && refused(GZ_CMD_ROUND_RESULT));
    }
    /* a lost unready is resent while Open or in a check, not once Signing */
    {
        static gz_lobby_member_t mu;
        member_sg(&mu, &cond);
        feed(&mu, ob, on);
        acts_reset();
        gz_lobby_member_unready(&mu, &A.l);
        n = st_msg(buf, sizeof buf, GZ_LOBBY_SIGNING, GZ_SEAT_READY, 1);
        CHECK(feed(&mu, buf, n) == GZ_OK && sends(GZ_KIND_UNREADY) == 0);
        n = st_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_READY, 1);
        CHECK(feed(&mu, buf, n) == GZ_OK && sends(GZ_KIND_UNREADY) == 1);
        mu.unready_reason = 0;                         /* restored from an older record: reason 2 */
        CHECK(feed(&mu, buf, n) == GZ_OK && last_sent(GZ_KIND_UNREADY, &g, NULL, NULL) && g.reason == 2);
    }

    /* S3: after the freeze a seat back in Joined readies by itself again */
    acts_reset();
    CHECK(gz_lobby_member_set_conditions(&m, &cond, &A.l) == GZ_OK && sends(GZ_KIND_READY) == 1);
    CHECK(last_sent(GZ_KIND_READY, &g, NULL, NULL) && !g.has_check_id && g.version == 1 && m.frozen);

    /* F2: a leave made while the connection was down reaches the host */
    mfree();
    member_sg(&m, &cond);
    feed(&m, ob, on); mkeep();
    m_in(&m, GZ_LIN_DISCONNECTED);
    acts_reset();
    CHECK(gz_lobby_member_leave(&m, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_ENDED) == 1 && sends(GZ_KIND_LEAVE) == 0);
    mkeep();
    CHECK(m_in(&m, GZ_LIN_CONNECTED) == GZ_OK && sends(GZ_KIND_HELLO) == 1);
    n = st_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_READY, 1);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_LEAVE) == 1 && last_sent(GZ_KIND_LEAVE, &g, NULL, NULL) && g.reason == 2);
    CHECK(feed(&m, ob, on) == GZ_OK && A.l.count == 0);                          /* nothing else */
    n = st_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_LEFT, 1);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(1) == 0 && sends(GZ_KIND_LEAVE) == 0);
    n = st_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_JOINED, 1);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_LEAVE) == 1);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_LEAVE) == 1);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_LEAVE) == 0);               /* three a connection */
    mrestore(&m2, &cond);                                                       /* and after a restart */
    CHECK(m2.left && m2.leave_reason == 2);
    CHECK(m_in(&m2, GZ_LIN_CONNECTED) == GZ_OK && sends(GZ_KIND_HELLO) == 1);
    n = st_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_READY, 1);
    CHECK(feed(&m2, buf, n) == GZ_OK && sends(GZ_KIND_LEAVE) == 1);
    /* F2: an unready made while down: resent when the host still shows Ready */
    member_sg(&m, &cond);
    feed(&m, ob, on);
    m_in(&m, GZ_LIN_DISCONNECTED);
    acts_reset();
    CHECK(gz_lobby_member_unready(&m, &A.l) == GZ_OK && saves(GZ_REC_READY_SENT) == 1 && sends(GZ_KIND_UNREADY) == 0);
    CHECK(m_in(&m, GZ_LIN_CONNECTED) == GZ_OK && sends(GZ_KIND_HELLO) == 1);
    n = st_msg(buf, sizeof buf, GZ_LOBBY_OPEN, GZ_SEAT_JOINED, 1);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_UNREADY) == 0 && sends(GZ_KIND_READY) == 0);
    n = st_msg(buf, sizeof buf, GZ_LOBBY_READY_CHECK, GZ_SEAT_READY, 1);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_UNREADY) == 1 && last_sent(GZ_KIND_UNREADY, &g, NULL, NULL) && g.reason == 2);
    n = st_msg(buf, sizeof buf, GZ_LOBBY_SIGNING, GZ_SEAT_CHOSEN, 1);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_UNREADY) == 0);

    /* m17: a signed cancel larger than the saved record can hold is not taken;
     * one that fits exactly is */
    {
        gz_lobby_enc_t e;
        gz_lobby_crypto_t hc = lt_crypto(&HOST);
        size_t pad, at256 = 0, at257 = 0;
        static uint8_t big[70000];
        memset(big, 0x61, sizeof big);
        for (pad = 1; pad < 400 && (!at256 || !at257); pad++) {
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_CANCEL, SCOPE);
            gz_lobby_enc_u16(&e, 2, 2);
            gz_lobby_enc_record(&e, 3, big, pad);
            n = gz_lobby_enc_sign(&e, &hc, GZ_LOBBY_KEY_HOST);
            if (n == 256) at256 = pad;
            if (n == 257) at257 = pad;
        }
        CHECK(at256 && at257);
        for (pad = 0; pad < 3; pad++) {
            size_t p = pad == 0 ? at256 : pad == 1 ? at257 : 60000;
            member_sg(&m, &cond);
            feed(&m, ob, on);
            gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_CANCEL, SCOPE);
            gz_lobby_enc_u16(&e, 2, 2);
            gz_lobby_enc_record(&e, 3, big, p);
            n = gz_lobby_enc_sign(&e, &hc, GZ_LOBBY_KEY_HOST);
            CHECK(n > 0 && gz_lobby_decode(buf, n, &g) == GZ_DEC_OK && g.kind == GZ_KIND_CANCEL);
            poison_stack();
            if (pad == 0) CHECK(feed(&m, buf, n) == GZ_OK && saves(GZ_REC_LOBBY_ENDED) == 1 && m.ended);
            else CHECK(feed(&m, buf, n) == GZ_OK && !any_save() && !m.ended);
        }
    }
    mfree();
}

static void test_review_host(void)
{
    static gz_lobby_host_t R2;
    uint8_t buf[600], chk[32], lv[64], hello[64];
    size_t n, lvn, hn, q;
    int i;
    gz_lobby_msg_t g;
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, lv, sizeof lv, GZ_KIND_LEAVE, SCOPE);
    lvn = gz_lobby_enc_done(&e);
    hn = hello_msg(hello, sizeof hello, SCOPE);

    /* F6: a check that started nobody; then strangers start nothing, a seat's
     * reconnect does */
    CLOCK = W_T0 - 3600000;
    host_open(0);
    for (i = 1; i <= 8; i++) seat_up(i, 8);
    CHECK(H.state == GZ_LOBBY_READY_CHECK && last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL));
    memcpy(chk, g.check_id, 32);
    for (i = 1; i <= 7; i++) {                       /* seven answer; each wants 8 members */
        n = ready_msg(buf, sizeof buf, i, 1, cd2_of(), chk, 8);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    /* b20: the rule is applied again as the window closes; only the failed-check
     * guard stops a new check here (no seat event since this one began) */
    CHECK(timer_in(GZ_LOBBY_TIMER_WINDOW) == GZ_OK && sends(GZ_KIND_START) == 0 && H.state == GZ_LOBBY_OPEN && H.check_failed);
    CHECK(sends(GZ_KIND_READY_CHECK) == 0);
    for (i = 20; i <= 23; i++) {
        CHECK(hin(GZ_LIN_CONNECTED, i, NULL, 0) == GZ_OK && sends(GZ_KIND_READY_CHECK) == 0);
        CHECK(hin(GZ_LIN_MESSAGE, i, hello, hn) == GZ_OK && sends(GZ_KIND_READY_CHECK) == 0);
    }
    n = ready_msg(buf, sizeof buf, 3, 1, cd2_of(), NULL, 8);   /* a duplicate ready: no change */
    CHECK(hin(GZ_LIN_MESSAGE, 3, buf, n) == GZ_OK && sends(GZ_KIND_READY_CHECK) == 0);
    fresh(8);                                        /* a ready seat reconnects */
    CHECK(sends(GZ_KIND_READY_CHECK) == 8 && H.state == GZ_LOBBY_READY_CHECK);
    /* F6: a seat whose min_members exceeds the target is not counted */
    host_open(0);
    for (i = 1; i <= 8; i++) seat_up(i, i == 8 ? 9 : 0);
    CHECK(H.state == GZ_LOBBY_OPEN);
    /* h20: the start rule counts connected seats only */
    host_open(0);
    for (i = 1; i <= 7; i++) seat_up(i, 0);
    hin(GZ_LIN_DISCONNECTED, 1, NULL, 0);
    seat_up(8, 0);
    CHECK(H.state == GZ_LOBBY_OPEN);
    CHECK(hin(GZ_LIN_CONNECTED, 1, NULL, 0) == GZ_OK && sends(GZ_KIND_READY_CHECK) == 8);

    /* F5: a ready the change limit refuses changes nothing in memory */
    host_open(0);
    seat_up(1, 0);                                   /* changes 1 and 2 */
    {
        uint8_t un[64], before[GZ_LOBBY_MAX_SAVED_MSG];
        size_t unn, bl;
        gz_lobby_enc_start(&e, un, sizeof un, GZ_KIND_UNREADY, SCOPE);
        unn = gz_lobby_enc_done(&e);
        for (i = 3; i <= 10; i++) {
            if (i % 2) hin(GZ_LIN_MESSAGE, 1, un, unn);
            else { n = ready_msg(buf, sizeof buf, 1, 1, cd2_of(), NULL, 0); hin(GZ_LIN_MESSAGE, 1, buf, n); }
            CHECK(saves(GZ_REC_SEAT) == 1);
        }
        CHECK(H.seats[0].state == GZ_SEAT_READY && H.seats[0].n_changes == 10);
        bl = H.seats[0].ready_len;
        memcpy(before, H.seats[0].ready_msg, bl);
        n = ready_msg(buf, sizeof buf, 1, 1, cd2_of(), NULL, 5);   /* new min_members */
        CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && !any_save() && sends(GZ_KIND_LOBBY_STATUS) == 1);
        CHECK(H.seats[0].min_members == 0 && H.seats[0].ready_len == bl && memcmp(H.seats[0].ready_msg, before, bl) == 0);
        {   /* a new version: the seat's ready for it is refused, and stays for version 1 */
            uint64_t v[3] = {1500, 1000, 1000};
            uint8_t cd3[32];
            acts_reset();
            CHECK(gz_lobby_host_set_values(&H, v, 3, &A.l) == GZ_OK);
            gz_terms_current_digest(T3, T3N, cd3);
            n = ready_msg(buf, sizeof buf, 1, 2, cd3, NULL, 0);
            CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_JOINED);
            CHECK(H.seats[0].ready_version == 1 && H.seats[0].state == GZ_SEAT_READY);
        }
    }

    /* F7: strangers hold 16 places at most; a seat's reconnect is never refused;
     * a stranger is closed 10 minutes after it came up, a silent one after 60 s */
    CLOCK = W_T0 - 3600000;
    host_open(0);
    seat_up(1, 0);
    for (i = 0; i < GZ_LOBBY_MAX_UNSEATED; i++)
        CHECK(lk_in(i, GZ_LIN_CONNECTED, MEM[20 + i].key[2].pub, NULL, 0) == GZ_OK && sends(1) == 0);
    CHECK(lk_in(1, GZ_LIN_MESSAGE, MEM[21].key[2].pub, hello, hn) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1);
    fresh(1);
    CHECK(sends(1) == 0 && has_conn(W_PEER(1)));
    CHECK(hin(GZ_LIN_MESSAGE, 1, hello, hn) == GZ_OK);
    CHECK(lk_in(16, GZ_LIN_CONNECTED, MEM[36].key[2].pub, NULL, 0) == GZ_OK && sends(1) == 1 && closed_peer(5000));
    CLOCK += 60000;
    CHECK(timer_in(GZ_LOBBY_TIMER_IDLE) == GZ_OK && closed_peer(5002) && !closed_peer(5001) && !closed_peer(W_PEER(1)));
    CLOCK += 540000;
    CHECK(timer_in(GZ_LOBBY_TIMER_IDLE) == GZ_OK && closed_peer(5001) && !closed_peer(W_PEER(1)));

    /* F8: three joins refused as invalid close the connection; refusals for a
     * limit cost no signature, and 32 of them close it too */
    host_open(0);
    hin(GZ_LIN_CONNECTED, 1, NULL, 0);
    n = join_msg(buf, sizeof buf, 1, MEM[1].key[3].pub, 2, 1);          /* bad bind_by_factory */
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && status_seat() == GZ_SEAT_REFUSED && !closed_peer(W_PEER(1)));
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && status_seat() == GZ_SEAT_REFUSED && !closed_peer(W_PEER(1)));
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && closed_peer(W_PEER(1)) && sends(GZ_KIND_LOBBY_STATUS) == 0);
    CHECK(hin(GZ_LIN_MESSAGE, 1, hello, hn) == GZ_OK && A.l.count == 0);         /* closed: nothing more */
    seat_up(2, 0);
    CHECK(hin(GZ_LIN_MESSAGE, 2, lv, lvn) == GZ_OK && status_seat() == GZ_SEAT_LEFT);
    n = join_msg(buf, sizeof buf, 2, MEM[2].key[3].pub, 2, 2);
    HOST.verifies = 0;
    for (i = 1; i <= 32; i++) {
        hin(GZ_LIN_MESSAGE, 2, buf, n);                                 /* a second creation on one connection */
        if (i < 32) CHECK(status_seat() == GZ_SEAT_REFUSED && !closed_peer(W_PEER(2)));
        else CHECK(closed_peer(W_PEER(2)) && sends(GZ_KIND_LOBBY_STATUS) == 0);   /* the 32nd closes */
    }
    CHECK(HOST.verifies == 0);

    /* h05: ten answers, target 8: the two who joined last are not chosen */
    CLOCK = W_T0 - 3600000;
    host_open(2);
    for (i = 1; i <= 7; i++) { seat_up(i, 0); CLOCK += 1000; }
    H.state = GZ_LOBBY_SIGNING;                       /* hold the check back while 8 to 10 join */
    for (i = 8; i <= 10; i++) { seat_up(i, 0); CLOCK += 1000; }
    H.state = GZ_LOBBY_OPEN;
    H.rule_dirty = 1;
    fresh(1);
    CHECK(H.state == GZ_LOBBY_READY_CHECK && last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL));
    memcpy(chk, g.check_id, 32);
    for (i = 10; i >= 1; i--) {                       /* answers arrive in reverse */
        n = ready_msg(buf, sizeof buf, i, 1, cd2_of(), chk, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CHECK(timer_in(GZ_LOBBY_TIMER_WINDOW) == GZ_OK && sends(GZ_KIND_START) == 10 && H.state == GZ_LOBBY_SIGNING);
    for (i = 1; i <= 10; i++) CHECK(H.seats[i - 1].chosen == (i <= 8));

    /* h09: without standby seats no join is taken during a check */
    host_open(0);
    for (i = 1; i <= 3; i++) seat_up(i, 0);
    H.state = GZ_LOBBY_READY_CHECK;
    hin(GZ_LIN_CONNECTED, 4, NULL, 0);
    n = join_msg(buf, sizeof buf, 4, MEM[4].key[3].pub, 4, 4);
    CHECK(hin(GZ_LIN_MESSAGE, 4, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED &&
          status_to(4, &g) && !g.has_reason);
    H.state = GZ_LOBBY_OPEN;
    CHECK(hin(GZ_LIN_MESSAGE, 4, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1);

    /* S5 and h11: a burst of `target` creations passes, then one a second */
    host_open(4);
    for (i = 1; i <= 9; i++) {
        hin(GZ_LIN_CONNECTED, i, NULL, 0);
        n = join_msg(buf, sizeof buf, i, MEM[i].key[3].pub, i, i);
        CHECK(hin(GZ_LIN_MESSAGE, i, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == (i <= 8));
    }
    CLOCK += 999;
    CHECK(hin(GZ_LIN_MESSAGE, 9, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    CLOCK += 1;
    CHECK(hin(GZ_LIN_MESSAGE, 9, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1);
    hin(GZ_LIN_CONNECTED, 10, NULL, 0);
    n = join_msg(buf, sizeof buf, 10, MEM[10].key[3].pub, 10, 10);
    CHECK(hin(GZ_LIN_MESSAGE, 10, buf, n) == GZ_OK && !any_save());

    /* h18: a restored freeze must name the restored values */
    for (q = 0; q < N_KEPT; q++) free(KEPT_B[q]);
    N_KEPT = 0;
    CLOCK = W_T0 - 3600000;
    host_open(0);
    keep_all();
    {
        uint8_t cm[300], fz[400], cd3[32];
        size_t cml, fn;
        gz_record_t r;
        int v;
        gz_terms_current_digest(T3, T3N, cd3);
        for (v = 1; v <= 3; v++) {
            cml = host_msg(cm, sizeof cm, GZ_KIND_READY_CHECK, chk, (uint32_t)(v == 3 ? 2 : v), v == 2 ? cd3 : cd2_of(), 30000, 0, &HOST);
            memcpy(fz, chk, 32);
            gz_lw_put(fz + 32, (uint64_t)(v == 3 ? 2 : v), 4);
            memcpy(fz + 36, v == 2 ? cd3 : cd2_of(), 32);
            fn = 68 + gz_la_put_blob(fz + 68, cm, cml);
            CHECK(gz_la_freeze_ok(fz, fn));
            restore_kept(&R2);
            r.type = GZ_REC_FREEZE; r.bytes.data = fz; r.bytes.len = fn;
            CHECK(gz_lobby_host_restore(&R2, &r) == (v == 1 ? GZ_OK : GZ_ERR_CORRUPT));
        }
    }

    /* F3, S1: the signing budget, a resumed hand-off, a chosen seat's leave */
    memset(&SG, 0, sizeof SG);
    for (i = 1; i <= 8; i++) {
        seat_up(i, 0);
        keep_all();
    }
    H.signing = sg();
    CHECK(H.state == GZ_LOBBY_READY_CHECK && last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL));
    memcpy(chk, g.check_id, 32);
    for (i = 1; i <= 8; i++) {
        n = ready_msg(buf, sizeof buf, i, 1, cd2_of(), chk, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CHECK(timer_in(GZ_LOBBY_TIMER_WINDOW) == GZ_OK && sends(GZ_KIND_START) == 8 && SG.begins == 1 && SG.signers == 9);
    CHECK(timers(GZ_LOBBY_TIMER_BUDGET) == 1 && H.budget_ms == CLOCK && SG.sigs && !SG.limits);
    keep_all();
    CHECK(hin(GZ_LIN_MESSAGE, 1, lv, lvn) == GZ_OK && saves(GZ_REC_SEAT) == 1 && H.seats[0].state == GZ_SEAT_LEFT);
    CHECK(seated_notes(MEM[1].key[2].pub, 0) == 0 && SG.lefts == 1);           /* held for the round */
    keep_all();
    restore_kept(&R2);
    R2.signing = sg();
    acts_reset();
    CHECK(gz_lobby_host_resume(&R2, &A.l) == GZ_OK && SG.resumes == 1 && R2.budget_ms == H.budget_ms);
    CHECK(seated_notes(MEM[1].key[2].pub, 1) == 1 && seated_notes(NULL, 1) == 8 && timers(GZ_LOBBY_TIMER_BUDGET) == 1);
    CLOCK += 599999;
    CHECK(timer_in(GZ_LOBBY_TIMER_BUDGET) == GZ_OK && A.l.count == 0);        /* Signing: the signing engine's (B3) */
    CLOCK += 1;
    CHECK(timer_in(GZ_LOBBY_TIMER_BUDGET) == GZ_OK && A.l.count == 0 && H.state == GZ_LOBBY_SIGNING && SG.cancels == 0);
    acts_reset();                                      /* the signing engine says the budget is spent */
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_FAILED, NULL, 0, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_ENDED) == 1 &&
          sends(GZ_KIND_CANCEL) == 8);
    CHECK(H.state == GZ_LOBBY_FAILED && H.end_reason == 3 && SG.cancels == 1 && seated_notes(MEM[1].key[2].pub, 0) == 1);
    CHECK(timer_in(GZ_LOBBY_TIMER_BUDGET) == GZ_OK && A.l.count == 0);        /* ended: nothing more */
    for (q = 0; q < N_KEPT; q++) free(KEPT_B[q]);
    N_KEPT = 0;
}

/* ---------------------------------------- review B of PR 30: findings */

static void test_review_b_host(void)
{
    static gz_lobby_host_t R2;
    uint8_t buf[600], chk[32], un[64], lv[64], hello[64];
    size_t n, unn, lvn, hn, q;
    int i, r;
    uint64_t t0;
    gz_lobby_msg_t g;
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, un, sizeof un, GZ_KIND_UNREADY, SCOPE);
    unn = gz_lobby_enc_done(&e);
    gz_lobby_enc_start(&e, lv, sizeof lv, GZ_KIND_LEAVE, SCOPE);
    lvn = gz_lobby_enc_done(&e);
    hn = hello_msg(hello, sizeof hello, SCOPE);

    /* B1: a chosen seat that left cannot join again with new keys while its
     * attempt runs (refused for a limit: it may try again); after the outcome
     * it can */
    memset(&SG, 0, sizeof SG);
    CLOCK = W_T0 - 3600000;
    host_open(1);
    H.signing = sg();
    for (i = 1; i <= 8; i++) { seat_up(i, 0); CLOCK += 1000; }
    CHECK(H.state == GZ_LOBBY_READY_CHECK && last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL));
    memcpy(chk, g.check_id, 32);
    for (i = 1; i <= 8; i++) {
        n = ready_msg(buf, sizeof buf, i, 1, cd2_of(), chk, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CHECK(timer_in(GZ_LOBBY_TIMER_WINDOW) == GZ_OK && H.state == GZ_LOBBY_SIGNING && H.seats[0].chosen && SG.begins == 1);
    CHECK(hin(GZ_LIN_MESSAGE, 1, lv, lvn) == GZ_OK && H.seats[0].state == GZ_SEAT_LEFT && SG.lefts == 1);
    fresh(1);
    CHECK(has_conn(W_PEER(1)));                                     /* held: still seated */
    n = join_msg(buf, sizeof buf, 1, MEM[30].key[3].pub, 30, 1);    /* the same contribution key, a new factory key */
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED &&
          status_to(1, &g) && !g.has_reason && !closed_peer(W_PEER(1)));
    CHECK(H.seats[0].chosen && H.seats[0].state == GZ_SEAT_LEFT && memcmp(H.seats[0].fkey, MEM[1].key[3].pub, 33) == 0);
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_RETRY, NULL, 0, &A.l) == GZ_OK && H.state == GZ_LOBBY_OPEN);
    CHECK(timers(GZ_LOBBY_TIMER_DEADLINE) == 1 && timers(GZ_LOBBY_TIMER_BUDGET) == 1);   /* B4, B3 */
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1 && H.seats[0].state == GZ_SEAT_JOINED &&
          memcmp(H.seats[0].fkey, MEM[30].key[3].pub, 33) == 0);
    /* B1 at restore: a seat record that changes a chosen seat's keys in
     * Signing is not this engine's */
    drive_to_signing(3, 0);
    CHECK(H.state == GZ_LOBBY_SIGNING && H.seats[0].chosen);
    {
        uint8_t rec[600];
        size_t rl = 0;
        gz_record_t x;
        for (q = 0; q < N_KEPT; q++)
            if (KEPT[q].type == GZ_REC_SEAT && memcmp(KEPT[q].bytes.data, MEM[1].key[2].pub, 33) == 0 &&
                KEPT[q].bytes.len <= sizeof rec) {
                rl = KEPT[q].bytes.len;
                memcpy(rec, KEPT[q].bytes.data, rl);
            }
        CHECK(rl > 0);
        x.type = GZ_REC_SEAT; x.bytes.data = rec; x.bytes.len = rl;
        restore_kept(&R2);
        CHECK(R2.state == GZ_LOBBY_SIGNING && gz_lobby_host_restore(&R2, &x) == GZ_OK);      /* the same keys */
        memcpy(rec + 33, MEM[30].key[3].pub, 33);
        CHECK(gz_lobby_host_restore(&R2, &x) == GZ_ERR_CORRUPT);
    }

    /* B3: once handed over, the budget is the signing engine's. In Signing the
     * lobby's timer cancels nothing; a later Funding is taken; from Funding on
     * the timer does nothing (b13) */
    memset(&SG, 0, sizeof SG);
    drive_to_signing(3, 0);
    H.signing = sg();
    t0 = H.budget_ms;
    CHECK(H.state == GZ_LOBBY_SIGNING && t0 == CLOCK);
    CLOCK = t0 + H.terms.signing_budget_ms + 1;
    CHECK(timer_in(GZ_LOBBY_TIMER_BUDGET) == GZ_OK && A.l.count == 0 && H.state == GZ_LOBBY_SIGNING && SG.cancels == 0);
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_FUNDING, NULL, 0, &A.l) == GZ_OK && !refused(GZ_CMD_ROUND_RESULT) &&
          H.state == GZ_LOBBY_FUNDING && saves(GZ_REC_LOBBY_STATE) == 1);
    CHECK(timer_in(GZ_LOBBY_TIMER_BUDGET) == GZ_OK && A.l.count == 0 && H.state == GZ_LOBBY_FUNDING);
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_FUNDING, NULL, 0, &A.l) == GZ_OK && refused(GZ_CMD_ROUND_RESULT));
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_ACTIVE, NULL, 0, &A.l) == GZ_OK && H.state == GZ_LOBBY_ACTIVE);
    CHECK(timer_in(GZ_LOBBY_TIMER_BUDGET) == GZ_OK && A.l.count == 0 && H.state == GZ_LOBBY_ACTIVE);
    /* a Funding after the lobby ended by a cancel while Signing is taken, and
     * restored; the cancel is not shown or resent any more */
    drive_to_signing(3, 0);
    acts_reset();
    CHECK(gz_lobby_host_cancel(&H, 2, &A.l) == GZ_OK && H.state == GZ_LOBBY_CANCELLED);
    keep_all();
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_FUNDING, NULL, 0, &A.l) == GZ_OK && !refused(GZ_CMD_ROUND_RESULT) &&
          H.state == GZ_LOBBY_FUNDING && saves(GZ_REC_LOBBY_STATE) == 1 && H.cancel_len == 0 && H.end_reason == 0);
    keep_all();
    restore_kept(&R2);
    CHECK(R2.state == GZ_LOBBY_FUNDING && R2.cancel_len == 0 && R2.end_reason == 0);
    /* but never for a lobby that handed nothing over */
    CLOCK = W_T0 - 3600000;
    host_open(0);
    acts_reset();
    CHECK(gz_lobby_host_cancel(&H, 2, &A.l) == GZ_OK);
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_FUNDING, NULL, 0, &A.l) == GZ_OK && refused(GZ_CMD_ROUND_RESULT) &&
          !any_save() && H.state == GZ_LOBBY_CANCELLED);
    /* b10: one budget for all attempts. After a retry the lobby's timer covers
     * the next check (b12: not early), and cancels once it is spent */
    drive_to_signing(5, 0);
    t0 = H.budget_ms;
    CLOCK += 60000;
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_RETRY, NULL, 0, &A.l) == GZ_OK && H.state == GZ_LOBBY_READY_CHECK);
    CHECK(timers(GZ_LOBBY_TIMER_BUDGET) == 1 && last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL));
    memcpy(chk, g.check_id, 32);
    for (i = 1; i <= 5; i++) {
        n = ready_msg(buf, sizeof buf, i, 1, cd2_of(), chk, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CHECK(timer_in(GZ_LOBBY_TIMER_WINDOW) == GZ_OK && sends(GZ_KIND_START) == 5 && H.state == GZ_LOBBY_SIGNING);
    CHECK(H.budget_ms == t0);
    for (q = 0, r = 0; q < A.l.count; q++)
        if (A.s[q].kind == GZ_ACTION_SAVE && A.s[q].u.save.records[0].type == GZ_REC_START_SENT)
            r = gz_lw_get(A.s[q].u.save.records[0].bytes.data + 32, 8) == t0;
    CHECK(r);
    acts_reset();
    CHECK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_RETRY, NULL, 0, &A.l) == GZ_OK && H.state == GZ_LOBBY_READY_CHECK);
    CLOCK = t0 + H.terms.signing_budget_ms - 1;
    CHECK(timer_in(GZ_LOBBY_TIMER_BUDGET) == GZ_OK && timers(GZ_LOBBY_TIMER_BUDGET) == 1 && !any_save() &&
          H.state == GZ_LOBBY_READY_CHECK);
    CLOCK += 1;
    CHECK(timer_in(GZ_LOBBY_TIMER_BUDGET) == GZ_OK && H.state == GZ_LOBBY_FAILED && H.end_reason == 3);

    /* B5: a seat whose min_members exceeds the target is left out before the
     * cut: with a standby place, eight members are chosen, not seven */
    memset(&SG, 0, sizeof SG);
    CLOCK = W_T0 - 3600000;
    host_open(1);
    H.signing = sg();
    seat_up(1, 65535);
    for (i = 2; i <= 9; i++) { CLOCK += 1000; seat_up(i, 0); }
    CHECK(H.state == GZ_LOBBY_READY_CHECK && last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL));
    memcpy(chk, g.check_id, 32);
    for (i = 1; i <= 9; i++) {
        n = ready_msg(buf, sizeof buf, i, 1, cd2_of(), chk, i == 1 ? 65535 : 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CHECK(timer_in(GZ_LOBBY_TIMER_WINDOW) == GZ_OK && H.state == GZ_LOBBY_SIGNING && SG.signers == 9);
    CHECK(sends(GZ_KIND_START) == 8 && !H.seats[0].chosen);
    for (i = 2; i <= 9; i++) CHECK(H.seats[i - 1].chosen);

    /* B6: moves that take a seat out are never limited. Seats 1 and 2 spend
     * their ten changes; seat 1 still withdraws from the check, and chosen
     * seat 2 still leaves while Signing (the signing engine is told) */
    memset(&SG, 0, sizeof SG);
    CLOCK = W_T0 - 3600000;
    host_open(0);
    H.signing = sg();
    for (i = 1; i <= 8; i++) {
        hin(GZ_LIN_CONNECTED, i, NULL, 0);
        n = join_msg(buf, sizeof buf, i, MEM[i].key[3].pub, i, i);
        hin(GZ_LIN_MESSAGE, i, buf, n);
        CLOCK += 1000;
    }
    for (r = 0; r < 4; r++)
        for (i = 1; i <= 2; i++) {
            n = ready_msg(buf, sizeof buf, i, 1, cd2_of(), NULL, 0);
            hin(GZ_LIN_MESSAGE, i, buf, n);
            hin(GZ_LIN_MESSAGE, i, un, unn);
        }
    for (i = 1; i <= 8; i++) {
        n = ready_msg(buf, sizeof buf, i, 1, cd2_of(), NULL, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CHECK(H.state == GZ_LOBBY_READY_CHECK && H.seats[0].n_changes == 10 && H.seats[1].n_changes == 10);
    last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL);
    memcpy(chk, g.check_id, 32);
    for (i = 1; i <= 8; i++) {
        n = ready_msg(buf, sizeof buf, i, 1, cd2_of(), chk, 0);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    CHECK(hin(GZ_LIN_MESSAGE, 1, un, unn) == GZ_OK && saves(GZ_REC_SEAT) == 1 && H.seats[0].state == GZ_SEAT_JOINED &&
          !H.seats[0].answered);
    CHECK(timer_in(GZ_LOBBY_TIMER_WINDOW) == GZ_OK && H.state == GZ_LOBBY_SIGNING && !H.seats[0].chosen && H.seats[1].chosen);
    CHECK(sends(GZ_KIND_START) == 7);
    CHECK(hin(GZ_LIN_MESSAGE, 2, lv, lvn) == GZ_OK && saves(GZ_REC_SEAT) == 1 && H.seats[1].state == GZ_SEAT_LEFT &&
          SG.lefts == 1);
    n = ready_msg(buf, sizeof buf, 1, 1, cd2_of(), NULL, 0);        /* a move into Ready is still limited */
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && !any_save() && H.seats[0].state == GZ_SEAT_JOINED);

    /* B7 and b01: eviction never takes a seated connection, even the oldest;
     * among unseated ones it takes one that has said nothing first */
    CLOCK = W_T0 - 3600000;
    host_open(0);
    seat_up(1, 0);
    fresh(1);                                        /* seated, silent, and older than every stranger */
    for (i = 0; i < GZ_LOBBY_MAX_UNSEATED; i++)
        CHECK(lk_in(i, GZ_LIN_CONNECTED, MEM[20 + i].key[2].pub, NULL, 0) == GZ_OK && A.l.count <= 1);
    CHECK(lk_in(16, GZ_LIN_CONNECTED, MEM[36].key[2].pub, NULL, 0) == GZ_OK && closed_peer(5000) &&
          !closed_peer(W_PEER(1)) && has_conn(W_PEER(1)));
    host_open(0);
    CHECK(lk_in(0, GZ_LIN_CONNECTED, MEM[20].key[2].pub, NULL, 0) == GZ_OK);
    CHECK(lk_in(0, GZ_LIN_MESSAGE, MEM[20].key[2].pub, hello, hn) == GZ_OK && sends(GZ_KIND_TERMS_OFFER) == 1);
    for (i = 1; i < GZ_LOBBY_MAX_UNSEATED; i++) CHECK(lk_in(i, GZ_LIN_CONNECTED, MEM[20 + i].key[2].pub, NULL, 0) == GZ_OK);
    CHECK(lk_in(16, GZ_LIN_CONNECTED, MEM[36].key[2].pub, NULL, 0) == GZ_OK && closed_peer(5001) && !closed_peer(5000) &&
          has_conn(5000));

    /* b20: a seat event during a check that starts nobody allows a new check
     * as soon as the window closes (the guard waits only without one) */
    CLOCK = W_T0 - 3600000;
    host_open(0);
    for (i = 1; i <= 8; i++) seat_up(i, 8);
    CHECK(H.state == GZ_LOBBY_READY_CHECK && last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL));
    memcpy(chk, g.check_id, 32);
    for (i = 1; i <= 7; i++) {
        n = ready_msg(buf, sizeof buf, i, 1, cd2_of(), chk, 8);
        hin(GZ_LIN_MESSAGE, i, buf, n);
    }
    fresh(8);                                        /* seat 8 reconnects during the check */
    CHECK(sends(GZ_KIND_READY_CHECK) == 0 && H.state == GZ_LOBBY_READY_CHECK);
    CHECK(timer_in(GZ_LOBBY_TIMER_WINDOW) == GZ_OK && sends(GZ_KIND_START) == 0 && sends(GZ_KIND_READY_CHECK) == 8 &&
          H.state == GZ_LOBBY_READY_CHECK);
    last_sent(GZ_KIND_READY_CHECK, &g, NULL, NULL);
    CHECK(memcmp(g.check_id, chk, 32) != 0);
    for (q = 0; q < N_KEPT; q++) free(KEPT_B[q]);
    N_KEPT = 0;
}

static void test_review_b_member(void)
{
    static gz_lobby_member_t mb, mb2;
    static uint8_t x[600], ob[8000];
    gz_lobby_conditions_t cond = lt_cond_fits();
    uint8_t chk[32], cd2[32];
    size_t xn, on;
    gz_record_t r;
    int o;
    memcpy(cd2, cd2_of(), 32);
    memset(chk, 0x5c, 32);
    on = offer(ob, sizeof ob, SCOPE, T1, T1N, T2, T2N, &HOST);

    /* B2: the member saves the signing outcome, so a restart after Retry or
     * after Active never hands the finished check to the signing engine again */
    for (o = 0; o < 3; o++) {
        memset(&SG, 0, sizeof SG);
        mfree();
        member_sg(&mb, &cond);
        CHECK(feed(&mb, ob, on) == GZ_OK); mkeep();
        xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
        CHECK(feed(&mb, x, xn) == GZ_OK); mkeep();
        xn = host_msg(x, sizeof x, GZ_KIND_START, chk, 0, NULL, 0, 1, &HOST);
        CHECK(feed(&mb, x, xn) == GZ_OK && SG.begins == 1); mkeep();
        acts_reset();
        if (o == 0) {
            CHECK(gz_lobby_member_round_result(&mb, GZ_LOBBY_ROUND_RETRY, held_check(&mb), &A.l) == GZ_OK && saves(GZ_REC_LOBBY_STATE) == 1);
            mkeep();
            CHECK(mb.start_len == 0 && mb.role == 0);          /* the start is spent */
            acts_reset();                                     /* so a repeated Retry saves nothing */
            CHECK(gz_lobby_member_round_result(&mb, GZ_LOBBY_ROUND_RETRY, held_check(&mb), &A.l) == GZ_OK && !any_save());
        } else if (o == 1) {
            CHECK(gz_lobby_member_round_result(&mb, GZ_LOBBY_ROUND_FUNDING, NULL, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_STATE) == 1);
            mkeep();
            acts_reset();
            CHECK(gz_lobby_member_round_result(&mb, GZ_LOBBY_ROUND_ACTIVE, NULL, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_STATE) == 1);
            mkeep();
        }   /* o == 2: the control, no outcome: the start resumes */
        mrestore(&mb2, &cond);
        acts_reset();
        CHECK(gz_lobby_member_resume(&mb2, &A.l) == GZ_OK && SG.begins == 1 && SG.resumes == (o == 2));
        if (o == 0) CHECK(mb2.start_len == 0 && mb2.role == 0 && mb2.round_state == 0);
        if (o == 1) CHECK(mb2.round_state == GZ_LOBBY_ACTIVE && mb2.lobby_state == GZ_LOBBY_ACTIVE && mb2.start_len == xn);
        /* a later start for a new check is taken after a retry */
        if (o == 0) {
            uint8_t chk2[32];
            memset(chk2, 0x5d, 32);
            CHECK(m_in(&mb2, GZ_LIN_CONNECTED) == GZ_OK);
            xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk2, 1, cd2, 30000, 0, &HOST);
            CHECK(feed(&mb2, x, xn) == GZ_OK && gz_lobby_member_may_sign(&mb2, chk2));
            xn = host_msg(x, sizeof x, GZ_KIND_START, chk2, 0, NULL, 0, 1, &HOST);
            CHECK(feed(&mb2, x, xn) == GZ_OK && SG.begins == 2);
        }
    }
    /* N1 (confirmation review): the member answered check 2 before its signing
     * engine reported the Retry of check 1. The Retry spends check 1's start
     * but keeps the answer to check 2, live (o 0) and after a restart (o 1),
     * and check 2's start then begins. */
    for (o = 0; o < 2; o++) {
        uint8_t chk2[32];
        gz_lobby_member_t *mp = &mb;
        memset(chk2, 0x5d, 32);
        memset(&SG, 0, sizeof SG);
        mfree();
        member_sg(&mb, &cond);
        CHECK(feed(&mb, ob, on) == GZ_OK); mkeep();
        xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
        CHECK(feed(&mb, x, xn) == GZ_OK); mkeep();
        xn = host_msg(x, sizeof x, GZ_KIND_START, chk, 0, NULL, 0, 1, &HOST);
        CHECK(feed(&mb, x, xn) == GZ_OK && SG.begins == 1); mkeep();
        xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk2, 1, cd2, 30000, 0, &HOST);
        CHECK(feed(&mb, x, xn) == GZ_OK && gz_lobby_member_may_sign(&mb, chk2)); mkeep();
        acts_reset();
        CHECK(gz_lobby_member_round_result(&mb, GZ_LOBBY_ROUND_RETRY, chk2, &A.l) == GZ_OK && !any_save() &&
              mb.start_len != 0);                                /* names another check: ignored */
        CHECK(gz_lobby_member_round_result(&mb, GZ_LOBBY_ROUND_RETRY, NULL, &A.l) == GZ_ERR_ARGUMENT);
        acts_reset();
        CHECK(gz_lobby_member_round_result(&mb, GZ_LOBBY_ROUND_RETRY, chk, &A.l) == GZ_OK && saves(GZ_REC_LOBBY_STATE) == 1);
        mkeep();
        CHECK(mb.start_len == 0 && mb.role == 0 && gz_lobby_member_may_sign(&mb, chk2));
        if (o == 1) {
            mrestore(&mb2, &cond);
            mp = &mb2;
            CHECK(mb2.start_len == 0 && gz_lobby_member_may_sign(&mb2, chk2) && !gz_lobby_member_may_sign(&mb2, chk));
            acts_reset();
            CHECK(gz_lobby_member_resume(&mb2, &A.l) == GZ_OK && SG.begins == 1);
            CHECK(m_in(&mb2, GZ_LIN_CONNECTED) == GZ_OK);
        }
        xn = host_msg(x, sizeof x, GZ_KIND_START, chk, 0, NULL, 0, 1, &HOST);   /* check 1's, resent: ignored */
        CHECK(feed(mp, x, xn) == GZ_OK && SG.begins == 1);
        xn = host_msg(x, sizeof x, GZ_KIND_START, chk2, 0, NULL, 0, 1, &HOST);
        CHECK(feed(mp, x, xn) == GZ_OK && SG.begins == 2);
    }
    /* The second case: check 2's start arrived, and was handed over, before
     * the Retry of check 1. That Retry names check 1, not the start held, so
     * it is ignored and check 2 proceeds, live (o 0) and after a restart
     * (o 1: resumed). A Retry naming check 2 is then taken. */
    for (o = 0; o < 2; o++) {
        uint8_t chk2[32];
        gz_lobby_member_t *mp = &mb;
        memset(chk2, 0x5d, 32);
        memset(&SG, 0, sizeof SG);
        mfree();
        member_sg(&mb, &cond);
        CHECK(feed(&mb, ob, on) == GZ_OK); mkeep();
        xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
        CHECK(feed(&mb, x, xn) == GZ_OK); mkeep();
        xn = host_msg(x, sizeof x, GZ_KIND_START, chk, 0, NULL, 0, 1, &HOST);
        CHECK(feed(&mb, x, xn) == GZ_OK && SG.begins == 1); mkeep();
        xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk2, 1, cd2, 30000, 0, &HOST);
        CHECK(feed(&mb, x, xn) == GZ_OK && gz_lobby_member_may_sign(&mb, chk2)); mkeep();
        xn = host_msg(x, sizeof x, GZ_KIND_START, chk2, 0, NULL, 0, 1, &HOST);
        CHECK(feed(&mb, x, xn) == GZ_OK && SG.begins == 2); mkeep();
        acts_reset();
        CHECK(gz_lobby_member_round_result(&mb, GZ_LOBBY_ROUND_RETRY, chk, &A.l) == GZ_OK && !any_save());
        CHECK(memcmp(held_check(&mb), chk2, 32) == 0 && mb.role == 1 && gz_lobby_member_may_sign(&mb, chk2));
        if (o == 1) {
            mrestore(&mb2, &cond);
            mp = &mb2;
            acts_reset();
            CHECK(gz_lobby_member_resume(&mb2, &A.l) == GZ_OK && SG.begins == 2 && SG.resumes == 1);
            CHECK(memcmp(held_check(&mb2), chk2, 32) == 0 && gz_lobby_member_may_sign(&mb2, chk2));
        }
        acts_reset();
        CHECK(gz_lobby_member_round_result(mp, GZ_LOBBY_ROUND_RETRY, chk2, &A.l) == GZ_OK &&
              saves(GZ_REC_LOBBY_STATE) == 1 && mp->start_len == 0 && !gz_lobby_member_may_sign(mp, chk2));
    }
    /* restore follows the rule too: a retry record that names another check
     * than the start restored changes nothing */
    {
        uint8_t rb[33];
        mfree();
        member_sg(&mb, &cond);
        CHECK(feed(&mb, ob, on) == GZ_OK); mkeep();
        xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, chk, 1, cd2, 30000, 0, &HOST);
        CHECK(feed(&mb, x, xn) == GZ_OK); mkeep();
        xn = host_msg(x, sizeof x, GZ_KIND_START, chk, 0, NULL, 0, 1, &HOST);
        CHECK(feed(&mb, x, xn) == GZ_OK); mkeep();
        mrestore(&mb2, &cond);
        rb[0] = GZ_LOBBY_OPEN;
        memset(rb + 1, 0x5d, 32);
        r.type = GZ_REC_LOBBY_STATE; r.bytes.data = rb; r.bytes.len = 33;
        CHECK(gz_lobby_member_restore(&mb2, &r) == GZ_OK && mb2.start_len != 0 && gz_lobby_member_may_sign(&mb2, chk));
        memcpy(rb + 1, chk, 32);
        CHECK(gz_lobby_member_restore(&mb2, &r) == GZ_OK && mb2.start_len == 0 && !gz_lobby_member_may_sign(&mb2, chk));
    }
    /* the record: 1 Open with the spent check (33 bytes), 4 Funding or 5
     * Active alone; nothing else */
    {
        uint8_t rb[34];
        memset(rb, 0x5c, sizeof rb);
        member_sg(&mb, &cond);
        r.type = GZ_REC_LOBBY_STATE; r.bytes.data = rb;
        for (o = 0; o < 8; o++) {
            rb[0] = (uint8_t)o;
            r.bytes.len = 1;
            CHECK(gz_lobby_member_restore(&mb, &r) == (o == 4 || o == 5 ? GZ_OK : GZ_ERR_CORRUPT));
            r.bytes.len = 33;
            CHECK(gz_lobby_member_restore(&mb, &r) == (o == 1 ? GZ_OK : GZ_ERR_CORRUPT));
        }
        rb[0] = 1;
        r.bytes.len = 2;
        CHECK(gz_lobby_member_restore(&mb, &r) == GZ_ERR_CORRUPT);
        r.bytes.len = 34;
        CHECK(gz_lobby_member_restore(&mb, &r) == GZ_ERR_CORRUPT);
    }
    mfree();
}

static int wr_run_to(world_t *w, int state, int max)
{
    int k;
    for (k = 0; k < max; k++) {
        if (w->node[0].alive && w->node[0].host->state == state) return 1;
        w_step(w, 0);
    }
    return w->node[0].alive && w->node[0].host->state == state;
}

static gz_lobby_seat_t *wr_seat(world_t *w, int i)
{
    gz_lobby_host_t *h = w->node[0].host;
    int k;
    for (k = 0; k < h->n_seats; k++)
        if (memcmp(h->seats[k].ckey, w->node[i].keys.key[2].pub, 33) == 0) return &h->seats[k];
    return NULL;
}

static void wr_host_result(world_t *w, int outcome, const uint8_t *failed, size_t n_failed)
{
    gz_action_list_t l;
    gz_action_list_init(&l, w_slots, 512, w_bytes, sizeof w_bytes);
    CHECK(gz_lobby_host_round_result(w->node[0].host, outcome, failed, n_failed, &l) == GZ_OK);
    w_submit(&w->node[0], &l);
}

/* Member i: the signing engine's outcome, or (0) the user's leave. */
static void wr_member(world_t *w, int i, int outcome)
{
    gz_action_list_t l;
    gz_action_list_init(&l, w_slots, 512, w_bytes, sizeof w_bytes);
    CHECK((outcome ? gz_lobby_member_round_result(w->node[i].mem, outcome, held_check(w->node[i].mem), &l) : gz_lobby_member_leave(w->node[i].mem, &l)) == GZ_OK);
    w_submit(&w->node[i], &l);
}

/* A member chosen for the host's current check whose signing engine began it. */
static int wr_chosen(world_t *w)
{
    const gz_lobby_host_t *h = w->node[0].host;
    int i, k;
    for (i = 1; i <= w->n; i++) {
        gz_lobby_seat_t *s = wr_seat(w, i);
        if (!s || !s->chosen) continue;
        for (k = 0; k < w->node[i].n_handoffs; k++)
            if (memcmp(w->node[i].handoffs[k].check, h->check_id, 32) == 0) return i;
    }
    return -1;
}

static void test_review_b_world(void)
{
    static world_t w;
    uint8_t C[32], fk_old[33], failed[33 * GZ_LOBBY_MAX_SEATS];
    gz_lobby_seat_t *s;
    gz_lobby_host_t *h;
    size_t k, nf;
    int c, o, i, e0, r0;

    /* B1, review B's scenario S1: a chosen seat leaves while Signing, comes
     * back with the same contribution key and a new factory key, and then the
     * host restarts. The seat keeps the keys it was chosen with, and the
     * resumed hand-off names the same participants (the model's V2) */
    w_init(&w, 8, 11, NULL);
    w.standbys = 1;
    w_start(&w);
    CHECK(wr_run_to(&w, GZ_LOBBY_SIGNING, 6000));
    w_run(&w, 40, 0);
    memcpy(C, w.node[0].host->check_id, 32);
    c = wr_chosen(&w);
    CHECK(c > 0);
    if (c > 0) {
        wr_member(&w, c, 0);
        w_run(&w, 40, 0);
        s = wr_seat(&w, c);
        CHECK(s && s->state == GZ_SEAT_LEFT && s->chosen && w.node[0].n_left == 1);
        memcpy(fk_old, s->fkey, 33);
        w_crash(&w, c);
        for (k = 0; k < w.node[c].n_recs; k++) free(w.node[c].recs[k].b);
        w.node[c].n_recs = 0;
        lt_key(&w.node[c].keys.key[3], "review b rejoin factory");
        w_boot(&w.node[c]);
        w_run(&w, 200, 0);
        s = wr_seat(&w, c);
        CHECK(w.node[c].mem->joined && s->state == GZ_SEAT_LEFT && s->chosen && memcmp(s->fkey, fk_old, 33) == 0);
        w_confirm(&w.node[0]);
        w_crash(&w, 0);
        w_boot(&w.node[0]);
        w_run(&w, 200, 0);
        h = w.node[0].host;
        s = wr_seat(&w, c);
        CHECK(h->state == GZ_LOBBY_SIGNING && memcmp(h->check_id, C, 32) == 0 && w.node[0].n_resumes >= 1);
        CHECK(s->chosen && memcmp(s->fkey, fk_old, 33) == 0 && w.node[0].n_v2 == 0 && w.failures == 0);
    }
    w_free(&w);

    /* B2, scenario S2: the member's signing engine reports Retry, or Active;
     * the member restarts and its signing engine is not handed the finished
     * check again (the model's V1); nor the host's after Active */
    for (o = 0; o < 2; o++) {
        w_init(&w, 8, 12, NULL);
        w_start(&w);
        CHECK(wr_run_to(&w, GZ_LOBBY_SIGNING, 6000));
        w_run(&w, 40, 0);
        memcpy(C, w.node[0].host->check_id, 32);
        c = wr_chosen(&w);
        CHECK(c > 0);
        if (c > 0) {
            if (o) {
                wr_host_result(&w, GZ_LOBBY_ROUND_FUNDING, NULL, 0);
                wr_host_result(&w, GZ_LOBBY_ROUND_ACTIVE, NULL, 0);
                w_ended(&w.node[0], C);
            }
            wr_member(&w, c, o ? GZ_LOBBY_ROUND_ACTIVE : GZ_LOBBY_ROUND_RETRY);
            w_ended(&w.node[c], C);
            w_confirm(&w.node[c]);
            e0 = w.node[c].n_begin_ended;
            r0 = w.node[c].n_resumes;
            w_crash(&w, c);
            w_boot(&w.node[c]);
            CHECK(w.node[c].n_begin_ended == e0 && w.node[c].n_resumes == r0);
            if (o) CHECK(w.node[c].mem->round_state == GZ_LOBBY_ACTIVE && w.node[c].mem->lobby_state == GZ_LOBBY_ACTIVE);
            else CHECK(w.node[c].mem->start_len == 0);
            if (o) {
                w_confirm(&w.node[0]);
                e0 = w.node[0].n_begin_ended;
                w_crash(&w, 0);
                w_boot(&w.node[0]);
                CHECK(w.node[0].host->state == GZ_LOBBY_ACTIVE && w.node[0].n_begin_ended == e0);
            }
            CHECK(w.failures == 0);
        }
        w_free(&w);
    }

    /* B4, scenario S3: Signing, then a retry with every chosen seat failed and
     * the members gone. With or without a host restart in Signing, the lobby
     * is cancelled at its deadline, reason 1 */
    for (o = 0; o < 2; o++) {
        w_init(&w, 8, 13, NULL);
        w_start(&w);
        CHECK(wr_run_to(&w, GZ_LOBBY_SIGNING, 6000));
        w_run(&w, 40, 0);
        if (o) {
            w_confirm(&w.node[0]);
            w_crash(&w, 0);
            w_boot(&w.node[0]);
            w_run(&w, 200, 0);
        }
        h = w.node[0].host;
        nf = 0;
        for (i = 0; i < h->n_seats; i++)
            if (h->seats[i].chosen) memcpy(failed + 33 * nf++, h->seats[i].ckey, 33);
        wr_host_result(&w, GZ_LOBBY_ROUND_RETRY, failed, nf);
        for (i = 1; i <= w.n; i++) { w.node[i].dead = 1; w_crash(&w, i); }
        while (w.now < h->terms.deadline * 1000 + 60000) w_step(&w, 0);
        CHECK(h->state == GZ_LOBBY_CANCELLED && h->end_reason == 1 && w.failures == 0);
        w_free(&w);
    }
}

/* ---------------------------------------------------- world scenarios */

static int chosen_of(const world_t *w, int i)
{
    const w_node_t *d = &w->node[i];
    return d->n_handoffs > 0 && d->handoffs[d->n_handoffs - 1].role == 1;
}

static void test_world_basic(void)
{
    static world_t w;
    gz_lobby_conditions_t cond = lt_cond_fits();
    uint8_t cd2[32];
    int i, k;
    gz_terms_current_digest(T2, T2N, cd2);
    /* test 15: three members, start at the deadline; twice from a clean start */
    for (k = 0; k < 2; k++) {
        w_init(&w, 3, 11 + (uint64_t)k, NULL);
        w_start(&w);
        w_run(&w, 13000, 0);
        if (w.node[0].host->state != GZ_LOBBY_SIGNING)
            printf("  world: failures %lu state %d seats %d now %llu\n", w.failures, w.node[0].host->state,
                   w.node[0].host->n_seats, (unsigned long long)(w.now - W_T0)),
            printf("  reason %d seats %d %d %d rv %u %u %u ans %d %d %d minm %d %d %d\n", w.node[0].host->end_reason,
                   w.node[0].host->seats[0].state, w.node[0].host->seats[1].state, w.node[0].host->seats[2].state,
                   w.node[0].host->seats[0].ready_version, w.node[0].host->seats[1].ready_version, w.node[0].host->seats[2].ready_version,
                   w.node[0].host->seats[0].answered, w.node[0].host->seats[1].answered, w.node[0].host->seats[2].answered,
                   w.node[0].host->seats[0].min_members, w.node[0].host->seats[1].min_members, w.node[0].host->seats[2].min_members);
        CHECK(w.failures == 0 && w.node[0].host->state == GZ_LOBBY_SIGNING);
        CHECK(w.node[0].n_handoffs == 1 && w.node[0].handoffs[0].n_participants == 4 && w.node[0].handoffs[0].signers == 4);
        CHECK(memcmp(w.node[0].handoffs[0].participants[0], w.node[0].keys.key[1].pub, 33) == 0);
        CHECK(memcmp(w.node[0].handoffs[0].digest, cd2, 32) == 0 && w_params_ok(&w.node[0].handoffs[0], 3));
        CHECK(memcmp(w.node[0].handoffs[0].factory[0], w.node[0].keys.key[3].pub, 33) == 0);
        for (i = 1; i <= 3; i++) {
            CHECK(chosen_of(&w, i) && w.node[i].handoffs[0].signers == 4);
            CHECK(w_params_ok(&w.node[i].handoffs[0], 3) && w.node[i].handoffs[0].start_len > 0);
            CHECK(memcmp(w.node[i].handoffs[0].check, w.node[0].handoffs[0].check, 32) == 0);
            CHECK(memcmp(w.node[i].handoffs[0].digest, cd2, 32) == 0);
            CHECK(w_count_recs(&w.node[i], GZ_REC_START_RECEIVED) == 1 && w_count_recs(&w.node[i], GZ_REC_FREEZE) == 1);
        }
        w_free(&w);
    }
    /* the target: eight members start at once, long before the deadline */
    w_init(&w, 8, 21, NULL);
    w_start(&w);
    w_run(&w, 2000, 0);
    CHECK(w.failures == 0 && w.node[0].host->state == GZ_LOBBY_SIGNING && w.now < 1794441600000ull);
    CHECK(w.node[0].n_handoffs == 1 && w.node[0].handoffs[0].n_participants == 9 && w_params_ok(&w.node[0].handoffs[0], 8));
    w_free(&w);
    /* Slice 1: a member whose conditions are not met refuses, with the reason */
    cond.limits.min_channel_sat = 200000;
    w_init(&w, 4, 31, NULL);
    w.node[4].cond = cond;
    w_start(&w);
    w_run(&w, 13000, 0);
    CHECK(w.failures == 0 && w.node[0].host->state == GZ_LOBBY_SIGNING && w.node[0].host->n_seats == 3);
    CHECK(w_has_note(&w.node[4], GZ_NOTE_REFUSED, GZ_FIT_NO, 30) && w.node[4].n_recs == 0 && w.node[4].n_handoffs == 0);
    for (i = 1; i <= 3; i++) CHECK(chosen_of(&w, i));
    w_free(&w);
    /* below the minimum at the deadline: cancelled, reason 1 */
    w_init(&w, 2, 41, NULL);
    w_start(&w);
    w_run(&w, 13000, 0);
    CHECK(w.node[0].host->state == GZ_LOBBY_CANCELLED && w.node[0].host->end_reason == 1);
    CHECK(w.node[0].n_cancels == 1 && w.node[0].cancel_reason == 1 && memcmp(w.node[0].cancel_scope, SCOPE, 32) == 0);
    CHECK(w.node[1].n_cancels == 1 && w.node[1].cancel_reason == 1 && w.node[2].n_cancels == 1);
    CHECK(w_has_note(&w.node[1], GZ_NOTE_ENDED, GZ_LOBBY_CANCELLED, -1) && w_has_note(&w.node[2], GZ_NOTE_ENDED, GZ_LOBBY_CANCELLED, -1));
    w_free(&w);
    /* a member's own minimum is respected */
    w_init(&w, 4, 51, NULL);
    w.node[2].cond.min_members = 5;
    w_start(&w);
    w_run(&w, 13000, 0);
    CHECK(w.node[0].host->state == GZ_LOBBY_SIGNING && w.node[0].handoffs[0].n_participants == 4);
    CHECK(!chosen_of(&w, 2) && w_has_note(&w.node[2], GZ_NOTE_STARTED, 2, -1) && w.node[2].n_handoffs == 0);
    CHECK(w.node[1].handoffs[0].min_members == 0 && w_params_ok(&w.node[1].handoffs[0], 3));
    CHECK(chosen_of(&w, 1) && chosen_of(&w, 3) && chosen_of(&w, 4));
    w_free(&w);
}

/* T6 in a running lobby (messages.md test 16). */
static void test_world_values(void)
{
    static world_t w;
    uint64_t v[3] = {1500, 1000, 1000};
    gz_action_list_t l;
    w_init(&w, 3, 61, NULL);
    LT_ADJ(w.node[1].cond, 0) = 1000;                    /* default option: never joins */
    LT_ADJ(w.node[2].cond, 0) = 1000;
    w.node[2].cond.current_only = 1;                     /* looser: ready while it fits */
    w_start(&w);
    w_run(&w, 400, 0);
    /* fits only now, default option: it joins and is never ready by itself (S2) */
    CHECK(w_has_note(&w.node[1], GZ_NOTE_REFUSED, GZ_FIT_NOW, 64) && w.node[1].n_recs == 2 &&
          w_count_recs(&w.node[1], GZ_REC_JOINED) == 1 && w_count_recs(&w.node[1], GZ_REC_READY_SENT) == 0);
    CHECK(w.node[2].mem->ready && w.node[3].mem->ready);
    gz_action_list_init(&l, w_slots, 512, w_bytes, sizeof w_bytes);
    CHECK(gz_lobby_host_set_values(w.node[0].host, v, 3, &l) == GZ_OK);
    w_submit(&w.node[0], &l);
    w_run(&w, 400, 0);
    CHECK(!w.node[2].mem->ready && w_has_note(&w.node[2], GZ_NOTE_UNREADY, GZ_FIT_NO, 64));
    CHECK(w.node[3].mem->ready && w.node[3].mem->ready_version == 2);
    w_free(&w);
}

/* Standbys fill a gap; removal before the start. */
static void test_world_standbys(void)
{
    static world_t w;
    gz_terms_outer_t o = T1O;
    gz_terms_current_t c;
    gz_action_list_t l;
    uint8_t first[33];
    int i, n_chosen = 0, n_standby = 0;
    w_init(&w, 5, 71, NULL);
    o.target = 3;
    w.outer_len = gz_terms_encode_outer(&o, w.outer, sizeof w.outer);
    lt_current(T2, T2N, &T1O, SCOPE, &c);
    gz_terms_outer_digest(w.outer, w.outer_len, c.outer_digest);
    w.current_len = gz_terms_encode_current(&c, w.current, sizeof w.current);
    w.standbys = 2;
    w_start(&w);
    w_run(&w, 1500, 0);
    CHECK(w.failures == 0 && w.node[0].host->state == GZ_LOBBY_SIGNING);
    for (i = 1; i <= 5; i++) {
        if (chosen_of(&w, i)) n_chosen++;
        else if (w_has_note(&w.node[i], GZ_NOTE_STARTED, 2, -1)) n_standby++;
    }
    CHECK(n_chosen == 3 && w.node[0].handoffs[0].n_participants == 4);
    /* the first chosen seat fails to sign and is gone: a standby takes its place */
    memcpy(first, w.node[0].handoffs[0].participants[1], 33);
    for (i = 1; i <= 5; i++) if (memcmp(w.node[i].keys.key[2].pub, first, 33) == 0) { w_crash(&w, i); w.node[i].dead = 1; }
    gz_action_list_init(&l, w_slots, 512, w_bytes, sizeof w_bytes);
    CHECK(gz_lobby_host_round_result(w.node[0].host, GZ_LOBBY_ROUND_RETRY, first, 1, &l) == GZ_OK);
    w_submit(&w.node[0], &l);
    w_run(&w, 1500, 0);
    CHECK(w.node[0].host->state == GZ_LOBBY_SIGNING && w.node[0].n_handoffs == 2);
    CHECK(w.node[0].handoffs[1].n_participants == 4);
    for (i = 1; i < 4; i++) CHECK(memcmp(w.node[0].handoffs[1].participants[i], first, 33) != 0);
    CHECK(memcmp(w.node[0].handoffs[1].digest, w.node[0].handoffs[0].digest, 32) == 0);
    CHECK(memcmp(w.node[0].handoffs[1].check, w.node[0].handoffs[0].check, 32) != 0);
    (void)n_standby;
    /* funding, active, then nothing more moves the lobby */
    gz_action_list_init(&l, w_slots, 512, w_bytes, sizeof w_bytes);
    CHECK(gz_lobby_host_round_result(w.node[0].host, GZ_LOBBY_ROUND_FUNDING, NULL, 0, &l) == GZ_OK);
    CHECK(gz_lobby_host_round_result(w.node[0].host, GZ_LOBBY_ROUND_ACTIVE, NULL, 0, &l) == GZ_OK);
    CHECK(gz_lobby_host_round_result(w.node[0].host, GZ_LOBBY_ROUND_RETRY, NULL, 0, &l) == GZ_OK);   /* refused now */
    CHECK(gz_lobby_host_cancel(w.node[0].host, 2, &l) == GZ_OK && w.node[0].host->state == GZ_LOBBY_ACTIVE);
    w_submit(&w.node[0], &l);
    w_free(&w);
    /* removal: the removed member is told and never chosen */
    w_init(&w, 4, 81, NULL);
    w_start(&w);
    w_run(&w, 400, 0);
    gz_action_list_init(&l, w_slots, 512, w_bytes, sizeof w_bytes);
    CHECK(gz_lobby_host_remove(w.node[0].host, w.node[2].keys.key[2].pub, &l) == GZ_OK);
    w_submit(&w.node[0], &l);
    w_run(&w, 13000, 0);
    CHECK(w.node[0].host->state == GZ_LOBBY_SIGNING && !chosen_of(&w, 2) && w.node[2].mem->ended);
    CHECK(w_has_note(&w.node[2], GZ_NOTE_SEAT, GZ_LOBBY_OPEN, GZ_SEAT_REMOVED));
    CHECK(chosen_of(&w, 1) && chosen_of(&w, 3) && chosen_of(&w, 4));
    w_free(&w);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int i;
    char label[64];
    memset(&HOST, 0, sizeof HOST);
    lt_key(&HOST.key[1], "host");
    lt_key(&HOST.key[3], "host factory");
    lt_key(&OTHER.key[1], "not the host");
    lt_key(&M1.key[2], "member 1 contribution");
    lt_key(&M1.key[3], "member 1 factory");
    for (i = 0; i < 40; i++) {
        snprintf(label, sizeof label, "member %d contribution", i);
        lt_key(&MEM[i].key[2], label);
        snprintf(label, sizeof label, "member %d factory", i);
        lt_key(&MEM[i].key[3], label);
    }
    T1N = lt_unhex(LT_T1, T1, sizeof T1);
    T2N = lt_unhex(LT_T2, T2, sizeof T2);
    T3N = lt_unhex(LT_T3, T3, sizeof T3);
    lt_outer(T1, T1N, &T1O);
    gz_terms_outer_digest(T1, T1N, SCOPE);
    test_member_hostile();
    test_member_classes();
    test_member_details();
    test_member_more();
    test_host_hostile();
    test_host_restart();
    test_host_details();
    test_host_checks();
    test_reconnect_joined();
    test_host_creations();
    test_host_order();
    test_host_join_keys();
    test_api_edges();
    test_host_restart_signing();
    test_host_commands();
    test_host_creations_restart();
    test_contract_v2();
    test_review_member();
    test_review_host();
    test_world_basic();
    test_world_values();
    test_world_standbys();
    test_review_b_host();
    test_review_b_member();
    test_review_b_world();
    return check_done();
}
