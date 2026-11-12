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
static void c_rand(void *ctx, uint32_t p, uint8_t *o, size_t n) { (void)ctx; (void)p; memset(o, 0x5a, n); }

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
    xn = gz_terms_outer_encode(&o, x, sizeof x);
    {
        uint8_t sc[32], cur[128];
        gz_terms_current_t v;
        size_t cn;
        gz_terms_outer_digest(x, xn, sc);
        gz_terms_current_decode(T2, T2N, &T1O, SCOPE, &v);
        memcpy(v.outer_digest, sc, 32);
        cn = gz_terms_current_encode(&v, &o, cur, sizeof cur);
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
        gz_terms_current_decode(T3, T3N, &T1O, SCOPE, &v);
        v.adj_value[1] = 999;
        c2n = gz_terms_current_encode(&v, &T1O, c2, sizeof c2);
        n = offer(buf, sizeof buf, SCOPE, T1, T1N, c2, c2n, &HOST);
        CHECK(feed(&m, buf, n) == GZ_OK && saves(GZ_REC_HOST_FAULT) == 1 && sends(GZ_KIND_LEAVE) == 1);
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
        gz_terms_current_decode(T3, T3N, &T1O, SCOPE, &v);
        v.version = 3;
        c4n = gz_terms_current_encode(&v, &T1O, c4, sizeof c4);
        n = offer(buf, sizeof buf, SCOPE, T1, T1N, c4, c4n, &HOST);
        CHECK(feed(&m, buf, n) == GZ_OK && saves(GZ_REC_HOST_FAULT) == 1 && sends(GZ_KIND_LEAVE) == 1);
        CHECK(note(GZ_NOTE_HOST_FAULT, GZ_FAULT_AFTER_FREEZE, -1));
    }
    /* a ready check at other values after the freeze: fault */
    member_up(&m, &cond);
    feed(&m, b2, n = offer(b2, sizeof b2, SCOPE, T1, T1N, T3, T3N, &HOST));
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, check, 2, cd3, 30000, 0, &HOST);
    feed(&m, x, xn);
    memset(check, 9, 32);
    xn = host_msg(x, sizeof x, GZ_KIND_READY_CHECK, check, 1, cd2, 30000, 0, &HOST);
    CHECK(feed(&m, x, xn) == GZ_OK && saves(GZ_REC_HOST_FAULT) == 1 && sends(GZ_KIND_LEAVE) == 1);
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
    cond.adj_max[0] = 1000;
    member_up(&m, &cond);
    n = offer(buf, sizeof buf, SCOPE, T1, T1N, T2, T2N, &HOST);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_JOIN) == 0 && note(GZ_NOTE_REFUSED, GZ_FIT_NOW, 64) && !any_save());
    cond.current_only = 1;
    member_up(&m, &cond);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_JOIN) == 1 && sends(GZ_KIND_READY) == 1);
    n = offer(buf, sizeof buf, SCOPE, T1, T1N, T3, T3N, &HOST);
    CHECK(feed(&m, buf, n) == GZ_OK && sends(GZ_KIND_UNREADY) == 1 && note(GZ_NOTE_UNREADY, GZ_FIT_NO, 64));
    CHECK(sends(GZ_KIND_READY) == 0 && saves(GZ_REC_READY_SENT) == 1 && saves(GZ_REC_TERMS_RECEIVED) == 0);
    /* the Slice 1 condition: channel below the member's minimum */
    cond = lt_cond_fits();
    cond.chan_min = 100001;
    member_up(&m, &cond);
    n = offer(buf, sizeof buf, SCOPE, T1, T1N, T2, T2N, &HOST);
    CHECK(feed(&m, buf, n) == GZ_OK && note(GZ_NOTE_REFUSED, GZ_FIT_NO, 30) && sends(GZ_KIND_JOIN) == 0 && !any_save());
    cond = lt_cond_fits(); cond.profiles = 1u << 1;
    member_up(&m, &cond);
    CHECK(feed(&m, buf, n) == GZ_OK && note(GZ_NOTE_REFUSED, GZ_FIT_NO, 8));
    cond = lt_cond_fits(); cond.life_min = 145;
    member_up(&m, &cond);
    CHECK(feed(&m, buf, n) == GZ_OK && note(GZ_NOTE_REFUSED, GZ_FIT_NO, 26));
    /* a user unready is kept across a restart */
    cond = lt_cond_fits();
    member_up(&m, &cond);
    feed(&m, buf, n);
    acts_reset();
    CHECK(gz_lobby_member_unready(&m, &A.l) == GZ_OK && sends(GZ_KIND_UNREADY) == 1 && saves(GZ_REC_READY_SENT) == 1);
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

/* -------------------------------------------- host, hostile members */

static gz_lobby_host_t H;
static lt_signer_t MEM[12];
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
    uint8_t buf[600], cd2[32], cd3[32];
    size_t n;
    int i;
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
    CLOCK += 1000;
    n = join_msg(buf, sizeof buf, 2, MEM[1].key[3].pub, 1, 2);                  /* another seat's factory key */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    n = join_msg(buf, sizeof buf, 2, HOST.key[3].pub, 0, 2);                    /* the host's factory key */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    n = join_msg(buf, sizeof buf, 2, MEM[2].key[3].pub, 3, 2);                  /* bad bind_by_factory */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    n = join_msg(buf, sizeof buf, 2, MEM[2].key[3].pub, 2, 3);                  /* bad bind_by_contribution */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    n = join_msg(buf, sizeof buf, 2, MEM[1].key[2].pub, 1, 2);                  /* another seat's contribution key */
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    n = join_msg(buf, sizeof buf, 2, MEM[2].key[3].pub, 2, 2);
    CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1);
    n = join_msg(buf, sizeof buf, 3, MEM[3].key[3].pub, 3, 3);                  /* one creation a second */
    CHECK(hin(GZ_LIN_MESSAGE, 3, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
    CLOCK += 1000;
    /* test 23: ready naming an old version during a change */
    n = ready_msg(buf, sizeof buf, 1, 1, cd2, NULL, 0);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_READY);
    CHECK(hin(GZ_LIN_MESSAGE, 1, buf, n) == GZ_OK && !any_save());               /* duplicate: not saved */
    {
        uint64_t v[3] = {1500, 1000, 1000};
        acts_reset();
        CHECK(gz_lobby_host_set_values(&H, v, 3, &A.l) == GZ_OK && saves(GZ_REC_CURRENT_SIGNED) == 1);
        CHECK(sends(GZ_KIND_TERMS_OFFER) == 2 && before(GZ_KIND_TERMS_OFFER, GZ_REC_CURRENT_SIGNED));
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
    /* test 56: a seat that loops ready/unready saves at most 10 changes in 10 minutes */
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
        CHECK(saved == 9);                     /* the join used one of the ten */
        CHECK(H.seats[1].state == GZ_SEAT_READY);
        CLOCK += 600000;
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
            CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && !any_save() && status_seat() == GZ_SEAT_REFUSED);
            hin(GZ_LIN_DISCONNECTED, 2, NULL, 0);
            hin(GZ_LIN_CONNECTED, 2, NULL, 0);
            CHECK(hin(GZ_LIN_MESSAGE, 2, buf, n) == GZ_OK && saves(GZ_REC_SEAT) == 1 && status_seat() == GZ_SEAT_JOINED);
        }
    }
    /* removal before the start: the seat cannot come back */
    acts_reset();
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
        CHECK(gz_lobby_host_set_values(&H, v, 3, &A.l) == GZ_ERR_ARGUMENT && A.l.count == 0);
        /* test 24: a stale check id is not counted; the open one is */
        {
            uint8_t stale[32], *chk = CHK;
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
            CHECK(gz_lobby_host_handle(&H, &in, &A.l) == GZ_OK && sends(GZ_KIND_START) == 0 && sends(GZ_KIND_CANCEL) == 4);
            CHECK(saves(GZ_REC_LOBBY_ENDED) == 1 && H.state == GZ_LOBBY_CANCELLED && before(GZ_KIND_CANCEL, GZ_REC_LOBBY_ENDED));
        }
    }
}

/* The host's restart: the freeze and the versions survive; a resumed host
 * resends the saved start after hello. */
static void test_host_restart(void)
{
    static gz_lobby_host_t H2;
    uint8_t buf[600], cd3[32];
    size_t n, i;
    gz_record_t recs[64];
    uint8_t *store[64];
    size_t nrec = 0, k;
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = lt_crypto(&HOST);
    gz_lobby_host_config_t cfg;
    gz_lobby_input_t in;
    gz_terms_current_digest(T3, T3N, cd3);
    CLOCK = W_T0;
    host_open(0);
#define KEEP() for (i = 0; i < A.l.count; i++) if (A.s[i].kind == GZ_ACTION_SAVE) \
    for (k = 0; k < A.s[i].u.save.n_records; k++) { recs[nrec] = A.s[i].u.save.records[k]; \
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
        size_t j = i;
        hin(GZ_LIN_CONNECTED, (int)j, NULL, 0);
        CLOCK += 1000;
        n = join_msg(buf, sizeof buf, (int)j, MEM[j].key[3].pub, (int)j, (int)j);
        hin(GZ_LIN_MESSAGE, (int)j, buf, n); KEEP();
        n = ready_msg(buf, sizeof buf, (int)j, 2, cd3, NULL, 0);
        hin(GZ_LIN_MESSAGE, (int)j, buf, n); KEEP();
        i = j;
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
    acts_reset();
    CHECK(gz_lobby_host_resume(&H2, &A.l) == GZ_OK);
    /* a damaged record stops the start */
    {
        gz_record_t bad = recs[0];
        static gz_lobby_host_t H3;
        bad.bytes.len -= 1;
        gz_lobby_host_init(&H3, &p, &cr, NULL, &cfg);
        CHECK(gz_lobby_host_restore(&H3, &bad) == GZ_ERR_CORRUPT);
    }
    for (i = 0; i < nrec; i++) free(store[i]);
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
        CHECK(memcmp(w.node[0].handoffs[0].digest, cd2, 32) == 0);
        for (i = 1; i <= 3; i++) {
            CHECK(chosen_of(&w, i) && w.node[i].handoffs[0].signers == 4);
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
    CHECK(w.node[0].n_handoffs == 1 && w.node[0].handoffs[0].n_participants == 9);
    w_free(&w);
    /* Slice 1: a member whose conditions are not met refuses, with the reason */
    cond.chan_min = 200000;
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
    CHECK(w_has_note(&w.node[1], GZ_NOTE_ENDED, GZ_LOBBY_CANCELLED, -1) && w_has_note(&w.node[2], GZ_NOTE_ENDED, GZ_LOBBY_CANCELLED, -1));
    w_free(&w);
    /* a member's own minimum is respected */
    w_init(&w, 4, 51, NULL);
    w.node[2].cond.min_members = 5;
    w_start(&w);
    w_run(&w, 13000, 0);
    CHECK(w.node[0].host->state == GZ_LOBBY_SIGNING && w.node[0].handoffs[0].n_participants == 4);
    CHECK(!chosen_of(&w, 2) && w_has_note(&w.node[2], GZ_NOTE_STARTED, 2, -1));
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
    w.node[1].cond.adj_max[0] = 1000;                    /* default option: never joins */
    w.node[2].cond.adj_max[0] = 1000;
    w.node[2].cond.current_only = 1;                     /* looser: ready while it fits */
    w_start(&w);
    w_run(&w, 400, 0);
    CHECK(w_has_note(&w.node[1], GZ_NOTE_REFUSED, GZ_FIT_NOW, 64) && w.node[1].n_recs == 0);
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
    w.outer_len = gz_terms_outer_encode(&o, w.outer, sizeof w.outer);
    gz_terms_current_decode(T2, T2N, &T1O, SCOPE, &c);
    gz_terms_outer_digest(w.outer, w.outer_len, c.outer_digest);
    w.current_len = gz_terms_current_encode(&c, &o, w.current, sizeof w.current);
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
    CHECK(gz_lobby_host_round_result(w.node[0].host, GZ_ROUND_RETRY, first, 1, &l) == GZ_OK);
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
    CHECK(gz_lobby_host_round_result(w.node[0].host, GZ_ROUND_FUNDING, NULL, 0, &l) == GZ_OK);
    CHECK(gz_lobby_host_round_result(w.node[0].host, GZ_ROUND_ACTIVE, NULL, 0, &l) == GZ_OK);
    CHECK(gz_lobby_host_round_result(w.node[0].host, GZ_ROUND_RETRY, NULL, 0, &l) == GZ_ERR_ARGUMENT);
    CHECK(gz_lobby_host_cancel(w.node[0].host, 2, &l) == GZ_ERR_ARGUMENT);
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
    for (i = 0; i < 12; i++) {
        snprintf(label, sizeof label, "member %d contribution", i);
        lt_key(&MEM[i].key[2], label);
        snprintf(label, sizeof label, "member %d factory", i);
        lt_key(&MEM[i].key[3], label);
    }
    T1N = lt_unhex(LT_T1, T1, sizeof T1);
    T2N = lt_unhex(LT_T2, T2, sizeof T2);
    T3N = lt_unhex(LT_T3, T3, sizeof T3);
    gz_terms_outer_decode(T1, T1N, &T1O);
    gz_terms_outer_digest(T1, T1N, SCOPE);
    test_member_hostile();
    test_member_classes();
    test_host_hostile();
    test_host_restart();
    test_world_basic();
    test_world_values();
    test_world_standbys();
    return check_done();
}
